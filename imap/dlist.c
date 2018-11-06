/* dlist.c - list protocol for dump and sync
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>

#include "global.h"
#include "assert.h"
#include "mboxlist.h"
#include "mailbox.h"
#include "quota.h"
#include "xmalloc.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "imapd.h"
#include "message.h"
#include "util.h"
#include "prot.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "dlist.h"

/* Parse routines */

static const char *lastkey = NULL;

static void printfile(struct protstream *out, const struct dlist *dl)
{
    struct stat sbuf;
    FILE *f;
    unsigned long size;
    struct message_guid guid2;
    const char *msg_base = NULL;
    size_t msg_len = 0;

    assert(dlist_isfile(dl));

    f = fopen(dl->sval, "r");
    if (!f) {
        syslog(LOG_ERR, "IOERROR: Failed to read file %s", dl->sval);
        prot_printf(out, "NIL");
        return;
    }
    if (fstat(fileno(f), &sbuf) == -1) {
        syslog(LOG_ERR, "IOERROR: Failed to stat file %s", dl->sval);
        prot_printf(out, "NIL");
        fclose(f);
        return;
    }
    size = sbuf.st_size;
    if (size != dl->nval) {
        syslog(LOG_ERR, "IOERROR: Size mismatch %s (%lu != " MODSEQ_FMT ")",
               dl->sval, size, dl->nval);
        prot_printf(out, "NIL");
        fclose(f);
        return;
    }

    map_refresh(fileno(f), 1, &msg_base, &msg_len, sbuf.st_size,
                "new message", 0);

    message_guid_generate(&guid2, msg_base, msg_len);

    if (!message_guid_equal(&guid2, dl->gval)) {
        syslog(LOG_ERR, "IOERROR: GUID mismatch %s",
               dl->sval);
        prot_printf(out, "NIL");
        fclose(f);
        map_free(&msg_base, &msg_len);
        return;
    }

    prot_printf(out, "%%{");
    prot_printastring(out, dl->part);
    prot_printf(out, " ");
    prot_printastring(out, message_guid_encode(dl->gval));
    prot_printf(out, " %lu}\r\n", size);
    prot_write(out, msg_base, msg_len);
    fclose(f);
    map_free(&msg_base, &msg_len);
}

/* XXX - these two functions should be out in append.c or reserve.c
 * or something more general */
EXPORTED const char *dlist_reserve_path(const char *part, int isarchive, int isbackup,
                                        const struct message_guid *guid)
{
    static char buf[MAX_MAILBOX_PATH];
    const char *base = NULL;

    /* part must be a configured partition name on this server */
    if (isbackup) {
        base = config_backupstagingpath();
    }
    else {
        if (isarchive) base = config_archivepartitiondir(part);
        if (!base) base = config_partitiondir(part);
    }

    /* we expect to have a base at this point, so let's assert that */
    assert(base != NULL);

    snprintf(buf, MAX_MAILBOX_PATH, "%s/sync./%lu/%s",
                  base, (unsigned long)getpid(),
                  message_guid_encode(guid));

    /* gotta make sure we can create files */
    if (cyrus_mkdir(buf, 0755)) {
        /* it's going to fail later, but at least this will help */
        syslog(LOG_ERR, "IOERROR: failed to create %s/sync./%lu/ for reserve: %m",
                        base, (unsigned long)getpid());
    }
    return buf;
}

static int reservefile(struct protstream *in, const char *part,
                       struct message_guid *guid, unsigned long size,
                       int isbackup, const char **fname)
{
    static struct message_guid debug_writefail_guid = MESSAGE_GUID_INITIALIZER;
    FILE *file;
    char buf[8192+1];
    int r = 0;

    if (debug_writefail_guid.status == GUID_UNKNOWN) {
        const char *guidstr = config_getstring(IMAPOPT_DEBUG_WRITEFAIL_GUID);
        if (guidstr) {
            if (!message_guid_decode(&debug_writefail_guid, guidstr)) {
                xsyslog(LOG_DEBUG, "debug_writefail_guid: ignoring invalid guid",
                                   "guid=<%s>", guidstr);
                message_guid_set_null(&debug_writefail_guid);
            }
        }
        else {
            message_guid_set_null(&debug_writefail_guid);
        }
    }

    /* XXX - write to a temporary file then move in to place! */
    *fname = dlist_reserve_path(part, /*isarchive*/0, isbackup, guid);

    /* remove any duplicates if they're still here */
    unlink(*fname);

    file = fopen(*fname, "w+");
    if (!file) {
        syslog(LOG_ERR,
               "IOERROR: failed to upload file %s", message_guid_encode(guid));
        r = IMAP_IOERROR;
    }
    else if (debug_writefail_guid.status == GUID_NONNULL
             && message_guid_equal(&debug_writefail_guid, guid)) {
        /* no error, but pretend the disk is full */
        fclose(file);
        file = NULL;
        errno = ENOSPC;
        syslog(LOG_ERR, "IOERROR: failed to upload file %s (simulated)",
                        message_guid_encode(guid));
        r = IMAP_IOERROR;
    }
    /* Note: in the case of error we still read the file's data from the wire,
     * to avoid losing protocol sync */

    /* XXX - calculate sha1 on the fly? */
    while (size) {
        size_t n = prot_read(in, buf, size > 8192 ? 8192 : size);
        if (!n) {
            syslog(LOG_ERR,
                "IOERROR: reading message: unexpected end of file");
            r = IMAP_IOERROR;
            break;
        }
        size -= n;
        if (!file) continue;
        if (fwrite(buf, 1, n, file) != n) {
            syslog(LOG_ERR, "IOERROR: writing to file '%s': %m", *fname);
            r = IMAP_IOERROR;
            break;
        }
    }

    if (r)
        goto error;

    /* Make sure that message flushed to disk just incase mmap has problems */
    fflush(file);
    if (ferror(file)) {
        r = IMAP_IOERROR;
        goto error;
    }

    if (fsync(fileno(file)) < 0) {
        syslog(LOG_ERR, "IOERROR: fsyncing file '%s': %m", *fname);
        r = IMAP_IOERROR;
        goto error;
    }

    fclose(file);

    return 0;

error:
    if (file) {
        fclose(file);
        unlink(*fname);
        *fname = NULL;
    }
    return r;
}

/* DLIST STUFF */

EXPORTED void dlist_push(struct dlist *parent, struct dlist *child)
{
    assert(!child->next);

    if (parent->head) {
        child->next = parent->head;
        parent->head = child;
    }
    else {
        parent->head = parent->tail = child;
    }
}

EXPORTED struct dlist *dlist_pop(struct dlist *parent)
{
    struct dlist *child;

    assert(parent->head);

    child = parent->head;
    parent->head = parent->head->next;
    child->next = NULL;

    return child;
}

EXPORTED void dlist_stitch(struct dlist *parent, struct dlist *child)
{
    assert(!child->next);

    if (parent->tail) {
        parent->tail->next = child;
        parent->tail = child;
    }
    else {
        parent->head = parent->tail = child;
    }
}

EXPORTED void dlist_unstitch(struct dlist *parent, struct dlist *child)
{
    struct dlist *prev = NULL;
    struct dlist *replace = NULL;

    /* find old record */
    for (replace = parent->head; replace; replace = replace->next) {
        if (replace == child) break;
        prev = replace;
    }

    assert(replace);

    if (prev) prev->next = child->next;
    else parent->head = child->next;

    if (parent->tail == child) parent->tail = prev;

    child->next = NULL;
}

static struct dlist *dlist_child(struct dlist *dl, const char *name)
{
    struct dlist *i = xzmalloc(sizeof(struct dlist));
    if (name) i->name = xstrdup(name);
    i->type = DL_NIL;
    if (dl)
        dlist_stitch(dl, i);
    return i;
}

static void _dlist_free_children(struct dlist *dl)
{
    struct dlist *next;
    struct dlist *i;

    if (!dl) return;

    i = dl->head;
    while (i) {
        next = i->next;
        dlist_free(&i);
        i = next;
    }

    dl->head = dl->tail = NULL;
}

static void _dlist_clean(struct dlist *dl)
{
    if (!dl) return;

    /* remove any children */
    _dlist_free_children(dl);

    /* clean out values */
    free(dl->part);
    dl->part = NULL;
    free(dl->sval);
    dl->sval = NULL;
    free(dl->gval);
    dl->gval = NULL;
    dl->nval = 0;
}


void dlist_makeatom(struct dlist *dl, const char *val)
{
    if (!dl) return;
    _dlist_clean(dl);
    if (val) {
        dl->type = DL_ATOM;
        dl->sval = xstrdup(val);
        dl->nval = strlen(val);
    }
    else
        dl->type = DL_NIL;
}

void dlist_makeflag(struct dlist *dl, const char *val)
{
    if (!dl) return;
    _dlist_clean(dl);
    if (val) {
        dl->type = DL_FLAG;
        dl->sval = xstrdup(val);
        dl->nval = strlen(val);
    }
    else
        dl->type = DL_NIL;
}

void dlist_makenum32(struct dlist *dl, uint32_t val)
{
    if (!dl) return;
    _dlist_clean(dl);
    dl->type = DL_NUM;
    dl->nval = val;
}

void dlist_makenum64(struct dlist *dl, bit64 val)
{
    if (!dl) return;
    _dlist_clean(dl);
    dl->type = DL_NUM;
    dl->nval = val;
}

void dlist_makedate(struct dlist *dl, time_t val)
{
    if (!dl) return;
    _dlist_clean(dl);
    dl->type = DL_DATE;
    dl->nval = val;
}

void dlist_makehex64(struct dlist *dl, bit64 val)
{
    if (!dl) return;
    _dlist_clean(dl);
    dl->type = DL_HEX;
    dl->nval = val;
}

void dlist_makeguid(struct dlist *dl, const struct message_guid *guid)
{
    if (!dl) return;
    _dlist_clean(dl);
    if (guid) {
        dl->type = DL_GUID,
        dl->gval = xzmalloc(sizeof(struct message_guid));
        message_guid_copy(dl->gval, guid);
    }
    else
        dl->type = DL_NIL;
}

void dlist_makefile(struct dlist *dl,
                    const char *part, const struct message_guid *guid,
                    unsigned long size, const char *fname)
{
    if (!dl) return;
    _dlist_clean(dl);
    if (part && guid && fname) {
        dl->type = DL_FILE;
        dl->gval = xzmalloc(sizeof(struct message_guid));
        message_guid_copy(dl->gval, guid);
        dl->sval = xstrdup(fname);
        dl->nval = size;
        dl->part = xstrdup(part);
    }
    else
        dl->type = DL_NIL;
}

EXPORTED void dlist_makemap(struct dlist *dl, const char *val, size_t len)
{
    if (!dl) return;
    _dlist_clean(dl);
    if (val) {
        dl->type = DL_BUF;
        /* WARNING - DO NOT replace this with xstrndup - the
         * data may be binary, and xstrndup does not copy
         * binary data correctly - but we still want to NULL
         * terminate for non-binary data */
        dl->sval = xmalloc(len+1);
        memcpy(dl->sval, val, len);
        dl->sval[len] = '\0'; /* make it string safe too */
        dl->nval = len;
    }
    else
        dl->type = DL_NIL;
}

EXPORTED struct dlist *dlist_newkvlist(struct dlist *parent, const char *name)
{
    struct dlist *dl = dlist_child(parent, name);
    dl->type = DL_KVLIST;
    return dl;
}

EXPORTED struct dlist *dlist_newlist(struct dlist *parent, const char *name)
{
    struct dlist *dl = dlist_child(parent, name);
    dl->type = DL_ATOMLIST;
    return dl;
}

EXPORTED struct dlist *dlist_newpklist(struct dlist *parent, const char *name)
{
    struct dlist *dl = dlist_child(parent, name);
    dl->type = DL_ATOMLIST;
    dl->nval = 1;
    return dl;
}

EXPORTED struct dlist *dlist_setatom(struct dlist *parent, const char *name, const char *val)
{
    struct dlist *dl = dlist_child(parent, name);
    dlist_makeatom(dl, val);
    return dl;
}

EXPORTED struct dlist *dlist_setflag(struct dlist *parent, const char *name, const char *val)
{
    struct dlist *dl = dlist_child(parent, name);
    dlist_makeflag(dl, val);
    return dl;
}

EXPORTED struct dlist *dlist_setnum64(struct dlist *parent, const char *name, bit64 val)
{
    struct dlist *dl = dlist_child(parent, name);
    dlist_makenum64(dl, val);
    return dl;
}

EXPORTED struct dlist *dlist_setnum32(struct dlist *parent, const char *name, uint32_t val)
{
    struct dlist *dl = dlist_child(parent, name);
    dlist_makenum32(dl, val);
    return dl;
}

EXPORTED struct dlist *dlist_setdate(struct dlist *parent, const char *name, time_t val)
{
    struct dlist *dl = dlist_child(parent, name);
    dlist_makedate(dl, val);
    return dl;
}

EXPORTED struct dlist *dlist_sethex64(struct dlist *parent, const char *name, bit64 val)
{
    struct dlist *dl = dlist_child(parent, name);
    dlist_makehex64(dl, val);
    return dl;
}

EXPORTED struct dlist *dlist_setmap(struct dlist *parent, const char *name,
                           const char *val, size_t len)
{
    struct dlist *dl = dlist_child(parent, name);
    dlist_makemap(dl, val, len);
    return dl;
}

EXPORTED struct dlist *dlist_setguid(struct dlist *parent, const char *name,
                                     const struct message_guid *guid)
{
    struct dlist *dl = dlist_child(parent, name);
    dlist_makeguid(dl, guid);
    return dl;
}

EXPORTED struct dlist *dlist_setfile(struct dlist *parent, const char *name,
                                     const char *part, const struct message_guid *guid,
                                     size_t size, const char *fname)
{
    struct dlist *dl = dlist_child(parent, name);
    dlist_makefile(dl, part, guid, size, fname);
    return dl;
}

static struct dlist *dlist_updatechild(struct dlist *parent, const char *name)
{
    struct dlist *dl = dlist_getchild(parent, name);
    if (!dl) dl = dlist_child(parent, name);
    return dl;
}

struct dlist *dlist_updateatom(struct dlist *parent, const char *name, const char *val)
{
    struct dlist *dl = dlist_updatechild(parent, name);
    dlist_makeatom(dl, val);
    return dl;
}

struct dlist *dlist_updateflag(struct dlist *parent, const char *name, const char *val)
{
    struct dlist *dl = dlist_updatechild(parent, name);
    dlist_makeflag(dl, val);
    return dl;
}

struct dlist *dlist_updatenum64(struct dlist *parent, const char *name, bit64 val)
{
    struct dlist *dl = dlist_updatechild(parent, name);
    dlist_makenum64(dl, val);
    return dl;
}

struct dlist *dlist_updatenum32(struct dlist *parent, const char *name, uint32_t val)
{
    struct dlist *dl = dlist_updatechild(parent, name);
    dlist_makenum32(dl, val);
    return dl;
}

struct dlist *dlist_updatedate(struct dlist *parent, const char *name, time_t val)
{
    struct dlist *dl = dlist_updatechild(parent, name);
    dlist_makedate(dl, val);
    return dl;
}

struct dlist *dlist_updatehex64(struct dlist *parent, const char *name, bit64 val)
{
    struct dlist *dl = dlist_updatechild(parent, name);
    dlist_makehex64(dl, val);
    return dl;
}

struct dlist *dlist_updatemap(struct dlist *parent, const char *name,
                           const char *val, size_t len)
{
    struct dlist *dl = dlist_updatechild(parent, name);
    dlist_makemap(dl, val, len);
    return dl;
}

struct dlist *dlist_updateguid(struct dlist *parent, const char *name,
                               const struct message_guid *guid)
{
    struct dlist *dl = dlist_updatechild(parent, name);
    dlist_makeguid(dl, guid);
    return dl;
}

struct dlist *dlist_updatefile(struct dlist *parent, const char *name,
                               const char *part, const struct message_guid *guid,
                               size_t size, const char *fname)
{
    struct dlist *dl = dlist_updatechild(parent, name);
    dlist_makefile(dl, part, guid, size, fname);
    return dl;
}

EXPORTED void dlist_print(const struct dlist *dl, int printkeys,
                 struct protstream *out)
{
    struct dlist *di;

    if (printkeys) {
        prot_printastring(out, dl->name);
        prot_putc(' ', out);
    }

    switch (dl->type) {
    case DL_NIL:
        prot_printf(out, "NIL");
        break;
    case DL_ATOM:
        prot_printastring(out, dl->sval);
        break;
    case DL_FLAG:
        prot_printf(out, "%s", dl->sval);
        break;
    case DL_NUM:
    case DL_DATE: /* for now, we will format it later */
        prot_printf(out, "%llu", dl->nval);
        break;
    case DL_FILE:
        printfile(out, dl);
        break;
    case DL_BUF:
        if (strlen(dl->sval) == dl->nval)
            prot_printastring(out, dl->sval);
        else
            prot_printliteral(out, dl->sval, dl->nval);
        break;
    case DL_GUID:
        prot_printf(out, "%s", message_guid_encode(dl->gval));
        break;
    case DL_HEX:
        {
            char buf[17];
            snprintf(buf, 17, "%016llx", dl->nval);
            prot_printf(out, "%s", buf);
        }
        break;
    case DL_KVLIST:
        prot_printf(out, "%%(");
        for (di = dl->head; di; di = di->next) {
            dlist_print(di, 1, out);
            if (di->next) {
                prot_printf(out, " ");
            }
        }
        prot_printf(out, ")");
        break;
    case DL_ATOMLIST:
        prot_printf(out, "(");
        for (di = dl->head; di; di = di->next) {
            dlist_print(di, dl->nval, out);
            if (di->next)
                prot_printf(out, " ");
        }
        prot_printf(out, ")");
        break;
    }
}

EXPORTED void dlist_printbuf(const struct dlist *dl, int printkeys, struct buf *outbuf)
{
    struct protstream *outstream;

    outstream = prot_writebuf(outbuf);
    dlist_print(dl, printkeys, outstream);
    prot_flush(outstream);
    prot_free(outstream);
}

EXPORTED void dlist_unlink_files(struct dlist *dl)
{
    struct dlist *i;

    if (!dl) return;

    for (i = dl->head; i; i = i->next) {
        dlist_unlink_files(i);
    }

    if (dl->type != DL_FILE) return;

    if (!dl->sval) return;

    syslog(LOG_DEBUG, "%s: unlinking %s", __func__, dl->sval);
    unlink(dl->sval);
}

EXPORTED void dlist_free(struct dlist **dlp)
{
    if (!*dlp) return;
    _dlist_clean(*dlp);
    free((*dlp)->name);
    free(*dlp);
    *dlp = NULL;
}

struct dlist_stack_node {
    const struct dlist *dl;
    int printkeys;
    struct dlist_stack_node *next;
};

struct dlist_print_iter {
    int printkeys;
    struct dlist_stack_node *parent;
    const struct dlist *next;
};

EXPORTED struct dlist_print_iter *dlist_print_iter_new(const struct dlist *dl, int printkeys)
{
    struct dlist_print_iter *iter = xzmalloc(sizeof *iter);
    iter->printkeys = printkeys;
    iter->next = dl;

    return iter;
}

EXPORTED const char *dlist_print_iter_step(struct dlist_print_iter *iter, struct buf *outbuf)
{
    /* already finished */
    if (!iter->next) return NULL;

    buf_reset(outbuf);

    /* Bundle short steps together to minimise call overhead.
     * Note that outbuf can grow significantly longer than this limit, if a
     * single item in the dlist is very long (e.g. a message), but then it
     * won't bundle up more than that.
     */
    while (iter->next != NULL && buf_len(outbuf) < 1024) {
        const struct dlist *curr = iter->next;
        struct dlist_stack_node *parent = NULL;
        int descend = 0;

        /* output */
        switch (curr->type) {
        case DL_KVLIST:
        case DL_ATOMLIST:
            // XXX should use equiv to "prot_printastring" for curr->name
            if (iter->printkeys)
                buf_printf(outbuf, "%s ", curr->name);

            buf_appendcstr(outbuf, curr->type == DL_KVLIST ? "%(" : "(");

            if (curr->head) {
                descend = 1;
            }
            else {
                buf_putc(outbuf, ')');
                if (curr->next)
                    buf_putc(outbuf, ' ');
            }
            break;

        default:
            dlist_printbuf(curr, iter->printkeys, outbuf);
            if (curr->next)
                buf_putc(outbuf, ' ');
            break;
        }

        /* increment */
        if (descend) {
            parent = xmalloc(sizeof *parent);
            parent->printkeys = iter->printkeys;
            parent->dl = curr;
            parent->next = iter->parent;
            iter->parent = parent;
            iter->next = curr->head;
            // XXX can this always be 1? we know an atom list here is non-empty
            iter->printkeys = curr->type == DL_KVLIST ? 1 : curr->nval;
        }
        else if (curr->next) {
            iter->next = curr->next;
        }
        else if (iter->parent) {
            /* multiple parents might be ending at the same point
             * don't mistake one parent ending for end of entire tree
             */
            do {
                buf_putc(outbuf, ')');

                parent = iter->parent;

                iter->parent = iter->parent->next;
                iter->next = parent->dl->next;
                iter->printkeys = parent->printkeys;

                free(parent);

                if (iter->next) {
                    /* found an unfinished dlist, stop closing parents */
                    buf_putc(outbuf, ' ');
                    break;
                }
            } while (iter->parent);
        }
        else {
            iter->next = NULL;
        }
    }

    /* and return */
    return buf_cstringnull(outbuf);
}

EXPORTED void dlist_print_iter_free(struct dlist_print_iter **iterp)
{
    struct dlist_print_iter *iter = *iterp;
    struct dlist_stack_node *tmp = NULL;

    *iterp = NULL;

    while (iter->parent) {
        tmp = iter->parent;
        iter->parent = iter->parent->next;
        free(tmp);
    }

    free(iter);
}

struct dlistsax_state {
    const char *base;
    const char *p;
    const char *end;
    dlistsax_cb_t *proc;
    int depth;
    struct dlistsax_data d;
    struct buf buf;
    struct buf gbuf;
};

#ifdef HAVE_DECLARE_OPTIMIZE
static int _parseqstring(struct dlistsax_state *s, struct buf *buf)
    __attribute__((optimize("-O3")));
static int _parseliteral(struct dlistsax_state *s, struct buf *buf)
    __attribute__((optimize("-O3")));
static int _parseitem(struct dlistsax_state *s, struct buf *buf)
    __attribute__((optimize("-O3")));
#endif

static int _parseqstring(struct dlistsax_state *s, struct buf *buf)
{
    buf->len = 0;

    /* get over the first quote */
    if (*s->p++ != '"') return IMAP_INVALID_IDENTIFIER;

    while (s->p < s->end) {
        /* found the end quote */
        if (*s->p == '"') {
            s->p++;
            return 0;
        }
        /* backslash just quotes the next char, no matter what it is */
        if (*s->p == '\\') {
            s->p++;
            if (s->p == s->end) break;
            /* fall through */
        }

        buf_putc(buf, *s->p++);
    }

    return IMAP_INVALID_IDENTIFIER;
}

static int _parseliteral(struct dlistsax_state *s, struct buf *buf)
{
    size_t len = 0;

    if (*s->p++ != '{') return IMAP_INVALID_IDENTIFIER;

    while (s->p < s->end) {
        if (cyrus_isdigit(*s->p)) {
            len = (len * 10) + (*s->p++ - '0');
            continue;
        }

        // skip literal+ if present
        if (*s->p == '+' && (s->p + 1 < s->end))
            s->p++;

        // we'd better be at the end of the literal
        if (*s->p == '}') {
            if (s->p + 3 + len >= s->end) break;
            if (s->p[1] != '\r') break;
            if (s->p[2] != '\n') break;
            buf_truncate(buf, 0);
            buf_appendmap(buf, s->p + 3, len);
            s->p += len + 3;
            return 0;
        }

        break;
    }

    return IMAP_INVALID_IDENTIFIER;
}

static int _parseitem(struct dlistsax_state *s, struct buf *buf)
{
    const char *sp;

    /* this is much faster than setmap because it doesn't
     * do a reset and check the MMAP flag */
    buf_truncate(buf, 0);

    switch (*s->p) {
    case '"':
        return _parseqstring(s, buf);

    case '{':
        return _parseliteral(s, buf);

    default:
        sp = memchr(s->p, ' ', s->end - s->p);
        if (!sp) sp = s->end;
        while (sp[-1] == ')' && sp > s->p) sp--;
        buf_appendmap(buf, s->p, sp - s->p);
        s->p = sp;
        if (buf->len == 3 && buf->s[0] == 'N' && buf->s[1] == 'I' && buf->s[2] == 'L')
            return IMAP_ZERO_LENGTH_LITERAL; // this is kinda bogus, but...
        return 0; /* this could be the last thing, so end is OK */
    }
}

static int _parsesax(struct dlistsax_state *s, int parsekey)
{
    int r = 0;

    s->depth++;

    /* handle the key if wanted */
    struct buf *backdoor = (struct buf *)(&s->d.kbuf);
    if (parsekey) {
        r = _parseitem(s, backdoor);
        if (r) return r;
        if (s->p >= s->end) return IMAP_INVALID_IDENTIFIER;
        if (*s->p == ' ') s->p++;
        else return IMAP_INVALID_IDENTIFIER;
    }
    else {
        backdoor->len = 0;
    }

    if (s->p >= s->end) return IMAP_INVALID_IDENTIFIER;

    /* check what sort of value we have */
    if (*s->p == '(') {
        r = s->proc(DLISTSAX_LISTSTART, &s->d);
        if (r) return r;

        s->p++;
        if (s->p >= s->end) return IMAP_INVALID_IDENTIFIER;

        while (*s->p != ')') {
            r = _parsesax(s, 0);
            if (r) return r;
            if (*s->p == ')') break;
            if (*s->p == ' ') s->p++;
            else return IMAP_INVALID_IDENTIFIER;
            if (s->p >= s->end) return IMAP_INVALID_IDENTIFIER;
        }

        r = s->proc(DLISTSAX_LISTEND, &s->d);
        if (r) return r;

        s->p++;
    }
    else if (*s->p == '%') {
        s->p++;
        if (s->p >= s->end) return IMAP_INVALID_IDENTIFIER;
        /* no whitespace allowed here */
        if (*s->p == '(') {
            r = s->proc(DLISTSAX_KVLISTSTART, &s->d);
            if (r) return r;

            s->p++;
            if (s->p >= s->end) return IMAP_INVALID_IDENTIFIER;

            while (*s->p != ')') {
                r = _parsesax(s, 1);
                if (r) return r;
                if (*s->p == ')') break;
                if (*s->p == ' ') s->p++;
                else return IMAP_INVALID_IDENTIFIER;
                if (s->p >= s->end) return IMAP_INVALID_IDENTIFIER;
            }

            r = s->proc(DLISTSAX_KVLISTEND, &s->d);
            if (r) return r;

            s->p++;
        }
        else {
            /* unknown percent type */
            return IMAP_INVALID_IDENTIFIER;
        }
    }
    else {
        r = _parseitem(s, &s->buf);
        if (r == IMAP_ZERO_LENGTH_LITERAL)
            s->d.data = NULL; // NIL
        else if (r) return r;
        else
            s->d.data = buf_cstring(&s->buf);
        r = s->proc(DLISTSAX_STRING, &s->d);
        s->d.data = NULL; // zero out for next call
        if (r) return r;
    }

    s->depth--;

    /* success */
    return 0;
}

EXPORTED int dlist_parsesax(const char *base, size_t len, int parsekey,
                            dlistsax_cb_t *proc, void *rock)
{
    static struct dlistsax_state state;
    int r;

    state.base = base;
    state.p = base;
    state.end = base + len;
    state.proc = proc;
    state.d.rock = rock;

    r = _parsesax(&state, parsekey);

    if (r) return r;

    if (state.p < state.end)
        return IMAP_IOERROR;

    return 0;
}

static char next_nonspace(struct protstream *in, char c)
{
    while (Uisspace(c)) c = prot_getc(in);
    return c;
}

EXPORTED int dlist_parse(struct dlist **dlp, int parsekey, int isbackup,
                          struct protstream *in)
{
    struct dlist *dl = NULL;
    static struct buf kbuf;
    static struct buf vbuf;
    int c;

    /* handle the key if wanted */
    if (parsekey) {
        c = getastring(in, NULL, &kbuf);
        c = next_nonspace(in, c);
    }
    else {
        buf_setcstr(&kbuf, "");
        c = prot_getc(in);
    }

    /* connection dropped? */
    if (c == EOF) goto fail;

    /* check what sort of value we have */
    if (c == '(') {
        dl = dlist_newlist(NULL, kbuf.s);
        c = next_nonspace(in, ' ');
        while (c != ')') {
            struct dlist *di = NULL;
            prot_ungetc(c, in);
            c = dlist_parse(&di, 0, isbackup, in);
            if (di) dlist_stitch(dl, di);
            c = next_nonspace(in, c);
            if (c == EOF) goto fail;
        }
        c = prot_getc(in);
    }
    else if (c == '%') {
        /* no whitespace allowed here */
        c = prot_getc(in);
        if (c == '(') {
            dl = dlist_newkvlist(NULL, kbuf.s);
            c = next_nonspace(in, ' ');
            while (c != ')') {
                struct dlist *di = NULL;
                prot_ungetc(c, in);
                c = dlist_parse(&di, 1, isbackup, in);
                if (di) dlist_stitch(dl, di);
                c = next_nonspace(in, c);
                if (c == EOF) goto fail;
            }
        }
        else if (c == '{') {
            struct message_guid tmp_guid;
            static struct buf pbuf, gbuf;
            unsigned size = 0;
            const char *fname;
            c = getastring(in, NULL, &pbuf);
            if (c != ' ') goto fail;
            c = getastring(in, NULL, &gbuf);
            if (c != ' ') goto fail;
            c = getuint32(in, &size);
            if (c != '}') goto fail;
            c = prot_getc(in);
            if (c == '\r') c = prot_getc(in);
            if (c != '\n') goto fail;
            if (!message_guid_decode(&tmp_guid, gbuf.s)) goto fail;
            if (reservefile(in, pbuf.s, &tmp_guid, size, isbackup, &fname)) goto fail;
            dl = dlist_setfile(NULL, kbuf.s, pbuf.s, &tmp_guid, size, fname);
            /* file literal */
        }
        else {
            /* unknown percent type */
            goto fail;
        }
        c = prot_getc(in);
    }
    else if (c == '{') {
        prot_ungetc(c, in);
        /* could be binary in a literal */
        c = getbastring(in, NULL, &vbuf);
        dl = dlist_setmap(NULL, kbuf.s, vbuf.s, vbuf.len);
    }
    else if (c == '\\') { /* special case for flags */
        prot_ungetc(c, in);
        c = getastring(in, NULL, &vbuf);
        dl = dlist_setflag(NULL, kbuf.s, vbuf.s);
    }
    else {
        prot_ungetc(c, in);
        c = getnastring(in, NULL, &vbuf);
        dl = dlist_setatom(NULL, kbuf.s, vbuf.s);
    }

    /* success */
    *dlp = dl;
    return c;

fail:
    dlist_free(&dl);
    return EOF;
}

EXPORTED int dlist_parse_asatomlist(struct dlist **dlp, int parsekey,
                            struct protstream *in)
{
    int c = dlist_parse(dlp, parsekey, 0, in);

    /* make a list with one item */
    if (*dlp && !dlist_isatomlist(*dlp)) {
        struct dlist *tmp = dlist_newlist(NULL, "");
        dlist_stitch(tmp, *dlp);
        *dlp = tmp;
    }

    return c;
}

EXPORTED int dlist_parsemap(struct dlist **dlp, int parsekey, int isbackup,
                   const char *base, unsigned len)
{
    struct protstream *stream;
    int c;
    struct dlist *dl = NULL;

    stream = prot_readmap(base, len);
    prot_setisclient(stream, 1); /* don't sync literals */
    c = dlist_parse(&dl, parsekey, isbackup, stream);
    prot_free(stream);

    if (c != EOF) {
        dlist_free(&dl);
        return IMAP_IOERROR; /* failed to slurp entire buffer */
    }

    *dlp = dl;

    return 0;
}

EXPORTED struct dlist *dlist_getchild(struct dlist *dl, const char *name)
{
    struct dlist *i;

    if (!dl) return NULL;

    for (i = dl->head; i; i = i->next) {
        if (i->name && !strcmp(name, i->name))
            return i;
    }
    lastkey = name;
    return NULL;
}

EXPORTED struct dlist *dlist_getchildn(struct dlist *dl, int num)
{
    struct dlist *i;

    if (!dl) return NULL;

    for (i = dl->head; i && num; i = i->next)
        num--;

    return i;
}

/* duplicate the parent list as a new list, and then move @num
 * of the children from the parent onto the new list */
EXPORTED struct dlist *dlist_splice(struct dlist *dl, int num)
{
    struct dlist *ret = dlist_newlist(NULL, dl->name);

    /* clone exact type */
    ret->type = dl->type;
    ret->nval = dl->nval;

    if (num > 0) {
        struct dlist *end = dlist_getchildn(dl, num - 1);

        /* take the start of the list */
        ret->head = dl->head;

        /* leave the end (if any) */
        if (end) {
            ret->tail = end;
            dl->head = end->next;
            end->next = NULL;
        }
        else {
            ret->tail = dl->tail;
            dl->head = NULL;
            dl->tail = NULL;
        }
    }

    return ret;
}

EXPORTED void dlist_splat(struct dlist *parent, struct dlist *child)
{
    struct dlist *prev = NULL;
    struct dlist *replace;

    /* find old record */
    for (replace = parent->head; replace; replace = replace->next) {
        if (replace == child) break;
        prev = replace;
    }

    assert(replace);

    if (child->head) {
        /* stitch in children */
        if (prev) prev->next = child->head;
        else parent->head = child->head;
        if (child->next) child->tail->next = child->next;
        else parent->tail = child->tail;
    }
    else {
        /* just remove the record */
        if (prev) prev->next = child->next;
        else parent->head = child->next;
        if (!child->next) parent->tail = prev;
    }
    /* remove the node itself, carefully blanking out
     * the now unlinked children */
    child->head = NULL;
    child->tail = NULL;
    dlist_free(&child);
}

struct dlist *dlist_getkvchild_bykey(struct dlist *dl,
                                     const char *key, const char *val)
{
    struct dlist *i;
    struct dlist *tmp;

    if (!dl) return NULL;

    for (i = dl->head; i; i = i->next) {
        tmp = dlist_getchild(i, key);
        if (tmp && !strcmp(tmp->sval, val))
            return i;
    }

    return NULL;
}

int dlist_toatom(struct dlist *dl, const char **valp)
{
    const char *str;
    size_t len;

    if (!dl) return 0;

    /* atom can be NULL */
    if (dl->type == DL_NIL) {
        *valp = NULL;
        return 1;
    }

    /* tomap always adds a trailing \0 */
    if (!dlist_tomap(dl, &str, &len))
        return 0;

    /* got NULLs? */
    if (dl->type == DL_BUF && strlen(str) != len)
        return 0;

    if (valp) *valp = str;

    return 1;
}

HIDDEN int dlist_tomap(struct dlist *dl, const char **valp, size_t *lenp)
{
    char tmp[30];

    if (!dl) return 0;

    switch (dl->type) {
    case DL_NUM:
    case DL_DATE:
        snprintf(tmp, 30, "%llu", dl->nval);
        dlist_makeatom(dl, tmp);
        break;

    case DL_HEX:
        snprintf(tmp, 30, "%016llx", dl->nval);
        dlist_makeatom(dl, tmp);
        break;

    case DL_GUID:
        dlist_makeatom(dl, message_guid_encode(dl->gval));
        break;

    case DL_ATOM:
    case DL_FLAG:
    case DL_BUF:
    case DL_NIL:
        break;

    default:
        return 0;
    }

    if (valp) *valp = dl->sval;
    if (lenp) *lenp = dl->nval;

    return 1;
}

/* ensure value is exactly one number */
static int dlist_tonum64(struct dlist *dl, bit64 *valp)
{
    const char *end;
    bit64 newval;

    if (!dl) return 0;

    switch (dl->type) {
    case DL_ATOM:
    case DL_BUF:
        if (parsenum(dl->sval, &end, dl->nval, &newval))
            return 0;
        if (end - dl->sval != (int)dl->nval)
            return 0;
        /* successfully parsed - switch to a numeric value */
        dlist_makenum64(dl, newval);
        break;

    case DL_NUM:
    case DL_HEX:
    case DL_DATE:
        break;

    default:
        return 0;
    }

    if (valp) *valp = dl->nval;

    return 1;
}

EXPORTED int dlist_tonum32(struct dlist *dl, uint32_t *valp)
{
    bit64 v;

    if (dlist_tonum64(dl, &v)) {
        if (valp) *valp = (uint32_t)v;
        return 1;
    }

    return 0;
}

int dlist_todate(struct dlist *dl, time_t *valp)
{
    bit64 v;

    if (dlist_tonum64(dl, &v)) {
        if (valp) *valp = (time_t)v;
        dl->type = DL_DATE;
        return 1;
    }

    return 0;
}

static int dlist_tohex64(struct dlist *dl, bit64 *valp)
{
    const char *end = NULL;
    bit64 newval;

    if (!dl) return 0;

    switch (dl->type) {
    case DL_ATOM:
    case DL_BUF:
        if (parsehex(dl->sval, &end, dl->nval, &newval))
            return 0;
        if (end - dl->sval != (int)dl->nval)
            return 0;
        /* successfully parsed - switch to a numeric value */
        dlist_makehex64(dl, newval);
        break;

    case DL_NUM:
    case DL_HEX:
    case DL_DATE:
        dl->type = DL_HEX;
        break;

    default:
        return 0;
    }

    if (valp) *valp = dl->nval;

    return 1;
}

EXPORTED int dlist_toguid(struct dlist *dl, struct message_guid **valp)
{
    struct message_guid tmpguid;

    if (!dl) return 0;

    switch (dl->type) {
    case DL_ATOM:
    case DL_BUF:
        if (dl->nval != 40)
            return 0;
        if (!message_guid_decode(&tmpguid, dl->sval))
            return 0;
        /* successfully parsed - switch to guid value */
        dlist_makeguid(dl, &tmpguid);
        break;

    case DL_GUID:
        break;

    default:
        return 0;
    }

    if (valp) *valp = dl->gval;

    return 1;
}

EXPORTED int dlist_tofile(struct dlist *dl,
                 const char **partp, struct message_guid **guidp,
                 unsigned long *sizep, const char **fnamep)
{
    if (!dlist_isfile(dl)) return 0;

    if (guidp) *guidp = dl->gval;
    if (sizep) *sizep = dl->nval;
    if (fnamep) *fnamep = dl->sval;
    if (partp) *partp = dl->part;

    return 1;
}

EXPORTED int dlist_isatomlist(const struct dlist *dl)
{
    if (!dl) return 0;
    return (dl->type == DL_ATOMLIST);
}

int dlist_iskvlist(const struct dlist *dl)
{
    if (!dl) return 0;

    return (dl->type == DL_KVLIST);
}

int dlist_isfile(const struct dlist *dl)
{
    if (!dl) return 0;

    return (dl->type == DL_FILE);
}

/* XXX - these ones aren't const, because they can change
 * things... */
int dlist_isnum(struct dlist *dl)
{
    bit64 tmp;

    if (!dl) return 0;

    /* see if it can be parsed as a number */
    return dlist_tonum64(dl, &tmp);
}

/* XXX - these ones aren't const, because they can change
 * things... */
EXPORTED int dlist_ishex64(struct dlist *dl)
{
    bit64 tmp;

    if (!dl) return 0;

    /* see if it can be parsed as a number */
    return dlist_tohex64(dl, &tmp);
}

/* XXX - these ones aren't const, because they can change
 * things... */
int dlist_isguid(struct dlist *dl)
{
    struct message_guid *tmp = NULL;

    if (!dl) return 0;

    return dlist_toguid(dl, &tmp);
}

/* XXX - this stuff is all shitty, rationalise later */
EXPORTED bit64 dlist_num(struct dlist *dl)
{
    bit64 v;

    if (!dl) return 0;

    if (dlist_tonum64(dl, &v))
        return v;

    return 0;
}

/* XXX - this stuff is all shitty, rationalise later */
EXPORTED const char *dlist_cstring(struct dlist *dl)
{
    static char zerochar = '\0';

    if (dl) {
        const char *res = NULL;
        dlist_toatom(dl, &res);
        if (res) return res;
    }

    return &zerochar;
}

EXPORTED int dlist_getatom(struct dlist *parent, const char *name, const char **valp)
{
    struct dlist *child = dlist_getchild(parent, name);
    return dlist_toatom(child, valp);
}

EXPORTED int dlist_getnum32(struct dlist *parent, const char *name, uint32_t *valp)
{
    struct dlist *child = dlist_getchild(parent, name);
    return dlist_tonum32(child, valp);
}

EXPORTED int dlist_getnum64(struct dlist *parent, const char *name, bit64 *valp)
{
    struct dlist *child = dlist_getchild(parent, name);
    return dlist_tonum64(child, valp);
}

EXPORTED int dlist_getdate(struct dlist *parent, const char *name, time_t *valp)
{
    struct dlist *child = dlist_getchild(parent, name);
    return dlist_todate(child, valp);
}

EXPORTED int dlist_gethex64(struct dlist *parent, const char *name, bit64 *valp)
{
    struct dlist *child = dlist_getchild(parent, name);
    return dlist_tohex64(child, valp);
}

EXPORTED int dlist_getguid(struct dlist *parent, const char *name,
                  struct message_guid **valp)
{
    struct dlist *child = dlist_getchild(parent, name);
    return dlist_toguid(child, valp);
}

EXPORTED int dlist_getmap(struct dlist *parent, const char *name,
                 const char **valp, size_t *lenp)
{
    struct dlist *child = dlist_getchild(parent, name);
    return dlist_tomap(child, valp, lenp);
}

EXPORTED int dlist_getbuf(struct dlist *parent, const char *name,
                          struct buf *value)
{
    const char *v = NULL;
    size_t l = 0;
    if (dlist_getmap(parent, name, &v, &l)) {
        buf_init_ro(value, v, l);
        return 1;
    }
    return 0;
}

int dlist_getfile(struct dlist *parent, const char *name,
                  const char **partp,
                  struct message_guid **guidp,
                  unsigned long *sizep,
                  const char **fnamep)
{
    struct dlist *child = dlist_getchild(parent, name);
    return dlist_tofile(child, partp, guidp, sizep, fnamep);
}

EXPORTED int dlist_getlist(struct dlist *dl, const char *name, struct dlist **valp)
{
    struct dlist *i = dlist_getchild(dl, name);
    if (!i) return 0;
    *valp = i;
    return 1;
}

EXPORTED const char *dlist_lastkey(void)
{
    return lastkey;
}
