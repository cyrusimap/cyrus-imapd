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
 *
 * $Id: sync_support.c,v 1.25 2010/01/06 17:01:41 murch Exp $
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
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <utime.h>

#include "global.h"
#include "assert.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "quota.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "acl.h"
#include "seen.h"
#include "mboxname.h"
#include "map.h"
#include "imapd.h"
#include "imparse.h"
#include "message.h"
#include "util.h"
#include "retry.h"
#include "cyr_lock.h"
#include "prot.h"

#include "dlist.h"

/* Parse routines */

const char *lastkey = NULL;

static void printfile(struct protstream *out, const struct dlist *dl)
{
    struct stat sbuf;
    FILE *f;
    unsigned long size;
    struct message_guid guid2;
    const char *msg_base = NULL;
    unsigned long msg_len = 0;

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

    if (!message_guid_equal(&guid2, (struct message_guid *) &dl->gval)) {
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
    prot_printastring(out, message_guid_encode(&dl->gval));
    prot_printf(out, " %lu}\r\n", size);
    prot_write(out, msg_base, msg_len);
    fclose(f);
    map_free(&msg_base, &msg_len);
}

/* XXX - these two functions should be out in append.c or reserve.c
 * or something more general */
const char *dlist_reserve_path(const char *part, struct message_guid *guid)
{
    static char buf[MAX_MAILBOX_PATH];
    snprintf(buf, MAX_MAILBOX_PATH, "%s/sync./%lu/%s",
		  config_partitiondir(part), (unsigned long)getpid(),
		  message_guid_encode(guid));
    cyrus_mkdir(buf, 0755);
    return buf;
}

static int reservefile(struct protstream *in, const char *part,
		       struct message_guid *guid, unsigned long size,
		       const char **fname)
{
    FILE *file;
    char buf[8192+1];
    int r = 0, n;
    
    /* XXX - write to a temporary file then move in to place! */
    *fname = dlist_reserve_path(part, guid);

    file = fopen(*fname, "w+");
    if (!file) {
	syslog(LOG_ERR, "Failed to upload file %s", message_guid_encode(guid));
	r = IMAP_IOERROR;
	/* Note: we still read the file's data from the wire,
	 * to avoid losing protocol sync */
    }

    /* XXX - calculate sha1 on the fly? */
    while (size) {
	n = prot_read(in, buf, size > 8192 ? 8192 : size);
	if (!n) {
	    syslog(LOG_ERR,
		"IOERROR: reading message: unexpected end of file");
	    r = IMAP_IOERROR;
	    break;
	}
	size -= n;
	if (!r) fwrite(buf, 1, n, file);
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

void dlist_stitch(struct dlist *dl, struct dlist *child)
{
    if (dl->tail)
	dl->tail = dl->tail->next = child;
    else
	dl->head = dl->tail = child;
}

static struct dlist *dlist_child(struct dlist *dl, const char *name)
{
    struct dlist *i = xzmalloc(sizeof(struct dlist));
    i->name = xstrdup(name);
    i->type = DL_NIL;
    if (dl)
	dlist_stitch(dl, i);
    return i;
}

struct dlist *dlist_atom(struct dlist *dl, const char *name, const char *val)
{
    struct dlist *i = dlist_child(dl, name);
    i->type = DL_ATOM;
    i->sval = xstrdup(val);
    return i;
}

struct dlist *dlist_flag(struct dlist *dl, const char *name, const char *val)
{
    struct dlist *i = dlist_child(dl, name);
    i->type = DL_FLAG;
    i->sval = xstrdup(val);
    return i;
}

struct dlist *dlist_num(struct dlist *dl, const char *name, unsigned long val)
{
    struct dlist *i = dlist_child(dl, name);
    i->type = DL_NUM;
    i->nval = (modseq_t)val;
    return i;
}

struct dlist *dlist_date(struct dlist *dl, const char *name, time_t val)
{
    struct dlist *i = dlist_child(dl, name);
    i->type = DL_DATE;
    i->nval = (modseq_t)val;
    return i;
}

struct dlist *dlist_modseq(struct dlist *dl, const char *name, modseq_t val)
{
    struct dlist *i = dlist_child(dl, name);
    i->type = DL_MODSEQ;
    i->nval = val;
    return i;
}

struct dlist *dlist_guid(struct dlist *dl, const char *name,
			   struct message_guid *guid)
{
    struct dlist *i = dlist_child(dl, name);
    i->type = DL_GUID,
    message_guid_copy(&i->gval, guid);
    return i;
}

struct dlist *dlist_file(struct dlist *dl, const char *name,
			   const char *part,
			   struct message_guid *guid,
			   unsigned long size,
			   const char *fname)
{
    struct dlist *i = dlist_child(dl, name);
    i->type = DL_FILE;
    message_guid_copy(&i->gval, guid);
    i->sval = xstrdup(fname);
    i->nval = size;
    i->part = xstrdup(part);
    return i;
}

struct dlist *dlist_buf(struct dlist *dl, const char *name,
		        const char *val, size_t len)
{
    struct dlist *i = dlist_child(dl, name);
    i->type = DL_BUF;
    i->sval = xmalloc(len+1);
    memcpy(i->sval, val, len);
    i->sval[len] = '\0'; /* make it string safe too */
    i->nval = len;
    return i;
}

struct dlist *dlist_kvlist(struct dlist *dl, const char *name)
{
    struct dlist *i = dlist_child(dl, name);
    i->type = DL_KVLIST;
    return i;
}

struct dlist *dlist_list(struct dlist *dl, const char *name)
{
    struct dlist *i = dlist_child(dl, name);
    i->type = DL_ATOMLIST;
    return i;
}

struct dlist *dlist_new(const char *name)
{
    return dlist_kvlist(NULL, name);
}

static void dlist_print_helper(const struct dlist *dl, int printkeys,
			       struct protstream *out, int level)
{
    struct dlist *di;
    int i;

    if (printkeys)
	prot_printf(out, "%s ", dl->name);

    switch (dl->type) {
    case DL_ATOM:
	prot_printastring(out, dl->sval);
	break;
    case DL_FLAG:
	prot_printf(out, "%s", dl->sval);
	break;
    case DL_NUM:
    case DL_DATE: /* for now, we will format it later */
    case DL_MODSEQ:
	prot_printf(out, MODSEQ_FMT, dl->nval);
	break;
    case DL_FILE:
	printfile(out, dl);
	break;
    case DL_BUF:
	prot_printliteral(out, dl->sval, dl->nval);
	break;
    case DL_KVLIST:
	if (level) {
	    prot_printf(out, "\r\n");
	    for (i = 0; i <= level; i++)
		prot_printf(out, " ");
	}
	prot_printf(out, "%%(");
	for (di = dl->head; di; di = di->next) {
	    dlist_print_helper(di, 1, out, level);
	    if (di->next) {
		prot_printf(out, " ");
	    }
	}
	prot_printf(out, ")");
	break;
    case DL_ATOMLIST:
	prot_printf(out, "(");
	for (di = dl->head; di; di = di->next) {
	    dlist_print_helper(di, 0, out, di->type == DL_KVLIST ? level + 1 : level);
	    if (di->next)
		prot_printf(out, " ");
	}
	prot_printf(out, ")");
	break;
    }
}

void dlist_print(const struct dlist *dl, int printkeys, struct protstream *out)
{
    dlist_print_helper(dl, printkeys, out, 0);
}

void dlist_free(struct dlist **dlp)
{
    struct dlist *i, *next;
    if (!*dlp) return;
    i = (*dlp)->head;
    while (i) {
	free(i->name);
	next = i->next;
	switch (i->type) {
	case DL_KVLIST:
	case DL_ATOMLIST:
	    dlist_free(&i);
	    break;
	case DL_FILE:
	    free(i->part);
	    /* drop through */
	default:
	    free(i->sval);
	}
	free(i);
	i = next;
    }
    free(*dlp);
    *dlp = NULL;
}

static char next_nonspace(struct protstream *in, char c)
{
    while (Uisspace(c)) {
	c = prot_getc(in);
    }
    return c;
}

char dlist_parse(struct dlist **dlp, int parsekey, struct protstream *in)
{
    struct dlist *dl = NULL;
    static struct buf kbuf;
    static struct buf vbuf;
    char c;

    /* handle the key if wanted */
    if (parsekey) {
	c = getword(in, &kbuf);
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
	dl = dlist_list(NULL, kbuf.s);
	c = next_nonspace(in, ' ');
	while (c != ')') {
	    struct dlist *di = NULL;
	    prot_ungetc(c, in);
	    c = dlist_parse(&di, 0, in);
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
	    dl = dlist_list(NULL, kbuf.s);
	    c = next_nonspace(in, ' ');
	    while (c != ')') {
		struct dlist *di = NULL;
		prot_ungetc(c, in);
		c = dlist_parse(&di, 1, in);
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
	    if (reservefile(in, pbuf.s, &tmp_guid, size, &fname)) goto fail;
	    dl = dlist_file(NULL, kbuf.s, pbuf.s, &tmp_guid, size, fname);
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
	dl = dlist_buf(NULL, kbuf.s, vbuf.s, vbuf.len);
    }
    else {
	prot_ungetc(c, in);
	c = getastring(in, NULL, &vbuf);
	dl = dlist_atom(NULL, kbuf.s, vbuf.s);
	if (imparse_isnumber(vbuf.s))
	    dl->nval = atomodseq_t(vbuf.s);
    }

    /* success */
    *dlp = dl;
    return c;

fail:
    dlist_free(&dl);
    return EOF;
}

static struct dlist *dlist_getchild(struct dlist *dl, const char *name)
{
    struct dlist *i;

    if (!dl) return NULL;

    for (i = dl->head; i; i = i->next) {
	if (!strcmp(name, i->name))
	    return i;
    }
    lastkey = name;
    return NULL;
}

/* XXX - type coercion logic here */

int dlist_getatom(struct dlist *dl, const char *name, const char **val)
{
    struct dlist *i = dlist_getchild(dl, name);
    if (!i) return 0;
    *val = i->sval;
    return 1;
}

int dlist_getbuf(struct dlist *dl, const char *name, const char **val, size_t *len)
{
    struct dlist *i = dlist_getchild(dl, name);
    if (!i) return 0;
    *val = i->sval;
    *len = (size_t)i->nval;
    return 1;
}

int dlist_getnum(struct dlist *dl, const char *name, uint32_t *val)
{
    struct dlist *i = dlist_getchild(dl, name);
    if (!i) return 0;
    *val = (uint32_t)i->nval;
    return 1;
}

int dlist_getdate(struct dlist *dl, const char *name, time_t *val)
{
    struct dlist *i = dlist_getchild(dl, name);
    if (!i) return 0;
    /* XXX: string parse when the date format changes */
    *val = (time_t)i->nval;
    return 1;
}

int dlist_getmodseq(struct dlist *dl, const char *name, modseq_t *val)
{
    struct dlist *i = dlist_getchild(dl, name);
    if (!i) return 0;
    *val = (modseq_t)i->nval;
    return 1;
}

int dlist_getguid(struct dlist *dl, const char *name, struct message_guid **val)
{
    struct dlist *i = dlist_getchild(dl, name);
    if (!i) return 0;
    /* XXX - maybe malloc like strings? would save some in the general case */
    if (!message_guid_decode(&i->gval, i->sval)) return 0;
    *val = &i->gval;
    return 1;
}

int dlist_getfile(struct dlist *dl, const char *name,
		   const char **part,
		   struct message_guid **guid,
		   unsigned long *size,
		   const char **fname)
{
    struct dlist *i = dlist_getchild(dl, name);
    if (!i) return 0;
    if (!message_guid_decode(&i->gval, i->sval)) return 0;
    *guid = &i->gval;
    *size = i->nval;
    *fname = i->sval;
    *part = i->part;
    return 1;
}

int dlist_getlist(struct dlist *dl, const char *name, struct dlist **val)
{
    struct dlist *i = dlist_getchild(dl, name);
    if (!i) return 0;
    *val = i;
    return 1;
}

const char *dlist_lastkey()
{
    return lastkey;
}
