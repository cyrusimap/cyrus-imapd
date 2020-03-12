/* mboxlist.c -- Mailbox list manipulation routines
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sysexits.h>
#include <syslog.h>

#include <sys/ipc.h>
#include <sys/msg.h>

#include "acl.h"
#include "annotate.h"
#include "bsearch.h"
#include "glob.h"
#include "assert.h"
#include "global.h"
#include "cyrusdb.h"
#include "util.h"
#include "mailbox.h"
#include "mboxevent.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "partlist.h"
#include "xstrlcat.h"
#include "user.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "mboxname.h"
#include "mupdate-client.h"

#include "mboxlist.h"
#include "quota.h"
#include "sync_log.h"

#define DB config_mboxlist_db
#define SUBDB config_subscription_db

#define KEY_TYPE_NAME 'N'
#define KEY_TYPE_ID   'I'
#define KEY_TYPE_ACL  'A'

#define DB_DOMAINSEP_STR    "\x1D"  /* group separator (GS) */
#define DB_DOMAINSEP_CHAR   DB_DOMAINSEP_STR[0]
#define DB_HIERSEP_STR      "\x1F"  /* unit separator  (US) */
#define DB_HIERSEP_CHAR     DB_HIERSEP_STR[0]
#define DB_USER_PREFIX      "user" DB_HIERSEP_STR

static mbname_t *mbname_from_dbname(const char *dbname);
static char *mbname_dbname(const mbname_t *mbname);
static char *mboxname_from_dbname(const char *dbname);
static char *mboxname_to_dbname(const char *intname);

cyrus_acl_canonproc_t mboxlist_ensureOwnerRights;

static struct db *mbdb;

static int mboxlist_dbopen = 0;
static int mboxlist_initialized = 0;

static int have_racl = 0;

static int mboxlist_opensubs(const char *userid, struct db **ret);
static void mboxlist_closesubs(struct db *sub);

static int mboxlist_rmquota(const mbentry_t *mbentry, void *rock);
static int mboxlist_changequota(const mbentry_t *mbentry, void *rock);

static void init_internal();

EXPORTED mbentry_t *mboxlist_entry_create(void)
{
    mbentry_t *ret = xzmalloc(sizeof(mbentry_t));
    /* xxx - initialiser functions here? */
    return ret;
}

EXPORTED mbentry_t *mboxlist_entry_copy(const mbentry_t *src)
{
    mbentry_t *copy = mboxlist_entry_create();
    copy->name = xstrdupnull(src->name);
    copy->ext_name = xstrdupnull(src->ext_name);

    copy->mtime = src->mtime;
    copy->uidvalidity = src->uidvalidity;
    copy->mbtype = src->mbtype;
    copy->createdmodseq = src->createdmodseq;
    copy->foldermodseq = src->foldermodseq;

    copy->partition = xstrdupnull(src->partition);
    copy->server = xstrdupnull(src->server);
    copy->acl = xstrdupnull(src->acl);
    copy->uniqueid = xstrdupnull(src->uniqueid);

    copy->legacy_specialuse = xstrdupnull(src->legacy_specialuse);

    return copy;
}

EXPORTED void mboxlist_entry_free(mbentry_t **mbentryptr)
{
    mbentry_t *mbentry = *mbentryptr;

    /* idempotent */
    if (!mbentry) return;

    free(mbentry->name);
    free(mbentry->ext_name);

    free(mbentry->partition);
    free(mbentry->server);
    free(mbentry->acl);
    free(mbentry->uniqueid);

    free(mbentry->legacy_specialuse);

    former_name_t *fname;
    while ((fname = ptrarray_pop(&mbentry->name_history))) {
        free(fname);
    }
    ptrarray_fini(&mbentry->name_history);

    free(mbentry);

    *mbentryptr = NULL;
}

static void _write_acl(struct dlist *dl, const char *aclstr)
{
    const char *p, *q;
    struct dlist *al = dlist_newkvlist(dl, "A");

    p = aclstr;

    while (p && *p) {
        char *name,*val;

        q = strchr(p, '\t');
        if (!q) break;

        name = xstrndup(p, q-p);
        q++;

        p = strchr(q, '\t');
        if (p) {
            val = xstrndup(q, p-q);
            p++;
        }
        else
            val = xstrdup(q);

        dlist_setatom(al, name, val);

        free(name);
        free(val);
    }
}

EXPORTED const char *mboxlist_mbtype_to_string(uint32_t mbtype)
{
    static struct buf buf = BUF_INITIALIZER;

    buf_reset(&buf);

    /* mailbox types */
    switch (mbtype_isa(mbtype)) {
    case MBTYPE_EMAIL:
        buf_putc(&buf, 'e');
        break;
    case MBTYPE_NETNEWS:
        buf_putc(&buf, 'n');
        break;
    case MBTYPE_COLLECTION:
        buf_putc(&buf, 'b');
        break;
    case MBTYPE_CALENDAR:
        buf_putc(&buf, 'c');
        break;
    case MBTYPE_ADDRESSBOOK:
        buf_putc(&buf, 'a');
        break;
    case MBTYPE_JMAPNOTIFY:
        buf_putc(&buf, 'j');
        break;
    case MBTYPE_JMAPSUBMIT:
        buf_putc(&buf, 's');
        break;
    case MBTYPE_JMAPPUSHSUB:
        buf_putc(&buf, 'p');
        break;
    }

    /* mailbox flags */
    if (mbtype & MBTYPE_DELETED)
        buf_putc(&buf, 'd');
    if (mbtype & MBTYPE_MOVING)
        buf_putc(&buf, 'm');
    if (mbtype & MBTYPE_REMOTE)
        buf_putc(&buf, 'r');
    if (mbtype & MBTYPE_RESERVE)
        buf_putc(&buf, 'z');
    if (mbtype & MBTYPE_INTERMEDIATE)
        buf_putc(&buf, 'i');
    if (mbtype & MBTYPE_LEGACY_DIRS)
        buf_putc(&buf, 'l');

    /* make sure we didn't forget to set a character for every interesting bit */
    assert(buf_len(&buf));

    return buf_cstring(&buf);
}

static struct dlist *mboxlist_entry_dlist(const char *dbname,
                                          const mbentry_t *mbentry)
{
    struct dlist *dl = dlist_newkvlist(NULL, dbname);

    if (mbentry->uniqueid)
        dlist_setatom(dl, "I", mbentry->uniqueid);

    if (mbentry->partition)
        dlist_setatom(dl, "P", mbentry->partition);

    if (mbentry->server)
        dlist_setatom(dl, "S", mbentry->server);

    if (mbentry->mbtype)
        dlist_setatom(dl, "T", mboxlist_mbtype_to_string(mbentry->mbtype));

    if (mbentry->uidvalidity)
        dlist_setnum32(dl, "V", mbentry->uidvalidity);

    if (mbentry->createdmodseq)
        dlist_setnum64(dl, "C", mbentry->createdmodseq);

    if (mbentry->foldermodseq)
        dlist_setnum64(dl, "F", mbentry->foldermodseq);

    dlist_setdate(dl, "M", time(NULL));

    if (mbentry->acl)
        _write_acl(dl, mbentry->acl);

    return dl;
}

EXPORTED char *mbentry_metapath(const struct mboxlist_entry *mbentry, int metatype, int isnew)
{
    return mboxname_metapath(mbentry->partition,
                             mbentry->name,
                             mbentry->uniqueid,
                             metatype,
                             isnew);
}

EXPORTED char *mbentry_datapath(const struct mboxlist_entry *mbentry, uint32_t uid)
{
    return mboxname_datapath(mbentry->partition,
                             mbentry->name,
                             mbentry->uniqueid,
                             uid);
}

static void mboxlist_dbname_to_key(const char *dbname,
                                   size_t len, struct buf *key)
{
    buf_reset(key);
    buf_putc(key, KEY_TYPE_NAME);
    buf_appendmap(key, dbname, len);
}

static void mboxlist_dbname_from_key(const char *key, size_t len,
                                     struct buf *dbname)
{
    buf_init_ro(dbname, key+1, len-1);
}

static void mboxlist_id_to_key(const char *id, struct buf *key)
{
    buf_reset(key);
    buf_putc(key, KEY_TYPE_ID);
    buf_appendcstr(key, id);
}

/*
 * read a single _N_ame record from the mailboxes.db and return a pointer to it
 */
static int mboxlist_read_name(const char *dbname,
                              const char **dataptr, size_t *datalenptr,
                              struct txn **tid, int wrlock)
{
    struct buf key = BUF_INITIALIZER;
    int namelen = strlen(dbname);
    int r;

    if (!namelen)
        return IMAP_MAILBOX_NONEXISTENT;

    mboxlist_dbname_to_key(dbname, namelen, &key);

    if (wrlock) {
        r = cyrusdb_fetchlock(mbdb, buf_base(&key), buf_len(&key),
                              dataptr, datalenptr, tid);
    } else {
        r = cyrusdb_fetch(mbdb, buf_base(&key), buf_len(&key),
                          dataptr, datalenptr, tid);
    }

    switch (r) {
    case CYRUSDB_OK:
        /* no entry required, just checking if it exists */
        r = 0;
        break;

    case CYRUSDB_AGAIN:
        r = IMAP_AGAIN;
        break;

    case CYRUSDB_NOTFOUND:
        r = IMAP_MAILBOX_NONEXISTENT;
        break;

    default:
    {
        char *intname = mboxname_from_dbname(dbname);
        xsyslog(LOG_ERR, "DBERROR: error fetching mboxlist",
                         "mailbox=<%s> error=<%s>",
                         intname, cyrusdb_strerror(r));
        free(intname);
        r = IMAP_IOERROR;
        break;
    }
    }

    buf_free(&key);
    return r;
}

EXPORTED uint32_t mboxlist_string_to_mbtype(const char *string)
{
    uint32_t mbtype = 0;

    if (!string) return 0; /* null just means default */

    for (; *string; string++) {
        /* mailbox types */
        switch (*string) {
        case 'a':
            mbtype = MBTYPE_ADDRESSBOOK;
            break;
        case 'b':
            mbtype = MBTYPE_COLLECTION;
            break;
        case 'c':
            mbtype = MBTYPE_CALENDAR;
            break;
        case 'e':
            mbtype = MBTYPE_EMAIL;
            break;
        case 'j':
            mbtype = MBTYPE_JMAPNOTIFY;
            break;
        case 'n':
            mbtype = MBTYPE_NETNEWS;
            break;
        case 'p':
            mbtype = MBTYPE_JMAPPUSHSUB;
            break;
        case 's':
            mbtype = MBTYPE_JMAPSUBMIT;
            break;

            
        /* mailbox flags */
        case 'd':
            mbtype |= MBTYPE_DELETED;
            break;
        case 'i':
            mbtype |= MBTYPE_INTERMEDIATE;
            break;
        case 'l':
            mbtype |= MBTYPE_LEGACY_DIRS;
            break;
        case 'm':
            mbtype |= MBTYPE_MOVING;
            break;
        case 'r':
            mbtype |= MBTYPE_REMOTE;
            break;
        case 'z':
            mbtype |= MBTYPE_RESERVE;
            break;
        }
    }

    /* make sure we didn't forget to set a character for every interesting bit */
    assert(mbtype);

    return mbtype;
}

struct parseentry_rock {
    struct mboxlist_entry *mbentry;
    struct buf *aclbuf;
    int doingacl;
    int doinghistory;
};

static int parseentry_cb(int type, struct dlistsax_data *d)
{
    struct parseentry_rock *rock = (struct parseentry_rock *)d->rock;
    const char *key = buf_cstring(&d->kbuf);

    switch(type) {
    case DLISTSAX_LISTSTART:
        if (!strcmp(key, "H")) rock->doinghistory = 1;
        break;
    case DLISTSAX_LISTEND:
        if (rock->doinghistory) rock->doinghistory = 0;
        break;
    case DLISTSAX_KVLISTSTART:
        if (!strcmp(key, "A")) {
            rock->doingacl = 1;
        }
        else if (rock->doinghistory) {
            ptrarray_append(&rock->mbentry->name_history,
                            xzmalloc(sizeof(former_name_t)));
        }
        break;
    case DLISTSAX_KVLISTEND:
        if (rock->doingacl) rock->doingacl = 0;
        break;
    case DLISTSAX_STRING:
        if (rock->doingacl) {
            buf_append(rock->aclbuf, &d->kbuf);
            buf_putc(rock->aclbuf, '\t');
            buf_appendcstr(rock->aclbuf, d->data);
            buf_putc(rock->aclbuf, '\t');
        }
        else if (rock->doinghistory) {
            former_name_t *fname = ptrarray_tail(&rock->mbentry->name_history);

            if (!strcmp(key, "F")) {
                fname->foldermodseq = atomodseq_t(d->data);
            }
            else if (!strcmp(key, "M")) {
                fname->mtime = atoi(d->data);
            }
            else if (!strcmp(key, "N")) {
                xstrncpy(fname->dbname, d->data, MAX_MAILBOX_NAME);
            }
        }
        else {
            if (!strcmp(key, "C")) {
                rock->mbentry->createdmodseq = atomodseq_t(d->data);
            }
            else if (!strcmp(key, "F")) {
                rock->mbentry->foldermodseq = atomodseq_t(d->data);
            }
            else if (!strcmp(key, "I")) {
                rock->mbentry->uniqueid = xstrdupnull(d->data);
            }
            else if (!strcmp(key, "M")) {
                rock->mbentry->mtime = atoi(d->data);
            }
            else if (!strcmp(key, "N")) {
                if (!rock->mbentry->name)
                    rock->mbentry->name = mboxname_from_dbname(d->data);
            }
            else if (!strcmp(key, "P")) {
                rock->mbentry->partition = xstrdupnull(d->data);
            }
            else if (!strcmp(key, "S")) {
                rock->mbentry->server = xstrdupnull(d->data);
            }
            else if (!strcmp(key, "T")) {
                rock->mbentry->mbtype = mboxlist_string_to_mbtype(d->data);
            }
            else if (!strcmp(key, "V")) {
                rock->mbentry->uidvalidity = atol(d->data);
            }
        }
    }

    return 0;
}

/*
 * parse a record read from the mailboxes.db into its parts.
 *
 * full dlist format is:
 *  A: _a_cl
 *  C  _c_reatedmodseq
 *  F: _f_oldermodseq
 *  H: name_h_istory
 *  I: unique_i_d
 *  M: _m_time
 *  N: _n_ame
 *  P: _p_artition
 *  S: _s_erver
 *  T: _t_ype
 *  V: uid_v_alidity
 */
static int mboxlist_parse_entry(mbentry_t **mbentryptr,
                                const char *name, size_t namelen,
                                const char *data, size_t datalen)
{
    static struct buf aclbuf;
    int r = IMAP_MAILBOX_BADFORMAT;
    char *freeme = NULL;
    char **target;
    char *p, *q;
    mbentry_t *mbentry = mboxlist_entry_create();
    char mboxname[MAX_MAILBOX_NAME+1];

    if (!datalen)
        goto done;

    if (name) {
      /* copy name */
        snprintf(mboxname, MAX_MAILBOX_NAME, "%.*s",
                 (int) (namelen ? namelen : strlen(name)), name);
        mbentry->name = mboxname_from_dbname(mboxname);
    }

    /* check for DLIST mboxlist */
    if (*data == '%') {
        struct parseentry_rock rock;
        memset(&rock, 0, sizeof(struct parseentry_rock));
        rock.mbentry = mbentry;
        rock.aclbuf = &aclbuf;
        aclbuf.len = 0;
        r = dlist_parsesax(data, datalen, 0, parseentry_cb, &rock);
        if (!r) mbentry->acl = buf_newcstring(&aclbuf);
        goto done;
    }

    /* copy data */
    freeme = p = xstrndup(data, datalen);

    /* check for extended mboxlist entry */
    if (*p == '(') {
        int last = 0;
        p++; /* past leading '(' */
        while (!last) {
            target = NULL;
            q = p;
            while (*q && *q != ' ' && *q != ')') q++;
            if (*q != ' ') break;
            *q++ = '\0';
            if (!strcmp(p, "uniqueid")) target = &mbentry->uniqueid;
            if (!strcmp(p, "specialuse")) target = &mbentry->legacy_specialuse;
            p = q;
            while (*q && *q != ' ' && *q != ')') q++;
            if (*q != ' ') last = 1;
            if (*q) *q++ = '\0';
            if (target) *target = xstrdup(p);
            p = q;
        }
        if (*p == ' ') p++; /* past trailing ' ' */
    }

    /* copy out interesting parts */
    mbentry->mbtype = strtol(p, &p, 10);
    if (*p == ' ') p++;

    q = p;
    while (*q && *q != ' ' && *q != '!') q++;
    if (*q == '!') {
        *q++ = '\0';
        mbentry->server = xstrdup(p);
        p = q;
        while (*q && *q != ' ') q++;
    }
    if (*q) *q++ = '\0';
    mbentry->partition = xstrdup(p);

    mbentry->acl = xstrdup(q);

    r = 0;

done:
    if (!r && mbentryptr)
        *mbentryptr = mbentry;
    else mboxlist_entry_free(&mbentry);
    free(freeme);
    return r;
}

/* read a record and parse into parts */
static int mboxlist_mylookup(const char *dbname,
                             mbentry_t **mbentryptr,
                             struct txn **tid, int wrlock, int allow_all)
{
    int r;
    const char *data;
    size_t datalen;
    mbentry_t *entry = NULL;

    init_internal();

    r = mboxlist_read_name(dbname, &data, &datalen, tid, wrlock);
    if (r) return r;

    r = mboxlist_parse_entry(&entry, dbname, 0, data, datalen);
    if (r) return r;

    if (!allow_all) {
        /* Ignore "reserved" entries, like they aren't there */
        if (entry->mbtype & MBTYPE_RESERVE) {
            r = IMAP_MAILBOX_RESERVED;
        }

        /* Ignore "deleted" entries, like they aren't there */
        else if (entry->mbtype & MBTYPE_DELETED) {
            r = IMAP_MAILBOX_NONEXISTENT;
        }

        /* Ignore "intermediate" entries, like they aren't there */
        else if (entry->mbtype & MBTYPE_INTERMEDIATE) {
            r = IMAP_MAILBOX_NONEXISTENT;
        }
    }

    if (!r && mbentryptr) *mbentryptr = entry;
    else mboxlist_entry_free(&entry);

    return r;
}

/*
 * Lookup 'name' in the mailbox list, ignoring reserved records
 */
EXPORTED int mboxlist_lookup(const char *name,
                             mbentry_t **entryptr, struct txn **tid)
{
    char *dbname = mboxname_to_dbname(name);
    int r = mboxlist_mylookup(dbname, entryptr, tid,
                              0/*wrlock*/, 0/*allow_all*/);
    free(dbname);
    return r;
}

EXPORTED int mboxlist_lookup_allow_all(const char *name,
                                   mbentry_t **entryptr,
                                   struct txn **tid)
{
    char *dbname = mboxname_to_dbname(name);
    int r = mboxlist_mylookup(dbname, entryptr, tid,
                              0/*wrlock*/, 1/*allow_all*/);
    free(dbname);
    return r;
}

struct _find_specialuse_data {
    const char *use;
    const char *userid;
    char *mboxname;
};

static int _find_specialuse(const mbentry_t *mbentry, void *rock)
{
    struct _find_specialuse_data *d = (struct _find_specialuse_data *)rock;
    struct buf attrib = BUF_INITIALIZER;

    annotatemore_lookup(mbentry->name, "/specialuse", d->userid, &attrib);

    if (attrib.len) {
        strarray_t *uses = strarray_split(buf_cstring(&attrib), NULL, 0);
        if (strarray_find_case(uses, d->use, 0) >= 0)
            d->mboxname = xstrdup(mbentry->name);
        strarray_free(uses);
    }

    buf_free(&attrib);

    if (d->mboxname) return CYRUSDB_DONE;
    return 0;
}


EXPORTED char *mboxlist_find_specialuse(const char *use, const char *userid)
{
    init_internal();
    assert(userid);

    /* \\Inbox is magical */
    if (!strcasecmp(use, "\\Inbox"))
        return mboxname_user_mbox(userid, NULL);

    struct _find_specialuse_data rock = { use, userid, NULL };
    mboxlist_usermboxtree(userid, NULL, _find_specialuse, &rock, MBOXTREE_SKIP_ROOT);
    return rock.mboxname;
}

/*
 * read a single unique_I_d record from the mailboxes.db and return a pointer to it
 */
static int mboxlist_read_uniqueid(const char *uniqueid,
                                  const char **dataptr, size_t *datalenptr,
                                  struct txn **tid, int wrlock)
{
    struct buf key = BUF_INITIALIZER;
    int r;

    if (!uniqueid)
        return IMAP_MAILBOX_NONEXISTENT;

    mboxlist_id_to_key(uniqueid, &key);

    if (wrlock) {
        r = cyrusdb_fetchlock(mbdb, buf_base(&key), buf_len(&key),
                              dataptr, datalenptr, tid);
    } else {
        r = cyrusdb_fetch(mbdb, buf_base(&key), buf_len(&key),
                          dataptr, datalenptr, tid);
    }

    switch (r) {
    case CYRUSDB_OK:
        /* no entry required, just checking if it exists */
        r = 0;
        break;

    case CYRUSDB_AGAIN:
        r = IMAP_AGAIN;
        break;

    case CYRUSDB_NOTFOUND:
        r = IMAP_MAILBOX_NONEXISTENT;
        break;

    default:
        syslog(LOG_ERR, "DBERROR: error fetching mboxlist %s: %s",
               uniqueid, cyrusdb_strerror(r));
        r = IMAP_IOERROR;
        break;
    }

    buf_free(&key);
    return r;
}

EXPORTED char *mboxlist_find_uniqueid(const char *uniqueid,
                                      const char *userid __attribute__((unused)),
                                      const struct auth_state *auth_state __attribute__((unused)))
{
    int r;
    const char *data;
    size_t datalen;
    mbentry_t *mbentry = NULL;
    char *mbname;

    init_internal();

    r = mboxlist_read_uniqueid(uniqueid, &data, &datalen, NULL, 0);
    if (r) return NULL;

    r = mboxlist_parse_entry(&mbentry, NULL, 0, data, datalen);
    if (r) return NULL;

    mbname = mbentry->name;
    mbentry->name = NULL;
    mboxlist_entry_free(&mbentry);

    return mbname;
}

/*
 * Lookup 'uniqueid' in the mailbox list, ignoring reserved records
 */
EXPORTED int mboxlist_lookup_by_uniqueid(const char *uniqueid,
                                         mbentry_t **entryptr, struct txn **tid)
{
    mbentry_t *entry = NULL;
    const char *data;
    size_t datalen;
    int r;

    init_internal();

    r = mboxlist_read_uniqueid(uniqueid, &data, &datalen, tid, 0);
    if (r) return r;

    r = mboxlist_parse_entry(&entry, NULL, 0, data, datalen);
    if (r) return r;

    /* Ignore "reserved" entries, like they aren't there */
    if (entry->mbtype & MBTYPE_RESERVE) {
        mboxlist_entry_free(&entry);
        return IMAP_MAILBOX_RESERVED;
    }

    if (entryptr) {
        entry->uniqueid = xstrdup(uniqueid);
        *entryptr = entry;
    }
    else mboxlist_entry_free(&entry);

    return 0;
}

/* given a mailbox name, find the staging directory.  XXX - this should
 * require more locking, and staging directories should be by pid */
HIDDEN int mboxlist_findstage(const char *name, char *stagedir, size_t sd_len)
{
    const char *root;
    mbentry_t *mbentry = NULL;
    int r;

    init_internal();

    assert(stagedir != NULL);

    /* Find mailbox */
    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) return r;

    root = config_partitiondir(mbentry->partition);
    mboxlist_entry_free(&mbentry);

    if (!root) return IMAP_PARTITION_UNKNOWN;

    snprintf(stagedir, sd_len, "%s/stage./", root);

    return 0;
}

#define ACL_RECORDSEP_CHAR      '\x1E'  /* record separator (RS) */

static void mboxlist_racl_key(int isuser, const char *keyuser,
                              const char *dbname, struct buf *buf)
{
    buf_reset(buf);
    buf_putc(buf, KEY_TYPE_ACL);
    if (keyuser || dbname) {
        buf_putc(buf, isuser ? 'U' : 'S');
        buf_putc(buf, ACL_RECORDSEP_CHAR);
        if (keyuser) {
            buf_appendcstr(buf, keyuser);
            buf_putc(buf, ACL_RECORDSEP_CHAR);
        }
        if (dbname) {
            buf_appendcstr(buf, dbname);
        }
    }
}

static int user_can_read(const strarray_t *aclbits, const char *user)
{
    int i;
    if (!aclbits) return 0;
    for (i = 0; i+1 < strarray_size(aclbits); i+=2) {
        // skip ACLs without read bit
        if (!strchr(strarray_nth(aclbits, i+1), 'r')) continue;
        if (!strcmp(strarray_nth(aclbits, i), user)) return 1;
    }
    return 0;
}

static int mboxlist_update_raclmodseq(const char *acluser)
{
    char *aclusermbox = mboxname_user_mbox(acluser, NULL);
    mbentry_t *raclmbentry = NULL;
    if (mboxlist_lookup(aclusermbox, &raclmbentry, NULL) == 0) {
        mboxname_nextraclmodseq(aclusermbox, 0);
        sync_log_mailbox(aclusermbox);
    }
    mboxlist_entry_free(&raclmbentry);
    free(aclusermbox);
    return 0;
}

static int mboxlist_update_racl(const char *dbname, const mbentry_t *oldmbentry,
                                const mbentry_t *newmbentry, struct txn **txn)
{
    static strarray_t *admins = NULL;
    struct buf buf = BUF_INITIALIZER;
    strarray_t *oldusers = NULL;
    strarray_t *newusers = NULL;
    int i;
    int r = 0;

    mbname_t *mbname = mbname_from_dbname(dbname);
    char *userid = xstrdupnull(mbname_userid(mbname));
    mbname_free(&mbname);

    if (!admins) admins = strarray_split(config_getstring(IMAPOPT_ADMINS), NULL, 0);

    if (oldmbentry && !(oldmbentry->mbtype & MBTYPE_DELETED))
        oldusers = strarray_split(oldmbentry->acl, "\t", 0);

    if (newmbentry && !(newmbentry->mbtype & MBTYPE_DELETED))
        newusers = strarray_split(newmbentry->acl, "\t", 0);

    if (oldusers) {
        for (i = 0; i+1 < strarray_size(oldusers); i+=2) {
            const char *acluser = strarray_nth(oldusers, i);
            if (!strchr(strarray_nth(oldusers, i+1), 'r')) continue;
            if (!strcmpsafe(userid, acluser)) continue;
            if (strarray_find(admins, acluser, 0) >= 0) continue;
            if (user_can_read(newusers, acluser)) continue;
            mboxlist_racl_key(!!userid, acluser, dbname, &buf);
            r = cyrusdb_delete(mbdb, buf.s, buf.len, txn, /*force*/1);
            if (r) goto done;
            mboxlist_update_raclmodseq(acluser);
        }
    }

    if (newusers) {
        for (i = 0; i+1 < strarray_size(newusers); i+=2) {
            const char *acluser = strarray_nth(newusers, i);
            if (!strchr(strarray_nth(newusers, i+1), 'r')) continue;
            if (!strcmpsafe(userid, acluser)) continue;
            if (strarray_find(admins, acluser, 0) >= 0) continue;
            if (user_can_read(oldusers, acluser)) continue;
            mboxlist_racl_key(!!userid, acluser, dbname, &buf);
            r = cyrusdb_store(mbdb, buf.s, buf.len, "", 0, txn);
            if (r) goto done;
            mboxlist_update_raclmodseq(acluser);
        }
    }

 done:
    strarray_free(oldusers);
    strarray_free(newusers);
    free(userid);
    buf_free(&buf);
    return r;
}

static void add_former_name(struct dlist *name_history, const char *dbname,
                            time_t mtime, modseq_t foldermodseq)
{
    struct dlist *fname = dlist_newkvlist(NULL, "");

    dlist_setatom(fname, "N", dbname);
    dlist_setnum64(fname, "F", foldermodseq);
    dlist_setdate(fname, "M", mtime);

    dlist_push(name_history, fname);
}

static int mboxlist_update_entry(const char *name,
                                 const mbentry_t *mbentry, struct txn **txn)
{
    char *dbname = mboxname_to_dbname(name);
    struct buf key = BUF_INITIALIZER;
    mbentry_t *old = NULL;
    int r = 0;

    mboxlist_mylookup(dbname, &old, txn, 0, 1); // ignore errors, it will be NULL

    if (have_racl) {
        r = mboxlist_update_racl(dbname, old, mbentry, txn);
        if (r) goto done;
    }

    mboxlist_dbname_to_key(dbname, strlen(name), &key);

    if (mbentry) {
        /* Create N record value */
        struct dlist *dl = mboxlist_entry_dlist(dbname, mbentry);
        struct buf mboxent = BUF_INITIALIZER;

        dlist_printbuf(dl, 0, &mboxent);
        r = cyrusdb_store(mbdb, buf_base(&key), buf_len(&key),
                          buf_cstring(&mboxent), buf_len(&mboxent), txn);
        if (!r && mbentry->uniqueid &&
            !(old && (old->mbtype & mbentry->mbtype & MBTYPE_DELETED))) {
            mbentry_t *oldid = NULL;
            struct dlist *name_history = dlist_newlist(NULL, "H");

            /* Remove I field from N record value */
            struct dlist *id = dlist_pop(dl);
            dlist_free(&id);

            /* Add N field for I record value */
            dlist_push(dl, dlist_setatom(NULL, "N", dbname));

            mboxlist_lookup_by_uniqueid(mbentry->uniqueid, &oldid, txn);

            if (oldid) {
                /* Existing mailbox */
                while (oldid->name_history.count) {
                    former_name_t *fname = ptrarray_shift(&oldid->name_history);
                    add_former_name(name_history, fname->dbname,
                                    fname->mtime, fname->foldermodseq);
                    free(fname);
                }

                if (strcmp(name, oldid->name)) {
                    /* Renamed mailbox */
                    add_former_name(name_history, name,
                                    time(NULL), mbentry->foldermodseq);
                }
                mboxlist_entry_free(&oldid);
            }
            else {
                /* New mailbox */
                add_former_name(name_history, name,
                                time(NULL), mbentry->foldermodseq);
            }

            /* Add H field for I record value */
            dlist_stitch(dl, name_history);

            buf_reset(&mboxent);
            dlist_printbuf(dl, 0, &mboxent);
            mboxlist_id_to_key(mbentry->uniqueid, &key);
            r = cyrusdb_store(mbdb, buf_base(&key), buf_len(&key),
                              buf_cstring(&mboxent), buf_len(&mboxent), txn);
        }
        dlist_free(&dl);
        buf_free(&mboxent);

        if (!r && config_auditlog) {
            /* XXX is there a difference between "" and NULL? */
            xsyslog(LOG_NOTICE, "auditlog: acl",
                                "sessionid=<%s> "
                                "mailbox=<%s> uniqueid=<%s> mbtype=<%s> "
                                "oldacl=<%s> acl=<%s> foldermodseq=<%llu>",
                    session_id(),
                    name, mbentry->uniqueid, mboxlist_mbtype_to_string(mbentry->mbtype),
                    old ? old->acl : "NONE", mbentry->acl, mbentry->foldermodseq);
        }
    }
    else {
        r = cyrusdb_delete(mbdb, buf_base(&key), buf_len(&key), txn, /*force*/1);
        if (!r && old->uniqueid) {
            mboxlist_id_to_key(old->uniqueid, &key);
            r = cyrusdb_delete(mbdb, buf_base(&key), buf_len(&key),
                               txn, /*force*/1);
        }
    }

 done:
    mboxlist_entry_free(&old);
    buf_free(&key);
    free(dbname);
    return r;
}

EXPORTED int mboxlist_delete(const char *name)
{
    return mboxlist_update_entry(name, NULL, NULL);
}

EXPORTED int mboxlist_update(mbentry_t *mbentry, int localonly)
{
    int r = 0, r2 = 0;
    struct txn *tid = NULL;

    init_internal();

    r = mboxlist_update_entry(mbentry->name, mbentry, &tid);

    if (!r)
        mboxname_setmodseq(mbentry->name, mbentry->foldermodseq, mbentry->mbtype,
                           MBOXMODSEQ_ISFOLDER);

    /* commit the change to mupdate */
    if (!r && !localonly && config_mupdate_server) {
        mupdate_handle *mupdate_h = NULL;

        r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
        if (r) {
            syslog(LOG_ERR,
                   "cannot connect to mupdate server for update of '%s'",
                   mbentry->name);
        } else {
            char *location = strconcat(config_servername, "!",
                                       mbentry->partition, (char *)NULL);
            r = mupdate_activate(mupdate_h, mbentry->name,
                                 location, mbentry->acl);
            free(location);
            if (r) {
                syslog(LOG_ERR,
                       "MUPDATE: can't update mailbox entry for '%s'",
                       mbentry->name);
            }
        }
        mupdate_disconnect(&mupdate_h);
    }

    if (tid) {
        if (r) {
            r2 = cyrusdb_abort(mbdb, tid);
            if (r2)
                xsyslog(LOG_ERR, "DBERROR: error aborting transaction",
                                 "error=<%s>", cyrusdb_strerror(r2));
        } else {
            r2 = cyrusdb_commit(mbdb, tid);
            if (r2)
                xsyslog(LOG_ERR, "DBERROR: error committing transaction",
                                 "error=<%s>", cyrusdb_strerror(r2));
        }
    }

    return r;
}

static void assert_namespacelocked(const char *mboxname)
{
    char *userid = mboxname_to_userid(mboxname);
    assert(user_isnamespacelocked(userid));
    free(userid);
}

static int _findparent(mbname_t *mbname, mbentry_t **mbentryp, int allow_all)
{
    mbentry_t *mbentry = NULL;
    int r = IMAP_MAILBOX_NONEXISTENT;

    init_internal();

    while (strarray_size(mbname_boxes(mbname))) {
        free(mbname_pop_boxes(mbname));
        /* skip exactly INBOX, since it's not a real intermediate folder,
         * and the parent of INBOX.INBOX.foo is INBOX */
        if (strarray_size(mbname_boxes(mbname)) == 1 &&
            !strcmp(strarray_nth(mbname_boxes(mbname), 0), "INBOX")) {
            free(mbname_pop_boxes(mbname));
        }
        mboxlist_entry_free(&mbentry);
        if (allow_all)
            r = mboxlist_lookup_allow_all(mbname_intname(mbname), &mbentry, NULL);
        else
            r = mboxlist_lookup(mbname_intname(mbname), &mbentry, NULL);
        if (r != IMAP_MAILBOX_NONEXISTENT)
            break;
    }

    if (r)
        mboxlist_entry_free(&mbentry);
    else
        *mbentryp = mbentry;

    return r;
}

EXPORTED int mboxlist_findparent(const char *mboxname,
                               mbentry_t **mbentryp)
{
    mbname_t *mbname = mbname_from_intname(mboxname);
    int r = _findparent(mbname, mbentryp, 0);
    mbname_free(&mbname);
    return r;
}

EXPORTED int mboxlist_findparent_allow_all(const char *mboxname,
                                            mbentry_t **mbentryp)
{
    mbname_t *mbname = mbname_from_intname(mboxname);
    int r = _findparent(mbname, mbentryp, 1);
    mbname_free(&mbname);
    return r;
}

static int mboxlist_create_partition(const char *mboxname,
                                     const char *part,
                                     char **out)
{
    mbentry_t *parent = NULL;

    if (!part) {
        int r = mboxlist_findparent(mboxname, &parent);
        if (!r) part = parent->partition;
    }

    /* use defaultpartition if specified */
    if (!part && config_defpartition)
        part = config_defpartition;

    /* look for most fitting partition */
    if (!part)
        part = partlist_local_select();

    /* Configuration error */
    if (!part || (strlen(part) > MAX_PARTITION_LEN))
        goto err;

    if (!config_partitiondir(part))
        goto err;

    *out = xstrdupnull(part);

    mboxlist_entry_free(&parent);
    return 0;

err:
    mboxlist_entry_free(&parent);
    return IMAP_PARTITION_UNKNOWN;
}

/*
 * Check if a mailbox can be created.  There is no other setup at this
 * stage, just the check!
 */
static int mboxlist_create_namecheck(const char *mboxname,
                                     const char *userid,
                                     const struct auth_state *auth_state,
                                     int isadmin, int force_subdirs)
{
    mbentry_t *mbentry = NULL;
    int r = 0;

    /* policy first */
    r = mboxname_policycheck(mboxname);
    if (r) goto done;

    /* is this the user's INBOX namespace? */
    if (!isadmin && mboxname_userownsmailbox(userid, mboxname)) {
        /* User has admin rights over their own mailbox namespace */
        if (config_implicitrights & ACL_ADMIN)
            isadmin = 1;
    }

    /* Check to see if mailbox already exists */
    r = mboxlist_lookup(mboxname, &mbentry, NULL);
    if (r != IMAP_MAILBOX_NONEXISTENT) {
        if (!r) {
            r = IMAP_MAILBOX_EXISTS;

            /* Lie about error if privacy demands */
            if (!isadmin &&
                !(cyrus_acl_myrights(auth_state, mbentry->acl) & ACL_LOOKUP)) {
                r = IMAP_PERMISSION_DENIED;
            }
        }

        goto done;
    }
    mboxlist_entry_free(&mbentry);

    /* look for a parent mailbox */
    r = mboxlist_findparent(mboxname, &mbentry);
    if (r == 0) {
        /* found a parent */
        char root[MAX_MAILBOX_NAME+1];

        /* check acl */
        if (!isadmin &&
            !(cyrus_acl_myrights(auth_state, mbentry->acl) & ACL_CREATE)) {
            r = IMAP_PERMISSION_DENIED;
            goto done;
        }

        /* check quota */
        if (quota_findroot(root, sizeof(root), mboxname)) {
            quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
            qdiffs[QUOTA_NUMFOLDERS] = 1;
            r = quota_check_useds(root, qdiffs);
            if (r) goto done;
        }

        /* make sure parent isn't forbidden from containing children */
        if ((!isadmin || mboxname_userownsmailbox(userid, mboxname))
            && config_getstring(IMAPOPT_SPECIALUSE_NOCHILDREN))
        {
            struct buf attrib = BUF_INITIALIZER;
            mbname_t *mbname;

            mbname = mbname_from_intname(mbentry->name);
            annotatemore_lookup(mbentry->name, "/specialuse",
                                mbname_userid(mbname), &attrib);
            mbname_free(&mbname);

            if (buf_len(&attrib)) {
                strarray_t *uses = strarray_split(buf_cstring(&attrib), NULL, 0);

                strarray_t *forbidden = strarray_split(
                    config_getstring(IMAPOPT_SPECIALUSE_NOCHILDREN),
                    NULL,
                    STRARRAY_TRIM
                );

                if (strarray_intersect(uses, forbidden))
                    r = IMAP_PERMISSION_DENIED;

                strarray_free(forbidden);
                strarray_free(uses);
            }

            buf_free(&attrib);
            if (r) goto done;
        }
    }
    else if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* no parent mailbox */
        if (!isadmin) {
            r = IMAP_PERMISSION_DENIED;
            goto done;
        }

        if (!force_subdirs) {
            mbname_t *mbname = mbname_from_intname(mboxname);
            if (!mbname_isdeleted(mbname) && mbname_userid(mbname) && strarray_size(mbname_boxes(mbname))) {
                /* Disallow creating user.X.* when no user.X */
                r = IMAP_PERMISSION_DENIED;
                goto done;
            }
            mbname_free(&mbname);
        }

        /* otherwise no parent is OK */
        r = 0;
    }

done:
    mboxlist_entry_free(&mbentry);

    return r;
}

static int mboxlist_create_acl(const char *mboxname, char **out)
{
    mbentry_t *mbentry = NULL;
    int r;
    int mask;

    char *defaultacl;
    char *identifier;
    char *rights;
    char *p;

    r = mboxlist_findparent(mboxname, &mbentry);
    if (!r) {
        *out = xstrdup(mbentry->acl);
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    *out = xstrdup("");
    char *owner = mboxname_to_userid(mboxname);
    if (owner) {
        /* owner gets full permission on own mailbox by default */
        cyrus_acl_set(out, owner, ACL_MODE_SET, ACL_ALL,
                      (cyrus_acl_canonproc_t *)0, (void *)0);
        free(owner);
        return 0;
    }

    defaultacl = identifier = xstrdup(config_getstring(IMAPOPT_DEFAULTACL));
    for (;;) {
        while (*identifier && Uisspace(*identifier)) identifier++;
        rights = identifier;
        while (*rights && !Uisspace(*rights)) rights++;
        if (!*rights) break;
        *rights++ = '\0';
        while (*rights && Uisspace(*rights)) rights++;
        if (!*rights) break;
        p = rights;
        while (*p && !Uisspace(*p)) p++;
        if (*p) *p++ = '\0';
        cyrus_acl_strtomask(rights, &mask);
        /* XXX and if strtomask fails? */
        cyrus_acl_set(out, identifier, ACL_MODE_SET, mask,
                      (cyrus_acl_canonproc_t *)0, (void *)0);
        identifier = p;
    }
    free(defaultacl);

    return 0;
}

/* and this API just plain sucks */
EXPORTED int mboxlist_createmailboxcheck(const char *name, int mbtype __attribute__((unused)),
                                const char *partition,
                                int isadmin, const char *userid,
                                const struct auth_state *auth_state,
                                char **newacl, char **newpartition,
                                int forceuser)
{
    char *part = NULL;
    char *acl = NULL;
    int r = 0;

    init_internal();

    r = mboxlist_create_namecheck(name, userid, auth_state,
                                  isadmin, forceuser);
    if (r) goto done;

    if (newacl) {
        r = mboxlist_create_acl(name, &acl);
        if (r) goto done;
    }

    if (newpartition) {
        r = mboxlist_create_partition(name, partition, &part);
        if (r) goto done;
    }

 done:
    if (r || !newacl) free(acl);
    else *newacl = acl;

    if (r || !newpartition) free(part);
    else *newpartition = part;

    return r;
}

/* PLEASE NOTE - ALWAYS CALL AFTER MAKING THE CHANGES, as this function
 * will check for children when deciding whether to create or remove
 * intermediate folders */
EXPORTED int mboxlist_update_intermediaries(const char *frommboxname,
                                            int mbtype, modseq_t modseq)
{
    mbentry_t *mbentry = NULL;
    mbname_t *mbname = mbname_from_intname(frommboxname);
    int r = 0;

    /* only use intermediates for user mailboxes */
    if (!mbname_userid(mbname))
        goto out;

    for (; strarray_size(mbname_boxes(mbname)); free(mbname_pop_boxes(mbname))) {

        /* check for magic INBOX */
        if (strarray_size(mbname_boxes(mbname)) == 1 &&
            !strcmp(strarray_nth(mbname_boxes(mbname), 0), "INBOX")) {
            /* don't generate magic INBOX intermediate, JMAP doesn't use it */
            goto out;
        }

        const char *mboxname = mbname_intname(mbname);
        char *dbname = mbname_dbname(mbname);

        mboxlist_entry_free(&mbentry);
        r = mboxlist_mylookup(dbname, &mbentry, NULL, 0, 1);
        free(dbname);

        if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;
        if (r) goto out;

        if (mbentry) {
            if (mbentry->mbtype & MBTYPE_DELETED) {
                /* fall through to create a new intermediate */
            }
            else if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
                /* existing intermediate - delete unless it still has children */
                if (mboxlist_haschildren(mboxname))
                    continue;

                /* bump modseq, we're removing a thing that can be seen */
                if (!modseq)
                    modseq = mboxname_nextmodseq(mboxname, mbentry->foldermodseq,
                                                 mbtype, MBOXMODSEQ_ISFOLDER);

                mbentry_t *newmbentry = mboxlist_entry_copy(mbentry);
                newmbentry->mbtype &= ~MBTYPE_INTERMEDIATE;
                newmbentry->mbtype |= MBTYPE_DELETED;
                newmbentry->foldermodseq = modseq;

                syslog(LOG_NOTICE,
                       "mboxlist: deleting intermediate with no children: %s (%s)",
                       mboxname, mbentry->uniqueid);
                r = mboxlist_update_entry(mboxname, newmbentry, NULL);
                mboxlist_entry_free(&newmbentry);
                if (r) goto out;
                sync_log_mailbox(mboxname);

                /* we've changed the type, we're done at this level */
                continue;
            }
            else {
                /* real mailbox, we're done at this level */
                continue;
            }
        }

        /* if there's no children, there's no need for intermediates */
        if (!mboxlist_haschildren(mboxname))
            continue;

        /* bump modseq, we're adding a thing that can be seen */
        if (!modseq)
            modseq = mboxname_nextmodseq(mboxname,
                                         mbentry ? mbentry->foldermodseq : 0,
                                         mbtype, MBOXMODSEQ_ISFOLDER);

        mbentry_t *newmbentry = mboxlist_entry_create();
        newmbentry->uniqueid = xstrdupnull(makeuuid());
        newmbentry->createdmodseq = modseq;
        newmbentry->foldermodseq = modseq;
        newmbentry->mbtype |= MBTYPE_INTERMEDIATE;
        newmbentry->foldermodseq = modseq;

        syslog(LOG_NOTICE,
               "mboxlist: creating intermediate with children: %s (%s)",
               mboxname, newmbentry->uniqueid);
        r = mboxlist_update_entry(mboxname, newmbentry, NULL);
        mboxlist_entry_free(&newmbentry);
        if (r) goto out;
        sync_log_mailbox(mboxname);
    }

out:
    mboxlist_entry_free(&mbentry);
    mbname_free(&mbname);

    return r;
}

EXPORTED int mboxlist_promote_intermediary(const char *mboxname)
{
    mbentry_t *mbentry = NULL, *parent = NULL;
    struct mailbox *mailbox = NULL;
    int r = 0;
    struct txn *tid = NULL;

    r = mboxlist_lookup_allow_all(mboxname, &mbentry, &tid);
    if (r || !(mbentry->mbtype & MBTYPE_INTERMEDIATE)) goto done;

    r = mboxlist_findparent(mboxname, &parent);
    if (r) goto done;

    r = mboxlist_create_partition(mboxname, parent->partition,
                                  &mbentry->partition);
    if (r) goto done;
    mbentry->mbtype = 0; // intermediaries are always standard
    free(mbentry->acl);
    mbentry->acl = xstrdupnull(parent->acl);

    r = mailbox_create(mboxname, mbentry->mbtype,
                       mbentry->partition, parent->acl,
                       mbentry->uniqueid, 0 /* options */,
                       mbentry->uidvalidity,
                       mbentry->createdmodseq,
                       mbentry->foldermodseq, &mailbox);
    if (r) goto done;

    r = mailbox_add_conversations(mailbox, /*silent*/1);
    if (r) goto done;

    r = mboxlist_update_entry(mboxname, mbentry, &tid);
    if (r) goto done;

done:
    mailbox_close(&mailbox);
    if (tid) {
        if (r) cyrusdb_abort(mbdb, tid);
        else {
            r = cyrusdb_commit(mbdb, tid);
        }
    }
    mboxlist_entry_free(&mbentry);
    mboxlist_entry_free(&parent);
    return r;
}

/*
 * Create a mailbox
 *
 * 1. verify ACL's to best of ability (CRASH: abort)
 * 2. verify parent ACL's if need to
 * 3. create the local mailbox locally (exclusive lock) and keep it locked
 * 4. open mupdate connection if necessary
 * 5. create mupdate entry (CRASH: mupdate inconsistent)
 *
 */

static int mboxlist_createmailbox_full(const char *mboxname, int mbtype,
                                const char *partition,
                                int isadmin, const char *userid,
                                const struct auth_state *auth_state,
                                int options, unsigned uidvalidity,
                                modseq_t createdmodseq,
                                modseq_t highestmodseq,
                                modseq_t foldermodseq,
                                const char *copyacl, const char *uniqueid,
                                int localonly, int forceuser, int dbonly,
                                int keep_intermediaries,
                                struct mailbox **mboxptr)
{
    int r;
    char *newpartition = NULL;
    char *acl = NULL;
    struct mailbox *newmailbox = NULL;
    int isremote = mbtype & MBTYPE_REMOTE;
    mbentry_t *newmbentry = NULL;

    r = mboxlist_create_namecheck(mboxname, userid, auth_state,
                                  isadmin, forceuser);
    if (r) goto done;

    assert_namespacelocked(mboxname);

    if (copyacl) {
        acl = xstrdup(copyacl);
    }
    else {
        r = mboxlist_create_acl(mboxname, &acl);
        if (r) goto done;
    }

    r = mboxlist_create_partition(mboxname, partition, &newpartition);
    if (r) goto done;

    if (!dbonly && !isremote) {
        /* Filesystem Operations */
        r = mailbox_create(mboxname, mbtype, newpartition, acl, uniqueid,
                           options, uidvalidity, createdmodseq, highestmodseq, &newmailbox);
        if (r) goto done; /* CREATE failed */
        r = mailbox_add_conversations(newmailbox, /*silent*/0);
        if (r) goto done;
    }

    /* all is well - activate the mailbox */
    newmbentry = mboxlist_entry_create();
    newmbentry->acl = xstrdupnull(acl);
    newmbentry->mbtype = mbtype;
    newmbentry->partition = xstrdupnull(newpartition);
    if (newmailbox) {
        newmbentry->uniqueid = xstrdupnull(newmailbox->uniqueid);
        newmbentry->uidvalidity = newmailbox->i.uidvalidity;
        newmbentry->createdmodseq = newmailbox->i.createdmodseq;
        newmbentry->foldermodseq = foldermodseq ? foldermodseq : newmailbox->i.highestmodseq;
    }
    r = mboxlist_update_entry(mboxname, newmbentry, NULL);

    if (!r && !keep_intermediaries) {
        /* create any missing intermediaries */
        r = mboxlist_update_intermediaries(mboxname, mbtype, newmbentry->foldermodseq);
    }

    if (r) {
        xsyslog(LOG_ERR, "DBERROR: failed to insert to mailboxes list",
                         "mailbox=<%s> error=<%s>",
                         mboxname, cyrusdb_strerror(r));
        r = IMAP_IOERROR;
    }

    /* 9. set MUPDATE entry as commited (CRASH: commited) */
    if (!r && config_mupdate_server && !localonly) {
        mupdate_handle *mupdate_h = NULL;
        char *loc = strconcat(config_servername, "!", newpartition, (char *)NULL);

        r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
        if (!r) r = mupdate_reserve(mupdate_h, mboxname, loc);
        if (!r) r = mupdate_activate(mupdate_h, mboxname, loc, acl);
        if (r) {
            syslog(LOG_ERR, "MUPDATE: can't commit mailbox entry for '%s'",
                   mboxname);
            mboxlist_update_entry(mboxname, NULL, 0);
        }
        if (mupdate_h) mupdate_disconnect(&mupdate_h);
        free(loc);
    }

done:
    if (newmailbox) {
        if (r) mailbox_delete(&newmailbox);
        else if (mboxptr) *mboxptr = newmailbox;
        else mailbox_close(&newmailbox);
    }

    free(acl);
    free(newpartition);
    mboxlist_entry_free(&newmbentry);

    return r;
}

EXPORTED int mboxlist_createmailboxlock(const char *name, int mbtype,
                           const char *partition,
                           int isadmin, const char *userid,
                           const struct auth_state *auth_state,
                           int localonly, int forceuser, int dbonly,
                           int notify, struct mailbox **mailboxptr)
{
    struct mboxlock *namespacelock = mboxname_usernamespacelock(name);

    int r = mboxlist_createmailbox_unq(name, mbtype, partition, isadmin,
                                      userid, auth_state, localonly,
                                      forceuser, dbonly, notify, NULL,
                                      mailboxptr);

    mboxname_release(&namespacelock);
    return r;
}

EXPORTED int mboxlist_createmailbox(const char *name, int mbtype,
                           const char *partition,
                           int isadmin, const char *userid,
                           const struct auth_state *auth_state,
                           int localonly, int forceuser, int dbonly,
                           int notify, struct mailbox **mailboxptr)
{
    return mboxlist_createmailbox_unq(name, mbtype, partition, isadmin,
                                      userid, auth_state, localonly,
                                      forceuser, dbonly, notify, NULL,
                                      mailboxptr);
}

EXPORTED int mboxlist_createmailbox_unq(const char *name, int mbtype,
                           const char *partition,
                           int isadmin, const char *userid,
                           const struct auth_state *auth_state,
                           int localonly, int forceuser, int dbonly,
                           int notify, const char *uniqueid,
                           struct mailbox **mailboxptr)
{
    int options = config_getint(IMAPOPT_MAILBOX_DEFAULT_OPTIONS)
                  | OPT_POP3_NEW_UIDL;

    return mboxlist_createmailbox_opts(name, mbtype, partition, isadmin, userid,
                                       auth_state, options, localonly, forceuser,
                                       dbonly, notify, uniqueid, mailboxptr);
}

EXPORTED int mboxlist_createmailbox_opts(const char *name, int mbtype,
                                         const char *partition,
                                         int isadmin, const char *userid,
                                         const struct auth_state *auth_state,
                                         int options, int localonly,
                                         int forceuser, int dbonly,
                                         int notify, const char *uniqueid,
                                         struct mailbox **mailboxptr)
{
    int r;
    struct mailbox *mailbox = NULL;
    uint32_t uidvalidity = 0;
    modseq_t createdmodseq = 0;
    mbentry_t *oldmbentry = NULL;

    init_internal();

    /* check if a mailbox tombstone or intermediate record exists */
    r = mboxlist_lookup_allow_all(name, &oldmbentry, NULL);
    if (!r) {
        if (oldmbentry->mbtype & MBTYPE_DELETED) {
            /* then the UIDVALIDITY must be higher than before */
            if (uidvalidity <= oldmbentry->uidvalidity)
                uidvalidity = oldmbentry->uidvalidity+1;
        }
        else if (oldmbentry->mbtype & MBTYPE_INTERMEDIATE) {
            /* then use the existing mailbox ID and createdmodseq */
            if (!uniqueid) uniqueid = oldmbentry->uniqueid;
            createdmodseq = oldmbentry->createdmodseq;
        }
    }

    r = mboxlist_createmailbox_full(name, mbtype, partition,
                                    isadmin, userid, auth_state,
                                    options, uidvalidity, createdmodseq, 0, 0, NULL,
                                    uniqueid, localonly,
                                    forceuser, dbonly, 0, &mailbox);

    if (notify && !r) {
        /* send a MailboxCreate event notification */
        struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_CREATE);
        mboxevent_extract_mailbox(mboxevent, mailbox);
        mboxevent_set_access(mboxevent, NULL, NULL, userid, mailbox->name, 1);

        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);
    }

    if (mailboxptr && !r) *mailboxptr = mailbox;
    else mailbox_close(&mailbox);

    mboxlist_entry_free(&oldmbentry);

    return r;
}

EXPORTED int mboxlist_createsync(const char *name, int mbtype,
                        const char *partition,
                        const char *userid, const struct auth_state *auth_state,
                        int options, unsigned uidvalidity,
                        modseq_t createdmodseq,
                        modseq_t highestmodseq,
                        modseq_t foldermodseq,
                        const char *acl, const char *uniqueid,
                        int local_only, int keep_intermediaries,
                        struct mailbox **mboxptr)
{
    return mboxlist_createmailbox_full(name, mbtype, partition,
                                       1, userid, auth_state,
                                       options, uidvalidity,
                                       createdmodseq, highestmodseq,
                                       foldermodseq, acl, uniqueid,
                                       local_only, 1, 0,
                                       keep_intermediaries, mboxptr);
}

/* insert an entry for the proxy */
EXPORTED int mboxlist_insertremote(mbentry_t *mbentry,
                          struct txn **txn)
{
    int r = 0;

    if (mbentry->server) {
        /* remote mailbox */
        if (config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_UNIFIED &&
            !strcasecmp(mbentry->server, config_servername)) {
            /* its on our server, make it a local mailbox */
            mbentry->mbtype &= ~MBTYPE_REMOTE;
            mbentry->server = NULL;
        }
        else {
            /* make sure it's a remote mailbox */
            mbentry->mbtype |= MBTYPE_REMOTE;
        }
    }

    /* database put */
    r = mboxlist_update_entry(mbentry->name, mbentry, txn);

    switch (r) {
    case CYRUSDB_OK:
        break;
    case CYRUSDB_AGAIN:
        abort(); /* shouldn't happen ! */
        break;
    default:
        xsyslog(LOG_ERR, "DBERROR: error updating database",
                         "mailbox=<%s> error=<%s>",
                         mbentry->name, cyrusdb_strerror(r));
        r = IMAP_IOERROR;
        break;
    }

    return r;
}

/* Special function to delete a remote mailbox.
 * Only affects mboxlist.
 * Assumes admin powers. */
EXPORTED int mboxlist_deleteremote(const char *name, struct txn **in_tid)
{
    int r;
    struct txn **tid;
    struct txn *lcl_tid = NULL;
    mbentry_t *mbentry = NULL;
    char *dbname = mboxname_to_dbname(name);

    if(in_tid) {
        tid = in_tid;
    } else {
        tid = &lcl_tid;
    }

 retry:
    r = mboxlist_mylookup(dbname, &mbentry, tid, 1, 1);
    switch (r) {
    case 0:
        break;

    case IMAP_MAILBOX_NONEXISTENT:
        r = 0;
        break;

    case IMAP_AGAIN:
        goto retry;
        break;

    default:
        goto done;
    }

    if (mbentry && (mbentry->mbtype & MBTYPE_REMOTE) && !mbentry->server) {
        syslog(LOG_ERR,
               "mboxlist_deleteremote called on non-remote mailbox: %s",
               name);
        goto done;
    }

    r = mboxlist_update_entry(name, NULL, tid);
    if (r) {
        xsyslog(LOG_ERR, "DBERROR: error deleting entry",
                         "mailbox=<%s> error=<%s>",
                         name, cyrusdb_strerror(r));
        r = IMAP_IOERROR;
    }

    /* commit db operations, but only if we weren't passed a transaction */
    if (!in_tid) {
        r = cyrusdb_commit(mbdb, *tid);
        if (r) {
            xsyslog(LOG_ERR, "DBERROR: failed on commit",
                             "error=<%s>",
                             cyrusdb_strerror(r));
            r = IMAP_IOERROR;
        }
        tid = NULL;
    }

 done:
    free(dbname);
    if (r && !in_tid && tid) {
        /* Abort the transaction if it is still in progress */
        cyrusdb_abort(mbdb, *tid);
    }
    mboxlist_entry_free(&mbentry);

    return r;
}

/*
 * Delayed Delete a mailbox: translate delete into rename
 */
EXPORTED int
mboxlist_delayed_deletemailbox(const char *name, int isadmin,
                               const char *userid,
                               const struct auth_state *auth_state,
                               struct mboxevent *mboxevent,
                               int flags)
{
    mbentry_t *mbentry = NULL;
    mbentry_t *newmbentry = NULL;
    strarray_t existing = STRARRAY_INITIALIZER;
    char newname[MAX_MAILBOX_BUFFER];
    int r = 0;
    long myrights;

    int checkacl = flags & MBOXLIST_DELETE_CHECKACL;
    int localonly = flags & MBOXLIST_DELETE_LOCALONLY;
    int force = flags & MBOXLIST_DELETE_FORCE;
    int keep_intermediaries = flags & MBOXLIST_DELETE_KEEP_INTERMEDIARIES;
    int unprotect_specialuse = flags & MBOXLIST_DELETE_UNPROTECT_SPECIALUSE;

    init_internal();

    if (!isadmin && force) return IMAP_PERMISSION_DENIED;

    /* delete of a user.X folder */
    mbname_t *mbname = mbname_from_intname(name);
    if (mbname_userid(mbname) && !strarray_size(mbname_boxes(mbname))) {
        /* Can't DELETE INBOX (your own inbox) */
        if (!strcmpsafe(mbname_userid(mbname), userid)) {
            r = IMAP_MAILBOX_NOTSUPPORTED;
            goto done;
        }
        /* Only admins may delete user */
        if (!isadmin) {
            r = IMAP_PERMISSION_DENIED;
            goto done;
        }
    }

    if (!isadmin && mbname_userid(mbname) && !unprotect_specialuse) {
        const char *protect = config_getstring(IMAPOPT_SPECIALUSE_PROTECT);
        if (protect) {
            struct buf attrib = BUF_INITIALIZER;
            annotatemore_lookup(mbname_intname(mbname), "/specialuse", mbname_userid(mbname), &attrib);
            if (attrib.len) {
                strarray_t *check = strarray_split(protect, NULL, STRARRAY_TRIM);
                strarray_t *uses = strarray_split(buf_cstring(&attrib), NULL, 0);
                if (strarray_intersect_case(uses, check))
                    r = IMAP_MAILBOX_SPECIALUSE;
                strarray_free(uses);
                strarray_free(check);
            }
            buf_free(&attrib);
        }
        if (r) goto done;
    }

    r = mboxlist_lookup_allow_all(name, &mbentry, NULL);
    if (r) goto done;

    /* check if user has Delete right (we've already excluded non-admins
     * from deleting a user mailbox) */
    if (checkacl && !(mbentry->mbtype & MBTYPE_INTERMEDIATE)) {
        myrights = cyrus_acl_myrights(auth_state, mbentry->acl);
        if (!(myrights & ACL_DELETEMBOX)) {
            /* User has admin rights over their own mailbox namespace */
            if (mboxname_userownsmailbox(userid, name) &&
                (config_implicitrights & ACL_ADMIN)) {
                isadmin = 1;
            }

            /* Lie about error if privacy demands */
            r = (isadmin || (myrights & ACL_LOOKUP)) ?
                IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;

            goto done;
        }
    }

    /* get the deleted name */
    mboxname_todeleted(name, newname, 1);

    /* Get mboxlist_renamemailbox to do the hard work. No ACL checks needed */
    r = mboxlist_renamemailbox(mbentry, newname, mbentry->partition,
                               0 /* uidvalidity */,
                               1 /* isadmin */, userid,
                               auth_state,
                               mboxevent,
                               localonly /* local_only */,
                               force, 1,
                               keep_intermediaries,
                               0 /* move_subscription */, 0 /* silent */);

    if (r) goto done;

    /* Bump the deletedmodseq of the entries of mbtype. Do not
     * bump the folderdeletedmodseq, yet. We'll take care of
     * that in mboxlist_deletemailbox. */
    r = mboxlist_lookup_allow_all(newname, &newmbentry, NULL);
    if (!r) mboxname_setmodseq(newname, newmbentry->foldermodseq,
                               newmbentry->mbtype, MBOXMODSEQ_ISDELETE);

done:
    strarray_fini(&existing);
    mboxlist_entry_free(&newmbentry);
    mboxlist_entry_free(&mbentry);
    mbname_free(&mbname);

    return r;
}

/*
 * Delete a mailbox.
 * Deleting the mailbox user.FOO may only be performed by an admin.
 *
 * 1. Begin transaction
 * 2. Verify ACL's
 * 3. remove from database
 * 4. remove from disk
 * 5. commit transaction
 * 6. Open mupdate connection if necessary
 * 7. delete from mupdate
 *
 */
EXPORTED int mboxlist_deletemailbox(const char *name, int isadmin,
                                    const char *userid,
                                    const struct auth_state *auth_state,
                                    struct mboxevent *mboxevent,
                                    int flags)
{
    mbentry_t *mbentry = NULL;
    int r = 0;
    long myrights;
    struct mailbox *mailbox = NULL;
    int isremote = 0;
    mupdate_handle *mupdate_h = NULL;

    int checkacl = flags & MBOXLIST_DELETE_CHECKACL;
    int localonly = flags & MBOXLIST_DELETE_LOCALONLY;
    int force = flags & MBOXLIST_DELETE_FORCE;
    int keep_intermediaries = flags & MBOXLIST_DELETE_KEEP_INTERMEDIARIES;
    int silent = flags & MBOXLIST_DELETE_SILENT;
    int unprotect_specialuse = flags & MBOXLIST_DELETE_UNPROTECT_SPECIALUSE;

    init_internal();

    if (!isadmin && force) return IMAP_PERMISSION_DENIED;

    assert_namespacelocked(name);

    /* delete of a user.X folder */
    mbname_t *mbname = mbname_from_intname(name);
    if (mbname_userid(mbname) && !strarray_size(mbname_boxes(mbname))) {
        /* Can't DELETE INBOX (your own inbox) */
        if (!strcmpsafe(mbname_userid(mbname), userid)) {
            r = IMAP_MAILBOX_NOTSUPPORTED;
            goto done;
        }
        /* Only admins may delete user */
        if (!isadmin) {
            r = IMAP_PERMISSION_DENIED;
            goto done;
        }
    }

    if (!isadmin && mbname_userid(mbname) && !unprotect_specialuse) {
        const char *protect = config_getstring(IMAPOPT_SPECIALUSE_PROTECT);
        if (protect) {
            struct buf attrib = BUF_INITIALIZER;
            annotatemore_lookup(mbname_intname(mbname), "/specialuse", mbname_userid(mbname), &attrib);
            if (attrib.len) {
                strarray_t *check = strarray_split(protect, NULL, STRARRAY_TRIM);
                strarray_t *uses = strarray_split(buf_cstring(&attrib), NULL, 0);
                if (strarray_intersect_case(uses, check))
                    r = IMAP_MAILBOX_SPECIALUSE;
                strarray_free(uses);
                strarray_free(check);
            }
            buf_free(&attrib);
        }
        if (r) goto done;
    }

    r = mboxlist_lookup_allow_all(name, &mbentry, NULL);
    if (r) goto done;

    if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
        // make it deleted and mark it done!
        if (!mboxname_isdeletedmailbox(name, NULL)) {
            mbentry_t *newmbentry = mboxlist_entry_copy(mbentry);
            newmbentry->mbtype = MBTYPE_DELETED;
            if (!silent) {
                newmbentry->foldermodseq = mboxname_nextmodseq(newmbentry->name, newmbentry->foldermodseq,
                                                               newmbentry->mbtype,
                                                               MBOXMODSEQ_ISFOLDER|MBOXMODSEQ_ISDELETE);
            }
            r = mboxlist_update(newmbentry, /*localonly*/1);
            if (r) {
                xsyslog(LOG_ERR, "DBERROR: error marking deleted",
                                 "mailbox=<%s> error=<%s>",
                                 name, cyrusdb_strerror(r));
            }
            mboxlist_entry_free(&newmbentry);
        }
        else {
            r = mboxlist_update_entry(name, NULL, 0);
            if (r) {
                xsyslog(LOG_ERR, "DBERROR: error deleting",
                                 "mailbox=<%s> error=<%s>",
                                 name, cyrusdb_strerror(r));
            }
        }
        goto done;
    }

    isremote = mbentry->mbtype & MBTYPE_REMOTE;

    /* check if user has Delete right (we've already excluded non-admins
     * from deleting a user mailbox) */
    if (checkacl) {
        myrights = cyrus_acl_myrights(auth_state, mbentry->acl);
        if(!(myrights & ACL_DELETEMBOX)) {
            /* User has admin rights over their own mailbox namespace */
            if (mboxname_userownsmailbox(userid, name) &&
                (config_implicitrights & ACL_ADMIN)) {
                isadmin = 1;
            }

            /* Lie about error if privacy demands */
            r = (isadmin || (myrights & ACL_LOOKUP)) ?
                IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
            goto done;
        }
    }

    /* Lock the mailbox if it isn't a remote mailbox */
    if (!isremote) {
        r = mailbox_open_iwl(name, &mailbox);
        if (!r) mailbox->silentchanges = silent;
    }
    if (r && !force) goto done;

    /* remove from mupdate */
    if (!isremote && !localonly && config_mupdate_server) {
        /* delete the mailbox in MUPDATE */
        r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
        if (r) {
            syslog(LOG_ERR,
                   "cannot connect to mupdate server for delete of '%s'",
                   name);
            goto done;
        }
        r = mupdate_delete(mupdate_h, name);
        if(r) {
            syslog(LOG_ERR,
                   "MUPDATE: can't delete mailbox entry '%s'", name);
        }
        if (mupdate_h) mupdate_disconnect(&mupdate_h);
    }
    if (r && !force) goto done;

    if (!isremote && !mboxname_isdeletedmailbox(name, NULL)) {
        /* store a DELETED marker */
        int haschildren = mboxlist_haschildren(name);
        mbentry_t *newmbentry = mboxlist_entry_create();
        newmbentry->name = xstrdupnull(name);
        newmbentry->mbtype |= haschildren ? MBTYPE_INTERMEDIATE : MBTYPE_DELETED;
        if (mailbox) {
            newmbentry->uniqueid = xstrdupnull(mailbox->uniqueid);
            newmbentry->uidvalidity = mailbox->i.uidvalidity;
            newmbentry->createdmodseq = mailbox->i.createdmodseq;
            newmbentry->foldermodseq = mailbox_modseq_dirty(mailbox);
        }
        r = mboxlist_update(newmbentry, /*localonly*/1);

        /* any other updated intermediates get the same modseq */
        if (!r && !keep_intermediaries) {
            r = mboxlist_update_intermediaries(mbentry->name, mbentry->mbtype, newmbentry->foldermodseq);
        }

        /* Bump the modseq of entries of mbtype. There's still a tombstone
         * for this mailbox, so don't bump the folderdeletedmodseq, yet. */
        if (!r) {
            mboxname_setmodseq(mbentry->name, newmbentry->foldermodseq,
                               mbentry->mbtype, MBOXMODSEQ_ISDELETE);
        }

        mboxlist_entry_free(&newmbentry);
    }
    else {
        /* delete entry (including DELETED.* mailboxes, no need
         * to keep that rubbish around) */
        r = mboxlist_update_entry(name, NULL, 0);
        if (r) {
            xsyslog(LOG_ERR, "DBERROR: error deleting",
                             "mailbox=<%s> error=<%s>",
                             name, cyrusdb_strerror(r));
            r = IMAP_IOERROR;
            if (!force) goto done;
        }
        /* This mailbox is gone completely, so mark its modseq */
        if (!r && !isremote && mboxname_isdeletedmailbox(name, NULL)) {
            mboxname_setmodseq(name, mailbox->foldermodseq, mbentry->mbtype,
                               MBOXMODSEQ_ISFOLDER|MBOXMODSEQ_ISDELETE);
        }
        if (r && !force) goto done;
    }


    /* delete underlying mailbox */
    if (!isremote && mailbox) {
        /* only on a real delete do we delete from the remote end as well */
        sync_log_unmailbox(mailbox->name);
        mboxevent_extract_mailbox(mboxevent, mailbox);
        mboxevent_set_access(mboxevent, NULL, NULL, userid, mailbox->name, 1);

        r = mailbox_delete(&mailbox);
        /* abort event notification */
        if (r && mboxevent)
            mboxevent_free(&mboxevent);
    }


 done:
    mailbox_close(&mailbox);
    mboxlist_entry_free(&mbentry);
    mbname_free(&mbname);

    return r;
}

EXPORTED int mboxlist_deletemailboxlock(const char *name, int isadmin,
                                    const char *userid,
                                    const struct auth_state *auth_state,
                                    struct mboxevent *mboxevent,
                                    int flags)
{
    struct mboxlock *namespacelock = mboxname_usernamespacelock(name);

    int r = mboxlist_deletemailbox(name, isadmin, userid, auth_state, mboxevent, flags);

    mboxname_release(&namespacelock);
    return r;
}

static int _rename_check_specialuse(const char *oldname, const char *newname)
{
    const char *protect = config_getstring(IMAPOPT_SPECIALUSE_PROTECT);
    if (!protect) return 0;

    mbname_t *old = mbname_from_intname(oldname);
    mbname_t *new = mbname_from_intname(newname);
    struct buf attrib = BUF_INITIALIZER;
    int r = 0;
    if (mbname_userid(old))
        annotatemore_lookup(oldname, "/specialuse", mbname_userid(old), &attrib);

    /* we have specialuse? */
    if (attrib.len) {
        strarray_t *check = strarray_split(protect, NULL, STRARRAY_TRIM);
        strarray_t *uses = strarray_split(buf_cstring(&attrib), NULL, 0);
        if (strarray_intersect_case(uses, check)) {
            /* then target must be a single-depth mailbox too */
            if (strarray_size(mbname_boxes(new)) != 1)
                r = IMAP_MAILBOX_SPECIALUSE;
            /* and have a userid as well */
            if (!mbname_userid(new))
                r = IMAP_MAILBOX_SPECIALUSE;
            /* and not be deleted */
            if (mbname_isdeleted(new))
                r = IMAP_MAILBOX_SPECIALUSE;
        }
        strarray_free(uses);
        strarray_free(check);
    }

    mbname_free(&new);
    mbname_free(&old);
    buf_free(&attrib);
    return r;
}

struct renmboxdata {
    size_t ol;
    size_t nl;
    char newname[MAX_MAILBOX_NAME+1];
    const struct auth_state *authstate;
    const char *partition;
    const char *userid;
    int local_only;
    int ignorequota;
    int found;
    int keep_intermediaries;
    int move_subscription;
};

static int renamecheck(const mbentry_t *mbentry, void *rock)
{
    struct renmboxdata *text = (struct renmboxdata *)rock;
    int r;

    text->found++;

    if((text->nl + strlen(mbentry->name + text->ol)) >= MAX_MAILBOX_NAME)
        return IMAP_MAILBOX_BADNAME;

    strcpy(text->newname + text->nl, mbentry->name + text->ol);

    /* force create, but don't ignore policy.  This is a filthy hack that
       will go away when we refactor this code */
    r = mboxlist_createmailboxcheck(text->newname, 0, text->partition, 1,
                                    text->userid, text->authstate, NULL, NULL, 2);
    return r;
}

static int dorename(const mbentry_t *mbentry, void *rock)
{
    struct renmboxdata *text = (struct renmboxdata *)rock;
    int r;

    if((text->nl + strlen(mbentry->name + text->ol)) >= MAX_MAILBOX_NAME)
        return IMAP_MAILBOX_BADNAME;

    strcpy(text->newname + text->nl, mbentry->name + text->ol);

    r = mboxlist_renamemailbox(mbentry, text->newname,
                               text->partition, /*uidvalidity*/0,
                               /*isadmin*/1, text->userid,
                               text->authstate,
                               /*mboxevent*/NULL,
                               text->local_only, /*forceuser*/1, text->ignorequota,
                               text->keep_intermediaries,
                               text->move_subscription, /*silent*/0);

    return r;
}

EXPORTED int mboxlist_renametree(const char *oldname, const char *newname,
                                 const char *partition, unsigned uidvalidity,
                                 int isadmin, const char *userid,
                                 const struct auth_state *auth_state,
                                 struct mboxevent *mboxevent,
                                 int local_only, int forceuser, int ignorequota,
                                 int keep_intermediaries, int move_subscription)
{
    struct renmboxdata rock;
    memset(&rock, 0, sizeof(struct renmboxdata));
    rock.ol = strlen(oldname);
    rock.nl = strlen(newname);
    memcpy(rock.newname, newname, rock.nl);
    rock.partition = partition;
    rock.authstate = auth_state;
    rock.userid = userid;
    rock.local_only = local_only;
    rock.ignorequota = ignorequota;
    rock.keep_intermediaries = keep_intermediaries;
    rock.move_subscription = move_subscription;
    mbentry_t *mbentry = NULL;
    int r;

    /* first check that we can rename safely */
    r = mboxlist_mboxtree(oldname, renamecheck, &rock, 0);
    if (r) return r;

    r = mboxlist_lookup_allow_all(oldname, &mbentry, 0);
    if (r) return r;

    if (mbentry->mbtype & (MBTYPE_RESERVE | MBTYPE_DELETED)) {
        mboxlist_entry_free(&mbentry);
        return IMAP_MAILBOX_NONEXISTENT;
    }

    // rename the root mailbox
    r = mboxlist_renamemailbox(mbentry, newname,
                               partition, uidvalidity,
                               isadmin, userid,
                               auth_state,
                               mboxevent,
                               local_only, forceuser, ignorequota,
                               keep_intermediaries, move_subscription, /*silent*/0);
    mboxlist_entry_free(&mbentry);

    // special-case only children exist
    if (r == IMAP_MAILBOX_NONEXISTENT && rock.found) r = 0;
    if (r) return r;

    // now the children
    r = mboxlist_mboxtree(oldname, dorename, &rock, MBOXTREE_SKIP_ROOT);
    return r;
}

/*
 * Rename/move a single mailbox (recursive renames are handled at a
 * higher level).  This only supports local mailboxes.  Remote
 * mailboxes are handled up in imapd.c
 */
EXPORTED int mboxlist_renamemailbox(const mbentry_t *mbentry,
                                    const char *newname,
                                    const char *partition, unsigned uidvalidity,
                                    int isadmin, const char *userid,
                                    const struct auth_state *auth_state,
                                    struct mboxevent *mboxevent,
                                    int local_only, int forceuser,
                                    int ignorequota, int keep_intermediaries,
                                    int move_subscription, int silent)
{
    int r;
    const char *oldname = mbentry->name;
    int mupdatecommiterror = 0;
    long myrights;
    int isusermbox = 0; /* Are we renaming someone's inbox */
    int partitionmove = 0;
    struct mailbox *oldmailbox = NULL;
    struct mailbox *newmailbox = NULL;
    strarray_t inter = STRARRAY_INITIALIZER;
    struct txn *tid = NULL;
    const char *root = NULL;
    char *newpartition = NULL;
    mupdate_handle *mupdate_h = NULL;
    mbentry_t *newmbentry = NULL;
    int modseqflags = MBOXMODSEQ_ISFOLDER;
    if (mboxname_isdeletedmailbox(newname, NULL))
        modseqflags |= MBOXMODSEQ_ISDELETE;

    init_internal();

    assert_namespacelocked(mbentry->name);
    assert_namespacelocked(newname);

    /* special-case: intermediate mailbox */
    if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
        r = mboxlist_create_namecheck(newname, userid, auth_state,
                                      isadmin, forceuser);
        if (r) goto done;
        newmbentry = mboxlist_entry_copy(mbentry);
        free(newmbentry->name);
        newmbentry->name = xstrdupnull(newname);
        if (!silent) {
            newmbentry->foldermodseq = mboxname_nextmodseq(newname, newmbentry->foldermodseq,
                                                           newmbentry->mbtype, modseqflags);
        }

        /* skip ahead to the database update */
        goto dbupdate;
    }

    myrights = cyrus_acl_myrights(auth_state, mbentry->acl);

    /* check the ACLs up-front */
    if (!isadmin) {
        if (!(myrights & ACL_DELETEMBOX)) {
            r = (myrights & ACL_LOOKUP) ?
                IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
            return r;
        }
    }

    /* 1. open mailbox */
    r = mailbox_open_iwl(oldname, &oldmailbox);
    if (r) return r;

    oldmailbox->silentchanges = silent;

    /* 2. verify valid move */
    /* XXX - handle remote mailbox */

    /* special case: same mailbox, must be a partition move */
    if (!strcmp(oldname, newname)) {
        const char *oldpath = mailbox_datapath(oldmailbox, 0);

        /* Only admin can move mailboxes between partitions */
        if (!isadmin) {
            r = IMAP_PERMISSION_DENIED;
            goto done;
        }

        /* No partition, we're definitely not moving anywhere */
        if (!partition) {
            r = IMAP_MAILBOX_EXISTS;
            goto done;
        }

        /* let mupdate code below know it was a partition move */
        partitionmove = 1;

        /* this is OK because it uses a different static buffer */
        root = config_partitiondir(partition);
        if (!root) {
            r = IMAP_PARTITION_UNKNOWN;
            goto done;
        }
        if (!strncmp(root, oldpath, strlen(root)) &&
            oldpath[strlen(root)] == '/') {
            /* partitions are the same or share common prefix */
            r = IMAP_MAILBOX_EXISTS;
            goto done;
        }

        /* NOTE: this is a rename to the same mailbox name on a
         * different partition.  This is a pretty filthy hack,
         * which should be handled by having four totally different
         * codepaths: INBOX -> INBOX.foo, user rename, regular rename
         * and of course this one, partition move */
        newpartition = xstrdup(partition);
        r = mailbox_copy_files(oldmailbox, newpartition, newname, oldmailbox->uniqueid);
        if (r) goto done;
        newmbentry = mboxlist_entry_create();
        newmbentry->mbtype = oldmailbox->mbtype;
        newmbentry->partition = xstrdupnull(newpartition);
        newmbentry->acl = xstrdupnull(oldmailbox->acl);
        newmbentry->uidvalidity = oldmailbox->i.uidvalidity;
        newmbentry->uniqueid = xstrdupnull(oldmailbox->uniqueid);
        newmbentry->createdmodseq = oldmailbox->i.createdmodseq;
        newmbentry->foldermodseq = silent ? oldmailbox->foldermodseq
                                          : mboxname_nextmodseq(newname, oldmailbox->foldermodseq,
                                                                oldmailbox->mbtype, modseqflags);

        r = mboxlist_update_entry(newname, newmbentry, &tid);
        if (r) goto done;

        /* skip ahead to the commit */
        goto dbdone;
    }

    if (!isadmin) {
        r = _rename_check_specialuse(oldname, newname);
        if (r) goto done;
    }

    /* RENAME of some user's INBOX */
    if (mboxname_isusermailbox(oldname, 1)) {
        if (mboxname_isdeletedmailbox(newname, NULL)) {
            /* delete user is OK */
        }
        else if (mboxname_isusermailbox(newname, 1)) {
            /* user rename is depends on config */
            if (!config_getswitch(IMAPOPT_ALLOWUSERMOVES)) {
                r = IMAP_MAILBOX_NOTSUPPORTED;
                goto done;
            }
        }
        else if (mboxname_userownsmailbox(userid, oldname) &&
                 mboxname_userownsmailbox(userid, newname)) {
            /* Special case of renaming inbox */
            isusermbox = 1;
        }
        else {
            /* Everything else is bogus */
            r = IMAP_MAILBOX_NOTSUPPORTED;
            goto done;
        }
    }

    r = mboxlist_create_namecheck(newname, userid, auth_state,
                                  isadmin, forceuser);
    if (r) goto done;

    r = mboxlist_create_partition(newname, partition, &newpartition);
    if (r) goto done;

    if (!newpartition) newpartition = xstrdup(config_defpartition);

    /* keep uidvalidity on rename unless specified */
    if (!uidvalidity)
        uidvalidity = oldmailbox->i.uidvalidity;

    /* Rename the actual mailbox */
    r = mailbox_rename_copy(oldmailbox, newname, newpartition, uidvalidity,
                            isusermbox ? userid : NULL, ignorequota,
                            silent, &newmailbox);

    if (r) goto done;

    syslog(LOG_INFO, "Rename: %s -> %s", oldname, newname);

    /* create new entry */
    newmbentry = mboxlist_entry_create();
    newmbentry->name = xstrdupnull(newmailbox->name);
    newmbentry->mbtype = newmailbox->mbtype;
    newmbentry->partition = xstrdupnull(newmailbox->part);
    newmbentry->acl = xstrdupnull(newmailbox->acl);
    newmbentry->uidvalidity = newmailbox->i.uidvalidity;
    newmbentry->uniqueid = xstrdupnull(newmailbox->uniqueid);
    newmbentry->createdmodseq = newmailbox->i.createdmodseq;
    newmbentry->foldermodseq = newmailbox->i.highestmodseq;

  dbupdate:

    do {
        r = 0;

        /* delete the old entry */
        if (!isusermbox) {
            /* store a DELETED marker */
            mbentry_t *oldmbentry = mboxlist_entry_create();
            oldmbentry->name = xstrdupnull(mbentry->name);
            oldmbentry->mbtype |= MBTYPE_DELETED;
            oldmbentry->uidvalidity = mbentry->uidvalidity;
            oldmbentry->uniqueid = xstrdupnull(mbentry->uniqueid);
            oldmbentry->createdmodseq = mbentry->createdmodseq;
            oldmbentry->foldermodseq = newmbentry->foldermodseq;

            r = mboxlist_update_entry(oldname, oldmbentry, &tid);

            mboxlist_entry_free(&oldmbentry);
        }

        /* create a new entry */
        if (!r) {
            r = mboxlist_update_entry(newname, newmbentry, &tid);
        }

        switch (r) {
        case 0: /* success */
            break;
        case CYRUSDB_AGAIN:
            tid = NULL;
            break;
        default:
            xsyslog(LOG_ERR, "DBERROR: rename failed on store",
                             "oldname=<%s> newname=<%s> error=<%s>",
                             oldname, newname, cyrusdb_strerror(r));
            r = IMAP_IOERROR;
            goto done;
            break;
        }
    } while (r == CYRUSDB_AGAIN);

 dbdone:

    /* 3. Commit transaction */
    r = cyrusdb_commit(mbdb, tid);

    tid = NULL;
    if (r) {
        xsyslog(LOG_ERR, "DBERROR: rename failed on commit",
                         "oldname=<%s> newname=<%s> error=<%s>",
                         oldname, newname, cyrusdb_strerror(r));
        r = IMAP_IOERROR;
        goto done;
    }

    /* Move subscription */
    if (move_subscription) {
        int is_subscribed = mboxlist_checksub(oldname, userid) == 0;
        int r2 = mboxlist_changesub(oldname, userid, auth_state, 0, 0, 0);
        if (r2) {
            syslog(LOG_ERR, "CHANGESUB: can't unsubscribe %s: %s",
                    oldname, error_message(r2));
        }
        if (is_subscribed) {
            r2 = mboxlist_changesub(newname, userid, auth_state, 1, 0, 0);
            if (r2) {
                syslog(LOG_ERR, "CHANGESUB: can't subscribe %s: %s",
                        newname, error_message(r2));
            }
        }
    }

    if (!local_only && config_mupdate_server) {
        /* commit the mailbox in MUPDATE */
        char *loc = strconcat(config_servername, "!", newpartition, (char *)NULL);

        r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
        if (!partitionmove) {
            if (!r && !isusermbox)
                r = mupdate_delete(mupdate_h, oldname);
            if (!r) r = mupdate_reserve(mupdate_h, newname, loc);
        }
        if (!r) r = mupdate_activate(mupdate_h, newname, loc, newmbentry->acl);
        if (r) {
            syslog(LOG_ERR,
                   "MUPDATE: can't commit mailbox entry for '%s'",
                   newname);
            mupdatecommiterror = r;
        }
        if (mupdate_h) mupdate_disconnect(&mupdate_h);
        free(loc);
    }

 done: /* Commit or cleanup */
    if (!r && newmailbox)
        r = mailbox_commit(newmailbox);

    if (!keep_intermediaries) {
        if (!r) r = mboxlist_update_intermediaries(oldname, newmbentry->mbtype, newmbentry->foldermodseq);
        if (!r) r = mboxlist_update_intermediaries(newname, newmbentry->mbtype, newmbentry->foldermodseq);
    }

    if (r) {
        /* rollback DB changes if it was an mupdate failure */
        if (mupdatecommiterror) {
            r = 0;

            /* delete the new entry */
            if (!isusermbox)
                r = mboxlist_update_entry(newname, NULL, &tid);

            /* recreate an old entry */
            if (!r)
                r = mboxlist_update_entry(oldname, newmbentry, &tid);

            /* Commit transaction */
            if (!r)
                r = cyrusdb_commit(mbdb, tid);

            tid = NULL;
            if (r) {
                /* XXX HOWTO repair this mess! */
                xsyslog(LOG_ERR, "DBERROR: failed DB rollback on mailboxrename",
                                 "oldname=<%s> newname=<%s> error=<%s>",
                                 oldname, newname, cyrusdb_strerror(r));
                xsyslog(LOG_ERR, "DBERROR: mailboxdb on mupdate and backend"
                                 " ARE NOT CONSISTENT",
                                 "mupdate_entry=<%s> backend_entry=<%s>",
                                 oldname, newname);
                r = IMAP_IOERROR;
            } else {
                r = mupdatecommiterror;
            }
        }

        if (newmailbox) mailbox_delete(&newmailbox);
        if (partitionmove && newpartition)
            mailbox_delete_cleanup(NULL, newpartition, newname, oldmailbox->uniqueid);
        mailbox_close(&oldmailbox);
    } else {
        /* log the rename before we close either mailbox, so that
         * we never nuke the mailbox from the replica before realising
         * that it has been renamed.  This can be moved later again when
         * we sync mailboxes by uniqueid rather than name... */
        sync_log_rename(oldname, newname);

        if (newmailbox) {
            /* prepare the event notification */
            if (mboxevent) {

                /* case of delayed delete */
                if (mboxevent->type == EVENT_MAILBOX_DELETE)
                    mboxevent_extract_mailbox(mboxevent, oldmailbox);
                else {
                    mboxevent_extract_mailbox(mboxevent, newmailbox);
                    mboxevent_extract_old_mailbox(mboxevent, oldmailbox);
                }

                mboxevent_set_access(mboxevent, NULL, NULL, userid, newmailbox->name, 1);
            }

            mailbox_rename_cleanup(&oldmailbox, isusermbox);

#ifdef WITH_DAV
            mailbox_add_dav(newmailbox);
#endif

            mailbox_close(&newmailbox);

            /* and log an append so that squatter indexes it */
            sync_log_append(newname);
        }
        else if (partitionmove) {
            char *oldpartition = xstrdup(oldmailbox->part);
            char *olduniqueid = xstrdup(oldmailbox->uniqueid);
            if (config_auditlog)
                syslog(LOG_NOTICE, "auditlog: partitionmove sessionid=<%s> "
                       "mailbox=<%s> uniqueid=<%s> oldpart=<%s> newpart=<%s>",
                       session_id(),
                       oldmailbox->name, oldmailbox->uniqueid,
                       oldpartition, partition);
            /* this will sync-log the name anyway */
            mailbox_close(&oldmailbox);
            mailbox_delete_cleanup(NULL, oldpartition, oldname, olduniqueid);
            free(olduniqueid);
            free(oldpartition);
        }
        else if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
            /* no event notification */
            if (mboxevent) mboxevent->type = EVENT_CANCELLED;
        }
        else
            abort(); /* impossible, in theory */
    }

    /* free memory */
    strarray_fini(&inter);
    free(newpartition);
    mboxlist_entry_free(&newmbentry);

    return r;
}

/*
 * Check if the admin rights are present in the 'rights'
 */
static int mboxlist_have_admin_rights(const char *rights) {
    int access, have_admin_access;

    cyrus_acl_strtomask(rights, &access);
    have_admin_access = access & ACL_ADMIN;

    return have_admin_access;
}

/*
 * Change the ACL for mailbox 'name' so that 'identifier' has the
 * rights enumerated in the string 'rights'.  If 'rights' is the null
 * pointer, removes the ACL entry for 'identifier'.   'isadmin' is
 * nonzero if user is a mailbox admin.  'userid' is the user's login id.
 *
 * 1. Start transaction
 * 2. Check rights
 * 3. Set db entry
 * 4. Change backup copy (cyrus.header)
 * 5. Commit transaction
 * 6. Change mupdate entry
 *
 */
EXPORTED int mboxlist_setacl(const struct namespace *namespace __attribute__((unused)),
                    const char *name,
                    const char *identifier, const char *rights,
                    int isadmin, const char *userid,
                    const struct auth_state *auth_state)
{
    mbentry_t *mbentry = NULL;
    int r;
    int myrights;
    int mode = ACL_MODE_SET;
    int isusermbox = 0;
    int isidentifiermbox = 0;
    int anyoneuseracl = 1;
    int ensure_owner_rights = 0;
    int mask;
    const char *mailbox_owner = NULL;
    struct mailbox *mailbox = NULL;
    char *newacl = NULL;
    struct txn *tid = NULL;

    init_internal();

    /* round trip identifier to potentially strip domain */
    mbname_t *idname = mbname_from_userid(identifier);
    /* XXX - enforce cross domain restrictions */
    identifier = mbname_userid(idname);

    char *dbname = mboxname_to_dbname(name);

    /* checks if the mailbox belongs to the user who is trying to change the
       access rights */
    if (mboxname_userownsmailbox(userid, name))
        isusermbox = 1;
    anyoneuseracl = config_getswitch(IMAPOPT_ANYONEUSERACL);

    /* checks if the identifier is the mailbox owner */
    if (mboxname_userownsmailbox(identifier, name))
        isidentifiermbox = 1;

    /* who is the mailbox owner? */
    if (isusermbox) {
        mailbox_owner = userid;
    }
    else if (isidentifiermbox) {
        mailbox_owner = identifier;
    }

    /* ensure the access rights if the folder owner is the current user or
       the identifier */
    ensure_owner_rights = isusermbox || isidentifiermbox;

    /* 1. Start Transaction */
    /* lookup the mailbox to make sure it exists and get its acl */
    do {
        r = mboxlist_mylookup(dbname, &mbentry, &tid, 1, 1);
    } while(r == IMAP_AGAIN);

    /* Can't do this to an in-transit or reserved mailbox */
    if (!r && mbentry->mbtype & (MBTYPE_MOVING | MBTYPE_RESERVE | MBTYPE_DELETED)) {
        r = IMAP_MAILBOX_NOTSUPPORTED;
    }

    /* if it is not a remote mailbox, we need to unlock the mailbox list,
     * lock the mailbox, and re-lock the mailboxes list */
    /* we must do this to obey our locking rules */
    if (!r && !(mbentry->mbtype & MBTYPE_REMOTE)) {
        cyrusdb_abort(mbdb, tid);
        tid = NULL;
        mboxlist_entry_free(&mbentry);

        /* open & lock mailbox header */
        r = mailbox_open_iwl(name, &mailbox);

        if (!r) {
            do {
                /* lookup the mailbox to make sure it exists and get its acl */
                r = mboxlist_mylookup(dbname, &mbentry, &tid, 1, 1);
            } while (r == IMAP_AGAIN);
        }

        if(r) goto done;
    }

    /* 2. Check Rights */
    if (!r && !isadmin) {
        myrights = cyrus_acl_myrights(auth_state, mbentry->acl);
        if (!(myrights & ACL_ADMIN)) {
            r = (myrights & ACL_LOOKUP) ?
                IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
            goto done;
        }
    }

    /* 2.1 Only admin user can set 'anyone' rights if config says so */
    if (!r && !isadmin && !anyoneuseracl && !strncmp(identifier, "anyone", 6)) {
      r = IMAP_PERMISSION_DENIED;
      goto done;
    }

    /* 3. Set DB Entry */
    if(!r) {
        /* Make change to ACL */
        newacl = xstrdup(mbentry->acl);
        if (rights && *rights) {
            /* rights are present and non-empty */
            mode = ACL_MODE_SET;
            if (*rights == '+') {
                rights++;
                mode = ACL_MODE_ADD;
            }
            else if (*rights == '-') {
                rights++;
                mode = ACL_MODE_REMOVE;
            }
            /* do not allow non-admin user to remove the admin rights from mailbox owner */
            if (!isadmin && isidentifiermbox && mode != ACL_MODE_ADD) {
                int has_admin_rights = mboxlist_have_admin_rights(rights);
                if ((has_admin_rights && mode == ACL_MODE_REMOVE) ||
                   (!has_admin_rights && mode != ACL_MODE_REMOVE)) {
                    syslog(LOG_ERR, "Denied removal of admin rights on "
                           "folder \"%s\" (owner: %s) by user \"%s\"", name,
                           mailbox_owner, userid);
                    r = IMAP_PERMISSION_DENIED;
                    goto done;
                }
            }

            r = cyrus_acl_strtomask(rights, &mask);

            if (!r && cyrus_acl_set(&newacl, identifier, mode, mask,
                                    ensure_owner_rights ? mboxlist_ensureOwnerRights : 0,
                                    (void *)mailbox_owner)) {
                r = IMAP_INVALID_IDENTIFIER;
            }
        } else {
            /* do not allow to remove the admin rights from mailbox owner */
            if (!isadmin && isidentifiermbox) {
                syslog(LOG_ERR, "Denied removal of admin rights on "
                       "folder \"%s\" (owner: %s) by user \"%s\"", name,
                       mailbox_owner, userid);
                r = IMAP_PERMISSION_DENIED;
                goto done;
            }

            if (cyrus_acl_remove(&newacl, identifier,
                                 ensure_owner_rights ? mboxlist_ensureOwnerRights : 0,
                                 (void *)mailbox_owner)) {
                r = IMAP_INVALID_IDENTIFIER;
            }
        }
    }

    if (!r) {
        /* ok, change the database */
        free(mbentry->acl);
        mbentry->acl = xstrdupnull(newacl);
        mbentry->foldermodseq = mailbox_modseq_dirty(mailbox);

        r = mboxlist_update_entry(name, mbentry, &tid);

        if (r) {
            xsyslog(LOG_ERR, "DBERROR: error updating acl",
                             "mailbox=<%s> error=<%s>",
                             name, cyrusdb_strerror(r));
            r = IMAP_IOERROR;
        }

        /* send a AclChange event notification */
        struct mboxevent *mboxevent = mboxevent_new(EVENT_ACL_CHANGE);
        mboxevent_extract_mailbox(mboxevent, mailbox);
        mboxevent_set_acl(mboxevent, identifier, rights);
        mboxevent_set_access(mboxevent, NULL, NULL, userid, mailbox->name, 0);

        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);

    }

    /* 4. Change backup copy (cyrus.header) */
    /* we already have it locked from above */
    if (!r && !(mbentry->mbtype & MBTYPE_REMOTE)) {
        mailbox_set_acl(mailbox, newacl);
        /* want to commit immediately to ensure ordering */
        r = mailbox_commit(mailbox);
    }

    /* 5. Commit transaction */
    if (!r) {
        if((r = cyrusdb_commit(mbdb, tid)) != 0) {
            xsyslog(LOG_ERR, "DBERROR: failed on commit",
                             "error=<%s>",
                             cyrusdb_strerror(r));
            r = IMAP_IOERROR;
        }
        tid = NULL;
    }

    /* 6. Change mupdate entry  */
    if (!r && config_mupdate_server) {
        mupdate_handle *mupdate_h = NULL;
        /* commit the update to MUPDATE */
        char buf[MAX_PARTITION_LEN + HOSTNAME_SIZE + 2];

        snprintf(buf, sizeof(buf), "%s!%s", config_servername, mbentry->partition);

        r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
        if(r) {
            syslog(LOG_ERR,
                   "cannot connect to mupdate server for setacl on '%s'",
                   name);
        } else {
            r = mupdate_activate(mupdate_h, name, buf, newacl);
            if(r) {
                syslog(LOG_ERR,
                       "MUPDATE: can't update mailbox entry for '%s'",
                       name);
            }
        }
        mupdate_disconnect(&mupdate_h);
    }

  done:
    if (r && tid) {
        /* if we are mid-transaction, abort it! */
        int r2 = cyrusdb_abort(mbdb, tid);
        if (r2) {
            syslog(LOG_ERR,
                   "DBERROR: error aborting txn in mboxlist_setacl: %s",
                   cyrusdb_strerror(r2));
        }
    }
    mailbox_close(&mailbox);
    free(newacl);
    mboxlist_entry_free(&mbentry);
    mbname_free(&idname);
    free(dbname);

    return r;
}

/* change the ACL for mailbox 'name' when we have nothing but the name and the new value */
EXPORTED int mboxlist_updateacl_raw(const char *name, const char *newacl)
{
    struct mailbox *mailbox = NULL;
    int r = mailbox_open_iwl(name, &mailbox);
    if (!r) r = mboxlist_sync_setacls(name, newacl, mailbox_modseq_dirty(mailbox));
    if (!r) r = mailbox_set_acl(mailbox, newacl);
    if (!r) r = mailbox_commit(mailbox);
    mailbox_close(&mailbox);
    return r;
}

/*
 * Change the ACL for mailbox 'name'.  We already have it locked
 * and have written the backup copy to the header, so there's
 * nothing left but to write the mailboxes.db.
 *
 * 1. Start transaction
 * 2. Set db entry
 * 3. Commit transaction
 * 4. Change mupdate entry
 *
 */
EXPORTED int
mboxlist_sync_setacls(const char *name, const char *newacl, modseq_t foldermodseq)
{
    mbentry_t *mbentry = NULL;
    int r;
    struct txn *tid = NULL;
    char *dbname = mboxname_to_dbname(name);

    init_internal();

    /* 1. Start Transaction */
    /* lookup the mailbox to make sure it exists and get its acl */
    do {
        r = mboxlist_mylookup(dbname, &mbentry, &tid, 1, 1);
    } while(r == IMAP_AGAIN);
    if (r) goto done;

    // nothing to change, great
    if (!strcmpsafe(mbentry->acl, newacl) && mbentry->foldermodseq >= foldermodseq)
        goto done;

    /* Can't do this to an in-transit or reserved mailbox */
    if (mbentry->mbtype & (MBTYPE_MOVING | MBTYPE_RESERVE | MBTYPE_DELETED)) {
        r = IMAP_MAILBOX_NOTSUPPORTED;
        goto done;
    }

    /* 2. Set DB Entry */
    free(mbentry->acl);
    mbentry->acl = xstrdupnull(newacl);
    if (mbentry->foldermodseq < foldermodseq)
        mbentry->foldermodseq = foldermodseq;

    r = mboxlist_update_entry(name, mbentry, &tid);

    if (r) {
        xsyslog(LOG_ERR, "DBERROR: error updating acl",
                         "mailbox=<%s> error=<%s>",
                         name, cyrusdb_strerror(r));
        r = IMAP_IOERROR;
        goto done;
    }

    /* 3. Commit transaction */
    r = cyrusdb_commit(mbdb, tid);
    if (r) {
        xsyslog(LOG_ERR, "DBERROR: failed on commit",
                         "mailbox=<%s> error=<%s>",
                         name, cyrusdb_strerror(r));
        r = IMAP_IOERROR;
        goto done;
    }
    tid = NULL;

    /* 4. Change mupdate entry  */
    if (config_mupdate_server) {
        mupdate_handle *mupdate_h = NULL;
        /* commit the update to MUPDATE */
        char buf[MAX_PARTITION_LEN + HOSTNAME_SIZE + 2];
        sprintf(buf, "%s!%s", config_servername, mbentry->partition);

        r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
        if (r) {
            syslog(LOG_ERR,
                   "cannot connect to mupdate server for syncacl on '%s'",
                   name);
        } else {
            r = mupdate_activate(mupdate_h, name, buf, newacl);
            if (r) {
                syslog(LOG_ERR,
                       "MUPDATE: can't update mailbox entry for '%s'",
                       name);
            }
        }
        mupdate_disconnect(&mupdate_h);
    }

done:
    free(dbname);

    if (tid) {
        /* if we are mid-transaction, abort it! */
        int r2 = cyrusdb_abort(mbdb, tid);
        if (r2) {
            syslog(LOG_ERR,
                   "DBERROR: error aborting txn in sync_setacls %s: %s",
                   name, cyrusdb_strerror(r2));
        }
    }

    mboxlist_entry_free(&mbentry);

    return r;
}

struct find_rock {
    ptrarray_t globs;
    struct namespace *namespace;
    const char *userid;
    const char *domain;
    int mb_category;
    int checkmboxlist;
    int issubs;
    int singlepercent;
    struct db *db;
    int isadmin;
    const struct auth_state *auth_state;
    mbname_t *mbname;
    mbentry_t *mbentry;
    int matchlen;
    findall_p *p;
    findall_cb *cb;
    void *procrock;
};

/* return non-zero if we like this one */
static int find_p(void *rockp,
                  const char *key, size_t keylen,
                  const char *data, size_t datalen)
{
    struct find_rock *rock = (struct find_rock *) rockp;
    struct buf dbname = BUF_INITIALIZER;
    int i;

    /* skip any non-name keys */
    if (key[0] != KEY_TYPE_NAME) return 0;

    mboxlist_dbname_from_key(key, keylen, &dbname);

    assert(!rock->mbname);
    rock->mbname = mbname_from_dbname(buf_cstring(&dbname));

    if (!rock->isadmin && !config_getswitch(IMAPOPT_CROSSDOMAINS)) {
        /* don't list mailboxes outside of the default domain */
        if (strcmpsafe(rock->domain, mbname_domain(rock->mbname)))
            goto nomatch;
    }

    if (rock->mb_category && mbname_category(rock->mbname, rock->namespace, rock->userid) != rock->mb_category)
        goto nomatch;

    /* NOTE: this will all be cleaned up to be much more efficient sooner or later, with
     * a mbname_t being kept inside the mbentry, and the extname cached all the way to
     * final use.  For now, we pay the cost of re-calculating for simplicity of the
     * changes to mbname_t itself */
    const char *extname = mbname_extname(rock->mbname, rock->namespace, rock->userid);
    if (!extname) goto nomatch;

    int matchlen = 0;
    for (i = 0; i < rock->globs.count; i++) {
        glob *g = ptrarray_nth(&rock->globs, i);
        int thismatch = glob_test(g, extname);
        if (thismatch > matchlen) matchlen = thismatch;
    }

    /* If its not a match, skip it -- partial matches are ok. */
    if (!matchlen) goto nomatch;

    rock->matchlen = matchlen;

    /* subs DB has empty keys */
    if (rock->issubs)
        goto good;

    /* ignore entirely deleted records */
    if (mboxlist_parse_entry(&rock->mbentry,
                             buf_cstring(&dbname), buf_len(&dbname),
                             data, datalen))
        goto nomatch;

    /* nobody sees tombstones */
    if (rock->mbentry->mbtype & MBTYPE_DELETED)
        goto nomatch;

    /* only admins and mailbox owners see intermediates */
    if (rock->mbentry->mbtype & MBTYPE_INTERMEDIATE) {
        if (rock->isadmin ||
            !strcmpsafe(rock->userid, mbname_userid(rock->mbname))) goto good;
        else goto nomatch;
    }

    /* check acl */
    if (!rock->isadmin) {
        if (!(cyrus_acl_myrights(rock->auth_state, rock->mbentry->acl) & ACL_LOOKUP)) goto nomatch;
    }

good:
    buf_free(&dbname);

    if (rock->p) {
        struct findall_data fdata = { extname, 0, rock->mbentry, rock->mbname, 0 };
        /* mbname confirms that it's an exact match */
        if (rock->matchlen == (int) strlen(extname))
            fdata.is_exactmatch = 1;
        if (!rock->p(&fdata, rock->procrock)) goto nomatch;
        return 1;
    }
    else {
        return 1;
    }

nomatch:
    mboxlist_entry_free(&rock->mbentry);
    mbname_free(&rock->mbname);
    buf_free(&dbname);
    return 0;
}

static int find_cb(void *rockp,
                   /* XXX - confirm these are the same?  - nah */
                   const char *key __attribute__((unused)),
                   size_t keylen __attribute__((unused)),
                   const char *data __attribute__((unused)),
                   size_t datalen __attribute__((unused)))
{
    struct find_rock *rock = (struct find_rock *) rockp;
    char *testname = NULL;
    int r = 0;
    int i;

    if (rock->checkmboxlist && !rock->mbentry) {
        char *dbname = mbname_dbname(rock->mbname);
        r = mboxlist_mylookup(dbname, &rock->mbentry, NULL, 0, 0);
        free(dbname);
        if (r) {
            if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;
            goto done;
        }
    }

    const char *extname = mbname_extname(rock->mbname, rock->namespace, rock->userid);
    testname = xstrndup(extname, rock->matchlen);

    struct findall_data fdata = { testname, rock->mb_category, rock->mbentry, rock->mbname, 0 };

    if (rock->singlepercent) {
        char sep = rock->namespace->hier_sep;
        char *p = testname;
        /* we need to try all the previous names in order */
        while ((p = strchr(p, sep)) != NULL) {
            *p = '\0';

            /* only if this expression could fully match */
            int matchlen = 0;
            for (i = 0; i < rock->globs.count; i++) {
                glob *g = ptrarray_nth(&rock->globs, i);
                int thismatch = glob_test(g, testname);
                if (thismatch > matchlen) matchlen = thismatch;
            }

            if (matchlen == (int)strlen(testname)) {
                r = (*rock->cb)(&fdata, rock->procrock);
                if (r) goto done;
            }

            /* replace the separator for the next longest name */
            *p++ = sep;
        }
    }

    /* mbname confirms that it's an exact match */
    if (rock->matchlen == (int)strlen(extname))
        fdata.is_exactmatch = 1;

    r = (*rock->cb)(&fdata, rock->procrock);

 done:
    free(testname);
    mboxlist_entry_free(&rock->mbentry);
    mbname_free(&rock->mbname);
    return r;
}

struct allmb_rock {
    struct mboxlist_entry *mbentry;
    mboxlist_cb *proc;
    void *rock;
    int flags;
};

static int allmbox_cb(void *rock,
                      const char *key,
                      size_t keylen,
                      const char *data,
                      size_t datalen)
{
    struct allmb_rock *mbrock = (struct allmb_rock *)rock;

    if (!mbrock->mbentry) {
        struct buf dbname = BUF_INITIALIZER;

        mboxlist_dbname_from_key(key, keylen, &dbname);
        int r = mboxlist_parse_entry(&mbrock->mbentry,
                                     buf_base(&dbname), buf_len(&dbname),
                                     data, datalen);
        buf_free(&dbname);
        if (r) return r;
    }

    return mbrock->proc(mbrock->mbentry, mbrock->rock);
}

static int allmbox_p(void *rock,
                     const char *key,
                     size_t keylen,
                     const char *data,
                     size_t datalen)
{
    struct allmb_rock *mbrock = (struct allmb_rock *)rock;
    struct buf dbname = BUF_INITIALIZER;
    int r;

    /* skip any non-name keys */
    if (!(keylen && key[0] == KEY_TYPE_NAME)) return 0;

    /* free previous record */
    mboxlist_entry_free(&mbrock->mbentry);

    mboxlist_dbname_from_key(key, keylen, &dbname);
    r = mboxlist_parse_entry(&mbrock->mbentry,
                             buf_base(&dbname), buf_len(&dbname),
                             data, datalen);
    buf_free(&dbname);
    if (r) return 0;

    if (!(mbrock->flags & MBOXTREE_TOMBSTONES) && (mbrock->mbentry->mbtype & MBTYPE_DELETED))
        return 0;

    if (!(mbrock->flags & MBOXTREE_INTERMEDIATES) && (mbrock->mbentry->mbtype & MBTYPE_INTERMEDIATE))
        return 0;

    return 1; /* process this record */
}

EXPORTED int mboxlist_allmbox(const char *prefix, mboxlist_cb *proc, void *rock, int flags)
{
    struct allmb_rock mbrock = { NULL, proc, rock, flags };
    struct buf key = BUF_INITIALIZER;
    char *freeme = NULL;
    int r = 0;

    init_internal();

    if (!prefix) prefix = "";
    else {
        mbname_t *mbname = mbname_from_intname(prefix);
        if (prefix[strlen(prefix)-1] == '.') {
            /* A mailbox pattern ending in the hierarchy separator */
            mbname_push_boxes(mbname, "");
        }
        prefix = freeme = mbname_dbname(mbname);
        mbname_free(&mbname);
    }

    mboxlist_dbname_to_key(prefix, strlen(prefix), &key);

    r = cyrusdb_foreach(mbdb, buf_base(&key), buf_len(&key),
                        allmbox_p, allmbox_cb, &mbrock, 0);

    mboxlist_entry_free(&mbrock.mbentry);
    buf_free(&key);
    free(freeme);

    return r;
}

EXPORTED int mboxlist_mboxtree(const char *mboxname, mboxlist_cb *proc, void *rock, int flags)
{
    struct allmb_rock mbrock = { NULL, proc, rock, flags };
    char *dbname = mboxname_to_dbname(mboxname);
    struct buf key = BUF_INITIALIZER;
    int r = 0;

    init_internal();

    if (!(flags & MBOXTREE_SKIP_ROOT)) {
        mboxlist_dbname_to_key(dbname, strlen(dbname), &key);
        r = cyrusdb_forone(mbdb, buf_base(&key), buf_len(&key),
                           allmbox_p, allmbox_cb, &mbrock, 0);
        if (r) goto done;
    }

    if (!(flags & MBOXTREE_SKIP_CHILDREN)) {
        char *prefix = strconcat(dbname, DB_HIERSEP_STR, (char *)NULL);
        mboxlist_dbname_to_key(prefix, strlen(prefix), &key);
        r = cyrusdb_foreach(mbdb, buf_base(&key), buf_len(&key),
                            allmbox_p, allmbox_cb, &mbrock, 0);
        free(prefix);
        if (r) goto done;
    }

    if ((flags & MBOXTREE_DELETED)) {
        struct buf buf = BUF_INITIALIZER;
        const char *p = strchr(dbname, DB_DOMAINSEP_CHAR);
        const char *dp = config_getstring(IMAPOPT_DELETEDPREFIX);
        if (p) {
            buf_printf(&buf, "%.*s%c%s%c%s%c",
                       (int)(p-dbname), dbname, DB_DOMAINSEP_CHAR,
                       dp, DB_HIERSEP_CHAR, p+1, DB_HIERSEP_CHAR);
        }
        else {
            buf_printf(&buf, "%s%c%s%c",
                       dp, DB_HIERSEP_CHAR, dbname, DB_HIERSEP_CHAR);
        }
        const char *prefix = buf_cstring(&buf);
        mboxlist_dbname_to_key(prefix, strlen(prefix), &key);
        r = cyrusdb_foreach(mbdb, buf_base(&key), buf_len(&key),
                            allmbox_p, allmbox_cb, &mbrock, 0);
        buf_free(&buf);
        if (r) goto done;
    }

 done:
    mboxlist_entry_free(&mbrock.mbentry);
    buf_free(&key);
    free(dbname);
    return r;
}

static int racls_del_cb(void *rock,
                  const char *key, size_t keylen,
                  const char *data __attribute__((unused)),
                  size_t datalen __attribute__((unused)))
{
    struct txn **txn = (struct txn **)rock;
    return cyrusdb_delete(mbdb, key, keylen, txn, /*force*/0);
}

static int racls_add_cb(const mbentry_t *mbentry, void *rock)
{
    struct txn **txn = (struct txn **)rock;
    return mboxlist_update_racl(mbentry->name, NULL, mbentry, txn);
}

EXPORTED int mboxlist_set_racls(int enabled)
{
    struct buf key = BUF_INITIALIZER;
    struct txn *tid = NULL;
    int r = 0;
    int modified_mbdb = 0;

    mboxlist_racl_key(0, NULL, NULL, &key);

    init_internal();

    if (have_racl && !enabled) {
        syslog(LOG_NOTICE, "removing reverse acl support");
        /* remove */
        r = cyrusdb_foreach(mbdb, buf_base(&key), buf_len(&key),
                            NULL, racls_del_cb, &tid, &tid);
        if (!r) have_racl = 0;
        modified_mbdb = 1;
    }
    if (enabled && !have_racl) {
        /* add */
        struct allmb_rock mbrock = { NULL, racls_add_cb, &tid, 0 };
        /* we can't use mboxlist_allmbox because it doesn't do transactions */
        syslog(LOG_NOTICE, "adding reverse acl support");
        r = cyrusdb_foreach(mbdb, "", 0, allmbox_p, allmbox_cb, &mbrock, &tid);
        if (r) {
            syslog(LOG_ERR, "ERROR: failed to add reverse acl support %s", error_message(r));
        }
        modified_mbdb = 1;
        mboxlist_entry_free(&mbrock.mbentry);
        if (!r) r = cyrusdb_store(mbdb, buf_base(&key), buf_len(&key), "", 0, &tid);
        if (!r) have_racl = 1;
    }

    if (!modified_mbdb || !tid) return r;

    if (r)
        cyrusdb_abort(mbdb, tid);
    else
        cyrusdb_commit(mbdb, tid);

    buf_free(&key);
    return r;
}


struct alluser_rock {
    char *prev;
    user_cb *proc;
    void *rock;
};

static int alluser_cb(const mbentry_t *mbentry, void *rock)
{
    struct alluser_rock *urock = (struct alluser_rock *)rock;
    char *userid = mboxname_to_userid(mbentry->name);
    int r = 0;

    if (userid) {
        if (strcmpsafe(urock->prev, userid)) {
            r = urock->proc(userid, urock->rock);
            free(urock->prev);
            urock->prev = userid;
        } else
            free(userid);
    }

    return r;
}

EXPORTED int mboxlist_alluser(user_cb *proc, void *rock)
{
    struct alluser_rock urock;
    int r = 0;

    init_internal();

    urock.prev = NULL;
    urock.proc = proc;
    urock.rock = rock;
    r = mboxlist_allmbox(NULL, alluser_cb, &urock, /*flags*/0);
    free(urock.prev);
    return r;
}

struct raclrock {
    int prefixlen;
    strarray_t *list;
};

static int racl_cb(void *rock,
                   const char *key, size_t keylen,
                   const char *data __attribute__((unused)),
                   size_t datalen __attribute__((unused)))
{
    struct raclrock *raclrock = (struct raclrock *)rock;
    strarray_appendm(raclrock->list, xstrndup(key + raclrock->prefixlen, keylen - raclrock->prefixlen));
    return 0;
}

static int mboxlist_racl_matches(struct db *db,
                                 int isuser, const char *userid,
                                 const struct auth_state *auth_state,
                                 const char *mboxprefix, size_t len,
                                 strarray_t *matches)
{
    struct buf raclprefix = BUF_INITIALIZER;
    strarray_t *groups = NULL;
    struct raclrock raclrock = { 0, matches };
    int i;

    /* direct access by userid */
    mboxlist_racl_key(isuser, userid, NULL, &raclprefix);
    /* this is the prefix */
    raclrock.prefixlen = buf_len(&raclprefix);
    /* we only need to look inside the prefix still, but we keep the length
     * in raclrock pointing to the start of the mboxname part of the key so
     * we get correct names in matches */
    if (len) buf_appendmap(&raclprefix, mboxprefix, len);
    cyrusdb_foreach(db,
                    buf_cstring(&raclprefix),
                    buf_len(&raclprefix),
                    NULL, racl_cb, &raclrock, NULL);

    /* indirect access via group membership: same logic as userid, but per group */
    if (auth_state)
        groups = auth_groups(auth_state);
    if (groups) {
        for (i = 0; i < strarray_size(groups); i++) {
            mboxlist_racl_key(isuser, strarray_nth(groups, i), NULL, &raclprefix);
            raclrock.prefixlen = buf_len(&raclprefix);
            if (len) buf_appendmap(&raclprefix, mboxprefix, len);

            cyrusdb_foreach(db,
                            buf_cstring(&raclprefix),
                            buf_len(&raclprefix),
                            NULL, racl_cb, &raclrock, NULL);
        }

        strarray_free(groups);
    }

    // can "anyone" access this?
    mboxlist_racl_key(isuser, "anyone", NULL, &raclprefix);
    raclrock.prefixlen = buf_len(&raclprefix);
    if (len) buf_appendmap(&raclprefix, mboxprefix, len);
    cyrusdb_foreach(db,
                    buf_cstring(&raclprefix),
                    buf_len(&raclprefix),
                    NULL, racl_cb, &raclrock, NULL);

    strarray_sort(matches, cmpstringp_raw);
    strarray_uniq(matches);

    buf_free(&raclprefix);
    return 0;
}

/* auth_state parameter is optional, but is needed for proper expansion
 * of group RACLs if flags contains MBOXTREE_PLUS_RACL */
EXPORTED int mboxlist_usermboxtree(const char *userid,
                                   const struct auth_state *auth_state,
                                   mboxlist_cb *proc, void *rock, int flags)
{
    char *inbox = mboxname_user_mbox(userid, 0);
    int r = mboxlist_mboxtree(inbox, proc, rock, flags);

    if (flags & MBOXTREE_PLUS_RACL) {
        /* we're using reverse ACLs */
        struct allmb_rock mbrock = { NULL, proc, rock, flags };
        struct buf key = BUF_INITIALIZER;
        int i;
        strarray_t matches = STRARRAY_INITIALIZER;

        /* user items */
        mboxlist_racl_matches(mbdb, 1, userid, auth_state, NULL, 0, &matches);
        for (i = 0; !r && i < strarray_size(&matches); i++) {
            const char *mboxname = strarray_nth(&matches, i);
            mboxlist_dbname_to_key(mboxname, strlen(mboxname), &key);
            r = cyrusdb_forone(mbdb, buf_base(&key), buf_len(&key),
                               allmbox_p, allmbox_cb, &mbrock, 0);
        }

        /* shared items */
        strarray_fini(&matches);
        strarray_init(&matches);
        mboxlist_racl_matches(mbdb, 0, userid, auth_state, NULL, 0, &matches);
        for (i = 0; !r && i < strarray_size(&matches); i++) {
            const char *mboxname = strarray_nth(&matches, i);
            mboxlist_dbname_to_key(mboxname, strlen(mboxname), &key);
            r = cyrusdb_forone(mbdb, buf_base(&key), buf_len(&key),
                               allmbox_p, allmbox_cb, &mbrock, 0);
        }

        buf_free(&key);
        strarray_fini(&matches);
        mboxlist_entry_free(&mbrock.mbentry);
    }

    free(inbox);
    return r;
}

static int mboxlist_find_category(struct find_rock *rock, const char *prefix, size_t len)
{
    struct buf key = BUF_INITIALIZER;
    int r = 0;

    init_internal();

    if (!rock->issubs && !rock->isadmin && have_racl) {
        /* we're using reverse ACLs */
        strarray_t matches = STRARRAY_INITIALIZER;
        int i;

        mboxlist_racl_matches(rock->db,
                              (rock->mb_category == MBNAME_OTHERUSER),
                              rock->userid,
                              rock->auth_state,
                              prefix, len,
                              &matches);

        /* now call the callbacks */
        for (i = 0; !r && i < strarray_size(&matches); i++) {
            const char *dbname = strarray_nth(&matches, i);
            mboxlist_dbname_to_key(dbname, strlen(dbname), &key);
            r = cyrusdb_forone(rock->db, buf_base(&key), buf_len(&key),
                               &find_p, &find_cb, rock, NULL);
        }
        strarray_fini(&matches);
    }
    else {
        mboxlist_dbname_to_key(prefix, len, &key);
        r = cyrusdb_foreach(rock->db, buf_base(&key), buf_len(&key),
                            &find_p, &find_cb, rock, NULL);
    }

    if (r == CYRUSDB_DONE) r = 0;
    buf_free(&key);
    return r;
}

/*
 * Find all mailboxes that match 'pattern'.
 * 'isadmin' is nonzero if user is a mailbox admin.  'userid'
 * is the user's login id.  For each matching mailbox, calls
 * 'proc' with the name of the mailbox.  If 'proc' ever returns
 * a nonzero value, mboxlist_findall immediately stops searching
 * and returns that value.  'rock' is passed along as an argument to proc in
 * case it wants some persistent storage or extra data.
 */
/* Find all mailboxes that match 'pattern'. */

static int mboxlist_do_find(struct find_rock *rock, const strarray_t *patterns)
{
    const char *userid = rock->userid;
    int isadmin = rock->isadmin;
    struct buf key = BUF_INITIALIZER;
    int crossdomains = config_getswitch(IMAPOPT_CROSSDOMAINS);
    int allowdeleted = config_getswitch(IMAPOPT_ALLOWDELETED);
    char inbox[MAX_MAILBOX_BUFFER];
    size_t inboxlen = 0;
    size_t prefixlen, len;
    size_t domainlen = 0;
    size_t userlen = userid ? strlen(userid) : 0;
    char domainpat[MAX_MAILBOX_BUFFER]; /* do intra-domain fetches only */
    char commonpat[MAX_MAILBOX_BUFFER];
    int r = 0;
    int i;
    const char *p;

    if (patterns->count < 1) return 0; /* nothing to do */

    for (i = 0; i < patterns->count; i++) {
        glob *g = glob_init(strarray_nth(patterns, i), rock->namespace->hier_sep);
        ptrarray_append(&rock->globs, g);
    }

    if (config_virtdomains && userid && (p = strchr(userid, '@'))) {
        userlen = p - userid;
        domainlen = strlen(p); /* includes separator */
        snprintf(domainpat, sizeof(domainpat), "%s%c", p+1, DB_DOMAINSEP_CHAR);
    }
    else
        domainpat[0] = '\0';

    /* calculate the inbox (with trailing .INBOX. for later use) */
    if (userid && (!(p = strchr(userid, rock->namespace->hier_sep)) ||
        ((p - userid) > (int)userlen)) &&
        strlen(userid)+7 < MAX_MAILBOX_BUFFER) {

        if (domainlen)
            snprintf(inbox, sizeof(inbox), "%s%c",
                     userid+userlen+1, DB_DOMAINSEP_CHAR);

        snprintf(inbox+domainlen, sizeof(inbox)-domainlen,
                 "%s%.*s%cINBOX%c", DB_USER_PREFIX,
                 (int)userlen, userid, DB_HIERSEP_CHAR, DB_HIERSEP_CHAR);
        inboxlen = strlen(inbox) - 7;
    }
    else {
        userid = 0;
    }

    /* Find the common search prefix of all patterns */
    const char *firstpat = strarray_nth(patterns, 0);
    for (prefixlen = 0; firstpat[prefixlen]; prefixlen++) {
        if (prefixlen >= MAX_MAILBOX_NAME) {
            r = IMAP_MAILBOX_BADNAME;
            goto done;
        }
        char c = firstpat[prefixlen];
        for (i = 1; i < patterns->count; i++) {
            const char *pat = strarray_nth(patterns, i);
            if (pat[prefixlen] != c) break;
        }
        if (c == rock->namespace->hier_sep) c = DB_HIERSEP_CHAR;

        if (i < patterns->count) break;
        if (c == '*' || c == '%' || c == '?') break;
        commonpat[prefixlen] = c;
    }
    commonpat[prefixlen] = '\0';

    if (patterns->count == 1) {
        /* Skip pattern which matches shared namespace prefix */
        if (!strcmp(firstpat+prefixlen, "%"))
            rock->singlepercent = 2;
        /* output prefix regardless */
        if (!strcmp(firstpat+prefixlen, "*%"))
            rock->singlepercent = 1;
    }

    /*
     * Personal (INBOX) namespace (only if not admin)
     */
    if (userid && !isadmin) {
        /* first the INBOX */
        rock->mb_category = MBNAME_INBOX;
        mboxlist_dbname_to_key(inbox, inboxlen, &key);
        r = cyrusdb_forone(rock->db, buf_base(&key), buf_len(&key),
                           &find_p, &find_cb, rock, NULL);
        if (r == CYRUSDB_DONE) r = 0;
        if (r) goto done;

        if (rock->namespace->isalt) {
            /* do exact INBOX subs before resetting the namebuffer */
            rock->mb_category = MBNAME_INBOXSUB;
            mboxlist_dbname_to_key(inbox, inboxlen+7, &key);
            r = cyrusdb_foreach(rock->db, buf_base(&key), buf_len(&key),
                                &find_p, &find_cb, rock, NULL);
            if (r == CYRUSDB_DONE) r = 0;
            if (r) goto done;

            /* reset the namebuffer */
            if (rock->cb)
                r = (*rock->cb)(NULL, rock->procrock);
            if (r) goto done;
        }

        /* iterate through all the mailboxes under the user's inbox */
        rock->mb_category = MBNAME_OWNER;
        mboxlist_dbname_to_key(inbox, inboxlen+1, &key);
        r = cyrusdb_foreach(rock->db, buf_base(&key), buf_len(&key),
                            &find_p, &find_cb, rock, NULL);
        if (r == CYRUSDB_DONE) r = 0;
        if (r) goto done;

        /* "Alt Prefix" folders */
        if (rock->namespace->isalt) {
            /* reset the namebuffer */
            if (rock->cb)
                r = (*rock->cb)(NULL, rock->procrock);
            if (r) goto done;

            rock->mb_category = MBNAME_ALTINBOX;

            /* special case user.foo.INBOX.  If we're singlepercent == 2, this could
             return DONE, in which case we don't need to foreach the rest of the
             altprefix space */
            mboxlist_dbname_to_key(inbox, inboxlen+6, &key);
            r = cyrusdb_forone(rock->db, buf_base(&key), buf_len(&key),
                               &find_p, &find_cb, rock, NULL);
            if (r == CYRUSDB_DONE) goto skipalt;
            if (r) goto done;

            /* special case any other altprefix stuff */
            rock->mb_category = MBNAME_ALTPREFIX;
            mboxlist_dbname_to_key(inbox, inboxlen+1, &key);
            r = cyrusdb_foreach(rock->db, buf_base(&key), buf_len(&key),
                                &find_p, &find_cb, rock, NULL);
        skipalt: /* we got a done, so skip out of the foreach early */
            if (r == CYRUSDB_DONE) r = 0;
            if (r) goto done;
        }
    }

    /*
     * Other Users namespace
     *
     * If "Other Users*" can match pattern, search for those mailboxes next
     */
    if (isadmin || rock->namespace->accessible[NAMESPACE_USER]) {
        len = strlen(rock->namespace->prefix[NAMESPACE_USER]);
        if (len) len--; // trailing separator

        if (!strncmp(rock->namespace->prefix[NAMESPACE_USER], commonpat, MIN(len, prefixlen))) {
            if (prefixlen <= len) {
                /* we match all users */
                strlcpy(domainpat+domainlen, DB_USER_PREFIX, sizeof(domainpat)-domainlen);
            }
            else {
                /* just those in this prefix */
                strlcpy(domainpat+domainlen, DB_USER_PREFIX, sizeof(domainpat)-domainlen);
                strlcpy(domainpat+domainlen+5, commonpat+len+1, sizeof(domainpat)-domainlen-5);
            }

            rock->mb_category = MBNAME_OTHERUSER;

            /* because of how domains work, with crossdomains or admin you can't prefix at all :( */
            size_t thislen = (isadmin || crossdomains) ? 0 : strlen(domainpat);

            /* reset the namebuffer */
            if (rock->cb)
                r = (*rock->cb)(NULL, rock->procrock);
            if (r) goto done;

            r = mboxlist_find_category(rock, domainpat, thislen);
            if (r) goto done;
        }
    }

    /*
     * Shared namespace
     *
     * search for all remaining mailboxes.
     * just bother looking at the ones that have the same pattern prefix.
     */
    if (isadmin || rock->namespace->accessible[NAMESPACE_SHARED]) {
        len = strlen(rock->namespace->prefix[NAMESPACE_SHARED]);
        if (len) len--; // trailing separator

        if (!strncmp(rock->namespace->prefix[NAMESPACE_SHARED], commonpat, MIN(len, prefixlen))) {
            rock->mb_category = MBNAME_SHARED;

            /* reset the namebuffer */
            if (rock->cb)
                r = (*rock->cb)(NULL, rock->procrock);
            if (r) goto done;

            /* iterate through all the non-user folders on the server */
            r = mboxlist_find_category(rock, domainpat, domainlen);
            if (r) goto done;
        }
    }

    /* finally deleted namespaces - first the owner */
    if (!isadmin && allowdeleted && userid) {
        /* inboxname to deleted */
        char prefix[MAX_MAILBOX_BUFFER];
        const char *deletedprefix = config_getstring(IMAPOPT_DELETEDPREFIX);

        snprintf(prefix, MAX_MAILBOX_BUFFER, "%.*s%s%c%.*s",
                 (int) domainlen, inbox, deletedprefix, DB_HIERSEP_CHAR,
                 (int) (inboxlen - domainlen), inbox+domainlen);

        size_t prefixlen = strlen(prefix);
        prefix[prefixlen] = DB_HIERSEP_CHAR;

        rock->mb_category = MBNAME_OWNERDELETED;

        /* reset the namebuffer */
        if (rock->cb)
            r = (*rock->cb)(NULL, rock->procrock);
        if (r) goto done;

        mboxlist_dbname_to_key(prefix, prefixlen+1, &key);
        r = cyrusdb_foreach(rock->db, buf_base(&key), buf_len(&key),
                            &find_p, &find_cb, rock, NULL);
        if (r) goto done;
    }

    /* and everything else */
    if (isadmin || (allowdeleted && rock->namespace->accessible[NAMESPACE_SHARED])) {
        rock->mb_category = MBNAME_OTHERDELETED;

        /* reset the namebuffer */
        if (rock->cb)
            r = (*rock->cb)(NULL, rock->procrock);
        if (r) goto done;

        /* iterate through all the non-user folders on the server */
        r = mboxlist_find_category(rock, domainpat, domainlen);
        if (r) goto done;
    }

    /* finish with a reset call always */
    if (rock->cb)
        r = (*rock->cb)(NULL, rock->procrock);

 done:
    for (i = 0; i < rock->globs.count; i++) {
        glob *g = ptrarray_nth(&rock->globs, i);
        glob_free(&g);
    }
    ptrarray_fini(&rock->globs);
    buf_free(&key);

    return r;
}

EXPORTED int mboxlist_findallmulti(struct namespace *namespace,
                                   const strarray_t *patterns, int isadmin,
                                   const char *userid, const struct auth_state *auth_state,
                                   findall_cb *proc, void *rock)
{
    return mboxlist_findallmulti_withp(namespace, patterns, isadmin,
                                       userid, auth_state,
                                       NULL, proc, rock);
}

EXPORTED int mboxlist_findallmulti_withp(struct namespace *namespace,
                                   const strarray_t *patterns, int isadmin,
                                   const char *userid, const struct auth_state *auth_state,
                                   findall_p *p, findall_cb *cb, void *rock)
{
    int r = 0;

    init_internal();

    if (!namespace) namespace = mboxname_get_adminnamespace();

    struct find_rock cbrock;
    memset(&cbrock, 0, sizeof(struct find_rock));

    cbrock.auth_state = auth_state;
    cbrock.db = mbdb;
    cbrock.isadmin = isadmin;
    cbrock.namespace = namespace;
    cbrock.p = p;
    cbrock.cb = cb;
    cbrock.procrock = rock;
    cbrock.userid = userid;
    if (userid) {
        const char *domp = strchr(userid, '@');
        if (domp) cbrock.domain = domp + 1;
    }

    r = mboxlist_do_find(&cbrock, patterns);

    return r;
}

EXPORTED int mboxlist_findall(struct namespace *namespace,
                              const char *pattern, int isadmin,
                              const char *userid, const struct auth_state *auth_state,
                              findall_cb *proc, void *rock)
{
    return mboxlist_findall_withp(namespace, pattern, isadmin,
                                  userid, auth_state,
                                  NULL, proc, rock);
}

EXPORTED int mboxlist_findall_withp(struct namespace *namespace,
                              const char *pattern, int isadmin,
                              const char *userid, const struct auth_state *auth_state,
                              findall_p *p, findall_cb *cb, void *rock)
{
    strarray_t patterns = STRARRAY_INITIALIZER;
    strarray_append(&patterns, pattern);

    init_internal();

    int r = mboxlist_findallmulti_withp(namespace, &patterns, isadmin, userid, auth_state,
                                  p, cb, rock);

    strarray_fini(&patterns);

    return r;
}

EXPORTED int mboxlist_findone(struct namespace *namespace,
                              const char *intname, int isadmin,
                              const char *userid, const struct auth_state *auth_state,
                              findall_cb *proc, void *rock)
{
    return mboxlist_findone_withp(namespace, intname, isadmin,
                                  userid, auth_state,
                                  NULL, proc, rock);
}

EXPORTED int mboxlist_findone_withp(struct namespace *namespace,
                              const char *intname, int isadmin,
                              const char *userid, const struct auth_state *auth_state,
                              findall_p *p, findall_cb *cb, void *rock)
{
    int r = 0;

    if (!namespace) namespace = mboxname_get_adminnamespace();

    struct find_rock cbrock;
    memset(&cbrock, 0, sizeof(struct find_rock));

    init_internal();

    cbrock.auth_state = auth_state;
    cbrock.db = mbdb;
    cbrock.isadmin = isadmin;
    cbrock.namespace = namespace;
    cbrock.p = p;
    cbrock.cb = cb;
    cbrock.procrock = rock;
    cbrock.userid = userid;
    if (userid) {
        const char *domp = strchr(userid, '@');
        if (domp) cbrock.domain = domp + 1;
    }

    struct buf key = BUF_INITIALIZER;
    mbname_t *mbname = mbname_from_intname(intname);
    char *dbname = mbname_dbname(mbname);
    glob *g = glob_init(mbname_extname(mbname, namespace, userid),
                        namespace->hier_sep);
    ptrarray_append(&cbrock.globs, g);
    mbname_free(&mbname);

    mboxlist_dbname_to_key(dbname, strlen(dbname), &key);
    r = cyrusdb_forone(cbrock.db, buf_base(&key), buf_len(&key),
                       &find_p, &find_cb, &cbrock, NULL);

    buf_free(&key);
    free(dbname);
    glob_free(&g);
    ptrarray_fini(&cbrock.globs);

    return r;
}

static int exists_cb(const mbentry_t *mbentry __attribute__((unused)), void *rock)
{
    int *exists = (int *)rock;
    *exists = 1;
    return CYRUSDB_DONE; /* one is enough */
}

struct changequota_rock {
    const char *root;
    int silent;
};

/*
 * Set all the resource quotas on, or create a quota root.
 */
EXPORTED int mboxlist_setquotas(const char *root,
                       quota_t newquotas[QUOTA_NUMRESOURCES],
                       modseq_t quotamodseq, int force)
{
    struct quota q;
    int r;
    int res;
    struct txn *tid = NULL;
    struct mboxevent *mboxevents = NULL;
    struct mboxevent *quotachange_event = NULL;
    struct mboxevent *quotawithin_event = NULL;
    int silent = quotamodseq ? 1 : 0;

    init_internal();

    if (!root[0] || root[0] == '.' || strchr(root, '/')
        || strchr(root, '*') || strchr(root, '%') || strchr(root, '?')) {
        return IMAP_MAILBOX_BADNAME;
    }

    quota_init(&q, root);
    r = quota_read(&q, &tid, 1);

    if (!r) {
        int changed = 0;
        int underquota;
        quota_t oldquotas[QUOTA_NUMRESOURCES];

        /* has it changed? */
        for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
            oldquotas[res] = q.limits[res];
            if (q.limits[res] != newquotas[res]) {
                underquota = 0;

                /* Prepare a QuotaChange event notification *now*.
                 *
                 * This is to ensure the QuotaChange is emitted before the
                 * subsequent QuotaWithin (if the latter becomes applicable).
                 */
                if (quotachange_event == NULL) {
                    quotachange_event = mboxevent_enqueue(EVENT_QUOTA_CHANGE,
                                                          &mboxevents);
                }

                /* prepare a QuotaWithin event notification if now under quota */
                if (quota_is_overquota(&q, res, NULL) &&
                    (!quota_is_overquota(&q, res, newquotas) || newquotas[res] == -1)) {
                    if (quotawithin_event == NULL)
                        quotawithin_event = mboxevent_enqueue(EVENT_QUOTA_WITHIN,
                                                              &mboxevents);
                    underquota++;
                }

                q.limits[res] = newquotas[res];
                changed++;

                mboxevent_extract_quota(quotachange_event, &q, res);
                if (underquota)
                    mboxevent_extract_quota(quotawithin_event, &q, res);
            }
        }
        if (changed) {
            if (quotamodseq)
                q.modseq = quotamodseq;
            r = quota_write(&q, silent, &tid);

            if (quotachange_event == NULL) {
                quotachange_event = mboxevent_enqueue(EVENT_QUOTA_CHANGE, &mboxevents);
            }

            for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
                mboxevent_extract_quota(quotachange_event, &q, res);
            }

            if (config_auditlog) {
                struct buf item = BUF_INITIALIZER;
                for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
                    buf_printf(&item, " old%s=<%lld> new%s=<%lld>",
                               quota_names[res], oldquotas[res],
                               quota_names[res], newquotas[res]);
                }
                syslog(LOG_NOTICE, "auditlog: setquota root=<%s>%s", root, buf_cstring(&item));
                buf_free(&item);
            }
        }

        if (!r)
            quota_commit(&tid);

        goto done;
    }

    if (r != IMAP_QUOTAROOT_NONEXISTENT)
        goto done;

    if (config_virtdomains && root[strlen(root)-1] == '!') {
        /* domain quota */
    }
    else {
        mbentry_t *mbentry = NULL;

        /* look for a top-level mailbox in the proposed quotaroot */
        r = mboxlist_lookup(root, &mbentry, NULL);
        if (r) {
            if (!force && r == IMAP_MAILBOX_NONEXISTENT) {
                mboxlist_mboxtree(root, exists_cb, &force, MBOXTREE_SKIP_ROOT);
            }
            /* are we going to force the create anyway? */
            if (force) {
                r = 0;
            }
        }
        else if (mbentry->mbtype & (MBTYPE_REMOTE | MBTYPE_MOVING)) {
            /* Can't set quota on a remote mailbox */
            r = IMAP_MAILBOX_NOTSUPPORTED;
        }
        mboxlist_entry_free(&mbentry);
        if (r) goto done;
    }

    /* safe against quota -f and other root change races */
    r = quota_changelock();
    if (r) goto done;

    /* initialise the quota */
    memcpy(q.limits, newquotas, sizeof(q.limits));
    if (quotamodseq)
        q.modseq = quotamodseq;
    r = quota_write(&q, silent, &tid);
    if (r) goto done;

    /* prepare a QuotaChange event notification */
    if (quotachange_event == NULL)
        quotachange_event = mboxevent_enqueue(EVENT_QUOTA_CHANGE, &mboxevents);

    for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
        mboxevent_extract_quota(quotachange_event, &q, res);
    }

    quota_commit(&tid);

    if (config_auditlog) {
        struct buf item = BUF_INITIALIZER;
        for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
            buf_printf(&item, " new%s=<%lld>",
                       quota_names[res], newquotas[res]);
        }
        syslog(LOG_NOTICE, "auditlog: newquota root=<%s>%s", root, buf_cstring(&item));
        buf_free(&item);
    }

    /* recurse through mailboxes, setting the quota and finding
     * out the usage */
    struct changequota_rock crock = { root, silent };
    mboxlist_mboxtree(root, mboxlist_changequota, &crock, 0);

    quota_changelockrelease();

done:
    quota_free(&q);
    if (r && tid) quota_abort(&tid);
    if (!r) {
        sync_log_quota(root);

        /* send QuotaChange and QuotaWithin event notifications */
        mboxevent_notify(&mboxevents);
    }
    mboxevent_freequeue(&mboxevents);

    return r;
}

/*
 *  Remove a quota root
 */
EXPORTED int mboxlist_unsetquota(const char *root)
{
    struct quota q;
    int r=0;

    init_internal();

    if (!root[0] || root[0] == '.' || strchr(root, '/')
        || strchr(root, '*') || strchr(root, '%') || strchr(root, '?')) {
        return IMAP_MAILBOX_BADNAME;
    }

    quota_init(&q, root);
    r = quota_read(&q, NULL, 0);
    /* already unset */
    if (r == IMAP_QUOTAROOT_NONEXISTENT) {
        r = 0;
        goto done;
    }
    if (r) goto done;

    r = quota_changelock();

    /*
     * Have to remove it from all affected mailboxes
     */
    mboxlist_mboxtree(root, mboxlist_rmquota, (void *)root, /*flags*/0);

    if (config_auditlog) {
        struct buf item = BUF_INITIALIZER;
        int res;
        for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
            buf_printf(&item, " old%s=<%lld>", quota_names[res], q.limits[res]);
        }
        syslog(LOG_NOTICE, "auditlog: rmquota root=<%s>%s", root, buf_cstring(&item));
        buf_free(&item);
    }

    r = quota_deleteroot(root, 0);
    quota_changelockrelease();

    if (!r) sync_log_quota(root);

 done:
    quota_free(&q);
    return r;
}

EXPORTED int mboxlist_update_foldermodseq(const char *name, modseq_t foldermodseq)
{
    mbentry_t *mbentry = NULL;

    init_internal();

    int r = mboxlist_lookup_allow_all(name, &mbentry, NULL);
    if (r) return r;

    if (mbentry->foldermodseq < foldermodseq) {
        mbentry->foldermodseq = foldermodseq;
        r = mboxlist_update(mbentry, 0);
    }

    mboxlist_entry_free(&mbentry);

    return r;
}

/*
 * ACL access canonicalization routine which ensures that 'owner'
 * retains lookup, administer, and create rights over a mailbox.
 */
EXPORTED int mboxlist_ensureOwnerRights(void *rock, const char *identifier,
                               int myrights)
{
    char *owner = (char *)rock;
    if (strcmp(identifier, owner) != 0) return myrights;
    return myrights|config_implicitrights;
}

/*
 * Helper function to remove the quota root for 'name'
 */
static int mboxlist_rmquota(const mbentry_t *mbentry, void *rock)
{
    int r = 0;
    struct mailbox *mailbox = NULL;
    const char *oldroot = (const char *) rock;

    assert(oldroot != NULL);

    r = mailbox_open_iwl(mbentry->name, &mailbox);
    if (r) goto done;

    if (mailbox->quotaroot) {
        if (strcmp(mailbox->quotaroot, oldroot)) {
            /* Part of a different quota root */
            goto done;
        }

        r = mailbox_set_quotaroot(mailbox, NULL);
    }

 done:
    mailbox_close(&mailbox);

    if (r) {
        syslog(LOG_ERR, "LOSTQUOTA: unable to remove quota root %s for %s: %s",
               oldroot, mbentry->name, error_message(r));
    }

    /* not a huge tragedy if we failed, so always return success */
    return 0;
}

/*
 * Helper function to change the quota root for 'name' to that pointed
 * to by the static global struct pointer 'mboxlist_newquota'.
 */
static int mboxlist_changequota(const mbentry_t *mbentry, void *rock)
{
    int r = 0;
    struct mailbox *mailbox = NULL;
    struct changequota_rock *crock = rock;
    int res;
    quota_t quota_usage[QUOTA_NUMRESOURCES];

    assert(crock->root);

    r = mailbox_open_iwl(mbentry->name, &mailbox);
    if (r) goto done;

    mailbox_get_usage(mailbox, quota_usage);

    if (mailbox->quotaroot) {
        quota_t quota_diff[QUOTA_NUMRESOURCES];

        if (strlen(mailbox->quotaroot) >= strlen(crock->root)) {
            /* Part of a child quota root - skip */
            goto done;
        }

        /* remove usage from the old quotaroot */
        for (res = 0; res < QUOTA_NUMRESOURCES ; res++) {
            quota_diff[res] = -quota_usage[res];
        }
        r = quota_update_useds(mailbox->quotaroot, quota_diff,
                               mailbox->name, crock->silent);
    }

    /* update (or set) the quotaroot */
    r = mailbox_set_quotaroot(mailbox, crock->root);
    if (r) goto done;

    /* update the new quota root */
    r = quota_update_useds(crock->root, quota_usage, mailbox->name, crock->silent);

 done:
    mailbox_close(&mailbox);

    if (r) {
        syslog(LOG_ERR, "LOSTQUOTA: unable to change quota root for %s to %s: %s",
               mbentry->name, crock->root, error_message(r));
    }

    /* Note, we're a callback, and it's not a huge tragedy if we
     * fail, so we don't ever return a failure */
    return 0;
}

EXPORTED int mboxlist_haschildren(const char *mboxname)
{
    int exists = 0;

    mboxlist_mboxtree(mboxname, exists_cb, &exists, MBOXTREE_SKIP_ROOT);

    return exists;
}

EXPORTED void mboxlist_done(void)
{
    /* DB->done() handled by cyrus_done() */
}

static void done_cb(void*rock __attribute__((unused)))
{
    if (mboxlist_dbopen) {
        mboxlist_close();
    }
    mboxlist_done();
}

static void init_internal()
{
    if (!mboxlist_initialized) {
        mboxlist_init(0);
    }
    if (!mboxlist_dbopen) {
        mboxlist_open(NULL);
    }
}

/* must be called after cyrus_init */
EXPORTED void mboxlist_init(int myflags)
{
    if (myflags & MBOXLIST_SYNC) {
        cyrusdb_sync(DB);
    }
    cyrus_modules_add(done_cb, NULL);
    mboxlist_initialized = 1;
}

static char *mboxlist_fname(void)
{
    const char *fname = config_getstring(IMAPOPT_MBOXLIST_DB_PATH);

    if (fname) return xstrdup(fname);

    return strconcat(config_dir, FNAME_MBOXLIST, (char *)NULL);
}

EXPORTED void mboxlist_open(const char *fname)
{
    int ret, flags;
    char *tofree = NULL;

    /* create db file name */
    if (!fname) {
        tofree = mboxlist_fname();
        fname = tofree;
    }

    mboxlist_init(0);

    flags = CYRUSDB_CREATE;

    ret = cyrusdb_open(DB, fname, flags, &mbdb);
    if (ret != 0) {
        xsyslog(LOG_ERR, "DBERROR: error opening mailboxes list",
                         "fname=<%s> error=<%s>",
                         fname, cyrusdb_strerror(ret));
            /* Exiting TEMPFAIL because Sendmail thinks this
               EX_OSFILE == permanent failure. */
        fatal("can't read mailboxes file", EX_TEMPFAIL);
    }

    free(tofree);

    mboxlist_dbopen = 1;

    struct buf key = BUF_INITIALIZER;
    mboxlist_racl_key(0, NULL, NULL, &key);
    have_racl = !cyrusdb_fetch(mbdb, buf_base(&key), buf_len(&key), NULL, NULL, NULL);
    buf_free(&key);
}

EXPORTED void mboxlist_close(void)
{
    int r;

    if (mboxlist_dbopen) {
        r = cyrusdb_close(mbdb);
        if (r) {
            xsyslog(LOG_ERR, "DBERROR: error closing mailboxes",
                             "error=<%s>",
                             cyrusdb_strerror(r));
        }
        mboxlist_dbopen = 0;
    }
}

/*
 * Open the subscription list for 'userid'.
 *
 * On success, returns zero.
 * On failure, returns an error code.
 */
static int
mboxlist_opensubs(const char *userid,
                  struct db **ret)
{
    int r = 0, flags;
    char *subsfname;

    /* Build subscription list filename */
    subsfname = user_hash_subs(userid);

    flags = CYRUSDB_CREATE;

    r = cyrusdb_open(SUBDB, subsfname, flags, ret);
    if (r != CYRUSDB_OK) {
        r = IMAP_IOERROR;
    }
    free(subsfname);

    return r;
}

/*
 * Close a subscription file
 */
static void mboxlist_closesubs(struct db *sub)
{
    cyrusdb_close(sub);
}

/*
 * Find subscribed mailboxes that match 'pattern'.
 * 'isadmin' is nonzero if user is a mailbox admin.  'userid'
 * is the user's login id.  For each matching mailbox, calls
 * 'proc' with the name of the mailbox.
 */
EXPORTED int mboxlist_findsubmulti(struct namespace *namespace,
                                   const strarray_t *patterns, int isadmin,
                                   const char *userid, const struct auth_state *auth_state,
                                   findall_cb *proc, void *rock,
                                   int force)
{
    return mboxlist_findsubmulti_withp(namespace, patterns, isadmin,
                                       userid, auth_state,
                                       NULL, proc, rock,
                                       force);
}

EXPORTED int mboxlist_findsubmulti_withp(struct namespace *namespace,
                                   const strarray_t *patterns, int isadmin,
                                   const char *userid, const struct auth_state *auth_state,
                                   findall_p *p, findall_cb *cb, void *rock,
                                   int force)
{
    int r = 0;

    init_internal();

    if (!namespace) namespace = mboxname_get_adminnamespace();

    struct find_rock cbrock;
    memset(&cbrock, 0, sizeof(struct find_rock));

    /* open the subscription file that contains the mailboxes the
       user is subscribed to */
    struct db *subs = NULL;
    r = mboxlist_opensubs(userid, &subs);
    if (r) return r;

    cbrock.auth_state = auth_state;
    cbrock.checkmboxlist = !force;
    cbrock.db = subs;
    cbrock.isadmin = isadmin;
    cbrock.issubs = 1;
    cbrock.namespace = namespace;
    cbrock.p = p;
    cbrock.cb = cb;
    cbrock.procrock = rock;
    cbrock.userid = userid;
    if (userid) {
        const char *domp = strchr(userid, '@');
        if (domp) cbrock.domain = domp + 1;
    }

    r = mboxlist_do_find(&cbrock, patterns);

    mboxlist_closesubs(subs);

    return r;
}

EXPORTED int mboxlist_findsub(struct namespace *namespace,
                              const char *pattern, int isadmin,
                              const char *userid, const struct auth_state *auth_state,
                              findall_cb *proc, void *rock,
                              int force)
{
    return mboxlist_findsub_withp(namespace, pattern, isadmin,
                                  userid, auth_state,
                                  NULL, proc, rock,
                                  force);
}

EXPORTED int mboxlist_findsub_withp(struct namespace *namespace,
                              const char *pattern, int isadmin,
                              const char *userid, const struct auth_state *auth_state,
                              findall_p *p, findall_cb *cb, void *rock,
                              int force)
{
    strarray_t patterns = STRARRAY_INITIALIZER;
    strarray_append(&patterns, pattern);

    init_internal();

    int r = mboxlist_findsubmulti_withp(namespace, &patterns, isadmin, userid, auth_state,
                                  p, cb, rock, force);

    strarray_fini(&patterns);

    return r;
}

static int subsadd_cb(void *rock, const char *key, size_t keylen,
                      const char *val __attribute__((unused)),
                      size_t vallen __attribute__((unused)))
{
    strarray_t *list = (strarray_t *)rock;
    struct buf dbname = BUF_INITIALIZER;

    mboxlist_dbname_from_key(key, keylen, &dbname);
    strarray_appendm(list, mboxname_from_dbname(buf_cstring(&dbname)));
    buf_free(&dbname);

    return 0;
}

EXPORTED strarray_t *mboxlist_sublist(const char *userid)
{
    struct buf key = BUF_INITIALIZER;
    struct db *subs = NULL;
    strarray_t *list = strarray_new();
    int r;

    init_internal();

    /* open subs DB */
    r = mboxlist_opensubs(userid, &subs);
    if (r) goto done;

    /* faster to do it all in a single slurp! */
    mboxlist_dbname_to_key("", 0, &key);
    r = cyrusdb_foreach(subs, buf_base(&key), buf_len(&key),
                        NULL, subsadd_cb, list, 0);

    mboxlist_closesubs(subs);

done:
    if (r) {
        strarray_free(list);
        return NULL;
    }
    buf_free(&key);
    return list;
}



struct submb_rock {
    struct mboxlist_entry *mbentry;
    const char *userid;
    int flags;
    mboxlist_cb *proc;
    void *rock;
};

static int usersubs_cb(void *rock, const char *key, size_t keylen,
                      const char *data __attribute__((unused)),
                      size_t datalen __attribute__((unused)))
{
    struct submb_rock *mbrock = (struct submb_rock *) rock;
    struct buf dbname = BUF_INITIALIZER;
    mbname_t *mbname = NULL;
    int r;

    /* free previous record */
    mboxlist_entry_free(&mbrock->mbentry);

    mboxlist_dbname_from_key(key, keylen, &dbname);
    mbname = mbname_from_dbname(buf_cstring(&dbname));

    if ((mbrock->flags & MBOXTREE_SKIP_PERSONAL) &&
        !strcmpsafe(mbrock->userid, mbname_userid(mbname))) {
        r = 0;
        goto done;
    }

    r = mboxlist_mylookup(buf_cstring(&dbname), &mbrock->mbentry, NULL, 0, 0);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        r = 0;
        goto done;
    }

    if (r) {
        syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
               mbname_intname(mbname), error_message(r));
        goto done;
    }

    r = mbrock->proc(mbrock->mbentry, mbrock->rock);

  done:
    mbname_free(&mbname);
    buf_free(&dbname);
    return r;
}

EXPORTED int mboxlist_usersubs(const char *userid, mboxlist_cb *proc,
                               void *rock, int flags)
{
    struct db *subs = NULL;
    struct submb_rock mbrock = { NULL, userid, flags, proc, rock };
    struct buf key = BUF_INITIALIZER;
    int r = 0;

    init_internal();

    /* open subs DB */
    r = mboxlist_opensubs(userid, &subs);
    if (r) return r;

    /* faster to do it all in a single slurp! */
    mboxlist_dbname_to_key("", 0, &key);
    r = cyrusdb_foreach(subs, buf_base(&key), buf_len(&key),
                        NULL, usersubs_cb, &mbrock, 0);

    mboxlist_entry_free(&mbrock.mbentry);

    mboxlist_closesubs(subs);
    buf_free(&key);

    return r;
}




/* returns CYRUSDB_NOTFOUND if the folder doesn't exist, and 0 if it does! */
EXPORTED int mboxlist_checksub(const char *name, const char *userid)
{
    int r;
    struct db *subs;
    const char *val;
    size_t vallen;

    init_internal();

    r = mboxlist_opensubs(userid, &subs);

    if (!r) {
        struct buf key = BUF_INITIALIZER;
        char *dbname = mboxname_to_dbname(name);

        mboxlist_dbname_to_key(dbname, strlen(dbname), &key);
        free(dbname);
        r = cyrusdb_fetch(subs, buf_base(&key), buf_len(&key),
                          &val, &vallen, NULL);
        buf_free(&key);
    }

    mboxlist_closesubs(subs);
    return r;
}

/*
 * Change 'user's subscription status for mailbox 'name'.
 * Subscribes if 'add' is nonzero, unsubscribes otherwise.
 * if 'force' is set, force the subscription through even if
 * we don't know about 'name'.
 */
EXPORTED int mboxlist_changesub(const char *name, const char *userid,
                                const struct auth_state *auth_state,
                                int add, int force, int notify)
{
    struct buf key = BUF_INITIALIZER;
    mbentry_t *mbentry = NULL;
    int r;
    struct db *subs;
    struct mboxevent *mboxevent;

    init_internal();

    if ((r = mboxlist_opensubs(userid, &subs)) != 0) {
        return r;
    }

    char *dbname = mboxname_to_dbname(name);

    if (add && !force) {
        /* Ensure mailbox exists and can be seen by user */
        if ((r = mboxlist_mylookup(dbname, &mbentry, NULL, 0, 0))!=0) {
            mboxlist_closesubs(subs);
            goto done;
        }
        if ((cyrus_acl_myrights(auth_state, mbentry->acl) & ACL_LOOKUP) == 0) {
            mboxlist_closesubs(subs);
            mboxlist_entry_free(&mbentry);
            r = IMAP_MAILBOX_NONEXISTENT;
            goto done;
        }
    }

    mboxlist_dbname_to_key(dbname, strlen(dbname), &key);
    if (add) {
        r = cyrusdb_store(subs, buf_base(&key), buf_len(&key), "", 0, NULL);
    } else {
        r = cyrusdb_delete(subs, buf_base(&key), buf_len(&key), NULL, 0);
        /* if it didn't exist, that's ok */
        if (r == CYRUSDB_EXISTS) r = CYRUSDB_OK;
    }

    switch (r) {
    case CYRUSDB_OK:
        r = 0;
        break;

    default:
        r = IMAP_IOERROR;
        break;
    }

    sync_log_subscribe(userid, name);
    mboxlist_closesubs(subs);
    mboxlist_entry_free(&mbentry);
    buf_free(&key);

    /* prepare a MailboxSubscribe or MailboxUnSubscribe event notification */
    if (notify && r == 0) {
        mboxevent = mboxevent_new(add ? EVENT_MAILBOX_SUBSCRIBE :
                                        EVENT_MAILBOX_UNSUBSCRIBE);

        mboxevent_set_access(mboxevent, NULL, NULL, userid, name, 1);
        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);
    }

  done:
    free(dbname);
    return r;
}

/* Transaction Handlers */
EXPORTED int mboxlist_commit(struct txn *tid)
{
    assert(tid);

    return cyrusdb_commit(mbdb, tid);
}

int mboxlist_abort(struct txn *tid)
{
    assert(tid);

    return cyrusdb_abort(mbdb, tid);
}

EXPORTED int mboxlist_delayed_delete_isenabled(void)
{
    enum enum_value config_delete_mode = config_getenum(IMAPOPT_DELETE_MODE);

    return(config_delete_mode == IMAP_ENUM_DELETE_MODE_DELAYED);
}


/* Handlers for mailboxes.db names */
static mbname_t *mbname_from_dbname(const char *dbname)
{
    mbname_t *mbname = mbname_from_userid(NULL);  // allocate empty mbname
    const char *p;

    if (!dbname || !*dbname) return mbname;

    const char *dp = config_getstring(IMAPOPT_DELETEDPREFIX);

    p = strchr(dbname, DB_DOMAINSEP_CHAR);
    if (p) {
        char domain[MAX_MAILBOX_NAME];
        snprintf(domain, sizeof(domain), "%.*s", (int) (p - dbname), dbname);
        mbname_set_domain(mbname, domain);
        dbname = p+1;
    }

    strarray_t *boxes = strarray_split(dbname, DB_HIERSEP_STR, 0);

    if (strarray_size(boxes) > 2 && !strcmpsafe(strarray_nth(boxes, 0), dp)) {
        free(strarray_shift(boxes));
        char *delval = strarray_pop(boxes);
        mbname_set_isdeleted(mbname, strtoul(delval, NULL, 16));
        free(delval);
    }

    if (strarray_size(boxes) > 1 && !strcmpsafe(strarray_nth(boxes, 0), "user")) {
        free(strarray_shift(boxes));
        char *localpart = strarray_shift(boxes);
        mbname_set_localpart(mbname, localpart);
        free(localpart);
    }

    mbname_set_boxes(mbname, boxes);
    strarray_free(boxes);

    return mbname;
}

/* all mailboxes have a database name representation, so this
 * function should never return a NULL.
 */
static char *mbname_dbname(const mbname_t *mbname)
{
    struct buf buf = BUF_INITIALIZER;
    int sep = 0;
    int i;

    const char *domain = mbname_domain(mbname);
    if (domain) {
        buf_appendcstr(&buf, domain);
        buf_putc(&buf, DB_DOMAINSEP_CHAR);
    }

    time_t is_deleted = mbname_isdeleted(mbname);
    if (is_deleted) {
        buf_appendcstr(&buf, config_getstring(IMAPOPT_DELETEDPREFIX));
        sep = 1;
    }

    const char *localpart = mbname_localpart(mbname);
    if (localpart) {
        if (sep) buf_putc(&buf, DB_HIERSEP_CHAR);
        buf_appendcstr(&buf, DB_USER_PREFIX);
        buf_appendcstr(&buf, localpart);
        sep = 1;
    }

    const strarray_t *boxes = mbname_boxes(mbname);
    for (i = 0; i < strarray_size(boxes); i++) {
        if (sep) buf_putc(&buf, DB_HIERSEP_CHAR);
        buf_appendcstr(&buf, strarray_nth(boxes, i));
        sep = 1;
    }

    if (is_deleted) {
        if (sep) buf_putc(&buf, DB_HIERSEP_CHAR);
        buf_printf(&buf, "%X", (unsigned) is_deleted);
        sep = 1;
    }

    return buf_release(&buf);
}

static char *mboxname_from_dbname(const char *dbname)
{
    mbname_t *mbname = mbname_from_dbname(dbname);
    char *res = xstrdupnull(mbname_intname(mbname));
    mbname_free(&mbname);
    return res;
}

static char *mboxname_to_dbname(const char *intname)
{
    mbname_t *mbname = mbname_from_intname(intname);
    char *res = mbname_dbname(mbname);
    mbname_free(&mbname);
    return res;
}


static int _check_rec_cb(void *rock,
                         const char *key, size_t keylen,
                         const char *data, size_t datalen)
{
    int *do_upgrade = (int *) rock;

    if (keylen && key[0] == KEY_TYPE_ID) {
        /* Verify that we have a valid I record */
        mbentry_t *mbentry = NULL;

        int r = mboxlist_parse_entry(&mbentry, NULL, 0, data, datalen);
        if (r) return r;

        *do_upgrade = (mbentry->name == NULL);
        mboxlist_entry_free(&mbentry);
    }
    else *do_upgrade = 1;

    return CYRUSDB_DONE;
}

struct upgrade_rock {
    struct buf *namebuf;
    struct txn **tid;
};

static int _upgrade_cb(void *rock,
                       const char *key, size_t keylen,
                       const char *data, size_t datalen)
{
    struct upgrade_rock *urock = (struct upgrade_rock *) rock;
    mbentry_t *mbentry = NULL;
    int r;

    /* skip $RACL or other $ space keys */
    if (key[0] == '$') return CYRUSDB_OK;

    r = mboxlist_parse_entry(&mbentry, NULL, 0, data, datalen);
    if (r) return r;

    buf_setmap(urock->namebuf, key, keylen);
    mbentry->name = mboxname_to_dbname(buf_cstring(urock->namebuf));
    mbentry->mbtype |= MBTYPE_LEGACY_DIRS;
    r = mboxlist_update_entry(mbentry->name, mbentry, urock->tid);

    mboxlist_entry_free(&mbentry);

    return r;
}

EXPORTED int mboxlist_upgrade(int *upgraded)
{
    int r, r2 = 0, do_upgrade = 0;
    struct buf buf = BUF_INITIALIZER;
    struct db *backup = NULL;
    struct txn *tid = NULL;
    struct upgrade_rock urock = { &buf, &tid };
    char *fname;

    if (upgraded) *upgraded = 0;

    /* check if we need to upgrade */
    mboxlist_open(NULL);
    r = cyrusdb_foreach(mbdb, "", 0, NULL, _check_rec_cb, &do_upgrade, NULL);
    mboxlist_close();

    if (r != CYRUSDB_DONE) return r;
    else if (!do_upgrade) return 0;

    /* create db file names */
    fname = mboxlist_fname();
    buf_setcstr(&buf, fname);
    buf_appendcstr(&buf, ".OLD");

    /* rename db file to backup */
    r = rename(fname, buf_cstring(&buf));
    free(fname);
    if (r) goto done;
    
    /* open backup db file */
    r = cyrusdb_open(DB, buf_cstring(&buf), 0, &backup);

    if (r) {
        syslog(LOG_ERR, "DBERROR: opening %s: %s", buf_cstring(&buf),
               cyrusdb_strerror(r));
        fatal("can't open mailboxes file", EX_TEMPFAIL);
    }

    /* open a new db file */
    mboxlist_open(NULL);

    /* perform upgrade from backup to new db */
    r = cyrusdb_foreach(backup, "", 0, NULL, _upgrade_cb, &urock, NULL);

    r2 = cyrusdb_close(backup);
    if (r2) {
        syslog(LOG_ERR, "DBERROR: error closing %s: %s", buf_cstring(&buf),
               cyrusdb_strerror(r2));
    }

    /* complete txn on new db */
    if (tid) {
        if (r) {
            r2 = mboxlist_abort(tid);
        } else {
            r2 = mboxlist_commit(tid);
        }

        if (r2) {
            syslog(LOG_ERR, "DBERROR: error %s txn in mboxlist_upgrade: %s",
                   r ? "aborting" : "committing", cyrusdb_strerror(r2));
        }
    }

    mboxlist_close();

    if (!r && upgraded) *upgraded = 1;

  done:
    buf_free(&buf);

    return r;
}
