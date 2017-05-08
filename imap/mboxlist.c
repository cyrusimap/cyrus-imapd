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
#include <syslog.h>

#include <sys/ipc.h>
#include <sys/msg.h>

#include "acl.h"
#include "annotate.h"
#include "glob.h"
#include "assert.h"
#include "global.h"
#include "cyrusdb.h"
#include "util.h"
#include "mailbox.h"
#include "mboxevent.h"
#include "exitcodes.h"
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

cyrus_acl_canonproc_t mboxlist_ensureOwnerRights;

static struct db *mbdb;

static int mboxlist_dbopen = 0;

static int mboxlist_opensubs(const char *userid, struct db **ret);
static void mboxlist_closesubs(struct db *sub);

static int mboxlist_rmquota(const mbentry_t *mbentry, void *rock);
static int mboxlist_changequota(const mbentry_t *mbentry, void *rock);

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

    if (mbtype & MBTYPE_DELETED)
        buf_putc(&buf, 'd');
    if (mbtype & MBTYPE_MOVING)
        buf_putc(&buf, 'm');
    if (mbtype & MBTYPE_NETNEWS)
        buf_putc(&buf, 'n');
    if (mbtype & MBTYPE_REMOTE)
        buf_putc(&buf, 'r');
    if (mbtype & MBTYPE_RESERVE)
        buf_putc(&buf, 'z');
    if (mbtype & MBTYPE_CALENDAR)
        buf_putc(&buf, 'c');
    if (mbtype & MBTYPE_COLLECTION)
        buf_putc(&buf, 'b');
    if (mbtype & MBTYPE_ADDRESSBOOK)
        buf_putc(&buf, 'a');

    return buf_cstring(&buf);
}

static char *mboxlist_entry_cstring(const mbentry_t *mbentry)
{
    struct buf buf = BUF_INITIALIZER;
    struct dlist *dl = dlist_newkvlist(NULL, mbentry->name);

    if (mbentry->acl)
        _write_acl(dl, mbentry->acl);

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

    if (mbentry->foldermodseq)
        dlist_setnum64(dl, "F", mbentry->foldermodseq);

    dlist_setdate(dl, "M", time(NULL));

    dlist_printbuf(dl, 0, &buf);

    dlist_free(&dl);

    return buf_release(&buf);
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

/*
 * read a single record from the mailboxes.db and return a pointer to it
 */
static int mboxlist_read(const char *name, const char **dataptr, size_t *datalenptr,
                         struct txn **tid, int wrlock)
{
    int namelen = strlen(name);
    int r;

    if (!namelen)
        return IMAP_MAILBOX_NONEXISTENT;

    if (wrlock) {
        r = cyrusdb_fetchlock(mbdb, name, namelen, dataptr, datalenptr, tid);
    } else {
        r = cyrusdb_fetch(mbdb, name, namelen, dataptr, datalenptr, tid);
    }

    switch (r) {
    case CYRUSDB_OK:
        /* no entry required, just checking if it exists */
        return 0;
        break;

    case CYRUSDB_AGAIN:
        return IMAP_AGAIN;
        break;

    case CYRUSDB_NOTFOUND:
        return IMAP_MAILBOX_NONEXISTENT;
        break;

    default:
        syslog(LOG_ERR, "DBERROR: error fetching mboxlist %s: %s",
               name, cyrusdb_strerror(r));
        return IMAP_IOERROR;
        break;
    }

    /* never get here */
}

EXPORTED uint32_t mboxlist_string_to_mbtype(const char *string)
{
    uint32_t mbtype = 0;

    if (!string) return 0; /* null just means default */

    for (; *string; string++) {
        switch (*string) {
        case 'a':
            mbtype |= MBTYPE_ADDRESSBOOK;
            break;
        case 'b':
            mbtype |= MBTYPE_COLLECTION;
            break;
        case 'c':
            mbtype |= MBTYPE_CALENDAR;
            break;
        case 'd':
            mbtype |= MBTYPE_DELETED;
            break;
        case 'm':
            mbtype |= MBTYPE_MOVING;
            break;
        case 'n':
            mbtype |= MBTYPE_NETNEWS;
            break;
        case 'r':
            mbtype |= MBTYPE_REMOTE;
            break;
        case 'z':
            mbtype |= MBTYPE_RESERVE;
            break;
        }
    }

    return mbtype;
}

struct parseentry_rock {
    struct mboxlist_entry *mbentry;
    struct buf *aclbuf;
    int doingacl;
};

int parseentry_cb(int type, struct dlistsax_data *d)
{
    struct parseentry_rock *rock = (struct parseentry_rock *)d->rock;

    switch(type) {
    case DLISTSAX_KVLISTSTART:
        if (!strcmp(buf_cstring(&d->kbuf), "A")) {
            rock->doingacl = 1;
        }
        break;
    case DLISTSAX_KVLISTEND:
        rock->doingacl = 0;
        break;
    case DLISTSAX_STRING:
        if (rock->doingacl) {
            buf_append(rock->aclbuf, &d->kbuf);
            buf_putc(rock->aclbuf, '\t');
            buf_append(rock->aclbuf, &d->buf);
            buf_putc(rock->aclbuf, '\t');
        }
        else {
            const char *key = buf_cstring(&d->kbuf);
            if (!strcmp(key, "F")) {
                rock->mbentry->foldermodseq = atoll(buf_cstring(&d->buf));
            }
            else if (!strcmp(key, "I")) {
                rock->mbentry->uniqueid = buf_newcstring(&d->buf);
            }
            else if (!strcmp(key, "M")) {
                rock->mbentry->mtime = atoi(buf_cstring(&d->buf));
            }
            else if (!strcmp(key, "P")) {
                rock->mbentry->partition = buf_newcstring(&d->buf);
            }
            else if (!strcmp(key, "S")) {
                rock->mbentry->server = buf_newcstring(&d->buf);
            }
            else if (!strcmp(key, "T")) {
                rock->mbentry->mbtype = mboxlist_string_to_mbtype(buf_cstring(&d->buf));
            }
            else if (!strcmp(key, "V")) {
                rock->mbentry->uidvalidity = atol(buf_cstring(&d->buf));
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
 *  I: unique_i_d
 *  M: _m_time
 *  P: _p_artition
 *  S: _s_erver
 *  T: _t_ype
 *  V: uid_v_alidity
 */
EXPORTED int mboxlist_parse_entry(mbentry_t **mbentryptr,
                                  const char *name, size_t namelen,
                                  const char *data, size_t datalen)
{
    static struct buf aclbuf;
    int r = IMAP_MAILBOX_BADFORMAT;
    char *freeme = NULL;
    char **target;
    char *p, *q;
    mbentry_t *mbentry = mboxlist_entry_create();

    if (!datalen)
        goto done;

    /* copy name */
    if (namelen)
        mbentry->name = xstrndup(name, namelen);
    else
        mbentry->name = xstrdup(name);

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
static int mboxlist_mylookup(const char *name,
                             mbentry_t **mbentryptr,
                             struct txn **tid, int wrlock)
{
    int r;
    const char *data;
    size_t datalen;

    r = mboxlist_read(name, &data, &datalen, tid, wrlock);
    if (r) return r;

    return mboxlist_parse_entry(mbentryptr, name, 0, data, datalen);
}

/*
 * Lookup 'name' in the mailbox list, ignoring reserved records
 */
EXPORTED int mboxlist_lookup(const char *name, mbentry_t **entryptr,
                             struct txn **tid)
{
    mbentry_t *entry = NULL;
    int r;

    r = mboxlist_mylookup(name, &entry, tid, 0);

    if (r) return r;

    /* Ignore "reserved" entries, like they aren't there */
    if (entry->mbtype & MBTYPE_RESERVE) {
        mboxlist_entry_free(&entry);
        return IMAP_MAILBOX_RESERVED;
    }

    /* Ignore "deleted" entries, like they aren't there */
    if (entry->mbtype & MBTYPE_DELETED) {
        mboxlist_entry_free(&entry);
        return IMAP_MAILBOX_NONEXISTENT;
    }

    if (entryptr) *entryptr = entry;
    else mboxlist_entry_free(&entry);

    return 0;
}

EXPORTED int mboxlist_lookup_allow_all(const char *name,
                                   mbentry_t **entryptr,
                                   struct txn **tid)
{
    return mboxlist_mylookup(name, entryptr, tid, 0);
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
        strarray_t *uses = strarray_split(buf_cstring(&attrib), " ", 0);
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
    /* \\Inbox is magical */
    if (!strcasecmp(use, "\\Inbox"))
        return mboxname_user_mbox(userid, NULL);

    struct _find_specialuse_data rock = { use, userid, NULL };
    mboxlist_usermboxtree(userid, _find_specialuse, &rock, MBOXTREE_SKIP_ROOT);
    return rock.mboxname;
}

struct _find_uniqueid_data {
    const char *uniqueid;
    char *mboxname;
};

static int _find_uniqueid(const mbentry_t *mbentry, void *rock) {
    struct _find_uniqueid_data *d = (struct _find_uniqueid_data *) rock;
    int r = 0;
    if (!strcmp(d->uniqueid, mbentry->uniqueid)) {
        d->mboxname = xstrdup(mbentry->name);
        r = CYRUSDB_DONE;
    }
    return r;
}

EXPORTED char *mboxlist_find_uniqueid(const char *uniqueid, const char *userid)
{
    struct _find_uniqueid_data rock = { uniqueid, NULL };
    mboxlist_usermboxtree(userid, _find_uniqueid, &rock, MBOXTREE_PLUS_RACL);
    return rock.mboxname;
}

/* given a mailbox name, find the staging directory.  XXX - this should
 * require more locking, and staging directories should be by pid */
HIDDEN int mboxlist_findstage(const char *name, char *stagedir, size_t sd_len)
{
    const char *root;
    mbentry_t *mbentry = NULL;
    int r;

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

static void mboxlist_racl_key(int isuser, const char *keyuser, const char *mbname, struct buf *buf)
{
    buf_setcstr(buf, "$RACL$");
    buf_putc(buf, isuser ? 'U' : 'S');
    buf_putc(buf, '$');
    if (keyuser) {
        buf_appendcstr(buf, keyuser);
        buf_putc(buf, '$');
    }
    if (mbname) {
        buf_appendcstr(buf, mbname);
    }
}

static int user_is_in(const strarray_t *aclbits, const char *user)
{
    int i;
    if (!aclbits) return 0;
    for (i = 0; i+1 < strarray_size(aclbits); i+=2) {
        if (!strcmp(strarray_nth(aclbits, i), user)) return 1;
    }
    return 0;
}

static int mboxlist_update_racl(const char *name, const mbentry_t *oldmbentry, const mbentry_t *newmbentry, struct txn **txn)
{
    static strarray_t *admins = NULL;
    struct buf buf = BUF_INITIALIZER;
    char *userid = mboxname_to_userid(name);
    strarray_t *oldusers = NULL;
    strarray_t *newusers = NULL;
    int i;
    int r = 0;

    if (!admins) admins = strarray_split(config_getstring(IMAPOPT_ADMINS), NULL, 0);

    if (oldmbentry && oldmbentry->mbtype != MBTYPE_DELETED)
        oldusers = strarray_split(oldmbentry->acl, "\t", 0);

    if (newmbentry && newmbentry->mbtype != MBTYPE_DELETED)
        newusers = strarray_split(newmbentry->acl, "\t", 0);

    if (oldusers) {
        for (i = 0; i+1 < strarray_size(oldusers); i+=2) {
            const char *acluser = strarray_nth(oldusers, i);
            const char *aclval = strarray_nth(oldusers, i+1);
            if (!strchr(aclval, 'l')) continue; /* non-lookup ACLs can be skipped */
            if (!strcmpsafe(userid, acluser)) continue;
            if (strarray_find(admins, acluser, 0) >= 0) continue;
            if (user_is_in(newusers, acluser)) continue;
            mboxlist_racl_key(!!userid, acluser, name, &buf);
            r = cyrusdb_delete(mbdb, buf.s, buf.len, txn, /*force*/1);
            if (r) goto done;
        }
    }

    if (newusers) {
        for (i = 0; i+1 < strarray_size(newusers); i+=2) {
            const char *acluser = strarray_nth(newusers, i);
            const char *aclval = strarray_nth(newusers, i+1);
            if (!strchr(aclval, 'l')) continue; /* non-lookup ACLs can be skipped */
            if (!strcmpsafe(userid, acluser)) continue;
            if (strarray_find(admins, acluser, 0) >= 0) continue;
            if (user_is_in(oldusers, acluser)) continue;
            mboxlist_racl_key(!!userid, acluser, name, &buf);
            r = cyrusdb_store(mbdb, buf.s, buf.len, "", 0, txn);
            if (r) goto done;
        }
    }

 done:
    strarray_free(oldusers);
    strarray_free(newusers);
    free(userid);
    buf_free(&buf);
    return r;
}

static int mboxlist_update_entry(const char *name, const mbentry_t *mbentry, struct txn **txn)
{
    mbentry_t *old = NULL;
    int r = 0;

    mboxlist_mylookup(name, &old, txn, 0); // ignore errors, it will be NULL

    if (!cyrusdb_fetch(mbdb, "$RACL", 5, NULL, NULL, txn)) {
        r = mboxlist_update_racl(name, old, mbentry, txn);
        /* XXX return value here is discarded? */
    }

    if (mbentry) {
        char *mboxent = mboxlist_entry_cstring(mbentry);
        r = cyrusdb_store(mbdb, name, strlen(name), mboxent, strlen(mboxent), txn);
        free(mboxent);

        if (!r && config_auditlog) {
            /* XXX is there a difference between "" and NULL? */
            if (old && strcmpsafe(old->acl, mbentry->acl)) {
                syslog(LOG_NOTICE, "auditlog: acl sessionid=<%s> "
                                   "mailbox=<%s> uniqueid=<%s> "
                                   "oldacl=<%s> acl=<%s>",
                       session_id(),
                       name, mbentry->uniqueid,
                       old->acl, mbentry->acl);
            }
        }
    }
    else {
        r = cyrusdb_delete(mbdb, name, strlen(name), txn, /*force*/1);
    }

    mboxlist_entry_free(&old);
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

    r = mboxlist_update_entry(mbentry->name, mbentry, &tid);

    if (!r)
        mboxname_setmodseq(mbentry->name, mbentry->foldermodseq, mbentry->mbtype, /*dofolder*/1);

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
        } else {
            r2 = cyrusdb_commit(mbdb, tid);
        }
    }

    if (r2) {
        syslog(LOG_ERR, "DBERROR: error %s txn in mboxlist_update: %s",
               r ? "aborting" : "committing", cyrusdb_strerror(r2));
    }

    return r;
}

EXPORTED int mboxlist_findparent(const char *mboxname,
                               mbentry_t **mbentryp)
{
    mbentry_t *mbentry = NULL;
    mbname_t *mbname = mbname_from_intname(mboxname);
    int r = IMAP_MAILBOX_NONEXISTENT;

    while (strarray_size(mbname_boxes(mbname))) {
        free(mbname_pop_boxes(mbname));
        mboxlist_entry_free(&mbentry);
        r = mboxlist_lookup(mbname_intname(mbname), &mbentry, NULL);
        if (r != IMAP_MAILBOX_NONEXISTENT)
            break;
    }

    if (r)
        mboxlist_entry_free(&mbentry);
    else
        *mbentryp = mbentry;

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
                                modseq_t highestmodseq,
                                const char *copyacl, const char *uniqueid,
                                int localonly, int forceuser, int dbonly,
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
                           options, uidvalidity, highestmodseq, &newmailbox);
        if (r) goto done; /* CREATE failed */
        r = mailbox_add_conversations(newmailbox);
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
        newmbentry->foldermodseq = newmailbox->i.highestmodseq;
    }
    r = mboxlist_update_entry(mboxname, newmbentry, NULL);

    if (r) {
        syslog(LOG_ERR, "DBERROR: failed to insert to mailboxes list %s: %s",
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

EXPORTED int mboxlist_createmailbox(const char *name, int mbtype,
                           const char *partition,
                           int isadmin, const char *userid,
                           const struct auth_state *auth_state,
                           int localonly, int forceuser, int dbonly,
                           int notify, struct mailbox **mailboxptr)
{
    int options = config_getint(IMAPOPT_MAILBOX_DEFAULT_OPTIONS)
                  | OPT_POP3_NEW_UIDL;
    int r;
    struct mailbox *mailbox = NULL;
    uint32_t uidvalidity = 0;

    /* check if a previous deleted mailbox existed */
    mbentry_t *oldmbentry = NULL;
    r = mboxlist_lookup_allow_all(name, &oldmbentry, NULL);
    if (!r && oldmbentry->mbtype == MBTYPE_DELETED) {
        /* then the UIDVALIDITY must be higher than before */
        if (uidvalidity <= oldmbentry->uidvalidity)
            uidvalidity = oldmbentry->uidvalidity+1;
    }
    mboxlist_entry_free(&oldmbentry);

    r = mboxlist_createmailbox_full(name, mbtype, partition,
                                    isadmin, userid, auth_state,
                                    options, uidvalidity, 0, NULL, NULL, localonly,
                                    forceuser, dbonly, &mailbox);

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

    return r;
}

EXPORTED int mboxlist_createsync(const char *name, int mbtype,
                        const char *partition,
                        const char *userid, const struct auth_state *auth_state,
                        int options, unsigned uidvalidity,
                        modseq_t highestmodseq,
                        const char *acl, const char *uniqueid,
                        int local_only, struct mailbox **mboxptr)
{
    return mboxlist_createmailbox_full(name, mbtype, partition,
                                       1, userid, auth_state,
                                       options, uidvalidity,
                                       highestmodseq, acl, uniqueid,
                                       local_only, 1, 0, mboxptr);
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
        syslog(LOG_ERR, "DBERROR: error updating database %s: %s",
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

    if(in_tid) {
        tid = in_tid;
    } else {
        tid = &lcl_tid;
    }

 retry:
    r = mboxlist_mylookup(name, &mbentry, tid, 1);
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
        syslog(LOG_ERR, "DBERROR: error deleting %s: %s",
               name, cyrusdb_strerror(r));
        r = IMAP_IOERROR;
    }

    /* commit db operations, but only if we weren't passed a transaction */
    if (!in_tid) {
        r = cyrusdb_commit(mbdb, *tid);
        if (r) {
            syslog(LOG_ERR, "DBERROR: failed on commit: %s",
                   cyrusdb_strerror(r));
            r = IMAP_IOERROR;
        }
        tid = NULL;
    }

 done:
    if (r && !in_tid && tid) {
        /* Abort the transaction if it is still in progress */
        cyrusdb_abort(mbdb, *tid);
    }

    return r;
}

static int addmbox_to_list(const mbentry_t *mbentry, void *rock)
{
    strarray_t *list = (strarray_t *)rock;
    strarray_append(list, mbentry->name);
    return 0;
}

/*
 * Delayed Delete a mailbox: translate delete into rename
 */
EXPORTED int
mboxlist_delayed_deletemailbox(const char *name, int isadmin,
                               const char *userid,
                               const struct auth_state *auth_state,
                               struct mboxevent *mboxevent,
                               int checkacl,
                               int localonly,
                               int force)
{
    mbentry_t *mbentry = NULL;
    strarray_t existing = STRARRAY_INITIALIZER;
    int i;
    char newname[MAX_MAILBOX_BUFFER];
    int r = 0;
    long myrights;

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

    if (!isadmin && mbname_userid(mbname)) {
        struct buf attrib = BUF_INITIALIZER;
        annotatemore_lookup(mbname_intname(mbname), "/specialuse", mbname_userid(mbname), &attrib);
        if (attrib.len)
            r = IMAP_MAILBOX_SPECIALUSE;
        buf_free(&attrib);
        if (r) goto done;
    }

    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) goto done;

    /* check if user has Delete right (we've already excluded non-admins
     * from deleting a user mailbox) */
    if (checkacl) {
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

    /* check if there are already too many! */
    mboxname_todeleted(name, newname, 0);
    r = mboxlist_mboxtree(newname, addmbox_to_list, &existing, MBOXTREE_SKIP_ROOT);
    if (r) goto done;

    /* keep the last 19, so the new one is the 20th */
    for (i = 0; i < (int)existing.count - 19; i++) {
        const char *subname = strarray_nth(&existing, i);
        syslog(LOG_NOTICE, "too many subfolders for %s, deleting %s (%d / %d)",
               newname, subname, i+1, (int)existing.count);
        r = mboxlist_deletemailbox(subname, 1, userid, auth_state, NULL, 0, 1, 1);
        if (r) goto done;
    }

    /* get the deleted name */
    mboxname_todeleted(name, newname, 1);

    /* Get mboxlist_renamemailbox to do the hard work. No ACL checks needed */
    r = mboxlist_renamemailbox((char *)name, newname, mbentry->partition,
                               0 /* uidvalidity */,
                               1 /* isadmin */, userid,
                               auth_state,
                               mboxevent,
                               localonly /* local_only */,
                               force, 1);

done:
    strarray_fini(&existing);
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
                                    int checkacl,
                                    int local_only, int force)
{
    mbentry_t *mbentry = NULL;
    int r = 0;
    long myrights;
    struct mailbox *mailbox = NULL;
    int isremote = 0;
    mupdate_handle *mupdate_h = NULL;

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

    if (!isadmin && mbname_userid(mbname)) {
        struct buf attrib = BUF_INITIALIZER;
        annotatemore_lookup(mbname_intname(mbname), "/specialuse", mbname_userid(mbname), &attrib);
        if (attrib.len)
            r = IMAP_MAILBOX_SPECIALUSE;
        buf_free(&attrib);
        if (r) goto done;
    }

    r = mboxlist_lookup_allow_all(name, &mbentry, NULL);
    if (r) goto done;

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
    }
    if (r && !force) goto done;

    /* remove from mupdate */
    if (!isremote && !local_only && config_mupdate_server) {
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
        mbentry_t *newmbentry = mboxlist_entry_create();
        newmbentry->name = xstrdupnull(name);
        newmbentry->mbtype = MBTYPE_DELETED;
        if (mailbox) {
            newmbentry->uniqueid = xstrdupnull(mailbox->uniqueid);
            newmbentry->uidvalidity = mailbox->i.uidvalidity;
            newmbentry->foldermodseq = mailbox_modseq_dirty(mailbox);
        }
        r = mboxlist_update(newmbentry, /*localonly*/1);
        mboxlist_entry_free(&newmbentry);
    }
    else {
        /* delete entry (including DELETED.* mailboxes, no need
         * to keep that rubbish around) */
        r = mboxlist_update_entry(name, NULL, 0);
        if (r) {
            syslog(LOG_ERR, "DBERROR: error deleting %s: %s",
                   name, cyrusdb_strerror(r));
            r = IMAP_IOERROR;
            if (!force) goto done;
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

static int _rename_check_specialuse(const char *oldname, const char *newname)
{
    mbname_t *old = mbname_from_intname(oldname);
    mbname_t *new = mbname_from_intname(newname);
    struct buf attrib = BUF_INITIALIZER;
    int r = 0;
    if (mbname_userid(old))
        annotatemore_lookup(oldname, "/specialuse", mbname_userid(old), &attrib);
    /* we have specialuse? */
    if (attrib.len) {
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
    mbname_free(&new);
    mbname_free(&old);
    buf_free(&attrib);
    return r;
}

/*
 * Rename/move a single mailbox (recursive renames are handled at a
 * higher level).  This only supports local mailboxes.  Remote
 * mailboxes are handled up in imapd.c
 */
EXPORTED int mboxlist_renamemailbox(const char *oldname, const char *newname,
                           const char *partition, unsigned uidvalidity,
                           int isadmin, const char *userid,
                           const struct auth_state *auth_state,
                           struct mboxevent *mboxevent,
                           int local_only, int forceuser, int ignorequota)
{
    int r;
    int mupdatecommiterror = 0;
    long myrights;
    int isusermbox = 0; /* Are we renaming someone's inbox */
    int partitionmove = 0;
    struct mailbox *oldmailbox = NULL;
    struct mailbox *newmailbox = NULL;
    struct txn *tid = NULL;
    const char *root = NULL;
    char *newpartition = NULL;
    mupdate_handle *mupdate_h = NULL;
    mbentry_t *newmbentry = NULL;

    /* 1. open mailbox */
    r = mailbox_open_iwl(oldname, &oldmailbox);
    if (r) return r;

    myrights = cyrus_acl_myrights(auth_state, oldmailbox->acl);

    /* check the ACLs up-front */
    if (!isadmin) {
        if (!(myrights & ACL_DELETEMBOX)) {
            r = (myrights & ACL_LOOKUP) ?
                IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
            goto done;
        }
    }

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
        newmbentry->foldermodseq = oldmailbox->i.highestmodseq; /* bump regardless, it's rare */

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
                            &newmailbox);

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
    newmbentry->foldermodseq = newmailbox->i.highestmodseq;

    do {
        r = 0;

        /* delete the old entry */
        if (!isusermbox) {
            /* store a DELETED marker */
            mbentry_t *oldmbentry = mboxlist_entry_create();
            oldmbentry->name = xstrdupnull(oldmailbox->name);
            oldmbentry->mbtype = MBTYPE_DELETED;
            oldmbentry->uidvalidity = oldmailbox->i.uidvalidity;
            oldmbentry->uniqueid = xstrdupnull(oldmailbox->uniqueid);
            oldmbentry->foldermodseq = mailbox_modseq_dirty(oldmailbox);

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
            syslog(LOG_ERR, "DBERROR: rename failed on store %s %s: %s",
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
        syslog(LOG_ERR, "DBERROR: rename failed on commit %s %s: %s",
               oldname, newname, cyrusdb_strerror(r));
        r = IMAP_IOERROR;
        goto done;
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

    if (r) {
        /* rollback DB changes if it was an mupdate failure */
        if (mupdatecommiterror) {
            r = 0;

            /* recreate an old entry */
            if (!isusermbox)
                r = mboxlist_update_entry(oldname, newmbentry, &tid);

            /* delete the new entry */
            if (!r)
                r = mboxlist_update_entry(newname, NULL, &tid);

            /* Commit transaction */
            if (!r)
                r = cyrusdb_commit(mbdb, tid);

            tid = NULL;
            if (r) {
                /* XXX HOWTO repair this mess! */
                syslog(LOG_ERR, "DBERROR: failed DB rollback on mailboxrename %s %s: %s",
                       oldname, newname, cyrusdb_strerror(r));
                syslog(LOG_ERR, "DBERROR: mailboxdb on mupdate and backend ARE NOT CONSISTENT");
                syslog(LOG_ERR, "DBERROR: mailboxdb on mupdate has entry for %s, mailboxdb on backend has entry for %s and files are on the old position", oldname, newname);
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

            /* log the rename before we close either mailbox, so that
             * we never nuke the mailbox from the replica before realising
             * that it has been renamed.  This can be moved later again when
             * we sync mailboxes by uniqueid rather than name... */
            sync_log_mailbox_double(oldname, newname);

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
        else
            abort(); /* impossible, in theory */
    }

    /* free memory */
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

    /* round trip identifier to potentially strip domain */
    mbname_t *mbname = mbname_from_userid(identifier);
    /* XXX - enforce cross domain restrictions */
    identifier = mbname_userid(mbname);

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
        r = mboxlist_mylookup(name, &mbentry, &tid, 1);
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
                r = mboxlist_mylookup(name, &mbentry, &tid, 1);
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

        r = mboxlist_update_entry(name, mbentry, &tid);

        if (r) {
            syslog(LOG_ERR, "DBERROR: error updating acl %s: %s",
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
        mailbox_set_acl(mailbox, newacl, 1);
        /* want to commit immediately to ensure ordering */
        r = mailbox_commit(mailbox);
    }

    /* 5. Commit transaction */
    if (!r) {
        if((r = cyrusdb_commit(mbdb, tid)) != 0) {
            syslog(LOG_ERR, "DBERROR: failed on commit: %s",
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
    mbname_free(&mbname);

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
mboxlist_sync_setacls(const char *name, const char *newacl)
{
    mbentry_t *mbentry = NULL;
    int r;
    struct txn *tid = NULL;

    /* 1. Start Transaction */
    /* lookup the mailbox to make sure it exists and get its acl */
    do {
        r = mboxlist_mylookup(name, &mbentry, &tid, 1);
    } while(r == IMAP_AGAIN);

    /* Can't do this to an in-transit or reserved mailbox */
    if (!r && mbentry->mbtype & (MBTYPE_MOVING | MBTYPE_RESERVE | MBTYPE_DELETED)) {
        r = IMAP_MAILBOX_NOTSUPPORTED;
    }

    /* 2. Set DB Entry */
    if (!r) {
        /* ok, change the database */
        free(mbentry->acl);
        mbentry->acl = xstrdupnull(newacl);

        r = mboxlist_update_entry(name, mbentry, &tid);

        if (r) {
            syslog(LOG_ERR, "DBERROR: error updating acl %s: %s",
                   name, cyrusdb_strerror(r));
            r = IMAP_IOERROR;
        }
    }

    /* 3. Commit transaction */
    if (!r) {
        r = cyrusdb_commit(mbdb, tid);
        if (r) {
            syslog(LOG_ERR, "DBERROR: failed on commit %s: %s",
                   name, cyrusdb_strerror(r));
            r = IMAP_IOERROR;
        }
        tid = NULL;
    }

    /* 4. Change mupdate entry  */
    if (!r && config_mupdate_server) {
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
            if(r) {
                syslog(LOG_ERR,
                       "MUPDATE: can't update mailbox entry for '%s'",
                       name);
            }
        }
        mupdate_disconnect(&mupdate_h);
    }

    if (r && tid) {
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
    findall_cb *proc;
    void *procrock;
};

/* return non-zero if we like this one */
static int find_p(void *rockp,
                  const char *key, size_t keylen,
                  const char *data, size_t datalen)
{
    struct find_rock *rock = (struct find_rock *) rockp;
    char intname[MAX_MAILBOX_PATH+1];
    int i;

    /* skip any $RACL or future $ space keys */
    if (key[0] == '$') return 0;

    memcpy(intname, key, keylen);
    intname[keylen] = 0;

    assert(!rock->mbname);
    rock->mbname = mbname_from_intname(intname);

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
    if (mboxlist_parse_entry(&rock->mbentry, key, keylen, data, datalen))
        goto nomatch;

    /* nobody sees tombstones */
    if (rock->mbentry->mbtype & MBTYPE_DELETED)
        goto nomatch;

    /* check acl */
    if (!rock->isadmin) {
        /* always suppress deleted for non-admin */
        if (mbname_isdeleted(rock->mbname)) goto nomatch;

        /* check the acls */
        if (!(cyrus_acl_myrights(rock->auth_state, rock->mbentry->acl) & ACL_LOOKUP)) goto nomatch;
    }

good:
    return 1;

nomatch:
    mboxlist_entry_free(&rock->mbentry);
    mbname_free(&rock->mbname);
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
        r = mboxlist_lookup(mbname_intname(rock->mbname), &rock->mbentry, NULL);
        if (r) {
            if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;
            goto done;
        }
    }

    const char *extname = mbname_extname(rock->mbname, rock->namespace, rock->userid);
    testname = xstrndup(extname, rock->matchlen);

    struct findall_data fdata = { testname, rock->mb_category, rock->mbentry, NULL };

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
                r = (*rock->proc)(&fdata, rock->procrock);
                if (r) goto done;
            }

            /* replace the separator for the next longest name */
            *p++ = sep;
        }
    }

    /* mbname confirms that it's an exact match */
    if (rock->matchlen == (int)strlen(extname))
        fdata.mbname = rock->mbname;

    r = (*rock->proc)(&fdata, rock->procrock);

 done:
    free(testname);
    mboxlist_entry_free(&rock->mbentry);
    mbname_free(&rock->mbname);
    return r;
}

struct allmb_rock {
    struct mboxlist_entry *mbentry;
    int flags;
    mboxlist_cb *proc;
    void *rock;
};

static int allmbox_cb(void *rock,
                      const char *key,
                      size_t keylen,
                      const char *data,
                      size_t datalen)
{
    struct allmb_rock *mbrock = (struct allmb_rock *)rock;

    if (!mbrock->mbentry) {
        int r = mboxlist_parse_entry(&mbrock->mbentry, key, keylen, data, datalen);
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
    int r;

    /* skip any dollar keys */
    if (keylen && key[0] == '$') return 0;

    /* free previous record */
    mboxlist_entry_free(&mbrock->mbentry);

    r = mboxlist_parse_entry(&mbrock->mbentry, key, keylen, data, datalen);
    if (r) return 0;

    if (!(mbrock->flags & MBOXTREE_TOMBSTONES) && (mbrock->mbentry->mbtype & MBTYPE_DELETED))
        return 0;

    return 1; /* process this record */
}

EXPORTED int mboxlist_allmbox(const char *prefix, mboxlist_cb *proc, void *rock, int incdel)
{
    struct allmb_rock mbrock = { NULL, 0, proc, rock };
    int r = 0;

    if (incdel) mbrock.flags |= MBOXTREE_TOMBSTONES;
    if (!prefix) prefix = "";

    r = cyrusdb_foreach(mbdb, prefix, strlen(prefix),
                        allmbox_p, allmbox_cb, &mbrock, 0);

    mboxlist_entry_free(&mbrock.mbentry);

    return r;
}

EXPORTED int mboxlist_mboxtree(const char *mboxname, mboxlist_cb *proc, void *rock, int flags)
{
    struct allmb_rock mbrock = { NULL, flags, proc, rock };
    int r = 0;

    if (!(flags & MBOXTREE_SKIP_ROOT)) {
        r = cyrusdb_forone(mbdb, mboxname, strlen(mboxname), allmbox_p, allmbox_cb, &mbrock, 0);
        if (r) goto done;
    }

    if (!(flags & MBOXTREE_SKIP_CHILDREN)) {
        char *prefix = strconcat(mboxname, ".", (char *)NULL);
        r = cyrusdb_foreach(mbdb, prefix, strlen(prefix), allmbox_p, allmbox_cb, &mbrock, 0);
        free(prefix);
        if (r) goto done;
    }

    if ((flags & MBOXTREE_DELETED)) {
        struct buf buf = BUF_INITIALIZER;
        const char *p = strchr(mboxname, '!');
        const char *dp = config_getstring(IMAPOPT_DELETEDPREFIX);
        if (p) {
            buf_printf(&buf, "%.*s!%s.%s", (int)(p-mboxname), mboxname, dp, p+1);
        }
        else {
            buf_printf(&buf, "%s.%s", dp, mboxname);
        }
        const char *prefix = buf_cstring(&buf);
        r = cyrusdb_foreach(mbdb, prefix, strlen(prefix), allmbox_p, allmbox_cb, &mbrock, 0);
        buf_free(&buf);
        if (r) goto done;
    }

 done:
    mboxlist_entry_free(&mbrock.mbentry);
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
    struct txn *tid = NULL;
    int r = 0;
    int now = !cyrusdb_fetch(mbdb, "$RACL", 5, NULL, NULL, &tid);

    if (now && !enabled) {
        syslog(LOG_NOTICE, "removing reverse acl support");
        /* remove */
        r = cyrusdb_foreach(mbdb, "$RACL", 5, NULL, racls_del_cb, &tid, &tid);
    }
    else if (enabled && !now) {
        /* add */
        struct allmb_rock mbrock = { NULL, 0, racls_add_cb, &tid };
        /* we can't use mboxlist_allmbox because it doesn't do transactions */
        syslog(LOG_NOTICE, "adding reverse acl support");
        r = cyrusdb_foreach(mbdb, "", 0, allmbox_p, allmbox_cb, &mbrock, &tid);
        if (r) {
            syslog(LOG_ERR, "ERROR: failed to add reverse acl support %s", error_message(r));
        }
        mboxlist_entry_free(&mbrock.mbentry);
        if (!r) r = cyrusdb_store(mbdb, "$RACL", 5, "", 0, &tid);
    }

    if (r)
        cyrusdb_abort(mbdb, tid);
    else
        cyrusdb_commit(mbdb, tid);

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
            urock->prev = xstrdup(userid);
        }
        free(userid);
    }

    return r;
}

EXPORTED int mboxlist_alluser(user_cb *proc, void *rock)
{
    struct alluser_rock urock;
    int r = 0;
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

EXPORTED int mboxlist_usermboxtree(const char *userid, mboxlist_cb *proc,
                                   void *rock, int flags)
{
    char *inbox = mboxname_user_mbox(userid, 0);
    int r = mboxlist_mboxtree(inbox, proc, rock, flags);

    if (flags & MBOXTREE_PLUS_RACL) {
        struct allmb_rock mbrock = { NULL, flags, proc, rock };
        /* we're using reverse ACLs */
        struct buf buf = BUF_INITIALIZER;
        strarray_t matches = STRARRAY_INITIALIZER;

        /* user items */
        mboxlist_racl_key(1, userid, NULL, &buf);
        /* this is the prefix */
        struct raclrock raclrock = { buf.len, &matches };
        /* we only need to look inside the prefix still, but we keep the length
         * in raclrock pointing to the start of the mboxname part of the key so
         * we get correct names in matches */
        r = cyrusdb_foreach(mbdb, buf.s, buf.len, NULL, racl_cb, &raclrock, NULL);
        buf_reset(&buf);

        /* shared items */
        mboxlist_racl_key(0, userid, NULL, &buf);
        raclrock.prefixlen = buf.len;
        if (!r) r = cyrusdb_foreach(mbdb, buf.s, buf.len, NULL, racl_cb, &raclrock, NULL);

        /* XXX - later we need to sort the array when we've added groups */
        int i;
        for (i = 0; !r && i < strarray_size(&matches); i++) {
            const char *mboxname = strarray_nth(&matches, i);
            r = cyrusdb_forone(mbdb, mboxname, strlen(mboxname), allmbox_p, allmbox_cb, &mbrock, 0);
        }
        buf_free(&buf);
        strarray_fini(&matches);
        mboxlist_entry_free(&mbrock.mbentry);
    }

    free(inbox);
    return r;
}

static int mboxlist_find_category(struct find_rock *rock, const char *prefix, size_t len)
{
    int r = 0;
    if (!rock->issubs && !rock->isadmin && !cyrusdb_fetch(rock->db, "$RACL", 5, NULL, NULL, NULL)) {
        /* we're using reverse ACLs */
        struct buf buf = BUF_INITIALIZER;
        strarray_t matches = STRARRAY_INITIALIZER;
        mboxlist_racl_key(rock->mb_category == MBNAME_OTHERUSER, rock->userid, NULL, &buf);
        /* this is the prefix */
        struct raclrock raclrock = { buf.len, &matches };
        /* we only need to look inside the prefix still, but we keep the length
         * in raclrock pointing to the start of the mboxname part of the key so
         * we get correct names in matches */
        if (len) buf_appendmap(&buf, prefix, len);
        r = cyrusdb_foreach(rock->db, buf.s, buf.len, NULL, racl_cb, &raclrock, NULL);
        /* XXX - later we need to sort the array when we've added groups */
        int i;
        for (i = 0; !r && i < strarray_size(&matches); i++) {
            const char *key = strarray_nth(&matches, i);
            r = cyrusdb_forone(rock->db, key, strlen(key), &find_p, &find_cb, rock, NULL);
        }
        strarray_fini(&matches);
    }
    else {
        r = cyrusdb_foreach(rock->db, prefix, len, &find_p, &find_cb, rock, NULL);
    }

    if (r == CYRUSDB_DONE) r = 0;
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

    int crossdomains = config_getswitch(IMAPOPT_CROSSDOMAINS);
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
        snprintf(domainpat, sizeof(domainpat), "%s!", p+1);
    }
    else
        domainpat[0] = '\0';

    /* calculate the inbox (with trailing .INBOX. for later use) */
    if (userid && (!(p = strchr(userid, rock->namespace->hier_sep)) ||
        ((p - userid) > (int)userlen)) &&
        strlen(userid)+7 < MAX_MAILBOX_BUFFER) {
        char *t, *tmpuser = NULL;
        const char *inboxuser;

        if (domainlen)
            snprintf(inbox, sizeof(inbox), "%s!", userid+userlen+1);
        if (rock->namespace->hier_sep == '/' && (p = strchr(userid, '.'))) {
            tmpuser = xmalloc(userlen);
            memcpy(tmpuser, userid, userlen);
            t = tmpuser + (p - userid);
            while(t < (tmpuser + userlen)) {
                if (*t == '.')
                    *t = '^';
                t++;
            }
            inboxuser = tmpuser;
        } else
            inboxuser = userid;
        snprintf(inbox+domainlen, sizeof(inbox)-domainlen,
                 "user.%.*s.INBOX.", (int)userlen, inboxuser);
        free(tmpuser);
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
        r = cyrusdb_forone(rock->db, inbox, inboxlen, &find_p, &find_cb, rock, NULL);
        if (r == CYRUSDB_DONE) r = 0;
        if (r) goto done;

        if (rock->namespace->isalt) {
            /* do exact INBOX subs before resetting the namebuffer */
            rock->mb_category = MBNAME_INBOXSUB;
            r = cyrusdb_foreach(rock->db, inbox, inboxlen+7, &find_p, &find_cb, rock, NULL);
            if (r == CYRUSDB_DONE) r = 0;
            if (r) goto done;

            /* reset the the namebuffer */
            r = (*rock->proc)(NULL, rock->procrock);
            if (r) goto done;
        }

        /* iterate through all the mailboxes under the user's inbox */
        rock->mb_category = MBNAME_OWNER;
        r = cyrusdb_foreach(rock->db, inbox, inboxlen+1, &find_p, &find_cb, rock, NULL);
        if (r == CYRUSDB_DONE) r = 0;
        if (r) goto done;

        /* "Alt Prefix" folders */
        if (rock->namespace->isalt) {
            /* reset the the namebuffer */
            r = (*rock->proc)(NULL, rock->procrock);
            if (r) goto done;

            rock->mb_category = MBNAME_ALTINBOX;

            /* special case user.foo.INBOX.  If we're singlepercent == 2, this could
             return DONE, in which case we don't need to foreach the rest of the
             altprefix space */
            r = cyrusdb_forone(rock->db, inbox, inboxlen+6, &find_p, &find_cb, rock, NULL);
            if (r == CYRUSDB_DONE) goto skipalt;
            if (r) goto done;

            /* special case any other altprefix stuff */
            rock->mb_category = MBNAME_ALTPREFIX;
            r = cyrusdb_foreach(rock->db, inbox, inboxlen+1, &find_p, &find_cb, rock, NULL);
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
            if (prefixlen < len) {
                /* we match all users */
                strlcpy(domainpat+domainlen, "user.", sizeof(domainpat)-domainlen);
            }
            else {
                /* just those in this prefix */
                strlcpy(domainpat+domainlen, "user.", sizeof(domainpat)-domainlen);
                strlcpy(domainpat+domainlen+5, commonpat+len+1, sizeof(domainpat)-domainlen-5);
            }

            rock->mb_category = MBNAME_OTHERUSER;

            /* because of how domains work, with crossdomains or admin you can't prefix at all :( */
            size_t thislen = (isadmin || crossdomains) ? 0 : strlen(domainpat);

            /* reset the the namebuffer */
            r = (*rock->proc)(NULL, rock->procrock);
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

            /* reset the the namebuffer */
            r = (*rock->proc)(NULL, rock->procrock);
            if (r) goto done;

            /* iterate through all the non-user folders on the server */
            r = mboxlist_find_category(rock, domainpat, domainlen);
            if (r) goto done;
        }
    }

    /* finish with a reset call always */
    r = (*rock->proc)(NULL, rock->procrock);

 done:
    for (i = 0; i < rock->globs.count; i++) {
        glob *g = ptrarray_nth(&rock->globs, i);
        glob_free(&g);
    }
    ptrarray_fini(&rock->globs);

    return r;
}

EXPORTED int mboxlist_findallmulti(struct namespace *namespace,
                                   const strarray_t *patterns, int isadmin,
                                   const char *userid, const struct auth_state *auth_state,
                                   findall_cb *proc, void *rock)
{
    int r = 0;

    if (!namespace) namespace = mboxname_get_adminnamespace();

    struct find_rock cbrock;
    memset(&cbrock, 0, sizeof(struct find_rock));

    cbrock.auth_state = auth_state;
    cbrock.db = mbdb;
    cbrock.isadmin = isadmin;
    cbrock.namespace = namespace;
    cbrock.proc = proc;
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
    strarray_t patterns = STRARRAY_INITIALIZER;
    strarray_append(&patterns, pattern);

    int r = mboxlist_findallmulti(namespace, &patterns, isadmin, userid, auth_state, proc, rock);

    strarray_fini(&patterns);

    return r;
}

EXPORTED int mboxlist_findone(struct namespace *namespace,
                              const char *intname, int isadmin,
                              const char *userid, const struct auth_state *auth_state,
                              findall_cb *proc, void *rock)
{
    int r = 0;

    if (!namespace) namespace = mboxname_get_adminnamespace();

    struct find_rock cbrock;
    memset(&cbrock, 0, sizeof(struct find_rock));

    cbrock.auth_state = auth_state;
    cbrock.db = mbdb;
    cbrock.isadmin = isadmin;
    cbrock.namespace = namespace;
    cbrock.proc = proc;
    cbrock.procrock = rock;
    cbrock.userid = userid;
    if (userid) {
        const char *domp = strchr(userid, '@');
        if (domp) cbrock.domain = domp + 1;
    }

    mbname_t *mbname = mbname_from_intname(intname);
    glob *g = glob_init(mbname_extname(mbname, namespace, userid),
                        namespace->hier_sep);
    ptrarray_append(&cbrock.globs, g);
    mbname_free(&mbname);

    r = cyrusdb_forone(cbrock.db, intname, strlen(intname), &find_p, &find_cb, &cbrock, NULL);

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

/*
 * Set all the resource quotas on, or create a quota root.
 */
EXPORTED int mboxlist_setquotas(const char *root,
                       quota_t newquotas[QUOTA_NUMRESOURCES], int force)
{
    struct quota q;
    int r;
    int res;
    struct txn *tid = NULL;
    struct mboxevent *mboxevents = NULL;
    struct mboxevent *quotachange_event = NULL;
    struct mboxevent *quotawithin_event = NULL;

    if (!root[0] || root[0] == '.' || strchr(root, '/')
        || strchr(root, '*') || strchr(root, '%') || strchr(root, '?')) {
        return IMAP_MAILBOX_BADNAME;
    }

    quota_init(&q, root);
    r = quota_read(&q, &tid, 1);

    if (!r) {
        int changed = 0;
        int underquota;

        /* has it changed? */
        for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
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
            r = quota_write(&q, &tid);

            if (quotachange_event == NULL) {
                quotachange_event = mboxevent_enqueue(EVENT_QUOTA_CHANGE, &mboxevents);
            }

            for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
                mboxevent_extract_quota(quotachange_event, &q, res);
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
    r = quota_write(&q, &tid);
    if (r) goto done;

    /* prepare a QuotaChange event notification */
    if (quotachange_event == NULL)
        quotachange_event = mboxevent_enqueue(EVENT_QUOTA_CHANGE, &mboxevents);

    for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
        mboxevent_extract_quota(quotachange_event, &q, res);
    }

    quota_commit(&tid);

    /* recurse through mailboxes, setting the quota and finding
     * out the usage */
    mboxlist_mboxtree(root, mboxlist_changequota, (void *)root, 0);

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

    r = quota_deleteroot(root);
    quota_changelockrelease();

    if (!r) sync_log_quota(root);

 done:
    quota_free(&q);
    return r;
}

EXPORTED modseq_t mboxlist_foldermodseq_dirty(struct mailbox *mailbox)
{
    mbentry_t *mbentry = NULL;
    modseq_t ret = 0;

    if (mboxlist_mylookup(mailbox->name, &mbentry, NULL, 0))
        return 0;

    ret = mbentry->foldermodseq = mailbox_modseq_dirty(mailbox);

    mboxlist_update(mbentry, 0);

    mboxlist_entry_free(&mbentry);

    return ret;
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
    const char *root = (const char *) rock;
    int res;
    quota_t quota_usage[QUOTA_NUMRESOURCES];

    assert(root);

    r = mailbox_open_iwl(mbentry->name, &mailbox);
    if (r) goto done;

    mailbox_get_usage(mailbox, quota_usage);

    if (mailbox->quotaroot) {
        quota_t quota_diff[QUOTA_NUMRESOURCES];

        if (strlen(mailbox->quotaroot) >= strlen(root)) {
            /* Part of a child quota root - skip */
            goto done;
        }

        /* remove usage from the old quotaroot */
        for (res = 0; res < QUOTA_NUMRESOURCES ; res++) {
            quota_diff[res] = -quota_usage[res];
        }
        r = quota_update_useds(mailbox->quotaroot, quota_diff,
                               mailbox->name);
    }

    /* update (or set) the quotaroot */
    r = mailbox_set_quotaroot(mailbox, root);
    if (r) goto done;

    /* update the new quota root */
    r = quota_update_useds(root, quota_usage, mailbox->name);

 done:
    mailbox_close(&mailbox);

    if (r) {
        syslog(LOG_ERR, "LOSTQUOTA: unable to change quota root for %s to %s: %s",
               mbentry->name, root, error_message(r));
    }

    /* Note, we're a callback, and it's not a huge tragedy if we
     * fail, so we don't ever return a failure */
    return 0;
}

/* must be called after cyrus_init */
EXPORTED void mboxlist_init(int myflags)
{
    if (myflags & MBOXLIST_SYNC) {
        cyrusdb_sync(DB);
    }
}

EXPORTED void mboxlist_open(const char *fname)
{
    int ret, flags;
    char *tofree = NULL;

    if (!fname)
        fname = config_getstring(IMAPOPT_MBOXLIST_DB_PATH);

    /* create db file name */
    if (!fname) {
        tofree = strconcat(config_dir, FNAME_MBOXLIST, (char *)NULL);
        fname = tofree;
    }

    flags = CYRUSDB_CREATE;
    if (config_getswitch(IMAPOPT_IMPROVED_MBOXLIST_SORT)) {
        flags |= CYRUSDB_MBOXSORT;
    }

    ret = cyrusdb_open(DB, fname, flags, &mbdb);
    if (ret != 0) {
        syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
               cyrusdb_strerror(ret));
            /* Exiting TEMPFAIL because Sendmail thinks this
               EC_OSFILE == permanent failure. */
        fatal("can't read mailboxes file", EC_TEMPFAIL);
    }

    free(tofree);

    mboxlist_dbopen = 1;
}

EXPORTED void mboxlist_close(void)
{
    int r;

    if (mboxlist_dbopen) {
        r = cyrusdb_close(mbdb);
        if (r) {
            syslog(LOG_ERR, "DBERROR: error closing mailboxes: %s",
                   cyrusdb_strerror(r));
        }
        mboxlist_dbopen = 0;
    }
}

EXPORTED void mboxlist_done(void)
{
    /* DB->done() handled by cyrus_done() */
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
    if (config_getswitch(IMAPOPT_IMPROVED_MBOXLIST_SORT)) {
        flags |= CYRUSDB_MBOXSORT;
    }

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
    int r = 0;

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
    cbrock.proc = proc;
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
    strarray_t patterns = STRARRAY_INITIALIZER;
    strarray_append(&patterns, pattern);

    int r = mboxlist_findsubmulti(namespace, &patterns, isadmin, userid, auth_state, proc, rock, force);

    strarray_fini(&patterns);

    return r;
}

static int subsadd_cb(void *rock, const char *key, size_t keylen,
                      const char *val __attribute__((unused)),
                      size_t vallen __attribute__((unused)))
{
    strarray_t *list = (strarray_t *)rock;
    strarray_appendm(list, xstrndup(key, keylen));
    return 0;
}

EXPORTED strarray_t *mboxlist_sublist(const char *userid)
{
    struct db *subs = NULL;
    strarray_t *list = strarray_new();
    int r;

    /* open subs DB */
    r = mboxlist_opensubs(userid, &subs);
    if (r) goto done;

    /* faster to do it all in a single slurp! */
    r = cyrusdb_foreach(subs, "", 0, subsadd_cb, NULL, list, 0);

    mboxlist_closesubs(subs);

done:
    if (r) {
        strarray_free(list);
        return NULL;
    }
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
    char mboxname[MAX_MAILBOX_NAME+1];
    int r;

    /* free previous record */
    mboxlist_entry_free(&mbrock->mbentry);

    snprintf(mboxname, MAX_MAILBOX_NAME, "%.*s", (int) keylen, key);

    if ((mbrock->flags & MBOXTREE_SKIP_PERSONAL) &&
        mboxname_userownsmailbox(mbrock->userid, mboxname)) return 0;

    r = mboxlist_lookup(mboxname, &mbrock->mbentry, NULL);
    if (r) {
        syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
               mboxname, error_message(r));
        return r;
    }

    return mbrock->proc(mbrock->mbentry, mbrock->rock);
}

EXPORTED int mboxlist_usersubs(const char *userid, mboxlist_cb *proc,
                               void *rock, int flags)
{
    struct db *subs = NULL;
    struct submb_rock mbrock = { NULL, userid, flags, proc, rock };
    int r = 0;

    /* open subs DB */
    r = mboxlist_opensubs(userid, &subs);
    if (r) return r;

    /* faster to do it all in a single slurp! */
    r = cyrusdb_foreach(subs, "", 0, NULL, usersubs_cb, &mbrock, 0);

    mboxlist_entry_free(&mbrock.mbentry);

    mboxlist_closesubs(subs);

    return r;
}




/* returns CYRUSDB_NOTFOUND if the folder doesn't exist, and 0 if it does! */
EXPORTED int mboxlist_checksub(const char *name, const char *userid)
{
    int r;
    struct db *subs;
    const char *val;
    size_t vallen;

    r = mboxlist_opensubs(userid, &subs);

    if (!r) r = cyrusdb_fetch(subs, name, strlen(name), &val, &vallen, NULL);

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
    mbentry_t *mbentry = NULL;
    int r;
    struct db *subs;
    struct mboxevent *mboxevent;

    if ((r = mboxlist_opensubs(userid, &subs)) != 0) {
        return r;
    }

    if (add && !force) {
        /* Ensure mailbox exists and can be seen by user */
        if ((r = mboxlist_lookup(name, &mbentry, NULL))!=0) {
            mboxlist_closesubs(subs);
            return r;
        }
        if ((cyrus_acl_myrights(auth_state, mbentry->acl) & ACL_LOOKUP) == 0) {
            mboxlist_closesubs(subs);
            mboxlist_entry_free(&mbentry);
            return IMAP_MAILBOX_NONEXISTENT;
        }
    }

    if (add) {
        r = cyrusdb_store(subs, name, strlen(name), "", 0, NULL);
    } else {
        r = cyrusdb_delete(subs, name, strlen(name), NULL, 0);
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

    /* prepare a MailboxSubscribe or MailboxUnSubscribe event notification */
    if (notify && r == 0) {
        mboxevent = mboxevent_new(add ? EVENT_MAILBOX_SUBSCRIBE :
                                        EVENT_MAILBOX_UNSUBSCRIBE);

        mboxevent_set_access(mboxevent, NULL, NULL, userid, name, 1);
        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);
    }

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
