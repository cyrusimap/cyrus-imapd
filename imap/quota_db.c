/* quota_db.c -- quota manipulation routines
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>

#include "cyrusdb.h"
#include "dlist.h"
#include "global.h"
#include "mailbox.h"
#include "mboxname.h"
#include "mboxevent.h"
#include "quota.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "strarray.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#define QDB config_quota_db

HIDDEN struct db *qdb;

/* skanky reuse of mboxname locks.  Ideally we would rename
 * them to something more general and use them elsewhere */
static struct mboxlock *qchangelock;

static void init_internal(void);

static int quota_initialized = 0;
static int quota_dbopen = 0;

/* keywords used when storing fields in the new quota db format */
static const char * const quota_db_names[QUOTA_NUMRESOURCES] = {
    "S",        /* QUOTA_STORAGE */
    "M",        /* QUOTA_MESSAGE */
    "AS",       /* QUOTA_ANNOTSTORAGE */
    "NF"        /* QUOTA_NUMFOLDERS */
};

/* IMAP atoms for various quota resources */
EXPORTED const char * const quota_names[QUOTA_NUMRESOURCES] = {
    "STORAGE",                  /* QUOTA_STORAGE -- RFC 2087 */
    "MESSAGE",                  /* QUOTA_MESSAGE -- RFC 2087 */
    "X-ANNOTATION-STORAGE",     /* QUOTA_ANNOTSTORAGE */
    "X-NUM-FOLDERS"             /* QUOTA_NUMFOLDERS */
};

EXPORTED const quota_t quota_units[QUOTA_NUMRESOURCES] = {
    1024,               /* QUOTA_STORAGE -- RFC 2087 */
    1,                  /* QUOTA_MESSAGE -- RFC 2087 */
    1024,               /* QUOTA_ANNOTSTORAGE */
    1                   /* QUOTA_NUMFOLDERS */
};

EXPORTED int quota_name_to_resource(const char *str)
{
    int res;

    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
        if (!strcasecmp(str, quota_names[res]))
            return res;
    }
    return -1;
}

EXPORTED int quota_changelock(void)
{
    return mboxname_lock("$QUOTACHANGE", &qchangelock, LOCK_EXCLUSIVE);
}

EXPORTED void quota_changelockrelease()
{
    mboxname_release(&qchangelock);
}

/*
 * Initialise a struct quota and set the root field.  Quota must be initialised
 * before use.
 */
EXPORTED void quota_init(struct quota *q, const char *root)
{
    int res;

    memset(q, 0, sizeof(*q));
    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++)
        q->limits[res] = QUOTA_UNLIMITED;

    q->root = xstrdup(root);
}

/* release all the memory allocated in a struct quota */
EXPORTED void quota_free(struct quota *q)
{
    free(q->scanmbox);
    free(q->root);
    memset(q, 0, sizeof(*q));
}

/*
 * Parse a quota database entry, which is formatted as a string
 * containing multiple space-separated fields, into a struct quota.
 * Returns: 0 on success or an IMAP error code.
 */
static int quota_parseval(const char *data, size_t datalen,
                          struct quota *quota, int iswrite)
{
    strarray_t *fields = NULL;
    int r = IMAP_MAILBOX_BADFORMAT;
    int i = 0;
    int res = QUOTA_STORAGE;
    struct dlist *dl = NULL;
    quota_t temp;
    modseq_t modseq = 0;

    /* new dlist format */
    if (data[0] == '%') {
        if (dlist_parsemap(&dl, 0, 0, data, datalen))
            goto out;

        for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
            struct dlist *val;
            struct dlist *item = dlist_getchild(dl, quota_db_names[res]);
            if (!item) continue;
            val = dlist_getchildn(item, 0);
            if (val) quota->useds[res] = dlist_num(val);
            val = dlist_getchildn(item, 1);
            if (val) quota->limits[res] = dlist_num(val);
        }

        /* only read the SCAN stuff if it's a write lock */
        if (iswrite) {
            struct dlist *scan = dlist_getchild(dl, "SCAN");
            const char *mboxname = NULL;
            if (scan && dlist_getatom(scan, "MBOX", &mboxname)) {
                quota->scanmbox = xstrdup(mboxname);
                for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
                    struct dlist *val = dlist_getchild(scan, quota_db_names[res]);
                    if (val) quota->scanuseds[res] = dlist_num(val);
                }
            }
        }

        dlist_getnum64(dl, "MODSEQ", &modseq);

        goto done;
    }

    /* parse historical formats */
    fields = strarray_split(data, NULL, 0);
    for (;;) {
        if (i+2 > fields->count)
            goto out;   /* need at least 2 more fields */
        if (sscanf(fields->data[i++], QUOTA_T_FMT, &quota->useds[res]) != 1)
            goto out;
        if (sscanf(fields->data[i++], QUOTA_T_FMT, &quota->limits[res]) != 1)
            goto out;
        /* skip over temporary extra used data from failed quota -f runs */
        if (i < fields->count &&
            sscanf(fields->data[i], QUOTA_T_FMT, &temp) == 1) {
            i++;
        }
        if (i == fields->count)
            break;      /* successfully parsed whole line */

        for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
            if (quota_db_names[res] && !strcasecmp(fields->data[i], quota_db_names[res]))
                break;
        }
        if (res == QUOTA_NUMRESOURCES)
            goto out;

        i++;
    }

done:
    quota->modseq = modseq;
    r = 0;
out:
    dlist_free(&dl);
    strarray_free(fields);
    return r;
}

EXPORTED int quota_read_withconversations(struct quota *quota)
{
    int r = quota_read(quota, NULL, 0);

    if (config_getswitch(IMAPOPT_QUOTA_USE_CONVERSATIONS)) {
        struct conversations_state *local_cstate = NULL;
        struct conversations_state *cstate = conversations_get_mbox(quota->root);
        if (!cstate) {
            conversations_open_mbox(quota->root, /*shared*/1, &local_cstate);
            cstate = local_cstate;
        }
        if (cstate) {
            struct conv_quota q = CONV_QUOTA_INIT;
            conversations_read_quota(cstate, &q);
            quota->useds[QUOTA_STORAGE] = q.storage;
            quota->useds[QUOTA_MESSAGE] = q.emails;
        }
        if (local_cstate) conversations_commit(&local_cstate);
    }

    return r;
}

/*
 * Read the quota entry 'quota'
 */
EXPORTED int quota_read(struct quota *quota, struct txn **tid, int wrlock)
{
    int r;
    size_t qrlen;
    const char *data;
    size_t datalen;

    init_internal();

    if (!quota->root || !(qrlen = strlen(quota->root)))
        return IMAP_QUOTAROOT_NONEXISTENT;

    if (wrlock)
        r = cyrusdb_fetchlock(qdb, quota->root, qrlen, &data, &datalen, tid);
    else
        r = cyrusdb_fetch(qdb, quota->root, qrlen, &data, &datalen, tid);

    if (!datalen) /* zero byte file can cause no data to be mapped */
        return IMAP_QUOTAROOT_NONEXISTENT;

    switch (r) {
    case CYRUSDB_OK:
        if (!*data) return IMAP_QUOTAROOT_NONEXISTENT;
        r = quota_parseval(data, datalen, quota, wrlock);
        if (r) {
            syslog(LOG_ERR, "DBERROR: error fetching quota "
                            "root=<%s> value=<%s>",
                   quota->root, data);
            return r;
        }
        break;

    case CYRUSDB_AGAIN:
        return IMAP_AGAIN;

    case CYRUSDB_NOTFOUND:
        return IMAP_QUOTAROOT_NONEXISTENT;
    }

    if (r) {
        syslog(LOG_ERR, "DBERROR: error fetching quota %s: %s",
               quota->root, cyrusdb_strerror(r));
        return IMAP_IOERROR;
    }

    return 0;
}

EXPORTED int quota_check(const struct quota *q,
                enum quota_resource res, quota_t delta)
{
    quota_t lim;

    if (q->limits[res] < 0)
        return 0;           /* unlimited */

    /*
     * We are always allowed to *reduce* usage even if it doesn't get us
     * below the quota.  As a side effect this allows our caller to pass
     * delta = -1 meaning "don't care about quota checks".
     */
    if (delta < 0)
        return 0;

    lim = (quota_t)q->limits[res] * quota_units[res];
    if (q->useds[res] + delta > lim) {
        struct mboxevent *mboxevent;

        /* send a QuotaExceed event notification */
        /* note: IMAP MULTIAPPEND is not taken into account by the RFC 5423.
         * so there is a strange behavior to send QuotaExceed notification with
         * value of messages/diskUsed less than value of maxMessages/DiskQuota.
         */
        mboxevent = mboxevent_new(EVENT_QUOTA_EXCEED);
        mboxevent_extract_quota(mboxevent, q, res);

        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);

        return IMAP_QUOTA_EXCEEDED;
    }
    return 0;
}

EXPORTED void quota_use(struct quota *q,
               enum quota_resource res, quota_t delta)
{
    /* prevent underflow */
    if ((delta < 0) && (-delta > q->useds[res])) {
        syslog(LOG_INFO, "Quota underflow for root %s, resource %s,"
                         " you may wish to run \"quota -f\"",
                         q->root, quota_names[res]);
        q->useds[res] = 0;
    }
    else {
        q->useds[res] += delta;
    }
}

struct quota_foreach_t {
    quotaproc_t *proc;
    void *rock;
    struct txn **tid;
};

static int do_onequota(void *rock,
                       const char *key, size_t keylen,
                       const char *data, size_t datalen)
{
    int r = 0;
    struct quota quota;
    struct quota_foreach_t *fd = (struct quota_foreach_t *)rock;
    char *root = xstrndup(key, keylen);
    int iswrite = fd->tid ? 1 : 0;

    init_internal();

    quota_init(&quota, root);

    /* XXX - error if not parsable? */
    if (datalen && !quota_parseval(data, datalen, &quota, iswrite)) {
        r = fd->proc(&quota, fd->rock);
    }

    quota_free(&quota);
    free(root);

    return r;
}

EXPORTED int quota_foreach(const char *prefix, quotaproc_t *proc,
                  void *rock, struct txn **tid)
{
    int r;
    const char *search = prefix ? (char *)prefix : "";
    struct quota_foreach_t foreach_d;

    init_internal();

    foreach_d.proc = proc;
    foreach_d.rock = rock;
    foreach_d.tid = tid;

    r = cyrusdb_foreach(qdb, search, strlen(search), NULL,
                     do_onequota, &foreach_d, tid);

    return r;
}

/*
 * Commit the outstanding quota transaction
 */
EXPORTED void quota_commit(struct txn **tid)
{
    if (tid && *tid) {
        if (cyrusdb_commit(qdb, *tid)) {
            syslog(LOG_ERR, "IOERROR: committing quota: %m");
        }
        *tid = NULL;
    }
}

/*
 * Abort the outstanding quota transaction
 */
EXPORTED void quota_abort(struct txn **tid)
{
    if (tid && *tid) {
        if (cyrusdb_abort(qdb, *tid)) {
            syslog(LOG_ERR, "IOERROR: aborting quota: %m");
        }
        *tid = NULL;
    }
}

/*
 * Write out the quota entry 'quota'
 */
EXPORTED int quota_write(struct quota *quota, int silent, struct txn **tid)
{
    int r;
    int qrlen;
    int res;
    struct buf buf = BUF_INITIALIZER;
    struct dlist *dl = NULL;

    init_internal();

    if (!quota->root) return IMAP_QUOTAROOT_NONEXISTENT;

    qrlen = strlen(quota->root);
    if (!qrlen) return IMAP_QUOTAROOT_NONEXISTENT;

    if (mboxname_isusermailbox(quota->root, /*isinbox*/0)) {
        if (silent)
            quota->modseq = mboxname_setquotamodseq(quota->root, quota->modseq);
        else
            quota->modseq = mboxname_nextquotamodseq(quota->root, quota->modseq);

    }

    dl = dlist_newkvlist(NULL, NULL);

    for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
        struct dlist *item = dlist_newlist(dl, quota_db_names[res]);
        dlist_setnum64(item, NULL, quota->useds[res]);
        if (quota->limits[res] != QUOTA_UNLIMITED)
            dlist_setnum64(item, NULL, quota->limits[res]);
    }

    if (quota->scanmbox) {
        struct dlist *scan = dlist_newkvlist(dl, "SCAN");
        dlist_setatom(scan, "MBOX", quota->scanmbox);
        for (res = 0; res < QUOTA_NUMRESOURCES; res++)
            dlist_setnum64(scan, quota_db_names[res], quota->scanuseds[res]);
    }

    dlist_setnum64(dl, "MODSEQ", quota->modseq);

    dlist_printbuf(dl, 0, &buf);

    r = cyrusdb_store(qdb, quota->root, qrlen, buf.s, buf.len, tid);

    switch (r) {
    case CYRUSDB_OK:
        r = 0;
        break;

    case CYRUSDB_AGAIN:
        r = IMAP_AGAIN;
        break;

    default:
        syslog(LOG_ERR, "DBERROR: error storing %s: %s",
               quota->root, cyrusdb_strerror(r));
        r = IMAP_IOERROR;
        break;
    }

    dlist_free(&dl);
    buf_free(&buf);
    return r;
}

EXPORTED int quota_update_useds(const char *quotaroot,
                       const quota_t diff[QUOTA_NUMRESOURCES],
                       const char *mboxname,
                       int silent)
{
    struct quota q;
    struct txn *tid = NULL;
    int r = 0;
    struct mboxevent *mboxevents = NULL;

    init_internal();

    if (!quotaroot || !*quotaroot)
        return IMAP_QUOTAROOT_NONEXISTENT;

    quota_init(&q, quotaroot);

    r = quota_read(&q, &tid, 1);

    if (!r) {
        int res;
        int cmp = 1;
        if (mboxname && q.scanmbox) {
            cmp = cyrusdb_compar(qdb, mboxname, strlen(mboxname),
                                 q.scanmbox, strlen(q.scanmbox));
        }
        for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
            int was_over = quota_is_overquota(&q, res, NULL);
            quota_use(&q, res, diff[res]);
            if (cmp <= 0)
                q.scanuseds[res] += diff[res];

            if (was_over && !quota_is_overquota(&q, res, NULL)) {
                struct mboxevent *mboxevent =
                    mboxevent_enqueue(EVENT_QUOTA_WITHIN, &mboxevents);
                mboxevent_extract_quota(mboxevent, &q, res);
            }
        }
        r = quota_write(&q, silent, &tid);
    }

    if (r) {
        quota_abort(&tid);
        goto out;
    }
    quota_commit(&tid);

    mboxevent_notify(&mboxevents);

out:
    quota_free(&q);
    if (r) {
        syslog(LOG_ERR, "LOSTQUOTA: unable to record change of "
               QUOTA_T_FMT " bytes and " QUOTA_T_FMT " messages in quota %s: %s",
               diff[QUOTA_STORAGE], diff[QUOTA_MESSAGE],
               quotaroot, error_message(r));
    }

    mboxevent_freequeue(&mboxevents);

    return r;
}

EXPORTED int quota_check_useds(const char *quotaroot,
                      const quota_t diff[QUOTA_NUMRESOURCES])
{
    int r = 0;
    struct quota q;
    int res;

    init_internal();

    /*
     * We are always allowed to *reduce* usage even if it doesn't get us
     * below the quota.  As a side effect this allows our caller to pass
     * delta = -1 meaning "don't care about quota checks".
     */
    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
        if (diff[res] >= 0)
            break;
    }
    if (res == QUOTA_NUMRESOURCES)
        return 0;           /* all negative */

    quota_init(&q, quotaroot);
    r = quota_read_withconversations(&q);

    if (r == IMAP_QUOTAROOT_NONEXISTENT) {
        r = 0;
        goto done;
    }
    if (r) goto done;

    for (res = 0 ; res < QUOTA_NUMRESOURCES ; res++) {
        r = quota_check(&q, res, diff[res]);
        if (r) goto done;
    }

done:
    quota_free(&q);
    return r;
}

/*
 * Remove the quota root 'quota'
 */
EXPORTED int quota_deleteroot(const char *quotaroot, int silent)
{
    int r;

    init_internal();

    if (!quotaroot || !*quotaroot)
        return IMAP_QUOTAROOT_NONEXISTENT;

    r = cyrusdb_delete(qdb, quotaroot, strlen(quotaroot), NULL, 0);

    switch (r) {
    case CYRUSDB_OK:
    case CYRUSDB_NOTFOUND:  /* shouldn't happen anyway */
        r = 0;
        break;

    case CYRUSDB_AGAIN:
        return IMAP_AGAIN;

    default:
        syslog(LOG_ERR, "DBERROR: error deleting quotaroot %s: %s",
               quotaroot, cyrusdb_strerror(r));
        return IMAP_IOERROR;
    }

    if (!silent && mboxname_isusermailbox(quotaroot, /*isinbox*/0)) {
        mboxname_nextquotamodseq(quotaroot, 0);
    }
    return r;
}

/*
 * Find the mailbox 'name' 's quotaroot, and return it in 'ret'.
 * 'ret' must be at least MAX_MAILBOX_NAME.
 *
 * returns true if a quotaroot is found, 0 otherwise.
*/
EXPORTED int quota_findroot(char *ret, size_t retlen, const char *name)
{
    char *tail, *p, *mbox;

    init_internal();

    strlcpy(ret, name, retlen);

    /* find the start of the unqualified mailbox name */
    mbox = (config_virtdomains && (p = strchr(ret, '!'))) ? p+1 : ret;
    tail = mbox + strlen(mbox);

    while (cyrusdb_fetch(qdb, ret, strlen(ret), NULL, NULL, NULL)) {
        tail = strrchr(mbox, '.');
        if (!tail) break;
        *tail = '\0';
    }
    if (tail) return 1;
    if (mbox == ret) return 0;

    /* check for a domain quota */
    *mbox = '\0';
    return (cyrusdb_fetch(qdb, ret, strlen(ret), NULL, NULL, NULL) == 0);
}

static void done_cb(void*rock __attribute__((unused)))
{
    if (quota_dbopen) {
        quotadb_close();
    }
    quotadb_done();
}

static void init_internal(void)
{
    if (!quota_initialized) {
        quotadb_init(0);
        quota_initialized = 1;
    }
    if (!quota_dbopen) {
        quotadb_open(NULL);
    }
}

/* must be called after cyrus_init */
EXPORTED void quotadb_init(int myflags)
{
    if (myflags & QUOTADB_SYNC) {
        cyrusdb_sync(QDB);
    }
    cyrus_modules_add(done_cb, NULL);
}

EXPORTED void quotadb_open(const char *fname)
{
    int ret;
    char *tofree = NULL;
    int flags = CYRUSDB_CREATE;

    if (!fname)
        fname = config_getstring(IMAPOPT_QUOTA_DB_PATH);

    /* create db file name */
    if (!fname) {
        tofree = strconcat(config_dir, FNAME_QUOTADB, (char *)NULL);
        fname = tofree;
    }

    if (config_getswitch(IMAPOPT_IMPROVED_MBOXLIST_SORT))
        flags |= CYRUSDB_MBOXSORT;

    ret = cyrusdb_open(QDB, fname, flags, &qdb);
    if (ret != 0) {
        syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
               cyrusdb_strerror(ret));
            /* Exiting TEMPFAIL because Sendmail thinks this
               EX_OSFILE == permanent failure. */
        fatal("can't read quotas file", EX_TEMPFAIL);
    }

    free(tofree);

    quota_dbopen = 1;
}

EXPORTED int quotadb_foreach(const char *prefix, size_t prefixlen,
                             foreach_p *p, foreach_cb *cb, void *rock)
{
    init_internal();
    return cyrusdb_foreach(qdb, prefix, prefixlen, p, cb, rock, NULL);
}

EXPORTED void quotadb_close(void)
{
    int r;

    if (quota_dbopen) {
        r = cyrusdb_close(qdb);
        if (r) {
            syslog(LOG_ERR, "DBERROR: error closing quotas: %s",
                   cyrusdb_strerror(r));
        }
        quota_dbopen = 0;
    }
}

EXPORTED void quotadb_done(void)
{
    /* DB->done() handled by cyrus_done() */
    quota_initialized = 0;
}

EXPORTED int quota_is_overquota(const struct quota *quota, enum quota_resource res,
                       quota_t newquotas[QUOTA_NUMRESOURCES])
{
    int limit = newquotas ? newquotas[res] : quota->limits[res];

    return limit >= 0 && quota->useds[res] >= ((quota_t)limit * quota_units[res]);
}
