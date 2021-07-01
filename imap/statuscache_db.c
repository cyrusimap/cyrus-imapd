/* statuscache_db.c -- Status caching routines
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

#include "assert.h"
#include "cyrusdb.h"
#include "imapd.h"
#include "global.h"
#include "mboxlist.h"
#include "mailbox.h"
#include "seen.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#include "statuscache.h"

#define DB config_statuscache_db

static struct db *statuscachedb = NULL;
static int _initted = 0;

/********************* CACHE METHODS ***********************/

static void statuscache_open(void)
{
    if (!config_getswitch(IMAPOPT_STATUSCACHE))
        return;

    char *fname = xstrdupnull(config_getstring(IMAPOPT_STATUSCACHE_DB_PATH));
    if (!fname)
        fname = strconcat(config_dir, FNAME_STATUSCACHEDB, (char *)NULL);

    int r = cyrusdb_open(DB, fname, CYRUSDB_CREATE, &statuscachedb);
    if (r) {
        syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
               cyrusdb_strerror(r));
        syslog(LOG_ERR, "statuscache in degraded mode");
        statuscachedb = NULL;
    }

    free(fname);
}

static void statuscache_close(void)
{
    if (!statuscachedb) return;

    int r = cyrusdb_close(statuscachedb);
    if (r) {
        syslog(LOG_ERR, "DBERROR: error closing statuscache: %s",
              cyrusdb_strerror(r));
    }

    statuscachedb = NULL;
}

static void done_cb(void *rock __attribute__((unused)))
{
    statuscache_close();
}

static void init_internal()
{
    if (_initted) return;
    statuscache_open();
    cyrus_modules_add(done_cb, NULL);
    _initted = 1;
}

static void statuscache_buildkey(const char *mboxname, const char *userid,
                                 struct buf *buf)
{
    buf_setcstr(buf, mboxname);
    /* double % is a safe separator, it can't exist in a mailboxname */
    buf_putc(buf, '%');
    if (userid) {
        buf_putc(buf, '%');
        buf_appendcstr(buf, userid);
    }
}

static void statuscache_read_index(const char *mboxname, struct statusdata *sdata)
{
    struct buf keybuf = BUF_INITIALIZER;
    const char *data = NULL;
    size_t datalen = 0;

    /* Don't access DB if it hasn't been opened */
    if (!statuscachedb)
        return;

    /* Check if there is an entry in the database */
    statuscache_buildkey(mboxname, NULL, &keybuf);
    int r = cyrusdb_fetch(statuscachedb, keybuf.s, keybuf.len, &data, &datalen, NULL);
    buf_free(&keybuf);

    if (r || !data || !datalen)
        return;

    const char *dend = data + datalen;

    char *p = (char *)data;
    if (*p++ != 'I') return;
    if (*p++ != ' ') return;

    unsigned version = (unsigned) strtoul(p, &p, 10);
    if (version != (unsigned) STATUSCACHE_VERSION) {
        /* Wrong version */
        return;
    }

    if (*p++ != ' ') return;
    if (*p++ != '(') return;

    // read the matched items
    if (p < dend) sdata->messages = strtoul(p, &p, 10);
    if (p < dend) sdata->uidnext = strtoul(p, &p, 10);
    if (p < dend) sdata->uidvalidity = strtoul(p, &p, 10);
    if (p < dend) sdata->mboptions = strtoul(p, &p, 10);
    if (p < dend) sdata->size = strtoull(p, &p, 10);
    if (p < dend) sdata->createdmodseq = strtoull(p, &p, 10);
    if (p < dend) sdata->highestmodseq = strtoull(p, &p, 10);

    if (*p++ != ')') return;

    /* Sanity check the data */
    if (!sdata->highestmodseq)
        return;

    sdata->statusitems |= STATUS_INDEXITEMS | STATUS_UIDVALIDITY;
}

static void statuscache_read_seen(const char *mboxname, const char *userid,
                                  struct statusdata *sdata)
{
    struct buf keybuf = BUF_INITIALIZER;
    const char *data = NULL;
    size_t datalen = 0;

    if (!userid)
        return;

    // if no messages, other counts must also be zero
    if (!sdata->messages) {
        sdata->recent = 0;
        sdata->unseen = 0;
        sdata->userid = userid;
        sdata->statusitems |= STATUS_SEENITEMS;
        return;
    }

    /* Don't access DB if it hasn't been opened */
    if (!statuscachedb)
        return;

    // we must have a HIGHESTMODSEQ to compare against
    if (!(sdata->statusitems & STATUS_HIGHESTMODSEQ))
        return;

    /* Check if there is an entry in the database */
    statuscache_buildkey(mboxname, userid, &keybuf);
    int r = cyrusdb_fetch(statuscachedb, keybuf.s, keybuf.len, &data, &datalen, NULL);
    buf_free(&keybuf);

    if (r || !data || !datalen)
        return;

    const char *dend = data + datalen;
    char *p = (char *)data;
    if (*p++ != 'S') return;
    if (*p++ != ' ') return;

    unsigned version = (unsigned) strtoul(p, &p, 10);
    if (version != (unsigned) STATUSCACHE_VERSION) {
        /* Wrong version */
        return;
    }

    if (*p++ != ' ') return;
    if (*p++ != '(') return;

    // read the matched items
    if (p < dend) sdata->recent = strtoul(p, &p, 10);
    if (p < dend) sdata->unseen = strtoul(p, &p, 10);
    modseq_t highestmodseq = strtoull(p, &p, 10);

    if (*p++ != ')') return;

    // doesn't match non-unseen key
    if (highestmodseq != sdata->highestmodseq)
        return;

    sdata->userid = userid;
    sdata->statusitems |= STATUS_SEENITEMS;
}

static int statuscache_lookup(const char *mboxname, const char *userid,
                       unsigned statusitems, struct statusdata *sdata)
{
    // nothing to read!
    if (!(statusitems & (STATUS_INDEXITEMS|STATUS_SEENITEMS)))
        return 0;

    init_internal();

    statuscache_read_index(mboxname, sdata);
    if (statusitems & STATUS_SEENITEMS)
        statuscache_read_seen(mboxname, userid, sdata);

    // did we get everything we wanted?
    if ((sdata->statusitems & statusitems) != statusitems)
        return IMAP_NO_NOSUCHMSG;

    return 0;
}

static int statuscache_store(const char *mboxname,
                             struct statusdata *sdata,
                             struct txn **tidptr)
{
    struct buf keybuf = BUF_INITIALIZER;
    struct buf databuf = BUF_INITIALIZER;
    int r = 0;

    statuscache_buildkey(mboxname, /*userid*/NULL, &keybuf);

    /* if we don't have a full index, just nuke the key */
    if (!sdata || (sdata->statusitems & STATUS_INDEXITEMS) != STATUS_INDEXITEMS) {
        r = cyrusdb_delete(statuscachedb, keybuf.s, keybuf.len, tidptr, 1);
        if (r != CYRUSDB_OK) {
            syslog(LOG_ERR, "DBERROR: error deleting statuscache for: %s (%s)",
                   mboxname, cyrusdb_strerror(r));
        }
        goto done;
    }


    buf_printf(&databuf,
                       "I %u (%u %u %u %u %llu " MODSEQ_FMT " " MODSEQ_FMT ")",
                       STATUSCACHE_VERSION,
                       sdata->messages, sdata->uidnext,
                       sdata->uidvalidity, sdata->mboptions, sdata->size,
                       sdata->createdmodseq, sdata->highestmodseq);

    r = cyrusdb_store(statuscachedb, keybuf.s, keybuf.len, databuf.s, databuf.len, tidptr);

    if (r != CYRUSDB_OK) {
        syslog(LOG_ERR, "DBERROR: error updating database: %s (%s)",
               mboxname, cyrusdb_strerror(r));
        goto done;
    }

    if ((sdata->statusitems & STATUS_SEENITEMS) != STATUS_SEENITEMS)
        goto done;

    // if there's no userid, we don't store this stuff
    if (!sdata->userid)
        goto done;

    statuscache_buildkey(mboxname, sdata->userid, &keybuf);

    /* The trailing whitespace is necessary because we
     * use non-length-based functions to parse the values.
     * Any non-digit char would be fine, but whitespace
     * looks less ugly in dbtool output */
    buf_reset(&databuf);
    buf_printf(&databuf,
                       "S %u (%u %u " MODSEQ_FMT ")",
                       STATUSCACHE_VERSION,
                       sdata->recent, sdata->unseen,
                       sdata->highestmodseq);

    r = cyrusdb_store(statuscachedb, keybuf.s, keybuf.len, databuf.s, databuf.len, tidptr);

    if (r != CYRUSDB_OK) {
        syslog(LOG_ERR, "DBERROR: error updating database: %s (%s)",
               mboxname, cyrusdb_strerror(r));
        goto done;
    }

done:
    buf_free(&keybuf);
    buf_free(&databuf);
    return r;
}

HIDDEN int statuscache_invalidate(const char *mboxname, struct statusdata *sdata)
{
    int doclose = 0;
    struct txn *tid = NULL;

    /* if it's disabled then skip */
    if (!config_getswitch(IMAPOPT_STATUSCACHE))
        return 0;

    /* if it's not already open, open and close it for just this */
    if (!statuscachedb) {
        statuscache_open();
        // failed to open, oh well
        if (!statuscachedb)
            return 0;
        doclose = 1;
    }

    int r = statuscache_store(mboxname, sdata, &tid);

    if (!r) {
        cyrusdb_commit(statuscachedb, tid);
    }
    else {
        syslog(LOG_NOTICE, "DBERROR: failed to store statuscache data for %s", mboxname);
        if (tid) cyrusdb_abort(statuscachedb, tid);
    }

    // if we opened the DB, close it now
    if (doclose)
        statuscache_close();

    return 0;
}



/****************** STATUSDATA FILLING METHODS ************************/

HIDDEN void status_fill_mbentry(const mbentry_t *mbentry, struct statusdata *sdata)
{
    assert(mbentry);
    assert(sdata);

    sdata->uidvalidity = mbentry->uidvalidity;
    sdata->mailboxid = mbentry->uniqueid;

    sdata->statusitems |= STATUS_MBENTRYITEMS;
}

HIDDEN void status_fill_mailbox(struct mailbox *mailbox, struct statusdata *sdata)
{
    assert(mailbox);
    assert(sdata);

    sdata->messages = mailbox->i.exists;
    sdata->uidnext = mailbox->i.last_uid+1;
    sdata->mboptions = mailbox->i.options;
    sdata->size = mailbox->i.quota_mailbox_used;
    sdata->createdmodseq = mailbox->i.createdmodseq;
    sdata->highestmodseq = mailbox->i.highestmodseq;

    // mbentry items are also available from an open mailbox
    sdata->uidvalidity = mailbox->i.uidvalidity;
    sdata->mailboxid = mailbox_uniqueid(mailbox);

    sdata->statusitems |= STATUS_INDEXITEMS | STATUS_MBENTRYITEMS;
}

HIDDEN void status_fill_seen(const char *userid, struct statusdata *sdata,
                                  unsigned numrecent, unsigned numunseen)
{
    assert(userid);
    assert(sdata);

    // we need a matching parent record to exist for these values to be valid
    assert(sdata->statusitems & STATUS_HIGHESTMODSEQ);

    sdata->userid = userid;
    sdata->recent = numrecent;
    sdata->unseen = numunseen;

    sdata->statusitems |= STATUS_SEENITEMS;
}

static int status_load_mailbox(struct mailbox *mailbox, const char *userid,
                               unsigned statusitems, struct statusdata *sdata)
{
    status_fill_mailbox(mailbox, sdata);

    if ((statusitems & STATUS_SEENITEMS) && mailbox->i.exists) {
        unsigned numrecent = 0;
        unsigned numunseen = 0;
        /* Read \Seen state */
        struct seqset *seq = NULL;
        int internalseen = mailbox_internal_seen(mailbox, userid);
        unsigned recentuid;

        if (internalseen) {
            recentuid = mailbox->i.recentuid;
        } else {
            struct seen *seendb = NULL;
            struct seendata sd = SEENDATA_INITIALIZER;

            int r = seen_open(userid, SEEN_CREATE, &seendb);
            if (!r) r = seen_read(seendb, mailbox_uniqueid(mailbox), &sd);
            seen_close(&seendb);
            if (r) return r;

            recentuid = sd.lastuid;
            seq = seqset_parse(sd.seenuids, NULL, recentuid);
            seen_freedata(&sd);
        }

        struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
        const message_t *msg;
        while ((msg = mailbox_iter_step(iter))) {
            const struct index_record *record = msg_record(msg);
            if (record->uid > recentuid)
                numrecent++;
            if (internalseen) {
                if (!(record->system_flags & FLAG_SEEN))
                    numunseen++;
            }
            else {
                if (!seqset_ismember(seq, record->uid))
                    numunseen++;
            }
        }
        mailbox_iter_done(&iter);
        seqset_free(seq);

        status_fill_seen(userid, sdata, numrecent, numunseen);
    }

    statuscache_invalidate(mailbox_name(mailbox), sdata);

    return 0;
}

static int status_lookup_internal(const char *mboxname, const char *userid,
                                  unsigned statusitems, struct statusdata *sdata)
{
    struct mailbox *mailbox = NULL;
    int r = 0;

    /* Check status cache if possible */
    if (config_getswitch(IMAPOPT_STATUSCACHE)) {
        /* Do actual lookup of cache item. */
        r = statuscache_lookup(mboxname, userid, statusitems, sdata);

        /* Seen/recent status uses "push" invalidation events from
         * seen_db.c.   This avoids needing to open cyrus.header to get
         * the mailbox uniqueid to open the seen db and get the
         * unseen_mtime and recentuid.
         */

        if (!r) {
            syslog(LOG_DEBUG, "statuscache, '%s', '%s', '0x%02x', 'yes'",
                   mboxname, userid, statusitems);
            return 0;
        }

        syslog(LOG_DEBUG, "statuscache, '%s', '%s', '0x%02x', 'no'",
               mboxname, userid, statusitems);
    }

    /* Missing or invalid cache entry */
    r = mailbox_open_irl(mboxname, &mailbox);
    if (r) return r;

    r = status_load_mailbox(mailbox, userid, statusitems, sdata);

    /* cache the new value while unlocking */
    if (!r) mailbox_unlock_index(mailbox, sdata);
    mailbox_close(&mailbox);

    return r;
}

EXPORTED int status_lookup_mbentry(const mbentry_t *mbentry, const char *userid,
                                  unsigned statusitems, struct statusdata *sdata)
{
    // check if we can get everything we need from the mbentry
    status_fill_mbentry(mbentry, sdata);
    if ((sdata->statusitems & statusitems) == statusitems)
        return 0;

    return status_lookup_internal(mbentry->name, userid, statusitems, sdata);
}

EXPORTED int status_lookup_mboxname(const char *mboxname, const char *userid,
                                    unsigned statusitems, struct statusdata *sdata)
{
    // we want an mbentry first, just in case we can get everything from there
    if (statusitems & STATUS_MAILBOXID) {
        mbentry_t *mbentry = NULL;
        int r = mboxlist_lookup_allow_all(mboxname, &mbentry, NULL);
        if (r) return r;
        r = status_lookup_mbentry(mbentry, userid, statusitems, sdata);
        mboxlist_entry_free(&mbentry);
        return r;
    }

    return status_lookup_internal(mboxname, userid, statusitems, sdata);
}


// this one has literally no smarts at all
EXPORTED int status_lookup_mbname(const mbname_t *mbname, const char *userid,
                                  unsigned statusitems, struct statusdata *sdata)
{
    return status_lookup_mboxname(mbname_intname(mbname), userid, statusitems, sdata);
}

/*
 * Performs a STATUS command on an open mailbox
 */
EXPORTED int status_lookup_mailbox(struct mailbox *mailbox, const char *userid,
                                   unsigned statusitems, struct statusdata *sdata)
{
    // check if we already have all the data we need (includes any possible mbentry)
    status_fill_mailbox(mailbox, sdata);
    if ((sdata->statusitems & statusitems) == statusitems)
        return 0;

    /* Check status cache if possible */
    if (config_getswitch(IMAPOPT_STATUSCACHE)) {
        /* Do actual lookup of cache item. */
        int r = statuscache_lookup(mailbox_name(mailbox), userid, statusitems, sdata);

        /* Seen/recent status uses "push" invalidation events from
         * seen_db.c.   This avoids needing to open cyrus.header to get
         * the mailbox uniqueid to open the seen db and get the
         * unseen_mtime and recentuid.
         */

        if (!r) {
            syslog(LOG_DEBUG, "statuscache, '%s', '%s', '0x%02x', 'yes'",
                   mailbox_name(mailbox), userid, statusitems);
            return 0;
        }

        syslog(LOG_DEBUG, "statuscache, '%s', '%s', '0x%02x', 'no'",
               mailbox_name(mailbox), userid, statusitems);
    }

    return status_load_mailbox(mailbox, userid, statusitems, sdata);
}
