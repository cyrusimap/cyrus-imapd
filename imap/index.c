/* index.c -- Routines for dealing with the index file in the imapd
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
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sysexits.h>
#include <syslog.h>
#include <ctype.h>
#include <stdlib.h>

#ifdef USE_HTTPD
/* For iCalendar indexing */
#include <libical/ical.h>
#include "vcard_support.h"
#endif

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "assert.h"
#include "backend.h"
#include "charset.h"
#include "conversations.h"
#include "dlist.h"
#include "hash.h"
#include "hashu64.h"
#include "http_client.h"
#include "jmap_util.h"
#include "global.h"
#include "times.h"
#include "imapd.h"
#include "lsort.h"
#include "mailbox.h"
#include "map.h"
#include "message.h"
#include "msgrecord.h"
#include "parseaddr.h"
#include "search_engines.h"
#include "search_query.h"
#include "seen.h"
#include "statuscache.h"
#include "strhash.h"
#include "user.h"
#include "util.h"
#include "xstats.h"
#include "ptrarray.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

#include "index.h"
#include "sync_log.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

EXPORTED unsigned client_capa;

static struct extractor_ctx *index_text_extractor = NULL;

/* Forward declarations */
static void index_refresh_locked(struct index_state *state);
static void index_tellexists(struct index_state *state);
static int index_lock(struct index_state *state, int readonly);
static void index_unlock(struct index_state *state);

struct index_modified_flags {
    int added_flags;
    bit32 added_system_flags;
    bit32 added_user_flags[MAX_USER_FLAGS/32];
    int removed_flags;
    bit32 removed_system_flags;
    bit32 removed_user_flags[MAX_USER_FLAGS/32];
};

static int index_writeseen(struct index_state *state);
static void index_fetchmsg(struct index_state *state,
                    const struct buf *msg,
                    unsigned offset, unsigned size,
                    unsigned start_octet, unsigned octet_count);
static int index_fetchsection(struct index_state *state, const char *resp,
                              const struct buf *msg,
                              char *section, struct body *body, unsigned size,
                              unsigned start_octet, unsigned octet_count);

static void index_fetchfsection(struct index_state *state,
                                const char *msg_base, unsigned long msg_size,
                                struct fieldlist *fsection,
                                struct body *body,
                                unsigned start_octet, unsigned octet_count);
static char *index_readheader(const char *msg_base, unsigned long msg_size,
                              unsigned offset, unsigned size);
static void index_fetchheader(struct index_state *state,
                              const char *msg_base, unsigned long msg_size,
                              unsigned size,
                              const strarray_t *headers,
                              const strarray_t *headers_not);
static void index_fetchcacheheader(struct index_state *state, struct index_record *record,
                                   const strarray_t *headers, unsigned start_octet,
                                   unsigned octet_count);
static void index_listflags(struct index_state *state);
static void index_fetchflags(struct index_state *state, uint32_t msgno);

static int index_copysetup(struct index_state *state, uint32_t msgno,
                           struct copyargs *copyargs);
static int index_storeflag(struct index_state *state,
                           struct index_modified_flags *modified_flags,
                           uint32_t msgno, msgrecord_t *msgrec,
                           struct storeargs *storeargs);
static int index_store_annotation(struct index_state *state, uint32_t msgno,
                           msgrecord_t *mrw, struct storeargs *storeargs,
                           int *dirty);
static int index_fetchreply(struct index_state *state, uint32_t msgno,
                            const struct fetchargs *fetchargs);
static void index_printflags(struct index_state *state, uint32_t msgno,
                             int usinguid, int printmodseq);
static char *get_localpart_addr(const char *header);
static char *get_displayname(const char *header);
static char *index_extract_subject(const char *subj, size_t len, int *is_refwd);
static char *_index_extract_subject(char *s, int *is_refwd);
static void index_get_ids(MsgData *msgdata,
                          char *envtokens[], const char *headers, unsigned size);

static int index_sort_compare(MsgData *md1, MsgData *md2,
                              const struct sortcrit *call_data);

static void *index_thread_getnext(Thread *thread);
static void index_thread_setnext(Thread *thread, Thread *next);
static int index_thread_compare(Thread *t1, Thread *t2,
                                const struct sortcrit *call_data);
static void index_thread_orderedsubj(struct index_state *state,
                                     unsigned *msgno_list, unsigned int nmsg,
                                     int usinguid);
static void index_thread_sort(Thread *root, const struct sortcrit *sortcrit);
static void index_thread_print(struct index_state *state,
                               Thread *threads, int usinguid);
static void index_thread_references(struct index_state *state,
                                    unsigned *msgno_list, unsigned int nmsg,
                                    int usinguid);
static void index_thread_refs(struct index_state *state,
                              unsigned *msgno_list, unsigned int nmsg,
                              int usinguid);

static seqset_t *_parse_sequence(struct index_state *state,
                                      const char *sequence, int usinguid);
static void massage_header(char *hdr);

/* NOTE: Make sure these are listed in CAPABILITY_STRING */
static const struct thread_algorithm thread_algs[] = {
    { "ORDEREDSUBJECT", index_thread_orderedsubj },
    { "REFERENCES", index_thread_references },
    { "REFS", index_thread_refs },
    { NULL, NULL }
};

EXPORTED int index_reload_record(struct index_state *state,
                                 uint32_t msgno,
                                 struct index_record *record)
{
    struct index_map *im = &state->map[msgno-1];
    int r = 0;
    int i;

    memset(record, 0, sizeof(struct index_record));
    if (!im->recno) {
        /* doh, gotta just fill in what we know */
        record->uid = im->uid;
    }
    else {
        record->recno = im->recno;
        record->uid = im->uid;
        r = mailbox_reload_index_record_dirty(state->mailbox, record);
    }
    /* NOTE: we have released the cyrus.index lock at this point, but are
     * still holding the mailbox name relock.  This means nobody can rewrite
     * the file under us - so the offsets are still guaranteed to be correct,
     * and all the immutable fields are unchanged.  That said, we can get a
     * read of a partially updated record which contains an invalid checksum
     * due to incomplete concurrent changes to mutable fields.  That's why we
     * used the _dirty API which ignores checksums.
     * but other errors are still bad */
    if (r) return r;

    /* better be! */
    assert(record->uid == im->uid);

    /* restore mutable fields */
    record->modseq = im->modseq;
    record->system_flags = im->system_flags;
    record->internal_flags = im->internal_flags;
    record->cache_offset = im->cache_offset;
    for (i = 0; i < MAX_USER_FLAGS/32; i++)
        record->user_flags[i] = im->user_flags[i];

    return 0;
}

static int index_rewrite_record(struct index_state *state,
                                uint32_t msgno,
                                struct index_record *record,
                                int silent)
{
    struct index_map *im = &state->map[msgno-1];
    int i;

    assert(record->uid == im->uid);

    if (!silent) {
        int r = mailbox_rewrite_index_record(state->mailbox, record);
        if (r) return r;
    }

    /* update tracking of mutable fields */
    im->modseq = record->modseq;
    im->system_flags = record->system_flags;
    im->internal_flags = record->internal_flags;
    im->cache_offset = record->cache_offset;
    for (i = 0; i < MAX_USER_FLAGS/32; i++)
        im->user_flags[i] = record->user_flags[i];

    return 0;
}

EXPORTED void index_release(struct index_state *state)
{
    if (!state) return;

    message_unref(&state->m);
    if (state->mailbox) {
        mailbox_close(&state->mailbox);
        state->mailbox = NULL; /* should be done by close anyway */
    }
}
static struct sortcrit *the_sortcrit;

/*
 * A mailbox is about to be closed.
 */
EXPORTED void index_close(struct index_state **stateptr)
{
    unsigned i;
    struct index_state *state = *stateptr;

    if (!state) return;

    index_release(state);

    free(state->map);
    free(state->mboxname);
    free(state->userid);
    for (i = 0; i < MAX_USER_FLAGS; i++)
        free(state->flagname[i]);
    free(state);

    *stateptr = NULL;
}

/*
 * A new mailbox has been selected and already opened, map it into
 * memory and do the initial CHECK.
 */
EXPORTED int index_open_mailbox(struct mailbox *mailbox, struct index_init *init,
                                struct index_state **stateptr)
{
    int r;
    struct index_state *state = xzmalloc(sizeof(struct index_state));

    state->mailbox = mailbox;
    state->mboxname = xstrdup(mailbox_name(mailbox));

    if (init) {
        state->authstate = init->authstate;
        state->examining = init->examine_mode;
        state->out = init->out;
        state->userid = xstrdupnull(init->userid);
        state->want_dav = init->want_dav;
        state->want_mbtype = init->want_mbtype;
        state->want_expunged = init->want_expunged;

        state->myrights = cyrus_acl_myrights(init->authstate,
                                             mailbox_acl(state->mailbox));
        if (state->examining)
            state->myrights &= ~ACL_READ_WRITE;

        /* Only allow setting flags on \Scheduled mailbox */
        if (mboxname_isscheduledmailbox(mailbox_name(state->mailbox),
                                        mailbox_mbtype(state->mailbox))) {
            state->myrights &= ~(ACL_INSERT | ACL_POST |
                                 ACL_CREATE | ACL_DELETEMBOX |
                                 ACL_DELETEMSG | ACL_EXPUNGE);
        }

        state->internalseen = mailbox_internal_seen(state->mailbox,
                                                    state->userid);
    }

    if (mbtype_isa(mailbox_mbtype(state->mailbox)) != MBTYPE_EMAIL) {
        if (state->want_dav) {
            /* User logged in using imapmagicplus token "dav" */
        }
        else if (mbtype_isa(mailbox_mbtype(state->mailbox)) == state->want_mbtype) {
            /* Caller explicitly asks for this NONIMAP type */
        }
        else {
            r = IMAP_MAILBOX_BADTYPE;
            goto fail;
        }
    }

    /* initialise the index_state */
    index_refresh_locked(state);

    /* have to get the vanished list while we're still locked */
    if (init)
        init->vanishedlist = index_vanished(state, &init->vanished);

    index_unlock(state);

    *stateptr = state;

    return 0;

fail:
    free(state->mboxname);
    free(state->userid);
    free(state);
    return r;
}

/*
 * A new mailbox has been selected, map it into memory and do the
 * initial CHECK.
 */
EXPORTED int index_open(const char *name, struct index_init *init,
                        struct index_state **stateptr)
{
    int r;
    struct mailbox *mailbox = NULL;

    r = init && init->examine_mode ? mailbox_open_irl(name, &mailbox) :
                                     mailbox_open_iwl(name, &mailbox);
    if (r) return r;

    r = index_open_mailbox(mailbox, init, stateptr);
    if (r) mailbox_close(&mailbox);

    return r;
}

EXPORTED int index_expunge(struct index_state *state, char *sequence,
                  int need_deleted)
{
    int r;
    uint32_t msgno;
    struct index_map *im;
    seqset_t *seq = NULL;
    struct index_record record;
    int numexpunged = 0;
    struct mboxevent *mboxevent = NULL;
    modseq_t oldmodseq;

    r = index_lock(state, /*readonly*/0);
    if (r) return r;

    /* XXX - check if not mailbox->i.deleted count and need_deleted */
    seq = _parse_sequence(state, sequence, 1);

    mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);

    for (msgno = 1; msgno <= state->exists; msgno++) {
        im = &state->map[msgno-1];

        if (im->internal_flags & FLAG_INTERNAL_EXPUNGED)
            continue; /* already expunged */

        if (need_deleted && !(im->system_flags & FLAG_DELETED))
            continue; /* no \Deleted flag */

        /* if there is a sequence list, check it */
        if (sequence && !seqset_ismember(seq, im->uid))
            continue; /* not in the list */

        /* load first once we know we have to process this one */
        if (index_reload_record(state, msgno, &record))
            continue;

        oldmodseq = im->modseq;

        if (!im->isseen) {
            if (state->numunseen)
                state->numunseen--;
            else
                syslog(LOG_ERR, "IOERROR: numunseen underflow in expunge: %s %u",
                       state->mboxname, im->uid);
            im->isseen = 1;
        }

        if (im->isrecent) {
            if (state->numrecent)
                state->numrecent--;
            else
                syslog(LOG_ERR, "IOERROR: numrecent underflow in expunge: %s %u",
                       state->mboxname, im->uid);
            im->isrecent = 0;
        }

        /* set the flags */
        record.system_flags |= FLAG_DELETED;
        record.internal_flags |= FLAG_INTERNAL_EXPUNGED;
        numexpunged++;
        state->num_expunged++;

        r = index_rewrite_record(state, msgno, &record, /*silent*/0);
        if (r) break;

        /* avoid telling again (equivalent to STORE FLAGS.SILENT) */
        if (im->told_modseq == oldmodseq)
            im->told_modseq = im->modseq;

        mboxevent_extract_record(mboxevent, state->mailbox, &record);
    }

    seqset_free(&seq);

    mboxevent_extract_mailbox(mboxevent, state->mailbox);
    mboxevent_set_access(mboxevent, NULL, NULL, state->userid, mailbox_name(state->mailbox), 1);
    mboxevent_set_numunseen(mboxevent, state->mailbox, state->numunseen);

    /* unlock before responding */
    index_unlock(state);

    if (!r && (numexpunged > 0)) {
        syslog(LOG_NOTICE, "Expunged %d messages from %s",
               numexpunged, state->mboxname);
        /* send the MessageExpunge event notification for "immediate", "default"
         * and "delayed" expunge */
        mboxevent_notify(&mboxevent);
    }

    mboxevent_free(&mboxevent);

    return r;
}

static char *index_buildseen(struct index_state *state, const char *oldseenuids)
{
    seqset_t *outlist;
    uint32_t msgno;
    unsigned oldmax;
    struct index_map *im;
    char *out;

    outlist = seqset_init(0, SEQ_MERGE);
    for (msgno = 1; msgno <= state->exists; msgno++) {
        im = &state->map[msgno-1];
        seqset_add(outlist, im->uid, im->isseen);
    }

    /* there may be future already seen UIDs that this process isn't
     * allowed to know about, but we can't blat them either!  This is
     * a massive pain... */
    oldmax = seq_lastnum(oldseenuids);
    if (oldmax > state->last_uid) {
        seqset_t *seq = seqset_parse(oldseenuids, NULL, oldmax);
        uint32_t uid;

        /* for each future UID, copy the state in the old seenuids */
        for (uid = state->last_uid + 1; uid <= oldmax; uid++)
            seqset_add(outlist, uid, seqset_ismember(seq, uid));

        seqset_free(&seq);
    }

    out = seqset_cstring(outlist);
    seqset_free(&outlist);

    return out;
}

static int index_writeseen(struct index_state *state)
{
    int r;
    struct seen *seendb = NULL;
    struct seendata oldsd = SEENDATA_INITIALIZER;
    struct seendata sd = SEENDATA_INITIALIZER;
    struct mailbox *mailbox = state->mailbox;
    const char *userid = (mailbox->i.options & OPT_IMAP_SHAREDSEEN) ? "anyone" : state->userid;

    if (!state->seen_dirty)
        return 0;

    state->seen_dirty = 0;

    /* only examining, can't write any changes */
    if (state->examining)
        return 0;

    /* always dirty the mailbox, we may just be updating recent counts which doesn't bump the
     * modseq because Recent is all sorts of evil */
    mailbox_index_dirty(mailbox);

    /* already handled! Just update the header fields */
    if (state->internalseen) {
        mailbox->i.recenttime = time(0);
        if (mailbox->i.recentuid < state->last_uid)
            mailbox->i.recentuid = state->last_uid;
        return 0;
    }

    r = seen_open(userid, SEEN_CREATE, &seendb);
    if (r) return r;

    r = seen_lockread(seendb, mailbox_uniqueid(mailbox), &oldsd);
    if (r) {
        oldsd.lastread = 0;
        oldsd.lastuid = 0;
        oldsd.lastchange = 0;
        oldsd.seenuids = xstrdup("");
    }

    /* fields of interest... */
    sd.lastuid = oldsd.lastuid;
    sd.seenuids = index_buildseen(state, oldsd.seenuids);
    if (!sd.seenuids) sd.seenuids = xstrdup("");

    /* make comparison only catch some changes */
    sd.lastread = oldsd.lastread;
    sd.lastchange = oldsd.lastchange;

    /* update \Recent lowmark */
    if (sd.lastuid < state->last_uid)
        sd.lastuid = state->last_uid;

    /* only commit if interesting fields have changed */
    if (!seen_compare(&sd, &oldsd)) {
        sd.lastread = time(NULL);
        sd.lastchange = mailbox->i.last_appenddate;
        r = seen_write(seendb, mailbox_uniqueid(mailbox), &sd);
    }

    seen_close(&seendb);

    seen_freedata(&oldsd);
    seen_freedata(&sd);

    return r;
}

/* caller must free the list with seqset_free() when done */
static seqset_t *_readseen(struct index_state *state, unsigned *recentuid)
{
    struct mailbox *mailbox = state->mailbox;
    seqset_t *seenlist = NULL;

    /* Obtain seen information */
    if (state->internalseen) {
        *recentuid = mailbox->i.recentuid;
    }
    else if (state->userid) {
        struct seen *seendb = NULL;
        struct seendata sd = SEENDATA_INITIALIZER;
        const char *userid = (mailbox->i.options & OPT_IMAP_SHAREDSEEN) ? "anyone" : state->userid;
        int r;

        r = seen_open(userid, SEEN_CREATE, &seendb);
        if (!r) r = seen_read(seendb, mailbox_uniqueid(mailbox), &sd);
        seen_close(&seendb);

        /* handle no seen DB gracefully */
        if (r) {
            *recentuid = mailbox->i.last_uid;
            prot_printf(state->out, "* OK (seen state failure) %s: %s\r\n",
                   error_message(IMAP_NO_CHECKPRESERVE), error_message(r));
            syslog(LOG_ERR, "Could not open seen state for %s (%s)",
                   userid, error_message(r));
        }
        else {
            *recentuid = sd.lastuid;
            seenlist = seqset_parse(sd.seenuids, NULL, *recentuid);
            seen_freedata(&sd);
        }
    }
    else {
        *recentuid = mailbox->i.last_uid; /* nothing is recent! */
    }

    return seenlist;
}

static void index_refresh_locked(struct index_state *state)
{
    struct mailbox *mailbox = state->mailbox;
    const message_t *msg;
    uint32_t msgno = 1;
    uint32_t firstnotseen = 0;
    uint32_t numrecent = 0;
    uint32_t numunseen = 0;
    uint32_t num_expunged = 0;
    uint32_t recentuid = 0;
    modseq_t delayed_modseq = 0;
    struct index_map *im;
    uint32_t need_records;
    seqset_t *seenlist;
    int i;

    /* need to start by having enough space for the entire index state
     * before telling of any expunges (which happens after this refresh
     * if the command allows it).  In the update case, where there's
     * already a map, we have to theoretically fit the number that existed
     * last time plus however many new records might be unEXPUNGEd on the
     * end */

    need_records = state->want_expunged ? mailbox->i.num_records : mailbox->i.exists;
    if (state->last_uid) {
        need_records = state->exists + (mailbox->i.last_uid - state->last_uid);
    }

    /* make sure we have space */
    if (need_records >= state->mapsize) {
        state->mapsize = (need_records | 0xff) + 1; /* round up 1-256 */
        state->map = xrealloc(state->map,
                              state->mapsize * sizeof(struct index_map));
    }

    seenlist = _readseen(state, &recentuid);

    /* walk through all records */
    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        im = &state->map[msgno-1];
        while (msgno <= state->exists && im->uid < record->uid) {
            /* NOTE: this same logic is repeated below for messages
             * past the end of recno (repack removing the trailing
             * records).  Make sure to keep them in sync */
            if (!(im->internal_flags & FLAG_INTERNAL_EXPUNGED)) {
                /* we don't even know the modseq of when it was wiped,
                 * but we can be sure it's since the last given highestmodseq,
                 * so simulate the lowest possible value.  This is fine for
                 * our told_modseq logic, and doesn't have to be exact because
                 * QRESYNC/CONDSTORE clients will see deletedmodseq and fall
                 * back to the inefficient codepath anyway */
                im->modseq = state->highestmodseq + 1;
            }
            if (!delayed_modseq || im->modseq < delayed_modseq)
                delayed_modseq = im->modseq - 1;
            im->recno = 0;
            /* simulate expunged flag so we get an EXPUNGE response and
             * tell about unlinked so we don't get IO errors trying to
             * find the file */
            im->internal_flags |= FLAG_INTERNAL_EXPUNGED |
                FLAG_INTERNAL_UNLINKED;
            im = &state->map[msgno++];

            /* this one is expunged */
            num_expunged++;
        }

        /* expunged record not in map, can skip immediately.  It's
         * never been told to this connection, so it doesn't need to
         * get its own msgno */
        if (!state->want_expunged
            && (msgno > state->exists || record->uid < im->uid)
            && (record->internal_flags & FLAG_INTERNAL_EXPUNGED))
            continue;

        /* make sure our UID map is consistent */
        if (msgno <= state->exists) {
            assert(im->uid == record->uid);
        }
        else {
            memset(im, 0, sizeof(struct index_map));
            im->uid = record->uid;
        }

        /* copy all mutable fields */
        im->recno = record->recno;
        im->modseq = record->modseq;
        im->system_flags = record->system_flags;
        im->internal_flags = record->internal_flags;
        im->cache_offset = record->cache_offset;
        for (i = 0; i < MAX_USER_FLAGS/32; i++)
            im->user_flags[i] = record->user_flags[i];

        /* re-calculate seen flags */
        if (state->internalseen)
            im->isseen = (im->system_flags & FLAG_SEEN) ? 1 : 0;
        else
            im->isseen = seqset_ismember(seenlist, im->uid) ? 1 : 0;

        /* for expunged records, just track the modseq */
        if (im->internal_flags & FLAG_INTERNAL_EXPUNGED) {
            num_expunged++;
            /* http://www.rfc-editor.org/errata_search.php?rfc=5162
             * Errata ID: 1809 - if there are expunged records we
             * aren't telling about, need to make the highestmodseq
             * be one lower so the client can safely resync */
            if (!delayed_modseq || im->modseq < delayed_modseq)
                delayed_modseq = im->modseq - 1;
        }
        else {
            if (msgno > state->exists) {
                /* don't auto-tell new records */
                im->told_modseq = im->modseq;
                if (im->uid > recentuid) {
                    /* mark recent if it's newly being added to the index and also
                     * greater than the recentuid - ensures only one session gets
                     * the \Recent flag for any one message */
                    im->isrecent = 1;
                    state->seen_dirty = 1;
                }
                else
                    im->isrecent = 0;
            }

            /* track select values */
            if (!im->isseen) {
                numunseen++;
                if (!firstnotseen)
                    firstnotseen = msgno;
            }
            if (im->isrecent) {
                numrecent++;
            }
        }

        /* make sure we don't overflow the memory we mapped */
        if (msgno > state->mapsize) {
            char buf[2048];
            sprintf(buf, "Exists wrong %u %u %u %u", msgno,
                    state->mapsize, mailbox->i.exists, mailbox->i.num_records);
            fatal(buf, EX_IOERR);
        }

        msgno++;
    }
    mailbox_iter_done(&iter);

    /* may be trailing records which need to be considered for
     * delayed_modseq purposes, and to get the count right for
     * later expunge processing */
    im = &state->map[msgno-1];
    while (msgno <= state->exists) {
        /* this is the same logic as the block above in the main loop,
         * see comments up there, and make sure the blocks are kept
         * in sync! */
        if (!(im->internal_flags & FLAG_INTERNAL_EXPUNGED))
            im->modseq = state->highestmodseq + 1;
        if (!delayed_modseq || im->modseq < delayed_modseq)
            delayed_modseq = im->modseq - 1;
        im->recno = 0;
        im->internal_flags |= FLAG_INTERNAL_EXPUNGED | FLAG_INTERNAL_UNLINKED;
        im = &state->map[msgno++];
        num_expunged++;
    }

    seqset_free(&seenlist);

    /* update the header tracking data */
    state->oldexists = state->exists; /* we last knew about this many */
    state->exists = msgno - 1; /* we actually got this many */
    state->delayed_modseq = delayed_modseq;
    state->oldhighestmodseq = state->highestmodseq;
    state->highestmodseq = mailbox->i.highestmodseq;
    state->generation = mailbox->i.generation_no;
    state->uidvalidity = mailbox->i.uidvalidity;
    state->last_uid = mailbox->i.last_uid;
    state->num_records = mailbox->i.num_records;
    state->num_expunged = num_expunged;
    state->firstnotseen = firstnotseen;
    state->numunseen = numunseen;
    state->numrecent = numrecent;
}

EXPORTED modseq_t index_highestmodseq(struct index_state *state)
{
    if (state->delayed_modseq)
        return state->delayed_modseq;
    return state->highestmodseq;
}

EXPORTED void index_select(struct index_state *state, struct index_init *init)
{
    index_tellexists(state);

    /* always print flags */
    index_checkflags(state, 1, 1);

    if (state->firstnotseen)
        prot_printf(state->out, "* OK [UNSEEN %u] Ok\r\n",
                    state->firstnotseen);
    prot_printf(state->out, "* OK [UIDVALIDITY %u] Ok\r\n",
                state->mailbox->i.uidvalidity);
    prot_printf(state->out, "* OK [UIDNEXT %lu] Ok\r\n",
                state->last_uid + 1);

    /* RFC 7162 */
    prot_printf(state->out, "* OK [HIGHESTMODSEQ " MODSEQ_FMT "] Ok\r\n",
                state->highestmodseq);

    /* RFC 8474 */
    prot_printf(state->out, "* OK [MAILBOXID (%s)] Ok\r\n",
                mailbox_uniqueid(state->mailbox));

    /* RFC 4467 */
    prot_printf(state->out, "* OK [URLMECH INTERNAL] Ok\r\n");

    /*
     * RFC 5257.  Note that we must report a maximum size for annotations
     * but we don't enforce any such limit, so pick a "large" number.
     */
    prot_printf(state->out, "* OK [ANNOTATIONS %u] Ok\r\n", 64*1024);

    if (init->vanishedlist) {
        char *vanished;
        const char *sequence = NULL;
        seqset_t *seq = NULL;
        struct index_map *im;
        uint32_t msgno;

        /* QRESYNC response:
         * UID FETCH seq FLAGS (CHANGEDSINCE modseq VANISHED)
          */

        vanished = seqset_cstring(init->vanishedlist);
        if (vanished) {
            prot_printf(state->out, "* VANISHED (EARLIER) %s\r\n", vanished);
            free(vanished);
        }

        sequence = init->vanished.sequence;
        if (sequence) seq = _parse_sequence(state, sequence, 1);
        for (msgno = 1; msgno <= state->exists; msgno++) {
            im = &state->map[msgno-1];
            if (sequence && !seqset_ismember(seq, im->uid))
                continue;
            if (im->modseq <= init->vanished.modseq)
                continue;
            index_printflags(state, msgno, 1, 0);
        }
        seqset_free(&seq);
    }
}

/*
 * Check for and report updates
 */
EXPORTED int index_check(struct index_state *state, int usinguid, int printuid)
{
    int r;

    if (!state) return 0;

    /* we don't write any records in here, but we want to write the recentuid if
     * there were new emails delivered... */
    r = index_lock(state, /*readonly*/0);

    /* Check for deleted mailbox  */
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Mailbox has been (re)moved */
        if (config_getswitch(IMAPOPT_DISCONNECT_ON_VANISHED_MAILBOX)) {
            syslog(LOG_WARNING,
                   "Mailbox %s has been (re)moved out from under client",
                   state->mboxname);
            mailbox_close(&state->mailbox);
            fatal("Mailbox has been (re)moved", EX_IOERR);
        }

        if (state->exists && (client_capa & CAPA_QRESYNC)) {
            /* XXX - is it OK to just expand to entire possible range? */
            prot_printf(state->out, "* VANISHED 1:%lu\r\n", state->last_uid);
        }
        else {
            int exists;
            for (exists = state->exists; exists > 0; exists--) {
                prot_printf(state->out, "* 1 EXPUNGE\r\n");
            }
        }

        state->exists = 0;
        return IMAP_MAILBOX_NONEXISTENT;
    }

    if (r) return r;

    index_tellchanges(state, usinguid, printuid, 0);
    index_unlock(state);

    return r;
}

/*
 * Perform UID FETCH (VANISHED) on a sequence.
 */
seqset_t *index_vanished(struct index_state *state,
                              struct vanished_params *params)
{
    struct mailbox *mailbox = state->mailbox;
    seqset_t *outlist;
    seqset_t *seq;

    /* check uidvalidity match */
    if (params->uidvalidity_is_max) {
        if (params->uidvalidity < mailbox->i.uidvalidity) return NULL;
    }
    else {
        if (params->uidvalidity != mailbox->i.uidvalidity) return NULL;
    }

    /* No recently expunged messages */
    if (params->modseq >= state->highestmodseq) return NULL;

    outlist = seqset_init(0, SEQ_SPARSE);
    seq = _parse_sequence(state, params->sequence, 1);

    /* XXX - use match_seq and match_uid */

    if (params->modseq >= mailbox->i.deletedmodseq) {
        const message_t *msg;
        /* all records are significant */
        /* List only expunged UIDs with MODSEQ > requested */
        struct mailbox_iter *iter = mailbox_iter_init(mailbox, params->modseq, 0);
        while ((msg = mailbox_iter_step(iter))) {
            const struct index_record *record = msg_record(msg);
            if (!(record->internal_flags & FLAG_INTERNAL_EXPUNGED))
                continue;
            if (!params->sequence || seqset_ismember(seq, record->uid))
                seqset_add(outlist, record->uid, 1);
        }
        mailbox_iter_done(&iter);
    }
    else {
        unsigned prevuid = 0;
        seqset_t *msgnolist;
        seqset_t *uidlist;
        uint32_t msgno;
        unsigned uid;

        syslog(LOG_NOTICE, "inefficient qresync ("
               MODSEQ_FMT " > " MODSEQ_FMT ") %s",
               mailbox->i.deletedmodseq, params->modseq,
               mailbox_name(mailbox));

        /* use the sequence to uid mapping provided by the client to
         * skip over any initial matches - see RFC 5162 section 3.1 */
        if (params->match_seq && params->match_uid) {
            msgnolist = _parse_sequence(state, params->match_seq, 0);
            uidlist = _parse_sequence(state, params->match_uid, 1);
            while ((msgno = seqset_getnext(msgnolist)) != 0) {
                uid = seqset_getnext(uidlist);
                /* first non-match, we'll start here */
                if (state->map[msgno-1].uid != uid)
                    break;
                /* ok, they matched - so we can start after here */
                prevuid = uid;
            }
            seqset_free(&msgnolist);
            seqset_free(&uidlist);
        }

        const message_t *msg;
        struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
        mailbox_iter_startuid(iter, prevuid);

        /* possible efficiency improvement - use "seq_getnext" on seq
         * to avoid incrementing through every single number for prevuid.
         * Only really an issue if there's a giant block of thousands of
         * expunged messages.  Only likely to be seen in the wild if
         * last_uid winds up being bumped up a few million by a bug... */

        /* for the rest of the mailbox, we're just going to have to assume
         * every record in the requested range which DOESN'T exist has been
         * expunged, so build a complete sequence */
        while ((msg = mailbox_iter_step(iter))) {
            const struct index_record *record = msg_record(msg);
            while (++prevuid < record->uid) {
                if (!params->sequence || seqset_ismember(seq, prevuid))
                    seqset_add(outlist, prevuid, 1);
            }
            prevuid = record->uid;
        }
        mailbox_iter_done(&iter);

        /* include the space past the final record up to last_uid as well */
        while (++prevuid <= mailbox->i.last_uid) {
            if (!params->sequence || seqset_ismember(seq, prevuid))
                seqset_add(outlist, prevuid, 1);
        }
    }

    seqset_free(&seq);

    return outlist;
}

static int _fetch_setseen(struct index_state *state,
                          struct mboxevent *mboxevent,
                          uint32_t msgno)
{
    struct index_map *im = &state->map[msgno-1];
    struct index_record record;
    int r;

    /* already seen */
    if (im->isseen)
        return 0;

    /* no rights to change it */
    if (!(state->myrights & ACL_SETSEEN))
        return 0;

    r = index_reload_record(state, msgno, &record);
    if (r) return r;

    /* track changes internally */
    if (state->numunseen)
        state->numunseen--;
    else
        syslog(LOG_ERR, "IOERROR: unseen underflow on setseen: %s %u",
               state->mboxname, im->uid);
    state->seen_dirty = 1;
    im->isseen = 1;

    /* also store in the record if it's internal seen */
    if (state->internalseen)
        record.system_flags |= FLAG_SEEN;

    /* need to bump modseq anyway, so always rewrite it */
    r = index_rewrite_record(state, msgno, &record, /*silent*/0);
    if (r) return r;

    mboxevent_extract_record(mboxevent, state->mailbox, &record);

    /* RFC 2060 says:
     * The \Seen flag is implicitly set; if this causes
     * the flags to change they SHOULD be included as part
     * of the FETCH responses.   This is handled later by
     * always including flags if the modseq has changed.
     */

    return 0;
}

/* seq can be NULL - means "ALL" */
EXPORTED void index_fetchresponses(struct index_state *state,
                          seqset_t *seq,
                          int usinguid,
                          const struct fetchargs *fetchargs,
                          int *fetchedsomething)
{
    uint32_t msgno, start, end;
    struct index_map *im;
    int fetched = 0;
    annotate_db_t *annot_db = NULL;

    /* Keep an open reference on the per-mailbox db to avoid
     * doing too many slow database opens during the fetch */
    if ((fetchargs->fetchitems & FETCH_ANNOTATION))
        annotate_getdb(state->mailbox, &annot_db);

    start = 1;
    end = state->exists;

    /* if we haven't told exists and we're fetching something past the end of the
     * old size, we need to tell exists now...
     * https://github.com/cyrusimap/cyrus-imapd/issues/1967
     */
    if (state->exists != state->oldexists) index_tellexists(state);

    /* if the modseq hasn't changed then there will be no unsolicited updates
     * to send, so we only need to scan messages inside the sequence range.
     * https://github.com/cyrusimap/cyrus-imapd/issues/1971
     */
    if (state->oldhighestmodseq == state->highestmodseq) {
        /* compress the search range down if a sequence was given */
        if (seq) {
            unsigned first = seqset_first(seq);
            unsigned last = seqset_last(seq);

            if (usinguid) {
                if (first > 1)
                    start = index_finduid(state, first);
                if (first == last)
                    end = start;
                else if (last < state->last_uid)
                    end = index_finduid(state, last);
            }
            else {
                start = first;
                end = last;
            }
        }
    }

    /* make sure we didn't go outside the range! */
    if (start < 1) start = 1;
    if (end > state->exists) end = state->exists;

    for (msgno = start; msgno <= end; msgno++) {
        im = &state->map[msgno-1];
        if (seq && !seqset_ismember(seq, usinguid ? im->uid : msgno)) {
            if (im->told_modseq !=0 && im->modseq > im->told_modseq)
                index_printflags(state, msgno, usinguid, 0);
            continue;
        }

        if (index_fetchreply(state, msgno, fetchargs))
            break;
        fetched = 1;
    }

    /* Update oldhighestmodseq, ensuring we don't have unsolicited updates */
    state->oldhighestmodseq = state->highestmodseq;

    if (fetchedsomething) *fetchedsomething = fetched;
    annotate_putdb(&annot_db);
}

/*
 * Perform a FETCH-related command on a sequence.
 * Fetchedsomething argument is 0 if nothing was fetched, 1 if something was
 * fetched.  (A fetch command that fetches nothing is not a valid fetch
 * command.)
 */
EXPORTED int index_fetch(struct index_state *state,
                const char *sequence,
                int usinguid,
                const struct fetchargs *fetchargs,
                int *fetchedsomething)
{
    seqset_t *seq;
    seqset_t *vanishedlist = NULL;
    struct index_map *im;
    uint32_t msgno;
    int r;
    struct mboxevent *mboxevent = NULL;

    r = index_lock(state, /*readonly*/0);  // can't be readonly because of FETCH_SETSEEN
    if (r) return r;

    seq = _parse_sequence(state, sequence, usinguid);

    /* set the \Seen flag if necessary - while we still have the lock */
    if (fetchargs->fetchitems & FETCH_SETSEEN && !state->examining && state->myrights & ACL_SETSEEN) {
        mboxevent = mboxevent_new(EVENT_MESSAGE_READ);

        for (msgno = 1; msgno <= state->exists; msgno++) {
            im = &state->map[msgno-1];
            if (!seqset_ismember(seq, usinguid ? im->uid : msgno))
                continue;
            r = _fetch_setseen(state, mboxevent, msgno);
            if (r) break;
        }

        mboxevent_extract_mailbox(mboxevent, state->mailbox);
        mboxevent_set_access(mboxevent, NULL, NULL, state->userid, mailbox_name(state->mailbox), 1);
        mboxevent_set_numunseen(mboxevent, state->mailbox,
                                state->numunseen);
    }

    if (fetchargs->vanished) {
        struct vanished_params v;
        v.sequence = sequence;
        v.uidvalidity = state->mailbox->i.uidvalidity;
        v.modseq = fetchargs->changedsince;
        v.match_seq = fetchargs->match_seq;
        v.match_uid = fetchargs->match_uid;
        /* XXX - return error unless usinguid? */
        vanishedlist = index_vanished(state, &v);
    }

    index_unlock(state);

    /* send MessageRead event notification for successfully rewritten records */
    mboxevent_notify(&mboxevent);
    mboxevent_free(&mboxevent);

    index_checkflags(state, 1, 0);

    if (seqset_first(vanishedlist)) {
        char *vanished = seqset_cstring(vanishedlist);
        prot_printf(state->out, "* VANISHED (EARLIER) %s\r\n", vanished);
        free(vanished);
    }

    seqset_free(&vanishedlist);

    index_fetchresponses(state, seq, usinguid, fetchargs, fetchedsomething);

    seqset_free(&seq);

    index_tellchanges(state, usinguid, usinguid, 0);

    return r;
}

/*
 * Perform a STORE command on a sequence
 */
EXPORTED int index_store(struct index_state *state, char *sequence,
                         struct storeargs *storeargs)
{
    struct mailbox *mailbox;
    int i, r = 0;
    uint32_t msgno;
    int userflag;
    seqset_t *seq;
    struct index_map *im;
    const strarray_t *flags = &storeargs->flags;
    struct mboxevent *mboxevents = NULL;
    struct mboxevent *flagsset = NULL, *flagsclear = NULL;
    struct index_modified_flags modified_flags;
    struct index_record record;

    if (storeargs->operation == STORE_ADD_FLAGS
        || storeargs->operation == STORE_REMOVE_FLAGS)
    {
        int did_limit_flags = 0;

        /* Quoth RFC 4314:
        *  STORE operation SHOULD NOT fail if the user has rights to modify
        *  at least one flag specified in the STORE, as the tagged NO
        *  response to a STORE command is not handled very well by deployed
        *  clients.
        */
        if (storeargs->seen && !(state->myrights & ACL_SETSEEN)) {
            syslog(LOG_DEBUG, "%s: no permission to alter \\Seen, removing from set",
                            __func__);
            storeargs->seen = 0;
            did_limit_flags = 1;
        }

        if ((storeargs->system_flags & FLAG_DELETED)
            && !(state->myrights & ACL_DELETEMSG))
        {
            syslog(LOG_DEBUG, "%s: no permission to alter \\Deleted, removing from set",
                            __func__);
            storeargs->system_flags &= ~FLAG_DELETED;
            did_limit_flags = 1;
        }

        if (((storeargs->system_flags & ~FLAG_DELETED) || flags->count)
            && !(state->myrights & ACL_WRITE))
        {
            syslog(LOG_DEBUG, "%s: no permission to alter other flags, removing from set",
                            __func__);
            storeargs->system_flags &= FLAG_DELETED; /* turn off everything BUT deleted */
            strarray_truncate(&storeargs->flags, 0);
            did_limit_flags = 1;
        }

        if (did_limit_flags
            && !storeargs->seen
            && !storeargs->system_flags
            && !flags->count)
        {
            syslog(LOG_DEBUG, "%s: no permitted flags left, rejecting", __func__);
            return IMAP_PERMISSION_DENIED;
        }
    }
    else {
        if ((storeargs->seen && !(state->myrights & ACL_SETSEEN)) ||
            ((storeargs->system_flags & FLAG_DELETED) &&
            !(state->myrights & ACL_DELETEMSG)) ||
            (((storeargs->system_flags & ~FLAG_DELETED) || flags->count) &&
            !(state->myrights & ACL_WRITE))) {
            return IMAP_PERMISSION_DENIED;
        }
    }

    r = index_lock(state, /*readonly*/0);
    if (r) return r;

    mailbox = state->mailbox;

    seq = _parse_sequence(state, sequence, storeargs->usinguid);

    for (i = 0; i < flags->count ; i++) {
        r = mailbox_user_flag(mailbox, flags->data[i], &userflag, 1);
        if (r) goto out;
        storeargs->user_flags[userflag/32] |= 1<<(userflag&31);
    }

    storeargs->update_time = time((time_t *)0);

    for (msgno = 1; msgno <= state->exists; msgno++) {
        im = &state->map[msgno-1];
        if (!seqset_ismember(seq, storeargs->usinguid ? im->uid : msgno))
            continue;

        /* if it's expunged already, skip it now */
        if ((im->internal_flags & FLAG_INTERNAL_EXPUNGED))
            continue;

        /* if it's changed already, skip it now */
        if (im->modseq > storeargs->unchangedsince) {
            if (!storeargs->modified) {
                uint32_t maxval = (storeargs->usinguid ?
                                   state->last_uid : state->exists);
                storeargs->modified = seqset_init(maxval, SEQ_SPARSE);
            }
            seqset_add(storeargs->modified,
                       (storeargs->usinguid ? im->uid : msgno),
                       /*ismember*/1);
            continue;
        }

        /* TODO(rsto): we need to keep index_reload_record here until we
         * can make sure that the index map doesn't contain uncommitted
         * changes for this msgno. See the comments in index_reload_record
         * on how it releases the cyrus.index lock in the middle of action */
        r = index_reload_record(state, msgno, &record);
        if (r) goto out;

        msgrecord_t *msgrec = msgrecord_from_index_record(state->mailbox, &record);

        switch (storeargs->operation) {
        case STORE_ADD_FLAGS:
        case STORE_REMOVE_FLAGS:
        case STORE_REPLACE_FLAGS:
            r = index_storeflag(state, &modified_flags, msgno, msgrec, storeargs);
            if (r) goto doneloop;

            // nothing to do?
            if (!(modified_flags.added_flags | modified_flags.removed_flags))
                goto doneloop;

            r = msgrecord_rewrite(msgrec);
            if (r) goto doneloop;

            if (modified_flags.added_flags) {
                if (flagsset == NULL)
                    flagsset = mboxevent_enqueue(EVENT_FLAGS_SET, &mboxevents);

                mboxevent_add_flags(flagsset, mailbox->h.flagname,
                                    modified_flags.added_system_flags,
                                    modified_flags.added_user_flags);
                mboxevent_extract_msgrecord(flagsset, msgrec);
            }
            if (modified_flags.removed_flags) {
                if (flagsclear == NULL)
                    flagsclear = mboxevent_enqueue(EVENT_FLAGS_CLEAR, &mboxevents);

                mboxevent_add_flags(flagsclear, mailbox->h.flagname,
                                    modified_flags.removed_system_flags,
                                    modified_flags.removed_user_flags);
                mboxevent_extract_msgrecord(flagsclear, msgrec);
            }
            break;

        case STORE_ANNOTATION: {
            int dirty = 0;
            r = index_store_annotation(state, msgno, msgrec, storeargs, &dirty);
            if (r) goto doneloop;
            if (!dirty) goto doneloop;

            // rewrite message
            r = msgrecord_rewrite(msgrec);
            if (r) goto doneloop;

            // XXX mboxevents?

            break;
        }

        default:
            r = IMAP_INTERNAL;
            break;
        }
        if (r) goto doneloop;

        /* msgrecord_rewrite already took care of rewriting the index_record,
         * but we want to stay up to date of the changes in the index_map.
         * Pass the silent flag to index_rewrite_record. */
        r = msgrecord_get_index_record(msgrec, &record);
        if (r) goto doneloop;
        r = index_rewrite_record(state, msgno, &record, /*silent*/1);

doneloop:
        msgrecord_unref(&msgrec);
        if (r) goto out;
    }


    /* let mboxevent_notify split FlagsSet into MessageRead, MessageTrash
     * and FlagsSet events */
    mboxevent_extract_mailbox(flagsset, mailbox);
    mboxevent_set_numunseen(flagsset, mailbox, state->numunseen);
    mboxevent_set_access(flagsset, NULL, NULL, state->userid, mailbox_name(state->mailbox), 1);

    mboxevent_extract_mailbox(flagsclear, mailbox);
    mboxevent_set_access(flagsclear, NULL, NULL, state->userid, mailbox_name(state->mailbox), 1);
    mboxevent_set_numunseen(flagsclear, mailbox, state->numunseen);

    mboxevent_notify(&mboxevents);

out:
    mboxevent_freequeue(&mboxevents);
    if (storeargs->operation == STORE_ANNOTATION && r)
        annotate_state_abort(&mailbox->annot_state);
    seqset_free(&seq);
    index_unlock(state);
    index_tellchanges(state, storeargs->usinguid, storeargs->usinguid,
                      (storeargs->unchangedsince != ~0ULL));

    return r;
}

static void prefetch_messages(struct index_state *state,
                              seqset_t *seq,
                              int usinguid)
{
    struct mailbox *mailbox = state->mailbox;
    struct index_map *im;
    uint32_t msgno;
    const char *fname;
    struct index_record record;

    syslog(LOG_ERR, "Prefetching initial parts of messages");

    for (msgno = 1; msgno <= state->exists; msgno++) {
        im = &state->map[msgno-1];
        if (!seqset_ismember(seq, usinguid ? im->uid : msgno))
            continue;

        if (index_reload_record(state, msgno, &record))
            continue;

        fname = mailbox_record_fname(mailbox, &record);
        if (!fname)
            continue;

        warmup_file(fname, 0, 16384);
    }
}


/*
 * Perform the XRUNANNOTATOR command which runs the
 * annotator callout for each message in the given sequence.
 */
EXPORTED int index_run_annotator(struct index_state *state,
                        const char *sequence, int usinguid,
                        struct namespace *namespace, int isadmin)
{
    struct index_record record;
    seqset_t *seq = NULL;
    struct index_map *im;
    uint32_t msgno;
    struct appendstate as;
    msgrecord_t *msgrec = NULL;
    int r = 0;

    /* We do the acl check here rather than in append_setup_mbox()
     * to account for the EXAMINE command where state->myrights has
     * fewer rights than the ACL actually grants */
    if (!(state->myrights & (ACL_WRITE|ACL_ANNOTATEMSG)))
        return IMAP_PERMISSION_DENIED;

    if (!config_getstring(IMAPOPT_ANNOTATION_CALLOUT))
        return 0;

    r = index_lock(state, /*readonly*/0);
    if (r) return r;

    r = append_setup_mbox(&as, state->mailbox,
                          state->userid, state->authstate,
                          0, NULL, namespace, isadmin, 0);
    if (r) goto out;

    seq = _parse_sequence(state, sequence, usinguid);
    if (!seq) goto out;

    prefetch_messages(state, seq, usinguid);

    for (msgno = 1; msgno <= state->exists; msgno++) {
        im = &state->map[msgno-1];
        if (!seqset_ismember(seq, usinguid ? im->uid : msgno))
            continue;

        /* if it's expunged already, skip it now */
        if ((im->internal_flags & FLAG_INTERNAL_EXPUNGED))
            continue;

        r = index_reload_record(state, msgno, &record);
        if (r) goto out;

        msgrec = msgrecord_from_index_record(state->mailbox, &record);

        r = append_run_annotator(&as, msgrec);
        if (r) goto out;

        /* msgrecord_rewrite already took care of rewriting the index_record,
         * but we want to stay up to date of the changes in the index_map.
         * Pass the silent flag to index_rewrite_record. */
        r = msgrecord_get_index_record(msgrec, &record);
        if (r) goto out;
        r = index_rewrite_record(state, msgno, &record, /*silent*/1);
        if (r) goto out;

        msgrecord_unref(&msgrec);
    }

out:
    seqset_free(&seq);

    if (msgrec) msgrecord_unref(&msgrec);
    if (!r) {
        r = append_commit(&as);
    }
    else {
        append_abort(&as);
    }
    index_unlock(state);

    index_tellchanges(state, usinguid, usinguid, 1);

    return r;
}

EXPORTED int index_warmup(struct mboxlist_entry *mbentry,
                          unsigned int warmup_flags,
                          seqset_t *uids)
{
    const char *fname = NULL;
    char *userid = NULL;
    char *tofree1 = NULL;
    char *tofree2 = NULL;
    unsigned int uid;
    strarray_t files = STRARRAY_INITIALIZER;
    int i;
    int r = 0;

    if (warmup_flags & WARMUP_INDEX) {
        fname = mbentry_metapath(mbentry, META_INDEX, 0);
        r = warmup_file(fname, 0, 0);
        if (r) goto out;
    }
    if (warmup_flags & WARMUP_CONVERSATIONS) {
        if (config_getswitch(IMAPOPT_CONVERSATIONS)) {
            fname = tofree1 = conversations_getmboxpath(mbentry->name);
            r = warmup_file(fname, 0, 0);
            if (r) goto out;
        }
    }
    if (warmup_flags & WARMUP_ANNOTATIONS) {
        fname = mbentry_metapath(mbentry, META_ANNOTATIONS, 0);
        r = warmup_file(fname, 0, 0);
        if (r) goto out;
    }
    if (warmup_flags & WARMUP_SEARCH) {
        userid = mboxname_to_userid(mbentry->name);
        r = search_list_files(userid, &files);
        if (r) goto out;
        for (i = 0 ; i < files.count ; i++) {
            fname = strarray_nth(&files, i);
            r = warmup_file(fname, 0, 0);
            if (r) goto out;
        }
    }
    while ((uid = seqset_getnext(uids))) {
        fname = mbentry_datapath(mbentry, uid);
        r = warmup_file(fname, 0, 0);
        if (r) goto out;
    }

out:
    if (r == ENOENT || r == ENOSYS)
        r = 0;
    if (r)
        syslog(LOG_ERR, "IOERROR: unable to warmup file %s: %s",
                fname, error_message(r));
    free(userid);
    free(tofree1);
    free(tofree2);
    strarray_fini(&files);
    return r;
}

static void build_query(search_builder_t *bx,
                        search_expr_t *e,
                        int remove,
                        int *nmatchesp)
{
    search_expr_t *child;
    int bop = -1;

    switch (e->op) {

    case SEOP_NOT:
        bop = SEARCH_OP_NOT;
        break;

    case SEOP_AND:
        bop = SEARCH_OP_AND;
        break;

    case SEOP_OR:
        bop = SEARCH_OP_OR;
        break;

    case SEOP_FUZZYMATCH:
        if (e->attr && e->attr->part >= 0) {
            bx->match(bx, e->attr->part, e->value.s);
            (*nmatchesp)++;
            if (remove && e->attr->part != SEARCH_PART_HEADERS) {
                /*
                 * We're relying on the search engine to correctly
                 * find matching messages, so we don't need to
                 * keep this node in the expression tree anymore.
                 * Rather than remove it we neuter it.
                 */
                search_expr_neutralise(e);
            }
        }
        return;

    default:
        return;
    }

    if (e->children) {
        assert(bop != -1);
        bx->begin_boolean(bx, bop);
        for (child = e->children ; child ; child = child->next)
            build_query(bx, child, remove, nmatchesp);
        bx->end_boolean(bx, bop);
    }
}

static int index_prefilter_messages(unsigned* msg_list,
                                    struct index_state *state,
                                    struct searchargs *searchargs __attribute((unused)))
{
    unsigned int msgno;

    xstats_inc(SEARCH_TRIVIAL);

    /* Just put in all possible messages. This falls back to Cyrus' default
     * search. */

    for (msgno = 1; msgno <= state->exists; msgno++)
        msg_list[msgno-1] = msgno;

    return state->exists;
}

static int index_scan_work(const char *s, unsigned long len,
                           const char *match, unsigned long min)
{
    while (len > min) {
        if (!strncasecmp(s, match, min)) return(1);
        s++;
        len--;
    }
    return(0);
}

/*
 * Guts of the SCAN command, lifted from _index_search()
 *
 * Returns 1 if we get a hit, otherwise returns 0.
 */
EXPORTED int index_scan(struct index_state *state, const char *contents)
{
    unsigned *msgno_list;
    uint32_t msgno;
    int n = 0;
    int listindex;
    int listcount;
    struct searchargs searchargs;
    unsigned long length;
    struct mailbox *mailbox = state->mailbox;
    charset_t ascii = charset_lookupname("US-ASCII");

    if (!(contents && contents[0])) return(0);

    if (index_check(state, 0, 0))
        return 0;

    if (state->exists <= 0) return 0;

    length = strlen(contents);

    memset(&searchargs, 0, sizeof(struct searchargs));
    searchargs.root = search_expr_new(NULL, SEOP_MATCH);
    searchargs.root->attr = search_attr_find("text");

    /* Use US-ASCII to emulate fgrep */

    searchargs.root->value.s = charset_convert(contents, ascii, charset_flags);

    search_expr_internalise(state, searchargs.root);

    msgno_list = (unsigned *) xmalloc(state->exists * sizeof(unsigned));

    listcount = index_prefilter_messages(msgno_list, state, &searchargs);

    for (listindex = 0; !n && listindex < listcount; listindex++) {
        if (!(listindex % 128) && cmd_cancelled(/*insearch*/1))
            break;
        struct buf buf = BUF_INITIALIZER;
        struct index_record record;
        msgno = msgno_list[listindex];

        if (index_reload_record(state, msgno, &record))
            continue;

        if (mailbox_map_record(mailbox, &record, &buf))
            continue;

        n += index_scan_work(buf.s, buf.len, contents, length);

        buf_free(&buf);
    }

    charset_free(&ascii);
    search_expr_free(searchargs.root);
    free(msgno_list);

    return n;
}

EXPORTED uint32_t index_getuid(struct index_state *state, uint32_t msgno)
{
    assert(msgno <= state->exists);
    return state->map[msgno-1].uid;
}

/* 'uid_list' is malloc'd string representing the hits from searchargs;
   returns number of hits */
EXPORTED int index_getuidsequence(struct index_state *state,
                         struct searchargs *searchargs,
                         unsigned **uid_list)
{
    search_query_t *query = NULL;
    search_folder_t *folder = NULL;
    int r;
    int n = 0;

    query = search_query_new(state, searchargs);
    r = search_query_run(query);
    if (r) goto out;
    folder = search_query_find_folder(query, index_mboxname(state));
    if (!folder) goto out;

    n = search_folder_get_array(folder, uid_list);

out:
    search_query_free(query);
    return n;
}

static int index_lock(struct index_state *state, int readonly)
{
    int r;

    if (state->mailbox) {
        if (state->examining || readonly) {
            r = mailbox_lock_index(state->mailbox, LOCK_SHARED);
            if (r) return r;
        }
        else {
            r = mailbox_lock_index(state->mailbox, LOCK_EXCLUSIVE);
            if (r) return r;
        }
    }
    else {
        if (state->examining || readonly) {
            r = mailbox_open_irl(state->mboxname, &state->mailbox);
            if (r) return r;
        }
        else {
            r = mailbox_open_iwl(state->mboxname, &state->mailbox);
            if (r) return r;
        }
    }

    /* if the UIDVALIDITY has changed, treat as a delete */
    if (state->mailbox->i.uidvalidity != state->uidvalidity) {
        mailbox_close(&state->mailbox);
        return IMAP_MAILBOX_NONEXISTENT;
    }

    /* if highestmodseq has changed or file is repacked, read updates */
    if (state->highestmodseq != state->mailbox->i.highestmodseq
        || state->generation != state->mailbox->i.generation_no)
        index_refresh_locked(state);

    return 0;
}

EXPORTED int index_status(struct index_state *state, struct statusdata *sdata)
{
    int r = index_lock(state, /*readonly*/1);
    if (r) return r;

    status_fill_mailbox(state->mailbox, sdata);
    status_fill_seen(state->userid, sdata, state->numrecent, state->numunseen);

    index_unlock(state);
    return 0;
}

EXPORTED int index_refresh(struct index_state *state)
{
    int r;

    r = index_lock(state, /*readonly*/1);  /* calls index_refresh_locked */
    if (r) return r;
    index_unlock(state);
    return 0;
}

static void index_unlock(struct index_state *state)
{
    // only update seen if we've got a writelocked mailbox
    if (mailbox_index_islocked(state->mailbox, 1))
        index_writeseen(state);  // XXX: errors?

    /* grab the latest modseq */
    state->highestmodseq = state->mailbox->i.highestmodseq;

    if (state->mailbox->i.dirty) {
        struct statusdata sdata = STATUSDATA_INIT;
        status_fill_mailbox(state->mailbox, &sdata);
        // we zero out recent data for everyone else
        status_fill_seen(state->userid, &sdata, /*recent*/0, state->numunseen);
        mailbox_unlock_index(state->mailbox, &sdata);
    }
    else {
        mailbox_unlock_index(state->mailbox, NULL);
    }
}

/*
 * RFC 4551 says:
 * If client specifies a MODSEQ criterion in a SEARCH command
 * and the server returns a non-empty SEARCH result, the server
 * MUST also append (to the end of the untagged SEARCH response)
 * the highest mod-sequence for all messages being returned.
 */
static int needs_modseq(const struct searchargs *searchargs,
                        const struct sortcrit *sortcrit)
{
    int i;

    if (search_expr_uses_attr(searchargs->root, "modseq"))
        return 1;

    if (sortcrit) {
        for (i = 0 ; sortcrit[i].key != SORT_SEQUENCE ; i++)
            if (sortcrit[i].key == SORT_MODSEQ)
                return 1;
    }

    return 0;
}

static void begin_esearch_response(struct index_state *state,
                                   struct searchargs *searchargs,
                                   int usinguid, search_folder_t *folder,
                                   int nmsg)

{
    /*
     * Implement RFC 4731 return options.
     */
    prot_printf(state->out, "* ESEARCH");
    if (searchargs->tag) {
        prot_printf(state->out, " (TAG \"%s\")", searchargs->tag);
    }
    /* RFC 4731: 3.1
     * An extended UID SEARCH command MUST cause an ESEARCH response with
     * the UID indicator present. */
    if (usinguid) prot_printf(state->out, " UID");
    if (searchargs->returnopts & SEARCH_RETURN_COUNT) {
        prot_printf(state->out, " COUNT %u", nmsg);
    }
    if (nmsg) {
        if (searchargs->returnopts & SEARCH_RETURN_MIN) {
            prot_printf(state->out, " MIN %u", search_folder_get_min(folder));
        }
        if (searchargs->returnopts & SEARCH_RETURN_MAX) {
            prot_printf(state->out, " MAX %u", search_folder_get_max(folder));
        }
    }
}

static void esearch_modseq_response(struct index_state *state,
                                    struct searchargs *searchargs,
                                    search_folder_t *folder,
                                    modseq_t highestmodseq)
{
    if (!highestmodseq) return;

    // restrict modseq to the returned items only
    if (searchargs->returnopts == SEARCH_RETURN_MIN) {
        highestmodseq = search_folder_get_first_modseq(folder);
    }
    if (searchargs->returnopts == SEARCH_RETURN_MAX) {
        highestmodseq = search_folder_get_last_modseq(folder);
    }
    if (searchargs->returnopts == (SEARCH_RETURN_MIN|SEARCH_RETURN_MAX)) {
        /* special case min and max should be greatest of the two */
        uint64_t last = search_folder_get_last_modseq(folder);
        highestmodseq = search_folder_get_first_modseq(folder);
        if (last > highestmodseq) highestmodseq = last;
    }

    if (highestmodseq)
        prot_printf(state->out, " MODSEQ " MODSEQ_FMT, highestmodseq);
}

/*
 * Performs a SEARCH command.
 * This is a wrapper around the search_query API which simply prints the results.
 */
EXPORTED int index_search(struct index_state *state,
                          struct searchargs *searchargs,
                          int usinguid)
{
    search_query_t *query = NULL;
    search_folder_t *folder;
    int nmsg = 0;
    int i;
    modseq_t highestmodseq = 0;
    int r;

    /* update the index */
    if (index_check(state, 0, 0))
        return 0;

    highestmodseq = needs_modseq(searchargs, NULL);

    query = search_query_new(state, searchargs);
    r = search_query_run(query);
    if (r) goto out;        /* search failed */
    folder = search_query_find_folder(query, index_mboxname(state));

    if (folder) {
        if (!usinguid)
            search_folder_use_msn(folder, state);
        if (highestmodseq)
            highestmodseq = search_folder_get_highest_modseq(folder);
        nmsg = search_folder_get_count(folder);
    }
    else
        nmsg = 0;

    if (searchargs->returnopts) {
        begin_esearch_response(state, searchargs, usinguid, folder, nmsg);

        if (nmsg) {
            if (searchargs->returnopts & SEARCH_RETURN_ALL) {
                seqset_t *seq = search_folder_get_seqset(folder);

                if (seqset_first(seq)) {
                    char *str = seqset_cstring(seq);
                    prot_printf(state->out, " ALL %s", str);
                    free(str);
                }

                seqset_free(&seq);
            }
            if (searchargs->returnopts & SEARCH_RETURN_RELEVANCY) {
                prot_printf(state->out, " RELEVANCY (");
                for (i = 0; i < nmsg; i++) {
                    if (i) prot_putc(' ', state->out);
                    /* for now all messages have relevancy=100 */
                    prot_printf(state->out, "%u", 100);
                }
                prot_printf(state->out, ")");
            }

            esearch_modseq_response(state, searchargs, folder, highestmodseq);
        }
    }
    else {
        prot_printf(state->out, "* SEARCH");

        if (nmsg) {
            search_folder_foreach(folder, i) {
                prot_printf(state->out, " %u", i);
            }
        }

        if (highestmodseq)
            prot_printf(state->out, " (MODSEQ " MODSEQ_FMT ")", highestmodseq);
    }

    prot_printf(state->out, "\r\n");

out:
    search_query_free(query);
    return nmsg;
}

/*
 * Performs a SORT command
 */
EXPORTED int index_sort(struct index_state *state,
               const struct sortcrit *sortcrit,
               struct searchargs *searchargs, int usinguid)
{
    int i;
    int nmsg = 0;
    modseq_t highestmodseq = 0;
    search_query_t *query = NULL;
    search_folder_t *folder = NULL;
    int r;

    /* update the index */
    if (index_check(state, 0, 0))
        return 0;

    highestmodseq = needs_modseq(searchargs, NULL);

    /* Search for messages based on the given criteria */
    query = search_query_new(state, searchargs);
    query->sortcrit = sortcrit;
    r = search_query_run(query);
    if (r) goto out;        /* search failed */
    folder = search_query_find_folder(query, index_mboxname(state));

    if (folder) {
        if (highestmodseq)
            highestmodseq = search_folder_get_highest_modseq(folder);
        nmsg = search_folder_get_count(folder);
    }

    if (searchargs->returnopts) {
        begin_esearch_response(state, searchargs, usinguid, folder, nmsg);

        if (nmsg) {
            if (searchargs->returnopts & SEARCH_RETURN_ALL) {
                seqset_t *seq = seqset_init(0, SEQ_SPARSE);

                for (i = 0 ; i < query->merged_msgdata.count ; i++) {
                    MsgData *md = ptrarray_nth(&query->merged_msgdata, i);
                    seqset_add(seq, usinguid ? md->uid : md->msgno, 1);
                }

                if (seqset_first(seq)) {
                    char *str = seqset_cstring(seq);
                    prot_printf(state->out, " ALL %s", str);
                    free(str);
                }

                seqset_free(&seq);
            }
            if (searchargs->returnopts & SEARCH_RETURN_RELEVANCY) {
                prot_printf(state->out, " RELEVANCY (");
                for (i = 0; i < nmsg; i++) {
                    if (i) prot_putc(' ', state->out);
                    /* for now all messages have relevancy=100 */
                    prot_printf(state->out, "%u", 100);
                }
                prot_printf(state->out, ")");
            }

            esearch_modseq_response(state, searchargs, folder, highestmodseq);
        }
    }
    else {
        prot_printf(state->out, "* SORT");

        if (nmsg) {
            /* Output the sorted messages */
            for (i = 0 ; i < query->merged_msgdata.count ; i++) {
                MsgData *md = ptrarray_nth(&query->merged_msgdata, i);
                prot_printf(state->out, " %u",
                            (usinguid ? md->uid : md->msgno));
            }
        }

        if (highestmodseq)
            prot_printf(state->out, " (MODSEQ " MODSEQ_FMT ")", highestmodseq);
    }

    prot_printf(state->out, "\r\n");

out:
    search_query_free(query);
    return nmsg;
}

#define UNPREDICTABLE       (-1)
static int search_predict_total(struct index_state *state,
                                struct conversations_state *cstate,
                                const struct searchargs *searchargs,
                                int conversations,
                                modseq_t *xconvmodseqp)
{
    conv_status_t convstatus = CONV_STATUS_INIT;
    uint32_t exists;

    if (conversations) {
        conversation_getstatus(cstate,
                               CONV_FOLDER_KEY_MBOX(cstate, state->mailbox),
                               &convstatus);
        /* always grab xconvmodseq, so we report a growing
         * highestmodseq to all callers */
        if (xconvmodseqp) *xconvmodseqp = convstatus.threadmodseq;
        exists = convstatus.threadexists;
    }
    else {
        if (xconvmodseqp) *xconvmodseqp = state->highestmodseq;
        /* we may be in xconvupdates, where expunged are present */
        exists = state->exists - state->num_expunged;
    }

    switch (search_expr_get_countability(searchargs->root)) {
    case SEC_EXISTS:
        return exists;

    case SEC_EXISTS|SEC_NOT:
        return 0;

    /* we don't try to optimise searches on \Recent */
    case SEC_SEEN:
        assert(state->exists >= state->numunseen);
        return state->exists - state->numunseen;

    case SEC_SEEN|SEC_NOT:
        return state->numunseen;

    case SEC_CONVSEEN:
        assert(conversations);
        assert(convstatus.threadexists >= convstatus.threadunseen);
        return convstatus.threadexists - convstatus.threadunseen;

    case SEC_CONVSEEN|SEC_NOT:
        assert(conversations);
        return convstatus.threadunseen;

    default:
        return UNPREDICTABLE;
    }
}

/*
 * Performs a XCONVSORT command
 */
EXPORTED int index_convsort(struct index_state *state,
                            struct sortcrit *sortcrit,
                            struct searchargs *searchargs,
                            const struct windowargs *windowargs)
{
    MsgData **msgdata = NULL;
    unsigned int mi;
    modseq_t xconvmodseq = 0;
    int i;
    hashu64_table seen_cids = HASHU64_TABLE_INITIALIZER;
    uint32_t pos = 0;
    int found_anchor = 0;
    uint32_t anchor_pos = 0;
    uint32_t first_pos = 0;
    unsigned int ninwindow = 0;
    ptrarray_t results = PTRARRAY_INITIALIZER;
    int total = 0;
    int r = 0;
    struct conversations_state *cstate = NULL;

    assert(windowargs);
    assert(!windowargs->changedsince);
    assert(!windowargs->upto);

    /* Check the client didn't specify MULTIANCHOR. */
    if (windowargs->anchor && windowargs->anchorfolder)
        return IMAP_PROTOCOL_BAD_PARAMETERS;

    /* make sure \Deleted messages are expunged.  Will also lock the
     * mailbox state and read any new information */
    r = index_expunge(state, NULL, 1);
    if (r) return r;

    if (windowargs->conversations) {
        cstate = conversations_get_mbox(index_mboxname(state));
        if (!cstate)
            return IMAP_INTERNAL;
    }

    search_expr_internalise(state, searchargs->root);

    /* this works both with and without conversations */
    total = search_predict_total(state, cstate, searchargs,
                                windowargs->conversations,
                                &xconvmodseq);
    /* not going to match anything? bonus */
    if (!total)
        goto out;

    construct_hashu64_table(&seen_cids, state->exists/4+4, 0);

    /* Create/load the msgdata array.
     * load data for ALL messages always.  We sort before searching so
     * we can take advantage of the window arguments to stop searching
     * early */
    msgdata = index_msgdata_load(state, NULL, state->exists, sortcrit,
                                 windowargs->anchor, &found_anchor);
    if (windowargs->anchor && !found_anchor) {
        r = IMAP_ANCHOR_NOT_FOUND;
        goto out;
    }

    /* Sort the messages based on the given criteria */
    index_msgdata_sort(msgdata, state->exists, sortcrit);

    /* One pass through the message list */
    for (mi = 0 ; mi < state->exists ; mi++) {
        MsgData *msg = msgdata[mi];
        struct index_map *im = &state->map[msg->msgno-1];

        /* can happen if we didn't "tellchanges" yet */
        if (im->internal_flags & FLAG_INTERNAL_EXPUNGED)
            continue;

        /* run the search program against all messages */
        if (!index_search_evaluate(state, searchargs->root, msg->msgno))
            continue;

        /* figure out whether this message is an exemplar */
        if (windowargs->conversations) {
            /* in conversations mode => only the first message seen
             * with each unique CID is an exemplar */
            if (hashu64_lookup(msg->cid, &seen_cids))
                continue;
            hashu64_insert(msg->cid, (void *)1, &seen_cids);
        }
        /* else not in conversations mode => all messages are exemplars */

        pos++;

        if (!anchor_pos &&
            windowargs->anchor == msg->uid) {
            /* we've found the anchor's position, rejoice! */
            anchor_pos = pos;
        }

        if (windowargs->anchor) {
            if (!anchor_pos)
                continue;
            if (pos < anchor_pos + windowargs->offset)
                continue;
        }
        else if (windowargs->position) {
            if (pos < windowargs->position)
                continue;
        }
        if (windowargs->limit &&
            ++ninwindow > windowargs->limit) {
            if (total == UNPREDICTABLE) {
                /* the total was not predictable, so we need to keep
                 * going over the whole list to count it */
                continue;
            }
            break;
        }

        if (!first_pos)
            first_pos = pos;
        ptrarray_append(&results, msg);
    }

    if (total == UNPREDICTABLE) {
        /* the total was not predictable prima facie */
        total = pos;
    }

    if (windowargs->anchor && !anchor_pos) {
        /* the anchor was present but not an exemplar */
        assert(results.count == 0);
        r = IMAP_ANCHOR_NOT_FOUND;
        goto out;
    }

    /* Print the resulting list */

    /* Yes, we could use a seqset here, but apparently the most common
     * sort order seen in the field is reverse date, which is basically
     * the worst case for seqset.  So we don't bother */
    if (results.count) {
        prot_printf(state->out, "* SORT");  /* uids */
        for (i = 0 ; i < results.count ; i++) {
            MsgData *msg = results.data[i];
            prot_printf(state->out, " %u", msg->uid);
        }
        prot_printf(state->out, "\r\n");
    }

out:
    if (!r) {
        if (first_pos)
            prot_printf(state->out, "* OK [POSITION %u]\r\n", first_pos);

        prot_printf(state->out, "* OK [HIGHESTMODSEQ " MODSEQ_FMT "]\r\n",
                    MAX(xconvmodseq, state->mailbox->i.highestmodseq));
        prot_printf(state->out, "* OK [UIDVALIDITY %u]\r\n",
                    state->mailbox->i.uidvalidity);
        prot_printf(state->out, "* OK [UIDNEXT %u]\r\n",
                    state->mailbox->i.last_uid + 1);
        prot_printf(state->out, "* OK [TOTAL %u]\r\n",
                    total);
    }

    /* free all our temporary data */
    index_msgdata_free(msgdata, state->exists);
    ptrarray_fini(&results);
    free_hashu64_table(&seen_cids, NULL);

    return r;
}

/*
 * Performs a XCONVMULTISORT command
 */
EXPORTED int index_convmultisort(struct index_state *state,
                                 struct sortcrit *sortcrit,
                                 struct searchargs *searchargs,
                                 const struct windowargs *windowargs)
{
    int mi;
    int fi;
    int i;
    hashu64_table seen_cids = HASHU64_TABLE_INITIALIZER;
    uint32_t pos = 0;
    uint32_t anchor_pos = 0;
    uint32_t first_pos = 0;
    unsigned int ninwindow = 0;
    /* array of (arrays of msgdata* with the same CID) */
    ptrarray_t results = PTRARRAY_INITIALIZER;
    /* Used as a placeholder which provides a non-NULL entry in the
     * seen_cids hashtable for conversations which are outside the
     * specified window. */
    ptrarray_t dummy_response;
    int total = UNPREDICTABLE;
    int r = 0;
    struct mboxname_counters counters;
    search_query_t *query = NULL;
    search_folder_t *folder = NULL;
    search_folder_t *anchor_folder = NULL;

    assert(windowargs);
    assert(!windowargs->changedsince);
    assert(!windowargs->upto);

    /* Client needs to have specified MULTIANCHOR which includes
     * the folder name instead of just ANCHOR.  Check that here
     * 'cos it's easier than doing so during parsing */
    if (windowargs->anchor && !windowargs->anchorfolder)
        return IMAP_PROTOCOL_BAD_PARAMETERS;

    /* make sure folder still exists and map in data */
    r = index_refresh(state);
    if (r) return r;

    r = mboxname_read_counters(index_mboxname(state), &counters);
    if (r) return r;
    query = search_query_new(state, searchargs);
    query->multiple = 1;
    query->need_ids = 1;
    query->need_expunge = 1;
    query->sortcrit = sortcrit;

    r = search_query_run(query);
    if (r) return r;

    if (windowargs->anchorfolder) {
        anchor_folder = search_query_find_folder(query, windowargs->anchorfolder);
        if (!anchor_folder) {
            r = IMAP_ANCHOR_NOT_FOUND;
            goto out;
        }
    }

    /* going to need to do conversation-level breakdown */
    if (windowargs->conversations)
        construct_hashu64_table(&seen_cids, query->merged_msgdata.count/4+4, 0);
    /* no need */
    else
        total = query->merged_msgdata.count;

    /* Another pass through the merged message list */
    for (mi = 0 ; mi < query->merged_msgdata.count ; mi++) {
        MsgData *md = ptrarray_nth(&query->merged_msgdata, mi);
        ptrarray_t *response = NULL;

        /* figure out whether this message is an exemplar */
        if (windowargs->conversations) {
            response = hashu64_lookup(md->cid, &seen_cids);
            /* in conversations mode => only the first message seen
             * with each unique CID is an exemplar */
            if (response) {
                if (response != &dummy_response)
                    ptrarray_append(response, md);
                continue;
            }
            hashu64_insert(md->cid, &dummy_response, &seen_cids);
        }
        /* else not in conversations mode => all messages are exemplars */

        pos++;

        if (!anchor_pos &&
            windowargs->anchor == md->uid &&
            anchor_folder == md->folder) {
            /* we've found the anchor's position, rejoice! */
            anchor_pos = pos;
        }

        if (windowargs->anchor) {
            if (!anchor_pos)
                continue;
            if (pos < anchor_pos + windowargs->offset)
                continue;
        }
        else if (windowargs->position) {
            if (pos < windowargs->position)
                continue;
        }
        if (windowargs->limit &&
            ++ninwindow > windowargs->limit) {
            if (total == UNPREDICTABLE) {
                /* the total was not predictable, so we need to keep
                 * going over the whole list to count it */
                continue;
            }
            break;
        }

        if (!first_pos)
            first_pos = pos;

        /* the message is the exemplar of a conversation which is inside
         * the specified window, so record a non-dummy seen_cids entry
         * and a results entry */
        response = ptrarray_new();
        ptrarray_push(response, md);
        ptrarray_push(&results, response);

        if (windowargs->conversations) {
            hashu64_insert(md->cid, response, &seen_cids);
        }
    }

    if (total == UNPREDICTABLE) {
        /* the total was not predictable prima facie */
        total = pos;
    }

    if (windowargs->anchor && !anchor_pos) {
        /* the anchor was not found */
        assert(results.count == 0);
        r = IMAP_ANCHOR_NOT_FOUND;
        goto out;
    }

    /* Print the resulting list */

    xstats_add(SEARCH_RESULT, results.count);
    if (results.count) {
        /* The untagged response would be XCONVMULTISORT but
         * Mail::IMAPTalk has an undocumented hack whereby any untagged
         * response matching /sort/i is assumed to be a sequence of
         * numeric uids.  Meh. */
        prot_printf(state->out, "* XCONVMULTI (");
        for (fi = 0 ; fi < query->folders_by_id.count ; fi++) {
            folder = ptrarray_nth(&query->folders_by_id, fi);

            char *extname = mboxname_to_external(folder->mboxname, searchargs->namespace, searchargs->userid);

            if (fi)
                prot_printf(state->out, " ");
            prot_printf(state->out, "(");
            prot_printstring(state->out, extname);
            prot_printf(state->out, " %u)", folder->uidvalidity);
            free(extname);
        }
        prot_printf(state->out, ") (");
        for (i = 0 ; i < results.count ; i++) {
            ptrarray_t *response = ptrarray_nth(&results, i);
            int j;
            if (i)
                prot_printf(state->out, " ");
            for (j = 0; j < response->count; j++) {
                MsgData *md = ptrarray_nth(response, j);
                if (!j)
                    prot_printf(state->out, "(%s" , conversation_id_encode(md->cid));
                prot_printf(state->out, " (%u %u)", md->folder->id, md->uid);
            }
            prot_printf(state->out, ")");
        }
        prot_printf(state->out, ")\r\n");
    }

out:
    if (!r) {
        if (first_pos)
            prot_printf(state->out, "* OK [POSITION %u]\r\n", first_pos);

        prot_printf(state->out, "* OK [HIGHESTMODSEQ " MODSEQ_FMT "]\r\n",
                    counters.mailmodseq);
#if 0
        prot_printf(state->out, "* OK [UIDNEXT %u]\r\n",
                    state->mailbox->i.last_uid + 1);
#endif
        prot_printf(state->out, "* OK [TOTAL %u]\r\n",
                    total);
    }

    /* free all our temporary data */
    free_hashu64_table(&seen_cids, NULL);
    for (i = 0 ; i < results.count ; i++) {
        ptrarray_t *response = ptrarray_nth(&results, i);
        ptrarray_free(response);
    }
    ptrarray_fini(&results);
    search_query_free(query);

    return r;
}

struct snippet_rock {
    struct protstream *out;
    struct namespace *namespace;
    const char *userid;
};

static int emit_snippet(struct mailbox *mailbox, uint32_t uid,
                        int part, const char *partid __attribute__((unused)),
                        const char *snippet, void *rock)
{
    struct snippet_rock *sr = (struct snippet_rock *)rock;
    const char *partname = search_part_as_string(part);

    if (!partname) return 0;

    char *extname = mboxname_to_external(mailbox_name(mailbox), sr->namespace, sr->userid);

    prot_printf(sr->out, "* SNIPPET ");
    prot_printstring(sr->out, extname);
    prot_printf(sr->out, " %u %u %s ", mailbox->i.uidvalidity, uid, partname);
    prot_printstring(sr->out, snippet);
    prot_printf(sr->out, "\r\n");

    free(extname);

    return 0;
}

EXPORTED int index_snippets(struct index_state *state,
                            const struct snippetargs *snippetargs,
                            struct searchargs *searchargs)
{
    void *intquery = NULL;
    search_builder_t *bx = NULL;
    search_text_receiver_t *rx = NULL;
    struct mailbox *mailbox = NULL;
    int i;
    int r = 0;
    int nmatches = 0;
    struct snippet_rock srock;

    /* reload index */
    r = index_refresh(state);
    if (r) return r;

    bx = search_begin_search(state->mailbox, SEARCH_MULTIPLE);
    if (!bx) {
        r = IMAP_INTERNAL;
        goto out;
    }

    build_query(bx, searchargs->root, 0, &nmatches);
    if (!bx->get_internalised) goto out;
    intquery = bx->get_internalised(bx);
    search_end_search(bx);
    if (!intquery) goto out;

    srock.out = state->out;
    srock.namespace = searchargs->namespace;
    srock.userid = searchargs->userid;
    rx = search_begin_snippets(intquery, 0/*verbose*/, &default_snippet_markup,
                               emit_snippet, &srock);
    if (!rx) goto out;

    for ( ; snippetargs ; snippetargs = snippetargs->next) {

        mailbox = NULL;
        if (!strcmp(snippetargs->mboxname, index_mboxname(state))) {
            mailbox = state->mailbox;
        }
        else {
            r = mailbox_open_irl(snippetargs->mboxname, &mailbox);
            if (r) goto out;
            mailbox_unlock_index(mailbox, NULL);
        }

        if (snippetargs->uidvalidity &&
            snippetargs->uidvalidity != mailbox->i.uidvalidity) {
            r = IMAP_NOTFOUND;
            goto out;
        }

        r = rx->begin_mailbox(rx, mailbox, /*incremental*/0);

        for (i = 0 ; i < snippetargs->uids.count ; i++) {
            uint32_t uid = snippetargs->uids.data[i];
            struct index_record record;

            /* It's OK to do a dirty read, because we only care about
             * the UID of the message */
            r = mailbox_find_index_record(mailbox, uid, &record);
            if (r == IMAP_MAILBOX_CHECKSUM) r = 0;
            if (r) continue;

            if (state->m) message_set_from_record(mailbox, &record, state->m);
            else state->m = message_new_from_record(mailbox, &record);

            index_getsearchtext(state->m, NULL, rx, INDEX_GETSEARCHTEXT_SNIPPET);
        }

        r = rx->end_mailbox(rx, mailbox);
        if (r) goto out;
        if (mailbox != state->mailbox)
            mailbox_close(&mailbox);
    }

out:
    if (rx) search_end_snippets(rx);
    if (intquery) search_free_internalised(intquery);
    if (mailbox != state->mailbox)
        mailbox_close(&mailbox);
    return r;
}

static modseq_t get_modseq_of(MsgData *msg,
                              struct conversations_state *cstate)
{
    modseq_t modseq = 0;

    if (cstate) {
        conversation_get_modseq(cstate, msg->cid, &modseq);
        /* TODO: error handling dammit */
    } else {
        modseq = msg->modseq;
    }
    return modseq;
}

/*
 * Performs a XCONVUPDATES command
 */
EXPORTED int index_convupdates(struct index_state *state,
                      struct sortcrit *sortcrit,
                      struct searchargs *searchargs,
                      const struct windowargs *windowargs)
{
    MsgData **msgdata = NULL;
    modseq_t xconvmodseq = 0;
    unsigned int mi;
    int i;
    hashu64_table seen_cids = HASHU64_TABLE_INITIALIZER;
    hashu64_table old_seen_cids = HASHU64_TABLE_INITIALIZER;
    int32_t pos = 0;
    uint32_t upto_pos = 0;
    ptrarray_t added = PTRARRAY_INITIALIZER;
    ptrarray_t removed = PTRARRAY_INITIALIZER;
    ptrarray_t changed = PTRARRAY_INITIALIZER;
    int total = 0;
    struct conversations_state *cstate = NULL;
    int is_mutable = search_is_mutable(sortcrit, searchargs->root);
    int r = 0;

    assert(windowargs);
    assert(windowargs->changedsince);
    assert(windowargs->offset == 0);
    assert(!windowargs->position);

    /* make sure \Deleted messages are expunged.  Will also lock the
     * mailbox state and read any new information */
    r = index_expunge(state, NULL, 1);
    if (r) return r;

    if (windowargs->conversations) {
        cstate = conversations_get_mbox(index_mboxname(state));
        if (!cstate)
            return IMAP_INTERNAL;
    }

    search_expr_internalise(state, searchargs->root);

    total = search_predict_total(state, cstate, searchargs,
                                windowargs->conversations,
                                &xconvmodseq);
    /* If there are no current and no expunged messages, we won't
     * have any results at all and can short circuit the main loop;
     * note that is a righter criterion than for XCONVSORT. */
    if (!total && !state->exists)
        goto out;

    construct_hashu64_table(&seen_cids, state->exists/4+4, 0);
    construct_hashu64_table(&old_seen_cids, state->exists/4+4, 0);

    /* Create/load the msgdata array
     * initial list - load data for ALL messages always */
    msgdata = index_msgdata_load(state, NULL, state->exists, sortcrit, 0, NULL);

    /* Sort the messages based on the given criteria */
    index_msgdata_sort(msgdata, state->exists, sortcrit);

    /* Discover exemplars */
    for (mi = 0 ; mi < state->exists ; mi++) {
        MsgData *msg = msgdata[mi];
        struct index_map *im = &state->map[msg->msgno-1];
        int was_old_exemplar = 0;
        int is_new_exemplar = 0;
        int is_deleted = 0;
        int is_new = 0;
        int was_deleted = 0;
        int is_changed = 0;
        int in_search = 0;

        in_search = index_search_evaluate(state, searchargs->root, msg->msgno);
        is_deleted = !!(im->internal_flags & FLAG_INTERNAL_EXPUNGED);
        is_new = (im->uid >= windowargs->uidnext);
        was_deleted = is_deleted && (im->modseq <= windowargs->modseq);

        /* is this message a current exemplar? */
        if (!is_deleted &&
            in_search &&
            (!windowargs->conversations || !hashu64_lookup(msg->cid, &seen_cids))) {
            is_new_exemplar = 1;
            pos++;
            if (windowargs->conversations)
                hashu64_insert(msg->cid, (void *)1, &seen_cids);
        }

        /* optimisation for when the total is
         * not known but we've hit 'upto' */
        if (upto_pos)
            continue;

        modseq_t modseq = get_modseq_of(msg, cstate);
        is_changed = (modseq > windowargs->modseq);

        /* was this message an old exemplar, or in the case of mutable
         * searches, possible an old exemplar? */
        if (!is_new &&
            !was_deleted &&
            (in_search || (is_mutable && is_changed)) &&
            (!windowargs->conversations || !hashu64_lookup(msg->cid, &old_seen_cids))) {
            was_old_exemplar = 1;
            if (windowargs->conversations)
                hashu64_insert(msg->cid, (void *)1, &old_seen_cids);
        }

        if (was_old_exemplar && !is_new_exemplar) {
            ptrarray_push(&removed, msg);
        } else if (!was_old_exemplar && is_new_exemplar) {
            msg->msgno = pos;   /* hacky: reuse ->msgno for pos */
            ptrarray_push(&added, msg);
        } else if (was_old_exemplar && is_new_exemplar) {
            if (is_changed) {
                ptrarray_push(&changed, msg);
                if (is_mutable) {
                    /* is the search is mutable, we're in a whole world of
                     * uncertainty about the client's state, so we just
                     * report the exemplar in all three lists and let the
                     * client sort it out. */
                    ptrarray_push(&removed, msg);
                    msg->msgno = pos;   /* hacky: reuse ->msgno for pos */
                    ptrarray_push(&added, msg);
                }
            }
        }

        /* if this is the last message the client cares about ('upto')
         * then we can break early...unless its a mutable search or
         * we need to keep going to calculate an accurate total */
        if (!is_mutable &&
            !upto_pos &&
            msg->uid == windowargs->upto) {
            if (total != UNPREDICTABLE)
                break;
            upto_pos = pos;
        }
    }

    /* unlike 'anchor', the case of not finding 'upto' is not an error */

    if (total == UNPREDICTABLE) {
        /* the total was not predictable prima facie */
        total = pos;
    }

    /* Print the resulting lists */

    if (added.count) {
        prot_printf(state->out, "* ADDED"); /* (uid pos) tuples */
        for (i = 0 ; i < added.count ; i++) {
            MsgData *msg = added.data[i];
            prot_printf(state->out, " (%u %u)",
                        msg->uid, msg->msgno);
        }
        prot_printf(state->out, "\r\n");
    }

    if (removed.count) {
        prot_printf(state->out, "* REMOVED");   /* uids */
        for (i = 0 ; i < removed.count ; i++) {
            MsgData *msg = removed.data[i];
            prot_printf(state->out, " %u", msg->uid);
        }
        prot_printf(state->out, "\r\n");
    }

    if (changed.count) {
        prot_printf(state->out, "* CHANGED");   /* cids or uids */
        for (i = 0 ; i < changed.count ; i++) {
            MsgData *msg = changed.data[i];
            if (windowargs->conversations)
                prot_printf(state->out, " %s",
                        conversation_id_encode(msg->cid));
            else
                prot_printf(state->out, " %u", msg->uid);
        }
        prot_printf(state->out, "\r\n");
    }

out:
    if (!r) {
        prot_printf(state->out, "* OK [HIGHESTMODSEQ " MODSEQ_FMT "]\r\n",
                    MAX(xconvmodseq, state->mailbox->i.highestmodseq));
        prot_printf(state->out, "* OK [UIDVALIDITY %u]\r\n",
                    state->mailbox->i.uidvalidity);
        prot_printf(state->out, "* OK [UIDNEXT %u]\r\n",
                    state->mailbox->i.last_uid + 1);
        prot_printf(state->out, "* OK [TOTAL %u]\r\n",
                    total);
    }

    /* free all our temporary data */
    index_msgdata_free(msgdata, state->exists);
    ptrarray_fini(&added);
    ptrarray_fini(&removed);
    ptrarray_fini(&changed);
    free_hashu64_table(&seen_cids, NULL);
    free_hashu64_table(&old_seen_cids, NULL);

    return r;
}

/*
 * Performs a THREAD command
 */
EXPORTED int index_thread(struct index_state *state, int algorithm,
                 struct searchargs *searchargs, int usinguid)
{
    search_query_t *query = NULL;
    search_folder_t *folder;
    unsigned *msgno_list;
    int nmsg = 0;
    clock_t start;
    modseq_t highestmodseq = 0;
    int r;

    /* update the index */
    if (index_check(state, 0, 0))
        return 0;

    highestmodseq = needs_modseq(searchargs, NULL);

    if(CONFIG_TIMING_VERBOSE)
        start = clock();

    /* Search for messages based on the given criteria */
    query = search_query_new(state, searchargs);
    r = search_query_run(query);
    if (r) goto out;        /* search failed */
    folder = search_query_find_folder(query, index_mboxname(state));

    if (folder) {
        search_folder_use_msn(folder, state);
        if (highestmodseq)
            highestmodseq = search_folder_get_highest_modseq(folder);
        nmsg = search_folder_get_array(folder, &msgno_list);
    }

    if (nmsg) {
        /* Thread messages using given algorithm */
        (*thread_algs[algorithm].threader)(state, msgno_list, nmsg, usinguid);

        free(msgno_list);

        if (highestmodseq)
            prot_printf(state->out, " (MODSEQ " MODSEQ_FMT ")", highestmodseq);
    }

    /* print an empty untagged response */
    else
        index_thread_print(state, NULL, usinguid);

    prot_printf(state->out, "\r\n");

    if (CONFIG_TIMING_VERBOSE) {
        /* debug */
        syslog(LOG_DEBUG, "THREAD %s processing time: %d msg in %f sec",
               thread_algs[algorithm].alg_name, nmsg,
               (clock() - start) / (double) CLOCKS_PER_SEC);
    }

out:
    search_query_free(query);
    return nmsg;
}

/*
 * Performs a COPY command
 */
EXPORTED int
index_copy(struct index_state *state,
           char *sequence,
           int usinguid,
           char *name,
           char **copyuidp,
           int nolink,
           struct namespace *namespace,
           int isadmin,
           int ismove,
           int ignorequota)
{
    struct copyargs copyargs;
    int i;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    quota_t *qptr = NULL;
    int r;
    struct appendstate appendstate;
    uint32_t msgno, checkval;
    long docopyuid;
    seqset_t *seq;
    struct mailbox *srcmailbox = NULL;
    struct mailbox *destmailbox = NULL;
    struct index_map *im;
    int is_same_user;
    ptrarray_t *msgrecs = NULL;

    *copyuidp = NULL;

    memset(&copyargs, 0, sizeof(struct copyargs));

    /* let's just see how common this is... */
    if (!strcmp(index_mboxname(state), name))
        syslog(LOG_NOTICE, "same mailbox copy %s (%s)", name, sequence);

    is_same_user = mboxname_same_userid(index_mboxname(state), name);
    if (is_same_user < 0)
        return is_same_user;

    r = index_check(state, usinguid, usinguid);
    if (r) return r;

    srcmailbox = state->mailbox;

    seq = _parse_sequence(state, sequence, usinguid);

    for (msgno = 1; msgno <= state->exists; msgno++) {
        im = &state->map[msgno-1];
        checkval = usinguid ? im->uid : msgno;
        if (!seqset_ismember(seq, checkval))
            continue;
        index_copysetup(state, msgno, &copyargs);
    }

    seqset_free(&seq);

    if (copyargs.nummsg == 0) {
        r =  IMAP_NO_NOSUCHMSG;
        goto done;
    }

    r = mailbox_open_iwl(name, &destmailbox);
    if (r) goto done;

    /* make sure copying into this mailbox is enabled */
    r = insert_into_mailbox_allowed(destmailbox);
    if (r) goto done;

    /* if using conversations, a COPY is the same email, so there's no extra usage */
    int checkquota = !ismove && !config_getswitch(IMAPOPT_QUOTA_USE_CONVERSATIONS);

    /* not moving or different quota root - need to check quota */
    if (checkquota || strcmpsafe(mailbox_quotaroot(srcmailbox), mailbox_quotaroot(destmailbox))) {
        for (i = 0; i < copyargs.nummsg; i++)
            qdiffs[QUOTA_STORAGE] += copyargs.records[i].size;
        qdiffs[QUOTA_MESSAGE] = copyargs.nummsg;
        qptr = qdiffs;
    }

    r = append_setup_mbox(&appendstate, destmailbox, state->userid,
                          state->authstate, ACL_INSERT,
                          ignorequota ? NULL : qptr, namespace, isadmin,
                          ismove ? EVENT_MESSAGE_MOVE : EVENT_MESSAGE_COPY);
    if (r) goto done;

    docopyuid = (appendstate.myrights & ACL_READ);
    msgrecs = ptrarray_new();

    for (i = 0; i < copyargs.nummsg; i++) {
        msgrecord_t *mr = msgrecord_from_index_record(srcmailbox, &copyargs.records[i]);
        ptrarray_append(msgrecs, mr);
    }
    r = append_copy(srcmailbox, &appendstate, msgrecs, nolink, is_same_user);
    if (r) {
        append_abort(&appendstate);
        goto done;
    }

    r = append_commit(&appendstate);
    if (r) goto done;

    /* unlock first so we don't hold the lock while expunging
     * the source */
    mailbox_unlock_index(destmailbox, NULL);

    if (docopyuid || ismove) {
        char *source;
        seqset_t *seq;
        unsigned uidvalidity = destmailbox->i.uidvalidity;

        seq = seqset_init(0, SEQ_SPARSE);

        for (i = 0; i < copyargs.nummsg; i++)
            seqset_add(seq, copyargs.records[i].uid, 1);

        source = seqset_cstring(seq);

        /* remove the source messages */
        if (ismove)
            r = index_expunge(state, source, 0);

        if (docopyuid) {
            *copyuidp = xmalloc(strlen(source) + 50);

            if (appendstate.nummsg == 1)
                sprintf(*copyuidp, "%u %s %u", uidvalidity, source,
                        appendstate.baseuid);
            else
                sprintf(*copyuidp, "%u %s %u:%u", uidvalidity, source,
                        appendstate.baseuid,
                        appendstate.baseuid + appendstate.nummsg - 1);
        }

        free(source);
        seqset_free(&seq);
    }

    if (!r) {
        /* we log the first name to get GUID-copy magic */
        sync_log_mailbox_double(index_mboxname(state), name);
        /* also want to log an append here, to make sure squatter notices */
        sync_log_append(name);
    }

done:
    free(copyargs.records);
    mailbox_close(&destmailbox);
    if (msgrecs) {
        for (i = 0; i < msgrecs->count; i++) {
            msgrecord_t *mr = ptrarray_nth(msgrecs, i);
            msgrecord_unref(&mr);
        }
        ptrarray_free(msgrecs);
    }

    return r;
}

/*
 * Helper function to multiappend a message to remote mailbox
 */
static int index_appendremote(struct index_state *state, uint32_t msgno,
                              struct protstream *pout)
{
    struct mailbox *mailbox = state->mailbox;
    struct buf buf = BUF_INITIALIZER;
    unsigned flag, flagmask = 0;
    char datebuf[RFC3501_DATETIME_MAX+1];
    char sepchar = '(';
    struct index_record record;
    int r;

    r = index_reload_record(state, msgno, &record);
    if (r) return r;

    /* Open the message file */
    if (mailbox_map_record(mailbox, &record, &buf))
        return IMAP_NO_MSGGONE;

    /* start the individual append */
    prot_printf(pout, " ");

    /* add system flags */
    if (record.system_flags & FLAG_ANSWERED) {
        prot_printf(pout, "%c\\Answered", sepchar);
        sepchar = ' ';
    }
    if (record.system_flags & FLAG_FLAGGED) {
        prot_printf(pout, "%c\\Flagged", sepchar);
        sepchar = ' ';
    }
    if (record.system_flags & FLAG_DRAFT) {
        prot_printf(pout, "%c\\Draft", sepchar);
        sepchar = ' ';
    }
    if (record.system_flags & FLAG_DELETED) {
        prot_printf(pout, "%c\\Deleted", sepchar);
        sepchar = ' ';
    }
    if (record.system_flags & FLAG_SEEN) {
        prot_printf(pout, "%c\\Seen", sepchar);
        sepchar = ' ';
    }

    /* add user flags */
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
        if ((flag & 31) == 0) {
            flagmask = record.user_flags[flag/32];
        }
        if (state->flagname[flag] && (flagmask & (1<<(flag & 31)))) {
            prot_printf(pout, "%c%s", sepchar, state->flagname[flag]);
            sepchar = ' ';
        }
    }

    /* add internal date */
    time_to_rfc3501(record.internaldate, datebuf, sizeof(datebuf));
    prot_printf(pout, ") \"%s\" ", datebuf);

    /* message literal */
    index_fetchmsg(state, &buf, 0, record.size, 0, 0);

    /* close the message file */
    buf_free(&buf);

    return 0;
}

/*
 * Performs a COPY command from a local mailbox to a remote mailbox
 */
EXPORTED int index_copy_remote(struct index_state *state, char *sequence,
                      int usinguid, struct protstream *pout)
{
    uint32_t msgno;
    seqset_t *seq;
    struct index_map *im;
    int r;

    r = index_check(state, usinguid, usinguid);
    if (r) return r;

    seq = _parse_sequence(state, sequence, usinguid);

    for (msgno = 1; msgno <= state->exists; msgno++) {
        im = &state->map[msgno-1];
        if (!seqset_ismember(seq, usinguid ? im->uid : msgno))
            continue;
        index_appendremote(state, msgno, pout);
    }

    seqset_free(&seq);

    return 0;
}

/*
 * Returns the msgno of the message with UID 'uid'.
 * If no message with UID 'uid', returns the message with
 * the highest UID not greater than 'uid'.
 */
EXPORTED uint32_t index_finduid(struct index_state *state, uint32_t uid)
{
    unsigned low = 1;
    unsigned high = state->exists;
    unsigned mid;
    unsigned miduid;

    while (low <= high) {
        mid = (high - low)/2 + low;
        miduid = index_getuid(state, mid);
        if (miduid == uid)
            return mid;
        else if (miduid > uid)
            high = mid - 1;
        else
            low = mid + 1;
    }
    return high;
}

/* Helper function to determine domain of data */
enum {
    DOMAIN_7BIT = 0,
    DOMAIN_8BIT,
    DOMAIN_BINARY
};

static int data_domain(const char *p, size_t n)
{
    int r = DOMAIN_7BIT;

    while (n--) {
        if (!*p) return DOMAIN_BINARY;
        if (*p & 0x80) r = DOMAIN_8BIT;
        p++;
    }

    return r;
}

/*
 * Helper function to fetch data from a message file.  Writes a
 * quoted-string or literal containing data from 'msg_base', which is
 * of size 'msg_size', starting at 'offset' and containing 'size'
 * octets.  If 'octet_count' is nonzero, the data is
 * further constrained by 'start_octet' and 'octet_count' as per the
 * IMAP command PARTIAL.
 */
void index_fetchmsg(struct index_state *state, const struct buf *msg,
                    unsigned offset,
                    unsigned size,     /* this is the correct size for a news message after
                                          having LF translated to CRLF */
                    unsigned start_octet, unsigned octet_count)
{
    unsigned n, domain;

    /* If no data, output NIL */
    if (!msg || !msg->s) {
        prot_printf(state->out, "NIL");
        return;
    }

    /* partial fetch: adjust 'size' */
    if (octet_count) {
        if (size <= start_octet) {
            size = 0;
        }
        else {
            size -= start_octet;
        }
        if (size > octet_count) size = octet_count;
    }

    /* If zero-length data, output empty quoted string */
    if (size == 0) {
        prot_printf(state->out, "\"\"");
        return;
    }

    /* Seek over PARTIAL constraint */
    offset += start_octet;
    n = size;
    if (offset + size > msg->len) {
        if (msg->len > offset) {
            n = msg->len - offset;
        }
        else {
            prot_printf(state->out, "\"\"");
            return;
        }
    }

    /* Get domain of the data */
    domain = data_domain(msg->s + offset, n);

    if (domain == DOMAIN_BINARY) {
        /* Write size of literal8 */
        prot_printf(state->out, "~{%u}\r\n", size);
    } else {
        /* Write size of literal */
        prot_printf(state->out, "{%u}\r\n", size);
    }

    /* Non-text literal -- tell the protstream about it */
    if (domain != DOMAIN_7BIT) prot_data_boundary(state->out);

    prot_write(state->out, msg->s + offset, n);
    while (n++ < size) {
        /* File too short, resynch client.
         *
         * This can only happen if the reported size of the part
         * is incorrect and would push us past EOF.
         */
        (void)prot_putc(' ', state->out);
    }

    /* End of non-text literal -- tell the protstream about it */
    if (domain != DOMAIN_7BIT) prot_data_boundary(state->out);
}

static int body_is_rfc822(struct body *body)
{
    return body &&
        !strcasecmpsafe(body->type, "MESSAGE") &&
        !strcasecmpsafe(body->subtype, "RFC822");
}

static struct body *find_part(struct body *body, int32_t part)
{
    if (body_is_rfc822(body))
        body = body->subpart;
    else if (!body->numparts)
        return NULL;

    if (body->numparts) {
        /* A multipart */
        if (part >= body->numparts + 1)
            return NULL;
        body = body->subpart + part - 1;
    }
    else {
        /* Every message has at least one part number. */
        if (part > 1)
            return NULL;
    }

    return body;
}

/*
 * Helper function to fetch a body section
 */
static int index_fetchsection(struct index_state *state, const char *resp,
                              const struct buf *inmsg,
                              char *section, struct body *body, unsigned size,
                              unsigned start_octet, unsigned octet_count)
{
    const char *p;
    unsigned offset = 0;
    char *decbuf = NULL;
    struct buf msg = BUF_INITIALIZER;
    struct body *top = body;
    int wantheader = 0;
    int32_t mimenum = 0;
    int r;

    p = section;

    buf_init_ro(&msg, inmsg->s, inmsg->len);

    /* Special-case BODY[] */
    if (*p == ']') {
        if (strstr(resp, "BINARY.SIZE")) {
            prot_printf(state->out, "%s%u", resp, size);
        } else {
            prot_printf(state->out, "%s", resp);
            index_fetchmsg(state, &msg, 0, size,
                           start_octet, octet_count);
        }
        return 0;
    }

    /*
       section         = "[" [section-spec] "]"

       section-msgtext = "HEADER" / "HEADER.FIELDS" [".NOT"] SP header-list /
                         "TEXT"
                    ; top-level or MESSAGE/RFC822 part

       section-part    = nz-number *("." nz-number)
                    ; body part nesting

       section-spec    = section-msgtext / (section-part ["." section-text])

       section-text    = section-msgtext / "MIME"
                    ; text other than actual body part (headers, etc.)
     */

    while (*p != ']') {
        switch (*p) {
        case 'H':
            if (!body_is_rfc822(body)) goto badpart;
            body = body->subpart;
            p += 6;
            wantheader = 1;
            goto emitpart;
        case 'T':
            if (!body_is_rfc822(body)) goto badpart;
            body = body->subpart;
            p += 4;
            goto emitpart;
        case 'M':
            if (body == top) goto badpart;
            p += 4;
            wantheader = 1;
            goto emitpart;
        default:
            mimenum = 0;
            r = parseint32(p, &p, &mimenum);
            if (*p == '.') p++;
            if (r || !mimenum) goto badpart;
            body = find_part(body, mimenum);
            if (!body) goto badpart;
            break;
        }
    }

emitpart:
    if (*p != ']') goto badpart;

    if (wantheader) {
        offset = body->header_offset;
        size = body->header_size;
    }
    else {
        offset = body->content_offset;
        size = body->content_size;
    }

    if (msg.s && !wantheader && (p = strstr(resp, "BINARY"))) {
        /* BINARY or BINARY.SIZE */
        int encoding = body->charset_enc & 0xff;
        size_t newsize;

        /* check that the offset isn't corrupt */
        if (offset + size > msg.len) {
            syslog(LOG_ERR, "invalid part offset in %s", index_mboxname(state));
            return IMAP_IOERROR;
        }

        msg.s = (char *)charset_decode_mimebody(msg.s + offset, size, encoding,
                                                &decbuf, &newsize);

        if (!msg.s) {
            /* failed to decode */
            if (decbuf) free(decbuf);
            return IMAP_NO_UNKNOWN_CTE;
        }
        else if (p[6] == '.') {
            /* BINARY.SIZE */
            prot_printf(state->out, "%s%zd", resp, newsize);
            if (decbuf) free(decbuf);
            return 0;
        }
        else {
            /* BINARY */
            offset = 0;
            size = newsize;
            msg.len = newsize;
        }
    }

    /* Output body part */
    prot_printf(state->out, "%s", resp);
    index_fetchmsg(state, &msg, offset, size,
                   start_octet, octet_count);

    if (decbuf) free(decbuf);
    return 0;

 badpart:
    if (strstr(resp, "BINARY.SIZE"))
        prot_printf(state->out, "%s0", resp);
    else
        prot_printf(state->out, "%sNIL", resp);
    return 0;
}

/*
 * Helper function to fetch a HEADER.FIELDS[.NOT] body section
 */
static void index_fetchfsection(struct index_state *state,
                                const char *msg_base,
                                unsigned long msg_size,
                                struct fieldlist *fsection,
                                struct body *body,
                                unsigned start_octet, unsigned octet_count)
{
    const char *p;
    int32_t mimenum = 0;
    int fields_not = 0;
    const char *crlf = "\r\n";
    unsigned crlf_start = 0;
    unsigned crlf_size = 2;
    char *buf;
    unsigned size;
    int r;

    /* If no data, output null quoted string */
    if (!msg_base) {
        prot_printf(state->out, "\"\"");
        return;
    }

    p = fsection->section;

    while (*p != 'H') {
        r = parseint32(p, &p, &mimenum);
        if (*p == '.') p++;

        if (r || !mimenum) goto badpart;

        body = find_part(body, mimenum);
        if (!body) goto badpart;
    }

    if (body_is_rfc822(body)) body = body->subpart;

    if (!body->header_size) goto badpart;

    if (p[13]) fields_not++;    /* Check for "." after "HEADER.FIELDS" */

    buf = index_readheader(msg_base, msg_size,
                           body->header_offset,
                           body->header_size);

    if (fields_not) {
        message_pruneheader(buf, 0, fsection->fields);
    }
    else {
        message_pruneheader(buf, fsection->fields, 0);
    }
    size = strlen(buf);

    /* partial fetch: adjust 'size' */
    if (octet_count) {
        if (size <= start_octet) {
            crlf_start = start_octet - size;
            size = 0;
            start_octet = 0;
            if (crlf_size <= crlf_start) {
                crlf_size = 0;
            }
            else {
                crlf_size -= crlf_start;
            }
        }
        else {
            size -= start_octet;
        }
        if (size > octet_count) {
            size = octet_count;
            crlf_size = 0;
        }
        else if (size + crlf_size > octet_count) {
            crlf_size = octet_count - size;
        }
    }

    /* If no data, output null quoted string */
    if (size + crlf_size == 0) {
        prot_printf(state->out, "\"\"");
        return;
    }

    /* Write literal */
    prot_printf(state->out, "{%u}\r\n", size + crlf_size);
    prot_write(state->out, buf + start_octet, size);
    prot_write(state->out, crlf + crlf_start, crlf_size);

    return;

 badpart:
    prot_printf(state->out, "NIL");
}

/*
 * Helper function to read a header section into a static buffer
 */
static char *index_readheader(const char *msg_base, unsigned long msg_size,
                              unsigned offset, unsigned size)
{
    static struct buf buf = BUF_INITIALIZER;

    if (offset + size > msg_size) {
        /* Message file is too short, truncate request */
        if (offset < msg_size) {
            size = msg_size - offset;
        }
        else {
            size = 0;
        }
    }

    buf_reset(&buf);
    buf_appendmap(&buf, msg_base+offset, size);
    return (char *)buf_cstring(&buf);
}

/*
 * Handle a FETCH RFC822.HEADER.LINES or RFC822.HEADER.LINES.NOT
 * that can't use the cacheheaders in cyrus.cache
 */
static void index_fetchheader(struct index_state *state,
                              const char *msg_base,
                              unsigned long msg_size,
                              unsigned size,
                              const strarray_t *headers,
                              const strarray_t *headers_not)
{
    char *buf;

    /* If no data, output null quoted string */
    if (!msg_base) {
        prot_printf(state->out, "\"\"");
        return;
    }

    buf = index_readheader(msg_base, msg_size, 0, size);

    message_pruneheader(buf, headers, headers_not);

    size = strlen(buf);
    prot_printf(state->out, "{%u}\r\n%s\r\n", size+2, buf);
}

/*
 * Handle a FETCH RFC822.HEADER.LINES that can use the
 * cacheheaders in cyrus.cache
 */
static void
index_fetchcacheheader(struct index_state *state, struct index_record *record,
                       const strarray_t *headers, unsigned start_octet,
                       unsigned octet_count)
{
    static struct buf buf = BUF_INITIALIZER;
    unsigned size;
    const char *crlf = "\r\n";
    unsigned crlf_start = 0;
    unsigned crlf_size = 2;
    struct mailbox *mailbox = state->mailbox;

    if (mailbox_cacherecord(mailbox, record)) {
        /* bogus cache record */
        prot_printf(state->out, "\"\"");
        return;
    }

    buf_setmap(&buf, cacheitem_base(record, CACHE_HEADERS),
                     cacheitem_size(record, CACHE_HEADERS));
    buf_cstring(&buf);

    message_pruneheader(buf.s, headers, 0);
    size = strlen(buf.s); /* not buf.len, it has been pruned */

    /* partial fetch: adjust 'size' */
    if (octet_count) {
        if (size <= start_octet) {
            crlf_start = start_octet - size;
            size = 0;
            start_octet = 0;
            if (crlf_size <= crlf_start) {
                crlf_size = 0;
            }
            else {
                crlf_size -= crlf_start;
            }
        }
        else {
            size -= start_octet;
        }
        if (size > octet_count) {
            size = octet_count;
            crlf_size = 0;
        }
        else if (size + crlf_size > octet_count) {
            crlf_size = octet_count - size;
        }
    }

    if (size + crlf_size == 0) {
        prot_printf(state->out, "\"\"");
    }
    else {
        prot_printf(state->out, "{%u}\r\n", size + crlf_size);
        prot_write(state->out, buf.s + start_octet, size);
        prot_write(state->out, crlf + crlf_start, crlf_size);
    }
}

/*
 * Send a * FLAGS response.
 */
static void index_listflags(struct index_state *state)
{
    unsigned i;
    int cancreate = 0;
    char sepchar = '(';

    prot_printf(state->out, "* FLAGS (\\Answered \\Flagged \\Draft \\Deleted \\Seen");
    for (i = 0; i < MAX_USER_FLAGS; i++) {
        if (state->flagname[i]) {
            prot_printf(state->out, " %s", state->flagname[i]);
        }
        else cancreate++;
    }
    prot_printf(state->out, ")\r\n* OK [PERMANENTFLAGS ");
    if (!state->examining) {
        if (state->myrights & ACL_WRITE) {
            prot_printf(state->out, "%c\\Answered \\Flagged \\Draft", sepchar);
            sepchar = ' ';
        }
        if (state->myrights & ACL_DELETEMSG) {
            prot_printf(state->out, "%c\\Deleted", sepchar);
            sepchar = ' ';
        }
        if (state->myrights & ACL_SETSEEN) {
            prot_printf(state->out, "%c\\Seen", sepchar);
            sepchar = ' ';
        }
        if (state->myrights & ACL_WRITE) {
            for (i = 0; i < MAX_USER_FLAGS; i++) {
                if (state->flagname[i]) {
                    prot_printf(state->out, " %s", state->flagname[i]);
                }
            }
            if (cancreate) {
                prot_printf(state->out, " \\*");
            }
        }
    }
    if (sepchar == '(') prot_printf(state->out, "(");
    prot_printf(state->out, ")] Ok\r\n");
}

EXPORTED void index_checkflags(struct index_state *state, int print, int dirty)
{
    struct mailbox *mailbox = state->mailbox;
    unsigned i;

    for (i = 0; i < MAX_USER_FLAGS; i++) {
        /* both empty */
        if (!mailbox->h.flagname[i] && !state->flagname[i])
            continue;

        /* both same */
        if (mailbox->h.flagname[i] && state->flagname[i] &&
            !strcmp(mailbox->h.flagname[i], state->flagname[i]))
            continue;

        /* ok, got something to change! */
        if (state->flagname[i])
            free(state->flagname[i]);
        if (mailbox->h.flagname[i])
            state->flagname[i] = xstrdup(mailbox->h.flagname[i]);
        else
            state->flagname[i] = NULL;

        dirty = 1;
    }

    if (dirty && print)
        index_listflags(state);
}

static void index_tellexpunge(struct index_state *state)
{
    unsigned oldmsgno;
    uint32_t msgno = 1;
    seqset_t *vanishedlist;
    struct index_map *im;
    unsigned exists = state->exists;

    // if we want expunged, we can't tell them!
    if (state->want_expunged) return;

    vanishedlist = seqset_init(0, SEQ_SPARSE);

    for (oldmsgno = 1; oldmsgno <= exists; oldmsgno++) {
        im = &state->map[oldmsgno-1];

        /* inform about expunges */
        if (im->internal_flags & FLAG_INTERNAL_EXPUNGED) {
            state->exists--;
            state->num_expunged--;
            /* they never knew about this one, skip */
            if (msgno > state->oldexists)
                continue;
            state->oldexists--;
            if ((client_capa & CAPA_QRESYNC))
                seqset_add(vanishedlist, im->uid, 1);
            else
                prot_printf(state->out, "* %u EXPUNGE\r\n", msgno);
            continue;
        }

        /* copy back if necessary (after first expunge) */
        if (msgno < oldmsgno)
            state->map[msgno-1] = *im;

        msgno++;
    }

    /* report all vanished if we're doing it this way */
    if (seqset_first(vanishedlist)) {
        char *vanished = seqset_cstring(vanishedlist);
        prot_printf(state->out, "* VANISHED %s\r\n", vanished);
        free(vanished);
    }
    seqset_free(&vanishedlist);

    /* highestmodseq can now come forward to real-time */
    state->delayed_modseq = 0;
}

static void index_tellexists(struct index_state *state)
{
    prot_printf(state->out, "* %u EXISTS\r\n", state->exists);
    prot_printf(state->out, "* %u RECENT\r\n", state->numrecent);
    state->oldexists = state->exists;
}

EXPORTED void index_tellchanges(struct index_state *state, int canexpunge,
                       int printuid, int printmodseq)
{
    uint32_t msgno;
    struct index_map *im;

    /* must call tellexpunge before tellexists, because tellexpunge changes
     * the size of oldexists to mention expunges, and tellexists will reset
     * oldexists.  If we do these out of order, we will tell the user about
     * expunges of messages they never saw, which would be wrong */
    if (canexpunge) index_tellexpunge(state);

    if (state->oldexists != state->exists) index_tellexists(state);

    if (state->oldhighestmodseq == state->highestmodseq) return;

    index_checkflags(state, 1, 0);

    /* print any changed message flags */
    for (msgno = 1; msgno <= state->exists; msgno++) {
        im = &state->map[msgno-1];

        /* report if it's changed since last told */
        if (im->modseq > im->told_modseq)
            index_printflags(state, msgno, printuid, printmodseq);
    }
}

struct fetch_annotation_rock {
    struct protstream *pout;
    const char *sep;
};

static void fetch_annotation_response(const char *mboxname
                                        __attribute__((unused)),
                                      uint32_t uid
                                        __attribute__((unused)),
                                      const char *entry,
                                      struct attvaluelist *attvalues,
                                      void *rock)
{
    char sep2 = '(';
    struct attvaluelist *l;
    struct fetch_annotation_rock *frock = rock;

    prot_printf(frock->pout, "%s", frock->sep);
    prot_printastring(frock->pout, entry);
    prot_putc(' ', frock->pout);

    for (l = attvalues ; l ; l = l->next) {
        prot_putc(sep2, frock->pout);
        sep2 = ' ';
        prot_printastring(frock->pout, l->attrib);
        prot_putc(' ', frock->pout);
        prot_printmap(frock->pout, l->value.s, l->value.len);
    }
    prot_putc(')', frock->pout);

    frock->sep = " ";
}

/*
 * Helper function to send FETCH data for the ANNOTATION
 * fetch item.
 */
static int index_fetchannotations(struct index_state *state,
                                  uint32_t msgno,
                                  const struct fetchargs *fetchargs)
{
    annotate_state_t *astate = NULL;
    struct fetch_annotation_rock rock;
    int r = 0;

    r = mailbox_get_annotate_state(state->mailbox,
                                   state->map[msgno-1].uid,
                                   &astate);
    if (r) return r;
    annotate_state_set_auth(astate, fetchargs->isadmin,
                            fetchargs->userid, fetchargs->authstate);

    memset(&rock, 0, sizeof(rock));
    rock.pout = state->out;
    rock.sep = "";

    r = annotate_state_fetch(astate,
                             &fetchargs->entries, &fetchargs->attribs,
                             fetch_annotation_response, &rock);

    return r;
}

struct fetch_mailbox_rock {
    struct index_state *state;
    int sep;
    int wantname;
    const struct fetchargs *fetchargs;
};

static int fetch_mailbox_cb(const conv_guidrec_t *rec, void *rock)
{
    static const int needrights = ACL_READ|ACL_LOOKUP;
    struct fetch_mailbox_rock *fmb_rock = (struct fetch_mailbox_rock *) rock;
    mbentry_t *mbentry = NULL;
    int myrights = 0;
    struct mailbox *mailbox = NULL;
    msgrecord_t *msgrecord = NULL;
    char *extname = NULL;
    int r = 0;

    assert(fmb_rock->state != NULL);
    assert(fmb_rock->fetchargs != NULL);

    /* convdb has flags: skip if flag deleted or flag internal expunged */
    if (rec->version >= 1) {
        if ((rec->system_flags & FLAG_DELETED)
            || (rec->internal_flags & FLAG_INTERNAL_EXPUNGED))
            goto done;
    }

    /* make sure we have appropriate rights */
    r = conv_guidrec_mbentry(rec, &mbentry);
    if (r) goto done;
    myrights = cyrus_acl_myrights(fmb_rock->state->authstate, mbentry->acl);
    if ((myrights & needrights) != needrights)
        goto done;

    /* convdb does not have flags: grab them from message record */
    if (rec->version == 0) {
        uint32_t system_flags, internal_flags;

        r = mailbox_open_irl(mbentry->name, &mailbox);
        if (r) goto done;

        r = msgrecord_find(mailbox, rec->uid, &msgrecord);
        if (r) goto done;

        r = msgrecord_get_systemflags(msgrecord, &system_flags);
        if (!r) r = msgrecord_get_internalflags(msgrecord, &internal_flags);
        if (r) goto done;

        if ((system_flags & FLAG_DELETED)
            || (internal_flags & FLAG_INTERNAL_EXPUNGED))
            goto done;
    }

    if (fmb_rock->wantname) {
        extname = mboxname_to_external(mbentry->name,
                                       fmb_rock->fetchargs->namespace,
                                       fmb_rock->fetchargs->userid);
    }

    if (fmb_rock->sep)
        prot_putc(fmb_rock->sep, fmb_rock->state->out);
    prot_printf(fmb_rock->state->out, "%s",
                fmb_rock->wantname ? extname : mbentry->uniqueid);
    fmb_rock->sep = ' ';

done:
    if (extname) free(extname);
    if (msgrecord) msgrecord_unref(&msgrecord);
    if (mailbox) mailbox_close(&mailbox);
    if (mbentry) mboxlist_entry_free(&mbentry);
    return r;
}

/*
 * Helper function to send FETCH data for the MAILBOXES
 * fetch item.
 */
static int index_fetchmailboxes(struct index_state *state,
                                uint32_t msgno,
                                const struct fetchargs *fetchargs)
{
    struct fetch_mailbox_rock rock = { state, 0, /*wantname*/ 1, fetchargs};
    struct index_record record;
    int r;

    if (!fetchargs->convstate) return 0;

    r = index_reload_record(state, msgno, &record);
    if (r) return r;

    return conversations_guid_foreach(fetchargs->convstate,
                                      message_guid_encode(&record.guid),
                                      &fetch_mailbox_cb,
                                      &rock);
}

/*
 * Helper function to send FETCH data for the MAILBOXIDS
 * fetch item.
 */
static int index_fetchmailboxids(struct index_state *state,
                                 uint32_t msgno,
                                 const struct fetchargs *fetchargs)
{
    struct fetch_mailbox_rock rock = { state, 0, /*wantname*/ 0, fetchargs};
    struct index_record record;
    int r;

    if (!fetchargs->convstate) return 0;

    r = index_reload_record(state, msgno, &record);
    if (r) return r;

    return conversations_guid_foreach(fetchargs->convstate,
                                      message_guid_encode(&record.guid),
                                      &fetch_mailbox_cb,
                                      &rock);
}

/*
 * Helper function to send * FETCH (FLAGS data.
 * Does not send the terminating close paren or CRLF.
 * Also sends preceeding * FLAGS if necessary.
 */
static void index_fetchflags(struct index_state *state,
                             uint32_t msgno)
{
    int sepchar = '(';
    unsigned flag;
    bit32 flagmask = 0;
    struct index_map *im = &state->map[msgno-1];

    prot_printf(state->out, "* %u FETCH (FLAGS ", msgno);

    if (im->isrecent) {
        prot_printf(state->out, "%c\\Recent", sepchar);
        sepchar = ' ';
    }
    if (im->system_flags & FLAG_ANSWERED) {
        prot_printf(state->out, "%c\\Answered", sepchar);
        sepchar = ' ';
    }
    if (im->system_flags & FLAG_FLAGGED) {
        prot_printf(state->out, "%c\\Flagged", sepchar);
        sepchar = ' ';
    }
    if (im->system_flags & FLAG_DRAFT) {
        prot_printf(state->out, "%c\\Draft", sepchar);
        sepchar = ' ';
    }
    if (im->system_flags & FLAG_DELETED) {
        prot_printf(state->out, "%c\\Deleted", sepchar);
        sepchar = ' ';
    }
    if (state->want_expunged && (im->internal_flags & FLAG_INTERNAL_EXPUNGED)) {
        prot_printf(state->out, "%c\\Expunged", sepchar);
        sepchar = ' ';
    }
    if (im->isseen) {
        prot_printf(state->out, "%c\\Seen", sepchar);
        sepchar = ' ';
    }
    for (flag = 0; flag < VECTOR_SIZE(state->flagname); flag++) {
        if ((flag & 31) == 0) {
            flagmask = im->user_flags[flag/32];
        }
        if (state->flagname[flag] && (flagmask & (1<<(flag & 31)))) {
            prot_printf(state->out, "%c%s", sepchar, state->flagname[flag]);
            sepchar = ' ';
        }
    }
    if (sepchar == '(') (void)prot_putc('(', state->out);
    (void)prot_putc(')', state->out);
    im->told_modseq = im->modseq;
}

static void index_printflags(struct index_state *state,
                             uint32_t msgno, int usinguid,
                             int printmodseq)
{
    struct index_map *im = &state->map[msgno-1];

    index_fetchflags(state, msgno);
    /* http://www.rfc-editor.org/errata_search.php?rfc=5162
     * Errata ID: 1807 - MUST send UID and MODSEQ to all
     * untagged FETCH unsolicited responses */
    if (usinguid || (client_capa & CAPA_QRESYNC))
        prot_printf(state->out, " UID %u", im->uid);
    if (printmodseq || (client_capa & CAPA_CONDSTORE))
        prot_printf(state->out, " MODSEQ (" MODSEQ_FMT ")", im->modseq);
    prot_printf(state->out, ")\r\n");
}

/* interface message_read_bodystructure which makes sure the cache record
 * exists and adds the MESSAGE/RFC822 wrapper to make fetch BODY[*]
 * work consistently */
static void loadbody(struct mailbox *mailbox, struct index_record *record,
                     struct body **bodyp)
{
    if (*bodyp) return;
    if (mailbox_cacherecord(mailbox, record)) return;
    struct body *body = xzmalloc(sizeof(struct body));
    message_read_bodystructure(record, &body->subpart);
    body->type = xstrdup("MESSAGE");
    body->subtype = xstrdup("RFC822");
    body->header_offset = 0;
    body->header_size = 0;
    body->content_offset = 0;
    body->content_offset = record->size;
    *bodyp = body;
}

/*
 * Helper function to send requested * FETCH data for a message
 */
static int index_fetchreply(struct index_state *state, uint32_t msgno,
                            const struct fetchargs *fetchargs)
{
    struct mailbox *mailbox = state->mailbox;
    int fetchitems = fetchargs->fetchitems;
    struct buf buf = BUF_INITIALIZER;
    struct octetinfo *oi = NULL;
    int sepchar = '(';
    int started = 0;
    struct section *section;
    struct fieldlist *fsection;
    char respbuf[100];
    int r = 0;
    struct index_map *im = &state->map[msgno-1];
    struct index_record record;
    struct body *body = NULL;

    /* Check the modseq against changedsince */
    if (fetchargs->changedsince && im->modseq <= fetchargs->changedsince)
        return 0;

    /* skip missing records entirely */
    if (!im->recno)
        return 0;

    r = index_reload_record(state, msgno, &record);
    if (r) {
        prot_printf(state->out, "* OK ");
        prot_printf(state->out, error_message(IMAP_NO_MSGGONE), msgno);
        prot_printf(state->out, "\r\n");
        return 0;
    }

    /* Check against the CID list filter */
    if (fetchargs->cidhash) {
        const char *key = conversation_id_encode(record.cid);
        if (!hash_lookup(key, fetchargs->cidhash))
            return 0;
    }

    /* Open the message file if we're going to need it */
    if ((fetchitems & (FETCH_HEADER|FETCH_TEXT|FETCH_SHA1|FETCH_RFC822)) ||
        fetchargs->cache_atleast > record.cache_version ||
        fetchargs->binsections || fetchargs->sizesections ||
        fetchargs->bodysections) {
        if (mailbox_map_record(mailbox, &record, &buf)) {
            prot_printf(state->out, "* OK ");
            prot_printf(state->out, error_message(IMAP_NO_MSGGONE), msgno);
            prot_printf(state->out, "\r\n");
            return 0;
        }
    }
    int ischanged = im->told_modseq < record.modseq;

    /* display flags if asked _OR_ if they've changed */
    if (fetchitems & FETCH_FLAGS || ischanged) {
        index_fetchflags(state, msgno);
        sepchar = ' ';
    }
    else if ((fetchitems & ~FETCH_SETSEEN) || fetchargs->fsections ||
             fetchargs->headers.count || fetchargs->headers_not.count) {
        /* these fetch items will always succeed, so start the response */
        prot_printf(state->out, "* %u FETCH ", msgno);
        started = 1;
    }
    if (fetchitems & FETCH_UID || (ischanged && (client_capa & CAPA_QRESYNC))) {
        prot_printf(state->out, "%cUID %u", sepchar, record.uid);
        sepchar = ' ';
    }
    if (fetchitems & FETCH_GUID) {
        prot_printf(state->out, "%cDIGEST.SHA1 %s", sepchar,
                    message_guid_encode(&record.guid));
        sepchar = ' ';
    }

    if (fetchitems & FETCH_INTERNALDATE) {
        time_t msgdate = record.internaldate;
        char datebuf[RFC3501_DATETIME_MAX+1];

        time_to_rfc3501(msgdate, datebuf, sizeof(datebuf));

        prot_printf(state->out, "%cINTERNALDATE \"%s\"",
                    sepchar, datebuf);
        sepchar = ' ';
    }

    if (fetchitems & FETCH_LASTUPDATED) {
        time_t msgdate = record.last_updated;
        char datebuf[RFC3501_DATETIME_MAX+1];

        time_to_rfc3501(msgdate, datebuf, sizeof(datebuf));

        prot_printf(state->out, "%cLASTUPDATED \"%s\"",
                    sepchar, datebuf);
        sepchar = ' ';
    }

    if (fetchitems & FETCH_MODSEQ || (ischanged && (client_capa & CAPA_CONDSTORE))) {
        prot_printf(state->out, "%cMODSEQ (" MODSEQ_FMT ")",
                    sepchar, record.modseq);
        sepchar = ' ';
    }
    if (fetchitems & FETCH_SIZE) {
        prot_printf(state->out, "%cRFC822.SIZE %u",
                    sepchar, record.size);
        sepchar = ' ';
    }
    if ((fetchitems & FETCH_ANNOTATION)) {
        prot_printf(state->out, "%cANNOTATION (", sepchar);
        r = index_fetchannotations(state, msgno, fetchargs);
        r = 0;
        prot_printf(state->out, ")");
        sepchar = ' ';
    }
    if (fetchitems & FETCH_PREVIEW) {
        prot_printf(state->out, "%cPREVIEW ", sepchar);
        const char *annot = config_getstring(IMAPOPT_JMAP_PREVIEW_ANNOT);
        if (annot && !strncmp(annot, "/shared/", 8)) {
            struct buf previewbuf = BUF_INITIALIZER;
            annotatemore_msg_lookup(mailbox, record.uid, annot+7,
                                    /*userid*/"", &previewbuf);
            if (buf_len(&previewbuf) > 256)
                buf_truncate(&previewbuf, 256); // XXX - utf8 chars
            prot_printastring(state->out, buf_cstring(&previewbuf));
            buf_free(&previewbuf);
        }
        else {
            prot_puts(state->out, "NIL");
        }

        sepchar = ' ';
    }
    if (fetchitems & FETCH_FILESIZE) {
        unsigned int msg_size = buf.len;
        if (!buf.s) {
            const char *fname = mailbox_record_fname(mailbox, &record);
            struct stat sbuf;
            /* Find the size of the message file */
            if (stat(fname, &sbuf) == -1)
                syslog(LOG_ERR, "IOERROR: stat on %s: %m", fname);
            else
                msg_size = sbuf.st_size;
        }
        prot_printf(state->out, "%cRFC822.FILESIZE %lu", sepchar,
                    (long unsigned)msg_size);
        sepchar = ' ';
    }
    if (fetchitems & FETCH_SHA1) {
        struct message_guid tmpguid;
        message_guid_generate(&tmpguid, buf.s, buf.len);
        prot_printf(state->out, "%cRFC822.SHA1 %s", sepchar, message_guid_encode(&tmpguid));
        sepchar = ' ';
    }
    if (fetchitems & FETCH_EMAILID) {
        char emailid[26];
        emailid[0] = 'M';
        memcpy(emailid+1, message_guid_encode(&record.guid), 24);
        emailid[25] = '\0';
        prot_printf(state->out, "%cEMAILID (%s)", sepchar, emailid);
        sepchar = ' ';
    }
    if ((fetchitems & FETCH_CID) &&
        config_getswitch(IMAPOPT_CONVERSATIONS)) {
        struct buf buf = BUF_INITIALIZER;
        if (!record.cid)
            buf_appendcstr(&buf, "NIL");
        else
            buf_printf(&buf, CONV_FMT, record.cid);
        prot_printf(state->out, "%cCID %s", sepchar, buf_cstring(&buf));
        buf_free(&buf);
        sepchar = ' ';
    }
    if ((fetchitems & FETCH_THREADID)) {
        char threadid[18];
        if (!record.cid) {
            threadid[0] = 'N';
            threadid[1] = 'I';
            threadid[2] = 'L';
            threadid[3] = '\0';
        }
        else {
            threadid[0] = 'T';
            memcpy(threadid+1, conversation_id_encode(record.cid), 16);
            threadid[17] = '\0';
        }

        prot_printf(state->out, "%cTHREADID (%s)", sepchar, threadid);
        sepchar = ' ';
    }
    if (fetchitems & FETCH_SAVEDATE) {
        time_t msgdate = record.savedate;
        char datebuf[RFC3501_DATETIME_MAX+1];

        // handle internaldate
        if (!msgdate) msgdate = record.internaldate;

        time_to_rfc3501(msgdate, datebuf, sizeof(datebuf));

        prot_printf(state->out, "%cSAVEDATE \"%s\"",
                    sepchar, datebuf);
        sepchar = ' ';
    }
    if (fetchitems & FETCH_CREATEDMODSEQ) {
        prot_printf(state->out, "%cCREATEDMODSEQ (" MODSEQ_FMT ")",
                    sepchar, record.createdmodseq);
        sepchar = ' ';
    }

    if ((fetchitems & FETCH_BASECID) &&
        config_getswitch(IMAPOPT_CONVERSATIONS)) {
        mailbox_read_basecid(mailbox, &record);
        struct buf buf = BUF_INITIALIZER;
        if (!record.basecid)
            buf_appendcstr(&buf, "NIL");
        else
            buf_printf(&buf, CONV_FMT, record.basecid);
        prot_printf(state->out, "%cBASECID %s", sepchar, buf_cstring(&buf));
        buf_free(&buf);
        sepchar = ' ';
    }
    if ((fetchitems & FETCH_FOLDER)) {
        char *extname = mboxname_to_external(index_mboxname(state),
                                             fetchargs->namespace, fetchargs->userid);
        prot_printf(state->out, "%cFOLDER ", sepchar);
        prot_printastring(state->out, extname);
        sepchar = ' ';
        free(extname);
    }
    if ((fetchitems & FETCH_UIDVALIDITY)) {
        prot_printf(state->out, "%cUIDVALIDITY %u", sepchar,
                    state->mailbox->i.uidvalidity);
        sepchar = ' ';
    }
    if (config_getswitch(IMAPOPT_CONVERSATIONS)) {
        if (fetchitems & FETCH_MAILBOXES) {
            prot_printf(state->out, "%cMAILBOXES (", sepchar);
            r = index_fetchmailboxes(state, msgno, fetchargs);
            r = 0;
            prot_printf(state->out, ")");
            sepchar = ' ';
        }
        if (fetchitems & FETCH_MAILBOXIDS) {
            prot_printf(state->out, "%cMAILBOXIDS (", sepchar);
            r = index_fetchmailboxids(state, msgno, fetchargs);
            r = 0;
            prot_printf(state->out, ")");
            sepchar = ' ';
        }
    }
    if (fetchitems & FETCH_ENVELOPE) {
        if (!mailbox_cacherecord(mailbox, &record)) {
            prot_printf(state->out, "%cENVELOPE ", sepchar);
            sepchar = ' ';
            prot_putbuf(state->out, cacheitem_buf(&record, CACHE_ENVELOPE));
        }
    }
    if (fetchitems & FETCH_BODYSTRUCTURE) {
        if (!mailbox_cacherecord(mailbox, &record)) {
            prot_printf(state->out, "%cBODYSTRUCTURE ", sepchar);
            sepchar = ' ';
            prot_putbuf(state->out, cacheitem_buf(&record, CACHE_BODYSTRUCTURE));
        }
    }
    if (fetchitems & FETCH_BODY) {
        if (!mailbox_cacherecord(mailbox, &record)) {
            prot_printf(state->out, "%cBODY ", sepchar);
            sepchar = ' ';
            prot_putbuf(state->out, cacheitem_buf(&record, CACHE_BODY));
        }
    }

    if (fetchitems & FETCH_HEADER) {
        prot_printf(state->out, "%cRFC822.HEADER ", sepchar);
        sepchar = ' ';
        index_fetchmsg(state, &buf, 0,
                       record.header_size,
                       (fetchitems & FETCH_IS_PARTIAL) ?
                         fetchargs->start_octet : 0,
                       (fetchitems & FETCH_IS_PARTIAL) ?
                         fetchargs->octet_count : 0);
    }
    else if (fetchargs->headers.count || fetchargs->headers_not.count) {
        prot_printf(state->out, "%cRFC822.HEADER ", sepchar);
        sepchar = ' ';
        if (fetchargs->cache_atleast > record.cache_version) {
            index_fetchheader(state, buf.s, buf.len,
                              record.header_size,
                              &fetchargs->headers, &fetchargs->headers_not);
        } else {
            index_fetchcacheheader(state, &record, &fetchargs->headers, 0, 0);
        }
    }

    if (fetchitems & FETCH_TEXT) {
        prot_printf(state->out, "%cRFC822.TEXT ", sepchar);
        sepchar = ' ';
        index_fetchmsg(state, &buf,
                       record.header_size, record.size - record.header_size,
                       (fetchitems & FETCH_IS_PARTIAL) ?
                         fetchargs->start_octet : 0,
                       (fetchitems & FETCH_IS_PARTIAL) ?
                         fetchargs->octet_count : 0);
    }
    if (fetchitems & FETCH_RFC822) {
        prot_printf(state->out, "%cRFC822 ", sepchar);
        sepchar = ' ';
        index_fetchmsg(state, &buf, 0, record.size,
                       (fetchitems & FETCH_IS_PARTIAL) ?
                         fetchargs->start_octet : 0,
                       (fetchitems & FETCH_IS_PARTIAL) ?
                         fetchargs->octet_count : 0);
    }

    for (fsection = fetchargs->fsections; fsection; fsection = fsection->next) {
        int i;
        prot_printf(state->out, "%cBODY[%s ", sepchar, fsection->section);
        sepchar = '(';
        for (i = 0 ; i < fsection->fields->count ; i++) {
            (void)prot_putc(sepchar, state->out);
            sepchar = ' ';
            prot_printastring(state->out, fsection->fields->data[i]);
        }
        (void)prot_putc(')', state->out);
        sepchar = ' ';

        oi = (struct octetinfo *)fsection->rock;

        prot_printf(state->out, "%s ", fsection->trail);

        if (fetchargs->cache_atleast > record.cache_version) {
            loadbody(mailbox, &record, &body);
            if (body) {
                index_fetchfsection(state, buf.s, buf.len,
                                    fsection,
                                    body,
                                    (fetchitems & FETCH_IS_PARTIAL) ?
                                      fetchargs->start_octet : oi->start_octet,
                                    (fetchitems & FETCH_IS_PARTIAL) ?
                                      fetchargs->octet_count : oi->octet_count);
            } else {
                prot_printf(state->out, "NIL");
            }

        }
        else {
            index_fetchcacheheader(state, &record, fsection->fields,
                                   (fetchitems & FETCH_IS_PARTIAL) ?
                                     fetchargs->start_octet : oi->start_octet,
                                   (fetchitems & FETCH_IS_PARTIAL) ?
                                     fetchargs->octet_count : oi->octet_count);
        }
    }
    for (section = fetchargs->bodysections; section; section = section->next) {
        respbuf[0] = 0;
        if (sepchar == '(' && !started) {
            /* we haven't output a fetch item yet, so start the response */
            snprintf(respbuf, sizeof(respbuf), "* %u FETCH ", msgno);
        }
        snprintf(respbuf+strlen(respbuf), sizeof(respbuf)-strlen(respbuf),
                 "%cBODY[%s ", sepchar, section->name);

        oi = &section->octetinfo;

        loadbody(mailbox, &record, &body);
        if (body) {
            r = index_fetchsection(state, respbuf, &buf,
                    section->name, body, record.size,
                    (fetchitems & FETCH_IS_PARTIAL) ?
                    fetchargs->start_octet : oi->start_octet,
                    (fetchitems & FETCH_IS_PARTIAL) ?
                    fetchargs->octet_count : oi->octet_count);
            if (!r) sepchar = ' ';
        }
    }
    for (section = fetchargs->binsections; section; section = section->next) {
        respbuf[0] = 0;
        if (sepchar == '(' && !started) {
            /* we haven't output a fetch item yet, so start the response */
            snprintf(respbuf, sizeof(respbuf), "* %u FETCH ", msgno);
        }
        snprintf(respbuf+strlen(respbuf), sizeof(respbuf)-strlen(respbuf),
                 "%cBINARY[%s ", sepchar, section->name);

        loadbody(mailbox, &record, &body);
        if (body) {
            oi = &section->octetinfo;
            r = index_fetchsection(state, respbuf, &buf,
                                   section->name, body, record.size,
                                   (fetchitems & FETCH_IS_PARTIAL) ?
                                    fetchargs->start_octet : oi->start_octet,
                                   (fetchitems & FETCH_IS_PARTIAL) ?
                                    fetchargs->octet_count : oi->octet_count);
            if (!r) sepchar = ' ';
        }
    }
    for (section = fetchargs->sizesections; section; section = section->next) {
        respbuf[0] = 0;
        if (sepchar == '(' && !started) {
            /* we haven't output a fetch item yet, so start the response */
            snprintf(respbuf, sizeof(respbuf), "* %u FETCH ", msgno);
        }
        snprintf(respbuf+strlen(respbuf), sizeof(respbuf)-strlen(respbuf),
                 "%cBINARY.SIZE[%s ", sepchar, section->name);

        loadbody(mailbox, &record, &body);
        if (body) {
            r = index_fetchsection(state, respbuf, &buf,
                                   section->name, body, record.size,
                                   fetchargs->start_octet, fetchargs->octet_count);
            if (!r) sepchar = ' ';
        }
    }
    if (sepchar != '(') {
        /* finsh the response if we have one */
        prot_printf(state->out, ")\r\n");
    }
    buf_free(&buf);
    if (body) {
        message_free_body(body);
        free(body);
    }

    return r;
}

/*
 * Fetch the text data associated with an IMAP URL.
 *
 * If outsize is NULL, the data will be output as a literal (URLFETCH),
 * otherwise just the data will be output (CATENATE), and its size returned
 * in *outsize.
 *
 * This is an amalgamation of index_fetchreply(), index_fetchsection()
 * and index_fetchmsg().
 */
EXPORTED int index_urlfetch(struct index_state *state, uint32_t msgno,
                   unsigned params, const char *section,
                   unsigned long start_octet, unsigned long octet_count,
                   struct protstream *pout, size_t maxsize, unsigned long *outsize)
{
    /* dumbass eM_Client sends this:
     * A4 APPEND "INBOX.Junk Mail" () "14-Jul-2013 17:01:02 +0000"
     * CATENATE (URL "/INBOX/;uid=83118/;section=TEXT.MIME"
     * URL "/INBOX/;uid=83118/;section=TEXT")
     *
     * genius.  I can sort of see how TEXT.MIME kinda == "HEADER",
     * so there we go */
    static char text_mime[] = "HEADER";
    struct buf buf = BUF_INITIALIZER;
    int domain = DOMAIN_7BIT;
    const char *data;
    size_t size;
    int32_t wantheader = 0;
    unsigned long n;
    int r = 0;
    char *decbuf = NULL;
    struct index_record record;
    struct body *top = NULL, *body = NULL;
    size_t section_offset, section_size;

    r = index_lock(state, /*readonly*/1); // XXX: do we need to stay locked for this entire function?
    if (r) return r;

    struct mailbox *mailbox = state->mailbox;

    if (!strcasecmpsafe(section, "TEXT.MIME"))
        section = text_mime;

    if (outsize) *outsize = 0;

    r = index_reload_record(state, msgno, &record);
    if (r) goto done;

    loadbody(mailbox, &record, &body);
    if (!body) goto done;
    top = body;

    /* Open the message file */
    if (mailbox_map_record(mailbox, &record, &buf)) {
        r = IMAP_NO_MSGGONE;
        goto done;
    }

    data = buf.s;
    size = buf.len;

    int is_binary = params & URLFETCH_BINARY;

    /* Special-case BODY[] */
    if (!section || !*section) {
        /* whole message, no further parsing */
    }
    else {
        const char *p = ucase((char *) section);
        int32_t mimenum = 0;

        while (*p) {
            switch(*p) {
            case 'H':
                if (is_binary) goto badpart;
                if (!body_is_rfc822(body)) goto badpart;
                body = body->subpart;
                p += 6;
                wantheader = 1;
                goto getoffset;
            case 'T':
                if (is_binary) goto badpart;
                if (!body_is_rfc822(body)) goto badpart;
                body = body->subpart;
                p += 4;
                goto getoffset;
            case 'M':
                if (is_binary) goto badpart;
                if (top == body) goto badpart;
                p += 4;
                wantheader = 1;
                goto getoffset;
            default:
                mimenum = 0;
                r = parseint32(p, &p, &mimenum);
                if (*p == '.') p++;
                if (r || !mimenum) goto badpart;
                body = find_part(body, mimenum);
                if (!body) goto badpart;
                break;
            }
        }

      getoffset:
        if (*p) goto badpart;

        section_offset = wantheader ? body->header_offset : body->content_offset;
        section_size = wantheader ? body->header_size : body->content_size;

        if (section_offset + section_size < section_offset
            || section_offset + section_size > size) {
            r = IMAP_INTERNAL;
            goto done;
        }

        data += section_offset;
        size = section_size;
    }

    if (is_binary) {
        int encoding = body->charset_enc & 0xff;

        data = charset_decode_mimebody(data, size, encoding,
                                       &decbuf, &size);

        /* update the encoding of this part per RFC 5524:3.2 */
        if (data && encoding) {
            domain = data_domain(data, size);
            free(body->encoding);
            switch (domain) {
            case DOMAIN_BINARY:
                body->encoding = xstrdup("BINARY");
                break;
            case DOMAIN_8BIT:
                body->encoding = xstrdup("8BIT");
                break;
            default:
                body->encoding = NULL; // will output 7BIT
                break;
            }
            body->content_size = size;
            body->content_lines = 0;
        }
    }

    if (params & URLFETCH_BODYPARTSTRUCTURE) {
        struct buf buf = BUF_INITIALIZER;
        message_write_body(&buf, body, 1);
        prot_puts(pout, " (BODYPARTSTRUCTURE ");
        if (buf_len(&buf))
            prot_putbuf(pout, &buf);
        else
            prot_puts(pout, "NIL");
        prot_puts(pout, ")");
        buf_free(&buf);
    }

    if (params & URLFETCH_BODY) {
        prot_printf(pout, " (BODY");
    }
    else if (params & URLFETCH_BINARY) {
        prot_printf(pout, " (BINARY");
        if (!data) {
            /* failed to decode */
            prot_printf(pout, " NIL)");
            r = 0;
            goto done;
        }
    }
    else if (params) {
        r = 0;
        goto done;
    }

    /* Handle PARTIAL request */
    n = octet_count ? octet_count : size;

    /* Sanity check the requested size */
    if (start_octet > size) {
        start_octet = size;
        n = 0;
    }
    else if (start_octet + n < start_octet || start_octet + n > size) {
        n = size - start_octet;
    }

    if (n > maxsize) {
        r = IMAP_MESSAGE_TOO_LARGE;
        goto done;
    }

    if (outsize) {
        /* Return size (CATENATE) */
        *outsize = n;
    } else {
        domain = data_domain(data + start_octet, n);

        if (domain == DOMAIN_BINARY) {
            /* Write size of literal8 */
            prot_printf(pout, " ~{%lu}\r\n", n);
        } else {
            /* Write size of literal */
            prot_printf(pout, " {%lu}\r\n", n);
        }
    }

    /* Non-text literal -- tell the protstream about it */
    if (domain != DOMAIN_7BIT) prot_data_boundary(pout);

    if (n) prot_write(pout, data + start_octet, n);

    /* End of non-text literal -- tell the protstream about it */
    if (domain != DOMAIN_7BIT) prot_data_boundary(pout);

    /* Complete extended URLFETCH response */
    if (params) prot_printf(pout, ")");

    r = 0;

  done:
    /* Close the message file */
    index_unlock(state);
    buf_free(&buf);

    if (top) {
        message_free_body(top);
        free(top);
    }
    if (decbuf) free(decbuf);
    return r;

  badpart:
    r = IMAP_PROTOCOL_BAD_PARAMETERS;
    goto done;
}

/*
 * Helper function to perform a STORE command for flags.
 */
static int index_storeflag(struct index_state *state,
                           struct index_modified_flags *modified_flags,
                           uint32_t msgno, msgrecord_t *msgrec,
                           struct storeargs *storeargs)
{
    uint32_t old, new, keep;
    unsigned i;
    int dirty = 0;
    modseq_t oldmodseq;
    struct index_map *im = &state->map[msgno-1];
    int r;

    memset(modified_flags, 0, sizeof(struct index_modified_flags));

    oldmodseq = im->modseq;

    /* Change \Seen flag.  This gets done on the index first and will only be
       copied into the record later if internalseen is set */
    if (state->myrights & ACL_SETSEEN) {
        old = im->isseen ? 1 : 0;
        new = old;
        if (storeargs->operation == STORE_REPLACE_FLAGS)
            new = storeargs->seen ? 1 : 0;
        else if (storeargs->seen)
            new = (storeargs->operation == STORE_ADD_FLAGS) ? 1 : 0;

        if (new != old) {
            if (state->numunseen || new < old)
                state->numunseen += (old - new);
            else
                syslog(LOG_ERR, "IOERROR: numunseen underflow in storeflag: %s %u",
                       state->mboxname, im->uid);
            im->isseen = new;
            state->seen_dirty = 1;
            dirty++;
        }
    }

    uint32_t system_flags;
    uint32_t internal_flags;
    uint32_t user_flags[MAX_USER_FLAGS/32];

    r = msgrecord_get_systemflags(msgrec, &system_flags);
    if (r) return r;

    r = msgrecord_get_internalflags(msgrec, &internal_flags);
    if (r) return r;

    r = msgrecord_get_userflags(msgrec, user_flags);
    if (r) return r;

    keep = internal_flags;
    old = system_flags & FLAGS_SYSTEM;
    new = storeargs->system_flags & FLAGS_SYSTEM;

    /* all other updates happen directly to the record */
    if (storeargs->operation == STORE_REPLACE_FLAGS) {
        if (!(state->myrights & ACL_WRITE)) {
            /* ACL_DELETE handled in index_store() */
            if ((old & FLAG_DELETED) != (new & FLAG_DELETED)) {
                dirty++;
                system_flags = (old & ~FLAG_DELETED) | (new & FLAG_DELETED);
            }
        }
        else {
            if (!(state->myrights & ACL_DELETEMSG)) {
                if ((old & ~FLAG_DELETED) != (new & ~FLAG_DELETED)) {
                    dirty++;
                    system_flags = (old & FLAG_DELETED) | (new & ~FLAG_DELETED);
                }
            }
            else {
                if (old != new) {
                    dirty++;
                    system_flags = new;
                }
            }
            for (i = 0; i < (MAX_USER_FLAGS/32); i++) {
                if (user_flags[i] != storeargs->user_flags[i]) {
                    uint32_t changed;
                    dirty++;

                    changed = ~user_flags[i] & storeargs->user_flags[i];
                    if (changed) {
                        modified_flags->added_user_flags[i] = changed;
                        modified_flags->added_flags++;
                    }

                    changed = user_flags[i] & ~storeargs->user_flags[i];
                    if (changed) {
                        modified_flags->removed_user_flags[i] = changed;
                        modified_flags->removed_flags++;
                    }
                    user_flags[i] = storeargs->user_flags[i];
                }
            }
        }
    }
    else if (storeargs->operation == STORE_ADD_FLAGS) {
        uint32_t added;

        if (~old & new) {
            dirty++;
            system_flags = old | new;
        }
        for (i = 0; i < (MAX_USER_FLAGS/32); i++) {
            added = ~user_flags[i] & storeargs->user_flags[i];
            if (added) {
                dirty++;
                user_flags[i] |= storeargs->user_flags[i];

                modified_flags->added_user_flags[i] = added;
                modified_flags->added_flags++;
            }
        }
    }
    else { /* STORE_REMOVE_FLAGS */
        uint32_t removed;

        if (old & new) {
            dirty++;
            system_flags &= ~storeargs->system_flags;
        }
        for (i = 0; i < (MAX_USER_FLAGS/32); i++) {
            removed = user_flags[i] & storeargs->user_flags[i];
            if (removed) {
                dirty++;
                user_flags[i] &= ~storeargs->user_flags[i];

                modified_flags->removed_user_flags[i] = removed;
                modified_flags->removed_flags++;
            }
        }
    }

    /* RFC 4551:
     * 3.8.  Additional Quality-of-Implementation Issues
     *
     * Server implementations should follow the following rule, which
     * applies to any successfully completed STORE/UID STORE (with and
     * without UNCHANGEDSINCE modifier), as well as to a FETCH command that
     * implicitly sets \Seen flag:
     *
     *    Adding the flag when it is already present or removing when it is
     *    not present SHOULD NOT change the mod-sequence.
     *
     * This will prevent spurious client synchronization requests.
     */
    if (!dirty) return 0;

    if (state->internalseen) {
        /* copy the seen flag from the index */
        if (im->isseen)
            system_flags |= FLAG_SEEN;
        else
            system_flags &= ~FLAG_SEEN;
    }
    /* add back the internal tracking flags */
    system_flags |= keep;

    modified_flags->added_system_flags = ~old & system_flags & FLAGS_SYSTEM;
    if (modified_flags->added_system_flags)
        modified_flags->added_flags++;
    modified_flags->removed_system_flags = old & ~system_flags & FLAGS_SYSTEM;
    if (modified_flags->removed_system_flags)
        modified_flags->removed_flags++;

    r = msgrecord_set_systemflags(msgrec, system_flags);
    if (r) return r;
    r = msgrecord_set_internalflags(msgrec, internal_flags);
    if (r) return r;
    r = msgrecord_set_userflags(msgrec, user_flags);
    if (r) return r;

    /* if it's silent and unchanged, update the seen value, but
     * not if qresync is enabled - RFC 4551 says that the MODSEQ
     * must always been told, and we prefer just to tell flags
     * as well in this case, it's simpler and not much more
     * bandwidth */
    if (!(client_capa & CAPA_CONDSTORE) && storeargs->silent && im->told_modseq == oldmodseq)
        im->told_modseq = im->modseq;

    return 0;
}

/*
 * Helper function to perform a STORE command for annotations
 */
static int index_store_annotation(struct index_state *state,
                                  uint32_t msgno,
                                  msgrecord_t *msgrec,
                                  struct storeargs *storeargs,
                                  int *dirty)
{
    modseq_t oldmodseq;
    struct index_record *record;
    struct index_map *im = &state->map[msgno-1];
    int r;

    r = msgrecord_get_index_record_rw(msgrec, &record);
    if (r) goto out;

    r = index_reload_record(state, msgno, record);
    if (r) goto out;

    oldmodseq = record->modseq;

    r = msgrecord_annot_set_auth(msgrec, storeargs->isadmin, storeargs->userid,
                                 storeargs->authstate);
    if (r) goto out;

    r = msgrecord_annot_writeall(msgrec, storeargs->entryatts);
    if (r) goto out;

    /* It would be nice if the annotate layer told us whether it
     * actually made a change to the database, but it doesn't, so
     * we have to assume the message is dirty */
    *dirty = 1;

    r = index_rewrite_record(state, msgno, record, /*silent*/1);
    if (r) goto out;

    /* if it's silent and unchanged, update the seen value */
    if (!(client_capa & CAPA_CONDSTORE) && storeargs->silent && im->told_modseq == oldmodseq)
        im->told_modseq = im->modseq;

out:
    return r;
}


/*
 * Evaluate a searchargs structure on a msgno
 */
EXPORTED int index_search_evaluate(struct index_state *state,
                                   const search_expr_t *e,
                                   uint32_t msgno)
{
    struct index_map *im = &state->map[msgno-1];
    struct index_record record;

    int always = search_expr_always_same(e);
    if (always < 0) return 0;
    if (always > 0) return 1;

    // failure to load is an error!
    int r = index_reload_record(state, msgno, &record);
    if (r) return 0;

    xstats_inc(SEARCH_EVALUATE);

    int flags = (im->isrecent ? MESSAGE_RECENT : 0)
              | (im->isseen ? MESSAGE_SEEN : 0);
    if (state->m) message_set_from_index(state->mailbox, &record, msgno, flags, state->m);
    else state->m = message_new_from_index(state->mailbox, &record, msgno, flags);
    int match = search_expr_evaluate(state->m, e);

    return match;
}

struct extractor_ctx {
    struct protstream *clientin;
    char *hostname;
    char *path;
    struct backend *be;
};

struct getsearchtext_rock
{
    search_text_receiver_t *receiver;
    int indexed_headers;
    int charset_flags;
    const strarray_t *partids;
    int snippet_iteration; /* 0..no snippet, 1..first run, 2..second run */
    struct extractor_ctx *ext;
    strarray_t striphtml; /* strip HTML from these plain text body part ids */
    uint8_t indexlevel;
    int flags;
};

static void stuff_part(search_text_receiver_t *receiver,
                       int part, const struct buf *buf)
{
    // don't try to index a zero length part
    if (!buf_len(buf)) return;

    if (part == SEARCH_PART_HEADERS &&
        !config_getswitch(IMAPOPT_SEARCH_INDEX_HEADERS))
        return;

    receiver->begin_part(receiver, part);
    receiver->append_text(receiver, buf);
    receiver->end_part(receiver, part);
}

static int extract_cb(const struct buf *text, void *rock)
{
    struct getsearchtext_rock *str = (struct getsearchtext_rock *)rock;
    return str->receiver->append_text(str->receiver, text);
}

#ifdef USE_HTTPD
static int extract_icalbuf(struct buf *raw, charset_t charset, int encoding,
                           struct getsearchtext_rock *str)
{
    icalcomponent *comp = NULL, *ical = NULL;
    const char *s;
    int r = 0;
    struct buf buf = BUF_INITIALIZER;

    /* Parse the message into an iCalendar object */
    const struct buf *icalbuf = NULL;
    if (encoding || strcasecmp(charset_canon_name(charset), "utf-8")) {
        char *tmp = charset_to_utf8(buf_cstring(raw), buf_len(raw), charset, encoding);
        if (!tmp) return 0; /* could be a bogus header - ignore */
        buf_initm(&buf, tmp, strlen(tmp));
        icalbuf = &buf;
    }
    else {
        icalbuf = raw;
    }
    ical = icalparser_parse_string(buf_cstring(icalbuf));
    buf_reset(&buf);
    if (!ical) {
        r = IMAP_INTERNAL;
        goto done;
    }

    for (comp = icalcomponent_get_first_real_component(ical);
         comp;
         comp = icalcomponent_get_next_component(ical, icalcomponent_isa(comp))) {

        icalproperty *prop;
        icalparameter *param;

        /* description */
        if ((s = icalcomponent_get_description(comp))) {
            buf_setcstr(&buf, s);
            charset_t utf8 = charset_lookupname("utf-8");
            str->receiver->begin_part(str->receiver, SEARCH_PART_BODY);
            charset_extract(extract_cb, str, &buf, utf8, 0, "calendar",
                            str->charset_flags);
            str->receiver->end_part(str->receiver, SEARCH_PART_BODY);
            charset_free(&utf8);
            buf_reset(&buf);
        }

        /* summary */
        if ((prop = icalcomponent_get_first_property(comp, ICAL_SUMMARY_PROPERTY))) {
            if ((s = icalproperty_get_summary(prop))) {
                buf_setcstr(&buf, s);
                stuff_part(str->receiver, SEARCH_PART_SUBJECT, &buf);
                buf_reset(&buf);
            }
        }

        /* organizer */
        if ((prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY))) {
            if ((s = icalproperty_get_organizer(prop))) {
                if (!strncasecmp(s, "mailto:", 7)) {
                    s += 7;
                }
                param = icalproperty_get_first_parameter(prop, ICAL_CN_PARAMETER);
                if (param) {
                    buf_printf(&buf, "\"%s\" <%s>", icalparameter_get_cn(param), s);
                } else {
                    buf_setcstr(&buf, s);
                }
                stuff_part(str->receiver, SEARCH_PART_FROM, &buf);
                buf_reset(&buf);
            }
        }

        /* attendees */
        for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY)) {
            if ((s = icalproperty_get_attendee(prop))) {
                if (!strncasecmp(s, "mailto:", 7)) {
                    s += 7;
                }
                param = icalproperty_get_first_parameter(prop, ICAL_CN_PARAMETER);
                if (buf.len) {
                    buf_appendcstr(&buf, ", ");
                }
                if (param) {
                    buf_printf(&buf, "\"%s\" <%s>", icalparameter_get_cn(param), s);
                } else {
                    buf_appendcstr(&buf, s);
                }
            }
        }
        if (buf.len) {
            stuff_part(str->receiver, SEARCH_PART_TO, &buf);
            buf_reset(&buf);
        }

        /* location */
        if ((prop = icalcomponent_get_first_property(comp, ICAL_LOCATION_PROPERTY))) {
            if ((s = icalproperty_get_location(prop))) {
                buf_setcstr(&buf, s);
                stuff_part(str->receiver, SEARCH_PART_LOCATION, &buf);
                buf_reset(&buf);
            }
        }
    }

done:
    if (ical) icalcomponent_free(ical);
    buf_free(&buf);
    return r;
}

static void _add_vcard_singlval(struct vparse_card *card, const char *key, struct buf *buf)
{
    struct vparse_entry *entry;
    for (entry = card->properties; entry; entry = entry->next) {
        if (strcasecmp(entry->name, key)) continue;
        const char *val = entry->v.value;
        if (val && val[0]) {
            if (buf_len(buf)) buf_putc(buf, ' ');
            buf_appendcstr(buf, val);
        }
    }
}

static void _add_vcard_multival(struct vparse_card *card, const char *key, struct buf *buf)
{
    struct vparse_entry *entry;
    for (entry = card->properties; entry; entry = entry->next) {
        if (strcasecmp(entry->name, key)) continue;
        const strarray_t *sa = entry->v.values;
        int i;
        for (i = 0; i < strarray_size(sa); i++) {
            const char *val = strarray_nth(sa, i);
            if (val && val[0]) {
                if (buf_len(buf)) buf_putc(buf, ' ');
                buf_appendcstr(buf, val);
            }
        }
    }
}

static int extract_vcardbuf(struct buf *raw, charset_t charset, int encoding,
                            struct getsearchtext_rock *str)
{
    struct vparse_card *vcard = NULL;
    int r = 0;
    struct buf buf = BUF_INITIALIZER;

    /* Parse the message into a vcard object */
    const struct buf *vcardbuf = NULL;
    if (encoding || strcasecmp(charset_canon_name(charset), "utf-8")) {
        char *tmp = charset_to_utf8(buf_cstring(raw), buf_len(raw), charset, encoding);
        if (!tmp) return 0; /* could be a bogus header - ignore */
        buf_initm(&buf, tmp, strlen(tmp));
        vcardbuf = &buf;
    }
    else {
        vcardbuf = raw;
    }

    vcard = vcard_parse_string(buf_cstring(vcardbuf));
    if (!vcard || !vcard->objects) {
        r = IMAP_INTERNAL;
        goto done;
    }

    buf_reset(&buf);

    // these are all the things that we think might be interesting
    _add_vcard_singlval(vcard->objects, "fn", &buf);
    _add_vcard_singlval(vcard->objects, "email", &buf);
    _add_vcard_singlval(vcard->objects, "tel", &buf);
    _add_vcard_singlval(vcard->objects, "url", &buf);
    _add_vcard_singlval(vcard->objects, "impp", &buf);
    _add_vcard_singlval(vcard->objects, "x-social-profile", &buf);
    _add_vcard_singlval(vcard->objects, "x-fm-online-other", &buf);
    _add_vcard_singlval(vcard->objects, "nickname", &buf);
    _add_vcard_singlval(vcard->objects, "note", &buf);

    _add_vcard_multival(vcard->objects, "n", &buf);
    _add_vcard_multival(vcard->objects, "org", &buf);
    _add_vcard_multival(vcard->objects, "adr", &buf);

    if (buf.len) {
        charset_t utf8 = charset_lookupname("utf-8");
        str->receiver->begin_part(str->receiver, SEARCH_PART_BODY);
        charset_extract(extract_cb, str, &buf, utf8, 0, "vcard",
                        str->charset_flags);
        str->receiver->end_part(str->receiver, SEARCH_PART_BODY);
        charset_free(&utf8);
        buf_reset(&buf);
    }

done:
    if (vcard) vparse_free_card(vcard);
    buf_free(&buf);
    return r;
}

#endif /* USE_HTTPD */


#define IDLE_TIMEOUT (5 * 60)  /* 5 min */

static int login(struct backend *s __attribute__((unused)),
                 const char *userid __attribute__((unused)),
                 sasl_callback_t *cb __attribute__((unused)),
                 const char **status __attribute__((unused)),
                 int noauth __attribute__((unused)))
{
    return 0;
}

static int ping(struct backend *s __attribute__((unused)),
                const char *userid __attribute__((unused)))
{
    return 0;
}

static int logout(struct backend *s __attribute__((unused)))
{
    return 0;
}

static void extractor_disconnect(struct extractor_ctx *ext)
{
    if (!ext) return;

    struct backend *be = ext->be;
    syslog(LOG_DEBUG, "extractor_disconnect(%p)", be);

    if (!be || (be->sock == -1)) {
        /* already disconnected */
        return;
    }

    /* need to logout of server */
    backend_disconnect(be);

    /* remove the timeout */
    if (be->timeout) prot_removewaitevent(be->clientin, be->timeout);
    be->timeout = NULL;
    be->clientin = NULL;
}

static struct prot_waitevent *
extractor_timeout(struct protstream *s __attribute__((unused)),
                  struct prot_waitevent *ev __attribute__((unused)),
                  void *rock)
{
    struct extractor_ctx *ext = rock;

    syslog(LOG_DEBUG, "extractor_timeout(%p)", ext);

    /* too long since we last used the extractor - disconnect */
    extractor_disconnect(ext);

    return NULL;
}

static struct protocol_t http =
{ "http", "HTTP", TYPE_SPEC, { .spec = { &login, &ping, &logout } } };

static int extractor_connect(struct extractor_ctx *ext)
{
    struct backend *be;
    time_t now = time(NULL);

    syslog(LOG_DEBUG, "extractor_connect()");

    be = ext->be;
    if (be && be->sock != -1) {
        // extend the timeout
        if (be->timeout) be->timeout->mark = now + IDLE_TIMEOUT;
        return 0;
    }

    // clean up any existing connection
    extractor_disconnect(ext);
    be = ext->be = backend_connect(be, ext->hostname,
                                   &http, NULL, NULL, NULL, -1);

    if (!be) {
        syslog(LOG_ERR, "extract_connect: failed to connect to %s",
               ext->hostname);
        return IMAP_IOERROR;
    }

    if (ext->clientin) {
        /* add a default timeout */
        be->clientin = ext->clientin;
        be->timeout = prot_addwaitevent(ext->clientin,
                                        now + IDLE_TIMEOUT,
                                        extractor_timeout, ext);
    }

    return 0;
}

static int extract_attachment(const char *type, const char *subtype,
                              const struct param *type_params,
                              const struct buf *data, int encoding,
                              const struct message_guid *content_guid,
                              struct getsearchtext_rock *str)
{
    struct backend *be;
    struct buf decbuf = BUF_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    hdrcache_t hdrs = NULL;
    struct body_t body = { 0, 0, 0, 0, 0, BUF_INITIALIZER };
    const char *guidstr, *errstr = NULL;
    size_t hostlen;
    const char **hdr, *p;
    int r = 0;

    if (!index_text_extractor) {
        /* This is a legitimate case for sieve and lmtpd (so we don't need
         * to spam the logs! */
        syslog(LOG_DEBUG, "%s: ignoring uninitialized extractor",
                __func__);
        return 0;
    }

    if (message_guid_isnull(content_guid)) {
        syslog(LOG_DEBUG, "extract_attachment: ignoring null guid for %s/%s",
               type ? type : "<null>", subtype ? subtype : "<null>");
        return 0;
    }

    struct extractor_ctx *ext = str->ext = index_text_extractor;

    r = extractor_connect(ext);
    if (r) return r;
    be = ext->be;

    hostlen = strcspn(ext->hostname, "/");
    guidstr = message_guid_encode(content_guid);

    /* try to fetch previously extracted text */
    unsigned statuscode = 0;
    prot_printf(be->out,
                "GET %s/%s %s\r\n"
                "Host: %.*s\r\n"
                "User-Agent: Cyrus/%s\r\n"
                "Connection: Keep-Alive\r\n"
                "Keep-Alive: timeout=%u\r\n"
                "Accept: text/plain\r\n"
                "X-Truncate-Length: " SIZE_T_FMT "\r\n"
                "\r\n",
                ext->path, guidstr, HTTP_VERSION,
                (int) hostlen, be->hostname, CYRUS_VERSION,
                IDLE_TIMEOUT, config_search_maxsize);
    prot_flush(be->out);

    /* Read GET response */
    do {
        r = http_read_response(be, METH_GET,
                               &statuscode, &hdrs, &body, &errstr);
        if (r) {
            syslog(LOG_ERR,
                   "extract_attachment: failed to read response for GET %s/%s",
                   ext->path, guidstr);
            statuscode = 599;
        }
    } while (statuscode < 200);

    syslog(LOG_DEBUG, "extract_attachment: GET %s/%s: got status %u",
           ext->path, guidstr, statuscode);

    if (statuscode == 200) goto gotdata;

    // otherwise we're going to try three times to PUT this request to the server!

    /* Decode data */
    if (encoding) {
        if (charset_decode(&decbuf, buf_base(data), buf_len(data), encoding)) {
            syslog(LOG_ERR, "extract_attachment: failed to decode data");
            r = IMAP_IOERROR;
            goto done;
        }
        data = &decbuf;
    }

    /* Build list of Content-Type parameters */
    const struct param *param;
    for (param = type_params; param && param->attribute; param = param->next) {
        /* Ignore all but select parameters */
        if (strcmp(param->attribute, "charset")) {
            continue;
        }
        buf_putc(&buf, ';');
        buf_appendcstr(&buf, param->attribute);
        if (param->value) {
            buf_putc(&buf, '=');
            buf_appendcstr(&buf, param->value);
        }
    }

    int retry;
    for (retry = 0; retry < 3; retry++) {
        if (retry) {
            // second and third time around, sleep and reconnect
            sleep(retry);
            extractor_disconnect(ext);
            r = extractor_connect(ext);
            if (r) continue;
            be = ext->be;
        }

        /* Send attachment to service for text extraction */
        prot_printf(be->out,
                    "PUT %s/%s %s\r\n"
                    "Host: %.*s\r\n"
                    "User-Agent: Cyrus/%s\r\n"
                    "Connection: Keep-Alive\r\n"
                    "Keep-Alive: timeout=%u\r\n"
                    "Accept: text/plain\r\n"
                    "Content-Type: %s/%s%s\r\n"
                    "Content-Length: " SIZE_T_FMT "\r\n"
                    "X-Truncate-Length: " SIZE_T_FMT "\r\n"
                    "\r\n",
                    ext->path, guidstr, HTTP_VERSION,
                    (int) hostlen, be->hostname, CYRUS_VERSION, IDLE_TIMEOUT,
                    type, subtype, buf_cstring(&buf), buf_len(data),
                    config_search_maxsize);
        prot_putbuf(be->out, data);
        prot_flush(be->out);

        /* Read PUT response */
        body.flags = 0;
        do {
            r = http_read_response(be, METH_PUT,
                                   &statuscode, &hdrs, &body, &errstr);
            if (r) {
                syslog(LOG_ERR,
                       "extract_attachment: failed to read response for PUT %s/%s",
                       ext->path, guidstr);
                statuscode = 599;
            }
        } while (statuscode < 200);

        syslog(LOG_DEBUG, "extract_attachment: PUT %s/%s: got status %u",
               ext->path, guidstr, statuscode);

        if (statuscode == 200 || statuscode == 201) {
            // we got a result, yay
            goto gotdata;
        }

        if (statuscode >= 400 && statuscode <= 499) {
            /* indexer can't extract this for some reason, never try again */
            goto done;
        }

        /* any other status code is an error */
        syslog(LOG_ERR, "extract GOT STATUSCODE %d with timeout %d: %s", statuscode, IDLE_TIMEOUT, errstr);
    }

    // dropped out of the loop?  Then we failed!
    r = IMAP_IOERROR;
    goto done;

gotdata:
    /* Abide by server's timeout, if any */
    if ((hdr = spool_getheader(hdrs, "Keep-Alive")) &&
        (p = strstr(hdr[0], "timeout="))) {
        int timeout = atoi(p+8);
        if (be->timeout) be->timeout->mark = time(NULL) + timeout;
    }
    /* Append extracted text */
    if (buf_len(&body.payload)) {
        str->receiver->begin_part(str->receiver, SEARCH_PART_ATTACHMENTBODY);
        str->receiver->append_text(str->receiver, &body.payload);
        str->receiver->end_part(str->receiver, SEARCH_PART_ATTACHMENTBODY);
    }

done:
    spool_free_hdrcache(hdrs);
    buf_free(&body.payload);
    buf_free(&buf);
    buf_free(&decbuf);
    return r;
}

EXPORTED void index_text_extractor_init(struct protstream *clientin)
{
    const char *exturl =
         config_getstring(IMAPOPT_SEARCH_ATTACHMENT_EXTRACTOR_URL);
    if (!exturl) return;

    syslog(LOG_DEBUG, "extractor_init(%p)", clientin);

    char scheme[6], server[100], path[256], *p;
    unsigned https, port;

    /* Parse URL (cheesy parser without having to use libxml2) */
    int n = sscanf(exturl, "%5[^:]://%99[^/]%255[^\n]",
                   scheme, server, path);
    if (n != 3 ||
        strncmp(lcase(scheme), "http", 4) || (scheme[4] && scheme[4] != 's')) {
        syslog(LOG_ERR,
               "extract_attachment: unexpected non-HTTP URL %s", exturl);
        return;
    }

    /* Normalize URL parts */
    https = (scheme[4] == 's');
    if (*(p = path + strlen(path) - 1) == '/') *p = '\0';
    if ((p = strrchr(server, ':'))) {
        *p++ = '\0';
        port = atoi(p);
    }
    else port = https ? 443 : 80;

    /* Build servername, port, and options */
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, "%s:%u%s/noauth", server, port, https ? "/tls" : "");

    index_text_extractor = xzmalloc(sizeof(struct extractor_ctx));
    index_text_extractor->clientin = clientin;
    index_text_extractor->path = xstrdup(path);
    index_text_extractor->hostname = buf_release(&buf);
}

EXPORTED void index_text_extractor_destroy(void)
{
    struct extractor_ctx *ext = index_text_extractor;

    syslog(LOG_DEBUG, "extractor_destroy(%p)", ext);

    if (!ext) return;

    extractor_disconnect(ext);
    free(ext->be);
    free(ext->hostname);
    free(ext->path);
    free(ext);

    index_text_extractor = NULL;
}


static int getsearchtext_cb(int isbody, charset_t charset, int encoding,
                            const char *type, const char *subtype,
                            const struct param *type_params __attribute__((unused)),
                            const char *disposition,
                            const struct param *disposition_params,
                            const struct message_guid *content_guid,
                            const char *partid,
                            struct buf *data,
                            void *rock)
{
    struct getsearchtext_rock *str = (struct getsearchtext_rock *)rock;
    char *q;
    struct buf text = BUF_INITIALIZER;
    int r = 0;

    if (isbody && partid && str->partids && strarray_find(str->partids, partid, 0) < 0) {
        /* Skip part */
        return 0;
    }

    if (str->receiver->begin_bodypart) {
        str->receiver->begin_bodypart(str->receiver,
                partid, content_guid, type, subtype);
    }

    if (!isbody) {

        if (str->snippet_iteration >= 2) goto done;

        if (!str->indexed_headers) {
            /* Only index the headers of the top message */
            q = charset_decode_mimeheader(buf_cstring(data), str->charset_flags);
            buf_init_ro_cstr(&text, q);
            stuff_part(str->receiver, SEARCH_PART_HEADERS, &text);
            free(q);
            buf_free(&text);
            str->indexed_headers = 1;
        }

        /* Index attachment file names */
        const struct param *param;
        if (disposition && !strcmp(disposition, "ATTACHMENT")) {
            /* Look for "Content-Disposition: attachment;filename=" header */
            for (param = disposition_params; param; param = param->next) {
                if (!strcmp(param->attribute, "FILENAME")) {
                    char *tmp = charset_decode_mimeheader(param->value, str->charset_flags);
                    buf_init_ro_cstr(&text, tmp);
                    stuff_part(str->receiver, SEARCH_PART_ATTACHMENTNAME, &text);
                    buf_free(&text);
                    free(tmp);
                }
                else if (!strcmp(param->attribute, "FILENAME*")) {
                    char *xval = charset_parse_mimexvalue(param->value, NULL);
                    if (!xval) xval = xstrdup(param->value);
                    if (xval) {
                        char *tmp = charset_decode_mimeheader(xval, str->charset_flags|CHARSET_MIME_UTF8);
                        buf_init_ro_cstr(&text, tmp);
                        stuff_part(str->receiver, SEARCH_PART_ATTACHMENTNAME, &text);
                        buf_free(&text);
                        free(tmp);
                        free(xval);
                    }
                }
            }
        }
        for(param = type_params; param; param = param->next) {
            /* Look for "Content-Type: foo;name=" header */
            if (strcmp(param->attribute, "NAME"))
                continue;
            char *tmp = charset_decode_mimeheader(param->value, str->charset_flags);
            buf_init_ro_cstr(&text, tmp);
            stuff_part(str->receiver, SEARCH_PART_ATTACHMENTNAME, &text);
            buf_free(&text);
            free(tmp);
        }


    }
    else if (buf_len(data) > 50 && !memcmp(data->s, "-----BEGIN PGP MESSAGE-----", 27)) {
        /* PGP encrypted body part - we don't want to index this,
         * it's a ton of random base64 noise */
    }
    else if (isbody && !strcmp(type, "TEXT") && strcmpsafe(subtype, "RTF")) {

        if (str->snippet_iteration >= 2) goto done;

        if (!strcmp(subtype, "CALENDAR")) {
#ifdef USE_HTTPD
            extract_icalbuf(data, charset, encoding, str);
#endif /* USE_HTTPD */
        }
        else if (!strcmp(subtype, "VCARD")) {
#ifdef USE_HTTPD
            extract_vcardbuf(data, charset, encoding, str);
#endif /* USE_HTTPD */
        }
        else {
            /* body-like */
            int mycharset_flags = str->charset_flags;
            const char *mysubtype = subtype;

            if (!strcmpsafe(subtype, "PLAIN") && partid &&
                    strarray_find(&str->striphtml, partid, 0) >= 0) {
                /* Strip any HTML tags from plain text before indexing */
                mycharset_flags &= ~(CHARSET_SKIPHTML|CHARSET_KEEPHTML);
                mysubtype = "HTML";
            }

            str->receiver->begin_part(str->receiver, SEARCH_PART_BODY);
            charset_extract(extract_cb, str, data, charset, encoding, mysubtype,
                           mycharset_flags);
            str->receiver->end_part(str->receiver, SEARCH_PART_BODY);
        }
    }
    else if (isbody && (!strcmp(type, "APPLICATION") || !strcmp(type, "TEXT"))) {

#ifdef USE_HTTPD
        // application/ics is an alias for text/icalendar
        if (!strcmp(subtype, "ICS")) {
            extract_icalbuf(data, charset, encoding, str);
            goto done;
        }
#endif /* USE_HTTPD */

        // these are encrypted fields which aren't worth indexing
        if (!strcmp(subtype, "PKCS7-MIME")) goto done;
        if (!strcmp(subtype, "PKCS7-ENCRYPTED")) goto done;
        if (!strcmp(subtype, "PKCS7-SIGNATURE")) goto done;
        if (!strcmp(subtype, "PGP-SIGNATURE")) goto done;
        if (!strcmp(subtype, "PGP-KEYS")) goto done;
        if (!strcmp(subtype, "PGP-ENCRYPTED")) goto done;

        /* Ignore attachments in first snippet generation pass */
        if (str->snippet_iteration == 1) goto done;

        /* Only generate snippets from named attachment parts */
        if (str->snippet_iteration >= 2 && !str->partids) goto done;

        if (!config_getstring(IMAPOPT_SEARCH_ATTACHMENT_EXTRACTOR_URL)) {
            /* Message has attachment, but no extractor is configured */
            str->indexlevel = 1;
            goto done;
        }

        r = extract_attachment(type, subtype, type_params, data, encoding,
                               content_guid, str);
        if (r) {
            syslog(LOG_ERR, "IOERROR index: can't extract attachment %s (%s/%s): %s",
                    message_guid_encode(content_guid),
                    type, subtype, error_message(r));

            if (str->flags & INDEX_GETSEARCHTEXT_PARTIALS) {
                /* mark message as partially indexed and continue */
                str->indexlevel |= SEARCH_INDEXLEVEL_PARTIAL;
                r = 0;
            }
        }
    }

done:
    if (str->receiver->end_bodypart) {
        str->receiver->end_bodypart(str->receiver);
    }
    return r;
}

static int find_striphtml_parts(message_t *msg, strarray_t *striphtml)
{
    const struct body *root;
    int r = message_get_cachebody(msg, &root);
    if (r) return r;

    ptrarray_t submsgs = PTRARRAY_INITIALIZER;
    ptrarray_t work = PTRARRAY_INITIALIZER;

    /* Add top-level message and find all rfc822 messages */
    ptrarray_push(&submsgs, (void*)root);
    ptrarray_push(&work, (void*) root);
    const struct body *body;
    while ((body = ptrarray_pop(&work))) {
        if (!strcmpsafe(body->type, "MESSAGE") &&
            !strcmpsafe(body->subtype, "RFC822")) {
            ptrarray_push(&submsgs, (void*)body);
        }
        int i;
        for (i = 0; i < body->numparts; i++) {
            ptrarray_push(&work, body->subpart + i);
        }
    }

    /* Process top-level and each embedded message separately */
    while ((root = ptrarray_pop(&submsgs))) {
        /* Check if submsg has any HTML part */
        int has_htmlpart = 0;
        int i;
        for (i = 0; i < root->numparts; i++) {
            ptrarray_push(&work, root->subpart + i);
        }
        while ((body = ptrarray_pop(&work))) {
            if (!strcmpsafe(body->type, "TEXT") &&
                !strcmpsafe(body->subtype, "HTML") &&
                (!body->disposition || !strcmp(body->disposition, "INLINE"))) {
                has_htmlpart = 1;
                break;
            }
            else if (!strcmpsafe(body->type, "MESSAGE") &&
                     !strcmpsafe(body->subtype, "RFC822")) {
                continue;
            }
            else if (body->numparts) {
                for (i = 0; i < body->numparts; i++) {
                    ptrarray_push(&work, body->subpart + i);
                }
            }
        }

        if (!has_htmlpart) continue;

        /* Keep track of plain text body part ids that
         * coexist with HTML bodies in the same submsg */

        for (i = 0; i < root->numparts; i++) {
            ptrarray_push(&work, root->subpart + i);
        }
        while ((body = ptrarray_pop(&work))) {
            if (!strcmpsafe(body->type, "TEXT") &&
                !strcmpsafe(body->subtype, "PLAIN")) {
                if (body->part_id) {
                    strarray_push(striphtml, body->part_id);
                }
            }
            else if (!strcmpsafe(body->type, "MESSAGE") &&
                     !strcmpsafe(body->subtype, "RFC822")) {
                continue;
            }
            else if (body->numparts) {
                int i;
                for (i = 0; i < body->numparts; i++) {
                    ptrarray_push(&work, body->subpart + i);
                }
            }
        }
    }

    ptrarray_fini(&submsgs);
    ptrarray_fini(&work);

    return 0;
}

EXPORTED int index_getsearchtext(message_t *msg, const strarray_t *partids,
                                 search_text_receiver_t *receiver,
                                 int flags)
{
    struct getsearchtext_rock str;
    struct buf buf = BUF_INITIALIZER;
    int format = MESSAGE_SEARCH;
    strarray_t types = STRARRAY_INITIALIZER;
    const char *type = NULL, *subtype = NULL;
    int i;
    int r;

    /* Determine Content-Type */
    r = message_get_type(msg, &type);
    if (r) return r;
    r = message_get_subtype(msg, &subtype);
    if (r) return r;

    /* Set up search receiver */
    r = receiver->begin_message(receiver, msg);
    if (r) return r;

    memset(&str, 0, sizeof(struct getsearchtext_rock));
    str.receiver = receiver;
    str.indexed_headers = 0;
    str.charset_flags = charset_flags;
    str.partids = partids;
    str.snippet_iteration = 0;
    str.flags = flags;
    str.indexlevel = SEARCH_INDEXLEVEL_ATTACH; // may get downgraded in callback

    /* Search receiver can override text conversion */
    if (receiver->index_charset_flags) {
        str.charset_flags = receiver->index_charset_flags(str.charset_flags);
    }

    if (flags & INDEX_GETSEARCHTEXT_SNIPPET) {
        str.charset_flags |= CHARSET_KEEPCASE;
        format = MESSAGE_SNIPPET;
    }

    /* Search receiver can override message field conversion */
    if (receiver->index_message_format) {
        format = receiver->index_message_format(format,
                flags & INDEX_GETSEARCHTEXT_SNIPPET);
    }

    /* Extract headers */
    if (!message_get_field(msg, "From", format, &buf))
        stuff_part(receiver, SEARCH_PART_FROM, &buf);

    if (!message_get_field(msg, "To", format, &buf))
        stuff_part(receiver, SEARCH_PART_TO, &buf);

    if (!message_get_field(msg, "Cc", format, &buf))
        stuff_part(receiver, SEARCH_PART_CC, &buf);

    if (!message_get_field(msg, "Bcc", format, &buf))
        stuff_part(receiver, SEARCH_PART_BCC, &buf);

    if (!message_get_field(msg, "Subject", format, &buf))
        stuff_part(receiver, SEARCH_PART_SUBJECT, &buf);

    if (!message_get_field(msg, "List-Id", format, &buf))
        stuff_part(receiver, SEARCH_PART_LISTID, &buf);

    if (!message_get_field(msg, "Mailing-List", format, &buf))
        stuff_part(receiver, SEARCH_PART_LISTID, &buf);

    if (!message_get_field(msg, "Mailing-List", format, &buf))
        stuff_part(receiver, SEARCH_PART_LISTID, &buf);

    if (!message_get_deliveredto(msg, &buf))
        stuff_part(receiver, SEARCH_PART_DELIVEREDTO, &buf);

    if (!message_get_priority(msg, &buf))
        stuff_part(receiver, SEARCH_PART_PRIORITY, &buf);

    if (!message_get_leaf_types(msg, &types) && types.count) {
        for (i = 0 ; i < types.count ; i+= 2) {
            receiver->begin_part(receiver, SEARCH_PART_TYPE);
            buf_setcstr(&buf, types.data[i]);
            buf_putc(&buf, '/');
            buf_appendcstr(&buf, types.data[i+1]);
            receiver->append_text(receiver, &buf);
            receiver->end_part(receiver, SEARCH_PART_TYPE);
        }
    }

    /* Determine when to strip HTML from plain text */
    find_striphtml_parts(msg, &str.striphtml);

    /* Generate snippets in two passes. */
    if (flags & INDEX_GETSEARCHTEXT_SNIPPET) {
        str.snippet_iteration = 1; /* first pass */
    }

    /* Traverse bodies */
    r = message_foreach_section(msg, getsearchtext_cb, &str);
    if (!r && str.snippet_iteration) {
        if (receiver->flush) {
            r = receiver->flush(receiver);
        }
        if (!r) {
            str.snippet_iteration = 2;
            r = message_foreach_section(msg, getsearchtext_cb, &str);
        }
        if (r == IMAP_OK_COMPLETED) r = 0;
    }
    if (r) goto done;

    /* Finalize message. */
    r = receiver->end_message(receiver, str.indexlevel);

    if (r == IMAP_OK_COMPLETED) r = 0;

    /* Log erroneous or partially indexed message */
    if (r || (str.indexlevel & SEARCH_INDEXLEVEL_PARTIAL)) {
        struct mailbox *mailbox = msg_mailbox(msg);
        uint32_t uid = 0;
        message_get_uid(msg, &uid);
        const char *mboxname = mailbox ? mailbox_name(mailbox) : "";
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: failed to index msg",
                    "mailbox=<%s> uid=<%d> r=<%s>",
                    mboxname, uid, error_message(r));
        }
        else {
            xsyslog(LOG_ERR,  "IOERROR: partially indexed msg",
                    "mailbox=<%s> uid=<%d>", mboxname, uid);
        }
    }

done:
    buf_free(&buf);
    strarray_fini(&types);
    strarray_fini(&str.striphtml);

    return r;
}

/*
 * Helper function to set up arguments to append_copy()
 */
#define COPYARGSGROW 30
static int index_copysetup(struct index_state *state, uint32_t msgno,
                           struct copyargs *copyargs)
{
    struct index_map *im = &state->map[msgno-1];
    int r;

    if (copyargs->nummsg == copyargs->msgalloc) {
        copyargs->msgalloc += COPYARGSGROW;
        copyargs->records = (struct index_record *)
          xrealloc((char *)copyargs->records,
                   copyargs->msgalloc * sizeof(struct index_record));
    }

    r = index_reload_record(state, msgno, &copyargs->records[copyargs->nummsg]);
    if (r) return r;

    /* seen is per user - embed it in the record */
    if (im->isseen)
        copyargs->records[copyargs->nummsg].system_flags |= FLAG_SEEN;
    else
        copyargs->records[copyargs->nummsg].system_flags &= ~FLAG_SEEN;

    if (state->want_expunged && (im->internal_flags & FLAG_INTERNAL_EXPUNGED)) {
        copyargs->records[copyargs->nummsg].system_flags &= ~FLAG_DELETED;
        copyargs->records[copyargs->nummsg].internal_flags &= ~FLAG_INTERNAL_EXPUNGED;
    }

    copyargs->nummsg++;

    return 0;
}

/*
 * Creates a list, and optionally also an array of pointers to, of msgdata.
 *
 * We fill these structs with the processed info that will be needed
 * by the specified sort criteria.
 */
MsgData **index_msgdata_load(struct index_state *state,
                             unsigned *msgno_list, int n,
                             const struct sortcrit *sortcrit,
                             unsigned int anchor, int *found_anchor)
{
    MsgData **ptrs, *md, *cur;
    int i, j;
    char *tmpenv;
    char *envtokens[NUMENVTOKENS];
    int did_cache, did_env, did_conv;
    int label;
    struct mailbox *mailbox = state->mailbox;
    struct index_record record;
    struct conversations_state *cstate = NULL;
    conversation_t conv = CONVERSATION_INIT;
    int *preload = NULL;

    if (!n) return NULL;

    /* create an array of MsgData */
    ptrs = (MsgData **) xzmalloc(n * sizeof(MsgData *) + n * sizeof(MsgData));
    md = (MsgData *)(ptrs + n);
    xstats_add(MSGDATA_LOAD, n);

    if (found_anchor)
        *found_anchor = 0;

    /* set mailbox level states */
    for (j = 0; sortcrit[j].key; j++); // count how many we need
    if (j) preload = xzmalloc(j * sizeof(int));
    for (j = 0; sortcrit[j].key; j++) {
        label = sortcrit[j].key;
        switch(label) {
        case SORT_SAVEDATE:
#ifdef WITH_JMAP
        case SORT_SNOOZEDUNTIL:
#endif
            preload[j] = !strcmpnull(mailbox_uniqueid(mailbox), sortcrit[j].args.mailbox.id);
            break;

        case SORT_HASCONVFLAG:
            preload[j] = -1;
            if (!cstate) cstate = conversations_get_mbox(index_mboxname(state));
            assert(cstate);
            if (cstate->counted_flags)
                preload[j] = strarray_find_case(cstate->counted_flags, sortcrit[j].args.flag.name, 0);
            break;

        default:
            break;
        }
    }

    for (i = 0 ; i < n ; i++) {
        cur = &md[i];
        ptrs[i] = cur;

        /* set msgno */
        cur->msgno = (msgno_list ? msgno_list[i] : (unsigned)(i+1));

        if (index_reload_record(state, cur->msgno, &record))
            continue;

        cur->uid = record.uid;
        cur->cid = record.cid;
        cur->system_flags = record.system_flags;
        cur->internal_flags = record.internal_flags;
        message_guid_copy(&cur->guid, &record.guid);
        if (found_anchor && record.uid == anchor)
            *found_anchor = 1;

        /* useful for convupdates */
        cur->modseq = record.modseq;

        did_cache = did_env = did_conv = 0;
        tmpenv = NULL;

        for (j = 0; sortcrit[j].key; j++) {
            label = sortcrit[j].key;

            if ((label == SORT_CC ||
                 label == SORT_FROM || label == SORT_SUBJECT ||
                 label == SORT_TO || label == LOAD_IDS ||
                 label == SORT_DISPLAYFROM || label == SORT_DISPLAYTO ||
                 label == SORT_SPAMSCORE) &&
                !did_cache) {

                /* fetch cached info */
                if (mailbox_cacherecord(mailbox, &record))
                    continue; /* can't do this with a broken cache */

                did_cache++;
            }

            if ((label == LOAD_IDS) && !did_env) {
                /* no point if we don't have enough data */
                if (cacheitem_size(&record, CACHE_ENVELOPE) <= 2)
                    continue;

                /* make a working copy of envelope -- strip outer ()'s */
                /* +1 -> skip the leading paren */
                /* -2 -> don't include the size of the outer parens */
                tmpenv = xstrndup(cacheitem_base(&record, CACHE_ENVELOPE) + 1,
                                  cacheitem_size(&record, CACHE_ENVELOPE) - 2);

                /* parse envelope into tokens */
                parse_cached_envelope(tmpenv, envtokens,
                                      VECTOR_SIZE(envtokens));

                did_env++;
            }

            if ((label == SORT_HASCONVFLAG || label == SORT_CONVMODSEQ ||
                label == SORT_CONVEXISTS || label == SORT_CONVSIZE) && !did_conv) {
                if (!cstate) cstate = conversations_get_mbox(index_mboxname(state));
                assert(cstate);
                if (conversation_load_advanced(cstate, record.cid, &conv, /*flags*/0))
                    continue;
                // useful to have for mutable sorts
                cur->convmodseq = conv.modseq;
                did_conv++;
            }

            switch (label) {
            case SORT_CC:
                cur->cc = get_localpart_addr(cacheitem_base(&record, CACHE_CC));
                break;
            case SORT_DATE:
                cur->sentdate = record.gmtime;
                /* fall through */
            case SORT_ARRIVAL:
                cur->internaldate = record.internaldate;
                break;
            case SORT_FROM:
                cur->from = get_localpart_addr(cacheitem_base(&record, CACHE_FROM));
                break;
            case SORT_MODSEQ:
                /* already copied above */
                break;
            case SORT_CREATEDMODSEQ:
                cur->createdmodseq = record.createdmodseq;
                break;
            case SORT_SIZE:
                cur->size = record.size;
                break;
            case SORT_SUBJECT:
                cur->xsubj = index_extract_subject(cacheitem_base(&record, CACHE_SUBJECT),
                                                   cacheitem_size(&record, CACHE_SUBJECT),
                                                   &cur->is_refwd);
                cur->xsubj_hash = strhash(cur->xsubj);
                break;
            case SORT_TO:
                cur->to = get_localpart_addr(cacheitem_base(&record, CACHE_TO));
                break;
            case SORT_ANNOTATION: {
                struct buf value = BUF_INITIALIZER;

                annotatemore_msg_lookup(state->mailbox,
                                        record.uid,
                                        sortcrit[j].args.annot.entry,
                                        sortcrit[j].args.annot.userid,
                                        &value);

                /* buf_release() never returns NULL, so if the lookup
                 * fails for any reason we just get an empty string here */
                strarray_appendm(&cur->annot, buf_release(&value));
                break;
            }
            case SORT_SAVEDATE:
                if (preload[j]) {
                    cur->savedate = record.savedate;
                }
                else {
                    /* If not in mailboxId, we use receivedAt */
                    cur->internaldate = record.internaldate;
                }
                break;
            case SORT_SNOOZEDUNTIL:
#ifdef WITH_JMAP
                if (preload[j] && (record.internal_flags & FLAG_INTERNAL_SNOOZED)) {
                    /* SAVEDATE == snoozed#until */
                    cur->savedate = record.savedate;

                    if (!cur->savedate) {
                        /* Try fetching snoozed#until directly */
                        json_t *snoozed =
                            jmap_fetch_snoozed(mailbox_name(mailbox), record.uid);

                        if (snoozed) {
                            time_from_iso8601(
                                json_string_value(json_object_get(snoozed,
                                                                  "until")),
                                &cur->savedate);
                            json_decref(snoozed);
                        }
                    }
                }
#endif
                if (!cur->savedate) {
                    /* If not snoozed in mailboxId, we use receivedAt */
                    cur->internaldate = record.internaldate;
                }
                break;
            case LOAD_IDS:
                index_get_ids(cur, envtokens, cacheitem_base(&record, CACHE_HEADERS),
                                              cacheitem_size(&record, CACHE_HEADERS));
                break;
            case SORT_DISPLAYFROM:
                cur->displayfrom = get_displayname(
                                   cacheitem_base(&record, CACHE_FROM));
                break;
            case SORT_DISPLAYTO:
                cur->displayto = get_displayname(
                                 cacheitem_base(&record, CACHE_TO));
                break;
            case SORT_SPAMSCORE: {
                const char *score = index_getheader(state, cur->msgno, "X-Spam-score");
                /* multiply by 100 to give an integer score */
                cur->spamscore = (int)((atof(score) * 100) + 0.5);
                break;
            }
            case SORT_HASFLAG: {
                const char *name = sortcrit[j].args.flag.name;
                if (mailbox_record_hasflag(mailbox, &record, name))
                    cur->hasflag |= (1<<j);
                break;
            }
            case SORT_HASCONVFLAG: {
                int idx = preload[j];
                /* flag exists in the conversation at all */
                if (idx >= 0 && conv.counts[idx] > 0 && j < 31)
                    cur->hasflag |= (1<<j);
                break;
            }
            case SORT_CONVEXISTS:
                cur->convexists = conv.exists;
                break;
            case SORT_CONVSIZE:
                cur->convsize = conv.size;
                break;
            case SORT_CONVMODSEQ:
                cur->convmodseq = conv.modseq;
                break;
            case SORT_RELEVANCY:
                /* for now all messages have relevancy=100 */
                break;
            }
        }

        free(tmpenv);
        conversation_fini(&conv);
    }

    free(preload);

    return ptrs;
}

static char *get_localpart_addr(const char *header)
{
    struct address *addr = NULL;
    char *ret = NULL;

    parseaddr_list(header, &addr);
    if (!addr) return NULL;

    if (addr->mailbox)
        ret = xstrdup(addr->mailbox);

    parseaddr_free(addr);

    return ret;
}

/*
 * Get the 'display-name' of an address from a header
 */
static char *get_displayname(const char *header)
{
    struct address *addr = NULL;
    char *ret = NULL;
    char *p;

    parseaddr_list(header, &addr);
    if (!addr) return NULL;

    if (addr->name && addr->name[0]) {
        /* pure RFC 5255 compatible "searchform" conversion */
        ret = charset_utf8_to_searchform(addr->name, /*flags*/0);
    }
    else if (addr->domain && addr->mailbox) {
        ret = strconcat(addr->mailbox, "@", addr->domain, (char *)NULL);
        /* gotta uppercase mailbox/domain */
        for (p = ret; *p; p++)
            *p = toupper(*p);
    }
    else if (addr->mailbox) {
        ret = xstrdup(addr->mailbox);
        /* gotta uppercase mailbox/domain */
        for (p = ret; *p; p++)
            *p = toupper(*p);
    }

    parseaddr_free(addr);

    return ret;
}

/*
 * Extract base subject from subject header
 *
 * This is a wrapper around _index_extract_subject() which preps the
 * subj NSTRING and checks for Netscape "[Fwd: ]".
 */
static char *index_extract_subject(const char *subj, size_t len, int *is_refwd)
{
    char *rawbuf, *buf, *s, *base;

    /* parse the subj NSTRING and make a working copy */
    if (!strcmp(subj, "NIL")) {                 /* NIL? */
        return xstrdup("");                     /* yes, return empty */
    } else if (*subj == '"') {                  /* quoted? */
        rawbuf = xstrndup(subj + 1, len - 2);   /* yes, strip quotes */
    } else {
        s = strchr(subj, '}') + 3;              /* literal, skip { }\r\n */
        rawbuf = xstrndup(s, len - (s - subj));
    }

    buf = charset_parse_mimeheader(rawbuf, charset_flags);
    free(rawbuf);

    for (s = buf;;) {
        base = _index_extract_subject(s, is_refwd);

        /* If we have a Netscape "[Fwd: ...]", extract the contents */
        if (!strncasecmp(base, "[fwd:", 5) &&
            base[strlen(base) - 1]  == ']') {

            /* inc refwd counter */
            *is_refwd += 1;

            /* trim "]" */
            base[strlen(base) - 1] = '\0';

            /* trim "[fwd:" */
            s = base + 5;
        }
        else /* otherwise, we're done */
            break;
    }

    base = xstrdup(base);

    free(buf);

    for (s = base; *s; s++) {
        *s = toupper(*s);
    }

    return base;
}

/*
 * Guts of subject extraction.
 *
 * Takes a subject string and returns a pointer to the base.
 */
static char *_index_extract_subject(char *s, int *is_refwd)
{
    char *base, *x;

    /* trim trailer
     *
     * start at the end of the string and work towards the front,
     * resetting the end of the string as we go.
     */
    for (x = s + strlen(s) - 1; x >= s;) {
        if (Uisspace(*x)) {                             /* whitespace? */
            *x = '\0';                                  /* yes, trim it */
            x--;                                        /* skip past it */
        }
        else if (x - s >= 4 &&
                 !strncasecmp(x-4, "(fwd)", 5)) {       /* "(fwd)"? */
            *(x-4) = '\0';                              /* yes, trim it */
            x -= 5;                                     /* skip past it */
            *is_refwd += 1;                             /* inc refwd counter */
        }
        else
            break;                                      /* we're done */
    }

    /* trim leader
     *
     * start at the head of the string and work towards the end,
     * skipping over stuff we don't care about.
     */
    for (base = s; base;) {
        if (Uisspace(*base)) base++;                    /* whitespace? */

        /* possible refwd */
        else if ((!strncasecmp(base, "re", 2) &&        /* "re"? */
                  (x = base + 2)) ||                    /* yes, skip past it */
                 (!strncasecmp(base, "fwd", 3) &&       /* "fwd"? */
                  (x = base + 3)) ||                    /* yes, skip past it */
                 (!strncasecmp(base, "fw", 2) &&        /* "fw"? */
                  (x = base + 2))) {                    /* yes, skip past it */
            int count = 0;                              /* init counter */

            while (Uisspace(*x)) x++;                   /* skip whitespace */

            if (*x == '[') {                            /* start of blob? */
                for (x++; x;) {                         /* yes, get count */
                    if (!*x) {                          /* end of subj, quit */
                        x = NULL;
                        break;
                    }
                    else if (*x == ']') {               /* end of blob, done */
                        break;
                                        /* if we have a digit, and we're still
                                           counting, keep building the count */
                    } else if (cyrus_isdigit((int) *x) && count != -1) {
                        count = count * 10 + *x - '0';
                        if (count < 0) {                /* overflow */
                            count = -1; /* abort counting */
                        }
                    } else {                            /* no digit, */
                        count = -1;                     /*  abort counting */
                    }
                    x++;
                }

                if (x)                                  /* end of blob? */
                    x++;                                /* yes, skip past it */
                else
                    break;                              /* no, we're done */
            }

            while (Uisspace(*x)) x++;                   /* skip whitespace */

            if (*x == ':') {                            /* ending colon? */
                base = x + 1;                           /* yes, skip past it */
                *is_refwd += (count > 0 ? count : 1);   /* inc refwd counter
                                                           by count or 1 */
            }
            else
                break;                                  /* no, we're done */
        }

#if 0 /* do nested blobs - wait for decision on this */
        else if (*base == '[') {                        /* start of blob? */
            int count = 1;                              /* yes, */
            x = base + 1;                               /*  find end of blob */
            while (count) {                             /* find matching ']' */
                if (!*x) {                              /* end of subj, quit */
                    x = NULL;
                    break;
                }
                else if (*x == '[')                     /* new open */
                    count++;                            /* inc counter */
                else if (*x == ']')                     /* close */
                    count--;                            /* dec counter */
                x++;
            }

            if (!x)                                     /* blob didn't close */
                break;                                  /*  so quit */

            else if (*x)                                /* end of subj? */
                base = x;                               /* no, skip blob */
#else
        else if (*base == '[' &&                        /* start of blob? */
                 (x = strpbrk(base+1, "[]")) &&         /* yes, end of blob */
                 *x == ']') {                           /*  (w/o nesting)? */

            if (*(x+1))                                 /* yes, end of subj? */
                base = x + 1;                           /* no, skip blob */
#endif
            else
                break;                                  /* yes, return blob */
        }
        else
            break;                                      /* we're done */
    }

    return base;
}

/* Get message-id, and references/in-reply-to */

void index_get_ids(MsgData *msgdata, char *envtokens[], const char *headers,
                   unsigned size)
{
    static struct buf buf;
    strarray_t refhdr = STRARRAY_INITIALIZER;
    char *refstr, *ref, *in_reply_to;

    buf_reset(&buf);

    /* get msgid */
    msgdata->msgid = find_msgid(envtokens[ENV_MSGID], NULL);
     /* if we don't have one, create one */
    if (!msgdata->msgid) {
        buf_printf(&buf, "<Empty-ID: %u>", msgdata->msgno);
        msgdata->msgid = xstrdup(buf.s);
        buf_reset(&buf);
    }

    /* Copy headers to the buffer */
    buf_appendmap(&buf, headers, size);
    buf_cstring(&buf);

    /* grab the References header */
    strarray_append(&refhdr, "references");
    message_pruneheader(buf.s, &refhdr, 0);
    strarray_fini(&refhdr);

    if (buf.s) {
        /* allocate some space for refs */
        /* find references */
        refstr = buf.s;
        massage_header(refstr);
        while ((ref = find_msgid(refstr, &refstr)) != NULL)
            strarray_appendm(&msgdata->ref, ref);
    }

    /* if we have no references, try in-reply-to */
    if (!msgdata->ref.count) {
        /* get in-reply-to id */
        in_reply_to = find_msgid(envtokens[ENV_INREPLYTO], NULL);
        /* if we have an in-reply-to id, make it the ref */
        if (in_reply_to)
            strarray_appendm(&msgdata->ref, in_reply_to);
    }
}

/*
 * Function for comparing two integers.
 */
#ifdef HAVE_DECLARE_OPTIMIZE
static inline int numcmp(modseq_t n1, modseq_t n2)
    __attribute__((pure, always_inline, optimize("-O3")));
#endif
static int numcmp(modseq_t n1, modseq_t n2)
{
    if (n1 < n2) return -1;
    if (n1 > n2) return 1;
    return 0;
}

/*
 * Comparison function for sorting message lists.
 */
static int index_sort_compare(MsgData *md1, MsgData *md2,
                              const struct sortcrit *sortcrit)
{
    int reverse, ret = 0, i = 0, ann = 0;

    do {
        /* determine sort order from reverse flag bit */
        reverse = sortcrit[i].flags & SORT_REVERSE;

        switch (sortcrit[i].key) {
        case SORT_SEQUENCE:
            ret = numcmp(md1->msgno, md2->msgno);
            break;
        case SORT_ARRIVAL:
            ret = numcmp(md1->internaldate, md2->internaldate);
            break;
        case SORT_CC:
            ret = strcmpsafe(md1->cc, md2->cc);
            break;
        case SORT_DATE: {
            time_t d1 = md1->sentdate ? md1->sentdate : md1->internaldate;
            time_t d2 = md2->sentdate ? md2->sentdate : md2->internaldate;
            ret = numcmp(d1, d2);
            break;
        }
        case SORT_SNOOZEDUNTIL:
        case SORT_SAVEDATE: {
            time_t d1 = md1->savedate ? md1->savedate : md1->internaldate;
            time_t d2 = md2->savedate ? md2->savedate : md2->internaldate;
            ret = numcmp(d1, d2);
            break;
        }
        case SORT_FROM:
            ret = strcmpsafe(md1->from, md2->from);
            break;
        case SORT_SIZE:
            ret = numcmp(md1->size, md2->size);
            break;
        case SORT_SUBJECT:
            ret = strcmpsafe(md1->xsubj, md2->xsubj);
            break;
        case SORT_TO:
            ret = strcmpsafe(md1->to, md2->to);
            break;
        case SORT_ANNOTATION:
            ret = strcmpsafe(md1->annot.data[ann], md2->annot.data[ann]);
            ann++;
            break;
        case SORT_MODSEQ:
            ret = numcmp(md1->modseq, md2->modseq);
            break;
        case SORT_CREATEDMODSEQ:
            ret = numcmp(md1->createdmodseq, md2->createdmodseq);
            break;
        case SORT_DISPLAYFROM:
            ret = strcmpsafe(md1->displayfrom, md2->displayfrom);
            break;
        case SORT_DISPLAYTO:
            ret = strcmpsafe(md1->displayto, md2->displayto);
            break;
        case SORT_UID:
            ret = numcmp(md1->uid, md2->uid);
            break;
        case SORT_CONVMODSEQ:
            ret = numcmp(md1->convmodseq, md2->convmodseq);
            break;
        case SORT_CONVEXISTS:
            ret = numcmp(md1->convexists, md2->convexists);
            break;
        case SORT_CONVSIZE:
            ret = numcmp(md1->convsize, md2->convsize);
            break;
        case SORT_SPAMSCORE:
            ret = numcmp(md1->spamscore, md2->spamscore);
            break;
        case SORT_HASFLAG:
        case SORT_HASCONVFLAG:
            if (i < 31)
                ret = numcmp(md1->hasflag & (1<<i),
                             md2->hasflag & (1<<i));
            break;
        case SORT_FOLDER:
            if (md1->folder && md2->folder)
                ret = strcmpsafe(md1->folder->mboxname, md2->folder->mboxname);
            break;
        case SORT_RELEVANCY:
            ret = 0;        /* for now all messages have relevancy=100 */
            break;
        case SORT_GUID:
            ret = message_guid_cmp(&md1->guid, &md2->guid);
            break;
        }
    } while (!ret && sortcrit[i++].key != SORT_SEQUENCE);

    // must be multi-folder with the same UID!  tiebreaker is GUID
    if (!ret) return message_guid_cmp(&md1->guid, &md2->guid);

    return (reverse ? -ret : ret);
}

static int sortcrit_is_uid(const struct sortcrit *sortcrit)
{
    if ((sortcrit->flags & SORT_REVERSE)) return 0;
    if (!(sortcrit->key == SORT_SEQUENCE)) return 0;
    return 1;
}

static int sortcrit_is_reverse_uid(const struct sortcrit *sortcrit)
{
    if (!(sortcrit->flags & SORT_REVERSE)) return 0;
    if (!(sortcrit->key == SORT_SEQUENCE)) return 0;
    return 1;
}

static int sortcrit_is_modseq(const struct sortcrit *sortcrit)
{
    if ((sortcrit->flags & SORT_REVERSE)) return 0;
    if (!(sortcrit->key == SORT_MODSEQ)) return 0;
    sortcrit++;
    if ((sortcrit->flags & SORT_REVERSE)) return 0;
    if (!(sortcrit->key == SORT_SEQUENCE)) return 0;
    return 1;
}

static int sortcrit_is_arrival(const struct sortcrit *sortcrit)
{
    if ((sortcrit->flags & SORT_REVERSE)) return 0;
    if (!(sortcrit->key == SORT_ARRIVAL)) return 0;
    sortcrit++;
    if ((sortcrit->flags & SORT_REVERSE)) return 0;
    if (!(sortcrit->key == SORT_SEQUENCE)) return 0;
    return 1;
}

static int sortcrit_is_reverse_arrival(const struct sortcrit *sortcrit)
{
    if (!(sortcrit->flags & SORT_REVERSE)) return 0;
    if (!(sortcrit->key == SORT_ARRIVAL)) return 0;
    sortcrit++;
    if ((sortcrit->flags & SORT_REVERSE)) return 0;
    if (!(sortcrit->key == SORT_SEQUENCE)) return 0;
    return 1;
}

static int sortcrit_is_reverse_flagged(const struct sortcrit *sortcrit)
{
    if (!(sortcrit->flags & SORT_REVERSE)) return 0;
    // both HASFLAG and HASCONVFLAG have the same representation internally
    if (!(sortcrit->key == SORT_HASFLAG ||
          sortcrit->key == SORT_HASCONVFLAG)) return 0;
    sortcrit++;
    if (!(sortcrit->flags & SORT_REVERSE)) return 0;
    if (!(sortcrit->key == SORT_ARRIVAL)) return 0;
    sortcrit++;
    if ((sortcrit->flags & SORT_REVERSE)) return 0;
    if (!(sortcrit->key == SORT_SEQUENCE)) return 0;
    return 1;
}

static int index_sort_compare_generic_qsort(const void *v1, const void *v2)
{
    MsgData *md1 = *(MsgData **)v1;
    MsgData *md2 = *(MsgData **)v2;

    return index_sort_compare(md1, md2, the_sortcrit);
}

#ifdef HAVE_DECLARE_OPTIMIZE
static inline int index_sort_compare_uid(const void *v1, const void *v2)
    __attribute__((pure, always_inline, optimize("-O3")));
#endif
static int index_sort_compare_uid(const void *v1, const void *v2)
{
    MsgData *md1 = *(MsgData **)v1;
    MsgData *md2 = *(MsgData **)v2;
    int ret;

    ret = md1->uid - md2->uid;
    if (ret) return ret;

    return message_guid_cmp(&md1->guid, &md2->guid);
}

#ifdef HAVE_DECLARE_OPTIMIZE
static inline int index_sort_compare_reverse_uid(const void *v1, const void *v2)
    __attribute__((pure, always_inline, optimize("-O3")));
#endif
static int index_sort_compare_reverse_uid(const void *v1, const void *v2)
{
    MsgData *md1 = *(MsgData **)v1;
    MsgData *md2 = *(MsgData **)v2;
    int ret;

    ret = md2->uid - md1->uid;
    if (ret) return ret;

    return message_guid_cmp(&md1->guid, &md2->guid);
}

#ifdef HAVE_DECLARE_OPTIMIZE
static inline int index_sort_compare_modseq(const void *v1, const void *v2)
    __attribute__((pure, always_inline, optimize("-O3")));
#endif
static int index_sort_compare_modseq(const void *v1, const void *v2)
{
    MsgData *md1 = *(MsgData **)v1;
    MsgData *md2 = *(MsgData **)v2;
    int ret;

    ret = md1->modseq - md2->modseq;
    if (ret) return ret;

    ret = md1->uid - md2->uid;
    if (ret) return ret;

    return message_guid_cmp(&md1->guid, &md2->guid);
}

#ifdef HAVE_DECLARE_OPTIMIZE
static inline int index_sort_compare_arrival(const void *v1, const void *v2)
    __attribute__((pure, always_inline, optimize("-O3")));
#endif
static int index_sort_compare_arrival(const void *v1, const void *v2)
{
    MsgData *md1 = *(MsgData **)v1;
    MsgData *md2 = *(MsgData **)v2;
    int ret;

    ret = md1->internaldate - md2->internaldate;
    if (ret) return ret;

    ret = md1->createdmodseq - md2->createdmodseq;
    if (ret) return ret;

    ret = md1->uid - md2->uid;
    if (ret) return ret;

    return message_guid_cmp(&md1->guid, &md2->guid);
}

#ifdef HAVE_DECLARE_OPTIMIZE
static inline int index_sort_compare_reverse_arrival(const void *v1, const void *v2)
    __attribute__((pure, always_inline, optimize("-O3")));
#endif
static int index_sort_compare_reverse_arrival(const void *v1, const void *v2)
{
    MsgData *md1 = *(MsgData **)v1;
    MsgData *md2 = *(MsgData **)v2;
    int ret;

    ret = md2->internaldate - md1->internaldate;
    if (ret) return ret;

    ret = md2->createdmodseq - md1->createdmodseq;
    if (ret) return ret;

    ret = md1->uid - md2->uid;
    if (ret) return ret;

    return message_guid_cmp(&md1->guid, &md2->guid);
}

#ifdef HAVE_DECLARE_OPTIMIZE
static inline int index_sort_compare_reverse_flagged(const void *v1, const void *v2)
    __attribute__((pure, always_inline, optimize("-O3")));
#endif
static int index_sort_compare_reverse_flagged(const void *v1, const void *v2)
{
    MsgData *md1 = *(MsgData **)v1;
    MsgData *md2 = *(MsgData **)v2;
    int ret;

    ret = md2->hasflag - md1->hasflag;
    if (ret) return ret;

    ret = md2->internaldate - md1->internaldate;
    if (ret) return ret;

    ret = md2->createdmodseq - md1->createdmodseq;
    if (ret) return ret;

    ret = md1->uid - md2->uid;
    if (ret) return ret;

    return message_guid_cmp(&md1->guid, &md2->guid);
}

void index_msgdata_sort(MsgData **msgdata, int n, const struct sortcrit *sortcrit)
{
    if (sortcrit_is_uid(sortcrit)) {
        qsort(msgdata, n, sizeof(MsgData *), index_sort_compare_uid);
    }
    else if (sortcrit_is_reverse_uid(sortcrit)) {
        qsort(msgdata, n, sizeof(MsgData *), index_sort_compare_reverse_uid);
    }
    else if (sortcrit_is_modseq(sortcrit)) {
        qsort(msgdata, n, sizeof(MsgData *), index_sort_compare_modseq);
    }
    else if (sortcrit_is_arrival(sortcrit)) {
        qsort(msgdata, n, sizeof(MsgData *), index_sort_compare_arrival);
    }
    else if (sortcrit_is_reverse_arrival(sortcrit)) {
        qsort(msgdata, n, sizeof(MsgData *), index_sort_compare_reverse_arrival);
    }
    else if (sortcrit_is_reverse_flagged(sortcrit)) {
        qsort(msgdata, n, sizeof(MsgData *), index_sort_compare_reverse_flagged);
    }
    else {
        char *tmp = sortcrit_as_string(sortcrit);
        syslog(LOG_DEBUG, "GENERICSORT: %s", tmp);
        free(tmp);
        the_sortcrit = (struct sortcrit *)sortcrit;
        qsort(msgdata, n, sizeof(MsgData *), index_sort_compare_generic_qsort);
    }
}

/*
 * Free an array of MsgData* as built by index_msgdata_load()
 */
void index_msgdata_free(MsgData **msgdata, unsigned int n)
{
    unsigned int i;

    if (!msgdata)
        return;
    for (i = 0 ; i < n ; i++) {
        MsgData *md = msgdata[i];

        if (!md) continue;

        free(md->cc);
        free(md->from);
        free(md->to);
        free(md->displayfrom);
        free(md->displayto);
        free(md->xsubj);
        free(md->msgid);
        free(md->listid);
        free(md->contenttype);
        strarray_fini(&md->ref);
        strarray_fini(&md->annot);
    }
    free(msgdata);
}

/*
 * Getnext function for sorting thread lists.
 */
static void *index_thread_getnext(Thread *thread)
{
    return thread->next;
}

/*
 * Setnext function for sorting thread lists.
 */
static void index_thread_setnext(Thread *thread, Thread *next)
{
    thread->next = next;
}

/*
 * Comparison function for sorting threads.
 */
static int index_thread_compare(Thread *t1, Thread *t2,
                                const struct sortcrit *call_data)
{
    MsgData *md1, *md2;

    /* if the container is empty, use the first child's container */
    md1 = t1->msgdata ? t1->msgdata : t1->child->msgdata;
    md2 = t2->msgdata ? t2->msgdata : t2->child->msgdata;
    return index_sort_compare(md1, md2, call_data);
}

/*
 * Sort a list of threads.
 */
static void index_thread_sort(Thread *root,
                              const struct sortcrit *sortcrit)
{
    Thread *child;

    /* sort the grandchildren */
    child = root->child;
    while (child) {
        /* if the child has children, sort them */
        if (child->child)
            index_thread_sort(child, sortcrit);
        child = child->next;
    }

    /* sort the children */
    root->child = lsort(root->child,
                        (void * (*)(void*)) index_thread_getnext,
                        (void (*)(void*,void*)) index_thread_setnext,
                        (int (*)(void*,void*,void*)) index_thread_compare,
                        (void *)sortcrit);
}

/*
 * Thread a list of messages using the ORDEREDSUBJECT algorithm.
 */
static void index_thread_orderedsubj(struct index_state *state,
                                     unsigned *msgno_list, unsigned int nmsg,
                                     int usinguid)
{
    MsgData **msgdata;
    unsigned int mi;
    static const struct sortcrit sortcrit[] =
                                 {{ SORT_SUBJECT,  0, {{NULL, NULL}} },
                                  { SORT_DATE,     0, {{NULL, NULL}} },
                                  { SORT_SEQUENCE, 0, {{NULL, NULL}} }};
    unsigned psubj_hash = 0;
    char *psubj;
    Thread *head, *newnode, *cur, *parent, *last;

    /* Create/load the msgdata array */
    msgdata = index_msgdata_load(state, msgno_list, nmsg, sortcrit, 0, NULL);

    /* Sort messages by subject and date */
    index_msgdata_sort(msgdata, nmsg, sortcrit);

    /* create an array of Thread to use as nodes of thread tree
     *
     * we will be building threads under a dummy head,
     * so we need (nmsg + 1) nodes
     */
    head = (Thread *) xzmalloc((nmsg + 1) * sizeof(Thread));

    newnode = head + 1; /* set next newnode to the second
                           one in the array (skip the head) */
    parent = head;      /* parent is the head node */
    psubj = NULL;       /* no previous subject */
    cur = NULL;         /* no current thread */
    last = NULL;        /* no last child */

    for (mi = 0 ; mi < nmsg ; mi++) {
        MsgData *msg = msgdata[mi];
        newnode->msgdata = msg;

        /* if no previous subj, or
           current subj = prev subj (subjs have same hash, and
           the strings are equal), then add message to current thread */
        if (!psubj ||
            (msg->xsubj_hash == psubj_hash &&
             !strcmp(msg->xsubj, psubj))) {
            /* if no children, create first child */
            if (!parent->child) {
                last = parent->child = newnode;
                if (!cur)               /* first thread */
                    parent = cur = parent->child;
            }
            /* otherwise, add to siblings */
            else {
                last->next = newnode;
                last = last->next;
            }
        }
        /* otherwise, create a new thread */
        else {
            cur->next = newnode;        /* create and start a new thread */
            parent = cur = cur->next;   /* now work with the new thread */
        }

        psubj_hash = msg->xsubj_hash;
        psubj = msg->xsubj;
        newnode++;
    }

    /* Sort threads by date */
    index_thread_sort(head, sortcrit+1);

    /* Output the threaded messages */
    index_thread_print(state, head, usinguid);

    /* free the thread array */
    free(head);

    /* free the msgdata array */
    index_msgdata_free(msgdata, nmsg);
}

/*
 * Guts of thread printing.  Recurses over children when necessary.
 *
 * Frees contents of msgdata as a side effect.
 */
static void _index_thread_print(struct index_state *state,
                                Thread *thread, int usinguid)
{
    Thread *child;

    /* for each thread... */
    while (thread) {
        /* start the thread */
        prot_printf(state->out, "(");

        /* if we have a message, print its identifier
         * (do nothing for empty containers)
         */
        if (thread->msgdata && thread->msgdata->uid) {
            prot_printf(state->out, "%u",
                        usinguid ? thread->msgdata->uid :
                        thread->msgdata->msgno);

            /* if we have a child, print the parent-child separator */
            if (thread->child) prot_printf(state->out, " ");
        }

        /* for each child, grandchild, etc... */
        child = thread->child;
        while (child) {
            /* if the child has siblings, print new branch and break */
            if (child->next) {
                _index_thread_print(state, child, usinguid);
                break;
            }
            /* otherwise print the only child */
            else {
                prot_printf(state->out, "%u",
                            usinguid ? child->msgdata->uid :
                            child->msgdata->msgno);

                /* if we have a child, print the parent-child separator */
                if (child->child) prot_printf(state->out, " ");

                child = child->child;
            }
        }

        /* end the thread */
        prot_printf(state->out, ")");

        thread = thread->next;
    }
}

/*
 * Print a list of threads.
 *
 * This is a wrapper around _index_thread_print() which simply prints the
 * start and end of the untagged thread response.
 */
static void index_thread_print(struct index_state *state,
                               Thread *thread, int usinguid)
{
    prot_printf(state->out, "* THREAD");

    if (thread) {
        prot_printf(state->out, " ");
        _index_thread_print(state, thread->child, usinguid);
    }
}

/*
 * Find threading algorithm for given arg.
 * Returns index into thread_algs[], or -1 if not found.
 */
EXPORTED int find_thread_algorithm(char *arg)
{
    int alg;

    ucase(arg);
    for (alg = 0; thread_algs[alg].alg_name; alg++) {
        if (!strcmp(arg, thread_algs[alg].alg_name))
            return alg;
    }
    return -1;
}

/*
 * The following code is an interpretation of JWZ's description
 * and pseudo-code in http://www.jwz.org/doc/threading.html.
 *
 * It has been modified to match the THREAD=REFERENCES algorithm.
 */

/*
 * Determines if child is a descendent of parent.
 *
 * Returns 1 if yes, 0 otherwise.
 */
static int thread_is_descendent(Thread *parent, Thread *child)
{
    Thread *kid;

    /* self */
    if (parent == child)
        return 1;

    /* search each child's descendents */
    for (kid = parent->child; kid; kid = kid->next) {
        if (thread_is_descendent(kid, child))
            return 1;
    }
    return 0;
}

/*
 * Links child into parent's children.
 */
static void thread_adopt_child(Thread *parent, Thread *child)
{
    child->parent = parent;
    child->next = parent->child;
    parent->child = child;
}

/*
 * Unlinks child from it's parent's children.
 */
static void thread_orphan_child(Thread *child)
{
    Thread *prev, *cur;

    /* sanity check -- make sure child is actually a child of parent */
    for (prev = NULL, cur = child->parent->child;
         cur != child && cur != NULL; prev = cur, cur = cur->next);

    if (!cur) {
        /* uh oh!  couldn't find the child in it's parent's children
         * we should probably return NO to thread command
         */
        return;
    }

    /* unlink child */
    if (!prev)  /* first child */
        child->parent->child = child->next;
    else
        prev->next = child->next;
    child->parent = child->next = NULL;
}

/*
 * Link messages together using message-id and references.
 */
static void ref_link_messages(MsgData **msgdata, unsigned int nmsg,
                              Thread **newnode, struct hash_table *id_table)
{
    Thread *cur, *parent, *ref;
    unsigned int mi;
    int dup_count = 0;
    char buf[100];
    int i;

    /* for each message... */
    for (mi = 0 ; mi < nmsg ; mi++) {
        MsgData *msg = msgdata[mi];

        /* fill the containers with msgdata
         *
         * if we already have a container, use it
         */
        if ((cur = (Thread *) hash_lookup(msg->msgid, id_table))) {
            /* If this container is not empty, then we have a duplicate
             * Message-ID.  Make this one unique so that we don't stomp
             * on the old one.
             */
            if (cur->msgdata) {
                snprintf(buf, sizeof(buf), "-dup%d", dup_count++);
                msg->msgid =
                    (char *) xrealloc(msg->msgid,
                                      strlen(msg->msgid) + strlen(buf) + 1);
                strcat(msg->msgid, buf);
                /* clear cur so that we create a new container */
                cur = NULL;
            }
            else
                cur->msgdata = msg;
        }

        /* otherwise, make and index a new container */
        if (!cur) {
            cur = *newnode;
            cur->msgdata = msg;
            hash_insert(msg->msgid, cur, id_table);
            (*newnode)++;
        }

        /* Step 1.A */
        for (i = 0, parent = NULL; i < msg->ref.count; i++) {
            /* if we don't already have a container for the reference,
             * make and index a new (empty) container
             */
            if (!(ref = (Thread *) hash_lookup(msg->ref.data[i], id_table))) {
                ref = *newnode;
                hash_insert(msg->ref.data[i], ref, id_table);
                (*newnode)++;
            }

            /* link the references together as parent-child iff:
             * - we won't change existing links, AND
             * - we won't create a loop
             */
            if (!ref->parent &&
                parent && !thread_is_descendent(ref, parent)) {
                thread_adopt_child(parent, ref);
            }

            parent = ref;
        }

        /* Step 1.B
         *
         * if we have a parent already, it is probably bogus (the result
         * of a truncated references field), so unlink from it because
         * we now have the actual parent
         */
        if (cur->parent) thread_orphan_child(cur);

        /* make the last reference the parent of our message iff:
         * - we won't create a loop
         */
        if (parent && !thread_is_descendent(cur, parent))
            thread_adopt_child(parent, cur);
    }
}

/*
 * Gather orphan messages under the root node.
 */
static void ref_gather_orphans(const char *key __attribute__((unused)),
                               void *data, void *rock)
{
    Thread *node = (Thread *)data;
    struct rootset *rootset = (struct rootset *)rock;

    /* we only care about nodes without parents */
    if (!node->parent) {
        if (node->next) {
            /* uh oh!  a node without a parent should not have a sibling
             * we should probably return NO to thread command
             */
            return;
        }

        /* add this node to root's children */
        node->next = rootset->root->child;
        rootset->root->child = node;
        rootset->nroot++;
    }
}

/*
 * Prune tree of empty containers.
 */
static void ref_prune_tree(Thread *parent)
{
    Thread *cur, *prev, *next, *child;

    for (prev = NULL, cur = parent->child, next = cur->next;
         cur;
         prev = cur, cur = next, next = (cur ? cur->next : NULL)) {

retry:
        /* if we have an empty container with no children, delete it */
        if (!cur->msgdata && !cur->child) {
            if (!prev)  /* first child */
                parent->child = cur->next;
            else
                prev->next = cur->next;

            /* we just removed cur from our list,
             * so we need to keep the same prev for the next pass
             */
            cur = prev;
        }

        /* if we have an empty container with children, AND
         * we're not at the root OR we only have one child,
         * then remove the container but promote its children to this level
         * (splice them into the current child list)
         */
        else if (!cur->msgdata && cur->child &&
                 (cur->parent || !cur->child->next)) {
            /* move cur's children into cur's place (start the splice) */
            if (!prev)  /* first child */
                parent->child = cur->child;
            else
                prev->next = cur->child;

            /* make cur's parent the new parent of cur's children
             * (they're moving in with grandma!)
             */
            child = cur->child;
            do {
                child->parent = cur->parent;
            } while (child->next && (child = child->next));

            /* make the cur's last child point to cur's next sibling
             * (finish the splice)
             */
            child->next = cur->next;

            /* we just replaced cur with it's children
             * so make it's first child the next node to process
             */
            next = cur->child;

            /* make cur childless and siblingless */
            cur->child = cur->next = NULL;

            /* we just removed cur from our list,
             * so we need to keep the same prev for the next pass
             */
            cur = prev;
        }

        /* if we have a message with children, prune it's children */
        else if (cur->child) {
            ref_prune_tree(cur);
            if (!cur->msgdata && !cur->child) {
                /* Did we end up with a completely empty node here?
                 * Go back and prune it too.  See Bug 3784.  */
                goto retry;
            }
        }
    }
}

/*
 * Sort the messages in the root set by date.
 */
static void ref_sort_root(Thread *root)
{
    Thread *cur;
    static const struct sortcrit sortcrit[] =
                                 {{ SORT_DATE,     0, {{NULL, NULL}} },
                                  { SORT_SEQUENCE, 0, {{NULL, NULL}} }};

    cur = root->child;
    while (cur) {
        /* if the message is a dummy, sort its children */
        if (!cur->msgdata) {
            cur->child = lsort(cur->child,
                               (void * (*)(void*)) index_thread_getnext,
                               (void (*)(void*,void*)) index_thread_setnext,
                               (int (*)(void*,void*,void*)) index_thread_compare,
                               (void *)sortcrit);
        }
        cur = cur->next;
    }

    /* sort the root set */
    root->child = lsort(root->child,
                        (void * (*)(void*)) index_thread_getnext,
                        (void (*)(void*,void*)) index_thread_setnext,
                        (int (*)(void*,void*,void*)) index_thread_compare,
                        (void *)sortcrit);
}

/*
 * Group threads with same subject.
 */
static void ref_group_subjects(Thread *root, unsigned nroot, Thread **newnode)
{
    Thread *cur, *old, *prev, *next, *child;
    struct hash_table subj_table;
    char *subj;

    /* Step 5.A: create a subj_table with one bucket for every possible
     * subject in the root set
     */
    construct_hash_table(&subj_table, nroot, 1);

    /* Step 5.B: populate the table with a container for each subject
     * at the root
     */
    for (cur = root->child; cur; cur = cur->next) {
        /* Step 5.B.i: find subject of the thread
         *
         * if the container is not empty, use it's subject
         */
        if (cur->msgdata)
            subj = cur->msgdata->xsubj;
        /* otherwise, use the subject of it's first child */
        else
            subj = cur->child->msgdata->xsubj;

        /* Step 5.B.ii: if subject is empty, skip it */
        if (!strlen(subj)) continue;

        /* Step 5.B.iii: lookup this subject in the table */
        old = (Thread *) hash_lookup(subj, &subj_table);

        /* Step 5.B.iv: insert the current container into the table iff:
         * - this subject is not in the table, OR
         * - this container is empty AND the one in the table is not
         *   (the empty one is more interesting as a root), OR
         * - the container in the table is a re/fwd AND this one is not
         *   (the non-re/fwd is the more interesting of the two)
         */
        if (!old ||
            (!cur->msgdata && old->msgdata) ||
            (old->msgdata && old->msgdata->is_refwd &&
             cur->msgdata && !cur->msgdata->is_refwd)) {
          hash_insert(subj, cur, &subj_table);
        }
    }

    /* 5.C - group containers with the same subject together */
    for (prev = NULL, cur = root->child, next = cur->next;
         cur;
         prev = cur, cur = next, next = (next ? next->next : NULL)) {
        /* Step 5.C.i: find subject of the thread
         *
         * if container is not empty, use it's subject
         */
        if (cur->msgdata)
            subj = cur->msgdata->xsubj;
        /* otherwise, use the subject of it's first child */
        else
            subj = cur->child->msgdata->xsubj;

        /* Step 5.C.ii: if subject is empty, skip it */
        if (!strlen(subj)) continue;

        /* Step 5.C.iii: lookup this subject in the table */
        old = (Thread *) hash_lookup(subj, &subj_table);

        /* Step 5.C.iv: if we found ourselves, skip it */
        if (!old || old == cur) continue;

        /* ok, we already have a container which contains our current subject,
         * so pull this container out of the root set, because we are going to
         * merge this node with another one
         */
        if (!prev)      /* we're at the root */
            root->child = cur->next;
        else
            prev->next = cur->next;
        cur->next = NULL;

        /* if both containers are dummies, append cur's children to old's */
        if (!old->msgdata && !cur->msgdata) {
            /* find old's last child */
            for (child = old->child; child->next; child = child->next);

            /* append cur's children to old's children list */
            child->next = cur->child;

            /* make old the parent of cur's children */
            for (child = cur->child; child; child = child->next)
                child->parent = old;

            /* make cur childless */
            cur->child = NULL;
        }

        /* if:
         * - old container is empty, OR
         * - the current message is a re/fwd AND the old one is not,
         * make the current container a child of the old one
         *
         * Note: we don't have to worry about the reverse cases
         * because step 5.B guarantees that they won't happen
         */
        else if (!old->msgdata ||
                 (cur->msgdata && cur->msgdata->is_refwd &&
                  !old->msgdata->is_refwd)) {
            thread_adopt_child(old, cur);
        }

        /* if both messages are re/fwds OR neither are re/fwds,
         * then make them both children of a new dummy container
         * (we don't want to assume any parent-child relationship between them)
         *
         * perhaps we can create a parent-child relationship
         * between re/fwds by counting the number of re/fwds
         *
         * Note: we need the hash table to still point to old,
         * so we must make old the dummy and make the contents of the
         * new container a copy of old's original contents
         */
        else {
            Thread *new = (*newnode)++;

            /* make new a copy of old (except parent and next) */
            new->msgdata = old->msgdata;
            new->child = old->child;
            new->next = NULL;

            /* make new the parent of it's newly adopted children */
            for (child = new->child; child; child = child->next)
                child->parent = new;

            /* make old the parent of cur and new */
            cur->parent = old;
            new->parent = old;

            /* empty old and make it have two children (cur and new) */
            old->msgdata = NULL;
            old->child = cur;
            cur->next = new;
        }

        /* we just removed cur from our list,
         * so we need to keep the same prev for the next pass
         */
        cur = prev;
    }

    free_hash_table(&subj_table, NULL);
}

/*
 * Guts of thread searching.  Recurses over children when necessary.
 */
static int _index_thread_search(struct index_state *state,
                                Thread *thread, int (*searchproc) (MsgData *))
{
    Thread *child;

    /* test the head node */
    if (thread->msgdata && searchproc(thread->msgdata)) return 1;

    /* test the children recursively */
    child = thread->child;
    while (child) {
        if (_index_thread_search(state, child, searchproc)) return 1;
        child = child->next;
    }

    /* if we get here, we struck out */
    return 0;
}

/*
 * Search a thread to see if it contains a message which matches searchproc().
 *
 * This is a wrapper around _index_thread_search() which iterates through
 * each thread and removes any which fail the searchproc().
 */
static void index_thread_search(struct index_state *state,
                                Thread *root, int (*searchproc) (MsgData *))
{
    Thread *cur, *prev, *next;

    for (prev = NULL, cur = root->child, next = cur->next;
         cur;
         prev = cur, cur= next, next = (cur ? cur->next : NULL)) {
        if (!_index_thread_search(state, cur, searchproc)) {
            /* unlink the thread from the list */
            if (!prev)  /* first thread */
                root->child = cur->next;
            else
                prev->next = cur->next;

            /* we just removed cur from our list,
             * so we need to keep the same prev for the next pass
             */
            cur = prev;
        }
    }
}

/*
 * Guts of the REFERENCES algorithms.  Behavior is tweaked with loadcrit[],
 * threadproc(), searchproc() and sortcrit[].
 */
static void _index_thread_ref(struct index_state *state, unsigned *msgno_list,
                              unsigned int nmsg,
                              const struct sortcrit loadcrit[],
                              MsgData **(*threadproc) (struct rootset *, Thread **),
                              int (*searchproc) (MsgData *),
                              const struct sortcrit sortcrit[], int usinguid)
{
    MsgData **msgdata, **thrdata = NULL;
    unsigned int mi;
    int tref, nnode;
    Thread *newnode;
    struct hash_table id_table;
    struct rootset rootset;

    /* Create/load the msgdata array */
    msgdata = index_msgdata_load(state, msgno_list, nmsg, loadcrit, 0, NULL);

    /* calculate the sum of the number of references for all messages */
    for (mi = 0, tref = 0 ; mi < nmsg ; mi++)
        tref += msgdata[mi]->ref.count;

    /* create an array of Thread to use as nodes of thread tree (including
     * empty containers)
     *
     * - We will be building threads under a dummy root, so we need at least
     *   (nmsg + 1) nodes.
     * - We also will need containers for references to non-existent messages.
     *   To make sure we have enough, we will take the worst case and
     *   use the sum of the number of references for all messages.
     * - Finally, we will need containers to group threads with the same
     *   subject together.  To make sure we have enough, we will take the
     *   worst case which will be half of the number of messages.
     *
     * This is overkill, but it is the only way to make sure we have enough
     * ahead of time.  If we tried to use xrealloc(), the array might be moved,
     * and our parent/child/next pointers will no longer be correct
     * (been there, done that).
     */
    nnode = (int) (1.5 * nmsg + 1 + tref);
    rootset.root = (Thread *) xmalloc(nnode * sizeof(Thread));
    memset(rootset.root, 0, nnode * sizeof(Thread));

    newnode = rootset.root + 1; /* set next newnode to the second
                                   one in the array (skip the root) */

    /* Step 0: create an id_table with one bucket for every possible
     * message-id and reference (nmsg + tref)
     */
    construct_hash_table(&id_table, nmsg + tref, 1);

    /* Step 1: link messages together */
    ref_link_messages(msgdata, nmsg, &newnode, &id_table);

    /* Step 2: find the root set (gather all of the orphan messages) */
    rootset.nroot = 0;
    hash_enumerate(&id_table, ref_gather_orphans, &rootset);

    /* discard id_table */
    free_hash_table(&id_table, NULL);

    /* Step 3: prune tree of empty containers - get our deposit back :^) */
    ref_prune_tree(rootset.root);

    /* Steps 4/5: algorithm-specific thread processing */
    if (threadproc) thrdata = threadproc(&rootset, &newnode);

    /* Optionally search threads (to be used by REFERENCES derivatives) */
    if (searchproc) index_thread_search(state, rootset.root, searchproc);

    /* Step 6: sort threads */
    if (sortcrit) index_thread_sort(rootset.root, sortcrit);

    /* Output the threaded messages */
    index_thread_print(state, rootset.root, usinguid);

    /* free the thread array */
    free(rootset.root);

    /* free the msgdata array */
    index_msgdata_free(msgdata, nmsg);
    index_msgdata_free(thrdata, rootset.nroot);
}

/*
 * Thread a list of messages using the REFERENCES algorithm.
 */
static MsgData **references_thread_proc(struct rootset *rootset,
                                        Thread **newnode)
{
    /* Step 4: sort the root set */
    ref_sort_root(rootset->root);
    
    /* Step 5: group root set by subject */
    ref_group_subjects(rootset->root, rootset->nroot, newnode);

    return NULL;
}

static void index_thread_references(struct index_state *state,
                                    unsigned *msgno_list, unsigned int nmsg,
                                    int usinguid)
{
    static const struct sortcrit loadcrit[] =
                                 {{ LOAD_IDS,      0, {{NULL,NULL}} },
                                  { SORT_SUBJECT,  0, {{NULL,NULL}} },
                                  { SORT_DATE,     0, {{NULL,NULL}} },
                                  { SORT_SEQUENCE, 0, {{NULL,NULL}} }};
    static const struct sortcrit sortcrit[] =
                                 {{ SORT_DATE,     0, {{NULL,NULL}} },
                                  { SORT_SEQUENCE, 0, {{NULL,NULL}} }};

    _index_thread_ref(state, msgno_list, nmsg, loadcrit,
                      references_thread_proc, NULL, sortcrit, usinguid);
}

/* Find most recent internaldate of all messages in thread */
static void find_most_recent(Thread *thread, MsgData *recent)
{
    Thread *child;

    /* test the head node */
    if (thread->msgdata->internaldate > recent->internaldate)
        recent->internaldate = thread->msgdata->internaldate;

    /* test the children recursively */
    child = thread->child;
    while (child) {
        find_most_recent(child, recent);
        child = child->next;
    }
}

/*
 * Tag the root of each thread with the most recent internaldate of all
 * messages in the thread.  The actual sorting will be done by the calling
 * function, but we leverage the fact that sorting by sentdate will fallback
 * to internaldate if sentdate == 0.
 */
static MsgData **refs_thread_proc(struct rootset *rootset,
                                  Thread **newnode __attribute((unused)))
{
    MsgData **ptrs, *md;
    Thread *cur;
    int i = 0;

    /* Create an array of MsgData for dummy roots */
    ptrs = (MsgData **) xzmalloc(rootset->nroot *
                                 (sizeof(MsgData *) + sizeof(MsgData)));
    md = (MsgData *)(ptrs + rootset->nroot);

    /* Find most recent internaldate in each thread */
    cur = rootset->root->child;
    while (cur) {
        /* If the message is a dummy, assign it MsgData for sorting */
        if (!cur->msgdata) {
            cur->msgdata = ptrs[i] = &md[i];
            i++;
            cur->msgdata->internaldate = cur->child->msgdata->internaldate;
        }
        cur->msgdata->sentdate = 0; /* force date sort to use internaldate */

        find_most_recent(cur, cur->msgdata);
        cur = cur->next;
    }

    return ptrs;
}

/*
 * Thread a list of messages using the REFS algorithm.
 */
static void index_thread_refs(struct index_state *state,
                              unsigned *msgno_list, unsigned int nmsg,
                              int usinguid)
{
    static const struct sortcrit loadcrit[] =
                                 {{ LOAD_IDS,      0, {{NULL,NULL}} },
                                  { SORT_DATE,     0, {{NULL,NULL}} },
                                  { SORT_ARRIVAL,  0, {{NULL,NULL}} },
                                  { SORT_SEQUENCE, 0, {{NULL,NULL}} }};
    static const struct sortcrit sortcrit[] =
                                 {{ SORT_DATE,     0, {{NULL,NULL}} },
                                  { SORT_ARRIVAL,  0, {{NULL,NULL}} },
                                  { SORT_SEQUENCE, 0, {{NULL,NULL}} }};

    _index_thread_ref(state, msgno_list, nmsg, loadcrit,
                      refs_thread_proc, NULL, sortcrit, usinguid);
}

/*
 * NNTP specific stuff.
 */
EXPORTED char *index_get_msgid(struct index_state *state,
                               uint32_t msgno)
{
    struct mailbox *mailbox = state->mailbox;
    struct index_record record;

    if (index_reload_record(state, msgno, &record))
        return NULL;

    return mailbox_cache_get_env(mailbox, &record, ENV_MSGID);
}

static void massage_header(char *hdr)
{
    int n = 0;
    char *p, c;

    for (p = hdr; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\r') {
            if (!n || *(p+1) == '\n') {
                /* no leading or trailing whitespace */
                continue;
            }
            /* replace with space */
            c = ' ';
        }
        else if (*p == '\n') {
            if (*(p+1) == ' ' || *(p+1) == '\t') {
                /* folded header */
                continue;
            }
            /* end of header */
            break;
        }
        else
            c = *p;

        hdr[n++] = c;
    }
    hdr[n] = '\0';
}

EXPORTED extern struct nntp_overview *index_overview(struct index_state *state,
                                                     uint32_t msgno)
{
    static struct nntp_overview over;
    static char *env = NULL, *from = NULL, *hdr = NULL;
    static int envsize = 0, fromsize = 0, hdrsize = 0;
    int size;
    char *envtokens[NUMENVTOKENS];
    struct address addr = { NULL, NULL, NULL, NULL, NULL, NULL, 0 };
    strarray_t refhdr = STRARRAY_INITIALIZER;
    struct mailbox *mailbox = state->mailbox;
    struct index_record record;

    /* flush any previous data */
    memset(&over, 0, sizeof(struct nntp_overview));

    if (index_reload_record(state, msgno, &record))
        return NULL;

    if (mailbox_cacherecord(mailbox, &record))
        return NULL; /* upper layers can cope! */

    /* make a working copy of envelope; strip outer ()'s */
    /* -2 -> don't include the size of the outer parens */
    /* +1 -> leave space for NUL */
    size = cacheitem_size(&record, CACHE_ENVELOPE) - 2 + 1;
    if (envsize < size) {
        envsize = size;
        env = xrealloc(env, envsize);
    }
    /* +1 -> skip the leading paren */
    strlcpy(env, cacheitem_base(&record, CACHE_ENVELOPE) + 1, size);

    /* make a working copy of headers */
    size = cacheitem_size(&record, CACHE_HEADERS);
    if (hdrsize < size+2) {
        hdrsize = size+100;
        hdr = xrealloc(hdr, hdrsize);
    }
    memcpy(hdr, cacheitem_base(&record, CACHE_HEADERS), size);
    hdr[size] = '\0';

    parse_cached_envelope(env, envtokens, VECTOR_SIZE(envtokens));

    over.uid = record.uid;
    over.bytes = record.size;
    over.lines = index_getlines(state, msgno);
    over.date = envtokens[ENV_DATE];
    over.msgid = envtokens[ENV_MSGID];

    /* massage subject */
    if ((over.subj = envtokens[ENV_SUBJECT]))
        massage_header(over.subj);

    /* build original From: header */
    if (envtokens[ENV_FROM]) /* paranoia */
        message_parse_env_address(envtokens[ENV_FROM], &addr);

    if (addr.mailbox && addr.domain) { /* paranoia */
        /* +3 -> add space for quotes and space */
        /* +4 -> add space for < @ > NUL */
        size = (addr.name ? strlen(addr.name) + 3 : 0) +
            strlen(addr.mailbox) + strlen(addr.domain) + 4;
        if (fromsize < size) {
            fromsize = size;
            from = xrealloc(from, fromsize);
        }
        from[0] = '\0';
        if (addr.name) sprintf(from, "\"%s\" ", addr.name);
        snprintf(from + strlen(from), fromsize - strlen(from),
                 "<%s@%s>", addr.mailbox, addr.domain);

        over.from = from;
    }

    /* massage references */
    strarray_append(&refhdr, "references");
    message_pruneheader(hdr, &refhdr, 0);
    strarray_fini(&refhdr);

    if (*hdr) {
        over.ref = hdr + 11; /* skip over header name */
        massage_header(over.ref);
    }

    return &over;
}

EXPORTED extern char *index_getheader(struct index_state *state,
                                      uint32_t msgno, char *hdr)
{
    static struct buf staticbuf = BUF_INITIALIZER;
    strarray_t headers = STRARRAY_INITIALIZER;
    struct mailbox *mailbox = state->mailbox;
    struct index_record record;
    char *buf;

    if (index_reload_record(state, msgno, &record))
        return NULL;

    /* see if the header is cached */
    if (mailbox_cached_header(hdr) != BIT32_MAX &&
        !mailbox_cacherecord(mailbox, &record)) {
        buf_copy(&staticbuf, cacheitem_buf(&record, CACHE_HEADERS));
    }
    else {
        /* uncached header */
        struct buf msgbuf = BUF_INITIALIZER;
        if (mailbox_map_record(mailbox, &record, &msgbuf))
            return NULL;
        buf_setcstr(&staticbuf, index_readheader(msgbuf.s, msgbuf.len, 0, record.header_size));
        buf_free(&msgbuf);
    }

    buf_cstring(&staticbuf);

    strarray_append(&headers, hdr);
    message_pruneheader(staticbuf.s, &headers, NULL);
    strarray_fini(&headers);

    buf = staticbuf.s;
    if (*buf) {
        buf += strlen(hdr) + 1; /* skip header: */
        massage_header(buf);
    }

    return buf;
}

EXPORTED extern unsigned long index_getsize(struct index_state *state,
                                            uint32_t msgno)
{
    struct index_record record;

    if (index_reload_record(state, msgno, &record))
        return 0;

    return record.size;
}

EXPORTED extern unsigned long index_getlines(struct index_state *state,
                                             uint32_t msgno)
{
    struct index_record record;
    struct body *body = NULL;
    unsigned long lines = 0;

    if (index_reload_record(state, msgno, &record))
        return 0;

    if (mailbox_cacherecord(state->mailbox, &record))
        return 0;

    message_read_bodystructure(&record, &body);
    if (!body) return 0;

    lines = body->content_lines;

    message_free_body(body);
    free(body);

    return lines;
}

EXPORTED const char *index_mboxname(const struct index_state *state)
{
    if (!state) return NULL;
    return state->mboxname;
}

EXPORTED int index_hasrights(const struct index_state *state, int rights)
{
    return state->myrights & rights;
}

/*
 * Parse a sequence into an array of sorted & merged ranges.
 */
static seqset_t *_parse_sequence(struct index_state *state,
                                      const char *sequence, int usinguid)
{
    unsigned maxval;

    /* Per RFC 3501, seq-number ABNF:
       "*" represents the largest number in use.
       In the case of message sequence numbers,
       it is the number of messages in a non-empty mailbox.
       In the case of unique identifiers,
       it is the unique identifier of the last message in the mailbox
       or, if the mailbox is empty, the mailbox's current UIDNEXT value.
    */
    if (usinguid) {
        if (state->exists) maxval = index_getuid(state, state->exists);
        else maxval = state->last_uid + 1;
    }
    else maxval = state->exists;

    return seqset_parse(sequence, NULL, maxval);
}

/*
 * Create a new search program.
 */
EXPORTED struct searchargs *new_searchargs(const char *tag, int state,
                                           struct namespace *namespace,
                                           const char *userid,
                                           struct auth_state *authstate,
                                           int isadmin)
{
    struct searchargs *sa;

    sa = (struct searchargs *)xzmalloc(sizeof(struct searchargs));
    sa->tag = tag;
    sa->state = state;
    /* default charset is US-ASCII */
    sa->charset = charset_lookupname("US-ASCII");

    sa->namespace = namespace;
    sa->userid = userid;
    sa->authstate = authstate;
    sa->isadmin = isadmin;

    return sa;
}

/*
 * Free the searchargs 's'
 */
EXPORTED void freesearchargs(struct searchargs *s)
{
    if (!s) return;

    charset_free(&s->charset);
    search_expr_free(s->root);
    free(s);
}

EXPORTED char *sortcrit_as_string(const struct sortcrit *sortcrit)
{
    struct buf b = BUF_INITIALIZER;
    static const char * const key_names[] = {
        "SEQUENCE", "ARRIVAL", "CC", "DATE",
        "DISPLAYFROM", "DISPLAYTO", "FROM",
        "SIZE", "SUBJECT", "TO", "ANNOTATION",
        "MODSEQ", "UID", "HASFLAG", "CONVMODSEQ",
        "CONVEXISTS", "CONVSIZE", "HASCONVFLAG",
        "FOLDER", "RELEVANCY", "SPAMSCORE", "GUID",
        "EMAILID", "THREADID", "SAVEDATE", "SNOOZEDUNTIL"
    };

    do {
        if (b.len)
            buf_putc(&b, ' ');
        if (sortcrit->flags & SORT_REVERSE)
            buf_appendcstr(&b, "REVERSE ");

        if (sortcrit->key < VECTOR_SIZE(key_names))
            buf_appendcstr(&b, key_names[sortcrit->key]);
        else
            buf_printf(&b, "UNKNOWN%u", sortcrit->key);

        switch (sortcrit->key) {
        case SORT_ANNOTATION:
            buf_printf(&b, " \"%s\" \"%s\"",
                       sortcrit->args.annot.entry,
                       *sortcrit->args.annot.userid ?
                            "value.priv" : "value.shared");
            break;
        }
        sortcrit++;
    } while (sortcrit->key);

    return buf_release(&b);
}

/*
 * Free an array of sortcrit
 */
EXPORTED void freesortcrit(struct sortcrit *s)
{
    int i = 0;

    if (!s) return;
    do {
        switch (s[i].key) {
        case SORT_ANNOTATION:
            free(s[i].args.annot.entry);
            free(s[i].args.annot.userid);
            break;
        case SORT_HASFLAG:
        case SORT_HASCONVFLAG:
            free(s[i].args.flag.name);
            break;
        case SORT_SAVEDATE:
        case SORT_SNOOZEDUNTIL:
            free(s[i].args.mailbox.id);
            break;
        }
        i++;
    } while (s[i].key != SORT_SEQUENCE);
    free(s);
}

EXPORTED int insert_into_mailbox_allowed(struct mailbox *mailbox)
{
    int r = 0;

    /* prohibit inserting into \Snoozed mailbox */
    if (mailbox->i.options & OPT_IMAP_HAS_ALARMS) {
        struct buf attrib = BUF_INITIALIZER;
        char *userid = mboxname_to_userid(mailbox_name(mailbox));

        r = annotatemore_lookup(mailbox_name(mailbox), "/specialuse", userid, &attrib);
        free(userid);

        if (!r && buf_len(&attrib)) {
            strarray_t *specialuse =
                strarray_split(buf_cstring(&attrib), NULL, 0);

            if (strarray_find(specialuse, "\\Snoozed", 0) >= 0) {
                r = IMAP_MAILBOX_NOTSUPPORTED;
            }
            strarray_free(specialuse);
        }
        buf_free(&attrib);
    }

    return r;
}
