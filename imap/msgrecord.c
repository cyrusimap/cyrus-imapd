/* msgrecord.c -- Message records encapsulate message metadata
 *
 * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
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

#include <assert.h>
#include <stdint.h>
#include <syslog.h>

#include "mailbox.h"
#include "msgrecord.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

struct msgrecord {
    int refcount;
    int isappend;

    uint32_t have;
    struct mailbox *mbox;
    struct index_record record;
    message_t *msg;
    annotate_state_t *annot_state;
};

#define M_MAILBOX       (1<<0)      /* an open mailbox* */
#define M_RECORD        (1<<2)      /* a valid index_record */
#define M_RECNO         (1<<3)      /* valid UID in index_record */
#define M_UID           (1<<4)      /* valid UID in index_record */
#define M_CACHE         (1<<5)      /* mmap()ed cyrus.cache */
#define M_MESSAGE       (1<<16)     /* message object - not in message_priv */
#define M_ANNOTATIONS   (1<<17)     /* annotations - not in message_priv */
#define M_ALL           (~0U)       /* everything */

static int msgrecord_need(msgrecord_t *mr, unsigned int need)
{
#define is_missing(flags)    ((need & ~(mr->have)) & (flags))
#define found(flags)         (mr->have |= (flags))
    int r = 0;

    if (!is_missing(M_ALL))
        return 0;       /* easy, we already have it */

    if (is_missing(M_MAILBOX)) {
        /* We can't get this for ourselves,
         * it needs to be passed in by the caller */
        return IMAP_NOTFOUND;
    }

    if (is_missing(M_RECORD)) {
        assert(!mr->isappend);
        r = msgrecord_need(mr, M_MAILBOX);
        if (r) return r;

        if (is_missing(M_RECNO) && is_missing(M_UID)) {
            /* need some way to find the record! */
            return IMAP_NOTFOUND;
        }
        r = mailbox_reload_index_record(mr->mbox, &mr->record);
        if (r) return r;

        found(M_RECORD|M_RECNO|M_UID);
    }

    if (is_missing(M_MESSAGE)) {
        r = msgrecord_need(mr, M_RECORD);
        if (r) return r;

        mr->msg = message_new_from_record(mr->mbox, &mr->record);
        if (mr->msg) {
            found(M_MESSAGE);
        }
        // else error??
    }

    if (is_missing(M_CACHE)) {
        r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
        r = mailbox_cacherecord(mr->mbox, &mr->record);
        if (r) return r;
        found(M_CACHE);
    }

    if (is_missing(M_ANNOTATIONS)) {
        if (mr->isappend) {
            syslog(LOG_ERR, "msgrecord: msgrecord msut be appended");
            return IMAP_NOTFOUND;
        }
        r = msgrecord_need(mr, M_MAILBOX|M_UID);
        if (r) return r;
        r = mailbox_get_annotate_state(mr->mbox, mr->record.uid, &mr->annot_state);
        if (r) return r;
        found(M_ANNOTATIONS);
    }

#undef is_missing
#undef found

    return r;
}

EXPORTED msgrecord_t *msgrecord_new(struct mailbox *mbox)
{
    msgrecord_t *mr = xzmalloc(sizeof(struct msgrecord));

    mr->mbox = mbox;
    mr->have = M_MAILBOX|M_RECORD;
    mr->refcount++;
    mr->isappend = 1;

    return mr;
}

EXPORTED msgrecord_t *msgrecord_from_uid(struct mailbox *mbox, uint32_t uid)
{
    msgrecord_t *mr = xzmalloc(sizeof(struct msgrecord));

    mr->mbox = mbox;
    mr->record.uid = uid;
    mr->have = M_MAILBOX|M_UID;
    mr->refcount++;
    mr->isappend = 0;

    return mr;
}

EXPORTED void msgrecord_set_from_recno(struct mailbox *mbox, uint32_t recno, msgrecord_t *mr)
{
    assert(mr->refcount == 1);

    memset(mr, 0, sizeof(msgrecord_t));
    mr->mbox = mbox;
    mr->record.recno = recno;
    mr->have = M_MAILBOX|M_RECNO;
    mr->isappend = 0;
    mr->refcount = 1;
}

EXPORTED msgrecord_t *msgrecord_from_recno(struct mailbox *mbox, uint32_t recno)
{
    msgrecord_t *mr = xzmalloc(sizeof(struct msgrecord));

    mr->mbox = mbox;
    mr->record.recno = recno;
    mr->have = M_MAILBOX|M_RECNO;
    mr->refcount++;
    mr->isappend = 0;

    return mr;
}

EXPORTED msgrecord_t *msgrecord_from_index_record(struct mailbox *mbox,
                                                  const struct index_record *record)
{
    assert(record->recno);
    assert(record->uid);

    msgrecord_t *mr = xzmalloc(sizeof(struct msgrecord));

    mr->mbox = mbox;
    mr->record = *record; // copy all the fields
    mr->have = M_MAILBOX|M_UID|M_RECNO|M_RECORD;
    mr->refcount++;
    mr->isappend = 0;

    return mr;
}

EXPORTED msgrecord_t *msgrecord_copy_msgrecord(struct mailbox *mbox,
                                               msgrecord_t *mr)
{
    /* need to have record, annotations and cache read in before we copy */
    assert(!msgrecord_need(mr, M_RECORD|M_CACHE|M_ANNOTATIONS));

    msgrecord_t *res = msgrecord_from_index_record(mbox ? mbox : mr->mbox, &mr->record);
    /* new records are appends */
    res->isappend = 1;

    /* these were for the old record, so wipe them */
    res->have &= ~(M_UID|M_RECNO);
    res->record.uid = 0;
    res->record.recno = 0;

    return res;
}


static void msgrecord_free(msgrecord_t *mr)
{
    if (mr->msg) message_unref(&mr->msg);
    free(mr);
}

EXPORTED void msgrecord_unref(msgrecord_t **mrp)
{
    msgrecord_t *mr;

    if (!mrp) return;
    mr = (msgrecord_t*) *mrp;
    if (!mr) return;

    assert(mr->refcount >= 1);
    if (--mr->refcount == 0) {
        msgrecord_free(mr);
    }
    *mrp = NULL;
}

EXPORTED int msgrecord_get_systemflags(msgrecord_t *mr, uint32_t *flags)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *flags = mr->record.system_flags;
    return 0;
}

EXPORTED int msgrecord_get_internalflags(msgrecord_t *mr, uint32_t *flags)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *flags = mr->record.internal_flags;
    return 0;
}

EXPORTED int msgrecord_get_userflags(msgrecord_t *mr,
                                     uint32_t flags[MAX_USER_FLAGS/32])
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    memcpy(flags, mr->record.user_flags, sizeof(uint32_t)*(MAX_USER_FLAGS/32));
    return 0;
}

EXPORTED int msgrecord_hasflag(msgrecord_t *mr, const char *flag, int *has)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *has = mailbox_record_hasflag(mr->mbox, &mr->record, flag);
    return 0;
}

EXPORTED int msgrecord_get_internaldate(msgrecord_t *mr, time_t *t)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *t = mr->record.internaldate;
    return 0;
}

EXPORTED int msgrecord_get_savedate(msgrecord_t *mr, time_t *t)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    if (mr->record.savedate)
        *t = mr->record.savedate;
    else
        *t = mr->record.internaldate;
    return 0;
}

EXPORTED int msgrecord_get_lastupdated(msgrecord_t *mr, time_t *t)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *t = mr->record.last_updated;
    return 0;
}

EXPORTED int msgrecord_get_cid(msgrecord_t *mr, bit64 *cid)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *cid = mr->record.cid;
    return 0;
}

EXPORTED int msgrecord_get_size(msgrecord_t *mr, uint32_t *size)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *size = mr->record.size;
    return 0;
}

EXPORTED int msgrecord_get_header_size(msgrecord_t *mr, uint32_t *header_size)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *header_size = mr->record.header_size;
    return 0;

}

EXPORTED int msgrecord_get_guid(msgrecord_t *mr, struct message_guid *guid)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *guid = mr->record.guid;
    return 0;
}

EXPORTED int msgrecord_get_uid(msgrecord_t *mr, uint32_t *uid)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *uid = mr->record.uid;
    return 0;
}

EXPORTED int msgrecord_get_modseq(msgrecord_t *mr, modseq_t *modseq)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *modseq = mr->record.modseq;
    return 0;
}

EXPORTED int msgrecord_get_createdmodseq(msgrecord_t *mr, modseq_t *modseq)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *modseq = mr->record.createdmodseq;
    return 0;
}

EXPORTED int msgrecord_load_cache(msgrecord_t *mr)
{
    return msgrecord_need(mr, M_CACHE);
}

EXPORTED int msgrecord_get_cache_version(msgrecord_t *mr, int *cache_version)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *cache_version = mr->record.cache_version;
    return 0;
}

EXPORTED int msgrecord_get_cache_env(msgrecord_t *mr, int token, char **tok)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *tok = mailbox_cache_get_env(mr->mbox, &mr->record, token);
    return 0;
}

EXPORTED int msgrecord_get_cache_item(msgrecord_t *mr, int field, char **item)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    *item = xstrndup(cacheitem_base(&mr->record, field),
                     cacheitem_size(&mr->record, field));
    return 0;
}

EXPORTED int msgrecord_get_mailbox(msgrecord_t *mr, struct mailbox **mboxp)
{
    int r = msgrecord_need(mr, M_MAILBOX);
    if (r) return r;
    *mboxp = mr->mbox;
    return 0;
}


EXPORTED int msgrecord_get_message(msgrecord_t *mr, message_t **msg)
{
    int r = msgrecord_need(mr, M_MESSAGE);
    if (r) return r;
    *msg = mr->msg;
    return 0;
}

EXPORTED int msgrecord_get_messageid(msgrecord_t *mr, struct buf *buf)
{
    int r = msgrecord_need(mr, M_MESSAGE);
    if (r) return r;
    return message_get_messageid(mr->msg, buf);
}

EXPORTED int msgrecord_get_body(msgrecord_t *mr, struct buf *buf)
{
    int  r;
    if (!mr->isappend) {
        r = msgrecord_need(mr, M_CACHE);
        if (r) return r;
    }

    /* Map the message into memory */
    r = mailbox_map_record(mr->mbox, &mr->record, buf);
    if (r) return r;

    return 0;
}

EXPORTED int msgrecord_extract_bodystructure(msgrecord_t *mr, struct body **body)
{
    int r = msgrecord_need(mr, M_CACHE);
    if (r) return r;
    message_read_bodystructure(&mr->record, body);
    return 0;
}

EXPORTED int msgrecord_get_index_record(msgrecord_t *mr,
                                        struct index_record *record)
{
    int r = msgrecord_need(mr, M_RECORD);
    if (r) return r;
    *record = mr->record;
    return 0;
}

EXPORTED int msgrecord_get_fname(msgrecord_t *mr, const char **fname)
{
    int r = msgrecord_need(mr, M_RECORD);
    if (r) return r;
    *fname = mailbox_record_fname(mr->mbox, &mr->record);
    return 0;
}


EXPORTED int msgrecord_annot_lookup(msgrecord_t *mr, const char *entry,
                                    const char *userid, struct buf *value)
{
    int r = msgrecord_need(mr, M_MAILBOX|M_UID|M_ANNOTATIONS);
    if (r) return r;

    return annotatemore_msg_lookup(mr->mbox, mr->record.uid, entry, userid, value);
}


EXPORTED int msgrecord_annot_findall(msgrecord_t *mr,
                                     const char *entry,
                                     annotatemore_find_proc_t proc,
                                     void *rock)
{
    int r = msgrecord_need(mr, M_MAILBOX|M_UID|M_ANNOTATIONS);
    if (r) return r;
    return annotatemore_findall_mailbox(mr->mbox, mr->record.uid, entry, /*modseq*/0,
                                proc, rock, /*flags*/0);
}

EXPORTED int msgrecord_annot_set_auth(msgrecord_t *mr, int isadmin,
                                      const char *userid,
                                      const struct auth_state *authstate)
{
    int r = msgrecord_need(mr, M_ANNOTATIONS);
    if (r) return r;
    annotate_state_begin(mr->annot_state); /* safe to call multiple times */
    annotate_state_set_auth(mr->annot_state, isadmin, userid, authstate);
    return 0;
}

EXPORTED int msgrecord_annot_write(msgrecord_t *mr,
                                   const char *entry,
                                   const char *userid,
                                   const struct buf *value)
{
    int r = msgrecord_need(mr, M_ANNOTATIONS|M_RECORD);
    if (r) return r;
    annotate_state_begin(mr->annot_state);

    if (!strcmpsafe(userid, "") && !strcmp(entry, IMAP_ANNOT_NS "snoozed")) {
        if (buf_len(value)) mr->record.internal_flags |= FLAG_INTERNAL_SNOOZED;
        else mr->record.internal_flags &= ~FLAG_INTERNAL_SNOOZED;
    }

    return annotate_state_write(mr->annot_state, entry, userid, value);
}

EXPORTED int msgrecord_annot_writeall(msgrecord_t *mr, struct entryattlist *l)
{
    int r = msgrecord_need(mr, M_ANNOTATIONS);
    if (r) return r;
    annotate_state_begin(mr->annot_state);

    struct entryattlist *e;
    struct attvaluelist *av;
    for (e = l; e; e = e->next) {
        if (strcmp(e->entry, IMAP_ANNOT_NS "snoozed")) continue;
        for (av = e->attvalues; av; av = av->next) {
            if (strcmp(av->attrib, "value.shared")) continue;
            if (buf_len(&av->value)) mr->record.internal_flags |= FLAG_INTERNAL_SNOOZED;
            else mr->record.internal_flags &= ~FLAG_INTERNAL_SNOOZED;
        }
    }

    return annotate_state_store(mr->annot_state, l);
}

EXPORTED int msgrecord_extract_annots(msgrecord_t *mr,
                                      struct entryattlist **annots)
{
    int r = msgrecord_need(mr, M_MAILBOX|M_RECORD|M_ANNOTATIONS);
    if (r) return r;
    // XXX - is there a way to get error return?
    *annots = mailbox_extract_annots(mr->mbox, &mr->record);
    return 0;
}

EXPORTED int msgrecord_extract_flags(msgrecord_t *mr,
                                     const char *userid,
                                     strarray_t **flags)
{
    int r = msgrecord_need(mr, M_MAILBOX|M_RECORD);
    if (r) return r;
    *flags = mailbox_extract_flags(mr->mbox, &mr->record, userid);
    return *flags == NULL ? IMAP_INTERNAL : 0;
}

EXPORTED int msgrecord_get_index_record_rw(msgrecord_t *mr,
                                           struct index_record **record)
{
    int r = msgrecord_need(mr, M_MAILBOX);
    if (r) return r;

    assert(mailbox_index_islocked(mr->mbox, 1));

    r = msgrecord_need(mr, M_RECORD);
    if (r) return r;
    *record = &mr->record;
    return 0;
}

EXPORTED int msgrecord_add_systemflags(msgrecord_t *mr, uint32_t system_flags)
{
    mr->record.system_flags |= system_flags;
    return 0;
}

EXPORTED int msgrecord_add_internalflags(msgrecord_t *mr, uint32_t internal_flags)
{
    mr->record.internal_flags |= internal_flags;
    return 0;
}

EXPORTED int msgrecord_set_uid(msgrecord_t *mr, uint32_t uid)
{
    assert(mr->isappend);
    int r = msgrecord_need(mr, M_MAILBOX);
    if (r) return r;
    assert(mailbox_index_islocked(mr->mbox, 1));
    assert(mr->mbox->i.last_uid < uid);
    mr->record.uid = uid;
    mr->have |= M_UID;
    return 0;
}

EXPORTED int msgrecord_set_cid(msgrecord_t *mr, bit64 cid)
{
    mr->record.cid = cid;
    return 0;
}

EXPORTED int msgrecord_set_systemflags(msgrecord_t *mr, uint32_t system_flags)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    mr->record.system_flags = system_flags;
    return 0;
}

EXPORTED int msgrecord_set_internalflags(msgrecord_t *mr, uint32_t internal_flags)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    mr->record.internal_flags = internal_flags;
    return 0;
}

EXPORTED int msgrecord_set_userflags(msgrecord_t *mr,
                                     uint32_t user_flags[MAX_USER_FLAGS/32])
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    memcpy(mr->record.user_flags, user_flags, sizeof(uint32_t)*(MAX_USER_FLAGS/32));
    return 0;
}

EXPORTED int msgrecord_set_userflag(msgrecord_t *mr, uint32_t userflag, int val)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    if (val)
        mr->record.user_flags[userflag/32] |= 1<<(userflag&31);
    else
        mr->record.user_flags[userflag/32] &= ~(1<<(userflag&31));
    return 0;
}

EXPORTED int msgrecord_set_cache_offset(msgrecord_t *mr, size_t offset)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    mr->record.cache_offset = offset;
    return 0;
}

EXPORTED int msgrecord_set_internaldate(msgrecord_t *mr, time_t internaldate)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    mr->record.internaldate = internaldate;
    return 0;
}

EXPORTED int msgrecord_set_savedate(msgrecord_t *mr, time_t savedate)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    mr->record.savedate = savedate;
    return 0;
}

EXPORTED int msgrecord_set_bodystructure(msgrecord_t *mr, struct body *body)
{
    return message_create_record(&mr->record, body);
}

EXPORTED int msgrecord_set_createdmodseq(msgrecord_t *mr, modseq_t modseq)
{
    if (!mr->isappend) {
        int r = msgrecord_need(mr, M_RECORD);
        if (r) return r;
    }
    mr->record.createdmodseq = modseq;
    return 0;
}

EXPORTED int msgrecord_should_archive(msgrecord_t *mr, void *rock)
{
    return mailbox_should_archive(mr->mbox, &mr->record, rock);
}

/* mailbox.c code goes here */

static int msgrecord_find_internal(struct mailbox *mbox,
                                           uint32_t uid,
                                           uint32_t recno,
                                           msgrecord_t **mrp)
{
    int r = 0;
    msgrecord_t *mr = NULL;
    struct buf buf = BUF_INITIALIZER;

    assert(uid || recno);

    /* lookup the message record */
    if (recno) {
        mr = msgrecord_from_recno(mbox, recno);
    }
    else {
        mr = msgrecord_from_uid(mbox, uid);
    }
    /* make sure we have an index_record */
    r = msgrecord_need(mr, M_RECORD);
    if (r) {
        msgrecord_unref(&mr);
        goto done;
    }
    mr->isappend = 0;
    *mrp = mr;

done:
    buf_free(&buf);
    return r;
}

EXPORTED int msgrecord_find(struct mailbox *mbox,
                            uint32_t uid,
                            msgrecord_t **mrp)
{
    return msgrecord_find_internal(mbox, uid, /*recno*/0, mrp);
}

EXPORTED int msgrecord_find_latest(struct mailbox *mbox, msgrecord_t **mr)
{

   return msgrecord_find_internal(mbox, mbox->i.last_uid, /*recno*/0, mr);
}

EXPORTED int msgrecord_find_index_record(struct mailbox *mbox,
                                         struct index_record record,
                                         msgrecord_t **mrp)
{
    int r;
    msgrecord_t *mr = NULL;

    r = record.recno ?
        msgrecord_find_internal(mbox, 0, record.recno, &mr) :
        msgrecord_find_internal(mbox, record.uid, 0, &mr);
    if (r) goto done;
    *mrp = mr;

done:
    return r;
}

static int msgrecord_save(msgrecord_t *mr)
{
    int r = 0;

    if (!mailbox_index_islocked(mr->mbox, 1)) {
        syslog(LOG_ERR, "msgrecord: need mailbox lock to save %s:%d",
                mailbox_name(mr->mbox), mr->record.uid);
        return IMAP_INTERNAL;
    }
    if (mr->isappend) {
        r = mailbox_append_index_record(mr->mbox, &mr->record);
        mr->isappend = 0;
    }
    else {
        r = msgrecord_need(mr, M_RECORD);
        if (!r) r = mailbox_rewrite_index_record(mr->mbox, &mr->record);
    }
    return r;
}

EXPORTED int msgrecord_append(msgrecord_t *mr)
{
    if (!mr->isappend) {
        syslog(LOG_ERR, "msgrecord: can't append, record %s:%d already exists",
                mailbox_name(mr->mbox), mr->record.uid);
        return IMAP_INTERNAL;
    }
    return msgrecord_save(mr);
}

EXPORTED int msgrecord_rewrite(msgrecord_t *mr)
{
    if (mr->isappend) {
        syslog(LOG_ERR, "msgrecord: can't rewrite, record must be appended");
        return IMAP_INTERNAL;
    }
    return msgrecord_save(mr);
}
