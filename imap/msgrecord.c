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

#include "imap_err.h"
#include "mailbox.h"

#include "msgrecord.h"

struct msgrecord {
    int rw;
    int refcount;

    uint32_t have;
    struct mailbox *mbox;
    struct index_record record;
    uint32_t uid;
    message_t *msg;
    annotate_state_t *annot_state;
};

#define M_MAILBOX       (1<<0)      /* an open mailbox* */
#define M_RECORD        (1<<2)      /* a valid index_record */
#define M_UID           (1<<3)      /* valid UID in index_record */
#define M_MESSAGE       (1<<16)     /* message object - not in messag_priv */
#define M_CACHE         (1<<5)      /* mmap()ed cyrus.cache */
#define M_ANNOTATIONS   (1<<17)     /* annotations - not in messag_priv */
#define M_ALL           (~0U)       /* everything */

static int msgrecord_need(const msgrecord_t *mrc, unsigned int need)
{
#define is_missing(flags)    ((need & ~(mr->have)) & (flags))
#define found(flags)         (mr->have |= (flags))
    int r = 0;

    msgrecord_t *mr = (msgrecord_t*) mrc;

    if (!is_missing(M_ALL))
        return 0;       /* easy, we already have it */

    if (is_missing(M_MAILBOX)) {
        /* We can't get this for ourselves,
         * it needs to be passed in by the caller */
        return IMAP_NOTFOUND;
    }

    if (is_missing(M_UID)) {
        /* We can't get this for ourselves,
         * it needs to be passed in by the caller */
        return IMAP_NOTFOUND;
    }

    if (is_missing(M_RECORD)) {
        r = msgrecord_need(mr, M_MAILBOX|M_UID);
        if (r) return r;

        if (!(r = mailbox_find_index_record(mr->mbox, mr->uid, &mr->record))) {
            found(M_RECORD);
        }
    }

    if (is_missing(M_MESSAGE)) {
        r = msgrecord_need(mr, M_RECORD);
        if (r) return r;

        mr->msg = message_new_from_record(mr->mbox, &mr->record);
        if (mr->msg) {
            found(M_MESSAGE);
        }
    }

    if (is_missing(M_CACHE)) {
        r = msgrecord_need(mr, M_MAILBOX|M_RECORD);
        if (r) return r;
        r = mailbox_cacherecord(mr->mbox, &mr->record);
        if (r) return r;
        found(M_CACHE);
    }

    if (is_missing(M_ANNOTATIONS)) {
        r = msgrecord_need(mr, M_MAILBOX|M_UID);
        if (r) return r;
        mr->annot_state = annotate_state_new();
        r = annotate_state_set_message(mr->annot_state, mr->mbox, mr->uid);
        if (r) return r;
        found(M_ANNOTATIONS);
    }

#undef is_missing
#undef found

    return r;
}

EXPORTED msgrecord_t *msgrecord_new_from_uid(struct mailbox *mbox, uint32_t uid)
{
    msgrecord_t *mr = xzmalloc(sizeof(struct msgrecord));

    mr->mbox = mbox;
    mr->uid = uid;
    mr->have = M_MAILBOX|M_UID;
    mr->refcount++;

    return mr;
}

EXPORTED msgrecord_t *msgrecord_new_from_index_record(struct mailbox *mbox,
                                                      struct index_record record)
{
    msgrecord_t *mr = xzmalloc(sizeof(struct msgrecord));

    mr->mbox = mbox;
    mr->uid = record.uid;
    mr->record = record;
    mr->have = M_MAILBOX|M_UID|M_RECORD;

    return mr;
}


static void msgrecord_free(msgrecord_t *mr)
{
    if (mr->msg) message_unref(&mr->msg);
    free(mr);
}

EXPORTED void msgrecord_unref(msgrecord_t **mrp)
{
    msgrecord_t *mr;

    if (!mrp || !(mr = *mrp)) return;
    assert(mr->refcount >= 1);
    if (--mr->refcount == 0) {
        if (mr->annot_state) {
            annotate_state_abort(&mr->annot_state);
        }
        msgrecord_free(mr);
    }
    *mrp = NULL;
}

EXPORTED int msgrecord_get_systemflags(const msgrecord_t *mr, uint32_t *flags)
{
    int r = msgrecord_need(mr, M_RECORD);
    if (r) return r;
    *flags = mr->record.system_flags;
    return 0;
}

EXPORTED int msgrecord_hasflag(const msgrecord_t *mr, const char *flag, int *has)
{
    int r = msgrecord_need(mr, M_RECORD);
    if (r) return r;
    *has = mailbox_record_hasflag(mr->mbox, &mr->record, flag);
    return 0;
}

EXPORTED int msgrecord_get_internaldate(const msgrecord_t *mr, time_t *t)
{
    int r = msgrecord_need(mr, M_RECORD);
    if (r) return r;
    *t = mr->record.internaldate;
    return 0;
}

EXPORTED int msgrecord_get_cid(const msgrecord_t *mr, bit64 *cid)
{
    int r = msgrecord_need(mr, M_RECORD);
    if (r) return r;
    *cid = mr->record.cid;
    return 0;
}

EXPORTED int msgrecord_get_size(const msgrecord_t *mr, uint32_t *size)
{
    int r = msgrecord_need(mr, M_RECORD);
    if (r) return r;
    *size = mr->record.size;
    return 0;
}

EXPORTED int msgrecord_get_guid(const msgrecord_t *mr, struct message_guid *guid)
{
    int r = msgrecord_need(mr, M_RECORD);
    if (r) return r;
    *guid = mr->record.guid;
    return 0;
}

EXPORTED int msgrecord_get_message(const msgrecord_t *mr, message_t **msg)
{
    int r = msgrecord_need(mr, M_MESSAGE);
    if (r) return r;
    *msg = mr->msg;
    return 0;
}

EXPORTED int msgrecord_get_body(const msgrecord_t *mr, struct buf *buf)
{
    /* FIXME this should probably be a function of message_t */
    int r = msgrecord_need(mr, M_CACHE);
    if (r) return r;

    /* Map the message into memory */
    r = mailbox_map_record(mr->mbox, &mr->record, buf);
    if (r) return r;

    return 0;
}

EXPORTED int msgrecord_get_bodystructure(const msgrecord_t *mr, struct body **body)
{
    int r = msgrecord_need(mr, M_CACHE);
    if (r) return r;
    message_read_bodystructure(&mr->record, body);
    return 0;
}

EXPORTED int msgrecord_annot_lookup(const msgrecord_t *mr, const char *entry,
                                    const char *userid, struct buf *value)
{
    int r = msgrecord_need(mr, M_MAILBOX|M_UID);
    if (r) return r;
    return annotatemore_msg_lookup(mr->mbox->name, mr->uid, entry, userid, value);
}


EXPORTED int msgrecord_annot_findall(const msgrecord_t *mr,
                                     const char *entry,
                                     annotatemore_find_proc_t proc,
                                     void *rock)
{
    int r = msgrecord_need(mr, M_MAILBOX|M_UID);
    if (r) return r;
    return annotatemore_findall(mr->mbox->name, mr->uid, entry, proc, rock);
}

EXPORTED int msgrecord_annot_write(msgrecord_t *mrw,
                                   const char *entry,
                                   const char *userid,
                                   const struct buf *value)
{
    int r = msgrecord_need(mrw, M_ANNOTATIONS);
    if (r) return r;
    annotate_state_begin(mrw->annot_state); /* safe to call multiple times */
    return annotate_state_write(mrw->annot_state, entry, userid, value);
}

EXPORTED int msgrecord_get_index_record(msgrecord_t *mrw,
                                        struct index_record *record)
{
    int r = msgrecord_need(mrw, M_RECORD);
    if (r) return r;
    *record = mrw->record;
    return 0;
}

EXPORTED int msgrecord_get_index_record_rw(msgrecord_t *mrw,
                                           struct index_record **record)
{
    int r = msgrecord_need(mrw, M_RECORD);
    if (r) return r;
    *record = &mrw->record;
    return 0;
}

EXPORTED int msgrecord_add_systemflags(msgrecord_t *mrw, uint32_t system_flags)
{
    int r = msgrecord_need(mrw, M_RECORD);
    if (r) return r;
    mrw->record.system_flags |= system_flags;
    return 0;
}

EXPORTED int msgrecord_set_systemflags(msgrecord_t *mrw, uint32_t system_flags)
{
    int r = msgrecord_need(mrw, M_RECORD);
    if (r) return r;
    mrw->record.system_flags = system_flags;
    return 0;
}

/* mailbox.c code goes here */

EXPORTED int mailbox_find_msgrecord_internal(struct mailbox *mbox,
                                             uint32_t uid,
                                             int reload,
                                             const msgrecord_t **mrp)
{

    int r = 0;
    msgrecord_t *mr;
    struct buf buf = BUF_INITIALIZER;

    /* FIXME depending on how many records are open, a hash table might
     * not a good choice. I'd like a balanced tree optimized for
     * 32-bit unsigned int keys. For prototyping, a hash table will do */
    /* Lookup if we already have a msgrecords for this UID. msgrecords in
     * mbox->msgrecords are read-only, so its safe to pass around pointers
     * to the same instance */
    buf_printf(&buf, "%d", uid);
    if (!mbox->msgrecords) {
        mbox->msgrecords = xzmalloc(sizeof(hash_table));
        construct_hash_table(mbox->msgrecords, 512, 0);
    }

    mr = hash_lookup(buf_cstring(&buf), mbox->msgrecords);
    if (!mr) {
        mr = msgrecord_new_from_uid(mbox, uid);
        /* force load of index record */
        r = msgrecord_need(mr, M_RECORD);
        if (r) {
            msgrecord_unref(&mr);
            goto done;
        }
        hash_insert(buf_cstring(&buf), mr, mbox->msgrecords);
    }
    else if (reload) {
        r = msgrecord_need(mr, M_RECORD);
        if (r) goto done;
        r = mailbox_reload_index_record(mbox, &mr->record);
        if (r) goto done;
    }
    *mrp = mr;

done:
    buf_free(&buf);
    return r;
}

EXPORTED int mailbox_find_msgrecord(struct mailbox *mbox,
                                    uint32_t uid,
                                    const msgrecord_t **mrp)
{
    return mailbox_find_msgrecord_internal(mbox, uid, 0, mrp);
}

EXPORTED int mailbox_find_msgrecord_rw(struct mailbox *mbox,
                                       uint32_t uid,
                                       msgrecord_t **mrp)
{
    int r;
    const msgrecord_t *mr;
    msgrecord_t *mrw;

    r = mailbox_find_msgrecord(mbox, uid, &mr);
    if (r) return r;

    r = mailbox_edit_msgrecord(mbox, mr, &mrw);
    if (r) return r;

    *mrp = mrw;
    return 0;
}

EXPORTED int mailbox_last_msgrecord(struct mailbox *mbox, const msgrecord_t **mr)
{

   return mailbox_find_msgrecord_internal(mbox, mbox->i.last_uid, 1, mr);
}

EXPORTED int mailbox_edit_msgrecord(struct mailbox *mbox, const msgrecord_t *mr,
                                    msgrecord_t **mrw)
{
    assert(mbox);
    *mrw = (msgrecord_t *) mr; // FIXME meh...
    return 0;
}

EXPORTED int mailbox_save_msgrecord(struct mailbox *mbox, msgrecord_t *mrw)
{
    int r = 0;
    if (mrw->have & M_ANNOTATIONS) {
        r = annotate_state_commit(&mrw->annot_state);
        if (r) return r;
    }
    if (mrw->have & M_RECORD) {
        r = mailbox_rewrite_index_record(mbox, &mrw->record);
        if (r) return r;
    }
    return r;
}

