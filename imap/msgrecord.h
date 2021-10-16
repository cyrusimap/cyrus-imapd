/* msgrecord.h -- Message records encapsulate message metadata
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

#ifndef INCLUDED_MSGRECORD_H
#define INCLUDED_MSGRECORD_H

#include "annotate.h"

typedef struct msgrecord msgrecord_t;
struct mailbox;

extern int msgrecord_find(struct mailbox *mbox, uint32_t uid, msgrecord_t **mr);
#if 0
extern int msgrecord_find_latest(struct mailbox *mbox, msgrecord_t **mr);
#endif
extern int msgrecord_find_index_record(struct mailbox *mbox, struct index_record record,
                                       msgrecord_t **mrp);
extern int msgrecord_append(msgrecord_t *mr);
extern int msgrecord_rewrite(msgrecord_t *mr);

extern msgrecord_t *msgrecord_new(struct mailbox *mbox);
extern msgrecord_t *msgrecord_from_uid(struct mailbox *mbox, uint32_t uid);
extern msgrecord_t *msgrecord_from_recno(struct mailbox *mbox, uint32_t recno);
extern msgrecord_t *msgrecord_from_index_record(struct mailbox *mbox, const struct index_record *record);
extern msgrecord_t *msgrecord_copy_msgrecord(struct mailbox *mbox, msgrecord_t *mr);
extern void msgrecord_unref(msgrecord_t **mr);

extern void msgrecord_set_from_recno(struct mailbox *mbox, uint32_t recno, msgrecord_t *mr);

/* Getters: all pointer values are owned by msgrecord */
extern int msgrecord_get_body(msgrecord_t *mr, struct buf *buf);
extern int msgrecord_get_cid(msgrecord_t *mr, bit64 *cid);
extern int msgrecord_get_guid(msgrecord_t *mr, struct message_guid *guid);
extern int msgrecord_get_uid(msgrecord_t *mr, uint32_t *uid);
extern int msgrecord_get_messageid(msgrecord_t *mr, struct buf *buf);
extern int msgrecord_get_modseq(msgrecord_t *mr, modseq_t *modseq);
extern int msgrecord_get_createdmodseq(msgrecord_t *mr, modseq_t *modseq);
extern int msgrecord_get_internaldate(msgrecord_t *mr, time_t *t);
extern int msgrecord_get_savedate(msgrecord_t *mr, time_t *t);
extern int msgrecord_get_lastupdated(msgrecord_t *mr, time_t *t);
extern int msgrecord_get_message(msgrecord_t *mr, message_t **msg);
extern int msgrecord_get_size(msgrecord_t *mr, uint32_t *size);
extern int msgrecord_get_header_size(msgrecord_t *mr, uint32_t *header_size);
extern int msgrecord_get_systemflags(msgrecord_t *mr, uint32_t *flags);
extern int msgrecord_get_internalflags(msgrecord_t *mr, uint32_t *flags);
extern int msgrecord_hasflag(msgrecord_t *mr, const char *flag, int *has);
extern int msgrecord_get_index_record(msgrecord_t *mr, struct index_record *record);
extern int msgrecord_get_index_record_rw(msgrecord_t *mr, struct index_record **record);
extern int msgrecord_get_userflags(msgrecord_t *mr, uint32_t user_flags[MAX_USER_FLAGS/32]);
extern int msgrecord_get_fname(msgrecord_t *mr, const char **fname);
extern int msgrecord_get_cache_version(msgrecord_t *mr, int *cache_version);
extern int msgrecord_get_cache_env(msgrecord_t *mr, int token, char **tok);
extern int msgrecord_get_cache_item(msgrecord_t *mr, int field, char **item);
extern int msgrecord_get_mailbox(msgrecord_t *mr, struct mailbox **mailboxptr);

/* Extract: all pointer values are owned by caller */
extern int msgrecord_extract_flags(msgrecord_t *mr, const char *userid, strarray_t **flags);
extern int msgrecord_extract_bodystructure(msgrecord_t *mr, struct body **body);

extern int msgrecord_load_cache(msgrecord_t *mr);

/* Setters and mutating functions */

// TODO(rsto): also strarray variant */
extern int msgrecord_set_systemflags(msgrecord_t *mr, uint32_t system_flags);
extern int msgrecord_add_systemflags(msgrecord_t *mr, uint32_t system_flags);
extern int msgrecord_set_internalflags(msgrecord_t *mr, uint32_t internal_flags);
extern int msgrecord_add_internalflags(msgrecord_t *mr, uint32_t internal_flags);
extern int msgrecord_set_userflags(msgrecord_t *mr, uint32_t user_flags[MAX_USER_FLAGS/32]);
extern int msgrecord_set_userflag(msgrecord_t *mr, uint32_t user_flag, int bit);
extern int msgrecord_set_uid(msgrecord_t *mr, uint32_t uid);
extern int msgrecord_set_cid(msgrecord_t *mr, bit64 cid);
extern int msgrecord_set_bodystructure(msgrecord_t *mr, struct body *body);
extern int msgrecord_set_internaldate(msgrecord_t *mr, time_t internaldate);
extern int msgrecord_set_savedate(msgrecord_t *mr, time_t savedate);
extern int msgrecord_set_cache_offset(msgrecord_t *mr, size_t offset);
extern int msgrecord_set_createdmodseq(msgrecord_t *mr, modseq_t modseq);

/* A light-weight layer above annotations. */
extern int msgrecord_annot_lookup(msgrecord_t *mr, const char *entry,
                                  const char *userid, struct buf *value);
extern int msgrecord_annot_findall(msgrecord_t *mr, const char *entry,
                                   annotatemore_find_proc_t proc,
                                   void *rock);
extern int msgrecord_annot_write(msgrecord_t *mr, const char *entry,
                                 const char *userid, const struct buf *value);
extern int msgrecord_annot_writeall(msgrecord_t *mr, struct entryattlist *l);

extern int msgrecord_annot_set_auth(msgrecord_t *mr, int isadmin,
                                    const char *userid,
                                    const struct auth_state *authstate);

extern int msgrecord_extract_annots(msgrecord_t *mr,
                                    struct entryattlist **annots);

/* misc */
extern int msgrecord_should_archive(msgrecord_t *mr, void *rock);


#endif /* INCLUDED_MSGRECORD_H */
