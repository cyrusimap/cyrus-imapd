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

/* While we are prototyping we'll also keep the mailbox.c code here */
extern int mailbox_find_msgrecord(struct mailbox *mbox, uint32_t uid,
                                  const msgrecord_t **mr);
extern int mailbox_find_msgrecord_rw(struct mailbox *mbox, uint32_t uid,
                                     msgrecord_t **mr);

extern int mailbox_last_msgrecord(struct mailbox *mbox, const msgrecord_t **mr);

extern int mailbox_edit_msgrecord(struct mailbox *mbox, const msgrecord_t *mr,
                                  msgrecord_t **mrw);

extern int mailbox_save_msgrecord(struct mailbox *mbox, msgrecord_t *mrw);

extern msgrecord_t *msgrecord_new_from_uid(struct mailbox *mbox, uint32_t uid);
extern msgrecord_t *msgrecord_new_from_index_record(struct mailbox *mbox,
                                                    struct index_record record);

// FIXME extern void msgrecord_ref(msgrecord_t *mr);
extern void msgrecord_unref(msgrecord_t **mr);

/* Getters: all pointer members are owned by msgrecord */
extern int msgrecord_get_body(const msgrecord_t *mr, struct buf *buf);
extern int msgrecord_get_bodystructure(const msgrecord_t *mr, struct body **body);
extern int msgrecord_get_cid(const msgrecord_t *mr, bit64 *cid);
extern int msgrecord_get_guid(const msgrecord_t *mr, struct message_guid *guid);
extern int msgrecord_get_internaldate(const msgrecord_t *mr, time_t *t);
extern int msgrecord_get_message(const msgrecord_t *mr, message_t **msg);
extern int msgrecord_get_size(const msgrecord_t *mr, uint32_t *size);
extern int msgrecord_get_systemflags(const msgrecord_t *mr, uint32_t *flags);
extern int msgrecord_hasflag(const msgrecord_t *mr, const char *flag, int *has);
extern int msgrecord_get_index_record(msgrecord_t *mrw, struct index_record *record);

/* Setters and mutating functions */
extern int msgrecord_get_index_record_rw(msgrecord_t *mrw,
                                         struct index_record **record);

// TODO(rsto): also for userflags, including strarray */
extern int msgrecord_set_systemflags(msgrecord_t *mrw, uint32_t system_flags);
extern int msgrecord_add_systemflags(msgrecord_t *mrw, uint32_t system_flags);

/* A light-weight layer above annotations. */
extern int msgrecord_annot_lookup(const msgrecord_t *mr, const char *entry,
                                  const char *userid, struct buf *value);
extern int msgrecord_annot_findall(const msgrecord_t *mr, const char *entry,
                                   annotatemore_find_proc_t proc,
                                   void *rock);
extern int msgrecord_annot_write(msgrecord_t *mrw, const char *entry,
                                 const char *userid, const struct buf *value);

#endif /* INCLUDED_MSGRECORD_H */
