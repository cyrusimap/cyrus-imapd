/* conversations.h -- Routines for dealing with the conversations database
 *
 * Copyright (c) 1994-2010 Carnegie Mellon University.  All rights reserved.
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

#ifndef __CYRUS_CONVERSATIONS_H_
#define __CYRUS_CONVERSATIONS_H_ 1

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include "arrayu64.h"
#include "hash.h"
#include "hashu64.h"
#include "message_guid.h"
#include "strarray.h"
#include "util.h"

typedef bit64   conversation_id_t;
#define CONV_FMT "%016llx"
#define NULLCONVERSATION        (0ULL)

struct index_record;
struct mailbox;

struct conversations_state {
    struct db *db;
    struct txn *txn;
    strarray_t *counted_flags;
    strarray_t *folder_names;
    hash_table folderstatus;
    char *path;
};

struct conversations_open {
    struct conversations_state s;
    struct conversations_open *next;
};

struct conversations_open *open_conversations;

typedef struct conversation conversation_t;
typedef struct conv_folder  conv_folder_t;
typedef struct conv_sender  conv_sender_t;
typedef struct conv_status  conv_status_t;
typedef struct conv_guidrec conv_guidrec_t;
typedef struct conv_thread  conv_thread_t;

#define MAX_CONVERSATION_FLAGS 256

struct conv_thread {
    conv_thread_t *next;
    struct message_guid guid;
    int exists;
    time_t internaldate;
    int32_t msgid;
    int32_t inreplyto;
};

struct conv_folder {
    conv_folder_t   *next;
    int             number;
    modseq_t        modseq;
    uint32_t        num_records;
    uint32_t        exists;
    uint32_t        unseen;
    uint32_t        prev_exists;
};

struct conv_guidrec {
    const char      *mboxname;
    uint32_t        uid;
    const char      *part;
};

struct conv_sender {
    conv_sender_t   *next;
    char            *name;
    char            *route;
    char            *mailbox;
    char            *domain;
    time_t          lastseen;
    uint32_t        exists;
};

struct conv_status {
    modseq_t modseq;
    uint32_t exists;
    uint32_t unseen;
};
#define CONV_STATUS_INIT {0, 0, 0}

struct conversation {
    modseq_t        modseq;
    uint32_t        num_records;
    uint32_t        exists;
    uint32_t        unseen;
    uint32_t        prev_unseen;
    uint32_t        size;
    uint32_t        *counts;
    conv_folder_t   *folders;
    conv_sender_t   *senders;
    conv_thread_t   *thread;
    char            *subject;
    int             dirty;
};

#include "mailbox.h"

/* Sets the suffix used for conversations db filenames.  Only needed
 * when doing special weird stuff like the conversations audit mode */
extern void conversations_set_directory(const char *dir);
extern void conversations_set_suffix(const char *suff);
extern char *conversations_getmboxpath(const char *mboxname);
extern char *conversations_getuserpath(const char *username);

extern int conversations_open_path(const char *path,
                                   struct conversations_state **statep);
extern int conversations_open_user(const char *username,
                                   struct conversations_state **statep);
extern int conversations_open_mbox(const char *mboxname,
                                   struct conversations_state **statep);
extern struct conversations_state *conversations_get_path(const char *path);
extern struct conversations_state *conversations_get_user(const char *username);
extern struct conversations_state *conversations_get_mbox(const char *mboxname);

/* either of these close */
extern int conversations_abort(struct conversations_state **state);
extern int conversations_commit(struct conversations_state **state);

/* functions for CONVDB_MSGID database only */
extern int conversations_add_msgid(struct conversations_state *state,
                                   const char *msgid,
                                   conversation_id_t cid);
extern int conversations_get_msgid(struct conversations_state *state,
                                   const char *msgid,
                                   arrayu64_t *cids);
extern conv_folder_t *conversation_get_folder(conversation_t *conv,
                                              int number, int create_flag);

extern void conversation_normalise_subject(struct buf *);

/* G record */
extern const strarray_t *conversations_get_folders(struct conversations_state *state);
extern int conversations_guid_exists(struct conversations_state *state,
                                     const char *guidrep);
extern int conversations_guid_foreach(struct conversations_state *state,
                                      const char *guidrep,
                                      int(*cb)(const conv_guidrec_t*,void*),
                                      void *rock);

/* F record items */
extern int conversation_getstatus(struct conversations_state *state,
                                  const char *mboxname,
                                  conv_status_t *status);
extern int conversation_setstatus(struct conversations_state *state,
                                  const char *mboxname,
                                  const conv_status_t *status);
extern int conversation_storestatus(struct conversations_state *state,
                                    const char *key, size_t keylen,
                                    const conv_status_t *status);
extern int conversation_parsestatus(const char *data, size_t datalen,
                                    conv_status_t *status);

/* B record items */
extern int conversation_get_modseq(struct conversations_state *state,
                                   conversation_id_t cid,
                                   modseq_t *modseqp);
extern int conversation_save(struct conversations_state *state,
                             conversation_id_t cid,
                             conversation_t *conv);
extern int conversation_load(struct conversations_state *state,
                             conversation_id_t cid,
                             conversation_t **convp);
extern int conversation_parse(struct conversations_state *state,
                              const char *data, size_t datalen,
                              conversation_t **convp);
extern int conversation_store(struct conversations_state *state,
                               const char *key, int keylen,
                               conversation_t *conv);
/* Update the internal data about a conversation, enforcing
 * consistency rules (e.g. the conversation's modseq is the
 * maximum of all the per-folder modseqs).  Sets conv->dirty
 * if any data actually changed.  */
extern int conversations_update_record(struct conversations_state *cstate,
                                       struct mailbox *mailbox,
                                       const struct index_record *old,
                                       struct index_record *new);

extern void conversation_update(struct conversations_state *state,
                                conversation_t *conv,
                                const char *mboxname,
                                int delta_num_records,
                                int delta_exists,
                                int delta_unseen,
                                int delta_size,
                                int *delta_counts,
                                modseq_t modseq);
extern conv_folder_t *conversation_find_folder(struct conversations_state *state,
                                               conversation_t *,
                                               const char *mboxname);
extern conversation_t *conversation_new(struct conversations_state *state);
extern void conversation_free(conversation_t *);

extern void conversation_update_sender(conversation_t *conv,
                                       const char *name,
                                       const char *route,
                                       const char *mailbox,
                                       const char *domain,
                                       time_t lastseen,
                                       int delta_exists);

extern int conversations_prune(struct conversations_state *state,
                               time_t thresh, unsigned int *,
                               unsigned int *);
extern void conversations_dump(struct conversations_state *, FILE *);
extern int conversations_undump(struct conversations_state *, FILE *);

extern int conversations_truncate(struct conversations_state *);

extern const char *conversation_id_encode(conversation_id_t cid);
extern int conversation_id_decode(conversation_id_t *cid, const char *text);


extern int conversations_zero_counts(struct conversations_state *state);
extern int conversations_cleanup_zero(struct conversations_state *state);

extern int conversations_rename_folder(struct conversations_state *state,
                                       const char *from_name,
                                       const char *to_name);

#endif /* __CYRUS_CONVERSATIONS_H_ */
