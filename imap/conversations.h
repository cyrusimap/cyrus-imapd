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
#include "bitvector.h"
#include "hash.h"
#include "hashu64.h"
#include "message_guid.h"
#include "strarray.h"
#include "util.h"

#define FNAME_CONVERSATIONS_SUFFIX "conversations"

#define CONV_FOLDER_KEY_MBOX(state, mailbox) \
    (state->folders_byname ? mailbox_name(mailbox) : mailbox_uniqueid(mailbox))

#define CONV_FOLDER_KEY_MBE(state, mbentry) \
    (!mbentry ? NULL : (state->folders_byname ? mbentry->name : mbentry->uniqueid))

typedef bit64   conversation_id_t;
#define CONV_FMT BIT64_FMT
#define NULLCONVERSATION        (0ULL)

struct index_record;
struct mailbox;

#define CONVERSATIONS_VERSION 2
#define CONVERSATIONS_KEY_VERSION 0
#define CONVERSATIONS_STATUS_VERSION 0
// RECORD_VERSION history:
// 0: original version - no version field in record
// 1: counts messages per folder and GUID, not UID
// 2: NFC-normalizes conversation subject
#define CONVERSATIONS_RECORD_VERSION 2

#define CONV_ISDIRTY     (1<<0)
#define CONV_WITHFOLDERS (1<<1)
#define CONV_WITHSENDERS (1<<2)
#define CONV_WITHSUBJECT (1<<3)
#define CONV_WITHTHREAD  (1<<4)

#define CONV_WITHALL CONV_WITHFOLDERS|CONV_WITHSENDERS|\
                     CONV_WITHSUBJECT|CONV_WITHTHREAD

struct conv_quota {
    ssize_t emails;
    ssize_t storage;
};

#define CONV_QUOTA_INIT { 0, 0 }

struct conversations_state {
    struct db *db;
    struct txn *txn;
    char *annotmboxname;
    strarray_t *counted_flags;
    strarray_t *folders;
    strarray_t *altrep;  // cache the alternative mboxname or uniqueid
    hash_table folderstatus;
    struct conv_quota quota;
    int trashfolder;
    int version;
    char *userid;
    char *trashmboxname;
    char *trashmboxid;
    char *path;
    unsigned folders_byname:1;
    unsigned quota_loaded:1;
    unsigned quota_dirty:1;
    unsigned is_shared:1;
    unsigned compact_emailids:1;
};

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
    uint32_t exists;
    uint64_t nano_internaldate; // nanoseconds since epoch
    modseq_t createdmodseq;
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

#define CONV_GUIDREC_VERSION 4          // (must be <= 127)
#define CONV_GUIDREC_BYNAME_VERSION 1   // last folders byname version

struct conv_guidrec {
    const struct conversations_state *cstate;  // this conversationsdb!
    const char      *guidrep; // [MESSAGE_GUID_SIZE*2], hex-encoded
    int             foldernum;
    uint32_t        uid;
    const char      *part;
    conversation_id_t cid;
    conversation_id_t basecid;      // if version >= 3
    char            version;
    uint32_t        system_flags;   // if version >= 1
    uint32_t        internal_flags; // if version >= 1
    uint64_t        nano_internaldate;   // if version >= 4 (nanoseconds since epoch)
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
    modseq_t threadmodseq;
    uint32_t threadexists;
    uint32_t threadunseen;
    uint32_t emailexists;
    uint32_t emailunseen;
};
#define CONV_STATUS_INIT { 0, 0, 0, 0, 0 }

struct conversation {
    int             version;
    modseq_t        modseq;
    uint32_t        num_records;
    uint32_t        exists;
    uint32_t        unseen;
    uint32_t        size;
    uint32_t        counts[32];
    conv_folder_t   *folders;
    conv_sender_t   *senders;
    conv_thread_t   *thread;
    char            *subject;
    modseq_t        createdmodseq;
    int             flags;
};

#define CONVERSATION_INIT { CONVERSATIONS_RECORD_VERSION, 0, 0, 0, 0, 0, {0}, \
                            NULL, NULL, NULL, NULL, 0, CONV_ISDIRTY }

struct emailcountitems {
    size_t foldernumrecords;
    size_t folderexists;
    size_t folderunseen;
    size_t numrecords;
    size_t exists;
    size_t unseen;
};

#define EMAILCOUNTITEMS_INIT { 0, 0, 0, 0, 0, 0 }

struct emailcounts {
    int foldernum;
    int trashfolder;
    int ispost;
    struct emailcountitems pre;
    struct emailcountitems post;
    bitvector_t exists_foldernums;
    bitvector_t mbtype_known;
    bitvector_t mbtype_mail;
};

#define EMAILCOUNTS_INIT { -1, -1, 0, EMAILCOUNTITEMS_INIT, EMAILCOUNTITEMS_INIT, \
                           BV_INITIALIZER, BV_INITIALIZER, BV_INITIALIZER }

extern void emailcounts_fini(struct emailcounts *ecounts);

#include "mailbox.h"

/* Sets the suffix used for conversations db filenames.  Only needed
 * when doing special weird stuff like the conversations audit mode */
extern void conversations_set_directory(const char *dir);
extern void conversations_set_suffix(const char *suff);
extern char *conversations_getmboxpath(const char *mboxname);
extern char *conversations_getuserpath(const char *username);

#define conversations_open_path(p, u, sh, sp) \
    conversations_open_path_version(p, u, sh, sp, 0)
extern int conversations_open_path_version(const char *path,
                                           const char *userid, int shared,
                                           struct conversations_state **statep,
                                           int version);
#define conversations_open_user(u, sh, sp) \
    conversations_open_user_version(u, sh, sp, 0)
extern int conversations_open_user_version(const char *username, int shared,
                                           struct conversations_state **statep,
                                           int version);
extern int conversations_open_mbox(const char *mboxname, int shared,
                                   struct conversations_state **statep);
extern struct conversations_state *conversations_get_path(const char *path);
extern struct conversations_state *conversations_get_user(const char *username);
extern struct conversations_state *conversations_get_mbox(const char *mboxname);

extern int conversations_num_folders(struct conversations_state *state);
extern const char* conversations_folder_mboxname(const struct conversations_state *state,
                                                 int foldernum);
extern const char* conversations_folder_uniqueid(const struct conversations_state *state,
                                                 int foldernum);
extern int conversation_folder_number(struct conversations_state *state,
                                      const char *name,
                                      int create_flag);

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
extern int conversations_guid_foreach(struct conversations_state *state,
                                      const char *guidrep,
                                      int(*cb)(const conv_guidrec_t*,void*),
                                      void *rock);
extern int conversations_iterate_searchset(struct conversations_state *state,
                                           const void *data, size_t n,
                                           int(*cb)(const conv_guidrec_t*,void*),
                                           void *rock);
extern int conversations_guid_cid_lookup(struct conversations_state *state,
                                         const char *guidrep, struct index_record *record);

/* lookup the matching name or uniqueid */
#define conv_guidrec_mboxname(rec) conversations_folder_mboxname((rec)->cstate, (rec)->foldernum)
#define conv_guidrec_uniqueid(rec) conversations_folder_uniqueid((rec)->cstate, (rec)->foldernum)
#define conv_guidrec_mbentry(rec, mbentryp) ( \
  ((rec)->version > CONV_GUIDREC_BYNAME_VERSION) ? \
   mboxlist_lookup_by_uniqueid(conv_guidrec_uniqueid(rec), mbentryp, NULL) : \
   mboxlist_lookup(conv_guidrec_mboxname(rec), mbentryp, NULL) \
 )
#define conv_guidrec_mboxcmp(rec, mbox) ( \
  ((rec)->version > CONV_GUIDREC_BYNAME_VERSION) ? \
   strcmpsafe(conv_guidrec_uniqueid(rec), mailbox_uniqueid(mbox)) : \
   strcmpsafe(conv_guidrec_mboxname(rec), mailbox_name(mbox)) \
 )

/* J record items */
#define CONV_JMAPID_SIZE 11  // 64-bits base64-encoded w/o padding
extern int conversations_jmapid_guidrep_lookup(struct conversations_state *state,
                                               const char *jidrep,
                                               char guidrep[2*MESSAGE_GUID_SIZE+1]);
extern void conversations_adjust_internaldate(struct conversations_state *cstate,
                                              const char *guidrep,
                                              struct timespec *internaldate);

/* F record items */
extern int conversation_getstatus(struct conversations_state *state,
                                  const char *mailbox,
                                  conv_status_t *status);
extern int conversation_setstatus(struct conversations_state *state,
                                  const char *mailbox,
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
extern int conversation_load_advanced(struct conversations_state *state,
                                      conversation_id_t cid,
                                      conversation_t *convp,
                                      int flags);
extern int conversation_load(struct conversations_state *state,
                             conversation_id_t cid,
                             conversation_t **convp);
extern int conversation_parse(const char *data, size_t datalen,
                              conversation_t *conv, int flags);
extern int conversation_store(struct conversations_state *state,
                               const char *key, int keylen,
                               conversation_t *conv);
/* Update the internal data about a conversation, enforcing
 * consistency rules (e.g. the conversation's modseq is the
 * maximum of all the per-folder modseqs).  Sets CONV_DIRTY
 * if any data actually changed.  */
extern int conversations_update_record(struct conversations_state *cstate,
                                       struct mailbox *mailbox,
                                       const struct index_record *old,
                                       struct index_record *new_,
                                       int allowrenumber,
                                       int ignorelimits,
                                       int silent);

extern int conversation_update(struct conversations_state *state,
                                conversation_t *conv,
                                struct emailcounts *ecounts,
                                ssize_t delta_size, int *delta_counts,
                                modseq_t modseq, modseq_t createdmodseq, int silent);
extern conv_folder_t *conversation_find_folder(struct conversations_state *state,
                                               conversation_t *,
                                               const char *mboxname);
extern conversation_t *conversation_new();
extern void conversation_fini(conversation_t *);
extern void conversation_free(conversation_t *);

extern void conversation_update_sender(conversation_t *conv,
                                       const char *name,
                                       const char *route,
                                       const char *mailbox,
                                       const char *domain,
                                       time_t lastseen,
                                       ssize_t delta_exists);
extern void conversation_update_thread(conversation_t *conv,
                                       const struct message_guid *guid,
                                       uint64_t nano_internaldate,
                                       modseq_t createdmodseq,
                                       int delta_exists);

extern int conversations_prune(struct conversations_state *state,
                               time_t thresh, unsigned int *,
                               unsigned int *);
extern void conversations_dump(struct conversations_state *, FILE *);
extern int conversations_undump(struct conversations_state *, FILE *);

extern int conversations_truncate(struct conversations_state *);

extern const char *conversation_id_encode(struct conversations_state *state,
                                          conversation_id_t cid);
extern int conversation_id_decode(conversation_id_t *cid, const char *text);


extern int conversations_zero_counts(struct conversations_state *state, int wipe, int do_upgrade);
extern int conversations_cleanup_zero(struct conversations_state *state);
extern int conversations_zero_modseq(struct conversations_state *state);

extern int conversations_rename_folder(struct conversations_state *state,
                                       const char *from_name,
                                       const char *to_name);

extern int conversations_check_msgid(const char *msgid, size_t len);

extern int conversations_read_quota(struct conversations_state *state, struct conv_quota *q);

extern int conversations_enable_compactids(struct conversations_state *cstate,
                                           int enable);

#endif /* __CYRUS_CONVERSATIONS_H_ */
