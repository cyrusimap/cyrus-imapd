/* backup.h -- replication-based backup api
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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
 *
 */

#ifndef BACKUP_BACKUP_H
#define BACKUP_BACKUP_H

#include "imap/dlist.h"
#include "imap/mboxname.h"
#include "imap/sync_support.h"

#include "lib/gzuncat.h"

struct backup;

const char *backup_get_staging_path(void);
void backup_cleanup_staging_path(void);

/* opening the backups database */
#define FNAME_BACKUPDB "/backups.db"
int backupdb_open(struct db **backup_dbp, struct txn **tidp);


/* opening and closing backups */
enum backup_open_nonblock {
    BACKUP_OPEN_BLOCK = 0,
    BACKUP_OPEN_NONBLOCK = 1,
};

enum backup_open_create {
    BACKUP_OPEN_NOCREATE = 0,
    BACKUP_OPEN_CREATE = 1,
    BACKUP_OPEN_CREATE_EXCL = 2,
};

int backup_open(struct backup **backupp,
                const mbname_t *mbname,
                enum backup_open_nonblock nonblock,
                enum backup_open_create create);

int backup_get_paths(const mbname_t *mbname,
                     struct buf *data_fname, struct buf *index_fname,
                     enum backup_open_create create);

int backup_open_paths(struct backup **backupp,
                      const char *data_fname,
                      const char *index_fname,
                      enum backup_open_nonblock nonblock,
                      enum backup_open_create create);

int backup_close(struct backup **backupp); // also ends index/append ops
int backup_unlink(struct backup **backupp);


/* verifying backups */
enum {
    BACKUP_VERIFY_LAST_CHECKSUM = (1 << 0),
    BACKUP_VERIFY_ALL_CHECKSUMS = (1 << 1),
    BACKUP_VERIFY_MESSAGE_LINKS = (1 << 2),
    BACKUP_VERIFY_MAILBOX_LINKS = (1 << 3),
    BACKUP_VERIFY_MESSAGE_GUIDS = (1 << 4),
};
#define BACKUP_VERIFY_QUICK BACKUP_VERIFY_LAST_CHECKSUM
#define BACKUP_VERIFY_MESSAGES (BACKUP_VERIFY_MESSAGE_LINKS | BACKUP_VERIFY_MESSAGE_GUIDS)
#define BACKUP_VERIFY_FULL  ((unsigned) -1)
int backup_verify(struct backup *backup, unsigned level, int verbose, FILE *out);


/* accessing backup properties */
const char *backup_get_data_fname(const struct backup *backup);
const char *backup_get_index_fname(const struct backup *backup);
int backup_stat(const struct backup *backup,
                struct stat *data_statp,
                struct stat *index_statp);


/* reading backup chunk data */
struct backup_chunk {
    struct backup_chunk *next;
    int id;
    time_t ts_start;
    time_t ts_end;
    off_t offset;
    size_t length;
    char *file_sha1;
    char *data_sha1;
};

struct backup_chunk_list {
    struct backup_chunk *head;
    struct backup_chunk *tail;
    size_t count;
};

void backup_chunk_list_add(struct backup_chunk_list *list,
                           struct backup_chunk *chunk);
void backup_chunk_list_empty(struct backup_chunk_list *list);
void backup_chunk_list_free(struct backup_chunk_list **chunk_listp);

struct backup_chunk_list *backup_get_chunks(struct backup *backup);
struct backup_chunk_list *backup_get_live_chunks(struct backup *backup,
                                                 time_t since);

struct backup_chunk *backup_get_chunk(struct backup *backup, int chunk_id);
struct backup_chunk *backup_get_latest_chunk(struct backup *backup);

void backup_chunk_free(struct backup_chunk **chunkp);

/* reading backup mailbox data */
struct backup_mailbox_message {
    struct backup_mailbox_message *next;
    int id;
    int mailbox_id;
    char *mailbox_uniqueid;
    int message_id;
    int last_chunk_id;
    int uid;
    modseq_t modseq;
    time_t last_updated;
    char *flags;
    time_t internaldate;
    struct message_guid guid;
    size_t size;
    char *annotations;
    time_t expunged;
};

struct backup_mailbox_message_list {
    struct backup_mailbox_message *head;
    struct backup_mailbox_message *tail;
    size_t count;
};

struct backup_mailbox {
    struct backup_mailbox *next;
    int id;
    int last_chunk_id;
    char *uniqueid;
    char *mboxname;
    char *mboxtype;
    uint32_t last_uid;
    modseq_t highestmodseq;
    uint32_t recentuid;
    time_t recenttime;
    time_t last_appenddate;
    time_t pop3_last_login;
    time_t pop3_show_after;
    uint32_t uidvalidity;
    char *partition;
    char *acl;
    char *options;
    uint32_t sync_crc;
    uint32_t sync_crc_annot;
    char *quotaroot;
    modseq_t xconvmodseq;
    char *annotations;
    time_t deleted;
    struct backup_mailbox_message_list *records;
};

struct backup_mailbox_list {
    struct backup_mailbox *head;
    struct backup_mailbox *tail;
    size_t count;
};

enum backup_mailbox_want_records {
    BACKUP_MAILBOX_NO_RECORDS = 0,
    BACKUP_MAILBOX_ALL_RECORDS = 1,
    BACKUP_MAILBOX_MATCH_RECORDS = 2,
};

int backup_get_mailbox_id(struct backup *backup, const char *uniqueid);

typedef int (*backup_mailbox_foreach_cb)(const struct backup_mailbox *mailbox,
                                         void *rock);
int backup_mailbox_foreach(struct backup *backup, int chunk_id,
                           enum backup_mailbox_want_records want_records,
                           backup_mailbox_foreach_cb cb, void *rock);

struct backup_mailbox_list *backup_get_mailboxes(
                                struct backup *backup,
                                int chunk_id,
                                enum backup_mailbox_want_records want_records);

struct backup_message;
struct backup_mailbox_list *backup_get_mailboxes_by_message(
                                struct backup *backup,
                                const struct backup_message *message,
                                enum backup_mailbox_want_records want_records);

struct backup_mailbox *backup_get_mailbox_by_uniqueid(
                                struct backup *backup,
                                const char *uniqueid,
                                enum backup_mailbox_want_records want_records);

struct backup_mailbox *backup_get_mailbox_by_name(
                                struct backup *backup,
                                const mbname_t *mbname,
                                enum backup_mailbox_want_records want_records);

struct dlist *backup_mailbox_to_dlist(const struct backup_mailbox *mailbox);

struct backup_mailbox *backup_mailbox_clone(const struct backup_mailbox *mailbox);

void backup_mailbox_free(struct backup_mailbox **mailboxp);

struct backup_mailbox_message_list *backup_get_mailbox_messages(struct backup *backup,
                                                                int chunk_id);

struct backup_mailbox_message *backup_get_mailbox_message(
                                    struct backup *backup,
                                    const char *uniqueid,
                                    const char *guid);

struct backup_mailbox_message *backup_mailbox_message_clone(
                                    const struct backup_mailbox_message *orig);

void backup_mailbox_message_free(struct backup_mailbox_message **mailbox_messagep);

void backup_mailbox_list_add(struct backup_mailbox_list *list,
                             struct backup_mailbox *mailbox);

struct backup_mailbox *backup_mailbox_list_remove(struct backup_mailbox_list *list,
                                                  struct backup_mailbox *mailbox);

struct backup_mailbox_message *backup_mailbox_message_list_remove(
    struct backup_mailbox_message_list *list,
    struct backup_mailbox_message *mailbox_message);

void backup_mailbox_list_empty(struct backup_mailbox_list *list);
void backup_mailbox_message_list_empty(struct backup_mailbox_message_list *list);


/* reading backup message data */
struct backup_message {
    int id;
    struct message_guid *guid;
    char *partition;
    int chunk_id;
    off_t offset;
    size_t length;
};

int backup_get_message_id(struct backup *backup, const char *guid);
// FIXME do i even need these?
struct backup_message *backup_get_message(struct backup *backup,
                                          const struct message_guid *guid);
char *backup_get_message_content(struct backup *backup,
                                 const struct backup_message *message);
void backup_message_free(struct backup_message **message);

typedef int (*backup_message_foreach_cb)(const struct backup_message *message,
                                         void *rock);
int backup_message_foreach(struct backup *backup,
                           int chunk_id, const time_t *sincep,
                           backup_message_foreach_cb cb, void *rock);


/* reading backup seen data */
struct backup_seen {
    int id;
    int last_chunk_id;
    char *uniqueid;
    time_t lastread;
    uint32_t lastuid;
    time_t lastchange;
    char *seenuids;
};

void backup_seen_free(struct backup_seen **seen);

typedef int (*backup_seen_foreach_cb)(const struct backup_seen *seen,
                                      void *rock);
int backup_seen_foreach(struct backup *backup,
                        int chunk_id,
                        backup_seen_foreach_cb cb,
                        void *rock);


/* reading backup subscription data */
struct backup_subscription {
    int id;
    int last_chunk_id;
    char *mboxname;
    time_t unsubscribed;
};

void backup_subscription_free(struct backup_subscription **sub);

typedef int (*backup_subscription_foreach_cb)(const struct backup_subscription *sub,
                                              void *rock);
int backup_subscription_foreach(struct backup *backup,
                                int chunk_id,
                                backup_subscription_foreach_cb cb,
                                void *rock);


/* reading backup sieve data */
struct backup_sieve {
    int id;
    int chunk_id;
    time_t last_update;
    char *filename;
    struct message_guid guid;
    off_t offset;
    time_t deleted;
};

void backup_sieve_free(struct backup_sieve **sieve);

typedef int (*backup_sieve_foreach_cb)(const struct backup_sieve *sieve,
                                       void *rock);
int backup_sieve_foreach(struct backup *backup,
                         int chunk_id,
                         backup_sieve_foreach_cb cb,
                         void *rock);


/* writing backup data */
enum backup_append_flush {
    BACKUP_APPEND_NOFLUSH = 0,
    BACKUP_APPEND_FLUSH = 1,
};

int backup_append_start(struct backup *backup,
                        const time_t *tsp,
                        enum backup_append_flush flush);
int backup_append(struct backup *backup,
                  struct dlist *dlist,
                  const time_t *tsp,
                  enum backup_append_flush flush);
int backup_append_end(struct backup *backup,
                      const time_t *tsp);
int backup_append_abort(struct backup *backup);


/* reading backup data */
typedef int (*backup_read_data_cb)(const struct buf *buf, void *rock);

int backup_read_chunk_data(struct backup *backup,
                           const struct backup_chunk *chunk,
                           backup_read_data_cb proc, void *rock);
int backup_read_message_data(struct backup *backup,
                             const struct backup_message *message,
                             backup_read_data_cb proc, void *rock);

typedef struct sync_msgid *(*sync_msgid_lookup_func)(
    const struct sync_msgid_list *list,
    const struct message_guid *guid);

int backup_prepare_message_upload(struct backup *backup,
                                  const char *partition,
                                  struct sync_msgid_list *msgid_list,
                                  sync_msgid_lookup_func msgid_lookup,
                                  struct dlist **uploadp);
/* miscellaneous */
int backup_reindex(const char *name,
                   enum backup_open_nonblock nonblock,
                   int verbose, FILE *out);
int backup_rename(const mbname_t *old_mbname, const mbname_t *new_mbname);
int backup_compact(const char *name,
                   enum backup_open_nonblock nonblock,
                   int force, int verbose, FILE *out);

#endif
