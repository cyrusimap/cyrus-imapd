/* lcb_internal.h -- replication-based backup internals
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

#include "lib/sqldb.h"
#include "lib/xsha1.h"

#include "imap/partlist.h"

#ifndef LIBCYRUS_BACKUP_SOURCE
#error "backup/lcb_internal.h is for internal use by libcyrus_backup ONLY"
#else
#ifndef BACKUP_LCB_INTERNAL_H
#define BACKUP_LCB_INTERNAL_H

enum {
    BACKUP_APPEND_INACTIVE  = 0,
    BACKUP_APPEND_ACTIVE    = 0x0001,
    BACKUP_APPEND_INDEXONLY = 0x0002,
};

struct backup_append_state {
    unsigned mode;
    gzFile gzfile;
    int chunk_id;
    size_t wrote;
    SHA1_CTX sha_ctx;
};

struct backup {
    int fd;
    char *data_fname;
    char *index_fname;
    char *oldindex_fname;
    sqldb_t *db;
    struct backup_append_state *append_state;
};

enum backup_open_reindex {
    BACKUP_OPEN_NOREINDEX = 0,
    BACKUP_OPEN_REINDEX = 1,
};

HIDDEN int backup_real_open(struct backup **backupp,
                            const char *data_fname, const char *index_fname,
                            enum backup_open_reindex reindex,
                            enum backup_open_nonblock nonblock,
                            enum backup_open_create create);

int backup_real_append_start(struct backup *backup,
                             time_t ts, off_t offset,
                             const char *file_sha1,
                             int index_only,
                             enum backup_append_flush flush);

int backup_real_append_end(struct backup *backup, time_t ts);


HIDDEN int backup_index(struct backup *backup, struct dlist *dlist,
                        time_t ts, off_t start, size_t len);

/* parsing data from backup data stream files */
__attribute__((nonnull(4)))
int parse_backup_line(struct protstream *in, time_t *ts,
                      struct buf *cmd, struct dlist **kin);

/* limit is how much of the file to calculate the sha1 of (in bytes),
 * or SHA1_LIMIT_WHOLE_FILE for the whole file */
#define SHA1_LIMIT_WHOLE_FILE ((size_t) -1)
const char *sha1_file(int fd, const char *fname, size_t limit,
                      char buf[2 * SHA1_DIGEST_LENGTH + 1]);

struct backup_mailbox *backup_mailbox_list_remove(
    struct backup_mailbox_list *list,
    struct backup_mailbox *node);

struct backup_mailbox_message *backup_mailbox_message_list_remove(
    struct backup_mailbox_message_list *list,
    struct backup_mailbox_message *mailbox_message);

const char *partlist_backup_select(void);
int partlist_backup_foreach(partlist_foreach_cb proc, void *rock);
void partlist_backup_done(void);
#endif
#endif
