/* sync_log.c -- Cyrus synchronization logging functions
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
 *
 * Original version written by David Carter <dpc22@cam.ac.uk>
 * Rewritten and integrated into Cyrus by Ken Murchison <ken@oceana.com>
 */

#ifndef INCLUDED_SYNC_LOG_H
#define INCLUDED_SYNC_LOG_H

#define SYNC_LOG_RETRIES (64)

void sync_log_init(void);
void sync_log_suppress(void);
void sync_log_done(void);

void sync_log(const char *fmt, ...);
void sync_log_channel(const char *channel, const char *fmt, ...);

struct buf *sync_log_rightnow_buf();
void sync_log_reset();


#define sync_log_user(user) \
    sync_log("USER %s\n", user)

#define sync_log_unuser(user) \
    sync_log("UNUSER %s\n", user)

#define sync_log_sieve(user) \
    sync_log("META %s\n", user)

#define sync_log_append(name) \
    sync_log("APPEND %s\n", name)

#define sync_log_mailbox(name) \
    do { assert(*name); sync_log("MAILBOX %s\n", name); } while (0)

#define sync_log_unmailbox(name) \
    sync_log("UNMAILBOX %s\n", name)

#define sync_log_mailbox_double(name1, name2) \
    sync_log("DOUBLEMAILBOX %s %s\n", name1, name2)

#define sync_log_rename(name1, name2) \
    sync_log("RENAME %s %s\nMAILBOX %s\nMAILBOX %s\n", name1, name2, name1, name2)

#define sync_log_quota(name) \
    sync_log("QUOTA %s\n", name)

#define sync_log_annotation(name) \
    sync_log("ANNOTATION %s\n", name)

#define sync_log_seen(user, name) \
    sync_log("SEEN %s %s\n", user, name)

#define sync_log_subscribe(user, name) \
    sync_log("SUB %s %s\n", user, name)

#define sync_log_channel_user(channel, user) \
    sync_log_channel(channel, "USER %s\n", user)

#define sync_log_channel_unuser(channel, user) \
    sync_log_channel(channel, "UNUSER %s\n", user)

#define sync_log_channel_sieve(channel, user) \
    sync_log_channel(channel, "META %s\n", user)

#define sync_log_channel_append(channel, name) \
    sync_log_channel(channel, "APPEND %s\n", name)

#define sync_log_channel_mailbox(channel, name) \
    sync_log_channel(channel, "MAILBOX %s\n", name)

#define sync_log_channel_unmailbox(channel, name) \
    sync_log_channel(channel, "UNMAILBOX %s\n", name)

#define sync_log_channel_mailbox_double(channel, name1, name2) \
    sync_log_channel(channel, "DOUBLEMAILBOX %s %s\n", name1, name2)

#define sync_log_channel_rename(channel, name1, name2) \
    sync_log_channel(channel, "RENAME %s %s\nMAILBOX %s\nMAILBOX %s\n", \
                              name1, name2, name1, name2)

#define sync_log_channel_quota(channel, name) \
    sync_log_channel(channel, "QUOTA %s\n", name)

#define sync_log_channel_annotation(channel, name) \
    sync_log_channel(channel, "ANNOTATION %s\n", name)

#define sync_log_channel_seen(channel, user, name) \
    sync_log_channel(channel, "SEEN %s %s\n", user, name)

#define sync_log_channel_subscribe(channel, user, name) \
    sync_log_channel(channel, "SUB %s %s\n", user, name)

/* read-side sync log code */
typedef struct sync_log_reader sync_log_reader_t;

sync_log_reader_t *sync_log_reader_create_with_channel(const char *channel);
sync_log_reader_t *sync_log_reader_create_with_content(const char *content);
sync_log_reader_t *sync_log_reader_create_with_filename(const char *filename);
sync_log_reader_t *sync_log_reader_create_with_fd(int fd);
void sync_log_reader_free(sync_log_reader_t *slr);
int sync_log_reader_begin(sync_log_reader_t *slr);
const char *sync_log_reader_get_file_name(const sync_log_reader_t *slr);
int sync_log_reader_end(sync_log_reader_t *slr);
int sync_log_reader_getitem(sync_log_reader_t *slr, const char *args[3]);

#endif /* INCLUDED_SYNC_LOG_H */
