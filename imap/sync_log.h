/* sync_log.c -- Cyrus synchronization logging functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
