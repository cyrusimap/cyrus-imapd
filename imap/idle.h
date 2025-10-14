/*
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
 */

#ifndef IDLE_H
#define IDLE_H

#include "json_support.h"
#include "mailbox.h"
#include "strarray.h"

extern const char *idle_method_desc;

/* Mailbox filter selectors from RFC 5465 */
typedef enum {
    FILTER_NONE = 0,              // key is NULL
    FILTER_SELECTED = (1 << 0),   // key is mailbox uniqueid
    FILTER_INBOXES = (1 << 1),    // key is userid
    FILTER_PERSONAL = (1 << 2),   // key is userid
    FILTER_SUBSCRIBED = (1 << 3), // key is userid
    FILTER_SUBTREE = (1 << 4),    // key list of mailboxes
    FILTER_MAILBOXES = (1 << 5)   // key list of mailboxes
} mailbox_filter_t;

#define IMAP_NOTIFY_MESSAGE_NEW                                                \
    (EVENT_MESSAGE_NEW | EVENT_MESSAGE_APPEND | EVENT_MESSAGE_COPY             \
     | EVENT_MESSAGE_MOVE)

#define IMAP_NOTIFY_MESSAGE_EXPUNGE                                            \
    (EVENT_MESSAGE_EXPUNGE | EVENT_MESSAGE_EXPIRE)

#define IMAP_NOTIFY_FLAG_CHANGE                                                \
    (EVENT_MESSAGE_READ | EVENT_MESSAGE_TRASH | EVENT_FLAGS_SET                \
     | EVENT_FLAGS_CLEAR)

#define IMAP_NOTIFY_ANNOTATION_CHANGE                                          \
    (0) // We don't currently have an EVENT for this

#define IMAP_NOTIFY_MESSAGE                                                    \
    (IMAP_NOTIFY_MESSAGE_NEW | IMAP_NOTIFY_MESSAGE_EXPUNGE                     \
     | IMAP_NOTIFY_FLAG_CHANGE | IMAP_NOTIFY_ANNOTATION_CHANGE)

#define IMAP_NOTIFY_MAILBOX_NAME                                               \
    (EVENT_MAILBOX_CREATE | EVENT_MAILBOX_DELETE | EVENT_MAILBOX_RENAME        \
     | EVENT_ACL_CHANGE)

#define IMAP_NOTIFY_SUBSCRIPTION_CHANGE                                        \
    (EVENT_MAILBOX_SUBSCRIBE | EVENT_MAILBOX_UNSUBSCRIBE)

#define IMAP_NOTIFY_MAILBOX                                                    \
    (IMAP_NOTIFY_MAILBOX_NAME | IMAP_NOTIFY_SUBSCRIPTION_CHANGE)

#define IMAP_NOTIFY_MAILBOX_METADATA_CHANGE                                    \
    (0) // We don't currently have an EVENT for this

#define IMAP_NOTIFY_SERVER_METADATA_CHANGE                                     \
    (0) // We don't currently have an EVENT for this

/* set up the link to the idled for notifications */
int idle_init(void);

/* Is IDLE enabled? */
int idle_enabled(void);

/* Start IDLEing on 'filter' mailboxes for 'events'. */
int idle_start(unsigned long events,
               time_t timeout,
               mailbox_filter_t filter,
               strarray_t *keys);

/* Reads and returns a message from idled, or NULL on error */
json_t *idle_get_message(void);

/* Stop IDLEing on 'filter' mailboxes. */
void idle_stop(mailbox_filter_t filter);

/* Clean up when IDLE is completed. */
void idle_done(void);

#endif /* IDLE_H */
