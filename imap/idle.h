/* idle.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef IDLE_H
#define IDLE_H

#include "json_support.h"
#include "mailbox.h"
#include "strarray.h"

extern const char *idle_method_desc;

/* Mailbox filter selectors from RFC 5465 */
typedef enum {
    FILTER_NONE             = 0,       // key is NULL
    FILTER_SELECTED         = (1<<0),  // key is mailbox uniqueid
    FILTER_INBOXES          = (1<<1),  // key is userid
    FILTER_PERSONAL         = (1<<2),  // key is userid
    FILTER_SUBSCRIBED       = (1<<3),  // key is userid
    FILTER_SUBTREE          = (1<<4),  // key list of mailboxes
    FILTER_MAILBOXES        = (1<<5)   // key list of mailboxes
} mailbox_filter_t;

#define IMAP_NOTIFY_MESSAGE_NEW                                         \
    ( EVENT_MESSAGE_NEW        | EVENT_MESSAGE_APPEND          |        \
      EVENT_MESSAGE_COPY       | EVENT_MESSAGE_MOVE              )

#define IMAP_NOTIFY_MESSAGE_EXPUNGE                                     \
    ( EVENT_MESSAGE_EXPUNGE    | EVENT_MESSAGE_EXPIRE            )

#define IMAP_NOTIFY_FLAG_CHANGE                                         \
    ( EVENT_MESSAGE_READ       | EVENT_MESSAGE_TRASH           |        \
      EVENT_FLAGS_SET          | EVENT_FLAGS_CLEAR               )

#define IMAP_NOTIFY_ANNOTATION_CHANGE                                   \
    ( 0 ) // We don't currently have an EVENT for this

#define IMAP_NOTIFY_MESSAGE                                             \
    ( IMAP_NOTIFY_MESSAGE_NEW  | IMAP_NOTIFY_MESSAGE_EXPUNGE   |        \
      IMAP_NOTIFY_FLAG_CHANGE  | IMAP_NOTIFY_ANNOTATION_CHANGE   )

#define IMAP_NOTIFY_MAILBOX_NAME                                        \
    ( EVENT_MAILBOX_CREATE     | EVENT_MAILBOX_DELETE          |        \
      EVENT_MAILBOX_RENAME     | EVENT_ACL_CHANGE                )

#define IMAP_NOTIFY_SUBSCRIPTION_CHANGE                                 \
    ( EVENT_MAILBOX_SUBSCRIBE  | EVENT_MAILBOX_UNSUBSCRIBE       )

#define IMAP_NOTIFY_MAILBOX                                             \
    ( IMAP_NOTIFY_MAILBOX_NAME | IMAP_NOTIFY_SUBSCRIPTION_CHANGE )

#define IMAP_NOTIFY_MAILBOX_METADATA_CHANGE                             \
    ( 0 ) // We don't currently have an EVENT for this

#define IMAP_NOTIFY_SERVER_METADATA_CHANGE                              \
    ( 0 ) // We don't currently have an EVENT for this

/* set up the link to the idled for notifications */
int idle_init(void);

/* Is IDLE enabled? */
int idle_enabled(void);

/* Start IDLEing on 'filter' mailboxes for 'events'. */
int idle_start(unsigned long events, time_t timeout,
               mailbox_filter_t filter, strarray_t *keys);

/* Reads and returns a message from idled, or NULL on error */
json_t *idle_get_message(void);

/* Stop IDLEing on 'filter' mailboxes. */
void idle_stop(mailbox_filter_t filter);

/* Clean up when IDLE is completed. */
void idle_done(void);

#endif /* IDLE_H */
