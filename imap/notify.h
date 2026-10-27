/* notify.h - abstract interface for notifications */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef NOTIFY_H
#define NOTIFY_H

#include <jansson.h>

#define NOTIFY_MAXSIZE 65536  /* 64k */

/**
 * Send a notification to the notifysocket.
 *
 * With a "json:" notifysocket, the notification is written to that stream
 * socket as one line of JSON: an object with the members "method", "class",
 * "priority", "user", "mailbox", "options" (an array), "message" and
 * "filepath", each omitted when NULL or empty.  The listener answers with one
 * line holding an object whose "status" is "OK" on success.  Otherwise it is
 * sent as a datagram of NUL-separated fields, as notifyd(8) expects, with a
 * non-string message serialized.
 *
 * @param method    notification method, such as an event_notifier value
 * @param class     notification class: "EVENT", "MAIL", "SIEVE", "IMIP", ...
 * @param priority  priority, or NULL
 * @param user      userid the notification is for, or NULL
 * @param mailbox   external mailbox name, or NULL
 * @param nopt      number of options
 * @param options   method-specific options
 * @param message   the message: a JSON string for text, or an object;
 *                  the caller keeps its reference
 * @param fname     path of a file to pass along, or NULL
 */
void notify(const char *method,
            const char *class, const char *priority,
            const char *user, const char *mailbox,
            int nopt, const char **options,
            json_t *message, const char *fname);

/**
 * Make a notification message from text, replacing any invalid UTF-8.
 *
 * @param text  the text, or NULL for an empty message
 * @return a new JSON string
 */
json_t *notify_text(const char *text);

#endif /* NOTIFY_H */
