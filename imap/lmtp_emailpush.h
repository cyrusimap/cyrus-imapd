/* lmtp_emailpush.h -- JMAP email delivery push from lmtpd */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/**
 * @file
 * Evaluates draft-ietf-jmap-emailpush filters when lmtpd delivers a message.
 *
 * For each recipient, lmtpd calls emailpush_begin(), then emailpush_add()
 * after each append to one of the recipient's mailboxes, then emailpush_end().
 * emailpush_end() matches the message, as delivered, against the filter of
 * each verified, unexpired PushSubscription of the recipient that has an
 * EmailPush config for the recipient's account, and reports the matches as
 * an EmailPush event.  The notification service builds and sends the push.
 *
 * All three do nothing unless jmap_emailpush is enabled.
 */

#ifndef LMTP_EMAILPUSH_H
#define LMTP_EMAILPUSH_H

#include <stdint.h>
#include <stdio.h>

#include "auth.h"
#include "mailbox.h"
#include "message.h"
#include "mboxname.h"

/**
 * Start collecting the deliveries for userid.
 */
extern void emailpush_begin(const char *userid);

/**
 * Record that uid in mailbox was delivered.  Ignored unless mailbox belongs
 * to the userid given to emailpush_begin().
 */
extern void emailpush_add(struct mailbox *mailbox, uint32_t uid);

/**
 * Report the subscriptions whose filters match the delivered message.
 *
 * @param content  the message, parsed from f if it hasn't been already
 * @param f        the message file
 * @param ns       the namespace for contact group lookups
 */
extern void emailpush_end(struct message_content *content,
                          FILE *f,
                          const struct namespace *ns);

#endif /* LMTP_EMAILPUSH_H */
