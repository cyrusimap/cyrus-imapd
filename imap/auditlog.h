/* auditlog - audit logging API */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/**
 * @file auditlog.h
 * @brief Structured audit logging API
 *
 * This API provides functions for writing logfmt log events to syslog. Each
 * function logs a specific kind of event with associated data (mailbox info,
 * message IDs, user info, etc.).
 *
 * All functions check the `auditlog` config option and return immediately
 * if auditing is disabled.
 */

#ifndef INCLUDED_AUDITLOG_H
#define INCLUDED_AUDITLOG_H

#include "imap/duplicate.h"
#include "imap/mailbox.h"
#include "imap/mboxlist.h"
#include "imap/quota.h"

#include "lib/libconfig.h"

#include <stdint.h>

/** @brief Log an ACL change on a mailbox */
extern void auditlog_acl(const char *mboxname,
                         const mbentry_t *oldmbentry,
                         const mbentry_t *mbentry);

/** @brief Log a client connection */
extern void auditlog_client(const char *action,
                            const char *userid,
                            const char *client);

/** @brief Log a duplicate delivery check or suppression */
extern void auditlog_duplicate(const char *action,
                               const duplicate_key_t *dkey);

/** @brief Log the result of Sieve processimip action */
extern void auditlog_imip(const char *message_id,
                          const char *outcome,
                          const char *errstr);

/** @brief Log an action on a mailbox (passed by struct) */
extern void auditlog_mailbox(const char *action,
                             const struct mailbox *oldmailbox,
                             const struct mailbox *mailbox,
                             const char *newpartition);

/** @brief Log an action on a mailbox (referenced by name) */
extern void auditlog_mboxname(const char *action,
                              const char *userid,
                              const char *mboxname);

/** @brief Log an action taken on an individual message (passed by struct) */
extern void auditlog_message(const char *action,
                             struct mailbox *mailbox,
                             const struct index_record *oldrecord,
                             const struct index_record *record,
                             const char *message_id);

/** @brief Log an action taken on an individual message (referenced by uid) */
extern void auditlog_message_uid(const char *action,
                                 const struct mailbox *mailbox,
                                 uint32_t uid,
                                 const char *flagstr);

/** @brief Log mailbox modseq state */
extern void auditlog_modseq(const struct mailbox *mailbox);

/** @brief Log a proxy connection to a backend server */
extern void auditlog_proxy(const char *userid, const char *status);

/** @brief Log a quota change */
extern void auditlog_quota(const char *action,
                           const char *root,
                           const quota_t *oldquotas,
                           const quota_t *newquotas);

/** @brief Log a Sieve filter action (fileinto, redirect, vacation, etc.) */
extern void auditlog_sieve(const char *action,
                           const char *userid,
                           const char *in_msgid,
                           const char *out_msgid,
                           const char *target,
                           const char *vac_from_addr,
                           const char *vac_to_addr);

/** @brief Log session traffic statistics */
extern void auditlog_traffic(uint64_t bytes_in, uint64_t bytes_out);

#endif
