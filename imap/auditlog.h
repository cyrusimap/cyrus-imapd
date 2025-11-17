/* auditlog - audit logging API */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_AUDITLOG_H
#define INCLUDED_AUDITLOG_H

#include "imap/duplicate.h"
#include "imap/mailbox.h"
#include "imap/mboxlist.h"
#include "imap/quota.h"

#include "lib/libconfig.h"

#include <stdint.h>

extern void auditlog_acl(const char *mboxname,
                         const mbentry_t *oldmbentry,
                         const mbentry_t *mbentry);
extern void auditlog_client(const char *action,
                            const char *userid,
                            const char *client);
extern void auditlog_duplicate(const char *action,
                               const duplicate_key_t *dkey);
extern void auditlog_imip(const char *message_id,
                          const char *outcome,
                          const char *errstr);
extern void auditlog_mailbox(const char *action,
                             const struct mailbox *oldmailbox,
                             const struct mailbox *mailbox,
                             const char *newpartition);
extern void auditlog_mboxname(const char *action,
                              const char *userid,
                              const char *mboxname);
extern void auditlog_message(const char *action,
                             struct mailbox *mailbox,
                             const struct index_record *oldrecord,
                             const struct index_record *record,
                             const char *message_id);
extern void auditlog_message_uid(const char *action,
                                 const struct mailbox *mailbox,
                                 uint32_t uid,
                                 const char *flagstr);
extern void auditlog_modseq(const struct mailbox *mailbox);
extern void auditlog_proxy(const char *userid, const char *status);
extern void auditlog_quota(const char *action,
                           const char *root,
                           const quota_t *oldquotas,
                           const quota_t *newquotas);
extern void auditlog_sieve(const char *action,
                           const char *userid,
                           const char *in_msgid,
                           const char *out_msgid,
                           const char *target,
                           const char *vac_from_addr,
                           const char *vac_to_addr);
extern void auditlog_traffic(uint64_t bytes_in, uint64_t bytes_out);

#endif
