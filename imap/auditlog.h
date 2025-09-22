/* auditlog - audit logging API
 *
 * Copyright (c) 1994-2025 Carnegie Mellon University.  All rights reserved.
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
#ifndef INCLUDED_AUDITLOG_H
#define INCLUDED_AUDITLOG_H

#include "imap/mailbox.h"
#include "imap/mboxlist.h"
#include "imap/quota.h"

#include "lib/libconfig.h"

#include <stdint.h>

extern void auditlog_client(const char *action,
                            const char *userid,
                            const char *client);
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
                             const struct index_record *record,
                             const char *message_id);
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
                           const char *from_addr,
                           const char *to_addr);
extern void auditlog_traffic(uint64_t bytes_in, uint64_t bytes_out);

#endif
