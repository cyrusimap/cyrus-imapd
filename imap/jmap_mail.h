/* jmap_mail.h -- Routines for handling JMAP mail messages */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef JMAP_MAIL_H
#define JMAP_MAIL_H

#include <config.h>

#include "hash.h"
#include "http_jmap.h"
#include "jmap_util.h"
#include "json_support.h"
#include "msgrecord.h"

extern int jmap_email_find(jmap_req_t *req, const char *email_id,
                           const char *from_accountid,
                           char **mboxnameptr, uint32_t *uidptr,
                           uint64_t *idateptr);
extern int jmap_email_get_with_props(jmap_req_t *req, hash_table *props,
                                     msgrecord_t *mr, json_t **msgp);

extern void jmap_emailsubmission_init(jmap_settings_t *settings);
extern void jmap_emailsubmission_capabilities(json_t *jcapabilities);

extern void jmap_mailbox_init(jmap_settings_t *settings);
extern void jmap_mailbox_capabilities(json_t *jcapabilities,
                                      int mayCreateToplevel);

#endif /* JMAP_MAIL_H */
