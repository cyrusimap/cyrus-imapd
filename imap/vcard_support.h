/* vcard_support.h - Helper functions for vcard */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef VCARD_SUPPORT_H
#define VCARD_SUPPORT_H

#include <config.h>

#include <libical/vcard.h>

#include "mailbox.h"
#include "message_guid.h"
#include "util.h"

#define VCARD_APPLE_LABEL_PROPERTY "X-ABLabel"
#define VCARD_APPLE_ABADR_PROPERTY "X-ABADR"

#define VCARD_NUM_BASE_N_FIELDS   5  // Number of fields defined in RFC 6350
#define VCARD_NUM_BASE_ADR_FIELDS 7  // Number of fields defined in RFC 6350

extern vcardcomponent *vcard_parse_string(const char *str);
extern vcardcomponent *vcard_parse_buf(const struct buf *buf);
extern struct buf *vcard_as_buf(vcardcomponent *vcard);

extern vcardcomponent *record_to_vcard(struct mailbox *mailbox,
                                         const struct index_record *record);

extern size_t vcard_prop_decode_value(vcardproperty *prop,
                                        struct buf *value,
                                        char **content_type,
                                        struct message_guid *guid);

extern const char *vcardproperty_get_xparam_value(vcardproperty *prop,
                                                  const char *name);

#endif /* VCARD_SUPPORT_H */
