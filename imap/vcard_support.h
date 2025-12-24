/* vcard_support.h -- Helper functions for vcard */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef VCARD_SUPPORT_H
#define VCARD_SUPPORT_H

#include <config.h>

#include "vparse.h"

#include "mailbox.h"
#include "message_guid.h"
#include "util.h"

extern struct vparse_card *vcard_parse_string(const char *str);
extern struct vparse_card *vcard_parse_buf(const struct buf *buf);
extern struct buf *vcard_as_buf(struct vparse_card *vcard);

extern struct vparse_card *record_to_vcard(struct mailbox *mailbox,
                                           const struct index_record *record);

extern size_t vcard_prop_decode_value(struct vparse_entry *prop,
                                      struct buf *value,
                                      char **content_type,
                                      struct message_guid *guid);

extern void vcard_to_v3(struct vparse_card *vcard);
extern void vcard_to_v4(struct vparse_card *vcard);


#ifdef HAVE_LIBICALVCARD

#include <libical/vcard.h>

extern vcardcomponent *vcard_parse_string_x(const char *str);
extern vcardcomponent *vcard_parse_buf_x(const struct buf *buf);
extern struct buf *vcard_as_buf_x(vcardcomponent *vcard);

extern vcardcomponent *record_to_vcard_x(struct mailbox *mailbox,
                                         const struct index_record *record);

extern size_t vcard_prop_decode_value_x(vcardproperty *prop,
                                        struct buf *value,
                                        char **content_type,
                                        struct message_guid *guid);

extern const char *vcardproperty_get_xparam_value(vcardproperty *prop,
                                                  const char *name);

#endif /* HAVE_LIBICALVCARD */

#endif /* VCARD_SUPPORT_H */
