/* jmap_notif.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef JMAP_NOTIF_H
#define JMAP_NOTIF_H

#include <jansson.h>

#include "imap/ical_support.h"
#include "common/jmap_util.h"
#include "imap/mboxlist.h"

#define JMAP_NOTIF_CALENDAREVENT "jmap-notif-calendarevent"

extern char *jmap_notifmboxname(const char *userid);
extern int jmap_create_notify_collection(const char *userid, mbentry_t **mbentryptr);
extern char *jmap_caleventnotif_format_fromheader(const char *userid);
extern int jmap_create_caleventnotif(struct mailbox *notifmbox,
                                     const char *userid,
                                     const struct auth_state *authstate,
                                     const char *calmboxname,
                                     const char *type,
                                     struct jmap_caleventid *eid,
                                     const strarray_t *schedule_addresses,
                                     const char *comment,
                                     int is_draft,
                                     json_t *jevent,
                                     json_t *jpatch);

extern int jmap_create_caldaveventnotif(const char *userid,
                                        const struct auth_state *authstate,
                                        const char *calmboxname,
                                        struct jmap_caleventid *eid,
                                        const strarray_t *schedule_addresses,
                                        int is_draft,
                                        icalcomponent *oldical,
                                        icalcomponent *newical,
                                        const char *sender_address,
                                        const char *sender_name);

extern int calendar_has_sharees(const mbentry_t *mbentry);

#endif /* JMAP_NOTIF_H */
