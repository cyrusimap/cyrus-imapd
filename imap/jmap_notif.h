/* jmap_notif.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef JMAP_NOTIF_H
#define JMAP_NOTIF_H

#include <jansson.h>

#include "ical_support.h"
#include "mboxlist.h"

#define JMAP_NOTIF_CALENDAREVENT "jmap-notif-calendarevent"

extern char *jmap_notifmboxname(const char *userid);
extern int jmap_create_notify_collection(const char *userid, mbentry_t **mbentryptr);
extern char *jmap_caleventnotif_format_fromheader(const char *userid);
extern int jmap_create_caleventnotif(struct mailbox *notifmbox,
                                     const char *userid,
                                     const struct auth_state *authstate,
                                     const char *calmboxname,
                                     const char *type,
                                     const char *ical_uid,
                                     const strarray_t *schedule_addresses,
                                     const char *comment,
                                     int is_draft,
                                     json_t *jevent,
                                     json_t *jpatch);

typedef struct transaction_t txn_t; // defined in httpd.h

extern int jmap_create_caldaveventnotif(struct transaction_t *txn,
                                        const char *userid,
                                        const struct auth_state *authstate,
                                        const char *calmboxname,
                                        const char *ical_uid,
                                        const strarray_t *schedule_addresses,
                                        int is_draft,
                                        icalcomponent *oldical,
                                        icalcomponent *newical);

extern int calendar_has_sharees(const mbentry_t *mbentry);

#endif /* JMAP_NOTIF_H */
