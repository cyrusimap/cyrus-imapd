/* jmap_notif.h
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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
 *
 */

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

#endif /* JMAP_NOTIF_H */
