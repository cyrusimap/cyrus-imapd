/* itip_support.h -- Routines for dealing with iTIP
 *
 * Copyright (c) 1994-2021 Carnegie Mellon University.  All rights reserved.
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

#ifndef ITIP_SUPPORT_H
#define ITIP_SUPPORT_H

#include <config.h>

#include <libical/ical.h>

#include "acl.h"
#include "strarray.h"


#define SCHED_INBOX     "Inbox/"
#define SCHED_OUTBOX    "Outbox/"
#define SCHED_DEFAULT   "Default/"

#define REQSTAT_PENDING         "1.0;Pending"
#define REQSTAT_SENT            "1.1;Sent"
#define REQSTAT_DELIVERED       "1.2;Delivered"
#define REQSTAT_SUCCESS         "2.0;Success"
#define REQSTAT_NOUSER          "3.7;Invalid calendar user"
#define REQSTAT_NOPRIVS         "3.8;Noauthority"
#define REQSTAT_TEMPFAIL        "5.1;Service unavailable"
#define REQSTAT_PERMFAIL        "5.2;Invalid calendar service"
#define REQSTAT_REJECTED        "5.3;No scheduling support for user"

struct sched_data {
    unsigned ischedule    : 1;
    unsigned is_reply     : 1;
    unsigned is_update    : 1;
    unsigned updates_only : 1;
    icalcomponent *itip;
    icalcomponent *oldical;
    icalcomponent *newical;
    icalparameter_scheduleforcesend force_send;
    const strarray_t *schedule_addresses;
    const char *status;
};

#define SCHEDSTAT_PENDING       "1.0"
#define SCHEDSTAT_SENT          "1.1"
#define SCHEDSTAT_DELIVERED     "1.2"
#define SCHEDSTAT_SUCCESS       "2.0"
#define SCHEDSTAT_PARAM         "2.3"
#define SCHEDSTAT_NOUSER        "3.7"
#define SCHEDSTAT_NOPRIVS       "3.8"
#define SCHEDSTAT_TEMPFAIL      "5.1"
#define SCHEDSTAT_PERMFAIL      "5.2"
#define SCHEDSTAT_REJECTED      "5.3"

/* Scheduling protocol flags */
#define SCHEDTYPE_REMOTE        (1<<0)
#define SCHEDTYPE_ISCHEDULE     (1<<1)
#define SCHEDTYPE_SSL           (1<<2)

extern unsigned config_allowsched;
extern struct strlist *cua_domains;
extern icaltimezone *utc_zone;

struct proplist {
    icalproperty *prop;
    struct proplist *next;
};

/* Each calendar user address has the following scheduling protocol params */
/* All memory must be freed with sched_param_fini. */
struct caldav_sched_param {
    char *userid;       /* Userid corresponding to calendar address */
    char *server;       /* Remote server user lives on */
    unsigned port;      /* Remote server port, default = 80 */
    unsigned flags;     /* Flags dictating protocol to use for scheduling */
    unsigned isyou;     /* true if the user is the same as the authenticated user */
    struct proplist *props; /* List of attendee iCal properties */
};

extern void sched_param_fini(struct caldav_sched_param *sparam);

extern char *caldav_scheddefault(const char *userid);

extern icalproperty *find_attendee(icalcomponent *comp, const char *match);
extern const char *get_organizer(icalcomponent *comp);
extern int partstat_changed(icalcomponent *oldcomp,
                            icalcomponent *newcomp, const char *attendee);

extern icalcomponent *master_to_recurrence(icalcomponent *master,
                                           icalproperty *recurid);

extern unsigned sched_deliver_local(const char *userid,
                                    const char *sender, const char *recipient,
                                    struct caldav_sched_param *sparam,
                                    struct sched_data *sched_data,
                                    struct auth_state *authstate,
                                    const char **attendeep, icalcomponent **icalp);

#endif /* ITIP_SUPPORT_H */
