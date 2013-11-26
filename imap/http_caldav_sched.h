/* http_caldav_sched.h -- Routines for dealing with CALDAV scheduling in httpd
 *
 * Copyright (c) 1994-2013 Carnegie Mellon University.  All rights reserved.
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

#ifndef HTTP_CALDAV_SCHED_H
#define HTTP_CALDAV_SCHED_H

#include <libical/ical.h>

#ifdef WITH_DKIM
#include <dkim.h>

#ifndef DKIM_CANON_ISCHEDULE
#undef WITH_DKIM
#endif

#endif /* WITH_DKIM */

#include "http_dav.h"


#define REQSTAT_PENDING		"1.0;Pending"
#define REQSTAT_SENT		"1.1;Sent"
#define REQSTAT_DELIVERED	"1.2;Delivered"
#define REQSTAT_SUCCESS		"2.0;Success"
#define REQSTAT_NOUSER		"3.7;Invalid calendar user"
#define REQSTAT_NOPRIVS		"3.8;Noauthority"
#define REQSTAT_TEMPFAIL	"5.1;Service unavailable"
#define REQSTAT_PERMFAIL	"5.2;Invalid calendar service"
#define REQSTAT_REJECTED	"5.3;No scheduling support for user"

struct sched_data {
    unsigned ischedule;
    unsigned is_reply;
    icalcomponent *itip;
    icalcomponent *master;
    unsigned comp_mask;
    char *force_send;
    const char *status;
};

/* Scheduling protocol flags */
#define SCHEDTYPE_REMOTE	(1<<0)
#define SCHEDTYPE_ISCHEDULE	(1<<1)
#define SCHEDTYPE_SSL		(1<<2)

struct proplist {
    icalproperty *prop;
    struct proplist *next;
};

/* Each calendar user address has the following scheduling protocol params */
struct sched_param {
    char *userid;	/* Userid corresponding to calendar address */ 
    char *server;	/* Remote server user lives on */
    unsigned port;	/* Remote server port, default = 80 */
    unsigned flags;	/* Flags dictating protocol to use for scheduling */
    struct proplist *props; /* List of attendee iCal properties */
};

extern int isched_send(struct sched_param *sparam, const char *recipient,
		       icalcomponent *ical, xmlNodePtr *xml);

extern int sched_busytime_query(struct transaction_t *txn,
				struct mime_type_t *mime, icalcomponent *comp);
extern void sched_deliver(const char *recipient, void *data, void *rock);
extern xmlNodePtr xml_add_schedresponse(xmlNodePtr root, xmlNsPtr dav_ns,
					xmlChar *recipient, xmlChar *status);
extern int caladdress_lookup(const char *addr, struct sched_param *param);

#endif /* HTTP_CALDAV_SCHED_H */
