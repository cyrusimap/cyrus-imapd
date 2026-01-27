/* http_caldav_sched.h - Routines for dealing with CALDAV scheduling in httpd */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef HTTP_CALDAV_SCHED_H
#define HTTP_CALDAV_SCHED_H

//#define IOPTEST

#include <config.h>

#include <libical/ical.h>

#ifdef WITH_DKIM
#include <dkim.h>

#ifndef DKIM_CANON_ISCHEDULE
#undef WITH_DKIM
#endif

#endif /* WITH_DKIM */

#include "calsched_support.h"
#include "http_dav.h"
#include "ical_support.h"
#include "itip_support.h"


struct freebusy {
    struct icalperiodtype per;
    struct icaltimetype recurid;
    icalparameter_fbtype type;
};

struct freebusy_array {
    struct freebusy *fb;
    unsigned len;
    unsigned alloc;
};

struct vavailability {
    int priority;
    struct icalperiodtype per;
    icalcomponent *ical;
};

struct vavailability_array {
    struct vavailability *vav;
    unsigned len;
    unsigned alloc;
};

struct freebusy_filter {
    unsigned flags;
    struct icaltimetype start;
    struct icaltimetype end;
    icaltimezone *tz;
    struct freebusy_array freebusy;     /* array of found freebusy periods */
    struct vavailability_array vavail;  /* array of found vavail components */
};

/* Bitmask of freebusy_filter flags */
enum {
    CHECK_CAL_TRANSP =          (1<<0),
    CHECK_USER_AVAIL =          (1<<1)
};

extern const char *ical_prodid;
extern icaltimezone *utc_zone;
extern icalarray *rscale_calendars;

extern icalcomponent *busytime_query_local(struct transaction_t *txn,
                                           struct propfind_ctx *fctx,
                                           char mailboxname[],
                                           icalproperty_method method,
                                           const char *uid,
                                           const char *organizer,
                                           const char *attendee);

extern int busytime_add_resource(struct mailbox *mailbox,
                                 struct freebusy_filter *fbfilter,
                                 struct caldav_data *cdata);

extern icalcomponent *busytime_to_ical(struct freebusy_filter *fbfilter,
                                       icalproperty_method method,
                                       const char *uid,
                                       const char *organizer,
                                       const char *attendee);

extern int isched_send(struct caldav_sched_param *sparam, const char *recipient,
                       icalcomponent *ical, xmlNodePtr *xml);

extern int sched_busytime_query(struct transaction_t *txn,
                                struct mime_type_t *mime, icalcomponent *comp);
extern void schedule_one_attendee(const char *cal_ownerid, const char *sched_userid,
                                  const strarray_t *schedule_addresses,
                                  const char *organizer, const char *attendee,
                                  icaltimetype h_cutoff,
                                  icalcomponent *oldical, icalcomponent *newical,
                                  enum sched_mechanism mech);

extern void sched_request(const char *cal_ownerid, const char *sched_userid,
                          const strarray_t *schedule_addresses,
                          const char *organizer,
                          icalcomponent *oldical, icalcomponent *newical,
                          enum sched_mechanism mech);
extern void sched_reply(const char *cal_ownerid, const char *sched_userid,
                        const strarray_t *schedule_addresses,
                        icalcomponent *oldical, icalcomponent *newical,
                        enum sched_mechanism mech);
extern void sched_deliver(const char *cal_ownerid, const char *sched_userid,
                          const char *sender, const char *recipient,
                          void *data, void *rock);
extern xmlNodePtr xml_add_schedresponse(xmlNodePtr root, xmlNsPtr dav_ns,
                                        xmlChar *recipient, xmlChar *status);
extern int caladdress_lookup(const char *addr, struct caldav_sched_param *param,
                             const strarray_t *schedule_addresses);

extern void caldav_get_schedule_addresses(hdrcache_t req_hdrs,
                                          const char *mboxname,
                                          const char *userid,
                                          strarray_t *addresses);

#endif /* HTTP_CALDAV_SCHED_H */
