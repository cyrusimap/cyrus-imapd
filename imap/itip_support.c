/* itip_support.c -- Routines for dealing with iTIP
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


#include <config.h>

#include <syslog.h>

#include "itip_support.h"
#include "caldav_db.h"
#include "caldav_util.h"
#include "http_dav.h"
#include "httpd.h"
#include "ical_support.h"
#include "jmap_ical.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
#include "imap/http_err.h"


HIDDEN void sched_param_fini(struct caldav_sched_param *sparam)
{
    free(sparam->userid);
    free(sparam->server);

    struct proplist *prop, *next;
    for (prop = sparam->props; prop; prop = next) {
        next = prop->next;
        free(prop);
    }

    memset(sparam, 0, sizeof(struct caldav_sched_param));
}

HIDDEN icalproperty *find_attendee(icalcomponent *comp, const char *match)
{
    if (!comp) return NULL;

    icalproperty *prop = icalcomponent_get_first_invitee(comp);

    for (; prop; prop = icalcomponent_get_next_invitee(comp)) {
        const char *attendee = icalproperty_get_invitee(prop);
        if (!attendee) continue;
        if (!strncasecmp(attendee, "mailto:", 7)) attendee += 7;

        /* Skip where not the server's responsibility */
        icalparameter *param = icalproperty_get_scheduleagent_parameter(prop);
        if (param) {
            icalparameter_scheduleagent agent =
                icalparameter_get_scheduleagent(param);
            if (agent != ICAL_SCHEDULEAGENT_SERVER) continue;
        }

        if (!strcasecmp(attendee, match)) return prop;
    }

    return NULL;
}

HIDDEN const char *get_organizer(icalcomponent *comp)
{
    icalproperty *prop =
        icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    const char *organizer = icalproperty_get_organizer(prop);
    if (!organizer) return NULL;
    if (!strncasecmp(organizer, "mailto:", 7)) organizer += 7;
    icalparameter *param = icalproperty_get_scheduleagent_parameter(prop);
    /* check if we're supposed to send replies to the organizer */
    if (param &&
        icalparameter_get_scheduleagent(param) != ICAL_SCHEDULEAGENT_SERVER)
        return NULL;
    return organizer;
}

static icalparameter_partstat get_partstat(icalcomponent *comp,
                                           const char *attendee)
{
    icalproperty *prop = find_attendee(comp, attendee);
    if (!prop) return ICAL_PARTSTAT_NEEDSACTION;
    icalparameter *param =
        icalproperty_get_first_parameter(prop, ICAL_PARTSTAT_PARAMETER);
    if (!param) return ICAL_PARTSTAT_NEEDSACTION;
    return icalparameter_get_partstat(param);
}

HIDDEN int partstat_changed(icalcomponent *oldcomp,
                              icalcomponent *newcomp, const char *attendee)
{
    if (!attendee) return 1; // something weird is going on, treat it as a change
    return (get_partstat(oldcomp, attendee) != get_partstat(newcomp, attendee));
}

/* Returns the calendar collection name to use as scheduling default.
 * This is just the *last* part of the complete path without trailing
 * path separator, e.g. 'Default' */
HIDDEN char *caldav_scheddefault(const char *userid)
{
    const char *annotname =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-default-calendar";

    char *calhomename = caldav_mboxname(userid, NULL);
    char *defaultname = NULL;
    struct buf attrib = BUF_INITIALIZER;

    int r = annotatemore_lookupmask(calhomename, annotname, userid, &attrib);
    if (!r && attrib.len) {
        defaultname = buf_release(&attrib);
    }
    else defaultname = xstrdup(SCHED_DEFAULT);

    size_t len = strlen(defaultname);
    if (defaultname[len-1] == '/') defaultname[len-1] = '\0';

    buf_free(&attrib);
    free(calhomename);
    return defaultname;
}


/*
 * deliver_merge_reply() helper function
 *
 * Merge VOTER responses into VPOLL subcomponents
 */
static void deliver_merge_vpoll_reply(icalcomponent *ical, icalcomponent *reply)
{
    icalcomponent *new_ballot, *vvoter;
    icalproperty *voterp;
    const char *voter;

    /* Get VOTER from reply */
    new_ballot =
        icalcomponent_get_first_component(reply, ICAL_VVOTER_COMPONENT);
    voterp = icalcomponent_get_first_property(new_ballot, ICAL_VOTER_PROPERTY);
    voter = icalproperty_get_voter(voterp);

    /* Locate VOTER in existing VPOLL */
    for (vvoter =
           icalcomponent_get_first_component(ical, ICAL_VVOTER_COMPONENT);
         vvoter;
         vvoter =
             icalcomponent_get_next_component(ical, ICAL_VVOTER_COMPONENT)) {

        voterp =
            icalcomponent_get_first_property(vvoter, ICAL_VOTER_PROPERTY);

        if (!strcmp(voter, icalproperty_get_voter(voterp))) {
            icalcomponent_remove_component(ical, vvoter);
            icalcomponent_free(vvoter);
            break;
        }
    }

    /* XXX  Actually need to compare POLL-ITEM-IDs */
    icalcomponent_add_component(ical, icalcomponent_clone(new_ballot));
}


static int deliver_merge_pollstatus(icalcomponent *ical, icalcomponent *request)
{
    int deliver_inbox = 0;
    icalcomponent *oldpoll, *newpoll, *vvoter, *next;

    /* Remove each VVOTER from old object */
    oldpoll =
        icalcomponent_get_first_component(ical, ICAL_VPOLL_COMPONENT);
    for (vvoter =
             icalcomponent_get_first_component(oldpoll, ICAL_VVOTER_COMPONENT);
         vvoter;
         vvoter = next) {

        next = icalcomponent_get_next_component(oldpoll, ICAL_VVOTER_COMPONENT);

        icalcomponent_remove_component(oldpoll, vvoter);
        icalcomponent_free(vvoter);
    }

    /* Add each VVOTER in the iTIP request to old object */
    newpoll = icalcomponent_get_first_component(request, ICAL_VPOLL_COMPONENT);
    for (vvoter =
             icalcomponent_get_first_component(newpoll, ICAL_VVOTER_COMPONENT);
         vvoter;
         vvoter =
             icalcomponent_get_next_component(newpoll, ICAL_VVOTER_COMPONENT)) {

        icalcomponent_add_component(oldpoll, icalcomponent_clone(vvoter));
    }

    return deliver_inbox;
}

/* annoying copypaste from libical because it's not exposed */
static struct icaltimetype _get_datetime(icalcomponent *comp, icalproperty *prop)
{
    icalcomponent *c;
    icalparameter *param;
    struct icaltimetype ret;

    ret = icalvalue_get_datetime(icalproperty_get_value(prop));

    if ((param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER)) != NULL) {
        const char *tzid = icalparameter_get_tzid(param);
        icaltimezone *tz = NULL;

        for (c = comp; c != NULL; c = icalcomponent_get_parent(c)) {
            tz = icalcomponent_get_timezone(c, tzid);
            if (tz != NULL)
                break;
        }

        if (tz == NULL)
            tz = icaltimezone_get_builtin_timezone_from_tzid(tzid);

        if (tz != NULL)
            ret = icaltime_set_timezone(&ret, tz);
    }

    return ret;
}


HIDDEN icalcomponent *master_to_recurrence(icalcomponent *master,
                                           icalproperty *recurid)
{
    icalproperty *prop, *next;

    icalproperty *endprop = NULL;
    icalproperty *startprop = NULL;

    icalcomponent *comp = icalcomponent_clone(master);

    for (prop = icalcomponent_get_first_property(comp, ICAL_ANY_PROPERTY);
         prop; prop = next) {
        next = icalcomponent_get_next_property(comp, ICAL_ANY_PROPERTY);

        switch (icalproperty_isa(prop)) {
            /* extract start and end for later processing */
        case ICAL_DTEND_PROPERTY:
            endprop = prop;
            break;

        case ICAL_DTSTART_PROPERTY:
            startprop = prop;
            break;

            /* Remove all recurrence properties */
        case ICAL_RRULE_PROPERTY:
        case ICAL_RDATE_PROPERTY:
        case ICAL_EXDATE_PROPERTY:
            icalcomponent_remove_property(comp, prop);
            icalproperty_free(prop);
            break;

        default:
            break;
        }
    }

    /* Add RECURRENCE-ID */
    icalcomponent_add_property(comp, icalproperty_clone(recurid));

    /* calculate a new dtend based on recurid */
    struct icaltimetype start = _get_datetime(master, startprop);
    struct icaltimetype newstart = _get_datetime(master, recurid);

    icaltimezone *startzone = (icaltimezone *)icaltime_get_timezone(start);
    icalcomponent_set_dtstart(comp, icaltime_convert_to_zone(newstart, startzone));

    if (endprop) {
        struct icaltimetype end = _get_datetime(master, endprop);

        // calculate and re-apply the diff
        struct icaldurationtype diff = icaltime_subtract(end, start);
        struct icaltimetype newend = icaltime_add(newstart, diff);

        icaltimezone *endzone = (icaltimezone *)icaltime_get_timezone(end);
        icalcomponent_set_dtend(comp, icaltime_convert_to_zone(newend, endzone));
    }
    /* otherwise it will be a duration, which is still valid! */

    return comp;
}


static const char *deliver_merge_reply(icalcomponent *ical,
                                       icalcomponent *reply)
{
    struct hash_table comp_table;
    icalcomponent *comp, *itip, *master = NULL;
    icalcomponent_kind kind;
    icalproperty *prop, *att;
    icalparameter *param;
    icalparameter_partstat partstat = ICAL_PARTSTAT_NONE;
    const char *attendee = NULL, *cn = NULL;

    /* Add each component of old object to hash table for comparison */
    construct_hash_table(&comp_table, 10, 1);
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);
    do {
        prop = icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (prop)
            hash_insert(icalproperty_get_value_as_string(prop), comp, &comp_table);
        else
            master = comp;

    } while ((comp = icalcomponent_get_next_component(ical, kind)));


    /* Process each component in the iTIP reply */
    for (itip = icalcomponent_get_first_component(reply, kind);
         itip;
         itip = icalcomponent_get_next_component(reply, kind)) {

        icalproperty *sequence =
            icalcomponent_get_first_property(itip, ICAL_SEQUENCE_PROPERTY);
        icalproperty *dtstamp =
            icalcomponent_get_first_property(itip, ICAL_DTSTAMP_PROPERTY);

        /* Lookup this comp in the hash table */
        prop = icalcomponent_get_first_property(itip, ICAL_RECURRENCEID_PROPERTY);
        if (prop)
            comp = hash_lookup(icalproperty_get_value_as_string(prop), &comp_table);
        else
            comp = master;

        if (!comp) {
            /* New recurrence overridden by attendee. */
            if (icalcomponent_get_status(master) == ICAL_STATUS_CANCELLED) {
                /* The master event has been cancelled - ignore this override. */
                continue;
            }

            icaltimetype occur = icaltime_null_time();
            icaltimetype recurid = icalproperty_get_recurrenceid(prop);
            icalproperty *rrule =
                icalcomponent_get_first_property(master, ICAL_RRULE_PROPERTY);

            if (rrule) {
                icalrecur_iterator *ritr =
                    icalrecur_iterator_new(icalproperty_get_rrule(rrule),
                                           icalcomponent_get_dtstart(master));

                icalrecur_iterator_set_start(ritr, recurid);
                occur = icalrecur_iterator_next(ritr);
                icalrecur_iterator_free(ritr);
            }

            if (icaltime_compare(occur, recurid) != 0) {
                /* RECURRENCE-ID is not a valid occurrence */
                continue;
            }

            /* create a new recurrence from master component. */
            comp = master_to_recurrence(master, prop);
            icalcomponent_add_component(ical, comp);

            /* Replace SEQUENCE */
            prop = icalcomponent_get_first_property(comp, ICAL_SEQUENCE_PROPERTY);
            if (prop) {
                icalcomponent_remove_property(comp, prop);
                icalproperty_free(prop);
            }
            if (sequence) icalcomponent_add_property(comp,
                                                     icalproperty_clone(sequence));
        }
        else if (icalcomponent_get_status(comp) == ICAL_STATUS_CANCELLED) {
            /* This component has been cancelled - ignore the reply */
            continue;
        }

        /* Get the sending attendee */
        att = icalcomponent_get_first_invitee(itip);
        attendee = icalproperty_get_invitee(att);
        param = icalproperty_get_first_parameter(att, ICAL_PARTSTAT_PARAMETER);
        if (param) partstat = icalparameter_get_partstat(param);
        param = icalproperty_get_first_parameter(att, ICAL_CN_PARAMETER);
        if (param) cn = icalparameter_get_cn(param);

        /* Find matching attendee in existing object */
        for (prop = icalcomponent_get_first_invitee(comp);
             prop && strcmp(attendee, icalproperty_get_invitee(prop));
             prop = icalcomponent_get_next_invitee(comp));
        if (!prop) {
            /* Attendee added themselves to this recurrence */
            assert(icalproperty_isa(prop) != ICAL_VOTER_PROPERTY);
            prop = icalproperty_clone(att);
            icalcomponent_add_property(comp, prop);
        }

        /* Set PARTSTAT */
        if (partstat != ICAL_PARTSTAT_NONE) {
            param = icalparameter_new_partstat(partstat);
            icalproperty_set_parameter(prop, param);
        }

        /* Set X-DTSTAMP and X-SEQUENCE */
        const char *val = icalproperty_get_value_as_string(dtstamp);
        icalproperty_set_xparam(prop, JMAPICAL_XPARAM_DTSTAMP, val, 1);

        val = sequence ? icalproperty_get_value_as_string(sequence) : "0";
        icalproperty_set_xparam(prop, JMAPICAL_XPARAM_SEQUENCE, val, 1);

        /* Set CN, if provided */
        if (cn &&
            !(param = icalproperty_get_first_parameter(prop, ICAL_CN_PARAMETER))) {
            param = icalparameter_new_cn(cn);
            icalproperty_set_parameter(prop, param);
        }

        /* Remove RSVP and SCHEDULE-STATUS */
        icalproperty_remove_parameter_by_kind(prop, ICAL_RSVP_PARAMETER);
        icalproperty_remove_parameter_by_kind(prop, ICAL_SCHEDULESTATUS_PARAMETER);

        /* Handle VPOLL reply */
        if (kind == ICAL_VPOLL_COMPONENT) deliver_merge_vpoll_reply(comp, itip);
    }

    free_hash_table(&comp_table, NULL);

    return attendee;
}


static int deliver_merge_request(const char *attendee,
                                 icalcomponent *ical, icalcomponent *request)
{
    int deliver_inbox = 0;
    struct hash_table comp_table;
    icalcomponent *comp, *itip;
    icalcomponent_kind kind = ICAL_NO_COMPONENT;
    icalproperty *prop;
    icalparameter *param;
    const char *tzid, *recurid, *organizer = NULL;

    /* Add each VTIMEZONE of old object to hash table for comparison */
    construct_hash_table(&comp_table, 10, 1);
    for (comp =
             icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
         comp;
         comp =
             icalcomponent_get_next_component(ical, ICAL_VTIMEZONE_COMPONENT)) {
        prop = icalcomponent_get_first_property(comp, ICAL_TZID_PROPERTY);
        tzid = icalproperty_get_tzid(prop);
        if (!tzid) continue;

        hash_insert(tzid, comp, &comp_table);
    }

    /* Process each VTIMEZONE in the iTIP request */
    for (itip = icalcomponent_get_first_component(request,
                                                  ICAL_VTIMEZONE_COMPONENT);
         itip;
         itip = icalcomponent_get_next_component(request,
                                                 ICAL_VTIMEZONE_COMPONENT)) {
        /* Lookup this TZID in the hash table */
        prop = icalcomponent_get_first_property(itip, ICAL_TZID_PROPERTY);
        tzid = icalproperty_get_tzid(prop);
        if (!tzid) continue;

        comp = hash_lookup(tzid, &comp_table);
        if (comp) {
            /* Remove component from old object */
            icalcomponent_remove_component(ical, comp);
            icalcomponent_free(comp);
        }

        /* Add new/modified component from iTIP request */
        icalcomponent_add_component(ical, icalcomponent_clone(itip));
    }

    free_hash_table(&comp_table, NULL);

    /* Add each component of old object to hash table for comparison */
    construct_hash_table(&comp_table, 10, 1);
    comp = icalcomponent_get_first_real_component(ical);
    if (comp) {
        kind = icalcomponent_isa(comp);
        organizer = get_organizer(comp);
    }
    for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
        prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (prop) recurid = icalproperty_get_value_as_string(prop);
        else recurid = "";

        hash_insert(recurid, comp, &comp_table);
    }

    /* Process each component in the iTIP request */
    itip = icalcomponent_get_first_real_component(request);
    if (kind == ICAL_NO_COMPONENT) kind = icalcomponent_isa(itip);
    for (; itip; itip = icalcomponent_get_next_component(request, kind)) {
        icalcomponent *new_comp = icalcomponent_clone(itip);

        /* Lookup this comp in the hash table */
        prop =
            icalcomponent_get_first_property(itip, ICAL_RECURRENCEID_PROPERTY);
        if (prop) recurid = icalproperty_get_value_as_string(prop);
        else recurid = "";

        comp = hash_lookup(recurid, &comp_table);
        if (comp) {
            int old_seq, new_seq;

            /* Check if this is something more than an update */
            /* XXX  Probably need to check PARTSTAT=NEEDS-ACTION
               and RSVP=TRUE as well */
            old_seq = icalcomponent_get_sequence(comp);
            new_seq = icalcomponent_get_sequence(itip);
            if (new_seq > old_seq) deliver_inbox = 1;
            else if (partstat_changed(comp, itip, organizer)) deliver_inbox = 1;

            /* Copy over any COMPLETED, PERCENT-COMPLETE,
               or TRANSP properties */
            prop =
                icalcomponent_get_first_property(comp, ICAL_COMPLETED_PROPERTY);
            if (prop) {
                icalcomponent_add_property(new_comp,
                                           icalproperty_clone(prop));
            }
            prop =
                icalcomponent_get_first_property(comp,
                                                 ICAL_PERCENTCOMPLETE_PROPERTY);
            if (prop) {
                icalcomponent_add_property(new_comp,
                                           icalproperty_clone(prop));
            }
            prop =
                icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
            if (prop) {
                icalcomponent_add_property(new_comp,
                                           icalproperty_clone(prop));
            }

            /* Copy over any ORGANIZER;SCHEDULE-STATUS */
            /* XXX  Do we only do this iff PARTSTAT!=NEEDS-ACTION */
            prop =
                icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
            param = icalproperty_get_schedulestatus_parameter(prop);
            if (param) {
                param = icalparameter_clone(param);
                prop =
                    icalcomponent_get_first_property(new_comp,
                                                     ICAL_ORGANIZER_PROPERTY);
                icalproperty_add_parameter(prop, param);
            }

            /* Remove component from old object */
            icalcomponent_remove_component(ical, comp);
            icalcomponent_free(comp);
        }
        else {
            /* New component */
            deliver_inbox = 1;
        }

        if (config_getenum(IMAPOPT_CALDAV_ALLOWSCHEDULING)
                           == IMAP_ENUM_CALDAV_ALLOWSCHEDULING_APPLE &&
            kind == ICAL_VEVENT_COMPONENT) {
            /* Make VEVENT component transparent if recipient ATTENDEE
               PARTSTAT=NEEDS-ACTION (for compatibility with CalendarServer) */
            for (prop =
                     icalcomponent_get_first_property(new_comp,
                                                      ICAL_ATTENDEE_PROPERTY);
                 prop && strcmp(icalproperty_get_attendee(prop), attendee);
                 prop =
                     icalcomponent_get_next_property(new_comp,
                                                     ICAL_ATTENDEE_PROPERTY));
            param =
                icalproperty_get_first_parameter(prop, ICAL_PARTSTAT_PARAMETER);
            if (param &&
                icalparameter_get_partstat(param) ==
                ICAL_PARTSTAT_NEEDSACTION) {
                prop =
                    icalcomponent_get_first_property(new_comp,
                                                     ICAL_TRANSP_PROPERTY);
                if (prop)
                    icalproperty_set_transp(prop, ICAL_TRANSP_TRANSPARENT);
                else {
                    prop = icalproperty_new_transp(ICAL_TRANSP_TRANSPARENT);
                    icalcomponent_add_property(new_comp, prop);
                }
            }
        }

        /* Add new/modified component from iTIP request */
        icalcomponent_add_component(ical, new_comp);
    }

    free_hash_table(&comp_table, NULL);

    return deliver_inbox;
}


static int deliver_merge_cancel(const char *recipient,
                                icalcomponent *ical, icalcomponent *cancel)
{
    struct hash_table comp_table;
    icalcomponent *comp, *itip, *master_comp = NULL;
    icalcomponent_kind kind = ICAL_NO_COMPONENT;
    icalproperty *prop;
    const char *recurid;
    int num_canceled = 0;

    /* Add each override component of old object to hash table for comparison */
    construct_hash_table(&comp_table, 10, 1);
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);

    for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
        prop = icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (prop) {
            recurid = icalproperty_get_value_as_string(prop);
            hash_insert(recurid, comp, &comp_table);
        }
        else {
            master_comp = comp;
        }
    }

    /* Process each component in the iTIP request */
    for (itip = icalcomponent_get_first_real_component(cancel);
         itip; itip = icalcomponent_get_next_component(cancel, kind)) {
        /* Make sure this component refers to our recipient */
        prop = find_attendee(itip, recipient);
        if (!prop) continue;

        /* Lookup this comp in the hash table */
        prop = icalcomponent_get_first_property(itip, ICAL_RECURRENCEID_PROPERTY);
        if (prop) {
            /* Override */
            recurid = icalproperty_get_value_as_string(prop);
            comp = hash_lookup(recurid, &comp_table);

            if (comp) {
                /* Set STATUS:CANCELLED on this component */
                icalcomponent_set_status(comp, ICAL_STATUS_CANCELLED);
                icalcomponent_set_sequence(comp,
                                           icalcomponent_get_sequence(comp)+1);
                num_canceled++;
            }
            else if (master_comp) {
                /* Set EXDATE on master component */
                struct icaltimetype exdate = icalproperty_get_exdate(prop);
                icalparameter *tzid =
                    icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);

                prop = icalproperty_new_exdate(exdate);
                if (tzid) {
                    icalproperty_add_parameter(prop, icalparameter_clone(tzid));
                }

                icalcomponent_add_property(master_comp, prop);
            }
        }
        else {
            /* Master - Set STATUS:CANCELLED on all components */
            for (comp = icalcomponent_get_first_component(ical, kind);
                 comp; comp = icalcomponent_get_next_component(ical, kind)) {
                icalcomponent_set_status(comp, ICAL_STATUS_CANCELLED);
                icalcomponent_set_sequence(comp,
                                           icalcomponent_get_sequence(comp)+1);
                num_canceled++;
            }
            break;
        }
    }

    free_hash_table(&comp_table, NULL);

    return (num_canceled >= hash_numrecords(&comp_table));
}


/* Deliver scheduling object to local recipient */
HIDDEN enum sched_deliver_outcome sched_deliver_local(const char *userid,
                                                      const char *sender,
                                                      const char *recipient,
                                                      struct caldav_sched_param *sparam,
                                                      struct sched_data *sched_data,
                                                      struct auth_state *authstate,
                                                      const char **attendeep,
                                                      icalcomponent **icalp)
{
    int r = 0, rights = 0, reqd_privs, deliver_inbox = 1;
    const char *attendee = NULL;
    static struct buf resource = BUF_INITIALIZER;
    char *mailboxname = NULL;
    mbentry_t *mbentry = NULL;
    struct mailbox *mailbox = NULL, *inbox = NULL;
    struct caldav_db *caldavdb = NULL;
    struct caldav_data *cdata;
    icalcomponent *ical = NULL;
    icalproperty_method method;
    icalcomponent_kind kind;
    icalcomponent *comp;
    icalproperty *prop;
    struct transaction_t txn;
    enum sched_deliver_outcome result = SCHED_DELIVER_ERROR;

    syslog(LOG_DEBUG, "sched_deliver_local(%s, %s, %X)",
           sender, recipient, sparam->flags);

    if (icalp) *icalp = NULL;
    if (attendeep) *attendeep = NULL;

    /* Start with an empty (clean) transaction */
    memset(&txn, 0, sizeof(struct transaction_t));
    txn.userid = userid;

    /* Create header cache */
    txn.req_hdrs = spool_new_hdrcache();
    if (!txn.req_hdrs) goto done;

    /* Check ACL of sender on recipient's Scheduling Inbox */
    mailboxname = caldav_mboxname(sparam->userid, SCHED_INBOX);
    r = mboxlist_lookup(mailboxname, &mbentry, NULL);
    if (r) {
        syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
               mailboxname, error_message(r));
        SCHED_STATUS(sched_data, REQSTAT_REJECTED, SCHEDSTAT_REJECTED);
        goto done;
    }

    if (mbentry && mbentry->acl) {
        rights = cyrus_acl_myrights(authstate, mbentry->acl);
    }
    mboxlist_entry_free(&mbentry);

    reqd_privs = SCHED_IS_REPLY(sched_data) ? DACL_REPLY : DACL_INVITE;
    if (!(rights & reqd_privs)) {
        SCHED_STATUS(sched_data, REQSTAT_NOPRIVS, SCHEDSTAT_NOPRIVS);
        syslog(LOG_DEBUG, "No scheduling receive ACL for user %s on Inbox %s",
               userid, sparam->userid);
        goto done;
    }

    /* Open recipient's Inbox for writing */
    if ((r = mailbox_open_iwl(mailboxname, &inbox))) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
               mailboxname, error_message(r));
        SCHED_STATUS(sched_data, REQSTAT_TEMPFAIL, SCHEDSTAT_TEMPFAIL);
        goto done;
    }
    free(mailboxname);
    mailboxname = NULL;

    /* Get METHOD of the iTIP message */
    method = icalcomponent_get_method(sched_data->itip);

    /* Search for iCal UID in recipient's calendars */
    caldavdb = caldav_open_userid(sparam->userid);
    if (!caldavdb) {
        SCHED_STATUS(sched_data, REQSTAT_TEMPFAIL, SCHEDSTAT_TEMPFAIL);
        goto done;
    }

    caldav_lookup_uid(caldavdb,
                      icalcomponent_get_uid(sched_data->itip), &cdata);

    if (cdata->dav.mailbox) {
        if (SCHED_INVITES_ONLY(sched_data)) {
            /* Configured to NOT process updates - ignore request */
            SCHED_STATUS(sched_data, REQSTAT_NOPRIVS, SCHEDSTAT_NOPRIVS);
            result = SCHED_DELIVER_NOACTION;
            goto done;
        }

        if (cdata->dav.mailbox_byname)
            mailboxname = xstrdup(cdata->dav.mailbox);
        else {
            mboxlist_lookup_by_uniqueid(cdata->dav.mailbox, &mbentry, NULL);
            if (!mbentry) {
                SCHED_STATUS(sched_data, REQSTAT_TEMPFAIL, SCHEDSTAT_TEMPFAIL);
                goto done;
            }
            mailboxname = xstrdup(mbentry->name);
            mboxlist_entry_free(&mbentry);
        }
        buf_setcstr(&resource, cdata->dav.resource);
    }
    else if (SCHED_IS_REPLY(sched_data)) {
        /* Can't find object belonging to organizer - ignore reply */
        SCHED_STATUS(sched_data, REQSTAT_PERMFAIL, SCHEDSTAT_PERMFAIL);
        goto done;
    }
    else if (method == ICAL_METHOD_CANCEL || method == ICAL_METHOD_POLLSTATUS) {
        /* Can't find object belonging to attendee - we're done */
        SCHED_STATUS(sched_data, REQSTAT_SUCCESS, SCHEDSTAT_DELIVERED);
        result = SCHED_DELIVER_NOACTION;
        goto done;
    }
    else if (SCHED_UPDATES_ONLY(sched_data)) {
        /* Can't find object belonging to attendee - ignore request */
        SCHED_STATUS(sched_data, REQSTAT_NOPRIVS, SCHEDSTAT_NOPRIVS);
        result = SCHED_DELIVER_NOACTION;
        goto done;
    }
    else {
        /* Can't find object belonging to attendee -
           use specified calendar, or default calendar */
        if (sched_data->calendarid) {
            mailboxname = caldav_mboxname(sparam->userid, sched_data->calendarid);
        }
        else {
            char *scheddefault = caldav_scheddefault(sparam->userid);
            mailboxname = caldav_mboxname(sparam->userid, scheddefault);
            free(scheddefault);
        }
        buf_reset(&resource);
        /* XXX - sanitize the uid? */
        buf_printf(&resource, "%s.ics",
                   icalcomponent_get_uid(sched_data->itip));

        /* Create new attendee object */
        ical = icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT, 0);

        /* Copy over VERSION property */
        prop = icalcomponent_get_first_property(sched_data->itip,
                                                ICAL_VERSION_PROPERTY);
        icalcomponent_add_property(ical, icalproperty_clone(prop));

        /* Copy over PRODID property */
        prop = icalcomponent_get_first_property(sched_data->itip,
                                                ICAL_PRODID_PROPERTY);
        icalcomponent_add_property(ical, icalproperty_clone(prop));

        /* Copy over any CALSCALE property */
        prop = icalcomponent_get_first_property(sched_data->itip,
                                                ICAL_CALSCALE_PROPERTY);
        if (prop) {
            icalcomponent_add_property(ical,
                                       icalproperty_clone(prop));
        }
    }

    /* Open recipient's calendar for writing */
    r = mailbox_open_iwl(mailboxname, &mailbox);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
               mailboxname, error_message(r));
        SCHED_STATUS(sched_data, REQSTAT_TEMPFAIL, SCHEDSTAT_TEMPFAIL);
        goto done;
    }

    if (cdata->dav.imap_uid) {
        /* Load message containing the resource and parse iCal data */
        ical = caldav_record_to_ical(mailbox, cdata, NULL, NULL);

        for (comp = icalcomponent_get_first_component(sched_data->itip,
                                                      ICAL_ANY_COMPONENT);
             comp;
             comp = icalcomponent_get_next_component(sched_data->itip,
                                                     ICAL_ANY_COMPONENT)) {
            /* Don't allow component type to be changed */
            int reject = 0;
            kind = icalcomponent_isa(comp);
            switch (kind) {
            case ICAL_VEVENT_COMPONENT:
                if (cdata->comp_type != CAL_COMP_VEVENT) reject = 1;
                break;
            case ICAL_VTODO_COMPONENT:
                if (cdata->comp_type != CAL_COMP_VTODO) reject = 1;
                break;
            case ICAL_VJOURNAL_COMPONENT:
                if (cdata->comp_type != CAL_COMP_VJOURNAL) reject = 1;
                break;
            case ICAL_VFREEBUSY_COMPONENT:
                if (cdata->comp_type != CAL_COMP_VFREEBUSY) reject = 1;
                break;
            case ICAL_VAVAILABILITY_COMPONENT:
                if (cdata->comp_type != CAL_COMP_VAVAILABILITY) reject = 1;
                break;
            case ICAL_VPOLL_COMPONENT:
                if (cdata->comp_type != CAL_COMP_VPOLL) reject = 1;
                break;
            default:
                break;
            }

            /* Don't allow ORGANIZER to be changed */
            if (!reject && cdata->organizer) {
                prop =
                    icalcomponent_get_first_property(comp,
                                                     ICAL_ORGANIZER_PROPERTY);
                if (prop) {
                    const char *organizer =
                        organizer = icalproperty_get_organizer(prop);
                    if (organizer) {
                        if (!strncasecmp(organizer, "mailto:", 7)) organizer += 7;
                        if (strcasecmp(cdata->organizer, organizer)) reject = 1;
                    }
                }
            }

            if (reject) {
                SCHED_STATUS(sched_data, REQSTAT_REJECTED, SCHEDSTAT_REJECTED);
                goto done;
            }
        }
    }

    switch (method) {
    case ICAL_METHOD_CANCEL: {
        int entire_comp = deliver_merge_cancel(recipient,
                                               ical, sched_data->itip);

        if (entire_comp && SCHED_DELETE_CANCELED(sched_data)) {
            /* Expunge the resource */
            struct index_record record;
            int r;

            memset(&record, 0, sizeof(struct index_record));

            /* Fetch index record for the resource */
            r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record);
            if (r) {
                syslog(LOG_ERR, "mailbox_find_index_record(%s, %u) failed: %s",
                       mailbox_name(mailbox), cdata->dav.imap_uid, error_message(r));
            }
            else {
                struct mboxevent *mboxevent =
                    mboxevent_new(EVENT_MESSAGE_EXPUNGE);

                record.internal_flags |= FLAG_INTERNAL_EXPUNGED;

                r = mailbox_rewrite_index_record(mailbox, &record);
                if (r) {
                    syslog(LOG_ERR, "expunging record (%s) failed: %s",
                           mailbox_name(mailbox), error_message(r));
                }
                else {
                    mboxevent_extract_record(mboxevent, mailbox, &record);
                    mboxevent_extract_mailbox(mboxevent, mailbox);
                    mboxevent_set_numunseen(mboxevent, mailbox, -1);
                    mboxevent_set_access(mboxevent, NULL, NULL, sparam->userid,
                                         mailbox_name(mailbox), 0);
                    mboxevent_notify(&mboxevent);
                    result = SCHED_DELIVER_DELETED;
                }

                mboxevent_free(&mboxevent);
            }

            if (!r) goto inbox;
        }
        break;
    }

    case ICAL_METHOD_REPLY:
        attendee = deliver_merge_reply(ical, sched_data->itip);
        if (attendeep) *attendeep = attendee;
        break;

    case ICAL_METHOD_REQUEST:
        deliver_inbox = deliver_merge_request(recipient,
                                              ical, sched_data->itip);
        break;

    case ICAL_METHOD_POLLSTATUS:
        deliver_inbox = deliver_merge_pollstatus(ical, sched_data->itip);
        break;

    default:
        /* Unknown METHOD -- ignore it */
        syslog(LOG_ERR, "Unknown iTIP method: %s",
               icalenum_method_to_string(method));

        sched_data->flags &= ~SCHEDFLAG_IS_REPLY;
        goto inbox;
    }

    /* Store the (updated) object in the recipients's calendar */
    strarray_t recipient_addresses = STRARRAY_INITIALIZER;
    strarray_append(&recipient_addresses, recipient);
    r = caldav_store_resource(&txn, ical, mailbox,
                              buf_cstring(&resource), cdata->dav.createdmodseq,
                              caldavdb, NEW_STAG, sparam->userid,
                              NULL, NULL, &recipient_addresses);
    strarray_fini(&recipient_addresses);

    if (r == HTTP_CREATED || r == HTTP_NO_CONTENT) {
        SCHED_STATUS(sched_data, REQSTAT_SUCCESS, SCHEDSTAT_DELIVERED);
        result =
            (r == HTTP_CREATED) ? SCHED_DELIVER_ADDED : SCHED_DELIVER_UPDATED;
    }
    else {
        syslog(LOG_ERR, "caldav_store_resource(%s) failed: %s (%s)",
               mailbox_name(mailbox), error_message(r), txn.error.resource);
        SCHED_STATUS(sched_data, REQSTAT_TEMPFAIL, SCHEDSTAT_TEMPFAIL);
        goto done;
    }

  inbox:
    if (deliver_inbox) {
        /* Create a name for the new iTIP message resource */
        buf_reset(&resource);
        buf_printf(&resource, "%s.ics", makeuuid());

        /* Store the message in the recipient's Inbox */
        r = caldav_store_resource(&txn, sched_data->itip, inbox,
                                  buf_cstring(&resource), 0, caldavdb, 0,
                                  NULL, NULL, NULL, NULL);
        /* XXX  What do we do if storing to Inbox fails? */
    }

  done:
    if (icalp) *icalp = ical;
    else if (ical) icalcomponent_free(ical);
    mailbox_close(&inbox);
    mailbox_close(&mailbox);
    if (caldavdb) caldav_close(caldavdb);
    spool_free_hdrcache(txn.req_hdrs);
    buf_free(&txn.buf);
    free(mailboxname);
    return result;
}
