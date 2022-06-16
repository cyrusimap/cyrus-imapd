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
    if (!comp) return NULL;
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

HIDDEN int organizer_changed(icalcomponent *oldcomp, icalcomponent *newcomp)
{
    return strcmpsafe(get_organizer(oldcomp), get_organizer(newcomp));
}

struct pick_scheddefault_rock {
    strarray_t ignore;
    char *collname;
};

static int pick_scheddefault_cb(const mbentry_t *mbentry, void *vrock)
{
    struct pick_scheddefault_rock *rock = vrock;
    mbname_t *mbname = NULL;
    int r = 0;

    if (mbentry->mbtype & MBTYPE_CALENDAR) {
        mbname = mbname_from_intname(mbentry->name);
        const char *collname = strarray_nth(mbname_boxes(mbname), -1);
        if (strarray_find(&rock->ignore, collname, 0) < 0) {
            if (mbentry->acl) {
                // Must be writable by owner
                const char *ownerid = mbname_userid(mbname);
                strarray_t *acl = strarray_split(mbentry->acl, "\t", STRARRAY_TRIM);
                for (int i = 0; i < strarray_size(acl); i += 2) {
                    const char *userid = strarray_nth(acl, i);
                    if (!strcmp(userid, ownerid) || !strcmp(userid, "anyone")) {
                        int rights = 0;
                        cyrus_acl_strtomask(strarray_nth(acl, i+1), &rights);
                        if (rights & ACL_INSERT) {
                            rock->collname = xstrdup(collname);
                            r = CYRUSDB_DONE;
                        }
                    }
                }
                strarray_free(acl);
            }
        }
    }

    mbname_free(&mbname);
    return r;
}

HIDDEN char *caldav_scheddefault(const char *userid, int fallback)
{
    const char *annotname =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-default-calendar";

    char *calhomename = caldav_mboxname(userid, NULL);
    char *collname = NULL;
    struct buf buf = BUF_INITIALIZER;

    int r = annotatemore_lookupmask(calhomename, annotname, userid, &buf);
    if (!r && buf.len) {
        // use scheduling default
        collname = buf_release(&buf);
    }
    else if (fallback) {
        // attempt to fallback using SCHED_DEFAULT
        collname = xstrdup(SCHED_DEFAULT);
        mbentry_t *mbentry = NULL;
        char *mboxname = caldav_mboxname(userid, collname);
        if (mboxlist_lookup(mboxname, &mbentry, NULL)) {
            // attempt to pick any other calendar
            xzfree(collname);
            struct pick_scheddefault_rock rock = { 0 };

            buf_setcstr(&buf, SCHED_INBOX);
            if (buf.len && buf.s[buf.len-1] == '/')
                buf_truncate(&buf, -1);
            strarray_append(&rock.ignore, buf_cstring(&buf));

            buf_setcstr(&buf, SCHED_OUTBOX);
            if (buf.len && buf.s[buf.len-1] == '/')
                buf_truncate(&buf, -1);
            strarray_append(&rock.ignore, buf_cstring(&buf));

            buf_setcstr(&buf, MANAGED_ATTACH);
            if (buf.len && buf.s[buf.len-1] == '/')
                buf_truncate(&buf, -1);
            strarray_append(&rock.ignore, buf_cstring(&buf));

            mboxlist_mboxtree(calhomename, pick_scheddefault_cb,
                    &rock, MBOXTREE_SKIP_ROOT);

            strarray_fini(&rock.ignore);
            collname = rock.collname;
        }
        mboxlist_entry_free(&mbentry);
        free(mboxname);
    }

    if (collname) {
        size_t len = strlen(collname);
        if (collname[len-1] == '/')
            collname[len-1] = '\0';
    }

    buf_free(&buf);
    free(calhomename);
    return collname;
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
    icalcomponent_add_property(comp, recurid);

    /* calculate a new dtend based on recurid */
    struct icaltimetype start = _get_datetime(master, startprop);
    struct icaltimetype newstart = _get_datetime(master, recurid);

    icaltimezone *startzone = (icaltimezone *)icaltime_get_timezone(start);
    icalproperty_set_dtstart(startprop,
                             icaltime_convert_to_zone(newstart, startzone));

    if (endprop) {
        struct icaltimetype end = _get_datetime(master, endprop);

        // calculate and re-apply the diff
        struct icaldurationtype diff = icaltime_subtract(end, start);
        struct icaltimetype newend = icaltime_add(newstart, diff);

        icaltimezone *endzone = (icaltimezone *)icaltime_get_timezone(end);
        icalproperty_set_dtend(endprop,
                               icaltime_convert_to_zone(newend, endzone));
    }
    /* otherwise it will be a duration, which is still valid! */

    return comp;
}


static const char *deliver_merge_reply(icalcomponent *ical,  // current iCalendar
                                       icalcomponent *reply) // iTIP reply
{
    struct hash_table override_table;
    icalcomponent *comp, *itip, *master = NULL;
    icalcomponent_kind kind;
    icalproperty *prop, *att;
    icalparameter *param;
    icalparameter_partstat partstat = ICAL_PARTSTAT_NONE;
    const char *attendee = NULL, *cn = NULL;
    icaltimezone *startzone = NULL;
    icaltimetype dtstart;
    ptrarray_t rrules = PTRARRAY_INITIALIZER;
    struct hash_table rdate_table = HASH_TABLE_INITIALIZER;

    /* Add each override component of current object to hash table for lookup */
    construct_hash_table(&override_table, 10, 1);
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);
    do {
        icaltimetype recurid = icalcomponent_get_recurrenceid_with_zone(comp);

        if (!icaltime_is_null_time(recurid)) {
            hash_insert(icaltime_as_ical_string(recurid), comp, &override_table);
        }
        else {
            /* Master component - get recurrence info */
            master = comp;

            construct_hash_table(&rdate_table, 10, 1);

            for (prop = icalcomponent_get_first_property(master,
                                                         ICAL_ANY_PROPERTY);
                 prop;
                 prop = icalcomponent_get_next_property(master,
                                                        ICAL_ANY_PROPERTY)) {
                switch(icalproperty_isa(prop)) {
                case ICAL_DTSTART_PROPERTY:
                    dtstart = icalproperty_get_datetime_with_component(prop,
                                                                       master);
                    startzone = (icaltimezone *) icaltime_get_timezone(dtstart);
                    break;

                case ICAL_RRULE_PROPERTY: {
                    struct icalrecurrencetype rrule =
                        icalproperty_get_rrule(prop);
                    ptrarray_append(&rrules, &rrule);
                    break;
                }

                case ICAL_RDATE_PROPERTY: {
                    /* Note: This assumes that RDATE;TZID == DTSTART;TZID */
                    struct icaldatetimeperiodtype rdate =
                        icalproperty_get_rdate(prop);

                    recurid= !icaltime_is_null_time(rdate.time) ?
                        rdate.time : rdate.period.start;

                    hash_insert(icaltime_as_ical_string(recurid),
                                (void *) 1, &rdate_table);
                    break;
                }

                default:
                    break;
                }
            }
        }

    } while ((comp = icalcomponent_get_next_component(ical, kind)));


    /* Process each component in the iTIP reply */
    for (itip = icalcomponent_get_first_component(reply, kind);
         itip;
         itip = icalcomponent_get_next_component(reply, kind)) {

        icalproperty *sequence =
            icalcomponent_get_first_property(itip, ICAL_SEQUENCE_PROPERTY);
        icalproperty *dtstamp =
            icalcomponent_get_first_property(itip, ICAL_DTSTAMP_PROPERTY);
        icaltimetype recurid = icalcomponent_get_recurrenceid_with_zone(itip);

        if (icaltime_is_null_time(recurid)) {
            comp = master;
        }
        else {
            /* Convert RECURRENCE-ID to DTSTART time zone
               and lookup in the override hash table */
            recurid = icaltime_convert_to_zone(recurid, startzone);
            comp = hash_lookup(icaltime_as_ical_string(recurid), &override_table);
        }

        if (!comp) {
            /* New recurrence overridden by attendee. */
            if (icalcomponent_get_status(master) == ICAL_STATUS_CANCELLED) {
                /* The master event has been cancelled - ignore this override. */
                continue;
            }

            /* Lookup RECURRENCE-ID in RDATE hash table */
            if (!hash_lookup(icaltime_as_ical_string(recurid), &rdate_table)) {
                int i, valid = 0, size = ptrarray_size(&rrules);

                /* Does it correspond to an occurrence of an RRULE? */
                for (i = 0; !valid && i < size; i++) {
                    struct icalrecurrencetype *rrule = ptrarray_nth(&rrules, i);
                    icalrecur_iterator *ritr =
                        icalrecur_iterator_new(*rrule, dtstart);

                    icalrecur_iterator_set_start(ritr, recurid);
                    valid = !icaltime_compare(recurid,
                                              icalrecur_iterator_next(ritr));
                    icalrecur_iterator_free(ritr);
                }

                if (!valid) {
                    /* RECURRENCE-ID is not a valid occurrence */
                    continue;
                }
            }

            /* Create a new override from the master component
               and add it to the current object */
            icalproperty *recuridp = icalproperty_new_recurrenceid(recurid);
            const char *tzid = icaltimezone_get_location(startzone);
            if (tzid) {
                icalproperty_set_parameter(recuridp, icalparameter_new_tzid(tzid));
            }
            comp = master_to_recurrence(master, recuridp);
            icalcomponent_add_component(ical, comp);

            /* Replace SEQUENCE */
            prop = icalcomponent_get_first_property(comp, ICAL_SEQUENCE_PROPERTY);
            if (prop) {
                icalcomponent_remove_property(comp, prop);
                icalproperty_free(prop);
            }
            if (sequence) {
                icalcomponent_add_property(comp, icalproperty_clone(sequence));
            }
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
             prop && strcmpnull(attendee, icalproperty_get_invitee(prop));
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

    free_hash_table(&override_table, NULL);
    free_hash_table(&rdate_table, NULL);
    ptrarray_fini(&rrules);

    return attendee;
}


static int deliver_merge_request(const char *attendee,
                                 icalcomponent *ical,     // current iCalendar
                                 icalcomponent *request)  // iTIP request
{
    int deliver_inbox = 0;
    struct hash_table comp_table, *tz_table, *override_table;
    icalcomponent *tz, *comp, *itip, *master = NULL;
    icalcomponent_kind kind = ICAL_NO_COMPONENT;
    icalproperty *prop;
    icalparameter *param;
    const char *tzid, *recurid, *organizer = NULL;
    int itip_is_all_instances = 0;

    /* Add each VTIMEZONE of current object to hash table for comparison */
    tz_table = construct_hash_table(&comp_table, 10, 1);
    for (tz = icalcomponent_get_first_component(ical,
                                                ICAL_VTIMEZONE_COMPONENT);
         tz;
         tz = icalcomponent_get_next_component(ical,
                                               ICAL_VTIMEZONE_COMPONENT)) {
        prop = icalcomponent_get_first_property(tz, ICAL_TZID_PROPERTY);
        tzid = icalproperty_get_tzid(prop);
        if (!tzid) continue;

        hash_insert(tzid, tz, tz_table);
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

        tz = hash_lookup(tzid, tz_table);
        if (tz) {
            /* Remove tz from current object */
            icalcomponent_remove_component(ical, tz);
            icalcomponent_free(tz);
        }

        /* Add new/modified tz from iTIP request to current object */
        icalcomponent_add_component(ical, icalcomponent_clone(itip));
    }

    free_hash_table(tz_table, NULL);

    /* Add each override component of current object to hash table */
    override_table = construct_hash_table(&comp_table, 10, 1);
    comp = icalcomponent_get_first_real_component(ical);
    if (comp) {
        kind = icalcomponent_isa(comp);
        organizer = get_organizer(comp);
    }
    for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
        prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (prop) {
            recurid = icalproperty_get_value_as_string(prop);
            hash_insert(recurid, comp, override_table);
        }
        else {
            master = comp;
        }
    }

    /* Process each "real" component in the iTIP request */
    itip = icalcomponent_get_first_real_component(request);
    if (kind == ICAL_NO_COMPONENT) kind = icalcomponent_isa(itip);
    for (; itip; itip = icalcomponent_get_next_component(request, kind)) {
        /* Clone the new/modified component from iTIP request */
        icalcomponent *new_comp = icalcomponent_clone(itip);

        prop =
            icalcomponent_get_first_property(itip, ICAL_RECURRENCEID_PROPERTY);
        if (prop) {
            /* Lookup this iTIP comp in the hash table of current obj overrides.
               We acually remove it from the hash table because those that are
               left behind are those that may be removed from the current object
               (see end of loop). */
            recurid = icalproperty_get_value_as_string(prop);
            comp = hash_del(recurid, override_table);
        }
        else {
            comp = master;
            itip_is_all_instances = 1;
        }

        if (comp) {
            /* Component exists in current object */
            int cur_seq, new_seq;

            /* Check if this is something more than an update */
            /* XXX  Probably need to check PARTSTAT=NEEDS-ACTION
               and RSVP=TRUE as well */
            cur_seq = icalcomponent_get_sequence(comp);
            new_seq = icalcomponent_get_sequence(itip);
            if (new_seq > cur_seq) deliver_inbox = 1;
            else if (partstat_changed(comp, itip, organizer)) deliver_inbox = 1;

            /* Copy over any COMPLETED, PERCENT-COMPLETE,
               or TRANSP properties from current component to iTIP component */
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

            /* Copy over VALARMs from current component to iTIP component */
            icalcomponent *alarm;
            for (alarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
                 alarm;
                 alarm = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT)) {
                icalcomponent_add_component(new_comp, icalcomponent_clone(alarm));
            }

            /* Copy over any ORGANIZER;SCHEDULE-STATUS
               from current component to iTIP component */
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

            if (master == comp) {
                /* Use updated master component since we will remove the old */
                master = new_comp;
            }

            /* Remove component from current object */
            icalcomponent_remove_component(ical, comp);
            icalcomponent_free(comp);
        }
        else {
            /* Component does NOT exist in current object */
            deliver_inbox = 1;

            if (master) {
                /* Inherit VALARMs and TRANSP property from master */
                icalcomponent *alarm;
                for (alarm = icalcomponent_get_first_component(master, ICAL_VALARM_COMPONENT);
                     alarm;
                     alarm = icalcomponent_get_next_component(master, ICAL_VALARM_COMPONENT)) {
                    icalcomponent_add_component(new_comp, icalcomponent_clone(alarm));
                }

                prop = icalcomponent_get_first_property(master,
                                                        ICAL_TRANSP_PROPERTY);
                if (prop) {
                    icalcomponent_add_property(new_comp,
                                               icalproperty_clone(prop));
                }
            }
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

        /* Add new/modified component from iTIP request to current object */
        icalcomponent_add_component(ical, new_comp);
    }

    if (itip_is_all_instances) {
        /* Remove components of current object that are not present in the
           iTIP request (those that remain in the current comp hash table). */
        icalcomponent *next = NULL;

        for (comp = icalcomponent_get_first_real_component(ical);
             comp; comp = next) {
            next = icalcomponent_get_next_component(ical, kind);
            prop = icalcomponent_get_first_property(comp,
                                                    ICAL_RECURRENCEID_PROPERTY);
            if (!prop) continue;

            recurid = icalproperty_get_value_as_string(prop);

            if (hash_lookup(recurid, override_table)) {
                icalcomponent_remove_component(ical, comp);
                icalcomponent_free(comp);
            }
        }
    }

    free_hash_table(override_table, NULL);

    return deliver_inbox;
}


static int deliver_merge_cancel(icalcomponent *ical,    // current iCalendar
                                icalcomponent *cancel)  // iTIP cancel
{
    struct hash_table override_table;
    icalcomponent *comp, *itip, *master_comp = NULL;
    icalcomponent_kind kind = ICAL_NO_COMPONENT;
    icalproperty *prop;
    const char *recurid;
    int num_canceled = 0;

    /* Add each override component of current object to hash table */
    construct_hash_table(&override_table, 10, 1);
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);

    for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
        prop = icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (prop) {
            recurid = icalproperty_get_value_as_string(prop);
            hash_insert(recurid, comp, &override_table);
        }
        else {
            master_comp = comp;
            hash_insert("", comp, &override_table);  // needed for canceled count
        }
    }

    /* Process each component in the iTIP request */
    for (itip = icalcomponent_get_first_real_component(cancel);
         itip; itip = icalcomponent_get_next_component(cancel, kind)) {

        /* Lookup this comp in the hash table */
        prop = icalcomponent_get_first_property(itip, ICAL_RECURRENCEID_PROPERTY);
        if (prop) {
            /* Lookup this iTIP comp in the hash table of current obj overrides */
            recurid = icalproperty_get_value_as_string(prop);
            comp = hash_lookup(recurid, &override_table);

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

    /* Did we cancel all instances? */
    int ret = (num_canceled >= hash_numrecords(&override_table));

    free_hash_table(&override_table, NULL);

    return ret;
}


static int deliver_merge_add(icalcomponent *ical,  // current iCalendar
                             icalcomponent *add)   // iTIP add
{
    icalcomponent *comp, *itip, *master_comp = NULL;
    icalcomponent_kind kind = ICAL_NO_COMPONENT;
    icalproperty *prop;

    /* Find master component of current object */
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);

    for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
        prop = icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (!prop) {
            master_comp = comp;
            break;
        }
    }
    if (!master_comp) return HTTP_NOT_FOUND;

    /* Process component in the iTIP request */
    itip = icalcomponent_get_first_real_component(add);

    /* Set RDATE on master component */
    prop = icalcomponent_get_first_property(itip, ICAL_DTSTART_PROPERTY);
    icaltimetype dtstart = icalproperty_get_dtstart(prop);
    icalparameter *tzid =
        icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER);
    struct icaldurationtype duration = icalcomponent_get_duration(itip);
    struct icaldatetimeperiodtype rdate = {
        ICALTIMETYPE_INITIALIZER,
        ICALPERIODTYPE_INITIALIZER
    };

    if (!icaldurationtype_is_null_duration(duration) &&
        icaldurationtype_as_int(duration) !=
        icaldurationtype_as_int(icalcomponent_get_duration(master_comp))) {
        /* Change in event duration */
        rdate.period.start = dtstart;
        rdate.period.duration = duration;
    }
    else {
        rdate.time = dtstart;
    }

    prop = icalproperty_new_rdate(rdate);
    if (tzid) {
        icalproperty_add_parameter(prop, icalparameter_clone(tzid));
    }

    icalcomponent_add_property(master_comp, prop);

    return 0;
}


HIDDEN void itip_strip_personal_data(icalcomponent *comp)
{
    icalcomponent *alarm, *nextalarm;
    icalproperty *prop, *nextprop;

    /* Remove any VALARM components */
    for (alarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
         alarm; alarm = nextalarm) {
        nextalarm = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT);
        icalcomponent_remove_component(comp, alarm);
        icalcomponent_free(alarm);
    }

    /* Remove TRANSP, COLOR, and CATEGORIES (if color) */
    for (prop = icalcomponent_get_first_property(comp, ICAL_ANY_PROPERTY);
         prop; prop = nextprop) {
        nextprop = icalcomponent_get_next_property(comp, ICAL_ANY_PROPERTY);
        switch (icalproperty_isa(prop)) {
        case ICAL_CATEGORIES_PROPERTY:
            if (!ical_categories_is_color(prop)) break;

            GCC_FALLTHROUGH

        case ICAL_COLOR_PROPERTY:
        case ICAL_TRANSP_PROPERTY:
            icalcomponent_remove_property(comp, prop);
            icalproperty_free(prop);
            break;

        default:
            break;
        }
    }
}


/* Deliver scheduling object to local recipient */
HIDDEN enum sched_deliver_outcome sched_deliver_local(const char *userid,
                                                      const char *sender,
                                                      const char *recipient,
                                                      struct address *mailfrom,
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
    icalcomponent *oldical = NULL;
    icalcomponent *itip = icalcomponent_clone(sched_data->itip);
    icalproperty_method method;
    icalcomponent_kind kind;
    icalcomponent *comp;
    icalproperty *prop;
    enum sched_deliver_outcome result = SCHED_DELIVER_ERROR;
    strarray_t recipient_addresses = STRARRAY_INITIALIZER;

    /* Start with an empty (clean) transaction */
    struct transaction_t txn = { .userid = userid };

    strarray_append(&recipient_addresses, recipient);

    syslog(LOG_DEBUG, "sched_deliver_local(%s, %s, %X)",
           sender, recipient, sparam->flags);

    if (icalp) *icalp = NULL;
    if (attendeep) *attendeep = NULL;

    if (!strcmp(sender, recipient)) {
        /* Ignore iTIP sent from and to the same address */
        result = SCHED_DELIVER_NOACTION;
        goto done;
    }

    /* Create header cache */
    txn.req_hdrs = spool_new_hdrcache();
    if (!txn.req_hdrs) goto done;

    /* Set scheduling headers for JMAP CalendarEventNotification */
    char *sched_sender_address = NULL;
    if (mailfrom && mailfrom->mailbox)
        sched_sender_address = address_get_all(mailfrom, 0);
    if (!sched_sender_address)
        sched_sender_address = xstrdup(sender);
    spool_append_header(xstrdup("Schedule-Sender-Address"),
            sched_sender_address, txn.req_hdrs);
    if (mailfrom && mailfrom->name)
        spool_append_header(xstrdup("Schedule-Sender-Name"),
                xstrdup(mailfrom->name), txn.req_hdrs);

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
    method = icalcomponent_get_method(itip);

    comp = icalcomponent_get_first_real_component(itip);
    kind = icalcomponent_isa(comp);

    /* Strip VALARMs, TRANSP, COLOR, and CATEGORIES (if color) */
    for (; comp; comp = icalcomponent_get_next_component(itip, kind)) {
        itip_strip_personal_data(comp);
    }

    /* Search for iCal UID in recipient's calendars */
    caldavdb = caldav_open_userid(sparam->userid);
    if (!caldavdb) {
        SCHED_STATUS(sched_data, REQSTAT_TEMPFAIL, SCHEDSTAT_TEMPFAIL);
        goto done;
    }

    caldav_lookup_uid(caldavdb, icalcomponent_get_uid(itip), &cdata);

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
    else if (method == ICAL_METHOD_ADD ||
             method == ICAL_METHOD_CANCEL ||
             method == ICAL_METHOD_POLLSTATUS) {
        /* Can't find object belonging to attendee - we're done */
        SCHED_STATUS(sched_data, REQSTAT_SUCCESS, SCHEDSTAT_DELIVERED);
        result = SCHED_DELIVER_NOACTION;
        goto done;
    }
    else if (SCHED_UPDATES_ONLY(sched_data)) {
        /* Configured to NOT process invites - ignore request */
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
            char *scheddefault = caldav_scheddefault(sparam->userid, 1);
            if (scheddefault) {
                mailboxname = caldav_mboxname(sparam->userid, scheddefault);
                free(scheddefault);
            }
            else {
                xsyslog(LOG_ERR, "could not find default calendar", NULL);
                SCHED_STATUS(sched_data, REQSTAT_TEMPFAIL, SCHEDSTAT_TEMPFAIL);
                goto done;
            }
        }
        buf_reset(&resource);
        /* XXX - sanitize the uid? */
        buf_printf(&resource, "%s.ics", icalcomponent_get_uid(itip));

        /* Create new attendee object */
        ical = icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT, 0);

        /* Copy over VERSION property */
        prop = icalcomponent_get_first_property(itip, ICAL_VERSION_PROPERTY);
        icalcomponent_add_property(ical, icalproperty_clone(prop));

        /* Copy over PRODID property */
        prop = icalcomponent_get_first_property(itip, ICAL_PRODID_PROPERTY);
        icalcomponent_add_property(ical, icalproperty_clone(prop));

        /* Copy over any CALSCALE property */
        prop = icalcomponent_get_first_property(itip, ICAL_CALSCALE_PROPERTY);
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
        oldical = caldav_record_to_ical(mailbox, cdata, NULL, NULL);
        ical = icalcomponent_clone(oldical);

        for (comp = icalcomponent_get_first_component(itip, kind);
             comp;
             comp = icalcomponent_get_next_component(itip, kind)) {
            /* Don't allow component type to be changed */
            int reject = 0;
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
                    const char *organizer = icalproperty_get_organizer(prop);
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
        int all_instances = deliver_merge_cancel(ical, itip);

        if (all_instances && SCHED_DELETE_CANCELED(sched_data)) {
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

#ifdef WITH_JMAP
                if (!r) {
                    comp = icalcomponent_get_first_real_component(ical);
                    if (comp && icalcomponent_isa(comp) == ICAL_VEVENT_COMPONENT) {
                        int r2 = jmap_create_caldaveventnotif(&txn, userid, authstate,
                                mailbox_name(mailbox), icalcomponent_get_uid(itip),
                                &recipient_addresses, 0, oldical, NULL);
                        if (r2) {
                            xsyslog(LOG_ERR, "jmap_create_caldaveventnotif failed",
                                    "error=%s", error_message(r2));
                        }
                    }
                }
#endif

                mboxevent_free(&mboxevent);
            }

            if (!r) goto inbox;
        }
        break;
    }

    case ICAL_METHOD_REPLY:
        attendee = deliver_merge_reply(ical, itip);
        if (attendeep) *attendeep = attendee;
        break;

    case ICAL_METHOD_REQUEST:
        deliver_inbox = deliver_merge_request(recipient, ical, itip);
        break;

    case ICAL_METHOD_ADD:
        r = deliver_merge_add(ical, itip);
        if (r) goto inbox;
        break;

    case ICAL_METHOD_POLLSTATUS:
        deliver_inbox = deliver_merge_pollstatus(ical, itip);
        break;

    default:
        /* Unknown METHOD -- ignore it */
        syslog(LOG_ERR, "Unknown iTIP method: %s",
               icalenum_method_to_string(method));

        sched_data->flags &= ~SCHEDFLAG_IS_REPLY;
        goto inbox;
    }

    /* Use default alarms for new VEVENTs */
    if (!oldical && ical) {
        for (comp = icalcomponent_get_first_real_component(ical);
             comp;
             comp = icalcomponent_get_next_component(ical,
                 icalcomponent_isa(comp))) {

            /* Remove VALARMs that came with iTIP message */
            icalcomponent *valarm, *nextvalarm = NULL;
            for (valarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
                    valarm; valarm = nextvalarm) {
                nextvalarm =
                    icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT);
                icalcomponent_remove_component(comp, valarm);
                icalcomponent_free(valarm);
            }
        }

        icalcomponent_set_usedefaultalerts(ical);

        /* Inject default alerts as VALARMS. */
        icalcomponent *alarms_withtime =
            caldav_read_calendar_icalalarms(mailbox_name(mailbox), userid,
                    CALDAV_DEFAULTALARMS_ANNOT_WITHTIME);
        icalcomponent *alarms_withdate =
            caldav_read_calendar_icalalarms(mailbox_name(mailbox), userid,
                    CALDAV_DEFAULTALARMS_ANNOT_WITHDATE);

        icalcomponent_add_defaultalerts(ical, alarms_withtime, alarms_withdate, 1);

        if (alarms_withtime) icalcomponent_free(alarms_withtime);
        if (alarms_withdate) icalcomponent_free(alarms_withdate);
    }

    /* Set SENT-BY property */
    if (mailfrom && ical) {
        char *val = address_get_all(mailfrom, 0);

        // XXX could use SENT-BY parameter as defined in RFC5545?
        for (comp = icalcomponent_get_first_real_component(ical);
             comp;
             comp = icalcomponent_get_next_component(ical,
                 icalcomponent_isa(comp))) {

            // Remove any stale SENT-BY properties
            while ((prop = icalcomponent_get_x_property_by_name(comp,
                            JMAPICAL_XPROP_SENTBY))) {
                icalcomponent_remove_property(comp, prop);
                icalproperty_free(prop);
            }

            prop = icalproperty_new(ICAL_X_PROPERTY);
            icalproperty_set_x_name(prop, JMAPICAL_XPROP_SENTBY);
            icalproperty_set_value(prop, icalvalue_new_text(val));
            icalcomponent_add_property(comp, prop);
        }

        free(val);
    }

    /* Store the (updated) object in the recipients's calendar */
    r = caldav_store_resource(&txn, ical, mailbox,
                              buf_cstring(&resource), cdata->dav.createdmodseq,
                              caldavdb, NEW_STAG, sparam->userid,
                              NULL, NULL, &recipient_addresses);

#ifdef WITH_JMAP
    if (r == HTTP_CREATED || r == HTTP_NO_CONTENT) {
        comp = icalcomponent_get_first_real_component(ical);
        if (comp && icalcomponent_isa(comp) == ICAL_VEVENT_COMPONENT) {
            int r2 = jmap_create_caldaveventnotif(&txn, userid, authstate,
                    mailbox_name(mailbox), icalcomponent_get_uid(itip),
                    &recipient_addresses, 0, oldical, ical);
            if (r2) {
                xsyslog(LOG_ERR, "jmap_create_caldaveventnotif failed",
                        "error=%s", error_message(r2));
            }
        }
    }
#endif

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
        r = caldav_store_resource(&txn, itip, inbox,
                                  buf_cstring(&resource), 0, caldavdb, 0,
                                  NULL, NULL, NULL, NULL);
        /* XXX  What do we do if storing to Inbox fails? */
    }

  done:
    strarray_fini(&recipient_addresses);
    if (icalp) *icalp = ical;
    else if (ical) icalcomponent_free(ical);
    if (oldical) icalcomponent_free(oldical);
    if (itip) icalcomponent_free(itip);
    mailbox_close(&inbox);
    mailbox_close(&mailbox);
    if (caldavdb) caldav_close(caldavdb);
    spool_free_hdrcache(txn.req_hdrs);
    buf_free(&txn.buf);
    free(mailboxname);
    return result;
}
