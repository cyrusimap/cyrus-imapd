/* ical_support.h -- Helper functions for libical
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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

#include <string.h>

#include "caldav_db.h"
#include "ical_support.h"
#include "util.h"

#ifdef HAVE_ICAL

icalcomponent *record_to_ical(struct mailbox *mailbox,
                              const struct index_record *record)
{
    struct buf buf = BUF_INITIALIZER;
    icalcomponent *ical = NULL;

    /* Load message containing the resource and parse iCal data */
    if (!mailbox_map_record(mailbox, record, &buf)) {
        ical = icalparser_parse_string(buf_cstring(&buf) + record->header_size);
        buf_free(&buf);
    }

    return ical;
}

const char *get_icalcomponent_errstr(icalcomponent *ical)
{
    icalcomponent *comp;

    for (comp = icalcomponent_get_first_component(ical, ICAL_ANY_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_ANY_COMPONENT)) {
        icalproperty *prop;

        for (prop = icalcomponent_get_first_property(comp, ICAL_ANY_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(comp, ICAL_ANY_PROPERTY)) {

            if (icalproperty_isa(prop) == ICAL_XLICERROR_PROPERTY) {
                const char *errstr = icalproperty_get_xlicerror(prop);
                char propname[256];

                if (!errstr) return "Unknown iCal parsing error";

                /* Check if this is an empty property error */
                if (sscanf(errstr,
                           "No value for %s property", propname) == 1) {
                    /* Empty LOCATION is OK */
                    if (!strcasecmp(propname, "LOCATION")) continue;
                    if (!strcasecmp(propname, "COMMENT")) continue;
                    if (!strcasecmp(propname, "DESCRIPTION")) continue;
                }
                else {
                    /* Ignore unknown property errors */
                    if (!strncmp(errstr, "Parse error in property name", 28))
                        continue;
                }

                return errstr;
            }
        }
    }

    return NULL;
}


extern icalcomponent* icalproperty_get_parent(const icalproperty*);

void icalcomponent_remove_invitee(icalcomponent *comp, icalproperty *prop)
{
    if (icalcomponent_isa(comp) == ICAL_VPOLL_COMPONENT) {
        icalcomponent *vvoter = icalproperty_get_parent(prop);

        icalcomponent_remove_component(comp, vvoter);
        icalcomponent_free(vvoter);
    }
    else {
        icalcomponent_remove_property(comp, prop);
        icalproperty_free(prop);
    }
}


icalproperty *icalcomponent_get_first_invitee(icalcomponent *comp)
{
    icalproperty *prop;

    if (icalcomponent_isa(comp) == ICAL_VPOLL_COMPONENT) {
        icalcomponent *vvoter =
            icalcomponent_get_first_component(comp, ICAL_VVOTER_COMPONENT);

        prop = icalcomponent_get_first_property(vvoter, ICAL_VOTER_PROPERTY);
    }
    else {
        prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
    }

    return prop;
}

icalproperty *icalcomponent_get_next_invitee(icalcomponent *comp)
{
    icalproperty *prop;

    if (icalcomponent_isa(comp) == ICAL_VPOLL_COMPONENT) {
        icalcomponent *vvoter =
            icalcomponent_get_next_component(comp, ICAL_VVOTER_COMPONENT);

        prop = icalcomponent_get_first_property(vvoter, ICAL_VOTER_PROPERTY);
    }
    else {
        prop = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY);
    }

    return prop;
}

const char *icalproperty_get_invitee(icalproperty *prop)
{
    const char *recip;

    if (icalproperty_isa(prop) == ICAL_VOTER_PROPERTY) {
        recip = icalproperty_get_voter(prop);
    }
    else {
        recip = icalproperty_get_attendee(prop);
    }

    return recip;
}


#ifndef HAVE_TZDIST_PROPS

/* Functions to replace those not available in libical < v2.0 */

icalproperty *icalproperty_new_tzidaliasof(const char *v)
{
    icalproperty *prop = icalproperty_new_x(v);
    icalproperty_set_x_name(prop, "TZID-ALIAS-OF");
    return prop;
}

icalproperty *icalproperty_new_tzuntil(struct icaltimetype v)
{
    icalproperty *prop = icalproperty_new_x(icaltime_as_ical_string(v));
    icalproperty_set_x_name(prop, "TZUNTIL");
    return prop;
}

#endif /* HAVE_TZDIST_PROPS */


#ifdef HAVE_IANA_PARAMS

#ifndef HAVE_MANAGED_ATTACH_PARAMS

icalparameter* icalproperty_get_iana_parameter_by_name(icalproperty *prop,
                                                       const char *name)
{
    icalparameter *param;

    for (param = icalproperty_get_first_parameter(prop, ICAL_IANA_PARAMETER);
         param && strcmp(icalparameter_get_iana_name(param), name);
         param = icalproperty_get_next_parameter(prop, ICAL_IANA_PARAMETER));

    return param;
}

/* Functions to replace those not available in libical < v2.0 */

icalparameter *icalparameter_new_filename(const char *fname)
{
    icalparameter *param = icalparameter_new(ICAL_IANA_PARAMETER);

    icalparameter_set_iana_name(param, "FILENAME");
    icalparameter_set_iana_value(param, fname);

    return param;
}

void icalparameter_set_filename(icalparameter *param, const char *fname)
{
    icalparameter_set_iana_value(param, fname);
}

icalparameter *icalparameter_new_managedid(const char *id)
{
    icalparameter *param = icalparameter_new(ICAL_IANA_PARAMETER);

    icalparameter_set_iana_name(param, "MANAGED-ID");
    icalparameter_set_iana_value(param, id);

    return param;
}

const char *icalparameter_get_managedid(icalparameter *param)
{
    return icalparameter_get_iana_value(param);
}

void icalparameter_set_managedid(icalparameter *param, const char *id)
{
    icalparameter_set_iana_value(param, id);
}

icalparameter *icalparameter_new_size(const char *sz)
{
    icalparameter *param = icalparameter_new(ICAL_IANA_PARAMETER);

    icalparameter_set_iana_name(param, "SIZE");
    icalparameter_set_iana_value(param, sz);

    return param;
}

void icalparameter_set_size(icalparameter *param, const char *sz)
{
    icalparameter_set_iana_value(param, sz);
}

#endif /* HAVE_MANAGED_ATTACH_PARAMS */


#ifndef HAVE_SCHEDULING_PARAMS

/* Functions to replace those not available in libical < v1.0 */

icalparameter_scheduleagent
icalparameter_get_scheduleagent(icalparameter *param)
{
    const char *agent = NULL;

    if (param) agent = icalparameter_get_iana_value(param);

    if (!agent) return ICAL_SCHEDULEAGENT_NONE;
    else if (!strcmp(agent, "SERVER")) return ICAL_SCHEDULEAGENT_SERVER;
    else if (!strcmp(agent, "CLIENT")) return ICAL_SCHEDULEAGENT_CLIENT;
    else return ICAL_SCHEDULEAGENT_X;
}

icalparameter_scheduleforcesend
icalparameter_get_scheduleforcesend(icalparameter *param)
{
    const char *force = NULL;

    if (param) force = icalparameter_get_iana_value(param);

    if (!force) return ICAL_SCHEDULEFORCESEND_NONE;
    else if (!strcmp(force, "REQUEST")) return ICAL_SCHEDULEFORCESEND_REQUEST;
    else if (!strcmp(force, "REPLY")) return ICAL_SCHEDULEFORCESEND_REPLY;
    else return ICAL_SCHEDULEFORCESEND_X;
}

icalparameter *icalparameter_new_schedulestatus(const char *stat)
{
    icalparameter *param = icalparameter_new(ICAL_IANA_PARAMETER);

    icalparameter_set_iana_name(param, "SCHEDULE-STATUS");
    icalparameter_set_iana_value(param, stat);

    return param;
}

#endif /* HAVE_SCHEDULING_PARAMS */

#endif /* HAVE_IANA_PARAMS */

#endif /* HAVE_ICAL */
