/* guesstz.c - guess IANA timezone names from VTIMEZONE components */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include <jansson.h>
#include <libical/ical.h>

#include "guesstz.h"

/*
 *  A guesstz database file is formatted as follows:
 *
 *   magic: <cstring 'guesstz', including zero>
 *     The file magic that identifies this file as guesstz database.
 *
 *   version: <uint8_t>
 *     The database version.
 *
 *   bom: <2*uint8_t>
 *     The uint16 value 0xFEFF encoded in database endianess.
 *
 *   created_at: <int64_t>
 *     The datetime this database was created at, in UNIX epoch time.
 *
 *   timerange:
 *     The time range in which timezone observances are expanded.
 *     trstart: <int64_t>
 *       The start of the time range in UNIX epoch time.
 *     trend: <int64_t>
 *       The end of the time range in UNIX epoch time.
 *
 *   ianaversion: <cstring, including zero>
 *     The IANA timezone database version.
 *
 *   tzoffsets_cnt: <uint32_t>
 *     The number of timezone offset records.
 *
 *   tzoffsets:
 *     The timezone offsets records.
 *     tzoffsets_cnt offset records, sorted ascending by offset:
 *       offset: int32_t
 *         The UTC offset.
 *       tzidx: uint64_t
 *         The byte index of the timezone, relative to the timezones field.
 *
 *   preftzs:
 *     The preferred timezones. If a preferred timezone is a match during
 *     timezone name guessing, then prefer this timezone over other matches.
 *
 *     preftzs_cnt: <uint16_t>
 *       The number of preferred timezones.
 *
 *     preftzs_cnt preferred timezone records, sorted ascending by tzidx:
 *       tzidx: uint64_t
 *         The byte index of the timezone, relative to the timezones field.
 *
 *   timezones:
 *     zero or more timezone records, in no particular order, terminated
 *     by a single zero byte.
 *       tzid: <cstring, including zero>
 *         The timezone identifier of the timezone.
 *       observances_cnt: <uint32_t>
 *         The number of observance records.
 *       observances_cnt observance records, sorted ascending by onset:
 *         onset: <int64_t>
 *           The onset time of the observance, in UNIX epoch time.
 *         offset: <int32_t>
 *           The UTC offset of the observance in seconds.
 *
 */

/* The records of the database are packed, so a field of one is only as
 * aligned as wherever the record happens to start.  Read every multi-byte
 * field through these, rather than by dereferencing a cast pointer. */
#define DEFINE_LOAD(type)                                                     \
    static inline type load_##type(const void *p)                             \
    {                                                                         \
        type v;                                                               \
        memcpy(&v, p, sizeof(v));                                             \
        return v;                                                             \
    }

DEFINE_LOAD(uint16_t)
DEFINE_LOAD(uint32_t)
DEFINE_LOAD(uint64_t)
DEFINE_LOAD(int32_t)
DEFINE_LOAD(int64_t)

#undef DEFINE_LOAD

struct observances {
    uint32_t count;
    const void *data;
    uint8_t *alloc;
};

#define OBSERVANCE_SIZE (sizeof(int64_t) + sizeof(int32_t))

struct tzoffsets {
    uint32_t count;
    const void *data;
};

#define TZOFFSET_SIZE (sizeof(int32_t) + sizeof(uint64_t))

struct preftzs {
    uint16_t count;
    const uint8_t *tzidxs;
};

#define PREFTZ_SIZE (sizeof(uint64_t))

struct guesstz_tz {
    const char *tzid;
    struct observances obs;
    uint64_t idx;
    char *alloc;
};

struct db {
    uint8_t version;
    time_t created_at;
    uint8_t bom[2];
    icaltimetype trstart;
    icaltimetype trend;
    const char *ianaversion;
    struct tzoffsets tzoffsets;
    struct preftzs preftzs;
    const uint8_t *timezones;
};

static uint8_t db_version = 1;

static const char *db_magic = "guesstz";

static uint16_t db_bom = 0xfeff;


struct observance {
    int64_t onset;
    int32_t offset;
};

struct tzoffset {
    int32_t offset;
    uint64_t tzidx;
};

/* A hand-curated list of timezones that follow the typical
 * pattern of shifting daylight savings time one hour from
 * standard time. One for (almost) every offset hour */
static const char *preferred_tzids[] = {
    "America/Adak",
    "America/Anchorage",
    "America/Los_Angeles",
    "America/Denver",
    "America/New_York",
    "America/Puerto_Rico",
    "America/Nuuk",
    "Atlantic/Azores",
    "Europe/London",
    "Europe/Berlin",
    "Europe/Athens",
    "Indian/Mauritius",
    "Asia/Dhaka",
    "Australia/Melbourne",
    "Pacific/Norfolk",
    NULL
};

struct icalobservance {
    icaltimetype onset;
    int offset_from;
    int offset_to;
    int is_daylight;
    int is_std;
    int is_gmt;
};

struct rdate {
    icalproperty *prop;
    struct icaldatetimeperiodtype date;
};

static void icaltime_set_utc(struct icaltimetype *t, int set)
{
    icaltime_set_timezone(t, set ? icaltimezone_get_utc_timezone() : NULL);
}

static void get_isstd_isgmt(icalproperty *prop,
                                         struct icalobservance *obs)
{
    const char *time_type =
        icalproperty_get_parameter_as_string(prop, "X-OBSERVED-AT");

    if (!time_type) time_type = "W";

    switch (time_type[0]) {
    case 'G': case 'g':
    case 'U': case 'u':
    case 'Z': case 'z':
        obs->is_gmt = obs->is_std = 1;
        break;
    case 'S': case 's':
        obs->is_gmt = 0;
        obs->is_std = 1;
        break;
    case 'W': case 'w':
    default:
        obs->is_gmt = obs->is_std = 0;
        break;
    }
}

static void check_tombstone(struct icalobservance *tombstone,
                            struct icalobservance *obs)
{
    if (icaltime_compare(obs->onset, tombstone->onset) > 0) {
        /* onset is closer to cutoff than existing tombstone */
        tombstone->offset_from = tombstone->offset_to = obs->offset_to;
        tombstone->is_daylight = obs->is_daylight;
        tombstone->onset = obs->onset;
    }
}

static int rdate_compare(const void *rdate1, const void *rdate2)
{
    return icaltime_compare(((struct rdate *) rdate1)->date.time,
                            ((struct rdate *) rdate2)->date.time);
}

static int observance_compare(const void *obs1, const void *obs2)
{
    return icaltime_compare(((struct icalobservance *) obs1)->onset,
                            ((struct icalobservance *) obs2)->onset);
}

static void expand_icalobservances(icalcomponent *vtz,
                                   icaltimetype start, icaltimetype end,
                                   icalarray *obsarray,
                                   struct icalobservance **proleptic)
{
    icalcomponent *comp, *nextc, *tomb_std = NULL, *tomb_day = NULL;
    icalproperty *prop, *proleptic_prop = NULL;
    struct icalobservance tombstone;
    unsigned need_tomb = !icaltime_is_null_time(start);

    // Create local copy so we can rewrite its contents
    vtz = icalcomponent_clone(vtz);

    /* See if we have a proleptic tzname in VTIMEZONE */
    for (prop = icalcomponent_get_first_property(vtz, ICAL_X_PROPERTY);
         prop;
         prop = icalcomponent_get_next_property(vtz, ICAL_X_PROPERTY)) {
        if (!strcmp("X-PROLEPTIC-TZNAME", icalproperty_get_x_name(prop))) {
            proleptic_prop = prop;
            break;
        }
    }

    memset(&tombstone, 0, sizeof(struct icalobservance));
    if (!proleptic_prop ||
        !icalproperty_get_parameter_as_string(prop, "X-NO-BIG-BANG"))
      tombstone.onset.year = -1;

    /* Process each VTMEZONE STANDARD/DAYLIGHT subcomponent */
    for (comp = icalcomponent_get_first_component(vtz, ICAL_ANY_COMPONENT);
         comp; comp = nextc) {
        icalproperty *dtstart_prop = NULL, *rrule_prop = NULL;
        icalarray *rdate_array = icalarray_new(sizeof(struct rdate), 10);
        icaltimetype dtstart;
        struct icalobservance obs;
        unsigned n, trunc_dtstart = 0;
        int r;

        nextc = icalcomponent_get_next_component(vtz, ICAL_ANY_COMPONENT);

        memset(&obs, 0, sizeof(struct icalobservance));
        obs.offset_from = obs.offset_to = INT_MAX;
        obs.is_daylight = (icalcomponent_isa(comp) == ICAL_XDAYLIGHT_COMPONENT);

        /* Grab the properties that we require to expand recurrences */
        for (prop = icalcomponent_get_first_property(comp, ICAL_ANY_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(comp, ICAL_ANY_PROPERTY)) {

            switch (icalproperty_isa(prop)) {
            case ICAL_DTSTART_PROPERTY:
                dtstart_prop = prop;
                obs.onset = dtstart = icalproperty_get_dtstart(prop);
                get_isstd_isgmt(prop, &obs);
                break;

            case ICAL_TZOFFSETFROM_PROPERTY:
                obs.offset_from = icalproperty_get_tzoffsetfrom(prop);
                break;

            case ICAL_TZOFFSETTO_PROPERTY:
                obs.offset_to = icalproperty_get_tzoffsetto(prop);
                break;

            case ICAL_RRULE_PROPERTY:
                rrule_prop = prop;
                break;

            case ICAL_RDATE_PROPERTY: {
                struct rdate rdate = { prop, icalproperty_get_rdate(prop) };

                icalarray_append(rdate_array, &rdate);
                break;
            }

            default:
                /* ignore all other properties */
                break;
            }
        }

        /* We MUST have DTSTART, TZNAME, TZOFFSETFROM, and TZOFFSETTO */
        if (!dtstart_prop ||
            obs.offset_from == INT_MAX || obs.offset_to == INT_MAX) {
            icalarray_free(rdate_array);
            continue;
        }

        /* Adjust DTSTART observance to UTC */
        icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
        icaltime_set_utc(&obs.onset, 1);

        /* Check DTSTART vs window close */
        if (!icaltime_is_null_time(end) &&
            icaltime_compare(obs.onset, end) >= 0) {
            /* All observances occur on/after window close - remove component */
            icalcomponent_remove_component(vtz, comp);
            icalcomponent_free(comp);

            /* Nothing else to do */
            icalarray_free(rdate_array);
            continue;
        }

        /* Check DTSTART vs window open */
        r = icaltime_compare(obs.onset, start);
        if (r < 0) {
            /* DTSTART is prior to our window open - check it vs tombstone */
            if (need_tomb) check_tombstone(&tombstone, &obs);

            /* Adjust it */
            trunc_dtstart = 1;

        }
        else {
            /* DTSTART is on/after our window open */
            if (r == 0) need_tomb = 0;

            if (obsarray && !rrule_prop) {
                /* Add the DTSTART observance to our array */
                icalarray_append(obsarray, &obs);
            }
        }

        if (rrule_prop) {
            struct icalrecurrencetype *rrule =
                icalproperty_get_rrule(rrule_prop);
            icalrecur_iterator *ritr = NULL;
            unsigned eternal = icaltime_is_null_time(rrule->until);
            unsigned trunc_until = 0;

            /* Check RRULE duration */
            if (!eternal && icaltime_compare(rrule->until, start) < 0) {
                /* RRULE ends prior to our window open -
                   check UNTIL vs tombstone */
                obs.onset = rrule->until;
                if (need_tomb) check_tombstone(&tombstone, &obs);

                /* Remove RRULE */
                icalcomponent_remove_property(comp, rrule_prop);
                icalproperty_free(rrule_prop);
            }
            else {
                /* RRULE ends on/after our window open */
                if (!icaltime_is_null_time(end) &&
                    (eternal || icaltime_compare(rrule->until, end) >= 0)) {
                    /* RRULE ends after our window close - need to adjust it */
                    trunc_until = 1;
                }

                if (!eternal) {
                    /* Adjust UNTIL to local time (for iterator) */
                    icaltime_adjust(&rrule->until, 0, 0, 0, obs.offset_from);
                    icaltime_set_utc(&rrule->until, 0);
                }

                if (trunc_dtstart) {
                    /* Bump RRULE start to 1 year prior to our window open */
                    dtstart.year = start.year - 1;
                    dtstart.month = start.month;
                    dtstart.day = start.day;
                    icaltime_normalize(dtstart);
                }

                ritr = icalrecur_iterator_new(rrule, dtstart);
            }

            /* Process any RRULE observances within our window */
            if (ritr) {
                icaltimetype recur, prev_onset;

                /* Mark original DTSTART (UTC) */
                dtstart = obs.onset;

                while (!icaltime_is_null_time(obs.onset = recur =
                                              icalrecur_iterator_next(ritr))) {
                    unsigned ydiff;

                    /* Adjust observance to UTC */
                    icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
                    icaltime_set_utc(&obs.onset, 1);

                    if (trunc_until && icaltime_compare(obs.onset, end) >= 0) {
                        /* Observance is on/after window close */

                        /* Check if DSTART is within 1yr of prev onset */
                        ydiff = prev_onset.year - dtstart.year;
                        if (ydiff <= 1) {
                            /* Remove RRULE */
                            icalcomponent_remove_property(comp, rrule_prop);
                            icalproperty_free(rrule_prop);

                            if (ydiff) {
                                /* Add previous onset as RDATE */
                                struct icaldatetimeperiodtype rdate = {
                                    prev_onset,
                                    icalperiodtype_null_period()
                                };
                                prop = icalproperty_new_rdate(rdate);
                                icalcomponent_add_property(comp, prop);
                            }
                        }
                        else if (!eternal) {
                            /* Set UNTIL to previous onset */
                            rrule->until = prev_onset;
                            icalproperty_set_rrule(rrule_prop, rrule);
                        }

                        /* We're done */
                        break;
                    }

                    /* Check observance vs our window open */
                    r = icaltime_compare(obs.onset, start);
                    if (r < 0) {
                        /* Observance is prior to our window open -
                           check it vs tombstone */
                        if (need_tomb) check_tombstone(&tombstone, &obs);
                    }
                    else {
                        /* Observance is on/after our window open */
                        if (r == 0) need_tomb = 0;

                        if (trunc_dtstart) {
                            /* Make this observance the new DTSTART */
                            icalproperty_set_dtstart(dtstart_prop, recur);
                            dtstart = obs.onset;
                            trunc_dtstart = 0;

                            /* Check if new DSTART is within 1yr of UNTIL */
                            ydiff = rrule->until.year - recur.year;
                            if (!trunc_until && ydiff <= 1) {
                                /* Remove RRULE */
                                icalcomponent_remove_property(comp, rrule_prop);
                                icalproperty_free(rrule_prop);

                                if (ydiff) {
                                    /* Add UNTIL as RDATE */
                                    struct icaldatetimeperiodtype rdate = {
                                        rrule->until,
                                        icalperiodtype_null_period()
                                    };
                                    prop = icalproperty_new_rdate(rdate);
                                    icalcomponent_add_property(comp, prop);
                                }
                            }
                        }

                        if (obsarray) {
                            /* Add the observance to our array */
                            icalarray_append(obsarray, &obs);
                        }
                        else if (!trunc_until) {
                            /* We're done */
                            break;
                        }
                    }
                    prev_onset = obs.onset;
                }
                icalrecur_iterator_free(ritr);
            }
        }

        /* Sort the RDATEs by onset */
        icalarray_sort(rdate_array, &rdate_compare);

        /* Check RDATEs */
        for (n = 0; n < rdate_array->num_elements; n++) {
            struct rdate *rdate = icalarray_element_at(rdate_array, n);

            if (n == 0 && icaltime_compare(rdate->date.time, dtstart) == 0) {
                /* RDATE is same as DTSTART - remove it */
                icalcomponent_remove_property(comp, rdate->prop);
                icalproperty_free(rdate->prop);
                continue;
            }

            obs.onset = rdate->date.time;
            get_isstd_isgmt(rdate->prop, &obs);

            /* Adjust observance to UTC */
            icaltime_adjust(&obs.onset, 0, 0, 0, -obs.offset_from);
            icaltime_set_utc(&obs.onset, 1);

            if (!icaltime_is_null_time(end) &&
                icaltime_compare(obs.onset, end) >= 0) {
                /* RDATE is after our window close - remove it */
                icalcomponent_remove_property(comp, rdate->prop);
                icalproperty_free(rdate->prop);

                continue;
            }

            r = icaltime_compare(obs.onset, start);
            if (r < 0) {
                /* RDATE is prior to window open - check it vs tombstone */
                if (need_tomb) check_tombstone(&tombstone, &obs);

                /* Remove it */
                icalcomponent_remove_property(comp, rdate->prop);
                icalproperty_free(rdate->prop);
            }
            else {
                /* RDATE is on/after our window open */
                if (r == 0) need_tomb = 0;

                if (trunc_dtstart) {
                    /* Make this RDATE the new DTSTART */
                    icalproperty_set_dtstart(dtstart_prop,
                                             rdate->date.time);
                    trunc_dtstart = 0;

                    icalcomponent_remove_property(comp, rdate->prop);
                    icalproperty_free(rdate->prop);
                }

                if (obsarray) {
                    /* Add the observance to our array */
                    icalarray_append(obsarray, &obs);
                }
            }
        }
        icalarray_free(rdate_array);

        /* Final check */
        if (trunc_dtstart) {
            /* All observances in comp occur prior to window open, remove it
               unless we haven't saved a tombstone comp of this type yet */
            if (icalcomponent_isa(comp) == ICAL_XDAYLIGHT_COMPONENT) {
                if (!tomb_day) {
                    tomb_day = comp;
                    comp = NULL;
                }
            }
            else if (!tomb_std) {
                tomb_std = comp;
                comp = NULL;
            }

            if (comp) {
                icalcomponent_remove_component(vtz, comp);
                icalcomponent_free(comp);
            }
        }
    }

    if (need_tomb && !icaltime_is_null_time(tombstone.onset)) {
        /* Need to add tombstone component/observance starting at window open
           as long as its not prior to start of TZ data */
        icalcomponent *tomb;
        icalproperty *prop, *nextp;

        if (obsarray) {
            /* Add the tombstone to our array */
            tombstone.onset = start;
            tombstone.is_gmt = tombstone.is_std = 1;
            icalarray_append(obsarray, &tombstone);
        }

        /* Determine which tombstone component we need */
        if (tombstone.is_daylight) {
            tomb = tomb_day;
            tomb_day = NULL;
        }
        else {
            tomb = tomb_std;
            tomb_std = NULL;
        }

        /* Set property values on our tombstone */
        for (prop = icalcomponent_get_first_property(tomb, ICAL_ANY_PROPERTY);
             prop; prop = nextp) {

            nextp = icalcomponent_get_next_property(tomb, ICAL_ANY_PROPERTY);

            switch (icalproperty_isa(prop)) {
            case ICAL_TZOFFSETFROM_PROPERTY:
                icalproperty_set_tzoffsetfrom(prop, tombstone.offset_from);
                break;
            case ICAL_TZOFFSETTO_PROPERTY:
                icalproperty_set_tzoffsetto(prop, tombstone.offset_to);
                break;
            case ICAL_DTSTART_PROPERTY:
                /* Adjust window open to local time */
                icaltime_adjust(&start, 0, 0, 0, tombstone.offset_from);
                icaltime_set_utc(&start, 0);

                icalproperty_set_dtstart(prop, start);
                break;
            default:
                icalcomponent_remove_property(tomb, prop);
                icalproperty_free(prop);
                break;
            }
        }

        /* Remove X-PROLEPTIC-TZNAME as it no longer applies */
        if (proleptic_prop) {
            icalcomponent_remove_property(vtz, proleptic_prop);
            icalproperty_free(proleptic_prop);
        }
    }

    /* Remove any unused tombstone components */
    if (tomb_std) {
        icalcomponent_remove_component(vtz, tomb_std);
        icalcomponent_free(tomb_std);
    }
    if (tomb_day) {
        icalcomponent_remove_component(vtz, tomb_day);
        icalcomponent_free(tomb_day);
    }

    if (obsarray && obsarray->num_elements) {
        struct icalobservance *obs;

        /* Sort the observances by onset */
        icalarray_sort(obsarray, &observance_compare);

        /* Set offset_to for tombstone, if necessary */
        obs = icalarray_element_at(obsarray, 0);
        if (!tombstone.offset_to) tombstone.offset_to = obs->offset_from;
    }

    if (proleptic) *proleptic = &tombstone;

    icalcomponent_free(vtz);
}

static int is_preferred_tzid(const char *tzid)
{
    const char **p;
    for (p = preferred_tzids; *p; p++) {
        if (!strcmp(tzid, *p)) return 1;
    }
    return 0;
}

#define OFFSETSTR_MAX 8

static int format_offset(int32_t offset, char *buffer)
{
    char sign = '+';
    if (offset < 0) {
        offset = -offset;
        sign = '-';
    }

    int hours = offset / 3600;
    int minutes = (offset % 3600) / 60;
    int seconds = offset % 60;

    if (hours > 23 || minutes > 59 || seconds > 59) {
        return 0;
    }

    snprintf(buffer, 8, "%c%02i%02i", sign, hours, minutes);
    if (seconds) {
        snprintf(buffer + 5, 3, "%02i", seconds);
    }

    return strlen(buffer);
}


static void observances_from_ical(struct observances *obs, icalarray *icalobs)
{
    obs->count = (uint32_t) icalobs->num_elements;
    obs->alloc = malloc(obs->count * OBSERVANCE_SIZE);
    obs->data = obs->alloc;

    const icaltimezone *utc = icaltimezone_get_utc_timezone();

    uint8_t *p = obs->alloc;
    size_t i;
    for (i = 0; i < obs->count; i++) {
        struct icalobservance *icalob = icalarray_element_at(icalobs, i);

        int64_t onset = icaltime_as_timet_with_zone(icalob->onset, utc);
        memcpy(p, &onset, sizeof(int64_t));
        p += 8;

        int32_t offset = icalob->offset_to;
        memcpy(p, &offset, sizeof(int32_t));
        p += 4;
    }
}

static struct observance observances_nth(struct observances *obs, uint32_t i)
{
    struct observance ob;

    const uint8_t *d = obs->data + i * OBSERVANCE_SIZE;
    ob.onset = load_int64_t(d);
    d += 8;
    ob.offset = load_int32_t(d);
    d += 4;

    return ob;
}

static struct tzoffset tzoffsets_nth(struct tzoffsets *tzoffs, uint32_t i)
{
    struct tzoffset tzoff;

    const uint8_t *d = tzoffs->data + i * TZOFFSET_SIZE;
    tzoff.offset = load_int32_t(d);
    d += 4;
    tzoff.tzidx = load_uint64_t(d);
    d += 8;

    return tzoff;
}

static ssize_t tzoffsets_first(struct tzoffsets *tzoffs, int32_t offset)
{
    ssize_t i;
    for (i = 0; i < tzoffs->count; i++) {
        struct tzoffset tzoff = tzoffsets_nth(tzoffs, i);
        if (tzoff.offset == offset) {
            return i;
        }
    }
    return -1;
}

static struct guesstz_tz timezones_idx(const uint8_t *timezones, uint64_t idx)
{
    struct guesstz_tz tz;

    const uint8_t *t = timezones + idx;
    tz.tzid = (char*) t;
    t += strlen(tz.tzid) + 1;
    tz.obs.count = load_uint32_t(t);
    t += 4;
    tz.obs.data = t;
    tz.idx = idx;

    return tz;
}

static void truncate_obs(struct observances *obs, int64_t onset)
{
    ssize_t i;
    struct observance ob;
    for (i = 0; i < obs->count; i++) {
        ob = observances_nth(obs, i);
        if (ob.onset >= onset) {
            break;
        }
    }
    if (i == obs->count) {
        obs->count = 0;
        return;
    }
    if (ob.onset > onset) {
        if (i == 0) {
            obs->count = 0;
            return;
        }
        else i--;
    }

    obs->data += i * OBSERVANCE_SIZE;
    obs->count = obs->count - i + 1;
}

static int is_preferred_tzidx(struct db *db, uint64_t idx)
{
    uint16_t i;
    for (i = 0; i < db->preftzs.count; i++) {
        if (idx == load_uint64_t(db->preftzs.tzidxs + i * PREFTZ_SIZE))
            return 1;
    }
    return 0;
}

static char *guess_timezone(struct db *db,
                            icalcomponent *vtz,
                            icaltimetype trstart,
                            icaltimetype trend)
{
    struct observances obs = { 0 };
    char *tzid = NULL;

    /* Limit expansion span to database time span */
    if ((icaltime_is_null_time(trend)) ||
         icaltime_compare(trend, db->trend) > 0) {
        trend = db->trend;
    }

    /* Generate observances */
    icalarray *icalobs = icalarray_new(sizeof(struct icalobservance), 20);
    expand_icalobservances(vtz, trstart, trend, icalobs, NULL);
    observances_from_ical(&obs, icalobs);
    icalarray_free(icalobs);
    if (!obs.count) goto done;

    /* Attempt to convert to Etc/GMT+X timezone */
    struct observance firstob = observances_nth(&obs, 0);
    if (obs.count == 1 && ((firstob.offset % (60*60)) == 0)) {
        if (icalcomponent_get_first_component(vtz, ICAL_XSTANDARD_COMPONENT) &&
            !icalcomponent_get_next_component(vtz, ICAL_XSTANDARD_COMPONENT) &&
            !icalcomponent_get_first_component(vtz, ICAL_XDAYLIGHT_COMPONENT)) {

            int32_t hh = firstob.offset / (60*60);
            if (-14 <= hh && hh <= 12) {
                char buf[11];
                snprintf(buf, 11, "Etc/GMT%+d", -hh);
                buf[10] = '\0';
                tzid = strdup(buf);
                goto done;
            }
        }
    }

    /* Lookup all timezones that have the same offset */
    ssize_t i = tzoffsets_first(&db->tzoffsets, firstob.offset);
    if (i < 0) goto done;

    for ( ; i < db->tzoffsets.count; i++) {
        struct tzoffset tzoff = tzoffsets_nth(&db->tzoffsets, i);
        if (tzoff.offset != firstob.offset) {
            break;
        }

        struct guesstz_tz dbtz = timezones_idx(db->timezones, tzoff.tzidx);
        struct observances *dbobs = &dbtz.obs;

        /* Truncate observances to start at or just before onset */
        truncate_obs(dbobs, firstob.onset);
        if (dbobs->count < obs.count) {
            continue;
        }

        /* Start offsets must match */
        struct observance dbob = observances_nth(dbobs, 0);
        if (dbob.offset != firstob.offset) {
            continue;
        }

        /* Compare remaining obervances */
        if (dbobs->count > 1 && obs.count > 1) {
            size_t cmplen = obs.count < dbobs->count ?
                obs.count - 1 : dbobs->count - 1;
            if (memcmp(obs.data + OBSERVANCE_SIZE,
                       dbobs->data + OBSERVANCE_SIZE, cmplen)) {
                continue;
            }
        }

        /* Found a match! */
        free(tzid);
        tzid = strdup(dbtz.tzid);

        /* Stop if this is a preferred timezone */
        if (is_preferred_tzidx(db, dbtz.idx)) {
            break;
        }
    }

done:
    if (obs.count) {
        free(obs.alloc);
    }
    return tzid;
}

static int compare_tzoffset(const void *va, const void *vb)
{
    int32_t offseta = load_int32_t(va);
    int32_t offsetb = load_int32_t(vb);

    if (offseta < offsetb)
        return -1;
    else if (offseta > offsetb)
        return 1;

    uint64_t tzidxa = load_uint64_t((const uint8_t *)va + 4);
    uint64_t tzidxb = load_uint64_t((const uint8_t *)vb + 4);
    if (tzidxa < tzidxb)
        return -1;
    else if (tzidxa > tzidxb)
        return 1;
    else
        return 0;
}

static int compare_uint64(const void *va, const void *vb)
{
    uint64_t a = load_uint64_t(va);
    uint64_t b = load_uint64_t(vb);

    if (a < b)
        return -1;
    else if (a > b)
        return 1;
    else
        return 0;
}

static int write_header(icaltimetype trstart, icaltimetype trend,
                        const char *iana_version,
                        FILE *fp)
{
    const icaltimezone *utc = icaltimezone_get_utc_timezone();
    int64_t created = (int64_t) time(NULL);
    int64_t ttrstart = icaltime_as_timet_with_zone(trstart, utc);
    int64_t ttrend = icaltime_as_timet_with_zone(trend, utc);

    fputs(db_magic, fp);
    fputc(0, fp);
    fputc(db_version, fp);
    fwrite(&db_bom, sizeof(uint16_t), 1, fp);
    fwrite(&created, sizeof(int64_t), 1, fp);
    fwrite(&ttrstart, sizeof(int64_t), 1, fp);
    fwrite(&ttrend, sizeof(int64_t), 1, fp);
    fputs(iana_version, fp);
    fputc(0, fp);

    return 0;
}

static int write_tzoffsets(icalarray *tzoffsets, FILE *fp)
{
    uint32_t tzoffsets_cnt = tzoffsets->num_elements;

    fwrite(&tzoffsets_cnt, sizeof(uint32_t), 1, fp);
    size_t i;
    for (i = 0; i < tzoffsets->num_elements; i++) {
        fwrite(icalarray_element_at(tzoffsets, i), TZOFFSET_SIZE, 1, fp);
    }

    return 0;
}

static int write_preftzs(icalarray *timezones, FILE *fp)
{
    icalarray *preftzs = icalarray_new(sizeof(uint64_t), 20);

    size_t i;
    for (i = 0; i < timezones->num_elements; i++) {
        struct guesstz_tz *tz = icalarray_element_at(timezones, i);
        if (is_preferred_tzid(tz->tzid)) {
            icalarray_append(preftzs, &tz->idx);
        }
    }
    icalarray_sort(preftzs, compare_uint64);

    uint16_t cnt = preftzs->num_elements;
    fwrite(&cnt, sizeof(uint16_t), 1, fp);

    for (i = 0; i < cnt; i++) {
        uint64_t *tzidx = icalarray_element_at(preftzs, i);
        fwrite(tzidx, sizeof(uint64_t), 1, fp);
    }

    icalarray_free(preftzs);

    return 0;
}

static int write_timezones(icalarray *timezones, FILE *fp)
{
    size_t i;
    for (i = 0; i < timezones->num_elements; i++) {
        struct guesstz_tz *tz = icalarray_element_at(timezones, i);
        fputs(tz->tzid, fp);
        fputc(0, fp);
        fwrite(&tz->obs.count, sizeof(uint32_t), 1, fp);
        fwrite(tz->obs.data, OBSERVANCE_SIZE, tz->obs.count, fp);
    }

    fputc(0, fp);

    return 0;
}

static char *ianaversion_from_zonedir(const char *zoneinfo_dir)
{
    char *ianaversion = NULL;
    char *fname = malloc(strlen(zoneinfo_dir) + 9);
    fname[0] = '\0';
    strcat(fname, zoneinfo_dir);
    strcat(fname, "/version");
    FILE *fp = fopen(fname, "r");

    if (fp) {
        char version[32];
        size_t n = fread(version, 1, 32, fp);
        if (n > 1) {
            version[n-1] = '\0';
            ianaversion = strdup(version);
        }
        fclose(fp);
    }
    if (!ianaversion) {
        ianaversion = strdup("unknown");
    }

    free(fname);
    return ianaversion;
}


static char *read_line(char *s, size_t size, void *fp)
{
    return fgets(s, (int)size, (FILE *)fp);
}

static icalcomponent *read_vcalendar(FILE *fp)
{
    icalcomponent *comp = NULL;
    icalparser *parser = icalparser_new();
    icalparser_set_gen_data(parser, fp);

    char *line;
    do {
        line = icalparser_get_line(parser, read_line);
        comp = icalparser_add_line(parser, line);
        /* icalparser_add_line does not take ownership of the line */
        if (line) icalmemory_free_buffer(line);
    } while (line && !comp);

    icalparser_free(parser);
    return comp;
}

static void add_vtimezone(icalarray *timezones, icalcomponent *vtz,
                          icaltimetype trstart, icaltimetype trend,
                          icalarray *tzoffsets)
{
    icalproperty *prop = icalcomponent_get_first_property(vtz, ICAL_TZID_PROPERTY);
    if (!prop) return;

    const char *tzid = icalproperty_get_tzid(prop);
    if (!tzid) return;

    icalarray *icalobs = icalarray_new(sizeof(struct icalobservance), 20);
    expand_icalobservances(vtz, trstart, trend, icalobs, NULL);

    if (icalobs->num_elements) {
        /* Initialize timezone */
        struct guesstz_tz tz = { 0 };
        tz.tzid = tz.alloc = strdup(tzid);
        observances_from_ical(&tz.obs, icalobs);

        /* Calculate timezone byte index */
        if (timezones->num_elements) {
            struct guesstz_tz *prev =
                icalarray_element_at(timezones, timezones->num_elements - 1);
            uint64_t prev_size = strlen(prev->tzid) + 1 + sizeof(uint32_t) +
                prev->obs.count * OBSERVANCE_SIZE;
            tz.idx = prev->idx + prev_size;
        }

        /* Deduplicate UTC offsets of this timezone */
        icalarray *uniqoffsets = icalarray_new(sizeof(int32_t), 20);
        size_t i;
        for (i = 0; i < icalobs->num_elements; i++) {
            struct icalobservance *icalob = icalarray_element_at(icalobs, i);
            int32_t offset = icalob->offset_to;

            int is_uniq = 1;
            size_t j;
            for (j = 0; j < uniqoffsets->num_elements; j++) {
                int32_t *val = icalarray_element_at(uniqoffsets, j);
                if (*val == offset) {
                    is_uniq = 0;
                    break;
                }
            }
            if (is_uniq) {
                icalarray_append(uniqoffsets, &offset);
            }
        }

        /* Add this timezone's unique UTC offsets to lookup table */
        uint8_t tzoffbuf[TZOFFSET_SIZE];
        memcpy(tzoffbuf + sizeof(int32_t), &tz.idx, sizeof(uint64_t));
        for (i = 0; i < uniqoffsets->num_elements; i++) {
            int32_t *val = icalarray_element_at(uniqoffsets, i);
            memcpy(tzoffbuf, val, sizeof(int32_t));
            icalarray_append(tzoffsets, tzoffbuf);
        }

        icalarray_append(timezones, &tz);
        icalarray_free(uniqoffsets);
    }

    icalarray_free(icalobs);
}

EXPORTED int guesstz_create(const char *zoneinfo_dir,
                   icaltimetype trstart, icaltimetype trend,
                   FILE *fp)
{
    char *paths[2] = { (char *) zoneinfo_dir, NULL };
    FTS *fts = fts_open(paths, 0, NULL);
    if (!fts) {
        fprintf(stderr, "fts_open(%s): %s\n", zoneinfo_dir, strerror(errno));
        return EX_IOERR;
    }

    icalarray *timezones = icalarray_new(sizeof(struct guesstz_tz), 20);
    icalarray *tzoffsets = icalarray_new(TZOFFSET_SIZE, 20);

    /* Process VTIMEZONEs */
    FTSENT *fe;
    while ((fe = fts_read(fts))) {
        if (fe->fts_info != FTS_F && fe->fts_info != FTS_SL) {
            continue;
        }
        /* Only look at VTIMEZONEs.  A zoneinfo directory also holds the IANA
         * version, vzic's zone tables and, once built, our own database. */
        if (fe->fts_namelen < 4 ||
            strcmp(fe->fts_name + fe->fts_namelen - 4, ".ics")) {
            continue;
        }
        FILE *vtzfp = fopen(fe->fts_accpath, "r");
        if (!vtzfp) {
            fprintf(stderr, "fopen(%s): %s\n", fe->fts_accpath, strerror(errno));
            continue;
        }
        icalcomponent *ical = read_vcalendar(vtzfp);
        if (!ical) {
            fprintf(stderr, "skipping %s\n", fe->fts_path);
            fclose(vtzfp);
            continue;
        }

        if (ical && icalcomponent_isa(ical) == ICAL_VCALENDAR_COMPONENT) {
            icalcomponent *vtz;
            for (vtz = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
                 vtz;
                 vtz = icalcomponent_get_next_component(ical, ICAL_VTIMEZONE_COMPONENT)) {

                add_vtimezone(timezones, vtz, trstart, trend, tzoffsets);
            }
        }
        if (ical) icalcomponent_free(ical);

        fclose(vtzfp);
    }
    fts_close(fts);
    icalarray_sort(tzoffsets, compare_tzoffset);

    /* Write database */
    char *ianaversion = ianaversion_from_zonedir(zoneinfo_dir);
    write_header(trstart, trend, ianaversion, fp);
    write_tzoffsets(tzoffsets, fp);
    write_preftzs(timezones, fp);
    write_timezones(timezones, fp);
    free(ianaversion);

    /* Free state */
    size_t i;
    for (i = 0; i < timezones->num_elements; i++) {
        struct guesstz_tz *tz = icalarray_element_at(timezones, i);
        free(tz->obs.alloc);
        free(tz->alloc);
    }
    icalarray_free(timezones);
    icalarray_free(tzoffsets);

    return 0;
}

static int read_db(struct db *db, void *data)
{
    const icaltimezone *utc = icaltimezone_get_utc_timezone();

    if (strcmp(data, db_magic)) return -1;
    data += strlen(db_magic) + 1;

    db->version = *((uint8_t*)data);
    data += 1;

    memcpy(db->bom, data, 2);
    data += 2;

    db->created_at = (time_t) load_int64_t(data);
    data += 8;

    int64_t ttrstart = load_int64_t(data);
    db->trstart = icaltime_from_timet_with_zone((time_t)ttrstart, 0, utc);
    data += 8;

    int64_t ttrend = load_int64_t(data);
    db->trend = icaltime_from_timet_with_zone((time_t)ttrend, 0, utc);
    data += 8;

    db->ianaversion = data;
    data += strlen(db->ianaversion) + 1;

    db->tzoffsets.count = load_uint32_t(data);
    data += 4;

    db->tzoffsets.data = data;
    data += TZOFFSET_SIZE * db->tzoffsets.count;

    db->preftzs.count = load_uint16_t(data);
    data += 2;

    db->preftzs.tzidxs = data;
    data += PREFTZ_SIZE * db->preftzs.count;

    db->timezones = data;

    return 0;
}

static json_t *encode_db(struct db *db)
{
    const icaltimezone *utc = icaltimezone_get_utc_timezone();
    icaltimetype dt = icaltime_from_timet_with_zone(db->created_at, 0, utc);

    /* Encode header */
    json_t *jconfig = json_object();
    json_object_set_new(jconfig, "dbVersion",
            json_integer(db->version));
    json_object_set_new(jconfig, "endianess",
            json_string(db->bom[0] == 0xfe ? "big" : "little"));
    json_object_set_new(jconfig, "ianaVersion",
            json_string(db->ianaversion));
    json_object_set_new(jconfig, "rangeStart",
            json_string(icaltime_as_ical_string(db->trstart)));
    json_object_set_new(jconfig, "rangeEnd",
            json_string(icaltime_as_ical_string(db->trend)));
    json_object_set_new(jconfig, "createdAt",
            json_string(icaltime_as_ical_string(dt)));

    json_t *jdb = json_object();
    json_object_set_new(jdb, "config", jconfig);

    /* Encode offsets */
    json_t *jtzoffsets = json_object();

    if (db->tzoffsets.count) {
        json_t *jofftzs = json_array();
        const uint8_t *data = db->tzoffsets.data;
        char offsetstr[OFFSETSTR_MAX];
        int32_t prevoff = 0;
        size_t i;

        for (i = 0; i < db->tzoffsets.count; i++) {
            int32_t offset = load_int32_t(data);
            data += 4;
            if (i > 0 && prevoff != offset) {
                format_offset(prevoff, offsetstr);
                json_object_set_new(jtzoffsets, offsetstr, jofftzs);
                jofftzs = json_array();
            }
            prevoff = offset;

            uint64_t tzidx = load_uint64_t(data);
            data += 8;
            const char *tzid = (const char *)db->timezones + tzidx;
            json_array_append_new(jofftzs, json_string(tzid));
        }

        if (json_array_size(jofftzs)) {
            format_offset(prevoff, offsetstr);
            json_object_set_new(jtzoffsets, offsetstr, jofftzs);
        }
        else json_decref(jofftzs);
    }

    json_object_set_new(jdb, "tzoffsets", jtzoffsets);

    /* Encode preftzs */
    json_t *jpreftzs = json_array();
    if (db->preftzs.count) {
        uint16_t i;
        for (i = 0; i < db->preftzs.count; i++) {
            uint64_t tzidx = load_uint64_t(db->preftzs.tzidxs + i * PREFTZ_SIZE);
            struct guesstz_tz tz = timezones_idx(db->timezones, tzidx);
            json_array_append_new(jpreftzs, json_string(tz.tzid));
        }
    }
    json_object_set_new(jdb, "preftzs", jpreftzs);

    /* Encode timezones */
    json_t *jtimezones = json_object();

    const uint8_t *data = db->timezones;
    while (*data) {
        json_t *jobs = json_array();
        const char *tzid = (const char *)data;
        data += strlen(tzid) + 1;
        uint32_t obs_cnt = load_uint32_t(data);
        data += 4;

        size_t i;
        for (i = 0; i < obs_cnt; i++) {
            int64_t onset = load_int64_t(data);
            data += 8;

            int32_t offset = load_int32_t(data);
            data += 4;

            icaltimetype dt = icaltime_from_timet_with_zone(onset, 0, utc);
            char offsetstr[OFFSETSTR_MAX];
            format_offset(offset, offsetstr);
            json_array_append_new(jobs, json_pack("[s s]",
                        icaltime_as_ical_string(dt), offsetstr));
        }

        json_object_set_new(jtimezones, tzid, jobs);
    }

    json_object_set_new(jdb, "timezones", jtimezones);

    return jdb;
}

struct guesstz {
    struct db db;
    int fd;
    void *addr;
    struct stat sb;
    char err[1024];
};

__attribute__((format(printf, 2, 3)))
static void print_error(guesstz_t *gtz, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(gtz->err, sizeof(gtz->err) - 1, fmt, args);
    va_end(args);
}

EXPORTED char *guesstz_guess(guesstz_t *gtz,
                        icalcomponent *vtz,
                        icaltimetype trstart,
                        icaltimetype trend)
{
    if ((icaltime_compare(trstart, gtz->db.trstart) < 0) ||
        (icaltime_compare(trstart, gtz->db.trend) >= 0)) {
        print_error(gtz, "trstart outside database time range: "
                "trstart=%s database=%s/%s",
                icaltime_as_ical_string(trstart),
                icaltime_as_ical_string(gtz->db.trstart),
                icaltime_as_ical_string(gtz->db.trend));
        return NULL;
    }
    return guess_timezone(&gtz->db, vtz, trstart, trend);
}

EXPORTED guesstz_t *guesstz_open(const char *path)
{
    struct guesstz *gtz = calloc(1, sizeof(struct guesstz));

    gtz->fd = open(path, O_RDONLY);
    if (gtz->fd == -1) {
        print_error(gtz, "open: %s", strerror(errno));
        goto done;
    }

    if (fstat(gtz->fd, &gtz->sb) == -1) {
        print_error(gtz, "fstat: %s", strerror(errno));
        goto done;
    }

    gtz->addr = mmap(NULL, gtz->sb.st_size, PROT_READ, MAP_PRIVATE, gtz->fd, 0);
    if (gtz->addr == MAP_FAILED) {
        print_error(gtz, "mmap: %s", strerror(errno));
        goto done;
    }

    read_db(&gtz->db, gtz->addr);

    if (memcmp(&db_bom, gtz->db.bom, 2)) {
        print_error(gtz, "database endianess differs");
        goto done;
    }

done:
    return gtz;
}

EXPORTED void guesstz_close(guesstz_t **gtzp)
{
    if (!gtzp || !*gtzp) return;

    guesstz_t *gtz = *gtzp;
    if (gtz->fd != -1) {
        if (gtz->addr != MAP_FAILED)
            munmap(gtz->addr, gtz->sb.st_size);
        close(gtz->fd);
    }
    free(gtz);

    *gtzp = NULL;
}

EXPORTED const char *guesstz_error(guesstz_t *gtz)
{
    return gtz->err[0] ? gtz->err : NULL;
}

EXPORTED char *guesstz_encode(guesstz_t *gtz)
{
    json_t *jdb = encode_db(&gtz->db);
    char *dump = json_dumps(jdb, JSON_INDENT(2)|JSON_SORT_KEYS);
    json_decref(jdb);
    return dump;
}
