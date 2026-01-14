/* cron.c - parsing Cron-style date-time specifications */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "lib/cron.h"
#include "lib/xmalloc.h"

#include <sysexits.h>
#include <syslog.h>
#include <time.h>

EXPORTED void cron_spec_from_timeval(struct cron_spec *result,
                                     time_t *run_time,
                                     const struct timeval *timeval)
{
    struct tm *tm = localtime(&timeval->tv_sec);

    if (tm->tm_mday == 0) {
        /* quoth localtime(3):
         *   In many implementations, including glibc, a 0 in tm_mday is
         *   interpreted as meaning the last day of the preceding month.
         */
        /* XXX month days logic duplicated from private impl in lib/times */
        static const int monthdays[12] = {
            31, 28, 31, 30, 31, 30,
            31, 31, 30, 31, 30, 31
        };
        const int year = tm->tm_year;
        const int leapday = (tm->tm_mon == 1 &&
                             (!(year % 4) && ((year % 100) || !(year % 400))));

        syslog(LOG_DEBUG, "%s: compensating for tm_mon=%d tm_mday=%d!\n",
                          __func__, tm->tm_mon, tm->tm_mday);
        tm->tm_mday = monthdays[result->months] + leapday;
        tm->tm_mon = (tm->tm_mon + 12 - 1) % 12;
        syslog(LOG_DEBUG, "%s: computed tm_mon=%d tm_mday=%d!\n",
                          __func__, tm->tm_mon, tm->tm_mday);
    }

    if (result) {
        *result = (struct cron_spec) {
            .minutes = UINT64_C(1) << tm->tm_min,
            .hours = UINT32_C(1) << tm->tm_hour,
            .days_of_month = UINT32_C(1) << (tm->tm_mday - 1),
            .months = UINT16_C(1) << tm->tm_mon,
            .days_of_week = UINT8_C(1) << tm->tm_wday,
        };
    }

    if (run_time) {
        tm->tm_sec = 0;
        *run_time = mktime(tm);
    }
}

EXPORTED bool cron_spec_matches(const struct cron_spec *spec,
                                const struct cron_spec *current_time)
{
    bool min_hr_mon, day;

    min_hr_mon = ((spec->minutes & current_time->minutes)
                  && (spec->hours & current_time->hours)
                  && (spec->months & current_time->months));

    /* quoth crontab(5):
     *   Note: The day of a command's execution can be specified by two
     *   fields — day of month, and day of week. If both fields are
     *   restricted (i.e., aren't *), the command will be run when either
     *   field matches the current time. For example, ``30 4 1,15 * 5''
     *   would cause a command to be run at 4:30 am on the 1st and 15th of
     *   each month, plus every Friday.
     */
    if (spec->days_of_month == CRON_ALL_DAYS_OF_MONTH) {
        day = (spec->days_of_week & current_time->days_of_week);
    }
    else if (spec->days_of_week == CRON_ALL_DAYS_OF_WEEK) {
        day = (spec->days_of_month & current_time->days_of_month);
    }
    else {
        day = ((spec->days_of_month & current_time->days_of_month)
               || (spec->days_of_week & current_time->days_of_week));
    }

    return min_hr_mon && day;
}

#define BIT(n) (UINT64_C(1) << (n))
static void dump_one(struct buf *buf,
                     const char *desc,
                     unsigned n_bits,
                     uint64_t all_bits,
                     uint64_t value)
{
    if (value == all_bits) {
        buf_printf(buf, "%s: all\n", desc);
    }
    else if (value == 0) {
        buf_printf(buf, "%s: none\n", desc);
    }
    else {
        const char *sep = "";
        unsigned i;

        buf_printf(buf, "%s: ", desc);
        for (i = 0; i < n_bits; i++) {
            if ((value & BIT(i))) {
                buf_printf(buf, "%s%u", sep, i);
                sep = ", ";
            }
        }
        buf_appendcstr(buf, "\n");
    }
}

EXPORTED void cron_spec_dump(struct buf *buf, const struct cron_spec *spec)
{
    dump_one(buf, "minutes", 60, CRON_ALL_MINUTES, spec->minutes);
    dump_one(buf, "hours", 24, CRON_ALL_HOURS, spec->hours);
    dump_one(buf, "days of month", 31,
             CRON_ALL_DAYS_OF_MONTH, spec->days_of_month);
    dump_one(buf, "months", 12, CRON_ALL_MONTHS, spec->months);
    dump_one(buf, "days of week", 7,
             CRON_ALL_DAYS_OF_WEEK, spec->days_of_week);
}
