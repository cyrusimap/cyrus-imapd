/* cron.c -- parsing Cron-style date-time specifications
 *
 * Copyright (c) 1994-2025 Carnegie Mellon University.  All rights reserved.
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
 */
#include <config.h>

#include "lib/cron.h"
#include "lib/util.h"
#include "lib/xmalloc.h"

#include <sysexits.h>
#include <syslog.h>
#include <time.h>

// struct cron_spec {
//     uint64_t minutes;       /* bits 0-59 represent minutes */
//     uint32_t hours;         /* bits 0-23 represent hours */
//     uint32_t days_of_month; /* bits 0-30 represent days 1-31 */
//     uint16_t months;        /* bits 0-11 represent months 1-12 */
//     uint8_t  days_of_week;  /* bits 0-6 represent days sun-sat */
// };
#define BIT(n) (UINT64_C(1) << (n))
EXPORTED void dump_cron_spec(struct buf *buf, const struct cron_spec *spec)
{
    const char *sep;
    unsigned i;

    if (spec->minutes == CRON_ALL_MINUTES) {
        buf_appendcstr(buf, "minutes: all\n");
    }
    else if (spec->minutes == 0) {
        buf_appendcstr(buf, "minutes: none\n");
    }
    else {
        sep = "";
        buf_appendcstr(buf, "minutes: ");
        for (i = 0; i < 60; i++) {
            if ((spec->minutes & BIT(i))) {
                buf_printf(buf, "%s%u", sep, i);
                sep = ", ";
            }
        }
        buf_appendcstr(buf, "\n");
    }

    if (spec->hours == CRON_ALL_HOURS) {
        buf_appendcstr(buf, "hours: all\n");
    }
    else if (spec->hours == 0) {
        buf_appendcstr(buf, "hours: none\n");
    }
    else {
        sep = "";
        buf_appendcstr(buf, "hours: ");
        for (i = 0; i < 24; i++) {
            if ((spec->hours & BIT(i))) {
                buf_printf(buf, "%s%u", sep, i);
                sep = ", ";
            }
        }
        buf_appendcstr(buf, "\n");
    }

    if (spec->days_of_month == CRON_ALL_DAYS_OF_MONTH) {
        buf_appendcstr(buf, "days_of_month: all\n");
    }
    else if (spec->days_of_month == 0) {
        buf_appendcstr(buf, "days_of_month: none\n");
    }
    else {
        sep = "";
        buf_appendcstr(buf, "days_of_month: ");
        for (i = 0; i < 31; i++) {
            if ((spec->days_of_month & BIT(i))) {
                buf_printf(buf, "%s%u", sep, i);
                sep = ", ";
            }
        }
        buf_appendcstr(buf, "\n");
    }

    if (spec->months == CRON_ALL_MONTHS) {
        buf_appendcstr(buf, "months: all\n");
    }
    else if (spec->months == 0) {
        buf_appendcstr(buf, "months: none\n");
    }
    else {
        sep = "";
        buf_appendcstr(buf, "months: ");
        for (i = 0; i < 12; i++) {
            if ((spec->months & BIT(i))) {
                buf_printf(buf, "%s%u", sep, i);
                sep = ", ";
            }
        }
        buf_appendcstr(buf, "\n");
    }

    if (spec->days_of_week == CRON_ALL_DAYS_OF_WEEK) {
        buf_appendcstr(buf, "days_of_week: all\n");
    }
    else if (spec->days_of_week == 0) {
        buf_appendcstr(buf, "days_of_week: none\n");
    }
    else {
        sep = "";
        buf_appendcstr(buf, "days_of_week: ");
        for (i = 0; i < 7; i++) {
            if ((spec->days_of_week & BIT(i))) {
                buf_printf(buf, "%s%u", sep, i);
                sep = ", ";
            }
        }
        buf_appendcstr(buf, "\n");
    }
}

EXPORTED void cron_spec_from_timeval(struct cron_spec *result,
                                     time_t *run_time,
                                     const struct timeval *timeval)
{
    struct tm *tm = localtime(&timeval->tv_sec);
    fprintf(stderr, "XXX t=" TIME_T_FMT " gave time=%s\n",
                    timeval->tv_sec, asctime(tm));

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
        fprintf(stderr, "XXX compensating for tm_mon=%d tm_mday=%d!\n",
                        tm->tm_mon, tm->tm_mday);
        tm->tm_mday = monthdays[result->months] + leapday;
        tm->tm_mon = (tm->tm_mon + 12 - 1) % 12;
        syslog(LOG_DEBUG, "%s: computed tm_mon=%d tm_mday=%d!\n",
                          __func__, tm->tm_mon, tm->tm_mday);
        fprintf(stderr, "XXX computed tm_mon=%d tm_mday=%d!\n",
                        tm->tm_mon, tm->tm_mday);
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
