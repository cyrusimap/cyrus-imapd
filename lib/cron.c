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
