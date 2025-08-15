/* cron.h -- parsing Cron-style date-time specifications
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
#ifndef INCLUDED_CRON_H
#define INCLUDED_CRON_H
#include <config.h>

#include "lib/util.h"

#include <stdbool.h>
#include <stdint.h>

#define CRON_ALL_MINUTES       UINT64_C(0x0FFFFFFFFFFFFFFF)
#define CRON_ALL_HOURS         UINT64_C(0x00FFFFFF)
#define CRON_ALL_DAYS_OF_MONTH UINT64_C(0x7FFFFFFF)
#define CRON_ALL_MONTHS        UINT64_C(0x0FFF)
#define CRON_ALL_DAYS_OF_WEEK  UINT64_C(0x7F)

struct cron_spec {
    uint64_t minutes;       /* bits 0-59 represent minutes */
    uint32_t hours;         /* bits 0-23 represent hours */
    uint32_t days_of_month; /* bits 0-30 represent days 1-31 */
    uint16_t months;        /* bits 0-11 represent months 1-12 */
    uint8_t  days_of_week;  /* bits 0-6 represent days sun-sat */
};

extern int cron_parse_spec(const char *spec,
                           struct cron_spec *result,
                           const char **err);
extern void cron_spec_from_timeval(struct cron_spec *result,
                                   time_t *run_time,
                                   const struct timeval *timeval);
extern bool cron_spec_matches(const struct cron_spec *spec,
                              const struct cron_spec *current_time);
extern void cron_spec_dump(struct buf *buf, const struct cron_spec *spec);
#endif
