/* cron.h - parsing Cron-style date-time specifications */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
