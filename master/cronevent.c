/* master/cronevent.c -- master process cronevent subsystem
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

#include "master/cronevent.h"

#include "lib/assert.h"
#include "lib/cron.h"
#include "lib/dynarray.h"
#include "lib/strarray.h"
#include "lib/xmalloc.h"

#include <stdint.h>
#include <stdlib.h>
#include <sysexits.h>
#include <time.h>

static dynarray_t cronevent_schedule
    = DYNARRAY_INITIALIZER(sizeof(struct cron_spec));
static dynarray_t cronevent_details
    = DYNARRAY_INITIALIZER(sizeof(struct cronevent_details));

static time_t cronevent_last_run_time = 0;

/* for unit tests */
HIDDEN void cronevent_get_schedule(dynarray_t **schedule,
                                   dynarray_t **details)
{
    *schedule = &cronevent_schedule;
    *details = &cronevent_details;
}

EXPORTED int cronevent_add(const char *name, const char *spec, const char *cmd)
{
    char err_buf[1024];
    struct cron_spec cron_spec = {0};
    struct cronevent_details *details = NULL;
    const char *parse_err = NULL;
    int spec_idx, det_idx;

    if (!cmd || !*cmd) {
        snprintf(err_buf, sizeof(err_buf), "missing cmd for %s", name);
        fatal(err_buf, EX_CONFIG);
    }

    if (cron_parse_spec(spec, &cron_spec, &parse_err)) {
        snprintf(err_buf, sizeof(err_buf),
                 "unable to parse spec \"%s\" for %s: %s",
                 spec, name, parse_err);
        fatal(err_buf, EX_CONFIG);
    }

    spec_idx = dynarray_append(&cronevent_schedule, &cron_spec);

    det_idx = dynarray_append_empty(&cronevent_details, (void **) &details);
    assert(spec_idx == det_idx);

    details->name = xstrdup(name);
    /* The xstrdup here looks weird, but strarray_splitm specifically wants
     * a heap-allocated string it can take ownership of.  It's not leaked.
     */
    strarray_splitm(&details->exec, xstrdup(cmd), NULL, 0);

    return 0;
}

EXPORTED void cronevent_clear(void)
{
    dynarray_fini(&cronevent_schedule);
    dynarray_fini(&cronevent_details);
}

EXPORTED void cronevent_poll_due(struct timeval now,
                                 cronevent_spawn_fn *spawner)
{
    struct cron_spec current_time;
    time_t run_time;
    int i;

    cron_spec_from_timeval(&current_time, &run_time, &now);

    /* only do anything once per minute */
    if (run_time <= cronevent_last_run_time) return;

    const int n_events = dynarray_size(&cronevent_schedule);
    assert(n_events == dynarray_size(&cronevent_details));

    for (i = 0; i < n_events; i++) {
        struct cron_spec *spec = dynarray_nth(&cronevent_schedule, i);
        struct cronevent_details *details;

        /* quoth crontab(5):
         *   Note: The day of a command's execution can be specified by two
         *   fields — day of month, and day of week. If both fields are
         *   restricted (i.e., aren't *), the command will be run when either
         *   field matches the current time. For example, ``30 4 1,15 * 5''
         *   would cause a command to be run at 4:30 am on the 1st and 15th of
         *   each month, plus every Friday.
         */
        if ((spec->minutes & current_time.minutes)
            && (spec->hours & current_time.hours)
            && (spec->months & current_time.months)
            && ((spec->days_of_month & current_time.days_of_month)
                || (spec->days_of_week & current_time.days_of_week)))
        {
            details = dynarray_nth(&cronevent_details, i);
            spawner(details->name, &details->exec);
        }
    }

    cronevent_last_run_time = run_time;
}
