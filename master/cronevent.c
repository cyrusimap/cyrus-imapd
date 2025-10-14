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
#include "lib/util.h"
#include "lib/xmalloc.h"

#include <stdint.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>

static dynarray_t cronevent_schedule =
    DYNARRAY_INITIALIZER(sizeof(struct cron_spec));
static dynarray_t cronevent_details =
    DYNARRAY_INITIALIZER(sizeof(struct cronevent_details));

static time_t cronevent_last_run_time = 0;

EXPORTED void cronevent_add(const char *name,
                            const char *spec,
                            const char *cmd,
                            bool ignore_err)
{
    struct cron_spec cron_spec = { 0 };
    struct cronevent_details *details = NULL;
    const char *parse_err = NULL;
    int spec_idx, det_idx;

    if (!name || !*name) {
        xsyslog(LOG_ERR, "event missing name",
                         "spec=<%s> cmd=<%s>",
                         spec, cmd);
        if (ignore_err) {
            return;
        }
        fatal("event missing name", EX_CONFIG);
    }

    if (!cmd || !*cmd) {
        xsyslog(LOG_ERR, "event missing cmd",
                         "name=<%s>", name);
        if (ignore_err) {
            return;
        }
        fatal("event missing cmd", EX_CONFIG);
    }

    if (!spec || cron_parse_spec(spec, &cron_spec, &parse_err)) {
        xsyslog(LOG_ERR, "unable to parse cron spec",
                         "name=<%s> spec=<%s> parse_err=<%s>",
                         name, spec, parse_err);
        if (ignore_err) {
            return;
        }
        fatal("unable to parse cron spec", EX_CONFIG);
    }

    spec_idx = dynarray_append(&cronevent_schedule, &cron_spec);

    det_idx = dynarray_append_empty(&cronevent_details, (void **) &details);
    assert(spec_idx == det_idx);

    details->name = xstrdup(name);
    /* The xstrdup here looks weird, but strarray_splitm specifically wants
     * a heap-allocated string it can take ownership of.  It's not leaked.
     */
    strarray_splitm(&details->exec, xstrdup(cmd), NULL, 0);
}

EXPORTED void cronevent_clear(void)
{
    struct cronevent_details *details;
    int i, n;

    dynarray_fini(&cronevent_schedule);

    for (i = 0, n = dynarray_size(&cronevent_details); i < n; i++) {
        details = dynarray_nth(&cronevent_details, i);
        free(details->name);
        strarray_fini(&details->exec);
    }
    dynarray_fini(&cronevent_details);

    cronevent_last_run_time = 0;
}

EXPORTED void cronevent_poll_due(struct timeval now,
                                 cronevent_spawn_fn *spawner,
                                 void *rock)
{
    struct cron_spec current_time;
    time_t run_time;
    int i;

    cron_spec_from_timeval(&current_time, &run_time, &now);

    /* only do anything once per minute */
    if (cronevent_last_run_time && run_time <= cronevent_last_run_time) {
        return;
    }

    const int n_events = dynarray_size(&cronevent_schedule);
    assert(n_events == dynarray_size(&cronevent_details));

    for (i = 0; i < n_events; i++) {
        struct cron_spec *spec = dynarray_nth(&cronevent_schedule, i);
        struct cronevent_details *details;

        if (cron_spec_matches(spec, &current_time)) {
            details = dynarray_nth(&cronevent_details, i);
            spawner(details->name, &details->exec, rock);
        }
    }

    cronevent_last_run_time = run_time;
}

/* hidden accessors for unit tests */
HIDDEN void cronevent_get_schedule(dynarray_t **schedule, dynarray_t **details)
{
    *schedule = &cronevent_schedule;
    *details = &cronevent_details;
}

HIDDEN time_t cronevent_get_last_run_time(void)
{
    return cronevent_last_run_time;
}

HIDDEN void cronevent_set_last_run_time(time_t run_time)
{
    cronevent_last_run_time = run_time;
}
