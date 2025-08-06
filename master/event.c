/* master/event.c -- master process event subsystem
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

#include "master/event.h"

#include "lib/assert.h"
#include "lib/util.h"

#include <sysexits.h>
#include <syslog.h>

static struct event *schedule = NULL;

static inline struct event *event_new(const char *name)
{
    struct event *evt = xzmalloc(sizeof(*evt));

    evt->name = xstrdup(name);
    return evt;
}

EXPORTED struct event *event_new_oneshot(const char *name, struct timeval mark)
{
    struct event *evt = event_new(name);

    evt->mark = mark;

    return evt;
}

EXPORTED struct event *event_new_periodic(const char *name,
                                          struct timeval mark,
                                          time_t period)
{
    struct event *evt = event_new(name);

    assert(period > 0);

    evt->mark = mark;
    evt->periodic = 1;
    evt->period = period;

    return evt;
}

EXPORTED struct event *event_new_hourmin(const char *name, int hour, int min)
{
    struct event *evt = event_new(name);
    struct tm *tm;
    struct timeval now;

    assert(hour >= 0 && hour <= 23);
    assert(min >= 0 && min <= 59);

    gettimeofday(&now, NULL);
    tm = localtime(&now.tv_sec);
    tm->tm_hour = hour;
    tm->tm_min = min;
    tm->tm_sec = 0;

    evt->periodic = 0;
    evt->period = 86400; /* 24 hours */
    evt->hour = hour;
    evt->min = min;
    evt->mark.tv_sec = mktime(tm);

    if (timesub(&now, &evt->mark) < 0.0) {
        /* already missed it, so schedule for next day */
        evt->mark.tv_sec += evt->period;
    }

    return evt;
}

EXPORTED void event_set_exec(struct event *evt, const char *cmd)
{
    strarray_truncate(&evt->exec, 0);

    if (cmd) {
        /* The xstrdup here looks weird, but strarray_splitm specifically wants
         * a heap-allocated string it can take ownership of.  It's not leaked.
         */
        strarray_splitm(&evt->exec, xstrdup(cmd), NULL, 0);
    }
}

EXPORTED void event_free(struct event *evt)
{
    strarray_fini(&evt->exec);
    free(evt->name);
    free(evt);
}

EXPORTED void schedule_event(struct event *evt)
{
    struct event *ptr;

    if (!evt->name)
        fatal("Serious software bug found: schedule_event() called on unnamed event!",
              EX_SOFTWARE);

    if (!schedule || timesub(&schedule->mark, &evt->mark) < 0.0) {
        evt->next = schedule;
        schedule = evt;

        return;
    }
    for (ptr = schedule;
         ptr->next && timesub(&evt->mark, &ptr->next->mark) <= 0.0;
         ptr = ptr->next) ;

    /* insert evt */
    evt->next = ptr->next;
    ptr->next = evt;
}

EXPORTED void reschedule_event(struct event *evt, struct timeval now)
{
    assert(evt->period);

    if (evt->periodic) {
        evt->mark = now;
        evt->mark.tv_sec += evt->period;
    }
    else {
        struct tm *tm;
        int delta;

        /* Daily Event */
        while (timesub(&now, &evt->mark) <= 0.0)
            evt->mark.tv_sec += evt->period;

        /* check for daylight savings fuzz... */
        tm = localtime(&evt->mark.tv_sec);
        if (tm->tm_hour != evt->hour || tm->tm_min != evt->min) {
            /* calculate the same time on the new day */
            tm->tm_hour = evt->hour;
            tm->tm_min = evt->min;
            delta = mktime(tm) - evt->mark.tv_sec;
            /* bring it within half a period either way */
            while (delta > (evt->period/2)) delta -= evt->period;
            while (delta < -(evt->period/2)) delta += evt->period;
            /* update the time */
            evt->mark.tv_sec += delta;
            /* and let us know about the change */
            syslog(LOG_NOTICE,
                   "timezone shift for %s - altering schedule by %d seconds",
                   evt->name, delta);
        }
    }

    schedule_event(evt);
}

EXPORTED struct event *schedule_peek(void)
{
    return schedule;
}

EXPORTED struct event *schedule_splice_due(struct timeval now)
{
    struct event *due, *last_due = NULL;

    due = schedule;
    while (due && timesub(&now, &due->mark) <= 0.0) {
        last_due = due;
        due = due->next;
    }

    if (last_due) {
        due = schedule;
        schedule = last_due->next;
        last_due->next = NULL;
        return due;
    }
    else {
        return NULL;
    }
}

EXPORTED void schedule_clear(void)
{
    while (schedule) {
        struct event *evt = schedule;
        schedule = schedule->next;
        event_free(evt);
    }
}
