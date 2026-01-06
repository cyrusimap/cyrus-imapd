/* master/event.c -- master process event subsystem */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
    evt->period = period;

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
    time_t now_s = now.tv_sec;
    time_t period = evt->period;
    time_t mark = MIN(now_s, evt->mark.tv_sec);

    assert(period > 0);

    /* don't fall behind schedule if we're running slow for some reason */
    mark += period;
    if (mark <= now_s) {
        unsigned skipped = 0;
        do {
            mark += period;
            skipped ++;
        } while (mark <= now_s);
        xsyslog(LOG_WARNING, "periodic event behind schedule",
                             "name=<%s> period=<" TIME_T_FMT "> skipped=<%u>",
                             evt->name, evt->period, skipped);
    }

    evt->mark.tv_sec = mark;

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
