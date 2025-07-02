#include <config.h>

#include "master/event.h"

#include "lib/assert.h"
#include "lib/util.h"

#include <sysexits.h>
#include <syslog.h>

static struct event *schedule = NULL;

EXPORTED struct event *event_new(const char *name)
{
    struct event *evt = xzmalloc(sizeof(*evt));

    evt->name = xstrdup(name);
    return evt;
}

EXPORTED void event_free(struct event *evt)
{
    if (evt->exec) {
        strarray_free(evt->exec);
        evt->exec = NULL;
    }
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
    struct event *due = NULL, *next;

    /* XXX same algorithm as original, including the bug where it
     * XXX reverses the order of the events, which becomes very
     * XXX clear as soon as you use good variable names instead
     * XXX of "a" and "ptr" :/
     */
    while (schedule && timesub(&now, &schedule->mark) <= 0.0) {
        next = schedule;

        /* delete */
        schedule = schedule->next;

        /* insert */
        next->next = due;
        due = next;
    }

    return due;
}

EXPORTED void schedule_clear(void)
{
    while (schedule) {
        struct event *evt = schedule;
        schedule = schedule->next;
        event_free(evt);
    }
}
