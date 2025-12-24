/* master/event.h -- master process event subsystem */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MASTER_EVENT_H
#define MASTER_EVENT_H

#include <sys/time.h>

#include "lib/strarray.h"

struct event {
    char *name;
    struct timeval mark;
    time_t period;
    strarray_t exec;
    struct event *next;
};

extern struct event *event_new_oneshot(const char *name, struct timeval mark);
extern struct event *event_new_periodic(const char *name,
                                        struct timeval mark,
                                        time_t period);
extern void event_free(struct event *evt);

extern void event_set_exec(struct event *evt, const char *cmd);

extern void schedule_event(struct event *evt);
extern void reschedule_event(struct event *evt, struct timeval now);

extern struct event *schedule_splice_due(struct timeval now);
extern struct event *schedule_peek(void);

extern void schedule_clear(void);

#endif
