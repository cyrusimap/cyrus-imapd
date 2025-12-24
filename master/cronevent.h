/* master/cronevent.h -- master process cronevent subsystem */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MASTER_CRONEVENT_H
#define MASTER_CRONEVENT_H

#include "lib/strarray.h"

#include <stdbool.h>

/* unit tests need to know this struct */
struct cronevent_details {
    char *name;
    strarray_t exec;
};

extern void cronevent_add(const char *name,
                          const char *spec,
                          const char *cmd,
                          bool ignore_err);
extern void cronevent_clear(void);

typedef void (cronevent_spawn_fn)(const char *name,
                                  const strarray_t *exec,
                                  void *rock);
extern void cronevent_poll_due(struct timeval now,
                               cronevent_spawn_fn *spawner,
                               void *rock);

#endif
