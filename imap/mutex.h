/* mutex.h - header for mutex functions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef CYRUS_MUTEX_H
#define CYRUS_MUTEX_H

#include <config.h>

void *cyrus_mutex_alloc(void);
int cyrus_mutex_lock(void *mutex);
int cyrus_mutex_unlock(void *mutex);
void cyrus_mutex_free(void *mutex);

#endif
