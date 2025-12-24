/* mutex_fake.c - fake mutex new/lock/unlock/destroy functions (for SASL) */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <pthread.h>
#include <sasl/sasl.h>

#include "xmalloc.h"

EXPORTED void *cyrus_mutex_alloc(void)
{
    pthread_mutex_t *ret = (pthread_mutex_t *)xmalloc(sizeof(pthread_mutex_t));

    pthread_mutex_init(ret, NULL);

    return ret;
}

EXPORTED int cyrus_mutex_lock(void *mutex)
{
    return pthread_mutex_lock(mutex);
}

EXPORTED int cyrus_mutex_unlock(void *mutex)
{
    return pthread_mutex_unlock(mutex);
}

EXPORTED void cyrus_mutex_free(void *mutex)
{
    if(!mutex) return;

    pthread_mutex_destroy(mutex);
    free(mutex);

    return;
}
