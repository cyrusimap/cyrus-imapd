/* mutex_fake.c - fake mutex new/lock/unlock/destroy functions (for SASL) */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <sasl/sasl.h>

EXPORTED void *cyrus_mutex_alloc(void)
{
    return (void *)0x1;
}

EXPORTED int cyrus_mutex_lock(void *mutex __attribute__((unused)))
{
    return SASL_OK;
}

EXPORTED int cyrus_mutex_unlock(void *mutex __attribute__((unused)))
{
    return SASL_OK;
}

EXPORTED void cyrus_mutex_free(void *mutex __attribute__((unused)))
{
    return;
}
