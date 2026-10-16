/* config.c */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "libsasl_min/saslutil.h"
#include "libsasl_min/saslint.h"

/* In cyrus-sasl, these functions provide fallback configuration lookup for
 * when the application didn't provide hooks into its own lookup.
 *
 * This implementation is embedded within the application, so there is no
 * fallback.
 */

EXPORTED int sasl_config_init(const char *filename __attribute__((unused)))
{
    return SASL_CONFIGERR;
}

EXPORTED void sasl_config_done(void)
{
    return;
}

EXPORTED const char *sasl_config_getstring(
    const char *key __attribute__((unused)),
    const char *def __attribute__((unused)))
{
    return NULL;
}
