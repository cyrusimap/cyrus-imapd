/* canonuser_internal.h - INTERNAL canonuser plugin */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef LIBSASL_MIN_CANONUSER_INTERNAL_H
#define LIBSASL_MIN_CANONUSER_INTERNAL_H

#include "libsasl_min/sasl.h"
#include "libsasl_min/saslplug.h"

extern int internal_canonuser_init(const sasl_utils_t *utils,
                                   int max_version,
                                   int *out_version,
                                   sasl_canonuser_plug_t **plug,
                                   const char *plugname);

#endif /* LIBSASL_MIN_CANONUSER_INTERNAL_H */

