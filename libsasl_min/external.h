/* external.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef LIBSASL_MIN_EXTERNAL_H
#define LIBSASL_MIN_EXTERNAL_H

#include "libsasl_min/saslplug.h"

extern int external_server_plug_init(const sasl_utils_t *utils,
                                     int maxversion,
                                     int *out_version,
                                     sasl_server_plug_t **pluglist,
                                     int *plugcount);

extern int external_client_plug_init(const sasl_utils_t *utils,
                                     int maxversion,
                                     int *out_version,
                                     sasl_client_plug_t **pluglist,
                                     int *plugcount);

#endif /* LIBSASL_MIN_EXTERNAL_H */

