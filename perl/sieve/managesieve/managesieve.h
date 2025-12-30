/* managesieve.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include "isieve.h"


struct xscyrus {
    isieve_t *isieve;

    char *errstr;               /* last error, if any */

    char *class; /* needed by perl */
};
