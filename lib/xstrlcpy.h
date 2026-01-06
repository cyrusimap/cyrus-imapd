/* xmalloc.h -- Allocation package that calls fatal() when out of memory */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_XSTRLCPY_H
#define INCLUDED_XSTRLCPY_H

#include <config.h>

/* for size_t */
#include <stdio.h>
/* for free() */
#include <stdlib.h>
/* for strlen() */
#include <string.h>

/* handy string manipulation functions */
#ifndef HAVE_STRLCPY
extern size_t strlcpy(char *dst, const char *src, size_t len);
#endif

#endif /* INCLUDED_XSTRLCPY_H */
