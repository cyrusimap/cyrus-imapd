/* xstrnchr.h -- Implementation of strnchr() */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_XSTRNCHR_H
#define INCLUDED_XSTRNCHR_H

#include <config.h>

/* for size_t */
#include <stdio.h>

#ifndef HAVE_STRNCHR
extern char *strnchr(const char *s, int c, size_t n);
#endif

#endif /* INCLUDED_XSTRNCHR_H */
