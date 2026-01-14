/* xmalloc.h - Allocation package that calls fatal() when out of memory */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_XMALLOC_H
#define INCLUDED_XMALLOC_H

/* for size_t */
#include <stdio.h>
/* for free() */
#include <stdlib.h>

#include "assert.h"

extern void *xmalloc(size_t size);
extern void *xzmalloc(size_t size);
extern void *xcalloc(size_t nmemb, size_t size);
extern void *xrealloc(void *ptr, size_t size);
extern void *xzrealloc(void *ptr, size_t orig_size, size_t new_size);
extern char *xstrdup(const char *str);
extern char *xstrdupnull(const char *str);
extern char *xstrdupsafe(const char *str);
extern char *xstrndup(const char *str, size_t len);
extern void *xmemdup(const void *ptr, size_t size);

/* free a pointer and also zero it
 *
 * CAUTION: ptr argument is evaluated multiple times, beware side effects!
 */
#define xzfree(ptr) do {    \
    assert((ptr) == (ptr)); \
    free(ptr);              \
    (ptr) = NULL;           \
} while (0)

/* Functions using xmalloc.h must provide a function called fatal() conforming
   to the following: */
extern void fatal(const char *fatal_message, int fatal_code)
   __attribute__ ((noreturn));

#endif /* INCLUDED_XMALLOC_H */
