/* xmalloc.h -- Allocation package that calls fatal() when out of memory
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
