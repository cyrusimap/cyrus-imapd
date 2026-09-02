/* xmalloc.h - Allocation package that calls fatal() when out of memory */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_XMALLOC_H
#define INCLUDED_XMALLOC_H

/* for size_t */
#include <stdio.h>
/* for free() */
#include <stdlib.h>

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
 *
 * _Static_assert requires that its first argument be an integer constant
 * expression.  When ptr has no side effects, (ptr) == (ptr) is a
 * tautology that can be resolved to 1, and the assertion passes.
 *
 * When ptr has side effects, (ptr) == (ptr) is not a tautology, and would need
 * to be evaluated at run time.  This means it's not an integer constant
 * expression, so the statement is invalid, and we'll get a compiler error of
 * some sort, preventing us from using a ptr with side effects.
 *
 * THIS RELIES ON THE COMPILER RESOLVING THE TAUTOLOGY EARLY ENOUGH.  If it
 * doesn't, even valid usage of xzfree will result in an error here.
 *
 * gcc resolves the tautology early enough, but clang does not.  Neither does
 * gcc when -Wpedantic is in play, but we don't use that.
 *
 * configure gives us HAVE_EARLY_CONSTANT_FOLDING, but this header is
 * installed, so it can't include config.h to use it!  Thus this crude
 * clang-specific exclusion for now.
 *
 * The point of the _Static_assert check is to prevent us misusing xzfree.  As
 * long as one of our CI compilers (gcc) does this check, it doesn't matter if
 * other ones don't.  So it's fine to omit the check when clang is detected.
 */
#ifndef __clang__
# define xzfree(ptr) do {                                               \
    _Static_assert((ptr) == (ptr), "xzfree argument has side effects"); \
    free(ptr);                                                          \
    (ptr) = NULL;                                                       \
} while (0)
#else
# define xzfree(ptr) do {   \
    free(ptr);              \
    (ptr) = NULL;           \
} while (0)
#endif

/* Functions using xmalloc.h must provide a function called fatal() conforming
   to the following: */
extern void fatal(const char *fatal_message, int fatal_code)
   __attribute__ ((noreturn));

#endif /* INCLUDED_XMALLOC_H */
