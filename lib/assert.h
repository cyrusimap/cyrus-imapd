/* assert.h - assert() macro that can exit cleanly */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_ASSERT_H
#define INCLUDED_ASSERT_H

__attribute__((noreturn))
void assertionfailed(const char *file, int line, const char *expr);

#define assert(expr)                                                \
    ((expr)                                                         \
     ? (void)(0)                                                    \
     : assertionfailed(__FILE__, __LINE__, #expr))

/* In C11, static_assert is a macro provided by the system assert header.
 * We can't use that header with this one, so provide an equivalent macro.
 *
 * In C23 and C++, static_assert is a language keyword, so do nothing.
 */
#if ((!defined __STDC_VERSION__ || __STDC_VERSION__ <= 201710L) \
     && !defined __cplusplus)
# undef static_assert
# define static_assert _Static_assert
#endif

#endif /* INCLUDED_ASSERT_H */
