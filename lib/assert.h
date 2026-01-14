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

#endif /* INCLUDED_ASSERT_H */
