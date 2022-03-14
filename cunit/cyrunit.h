/* cyrunit.h - wrapper for CUnit assert macros
 *
 * Copyright (c) 1994-2010 Carnegie Mellon University.  All rights reserved.
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

#ifndef INCLUDED_CUNIT_H
#define INCLUDED_CUNIT_H

#include <stdio.h>
#include <stdarg.h>
#include <CUnit/CUnit.h>
#include "cunit-syslog.h"

extern int verbose;

/* initialise libconfig from a string */
extern void config_read_string(const char *s);

/*
 * The standard CUnit assertion *EQUAL* macros have a flaw: they do
 * not report the actual values of the 'actual' and 'expected' values,
 * which makes it rather hard to see why an assertion failed.  So we
 * replace the macros with improved ones, keeping the same API.
 */
/* XXX Would like to add __attribute__((format(printf, 6, 7)))
 * XXX to this so the compiler can warn if it's misused, but it looks
 * XXX like it currently gets very confused by the layers of macros
 * XXX and produces bogus warnings. :(
 */
extern CU_BOOL CU_assertFormatImplementation(CU_BOOL bValue, unsigned int uiLine,
                                             char strFile[], char strFunction[],
                                             CU_BOOL bFatal,
                                             char strConditionFormat[], ...);
extern void __cunit_wrap_test(const char *name, void (*fn)(void));
extern int __cunit_wrap_fixture(const char *name, int (*fn)(void));

#undef CU_ASSERT_EQUAL
#define CU_ASSERT_EQUAL(actual,expected) do {                           \
    long long _a = (actual), _e = (expected);                           \
    CU_assertFormatImplementation((_a == _e), __LINE__,                 \
        __FILE__, "", CU_FALSE,                                         \
        "CU_ASSERT_EQUAL(%s=%lld,%s=%lld)",                             \
        #actual, _a, #expected, _e);                                    \
} while(0)

#undef CU_ASSERT_EQUAL_FATAL
#define CU_ASSERT_EQUAL_FATAL(actual,expected) do {                     \
    long long _a = (actual), _e = (expected);                           \
    CU_assertFormatImplementation((_a == _e), __LINE__,                 \
        __FILE__, "", CU_TRUE,                                          \
        "CU_ASSERT_EQUAL_FATAL(%s=%lld,%s=%lld)",                       \
        #actual, _a, #expected, _e);                                    \
} while(0)

#undef CU_ASSERT_NOT_EQUAL
#define CU_ASSERT_NOT_EQUAL(actual,expected) do {                       \
    long long _a = (actual), _e = (expected);                           \
    CU_assertFormatImplementation((_a != _e), __LINE__,                 \
        __FILE__, "", CU_FALSE,                                         \
        "CU_ASSERT_NOT_EQUAL(%s=%lld,%s=%lld)",                         \
        #actual, _a, #expected, _e);                                    \
} while(0)

#undef CU_ASSERT_NOT_EQUAL_FATAL
#define CU_ASSERT_NOT_EQUAL_FATAL(actual,expected) do {                 \
    long long _a = (actual), _e = (expected);                           \
    CU_assertFormatImplementation((_a != _e), __LINE__,                 \
        __FILE__, "", CU_TRUE,                                          \
        "CU_ASSERT_NOT_EQUAL_FATAL(%s=%lld,%s=%lld)",                   \
        #actual, _a, #expected, _e);                                    \
} while(0)



#undef CU_ASSERT_PTR_EQUAL
#define CU_ASSERT_PTR_EQUAL(actual,expected) do {                       \
    const void *_a = (actual), *_e = (expected);                        \
    CU_assertFormatImplementation((_a == _e), __LINE__,                 \
        __FILE__, "", CU_FALSE,                                         \
        "CU_ASSERT_PTR_EQUAL(%s=%p,%s=%p)",                             \
        #actual, _a, #expected, _e);                                    \
} while(0)

#undef CU_ASSERT_PTR_EQUAL_FATAL
#define CU_ASSERT_PTR_EQUAL_FATAL(actual,expected) do {                 \
    const void *_a = (actual), *_e = (expected);                        \
    CU_assertFormatImplementation((_a == _e), __LINE__,                 \
        __FILE__, "", CU_TRUE,                                          \
        "CU_ASSERT_PTR_EQUAL_FATAL(%s=%p,%s=%p)",                       \
        #actual, _a, #expected, _e);                                    \
} while(0)

#undef CU_ASSERT_PTR_NOT_EQUAL
#define CU_ASSERT_PTR_NOT_EQUAL(actual,expected) do {                   \
    const void *_a = (actual), *_e = (expected);                        \
    CU_assertFormatImplementation((_a != _e), __LINE__,                 \
        __FILE__, "", CU_FALSE,                                         \
        "CU_ASSERT_PTR_NOT_EQUAL(%s=%p,%s=%p)",                         \
        #actual, _a, #expected, _e);                                    \
} while(0)

#undef CU_ASSERT_PTR_NOT_EQUAL_FATAL
#define CU_ASSERT_PTR_NOT_EQUAL_FATAL(actual,expected) do {             \
    const void *_a = (actual), *_e = (expected);                        \
    CU_assertFormatImplementation((_a != _e), __LINE__,                 \
        __FILE__, "", CU_TRUE,                                          \
        "CU_ASSERT_PTR_NOT_EQUAL_FATAL(%s=%p,%s=%p)",                   \
        #actual, _a, #expected, _e);                                    \
} while(0)

#undef CU_ASSERT_PTR_NULL
#define CU_ASSERT_PTR_NULL(actual) do {                                 \
    const void *_a = (actual);                                          \
    CU_assertFormatImplementation(!(_a), __LINE__,                      \
        __FILE__, "", CU_FALSE,                                         \
        "CU_ASSERT_PTR_NULL(%s)", #actual);                             \
} while(0)

#undef CU_ASSERT_PTR_NULL_FATAL
#define CU_ASSERT_PTR_NULL_FATAL(actual) do {                           \
    const void *_a = (actual);                                          \
    CU_assertFormatImplementation(!(_a), __LINE__,                      \
        __FILE__, "", CU_TRUE,                                          \
        "CU_ASSERT_PTR_NULL(%s)", #actual);                             \
} while(0)

#undef CU_ASSERT_PTR_NOT_NULL
#define CU_ASSERT_PTR_NOT_NULL(actual) do {                             \
    const void *_a = (actual);                                          \
    CU_assertFormatImplementation(!!(_a), __LINE__,                     \
        __FILE__, "", CU_FALSE,                                         \
        "CU_ASSERT_PTR_NULL(%s)", #actual);                             \
} while(0)

#undef CU_ASSERT_PTR_NOT_NULL_FATAL
#define CU_ASSERT_PTR_NOT_NULL_FATAL(actual) do {                       \
    const void *_a = (actual);                                          \
    CU_assertFormatImplementation(!!(_a), __LINE__,                     \
        __FILE__, "", CU_TRUE,                                          \
        "CU_ASSERT_PTR_NULL(%s)", #actual);                             \
} while(0)

#undef CU_ASSERT_STRING_EQUAL
#define CU_ASSERT_STRING_EQUAL(actual,expected) do {                    \
    const char *_a = (actual), *_e = (expected);                        \
    CU_assertFormatImplementation(!strcmp(_a?_a:"",_e?_e:""), __LINE__, \
        __FILE__, "", CU_FALSE,                                         \
        "CU_ASSERT_STRING_EQUAL(%s=\"%s\",%s=\"%s\")",                  \
        #actual, _a, #expected, _e);                                    \
} while(0)

#undef CU_ASSERT_STRING_EQUAL_FATAL
#define CU_ASSERT_STRING_EQUAL_FATAL(actual,expected) do {              \
    const char *_a = (actual), *_e = (expected);                        \
    CU_assertFormatImplementation(!strcmp(_a?_a:"",_e?_e:""), __LINE__, \
        __FILE__, "", CU_TRUE,                                          \
        "CU_ASSERT_STRING_EQUAL_FATAL(%s=\"%s\",%s=\"%s\")",            \
        #actual, _a, #expected, _e);                                    \
} while(0)

#undef CU_ASSERT_STRING_NOT_EQUAL
#define CU_ASSERT_STRING_NOT_EQUAL(actual,expected) do {                \
    const char *_a = (actual), *_e = (expected);                        \
    CU_assertFormatImplementation(!!strcmp(_a?_a:"",_e?_e:""),          \
        __LINE__, __FILE__, "", CU_FALSE,                               \
        "CU_ASSERT_STRING_NOT_EQUAL(%s=\"%s\",%s=\"%s\")",              \
        #actual, _a, #expected, _e);                                    \
} while(0)

#undef CU_ASSERT_STRING_NOT_EQUAL_FATAL
#define CU_ASSERT_STRING_NOT_EQUAL_FATAL(actual,expected) do {          \
    const char *_a = (actual), *_e = (expected);                        \
    CU_assertFormatImplementation(!!strcmp(_a?_a:"",_e?_e:""),          \
        __LINE__, __FILE__, "", CU_TRUE,                                \
        "CU_ASSERT_STRING_NOT_EQUAL_FATAL(%s=\"%s\",%s=\"%s\")",        \
        #actual, _a, #expected, _e);                                    \
} while(0)

#define CU_SYSLOG_MATCH(re) \
    CU_syslogMatchBegin((re), __FILE__, __LINE__)

#define CU_ASSERT_SYSLOG(match, expected) do {                          \
    const char *_s = NULL; unsigned int _e = (expected),                \
    _a = CU_syslogMatchEnd((match), &_s);                               \
    CU_assertFormatImplementation((_a == _e), __LINE__,                 \
        __FILE__, "", CU_FALSE,                                         \
        "CU_ASSERT_SYSLOG(/%s/=%u, %s=%u)",                             \
        _s, _a, #expected, _e);                                         \
} while(0)

#define CU_ASSERT_SYSLOG_FATAL(match, expected) do {                    \
    const char *_s = NULL; unsigned int _e = (expected),                \
    _a = CU_syslogMatchEnd((match), &_s);                               \
    CU_assertFormatImplementation((_a == _e), __LINE__,                 \
        __FILE__, "", CU_TRUE,                                          \
        "CU_ASSERT_SYSLOG_FATAL(/%s/=%u, %s=%u)",                       \
        _s, _a, #expected, _e);                                         \
} while(0)

extern jmp_buf fatal_jbuf;
extern int fatal_expected;
extern char *fatal_string;
extern int fatal_code;

#define CU_EXPECT_CYRFATAL_BEGIN                                \
do {                                                            \
    fatal_expected = 1;                                         \
    if (fatal_string) free(fatal_string);                       \
    fatal_string = NULL;                                        \
    fatal_code = 0;                                             \
    if (!setjmp(fatal_jbuf)) {                                  \
        /* code that we expect to call fatal() */

#define CU_EXPECT_CYRFATAL_END(expected_code, expected_string)  \
        CU_FAIL_FATAL("fatal codepath didn't call fatal");      \
    } else {                                                    \
        int _ec = (expected_code);                              \
        const char *_es = (expected_string);                    \
        CU_ASSERT_EQUAL(fatal_code, _ec);                       \
        if (_es) CU_ASSERT_STRING_EQUAL(fatal_string, _es);     \
        if (fatal_string) free(fatal_string);                   \
        fatal_string = NULL;                                    \
}   } while (0)


/* for parametrised tests */

#define CUNIT_PARAM(x)      (x)

struct cunit_param
{
    /* initialisation state */
    const char *name;
    char **variable;
    /* iteration state */
    int nvalues;
    char **values;
    int idx;
    char *freeme1;
};
#define __CUNIT_DECLARE_PARAM(nm) \
    { #nm, &nm, 0, NULL, 0, NULL }
#define __CUNIT_LAST_PARAM \
    { NULL, NULL, 0, NULL, 0, NULL }

extern void __cunit_params_begin(struct cunit_param *);
extern int __cunit_params_next(struct cunit_param *);
extern void __cunit_params_end(void);

#endif /* INCLUDED_CUNIT_H */
