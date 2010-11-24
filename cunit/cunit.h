/* cunit.h - wrapper for CUnit assert macros
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

extern int verbose;

/*
 * The standard CUnit assertion *EQUAL* macros have a flaw: they do
 * not report the actual values of the 'actual' and 'expected' values,
 * which makes it rather hard to see why an assertion failed.  So we
 * replace the macros with improved ones, keeping the same API.
 */
static CU_BOOL CU_assertFormatImplementation(
    CU_BOOL bValue,
    unsigned int uiLine,
    char strFile[],
    char strFunction[],
    CU_BOOL bFatal,
    char strConditionFormat[],
    ...)
{
    va_list args;
    char buf[1024];

    va_start(args, strConditionFormat);
    vsnprintf(buf, sizeof(buf), strConditionFormat, args);
    va_end(args);

    if (verbose > 1 && bValue)
	fprintf(stderr, "    %s:%u %s\n", strFile, uiLine, buf);

    return CU_assertImplementation(bValue, uiLine, buf, strFile, strFunction, bFatal);
}

#undef CU_ASSERT_EQUAL
#define CU_ASSERT_EQUAL(actual,expected) \
  { long long _a = (actual), _e = (expected); \
    CU_assertFormatImplementation((_a == _e), __LINE__, \
     __FILE__, "", CU_FALSE, \
    "CU_ASSERT_EQUAL(" #actual "=%lld," #expected "=%lld)", _a, _e); }

#undef CU_ASSERT_EQUAL_FATAL
#define CU_ASSERT_EQUAL_FATAL(actual,expected) \
  { long long _a = (actual), _e = (expected); \
    CU_assertFormatImplementation((_a == _e), __LINE__, \
     __FILE__, "", CU_TRUE, \
    "CU_ASSERT_EQUAL_FATAL(" #actual "=%lld," #expected "=%lld)", _a, _e); }

#undef CU_ASSERT_NOT_EQUAL
#define CU_ASSERT_NOT_EQUAL(actual,expected) \
  { long long _a = (actual), _e = (expected); \
    CU_assertFormatImplementation((_a != _e), __LINE__, \
     __FILE__, "", CU_FALSE, \
    "CU_ASSERT_NOT_EQUAL(" #actual "=%lld," #expected "=%lld)", _a, _e); }

#undef CU_ASSERT_NOT_EQUAL_FATAL
#define CU_ASSERT_NOT_EQUAL_FATAL(actual,expected) \
  { long long _a = (actual), _e = (expected); \
    CU_assertFormatImplementation((_a != _e), __LINE__, \
     __FILE__, "", CU_TRUE, \
    "CU_ASSERT_NOT_EQUAL_FATAL(" #actual "=%lld," #expected "=%lld)", _a, _e); }



#undef CU_ASSERT_PTR_EQUAL
#define CU_ASSERT_PTR_EQUAL(actual,expected) \
  { void *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation((_a == _e), __LINE__, \
     __FILE__, "", CU_FALSE, \
    "CU_ASSERT_PTR_EQUAL(" #actual "=%p," #expected "=%p)", _a, _e); }

#undef CU_ASSERT_PTR_EQUAL_FATAL
#define CU_ASSERT_PTR_EQUAL_FATAL(actual,expected) \
  { void *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation((_a == _e), __LINE__, \
     __FILE__, "", CU_TRUE, \
    "CU_ASSERT_PTR_EQUAL_FATAL(" #actual "=%p," #expected "=%p)", _a, _e); }

#undef CU_ASSERT_PTR_NOT_EQUAL
#define CU_ASSERT_PTR_NOT_EQUAL(actual,expected) \
  { void *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation((_a != _e), __LINE__, \
     __FILE__, "", CU_FALSE, \
    "CU_ASSERT_PTR_NOT_EQUAL(" #actual "=%p," #expected "=%p)", _a, _e); }

#undef CU_ASSERT_PTR_NOT_EQUAL_FATAL
#define CU_ASSERT_PTR_NOT_EQUAL_FATAL(actual,expected) \
  { void *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation((_a != _e), __LINE__, \
     __FILE__, "", CU_TRUE, \
    "CU_ASSERT_PTR_NOT_EQUAL_FATAL(" #actual "=%p," #expected "=%p)", _a, _e); }


#undef CU_ASSERT_STRING_EQUAL
#define CU_ASSERT_STRING_EQUAL(actual,expected) \
  { const char *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation(!strcmp(_a?_a:"",_e?_e:""), __LINE__, \
     __FILE__, "", CU_FALSE, \
    "CU_ASSERT_STRING_EQUAL(" #actual "=\"%s\"," #expected "=\"%s\")", _a, _e); }

#undef CU_ASSERT_STRING_EQUAL_FATAL
#define CU_ASSERT_STRING_EQUAL_FATAL(actual,expected) \
  { const char *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation(!strcmp(_a?_a:"",_e?_e:""), __LINE__, \
     __FILE__, "", CU_TRUE, \
    "CU_ASSERT_STRING_EQUAL_FATAL(" #actual "=\"%s\"," #expected "=\"%s\")", _a, _e); }

#undef CU_ASSERT_STRING_NOT_EQUAL
#define CU_ASSERT_STRING_NOT_EQUAL(actual,expected) \
  { const char *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation(!!strcmp(_a?_a:"",_e?_e:""), __LINE__, \
     __FILE__, "", CU_FALSE, \
    "CU_ASSERT_STRING_NOT_EQUAL(" #actual "=\"%s\"," #expected "=\"%s\")", _a, _e); }

#undef CU_ASSERT_STRING_NOT_EQUAL_FATAL
#define CU_ASSERT_STRING_NOT_EQUAL_FATAL(actual,expected) \
  { const char *_a = (actual), *_e = (expected); \
    CU_assertFormatImplementation(!!strcmp(_a?_a:"",_e?_e:""), __LINE__, \
     __FILE__, "", CU_TRUE, \
    "CU_ASSERT_STRING_NOT_EQUAL_FATAL(" #actual "=\"%s\"," #expected "=\"%s\")", _a, _e); }

#endif /* INCLUDED_CUNIT_H */
