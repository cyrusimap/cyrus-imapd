/* test_time.c -- regression test for cyrus time routines
 *
 * Copyright (c) 2010 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include "cunit/cunit.h"
#include "global.h"
#include "message.h"

#define TZ_UTC		"UTC+00.00"
#define TZ_NEWYORK	"EST+05.00"
#define TZ_MELBOURNE	"AEST-11.00"

#define MAX_TZ_STACK	5
static int n_tz_stack = 0;
static char *tz_stack[MAX_TZ_STACK];

static inline void xxputenv(char *s, const char *f)
{
    if (verbose > 1)
	fprintf(stderr, "\n%s:putenv(\"%s\")\n", f, s);
    putenv(s);
}
#define putenv(s) xxputenv((s), __FUNCTION__)

static char *stash_tz(const char *tz)
{
    char *s = malloc(4+(tz == NULL ? 0 : strlen(tz)));
    assert(s);
    sprintf(s, "TZ=%s", (tz == NULL ? "" : tz));
    assert(n_tz_stack < MAX_TZ_STACK-1);
    return tz_stack[n_tz_stack++] = s;
}

static void push_tz(const char *tz)
{
    if (n_tz_stack == 0)
	stash_tz(getenv("TZ"));
    putenv(stash_tz(tz));
    tzset();
}

static void pop_tz(void)
{
    char *old;
    assert(n_tz_stack > 1);
    old = tz_stack[--n_tz_stack];
    putenv(tz_stack[n_tz_stack-1]);
    tzset();
    free(old);
}

static int init(void)
{
    /*
     * Ensure that libc's idea of which timezone we're in is
     * predictable, in case any of the tests here depend on
     * it.  The timezone is faked up to simulate Australian
     * Eastern Standard time, only because I live there.
     */
    push_tz(TZ_MELBOURNE);
    return 0;
}

static int cleanup(void)
{
    pop_tz();
    if (n_tz_stack != 1)
	return -1;
    return 0;
}


static void
test_rfc3501(void)
{
    time_t t;
    int r;

    /* Well-formed full RFC3501 format with 2-digit day
     * "dd-mmm-yyyy HH:MM:SS zzzzz" */
    t = 0xdeadbeef;
    r = cyrus_parsetime("15-Oct-2010 03:19:52 +1100", &t);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(t, 1287073192);

    /* Well-formed full RFC3501 format with 1-digit day
     * " d-mmm-yyyy HH:MM:SS zzzzz" */
    t = 0xdeadbeef;
    r = cyrus_parsetime(" 5-Oct-2010 03:19:52 +1100", &t);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(t, 1286209192);
}

static void
test_military_timezones(void)
{
    time_t t;
    int r;
    time_t zulu = 813727192;

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * uppercase 1-char timezone = UTC, "dd-mmm-yy HH:MM:SS-z" */
    t = 0xdeadbeef;
    r = cyrus_parsetime("15-Oct-95 03:19:52-Z", &t);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(t, zulu);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * lowercase 1-char timezone = UTC, "dd-mmm-yy HH:MM:SS-z" */
    t = 0xdeadbeef;
    r = cyrus_parsetime("15-Oct-95 03:19:52-z", &t);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(t, zulu);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * uppercase 1-char timezone = +0100, "dd-mmm-yy HH:MM:SS-z" */
    t = 0xdeadbeef;
    r = cyrus_parsetime("15-Oct-95 03:19:52-A", &t);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(t, zulu-1*3600);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * uppercase 1-char timezone = +0200, "dd-mmm-yy HH:MM:SS-z" */
    t = 0xdeadbeef;
    r = cyrus_parsetime("15-Oct-95 03:19:52-B", &t);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(t, zulu-2*3600);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * uppercase 1-char timezone = +0900, "dd-mmm-yy HH:MM:SS-z" */
    t = 0xdeadbeef;
    r = cyrus_parsetime("15-Oct-95 03:19:52-I", &t);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(t, zulu-9*3600);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * erroneous uppercase 1-char timezone, "dd-mmm-yy HH:MM:SS-z" */
    t = 0xdeadbeef;
    r = cyrus_parsetime("15-Oct-95 03:19:52-J", &t);
    CU_ASSERT_EQUAL(r, -EINVAL);
    CU_ASSERT_EQUAL(t, 0xdeadbeef);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * uppercase 1-char timezone = +1000, "dd-mmm-yy HH:MM:SS-z" */
    t = 0xdeadbeef;
    r = cyrus_parsetime("15-Oct-95 03:19:52-K", &t);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(t, zulu-10*3600);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * 1-char timezone = +1200, "dd-mmm-yy HH:MM:SS-z" */
    t = 0xdeadbeef;
    r = cyrus_parsetime("15-Oct-95 03:19:52-M", &t);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(t, zulu-12*3600);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * uppercase 1-char timezone = -0100, "dd-mmm-yy HH:MM:SS-z" */
    t = 0xdeadbeef;
    r = cyrus_parsetime("15-Oct-95 03:19:52-N", &t);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(t, zulu+1*3600);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * 1-char timezone = -1200, "dd-mmm-yy HH:MM:SS-z" */
    t = 0xdeadbeef;
    r = cyrus_parsetime("15-Oct-95 03:19:52-Y", &t);
    CU_ASSERT_EQUAL(r, 0);
    CU_ASSERT_EQUAL(t, zulu+12*3600);
}

/*  " d-mmm-yy HH:MM:SS-z" */
/*  "dd-mmm-yy HH:MM:SS-zz" */
/*  " d-mmm-yy HH:MM:SS-zz" */
/*  "dd-mmm-yy HH:MM:SS-zzz" */
/*  " d-mmm-yy HH:MM:SS-zzz" */

/*
 * Test message_parse_date()
 */
static void test_parse_rfc822(void)
{
    static const char DATETIME[] = "Tue, 16 Nov 2010 12:46:49 +1100";
    static const time_t TIMET = 1289872009;
    time_t t;

    /*
     * Convert the datetime string into a time_t, which is always
     * expressed in UTC regardless of the current timezone.
     */
    t = message_parse_date(DATETIME, 0);
    CU_ASSERT_EQUAL(t, TIMET);

    push_tz(TZ_UTC);
    t = message_parse_date(DATETIME, 0);
    CU_ASSERT_EQUAL(t, TIMET);
    pop_tz();

    push_tz(TZ_NEWYORK);
    t = message_parse_date(DATETIME, 0);
    CU_ASSERT_EQUAL(t, TIMET);
    pop_tz();
}


static void test_ctime(void)
{
    static const char DATETIME[] = "16-Nov-2010 13:15:25 +1100";
    static const time_t TIMET = 1289873725;
    time_t t;
    char buf[30];

    memset(buf, 0, sizeof(buf));
    cyrus_ctime(TIMET, buf);
    CU_ASSERT_STRING_EQUAL(buf, DATETIME);
}


/*
 * Seen in the wild, generated by Apple Mail: a date
 * which is a valid UNIX time_t because it's in the first
 * hour of 1970 in UTC, but expressed in a timezone which
 * makes it be in the last day of 1969.  This is weird
 * and probably technically valid but does not need to
 * be supported, but we do need to fail gracefully.
 */
static void test_zerohour(void)
{
    static const char DATETIME_NY[] = "Wed, 31 Dec 1969 19:36:29 -0500";
    static const char DATETIME_MEL[] = " 1-Jan-1970 11:36:29 +1100";
    static const time_t TIMET = 2189;
    time_t t;
    char buf[30];

    t = message_parse_date(DATETIME_NY, 0);
    CU_ASSERT_EQUAL(t, 0);  /* fail gracefully */

    push_tz(TZ_UTC);
    t = message_parse_date(DATETIME_NY, 0);
    CU_ASSERT_EQUAL(t, 0);  /* fail gracefully */
    pop_tz();

    push_tz(TZ_NEWYORK);
    t = message_parse_date(DATETIME_NY, 0);
    CU_ASSERT_EQUAL(t, 0);  /* fail gracefully */
    pop_tz();

    memset(buf, 0, sizeof(buf));
    cyrus_ctime(TIMET, buf);
    CU_ASSERT_STRING_EQUAL(buf, DATETIME_MEL);
}
