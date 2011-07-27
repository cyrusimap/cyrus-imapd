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
#include "times.h"

#define TZ_UTC		"UTC+00"
#define TZ_NEWYORK	"EST+05"
#define TZ_MELBOURNE	"AEST-11"

#define UNINIT_TIMET ((time_t)0xdeadbeef)

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

static int set_up(void)
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

static int tear_down(void)
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
    t = UNINIT_TIMET;
    r = time_from_rfc3501("15-Oct-2010 03:19:52 +1100", &t);
    CU_ASSERT_EQUAL(r, 26);
    CU_ASSERT_EQUAL(t, 1287073192);

    /* Well-formed full RFC3501 format with 1-digit day
     * " d-mmm-yyyy HH:MM:SS zzzzz" */
    t = UNINIT_TIMET;
    r = time_from_rfc3501(" 5-Oct-2010 03:19:52 +1100", &t);
    CU_ASSERT_EQUAL(r, 26);
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
    t = UNINIT_TIMET;
    r = time_from_rfc3501("15-Oct-95 03:19:52-Z", &t);
    CU_ASSERT_EQUAL(r, 20);
    CU_ASSERT_EQUAL(t, zulu);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * lowercase 1-char timezone = UTC, "dd-mmm-yy HH:MM:SS-z" */
    t = UNINIT_TIMET;
    r = time_from_rfc3501("15-Oct-95 03:19:52-z", &t);
    CU_ASSERT_EQUAL(r, 20);
    CU_ASSERT_EQUAL(t, zulu);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * uppercase 1-char timezone = +0100, "dd-mmm-yy HH:MM:SS-z" */
    t = UNINIT_TIMET;
    r = time_from_rfc3501("15-Oct-95 03:19:52-A", &t);
    CU_ASSERT_EQUAL(r, 20);
    CU_ASSERT_EQUAL(t, zulu-1*3600);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * uppercase 1-char timezone = +0200, "dd-mmm-yy HH:MM:SS-z" */
    t = UNINIT_TIMET;
    r = time_from_rfc3501("15-Oct-95 03:19:52-B", &t);
    CU_ASSERT_EQUAL(r, 20);
    CU_ASSERT_EQUAL(t, zulu-2*3600);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * uppercase 1-char timezone = +0900, "dd-mmm-yy HH:MM:SS-z" */
    t = UNINIT_TIMET;
    r = time_from_rfc3501("15-Oct-95 03:19:52-I", &t);
    CU_ASSERT_EQUAL(r, 20);
    CU_ASSERT_EQUAL(t, zulu-9*3600);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * erroneous uppercase 1-char timezone, "dd-mmm-yy HH:MM:SS-z" */
    t = UNINIT_TIMET;
    r = time_from_rfc3501("15-Oct-95 03:19:52-J", &t);
    CU_ASSERT_EQUAL(r, -1);
    CU_ASSERT_EQUAL(t, UNINIT_TIMET);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * uppercase 1-char timezone = +1000, "dd-mmm-yy HH:MM:SS-z" */
    t = UNINIT_TIMET;
    r = time_from_rfc3501("15-Oct-95 03:19:52-K", &t);
    CU_ASSERT_EQUAL(r, 20);
    CU_ASSERT_EQUAL(t, zulu-10*3600);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * 1-char timezone = +1200, "dd-mmm-yy HH:MM:SS-z" */
    t = UNINIT_TIMET;
    r = time_from_rfc3501("15-Oct-95 03:19:52-M", &t);
    CU_ASSERT_EQUAL(r, 20);
    CU_ASSERT_EQUAL(t, zulu-12*3600);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * uppercase 1-char timezone = -0100, "dd-mmm-yy HH:MM:SS-z" */
    t = UNINIT_TIMET;
    r = time_from_rfc3501("15-Oct-95 03:19:52-N", &t);
    CU_ASSERT_EQUAL(r, 20);
    CU_ASSERT_EQUAL(t, zulu+1*3600);

    /* Well-formed legacy format with 2-digit day, 2-digit year,
     * 1-char timezone = -1200, "dd-mmm-yy HH:MM:SS-z" */
    t = UNINIT_TIMET;
    r = time_from_rfc3501("15-Oct-95 03:19:52-Y", &t);
    CU_ASSERT_EQUAL(r, 20);
    CU_ASSERT_EQUAL(t, zulu+12*3600);
}

/*  " d-mmm-yy HH:MM:SS-z" */
/*  "dd-mmm-yy HH:MM:SS-zz" */
/*  " d-mmm-yy HH:MM:SS-zz" */
/*  "dd-mmm-yy HH:MM:SS-zzz" */
/*  " d-mmm-yy HH:MM:SS-zzz" */

/*
 * Test time_from_rfc822()
 */
static void test_parse_rfc822(void)
{
    static const char DATETIME[] = "Tue, 16 Nov 2010 12:46:49 +1100";
    static const time_t TIMET = 1289872009;
    time_t t;
    int r;

    /*
     * Convert the datetime string into a time_t, which is always
     * expressed in UTC regardless of the current timezone.
     */
    t = UNINIT_TIMET;
    r = time_from_rfc822(DATETIME, &t);
    CU_ASSERT_EQUAL(r, 31);
    CU_ASSERT_EQUAL(t, TIMET);

    push_tz(TZ_UTC);
    t = UNINIT_TIMET;
    r = time_from_rfc822(DATETIME, &t);
    CU_ASSERT_EQUAL(r, 31);
    CU_ASSERT_EQUAL(t, TIMET);
    pop_tz();

    push_tz(TZ_NEWYORK);
    t = UNINIT_TIMET;
    r = time_from_rfc822(DATETIME, &t);
    CU_ASSERT_EQUAL(r, 31);
    CU_ASSERT_EQUAL(t, TIMET);
    pop_tz();
}

/*
 * Test time_to_rfc822()
 */
static void test_gen_rfc822(void)
{
    static const char DATETIME_MEL[] = "Fri, 26 Nov 2010 14:22:02 +1100";
    static const char DATETIME_UTC[] = "Fri, 26 Nov 2010 03:22:02 +0000";
    static const char DATETIME_NYC[] = "Thu, 25 Nov 2010 22:22:02 -0500";
    static const time_t TIMET = 1290741722;
    int r;
    char buf[RFC822_DATETIME_MAX+1];

    memset(buf, 0x45, sizeof(buf));
    r = time_to_rfc822(TIMET, buf, sizeof(buf));
    CU_ASSERT_EQUAL(r, 31);
    CU_ASSERT_STRING_EQUAL(buf, DATETIME_MEL);

    push_tz(TZ_UTC);
    memset(buf, 0x45, sizeof(buf));
    r = time_to_rfc822(TIMET, buf, sizeof(buf));
    CU_ASSERT_EQUAL(r, 31);
    CU_ASSERT_STRING_EQUAL(buf, DATETIME_UTC);
    pop_tz();

    push_tz(TZ_NEWYORK);
    memset(buf, 0x45, sizeof(buf));
    r = time_to_rfc822(TIMET, buf, sizeof(buf));
    CU_ASSERT_EQUAL(r, 31);
    CU_ASSERT_STRING_EQUAL(buf, DATETIME_NYC);
    pop_tz();
}


static void test_ctime(void)
{
    static const char DATETIME[] = "16-Nov-2010 13:15:25 +1100";
    static const time_t TIMET = 1289873725;
    char buf[RFC3501_DATETIME_MAX+1];

    memset(buf, 0, sizeof(buf));
    time_to_rfc3501(TIMET, buf, sizeof(buf));
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
    int r;
    char buf[RFC3501_DATETIME_MAX+1];

    t = UNINIT_TIMET;
    r = time_from_rfc822(DATETIME_NY, &t);
    CU_ASSERT_EQUAL(r, -1);
    CU_ASSERT_EQUAL(t, UNINIT_TIMET);  /* fail gracefully */

    push_tz(TZ_UTC);
    t = UNINIT_TIMET;
    r = time_from_rfc822(DATETIME_NY, &t);
    CU_ASSERT_EQUAL(r, -1);
    CU_ASSERT_EQUAL(t, UNINIT_TIMET);  /* fail gracefully */
    pop_tz();

    push_tz(TZ_NEWYORK);
    t = UNINIT_TIMET;
    r = time_from_rfc822(DATETIME_NY, &t);
    CU_ASSERT_EQUAL(r, -1);
    CU_ASSERT_EQUAL(t, UNINIT_TIMET);  /* fail gracefully */
    pop_tz();

    memset(buf, 0, sizeof(buf));
    time_to_rfc3501(TIMET, buf, sizeof(buf));
    CU_ASSERT_STRING_EQUAL(buf, DATETIME_MEL);
}

static void
test_parse_iso8601(void)
{
    static const char DATETIME_MEL[] = "2010-11-26T14:22:02+11:00";
    static const char DATETIME_UTC[] = "2010-11-26T03:22:02Z";
    static const char DATETIME_NYC[] = "2010-11-25T22:22:02-05:00";
    static const time_t TIMET = 1290741722;
    time_t t;
    int r;

    t = UNINIT_TIMET;
    r = time_from_iso8601(DATETIME_MEL, &t);
    CU_ASSERT_EQUAL(r, 25);
    CU_ASSERT_EQUAL(t, TIMET);

    t = UNINIT_TIMET;
    r = time_from_iso8601(DATETIME_UTC, &t);
    CU_ASSERT_EQUAL(r, 20);
    CU_ASSERT_EQUAL(t, TIMET);

    t = UNINIT_TIMET;
    r = time_from_iso8601(DATETIME_NYC, &t);
    CU_ASSERT_EQUAL(r, 25);
    CU_ASSERT_EQUAL(t, TIMET);
}

static void
test_gen_iso8601(void)
{
    static const char DATETIME_UTC[] = "2010-11-26T03:22:02Z";
    static const time_t TIMET = 1290741722;
    char buf[30];
    int r;

    r = time_to_iso8601(TIMET, buf, sizeof(buf));
    CU_ASSERT_EQUAL(r, 20);
    CU_ASSERT_STRING_EQUAL(buf, DATETIME_UTC);
}

/* Test that the 29 Feb works in some actual leap years,
 * and not in some not-leap years */
static void
test_leapyear_rfc3501(void)
{
    /* 2000 is a leapyear */
    static const char FEB2000_STR[] = "29-Feb-2000 11:22:33 +1100";
    static const time_t FEB2000_TIMET = 951783753;
    /* 2001 is not a leapyear */
    static const char FEB2001_STR[] = "29-Feb-2001 11:22:33 +1100";
    /* 2004 is a leapyear */
    static const char FEB2004_STR[] = "29-Feb-2004 11:22:33 +1100";
    static const time_t FEB2004_TIMET = 1078014153;
    time_t t;
    int r;

    t = UNINIT_TIMET;
    r = time_from_rfc3501(FEB2000_STR, &t);
    CU_ASSERT_EQUAL(r, 26);
    CU_ASSERT_EQUAL(t, FEB2000_TIMET);

    t = UNINIT_TIMET;
    r = time_from_rfc3501(FEB2001_STR, &t);
    CU_ASSERT_EQUAL(r, -1);
    CU_ASSERT_EQUAL(t, UNINIT_TIMET);

    t = UNINIT_TIMET;
    r = time_from_rfc3501(FEB2004_STR, &t);
    CU_ASSERT_EQUAL(r, 26);
    CU_ASSERT_EQUAL(t, FEB2004_TIMET);
}

static void
test_leapyear_iso8601(void)
{
    /* 2000 is a leapyear */
    static const char FEB2000_STR[] = "2000-02-29T11:22:33+11:00";
    static const time_t FEB2000_TIMET = 951783753;
    /* 2001 is not a leapyear */
    static const char FEB2001_STR[] = "2001-02-29T11:22:33+11:00";
    /* 2004 is a leapyear */
    static const char FEB2004_STR[] = "2004-02-29T11:22:33+11:00";
    static const time_t FEB2004_TIMET = 1078014153;
    time_t t;
    int r;

    t = UNINIT_TIMET;
    r = time_from_iso8601(FEB2000_STR, &t);
    CU_ASSERT_EQUAL(r, 25);
    CU_ASSERT_EQUAL(t, FEB2000_TIMET);

    t = UNINIT_TIMET;
    r = time_from_iso8601(FEB2001_STR, &t);
    CU_ASSERT_EQUAL(r, -1);
    CU_ASSERT_EQUAL(t, UNINIT_TIMET);

    t = UNINIT_TIMET;
    r = time_from_iso8601(FEB2004_STR, &t);
    CU_ASSERT_EQUAL(r, 25);
    CU_ASSERT_EQUAL(t, FEB2004_TIMET);
}

static void
test_leapyear_rfc822(void)
{
    /* 2000 is a leapyear */
    static const char FEB2000_STR[] = "Tue, 29 Feb 2000 11:22:33 +1100";
    static const time_t FEB2000_TIMET = 951783753;
    /* 2001 is not a leapyear */
    static const char FEB2001_STR[] = "Thu, 29 Feb 2001 11:22:33 +1100";
    /* 2004 is a leapyear */
    static const char FEB2004_STR[] = "Sun, 29 Feb 2004 11:22:33 +1100";
    static const time_t FEB2004_TIMET = 1078014153;
    time_t t;
    int r;

    t = UNINIT_TIMET;
    r = time_from_rfc822(FEB2000_STR, &t);
    CU_ASSERT_EQUAL(r, 31);
    CU_ASSERT_EQUAL(t, FEB2000_TIMET);

    t = UNINIT_TIMET;
    r = time_from_rfc822(FEB2001_STR, &t);
    CU_ASSERT_EQUAL(r, -1);
    CU_ASSERT_EQUAL(t, UNINIT_TIMET);

    t = UNINIT_TIMET;
    r = time_from_rfc822(FEB2004_STR, &t);
    CU_ASSERT_EQUAL(r, 31);
    CU_ASSERT_EQUAL(t, FEB2004_TIMET);
}
