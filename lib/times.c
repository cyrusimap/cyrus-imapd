/* times.c -- Time/date utilities
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
 *
 * $Id: rfc822date.c,v 1.8 2010/01/06 17:01:47 murch Exp $
 */

#include <stdio.h>
#include <memory.h>
#include <ctype.h>

#include "assert.h"
#include "times.h"
#include "util.h"
#include "gmtoff.h"
#include "mkgmtime.h"

static char *month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

static char *wday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

/* 'buf' must be at least 80 characters */
void rfc822date_gen(char *buf, size_t len, time_t t)
{
    struct tm *tm;
    long gmtoff;
    int gmtnegative = 0;

    assert(buf != NULL);

    tm = localtime(&t);
    gmtoff = gmtoff_of(tm, t);
    if (gmtoff < 0) {
	gmtoff = -gmtoff;
	gmtnegative = 1;
    }
    gmtoff /= 60;

    snprintf(buf, len, "%s, %02d %s %4d %02d:%02d:%02d %c%.2lu%.2lu",
	     wday[tm->tm_wday], 
	     tm->tm_mday, month[tm->tm_mon], tm->tm_year + 1900,
	     tm->tm_hour, tm->tm_min, tm->tm_sec,
	     gmtnegative ? '-' : '+', gmtoff / 60, gmtoff % 60);
}

#define isleap(year) (!((year) % 4) && (((year) % 100) || !((year) % 400)))

/*
 * Parse an RFC 3339 = ISO 8601 format date-time string.
 * Returns: number of characters in @s consumed, or -1 on error.
 */
int time_from_iso8601(const char *s, time_t *tp)
{
    const char *origs = s;
    struct tm exp;
    int n, tm_off, leapday;
    static const int numdays[] = {
	31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };

    /* parse the ISO 8601 date/time */
    memset(&exp, 0, sizeof(struct tm));
    n = sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d", 
	       &exp.tm_year, &exp.tm_mon, &exp.tm_mday,
	       &exp.tm_hour, &exp.tm_min, &exp.tm_sec);
    if (n != 6)
	return -1;

    s += 19;
    if (*s == '.') {
	/* skip fractional secs */
	while (Uisdigit(*(++s)));
    }

    /* handle offset */
    switch (*s++) {
    case 'Z': tm_off = 0; break;
    case '-': tm_off = -1; break;
    case '+': tm_off = 1; break;
    default: return -1;
    }
    if (tm_off) {
	int tm_houroff, tm_minoff;

	n = sscanf(s, "%2d:%2d", &tm_houroff, &tm_minoff);
	if (n != 2)
	    return -1;
	tm_off *= 60 * (60 * tm_houroff + tm_minoff);
	s += 5;
    }

    exp.tm_year -= 1900; /* normalize to years since 1900 */
    exp.tm_mon--; /* normalize to months since January */

    /* sanity check the date/time (including leap day & second) */
    leapday = exp.tm_mon == 1 && isleap(exp.tm_year + 1900);
    if (exp.tm_year < 70 || exp.tm_mon < 0 || exp.tm_mon > 11 ||
	exp.tm_mday < 1 ||
	exp.tm_mday > (numdays[exp.tm_mon] + leapday) ||
	exp.tm_hour > 23 || exp.tm_min > 59 || exp.tm_sec > 60) {
	return -1;
    }

    /* normalize to GMT */
    *tp = mkgmtime(&exp) - tm_off;
    return s - origs;
}

/*
 * Generate an RFC 3339 = ISO 8601 format date-time string
 * in Zulu (UTC).  The format supports an encoded offset,
 * but we don't generate that here.
 *
 * Returns: number of characters in @buf generated, or -1 on error.
 */
int time_to_iso8601(time_t t, char *buf, size_t len)
{
    struct tm *exp = (struct tm *) gmtime(&t);
    return strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", exp);
}
