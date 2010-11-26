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
#include <errno.h>
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


static const char * const monthname[12] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/* Convert a time_t date to an IMAP-style date
 * datebuf needs to be >= 30 bytes */
void cyrus_ctime(time_t date, char *datebuf) 
{
    struct tm *tm = localtime(&date);
    long gmtoff = gmtoff_of(tm, date);
    int gmtnegative = 0;

    assert(date > 0);
    assert(tm->tm_year >= 69);

    if (gmtoff < 0) {
	gmtoff = -gmtoff;
	gmtnegative = 1;
    }
    gmtoff /= 60;
    sprintf(datebuf,
	    "%2u-%s-%u %.2u:%.2u:%.2u %c%.2lu%.2lu",
	    tm->tm_mday, monthname[tm->tm_mon], tm->tm_year+1900,
	    tm->tm_hour, tm->tm_min, tm->tm_sec,
	    gmtnegative ? '-' : '+', gmtoff/60, gmtoff%60);
}


/*
 * Parse a string in IMAP date-time format (and some more
 * obscure legacy formats too) to a time_t.  Parses both
 * date and time parts.
 *
 * Specific formats accepted are listed below.  Note that only
 * the first two are compliant with RFC3501, the remainder
 * are legacy formats.  Note that the " quotes are not part
 * of the format, they're just used in this comment to show
 * where the leading spaces are.
 *
 *  "dd-mmm-yyyy HH:MM:SS zzzzz"
 *  " d-mmm-yyyy HH:MM:SS zzzzz"
 *  "dd-mmm-yy HH:MM:SS-z"
 *  " d-mmm-yy HH:MM:SS-z"
 *  "dd-mmm-yy HH:MM:SS-zz"
 *  " d-mmm-yy HH:MM:SS-zz"
 *  "dd-mmm-yy HH:MM:SS-zzz"
 *  " d-mmm-yy HH:MM:SS-zzz"
 *
 * where:
 *  dd	is the day-of-month between 1 and 31 inclusive.
 * mmm	is the three-letter abbreviation for the English
 *      month name (case insensitive).
 * yy	is the 2 digit year, between 00 (the year 1900)
 *	and 99 (the year 1999) inclusive.
 * yyyy is the 4 digit year, between 1900 and disaster
 *      (31b time_t wrapping in 2038 is not handled, sorry).
 * HH	is the hour, zero padded, between 00 and 23 inclusive.
 * MM 	is the minute, zero padded, between 00 and 59 inclusive.
 * MM 	is the second, zero padded, between 00 and 60 inclusive
 *      (to account for leap seconds).
 * z	is a US military style single character time zone.
 *	    A (Alpha) is +0100 ... I (India) is +0900
 *	    J (Juliet) is not defined
 *	    K (Kilo) is +1000 ... M (Mike) is +1200
 *	    N (November) is -0100 ... Y (Yankee) is -1200
 *	    Z (Zulu) is UTC
 * zz	is the case-insensitive string "UT", denoting UTC time.
 * zzz	is a three-character case insensitive North American
 *	time zone name, one of the following (listed with the
 *	UTC offsets and comments):
 *	    AST	-0400	Atlantic Standard Time
 *	    ADT	-0300	Atlantic Daylight Time
 *	    EST	-0500	Eastern Standard Time
 *	    EDT	-0400	Eastern Daylight Time
 *	    CST	-0600	Central Standard Time
 *	    CDT	-0500	Central Daylight Time
 *	    MST	-0700	Mountain Standard Time
 *	    MDT	-0600	Mountain Daylight Time
 *	    PST	-0800	Pacific Standard Time
 *	    PDT	-0700	Pacific Daylight Time
 *	    YST	-0900	Yukon Standard Time
 *			(Obsolete, now AKST = Alaska S.T.)
 *	    YDT	-0800	Yukon Daylight Time
 *			(Obsolete, now AKDT = Alaska D.T.)
 *	    HST	-1000	Hawaiian Standard Time
 *			(Obsolete, now HAST = Hawaiian/Aleutian S.T.)
 *	    HDT	-0900	Hawaiian Daylight Time
 *			(Obsolete, now HADT = Hawaiian/Aleutian D.T.)
 *	    BST	-1100	Used in American Samoa & Midway Island
 *			(Obsolete, now SST = Samoa S.T.)
 *	    BDT	-1000	Nonsensical, standard time is used
 *			all year around in the SST territories.
 * zzzzz is an numeric time zone offset in the form +HHMM
 *	or -HMMM.
 *
 * Returns: 0 on success, or a negative errno on error.
 */
int cyrus_parsetime(const char *s, time_t *date)
{
    static const int max_monthdays[12] = {
	31, 29, 31, 30, 31, 30,
	31, 31, 30, 31, 30, 31
    };
    int c;
    struct tm tm;
    int old_format = 0;
    char month[4], zone[4], *p;
    time_t tmp_gmtime;
    int zone_off;   /* timezone offset in minutes */

    memset(&tm, 0, sizeof tm);

    /* Day of month */
    c = *s++;
    if (c == ' ')
	c = '0';
    else if (!isdigit(c))
	goto baddate;
    tm.tm_mday = c - '0';

    c = *s++;
    if (isdigit(c)) {
	tm.tm_mday = tm.tm_mday * 10 + c - '0';
	c = *s++;
	if (tm.tm_mday <= 0 || tm.tm_mday > 31)
	    goto baddate;
    }

    if (c != '-')
	goto baddate;
    c = *s++;

    /* Month name */
    if (!isalpha(c))
	goto baddate;
    month[0] = c;
    c = *s++;
    if (!isalpha(c))
	goto baddate;
    month[1] = c;
    c = *s++;
    if (!isalpha(c))
	goto baddate;
    month[2] = c;
    c = *s++;
    month[3] = '\0';

    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcasecmp(month, monthname[tm.tm_mon]))
	    break;
    }
    if (tm.tm_mon == 12)
	goto baddate;

    /* This works fine in leap years but allows false
     * negatives in the non-leap years.  */
    if (tm.tm_mday > max_monthdays[tm.tm_mon])
	goto baddate;

    if (c != '-')
	goto baddate;
    c = *s++;

    /* Year */
    if (!isdigit(c))
	goto baddate;
    tm.tm_year = c - '0';
    c = *s++;
    if (!isdigit(c))
	goto baddate;
    tm.tm_year = tm.tm_year * 10 + c - '0';
    c = *s++;
    if (isdigit(c)) {
	if (tm.tm_year < 19)
	    goto baddate;
	tm.tm_year -= 19;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = *s++;
	if (!isdigit(c))
	    goto baddate;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = *s++;
    }
    else
	old_format++;

    /* Hour */
    if (c != ' ')
	goto baddate;
    c = *s++;
    if (!isdigit(c))
	goto baddate;
    tm.tm_hour = c - '0';
    c = *s++;
    if (!isdigit(c))
	goto baddate;
    tm.tm_hour = tm.tm_hour * 10 + c - '0';
    c = *s++;
    if (tm.tm_hour > 23)
	goto baddate;

    /* Minute */
    if (c != ':')
	goto baddate;
    c = *s++;
    if (!isdigit(c))
	goto baddate;
    tm.tm_min = c - '0';
    c = *s++;
    if (!isdigit(c))
	goto baddate;
    tm.tm_min = tm.tm_min * 10 + c - '0';
    c = *s++;
    if (tm.tm_min > 59)
	goto baddate;

    /* Second */
    if (c != ':')
	goto baddate;
    c = *s++;
    if (!isdigit(c))
	goto baddate;
    tm.tm_sec = c - '0';
    c = *s++;
    if (!isdigit(c))
	goto baddate;
    tm.tm_sec = tm.tm_sec * 10 + c - '0';
    c = *s++;
    if (tm.tm_min > 60)
	goto baddate;

    /* Time zone */
    if (old_format) {
	if (c != '-')
	    goto baddate;
	c = *s++;

	if (!isalpha(c))
	    goto baddate;
	zone[0] = c;
	c = *s++;

	if (c == '\0') {
	    /* Military (single-char) zones */
	    zone[1] = '\0';
	    lcase(zone);
	    if (zone[0] <= 'i') {
		zone_off = (zone[0] - 'a' + 1)*60;
	    }
	    else if (zone[0] == 'j') {
		goto baddate;
	    }
	    else if (zone[0] <= 'm') {
		zone_off = (zone[0] - 'k' + 10)*60;
	    }
	    else if (zone[0] < 'z') {
		zone_off = ('m' - zone[0])*60;
	    }
	    else    /* 'z' */
		zone_off = 0;
	}
	else {
	    /* UT (universal time) */
	    zone[1] = c;
	    c = *s++;
	    if (c == '\0') {
		zone[2] = '\0';
		lcase(zone);
		if (!strcmp(zone, "ut"))
		    goto baddate;
		zone_off = 0;
	    }
	    else {
		/* 3-char time zone */
		zone[2] = c;
		c = *s++;
		if (c != '\0')
		    goto baddate;
		zone[3] = '\0';
		lcase(zone);
		p = strchr("aecmpyhb", zone[0]);
		if (c != '\0' || zone[2] != 't' || !p)
		    goto baddate;
		zone_off = (strlen(p) - 12)*60;
		if (zone[1] == 'd')
		    zone_off += 60;
		else if (zone[1] != 's')
		    goto baddate;
	    }
	}
    }
    else {
	if (c != ' ')
	    goto baddate;
	c = *s++;

	if (c != '+' && c != '-')
	    goto baddate;
	zone[0] = c;

	c = *s++;
	if (!isdigit(c))
	    goto baddate;
	zone_off = c - '0';
	c = *s++;
	if (!isdigit(c))
	    goto baddate;
	zone_off = zone_off * 10 + c - '0';
	c = *s++;
	if (!isdigit(c))
	    goto baddate;
	zone_off = zone_off * 6 + c - '0';
	c = *s++;
	if (!isdigit(c))
	    goto baddate;
	zone_off = zone_off * 10 + c - '0';

	if (zone[0] == '-')
	    zone_off = -zone_off;

	c = *s++;
	if (c != '\0')
	    goto baddate;
    }

    tm.tm_isdst = -1;

    tmp_gmtime = mkgmtime(&tm);
    if (tmp_gmtime == -1)
	goto baddate;

    *date = tmp_gmtime - zone_off*60;

    return 0;

baddate:
    return -EINVAL;
}

