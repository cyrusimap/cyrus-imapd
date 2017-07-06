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
 */

#include <ctype.h>
#include <memory.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "assert.h"
#include "times.h"
#include "util.h"
#include "gmtoff.h"
#include "mkgmtime.h"
#include "times-private.h"

static const char * const monthname[12] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};
static const char * const wday[7] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};


static int monthdays(int year/*since 1900*/, int month/*0-based*/)
{
    int leapday;
    static const int mdays[12] = {
        31, 28, 31, 30, 31, 30,
        31, 31, 30, 31, 30, 31
    };

#define isleap(year) (!((year) % 4) && (((year) % 100) || !((year) % 400)))
    leapday = (month == 1 && isleap(year+1900));
    return mdays[month] + leapday;
#undef isleap
}

/* 'buf' must be at least 80 characters */
EXPORTED int time_to_rfc822(time_t t, char *buf, size_t len)
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

    return snprintf(buf, len, "%s, %02d %s %4d %02d:%02d:%02d %c%.2lu%.2lu",
             wday[tm->tm_wday],
             tm->tm_mday, monthname[tm->tm_mon], tm->tm_year + 1900,
             tm->tm_hour, tm->tm_min, tm->tm_sec,
             gmtnegative ? '-' : '+', gmtoff / 60, gmtoff % 60);
}


/*
 * Skip RFC822 FWS = Folding White Space.  This is the white
 * space that can be inserted harmlessly into structured
 * RFC822 headers, including splitting them over multiple lines.
 *
 * Note that RFC822 isn't entirely clear about whether such
 * space may be present in date-times, but it's successor
 * RFC2822 is quite clear and explicit.  Note also that
 * neither RFC allows for (comments) inside a date-time,
 * so we don't attempt to handle that here.
 */
static const char *skip_fws(const char *p)
{
    if (!p)
        return NULL;
    while (*p && Uisspace(*p)) {
        /* check for end of an RFC822 header line */
        if (*p == '\n') {
            p++;
            if (*p != ' ' && *p != '\t')
                return NULL;
        }
        else
            p++;
    }
    return (*p ? p : NULL);
}

static int parse_rfc822(const char *s, time_t *tp, int dayonly)
{
    const char *origs = s;
    struct tm tm;
    time_t t;
    char month[4];
    int zone_off = 0;

    if (!s)
        goto baddate;

    memset(&tm, 0, sizeof(tm));

    s = skip_fws(s);
    if (!s)
        goto baddate;

    if (Uisalpha(*s)) {
        /* Day name -- skip over it */
        s++;
        if (!Uisalpha(*s))
            goto baddate;
        s++;
        if (!Uisalpha(*s))
            goto baddate;
        s++;
        s = skip_fws(s);
        if (!s || *s++ != ',')
            goto baddate;
        s = skip_fws(s);
        if (!s)
            goto baddate;
    }

    if (!Uisdigit(*s))
        goto baddate;
    tm.tm_mday = *s++ - '0';
    if (Uisdigit(*s)) {
        tm.tm_mday = tm.tm_mday*10 + *s++ - '0';
    }

    /* Parse month name */
    s = skip_fws(s);
    if (!s)
        goto baddate;
    month[0] = *s++;
    if (!Uisalpha(month[0]))
        goto baddate;
    month[1] = *s++;
    if (!Uisalpha(month[1]))
        goto baddate;
    month[2] = *s++;
    if (!Uisalpha(month[2]))
        goto baddate;
    month[3] = '\0';
    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
        if (!strcasecmp(month, monthname[tm.tm_mon])) break;
    }
    if (tm.tm_mon == 12)
        goto baddate;

    /* Parse year */
    s = skip_fws(s);
    if (!s || !Uisdigit(*s))
        goto baddate;
    tm.tm_year = *s++ - '0';
    if (!Uisdigit(*s))
        goto baddate;
    tm.tm_year = tm.tm_year * 10 + *s++ - '0';
    if (Uisdigit(*s)) {
        if (tm.tm_year < 19)
            goto baddate;
        tm.tm_year -= 19;
        tm.tm_year = tm.tm_year * 10 + *s++ - '0';
        if (!Uisdigit(*s))
            goto baddate;
        tm.tm_year = tm.tm_year * 10 + *s++ - '0';
    } else {
        if (tm.tm_year < 70) {
            /* two-digit year, probably after 2000.
             * This patent was overturned, right?
             */
            tm.tm_year += 100;
        }
    }
    if (Uisdigit(*s)) {
       /* five-digit date */
       goto baddate;
     }

    if (tm.tm_mday > monthdays(tm.tm_year, tm.tm_mon))
        goto baddate;

    s = skip_fws(s);
    if (s && !dayonly) {
        /* Parse hour */
        if (!s || !Uisdigit(*s))
            goto badtime;
        tm.tm_hour = *s++ - '0';
        if (!Uisdigit(*s))
            goto badtime;
        tm.tm_hour = tm.tm_hour * 10 + *s++ - '0';
        if (!s || *s++ != ':')
            goto badtime;

        /* Parse min */
        if (!s || !Uisdigit(*s))
            goto badtime;
        tm.tm_min = *s++ - '0';
        if (!Uisdigit(*s))
            goto badtime;
        tm.tm_min = tm.tm_min * 10 + *s++ - '0';

        if (*s == ':') {
            /* Parse sec */
            if (!++s || !Uisdigit(*s))
                goto badtime;
            tm.tm_sec = *s++ - '0';
            if (!Uisdigit(*s))
                goto badtime;
            tm.tm_sec = tm.tm_sec * 10 + *s++ - '0';
        }

        s = skip_fws(s);
        if (s) {
            /* Parse timezone offset */
            if (*s == '+' || *s == '-') {
                /* Parse numeric offset */
                int east = (*s++ == '-');

                if (!s || !Uisdigit(*s))
                    goto badzone;
                zone_off = *s++ - '0';
                if (!s || !Uisdigit(*s))
                    goto badzone;
                zone_off = zone_off * 10 + *s++ - '0';
                if (!s || !Uisdigit(*s))
                    goto badzone;
                zone_off = zone_off * 6 + *s++ - '0';
                if (!s || !Uisdigit(*s))
                    goto badzone;
                zone_off = zone_off * 10 + *s++ - '0';

                if (east)
                    zone_off = -zone_off;
            }
            else if (Uisalpha(*s)) {
                char zone[4];

                zone[0] = *s++;
                if (!Uisalpha(*s)) {
                    /* Parse military (single-char) zone */
                    zone[1] = '\0';
                    lcase(zone);
                    if (zone[0] < 'j')
                        zone_off = (zone[0] - 'a' + 1) * 60;
                    else if (zone[0] == 'j')
                        goto badzone;
                    else if (zone[0] <= 'm')
                        zone_off = (zone[0] - 'a') * 60;
                    else if (zone[0] < 'z')
                        zone_off = ('m' - zone[0]) * 60;
                    else
                        zone_off = 0;
                }
                else {
                    zone[1] = *s++;
                    if (!Uisalpha(*s)) {
                        /* Parse UT (universal time) */
                        zone[2] = '\0';
                        lcase(zone);
                        if (strcmp(zone, "ut"))
                            goto badzone;
                        zone_off = 0;
                    }
                    else {
                        /* Parse 3-char time zone */
                        char *p;

                        zone[2] = *s;
                        zone[3] = '\0';
                        lcase(zone);
                        /* GMT (Greenwich mean time) */
                        if (!strcmp(zone, "gmt"))
                            zone_off = 0;

                        /* US time zone */
                        else {
                            p = strchr("aecmpyhb", zone[0]);
                            if (!p || zone[2] != 't')
                                goto badzone;
                            zone_off = (strlen(p) - 12) * 60;
                            if (zone[1] == 'd')
                                zone_off += 60;
                            else if (zone[1] != 's')
                                goto badzone;
                        }
                    }
                }
            }
            else
 badzone:
                zone_off = 0;
        }
    }
    else
 badtime:
        tm.tm_hour = 12;

    tm.tm_isdst = -1;

    if (!dayonly)
        t = mkgmtime(&tm);
    else {
        assert(zone_off == 0);
        t = mktime(&tm);
    }
    if (t >= 0) {
        *tp = (t - zone_off * 60);
        return s - origs;
    }

 baddate:
    return -1;
}

/*
 * Parse an RFC822 (strictly speaking, RFC2822) date-time
 * from the @s into a UNIX time_t *@tp.  The string @s is
 * terminated either by a NUL or by an RFC822 end of header
 * line (CRLF not followed by whitespace); this allows
 * parsing dates directly out of mapped messages.
 *
 * Returns: number of characters consumed from @s or -1 on error.
 */
EXPORTED int time_from_rfc822(const char *s, time_t *tp)
{
    return parse_rfc822(s, tp, 0);
}

/*
 * Parse an RFC822 (strictly speaking, RFC2822) date-time
 * from the @s into a UNIX time_t *@tp, but parse only the
 * date portion, ignoring the time and timezone and returning
 * a time in the server's timezone.  This is a godawful hack
 * designed to support the Cyrus implementation of the
 * IMAP SEARCH command.
 *
 * Returns: number of characters consumed from @s or -1 on error.
 */
EXPORTED int day_from_rfc822(const char *s, time_t *tp)
{
    return parse_rfc822(s, tp, 1);
}

/*
 * Parse an RFC 3339 = ISO 8601 format date-time string.
 * Returns: number of characters in @s consumed, or -1 on error.
 */
EXPORTED int time_from_iso8601(const char *s, time_t *tp)
{
    const char *origs = s;
    struct tm exp;
    int n, tm_off;

    /* parse the ISO 8601 date/time */
    /* XXX should use strptime ? */
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
    if (exp.tm_year < 70 || exp.tm_mon < 0 || exp.tm_mon > 11 ||
        exp.tm_mday < 1 ||
        exp.tm_mday > monthdays(exp.tm_year, exp.tm_mon) ||
        exp.tm_hour > 23 || exp.tm_min > 59 || exp.tm_sec > 60) {
        return -1;
    }

    /* normalize to GMT */
    *tp = mkgmtime(&exp) - tm_off;
    return s - origs;
}

static int breakdown_time_to_iso8601(const struct timeval *t, struct tm *tm,
                                     enum timeval_precision tv_precision,
                                     char *buf, size_t len, int withsep)
{
    long gmtoff = gmtoff_of(tm, t->tv_sec);
    int gmtnegative = 0;
    size_t rlen;
    const char *datefmt = withsep ? "%Y-%m-%dT%H:%M:%S" : "%Y%m%dT%H%M%S";

    /*assert(date > 0); - it turns out these can happen, annoyingly enough */
    assert(tm->tm_year >= 69);

    if (gmtoff < 0) {
        gmtoff = -gmtoff;
        gmtnegative = 1;
    }
    gmtoff /= 60;

    rlen = strftime(buf, len, datefmt, tm);
    if (rlen > 0) {
        switch(tv_precision) {
        case timeval_ms:
            rlen += snprintf(buf+rlen, len-rlen, ".%.3lu", t->tv_usec/1000);
            break;
        case timeval_us:
            rlen += snprintf(buf+rlen, len-rlen, ".%.6lu", t->tv_usec);
            break;
        case timeval_s:
            break;
        }

        /* UTC can be written "Z" or "+00:00" */
        if ((gmtoff/60 == gmtoff%60) && (gmtoff/60 == 0))
            rlen += snprintf(buf+rlen, len-rlen, "Z");
        else
            rlen += snprintf(buf+rlen, len-rlen, "%c%.2lu:%.2lu",
                             gmtnegative ? '-' : '+', gmtoff/60, gmtoff%60);
    }

    return rlen;
}

/*
 * Generate an RFC 3339 = ISO 8601 format date-time string in Zulu (UTC).
 *
 * Returns: number of characters in @buf generated, or -1 on error.
 */
EXPORTED int time_to_iso8601(time_t t, char *buf, size_t len, int withsep)
{
    struct tm *tm = (struct tm *) gmtime(&t);
    struct timeval tv = { t, 0 };

    return breakdown_time_to_iso8601(&tv, tm, timeval_s, buf, len, withsep);
}

/*
 * Generate an RFC 3339 = ISO 8601 format date-time string in local time with
 * offset from UTC and fractions of second.
 *
 * Returns: number of characters in @buf generated, or -1 on error.
 */
EXPORTED int timeval_to_iso8601(const struct timeval *tv, enum timeval_precision tv_prec,
                       char *buf, size_t len)
{
    struct tm *tm = localtime(&(tv->tv_sec));
    return breakdown_time_to_iso8601(tv, tm, tv_prec, buf, len, 1);
}

EXPORTED int time_to_rfc3339(time_t t, char *buf, size_t len)
{
    struct tm *tm = gmtime(&t);

    return snprintf(buf, len, "%4d-%02d-%02dT%02d:%02d:%02dZ",
                    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                    tm->tm_hour, tm->tm_min, tm->tm_sec);
}

/*
 * Convert a time_t date to an IMAP-style date
 * datebuf needs to be >= 30 bytes.
 *
 * Returns: number of characters in @buf generated, or -1 on error.
 */
EXPORTED int time_to_rfc3501(time_t date, char *buf, size_t len)
{
    struct tm *tm = localtime(&date);
    long gmtoff = gmtoff_of(tm, date);
    int gmtnegative = 0;

    /*assert(date > 0); - it turns out these can happen, annoyingly enough */
    assert(tm->tm_year >= 69);

    if (gmtoff < 0) {
        gmtoff = -gmtoff;
        gmtnegative = 1;
    }
    gmtoff /= 60;
    return snprintf(buf, len,
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
 *  dd  is the day-of-month between 1 and 31 inclusive.
 * mmm  is the three-letter abbreviation for the English
 *      month name (case insensitive).
 * yy   is the 2 digit year, between 00 (the year 1900)
 *      and 99 (the year 1999) inclusive.
 * yyyy is the 4 digit year, between 1900 and disaster
 *      (31b time_t wrapping in 2038 is not handled, sorry).
 * HH   is the hour, zero padded, between 00 and 23 inclusive.
 * MM   is the minute, zero padded, between 00 and 59 inclusive.
 * MM   is the second, zero padded, between 00 and 60 inclusive
 *      (to account for leap seconds).
 * z    is a US military style single character time zone.
 *          A (Alpha) is +0100 ... I (India) is +0900
 *          J (Juliet) is not defined
 *          K (Kilo) is +1000 ... M (Mike) is +1200
 *          N (November) is -0100 ... Y (Yankee) is -1200
 *          Z (Zulu) is UTC
 * zz   is the case-insensitive string "UT", denoting UTC time.
 * zzz  is a three-character case insensitive North American
 *      time zone name, one of the following (listed with the
 *      UTC offsets and comments):
 *          AST -0400   Atlantic Standard Time
 *          ADT -0300   Atlantic Daylight Time
 *          EST -0500   Eastern Standard Time
 *          EDT -0400   Eastern Daylight Time
 *          CST -0600   Central Standard Time
 *          CDT -0500   Central Daylight Time
 *          MST -0700   Mountain Standard Time
 *          MDT -0600   Mountain Daylight Time
 *          PST -0800   Pacific Standard Time
 *          PDT -0700   Pacific Daylight Time
 *          YST -0900   Yukon Standard Time
 *                      (Obsolete, now AKST = Alaska S.T.)
 *          YDT -0800   Yukon Daylight Time
 *                      (Obsolete, now AKDT = Alaska D.T.)
 *          HST -1000   Hawaiian Standard Time
 *                      (Obsolete, now HAST = Hawaiian/Aleutian S.T.)
 *          HDT -0900   Hawaiian Daylight Time
 *                      (Obsolete, now HADT = Hawaiian/Aleutian D.T.)
 *          BST -1100   Used in American Samoa & Midway Island
 *                      (Obsolete, now SST = Samoa S.T.)
 *          BDT -1000   Nonsensical, standard time is used
 *                      all year around in the SST territories.
 * zzzzz is an numeric time zone offset in the form +HHMM
 *      or -HMMM.
 *
 * Returns: Number of characters consumed from @s on success,
 *          or -1 on error.
 */
EXPORTED int time_from_rfc3501(const char *s, time_t *date)
{
    const char *origs = s;
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

    if (tm.tm_mday > monthdays(tm.tm_year, tm.tm_mon))
        goto baddate;

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

    return s-1 - origs;

baddate:
    return -1;
}

/**
 ** Support functions for time_from_rfc5322()
 **/
static inline int get_next_char(struct rfc822dtbuf *buf)
{
    int c;

    if (buf->offset < buf->len) {
        buf->offset++;
        c = buf->str[buf->offset];
        return c;
    }

    return EOB;
}

static inline int get_current_char(struct rfc822dtbuf *buf)
{
    int offset = buf->offset;

    if (offset < buf->len)
        return buf->str[offset];
    else
        return EOB;
}

static inline int get_previous_char(struct rfc822dtbuf *buf)
{
    int offset = buf->offset;

    offset--;
    if (offset >= 0)
        return buf->str[offset];
    else
        return EOB;
}

/*
  TODO: Support comments as per RFC.
*/
static int skip_ws(struct rfc822dtbuf *buf, int skipcomment)
{
    int c = buf->str[buf->offset];

    while (c != EOB) {
        if (special[c]) {
            c = get_next_char(buf);
            continue;
        }

        break;
    }

    return 1;
}

static int get_next_token(struct rfc822dtbuf *buf, char **str, int *len)
{
    int c, ret = 1;
    long ch;
    static char cache[RFC5322_DATETIME_MAX];

    memset(cache, 1, RFC5322_DATETIME_MAX);

    c = get_current_char(buf);
    if (c == EOB) {
        ret = 0;
        goto failed;
    }

    *len = 0;
    for (;;) {
        if (special[c] || separators[c])
            break;

        ch = charset[c + 1];
        if (!(ch & (Alpha | Digit)))
            break;

        if (*len >= RFC5322_DATETIME_MAX)
            break;

        cache[*len] = c;
        *len += 1;

        c = get_next_char(buf);
        if (c == EOB) {
            ret = 0;
            break;
        }
    }

 failed:
    *str = cache;

    return ret;
}

static inline int to_int(char *str, int len)
{
    int i, num = 0;

    for (i = 0; i<len; i++) {
        if (charset[str[i] + 1] & Digit)
            num = num * 10 + (str[i] - '0');
        else {
            num = -9999;
            break;
        }
    }

    return num;
}

static inline int to_upper_str_in_place(char **str, int len)
{
    int i;

    for (i=0; i<len; i++) {
        int c = str[0][i];
        if (charset[c + 1] & LAlpha)
            str[0][i] = str[0][i] - 32;
    }

    return 1;
}

static inline int to_upper(char ch)
{
    if (charset[ch + 1] & LAlpha)
        ch =  ch - 32;

    return ch;
}

static inline int to_lower(char ch)
{
    if (charset[ch + 1] & UAlpha)
        ch = ch + 32;

    return ch;
}

static int compute_tzoffset(char *str, int len, int sign)
{
    int offset = 0;

    if (len == 1) {         /* Military timezone */
        int ch;
        ch = to_upper(str[0]);
        if (ch < 'J')
            return (str[0] - 'A' + 1) * 60;
        if (ch == 'J')
            return 0;
        if (ch <= 'M')
            return (str[0] - 'A') * 60;;
        if (ch < 'Z')
            return ('M' - str[0]) * 60;

        return 0;
    }

    if (len == 2 &&
        to_upper(str[0]) == 'U' &&
        to_upper(str[1]) == 'T') {         /* Universal Time zone (UT) */
        return 0;
    }

    if (len == 3) {
        char *p;

        if (to_upper(str[2]) != 'T')
            return 0;

        p = strchr("AECMPYHB", to_upper(str[0]));
        if (!p)
            return 0;
        offset = (strlen(p) - 12) *  60;

        if (to_upper(str[1]) == 'D')
            return offset + 60;
        if (to_upper(str[1]) == 'S')
            return offset;
    }

    if (len == 4) {         /* The number timezone offset */
        int i;

        for (i = 0; i<len; i++) {
            if (!(charset[str[i] + 1] & Digit))
                return 0;
        }

        offset = ((str[0] - '0') * 10 + (str[1] - '0')) * 60 +
            (str[2] - '0') * 10 +
            (str[3] - '0');

        return (sign == '+') ? offset : -offset;
    }

    return 0;
}

/*
 *  Date Format as per https://tools.ietf.org/html/rfc5322#section-3.3:
 *
 * date-time = [ ([FWS] day-name) "," ]
 *             ([FWS] 1*2DIGIT FWS)
 *             month
 *             (FWS 4*DIGIT FWS)
 *             2DIGIT ":" 2DIGIT [ ":" 2DIGIT ]
 *             (FWS ( "+" / "-" ) 4DIGIT)
 *             [CFWS]
 *
 * day-name = "Mon" / "Tue" / "Wed" / "Thu" / "Fri" / "Sat" / "Sun"
 * month = "Jan" / "Feb" / "Mar" / "Apr" / "May" / "Jun" / "Jul" / "Aug" /
 *         "Sep" / "Oct" / "Nov" / "Dec"
 *
 */

static int tokenise_str_and_create_tm(struct rfc822dtbuf *buf,
                                      struct tm *tm,
                                      int *tz_offset)
{
    long ch;
    int c, i, len;
    char *str_token = NULL;

    /* Skip leading WS, if any */
    skip_ws(buf, 0);

    c = get_current_char(buf);
    if (c == EOB)
        goto failed;

    ch = charset[c + 1];
    if (ch & Alpha) {       /* Most likely a weekday at the start. */
        if (!get_next_token(buf, &str_token, &len))
            goto failed;

        /* We might have a weekday token here, which we should skip*/
        if (len != 3)
            goto failed;

        /* The weekday is foll wed by a ',', consume that. */
        if (get_current_char(buf) == ',')
            get_next_char(buf);
        else
            goto failed;

        skip_ws(buf, 0);
    }

    /** DATE **/
    /* date (1 or 2 digits) */
    if (!get_next_token(buf, &str_token, &len))
        goto failed;

    if (len < 1 || len > 2 || !(charset[str_token[0] + 1] & Digit))
        goto failed;

    tm->tm_mday = to_int(str_token, len);
    if (tm->tm_mday == -9999)
        goto failed;

    /* month name */
    get_next_char(buf);     /* Consume a character, either a '-' or ' ' */

    if (!get_next_token(buf, &str_token, &len) ||
        len != 3 ||
        !(charset[str_token[0] + 1] & Alpha))
        goto failed;

    str_token[0] = to_upper(str_token[0]);
    str_token[1] = to_lower(str_token[1]);
    str_token[2] = to_lower(str_token[2]);
    for (i = 0; i < 12; i++) {
        if (memcmp(monthname[i], str_token, 3) == 0) {
            tm->tm_mon = i;
            break;
        }
    }
    if (i == 12)
        goto failed;

    /* year 2, 4 or >4 digits */
    get_next_char(buf);     /* Consume a character, either a '-' or ' ' */

    if (!get_next_token(buf, &str_token, &len))
        goto failed;

    tm->tm_year = to_int(str_token, len);
    if (tm->tm_year == -9999)
        goto failed;

    if (len == 2) {
        /* A 2 digit year */
        if (tm->tm_year < 70)
            tm->tm_year += 100;
    } else {
        if (tm->tm_year < 1900)
            goto failed;
        tm->tm_year -= 1900;
    }

    /** TIME **/
    skip_ws(buf, 0);
    /* hour */
    if (!get_next_token(buf, &str_token, &len))
        goto failed;

    if (len < 1 || len > 2 || !(charset[str_token[0] + 1] & Digit))
        goto failed;

    tm->tm_hour = to_int(str_token, len);
    if (tm->tm_hour == -9999)
        goto failed;

    /* minutes */
    if (get_current_char(buf) == ':' ||
        get_current_char(buf) == '.')
        get_next_char(buf); /* Consume ':'/'.' */
    else
        goto failed;    /* Something is broken */

    if (!get_next_token(buf, &str_token, &len))
        goto failed;

    if (len < 1 || len > 2 || !(charset[str_token[0] + 1] & Digit))
        goto failed;

    tm->tm_min = to_int(str_token, len);
    if (tm->tm_min == -9999)
        goto failed;


    /* seconds[optional] */
    if (get_current_char(buf) == ':' ||
        get_current_char(buf) == '.') {
        get_next_char(buf); /* Consume ':'/'.' */

        if (!get_next_token(buf, &str_token, &len))
            goto failed;

        if (len < 1 || len > 2 || !(charset[str_token[0] + 1] & Digit))
            goto failed;

        tm->tm_sec = to_int(str_token, len);
        if (tm->tm_sec == -9999)
            goto failed;

    }

    /* timezone */
    skip_ws(buf, 0);
    c = get_current_char(buf); /* the '+' or '-' in the timezone */
    get_next_char(buf);        /* consume '+' or '-' */

    if (!get_next_token(buf, &str_token, &len)) {
        *tz_offset = 0;
    } else {
        *tz_offset = compute_tzoffset(str_token, len, c);
    }

    /* dst */
    tm->tm_isdst = -1;
    return buf->offset;
 failed:
    return -1;

}


/*
 * time_from_rfc5322()
 * This is meant to be the replacement function for time_from_rfc822() and
 * time_from_rfc3501() functions.
 * Returns: Number of characters consumed from @s on success,
 *          or -1 on error.
 */
EXPORTED int time_from_rfc5322(const char *s, time_t *date)
{
    struct rfc822dtbuf buf;
    struct tm tm;
    time_t tmp_gmtime;
    int tzone_offset = 0;

    if (!s)
        goto baddate;

    memset(&tm, 0, sizeof(struct tm));
    *date = 0;

    buf.str = s;
    buf.len = strlen(s);
    buf.offset = 0;

    if (tokenise_str_and_create_tm(&buf, &tm, &tzone_offset) == -1)
        goto baddate;

    tmp_gmtime = mkgmtime(&tm);
    if (tmp_gmtime == -1)
        goto baddate;

    *date = tmp_gmtime - tzone_offset * 60;

    return buf.offset;

 baddate:
    return -1;
}

/*
 * time_to_rfc5322()
 * Convert a time_t date to an IMAP-style date.
 * `buf` which is the buffer this function is going to write into, needs to
 * be atleast RFC5322_DATETIME_MAX (32), if not more.
 *
 */
EXPORTED int time_to_rfc5322(time_t date, char *buf, size_t len)
{
    struct tm *tm = localtime(&date);
    long gmtoff = gmtoff_of(tm, date);
    int gmtnegative = 0;

    if (gmtoff < 0) {
        gmtoff = -gmtoff;
        gmtnegative = 1;
    }

    gmtoff /= 60;

    return snprintf(buf, len,
             "%s, %02d %s %04d %02d:%02d:%02d %c%02lu%02lu",
             wday[tm->tm_wday],
             tm->tm_mday, monthname[tm->tm_mon], tm->tm_year + 1900,
             tm->tm_hour, tm->tm_min, tm->tm_sec,
             gmtnegative ? '-' : '+', gmtoff/60, gmtoff%60);
}
