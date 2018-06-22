/* cyr_buildinfo.c -- report cyrus configured components
 *
 * Copyright (c) 2018 Carnegie Mellon University.  All rights reserved.
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

#include <stdio.h>

static int have_sections = 0;
static int have_keys = 0;

static void start_section(const char *name)
{
    if (have_sections)
	putchar(',');
    printf("\n  \"%s\": {", name);
    have_sections++;
}

static void end_section(void)
{
    have_keys = 0;
    printf("\n  }");
}

static void key_true(const char *key)
{
    if (have_keys)
	putchar(',');
    printf("\n    \"%s\": true", key);
    have_keys++;
}

static void key_false(const char *key)
{
    if (have_keys)
	putchar(',');
    printf("\n    \"%s\": false", key);
    have_keys++;
}

int main (int argc __attribute__((unused)),
	  char **argv __attribute__((unused)))
{
    putchar('{');

    start_section("component");
#ifdef ENABLE_MBOXEVENT
    key_true("event_notification");
#else
    key_false("event_notification");
#endif
#ifdef HAVE_GSSAPI_H
    key_true("gssapi");
#else
    key_false("gssapi");
#endif
#ifdef USE_AUTOCREATE
    key_true("autocreate");
#else
    key_false("autocreate");
#endif
#ifdef USE_IDLED
    key_true("idled");
#else
    key_false("idled");
#endif
#ifdef USE_HTTPD
    key_true("httpd");
#else
    key_false("httpd");
#endif
#ifdef HAVE_KRB
    key_true("kerberos_v4");
#else
    key_false("kerberos_v4");
#endif
#ifdef USE_MURDER
    key_true("murder");
#else
    key_false("murder");
#endif
#ifdef USE_NNTPD
    key_true("nntpd");
#else
    key_false("nntpd");
#endif
#ifdef USE_REPLICATION
    key_true("replication");
#else
    key_false("replication");
#endif
#ifdef USE_SIEVE
    key_true("sieve");
#else
    key_false("sieve");
#endif
#ifdef USE_CALALARMD
    key_true("calalarmd");
#else
    key_false("calalarmd");
#endif
#ifdef WITH_JMAP
    key_true("jmap");
#else
    key_false("jmap");
#endif
#ifdef ENABLE_OBJECTSTORE
    key_true("objectstore");
#else
    key_false("objectstore");
#endif
#ifdef ENABLE_BACKUP
    key_true("backup");
#else
    key_false("backup");
#endif
#if defined(HAVE_UCDSNMP) || defined(HAVE_NETSNMP)
    key_true("snmp");
#else
    key_false("snmp");
#endif
    end_section();

    start_section("dependency");
#ifdef HAVE_LDAP
    key_true("ldap");
#else
    key_false("ldap");
#endif
#ifdef HAVE_SSL
    key_true("openssl");
#else
    key_false("openssl");
#endif
#ifdef HAVE_ZLIB
    key_true("zlib");
#else
    key_false("zlib");
#endif
#if defined(ENABLE_REGEX) && defined(HAVE_PCREPOSIX_H)
    key_true("pcre");
#else
    key_false("pcre");
#endif
#ifdef HAVE_CLAMAV
    key_true("clamav");
#else
    key_false("clamav");
#endif
#ifdef HAVE_UCDSNMP
    key_true("ucdsnmp");
#else
    key_false("ucdsnmp");
#endif
#ifdef HAVE_NETSNMP
    key_true("netsnmp");
#else
    key_false("netsnmp");
#endif
#ifdef WITH_OPENIO
    key_true("openio");
#else
    key_false("openio");
#endif
#ifdef HAVE_NGHTTP2
    key_true("nghttp2");
#else
    key_false("nghttp2");
#endif
#ifdef HAVE_BROTLI
    key_true("brotli");
#else
    key_false("brotli");
#endif
#ifdef USE_HTTPD
    key_true("xml2");
#else
    key_false("xml2");
#endif
#ifdef HAVE_ICAL
    key_true("ical");
#else
    key_false("ical");
#endif
#ifdef HAVE_ICU
    key_true("icu4c");
#else
    key_false("icu4c");
#endif
#ifdef HAVE_SHAPELIB
    key_true("shapelib");
#else
    key_false("shapelib");
#endif
    end_section();

    start_section("database");
#ifdef HAVE_MYSQL
    key_true("mysql");
#else
    key_false("mysql");
#endif
#ifdef HAVE_PGSQL
    key_true("pgsql");
#else
    key_false("pgsql");
#endif
#ifdef HAVE_SQLITE
    key_true("sqlite");
#else
    key_false("sqlite");
#endif
    end_section();

    start_section("search");
#ifdef USE_SQUAT
    key_true("squat");
#else
    key_false("squat");
#endif
    end_section();

    start_section("hardware");
#ifdef HAVE_SSE42
    key_true("sse42");
#else
    key_false("sse42");
#endif
    end_section();

    puts("\n}");
    return 0;
}
