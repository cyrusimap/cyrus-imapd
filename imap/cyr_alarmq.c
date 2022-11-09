/* cyr_alarmq.c -- Program to display pending calalarmd work
 *
 * Copyright (c) 1994-2022 Carnegie Mellon University.  All rights reserved.
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
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <sysexits.h>
#include <time.h>

#include "lib/strhash.h"
#include "lib/times.h"
#include "lib/util.h"

#include "imap/caldav_alarm.h"
#include "imap/global.h"
#include "imap/json_support.h"

static int overdue_threshold = CALDAV_ALARM_LOOKAHEAD;
static int want_color = -1;

static void usage(void) __attribute__((noreturn));
static void usage(void)
{
    fprintf(stderr, "XXX someone better write a usage() for this!\n");
    exit(EX_USAGE);
}

/* XXX move to lib/util.c once the implementation stabilises */
#define SGR_DONE (-1)
#define COLOR_RED       (31)
#define COLOR_GREEN     (32)
#define COLOR_YELLOW    (33)
static void _buf_appendsgr(struct buf *dst, ...)
{
    va_list ap;
    int n, sep = 0;

    buf_appendcstr(dst, "\033[");
    va_start(ap, dst);
    while ((n = va_arg(ap, int)) >= 0) {
        if (sep) buf_putc(dst, sep);
        buf_printf(dst, "%d", n);
        sep = ';';
    }
    buf_putc(dst, 'm');
}

static void _buf_append_kv(struct buf *dst, int sep, int want_color,
                           const char *key, const char *value)
{
    if (sep) buf_putc(dst, sep);
    buf_appendcstr(dst, key);
    buf_appendcstr(dst, "=<");
    if (want_color) {
        unsigned color = 17 + strhash(value) % 214; /* xterm-256 colour cube */
        _buf_appendsgr(dst, 38, 5, color, SGR_DONE);
        buf_appendcstr(dst, value);
        _buf_appendsgr(dst, 0, SGR_DONE);
    }
    else {
        buf_appendcstr(dst, value);
    }
    buf_appendcstr(dst, ">");
}

__attribute__((format(printf, 5, 6)))
static void _buf_append_kvf(struct buf *dst, int sep, int want_color,
                            const char *key, const char *valfmt,
                            ...)
{
    va_list ap;
    struct buf valbuf = BUF_INITIALIZER;

    va_start(ap, valfmt);
    buf_vprintf(&valbuf, valfmt, ap);

    _buf_append_kv(dst, sep, want_color, key, buf_cstring(&valbuf));

    buf_free(&valbuf);
}

static inline const char *format_localtime(time_t t, char *buf, size_t len)
{
    struct timeval tv = { t, 0 };

    memset(buf, 0, len);
    timeval_to_iso8601(&tv, timeval_s, buf, len);

    buf[10] = ' '; /* replace T */
    buf[19] = '\0'; /* drop tz */

    return buf;
}

static void pretty_nextcheck(struct buf *dst, time_t nextcheck)
{
    char timebuf[ISO8601_DATETIME_MAX + 1] = {0};

    /* color nextcheck time according to whether and how overdue it is */
    if (want_color) {
        double diff = difftime(time(NULL), nextcheck);
        int color = COLOR_GREEN;

        if (diff > 0) color = COLOR_YELLOW;
        if (diff > overdue_threshold) color = COLOR_RED;
        _buf_appendsgr(dst, color, SGR_DONE);
    }
    buf_appendcstr(dst, format_localtime(nextcheck, timebuf, sizeof(timebuf)));
    if (want_color) _buf_appendsgr(dst, 0, SGR_DONE);
}

static void pretty_error(struct buf *dst, uint32_t num_retries,
                         time_t last_run, const char *last_err)
{
    char timebuf[ISO8601_DATETIME_MAX + 1] = {0};
    int sep = ' ';

    if (last_err) {
        _buf_append_kvf(dst, sep, 0, "attempts", "%" PRIu32, num_retries);
        buf_printf(dst, " error=<%s|",
                   format_localtime(last_run, timebuf, sizeof(timebuf)));

        /* error message in color */
        if (want_color) _buf_appendsgr(dst, COLOR_RED, SGR_DONE);
        buf_appendcstr(dst, last_err);
        if (want_color) _buf_appendsgr(dst, 0, SGR_DONE);

        buf_putc(dst, '>');
    }
}

static void printone_calendar_json(const char *mboxname,
                                   uint32_t imap_uid,
                                   time_t nextcheck,
                                   uint32_t num_rcpts,
                                   uint32_t num_retries,
                                   time_t last_run,
                                   const char *last_err,
                                   void *rock)
{
    json_t *j;
    int *sep = (int *) rock;
    char timebuf[ISO8601_DATETIME_MAX + 1];

    j = json_object();
    json_object_set_new(j, "type", json_string("calendar"));

    if (nextcheck) {
        memset(timebuf, 0, sizeof(timebuf));
        time_to_iso8601(nextcheck, timebuf, sizeof(timebuf), 1);
        json_object_set_new(j, "nextcheck", json_string(timebuf));
    }

    json_object_set_new(j, "mboxname", json_string(mboxname));
    json_object_set_new(j, "imap_uid", json_integer(imap_uid));
    json_object_set_new(j, "num_rcpts", json_integer(num_rcpts));
    json_object_set_new(j, "num_retries", json_integer(num_retries));
    if (last_run) {
        memset(timebuf, 0, sizeof(timebuf));
        time_to_iso8601(last_run, timebuf, sizeof(timebuf), 1);
        json_object_set_new(j, "last_run", json_string(timebuf));
    }
    json_object_set_new(j, "last_err", json_string(last_err));

    if (sep) {
       if (*sep) printf("%c\n", *sep);
        *sep = ',';
    }

    json_dumpf(j, stdout, 0);

    json_decref(j);
}

static void printone_calendar_pretty(const char *mboxname,
                                     uint32_t imap_uid,
                                     time_t nextcheck,
                                     uint32_t num_rcpts,
                                     uint32_t num_retries,
                                     time_t last_run,
                                     const char *last_err,
                                     void *rock __attribute__((unused)))
{
    char timebuf[ISO8601_DATETIME_MAX + 1] = {0};

    printf("%s ", format_localtime(nextcheck, timebuf, sizeof(timebuf)));
    printf("type=<calendar> mboxname=<%s> ", mboxname);
    printf("uid=<%" PRIu32 "> ", imap_uid);
    printf("num_rcpts=<%" PRIu32 "> ", num_rcpts);
    printf("num_retries=<%" PRIu32 "> ", num_retries);
    printf("last_run=<%s> ", format_localtime(last_run, timebuf, sizeof(timebuf)));
    printf("last_err=<%s>\n", last_err);
}

static void printone_snooze_json(const char *userid,
                                 time_t nextcheck,
                                 uint32_t num_retries,
                                 time_t last_run,
                                 const char *last_err,
                                 json_t *snoozed,
                                 void *rock)
{
    json_t *j;
    int *sep = (int *) rock;
    char timebuf[ISO8601_DATETIME_MAX + 1];

    j = json_object();
    json_object_set_new(j, "type", json_string("snooze"));

    json_object_set_new(j, "userid", json_string(userid));

    if (nextcheck) {
        memset(timebuf, 0, sizeof(timebuf));
        time_to_iso8601(nextcheck, timebuf, sizeof(timebuf), 1);
        json_object_set_new(j, "nextcheck", json_string(timebuf));
    }

    json_object_set_new(j, "num_retries", json_integer(num_retries));
    if (last_run) {
        memset(timebuf, 0, sizeof(timebuf));
        time_to_iso8601(last_run, timebuf, sizeof(timebuf), 1);
        json_object_set_new(j, "last_run", json_string(timebuf));
    }
    json_object_set_new(j, "last_err", json_string(last_err));

    json_object_set(j, "snoozed", snoozed);

    if (sep) {
       if (*sep) printf("%c\n", *sep);
        *sep = ',';
    }

    json_dumpf(j, stdout, 0);

    json_decref(j);
}

static void printone_snooze_pretty(const char *userid,
                                   time_t nextcheck,
                                   uint32_t num_retries,
                                   time_t last_run,
                                   const char *last_err,
                                   json_t *snoozed,
                                   void *rock __attribute__((unused)))
{
    static struct buf buf = BUF_INITIALIZER;
    json_t *until, *moveToMailboxId, *setKeywords;
    int sep = ' ';

    buf_reset(&buf);

    pretty_nextcheck(&buf, nextcheck);
    _buf_append_kv(&buf, sep, want_color, "userid", userid);
    _buf_append_kv(&buf, sep, 0, "type", "snooze");

    until = json_object_get(snoozed, "until");
    moveToMailboxId = json_object_get(snoozed, "moveToMailboxId");
    setKeywords = json_object_get(snoozed, "setKeywords");

    if (until) {
        /* XXX can we parse this and then format_localtime it? */
        _buf_append_kv(&buf, sep, 0, "until", json_string_value(until));
    }

    if (moveToMailboxId) {
        _buf_append_kv(&buf, sep, 0, "moveToMailboxId",
                       json_string_value(moveToMailboxId));
    }

    if (setKeywords) {
        const char *key;
        json_t *value;

        json_object_foreach(setKeywords, key, value) {
            if (json_is_true(value)) {
                _buf_append_kv(&buf, sep, 0, "setKeyword", key);
            }
            else {
                _buf_append_kv(&buf, sep, 0, "unsetKeyword", key);
            }
        }
    }

    pretty_error(&buf, num_retries, last_run, last_err);

    buf_putc(&buf, '\n');
    fputs(buf_cstring(&buf), stdout);
}

static void printone_send_json(const char *userid,
                               time_t nextcheck, uint32_t num_retries,
                               time_t last_run, const char *last_err,
                               json_t *submission,
                               void *rock)
{
    json_t *j;
    int *sep = (int *) rock;
    char timebuf[ISO8601_DATETIME_MAX + 1];

    j = json_object();
    json_object_set_new(j, "type", json_string("send"));

    if (userid) {
        json_object_set_new(j, "userid", json_string(userid));
    }

    if (nextcheck) {
        memset(timebuf, 0, sizeof(timebuf));
        time_to_iso8601(nextcheck, timebuf, sizeof(timebuf), 1);
        json_object_set_new(j, "nextcheck", json_string(timebuf));
    }

    if (last_run) {
        memset(timebuf, 0, sizeof(timebuf));
        time_to_iso8601(last_run, timebuf, sizeof(timebuf), 1);
        json_object_set_new(j, "last_run", json_string(timebuf));
    }

    json_object_set_new(j, "num_retries", json_integer(num_retries));
    json_object_set_new(j, "last_err", json_string(last_err));
    json_object_set(j, "submission", submission);

    if (sep) {
       if (*sep) printf("%c\n", *sep);
        *sep = ',';
    }

    json_dumpf(j, stdout, 0);

    json_decref(j);
}

static void printone_send_pretty(const char *userid,
                                 time_t nextcheck, uint32_t num_retries,
                                 time_t last_run, const char *last_err,
                                 json_t *submission,
                                 void *rock __attribute__((unused)))
{
    const char *identityId;
    json_t *envelope, *mailFrom, *rcptTo, *value;
    static struct buf buf = BUF_INITIALIZER;
    size_t i;
    int sep = ' ';

    buf_reset(&buf);

    identityId = json_string_value(json_object_get(submission, "identityId"));

    envelope = json_object_get(submission, "envelope");
    mailFrom = json_object_get(envelope, "mailFrom");
    rcptTo = json_object_get(envelope, "rcptTo");

    pretty_nextcheck(&buf, nextcheck);

    _buf_append_kv(&buf, sep, want_color, "userid", userid);
    _buf_append_kv(&buf, sep, 0, "type", "send");
    _buf_append_kv(&buf, sep, want_color, "identityId", identityId);
    _buf_append_kv(&buf, sep, 0, "from",
                   json_string_value(json_object_get(mailFrom, "email")));

    json_array_foreach(rcptTo, i, value) {
        _buf_append_kv(&buf, sep, 0, "to",
                       json_string_value(json_object_get(value, "email")));
    }

    pretty_error(&buf, num_retries, last_run, last_err);

    buf_putc(&buf, '\n');
    fputs(buf_cstring(&buf), stdout);
}

static void printone_unscheduled_json(const char *mboxname,
                                      uint32_t imap_uid,
                                      time_t nextcheck,
                                      uint32_t num_rcpts,
                                      uint32_t num_retries,
                                      time_t last_run,
                                      const char *last_err,
                                      void *rock)
{
    json_t *j;
    int *sep = (int *) rock;
    char timebuf[ISO8601_DATETIME_MAX + 1];

    j = json_object();
    json_object_set_new(j, "type", json_string("unscheduled"));

    if (nextcheck) {
        memset(timebuf, 0, sizeof(timebuf));
        time_to_iso8601(nextcheck, timebuf, sizeof(timebuf), 1);
        json_object_set_new(j, "nextcheck", json_string(timebuf));
    }

    json_object_set_new(j, "mboxname", json_string(mboxname));
    json_object_set_new(j, "imap_uid", json_integer(imap_uid));
    json_object_set_new(j, "num_rcpts", json_integer(num_rcpts));
    json_object_set_new(j, "num_retries", json_integer(num_retries));
    if (last_run) {
        memset(timebuf, 0, sizeof(timebuf));
        time_to_iso8601(last_run, timebuf, sizeof(timebuf), 1);
        json_object_set_new(j, "last_run", json_string(timebuf));
    }
    json_object_set_new(j, "last_err", json_string(last_err));

    if (sep) {
       if (*sep) printf("%c\n", *sep);
        *sep = ',';
    }

    json_dumpf(j, stdout, 0);

    json_decref(j);
}

static void printone_unscheduled_pretty(const char *mboxname,
                                        uint32_t imap_uid,
                                        time_t nextcheck,
                                        uint32_t num_rcpts,
                                        uint32_t num_retries,
                                        time_t last_run,
                                        const char *last_err,
                                        void *rock __attribute__((unused)))
{
    char timebuf[ISO8601_DATETIME_MAX + 1] = {0};

    printf("%s ", format_localtime(nextcheck, timebuf, sizeof(timebuf)));
    printf("type=<unscheduled> mboxname=<%s> ", mboxname);
    printf("uid=<%" PRIu32 "> ", imap_uid);
    printf("num_rcpts=<%" PRIu32 "> ", num_rcpts);
    printf("num_retries=<%" PRIu32 "> ", num_retries);
    printf("last_run=<%s> ", format_localtime(last_run, timebuf, sizeof(timebuf)));
    printf("last_err=<%s>\n", last_err);
}

static int parse_color_arg(const char *arg)
{
    switch (arg[0]) {
    case 'y': /* yes */
        return 1;
    case 'n': /* no */
        return 0;
    case 'a': /* always, auto */
        if (0 == strcmp(arg, "always")) return 1;
        return -1;
    default:
        usage();
    }
}

int main(int argc, char *argv[])
{
    int opt, r;
    char *alt_config = NULL;
    int want_json = 0;

    /* keep this in alphabetical order */
    static const char short_options[] = "C:j";

    enum {
        LONGOPT_COLOR = 1,
    };

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { "color", optional_argument, NULL, LONGOPT_COLOR },
        { "json", no_argument, NULL, 'j' },
        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        case 'j':
            want_json = 1;
            break;
        case LONGOPT_COLOR:
            if (optarg) want_color = parse_color_arg(optarg);
            else want_color = 1;
            break;
        default:
            usage();
        }
    }

    if (want_color < 0) {
        want_color = isatty(STDOUT_FILENO);
        errno = 0;
    }

    cyrus_init(alt_config, "cyr_alarmq", 0, 0);

    if (want_json) {
        int sep = '[';
        r = caldav_alarm_list(0, 0,
                              printone_calendar_json,
                              printone_snooze_json,
                              printone_send_json,
                              printone_unscheduled_json,
                              &sep);
        if (sep == ',') fputs("\n]\n", stdout);
    }
    else {
        r = caldav_alarm_list(0, 0,
                              printone_calendar_pretty,
                              printone_snooze_pretty,
                              printone_send_pretty,
                              printone_unscheduled_pretty,
                              NULL);
    }

    if (r) {
        fprintf(stderr, "whoops, something went wrong? r=%d\n", r);
    }

    cyrus_done();

    return 0;
}
