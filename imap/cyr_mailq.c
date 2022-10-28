/* cyr_mailq.c -- Program to display pending JMAP Scheduled Send mail
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
#include <getopt.h>
#include <sysexits.h>
#include <time.h>

#include "lib/times.h"

#include "imap/caldav_alarm.h"
#include "imap/global.h"
#include "imap/json_support.h"

static void usage(void) __attribute__((noreturn));
static void usage(void)
{
    fprintf(stderr, "XXX someone better write a usage() for this!\n");
    exit(EX_USAGE);
}

void printone_json(time_t nextcheck, uint32_t num_retries,
                   time_t last_run, const char *last_err,
                   json_t *submission,
                   void *rock)
{
    json_t *j;
    int *sep = (int *) rock;
    char timebuf[ISO8601_DATETIME_MAX + 1];

    j = json_object();

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

void printone_pretty(time_t nextcheck, uint32_t num_retries,
                     time_t last_run, const char *last_err,
                     json_t *submission,
                     void *rock __attribute__((unused)))
{
    const time_t now = time(NULL);
    const char *identityId;
    json_t *envelope, *mailFrom, *rcptTo, *value;
    size_t i;

    identityId = json_string_value(json_object_get(submission, "identityId"));

    envelope = json_object_get(submission, "envelope");
    mailFrom = json_object_get(envelope, "mailFrom");
    rcptTo = json_object_get(envelope, "rcptTo");

    /* XXX make nextcheck display colour according to magnitude */
    printf("%g %s ", difftime(nextcheck, now), identityId);
    if (last_err) {
        printf("%" PRIu32 ":%g:%s ",
               num_retries, difftime(last_run, now), last_err);
    }
    printf("%s ", json_string_value(json_object_get(mailFrom, "email")));
    json_array_foreach(rcptTo, i, value) {
        printf("%s ", json_string_value(json_object_get(value, "email")));
    }

    fputs("\n", stdout);
}

int main(int argc, char *argv[])
{
    int opt, r;
    char *alt_config = NULL;
    int want_json = 0;

    /* keep this in alphabetical order */
    static const char short_options[] = "C:j";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
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
        default:
            usage();
        }
    }

    cyrus_init(alt_config, "cyr_mailq", 0, 0);

    if (want_json) {
        int sep = '[';
        r = caldav_alarm_list_futurerelease(0, 0, printone_json, &sep);
        if (sep == ',') fputs("\n]\n", stdout);
    }
    else {
        r = caldav_alarm_list_futurerelease(0, 0, printone_pretty, NULL);
    }

    if (r) {
        fprintf(stderr, "whoops, something went wrong? r=%d\n", r);
    }

    cyrus_done();

    return 0;
}
