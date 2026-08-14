/* cyr_guesstz.c - create and query the timezone guessing database */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <libical/ical.h>

#include "guesstz.h"

static const char *default_trstart = "20000101T000000Z";
static const char *default_trend = "20640101T000000Z";

static void usage(const char *name)
{
    fprintf(stderr, "Usage:\n\n");
    fprintf(stderr, "Create database from zoneinfo\n");
    fprintf(stderr, "  %s -z <zoneinfo> [-r <timerange>] <dbfile>\n", name);
    fprintf(stderr, "Print database\n");
    fprintf(stderr, "  %s -p [-r <timerange>] <dbfile>\n", name);
    fprintf(stderr, "Guess timezone id of VTIMEZONE from stdin\n");
    fprintf(stderr, "  %s [-r <timerange>] <dbfile>\n", name);
    fprintf(stderr, "\n");
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  dbfile: file path of database\n");
    fprintf(stderr, "  zoneinfo: file path of zoneinfo directory\n");
    fprintf(stderr, "  timerange: [start,end) observance expansion time-range\n");
    fprintf(stderr, "     format:  UTC DATE-TIME '/' UTC DATE-TIME\n");
    fprintf(stderr, "     default: %s/%s\n", default_trstart, default_trend);
    exit(EX_USAGE);
}

static char *slurp(FILE *fp)
{
    size_t len = 0, alloc = 8192;
    char *buf = malloc(alloc);

    for (;;) {
        if (len + 1 == alloc) {
            alloc *= 2;
            buf = realloc(buf, alloc);
        }
        size_t n = fread(buf + len, 1, alloc - len - 1, fp);
        if (!n) break;
        len += n;
    }
    buf[len] = '\0';

    return buf;
}

int main(int argc, char **argv)
{
    int opt;
    const char *fname = NULL;
    const char *zoneinfo_dir = NULL;
    enum mode { GUESS = 0, CREATE, ENCODE } mode = GUESS;
    struct icalperiodtype span = ICALPERIODTYPE_INITIALIZER;
    guesstz_t *gtz = NULL;
    int r = 0;

    /* keep this in alphabetical order */
    static const char short_options[] = "pr:z:";

    static const struct option long_options[] = {
        { "print", no_argument, NULL, 'p' },
        { "timerange", required_argument, NULL, 'r' },
        { "zoneinfo", required_argument, NULL, 'z' },
        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'p':
            if (mode != GUESS)
                usage(argv[0]);
            mode = ENCODE;
            break;
        case 'r':
            span = icalperiodtype_from_string(optarg);
            if (icalperiodtype_is_null_period(span) ||
                icaltime_compare(span.start, span.end) >= 0) {
                fprintf(stderr, "invalid timerange: %s\n", optarg);
                usage(argv[0]);
            }
            break;
        case 'z':
            if (mode != GUESS)
                usage(argv[0]);
            mode = CREATE;
            zoneinfo_dir = optarg;
            break;
        default:
            usage(argv[0]);
        }
    }

    if (optind != argc - 1)
        usage(argv[0]);
    fname = argv[optind];

    if (icalperiodtype_is_null_period(span)) {
        span.start = icaltime_from_string(default_trstart);
        span.end = icaltime_from_string(default_trend);
    }

    if (mode == CREATE) {
        FILE *fp = fopen(fname, "w");
        if (!fp) {
            fprintf(stderr, "fopen(%s): %s\n", fname, strerror(errno));
            return EX_CANTCREAT;
        }
        r = guesstz_create(zoneinfo_dir, span.start, span.end, fp);
        fclose(fp);
        return r;
    }

    gtz = guesstz_open(fname);
    if (guesstz_error(gtz)) {
        fprintf(stderr, "%s\n", guesstz_error(gtz));
        r = EX_DATAERR;
        goto done;
    }

    if (mode == ENCODE) {
        char *dump = guesstz_encode(gtz);
        puts(dump);
        free(dump);
    }
    else {
        char *buf = slurp(stdin);
        icalcomponent *ical = icalparser_parse_string(buf);
        free(buf);
        if (!ical) {
            fprintf(stderr, "can't read VTIMEZONE\n");
            r = EX_DATAERR;
            goto done;
        }

        icalcomponent *vtz;
        for (vtz = icalcomponent_get_first_component(ical,
                                                     ICAL_VTIMEZONE_COMPONENT);
             vtz;
             vtz = icalcomponent_get_next_component(ical,
                                                    ICAL_VTIMEZONE_COMPONENT)) {
            char *tzid = guesstz_guess(gtz, vtz, span.start, span.end);
            if (guesstz_error(gtz)) {
                fprintf(stderr, "%s\n", guesstz_error(gtz));
                free(tzid);
                r = EX_DATAERR;
                break;
            }
            printf("%s\n", tzid ? tzid : "unknown");
            free(tzid);
        }
        icalcomponent_free(ical);
    }

done:
    guesstz_close(&gtz);
    return r;
}
