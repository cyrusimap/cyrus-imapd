/* cyr_guesstzdb.c - tool to generate a database for guesstz
 *
 * Copyright (c) 1994-2021 Carnegie Mellon University.  All rights reserved.
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
#include <sysexits.h>

#include "cyrusdb.h"
#include "global.h"
#include "proc.h"
#include "../master/masterconf.h"

#include "guesstz.h"

/* Make ld happy */
const char *MASTER_CONFIG_FILENAME = DEFAULT_MASTER_CONFIG_FILENAME;

static const char *expandrange_start = "20000101T000000Z";
static const char *expandrange_end   = "20380101T000000Z";

/* Print usage info on stderr and exit */
__attribute__((noreturn)) static int usage(const char *name)
{
    fprintf(stderr,
            "usage: %s [mode] [options]\n"
            "\n"
            "Mode flags: \n"
            "  -c                create database\n"
            "  -p                print database\n"
            "  -h                show usage\n"
            "\n"
            "General options:\n"
            "  -C <alt-config>   use alternative imapd.conf config file\n"
            "  -F <alt-file>     use alternative database file\n"
            "Create mode options:\n"
            "  -R <start>,<end>  cover time range\n"
            "  -Z <alt-zoneinfo> use alternative zoneinfo dir\n"
            "\n",
        name);
    exit(EX_USAGE);
}

int main(int argc, char *argv[])
{
    char *alt_config = NULL;
    const char *alt_fname = NULL;
    const char *alt_range = NULL;
    const char *alt_zoneinfo = NULL;
    enum mode { CREATE, PRINT, UNKNOWN } m = UNKNOWN;
    char *namec = strdup(argv[0]);
    char *name = basename(namec);

    extern char *optarg;
    int opt;

    /* Parse arguments */
    while ((opt = getopt(argc, argv, "chpC:F:R:Z:")) != EOF) {
        switch (opt) {
        case 'C':               /* alt config file */
            alt_config = optarg;
            break;
        case 'F':
            alt_fname = optarg;
            break;
        case 'R':
            alt_range = optarg;
            break;
        case 'Z':
            alt_zoneinfo = optarg;
            break;
        case 'c':
            if (m != UNKNOWN)
                usage(name);
            m = CREATE;
            break;
        case 'h':
            usage(name);
            break;
        case 'p':
            if (m != UNKNOWN)
                usage(name);
            m = PRINT;
            break;
        default:
            usage(name);
        }
    }
    if (optind < argc || m == UNKNOWN) {
        usage(name);
    }

    cyrus_init(alt_config, "cyr_guesstzdb", 0, 0);

    if (m == CREATE) {
        /* Determine observance expansion time range */
        const icaltimezone *utc = icaltimezone_get_utc_timezone();
        icaltimetype dbstart = icaltime_from_string(expandrange_start);
        icaltimetype dbend = icaltime_from_string(expandrange_end);
        if (alt_range) {
            int is_valid = 0;
            struct buf buf = BUF_INITIALIZER;
            const char *sep = strchr(alt_range, ',');
            if (sep) {
                buf_setmap(&buf, alt_range, sep - alt_range);
                dbstart = icaltime_from_string(buf_cstring(&buf));
                if (icalerrno == ICAL_NO_ERROR) {
                    buf_setcstr(&buf, sep + 1);
                    dbend = icaltime_from_string(buf_cstring(&buf));
                    if (icalerrno == ICAL_NO_ERROR) {
                        is_valid = (dbstart.zone == utc && dbend.zone == utc) &&
                            icaltime_compare(dbstart, dbend) < 0;
                    }
                }
            }
            buf_free(&buf);
            if (!is_valid) {
                fprintf(stderr, "Invalid time range\n");
                usage(name);
            }
        }
        /* Create database */
        int r = guesstz_create(alt_zoneinfo, alt_fname, dbstart, dbend);
        if (r) {
            fprintf(stderr, "Could not create db: %s (also see syslog)\n",
                    cyrusdb_strerror(r));
            return EX_IOERR;
        }
    }
    else if (m == PRINT) {
        /* Print database */
        char *str = guesstz_dump(alt_fname);
        if (!str) {
            fprintf(stderr, "Could not read db (also see syslog)\n");
            return EX_IOERR;
        }
        puts(str);
        free(str);
    }

    /* All done */
    return 0;
}
