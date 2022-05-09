/* cyr_synclog.c -- add a line to the sync log file for replication
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 * Originally written by Bron Gondwana <brong@fastmail.fm>
 */

#include <config.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "assert.h"
#include "global.h"
#include "sync_log.h"
#include "util.h"
#include "xmalloc.h"

void usage(const char *name) {
    fprintf(stderr, "Usage: %s [-C altconfig] [-{type}] value\n", name);

    fprintf(stderr, "\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "types:\n");
    fprintf(stderr, "  -u   USER\n");
    fprintf(stderr, "  -U   UNUSER\n");
    fprintf(stderr, "  -v   SIEVE\n");
    fprintf(stderr, "  -m   MAILBOX\n");
    fprintf(stderr, "  -M   UNMAILBOX\n");
    fprintf(stderr, "  -q   QUOTA\n");
    fprintf(stderr, "  -n   ANNOTATION\n");
    fprintf(stderr, "  -s   SEEN\n");
    fprintf(stderr, "  -b   SUBSCRIPTION\n");
    fprintf(stderr, "\n");
    fprintf(stderr,
	    "You may omit the type flag and just specify a complete log line\n");
    exit(-1);
}

int main(int argc, char *argv[])
{
    char *alt_config = NULL;
    char cmd = '\0';
    int opt;

    /* keep this in alphabetical order */
    static const char *const short_options = "C:MUabcmnqsuv";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { "unmailbox", no_argument, NULL, 'M' },
        { "unuser", no_argument, NULL, 'U' },
        { "append", no_argument, NULL, 'a' },
        { "subscription", no_argument, NULL, 'b' },
        { "acl", no_argument, NULL, 'c' },
        { "mailbox", no_argument, NULL, 'm' },
        { "annotation", no_argument, NULL, 'n' },
        { "quota", no_argument, NULL, 'q' },
        { "seen", no_argument, NULL, 's' },
        { "user", no_argument, NULL, 'u' },
        { "sieve", no_argument, NULL, 'v' },
        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        case 'u': /* User */
            cmd = 'u';
            break;
        case 'U': /* UnUser */
            cmd = 'U';
            break;
        case 'v': /* sieVe */
            cmd = 'v';
            break;
        case 'm': /* Mailbox */
            cmd = 'm';
            break;
        case 'M': /* UnMailbox */
            cmd = 'M';
            break;
        case 'a': /* Append */
            cmd = 'a';
            break;
        case 'c': /* aCl */
            cmd = 'c';
            break;
        case 'q': /* Quota */
            cmd = 'q';
            break;
        case 'n': /* aNnotation */
            cmd = 'n';
            break;
        case 's': /* Seen */
            cmd = 's';
            break;
        case 'b': /* suBscription */
            cmd = 'b';
            break;
        }
    }

    /* need at least one value */
    if ((argc - optind) < 1) usage(argv[0]);
    /* and not an empty string */
    if (!argv[optind][0]) usage(argv[0]);

    if (cmd == 's' || cmd == 'b') {
	/* need a second value */
	if ((argc - optind) < 2) usage(argv[0]);
	/* and not an empty string */
	if (!argv[optind+1][0]) usage(argv[0]);
    }

    cyrus_init(alt_config, "cyr_synclog", 0, 0);
    sync_log_init();

    switch(cmd) {
        case 'u': /* User */
            sync_log_user(argv[optind]);
            break;
        case 'U': /* UnUser */
            sync_log_unuser(argv[optind]);
            break;
        case 'v': /* sieVe */
            sync_log_sieve(argv[optind]);
            break;
        case 'm': /* Mailbox */
            sync_log_mailbox(argv[optind]);
            break;
        case 'M': /* UnMailbox */
            sync_log_unmailbox(argv[optind]);
            break;
        case 'q': /* Quota */
            sync_log_quota(argv[optind]);
            break;
        case 'n': /* aNnotation */
            sync_log_annotation(argv[optind]);
            break;
        case 's': /* Seen */
            sync_log_seen(argv[optind], argv[optind+1]);
            break;
        case 'b': /* suBscription */
            sync_log_subscribe(argv[optind], argv[optind+1]);
            break;
        default:
            /* just as is! */
            sync_log(argv[optind]);
            break;
    }

    sync_log_done();

    cyrus_done();

    return 0;
}
