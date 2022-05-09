/* ctl_deliver.c -- Program to perform operations on duplicate delivery db
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
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>

#include "duplicate.h"
#include "global.h"
#include "libcyr_cfg.h"
#include "util.h"
#include "xmalloc.h"

static void usage(void)
{
    fprintf(stderr,
            "ctl_deliver [-C <altconfig>] -d [-f <dbfile>]\n");
    exit(-1);
}

int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt, r = 0;
    char *alt_file = NULL;
    char *alt_config = NULL;
    char *days = NULL;
    enum { DUMP, PRUNE, NONE } op = NONE;

    while ((opt = getopt(argc, argv, "C:dE:f:")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'd':
            if (op == NONE) op = DUMP;
            else usage();
            break;

        case 'f':
            if (alt_file == NULL) alt_file = optarg;
            else usage ();
            break;

        case 'E':
            if (op == NONE) op = PRUNE;
            else usage();
            /* deprecated, but we still support it */
            days = optarg;
            break;

        default:
            usage();
            break;
        }
    }

    switch (op) {
    case PRUNE: {
        char buf[4096];

        fprintf(stderr, "ctl_deliver -E is deprecated: "
                "using cyr_expire -E instead\n");

        r = snprintf(buf, sizeof(buf), "%s/cyr_expire", SBIN_DIR);
        if(r < 0 || r >= (int) sizeof(buf)) {
            fatal("cyr_expire command buffer not sufficiently big", EX_CONFIG);
        }

        if (alt_config)
            execl(buf, buf, "-C", alt_config, "-E", days, NULL);
        else
            execl(buf, buf, "-E", days, NULL);

        break;
    }

    case DUMP:
        cyrus_init(alt_config, "ctl_deliver", 0, 0);

        if (duplicate_init(alt_file) != 0) {
            fprintf(stderr,
                    "ctl_deliver: unable to init duplicate delivery database\n");
            exit(1);
        }

        printf("it is NOW: %d\n", (int) time(NULL));
        printf("got %d entries\n", duplicate_dump(stdout));

        r = 0;

        duplicate_done();
        cyrus_done();
        break;

    case NONE:
        r = 2;
        usage();
        break;
    }

    return r;
}
