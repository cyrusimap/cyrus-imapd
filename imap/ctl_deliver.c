/* ctl_deliver.c -- Program to perform operations on duplicate delivery db */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <getopt.h>
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

    /* keep this in alphabetical order */
    static const char short_options[] = "C:E:df:";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        /* n.b. no long option for "deprecated" -E */
        { "dump", no_argument, NULL, 'd' },
        { "filename", required_argument, NULL, 'f' },

        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
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
