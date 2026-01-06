/* tls_prune.c -- program to prune TLS session db of expired sessions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <getopt.h>
#include <stdio.h>
#include <sysexits.h>
#include <unistd.h>

#include "global.h"
#include "tls.h"
#include "util.h"
#include "xmalloc.h"

static void usage(void)
{
    fprintf(stderr, "tls_prune [-C <altconfig>]\n");
    exit(-1);
}

int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt,r;
    char *alt_config = NULL;

    /* keep this in alphabetical order */
    static const char short_options[] = "C:";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */

        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        default:
            usage();
            break;
        }
    }

    cyrus_init(alt_config, "tls_prune", 0, 0);

    r = tls_prune_sessions();

    cyrus_done();

    return r;
}
