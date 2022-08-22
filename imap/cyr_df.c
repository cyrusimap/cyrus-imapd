/* cyr_df.c -- report Cyrus spool partition disk space usage
 *
 * Copyright (c) 1994-2009 Carnegie Mellon University.  All rights reserved.
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
#include <stdlib.h>
#include <stdio.h>
#include <sysexits.h>
#include "string.h"
#include <sys/statvfs.h>
#include <sys/types.h>

#include "global.h"
#include "util.h"
#include "xmalloc.h"

/* forward declarations */
static void usage(void);
static void get_part_stats(const char *key, const char *val, void *rock);

int main(int argc, char *argv[])
{
    int opt, code = 0;
    char *alt_config = NULL;
    int meta = 0;

    /* keep this in alphabetical order */
    static const char *const short_options = "C:m";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { "metadata", no_argument, NULL, 'm' },
        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'm': /* check metapartitions */
            meta = 1;
            break;

        default:
            usage();
        }
    }

    cyrus_init(alt_config, "cyr_df", 0, 0);

    printf("%-12s %12s %12s %12s %3s %s\n", "Partition",
           "1k-blocks", "Used", "Available", "Use%", "Location");

    config_foreachoverflowstring(get_part_stats, &meta);

    cyrus_done();

    exit(code);
}


static void usage(void)
{
    fprintf(stderr,
            "usage: cyr_df [-C <alt_config>] [-m]\n");
    exit(EX_USAGE);
}


/*
 * config_foreachoverflowstring() callback function to find partition-
 * options and print filesystem stats
 */
static void get_part_stats(const char *key, const char *val, void *rock)
{
    int meta = *((int*) rock);
    const char *part, *path;
    struct statvfs s;
    long blocks_used;
    long blocks_percent_used;

    if (meta) {
        if (strncmp("meta", key, 4)) return;
        key += 4;
    }
    if (strncmp("partition-", key, 10)) return;

    part = key+10;
    path = val;

    if (statvfs(path, &s)) return;

    blocks_used = s.f_blocks - s.f_bfree;
    blocks_percent_used = (long)
        (blocks_used * 100.0 / (blocks_used + s.f_bavail) + 0.5);

    printf("%-12s %12ld %12ld %12ld %3ld%% %s\n",
           part,
           (long) (s.f_blocks * (s.f_frsize / 1024.0)),
           (long) ((s.f_blocks - s.f_bfree) * (s.f_frsize / 1024.0)),
           (long) (s.f_bavail * (s.f_frsize / 1024.0)),
           blocks_percent_used, path);
}
