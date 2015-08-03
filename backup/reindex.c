/* reindex.c -- replication-based backup reindexer
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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
 */

/*
 * Prototype of building backup index from anticipated backup data format.
 * This tool will go away once its functionality is properly integrated into
 * the backup system and its utilities.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "lib/exitcodes.h"

#include "backup/gzuncat.h"

EXPORTED void fatal(const char *error, int code) {
    fprintf(stderr, "fatal error: %s\n", error);
    exit(code);
}

static void usage(const char *name) {
    fprintf(stderr, "Usage: %s backup_filename\n", name);
    exit(EC_USAGE);
}

static void oneline(char *str) {
    char *p;

    for (p = str; *p; p++) {
        if (*p == '\n') {
            *p = '\0';
            break;
        }
    }
}

int main (int argc, char **argv) {
    if (argc != 2) usage(argv[0]);

    const char *backup_filename = argv[1];

    fprintf(stderr, "reindexing %s...\n", backup_filename);

    struct gzuncat *gzuc = gzuc_open(backup_filename);

    while (gzuc && !gzuc_eof(gzuc)) {
        gzuc_member_start(gzuc);

        fprintf(stderr, "found member at offset %jd\n", gzuc_member_offset(gzuc));

        while (!gzuc_member_eof(gzuc)) {
            char buf[1024];
            ssize_t n = gzuc_read(gzuc, buf, sizeof(buf));

            if (n > 0) {
                fprintf(stderr, "read %lu bytes from offset %jd:\n", n, gzuc_member_offset(gzuc));
                oneline(buf);
                fprintf(stderr, "> %.70s ...\n", buf);
            }
            else if (n < 0) {
                fprintf(stderr, "gzuc_read returned %ld\n", n);
            }
            else {
                fprintf(stderr, "found end of member\n");
            }
        }

        gzuc_member_end(gzuc, NULL);
    }

    fprintf(stderr, "reached end of file\n");

    gzuc_close(&gzuc);

    return 0;
}
