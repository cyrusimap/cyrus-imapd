/* cvt_cyrusdb.c -- Convert between two database formats
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>

#include <sys/ipc.h>
#include <sys/msg.h>

#include "cyrusdb.h"
#include "global.h"
#include "mailbox.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

int main(int argc, char *argv[])
{
    const char *OLDDB = NULL, *NEWDB = NULL;
    const char *old_db, *new_db;
    int i;
    int opt;
    char *alt_config = NULL;
    int r;

    while ((opt = getopt(argc, argv, "C:")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        }
    }

    if ((argc - optind) != 4) {
        strarray_t *backends = cyrusdb_backends();
        char sep;

        fprintf(stderr, "Usage: %s [-C altconfig] <old db> <old db backend> <new db> <new db backend>\n", argv[0]);
        fprintf(stderr, "Usable Backends:  ");

        for(i=0, sep = ':'; i < backends->count; i++) {
            fprintf(stderr, "%c %s", sep, strarray_nth(backends, i));
            sep = ',';
        }
        strarray_free(backends);

        fprintf(stderr, "\n");
        exit(-1);
    }

    old_db = argv[optind];
    new_db = argv[optind+2];

    if (old_db[0] != '/' || new_db[0] != '/') {
        printf("\nSorry, you cannot use this tool with relative path names.\n"
               "This is because some database backends (mainly berkeley) do not\n"
               "always do what you would expect with them.\n"
               "\nPlease use absolute pathnames instead.\n\n");
        exit(EX_OSERR);
    }

    OLDDB = argv[optind+1];
    NEWDB = argv[optind+3];

    if (NEWDB == OLDDB) {
        fatal("no conversion required", EX_TEMPFAIL);
    }

    cyrus_init(alt_config, "cvt_cyrusdb", 0, 0);

    printf("Converting from %s (%s) to %s (%s)\n", old_db, OLDDB,
           new_db, NEWDB);

    r = cyrusdb_convert(old_db, new_db, OLDDB, NEWDB);
    if (r) {
        printf("\nDBERROR: Conversion failed (r was %d)."
               " Check syslog for details.\n", r);
    }

    cyrus_done();

    return 0;
}
