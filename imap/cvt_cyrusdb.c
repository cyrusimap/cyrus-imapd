/* cvt_cyrusdb.c - Convert between two database formats */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <getopt.h>
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
               "This is because some database backends do not\n"
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

    int r = cyrusdb_convert(old_db, new_db, OLDDB, NEWDB);
    if (r) {
        printf("\nDBERROR: Conversion failed (r was %d)."
               " Check syslog for details.\n", r);
    }

    cyrus_done();

    return 0;
}
