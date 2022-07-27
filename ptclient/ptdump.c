/*
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
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "auth_pts.h"
#include "cyrusdb.h"
#include "imap/global.h"
#include "libconfig.h"

static int dump_cb(void *rockp __attribute__((unused)),
                     const char *key, size_t keylen,
                     const char *data,
                     size_t datalen __attribute__((unused)))
{
    struct auth_state *authstate = (struct auth_state *)data;
    int i;

    printf("user: ");
    fwrite(key, keylen, 1, stdout);
    printf(" time: %d groups: %d\n",
           (unsigned)authstate->mark, (unsigned)authstate->ngroups);

    for (i=0; i < authstate->ngroups; i++)
        printf("  %s\n",authstate->groups[i].id);

    return 0;
}

int main(int argc, char *argv[])
{
    struct db *ptdb;
    int opt;
    int r;
    const char *fname;
    char *alt_config = NULL, *tofree = NULL;

    /* keep this in alphabetical order */
    static const char *const short_options = "C:";

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
            fprintf(stderr,"usage: [-C filename]"
                    "\n\t-C <filename>\tAlternate Config File"
                    "\n");
            exit(-1);
            break;
            /* just pass through */
        }
    }

    cyrus_init(alt_config, "ptdump", 0, 0);

    /* open database */
    fname = config_getstring(IMAPOPT_PTSCACHE_DB_PATH);
    if (!fname) {
        tofree = strconcat(config_dir, PTS_DBFIL, NULL);
        fname = tofree;
    }

    r = cyrusdb_open(config_ptscache_db, fname, CYRUSDB_CREATE, &ptdb);
    if(r != CYRUSDB_OK) {
        fprintf(stderr,"error opening %s (%s)", fname,
               cyrusdb_strerror(r));
        exit(1);
    }

    if (tofree) free(tofree);

    /* iterate through db, printing entries */
    cyrusdb_foreach(ptdb, "", 0, NULL, dump_cb, ptdb, NULL);

    cyrusdb_close(ptdb);

    cyrus_done();

    return 0;
}
