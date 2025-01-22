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

/* This program purges old entries from the database. It holds an exclusive
 * lock throughout the process.
 *
 * NOTE: by adding the alt_file flag, we let exit() handle the cleanup of
 *       the lock file's fd. That's bad in principal but not in practice. We do
 *       to make the code easier to read.
 */

#include <config.h>

#include <sys/param.h>
#ifndef MAXPATHLEN
#define MAXPATHLEN MAXPATHNAMELEN
#endif

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sysexits.h>
#include <syslog.h>

#include "auth_pts.h"
#include "cyrusdb.h"
#include "imap/global.h"
#include "libconfig.h"
#include "xmalloc.h"

/* global */
static time_t timenow;
static time_t expire_time = (3*60*60); /* 3 Hours */

static int expire_p(void *rockp __attribute__((unused)),
                    const char *key __attribute__((unused)),
                    size_t keylen __attribute__((unused)),
                    const char *data,
                    size_t datalen __attribute__((unused)))
{
    struct auth_state *authstate = (struct auth_state *)data;
    if (authstate->mark + expire_time < timenow) {
        return 1;
    }
    return 0; /* skip this one */
}

static int expire_cb(void *rockp,
                     const char *key, size_t keylen,
                     const char *data __attribute__((unused)),
                     size_t datalen __attribute__((unused)))
{
    /* We only get called when we want to delete it */
    syslog(LOG_DEBUG, "deleting entry for %s", key);

    /* xxx maybe we should use transactions for this */
    cyrusdb_delete((struct db *)rockp, key, keylen, NULL, 0);
    return 0;
}

int main(int argc, char *argv[])
{
    struct db *ptdb;
    int opt;
    int r;
    const char *fname;
    char *alt_config = NULL, *tofree = NULL;

    openlog("ptexpire", LOG_PID, SYSLOG_FACILITY);

    /* keep this in alphabetical order */
    static const char short_options[] = "C:E:";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { "expire-duration", required_argument, NULL, 'E' },

        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        case 'E':
            expire_time = atoi(optarg);
            break;
        default:
            fprintf(stderr,"usage: [-C filename] [-E time]"
                    "\n\t-C <filename>\tAlternate Config File"
                    "\n\t-E <seconds>\tExpiration time"
                    "\n");
            syslog(LOG_ERR, "Invalid command line option");
            exit(-1);
            break;
            /* just pass through */
        }
    }

    cyrus_init(alt_config, "ptexpire", 0, 0);

    syslog(LOG_DEBUG, "ptexpire.c %s", PACKAGE_VERSION);

    /* open database */
    fname = config_getstring(IMAPOPT_PTSCACHE_DB_PATH);
    if (!fname) {
        tofree = strconcat(config_dir, PTS_DBFIL, NULL);
        fname = tofree;
    }

    r = cyrusdb_open(config_ptscache_db, fname, CYRUSDB_CREATE, &ptdb);
    if(r != CYRUSDB_OK) {
        syslog(LOG_ERR, "error opening %s (%s)", fname,
               cyrusdb_strerror(r));
        exit(1);
    }

    if (optind < argc) {
        int i;
        for (i = optind; i < argc; i++) {
	    const char *userid = argv[i];
            int r = cyrusdb_delete(ptdb, userid, strlen(userid), /*tid*/NULL, /*force*/0);
            syslog(LOG_INFO, "Removing cache for %s (%s)", userid,
                   r == CYRUSDB_OK ? "found" : "not-found");
        }
    }
    else {
        timenow = time(0);
        syslog(LOG_INFO, "Expiring entries older than %d seconds (currently %d)",
               (int)expire_time, (int)timenow);

        /* iterate through db, wiping expired entries */
        cyrusdb_foreach(ptdb, "", 0, expire_p, expire_cb, ptdb, NULL);
    }

    cyrusdb_close(ptdb);

    cyrus_done();

    if (tofree) free(tofree);

    syslog(LOG_INFO, "finished");
    return 0;
}
