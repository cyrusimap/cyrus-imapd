/*
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "auth_krb_pts.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "imapconf.h"
#include "lock.h"

static char rcsid[] = "$Id: ptexpire.c,v 1.10.16.4 2002/11/15 21:47:05 rjs3 Exp $";

/* global */
time_t timenow;
time_t expire_time = (3*60*60); /* 3 Hours */

int config_need_data = 0;

int fatal(char *msg, int exitcode __attribute__((unused)))
{
    syslog(LOG_ERR,"%s", msg);
    exit(-1);
}

static int expire_p(void *rockp __attribute__((unused)),
		    const char *key __attribute__((unused)),
		    int keylen __attribute__((unused)),
		    const char *data,
		    int datalen __attribute__((unused)))
{
    struct auth_state *authstate = (struct auth_state *)data;
    if (authstate->mark + expire_time < timenow) {
	return 1;
    }
    return 0; /* skip this one */
}

static int expire_cb(void *rockp,
		     const char *key, int keylen,
		     const char *data __attribute__((unused)),
		     int datalen __attribute__((unused))) 
{
    /* We only get called when we want to delete it */
    syslog(LOG_DEBUG, "deleteing entry for %s", key);

    /* xxx maybe we should use transactions for this */
    CONFIG_DB_PTS->delete((struct db *)rockp, key, keylen, NULL, 0);
    return 0;
}

int main(int argc, char *argv[])
{
    struct db *ptdb;
    char fnamebuf[1024];
    extern char *optarg;
    int opt;
    int r;
    char *alt_config = NULL;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);
    
    openlog("ptexpire", LOG_PID, LOG_LOCAL7);

    while ((opt = getopt(argc, argv, "C:E:")) != EOF) {
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

    config_init(alt_config, "ptexpire");

    timenow = time(0);
    syslog(LOG_INFO, "Expiring entries older than %d seconds (currently %d)",
	   expire_time, timenow);
    syslog(LOG_DEBUG, "%s", rcsid);
    
    /* open database */
    strcpy(fnamebuf, config_dir);
    strcat(fnamebuf, PTS_DBFIL);
    r = CONFIG_DB_PTS->open(fnamebuf, &ptdb);
    if(r != CYRUSDB_OK) {
	syslog(LOG_ERR, "error opening %s (%s)", fnamebuf,
	       cyrusdb_strerror(r));
	exit(1);
    }

    /* iterate through db, wiping expired entries */
    CONFIG_DB_PTS->foreach(ptdb, "", 0, expire_p, expire_cb, ptdb, NULL);

    CONFIG_DB_PTS->close(ptdb);

    cyrus_done();

    syslog(LOG_INFO, "finished");
    return 0;
}      
