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

#include "lock.h"
#include "auth_krb_pts.h"


static char rcsid[] = "$Id: ptexpire.c,v 1.10.16.1 2002/09/26 19:01:04 ken3 Exp $";

int main(int argc, char *argv[])
{
    char fnamebuf[MAXPATHLEN];
    DB *ptdb;
    DBC *cursor;
    DBT key, data;
    time_t expire_time = EXPIRE_TIME;
    extern char *optarg;
    int opt;
    int fd;
    int r;
    char *alt_file = NULL;
    struct auth_state *authstate;
    time_t timenow;

    openlog("ptexpire", LOG_PID, LOG_LOCAL7);

    while ((opt = getopt(argc, argv, "v:f:E:")) != EOF) {
	switch (opt) {
	case 'f':
	    alt_file = optarg;
	    break;
	case 'E':
	    expire_time = atoi(optarg);
	    break;
	case '?':
	    fprintf(stderr,"usage: -vEf"
		    "\n\t-E <seconds>\tExpiration time"
		    "\n\t-v <n>\tVerbosity level"
		    "\n\t-f <dbfile>\tAlternate location for the db file."
	     "\n\t*WARNING* Using this option bypasses the locking mechanism."
		    "\n\t** DO NOT USE THIS OPTION ON A LIVE DATABASE FILE **"
		    "\n");
	    syslog(LOG_ERR, "Invalid command line option");
	    exit(-1);
	    break;
	default:
	    break;
	    /* just pass through */
	}
    }

    timenow = time(0);
    syslog(LOG_NOTICE, "start (%d): %s", timenow, rcsid);
    syslog(LOG_DEBUG, "Expiring entries older than %d seconds", expire_time);
    
    /* lock database */
    if (alt_file) {
	syslog(LOG_DEBUG, "Using alternate file: %s", alt_file);
	strcpy(fnamebuf, alt_file);
    } else {
	strcpy(fnamebuf, STATEDIR);
	strcat(fnamebuf, PTS_DBLOCK);
	fd = open(fnamebuf, O_CREAT|O_TRUNC|O_RDWR, 0664);
	if (fd == -1) {
	    syslog(LOG_ERR, "IOERROR: creating lock file %s: %m", fnamebuf);
	    return 1;
	}
	if (lock_blocking(fd) < 0) {
	    syslog(LOG_ERR, "IOERROR: locking lock file %s: %m", fnamebuf);
	    return 1;
	}
	strcpy(fnamebuf, STATEDIR);
	strcat(fnamebuf, PTS_DBFIL);
    }

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    r = db_create(&ptdb, NULL, 0);
    if (r != 0) {
	syslog(LOG_ERR, "db_create: %s", db_strerror(r));
	return 1;
    }

#if DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 1
    r = ptdb->open(ptdb, NULL, fnamebuf, NULL, DB_HASH, 0, 0664);
#else
    r = ptdb->open(ptdb, fnamebuf, NULL, DB_HASH, 0, 0664);
#endif
    if (r != 0) {
	syslog(LOG_ERR, "opening %s: %s", fnamebuf, db_strerror(r));
	return 1;
    }
    
    r = ptdb->cursor(ptdb, NULL, &cursor, DB_WRITECURSOR);
    if (r != 0) { 
	syslog(LOG_ERR, "unable to create cursor: %s", db_strerror(r));
	return 1;
    }

    r = cursor->c_get(cursor, &key, &data, DB_FIRST);
    while (r != DB_NOTFOUND) {
	if (r != 0) {
	    syslog(LOG_ERR, "error advancing: %s", db_strerror(r));
	    return 1;
	}
	
	authstate = data.data;
	if (authstate->mark + expire_time < timenow) {
	    r = cursor->c_del(cursor, 0);
	    if (r != 0) {
		syslog(LOG_ERR, "error deleting: %s", db_strerror(r));
		return 1;
	    }
	}
	    
	r = cursor->c_get(cursor, &key, &data, DB_NEXT);
    }
    r = cursor->c_close(cursor);
    if (r != 0) {
	syslog(LOG_ERR, "error closing cursor: %s", db_strerror(r));
    }

    r = ptdb->close(ptdb, 0);
    if (r != 0) {
	syslog(LOG_ERR, "DBERROR: closing %s: %s", fnamebuf, db_strerror);
    }

    syslog(LOG_NOTICE, "finished");
    exit(0);
}      

int fatal(char *msg, int exitcode)
{
    syslog(LOG_ERR,"%s", msg);
    exit(-1);
}
