/*
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


static char rcsid[] = "$Id: ptexpire.c,v 1.9 2000/02/10 21:25:43 leg Exp $";

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
	
    r = ptdb->open(ptdb, fnamebuf, NULL, DB_HASH, 0, 0664);
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
