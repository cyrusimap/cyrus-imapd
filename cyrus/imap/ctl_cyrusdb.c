/* ctl_cyrusdb.c -- Program to perform operations common to all cyrus DBs
 *
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
 * $Id: ctl_cyrusdb.c,v 1.7 2002/02/05 21:34:17 ken3 Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <com_err.h>
#include <errno.h>
#include <time.h>

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "util.h"
#include "imapconf.h"
#include "exitcodes.h"
#include "cyrusdb.h"

/* find out what things are using... */
#include "mboxlist.h"
#include "seen.h"
#include "duplicate.h"
#include "tls.h"

struct cyrusdb_backend *dbenvs[] =
{
    CONFIG_DB_MBOX,
    CONFIG_DB_SUBS,
    CONFIG_DB_SEEN,
    CONFIG_DB_DUPLICATE,
    CONFIG_DB_TLS,
    NULL
};

void fatal(const char *message, int code)
{
    fprintf(stderr, "fatal error: %s\n", message);
    exit(code);
}

void usage(void)
{
    fprintf(stderr, "ctl_cyrusdb [-C <altconfig>] -c\n");
    fprintf(stderr, "ctl_cyrusdb [-C <altconfig>] -r\n");
    exit(-1);
}


int
main(argc, argv)
     int argc;
     char *argv[];
{
    extern char *optarg;
    int opt, r, r2;
    char *alt_config = NULL;
    int flag = 0;
    enum { RECOVER, CHECKPOINT, NONE } op = NONE;
    char dirname[1024], backup1[1024], backup2[1024];
    char *msg = "";
    int i;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);
    r = r2 = 0;

    while ((opt = getopt(argc, argv, "C:rc")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'r':
	    flag |= CYRUSDB_RECOVER;
	    msg = "recovering cyrus databases";
	    if (op == NONE) op = RECOVER;
	    else usage();
	    break;

	case 'c':
	    msg = "checkpointing cyrus databases";
	    if (op == NONE) op = CHECKPOINT;
	    else usage();
	    break;

	default:
	    usage();
	    break;
	}
    }

    if (op == NONE) {
	usage();
	exit(1);
    }

    config_init(alt_config, "ctl_cyrusdb");

    /* create the name of the db directory */
    strcpy(dirname, config_dir);
    strcat(dirname, FNAME_DBDIR);

    /* create the names of the backup directories */
    strcpy(backup1, dirname);
    strcat(backup1, ".backup1/");
    strcpy(backup2, dirname);
    strcat(backup2, ".backup2/");

    syslog(LOG_NOTICE, "%s", msg);
    for (i = 0; dbenvs[i] != NULL; i++) {
	r = (dbenvs[i])->init(dirname, flag);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: init %s: %s", dirname,
		   cyrusdb_strerror(r));
	    fprintf(stderr, 
		    "ctl_cyrusdb: unable to init environment\n");
	    dbenvs[i] = NULL;
	    /* stop here, but we need to close all existing ones */
	    break;
	}
	
	r2 = 0;
	switch (op) {
	case RECOVER:
	    break;
	    
	case CHECKPOINT:
	    r2 = (dbenvs[i])->sync();
	    if (r2) {
		syslog(LOG_ERR, "DBERROR: sync %s: %s", dirname,
		       cyrusdb_strerror(r));
		fprintf(stderr, 
			"ctl_cyrusdb: unable to sync environment\n");
	    }

	    /* ARCHIVE */
	    r2 = 0;

	    /* only rotate the backup the first time through */
	    if (i == 0) {
		char *tail;
		DIR *dirp;
		struct dirent *dirent;

		tail = backup2 + strlen(backup2);

		/* remove db.backup2 */
		dirp = opendir(backup2);
		if (dirp) {
		    while ((dirent = readdir(dirp)) != NULL) {
			if (dirent->d_name[0] == '.') continue;

			strcpy(tail, dirent->d_name);
			unlink(backup2);
		    }

		    closedir(dirp);
		}
		*tail = '\0';
		r2 = rmdir(backup2);

		/* move db.backup1 to db.backup2 */
		if (r2 == 0 || errno == ENOENT)
		    r2 = rename(backup1, backup2);

		/* make a new db.backup1 */
		if (r2 == 0 || errno == ENOENT)
		    r2 = mkdir(backup1, 0755);
	    }

	    /* do the archive */
	    if (r2 == 0)
		r2 = (dbenvs[i])->archive(backup1);

	    if (r2) {
		syslog(LOG_ERR, "DBERROR: archive %s: %s", dirname,
		       cyrusdb_strerror(r));
		fprintf(stderr, 
			"ctl_cyrusdb: unable to archive environment\n");
	    }

	    break;
	    
	default:
	    break;
	}
    }

    for (i = 0; dbenvs[i] != NULL; i++) {
	r2 = (dbenvs[i])->done();
	if (r2) {
	    syslog(LOG_ERR, "DBERROR: done: %s", cyrusdb_strerror(r));
	}
    }

    syslog(LOG_NOTICE, "done %s", msg);
    exit(r || r2);
}
