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
 * $Id: ctl_cyrusdb.c,v 1.3 2001/09/29 01:36:15 ken3 Exp $
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

#include "util.h"
#include "imapconf.h"
#include "exitcodes.h"
#include "cyrusdb.h"


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
    char dirname[1024];
    char *msg = "";

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

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

    syslog(LOG_NOTICE, "%s", msg);
    r = (&cyrusdb_db3)->init(dirname, flag);

    if (r) {
	syslog(LOG_ERR, "DBERROR: init %s: %s", dirname,
	       cyrusdb_strerror(r));
	fprintf(stderr, 
		"ctl_cyrusdb: unable to init environment\n");
	op = NONE;
    }

    switch (op) {
    case RECOVER:
	r2 = 0;
	break;

    case CHECKPOINT:
	r2 = (&cyrusdb_db3)->sync();
	if (r2) {
	    syslog(LOG_ERR, "DBERROR: sync %s: %s", dirname,
		   cyrusdb_strerror(r));
	    fprintf(stderr, 
		    "ctl_cyrusdb: unable to sync environment\n");
	}
	break;

    default:
	break;
    }

    if (!r) (&cyrusdb_db3)->done();

    syslog(LOG_NOTICE, "done %s", msg);

    exit(r || r2);
}
