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
 * $Id: ctl_cyrusdb.c,v 1.1 2001/09/18 14:05:06 ken3 Exp $
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
    fprintf(stderr,
	    "ctl_cyrusdb [-C <altconfig>] [-r]\n");
    exit(-1);
}


int
main(argc, argv)
     int argc;
     char *argv[];
{
    extern char *optarg;
    int opt, r = 0;
    char *alt_config = NULL;
    int flag = 0;
    enum { RECOVER, NONE } op = NONE;
    char buf[1024];

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "C:r")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'r':
	    flag |= CYRUSDB_RECOVER;
	    if (op == NONE) op = RECOVER;
	    break;

	default:
	    usage();
	    break;
	}
    }

    config_init(alt_config, "ctl_cyrusdb");

    /* create the name of the db file */
    strcpy(buf, config_dir);
    strcat(buf, FNAME_DBDIR);
    r = (&cyrusdb_db3)->init(buf, flag);

    if (r != 0) {
	syslog(LOG_ERR, "DBERROR: init %s: %s", buf,
	       cyrusdb_strerror(r));
	fprintf(stderr, 
		"ctl_cyrusdb: unable to init databases\n");
	exit(1);
    }
    switch (op) {
    case RECOVER:
	break;

    case NONE:
	r = 2;
	usage();
	break;
    }
    (&cyrusdb_db3)->done();

    return r;
}
