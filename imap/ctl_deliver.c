/* ctl_deliver.c -- Program to perform operations on duplicate delivery db
 $Id: ctl_deliver.c,v 1.10 2001/09/07 18:31:58 ken3 Exp $
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
#include <cyrusdb.h>
#include <time.h>

#include "util.h"
#include "imapconf.h"
#include "exitcodes.h"
#include "duplicate.h"


static int dump_p(void *rockp,
		  const char *key, int keylen,
		  const char *data, int datalen)
{
    return 1;
}

static int dump_cb(void *rockp,
		   const char *key, int keylen,
		   const char *data, int datalen)
{
    int *count = (int *) rockp;
    time_t mark;
    char *id, *to, *freeme = NULL;

    (*count)++;

    memcpy(&mark, data, sizeof(time_t));
    to = (char*) key + strlen(key) + 1;
    id = (char *) key;
#if 0
    if (*key != '<') {
	int n;
	char *p;

	id = freeme = (char *) xmalloc(2 * strlen(key) + 1);

	for (n = 0, p = freeme; n < strlen(key); n++, p+=2)
	    sprintf(p, "%02X", key[n]);
    }
#endif
    printf("id: %-40s\tto: %-20s\tat: %d\n", id, to, mark);

    if (freeme) free(freeme);

    return 0;
}

int
dump_deliver(fname)
    char *fname;
{
    char *tofree = NULL;
    struct db *db;
    int count = 0, r;

   /* create the name of the db file */
    if (!fname) {
	fname = (char *) xmalloc(strlen(config_dir)+sizeof(FNAME_DELIVERDB)+1);
	tofree = fname;
	strcpy(fname, config_dir);
	strcat(fname, FNAME_DELIVERDB);
    }

    r = CONFIG_DB_DELIVER->open(fname, &db);
    if (r != CYRUSDB_OK) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s",
	       fname, cyrusdb_strerror(r));
	return 1;
    }
    else {
	/* check each entry in our database */
	CONFIG_DB_DELIVER->foreach(db, "", 0, &dump_p, &dump_cb, &count, NULL);
	printf("got %d entries\n", count);

	CONFIG_DB_DELIVER->close(db);
    }

    if (tofree) free(tofree);

    return 0;
}

void fatal(const char *message, int code)
{
    fprintf(stderr, "fatal error: %s\n", message);
    exit(code);
}

void usage(void)
{
    fprintf(stderr,
	    "ctl_deliver [-C <altconfig>] -d [-f <dbfile>]\n"
	    "ctl_deliver [-C <altconfig>] [-r] -E <days>\n");
    exit(-1);
}


int
main(argc, argv)
     int argc;
     char *argv[];
{
    extern char *optarg;
    int opt, r = 0;
    char *alt_file = NULL;
    char *alt_config = NULL;
    int days = 0;
    int flag = 0;
    enum { DUMP, PRUNE, RECOVER, NONE } op = NONE;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "C:drE:f:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'd':
	    if (op == NONE) op = DUMP;
	    else usage();
	    break;

	case 'r':
	    flag |= DUPLICATE_RECOVER;
	    if (op == NONE) op = RECOVER;
	    break;

        case 'f':
            if (alt_file == NULL) alt_file = optarg;
            else usage ();
            break;

	case 'E':
	    if (op == NONE || op == RECOVER) op = PRUNE;
	    else usage();
	    days = atoi(optarg);
	    break;
	
	default:
	    usage();
	    break;
	}
    }

    config_init(alt_config, "ctl_deliver");

    if (duplicate_init(flag) != 0) {
	fprintf(stderr, 
		"ctl_deliver: unable to init duplicate delivery database\n");
	exit(1);
    }
    switch (op) {
    case PRUNE:
	r = duplicate_prune(days);
	break;

    case DUMP:
	printf("it is NOW: %d\n", (int) time(NULL));
  
	dump_deliver(alt_file);

	r = 0;
	break;

    case RECOVER:
	break;

    case NONE:
	r = 2;
	usage();
	break;
    }
    duplicate_done();

    return r;
}

/* $Header: /mnt/data/cyrus/cvsroot/src/cyrus/imap/ctl_deliver.c,v 1.10 2001/09/07 18:31:58 ken3 Exp $ */
