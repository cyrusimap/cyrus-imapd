/* ctl_deliver.c -- Program to perform operations on duplicate delivery db
 $Id: ctl_deliver.c,v 1.9 2001/02/22 19:27:16 ken3 Exp $
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
#include <db.h>
#include <time.h>

#include "util.h"
#include "imapconf.h"
#include "mailbox.h"
#include "exitcodes.h"
#include "mboxlist.h"
#include "duplicate.h"

int
dump_deliver(fname)
     char *fname;
{
    DB *db;
    DB_TXN *tid = NULL;
    DBC *c;
    int ret;
    DBT key, data;
    int count = 0, r;
    time_t mark;
    char *to;

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    ret = db_create(&db, duplicate_dbenv, 0);
    if (ret != 0) {
	fprintf(stderr, "Unable to open db file: %s\n", fname);
	return -1;
    }
    ret = db->open(db, fname, NULL, DB_UNKNOWN, DB_RDONLY, 0664);
    if (ret != 0) {
	fprintf(stderr, "Unable to open db file: %s\n", fname);
	return -1;
    }

    if ((r = db->cursor(db, tid, &c, 0)) != 0) {
	fprintf(stderr, "DBERROR: error creating cursor: %s", strerror(r));
	return -2;
    }

    r = c->c_get(c, &key, &data, DB_FIRST);
    while (r == 0) {
	count++;
	(void)memcpy(&mark, data.data, sizeof(time_t));
	to = ((char *)key.data + (strlen(key.data) + 1));
	printf("id: %-40s\tto: %-20s\tat: %d\n", 
	       (char *) key.data, to, (int) mark);
	r = c->c_get(c, &key, &data, DB_NEXT);
    }
    if (r != DB_NOTFOUND) {
	fprintf(stderr, "error detected looking up entry: %s\n", strerror(r));
    }
    printf("got %d entries\n", count);

    switch (r = c->c_close(c)) {
    case 0:
	break;
    default:
	fprintf(stderr, "error closing cursor: %s\n", strerror(r));
	break;
    }
    switch (r = db->close(db, 0)) {
    case 0:
	break;
    default:
	fprintf(stderr, "error closing database: %s\n", strerror(r));
	break;
    }

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
	    "ctl_deliver [-C <altconfig>] -d -f <dbfile>\n"
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
		"deliver: unable to init duplicate delivery database\n");
	exit(1);
    }
    switch (op) {
    case PRUNE:
	r = duplicate_prune(days);
	break;

    case DUMP:
	if (alt_file == NULL) {
	    usage();
	} else {
	    printf("it is NOW: %d\n", (int) time(NULL));
  
	    dump_deliver(alt_file);
	}
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

/* $Header: /mnt/data/cyrus/cvsroot/src/cyrus/imap/ctl_deliver.c,v 1.9 2001/02/22 19:27:16 ken3 Exp $ */
