/* ctl_mboxlist.c -- do DB related operations on mboxlist
 *
 * Copyright 2000 Carnegie Mellon University
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
 */

/* $Id: ctl_mboxlist.c,v 1.1 2000/02/15 22:21:18 leg Exp $ */


#include <config.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <syslog.h>

#include <db.h>
#include "exitcodes.h"
#include "mboxlist.h"
#include "config.h"

extern int optind;
extern char *optarg;
extern int errno;

extern DB *mbdb;
extern DB_ENV *dbenv;

void fatal(const char *message, int code)
{
    fprintf(stderr, "fatal error: %s\n", message);
    exit(code);
}

void do_dump(void)
{
    int r;
    DBC *cursor = NULL;
    DBT key, data;
    int buf[16384];
    int bufkey[MAX_MAILBOX_NAME * 2];
    struct mbox_entry *mboxent;

    memset(&key, 0, sizeof(key));
    key.flags = DB_DBT_USERMEM;
    key.data = bufkey;
    key.ulen = sizeof(bufkey);

    memset(&data, 0, sizeof(data));
    data.flags = DB_DBT_USERMEM;
    data.data = buf;
    data.ulen = sizeof(buf);

    r = mbdb->cursor(mbdb, NULL, &cursor, 0);
    if (r != 0) { 
	fprintf(stderr, "DBERROR: Unable to create cursor: %s\n",
		db_strerror(r));
	goto error;
    }

    r = cursor->c_get(cursor, &key, &data, DB_FIRST);
    while (r != DB_NOTFOUND) {
	switch (r) {
	case 0:
	    break;
	default:
	    fprintf(stderr, "DBERROR: error advancing: %s\n", db_strerror(r));
	    goto error;
	}

	mboxent = (struct mbox_entry *) data.data;
	printf("%s\t%s\t%s\n", mboxent->name, 
	       mboxent->partition, mboxent->acls);
	
	r = cursor->c_get(cursor, &key, &data, DB_NEXT);
    }

 error:
    switch (r = cursor->c_close(cursor)) {
    case 0:
	break;
    default:
	fprintf(stderr, "DBERROR: error closing cursor: %s\n", db_strerror(r));
	return;
    }

    return;
}

void usage(void)
{
    fprintf(stderr, "ctl_mboxlist -c\n");
    fprintf(stderr, "ctl_mboxlist -r\n");
    fprintf(stderr, "ctl_mboxlist -d [-f filename]\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    char *mboxdb_fname = NULL;
    int opt;
    enum { DUMP, RECOVER, CHECKPOINT, NONE } op = NONE;

    config_init("ctl_mboxlist");
    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "drcf:")) != EOF) {
	switch (opt) {
	case 'r':
	    if (op == NONE) op = RECOVER;
	    else usage();
	    break;

	case 'c':
	    if (op == NONE) op = CHECKPOINT;
	    else usage();
	    break;

	case 'f':
	    if (op != NONE && op != DUMP) usage();
	    if (!mboxdb_fname) {
		mboxdb_fname = optarg;
	    } else {
		usage();
	    }
	    break;

	case 'd':
	    if (op == NONE) op = DUMP;
	    else usage();
	    break;

	default:
	    usage();
	    break;
	}
    }

    switch (op) {
    case RECOVER:
	syslog(LOG_NOTICE, "running mboxlist recovery");
	mboxlist_init(MBOXLIST_RECOVER);
	mboxlist_done();
	syslog(LOG_NOTICE, "done running mboxlist recovery");
	return 0;

    case CHECKPOINT:
	syslog(LOG_NOTICE, "checkpointing mboxlist");
	mboxlist_init(MBOXLIST_SYNC);
	mboxlist_done();
	return 0;
	
    case DUMP:
	mboxlist_init(0);
	mboxlist_open(mboxdb_fname);
	
	do_dump();
	
	mboxlist_close();
	mboxlist_done();
	return 0;

    default:
	usage();
	return 1;
    }

    return 0;
}
