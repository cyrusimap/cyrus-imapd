/* ctl_mboxlist.c -- do DB related operations on mboxlist
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
 */

/* $Id: ctl_mboxlist.c,v 1.14 2000/07/18 23:27:03 leg Exp $ */

/* currently doesn't catch signals; probably SHOULD */

#include <config.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <syslog.h>
#include <com_err.h>
#include <stdlib.h>
#include <string.h>

#include "exitcodes.h"
#include "mboxlist.h"
#include "acapmbox.h"
#include "imapconf.h"
#include "assert.h"
#include "xmalloc.h"
#include "imap_err.h"

extern int optind;
extern char *optarg;
extern int errno;

enum mboxop { DUMP, POPULATE, RECOVER, CHECKPOINT, UNDUMP, NONE };

void fatal(const char *message, int code)
{
    fprintf(stderr, "fatal error: %s\n", message);
    exit(code);
}

struct dumprock {
    enum mboxop op;
};

static int dump_cb(void *rockp,
		   const char *key, int keylen,
		   const char *data, int datalen)
{
    struct dumprock *d = (struct dumprock *) rockp;
    int r;
    struct mailbox mailbox;
    char *p;
    char *name, *part, *acl;

    /* \0 terminate 'name' */
    name = xstrndup(key, keylen);

    p = strchr(data, ' ');
    if (p == NULL) {
	abort();
    }
    p++;
    acl = strchr(p, ' ');
    if (acl == NULL) {
	abort();
    }
    /* grab 'part', \0 terminate */
    part = xstrndup(p, acl - p);

    /* \0 terminate 'acl' */
    p = acl + 1;
    acl = xstrndup(p, datalen - (p - data));

    switch (d->op) {
    case DUMP:
	printf("%s\t%s\t%s\n", name, part, acl);
	break;

    case POPULATE:
    {
	acapmbox_handle_t *handle = acapmbox_get_handle();
	acapmbox_data_t mboxdata;

	if (!handle) {
	    fprintf(stderr, "can't contact ACAP server\n");
	    return IMAP_SERVER_UNAVAILABLE;
	}
	acapmbox_new(&mboxdata, NULL, name);
	mboxdata.status = ACAPMBOX_COMMITTED;
	mboxdata.acl = acl;

	/* open index file for mailbox */
	r = mailbox_open_header(name, NULL, &mailbox);
	if (!r) {
	    r = mailbox_open_index(&mailbox);
	    if (r) {
		fprintf(stderr, "Error opening index for %s\n", name);
		return IMAP_SERVER_UNAVAILABLE;
	    }
		
	    mboxdata.uidvalidity = mailbox.uidvalidity;
	    mboxdata.answered = mailbox.answered;
	    mboxdata.flagged = mailbox.flagged;
	    mboxdata.deleted = mailbox.deleted;
	    mboxdata.total = mailbox.exists;
		
	    /* close index file for mailbox */
	    mailbox_close(&mailbox);
	}

	r = acapmbox_store(handle, &mboxdata, 1);
	if (r) {
	    fprintf(stderr, "problem storing '%s': %s\n", name,
		    error_message(r));
	    r = 0; /* not a database error, though */
	    return IMAP_IOERROR;
	}
	break;
    }

    default: /* yikes ! */
	abort();
	break;
    }

    free(name);
    free(part);
    free(acl);

    return 0;
}

void do_dump(enum mboxop op)
{
    struct dumprock d;

    assert(op == DUMP || op == POPULATE);

    d.op = op;

    CONFIG_DB_MBOX->foreach(mbdb, "", 0, &dump_cb, &d, NULL);

    return;
}

void do_undump(void)
{
    int r = 0;
    char buf[16384];
    int line = 0;
    char *key, *data;
    int keylen, datalen;
    
    while (fgets(buf, sizeof(buf), stdin)) {
	char *name, *partition, *acl;
	char *p;
	int tries = 0;
	
	line++;

	name = buf;
	for (p = buf; *p && *p != '\t'; p++) ;
	if (!*p) {
	    fprintf(stderr, "line %d: no partition found\n", line);
	    continue;
	}
	*p++ = '\0';
	partition = p;
	for (; *p && *p != '\t'; p++) ;
	if (!*p) {
	    fprintf(stderr, "line %d: no acl found\n", line);
	    continue;
	}
	*p++ = '\0';
	acl = p;
	/* chop off the newline */
	for (; *p && *p != '\r' && *p != '\n'; p++) ;
	*p++ = '\0';

	if (strlen(name) >= MAX_MAILBOX_NAME) {
	    fprintf(stderr, "line %d: mailbox name too long\n", line);
	    continue;
	}
	if (strlen(partition) >= MAX_PARTITION_LEN) {
	    fprintf(stderr, "line %d: partition name too long\n", line);
	    continue;
	}

	key = name; keylen = strlen(key);
	data = mboxlist_makeentry(0, partition, acl); datalen = strlen(data);
	
	tries = 0;
    retry:
	r = CONFIG_DB_MBOX->store(mbdb, key, keylen, data, datalen, NULL);
	switch (r) {
	case 0:
	    break;
	case CYRUSDB_AGAIN:
	    if (tries++ < 5) {
		fprintf(stderr, "warning: DB_LOCK_DEADLOCK; retrying\n");
		goto retry;
	    }
	    fprintf(stderr, "error: too many deadlocks, aborting\n");
	    break;
	default:
	    r = IMAP_IOERROR;
	    break;
	}

	free(data);

	if (r) break;
    }

    if (r) {
	fprintf(stderr, "db error: %s\n", cyrusdb_strerror(r));
    }

    return;
}

void usage(void)
{
    fprintf(stderr, "ctl_mboxlist -c\n");
    fprintf(stderr, "ctl_mboxlist -r\n");
    fprintf(stderr, "ctl_mboxlist -d [-f filename]\n");
    fprintf(stderr, "ctl_mboxlist -u [-f filename] [< mboxlist.dump]\n");
    fprintf(stderr, "ctl_mboxlist -a [-f filename]\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    char *mboxdb_fname = NULL;
    int opt;
    enum mboxop op = NONE;

    config_init("ctl_mboxlist");
    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "adurcf:")) != EOF) {
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

	case 'u':
	    if (op == NONE) op = UNDUMP;
	    else usage();
	    break;

	case 'a':
	    if (op == NONE) op = POPULATE;
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
    case POPULATE:
	mboxlist_init(0);
	mboxlist_open(mboxdb_fname);
	
	do_dump(op);
	
	mboxlist_close();
	mboxlist_done();
	return 0;

    case UNDUMP:
	mboxlist_init(0);
	mboxlist_open(mboxdb_fname);

	do_undump();

	mboxlist_close();
	mboxlist_done();
	return 0;

    default:
	usage();
	return 1;
    }

    return 0;
}
