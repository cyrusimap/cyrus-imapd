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

/* $Id: ctl_mboxlist.c,v 1.28 2002/03/01 22:17:21 rjs3 Exp $ */

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
#include <sasl/sasl.h>

#include "exitcodes.h"
#include "mboxlist.h"
#include "imapconf.h"
#include "assert.h"
#include "xmalloc.h"
#include "imap_err.h"
#include "mupdate-client.h"

extern int optind;
extern char *optarg;
extern int errno;

enum mboxop { DUMP, M_POPULATE, RECOVER, CHECKPOINT, UNDUMP, NONE };

void fatal(const char *message, int code)
{
    fprintf(stderr, "fatal error: %s\n", message);
    exit(code);
}

struct dumprock {
    enum mboxop op;
    mupdate_handle *h;
};

static int dump_p(void *rockp,
		  const char *key, int keylen,
		  const char *data, int datalen)
{
    return 1;
}

struct mb_node 
{
    char mailbox[MAX_MAILBOX_NAME];
    char server[MAX_MAILBOX_NAME];
    char *acl;
    struct mb_node *next;
};

struct mb_node *del_head = NULL, *act_head = NULL, **act_tail = &act_head;

/* For each mailbox that this guy gets called for, check that
 * it is a mailbox that:
 * a) mupdate server thinks *we* host
 *    -> Because we were called, this is the case, provided we
 *    -> gave the prefix parameter to the remote.
 * b) we do not actually host
 *
 * if that's the case, enqueue a delete
 * otherwise, we both agree that it exists, but we still need
 * to verify that its info is up to date.
 */
static int mupdate_list_cb(struct mupdate_mailboxdata *mdata,
			   const char *cmd, void *context) 
{
    int ret;

    /* the server thinks we have it, do we think we have it? */
    ret = mboxlist_lookup(mdata->mailbox, NULL, NULL, NULL);
    if(ret) {
	struct mb_node *next;
	
	next = xzmalloc(sizeof(struct mb_node));
	strcpy(next->mailbox, mdata->mailbox);
	
	next->next = del_head;
	del_head = next;
    } else {
	/* we both agree that it exists */
	/* throw it onto the back of the activate queue */
	/* we may or may not need to send an update */
	struct mb_node *next;
	
	next = xzmalloc(sizeof(struct mb_node));
	strcpy(next->mailbox, mdata->mailbox);
	strcpy(next->server, mdata->server);
	if(!strncmp(cmd, "MAILBOX", 7))
	    next->acl = xstrdup(mdata->acl);

	*act_tail = next;
	act_tail = &(next->next);
    }
    return 0;
}

static int dump_cb(void *rockp,
		   const char *key, int keylen,
		   const char *data, int datalen)
{
    struct dumprock *d = (struct dumprock *) rockp;
    int r;
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

    case M_POPULATE: 
    {
	char *realpart = xmalloc(strlen(config_servername) + 1
				 + strlen(part) + 1);
	int skip_flag;
	
	/* realpart is 'hostname!partition' */
	sprintf(realpart, "%s!%s", config_servername, part);

	/* If they match, then we should check that we actually need
	 * to update it.  If they *don't* match, then we believe that we
	 * need to send fresh data.  There will be no point at which something
	 * is in the act_head list that we do not have locally, because that
	 * is a condition of being in the act_head list */
	if(act_head && !strcmp(name, act_head->mailbox)) {
	    struct mb_node *tmp;
	    /* Do not update if location does match, and there is an acl,
	     * and the acl matches */
	    if(act_head->acl &&
	       !strcmp(realpart, act_head->server) &&
	       !strcmp(acl, act_head->acl)) {
		skip_flag = 1;
	    } else {
		skip_flag = 0;
	    }

	    /* in any case, free the node. */
	    if(act_head->acl) free(act_head->acl);
	    tmp = act_head;
	    act_head = act_head->next;
	    free(tmp);
	} else {
	    skip_flag = 0;
	}

	if(skip_flag) break;

	r = mupdate_activate(d->h,name,realpart,acl);

	free(realpart);
	
	if(r == MUPDATE_NOCONN) {
	    fprintf(stderr, "permanant failure storing '%s'\n", name);
	    return IMAP_IOERROR;
	} else if (r == MUPDATE_FAIL) {
	    fprintf(stderr,
		    "temporary failure storing '%s' (update continuing)",
		    name);
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

    assert(op == DUMP || op == M_POPULATE);

    d.op = op;

    if(op == M_POPULATE) {
	int ret;
	char buf[1024];

	sasl_client_init(NULL);

	ret = mupdate_connect(NULL, NULL, &(d.h), NULL);
	if(ret) {
	    fprintf(stderr, "couldn't connect to mupdate server\n");
	    exit(1);
	}

	/* now we need a list of what the remote thinks we have
	 * To generate it, ask for a prefix of '<our hostname>!',
	 * (to ensure we get exactly our hostname) */
	snprintf(buf, sizeof(buf), "%s!", config_servername);
	ret = mupdate_list(d.h, mupdate_list_cb, buf, NULL);
	if(ret) {
	    fprintf(stderr, "couldn't do LIST command on mupdate server\n");
	    exit(1);
	}

	/* Run pending deletes */
	while(del_head) {
	    struct mb_node *me = del_head;
	    del_head = del_head->next;

	    ret = mupdate_delete(d.h, me->mailbox);
	    if(ret) {
		fprintf(stderr, "couldn't delete %s", me->mailbox);
		exit(1);
	    }
		
	    free(me);
	}
    }

    /* Dump Database */
    CONFIG_DB_MBOX->foreach(mbdb, "", 0, &dump_p, &dump_cb, &d, NULL);

    if(op == M_POPULATE) {
	mupdate_disconnect(&(d.h));
	sasl_done();
    }
    
    return;
}

void do_undump(void)
{
    int r = 0;
    char buf[16384];
    int line = 0;
    char last_commit[MAX_MAILBOX_NAME];
    char *key=NULL, *data=NULL;
    int keylen, datalen;
    const int PER_COMMIT = 1000;
    int untilCommit = PER_COMMIT;
    struct txn *tid = NULL;
    
    last_commit[0] = '\0';

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
	r = CONFIG_DB_MBOX->store(mbdb, key, keylen, data, datalen, &tid);
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

	if(--untilCommit == 0) {
	    /* commit */
	    r = CONFIG_DB_MBOX->commit(mbdb, tid);
	    if(r) break;
	    tid = NULL;
	    untilCommit = PER_COMMIT;
	    strncpy(last_commit,key,MAX_MAILBOX_NAME);
	}

	if (r) break;
    }

    if(!r && tid) {
	/* commit the last transaction */
	r=CONFIG_DB_MBOX->commit(mbdb, tid);
    }

    if (r) {
	if(tid) CONFIG_DB_MBOX->abort(mbdb, tid);
	fprintf(stderr, "db error: %s\n", cyrusdb_strerror(r));
	if(key) fprintf(stderr, "was processing mailbox: %s\n", key);
	if(last_commit[0]) fprintf(stderr, "last commit was at: %s\n",
				   last_commit);
	else fprintf(stderr, "no commits\n");
    }
    

    return;
}

void usage(void)
{
    fprintf(stderr, "DUMP:\n");
    fprintf(stderr, "  ctl_mboxlist [-C <alt_config>] -d [-f filename]\n");
    fprintf(stderr, "UNDUMP:\n");
    fprintf(stderr,
	    "  ctl_mboxlist [-C <alt_config>] -u [-f filename]"
	    "    [< mboxlist.dump]\n");
    fprintf(stderr, "MUPDATE populate:\n");
    fprintf(stderr, "  ctl_mboxlist [-C <alt_config>] -m [-f filename]\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    char *mboxdb_fname = NULL;
    int opt;
    enum mboxop op = NONE;
    char *alt_config = NULL;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    while ((opt = getopt(argc, argv, "C:amdurcf:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'r':
	    /* deprecated, but we still support it */
	    fprintf(stderr, "ctl_mboxlist -r is deprecated: "
		    "use ctl_cyrusdb -r instead\b");
	    syslog(LOG_WARNING, "ctl_mboxlist -r is deprecated: "
		   "use ctl_cyrusdb -r instead\b");
	    if (op == NONE) op = RECOVER;
	    else usage();
	    break;

	case 'c':
	    /* deprecated, but we still support it */
	    fprintf(stderr, "ctl_mboxlist -c is deprecated: "
		    "use ctl_cyrusdb -c instead\b");
	    syslog(LOG_WARNING, "ctl_mboxlist -c is deprecated: "
		   "use ctl_cyrusdb -c instead\b");
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

	case 'm':
	    if (op == NONE) op = M_POPULATE;
	    else usage();
	    break;

	default:
	    usage();
	    break;
	}
    }

    config_init(alt_config, "ctl_mboxlist");

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
    case M_POPULATE:
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
