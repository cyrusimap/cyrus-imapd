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
 * $Id: ctl_cyrusdb.c,v 1.11 2002/05/06 21:27:07 rjs3 Exp $
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
#include "xmalloc.h"
#include "cyrusdb.h"

/* find out what things are using... */
#include "mboxlist.h"
#include "seen.h"
#include "duplicate.h"
#include "tls.h"

#define N(a) (sizeof(a) / sizeof(a[0]))

struct cyrusdb {
    const char *name;
    struct cyrusdb_backend *env;
    int archive;
} dblist[] = {
    { FNAME_MBOXLIST,		CONFIG_DB_MBOX,		1 },
    { FNAME_DELIVERDB,		CONFIG_DB_DUPLICATE,	0 },
    { FNAME_TLSSESSIONS,	CONFIG_DB_TLS,		0 },
    { NULL,			NULL,			0 }
};

static int compdb(const void *v1, const void *v2)
{
    struct cyrusdb *db1 = (struct cyrusdb *) v1;
    struct cyrusdb *db2 = (struct cyrusdb *) v2;

    return (db1->env - db2->env);
}

void fatal(const char *message, int code)
{
    fprintf(stderr, "fatal error: %s\n", message);
    exit(code);
}

void usage(void)
{
    fprintf(stderr, "ctl_cyrusdb [-C <altconfig>] -c\n");
    fprintf(stderr, "ctl_cyrusdb [-C <altconfig>] -r [-x]\n");
    exit(-1);
}

/* Callback for use by recover_reserved */
static int fixmbox(char *name,
		   int matchlen __attribute__((unused)),
		   int maycreate __attribute__((unused)),
		   void *rock __attribute__((unused)))
{
    int mbtype;
    int r;
    char *path, *part, *acl;
    struct mailbox mb;

    /* Do an mboxlist_detail on the mailbox */
    r = mboxlist_detail(name, &mbtype, &path, &part, &acl, NULL);

    /* if it is MBTYPE_RESERVED, unset it & call mboxlist_delete */
    if(!r && (mbtype & MBTYPE_RESERVE)) {
	/* Okay, since this needs to be able to run on a live server, locking
	   is a bit tricky:  We want to lock the mailbox, then
	   re-check that the flag is still valid */

	r = mailbox_open_locked(name, path, acl, NULL, &mb, 0);
	if(r) {
	    syslog(LOG_ERR,
		   "could not lock mailbox '%s' to clear reservation: %s",
		   name, error_message(r));
	    return 0;
	}

	/* Do an mboxlist_detail on the mailbox */
	r = mboxlist_detail(name, &mbtype, &path, &part, &acl, NULL);
	
	if(r || !(mbtype & MBTYPE_RESERVE)) {
	    syslog(LOG_ERR,
		   "mailbox '%s' is no longer reserved, skipping recovery.",
		   name);
	    return 0;
	}

	r = mboxlist_update(name, (mbtype & ~MBTYPE_RESERVE), part, acl);

	if(!r) {
	    r = mboxlist_deletemailbox(name, 1, NULL, NULL, 0, 0);
	    if(r) {
		/* put it back, log the error */
		mboxlist_update(name, mbtype, part, acl);
		syslog(LOG_ERR,
		       "could not remove mailbox '%s' after unreserving: %s",
		       name, error_message(r));
	    } else {
		syslog(LOG_ERR,
		       "removed reserved mailbox '%s'",
		       name);
	    }
	}
    }

    return 0;
}
void recover_reserved() 
{
    char pattern[2] = { '*', '\0' };
    
    mboxlist_init(0);
    mboxlist_open(NULL);

    /* build a list of mailboxes - we're using internal names here */
    mboxlist_findall(NULL, pattern, 1, NULL,
		     NULL, fixmbox, NULL);

    mboxlist_close();
    mboxlist_done();
}


int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt, r, r2;
    char *alt_config = NULL;
    int flag = 0;
    int reserve_flag = 1;
    enum { RECOVER, CHECKPOINT, NONE } op = NONE;
    char dirname[1024], backup1[1024], backup2[1024];
    char *archive_files[N(dblist)];
    char *msg = "";
    int i, j, rotated = 0;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);
    r = r2 = 0;

    while ((opt = getopt(argc, argv, "C:rxc")) != EOF) {
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

	case 'x':
	    reserve_flag = 0;
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

    if(op != RECOVER && !reserve_flag) {
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

    /* sort dbenvs */
    qsort(dblist, N(dblist)-1, sizeof(struct cyrusdb), &compdb);

    memset(archive_files, 0, N(dblist) * sizeof(char*));
    for (i = 0, j = 0; dblist[i].name != NULL; i++) {

	/* if we need to archive this db, add it to the list */
	if (dblist[i].archive) {
	    archive_files[j] = (char*) xmalloc(strlen(config_dir) +
					       strlen(dblist[i].name) + 1);
	    strcpy(archive_files[j], config_dir);
	    strcat(archive_files[j++], dblist[i].name);
	}

	/* deal with each dbenv once */
	if (dblist[i].env == dblist[i+1].env) continue;

	r = (dblist[i].env)->init(dirname, flag);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: init %s: %s", dirname,
		   cyrusdb_strerror(r));
	    fprintf(stderr, 
		    "ctl_cyrusdb: unable to init environment\n");
	    dblist[i].env = NULL;
	    /* stop here, but we need to close all existing ones */
	    break;
	}
	
	r2 = 0;
	switch (op) {
	case RECOVER:
	    break;
	    
	case CHECKPOINT:
	    r2 = (dblist[i].env)->sync();
	    if (r2) {
		syslog(LOG_ERR, "DBERROR: sync %s: %s", dirname,
		       cyrusdb_strerror(r));
		fprintf(stderr, 
			"ctl_cyrusdb: unable to sync environment\n");
	    }

	    /* ARCHIVE */
	    r2 = 0;

	    if (!rotated) {
		/* rotate the backup directories -- ONE time only */
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

		rotated = 1;
	    }

	    /* do the archive */
	    if (r2 == 0)
		r2 = (dblist[i].env)->archive((const char**) archive_files,
					      backup1);

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

	/* free the archive_list */
	while (j > 0) {
	    free(archive_files[--j]);
	    archive_files[j] = NULL;
	}

	r2 = (dblist[i].env)->done();
	if (r2) {
	    syslog(LOG_ERR, "DBERROR: done: %s", cyrusdb_strerror(r));
	}
    }

    if(op == RECOVER && reserve_flag)
	recover_reserved();

    syslog(LOG_NOTICE, "done %s", msg);
    exit(r || r2);
}
