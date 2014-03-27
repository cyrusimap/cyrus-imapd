/* reconstruct.c -- program to reconstruct a mailbox 
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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
 * $Id: reconstruct.c,v 1.112 2010/01/06 17:01:39 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <utime.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <stdlib.h>
#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

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

#include "acl.h"
#include "assert.h"
#include "bsearch.h"
#include "caldav_db.h"
#include "carddav_db.h"
#include "crc32.h"
#include "hash.h"
#include "imparse.h"
#include "global.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "map.h"
#include "message.h"
#include "message_guid.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "global.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "quota.h"
#include "seen.h"
#include "retry.h"
#include "convert_code.h"
#include "util.h"
#include "sync_log.h"
#include "cyr_lock.h"

extern int optind;
extern char *optarg;

struct discovered {
    char *name;
    struct discovered *next;
};

hash_table unqid_table;

/* current namespace */
static struct namespace recon_namespace;

/* config.c stuff */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

/* forward declarations */
void do_mboxlist(void);
int do_reconstruct(char *name, int matchlen, int maycreate, void *rock);
int reconstruct(char *name, struct discovered *l);
void usage(void);
char * getmailname (char * mailboxname);

extern cyrus_acl_canonproc_t mboxlist_ensureOwnerRights;

int reconstruct_flags = RECONSTRUCT_MAKE_CHANGES | RECONSTRUCT_DO_STAT;

int main(int argc, char **argv)
{
    int opt, i, r;
    int rflag = 0;
    int mflag = 0;
    int fflag = 0;
    int xflag = 0;
    char buf[MAX_MAILBOX_PATH+1];
    char *fname;
    struct discovered head;
    char *alt_config = NULL;
    char *start_part = NULL;

    memset(&head, 0, sizeof(head));

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    /* Ensure we're up-to-date on the index file format */
    assert(INDEX_HEADER_SIZE == (OFFSET_HEADER_CRC+4));
    assert(INDEX_RECORD_SIZE == (OFFSET_RECORD_CRC+4));

    construct_hash_table(&unqid_table, 2047, 1);

    while ((opt = getopt(argc, argv, "C:kp:rmfsxgGqRUoOn")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'p':
	    start_part = optarg;
	    break;

	case 'r':
	    rflag = 1;
	    break;

	case 'm':
	    mflag = 1;
	    break;

	case 'n':
	    reconstruct_flags &= ~RECONSTRUCT_MAKE_CHANGES;
	    break;

	case 'g':
	    fprintf(stderr, "deprecated option -g used\n");
	    break;

	case 'G':
	    reconstruct_flags |= RECONSTRUCT_ALWAYS_PARSE;
	    break;

	case 'f':
	    fflag = 1;
	    break;

	case 'x':
	    xflag = 1;
	    break;

	case 'k':
	    fprintf(stderr, "deprecated option -k used\n");
	    break;

	case 's':
	    reconstruct_flags &= ~RECONSTRUCT_DO_STAT;
	    break;

	case 'q':
	    reconstruct_flags |= RECONSTRUCT_QUIET;
	    break;

	case 'R':
	    reconstruct_flags |= RECONSTRUCT_GUID_REWRITE;
	    break;

	case 'U':
	    reconstruct_flags |= RECONSTRUCT_GUID_UNLINK;
	    break;

	case 'o':
	    reconstruct_flags |= RECONSTRUCT_IGNORE_ODDFILES;
	    break;

	case 'O':
	    reconstruct_flags |= RECONSTRUCT_REMOVE_ODDFILES;
	    break;

	default:
	    usage();
	}
    }

    cyrus_init(alt_config, "reconstruct", 0);
    global_sasl_init(1,0,NULL);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&recon_namespace, 1)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    sync_log_init();

    if (mflag) {
	if (rflag || fflag || optind != argc) {
	    cyrus_done();
	    usage();
	}
	do_mboxlist();
    }

    mboxlist_init(0);
    mboxlist_open(NULL);

    quotadb_init(0);
    quotadb_open(NULL);

    caldav_init();
    carddav_init();

    /* Deal with nonexistent mailboxes */
    if (start_part) {
	/* We were handed a mailbox that does not exist currently */
	if(optind == argc) {
	    fprintf(stderr,
		    "When using -p, you must specify a mailbox to attempt to reconstruct.");
	    exit(EC_USAGE);
	}

	/* do any of the mailboxes exist in mboxlist already? */
	/* Do they look like mailboxes? */
	for (i = optind; i < argc; i++) {
	    struct stat sbuf;

	    if(strchr(argv[i],'%') || strchr(argv[i],'*')) {
		fprintf(stderr, "Using wildcards with -p is not supported.\n");
		exit(EC_USAGE);
	    }

	    /* Translate mailboxname */
	    (*recon_namespace.mboxname_tointernal)(&recon_namespace, argv[i],
						   NULL, buf);

	    /* Does it exist */
	    do {
		r = mboxlist_lookup(buf, NULL, NULL);
	    } while (r == IMAP_AGAIN);

	    if (r != IMAP_MAILBOX_NONEXISTENT) {
		fprintf(stderr,
			"Mailbox %s already exists.  Cannot specify -p.\n",
			argv[i]);
		exit(EC_USAGE);
	    }

	    /* Does the suspected path *look* like a mailbox? */
	    fname = mboxname_metapath(start_part, buf, META_HEADER, 0);
	    if (stat(fname, &sbuf) < 0) {
		fprintf(stderr,
			"%s does not appear to be a mailbox (no %s).\n",
			argv[i], fname);
		exit(EC_USAGE);
	    }
	}
	
	/* None of them exist.  Create them. */
	for (i = optind; i < argc; i++) {
	    /* Translate mailboxname */
	    (*recon_namespace.mboxname_tointernal)(&recon_namespace, argv[i],
						   NULL, buf);

	    r = mboxlist_createmailbox(buf, 0, start_part, 1,
				       "cyrus", NULL, 0, 0, !xflag);
	    if(r) {
		fprintf(stderr, "could not create %s\n", argv[i]);
	    }
	}
    }

    /* Normal Operation */
    if (optind == argc) {
	if (rflag) {
	    fprintf(stderr, "please specify a mailbox to recurse from\n");
	    cyrus_done();
	    exit(EC_USAGE);
	}
	assert(!rflag);
	strlcpy(buf, "*", sizeof(buf));
	(*recon_namespace.mboxlist_findall)(&recon_namespace, buf, 1, 0, 0,
					    do_reconstruct, NULL);
    }

    for (i = optind; i < argc; i++) {
	char *domain = NULL;

	/* save domain */
	if (config_virtdomains) domain = strchr(argv[i], '@');

	strlcpy(buf, argv[i], sizeof(buf));
	/* Translate any separators in mailboxname */
	mboxname_hiersep_tointernal(&recon_namespace, buf,
				    config_virtdomains ?
				    strcspn(buf, "@") : 0);

	/* reconstruct the first mailbox/pattern */
	(*recon_namespace.mboxlist_findall)(&recon_namespace, buf, 1, 0,
					    0, do_reconstruct, 
					    fflag ? &head : NULL);
	if (rflag) {
	    /* build a pattern for submailboxes */
	    char *p = strchr(buf, '@');
	    if (p) *p = '\0';
	    strlcat(buf, ".*", sizeof(buf));

	    /* append the domain */
	    if (domain) strlcat(buf, domain, sizeof(buf));

	    /* reconstruct the submailboxes */
	    (*recon_namespace.mboxlist_findall)(&recon_namespace, buf, 1, 0,
						0, do_reconstruct, 
						fflag ? &head : NULL);
	}
    }

    /* examine our list to see if we discovered anything */
    while (head.next) {
	struct discovered *p;
	int r = 0;

	p = head.next;
	head.next = p->next;

	/* create p (database only) and reconstruct it */
	/* partition is defined by the parent mailbox */
	r = mboxlist_createmailbox(p->name, 0, NULL, 1,
				   "cyrus", NULL, 0, 0, !xflag);
	if (r) {
	    fprintf(stderr, "createmailbox %s: %s\n",
		    p->name, error_message(r));
	} else {
	    do_reconstruct(p->name, strlen(p->name), 0, &head);
	}
	/* may have added more things into our list */

	free(p->name);
	free(p);
    }

    free_hash_table(&unqid_table, free);

    sync_log_done();

    mboxlist_close();
    mboxlist_done();

    quotadb_close();
    quotadb_done();

    carddav_done();
    caldav_done();

    cyrus_done();

    return 0;
}

void usage(void)
{
    fprintf(stderr,
	    "usage: reconstruct [-C <alt_config>] [-p partition] [-ksrfx] mailbox...\n");
    fprintf(stderr, "       reconstruct [-C <alt_config>] -m\n");
    exit(EC_USAGE);
}    

/*
 * mboxlist_findall() callback function to reconstruct a mailbox
 */
int
do_reconstruct(char *name,
	       int matchlen,
	       int maycreate __attribute__((unused)),
	       void *rock)
{
    struct discovered *found = (struct discovered *)rock;
    int r;
    char buf[MAX_MAILBOX_NAME];
    static char lastname[MAX_MAILBOX_NAME] = "";
    char *other;
    struct mailbox *mailbox = NULL;
    char outpath[MAX_MAILBOX_PATH];

    signals_poll();

    /* don't repeat */
    if (matchlen == (int) strlen(lastname) &&
	!strncmp(name, lastname, matchlen)) return 0;

    if(matchlen >= (int) sizeof(lastname))
	matchlen = sizeof(lastname) - 1;
    
    strncpy(lastname, name, matchlen);
    lastname[matchlen] = '\0';

    r = mailbox_reconstruct(lastname, reconstruct_flags);
    if (r) {
	com_err(lastname, r, "%s",
		(r == IMAP_IOERROR) ? error_message(errno) : NULL);
	return 0;
    }

    r = mailbox_open_iwl(lastname, &mailbox);
    if (r) {
	com_err(lastname, r, "Failed to open after reconstruct");
	return 0;
    }

    other = hash_lookup(mailbox->uniqueid, &unqid_table);
    if (other) {
	syslog (LOG_ERR, "uniqueid clash with %s for %s - changing %s",
		other, mailbox->uniqueid, mailbox->name);
	/* uniqueid change required! */
	mailbox_make_uniqueid(mailbox);
    }

    hash_insert(mailbox->uniqueid, xstrdup(mailbox->name), &unqid_table);

    /* Convert internal name to external */
    (*recon_namespace.mboxname_toexternal)(&recon_namespace, lastname,
					   NULL, buf);
    if (!(reconstruct_flags & RECONSTRUCT_QUIET))
	printf("%s\n", buf);

    strncpy(outpath, mailbox_meta_fname(mailbox, META_HEADER), MAX_MAILBOX_NAME);
    mailbox_close(&mailbox);

    if (found) {
	char fnamebuf[MAX_MAILBOX_PATH];
	char *ptr;
	DIR *dirp;
	struct dirent *dirent;
	struct stat sbuf;

	ptr = strstr(outpath, "cyrus.header");
	if (!ptr) return 0;
	*ptr = 0;

	r = chdir(outpath);
	if (r) return 0;

	/* we recurse down this directory to see if there's any mailboxes
	   under this not in the mailboxes database */
	dirp = opendir(".");
	if (!dirp) return 0;

	while ((dirent = readdir(dirp)) != NULL) {
	    struct discovered *new;

	    /* mailbox directories never have a dot in them */
	    if (strchr(dirent->d_name, '.')) continue;
	    if (stat(dirent->d_name, &sbuf) < 0) continue;
	    if (!S_ISDIR(sbuf.st_mode)) continue;

	    /* ok, we found a directory that doesn't have a dot in it;
               is there a cyrus.header file? */
	    snprintf(fnamebuf, MAX_MAILBOX_PATH, "%s%s",
		     dirent->d_name, FNAME_HEADER);
	    if (stat(fnamebuf, &sbuf) < 0) continue;

	    /* ok, we have a real mailbox directory */
	    snprintf(buf, MAX_MAILBOX_NAME, "%s.%s", 
		     name, dirent->d_name);

	    /* does fnamebuf exist as a mailbox in mboxlist? */
	    do {
		r = mboxlist_lookup(buf, NULL, NULL);
	    } while (r == IMAP_AGAIN);
	    if (!r) continue; /* mailbox exists; it'll be reconstructed
			         with a -r */

	    if (r != IMAP_MAILBOX_NONEXISTENT) break; /* erg? */
	    else r = 0; /* reset error condition */

	    printf("discovered %s\n", buf);
	    new = (struct discovered *) xmalloc(sizeof(struct discovered));
	    new->name = strdup(buf);
	    new->next = found->next;
	    found->next = new;
	}
	closedir(dirp);
    }

    return 0;
}

/*
 * Reconstruct the mailboxes list.
 */
void do_mboxlist(void)
{
    fprintf(stderr, "reconstructing mailboxes.db currently not supported\n");
    exit(EC_USAGE);
}
