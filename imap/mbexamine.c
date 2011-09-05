/* mbexamine.c -- examine the contents of a mailbox index and cache
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
 * $Id: mbexamine.c,v 1.25 2010/01/06 17:01:36 murch Exp $
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
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <stdlib.h>

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
#include "convert_code.h"
#include "exitcodes.h"
#include "index.h"
#include "global.h"
#include "imap_err.h"
#include "imparse.h"
#include "mailbox.h"
#include "message.h"
#include "message_guid.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "seen.h"
#include "retry.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

extern int optind;
extern char *optarg;

/* current namespace */
static struct namespace recon_namespace;

/* config.c stuff */
const int config_need_data = 0;

/* forward declarations */
static int do_examine(char *name, int matchlen, int maycreate, void *rock);
static int do_quota(char *name, int matchlen, int maycreate, void *rock);
void usage(void);
void shut_down(int code);

int code = 0;

unsigned wantuid = 0;
unsigned wantvalue = 0;

int main(int argc, char **argv)
{
    int opt, i, r;
    char buf[MAX_MAILBOX_PATH+1];
    char *alt_config = NULL;
    int quotachk = 0;

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    /* Ensure we're up-to-date on the index file format */
    assert(INDEX_HEADER_SIZE == (OFFSET_HEADER_CRC+4));
    assert(INDEX_RECORD_SIZE == (OFFSET_RECORD_CRC+4));

    while ((opt = getopt(argc, argv, "C:u:s:q")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'u':
	    if(wantvalue) usage();
	    wantuid = 1;
	    wantvalue = atoi(optarg);
	    break;
	    
	case 's':
	    if(wantvalue) usage();
	    wantvalue = atoi(optarg);
	    break;

	case 'q':
	    quotachk = 1;
	    break;
	    
	default:
	    usage();
	}
    }

    cyrus_init(alt_config, "mbexamine", 0);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&recon_namespace, 1)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    mboxlist_init(0);
    mboxlist_open(NULL);

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);

    if (optind == argc) {
	strlcpy(buf, "*", sizeof(buf));
	(*recon_namespace.mboxlist_findall)(&recon_namespace, buf, 1, 0, 0,
					    quotachk ? do_quota : do_examine,
					    NULL);
    }

    for (i = optind; i < argc; i++) {
	/* Handle virtdomains and separators in mailboxname */
	(*recon_namespace.mboxname_tointernal)(&recon_namespace, argv[i],
					       NULL, buf);
	(*recon_namespace.mboxlist_findall)(&recon_namespace, buf, 1, 0, 0,
					    quotachk ? do_quota : do_examine,
					    NULL);
    }

    mboxlist_close();
    mboxlist_done();

    exit(code);
}

void usage(void)
{
    fprintf(stderr,
	    "usage: mbexamine [-C <alt_config>] [-s seqnum] mailbox...\n"
	    "       mbexamine [-C <alt_config>] [-u uid] mailbox...\n"
	    "       mbexamine [-C <alt_config>] -q mailbox...\n");
    exit(EC_USAGE);
}

void print_rec(const char *name, const struct buf *citem)
{
    printf(" %s>{%d}%.*s\n", name, citem->len, citem->len, citem->s); 
}

/*
 * mboxlist_findall() callback function to examine a mailbox
 */
static int do_examine(char *name,
		      int matchlen __attribute__((unused)),
		      int maycreate __attribute__((unused)),
		      void *rock __attribute__((unused)))
{
    unsigned i, msgno, recno;
    int r = 0;
    int flag = 0;
    char ext_name_buf[MAX_MAILBOX_PATH+1];
    struct mailbox *mailbox = NULL;
    struct index_record record;
    int j;
    
    signals_poll();

    /* Convert internal name to external */
    (*recon_namespace.mboxname_toexternal)(&recon_namespace, name,
					   "cyrus", ext_name_buf);
    printf("Examining %s...\n", ext_name_buf);

    /* Open/lock header */
    r = mailbox_open_irl(name, &mailbox);
    if (r) return r;

    if (chdir(mailbox_datapath(mailbox)) == -1) {
	r = IMAP_IOERROR;
	goto done;
    }

    printf(" Mailbox Header Info:\n");
    printf("  Path to mailbox: %s\n", mailbox_datapath(mailbox));
    printf("  Mailbox ACL: %s\n", mailbox->acl); /* xxx parse */
    printf("  Unique ID: %s\n", mailbox->uniqueid);
    printf("  User Flags: ");

    for (i = 0; i < MAX_USER_FLAGS; i++) {
	if (!mailbox->flagname[i]) break;
	printf("%s ", mailbox->flagname[i]);
    }

    if (!i) printf("[none]");

    printf("\n");

    printf("\n Index Header Info:\n");
    printf("  Generation Number: %d\n", mailbox->i.generation_no);
    printf("  Minor Version: %d\n", mailbox->i.minor_version);
    printf("  Header Size: %u bytes  Record Size: %u bytes\n",
	   mailbox->i.start_offset, mailbox->i.record_size);
    printf("  Number of Messages: %u  Mailbox Size: " QUOTA_T_FMT " bytes\n",
	   mailbox->i.exists, mailbox->i.quota_mailbox_used);
    printf("  Last Append Date: (%lu) %s",
	   mailbox->i.last_appenddate, ctime(&mailbox->i.last_appenddate));
    printf("  UIDValidity: %u  Last UID: %u\n",
	   mailbox->i.uidvalidity, mailbox->i.last_uid);
    printf("  Deleted: %u  Answered: %u  Flagged: %u\n",
	   mailbox->i.deleted, mailbox->i.answered, mailbox->i.flagged);
    printf("  Mailbox Options:");
    if (!mailbox->i.options) {
	printf(" NONE");
    } else {
	if (mailbox->i.options & OPT_POP3_NEW_UIDL) {
	    printf(" POP3_NEW_UIDL");
	}
	if (mailbox->i.options & OPT_IMAP_SHAREDSEEN) {
	    printf(" IMAP_SHAREDSEEN");
	}
	if (mailbox->i.options & OPT_IMAP_DUPDELIVER) {
	    printf(" IMAP_DUPDELIVER");
	}
    }
    printf("\n");
    printf("  Last POP3 Login: (%ld) %s", mailbox->i.pop3_last_login,
	   ctime((const long *) &mailbox->i.pop3_last_login));
    printf("  Highest Mod Sequence: " MODSEQ_FMT "\n",
	   mailbox->i.highestmodseq);

    printf("\n Message Info:\n");

    msgno = 1;
    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	if (mailbox_read_index_record(mailbox, recno, &record))
	    continue;

	if (record.system_flags & FLAG_EXPUNGED)
	    continue;

	if (wantvalue) {
	    if (wantuid) {
		if (record.uid != wantvalue) continue;
	    } else {
		if (msgno != wantvalue) continue;
	    }
	    flag = 1;
	}

	printf("%06u> UID:%08u   INT_DATE:%lu SENTDATE:%lu SIZE:%-6u\n",
	       msgno, record.uid, record.internaldate,
	       record.sentdate, record.size);
	printf("      > HDRSIZE:%-6u LASTUPD :%lu SYSFLAGS:%08X",
	       record.header_size, record.last_updated,
	       record.system_flags);
	if (mailbox->i.minor_version >= 5)
	    printf("   LINES:%-6u\n", record.content_lines);

	if (mailbox->i.minor_version >= 6)
	    printf("      > CACHEVER:%-2u", record.cache_version);

	if (mailbox->i.minor_version >= 7) {
	    printf(" GUID:%s", message_guid_encode(&record.guid));
	}

	if (mailbox->i.minor_version >= 8) {
	    printf(" MODSEQ:" MODSEQ_FMT, record.modseq);
	}

	printf("\n");

	printf("      > USERFLAGS:");
	for (j=(MAX_USER_FLAGS/32)-1; j>=0; j--) {
	    printf(" %08X", record.user_flags[j]);
	}
	printf("\n");

	if (!mailbox_cacherecord(mailbox, &record)) {
	    print_rec("Envel", cacheitem_buf(&record, CACHE_ENVELOPE));
	    print_rec("BdyStr", cacheitem_buf(&record, CACHE_BODYSTRUCTURE));
	    print_rec("Body", cacheitem_buf(&record, CACHE_BODY));
	    print_rec("CacHdr", cacheitem_buf(&record, CACHE_HEADERS));
	    print_rec("From", cacheitem_buf(&record, CACHE_FROM));
	    print_rec("To", cacheitem_buf(&record, CACHE_TO));
	    print_rec("Cc", cacheitem_buf(&record, CACHE_CC));
	    print_rec("Bcc", cacheitem_buf(&record, CACHE_BCC));
	    print_rec("Subjct", cacheitem_buf(&record, CACHE_SUBJECT));
	}

	if (flag) break;
    }

    if (wantvalue && !flag) {
	printf("Desired message not found\n");
    }

 done:
    mailbox_close(&mailbox);

    return r;
}

/*
 * mboxlist_findall() callback function to examine a mailbox quota usage
 */
static int do_quota(char *name,
		    int matchlen __attribute__((unused)),
		    int maycreate __attribute__((unused)),
		    void *rock __attribute__((unused)))
{
    uint32_t recno;
    int r = 0;
    char ext_name_buf[MAX_MAILBOX_PATH+1];
    struct mailbox *mailbox = NULL;
    struct index_record record;
    quota_t total = 0;
    char *fname;
    struct stat sbuf;
    
    signals_poll();

    /* Convert internal name to external */
    (*recon_namespace.mboxname_toexternal)(&recon_namespace, name,
					   "cyrus", ext_name_buf);
    printf("Examining %s...", ext_name_buf);

    /* Open/lock header */
    r = mailbox_open_irl(name, &mailbox);
    if (r) return r;

    if (chdir(mailbox_datapath(mailbox)) == -1) {
	r = IMAP_IOERROR;
	goto done;
    }

    for(recno = 1; recno <= mailbox->i.num_records; recno++) {
	if (mailbox_read_index_record(mailbox, recno, &record))
	    continue;

	if (record.system_flags & FLAG_EXPUNGED)
	    continue;

	fname = mailbox_message_fname(mailbox, record.uid);

	if (stat(fname, &sbuf) != 0) {
	    syslog(LOG_WARNING,
		   "Can not open message file %s -- skipping\n", fname);
	    continue;
	}

	if (record.size != (unsigned) sbuf.st_size) {
	    printf("  Message %u has INCORRECT size in index record\n", record.uid);
	    r = 0;
	    goto done;
	}

	total += sbuf.st_size;
    }

    if (mailbox->i.quota_mailbox_used != total) {
	printf("  Mailbox has INCORRECT total quota usage\n");
    }
    else {
	printf("  Mailbox has CORRECT total quota usage\n");
    }

 done:
    mailbox_close(&mailbox);

    return r;
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    in_shutdown = 1;

    mboxlist_close();
    mboxlist_done();
    exit(code);
}
