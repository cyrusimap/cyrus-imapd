/* $Id: cyrdump.c,v 1.9.4.6 2002/11/15 21:46:55 rjs3 Exp $
 * Copyright (c) 2001 Carnegie Mellon University.  All rights reserved.
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
 *
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <com_err.h>
#include <string.h>
#include <time.h>

/* cyrus includes */
#include "imapconf.h"
#include "sysexits.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "imapd.h"
#include "exitcodes.h"
#include "imapurl.h"

/* config.c stuff */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

int verbose = 0;

static int dump_me(char *name, int matchlen, int maycreate, void *rock);
static void print_seq(const char *tag, const char *attrib, 
		      unsigned *seq, int n);
int usage(const char *name);

/* available from elsewhere */
int index_getuidsequence(struct mailbox *mailbox, 
                        struct searchargs *searchargs,
                        unsigned **uid_list);

/* current namespace */
static struct namespace dump_namespace;

int imapd_exists;
struct protstream *imapd_out = NULL;
struct auth_state *imapd_authstate = NULL;
char *imapd_userid = NULL;

struct incremental_record {
    int incruid;
};

int main(int argc, char *argv[])
{
    int option;
    char buf[MAX_MAILBOX_PATH];
    int i, r;
    char *alt_config = NULL;
    struct incremental_record irec;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);

    while ((option = getopt(argc, argv, "v")) != EOF) {
	switch (option) {
	case 'v':
	    verbose++;
	    break;

	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	default:
	    usage(argv[0]);
	    break;
	}
    }

    if (optind == argc) {
	usage(argv[0]);
    }

    config_init(alt_config, "dump");
    mboxlist_init(0);
    mboxlist_open(NULL);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&dump_namespace, 1)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    irec.incruid = 0;
    for (i = optind; i < argc; i++) {
	strlcpy(buf, argv[optind], sizeof(buf));
	/* Translate any separators in mailboxname */
	mboxname_hiersep_tointernal(&dump_namespace, buf, 0);
	(*dump_namespace.mboxlist_findall)(&dump_namespace, buf, 1, 0, 0,
					   dump_me, &irec);
    }

    mboxlist_close();
    mboxlist_done();

    cyrus_done();
    
    return 0;
}

int usage(const char *name)
{
    fprintf(stderr, "usage: %s [-v] [mboxpattern ...]\n", name);

    exit(EC_USAGE);
}

/* 'boundary' must be at least 100 long */
static void generate_boundary(char *boundary)
{
    snprintf(boundary, 100, "dump-%ld-%ld-%ld", 
	     (long) getpid(), (long) time(NULL), (long) rand());
}

static int dump_me(char *name, int matchlen, int maycreate, void *rock)
{
    int r;
    struct mailbox m;
    char boundary[100];
    char imapurl[MAX_MAILBOX_PATH];
    struct incremental_record *irec = (struct incremental_record *) rock;
    struct searchargs searchargs;
    unsigned *uids;
    unsigned *uidseq;
    int i, n, numuids;

    memset(&m, 0, sizeof(struct mailbox));
    r = mailbox_open_header(name, 0, &m);
    if (r) {
	if (verbose) {
	    printf("error opening %s: %s\n", name, error_message(r));
	}
	return 0;
    }
    
    r = mailbox_open_index(&m);
    if (!r) r = mailbox_lock_pop(&m);
    if (r) {
	if (verbose) {
	    printf("error locking index %s: %s\n", name, error_message(r));
	}
	mailbox_close(&m);
	return 0;
    }
    
    mailbox_read_index_header(&m);
    index_operatemailbox(&m);

    generate_boundary(boundary);

    printf("Content-Type: multipart/related; boundary=\"%s\"\n\n", boundary);

    printf("--%s\n", boundary);
    printf("Content-Type: text/xml\n");
    printf("IMAP-Dump-Version: 0\n");
    printf("\n");

    printf("<imapdump uniqueid=\"%s\">\n", m.uniqueid);
    imapurl_toURL(imapurl, config_servername, m.name, NULL);
    printf("  <mailbox-url>%s</mailbox-url>\n", imapurl);
    printf("  <incremental-uid>%d</incremental-uid>\n", irec->incruid);
    printf("  <nextuid>%ld</nextuid>\n", m.last_uid + 1);
    printf("\n");

    memset(&searchargs, 0, sizeof(struct searchargs));
    numuids = index_getuidsequence(&m, &searchargs, &uids);
    print_seq("uidlist", NULL, uids, numuids);
    printf("\n");

    printf("  <flags>\n");

    searchargs.system_flags_set = FLAG_ANSWERED;
    n = index_getuidsequence(&m, &searchargs, &uidseq);
    print_seq("flag", "name=\"\\Answered\" user=\"*\"", uidseq, n);
    if (uidseq) free(uidseq);

    searchargs.system_flags_set = FLAG_DELETED;
    n = index_getuidsequence(&m, &searchargs, &uidseq);
    print_seq("flag", "name=\"\\Deleted\" user=\"*\"", uidseq, n);
    if (uidseq) free(uidseq);

    searchargs.system_flags_set = FLAG_DRAFT;
    n = index_getuidsequence(&m, &searchargs, &uidseq);
    print_seq("flag", "name=\"\\Draft\" user=\"*\"", uidseq, n);
    if (uidseq) free(uidseq);

    searchargs.system_flags_set = FLAG_FLAGGED;
    n = index_getuidsequence(&m, &searchargs, &uidseq);
    print_seq("flag", "name=\"\\Flagged\" user=\"*\"", uidseq, n);
    if (uidseq) free(uidseq);

    printf("  </flags>\n");

    printf("</imapdump>\n");

    for (i = 0; i < numuids; i++) {
	const char *base;
	unsigned long len;

	if (uids[i] < irec->incruid) {
	    /* already dumped this message */
	    /* xxx could do binary search to get to the first
	       undumped uid */
	    continue;
	}

	printf("\n--%s\n", boundary);
	printf("Content-Type: message/rfc822\n");
	printf("Content-ID: %d\n", uids[i]);
	printf("\n");
	r = mailbox_map_message(&m, 0, uids[i], &base, &len);
	if (r) {
	    if (verbose) {
		printf("error mapping message %d: %s\n", uids[i], 
		       error_message(r));
	    }
	    break;
	}
	fwrite(base, 1, len, stdout);
	mailbox_unmap_message(&m, uids[i], &base, &len);
    }

    printf("\n--%s--\n", boundary);

    index_closemailbox(&m);
    mailbox_close(&m);

    return 0;
}

static void print_seq(const char *tag, const char *attrib,
		      unsigned *seq, int n)
{
    int i;

    printf("  <%s%s%s>", tag, attrib ? " " : "", attrib ? attrib : "");
    for (i = 0; i < n; i++) {
	printf("%u ", seq[i]);
    }
    printf("</%s>\n", tag);
}


#if 0
    char *p, *str;
    int str_sz;
    int run_start = 0;
    int first_time = 1;

    p = str = (char *) xmalloc(sizeof(char) * 1024);
    str_sz = 1024;
    run_start = msgno_list[0];
    for (i = 1; i < n; i++) {
	if (msgno_list[i] == msgno_list[i-1] + 1) {
	    /* on a run */
	    continue;
	}
	if (first_time) {
	    first_time = 0;
	} else {
	    *p++ = ',';
	}
	if (run_start != msgno_list[i-1]) {
	    /* non-trivial run */
	    p += sprintf(p, "%d:%d", run_start, msgno_list[i-1]);
	} else {
	    /* singleton */
	    p += sprintf(p, "%d", msgno_list[i-1]);
	}
	if (p > (str + str_sz - 20)) {
	    /* running out of room */
	    int x;

	    x = p - str;
	    str = (char *) xrealloc(str, str_sz *= 2);
	    p = str + x;
	}
	run_start = msgno_list[i];
    }
    /* now handle the last entry */
    if (!first_time) {
	*p++ = ',';
    }
    if (run_start != msgno_list[i-1]) {
	sprintf(p, "%d:%d", run_start, msgno_list[i-1]);
    } else {
	sprintf(p, "%d", msgno_list[i-1]);
    }

    return str;

#endif

void printastring(const char *s)
{
    fatal("not implemented", EC_SOFTWARE);
}
