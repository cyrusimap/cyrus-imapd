/* $Id: cyrrestore.c,v 1.4 2003/04/24 17:27:56 rjs3 Exp $
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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

int verbose = 0;

static int dump_me(char *name, int matchlen, int maycreate, void *rock);
static void print_seq(const char *tag, const char *attrib, 
		      unsigned *seq, int n);
int usage(const char *name);

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
    char buf[MAX_MAILBOX_PATH+1];
    int i;
    char *alt_config = NULL;
    struct incremental_record irec;

    if (geteuid() == 0) {
	usage(argv[0]);
    }

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

    config_init(alt_config, "restore");
    mboxlist_init(0);
    mboxlist_open(NULL);

    irec.incruid = 0;
    for (i = optind; i < argc; i++) {
	/* specify argument multiple times to deal with incrementals */
	strlcpy(buf, argv[optind], sizeof(buf));
	restore_me(buf);
    }

    mboxlist_close();
    mboxlist_done();

    return 0;
}

int usage(const char *name)
{
    fprintf(stderr, "usage: %s [-v] [mbox ...]\n", name);

    exit(EC_USAGE);
}

void fatal(const char *s, int code) 
{
    fprintf(stderr, "fatal error: %s\n", s);
    exit(code);
}

static int parse_dump_record(FILE *f, int version, 
			     struct incremental_record *irec)
{
    printf("<imapdump uniqueid=\"%s\">\n", m.uniqueid);
    imapurl_toURL(imapurl, config_servername, m.name);
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
}

static int restore_me(char *mailboxname)
{
    int r;
    struct mailbox m;
    char boundary[100];
    char imapurl[MAX_MAILBOX_PATH+1];
    char buf[2048];
    struct incremental_record irec;
    struct searchargs searchargs;
    unsigned *uids;
    unsigned *uidseq;
    int i, n, numuids;
    int newmailbox;

    /* create mailbox */
    r = mboxlist_createmailbox(mailboxname, 0, NULL /* : partition */,
			       1 : /* isadmin */, "anonymous", NULL);
    if (r && r != IMAP_MAILBOX_EXISTS) {
	fatal("can't create mailbox", EC_SOFTWARE);
    }
    newmailbox = (r == 0);

    /* open mailbox */
    memset(&m, 0, sizeof(m));
    r = mailbox_open_header(name, 0, &m);
    if (r) {
	if (verbose) {
	    printf("error opening %s: %s\n", name, error_message(r));
	}
	return IMAP_IOERROR;
    }
    
    r = mailbox_open_index(&m);
    if (!r) r = mailbox_lock_pop(&m);
    if (r) {
	if (verbose) {
	    printf("error locking index %s: %s\n", name, error_message(r));
	}
	mailbox_close(&m);
	return IMAP_IOERROR;
    }

    mailbox_read_index_header(&m);

    imapd_exists = m.exists;

    if (fgets(buf, sizeof buf, stdin) == NULL) goto badfmt;
    if (strncasecmp(buf, "Content-Type:", 13)) goto badfmt;
    /* find boundary */
    p = strstr(buf, "boundary=\"");
    if (!p) goto badfmt;
    p += 10;
    q = boundary;
    while (*p && *p != '"') {
	*q++ = *p++;
    }
    *q = '\0';

    if (fgets(buf, sizeof buf, stdin) == NULL) goto badfmt;
    if (buf[0] != '\n') goto badfmt;

    if (fgets(buf, sizeof buf, stdin) == NULL) goto badfmt;
    if (buf[0] != '-' || buf[1] != '-' ||
	strncmp(buf + 2, boundary, strlen(boundary))) goto badfmt;

    if (fgets(buf, sizeof buf, stdin) == NULL) goto badfmt;
    /* check content-type */

    if (fgets(buf, sizeof buf, stdin) == NULL) goto badfmt;
    /* check dump version */

    if (fgets(buf, sizeof buf, stdin) == NULL) goto badfmt;


    process_dump_record(stdin, version, &irec);
    if (buf[0] != '\n') goto badfmt;

    printf("--%s\n", boundary);
    printf("Content-Type: text/xml\n");
    printf("IMAP-Dump-Version: 0\n");
    printf("\n");

    /* XXX what is going on here?  in addition to the random empty block
     * below, there's the fact that uids[] and numuids haven't been inited
     * yet */

    /* check if the incremental is valid */
    if (!newmailbox) {


    }
    
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
