/* deliver.c -- deliver shell - just calls lmtpd
 * Tim Martin
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

/* $Id: deliver.c,v 1.164.4.3 2002/10/08 20:50:10 rjs3 Exp $ */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <com_err.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include "imapconf.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "xmalloc.h"
#include "lmtpengine.h"
#include "prot.h"
#include "version.h"

/* config.c stuff */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

extern int optind;
extern char *optarg;

static int lmtpdsock;
static int logdebug = 0;

static struct protstream *deliver_out, *deliver_in;

static const char *sockaddr;

/* unused for deliver.c, but needed to make lmtpengine.c happy */
int deliver_logfd = -1;

/* forward declarations */

static int deliver_msg(char *return_path, char *authuser, int ignorequota,
		       char **users, int numusers, char *mailbox);
static int init_net(const char *sockaddr);

static void
usage()
{
    fprintf(stderr, 
	    "421-4.3.0 usage: deliver [-C <alt_config> ] [-m mailbox]"
	    " [-a auth] [-r return_path] [-l] [-D]\r\n");
    fprintf(stderr, "421 4.3.0 %s\n", CYRUS_VERSION);
    exit(EC_USAGE);
}

void fatal(const char* s, int code)
{
    prot_printf(deliver_out,"421 4.3.0 deliver: %s\r\n", s);
    prot_flush(deliver_out);
    exit(code);
}

static int push(int in, int out)
{
    char buf[4096];
    int len;
    int cnt;
    int amnt = 0;

    len = read(in, buf, sizeof(buf)-1);
    if (len == -1) {
	exit(EC_IOERR);
    }
    if (len == 0) {
	exit(0);
    }

    /* keep writing until we have written the whole thing
       xxx can cause deadlock??? */
    do {
	cnt = write(out, buf+amnt,len-amnt);
    	if (cnt == -1) exit(EC_IOERR);
	amnt += cnt;
    } while (amnt<len);

    return 0;
}

/*
 * Here we're just an intermediatory piping stdin to lmtp socket
 * and lmtp socket to stdout
 */
void pipe_through(int lmtp_in, int lmtp_out, int local_in, int local_out)
{
    int nfound;
    int highest = 3;
    fd_set read_set, rset;
    fd_set write_set, wset;


    FD_ZERO(&read_set);
    FD_SET(lmtp_in, &read_set);
    if (lmtp_in >= highest) highest = lmtp_in+1;
    FD_SET(local_in, &read_set);

    FD_ZERO(&write_set);
    FD_SET(lmtp_out, &write_set);
    if (lmtp_out >= highest) highest = lmtp_out+1;
    FD_SET(local_out, &write_set);

    while (1)
    {
	rset = read_set;
	wset = write_set;
	nfound = select(highest, &rset, &wset, NULL, NULL);
	if (nfound < 0) {
	    if (errno == EINTR) continue;
	    exit(EC_IOERR);
	}

	if ((FD_ISSET(lmtp_in,&rset))  && (FD_ISSET(local_out,&wset))) {
	    push(lmtp_in, local_out);
	}
	if ((FD_ISSET(local_in,&rset)) && (FD_ISSET(lmtp_out,&wset))) {
	    push(local_in, lmtp_out);
	} else {
	    /* weird; this shouldn't happen */
	    usleep(1000);
	}
    }
}

int main(int argc, char **argv)
{
    int opt;
    int lmtpflag = 0;
    int ignorequota = 0;
    char *mailboxname = NULL;
    char *authuser = NULL;
    char *return_path = NULL;
    char buf[1024];
    char *alt_config = NULL;

    while ((opt = getopt(argc, argv, "C:df:r:m:a:F:eE:lqD")) != EOF) {
	switch(opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'd':
	    /* Ignore -- /bin/mail compatibility flags */
	    break;

        case 'D':
	    logdebug = 1;
	    break;

	case 'r':
	case 'f':
	    return_path = optarg;
	    break;

	case 'm':
	    if (mailboxname) {
		fprintf(stderr, "deliver: multiple -m options\n");
		usage();
	    }
	    if (*optarg) mailboxname = optarg;
	    break;

	case 'a':
	    if (authuser) {
		fprintf(stderr, "deliver: multiple -a options\n");
		usage();
	    }
	    authuser = optarg;
	    break;

	case 'F': /* set IMAP flag. we no longer support this */
	    fprintf(stderr,"deliver: 'F' option no longer supported\n");
	    usage();
	    break;

	case 'e':
	    /* duplicate delivery. ignore */
	    break;

	case 'E':
	    fprintf(stderr,"deliver: 'E' option no longer supported\n");
	    usage();
	    break;

	case 'l':
	    lmtpflag = 1;
	    break;

	case 'q':
	    ignorequota = 1;
	    break;

	default:
	    usage();
	}
    }

    deliver_in = prot_new(0, 0);
    deliver_out = prot_new(1, 1);
    prot_setflushonread(deliver_in, deliver_out);
    prot_settimeout(deliver_in, 300);

    config_init(alt_config, "deliver");

    sockaddr = config_getstring(IMAPOPT_LMTPSOCKET);
    if (!sockaddr) {	
	strcpy(buf, config_dir);
	strcat(buf, "/socket/lmtp");
	sockaddr = buf;
    }

    if (lmtpflag == 1) {
	int s = init_net(sockaddr);

	pipe_through(s,s,0,1);
    }

    if (return_path == NULL) {
	uid_t me = getuid();
	struct passwd *p = getpwuid(me);
	return_path = p->pw_name;
    }

    /* deliver to users or global mailbox */
    return deliver_msg(return_path,authuser, ignorequota,
		       argv+optind, argc - optind, mailboxname);
}

void just_exit(const char *msg)
{
    com_err(msg, 0, error_message(errno));

    fatal(msg, EC_CONFIG);
}

/* initialize the network 
 * we talk on unix sockets
 */
static int init_net(const char *unixpath)
{
  struct sockaddr_un addr;

  if ((lmtpdsock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
      just_exit("socket failed");
  }

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, unixpath);

  if (connect(lmtpdsock, (struct sockaddr *) &addr, 
	      sizeof(addr.sun_family) + strlen(addr.sun_path) + 1) < 0) {
      just_exit("connect failed");
  }

  return lmtpdsock;
}

static int deliver_msg(char *return_path, char *authuser, int ignorequota,
		       char **users, int numusers, char *mailbox)
{
    int r;
    struct lmtp_conn *conn;
    struct lmtp_txn *txn = LMTP_TXN_ALLOC(numusers ? numusers : 1);
    int j;
    int ml = 0;

    /* must have either some users or a mailbox */
    if (!numusers && !mailbox) {
	usage();
    }

    /* connect */
    r = lmtp_connect(sockaddr, NULL, &conn);
    if (r) {
	just_exit("couldn't connect to lmtpd");
    }

    /* setup txn */
    txn->from = return_path;
    txn->auth = authuser;
    txn->data = deliver_in;
    txn->isdotstuffed = 0;
    txn->rcpt_num = numusers ? numusers : 1;
    if (mailbox) ml = strlen(mailbox);
    if (numusers == 0) {
	/* just deliver to mailbox 'mailbox' */
	const char *BB = config_getstring(IMAPOPT_POSTUSER);
	txn->rcpt[0].addr = (char *) xmalloc(ml + strlen(BB) + 2); /* xxx leaks! */
	sprintf(txn->rcpt[0].addr, "%s+%s", BB, mailbox);
	txn->rcpt[0].ignorequota = ignorequota;
    } else {
	/* setup each recipient */
	for (j = 0; j < numusers; j++) {
	    if (mailbox) {
		/* we let it leak ! */
		txn->rcpt[j].addr = 
		    (char *) xmalloc(strlen(users[j]) + ml + 2);
		sprintf(txn->rcpt[j].addr, "%s+%s", users[j], mailbox);
	    } else {
		txn->rcpt[j].addr = users[j];
	    }
	    txn->rcpt[j].ignorequota = ignorequota;
	}
    }

    /* run txn */
    r = lmtp_runtxn(conn, txn);

    /* disconnect */
    lmtp_disconnect(conn);

    /* examine txn for error state */
    r = 0;
    for (j = 0; j < txn->rcpt_num; j++) {
	switch (txn->rcpt[j].result) {
	case RCPT_GOOD:
	    break;

	case RCPT_TEMPFAIL:
	    r = EC_TEMPFAIL;
	    break;

	case RCPT_PERMFAIL:
	    /* we just need any permanent failure, though we should
	       probably return data from the client-side LMTP info */
	    printf("%s: %s\n", 
		   txn->rcpt[j].addr, error_message(txn->rcpt[j].r));
	    if (r != EC_TEMPFAIL) {
		r = EC_DATAERR;
	    }
	    break;
	}
    }

    /* return appropriately */
    return r;
}
