/* lmtpproxyd.c -- Program to proxy mail delivery
 *
 * $Id: lmtpproxyd.c,v 1.63 2004/02/27 17:44:53 ken3 Exp $
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
#include <sys/types.h>
#include <sys/wait.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "acl.h"
#include "assert.h"
#include "util.h"
#include "prot.h"
#include "global.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "version.h"
#include "mboxname.h"

#include "mupdate-client.h"
#include "backend.h"
#include "lmtpengine.h"
#include "lmtpstats.h"

/* config.c stuff */
const int config_need_data = 0;

struct protstream *deliver_out = NULL, *deliver_in = NULL;

extern int optind;
extern char *optarg;

/* our cached connections */
struct backend **backend_cached = NULL;

/* a final destination for a message */
struct rcpt {
    char rcpt[MAX_MAILBOX_NAME+1]; /* where? */
    int rcpt_num;		    /* credit this to who? */
    struct rcpt *next;
};

struct dest {
    char server[MAX_MAILBOX_NAME+1];  /* where? */
    char authas[MAX_MAILBOX_NAME+1];  /* as who? */
    int rnum;			      /* number of rcpts */
    struct rcpt *to;
    struct dest *next;
};

enum pending {
    s_wait,			/* processing sieve requests */
    s_err,			/* error in sieve processing/sending */
    s_done,			/* sieve script successfully run */
    nosieve,			/* no sieve script */
    done,
};

/* data pertaining to a message in transit */
struct mydata {
    int cur_rcpt;

    const char *temp[2];	/* used to avoid extra indirection in
				   getenvelope() */
    char *authuser;		/* user who submitted message */

    struct dest *dlist;
    enum pending *pend;
};

typedef struct mydata mydata_t;

static int adddest(struct mydata *mydata, const char *rcpt,
		   char *mailbox, const char *authas);

/* data per script */
typedef struct script_data {
    char *username;
    char *mailboxname;
} script_data_t;

/* forward declarations */
static int deliver(message_data_t *msgdata, char *authuser,
		   struct auth_state *authstate);
static int verify_user(const char *user, const char *domain, const char *mailbox,
		       long quotacheck, struct auth_state *authstate);
FILE *proxy_spoolfile(message_data_t *msgdata);
void shut_down(int code);
static void usage();

/* current namespace */
static struct namespace lmtpd_namespace;

struct lmtp_func mylmtp = { &deliver, &verify_user, &shut_down,
			    &proxy_spoolfile, NULL, &lmtpd_namespace,
			    0, 0, 0 };

/* globals */
static int quotaoverride = 0;		/* should i override quota? */
const char *BB = "";
static mupdate_handle *mhandle = NULL;
int deliver_logfd = -1; /* used in lmtpengine.c */

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, &mysasl_proxy_policy, NULL },
    { SASL_CB_CANON_USER, &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

int service_init(int argc __attribute__((unused)),
		 char **argv __attribute__((unused)),
		 char **envp __attribute__((unused)))
{
    int r;

    if (geteuid() == 0) return 1;
    
    signals_set_shutdown(&shut_down);
    signals_add_handlers();
    signal(SIGPIPE, SIG_IGN);

    BB = config_getstring(IMAPOPT_POSTUSER);

    global_sasl_init(1, 1, mysasl_cb);

    /* Set namespace */
    if ((r = mboxname_init_namespace(&lmtpd_namespace, 0)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    if (!config_mupdate_server) {
	syslog(LOG_ERR, "no mupdate_server defined");
	return EC_CONFIG;
    }
    mhandle = NULL;

    /* setup the cache */
    backend_cached = xmalloc(sizeof(struct backend *));
    backend_cached[0] = NULL;

    return 0;
}

static int mupdate_ignore_cb(struct mupdate_mailboxdata *mdata __attribute__((unused)),
			     const char *cmd __attribute__((unused)),
			     void *context __attribute__((unused))) 
{
    /* If we get called, we've recieved something other than an OK in
     * response to the NOOP, so we want to hang up this connection anyway */
    return MUPDATE_FAIL;
}


/*
 * run for each accepted connection
 */
int service_main(int argc __attribute__((unused)),
		 char **argv __attribute__((unused)),
		 char **envp __attribute__((unused)))
{
    int opt;
    int r;

    deliver_in = prot_new(0, 0);
    deliver_out = prot_new(1, 1);
    prot_setflushonread(deliver_in, deliver_out);
    prot_settimeout(deliver_in, 300);

    while ((opt = getopt(argc, argv, "q")) != EOF) {
	switch(opt) {
	case 'q':
	    quotaoverride = 1;
	    break;

	default:
	    usage();
	}
    }

    /* get a connection to the mupdate server */
    r = 0;
    if (mhandle) {
	/* we have one already, test it */
	r = mupdate_noop(mhandle, mupdate_ignore_cb, NULL);
	if(r) {
	    /* will NULL mhandle for us */
	    mupdate_disconnect(&mhandle);
	}
    }
    /* connect to the mupdate server */
    if (!mhandle) {
	r = mupdate_connect(config_mupdate_server, NULL, &mhandle, NULL);
    }	
    if (!r) {
	lmtpmode(&mylmtp, deliver_in, deliver_out, 0);
    } else {
	mhandle = NULL;
	syslog(LOG_ERR, "couldn't connect to %s: %s", config_mupdate_server,
	       error_message(r));
	prot_printf(deliver_out, "451 %s LMTP Cyrus %s %s\r\n",
		    config_servername, CYRUS_VERSION, error_message(r));
    }

    /* free session state */
    if (deliver_in) prot_free(deliver_in);
    if (deliver_out) prot_free(deliver_out);
    deliver_in = deliver_out = NULL;

    if (deliver_logfd != -1) {
        close(deliver_logfd);
        deliver_logfd = -1;
    }

    cyrus_close_sock(0);
    cyrus_close_sock(1);
    cyrus_close_sock(2);

    return 0;
}

/* Called by service API to shut down the service */
void service_abort(int error)
{
    shut_down(error);
}

static void usage()
{
    fprintf(stderr, "421-4.3.0 usage: lmtpproxyd [-C <alt_config>]\r\n");
    fprintf(stderr, "421 4.3.0 %s\n", CYRUS_VERSION);
    exit(EC_USAGE);
}

/* return the connection to the server */
static struct backend *proxyd_findserver(const char *server)
{
    int i = 0;
    struct backend *ret = NULL;

    while (backend_cached && backend_cached[i]) {
	if (!strcmp(server, backend_cached[i]->hostname)) {
	    ret = backend_cached[i];
	    /* ping/noop the server */
	    if (backend_ping(ret, &protocol[PROTOCOL_LMTP])) {
		backend_disconnect(ret, &protocol[PROTOCOL_LMTP]);
	    }
	    break;
	}
	i++;
    }

    if (!ret || (ret->sock == -1)) {
	/* need to (re)establish connection to server or create one */
	ret = backend_connect(ret, server, &protocol[PROTOCOL_LMTP], "", NULL);
	if (!ret) return NULL;
    }

    /* insert server in list of cached connections */
    if (!backend_cached[i]) {
	backend_cached = (struct backend **) 
	    xrealloc(backend_cached, (i + 2) * sizeof(struct backend *));
	backend_cached[i] = ret;
	backend_cached[i + 1] = NULL;
    }

    return ret;
}

static int adddest(struct mydata *mydata, const char *rcpt,
		   char *mailbox, const char *authas)
{
    struct rcpt *new_rcpt = xmalloc(sizeof(struct rcpt));
    struct dest *d;
    struct mupdate_mailboxdata *mailboxdata;
    int r;

    strlcpy(new_rcpt->rcpt, rcpt, sizeof(new_rcpt->rcpt));
    new_rcpt->rcpt_num = mydata->cur_rcpt;
    
    /* find what server we're sending this to */
    r = mupdate_find(mhandle, mailbox, &mailboxdata);

    if (r == MUPDATE_MAILBOX_UNKNOWN) {
	r = IMAP_MAILBOX_NONEXISTENT;
    } else if (r) {
	/* xxx -- yuck: our error handling for now will be to exit;
	   this txn will be retried later -- to do otherwise means
	   that we may have to restart this transaction from scratch */
	fatal("error communicating with MUPDATE server", EC_TEMPFAIL);
    }

    if (r) {
	free(new_rcpt);
	return r;
    }

    assert(mailboxdata != NULL);

    /* xxx hide the fact that we are storing partitions */
    if(mailboxdata->server) {
	char *c;
	c = strchr(mailboxdata->server, '!');
	if(c) *c = '\0';
    }

    /* see if we currently have a 'mailboxdata->server'/'authas' 
       combination. */
    d = mydata->dlist;
    for (d = mydata->dlist; d != NULL; d = d->next) {
	if (!strcmp(d->server, mailboxdata->server) && 
	    !strcmp(d->authas, authas ? authas : "")) break;
    }

    if (d == NULL) {
	/* create a new one */
	d = xmalloc(sizeof(struct dest));
	strlcpy(d->server, mailboxdata->server, sizeof(d->server));
	strlcpy(d->authas, authas ? authas : "", sizeof(d->authas));
	d->rnum = 0;
	d->to = NULL;
	d->next = mydata->dlist;
	mydata->dlist = d;
    }

    /* add rcpt to d */
    d->rnum++;
    new_rcpt->next = d->to;
    d->to = new_rcpt;

    /* don't need to free mailboxdata; it goes with the handle */

    /* and we're done */
    return 0;
}

static void runme(struct mydata *mydata, message_data_t *msgdata)
{
    struct dest *d;

    /* run the txns */
    d = mydata->dlist;
    while (d) {
	struct lmtp_txn *lt = LMTP_TXN_ALLOC(d->rnum);
	struct rcpt *rc;
	struct backend *remote;
	int i = 0;
	int r = 0;
	
	lt->from = msgdata->return_path;
	lt->auth = d->authas[0] ? d->authas : NULL;
	lt->isdotstuffed = 0;
	lt->tempfail_unknown_mailbox = 1;
	
	prot_rewind(msgdata->data);
	lt->data = msgdata->data;
	lt->rcpt_num = d->rnum;
	rc = d->to;
	for (rc = d->to; rc != NULL; rc = rc->next, i++) {
	    assert(i < d->rnum);
	    lt->rcpt[i].addr = rc->rcpt;
	    lt->rcpt[i].ignorequota =
		msg_getrcpt_ignorequota(msgdata, rc->rcpt_num);
	}
	assert(i == d->rnum);

	remote = proxyd_findserver(d->server);
	if (remote) {
	    r = lmtp_runtxn(remote, lt);
	} else {
	    /* remote server not available; tempfail all deliveries */
	    for (rc = d->to, i = 0; i < d->rnum; i++) {
		lt->rcpt[i].result = RCPT_TEMPFAIL;
		lt->rcpt[i].r = IMAP_SERVER_UNAVAILABLE;
	    }
	}

	/* process results of the txn, propogating error state to the
	   recipients */
	for (rc = d->to, i = 0; rc != NULL; rc = rc->next, i++) {
	    int j = rc->rcpt_num;
	    switch (mydata->pend[j]) {
	    case s_wait:
		/* hmmm, if something fails we'll want to try an 
		   error delivery */
		if (lt->rcpt[i].result != RCPT_GOOD) {
		    mydata->pend[j] = s_err;
		}
		break;
	    case s_err:
		/* we've already detected an error for this recipient,
		   and nothing will convince me otherwise */
		break;
	    case nosieve:
		/* this is the only delivery we're attempting for this rcpt */
		msg_setrcpt_status(msgdata, j, lt->rcpt[i].r);
		mydata->pend[j] = done;
		break;
	    case done:
	    case s_done:
		/* yikes! we shouldn't be getting a notification for this
		   person! */
		abort();
		break;
	    }
	}

	free(lt);
	d = d->next;
    }
}

/* deliver() runs through each recipient in 'msgdata', compiling a list of 
   final destinations for this message (each represented by a 'struct dest'
   linked off of 'mydata'.

   it then batches all the times this message is going to the same
   backend server with the same authentication, and attempts delivery of
   all of them simultaneously.

   it then examines the results, attempts any error deliveries (for sieve
   script errors) if necessary, and assigns the correct result for
   each of the original receipients.
*/
int deliver(message_data_t *msgdata, char *authuser,
	    struct auth_state *authstate __attribute__((unused)))
{
    int n, nrcpts;
    mydata_t mydata;
    struct dest *d;
    
    assert(msgdata);
    nrcpts = msg_getnumrcpt(msgdata);
    assert(nrcpts);

    /* create 'mydata', our per-delivery data */
    mydata.temp[0] = mydata.temp[1] = NULL;
    mydata.authuser = authuser;
    mydata.dlist = NULL;
    mydata.pend = xzmalloc(sizeof(enum pending) * nrcpts);

    /* loop through each recipient, compiling list of destinations */
    for (n = 0; n < nrcpts; n++) {
	char namebuf[MAX_MAILBOX_NAME+1] = "";
	const char *rcpt, *user, *domain, *mailbox;
	int r = 0;

	rcpt = msg_getrcptall(msgdata, n);
	msg_getrcpt(msgdata, n, &user, &domain, &mailbox);
	mydata.cur_rcpt = n;

	if (domain) snprintf(namebuf, sizeof(namebuf), "%s!", domain);

	/* case 1: shared mailbox request */
	if (!user) {
	    strlcat(namebuf, mailbox, sizeof(namebuf));

	    r = adddest(&mydata, rcpt, namebuf, mydata.authuser);
	    if (r) {
		msg_setrcpt_status(msgdata, n, r);
		mydata.pend[n] = done;
	    } else {
		mydata.pend[n] = nosieve;
	    }
	}

	/* case 2: ordinary user, Sieve script---naaah, not here */

	/* case 3: ordinary user, no Sieve script -- assume INBOX for now */
	else {
	    strlcat(namebuf, "user.", sizeof(namebuf));
	    strlcat(namebuf, user, sizeof(namebuf));

	    r = adddest(&mydata, rcpt, namebuf, authuser);
	    if (r) {
		msg_setrcpt_status(msgdata, n, r);
		mydata.pend[n] = done;
	    } else {
		mydata.pend[n] = nosieve;
	    }
	}
    }

    /* run the txns */
    runme(&mydata, msgdata);

    /* free the recipient/destination lists */
    d = mydata.dlist;
    while (d) {
	struct dest *nextd = d->next;
	struct rcpt *rc = d->to;
	
	while (rc) {
	    struct rcpt *nextrc = rc->next;
	    free(rc);
	    rc = nextrc;
	}
	free(d);
	d = nextd;
    }
    mydata.dlist = NULL;

    /* do any sieve error recovery, if needed */
    for (n = 0; n < nrcpts; n++) {
	switch (mydata.pend[n]) {
	case s_wait:
	case s_err:
	case s_done:
	    /* yikes, we haven't implemented sieve ! */
	    syslog(LOG_CRIT, 
		   "sieve states reached, but we don't implement sieve");
	    abort();
	    break;
	case nosieve:
	    /* yikes, we never got an answer on this one */
	    syslog(LOG_CRIT, "still waiting for response to rcpt %d",
		   n);
	    abort();
	    break;
	case done:
	    /* good */
	    break;
	}
    }

    /* run the error recovery txns */
    runme(&mydata, msgdata);

    /* everything should be in the 'done' state now, verify this */
    for (n = 0; n < nrcpts; n++) {
	assert(mydata.pend[n] == done || mydata.pend[n] == s_done);
    }
	    
    /* free data */
    free(mydata.pend);
    
    return 0;
}

void fatal(const char* s, int code)
{
    if(deliver_out) {
	prot_printf(deliver_out,"421 4.3.0 deliver: %s\r\n", s);
	prot_flush(deliver_out);
    } else {
	syslog(LOG_ERR, "FATAL: %s", s);
    }
    
    exit(code);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    int i;

    /* close backend connections */
    i = 0;
    while (backend_cached && backend_cached[i]) {
	backend_disconnect(backend_cached[i], &protocol[PROTOCOL_LMTP]);
	free(backend_cached[i]);
	i++;
    }
    if (backend_cached) free(backend_cached);

    if (deliver_out) prot_flush(deliver_out);
    if (mhandle) {
	mupdate_disconnect(&mhandle);
    }

    cyrus_done();

    exit(code);
}

static int verify_user(const char *user, const char *domain, const char *mailbox,
		       long quotacheck __attribute__((unused)),
		       struct auth_state *authstate __attribute__((unused)))
{
    char namebuf[MAX_MAILBOX_NAME+1] = "";
    int r = 0;

    if ((!user && !mailbox) ||
	(domain && (strlen(domain) + 1 > sizeof(namebuf)))) {
	r = IMAP_MAILBOX_NONEXISTENT;
    } else {
	/* construct the mailbox that we will verify */
	if (domain) snprintf(namebuf, sizeof(namebuf), "%s!", domain);

	if (!user) {
	    /* shared folder */
	    if (strlen(namebuf) + strlen(mailbox) > sizeof(namebuf)) {
		r = IMAP_MAILBOX_NONEXISTENT;
	    } else {
		strlcat(namebuf, mailbox, sizeof(namebuf));
	    }
	} else {
	    /* ordinary user -- check INBOX */
	    if (strlen(namebuf) + 5 + strlen(user) > sizeof(namebuf)) {
		r = IMAP_MAILBOX_NONEXISTENT;
	    } else {
		strlcat(namebuf, "user.", sizeof(namebuf));
		strlcat(namebuf, user, sizeof(namebuf));
	    }
	}
    }

#ifdef CHECK_MUPDATE_EARLY
    if (!r) {
	struct mupdate_mailboxdata *mailboxdata;
	r = mupdate_find(mhandle, namebuf, &mailboxdata);
	if (r == MUPDATE_NOCONN) {
	    /* yuck; our error handling for now will be to exit;
	       this txn will be retried later */
	    
	}
    }
    if (!r) {
	/* xxx check ACL */

    }

    if (!r) {
	/* add to destination list */
       
    }
#endif

    if (r) syslog(LOG_DEBUG, "verify_user(%s) failed: %s", namebuf,
		  error_message(r));

    return r;
}

/* we're a proxy, we don't care about single instance store */
FILE *proxy_spoolfile(message_data_t *msgdata __attribute__((unused))) 
{
    return tmpfile();
}
    
