/* lmtpproxyd.c -- Program to proxy mail delivery
 *
 * $Id: lmtpproxyd.c,v 1.34 2002/02/14 22:41:18 leg Exp $
 * Copyright (c) 1999-2000 Carnegie Mellon University.  All rights reserved.
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
#include "imapconf.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "version.h"
#include "mboxname.h"

#include "mupdate-client.h"
#include "lmtpengine.h"
#include "lmtpstats.h"

struct protstream *deliver_out, *deliver_in;

extern int optind;
extern char *optarg;

extern int errno;

/* a final destination for a message */
struct rcpt {
    char mailbox[MAX_MAILBOX_NAME]; /* where? */
    int rcpt_num;		    /* credit this to who? */
    struct rcpt *next;
};

struct dest {
    char server[MAX_MAILBOX_NAME];  /* where? */
    char authas[MAX_MAILBOX_NAME];  /* as who? */
    int rnum;			    /* number of rcpts */
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

static int adddest(struct mydata *mydata, 
		   const char *mailbox, const char *authas);

/* data per script */
typedef struct script_data {
    char *username;
    char *mailboxname;
} script_data_t;

/* forward declarations */
static int deliver(message_data_t *msgdata, char *authuser,
		   struct auth_state *authstate);
static int verify_user(const char *user, long quotacheck,
		       struct auth_state *authstate);
void shut_down(int code);
static void usage();

struct lmtp_func mylmtp = { &deliver, &verify_user, &shut_down, 0, 0, 0 };

/* globals */
static int quotaoverride = 0;		/* should i override quota? */
const char *BB = "";
static mupdate_handle *mhandle;
static const char *mupdate_server = NULL;

/* current namespace */
static struct namespace lmtpd_namespace;

/* should we allow users to proxy?  return SASL_OK if yes,
   SASL_BADAUTH otherwise */
static int mysasl_authproc(sasl_conn_t *conn,
			   void *context,
			   const char *requested_user, unsigned rlen,
			   const char *auth_identity, unsigned alen,
			   const char *def_realm, unsigned urlen,
			   struct propctx *propctx)
{
    const char *val;
    char *realm;
    int allowed=0;
    struct auth_state *authstate;

    /* check if remote realm */
    if ((realm = strchr(auth_identity, '@'))!=NULL) {
	realm++;
	val = config_getstring("loginrealms", "");
	while (*val) {
	    if (!strncasecmp(val, realm, strlen(realm)) &&
		(!val[strlen(realm)] || isspace((int) val[strlen(realm)]))) {
		break;
	    }
	    /* not this realm, try next one */
	    while (*val && !isspace((int) *val)) val++;
	    while (*val && isspace((int) *val)) val++;
	}
	if (!*val) {
	    sasl_seterror(conn, 0, "cross-realm login %s denied",
			  auth_identity);
	    return SASL_BADAUTH;
	}
    }

    /* ok, is auth_identity an admin? 
     * for now only admins can do lmtp from another machine
     */
    authstate = auth_newstate(auth_identity, NULL);
    allowed = authisa(authstate, "lmtp", "admins");
    auth_freestate(authstate);
    
    if (!allowed) {
	sasl_seterror(conn, 0, "only admins may authenticate");
	return SASL_BADAUTH;
    }

    return SASL_OK;
}

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, &mysasl_authproc, NULL },
    { SASL_CB_CANON_USER, &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

int service_init(int argc, char **argv, char **envp)
{
    int r;

    config_changeident("lmtpd");
    if (geteuid() == 0) return 1;
    
    signals_set_shutdown(&shut_down);
    signals_add_handlers();
    signal(SIGPIPE, SIG_IGN);

    BB = config_getstring("postuser", BB);

    if ((r = sasl_server_init(mysasl_cb, "Cyrus")) != SASL_OK) {
	syslog(LOG_ERR, "SASL failed initializing: sasl_server_init(): %s", 
	       sasl_errstring(r, NULL, NULL));
	return EC_SOFTWARE;
    }

    r = sasl_client_init(NULL);
    if(r != 0) {
	syslog(LOG_ERR, "could not initialize client-side SASL: %s",
	       sasl_errstring(r, NULL, NULL));
	return EC_SOFTWARE;
    }

    /* Set namespace */
    if ((r = mboxname_init_namespace(&lmtpd_namespace, 0)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    mupdate_server = config_getstring("mupdate_server", NULL);
    if (!mupdate_server) {
	syslog(LOG_ERR, "no mupdate_server defined");
	return EC_CONFIG;
    }
    mhandle = NULL;

    return 0;
}

/*
 * run for each accepted connection
 */
int service_main(int argc, char **argv, char **envp)
{
    int opt;
    int r;

    deliver_in = prot_new(0, 0);
    deliver_out = prot_new(1, 1);
    prot_setflushonread(deliver_in, deliver_out);
    prot_settimeout(deliver_in, 300);

    while ((opt = getopt(argc, argv, "C:q")) != EOF) {
	switch(opt) {
	case 'C': /* alt config file - handled by service::main() */
	    break;

	case 'q':
	    quotaoverride = 1;
	    break;

	default:
	    usage();
	}
    }

    /* get a connection to the mupdate server */
    r = 0;
    if (!mhandle) {
	r = mupdate_connect(mupdate_server, NULL, &mhandle, NULL);
    }
    if (!r) {
	lmtpmode(&mylmtp, deliver_in, deliver_out, 0);
    } else {
	mhandle = NULL;
	syslog(LOG_ERR, "couldn't connect to %s: %s", mupdate_server,
	       error_message(r));
	prot_printf(deliver_out, "451 %s LMTP Cyrus %s %s\r\n",
		    config_servername, CYRUS_VERSION, error_message(r));
    }

    /* free session state */
    if (deliver_in) prot_free(deliver_in);
    if (deliver_out) prot_free(deliver_out);
    close(0);
    close(1);
    close(2);

    return 0;
}

/* called if 'service_init()' was called but not 'service_main()' */
void service_abort(int error)
{
    exit(error);
}

static void usage()
{
    fprintf(stderr, "421-4.3.0 usage: lmtpproxyd [-C <alt_config>]\r\n");
    fprintf(stderr, "421 4.3.0 %s\n", CYRUS_VERSION);
    exit(EC_USAGE);
}

struct connlist {
    char *host;
    struct lmtp_conn *conn;
    struct connlist *next;
} *chead = NULL;

extern sasl_callback_t *mysasl_callbacks(const char *username,
					 const char *authname,
					 const char *realm,
					 const char *password);
void free_callbacks(sasl_callback_t *in);

static struct lmtp_conn *getconn(const char *server)
{
    int r;
    struct connlist *p = chead;
    sasl_callback_t *cb = NULL;

    for (p = chead; p != NULL; p = p->next) {
	if (!strcmp(p->host, server)) break;
    }
    if (!p) {
	const char *pass;
	char *cp;
	char optstr[128];

	/* create a new one */
	p = xmalloc(sizeof(struct connlist));
	p->host = xstrdup(server);

	strcpy(optstr, server);
	cp = strchr(optstr, '.');
	if (cp) *cp = '\0';
	strcat(optstr, "_password");
	pass = config_getstring(optstr, NULL);

	cb = mysasl_callbacks(config_getstring("lmtpproxy_username", ""),
			      config_getstring("lmtpproxy_authname", "proxy"),
			      config_getstring("lmtpproxy_realm", NULL),
			      pass);
	
	r = lmtp_connect(p->host, cb, &p->conn);
	if (r) {
	    fatal("can't connect to backend lmtp server", EC_TEMPFAIL);
	}

	/* insert it */
	p->next = chead;
	chead = p;
    }

    /* verify connection is ok */
    r = lmtp_verify_conn(p->conn);
    if (r) {
	r = lmtp_disconnect(p->conn);
	if (r) {
	    fatal("can't dispose of backend server connection", EC_TEMPFAIL);
	}

	r = lmtp_connect(p->host, NULL, &p->conn);
	if (r) {
	    fatal("can't connect to backend lmtp server", EC_TEMPFAIL);
	}
    }

    if(cb) free_callbacks(cb);

    return p->conn;
}

static void putconn(const char *server, struct lmtp_conn *c)
{
    return;
}

static int adddest(struct mydata *mydata, 
		   const char *mailbox, const char *authas)
{
    struct rcpt *new = xmalloc(sizeof(struct rcpt));
    struct dest *d;
    struct mupdate_mailboxdata *mailboxdata;
    int sl = strlen(BB);
    int r;
    char buf[MAX_MAILBOX_NAME];

    strlcpy(new->mailbox, mailbox, MAX_MAILBOX_NAME);
    new->rcpt_num = mydata->cur_rcpt;
    
    /* find what server we're sending this to */
    if (!strncmp(mailbox, BB, sl) && mailbox[sl] == '+') {
	/* special shared folder address */
	strcpy(buf, mailbox + sl + 1);
	mboxname_hiersep_tointernal(&lmtpd_namespace, buf);
	r = mupdate_find(mhandle, buf, &mailboxdata);
    } else {
	char *plus;

	strlcpy(buf, "user.", sizeof buf);
	strlcat(buf, mailbox, sizeof buf);
	plus = strchr(buf, '+');
	if (plus) *plus = '\0';

	/* find where this user lives */
	r = mupdate_find(mhandle, buf, &mailboxdata);
    }

    if (r == MUPDATE_NOCONN) {
	/* yuck; our error handling for now will be to exit;
	   this txn will be retried later */
	fatal("mupdate server not responding", EC_TEMPFAIL);
    }

    if (r) {
	free(new);
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
	strlcpy(d->server, mailboxdata->server, MAX_MAILBOX_NAME);
	strlcpy(d->authas, authas ? authas : "", MAX_MAILBOX_NAME);
	d->rnum = 0;
	d->to = NULL;
	d->next = mydata->dlist;
	mydata->dlist = d;
    }

    /* add rcpt to d */
    d->rnum++;
    new->next = d->to;
    d->to = new;

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
	struct lmtp_conn *remote;
	int i = 0;
	int r = 0;
	
	lt->from = msgdata->return_path;
	lt->auth = d->authas[0] ? d->authas : NULL;
	lt->isdotstuffed = 0;
	
	prot_rewind(msgdata->data);
	lt->data = msgdata->data;
	lt->rcpt_num = d->rnum;
	rc = d->to;
	for (rc = d->to; rc != NULL; rc = rc->next) {
	    assert(i < d->rnum);
	    lt->rcpt[i++].addr = rc->mailbox;
	}
	assert(i == d->rnum);
	
	remote = getconn(d->server);
	if (remote) {
	    r = lmtp_runtxn(remote, lt);
	    putconn(d->server, remote);
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
	    struct auth_state *authstate)
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
	char *rcpt = xstrdup(msg_getrcpt(msgdata, n));
	char *plus;
	int r = 0;

	mydata.cur_rcpt = n;
	plus = strchr(rcpt, '+');
	if (plus) *plus++ = '\0';
	/* case 1: shared mailbox request */
	if (plus && !strcmp(rcpt, BB)) {
	    *--plus = '+';	/* put that plus back */
	    r = adddest(&mydata, rcpt, mydata.authuser);
	    
	    if (r) {
		msg_setrcpt_status(msgdata, n, r);
		mydata.pend[n] = done;
	    } else {
		mydata.pend[n] = nosieve;
	    }
	}

	/* case 2: ordinary user, Sieve script---naaah, not here */

	/* case 3: ordinary user, no Sieve script */
	else {
	    if (plus) *--plus = '+';

	    r = adddest(&mydata, rcpt, authuser);
	    if (r) {
		msg_setrcpt_status(msgdata, n, r);
		mydata.pend[n] = done;
	    } else {
		mydata.pend[n] = nosieve;
	    }
	}

	free(rcpt);
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
    prot_printf(deliver_out,"421 4.3.0 deliver: %s\r\n", s);
    prot_flush(deliver_out);
    exit(code);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    prot_flush(deliver_out);
    if (mhandle) {
	mupdate_disconnect(&mhandle);
    }

    exit(code);
}

static int verify_user(const char *user,
		       long quotacheck,
		       struct auth_state *authstate)
{
    char buf[MAX_MAILBOX_PATH];
    int r = 0;
    int sl = strlen(BB);

    /* check to see if mailbox exists */
    if (!strncmp(user, BB, sl) && user[sl] == '+') {
	/* special shared folder address */
	strcpy(buf, user + sl + 1);
    } else {			/* ordinary user */
	int l;
	char *plus = strchr(user, '+');

	if (plus) l = plus - user;
	else l = strlen(buf);

	if (l >= MAX_MAILBOX_NAME) {
	    /* too long a name */
	    r = IMAP_MAILBOX_NONEXISTENT;
	} else {
	    /* just copy before the plus */
	    strcpy(buf, "user.");
	    strncat(buf, user, l);
	    buf[l + 5] = '\0';
	}
    }

#ifdef CHECK_MUPDATE_EARLY
    /* Translate any separators */
    if (!r) mboxname_hiersep_tointernal(&lmtpd_namespace, buf);
    if (!r) {
	r = mupdate_find(mhandle, buf, &mailboxdata);
	if (r == MUPDATE_NOCONN) {
	    /* yuck; our error handling for now will be to exit;
	       this txn will be retried later */
	    
	}
    if (!r) {
	/* xxx check ACL */

    }

    if (!r) {
	/* add to destination list */
       
    }
#endif

    return r;
}
