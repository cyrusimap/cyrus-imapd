/* lmtpd.c -- Program to deliver mail to a mailbox
 *
 * $Id: lmtpd.c,v 1.129 2004/02/08 18:44:28 ken3 Exp $
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
#include "auth.h"
#include "prot.h"
#include "imparse.h"
#include "lock.h"
#include "global.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "version.h"
#include "duplicate.h"
#include "append.h"
#include "mboxlist.h"
#include "notify.h"
#include "idle.h"
#include "tls.h"

#include "lmtpengine.h"
#include "lmtpstats.h"
#include "lmtp_sieve.h"

/* forward declarations */
static int deliver(message_data_t *msgdata, char *authuser,
		   struct auth_state *authstate);
static int verify_user(const char *user, long quotacheck,
		       struct auth_state *authstate);
static char *generate_notify(message_data_t *m);

void shut_down(int code);

static FILE *spoolfile(message_data_t *msgdata);
static void removespool(message_data_t *msgdata);

struct lmtp_func mylmtp = { &deliver, &verify_user, &shut_down,
			    &spoolfile, &removespool, 0, 1, 0 };

static void usage();

/* global state */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

extern int optind;
extern char *optarg;
static int dupelim = 1;		/* eliminate duplicate messages with
				   same message-id */
static int singleinstance = 1;	/* attempt single instance store */
const char *BB = "";

#ifdef USE_SIEVE
static sieve_interp_t *sieve_interp = NULL;
#endif

/* per-user/session state */
static struct protstream *deliver_out, *deliver_in;
int deliver_logfd = -1; /* used in lmtpengine.c */

/* current namespace */
static struct namespace lmtpd_namespace;

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

    singleinstance = config_getswitch(IMAPOPT_SINGLEINSTANCESTORE);
    BB = config_getstring(IMAPOPT_POSTUSER);

    global_sasl_init(0, 1, mysasl_cb);

    dupelim = config_getswitch(IMAPOPT_DUPLICATESUPPRESSION);

#ifdef USE_SIEVE
    mylmtp.addheaders = xmalloc(80);
    snprintf(mylmtp.addheaders, 80, "X-Sieve: %s\r\n", SIEVE_VERSION);

    /* setup sieve support */
    sieve_interp = setup_sieve();
#else
    if (dupelim)
#endif
    {
	/* initialize duplicate delivery database */
	if (duplicate_init(NULL, 0) != 0) {
	    fatal("lmtpd: unable to init duplicate delivery database",
		  EC_SOFTWARE);
	}
    }

    /* so we can do mboxlist operations */
    mboxlist_init(0);
    mboxlist_open(NULL);

    /* so we can do quota operations */
    quotadb_init(0);
    quotadb_open(NULL);

    /* setup for sending IMAP IDLE notifications */
    idle_enabled();

    /* Set namespace */
    if ((r = mboxname_init_namespace(&lmtpd_namespace, 0)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    /* create connection to the SNMP listener, if available. */
    snmp_connect(); /* ignore return code */
    snmp_set_str(SERVER_NAME_VERSION, CYRUS_VERSION);

    return 0;
}

/*
 * run for each accepted connection
 */
int service_main(int argc, char **argv, 
		 char **envp __attribute__((unused)))
{
    int opt;

    deliver_in = prot_new(0, 0);
    deliver_out = prot_new(1, 1);
    prot_setflushonread(deliver_in, deliver_out);
    prot_settimeout(deliver_in, 360);

    while ((opt = getopt(argc, argv, "a")) != EOF) {
	switch(opt) {
	case 'a':
	    mylmtp.preauth = 1;
	    break;

	default:
	    usage();
	}
    }

    snmp_increment(TOTAL_CONNECTIONS, 1);
    snmp_increment(ACTIVE_CONNECTIONS, 1);

    lmtpmode(&mylmtp, deliver_in, deliver_out, 0);

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

static void
usage()
{
    fprintf(stderr, "421-4.3.0 usage: lmtpd [-C <alt_config>] [-a]\r\n");
    fprintf(stderr, "421 4.3.0 %s\n", CYRUS_VERSION);
    exit(EC_USAGE);
}

/* places msg in mailbox mailboxname.  
 * if you wish to use single instance store, pass stage as non-NULL
 * if you want to deliver message regardless of duplicates, pass id as NULL
 * if you want to notify, pass user
 * if you want to force delivery (to force delivery to INBOX, for instance)
 * pass acloverride
 */
int deliver_mailbox(struct protstream *msg,
		    struct stagemsg *stage,
		    unsigned size,
		    char **flag,
		    int nflags,
		    char *authuser,
		    struct auth_state *authstate,
		    char *id,
		    char *user,
		    char *notifyheader,
		    const char *mailboxname,
		    int quotaoverride,
		    int acloverride)
{
    int r;
    struct appendstate as;
    char namebuf[MAX_MAILBOX_PATH+1];
    time_t now = time(NULL);
    unsigned long uid;

    /* Translate any separators in user */
    if (user && *user != '@')
	mboxname_hiersep_tointernal(&lmtpd_namespace, user,
				    config_virtdomains ?
				    strcspn(user, "@") : 0);

    r = (*lmtpd_namespace.mboxname_tointernal)(&lmtpd_namespace, mailboxname,
					       user, namebuf);

    if (dupelim && id && 
	duplicate_check(id, strlen(id), namebuf, strlen(namebuf))) {
	/* duplicate message */
	duplicate_log(id, namebuf, "delivery");
	return 0;
    }

    if (!r) {
	r = append_setup(&as, namebuf, MAILBOX_FORMAT_NORMAL,
			 authuser, authstate, acloverride ? 0 : ACL_POST, 
			 quotaoverride ? -1 : 0);
    }

    if (!r) {
	prot_rewind(msg);
	r = append_fromstage(&as, stage, now,
			     (const char **) flag, nflags, !singleinstance);
	if (!r) append_commit(&as, quotaoverride ? -1 : 0, NULL, &uid, NULL);
	else append_abort(&as);
    }

    if (!r && user && strcspn(user, "@")) {
	const char *notifier = config_getstring(IMAPOPT_MAILNOTIFIER);

	if (notifier) {
	    /* do we want to replace user.XXX with INBOX? */
	    notify(notifier, "MAIL", NULL, user, mailboxname, 0, NULL,
		   notifyheader ? notifyheader : "");
	}
    }

    if (!r && dupelim && id) duplicate_mark(id, strlen(id), 
					    namebuf, strlen(namebuf),
					    now, uid);
    return r;
}

int deliver(message_data_t *msgdata, char *authuser,
	    struct auth_state *authstate)
{
    int n, nrcpts;
    sieve_msgdata_t mydata;
    char namebuf[MAX_MAILBOX_PATH+1];
    
    assert(msgdata);
    nrcpts = msg_getnumrcpt(msgdata);
    assert(nrcpts);

    /* create 'mydata', our per-delivery data */
    mydata.m = msgdata;
    mydata.stage = (struct stagemsg *) msg_getrock(msgdata);
    mydata.notifyheader = generate_notify(msgdata);
    mydata.namespace = &lmtpd_namespace;
    mydata.authuser = authuser;
    mydata.authstate = authstate;
    
    /* loop through each recipient, attempting delivery for each */
    for (n = 0; n < nrcpts; n++) {
	char *rcpt = xstrdup(msg_getrcpt(msgdata, n));
	char *plus, *domain = NULL, user[MAX_MAILBOX_NAME+1];
	int quotaoverride = msg_getrcpt_ignorequota(msgdata, n);
	int r = 0;

	if (config_virtdomains && (domain = strchr(rcpt, '@'))) {
	    *domain++ = '\0';
	    if (config_defdomain && !strcasecmp(config_defdomain, domain))
		domain = NULL;
	}

	mydata.cur_rcpt = n;
	plus = strchr(rcpt, '+');
	if (plus) *plus++ = '\0';
	/* case 1: shared mailbox request */
	if (plus && !strcmp(rcpt, BB)) {
	    strcpy(user, "");
	    if (domain) sprintf(user+strlen(user), "@%s", domain);
	    strlcpy(namebuf, lmtpd_namespace.prefix[NAMESPACE_SHARED],
		    sizeof(namebuf));
	    strlcat(namebuf, plus, sizeof(namebuf));
	    r = deliver_mailbox(msgdata->data, 
				mydata.stage,
				msgdata->size, 
				NULL, 0,
				mydata.authuser, mydata.authstate,
				msgdata->id, user, mydata.notifyheader,
				namebuf, quotaoverride, 0);
	}

	/* case 2: ordinary user, might have Sieve script */
	else if (!strchr(rcpt, lmtpd_namespace.hier_sep) &&
	         strlen(rcpt) + 30 <= MAX_MAILBOX_PATH) {

	    strlcpy(user, rcpt, sizeof(user));
	    if (domain) sprintf(user+strlen(user), "@%s", domain);

#ifdef USE_SIEVE
	    r = run_sieve(user, plus, sieve_interp, &mydata);
	    /* if there was no sieve script, or an error during execution,
	       r is non-zero and we'll do normal delivery */
#else
	    r = 1;		/* normal delivery */
#endif

	    if (r && plus &&
		strlen(user) + strlen(plus) + 30 <= MAX_MAILBOX_PATH) {
		/* normal delivery to + mailbox */
		strlcpy(namebuf, lmtpd_namespace.prefix[NAMESPACE_INBOX],
			sizeof(namebuf));
		strlcat(namebuf, plus, sizeof(namebuf));
		
		r = deliver_mailbox(msgdata->data, 
				    mydata.stage, 
				    msgdata->size, 
				    NULL, 0, 
				    mydata.authuser, mydata.authstate,
				    msgdata->id, user, mydata.notifyheader,
				    namebuf, quotaoverride, 0);
	    }

	    if (r) {
		/* normal delivery to INBOX */
		strlcpy(namebuf, "INBOX", sizeof(namebuf));
		
		/* ignore ACL's trying to deliver to INBOX */
		r = deliver_mailbox(msgdata->data, 
				    mydata.stage,
				    msgdata->size, 
				    NULL, 0, 
				    mydata.authuser, mydata.authstate,
				    msgdata->id, user, mydata.notifyheader,
				    namebuf, quotaoverride, 1);
	    }
	}

	free(rcpt);
	msg_setrcpt_status(msgdata, n, r);
    }

    append_removestage(mydata.stage);
    if (mydata.notifyheader) free(mydata.notifyheader);

    return 0;
}

void fatal(const char* s, int code)
{
    static int recurse_code = 0;
    
    if(recurse_code) {
	/* We were called recursively. Just give up */
	snmp_increment(ACTIVE_CONNECTIONS, -1);
	exit(recurse_code);
    }
    recurse_code = code;
    if(deliver_out) {
	prot_printf(deliver_out,"421 4.3.0 lmtpd: %s\r\n", s);
	prot_flush(deliver_out);
    }

    syslog(LOG_ERR, "FATAL: %s", s);
    
    /* shouldn't return */
    shut_down(code);

    exit(code);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
#ifdef USE_SIEVE
    sieve_interp_free(&sieve_interp);
#else
    if (dupelim)
#endif
	duplicate_done();

    mboxlist_close();
    mboxlist_done();

    quotadb_close();
    quotadb_done();
#ifdef HAVE_SSL
    tls_shutdown_serverengine();
#endif
    if (deliver_out) {
	prot_flush(deliver_out);

	/* one less active connection */
	snmp_increment(ACTIVE_CONNECTIONS, -1);
    }

    cyrus_done();

    exit(code);
}

static int verify_user(const char *user, long quotacheck,
		       struct auth_state *authstate)
{
    char buf[MAX_MAILBOX_NAME+1];
    char *plus;
    int r = 0;
    int sl = strlen(BB);
    char *domain = NULL;
    int userlen = strlen(user), domainlen = 0;

    if (config_virtdomains && (domain = strchr(user, '@'))) {
	userlen = domain - user;
	domain++;
	/* ignore default domain */
	if (!(config_defdomain && !strcasecmp(config_defdomain, domain)))
	    domainlen = strlen(domain)+1;
    }

    /* check to see if mailbox exists and we can append to it */
    if (!strncmp(user, BB, sl) && user[sl] == '+') {
	/* special shared folder address */
	if (domainlen)
	    snprintf(buf, sizeof(buf),
		     "%s!%.*s", domain, userlen - sl - 1, user + sl + 1);
	else
	    snprintf(buf, sizeof(buf),
		     "%.*s", userlen - sl - 1, user + sl + 1);
	/* Translate any separators in user */
	mboxname_hiersep_tointernal(&lmtpd_namespace, buf+domainlen, 0);
	/* - must have posting privileges on shared folders
	   - don't care about message size (1 msg over quota allowed) */
	r = append_check(buf, MAILBOX_FORMAT_NORMAL, authstate,
			 ACL_POST, quotacheck > 0 ? 0 : quotacheck);
    } else {
	/* ordinary user */
	if (userlen > sizeof(buf)-10) {
	    r = IMAP_MAILBOX_NONEXISTENT;
	} else {
	    if (domainlen)
		snprintf(buf, sizeof(buf),
			 "%s!user.%.*s", domain, userlen, user);
	    else
		snprintf(buf, sizeof(buf), "user.%.*s", userlen, user);
	    plus = strchr(buf, '+');
	    if (plus) *plus = '\0';
	    /* Translate any separators in user */
	    mboxname_hiersep_tointernal(&lmtpd_namespace, buf+domainlen+5, 0);
	    /* - don't care about ACL on INBOX (always allow post)
	       - don't care about message size (1 msg over quota allowed) */
	    r = append_check(buf, MAILBOX_FORMAT_NORMAL, authstate,
			     0, quotacheck > 0 ? 0 : quotacheck);
	}
    }

    if (r) syslog(LOG_DEBUG, "append_check() of '%s' failed (%s)", buf,
		  error_message(r));

    return r;
}

const char *notifyheaders[] = { "From", "Subject", "To", 0 };
/* returns a malloc'd string that should be sent to users for successful
   delivery of 'm'. */
char *generate_notify(message_data_t *m)
{
    const char **body;
    char *ret = NULL;
    unsigned int len = 0;
    unsigned int pos = 0;
    int i;

    for (i = 0; notifyheaders[i]; i++) {
	const char *h = notifyheaders[i];
	body = msg_getheader(m, h);
	if (body) {
	    int j;

	    for (j = 0; body[j] != NULL; j++) {
		/* put the header */
		/* need: length + ": " + '\0'*/
		while (pos + strlen(h) + 3 > len) {
		    ret = xrealloc(ret, len += 1024);
		}
		pos += sprintf(ret + pos, "%s: ", h);
		
		/* put the header body.
		   xxx it would be nice to linewrap.*/
		/* need: length + '\n' + '\0' */
		while (pos + strlen(body[j]) + 2 > len) {
		    ret = xrealloc(ret, len += 1024);
		}
		pos += sprintf(ret + pos, "%s\n", body[j]);
	    }
	}
    }

    return ret;
}

FILE *spoolfile(message_data_t *msgdata)
{
    int i, n;
    time_t now = time(NULL);
    FILE *f = NULL;

    /* spool to the stage of one of the recipients */
    n = msg_getnumrcpt(msgdata);
    for (i = 0; !f && (i < n); i++) {
	int r = 0;
	char *rcpt, *plus, *user = NULL, *domain = NULL;
	char namebuf[MAX_MAILBOX_PATH+1], mailboxname[MAX_MAILBOX_PATH+1];

	/* build the mailboxname from the recipient address */
	user = rcpt = xstrdup(msg_getrcpt(msgdata, i));
	if (config_virtdomains && (domain = strchr(rcpt, '@'))) {
	    *domain = '\0';
	}

	plus = strchr(rcpt, '+');
	if (plus) *plus++ = '\0';

	/* case 1: shared mailbox request */
	if (plus && !strcmp(rcpt, BB)) {
	    strlcpy(namebuf, lmtpd_namespace.prefix[NAMESPACE_SHARED],
		    sizeof(namebuf));
	    strlcat(namebuf, plus, sizeof(namebuf));
	    user += strlen(BB);
	}

	/* case 2: ordinary user */
	else if (!strchr(rcpt, lmtpd_namespace.hier_sep) &&
	         strlen(rcpt) + 30 <= MAX_MAILBOX_PATH) {

	    /* assume delivery to INBOX for now */
	    strlcpy(namebuf, "INBOX", sizeof(namebuf));
	}

	/* case 3: unable to handle rcpt */
	else {
	    /* force error and we'll fallback to using /tmp */
	    r = 1;
	}

	/* reassemble the user and domain */
	if (domain) {
	    *domain = '@';
	    /* slide the domain up to the user */
	    if (plus) memmove(plus-1, domain, strlen(domain)+1);
	}

	if (!r) {
	    /* Translate any separators in user */
	    if (user && *user != '@')
		mboxname_hiersep_tointernal(&lmtpd_namespace, user,
					    config_virtdomains ?
					    strcspn(user, "@") : 0);

	    r = (*lmtpd_namespace.mboxname_tointernal)(&lmtpd_namespace,
						       namebuf,
						       user, mailboxname);
	}

	free(rcpt);

	if (!r) {
	    struct stagemsg *stage = NULL;

	    /* setup stage for later use by deliver() */
	    f = append_newstage(mailboxname, now, 0, &stage);
	    msg_setrock(msgdata, (void*) stage);
	}
    }

    return f;
}

void removespool(message_data_t *msgdata)
{
    struct stagemsg *stage = (struct stagemsg *) msg_getrock(msgdata);

    append_removestage(stage);
}

