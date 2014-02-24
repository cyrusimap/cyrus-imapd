/* lmtpd.c -- Program to deliver mail to a mailbox
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
 * $Id: lmtpd.c,v 1.167 2010/05/25 20:59:19 wescraig Exp $
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
#include "annotate.h"
#include "append.h"
#include "assert.h"
#include "auth.h"
#include "backend.h"
#include "caldav_db.h"
#include "carddav_db.h"
#include "duplicate.h"
#include "exitcodes.h"
#include "global.h"
#include "idle.h"
#include "imap_err.h"
#include "imparse.h"
#include "cyr_lock.h"
#include "mailbox.h"
#include "map.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "message.h"
#include "mupdate.h"
#include "notify.h"
#include "prot.h"
#include "proxy.h"
#include "statuscache.h"
#include "telemetry.h"
#include "tls.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"

#include "lmtpd.h"
#include "lmtpengine.h"
#include "lmtpstats.h"
#ifdef USE_SIEVE
#include "lmtp_sieve.h"

static sieve_interp_t *sieve_interp = NULL;
#endif

#include "sync_log.h"

/* forward declarations */
static int deliver(message_data_t *msgdata, char *authuser,
		   struct auth_state *authstate);
static int verify_user(const char *user, const char *domain, char *mailbox,
		       quota_t quotacheck, struct auth_state *authstate);
static char *generate_notify(message_data_t *m);

void shut_down(int code);

static FILE *spoolfile(message_data_t *msgdata);
static void removespool(message_data_t *msgdata);

/* current namespace */
static struct namespace lmtpd_namespace;

struct lmtp_func mylmtp = { &deliver, &verify_user, &shut_down,
			    &spoolfile, &removespool, &lmtpd_namespace,
			    0, 1, 0 };

static void usage();

/* global state */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

extern int optind;
extern char *optarg;
static int dupelim = 1;		/* eliminate duplicate messages with
				   same message-id */
static int singleinstance = 1;	/* attempt single instance store */

struct stagemsg *stage = NULL;

/* per-user/session state */
static struct protstream *deliver_out, *deliver_in;
int deliver_logfd = -1; /* used in lmtpengine.c */

/* our cached connections */
mupdate_handle *mhandle = NULL;
struct backend **backend_cached = NULL;

static struct protocol_t lmtp_protocol =
{ "lmtp", "lmtp", TYPE_STD,
  { { { 0, "220 " },
      { "LHLO", "lmtpproxyd", "250 ", NULL,
	{ { "AUTH ", CAPA_AUTH },
	  { "STARTTLS", CAPA_STARTTLS },
	  { "PIPELINING", CAPA_PIPELINING },
	  { "IGNOREQUOTA", CAPA_IGNOREQUOTA },
	  { NULL, 0 } } },
      { "STARTTLS", "220", "454", 0 },
      { "AUTH", 512, 0, "235", "5", "334 ", "*", NULL, 0 },
      { NULL, NULL, NULL },
      { "NOOP", NULL, "250" },
      { "QUIT", NULL, "221" } } }
};

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, (mysasl_cb_ft *) &mysasl_proxy_policy, NULL },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};


int service_init(int argc __attribute__((unused)), 
		 char **argv __attribute__((unused)), 
		 char **envp __attribute__((unused)))
{
    int r;

    if (geteuid() == 0) return 1;
    
    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    singleinstance = config_getswitch(IMAPOPT_SINGLEINSTANCESTORE);

    global_sasl_init(1, 1, mysasl_cb);

    if (config_mupdate_server &&
	(config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_STANDARD) &&
	!config_getstring(IMAPOPT_PROXYSERVERS)) {
	/* proxy only -- talk directly to mupdate master */
	r = mupdate_connect(config_mupdate_server, NULL, &mhandle, NULL);
	if (r) {
	    syslog(LOG_ERR, "couldn't connect to MUPDATE server %s: %s",
		   config_mupdate_server, error_message(r));
	    fatal("error connecting with MUPDATE server", EC_TEMPFAIL);
	}
    }
    else {
	dupelim = config_getswitch(IMAPOPT_DUPLICATESUPPRESSION);

#ifdef USE_SIEVE
	mylmtp.addheaders = xzmalloc(2 * sizeof(struct addheader));
	mylmtp.addheaders[0].name = "X-Sieve";
	mylmtp.addheaders[0].body = SIEVE_VERSION;

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

	/* so we can do DAV opterations */
	caldav_init();
	carddav_init();

	/* Initialize the annotatemore db (for sieve on shared mailboxes) */
	annotatemore_init(0, NULL, NULL);
	annotatemore_open(NULL);

	/* setup for statuscache invalidation */
	statuscache_open(NULL);

	/* setup for sending IMAP IDLE notifications */
	idle_enabled();
    }

    /* Set namespace */
    if ((r = mboxname_init_namespace(&lmtpd_namespace, 0)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    /* create connection to the SNMP listener, if available. */
    snmp_connect(); /* ignore return code */
    snmp_set_str(SERVER_NAME_VERSION, cyrus_version());

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
int service_main(int argc, char **argv, 
		 char **envp __attribute__((unused)))
{
    int opt, r;

    sync_log_init();

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

    /* get a connection to the mupdate server */
    r = 0;
    if (mhandle) {
	/* we have one already, test it */
	r = mupdate_noop(mhandle, mupdate_ignore_cb, NULL);
	if (r) {
	    /* will NULL mhandle for us */
	    mupdate_disconnect(&mhandle);

	    /* connect to the mupdate server */
	    r = mupdate_connect(config_mupdate_server, NULL, &mhandle, NULL);
	}
    }
    if (!r) {
	lmtpmode(&mylmtp, deliver_in, deliver_out, 0);
    } else {
	syslog(LOG_ERR, "couldn't connect to %s: %s", config_mupdate_server,
	       error_message(r));
	prot_printf(deliver_out, "451");
	if (config_serverinfo) prot_printf(deliver_out, " %s", config_servername);
	if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	    prot_printf(deliver_out, " Cyrus LMTP%s %s",
			config_mupdate_server ? " Murder" : "", cyrus_version());
	}
	prot_printf(deliver_out, " %s\r\n", error_message(r));
    }

    /* free session state */
    if (deliver_in) prot_free(deliver_in);
    if (deliver_out) prot_free(deliver_out);
    deliver_in = deliver_out = NULL;

    if (deliver_logfd != -1) {
	close(deliver_logfd);
	deliver_logfd = -1;
    }

    cyrus_reset_stdio();

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
    fprintf(stderr, "421 4.3.0 %s\n", cyrus_version());
    exit(EC_USAGE);
}

struct fuzz_rock {
    char *mboxname;
    size_t prefixlen;
    char *pat;
    size_t patlen;
    size_t matchlen;
};

#define WSP_CHARS "- _"

static int fuzzy_match_cb(char *name,
			  int matchlen __attribute__((unused)),
			  int maycreate __attribute__((unused)),
			  void *rock)
{
    struct fuzz_rock *frock = (struct fuzz_rock *) rock;
    unsigned i;

    for (i = frock->prefixlen; name[i] && frock->pat[i]; i++) {
	if (tolower((int) name[i]) != frock->pat[i] &&
	    !(strchr(WSP_CHARS, name[i]) &&
	      strchr(WSP_CHARS, frock->pat[i]))) {
	    break;
	}
    }

    /* see if we have a [partial] match */
    if (!name[i] && (!frock->pat[i] || frock->pat[i] == '.') &&
	i > frock->matchlen) {
	frock->matchlen = i;
	strlcpy(frock->mboxname, name, i+1);
	if (i == frock->patlen) return CYRUSDB_DONE;
    }

    return 0;
}

int fuzzy_match(char *mboxname)
{
    char name[MAX_MAILBOX_BUFFER], prefix[MAX_MAILBOX_BUFFER], *p = NULL;
    size_t prefixlen;
    struct fuzz_rock frock;

    /* make a working copy */
    strlcpy(name, mboxname, sizeof(name));

    /* check to see if this is an personal mailbox */
    if (!strncmp(name, "user.", 5) || (p = strstr(name, "!user."))) {
	p = p ? p + 6 : name + 5;

	/* check to see if this is an INBOX (no '.' after the userid) */
	if (!(p = strchr(p, '.'))) return 0;
    }

    if (p) p++;  /* skip the trailing '.' */
    else p = name;

    /* copy the prefix */
    prefixlen = p - name;
    strlcpy(prefix, name, prefixlen+1);

    /* normalize the rest of the pattern to lowercase */
    lcase(p);

    frock.mboxname = mboxname;
    frock.prefixlen = prefixlen;
    frock.pat = name;
    frock.patlen = strlen(name);
    frock.matchlen = 0;

    strlcat(prefix, "*", sizeof(prefix));
    mboxlist_findall(NULL, prefix, 1, NULL, NULL, fuzzy_match_cb, &frock);

    return frock.matchlen;
}

/* proxy mboxlist_lookup; on misses, it asks the listener for this
   machine to make a roundtrip to the master mailbox server to make
   sure it's up to date */
static int mlookup(const char *name, char **server, char **aclp, void *tid)
{
    int r;
    char *c;

    if (server) *server = NULL;

    if (mhandle) {
	/* proxy only, so check the mupdate master */
	struct mupdate_mailboxdata *mailboxdata;

	/* find what server we're sending this to */
	r = mupdate_find(mhandle, name, &mailboxdata);

	if (r == MUPDATE_MAILBOX_UNKNOWN) {
	    return IMAP_MAILBOX_NONEXISTENT;
	} else if (r) {
	    /* xxx -- yuck: our error handling for now will be to exit;
	       this txn will be retried later -- to do otherwise means
	       that we may have to restart this transaction from scratch */
	    fatal("error communicating with MUPDATE server", EC_TEMPFAIL);
	}

	if (mailboxdata->t == RESERVE) return IMAP_MAILBOX_RESERVED;

	if (aclp) *aclp = (char *) mailboxdata->acl;
	if (server) *server = (char *) mailboxdata->server;
	c = strchr(*server, '!');
	if (c) *c = '\0';
    }
    else {
	struct mboxlist_entry mbentry;
	/* do a local lookup and kick the slave if necessary */
	r = mboxlist_lookup(name, &mbentry, tid);
	if (r == IMAP_MAILBOX_NONEXISTENT && config_mupdate_server) {
	    kick_mupdate();
	    r = mboxlist_lookup(name, &mbentry, tid);
	}
	if (r) return r;
	if (mbentry.mbtype & MBTYPE_MOVING)  return IMAP_MAILBOX_MOVED;
	if (mbentry.mbtype & MBTYPE_DELETED) return IMAP_MAILBOX_NONEXISTENT;

	if (aclp) *aclp = mbentry.acl;
	if (server) {
	    if (mbentry.mbtype & MBTYPE_REMOTE) {
		/* xxx hide the fact that we are storing partitions */
		*server = mbentry.partition;
		c = strchr(*server, '!');
		if (c) *c = '\0';
	    }
	}
    }

    return r;
}

/* places msg in mailbox mailboxname.  
 * if you wish to use single instance store, pass stage as non-NULL
 * if you want to deliver message regardless of duplicates, pass id as NULL
 * if you want to notify, pass user
 * if you want to force delivery (to force delivery to INBOX, for instance)
 * pass acloverride
 */
int deliver_mailbox(FILE *f,
		    struct message_content *content,
		    struct stagemsg *stage,
		    unsigned size,
		    char **flag,
		    int nflags,
		    char *authuser,
		    struct auth_state *authstate,
		    char *id,
		    const char *user,
		    char *notifyheader,
		    const char *mailboxname,
		    char *date,
		    int quotaoverride,
		    int acloverride)
{
    int r;
    struct appendstate as;
    unsigned long uid;
    const char *notifier;
    duplicate_key_t dkey = {NULL, NULL, NULL};

    r = append_setup(&as, mailboxname,
		     authuser, authstate, acloverride ? 0 : ACL_POST, 
		     quotaoverride ? (long) -1 :
		     config_getswitch(IMAPOPT_LMTP_STRICT_QUOTA) ?
		     (long) size : 0);

    /* check for duplicate message */
    dkey.id = id;
    dkey.to = mailboxname;
    dkey.date = date;
    if (!r && id && dupelim && !(as.mailbox->i.options & OPT_IMAP_DUPDELIVER) &&
	duplicate_check(&dkey)) {
	duplicate_log(&dkey, "delivery");
	append_abort(&as);
	return 0;
    }

    if (!r && !content->body) {
	/* parse the message body if we haven't already,
	   and keep the file mmap'ed */
	r = message_parse_file(f, &content->base, &content->len, &content->body);
    }

    if (!r) {
	r = append_fromstage(&as, &content->body, stage, 0,
			     (const char **) flag, nflags, !singleinstance);

	if (r) {
	    append_abort(&as);
	} else {
	    struct mailbox *mailbox = NULL;
	    /* hold the mailbox open until the duplicate mark is done */
	    r = append_commit(&as, quotaoverride ? -1 : 0, NULL, &uid,
			      NULL, &mailbox);
	    if (!r) {
		syslog(LOG_INFO, "Delivered: %s to mailbox: %s",
		       id, mailboxname);
		if (dupelim && id) {
		    duplicate_mark(&dkey, time(NULL), uid);
		}
		mailbox_close(&mailbox);
	    }
	}
    }

    if (!r && user && (notifier = config_getstring(IMAPOPT_MAILNOTIFIER))) {
	char inbox[MAX_MAILBOX_BUFFER];
	char namebuf[MAX_MAILBOX_BUFFER];
	char userbuf[MAX_MAILBOX_BUFFER];
	const char *notify_mailbox = mailboxname;
	int r2;

	/* translate user.foo to INBOX */
	if (!(*lmtpd_namespace.mboxname_tointernal)(&lmtpd_namespace,
						    "INBOX", user, inbox)) {
	    size_t inboxlen = strlen(inbox);
	    if (strlen(mailboxname) >= inboxlen &&
		!strncmp(mailboxname, inbox, inboxlen) &&
		(!mailboxname[inboxlen] || mailboxname[inboxlen] == '.')) {
		strlcpy(inbox, "INBOX", sizeof(inbox)); 
		strlcat(inbox, mailboxname+inboxlen, sizeof(inbox));
		notify_mailbox = inbox;
	    }
	}

	/* translate mailboxname */
	r2 = (*lmtpd_namespace.mboxname_toexternal)(&lmtpd_namespace,
						    notify_mailbox,
						    user, namebuf);
	if (!r2) {
	    strlcpy(userbuf, user, sizeof(userbuf));
	    /* translate any separators in user */
	    mboxname_hiersep_toexternal(&lmtpd_namespace, userbuf,
					config_virtdomains ?
					strcspn(userbuf, "@") : 0);
	    notify(notifier, "MAIL", NULL, userbuf, namebuf, 0, NULL,
		   notifyheader ? notifyheader : "");
	}
    }

    return r;
}

enum rcpt_status {
    done = 0,
    nosieve,			/* no sieve script */
    s_wait,			/* processing sieve requests */
    s_err,			/* error in sieve processing/sending */
    s_done,			/* sieve script successfully run */
};

void deliver_remote(message_data_t *msgdata,
		    struct dest *dlist, enum rcpt_status *status)
{
    struct dest *d;

    /* run the txns */
    d = dlist;
    while (d) {
	struct lmtp_txn *lt = LMTP_TXN_ALLOC(d->rnum);
	struct rcpt *rc;
	struct backend *remote;
	int i = 0;
	
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

	remote = proxy_findserver(d->server, &lmtp_protocol, "",
				  &backend_cached, NULL, NULL, NULL);
	if (remote) {
	    int txn_timeout = config_getint(IMAPOPT_LMTPTXN_TIMEOUT);
	    if (txn_timeout) 
		prot_settimeout(remote->in, txn_timeout);
	    lmtp_runtxn(remote, lt);
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
	    switch (status[j]) {
	    case s_wait:
		/* hmmm, if something fails we'll want to try an 
		   error delivery */
		if (lt->rcpt[i].result != RCPT_GOOD) {
		    status[j] = s_err;
		}
		break;
	    case s_err:
		/* we've already detected an error for this recipient,
		   and nothing will convince me otherwise */
		break;
	    case nosieve:
		/* this is the only delivery we're attempting for this rcpt */
		msg_setrcpt_status(msgdata, j, lt->rcpt[i].r);
		status[j] = done;
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

int deliver_local(deliver_data_t *mydata, char **flag, int nflags,
		  const char *username, const char *mailboxname)
{
    char namebuf[MAX_MAILBOX_BUFFER] = "", *tail;
    message_data_t *md = mydata->m;
    int quotaoverride = msg_getrcpt_ignorequota(md, mydata->cur_rcpt);
    int ret;

    /* case 1: shared mailbox request */
    if (!*username || username[0] == '@') {
	if (*username) snprintf(namebuf, sizeof(namebuf), "%s!", username+1);
	strlcat(namebuf, mailboxname, sizeof(namebuf));

	return deliver_mailbox(md->f, mydata->content, mydata->stage,
			       md->size, flag, nflags,
			       mydata->authuser, mydata->authstate, md->id,
			       NULL, mydata->notifyheader,
			       namebuf, md->date, quotaoverride, 0);
    }

    /* case 2: ordinary user */
    ret = (*mydata->namespace->mboxname_tointernal)(mydata->namespace,
						    "INBOX",
						    username, namebuf);

    if (!ret) {
	int ret2 = 1;

	tail = namebuf + strlen(namebuf);
	if (mailboxname) {
	    strlcat(namebuf, ".", sizeof(namebuf));
	    strlcat(namebuf, mailboxname, sizeof(namebuf));

	    ret2 = deliver_mailbox(md->f, mydata->content, mydata->stage,
				   md->size, flag, nflags,
				   mydata->authuser, mydata->authstate, md->id,
				   username, mydata->notifyheader,
				   namebuf, md->date, quotaoverride, 0);
	}
	if (ret2 == IMAP_MAILBOX_NONEXISTENT && mailboxname &&
	    config_getswitch(IMAPOPT_LMTP_FUZZY_MAILBOX_MATCH) &&
	    fuzzy_match(namebuf)) {
	    /* try delivery to a fuzzy matched mailbox */
	    ret2 = deliver_mailbox(md->f, mydata->content, mydata->stage,
				   md->size, flag, nflags,
				   mydata->authuser, mydata->authstate, md->id,
				   username, mydata->notifyheader,
				   namebuf, md->date, quotaoverride, 0);
	}
	if (ret2) {
	    /* normal delivery to INBOX */
	    struct auth_state *authstate = auth_newstate(username);

	    *tail = '\0';

	    ret = deliver_mailbox(md->f, mydata->content, mydata->stage,
				  md->size, flag, nflags,
				  (char *) username, authstate, md->id,
				  username, mydata->notifyheader,
				  namebuf, md->date, quotaoverride, 1);

	    if (authstate) auth_freestate(authstate);
	}
    }

    return ret;
}

int deliver(message_data_t *msgdata, char *authuser,
	    struct auth_state *authstate)
{
    int n, nrcpts;
    struct dest *dlist = NULL;
    enum rcpt_status *status;
    struct message_content content = { NULL, 0, NULL };
    char *notifyheader;
    deliver_data_t mydata;
    
    assert(msgdata);
    nrcpts = msg_getnumrcpt(msgdata);
    assert(nrcpts);

    notifyheader = generate_notify(msgdata);

    /* create our per-recipient status */
    status = xzmalloc(sizeof(enum rcpt_status) * nrcpts);

    /* create 'mydata', our per-delivery data */
    mydata.m = msgdata;
    mydata.content = &content;
    mydata.stage = stage;
    mydata.notifyheader = notifyheader;
    mydata.namespace = &lmtpd_namespace;
    mydata.authuser = authuser;
    mydata.authstate = authstate;
    
    /* loop through each recipient, attempting delivery for each */
    for (n = 0; n < nrcpts; n++) {
	char namebuf[MAX_MAILBOX_BUFFER] = "", *server;
	char userbuf[MAX_MAILBOX_BUFFER];
	const char *rcpt, *user, *domain, *mailbox;
	int r = 0;

	rcpt = msg_getrcptall(msgdata, n);
	msg_getrcpt(msgdata, n, &user, &domain, &mailbox);

	namebuf[0] = '\0';
	userbuf[0] = '\0';

	if (domain) snprintf(namebuf, sizeof(namebuf), "%s!", domain);

	/* case 1: shared mailbox request */
	if (!user) {
	    strlcat(namebuf, mailbox, sizeof(namebuf));
	}
	/* case 2: ordinary user */
	else {
	    strlcat(namebuf, "user.", sizeof(namebuf));
	    strlcat(namebuf, user, sizeof(namebuf));

	    strlcpy(userbuf, user, sizeof(userbuf));
	}
	if (domain) {
	    strlcat(userbuf, "@", sizeof(userbuf));
	    strlcat(userbuf, domain, sizeof(userbuf));
	}

	r = mlookup(namebuf, &server, NULL, NULL);
	if (!r && server) {
	    /* remote mailbox */
	    proxy_adddest(&dlist, rcpt, n, server, authuser);
	    status[n] = nosieve;
	}
	else if (!r) {
	    /* local mailbox */
	    mydata.cur_rcpt = n;
#ifdef USE_SIEVE
	    r = run_sieve(user, domain, mailbox, sieve_interp, &mydata);
	    /* if there was no sieve script, or an error during execution,
	       r is non-zero and we'll do normal delivery */
#else
	    r = 1;	/* normal delivery */
#endif

	    if (r) {
		r = deliver_local(&mydata, NULL, 0, userbuf, mailbox);
	    }
	}

	telemetry_rusage( user );
	msg_setrcpt_status(msgdata, n, r);
    }

    if (dlist) {
	struct dest *d;

	/* run the txns */
	deliver_remote(msgdata, dlist, status);

	/* free the recipient/destination lists */
	d = dlist;
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
	dlist = NULL;

	/* do any sieve error recovery, if needed */
	for (n = 0; n < nrcpts; n++) {
	    switch (status[n]) {
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
	deliver_remote(msgdata, dlist, status);

	/* everything should be in the 'done' state now, verify this */
	for (n = 0; n < nrcpts; n++) {
	    assert(status[n] == done || status[n] == s_done);
	}
    }
   
    /* cleanup */
    free(status);
    if (content.base) map_free(&content.base, &content.len);
    if (content.body) {
	message_free_body(content.body);
	free(content.body);
    }
    append_removestage(stage);
    stage = NULL;
    if (notifyheader) free(notifyheader);

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
    if (stage) append_removestage(stage);

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
    int i;

    /* set flag */
    in_shutdown = 1;

    /* close backend connections */
    i = 0;
    while (backend_cached && backend_cached[i]) {
	proxy_downserver(backend_cached[i]);
	free(backend_cached[i]);
	i++;
    }
    if (backend_cached) free(backend_cached);

    if (mhandle) {
	mupdate_disconnect(&mhandle);
    } else {
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

	carddav_done();
	caldav_done();

	annotatemore_close();
	annotatemore_done();

	statuscache_close();
	statuscache_done();
    }

#ifdef HAVE_SSL
    tls_shutdown_serverengine();
#endif
    if (deliver_out) {
	prot_flush(deliver_out);

	/* one less active connection */
	snmp_increment(ACTIVE_CONNECTIONS, -1);
    }

    sync_log_done();

    cyrus_done();

    exit(code);
}

static int verify_user(const char *user, const char *domain, char *mailbox,
		       quota_t quotacheck, struct auth_state *authstate)
{
    char namebuf[MAX_MAILBOX_BUFFER] = "";
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

    if (!r) {
	char *server, *acl;
	long aclcheck = !user ? ACL_POST : 0;
	/*
	 * check to see if mailbox exists and we can append to it:
	 *
	 * - must have posting privileges on shared folders
	 * - don't care about ACL on INBOX (always allow post)
	 * - don't care about message size (1 msg over quota allowed)
	 */
	r = mlookup(namebuf, &server, &acl, NULL);

	if (r == IMAP_MAILBOX_NONEXISTENT && !user &&
	    config_getswitch(IMAPOPT_LMTP_FUZZY_MAILBOX_MATCH) &&
	    /* see if we have a mailbox whose name is close */
	    fuzzy_match(namebuf)) {

	    /* We are guaranteed that the mailbox returned by fuzzy_match()
	       will be no longer than the original, so we can copy over
	       the existing mailbox.  The keeps us from having to do the
	       fuzzy match multiple times. */
	    strcpy(mailbox, domain ? namebuf+strlen(domain)+1 : namebuf);

	    r = mlookup(namebuf, &server, &acl, NULL);
	}

	if (!r && server) {
	    int access = cyrus_acl_myrights(authstate, acl);

	    if ((access & aclcheck) != aclcheck) {
		r = (access & ACL_LOOKUP) ?
		    IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	    }
	} else if (!r) {
	    r = append_check(namebuf, authstate,
			     aclcheck, (quotacheck < 0)
			     || config_getswitch(IMAPOPT_LMTP_STRICT_QUOTA) ?
			     quotacheck : 0);
	}
    }

    if (r) syslog(LOG_DEBUG, "verify_user(%s) failed: %s", namebuf,
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

    /* spool to the stage of one of the recipients
       (don't bother if we're only a proxy) */
    n = mhandle ? 0 : msg_getnumrcpt(msgdata);
    for (i = 0; !f && (i < n); i++) {
	char namebuf[MAX_MAILBOX_BUFFER] = "", *server;
	const char *user, *domain, *mailbox;
	int r;

	/* build the mailboxname from the recipient address */
	msg_getrcpt(msgdata, i, &user, &domain, &mailbox);

	if (domain) snprintf(namebuf, sizeof(namebuf), "%s!", domain);

	/* case 1: shared mailbox request */
	if (!user) {
	    strlcat(namebuf, mailbox, sizeof(namebuf));
	}

	/* case 2: ordinary user */
	else {
	    /* assume delivery to INBOX for now */
	    strlcat(namebuf, "user.", sizeof(namebuf));
	    strlcat(namebuf, user, sizeof(namebuf));
	}

	r = mlookup(namebuf, &server, NULL, NULL);
	if (!r && !server) {
	    /* local mailbox -- setup stage for later use by deliver() */
	    f = append_newstage(namebuf, now, 0, &stage);
	}
    }

    if (!f) {
	/* we only have remote mailboxes, so use a tempfile */
	int fd = create_tempfile(config_getstring(IMAPOPT_TEMP_PATH));

	if (fd != -1) f = fdopen(fd, "w+");
    }

    return f;
}

void removespool(message_data_t *msgdata __attribute__((unused)))
{
    append_removestage(stage);
    stage = NULL;
}
