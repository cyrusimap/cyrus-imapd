/* nntpd.c -- NNTP server
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 */

/*
 * TODO:
 *
 * - support for control messages
 * - OVER/XOVER (will this fix problems with Netscape & Outlook?)
 * - wildmat support
 * - support for msgid in commands
 * - use nntpd-specific DB instead of deliver.db?
 */

/*
 * $Id: nntpd.c,v 1.1.2.9 2002/09/25 19:10:58 ken3 Exp $
 */
#include <config.h>


#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/param.h>
#include <syslog.h>
#include <com_err.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "prot.h"

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "acl.h"
#include "util.h"
#include "auth.h"
#include "iptostring.h"
#include "imapconf.h"
#include "tls.h"

#include "exitcodes.h"
#include "imap_err.h"
#include "nntp_err.h"
#include "mailbox.h"
#include "append.h"
#include "duplicate.h"
#include "version.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "telemetry.h"

extern int optind;
extern char *optarg;
extern int opterr;

extern int errno;

/* Stuff to make index.c link */
int imapd_exists;
struct protstream *imapd_out = NULL;
struct auth_state *imapd_authstate = NULL;
char *imapd_userid = NULL;
void printastring(const char *s)
{
    fatal("not implemented", EC_SOFTWARE);
}
/* end stuff to make index.c link */

extern void index_operatemailbox(struct mailbox *mailbox);
extern int index_finduid(unsigned uid);
extern int index_getuid(unsigned msgno);


#ifdef HAVE_SSL
static SSL *tls_conn;
#endif /* HAVE_SSL */

sasl_conn_t *nntp_saslconn; /* the sasl connection context */

static int have_dupdb = 1;	/* duplicate delivery db is initialized */
static int dupelim = 1;		/* eliminate duplicate messages with
				   same message-id */
char newsprefix[100] = "";
char *nntp_userid = 0;
struct auth_state *nntp_authstate = 0;
static struct mailbox *nntp_group = 0;
struct sockaddr_in nntp_localaddr, nntp_remoteaddr;
int nntp_haveaddr = 0;
char nntp_clienthost[250] = "[local]";
struct protstream *nntp_out = NULL;
struct protstream *nntp_in = NULL;
unsigned nntp_exists = 0;
unsigned nntp_current = 0;

static int nntps = 0;
int nntp_starttls_done = 0;

static struct mailbox mboxstruct;

/* the sasl proxy policy context */
static struct proxy_context nntp_proxyctx = {
    0, 1, NULL, NULL, NULL
};

/*
 * values for article parts 
 * these correspond to the last digit of the response code
 */
enum {
    ARTICLE_ALL  = 0,
    ARTICLE_HEAD = 1,
    ARTICLE_BODY = 2,
    ARTICLE_STAT = 3
};

/* values for post modes */
enum {
    POST_POST     = 0,
    POST_IHAVE    = 1,
    POST_CHECK    = 2,
    POST_TAKETHIS = 3,
};

/* response codes for each stage of posting */
struct {
    int ok, cont, no, fail;
} post_codes[] = { { 240, 340, 440, 441 },
		   { 235, 335, 435, 436 },
		   {  -1, 238, 438,  -1 },
		   { 239,  -1,  -1, 439 } };

static void cmd_starttls();
static void cmd_user();
static void cmd_pass();
static void cmd_mode();
static void cmd_list();
static void cmd_article();
static void cmd_post();
static void cmdloop(void);
static struct mailbox *open_group();
static int parsenum(char *ptr);
void usage(void);
void shut_down(int code) __attribute__ ((noreturn));


extern void setproctitle_init(int argc, char **argv, char **envp);
extern int proc_register(const char *progname, const char *clienthost, 
			 const char *userid, const char *mailbox);
extern void proc_cleanup(void);


static struct 
{
    char *ipremoteport;
    char *iplocalport;
    sasl_ssf_t ssf;
    char *authid;
} saslprops = {NULL,NULL,0,NULL};

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, &mysasl_proxy_policy, (void*) &nntp_proxyctx },
    { SASL_CB_CANON_USER, &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

static void nntp_reset(void)
{
    proc_cleanup();

    if (nntp_group) {
	mailbox_close(nntp_group);
	nntp_group = 0;
    }

    if (nntp_in) {
	prot_NONBLOCK(nntp_in);
	prot_fill(nntp_in);
	
	prot_free(nntp_in);
    }

    if (nntp_out) {
	prot_flush(nntp_out);
	prot_free(nntp_out);
    }
    
    nntp_in = nntp_out = NULL;

    close(0);
    close(1);
    close(2);

    strcpy(nntp_clienthost, "[local]");
    if (nntp_userid != NULL) {
	free(nntp_userid);
	nntp_userid = NULL;
    }
    if (nntp_saslconn) {
	sasl_dispose(&nntp_saslconn);
	nntp_saslconn = NULL;
    }
    nntp_starttls_done = 0;

    if(saslprops.iplocalport) {
       free(saslprops.iplocalport);
       saslprops.iplocalport = NULL;
    }
    if(saslprops.ipremoteport) {
       free(saslprops.ipremoteport);
       saslprops.ipremoteport = NULL;
    }
    if(saslprops.authid) {
       free(saslprops.authid);
       saslprops.authid = NULL;
    }
    saslprops.ssf = 0;

#ifdef HAVE_SSL
    if (tls_conn) {
	tls_reset_servertls(&tls_conn);
	tls_conn = NULL;
    }
#endif

    nntp_exists = 0;
    nntp_current = 0;
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc __attribute__((unused)),
		 char **argv __attribute__((unused)),
		 char **envp __attribute__((unused)))
{
    int opt;
    const char *prefix;

    initialize_nntp_error_table();

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);
    setproctitle_init(argc, argv, envp);

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signals_add_handlers();
    signal(SIGPIPE, SIG_IGN);

    /* load the SASL plugins */
    config_sasl_init(0, 1, mysasl_cb);

    if ((prefix = config_getstring(IMAPOPT_NEWSPREFIX)))
	snprintf(newsprefix, sizeof(newsprefix), "%s.", prefix);

    dupelim = config_getswitch(IMAPOPT_DUPLICATESUPPRESSION);
    /* initialize duplicate delivery database */
    if (duplicate_init(NULL, 0) != 0) {
	syslog(LOG_ERR, 
	       "lmtpd: unable to init duplicate delivery database\n");
	dupelim = have_dupdb = 0;
    }

    /* open the mboxlist, we'll need it for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);

    while ((opt = getopt(argc, argv, "C:Ds")) != EOF) {
	switch(opt) {
	case 'C': /* alt config file - handled by service::main() */
	    break;
	case 'D': /* external debugger - handled by service::main() */
 	    break;
	case 's': /* nntps (do starttls right away) */
	    nntps = 1;
	    if (!tls_enabled()) {
		syslog(LOG_ERR, "nntps: required OpenSSL options not present");
		fatal("nntps: required OpenSSL options not present",
		      EC_CONFIG);
	    }
	    break;

	default:
	    usage();
	}
    }

    return 0;
}

/*
 * run for each accepted connection
 */
int service_main(int argc, char **argv, char **envp)
{
    socklen_t salen;
    struct hostent *hp;
    char localip[60], remoteip[60];
    int timeout;
    sasl_security_properties_t *secprops=NULL;

    signals_poll();

    nntp_in = prot_new(0, 0);
    nntp_out = prot_new(1, 1);

    /* Find out name of client host */
    salen = sizeof(nntp_remoteaddr);
    if (getpeername(0, (struct sockaddr *)&nntp_remoteaddr, &salen) == 0 &&
	nntp_remoteaddr.sin_family == AF_INET) {
	hp = gethostbyaddr((char *)&nntp_remoteaddr.sin_addr,
			   sizeof(nntp_remoteaddr.sin_addr), AF_INET);
	if (hp != NULL) {
	    strncpy(nntp_clienthost, hp->h_name, sizeof(nntp_clienthost)-30);
	    nntp_clienthost[sizeof(nntp_clienthost)-30] = '\0';
	} else {
	    nntp_clienthost[0] = '\0';
	}
	strcat(nntp_clienthost, "[");
	strcat(nntp_clienthost, inet_ntoa(nntp_remoteaddr.sin_addr));
	strcat(nntp_clienthost, "]");
	salen = sizeof(nntp_localaddr);
	if (getsockname(0, (struct sockaddr *)&nntp_localaddr, &salen) == 0) {
	    nntp_haveaddr = 1;
	}
    }

    /* other params should be filled in */
    if (sasl_server_new("nntp", config_servername, NULL, NULL, NULL,
			NULL, 0, &nntp_saslconn) != SASL_OK)
	fatal("SASL failed initializing: sasl_server_new()",EC_TEMPFAIL); 

    /* will always return something valid */
    secprops = mysasl_secprops(SASL_SEC_NOPLAINTEXT);
    sasl_setprop(nntp_saslconn, SASL_SEC_PROPS, secprops);
    
    if(iptostring((struct sockaddr *)&nntp_localaddr,
		  sizeof(struct sockaddr_in), localip, 60) == 0) {
	sasl_setprop(nntp_saslconn, SASL_IPLOCALPORT, localip);
	saslprops.iplocalport = xstrdup(localip);
    }
    
    if(iptostring((struct sockaddr *)&nntp_remoteaddr,
		  sizeof(struct sockaddr_in), remoteip, 60) == 0) {
	sasl_setprop(nntp_saslconn, SASL_IPREMOTEPORT, remoteip);  
	saslprops.ipremoteport = xstrdup(remoteip);
    }

    proc_register("nntpd", nntp_clienthost, NULL, NULL);

    /* Set inactivity timer */
    timeout = config_getint(IMAPOPT_TIMEOUT);
    if (timeout < 3) timeout = 3;
    prot_settimeout(nntp_in, timeout*60);
    prot_setflushonread(nntp_in, nntp_out);

    /* we were connected on nntps port so we should do 
       TLS negotiation immediatly */
    if (nntps == 1) cmd_starttls(1);

    prot_printf(nntp_out,
		"200 %s Cyrus NNTP %s server ready, posting allowed\r\n",
		config_servername, CYRUS_VERSION);

    cmdloop();

    /* QUIT executed */

    /* cleanup */
    nntp_reset();

    return 0;
}

/* called if 'service_init()' was called but not 'service_main()' */
void service_abort(int error)
{
    shut_down(error);
}

void usage(void)
{
    prot_printf(nntp_out, "503 usage: nntpd [-C <alt_config>] [-s]\r\n");
    prot_flush(nntp_out);
    exit(EC_USAGE);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code)
{
    proc_cleanup();
    if (nntp_group) {
	mailbox_close(nntp_group);
    }

    duplicate_done();

    mboxlist_close();
    mboxlist_done();

    if (nntp_in) {
	prot_NONBLOCK(nntp_in);
	prot_fill(nntp_in);
	prot_free(nntp_in);
    }

    if (nntp_out) {
	prot_flush(nntp_out);
	prot_free(nntp_out);
    }

#ifdef HAVE_SSL
    tls_shutdown_serverengine();
#endif

    exit(code);
}

void fatal(const char* s, int code)
{
    static int recurse_code = 0;

    if (recurse_code) {
	/* We were called recursively. Just give up */
	proc_cleanup();
	exit(recurse_code);
    }
    recurse_code = code;
    if (nntp_out) {
	prot_printf(nntp_out, "400 Fatal error: %s\r\n", s);
	prot_flush(nntp_out);
    }
    shut_down(code);
}

/*
 * Top-level command loop parsing
 */
static void cmdloop(void)
{
    int c;
    static struct buf cmd, arg1, arg2;
    const char *err;

    for (;;) {
	signals_poll();

	/* Parse command name */
	c = getword(nntp_in, &cmd);
	if (c == EOF) {
	    if ((err = prot_error(nntp_in))!=NULL) {
		syslog(LOG_WARNING, "%s, closing connection", err);
		prot_printf(nntp_out, "400 %s\r\n", err);
	    }
	    return;
	}
	if (!cmd.s[0]) {
	    prot_printf(nntp_out, "501 Null command\r\n");
	    eatline(nntp_in, c);
	    continue;
	}

	lcase(cmd.s);

	if (!strcmp(cmd.s, "quit")) {
	    if (c == '\r') c = prot_getc(nntp_in);
	    if (c != '\n') goto extraargs;

	    prot_printf(nntp_out, "205 Bye\r\n");
	    return;
	}
	else if (!strcmp(cmd.s, "date")) {
	    time_t now = time(NULL);
	    struct tm *my_tm = gmtime(&now);
	    char buf[15];

	    if (c == '\r') c = prot_getc(nntp_in);
	    if (c != '\n') goto extraargs;

	    strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", my_tm);
	    prot_printf(nntp_out, "111 %s\r\n", buf);
	}
	else if (!strcmp(cmd.s, "mode")) {
	    if (c != ' ') goto missingargs;
	    c = getword(nntp_in, &arg1);
	    if (c == EOF) goto missingargs;
	    if (c == '\r') c = prot_getc(nntp_in);
	    if (c != '\n') goto extraargs;

	    cmd_mode(arg1.s);
	}
	else if (!strcmp(cmd.s, "authinfo")) {
	    if (c != ' ') goto missingargs;
	    c = getword(nntp_in, &arg1);
	    if (c == EOF) goto missingargs;
	    if (c != ' ') goto missingargs;
	    c = getword(nntp_in, &arg2);
	    if (c == EOF) goto missingargs;
	    if (c == '\r') c = prot_getc(nntp_in);
	    if (c != '\n') goto extraargs;

	    lcase(arg1.s);
	    if (!strcmp(arg1.s, "user"))
		cmd_user(arg2.s);
	    else if (!strcmp(arg1.s, "pass"))
		cmd_pass(arg2.s);
	    else
		prot_printf(nntp_out, "500 Unrecognized command\r\n");
	}
	else if (!strcmp(cmd.s, "list")) {
	    arg1.len = arg2.len = 0;
	    if (c == ' ') {
		c = getword(nntp_in, &arg1);
		if (c == EOF) goto missingargs;
		if (c == ' ') {
		    c = getword(nntp_in, &arg2);
		    if (c == EOF) goto missingargs;
		}
	    }
	    if (c == '\r') c = prot_getc(nntp_in);
	    if (c != '\n') goto extraargs;

	    cmd_list(arg1.len ? arg1.s : NULL, arg2.len ? arg2.s : NULL);
	}
	else if (!strcmp(cmd.s, "listgroup")) {
	    arg1.len = 0;
	    if (c == ' ') {
		c = getword(nntp_in, &arg1);
		if (c == EOF) goto missingargs;
	    }
	    if (c == '\r') c = prot_getc(nntp_in);
	    if (c != '\n') goto extraargs;

	    if (arg1.len) nntp_group = open_group(arg1.s, 0);
	    if (nntp_group) {
		int i;
		prot_printf(nntp_out, "211 list of articles follows\r\n");
		for (i = 1; i <= nntp_exists; i++)
		    prot_printf(nntp_out, "%u\r\n", index_getuid(i));
		prot_printf(nntp_out, ".\r\n");
	    }
	}
	else if (!strcmp(cmd.s, "group")) {
	    if (c != ' ') goto missingargs;
	    c = getword(nntp_in, &arg1);
	    if (c == EOF) goto missingargs;
	    if (c == '\r') c = prot_getc(nntp_in);
	    if (c != '\n') goto extraargs;

	    nntp_group = open_group(arg1.s, 0);
	    if (nntp_group) {
		prot_printf(nntp_out, "211 %u %u %u %s\r\n",
			    nntp_exists, nntp_exists ? index_getuid(1) : 1,
			    nntp_exists ? index_getuid(nntp_exists) : 0,
			    arg1.s);
	    }
	}
	else if (!strcmp(cmd.s, "last")) {
	    if (!nntp_group) goto nogroup;
	    if (c == '\r') c = prot_getc(nntp_in);
	    if (c != '\n') goto extraargs;
	    if (nntp_current == 1) {
		prot_printf(nntp_out,
			    "422 No previous article in this group\r\n");
	    } else {
		prot_printf(nntp_out, "223 %u %s\r\n",
			    index_getuid(--nntp_current), "<0>");
	    }
	}
	else if (!strcmp(cmd.s, "next")) {
	    if (!nntp_group) goto nogroup;
	    if (c == '\r') c = prot_getc(nntp_in);
	    if (c != '\n') goto extraargs;
	    if (nntp_current == nntp_exists) {
		prot_printf(nntp_out, "422 No next article in this group\r\n");
	    } else {
		prot_printf(nntp_out, "223 %u %s\r\n",
			    index_getuid(++nntp_current), "<0>");
	    }
	}
	else if (!strcmp(cmd.s, "article") || !strcmp(cmd.s, "head") ||
		 !strcmp(cmd.s, "body") || !strcmp(cmd.s, "stat")) {
	    unsigned long uid = 0;
	    int part = 0, idx;

	    if (c == ' ') {
		c = getword(nntp_in, &arg1);
		if (c == EOF) goto missingargs;
		uid = parsenum(arg1.s);
	    }
	    if (c == '\r') c = prot_getc(nntp_in);
	    if (c != '\n') goto extraargs;
	    if (uid == -1) goto nomsgid;
	    else {
		if (!nntp_group) goto nogroup;
		if (uid) {
		    idx = index_finduid(uid);
		    if (index_getuid(idx) != uid) goto noarticle;
		    nntp_current = idx;
		} else {
		    uid = index_getuid(nntp_current);
		}
	    }

	    switch (cmd.s[0]) {
	    case 'a': part = ARTICLE_ALL;  break;
	    case 'h': part = ARTICLE_HEAD; break;
	    case 'b': part = ARTICLE_BODY; break;
	    case 's': part = ARTICLE_STAT; break;
	    }

	    cmd_article(uid, part);
	}
	else if (!strcmp(cmd.s, "post")) {
	    if (c == '\r') c = prot_getc(nntp_in);
	    if (c != '\n') goto extraargs;

	    cmd_post(NULL, POST_POST);
	}
	else if (!strcmp(cmd.s, "ihave") ||
		 !strcmp(cmd.s, "check") || !strcmp(cmd.s, "takethis")) {
	    int mode = 0;

	    if (c != ' ') goto missingargs;
	    c = getword(nntp_in, &arg1);
	    if (c == EOF) goto missingargs;
	    if (c == '\r') c = prot_getc(nntp_in);
	    if (c != '\n') goto extraargs;

	    switch (cmd.s[0]) {
	    case 'i': mode = POST_IHAVE;    break;
	    case 'c': mode = POST_CHECK;    break;
	    case 't': mode = POST_TAKETHIS; break;
	    }

	    cmd_post(arg1.s, mode);
	}
	else {
	    prot_printf(nntp_out, "500 Unrecognized command\r\n");
	    eatline(nntp_in, c);
	}

	continue;

      extraargs:
	prot_printf(nntp_out, "501 Unexpected extra argument\r\n");
	eatline(nntp_in, c);
	continue;

      missingargs:
	prot_printf(nntp_out, "501 Missing argument\r\n");
	eatline(nntp_in, c);
	continue;

      nogroup:
	prot_printf(nntp_out, "412 No newsgroup selected\r\n");
	eatline(nntp_in, c);
	continue;

      noarticle:
	prot_printf(nntp_out, "423 No such article in this newsgroup\r\n");
	eatline(nntp_in, c);
	continue;

      nomsgid:
	prot_printf(nntp_out, "430 No article found with that message-id\r\n");
	eatline(nntp_in, c);
	continue;
    }
}

#ifdef HAVE_SSL
static void cmd_starttls(int nntps)
{
    int result;
    int *layerp;
    sasl_ssf_t ssf;
    char *auth_id;

    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &ssf;

    if (nntp_starttls_done == 1)
    {
	prot_printf(nntp_out, "400 %s\r\n", 
		    "Already successfully executed STLS");
	return;
    }

    result=tls_init_serverengine("nntp",
				 5,        /* depth to verify */
				 !nntps,   /* can client auth? */
				 !nntps);  /* TLS only? */

    if (result == -1) {

	syslog(LOG_ERR, "[nntpd] error initializing TLS");

	if (nntps == 0)
	    prot_printf(nntp_out, "400 %s\r\n", "Error initializing TLS");
	else
	    fatal("tls_init() failed",EC_TEMPFAIL);

	return;
    }

    if (nntps == 0)
    {
	prot_printf(nntp_out, "300 %s\r\n", "Begin TLS negotiation now");
	/* must flush our buffers before starting tls */
	prot_flush(nntp_out);
    }
  
    result=tls_start_servertls(0, /* read */
			       1, /* write */
			       layerp,
			       &auth_id,
			       &tls_conn);

    /* if error */
    if (result==-1) {
	if (nntps == 0) {
	    prot_printf(nntp_out, "400 Starttls failed\r\n");
	    syslog(LOG_NOTICE, "[nntpd] STARTTLS failed: %s", nntp_clienthost);
	} else {
	    syslog(LOG_NOTICE, "nntps failed: %s", nntp_clienthost);
	    fatal("tls_start_servertls() failed", EC_TEMPFAIL);
	}
	return;
    }

    /* tell SASL about the negotiated layer */
    result = sasl_setprop(nntp_saslconn, SASL_SSF_EXTERNAL, &ssf);
    if (result != SASL_OK) {
	fatal("sasl_setprop() failed: cmd_starttls()", EC_TEMPFAIL);
    }
    saslprops.ssf = ssf;

    result = sasl_setprop(nntp_saslconn, SASL_AUTH_EXTERNAL, auth_id);
    if (result != SASL_OK) {
        fatal("sasl_setprop() failed: cmd_starttls()", EC_TEMPFAIL);
    }
    if(saslprops.authid) {
	free(saslprops.authid);
	saslprops.authid = NULL;
    }
    if(auth_id)
	saslprops.authid = xstrdup(auth_id);

    /* tell the prot layer about our new layers */
    prot_settls(nntp_in, tls_conn);
    prot_settls(nntp_out, tls_conn);

    nntp_starttls_done = 1;
}
#else
static void cmd_starttls(int nntps __attribute__((unused)))
{
    fatal("cmd_starttls() called, but no OpenSSL", EC_SOFTWARE);
}
#endif /* HAVE_SSL */


void cmd_user(char *user)
{
    int fd;
    struct protstream *shutdown_in;
    char buf[1024];
    char *p;
    char shutdownfilename[1024];

    /* possibly disallow USER */
    if (!(nntp_starttls_done || config_getswitch(IMAPOPT_ALLOWPLAINTEXT))) {
	prot_printf(nntp_out,
		    "503 AUTHINFO USER command only available under a layer\r\n");
	return;
    }

    if (nntp_userid) {
	prot_printf(nntp_out, "381 Must give AUTHINFO PASS command\r\n");
	return;
    }

    snprintf(shutdownfilename, sizeof(shutdownfilename),
	     "%s/msg/shutdown", config_dir);
    if ((fd = open(shutdownfilename, O_RDONLY, 0)) != -1) {
	shutdown_in = prot_new(fd, 0);
	prot_fgets(buf, sizeof(buf), shutdown_in);
	if ((p = strchr(buf, '\r'))!=NULL) *p = 0;
	if ((p = strchr(buf, '\n'))!=NULL) *p = 0;

	for(p = buf; *p == '['; p++); /* can't have [ be first char */
	prot_printf(nntp_out, "250 %s\r\n", p);
	prot_flush(nntp_out);
	shut_down(0);
    }
    else if (!(p = canonify_userid(user, NULL, NULL))) {
	prot_printf(nntp_out, "482 Invalid user\r\n");
	syslog(LOG_NOTICE,
	       "badlogin: %s plaintext %s invalid user",
	       nntp_clienthost, beautify_string(user));
    }
    else {
	nntp_userid = xstrdup(p);
	prot_printf(nntp_out, "381 Give AUTHINFO PASS command\r\n");
    }
}

void cmd_pass(char *pass)
{
    char *reply = 0;

    if (!nntp_userid) {
	prot_printf(nntp_out, "480 Must give AUTHINFO USER command\r\n");
	return;
    }

    if (!strcmp(nntp_userid, "anonymous")) {
	if (config_getswitch(IMAPOPT_ALLOWANONYMOUSLOGIN)) {
	    pass = beautify_string(pass);
	    if (strlen(pass) > 500) pass[500] = '\0';
	    syslog(LOG_NOTICE, "login: %s anonymous %s",
		   nntp_clienthost, pass);
	}
	else {
	    syslog(LOG_NOTICE, "badlogin: %s anonymous login refused",
		   nntp_clienthost);
	    prot_printf(nntp_out, "482 Invalid login\r\n");
	    return;
	}
    }
    else if (sasl_checkpass(nntp_saslconn,
			    nntp_userid,
			    strlen(nntp_userid),
			    pass,
			    strlen(pass))!=SASL_OK) { 
	if (reply) {
	    syslog(LOG_NOTICE, "badlogin: %s plaintext %s %s",
		   nntp_clienthost, nntp_userid, reply);
	}
	prot_printf(nntp_out, "482 Invalid login\r\n");
	free(nntp_userid);
	nntp_userid = 0;

	return;
    }
    else {
	syslog(LOG_NOTICE, "login: %s %s plaintext%s %s", nntp_clienthost,
	       nntp_userid, nntp_starttls_done ? "+TLS" : "", 
	       reply ? reply : "");

	prot_printf(nntp_out, "281 User logged in\r\n");

	nntp_authstate = auth_newstate(nntp_userid, NULL);

	/* Create telemetry log */
	telemetry_log(nntp_userid, nntp_in, nntp_out);
    }
}

void cmd_mode(char *arg)
{
    lcase(arg);

    if (!strcmp(arg, "reader")) {
	prot_printf(nntp_out, "200 Cyrus NNTP ready, posting allowed\r\n");
    }
    else if (!strcmp(arg, "stream")) {
	prot_printf(nntp_out, "203 Streaming is OK\r\n");
    }
    else {
	prot_printf(nntp_out, "500 Unrecognized MODE\r\n");
    }
    prot_flush(nntp_out);
}

/*
 * mboxlist_findall() callback function to LIST a newsgroup
 */
int do_list(char *name, int matchlen, int maycreate __attribute__((unused)),
	    void *rock)
{
    static char lastname[MAX_MAILBOX_PATH] = "";
    char *acl;
    int r, post;

    /* don't repeat */
    if (matchlen == strlen(lastname) &&
	!strncmp(name, lastname, matchlen)) return 0;

    strncpy(lastname, name, matchlen);
    lastname[matchlen] = '\0';

    nntp_group = open_group(name, 1);
    if (nntp_group) {
	/* look it up */
	r = mboxlist_detail(name, NULL, NULL, NULL, &acl, NULL);
	if (r) return r;
	/* see if we can post */
	post = acl && (cyrus_acl_myrights(nntp_authstate, acl) & ACL_POST);

	prot_printf(nntp_out, "%s %u %u %c\r\n", name+strlen(newsprefix),
		    nntp_exists ? index_getuid(1) : 1,
		    nntp_exists ? index_getuid(nntp_exists) : 0,
		    post ? 'y' : 'n');
    }

    return 0;
}

void cmd_list(char *arg1, char *arg2)
{
    if (!arg1)
	arg1 = "active";
    else
	lcase(arg1);

    if (!strcmp(arg1, "extensions")) {
	if (arg2) {
	    prot_printf(nntp_out, "501 Unexpected extra argument\r\n");
	    return;
	}

	prot_printf(nntp_out, "202 Extensions supported:\r\n");
	prot_printf(nntp_out, "AUTHINFO USER\r\n");
	prot_printf(nntp_out, "LISTGROUP\r\n");
	prot_printf(nntp_out, ".\r\n");
    }
    else if (!strcmp(arg1, "active")) {
	char pattern[MAX_MAILBOX_PATH];

	if (arg2) {
	    /* XXX do something with wildmat */
	}
	strcpy(pattern, newsprefix);
	strcat(pattern, "*");

	prot_printf(nntp_out, "215 list of newsgroups follows:\r\n");

	mboxlist_findall(NULL, pattern, 0, nntp_userid, nntp_authstate,
			 do_list, NULL);

	if (nntp_group) {
	    mailbox_close(nntp_group);
	    nntp_group = 0;
	}

	prot_printf(nntp_out, ".\r\n");
    }
    else {
	prot_printf(nntp_out, "500 Unrecognized LIST command\r\n");
    }
    prot_flush(nntp_out);
}

struct mailbox *open_group(char *name, int has_prefix)
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r = 0;
    int doclose = 0;

    if (nntp_group) {
	mailbox_close(nntp_group);
	nntp_group = 0;
    }

    if (!has_prefix) {
	snprintf(mailboxname, sizeof(mailboxname), "%s%s", newsprefix, name);
	name = mailboxname;
    }

    if (!r) {
	r = mailbox_open_header(name, nntp_authstate, &mboxstruct);
    }

    if (!r) {
	doclose = 1;
	r = mailbox_open_index(&mboxstruct);
    }
    if (!r && !(mboxstruct.myrights & ACL_READ)) {
	r = (mboxstruct.myrights & ACL_LOOKUP) ?
	    IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
    }
    if (!r && chdir(mboxstruct.path)) {
	syslog(LOG_ERR,
	       "IOERROR: changing directory to %s: %m", mboxstruct.path);
	r = IMAP_IOERROR;
    }
    if (!r) {
	nntp_exists = mboxstruct.exists;
	nntp_current = 1;
	index_operatemailbox(&mboxstruct);
    }

    if (r) {
	prot_printf(nntp_out, "411 %s\r\n", error_message(r));
	if (doclose) mailbox_close(&mboxstruct);
	return NULL;
    }

    syslog(LOG_DEBUG, "open: user %s opened %s", nntp_userid, name);

    return &mboxstruct;
}

static void cmd_article(unsigned long uid, int part)
{
    FILE *msgfile;
    char buf[4096];
    char fnamebuf[MAILBOX_FNAME_LEN];

    mailbox_message_get_fname(nntp_group, uid, fnamebuf);
    msgfile = fopen(fnamebuf, "r");
    if (!msgfile) {
	prot_printf(nntp_out, "502 Could not read message file\r\n");
	return;
    }
    prot_printf(nntp_out, "%u %lu %s\r\n", 220 + part, uid, "<0>");

    if (part != ARTICLE_STAT) {
	while (fgets(buf, sizeof(buf), msgfile)) {

	    if (part != ARTICLE_ALL && buf[0] == '\r' && buf[1] == '\n') {
		/* blank line between header and body */
		if (part == ARTICLE_HEAD) {
		    /* we're done */
		    break;
		}
		else if (part == ARTICLE_BODY) {
		    /* start outputing text */
		    part = ARTICLE_ALL;
		    continue;
		}
	    }

	    if (part != ARTICLE_BODY) {
		if (buf[0] == '.') prot_putc('.', nntp_out);
		do {
		    prot_printf(nntp_out, "%s", buf);
		} while (buf[strlen(buf)-1] != '\n' &&
			 fgets(buf, sizeof(buf), msgfile));
	    }
	}

	/* Protect against messages not ending in CRLF */
	if (buf[strlen(buf)-1] != '\n') prot_printf(nntp_out, "\r\n");

	prot_printf(nntp_out, ".\r\n");
    }

    fclose(msgfile);
}

static int parsenum(char *ptr)
{
    char *p = ptr;
    int result = 0;

    while (*p && isdigit((int) *p)) {
	result = result * 10 + *p++ - '0';
    }

    return (*p ? -1 : result);
}

/* ----- this section defines functions on message_data_t.
   ----- access functions and the like, etc. */

#define HEADERCACHESIZE 4009
#define RCPT_GROW 30

typedef struct message_data message_data_t;
typedef struct Header header_t;

/* data per message */
struct Header {
    char *name;
    int ncontents;
    char *contents[1];
};

struct message_data {
    struct protstream *data;	/* message in temp file */
    FILE *f;			/* FILE * corresponding */

    char *id;			/* message id */
    int size;			/* size of message */

    char **rcpt;		/* mailboxes to post message */
    int rcpt_num;		/* number of groups */

    header_t *cache[HEADERCACHESIZE];
};

/* returns non-zero on failure */
int msg_new(message_data_t **m)
{
    message_data_t *ret = (message_data_t *) xmalloc(sizeof(message_data_t));
    int i;

    ret->data = NULL;
    ret->f = NULL;
    ret->id = NULL;
    ret->size = 0;
    ret->rcpt = NULL;
    ret->rcpt_num = 0;

    for (i = 0; i < HEADERCACHESIZE; i++)
	ret->cache[i] = NULL;

    *m = ret;
    return 0;
}

void msg_free(message_data_t *m)
{
    int i;

    if (m->data) {
	prot_free(m->data);
    }
    if (m->f) {
	fclose(m->f);
    }
    if (m->id) {
	free(m->id);
    }

    if (m->rcpt) {
	for (i = 0; i < m->rcpt_num; i++) {
	    free(m->rcpt[i]);
	}
	free(m->rcpt);
    }

    for (i = 0; i < HEADERCACHESIZE; i++) {
	if (m->cache[i]) {
	    int j;

	    free(m->cache[i]->name);
	    for (j = 0; j < m->cache[i]->ncontents; j++) {
		free(m->cache[i]->contents[j]);
	    }

	    free(m->cache[i]);
	}
    }

    free(m);
}

/* hash function used for header cache in struct msg */
static int hashheader(char *header)
{
    int x = 0;
    /* any CHAR except ' ', :, or a ctrl char */
    for (; !iscntrl((int) *header) && (*header != ' ') && (*header != ':'); 
	 header++) {
	x *= 256;
	x += *header;
	x %= HEADERCACHESIZE;
    }
    return x;
}

const char **msg_getheader(message_data_t *m, const char *phead)
{
    char *head;
    const char **ret = NULL;
    int clinit, cl;

    assert(m && phead);

    head = xstrdup(phead);
    lcase(head);

    /* check the cache */
    clinit = cl = hashheader(head);
    while (m->cache[cl] != NULL) {
	if (!strcmp(head, m->cache[cl]->name)) {
	    ret = (const char **) m->cache[cl]->contents;
	    break;
	}
	cl++; /* try next hash bin */
	cl %= HEADERCACHESIZE;
	if (cl == clinit) break; /* gone all the way around */
    }

    free(head);

    return ret;
}

/* copies the message from fin to fout, massaging accordingly: 
   . newlines are fiddled to \r\n
   . "." terminates 
   . embedded NULs are rejected
   . bare \r are removed
*/
static int copy_msg(struct protstream *fin, FILE *fout)
{
    char buf[8192], *p;
    int r = 0;

    while (prot_fgets(buf, sizeof(buf)-1, fin)) {
	p = buf + strlen(buf) - 1;
	if (p < buf) {
	    /* buffer start with a \0 */
	    r = IMAP_MESSAGE_CONTAINSNULL;
	    continue; /* need to eat the rest of the message */
	}
	else if (buf[0] == '\r' && buf[1] == '\0') {
	    /* The message contained \r\0, and fgets is confusing us. */
	    r = IMAP_MESSAGE_CONTAINSNULL;
	    continue; /* need to eat the rest of the message */
	}
	else if (p[0] == '\r') {
	    /*
	     * We were unlucky enough to get a CR just before we ran
	     * out of buffer--put it back.
	     */
	    prot_ungetc('\r', fin);
	    *p = '\0';
	}
	else if (p[0] == '\n' && p[-1] != '\r') {
	    /* found an \n without a \r */
	    p[0] = '\r';
	    p[1] = '\n';
	    p[2] = '\0';
	}
	else if (p[0] != '\n') {
	    /* line contained a \0 not at the end */
	    r = IMAP_MESSAGE_CONTAINSNULL;
	    continue;
	}

	/* Remove any lone CR characters */
	while ((p = strchr(buf, '\r')) && p[1] != '\n') {
	    strcpy(p, p+1);
	}
	
	if (buf[0] == '.') {
	    if (buf[1] == '\r' && buf[2] == '\n') {
		/* End of message */
		goto nntpdot;
	    }
	    /* Remove the dot-stuffing */
	    if (fout) fputs(buf+1, fout);
	} else {
	    if (fout) fputs(buf, fout);
	}
    }

    /* wow, serious error---got a premature EOF. */
    return IMAP_IOERROR;

 nntpdot:
    return r;
}

/* take a list of headers, pull the first one out and return it in
   name and contents.

   copies fin to fout, massaging 

   returns 0 on success, negative on failure */
typedef enum {
    NAME_START,
    NAME,
    COLON,
    BODY_START,
    BODY
} state;

enum {
    NAMEINC = 128,
    BODYINC = 1024
};

/* we don't have to worry about dotstuffing here, since it's illegal
   for a header to begin with a dot!

   returns 0 on success, filling in 'headname' and 'contents' with a static
   pointer (blech).
   on end of headers, returns 0 with NULL 'headname' and NULL 'contents'

   on error, returns < 0
*/
static int parseheader(struct protstream *fin, FILE *fout, 
		       char **headname, char **contents) {
    int c;
    static char *name = NULL, *body = NULL;
    static int namelen = 0, bodylen = 0;
    int off = 0;
    state s = NAME_START;
    int r = 0;
    int reject8bit = config_getswitch(IMAPOPT_REJECT8BIT);

    if (namelen == 0) {
	namelen += NAMEINC;
	name = (char *) xrealloc(name, namelen * sizeof(char));
    }
    if (bodylen == 0) {
	bodylen += BODYINC;
	body = (char *) xrealloc(body, bodylen * sizeof(char));
    }

    /* there are two ways out of this loop, both via gotos:
       either we successfully read a header (got_header)
       or we hit an error (ph_error) */
    while ((c = prot_getc(fin)) != EOF) { /* examine each character */
	switch (s) {
	case NAME_START:
	    if (c == '.') {
		int peek;

		peek = prot_getc(fin);
		prot_ungetc(peek, fin);
		
		if (peek == '\r' || peek == '\n') {
		    /* just reached the end of message */
		    r = IMAP_MESSAGE_NOBLANKLINE;
		    goto ph_error;
		}
	    }
	    if (c == '\r' || c == '\n') {
		/* just reached the end of headers */
		r = 0;
		goto ph_error;
	    }
	    /* field-name      =       1*ftext
	       ftext           =       %d33-57 / %d59-126         
	                               ; Any character except
				       ;  controls, SP, and
				       ;  ":". */
	    if (!((c >= 33 && c <= 57) || (c >= 59 && c <= 126))) {
		/* invalid header name */
		r = IMAP_MESSAGE_BADHEADER;
		goto ph_error;
	    }
	    name[0] = tolower(c);
	    off = 1;
	    s = NAME;
	    break;

	case NAME:
	    if (c == ' ' || c == '\t' || c == ':') {
		name[off] = '\0';
		s = (c == ':' ? BODY_START : COLON);
		break;
	    }
	    if (!((c >= 33 && c <= 57) || (c >= 59 && c <= 126))) {
		r = IMAP_MESSAGE_BADHEADER;
		goto ph_error;
	    }
	    name[off++] = tolower(c);
	    if (off >= namelen - 3) {
		namelen += NAMEINC;
		name = (char *) xrealloc(name, namelen);
	    }
	    break;
	
	case COLON:
	    if (c == ':') {
		s = BODY_START;
	    } else if (c != ' ' && c != '\t') {
		/* i want to avoid confusing dot-stuffing later */
		while (c == '.') {
		    fputc(c, fout);
		    c = prot_getc(fin);
		}
		r = IMAP_MESSAGE_BADHEADER;
		goto ph_error;
	    }
	    break;

	case BODY_START:
	    if (c == ' ' || c == '\t') /* eat the whitespace */
		break;
	    off = 0;
	    s = BODY;
	    if (!strcasecmp(name, "path")) {
		/* prepend servername to Path: header */
		sprintf(body, "%s!", config_servername);
		off += strlen(body);
		fputs(body, fout);
	    }
	    /* falls through! */
	case BODY:
	    /* now we want to convert all newlines into \r\n */
	    if (c == '\r' || c == '\n') {
		int peek;

		peek = prot_getc(fin);
		
		fputc('\r', fout);
		fputc('\n', fout);
		/* we should peek ahead to see if it's folded whitespace */
		if (c == '\r' && peek == '\n') {
		    c = prot_getc(fin);
		} else {
		    c = peek; /* single newline seperator */
		}
		if (c != ' ' && c != '\t') {
		    /* this is the end of the header */
		    body[off] = '\0';
		    prot_ungetc(c, fin);
		    goto got_header;
		}
		/* ignore this whitespace, but we'll copy all the rest in */
		break;
	    } else {
		if (c >= 0x80) {
		    if (reject8bit) {
			/* We have been configured to reject all mail of this
			   form. */
			r = IMAP_MESSAGE_CONTAINS8BIT;
			goto ph_error;
		    } else {
			/* We have been configured to munge all mail of this
			   form. */
			c = 'X';
		    }
		}
		/* just an ordinary character */
		body[off++] = c;
		if (off >= bodylen - 3) {
		    bodylen += BODYINC;
		    body = (char *) xrealloc(body, bodylen);
		}
	    }
	}

	/* copy this to the output */
	fputc(c, fout);
    }

    /* if we fall off the end of the loop, we hit some sort of error
       condition */

 ph_error:
    /* put the last character back; we'll copy it later */
    prot_ungetc(c, fin);

    /* and we didn't get a header */
    if (headname != NULL) *headname = NULL;
    if (contents != NULL) *contents = NULL;
    return r;

 got_header:
    if (headname != NULL) *headname = xstrdup(name);
    if (contents != NULL) *contents = xstrdup(body);

    return 0;
}

static int fill_cache(struct protstream *fin, FILE *fout, message_data_t *m)
{
    int r = 0;

    /* let's fill that header cache */
    for (;;) {
	char *name, *body;
	int cl, clinit;

	if ((r = parseheader(fin, fout, &name, &body)) < 0) {
	    break;
	}
	if (!name) {
	    /* reached the end of headers */
	    break;
	}

	/* put it in the hash table */
	clinit = cl = hashheader(name);
	while (m->cache[cl] != NULL && strcmp(name, m->cache[cl]->name)) {
	    cl++;		/* resolve collisions linearly */
	    cl %= HEADERCACHESIZE;
	    if (cl == clinit) break; /* gone all the way around, so bail */
	}

	/* found where to put it, so insert it into a list */
	if (m->cache[cl]) {
	    /* add this body on */
	    m->cache[cl]->contents[m->cache[cl]->ncontents++] = body;

	    /* whoops, won't have room for the null at the end! */
	    if (!(m->cache[cl]->ncontents % 8)) {
		/* increase the size */
		m->cache[cl] = (header_t *)
		    xrealloc(m->cache[cl],sizeof(header_t) +
			     ((8 + m->cache[cl]->ncontents) * sizeof(char *)));
	    }

	    /* have no need of this */
	    free(name);
	} else {
	    /* create a new entry in the hash table */
	    m->cache[cl] = (header_t *) xmalloc(sizeof(header_t) + 
						8 * sizeof(char*));
	    m->cache[cl]->name = name;
	    m->cache[cl]->contents[0] = body;
	    m->cache[cl]->ncontents = 1;
	}

	/* we always want a NULL at the end */
	m->cache[cl]->contents[m->cache[cl]->ncontents] = NULL;
    }

    return r;
}

static int parse_groups(const char *groups, message_data_t *msg)
{
    const char *p = groups;
    char *rcpt;
    size_t n;

    for (;;) {
	while (p && *p && (isspace((int) *p) || *p == ',')) p++;

	if (!p || !*p) return 0;

	if (!(msg->rcpt_num % RCPT_GROW)) { /* time to alloc more */
	    msg->rcpt = (char **)
		xrealloc(msg->rcpt, (msg->rcpt_num + RCPT_GROW + 1) * 
			 sizeof(char *));
	}

	n = strcspn(p, ", \t");
	rcpt = xmalloc(strlen(newsprefix) + n + 1);
	if (!rcpt) return -1;

	sprintf(rcpt, "%s%.*s", newsprefix, n, p);
	
	msg->rcpt[msg->rcpt_num] = rcpt;
	msg->rcpt_num++;
	msg->rcpt[msg->rcpt_num] = NULL;

	p += n;
    }

    return NNTP_FAIL_NEWSGROUPS;
}

/*
 * file in the message structure 'm' from 'pin', assuming a dot-stuffed
 * stream a la nntp.
 *
 * returns 0 on success, imap error code on failure
 */
static int savemsg(message_data_t *m, FILE *f)
{
    struct stat sbuf;
    const char **body;
    int r;

    /* fill the cache */
    r = fill_cache(nntp_in, f, m);
    if (r) {
	/* got a bad header */

	/* flush the remaining output */
	copy_msg(nntp_in, f);
	return r;
    }

    /* now, using our header cache, fill in the data that we want */

    /* XXX check for control messages */

    /* get message-id */
    if ((body = msg_getheader(m, "message-id")) != NULL) {
	m->id = xstrdup(body[0]);
    } else {
	m->id = NULL;	/* no message-id */
    }

    /* add Path: header (if necessary) */
    if ((body = msg_getheader(m, "path")) == NULL) {
	fprintf(f, "Path: %s!%s\r\n",
		config_servername, nntp_userid ? nntp_userid : "anonymous");
    }

    /* get newsgroups */
    if ((body = msg_getheader(m, "newsgroups")) != NULL) {
	/* parse newsgroups */
	if ((r = parse_groups(body[0], m)) == 0) {
	    char buf[1024] = "";
	    const char *sep = "";
	    int n;

	    for (n = 0; n < m->rcpt_num; n++) {
		snprintf(buf+strlen(buf), sizeof(buf)-strlen(buf), "%s%s+%s",
			 sep, /* XXX make this an option */ "post",
			 m->rcpt[n]);
		sep = ", ";
	    }

	    /* add To: header */
	    fprintf(f, "To: %s\r\n", buf);
	}
    } else {
	r = NNTP_NO_NEWSGROUPS;		/* no newsgroups */
    }

    r |= copy_msg(nntp_in, f);

    if (r) return r;

    fflush(f);
    if (ferror(f)) {
	return IMAP_IOERROR;
    }

    if (fstat(fileno(f), &sbuf) == -1) {
	return IMAP_IOERROR;
    }
    m->size = sbuf.st_size;
    m->f = f;
    m->data = prot_new(fileno(f), 0);

    return 0;
}

static int deliver(message_data_t *msg)
{
    int n, r;
    char *rcpt;
    struct appendstate as;
    time_t now = time(NULL);
    unsigned long uid;

    for (n = 0; n < msg->rcpt_num; n++) {
	rcpt = msg->rcpt[n];

	if (dupelim && msg->id && 
	    duplicate_check(msg->id, strlen(msg->id), rcpt, strlen(rcpt))) {
	    /* duplicate message */
	    duplicate_log(msg->id, rcpt);
	    continue;
	}

	r = append_setup(&as, rcpt, MAILBOX_FORMAT_NORMAL,
			 nntp_userid, nntp_authstate, ACL_POST, 0);

	if (!r) {
	    prot_rewind(msg->data);
	    r = append_fromstream(&as, msg->data, msg->size, now,
				  (const char **) NULL, 0);
	    if (!r) append_commit(&as, NULL, &uid, NULL);
	    else append_abort(&as);
	}

	if (!r && dupelim && msg->id)
	    duplicate_mark(msg->id, strlen(msg->id), rcpt, strlen(rcpt), now);

	if (r) return r;
    }

    /* mark msgid for IHAVE/CHECK/TAKETHIS and reader commands
     *
     * XXX this should be replaced with netnews.db having the form:
     *
     * key = <msgid>   data = <mbox>:<uid>\t<lines>\t<time>\0
     */
    if (dupelim && msg->id)
	duplicate_mark(msg->id, strlen(msg->id), "", 0, time(NULL));

    return  0;
}

static void cmd_post(char *msgid, int mode)
{
    FILE *f = NULL;
    message_data_t *msg;
    int r = 0;

    /* check if we want this article
     *
     * XXX this should be replaced with netnews.db (see above)
     */
    if (dupelim && msgid && 
	duplicate_check(msgid, strlen(msgid), "", 0)) {
	/* duplicate message */
	r = NNTP_DONT_SEND;
    }

    if (mode != POST_TAKETHIS) {
	if (r) {
	    prot_printf(nntp_out, "%u Do not send article %s\r\n",
			post_codes[mode].no, msgid ? msgid : "");
	    return;
	}
	else {
	    prot_printf(nntp_out, "%u Send article %s\r\n",
			post_codes[mode].cont, msgid ? msgid : "");
	    if (mode == POST_CHECK) return;
	}
    }

    /* get a spool file if needed */
    if (!r) {
	f = tmpfile();
	if (!f) r = IMAP_IOERROR;
    }

    if (f) {
	/* spool the article */
	msg_new(&msg);

	r = savemsg(msg, f);

	/* deliver the article */
	if (!r) r = deliver(msg);

	if (!r) {
	    if (mode == POST_POST) {
		/* XXX send the article upstream */
	    }

	    prot_printf(nntp_out, "%u Article %s received ok\r\n",
			post_codes[mode].ok, msg->id ? msg->id : "");
	}

	msg_free(msg); /* does fclose() */
    }
    else {
	/* flush the article from the stream */
	copy_msg(nntp_in, NULL);
    }

    if (r) {
	prot_printf(nntp_out, "%u Failed receiving article %s (%s)\r\n",
		    post_codes[mode].fail, msgid ? msgid : "",
		    error_message(r));
    }

    prot_flush(nntp_out);
}
