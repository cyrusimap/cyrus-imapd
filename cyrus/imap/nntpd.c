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
 *
 * $Id: nntpd.c,v 1.1.2.47 2002/12/17 16:35:08 ken3 Exp $
 */

/*
 * TODO:
 *
 * - remove Xref header from articles
 */


#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <errno.h>
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

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "acl.h"
#include "append.h"
#include "auth.h"
#include "duplicate.h"
#include "exitcodes.h"
#include "imapconf.h"
#include "imap_err.h"
#include "index.h"
#include "iptostring.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "mkgmtime.h"
#include "netnews.h"
#include "nntp_err.h"
#include "prot.h"
#include "rfc822date.h"
#include "spool.h"
#include "telemetry.h"
#include "tls.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"

extern int optind;
extern char *optarg;
extern int opterr;

/* Stuff to make index.c link */
int imapd_exists;
struct protstream *imapd_out = NULL;
struct auth_state *imapd_authstate = NULL;
static int nntp_logfd = -1;
char *imapd_userid = NULL;
void printastring(const char *s)
{
    fatal("not implemented", EC_SOFTWARE);
}
/* end stuff to make index.c link */


#ifdef HAVE_SSL
static SSL *tls_conn;
#endif /* HAVE_SSL */

sasl_conn_t *nntp_saslconn; /* the sasl connection context */

static int have_newsdb = 1;	/* news db is initialized */
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
unsigned did_extensions = 0;
int config_allowanonymous;

static int nntps = 0;
int nntp_starttls_done = 0;

static struct mailbox mboxstruct;

/* the sasl proxy policy context */
static struct proxy_context nntp_proxyctx = {
    0, 1, NULL, NULL, NULL
};

/* for config.c */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

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

static void cmdloop(void);
static int open_group();
static int parserange(char *str, unsigned long *uid, unsigned long *last,
		      char **msgid);
static time_t parse_datetime(char *datestr, char *timestr, char *gmt);
static void cmd_article();
static void cmd_authinfo_user();
static void cmd_authinfo_pass();
static void cmd_authinfo_sasl();
static void cmd_hdr();
static void cmd_help();
static void cmd_list();
static void cmd_mode();
static int do_newnews(char *msgid, char *mailbox, unsigned long uid,
		      unsigned long lines, time_t tstamp, void *rock);
static void cmd_over();
static void cmd_post();
static void cmd_starttls();
void usage(void);
void shut_down(int code) __attribute__ ((noreturn));


extern void setproctitle_init(int argc, char **argv, char **envp);
extern int proc_register(const char *progname, const char *clienthost, 
			 const char *userid, const char *mailbox);
extern void proc_cleanup(void);

extern int saslserver(sasl_conn_t *conn, const char *mech,
		      const char *init_resp, const char *continuation,
		      struct protstream *pin, struct protstream *pout,
		      int *sasl_result, char **success_data);

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

    /* initialize news database */
    if (netnews_init(NULL, 0) != 0) {
	syslog(LOG_ERR, "nntpd: unable to init news database\n");
	have_newsdb = 0;
    }

    dupelim = config_getswitch(IMAPOPT_DUPLICATESUPPRESSION);
    /* initialize duplicate delivery database */
    if (duplicate_init(NULL, 0) != 0) {
	syslog(LOG_ERR, 
	       "nntpd: unable to init duplicate delivery database\n");
	dupelim = 0;
    }

    /* open the mboxlist, we'll need it for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);

    while ((opt = getopt(argc, argv, "s")) != EOF) {
	switch(opt) {
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
    if (sasl_server_new("news", config_servername, NULL, NULL, NULL,
			NULL, SASL_SUCCESS_DATA, &nntp_saslconn) != SASL_OK)
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

    netnews_done();
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

    cyrus_done();

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

/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(sasl_conn_t **conn) 
{
    int ret;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("nntp", config_servername,
                         NULL, NULL, NULL,
                         NULL, SASL_SUCCESS_DATA, conn);
    if(ret != SASL_OK) return ret;

    if(saslprops.ipremoteport)
       ret = sasl_setprop(*conn, SASL_IPREMOTEPORT,
                          saslprops.ipremoteport);
    if(ret != SASL_OK) return ret;
    
    if(saslprops.iplocalport)
       ret = sasl_setprop(*conn, SASL_IPLOCALPORT,
                          saslprops.iplocalport);
    if(ret != SASL_OK) return ret;
    secprops = mysasl_secprops(SASL_SEC_NOPLAINTEXT);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if(saslprops.ssf) {
       ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &saslprops.ssf);
    }

    if(ret != SASL_OK) return ret;

    if(saslprops.authid) {
       ret = sasl_setprop(*conn, SASL_AUTH_EXTERNAL, saslprops.authid);
       if(ret != SASL_OK) return ret;
    }
    /* End TLS/SSL Info */

    return SASL_OK;
}

/*
 * Top-level command loop parsing
 */
static void cmdloop(void)
{
    int c, r = 0, mode;
    static struct buf cmd, arg1, arg2, arg3, arg4;
    char *p;
    const char *err;
    unsigned long uid;

    config_allowanonymous = config_getswitch(IMAPOPT_ALLOWANONYMOUSLOGIN);

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
	    prot_printf(nntp_out, "501 Empty command\r\n");
	    eatline(nntp_in, c);
	    continue;
	}
	if (islower((unsigned char) cmd.s[0])) 
	    cmd.s[0] = toupper((unsigned char) cmd.s[0]);
	for (p = &cmd.s[1]; *p; p++) {
	    if (isupper((unsigned char) *p)) *p = tolower((unsigned char) *p);
	}

	/* Only Authinfo/Check/Head/Help/Ihave/List [ Active | Extensions ]/
	   Mode/Quit/Stat/Starttls/Takethis allowed when not logged in */
	if (!nntp_userid && !config_allowanonymous &&
	    !strchr("ACHILMQST", cmd.s[0])) goto nologin;
    
	switch (cmd.s[0]) {
	case 'A':
	    if (!strcmp(cmd.s, "Authinfo")) {
		arg3.len = 0;
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg1);
		if (c == EOF) goto missingargs;
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg2);
		if (c == EOF) goto missingargs;

		lcase(arg1.s);
		if (!strcmp(arg1.s, "sasl") && c == ' ') {
		    c = getword(nntp_in, &arg3);
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		if (!strcmp(arg1.s, "user"))
		    cmd_authinfo_user(arg2.s);
		else if (!strcmp(arg1.s, "pass"))
		    cmd_authinfo_pass(arg2.s);
		else if (!strcmp(arg1.s, "sasl"))
		    cmd_authinfo_sasl(arg2.s, arg3.len ? arg3.s : NULL);
		else
		    prot_printf(nntp_out, "500 Unrecognized command\r\n");
	    }
	    else if (!nntp_userid && !config_allowanonymous) goto nologin;
	    else if (!strcmp(cmd.s, "Article")) {
		char *msgid;

		mode = ARTICLE_ALL;

	      article:
		msgid = NULL;
		if (arg1.s) *arg1.s = 0;

		if (c == ' ') {
		    c = getword(nntp_in, &arg1);
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		if (parserange(arg1.s, &uid, NULL, &msgid) == -1) {
		    if (!nntp_group) goto noopengroup;
		    if (!nntp_current) goto nocurrent;
		    goto noarticle;
		}

		cmd_article(mode, msgid, uid);
	    }
	    else goto badcmd;
	    break;

	case 'B':
	    if (!strcmp(cmd.s, "Body")) {
		mode = ARTICLE_BODY;
		goto article;
	    }
	    else goto badcmd;
	    break;

	case 'C':
	    if (!strcmp(cmd.s, "Check")) {
		mode = POST_CHECK;
		goto ihave;
	    }
	    else goto badcmd;
	    break;

	case 'D':
	    if (!strcmp(cmd.s, "Date")) {
		time_t now = time(NULL);
		struct tm *my_tm = gmtime(&now);
		char buf[15];

		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", my_tm);
		prot_printf(nntp_out, "111 %s\r\n", buf);
	    }
	    else goto badcmd;
	    break;

	case 'G':
	    if (!strcmp(cmd.s, "Group")) {
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		r = open_group(arg1.s, 0);
		if (r) goto nogroup;
		else {
		    nntp_exists = nntp_group->exists;
		    if (nntp_exists) nntp_current = 1;

		    prot_printf(nntp_out, "211 %u %u %u %s\r\n",
				nntp_exists, nntp_exists ? index_getuid(1) : 1,
				nntp_exists ? index_getuid(nntp_exists) : 0,
				arg1.s);
		}
	    }
	    else goto badcmd;
	    break;

	case 'H':
	    if (!strcmp(cmd.s, "Head")) {
		mode = ARTICLE_HEAD;
		goto article;
	    }
	    else if (!strcmp(cmd.s, "Help")) {
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		cmd_help();
	    }
	    else if (!nntp_userid && !config_allowanonymous) goto nologin;
	    else if (!strcmp(cmd.s, "Hdr")) {
		unsigned long last;
		char *msgid;

	      hdr:
		msgid = NULL;
		if (arg2.s) *arg2.s = 0;

		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg1);
		if (c == EOF) goto missingargs;
		if (c == ' ') {
		    c = getword(nntp_in, &arg2);
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		if (parserange(arg2.s, &uid, &last, &msgid) == -1) {
		    if (!nntp_group) goto noopengroup;
		    if (!nntp_current) goto nocurrent;
		    goto noarticle;
		}

		cmd_hdr(cmd.s, arg1.s, msgid, uid, last);
	    }
	    else goto badcmd;
	    break;

	case 'I':
	    if (!strcmp(cmd.s, "Ihave")) {
		mode = POST_IHAVE;

	      ihave:
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		cmd_post(arg1.s, mode);
	    }
	    else goto badcmd;
	    break;

	case 'L':
	    if (!strcmp(cmd.s, "List")) {
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
	    else if (!nntp_userid && !config_allowanonymous) goto nologin;
	    else if (!strcmp(cmd.s, "Last")) {
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;
		if (!nntp_group) goto noopengroup;
		if (nntp_current == 1) {
		    prot_printf(nntp_out,
				"422 No previous article in this group\r\n");
		} else {
		    char *msgid = index_get_msgid(nntp_group, --nntp_current);

		    prot_printf(nntp_out, "223 %u %s\r\n",
				index_getuid(nntp_current),
				msgid ? msgid : "<0>");

		    if (msgid) free(msgid);
		}
	    }
	    else if (!strcmp(cmd.s, "Listgroup")) {
		arg1.len = 0;

		if (c == ' ') {
		    c = getword(nntp_in, &arg1);
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		if (arg1.len) {
		    r = open_group(arg1.s, 0);
		    if (r) goto nogroup;

		    nntp_exists = nntp_group->exists;
		    if (nntp_exists) nntp_current = 1;
		}
		if (!nntp_group) goto noopengroup;
		else {
		    int i;
		    prot_printf(nntp_out, "211 list of articles follows\r\n");
		    for (i = 1; i <= nntp_exists; i++)
			prot_printf(nntp_out, "%u\r\n", index_getuid(i));
		    prot_printf(nntp_out, ".\r\n");
		}
	    }
	    else goto badcmd;
	    break;

	case 'M':
	    if (!strcmp(cmd.s, "Mode")) {
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		cmd_mode(arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'N':
	    if (!strcmp(cmd.s, "Newgroups")) {
		goto cmdnotimpl;
	    }
	    else if (!strcmp(cmd.s, "Newnews")) {
		time_t tstamp;
		struct wildmat *wild;

		if (!config_getswitch(IMAPOPT_ALLOWNEWNEWS))
		    goto cmddisabled;

		arg4.len = 0;
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg1);
		if (c == EOF) goto missingargs;
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg2);
		if (c == EOF) goto missingargs;
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg3);
		if (c == EOF) goto missingargs;
		if (c == ' ') {
		    c = getword(nntp_in, &arg4);
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		if ((tstamp = parse_datetime(arg2.s, arg3.s,
					     arg4.len ? arg4.s : NULL)) < 0)
		    goto baddatetime;

		wild = split_wildmats(arg1.s);

		prot_printf(nntp_out, "230 List of new articles follows\r\n");

		netnews_findall(wild, tstamp, 1, do_newnews, NULL);

		prot_printf(nntp_out, ".\r\n");

		free_wildmats(wild);
	    }
	    else if (!strcmp(cmd.s, "Next")) {
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;
		if (!nntp_group) goto noopengroup;
		if (nntp_current == nntp_exists) {
		    prot_printf(nntp_out,
				"421 No next article in this group\r\n");
		} else {
		    char *msgid = index_get_msgid(nntp_group, ++nntp_current);

		    prot_printf(nntp_out, "223 %u %s\r\n",
				index_getuid(nntp_current),
				msgid ? msgid : "<0>");

		    if (msgid) free(msgid);
		}
	    }
	    else goto badcmd;
	    break;

	case 'O':
	    if (!strcmp(cmd.s, "Over")) {
		unsigned long last;

	      over:
		if (arg1.s) *arg1.s = 0;

		if (c == ' ') {
		    c = getword(nntp_in, &arg1);
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		if (parserange(arg1.s, &uid, &last, NULL) == -1) {
		    if (!nntp_group) goto noopengroup;
		    if (!nntp_current) goto nocurrent;
		    goto noarticle;
		}

		cmd_over(uid, last);
	    }
	    else goto badcmd;
	    break;

	case 'P':
	    if (!strcmp(cmd.s, "Post")) {
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		cmd_post(NULL, POST_POST);
	    }
	    else goto badcmd;
	    break;

	case 'Q':
	    if (!strcmp(cmd.s, "Quit")) {
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		prot_printf(nntp_out, "205 Bye\r\n");
		return;
	    }
	    else goto badcmd;
	    break;

	case 'S':
	    if (!strcmp(cmd.s, "Starttls") && tls_enabled()) {
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		cmd_starttls(0);
	    }
	    else if (!strcmp(cmd.s, "Stat")) {
		mode = ARTICLE_STAT;
		goto article;
	    }
	    else if (!nntp_userid && !config_allowanonymous) goto nologin;
	    else if (!strcmp(cmd.s, "Slave")) {	
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		prot_printf(nntp_out, "202 Slave status noted\r\n");
	    }
	    else goto badcmd;
	    break;

	case 'T':
	    if (!strcmp(cmd.s, "Takethis")) {
		mode = POST_TAKETHIS;
		goto ihave;
	    }
	    else goto badcmd;
	    break;

	case 'X':
	    if (!strcmp(cmd.s, "Xhdr")) {
		goto hdr;
	    }
	    else if (!strcmp(cmd.s, "Xover")) {
		goto over;
	    }
	    else goto badcmd;
	    break;

	default:
	  badcmd:
	    prot_printf(nntp_out, "500 Unrecognized command\r\n");
	    eatline(nntp_in, c);
	}

	continue;

      nologin:
	prot_printf(nntp_out, "%u Authentication required\r\n",
		    did_extensions ? 450 : 480);
	eatline(nntp_in, c);
	continue;

      cmdnotimpl:
	prot_printf(nntp_out, "503 \"%s\" not yet implemented\r\n", cmd.s);
	eatline(nntp_in, c);
	continue;

      cmddisabled:
	prot_printf(nntp_out, "500 \"%s\" disabled\r\n", cmd.s);
	eatline(nntp_in, c);
	continue;

      extraargs:
	prot_printf(nntp_out, "501 Unexpected extra argument\r\n");
	eatline(nntp_in, c);
	continue;

      missingargs:
	prot_printf(nntp_out, "501 Missing argument\r\n");
	eatline(nntp_in, c);
	continue;

      baddatetime:
	prot_printf(nntp_out, "501 Bad date/time\r\n");
	continue;

      nogroup:
	prot_printf(nntp_out, "411 No such newsgroup (%s)\r\n",
		    error_message(r));
	continue;

      noopengroup:
	prot_printf(nntp_out, "412 No newsgroup selected\r\n");
	continue;

      nocurrent:
	prot_printf(nntp_out, "420 No current article selected\r\n");
	continue;

      noarticle:
	prot_printf(nntp_out, "423 No such article in this newsgroup\r\n");
	continue;
    }
}

static int parsenum(char *str, char **rem)
{
    char *p = str;
    int result = 0;

    while (*p && isdigit((int) *p)) {
	result = result * 10 + *p++ - '0';
	if (result < 0) {
	    /* xxx overflow */
	}
    }

    if (rem) {
	*rem = p;
	return (*p && p == str ? -1 : result);
    }

    return (*p ? -1 : result);
}

static int parserange(char *str, unsigned long *uid, unsigned long *last,
		      char **msgid)
{
    char *p = NULL;

    if (!str || !*str) {
	/* no string, use current article */
	if (!nntp_group || !nntp_current) return -1;

	*uid = index_getuid(nntp_current);
	if (last) *last = *uid;
    }
    else if ((*uid = parsenum(str, &p)) == -1) {
	/* not a number, assume msgid */
	if (msgid) {
	    *msgid = str;
	    return 0;
	}
	else return -1;
    }
    else if (!nntp_group) return -1;
    else if (p && *p) {
	/* extra stuff, check for range */
	if (!last || (*p != '-')) return -1;
	if (*++p)
	    *last = parsenum(p, NULL);
	else
	    *last = index_getuid(nntp_exists);
	if (*last == -1) return -1;
    }
    else if (last)
	*last = *uid;

    if (msgid) *msgid = NULL;

    return 0;
}

static const int numdays[] = {
    31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};

#define isleap(year) (!((year) % 4) && (((year) % 100) || !((year) % 400)))

/*
 * Parse a date/time specification per draft-ietf-nntpext-base.
 */
static time_t parse_datetime(char *datestr, char *timestr, char *gmt)
{
    int datelen = strlen(datestr), leapday;
    unsigned long d, t;
    char *p;
    struct tm tm;

    /* check format of strings */
    if ((datelen != 6 && datelen != 8) ||
	strlen(timestr) != 6 || (gmt && strcasecmp(gmt, "GMT")))
	return -1;

    /* convert datestr to ulong */
    d = strtoul(datestr, &p, 10);
    if (d < 0 || *p) return -1;

    /* convert timestr to ulong */
    t = strtoul(timestr, &p, 10);
    if (t < 0 || *p) return -1;

    /* populate the time struct */
    tm.tm_year = d / 10000;
    d %= 10000;
    tm.tm_mon = d / 100 - 1;
    tm.tm_mday = d % 100;

    tm.tm_hour = t / 10000;
    t %= 10000;
    tm.tm_min = t / 100;
    tm.tm_sec = t % 100;

    /* massage the year to years since 1900 */
    if (tm.tm_year > 99) tm.tm_year -= 1900;
    else {
	/*
	 * guess century
	 * if year > current year, use previous century
	 * otherwise, use current century
	 */
	time_t now = time(NULL);
	struct tm *current;
	int century;

        current = gmt ? gmtime(&now) : localtime(&now);
        century = current->tm_year / 100;
        if (tm.tm_year > current->tm_year % 100) century--;
        tm.tm_year += century * 100;
    }

    /* sanity check the date/time (including leap day and leap second) */
    leapday = tm.tm_mon == 1 && isleap(tm.tm_year + 1900);
    if (tm.tm_year < 70 || tm.tm_mon < 0 || tm.tm_mon > 11 ||
	tm.tm_mday < 1 || tm.tm_mday > (numdays[tm.tm_mon] + leapday) ||
	tm.tm_hour > 23 || tm.tm_min > 59 || tm.tm_sec > 60)
        return -1;

    return (gmt ? mkgmtime(&tm) : mktime(&tm));
}

int open_group(char *name, int has_prefix)
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

    if (r) {
	if (doclose) mailbox_close(&mboxstruct);
	return r;
    }

    nntp_group = &mboxstruct;
    index_operatemailbox(nntp_group);

    syslog(LOG_DEBUG, "open: user %s opened %s",
	   nntp_userid ? nntp_userid : "anonymous", name);

    return 0;
}

static void cmd_article(int part, char *msgid, unsigned long uid)
{
    int by_msgid;
    char fname[MAX_MAILBOX_PATH];
    struct mailbox *mbox;
    FILE *msgfile;
    char buf[4096];

    if (msgid) {
	int r;
	char *mailbox, *path;
	struct mailbox tmpbox;

	by_msgid = 1;
	if (netnews_lookup(msgid, &mailbox, &uid, NULL, NULL)) {
	    r = mboxlist_lookup(mailbox, &path, NULL, NULL);
	    if (r) {
		prot_printf(nntp_out,
			    "430 No article found with that message-id (%s)\r\n",
			    error_message(r));
		return;
	    }

	    strcpy(fname, path);
	    mbox = memset(&tmpbox, 0, sizeof(struct mailbox));
	} else {
	    prot_printf(nntp_out,
			"430 No article found with that message-id\r\n");
	    return;
	}
    } else {
	by_msgid = 0;
	msgid = index_get_msgid(nntp_group, index_finduid(uid));
	strcpy(fname, nntp_group->path);
	mbox = nntp_group;
    }

    strcat(fname, "/");
    mailbox_message_get_fname(mbox, uid, fname + strlen(fname));

    msgfile = fopen(fname, "r");
    if (!msgfile) {
	prot_printf(nntp_out, "502 Could not read message file\r\n");
	return;
    }
    prot_printf(nntp_out, "%u %lu %s Article retrieved\r\n",
		220 + part, by_msgid ? 0 : uid, msgid ? msgid : "<0>");

    if (!by_msgid) free(msgid);

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

void cmd_authinfo_user(char *user)
{
    int fd;
    struct protstream *shutdown_in;
    char buf[1024];
    char *p;
    char shutdownfilename[1024];

    /* possibly disallow USER */
    if (!(nntp_starttls_done || config_getswitch(IMAPOPT_ALLOWPLAINTEXT))) {
	prot_printf(nntp_out,
		    "501 AUTHINFO USER command only available under a layer\r\n");
	return;
    }

    if (nntp_userid) {
	prot_printf(nntp_out, "%u Must give AUTHINFO PASS command\r\n",
		    did_extensions ? 350 : 381);
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
	prot_printf(nntp_out, "205 closing connection - %s\r\n", p);
	prot_flush(nntp_out);
	shut_down(0);
    }
    else if (!(p = canonify_userid(user, NULL, NULL))) {
	prot_printf(nntp_out, "%u Invalid user\r\n",
		    did_extensions ? 452 : 482);
	syslog(LOG_NOTICE,
	       "badlogin: %s plaintext %s invalid user",
	       nntp_clienthost, beautify_string(user));
    }
    else {
	nntp_userid = xstrdup(p);
	prot_printf(nntp_out, "%u Give AUTHINFO PASS command\r\n",
		    did_extensions ? 350 : 381);
    }
}

void cmd_authinfo_pass(char *pass)
{
    char *reply = 0;

    if (!nntp_userid) {
	prot_printf(nntp_out, "%u Must give AUTHINFO USER command first\r\n",
		    did_extensions ? 450 : 480);
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
	    prot_printf(nntp_out, "%u Invalid login\r\n",
			did_extensions ? 452 : 482);
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
	prot_printf(nntp_out, "%u Invalid login\r\n",
		    did_extensions ? 452 : 482);
	free(nntp_userid);
	nntp_userid = 0;

	return;
    }
    else {
	syslog(LOG_NOTICE, "login: %s %s plaintext%s %s", nntp_clienthost,
	       nntp_userid, nntp_starttls_done ? "+TLS" : "", 
	       reply ? reply : "");

	prot_printf(nntp_out, "%u User logged in\r\n",
		    did_extensions ? 250 : 281);

	nntp_authstate = auth_newstate(nntp_userid);

	/* Create telemetry log */
	nntp_logfd = telemetry_log(nntp_userid, nntp_in, nntp_out);
    }
}

void cmd_authinfo_sasl(char *mech, char *resp)
{
    int r, sasl_result;
    char *success_data;
    const int *ssfp;
    char *ssfmsg = NULL;
    const char *canon_user;

    if (nntp_userid) {
	prot_printf(nntp_out, "501 Already authenticated\r\n");
	return;
    }

    r = saslserver(nntp_saslconn, mech, resp, "351 ", nntp_in, nntp_out,
		   &sasl_result, &success_data);

    if (r) {
	const char *errorstring = NULL;

	switch (r) {
	case IMAP_SASL_CANCEL:
	    prot_printf(nntp_out,
			"501 Client canceled authentication\r\n");
	    break;
	case IMAP_SASL_PROTERR:
	    errorstring = prot_error(nntp_in);

	    prot_printf(nntp_out,
			"503 Error reading client response: %s\r\n",
			errorstring ? errorstring : "");
	    break;
	default: 
	    /* failed authentication */
	    errorstring = sasl_errstring(sasl_result, NULL, NULL);

	    syslog(LOG_NOTICE, "badlogin: %s %s [%s]",
		   nntp_clienthost, mech, sasl_errdetail(nntp_saslconn));

	    sleep(3);

	    if (errorstring) {
		prot_printf(nntp_out, "452 %s\r\n", errorstring);
	    } else {
		prot_printf(nntp_out, "452 Error authenticating\r\n");
	    }
	}

	reset_saslconn(&nntp_saslconn);
	return;
    }

    /* successful authentication */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_proxy_policy()
     */
    sasl_result = sasl_getprop(nntp_saslconn, SASL_USERNAME,
			       (const void **) &canon_user);
    nntp_userid = xstrdup(canon_user);
    if (sasl_result != SASL_OK) {
	prot_printf(nntp_out, "452 weird SASL error %d SASL_USERNAME\r\n", 
		    sasl_result);
	syslog(LOG_ERR, "weird SASL error %d getting SASL_USERNAME", 
	       sasl_result);
	reset_saslconn(&nntp_saslconn);
	return;
    }

    proc_register("nntpd", nntp_clienthost, nntp_userid, (char *)0);

    syslog(LOG_NOTICE, "login: %s %s %s%s %s", nntp_clienthost, nntp_userid,
	   mech, nntp_starttls_done ? "+TLS" : "", "User logged in");

    sasl_getprop(nntp_saslconn, SASL_SSF, (const void **) &ssfp);

    /* really, we should be doing a sasl_getprop on SASL_SSF_EXTERNAL,
       but the current libsasl doesn't allow that. */
    if (nntp_starttls_done) {
	switch(*ssfp) {
	case 0: ssfmsg = "tls protection"; break;
	case 1: ssfmsg = "tls plus integrity protection"; break;
	default: ssfmsg = "tls plus privacy protection"; break;
	}
    } else {
	switch(*ssfp) {
	case 0: ssfmsg = "no protection"; break;
	case 1: ssfmsg = "integrity protection"; break;
	default: ssfmsg = "privacy protection"; break;
	}
    }

    if (success_data)
	prot_printf(nntp_out, "251 %s\r\n", success_data);
    else
	prot_printf(nntp_out, "250 Success (%s)\r\n", ssfmsg);

    prot_setsasl(nntp_in,  nntp_saslconn);
    prot_setsasl(nntp_out, nntp_saslconn);

    /* Create telemetry log */
    nntp_logfd = telemetry_log(nntp_userid, nntp_in, nntp_out);
}

static void cmd_hdr(char *cmd, char *hdr, char *msgid,
		    unsigned long uid, unsigned long last)
{
    int by_msgid = 0, msgno;
    char *oldgroup = NULL, *body;

    lcase(hdr);

    if (msgid) {
	char *mailbox;
	int r;

	by_msgid = 1;
	if (netnews_lookup(msgid, &mailbox, &uid, NULL, NULL)) {
	    if (nntp_group) oldgroup = xstrdup(nntp_group->name);
	    r = open_group(mailbox, 1);
	    if (r) {
		/* switch back to previously selected group */
		if (oldgroup) {
		    open_group(oldgroup, 1);
		    free(oldgroup);
		    prot_printf(nntp_out, "411 No such newsgroup (%s)\r\n",
				error_message(r));
		}
		return;
	    }

	    last = uid;
	} else {
	    prot_printf(nntp_out,
			"430 No article found with that message-id\r\n");
	    return;
	}
    }

    prot_printf(nntp_out, "%u Header follows:\r\n", cmd[0] == 'X' ? 221 : 225);

    for (; uid <= last; uid++) {
	msgno = index_finduid(uid);
	if (index_getuid(msgno) != uid) continue;

	if ((body = index_getheader(nntp_group, msgno, hdr))) {
	    prot_printf(nntp_out, "%lu %s\r\n", by_msgid ? 0 : uid, body);
	}
    }

    prot_printf(nntp_out, ".\r\n");

    /* switch back to previously selected group */
    if (oldgroup) {
	open_group(oldgroup, 1);
	free(oldgroup);
    }
}

static void cmd_help()
{
    prot_printf(nntp_out, "100 Supported commands:\r\n");
    prot_printf(nntp_out, "\tARTICLE\r\n");
    prot_printf(nntp_out, "\tAUTHINFO USER | PASS | SASL\r\n");
    prot_printf(nntp_out, "\tBODY\r\n");
    prot_printf(nntp_out, "\tCHECK\r\n");
    prot_printf(nntp_out, "\tDATE\r\n");
    prot_printf(nntp_out, "\tGROUP\r\n");
    prot_printf(nntp_out, "\tHDR | XHDR\r\n");
    prot_printf(nntp_out, "\tHEAD\r\n");
    prot_printf(nntp_out, "\tHELP\r\n");
    prot_printf(nntp_out, "\tIHAVE\r\n");
    prot_printf(nntp_out, "\tLAST\r\n");
    prot_printf(nntp_out, "\tLIST [ ACTIVE | EXTENSIONS | OVERVIEW.FMT ]\r\n");
    prot_printf(nntp_out, "\tLISTGROUP\r\n");
    prot_printf(nntp_out, "\tMODE READER | STREAM\r\n");
    if (config_getswitch(IMAPOPT_ALLOWNEWNEWS))
	prot_printf(nntp_out, "\tNEWNEWS\r\n");
    prot_printf(nntp_out, "\tNEXT\r\n");
    prot_printf(nntp_out, "\tOVER | XOVER\r\n");
    prot_printf(nntp_out, "\tPOST\r\n");
    prot_printf(nntp_out, "\tQUIT\r\n");
    prot_printf(nntp_out, "\tSLAVE\r\n");
    prot_printf(nntp_out, "\tSTARTTLS\r\n");
    prot_printf(nntp_out, "\tSTAT\r\n");
    prot_printf(nntp_out, "\tTAKETHIS\r\n");
    prot_printf(nntp_out, ".\r\n");
}

/*
 * mboxlist_findall() callback function to LIST an ACTIVE newsgroup
 */
int do_active(char *name, int matchlen, int maycreate __attribute__((unused)),
	    void *rock)
{
    static char lastname[MAX_MAILBOX_NAME+1] = "";
    struct wildmat *wild = (struct wildmat *) rock;
    char *acl;
    int r, myrights;

    /* skip personal mailboxes */
    if ((!strncasecmp(name, "INBOX", 5) && (!name[5] || name[5] == '.')) ||
	!strncmp(name, "user.", 5))
	return 0;

    /* don't repeat */
    if (matchlen == strlen(lastname) &&
	!strncmp(name, lastname, matchlen)) return 0;

    strncpy(lastname, name, matchlen);
    lastname[matchlen] = '\0';

    /* see if the mailbox matches one of our wildmats */
    while (wild->pat && wildmat(name, wild->pat) != 1) wild++;

    /* if we don't have a match, or its a negative match, skip it */
    if (!wild->pat || wild->not) return 0;

    /* look it up */
    r = mboxlist_detail(name, NULL, NULL, NULL, &acl, NULL);
    if (r) return 0;

    if (!(acl && (myrights = cyrus_acl_myrights(nntp_authstate, acl)) &&
	  (myrights & ACL_LOOKUP) && (myrights & ACL_READ)))
	return 0;

    if (open_group(name, 1) == 0) {
	prot_printf(nntp_out, "%s %u %u %c\r\n", name+strlen(newsprefix),
		    nntp_group->exists ? index_getuid(1) : 1,
		    nntp_group->exists ? index_getuid(nntp_group->exists) : 0,
		    myrights & ACL_POST ? 'y' : 'n');

	mailbox_close(nntp_group);
	nntp_group = 0;
    }

    return 0;
}

void cmd_list(char *arg1, char *arg2)
{
    if (!arg1)
	arg1 = "active";
    else
	lcase(arg1);

    if (!strcmp(arg1, "active")) {
	char pattern[MAX_MAILBOX_NAME+1];
	struct wildmat *wild;

	if (!arg2) arg2 = "*";

	/* split the list of wildmats */
	wild = split_wildmats(arg2);

	prot_printf(nntp_out, "215 list of newsgroups follows:\r\n");

	strcpy(pattern, newsprefix);
	strcat(pattern, "*");
	mboxlist_findall(NULL, pattern, 0, nntp_userid, nntp_authstate,
			 do_active, wild);

	prot_printf(nntp_out, ".\r\n");

	if (nntp_group) {
	    mailbox_close(nntp_group);
	    nntp_group = 0;
	}

	/* free the wildmats */
	free_wildmats(wild);
    }
    else if (!strcmp(arg1, "extensions")) {
	unsigned mechcount = 0;
	const char *mechlist;

	if (arg2) {
	    prot_printf(nntp_out, "501 Unexpected extra argument\r\n");
	    return;
	}

	prot_printf(nntp_out, "202 Extensions supported:\r\n");

	/* check for SASL mechs */
	sasl_listmech(nntp_saslconn, NULL, "SASL ", " ", "\r\n",
		      &mechlist, NULL, &mechcount);

	if (mechcount || config_getswitch(IMAPOPT_ALLOWPLAINTEXT)) {
	    prot_printf(nntp_out, "AUTHINFO%s\r\n",
			config_getswitch(IMAPOPT_ALLOWPLAINTEXT) ? " USER" : "");

	    /* add the SASL mechs */
	    if (mechcount) prot_write(nntp_out, mechlist, strlen(mechlist));
	}

	prot_printf(nntp_out, "HDR\r\n");
	prot_printf(nntp_out, "LISTGROUP\r\n");
	prot_printf(nntp_out, "OVER\r\n");
	prot_printf(nntp_out, "STARTTLS\r\n");
	prot_printf(nntp_out, ".\r\n");

	did_extensions = 1;
    }
    else if (!nntp_userid && !config_allowanonymous) {
	prot_printf(nntp_out, "%u Authentication required\r\n",
		    did_extensions ? 450 : 480);
	return;
    }
    else if (!strcmp(arg1, "overview.fmt")) {
	if (arg2) {
	    prot_printf(nntp_out, "501 Unexpected extra argument\r\n");
	    return;
	}

	prot_printf(nntp_out, "215 Order of overview fields follows:\r\n");
	prot_printf(nntp_out, "Subject:\r\n");
	prot_printf(nntp_out, "From:\r\n");
	prot_printf(nntp_out, "Date:\r\n");
	prot_printf(nntp_out, "Message-ID:\r\n");
	prot_printf(nntp_out, "References:\r\n");
	prot_printf(nntp_out, "Bytes:\r\n");
	prot_printf(nntp_out, "Lines:\r\n");
	prot_printf(nntp_out, ".\r\n");
    }
    else if (!strcmp(arg1, "active.times") || !strcmp(arg1, "distributions") ||
	     !strcmp(arg1, "distrib.pats") || !strcmp(arg1, "newsgroups")) {
	prot_printf(nntp_out, "501 Unsupported LIST command\r\n");
    }
    else {
	prot_printf(nntp_out, "501 Unrecognized LIST command\r\n");
    }
    prot_flush(nntp_out);
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
	prot_printf(nntp_out, "501 Unrecognized MODE\r\n");
    }
    prot_flush(nntp_out);
}

/*
 * newnews_findall() callback function to list NEWNEWS
 */
static int do_newnews(char *msgid, char *mailbox, unsigned long uid,
		      unsigned long lines, time_t tstamp, void *rock)
{
    prot_printf(nntp_out, "%s\r\n", msgid);

    return 0;
}

static void cmd_over(unsigned long uid, unsigned long last)
{
    int msgno;
    struct nntp_overview *over;
    int found = 0;

    for (; uid <= last; uid++) {
	msgno = index_finduid(uid);
	if (index_getuid(msgno) != uid) continue;

	if ((over = index_overview(nntp_group, msgno))) {
	    if (!found++)
		prot_printf(nntp_out, "224 Overview information follows:\r\n");

	    prot_printf(nntp_out, "%lu\t%s\t%s\t%s\t%s\t%s\t%lu\t",
			over->uid,
			over->subj ? over->subj : "",
			over->from ? over->from : "",
			over->date ? over->date : "",
			over->msgid ? over->msgid : "",
			over->ref ? over->ref : "",
			over->bytes);

	    if (over->msgid &&
		netnews_lookup(over->msgid, NULL, NULL, &over->lines, NULL))
		prot_printf(nntp_out, "%lu", over->lines);

	    prot_printf(nntp_out, "\r\n");
	}
    }

    if (found)
	prot_printf(nntp_out, ".\r\n");
    else
	prot_printf(nntp_out, "420 No articles selected\r\n");
}


#define RCPT_GROW 30

typedef struct message_data message_data_t;

struct message_data {
    struct protstream *data;	/* message in temp file */
    FILE *f;			/* FILE * corresponding */

    char *id;			/* message id */
    char *path;			/* path */
    char *control;		/* control message */
    unsigned long size;		/* size of message in bytes */
    unsigned long lines;	/* number of lines in body of message */

    char **rcpt;		/* mailboxes to post message */
    int rcpt_num;		/* number of groups */

    hdrcache_t hdrcache;
};

/* returns non-zero on failure */
int msg_new(message_data_t **m)
{
    message_data_t *ret = (message_data_t *) xmalloc(sizeof(message_data_t));

    ret->data = NULL;
    ret->f = NULL;
    ret->id = NULL;
    ret->path = NULL;
    ret->control = NULL;
    ret->size = 0;
    ret->lines = 0;
    ret->rcpt = NULL;
    ret->rcpt_num = 0;

    ret->hdrcache = spool_new_hdrcache();

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
    if (m->path) {
	free(m->path);
    }
    if (m->control) {
	free(m->control);
    }

    if (m->rcpt) {
	for (i = 0; i < m->rcpt_num; i++) {
	    free(m->rcpt[i]);
	}
	free(m->rcpt);
    }

    spool_free_hdrcache(m->hdrcache);

    free(m);
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
    static int post_count = 0;

    /* fill the cache */
    r = spool_fill_hdrcache(nntp_in, f, m->hdrcache);
    if (r) {
	/* got a bad header */

	/* flush the remaining output */
	spool_copy_msg(nntp_in, f, NULL);
	return r;
    }

    /* now, using our header cache, fill in the data that we want */

    /* get path */
    if ((body = spool_getheader(m->hdrcache, "path")) != NULL) {
	m->path = xstrdup(body[0]);
    } else {
	m->path = NULL;		/* no path-id */
	fprintf(f, "Path: %s!%s\r\n",
		config_servername, nntp_userid ? nntp_userid : "anonymous");
    }

    /* get message-id */
    if ((body = spool_getheader(m->hdrcache, "message-id")) != NULL) {
	m->id = xstrdup(body[0]);
    } else {
	/* no message-id, create one */
	time_t t = time(NULL);
	pid_t p = getpid();

	m->id = xmalloc(40 + strlen(config_servername));
	sprintf(m->id, "<cmu-nntpd-%d-%d-%d@%s>", p, (int) t, 
		post_count++, config_servername);
	fprintf(f, "Message-ID: %s\r\n", m->id);
    }

    /* get date */
    if ((body = spool_getheader(m->hdrcache, "date")) == NULL) {
	/* date, create one */
	time_t t = time(NULL);
	char datestr[80];

	rfc822date_gen(datestr, sizeof(datestr), t);
	fprintf(f, "Date: %s\r\n", datestr);
    }

    /* get control */
    if ((body = spool_getheader(m->hdrcache, "control")) != NULL) {
	int len;

	m->control = xstrdup(body[0]);

	/* create a recipient for the appropriate pseudo newsgroup */
	m->rcpt_num = 1;
	m->rcpt = (char **) xmalloc(sizeof(char *));
	len = strcspn(m->control, " \t\r\n");
	m->rcpt[0] = xmalloc(strlen(newsprefix) + 8 + len + 1);
	sprintf(m->rcpt[0], "%scontrol.%.*s", newsprefix, len, m->control);
    } else {
	m->control = NULL;	/* no control */

	/* get newsgroups */
	if ((body = spool_getheader(m->hdrcache, "newsgroups")) != NULL) {
	    /* parse newsgroups and create recipients */
	    if (!m->control && (r = parse_groups(body[0], m)) == 0) {
		char buf[1024] = "";
		const char *sep = "";
		int n;

		/* build a To: header */
		for (n = 0; n < m->rcpt_num; n++) {
		    snprintf(buf+strlen(buf), sizeof(buf)-strlen(buf),
			     "%s%s+%s@%s", sep,
			     config_getstring(IMAPOPT_NEWSPOSTUSER),
			     m->rcpt[n]+strlen(newsprefix),
			     config_servername);
		    sep = ", ";
		}

		/* add To: header */
		fprintf(f, "To: %s\r\n", buf);
	    }
	} else {
	    r = NNTP_NO_NEWSGROUPS;		/* no newsgroups */
	}
    }

    r |= spool_copy_msg(nntp_in, f, &m->lines);

    if (r) return r;

    fflush(f);
    if (ferror(f)) {
	return IMAP_IOERROR;
    }

    if (fstat(fileno(f), &sbuf) == -1) {
	return IMAP_IOERROR;
    }
    m->size = sbuf.st_size;
    m->lines--; /* don't count header/body separator */
    m->f = f;
    m->data = prot_new(fileno(f), 0);

    return 0;
}

static int deliver(message_data_t *msg)
{
    int n, r;
    char *rcpt = NULL;
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

    /* store msgid for IHAVE/CHECK/TAKETHIS and reader commands */
    if (have_newsdb && msg->id && rcpt)
	netnews_store(msg->id, rcpt, uid, msg->lines, now);

    return  0;
}

static int newgroup(message_data_t *msg)
{
    int r;
    char *group;
    char mailboxname[MAX_MAILBOX_NAME+1];

    /* isolate newsgroup */
    group = msg->control + 8; /* skip "newgroup" */
    while (isspace((int) *group)) group++;

    snprintf(mailboxname, sizeof(mailboxname), "%s%.*s",
	     newsprefix, (int) strcspn(group, " \t\r\n"), group);

    /* XXX check ACL, localonly? force? */
    r = mboxlist_createmailbox(mailboxname, 0, NULL, 1,
			       nntp_userid, nntp_authstate, 0, 0);

    /* XXX check body of message for useful MIME parts */

    return r;
}

static int rmgroup(message_data_t *msg)
{
    int r;
    char *group;
    char mailboxname[MAX_MAILBOX_NAME+1];

    /* isolate newsgroup */
    group = msg->control + 7; /* skip "rmgroup" */
    while (isspace((int) *group)) group++;

    snprintf(mailboxname, sizeof(mailboxname), "%s%.*s",
	     newsprefix, (int) strcspn(group, " \t\r\n"), group);

    /* XXX should we delete right away, or wait until empty? */

    /* XXX check ACL, localonly? force? */
    r = mboxlist_deletemailbox(mailboxname, 1,
			       nntp_userid, nntp_authstate, 0, 0, 0);

    return r;
}

static int mvgroup(message_data_t *msg)
{
    int r, len;
    char *group;
    char oldmailboxname[MAX_MAILBOX_NAME+1];
    char newmailboxname[MAX_MAILBOX_NAME+1];

    /* isolate old newsgroup */
    group = msg->control + 7; /* skip "mvgroup" */
    while (isspace((int) *group)) group++;

    len = (int) strcspn(group, " \t\r\n");
    snprintf(oldmailboxname, sizeof(oldmailboxname), "%s%.*s",
	     newsprefix, len, group);

    /* isolate new newsgroup */
    group += len; /* skip old newsgroup */
    while (isspace((int) *group)) group++;

    len = (int) strcspn(group, " \t\r\n");
    snprintf(newmailboxname, sizeof(newmailboxname), "%s%.*s",
	     newsprefix, len, group);

    /* XXX check ACL, localonly? force? */
    r = mboxlist_renamemailbox(oldmailboxname, newmailboxname, NULL, 1,
			       nntp_userid, nntp_authstate);

    /* XXX check body of message for useful MIME parts */

    return r;
}

static int expunge_cancelled(struct mailbox *mailbox, void *rock, char *index)
{
    int uid = ntohl(*((bit32 *)(index+OFFSET_UID)));

    return (uid == *((unsigned long *) rock));
}

static int cancel(message_data_t *msg)
{
    int r = 0;
    char *msgid, *p, *mailbox;
    time_t now = time(NULL);
    unsigned long uid;

    /* isolate msgid */
    msgid = strchr(msg->control, '<');
    p = strrchr(msgid, '>') + 1;
    *p = '\0';

    if (netnews_lookup(msgid, &mailbox, &uid, NULL, NULL)) {
	struct mailbox mbox;
	int doclose = 0;

	r = mailbox_open_header(mailbox, 0, &mbox);

	if (!r) {
	    doclose = 1;
	    if (mbox.header_fd != -1)
		mailbox_lock_header(&mbox);
	    mbox.header_lock_count = 1;

	    r = mailbox_open_index(&mbox);
	}

	if (!r) {
	    mailbox_lock_index(&mbox);
	    mbox.index_lock_count = 1;
	    /* XXX check ACL */
	    mailbox_expunge(&mbox, 0, expunge_cancelled, &uid);
	}

	if (doclose) mailbox_close(&mbox);
    }

    /* store msgid of cancelled message for IHAVE/CHECK/TAKETHIS
     * (in case we haven't received the message yet)
     */
    if (have_newsdb) netnews_store(msgid, "", uid, 0, now);

    return r;
}

static void feedpeer(message_data_t *msg)
{
    const char *server;
    char *path, *s;
    int len;
    struct hostent *hp;
    struct sockaddr_in sin;
    int sock;
    struct protstream *pin, *pout;
    char buf[4096];

    if ((server = config_getstring(IMAPOPT_NEWSPEER)) == NULL) {
	syslog(LOG_ERR, "no newspeer defined");
	return;
    }

    /* check path to see if this message came through our peer */
    len = strlen(server);
    path = msg->path;
    while (path && (s = strchr(path, '!'))) {
	if ((s - path) == len && !strncmp(path, server, len)) return;
	path = s + 1;
    }

    if ((hp = gethostbyname(server)) == NULL) {
	syslog(LOG_ERR, "gethostbyname(%s) failed: %m", server);
	return;
    }

    sin.sin_family = AF_INET;
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_port = htons(119);
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	syslog(LOG_ERR, "socket() failed: %m");
	return;
    }
    if (connect(sock, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
	syslog(LOG_ERR, "connect() failed: %m");
	return;
    }
    
    pin = prot_new(sock, 0);
    pout = prot_new(sock, 1);
    prot_setflushonread(pin, pout);

    /* read the initial greeting */
    if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("200", buf, 3)) {
	syslog(LOG_ERR, "peer doesn't allow posting");
	goto quit;
    }

    /* tell the peer about our new article */
    prot_printf(pout, "IHAVE %s\r\n", msg->id);
    prot_flush(pout);

    if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("335", buf, 3)) {
	syslog(LOG_ERR, "peer doesn't want article %s", msg->id);
	goto quit;
    }

    /* send the article */
    rewind(msg->f);
    while (fgets(buf, sizeof(buf), msg->f)) {
	if (buf[0] == '.') prot_putc('.', pout);
	do {
	    prot_printf(pout, "%s", buf);
	} while (buf[strlen(buf)-1] != '\n' &&
		 fgets(buf, sizeof(buf), msg->f));
    }

    /* Protect against messages not ending in CRLF */
    if (buf[strlen(buf)-1] != '\n') prot_printf(pout, "\r\n");

    prot_printf(pout, ".\r\n");

    if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("235", buf, 3)) {
	syslog(LOG_ERR, "article %s transfer failed", msg->id);
    }

  quit:
    prot_printf(pout, "QUIT\r\n");
    prot_flush(pout);

    prot_fgets(buf, sizeof(buf), pin);

    /* Flush the incoming buffer */
    prot_NONBLOCK(pin);
    prot_fill(pin);

    /* close/free socket & prot layer */
    close(sock);
    
    prot_free(pin);
    prot_free(pout);

    return;
}

static void cmd_post(char *msgid, int mode)
{
    FILE *f = NULL;
    message_data_t *msg;
    int r = 0;

    /* check if we want this article */
    if (have_newsdb && msgid &&
	netnews_lookup(msgid, NULL, NULL, NULL, NULL)) {
	/* already have it */
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

    /* get a spool file (if needed) */
    if (!r) {
	f = tmpfile();
	if (!f) r = IMAP_IOERROR;
    }

    if (f) {
	msg_new(&msg);

	/* spool the article */
	r = savemsg(msg, f);

	if (!r) {
	    /* deliver the article */
	    r = deliver(msg);

	    if (msg->control) {
		if (!strncmp(msg->control, "newgroup", 8))
		    r = newgroup(msg);
		else if (!strncmp(msg->control, "rmgroup", 7))
		    r = rmgroup(msg);
		else if (!strncmp(msg->control, "mvgroup", 7))
		    r = mvgroup(msg);
		else if (!strncmp(msg->control, "cancel", 6))
		    r = cancel(msg);
		else
		    syslog(LOG_ERR, "unknown control message: %s",
			   msg->control);
	    }
	}

	if (!r) {
	    if (msg->id) {
		/* send the article upstream */
		feedpeer(msg);
	    }

	    prot_printf(nntp_out, "%u Article %s received ok\r\n",
			post_codes[mode].ok, msg->id ? msg->id : "");
	}

	msg_free(msg); /* does fclose() */
    }
    else {
	/* flush the article from the stream */
	spool_copy_msg(nntp_in, NULL, NULL);
    }

    if (r) {
	prot_printf(nntp_out, "%u Failed receiving article %s (%s)\r\n",
		    post_codes[mode].fail, msgid ? msgid : "",
		    error_message(r));
    }

    prot_flush(nntp_out);
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
	prot_printf(nntp_out, "483 %s\r\n", 
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
	    prot_printf(nntp_out, "580 %s\r\n", "Error initializing TLS");
	else
	    fatal("tls_init() failed",EC_TEMPFAIL);

	return;
    }

    if (nntps == 0)
    {
	prot_printf(nntp_out, "382 %s\r\n", "Begin TLS negotiation now");
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
	    prot_printf(nntp_out, "580 Starttls failed\r\n");
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
