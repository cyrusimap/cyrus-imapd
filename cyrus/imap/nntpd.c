/* nntpd.c -- NNTP server
 *
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
 * $Id: nntpd.c,v 1.1.2.80 2003/05/08 20:56:53 ken3 Exp $
 */

/*
 * TODO:
 *
 * - remove Xref header from articles
 * - add PGP verification code and ACLs for control messages
 * - figure out what to do with control messages when proxying
 * - figure out how to do singleinstancestore
 */


#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/param.h>
#include <syslog.h>
#include <com_err.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "acl.h"
#include "append.h"
#include "auth.h"
#include "backend.h"
#include "duplicate.h"
#include "exitcodes.h"
#include "global.h"
#include "imap_err.h"
#include "index.h"
#include "iptostring.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "mkgmtime.h"
#include "mupdate-client.h"
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
char *imapd_userid = NULL;
void printastring(const char *s)
{
    fatal("not implemented", EC_SOFTWARE);
}
/* end stuff to make index.c link */

/* PROXY STUFF */
/* we want a list of our outgoing connections here and which one we're
   currently piping */
#define IDLE_TIMEOUT (5 * 60)

/* the current server most commands go to */
struct backend *backend_current = NULL;

/* our cached connections */
struct backend **backend_cached = NULL;

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
struct sockaddr_storage nntp_localaddr, nntp_remoteaddr;
int nntp_haveaddr = 0;
char nntp_clienthost[NI_MAXHOST*2+1] = "[local]";
struct protstream *nntp_out = NULL;
struct protstream *nntp_in = NULL;
static int nntp_logfd = -1;
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
static int open_group(char *name, int has_prefix,
		      struct backend **ret, int *postable);
static int parserange(char *str, unsigned long *uid, unsigned long *last,
		      char **msgid, struct backend **be);
static time_t parse_datetime(char *datestr, char *timestr, char *gmt);
static void cmd_article(int part, char *msgid, unsigned long uid);
static void cmd_authinfo_user(char *user);
static void cmd_authinfo_pass(char *pass);
static void cmd_authinfo_sasl(char *mech, char *resp);
static void cmd_hdr(char *cmd, char *hdr, char *msgid,
		    unsigned long uid, unsigned long last);
static void cmd_help(void);
static void cmd_list(char *arg1, char *arg2);
static void cmd_mode(char *arg);
static int do_newnews(char *msgid, char *mailbox, unsigned long uid,
		      unsigned long lines, time_t tstamp, void *rock);
static void cmd_over(unsigned long uid, unsigned long last);
static void cmd_post(char *msgid, int mode);
static void cmd_starttls(int nntps);
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

/* proxy support functions */
void proxyd_downserver(struct backend *s)
{
    if (!s || !s->timeout) {
	/* already disconnected */
	return;
    }

    /* need to logout of server */
    backend_disconnect(s, &protocol[PROTOCOL_NNTP]);

    if(s == backend_current) backend_current = NULL;

    /* remove the timeout */
    prot_removewaitevent(nntp_in, s->timeout);
    s->timeout = NULL;
}

struct prot_waitevent *backend_timeout(struct protstream *s,
				       struct prot_waitevent *ev, void *rock)
{
    struct backend *be = (struct backend *) rock;

    if (be != backend_current) {
	/* server is not our current server, and idle too long.
	 * down the backend server (removes the event as a side-effect)
	 */
	proxyd_downserver(be);
	return NULL;
    }
    else {
	/* it will timeout in IDLE_TIMEOUT seconds from now */
	ev->mark = time(NULL) + IDLE_TIMEOUT;
	return ev;
    }
}

/* return the connection to the server */
struct backend *proxyd_findserver(const char *server)
{
    int i = 0;
    struct backend *ret = NULL;

    while (backend_cached && backend_cached[i]) {
	if (!strcmp(server, backend_cached[i]->hostname)) {
	    /* xxx do we want to ping/noop the server here? */
	    ret = backend_cached[i];
	    break;
	}
	i++;
    }

    if (!ret || !ret->timeout) {
	/* need to (re)establish connection to server or create one */
	ret = backend_connect(ret, server, &protocol[PROTOCOL_NNTP],
			      nntp_userid ? nntp_userid : "anonymous", NULL);
	if(!ret) return NULL;

	/* set the id */
	if (!ret->context) {
	    ret->context = xmalloc(sizeof(unsigned));
	    *((unsigned *) ret->context) = i;
	}

	/* add the timeout */
	ret->timeout = prot_addwaitevent(nntp_in, time(NULL) + IDLE_TIMEOUT,
					 backend_timeout, ret);
    }

    ret->timeout->mark = time(NULL) + IDLE_TIMEOUT;

    /* insert server in list of cached connections */
    if (!backend_cached[i]) {
	backend_cached = (struct backend **) 
	    xrealloc(backend_cached, (i + 2) * sizeof(struct backend *));
	backend_cached[i] = ret;
	backend_cached[i + 1] = NULL;
    }

    return ret;
}

static void kick_mupdate(void)
{
    char buf[2048];
    struct sockaddr_un srvaddr;
    int s, r;
    int len;
    
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	syslog(LOG_ERR, "socket: %m");
	return;
    }

    strlcpy(buf, config_dir, sizeof(buf));
    strlcat(buf, FNAME_MUPDATE_TARGET_SOCK, sizeof(buf));
    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, buf);
    len = sizeof(srvaddr.sun_family) + strlen(srvaddr.sun_path) + 1;

    r = connect(s, (struct sockaddr *)&srvaddr, len);
    if (r == -1) {
	syslog(LOG_ERR, "kick_mupdate: can't connect to target: %m");
	close(s);
	return;
    }

    r = read(s, buf, sizeof(buf));
    if (r <= 0) {
	syslog(LOG_ERR, "kick_mupdate: can't read from target: %m");
	close(s);
	return;
    }

    /* if we got here, it's been kicked */
    close(s);
    return;
}

/* proxy mboxlist_lookup; on misses, it asks the listener for this
   machine to make a roundtrip to the master mailbox server to make
   sure it's up to date */
static int mlookup(const char *name, char **pathp, 
		   char **aclp, void *tid)
{
    int r;

    if(pathp) *pathp = NULL;

    r = mboxlist_lookup(name, pathp, aclp, tid);
    if (r == IMAP_MAILBOX_NONEXISTENT && config_mupdate_server) {
	kick_mupdate();
	r = mboxlist_lookup(name, pathp, aclp, tid);
    }

    /* xxx hide the fact that we are storing partitions */
    if(pathp && *pathp) {
	char *c;
	c = strchr(*pathp, '!');
	if(c) *c = '\0';
    }
    return r;
}

static int read_response(struct backend *s, int force_notfatal, char **result)
{
    static char buf[2048];

    s->timeout->mark = time(NULL) + IDLE_TIMEOUT;

    if (!prot_fgets(buf, sizeof(buf), s->in)) {
	/* uh oh */
	if (s == backend_current && !force_notfatal)
	    fatal("Lost connection to selected backend", EC_UNAVAILABLE);
	proxyd_downserver(s);
	return IMAP_SERVER_UNAVAILABLE;
    }

    *result = buf;
    return 0;
}

static int pipe_to_end_of_response(struct backend *s, int force_notfatal)
{
    char buf[2048];

    s->timeout->mark = time(NULL) + IDLE_TIMEOUT;

    do {
	if (!prot_fgets(buf, sizeof(buf), s->in)) {
	    /* uh oh */
	    if (s == backend_current && !force_notfatal)
		fatal("Lost connection to selected backend", EC_UNAVAILABLE);
	    proxyd_downserver(s);
	    return IMAP_SERVER_UNAVAILABLE;
	}

	prot_printf(nntp_out, "%s", buf);
    } while (strcmp(buf, ".\r\n"));

    return 0;
}
/* end proxy support functions */

static void nntp_reset(void)
{
    int i;

    proc_cleanup();

    /* close local mailbox */
    if (nntp_group) {
	mailbox_close(nntp_group);
	nntp_group = 0;
    }

    /* close backend connections */
    i = 0;
    while (backend_cached[i]) {
	proxyd_downserver(backend_cached[i]);
	free(backend_cached[i]->context);
	free(backend_cached[i]);
	i++;
    }
    free(backend_cached);
    backend_cached = NULL;
    backend_current = NULL;

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

#ifdef HAVE_SSL
    if (tls_conn) {
	tls_reset_servertls(&tls_conn);
	tls_conn = NULL;
    }
#endif

    cyrus_close_sock(0);
    cyrus_close_sock(1);
    cyrus_close_sock(2);

    strcpy(nntp_clienthost, "[local]");
    if (nntp_logfd != -1) {
	close(nntp_logfd);
	nntp_logfd = -1;
    }
    if (nntp_userid != NULL) {
	free(nntp_userid);
	nntp_userid = NULL;
    }
    if (nntp_authstate) {
	auth_freestate(nntp_authstate);
	nntp_authstate = NULL;
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
    global_sasl_init(1, 1, mysasl_cb);

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
    char localip[60], remoteip[60];
    char hbuf[NI_MAXHOST];
    int timeout;
    sasl_security_properties_t *secprops=NULL;
    char unavail[1024];

    signals_poll();

    nntp_in = prot_new(0, 0);
    nntp_out = prot_new(1, 1);

    /* Find out name of client host */
    salen = sizeof(nntp_remoteaddr);
    if (getpeername(0, (struct sockaddr *)&nntp_remoteaddr, &salen) == 0 &&
	(nntp_remoteaddr.ss_family == AF_INET ||
	 nntp_remoteaddr.ss_family == AF_INET6)) {
	if (getnameinfo((struct sockaddr *)&nntp_remoteaddr, salen,
			hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) == 0) {
	    strncpy(nntp_clienthost, hbuf, sizeof(hbuf));
	    nntp_clienthost[sizeof(nntp_clienthost)-30] = '\0';
	} else {
	    nntp_clienthost[0] = '\0';
	}
	getnameinfo((struct sockaddr *)&nntp_remoteaddr, salen, hbuf,
		    sizeof(hbuf), NULL, 0, NI_NUMERICHOST | NI_WITHSCOPEID);

	strlcat(nntp_clienthost, "[", sizeof(nntp_clienthost));
	strlcat(nntp_clienthost, hbuf, sizeof(nntp_clienthost));
	strlcat(nntp_clienthost, "]", sizeof(nntp_clienthost));
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
    
    if(iptostring((struct sockaddr *)&nntp_localaddr, salen,
		  localip, 60) == 0) {
	sasl_setprop(nntp_saslconn, SASL_IPLOCALPORT, localip);
	saslprops.iplocalport = xstrdup(localip);
    }
    
    if(iptostring((struct sockaddr *)&nntp_remoteaddr, salen,
		  remoteip, 60) == 0) {
	sasl_setprop(nntp_saslconn, SASL_IPREMOTEPORT, remoteip);  
	saslprops.ipremoteport = xstrdup(remoteip);
    }

    proc_register("nntpd", nntp_clienthost, NULL, NULL);

    /* Set inactivity timer */
    timeout = config_getint(IMAPOPT_TIMEOUT);
    if (timeout < 3) timeout = 3;
    prot_settimeout(nntp_in, timeout*60);
    prot_setflushonread(nntp_in, nntp_out);

    /* setup the cache */
    backend_cached = xmalloc(sizeof(struct backend *));
    backend_cached[0] = NULL;

    /* we were connected on nntps port so we should do 
       TLS negotiation immediatly */
    if (nntps == 1) cmd_starttls(1);

    if (shutdown_file(unavail, sizeof(unavail))) {
	prot_printf(nntp_out,
		    "400 %s Cyrus NNTP%s %s server unavailable, %s\r\n",
		    config_servername, config_mupdate_server ? " Murder" : "",
		    CYRUS_VERSION, unavail);

	shut_down(0);
    }

    prot_printf(nntp_out,
		"200 %s Cyrus NNTP%s %s server ready, posting allowed\r\n",
		config_servername, config_mupdate_server ? " Murder" : "",
		CYRUS_VERSION);

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
    int i;

    proc_cleanup();

    /* close local mailbox */
    if (nntp_group) {
	mailbox_close(nntp_group);
    }

    /* close backend connections */
    i = 0;
    while (backend_cached && backend_cached[i]) {
	proxyd_downserver(backend_cached[i]);
	free(backend_cached[i]->context);
	free(backend_cached[i]);
	i++;
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
	prot_printf(nntp_out, "205 Fatal error: %s\r\n", s);
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
    ret = sasl_server_new("news", config_servername,
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
    char *p, *result, buf[1024];
    const char *err;
    unsigned long uid;
    struct backend *be;

    config_allowanonymous = config_getswitch(IMAPOPT_ALLOWANONYMOUSLOGIN);

    for (;;) {
	signals_poll();

	/* Parse command name */
	c = getword(nntp_in, &cmd);
	if (c == EOF) {
	    if ((err = prot_error(nntp_in)) != NULL) {
		syslog(LOG_WARNING, "%s, closing connection", err);
		prot_printf(nntp_out, "400 %s\r\n", err);
	    }
	    return;
	}
	if (shutdown_file(buf, sizeof(buf))) {
	    prot_printf(nntp_out, "400 %s\r\n", buf);
	    shut_down(0);
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
		    prot_printf(nntp_out,
				"501 Unrecognized AUTHINFO command\r\n");
	    }
	    else if (!nntp_userid && !config_allowanonymous) goto nologin;
	    else if (!strcmp(cmd.s, "Article")) {
		char curgroup[MAX_MAILBOX_NAME+1], *msgid;

		mode = ARTICLE_ALL;

	      article:
		if (arg1.s) *arg1.s = 0;

		if (c == ' ') {
		    c = getword(nntp_in, &arg1);
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		/* in case a msgid makes us switch groups */
		strcpy(curgroup, nntp_group ? nntp_group->name : "");

		if (parserange(arg1.s, &uid, NULL, &msgid, &be) != -1) {
		    if (be) {
			if (arg1.s && *arg1.s)
			    prot_printf(be->out, "%s %s\r\n", cmd.s, arg1.s);
			else
			    prot_printf(be->out, "%s\r\n", cmd.s);

			r = read_response(be, 0, &result);
			if (r) goto noopengroup;

			prot_printf(nntp_out, "%s", result);
			if (!strncmp(result, "22", 2) &&
			    mode != ARTICLE_STAT) {
			    pipe_to_end_of_response(be, 0);
			}
		    }
		    else
			cmd_article(mode, msgid, uid);
		}

		/* return to previously selected group */
		if (*curgroup && nntp_group &&
		    strcmp(curgroup, nntp_group->name)) {
		       open_group(curgroup, 1, NULL, NULL);
		}
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

		r = open_group(arg1.s, 0, &backend_current, NULL);
		if (r) goto nogroup;
		else if (backend_current) {
		    prot_printf(backend_current->out, "GROUP %s\r\n", arg1.s);
		    r = read_response(backend_current, 0, &result);
		    if (r) goto nogroup;

		    prot_printf(nntp_out, "%s", result);
		}
		else {
		    nntp_exists = nntp_group->exists;
		    nntp_current = nntp_exists > 0;

		    prot_printf(nntp_out, "211 %u %lu %lu %s\r\n",
				nntp_exists,
				nntp_exists ? index_getuid(1) :
				nntp_group->last_uid+1,
				nntp_exists ? index_getuid(nntp_exists) :
				nntp_group->last_uid,
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
		char curgroup[MAX_MAILBOX_NAME+1], *msgid;
		unsigned long last;

	      hdr:
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

		/* in case a msgid makes us switch groups */
		strcpy(curgroup, nntp_group ? nntp_group->name : "");

		if (parserange(arg2.s, &uid, &last, &msgid, &be) != -1) {
		    if (be) {
			if (arg2.s && *arg2.s)
			    prot_printf(be->out, "%s %s %s\r\n",
					cmd.s, arg1.s, arg2.s);
			else
			    prot_printf(be->out, "%s %s\r\n", cmd.s, arg1.s);

			r = read_response(be, 0, &result);
			if (r) goto noopengroup;

			prot_printf(nntp_out, "%s", result);
			if (!strncmp(result, "225", 3)) {
			    pipe_to_end_of_response(be, 0);
			}
		    }
		    else
			cmd_hdr(cmd.s, arg1.s, msgid, uid, last);
		}

		/* return to previously selected group */
		if (*curgroup && nntp_group &&
		    strcmp(curgroup, nntp_group->name)) {
		       open_group(curgroup, 1, NULL, NULL);
		}
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

		if (backend_current) {
		    prot_printf(backend_current->out, "LAST\r\n");

		    r = read_response(backend_current, 0, &result);
		    if (r) goto noopengroup;

		    prot_printf(nntp_out, "%s", result);
		}
		else if (!nntp_group) goto noopengroup;
		else if (!nntp_current) goto nocurrent;
		else if (nntp_current == 1) {
		    prot_printf(nntp_out,
				"422 No previous article in this group\r\n");
		}
		else {
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
		    r = open_group(arg1.s, 0, &backend_current, NULL);
		    if (r) goto nogroup;

		    if (nntp_group) {
			nntp_exists = nntp_group->exists;
			nntp_current = nntp_exists > 0;
		    }
		}
		if (backend_current) {
		    if (arg1.len)
			prot_printf(backend_current->out, "LISTGROUP %s\r\n",
				    arg1.s);
		    else
			prot_printf(backend_current->out, "LISTGROUP\r\n");

		    r = read_response(backend_current, 0, &result);
		    if (r) goto noopengroup;

		    prot_printf(nntp_out, "%s", result);
		    if (!strncmp(result, "211", 3)) {
			pipe_to_end_of_response(backend_current, 0);
		    }
		}
		else if (!nntp_group) goto noopengroup;
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

		if (backend_current) {
		    prot_printf(backend_current->out, "NEXT\r\n");

		    r = read_response(backend_current, 0, &result);
		    if (r) goto noopengroup;

		    prot_printf(nntp_out, "%s", result);
		}
		else if (!nntp_group) goto noopengroup;
		else if (!nntp_current) goto nocurrent;
		else if (nntp_current == nntp_exists) {
		    prot_printf(nntp_out,
				"421 No next article in this group\r\n");
		}
		else {
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

		if (parserange(arg1.s, &uid, &last, NULL, &be) != -1) {
		    if (be) {
			if (arg1.s && *arg1.s)
			    prot_printf(be->out, "%s %s\r\n", cmd.s, arg1.s);
			else
			    prot_printf(be->out, "%s\r\n", cmd.s);

			r = read_response(be, 0, &result);
			if (r) goto noopengroup;

			prot_printf(nntp_out, "%s", result);
			if (!strncmp(result, "224", 3)) {
			    pipe_to_end_of_response(be, 0);
			}
		    }
		    else
			cmd_over(uid, last);
		}
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
	    if (!strcmp(cmd.s, "Starttls")) {
		if (!tls_enabled()) {
		    /* we don't support starttls */
		    goto badcmd;
		}

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
	prot_printf(nntp_out, "480 Authentication required\r\n");
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
		      char **msgid, struct backend **ret)
{
    char *p = NULL, *mboxname;
    int r = 0;

    *uid = 0;
    if (last) *last = 0;
    if (msgid) *msgid = NULL;
    if (ret) *ret = NULL;

    if (!str || !*str) {
	/* argument, use current article */
	if (backend_current) {
	    if (ret) *ret = backend_current;
	}
	else if (!nntp_group) goto noopengroup;
	else if (!nntp_current) goto nocurrent;
	else {
	    *uid = index_getuid(nntp_current);
	    if (last) *last = *uid;
	}
    }
    else if (*str == '<') {
	/* message-id, find server and/or mailbox */
	if (!msgid) goto badrange;
	if (!netnews_lookup(str, &mboxname, uid, NULL, NULL) ||
	    (r = open_group(mboxname, 1, ret, NULL)))
	    goto nomsgid;
	*msgid = str;
    }
    else if (backend_current)
	*ret = backend_current;
    else if (!nntp_group) goto noopengroup;
    else if (!nntp_exists) goto noarticle;
    else if ((*uid = parsenum(str, &p)) <= 0) goto badrange;
    else if (p && *p) {
	/* extra stuff, check for range */
	if (!last || (*p != '-')) goto badrange;
	if (*++p)
	    *last = parsenum(p, NULL);
	else
	    *last = index_getuid(nntp_exists);
	if (*last <= 0 || *last < *uid) goto badrange;
    }

    if (last && !*last) *last = *uid;

    return 0;

  noopengroup:
    prot_printf(nntp_out, "412 No newsgroup selected\r\n");
    return -1;

  nocurrent:
    prot_printf(nntp_out, "420 No current article selected\r\n");
    return -1;

  noarticle:
    prot_printf(nntp_out, "423 No such article in this newsgroup\r\n");
    return -1;

  nomsgid:
    prot_printf(nntp_out, "430 No article found with that message-id");
    if (r) prot_printf(nntp_out, " (%s)", error_message(r));
    prot_printf(nntp_out, "\r\n");
    return -1;

  badrange:
    prot_printf(nntp_out, "501 Bad message-id or range\r\n");
    return -1;
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

static int open_group(char *name, int has_prefix,
		      struct backend **ret, int *postable)
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r = 0;
    char *acl, *newserver;
    struct backend *backend_next = NULL;

    /* close local group */
    if (nntp_group) {
	mailbox_close(nntp_group);
	nntp_group = 0;
    }

    if (!has_prefix) {
	snprintf(mailboxname, sizeof(mailboxname), "%s%s", newsprefix, name);
	name = mailboxname;
    }

    if (!r) r = mlookup(name, &newserver, &acl, NULL);

    if (!r && acl) {
	int myrights = cyrus_acl_myrights(nntp_authstate, acl);

	if (postable) *postable = myrights & ACL_POST;
	if (!(myrights & ACL_READ)) {
	    r = (myrights & ACL_LOOKUP) ?
		IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	}
    }

    if (r) return r;

    if (newserver[0] == '/') {
	/* local group */
	int doclose = 0;

	r = mailbox_open_header(name, nntp_authstate, &mboxstruct);

	if (!r) {
	    doclose = 1;
	    r = mailbox_open_index(&mboxstruct);
	}

	if (r) {
	    if (doclose) mailbox_close(&mboxstruct);
	    return r;
	}

	nntp_group = &mboxstruct;
	index_operatemailbox(nntp_group);

	if (ret) *ret = NULL;
    }
    else {
	/* remote group */
	backend_next = proxyd_findserver(newserver);
	if (!backend_next) return IMAP_SERVER_UNAVAILABLE;

	*ret = backend_next;
    }

    syslog(LOG_DEBUG, "open: user %s opened %s",
	   nntp_userid ? nntp_userid : "anonymous", name);

    return 0;
}

static void cmd_article(int part, char *msgid, unsigned long uid)
{
    int msgno, by_msgid;
    char fname[MAX_MAILBOX_PATH+1];
    FILE *msgfile;
    char buf[4096];

    msgno = index_finduid(uid);
    if (!msgno || index_getuid(msgno) != uid) {
	prot_printf(nntp_out, "423 No such article in this newsgroup\r\n");
	return;
    }

    strlcpy(fname, nntp_group->path, sizeof(fname));
    strlcat(fname, "/", sizeof(fname));
    mailbox_message_get_fname(nntp_group, uid, fname + strlen(fname),
			      sizeof(fname) - strlen(fname));

    msgfile = fopen(fname, "r");
    if (!msgfile) {
	prot_printf(nntp_out, "502 Could not read message file\r\n");
	return;
    }

    if (!(by_msgid = msgid != NULL))
	msgid = index_get_msgid(nntp_group, msgno);

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

static void cmd_authinfo_user(char *user)
{
    char *p;

    if (nntp_authstate) {
	prot_printf(nntp_out, "502 Already authenticated\r\n");
	return;
    }

    /* possibly disallow USER */
    if (!(nntp_starttls_done || config_getswitch(IMAPOPT_ALLOWPLAINTEXT))) {
	prot_printf(nntp_out,
		    "483 AUTHINFO USER command only available under a layer\r\n");
	return;
    }

    if (nntp_userid) {
	prot_printf(nntp_out, "381 Must give AUTHINFO PASS command\r\n");
	return;
    }

    if (!(p = canonify_userid(user, NULL, NULL))) {
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

static void cmd_authinfo_pass(char *pass)
{
    char *reply = 0;

    if (nntp_authstate) {
	prot_printf(nntp_out, "502 Already authenticated\r\n");
	return;
    }

    if (!nntp_userid) {
	prot_printf(nntp_out, "480 Must give AUTHINFO USER command first\r\n");
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

	nntp_authstate = auth_newstate(nntp_userid);

	/* Create telemetry log */
	nntp_logfd = telemetry_log(nntp_userid, nntp_in, nntp_out);
    }
}

static void cmd_authinfo_sasl(char *mech, char *resp)
{
    int r, sasl_result;
    char *success_data;
    const int *ssfp;
    char *ssfmsg = NULL;
    const char *canon_user;

    if (nntp_userid) {
	prot_printf(nntp_out, "502 Already authenticated\r\n");
	return;
    }

    r = saslserver(nntp_saslconn, mech, resp, "381 ", nntp_in, nntp_out,
		   &sasl_result, &success_data);

    if (r) {
	const char *errorstring = NULL;

	switch (r) {
	case IMAP_SASL_CANCEL:
	    prot_printf(nntp_out,
			"482 Client canceled authentication\r\n");
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
		prot_printf(nntp_out, "482 %s\r\n", errorstring);
	    } else {
		prot_printf(nntp_out, "482 Error authenticating\r\n");
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
	prot_printf(nntp_out, "482 weird SASL error %d SASL_USERNAME\r\n", 
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
	prot_printf(nntp_out, "282 %s\r\n", success_data);
    else
	prot_printf(nntp_out, "281 Success (%s)\r\n", ssfmsg);

    prot_setsasl(nntp_in,  nntp_saslconn);
    prot_setsasl(nntp_out, nntp_saslconn);

    /* Create telemetry log */
    nntp_logfd = telemetry_log(nntp_userid, nntp_in, nntp_out);
}

static void cmd_hdr(char *cmd, char *hdr, char *msgid,
		    unsigned long uid, unsigned long last)
{
    lcase(hdr);

    prot_printf(nntp_out, "%u Header follows:\r\n", cmd[0] == 'X' ? 221 : 225);

    for (; uid <= last; uid++) {
	char *body;
	int msgno = index_finduid(uid);

	if (!msgno || index_getuid(msgno) != uid) continue;

	/* see if we're looking for metadata */
	if (hdr[0] == ':') {
	    if (!strcasecmp(":size", hdr))
		prot_printf(nntp_out, "%lu %lu\r\n", msgid ? 0 : uid,
			    index_getsize(nntp_group, msgno));
	    else if (!strcasecmp(":lines", hdr))
		prot_printf(nntp_out, "%lu %lu\r\n", msgid ? 0 : uid,
			    index_getlines(nntp_group, msgno));
	    else
		prot_printf(nntp_out, "%lu \r\n", msgid ? 0 : uid);
	}
	else if ((body = index_getheader(nntp_group, msgno, hdr))) {
	    prot_printf(nntp_out, "%lu %s\r\n", msgid ? 0 : uid, body);
	}
    }

    prot_printf(nntp_out, ".\r\n");
}

static void cmd_help(void)
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
    if (tls_enabled() && !nntp_starttls_done)
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
    int r, postable;
    struct backend *be;

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

    /* open the group */
    r = open_group(name, 1, &be, &postable);
    if (r) {
	/* can't open group, skip it */
    }
    else if (be) {
	char *result;

	prot_printf(be->out, "GROUP %s\r\n", name+strlen(newsprefix));

	r = read_response(be, 0, &result);
	if (!r && !strncmp(result, "211 ", 4)) {
	    unsigned count, first, last;

	    sscanf(result, "211 %u %u %u %s", &count, &first, &last, name);
	    prot_printf(nntp_out, "%s %u %u %c\r\n",
			name, last, first, postable & ACL_POST ? 'y' : 'n');
	}
    }
    else {
	prot_printf(nntp_out, "%s %lu %lu %c\r\n", name+strlen(newsprefix),
		    nntp_group->exists ? index_getuid(nntp_group->exists) :
		    nntp_group->last_uid,
		    nntp_group->exists ? index_getuid(1) :
		    nntp_group->last_uid+1,
		    postable ? 'y' : 'n');

	mailbox_close(nntp_group);
	nntp_group = 0;
    }

    return 0;
}

static void cmd_list(char *arg1, char *arg2)
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

	if (mechcount || nntp_starttls_done ||
	    config_getswitch(IMAPOPT_ALLOWPLAINTEXT)) {
	    prot_printf(nntp_out, "AUTHINFO%s\r\n",
			nntp_starttls_done ||
			config_getswitch(IMAPOPT_ALLOWPLAINTEXT) ? " USER" : "");

	    /* add the SASL mechs */
	    if (mechcount) prot_write(nntp_out, mechlist, strlen(mechlist));
	}

	prot_printf(nntp_out, "HDR\r\n");
	prot_printf(nntp_out, "LISTGROUP\r\n");
	prot_printf(nntp_out, "OVER\r\n");
	if (tls_enabled() && !nntp_starttls_done)
	    prot_printf(nntp_out, "STARTTLS\r\n");
	prot_printf(nntp_out, ".\r\n");

	did_extensions = 1;
    }
    else if (!nntp_userid && !config_allowanonymous) {
	prot_printf(nntp_out, "480 Authentication required\r\n");
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
	if (did_extensions) {
	    /* new OVER format */
	    prot_printf(nntp_out, ":bytes\r\n");
	    prot_printf(nntp_out, ":lines\r\n");
	} else {
	    /* old XOVER format */
	    prot_printf(nntp_out, "Bytes:\r\n");
	    prot_printf(nntp_out, "Lines:\r\n");
	}
	prot_printf(nntp_out, ".\r\n");
    }
    else if (!strcmp(arg1, "active.times") || !strcmp(arg1, "distributions") ||
	     !strcmp(arg1, "distrib.pats") || !strcmp(arg1, "newsgroups")) {
	prot_printf(nntp_out, "503 Unsupported LIST command\r\n");
    }
    else {
	prot_printf(nntp_out, "501 Unrecognized LIST command\r\n");
    }
    prot_flush(nntp_out);
}

static void cmd_mode(char *arg)
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
	if (!msgno || index_getuid(msgno) != uid) continue;

	if ((over = index_overview(nntp_group, msgno))) {
	    if (!found++)
		prot_printf(nntp_out, "224 Overview information follows:\r\n");

	    prot_printf(nntp_out, "%lu\t%s\t%s\t%s\t%s\t%s\t%lu\t%lu\r\n",
			over->uid,
			over->subj ? over->subj : "",
			over->from ? over->from : "",
			over->date ? over->date : "",
			over->msgid ? over->msgid : "",
			over->ref ? over->ref : "",
			over->bytes, over->lines);
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
		const char *newspostuser;

		if ((newspostuser = config_getstring(IMAPOPT_NEWSPOSTUSER))) {
		    char buf[1024] = "";
		    const char *sep = "";
		    int n;

		    /* build a To: header */
		    for (n = 0; n < m->rcpt_num; n++) {
			snprintf(buf+strlen(buf), sizeof(buf)-strlen(buf),
				 "%s%s+%s@%s", sep, newspostuser,
				 m->rcpt[n]+strlen(newsprefix),
				 config_servername);
			sep = ", ";
		    }

		    /* add To: header */
		    fprintf(f, "To: %s\r\n", buf);
		}
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
    int n, r, myrights;
    char *rcpt = NULL, *local_rcpt = NULL, *server, *acl;
    time_t now = time(NULL);
    unsigned long uid, backend_mask = 0;

    /* check ACLs of all mailboxes */
    for (n = 0; n < msg->rcpt_num; n++) {
	rcpt = msg->rcpt[n];

	/* look it up */
	r = mlookup(rcpt, &server, &acl, NULL);
	if (r) return IMAP_MAILBOX_NONEXISTENT;

	if (!(acl && (myrights = cyrus_acl_myrights(nntp_authstate, acl)) &&
	      (myrights & ACL_POST)))
	    return IMAP_PERMISSION_DENIED;

	if (server[0] == '/') {
	    /* local group */
	    struct appendstate as;

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

	    local_rcpt = rcpt;
	}
	else {
	    /* remote group */
	    struct backend *be = NULL;
	    unsigned id;
	    char buf[4096];

	    be = proxyd_findserver(server);
	    if (!be) return IMAP_SERVER_UNAVAILABLE;

	    /* check if we've already sent to this backend
	     * XXX this only works for <= 32 backends
	     */
	    if ((id = *((unsigned *) be->context)) < 32) {
		if (backend_mask & (1 << id)) continue;
		backend_mask |= (1 << id);
	    }

	    /* tell the backend about our new article */
	    prot_printf(be->out, "IHAVE %s\r\n", msg->id);
	    prot_flush(be->out);

	    if (!prot_fgets(buf, sizeof(buf), be->in) ||
		strncmp("335", buf, 3)) {
		syslog(LOG_NOTICE, "backend doesn't want article %s", msg->id);
		continue;
	    }

	    /* send the article */
	    rewind(msg->f);
	    while (fgets(buf, sizeof(buf), msg->f)) {
		if (buf[0] == '.') prot_putc('.', be->out);
		do {
		    prot_printf(be->out, "%s", buf);
		} while (buf[strlen(buf)-1] != '\n' &&
			 fgets(buf, sizeof(buf), msg->f));
	    }

	    /* Protect against messages not ending in CRLF */
	    if (buf[strlen(buf)-1] != '\n') prot_printf(be->out, "\r\n");

	    prot_printf(be->out, ".\r\n");

	    if (!prot_fgets(buf, sizeof(buf), be->in) ||
		strncmp("235", buf, 3)) {
		syslog(LOG_WARNING, "article %s transfer failed", msg->id);
		return NNTP_FAIL_TRANSFER;
	    }
	}
    }

    /* store msgid for IHAVE/CHECK/TAKETHIS and reader commands */
    if (have_newsdb && msg->id) {
	if (local_rcpt)
	    netnews_store(msg->id, local_rcpt, uid, msg->lines, now);
	else if (rcpt)
	    netnews_store(msg->id, rcpt, 0, 0, now);
    }

    return  0;
}
#if 0 /* XXX don't process control messages until we implement PGP and ACLs */
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
#endif
static void feedpeer(message_data_t *msg)
{
    const char *peer, *port = "119";
    char *server, *path, *s;
    struct wildmat *wild = NULL, *w;
    int len, err, n, feed = 1;
    struct addrinfo hints, *res, *res0;
    int sock = -1;
    struct protstream *pin, *pout;
    char buf[4096];

    if ((peer = config_getstring(IMAPOPT_NEWSPEER)) == NULL) {
	syslog(LOG_ERR, "no newspeer defined");
	return;
    }

    /* make a working copy of the peer */
    server = xstrdup(peer);

    /* check for a wildmat pattern */
    if ((s = strchr(server, ':'))) {
	*s++ = '\0';
	wild = split_wildmats(s);
    }

    /* check path to see if this message came through our peer */
    len = strlen(server);
    path = msg->path;
    while (path && (s = strchr(path, '!'))) {
	if ((s - path) == len && !strncmp(path, server, len)) {
	    free(server);
	    return;
	}
	path = s + 1;
    }

    /* check newsgroups against wildmat to see if we should feed it */
    if (wild) {
	feed = 0;
	for (n = 0; n < msg->rcpt_num; n++) {
	    /* see if the newsgroup matches one of our wildmats */
	    w = wild;
	    while (w->pat &&
		   wildmat(msg->rcpt[n], w->pat) != 1) {
		w++;
	    }

	    if (w->pat) {
		/* we have a match, check to see what kind of match */
		if (!w->not) {
		    /* positive match, ok to feed, keep checking */
		    feed = 1;
		}
		else if (w->not < 0) {
		    /* absolute negative match, do not feed */
		    feed = 0;
		    break;
		}
		else {
		    /* negative match, keep checking */
		}
	    }
	    else {
		/* no match, keep checking */
	    }
	}

	free_wildmats(wild);
    }

    if (!feed) {
	free(server);
	return;
    }
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    if ((err = getaddrinfo(server, port, &hints, &res0)) != 0) {
	syslog(LOG_ERR, "getaddrinfo(%s, %s) failed: %m", server, port);
	free(server);
	return;
    }

    for (res = res0; res; res = res->ai_next) {
	if ((sock = socket(res->ai_family, res->ai_socktype,
			   res->ai_protocol)) < 0)
	    continue;
	if (connect(sock, res->ai_addr, res->ai_addrlen) >= 0)
	    break;
	close(sock);
	sock = -1;
    }
    freeaddrinfo(res0);
    if(sock < 0) {
	syslog(LOG_ERR, "connect(%s:%s) failed: %m", server, port);
	free(server);
	return;
    }
    free(server);
    
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
#if 0 /* XXX don't process control messages until we implement PGP and ACLs */
	    if (msg->control && !config_mupdate_server) {
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
#endif
	}

	if (!r) {
	    prot_printf(nntp_out, "%u Article %s received ok\r\n",
			post_codes[mode].ok, msg->id ? msg->id : "");

	    if (msg->id) {
		/* send the article upstream */
		feedpeer(msg);
	    }
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

    if (nntp_starttls_done == 1) {
	prot_printf(nntp_out, "502 %s\r\n", 
		    "Already successfully executed STARTTLS");
	return;
    }

    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &ssf;

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
