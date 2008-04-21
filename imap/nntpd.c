/* nntpd.c -- NNTP server
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
 * $Id: nntpd.c,v 1.67 2008/04/21 15:55:01 murch Exp $
 */

/*
 * TODO:
 *
 * - add sender and PGP verification code for control messages
 * - figure out what to do with control messages when proxying
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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "assert.h"
#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "auth.h"
#include "backend.h"
#include "duplicate.h"
#include "exitcodes.h"
#include "global.h"
#include "hash.h"
#include "idle.h"
#include "imap_err.h"
#include "index.h"
#include "iptostring.h"
#include "mailbox.h"
#include "map.h"
#include "mboxlist.h"
#include "mkgmtime.h"
#include "mupdate-client.h"
#include "nntp_err.h"
#include "prot.h"
#include "proxy.h"
#include "retry.h"
#include "rfc822date.h"
#include "smtpclient.h"
#include "spool.h"
#include "sync_log.h"
#include "telemetry.h"
#include "tls.h"
#include "util.h"
#include "version.h"
#include "wildmat.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

extern int optind;
extern char *optarg;
extern int opterr;

/* Stuff to make index.c link */
int imapd_exists;
struct protstream *imapd_out = NULL;
struct auth_state *imapd_authstate = NULL;
char *imapd_userid = NULL;
int imapd_condstore_client = 0;

void printastring(const char *s __attribute__((unused)))
{
    fatal("not implemented", EC_SOFTWARE);
}
/* end stuff to make index.c link */

/* PROXY STUFF */
/* we want a list of our outgoing connections here and which one we're
   currently piping */

/* the current server most commands go to */
struct backend *backend_current = NULL;

/* our cached connections */
struct backend **backend_cached = NULL;

#ifdef HAVE_SSL
static SSL *tls_conn;
#endif /* HAVE_SSL */

sasl_conn_t *nntp_saslconn; /* the sasl connection context */

int nntp_timeout;
char newsprefix[100] = "";
char *nntp_userid = 0, *newsmaster;
struct auth_state *nntp_authstate = 0, *newsmaster_authstate;
static struct mailbox *nntp_group = 0;
struct sockaddr_storage nntp_localaddr, nntp_remoteaddr;
int nntp_haveaddr = 0;
char nntp_clienthost[NI_MAXHOST*2+1] = "[local]";
struct protstream *nntp_out = NULL;
struct protstream *nntp_in = NULL;
struct protgroup *protin = NULL;
static int nntp_logfd = -1;
unsigned nntp_exists = 0;
unsigned nntp_current = 0;
unsigned did_capabilities = 0;
int allowanonymous = 0;
int singleinstance = 1;	/* attempt single instance store */

struct stagemsg *stage = NULL;

/* Bitmasks for NNTP modes */
enum {
    MODE_READ =	(1<<0),
    MODE_FEED =	(1<<1)
};

static unsigned nntp_capa = MODE_READ | MODE_FEED; /* general-purpose */

static sasl_ssf_t extprops_ssf = 0;
static int nntps = 0;
int nntp_starttls_done = 0;

static struct mailbox mboxstruct;

/* the sasl proxy policy context */
static struct proxy_context nntp_proxyctx = {
    0, 1, &nntp_authstate, NULL, NULL
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
    POST_TAKETHIS = 3
};

/* response codes for each stage of posting */
struct {
    int ok, cont, no, fail;
} post_codes[] = { { 240, 340, 440, 441 },
		   { 235, 335, 435, 436 },
		   {  -1, 238, 438,  -1 },
		   { 239,  -1,  -1, 439 } };

struct wildmat {
    char *pat;
    int not;
};

static struct wildmat *split_wildmats(char *str);
static void free_wildmats(struct wildmat *wild);

static void cmdloop(void);
static int open_group(char *name, int has_prefix,
		      struct backend **ret, int *postable);
static int parserange(char *str, unsigned long *uid, unsigned long *last,
		      char **msgid, struct backend **be);
static time_t parse_datetime(char *datestr, char *timestr, char *gmt);
static void cmd_article(int part, char *msgid, unsigned long uid);
static void cmd_authinfo_user(char *user);
static void cmd_authinfo_pass(char *pass);
static void cmd_authinfo_sasl(char *cmd, char *mech, char *resp);
static void cmd_capabilities(char *keyword);
static void cmd_hdr(char *cmd, char *hdr, char *pat, char *msgid,
		    unsigned long uid, unsigned long last);
static void cmd_help(void);
static void cmd_list(char *arg1, char *arg2);
static void cmd_mode(char *arg);
static void cmd_newgroups(time_t tstamp);
static void cmd_newnews(char *wild, time_t tstamp);
static void cmd_over(char *msgid, unsigned long uid, unsigned long last);
static void cmd_post(char *msgid, int mode);
static void cmd_starttls(int nntps);
void usage(void);
void shut_down(int code) __attribute__ ((noreturn));


extern void setproctitle_init(int argc, char **argv, char **envp);
extern int proc_register(const char *progname, const char *clienthost, 
			 const char *userid, const char *mailbox);
extern void proc_cleanup(void);

extern int saslserver(sasl_conn_t *conn, const char *mech,
		      const char *init_resp, const char *resp_prefix,
		      const char *continuation, const char *empty_resp,
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

static char *nntp_parsesuccess(char *str, const char **status)
{
    char *success = NULL;

    if (!strncmp(str, "283 ", 4)) {
	success = str+4;
    }

    if (status) *status = NULL;
    return success;
}

static struct protocol_t nntp_protocol =
{ "nntp", "nntp",
  { 0, "20" },
  { "CAPABILITIES", NULL, ".", NULL,
    { { "SASL ", CAPA_AUTH },
      { "STARTTLS", CAPA_STARTTLS },
      { NULL, 0 } } },
  { "STARTTLS", "382", "580", 0 },
  { "AUTHINFO SASL", 512, 0, "28", "48", "383 ", "*", &nntp_parsesuccess },
  { "DATE", NULL, "111" },
  { "QUIT", NULL, "205" }
};

/* proxy mboxlist_lookup; on misses, it asks the listener for this
   machine to make a roundtrip to the master mailbox server to make
   sure it's up to date */
static int mlookup(const char *name, char **server, char **aclp, void *tid)
{
    int r, type;

    if(server) *server = NULL;

    r = mboxlist_detail(name, &type, NULL, NULL, server, aclp, tid);
    if (r == IMAP_MAILBOX_NONEXISTENT && config_mupdate_server) {
	kick_mupdate();
	r = mboxlist_detail(name, &type, NULL, NULL, server, aclp, tid);
    }

    if (type & MBTYPE_REMOTE) {
	/* xxx hide the fact that we are storing partitions */
	if(server && *server) {
	    char *c;
	    c = strchr(*server, '!');
	    if(c) *c = '\0';
	}
    }
    else if (server)
	*server = NULL;

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
	proxy_downserver(s);
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
	    proxy_downserver(s);
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
    while (backend_cached && backend_cached[i]) {
	proxy_downserver(backend_cached[i]);
	free(backend_cached[i]->context);
	free(backend_cached[i]);
	i++;
    }
    if (backend_cached) free(backend_cached);
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

    if (protin) protgroup_reset(protin);

#ifdef HAVE_SSL
    if (tls_conn) {
	tls_reset_servertls(&tls_conn);
	tls_conn = NULL;
    }
#endif

    cyrus_reset_stdio();

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
    did_capabilities = 0;
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
    signal(SIGPIPE, SIG_IGN);

    /* load the SASL plugins */
    global_sasl_init(1, 1, mysasl_cb);

    if ((prefix = config_getstring(IMAPOPT_NEWSPREFIX)))
	snprintf(newsprefix, sizeof(newsprefix), "%s.", prefix);

    /* initialize duplicate delivery database */
    if (duplicate_init(NULL, 0) != 0) {
	syslog(LOG_ERR, 
	       "unable to init duplicate delivery database\n");
	fatal("unable to init duplicate delivery database", EC_SOFTWARE);
    }

    /* open the mboxlist, we'll need it for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);

    /* open the quota db, we'll need it for expunge */
    quotadb_init(0);
    quotadb_open(NULL);

    /* setup for sending IMAP IDLE notifications */
    idle_enabled();

    while ((opt = getopt(argc, argv, "srfp:")) != EOF) {
	switch(opt) {
	case 's': /* nntps (do starttls right away) */
	    nntps = 1;
	    if (!tls_enabled()) {
		syslog(LOG_ERR, "nntps: required OpenSSL options not present");
		fatal("nntps: required OpenSSL options not present",
		      EC_CONFIG);
	    }
	    break;

	case 'r': /* enter reader-only mode */
	    nntp_capa = MODE_READ;
	    break;

	case 'f': /* enter feeder-only mode */
	    nntp_capa = MODE_FEED;
	    break;

	case 'p': /* external protection */
	    extprops_ssf = atoi(optarg);
	    break;

	default:
	    usage();
	}
    }

    /* Initialize the annotatemore extention */
    annotatemore_init(0, NULL, NULL);
    annotatemore_open(NULL);

    newsmaster = (char *) config_getstring(IMAPOPT_NEWSMASTER);
    newsmaster_authstate = auth_newstate(newsmaster);

    singleinstance = config_getswitch(IMAPOPT_SINGLEINSTANCESTORE);

    /* Create a protgroup for input from the client and selected backend */
    protin = protgroup_new(2);

    return 0;
}

/*
 * run for each accepted connection
 */
int service_main(int argc __attribute__((unused)),
		 char **argv __attribute__((unused)),
		 char **envp __attribute__((unused)))
{
    socklen_t salen;
    char localip[60], remoteip[60];
    char hbuf[NI_MAXHOST];
    int niflags;
    sasl_security_properties_t *secprops=NULL;
    int shutdown;
    char unavail[1024];

    signals_poll();

    sync_log_init();

    nntp_in = prot_new(0, 0);
    nntp_out = prot_new(1, 1);
    protgroup_insert(protin, nntp_in);

    /* Find out name of client host */
    salen = sizeof(nntp_remoteaddr);
    if (getpeername(0, (struct sockaddr *)&nntp_remoteaddr, &salen) == 0 &&
	(nntp_remoteaddr.ss_family == AF_INET ||
	 nntp_remoteaddr.ss_family == AF_INET6)) {
	if (getnameinfo((struct sockaddr *)&nntp_remoteaddr, salen,
			hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) == 0) {
	    strncpy(nntp_clienthost, hbuf, sizeof(hbuf));
	    strlcat(nntp_clienthost, " ", sizeof(nntp_clienthost));
	    nntp_clienthost[sizeof(nntp_clienthost)-30] = '\0';
	} else {
	    nntp_clienthost[0] = '\0';
	}
	niflags = NI_NUMERICHOST;
#ifdef NI_WITHSCOPEID
	if (((struct sockaddr *)&nntp_remoteaddr)->sa_family == AF_INET6)
	    niflags |= NI_WITHSCOPEID;
#endif
	if (getnameinfo((struct sockaddr *)&nntp_remoteaddr, salen, hbuf,
			sizeof(hbuf), NULL, 0, niflags) != 0)
	    strlcpy(hbuf, "unknown", sizeof(hbuf));
	strlcat(nntp_clienthost, "[", sizeof(nntp_clienthost));
	strlcat(nntp_clienthost, hbuf, sizeof(nntp_clienthost));
	strlcat(nntp_clienthost, "]", sizeof(nntp_clienthost));
	salen = sizeof(nntp_localaddr);
	if (getsockname(0, (struct sockaddr *)&nntp_localaddr, &salen) == 0) {
	    nntp_haveaddr = 1;
	}
    }

    /* other params should be filled in */
    if (sasl_server_new("nntp", config_servername, NULL, NULL, NULL,
			NULL, SASL_SUCCESS_DATA, &nntp_saslconn) != SASL_OK)
	fatal("SASL failed initializing: sasl_server_new()",EC_TEMPFAIL); 

    /* will always return something valid */
    secprops = mysasl_secprops(0);
    sasl_setprop(nntp_saslconn, SASL_SEC_PROPS, secprops);
    sasl_setprop(nntp_saslconn, SASL_SSF_EXTERNAL, &extprops_ssf);
    
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
    nntp_timeout = config_getint(IMAPOPT_NNTPTIMEOUT);
    if (nntp_timeout < 3) nntp_timeout = 3;
    nntp_timeout *= 60;
    prot_settimeout(nntp_in, nntp_timeout);
    prot_setflushonread(nntp_in, nntp_out);

    /* we were connected on nntps port so we should do 
       TLS negotiation immediatly */
    if (nntps == 1) cmd_starttls(1);

    if ((shutdown = shutdown_file(unavail, sizeof(unavail)))) {
	prot_printf(nntp_out, "%u", 400);
    } else {
	prot_printf(nntp_out, "%u", (nntp_capa & MODE_READ) ? 200 : 201);
    }
    if (config_serverinfo) prot_printf(nntp_out, " %s", config_servername);
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	prot_printf(nntp_out, " Cyrus NNTP%s %s",
		    config_mupdate_server ? " Murder" : "", CYRUS_VERSION);
    }
    if (shutdown) {
	prot_printf(nntp_out, "server unavailable, %s\r\n", unavail);
	shut_down(0);
    }
    else {
	prot_printf(nntp_out, " server ready, posting %s\r\n",
		    (nntp_capa & MODE_READ) ? "allowed" : "prohibited");
    }

    cmdloop();

    /* QUIT executed */

    /* cleanup */
    nntp_reset();

    return 0;
}

/* Called by service API to shut down the service */
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
	proxy_downserver(backend_cached[i]);
	free(backend_cached[i]->context);
	free(backend_cached[i]);
	i++;
    }
    if (backend_cached) free(backend_cached);

    duplicate_done();

    mboxlist_close();
    mboxlist_done();

    quotadb_close();
    quotadb_done();

    annotatemore_close();
    annotatemore_done();

    if (nntp_in) {
	prot_NONBLOCK(nntp_in);
	prot_fill(nntp_in);
	prot_free(nntp_in);
    }

    if (nntp_out) {
	prot_flush(nntp_out);
	prot_free(nntp_out);
    }

    if (protin) protgroup_free(protin);

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
    if (stage) append_removestage(stage);
    syslog(LOG_ERR, "Fatal error: %s", s);
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
    secprops = mysasl_secprops(0);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
    if(saslprops.ssf) {
	ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &saslprops.ssf);
    } else {
	ret = sasl_setprop(*conn, SASL_SSF_EXTERNAL, &extprops_ssf);
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
    unsigned long uid, last;
    struct backend *be;

    allowanonymous = config_getswitch(IMAPOPT_ALLOWANONYMOUSLOGIN);

    for (;;) {
	/* Flush any buffered output */
	prot_flush(nntp_out);
	if (backend_current) prot_flush(backend_current->out);

	/* Check for shutdown file */
	if (shutdown_file(buf, sizeof(buf))) {
	    prot_printf(nntp_out, "400 %s\r\n", buf);
	    shut_down(0);
	}

	signals_poll();

	if (!proxy_check_input(protin, nntp_in, nntp_out,
			       backend_current ? backend_current->in : NULL,
			       NULL, 0)) {
	    /* No input from client */
	    continue;
	}

	/* Parse command name */
	c = getword(nntp_in, &cmd);
	if (c == EOF) {
	    if ((err = prot_error(nntp_in)) != NULL
		 && strcmp(err, PROT_EOF_STRING)) {
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

	/* Ihave/Takethis only allowed for feeders */
	if (!(nntp_capa & MODE_FEED) &&
	    strchr("IT", cmd.s[0])) goto noperm;
    
	/* Body/Date/Group/Newgroups/Newnews/Next/Over/Post/Xhdr/Xover/Xpat
	   only allowed for readers */
	if (!(nntp_capa & MODE_READ) &&
	    strchr("BDGNOPX", cmd.s[0])) goto noperm;
    
	/* Only Authinfo/Capabilities/Check/Head/Help/Ihave/List Active/
	   Mode/Quit/Starttls/Stat/Takethis allowed when not logged in */
	if (!nntp_userid && !allowanonymous &&
	    !strchr("ACHILMQST", cmd.s[0])) goto nologin;

	switch (cmd.s[0]) {
	case 'A':
	    if (!strcmp(cmd.s, "Authinfo")) {
		arg2.len = arg3.len = 0;
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg1); /* subcommand */
		if (c == EOF) goto missingargs;

		lcase(arg1.s);

		if (strcmp(arg1.s, "generic") && c != ' ') {
		    /* arg2 is required for all subcommands except generic */
		    goto missingargs;
		}
		if (c == ' ') {
		    c = getword(nntp_in, &arg2); /* argument/sasl mech */
		    if (c == EOF) goto missingargs;
		}

		if (!strcmp(arg1.s, "sasl") && c == ' ') {
		    c = getword(nntp_in, &arg3); /* init response (optional) */
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		if (!strcmp(arg1.s, "user"))
		    cmd_authinfo_user(arg2.s);
		else if (!strcmp(arg1.s, "pass"))
		    cmd_authinfo_pass(arg2.s);
		else if (!strcmp(arg1.s, "sasl") || !strcmp(arg1.s, "generic"))
		    cmd_authinfo_sasl(arg1.s, arg2.len ? arg2.s : NULL,
				      arg3.len ? arg3.s : NULL);
		else
		    prot_printf(nntp_out,
				"501 Unrecognized AUTHINFO command\r\n");
	    }
	    else if (!(nntp_capa & MODE_READ)) goto noperm;
	    else if (!nntp_userid && !allowanonymous) goto nologin;
	    else if (!strcmp(cmd.s, "Article")) {
		char curgroup[MAX_MAILBOX_NAME+1], *msgid;

		mode = ARTICLE_ALL;

	      article:
		if (arg1.s) *arg1.s = 0;

		if (c == ' ') {
		    c = getword(nntp_in, &arg1); /* number/msgid (optional) */
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

			if (be != backend_current) {
			    r = read_response(be, 0, &result);
			    if (r) goto noopengroup;

			    prot_printf(nntp_out, "%s", result);
			    if (!strncmp(result, "22", 2) &&
				mode != ARTICLE_STAT) {
				pipe_to_end_of_response(be, 0);
			    }
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
	    if (!strcmp(cmd.s, "Capabilities")) {
		arg1.len = 0;

		if (c == ' ') {
		    c = getword(nntp_in, &arg1); /* keyword (optional) */
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		cmd_capabilities(arg1.s);
	    }
	    else if (!(nntp_capa & MODE_FEED)) goto noperm;
	    else if (!strcmp(cmd.s, "Check")) {
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
		c = getword(nntp_in, &arg1); /* group */
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		r = open_group(arg1.s, 0, &be, NULL);
		if (r) goto nogroup;
		else if (be) {
		    prot_printf(be->out, "GROUP %s\r\n", arg1.s);
		    r = read_response(be, 0, &result);
		    if (r) goto nogroup;

		    prot_printf(nntp_out, "%s", result);

		    if (!strncmp(result, "211", 3)) {
			if (backend_current && backend_current != be) {
			    /* remove backend_current from the protgroup */
			    protgroup_delete(protin, backend_current->in);
			}
			backend_current = be;

			/* add backend_current to the protgroup */
			protgroup_insert(protin, backend_current->in);
		    }
		}
		else {
		    if (backend_current) {
			/* remove backend_current from the protgroup */
			protgroup_delete(protin, backend_current->in);
		    }
		    backend_current = NULL;

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
	    else if (!(nntp_capa & MODE_READ)) goto noperm;
	    else if (!nntp_userid && !allowanonymous) goto nologin;
	    else if (!strcmp(cmd.s, "Hdr")) {
		char curgroup[MAX_MAILBOX_NAME+1], *msgid;

	      hdr:
		if (arg2.s) *arg2.s = 0;

		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg1); /* header */
		if (c == EOF) goto missingargs;
		if (c == ' ') {
		    c = getword(nntp_in, &arg2); /* range (optional) */
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

			if (be != backend_current) {
			    r = read_response(be, 0, &result);
			    if (r) goto noopengroup;

			    prot_printf(nntp_out, "%s", result);
			    if (!strncmp(result, "22", 2)) { /* 221 or 225 */
				pipe_to_end_of_response(be, 0);
			    }
			}
		    }
		    else
			cmd_hdr(cmd.s, arg1.s, NULL, msgid, uid, last);
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
		c = getword(nntp_in, &arg1); /* msgid */
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
		    c = getword(nntp_in, &arg1); /* subcommand (optional) */
		    if (c == EOF) goto missingargs;
		    if (c == ' ') {
			c = getword(nntp_in, &arg2); /* argument (optional) */
			if (c == EOF) goto missingargs;
		    }
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		cmd_list(arg1.len ? arg1.s : NULL, arg2.len ? arg2.s : NULL);
	    }
	    else if (!(nntp_capa & MODE_READ)) goto noperm;
	    else if (!nntp_userid && !allowanonymous) goto nologin;
	    else if (!strcmp(cmd.s, "Last")) {
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		if (backend_current) {
		    prot_printf(backend_current->out, "LAST\r\n");
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
		arg2.s = arg2.s ? strcpy(arg2.s, "1-") : "1-";
		be = backend_current;

		if (c == ' ') {
		    c = getword(nntp_in, &arg1); /* group (optional) */
		    if (c == EOF) goto missingargs;
		    if (c == ' ') {
			c = getword(nntp_in, &arg2); /* range (optional) */
			if (c == EOF) goto missingargs;
		    }
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		if (arg1.len) {
		    r = open_group(arg1.s, 0, &be, NULL);
		    if (r) goto nogroup;
		}

		if (be) {
		    if (arg1.len)
			prot_printf(be->out, "LISTGROUP %s %s\r\n",
				    arg1.s, arg2.s);
		    else
			prot_printf(be->out, "LISTGROUP\r\n");

		    r = read_response(be, 0, &result);
		    if (r) goto noopengroup;

		    prot_printf(nntp_out, "%s", result);

		    if (!strncmp(result, "211", 3)) {
			pipe_to_end_of_response(be, 0);

			if (backend_current && backend_current != be) {
			    /* remove backend_current from the protgroup */
			    protgroup_delete(protin, backend_current->in);
			}
			backend_current = be;

			/* add backend_current to the protgroup */
			protgroup_insert(protin, backend_current->in);
		    }
		}
		else if (!nntp_group) goto noopengroup;
		else if (parserange(arg2.s, &uid, &last, NULL, NULL) != -1) {
		    int msgno, last_msgno;

		    if (backend_current) {
			/* remove backend_current from the protgroup */
			protgroup_delete(protin, backend_current->in);
		    }
		    backend_current = NULL;

		    nntp_exists = nntp_group->exists;
		    nntp_current = nntp_exists > 0;

		    prot_printf(nntp_out, "211 %u %lu %lu %s\r\n",
				nntp_exists,
				nntp_exists ? index_getuid(1) :
				nntp_group->last_uid+1,
				nntp_exists ? index_getuid(nntp_exists) :
				nntp_group->last_uid,
				nntp_group->name + strlen(newsprefix));

		    msgno = index_finduid(uid);
		    if (!msgno || index_getuid(msgno) != uid) msgno++;
		    last_msgno = index_finduid(last);

		    for (; msgno <= last_msgno; msgno++)
			prot_printf(nntp_out, "%u\r\n", index_getuid(msgno));
		    prot_printf(nntp_out, ".\r\n");
		}
	    }
	    else goto badcmd;
	    break;

	case 'M':
	    if (!strcmp(cmd.s, "Mode")) {
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg1); /* mode */
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		cmd_mode(arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'N':
	    if (!strcmp(cmd.s, "Newgroups")) {
		time_t tstamp;

		arg3.len = 0;
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg1); /* date */
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg2); /* time */
		if (c == EOF) goto missingargs;
		if (c == ' ') {
		    c = getword(nntp_in, &arg3); /* "GMT" (optional) */
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		if ((tstamp = parse_datetime(arg1.s, arg2.s,
					     arg3.len ? arg3.s : NULL)) < 0)
		    goto baddatetime;

		cmd_newgroups(tstamp);
	    }
	    else if (!strcmp(cmd.s, "Newnews")) {
		time_t tstamp;

		if (!config_getswitch(IMAPOPT_ALLOWNEWNEWS))
		    goto cmddisabled;

		arg4.len = 0;
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg1); /* wildmat */
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg2); /* date */
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg3); /* time */
		if (c == EOF) goto missingargs;
		if (c == ' ') {
		    c = getword(nntp_in, &arg4); /* "GMT" (optional) */
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		if ((tstamp = parse_datetime(arg2.s, arg3.s,
					     arg4.len ? arg4.s : NULL)) < 0)
		    goto baddatetime;

		cmd_newnews(arg1.s, tstamp);
	    }
	    else if (!strcmp(cmd.s, "Next")) {
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		if (backend_current) {
		    prot_printf(backend_current->out, "NEXT\r\n");
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
		char curgroup[MAX_MAILBOX_NAME+1], *msgid;

	      over:
		if (arg1.s) *arg1.s = 0;

		if (c == ' ') {
		    c = getword(nntp_in, &arg1); /* range/msgid (optional) */
		    if (c == EOF) goto missingargs;
		}
		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		/* in case a msgid makes us switch groups */
		strcpy(curgroup, nntp_group ? nntp_group->name : "");

		msgid = NULL;
		if (parserange(arg1.s, &uid, &last,
			       /* XOVER doesn't accept message-id */
			       (cmd.s[0] == 'X' ? NULL : &msgid), &be) != -1) {
		    if (be) {
			if (arg1.s && *arg1.s)
			    prot_printf(be->out, "%s %s\r\n", cmd.s, arg1.s);
			else
			    prot_printf(be->out, "%s\r\n", cmd.s);

			if (be != backend_current) {
			    r = read_response(be, 0, &result);
			    if (r) goto noopengroup;

			    prot_printf(nntp_out, "%s", result);
			    if (!strncmp(result, "224", 3)) {
				pipe_to_end_of_response(be, 0);
			    }
			}
		    }
		    else
			cmd_over(msgid, uid, last);
		}

		/* return to previously selected group */
		if (*curgroup && nntp_group &&
		    strcmp(curgroup, nntp_group->name)) {
		       open_group(curgroup, 1, NULL, NULL);
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

		prot_printf(nntp_out, "205 Connection closing\r\n");
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
	    else if (!nntp_userid && !allowanonymous) goto nologin;
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
	    else if (!strcmp(cmd.s, "Xpat")) {
		char curgroup[MAX_MAILBOX_NAME+1], *msgid;

		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg1); /* header */
		if (c != ' ') goto missingargs;

		/* gobble extra whitespace (hack for Mozilla) */
		while ((c = prot_getc(nntp_in)) == ' ');
		prot_ungetc(c, nntp_in);

		c = getword(nntp_in, &arg2); /* range */
		if (c != ' ') goto missingargs;
		c = getword(nntp_in, &arg3); /* wildmat */
		if (c == EOF) goto missingargs;

		/* XXX per RFC 2980, we can have multiple patterns */

		if (c == '\r') c = prot_getc(nntp_in);
		if (c != '\n') goto extraargs;

		/* in case a msgid makes us switch groups */
		strcpy(curgroup, nntp_group ? nntp_group->name : "");

		if (parserange(arg2.s, &uid, &last, &msgid, &be) != -1) {
		    if (be) {
			prot_printf(be->out, "%s %s %s %s\r\n",
				    cmd.s, arg1.s, arg2.s, arg3.s);

			if (be != backend_current) {
			    r = read_response(be, 0, &result);
			    if (r) goto noopengroup;

			    prot_printf(nntp_out, "%s", result);
			    if (!strncmp(result, "221", 3)) {
				pipe_to_end_of_response(be, 0);
			    }
			}
		    }
		    else
			cmd_hdr(cmd.s, arg1.s, arg3.s, msgid, uid, last);
		}

		/* return to previously selected group */
		if (*curgroup && nntp_group &&
		    strcmp(curgroup, nntp_group->name)) {
		       open_group(curgroup, 1, NULL, NULL);
		}
	    }
	    else goto badcmd;
	    break;

	default:
	  badcmd:
	    prot_printf(nntp_out, "500 Unrecognized command\r\n");
	    eatline(nntp_in, c);
	}

	continue;

      noperm:
	prot_printf(nntp_out, "502 Permission denied\r\n");
	eatline(nntp_in, c);
	continue;

      nologin:
	prot_printf(nntp_out, "480 Authentication required\r\n");
	eatline(nntp_in, c);
	continue;

      cmddisabled:
	prot_printf(nntp_out, "503 \"%s\" disabled\r\n", cmd.s);
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
	prot_printf(nntp_out, "420 Current article number is invalid\r\n");
	continue;
    }
}

struct findrock {
    const char *mailbox;
    unsigned long uid;
};

/*
 * duplicate_find() callback function to fetch a message by msgid
 */
static int find_cb(const char *msgid __attribute__((unused)),
		   const char *mailbox,
		   time_t mark __attribute__((unused)),
		   unsigned long uid, void *rock)
{
    struct findrock *frock = (struct findrock *) rock;

    /* make sure its a message in a mailbox that we're serving via NNTP */
    if (!strncmp(mailbox, "user.", 5) ||
	strncmp(mailbox, newsprefix, strlen(newsprefix))) return 0;

    frock->mailbox = mailbox;
    frock->uid = uid;

    return CYRUSDB_DONE;
}

static int find_msgid(char *msgid, char **mailbox, unsigned long *uid)
{
    struct findrock frock = { NULL, 0 };

    duplicate_find(msgid, &find_cb, &frock);

    if (!frock.mailbox) return 0;

    if (mailbox) {
	if (!frock.mailbox[0]) return 0;
	*mailbox = (char *) frock.mailbox;
    }
    if (uid) {
	if (!frock.uid) return 0;
	*uid = frock.uid;
    }

    return 1;
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
	/* no argument, use current article */
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
	if (!find_msgid(str, &mboxname, uid)) goto nomsgid;
	if (!nntp_group || strcmp(mboxname, nntp_group->name)) {
	    if ((r = open_group(mboxname, 1, ret, NULL))) goto nomsgid;
	    *msgid = str;
	}
	/* else, within the current group, so treat as by uid */
    }
    else if (backend_current)
	*ret = backend_current;
    else if (!nntp_group) goto noopengroup;
    else if ((*uid = parsenum(str, &p)) <= 0) goto badrange;
    else if (p && *p) {
	/* extra stuff, check for range */
	if (!last || (*p != '-')) goto badrange;
	if (*++p)
	    *last = parsenum(p, NULL);
	else
	    *last = index_getuid(nntp_exists);
    }

    if (last && !*last) *last = *uid;

    return 0;

  noopengroup:
    prot_printf(nntp_out, "412 No newsgroup selected\r\n");
    return -1;

  nocurrent:
    prot_printf(nntp_out, "420 Current article number is invalid\r\n");
    return -1;

  nomsgid:
    prot_printf(nntp_out, "430 No article found with that message-id");
    if (r) prot_printf(nntp_out, " (%s)", error_message(r));
    prot_printf(nntp_out, "\r\n");
    return -1;

  badrange:
    prot_printf(nntp_out, "501 Bad message-id, message number, or range\r\n");
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
    if (d == ULONG_MAX || *p) return -1;

    /* convert timestr to ulong */
    t = strtoul(timestr, &p, 10);
    if (t == ULONG_MAX || *p) return -1;

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

static int open_group(char *name, int has_prefix, struct backend **ret,
		      int *postable /* used for LIST ACTIVE only */)
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
	if (!postable && /* allow limited 'r' for LIST ACTIVE */
	    !(myrights & ACL_READ)) {
	    r = (myrights & ACL_LOOKUP) ?
		IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	}
    }

    if (r) return r;

    if (newserver) {
	/* remote group */
	backend_next = proxy_findserver(newserver, &nntp_protocol,
					nntp_userid ? nntp_userid : "anonymous",
					&backend_cached, &backend_current,
					NULL, nntp_in);
	if (!backend_next) return IMAP_SERVER_UNAVAILABLE;

	*ret = backend_next;
    }
    else {
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

    syslog(LOG_DEBUG, "open: user %s opened %s",
	   nntp_userid ? nntp_userid : "anonymous", name);

    return 0;
}

static void cmd_capabilities(char *keyword __attribute__((unused)))
{
    const char *mechlist;
    int mechcount = 0;

    prot_printf(nntp_out, "101 Capability list follows:\r\n");
    prot_printf(nntp_out, "VERSION 2\r\n");
    if (nntp_authstate || (config_serverinfo == IMAP_ENUM_SERVERINFO_ON)) {
	prot_printf(nntp_out,
		    "IMPLEMENTATION Cyrus NNTP%s %s\r\n",
		    config_mupdate_server ? " Murder" : "", CYRUS_VERSION);
    }

    /* add STARTTLS */
    if (tls_enabled() && !nntp_starttls_done && !nntp_authstate)
	prot_printf(nntp_out, "STARTTLS\r\n");

    /* check for SASL mechs */
    sasl_listmech(nntp_saslconn, NULL, "SASL ", " ", "\r\n",
		  &mechlist, NULL, &mechcount);

    /* add the AUTHINFO variants */
    if (!nntp_authstate) {
	prot_printf(nntp_out, "AUTHINFO%s%s\r\n",
		    (nntp_starttls_done || (extprops_ssf > 1) ||
		     config_getswitch(IMAPOPT_ALLOWPLAINTEXT)) ?
		    " USER" : "", mechcount ? " SASL" : "");
    }

    /* add the SASL mechs */
    if (mechcount) prot_printf(nntp_out, "%s", mechlist);

    /* add the reader capabilities/extensions */
    if ((nntp_capa & MODE_READ) && (nntp_userid || allowanonymous)) {
	prot_printf(nntp_out, "READER\r\n");
	prot_printf(nntp_out, "POST\r\n");
	if (config_getswitch(IMAPOPT_ALLOWNEWNEWS))
	    prot_printf(nntp_out, "NEWNEWS\r\n");
	prot_printf(nntp_out, "HDR\r\n");
	prot_printf(nntp_out, "OVER\r\n");
	prot_printf(nntp_out, "XPAT\r\n");
    }

    /* add the feeder capabilities/extensions */
    if (nntp_capa & MODE_FEED) {
	prot_printf(nntp_out, "IHAVE\r\n");
	prot_printf(nntp_out, "STREAMING\r\n");
    }

    /* add the LIST variants */
    prot_printf(nntp_out, "LIST ACTIVE%s\r\n",
		((nntp_capa & MODE_READ) && (nntp_userid || allowanonymous)) ?
		" HEADERS NEWSGROUPS OVERVIEW.FMT" : "");

    prot_printf(nntp_out, ".\r\n");

    did_capabilities = 1;
}

/*
 * duplicate_find() callback function to build Xref content
 */
struct xref_rock {
    char *buf;
    size_t size;
};

static int xref_cb(const char *msgid __attribute__((unused)),
		   const char *mailbox,
		   time_t mark __attribute__((unused)),
		   unsigned long uid, void *rock)
{
    struct xref_rock *xrock = (struct xref_rock *) rock;
    size_t len = strlen(xrock->buf);

    /* make sure its a message in a mailbox that we're serving via NNTP */
    if (*mailbox && !strncmp(mailbox, newsprefix, strlen(newsprefix)) &&
	strncmp(mailbox, "user.", 5)) {
	snprintf(xrock->buf + len, xrock->size - len,
		 " %s:%lu", mailbox + strlen(newsprefix), uid);
    }

    return 0;
}

/*
 * Build an Xref header.  We have to do this on the fly because there is
 * no way to store it in the article at delivery time.
 */
static void build_xref(char *msgid, char *buf, size_t size, int body_only)
{
    struct xref_rock xrock = { buf, size };

    snprintf(buf, size, "%s%s", body_only ? "" : "Xref: ", config_servername);
    duplicate_find(msgid, &xref_cb, &xrock);
}

static void cmd_article(int part, char *msgid, unsigned long uid)
{
    int msgno, by_msgid = (msgid != NULL);
    char fname[MAX_MAILBOX_PATH+1];
    FILE *msgfile;

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

    nntp_current = msgno;

    if (!by_msgid) msgid = index_get_msgid(nntp_group, msgno);

    prot_printf(nntp_out, "%u %lu %s\r\n",
		220 + part, by_msgid ? 0 : uid, msgid ? msgid : "<0>");

    if (part != ARTICLE_STAT) {
	char buf[4096];
	int body = 0;
	int output = (part != ARTICLE_BODY);

	while (fgets(buf, sizeof(buf), msgfile)) {

	    if (!body && buf[0] == '\r' && buf[1] == '\n') {
		/* blank line between header and body */
		body = 1;
		if (output) {
		    /* add the Xref header */
		    char xref[8192];

		    build_xref(msgid, xref, sizeof(xref), 0);
		    prot_printf(nntp_out, "%s\r\n", xref);
		}
		if (part == ARTICLE_HEAD) {
		    /* we're done */
		    break;
		}
		else if (part == ARTICLE_BODY) {
		    /* start outputing text */
		    output = 1;
		    continue;
		}
	    }

	    if (output) {
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

	/* Reset inactivity timer in case we spend a long time
	   pushing data to the client over a slow link. */
	prot_resettimeout(nntp_in);
    }

    if (!by_msgid) free(msgid);

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
    if (!(nntp_starttls_done || (extprops_ssf > 1) ||
	  config_getswitch(IMAPOPT_ALLOWPLAINTEXT))) {
	prot_printf(nntp_out,
		    "483 AUTHINFO USER command only available under a layer\r\n");
	return;
    }

    if (nntp_userid) {
	prot_printf(nntp_out, "502 Must give AUTHINFO PASS command\r\n");
	return;
    }

    if (!(p = canonify_userid(user, NULL, NULL))) {
	prot_printf(nntp_out, "502 Invalid user\r\n");
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
    if (nntp_authstate) {
	prot_printf(nntp_out, "502 Already authenticated\r\n");
	return;
    }

    if (!nntp_userid) {
	prot_printf(nntp_out, "482 Must give AUTHINFO USER command first\r\n");
	return;
    }

    if (!strcmp(nntp_userid, "anonymous")) {
	if (allowanonymous) {
	    pass = beautify_string(pass);
	    if (strlen(pass) > 500) pass[500] = '\0';
	    syslog(LOG_NOTICE, "login: %s anonymous %s",
		   nntp_clienthost, pass);
	}
	else {
	    syslog(LOG_NOTICE, "badlogin: %s anonymous login refused",
		   nntp_clienthost);
	    prot_printf(nntp_out, "502 Invalid login\r\n");
	    return;
	}
    }
    else if (sasl_checkpass(nntp_saslconn,
			    nntp_userid,
			    strlen(nntp_userid),
			    pass,
			    strlen(pass))!=SASL_OK) { 
	syslog(LOG_NOTICE, "badlogin: %s plaintext %s %s",
	       nntp_clienthost, nntp_userid, sasl_errdetail(nntp_saslconn));
	sleep(3);
	prot_printf(nntp_out, "502 Invalid login\r\n");
	free(nntp_userid);
	nntp_userid = 0;

	return;
    }
    else {
	syslog(LOG_NOTICE, "login: %s %s plaintext%s %s", nntp_clienthost,
	       nntp_userid, nntp_starttls_done ? "+TLS" : "",
	       "User logged in");

	prot_printf(nntp_out, "281 User logged in\r\n");

	nntp_authstate = auth_newstate(nntp_userid);

	/* Create telemetry log */
	nntp_logfd = telemetry_log(nntp_userid, nntp_in, nntp_out, 0);
    }
}

static void cmd_authinfo_sasl(char *cmd, char *mech, char *resp)
{
    int r, sasl_result;
    char *success_data;
    sasl_ssf_t ssf;
    char *ssfmsg = NULL;
    const void *val;

    if (nntp_userid) {
	prot_printf(nntp_out, "502 Already authenticated\r\n");
	return;
    }

    if (cmd[0] == 'g') {
	/* if client didn't specify any mech we give them the list */
	if (!mech) {
	    const char *sasllist;
	    int mechnum;

	    prot_printf(nntp_out, "281 List of mechanisms follows\r\n");
      
	    /* CRLF separated, dot terminated */
	    if (sasl_listmech(nntp_saslconn, NULL,
			      "", "\r\n", "\r\n",
			      &sasllist,
			      NULL, &mechnum) == SASL_OK) {
		if (mechnum > 0) {
		    prot_printf(nntp_out, "%s", sasllist);
		}
	    }
      
	    prot_printf(nntp_out, ".\r\n");
	    return;
	}

	r = saslserver(nntp_saslconn, mech, resp, "AUTHINFO GENERIC ", "381 ",
		       "", nntp_in, nntp_out, &sasl_result, &success_data);
    }
    else
	r = saslserver(nntp_saslconn, mech, resp, "", "383 ", "=",
		       nntp_in, nntp_out, &sasl_result, &success_data);

    if (r) {
	int code;
	const char *errorstring = NULL;

	switch (r) {
	case IMAP_SASL_CANCEL:
	    prot_printf(nntp_out,
			"481 Client canceled authentication\r\n");
	    break;
	case IMAP_SASL_PROTERR:
	    errorstring = prot_error(nntp_in);

	    prot_printf(nntp_out,
			"482 Error reading client response: %s\r\n",
			errorstring ? errorstring : "");
	    break;
	default: 
	    /* failed authentication */
	    switch (sasl_result) {
	    case SASL_NOMECH:
	    case SASL_TOOWEAK:
		code = 501;
		break;
	    case SASL_ENCRYPT:
		code = 483;
		break;
	    case SASL_BADPROT:
		code = 482;
		break;
	    default:
		code = 481;
	    }

	    syslog(LOG_NOTICE, "badlogin: %s %s [%s]",
		   nntp_clienthost, mech, sasl_errdetail(nntp_saslconn));

	    sleep(3);

	    /* Don't allow user probing */
	    if (sasl_result == SASL_NOUSER) sasl_result = SASL_BADAUTH;

	    errorstring = sasl_errstring(sasl_result, NULL, NULL);
	    if (errorstring) {
		prot_printf(nntp_out, "%d %s\r\n", code, errorstring);
	    } else {
		prot_printf(nntp_out, "%d Error authenticating\r\n", code);
	    }
	}

	reset_saslconn(&nntp_saslconn);
	return;
    }

    /* successful authentication */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_proxy_policy()
     */
    sasl_result = sasl_getprop(nntp_saslconn, SASL_USERNAME, &val);
    if (sasl_result != SASL_OK) {
	prot_printf(nntp_out, "481 weird SASL error %d SASL_USERNAME\r\n", 
		    sasl_result);
	syslog(LOG_ERR, "weird SASL error %d getting SASL_USERNAME", 
	       sasl_result);
	reset_saslconn(&nntp_saslconn);
	return;
    }
    nntp_userid = xstrdup((const char *) val);

    proc_register("nntpd", nntp_clienthost, nntp_userid, (char *)0);

    syslog(LOG_NOTICE, "login: %s %s %s%s %s", nntp_clienthost, nntp_userid,
	   mech, nntp_starttls_done ? "+TLS" : "", "User logged in");

    sasl_getprop(nntp_saslconn, SASL_SSF, &val);
    ssf = *((sasl_ssf_t *) val);

    /* really, we should be doing a sasl_getprop on SASL_SSF_EXTERNAL,
       but the current libsasl doesn't allow that. */
    if (nntp_starttls_done) {
	switch(ssf) {
	case 0: ssfmsg = "tls protection"; break;
	case 1: ssfmsg = "tls plus integrity protection"; break;
	default: ssfmsg = "tls plus privacy protection"; break;
	}
    } else {
	switch(ssf) {
	case 0: ssfmsg = "no protection"; break;
	case 1: ssfmsg = "integrity protection"; break;
	default: ssfmsg = "privacy protection"; break;
	}
    }

    if (success_data) {
	prot_printf(nntp_out, "283 %s\r\n", success_data);
	free(success_data);
    } else {
	prot_printf(nntp_out, "281 Success (%s)\r\n", ssfmsg);
    }

    prot_setsasl(nntp_in,  nntp_saslconn);
    prot_setsasl(nntp_out, nntp_saslconn);

    /* Create telemetry log */
    nntp_logfd = telemetry_log(nntp_userid, nntp_in, nntp_out, 0);
}

static void cmd_hdr(char *cmd, char *hdr, char *pat, char *msgid,
		    unsigned long uid, unsigned long last)
{
    int msgno, last_msgno;
    int by_msgid = (msgid != NULL);
    int found = 0;

    lcase(hdr);

    msgno = index_finduid(uid);
    if (!msgno || index_getuid(msgno) != uid) msgno++;
    last_msgno = index_finduid(last);

    for (; msgno <= last_msgno; msgno++) {
	char *body;

	if (!found++)
	    prot_printf(nntp_out, "%u Headers follow:\r\n",
			cmd[0] == 'X' ? 221 : 225);

	/* see if we're looking for metadata */
	if (hdr[0] == ':') {
	    if (!strcasecmp(":size", hdr)) {
		char xref[8192];
		unsigned long size = index_getsize(nntp_group, msgno);

		if (!by_msgid) msgid = index_get_msgid(nntp_group, msgno);
		build_xref(msgid, xref, sizeof(xref), 0);
		if (!by_msgid) free(msgid);

		prot_printf(nntp_out, "%lu %lu\r\n", by_msgid ? 0 : uid,
			    size + strlen(xref) + 2); /* +2 for \r\n */
	    }
	    else if (!strcasecmp(":lines", hdr))
		prot_printf(nntp_out, "%u %lu\r\n",
			    by_msgid ? 0 : index_getuid(msgno),
			    index_getlines(nntp_group, msgno));
	    else
		prot_printf(nntp_out, "%u \r\n",
			    by_msgid ? 0 : index_getuid(msgno));
	}
	else if (!strcmp(hdr, "xref") && !pat /* [X]HDR only */) {
	    char xref[8192];

	    if (!by_msgid) msgid = index_get_msgid(nntp_group, msgno);
	    build_xref(msgid, xref, sizeof(xref), 1);
	    if (!by_msgid) free(msgid);

	    prot_printf(nntp_out, "%u %s\r\n",
			by_msgid ? 0 : index_getuid(msgno), xref);
	}
	else if ((body = index_getheader(nntp_group, msgno, hdr)) &&
		 (!pat ||			/* [X]HDR */
		  wildmat(body, pat))) {	/* XPAT with match */
		prot_printf(nntp_out, "%u %s\r\n",
			    by_msgid ? 0 : index_getuid(msgno), body);
	}
    }

    if (found)
	prot_printf(nntp_out, ".\r\n");
    else
	prot_printf(nntp_out, "423 No such article(s) in this newsgroup\r\n");
}

static void cmd_help(void)
{
    prot_printf(nntp_out, "100 Supported commands:\r\n");

    if ((nntp_capa & MODE_READ) && (nntp_userid || allowanonymous)) {
	prot_printf(nntp_out, "\tARTICLE [ message-id | number ]\r\n"
		    "\t\tRetrieve entirety of the specified article.\r\n");
    }
    if (!nntp_authstate) {
	if (!nntp_userid) {
	    prot_printf(nntp_out, "\tAUTHINFO SASL mechanism [initial-response]\r\n"
			"\t\tPerform an authentication exchange using the specified\r\n"
			"\t\tSASL mechanism.\r\n");
	    prot_printf(nntp_out, "\tAUTHINFO USER username\r\n"
			"\t\tPresent username for authentication.\r\n");
	}
	prot_printf(nntp_out, "\tAUTHINFO PASS password\r\n"
		    "\t\tPresent clear-text password for authentication.\r\n");
    }
    if ((nntp_capa & MODE_READ) && (nntp_userid || allowanonymous)) {
	prot_printf(nntp_out, "\tBODY [ message-id | number ]\r\n"
		    "\t\tRetrieve body of the specified article.\r\n");
    }
    prot_printf(nntp_out, "\tCAPABILITIES\r\n"
		"\t\tList the current server capabilities.\r\n");
    if (nntp_capa & MODE_FEED) {
	prot_printf(nntp_out, "\tCHECK message-id\r\n"
		    "\t\tCheck if the server wants the specified article.\r\n");
    }
    if ((nntp_capa & MODE_READ) && (nntp_userid || allowanonymous)) {
	prot_printf(nntp_out, "\tDATE\r\n"
		    "\t\tRequest the current server UTC date and time.\r\n");
	prot_printf(nntp_out, "\tGROUP group\r\n"
		    "\t\tSelect a newsgroup for article retrieval.\r\n");
	prot_printf(nntp_out, "\tHDR header [ message-id | range ]\r\n"
		    "\t\tRetrieve the specified header/metadata from the\r\n"
		    "\t\tspecified article(s).\r\n");
    }
    prot_printf(nntp_out, "\tHEAD [ message-id | number ]\r\n"
		"\t\tRetrieve the headers of the specified article.\r\n");
    prot_printf(nntp_out, "\tHELP\r\n"
		"\t\tRequest command summary (this text).\r\n");
    if (nntp_capa & MODE_FEED) {
	prot_printf(nntp_out, "\tIHAVE message-id\r\n"
		    "\t\tPresent/transfer the specified article to the server.\r\n");
    }
    if ((nntp_capa & MODE_READ) && (nntp_userid || allowanonymous)) {
	prot_printf(nntp_out, "\tLAST\r\n"
		    "\t\tSelect the previous article.\r\n");
    }
    prot_printf(nntp_out, "\tLIST [ ACTIVE wildmat ]\r\n"
		"\t\tList the (subset of) valid newsgroups.\r\n");
    if ((nntp_capa & MODE_READ) && (nntp_userid || allowanonymous)) {
	prot_printf(nntp_out, "\tLIST HEADERS [ MSGID | RANGE ]\r\n"
		    "\t\tList the headers and metadata items available via HDR.\r\n");
	prot_printf(nntp_out, "\tLIST NEWSGROUPS [wildmat]\r\n"
		    "\t\tList the descriptions of the specified newsgroups.\r\n");
	prot_printf(nntp_out, "\tLIST OVERVIEW.FMT\r\n"
		    "\t\tList the headers and metadata items available via OVER.\r\n");
	prot_printf(nntp_out, "\tLISTGROUP [group [range]]\r\n"
		    "\t\tList the article numbers in the specified newsgroup.\r\n");
	if (config_getswitch(IMAPOPT_ALLOWNEWNEWS))
	    prot_printf(nntp_out, "\tNEWNEWS wildmat date time [GMT]\r\n"
			"\t\tList the newly arrived articles in the specified newsgroup(s)\r\n"
			"\t\tsince the specified date and time.\r\n");
	prot_printf(nntp_out, "\tNEXT\r\n"
		    "\t\tSelect the next article.\r\n");
	prot_printf(nntp_out, "\tOVER [ message-id | range ]\r\n"
		    "\t\tRetrieve the overview information for the specified article(s).\r\n");
	prot_printf(nntp_out, "\tPOST\r\n"
		    "\t\tPost an article to the server.\r\n");
    }

    prot_printf(nntp_out, "\tQUIT\r\n"
		"\t\tTerminate the session.\r\n");
    if (tls_enabled() && !nntp_starttls_done && !nntp_authstate) {
	prot_printf(nntp_out, "\tSTARTTLS\r\n"
		    "\t\tStart a TLS negotiation.\r\n");
    }
    prot_printf(nntp_out, "\tSTAT [ message-id | number ]\r\n"
		"\t\tCheck if the specified article exists.\r\n");
    if (nntp_capa & MODE_FEED) {
	prot_printf(nntp_out, "\tTAKETHIS message-id\r\n"
		    "\t\tTransfer the specified article to the server.\r\n");
    }
    if ((nntp_capa & MODE_READ) && (nntp_userid || allowanonymous)) {
	prot_printf(nntp_out, "\tXPAT header message-id|range wildmat\r\n"
		    "\t\tList the specified article(s) in which the contents\r\n"
		    "\t\tof the specified header/metadata matches the wildmat.\r\n");
    }
    prot_printf(nntp_out, ".\r\n");
}

struct list_rock {
    int (*proc)();
    struct wildmat *wild;
    struct hash_table server_table;
};

/*
 * mboxlist_findall() callback function to LIST
 */
int list_cb(char *name, int matchlen, int maycreate __attribute__((unused)),
	    void *rock)
{
    static char lastname[MAX_MAILBOX_NAME+1];
    struct list_rock *lrock = (struct list_rock *) rock;
    struct wildmat *wild;

    /* We have to reset the initial state.
     * Handle it as a dirty hack.
     */
    if (!name) {
	lastname[0] = '\0';
	return 0;
    }

    /* skip personal mailboxes */
    if ((!strncasecmp(name, "INBOX", 5) && (!name[5] || name[5] == '.')) ||
	!strncmp(name, "user.", 5))
	return 0;

    /* don't repeat */
    if (matchlen == (int) strlen(lastname) &&
	!strncmp(name, lastname, matchlen)) return 0;

    strncpy(lastname, name, matchlen);
    lastname[matchlen] = '\0';

    /* see if the mailbox matches one of our wildmats */
    wild = lrock->wild;
    while (wild->pat && wildmat(name, wild->pat) != 1) wild++;

    /* if we don't have a match, or its a negative match, skip it */
    if (!wild->pat || wild->not) return 0;

    return lrock->proc(name, lrock);
}

struct enum_rock {
    const char *cmd;
    char *wild;
};

/*
 * hash_enumerate() callback function to LIST (proxy)
 */
void list_proxy(char *server, void *data __attribute__((unused)), void *rock)
{
    struct enum_rock *erock = (struct enum_rock *) rock;
    struct backend *be;
    int r;
    char *result;

    be = proxy_findserver(server, &nntp_protocol,
			  nntp_userid ? nntp_userid : "anonymous",
			  &backend_cached, &backend_current, NULL, nntp_in);
    if (!be) return;

    prot_printf(be->out, "LIST %s %s\r\n", erock->cmd, erock->wild);

    r = read_response(be, 0, &result);
    if (!r && !strncmp(result, "215 ", 4)) {
	while (!(r = read_response(be, 0, &result)) && result[0] != '.') {
	    prot_printf(nntp_out, "%s", result);
	}
    }
}

/*
 * perform LIST ACTIVE (backend) or create a server hash table (proxy)
 */
int do_active(char *name, void *rock)
{
    struct list_rock *lrock = (struct list_rock *) rock;
    int r, postable;
    struct backend *be;

    /* open the group */
    r = open_group(name, 1, &be, &postable);
    if (r) {
	/* can't open group, skip it */
    }
    else if (be) {
	if (!hash_lookup(be->hostname, &lrock->server_table)) {
	    /* add this server to our table */
	    hash_insert(be->hostname, (void *)0xDEADBEEF, &lrock->server_table);
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

/*
 * perform LIST NEWSGROUPS (backend) or create a server hash table (proxy)
 */
int do_newsgroups(char *name, void *rock)
{
    struct list_rock *lrock = (struct list_rock *) rock;
    char *acl, *server;
    int r;

    r = mlookup(name, &server, &acl, NULL);

    if (r || !acl || !(cyrus_acl_myrights(nntp_authstate, acl) && ACL_LOOKUP))
	return 0;

    if (server) {
	/* remote group */
	if (!hash_lookup(server, &lrock->server_table)) {
	    /* add this server to our table */
	    hash_insert(server, (void *)0xDEADBEEF, &lrock->server_table);
	}
    }
    else {
	/* local group */
	return CYRUSDB_DONE;
    }

    return 0;
}

/*
 * annotatemore_findall() callback function to LIST NEWSGROUPS
 */
int newsgroups_cb(const char *mailbox,
		  const char *entry __attribute__((unused)),
		  const char *userid,
		  struct annotation_data *attrib, void *rock)
{
    struct wildmat *wild = (struct wildmat *) rock;

    /* skip personal mailboxes */
    if ((!strncasecmp(mailbox, "INBOX", 5) &&
	 (!mailbox[5] || mailbox[5] == '.')) ||
	!strncmp(mailbox, "user.", 5))
	return 0;

    /* see if the mailbox matches one of our wildmats */
    while (wild->pat && wildmat(mailbox, wild->pat) != 1) wild++;

    /* if we don't have a match, or its a negative match, skip it */
    if (!wild->pat || wild->not) return 0;

    /* we only care about shared /comment */
    if (userid[0]) return 0;

    prot_printf(nntp_out, "%s\t%s\r\n", mailbox+strlen(newsprefix),
		attrib->value);

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
	struct list_rock lrock;
	struct enum_rock erock;

	if (!arg2) arg2 = "*";

	erock.cmd = "ACTIVE";
	erock.wild = xstrdup(arg2); /* make a copy before we munge it */

	lrock.proc = do_active;
	lrock.wild = split_wildmats(arg2); /* split the list of wildmats */

	/* xxx better way to determine a size for this table? */
	construct_hash_table(&lrock.server_table, 10, 1);

	prot_printf(nntp_out, "215 List of newsgroups follows:\r\n");

	strcpy(pattern, newsprefix);
	strcat(pattern, "*");
	list_cb(NULL, 0, 0, NULL);
	mboxlist_findall(NULL, pattern, 0, nntp_userid, nntp_authstate,
			 list_cb, &lrock);

	/* proxy to the backends */
	hash_enumerate(&lrock.server_table, list_proxy, &erock);

	prot_printf(nntp_out, ".\r\n");

	/* free the hash table */
	free_hash_table(&lrock.server_table, NULL);

	/* free the wildmats */
	free_wildmats(lrock.wild);
	free(erock.wild);

	if (nntp_group) {
	    mailbox_close(nntp_group);
	    nntp_group = 0;
	}
    }
    else if (!(nntp_capa & MODE_READ)) {
	prot_printf(nntp_out, "502 Permission denied\r\n");
	return;
    }
    else if (!nntp_userid && !allowanonymous) {
	prot_printf(nntp_out, "480 Authentication required\r\n");
	return;
    }
    else if (!strcmp(arg1, "headers")) {
	if (arg2 && strcmp(arg2, "msgid") && strcmp(arg2, "range")) {
	    prot_printf(nntp_out, "501 Unexpected extra argument\r\n");
	    return;
	}

	prot_printf(nntp_out, "215 Header and metadata list follows:\r\n");
	prot_printf(nntp_out, ":\r\n"); /* all headers */
	prot_printf(nntp_out, ":bytes\r\n");
	prot_printf(nntp_out, ":lines\r\n");
	prot_printf(nntp_out, ".\r\n");
    }
    else if (!strcmp(arg1, "newsgroups")) {
	char pattern[MAX_MAILBOX_NAME+1];
	struct list_rock lrock;
	struct enum_rock erock;

	if (!arg2) arg2 = "*";

	erock.cmd = "NEWSGROUPS";
	erock.wild = xstrdup(arg2); /* make a copy before we munge it */

	lrock.proc = do_newsgroups;
	lrock.wild = split_wildmats(arg2); /* split the list of wildmats */

	/* xxx better way to determine a size for this table? */
	construct_hash_table(&lrock.server_table, 10, 1);

	prot_printf(nntp_out, "215 List of newsgroups follows:\r\n");

	strcpy(pattern, newsprefix);
	strcat(pattern, "*");
	list_cb(NULL, 0, 0, NULL);
	mboxlist_findall(NULL, pattern, 0, nntp_userid, nntp_authstate,
			 list_cb, &lrock);

	/* proxy to the backends */
	hash_enumerate(&lrock.server_table, list_proxy, &erock);

	strcpy(pattern, newsprefix);
	strcat(pattern, "*");
	annotatemore_findall(pattern, "/comment",
			     newsgroups_cb, lrock.wild, NULL);

	prot_printf(nntp_out, ".\r\n");

	/* free the hash table */
	free_hash_table(&lrock.server_table, NULL);

	/* free the wildmats */
	free_wildmats(lrock.wild);
	free(erock.wild);
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
	if (did_capabilities) {
	    /* new OVER format */
	    prot_printf(nntp_out, ":bytes\r\n");
	    prot_printf(nntp_out, ":lines\r\n");
	} else {
	    /* old XOVER format */
	    prot_printf(nntp_out, "Bytes:\r\n");
	    prot_printf(nntp_out, "Lines:\r\n");
	}
	prot_printf(nntp_out, "Xref:full\r\n");
	prot_printf(nntp_out, ".\r\n");
    }
    else if (!strcmp(arg1, "active.times") || !strcmp(arg1, "distributions") ||
	     !strcmp(arg1, "distrib.pats")) {
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
	prot_printf(nntp_out, "%u", (nntp_capa & MODE_READ) ? 200 : 201);
	if (config_serverinfo || nntp_authstate) {
	    prot_printf(nntp_out, " %s", config_servername);
	}
	if (nntp_authstate || (config_serverinfo == IMAP_ENUM_SERVERINFO_ON)) {
	    prot_printf(nntp_out, " Cyrus NNTP%s %s",
			config_mupdate_server ? " Murder" : "", CYRUS_VERSION);
	}
	prot_printf(nntp_out, " server ready, posting %s\r\n",
		    (nntp_capa & MODE_READ) ? "allowed" : "prohibited");
    }
    else if (!strcmp(arg, "stream")) {
	if (nntp_capa & MODE_FEED) {
	    prot_printf(nntp_out, "203 Streaming allowed\r\n");
	}
	else {
	    prot_printf(nntp_out, "502 Streaming prohibited\r\n");
	}
    }
    else {
	prot_printf(nntp_out, "501 Unrecognized MODE\r\n");
    }
    prot_flush(nntp_out);
}

static void cmd_newgroups(time_t tstamp __attribute__((unused)))
{
    prot_printf(nntp_out, "503 Can't determine NEWGROUPS at this time\r\n");
#if 0
    prot_printf(nntp_out, "231 List of new newsgroups follows:\r\n");

    /* Do search of annotations here. */

    prot_printf(nntp_out, ".\r\n");
#endif
}

struct newrock {
    time_t tstamp;
    struct wildmat *wild;
};

/*
 * duplicate_find() callback function to list NEWNEWS
 */
static int newnews_cb(const char *msgid, const char *rcpt, time_t mark,
		      unsigned long uid, void *rock)
{
    static char lastid[1024];
    struct newrock *nrock = (struct newrock *) rock;

    /* We have to reset the initial state.
     * Handle it as a dirty hack.
     */
    if (!msgid) {
	lastid[0] = '\0';
	return 0;
    }

    /* Make sure we don't return duplicate msgids,
     * the message is newer than the tstamp, and
     * the message isn't in a personal mailbox.
     */
    if (strcmp(msgid, lastid) && mark >= nrock->tstamp &&
	uid && rcpt[0] && strncmp(rcpt, "user.", 5)) {
	struct wildmat *wild = nrock->wild;

	strlcpy(lastid, msgid, sizeof(lastid));

	/* see if the mailbox matches one of our wildmats */
	while (wild->pat && wildmat(rcpt, wild->pat) != 1) wild++;

	/* we have a match, and its not a negative match */
	if (wild->pat && !wild->not)
	    prot_printf(nntp_out, "%s\r\n", msgid);
    }

    return 0;
}

static void cmd_newnews(char *wild, time_t tstamp)
{
    struct newrock nrock;

    nrock.tstamp = tstamp;
    nrock.wild = split_wildmats(wild);

    prot_printf(nntp_out, "230 List of new articles follows:\r\n");

    newnews_cb(NULL, NULL, 0, 0, NULL);
    duplicate_find("", &newnews_cb, &nrock);

    prot_printf(nntp_out, ".\r\n");

    free_wildmats(nrock.wild);
}

static void cmd_over(char *msgid, unsigned long uid, unsigned long last)
{
    unsigned msgno, last_msgno;
    struct nntp_overview *over;
    int found = 0;

    msgno = index_finduid(uid);
    if (!msgno || index_getuid(msgno) != uid) msgno++;
    last_msgno = index_finduid(last);

    for (; msgno <= last_msgno; msgno++) {
	if (!found++)
	    prot_printf(nntp_out, "224 Overview information follows:\r\n");

	if ((over = index_overview(nntp_group, msgno))) {
	    char xref[8192];

	    build_xref(over->msgid, xref, sizeof(xref), 0);

	    prot_printf(nntp_out, "%lu\t%s\t%s\t%s\t%s\t%s\t%lu\t%lu\t%s\r\n",
			msgid ? 0 : over->uid,
			over->subj ? over->subj : "",
			over->from ? over->from : "",
			over->date ? over->date : "",
			over->msgid ? over->msgid : "",
			over->ref ? over->ref : "",
			over->bytes + strlen(xref) + 2, /* +2 for \r\n */
			over->lines, xref);
	}
    }

    if (found)
	prot_printf(nntp_out, ".\r\n");
    else
	prot_printf(nntp_out, "423 No such article(s) in this newsgroup\r\n");
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
    const char *p;
    char *rcpt = NULL;
    size_t n;

    for (p = groups;; p += n) {
	/* skip whitespace */
	while (p && *p && (isspace((int) *p) || *p == ',')) p++;

	if (!p || !*p) return 0;

	if (!(msg->rcpt_num % RCPT_GROW)) { /* time to alloc more */
	    msg->rcpt = (char **)
		xrealloc(msg->rcpt, (msg->rcpt_num + RCPT_GROW + 1) * 
			 sizeof(char *));
	}

	/* find end of group name */
	n = strcspn(p, ", \t");
	rcpt = xrealloc(rcpt, strlen(newsprefix) + n + 1);
	if (!rcpt) return -1;

	/* construct the mailbox name */
	sprintf(rcpt, "%s%.*s", newsprefix, n, p);
	
	/* Only add mailboxes that exist */
	if (!mlookup(rcpt, NULL, NULL, NULL)) {
	    msg->rcpt[msg->rcpt_num] = rcpt;
	    msg->rcpt_num++;
	    msg->rcpt[msg->rcpt_num] = rcpt = NULL;
	}
    }

    /* never reached */
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
    const char **body, **groups;
    int r, i;
    time_t now = time(NULL);
    static int post_count = 0;
    FILE *stagef = NULL;
    const char *skipheaders[] = {
	"Path",		/* need to prepend our servername */
	"Xref",		/* need to remove (generated on the fly) */
	"Reply-To",	/* need to add "post" email addresses */
	NULL
    };
    int addlen;

    m->f = f;

    /* fill the cache */
    r = spool_fill_hdrcache(nntp_in, f, m->hdrcache, skipheaders);
    if (r) {
	/* got a bad header */

	/* flush the remaining output */
	spool_copy_msg(nntp_in, NULL);
	return r;
    }

    /* now, using our header cache, fill in the data that we want */

    /* get path */
    addlen = strlen(config_servername) + 1;
    if ((body = spool_getheader(m->hdrcache, "path")) != NULL) {
	/* prepend to the cached path */
	addlen += strlen(body[0]);
	body[0] = xrealloc((char *) body[0], addlen + 1);
	memmove((char *) body[0] + strlen(config_servername) + 1, body[0],
		strlen(body[0]) + 1);  /* +1 for \0 */
	strcpy((char *) body[0], config_servername);
	*((char *) body[0] + strlen(config_servername)) = '!';
	m->path = xstrdup(body[0]);
    } else {
	/* no path, create one */
	addlen += nntp_userid ? strlen(nntp_userid) : strlen("anonymous");
	m->path = xmalloc(addlen + 1);
	sprintf(m->path, "%s!%s", config_servername,
		nntp_userid ? nntp_userid : "anonymous");
	spool_cache_header(xstrdup("Path"), xstrdup(m->path), m->hdrcache);
    }
    fprintf(f, "Path: %s\r\n", m->path);

    /* get message-id */
    if ((body = spool_getheader(m->hdrcache, "message-id")) != NULL) {
	m->id = xstrdup(body[0]);
    } else {
	/* no message-id, create one */
	pid_t p = getpid();

	m->id = xmalloc(40 + strlen(config_servername));
	sprintf(m->id, "<cmu-nntpd-%d-%d-%d@%s>", p, (int) now, 
		post_count++, config_servername);
	fprintf(f, "Message-ID: %s\r\n", m->id);
	spool_cache_header(xstrdup("Message-ID"), xstrdup(m->id), m->hdrcache);
    }

    /* get date */
    if ((body = spool_getheader(m->hdrcache, "date")) == NULL) {
	/* no date, create one */
	char datestr[80];

	rfc822date_gen(datestr, sizeof(datestr), now);
	fprintf(f, "Date: %s\r\n", datestr);
	spool_cache_header(xstrdup("Date"), xstrdup(datestr), m->hdrcache);
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
	if ((groups = spool_getheader(m->hdrcache, "newsgroups")) != NULL) {
	    /* parse newsgroups and create recipients */
	    r = parse_groups(groups[0], m);
	    if (!r && !m->rcpt_num) {
		r = IMAP_MAILBOX_NONEXISTENT; /* no newsgroups that we serve */
	    }
	    if (!r) {
		const char *newspostuser = config_getstring(IMAPOPT_NEWSPOSTUSER);
		/* get reply-to */
		body = spool_getheader(m->hdrcache, "reply-to");

		/* add Reply-To: header */
		if (body || newspostuser) {
		    const char **postto, *p;
		    char *replyto, *r, *fold = NULL, *sep = "";
		    size_t n;

		    if (newspostuser) {
			/* add "post" email addresses based on newsgroup */

			/* determine which groups header to use */
			postto = spool_getheader(m->hdrcache, "followup-to");
			if (!postto) postto = groups;

			/* count the number of groups */
			for (n = 0, p = postto[0]; p; n++) {
			    p = strchr(p, ',');
			    if (p) p++;
			}

			/* estimate size of post addresses */
			addlen = strlen(postto[0]) +
			    n * (strlen(newspostuser) + 3);

			if (body) {
			    /* append to the cached header */
			    addlen += strlen(body[0]);
			    body[0] = xrealloc((char *) body[0], addlen + 1);
			    replyto = (char *) body[0];
			    fold = replyto + strlen(replyto) + 1;
			    sep = ", ";
			}
			else {
			    /* create a new header body */
			    replyto = xzmalloc(addlen + 1);
			}

			r = replyto + strlen(replyto);
			for (p = postto[0];; p += n) {
			    /* skip whitespace */
			    while (p && *p &&
				   (isspace((int) *p) || *p == ',')) p++;
			    if (!p || !*p) break;

			    /* find end of group name */
			    n = strcspn(p, ", \t");

			    /* add the post address */
			    r += sprintf(r, "%s%s+%.*s",
					 sep, newspostuser, n, p);

			    sep = ", ";
			}

			if (!body) {
			    /* add the new header to the cache */
			    spool_cache_header(xstrdup("Reply-To"), replyto,
					       m->hdrcache);
			}
		    } else {
			/* no newspostuser, use original replyto */
			replyto = (char *) body[0];
		    }

		    /* add the header to the file */
		    fprintf(f, "Reply-To: ");
		    r = replyto;
		    if (fold) {
			fprintf(f, "%.*s\r\n\t", fold - r, r);
			r = fold;
		    }
		    fprintf(f, "%s\r\n", r);
		}
	    }
	} else {
	    r = NNTP_NO_NEWSGROUPS;		/* no newsgroups header */
	}

	if (r) {
	    /* error getting newsgroups */

	    /* flush the remaining output */
	    spool_copy_msg(nntp_in, NULL);
	    return r;
	}
    }

    fflush(f);
    if (ferror(f)) {
	return IMAP_IOERROR;
    }

    if (fstat(fileno(f), &sbuf) == -1) {
	return IMAP_IOERROR;
    }

    /* spool to the stage of one of the recipients */
    for (i = 0; !stagef && (i < m->rcpt_num); i++) {
	stagef = append_newstage(m->rcpt[i], now, 0, &stage);
    }

    if (stagef) {
	const char *base = 0;
	unsigned long size = 0;
	int n;

	/* copy the header from our tmpfile to the stage */
	map_refresh(fileno(f), 1, &base, &size, sbuf.st_size, "tmp", 0);
	n = retry_write(fileno(stagef), base, size);
	map_free(&base, &size);

	if (n == -1) {
	    /* close and remove the stage */
	    fclose(stagef);
	    append_removestage(stage);
	    stage = NULL;
	    return IMAP_IOERROR;
	}
	else {
	    /* close the tmpfile and use the stage */
	    fclose(f);
	    m->f = f = stagef;
	}
    }
    /* else this is probably a remote group, so use the tmpfile */

    r = spool_copy_msg(nntp_in, f);

    if (r) return r;

    fflush(f);
    if (ferror(f)) {
	return IMAP_IOERROR;
    }

    if (fstat(fileno(f), &sbuf) == -1) {
	return IMAP_IOERROR;
    }
    m->size = sbuf.st_size;
    m->data = prot_new(fileno(f), 0);

    return 0;
}

static int deliver_remote(message_data_t *msg, struct dest *dlist)
{
    struct dest *d;

    /* run the txns */
    for (d = dlist; d; d = d->next) {
	struct backend *be;
	char buf[4096];

	be = proxy_findserver(d->server, &nntp_protocol,
			      nntp_userid ? nntp_userid : "anonymous",
			      &backend_cached, &backend_current,
			      NULL, nntp_in);
	if (!be) return IMAP_SERVER_UNAVAILABLE;

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
	    syslog(LOG_WARNING, "article %s transfer to backend failed",
		   msg->id);
	    return NNTP_FAIL_TRANSFER;
	}
    }

    return 0;
}

static int deliver(message_data_t *msg)
{
    int n, r = 0, myrights;
    char *rcpt = NULL, *local_rcpt = NULL, *server, *acl;
    time_t now = time(NULL);
    unsigned long uid;
    struct body *body = NULL;
    struct dest *dlist = NULL;

    /* check ACLs of all mailboxes */
    for (n = 0; n < msg->rcpt_num; n++) {
	rcpt = msg->rcpt[n];

	/* look it up */
	r = mlookup(rcpt, &server, &acl, NULL);
	if (r) return IMAP_MAILBOX_NONEXISTENT;

	if (!(acl && (myrights = cyrus_acl_myrights(nntp_authstate, acl)) &&
	      (myrights & ACL_POST)))
	    return IMAP_PERMISSION_DENIED;

	if (server) {
	    /* remote group */
	    proxy_adddest(&dlist, NULL, 0, server, "");
	}
	else {
	    /* local group */
	    struct appendstate as;

	    if (msg->id && 
		duplicate_check(msg->id, strlen(msg->id), rcpt, strlen(rcpt))) {
		/* duplicate message */
		duplicate_log(msg->id, rcpt, "nntp delivery");
		continue;
	    }

	    r = append_setup(&as, rcpt, MAILBOX_FORMAT_NORMAL,
			     nntp_userid, nntp_authstate, ACL_POST, 0);

	    if (!r) {
		prot_rewind(msg->data);
		if (stage) {
		    r = append_fromstage(&as, &body, stage, now,
					 (const char **) NULL, 0, !singleinstance);
		} else {
		    /* XXX should never get here */
		    r = append_fromstream(&as, &body, msg->data, msg->size, now,
					  (const char **) NULL, 0);
		}
		if (r || (msg->id &&   
			  duplicate_check(msg->id, strlen(msg->id),
					  rcpt, strlen(rcpt)))) {  
		    append_abort(&as);
                   
		    if (!r) {
			/* duplicate message */
			duplicate_log(msg->id, rcpt, "nntp delivery");
			continue;
		    }            
		}                
		else {           
		    r = append_commit(&as, 0, NULL, &uid, NULL);
		    if (!r) sync_log_append(rcpt);
		}
	    }

	    if (!r && msg->id)
		duplicate_mark(msg->id, strlen(msg->id), rcpt, strlen(rcpt),
			       now, uid);

	    if (r) return r;

	    local_rcpt = rcpt;
	}
    }

    if (body) {
	message_free_body(body);
	free(body);
    }

    if (dlist) {
	struct dest *d;

	/* run the txns */
	r = deliver_remote(msg, dlist);

	/* free the destination list */
	d = dlist;
	while (d) {
	    struct dest *nextd = d->next;
	    free(d);
	    d = nextd;
	}
    }

    return r;
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

    r = mboxlist_createmailbox(mailboxname, 0, NULL, 0,
			       newsmaster, newsmaster_authstate, 0, 0, 0);

    /* XXX check body of message for useful MIME parts */

    if (!r) sync_log_mailbox(mailboxname);

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

    r = mboxlist_deletemailbox(mailboxname, 0,
			       newsmaster, newsmaster_authstate, 1, 0, 0);

    if (!r) sync_log_mailbox(mailboxname);

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

    r = mboxlist_renamemailbox(oldmailboxname, newmailboxname, NULL, 0,
			       newsmaster, newsmaster_authstate, 0);

    /* XXX check body of message for useful MIME parts */

    if (!r) sync_log_mailbox_double(oldmailboxname, newmailboxname);

    return r;
}

/*
 * mailbox_exchange() callback function to delete cancelled articles
 */
static unsigned expunge_cancelled(struct mailbox *mailbox __attribute__((unused)),
				  void *rock,
				  unsigned char *index,
				  int expunge_flags __attribute__((unused)))
{
    unsigned uid = ntohl(*((bit32 *)(index+OFFSET_UID)));

    /* only expunge the UID that we obtained from the msgid */
    return (uid == *((unsigned long *) rock));
}

/*
 * duplicate_find() callback function to cancel articles
 */
static int cancel_cb(const char *msgid __attribute__((unused)),
		     const char *mailbox,
		     time_t mark __attribute__((unused)),
		     unsigned long uid,
		     void *rock)
{
    /* make sure its a message in a mailbox that we're serving via NNTP */
    if (*mailbox && !strncmp(mailbox, newsprefix, strlen(newsprefix)) &&
	strncmp(mailbox, "user.", 5)) {
	struct mailbox mbox;
	int r, doclose = 0;

	r = mailbox_open_header(mailbox, 0, &mbox);

	if (!r &&
	    !(cyrus_acl_myrights(newsmaster_authstate, mbox.acl) & ACL_DELETEMSG))
	    r = IMAP_PERMISSION_DENIED;

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
	    mailbox_expunge(&mbox, expunge_cancelled, &uid, EXPUNGE_FORCE);
	}

	if (doclose) mailbox_close(&mbox);

	/* if we failed, pass the return code back in the rock */
	if (r) *((int *) rock) = r;
	else sync_log_mailbox(mbox.name);
    }

    return 0;
}

static int cancel(message_data_t *msg)
{
    int r = 0;
    char *msgid, *p;
    time_t now = time(NULL);

    /* isolate msgid */
    msgid = strchr(msg->control, '<');
    p = strrchr(msgid, '>') + 1;
    *p = '\0';

    /* find and expunge the message from all mailboxes */
    duplicate_find(msgid, &cancel_cb, &r);

    /* store msgid of cancelled message for IHAVE/CHECK/TAKETHIS
     * (in case we haven't received the message yet)
     */
    duplicate_mark(msgid, strlen(msgid), "", 0, 0, now);

    return r;
}

/* strip any post addresses from a header body.
 * returns 1 if a nonpost address was found, 0 otherwise.
 */
static int strip_post_addresses(char *body)
{
    const char *newspostuser = config_getstring(IMAPOPT_NEWSPOSTUSER);
    char *p, *end;
    size_t postlen, n;
    int nonpost = 0;

    if (!newspostuser) return 1;  /* we didn't add this header, so leave it */
    postlen = strlen(newspostuser);

    for (p = body;; p += n) {
	end = p;

	/* skip whitespace */
	while (p && *p && (isspace((int) *p) || *p == ',')) p++;

	if (!p || !*p) break;

	/* find end of address */
	n = strcspn(p, ", \t\r\n");

	if ((n > postlen + 1) &&  /* +1 for '+' */
	    !strncmp(p, newspostuser, postlen) && p[postlen] == '+') {
	    /* found a post address.  since we always add the post
	     * addresses to the end of the header, truncate it right here.
	     */
	    strcpy(end, "\r\n");
	    break;
	}
	
	nonpost = 1;
    }

    return nonpost;
}


static void feedpeer(char *peer, message_data_t *msg)
{
    char *user, *pass, *host, *port, *wild, *path, *s;
    int oldform = 0;
    struct wildmat *wmat = NULL, *w;
    int len, err, n, feed = 1;
    struct addrinfo hints, *res, *res0;
    int sock = -1;
    struct protstream *pin, *pout;
    char buf[4096];
    int body = 0, skip;

    /* parse the peer */
    user = pass = host = port = wild = NULL;
    if ((wild = strrchr(peer, '/')))
	*wild++ = '\0';
    else if ((wild = strrchr(peer, ':')) &&
	     strcspn(wild, "!*?,.") != strlen(wild)) {
	*wild++ = '\0';
	host = peer;
	oldform = 1;
    }
    if (!oldform) {
	if ((host = strchr(peer, '@'))) {
	    *host++ = '\0';
	    user = peer;
	    if ((pass = strchr(user, ':'))) *pass++ = '\0';
	}
	else
	    host = peer;

	if ((port = strchr(host, ':'))) *port++ = '\0';
    }

    /* check path to see if this message came through our peer */
    len = strlen(host);
    path = msg->path;
    while (path && (s = strchr(path, '!'))) {
	if ((s - path) == len && !strncmp(path, host, len)) {
	    return;
	}
	path = s + 1;
    }

    /* check newsgroups against wildmat to see if we should feed it */
    if (wild && *wild) {
	wmat = split_wildmats(wild);

	feed = 0;
	for (n = 0; n < msg->rcpt_num; n++) {
	    /* see if the newsgroup matches one of our wildmats */
	    w = wmat;
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

	free_wildmats(wmat);
    }

    if (!feed) return;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    if (!port || !*port) port = "119";
    if ((err = getaddrinfo(host, port, &hints, &res0)) != 0) {
	syslog(LOG_ERR, "getaddrinfo(%s, %s) failed: %m", host, port);
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
	syslog(LOG_ERR, "connect(%s:%s) failed: %m", host, port);
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

    if (user) {
	/* change to reader mode - not always necessary, so ignore result */
	prot_printf(pout, "MODE READER\r\n");
	prot_fgets(buf, sizeof(buf), pin);

	if (*user) {
	    /* authenticate to peer */
	    /* XXX this should be modified to support SASL and STARTTLS */

	    prot_printf(pout, "AUTHINFO USER %s\r\n", user);
	    if (!prot_fgets(buf, sizeof(buf), pin)) {
		syslog(LOG_ERR, "AUTHINFO USER terminated abnormally");
		goto quit;
	    }
	    else if (!strncmp("381", buf, 3)) {
		/* password required */
		if (!pass) {
		    syslog(LOG_ERR, "need password for AUTHINFO PASS");
		    goto quit;
		}

		prot_printf(pout, "AUTHINFO PASS %s\r\n", pass);
		if (!prot_fgets(buf, sizeof(buf), pin)) {
		    syslog(LOG_ERR, "AUTHINFO PASS terminated abnormally");
		    goto quit;
		}
	    }

	    if (strncmp("281", buf, 3)) {
		/* auth failed */
		syslog(LOG_ERR, "authentication failed");
		goto quit;
	    }
	}

	/* tell the peer we want to post */
	prot_printf(pout, "POST\r\n");
	prot_flush(pout);

	if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("340", buf, 3)) {
	    syslog(LOG_ERR, "peer doesn't allow posting");
	    goto quit;
	}
    }
    else {
	/* tell the peer about our new article */
	prot_printf(pout, "IHAVE %s\r\n", msg->id);
	prot_flush(pout);

	if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("335", buf, 3)) {
	    syslog(LOG_ERR, "peer doesn't want article %s", msg->id);
	    goto quit;
	}
    }

    /* send the article */
    rewind(msg->f);
    while (fgets(buf, sizeof(buf), msg->f)) {
	if (!body && buf[0] == '\r' && buf[1] == '\n') {
	    /* blank line between header and body */
	    body = 1;
	}

	skip = 0;
	if (!body) {
	    if (!strncasecmp(buf, "Reply-To:", 9)) {
		/* strip any post addresses, skip if becomes empty */
		if (!strip_post_addresses(buf+9)) skip = 1;
	    }
	}

	if (!skip && buf[0] == '.') prot_putc('.', pout);
	do {
	    if (!skip) prot_printf(pout, "%s", buf);
	} while (buf[strlen(buf)-1] != '\n' &&
		 fgets(buf, sizeof(buf), msg->f));
    }

    /* Protect against messages not ending in CRLF */
    if (buf[strlen(buf)-1] != '\n') prot_printf(pout, "\r\n");

    prot_printf(pout, ".\r\n");

    if (!prot_fgets(buf, sizeof(buf), pin) || strncmp("2", buf, 1)) {
	syslog(LOG_ERR, "article %s transfer to peer failed", msg->id);
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

void printstring(const char *s __attribute__((unused)))
{
    /* needed to link against annotate.o */
    fatal("printstring() executed, but its not used for nntpd!",
	  EC_SOFTWARE);
}

#define ALLOC_SIZE 10

static void news2mail(message_data_t *msg)
{
    struct annotation_data attrib;
    int n, i, r;
    FILE *sm;
    static const char **smbuf = NULL;
    static int allocsize = 0;
    int sm_stat;
    pid_t sm_pid;
    char buf[4096], to[1024] = "";

    if (!smbuf) {
	allocsize += ALLOC_SIZE;
	smbuf = xzmalloc(allocsize * sizeof(const char *));

	smbuf[0] = "sendmail";
	smbuf[1] = "-i";		/* ignore dots */
	smbuf[2] = "-f";
	smbuf[3] = "<>";
	smbuf[4] = "--";
    }

    for (i = 5, n = 0; n < msg->rcpt_num; n++) {
	/* see if we want to send this to a mailing list */
	r = annotatemore_lookup(msg->rcpt[n],
				"/vendor/cmu/cyrus-imapd/news2mail", "",
				&attrib);
	if (r) continue;

	/* add the email address to our argv[] and to our To: header */
	if (attrib.value) {
	    if (i >= allocsize - 1) {
		allocsize += ALLOC_SIZE;
		smbuf = xrealloc(smbuf, allocsize * sizeof(const char *));
	    }

	    smbuf[i++] = xstrdup(attrib.value);
	    smbuf[i] = NULL;

	    if (to[0]) strlcat(to, ", ", sizeof(to));
	    strlcat(to, attrib.value, sizeof(to));
	}
    }

    /* send the message */
    if (i > 5) {
	sm_pid = open_sendmail(smbuf, &sm);

	if (!sm)
	    syslog(LOG_ERR, "news2mail: could not spawn sendmail process");
	else {
	    int body = 0, skip, found_to = 0;

	    rewind(msg->f);

	    while (fgets(buf, sizeof(buf), msg->f)) {
		if (!body && buf[0] == '\r' && buf[1] == '\n') {
		    /* blank line between header and body */
		    body = 1;

		    /* insert a To: header if the message doesn't have one */
		    if (!found_to) fprintf(sm, "To: %s\r\n", to);
		}

		skip = 0;
		if (!body) {
		    /* munge various news-specific headers */
		    if (!strncasecmp(buf, "Newsgroups:", 11)) {
			/* rename Newsgroups: to X-Newsgroups: */
			fprintf(sm, "X-");
		    } else if (!strncasecmp(buf, "Xref:", 5) ||
			       !strncasecmp(buf, "Path:", 5) ||
			       !strncasecmp(buf, "NNTP-Posting-", 13)) {
			/* skip these (for now) */
			skip = 1;
		    } else if (!strncasecmp(buf, "To:", 3)) {
			/* insert our mailing list RCPTs first, and then
			   fold the header to accomodate the original RCPTs */
			fprintf(sm, "To: %s,\r\n", to);
			/* overwrite the original "To:" with spaces */
			memset(buf, ' ', 3);
			found_to = 1;
		    } else if (!strncasecmp(buf, "Reply-To:", 9)) {
			/* strip any post addresses, skip if becomes empty */
			if (!strip_post_addresses(buf+9)) skip = 1;
		    }
		}

		do {
		    if (!skip) fprintf(sm, "%s", buf);
		} while (buf[strlen(buf)-1] != '\n' &&
			 fgets(buf, sizeof(buf), msg->f));
	    }

	    /* Protect against messages not ending in CRLF */
	    if (buf[strlen(buf)-1] != '\n') fprintf(sm, "\r\n");

	    fclose(sm);
	    while (waitpid(sm_pid, &sm_stat, 0) < 0);

	    if (sm_stat) /* sendmail exit value */
		syslog(LOG_ERR, "news2mail failed: %s",
		       sendmail_errstr(sm_stat));
	}

	/* free the RCPTs */
	for (i = 5; smbuf[i]; i++) {
	    free((char *) smbuf[i]);
	    smbuf[i] = NULL;
	}
    }

    return;
}

static void cmd_post(char *msgid, int mode)
{
    FILE *f = NULL;
    message_data_t *msg;
    int r = 0;

    /* check if we want this article */
    if (msgid && find_msgid(msgid, NULL, NULL)) {
	/* already have it */
	r = NNTP_DONT_SEND;
    }

    if (mode != POST_TAKETHIS) {
	if (r) {
	    prot_printf(nntp_out, "%u %s Do not send article\r\n",
			post_codes[mode].no, msgid ? msgid : "");
	    return;
	}
	else {
	    prot_printf(nntp_out, "%u %s Send article\r\n",
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

	/* deliver the article */
	if (!r) r = deliver(msg);

	if (!r) {
	    prot_printf(nntp_out, "%u %s Article received ok\r\n",
			post_codes[mode].ok, msg->id ? msg->id : "");

	    /* process control messages */
	    if (msg->control && !config_mupdate_server) {
		int r1 = 0;

		/* XXX check PGP signature */
		if (!strncmp(msg->control, "newgroup", 8))
		    r1 = newgroup(msg);
		else if (!strncmp(msg->control, "rmgroup", 7))
		    r1 = rmgroup(msg);
		else if (!strncmp(msg->control, "mvgroup", 7))
		    r1 = mvgroup(msg);
		else if (!strncmp(msg->control, "cancel", 6))
		    r1 = cancel(msg);
		else
		    r1 = NNTP_UNKNOWN_CONTROLMSG;

		if (r1)
		    syslog(LOG_WARNING, "control message '%s' failed: %s",
			   msg->control, error_message(r1));
		else {
		    syslog(LOG_INFO, "control message '%s' succeeded",
			   msg->control);
		}
	    }

	    if (msg->id) {
		const char *peers = config_getstring(IMAPOPT_NEWSPEER);

		/* send the article upstream */
		if (peers) {
		    char *tmpbuf, *cur_peer, *next_peer;

		    /* make a working copy of the peers */
		    cur_peer = tmpbuf = xstrdup(peers);

		    while (cur_peer) {
			/* eat any leading whitespace */
			while (isspace(*cur_peer)) cur_peer++;

			/* find end of peer */
			if ((next_peer = strchr(cur_peer, ' ')) ||
			    (next_peer = strchr(cur_peer, '\t')))
			    *next_peer++ = '\0';

			/* feed the article to this peer */
			feedpeer(cur_peer, msg);

			/* move to next peer */
			cur_peer = next_peer;
		    }

		    free(tmpbuf);
		}

		/* gateway news to mail */
		news2mail(msg);
	    }
	}

	msg_free(msg); /* does fclose() */
	if (stage) append_removestage(stage);
	stage = NULL;
    }
    else {
	/* flush the article from the stream */
	spool_copy_msg(nntp_in, NULL);
    }

    if (r) {
	prot_printf(nntp_out, "%u %s Failed receiving article (%s)\r\n",
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
			       nntps ? 180 : nntp_timeout,
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

static struct wildmat *split_wildmats(char *str)
{
    const char *prefix;
    char pattern[MAX_MAILBOX_NAME+1] = "", *p, *c;
    struct wildmat *wild = NULL;
    int n = 0;

    if ((prefix = config_getstring(IMAPOPT_NEWSPREFIX)))
	snprintf(pattern, sizeof(pattern), "%s.", prefix);
    p = pattern + strlen(pattern);

    /*
     * split the list of wildmats
     *
     * we split them right to left because this is the order in which
     * we want to test them (per draft-ietf-nntpext-base 5.2)
     */
    do {
	if ((c = strrchr(str, ',')))
	    *c++ = '\0';
	else
	    c = str;

	if (!(n % 10)) /* alloc some more */
	    wild = xrealloc(wild, (n + 11) * sizeof(struct wildmat));

	if (*c == '!') wild[n].not = 1;		/* not */
	else if (*c == '@') wild[n].not = -1;	/* absolute not (feeding) */
	else wild[n].not = 0;

	strcpy(p, wild[n].not ? c + 1 : c);
	wild[n++].pat = xstrdup(pattern);
    } while (c != str);
    wild[n].pat = NULL;

    return wild;
}

static void free_wildmats(struct wildmat *wild)
{
    struct wildmat *w = wild;

    while (w->pat) {
	free(w->pat);
	w++;
    }
    free(wild);
}
