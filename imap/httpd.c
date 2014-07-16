/* httpd.c -- HTTP/WebDAV/CalDAV server protocol parsing
 *
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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
#include <sys/param.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "prot.h"

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "httpd.h"
#include "http_proxy.h"

#include "assert.h"
#include "util.h"
#include "iptostring.h"
#include "global.h"
#include "tls.h"
#include "map.h"

#include "exitcodes.h"
#include "imapd.h"
#include "imap_err.h"
#include "http_err.h"
#include "version.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "sync_log.h"
#include "telemetry.h"
#include "backend.h"
#include "proxy.h"
#include "userdeny.h"
#include "message.h"
#include "idle.h"
#include "rfc822date.h"
#include "tok.h"
#include "wildmat.h"
#include "md5.h"

#ifdef WITH_DAV
#include "http_dav.h"
#endif

#include <libxml/tree.h>
#include <libxml/HTMLtree.h>
#include <libxml/uri.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif /* HAVE_ZLIB */


static const char tls_message[] =
    HTML_DOCTYPE
    "<html>\n<head>\n<title>TLS Required</title>\n</head>\n" \
    "<body>\n<h2>TLS is required to use Basic authentication</h2>\n" \
    "Use <a href=\"%s\">%s</a> instead.\n" \
    "</body>\n</html>\n";

extern int optind;
extern char *optarg;
extern int opterr;


#ifdef HAVE_SSL
static SSL *tls_conn;
#endif /* HAVE_SSL */

sasl_conn_t *httpd_saslconn; /* the sasl connection context */

static struct wildmat *allow_cors = NULL;
int httpd_timeout, httpd_keepalive;
char *httpd_userid = NULL, *proxy_userid = NULL;
struct auth_state *httpd_authstate = 0;
int httpd_userisadmin = 0;
int httpd_userisproxyadmin = 0;
struct sockaddr_storage httpd_localaddr, httpd_remoteaddr;
int httpd_haveaddr = 0;
char httpd_clienthost[NI_MAXHOST*2+1] = "[local]";
struct protstream *httpd_out = NULL;
struct protstream *httpd_in = NULL;
struct protgroup *protin = NULL;
static int httpd_logfd = -1;

static sasl_ssf_t extprops_ssf = 0;
int https = 0;
int httpd_tls_done = 0;
int httpd_tls_required = 0;
unsigned avail_auth_schemes = 0; /* bitmask of available auth schemes */
unsigned long config_httpmodules;
int config_httpprettytelemetry;

static time_t compile_time;
struct buf serverinfo = BUF_INITIALIZER;

static void digest_send_success(const char *name __attribute__((unused)),
				const char *data)
{
    prot_printf(httpd_out, "Authentication-Info: %s\r\n", data);
}

/* List of HTTP auth schemes that we support */
struct auth_scheme_t auth_schemes[] = {
    { AUTH_BASIC, "Basic", NULL, AUTH_SERVER_FIRST | AUTH_BASE64, NULL, NULL },
    { AUTH_DIGEST, "Digest", HTTP_DIGEST_MECH, AUTH_NEED_REQUEST|AUTH_SERVER_FIRST,
      &digest_send_success, digest_recv_success },
    { AUTH_SPNEGO, "Negotiate", "GSS-SPNEGO", AUTH_BASE64, NULL, NULL },
    { AUTH_NTLM, "NTLM", "NTLM", AUTH_NEED_PERSIST | AUTH_BASE64, NULL, NULL },
    { -1, NULL, NULL, 0, NULL, NULL }
};


/* the sasl proxy policy context */
static struct proxy_context httpd_proxyctx = {
    0, 1, &httpd_authstate, &httpd_userisadmin, &httpd_userisproxyadmin
};

/* signal to config.c */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

/* current namespace */
struct namespace httpd_namespace;

/* PROXY STUFF */
/* we want a list of our outgoing connections here and which one we're
   currently piping */

/* the current server most commands go to */
struct backend *backend_current = NULL;

/* our cached connections */
struct backend **backend_cached = NULL;

/* end PROXY stuff */

static void starttls(int https);
void usage(void);
void shut_down(int code) __attribute__ ((noreturn));

extern void setproctitle_init(int argc, char **argv, char **envp);
extern int proc_register(const char *progname, const char *clienthost, 
			 const char *userid, const char *mailbox);
extern void proc_cleanup(void);

/* Enable the resetting of a sasl_conn_t */
static int reset_saslconn(sasl_conn_t **conn);

static void cmdloop(void);
static int parse_expect(struct transaction_t *txn);
static void parse_connection(struct transaction_t *txn);
static int parse_ranges(const char *hdr, unsigned long len,
			struct range **ranges);
static int proxy_authz(const char **authzid, struct transaction_t *txn);
static void auth_success(struct transaction_t *txn);
static int http_auth(const char *creds, struct transaction_t *txn);
static void keep_alive(int sig);

static int meth_get(struct transaction_t *txn, void *params);
static int meth_propfind_root(struct transaction_t *txn, void *params);


static struct {
    char *ipremoteport;
    char *iplocalport;
    sasl_ssf_t ssf;
    char *authid;
} saslprops = {NULL,NULL,0,NULL};

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, (mysasl_cb_ft *) &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, (mysasl_cb_ft *) &mysasl_proxy_policy, (void*) &httpd_proxyctx },
    { SASL_CB_CANON_USER, (mysasl_cb_ft *) &mysasl_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

/* Array of HTTP methods known by our server. */
const struct known_meth_t http_methods[] = {
    { "ACL",		0 },
    { "COPY",	   	METH_NOBODY },
    { "DELETE",	   	METH_NOBODY },
    { "GET",	   	METH_NOBODY },
    { "HEAD",	   	METH_NOBODY },
    { "LOCK",		0 },
    { "MKCALENDAR",	0 },
    { "MKCOL",		0 },
    { "MOVE",		METH_NOBODY },
    { "OPTIONS",	METH_NOBODY },
    { "POST",		0 },
    { "PROPFIND",	0 },
    { "PROPPATCH",	0 },
    { "PUT",		0 },
    { "REPORT",		0 },
    { "TRACE",	   	METH_NOBODY },
    { "UNLOCK",	   	METH_NOBODY },
    { NULL,		0 }
};

/* Namespace to fetch static content from filesystem */
struct namespace_t namespace_default = {
    URL_NS_DEFAULT, 1, "", NULL, 0 /* no auth */, ALLOW_READ,
    NULL, NULL, NULL, NULL,
    {
	{ NULL,			NULL },			/* ACL		*/
	{ NULL,			NULL },			/* COPY		*/
	{ NULL,			NULL },			/* DELETE	*/
	{ &meth_get,		NULL },			/* GET		*/
	{ &meth_get,		NULL },			/* HEAD		*/
	{ NULL,			NULL },			/* LOCK		*/
	{ NULL,			NULL },			/* MKCALENDAR	*/
	{ NULL,			NULL },			/* MKCOL	*/
	{ NULL,			NULL },			/* MOVE		*/
	{ &meth_options,	NULL },			/* OPTIONS	*/
	{ NULL,			NULL },			/* POST		*/
	{ &meth_propfind_root,	NULL },			/* PROPFIND	*/
	{ NULL,			NULL },			/* PROPPATCH	*/
	{ NULL,			NULL },			/* PUT		*/
	{ NULL,			NULL },			/* REPORT	*/
	{ &meth_trace,		NULL },			/* TRACE	*/
	{ NULL,			NULL },			/* UNLOCK	*/
    }
};

/* Array of different namespaces and features supported by the server */
struct namespace_t *namespaces[] = {
#ifdef WITH_DAV
    &namespace_principal,
    &namespace_calendar,
    &namespace_addressbook,
    &namespace_ischedule,
    &namespace_domainkey,
#ifdef WITH_JSON
    &namespace_timezone,
#endif
#endif
#ifdef WITH_RSS
    &namespace_rss,
#endif
    &namespace_default,		/* MUST be present and be last!! */
    NULL,
};


static void httpd_reset(void)
{
    int i;
    int bytes_in = 0;
    int bytes_out = 0;

    /* Do any namespace specific cleanup */
    for (i = 0; namespaces[i]; i++) {
	if (namespaces[i]->enabled && namespaces[i]->reset)
	    namespaces[i]->reset();
    }

    proc_cleanup();

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

    if (httpd_in) {
	prot_NONBLOCK(httpd_in);
	prot_fill(httpd_in);
	bytes_in = prot_bytes_in(httpd_in);
	prot_free(httpd_in);
    }

    if (httpd_out) {
	prot_flush(httpd_out);
	bytes_out = prot_bytes_out(httpd_out);
	prot_free(httpd_out);
    }

    if (config_auditlog) {
	syslog(LOG_NOTICE,
	       "auditlog: traffic sessionid=<%s> bytes_in=<%d> bytes_out=<%d>", 
	       session_id(), bytes_in, bytes_out);
    }
    
    httpd_in = httpd_out = NULL;

    if (protin) protgroup_reset(protin);

#ifdef HAVE_SSL
    if (tls_conn) {
	tls_reset_servertls(&tls_conn);
	tls_conn = NULL;
    }
#endif

    cyrus_reset_stdio();

    strcpy(httpd_clienthost, "[local]");
    if (httpd_logfd != -1) {
	close(httpd_logfd);
	httpd_logfd = -1;
    }
    if (httpd_userid != NULL) {
	free(httpd_userid);
	httpd_userid = NULL;
    }
    if (proxy_userid != NULL) {
	free(proxy_userid);
	proxy_userid = NULL;
    }
    if (httpd_authstate) {
	auth_freestate(httpd_authstate);
	httpd_authstate = NULL;
    }
    if (httpd_saslconn) {
	sasl_dispose(&httpd_saslconn);
	httpd_saslconn = NULL;
    }
    httpd_tls_done = 0;

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
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc __attribute__((unused)),
		 char **argv __attribute__((unused)),
		 char **envp __attribute__((unused)))
{
    int r, opt, i, allow_trace = config_getswitch(IMAPOPT_HTTPALLOWTRACE);

    LIBXML_TEST_VERSION

    initialize_http_error_table();

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);
    setproctitle_init(argc, argv, envp);

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signal(SIGPIPE, SIG_IGN);

    /* load the SASL plugins */
    global_sasl_init(1, 1, mysasl_cb);

    /* open the mboxlist, we'll need it for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);

    /* open the quota db, we'll need it for expunge */
    quotadb_init(0);
    quotadb_open(NULL);

    /* open the user deny db */
    denydb_init(0);
    denydb_open(NULL);

    /* open annotations.db, we'll need it for collection properties */
    annotatemore_init(0, NULL, NULL);
    annotatemore_open(NULL);

    /* setup for sending IMAP IDLE notifications */
    idle_enabled();

    /* Set namespace */
    if ((r = mboxname_init_namespace(&httpd_namespace, 1)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }
    /* External names are in URIs (UNIX sep) */
    httpd_namespace.hier_sep = '/';

    while ((opt = getopt(argc, argv, "sp:")) != EOF) {
	switch(opt) {
	case 's': /* https (do TLS right away) */
	    https = 1;
	    if (!tls_enabled()) {
		syslog(LOG_ERR, "https: required OpenSSL options not present");
		fatal("https: required OpenSSL options not present",
		      EC_CONFIG);
	    }
	    break;

	case 'p': /* external protection */
	    extprops_ssf = atoi(optarg);
	    break;

	default:
	    usage();
	}
    }

    /* Create a protgroup for input from the client and selected backend */
    protin = protgroup_new(2);

    config_httpprettytelemetry = config_getswitch(IMAPOPT_HTTPPRETTYTELEMETRY);

    if (config_getstring(IMAPOPT_HTTPALLOWCORS)) {
	allow_cors =
	    split_wildmats((char *) config_getstring(IMAPOPT_HTTPALLOWCORS),
			   NULL);
    }

    /* Construct serverinfo string */
    buf_printf(&serverinfo, "Cyrus/%s%s Cyrus-SASL/%u.%u.%u",
	       cyrus_version(), config_mupdate_server ? " (Murder)" : "",
	       SASL_VERSION_MAJOR, SASL_VERSION_MINOR, SASL_VERSION_STEP);
#ifdef HAVE_SSL
    buf_printf(&serverinfo, " OpenSSL/%s", SHLIB_VERSION_NUMBER);
#endif
#ifdef HAVE_ZLIB
    buf_printf(&serverinfo, " zlib/%s", ZLIB_VERSION);
#endif
    buf_printf(&serverinfo, " libxml/%s", LIBXML_DOTTED_VERSION);

    /* Do any namespace specific initialization */
    config_httpmodules = config_getbitfield(IMAPOPT_HTTPMODULES);
    for (i = 0; namespaces[i]; i++) {
	if (allow_trace) namespaces[i]->allow |= ALLOW_TRACE;
	if (namespaces[i]->init) namespaces[i]->init(&serverinfo);
    }

    compile_time = calc_compile_time(__TIME__, __DATE__);

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
    char hbuf[NI_MAXHOST];
    char localip[60], remoteip[60];
    int niflags;
    sasl_security_properties_t *secprops=NULL;
    const char *mechlist, *mech;
    int mechcount = 0;
    size_t mechlen;
    struct auth_scheme_t *scheme;

    session_new_id();

    signals_poll();

    sync_log_init();

    httpd_in = prot_new(0, 0);
    httpd_out = prot_new(1, 1);
    protgroup_insert(protin, httpd_in);

    /* Find out name of client host */
    salen = sizeof(httpd_remoteaddr);
    if (getpeername(0, (struct sockaddr *)&httpd_remoteaddr, &salen) == 0 &&
	(httpd_remoteaddr.ss_family == AF_INET ||
	 httpd_remoteaddr.ss_family == AF_INET6)) {
	if (getnameinfo((struct sockaddr *)&httpd_remoteaddr, salen,
			hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) == 0) {
    	    strncpy(httpd_clienthost, hbuf, sizeof(hbuf));
	    strlcat(httpd_clienthost, " ", sizeof(httpd_clienthost));
	} else {
	    httpd_clienthost[0] = '\0';
	}
	niflags = NI_NUMERICHOST;
#ifdef NI_WITHSCOPEID
	if (((struct sockaddr *)&httpd_remoteaddr)->sa_family == AF_INET6)
	    niflags |= NI_WITHSCOPEID;
#endif
	if (getnameinfo((struct sockaddr *)&httpd_remoteaddr, salen, hbuf,
			sizeof(hbuf), NULL, 0, niflags) != 0)
	    strlcpy(hbuf, "unknown", sizeof(hbuf));
	strlcat(httpd_clienthost, "[", sizeof(httpd_clienthost));
	strlcat(httpd_clienthost, hbuf, sizeof(httpd_clienthost));
	strlcat(httpd_clienthost, "]", sizeof(httpd_clienthost));
	salen = sizeof(httpd_localaddr);
	if (getsockname(0, (struct sockaddr *)&httpd_localaddr, &salen) == 0) {
	    httpd_haveaddr = 1;
	}

	/* Create pre-authentication telemetry log based on client IP */
	httpd_logfd = telemetry_log(hbuf, httpd_in, httpd_out, 0);
    }

    /* other params should be filled in */
    if (sasl_server_new("HTTP", config_servername, NULL, NULL, NULL, NULL,
			SASL_USAGE_FLAGS, &httpd_saslconn) != SASL_OK)
	fatal("SASL failed initializing: sasl_server_new()",EC_TEMPFAIL); 

    /* will always return something valid */
    secprops = mysasl_secprops(0);

    /* no HTTP clients seem to use "auth-int" */
    secprops->max_ssf = 0;				/* "auth" only */
    secprops->maxbufsize = 0;  			   	/* don't need maxbuf */
    if (sasl_setprop(httpd_saslconn, SASL_SEC_PROPS, secprops) != SASL_OK)
	fatal("Failed to set SASL property", EC_TEMPFAIL);
    if (sasl_setprop(httpd_saslconn, SASL_SSF_EXTERNAL, &extprops_ssf) != SASL_OK)
	fatal("Failed to set SASL property", EC_TEMPFAIL);
    
    if(iptostring((struct sockaddr *)&httpd_localaddr,
		  salen, localip, 60) == 0) {
	sasl_setprop(httpd_saslconn, SASL_IPLOCALPORT, localip);
	saslprops.iplocalport = xstrdup(localip);
    }
    
    if(iptostring((struct sockaddr *)&httpd_remoteaddr,
		  salen, remoteip, 60) == 0) {
	sasl_setprop(httpd_saslconn, SASL_IPREMOTEPORT, remoteip);  
	saslprops.ipremoteport = xstrdup(remoteip);
    }

    /* See which auth schemes are available to us */
    if ((extprops_ssf >= 2) || config_getswitch(IMAPOPT_ALLOWPLAINTEXT)) {
	avail_auth_schemes |= (1 << AUTH_BASIC);
    }
    sasl_listmech(httpd_saslconn, NULL, NULL, " ", NULL,
		  &mechlist, NULL, &mechcount);
    for (mech = mechlist; mechcount--; mech += ++mechlen) {
	mechlen = strcspn(mech, " \0");
	for (scheme = auth_schemes; scheme->name; scheme++) {
	    if (scheme->saslmech && !strncmp(mech, scheme->saslmech, mechlen)) {
		avail_auth_schemes |= (1 << scheme->idx);
		break;
	    }
	}
    }
    httpd_tls_required = !avail_auth_schemes;

    proc_register("httpd", httpd_clienthost, NULL, NULL);

    /* Set inactivity timer */
    httpd_timeout = config_getint(IMAPOPT_HTTPTIMEOUT);
    if (httpd_timeout < 0) httpd_timeout = 0;
    httpd_timeout *= 60;
    prot_settimeout(httpd_in, httpd_timeout);
    prot_setflushonread(httpd_in, httpd_out);

    /* we were connected on https port so we should do 
       TLS negotiation immediatly */
    if (https == 1) starttls(1);

    /* Setup the signal handler for keepalive heartbeat */
    httpd_keepalive = config_getint(IMAPOPT_HTTPKEEPALIVE);
    if (httpd_keepalive < 0) httpd_keepalive = 0;
    if (httpd_keepalive) {
	struct sigaction action;

	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
#ifdef SA_RESTART
	action.sa_flags |= SA_RESTART;
#endif
	action.sa_handler = keep_alive;
	if (sigaction(SIGALRM, &action, NULL) < 0) {
	    syslog(LOG_ERR, "unable to install signal handler for %d: %m", SIGALRM);
	    httpd_keepalive = 0;
	}
    }

    cmdloop();

    /* Closing connection */

    /* cleanup */
    signal(SIGALRM, SIG_IGN);
    httpd_reset();

    return 0;
}


/* Called by service API to shut down the service */
void service_abort(int error)
{
    shut_down(error);
}


void usage(void)
{
    prot_printf(httpd_out, "%s: usage: httpd [-C <alt_config>] [-s]\r\n",
		error_message(HTTP_SERVER_ERROR));
    prot_flush(httpd_out);
    exit(EC_USAGE);
}


/*
 * Cleanly shut down and exit
 */
void shut_down(int code)
{
    int i;
    int bytes_in = 0;
    int bytes_out = 0;

    in_shutdown = 1;

    if (allow_cors) free_wildmats(allow_cors);

    /* Do any namespace specific cleanup */
    for (i = 0; namespaces[i]; i++) {
	if (namespaces[i]->enabled && namespaces[i]->shutdown)
	    namespaces[i]->shutdown();
    }

    xmlCleanupParser();

    proc_cleanup();

    /* close backend connections */
    i = 0;
    while (backend_cached && backend_cached[i]) {
	proxy_downserver(backend_cached[i]);
	free(backend_cached[i]->context);
	free(backend_cached[i]);
	i++;
    }
    if (backend_cached) free(backend_cached);

    sync_log_done();

    mboxlist_close();
    mboxlist_done();

    quotadb_close();
    quotadb_done();

    denydb_close();
    denydb_done();

    annotatemore_close();
    annotatemore_done();

    if (httpd_in) {
	prot_NONBLOCK(httpd_in);
	prot_fill(httpd_in);
	bytes_in = prot_bytes_in(httpd_in);
	prot_free(httpd_in);
    }

    if (httpd_out) {
	prot_flush(httpd_out);
	bytes_out = prot_bytes_out(httpd_out);
	prot_free(httpd_out);
    }

    if (protin) protgroup_free(protin);

    if (config_auditlog)
	syslog(LOG_NOTICE,
	       "auditlog: traffic sessionid=<%s> bytes_in=<%d> bytes_out=<%d>", 
	       session_id(), bytes_in, bytes_out);

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
    if (httpd_out) {
	prot_printf(httpd_out,
		    "HTTP/1.1 %s\r\n"
		    "Content-Type: text/plain\r\n"
		    "Connection: close\r\n\r\n"
		    "Fatal error: %s\r\n",
		    error_message(HTTP_SERVER_ERROR), s);
	prot_flush(httpd_out);
    }
    syslog(LOG_ERR, "Fatal error: %s", s);
    shut_down(code);
}




#ifdef HAVE_SSL
static void starttls(int https)
{
    int result;
    int *layerp;
    sasl_ssf_t ssf;
    char *auth_id;

    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &ssf;

    result=tls_init_serverengine("http",
				 5,        /* depth to verify */
				 !https,   /* can client auth? */
				 !https);  /* TLS only? */

    if (result == -1) {
	syslog(LOG_ERR, "[httpd] error initializing TLS");
	fatal("tls_init() failed",EC_TEMPFAIL);
    }

    if (!https) {
	/* tell client to start TLS upgrade (RFC 2817) */
	response_header(HTTP_SWITCH_PROT, NULL);
    }
  
    result=tls_start_servertls(0, /* read */
			       1, /* write */
			       https ? 180 : httpd_timeout,
			       layerp,
			       &auth_id,
			       &tls_conn);

    /* if error */
    if (result == -1) {
	syslog(LOG_NOTICE, "https failed: %s", httpd_clienthost);
	fatal("tls_start_servertls() failed", EC_TEMPFAIL);
    }

    /* tell SASL about the negotiated layer */
    result = sasl_setprop(httpd_saslconn, SASL_SSF_EXTERNAL, &ssf);
    if (result != SASL_OK) {
	fatal("sasl_setprop() failed: starttls()", EC_TEMPFAIL);
    }
    saslprops.ssf = ssf;

    result = sasl_setprop(httpd_saslconn, SASL_AUTH_EXTERNAL, auth_id);
    if (result != SASL_OK) {
        fatal("sasl_setprop() failed: starttls()", EC_TEMPFAIL);
    }
    if (saslprops.authid) {
	free(saslprops.authid);
	saslprops.authid = NULL;
    }
    if (auth_id) saslprops.authid = xstrdup(auth_id);

    /* tell the prot layer about our new layers */
    prot_settls(httpd_in, tls_conn);
    prot_settls(httpd_out, tls_conn);

    httpd_tls_done = 1;
    httpd_tls_required = 0;

    avail_auth_schemes |= (1 << AUTH_BASIC);
}
#else
static void starttls(int https __attribute__((unused)))
{
    fatal("starttls() called, but no OpenSSL", EC_SOFTWARE);
}
#endif /* HAVE_SSL */


/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(sasl_conn_t **conn) 
{
    int ret;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("HTTP", config_servername, NULL, NULL, NULL, NULL,
			  SASL_USAGE_FLAGS, conn);
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

    /* no HTTP clients seem to use "auth-int" */
    secprops->max_ssf = 0;				/* "auth" only */
    secprops->maxbufsize = 0;  			   	/* don't need maxbuf */
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
    int gzip_enabled = 0;
    struct transaction_t txn;

    /* Start with an empty (clean) transaction */
    memset(&txn, 0, sizeof(struct transaction_t));

    /* Pre-allocate our working buffer */
    buf_ensure(&txn.buf, 1024);

#ifdef HAVE_ZLIB
    /* Always use gzip format because IE incorrectly uses raw deflate */
    if (config_getswitch(IMAPOPT_HTTPALLOWCOMPRESS) &&
	deflateInit2(&txn.zstrm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
		     16+MAX_WBITS, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY) == Z_OK) {
	gzip_enabled = 1;
    }
#endif

    for (;;) {
	int ret, empty, r, i, c;
	char *p;
	tok_t tok;
	const char **hdr, *query;
	const struct namespace_t *namespace;
	const struct method_t *meth_t;
	struct request_line_t *req_line = &txn.req_line;

	/* Reset txn state */
	txn.meth = METH_UNKNOWN;
	memset(&txn.flags, 0, sizeof(struct txn_flags_t));
	txn.flags.conn = 0;
	txn.flags.vary = VARY_AE;
	memset(req_line, 0, sizeof(struct request_line_t));
	memset(&txn.req_tgt, 0, sizeof(struct request_target_t));
	construct_hash_table(&txn.req_qparams, 10, 1);
	txn.req_uri = NULL;
	txn.auth_chal.param = NULL;
	txn.req_hdrs = NULL;
	txn.req_body.flags = 0;
	buf_reset(&txn.req_body.payload);
	txn.location = NULL;
	memset(&txn.error, 0, sizeof(struct error_t));
	memset(&txn.resp_body, 0,  /* Don't zero the response payload buffer */
	       sizeof(struct resp_body_t) - sizeof(struct buf));
	buf_reset(&txn.resp_body.payload);
	buf_reset(&txn.buf);
	ret = empty = 0;

	/* Create header cache */
	if (!(txn.req_hdrs = spool_new_hdrcache())) {
	    txn.error.desc = "Unable to create header cache";
	    ret = HTTP_SERVER_ERROR;
	}

      req_line:
	do {
	    /* Flush any buffered output */
	    prot_flush(httpd_out);
	    if (backend_current) prot_flush(backend_current->out);

	    /* Check for shutdown file */
	    if (shutdown_file(txn.buf.s, txn.buf.alloc) ||
		(httpd_userid &&
		 userdeny(httpd_userid, config_ident, txn.buf.s, txn.buf.alloc))) {
		txn.error.desc = txn.buf.s;
		ret = HTTP_UNAVAILABLE;
		break;
	    }

	    signals_poll();

	} while (!proxy_check_input(protin, httpd_in, httpd_out,
				    backend_current ? backend_current->in : NULL,
				    NULL, 0));
	if (ret) {
	    txn.flags.conn = CONN_CLOSE;
	    error_response(ret, &txn);
	    protgroup_free(protin);
	    shut_down(0);
	}


	/* Read request-line */
	syslog(LOG_DEBUG, "read & parse request-line");
	if (!prot_fgets(req_line->buf, MAX_REQ_LINE+1, httpd_in)) {
	    txn.error.desc = prot_error(httpd_in);
	    if (txn.error.desc && strcmp(txn.error.desc, PROT_EOF_STRING)) {
		/* client timed out */
		syslog(LOG_WARNING, "%s, closing connection", txn.error.desc);
		ret = HTTP_TIMEOUT;
	    }
	    else {
		/* client closed connection */
	    }

	    txn.flags.conn = CONN_CLOSE;
	    goto done;
	}

	/* Trim CRLF from request-line */
	p = req_line->buf + strlen(req_line->buf);
	if (p[-1] == '\n') *--p = '\0';
	if (p[-1] == '\r') *--p = '\0';

	/* Ignore 1 empty line before request-line per HTTPbis Part 1 Sec 3.5 */
	if (!empty++ && !*req_line->buf) goto req_line;

	/* Parse request-line = method SP request-target SP HTTP-version CRLF */
	tok_initm(&tok, req_line->buf, " ", 0);
	if (!(req_line->meth = tok_next(&tok))) {
	    ret = HTTP_BAD_REQUEST;
	    txn.error.desc = "Missing method in request-line";
	}
	else if (!(req_line->uri = tok_next(&tok))) {
	    ret = HTTP_BAD_REQUEST;
	    txn.error.desc = "Missing request-target in request-line";
	}
	else if ((size_t) (p - req_line->buf) > MAX_REQ_LINE - 2) {
	    /* request-line overran the size of our buffer */
	    ret = HTTP_TOO_LONG;
	    buf_printf(&txn.buf,
		       "Length of request-line MUST be less than %u octets",
		       MAX_REQ_LINE);
	    txn.error.desc = buf_cstring(&txn.buf);
	}
	else if (!(req_line->ver = tok_next(&tok))) {
	    ret = HTTP_BAD_REQUEST;
	    txn.error.desc = "Missing HTTP-version in request-line";
	}
	else if (tok_next(&tok)) {
	    ret = HTTP_BAD_REQUEST;
	    txn.error.desc = "Unexpected extra argument(s) in request-line";
	}

	/* Check HTTP-Version - MUST be HTTP/1.x */
	else if (strlen(req_line->ver) != HTTP_VERSION_LEN
		 || strncmp(req_line->ver, HTTP_VERSION, HTTP_VERSION_LEN-1)
		 || !isdigit(req_line->ver[HTTP_VERSION_LEN-1])) {
	    ret = HTTP_BAD_VERSION;
	    buf_printf(&txn.buf,
		     "This server only speaks %.*sx",
		       HTTP_VERSION_LEN-1, HTTP_VERSION);
	    txn.error.desc = buf_cstring(&txn.buf);
	}
	else if (req_line->ver[HTTP_VERSION_LEN-1] == '0') {
	    /* HTTP/1.0 connection */
	    txn.flags.ver1_0 = 1;
	}
	tok_fini(&tok);

	if (ret) {
	    txn.flags.conn = CONN_CLOSE;
	    goto done;
	}

	/* Read and parse headers */
	syslog(LOG_DEBUG, "read & parse headers");
	if ((r = spool_fill_hdrcache(httpd_in, NULL, txn.req_hdrs, NULL))) {
	    ret = HTTP_BAD_REQUEST;
	    txn.error.desc = error_message(r);
	}
	else if ((txn.error.desc = prot_error(httpd_in)) &&
		 strcmp(txn.error.desc, PROT_EOF_STRING)) {
	    /* client timed out */
	    syslog(LOG_WARNING, "%s, closing connection", txn.error.desc);
	    ret = HTTP_TIMEOUT;
	}

	/* Read CRLF separating headers and body */
	else if ((c = prot_getc(httpd_in)) != '\r' ||
		 (c = prot_getc(httpd_in)) != '\n') {
	    ret = HTTP_BAD_REQUEST;
	    txn.error.desc = error_message(IMAP_MESSAGE_NOBLANKLINE);
	}

	if (ret) {
	    txn.flags.conn = CONN_CLOSE;
	    goto done;
	}

	/* Check for Connection options */
	parse_connection(&txn);
	if (txn.flags.conn & CONN_UPGRADE) {
	    starttls(0);
	    txn.flags.conn &= ~CONN_UPGRADE;
	}

	/* Check for HTTP method override */
	if (!strcmp(req_line->meth, "POST") &&
	    (hdr = spool_getheader(txn.req_hdrs, "X-HTTP-Method-Override"))) {
	    txn.flags.override = 1;
	    req_line->meth = (char *) hdr[0];
	}

	/* Check Method against our list of known methods */
	for (txn.meth = 0; (txn.meth < METH_UNKNOWN) &&
		 strcmp(http_methods[txn.meth].name, req_line->meth);
	     txn.meth++);

	if (txn.meth == METH_UNKNOWN) ret = HTTP_NOT_IMPLEMENTED;

	/* Parse request-target URI */
	else if (!(txn.req_uri = parse_uri(txn.meth, req_line->uri, 1,
					   &txn.error.desc))) {
	    ret = HTTP_BAD_REQUEST;
	}

	/* Check message framing */
	else if ((r = http_parse_framing(txn.req_hdrs, &txn.req_body,
					 &txn.error.desc))) {
	    ret = r;
	}

	/* Check for Expectations */
	else if ((r = parse_expect(&txn))) {
	    ret = r;
	}

	/* Check for mandatory Host header (HTTP/1.1+ only) */
	else if ((hdr = spool_getheader(txn.req_hdrs, "Host")) && hdr[1]) {
	    ret = HTTP_BAD_REQUEST;
	    txn.error.desc = "Too many Host headers";
	}
	else if (!hdr) {
	    if (txn.flags.ver1_0) {
		/* HTTP/1.0 - create a Host header from URI */
		if (txn.req_uri->server) {
		    buf_setcstr(&txn.buf, txn.req_uri->server);
		    if (txn.req_uri->port)
			buf_printf(&txn.buf, ":%d", txn.req_uri->port);
		}
		else buf_setcstr(&txn.buf, config_servername);

		spool_cache_header(xstrdup("Host"),
				   xstrdup(buf_cstring(&txn.buf)),
				   txn.req_hdrs);
		buf_reset(&txn.buf);
	    }
	    else {
		ret = HTTP_BAD_REQUEST;
		txn.error.desc = "Missing Host header";
	    }
	}

	if (ret) goto done;

	query = URI_QUERY(txn.req_uri);

	/* Find the namespace of the requested resource */
	for (i = 0; namespaces[i]; i++) {
	    const char *path = txn.req_uri->path;
	    size_t len;

	    /* Skip disabled namespaces */
	    if (!namespaces[i]->enabled) continue;

	    /* Handle any /.well-known/ bootstrapping */
	    if (namespaces[i]->well_known) {
		len = strlen(namespaces[i]->well_known);
		if (!strncmp(path, namespaces[i]->well_known, len) &&
		    (!path[len] || path[len] == '/')) {

		    hdr = spool_getheader(txn.req_hdrs, "Host");
		    buf_reset(&txn.buf);
		    buf_printf(&txn.buf, "%s://%s",
			       https? "https" : "http", hdr[0]);
		    buf_appendcstr(&txn.buf, namespaces[i]->prefix);
		    buf_appendcstr(&txn.buf, path + len);
		    if (query) buf_printf(&txn.buf, "?%s", query);
		    txn.location = buf_cstring(&txn.buf);

		    ret = HTTP_MOVED;
		    goto done;
		}
	    }

	    /* See if the prefix matches - terminated with NUL or '/' */
	    len = strlen(namespaces[i]->prefix);
	    if (!strncmp(path, namespaces[i]->prefix, len) &&
		(!path[len] || (path[len] == '/') || !strcmp(path, "*"))) {
		break;
	    }
	}
	if ((namespace = namespaces[i])) {
	    txn.req_tgt.namespace = namespace->id;
	    txn.req_tgt.allow = namespace->allow;

	    /* Check if method is supported in this namespace */
	    meth_t = &namespace->methods[txn.meth];
	    if (!meth_t->proc) ret = HTTP_NOT_ALLOWED;

	    /* Check if method expects a body */
	    else if ((http_methods[txn.meth].flags & METH_NOBODY) &&
		     (txn.req_body.framing != FRAMING_LENGTH ||
		      /* XXX  Will break if client sends just a last-chunk */
		      txn.req_body.len)) {
		ret = HTTP_BAD_MEDIATYPE;
	    }
	} else {
	    /* XXX  Should never get here */
	    ret = HTTP_SERVER_ERROR;
	}

	if (ret) goto done;

	/* Perform authentication, if necessary */
	if ((hdr = spool_getheader(txn.req_hdrs, "Authorization"))) {
	    if (httpd_userid) {
		/* Reauth - reinitialize */
		syslog(LOG_DEBUG, "reauth - reinit");
		reset_saslconn(&httpd_saslconn);
		txn.auth_chal.scheme = NULL;
	    }

	    /* Check the auth credentials */
	    r = http_auth(hdr[0], &txn);
	    if ((r < 0) || !txn.auth_chal.scheme) {
		/* Auth failed - reinitialize */
		syslog(LOG_DEBUG, "auth failed - reinit");
		reset_saslconn(&httpd_saslconn);
		txn.auth_chal.scheme = NULL;
		ret = HTTP_UNAUTHORIZED;
	    }
	}
	else if (!httpd_userid && txn.auth_chal.scheme) {
	    /* Started auth exchange, but client didn't engage - reinit */
	    syslog(LOG_DEBUG, "client didn't complete auth - reinit");
	    reset_saslconn(&httpd_saslconn);
	    txn.auth_chal.scheme = NULL;
	}

	/* Perform proxy authorization, if necessary */
	else if (saslprops.authid &&
		 (hdr = spool_getheader(txn.req_hdrs, "Authorize-As")) &&
		 *hdr[0]) {
	    const char *authzid = hdr[0];

	    r = proxy_authz(&authzid, &txn);
	    if (r) {
		/* Proxy authz failed - reinitialize */
		syslog(LOG_DEBUG, "proxy authz failed - reinit");
		reset_saslconn(&httpd_saslconn);
		txn.auth_chal.scheme = NULL;
		ret = HTTP_UNAUTHORIZED;
	    }
	    else {
		httpd_userid = xstrdup(authzid);
		auth_success(&txn);
	    }
	}

	/* Request authentication, if necessary */
	switch (txn.meth) {
	case METH_GET:
	case METH_HEAD:
	case METH_OPTIONS:
	    /* Let method processing function decide if auth is needed */
	    break;

	default:
	    if (!httpd_userid && namespace->need_auth) {
		/* Authentication required */
		ret = HTTP_UNAUTHORIZED;
	    }
	}

	if (ret) goto need_auth;

	/* Check if this is a Cross-Origin Resource Sharing request */
	if (allow_cors && (hdr = spool_getheader(txn.req_hdrs, "Origin"))) {
	    const char *err = NULL;
	    xmlURIPtr uri = parse_uri(METH_UNKNOWN, hdr[0], 0, &err);

	    if (uri && uri->scheme && uri->server) {
		int o_https = !strcasecmp(uri->scheme, "https");

		if ((https == o_https) &&
		    !strcasecmp(uri->server,
				*spool_getheader(txn.req_hdrs, "Host"))) {
		    txn.flags.cors = CORS_SIMPLE;
		}
		else {
		    struct wildmat *wild;

		    /* Create URI w/o path or default port */
		    assert(!buf_len(&txn.buf));
		    buf_printf(&txn.buf, "%s://%s",
			       lcase(uri->scheme), lcase(uri->server));
		    if (uri->port &&
			((o_https && uri->port != 443) ||
			 (!o_https && uri->port != 80))) {
			buf_printf(&txn.buf, ":%d", uri->port);
		    }

		    /* Check Origin against the 'httpallowcors' wildmat */
		    for (wild = allow_cors; wild->pat; wild++) {
			if (wildmat(buf_cstring(&txn.buf), wild->pat)) {
			    /* If we have a non-negative match, allow request */
			    if (!wild->not) txn.flags.cors = CORS_SIMPLE;
			    break;
			}
		    }
		    buf_reset(&txn.buf);
		}
	    }
	    xmlFreeURI(uri);
	}

	/* Check if we should compress response body */
	if (gzip_enabled) {
	    /* XXX  Do we want to support deflate even though M$
	       doesn't implement it correctly (raw deflate vs. zlib)? */

	    if (!txn.flags.ver1_0 &&
		(hdr = spool_getheader(txn.req_hdrs, "TE"))) {
		struct accept *e, *enc = parse_accept(hdr);

		for (e = enc; e && e->token; e++) {
		    if (e->qual > 0.0 &&
			(!strcasecmp(e->token, "gzip") ||
			 !strcasecmp(e->token, "x-gzip"))) {
			txn.flags.te = TE_GZIP;
		    }
		    free(e->token);
		}
		if (enc) free(enc);
	    }
	    else if ((hdr = spool_getheader(txn.req_hdrs, "Accept-Encoding"))) {
		struct accept *e, *enc = parse_accept(hdr);

		for (e = enc; e && e->token; e++) {
		    if (e->qual > 0.0 &&
			(!strcasecmp(e->token, "gzip") ||
			 !strcasecmp(e->token, "x-gzip"))) {
			txn.resp_body.enc = CE_GZIP;
		    }
		    free(e->token);
		}
		if (enc) free(enc);
	    }
	}

	/* Parse any query parameters */
	if (query) {
	    /* Parse the query string and add param/value pairs to hash table */
	    tok_t tok;
	    char *param;

	    assert(!buf_len(&txn.buf));  /* Unescape buffer */

	    tok_init(&tok, (char *) query, ";&=", TOK_TRIMLEFT|TOK_TRIMRIGHT);
	    while ((param = tok_next(&tok))) {
		struct strlist *vals;
		char *value = tok_next(&tok);
		size_t len;

		if (!value) value = "";
		len = strlen(value);
		buf_ensure(&txn.buf, len);

		vals = hash_lookup(param, &txn.req_qparams);
		appendstrlist(&vals,
			      xmlURIUnescapeString(value, len, txn.buf.s));
		hash_insert(param, vals, &txn.req_qparams);
	    }
	    tok_fini(&tok);

	    buf_reset(&txn.buf);
	}

	/* Start method processing alarm (HTTP/1.1+ only) */
	if (!txn.flags.ver1_0) alarm(httpd_keepalive);

	/* Process the requested method */
	ret = (*meth_t->proc)(&txn, meth_t->params);

      need_auth:
	if (ret == HTTP_UNAUTHORIZED) {
	    /* User must authenticate */

	    if (httpd_tls_required) {
		/* We only support TLS+Basic, so tell client to use TLS */
		ret = 0;

		/* Check which response is required */
		if ((hdr = spool_getheader(txn.req_hdrs, "Upgrade")) &&
		    !strncmp(hdr[0], TLS_VERSION, strcspn(hdr[0], " ,"))) {
		    /* Client (Murder proxy) supports RFC 2817 (TLS upgrade) */

		    response_header(HTTP_UPGRADE, &txn);
		}
		else {
		    /* All other clients use RFC 2818 (HTTPS) */
		    const char *path = txn.req_uri->path;
		    struct buf *html = &txn.resp_body.payload;

		    /* Create https URL */
		    hdr = spool_getheader(txn.req_hdrs, "Host");
		    buf_printf(&txn.buf, "https://%s", hdr[0]);
		    if (strcmp(path, "*")) {
			buf_appendcstr(&txn.buf, path);
			if (query) buf_printf(&txn.buf, "?%s", query);
		    }

		    txn.location = buf_cstring(&txn.buf);

		    /* Create HTML body */
		    buf_reset(html);
		    buf_printf(html, tls_message,
			       buf_cstring(&txn.buf), buf_cstring(&txn.buf));

		    /* Output our HTML response */
		    txn.resp_body.type = "text/html; charset=utf-8";
		    write_body(HTTP_MOVED, &txn,
			       buf_cstring(html), buf_len(html));
		}
	    }
	    else {
		/* Tell client to authenticate */
		if (r == SASL_CONTINUE)
		    txn.error.desc = "Continue authentication exchange";
		else if (r) txn.error.desc = "Authentication failed";
		else txn.error.desc =
			 "Must authenticate to access the specified target";
	    }
	}

      done:
	/* Handle errors (success responses handled by method functions) */
	if (ret) error_response(ret, &txn);

	/* Read and discard any unread request body */
	if (!(txn.flags.conn & CONN_CLOSE)) {
	    txn.req_body.flags |= BODY_DISCARD;
	    if (http_read_body(httpd_in, httpd_out,
			       txn.req_hdrs, &txn.req_body, &txn.error.desc)) {
		txn.flags.conn = CONN_CLOSE;
	    }
	}

	/* Memory cleanup */
	if (txn.req_uri) xmlFreeURI(txn.req_uri);
	if (txn.req_hdrs) spool_free_hdrcache(txn.req_hdrs);
	free_hash_table(&txn.req_qparams, (void (*)(void *)) &freestrlist);

	if (txn.flags.conn & CONN_CLOSE) {
	    buf_free(&txn.buf);
	    buf_free(&txn.req_body.payload);
	    buf_free(&txn.resp_body.payload);
#ifdef HAVE_ZLIB
	    deflateEnd(&txn.zstrm);
	    buf_free(&txn.zbuf);
#endif
	    return;
	}

	continue;
    }
}

/****************************  Parsing Routines  ******************************/

/* Parse URI, returning the path */
xmlURIPtr parse_uri(unsigned meth, const char *uri, unsigned path_reqd,
		    const char **errstr)
{
    xmlURIPtr p_uri;  /* parsed URI */

    /* Parse entire URI */
    if ((p_uri = xmlParseURI(uri)) == NULL) {
	*errstr = "Illegal request target URI";
	goto bad_request;
    }

    if (p_uri->scheme) {
	/* Check sanity of scheme */

	if (strcasecmp(p_uri->scheme, "http") &&
	    strcasecmp(p_uri->scheme, "https")) {
	    *errstr = "Unsupported URI scheme";
	    goto bad_request;
	}
    }

    /* Check sanity of path */
    if (path_reqd && (!p_uri->path || !*p_uri->path)) {
	*errstr = "Empty path in target URI";
	goto bad_request;
    }
    else if (p_uri->path) {
	if ((p_uri->path[0] != '/') &&
	    (strcmp(p_uri->path, "*") || (meth != METH_OPTIONS))) {
	    /* No special URLs except for "OPTIONS * HTTP/1.1" */
	    *errstr = "Illegal request target URI";
	    goto bad_request;
	}
	else if (strstr(p_uri->path, "/..")) {
	    /* Don't allow access up directory tree */
	    *errstr = "Illegal request target URI";
	    goto bad_request;
	}
	else if (strlen(p_uri->path) > MAX_MAILBOX_PATH) {
	    *errstr = "Request target URI too long";
	    goto bad_request;
	}
    }

    return p_uri;

  bad_request:
    if (p_uri) xmlFreeURI(p_uri);
    return NULL;
}


/* Calculate compile time of a file for use as Last-Modified and/or ETag */
time_t calc_compile_time(const char *time, const char *date)
{
    struct tm tm;
    char month[4];
    const char *monthname[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    memset(&tm, 0, sizeof(struct tm));
    tm.tm_isdst = -1;
    sscanf(time, "%02d:%02d:%02d", &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    sscanf(date, "%s %2d %4d", month, &tm.tm_mday, &tm.tm_year);
    tm.tm_year -= 1900;
    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcmp(month, monthname[tm.tm_mon])) break;
    }

    return mktime(&tm);
}


/* Parse Expect header(s) for interesting expectations */
static int parse_expect(struct transaction_t *txn)
{
    const char **exp = spool_getheader(txn->req_hdrs, "Expect");
    int i, ret = 0;

    /* Expect not supported by HTTP/1.0 clients */
    if (exp && txn->flags.ver1_0) return HTTP_EXPECT_FAILED;

    /* Look for interesting expectations.  Unknown == error */
    for (i = 0; !ret && exp && exp[i]; i++) {
	tok_t tok = TOK_INITIALIZER(exp[i], ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
	char *token;

	while (!ret && (token = tok_next(&tok))) {
	    /* Check if this is a non-persistent connection */
	    if (!strcasecmp(token, "100-continue")) {
		syslog(LOG_DEBUG, "Expect: 100-continue");
		txn->req_body.flags |= BODY_CONTINUE;
	    }
	    else {
		txn->error.desc = "Unsupported Expectation";
		ret = HTTP_EXPECT_FAILED;
	    }
	}

	tok_fini(&tok);
    }

    return ret;
}


/* Parse Connection header(s) for interesting options */
static void parse_connection(struct transaction_t *txn)
{
    const char **conn = spool_getheader(txn->req_hdrs, "Connection");
    int i;

    /* Look for interesting connection tokens */
    for (i = 0; conn && conn[i]; i++) {
	tok_t tok = TOK_INITIALIZER(conn[i], ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
	char *token;

	while ((token = tok_next(&tok))) {
	    if (httpd_timeout) {
		/* Check if this is a non-persistent connection */
		if (!strcasecmp(token, "close")) {
		    txn->flags.conn |= CONN_CLOSE;
		    continue;
		}

		/* Check if this is a persistent connection */
		else if (!strcasecmp(token, "keep-alive")) {
		    txn->flags.conn |= CONN_KEEPALIVE;
		    continue;
		}
	    }

	    /* Check if we need to upgrade to TLS */
	    if (!httpd_tls_done && tls_enabled() &&
		     !strcasecmp(token, "Upgrade")) {
		const char **upgrd;

		if ((upgrd = spool_getheader(txn->req_hdrs, "Upgrade")) &&
		    !strncmp(upgrd[0], TLS_VERSION, strcspn(upgrd[0], " ,"))) {
		    syslog(LOG_DEBUG, "client requested TLS");
		    txn->flags.conn |= CONN_UPGRADE;
		}
	    }
	}

	tok_fini(&tok);
    }

    if (!httpd_timeout) txn->flags.conn |= CONN_CLOSE;
    else if (txn->flags.conn & CONN_CLOSE) {
	/* close overrides keep-alive */
	txn->flags.conn &= ~CONN_KEEPALIVE;
    }
    else if (txn->flags.ver1_0 && !(txn->flags.conn & CONN_KEEPALIVE)) {
	/* HTTP/1.0 - non-persistent connection unless keep-alive */
	txn->flags.conn |= CONN_CLOSE;
    }
}


/* Compare accept quality values so that they sort in descending order */
static int compare_accept(const struct accept *a1, const struct accept *a2)
{
    if (a2->qual < a1->qual) return -1;
    if (a2->qual > a1->qual) return 1;
    return 0;
}

struct accept *parse_accept(const char **hdr)
{
    int i, n = 0, alloc = 0;
    struct accept *ret = NULL;
#define GROW_ACCEPT 10;

    for (i = 0; hdr && hdr[i]; i++) {
	tok_t tok = TOK_INITIALIZER(hdr[i], ";,", TOK_TRIMLEFT|TOK_TRIMRIGHT);
	char *token;

	while ((token = tok_next(&tok))) {
	    if (!strncmp(token, "q=", 2)) {
		if (!ret) break;
		ret[n-1].qual = strtof(token+2, NULL);
	    }
	    else {
		if (n + 1 >= alloc)  {
		    alloc += GROW_ACCEPT;
		    ret = xrealloc(ret, alloc * sizeof(struct accept));
		}
		ret[n].token = xstrdup(token);
		ret[n].qual = 1.0;
		ret[++n].token = NULL;
	    }
	}
	tok_fini(&tok);
    }

    qsort(ret, n, sizeof(struct accept),
	  (int (*)(const void *, const void *)) &compare_accept);

    return ret;
}


/****************************  Response Routines  *****************************/


/* Create RFC3339 date ('buf' must be at least 21 characters) */
char *rfc3339date_gen(char *buf, size_t len, time_t t)
{
    struct tm *tm = gmtime(&t);

    snprintf(buf, len, "%4d-%02d-%02dT%02d:%02d:%02dZ",
	     tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, 
	     tm->tm_hour, tm->tm_min, tm->tm_sec);

    return buf;
}


/* Create HTTP-date ('buf' must be at least 30 characters) */
char *httpdate_gen(char *buf, size_t len, time_t t)
{
    static char *month[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
			     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    static char *wday[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };

    struct tm *tm = gmtime(&t);

    snprintf(buf, len, "%3s, %02d %3s %4d %02d:%02d:%02d GMT",
	     wday[tm->tm_wday], 
	     tm->tm_mday, month[tm->tm_mon], tm->tm_year + 1900,
	     tm->tm_hour, tm->tm_min, tm->tm_sec);

    return buf;
}


/* Create an HTTP Status-Line given response code */
const char *http_statusline(long code)
{
    static struct buf statline = BUF_INITIALIZER;
    static unsigned tail = 0;

    if (!tail) {
	buf_setcstr(&statline, HTTP_VERSION);
	buf_putc(&statline, ' ');
	tail = buf_len(&statline);
    }

    buf_truncate(&statline, tail);
    buf_appendcstr(&statline, error_message(code));
    return buf_cstring(&statline);
}


/* Output an HTTP response header.
 * 'code' specifies the HTTP Status-Code and Reason-Phrase.
 * 'txn' contains the transaction context
 */

#define WWW_Authenticate(name, param)				\
    prot_printf(httpd_out, "WWW-Authenticate: %s", name);	\
    if (param) prot_printf(httpd_out, " %s", param);		\
    prot_puts(httpd_out, "\r\n")

#define Access_Control_Expose(hdr)				\
    prot_puts(httpd_out, "Access-Control-Expose-Headers: " hdr "\r\n")

void comma_list_hdr(const char *hdr, const char *vals[], unsigned flags, ...)
{
    const char *sep = " ";
    va_list args;
    int i;

    va_start(args, flags);
    prot_printf(httpd_out, "%s:", hdr);
    for (i = 0; vals[i]; i++) {
	if (flags & (1 << i)) {
	    prot_puts(httpd_out, sep);
	    prot_vprintf(httpd_out, vals[i], args);
	    sep = ", ";
	}
	else {
	    /* discard any unused args */
	    vsnprintf(NULL, 0, vals[i], args);
	}
    }
    prot_puts(httpd_out, "\r\n");
    va_end(args);
}

void allow_hdr(const char *hdr, unsigned allow)
{
    const char *meths[] = {
	"OPTIONS, GET, HEAD", "POST", "PUT", "DELETE", "TRACE", NULL
    };

    comma_list_hdr(hdr, meths, allow);

    if (allow & ALLOW_DAV) {
	prot_printf(httpd_out, "%s: PROPFIND, REPORT", hdr);
	if (allow & ALLOW_WRITE) {
	    prot_puts(httpd_out, ", COPY, MOVE, LOCK, UNLOCK");
	}
	if (allow & ALLOW_WRITECOL) {
	    prot_puts(httpd_out, ", PROPPATCH, MKCOL, ACL");
	    if (allow & ALLOW_CAL) {
		prot_printf(httpd_out, "\r\n%s: MKCALENDAR", hdr);
	    }
	}
	prot_puts(httpd_out, "\r\n");
    }
}

#define MD5_BASE64_LEN 25   /* ((MD5_DIGEST_LENGTH / 3) + 1) * 4 */

void Content_MD5(const unsigned char *md5)
{
    char base64[MD5_BASE64_LEN+1];

    sasl_encode64((char *) md5, MD5_DIGEST_LENGTH,
		  base64, MD5_BASE64_LEN, NULL);
    prot_printf(httpd_out, "Content-MD5: %s\r\n", base64);
}


void response_header(long code, struct transaction_t *txn)
{
    time_t now;
    char datestr[30];
    unsigned keepalive;
    const char **hdr;
    struct auth_challenge_t *auth_chal;
    struct resp_body_t *resp_body;
    static struct buf log = BUF_INITIALIZER;

    /* Stop method processing alarm */
    keepalive = alarm(0);


    /* Status-Line */
    prot_printf(httpd_out, "%s\r\n", http_statusline(code));


    /* Connection Management */
    switch (code) {
    case HTTP_SWITCH_PROT:
	keepalive = 0;  /* No alarm during TLS negotiation */

	prot_printf(httpd_out, "Upgrade: %s\r\n", TLS_VERSION);
	prot_puts(httpd_out, "Connection: Upgrade\r\n");

	/* Fall through as provisional response */

    case HTTP_CONTINUE:
    case HTTP_PROCESSING:
	/* Provisional response - nothing else needed */

	/* CRLF terminating the header block */
	prot_puts(httpd_out, "\r\n");

	/* Force the response to the client immediately */
	prot_flush(httpd_out);

	/* Reset method processing alarm */
	alarm(keepalive);

	return;

    case HTTP_UPGRADE:
	txn->flags.conn |= CONN_UPGRADE;
	prot_printf(httpd_out, "Upgrade: %s\r\n", TLS_VERSION);

	/* Fall through as final response */

    default:
	/* Final response */
	if (txn->flags.conn) {
	    /* Construct Connection header */
	    const char *conn_tokens[] =
		{ "close", "Upgrade", "Keep-Alive", NULL };

	    if (txn->flags.conn & CONN_KEEPALIVE) {
		prot_printf(httpd_out, "Keep-Alive: timeout=%d\r\n",
			    httpd_timeout);
	    }

	    comma_list_hdr("Connection", conn_tokens, txn->flags.conn);
	}

	auth_chal = &txn->auth_chal;
	resp_body = &txn->resp_body;
    }


    /* Control Data */
    now = time(0);
    httpdate_gen(datestr, sizeof(datestr), now);
    prot_printf(httpd_out, "Date: %s\r\n", datestr);

    if (httpd_tls_done) {
	prot_puts(httpd_out, "Strict-Transport-Security: max-age=600\r\n");
    }
    if (txn->location) {
	prot_printf(httpd_out, "Location: %s\r\n", txn->location);
    }
    if (txn->flags.cc) {
	/* Construct Cache-Control header */
	const char *cc_dirs[] =
	    { "must-revalidate", "no-cache", "no-store", "no-transform",
	      "public", "private", "max-age=%d", NULL };

	comma_list_hdr("Cache-Control", cc_dirs, txn->flags.cc,
		       resp_body->maxage);

	if (txn->flags.cc & CC_MAXAGE) {
	    httpdate_gen(datestr, sizeof(datestr), now + resp_body->maxage);
	    prot_printf(httpd_out, "Expires: %s\r\n", datestr);
	}
    }
    if (txn->flags.cors) {
	/* Construct Cross-Origin Resource Sharing headers */
	prot_printf(httpd_out, "Access-Control-Allow-Origin: %s\r\n",
		    *spool_getheader(txn->req_hdrs, "Origin"));
	prot_puts(httpd_out, "Access-Control-Allow-Credentials: true\r\n");

	if (txn->flags.cors == CORS_PREFLIGHT) {
	    allow_hdr("Access-Control-Allow-Methods", txn->req_tgt.allow);

	    for (hdr = spool_getheader(txn->req_hdrs,
				       "Access-Control-Request-Headers");
		 hdr && *hdr; hdr++) {
		prot_printf(httpd_out,
			    "Access-Control-Allow-Headers: %s\r\n", *hdr);
	    }
	    prot_puts(httpd_out, "Access-Control-Max-Age: 3600\r\n");
	}
    }
    if (txn->flags.vary) {
	/* Construct Vary header */
	const char *vary_hdrs[] =
	    { "Accept", "Accept-Encoding", "Brief", "Prefer", NULL };

	comma_list_hdr("Vary", vary_hdrs, txn->flags.vary);
    }


    /* Response Context */
    if (txn->flags.mime) {
	prot_puts(httpd_out, "MIME-Version: 1.0\r\n");
    }
    if (txn->req_tgt.allow & ALLOW_ISCHEDULE) {
	prot_puts(httpd_out, "iSchedule-Version: 1.0\r\n");
	if (resp_body->iserial) {
	    prot_printf(httpd_out, "iSchedule-Capabilities: %ld\r\n",
			resp_body->iserial);
	}
    }
    if (resp_body->prefs) {
	/* Construct Preference-Applied header */
	const char *prefs[] =
	    { "return=minimal", "return=representation", "depth-noroot", NULL };

	comma_list_hdr("Preference-Applied", prefs, resp_body->prefs);
	if (txn->flags.cors) Access_Control_Expose("Preference-Applied");
    }

    switch (code) {
    case HTTP_OK:
	switch (txn->meth) {
	case METH_GET:
	case METH_HEAD:
	    /* Construct Accept-Ranges header for GET and HEAD responses */
	    prot_printf(httpd_out, "Accept-Ranges: %s\r\n",
			txn->flags.ranges ? "bytes" : "none");
	    break;

	case METH_OPTIONS:
	    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
		prot_printf(httpd_out, "Server: %s\r\n",
			    buf_cstring(&serverinfo));
	    }

	    if (txn->req_tgt.allow & ALLOW_DAV) {
		/* Construct DAV header(s) based on namespace of request URL */
		prot_printf(httpd_out, "DAV: 1,%s 3, access-control%s\r\n",
			    (txn->req_tgt.allow & ALLOW_WRITE) ? " 2," : "",
			    (txn->req_tgt.allow & ALLOW_WRITECOL) ?
			    ", extended-mkcol" : "");
		if (txn->req_tgt.allow & ALLOW_CAL) {
		    prot_printf(httpd_out, "DAV: calendar-access%s%s\r\n",
				(txn->req_tgt.allow & ALLOW_CAL_AVAIL) ?
				", calendar-availability" : "",
				(txn->req_tgt.allow & ALLOW_CAL_SCHED) ?
				", calendar-auto-schedule" : "");

		    /* Backwards compatibility with Apple VAV clients */
		    if ((txn->req_tgt.allow &
			 (ALLOW_CAL_AVAIL | ALLOW_CAL_SCHED)) ==
			(ALLOW_CAL_AVAIL | ALLOW_CAL_SCHED))
			prot_printf(httpd_out, "DAV: inbox-availability\r\n");
		}
		if (txn->req_tgt.allow & ALLOW_CARD) {
		    prot_puts(httpd_out, "DAV: addressbook\r\n");
		}
	    }

	    if (txn->flags.cors == CORS_PREFLIGHT) {
		/* Access-Control-Allow-Methods supersedes Allow */
		break;
	    }
	    else goto allow;
	}
	goto authorized;

    case HTTP_NOT_ALLOWED:
    allow:
	/* Construct Allow header(s) for OPTIONS and 405 response */
	allow_hdr("Allow", txn->req_tgt.allow);
	goto authorized;

    case HTTP_BAD_MEDIATYPE:
	if (txn->req_body.te == TE_UNKNOWN) {
	    /* Construct Allow-Encoding header for 415 response */
#ifdef HAVE_ZLIB
	    prot_puts(httpd_out, "Allow-Encoding: gzip, deflate\r\n");
#else
	    prot_puts(httpd_out, "Allow-Encoding: identity\r\n");
#endif
	}
	goto authorized;

    case HTTP_UNAUTHORIZED:
	/* Authentication Challenges */
	if (!auth_chal->scheme) {
	    /* Require authentication by advertising all possible schemes */
	    struct auth_scheme_t *scheme;

	    for (scheme = auth_schemes; scheme->name; scheme++) {
		/* Only advertise what is available and
		   can work with the type of connection */
		if ((avail_auth_schemes & (1 << scheme->idx)) &&
		    !((txn->flags.conn & CONN_CLOSE) &&
		      (scheme->flags & AUTH_NEED_PERSIST))) {
		    auth_chal->param = NULL;

		    if (scheme->flags & AUTH_SERVER_FIRST) {
			/* Generate the initial challenge */
			http_auth(scheme->name, txn);

			if (!auth_chal->param) continue;  /* If fail, skip it */
		    }
		    WWW_Authenticate(scheme->name, auth_chal->param);
		}
	    }
	}
	else {
	    /* Continue with current authentication exchange */ 
	    WWW_Authenticate(auth_chal->scheme->name, auth_chal->param);
	}
	break;

    default:
    authorized:
	/* Authentication completed/unnecessary */
	if (auth_chal->param) {
	    /* Authentication completed with success data */
	    if (auth_chal->scheme->send_success) {
		/* Special handling of success data for this scheme */
		auth_chal->scheme->send_success(auth_chal->scheme->name,
						auth_chal->param);
	    }
	    else {
		/* Default handling of success data */
		WWW_Authenticate(auth_chal->scheme->name, auth_chal->param);
	    }
	}
    }


    /* Validators */
    if (resp_body->lock) {
	prot_printf(httpd_out, "Lock-Token: <%s>\r\n", resp_body->lock);
	if (txn->flags.cors) Access_Control_Expose("Lock-Token");
    }
    if (resp_body->stag) {
	prot_printf(httpd_out, "Schedule-Tag: \"%s\"\r\n", resp_body->stag);
	if (txn->flags.cors) Access_Control_Expose("Schedule-Tag");
    }
    if (resp_body->etag) {
	prot_printf(httpd_out, "ETag: %s\"%s\"\r\n",
		    resp_body->enc ? "W/" : "", resp_body->etag);
	if (txn->flags.cors) Access_Control_Expose("ETag");
    }
    if (resp_body->lastmod) {
	/* Last-Modified MUST NOT be in the future */
	resp_body->lastmod = MIN(resp_body->lastmod, now);
	httpdate_gen(datestr, sizeof(datestr), resp_body->lastmod);
	prot_printf(httpd_out, "Last-Modified: %s\r\n", datestr);
    }


    /* Representation Metadata */
    if (resp_body->type) {
	prot_printf(httpd_out, "Content-Type: %s\r\n", resp_body->type);

	if (resp_body->fname) {
	    prot_printf(httpd_out,
			"Content-Disposition: inline; filename=\"%s\"\r\n",
			resp_body->fname);
	}
	if (txn->resp_body.enc) {
	    /* Construct Content-Encoding header */
	    const char *ce[] =
		{ "deflate", "gzip", NULL };

	    comma_list_hdr("Content-Encoding", ce, txn->resp_body.enc);
	}
	if (resp_body->lang) {
	    prot_printf(httpd_out, "Content-Language: %s\r\n", resp_body->lang);
	}
	if (resp_body->loc) {
	    prot_printf(httpd_out, "Content-Location: %s\r\n", resp_body->loc);
	    if (txn->flags.cors) Access_Control_Expose("Content-Location");
	}
	if (resp_body->md5) {
	    Content_MD5(resp_body->md5);
	}
    }


    /* Payload */
    switch (code) {
    case HTTP_NO_CONTENT:
    case HTTP_NOT_MODIFIED:
	/* MUST NOT include a body */
	break;

    case HTTP_UNSAT_RANGE:
	prot_printf(httpd_out, "Content-Range: bytes */%lu\r\n",
		    resp_body->len);
	resp_body->len = 0;  /* No content */

	/* Fall through and specify framing */

    case HTTP_PARTIAL:
	if (resp_body->range) {
	    prot_printf(httpd_out, "Content-Range: bytes %lu-%lu/%lu\r\n",
			resp_body->range->first, resp_body->range->last,
			resp_body->len);

	    /* Set actual content length of range */
	    resp_body->len = resp_body->range->last -
		resp_body->range->first + 1;

	    free(resp_body->range);
	}

	/* Fall through and specify framing */

    default:
	if (txn->flags.te) {
	    /* HTTP/1.1+ only - we use close-delimiting for HTTP/1.0 */
	    if (!txn->flags.ver1_0) {
		/* Construct Transfer-Encoding header */
		const char *te[] =
		    { "deflate", "gzip", "chunked", NULL };

		comma_list_hdr("Transfer-Encoding", te, txn->flags.te);

		if (txn->flags.trailer) {
		    /* Construct Trailer header */
		    const char *trailer_hdrs[] =
			{ "Content-MD5", NULL };

		    comma_list_hdr("Trailer", trailer_hdrs, txn->flags.trailer);
		}
	    }
	}
	else if (resp_body->len || txn->meth != METH_HEAD) {
	    prot_printf(httpd_out, "Content-Length: %lu\r\n", resp_body->len);
	}
    }


    /* CRLF terminating the header block */
    prot_puts(httpd_out, "\r\n");


    /* Log the client request and our response */
    buf_reset(&log);
    /* Add client data */
    buf_printf(&log, "%s", httpd_clienthost);
    if (proxy_userid) buf_printf(&log, " as \"%s\"", proxy_userid);
    if (txn->req_hdrs &&
	(hdr = spool_getheader(txn->req_hdrs, "User-Agent"))) {
	buf_printf(&log, " with \"%s\"", hdr[0]);
	if ((hdr = spool_getheader(txn->req_hdrs, "X-Client")))
	    buf_printf(&log, " by \"%s\"", hdr[0]);
	else if ((hdr = spool_getheader(txn->req_hdrs, "X-Requested-With")))
	    buf_printf(&log, " by \"%s\"", hdr[0]);
    }
    /* Add request-line */
    buf_appendcstr(&log, "; \"");
    if (txn->req_line.meth) {
	buf_printf(&log, "%s",
		   txn->flags.override ? "POST" : txn->req_line.meth);
	if (txn->req_line.uri) {
	    buf_printf(&log, " %s", txn->req_line.uri);
	    if (txn->req_line.ver) {
		buf_printf(&log, " %s", txn->req_line.ver);
		if (code != HTTP_TOO_LONG) {
		    char *p = txn->req_line.ver + strlen(txn->req_line.ver) + 1;
		    if (*p) buf_printf(&log, " %s", p);
		}
	    }
	}
    }
    buf_appendcstr(&log, "\"");
    if (txn->req_hdrs) {
	/* Add any request modifying headers */
	const char *sep = " (";

	if (txn->flags.override) {
	    buf_printf(&log, "%smethod-override=%s", sep, txn->req_line.meth);
	    sep = "; ";
	}
	if ((hdr = spool_getheader(txn->req_hdrs, "Origin"))) {
	    buf_printf(&log, "%sorigin=%s", sep, hdr[0]);
	    sep = "; ";
	}
	if ((hdr = spool_getheader(txn->req_hdrs, "Referer"))) {
	    buf_printf(&log, "%sreferer=%s", sep, hdr[0]);
	    sep = "; ";
	}
	if ((hdr = spool_getheader(txn->req_hdrs, "Destination"))) {
	    buf_printf(&log, "%sdestination=%s", sep, hdr[0]);
	    sep = "; ";
	}
	if ((hdr = spool_getheader(txn->req_hdrs, ":type"))) {
	    buf_printf(&log, "%stype=%s", sep, hdr[0]);
	    sep = "; ";
	}
	if ((hdr = spool_getheader(txn->req_hdrs, "Depth"))) {
	    buf_printf(&log, "%sdepth=%s", sep, hdr[0]);
	    sep = "; ";
	}
	if (*sep == ';') buf_appendcstr(&log, ")");
    }
    buf_printf(&log, " => \"%s\"", error_message(code));
    /* Add any auxiliary response data */
    if (txn->location) {
	buf_printf(&log, " (location=%s)", txn->location);
    }
    else if (txn->flags.cors) {
	buf_appendcstr(&log, " (allow-origin)");
    }
    else if (txn->error.desc) {
	buf_printf(&log, " (error=%s)", txn->error.desc);
    }
    syslog(LOG_INFO, "%s", buf_cstring(&log));
}


static void keep_alive(int sig)
{
    if (sig == SIGALRM) {
	response_header(HTTP_CONTINUE, NULL);
	alarm(httpd_keepalive);
    }
}


/*
 * Output an HTTP response with multipart body data.
 *
 * An initial call with 'code' != 0 will output a response header
 * and the preamble.
 * All subsequent calls should have 'code' = 0 to output just a body part.
 * A final call with 'len' = 0 ends the multipart body.
 */
void write_multipart_body(long code, struct transaction_t *txn,
			  const char *buf, unsigned len)
{
    static char boundary[100];
    struct buf *body = &txn->resp_body.payload;

    if (code) {
	const char *preamble =
	    "This is a message with multiple parts in MIME format.\r\n";

	txn->flags.mime = 1;

	/* Create multipart boundary */
	snprintf(boundary, sizeof(boundary), "%s-%ld-%ld-%ld",
		 *spool_getheader(txn->req_hdrs, "Host"),
		 (long) getpid(), (long) time(0), (long) rand());

	/* Create Content-Type w/ boundary */
	assert(!buf_len(&txn->buf));
	buf_printf(&txn->buf, "%s; boundary=\"%s\"",
		   txn->resp_body.type, boundary);
	txn->resp_body.type = buf_cstring(&txn->buf);

	/* Setup for chunked response and begin multipart */
	txn->flags.te |= TE_CHUNKED;
	if (!buf) {
	    buf = preamble;
	    len = strlen(preamble);
	}
	write_body(code, txn, buf, len);
    }
    else if (len) {
	/* Output delimiter and MIME part-headers */
	buf_reset(body);
	buf_printf(body, "\r\n--%s\r\n", boundary);
	buf_printf(body, "Content-Type: %s\r\n", txn->resp_body.type);
	if (txn->resp_body.range) {
	    buf_printf(body, "Content-Range: bytes %lu-%lu/%lu\r\n",
		       txn->resp_body.range->first,
		       txn->resp_body.range->last,
		       txn->resp_body.len);
	}
	buf_printf(body, "Content-Length: %d\r\n\r\n", len);
	write_body(0, txn, buf_cstring(body), buf_len(body));

	/* Output body-part data */
	write_body(0, txn, buf, len);
    }
    else {
	const char *epilogue = "\r\nEnd of MIME multipart body.\r\n";

	/* Output close-delimiter and epilogue */
	buf_reset(body);
	buf_printf(body, "\r\n--%s--\r\n%s", boundary, epilogue);
	write_body(0, txn, buf_cstring(body), buf_len(body));

	/* End of output */
	write_body(0, txn, NULL, 0);
    }
}


/* Output multipart/byteranges */
static void multipart_byteranges(struct transaction_t *txn,
				 const char *msg_base)
{
    /* Save Content-Range and Content-Type pointers */
    struct range *range = txn->resp_body.range;
    const char *type = txn->resp_body.type;

    /* Start multipart response */
    txn->resp_body.range = NULL;
    txn->resp_body.type = "multipart/byteranges";
    write_multipart_body(HTTP_PARTIAL, txn, NULL, 0);

    txn->resp_body.type = type;
    while (range) {
	unsigned long offset = range->first;
	unsigned long datalen = range->last - range->first + 1;
	struct range *next = range->next;

	/* Output range as body part */
	txn->resp_body.range = range;
	write_multipart_body(0, txn, msg_base + offset, datalen);

	/* Cleanup */
	free(range);
	range = next;
    }

    /* End of multipart body */
    write_multipart_body(0, txn, NULL, 0);
}


/*
 * Output an HTTP response with body data, compressed as necessary.
 *
 * For chunked body data, an initial call with 'code' != 0 will output
 * a response header and the first body chunk.
 * All subsequent calls should have 'code' = 0 to output just the body chunk.
 * A final call with 'len' = 0 ends the chunked body.
 *
 * NOTE: HTTP/1.0 clients can't handle chunked encoding,
 *       so we use bare chunks and close the connection when done.
 */
void write_body(long code, struct transaction_t *txn,
		const char *buf, unsigned len)
{
    unsigned is_dynamic = code ? (txn->flags.te & TE_CHUNKED) : 1;
    unsigned outlen = len, offset = 0;
    int do_md5 = config_getswitch(IMAPOPT_HTTPCONTENTMD5);
    static MD5_CTX ctx;
    static unsigned char md5[MD5_DIGEST_LENGTH];

    if (!is_dynamic && len < GZIP_MIN_LEN) {
	/* Don't compress small static content */
	txn->resp_body.enc = CE_IDENTITY;
	txn->flags.te = TE_NONE;
    }

    /* Compress data */
    if (txn->resp_body.enc || txn->flags.te & ~TE_CHUNKED) {
#ifdef HAVE_ZLIB
	/* Only flush for static content or on last (zero-length) chunk */
	unsigned flush = (is_dynamic && len) ? Z_NO_FLUSH : Z_FINISH;

	if (code) deflateReset(&txn->zstrm);

	txn->zstrm.next_in = (Bytef *) buf;
	txn->zstrm.avail_in = len;
	buf_reset(&txn->zbuf);

	do {
	    buf_ensure(&txn->zbuf,
		       deflateBound(&txn->zstrm, txn->zstrm.avail_in));

	    txn->zstrm.next_out = (Bytef *) txn->zbuf.s + txn->zbuf.len;
	    txn->zstrm.avail_out = txn->zbuf.alloc - txn->zbuf.len;

	    deflate(&txn->zstrm, flush);
	    txn->zbuf.len = txn->zbuf.alloc - txn->zstrm.avail_out;

	} while (!txn->zstrm.avail_out);

	buf = txn->zbuf.s;
	outlen = txn->zbuf.len;
#else
	/* XXX should never get here */
	fatal("Compression requested, but no zlib", EC_SOFTWARE);
#endif /* HAVE_ZLIB */
    }

    if (code) {
	/* Initial call - prepare response header based on CE, TE and version */
	if (do_md5) MD5Init(&ctx);

	if (txn->flags.te & ~TE_CHUNKED) {
	    /* Transfer-Encoded content MUST be chunked */
	    txn->flags.te |= TE_CHUNKED;

	    if (!is_dynamic) {
		/* Handle static content as last chunk */
		len = 0;
	    }
	}

	if (!(txn->flags.te & TE_CHUNKED)) {
	    /* Full/partial body (no encoding).
	     *
	     * In all cases, 'resp_body.len' is used to specify complete-length
	     * In the case of a 206 or 416 response, Content-Length will be
	     * set accordingly in response_header().
	     */
	    txn->resp_body.len = outlen;

	    if (code == HTTP_PARTIAL) {
		/* check_precond() tells us that this is a range request */
		code = parse_ranges(*spool_getheader(txn->req_hdrs, "Range"),
				    outlen, &txn->resp_body.range);

		switch (code) {
		case HTTP_OK:
		    /* Full body (unknown range-unit) */
		    break;

		case HTTP_PARTIAL:
		    /* One or more range request(s) */
		    txn->resp_body.len = outlen;

		    if (txn->resp_body.range->next) {
			/* Multiple ranges */
			multipart_byteranges(txn, buf);
			return;
		    }
		    else {
			/* Single range - set data parameters accordingly */
			offset += txn->resp_body.range->first;
			outlen = txn->resp_body.range->last -
			    txn->resp_body.range->first + 1;
		    }
		    break;

		case HTTP_UNSAT_RANGE:
		    /* No valid ranges */
		    outlen = 0;
		    break;
		}
	    }

	    if (outlen && do_md5) {
		MD5Update(&ctx, buf+offset, outlen);
		MD5Final(md5, &ctx);
		txn->resp_body.md5 = md5;
	    }
	}
	else if (txn->flags.ver1_0) {
	    /* HTTP/1.0 doesn't support chunked - close-delimit the body */
	    txn->flags.conn = CONN_CLOSE;
	}
	else if (do_md5) txn->flags.trailer = TRAILER_CMD5;

	response_header(code, txn);

	/* MUST NOT send a body for 1xx/204/304 response or any HEAD response */
	switch (code) {
	case HTTP_CONTINUE:
	case HTTP_SWITCH_PROT:
	case HTTP_PROCESSING:
	case HTTP_NO_CONTENT:
	case HTTP_NOT_MODIFIED:
	    return;

	default:
	    if (txn->meth == METH_HEAD) return;
	}
    }

    /* Output data */
    if ((txn->flags.te & TE_CHUNKED) && !txn->flags.ver1_0) {
	/* HTTP/1.1 chunk */
	if (outlen) {
	    prot_printf(httpd_out, "%x\r\n", outlen);
	    prot_write(httpd_out, buf, outlen);
	    prot_puts(httpd_out, "\r\n");

	    if (do_md5) MD5Update(&ctx, buf, outlen);	    
	}
	if (!len) {
	    /* Terminate the HTTP/1.1 body with a zero-length chunk */
	    prot_puts(httpd_out, "0\r\n");

	    /* Trailer */
	    if (do_md5) {
		MD5Final(md5, &ctx);
		Content_MD5(md5);
	    }

	    prot_puts(httpd_out, "\r\n");
	}
    }
    else {
	/* Full body or HTTP/1.0 close-delimited body */
	prot_write(httpd_out, buf + offset, outlen);
    }
}


/* Output an HTTP response with application/xml body */
void xml_response(long code, struct transaction_t *txn, xmlDocPtr xml)
{
    xmlChar *buf;
    int bufsiz;

    switch (code) {
    case HTTP_OK:
    case HTTP_CREATED:
    case HTTP_NO_CONTENT:
    case HTTP_MULTI_STATUS:
	break;

    default:
	/* Neither Brief nor Prefer affect error response bodies */
	txn->flags.vary &= ~(VARY_BRIEF | VARY_PREFER);
	txn->resp_body.prefs = 0;
    }

    /* Dump XML response tree into a text buffer */
    xmlDocDumpFormatMemoryEnc(xml, &buf, &bufsiz, "utf-8",
			      config_httpprettytelemetry);

    if (buf) {
	/* Output the XML response */
	txn->resp_body.type = "application/xml; charset=utf-8";

	write_body(code, txn, (char *) buf, bufsiz);

	/* Cleanup */
	xmlFree(buf);
    }
    else {
	txn->error.precond = 0;
	txn->error.desc = "Error dumping XML tree\r\n";
	error_response(HTTP_SERVER_ERROR, txn);
    }
}

void buf_printf_markup(struct buf *buf, unsigned level, const char *fmt, ...)
{
    va_list args;
    const char *eol = "\n";

    if (!config_httpprettytelemetry) {
	level = 0;
	eol = "";
    }

    va_start(args, fmt);

    buf_printf(buf, "%*s", level * MARKUP_INDENT, "");
    buf_vprintf(buf, fmt, args);
    buf_appendcstr(buf, eol);

    va_end(args);
}


/* Output an HTTP error response with optional XML or HTML body */
void error_response(long code, struct transaction_t *txn)
{
    struct buf *html = &txn->resp_body.payload;

    /* Neither Brief nor Prefer affect error response bodies */
    txn->flags.vary &= ~(VARY_BRIEF | VARY_PREFER);
    txn->resp_body.prefs = 0;

#ifdef WITH_DAV
    if (code != HTTP_UNAUTHORIZED && txn->error.precond) {
	xmlNodePtr root = xml_add_error(NULL, &txn->error, NULL);

	if (root) {
	    xml_response(code, txn, root->doc);
	    xmlFreeDoc(root->doc);
	    return;
	}
    }
#endif

    if (!txn->error.desc) {
	switch (code) {
	    /* 4xx codes */
	case HTTP_BAD_REQUEST:
	    txn->error.desc =
		"The request was not understood by this server.";
	    break;

	case HTTP_NOT_FOUND:
	    txn->error.desc =
		"The requested URL was not found on this server.";
	    break;

	case HTTP_NOT_ALLOWED:
	    txn->error.desc =
		"The requested method is not allowed for the URL.";
	    break;

	case HTTP_GONE:
	    txn->error.desc =
		"The requested URL has been removed from this server.";
	    break;

	    /* 5xx codes */
	case HTTP_SERVER_ERROR:
	    txn->error.desc =
		"The server encountered an internal error.";
	    break;

	case HTTP_NOT_IMPLEMENTED:
	    txn->error.desc =
		"The requested method is not implemented by this server.";
	    break;

	case HTTP_UNAVAILABLE:
	    txn->error.desc =
		"The server is unable to process the request at this time.";
	    break;
	}
    }

    buf_reset(html);
    if (txn->error.desc) {
	const char **hdr, *host = "";
	char *port = NULL;
	unsigned level = 0;

	if (txn->req_hdrs &&
	    (hdr = spool_getheader(txn->req_hdrs, "Host")) &&
	    hdr[0] && *hdr[0]) {
	    host = (char *) hdr[0];
	    if ((port = strchr(host, ':'))) *port++ = '\0';
	}
	else if (config_serverinfo != IMAP_ENUM_SERVERINFO_OFF) {
	    host = config_servername;
	}
	if (!port) port = strchr(saslprops.iplocalport, ';')+1;

	buf_printf_markup(html, level, HTML_DOCTYPE);
	buf_printf_markup(html, level++, "<html>");
	buf_printf_markup(html, level++, "<head>");
	buf_printf_markup(html, level, "<title>%s</title>",
			  error_message(code));
	buf_printf_markup(html, --level, "</head>");
	buf_printf_markup(html, level++, "<body>");
	buf_printf_markup(html, level, "<h1>%s</h1>", error_message(code)+4);
	buf_printf_markup(html, level, "<p>%s</p>", txn->error.desc);
	buf_printf_markup(html, level, "<hr>");
	buf_printf_markup(html, level,
			  "<address>%s Server at %s Port %s</address>",
			  buf_cstring(&serverinfo), host, port);
	buf_printf_markup(html, --level, "</body>");
	buf_printf_markup(html, --level, "</html>");

	txn->resp_body.type = "text/html; charset=utf-8";
    }

    write_body(code, txn, buf_cstring(html), buf_len(html));
}


static int proxy_authz(const char **authzid, struct transaction_t *txn)
{
    static char authzbuf[MAX_MAILBOX_BUFFER];
    unsigned authzlen;
    int status;

    syslog(LOG_DEBUG, "proxy_auth: authzid='%s'", *authzid);

    /* Free userid & authstate previously allocated for auth'd user */
    if (httpd_userid) {
	free(httpd_userid);
	httpd_userid = NULL;
    }
    if (httpd_authstate) {
	auth_freestate(httpd_authstate);
	httpd_authstate = NULL;
    }

    if (!(config_mupdate_server && config_getstring(IMAPOPT_PROXYSERVERS))) {
	/* Not a backend in a Murder - proxy authz is not allowed */
	syslog(LOG_NOTICE, "badlogin: %s %s %s %s",
	       httpd_clienthost, txn->auth_chal.scheme->name, saslprops.authid,
	       "proxy authz attempted on non-Murder backend");
	return SASL_NOAUTHZ;
    }

    /* Canonify the authzid */
    status = mysasl_canon_user(httpd_saslconn, NULL,
			       *authzid, strlen(*authzid),
			       SASL_CU_AUTHZID, NULL,
			       authzbuf, sizeof(authzbuf), &authzlen);
    if (status) {
	syslog(LOG_NOTICE, "badlogin: %s %s %s invalid user",
	       httpd_clienthost, txn->auth_chal.scheme->name,
	       beautify_string(*authzid));
	return status;
    }

    /* See if auth'd user is allowed to proxy */
    status = mysasl_proxy_policy(httpd_saslconn, &httpd_proxyctx,
				 authzbuf, authzlen,
				 saslprops.authid, strlen(saslprops.authid),
				 NULL, 0, NULL);

    if (status) {
	syslog(LOG_NOTICE, "badlogin: %s %s %s %s",
	       httpd_clienthost, txn->auth_chal.scheme->name, saslprops.authid,
	       sasl_errdetail(httpd_saslconn));
	return status;
    }

    *authzid = authzbuf;

    return status;
}


/* Write cached header (redacting authorization credentials) to buffer. */
static void log_cachehdr(const char *name, const char *contents, void *rock)
{
    struct buf *buf = (struct buf *) rock;

    /* Ignore private headers in our cache */
    if (name[0] == ':') return;

    buf_printf(buf, "%c%s: ", toupper(name[0]), name+1);
    if (!strcmp(name, "authorization")) {
	/* Replace authorization credentials with an ellipsis */
	const char *creds = strchr(contents, ' ') + 1;
	buf_printf(buf, "%.*s%-*s\r\n", (int) (creds - contents), contents,
		   (int) strlen(creds), "...");
    }
    else buf_printf(buf, "%s\r\n", contents);
}


static void auth_success(struct transaction_t *txn)
{
    struct auth_scheme_t *scheme = txn->auth_chal.scheme;
    int i;

    proc_register("httpd", httpd_clienthost, httpd_userid, (char *)0);

    syslog(LOG_NOTICE, "login: %s %s %s%s %s SESSIONID=<%s>",
	   httpd_clienthost, httpd_userid, scheme->name,
	   httpd_tls_done ? "+TLS" : "", "User logged in",
	   session_id());


    /* Recreate telemetry log entry for request (w/ credentials redacted) */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "<%ld<", time(NULL));		/* timestamp */
    buf_printf(&txn->buf, "%s %s %s\r\n",		/* request-line*/
	       txn->req_line.meth, txn->req_line.uri, txn->req_line.ver);
    spool_enum_hdrcache(txn->req_hdrs,			/* header fields */
			&log_cachehdr, &txn->buf);
    buf_appendcstr(&txn->buf, "\r\n");			/* CRLF */
    buf_append(&txn->buf, &txn->req_body.payload);	/* message body */
    buf_appendmap(&txn->buf,				/* buffered input */
		  (const char *) httpd_in->ptr, httpd_in->cnt);

    if (httpd_logfd != -1) {
	/* Rewind log to current request and truncate it */
	off_t end = lseek(httpd_logfd, 0, SEEK_END);

	ftruncate(httpd_logfd, end - buf_len(&txn->buf));
    }

    if (!proxy_userid || strcmp(proxy_userid, httpd_userid)) {
	/* Close existing telemetry log */
	close(httpd_logfd);

	prot_setlog(httpd_in, PROT_NO_FD);
	prot_setlog(httpd_out, PROT_NO_FD);

	/* Create telemetry log based on new userid */
	httpd_logfd = telemetry_log(httpd_userid, httpd_in, httpd_out, 0);
    }

    if (httpd_logfd != -1) {
	/* Log credential-redacted request */
	write(httpd_logfd, buf_cstring(&txn->buf), buf_len(&txn->buf));
    }

    buf_reset(&txn->buf);

    /* Make a copy of the external userid for use in proxying */
    if (proxy_userid) free(proxy_userid);
    proxy_userid = xstrdup(httpd_userid);

    /* Translate any separators in userid */
    mboxname_hiersep_tointernal(&httpd_namespace, httpd_userid,
				config_virtdomains ?
				strcspn(httpd_userid, "@") : 0);

    /* Do any namespace specific post-auth processing */
    for (i = 0; namespaces[i]; i++) {
	if (namespaces[i]->enabled && namespaces[i]->auth)
	    namespaces[i]->auth(httpd_userid);
    }
}


/* Perform HTTP Authentication based on the given credentials ('creds').
 * Returns the selected auth scheme and any server challenge in 'chal'.
 * May be called multiple times if auth scheme requires multiple steps.
 * SASL status between steps is maintained in 'status'.
 */
#define BASE64_BUF_SIZE 21848	/* per RFC 4422: ((16K / 3) + 1) * 4  */

static int http_auth(const char *creds, struct transaction_t *txn)
{
    struct auth_challenge_t *chal = &txn->auth_chal;
    static int status = SASL_OK;
    int slen;
    const char *clientin = NULL, *realm = NULL, *user, **authzid;
    unsigned int clientinlen = 0;
    struct auth_scheme_t *scheme;
    static char base64[BASE64_BUF_SIZE+1];
    const void *canon_user;

    /* Split credentials into auth scheme and response */
    slen = strcspn(creds, " \0");
    if ((clientin = strchr(creds, ' '))) clientinlen = strlen(++clientin);

    syslog(LOG_DEBUG,
	   "http_auth: status=%d   scheme='%s'   creds='%.*s%s'",
	   status, chal->scheme ? chal->scheme->name : "",
	   slen, creds, clientin ? " <response>" : "");

    /* Free userid & authstate previously allocated for auth'd user */
    if (httpd_userid) {
	free(httpd_userid);
	httpd_userid = NULL;
    }
    if (httpd_authstate) {
	auth_freestate(httpd_authstate);
	httpd_authstate = NULL;
    }
    chal->param = NULL;

    if (chal->scheme) {
	/* Use current scheme, if possible */
	scheme = chal->scheme;

	if (strncasecmp(scheme->name, creds, slen)) {
	    /* Changing auth scheme -> reset state */
	    syslog(LOG_DEBUG, "http_auth: changing scheme");
	    reset_saslconn(&httpd_saslconn);
	    chal->scheme = NULL;
	    status = SASL_OK;
	}
    }

    if (!chal->scheme) {
	/* Find the client-specified auth scheme */
	syslog(LOG_DEBUG, "http_auth: find client scheme");
	for (scheme = auth_schemes; scheme->name; scheme++) {
	    if (slen && !strncasecmp(scheme->name, creds, slen)) {
		/* Found a supported scheme, see if its available */
		if (!(avail_auth_schemes & (1 << scheme->idx))) scheme = NULL;
		break;
	    }
	}
	if (!scheme || !scheme->name) {
	    /* Didn't find a matching scheme that is available */
	    syslog(LOG_DEBUG, "Unknown auth scheme '%.*s'", slen, creds);
	    return SASL_NOMECH;
	}
	/* We found it! */
	syslog(LOG_DEBUG, "http_auth: found matching scheme: %s", scheme->name);
	chal->scheme = scheme;
	status = SASL_OK;
    }

    /* Base64 decode any client response, if necesary */
    if (clientin && (scheme->flags & AUTH_BASE64)) {
	int r = sasl_decode64(clientin, clientinlen,
			      base64, BASE64_BUF_SIZE, &clientinlen);
	if (r != SASL_OK) {
	    syslog(LOG_ERR, "Base64 decode failed: %s",
		   sasl_errstring(r, NULL, NULL));
	    return r;
	}
	clientin = base64;
    }

    /* Get realm - based on namespace of URL */
    switch (txn->req_tgt.namespace) {
    case URL_NS_DEFAULT:
    case URL_NS_PRINCIPAL:
	realm = config_getstring(IMAPOPT_DAV_REALM);
	break;

    case URL_NS_CALENDAR:
	realm = config_getstring(IMAPOPT_CALDAV_REALM);
	break;

    case URL_NS_ADDRESSBOOK:
	realm = config_getstring(IMAPOPT_CARDDAV_REALM);
	break;

    case URL_NS_RSS:
	realm = config_getstring(IMAPOPT_RSS_REALM);
	break;
    }
    if (!realm) realm = config_servername;

#ifdef SASL_HTTP_REQUEST
    /* Setup SASL HTTP request, if necessary */
    if (scheme->flags & AUTH_NEED_REQUEST) {
	sasl_http_request_t sasl_http_req;

	sasl_http_req.method = txn->req_line.meth;
	sasl_http_req.uri = txn->req_line.uri;
	sasl_http_req.entity = NULL;
	sasl_http_req.elen = 0;
	sasl_http_req.non_persist = txn->flags.conn & CONN_CLOSE;
	sasl_setprop(httpd_saslconn, SASL_HTTP_REQUEST, &sasl_http_req);
    }
#endif /* SASL_HTTP_REQUEST */

    if (scheme->idx == AUTH_BASIC) {
	/* Basic (plaintext) authentication */
	char *pass;

	if (!clientin) {
	    /* Create initial challenge (base64 buffer is static) */
	    snprintf(base64, BASE64_BUF_SIZE, "realm=\"%s\"", realm);
	    chal->param = base64;
	    chal->scheme = NULL;  /* make sure we don't reset the SASL ctx */
	    return status;
	}

	/* Split credentials into <user> ':' <pass>.
	 * We are working with base64 buffer, so we can modify it.
	 */
	user = base64;
	pass = strchr(base64, ':');
	if (!pass) {
	    syslog(LOG_ERR, "Basic auth: Missing password");
	    return SASL_BADPARAM;
	}
	*pass++ = '\0';
	
	/* Verify the password */
	status = sasl_checkpass(httpd_saslconn, user, strlen(user),
				pass, strlen(pass));
	memset(pass, 0, strlen(pass));		/* erase plaintext password */

	if (status) {
	    syslog(LOG_NOTICE, "badlogin: %s Basic %s %s",
		   httpd_clienthost, user, sasl_errdetail(httpd_saslconn));

	    /* Don't allow user probing */
	    if (status == SASL_NOUSER) status = SASL_BADAUTH;
	    return status;
	}

	/* Successful authentication - fall through */
    }
    else {
	/* SASL-based authentication (Digest, Negotiate, NTLM) */
	const char *serverout = NULL;
	unsigned int serveroutlen = 0;

	if (status == SASL_CONTINUE) {
	    /* Continue current authentication exchange */
	    syslog(LOG_DEBUG, "http_auth: continue %s", scheme->saslmech);
	    status = sasl_server_step(httpd_saslconn, clientin, clientinlen,
				      &serverout, &serveroutlen);
	}
	else {
	    /* Start new authentication exchange */
	    syslog(LOG_DEBUG, "http_auth: start %s", scheme->saslmech);
	    status = sasl_server_start(httpd_saslconn, scheme->saslmech,
				       clientin, clientinlen,
				       &serverout, &serveroutlen);
	}

	/* Failure - probably bad client response */
	if ((status != SASL_OK) && (status != SASL_CONTINUE)) {
	    syslog(LOG_ERR, "SASL failed: %s",
		   sasl_errstring(status, NULL, NULL));
	    return status;
	}

	/* Base64 encode any server challenge, if necesary */
	if (serverout && (scheme->flags & AUTH_BASE64)) {
	    int r = sasl_encode64(serverout, serveroutlen,
				   base64, BASE64_BUF_SIZE, NULL);
	    if (r != SASL_OK) {
		syslog(LOG_ERR, "Base64 encode failed: %s",
		       sasl_errstring(r, NULL, NULL));
		return r;
	    }
	    serverout = base64;
	}

	chal->param = serverout;

	if (status == SASL_CONTINUE) {
	    /* Need another step to complete authentication */
	    return status;
	}

	/* Successful authentication
	 *
	 * HTTP doesn't support security layers,
	 * so don't attach SASL context to prot layer.
	 */
    }

    /* Get the userid from SASL - already canonicalized */
    status = sasl_getprop(httpd_saslconn, SASL_USERNAME, &canon_user);
    if (status != SASL_OK) {
	syslog(LOG_ERR, "weird SASL error %d getting SASL_USERNAME", status);
	return status;
    }
    user = (const char *) canon_user;

    if (saslprops.authid) free(saslprops.authid);
    saslprops.authid = xstrdup(user);

    authzid = spool_getheader(txn->req_hdrs, "Authorize-As");
    if (authzid && *authzid[0]) {
	/* Trying to proxy as another user */
	user = authzid[0];

	status = proxy_authz(&user, txn);
	if (status) return status;
    }

    httpd_userid = xstrdup(user);

    auth_success(txn);

    return status;
}


/*************************  Method Execution Routines  ************************/


/* Compare an etag in a header to a resource etag.
 * Returns 0 if a match, non-zero otherwise.
 */
int etagcmp(const char *hdr, const char *etag)
{
    size_t len;

    if (!etag) return -1;		/* no representation	   */
    if (!strcmp(hdr, "*")) return 0;	/* any representation	   */

    len = strlen(etag);
    if (!strncmp(hdr, "W/", 2)) hdr+=2;	/* skip weak prefix	   */
    if (*hdr++ != '\"') return 1;    	/* match/skip open DQUOTE  */
    if (strlen(hdr) != len+1) return 1;	/* make sure lengths match */
    if (hdr[len] != '\"') return 1;    	/* match close DQUOTE	   */

    return strncmp(hdr, etag, len);
}


/* Compare a resource etag to a comma-separated list and/or multiple headers
 * looking for a match.  Returns 1 if a match is found, 0 otherwise.
 */
static unsigned etag_match(const char *hdr[], const char *etag)
{
    unsigned i, match = 0;
    tok_t tok;
    char *token;

    for (i = 0; !match && hdr[i]; i++) {
	tok_init(&tok, hdr[i], ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
	while (!match && (token = tok_next(&tok))) {
	    if (!etagcmp(token, etag)) match = 1;
	}
	tok_fini(&tok);
    }

    return match;
}


/* Evaluate If header.  Note that we can't short-circuit any of the tests
   because we need to check for a lock-token anywhere in the header */
static int eval_if(const char *hdr, const char *etag, const char *lock_token,
		   unsigned *locked)
{
    unsigned ret = 0;
    tok_t tok_l;
    char *list;

    /* Process each list, ORing the results */
    tok_init(&tok_l, hdr, ")", TOK_TRIMLEFT|TOK_TRIMRIGHT);
    while ((list = tok_next(&tok_l))) {
	unsigned ret_l = 1;
	tok_t tok_c;
	char *cond;

	/* XXX  Need to handle Resource-Tag for Tagged-list (COPY/MOVE dest) */

	/* Process each condition, ANDing the results */
	tok_initm(&tok_c, list+1, "]>", TOK_TRIMLEFT|TOK_TRIMRIGHT);
	while ((cond = tok_next(&tok_c))) {
	    unsigned r, not = 0;

	    if (!strncmp(cond, "Not", 3)) {
		not = 1;
		cond += 3;
		while (*cond == ' ') cond++;
	    }
	    if (*cond == '[') {
		/* ETag */
		r = !etagcmp(cond+1, etag);
	    }
	    else {
		/* State Token */
		if (!lock_token) r = 0;
		else {
		    r = !strcmp(cond+1, lock_token);
		    if (r) {
			/* Correct lock-token has been provided */
			*locked = 0;
		    }
		}
	    }

	    ret_l &= (not ? !r : r);
	}

	tok_fini(&tok_c);

	ret |= ret_l;
    }

    tok_fini(&tok_l);

    return (ret || locked);
}


static int parse_ranges(const char *hdr, unsigned long len,
			struct range **ranges)
{
    int ret = HTTP_UNSAT_RANGE;
    struct range *new, *tail = *ranges = NULL;
    tok_t tok;
    char *token;

    if (!len) return HTTP_OK;  /* need to know length of representation */

    /* we only handle byte-unit */
    if (!hdr || strncmp(hdr, "bytes=", 6)) return HTTP_OK;

    tok_init(&tok, hdr+6, ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
    while ((token = tok_next(&tok))) {
	/* default to entire representation */
	unsigned long first = 0;
	unsigned long last = len - 1;
	char *p, *endp;

	if (!(p = strchr(token, '-'))) continue;  /* bad byte-range-set */

	if (p == token) {
	    /* suffix-byte-range-spec */
	    unsigned long suffix = strtoul(++p, &endp, 10);

	    if (endp == p || *endp) continue;  /* bad suffix-length */
	    if (!suffix) continue;	/* unsatisfiable suffix-length */
		
	    /* don't start before byte zero */
	    if (suffix < len) first = len - suffix;
	}
	else {
	    /* byte-range-spec */
	    first = strtoul(token, &endp, 10);
	    if (endp != p) continue;      /* bad first-byte-pos */
	    if (first >= len) continue;   /* unsatisfiable first-byte-pos */

	    if (*++p) {
		/* last-byte-pos */
		last = strtoul(p, &endp, 10);
		if (*endp || last < first) continue; /* bad last-byte-pos */

		/* don't go past end of representation */
		if (last >= len) last = len - 1;
	    }
	}

	ret = HTTP_PARTIAL;

	/* Coalesce overlapping ranges, or those with a gap < 80 bytes */
	if (tail &&
	    first >= tail->first && (long) (first - tail->last) < 80) {
	    tail->last = MAX(last, tail->last);
	    continue;
	}

	/* Create a new range and append it to linked list */
	new = xzmalloc(sizeof(struct range));
	new->first = first;
	new->last = last;

	if (tail) tail->next = new;
	else *ranges = new;
	tail = new;
    }

    tok_fini(&tok);

    return ret;
}


/* Check headers for any preconditions.
 *
 * Interaction is complex and is documented in RFC 4918 and
 * Section 5 of HTTPbis, Part 4.
 */
int check_precond(struct transaction_t *txn, const void *data,
		  const char *etag, time_t lastmod)
{
    const char *lock_token = NULL;
    unsigned locked = 0;
    hdrcache_t hdrcache = txn->req_hdrs;
    const char **hdr;
    time_t since;

#ifdef WITH_DAV
    struct dav_data *ddata = (struct dav_data *) data;

    /* Check for a write-lock on the source */
    if (ddata && ddata->lock_expire > time(NULL)) {
	lock_token = ddata->lock_token;

	switch (txn->meth) {
	case METH_DELETE:
	case METH_LOCK:
	case METH_MOVE:
	case METH_POST:
	case METH_PUT:
	    /* State-changing method: Only the lock owner can execute
	       and MUST provide the correct lock-token in an If header */
	    if (strcmp(ddata->lock_ownerid, httpd_userid)) return HTTP_LOCKED;

	    locked = 1;
	    break;

	case METH_UNLOCK:
	    /* State-changing method: Authorized in meth_unlock() */
	    break;

	case METH_ACL:
	case METH_MKCALENDAR:
	case METH_MKCOL:
	case METH_PROPPATCH:
	    /* State-changing method: Locks on collections unsupported */
	    break;

	default:
	    /* Non-state-changing method: Always allowed */
	    break;
	}
    }
#else
    assert(!data);
#endif /* WITH_DAV */

    /* Per RFC 4918, If is similar to If-Match, but with lock-token submission.
       Per Section 5 of HTTPbis, Part 4, LOCK errors supercede preconditions */
    if ((hdr = spool_getheader(hdrcache, "If"))) {
	/* State tokens (sync-token, lock-token) and Etags */
	if (!eval_if(hdr[0], etag, lock_token, &locked))
	    return HTTP_PRECOND_FAILED;
    }

    if (locked) {
	/* Correct lock-token was not provided in If header */
	return HTTP_LOCKED;
    }

    /* Evaluate other precondition headers per Section 5 of HTTPbis, Part 4 */

    /* Step 1 */
    if ((hdr = spool_getheader(hdrcache, "If-Match"))) {
	if (!etag_match(hdr, etag)) return HTTP_PRECOND_FAILED;

	/* Continue to step 3 */
    }

    /* Step 2 */
    else if ((hdr = spool_getheader(hdrcache, "If-Unmodified-Since"))) {
	since = message_parse_date((char *) hdr[0],
				   PARSE_DATE|PARSE_TIME|PARSE_ZONE|
				   PARSE_GMT|PARSE_NOCREATE);

	if (since && (lastmod > since)) return HTTP_PRECOND_FAILED;

	/* Continue to step 3 */
    }

    /* Step 3 */
    if ((hdr = spool_getheader(hdrcache, "If-None-Match"))) {
	if (etag_match(hdr, etag)) {
	    if (txn->meth == METH_GET || txn->meth == METH_HEAD)
		return HTTP_NOT_MODIFIED;
	    else
		return HTTP_PRECOND_FAILED;
	}

	/* Continue to step 5 */
    }

    /* Step 4 */
    else if ((txn->meth == METH_GET || txn->meth == METH_HEAD) &&
	     (hdr = spool_getheader(hdrcache, "If-Modified-Since"))) {
	since = message_parse_date((char *) hdr[0],
				   PARSE_DATE|PARSE_TIME|PARSE_ZONE|
				   PARSE_GMT|PARSE_NOCREATE);

	if (lastmod <= since) return HTTP_NOT_MODIFIED;

	/* Continue to step 5 */
    }

    /* Step 5 */
    if (txn->flags.ranges &&  /* Only if we support Range requests */
	txn->meth == METH_GET && (hdr = spool_getheader(hdrcache, "Range"))) {

	if ((hdr = spool_getheader(hdrcache, "If-Range"))) {
	    since = message_parse_date((char *) hdr[0],
				       PARSE_DATE|PARSE_TIME|PARSE_ZONE|
				       PARSE_GMT|PARSE_NOCREATE);
	}

	/* Only process Range if If-Range isn't present or validator matches */
	if (!hdr || (since && (lastmod <= since)) || !etagcmp(hdr[0], etag))
	    return HTTP_PARTIAL;
    }

    /* Step 6 */
    return HTTP_OK;
}


const struct mimetype {
    const char *ext;
    const char *type;
    unsigned int compressible;
} mimetypes[] = {
    { ".css",  "text/css", 1 },
    { ".htm",  "text/html", 1 },
    { ".html", "text/html", 1 },
    { ".ics",  "text/calendar", 1 },
    { ".ifb",  "text/calendar", 1 },
    { ".text", "text/plain", 1 },
    { ".txt",  "text/plain", 1 },

    { ".cgm",  "image/cgm", 1 },
    { ".gif",  "image/gif", 0 },
    { ".jpg",  "image/jpeg", 0 },
    { ".jpeg", "image/jpeg", 0 },
    { ".png",  "image/png", 0 },
    { ".svg",  "image/svg+xml", 1 },
    { ".tif",  "image/tiff", 1 },
    { ".tiff", "image/tiff", 1 },

    { ".aac",  "audio/aac", 0 },
    { ".m4a",  "audio/mp4", 0 },
    { ".mp3",  "audio/mpeg", 0 },
    { ".mpeg", "audio/mpeg", 0 },
    { ".oga",  "audio/ogg", 0 },
    { ".ogg",  "audio/ogg", 0 },
    { ".wav",  "audio/wav", 0 },

    { ".avi",  "video/x-msvideo", 0 },
    { ".mov",  "video/quicktime", 0 },
    { ".m4v",  "video/mp4", 0 },
    { ".ogv",  "video/ogg", 0 },
    { ".qt",   "video/quicktime", 0 },
    { ".wmv",  "video/x-ms-wmv", 0 },

    { ".bz",   "application/x-bzip", 0 },
    { ".bz2",  "application/x-bzip2", 0 },
    { ".gz",   "application/gzip", 0 },
    { ".gzip", "application/gzip", 0 },
    { ".tgz",  "application/gzip", 0 },
    { ".zip",  "application/zip", 0 },

    { ".doc",  "application/msword", 1 },
    { ".jcs",  "application/calendar+json", 1 },
    { ".jfb",  "application/calendar+json", 1 },
    { ".js",   "application/javascript", 1 },
    { ".json", "application/json", 1 },
    { ".pdf",  "application/pdf", 1 },
    { ".ppt",  "application/vnd.ms-powerpoint", 1 },
    { ".sh",   "application/x-sh", 1 },
    { ".tar",  "application/x-tar", 1 },
    { ".xcs",  "application/calendar+xml", 1 },
    { ".xfb",  "application/calendar+xml", 1 },
    { ".xls",  "application/vnd.ms-excel", 1 },
    { ".xml",  "application/xml", 1 },

    { NULL, NULL, 0 }
};


static int list_well_known(struct transaction_t *txn)
{
    static struct buf body = BUF_INITIALIZER;
    static time_t lastmod = 0;
    struct stat sbuf;
    int precond;    

    /* stat() imapd.conf for Last-Modified and ETag */
    stat(config_filename, &sbuf);
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%ld-%ld-%ld",
	       compile_time, sbuf.st_mtime, sbuf.st_size);
    sbuf.st_mtime = MAX(compile_time, sbuf.st_mtime);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, NULL, buf_cstring(&txn->buf), sbuf.st_mtime);

    switch (precond) {
    case HTTP_OK:
    case HTTP_NOT_MODIFIED:
	/* Fill in ETag, Last-Modified, and Expires */
	txn->resp_body.etag = buf_cstring(&txn->buf);
	txn->resp_body.lastmod = sbuf.st_mtime;
	txn->resp_body.maxage = 86400;  /* 24 hrs */
	txn->flags.cc |= CC_MAXAGE;

	if (precond != HTTP_NOT_MODIFIED) break;

    default:
	/* We failed a precondition - don't perform the request */
	return precond;
    }

    if (txn->resp_body.lastmod > lastmod) {
	const char *proto = NULL, *host = NULL;
	unsigned i, level = 0;

	/* Start HTML */
	buf_reset(&body);
	buf_printf_markup(&body, level, HTML_DOCTYPE);
	buf_printf_markup(&body, level++, "<html>");
	buf_printf_markup(&body, level++, "<head>");
	buf_printf_markup(&body, level,
			  "<title>%s</title>", "Well-Known Locations");
	buf_printf_markup(&body, --level, "</head>");
	buf_printf_markup(&body, level++, "<body>");
	buf_printf_markup(&body, level,
			  "<h2>%s</h2>", "Well-Known Locations");
	buf_printf_markup(&body, level++, "<ul>");

	/* Add the list of enabled /.well-known/ URLs */
	http_proto_host(txn->req_hdrs, &proto, &host);
	for (i = 0; namespaces[i]; i++) {

	    if (namespaces[i]->enabled && namespaces[i]->well_known) {
		buf_printf_markup(&body, level,
				  "<li><a href=\"%s://%s%s\">%s</a></li>",
				  proto, host, namespaces[i]->prefix,
				  namespaces[i]->well_known);
	    }
	}

	/* Finish HTML */
	buf_printf_markup(&body, --level, "</ul>");
	buf_printf_markup(&body, --level, "</body>");
	buf_printf_markup(&body, --level, "</html>");

	lastmod = txn->resp_body.lastmod;
    }

    /* Output the HTML response */
    txn->resp_body.type = "text/html; charset=utf-8";
    write_body(precond, txn, buf_cstring(&body), buf_len(&body));

    return 0;
}


#define WELL_KNOWN_PREFIX "/.well-known"

/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn,
		    void *params __attribute__((unused)))
{
    int ret = 0, r, fd = -1, precond, len;
    const char *prefix, *urls, *path, *ext;
    static struct buf pathbuf = BUF_INITIALIZER;
    struct stat sbuf;
    const char *msg_base = NULL;
    unsigned long msg_size = 0;
    struct resp_body_t *resp_body = &txn->resp_body;

    /* Check if this is a request for /.well-known/ listing */
    len = strlen(WELL_KNOWN_PREFIX);
    if (!strncmp(txn->req_uri->path, WELL_KNOWN_PREFIX, len)) {
	if (txn->req_uri->path[len] == '/') len++;
	if (txn->req_uri->path[len] == '\0') return list_well_known(txn);
	else return HTTP_NOT_FOUND;
    }

    /* Serve up static pages */
    prefix = config_getstring(IMAPOPT_HTTPDOCROOT);
    if (!prefix) return HTTP_NOT_FOUND;

    if (*prefix != '/') {
	/* Remote content */
	struct backend *be;

	be = proxy_findserver(prefix, &http_protocol, proxy_userid,
			      &backend_cached, NULL, NULL, httpd_in);
	if (!be) return HTTP_UNAVAILABLE;

	return http_pipe_req_resp(be, txn);
    }

    /* Local content */
    if ((urls = config_getstring(IMAPOPT_HTTPALLOWEDURLS))) {
	tok_t tok = TOK_INITIALIZER(urls, " \t", TOK_TRIMLEFT|TOK_TRIMRIGHT);
	char *token;

	while ((token = tok_next(&tok)) && strcmp(token, txn->req_uri->path))
	tok_fini(&tok);

	if (!token) return HTTP_NOT_FOUND;
    }

    buf_setcstr(&pathbuf, prefix);
    buf_appendcstr(&pathbuf, txn->req_uri->path);
    path = buf_cstring(&pathbuf);

    /* See if path is a directory and look for index.html */
    if (!(r = stat(path, &sbuf)) && S_ISDIR(sbuf.st_mode)) {
	buf_appendcstr(&pathbuf, "/index.html");
	path = buf_cstring(&pathbuf);
	r = stat(path, &sbuf);
    }

    /* See if file exists and get Content-Length & Last-Modified time */
    if (r || !S_ISREG(sbuf.st_mode)) return HTTP_NOT_FOUND;

    if (!resp_body->type) {
	/* Caller hasn't specified the Content-Type */
	resp_body->type = "application/octet-stream";
	
	if ((ext = strrchr(path, '.'))) {
	    /* Try to use filename extension to identity Content-Type */
	    const struct mimetype *mtype;

	    for (mtype = mimetypes; mtype->ext; mtype++) {
		if (!strcasecmp(ext, mtype->ext)) {
		    resp_body->type = mtype->type;
		    if (!mtype->compressible) {
			/* Never compress non-compressible resources */
			txn->resp_body.enc = CE_IDENTITY;
			txn->flags.te = TE_NONE;
			txn->flags.vary &= ~VARY_AE;
		    }
		    break;
		}
	    }
	}
    }

    /* Generate Etag */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%ld-%ld", (long) sbuf.st_mtime, (long) sbuf.st_size);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, NULL, buf_cstring(&txn->buf), sbuf.st_mtime);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
	/* Fill in ETag, Last-Modified, and Expires */
	resp_body->etag = buf_cstring(&txn->buf);
	resp_body->lastmod = sbuf.st_mtime;
	resp_body->maxage = 86400;  /* 24 hrs */
	txn->flags.cc |= CC_MAXAGE;
	if (httpd_userid) txn->flags.cc |= CC_PUBLIC;

	if (precond != HTTP_NOT_MODIFIED) break;

    default:
	/* We failed a precondition - don't perform the request */
	resp_body->type = NULL;
	return precond;
    }

    if (txn->meth == METH_GET) {
	/* Open and mmap the file */
	if ((fd = open(path, O_RDONLY)) == -1) return HTTP_SERVER_ERROR;
	map_refresh(fd, 1, &msg_base, &msg_size, sbuf.st_size, path, NULL);
    }

    write_body(precond, txn, msg_base, sbuf.st_size);

    if (fd != -1) {
	map_free(&msg_base, &msg_size);
	close(fd);
    }

    return ret;
}


/* Perform an OPTIONS request */
int meth_options(struct transaction_t *txn, void *params)
{
    parse_path_t parse_path = (parse_path_t) params;
    int r, i;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Response doesn't have a body, so no Vary */
    txn->flags.vary = 0;

    /* Special case "*" - show all features/methods available on server */
    if (!strcmp(txn->req_uri->path, "*")) {
	for (i = 0; namespaces[i]; i++) {
	    if (namespaces[i]->enabled)
		txn->req_tgt.allow |= namespaces[i]->allow;
	}
    }
    else {
	if (parse_path) {
	    /* Parse the path */
	    r = parse_path(txn->req_uri->path, &txn->req_tgt, &txn->error.desc);
	    if (r) return r;
	}

	if (txn->flags.cors) {
	    const char **hdr =
		spool_getheader(txn->req_hdrs, "Access-Control-Request-Method");

	    if (hdr) {
		/* CORS preflight request */
		unsigned meth;

		txn->flags.cors = CORS_PREFLIGHT;

		/* Check Method against our list of known methods */
		for (meth = 0; (meth < METH_UNKNOWN) &&
			 strcmp(http_methods[meth].name, hdr[0]); meth++);

		if (meth == METH_UNKNOWN) txn->flags.cors = 0;
		else {
		    /* Check Method against those supported by the resource */
		    for (i = 0; namespaces[i] &&
			     namespaces[i]->id != txn->req_tgt.namespace; i++);

		    if (!namespaces[i]->methods[meth].proc) txn->flags.cors = 0;
		}
	    }
	}
    }

    response_header(HTTP_OK, txn);
    return 0;
}


/* Perform an PROPFIND request on "/" iff we support CalDAV */
static int meth_propfind_root(struct transaction_t *txn,
			      void *params __attribute__((unused)))
{
    assert(txn);

#ifdef WITH_DAV
    /* Apple iCal and Evolution both check "/" */
    if (!strcmp(txn->req_uri->path, "/") ||
	!strcmp(txn->req_uri->path, "/dav/")) {
	/* Array of known "live" properties */
	const struct prop_entry root_props[] = {

	    /* WebDAV ACL (RFC 3744) properties */
	    { "principal-collection-set", NS_DAV, PROP_COLLECTION,
	      propfind_princolset, NULL, NULL },

	    /* WebDAV Current Principal (RFC 5397) properties */
	    { "current-user-principal", NS_DAV, PROP_COLLECTION,
	      propfind_curprin, NULL, NULL },

	    { NULL, 0, 0, NULL, NULL, NULL }
	};

	struct meth_params root_params = {
	    .lprops = root_props
	};

	/* Make a working copy of target path */
	strlcpy(txn->req_tgt.path, txn->req_uri->path,
		sizeof(txn->req_tgt.path));
	txn->req_tgt.tail = txn->req_tgt.path + strlen(txn->req_tgt.path);

	txn->req_tgt.allow |= ALLOW_DAV;
	return meth_propfind(txn, &root_params);
    }
#endif

    return HTTP_NOT_ALLOWED;
}


/* Write cached header to buf, excluding any that might have sensitive data. */
static void trace_cachehdr(const char *name, const char *contents, void *rock)
{
    struct buf *buf = (struct buf *) rock;
    const char **hdr, *sensitive[] =
	{ "authorization", "cookie", "proxy-authorization", NULL };

    /* Ignore private headers in our cache */
    if (name[0] == ':') return;

    for (hdr = sensitive; *hdr && strcmp(name, *hdr); hdr++);

    if (!*hdr) buf_printf(buf, "%c%s: %s\r\n",
			  toupper(name[0]), name+1, contents);
}

/* Perform an TRACE request */
int meth_trace(struct transaction_t *txn, void *params)
{
    parse_path_t parse_path = (parse_path_t) params;
    const char **hdr;
    unsigned long max_fwd = -1;
    struct buf *msg = &txn->resp_body.payload;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Make sure method is allowed */
    if (!(txn->req_tgt.allow & ALLOW_TRACE)) return HTTP_NOT_ALLOWED;

    if ((hdr = spool_getheader(txn->req_hdrs, "Max-Forwards"))) {
	max_fwd = strtoul(hdr[0], NULL, 10);
    }

    if (max_fwd && parse_path) {
	/* Parse the path */
	int r;

	if ((r = parse_path(txn->req_uri->path,
			    &txn->req_tgt, &txn->error.desc))) return r;

	if (*txn->req_tgt.mboxname) {
	    /* Locate the mailbox */
	    char *server;

	    r = http_mlookup(txn->req_tgt.mboxname, &server, NULL, NULL);
	    if (r) {
		syslog(LOG_ERR, "mlookup(%s) failed: %s",
		       txn->req_tgt.mboxname, error_message(r));
		txn->error.desc = error_message(r);

		switch (r) {
		case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
		case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
		default: return HTTP_SERVER_ERROR;
		}
	    }

	    if (server) {
		/* Remote mailbox */
		struct backend *be;

		be = proxy_findserver(server, &http_protocol, proxy_userid,
				      &backend_cached, NULL, NULL, httpd_in);
		if (!be) return HTTP_UNAVAILABLE;

		return http_pipe_req_resp(be, txn);
	    }

	    /* Local mailbox */
	}
    }

    /* Echo the request back to the client as a message/http:
     *
     * - Piece the Request-line back together
     * - Use all non-sensitive cached headers from client
     */
    buf_reset(msg);
    buf_printf(msg, "TRACE %s %s\r\n", txn->req_line.uri, txn->req_line.ver);
    spool_enum_hdrcache(txn->req_hdrs, &trace_cachehdr, msg);
    buf_appendcstr(msg, "\r\n");

    txn->resp_body.type = "message/http";
    txn->resp_body.len = buf_len(msg);

    write_body(HTTP_OK, txn, buf_cstring(msg), buf_len(msg));

    return 0;
}
