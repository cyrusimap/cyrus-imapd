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

#ifdef WITH_CALDAV
#include <libical/ical.h>
#endif

#include <libxml/tree.h>
#include <libxml/HTMLtree.h>
#include <libxml/uri.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif /* HAVE_ZLIB */


#define DEBUG 1


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

static struct mailbox *httpd_mailbox = NULL;
int httpd_timeout, httpd_keepalive;
char *httpd_userid = 0;
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
unsigned avail_auth_schemes = 0; /* bitmask of available aith schemes */

struct buf serverinfo = BUF_INITIALIZER;

static void digest_send_success(const char *name __attribute__((unused)),
				const char *data)
{
    prot_printf(httpd_out, "Authentication-Info: %s\r\n", data);
}

/* List of HTTP auth schemes that we support */
struct auth_scheme_t auth_schemes[] = {
    { AUTH_BASIC, "Basic", NULL, 0, 1, 1, NULL, NULL },
    { AUTH_DIGEST, "Digest", HTTP_DIGEST_MECH, 0, 1, 0,
      &digest_send_success, digest_recv_success },
    { AUTH_SPNEGO, "Negotiate", "GSS-SPNEGO", 0, 0, 1, NULL, NULL },
    { AUTH_NTLM, "NTLM", "NTLM", 1, 0, 1, NULL, NULL },
    { -1, NULL, NULL, -1, -1, -1, NULL, NULL }
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
static struct accept *parse_accept(const char *hdr);
static int http_auth(const char *creds, const char *authzid,
		     struct auth_challenge_t *chal);
static void log_cachehdr(const char *name, const char *contents, void *rock);
static void keep_alive(int sig);

static int meth_get(struct transaction_t *txn);


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

struct accept {
    char *token;
    float qual;
    struct accept *next;
};

static void httpd_reset(void)
{
    int i;
    int bytes_in = 0;
    int bytes_out = 0;

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

    if (httpd_mailbox) mailbox_close(&httpd_mailbox);
    httpd_mailbox = NULL;

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
    int r, opt;

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

    /* Construct serverinfo string */
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	buf_printf(&serverinfo, "Cyrus%s/%s Cyrus-SASL/%u.%u.%u",
		   config_mupdate_server ? "-Murder" : "", cyrus_version(),
		   SASL_VERSION_MAJOR, SASL_VERSION_MINOR, SASL_VERSION_STEP);
#ifdef HAVE_SSL
	buf_printf(&serverinfo, " OpenSSL/%s", SHLIB_VERSION_NUMBER);
#endif
#ifdef HAVE_ZLIB
	buf_printf(&serverinfo, " zlib/%s", ZLIB_VERSION);
#endif
	buf_printf(&serverinfo, " libxml/%s", LIBXML_DOTTED_VERSION);
#ifdef WITH_CALDAV
	buf_printf(&serverinfo, " libical/%s", ICAL_VERSION);
    }
#endif

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

    if (httpd_mailbox) mailbox_close(&httpd_mailbox);

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
	prot_printf(httpd_out, "%s: Fatal error: %s\r\n",
		    error_message(HTTP_SERVER_ERROR), s);
	prot_flush(httpd_out);
    }
    syslog(LOG_ERR, "Fatal error: %s", s);
    shut_down(code);
}




#ifdef HAVE_SSL
/*  XXX  Needs clean up if we are going to support TLS upgrade (RFC 2817) */
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
	/* tell client to start TLS */
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


/* Array of HTTP methods known by our server. */
const char *http_methods[] = {
    "ACL",
    "COPY",
    "DELETE",
    "GET",
    "HEAD",
    "LOCK",
    "MKCALENDAR",
    "MKCOL",
    "MOVE",
    "OPTIONS",
    "POST",
    "PROPFIND",
    "PROPPATCH",
    "PUT",
    "REPORT",
    "UNLOCK",
    NULL
};

/* Namespace to fetch static content from filesystem */
const struct namespace_t namespace_default = {
    URL_NS_DEFAULT, "", 0 /* no auth */, ALLOW_READ,
    {
	NULL,			/* ACL		*/
	NULL,			/* COPY		*/
	NULL,			/* DELETE	*/
	&meth_get,		/* GET		*/
	&meth_get,		/* HEAD		*/
	NULL,			/* LOCK		*/
	NULL,			/* MKCALENDAR	*/
	NULL,			/* MKCOL	*/
	NULL,			/* MOVE		*/
	&meth_options,		/* OPTIONS	*/
	NULL,			/* POST		*/
#ifdef WITH_CALDAV
	&meth_propfind,		/* PROPFIND	*/
#else
	NULL,			/* PROPFIND	*/
#endif
	NULL,			/* PROPPATCH	*/
	NULL,			/* PUT		*/
	NULL,			/* REPORT	*/
	NULL			/* UNLOCK	*/
    }
};

/* Array of different namespaces and features supported by the server */
const struct namespace_t *namespaces[] = {
#ifdef WITH_CALDAV
    &namespace_calendar,
    &namespace_principal,
#endif
#ifdef WITH_RSS
    &namespace_rss,
#endif
    &namespace_default,		/* MUST be present and be last!! */
    NULL,
};


/*
 * Top-level command loop parsing
 */
static void cmdloop(void)
{
    int c, ret, r, i, gzip_enabled = 0;
    static struct buf meth, uri, ver;
    char buf[1024];
    const char **hdr;
    struct transaction_t txn;
    const struct namespace_t *namespace;
    method_proc_t meth_proc;

    /* Start with an empty (clean) transaction */
    memset(&txn, 0, sizeof(struct transaction_t));

#ifdef HAVE_ZLIB
    /* Always use gzip format because IE incorrectly uses raw deflate */
    if (config_getswitch(IMAPOPT_HTTPALLOWCOMPRESS) &&
	deflateInit2(&txn.zstrm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
		     16+MAX_WBITS, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY) == Z_OK) {
	gzip_enabled = 1;
    }
#endif

    for (;;) {
	/* Reset state */
	ret = 0;
	txn.meth = NULL;
	txn.flags = !httpd_timeout ? HTTP_CLOSE : 0;
	txn.auth_chal.param = NULL;
	txn.loc = txn.etag = NULL;
	txn.req_hdrs = NULL;
	memset(&txn.error, 0, sizeof(struct error_t));
	memset(&txn.resp_body, 0, sizeof(struct resp_body_t));
#ifdef HAVE_ZLIB
	deflateReset(&txn.zstrm);
#endif

	/* Flush any buffered output */
	prot_flush(httpd_out);
	if (backend_current) prot_flush(backend_current->out);

	/* Check for shutdown file */
	if (shutdown_file(buf, sizeof(buf)) ||
	    (httpd_userid &&
	     userdeny(httpd_userid, config_ident, buf, sizeof(buf)))) {
	    txn.error.desc = buf;
	    txn.flags |= HTTP_CLOSE;
	    response_header(HTTP_UNAVAILABLE, &txn);
	    shut_down(0);
	}

	signals_poll();

	if (!proxy_check_input(protin, httpd_in, httpd_out,
			       backend_current ? backend_current->in : NULL,
			       NULL, 0)) {
	    /* No input from client */
	    continue;
	}

	/* Read Request-Line = Method SP request-target SP HTTP-Version CRLF */
	c = getword(httpd_in, &meth);
	if (c == ' ') {
	    c = getword(httpd_in, &uri);
	    if (c == ' ') {
		c = getword(httpd_in, &ver);
		if (c == '\r') c = prot_getc(httpd_in);
	    }
	}
	if (c == EOF) {
	    txn.error.desc = prot_error(httpd_in);
	    if (txn.error.desc && strcmp(txn.error.desc, PROT_EOF_STRING)) {
		syslog(LOG_WARNING, "%s, closing connection", txn.error.desc);
	    }
	    /* client closed connection or timed out */
	    txn.flags |= HTTP_CLOSE;
	    goto done;
	}
	if (!buf_len(&meth) || !buf_len(&uri) || !buf_len(&ver)) {
	    ret = HTTP_BAD_REQUEST;
	    txn.error.desc = "Missing arguments in Request-Line";
	}
	else if (c != '\n') {
	    ret = HTTP_BAD_REQUEST;
	    txn.error.desc = "Unexpected extra arguments in Request-Line";
	}
	if (ret) eatline(httpd_in, c);

	/* Check HTTP-Version */
	if (!ret && strcmp(buf_cstring(&ver), HTTP_VERSION)) {
	    ret = HTTP_BAD_VERSION;
	    snprintf(buf, sizeof(buf),
		     "This server only speaks %s", HTTP_VERSION);
	    txn.error.desc = buf;
	}

	/* Parse request-target URI */
	if (!ret &&
	    (r = parse_uri(buf_cstring(&meth), buf_cstring(&uri),
			   &txn.req_tgt, &txn.error.desc))) {
	    ret = r;
	}

	/* Find the namespace of the requested resource */
	if (!ret) {
	    for (i = 0; namespaces[i]; i++) {
		size_t len = strlen(namespaces[i]->prefix);

		/* See if the prefix matches - terminated with NUL or '/' */
		if (!strncmp(namespaces[i]->prefix, txn.req_tgt.path, len) &&
		    (!txn.req_tgt.path[len] ||
		     (txn.req_tgt.path[len] == '/') ||
		     !strcmp(txn.req_tgt.path, "*"))) break;
	    }
	    if ((namespace = namespaces[i])) {
		txn.req_tgt.namespace = namespace->id;
		txn.req_tgt.allow = namespace->allow;
	    } else {
		/* XXX  Should never get here */
		ret = HTTP_SERVER_ERROR;
	    }
	}

	/* Check Method against list of supported methods in the namespace */
	if (!ret) {
	    txn.meth = buf_cstring(&meth);
	    for (i = 0;
		 http_methods[i] && strcmp(http_methods[i], txn.meth); i++);

	    if (!http_methods[i]) ret = HTTP_NOT_IMPLEMENTED;
	    else if (!(meth_proc = namespace->proc[i])) ret = HTTP_NOT_ALLOWED;
	}

	/* Read and parse headers */
	syslog(LOG_DEBUG, "read & parse headers");
	if (!(txn.req_hdrs = spool_new_hdrcache())) {
	    ret = HTTP_SERVER_ERROR;
	    txn.flags |= HTTP_CLOSE;
	    txn.error.desc = "Unable to create header cache";
	    goto done;
	}
	if ((r = spool_fill_hdrcache(httpd_in, NULL, txn.req_hdrs, NULL))) {
	    ret = HTTP_BAD_REQUEST;
	    txn.error.desc = "Request contains invalid header";
	}

	/* Read CRLF separating headers and body */
	c = prot_getc(httpd_in);
	if (c == '\r') c = prot_getc(httpd_in);
	if (c != '\n') {
	    ret = HTTP_BAD_REQUEST;
	    txn.flags |= HTTP_CLOSE;
	    txn.error.desc = "Missing separator between headers and body";
	    goto done;
	}

	/* Check for mandatory Host header */
	if (!ret && !(hdr = spool_getheader(txn.req_hdrs, "Host"))) {
	    ret = HTTP_BAD_REQUEST;
	    txn.error.desc = "Missing Host header";
	}

	/* Check for connection directives */
	if ((hdr = spool_getheader(txn.req_hdrs, "Connection"))) {
	    /* Check if this is a non-persistent connection */
	    if (!strcmp(hdr[0], "close")) {
		syslog(LOG_DEBUG, "non-persistent connection");
		txn.flags |= HTTP_CLOSE;
	    }

	    /* Check if we need to start TLS */
	    else if (!ret && !httpd_tls_done && tls_enabled() &&
		     !strcmp(hdr[0], "Upgrade")) {
		const char **upgd;

		if ((upgd = spool_getheader(txn.req_hdrs, "Upgrade")) &&
		    !strcmp(upgd[0], "TLS/1.0")) {
		    syslog(LOG_DEBUG, "client requested TLS");
		    starttls(0);
		}
	    }
	}

	/* Handle CalDAV bootstrapping */
	if (!ret && !strncmp(txn.req_tgt.path, "/.well-known/caldav", 19) &&
	    (!txn.req_tgt.path[19] || !strcmp(txn.req_tgt.path+19, "/"))) {
	    ret = HTTP_MOVED;

	    hdr = spool_getheader(txn.req_hdrs, "Host");
	    snprintf(buf, sizeof(buf), "%s://%s/calendars/",
		     https ? "https" : "http", hdr[0]);
	    txn.loc = buf;
	}

	if (ret) goto done;

	/* Start method processing alarm */
	alarm(httpd_keepalive);

	if (!httpd_userid) {
	    const char **creds, **authzid;

	    /* Perform authentication, if necessary */
	    if ((creds = spool_getheader(txn.req_hdrs, "Authorization"))) {
		/* Check the auth credentials */
#ifdef SASL_HTTP_REQUEST
		/* Setup SASL HTTP request in case we need it */
		sasl_http_request_t sasl_http_req;

		txn.flags |= HTTP_READBODY;
		if ((r = read_body(httpd_in, txn.req_hdrs, &txn.req_body,
				   &txn.error.desc))) {
		    txn.flags |= HTTP_CLOSE;
		    ret = r;
		    goto done;
		}
		sasl_http_req.method = txn.meth;
		sasl_http_req.uri = buf_cstring(&uri);
		sasl_http_req.entity = (u_char *) buf_cstring(&txn.req_body);
		sasl_http_req.elen = buf_len(&txn.req_body);
		sasl_http_req.non_persist = (txn.flags & HTTP_CLOSE);
		sasl_setprop(httpd_saslconn, SASL_HTTP_REQUEST, &sasl_http_req);
#endif /* SASL_HTTP_REQUEST */

		authzid = spool_getheader(txn.req_hdrs, "Authorization-Id");
		r = http_auth(creds[0],
			      authzid ? authzid[0] : NULL, &txn.auth_chal);
		if ((r < 0) || !txn.auth_chal.scheme) {
		    /* Auth failed - reinitialize */
		    syslog(LOG_DEBUG, "auth failed - reinit");
		    reset_saslconn(&httpd_saslconn);
		    txn.auth_chal.scheme = NULL;
		    r = SASL_FAIL;
		}
		else if ((r == SASL_OK) && (httpd_logfd != -1)) {
		    /* Auth succeeded - log request to userid telemetry */
		    FILE *logf = fdopen(httpd_logfd, "a");
		    fprintf(logf, "<%ld<", time(NULL));
		    fprintf(logf, "%s %s", txn.meth, txn.req_tgt.path);
		    if (*txn.req_tgt.query)
			fprintf(logf, "?%s", txn.req_tgt.query);
		    fprintf(logf, " %s\r\n", HTTP_VERSION);
		    spool_enum_hdrcache(txn.req_hdrs, &log_cachehdr, logf);
		    fprintf(logf, "\r\n%s", buf_cstring(&txn.req_body));
		    fflush(logf);
		}
	    }
	    else if (txn.auth_chal.scheme) {
		/* Started auth exchange, but client didn't engage - reinit */
		syslog(LOG_DEBUG, "client didn't complete auth - reinit");
		reset_saslconn(&httpd_saslconn);
		txn.auth_chal.scheme = NULL;
	    }
	}

	/* Request authentication, if necessary */
	if (!httpd_userid && (r || namespace->need_auth)) {
	  need_auth:
	    /* User must authenticate */

	    if (httpd_tls_required) {
		/* We only support TLS+Basic, so tell client to use TLS */
		struct buf html = BUF_INITIALIZER;
		long code;

		/* Create https URL */
		hdr = spool_getheader(txn.req_hdrs, "Host");
		snprintf(buf, sizeof(buf),
			 "https://%s%s", hdr[0], txn.req_tgt.path);

		/* Create HTML body */
		buf_printf(&html, tls_message, buf, buf);

		/* Check which response is required */
		if ((hdr = spool_getheader(txn.req_hdrs, "User-Agent")) &&
		    !strncmp(hdr[0], "Cyrus-Murder/", 13)) {
		    /* Murder proxies use RFC 2817 (TLS upgrade) */
		    code = HTTP_UPGRADE;
		}
		else {
		    /* All other clients use RFC 2818 (HTTPS) */
		    code = HTTP_MOVED;
		    txn.loc = buf;
		}

		/* Output our HTML response */
		txn.resp_body.type = "text/html; charset=utf-8";
		write_body(code, &txn, html.s, html.len);

		buf_free(&html);
		goto done;
	    }
	    else {
		/* Tell client to authenticate */
		ret = HTTP_UNAUTHORIZED;
		if (r) txn.error.desc = "Authentication failed";
		else txn.error.desc = "Must authenticate to access the specified target";
	    }
	}

	/* Check if we should compress response body */
	if (!ret && gzip_enabled &&
	    (hdr = spool_getheader(txn.req_hdrs, "Accept-Encoding"))) {
	    struct accept *e, *enc = parse_accept(hdr[0]);

	    for (e = enc; e && e->token; e++) {
		if (!strcmp(e->token, "gzip") || !strcmp(e->token, "x-gzip")) {
		    txn.flags |= HTTP_GZIP;
		}
		/* XXX  Do we want to support deflate even though M$
		   doesn't implement it correctly (raw deflate vs. zlib)? */

		free(e->token);
	    }
	    if (enc) free(enc);
	}

	/* XXX  Check if method expects a body.  If not, return 415 */

	/* Process the requested method */
	if (!ret) {
	    ret = (*meth_proc)(&txn);
	    if (ret == HTTP_UNAUTHORIZED) goto need_auth;
	}

      done:
	/* If we haven't the read body, read and discard it */
	if (txn.req_hdrs && !(txn.flags & HTTP_READBODY) &&
	    read_body(httpd_in, txn.req_hdrs, NULL, &txn.error.desc)) {
	    txn.flags |= HTTP_CLOSE;
	}

	/* Handle errors (success responses handled by method functions) */
	if (ret) error_response(ret, &txn);

	/* Memory cleanup */
	if (txn.req_hdrs) spool_free_hdrcache(txn.req_hdrs);

	if (txn.flags & HTTP_CLOSE) {
	    buf_free(&txn.req_body);
#ifdef HAVE_ZLIB
	    deflateEnd(&txn.zstrm);
#endif
	    return;
	}

	continue;
    }
}

/****************************  Parsing Routines  ******************************/

/* Parse URI, returning the path */
int parse_uri(const char *meth, const char *uri,
	      struct request_target_t *tgt, const char **errstr)
{
    xmlURIPtr p_uri;  /* parsed URI */

    memset(tgt, 0, sizeof(struct request_target_t));

    /* Parse entire URI */
    if ((p_uri = xmlParseURI(uri)) == NULL) {
	*errstr = "Illegal request target URI";
	return HTTP_BAD_REQUEST;
    }

    if (p_uri->scheme) {
	/* Check sanity of scheme */

	if (strcasecmp(p_uri->scheme, "http") &&
	    strcasecmp(p_uri->scheme, "https")) {
	    xmlFreeURI(p_uri);
	    *errstr = "Unsupported URI scheme";
	    return HTTP_BAD_REQUEST;
	}
    }

    /* XXX  Probably need to grab server part for remote COPY/MOVE */

    /* Check sanity of path */
    if (!p_uri->path || !*p_uri->path) {
	xmlFreeURI(p_uri);
	*errstr = "Empty path in target URI";
	return HTTP_BAD_REQUEST;
    }

    if ((strlen(p_uri->path) > MAX_MAILBOX_PATH) ||
	(p_uri->query && (strlen(p_uri->query) > MAX_QUERY_LEN))) {
	xmlFreeURI(p_uri);
	return HTTP_TOO_LONG;
    }

    if ((p_uri->path[0] != '/') &&
	(strcmp(p_uri->path, "*") || !meth || (meth[0] != 'O'))) {
	*errstr = "Illegal request target URI";
	return HTTP_BAD_REQUEST;
    }

    /* Make a working copy of the path and query,  and free the parsed struct */
    strcpy(tgt->path, p_uri->path);
    if (p_uri->query) strcpy(tgt->query, p_uri->query);
    xmlFreeURI(p_uri);

    return 0;
}


/*
 * Read the body of a request or response.
 * Handles identity and chunked encoding only.
 */
int read_body(struct protstream *pin,
	      hdrcache_t hdrs, struct buf *body, const char **errstr)
{
    const char **hdr;
    unsigned long len = 0, chunk;
    unsigned need_cont = 0, is_chunked;

    syslog(LOG_DEBUG, "read body(dump = %d)", body != NULL);

    /* Check if client expects 100 (Continue) status before sending body */
    if ((hdr = spool_getheader(hdrs, "Expect"))) {
	if (!strcasecmp(hdr[0], "100-continue"))
	    need_cont = 1;
	else {
	    *errstr = "Unsupported Expect";
	    return HTTP_EXPECT_FAILED;
	}
    }

    if (body) buf_reset(body);
    else if (need_cont) {
	/* Don't care about the body and client hasn't sent it, we're done */
	return 0;
    }

    /* Check for Transfer-Encoding */
    if ((hdr = spool_getheader(hdrs, "Transfer-Encoding"))) {
	if (!strcasecmp(hdr[0], "chunked")) {
	    /* "chunked" encoding */
	    is_chunked = 1;
	}
	/* XXX  Should we handle compress/deflate/gzip? */
	else {
	    *errstr = "Specified Transfer-Encoding not implemented";
	    return HTTP_NOT_IMPLEMENTED;
	}
    }
    else {
	/* "identity" encoding - treat it as a single chunk of size "len" */
	is_chunked = 0;
	len = chunk = 0;

	/* Check for Content-Length */
	if ((hdr = spool_getheader(hdrs, "Content-Length"))) {
	    len = strtoul(hdr[0], NULL, 10);
	    /* XXX  Should we sanity check and/or limit the body len? */
	}
    }

    if (need_cont) {
	/* Tell client to send the body */
	response_header(HTTP_CONTINUE, NULL);
    }

    /* Read and buffer the body */
    do {
	char buf[PROT_BUFSIZE];
	unsigned long n;

	if (is_chunked) {
	    /* Read chunk-size and any chunk-ext */
	    prot_fgets(buf, PROT_BUFSIZE-2, pin);
	    if (sscanf(buf, "%lx", &chunk) != 1) {
		*errstr = "Unable to read chunk size";
		return HTTP_BAD_REQUEST;
	    }
	    len = chunk;
	}

	/* Read chunk-data */ 
	while (len) {
	    if (!(n = prot_read(pin, buf,
				len > PROT_BUFSIZE ? PROT_BUFSIZE : len))) {
		syslog(LOG_ERR, "prot_read() error");
		*errstr = "Unable to read body data";
		return HTTP_BAD_REQUEST;
	    }

	    if (body) buf_appendmap(body, buf, n);
	    len -= n;
	}

	if (is_chunked) {
	    if (!chunk) {
		/* last-chunk: Read/parse any trailing headers */
		spool_fill_hdrcache(pin, NULL, hdrs, NULL);
	    }

	    /* Read CRLF terminating the chunk */
	    *buf = prot_getc(pin);
	    if (*buf == '\r') *buf = prot_getc(pin);
	    if (*buf != '\n') {
		*errstr = "Missing CRLF in body";
		return HTTP_BAD_REQUEST;
	    }
	}

    } while (chunk);  /* Continue until we get last-chunk */

    return 0;
}

/* Compare accept quality values so that they sort in descending order */
static int compare_accept(const struct accept *a1, const struct accept *a2)
{
    if (a2->qual < a1->qual) return -1;
    if (a2->qual > a1->qual) return 1;
    return 0;
}

static struct accept *parse_accept(const char *hdr)
{
    tok_t tok = TOK_INITIALIZER(hdr, ";,\r\n", TOK_TRIMLEFT|TOK_TRIMRIGHT);
    char *token;
    int n = 0, alloc = 0;
    struct accept *ret = NULL;
#define GROW_ACCEPT 10;

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

    qsort(ret, n, sizeof(struct accept),
	  (int (*)(const void *, const void *)) &compare_accept);

    return ret;
}


/****************************  Response Routines  *****************************/


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
    prot_printf(httpd_out, "\r\n")


void response_header(long code, struct transaction_t *txn)
{
    char datestr[80];
    struct auth_challenge_t *auth_chal;
    struct resp_body_t *resp_body;
    static struct buf log = BUF_INITIALIZER;
    const char **hdr;

    /* Stop method processing alarm */
    alarm(0);

    if (txn && txn->req_hdrs) {
	/* Log the client request and our response */
	buf_reset(&log);
	buf_printf(&log, "%s", httpd_clienthost);
	if (httpd_userid) buf_printf(&log, " as \"%s\"", httpd_userid);
	if ((hdr = spool_getheader(txn->req_hdrs, "User-Agent"))) {
	    buf_printf(&log, " with \"%s\"", hdr[0]);
	}
	buf_printf(&log, "; \"%s %s", txn->meth, txn->req_tgt.path);
	if (*txn->req_tgt.query) {
	    buf_printf(&log, "?%s", txn->req_tgt.query);
	}
	buf_printf(&log, " %s\"", HTTP_VERSION);
	if ((hdr = spool_getheader(txn->req_hdrs, "Destination"))) {
	    buf_printf(&log, " (%s)", hdr[0]);
	}
	buf_printf(&log, " => \"%s\"", error_message(code));
	if (txn->loc) buf_printf(&log, " (%s)", txn->loc);
	syslog(LOG_INFO, "%s", buf_cstring(&log));
    }


    /* Status-Line */
    prot_printf(httpd_out, "%s\r\n", http_statusline(code));


    /* General Header Fields */
    rfc822date_gen(datestr, sizeof(datestr), time(0));
    prot_printf(httpd_out, "Date: %s\r\n", datestr);

    if (!httpd_tls_done && tls_enabled()) {
	prot_printf(httpd_out, "Upgrade: TLS/1.0\r\n");
    }

    switch (code) {
    case HTTP_SWITCH_PROT:
	prot_printf(httpd_out, "Connection: Upgrade\r\n");

    case HTTP_CONTINUE:
    case HTTP_PROCESSING:
	/* Provisional response - nothing else needed */

	/* Blank line terminating the header */
	prot_printf(httpd_out, "\r\n");

	/* Force the response to the client immediately */
	prot_flush(httpd_out);

	/* Restart method processing alarm (don't interrupt TLS negotiation) */
	if (code != HTTP_SWITCH_PROT) alarm(httpd_keepalive);

	return;
    }

    /* Final response */
    if (txn->flags & HTTP_CLOSE)
	prot_printf(httpd_out, "Connection: close");
    else {
	prot_printf(httpd_out, "Keep-Alive: timeout=%d\r\n", httpd_timeout);
	prot_printf(httpd_out, "Connection: Keep-Alive");
    }
    prot_printf(httpd_out, "%s\r\n",
		(code == HTTP_UPGRADE) ? ", Upgrade" : "");


    /* Response Header Fields */
    if (httpd_tls_done) {
	prot_printf(httpd_out, "Strict-Transport-Security: max-age=600\r\n");
    }

    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	prot_printf(httpd_out, "Server: %s\r\n", buf_cstring(&serverinfo));
    }

    prot_printf(httpd_out, "Accept-Ranges: none\r\n");

    if (txn->req_tgt.allow & ALLOW_DAV) {
	prot_printf(httpd_out, "DAV: 1, 3");
	if (txn->req_tgt.allow & ALLOW_WRITE) {
	    prot_printf(httpd_out, ", access-control, extended-mkcol");
	}
	if (txn->req_tgt.allow & ALLOW_CAL) {
	    prot_printf(httpd_out, ", calendar-access");
	    /* calendar-auto-schedule  */
	}
#if 0
	if (txn->req_tgt.allow & ALLOW_CARD) {
	    prot_printf(httpd_out, ", addressbook");
	}
#endif
	prot_printf(httpd_out, "\r\n");
    }

    if ((code == HTTP_NOT_ALLOWED) ||
	((code == HTTP_OK) && txn->meth && (txn->meth[0] == 'O'))) {
	prot_printf(httpd_out, "Allow: OPTIONS");
	if (txn->req_tgt.allow & ALLOW_READ) {
	    prot_printf(httpd_out, ", GET, HEAD");
	}
	if (txn->req_tgt.allow & ALLOW_WRITE) {
	    prot_printf(httpd_out, ", POST, PUT, DELETE");
	}
	prot_printf(httpd_out, "\r\n");
	if (txn->req_tgt.allow & ALLOW_DAV) {
	    prot_printf(httpd_out, "Allow: REPORT, PROPFIND");
	    if (txn->req_tgt.allow & ALLOW_WRITE) {  /* LOCK, UNLOCK */
		prot_printf(httpd_out, ", PROPPATCH, COPY, MOVE, ACL, MKCOL");
		if (txn->req_tgt.allow & ALLOW_CAL) {
		    prot_printf(httpd_out, ", MKCALENDAR");
		}
	    }
	    prot_printf(httpd_out, "\r\n");
	}
    }

    auth_chal = &txn->auth_chal;
    if (code == HTTP_UNAUTHORIZED) {
	if (!auth_chal->scheme) {
	    /* Require authentication by advertising all possible schemes */
	    struct auth_scheme_t *scheme;

	    for (scheme = auth_schemes; scheme->name; scheme++) {
		/* Only advertise what is available and
		   can work with the type of connection */
		if ((avail_auth_schemes & (1 << scheme->idx)) &&
		    (!(txn->flags & HTTP_CLOSE) || !scheme->need_persist)) {
		    auth_chal->param = NULL;

		    if (scheme->is_server_first) {
			/* Generate the initial challenge */
			http_auth(scheme->name, NULL, auth_chal);

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
    } else if (auth_chal->param) {
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

    if (txn->flags & HTTP_NOCACHE) {
	prot_printf(httpd_out, "Cache-Control: no-cache\r\n");
    }

    if (txn->etag) prot_printf(httpd_out, "ETag: \"%s\"\r\n", txn->etag);

    if (txn->loc) prot_printf(httpd_out, "Location: %s\r\n", txn->loc);


    /* Payload Header Fields */
    resp_body = &txn->resp_body;
    if (txn->flags & HTTP_CHUNKED) {
	prot_printf(httpd_out, "Transfer-Encoding: chunked\r\n");
    }
    else {
	prot_printf(httpd_out, "Content-Length: %lu\r\n", resp_body->len);
    }


    /* Representation Header Fields */
    if (resp_body->enc) {
	prot_printf(httpd_out, "Content-Encoding: %s\r\n", resp_body->enc);
    }
    if (resp_body->lang) {
	prot_printf(httpd_out, "Content-Language: %s\r\n", resp_body->lang);
    }
    if (resp_body->loc && resp_body->len) {
	prot_printf(httpd_out, "Content-Location: %s\r\n", resp_body->loc);
    }
    if (resp_body->type) {
	prot_printf(httpd_out, "Content-Type: %s\r\n", resp_body->type);
    }
    if (resp_body->lastmod) {
	rfc822date_gen(datestr, sizeof(datestr), resp_body->lastmod);
	prot_printf(httpd_out, "Last-Modified: %s\r\n", datestr);
    }


    /* Blank line terminating the header */
    prot_printf(httpd_out, "\r\n");
}


static void keep_alive(int sig)
{
    if (sig == SIGALRM) response_header(HTTP_PROCESSING, NULL);
}


/* List of incompressible MIME types */
static const char *comp_mime[] = {
    "image/gif",
    "image/jpeg",
    "image/png",
    NULL
};


/* Determine if a MIME type is incompressible */
static int is_incompressible(const char *type)
{
    const char **m;

    for (m = comp_mime; *m && strcasecmp(*m, type); m++);
    return (*m != NULL);
}


/*
 * Output an HTTP response with body data, compressed as necessary.
 *
 * For chunked body data, an initial call with 'code' != 0 will output
 * a response header and the first body chunk.
 * All subsequent calls should have 'code' = 0 to output just the body chunk.
 * A final call with 'len' = 0 ends the chunked body.
 */
void write_body(long code, struct transaction_t *txn,
		const char *buf, unsigned len)
{
#define GZIP_MIN_LEN 300

    unsigned is_chunked = (txn->flags & HTTP_CHUNKED);

    if (code) {
	if ((!is_chunked && len < GZIP_MIN_LEN) ||
	    is_incompressible(txn->resp_body.type)) txn->flags &= ~HTTP_GZIP;

	if (txn->flags & HTTP_GZIP) {
	    txn->resp_body.enc = "gzip";
	    txn->flags |= HTTP_CHUNKED;  /* always chunk gzipped output */
	}
	else if (!is_chunked) txn->resp_body.len = len;

	response_header(code, txn);
    }

    if (txn->meth && txn->meth[0] == 'H') return;

#ifdef HAVE_ZLIB
    if (txn->flags & HTTP_GZIP) {
	char zbuf[PROT_BUFSIZE];
	unsigned flush, out;

	/* don't flush until last chunk */
	flush = (is_chunked && len) ? Z_NO_FLUSH : Z_FINISH;

	txn->zstrm.next_in = (Bytef *) buf;
	txn->zstrm.avail_in = len;

	do {
	    txn->zstrm.next_out = (Bytef *) zbuf;
	    txn->zstrm.avail_out = PROT_BUFSIZE;

	    deflate(&txn->zstrm, flush);
	    out = PROT_BUFSIZE - txn->zstrm.avail_out;

	    if (out) {
		/* we have a chunk of compressed output */
		prot_printf(httpd_out, "%x\r\n", out);
		prot_write(httpd_out, zbuf, out);
		prot_printf(httpd_out, "\r\n");
	    }

	} while (!txn->zstrm.avail_out);

	if (flush == Z_FINISH) prot_printf(httpd_out, "0\r\n\r\n");

	return;
    }
#endif /* HAVE_ZLIB */

    if (is_chunked) {
	/* chunk */
	prot_printf(httpd_out, "%x\r\n", len);
	prot_write(httpd_out, buf, len);
	prot_printf(httpd_out, "\r\n");
    }
    else {
	/* full body */
	prot_write(httpd_out, buf, len);
    }
}


/* Output an HTTP response with text/html body */
void html_response(long code, struct transaction_t *txn, xmlDocPtr html)
{
    xmlChar *buf;
    int bufsiz;

    /* Dump HTML response tree into a text buffer */
    htmlDocDumpMemoryFormat(html, &buf, &bufsiz, DEBUG ? 1 : 0);

    if (buf) {
	/* Output the XML response */
	txn->resp_body.type = "text/html; charset=utf-8";

	write_body(code, txn, (char *) buf, bufsiz);

	/* Cleanup */
	xmlFree(buf);
    }
    else {
	txn->error.precond = NULL;
	txn->error.desc = "Error dumping HTML tree";
	error_response(HTTP_SERVER_ERROR, txn);
    }
}


/* Output an HTTP response with application/xml body */
void xml_response(long code, struct transaction_t *txn, xmlDocPtr xml)
{
    xmlChar *buf;
    int bufsiz;

    /* Dump XML response tree into a text buffer */
    xmlDocDumpFormatMemoryEnc(xml, &buf, &bufsiz, "utf-8", DEBUG ? 1 : 0);

    if (buf) {
	/* Output the XML response */
	txn->resp_body.type = "application/xml; charset=utf-8";

	write_body(code, txn, (char *) buf, bufsiz);

	/* Cleanup */
	xmlFree(buf);
    }
    else {
	txn->error.precond = NULL;
	txn->error.desc = "Error dumping XML tree";
	error_response(HTTP_SERVER_ERROR, txn);
    }
}


/* Output an HTTP error response with optional XML or text body */
void error_response(long code, struct transaction_t *txn)
{
    if (txn->meth && txn->meth[0] == 'H') {
	txn->error.precond = NULL;
	txn->error.desc = NULL;
    }

    if (txn->error.precond) {
	xmlNodePtr root = xml_add_error(NULL, &txn->error, NULL);

	if (root) {
	    xml_response(code, txn, root->doc);
	    xmlFreeDoc(root->doc);
	    return;
	}
    }

    if (txn->error.desc) txn->resp_body.type = "text/plain";
    write_body(code, txn, txn->error.desc,
	       txn->error.desc ? strlen(txn->error.desc) : 0);
}


/* Perform HTTP Authentication based on the given credentials ('creds').
 * Returns the selected auth scheme and any server challenge in 'chal'.
 * May be called multiple times if auth scheme requires multiple steps.
 * SASL status between steps is maintained in 'status'.
 */
#define BASE64_BUF_SIZE 21848	/* per RFC 4422: ((16K / 3) + 1) * 4  */

static int http_auth(const char *creds, const char *authzid,
		     struct auth_challenge_t *chal)
{
    static int status = SASL_OK;
    size_t slen;
    const char *clientin = NULL, *user;
    unsigned int clientinlen = 0;
    struct auth_scheme_t *scheme;
    static char base64[BASE64_BUF_SIZE+1];
    const void *canon_user;

    chal->param = NULL;

    /* Split credentials into auth scheme and response */
    slen = strcspn(creds, " \0");
    if ((clientin = strchr(creds, ' '))) clientinlen = strlen(++clientin);

    syslog(LOG_DEBUG,
	   "http_auth: status=%d   scheme='%s'   creds='%.*s%s'   authzid='%s'",
	   status, chal->scheme ? chal->scheme->name : "",
	   slen, creds, clientin ? " <response>" : "",
	   authzid ? authzid : "");

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
    if (clientin && scheme->do_base64) {
	int r = sasl_decode64(clientin, clientinlen,
			      base64, BASE64_BUF_SIZE, &clientinlen);
	if (r != SASL_OK) {
	    syslog(LOG_ERR, "Base64 decode failed: %s",
		   sasl_errstring(r, NULL, NULL));
	    return r;
	}
	clientin = base64;
    }

    if (scheme->idx == AUTH_BASIC) {
	/* Basic (plaintext) authentication */
	char *pass;

	if (!clientin) {
	    /* Create initial challenge (base64 buffer is static) */
	    snprintf(base64, BASE64_BUF_SIZE,
		     "realm=\"%s\"", config_servername);
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
	if (serverout && scheme->do_base64) {
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

    if (authzid && *authzid) {
	/* Trying to proxy as another user */
	char authzbuf[MAX_MAILBOX_BUFFER];
	unsigned authzlen;

	/* Canonify the authzid */
	status = mysasl_canon_user(httpd_saslconn, NULL,
				   authzid, strlen(authzid),
				   SASL_CU_AUTHZID, NULL,
				   authzbuf, sizeof(authzbuf), &authzlen);
	if (status) {
	    syslog(LOG_NOTICE, "badlogin: %s Basic %s invalid user",
		   httpd_clienthost, beautify_string(authzid));
	    return status;
	}
	authzid = authzbuf;
	user = (const char *) canon_user;

	/* See if user is allowed to proxy */
	status = mysasl_proxy_policy(httpd_saslconn,
				     &httpd_proxyctx,
				     authzid, authzlen,
				     user, strlen(user),
				     NULL, 0, NULL);

	if (status) {
	    syslog(LOG_NOTICE, "badlogin: %s Basic %s %s",
		   httpd_clienthost, user, sasl_errdetail(httpd_saslconn));
	    return status;
	}

	canon_user = authzid;
    }

    httpd_userid = xstrdup((const char *) canon_user);

    proc_register("httpd", httpd_clienthost, httpd_userid, (char *)0);

    syslog(LOG_NOTICE, "login: %s %s %s%s %s",
	   httpd_clienthost, httpd_userid, scheme->name,
	   httpd_tls_done ? "+TLS" : "", "User logged in");

    /* Close IP-based telemetry log and create new log based on userid */
    if (httpd_logfd != -1) close(httpd_logfd);
    httpd_logfd = telemetry_log(httpd_userid, httpd_in, httpd_out, 0);

    return status;
}


/* Write cached header (removing auth creds) to telemetry log. */
static void log_cachehdr(const char *name, const char *contents, void *rock)
{
    FILE *logf = (FILE *) rock;

    fprintf(logf, "%c%s: ", toupper(name[0]), name+1);
    if (!strcmp(name, "authorization"))
	fprintf(logf, "%.*s ...\r\n", strcspn(contents, " \t\r\n"), contents);
    else
	fprintf(logf, "%s\r\n", contents);
}


/*************************  Method Execution Routines  ************************/


/* "Open" the requested mailbox.  Either return the existing open
 * mailbox if it matches, or close the existing and open the requested.
 */
int http_mailbox_open(const char *name, struct mailbox **mailbox, int locktype)
{
    int r;

    if (httpd_mailbox && !strcmp(httpd_mailbox->name, name)) {
	r = mailbox_lock_index(httpd_mailbox, locktype);
    }
    else {
	if (httpd_mailbox) {
	    mailbox_close(&httpd_mailbox);
	    httpd_mailbox = NULL;
	}
	if (locktype == LOCK_EXCLUSIVE)
	    r = mailbox_open_iwl(name, &httpd_mailbox);
	else
	    r = mailbox_open_irl(name, &httpd_mailbox);
    }

    *mailbox = httpd_mailbox;
    return r;
}


/* Compare an etag in a header to a resource etag.
 * Returns 0 if a match, non-zero otherwise.
 */
static int etagcmp(const char *hdr, const char *etag) {
    size_t len;

    if (!etag) return -1;		/* no representation	   */
    if (!strcmp(hdr, "*")) return 0;	/* any representation	   */

    len = strlen(etag);
    if (strlen(hdr) != len+2) return 1;	/* make sure lengths match */
    if (hdr[0] != '\"') return 1;    	/* match open DQUOTE 	   */
    return strncmp(hdr+1, etag, len);   /* skip DQUOTE		   */
}


/* Check headers for any preconditions.
 *
 * Interaction (if any) is complex and is documented in I-D HTTPbis:
 *
 * The If-Match and If-Unmodified-Since headers can be used together, and
 * the If-None-Match and If-Modified-Since headers can be used together, but
 * any other interaction is undefined.
 */
int check_precond(const char *meth, const char *etag, time_t lastmod,
		  hdrcache_t hdrcache)
{
    unsigned ret = HTTP_OK;
    const char **hdr;
    time_t since;

    if ((hdr = spool_getheader(hdrcache, "If"))) {
	/* XXX  Need to support this for sync-token and possibly lock-token */
	syslog(LOG_WARNING, "If: %s", hdr[0]);
    }

    if ((hdr = spool_getheader(hdrcache, "If-Match"))) {
	if (!etagcmp(hdr[0], etag)) {
	    /* Precond success - fall through and check If-Unmodified-Since */
	}
	else return HTTP_PRECOND_FAILED;
    }

    if ((hdr = spool_getheader(hdrcache, "If-Unmodified-Since"))) {
	if (!(since = message_parse_date((char *) hdr[0],
					 PARSE_DATE|PARSE_TIME|PARSE_ZONE|
					 PARSE_GMT|PARSE_NOCREATE))) {
	    since = lastmod;
	}

	if (lastmod <= since) {
	    /* Precond success - ignore remaining conditional headers */
	    return HTTP_OK;
	}
	else return HTTP_PRECOND_FAILED;
    }

    if ((hdr = spool_getheader(hdrcache, "If-None-Match"))) {
	if (etagcmp(hdr[0], etag)) {
	    /* Precond success - ignore If-Modified-Since */
	    return HTTP_OK;
	}
	else if (!strchr("GH", meth[0])) return HTTP_PRECOND_FAILED;
	else {
	    ret = HTTP_NOT_MODIFIED;
	    /* Fall through and check If-Modified-Since */
	}
    }

    if ((hdr = spool_getheader(hdrcache, "If-Modified-Since"))) {
	since = message_parse_date((char *) hdr[0],
				   PARSE_DATE|PARSE_TIME|PARSE_ZONE|
				   PARSE_GMT|PARSE_NOCREATE);

	if (lastmod > since) {
	    /* Precond success - this trumps an If-None-Match 304 response */
	    return HTTP_OK;
	}
	else return HTTP_NOT_MODIFIED;
    }

    return ret;
}


/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn)
{
    return get_doc(txn, NULL);
}

int get_doc(struct transaction_t *txn, filter_proc_t filter)
{
    int ret = 0, fd, precond;
    const char *prefix, *path, *ext;
    static struct buf pathbuf = BUF_INITIALIZER;
    struct stat sbuf;
    const char *msg_base = NULL;
    unsigned long msg_size = 0;
    struct message_guid guid;
    struct resp_body_t *resp_body = &txn->resp_body;

    /* Serve up static pages */
    prefix = config_getstring(IMAPOPT_HTTPDOCROOT);
    if (!prefix) return HTTP_NOT_FOUND;

    buf_setcstr(&pathbuf, prefix);
    if (!txn->req_tgt.path || !*txn->req_tgt.path ||
	(txn->req_tgt.path[0] == '/' && txn->req_tgt.path[1] == '\0'))
	buf_appendcstr(&pathbuf, "/index.html");
    else
	buf_appendcstr(&pathbuf, txn->req_tgt.path);
    path = buf_cstring(&pathbuf);

    /* See if file exists and get Content-Length & Last-Modified time */
    if (stat(path, &sbuf)) return HTTP_NOT_FOUND;

    /* Open the file */
    fd = open(path, O_RDONLY);
    if (fd == -1) return HTTP_NOT_FOUND;

    map_refresh(fd, 1, &msg_base, &msg_size, sbuf.st_size, path, NULL);

    /* Fill in Etag, Last-Modified, and Content-Length */
    message_guid_generate(&guid, msg_base, msg_size);
    txn->etag = message_guid_encode(&guid);
    resp_body->lastmod = sbuf.st_mtime;
    resp_body->len = msg_size;

    /* Check any preconditions */
    precond = check_precond(txn->meth, txn->etag,
			    resp_body->lastmod, txn->req_hdrs);

    /* We failed a precondition - don't perform the request */
    if (precond != HTTP_OK) {
	map_free(&msg_base, &msg_size);
	close(fd);

	return precond;
    }

    if ((ext = strrchr(txn->req_tgt.path, '.'))) {
	/* Try to use filename extension to identity Content-Type */
	if (!strcmp(ext, ".text") || !strcmp(ext, ".txt"))
	    resp_body->type = "text/plain";
	else if (!strcmp(ext, ".html") || !strcmp(ext, ".htm"))
	    resp_body->type = "text/html";
	else if (!strcmp(ext, ".css"))
	    resp_body->type = "text/css";
	else if (!strcmp(ext, ".js"))
	    resp_body->type = "text/javascript";
	else if (!strcmp(ext, ".jpeg") || !strcmp(ext, ".jpg"))
	    resp_body->type = "image/jpeg";
	else if (!strcmp(ext, ".gif"))
	    resp_body->type = "image/gif";
	else if (!strcmp(ext, ".png"))
	    resp_body->type = "image/png";
	else
	    resp_body->type = "application/octet-stream";
    }
    else {
	/* Try to usr filetype signatures to identity Content-Type */
	if (msg_size >= 8 &&
	    !memcmp(msg_base, "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", 8)) {
	    resp_body->type = "image/png";
	} else if (msg_size >= 4 &&
		   !memcmp(msg_base, "\xFF\xD8\xFF\xE0", 4)) {
	    resp_body->type = "image/jpeg";
	} else if (msg_size >= 6 &&
		   (!memcmp(msg_base, "GIF87a", 6) ||
		    !memcmp(msg_base, "GIF89a", 6))) {
	    resp_body->type = "image/gif";
	} else {
	    resp_body->type = "application/octet-stream";
	}
    }

    if (filter) ret = (*filter)(txn, msg_base, msg_size);
    else write_body(HTTP_OK, txn, msg_base, msg_size);

    map_free(&msg_base, &msg_size);
    close(fd);

    return ret;
}


/* Perform an OPTIONS request */
int meth_options(struct transaction_t *txn)
{
    /* Response should not be cached */
    txn->flags |= HTTP_NOCACHE;

#ifdef WITH_CALDAV
    /* Special case "*" - show all features/methods available on server */
    if (!strcmp(txn->req_tgt.path, "*")) txn->req_tgt.allow = ALLOW_ALL;
#endif

    response_header(HTTP_OK, txn);
    return 0;
}
