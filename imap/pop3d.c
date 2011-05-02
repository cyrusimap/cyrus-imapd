/* pop3d.c -- POP3 server protocol parsing
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
 * $Id: pop3d.c,v 1.202 2010/05/25 20:59:19 wescraig Exp $
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

#include "assert.h"
#include "acl.h"
#include "util.h"
#include "auth.h"
#include "iptostring.h"
#include "global.h"
#include "tls.h"

#include "exitcodes.h"
#include "imapd.h"
#include "imap_err.h"
#include "mailbox.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "mboxlist.h"
#include "idle.h"
#include "telemetry.h"
#include "backend.h"
#include "proc.h"
#include "proxy.h"
#include "seen.h"
#include "userdeny.h"

#include "sync_log.h"
#include "statuscache.h"

#ifdef HAVE_KRB
/* kerberos des is purported to conflict with OpenSSL DES */
#define DES_DEFS
#include <krb.h>

/* MIT's kpop authentication kludge */
char klrealm[REALM_SZ];
AUTH_DAT kdata;
#endif /* HAVE_KRB */
static int kflag = 0;

extern int optind;
extern char *optarg;
extern int opterr;



#ifdef HAVE_SSL
static SSL *tls_conn;
#endif /* HAVE_SSL */

sasl_conn_t *popd_saslconn; /* the sasl connection context */

int popd_timeout;
char *popd_userid = 0, *popd_subfolder = 0;
struct mailbox *popd_mailbox = NULL;
struct auth_state *popd_authstate = 0;
int config_popuseacl, config_popuseimapflags;
struct sockaddr_storage popd_localaddr, popd_remoteaddr;
int popd_haveaddr = 0;
char popd_clienthost[NI_MAXHOST*2+1] = "[local]";
struct protstream *popd_out = NULL;
struct protstream *popd_in = NULL;
static int popd_logfd = -1;
unsigned popd_exists = 0;
time_t popd_login_time;
int count_retr = 0;
int count_top = 0;
int count_dele = 0;
struct msg {
    unsigned uid;
    uint32_t recno;
    unsigned size;
    int deleted;
    int seen;
} *popd_msg = NULL;

static sasl_ssf_t extprops_ssf = 0;
static int pop3s = 0;
int popd_starttls_done = 0;

static int popd_myrights;

/* the sasl proxy policy context */
static struct proxy_context popd_proxyctx = {
    0, 1, &popd_authstate, NULL, NULL
};

/* signal to config.c */
const int config_need_data = CONFIG_NEED_PARTITION_DATA;

/* current namespace */
static struct namespace popd_namespace;

/* PROXY stuff */
struct backend *backend = NULL;

static struct protocol_t pop3_protocol =
{ "pop3", "pop",
  { 0, "+OK " },
  { "CAPA", NULL, ".", NULL,
    { { "SASL ", CAPA_AUTH },
      { "STLS", CAPA_STARTTLS },
      { NULL, 0 } } },
  { "STLS", "+OK", "-ERR", 0 },
  { "AUTH", 255, 0, "+OK", "-ERR", "+ ", "*", NULL, 0 },
  { NULL, NULL, NULL },
  { "NOOP", NULL, "+OK" },
  { "QUIT", NULL, "+OK" }
};

static void bitpipe(void);
/* end PROXY stuff */

static char popd_apop_chal[45 + MAXHOSTNAMELEN + 1]; /* <rand.time@hostname> */
static void cmd_apop(char *response);

static void cmd_auth(char *arg);
static void cmd_capa(void);
static void cmd_pass(char *pass);
static void cmd_user(char *user);
static void cmd_starttls(int pop3s);
static int blat(int msg, int lines);
static int openinbox(void);
static void cmdloop(void);
static void kpop(void);
static unsigned parse_msgno(char **ptr);
static void uidl_msg(uint32_t msgno);
static int msg_exists_or_err(uint32_t msgno);
static int update_seen(void);
void usage(void);
void shut_down(int code) __attribute__ ((noreturn));

extern int saslserver(sasl_conn_t *conn, const char *mech,
		      const char *init_resp, const char *resp_prefix,
		      const char *continuation, const char *empty_chal,
		      struct protstream *pin, struct protstream *pout,
		      int *sasl_result, char **success_data);

/* Enable the resetting of a sasl_conn_t */
static int reset_saslconn(sasl_conn_t **conn);

static struct 
{
    char *ipremoteport;
    char *iplocalport;
    sasl_ssf_t ssf;
    char *authid;
} saslprops = {NULL,NULL,0,NULL};

static int popd_canon_user(sasl_conn_t *conn, void *context,
			   const char *user, unsigned ulen,
			   unsigned flags, const char *user_realm,
			   char *out, unsigned out_max, unsigned *out_ulen)
{
    char userbuf[MAX_MAILBOX_BUFFER], *p;
    size_t n;
    int r;

    if (!ulen) ulen = strlen(user);

    if (config_getswitch(IMAPOPT_POPSUBFOLDERS)) {
	/* make a working copy of the auth[z]id */
	if (ulen >= MAX_MAILBOX_BUFFER) {
	    sasl_seterror(conn, 0, "buffer overflow while canonicalizing");
	    return SASL_BUFOVER;
	}
	memcpy(userbuf, user, ulen);
	userbuf[ulen] = '\0';
	user = userbuf;

	/* See if we're trying to access a subfolder */
	if ((p = strchr(userbuf, '+'))) {
	    n = config_virtdomains ? strcspn(p, "@") : strlen(p);

	    if (flags & SASL_CU_AUTHZID) {
		/* make a copy of the subfolder */
		if (popd_subfolder) free(popd_subfolder);
		popd_subfolder = xstrndup(p, n);
	    }

	    /* strip the subfolder from the auth[z]id */
	    memmove(p, p+n, strlen(p+n)+1);
	    ulen -= n;
	}
    }

    r = mysasl_canon_user(conn, context, user, ulen, flags, user_realm,
			  out, out_max, out_ulen);

    if (!r && popd_subfolder && flags == SASL_CU_AUTHZID) {
	/* If we're only doing the authzid, put back the subfolder
	   in case its used in the challenge/response calculation */
	n = strlen(popd_subfolder);
	if (*out_ulen + n > out_max) {
	    sasl_seterror(conn, 0, "buffer overflow while canonicalizing");
	    r = SASL_BUFOVER;
	}
	else {
	    p = (config_virtdomains && (p = strchr(out, '@'))) ?
		p : out + *out_ulen;
	    memmove(p+n, p, strlen(p)+1);
	    memcpy(p, popd_subfolder, n);
	    *out_ulen += n;
	}
    }

    return r;
}

static int popd_proxy_policy(sasl_conn_t *conn,
			     void *context,
			     const char *requested_user, unsigned rlen,
			     const char *auth_identity, unsigned alen,
			     const char *def_realm,
			     unsigned urlen,
			     struct propctx *propctx)
{
    char userbuf[MAX_MAILBOX_BUFFER];

    if (config_getswitch(IMAPOPT_POPSUBFOLDERS)) {
	size_t n;
	char *p;

	/* make a working copy of the authzid */
	if (!rlen) rlen = strlen(requested_user);
	if (rlen >= MAX_MAILBOX_BUFFER) {
	    sasl_seterror(conn, 0, "buffer overflow while proxying");
	    return SASL_BUFOVER;
	}
	memcpy(userbuf, requested_user, rlen);
	userbuf[rlen] = '\0';
	requested_user = userbuf;

	/* See if we're trying to access a subfolder */
	if ((p = strchr(userbuf, '+'))) {
	    n = config_virtdomains ? strcspn(p, "@") : strlen(p);

	    /* strip the subfolder from the authzid */
	    memmove(p, p+n, strlen(p+n)+1);
	    rlen -= n;
	}
    }

    return mysasl_proxy_policy(conn, context, requested_user, rlen,
			       auth_identity, alen, def_realm, urlen, propctx);
}

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, &popd_proxy_policy, (void*) &popd_proxyctx },
    { SASL_CB_CANON_USER, &popd_canon_user, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

static void popd_reset(void)
{
    int bytes_in = 0;
    int bytes_out = 0;

    proc_cleanup();

    syslog(LOG_NOTICE, "counts: retr=<%d> top=<%d> dele=<%d>",
                       count_retr, count_top, count_dele);
    count_retr = 0;
    count_top = 0;
    count_dele = 0;

    /* close local mailbox */
    if (popd_mailbox)
	mailbox_close(&popd_mailbox);

    /* close backend connection */
    if (backend) {
	backend_disconnect(backend);
	free(backend);
	backend = NULL;
    }

    if (popd_in) {
	prot_NONBLOCK(popd_in);
	prot_fill(popd_in);
	bytes_in = prot_bytes_in(popd_in);
	prot_free(popd_in);
    }

    if (popd_out) {
	prot_flush(popd_out);
	bytes_out = prot_bytes_out(popd_out);
	prot_free(popd_out);
    }

    if (config_auditlog)
	syslog(LOG_NOTICE, "auditlog: traffic sessionid=<%s> bytes_in=<%d> bytes_out=<%d>", 
			   session_id(), bytes_in, bytes_out);
    
    popd_in = popd_out = NULL;

#ifdef HAVE_SSL
    if (tls_conn) {
	tls_reset_servertls(&tls_conn);
	tls_conn = NULL;
    }
#endif

    cyrus_reset_stdio();

    strcpy(popd_clienthost, "[local]");
    if (popd_logfd != -1) {
	close(popd_logfd);
	popd_logfd = -1;
    }
    if (popd_userid != NULL) {
	free(popd_userid);
	popd_userid = NULL;
    }
    if (popd_subfolder != NULL) {
	free(popd_subfolder);
	popd_subfolder = NULL;
    }
    if (popd_authstate) {
	auth_freestate(popd_authstate);
	popd_authstate = NULL;
    }
    if (popd_saslconn) {
	sasl_dispose(&popd_saslconn);
	popd_saslconn = NULL;
    }
    popd_starttls_done = 0;

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

    popd_exists = 0;
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc __attribute__((unused)),
		 char **argv __attribute__((unused)),
		 char **envp __attribute__((unused)))
{
    int r;
    int opt;

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

    if (config_getswitch(IMAPOPT_STATUSCACHE)) {
	/* open statuscache db to optimize handling an empty maildrop */
	statuscache_open(NULL);
    }

    /* setup for sending IMAP IDLE notifications */
    idle_enabled();

    /* Set namespace */
    if ((r = mboxname_init_namespace(&popd_namespace, 1)) != 0) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    while ((opt = getopt(argc, argv, "skp:")) != EOF) {
	switch(opt) {
	case 's': /* pop3s (do starttls right away) */
	    pop3s = 1;
	    if (!tls_enabled()) {
		syslog(LOG_ERR, "pop3s: required OpenSSL options not present");
		fatal("pop3s: required OpenSSL options not present",
		      EC_CONFIG);
	    }
	    break;

	case 'k':
	    kflag++;
	    break;

	case 'p': /* external protection */
	    extprops_ssf = atoi(optarg);
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
int service_main(int argc __attribute__((unused)),
		 char **argv __attribute__((unused)),
		 char **envp __attribute__((unused)))
{
    socklen_t salen;
    char hbuf[NI_MAXHOST];
    char localip[60], remoteip[60];
    int niflags;
    sasl_security_properties_t *secprops=NULL;

    session_new_id();

    signals_poll();

    sync_log_init();

    popd_in = prot_new(0, 0);
    popd_out = prot_new(1, 1);

    count_retr = 0;
    count_top = 0;
    count_dele = 0;

    /* Find out name of client host */
    salen = sizeof(popd_remoteaddr);
    if (getpeername(0, (struct sockaddr *)&popd_remoteaddr, &salen) == 0 &&
	(popd_remoteaddr.ss_family == AF_INET ||
	 popd_remoteaddr.ss_family == AF_INET6)) {
	if (getnameinfo((struct sockaddr *)&popd_remoteaddr, salen,
			hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) == 0) {
    	    strncpy(popd_clienthost, hbuf, sizeof(hbuf));
	    strlcat(popd_clienthost, " ", sizeof(popd_clienthost));
	} else {
	    popd_clienthost[0] = '\0';
	}
	niflags = NI_NUMERICHOST;
#ifdef NI_WITHSCOPEID
	if (((struct sockaddr *)&popd_remoteaddr)->sa_family == AF_INET6)
	    niflags |= NI_WITHSCOPEID;
#endif
	if (getnameinfo((struct sockaddr *)&popd_remoteaddr, salen, hbuf,
			sizeof(hbuf), NULL, 0, niflags) != 0)
	    strlcpy(hbuf, "unknown", sizeof(hbuf));
	strlcat(popd_clienthost, "[", sizeof(popd_clienthost));
	strlcat(popd_clienthost, hbuf, sizeof(popd_clienthost));
	strlcat(popd_clienthost, "]", sizeof(popd_clienthost));
	salen = sizeof(popd_localaddr);
	if (getsockname(0, (struct sockaddr *)&popd_localaddr, &salen) == 0) {
	    popd_haveaddr = 1;
	}
    }

    /* other params should be filled in */
    if (sasl_server_new("pop", config_servername, NULL, NULL, NULL,
			NULL, 0, &popd_saslconn) != SASL_OK)
	fatal("SASL failed initializing: sasl_server_new()",EC_TEMPFAIL); 

    /* will always return something valid */
    secprops = mysasl_secprops(0);
    if (sasl_setprop(popd_saslconn, SASL_SEC_PROPS, secprops) != SASL_OK)
	fatal("Failed to set SASL property", EC_TEMPFAIL);
    if (sasl_setprop(popd_saslconn, SASL_SSF_EXTERNAL, &extprops_ssf) != SASL_OK)
	fatal("Failed to set SASL property", EC_TEMPFAIL);
    
    if(iptostring((struct sockaddr *)&popd_localaddr,
		  salen, localip, 60) == 0) {
	sasl_setprop(popd_saslconn, SASL_IPLOCALPORT, localip);
	saslprops.iplocalport = xstrdup(localip);
    }
    
    if(iptostring((struct sockaddr *)&popd_remoteaddr,
		  salen, remoteip, 60) == 0) {
	sasl_setprop(popd_saslconn, SASL_IPREMOTEPORT, remoteip);  
	saslprops.ipremoteport = xstrdup(remoteip);
    }

    proc_register("pop3d", popd_clienthost, NULL, NULL);

    /* Set inactivity timer */
    popd_timeout = config_getint(IMAPOPT_POPTIMEOUT);
    if (popd_timeout < 10) popd_timeout = 10;
    popd_timeout *= 60;
    prot_settimeout(popd_in, popd_timeout);
    prot_setflushonread(popd_in, popd_out);

    if (kflag) kpop();

    /* we were connected on pop3s port so we should do 
       TLS negotiation immediatly */
    if (pop3s == 1) cmd_starttls(1);

    /* Create APOP challenge for banner */
    *popd_apop_chal = 0;
    if (config_getswitch(IMAPOPT_ALLOWAPOP) &&
	(sasl_checkapop(popd_saslconn, NULL, 0, NULL, 0) == SASL_OK) &&
	!sasl_mkchal(popd_saslconn,
		     popd_apop_chal, sizeof(popd_apop_chal), 1)) {
	syslog(LOG_WARNING, "APOP disabled: can't create challenge");
    }

    prot_printf(popd_out, "+OK");
    if (config_serverinfo) prot_printf(popd_out, " %s", config_servername);
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	prot_printf(popd_out, " Cyrus POP3%s %s",
		    config_mupdate_server ? " Murder" : "", cyrus_version());
    }
    prot_printf(popd_out, " server ready %s\r\n", popd_apop_chal);

    cmdloop();

    /* QUIT executed */

    /* don't bother reusing KPOP connections */
    if (kflag) shut_down(0);

    /* cleanup */
    popd_reset();

    return 0;
}

/* Called by service API to shut down the service */
void service_abort(int error)
{
    shut_down(error);
}

void usage(void)
{
    prot_printf(popd_out, "-ERR usage: pop3d [-C <alt_config>] [-k] [-s]\r\n");
    prot_flush(popd_out);
    exit(EC_USAGE);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code)
{
    int bytes_in = 0;
    int bytes_out = 0;

    in_shutdown = 1;

    proc_cleanup();

    /* close local mailbox */
    if (popd_mailbox)
	mailbox_close(&popd_mailbox);

    if (popd_msg) {
	free(popd_msg);
    }

    /* close backend connection */
    if (backend) {
	backend_disconnect(backend);
	free(backend);
    }

    syslog(LOG_NOTICE, "counts: retr=<%d> top=<%d> dele=<%d>",
                       count_retr, count_top, count_dele);

    sync_log_done();

    if (config_getswitch(IMAPOPT_STATUSCACHE)) {
	statuscache_close();
	statuscache_done();
    }

    mboxlist_close();
    mboxlist_done();

    quotadb_close();
    quotadb_done();

    denydb_close();
    denydb_done();

    if (popd_in) {
	prot_NONBLOCK(popd_in);
	prot_fill(popd_in);
	bytes_in = prot_bytes_in(popd_in);
	prot_free(popd_in);
    }

    if (popd_out) {
	prot_flush(popd_out);
	bytes_out = prot_bytes_out(popd_out);
	prot_free(popd_out);
    }

    if (config_auditlog)
	syslog(LOG_NOTICE, "auditlog: traffic sessionid=<%s> bytes_in=<%d> bytes_out=<%d>", 
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
    if (popd_out) {
	prot_printf(popd_out, "-ERR [SYS/PERM] Fatal error: %s\r\n", s);
	prot_flush(popd_out);
    }
    syslog(LOG_ERR, "Fatal error: %s", s);
    shut_down(code);
}

#ifdef HAVE_KRB
/* translate IPv4 mapped IPv6 address to IPv4 address */
#ifdef IN6_IS_ADDR_V4MAPPED
static void sockaddr_unmapped(struct sockaddr *sa, socklen_t *len)
{
    struct sockaddr_in6 *sin6;
    struct sockaddr_in *sin4;
    uint32_t addr;
    int port;

    if (sa->sa_family != AF_INET6)
	return;
    sin6 = (struct sockaddr_in6 *)sa;
    if (!IN6_IS_ADDR_V4MAPPED((&sin6->sin6_addr)))
	return;
    sin4 = (struct sockaddr_in *)sa;
    addr = *(uint32_t *)&sin6->sin6_addr.s6_addr[12];
    port = sin6->sin6_port;
    memset(sin4, 0, sizeof(struct sockaddr_in));
    sin4->sin_addr.s_addr = addr;
    sin4->sin_port = port;
    sin4->sin_family = AF_INET;
#ifdef HAVE_SOCKADDR_SA_LEN
    sin4->sin_len = sizeof(struct sockaddr_in);
#endif
    *len = sizeof(struct sockaddr_in);
}
#else
static void sockaddr_unmapped(struct sockaddr *sa __attribute__((unused)),
			      socklen_t *len __attribute__((unused)))
{
    return;
}
#endif


/*
 * MIT's kludge of a kpop protocol
 * Client does a krb_sendauth() first thing
 */
void kpop(void)
{
    Key_schedule schedule;
    KTEXT_ST ticket;
    char instance[INST_SZ];  
    char version[9];
    const char *srvtab;
    int r;
    socklen_t len;
    
    if (!popd_haveaddr) {
	fatal("Cannot get client's IP address", EC_OSERR);
    }

    srvtab = config_getstring(IMAPOPT_SRVTAB);

    sockaddr_unmapped((struct sockaddr *)&popd_remoteaddr, &len);
    if (popd_remoteaddr.ss_family != AF_INET) {
	prot_printf(popd_out,
		    "-ERR [AUTH] Kerberos authentication failure: %s\r\n",
		    "not an IPv4 connection");
	shut_down(0);
    }

    strcpy(instance, "*");
    r = krb_recvauth(0L, 0, &ticket, "pop", instance,
		     (struct sockaddr_in *) &popd_remoteaddr,
		     (struct sockaddr_in *) NULL,
		     &kdata, (char*) srvtab, schedule, version);
    
    if (r) {
	prot_printf(popd_out, "-ERR [AUTH] Kerberos authentication failure: %s\r\n",
		    krb_err_txt[r]);
	syslog(LOG_NOTICE,
	       "badlogin: %s kpop ? %s%s%s@%s %s",
	       popd_clienthost, kdata.pname,
	       kdata.pinst[0] ? "." : "", kdata.pinst,
	       kdata.prealm, krb_err_txt[r]);
	shut_down(0);
    }
    
    r = krb_get_lrealm(klrealm,1);
    if (r) {
	prot_printf(popd_out, "-ERR [AUTH] Kerberos failure: %s\r\n",
		    krb_err_txt[r]);
	syslog(LOG_NOTICE,
	       "badlogin: %s kpop ? %s%s%s@%s krb_get_lrealm: %s",
	       popd_clienthost, kdata.pname,
	       kdata.pinst[0] ? "." : "", kdata.pinst,
	       kdata.prealm, krb_err_txt[r]);
	shut_down(0);
    }
}
#else
void kpop(void)
{
    usage();
}
#endif

static int expunge_deleted(void)
{
    struct index_record record;
    uint32_t msgno;
    int r = 0;

    /* loop over all known messages looking for deletes */
    for (msgno = 1; msgno <= popd_exists; msgno++) {
	/* not deleted? skip */
	if (!popd_msg[msgno].deleted)
	    continue;

	/* error reading? abort */
	r = mailbox_read_index_record(popd_mailbox, popd_msg[msgno].recno, &record);
	if (r) break;

	/* already expunged? skip */
	if (record.system_flags & FLAG_EXPUNGED)
	    continue;

	/* mark expunged */
	record.system_flags |= FLAG_EXPUNGED;

	/* store back to the mailbox */
	r = mailbox_rewrite_index_record(popd_mailbox, &record);
	if (r) break;
    }

    if (r) {
	syslog(LOG_ERR, "IOERROR: %s failed to expunge record %u uid %u, aborting",
	       popd_mailbox->name, msgno, popd_msg[msgno].uid);
    }

    return r;
}

/*
 * Top-level command loop parsing
 */
static void cmdloop(void)
{
    char inputbuf[8192];
    char *p;
    char *arg;
    uint32_t msgno = 0;

    for (;;) {
	signals_poll();

	if (backend) {
	    /* create a pipe from client to backend */
	    bitpipe();

	    /* pipe has been closed */
           telemetry_rusage( popd_userid );
	    return;
	}

	/* check for shutdown file */
	if (shutdown_file(inputbuf, sizeof(inputbuf)) ||
	    (popd_userid &&
	     userdeny(popd_userid, config_ident, inputbuf, sizeof(inputbuf)))) {
	    for (p = inputbuf; *p == '['; p++); /* can't have [ be first char */
	    prot_printf(popd_out, "-ERR [SYS/TEMP] %s\r\n", p);
	    telemetry_rusage( popd_userid );
	    shut_down(0);
	}

	if (!prot_fgets(inputbuf, sizeof(inputbuf), popd_in)) {
	    telemetry_rusage( popd_userid );
	    shut_down(0);
	}

	if (popd_mailbox &&
	    config_getswitch(IMAPOPT_DISCONNECT_ON_VANISHED_MAILBOX)) {
	    if (popd_mailbox->i.options & OPT_MAILBOX_DELETED) {
		/* Mailbox has been (re)moved */
		syslog(LOG_WARNING,
		       "Maildrop %s has been (re)moved out from under client",
		       popd_mailbox->name);
		prot_printf(popd_out,
			    "-ERR [SYS/TEMP] "
			    "Maildrop has been (re)moved\r\n");
		shut_down(0);
	    }
	}

	p = inputbuf + strlen(inputbuf);
	if (p > inputbuf && p[-1] == '\n') *--p = '\0';
	if (p > inputbuf && p[-1] == '\r') *--p = '\0';

	/* Parse into keword and argument */
	for (p = inputbuf; *p && !Uisspace(*p); p++);
	if (*p) {
	    *p++ = '\0';
	    arg = p;
	    if (strcasecmp(inputbuf, "pass") != 0) {
		while (*arg && Uisspace(*arg)) {
		    arg++;
		}
	    }
	    if (!*arg) {
		if (strcasecmp(inputbuf, "auth") == 0) {
		    /* HACK for MS Outlook's incorrect use of the old-style
		     * SASL discovery method.
		     * Outlook uses "AUTH \r\n" instead if "AUTH\r\n"
		     */
		    arg = 0;
		}
		else {
		    prot_printf(popd_out, "-ERR Syntax error\r\n");
		    continue;
		}
	    }
	}
	else {
	    arg = 0;
	}
	lcase(inputbuf);

	if (!strcmp(inputbuf, "quit")) {
	    if (!arg) {
		int pollpadding =config_getint(IMAPOPT_POPPOLLPADDING);
		int minpollsec = config_getint(IMAPOPT_POPMINPOLL)*60;

		/* check preconditions! */
		if (!popd_mailbox)
		    goto done;
		if (mailbox_lock_index(popd_mailbox, LOCK_EXCLUSIVE))
		    goto done;
		if (popd_mailbox->i.options & OPT_MAILBOX_DELETED)
		    goto done;

		/* mark dirty in case everything else misses it - we're updating
		 * at least the last login */
		mailbox_index_dirty(popd_mailbox);
		if ((minpollsec > 0) && (pollpadding > 1)) { 
		    time_t mintime = popd_login_time - (minpollsec*(pollpadding));
		    if (popd_mailbox->i.pop3_last_login < mintime) {
			popd_mailbox->i.pop3_last_login = mintime + minpollsec; 
		    } else {
			popd_mailbox->i.pop3_last_login += minpollsec;
		    }
		} else { 
		    popd_mailbox->i.pop3_last_login = popd_login_time;
		}

		/* look for deleted messages */
		expunge_deleted();

		/* update seen data */
		update_seen();

		/* unlock will commit changes */
		mailbox_unlock_index(popd_mailbox, NULL);

done:
		prot_printf(popd_out, "+OK\r\n");
               telemetry_rusage( popd_userid );
		return;
	    }
	    else 
		prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	}
	else if (!strcmp(inputbuf, "capa")) {
	    if (arg) {
		prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	    } else {
		cmd_capa();
	    }
	}
	else if (!popd_authstate) {
	    if (!strcmp(inputbuf, "user")) {
		if (!arg) {
		    prot_printf(popd_out, "-ERR Missing argument\r\n");
		}
		else {
		    cmd_user(arg);
		}
	    }
	    else if (!strcmp(inputbuf, "pass")) {
		if (!arg) prot_printf(popd_out, "-ERR Missing argument\r\n");
		else cmd_pass(arg);
	    }
	    else if (!strcmp(inputbuf, "apop") && *popd_apop_chal) {
		if (!arg) prot_printf(popd_out, "-ERR Missing argument\r\n");
		else cmd_apop(arg);
	    }
	    else if (!strcmp(inputbuf, "auth")) {
		cmd_auth(arg);
	    }
	    else if (!strcmp(inputbuf, "stls") && tls_enabled()) {
		if (arg) {
		    prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
		} else {
		    /* XXX  discard any input pipelined after STLS */
		    prot_flush(popd_in);

		    cmd_starttls(0);
		}
	    }
	    else {
		prot_printf(popd_out, "-ERR Unrecognized command\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "stat")) {
	    unsigned nmsgs = 0, totsize = 0;
	    if (arg) {
		prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	    }
	    else {
		for (msgno = 1; msgno <= popd_exists; msgno++) {
		    if (!popd_msg[msgno].deleted) {
			nmsgs++;
			totsize += popd_msg[msgno].size;
		    }
		}
		prot_printf(popd_out, "+OK %u %u\r\n", nmsgs, totsize);
	    }
	}
	else if (!strcmp(inputbuf, "list")) {
	    if (arg) {
		msgno = parse_msgno(&arg);
		if (msgno) {
		    prot_printf(popd_out, "+OK %u %u\r\n", msgno, popd_msg[msgno].size);
		}
	    }
	    else {
		prot_printf(popd_out, "+OK scan listing follows\r\n");
		for (msgno = 1; msgno <= popd_exists; msgno++) {
		    if (!popd_msg[msgno].deleted)
			prot_printf(popd_out, "%u %u\r\n", msgno, popd_msg[msgno].size);
		}
		prot_printf(popd_out, ".\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "retr")) {
	    if (!arg) prot_printf(popd_out, "-ERR Missing argument\r\n");
	    else {
		msgno = parse_msgno(&arg);
		if (msgno) {
		    blat(msgno, -1);
		    popd_msg[msgno].seen = 1;
		    count_retr++;
		}
	    }
	}
	else if (!strcmp(inputbuf, "dele")) {
	    if (!arg) prot_printf(popd_out, "-ERR Missing argument\r\n");
	    else if (config_popuseacl && !(popd_myrights & ACL_DELETEMSG)) {
		prot_printf(popd_out, "-ERR [SYS/PERM] %s\r\n",
			    error_message(IMAP_PERMISSION_DENIED));
	    }
	    else {
		msgno = parse_msgno(&arg);
		if (msgno) {
		    popd_msg[msgno].deleted = 1;
		    prot_printf(popd_out, "+OK message deleted\r\n");
		    count_dele++;
		}
	    }
	}
	else if (!strcmp(inputbuf, "noop")) {
	    if (arg)
		prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	    else 
		prot_printf(popd_out, "+OK\r\n");
	}
	else if (!strcmp(inputbuf, "rset")) {
	    if (arg) 
		prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	    else {
		for (msgno = 1; msgno <= popd_exists; msgno++) {
		    popd_msg[msgno].deleted = 0;
		    popd_msg[msgno].seen = 0;
		}
		prot_printf(popd_out, "+OK\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "top")) {
	    const char *p = arg;
	    uint32_t num;
	    uint32_t lines;
	    int r;

	    while (*p && Uisspace(*p)) {
		p++;
	    }

	    /* special case, can't just parse_msgno */
	    r = parseuint32(p, &p, &num);
	    if (r || !*p) {
		prot_printf(popd_out, "-ERR Missing argument\r\n");
	    }
	    else {
		msgno = num;
		/* skip over whitespace */
		while (*p && Uisspace(*p)) {
		    p++;
		}
		if (parseuint32(p, &p, &lines)) {
		    prot_printf(popd_out, "-ERR Invalid number of lines\r\n");
		}
		else if (*p) {
		    prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg_exists_or_err(msgno)) {
		    blat(msgno, lines);
		    count_top++;
		}
	    }
	}
	else if (!strcmp(inputbuf, "uidl")) {
	    if (arg) {
		msgno = parse_msgno(&arg);
		if (msgno) {
		    prot_printf(popd_out, "+OK ");
		    uidl_msg(msgno);
		}
	    }
	    else {
		prot_printf(popd_out, "+OK unique-id listing follows\r\n");
		for (msgno = 1; msgno <= popd_exists; msgno++) {
		    if (!popd_msg[msgno].deleted)
			uidl_msg(msgno);
		}
		prot_printf(popd_out, ".\r\n");
	    }
	}
	else {
	    prot_printf(popd_out, "-ERR Unrecognized command\r\n");
	}
    }
}

unsigned parse_msgno(char **ptr)
{
    const char *p;
    uint32_t msgno;
    int r;

    p = *ptr;

    /* skip leading whitespace */
    while (*p && Uisspace(*p)) {
	p++;
    }

    r = parseuint32(p, &p, &msgno);

    if (*p) {
	prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	*ptr = (char *)p;
    }
    else if (msg_exists_or_err(msgno))
	return msgno;

    return 0;
}

int msg_exists_or_err(uint32_t msgno)
{
    if (msgno < 1 || msgno > popd_exists ||
	     popd_msg[msgno].deleted) {
	prot_printf(popd_out, "-ERR No such message\r\n");
	return 0;
    }
    return 1;
}

void uidl_msg(uint32_t msgno)
{
    if (popd_mailbox->i.options & OPT_POP3_NEW_UIDL) {
	prot_printf(popd_out, "%u %u.%u\r\n", msgno, 
		    popd_mailbox->i.uidvalidity,
		    popd_msg[msgno].uid);
    } else {
	prot_printf(popd_out, "%u %u\r\n", msgno,
		    popd_msg[msgno].uid);
    }
}

#ifdef HAVE_SSL
static void cmd_starttls(int pop3s)
{
    int result;
    int *layerp;
    sasl_ssf_t ssf;
    char *auth_id;

    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &ssf;

    if (popd_starttls_done == 1)
    {
	prot_printf(popd_out, "-ERR %s\r\n", 
		    "Already successfully executed STLS");
	return;
    }

    result=tls_init_serverengine("pop3",
				 5,        /* depth to verify */
				 !pop3s,   /* can client auth? */
				 !pop3s);  /* TLS only? */

    if (result == -1) {

	syslog(LOG_ERR, "[pop3d] error initializing TLS");

	if (pop3s == 0)
	    prot_printf(popd_out, "-ERR [SYS/PERM] %s\r\n", "Error initializing TLS");
	else
	    fatal("tls_init() failed",EC_TEMPFAIL);

	return;
    }

    if (pop3s == 0)
    {
	prot_printf(popd_out, "+OK %s\r\n", "Begin TLS negotiation now");
	/* must flush our buffers before starting tls */
	prot_flush(popd_out);
    }
  
    result=tls_start_servertls(0, /* read */
			       1, /* write */
			       pop3s ? 180 : popd_timeout,
			       layerp,
			       &auth_id,
			       &tls_conn);

    /* if error */
    if (result==-1) {
	if (pop3s == 0) {
	    prot_printf(popd_out, "-ERR [SYS/PERM] Starttls failed\r\n");
	    syslog(LOG_NOTICE, "[pop3d] STARTTLS failed: %s", popd_clienthost);
	} else {
	    syslog(LOG_NOTICE, "pop3s failed: %s", popd_clienthost);
	    fatal("tls_start_servertls() failed", EC_TEMPFAIL);
	}
	return;
    }

    /* tell SASL about the negotiated layer */
    result = sasl_setprop(popd_saslconn, SASL_SSF_EXTERNAL, &ssf);
    if (result != SASL_OK) {
	fatal("sasl_setprop() failed: cmd_starttls()", EC_TEMPFAIL);
    }
    saslprops.ssf = ssf;

    result = sasl_setprop(popd_saslconn, SASL_AUTH_EXTERNAL, auth_id);
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
    prot_settls(popd_in, tls_conn);
    prot_settls(popd_out, tls_conn);

    popd_starttls_done = 1;
}
#else
static void cmd_starttls(int pop3s __attribute__((unused)))
{
    fatal("cmd_starttls() called, but no OpenSSL", EC_SOFTWARE);
}
#endif /* HAVE_SSL */

static void cmd_apop(char *response)
{
    int sasl_result;
    const void *canon_user;
    int failedloginpause;

    assert(response != NULL);

    if (popd_userid) {
	prot_printf(popd_out, "-ERR [AUTH] Must give PASS command\r\n");
	return;
    }

    sasl_result = sasl_checkapop(popd_saslconn,
				 popd_apop_chal,
				 strlen(popd_apop_chal),
				 response,
				 strlen(response));
    
    /* failed authentication */
    if (sasl_result != SASL_OK)
    {
	syslog(LOG_NOTICE, "badlogin: %s APOP (%s) %s",
	       popd_clienthost, popd_apop_chal,
	       sasl_errdetail(popd_saslconn));
	
	failedloginpause = config_getint(IMAPOPT_FAILEDLOGINPAUSE);
	if (failedloginpause != 0) {
	    sleep(failedloginpause);
	}

	/* Don't allow user probing */
	if (sasl_result == SASL_NOUSER) sasl_result = SASL_BADAUTH;
		
	prot_printf(popd_out, "-ERR [AUTH] authenticating: %s\r\n",
		    sasl_errstring(sasl_result, NULL, NULL));

	if (popd_subfolder) {
	    free(popd_subfolder);
	    popd_subfolder = 0;
	}
	return;
    }

    /* successful authentication */

    /*
     * get the userid from SASL --- already canonicalized from
     * mysasl_proxy_policy()
     */
    sasl_result = sasl_getprop(popd_saslconn, SASL_USERNAME, &canon_user);
    if (sasl_result != SASL_OK) {
	prot_printf(popd_out, 
		    "-ERR [AUTH] weird SASL error %d getting SASL_USERNAME\r\n", 
		    sasl_result);
	if (popd_subfolder) {
	    free(popd_subfolder);
	    popd_subfolder = 0;
	}
	return;
    }
    popd_userid = xstrdup((const char *) canon_user);
    
    syslog(LOG_NOTICE, "login: %s %s%s APOP%s %s", popd_clienthost,
	   popd_userid, popd_subfolder ? popd_subfolder : "",
	   popd_starttls_done ? "+TLS" : "", "User logged in");

    popd_authstate = auth_newstate(popd_userid);

    openinbox();
}

void cmd_user(char *user)
{
    char userbuf[MAX_MAILBOX_BUFFER], *dot, *domain;
    unsigned userlen;

    /* possibly disallow USER */
    if (!(kflag || popd_starttls_done || (extprops_ssf > 1) ||
	  config_getswitch(IMAPOPT_ALLOWPLAINTEXT))) {
	prot_printf(popd_out,
		    "-ERR [AUTH] USER command only available under a layer\r\n");
	return;
    }

    if (popd_userid) {
	prot_printf(popd_out, "-ERR [AUTH] Must give PASS command\r\n");
	return;
    }

    if (popd_canon_user(popd_saslconn, NULL, user, 0,
			SASL_CU_AUTHID | SASL_CU_AUTHZID,
			NULL, userbuf, sizeof(userbuf), &userlen) ||
	     /* '.' isn't allowed if '.' is the hierarchy separator */
	     (popd_namespace.hier_sep == '.' && (dot = strchr(userbuf, '.')) &&
	      !(config_virtdomains &&  /* allow '.' in dom.ain */
		(domain = strchr(userbuf, '@')) && (dot > domain))) ||
	     strlen(userbuf) + 6 >= MAX_MAILBOX_BUFFER) {
	prot_printf(popd_out, "-ERR [AUTH] Invalid user\r\n");
	syslog(LOG_NOTICE,
	       "badlogin: %s plaintext %s invalid user",
	       popd_clienthost, beautify_string(user));
    }
    else {
	popd_userid = xstrdup(userbuf);
	prot_printf(popd_out, "+OK Name is a valid mailbox\r\n");
    }
}

void cmd_pass(char *pass)
{
    int failedloginpause;

    if (!popd_userid) {
	prot_printf(popd_out, "-ERR [AUTH] Must give USER command\r\n");
	return;
    }

#ifdef HAVE_KRB
    if (kflag) {
	if (strcmp(popd_userid, kdata.pname) != 0 ||
	    kdata.pinst[0] ||
	    strcmp(klrealm, kdata.prealm) != 0) {
	    prot_printf(popd_out, "-ERR [AUTH] Invalid login\r\n");
	    syslog(LOG_NOTICE,
		   "badlogin: %s kpop %s %s%s%s@%s access denied",
		   popd_clienthost, popd_userid,
		   kdata.pname, kdata.pinst[0] ? "." : "",
		   kdata.pinst, kdata.prealm);
	    return;
	}

	syslog(LOG_NOTICE, "login: %s %s%s KPOP%s %s", popd_clienthost,
	       popd_userid, popd_subfolder ? popd_subfolder : "",
	       popd_starttls_done ? "+TLS" : "", "User logged in");

	openinbox();
	return;
    }
#endif

    if (!strcmp(popd_userid, "anonymous")) {
	if (config_getswitch(IMAPOPT_ALLOWANONYMOUSLOGIN)) {
	    pass = beautify_string(pass);
	    if (strlen(pass) > 500) pass[500] = '\0';
	    syslog(LOG_NOTICE, "login: %s anonymous %s",
		   popd_clienthost, pass);
	}
	else {
	    syslog(LOG_NOTICE, "badlogin: %s anonymous login refused",
		   popd_clienthost);
	    prot_printf(popd_out, "-ERR [AUTH] Invalid login\r\n");
	    return;
	}
    }
    else if (sasl_checkpass(popd_saslconn,
			    popd_userid,
			    strlen(popd_userid),
			    pass,
			    strlen(pass))!=SASL_OK) { 
	syslog(LOG_NOTICE, "badlogin: %s plaintext %s %s",
	       popd_clienthost, popd_userid, sasl_errdetail(popd_saslconn));
	failedloginpause = config_getint(IMAPOPT_FAILEDLOGINPAUSE);
	if (failedloginpause != 0) {
	    sleep(failedloginpause);
	}
	prot_printf(popd_out, "-ERR [AUTH] Invalid login\r\n");
	free(popd_userid);
	popd_userid = 0;
	if (popd_subfolder) {
	    free(popd_subfolder);
	    popd_subfolder = 0;
	}
	return;
    }
    else {
	/* successful authentication */
	int sasl_result, plaintextloginpause;
	const void *val;

	free(popd_userid);
	popd_userid = 0;

	/* get the userid from SASL --- already canonicalized from
	 * mysasl_proxy_policy()
	 */
	sasl_result = sasl_getprop(popd_saslconn, SASL_USERNAME, &val);
	if (sasl_result != SASL_OK) {
	    prot_printf(popd_out, 
			"-ERR [AUTH] weird SASL error %d getting SASL_USERNAME\r\n", 
			sasl_result);
	    if (popd_subfolder) {
		free(popd_subfolder);
		popd_subfolder = 0;
	    }
	    return;
	}
	popd_userid = xstrdup((const char *) val);

	syslog(LOG_NOTICE, "login: %s %s%s plaintext%s %s SESSIONID=<%s>", popd_clienthost,
	       popd_userid, popd_subfolder ? popd_subfolder : "",
	       popd_starttls_done ? "+TLS" : "", "User logged in", session_id());

	if ((plaintextloginpause = config_getint(IMAPOPT_PLAINTEXTLOGINPAUSE))
	     != 0) {
	    sleep(plaintextloginpause);
	}
    }

    popd_authstate = auth_newstate(popd_userid);

    openinbox();
}

/* Handle the POP3 Extension extension.
 */
void cmd_capa(void)
{
    int minpoll = config_getint(IMAPOPT_POPMINPOLL) * 60;
    int expire = config_getint(IMAPOPT_POPEXPIRETIME);
    int mechcount;
    const char *mechlist;

    prot_printf(popd_out, "+OK List of capabilities follows\r\n");

    /* SASL special case: print SASL, then a list of supported capabilities */
    if ((!popd_authstate || saslprops.ssf) &&
	sasl_listmech(popd_saslconn,
		      NULL, /* should be id string */
		      "SASL ", " ", "\r\n",
		      &mechlist,
		      NULL, &mechcount) == SASL_OK && mechcount > 0) {
	prot_write(popd_out, mechlist, strlen(mechlist));
    }

    if (tls_enabled() && !popd_starttls_done && !popd_authstate) {
	prot_printf(popd_out, "STLS\r\n");
    }
    if (expire < 0) {
	prot_printf(popd_out, "EXPIRE NEVER\r\n");
    } else {
	prot_printf(popd_out, "EXPIRE %d\r\n", expire);
    }

    prot_printf(popd_out, "LOGIN-DELAY %d\r\n", minpoll);
    prot_printf(popd_out, "TOP\r\n");
    prot_printf(popd_out, "UIDL\r\n");
    prot_printf(popd_out, "PIPELINING\r\n");
    prot_printf(popd_out, "RESP-CODES\r\n");
    prot_printf(popd_out, "AUTH-RESP-CODE\r\n");

    if (!popd_authstate &&
	(kflag || popd_starttls_done || (extprops_ssf > 1)
	 || config_getswitch(IMAPOPT_ALLOWPLAINTEXT))) {
	prot_printf(popd_out, "USER\r\n");
    }
    
    if (popd_authstate || (config_serverinfo == IMAP_ENUM_SERVERINFO_ON)) {
	prot_printf(popd_out,
		    "IMPLEMENTATION Cyrus POP3%s %s\r\n",
		    config_mupdate_server ? " Murder" : "", cyrus_version());
    }

    prot_printf(popd_out, ".\r\n");
    prot_flush(popd_out);
}


void cmd_auth(char *arg)
{
    int r, sasl_result;
    char *authtype;
    const void *val;
    const char *canon_user;
    int failedloginpause;

    /* if client didn't specify an argument we give them the list
     *
     * XXX This method of mechanism discovery is an undocumented feature
     * that appeared in draft-myers-sasl-pop3 and is still used by
     * some clients.
     */
    if (!arg) {
	const char *sasllist;
	int mechnum;

	prot_printf(popd_out, "+OK List of supported mechanisms follows\r\n");
      
	/* CRLF separated, dot terminated */
	if (sasl_listmech(popd_saslconn, NULL,
			  "", "\r\n", "\r\n",
			  &sasllist,
			  NULL, &mechnum) == SASL_OK) {
	    if (mechnum>0) {
		prot_printf(popd_out,"%s",sasllist);
	    }
	}
      
	prot_printf(popd_out, ".\r\n");
      	return;
    }

    authtype = arg;

    /* according to RFC 2449, since we advertise the "SASL" capability, we
     * must accept an optional second argument as an initial client
     * response (base64 encoded!).
     */ 
    while (*arg && !Uisspace(*arg)) {
	arg++;
    }
    if (Uisspace(*arg)) {
	/* null terminate authtype, get argument */
	*arg++ = '\0';
    } else {
	/* no optional client response */
	arg = NULL;
    }

    r = saslserver(popd_saslconn, authtype, arg, "", "+ ", "",
		   popd_in, popd_out, &sasl_result, NULL);

    if (r) {
	const char *errorstring = NULL;

	switch (r) {
	case IMAP_SASL_CANCEL:
	    prot_printf(popd_out,
			"-ERR [AUTH] Client canceled authentication\r\n");
	    break;
	case IMAP_SASL_PROTERR:
	    errorstring = prot_error(popd_in);

	    prot_printf(popd_out,
			"-ERR [AUTH] Error reading client response: %s\r\n",
			errorstring ? errorstring : "");
	    break;
	default:
	    /* failed authentication */
	    if (authtype) {
		syslog(LOG_NOTICE, "badlogin: %s %s %s",
		       popd_clienthost, authtype,
		       sasl_errstring(sasl_result, NULL, NULL));
	    } else {
		syslog(LOG_NOTICE, "badlogin: %s %s",
		       popd_clienthost, authtype);
	    }

	    failedloginpause = config_getint(IMAPOPT_FAILEDLOGINPAUSE);
	    if (failedloginpause != 0) {
	        sleep(failedloginpause);
	    }

	    /* Don't allow user probing */
	    if (sasl_result == SASL_NOUSER) sasl_result = SASL_BADAUTH;
		
	    prot_printf(popd_out, "-ERR [AUTH] authenticating: %s\r\n",
			sasl_errstring(sasl_result, NULL, NULL));
	}
	
	if (popd_subfolder) {
	    free(popd_subfolder);
	    popd_subfolder = 0;
	}
	reset_saslconn(&popd_saslconn);
	return;
    }

    /* successful authentication */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_proxy_policy()
     */
    sasl_result = sasl_getprop(popd_saslconn, SASL_USERNAME, &val);
    if (sasl_result != SASL_OK) {
	prot_printf(popd_out, 
		    "-ERR [AUTH] weird SASL error %d getting SASL_USERNAME\r\n", 
		    sasl_result);
	return;
    }
    canon_user = (const char *) val;

    /* If we're proxying, the authzid may contain a subfolder,
       so re-canonify it */
    if (config_getswitch(IMAPOPT_POPSUBFOLDERS) && strchr(canon_user, '+')) {
	char userbuf[MAX_MAILBOX_BUFFER];
	unsigned userlen;

	sasl_result = popd_canon_user(popd_saslconn, NULL, canon_user, 0,
				      SASL_CU_AUTHID | SASL_CU_AUTHZID,
				      NULL, userbuf, sizeof(userbuf), &userlen);
	if (sasl_result != SASL_OK) {
	    prot_printf(popd_out, 
			"-ERR [AUTH] SASL canonification error %d\r\n", 
			sasl_result);
	    return;
	}

	popd_userid = xstrdup(userbuf);
    } else {
	popd_userid = xstrdup(canon_user);
    }
    syslog(LOG_NOTICE, "login: %s %s%s %s%s %s", popd_clienthost,
	   popd_userid, popd_subfolder ? popd_subfolder : "",
	   authtype, popd_starttls_done ? "+TLS" : "", "User logged in");

    sasl_getprop(popd_saslconn, SASL_SSF, &val);
    saslprops.ssf = *((sasl_ssf_t *) val);

    if (!openinbox()) {
	prot_setsasl(popd_in,  popd_saslconn);
	prot_setsasl(popd_out, popd_saslconn);
    }
    else {
	reset_saslconn(&popd_saslconn);
    }
}

/*
 * Complete the login process by opening and locking the user's inbox
 */
int openinbox(void)
{
    char userid[MAX_MAILBOX_BUFFER], inboxname[MAX_MAILBOX_BUFFER];
    char extname[MAX_MAILBOX_BUFFER] = "INBOX";
    int myrights = 0;
    int r, log_level = LOG_ERR;
    const char *statusline = NULL;
    struct mboxlist_entry *mbentry = NULL;
    struct statusdata sdata;

    /* Translate any separators in userid
       (use a copy since we need the original userid for AUTH to backend) */
    strlcpy(userid, popd_userid, sizeof(userid));
    mboxname_hiersep_tointernal(&popd_namespace, userid,
				config_virtdomains ?
				strcspn(userid, "@") : 0);

    /* Create the mailbox that we're trying to access */
    if (popd_subfolder && popd_subfolder[1]) {
	snprintf(extname+5, sizeof(extname)-5, "%c%s",
		 popd_namespace.hier_sep, popd_subfolder+1);
    }
    r = (*popd_namespace.mboxname_tointernal)(&popd_namespace, extname,
					      userid, inboxname);

    if (!r) r = mboxlist_lookup(inboxname, &mbentry, NULL);
    if (!r && (config_popuseacl = config_getswitch(IMAPOPT_POPUSEACL)) &&
	(!mbentry->acl ||
	 !((myrights = cyrus_acl_myrights(popd_authstate, mbentry->acl)) & ACL_READ))) {
	r = (myrights & ACL_LOOKUP) ?
	    IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	log_level = LOG_INFO;
    }
    if (r) {
	sleep(3);
	syslog(log_level, "Unable to locate maildrop %s: %s",
	       inboxname, error_message(r));
	prot_printf(popd_out,
		    "-ERR [SYS/PERM] Unable to locate maildrop: %s\r\n",
		    error_message(r));
	goto fail;
    }

    if (mbentry->mbtype & MBTYPE_REMOTE) {
	/* remote mailbox */

	/* Make a working copy of userid in case we need to alter it */
	strlcpy(userid, popd_userid, sizeof(userid));

	if (popd_subfolder) {
	    /* Add the subfolder back to the userid for proxying */
	    size_t n = strlen(popd_subfolder);
	    char *p = (config_virtdomains && (p = strchr(userid, '@'))) ?
		p : userid + strlen(userid);
	    memmove(p+n, p, strlen(p)+1);
	    memcpy(p, popd_subfolder, n);
	}

	backend = backend_connect(NULL, mbentry->server, &pop3_protocol,
				  userid, NULL, &statusline);

	if (!backend) {
	    syslog(LOG_ERR, "couldn't authenticate to backend server");
	    prot_printf(popd_out, "-ERR%s",
			statusline ? statusline :
			" Authentication to backend server failed\r\n");
	    prot_flush(popd_out);
	    
	    goto fail;
	}
    }
    else if (config_getswitch(IMAPOPT_STATUSCACHE) &&
	     !(r = statuscache_lookup(inboxname, userid, STATUS_MESSAGES, &sdata)) &&
	     !sdata.messages) {
	/* local mailbox (empty) -- don't bother opening the mailbox */
	syslog(LOG_INFO, "optimized mode for empty maildrop: %s", popd_userid);
    }
    else {
	/* local mailbox */
	uint32_t recno, msgno;
	struct index_record record;
	int minpoll;

	popd_login_time = time(0);

	r = mailbox_open_iwl(inboxname, &popd_mailbox);
	if (r) {
	    sleep(3);
	    syslog(log_level, "Unable to open maildrop %s: %s",
		   inboxname, error_message(r));
	    prot_printf(popd_out,
			"-ERR [SYS/PERM] Unable to open maildrop: %s\r\n",
			error_message(r));
	    goto fail;
	}
	popd_myrights = cyrus_acl_myrights(popd_authstate, popd_mailbox->acl);
	if (config_popuseacl && !(popd_myrights & ACL_READ)) {
	    r = (popd_myrights & ACL_LOOKUP) ?
		 IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	    log_level = LOG_INFO;
	}

	if (r) {
	    mailbox_close(&popd_mailbox);
	    syslog(LOG_ERR, "Unable to lock maildrop %s: %s",
		   inboxname, error_message(r));
	    prot_printf(popd_out,
			"-ERR [IN-USE] Unable to lock maildrop: %s\r\n",
			error_message(r));
	    goto fail;
	}

	if ((minpoll = config_getint(IMAPOPT_POPMINPOLL)) &&
	    popd_mailbox->i.pop3_last_login + 60*minpoll > popd_login_time) {
	    prot_printf(popd_out,
			"-ERR [LOGIN-DELAY] Logins must be at least %d minute%s apart\r\n",
			minpoll, minpoll > 1 ? "s" : "");
	    mailbox_close(&popd_mailbox);
	    goto fail;
	}

	popd_msg = (struct msg *) xrealloc(popd_msg, (popd_mailbox->i.exists+1) *
					   sizeof(struct msg));
	config_popuseimapflags = config_getswitch(IMAPOPT_POPUSEIMAPFLAGS);
	msgno = 0;
	for (recno = 1; recno <= popd_mailbox->i.num_records; recno++) {
	    if (mailbox_read_index_record(popd_mailbox, recno, &record))
		break;

	    if (record.system_flags & FLAG_EXPUNGED)
		continue;

	    if (config_popuseimapflags &&
		(record.system_flags & FLAG_DELETED)) {
		/* Ignore \Deleted messages */
		continue;
	    }

	    if (popd_mailbox->i.pop3_show_after &&
		record.internaldate <= popd_mailbox->i.pop3_show_after) {
		/* Ignore messages older than the "show after" date */
		continue;
	    }

	    msgno++;
	    popd_msg[msgno].recno = recno;
	    popd_msg[msgno].uid = record.uid;
	    popd_msg[msgno].size = record.size;
	    popd_msg[msgno].deleted = 0;
	    popd_msg[msgno].seen = 0;

	    if (msgno >= popd_mailbox->i.exists)
		break; /* we're full! */
	}
	popd_exists = msgno;

	/* finished our initial read */
	mailbox_unlock_index(popd_mailbox, NULL);

	/* Update the statuscache entry if the maildrop is empty */
	if (config_getswitch(IMAPOPT_STATUSCACHE) && !popd_exists) {
	    /* We always have message count, uidnext,
	     * uidvalidity, and highestmodseq for cache */
	    unsigned statusitems = STATUS_MESSAGES | STATUS_UIDNEXT |
		STATUS_UIDVALIDITY | STATUS_HIGHESTMODSEQ;

	    statuscache_fill(&sdata, popd_userid, popd_mailbox,
			     statusitems, 0, 0);
	    mailbox_close(&popd_mailbox);
	    statuscache_update(inboxname, &sdata);
	}
    }

    /* register process */
    proc_register("pop3d", popd_clienthost, popd_userid, inboxname);

    /* Create telemetry log */
    popd_logfd = telemetry_log(popd_userid, popd_in, popd_out, 0);

    mboxlist_entry_free(&mbentry);

    if (statusline)
	prot_printf(popd_out, "+OK%s", statusline);
    else
	prot_printf(popd_out, "+OK Mailbox locked and ready SESSIONID=<%s>\r\n", session_id());
    prot_flush(popd_out);

    return 0;

  fail:
    mboxlist_entry_free(&mbentry);
    free(popd_userid);
    popd_userid = 0;
    if (popd_subfolder) {
	free(popd_subfolder);
	popd_subfolder = 0;
    }
    auth_freestate(popd_authstate);
    popd_authstate = NULL;
    return 1;
}

static int blat(int msgno, int lines)
{
    FILE *msgfile;
    char buf[4096];
    char *fname;
    int thisline = -2;

    fname = mailbox_message_fname(popd_mailbox, popd_msg[msgno].uid);
    msgfile = fopen(fname, "r");
    if (!msgfile) {
	prot_printf(popd_out, "-ERR [SYS/PERM] Could not read message file\r\n");
	return IMAP_IOERROR;
    }
    prot_printf(popd_out, "+OK Message follows\r\n");
    while (lines != thisline) {
	if (!fgets(buf, sizeof(buf), msgfile)) break;

	if (thisline < 0) {
	    if (buf[0] == '\r' && buf[1] == '\n') thisline = 0;
	}
	else thisline++;

	if (buf[0] == '.') 
	    (void)prot_putc('.', popd_out);
	do {
	    prot_printf(popd_out, "%s", buf);
	}
	while (buf[strlen(buf)-1] != '\n' && fgets(buf, sizeof(buf), msgfile));
    }
    fclose(msgfile);

    /* Protect against messages not ending in CRLF */
    if (buf[strlen(buf)-1] != '\n') prot_printf(popd_out, "\r\n");

    prot_printf(popd_out, ".\r\n");

    /* Reset inactivity timer in case we spend a long time
       pushing data to the client over a slow link. */
    prot_resettimeout(popd_in);

    return 0;
}

/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(sasl_conn_t **conn) 
{
    int ret;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(conn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("pop", config_servername,
                         NULL, NULL, NULL,
                         NULL, 0, conn);
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

/* we've authenticated the client, we've connected to the backend.
   now it's all up to them */
static void bitpipe(void)
{
    struct protgroup *protin = protgroup_new(2);
    int shutdown = 0;
    char buf[4096];

    protgroup_insert(protin, popd_in);
    protgroup_insert(protin, backend->in);

    do {
	/* Flush any buffered output */
	prot_flush(popd_out);
	prot_flush(backend->out);

	/* check for shutdown file */
	if (shutdown_file(buf, sizeof(buf)) ||
	    userdeny(popd_userid, config_ident, buf, sizeof(buf))) {
	    shutdown = 1;
	    goto done;
	}
    } while (!proxy_check_input(protin, popd_in, popd_out,
				backend->in, backend->out, 0));

 done:
    /* ok, we're done. */
    protgroup_free(protin);

    if (shutdown) {
	char *p;
	for (p = buf; *p == '['; p++); /* can't have [ be first char */
	prot_printf(popd_out, "-ERR [SYS/TEMP] %s\r\n", p);
	shut_down(0);
    }

    return;
}

/* Merge our read messages with the existing \Seen database */
static int update_seen(void)
{
    unsigned i;
    struct index_record record;
    int r = 0;

    if (!config_popuseimapflags)
	return 0;

    if (config_popuseacl && !(popd_myrights & ACL_SETSEEN))
	return 0;

    /* we know this mailbox must be owned by the user, because 
     * all POP mailboxes are */
    for (i = 0; i < popd_exists; i++) {
	if (!popd_msg[i].seen)
	    continue; /* don't even need to check */
	if (mailbox_read_index_record(popd_mailbox, popd_msg[i].recno, &record))
	    continue;
	if (record.system_flags & FLAG_EXPUNGED)
	    continue; /* already expunged */
	if (record.system_flags & FLAG_SEEN)
	    continue; /* already seen */
	record.system_flags |= FLAG_SEEN;
	r = mailbox_rewrite_index_record(popd_mailbox, &record);
	if (r) break;
    }

    return r;
}
