/* pop3proxyd.c -- POP3 server protocol parsing (proxy)
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
 * $Id: pop3proxyd.c,v 1.35 2002/02/27 03:47:15 rjs3 Exp $
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
#include "imapconf.h"
#include "tls.h"

#include "iptostring.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "version.h"
#include "xmalloc.h"
#include "mboxlist.h"

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

extern int errno;



#ifdef HAVE_SSL
static SSL *tls_conn;
#endif /* HAVE_SSL */

sasl_conn_t *popd_saslconn; /* the sasl connection context */

char *popd_userid = 0;
struct sockaddr_in popd_localaddr, popd_remoteaddr;
int popd_haveaddr = 0;
char popd_clienthost[250] = "[local]";
struct protstream *popd_out, *popd_in;
int popd_starttls_done = 0;
int popd_auth_done = 0;

struct protstream *backend_out, *backend_in;
int backend_sock;
sasl_conn_t *backend_saslconn;

/* current namespace */
static struct namespace popd_namespace;

static void cmd_apop(char *response);
static int apop_enabled(void);
static char popd_apop_chal[45 + MAXHOSTNAMELEN + 1]; /* <rand.time@hostname> */

static void cmd_auth();
static void cmd_capa();
static void cmd_pass();
static void cmd_user();
static void cmd_starttls(int pop3s);
static void cmdloop(void);
static void kpop(void);
static void usage(void);
static void openproxy(void);
static void bitpipe(void);

extern void setproctitle_init(int argc, char **argv, char **envp);
extern int proc_register(const char *progname, const char *clienthost, 
			 const char *userid, const char *mailbox);
extern void proc_cleanup(void);
void shut_down(int code) __attribute__ ((noreturn));

/* Enable the resetting of a sasl_conn_t */
static int reset_saslconn(sasl_conn_t **conn);

static struct 
{
    char *ipremoteport;
    char *iplocalport;
    sasl_ssf_t ssf;
    char *authid;
} saslprops = {NULL,NULL,0,NULL};

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc, char **argv, char **envp)
{
    int r;

    config_changeident("pop3d");
    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);
    setproctitle_init(argc, argv, envp);

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signals_add_handlers();
    signal(SIGPIPE, SIG_IGN);

    /* set the SASL allocation functions */
    sasl_set_alloc((sasl_malloc_t *) &xmalloc, 
		   (sasl_calloc_t *) &calloc, 
		   (sasl_realloc_t *) &xrealloc, 
		   (sasl_free_t *) &free);

    /* load the SASL plugins */
    if ((r = sasl_server_init(mysasl_cb, "Cyrus")) != SASL_OK) {
	syslog(LOG_ERR, "SASL failed initializing: sasl_server_init(): %s", 
	       sasl_errstring(r, NULL, NULL));
	return 2;
    }

    /* open the mboxlist, we'll need it for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);

    /* Set namespace */
    if ((r = mboxname_init_namespace(&popd_namespace, 0)) != 0) {
	syslog(LOG_ERR, error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    return 0;
}

/*
 * run for each accepted connection
 */
int service_main(int argc, char **argv, char **envp)
{
    int pop3s = 0;
    int opt;
    socklen_t salen;
    struct hostent *hp;
    char localip[60], remoteip[60];
    int timeout;
    sasl_security_properties_t *secprops=NULL;

    signals_poll();

    popd_in = prot_new(0, 0);
    popd_out = prot_new(1, 1);

    while ((opt = getopt(argc, argv, "C:sk")) != EOF) {
	switch(opt) {
	case 'C': /* alt config file - handled by service::main() */
	    break;

	case 's': /* pop3s (do starttls right away) */
	    pop3s = 1;
	    if (!tls_enabled("pop3")) {
		syslog(LOG_ERR, "pop3s: required OpenSSL options not present");
		fatal("pop3s: required OpenSSL options not present",
		      EC_CONFIG);
	    }
	case 'k':
	    kflag++;
	    break;
	default:
	    usage();
	}
    }

    /* Find out name of client host */
    salen = sizeof(popd_remoteaddr);
    if (getpeername(0, (struct sockaddr *)&popd_remoteaddr, &salen) == 0 &&
	popd_remoteaddr.sin_family == AF_INET) {
	hp = gethostbyaddr((char *)&popd_remoteaddr.sin_addr,
			   sizeof(popd_remoteaddr.sin_addr), AF_INET);
	if (hp != NULL) {
	    strncpy(popd_clienthost, hp->h_name, sizeof(popd_clienthost)-30);
	    popd_clienthost[sizeof(popd_clienthost)-30] = '\0';
	} else {
	    popd_clienthost[0] = '\0';
	}
	strcat(popd_clienthost, "[");
	strcat(popd_clienthost, inet_ntoa(popd_remoteaddr.sin_addr));
	strcat(popd_clienthost, "]");
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
    secprops = mysasl_secprops(SASL_SEC_NOPLAINTEXT);
    sasl_setprop(popd_saslconn, SASL_SEC_PROPS, secprops);
    
    if(iptostring((struct sockaddr *)&popd_localaddr,
		  sizeof(struct sockaddr_in), localip, 60) == 0) {
	sasl_setprop(popd_saslconn, SASL_IPLOCALPORT, localip);
	saslprops.iplocalport = xstrdup(localip);
    }
    if(iptostring((struct sockaddr *)&popd_remoteaddr,
		  sizeof(struct sockaddr_in), remoteip, 60) == 0) {
	sasl_setprop(popd_saslconn, SASL_IPREMOTEPORT, remoteip);  
	saslprops.ipremoteport = xstrdup(remoteip);
    }

    proc_register("pop3d", popd_clienthost, NULL, NULL);

    /* Set inactivity timer */
    timeout = config_getint("poptimeout", 10);
    if (timeout < 10) timeout = 10;
    prot_settimeout(popd_in, timeout*60);
    prot_setflushonread(popd_in, popd_out);

    if (kflag) kpop();

    /* we were connected on pop3s port so we should do 
       TLS negotiation immediatly */
    if (pop3s == 1) cmd_starttls(1);

    /* Create APOP challenge for banner */
    if (!sasl_mkchal(popd_saslconn, popd_apop_chal, sizeof(popd_apop_chal), 1)) {
	syslog(LOG_ERR, "APOP disabled: can't create challenge");
	*popd_apop_chal = 0;
    }

    prot_printf(popd_out, "+OK %s Cyrus POP3 Murder %s server ready %s\r\n",
		config_servername, CYRUS_VERSION,
		apop_enabled() ? popd_apop_chal : "");
    cmdloop();
    
    /* xxx no process reuse for you */
    shut_down(0);
    /* return 0; */
}

/* called if 'service_init()' was called but not 'service_main()' */
void service_abort(int error)
{
    shut_down(error);
}

void usage(void)
{
    prot_printf(popd_out,
		"-ERR usage: pop3proxyd [-C <alt_config>]"
		" [-k] [-s]\r\n");
    prot_flush(popd_out);
    exit(EC_USAGE);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code)
{
    proc_cleanup();
    mboxlist_close();
    mboxlist_done();
#ifdef HAVE_SSL
    tls_shutdown_serverengine();
#endif
    prot_flush(popd_out);
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
    prot_printf(popd_out, "-ERR [SYS/PERM] Fatal error: %s\r\n", s);
    prot_flush(popd_out);
    shut_down(code);
}

/*
 * Found a shutdown file: Spit out an untagged BYE and shut down
 */
void shutdown_file(void)
{
    int fd;
    struct protstream *shutdown_in;
    char buf[1024];
    char *p;
    static char shutdownfilename[1024];
    
    if (!shutdownfilename[0])
	sprintf(shutdownfilename, "%s/msg/shutdown", config_dir);
    if ((fd = open(shutdownfilename, O_RDONLY, 0)) == -1) return;

    shutdown_in = prot_new(fd, 0);
    prot_fgets(buf, sizeof(buf), shutdown_in);
    if ((p = strchr(buf, '\r')) != NULL) *p = 0;
    if ((p = strchr(buf, '\n')) != NULL) *p = 0;

    for (p = buf; *p == '['; p++); /* can't have [ be first char, sigh */
    prot_printf(popd_out, "-ERR [SYS/TEMP] %s\r\n", p);

    shut_down(0);
}

#ifdef HAVE_KRB
/*
 * MIT's kludge of a kpop protocol
 * Client does a krb_sendauth() first thing
 */
static void kpop(void)
{
    Key_schedule schedule;
    KTEXT_ST ticket;
    char instance[INST_SZ];  
    char version[9];
    const char *srvtab;
    int r;

    if (!popd_haveaddr) {
	fatal("Cannot get client's IP address", EC_OSERR);
    }

    srvtab = config_getstring("srvtab", "");

    strcpy(instance, "*");
    r = krb_recvauth(0L, 0, &ticket, "pop", instance,
		     &popd_remoteaddr, (struct sockaddr_in *) NULL,
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
static void kpop(void)
{
    usage();
}
#endif

/*
 * Top-level command loop parsing
 */
static void cmdloop(void)
{
    char inputbuf[8192];
    char *p, *arg;

    for (;;) {
	signals_poll();

	if (popd_auth_done) {
	    bitpipe();
	    return;
	}

	/* check for shutdown file */
	shutdown_file();

	if (!prot_fgets(inputbuf, sizeof(inputbuf), popd_in)) {
	    return;
	}

	p = inputbuf + strlen(inputbuf);
	if (p > inputbuf && p[-1] == '\n') *--p = '\0';
	if (p > inputbuf && p[-1] == '\r') *--p = '\0';

	/* Parse into keword and argument */
	for (p = inputbuf; *p && !isspace((int) *p); p++);
	if (*p) {
	    *p++ = '\0';
	    arg = p;
	    if (strcasecmp(inputbuf, "pass") != 0) {
		while (*arg && isspace((int) *arg)) {
		    arg++;
		}
	    }
	    if (!*arg) {
		prot_printf(popd_out, "-ERR Syntax error\r\n");
		continue;
	    }
	}
	else {
	    arg = 0;
	}
	lcase(inputbuf);

	if (!strcmp(inputbuf, "quit")) {
	    if (!arg) {
		prot_printf(popd_out, "+OK\r\n");
		shut_down(0);
	    }
	    else prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	}
	else if (!strcmp(inputbuf, "capa")) {
	    if (arg) {
		prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	    } else {
		cmd_capa();
	    }
	}
	else if (!strcmp(inputbuf, "user")) {
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
	else if (!strcmp(inputbuf, "apop") && apop_enabled()) {
	    if (!arg) prot_printf(popd_out, "-ERR Missing argument\r\n");
	    else cmd_apop(arg);
	}
	else if (!strcmp(inputbuf, "auth")) {
	    cmd_auth(arg);
	}
	else if (!strcmp(inputbuf, "stls") && tls_enabled("pop3")) {
	    if (arg) {
		prot_printf(popd_out,
			    "-ERR STLS doesn't take any arguements\r\n");
	    } else {
		cmd_starttls(0);
	    }
	}
	else {
	    prot_printf(popd_out, "-ERR Unrecognized command\r\n");
	}
    }		
}

#ifdef HAVE_SSL
static void cmd_starttls(int pop3s)
{
    char *tls_cert, *tls_key;
    int result;
    int *layerp;
    char *auth_id;
    sasl_ssf_t ssf;

    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &ssf;

    if (popd_starttls_done == 1)
    {
	prot_printf(popd_out, "-ERR %s\r\n", 
		    "Already successfully executed STLS");
	return;
    }

    tls_cert = (char *)config_getstring("tls_pop3_cert_file",
					config_getstring("tls_cert_file", ""));
    tls_key = (char *)config_getstring("tls_pop3_key_file",
				       config_getstring("tls_key_file", ""));

    result=tls_init_serverengine("pop3",
				 5,        /* depth to verify */
				 !pop3s,   /* can client auth? */
				 0,        /* require client to auth? */
				 !pop3s);  /* TLSv1 only? */

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
static void cmd_starttls(int pop3s)
{
    fatal("cmd_starttls() called, but no OpenSSL", EC_SOFTWARE);
}
#endif /* HAVE_SSL */

static int apop_enabled(void)
{
    /* Check if pseudo APOP mechanism is enabled (challenge == NULL) */
    if (sasl_checkapop(popd_saslconn, NULL, 0, NULL, 0) != SASL_OK) return 0;
    /* Check if we have a challenge string */
    if (!*popd_apop_chal) return 0;
    return 1;
}

static void cmd_apop(char *response)
{
    int fd;
    struct protstream *shutdown_in;
    char buf[1024];
    char *p;
    char shutdownfilename[1024];
    int sasl_result;
    char *canon_user;

    assert(response != NULL);

    if (popd_userid) {
	prot_printf(popd_out, "-ERR [AUTH] Must give PASS command\r\n");
	return;
    }

    /* Check if it is enabled (challenge == NULL) */
    if(sasl_checkapop(popd_saslconn, NULL, 0, NULL, 0) != SASL_OK)
	fatal("cmd_apop called without working sasl_checkapop", EC_SOFTWARE);

    sprintf(shutdownfilename, "%s/msg/shutdown", config_dir);
    if ((fd = open(shutdownfilename, O_RDONLY, 0)) != -1) {
	shutdown_in = prot_new(fd, 0);
	prot_fgets(buf, sizeof(buf), shutdown_in);
	if ((p = strchr(buf, '\r'))!=NULL) *p = 0;
	if ((p = strchr(buf, '\n'))!=NULL) *p = 0;

	for(p = buf; *p == '['; p++); /* can't have [ be first char */
	prot_printf(popd_out, "-ERR [SYS/TEMP] %s\r\n", p);
	prot_flush(popd_out);
	shut_down(0);
    }

    sasl_result = sasl_checkapop(popd_saslconn,
				 popd_apop_chal,
				 strlen(popd_apop_chal),
				 response,
				 strlen(response));
    
    /* failed authentication */
    if (sasl_result != SASL_OK)
    {
	sleep(3);      
		
	prot_printf(popd_out, "-ERR [AUTH] authenticating: %s\r\n",
		    sasl_errstring(sasl_result, NULL, NULL));

	syslog(LOG_NOTICE, "badlogin: %s APOP (%s) %s",
	       popd_clienthost, popd_apop_chal,
	       sasl_errdetail(popd_saslconn));
	
	return;
    }

    /* successful authentication */

    /*
     * get the userid from SASL --- already canonicalized from
     * mysasl_authproc()
     */
    sasl_result = sasl_getprop(popd_saslconn, SASL_USERNAME,
			       (const void **) &canon_user);
    popd_userid = xstrdup(canon_user);
    if (sasl_result != SASL_OK) {
	prot_printf(popd_out, 
		    "-ERR [AUTH] weird SASL error %d getting SASL_USERNAME\r\n", 
		    sasl_result);
	return;
    }
    
    syslog(LOG_NOTICE, "login: %s %s APOP %s",
	   popd_clienthost, popd_userid, "User logged in");

    openproxy();
    popd_auth_done = 1;
}

void
cmd_user(user)
char *user;
{
    char *p;

    /* possibly disallow USER */
    if (!(kflag || popd_starttls_done ||
	  config_getswitch("allowplaintext", 1))) {
	prot_printf(popd_out,
		    "-ERR [AUTH] USER command only available under a layer\r\n");
	return;
    }

    if (popd_userid) {
	prot_printf(popd_out, "-ERR [AUTH] Must give PASS command\r\n");
	return;
    }

    shutdown_file(); /* check for shutdown file */
    if (!(p = auth_canonifyid(user,0)) ||
	/* '.' isn't allowed if '.' is the hierarchy separator */
	(popd_namespace.hier_sep == '.' && strchr(p, '.')) ||
	strlen(p) + 6 > MAX_MAILBOX_PATH) {

	prot_printf(popd_out, "-ERR [AUTH] Invalid user\r\n");
	syslog(LOG_NOTICE,
	       "badlogin: %s plaintext %s invalid user",
	       popd_clienthost, beautify_string(user));
    }
    else {
	popd_userid = xstrdup(p);
	prot_printf(popd_out, "+OK Name is a valid mailbox\r\n");
    }
}

void cmd_pass(char *pass)
{
    char *reply = 0;
    int plaintextloginpause;

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

	openproxy();
	syslog(LOG_NOTICE, "login: %s %s kpop", popd_clienthost, popd_userid);
	popd_auth_done = 1;
	return;
    }
#endif

    if (!strcmp(popd_userid, "anonymous")) {
	if (config_getswitch("allowanonymouslogin", 0)) {
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
	if (reply) {
	    syslog(LOG_NOTICE, "badlogin: %s plaintext %s %s",
		   popd_clienthost, popd_userid, reply);
	}
	sleep(3);
	prot_printf(popd_out, "-ERR [AUTH] Invalid login\r\n");
	free(popd_userid);
	popd_userid = 0;

	return;
    }
    else {
	syslog(LOG_NOTICE, "login: %s %s plaintext %s",
	       popd_clienthost, popd_userid, reply ? reply : "");
	plaintextloginpause = config_getint("plaintextloginpause", 0);
	if (plaintextloginpause) sleep(plaintextloginpause);
    }

    openproxy();
    popd_auth_done = 1;
}

/* Handle the POP3 Extension extension.
 */
void
cmd_capa()
{
    int minpoll = config_getint("popminpoll", 0) * 60;
    int expire = config_getint("popexpiretime", -1);
    unsigned mechcount;
    const char *mechlist;

    prot_printf(popd_out, "+OK List of capabilities follows\r\n");

    /* SASL special case: print SASL, then a list of supported capabilities */
    if (sasl_listmech(popd_saslconn,
		      NULL, /* should be id string */
		      "SASL ", " ", "\r\n",
		      &mechlist,
		      NULL, &mechcount) == SASL_OK && mechcount > 0) {
	prot_write(popd_out, mechlist, strlen(mechlist));
    }

    if (tls_enabled("pop3")) {
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

    if (kflag || popd_starttls_done || config_getswitch("allowplaintext", 1)) {
	prot_printf(popd_out, "USER\r\n");
    }
    
    prot_printf(popd_out,
		"IMPLEMENTATION Cyrus POP3 proxy server %s\r\n",
		CYRUS_VERSION);

    prot_printf(popd_out, ".\r\n");
    prot_flush(popd_out);
}


/* according to RFC 2449, since we advertise the "SASL" capability, we
 * must accept an optional second argument of the initial client
 * response (base64 encoded!).
 */ 
void cmd_auth(char *arg)
{
    int sasl_result;
    static struct buf clientin;
    unsigned clientinlen=0;
    char *authtype;
    const char *serverout;
    unsigned int serveroutlen;
    char *cin;

    /* if client didn't specify an argument we give them the list */
    if (!arg) {
	const char *sasllist;
	unsigned int mechnum;

	prot_printf(popd_out, "+OK List of supported mechanisms follows\r\n");
      
	/* CRLF seperated, dot terminated */
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
    while (*arg && !isspace((int) *arg)) {
	arg++;
    }
    if (isspace((int) *arg)) {
	/* null terminate authtype, get argument */
	*arg++ = '\0';
    } else {
	/* no optional client response */
	arg = NULL;
    }

    /* if arg != NULL, it's an initial client response */
    if (arg) {
	int arglen = strlen(arg);

	clientin.alloc = arglen + 1;
	cin = clientin.s = xmalloc(clientin.alloc);
	sasl_result = sasl_decode64(arg, arglen, clientin.s,
				    clientin.alloc, &clientinlen);
    } else {
	sasl_result = SASL_OK;
	cin = NULL;
	clientinlen = 0;
    }

    /* server did specify a command, so let's try to authenticate */
    if (sasl_result == SASL_OK || sasl_result == SASL_CONTINUE)
	sasl_result = sasl_server_start(popd_saslconn, authtype,
					cin, clientinlen,
					&serverout, &serveroutlen);
    /* sasl_server_start will return SASL_OK or SASL_CONTINUE on success */
    while (sasl_result == SASL_CONTINUE)
    {
	char c;
	
	/* print the message to the user */
	printauthready(popd_out, serveroutlen, (unsigned char *)serverout);

        c = prot_getc(popd_in);
        if(c == '*') {
            eatline(popd_in,c);
            prot_printf(popd_out,
                        "-ERR [AUTH] Client canceled authentication\r\n");
            reset_saslconn(&popd_saslconn);
            return;
        } else {
            prot_ungetc(c, popd_in);
        }

	/* get string from user */
	clientinlen = getbase64string(popd_in, &clientin);
	if (clientinlen == -1) {
	    prot_printf(popd_out, "-ERR [AUTH] Invalid base64 string\r\n");
	    return;
	}

	sasl_result = sasl_server_step(popd_saslconn,
				       clientin.s,
				       clientinlen,
				       &serverout, &serveroutlen);
    }

    /* failed authentication */
    if (sasl_result != SASL_OK)
    {
	sleep(3);      

	reset_saslconn(&popd_saslconn);
	
	/* convert the sasl error code to a string */
	prot_printf(popd_out, "-ERR [AUTH] authenticating: %s\r\n",
		    sasl_errstring(sasl_result, NULL, NULL));

	if (authtype) {
	    syslog(LOG_NOTICE, "badlogin: %s %s %s",
		   popd_clienthost, authtype, sasl_errdetail(popd_saslconn));
	} else {
	    syslog(LOG_NOTICE, "badlogin: %s %s",
		   popd_clienthost, sasl_errdetail(popd_saslconn));
	}
	
	return;
    }

    /* successful authentication */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_authproc()
     */
    /* FIXME XXX: popd_userid is NOT CONST */
    sasl_result = sasl_getprop(popd_saslconn, SASL_USERNAME,
			       (const void **) &popd_userid);
    if (sasl_result != SASL_OK) {
	prot_printf(popd_out, 
		    "-ERR [AUTH] weird SASL error %d getting SASL_USERNAME\r\n", 
		    sasl_result);
	return;
    }
    
    proc_register("pop3d", popd_clienthost, popd_userid, NULL);
    syslog(LOG_NOTICE, "login: %s %s %s %s", popd_clienthost, popd_userid,
	   authtype, "User logged in");
    
    openproxy();

    prot_setsasl(popd_in,  popd_saslconn);
    prot_setsasl(popd_out, popd_saslconn);

    popd_auth_done = 1;
}

static int mysasl_getauthline(struct protstream *p, char **line, 
			      unsigned int *linelen)
{
    char buf[2096];
    char *str = (char *) buf;
    
    if (!prot_fgets(str, sizeof(buf), p)) {
	return SASL_FAIL;
    }
    if (!strncasecmp(str, "+OK", 3)) { return SASL_OK; }
    if (!strncasecmp(str, "-ERR", 4)) { return SASL_BADAUTH; }
    if (str[0] == '+' && str[1] == ' ') {
	size_t len;
	str += 2; /* jump past the "+ " */

	len = strlen(str) + 1;

	*line = xmalloc(strlen(str) + 1);
	if (*str != '\r') {	/* decode it */
	    int r;
	    
	    r = sasl_decode64(str, strlen(str), *line, len, linelen);
	    if (r != SASL_OK) {
		return r;
	    }
	    
	    return SASL_CONTINUE;
	} else {		/* blank challenge */
	    *line = NULL;
	    *linelen = 0;

	    return SASL_CONTINUE;
	}
    } else {
	/* huh??? */
	return SASL_FAIL;
    }
}

extern sasl_callback_t *mysasl_callbacks(const char *username,
					 const char *authname,
					 const char *realm,
					 const char *password);
extern void free_callbacks(sasl_callback_t *in);

static int proxy_authenticate(const char *hostname)
{
    int r;
    sasl_security_properties_t *secprops = NULL;
    struct sockaddr_in saddr_l;
    struct sockaddr_in saddr_r;
    socklen_t addrsize;
    sasl_callback_t *cb;
    char buf[2048];
    char optstr[128];
    char *in, *p;
    const char *out;
    unsigned int inlen, outlen;
    const char *mechusing;
    unsigned b64len;
    char localip[60], remoteip[60];
    const char *pass;

    strcpy(optstr, hostname);
    p = strchr(optstr, '.');
    if (p) *p = '\0';
    strcat(optstr, "_password");
    pass = config_getstring(optstr, NULL);
    cb = mysasl_callbacks(popd_userid, 
			  config_getstring("proxy_authname", "proxy"),
			  config_getstring("proxy_realm", NULL),
			  pass);

    r = sasl_client_new("pop", hostname, NULL, NULL,
			cb, 0, &backend_saslconn);
    if (r != SASL_OK) {
	return r;
    }

    secprops = mysasl_secprops(0);
    r = sasl_setprop(backend_saslconn, SASL_SEC_PROPS, secprops);
    if (r != SASL_OK) {
	return r;
    }

    /* set the IP addresses */
    addrsize=sizeof(struct sockaddr_in);
    if (getpeername(backend_sock, (struct sockaddr *)&saddr_r, &addrsize) != 0)
	return SASL_FAIL;
    addrsize=sizeof(struct sockaddr_in);
    if (getsockname(backend_sock, (struct sockaddr *)&saddr_l,&addrsize)!=0)
	return SASL_FAIL;

    if (iptostring((struct sockaddr *)&saddr_r,
		   sizeof(struct sockaddr_in), remoteip, 60) != 0)
	return SASL_FAIL;
    if (iptostring((struct sockaddr *)&saddr_l,
		   sizeof(struct sockaddr_in), localip, 60) != 0)
	return SASL_FAIL;

    r = sasl_setprop(backend_saslconn, SASL_IPLOCALPORT, localip);
    if (r != SASL_OK) return r;
    r = sasl_setprop(backend_saslconn, SASL_IPREMOTEPORT, remoteip);
    if (r != SASL_OK) return r;

    /* read the initial greeting */
    if (!prot_fgets(buf, sizeof(buf), backend_in)) {
	return SASL_FAIL;
    }

    strcpy(buf, hostname);
    p = strchr(buf, '.');
    *p = '\0';
    strcat(buf, "_mechs");

    /* we now do the actual SASL exchange */
    r = sasl_client_start(backend_saslconn, 
			  config_getstring(buf, "KERBEROS_V4"),
			  NULL, &out, &outlen, &mechusing);
    if ((r != SASL_OK) && (r != SASL_CONTINUE)) {
	return r;
    }
    if (out == NULL || outlen == 0) {
	prot_printf(backend_out, "AUTH %s\r\n", mechusing);
    } else {
	/* send initial challenge */
	r = sasl_encode64(out, outlen, buf, sizeof(buf), &b64len);
	if (r != SASL_OK)
	    return r;
	prot_printf(backend_out, "AUTH %s %s\r\n", mechusing, buf);
    }

    in = NULL;
    inlen = 0;
    r = mysasl_getauthline(backend_in, &in, &inlen);
    while (r == SASL_CONTINUE) {
	r = sasl_client_step(backend_saslconn, in, inlen, NULL, &out, &outlen);
	if (in) { 
	    free(in);
	}
	if (r != SASL_OK && r != SASL_CONTINUE) {
	    return r;
	}

	r = sasl_encode64(out, outlen, buf, sizeof(buf), &b64len);
	if (r != SASL_OK) {
	    return r;
	}

	prot_write(backend_out, buf, b64len);
	prot_printf(backend_out, "\r\n");

	r = mysasl_getauthline(backend_in, &in, &inlen);
    }

    /* Done with callbacks */
    free_callbacks(cb);

    if (r == SASL_OK) {
	prot_setsasl(backend_in, backend_saslconn);
	prot_setsasl(backend_out, backend_saslconn);
    }

    /* r == SASL_OK on success */
    return r;
}

static void openproxy(void)
{
    struct hostent *hp;
    struct sockaddr_in sin;
    char inboxname[MAX_MAILBOX_PATH];
    int r;
    char *server = NULL;

    /* have to figure out what server to connect to */
    strcpy(inboxname, "user.");
    strcat(inboxname, popd_userid);

    /* Translate any separators in userid part of inboxname
       (we need the original userid for AUTH to backend) */
    mboxname_hiersep_tointernal(&popd_namespace, inboxname+5);

    r = mboxlist_lookup(inboxname, &server, NULL, NULL);
    if (r) fatal("couldn't find backend server", EC_CONFIG);

    /* xxx hide the fact that we are storing partitions */
    if(server) {
	char *c;
	c = strchr(server, '!');
	if(c) *c = '\0';
    }

    hp = gethostbyname(server);
    if (!hp) fatal("gethostbyname failed", EC_CONFIG);
    sin.sin_family = AF_INET;
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_port = htons(110);
    
    if ((backend_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	syslog(LOG_ERR, "socket() failed: %m");
	fatal("socket failed", EC_CONFIG);
    }
    if (connect(backend_sock, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
	syslog(LOG_ERR, "connect() failed: %m");
	fatal("connect failed", 1);
    }
    
    backend_in = prot_new(backend_sock, 0);
    backend_out = prot_new(backend_sock, 1);
    prot_setflushonread(backend_in, backend_out);

    if (proxy_authenticate(server) != SASL_OK) {
	syslog(LOG_ERR, "couldn't authenticate to backend server");
	fatal("couldn't authenticate to backend server", 1);
    }

    prot_printf(popd_out, "+OK Maildrop locked and ready\r\n");
    prot_flush(popd_out);
    return;
}

/* we've authenticated the client, we've connected to the backend.
   now it's all up to them */
static void bitpipe(void)
{
    fd_set read_set, rset;
    int nfds, r;
    char buf[4096];
    
    FD_ZERO(&read_set);
    FD_SET(0, &read_set);  
    FD_SET(backend_sock, &read_set);
    nfds = backend_sock + 1;
    
    for (;;) {
	rset = read_set;
	r = select(nfds, &rset, NULL, NULL, NULL);
	/* if select() failed it's not worth trying to figure anything out */
	if (r < 0) goto done;

	if (FD_ISSET(0, &rset)) {
	    do {
		int c = prot_read(popd_in, buf, sizeof(buf));
		if (c == 0 || c < 0) goto done;
		prot_write(backend_out, buf, c);
	    } while (popd_in->cnt > 0);
	    prot_flush(backend_out);
	}

	if (FD_ISSET(backend_sock, &rset)) {
	    do {
		int c = prot_read(backend_in, buf, sizeof(buf));
		if (c == 0 || c < 0) goto done;
		prot_write(popd_out, buf, c);
	    } while (backend_in->cnt > 0);
	    prot_flush(popd_out);
	}
    }
 done:
    /* ok, we're done. close backend connection */
    prot_free(backend_in);
    prot_free(backend_out);
    close(backend_sock);

    /* close the connection to the client */
    close(0);
    close(1);
    prot_free(popd_in);
    prot_free(popd_out);

    return;
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
    secprops = mysasl_secprops(SASL_SEC_NOPLAINTEXT);
    ret = sasl_setprop(*conn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    /* If we have TLS/SSL info, set it */
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
