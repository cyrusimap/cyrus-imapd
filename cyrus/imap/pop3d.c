/* pop3d.c -- POP3 server protocol parsing
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
 * $Id: pop3d.c,v 1.78 2000/11/30 15:55:44 ken3 Exp $
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
#include <sys/types.h>
#include <sys/param.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "prot.h"

#include <sasl.h>
#include <saslutil.h>

#include "acl.h"
#include "util.h"
#include "auth.h"
#include "imapconf.h"
#include "tls.h"


#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "version.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "imapidle.h"

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
extern SSL *tls_conn;
#endif /* HAVE_SSL */

sasl_conn_t *popd_saslconn; /* the sasl connection context */

char *popd_userid = 0;
struct mailbox *popd_mailbox = 0;
struct sockaddr_in popd_localaddr, popd_remoteaddr;
int popd_haveaddr = 0;
char popd_clienthost[250] = "[local]";
struct protstream *popd_out, *popd_in;
unsigned popd_exists = 0;
unsigned popd_highest;
unsigned popd_login_time;
struct msg {
    unsigned uid;
    unsigned size;
    int deleted;
} *popd_msg;

int popd_starttls_done = 0;

static struct mailbox mboxstruct;

static int expungedeleted();

static void cmd_auth();
static void cmd_capa();
static void cmd_pass();
static void cmd_user();
static void cmd_starttls(int pop3s);
static int starttls_enabled(void);
void eatline(void);
static void blat(int msg,int lines);
int openinbox(void);
static void cmdloop(void);
void kpop(void);
static int parsenum(char **ptr);
void usage(void);
void shut_down(int code) __attribute__ ((noreturn));


extern void setproctitle_init(int argc, char **argv, char **envp);
extern int proc_register(char *progname, char *clienthost, 
			 char *userid, char *mailbox);
extern void proc_cleanup(void);

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

    /* set the mailbox update notifier for IMAP IDLE */
    mailbox_set_updatenotifier(imap_idlenotify);

    return 0;
}

/*
 * run for each accepted connection
 */
int service_main(int argc, char **argv, char **envp)
{
    int pop3s = 0;
    int opt;
    int salen;
    struct hostent *hp;
    int timeout;
    sasl_security_properties_t *secprops=NULL;

    signals_poll();

    popd_in = prot_new(0, 0);
    popd_out = prot_new(1, 1);

    while ((opt = getopt(argc, argv, "sk")) != EOF) {
	switch(opt) {
	case 's': /* pop3s (do starttls right away) */
	    pop3s = 1;
	    if (!starttls_enabled()) {
		syslog(LOG_ERR, "pop3s: required OpenSSL options not present");
		fatal("pop3s: required OpenSSL options not present",
		      EC_CONFIG);
	    }
	    break;

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
    if (sasl_server_new("pop", config_servername, NULL, 
			NULL, SASL_SECURITY_LAYER, &popd_saslconn) != SASL_OK)
	fatal("SASL failed initializing: sasl_server_new()",EC_TEMPFAIL); 

    /* will always return something valid */
    secprops = mysasl_secprops(SASL_SEC_NOPLAINTEXT);
    sasl_setprop(popd_saslconn, SASL_SEC_PROPS, secprops);
    
    sasl_setprop(popd_saslconn, SASL_IP_REMOTE, &popd_remoteaddr);  
    sasl_setprop(popd_saslconn, SASL_IP_LOCAL, &popd_localaddr);  

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

    prot_printf(popd_out, "+OK %s Cyrus POP3 %s server ready\r\n",
		config_servername, CYRUS_VERSION);
    cmdloop();

    return 0;
}

/* called if 'service_init()' was called but not 'service_main()' */
void service_abort(int error)
{
    mboxlist_close();
    mboxlist_done();
}

void usage(void)
{
    prot_printf(popd_out, "-ERR usage: pop3d [-k] [-s]\r\n");
    prot_flush(popd_out);
    exit(EC_USAGE);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code)
{
    proc_cleanup();
    if (popd_mailbox) {
	mailbox_close(popd_mailbox);
    }
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
    prot_printf(popd_out, "-ERR Fatal error: %s\r\n", s);
    prot_flush(popd_out);
    shut_down(code);
}

#ifdef HAVE_KRB
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

    if (!popd_haveaddr) {
	fatal("Cannot get client's IP address", EC_OSERR);
    }

    srvtab = config_getstring("srvtab", "");

    strcpy(instance, "*");
    r = krb_recvauth(0L, 0, &ticket, "pop", instance,
		     &popd_remoteaddr, (struct sockaddr_in *) NULL,
		     &kdata, (char*) srvtab, schedule, version);
    
    if (r) {
	prot_printf(popd_out, "-ERR Kerberos authentication failure: %s\r\n",
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
	prot_printf(popd_out, "-ERR Kerberos failure: %s\r\n",
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

/*
 * Top-level command loop parsing
 */
static void cmdloop(void)
{
    char inputbuf[8192];
    char *p, *arg;
    unsigned msg = 0;

    for (;;) {
	signals_poll();

	if (!prot_fgets(inputbuf, sizeof(inputbuf), popd_in)) {
	    shut_down(0);
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
		if (popd_mailbox) {
		    if (!mailbox_lock_index(popd_mailbox)) {
			popd_mailbox->pop3_last_login = popd_login_time;
			mailbox_write_index_header(popd_mailbox);
			mailbox_unlock_index(popd_mailbox);
		    }

		    for (msg = 1; msg <= popd_exists; msg++) {
			if (popd_msg[msg].deleted) break;
		    }

		    if (msg <= popd_exists) {
			(void) mailbox_expunge(popd_mailbox, 1, expungedeleted, 0);
		    }
		}
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
	else if (!strcmp(inputbuf, "stls") && starttls_enabled()) {
	    if (arg) {
		prot_printf(popd_out,
			    "-ERR STLS doesn't take any arguements\r\n");
	    } else {
		cmd_starttls(0);
	    }
	}
	else if (!popd_mailbox) {
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
	    else if (!strcmp(inputbuf, "auth")) {
		cmd_auth(arg);
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
		for (msg = 1; msg <= popd_exists; msg++) {
		    if (!popd_msg[msg].deleted) {
			nmsgs++;
			totsize += popd_msg[msg].size;
		    }
		}
		prot_printf(popd_out, "+OK %u %u\r\n", nmsgs, totsize);
	    }
	}
	else if (!strcmp(inputbuf, "list")) {
	    if (arg) {
		msg = parsenum(&arg);
		if (arg) {
		    prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    prot_printf(popd_out, "-ERR No such message\r\n");
		}
		else {
		    prot_printf(popd_out, "+OK %u %u\r\n", msg, popd_msg[msg].size);
		}
	    }
	    else {
		prot_printf(popd_out, "+OK scan listing follows\r\n");
		for (msg = 1; msg <= popd_exists; msg++) {
		    if (!popd_msg[msg].deleted) {
			prot_printf(popd_out, "%u %u\r\n", msg, popd_msg[msg].size);
		    }
		}
		prot_printf(popd_out, ".\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "retr")) {
	    if (!arg) prot_printf(popd_out, "-ERR Missing argument\r\n");
	    else {
		msg = parsenum(&arg);
		if (arg) {
		    prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    prot_printf(popd_out, "-ERR No such message\r\n");
		}
		else {
		    if (msg > popd_highest) popd_highest = msg;
		    blat(msg, -1);
		}
	    }
	}
	else if (!strcmp(inputbuf, "dele")) {
	    if (!arg) prot_printf(popd_out, "-ERR Missing argument\r\n");
	    else {
		msg = parsenum(&arg);
		if (arg) {
		    prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    prot_printf(popd_out, "-ERR No such message\r\n");
		}
		else {
		    popd_msg[msg].deleted = 1;
		    if (msg > popd_highest) popd_highest = msg;
		    prot_printf(popd_out, "+OK message deleted\r\n");
		}
	    }
	}
	else if (!strcmp(inputbuf, "noop")) {
	    if (arg) {
		prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	    }
	    else {
		prot_printf(popd_out, "+OK\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "last")) {
	    if (arg) {
		prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	    }
	    else {
		prot_printf(popd_out, "+OK %u\r\n", popd_highest);
	    }
	}
	else if (!strcmp(inputbuf, "rset")) {
	    if (arg) {
		prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	    }
	    else {
		popd_highest = 0;
		for (msg = 1; msg <= popd_exists; msg++) {
		    popd_msg[msg].deleted = 0;
		}
		prot_printf(popd_out, "+OK\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "top")) {
	    int lines;

	    if (arg) msg = parsenum(&arg);
	    if (!arg) prot_printf(popd_out, "-ERR Missing argument\r\n");
	    else {
		lines = parsenum(&arg);
		if (arg) {
		    prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    prot_printf(popd_out, "-ERR No such message\r\n");
		}
		else if (lines < 0) {
		    prot_printf(popd_out, "-ERR Invalid number of lines\r\n");
		}
		else {
		    blat(msg, lines);
		}
	    }
	}
	else if (!strcmp(inputbuf, "uidl")) {
	    if (arg) {
		msg = parsenum(&arg);
		if (arg) {
		    prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    prot_printf(popd_out, "-ERR No such message\r\n");
		}
		else {
		    prot_printf(popd_out, "+OK %u %u\r\n", msg, popd_msg[msg].uid);
		}
	    }
	    else {
		prot_printf(popd_out, "+OK unique-id listing follows\r\n");
		for (msg = 1; msg <= popd_exists; msg++) {
		    if (!popd_msg[msg].deleted) {
			prot_printf(popd_out, "%u %u\r\n", msg, 
				    popd_msg[msg].uid);
		    }
		}
		prot_printf(popd_out, ".\r\n");
	    }
	}
	else {
	    prot_printf(popd_out, "-ERR Unrecognized command\r\n");
	}
    }		
}

#ifdef HAVE_SSL
static int starttls_enabled(void)
{
    if (config_getstring("tls_cert_file", NULL) == NULL) return 0;
    if (config_getstring("tls_key_file", NULL) == NULL) return 0;
    return 1;
}

static void cmd_starttls(int pop3s)
{
    int result;
    int *layerp;
    sasl_external_properties_t external;


    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &(external.ssf);

    if (popd_starttls_done == 1)
    {
	prot_printf(popd_out, "-ERR %s\r\n", 
		    "Already successfully executed STLS");
	return;
    }

    result=tls_init_serverengine(5,        /* depth to verify */
				 !pop3s,   /* can client auth? */
				 0,        /* require client to auth? */
				 (char *)config_getstring("tls_ca_file", ""),
				 (char *)config_getstring("tls_ca_path", ""),
				 (char *)config_getstring("tls_cert_file", ""),
				 (char *)config_getstring("tls_key_file", ""));

    if (result == -1) {

	syslog(LOG_ERR, "[pop3d] error initializing TLS: "
	       "[CA_file: %s] [CA_path: %s] [cert_file: %s] [key_file: %s]",
	       (char *) config_getstring("tls_ca_file", ""),
	       (char *) config_getstring("tls_ca_path", ""),
	       (char *) config_getstring("tls_cert_file", ""),
	       (char *) config_getstring("tls_key_file", ""));

	if (pop3s == 0)
	    prot_printf(popd_out, "-ERR %s\r\n", "Error initializing TLS");
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
			       &(external.auth_id));

    /* if error */
    if (result==-1) {
	if (pop3s == 0) {
	    prot_printf(popd_out, "-ERR Starttls failed\r\n");
	    syslog(LOG_NOTICE, "[pop3d] STARTTLS failed: %s", popd_clienthost);
	} else {
	    syslog(LOG_NOTICE, "pop3s failed: %s", popd_clienthost);
	    fatal("tls_start_servertls() failed", EC_TEMPFAIL);
	}
	return;
    }

    /* tell SASL about the negotiated layer */
    result = sasl_setprop(popd_saslconn, SASL_SSF_EXTERNAL, &external);

    if (result != SASL_OK) {
	fatal("sasl_setprop() failed: cmd_starttls()", EC_TEMPFAIL);
    }

    /* if authenticated set that */
    if (external.auth_id != NULL) {
	popd_userid = external.auth_id;
    }

    /* tell the prot layer about our new layers */
    prot_settls(popd_in, tls_conn);
    prot_settls(popd_out, tls_conn);

    popd_starttls_done = 1;
}
#else
static int starttls_enabled(void)
{
    return 0;
}

static void cmd_starttls(int pop3s __attribute__((unused)))
{
    fatal("cmd_starttls() called, but no OpenSSL", EC_SOFTWARE);
}
#endif /* HAVE_SSL */

void
cmd_user(user)
char *user;
{
    int fd;
    struct protstream *shutdown_in;
    char buf[1024];
    char *p;
    char shutdownfilename[1024];

    if (popd_userid) {
	prot_printf(popd_out, "-ERR Must give PASS command\r\n");
	return;
    }

    sprintf(shutdownfilename, "%s/msg/shutdown", config_dir);
    if ((fd = open(shutdownfilename, O_RDONLY, 0)) != -1) {
	shutdown_in = prot_new(fd, 0);
	prot_fgets(buf, sizeof(buf), shutdown_in);
	if ((p = strchr(buf, '\r'))!=NULL) *p = 0;
	if ((p = strchr(buf, '\n'))!=NULL) *p = 0;

	for(p = buf; *p == '['; p++); /* can't have [ be first char */
	prot_printf(popd_out, "-ERR %s\r\n", p);
	prot_flush(popd_out);
	shut_down(0);
    }
    else if (!(p = auth_canonifyid(user)) ||
	       strchr(p, '.') || strlen(p) + 6 > MAX_MAILBOX_PATH) {
	prot_printf(popd_out, "-ERR Invalid user\r\n");
	syslog(LOG_NOTICE,
	       "badlogin: %s plaintext %s invalid user",
	       popd_clienthost, beautify_string(user));
    }
    else {
	popd_userid = xstrdup(p);
	prot_printf(popd_out, "+OK Name is a valid mailbox\r\n");
    }
}

void cmd_pass(pass)
char *pass;
{
    char *reply = 0;
    int plaintextloginpause;

    if (!popd_userid) {
	prot_printf(popd_out, "-ERR Must give USER command\r\n");
	return;
    }

#ifdef HAVE_KRB
    if (kflag) {
	if (strcmp(popd_userid, kdata.pname) != 0 ||
	    kdata.pinst[0] ||
	    strcmp(klrealm, kdata.prealm) != 0) {
	    prot_printf(popd_out, "-ERR Invalid login\r\n");
	    syslog(LOG_NOTICE,
		   "badlogin: %s kpop %s %s%s%s@%s access denied",
		   popd_clienthost, popd_userid,
		   kdata.pname, kdata.pinst[0] ? "." : "",
		   kdata.pinst, kdata.prealm);
	    return;
	}

	syslog(LOG_NOTICE, "login: %s %s kpop", popd_clienthost, popd_userid);

	openinbox();
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
	    prot_printf(popd_out, "-ERR Invalid login\r\n");
	    return;
	}
    }
    else if ((sasl_checkpass(popd_saslconn,
			     popd_userid,
			     strlen(popd_userid),
			     pass,
			     strlen(pass),
			     (const char **) &reply))!=SASL_OK) { 
	if (reply) {
	    syslog(LOG_NOTICE, "badlogin: %s plaintext %s %s",
		   popd_clienthost, popd_userid, reply);
	}
	sleep(3);
	prot_printf(popd_out, "-ERR Invalid login\r\n");
	free(popd_userid);
	popd_userid = 0;

	return;
    }
    else {
	syslog(LOG_NOTICE, "login: %s %s plaintext %s",
	       popd_clienthost, popd_userid, reply ? reply : "");
	if ((plaintextloginpause = config_getint("plaintextloginpause", 0))!=0) {
	    sleep(plaintextloginpause);
	}
    }
    openinbox();
}

/* Handle the POP3 Extension extension.
 */
void
cmd_capa()
{
    int minpoll = config_getint("popminpoll", 0) * 60;
    int expire = config_getint("popexpiretime", -1);
    int mechcount;
    char *mechlist;

    prot_printf(popd_out, "+OK List of capabilities follows\r\n");

    /* SASL special case: print SASL, then a list of supported capabilities */
    if (sasl_listmech(popd_saslconn,
		      NULL, /* should be id string */
		      "SASL ", " ", "\r\n",
		      &mechlist,
		      NULL, &mechcount) == SASL_OK && mechcount > 0) {
	prot_write(popd_out, mechlist, strlen(mechlist));
	free(mechlist);
    }

    if (starttls_enabled()) {
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
    prot_printf(popd_out, "USER\r\n");
    
    prot_printf(popd_out,
		"IMPLEMENTATION Cyrus POP3 server %s\r\n",
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
    int clientinlen=0;
    char *authtype;
    char *serverout;
    unsigned int serveroutlen;
    const char *errstr;

    /* if client didn't specify an argument we give them the list */
    if (!arg) {
	char *sasllist;
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
	clientin.s = xmalloc(clientin.alloc);
	sasl_result = sasl_decode64(arg, arglen, clientin.s, &clientinlen);
    } else {
	sasl_result = SASL_OK;
	clientinlen = 0;
    }

    /* server did specify a command, so let's try to authenticate */
    if (sasl_result == SASL_OK || sasl_result == SASL_CONTINUE)
	sasl_result = sasl_server_start(popd_saslconn, authtype,
					clientin.s, clientinlen,
					&serverout, &serveroutlen,
					&errstr);
    /* sasl_server_start will return SASL_OK or SASL_CONTINUE on success */
    while (sasl_result == SASL_CONTINUE)
    {
	/* print the message to the user */
	printauthready(popd_out, serveroutlen, (unsigned char *)serverout);
	free(serverout);

	/* get string from user */
	clientinlen = getbase64string(popd_in, &clientin);
	if (clientinlen == -1) {
	    prot_printf(popd_out, "-ERR Invalid base64 string\r\n");
	    return;
	}

	sasl_result = sasl_server_step(popd_saslconn,
				       clientin.s,
				       clientinlen,
				       &serverout, &serveroutlen,
				       &errstr);
    }

    /* failed authentication */
    if (sasl_result != SASL_OK)
    {
	sleep(3);      
	
	/* convert the sasl error code to a string */
	if (!errstr) errstr = sasl_errstring(sasl_result, NULL, NULL);
	if (!errstr) errstr = "unknown error";
	
	prot_printf(popd_out, "-ERR authenticating: %s\r\n", errstr);

	if (authtype) {
	    syslog(LOG_NOTICE, "badlogin: %s %s %s",
		   popd_clienthost, authtype, errstr);
	} else {
	    syslog(LOG_NOTICE, "badlogin: %s %s",
		   popd_clienthost, authtype);
	}
	
	return;
    }

    /* successful authentication */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_authproc()
     */
    sasl_result = sasl_getprop(popd_saslconn, SASL_USERNAME,
			       (void **) &popd_userid);
    if (sasl_result != SASL_OK) {
	prot_printf(popd_out, 
		    "-ERR weird SASL error %d getting SASL_USERNAME\r\n", 
		    sasl_result);
	return;
    }
    
    if (openinbox()==0) {
	proc_register("pop3d", popd_clienthost, 
		      popd_userid, popd_mailbox->name);    

	syslog(LOG_NOTICE, "login: %s %s %s %s", popd_clienthost, popd_userid,
	       authtype, "User logged in");

	prot_setsasl(popd_in,  popd_saslconn);
	prot_setsasl(popd_out, popd_saslconn);
    }
}

/*
 * Complete the login process by opening and locking the user's inbox
 */
int openinbox(void)
{
    char inboxname[MAX_MAILBOX_PATH];
    int r, msg;
    struct index_record record;
    char buf[MAX_MAILBOX_PATH];
    FILE *logfile;
    int minpoll;

    popd_login_time = time(0);

    strcpy(inboxname, "user.");
    strcat(inboxname, popd_userid);
    r = mailbox_open_header(inboxname, 0, &mboxstruct);
    if (r) {
	free(popd_userid);
	popd_userid = 0;
	sleep(3);
	prot_printf(popd_out, "-ERR Invalid login\r\n");
	return 1;
    }

    r = mailbox_open_index(&mboxstruct);
    if (!r) r = mailbox_lock_pop(&mboxstruct);
    if (r) {
	mailbox_close(&mboxstruct);
	free(popd_userid);
	popd_userid = 0;
	prot_printf(popd_out, "-ERR [IN-USE] Unable to lock maildrop\r\n");
	return 1;
    }

    if ((minpoll = config_getint("popminpoll", 0)) &&
	mboxstruct.pop3_last_login + 60*minpoll > popd_login_time) {
	prot_printf(popd_out,
	    "-ERR [LOGIN-DELAY] Logins must be at least %d minute%s apart\r\n",
		    minpoll, minpoll > 1 ? "s" : "");
	if (!mailbox_lock_index(&mboxstruct)) {
	    mboxstruct.pop3_last_login = popd_login_time;
	    mailbox_write_index_header(&mboxstruct);
	}
	mailbox_close(&mboxstruct);
	free(popd_userid);
	popd_userid = 0;
	return 1;
    }

    if (chdir(mboxstruct.path)) {
	syslog(LOG_ERR, "IOERROR: changing directory to %s: %m",
	       mboxstruct.path);
	r = IMAP_IOERROR;
    }
    if (!r) {
	popd_exists = mboxstruct.exists;
	popd_highest = 0;
	popd_msg = (struct msg *)xmalloc((popd_exists+1) * sizeof(struct msg));
	for (msg = 1; msg <= popd_exists; msg++) {
	    if ((r = mailbox_read_index_record(&mboxstruct, msg, &record))!=0)
	      break;
	    popd_msg[msg].uid = record.uid;
	    popd_msg[msg].size = record.size;
	    popd_msg[msg].deleted = 0;
	}
    }
    if (r) {
	mailbox_close(&mboxstruct);
	free(popd_userid);
	popd_userid = 0;
	free(popd_msg);
	popd_msg = 0;
	popd_exists = 0;
	prot_printf(popd_out, "-ERR Unable to read maildrop\r\n");
	return 1;
    }
    popd_mailbox = &mboxstruct;
    proc_register("pop3d", popd_clienthost, popd_userid, popd_mailbox->name);

    /* Create telemetry log */
    sprintf(buf, "%s%s%s/%lu", config_dir, FNAME_LOGDIR, popd_userid,
	    (long unsigned) getpid());
    logfile = fopen(buf, "w");
    if (logfile) {
	prot_setlog(popd_in, fileno(logfile));
	prot_setlog(popd_out, fileno(logfile));
    }

    prot_printf(popd_out, "+OK Maildrop locked and ready\r\n");
    return 0;
}

static void blat(int msg,int lines)
{
    FILE *msgfile;
    char buf[4096];
    int thisline = -2;

    msgfile = fopen(mailbox_message_fname(popd_mailbox, popd_msg[msg].uid),
		    "r");
    if (!msgfile) {
	prot_printf(popd_out, "-ERR Could not read message file\r\n");
	return;
    }
    prot_printf(popd_out, "+OK Message follows\r\n");
    while (lines != thisline) {
	if (!fgets(buf, sizeof(buf), msgfile)) break;

	if (thisline < 0) {
	    if (buf[0] == '\r' && buf[1] == '\n') thisline = 0;
	}
	else thisline++;

	if (buf[0] == '.') prot_putc('.', popd_out);
	do {
	    prot_printf(popd_out, "%s", buf);
	}
	while (buf[strlen(buf)-1] != '\n' && fgets(buf, sizeof(buf), msgfile));
    }
    fclose(msgfile);

    /* Protect against messages not ending in CRLF */
    if (buf[strlen(buf)-1] != '\n') prot_printf(popd_out, "\r\n");

    prot_printf(popd_out, ".\r\n");
}

static int parsenum(char **ptr)
{
    char *p = *ptr;
    int result = 0;

    if (!isdigit((int) *p)) {
	*ptr = 0;
	return -1;
    }
    while (*p && isdigit((int) *p)) {
	result = result * 10 + *p++ - '0';
    }

    if (*p) {
	while (*p && isspace((int) *p)) p++;
	*ptr = p;
    }
    else *ptr = 0;
    return result;
}

static int expungedeleted(rock, index)
char *rock;
char *index;
{
    int msg;
    int uid = ntohl(*((bit32 *)(index+OFFSET_UID)));

    for (msg = 1; msg <= popd_exists; msg++) {
	if (popd_msg[msg].uid == uid) {
	    return popd_msg[msg].deleted;
	}
    }
    return 0;
}

/*
 * Eat characters up to and including the next newline
 */
void eatline(void)
{
    int c;

    while ((c = prot_getc(popd_in)) != EOF && c != '\n')
    { }
}
