/* pop3d.c -- POP3 server protocol parsing
 *
 * Copyright 1998 Carnegie Mellon University
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
 */

/*
 * $Id: pop3d.c,v 1.54.2.1 2000/11/02 00:49:54 ken3 Exp $
 */

#ifndef __GNUC__
/* can't use attributes... */
#define __attribute__(foo)
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

#include <sasl.h>

#include "acl.h"
#include "util.h"
#include "auth.h"
#include "config.h"

/* openSSL has it's own DES function which conflict in names with those used by krb.h */
#ifdef HAVE_SSL
#undef HAVE_SSL
#endif /* HAVE_SSL */

#include "prot.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "version.h"
#include "xmalloc.h"

extern int optind;
extern char *optarg;
extern int opterr;

extern int errno;

extern char *login_capabilities();

#ifdef HAVE_KRB
#include <krb.h>

/* MIT's kpop authentication kludge */
int kflag = 0;
char klrealm[REALM_SZ];
AUTH_DAT kdata;
#endif

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

static struct mailbox mboxstruct;

static int expungedeleted();

static void cmd_auth();
static void cmd_capa();
static void cmd_pass();
static void cmd_user();

/* This creates a structure that defines the allowable
 *   security properties 
 */
static sasl_security_properties_t *make_secprops(int min,int max)
{
  sasl_security_properties_t *ret=
    (sasl_security_properties_t *) xmalloc(sizeof(sasl_security_properties_t));

  ret->maxbufsize=4000;
  ret->min_ssf=min;     /* minimum allowable security strength */
  ret->max_ssf=max;     /* maximum allowable security strength */

  ret->security_flags = 0;
  if (!config_getswitch("allowplaintext", 1)) {
      ret->security_flags |= SASL_SEC_NOPLAINTEXT;
  }
  if (!config_getswitch("allowanonymouslogin", 0)) {
      ret->security_flags |= SASL_SEC_NOANONYMOUS;
  }
  ret->property_names=NULL;
  ret->property_values=NULL;

  return ret;
}

/* this is a wrapper to call the cyrus configuration from SASL */
static int mysasl_config(void *context __attribute__((unused)), 
			 const char *plugin_name,
			 const char *option,
			 const char **result,
			 unsigned *len)
{
    char opt[1024];

    if (strcmp(option, "srvtab")) { /* we don't transform srvtab! */
	int sl = 5 + (plugin_name ? strlen(plugin_name) + 1 : 0);

	strncpy(opt, "sasl_", 1024);
	if (plugin_name) {
	    int i = 5;

	    for (i = 0; i < strlen(plugin_name); i++) {
		opt[i + 5] = tolower(plugin_name[i]);
	    }
	    opt[i] = '_';
	}
 	strncat(opt, option, 1024 - sl - 1);
    } else {
	strncpy(opt, option, 1024);
    }
    opt[1023] = '\0';		/* paranoia */

    *result = config_getstring(opt, NULL);
    if (*result == NULL && plugin_name) {
	/* try again without plugin name */

	strncpy(opt, "sasl_", 1024);
 	strncat(opt, option, 1024 - 6);
	opt[1023] = '\0';	/* paranoia */
	*result = config_getstring(opt, NULL);
    }

    if (*result) {
	if (len) { *len = strlen(*result); }
	return SASL_OK;
    } else {
	return SASL_FAIL;
    }
}

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

main(argc, argv, envp)
int argc;
char **argv;
char **envp;
{
    int opt;
    char hostname[MAXHOSTNAMELEN+1];
    int salen;
    struct hostent *hp;
    struct sockaddr_in sa;
    int timeout;
    sasl_security_properties_t *secprops=NULL;

    popd_in = prot_new(0, 0);
    popd_out = prot_new(1, 1);

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    opterr = 0;
    while ((opt = getopt(argc, argv, "k")) != EOF) {
	switch(opt) {
#ifdef HAVE_KRB
	case 'k':
	    kflag++;
	    break;
#endif

	default:
	    usage();
	}
    }

    setproctitle_init(argc, argv, envp);
    config_init("pop3d");

    signal(SIGPIPE, SIG_IGN);
    gethostname(hostname, sizeof(hostname));

    /* Find out name of client host */
    salen = sizeof(popd_remoteaddr);
    if (getpeername(0, (struct sockaddr *)&popd_remoteaddr, &salen) == 0 &&
	popd_remoteaddr.sin_family == AF_INET) {
	if (hp = gethostbyaddr((char *)&popd_remoteaddr.sin_addr,
			       sizeof(popd_remoteaddr.sin_addr), AF_INET)) {
	    if (strlen(hp->h_name) + 30 > sizeof(popd_clienthost)) {
		strncpy(popd_clienthost, hp->h_name, sizeof(popd_clienthost)-30);
		popd_clienthost[sizeof(popd_clienthost)-30] = '\0';
	    }
	    else {
		strcpy(popd_clienthost, hp->h_name);
	    }
	}
	else {
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

    /* Make a SASL connection and setup some properties for it */

    if (sasl_server_init(mysasl_cb, "Cyrus") != SASL_OK)
	fatal("SASL failed initializing: sasl_server_init()",EC_TEMPFAIL); 

    /* other params should be filled in */
    if (sasl_server_new("pop", hostname, NULL, 
			NULL, 2000, &popd_saslconn)!=SASL_OK)
	fatal("SASL failed initializing: sasl_server_new()",EC_TEMPFAIL); 

    /* will always return something valid */
    secprops=make_secprops(0,2000);        
    sasl_setprop(popd_saslconn, SASL_SEC_PROPS, secprops);
    
    sasl_setprop(popd_saslconn,   SASL_IP_REMOTE, &popd_remoteaddr);  
    sasl_setprop(popd_saslconn,   SASL_IP_LOCAL, &popd_localaddr);  

    proc_register("pop3d", popd_clienthost, (char *)0, (char *)0);

    /* Set inactivity timer */
    timeout = config_getint("poptimeout", 10);
    if (timeout < 10) timeout = 10;
    prot_settimeout(popd_in, timeout*60);
    prot_setflushonread(popd_in, popd_out);

#ifdef HAVE_KRB
    if (kflag) kpop();
#endif

    prot_printf(popd_out, "+OK %s Cyrus POP3 %s server ready\r\n",
		hostname, CYRUS_VERSION);

    cmdloop();
}

usage()
{
    prot_printf(popd_out, "-ERR usage: pop3d%s\r\n",
#ifdef HAVE_KRB
		" [-k]"
#else
		""
#endif
		);
    prot_flush(popd_out);
    exit(EC_USAGE);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
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
kpop()
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
#endif

/*
 * Top-level command loop parsing
 */
cmdloop()
{
    char inputbuf[8192];
    char *p, *arg;
    unsigned msg;

    for (;;) {
	if (!prot_fgets(inputbuf, sizeof(inputbuf), popd_in)) {
	    shut_down(0);
	}

	p = inputbuf + strlen(inputbuf);
	if (p > inputbuf && p[-1] == '\n') *--p = '\0';
	if (p > inputbuf && p[-1] == '\r') *--p = '\0';

	/* Parse into keword and argument */
	for (p = inputbuf; *p && !isspace(*p); p++);
	if (*p) {
	    *p++ = '\0';
	    arg = p;
	    if (strcasecmp(inputbuf, "pass") != 0) {
		while (*arg && isspace(*arg)) {
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
			prot_printf(popd_out, "%u %u\r\n", msg, popd_msg[msg].uid);
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
	if (p = strchr(buf, '\r')) *p = 0;
	if (p = strchr(buf, '\n')) *p = 0;

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
	if (plaintextloginpause = config_getint("plaintextloginpause", 0)) {
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
    int i;
    int minpoll = config_getint("popminpoll", 0) * 60;
    int expire = config_getint("popexpiretime", -1);
    const char *capabilities, *next_capabilities;
    char *sasllist;
    
    prot_printf(popd_out, "+OK List of capabilities follows\r\n");

#if 0
    /* SASL special case: print SASL, then a list of supported capabilities
       (parsed from the IMAP-style login_capabilities function, then a CRLF */
    if (sasl_listmech(popd_saslconn,
			 "", /* should be id string */
			 ""," ","",
			 &sasllist,
			 NULL,NULL)==SASL_OK)
    {
      prot_printf(popd_out, "SASL"); /* no \r\n */
      prot_printf(popd_out," %s",sasllist);
      prot_printf(popd_out, "\r\n");    
    }
#endif

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




void
cmd_auth(authtype)
char *authtype;
{
    int sasl_result;
    char * clientin;
    int clientinlen=0;
    
    char *serverout;
    unsigned int serveroutlen;
    const char *errstr;
    
    const char *errorstring = NULL;

    char buf[MAX_MAILBOX_PATH];
    char *p;
    FILE *logfile;

    int *ssfp;
    char *ssfmsg=NULL;

   
    /* if client didn't specify an auth mechanism we give them the list */
    if (!authtype) {
      char *sasllist;
      unsigned int mechnum;

      prot_printf(popd_out, "+OK List of supported mechanisms follows\r\n");
      
      /* SASL special case: print SASL, then a list of supported capabilities
       * (parsed from the IMAP-style login_capabilities function, 
       * then a CRLF */
      if (sasl_listmech(popd_saslconn,
			"", /* should be id string */
			"","\r\n","\r\n",
			&sasllist,
			NULL,&mechnum) == SASL_OK) {
	  if (mechnum>0) {
	      prot_printf(popd_out,"%s",sasllist);
	  }
      }
      
      prot_printf(popd_out, ".\r\n");
      
      return;
    }

    /* server did specify a command, so let's try to authenticate */

    sasl_result = sasl_server_start(popd_saslconn, authtype,
				    NULL, 0,
				    &serverout, &serveroutlen,
				    &errstr);    

    /* sasl_server_start will return SASL_OK or SASL_CONTINUE on success */

    while (sasl_result == SASL_CONTINUE)
    {

      /* print the message to the user */
      printauthready(serveroutlen, (unsigned char *)serverout);
      free(serverout);

      /* get string from user */
      clientinlen = readbase64string(&clientin);
      if (clientinlen == -1) {
	prot_printf(popd_out, "-ERR Invalid base64 string\r\n");
	return;
      }

      sasl_result = sasl_server_step(popd_saslconn,
				     clientin,
				     clientinlen,
				     &serverout, &serveroutlen,
				     &errstr);
    }


    /* failed authentication */
    if (sasl_result != SASL_OK)
    {
	syslog(LOG_NOTICE, "badlogin: %s %s %i",
	       popd_clienthost, authtype, sasl_result);
	
	if (clientin) {
	    syslog(LOG_NOTICE, "badlogin: %s %s %s",
		   popd_clienthost, authtype, clientin);
	} else {
	    syslog(LOG_NOTICE, "badlogin: %s %s",
		   popd_clienthost, authtype);
	}
	
	sleep(3);      
	
	/* convert the sasl error code to a string */
	errorstring = sasl_errstring(sasl_result, NULL, NULL);
      
	if (errorstring)
	    prot_printf(popd_out, "-ERR %s\r\n",errorstring);
	else
	    prot_printf(popd_out, "-ERR Error Authenticating\r\n");
	
	return;
    }

    /* successful authentication */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_authproc()
     */

    sasl_result = sasl_getprop(popd_saslconn, SASL_USERNAME,
			     (void **) &popd_userid);
    if (sasl_result!=SASL_OK)
    {
      prot_printf(popd_out, "-ERR weird SASL error %d getting SASL_USERNAME\r\n", 
		  sasl_result);
      return;
    }

    syslog(LOG_NOTICE, "login: %s %s %s sasl code=%d", popd_clienthost, popd_userid,
	   authtype, sasl_result);

    /* xxx here */
    if (openinbox()==0)
    {

      proc_register("pop3d", popd_clienthost, popd_userid, popd_mailbox->name);    

      syslog(LOG_NOTICE, "login: %s %s %s %s", popd_clienthost, popd_userid,
	     authtype, "User logged in");


      prot_setsasl(popd_in,  popd_saslconn);
      prot_setsasl(popd_out, popd_saslconn);

    }

}
    

/*
 * Complete the login process by opening and locking the user's inbox
 */
int openinbox()
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
	    if (r = mailbox_read_index_record(&mboxstruct, msg, &record))
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
    sprintf(buf, "%s%s%s/%u", config_dir, FNAME_LOGDIR, popd_userid,
	    getpid());
    logfile = fopen(buf, "w");
    if (logfile) {
	prot_setlog(popd_in, fileno(logfile));
	prot_setlog(popd_out, fileno(logfile));
    }

    prot_printf(popd_out, "+OK Maildrop locked and ready\r\n");
    return 0;
}

blat(msg, lines)
int msg;
int lines;
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

int parsenum(ptr)
char **ptr;
{
    char *p = *ptr;
    int result = 0;

    if (!isdigit(*p)) {
	*ptr = 0;
	return -1;
    }
    while (*p && isdigit(*p)) {
	result = result * 10 + *p++ - '0';
    }

    if (*p) {
	while (*p && isspace(*p)) p++;
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
 * Print an authentication ready response
 */
static char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
printauthready(len, data)
int len;
unsigned char *data;
{
    int c1, c2, c3;

    prot_putc('+', popd_out);
    prot_putc(' ', popd_out);
    while (len) {
	c1 = *data++;
	len--;
	prot_putc(basis_64[c1>>2], popd_out);
	if (len == 0) c2 = 0;
	else c2 = *data++;
	prot_putc(basis_64[((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)], popd_out);
	if (len == 0) {
	    prot_putc('=', popd_out);
	    prot_putc('=', popd_out);
	    break;
	}

	if (--len == 0) c3 = 0;
	else c3 = *data++;
        prot_putc(basis_64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)], popd_out);
	if (len == 0) {
	    prot_putc('=', popd_out);
	    break;
	}
	
	--len;
        prot_putc(basis_64[c3 & 0x3F], popd_out);
    }
    prot_putc('\r', popd_out);
    prot_putc('\n', popd_out);
    prot_flush(popd_out);
}

#define XX 127
/*
 * Table for decoding base64
 */
static const char index_64[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,63,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,XX,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
    XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};
#define CHAR64(c)  (index_64[(unsigned char)(c)])

#define BUFGROWSIZE 100

/*
 * Parse a base64_string
 */
int readbase64string(ptr)
char **ptr;
{
    int c1, c2, c3, c4;
    int i, len = 0;
    static char *buf;
    static int alloc = 0;

    if (alloc == 0) {
	alloc = BUFGROWSIZE;
	buf = xmalloc(alloc+1);
    }
	
    for (;;) {
	c1 = prot_getc(popd_in);
	if (c1 == '\r') {
	    c1 = prot_getc(popd_in);
	    if (c1 != '\n') {
		eatline();
		return -1;
	    }
	    *ptr = buf;
	    return len;
	}
	else if (c1 == '\n') {
	    *ptr = buf;
	    return len;
	}

	if (CHAR64(c1) == XX) {
	    eatline();
	    return -1;
	}
	
	c2 = prot_getc(popd_in);
	if (CHAR64(c2) == XX) {
	    if (c2 != '\n') eatline();
	    return -1;
	}

	c3 = prot_getc(popd_in);
	if (c3 != '=' && CHAR64(c3) == XX) {
	    if (c3 != '\n') eatline();
	    return -1;
	}

	c4 = prot_getc(popd_in);
	if (c4 != '=' && CHAR64(c4) == XX) {
	    if (c4 != '\n') eatline();
	    return -1;
	}

	if (len+3 >= alloc) {
	    alloc = len+BUFGROWSIZE;
	    buf = xrealloc(buf, alloc+1);
	}

	buf[len++] = ((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
	if (c3 == '=') {
	    c1 = prot_getc(popd_in);
	    if (c1 == '\r') c1 = prot_getc(popd_in);
	    if (c1 != '\n') {
		eatline();
		return -1;
	    }
	    if (c4 != '=') return -1;
	    *ptr = buf;
	    return len;
	}
	buf[len++] = (((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
	if (c4 == '=') {
	    c1 = prot_getc(popd_in);
	    if (c1 == '\r') c1 = prot_getc(popd_in);
	    if (c1 != '\n') {
		eatline();
		return -1;
	    }
	    *ptr = buf;
	    return len;
	}
	buf[len++] = (((CHAR64(c3)&0x3)<<6) | CHAR64(c4));
    }
}

/*
 * Parse a base64_string
 */
int parsebase64string(ptr, s)
char **ptr;
const char *s;
{
    int c1, c2, c3, c4;
    int i, len = 0;
    static char *buf;
    static int alloc = 0;

    if (alloc == 0) {
	alloc = BUFGROWSIZE;
	buf = xmalloc(alloc+1);
    }
	
    for (;;) {
	c1 = *s++;
	if (c1 == '\0') {
	    *ptr = buf;
	    return len;
	}

	if (CHAR64(c1) == XX) {
	    return -1;
	}
	
	c2 = *s++;
	if (CHAR64(c2) == XX) {
	    return -1;
	}

	c3 = *s++;
	if (c3 != '=' && CHAR64(c3) == XX) {
	    return -1;
	}

	c4 = *s++;
	if (c4 != '=' && CHAR64(c4) == XX) {
	    return -1;
	}

	if (len+3 >= alloc) {
	    alloc = len+BUFGROWSIZE;
	    buf = xrealloc(buf, alloc+1);
	}

	buf[len++] = ((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
	if (c3 == '=') {
	    c1 = *s++;
	    if (c1 != '\0') {
		return -1;
	    }
	    if (c4 != '=') return -1;
	    *ptr = buf;
	    return len;
	}
	buf[len++] = (((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
	if (c4 == '=') {
	    c1 = *s++;
	    if (c1 != '\0') {
		return -1;
	    }
	    *ptr = buf;
	    return len;
	}
	buf[len++] = (((CHAR64(c3)&0x3)<<6) | CHAR64(c4));
    }
}

/*
 * Eat characters up to and including the next newline
 */
eatline()
{
    int c;

    while ((c = prot_getc(popd_in)) != EOF && c != '\n');
}
