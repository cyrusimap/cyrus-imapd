/* imapd.c -- IMAP server protocol parsing
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

/* $Id: imapd.c,v 1.198.2.5 2000/07/14 20:05:11 ken3 Exp $ */

#ifndef __GNUC__
#define __attribute__(foo)
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <syslog.h>
#include <com_err.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

#include <sasl.h>

#include "acl.h"
#include "util.h"
#include "auth.h"
#include "map.h"
#include "config.h"
#include "version.h"
#include "charset.h"
#include "imparse.h"
#include "mkgmtime.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "imapd.h"
#include "xmalloc.h"

#ifdef HAVE_SSL
#include "tls.h"
#endif /* HAVE_SSL */

extern int optind;
extern char *optarg;

extern int errno;

extern char *login_capabilities();

struct buf {
    char *s;
    int alloc;
};

sasl_conn_t *imapd_saslconn; /* the sasl connection context */
int imapd_starttls_done = 0; /* have we done a sucessful starttls yet? */

char *imapd_userid;
struct auth_state *imapd_authstate = 0;
int imapd_userisadmin;
struct mailbox *imapd_mailbox;
int imapd_exists;
struct sockaddr_in imapd_localaddr, imapd_remoteaddr;
int imapd_haveaddr = 0;
char imapd_clienthost[250] = "[local]";
struct protstream *imapd_out, *imapd_in;
time_t imapd_logtime;

#ifdef HAVE_SSL
extern SSL *tls_conn;
#endif /* HAVE_SSL */

static struct mailbox mboxstruct;

static struct fetchargs zerofetchargs;

static char *monthname[] = {
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec"
};

void usage P((void));
void shutdown_file P((int fd));
void motd_file P((int fd));
void shut_down P((int code));
void fatal P((const char *s, int code));

void cmdloop P((void));
void cmd_login P((char *tag, char *user, char *passwd));
void cmd_authenticate P((char *tag, char *authtype));
void cmd_noop P((char *tag, char *cmd));
void cmd_capability P((char *tag));
void cmd_append P((char *tag, char *name));
void cmd_select P((char *tag, char *cmd, char *name));
void cmd_close P((char *tag));
void cmd_fetch P((char *tag, char *sequence, int usinguid));
void cmd_partial P((char *tag, char *msgno, char *data,
		    char *start, char *count));
void cmd_store P((char *tag, char *sequence, char *operation, int usinguid));
void cmd_search P((char *tag, int usinguid));
void cmd_copy P((char *tag, char *sequence, char *name, int usinguid));
void cmd_expunge P((char *tag, char *sequence));
void cmd_create P((char *tag, char *name, char *partition));
void cmd_delete P((char *tag, char *name));
void cmd_rename P((char *tag, char *oldname, char *newname, char *partition));
void cmd_find P((char *tag, char *namespace, char *pattern));
void cmd_list P((char *tag, int subscribed, char *reference, char *pattern));
void cmd_changesub P((char *tag, char *namespace, char *name, int add));
void cmd_getacl P((char *tag, char *name, int oldform));
void cmd_listrights P((char *tag, char *name, char *identifier));
void cmd_myrights P((char *tag, char *name, int oldform));
void cmd_setacl P((char *tag, char *name, char *identifier, char *rights));
void cmd_getquota P((char *tag, char *name));
void cmd_getquotaroot P((char *tag, char *name));
void cmd_setquota P((char *tag, char *quotaroot));
void cmd_status P((char *tag, char *name));
void cmd_getuids P((char *tag, char *startuid));
void cmd_unselect P((char* tag));
void cmd_namespace P((char* tag));
void cmd_id P((char* tag));

void id_getcmdline P((int argc, char **argv));

void cmd_starttls(char *tag);
int starttls_enabled(void);

#ifdef ENABLE_X_NETSCAPE_HACK
void cmd_netscrape P((char* tag));
#endif

enum string_types { IMAP_ASTRING, IMAP_NSTRING, IMAP_STRING };
#define getastring(buf)	getxstring(buf, IMAP_ASTRING)
#define getnstring(buf)	getxstring(buf, IMAP_NSTRING)
#define getstring(buf)	getxstring(buf, IMAP_STRING)

int getword P((struct buf *buf));
int getxstring P((struct buf *buf, int type));
int getbase64string P((struct buf *buf));
int getsearchprogram P((char *tag, struct searchargs *searchargs,
			int *charset, int parsecharset));
int getsearchcriteria P((char *tag, struct searchargs *searchargs,
			 int *charset, int parsecharset));
int getsearchdate P((time_t *start, time_t *end));
int getdatetime P((time_t *date));

void eatline P((int c));
void printstring P((const char *s));
void printastring P((const char *s));

void appendfieldlist P((struct fieldlist **l, char *section,
			struct strlist *fields, char *trail));
void appendstrlist P((struct strlist **l, char *s));
void appendstrlistpat P((struct strlist **l, char *s));
void freefieldlist P((struct fieldlist *l));
void freestrlist P((struct strlist *l));
void appendsearchargs P((struct searchargs *s, struct searchargs *s1,
			 struct searchargs *s2));
void freesearchargs P((struct searchargs *s));

void printauthready P((int len, unsigned char *data));

/* XXX fix when proto-izing mboxlist.c */
static int mailboxdata(), listdata(), lsubdata();
static void mstringdata P((char *cmd, char *name, int matchlen, int maycreate));
void mboxlist_close P((void));

/* This creates a structure that defines the allowable
 *   security properties 
 */
static sasl_security_properties_t *make_secprops(int min, int max)
{
  sasl_security_properties_t *ret =
    (sasl_security_properties_t *) xmalloc(sizeof(sasl_security_properties_t));

  ret->maxbufsize = 4000;
  ret->min_ssf = min;		/* minimum allowable security strength */
  ret->max_ssf = max;		/* maximum allowable security strength */

  ret->security_flags = 0;

  ret->security_flags |= SASL_SEC_NOPLAINTEXT;

  if (!config_getswitch("allowanonymouslogin", 0)) {
      ret->security_flags |= SASL_SEC_NOANONYMOUS;
  }
  ret->property_names = NULL;
  ret->property_values = NULL;

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

/*
 * acl_ok() checks to see if the the inbox for 'user' grants the 'a'
 * right to the principal 'auth_identity'. Returns 1 if so, 0 if not.
 */
static int acl_ok(user, auth_identity)
const char *user;
const char *auth_identity;
{
    char *acl;
    char inboxname[1024];
    int r;
    struct auth_state *authstate;

    if (strchr(user, '.') || strlen(user)+6 >= sizeof(inboxname)) return 0;

    strcpy(inboxname, "user.");
    strcat(inboxname, user);

    if (!(authstate = auth_newstate(auth_identity, (char *)0)) ||
	mboxlist_lookup(inboxname, (char **)0, &acl)) {
	r = 0;  /* Failed so assume no proxy access */
    }
    else {
	r = (acl_myrights(authstate, acl) & ACL_ADMIN) != 0;
    }
    if (authstate) auth_freestate(authstate);
    return r;
}

/* returns true if imapd_authstate is in "item";
   expected: item = admins or proxyservers */
static int authisa(const char *item)
{
    const char *val = config_getstring(item, "");
    char buf[MAX_MAILBOX_PATH];

    while (*val) {
	char *p;
	
	for (p = (char *) val; *p && !isspace(*p); p++);
	strncpy(buf, val, p-val);
	buf[p-val] = 0;

	if (auth_memberof(imapd_authstate, buf)) {
	    return 1;
	}
	val = p;
	while (*val && isspace(*val)) val++;
    }
    return 0;
}

/* should we allow users to proxy?  return SASL_OK if yes,
   SASL_BADAUTH otherwise */
static mysasl_authproc(void *context __attribute__((unused)),
		       const char *auth_identity,
		       const char *requested_user,
		       const char **user,
		       const char **errstr)
{
    char *p;
    const char *val;
    char *canon_authuser, *canon_requser;
    char *username=NULL, *realm;
    char buf[MAX_MAILBOX_PATH];
    static char replybuf[100];

    canon_authuser = auth_canonifyid(auth_identity);
    if (!canon_authuser) {
	*errstr = "bad userid authenticated";
	return SASL_BADAUTH;
    }
    canon_authuser = xstrdup(canon_authuser);

    canon_requser = auth_canonifyid(requested_user);
    if (!canon_requser) {
	*errstr = "bad userid requested";
	return SASL_BADAUTH;
    }
    canon_requser = xstrdup(canon_requser);

    /* check if remote realm */
    if (realm = strchr(canon_authuser, '@')) {
	realm++;
	val = config_getstring("loginrealms", "");
	while (*val) {
	    if (!strncasecmp(val, realm, strlen(realm)) &&
		(!val[strlen(realm)] || isspace(val[strlen(realm)]))) {
		break;
	    }
	    /* not this realm, try next one */
	    while (*val && !isspace(*val)) val++;
	    while (*val && isspace(*val)) val++;
	}
	if (!*val) {
	    snprintf(replybuf, 100, "cross-realm login %s denied", 
		     canon_authuser);
	    *errstr = replybuf;
	    return SASL_BADAUTH;
	}
    }

    imapd_authstate = auth_newstate(canon_authuser, NULL);

    /* ok, is auth_identity an admin? */
    imapd_userisadmin = authisa("admins");

    if (strcmp(canon_authuser, canon_requser)) {
	/* we want to authenticate as a different user; we'll allow this
	   if we're an admin or if we've allowed ACL proxy logins */
	int use_acl = config_getswitch("loginuseacl", 0);

	if (imapd_userisadmin ||
	    (use_acl && acl_ok(canon_requser, canon_authuser)) ||
	    authisa("proxyservers")) {
	    /* proxy ok! */

	    imapd_userisadmin = 0;	/* no longer admin */
	    auth_freestate(imapd_authstate);
	    
	    imapd_authstate = auth_newstate(canon_requser, NULL);
	} else {
	    *errstr = "user is not allowed to proxy";
	    
	    free(canon_authuser);
	    free(canon_requser);
	    auth_freestate(imapd_authstate);
	    
	    return SASL_BADAUTH;
	}
    }

    free(canon_authuser);
    *user = canon_requser;
    *errstr = NULL;
    return SASL_OK;
}

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, &mysasl_authproc, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

main(argc, argv, envp)
int argc;
char **argv;
char **envp;
{
    int opt;
    int salen;
    struct hostent *hp;
    int timeout;
    char hostname[MAXHOSTNAMELEN+1];
    sasl_security_properties_t *secprops = NULL;
    sasl_external_properties_t extprops;

    memset(&extprops, 0, sizeof(sasl_external_properties_t));

    if (gethostname(hostname, MAXHOSTNAMELEN) != 0) {
	fatal("gethostname failed\n",EC_USAGE);
    }

    /* get command line args for use in ID before getopt mangles them */
    id_getcmdline(argc, argv);

    while ((opt = getopt(argc, argv, "p:")) != EOF) {
	switch (opt) {
	case 'p': /* external protection */
	    extprops.ssf = atoi(optarg);
	    break;

	default:
	    break;
	}
    }

    imapd_in = prot_new(0, 0);
    imapd_out = prot_new(1, 1);

    setproctitle_init(argc, argv, envp);
    config_init("imapd");

    signal(SIGPIPE, SIG_IGN);

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    /* Find out name of client host */
    salen = sizeof(imapd_remoteaddr);
    if (getpeername(0, (struct sockaddr *)&imapd_remoteaddr, &salen) == 0 &&
	imapd_remoteaddr.sin_family == AF_INET) {
	if (hp = gethostbyaddr((char *)&imapd_remoteaddr.sin_addr,
			       sizeof(imapd_remoteaddr.sin_addr), AF_INET)) {
	    strncpy(imapd_clienthost, hp->h_name, sizeof(imapd_clienthost)-30);
	    imapd_clienthost[sizeof(imapd_clienthost)-30] = '\0';
	}
	else {
	    imapd_clienthost[0] = '\0';
	}
	strcat(imapd_clienthost, "[");
	strcat(imapd_clienthost, inet_ntoa(imapd_remoteaddr.sin_addr));
	strcat(imapd_clienthost, "]");
	salen = sizeof(imapd_localaddr);
	if (getsockname(0, (struct sockaddr *)&imapd_localaddr, &salen) == 0) {
	    imapd_haveaddr = 1;
	}
    }

    /* set the SASL allocation functions */
    sasl_set_alloc((sasl_malloc_t *) &xmalloc, 
		   (sasl_calloc_t *) &calloc, 
		   (sasl_realloc_t *) &xrealloc, 
		   (sasl_free_t *) &free);

    /* Make a SASL connection and setup some properties for it */
    if (sasl_server_init(mysasl_cb, "Cyrus") != SASL_OK)
	fatal("SASL failed initializing: sasl_server_init()", EC_TEMPFAIL); 

    /* other params should be filled in */
    if (sasl_server_new("imap", hostname, NULL, NULL, SASL_SECURITY_LAYER, 
			&imapd_saslconn)
	   != SASL_OK)
	fatal("SASL failed initializing: sasl_server_new()", EC_TEMPFAIL); 

    secprops = make_secprops(config_getint("sasl_minimum_layer", 0),
			     config_getint("sasl_maximum_layer", 256));

    sasl_setprop(imapd_saslconn, SASL_SEC_PROPS, secprops);
    if (extprops.ssf) {
	sasl_setprop(imapd_saslconn, SASL_SSF_EXTERNAL, &extprops);
    }
    sasl_setprop(imapd_saslconn, SASL_IP_REMOTE, &imapd_remoteaddr);
    sasl_setprop(imapd_saslconn, SASL_IP_LOCAL, &imapd_localaddr);

    proc_register("imapd", imapd_clienthost, (char *)0, (char *)0);

    /* Set inactivity timer */
    timeout = config_getint("timeout", 30);
    if (timeout < 30) timeout = 30;
    prot_settimeout(imapd_in, timeout*60);
    prot_setflushonread(imapd_in, imapd_out);

    cmdloop();
}

void
usage()
{
    prot_printf(imapd_out, "* BYE usage: imapd\r\n");
    prot_flush(imapd_out);
    exit(EC_USAGE);
}

/*
 * found a motd file; spit out message and return
 */
void motd_file(fd)
int fd;
{
    struct protstream *motd_in;
    char buf[1024];
    char *p;

    motd_in = prot_new(fd, 0);

    prot_fgets(buf, sizeof(buf), motd_in);
    if (p = strchr(buf, '\r')) *p = 0;
    if (p = strchr(buf, '\n')) *p = 0;

    for(p = buf; *p == '['; p++); /* can't have [ be first char, sigh */
    prot_printf(imapd_out, "* OK [ALERT] %s\r\n", p);
}

/*
 * Found a shutdown file: Spit out an untagged BYE and shut down
 */
void shutdown_file(fd)
int fd;
{
    struct protstream *shutdown_in;
    char buf[1024];
    char *p;

    shutdown_in = prot_new(fd, 0);

    prot_fgets(buf, sizeof(buf), shutdown_in);
    if (p = strchr(buf, '\r')) *p = 0;
    if (p = strchr(buf, '\n')) *p = 0;

    for(p = buf; *p == '['; p++); /* can't have [ be first char, sigh */
    prot_printf(imapd_out, "* BYE [ALERT] %s\r\n", p);

    shut_down(0);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    proc_cleanup();
    if (imapd_mailbox) {
	index_closemailbox(imapd_mailbox);
	mailbox_close(imapd_mailbox);
    }
    prot_flush(imapd_out);
    exit(code);
}

void
fatal(s, code)
const char *s;
int code;
{
    static int recurse_code = 0;

    if (recurse_code) {
	/* We were called recursively. Just give up */
	proc_cleanup();
	exit(recurse_code);
    }
    recurse_code = code;
    prot_printf(imapd_out, "* BYE Fatal error: %s\r\n", s);
    prot_flush(imapd_out);
    shut_down(code);

}

/*
 * Top-level command loop parsing
 */
void
cmdloop()
{
    int fd;
    char shutdownfilename[1024];
    char motdfilename[1024];
    char hostname[MAXHOSTNAMELEN+1];
    int c;
    int usinguid, havepartition, havenamespace, oldform;
    static struct buf tag, cmd, arg1, arg2, arg3, arg4;
    char *p;
    const char *err;

    sprintf(shutdownfilename, "%s/msg/shutdown", config_dir);

    gethostname(hostname, sizeof(hostname));
    prot_printf(imapd_out,
		"* OK %s Cyrus IMAP4 %s server ready\r\n", hostname,
		CYRUS_VERSION);

    sprintf(motdfilename, "%s/msg/motd", config_dir);
    if ((fd = open(motdfilename, O_RDONLY, 0)) != -1) {
	motd_file(fd);
	close(fd);
    }

    for (;;) {
	if (! imapd_userisadmin &&
	    (fd = open(shutdownfilename, O_RDONLY, 0)) != -1) {
	    shutdown_file(fd);
	}

	/* Parse tag */
	c = getword(&tag);
	if (c == EOF) {
	    if (err = prot_error(imapd_in)) {
		syslog(LOG_WARNING, "PROTERR: %s", err);
		prot_printf(imapd_out, "* BYE %s\r\n", err);
	    }
	    shut_down(0);
	}
	if (c != ' ' || !imparse_isatom(tag.s) || (tag.s[0] == '*' && !tag.s[1])) {
	    prot_printf(imapd_out, "* BAD Invalid tag\r\n");
	    eatline(c);
	    continue;
	}

	/* Parse command name */
	c = getword(&cmd);
	if (!cmd.s[0]) {
	    prot_printf(imapd_out, "%s BAD Null command\r\n", tag.s);
	    eatline(c);
	    continue;
	}
	if (islower(cmd.s[0])) cmd.s[0] = toupper(cmd.s[0]);
	for (p = &cmd.s[1]; *p; p++) {
	    if (isupper(*p)) *p = tolower(*p);
	}

	/* Only Authenticate/Login/Logout/Noop/Capability/Id/Starttls
	   allowed when not logged in */
	if (!imapd_userid && !strchr("ALNCIS", cmd.s[0])) goto nologin;
    
	/* note that about half the commands (the common ones that don't
	   hit the mailboxes file) now close the mailboxes file just in
	   case it was open. */
	switch (cmd.s[0]) {
	case 'A':
	    if (!strcmp(cmd.s, "Authenticate")) {
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (!imparse_isatom(arg1.s)) {
		    prot_printf(imapd_out, "%s BAD Invalid authenticate mechanism\r\n", tag.s);
		    eatline(c);
		    continue;
		}
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		
		if (imapd_userid) {
		    prot_printf(imapd_out, "%s BAD Already authenticated\r\n", tag.s);
		    continue;
		}
		cmd_authenticate(tag.s, arg1.s);
	    }
	    else if (!imapd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "Append")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;

		cmd_append(tag.s, arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'B':
	    if (!strcmp(cmd.s, "Bboard")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		cmd_select(tag.s, cmd.s, arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'C':
	    if (!strcmp(cmd.s, "Capability")) {
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_capability(tag.s);
	    }
	    else if (!imapd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "Check")) {
		if (!imapd_mailbox) goto nomailbox;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		mboxlist_close();	
		cmd_noop(tag.s, cmd.s);
	    }
	    else if (!strcmp(cmd.s, "Copy")) {
		if (!imapd_mailbox) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    copy:
		c = getword(&arg1);
		if (c == '\r') goto missingargs;
		if (c != ' ' || !imparse_issequence(arg1.s)) goto badsequence;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		cmd_copy(tag.s, arg1.s, arg2.s, usinguid);
	    }
	    else if (!strcmp(cmd.s, "Create")) {
		havepartition = 0;
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == ' ') {
		    havepartition = 1;
		    c = getword(&arg2);
		    if (!imparse_isatom(arg2.s)) goto badpartition;
		}
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_create(tag.s, arg1.s, havepartition ? arg2.s : 0);
	    }
	    else if (!strcmp(cmd.s, "Close")) {
		if (!imapd_mailbox) goto nomailbox;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		mboxlist_close();	
		cmd_close(tag.s);
	    }
	    else goto badcmd;
	    break;

	case 'D':
	    if (!strcmp(cmd.s, "Delete")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_delete(tag.s, arg1.s);
	    }
	    else if (!strcmp(cmd.s, "Deleteacl")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (!strcasecmp(arg1.s, "mailbox")) {
		    if (c != ' ') goto missingargs;
		    c = getastring(&arg1);
		}
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_setacl(tag.s, arg1.s, arg2.s, (char *)0);
	    }
	    else goto badcmd;
	    break;

	case 'E':
	    if (!strcmp(cmd.s, "Expunge")) {
		if (!imapd_mailbox) goto nomailbox;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		mboxlist_close();	
		cmd_expunge(tag.s, 0);
	    }
	    else if (!strcmp(cmd.s, "Examine")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		cmd_select(tag.s, cmd.s, arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'F':
	    if (!strcmp(cmd.s, "Fetch")) {
		if (!imapd_mailbox) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    fetch:
		c = getword(&arg1);
		if (c == '\r') goto missingargs;
		if (c != ' ' || !imparse_issequence(arg1.s)) goto badsequence;
		mboxlist_close();	
		cmd_fetch(tag.s, arg1.s, usinguid);
	    }
	    else if (!strcmp(cmd.s, "Find")) {
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_find(tag.s, arg1.s, arg2.s);
	    }
	    else goto badcmd;
	    break;

	case 'G':
	    if (!strcmp(cmd.s, "Getacl")) {
		oldform = 0;
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (!strcasecmp(arg1.s, "mailbox")) {
		    oldform = 1;
		    if (c != ' ') goto missingargs;
		    c = getastring(&arg1);
		}
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_getacl(tag.s, arg1.s, oldform);
	    }
	    else if (!strcmp(cmd.s, "Getquota")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_getquota(tag.s, arg1.s);
	    }
	    else if (!strcmp(cmd.s, "Getquotaroot")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_getquotaroot(tag.s, arg1.s);
	    }
#ifdef ENABLE_EXPERIMENT_OPTIMIZE_1
	    /* This command is disabled because it was removed from the
	       OPTIMIZE-1 extension, now known as UIDPLUS. */
	    else if (!strcmp(cmd.s, "Getuids")) {
		if (!imapd_mailbox) goto nomailbox;
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_getuids(tag.s, arg1.s);
	    }
#endif /* ENABLE_EXPERIMENT_OPTIMIZE_1 */
	    else goto badcmd;
	    break;

	case 'I':
	    if (!strcmp(cmd.s, "Id")) {
		if (c != ' ') goto missingargs;
		cmd_id(tag.s);
	    }
	    else goto badcmd;
	    break;

	case 'L':
	    if (!strcmp(cmd.s, "Login")) {
		if (c != ' ' || (c = getastring(&arg1)) != ' ') {
		    goto missingargs;
		}
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		
		if (imapd_userid) {
		    prot_printf(imapd_out, "%s BAD Already logged in\r\n", tag.s);
		    continue;
		}
		cmd_login(tag.s, arg1.s, arg2.s);
	    }
	    else if (!strcmp(cmd.s, "Logout")) {
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		
		prot_printf(imapd_out, "* BYE %s\r\n", error_message(IMAP_BYE_LOGOUT));
		prot_printf(imapd_out, "%s OK %s\r\n", tag.s, error_message(IMAP_OK_COMPLETED));
		shut_down(0);
	    }
	    else if (!imapd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "List")) {
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_list(tag.s, 0, arg1.s, arg2.s);
	    }
	    else if (!strcmp(cmd.s, "Lsub")) {
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_list(tag.s, 1, arg1.s, arg2.s);
	    }
	    else if (!strcmp(cmd.s, "Listrights")) {
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_listrights(tag.s, arg1.s, arg2.s);
	    }
	    else goto badcmd;
	    break;

	case 'M':
	    if (!strcmp(cmd.s, "Myrights")) {
		oldform = 0;
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (!strcasecmp(arg1.s, "mailbox")) {
		    oldform = 1;
		    if (c != ' ') goto missingargs;
		    c = getastring(&arg1);
		}
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_myrights(tag.s, arg1.s, oldform);
	    }
	    else goto badcmd;
	    break;

	case 'N':
	    if (!strcmp(cmd.s, "Noop")) {
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		mboxlist_close();	
		cmd_noop(tag.s, cmd.s);
	    }
#ifdef ENABLE_X_NETSCAPE_HACK
	    else if (!strcmp(cmd.s, "Netscape")) {
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_netscrape(tag.s);
	    }
#endif
	    else if (!imapd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "Namespace")) {
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_namespace(tag.s);
	    }
	    else goto badcmd;
	    break;

	case 'P':
	    if (!strcmp(cmd.s, "Partial")) {
		if (!imapd_mailbox) goto nomailbox;
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		c = getword(&arg2);
		if (c != ' ') goto missingargs;
		c = getword(&arg3);
		if (c != ' ') goto missingargs;
		c = getword(&arg4);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		mboxlist_close();	
		cmd_partial(tag.s, arg1.s, arg2.s, arg3.s, arg4.s);
	    }
	    else goto badcmd;
	    break;

	case 'R':
	    if (!strcmp(cmd.s, "Rename")) {
		havepartition = 0;
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == ' ') {
		    havepartition = 1;
		    c = getword(&arg3);
		    if (!imparse_isatom(arg3.s)) goto badpartition;
		}
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_rename(tag.s, arg1.s, arg2.s, havepartition ? arg3.s : 0);
	    }
	    else goto badcmd;
	    break;
	    
	case 'S':
	    if (!strcmp(cmd.s, "Starttls")) {
		if (!starttls_enabled()) {
		    /* we don't support starttls */
		    goto badcmd;
		}

		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		/* if we've already done SASL fail */
		if (imapd_userid != NULL) {
		    prot_printf(imapd_out, 
	       "%s BAD Can't Starttls after authentication\r\n", tag.s);
		    continue;
		}
		
		/* check if already did a successful tls */
		if (imapd_starttls_done == 1) {
		    prot_printf(imapd_out, 
				"%s BAD Already did a successful Starttls\r\n",
				tag.s);
		    continue;
		}
		cmd_starttls(tag.s);	      
		continue;
	    } else if (!imapd_userid) {
		goto nologin;
	    }
	    if (!imapd_userid) {
		goto nologin;
	    } else if (!strcmp(cmd.s, "Store")) {
		if (!imapd_mailbox) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    store:
		c = getword(&arg1);
		if (c != ' ' || !imparse_issequence(arg1.s)) goto badsequence;
		c = getword(&arg2);
		if (c != ' ') goto badsequence;
		mboxlist_close();	
		cmd_store(tag.s, arg1.s, arg2.s, usinguid);
	    }
	    else if (!strcmp(cmd.s, "Select")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		cmd_select(tag.s, cmd.s, arg1.s);
	    }
	    else if (!strcmp(cmd.s, "Search")) {
		if (!imapd_mailbox) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    search:
		mboxlist_close();	
		cmd_search(tag.s, usinguid);
	    }
	    else if (!strcmp(cmd.s, "Subscribe")) {
		if (c != ' ') goto missingargs;
		havenamespace = 0;
		c = getastring(&arg1);
		if (c == ' ') {
		    havenamespace = 1;
		    c = getastring(&arg2);
		}
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		if (havenamespace) {
		    cmd_changesub(tag.s, arg1.s, arg2.s, 1);
		}
		else {
		    cmd_changesub(tag.s, (char *)0, arg1.s, 1);
		}
	    }		
	    else if (!strcmp(cmd.s, "Setacl")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (!strcasecmp(arg1.s, "mailbox")) {
		    if (c != ' ') goto missingargs;
		    c = getastring(&arg1);
		}
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c != ' ') goto missingargs;
		c = getastring(&arg3);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_setacl(tag.s, arg1.s, arg2.s, arg3.s);
	    }
	    else if (!strcmp(cmd.s, "Setquota")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		cmd_setquota(tag.s, arg1.s);
	    }
	    else if (!strcmp(cmd.s, "Status")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		cmd_status(tag.s, arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'U':
	    if (!strcmp(cmd.s, "Uid")) {
		if (!imapd_mailbox) goto nomailbox;
		usinguid = 1;
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		lcase(arg1.s);
		if (!strcmp(arg1.s, "fetch")) {
		    goto fetch;
		}
		else if (!strcmp(arg1.s, "store")) {
		    goto store;
		}
		else if (!strcmp(arg1.s, "search")) {
		    goto search;
		}
		else if (!strcmp(arg1.s, "copy")) {
		    goto copy;
		}
		else if (!strcmp(arg1.s, "expunge")) {
		    c = getword(&arg1);
		    if (!imparse_issequence(arg1.s)) goto badsequence;
		    if (c == '\r') c = prot_getc(imapd_in);
		    if (c != '\n') goto extraargs;
		    cmd_expunge(tag.s, arg1.s);
		}
		else {
		    prot_printf(imapd_out, "%s BAD Unrecognized UID subcommand\r\n", tag.s);
		    eatline(c);
		}
	    }
	    else if (!strcmp(cmd.s, "Unsubscribe")) {
		if (c != ' ') goto missingargs;
		havenamespace = 0;
		c = getastring(&arg1);
		if (c == ' ') {
		    havenamespace = 1;
		    c = getastring(&arg2);
		}
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		if (havenamespace) {
		    cmd_changesub(tag.s, arg1.s, arg2.s, 0);
		}
		else {
		    cmd_changesub(tag.s, (char *)0, arg1.s, 0);
		}
	    }		
	    else if (!strcmp(cmd.s, "Unselect")) {
		if (!imapd_mailbox) goto nomailbox;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_unselect(tag.s);
	    }
	    else goto badcmd;
	    break;

	default:
	badcmd:
	    prot_printf(imapd_out, "%s BAD Unrecognized command\r\n", tag.s);
	    eatline(c);
	}

	continue;

    nologin:
	prot_printf(imapd_out, "%s BAD Please login first\r\n", tag.s);
	eatline(c);
	continue;

    nomailbox:
	prot_printf(imapd_out, "%s BAD Please select a mailbox first\r\n", tag.s);
	eatline(c);
	continue;

    missingargs:
	prot_printf(imapd_out, "%s BAD Missing required argument to %s\r\n", tag.s, cmd.s);
	eatline(c);
	continue;

    extraargs:
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to %s\r\n", tag.s, cmd.s);
	eatline(c);
	continue;

    badsequence:
	prot_printf(imapd_out, "%s BAD Invalid sequence in %s\r\n", tag.s, cmd.s);
	eatline(c);
	continue;

    badpartition:
	prot_printf(imapd_out, "%s BAD Invalid partition name in %s\r\n",
	       tag.s, cmd.s);
	eatline(c);
	continue;
    }
}

/*
 * Perform a LOGIN command
 */
void
cmd_login(tag, user, passwd)
char *tag;
char *user;
char *passwd;
{
    char *canon_user;
    const char *reply = 0;
    const char *val;
    char buf[MAX_MAILBOX_PATH];
    char *p;
    FILE *logfile;
    int plaintextloginpause;
    int result;

    canon_user = auth_canonifyid(user);

    /* possibly disallow login */
    if ((imapd_starttls_done == 0) &&
	(config_getswitch("allowplaintext", 1) == 0) &&
	strcmp(canon_user, "anonymous") != 0) {
	prot_printf(imapd_out, "%s NO Login only available under a layer\r\n",
		    tag, result);
	return;
    }

    if (!canon_user) {
	syslog(LOG_NOTICE, "badlogin: %s plaintext %s invalid user",
	       imapd_clienthost, beautify_string(user));
	prot_printf(imapd_out, "%s NO %s\r\n", tag, 
		    error_message(IMAP_INVALID_USER));
	return;
    }

    if (!strcmp(canon_user, "anonymous")) {
	if (config_getswitch("allowanonymouslogin", 0)) {
	    passwd = beautify_string(passwd);
	    if (strlen(passwd) > 500) passwd[500] = '\0';
	    syslog(LOG_NOTICE, "login: %s anonymous %s",
		   imapd_clienthost, passwd);
	    reply = "Anonymous access granted";
	    imapd_userid = xstrdup("anonymous");
	}
	else {
	    syslog(LOG_NOTICE, "badlogin: %s anonymous login refused",
		   imapd_clienthost);
	    prot_printf(imapd_out, "%s NO %s\r\n", tag,
		   error_message(IMAP_ANONYMOUS_NOT_PERMITTED));
	    return;
	}
    }
    else if ((result = sasl_checkpass(imapd_saslconn,
				      canon_user,
				      strlen(canon_user),
				      passwd,
				      strlen(passwd),
				      &reply)) != SASL_OK) { 
	if (reply) {
	    syslog(LOG_NOTICE, "badlogin: %s plaintext %s %s",
		   imapd_clienthost, canon_user, reply);
	}
	sleep(3);

	if (reply) {
	    prot_printf(imapd_out, "%s NO Login failed: %s\r\n", tag, reply);
	} else if (reply = sasl_errstring(result, NULL, NULL)) {
	    prot_printf(imapd_out, "%s NO Login failed: %s\r\n", tag, reply);
	} else {
	    prot_printf(imapd_out, "%s NO Login failed: %d\r\n", tag, result);
	}
	return;
    }
    else {
	imapd_userid = xstrdup(canon_user);
	syslog(LOG_NOTICE, "login: %s %s plaintext %s", imapd_clienthost,
	       canon_user, reply ? reply : "");
	if (plaintextloginpause = config_getint("plaintextloginpause", 0)) {
	    sleep(plaintextloginpause);
	}
    }
    

    imapd_authstate = auth_newstate(canon_user, (char *)0);

    val = config_getstring("admins", "");
    while (*val) {
	for (p = (char *)val; *p && !isspace(*p); p++);
	strncpy(buf, val, p - val);
	buf[p-val] = 0;
	if (auth_memberof(imapd_authstate, buf)) {
	    imapd_userisadmin = 1;
	    break;
	}
	val = p;
	while (*val && isspace(*val)) val++;
    }

    if (!reply) reply = "User logged in";

    /* Create telemetry log */
    sprintf(buf, "%s%s%s/%u", config_dir, FNAME_LOGDIR, imapd_userid,
	    getpid());
    logfile = fopen(buf, "w");
    if (logfile) {
	prot_setlog(imapd_in, fileno(logfile));
	prot_setlog(imapd_out, fileno(logfile));
	if (config_getswitch("logtimestamps", 0)) {
	    prot_setlogtime(imapd_in, &imapd_logtime);
	    prot_setlogtime(imapd_out, &imapd_logtime);
	}
    }

    prot_printf(imapd_out, "%s OK %s\r\n", tag, reply);
    return;
}

/*
 * Perform an AUTHENTICATE command
 */
void
cmd_authenticate(tag, authtype)
char *tag;
char *authtype;
{
    int sasl_result;
    static struct buf clientin;
    int clientinlen=0;
    
    char *serverout;
    unsigned int serveroutlen;
    const char *errstr;
    
    const char *errorstring = NULL;

    char buf[MAX_MAILBOX_PATH];
    FILE *logfile;

    int *ssfp;
    char *ssfmsg=NULL;

    sasl_result = sasl_server_start(imapd_saslconn, authtype,
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
      clientinlen = getbase64string(&clientin);
      if (clientinlen == -1) {
	prot_printf(imapd_out, "%s BAD Invalid base64 string\r\n", tag);
	return;
      }

      sasl_result = sasl_server_step(imapd_saslconn,
				     clientin.s,
				     clientinlen,
				     &serverout, &serveroutlen,
				     &errstr);
    }


    /* failed authentication */
    if (sasl_result != SASL_OK)
    {
	/* convert the sasl error code to a string */
	errorstring = sasl_errstring(sasl_result, NULL, NULL);
      
	syslog(LOG_NOTICE, "badlogin: %s %s %s",
	       imapd_clienthost, authtype, errorstring);
	
	if (errstr) {
	    syslog(LOG_NOTICE, "badlogin: %s %s %s",
		   imapd_clienthost, authtype, errstr);
	}
	
	sleep(3);
	
	if (errorstring) {
	    prot_printf(imapd_out, "%s NO %s\r\n", tag, errorstring);
	} else {
	    prot_printf(imapd_out, "%s NO Error authenticating\r\n", tag);
	}

	return;
    }

    /* successful authentication */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_authproc()
     */
    sasl_result = sasl_getprop(imapd_saslconn, SASL_USERNAME,
			     (void **) &imapd_userid);
    if (sasl_result!=SASL_OK)
    {
	prot_printf(imapd_out, "%s NO weird SASL error %d SASL_USERNAME\r\n", 
		    tag, sasl_result);
	syslog(LOG_ERR, "weird SASL error %d getting SASL_USERNAME", 
	       sasl_result);
	return;
    }

    proc_register("imapd", imapd_clienthost, imapd_userid, (char *)0);

    syslog(LOG_NOTICE, "login: %s %s %s %s", imapd_clienthost, imapd_userid,
	   authtype, "User logged in");

    sasl_getprop(imapd_saslconn, SASL_SSF, (void **) &ssfp);

    switch(*ssfp)
      {
      case 0: ssfmsg="no protection";break;
      case 1: ssfmsg="integrity protection";break;
      default: ssfmsg="privacy protection";break;
      }

    prot_printf(imapd_out, "%s OK Success (%s)\r\n", tag,ssfmsg);

    prot_setsasl(imapd_in,  imapd_saslconn);
    prot_setsasl(imapd_out, imapd_saslconn);

    /* Create telemetry log */
    sprintf(buf, "%s%s%s/%u", config_dir, FNAME_LOGDIR, imapd_userid,
	    getpid());
    logfile = fopen(buf, "w");
    if (logfile) {
	prot_setlog(imapd_in, fileno(logfile));
	prot_setlog(imapd_out, fileno(logfile));
	if (config_getswitch("logtimestamps", 0)) {
	    prot_setlogtime(imapd_in, &imapd_logtime);
	    prot_setlogtime(imapd_out, &imapd_logtime);
	}
    }

    return;
}

/*
 * Perform a NOOP command
 */
void
cmd_noop(tag, cmd)
char *tag;
char *cmd;
{
    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 1);
    }
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Parse and perform an ID command.
 *
 * the command has been parsed up to the parameter list.
 *
 * we only allow one ID in non-authenticated state from a given client.
 * we only allow MAXIDFAILED consecutive failed IDs from a given client.
 * we only record MAXIDLOG ID responses from a given client.
 *
 * the ID specification (draft-showalter-imap-id-03.txt) that i'm
 * working from says one thing and does another.  i'll do what i think
 * it means, which means that this is subject to change.  
 */
#define MAXIDFAILED	3
#define MAXIDLOG	5
#define MAXIDFIELDLEN	30
#define MAXIDVALUELEN	1024
#define MAXIDPAIRS	30

static char id_resp_command[MAXIDVALUELEN];
static char id_resp_arguments[MAXIDVALUELEN] = "";

void id_getcmdline(int argc, char **argv)
{
    snprintf(id_resp_command, MAXIDVALUELEN, *argv);
    while (--argc > 0) {
	snprintf(id_resp_arguments + strlen(id_resp_arguments),
		 MAXIDVALUELEN - strlen(id_resp_arguments),
		 "%s%s", *++argv, (argc > 1) ? " " : "");
    }
}

void cmd_id(char *tag)
{
    static int did_id = 0;
    static int failed_id = 0;
    static int logged_id = 0;
    int error = 0;
    int c, npair = 0;
    static struct buf arg, field;
    struct strlist *fields = 0, *values = 0;
    struct utsname os;

    /* check if we've already had an ID in non-authenticated state */
    if (!imapd_userid && did_id) {
	prot_printf(imapd_out,
		    "%s NO Only one Id allowed in non-authenticated state\r\n",
		    tag);
	eatline(c);
	return;
    }

    /* check if we've had too many failed IDs in a row */
    if (failed_id >= MAXIDFAILED) {
	prot_printf(imapd_out, "%s NO Too many (%u) invalid Id commands\r\n",
		    tag, failed_id);
	eatline(c);
	return;
    }

    /* ok, accept parameter list */
    c = getword(&arg);
    /* check for "NIL" or start of parameter list */
    if (strcasecmp(arg.s, "NIL") && c != '(') {
	prot_printf(imapd_out, "%s BAD Invalid parameter list in Id\r\n", tag);
	eatline(c);
	failed_id++;
	return;
    }

    /* parse parameter list */
    if (c == '(') {
	for (;;) {
	    if (c == ')') {
		/* end of string/value pairs */
		break;
	    }

	    /* get field name */
	    c = getstring(&field);
	    if (c != ' ') {
		prot_printf(imapd_out,
			    "%s BAD Invalid/missing field name in Id\r\n",
			    tag);
		error = 1;
		break;
	    }

	    /* get field value */
	    c = getnstring(&arg);
	    if (c != ' ' && c != ')') {
		prot_printf(imapd_out,
			    "%s BAD Invalid/missing value in Id\r\n",
			    tag);
		error = 1;
		break;
	    }

	    /* ok, we're anal, but we'll still process the ID command */
	    if (strlen(field.s) > MAXIDFIELDLEN) {
		prot_printf(imapd_out, 
			    "%s BAD field longer than %u octets in Id\r\n",
			    tag, MAXIDFIELDLEN);
		error = 1;
		break;
	    }
	    if (strlen(arg.s) > MAXIDVALUELEN) {
		prot_printf(imapd_out,
			    "%s BAD value longer than %u octets in Id\r\n",
			    tag, MAXIDVALUELEN);
		error = 1;
		break;
	    }
	    if (++npair > MAXIDPAIRS) {
		prot_printf(imapd_out,
			    "%s BAD too many (%u) field-value pairs in ID\r\n",
			    tag, MAXIDPAIRS);
		error = 1;
		break;
	    }
	    
	    /* ok, we're happy enough */
	    appendstrlist(&fields, field.s);
	    appendstrlist(&values, arg.s);
	}

	if (error || c != ')') {
	    /* erp! */
	    eatline(c);
	    freestrlist(fields);
	    freestrlist(values);
	    failed_id++;
	    return;
	}
	c = prot_getc(imapd_in);
    }

    /* check for CRLF */
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out,
		    "%s BAD Unexpected extra arguments to Id\r\n", tag);
	eatline(c);
	freestrlist(fields);
	freestrlist(values);
	failed_id++;
	return;
    }

    /* log the client's ID string.
       eventually this should be a callback or something. */
    if (npair && logged_id < MAXIDLOG) {
#define LOGSTR	"client id:"
	char logbuf[strlen(LOGSTR) +
		   MAXIDPAIRS * (MAXIDFIELDLEN + MAXIDVALUELEN + 6)];
	struct strlist *fptr, *vptr;

	strcpy(logbuf, LOGSTR);
	for (fptr = fields, vptr = values; fptr;
	     fptr = fptr->next, vptr = vptr->next) {
	    /* should we check for and format literals here ??? */
	    sprintf(logbuf+strlen(logbuf), " \"%s\" ", fptr->s);
	    if (!strcmp(vptr->s, "NIL"))
		sprintf(logbuf+strlen(logbuf), "NIL");
	    else
		sprintf(logbuf+strlen(logbuf), "\"%s\"", vptr->s);
	}

	syslog(LOG_INFO, "%s", logbuf);

	logged_id++;
    }

    freestrlist(fields);
    freestrlist(values);

    /* spit out our ID string.
       eventually this might be configurable. */
    if (config_getswitch("imapidresponse", 1)) {
	char env_buf[MAXIDVALUELEN];

	prot_printf(imapd_out, "* ID ("
		    "\"name\" \"Cyrus\""
		    " \"version\" \"%s\""
		    " \"vendor\" \"Project Cyrus\""
		    " \"support-url\" \"http://asg.web.cmu.edu/cyrus\"",
		    CYRUS_VERSION);

	/* add the os info */
	if (uname(&os) != -1)
	    prot_printf(imapd_out,
			" \"os\" \"%s\""
			" \"os-version\" \"%s\"",
			os.sysname, os.release);

	/* add the command line info */
	prot_printf(imapd_out, " \"command\" \"%s\"", id_resp_command);
	if (strlen(id_resp_arguments))
	    prot_printf(imapd_out, " \"arguments\" \"%s\"", id_resp_arguments);
	else
	    prot_printf(imapd_out, " \"arguments\" NIL");

	/* add the environment info */
	snprintf(env_buf, MAXIDVALUELEN,"Cyrus SASL %d.%d.%d",
		 SASL_VERSION_MAJOR, SASL_VERSION_MINOR, SASL_VERSION_STEP);
#ifdef DB_VERSION_STRING
	snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
		 "; %s", DB_VERSION_STRING);
#endif
#ifdef HAVE_SSL
	snprintf(env_buf + strlen(env_buf), MAXIDVALUELEN - strlen(env_buf),
		 "; %s", OPENSSL_VERSION_TEXT);
#endif
	prot_printf(imapd_out, " \"environment\" \"%s\")\r\n", env_buf);
    }
    else
	prot_printf(imapd_out, "* ID NIL\r\n");

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));

    failed_id = 0;
    did_id = 1;
}

/*
 * Perform a CAPABILITY command
 */
void
cmd_capability(tag)
char *tag;
{
    char *sasllist; /* the list of SASL mechanisms */
    unsigned mechcount;

    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 0);
    }
    prot_printf(imapd_out,
     "* CAPABILITY IMAP4 IMAP4rev1 ACL QUOTA LITERAL+ NAMESPACE UIDPLUS");
    /* XXX */
    prot_printf(imapd_out,
		" X-NON-HIERARCHICAL-RENAME NO_ATOMIC_RENAME");
    if (starttls_enabled()) {
	prot_printf(imapd_out, " STARTTLS");
    }
    if ((imapd_starttls_done == 0) &&
	(config_getswitch("allowplaintext", 1)==0))
    {
      prot_printf(imapd_out, " LOGINDISABLED");	
    }      
    /* add the SASL mechs */
    if (sasl_listmech(imapd_saslconn, NULL, 
		      "AUTH=", " AUTH=", "",
		      &sasllist,
		      NULL, &mechcount) == SASL_OK && mechcount > 0) {
	prot_printf(imapd_out, " %s", sasllist);      
	free(sasllist);
    } else {
	/* else don't show anything */
    }

    prot_printf(imapd_out, " UNSELECT ID");
#ifdef ENABLE_X_NETSCAPE_HACK
    prot_printf(imapd_out, " X-NETSCAPE");
#endif
    prot_printf(imapd_out, "\r\n%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Parse and perform an APPEND command.
 * The command has been parsed up to and including
 * the mailbox name.
 */
#define FLAGGROW 10
void
cmd_append(tag, name)
char *tag;
char *name;
{
    int c;
    char **flag = 0;
    int nflags = 0, flagalloc = 0;
    static struct buf arg;
    char *p;
    time_t internaldate = time(0);
    unsigned size = 0;
    int sawdigit = 0;
    int isnowait = 0;
    int r;
    char mailboxname[MAX_MAILBOX_NAME+1];
    struct mailbox mailbox;
    unsigned long uidvalidity, newuid;

    /* Parse flags */
    c = getword(&arg);
    if  (c == '(' && !arg.s[0]) {
	do {
	    c = getword(&arg);
	    if (arg.s[0] == '\\') {
		lcase(arg.s);
		if (strcmp(arg.s, "\\seen") && strcmp(arg.s, "\\answered") &&
		    strcmp(arg.s, "\\flagged") && strcmp(arg.s, "\\draft") &&
		    strcmp(arg.s, "\\deleted")) {
		    prot_printf(imapd_out, "%s BAD Invalid system flag in Append command\r\n",tag);
		    eatline(c);
		    goto freeflags;
		}
	    }
	    else if (!imparse_isatom(arg.s)) {
		if (!nflags && !arg.s[0] && c == ')') break; /* empty list */
		prot_printf(imapd_out, "%s BAD Invalid flag name %s in Append command\r\n",
			    tag, arg.s);
		eatline(c);
		goto freeflags;
	    }
	    if (nflags == flagalloc) {
		flagalloc += FLAGGROW;
		flag = (char **)xrealloc((char *)flag, flagalloc*sizeof(char *));
	    }
	    flag[nflags++] = xstrdup(arg.s);
	} while (c == ' ');
	if (c != ')') {
	    prot_printf(imapd_out,
	    "%s BAD Missing space or ) after flag name in Append command\r\n",
			tag);
	    eatline(c);
	    goto freeflags;
	}
	c = prot_getc(imapd_in);
	if (c != ' ') {
	    prot_printf(imapd_out,
		  "%s BAD Missing space after flag list in Append command\r\n",
			tag);
	    eatline(c);
	    goto freeflags;
	}
	c = getword(&arg);
    }

    /* Parse internaldate */
    if (c == '\"' && !arg.s[0]) {
	prot_ungetc(c, imapd_in);
	c = getdatetime(&internaldate);
	if (c != ' ') {
	    prot_printf(imapd_out, "%s BAD Invalid date-time in Append command\r\n", tag);
	    eatline(c);
	    goto freeflags;
	}
	c = getword(&arg);
    }

    if (arg.s[0] != '{') {
	prot_printf(imapd_out, "%s BAD Missing required argument to Append command\r\n",
	       tag);
	eatline(c);
	goto freeflags;
    }

    /* Read size from literal */
    for (p = arg.s + 1; *p && isdigit(*p); p++) {
	sawdigit++;
	size = size*10 + *p - '0';
    }
    if (*p == '+') {
	isnowait++;
	p++;
    }

    if (c == '\r') {
	c = prot_getc(imapd_in);
    }
    else {
	prot_ungetc(c, imapd_in);
	c = ' ';		/* Force a syntax error */
    }

    if (*p != '}' || p[1] || c != '\n' || !sawdigit) {
	prot_printf(imapd_out, "%s BAD Invalid literal in Append command\r\n", tag);
	eatline(c);
	goto freeflags;
    }
    if (size < 2) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag,
		    error_message(IMAP_MESSAGE_NOBLANKLINE));
	eatline(c);
	goto freeflags;
    }

    /* Set up the append */
    r = mboxname_tointernal(name, imapd_userid, mailboxname);
    if (!r) {
	r = append_setup(&mailbox, mailboxname, MAILBOX_FORMAT_NORMAL,
			 imapd_authstate, ACL_INSERT, size);
    }
    if (r) {
	if (isnowait) {
	    /* Eat message and trailing newline */
	    while (size--) c = prot_getc(imapd_in);
	    eatline(' ');
	}
	    
	prot_printf(imapd_out, "%s NO %s%s\r\n",
	       tag,
	       (r == IMAP_MAILBOX_NONEXISTENT &&
		mboxlist_createmailboxcheck(mailboxname, 0, 0,
					    imapd_userisadmin,
					    imapd_userid, imapd_authstate,
					    (char **)0, (char **)0) == 0)
	       ? "[TRYCREATE] " : "", error_message(r));
	goto freeflags;
    }

    if (!isnowait) {
	/* Tell client to send the message */
	prot_printf(imapd_out, "+ go ahead\r\n");
	prot_flush(imapd_out);
    }

    /* Perform the rest of the append */
    r = append_fromstream(&mailbox, imapd_in, size, internaldate, flag, nflags,
			  imapd_userid);
    uidvalidity = mailbox.uidvalidity;
    newuid = mailbox.last_uid;
    mailbox_close(&mailbox);

    /* Parse newline terminating command */
    c = prot_getc(imapd_in);
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	if (c == EOF) return;
	prot_printf(imapd_out, "* BAD Junk after literal in APPEND command\r\n");
	eatline(c);
    }

    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 0);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK [APPENDUID %u %u] %s\r\n", tag,
		    uidvalidity, newuid,
		    error_message(IMAP_OK_COMPLETED));
    }

 freeflags:
    while (nflags--) {
	free(flag[nflags]);
    }
    if (flag) free((char *)flag);
}

/*
 * Perform a SELECT/EXAMINE/BBOARD command
 */
void
cmd_select(tag, cmd, name)
char *tag;
char *cmd;
char *name;
{
    struct mailbox mailbox;
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r = 0;
    double usage;
    int doclose = 0;

    if (imapd_mailbox) {
	index_closemailbox(imapd_mailbox);
	mailbox_close(imapd_mailbox);
	imapd_mailbox = 0;
    }

    if (cmd[0] == 'B') {
	/* BBoard namespace is empty */
	r = IMAP_MAILBOX_NONEXISTENT;
    }
    else {
	r = mboxname_tointernal(name, imapd_userid, mailboxname);
    }

    if (!r) {
	r = mailbox_open_header(mailboxname, imapd_authstate, &mailbox);
    }

    if (!r) {
	doclose = 1;
	r = mailbox_open_index(&mailbox);
    }
    if (!r && !(mailbox.myrights & ACL_READ)) {
	r = (imapd_userisadmin || (mailbox.myrights & ACL_LOOKUP)) ?
	  IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
    }
    if (!r && chdir(mailbox.path)) {
	syslog(LOG_ERR, "IOERROR: changing directory to %s: %m", mailbox.path);
	r = IMAP_IOERROR;
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	if (doclose) mailbox_close(&mailbox);
	return;
    }

    if (mailbox.format == MAILBOX_FORMAT_NETNEWS) {
	(void) mailbox_expungenews(&mailbox);
    }

    mboxstruct = mailbox;
    imapd_mailbox = &mboxstruct;

    index_newmailbox(imapd_mailbox, cmd[0] == 'E');

    /* Examine command puts mailbox in read-only mode */
    if (cmd[0] == 'E') {
	imapd_mailbox->myrights &= ~(ACL_SEEN|ACL_WRITE|ACL_DELETE);
    }

    if (imapd_mailbox->myrights & ACL_DELETE) {
	/* Warn if mailbox is close to or over quota */
	mailbox_read_quota(&imapd_mailbox->quota);
	if (imapd_mailbox->quota.limit > 0) {
	    usage = ((double) imapd_mailbox->quota.used * 100.0) / (double)
		(imapd_mailbox->quota.limit * QUOTA_UNITS);
	    if (usage >= 100.0) {
		prot_printf(imapd_out, "* NO [ALERT] %s\r\n",
			    error_message(IMAP_NO_OVERQUOTA));
	    }
	    else if (usage > config_getint("quotawarn", 90)) {
		int usageint = (int) usage;
		prot_printf(imapd_out, "* NO [ALERT] ");
		prot_printf(imapd_out, error_message(IMAP_NO_CLOSEQUOTA),
			    usageint);
		prot_printf(imapd_out, "\r\n");
	    }
	}
    }

    prot_printf(imapd_out, "%s OK [READ-%s] %s\r\n", tag,
	   (imapd_mailbox->myrights & (ACL_WRITE|ACL_DELETE)) ?
		"WRITE" : "ONLY", error_message(IMAP_OK_COMPLETED));

    proc_register("imapd", imapd_clienthost, imapd_userid, mailboxname);
    syslog(LOG_DEBUG, "open: user %s opened %s", imapd_userid, name);
}
	  
/*
 * Perform a CLOSE command
 */
void
cmd_close(tag)
char *tag;
{
    int r;

    if (!(imapd_mailbox->myrights & ACL_DELETE)) r = 0;
    else {
	r = mailbox_expunge(imapd_mailbox, 1, (int (*)())0, (char *)0);
    }

    index_closemailbox(imapd_mailbox);
    mailbox_close(imapd_mailbox);
    imapd_mailbox = 0;

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }
}    

/*
 * Perform an UNSELECT command -- for some support of IMAP proxy.
 * Just like close except no expunge.
 */
void
cmd_unselect(tag)
char* tag;
{
    index_closemailbox(imapd_mailbox);
    mailbox_close(imapd_mailbox);
    imapd_mailbox = 0;

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Parse and perform a FETCH/UID FETCH command
 * The command has been parsed up to and including
 * the sequence
 */
void
cmd_fetch(tag, sequence, usinguid)
char *tag;
char *sequence;
int usinguid;
{
    char *cmd = usinguid ? "UID Fetch" : "Fetch";
    static struct buf fetchatt, fieldname;
    int c, i;
    int inlist = 0;
    int fetchitems = 0;
    struct fetchargs fetchargs;
    struct strlist *newfields = 0;
    char *p, *section;
    int fetchedsomething;

    fetchargs = zerofetchargs;

    c = getword(&fetchatt);
    if (c == '(' && !fetchatt.s[0]) {
	inlist = 1;
	c = getword(&fetchatt);
    }
    for (;;) {
	ucase(fetchatt.s);
	switch (fetchatt.s[0]) {
	case 'A':
	    if (!inlist && !strcmp(fetchatt.s, "ALL")) {
		fetchitems |= FETCH_ALL;
	    }
	    else goto badatt;
	    break;

	case 'B':
	    if (!strcmp(fetchatt.s, "BODY")) {
		fetchitems |= FETCH_BODY;
	    }
	    else if (!strcmp(fetchatt.s, "BODYSTRUCTURE")) {
		fetchitems |= FETCH_BODYSTRUCTURE;
	    }
	    else if (!strncmp(fetchatt.s, "BODY[", 5) ||
		     !strncmp(fetchatt.s, "BODY.PEEK[", 10)) {
		p = section = fetchatt.s + 5;
		if (*p == 'P') {
		    p = section += 5;
		}
		else {
		    fetchitems |= FETCH_SETSEEN;
		}
		while (isdigit(*p) || *p == '.') {
		    if (*p == '.' && !isdigit(p[-1])) break;
		    /* Obsolete section 0 can only occur before close brace */
		    if (*p == '0' && !isdigit(p[-1]) && p[1] != ']') break;
		    p++;
		}

		if (*p == 'H' && !strncmp(p, "HEADER.FIELDS", 13) &&
		    (p == section || p[-1] == '.') &&
		    (p[13] == '\0' || !strcmp(p+13, ".NOT"))) {

		    /*
		     * If not top-level or a HEADER.FIELDS.NOT, can't pull
		     * the headers out of the cache.
		     */
		    if (p != section || p[13] != '\0') {
			fetchitems |= FETCH_UNCACHEDHEADER;
		    }

		    if (c != ' ') {
			prot_printf(imapd_out,
				    "%s BAD Missing required argument to %s %s\r\n",
				    tag, cmd, fetchatt.s);
			eatline(c);
			goto freeargs;
		    }
		    c = prot_getc(imapd_in);
		    if (c != '(') {
			prot_printf(imapd_out, "%s BAD Missing required open parenthesis in %s %s\r\n",
				    tag, cmd, fetchatt.s);
			eatline(c);
			goto freeargs;
		    }
		    do {
			c = getastring(&fieldname);
			for (p = fieldname.s; *p; p++) {
			    if (*p <= ' ' || *p & 0x80 || *p == ':') break;
			}
			if (*p || !*fieldname.s) {
			    prot_printf(imapd_out, "%s BAD Invalid field-name in %s %s\r\n",
					tag, cmd, fetchatt.s);
			    eatline(c);
			    goto freeargs;
			}
			appendstrlist(&newfields, fieldname.s);
			if (!(fetchitems & FETCH_UNCACHEDHEADER)) {
			    for (i=0; i<mailbox_num_cache_header; i++) {
				if (!strcasecmp(mailbox_cache_header_name[i],
						fieldname.s)) break;
			    }
			    if (i == mailbox_num_cache_header) {
				fetchitems |= FETCH_UNCACHEDHEADER;
			    }
			}
		    } while (c == ' ');
		    if (c != ')') {
			prot_printf(imapd_out, "%s BAD Missing required close parenthesis in %s %s\r\n",
				    tag, cmd, fetchatt.s);
			eatline(c);
			goto freeargs;
		    }

		    /* Grab/parse the ]<x.y> part */
		    c = getword(&fieldname);
		    p = fieldname.s;
		    if (*p++ != ']') {
			prot_printf(imapd_out, "%s BAD Missing required close bracket after %s %s\r\n",
				    tag, cmd, fetchatt.s);
			eatline(c);
			goto freeargs;
		    }
		    if (*p == '<' && isdigit(p[1])) {
			p += 2;
			while (isdigit(*p)) p++;

			if (*p == '.' && p[1] >= '1' && p[1] <= '9') {
			    p += 2;
			    while (isdigit(*p)) p++;
			}
			else p--;

			if (*p != '>') {
			    prot_printf(imapd_out, "%s BAD Invalid body partial\r\n", tag);
			    eatline(c);
			    goto freeargs;
			}
			p++;
		    }
		    if (*p) {
			prot_printf(imapd_out, "%s BAD Junk after body section\r\n", tag);
			eatline(c);
			goto freeargs;
		    }
		    appendfieldlist(&fetchargs.fsections,
				    section, newfields, fieldname.s);
		    newfields = 0;
		    break;
		}

		switch (*p) {
		case 'H':
		    if (p != section && p[-1] != '.') break;
		    if (!strncmp(p, "HEADER]", 7)) p += 6;
		    break;

		case 'M':
		    if (!strncmp(p-1, ".MIME]", 6)) p += 4;
		    break;

		case 'T':
		    if (p != section && p[-1] != '.') break;
		    if (!strncmp(p, "TEXT]", 5)) p += 4;
		    break;
		}

		if (*p != ']') {
		    prot_printf(imapd_out, "%s BAD Invalid body section\r\n", tag);
		    eatline(c);
		    goto freeargs;
		}
		p++;
		if (*p == '<' && isdigit(p[1])) {
		    p += 2;
		    while (isdigit(*p)) p++;

		    if (*p == '.' && p[1] >= '1' && p[1] <= '9') {
			p += 2;
			while (isdigit(*p)) p++;
		    }
		    else p--;

		    if (*p != '>') {
			prot_printf(imapd_out, "%s BAD Invalid body partial\r\n", tag);
			eatline(c);
			goto freeargs;
		    }
		    p++;
		}

		if (*p) {
		    prot_printf(imapd_out, "%s BAD Junk after body section\r\n", tag);
		    eatline(c);
		    goto freeargs;
		}
		appendstrlist(&fetchargs.bodysections, section);
	    }
	    else goto badatt;
	    break;

	case 'E':
	    if (!strcmp(fetchatt.s, "ENVELOPE")) {
		fetchitems |= FETCH_ENVELOPE;
	    }
	    else goto badatt;
	    break;

	case 'F':
	    if (!inlist && !strcmp(fetchatt.s, "FAST")) {
		fetchitems |= FETCH_FAST;
	    }
	    else if (!inlist && !strcmp(fetchatt.s, "FULL")) {
		fetchitems |= FETCH_FULL;
	    }
	    else if (!strcmp(fetchatt.s, "FLAGS")) {
		fetchitems |= FETCH_FLAGS;
	    }
	    else goto badatt;
	    break;

	case 'I':
	    if (!strcmp(fetchatt.s, "INTERNALDATE")) {
		fetchitems |= FETCH_INTERNALDATE;
	    }
	    else goto badatt;
	    break;

	case 'R':
	    if (!strcmp(fetchatt.s, "RFC822")) {
		fetchitems |= FETCH_RFC822|FETCH_SETSEEN;
	    }
	    else if (!strcmp(fetchatt.s, "RFC822.HEADER")) {
		fetchitems |= FETCH_HEADER;
	    }
	    else if (!strcmp(fetchatt.s, "RFC822.PEEK")) {
		fetchitems |= FETCH_RFC822;
	    }
	    else if (!strcmp(fetchatt.s, "RFC822.SIZE")) {
		fetchitems |= FETCH_SIZE;
	    }
	    else if (!strcmp(fetchatt.s, "RFC822.TEXT")) {
		fetchitems |= FETCH_TEXT|FETCH_SETSEEN;
	    }
	    else if (!strcmp(fetchatt.s, "RFC822.TEXT.PEEK")) {
		fetchitems |= FETCH_TEXT;
	    }
	    else if (!strcmp(fetchatt.s, "RFC822.HEADER.LINES") ||
		     !strcmp(fetchatt.s, "RFC822.HEADER.LINES.NOT")) {
		if (c != ' ') {
		    prot_printf(imapd_out, "%s BAD Missing required argument to %s %s\r\n",
			   tag, cmd, fetchatt.s);
		    eatline(c);
		    goto freeargs;
		}
		c = prot_getc(imapd_in);
		if (c != '(') {
		    prot_printf(imapd_out, "%s BAD Missing required open parenthesis in %s %s\r\n",
			   tag, cmd, fetchatt.s);
		    eatline(c);
		    goto freeargs;
		}
		do {
		    c = getastring(&fieldname);
		    for (p = fieldname.s; *p; p++) {
			if (*p <= ' ' || *p & 0x80 || *p == ':') break;
		    }
		    if (*p || !*fieldname.s) {
			prot_printf(imapd_out, "%s BAD Invalid field-name in %s %s\r\n",
			       tag, cmd, fetchatt.s);
			eatline(c);
			goto freeargs;
		    }
		    lcase(fieldname.s);;
		    appendstrlist(strlen(fetchatt.s) == 19 ?
				  &fetchargs.headers : &fetchargs.headers_not,
				  fieldname.s);
		    if (strlen(fetchatt.s) != 19) {
			fetchitems |= FETCH_UNCACHEDHEADER;
		    }
		    if (!(fetchitems & FETCH_UNCACHEDHEADER)) {
			for (i=0; i<mailbox_num_cache_header; i++) {
			    if (!strcmp(mailbox_cache_header_name[i],
					fieldname.s)) break;
			}
			if (i == mailbox_num_cache_header) {
			    fetchitems |= FETCH_UNCACHEDHEADER;
			}
		   }
		} while (c == ' ');
		if (c != ')') {
		    prot_printf(imapd_out, "%s BAD Missing required close parenthesis in %s %s\r\n",
			   tag, cmd, fetchatt.s);
		    eatline(c);
		    goto freeargs;
		}
		c = prot_getc(imapd_in);
	    }
	    else goto badatt;
	    break;

	case 'U':
	    if (!strcmp(fetchatt.s, "UID")) {
		fetchitems |= FETCH_UID;
	    }
	    else goto badatt;
	    break;

	default:
	badatt:
	    prot_printf(imapd_out, "%s BAD Invalid %s attribute %s\r\n", tag, cmd, fetchatt.s);
	    eatline(c);
	    goto freeargs;
	}

	if (inlist && c == ' ') c = getword(&fetchatt);
	else break;
    }
    
    if (inlist && c == ')') {
	inlist = 0;
	c = prot_getc(imapd_in);
    }
    if (inlist) {
	prot_printf(imapd_out, "%s BAD Missing close parenthesis in %s\r\n", tag, cmd);
	eatline(c);
	goto freeargs;
    }
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to %s\r\n", tag, cmd);
	eatline(c);
	goto freeargs;
    }

    if (!fetchitems && !fetchargs.bodysections && !fetchargs.fsections &&
	!fetchargs.headers && !fetchargs.headers_not) {
	prot_printf(imapd_out, "%s BAD Missing required argument to %s\r\n", tag, cmd);
	goto freeargs;
    }

    if (usinguid) {
	fetchitems |= FETCH_UID;
	index_check(imapd_mailbox, 1, 0);
    }

    fetchargs.fetchitems = fetchitems;
    index_fetch(imapd_mailbox, sequence, usinguid, &fetchargs,
		&fetchedsomething);

    if (fetchedsomething || usinguid) {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    } else {
	/* normal FETCH, nothing came back */
	prot_printf(imapd_out, "%s NO %s\r\n", tag,
		    error_message(IMAP_NO_NOSUCHMSG));
    }

 freeargs:
    freestrlist(newfields);
    freestrlist(fetchargs.bodysections);
    freefieldlist(fetchargs.fsections);
    freestrlist(fetchargs.headers);
    freestrlist(fetchargs.headers_not);
}

/*
 * Perform a PARTIAL command
 */
void
cmd_partial(tag, msgno, data, start, count)
char *tag;
char *msgno;
char *data;
char *start;
char *count;
{
    char *p;
    struct fetchargs fetchargs;
    char *section;
    int fetchedsomething;

    fetchargs = zerofetchargs;

    for (p = msgno; *p; p++) {
	if (!isdigit(*p)) break;
    }
    if (*p || !*msgno) {
	prot_printf(imapd_out, "%s BAD Invalid message number\r\n", tag);
	return;
    }

    lcase(data);
    if (!strcmp(data, "rfc822")) {
	fetchargs.fetchitems = FETCH_RFC822|FETCH_SETSEEN;
    }
    else if (!strcmp(data, "rfc822.header")) {
	fetchargs.fetchitems = FETCH_HEADER;
    }
    else if (!strcmp(data, "rfc822.peek")) {
	fetchargs.fetchitems = FETCH_RFC822;
    }
    else if (!strcmp(data, "rfc822.text")) {
	fetchargs.fetchitems = FETCH_TEXT|FETCH_SETSEEN;
    }
    else if (!strcmp(data, "rfc822.text.peek")) {
	fetchargs.fetchitems = FETCH_TEXT;
    }
    else if (!strncmp(data, "body[", 5) ||
	     !strncmp(data, "body.peek[", 10)) {
	p = section = data + 5;
	if (*p == 'p') {
	    p = section += 5;
	}
	else {
	    fetchargs.fetchitems = FETCH_SETSEEN;
	}
	while (isdigit(*p) || *p == '.') {
	    if (*p == '.' && (p == section || !isdigit(p[1]))) break;
	    p++;
	}
	if (p == section || *p != ']' || p[1]) {
	    prot_printf(imapd_out, "%s BAD Invalid body section\r\n", tag);
	    freestrlist(fetchargs.bodysections);
	    return;
	}
	*p = '\0';
	appendstrlist(&fetchargs.bodysections, section);
    }
    else {
	prot_printf(imapd_out, "%s BAD Invalid Partial item\r\n", tag);
	freestrlist(fetchargs.bodysections);
	return;
    }

    for (p = start; *p; p++) {
	if (!isdigit(*p)) break;
	fetchargs.start_octet = fetchargs.start_octet*10 + *p - '0';
    }
    if (*p || !fetchargs.start_octet) {
	prot_printf(imapd_out, "%s BAD Invalid starting octet\r\n", tag);
	freestrlist(fetchargs.bodysections);
	return;
    }
    
    for (p = count; *p; p++) {
	if (!isdigit(*p)) break;
	fetchargs.octet_count = fetchargs.octet_count*10 + *p - '0';
    }
    if (*p || !*count) {
	prot_printf(imapd_out, "%s BAD Invalid octet count\r\n", tag);
	freestrlist(fetchargs.bodysections);
	return;
    }

    index_fetch(imapd_mailbox, msgno, 0, &fetchargs, &fetchedsomething);

    index_check(imapd_mailbox, 0, 0);

    if (fetchedsomething) {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    } else {
	prot_printf(imapd_out,
		    "%s BAD Invalid sequence in PARTIAL command\r\n",
		    tag);
    }

    freestrlist(fetchargs.bodysections);
}

/*
 * Parse and perform a STORE/UID STORE command
 * The command has been parsed up to and including
 * the FLAGS/+FLAGS/-FLAGS
 */
void
cmd_store(tag, sequence, operation, usinguid)
char *tag;
char *sequence;
char *operation;
int usinguid;
{
    char *cmd = usinguid ? "UID Store" : "Store";
    struct storeargs storeargs;
    static struct storeargs zerostoreargs;
    static struct buf flagname;
    int len, c;
    char **flag = 0;
    int nflags = 0, flagalloc = 0;
    int flagsparsed = 0, inlist = 0;
    int r;

    storeargs = zerostoreargs;

    lcase(operation);

    len = strlen(operation);
    if (len > 7 && !strcmp(operation+len-7, ".silent")) {
	storeargs.silent = 1;
	operation[len-7] = '\0';
    }
    
    if (!strcmp(operation, "+flags")) {
	storeargs.operation = STORE_ADD;
    }
    else if (!strcmp(operation, "-flags")) {
	storeargs.operation = STORE_REMOVE;
    }
    else if (!strcmp(operation, "flags")) {
	storeargs.operation = STORE_REPLACE;
    }
    else {
	prot_printf(imapd_out, "%s BAD Invalid %s attribute\r\n", tag, cmd);
	eatline(' ');
	return;
    }

    for (;;) {
	c = getword(&flagname);
	if (c == '(' && !flagname.s[0] && !flagsparsed && !inlist) {
	    inlist = 1;
	    continue;
	}

	if (flagname.s[0] == '\\') {
	    lcase(flagname.s);
	    if (!strcmp(flagname.s, "\\seen")) {
		storeargs.seen = 1;
	    }
	    else if (!strcmp(flagname.s, "\\answered")) {
		storeargs.system_flags |= FLAG_ANSWERED;
	    }
	    else if (!strcmp(flagname.s, "\\flagged")) {
		storeargs.system_flags |= FLAG_FLAGGED;
	    }
	    else if (!strcmp(flagname.s, "\\deleted")) {
		storeargs.system_flags |= FLAG_DELETED;
	    }
	    else if (!strcmp(flagname.s, "\\draft")) {
		storeargs.system_flags |= FLAG_DRAFT;
	    }
	    else {
		prot_printf(imapd_out, "%s BAD Invalid system flag in %s command\r\n",
		       tag, cmd);
		eatline(c);
		goto freeflags;
	    }
	}
	else if (!imparse_isatom(flagname.s)) {
	    prot_printf(imapd_out, "%s BAD Invalid flag name %s in %s command\r\n",
		   tag, flagname.s, cmd);
	    eatline(c);
	    goto freeflags;
	}
	else {
	    if (nflags == flagalloc) {
		flagalloc += FLAGGROW;
		flag = (char **)xrealloc((char *)flag,
					 flagalloc*sizeof(char *));
	    }
	    flag[nflags++] = xstrdup(flagname.s);
	}

	flagsparsed++;
	if (c != ' ') break;
    }

    if (inlist && c == ')') {
	inlist = 0;
	c = prot_getc(imapd_in);
    }
    if (inlist) {
	prot_printf(imapd_out, "%s BAD Missing close parenthesis in %s\r\n", tag, cmd);
	eatline(c);
	return;
    }
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to %s\r\n", tag, cmd);
	eatline(c);
	return;
    }

    if (!flagsparsed) {
	prot_printf(imapd_out, "%s BAD Missing required argument to %s\r\n", tag, cmd);
	return;
    }

    r = index_store(imapd_mailbox, sequence, usinguid, &storeargs,
		    flag, nflags);
	
    if (usinguid) {
	index_check(imapd_mailbox, 1, 0);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }

 freeflags:
    while (nflags--) {
	free(flag[nflags]);
    }
    if (flag) free((char *)flag);
}

void
cmd_search(tag, usinguid)
char *tag;
int usinguid;
{
    int c;
    int charset = 0;
    struct searchargs *searchargs;
    static struct searchargs zerosearchargs;

    searchargs = (struct searchargs *)xmalloc(sizeof(struct searchargs));
    *searchargs = zerosearchargs;

    c = getsearchprogram(tag, searchargs, &charset, 1);
    if (c == EOF) {
	eatline(' ');
	freesearchargs(searchargs);
	return;
    }

    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to Search\r\n", tag);
	eatline(c);
	freesearchargs(searchargs);
	return;
    }

    if (charset == -1) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag,
	       error_message(IMAP_UNRECOGNIZED_CHARSET));
    }
    else {
	index_search(imapd_mailbox, searchargs, usinguid);
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }

    freesearchargs(searchargs);
}

/*
 * Perform a COPY/UID COPY command
 */    
void
cmd_copy(tag, sequence, name, usinguid)
char *tag;
char *sequence;
char *name;
int usinguid;
{
    int r;
    char mailboxname[MAX_MAILBOX_NAME+1];
    char *copyuid;

    r = mboxname_tointernal(name, imapd_userid, mailboxname);
    if (!r) {
	r = index_copy(imapd_mailbox, sequence, usinguid, mailboxname,
		       &copyuid);
    }

    index_check(imapd_mailbox, usinguid, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s%s\r\n", tag,
		    (r == IMAP_MAILBOX_NONEXISTENT &&
		     mboxlist_createmailboxcheck(mailboxname, 0, 0,
						 imapd_userisadmin,
						 imapd_userid, imapd_authstate,
						 (char **)0, (char **)0) == 0)
		    ? "[TRYCREATE] " : "", error_message(r));
    }
    else {
	if (copyuid) {
	    prot_printf(imapd_out, "%s OK [COPYUID %s] %s\r\n", tag,
			copyuid, error_message(IMAP_OK_COMPLETED));
	    free(copyuid);
	}
	else if (usinguid) {
	    prot_printf(imapd_out, "%s OK %s\r\n", tag,
			error_message(IMAP_OK_COMPLETED));
	}
	else {
	    /* normal COPY, message doesn't exist */
	    prot_printf(imapd_out, "%s NO %s\r\n", tag,
			error_message(IMAP_NO_NOSUCHMSG));
	}
    }
}    

/*
 * Perform an EXPUNGE command
 */
void
cmd_expunge(tag, sequence)
char *tag;
char *sequence;
{
    int r;

    if (!(imapd_mailbox->myrights & ACL_DELETE)) r = IMAP_PERMISSION_DENIED;
    else if (sequence) {
	r = mailbox_expunge(imapd_mailbox, 1, index_expungeuidlist, sequence);
    }
    else {
	r = mailbox_expunge(imapd_mailbox, 1, (mailbox_decideproc_t *)0,
			    (void *)0);
    }

    index_check(imapd_mailbox, 0, 0);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }
}    

/*
 * Perform a CREATE command
 */
void
cmd_create(tag, name, partition)
char *tag;
char *name;
char *partition;
{
    int r = 0;
    char mailboxname[MAX_MAILBOX_NAME+1];
    int autocreatequota;

    if (partition && !imapd_userisadmin) {
	r = IMAP_PERMISSION_DENIED;
    }

    if (name[0] && name[strlen(name)-1] == '.') {
	/* We don't care about trailing hierarchy delimiters. */
	name[strlen(name)-1] = '\0';
    }

    if (!r) {
	r = mboxname_tointernal(name, imapd_userid, mailboxname);
    }

    if (!r) {
	r = mboxlist_createmailbox(mailboxname, MAILBOX_FORMAT_NORMAL, partition,
				   imapd_userisadmin, imapd_userid, imapd_authstate);

	if (r == IMAP_PERMISSION_DENIED && !strcasecmp(name, "INBOX") &&
	    (autocreatequota = config_getint("autocreatequota", 0))) {

	    /* Auto create */
	    r = mboxlist_createmailbox(mailboxname, MAILBOX_FORMAT_NORMAL,
				       partition, 1, imapd_userid, imapd_authstate);
	    
	    if (!r && autocreatequota > 0) {
		(void) mboxlist_setquota(mailboxname, autocreatequota);
	    }
	}
    }

    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 0);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }
}	

/*
 * Perform a DELETE command
 */
void
cmd_delete(tag, name)
char *tag;
char *name;
{
    int r;
    char mailboxname[MAX_MAILBOX_NAME+1];

    r = mboxname_tointernal(name, imapd_userid, mailboxname);

    if (!r) {
	r = mboxlist_deletemailbox(mailboxname, imapd_userisadmin,
				   imapd_userid, imapd_authstate, 1);
    }

    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 0);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }
}	

/*
 * Perform a RENAME command
 */
void
cmd_rename(tag, oldname, newname, partition)
char *tag;
char *oldname;
char *newname;
char *partition;
{
    int r;
    char oldmailboxname[MAX_MAILBOX_NAME+1];
    char newmailboxname[MAX_MAILBOX_NAME+1];


    if (partition && !imapd_userisadmin) {
	r = IMAP_PERMISSION_DENIED;
    }
    else {
	r = mboxname_tointernal(oldname, imapd_userid, oldmailboxname);
    }

    if (!r) {
	r = mboxname_tointernal(newname, imapd_userid, newmailboxname);
    }

    if (!r) {
	r = mboxlist_renamemailbox(oldmailboxname, newmailboxname, partition,
				   imapd_userisadmin, imapd_userid, imapd_authstate);
    }

    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 0);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }
}	

/*
 * Perform a FIND command
 */
void
cmd_find(tag, namespace, pattern)
char *tag;
char *namespace;
char *pattern;
{
    char *p;
    lcase(namespace);

    for (p = pattern; *p; p++) {
	if (*p == '%') *p = '?';
    }

    if (!strcmp(namespace, "mailboxes")) {
	mboxlist_findsub(pattern, imapd_userisadmin, imapd_userid, imapd_authstate,
			 mailboxdata);
    }
    else if (!strcmp(namespace, "all.mailboxes")) {
	mboxlist_findall(pattern, imapd_userisadmin, imapd_userid,
			 imapd_authstate, mailboxdata, NULL);
    }
    else if (!strcmp(namespace, "bboards")
	     || !strcmp(namespace, "all.bboards")) {
	;
    }
    else {
	prot_printf(imapd_out, "%s BAD Invalid FIND subcommand\r\n", tag);
	return;
    }
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Perform a LIST or LSUB command
 */
void
cmd_list(tag, subscribed, reference, pattern)
char *tag;
int subscribed;
char *reference;
char *pattern;
{
    char *buf = NULL;
    int patlen = 0;
    int reflen = 0;
    static int ignorereference = 0;

    /* Ignore the reference argument?
       (the behavior in 1.5.10 & older) */
    if (ignorereference == 0) {
	ignorereference = config_getswitch("ignorereference", 0);
    }

    /* Reset state in mstringdata */
    mstringdata(NULL, NULL, 0, 0);
    
    if (!pattern[0] && !subscribed) {
	/* Special case: query top-level hierarchy separator */
	prot_printf(imapd_out, "* LIST (\\Noselect) \".\" \"\"\r\n");
    } else {
	/* Do we need to concatenate fields? */
	if (!ignorereference || pattern[0] == '.') {
	    /* Either
	     * - name begins with dot
	     * - we're configured to honor the reference argument */

	    /* Allocate a buffer, figure out how to stick the arguments
	       together, do it, then do that instead of using pattern. */
	    patlen = strlen(pattern);
	    reflen = strlen(reference);
	    
	    buf = xmalloc(patlen + reflen + 1);
	    buf[0] = '\0';

	    if (*reference) {
		/* check for LIST A. .B, change to LIST "" A.B */
		if (reference[reflen-1] == '.' && pattern[0] == '.') {
		    reference[--reflen] = '\0';
		}
		strcpy(buf, reference);
	    }
	    strcat(buf, pattern);
	    pattern = buf;
	}

	if (subscribed) {
	    mboxlist_findsub(pattern, imapd_userisadmin, imapd_userid,
			     imapd_authstate, lsubdata, NULL);
	    lsubdata((char *)0, 0, 0, 0);
	}
	else {
	    mboxlist_findall(pattern, imapd_userisadmin, imapd_userid,
			     imapd_authstate, listdata, NULL);
	    listdata((char *)0, 0, 0, 0);
	}

	if (buf) free(buf);
    }
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}
  
/*
 * Perform a SUBSCRIBE (add is nonzero) or
 * UNSUBSCRIBE (add is zero) command
 */
void
cmd_changesub(tag, namespace, name, add)
char *tag;
char *namespace;
char *name;
int add;
{
    int r;
    char mailboxname[MAX_MAILBOX_NAME+1];

    if (namespace) lcase(namespace);
    if (!namespace || !strcmp(namespace, "mailbox")) {
	r = mboxname_tointernal(name, imapd_userid, mailboxname);
	if (!r) {
	    r = mboxlist_changesub(mailboxname, imapd_userid, imapd_authstate, add);
	}
    }
    else if (!strcmp(namespace, "bboard")) {
	r = add ? IMAP_MAILBOX_NONEXISTENT : 0;
    }
    else {
	prot_printf(imapd_out, "%s BAD Invalid %s subcommand\r\n", tag,
	       add ? "Subscribe" : "Unsubscribe");
	return;
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s: %s\r\n", tag,
	       add ? "Subscribe" : "Unsubscribe", error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }
}

/*
 * Perform a GETACL command
 */
void
cmd_getacl(tag, name, oldform)
char *tag;
char *name;
int oldform;
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r, access;
    char *acl;
    char *rights, *nextid;

    r = mboxname_tointernal(name, imapd_userid, mailboxname);

    if (!r) {
	r = mboxlist_lookup(mailboxname, (char **)0, &acl);
    }

    if (!r) {
	access = acl_myrights(imapd_authstate, acl);

	if (!(access & (ACL_READ|ACL_ADMIN)) &&
	    !imapd_userisadmin &&
	    !mboxname_userownsmailbox(imapd_userid, mailboxname)) {
	    r = (access&ACL_LOOKUP) ?
	      IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	}
    }
    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    if (oldform) {
	while (acl) {
	    rights = strchr(acl, '\t');
	    if (!rights) break;
	    *rights++ = '\0';

	    nextid = strchr(rights, '\t');
	    if (!nextid) break;
	    *nextid++ = '\0';

	    prot_printf(imapd_out, "* ACL MAILBOX ");
	    printastring(name);
	    prot_printf(imapd_out, " ");
	    printastring(acl);
	    prot_printf(imapd_out, " ");
	    printastring(rights);
	    prot_printf(imapd_out, "\r\n");
	    acl = nextid;
	}
    }
    else {
	prot_printf(imapd_out, "* ACL ");
	printastring(name);
	
	while (acl) {
	    rights = strchr(acl, '\t');
	    if (!rights) break;
	    *rights++ = '\0';

	    nextid = strchr(rights, '\t');
	    if (!nextid) break;
	    *nextid++ = '\0';

	    prot_printf(imapd_out, " ");
	    printastring(acl);
	    prot_printf(imapd_out, " ");
	    printastring(rights);
	    acl = nextid;
	}
	prot_printf(imapd_out, "\r\n");
    }
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Perform a LISTRIGHTS command
 */
void
cmd_listrights(tag, name, identifier)
char *tag;
char *name;
char *identifier;
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r, rights;
    char *canon_identifier;
    int canonidlen;
    char *acl;
    char *rightsdesc;

    r = mboxname_tointernal(name, imapd_userid, mailboxname);

    if (!r) {
	r = mboxlist_lookup(mailboxname, (char **)0, &acl);
    }

    if (!r) {
	rights = acl_myrights(imapd_authstate, acl);

	if (!rights && !imapd_userisadmin &&
	    !mboxname_userownsmailbox(imapd_userid, mailboxname)) {
	    r = IMAP_MAILBOX_NONEXISTENT;
	}
    }

    if (!r) {
	canon_identifier = auth_canonifyid(identifier);
	if (canon_identifier) canonidlen = strlen(canon_identifier);

	if (!canon_identifier) {
	    rightsdesc = "\"\"";
	}
	else if (!strncmp(mailboxname, "user.", 5) &&
		 !strchr(canon_identifier, '.') &&
		 !strncmp(mailboxname+5, canon_identifier, canonidlen) &&
		 (mailboxname[5+canonidlen] == '\0' ||
		  mailboxname[5+canonidlen] == '.')) {
	    rightsdesc = "lca r s w i p d 0 1 2 3 4 5 6 7 8 9";
	}
	else {
	    rightsdesc = "\"\" l r s w i p c d a 0 1 2 3 4 5 6 7 8 9";
	}

	prot_printf(imapd_out, "* LISTRIGHTS ");
	printastring(name);
	prot_putc(' ', imapd_out);
	printastring(identifier);
	prot_printf(imapd_out, " %s", rightsdesc);

	prot_printf(imapd_out, "\r\n%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
	return;
    }

    prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
}

/*
 * Perform a MYRIGHTS command
 */
void
cmd_myrights(tag, name, oldform)
char *tag;
char *name;
int oldform;
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r, rights;
    char *acl;
    char str[ACL_MAXSTR];

    r = mboxname_tointernal(name, imapd_userid, mailboxname);

    if (!r) {
	r = mboxlist_lookup(mailboxname, (char **)0, &acl);
    }

    if (!r) {
	rights = acl_myrights(imapd_authstate, acl);

	/* Add in implicit rights */
	if (imapd_userisadmin ||
	    mboxname_userownsmailbox(imapd_userid, mailboxname)) {
	    rights |= ACL_LOOKUP|ACL_ADMIN;
	}

	if (!rights) {
	    r = IMAP_MAILBOX_NONEXISTENT;
	}
    }
    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "* MYRIGHTS ");
    if (oldform) prot_printf(imapd_out, "MAILBOX ");
    printastring(name);
    prot_printf(imapd_out, " ");
    printastring(acl_masktostr(rights, str));
    prot_printf(imapd_out, "\r\n%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Perform a SETACL command
 */
void
cmd_setacl(tag, name, identifier, rights)
char *tag;
char *name;
char *identifier;
char *rights;
{
    int r;
    char mailboxname[MAX_MAILBOX_NAME+1];

    r = mboxname_tointernal(name, imapd_userid, mailboxname);

    if (!r) {
	r = mboxlist_setacl(mailboxname, identifier, rights,
			    imapd_userisadmin, imapd_userid, imapd_authstate);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Perform a GETQUOTA command
 */
void
cmd_getquota(tag, name)
char *tag;
char *name;
{
    int r;
    struct quota quota;
    char buf[MAX_MAILBOX_PATH];

    quota.root = name;
    quota.fd = -1;

    if (!imapd_userisadmin) r = IMAP_PERMISSION_DENIED;
    else {
	mailbox_hash_quota(buf, quota.root);
	quota.fd = open(buf, O_RDWR, 0);
	if (quota.fd == -1) {
	    r = IMAP_QUOTAROOT_NONEXISTENT;
	}
	else {
	    r = mailbox_read_quota(&quota);
	}
    }
    
    if (!r) {
	prot_printf(imapd_out, "* QUOTA ");
	printastring(quota.root);
	prot_printf(imapd_out, " (");
	if (quota.limit >= 0) {
	    prot_printf(imapd_out, "STORAGE %u %d",
			quota.used/QUOTA_UNITS, quota.limit);
	}
	prot_printf(imapd_out, ")\r\n");
    }

    if (quota.fd != -1) {
	close(quota.fd);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}


/*
 * Perform a GETQUOTAROOT command
 */
void
cmd_getquotaroot(tag, name)
char *tag;
char *name;
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    struct mailbox mailbox;
    int r;
    int doclose = 0;

    r = mboxname_tointernal(name, imapd_userid, mailboxname);

    if (!r) {
	r = mailbox_open_header(mailboxname, imapd_authstate, &mailbox);
    }

    if (!r) {
	doclose = 1;
	if (!imapd_userisadmin && !(mailbox.myrights & ACL_READ)) {
	    r = (mailbox.myrights & ACL_LOOKUP) ?
	      IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	}
    }

    if (!r) {
	prot_printf(imapd_out, "* QUOTAROOT ");
	printastring(name);
	if (mailbox.quota.root) {
	    prot_printf(imapd_out, " ");
	    printastring(mailbox.quota.root);
	    r = mailbox_read_quota(&mailbox.quota);
	    if (!r) {
		prot_printf(imapd_out, "\r\n* QUOTA ");
		printastring(mailbox.quota.root);
		prot_printf(imapd_out, " (");
		if (mailbox.quota.limit >= 0) {
		    prot_printf(imapd_out, "STORAGE %u %d",
				mailbox.quota.used/QUOTA_UNITS,
				mailbox.quota.limit);
		}
		prot_putc(')', imapd_out);
	    }
	}
	prot_printf(imapd_out, "\r\n");
    }

    if (doclose) mailbox_close(&mailbox);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Parse and perform a SETQUOTA command
 * The command has been parsed up to the resource list
 */
void
cmd_setquota(tag, quotaroot)
char *tag;
char *quotaroot;
{
    int newquota = -1;
    int badresource = 0;
    int c;
    static struct buf arg;
    char *p;
    int r;

    c = prot_getc(imapd_in);
    if (c != '(') goto badlist;

    c = getword(&arg);
    if (c != ')' || arg.s[0] != '\0') {
	for (;;) {
	    if (c != ' ') goto badlist;
	    if (strcasecmp(arg.s, "storage") != 0) badresource = 1;
	    c = getword(&arg);
	    if (c != ' ' && c != ')') goto badlist;
	    if (arg.s[0] == '\0') goto badlist;
	    newquota = 0;
	    for (p = arg.s; *p; p++) {
		if (!isdigit(*p)) goto badlist;
		newquota = newquota * 10 + *p - '0';
	    }
	    if (c == ')') break;
	}
    }
    c = prot_getc(imapd_in);
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to SETQUOTA\r\n", tag);
	eatline(c);
	return;
    }

    if (badresource) r = IMAP_UNSUPPORTED_QUOTA;
    else if (!imapd_userisadmin) r = IMAP_PERMISSION_DENIED;
    else {
	r = mboxlist_setquota(quotaroot, newquota);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
    return;

 badlist:
    prot_printf(imapd_out, "%s BAD Invalid quota list in Setquota\r\n", tag);
    eatline(c);
}

#ifdef HAVE_SSL
/*
 * this implements the STARTTLS command, as described in RFC 2595.
 * one caveat: it assumes that no external layer is currently present.
 * if a client executes this command, information about the external
 * layer that was passed on the command line is disgarded. this should
 * be fixed.
 */
int starttls_enabled(void)
{
    if (config_getstring("tls_ca_file", NULL) == NULL) return 0;
    if (config_getstring("tls_ca_path", NULL) == NULL) return 0;
    return 1;
}

void cmd_starttls(char *tag)
{
    int result;
    int *layerp;
    sasl_external_properties_t external;

    /* SASL and openssl have different ideas about whether ssf is signed */
    layerp = (int *) &(external.ssf);

    if (imapd_starttls_done == 1)
    {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, 
		    "Already successfully executed STARTTLS");
	return;
    }

    result=tls_init_serverengine(5,        /* depth to verify */
				 1,        /* can client auth? */
				 0,        /* required client to auth? */
				 (char *)config_getstring("tls_ca_file", ""),
				 (char *)config_getstring("tls_ca_path", ""),
				 (char *)config_getstring("tls_cert_file", ""),
				 (char *)config_getstring("tls_key_file", ""));

    if (result == -1) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, "Error initializing TLS");
	syslog(LOG_ERR, "error initializing TLS: "
	       "[CA_file: %s] [CA_path: %s] [cert_file: %s] [key_file: %s]",
	       (char *) config_getstring("tls_CA_file", ""),
	       (char *) config_getstring("tls_CA_path", ""),
	       (char *) config_getstring("tls_cert_file", ""),
	       (char *) config_getstring("tls_key_file", ""));
	prot_printf(imapd_out, "%s NO %s\r\n", tag, 
		    error_message(IMAP_IOERROR));
	return;
    }

    prot_printf(imapd_out, "%s OK %s\r\n", tag,	"Begin TLS negotiation now");
    /* must flush our buffers before starting tls */
    prot_flush(imapd_out);
  
    result=tls_start_servertls(0, /* read */
			       1, /* write */
			       layerp,
			       &(external.auth_id));
    if (result==-1) {
	prot_printf(imapd_out, "%s NO Starttls failed\r\n", tag);
	syslog(LOG_NOTICE, "STARTTLS failed: %s", imapd_clienthost);
	return;
    }

    /* tell SASL about the negotiated layer */
    result = sasl_setprop(imapd_saslconn, SASL_SSF_EXTERNAL, &external);

    if (result != SASL_OK) {
	fatal("sasl_setprop() failed: cmd_starttls()", EC_TEMPFAIL);
    }

    /* if authenticated set that */
    if (external.auth_id != NULL) {
	imapd_userid = external.auth_id;
    }

    /* tell the prot layer about our new layers */
    prot_settls(imapd_in, tls_conn);
    prot_settls(imapd_out, tls_conn);

    imapd_starttls_done = 1;
}
#else
int starttls_enabled(void)
{
    return 0;
}

void cmd_starttls(char *tag)
{
    fatal("cmd_starttls() executed, but starttls isn't implemented!",
	  EC_SOFTWARE);
}
#endif /* HAVE_SSL */

/*
 * Parse and perform a STATUS command
 * The command has been parsed up to the attribute list
 */
void
cmd_status(tag, name)
char *tag;
char *name;
{
    int c;
    int statusitems = 0;
    static struct buf arg;
    struct mailbox mailbox;
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r = 0;
    int doclose = 0;

    c = prot_getc(imapd_in);
    if (c != '(') goto badlist;

    c = getword(&arg);
    if (arg.s[0] == '\0') goto badlist;
    for (;;) {
	lcase(arg.s);
	if (!strcmp(arg.s, "messages")) {
	    statusitems |= STATUS_MESSAGES;
	}
	else if (!strcmp(arg.s, "recent")) {
	    statusitems |= STATUS_RECENT;
	}
	else if (!strcmp(arg.s, "uidnext")) {
	    statusitems |= STATUS_UIDNEXT;
	}
	else if (!strcmp(arg.s, "uidvalidity")) {
	    statusitems |= STATUS_UIDVALIDITY;
	}
	else if (!strcmp(arg.s, "unseen")) {
	    statusitems |= STATUS_UNSEEN;
	}
	else {
	    prot_printf(imapd_out, "%s BAD Invalid Status attribute %s\r\n",
			tag, arg.s);
	    eatline(c);
	    return;
	}
	    
	if (c == ' ') c = getword(&arg);
	else break;
    }

    if (c != ')') {
	prot_printf(imapd_out,
		    "%s BAD Missing close parenthesis in Status\r\n", tag);
	eatline(c);
	return;
    }

    c = prot_getc(imapd_in);
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out,
		    "%s BAD Unexpected extra arguments to Status\r\n", tag);
	eatline(c);
	return;
    }

    /*
     * Perform a full checkpoint of any open mailbox, in case we're
     * doing a STATUS check of the current mailbox.
     */
    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 1);
    }

    r = mboxname_tointernal(name, imapd_userid, mailboxname);

    if (!r) {
	r = mailbox_open_header(mailboxname, imapd_authstate, &mailbox);
    }

    if (!r) {
	doclose = 1;
	r = mailbox_open_index(&mailbox);
    }
    if (!r && !(mailbox.myrights & ACL_READ)) {
	r = (imapd_userisadmin || (mailbox.myrights & ACL_LOOKUP)) ?
	  IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
    }

    if (!r) {
	r = index_status(&mailbox, name, statusitems);
    }

    if (doclose) mailbox_close(&mailbox);
    
    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
    return;

 badlist:
    prot_printf(imapd_out, "%s BAD Invalid status list in Status\r\n", tag);
    eatline(c);
}

#ifdef ENABLE_EXPERIMENT_OPTIMIZE_1
/* This extension has been superceded by UIDPLUS and therefore this code
 * is not used. */
/*
 * Perform a GETUIDS command
 */
void
cmd_getuids(tag, startuid)
char *tag;
char *startuid;
{
    char *p;
    unsigned uid = 0;

    for (p = startuid; *p; p++) {
	if (!isdigit(*p)) break;
	uid = uid * 10 + *p - '0';
    }
    if (*p || !uid) {
	prot_printf(imapd_out, "%s BAD Invalid UID\r\n", tag);
	return;
    }

    index_check(imapd_mailbox, 0, 0);

    index_getuids(imapd_mailbox, uid);

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}
#endif /* ENABLE_EXPERIMENT_OPTIMIZE_1 */

#ifdef ENABLE_X_NETSCAPE_HACK
/*
 * Reply to Netscape's crock with a crock of my own
 */
void
cmd_netscrape(tag)
    char *tag;
{
    const char *url;
    /* so tempting, and yet ... */
    /* url = "http://random.yahoo.com/ryl/"; */
    url = config_getstring("netscapeurl",
			   "http://andrew2.andrew.cmu.edu/cyrus/imapd/netscape-admin.html");

    /* I only know of three things to reply with: */
    prot_printf(imapd_out,
"* OK [NETSCAPE] Carnegie Mellon Cyrus IMAP\r\n* VERSION %s\r\n",
		CYRUS_VERSION);
    prot_printf(imapd_out,
		"* ACCOUNT-URL %s\r\n%s OK %s\r\n",
		url, tag, error_message(IMAP_OK_COMPLETED));
}
#endif /* ENABLE_X_NETSCAPE_HACK */

/* Callback for cmd_namespace to be passed to mboxlist_findall.
 * For each top-level mailbox found, print a bit of the response
 * if it is a shared namespace.  The rock is used as an integer in
 * order to ensure the namespace response is correct on a server with
 * no shared namespace.
 */
/* locations to set if the user can see a given namespace */
#define NAMESPACE_INBOX  0
#define NAMESPACE_USER   1
#define NAMESPACE_SHARED 2
static int namespacedata(name, matchlen, maycreate, rock)
    char* name;
    int matchlen;
    int maycreate;
    void* rock;
{
    int* sawone = (int*) rock;

    if (!name) {
	return 0;
    }
    
    if (!(strncmp(name, "INBOX.", 6))) {
	/* The user has a "personal" namespace. */
	sawone[NAMESPACE_INBOX] = 1;
    } else if (!(strncmp(name, "user.", 5))) {
	/* The user can see the "other users" namespace. */
	sawone[NAMESPACE_USER] = 1;
    } else {
	/* The user can see the "shared" namespace. */
	sawone[NAMESPACE_SHARED] = 1;
    }

    return 0;
}

/*
 * Print out a response to the NAMESPACE command defined by
 * RFC 2342.
 */
void cmd_namespace(tag)
    char* tag;
{
    int sawone[3] = {0, 0, 0};
    char* pattern = xstrdup("%");

    /* now find all the exciting toplevel namespaces */
    mboxlist_findall(pattern, imapd_userisadmin, imapd_userid,
		     imapd_authstate, namespacedata, (void*) sawone);

    prot_printf(imapd_out, "* NAMESPACE %s %s %s\r\n",
		(sawone[NAMESPACE_INBOX]) ? "((\"INBOX.\" \".\"))" : "NIL",
		(sawone[NAMESPACE_USER]) ? "((\"user.\" \".\"))" : "NIL",
		(sawone[NAMESPACE_SHARED]) ? "((\"\" \".\"))" : "NIL");

    prot_printf(imapd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
    free(pattern);
}

/*
 * Parse a word
 * (token not containing whitespace, parens, or double quotes)
 */
#define BUFGROWSIZE 100
int getword(buf)
struct buf *buf;
{
    int c;
    int len = 0;

    if (buf->alloc == 0) {
	buf->alloc = BUFGROWSIZE;
	buf->s = xmalloc(buf->alloc+1);
    }
	
    for (;;) {
	c = prot_getc(imapd_in);
	if (c == EOF || isspace(c) || c == '(' || c == ')' || c == '\"') {
	    buf->s[len] = '\0';
	    return c;
	}
	if (len == buf->alloc) {
	    buf->alloc += BUFGROWSIZE;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
	}
	buf->s[len++] = c;
    }
}

/*
 * Parse an xstring
 * (astring, nstring or string based on type)
 */
int getxstring(buf, type)
struct buf *buf;
int type;
{
    int c;
    int i, len = 0;
    int sawdigit = 0;
    int isnowait;

    if (buf->alloc == 0) {
	buf->alloc = BUFGROWSIZE;
	buf->s = xmalloc(buf->alloc+1);
    }
	
    c = prot_getc(imapd_in);
    switch (c) {
    default:
	switch (type) {
	case IMAP_ASTRING:	 /* atom, quoted-string or literal */
	    /*
	     * Atom -- server is liberal in accepting specials other
	     * than whitespace, parens, or double quotes
	     */
	    for (;;) {
		if (c == EOF || isspace(c) || c == '(' || c == ')' || c == '\"') {
		    buf->s[len] = '\0';
		    return c;
		}
		if (len == buf->alloc) {
		    buf->alloc += BUFGROWSIZE;
		    buf->s = xrealloc(buf->s, buf->alloc+1);
		}
		buf->s[len++] = c;
		c = prot_getc(imapd_in);
	    }
	    break;

	case IMAP_NSTRING:	 /* "NIL", quoted-string or literal */
	    /*
	     * Look for "NIL"
	     */
	    if (c == 'N') {
		prot_ungetc(c, imapd_in);
		c = getword(buf);
		if (!strcmp(buf->s, "NIL"))
		    return c;
	    }
	    if (c != EOF) prot_ungetc(c, imapd_in);
	    return EOF;
	    break;

	case IMAP_STRING:	 /* quoted-string or literal */
	    /*
	     * Nothing to do here - fall through.
	     */
	    break;
	}
	
    case EOF:
    case ' ':
    case '(':
    case ')':
    case '\r':
    case '\n':
	/* Invalid starting character */
	buf->s[0] = '\0';
	if (c != EOF) prot_ungetc(c, imapd_in);
	return EOF;

    case '\"':
	/*
	 * Quoted-string.  Server is liberal in accepting qspecials
	 * other than double-quote, CR, and LF.
	 */
	for (;;) {
	    c = prot_getc(imapd_in);
	    if (c == '\\') {
		c = prot_getc(imapd_in);
	    }
	    else if (c == '\"') {
		buf->s[len] = '\0';
		return prot_getc(imapd_in);
	    }
	    else if (c == EOF || c == '\r' || c == '\n') {
		buf->s[len] = '\0';
		if (c != EOF) prot_ungetc(c, imapd_in);
		return EOF;
	    }
	    if (len == buf->alloc) {
		buf->alloc += BUFGROWSIZE;
		buf->s = xrealloc(buf->s, buf->alloc+1);
	    }
	    buf->s[len++] = c;
	}
    case '{':
	/* Literal */
	isnowait = 0;
	buf->s[0] = '\0';
	while ((c = prot_getc(imapd_in)) != EOF && isdigit(c)) {
	    sawdigit = 1;
	    len = len*10 + c - '0';
	}
	if (c == '+') {
	    isnowait++;
	    c = prot_getc(imapd_in);
	}
	if (!sawdigit || c != '}') {
	    if (c != EOF) prot_ungetc(c, imapd_in);
	    return EOF;
	}
	c = prot_getc(imapd_in);
	if (c != '\r') {
	    if (c != EOF) prot_ungetc(c, imapd_in);
	    return EOF;
	}
	c = prot_getc(imapd_in);
	if (c != '\n') {
	    if (c != EOF) prot_ungetc(c, imapd_in);
	    return EOF;
	}
	if (len >= buf->alloc) {
	    buf->alloc = len+1;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
	}
	if (!isnowait) {
	    prot_printf(imapd_out, "+ go ahead\r\n");
	    prot_flush(imapd_out);
	}
	for (i = 0; i < len; i++) {
	    c = prot_getc(imapd_in);
	    if (c == EOF) {
		buf->s[len] = '\0';
		return EOF;
	    }
	    buf->s[i] = c;
	}
	buf->s[len] = '\0';
	if (strlen(buf->s) != len) return EOF; /* Disallow imbedded NUL */
	return prot_getc(imapd_in);
    }
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

/*
 * Parse a base64_string
 */
int getbase64string(buf)
struct buf *buf;
{
    int c1, c2, c3, c4;
    int len = 0;

    if (buf->alloc == 0) {
	buf->alloc = BUFGROWSIZE;
	buf->s = xmalloc(buf->alloc+1);
    }
	
    for (;;) {
	c1 = prot_getc(imapd_in);
	if (c1 == '\r') {
	    c1 = prot_getc(imapd_in);
	    if (c1 != '\n') {
		eatline(c1);
		return -1;
	    }
	    return len;
	}
	else if (c1 == '\n') return len;

	if (CHAR64(c1) == XX) {
	    eatline(c1);
	    return -1;
	}
	
	c2 = prot_getc(imapd_in);
	if (CHAR64(c2) == XX) {
	    eatline(c2);
	    return -1;
	}

	c3 = prot_getc(imapd_in);
	if (c3 != '=' && CHAR64(c3) == XX) {
	    eatline(c3);
	    return -1;
	}

	c4 = prot_getc(imapd_in);
	if (c4 != '=' && CHAR64(c4) == XX) {
	    eatline(c4);
	    return -1;
	}

	if (len+3 >= buf->alloc) {
	    buf->alloc = len+BUFGROWSIZE;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
	}

	buf->s[len++] = ((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
	if (c3 == '=') {
	    c1 = prot_getc(imapd_in);
	    if (c1 == '\r') c1 = prot_getc(imapd_in);
	    if (c1 != '\n') {
		eatline(c1);
		return -1;
	    }
	    if (c4 != '=') return -1;
	    return len;
	}
	buf->s[len++] = (((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
	if (c4 == '=') {
	    c1 = prot_getc(imapd_in);
	    if (c1 == '\r') c1 = prot_getc(imapd_in);
	    if (c1 != '\n') {
		eatline(c1);
		return -1;
	    }
	    return len;
	}
	buf->s[len++] = (((CHAR64(c3)&0x3)<<6) | CHAR64(c4));
    }
}

/*
 * Parse a search program
 */
int getsearchprogram(tag, searchargs, charset, parsecharset)
char *tag;
struct searchargs *searchargs;
int *charset;
int parsecharset;
{
    int c;

    do {
	c = getsearchcriteria(tag, searchargs, charset, parsecharset);
	parsecharset = 0;
    } while (c == ' ');
    return c;
}

/*
 * Parse a search criteria
 */
int getsearchcriteria(tag, searchargs, charset, parsecharset)
char *tag;
struct searchargs *searchargs;
int *charset;
int parsecharset;
{
    static struct buf criteria, arg;
    static struct searchargs zerosearchargs;
    struct searchargs *sub1, *sub2;
    char *p, *str;
    int i, c, flag, size;
    time_t start, end;

    c = getword(&criteria);
    lcase(criteria.s);
    switch (criteria.s[0]) {
    case '\0':
	if (c != '(') goto badcri;
	c = getsearchprogram(tag, searchargs, charset, 0);
	if (c == EOF) return EOF;
	if (c != ')') {
	    prot_printf(imapd_out, "%s BAD Missing required close paren in Search command\r\n",
		   tag);
	    if (c != EOF) prot_ungetc(c, imapd_in);
	    return EOF;
	}
	c = prot_getc(imapd_in);
	break;

    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case '*':
	if (imparse_issequence(criteria.s)) {
	    appendstrlist(&searchargs->sequence, criteria.s);
	}
	else goto badcri;
	break;

    case 'a':
	if (!strcmp(criteria.s, "answered")) {
	    searchargs->system_flags_set |= FLAG_ANSWERED;
	}
	else if (!strcmp(criteria.s, "all")) {
	    break;
	}
	else goto badcri;
	break;

    case 'b':
	if (!strcmp(criteria.s, "before")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->before || searchargs->before > start) {
		searchargs->before = start;
	    }
	}
	else if (!strcmp(criteria.s, "bcc")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->bcc, str);
	    }
	}
	else if (!strcmp(criteria.s, "body")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->body, str);
	    }
	}
	else goto badcri;
	break;

    case 'c':
	if (!strcmp(criteria.s, "cc")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->cc, str);
	    }
	}
	else if (parsecharset && !strcmp(criteria.s, "charset")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c != ' ') goto missingarg;
	    lcase(arg.s);
	    *charset = charset_lookupname(arg.s);
	}
	else goto badcri;
	break;

    case 'd':
	if (!strcmp(criteria.s, "deleted")) {
	    searchargs->system_flags_set |= FLAG_DELETED;
	}
	else if (!strcmp(criteria.s, "draft")) {
	    searchargs->system_flags_set |= FLAG_DRAFT;
	}
	else goto badcri;
	break;

    case 'f':
	if (!strcmp(criteria.s, "flagged")) {
	    searchargs->system_flags_set |= FLAG_FLAGGED;
	}
	else if (!strcmp(criteria.s, "from")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->from, str);
	    }
	}
	else goto badcri;
	break;

    case 'h':
	if (!strcmp(criteria.s, "header")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c != ' ') goto missingarg;
	    lcase(arg.s);
	    if (!(searchargs->flags & SEARCH_UNCACHEDHEADER)) {
		for (i=0; i<mailbox_num_cache_header; i++) {
		    if (!strcmp(mailbox_cache_header_name[i], arg.s)) break;
		}
		if (i == mailbox_num_cache_header) {
		    searchargs->flags |= SEARCH_UNCACHEDHEADER;
		}
	    }
	    appendstrlist(&searchargs->header_name, arg.s);
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->header, str);
	    }
	}
	else goto badcri;
	break;

    case 'k':
	if (!strcmp(criteria.s, "keyword")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(&arg);
	    if (!imparse_isatom(arg.s)) goto badflag;
	    lcase(arg.s);
	    for (flag=0; flag < MAX_USER_FLAGS; flag++) {
		if (imapd_mailbox->flagname[flag] &&
		    !strcasecmp(imapd_mailbox->flagname[flag], arg.s)) break;
	    }
	    if (flag == MAX_USER_FLAGS) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
		break;
	    }
	    searchargs->user_flags_set[flag/32] |= 1<<(flag&31);
	}
	else goto badcri;
	break;

    case 'l':
	if (!strcmp(criteria.s, "larger")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(&arg);
	    size = 0;
	    for (p = arg.s; *p && isdigit(*p); p++) {
		size = size * 10 + *p - '0';
	    }
	    if (!arg.s || *p) goto badnumber;
	    if (size > searchargs->larger) searchargs->larger = size;
	}
	else goto badcri;
	break;

    case 'n':
	if (!strcmp(criteria.s, "not")) {
	    if (c != ' ') goto missingarg;		
	    sub1 = (struct searchargs *)xmalloc(sizeof(struct searchargs));
	    *sub1 = zerosearchargs;
	    c = getsearchcriteria(tag, sub1, charset, 0);
	    if (c == EOF) {
		freesearchargs(sub1);
		return EOF;
	    }

	    appendsearchargs(searchargs, sub1, (struct searchargs *)0);
	}
	else if (!strcmp(criteria.s, "new")) {
	    searchargs->flags |= (SEARCH_SEEN_UNSET|SEARCH_RECENT_SET);
	}
	else goto badcri;
	break;

    case 'o':
	if (!strcmp(criteria.s, "or")) {
	    if (c != ' ') goto missingarg;		
	    sub1 = (struct searchargs *)xmalloc(sizeof(struct searchargs));
	    *sub1 = zerosearchargs;
	    c = getsearchcriteria(tag, sub1, charset, 0);
	    if (c == EOF) {
		freesearchargs(sub1);
		return EOF;
	    }
	    if (c != ' ') goto missingarg;		
	    sub2 = (struct searchargs *)xmalloc(sizeof(struct searchargs));
	    *sub2 = zerosearchargs;
	    c = getsearchcriteria(tag, sub2, charset, 0);
	    if (c == EOF) {
		freesearchargs(sub1);
		freesearchargs(sub2);
		return EOF;
	    }
	    appendsearchargs(searchargs, sub1, sub2);
	}
	else if (!strcmp(criteria.s, "old")) {
	    searchargs->flags |= SEARCH_RECENT_UNSET;
	}
	else if (!strcmp(criteria.s, "on")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->before || searchargs->before > end) {
		searchargs->before = end;
	    }
	    if (!searchargs->after || searchargs->after < start) {
		searchargs->after = start;
	    }
	}
	else goto badcri;
	break;

    case 'r':
	if (!strcmp(criteria.s, "recent")) {
	    searchargs->flags |= SEARCH_RECENT_SET;
	}
	else goto badcri;
	break;

    case 's':
	if (!strcmp(criteria.s, "seen")) {
	    searchargs->flags |= SEARCH_SEEN_SET;
	}
	else if (!strcmp(criteria.s, "sentbefore")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->sentbefore || searchargs->sentbefore > start) {
		searchargs->sentbefore = start;
	    }
	}
	else if (!strcmp(criteria.s, "senton")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->sentbefore || searchargs->sentbefore > end) {
		searchargs->sentbefore = end;
	    }
	    if (!searchargs->sentafter || searchargs->sentafter < start) {
		searchargs->sentafter = start;
	    }
	}
	else if (!strcmp(criteria.s, "sentsince")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->sentafter || searchargs->sentafter < start) {
		searchargs->sentafter = start;
	    }
	}
	else if (!strcmp(criteria.s, "since")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->after || searchargs->after < start) {
		searchargs->after = start;
	    }
	}
	else if (!strcmp(criteria.s, "smaller")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(&arg);
	    size = 0;
	    for (p = arg.s; *p && isdigit(*p); p++) {
		size = size * 10 + *p - '0';
	    }
	    if (!arg.s || *p) goto badnumber;
	    if (size == 0) size = 1;
	    if (!searchargs->smaller || size < searchargs->smaller)
	      searchargs->smaller = size;
	}
	else if (!strcmp(criteria.s, "subject")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->subject, str);
	    }
	}
	else goto badcri;
	break;

    case 't':
	if (!strcmp(criteria.s, "to")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->to, str);
	    }
	}
	else if (!strcmp(criteria.s, "text")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset, NULL, 0);
	    if (strchr(str, EMPTY)) {
		/* Force failure */
		searchargs->flags = (SEARCH_RECENT_SET|SEARCH_RECENT_UNSET);
	    }
	    else {
		appendstrlistpat(&searchargs->text, str);
	    }
	}
	else goto badcri;
	break;

    case 'u':
	if (!strcmp(criteria.s, "uid")) {
	    if (c != ' ') goto missingarg;
	    c = getword(&arg);
	    if (!imparse_issequence(arg.s)) goto badcri;
	    appendstrlist(&searchargs->uidsequence, arg.s);
	}
	else if (!strcmp(criteria.s, "unseen")) {
	    searchargs->flags |= SEARCH_SEEN_UNSET;
	}
	else if (!strcmp(criteria.s, "unanswered")) {
	    searchargs->system_flags_unset |= FLAG_ANSWERED;
	}
	else if (!strcmp(criteria.s, "undeleted")) {
	    searchargs->system_flags_unset |= FLAG_DELETED;
	}
	else if (!strcmp(criteria.s, "undraft")) {
	    searchargs->system_flags_unset |= FLAG_DRAFT;
	}
	else if (!strcmp(criteria.s, "unflagged")) {
	    searchargs->system_flags_unset |= FLAG_FLAGGED;
	}
	else if (!strcmp(criteria.s, "unkeyword")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(&arg);
	    if (!imparse_isatom(arg.s)) goto badflag;
	    lcase(arg.s);
	    for (flag=0; flag < MAX_USER_FLAGS; flag++) {
		if (imapd_mailbox->flagname[flag] &&
		    !strcasecmp(imapd_mailbox->flagname[flag], arg.s)) break;
	    }
	    if (flag != MAX_USER_FLAGS) {
		searchargs->user_flags_unset[flag/32] |= 1<<(flag&31);
	    }
	}
	else goto badcri;
	break;

    default:
    badcri:
	prot_printf(imapd_out, "%s BAD Invalid Search criteria\r\n", tag);
	if (c != EOF) prot_ungetc(c, imapd_in);
	return EOF;
    }

    return c;

 missingarg:
    prot_printf(imapd_out, "%s BAD Missing required argument to Search %s\r\n",
	   tag, criteria.s);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;

 badflag:
    prot_printf(imapd_out, "%s BAD Invalid flag name %s in Search command\r\n",
	   tag, arg.s);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;

 baddate:
    prot_printf(imapd_out, "%s BAD Invalid date in Search command\r\n", tag);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;

 badnumber:
    prot_printf(imapd_out, "%s BAD Invalid number in Search command\r\n", tag);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

/*
 * Parse a "date", for SEARCH criteria
 * The time_t's pointed to by 'start' and 'end' are set to the
 * times of the start and end of the parsed date.
 */
int getsearchdate(start, end)
time_t *start, *end;
{
    int c;
    struct tm tm;
    static struct tm zerotm;
    int quoted = 0;
    char month[4];

    tm = zerotm;

    c = prot_getc(imapd_in);
    if (c == '\"') {
	quoted++;
	c = prot_getc(imapd_in);
    }

    /* Day of month */
    if (!isdigit(c)) goto baddate;
    tm.tm_mday = c - '0';
    c = prot_getc(imapd_in);
    if (isdigit(c)) {
	tm.tm_mday = tm.tm_mday * 10 + c - '0';
	c = prot_getc(imapd_in);
    }
    
    if (c != '-') goto baddate;
    c = prot_getc(imapd_in);

    /* Month name */
    if (!isalpha(c)) goto baddate;
    month[0] = c;
    c = prot_getc(imapd_in);
    if (!isalpha(c)) goto baddate;
    month[1] = c;
    c = prot_getc(imapd_in);
    if (!isalpha(c)) goto baddate;
    month[2] = c;
    c = prot_getc(imapd_in);
    month[3] = '\0';
    lcase(month);

    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcmp(month, monthname[tm.tm_mon])) break;
    }
    if (tm.tm_mon == 12) goto baddate;

    if (c != '-') goto baddate;
    c = prot_getc(imapd_in);

    /* Year */
    if (!isdigit(c)) goto baddate;
    tm.tm_year = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_year = tm.tm_year * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (isdigit(c)) {
	if (tm.tm_year < 19) goto baddate;
	tm.tm_year -= 19;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = prot_getc(imapd_in);
    }

    if (quoted) {
	if (c != '\"') goto baddate;
	c = prot_getc(imapd_in);
    }

    tm.tm_isdst = -1;
    *start = mktime(&tm);

    tm.tm_sec = tm.tm_min = 59;
    tm.tm_hour = 23;
    tm.tm_isdst = -1;
    *end = mktime(&tm);

    return c;

 baddate:
    prot_ungetc(c, imapd_in);
    return EOF;
}

/*
 * Parse a date_time, for the APPEND command
 */
int getdatetime(date)
time_t *date;
{
    int c;
    struct tm tm;
    int old_format = 0;
    static struct tm zerotm;
    char month[4], zone[4], *p;
    int zone_off;

    tm = zerotm;

    c = prot_getc(imapd_in);
    if (c != '\"') goto baddate;
    
    /* Day of month */
    c = prot_getc(imapd_in);
    if (c == ' ') c = '0';
    if (!isdigit(c)) goto baddate;
    tm.tm_mday = c - '0';
    c = prot_getc(imapd_in);
    if (isdigit(c)) {
	tm.tm_mday = tm.tm_mday * 10 + c - '0';
	c = prot_getc(imapd_in);
    }
    
    if (c != '-') goto baddate;
    c = prot_getc(imapd_in);

    /* Month name */
    if (!isalpha(c)) goto baddate;
    month[0] = c;
    c = prot_getc(imapd_in);
    if (!isalpha(c)) goto baddate;
    month[1] = c;
    c = prot_getc(imapd_in);
    if (!isalpha(c)) goto baddate;
    month[2] = c;
    c = prot_getc(imapd_in);
    month[3] = '\0';
    lcase(month);

    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcmp(month, monthname[tm.tm_mon])) break;
    }
    if (tm.tm_mon == 12) goto baddate;

    if (c != '-') goto baddate;
    c = prot_getc(imapd_in);

    /* Year */
    if (!isdigit(c)) goto baddate;
    tm.tm_year = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_year = tm.tm_year * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (isdigit(c)) {
	if (tm.tm_year < 19) goto baddate;
	tm.tm_year -= 19;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = prot_getc(imapd_in);
    }
    else old_format++;

    /* Hour */
    if (c != ' ') goto baddate;
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_hour = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_hour = tm.tm_hour * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (tm.tm_hour > 23) goto baddate;

    /* Minute */
    if (c != ':') goto baddate;
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_min = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_min = tm.tm_min * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (tm.tm_min > 59) goto baddate;

    /* Second */
    if (c != ':') goto baddate;
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_sec = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_sec = tm.tm_sec * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (tm.tm_min > 60) goto baddate;

    /* Time zone */
    if (old_format) {
	if (c != '-') goto baddate;
	c = prot_getc(imapd_in);

	if (!isalpha(c)) goto baddate;
	zone[0] = c;
	c = prot_getc(imapd_in);

	if (c == '\"') {
	    /* Military (single-char) zones */
	    zone[1] = '\0';
	    lcase(zone);
	    if (zone[0] <= 'm') {
		zone_off = (zone[0] - 'a' + 1)*60;
	    }
	    else if (zone[0] < 'z') {
		zone_off = ('m' - zone[0])*60;
	    }
	    else zone_off = 0;
	}
	else {
	    /* UT (universal time) */
	    zone[1] = c;
	    c = prot_getc(imapd_in);
	    if (c == '\"') {
		zone[2] = '\0';
		lcase(zone);
		if (!strcmp(zone, "ut")) goto baddate;
		zone_off = 0;
	    }
	    else {
		/* 3-char time zone */
		zone[2] = c;
		c = prot_getc(imapd_in);
		if (c != '\"') goto baddate;
		zone[3] = '\0';
		lcase(zone);
		p = strchr("aecmpyhb", zone[0]);
		if (c != '\"' || zone[2] != 't' || !p) goto baddate;
		zone_off = (strlen(p) - 12)*60;
		if (zone[1] == 'd') zone_off -= 60;
		else if (zone[1] != 's') goto baddate;
	    }
	}
    }
    else {
	if (c != ' ') goto baddate;
	c = prot_getc(imapd_in);

	if (c != '+' && c != '-') goto baddate;
	zone[0] = c;

	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	zone_off = c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 10 + c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 6 + c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 10 + c - '0';

	if (zone[0] == '-') zone_off = -zone_off;

	c = prot_getc(imapd_in);
	if (c != '\"') goto baddate;

    }

    c = prot_getc(imapd_in);

    tm.tm_isdst = -1;
    *date = mkgmtime(&tm) - zone_off*60;

    return c;

 baddate:
    prot_ungetc(c, imapd_in);
    return EOF;
}

/*
 * Eat characters up to and including the next newline
 * Also look for and eat non-synchronizing literals.
 */
void
eatline(c)
int c;
{
    int state = 0;
    char *statediagram = " {+}\r";
    int size = -1;

    for (;;) {
	if (c == '\n') return;
	if (c == statediagram[state+1]) {
	    state++;
	    if (state == 1) size = 0;
	    else if (c == '\r') {
		/* Got a non-synchronizing literal */
		c = prot_getc(imapd_in);/* Eat newline */
		while (size--) {
		    c = prot_getc(imapd_in); /* Eat contents */
		}
		state = 0;	/* Go back to scanning for eol */
	    }
	}
	else if (state == 1 && isdigit(c)) {
	    size = size * 10 + c - '0';
	}
	else state = 0;

	c = prot_getc(imapd_in);
	if (c == EOF) return;
    }
}

/*
 * Print 's' as a quoted-string or literal (but not an atom)
 */
void
printstring(s)
const char *s;
{
    const char *p;
    int len = 0;

    /* Look for any non-QCHAR characters */
    for (p = s; *p; p++) {
	len++;
	if (*p & 0x80 || *p == '\r' || *p == '\n'
	    || *p == '\"' || *p == '%' || *p == '\\') break;
    }

    if (*p || len >= 1024) {
	prot_printf(imapd_out, "{%u}\r\n%s", strlen(s), s);
    }
    else {
	prot_printf(imapd_out, "\"%s\"", s);
    }
}

/*
 * Print 's' as an atom, quoted-string, or literal
 */
void
printastring(s)
const char *s;
{
    const char *p;
    int len = 0;

    if (imparse_isatom(s)) {
	prot_printf(imapd_out, "%s", s);
	return;
    }

    /* Look for any non-QCHAR characters */
    for (p = s; *p; p++) {
	len++;
	if (*p & 0x80 || *p == '\r' || *p == '\n'
	    || *p == '\"' || *p == '%' || *p == '\\') break;
    }

    if (*p || len >= 1024) {
	prot_printf(imapd_out, "{%u}\r\n%s", strlen(s), s);
    }
    else {
	prot_printf(imapd_out, "\"%s\"", s);
    }
}

/*
 * Append 'section', 'fields', 'trail' to the fieldlist 'l'.
 */
void
appendfieldlist(l, section, fields, trail)
struct fieldlist **l;
char *section;
struct strlist *fields;
char *trail;
{
    struct fieldlist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct fieldlist *)xmalloc(sizeof(struct fieldlist));
    (*tail)->section = xstrdup(section);
    (*tail)->fields = fields;
    (*tail)->trail = xstrdup(trail);
    (*tail)->next = 0;
}

/*
 * Append 's' to the strlist 'l'.
 */
void
appendstrlist(l, s)
struct strlist **l;
char *s;
{
    struct strlist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct strlist *)xmalloc(sizeof(struct strlist));
    (*tail)->s = xstrdup(s);
    (*tail)->p = 0;
    (*tail)->next = 0;
}

/*
 * Append 's' to the strlist 'l', compiling it as a pattern.
 * Caller must pass in memory that is freed when the strlist is freed.
 */
void
appendstrlistpat(l, s)
struct strlist **l;
char *s;
{
    struct strlist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct strlist *)xmalloc(sizeof(struct strlist));
    (*tail)->s = s;
    (*tail)->p = charset_compilepat(s);
    (*tail)->next = 0;
}

/*
 * Free the fieldlist 'l'
 */
void
freefieldlist(l)
struct fieldlist *l;
{
    struct fieldlist *n;

    while (l) {
	n = l->next;
	free(l->section);
	freestrlist(l->fields);
	free(l->trail);
	free((char *)l);
	l = n;
    }
}

/*
 * Free the strlist 'l'
 */
void
freestrlist(l)
struct strlist *l;
{
    struct strlist *n;

    while (l) {
	n = l->next;
	free(l->s);
	if (l->p) charset_freepat(l->p);
	free((char *)l);
	l = n;
    }
}

/*
 * Append the searchargs 's1' and 's2' to the sublist of 's'
 */
void
appendsearchargs(s, s1, s2)
struct searchargs *s, *s1, *s2;
{
    struct searchsub **tail = &s->sublist;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct searchsub *)xmalloc(sizeof(struct searchsub));
    (*tail)->sub1 = s1;
    (*tail)->sub2 = s2;
    (*tail)->next = 0;
}


/*
 * Free the searchargs 's'
 */
void
freesearchargs(s)
struct searchargs *s;
{
    struct searchsub *sub, *n;

    if (!s) return;

    freestrlist(s->sequence);
    freestrlist(s->uidsequence);
    freestrlist(s->from);
    freestrlist(s->to);
    freestrlist(s->cc);
    freestrlist(s->bcc);
    freestrlist(s->subject);
    freestrlist(s->body);
    freestrlist(s->text);
    freestrlist(s->header_name);
    freestrlist(s->header);

    for (sub = s->sublist; sub; sub = n) {
	n = sub->next;
	freesearchargs(sub->sub1);
	freesearchargs(sub->sub2);
	free(sub);
    }
    free(s);
}

/*
 * Print an authentication ready response
 */
static char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
void
printauthready(len, data)
int len;
unsigned char *data;
{
    int c1, c2, c3;

    prot_putc('+', imapd_out);
    prot_putc(' ', imapd_out);
    while (len) {
	c1 = *data++;
	len--;
	prot_putc(basis_64[c1>>2], imapd_out);
	if (len == 0) c2 = 0;
	else c2 = *data++;
	prot_putc(basis_64[((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)], imapd_out);
	if (len == 0) {
	    prot_putc('=', imapd_out);
	    prot_putc('=', imapd_out);
	    break;
	}

	if (--len == 0) c3 = 0;
	else c3 = *data++;
        prot_putc(basis_64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)], imapd_out);
	if (len == 0) {
	    prot_putc('=', imapd_out);
	    break;
	}
	
	--len;
        prot_putc(basis_64[c3 & 0x3F], imapd_out);
    }
    prot_putc('\r', imapd_out);
    prot_putc('\n', imapd_out);
    prot_flush(imapd_out);
}

/*
 * Issue a MAILBOX untagged response
 */
static int mailboxdata(name, matchlen, maycreate, rock)
char *name;
int matchlen;
int maycreate;
void* rock;
{
    prot_printf(imapd_out, "* MAILBOX %s\r\n", name);
    return 0;
}

/*
 * Issue a LIST or LSUB untagged response
 */
static void mstringdata(cmd, name, matchlen, maycreate)
char *cmd;
char *name;
int matchlen;
int maycreate;
{
    static char lastname[MAX_MAILBOX_PATH];
    static int lastnamedelayed;
    static sawuser = 0;
    int lastnamehassub = 0;
    int c;

    /* We have to reset the sawuser flag before each list command.
     * Handle it as a dirty hack.
     */
    if (cmd == NULL) {
	sawuser = 0;
	return;
    }
    
    if (lastnamedelayed) {
	if (name && strncmp(lastname, name, strlen(lastname)) == 0 &&
	    name[strlen(lastname)] == '.') {
	    lastnamehassub = 1;
	}
	prot_printf(imapd_out, "* %s (%s) \".\" ", cmd,
	       lastnamehassub ? "" : "\\Noinferiors");
	printastring(lastname);
	prot_printf(imapd_out, "\r\n");
	lastnamedelayed = 0;
    }

    /* Special-case to flush any final state */
    if (!name) {
	lastname[0] = '\0';
	return;
    }

    /* Suppress any output of a partial match */
    if (name[matchlen] && strncmp(lastname, name, matchlen) == 0) {
	return;
    }
	
    /*
     * We can get a partial match for "user" multiple times with
     * other matches inbetween.  Handle it as a special case
     */
    if (matchlen == 4 && strncasecmp(name, "user", 4) == 0) {
	if (sawuser) return;
	sawuser = 1;
    }

    strcpy(lastname, name);
    lastname[matchlen] = '\0';

    if (!name[matchlen] && !maycreate) {
	lastnamedelayed = 1;
	return;
    }

    c = name[matchlen];
    if (c) name[matchlen] = '\0';
    prot_printf(imapd_out, "* %s (%s) \".\" ", cmd, c ? "\\Noselect" : "");
    printstring(name);
    prot_printf(imapd_out, "\r\n");
    if (c) name[matchlen] = c;
    return;
}

/*
 * Issue a LIST untagged response
 */
static int listdata(name, matchlen, maycreate, rock)
char *name;
int matchlen;
int maycreate;
void* rock;
{
    mstringdata("LIST", name, matchlen, maycreate);
    return 0;
}

/*
 * Issue a LSUB untagged response
 */
static int lsubdata(name, matchlen, maycreate, rock)
char *name;
int matchlen;
int maycreate;
void* rock;
{
    mstringdata("LSUB", name, matchlen, maycreate);
    return 0;
}
