/* proxyd.c -- IMAP server proxy
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

/* $Id: proxyd.c,v 1.2 2000/01/28 22:09:50 leg Exp $ */

#ifndef __GNUC__
#define __attribute__(foo)
#endif

#include <stdio.h>
#include <string.h>
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
#include <assert.h>

#include <sasl.h>

#include "prot.h"

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
#include "mboxname.h"
#include "mailbox.h"
#include "xmalloc.h"

/* PROXY STUFF */
/* we want a list of our outgoing connections here and which one we're
   currently piping */
#define LAST_RESULT_LEN 1024
#define IDLE_TIMEOUT (5 * 60)

struct backend {
    char *hostname;
    struct sockaddr_in addr;
    int sock;
    time_t lastused;
    sasl_conn_t *saslconn;
    char last_result[LAST_RESULT_LEN];
    struct protstream *in; /* from the be server to me, the proxy */
    struct protstream *out; /* to the be server */
};

static unsigned int proxyd_cmdcnt;

/* all subscription commands go to the backend server containing the
   user's inbox */
struct backend *backend_inbox;

/* the current server most commands go to */
struct backend *backend_current;

/* our cached connections */
struct backend **backend_cached;

/* -------- from imapd ---------- */

extern int optind;
extern char *optarg;

extern int errno;

struct buf {
    char *s;
    int alloc;
};

sasl_conn_t *proxyd_saslconn; /* the sasl connection context to the client */

char *proxyd_userid;
struct auth_state *proxyd_authstate = 0;
int proxyd_userisadmin;
struct sockaddr_in proxyd_localaddr, proxyd_remoteaddr;
int proxyd_haveaddr = 0;
char proxyd_clienthost[250] = "[local]";
struct protstream *proxyd_out, *proxyd_in;
time_t proxyd_logtime;

static char *monthname[] = {
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec"
};

void usage(void);
void shutdown_file(int fd);
void motd_file(int fd);
void shut_down(int code);
void fatal(const char *s, int code);

void cmdloop(void);
void cmd_login(char *tag, char *user, char *passwd);
void cmd_authenticate(char *tag, char *authtype);
void cmd_noop(char *tag, char *cmd);
void cmd_capability(char *tag);
void cmd_append(char *tag, char *name);
void cmd_select(char *tag, char *cmd, char *name);
void cmd_close(char *tag);
void cmd_fetch(char *tag, char *sequence, int usinguid);
void cmd_partial(char *tag, char *msgno, char *data,
		 char *start, char *count);
void cmd_store(char *tag, char *sequence, char *operation, int usinguid);
void cmd_search(char *tag, int usinguid);
void cmd_copy(char *tag, char *sequence, char *name, int usinguid);
void cmd_expunge(char *tag, char *sequence);
void cmd_create(char *tag, char *name, char *partition);
void cmd_delete(char *tag, char *name);
void cmd_rename(char *tag, char *oldname, char *newname, char *partition);
void cmd_find(char *tag, char *namespace, char *pattern);
void cmd_list(char *tag, int subscribed, char *reference, char *pattern);
void cmd_changesub(char *tag, char *namespace, char *name, int add);
void cmd_getacl(char *tag, char *name, int oldform);
void cmd_listrights(char *tag, char *name, char *identifier);
void cmd_myrights(char *tag, char *name, int oldform);
void cmd_setacl(char *tag, char *name, char *identifier, char *rights);
void cmd_getquota(char *tag, char *name);
void cmd_getquotaroot(char *tag, char *name);
void cmd_setquota(char *tag, char *quotaroot);
void cmd_status(char *tag, char *name);
void cmd_getuids(char *tag, char *startuid);
void cmd_unselect(char* tag);
void cmd_namespace(char* tag);

#ifdef ENABLE_X_NETSCAPE_HACK
void cmd_netscape (char* tag);
#endif

int getword (struct buf *buf);
int getastring (struct buf *buf);
int getbase64string (struct buf *buf);

void eatline (int c);
void printstring (const char *s);
void printastring (const char *s);

void printauthready (int len, unsigned char *data);

/* XXX fix when proto-izing mboxlist.c */
static int mailboxdata(), listdata(), lsubdata();
static void mstringdata(char *cmd, char *name, int matchlen, int maycreate);

/* proxy support functions */
#define OK 0
#define NO 1
#define BAD 2

static void proxyd_gentag(char *tag)
{
    sprintf(tag, "PROXY%d", proxyd_cmdcnt++);
}

static int pipe_until_tag(struct backend *s, char *tag)
{
    char buf[2048];
    char eol[128];
    int sl;
    int sawtag = 0, cont = 0, r = -1;
    int taglen = strlen(tag);

    s->lastused = time(NULL);
    
    eol[0] = '\0';

    /* the only complication here are literals */
    for (;;) {
	/* if "cont" is set, we're looking at the continuation to a very
	   long line */

	if (!prot_fgets(buf, sizeof(buf), s->in)) {
	    /* uh oh */
	    return -1;
	}
	if (!cont && !strncmp(tag, buf, taglen)) {
	    if (buf[taglen] == ' ') {
		strncpy(s->last_result, buf + taglen + 1, LAST_RESULT_LEN);
		switch (buf[taglen + 1]) {
		case 'O': case 'o':
		    r = OK;
		    break;
		case 'N': case 'n':
		    r = NO;
		    break;
		case 'B': case 'b':
		    r = BAD;
		    break;
		default: /* huh? no result? */
		    r = -1;
		    break;
		}
	    }
	    /* we currently assume that tagged responses are:
	       a) short
	       b) don't contain literals

	       IMAP grammar allows both, unfortunately */
	    return r;
	}
	
	sl = strlen(buf);
	if (sl == (sizeof(buf) - 1)) { /* only got part of a line */
	    /* we save the last 64 characters in case it has important
	       literal information */
	    strncpy(eol, buf + sl - 64, 65);

	    /* write out this part, but we have to keep reading until we
	       hit the end of the line */
	    prot_write(proxyd_out, buf, sl);
	    cont = 1;
	    continue;
	} else {		/* we got the end of the line */
	    int i;
	    int litlen = 0, islit = 0;

	    prot_write(proxyd_out, buf, sl);

	    /* now we have to see if this line ends with a literal */
	    if (sl < 64) {
		strncat(eol, buf, 64);
	    } else {
		strncat(eol, buf + sl - 63, 64);
	    }

	    /* eol now contains the last characters from the line; we want
	       to see if we've hit a literal */
	    i = strlen(eol);
	    if (eol[i-1] == '\n' && eol[i-2] == '\r' && eol[i-3] == '}') {
		/* possible literal */
		i -= 3;
		while (i > 0 && eol[i] != '{' && isdigit(eol[i])) {
		    i--;
		}
		if (eol[i] == '{') {
		    islit = 1;
		    litlen = atoi(eol + i + 1);
		}
	    }

	    /* copy the literal over */
	    if (islit) {
		while (litlen > 0) {
		    int j = (litlen > sizeof(buf) ? sizeof(buf) : litlen);
		    
		    j = prot_read(s->in, buf, j);
		    prot_write(proxyd_out, buf, j);
		    litlen -= j;
		}

		/* none of our saved information has any relevance now */
		eol[0] = '\0';
		
		/* have to keep going for the end of the line */
		continue;
	    }
	}

	/* ok, let's read another line */
	cont = 0;
    }

    return r;
}

static int pipe_including_tag(struct backend *s, char *tag)
{
    int r;

    r = pipe_until_tag(s, tag);
    switch (r) {
    case OK:
    case NO:
    case BAD:
	prot_printf(proxyd_out, "%s %s", tag, s->last_result);
	break;
    default:
	break;
    }
    return r;
}

/* copy our current input to s until we hit a true EOL.

   the optimistic literal parameter is how happy we should be about assuming
   that a command will go through by converting synchronizing literals of
   size less than optimistic_literal to nonsync

   returns 0 on success, <0 on big failure, >0 on full command not sent */
static int pipe_command(struct backend *s, int optimistic_literal)
{
    char buf[2048];
    char eol[128];
    int sl;

    s->lastused = time(NULL);
    
    eol[0] = '\0';

    /* again, the complication here are literals */
    for (;;) {
	if (!prot_fgets(buf, sizeof(buf), proxyd_in)) {
	    /* uh oh */
	    return -1;
	}

	sl = strlen(buf);
	if (sl == (sizeof(buf) - 1)) { /* only got part of a line */
	    strcpy(eol, buf + sl - 64);

	    /* and write this out, except for what we've saved */
	    prot_write(s->out, buf, sl - 64);
	    continue;
	} else {
	    int i, nonsynch = 0, islit = 0, litlen;

	    if (sl < 64) {
		strcat(eol, buf);
	    } else {
		/* write out what we have, and copy the last 64 characters
		   to eol */
		prot_printf(s->out, "%s", eol);
		prot_write(s->out, buf, sl - 64);
		strcpy(eol, buf + sl - 64);
	    }

	    /* now determine if eol has a literal in it */
	    i = strlen(eol);
	    if (eol[i-1] == '\n' && eol[i-2] == '\r' && eol[i-3] == '}') {
		/* possible literal */
		i -= 3;
		if (eol[i] == '+') {
		    nonsynch = 1;
		    i--;
		}
		while (i > 0 && eol[i] != '{' && isdigit(eol[i])) {
		    i--;
		}
		if (eol[i] == '{') {
		    islit = 1;
		    litlen = atoi(eol + i + 1);
		}
	    }

	    if (islit) {
		if (nonsynch) {
		    prot_write(s->out, eol, strlen(eol));
		} else if (!nonsynch && (litlen <= optimistic_literal)) {
		    prot_printf(proxyd_out, "+ i am an optimist\r\n");
		    prot_write(s->out, eol, strlen(eol) - 3);
		    /* need to insert a + to turn it into a nonsynch */
		    prot_printf(s->out, "+}\r\n");
		} else {
		    /* we do a standard synchronizing literal */
		    prot_write(s->out, eol, strlen(eol));
		    /* but here the game gets tricky... */
		    prot_fgets(buf, sizeof(buf), s->in);
		    /* but for now we cheat */
		    prot_write(proxyd_out, buf, strlen(buf));
		    if (buf[0] != '+' && buf[1] != ' ') {
			char *p = strchr(buf, ' ');
			/* strncpy(s->last_result, p + 1, LAST_RESULT_LEN);*/

			/* stop sending command now */
			return 1;
		    }
		}

		/* gobble literal and sent it onward */
		while (litlen > 0) {
		    int j = (litlen > sizeof(buf) ? sizeof(buf) : litlen);

		    j = prot_read(s->in, buf, j);
		    prot_write(proxyd_out, buf, j);
		    litlen -= j;
		}

		eol[0] = '\0';
		
		/* have to keep going for the send of the command */
		continue; 
	    } else {
		/* no literal, so we're done! */
		prot_write(s->out, eol, strlen(eol));

		return;
	    }
	}
    }
}

/* This creates a structure that defines the allowable
 *   security properties 
 */
static sasl_security_properties_t *make_secprops(int min, int max)
{
    sasl_security_properties_t *ret = (sasl_security_properties_t *)
	xmalloc(sizeof(sasl_security_properties_t));

    ret->maxbufsize = 4096;
    ret->min_ssf = min;
    ret->max_ssf = max;
    
    ret->security_flags = 0;
    if (!config_getswitch("allowplaintext", 1)) {
	ret->security_flags |= SASL_SEC_NOPLAINTEXT;
    }
    if (!config_getswitch("allowanonymouslogin", 0)) {
	ret->security_flags |= SASL_SEC_NOANONYMOUS;
    }
    
    ret->property_names = NULL;
    ret->property_values = NULL;

    return ret;
}

static int mysasl_simple_cb(void *context, int id, const char **result,
			    unsigned int *len)
{
    if (!result) {
	return SASL_BADPARAM;
    }

    switch (id) {
    case SASL_CB_USER:
	*result = proxyd_userid;
	break;
    case SASL_CB_AUTHNAME:
	*result = config_getstring("proxylogin", "proxy");
	break;
    case SASL_CB_LANGUAGE:
	*result = NULL;
	break;
    default:
	return SASL_BADPARAM;
    }
    if (len) {
	*len = *result ? strlen(*result) : 0;
    }

    return SASL_OK;
}

static int mysasl_getrealm_cb(void *context, int id,
			      const char **availrealms __attribute__((unused)),
			      const char **result)
{
    if (id != SASL_CB_GETREALM || !result) {
	return SASL_BADPARAM;
    }

    *result = config_getstring("proxyrealm", "");

    return SASL_OK;
}

static int mysasl_getsecret_cb(sasl_conn_t *conn,
			       void *context,
			       int id,
			       sasl_secret_t **result)
{
    char optstr[1024];
    const char *pass;
    char *p;
    size_t len;
    struct backend *s = (struct backend *) context;

    if (!conn || !result || id != SASL_CB_PASS) {
	return SASL_BADPARAM;
    }

    strcpy(optstr, s->hostname);
    p = strchr(optstr, '.');
    *p = '\0';
    strcat(optstr, "_password");
    pass = config_getstring(optstr, "");
    len = strlen(pass);

    *result = (sasl_secret_t *) xmalloc(sizeof(sasl_secret_t) + len);
    (*result)->len = len;
    strcpy((*result)->data, pass);

    return SASL_OK;
}

static sasl_callback_t *make_callbacks(struct backend *s)
{
    sasl_callback_t *ret = xmalloc(5 * sizeof(sasl_callback_t));

    /* user callback */
    ret[0].id = SASL_CB_USER;
    ret[0].proc = &mysasl_simple_cb;
    ret[0].context = s;

    /* authname */
    ret[1].id = SASL_CB_AUTHNAME;
    ret[1].proc = &mysasl_simple_cb;
    ret[1].context = s;

    /* realm */
    ret[2].id = SASL_CB_GETREALM;
    ret[2].proc = &mysasl_getrealm_cb;
    ret[2].context = s;

    /* password */
    ret[3].id = SASL_CB_PASS;
    ret[3].proc = &mysasl_getsecret_cb;
    ret[3].context = s;
    
    ret[4].id = SASL_CB_LIST_END;
    ret[4].proc = NULL;
    ret[4].context = s;

    return ret;
}

static int mysasl_getauthline(struct protstream *p, char *tag,
			      char **line, unsigned int *linelen)
{
    char buf[2096];
    int saslresult;
    char *str = (char *) buf;
    
    if (!prot_fgets(str, sizeof(buf), p)) {
	return SASL_FAIL;
    }
    if (!strncmp(str, tag, strlen(tag))) {
	str += strlen(tag) + 1;
	if (!strncasecmp(str, "OK ", 3)) { return SASL_OK; }
	if (!strncasecmp(str, "NO ", 3)) { return SASL_BADAUTH; }
	return SASL_FAIL; /* huh? */
    } else if (str[0] == '+' && str[1] == ' ') {
	str += 2; /* jump past the "+ " */

	*line = xmalloc(strlen(str) + 1);
	if (*str != '\r') {	/* decode it */
	    int r;
	    
	    r = sasl_decode64(str, strlen(str), *line, linelen);
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

static int proxy_authenticate(struct backend *s)
{
    int r;
    sasl_security_properties_t *secprops = NULL;
    struct sockaddr_in *saddr_l = 
	(struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
    struct sockaddr_in *saddr_r = 
	(struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
    int addrsize = sizeof(struct sockaddr_in);
    sasl_callback_t *cb;
    char mytag[128];
    char buf[2048];
    char *in, *out, *p;
    unsigned int inlen, outlen;
    const char *mechusing;
    int b64len;

    cb = make_callbacks(s);

    r = sasl_client_new("imap", s->hostname, cb, 0, &s->saslconn);
    if (r != SASL_OK) {
	return r;
    }

    secprops = make_secprops(0, 0);
    if (secprops != NULL) {
	r = sasl_setprop(s->saslconn, SASL_SEC_PROPS, secprops);
	free(secprops);
	if (r != SASL_OK) {
	    return r;
	}
    }

    /* set the IP addresses */
    if (getpeername(s->sock, (struct sockaddr *)saddr_r, &addrsize) != 0)
	return SASL_FAIL;
    r = sasl_setprop(s->saslconn, SASL_IP_REMOTE, saddr_r);
    if (r != SASL_OK) return r;
  
    addrsize=sizeof(struct sockaddr_in);
    if (getsockname(s->sock, (struct sockaddr *)saddr_l,&addrsize)!=0)
	return SASL_FAIL;
    r = sasl_setprop(s->saslconn, SASL_IP_LOCAL, saddr_l);
    if (r != SASL_OK) return r;
    free(saddr_l);
    free(saddr_r);

    /* read the initial greeting */
    if (!prot_fgets(buf, sizeof(buf), s->in)) {
	return SASL_FAIL;
    }

    strcpy(buf, s->hostname);
    p = strchr(buf, '.');
    *p = '\0';
    strcat(buf, "_mechs");

    /* we now do the actual SASL exchange */
    r = sasl_client_start(s->saslconn, config_getstring(buf, "KERBEROS_V4"),
			  NULL, NULL, &out, &outlen, &mechusing);
    if (out) {
	/* IMAP can't deal with client-sends-first */
	free(out);
    }
    if ((r != SASL_OK) && (r != SASL_CONTINUE)) {
	return r;
    }
    proxyd_gentag(mytag);
    prot_printf(s->out, "%s AUTHENTICATE %s\r\n", mytag, mechusing);

    in = NULL;
    inlen = 0;
    r = mysasl_getauthline(s->in, mytag, &in, &inlen);
    while (r == SASL_CONTINUE) {
	r = sasl_client_step(s->saslconn, in, inlen, NULL, &out, &outlen);
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
	if (outlen > 0) { free(out); }

	prot_write(s->out, buf, b64len);
	prot_printf(s->out, "\r\n");

	r = mysasl_getauthline(s->in, mytag, &in, &inlen);
    }

    /* r == SASL_OK on success */
    return r;
}

void proxyd_downserver(struct backend *s)
{
    char tag[128];
    int taglen;
    char buf[1024];

    if (!s->lastused) {
	/* already disconnected */
	return;
    }

    /* need to logout of server */
    proxyd_gentag(tag);
    prot_printf(s->out, "%s LOGOUT\r\n", tag);
    while (prot_fgets(buf, sizeof(buf), s->in)) {
	if (!strncmp(tag, buf, taglen)) {
	    break;
	}
    }

    close(s->sock);
    prot_free(s->in);
    prot_free(s->out);
    s->lastused = 0;
}

/* return the connection to the server */
struct backend *proxyd_findserver(char *server)
{
    int i = 0;
    struct backend *ret = NULL;

    while (backend_cached[i]) {
	if (!strcmp(server, backend_cached[i]->hostname)) {
	    ret = backend_cached[i];
	    break;
	}
	i++;
    }

    if (!ret) {
	struct hostent *hp;

	ret = xmalloc(sizeof(struct backend));
	ret->hostname = xstrdup(server);
	if ((hp = gethostbyname(server)) == NULL) {
	    fatal("gethostbyname failed", 1);
	}
	ret->addr.sin_family = AF_INET;
	memcpy(&ret->addr.sin_addr, hp->h_addr, hp->h_length);
	ret->addr.sin_port = htons(143);

	ret->lastused = 0;
    }
	
    if (!ret->lastused) {
	/* need to (re)establish connection to server or create one */
	int sock;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	    fatal("socket failed", 1);
	}
	if (connect(sock, (struct sockaddr *) &ret->addr, 
		    sizeof(ret->addr)) < 0) {
	    fatal("connect failed", 1);
	}
	
	ret->in = prot_new(sock, 0);
	ret->out = prot_new(sock, 1);
	ret->sock = sock;
	prot_setflushonread(ret->in, ret->out);

	/* now need to authenticate to backend server */
	if (proxy_authenticate(ret)) {
	    fatal("couldn't authenticate to backend server", 1);
	}
    }

    ret->lastused = time(NULL);

    if (!backend_cached[i]) {
	/* insert server in list of cached connections */
	backend_cached = (struct backend **) 
	    xrealloc(backend_cached, (i + 2) * sizeof(struct backend *));
	backend_cached[i] = ret;
	backend_cached[i + 1] = NULL;
    }

    return ret;
}

static struct backend *proxyd_findinboxserver(void)
{
    char inbox[MAX_MAILBOX_NAME];
    int r;
    char *server;
    struct backend *s;

    strcpy(inbox, "user.");
    strcat(inbox, proxyd_userid);
	
    r = mboxlist_lookup(inbox, &server, NULL, NULL);
    s = proxyd_findserver(server);

    return s;
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
	    strncat(opt, plugin_name, 1019);
	    strncat(opt, "_", 1024 - sl);
	}
 	strncat(opt, option, 1024 - sl - 1);
	opt[1023] = '\0';
    } else {
	strncpy(opt, option, 1024);
    }

    *result = config_getstring(opt, NULL);
    if (*result != NULL) {
	if (len) { *len = strlen(*result); }
	return SASL_OK;
    }
   
    return SASL_FAIL;
}

/*
 * acl_ok() checks to see if the the inbox for 'user' grants the 'a'
 * right to the principal 'auth_identity'. Returns 1 if so, 0 if not.
 */
static int acl_ok(const char *user, const char *auth_identity)
{
    char *acl;
    char inboxname[1024];
    int r;
    struct auth_state *authstate;

    if (strchr(user, '.') || strlen(user)+6 >= sizeof(inboxname)) return 0;

    strcpy(inboxname, "user.");
    strcat(inboxname, user);

    if (!(authstate = auth_newstate(auth_identity, (char *)0)) ||
	mboxlist_lookup(inboxname, (char **)0, &acl, NULL)) {
	r = 0;  /* Failed so assume no proxy access */
    }
    else {
	r = (acl_myrights(authstate, acl) & ACL_ADMIN) != 0;
    }
    if (authstate) auth_freestate(authstate);
    return r;
}

/* returns true if proxyd_authstate is in "item";
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

	if (auth_memberof(proxyd_authstate, buf)) {
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

    proxyd_authstate = auth_newstate(canon_authuser, NULL);

    /* ok, is auth_identity an admin? */
    proxyd_userisadmin = authisa("admins");

    if (strcmp(canon_authuser, canon_requser)) {
	/* we want to authenticate as a different user; we'll allow this
	   if we're an admin or if we've allowed ACL proxy logins */
	int use_acl = config_getswitch("loginuseacl", 0);

	if (proxyd_userisadmin ||
	    (use_acl && acl_ok(canon_requser, canon_authuser)) ||
	    authisa("proxyservers")) {
	    /* proxy ok! */

	    proxyd_userisadmin = 0;	/* no longer admin */
	    auth_freestate(proxyd_authstate);
	    
	    proxyd_authstate = auth_newstate(canon_requser, NULL);
	} else {
	    *errstr = "user is not allowed to proxy";
	    
	    free(canon_authuser);
	    free(canon_requser);
	    auth_freestate(proxyd_authstate);
	    
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
    int salen;
    struct hostent *hp;
    int timeout;
    char hostname[MAXHOSTNAMELEN+1];
    sasl_security_properties_t *secprops = NULL;

    if (gethostname(hostname, MAXHOSTNAMELEN)!=0)
      fatal("gethostname failed\n",EC_USAGE);

    proxyd_in = prot_new(0, 0);
    proxyd_out = prot_new(1, 1);

    setproctitle_init(argc, argv, envp);
    config_init("proxyd");

    mboxlist_open();

    signal(SIGPIPE, SIG_IGN);

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    /* Find out name of client host */
    salen = sizeof(proxyd_remoteaddr);
    if (getpeername(0, (struct sockaddr *)&proxyd_remoteaddr, &salen) == 0 &&
	proxyd_remoteaddr.sin_family == AF_INET) {
	if (hp = gethostbyaddr((char *)&proxyd_remoteaddr.sin_addr,
			       sizeof(proxyd_remoteaddr.sin_addr), AF_INET)) {
	    strncpy(proxyd_clienthost, hp->h_name, sizeof(proxyd_clienthost)-30);
	    proxyd_clienthost[sizeof(proxyd_clienthost)-30] = '\0';
	}
	else {
	    proxyd_clienthost[0] = '\0';
	}
	strcat(proxyd_clienthost, "[");
	strcat(proxyd_clienthost, inet_ntoa(proxyd_remoteaddr.sin_addr));
	strcat(proxyd_clienthost, "]");
	salen = sizeof(proxyd_localaddr);
	if (getsockname(0, (struct sockaddr *)&proxyd_localaddr,
			&salen) == 0) {
	    proxyd_haveaddr = 1;
	}
    }

    /* set the SASL allocation functions */
    sasl_set_alloc((sasl_malloc_t *) &xmalloc, 
		   (sasl_calloc_t *) &calloc, 
		   (sasl_realloc_t *) &xrealloc, 
		   (sasl_free_t *) &free);

    /* start up sasl */
    if (sasl_server_init(mysasl_cb, "Cyrus") != SASL_OK) {
	fatal("SASL failed initializing: sasl_server_init()", EC_TEMPFAIL); 
    }

    if (sasl_client_init(NULL) != SASL_OK) {
	fatal("SASL failed initializing: sasl_client_init()", EC_TEMPFAIL);
    }
    
    /* Make a SASL connection and setup some properties for it */
    /* other params should be filled in */
    if (sasl_server_new("imap", hostname, NULL, NULL, SASL_SECURITY_LAYER, 
			&proxyd_saslconn)
	   != SASL_OK)
	fatal("SASL failed initializing: sasl_server_new()", EC_TEMPFAIL); 

    /* will always return something valid */
    /* should be configurable! */
    secprops = make_secprops(0, 2000);
    sasl_setprop(proxyd_saslconn, SASL_SEC_PROPS, secprops);
    
    sasl_setprop(proxyd_saslconn, SASL_IP_REMOTE, &proxyd_remoteaddr);  
    sasl_setprop(proxyd_saslconn, SASL_IP_LOCAL, &proxyd_localaddr);  

    proc_register("proxyd", proxyd_clienthost, (char *)0, (char *)0);

    /* Set inactivity timer */
    timeout = config_getint("timeout", 30);
    if (timeout < 30) timeout = 30;
    prot_settimeout(proxyd_in, timeout*60);
    prot_setflushonread(proxyd_in, proxyd_out);

    /* setup the cache */
    backend_cached = xmalloc(sizeof(struct backend *));
    backend_cached[0] = NULL;

    cmdloop();
}

void
usage()
{
    prot_printf(proxyd_out, "* BYE usage: proxyd\r\n");
    prot_flush(proxyd_out);
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
    prot_printf(proxyd_out, "* OK [ALERT] %s\r\n", p);
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

    for (p = buf; *p == '['; p++); /* can't have [ be first char, sigh */
    prot_printf(proxyd_out, "* BYE [ALERT] %s\r\n", p);

    shut_down(0);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    int i;

    proc_cleanup();

    i = 0;
    while (backend_cached[i]) {
	proxyd_downserver(backend_cached[i]);

	i++;
    }

    mboxlist_done();
    prot_flush(proxyd_out);
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
    prot_printf(proxyd_out, "* BYE Fatal error: %s\r\n", s);
    prot_flush(proxyd_out);
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
    int c, i;
    time_t mark, now;
    struct timeval tv;
    fd_set rfds;
    int usinguid, havepartition, havenamespace, oldform;
    static struct buf tag, cmd, arg1, arg2, arg3, arg4;
    char *p;
    const char *err;

    sprintf(shutdownfilename, "%s/msg/shutdown", config_dir);

    gethostname(hostname, sizeof(hostname));
    prot_printf(proxyd_out,
		"* OK %s Cyrus IMAP4 Murder %s server ready\r\n", hostname,
		CYRUS_VERSION);

    sprintf(motdfilename, "%s/msg/motd", config_dir);
    if ((fd = open(motdfilename, O_RDONLY, 0)) != -1) {
	motd_file(fd);
	close(fd);
    }

    for (;;) {
	if (! proxyd_userisadmin &&
	    (fd = open(shutdownfilename, O_RDONLY, 0)) != -1) {
	    shutdown_file(fd);
	}

#if NEEDS_PROXY
	/* this doesn't properly work with the prot layer; perhaps do
           it with a read callback in the prot layer? */

	prot_flush(proxyd_out);
	do {
	    now = time(NULL);
	    mark = IDLE_TIMEOUT + 1;
	    i = 0;
	    while (backend_cached[i]) {
		if ((backend_cached[i]->lastused != 0) &&
		    (backend_cached[i] != backend_current)) {
		    /* server i is connected and not our current server */

		    if (backend_cached[i]->lastused + IDLE_TIMEOUT < now) {
			/* idle too long */
			proxyd_downserver(backend_cached[i]);
		    } else {
			/* it will timeout in mark seconds */
			int timeout = backend_cached[i]->lastused + 
			                IDLE_TIMEOUT - now;

			mark = (timeout < mark ? timeout : mark);
		    }
		}
		i++;
	    }
	    tv.tv_sec = mark;
	    tv.tv_usec = 0;
	    
	    FD_ZERO(&rfds);
	    FD_SET(0, &rfds);
	} while ((mark != IDLE_TIMEOUT + 1) &&
		 (select(1, &rfds, NULL, NULL, &tv) == 0));
#endif
	
	/* Parse tag */
	c = getword(&tag);
	if (c == EOF) {
	    if (err = prot_error(proxyd_in)) {
		syslog(LOG_WARNING, "PROTERR: %s", err);
		prot_printf(proxyd_out, "* BYE %s\r\n", err);
	    }
	    shut_down(0);
	}
	if (c != ' ' || !imparse_isatom(tag.s) || 
	    (tag.s[0] == '*' && !tag.s[1])) {
	    prot_printf(proxyd_out, "* BAD Invalid tag\r\n");
	    eatline(c);
	    continue;
	}

	/* Parse command name */
	c = getword(&cmd);
	if (!cmd.s[0]) {
	    prot_printf(proxyd_out, "%s BAD Null command\r\n", tag.s);
	    eatline(c);
	    continue;
	}
	if (islower(cmd.s[0])) cmd.s[0] = toupper(cmd.s[0]);
	for (p = &cmd.s[1]; *p; p++) {
	    if (isupper(*p)) *p = tolower(*p);
	}

	/* Only Authenticate/Login/Logout/Noop allowed when not logged in */
	if (!proxyd_userid && !strchr("ALNC", cmd.s[0])) goto nologin;
    
	/* note that about half the commands (the common ones that don't
	   hit the mailboxes file) now close the mailboxes file just in
	   case it was open. */
	switch (cmd.s[0]) {
	case 'A':
	    if (!strcmp(cmd.s, "Authenticate")) {
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (!imparse_isatom(arg1.s)) {
		    prot_printf(proxyd_out, 
				"%s BAD Invalid authenticate mechanism\r\n", 
				tag.s);
		    eatline(c);
		    continue;
		}
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		
		if (proxyd_userid) {
		    prot_printf(proxyd_out, 
				"%s BAD Already authenticated\r\n", tag.s);
		    continue;
		}
		cmd_authenticate(tag.s, arg1.s);
	    }
	    else if (!proxyd_userid) goto nologin;
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
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;

		cmd_select(tag.s, cmd.s, arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'C':
	    if (!strcmp(cmd.s, "Capability")) {
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		cmd_capability(tag.s);
	    }
	    else if (!proxyd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "Check")) {
		if (!backend_current) goto nomailbox;
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		mboxlist_close();	
		cmd_noop(tag.s, cmd.s);
	    }
	    else if (!strcmp(cmd.s, "Copy")) {
		if (!backend_current) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    copy:
		c = getword(&arg1);
		if (c == '\r') goto missingargs;
		if (c != ' ' || !imparse_issequence(arg1.s)) goto badsequence;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(proxyd_in);
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
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		cmd_create(tag.s, arg1.s, havepartition ? arg2.s : 0);
	    }
	    else if (!strcmp(cmd.s, "Close")) {
		if (!backend_current) goto nomailbox;
		if (c == '\r') c = prot_getc(proxyd_in);
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
		if (c == '\r') c = prot_getc(proxyd_in);
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
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		cmd_setacl(tag.s, arg1.s, arg2.s, (char *)0);
	    }
	    else goto badcmd;
	    break;

	case 'E':
	    if (!strcmp(cmd.s, "Expunge")) {
		if (!backend_current) goto nomailbox;
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		mboxlist_close();	
		cmd_expunge(tag.s, 0);
	    }
	    else if (!strcmp(cmd.s, "Examine")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;

		cmd_select(tag.s, cmd.s, arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'F':
	    if (!strcmp(cmd.s, "Fetch")) {
		if (!backend_current) goto nomailbox;
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
		if (c == '\r') c = prot_getc(proxyd_in);
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
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		cmd_getacl(tag.s, arg1.s, oldform);
	    }
	    else if (!strcmp(cmd.s, "Getquota")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		cmd_getquota(tag.s, arg1.s);
	    }
	    else if (!strcmp(cmd.s, "Getquotaroot")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		cmd_getquotaroot(tag.s, arg1.s);
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
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		
		if (proxyd_userid) {
		    prot_printf(proxyd_out, 
				"%s BAD Already logged in\r\n", tag.s);
		    continue;
		}
		cmd_login(tag.s, arg1.s, arg2.s);
	    }
	    else if (!strcmp(cmd.s, "Logout")) {
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		
		prot_printf(proxyd_out, 
			    "* BYE %s\r\n", error_message(IMAP_BYE_LOGOUT));
		prot_printf(proxyd_out, "%s OK %s\r\n", 
			    tag.s, error_message(IMAP_OK_COMPLETED));
		shut_down(0);
	    }
	    else if (!proxyd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "List")) {
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		cmd_list(tag.s, 0, arg1.s, arg2.s);
	    }
	    else if (!strcmp(cmd.s, "Lsub")) {
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		cmd_list(tag.s, 1, arg1.s, arg2.s);
	    }
	    else if (!strcmp(cmd.s, "Listrights")) {
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == '\r') c = prot_getc(proxyd_in);
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
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		cmd_myrights(tag.s, arg1.s, oldform);
	    }
	    else goto badcmd;
	    break;

	case 'N':
	    if (!strcmp(cmd.s, "Noop")) {
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		mboxlist_close();
		cmd_noop(tag.s, cmd.s);
	    }
#ifdef ENABLE_X_NETSCAPE_HACK
	    else if (!strcmp(cmd.s, "Netscape")) {
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		cmd_netscape(tag.s);
	    }
#endif
	    else if (!proxyd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "Namespace")) {
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		cmd_namespace(tag.s);
	    }
	    else goto badcmd;
	    break;

	case 'P':
	    if (!strcmp(cmd.s, "Partial")) {
		if (!backend_current) goto nomailbox;
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		c = getword(&arg2);
		if (c != ' ') goto missingargs;
		c = getword(&arg3);
		if (c != ' ') goto missingargs;
		c = getword(&arg4);
		if (c == '\r') c = prot_getc(proxyd_in);
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
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		cmd_rename(tag.s, arg1.s, arg2.s, havepartition ? arg3.s : 0);
	    }
	    else goto badcmd;
	    break;
	    
	case 'S':
	    if (!strcmp(cmd.s, "Store")) {
		if (!backend_current) goto nomailbox;
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
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;

		cmd_select(tag.s, cmd.s, arg1.s);
	    }
	    else if (!strcmp(cmd.s, "Search")) {
		if (!backend_current) goto nomailbox;
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
		if (c == '\r') c = prot_getc(proxyd_in);
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
		if (c == '\r') c = prot_getc(proxyd_in);
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
		if (!backend_current) goto nomailbox;
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
		    if (c == '\r') c = prot_getc(proxyd_in);
		    if (c != '\n') goto extraargs;
		    cmd_expunge(tag.s, arg1.s);
		}
		else {
		    prot_printf(proxyd_out, 
				"%s BAD Unrecognized UID subcommand\r\n", 
				tag.s);
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
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		if (havenamespace) {
		    cmd_changesub(tag.s, arg1.s, arg2.s, 0);
		}
		else {
		    cmd_changesub(tag.s, (char *)0, arg1.s, 0);
		}
	    }		
	    else if (!strcmp(cmd.s, "Unselect")) {
		if (!backend_current) goto nomailbox;
		if (c == '\r') c = prot_getc(proxyd_in);
		if (c != '\n') goto extraargs;
		cmd_unselect(tag.s);
	    }
	    else goto badcmd;
	    break;

	default:
	badcmd:
	    prot_printf(proxyd_out, "%s BAD Unrecognized command\r\n", tag.s);
	    eatline(c);
	}

	continue;

    nologin:
	prot_printf(proxyd_out, "%s BAD Please login first\r\n", tag.s);
	eatline(c);
	continue;

    nomailbox:
	prot_printf(proxyd_out, "%s BAD Please select a mailbox first\r\n", 
		    tag.s);
	eatline(c);
	continue;

    missingargs:
	prot_printf(proxyd_out, "%s BAD Missing required argument to %s\r\n", 
		    tag.s, cmd.s);
	eatline(c);
	continue;

    extraargs:
	prot_printf(proxyd_out, "%s BAD Unexpected extra arguments to %s\r\n",
		    tag.s, cmd.s);
	eatline(c);
	continue;

    badsequence:
	prot_printf(proxyd_out, "%s BAD Invalid sequence in %s\r\n", 
		    tag.s, cmd.s);
	eatline(c);
	continue;

    badpartition:
	prot_printf(proxyd_out, "%s BAD Invalid partition name in %s\r\n",
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
    char *reply = 0;
    const char *val;
    char buf[MAX_MAILBOX_PATH];
    char *p;
    FILE *logfile;
    int plaintextloginpause;
    int result;

    canon_user = auth_canonifyid(user);
    if (!canon_user) {
	syslog(LOG_NOTICE, "badlogin: %s plaintext %s invalid user",
	       proxyd_clienthost, beautify_string(user));
	prot_printf(proxyd_out, "%s NO %s\r\n", tag, 
		    error_message(IMAP_INVALID_USER));
	return;
    }

    if (!strcmp(canon_user, "anonymous")) {
	if (config_getswitch("allowanonymouslogin", 0)) {
	    passwd = beautify_string(passwd);
	    if (strlen(passwd) > 500) passwd[500] = '\0';
	    syslog(LOG_NOTICE, "login: %s anonymous %s",
		   proxyd_clienthost, passwd);
	    reply = "Anonymous access granted";
	    proxyd_userid = xstrdup("anonymous");
	}
	else {
	    syslog(LOG_NOTICE, "badlogin: %s anonymous login refused",
		   proxyd_clienthost);
	    prot_printf(proxyd_out, "%s NO %s\r\n", tag,
		   error_message(IMAP_ANONYMOUS_NOT_PERMITTED));
	    return;
	}
    }
    else if ((result=sasl_checkpass(proxyd_saslconn,
				    canon_user,
				    strlen(canon_user),
				    passwd,
				    strlen(passwd),
				    (const char **) &reply))!=SASL_OK) {
	const char *errorstring = sasl_errstring(result, NULL, NULL);
	if (reply) {
	    syslog(LOG_NOTICE, "badlogin: %s plaintext %s %s",
		   proxyd_clienthost, canon_user, reply);
	}
	sleep(3);
	if (errorstring) {
	    prot_printf(proxyd_out, "%s NO Login failed: %s\r\n", 
			tag, errorstring);
	} else {
	    prot_printf(proxyd_out, "%s NO Login failed.", tag);
	}	    
	return;
    }
    else {
	proxyd_userid = xstrdup(canon_user);
	syslog(LOG_NOTICE, "login: %s %s plaintext %s", proxyd_clienthost,
	       canon_user, reply ? reply : "");
	if (plaintextloginpause = config_getint("plaintextloginpause", 0)) {
	    sleep(plaintextloginpause);
	}
    }
    

    proxyd_authstate = auth_newstate(canon_user, (char *)0);

    val = config_getstring("admins", "");
    while (*val) {
	for (p = (char *)val; *p && !isspace(*p); p++);
	strncpy(buf, val, p - val);
	buf[p-val] = 0;
	if (auth_memberof(proxyd_authstate, buf)) {
	    proxyd_userisadmin = 1;
	    break;
	}
	val = p;
	while (*val && isspace(*val)) val++;
    }

    if (!reply) reply = "User logged in";

    /* Create telemetry log */
    sprintf(buf, "%s%s%s/%u", config_dir, FNAME_LOGDIR, proxyd_userid,
	    getpid());
    logfile = fopen(buf, "w");
    if (logfile) {
	prot_setlog(proxyd_in, fileno(logfile));
	prot_setlog(proxyd_out, fileno(logfile));
	if (config_getswitch("logtimestamps", 0)) {
	    prot_setlogtime(proxyd_in, &proxyd_logtime);
	    prot_setlogtime(proxyd_out, &proxyd_logtime);
	}
    }

    prot_printf(proxyd_out, "%s OK %s\r\n", tag, reply);
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
    char *p;
    FILE *logfile;

    int *ssfp;
    char *ssfmsg=NULL;

    sasl_result = sasl_server_start(proxyd_saslconn, authtype,
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
	prot_printf(proxyd_out, "%s BAD Invalid base64 string\r\n", tag);
	return;
      }

      sasl_result = sasl_server_step(proxyd_saslconn,
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
	       proxyd_clienthost, authtype, errorstring);
	
	if (errstr) {
	    syslog(LOG_NOTICE, "badlogin: %s %s %s",
		   proxyd_clienthost, authtype, errstr);
	}
	
	sleep(3);
	
	if (errorstring) {
	    prot_printf(proxyd_out, "%s NO %s\r\n", tag, errorstring);
	} else {
	    prot_printf(proxyd_out, "%s NO Error authenticating\r\n", tag);
	}

	return;
    }

    /* successful authentication */

    /* get the userid from SASL --- already canonicalized from
     * mysasl_authproc()
     */
    sasl_result = sasl_getprop(proxyd_saslconn, SASL_USERNAME,
			     (void **) &proxyd_userid);
    if (sasl_result!=SASL_OK)
    {
	prot_printf(proxyd_out, "%s NO weird SASL error %d SASL_USERNAME\r\n", 
		    tag, sasl_result);
	syslog(LOG_ERR, "weird SASL error %d getting SASL_USERNAME", 
	       sasl_result);
	return;
    }

    proc_register("proxyd", proxyd_clienthost, proxyd_userid, (char *)0);

    syslog(LOG_NOTICE, "login: %s %s %s %s", proxyd_clienthost, proxyd_userid,
	   authtype, "User logged in");

    sasl_getprop(proxyd_saslconn, SASL_SSF, (void **) &ssfp);

    switch(*ssfp)
      {
      case 0: ssfmsg="no protection";break;
      case 1: ssfmsg="integrity protection";break;
      default: ssfmsg="privacy protection";break;
      }

    prot_printf(proxyd_out, "%s OK Success (%s)\r\n", tag,ssfmsg);

    prot_setsasl(proxyd_in,  proxyd_saslconn);
    prot_setsasl(proxyd_out, proxyd_saslconn);

    /* Create telemetry log */
    sprintf(buf, "%s%s%s/%u", config_dir, FNAME_LOGDIR, proxyd_userid,
	    getpid());
    logfile = fopen(buf, "w");
    if (logfile) {
	prot_setlog(proxyd_in, fileno(logfile));
	prot_setlog(proxyd_out, fileno(logfile));
	if (config_getswitch("logtimestamps", 0)) {
	    prot_setlogtime(proxyd_in, &proxyd_logtime);
	    prot_setlogtime(proxyd_out, &proxyd_logtime);
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
    if (backend_current) {
	prot_printf(backend_current->out, "%s %s\r\n", tag, cmd);
	pipe_including_tag(backend_current, tag);
    } else {
	prot_printf(proxyd_out, "%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
    }
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

    if (backend_current) {
	char mytag[128];
	
	proxyd_gentag(mytag);
	/* do i want to do a NOOP for every operation? */
	prot_printf(backend_current->out, "%s Noop\r\n", mytag);
	pipe_until_tag(backend_current, mytag);
    }
    prot_printf(proxyd_out, "* CAPABILITY ");
    prot_printf(proxyd_out, CAPABILITY_STRING);

    if (sasl_listmech(proxyd_saslconn, NULL, 
		      "AUTH=", " AUTH=", "",
		      &sasllist,
		      NULL, &mechcount) == SASL_OK && mechcount > 0) {
	prot_printf(proxyd_out, " %s", sasllist);      
	free(sasllist);
    } else {
	/* else don't show anything */
    }

#ifdef ENABLE_X_NETSCAPE_HACK
    prot_printf(proxyd_out, " X-NETSCAPE");
#endif
    prot_printf(proxyd_out, "\r\n");

    prot_printf(proxyd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Parse and perform an APPEND command.
 * The command has been parsed up to and including
 * the mailbox name.
 */
void cmd_append(char *tag, char *name)
{
    int r;
    char *mailboxname;
    char *newserver;
    struct backend *s = NULL;

    /* we want to pipeline this whole command through to the server that
       has name on it, and then do a noop on our current server */
    r = mboxname_tointernal(name, proxyd_userid, mailboxname);

    if (!r) {
	r = mboxlist_lookup(mailboxname, &newserver, NULL, NULL);
    }
    if (!r) {
	s = proxyd_findserver(newserver);
    }

    if (s) {
	prot_printf(s->out, "%s Append {%d+}\r\n%s ", tag, strlen(name), name);
	if (!pipe_command(s, 16384)) {
	    pipe_until_tag(s, tag);
	}
    }

    if (backend_current && backend_current != s) {
	char mytag[128];

	proxyd_gentag(mytag);
	
	prot_printf(backend_current->out, "%s Noop\r\n", mytag);
	pipe_until_tag(backend_current, mytag);
    }

    if (r) {
	prot_printf(proxyd_out, "%s NO %s\r\n", tag, error_message(r));
    } else {
	/* we're allowed to reference last_result since the noop, if
	   sent, went to a different server */
	prot_printf(proxyd_out, "%s %s\r\n", tag, s->last_result);
    }
}

/*
 * Perform a SELECT/EXAMINE/BBOARD command
 */
void cmd_select(char *tag, char *cmd, char *name)
{
    struct mailbox mailbox;
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r = 0;
    int usage;
    int doclose = 0;
    char *newserver;

    if (backend_current) {
	char mytag[128];

	proxyd_gentag(mytag);
	prot_printf(backend_current->out, "%s Unselect\r\n", mytag);
	pipe_until_tag(backend_current, mytag);
	backend_current = NULL;
    }

    if (cmd[0] == 'B') {
	/* BBoard namespace is empty */
	r = IMAP_MAILBOX_NONEXISTENT;
    }
    else {
	r = mboxname_tointernal(name, proxyd_userid, mailboxname);
    }

    if (!r) {
	r = mboxlist_lookup(mailboxname, &newserver, NULL, NULL);
    }

    if (!r) {
	backend_current = proxyd_findserver(newserver);
    }

    if (!backend_current) {
	r = IMAP_SERVER_UNAVAILABLE;
    }

    if (r) {
	prot_printf(proxyd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }

    prot_printf(backend_current->out, "%s %s {%d+}\r\n%s\r\n", tag, cmd, 
		strlen(mailboxname), mailboxname);
    switch (pipe_including_tag(backend_current, tag)) {
    case OK:
	proc_register("proxyd", proxyd_clienthost, proxyd_userid, mailboxname);
	syslog(LOG_DEBUG, "open: user %s opened %s on %s", proxyd_userid, name,
	       newserver);
	break;
    default:
	syslog(LOG_DEBUG, "open: user %s failed to open %s", proxyd_userid,
	       name);
	/* not successfully selected */
	backend_current = NULL;
	break;
    }
}
	  
/*
 * Perform a CLOSE command
 */
void cmd_close(char *tag)
{
    int r;

    assert(backend_current != NULL);
    
    prot_printf(backend_current->out, "%s Close\r\n", tag);
    pipe_including_tag(backend_current, tag);
    backend_current = NULL;
}

/*
 * Perform an UNSELECT command -- for some support of IMAP proxy.
 * Just like close except no expunge.
 */
void cmd_unselect(char *tag)
{
    assert(backend_current != NULL);

    prot_printf(backend_current->out, "%s Unselect\r\n", tag);
    pipe_including_tag(backend_current, tag);
    backend_current = NULL;
}

/*
 * Parse and perform a FETCH/UID FETCH command
 * The command has been parsed up to and including
 * the sequence
 */
void cmd_fetch(char *tag, char *sequence, int usinguid)
{
    char *cmd = usinguid ? "UID Fetch" : "Fetch";

    assert(backend_current != NULL);

    prot_printf(backend_current->out, "%s %s %s ", tag, cmd, sequence);
    if (!pipe_command(backend_current, 65536)) {
	pipe_including_tag(backend_current, tag);
    }
}

/*
 * Perform a PARTIAL command
 */
void cmd_partial(char *tag, char *msgno, char *data, char *start, char *count)
{
    assert(backend_current != NULL);

    prot_printf(backend_current->out, "%s Partial %s %s %s %s\r\n",
		tag, msgno, data, start, count);
    pipe_including_tag(backend_current, tag);
}

/*
 * Parse and perform a STORE/UID STORE command
 * The command has been parsed up to and including
 * the FLAGS/+FLAGS/-FLAGS
 */
void cmd_store(char *tag, char *sequence, char *operation, int usinguid)
{
    char *cmd = usinguid ? "UID Store" : "Store";

    assert(backend_current != NULL);

    prot_printf(backend_current->out, "%s %s %s %s ",
		tag, cmd, sequence, operation);
    if (!pipe_command(backend_current, 65536)) {
	pipe_including_tag(backend_current, tag);
    }
}

void cmd_search(char *tag, int usinguid)
{
    char *cmd = usinguid ? "UID Search" : "Search";

    assert(backend_current != NULL);

    prot_printf(backend_current->out, "%s %s ", tag, cmd);
    if (!pipe_command(backend_current, 65536)) {
	pipe_including_tag(backend_current, tag);
    }
}

/*
 * Perform a COPY/UID COPY command
 */    
void cmd_copy(char *tag, char *sequence, char *name, int usinguid)
{
    char *server;
    char *cmd = usinguid ? "UID Copy" : "Copy";
    struct backend *s = NULL;
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r;

    assert(backend_current != NULL);

    r = mboxname_tointernal(name, proxyd_userid, mailboxname);
    if (!r) r = mboxlist_lookup(mailboxname, &server, NULL, NULL);
    if (!r) s = proxyd_findserver(server);

    if (!s) {
	/* no such mailbox or other problem */
	r = mboxlist_createmailboxcheck(mailboxname, 0, 0, proxyd_userisadmin, 
					proxyd_userid, proxyd_authstate,
					NULL, NULL);
	prot_printf(proxyd_out, "%s NO %s%s\r\n", tag,
		    r == 0 ? "[TRYCREATE] " : "", error_message(r));
    } else if (s == backend_current) {
	/* this is the easy case */
	prot_printf(backend_current->out, "%s %s %s {%d+}\r\n%s\r\n",
		    tag, cmd, sequence, strlen(mailboxname), mailboxname);
	pipe_including_tag(backend_current, tag);
    } else {
#if NEEDS_PROXY
	/* this is the hard case; we have to fetch the messages and append
	   them to the other mailbox */
#endif
	prot_printf(proxyd_out, "%s NO i don't like you\r\n");
    }
}    

/*
 * Perform an EXPUNGE command
 * sequence == NULL if this isn't a UID EXPUNGE
 */
void cmd_expunge(char *tag, char *sequence)
{
    int r;

    assert(backend_current != NULL);

    if (sequence) {
	prot_printf(backend_current->out, "%s UID Expunge %s\r\n", tag,
		    sequence);
    } else {
	prot_printf(backend_current->out, "%s Expunge\r\n", tag);
    }
    pipe_including_tag(backend_current, tag);
}    

/*
 * Perform a CREATE command
 */
void cmd_create(char *tag, char *name, char *server)
{
    struct backend *s = NULL;
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r;

    r = mboxname_tointernal(name, proxyd_userid, mailboxname);

    if (!r && !server) {
	r = mboxlist_createmailboxcheck(mailboxname, 0, 0, proxyd_userisadmin,
					proxyd_userid, proxyd_authstate,
					NULL, &server);
    }
    if (!r && server) {
	s = proxyd_findserver(server);

	if (s) {
	    /* ok, send the create to that server */

	    prot_printf(s->out, "%s CREATE {%d+}\r\n%s\r\n", 
			tag, strlen(mailboxname), mailboxname);
	    pipe_including_tag(s, tag);
	} else {
	    /* you want it where?!? */
	    
	    prot_printf(proxyd_out, "%s NO %s\r\n", 
			error_message(IMAP_SERVER_UNAVAILABLE));
	}
    } else {
	prot_printf(proxyd_out, "%s NO %s\r\n", tag, error_message(r));
    }
}

/*
 * Perform a DELETE command
 */
void cmd_delete(char *tag, char *name)
{
    int r;
    char *server;
    struct backend *s = NULL;
    char mailboxname[MAX_MAILBOX_NAME+1];

    r = mboxname_tointernal(name, proxyd_userid, mailboxname);

    if (!r) r = mboxlist_lookup(mailboxname, &server, NULL, NULL);
    if (!r) {
	s = proxyd_findserver(server);

	if (s) {
	    prot_printf(s->out, "%s DELETE {%d+}\r\n%s\r\n", 
			tag, strlen(mailboxname), mailboxname);
	    pipe_including_tag(s, tag);
	} else {
	    prot_printf(proxyd_out, "%s NO %s\r\n",
			error_message(IMAP_SERVER_UNAVAILABLE));
	}
    } else {
	prot_printf(proxyd_out, "%s NO %s\r\n", tag, error_message(r));
    }
}	

/*
 * Perform a RENAME command
 */
void cmd_rename(char *tag, char *oldname, char *newname, char *partition)
{
    int r;
    char *server;
    char oldmailboxname[MAX_MAILBOX_NAME+1];
    char newmailboxname[MAX_MAILBOX_NAME+1];
    struct backend *s = NULL;

    if (partition) {
	prot_printf(proxyd_out, 
		    "%s NO cross-server RENAME not implemented\r\n", tag);
    } else {
        r = mboxname_tointernal(oldname, proxyd_userid, oldmailboxname);
	if (!r) mboxname_tointernal(newname, proxyd_userid, newmailboxname);
	if (!r) r = mboxlist_lookup(oldmailboxname, &server, NULL, NULL);
	if (!r) {
	    s = proxyd_findserver(server);

	    if (s) {
		prot_printf(s->out, "%s RENAME {%d+}\r\n%s {%d+}\r\n%s\r\n", 
			    tag, strlen(oldmailboxname), oldmailboxname,
			    strlen(newmailboxname), newmailboxname);
		pipe_including_tag(s, tag);
	    } else {
		prot_printf(proxyd_out, "%s NO %s\r\n",
			    error_message(IMAP_SERVER_UNAVAILABLE));
	    }
	} else {
	    prot_printf(proxyd_out, "%s NO %s\r\n", tag, error_message(r));
	}
    }
}

/*
 * Perform a FIND command
 */
void cmd_find(char *tag, char *namespace, char *pattern)
{
    char *p;
    lcase(namespace);

    for (p = pattern; *p; p++) {
	if (*p == '%') *p = '?';
    }

    if (!strcmp(namespace, "mailboxes")) {
	mboxlist_findsub(pattern, proxyd_userisadmin, proxyd_userid,
			 proxyd_authstate, mailboxdata);
    } else if (!strcmp(namespace, "all.mailboxes")) {
	mboxlist_findall(pattern, proxyd_userisadmin, proxyd_userid,
			 proxyd_authstate, mailboxdata, NULL);
    } else if (!strcmp(namespace, "bboards")
	       || !strcmp(namespace, "all.bboards")) {
	;
    } else {
	prot_printf(proxyd_out, "%s BAD Invalid FIND subcommand\r\n", tag);
	return;
    }

    if (backend_current) {
	char mytag[128];

	proxyd_gentag(mytag);

	prot_printf(backend_current->out, "%s Noop\r\n", mytag);
	pipe_until_tag(backend_current, mytag);
    }

    prot_printf(proxyd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Perform a LIST or LSUB command
 * LISTs we do locally
 * LSUBs we farm out
 */
void cmd_list(char *tag, int subscribed, char *reference, char *pattern)
{
    char *buf = NULL;
    int patlen = 0;
    int reflen = 0;
    static int ignorereference = -1;

    /* Ignore the reference argument?
       (the behavior in 1.5.10 & older) */
    if (ignorereference == -1) {
	ignorereference = config_getswitch("ignorereference", 0);
    }

    /* Reset state in mstringdata */
    mstringdata(NULL, NULL, 0, 0);
    
    if (!pattern[0] && !subscribed) {
	/* Special case: query top-level hierarchy separator */
	prot_printf(proxyd_out, "* LIST (\\Noselect) \".\" \"\"\r\n");
    } else if (subscribed) {	/* do an LSUB command; contact our INBOX */
	if (!backend_inbox) {
	    backend_inbox = proxyd_findinboxserver();
	}

	if (backend_inbox) {
	    prot_printf(backend_inbox->out, 
			"%s Lsub {%d+}\r\n%s {%d+}\r\n%s\r\n",
			tag, strlen(reference), reference,
			strlen(pattern), pattern);
	    pipe_until_tag(backend_inbox, tag);
	} else {		/* user doesn't have an INBOX */
	    /* noop */
	}
    } else {			/* do a LIST locally */
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

	mboxlist_findall(pattern, proxyd_userisadmin, proxyd_userid,
			 proxyd_authstate, listdata, NULL);
	listdata((char *)0, 0, 0, 0);

	if (buf) free(buf);
    }

    if (backend_current && (!subscribed || backend_current != backend_inbox)) {
	/* our Lsub would've done this if 
	   backend_current == backend_inbox */
	char mytag[128];

	proxyd_gentag(mytag);

	prot_printf(backend_current->out, "%s Noop\r\n", mytag);
	pipe_until_tag(backend_current, mytag);
    }

    prot_printf(proxyd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}
  
/*
 * Perform a SUBSCRIBE (add is nonzero) or
 * UNSUBSCRIBE (add is zero) command
 */
void cmd_changesub(char *tag, char *namespace, char *name, int add)
{
    char *cmd = add ? "Subscribe" : "Unsubscribe";
    int r;
    char mailboxname[MAX_MAILBOX_NAME+1];

    if (!backend_inbox) {
	backend_inbox = proxyd_findinboxserver();
    }

    if (backend_inbox) {
	if (namespace) {
	    prot_printf(backend_inbox->out, 
			"%s %s {%d+}\r\n%s {%d+}\r\n%s\r\n", 
			tag, cmd, 
			strlen(namespace), namespace,
			strlen(name), name);
	} else {
	    prot_printf(backend_inbox->out, "%s %s {%d+}\r\n%s\r\n", 
			tag, cmd, 
			strlen(name), name);
	}
	pipe_including_tag(backend_inbox, tag);
    } else {
	r = IMAP_SERVER_UNAVAILABLE;
	prot_printf(proxyd_out, "%s NO %s: %s\r\n", tag,
		    add ? "Subscribe" : "Unsubscribe", error_message(r));
    }
}

/*
 * Perform a GETACL command
 */
void cmd_getacl(char *tag, char *name, int oldform)
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r, access;
    char *acl;
    char *rights, *nextid;

    r = mboxname_tointernal(name, proxyd_userid, mailboxname);

    if (!r) {
	r = mboxlist_lookup(mailboxname, (char **)0, &acl, NULL);
    }

    if (!r) {
	access = acl_myrights(proxyd_authstate, acl);

	if (!(access & (ACL_READ|ACL_ADMIN)) &&
	    !proxyd_userisadmin &&
	    !mboxname_userownsmailbox(proxyd_userid, mailboxname)) {
	    r = (access & ACL_LOOKUP) ?
	      IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	}
    }
    if (r) {
	prot_printf(proxyd_out, "%s NO %s\r\n", tag, error_message(r));
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

	    prot_printf(proxyd_out, "* ACL MAILBOX ");
	    printastring(name);
	    prot_printf(proxyd_out, " ");
	    printastring(acl);
	    prot_printf(proxyd_out, " ");
	    printastring(rights);
	    prot_printf(proxyd_out, "\r\n");
	    acl = nextid;
	}
    }
    else {
	prot_printf(proxyd_out, "* ACL ");
	printastring(name);
	
	while (acl) {
	    rights = strchr(acl, '\t');
	    if (!rights) break;
	    *rights++ = '\0';

	    nextid = strchr(rights, '\t');
	    if (!nextid) break;
	    *nextid++ = '\0';

	    prot_printf(proxyd_out, " ");
	    printastring(acl);
	    prot_printf(proxyd_out, " ");
	    printastring(rights);
	    acl = nextid;
	}
	prot_printf(proxyd_out, "\r\n");
    }
    prot_printf(proxyd_out, "%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Perform a LISTRIGHTS command
 */
void cmd_listrights(char *tag, char *name, char *identifier)
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r, rights;
    char *canon_identifier;
    int canonidlen;
    char *acl;
    char *rightsdesc;

    r = mboxname_tointernal(name, proxyd_userid, mailboxname);

    if (!r) {
	r = mboxlist_lookup(mailboxname, (char **)0, &acl, NULL);
    }

    if (!r) {
	rights = acl_myrights(proxyd_authstate, acl);

	if (!rights && !proxyd_userisadmin &&
	    !mboxname_userownsmailbox(proxyd_userid, mailboxname)) {
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

	prot_printf(proxyd_out, "* LISTRIGHTS ");
	printastring(name);
	prot_putc(' ', proxyd_out);
	printastring(identifier);
	prot_printf(proxyd_out, " %s", rightsdesc);

	prot_printf(proxyd_out, "\r\n%s OK %s\r\n", tag,
		    error_message(IMAP_OK_COMPLETED));
	return;
    }

    prot_printf(proxyd_out, "%s NO %s\r\n", tag, error_message(r));
}

/*
 * Perform a MYRIGHTS command
 */
void cmd_myrights(char *tag, char *name, int oldform)
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r, rights;
    char *acl;
    char str[ACL_MAXSTR];

    r = mboxname_tointernal(name, proxyd_userid, mailboxname);

    if (!r) {
	r = mboxlist_lookup(mailboxname, (char **)0, &acl, NULL);
    }

    if (!r) {
	rights = acl_myrights(proxyd_authstate, acl);

	/* Add in implicit rights */
	if (proxyd_userisadmin ||
	    mboxname_userownsmailbox(proxyd_userid, mailboxname)) {
	    rights |= ACL_LOOKUP|ACL_ADMIN;
	}

	if (!rights) {
	    r = IMAP_MAILBOX_NONEXISTENT;
	}
    }
    if (r) {
	prot_printf(proxyd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(proxyd_out, "* MYRIGHTS ");
    if (oldform) prot_printf(proxyd_out, "MAILBOX ");
    printastring(name);
    prot_printf(proxyd_out, " ");
    printastring(acl_masktostr(rights, str));
    prot_printf(proxyd_out, "\r\n%s OK %s\r\n", tag,
		error_message(IMAP_OK_COMPLETED));
}

/*
 * Perform a SETACL command
 */
void cmd_setacl(char *tag, char *name, char *identifier, char *rights)
{
    int r;
    char *cmd = rights ? "Setacl" : "Deleteacl";
    char mailboxname[MAX_MAILBOX_NAME+1];
    char *server;
    struct backend *s;

    r = mboxname_tointernal(name, proxyd_userid, mailboxname);

    if (!r) {
	r = mboxlist_lookup(mailboxname, &server, NULL, NULL);
    }

    if (!r) {
	s = proxyd_findserver(server);
    }

    if (s) {
	if (rights) {
	    prot_printf(s->out, 
			"%s Setacl {%d+}\r\n%s {%d+}\r\n%s {%d+}\r\n%s\r\n",
			tag, strlen(name), name,
			strlen(identifier), identifier,
			strlen(rights), rights);
	} else {
	    prot_printf(s->out, 
			"%s Deleteacl {%d+}\r\n%s {%d+}\r\n%s\r\n",
			tag, strlen(name), name,
			strlen(identifier), identifier);
	}	    
	pipe_including_tag(s, tag);
    } else {
	r = IMAP_SERVER_UNAVAILABLE;
    }

    if (r) {
	prot_printf(proxyd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
}

/*
 * Perform a GETQUOTA command
 */
void cmd_getquota(char *tag, char *name)
{
    prot_printf(proxyd_out, "%s NO not supported from proxy server\r\n");
}

/*
 * Perform a GETQUOTAROOT command
 */
void cmd_getquotaroot(char *tag, char *name)
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    char *server;
    int r;
    struct backend *s;

    r = mboxname_tointernal(name, proxyd_userid, mailboxname);
    if (!r) r = mboxlist_lookup(mailboxname, &server, NULL, NULL);
    if (!r) s = proxyd_findserver(server);

    if (s) {
	prot_printf(s->out, "%s Getquotaroot {%d+}\r\n%s\r\n",
		    tag, strlen(name), name);
	pipe_including_tag(s, tag);
    } else {
	r = IMAP_SERVER_UNAVAILABLE;
    }

    if (r) {
	prot_printf(proxyd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
}

/*
 * Parse and perform a SETQUOTA command
 * The command has been parsed up to the resource list
 */
void cmd_setquota(char *tag, char *quotaroot)
{
    prot_printf(proxyd_out, "%s NO not supported from proxy server\r\n");
    eatline(prot_getc(proxyd_in));
}

/*
 * Parse and perform a STATUS command
 * The command has been parsed up to the attribute list
 */
void cmd_status(char *tag, char *name)
{
    char mailboxname[MAX_MAILBOX_NAME+1];
    int r;
    char *server;
    struct backend *s;

    r = mboxname_tointernal(name, proxyd_userid, mailboxname);

    if (!r) {
	r = mboxlist_lookup(mailboxname, &server, NULL, NULL);
    }

    if (!r) {
	s = proxyd_findserver(server);
    }

    if (!s) {
	r = IMAP_SERVER_UNAVAILABLE;
    }
    
    if (!r) {
	prot_printf(s->out, "%s Status {%d}\r\n%s ", tag,
		    strlen(name), name);
	if (!pipe_command(s, 65536)) {
	    pipe_until_tag(s, tag);
	}
	if (backend_current && s != backend_current) {
	    char mytag[128];
	    
	    proxyd_gentag(mytag);

	    prot_printf(backend_current->out, "%s Noop\r\n", mytag);
	    pipe_until_tag(backend_current, mytag);
	}
    }

    if (!r) {
	prot_printf(proxyd_out, "%s %s\r\n", tag, s->last_result);
    } else {
	prot_printf(proxyd_out, "%s NO %s\r\n", error_message(r));
    }
}

#ifdef ENABLE_X_NETSCAPE_HACK
/*
 * Reply to Netscape's crock with a crock of my own
 */
void
cmd_netscape(tag)
    char *tag;
{
    char *url;
    /* so tempting, and yet ... */
    /* url = "http://random.yahoo.com/ryl/"; */
    url = config_getstring("netscapeurl",
			   "http://andrew2.andrew.cmu.edu/cyrus/imapd/netscape-admin.html");

    /* I only know of three things to reply with: */
    prot_printf(proxyd_out,
"* OK [NETSCAPE] Carnegie Mellon Cyrus IMAP proxy\r\n* VERSION %s\r\n",
		CYRUS_VERSION);
    prot_printf(proxyd_out,
		"* ACCOUNT-URL %s\r\n%s OK %s\r\n",
		url, tag, error_message(IMAP_OK_COMPLETED));

    /* no tagged response?!? */
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
    mboxlist_findall(pattern, proxyd_userisadmin, proxyd_userid,
		     proxyd_authstate, namespacedata, (void*) sawone);

    prot_printf(proxyd_out, "* NAMESPACE %s %s %s\r\n",
		(sawone[NAMESPACE_INBOX]) ? "((\"INBOX.\" \".\"))" : "NIL",
		(sawone[NAMESPACE_USER]) ? "((\"user.\" \".\"))" : "NIL",
		(sawone[NAMESPACE_SHARED]) ? "((\"\" \".\"))" : "NIL");

    prot_printf(proxyd_out, "%s OK %s\r\n", tag,
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
	c = prot_getc(proxyd_in);
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
 * Parse an astring
 * (atom, quoted-string, or literal)
 */
int getastring(buf)
struct buf *buf;
{
    int c;
    int i, len = 0;
    int sawdigit = 0;
    int isnowait;

    if (buf->alloc == 0) {
	buf->alloc = BUFGROWSIZE;
	buf->s = xmalloc(buf->alloc+1);
    }
	
    c = prot_getc(proxyd_in);
    switch (c) {
    case EOF:
    case ' ':
    case '(':
    case ')':
    case '\r':
    case '\n':
	/* Invalid starting character */
	buf->s[0] = '\0';
	if (c != EOF) prot_ungetc(c, proxyd_in);
	return EOF;

    default:
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
	    c = prot_getc(proxyd_in);
	}
	
    case '\"':
	/*
	 * Quoted-string.  Server is liberal in accepting qspecials
	 * other than double-quote, CR, and LF.
	 */
	for (;;) {
	    c = prot_getc(proxyd_in);
	    if (c == '\\') {
		c = prot_getc(proxyd_in);
	    }
	    else if (c == '\"') {
		buf->s[len] = '\0';
		return prot_getc(proxyd_in);
	    }
	    else if (c == EOF || c == '\r' || c == '\n') {
		buf->s[len] = '\0';
		if (c != EOF) prot_ungetc(c, proxyd_in);
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
	while ((c = prot_getc(proxyd_in)) != EOF && isdigit(c)) {
	    sawdigit = 1;
	    len = len*10 + c - '0';
	}
	if (c == '+') {
	    isnowait++;
	    c = prot_getc(proxyd_in);
	}
	if (!sawdigit || c != '}') {
	    if (c != EOF) prot_ungetc(c, proxyd_in);
	    return EOF;
	}
	c = prot_getc(proxyd_in);
	if (c != '\r') {
	    if (c != EOF) prot_ungetc(c, proxyd_in);
	    return EOF;
	}
	c = prot_getc(proxyd_in);
	if (c != '\n') {
	    if (c != EOF) prot_ungetc(c, proxyd_in);
	    return EOF;
	}
	if (len >= buf->alloc) {
	    buf->alloc = len+1;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
	}
	if (!isnowait) {
	    prot_printf(proxyd_out, "+ go ahead\r\n");
	    prot_flush(proxyd_out);
	}
	for (i = 0; i < len; i++) {
	    c = prot_getc(proxyd_in);
	    if (c == EOF) {
		buf->s[len] = '\0';
		return EOF;
	    }
	    buf->s[i] = c;
	}
	buf->s[len] = '\0';
	if (strlen(buf->s) != len) return EOF; /* Disallow imbedded NUL */
	return prot_getc(proxyd_in);
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
	c1 = prot_getc(proxyd_in);
	if (c1 == '\r') {
	    c1 = prot_getc(proxyd_in);
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
	
	c2 = prot_getc(proxyd_in);
	if (CHAR64(c2) == XX) {
	    eatline(c2);
	    return -1;
	}

	c3 = prot_getc(proxyd_in);
	if (c3 != '=' && CHAR64(c3) == XX) {
	    eatline(c3);
	    return -1;
	}

	c4 = prot_getc(proxyd_in);
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
	    c1 = prot_getc(proxyd_in);
	    if (c1 == '\r') c1 = prot_getc(proxyd_in);
	    if (c1 != '\n') {
		eatline(c1);
		return -1;
	    }
	    if (c4 != '=') return -1;
	    return len;
	}
	buf->s[len++] = (((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
	if (c4 == '=') {
	    c1 = prot_getc(proxyd_in);
	    if (c1 == '\r') c1 = prot_getc(proxyd_in);
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
		c = prot_getc(proxyd_in);/* Eat newline */
		while (size--) {
		    c = prot_getc(proxyd_in); /* Eat contents */
		}
		state = 0;	/* Go back to scanning for eol */
	    }
	}
	else if (state == 1 && isdigit(c)) {
	    size = size * 10 + c - '0';
	}
	else state = 0;

	c = prot_getc(proxyd_in);
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
	prot_printf(proxyd_out, "{%u}\r\n%s", strlen(s), s);
    }
    else {
	prot_printf(proxyd_out, "\"%s\"", s);
    }
}

/*
 * Print 's' as an atom, quoted-string, or literal
 */
void printastring(const char *s)
{
    const char *p;
    int len = 0;

    if (imparse_isatom(s)) {
	prot_printf(proxyd_out, "%s", s);
	return;
    }

    /* Look for any non-QCHAR characters */
    for ((p = s) && len < 1024; *p; p++) {
	len++;
	if (*p & 0x80 || *p == '\r' || *p == '\n'
	    || *p == '\"' || *p == '%' || *p == '\\') break;
    }

    if (*p || len >= 1024) {
	prot_printf(proxyd_out, "{%u}\r\n%s", strlen(s), s);
    }
    else {
	prot_printf(proxyd_out, "\"%s\"", s);
    }
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

    prot_putc('+', proxyd_out);
    prot_putc(' ', proxyd_out);
    while (len) {
	c1 = *data++;
	len--;
	prot_putc(basis_64[c1>>2], proxyd_out);
	if (len == 0) c2 = 0;
	else c2 = *data++;
	prot_putc(basis_64[((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)], proxyd_out);
	if (len == 0) {
	    prot_putc('=', proxyd_out);
	    prot_putc('=', proxyd_out);
	    break;
	}

	if (--len == 0) c3 = 0;
	else c3 = *data++;
        prot_putc(basis_64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)], proxyd_out);
	if (len == 0) {
	    prot_putc('=', proxyd_out);
	    break;
	}
	
	--len;
        prot_putc(basis_64[c3 & 0x3F], proxyd_out);
    }
    prot_putc('\r', proxyd_out);
    prot_putc('\n', proxyd_out);
    prot_flush(proxyd_out);
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
    prot_printf(proxyd_out, "* MAILBOX %s\r\n", name);
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
	prot_printf(proxyd_out, "* %s (%s) \".\" ", cmd,
	       lastnamehassub ? "" : "\\Noinferiors");
	printastring(lastname);
	prot_printf(proxyd_out, "\r\n");
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
    prot_printf(proxyd_out, "* %s (%s) \".\" ", cmd, c ? "\\Noselect" : "");
    printstring(name);
    prot_printf(proxyd_out, "\r\n");
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
