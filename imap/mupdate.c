/* mupdate.c -- cyrus murder database master 
 *
 * $Id: mupdate.c,v 1.40 2002/02/01 19:42:52 rjs3 Exp $
 * Copyright (c) 2001 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>

#include <sys/time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <syslog.h>
#include <errno.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include "mupdate.h"
#include "mupdate-client.h"
#include "xmalloc.h"
#include "iptostring.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "prot.h"
#include "imapconf.h"
#include "version.h"

static int masterp = 0;

enum {
    poll_interval = 1
};

struct pending {
    enum settype t;
    struct pending *next;

    char mailbox[MAX_MAILBOX_NAME];
};

struct conn {
    int fd;
    struct protstream *pin;
    struct protstream *pout;
    sasl_conn_t *saslconn;
    char *userid;

    const char *clienthost;

    struct 
    {
	char *ipremoteport;
	char *iplocalport;
    } saslprops;

    /* pending changes to send, in reverse order */
    const char *streaming; /* tag */
    pthread_mutex_t m;
    pthread_cond_t cond;

    struct pending *plist;
    struct conn *updatelist_next;

    /* Prefix for list commands */
    const char *list_prefix;
    size_t list_prefix_len;

    struct conn *next;
};

int ready_for_connections = 0;
pthread_cond_t ready_for_connections_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t ready_for_connections_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t connlist_mutex = PTHREAD_MUTEX_INITIALIZER;
struct conn *connlist = NULL;

/* ---- database access ---- */
pthread_mutex_t mailboxes_mutex = PTHREAD_MUTEX_INITIALIZER;
struct conn *updatelist = NULL;

/* --- prototypes --- */
void cmd_authenticate(struct conn *C,
		      const char *tag, const char *mech,
		      const char *clientstart);
void cmd_set(struct conn *C, 
	     const char *tag, const char *mailbox,
	     const char *server, const char *acl, enum settype t);
void cmd_find(struct conn *C, const char *tag, const char *mailbox,
	      int dook);
void cmd_list(struct conn *C, const char *tag, const char *host_prefix);
void cmd_startupdate(struct conn *C, const char *tag);
void shut_down(int code);
static int reset_saslconn(struct conn *c);
void database_init();
void sendupdates(struct conn *C);

/* --- prototypes in mupdate-client.c */
void *mupdate_client_start(void *rock);

/* --- mutex wrapper functions for SASL */
void *my_mutex_new(void)
{
    pthread_mutex_t *ret = (pthread_mutex_t *)xmalloc(sizeof(pthread_mutex_t));

    pthread_mutex_init(ret, NULL);

    return ret;
}

int my_mutex_destroy(pthread_mutex_t *m)
{
    if(!m) return SASL_BADPARAM;
    
    if(pthread_mutex_destroy(m)) return SASL_FAIL;

    free(m);

    return SASL_OK;
}
/* end mutex wrapper functions */

static struct conn *conn_new(int fd)
{
    struct conn *C = xzmalloc(sizeof(struct conn));
    
    C->fd = fd;
    pthread_mutex_lock(&connlist_mutex); /* LOCK */
    C->next = connlist;
    connlist = C;
    pthread_mutex_unlock(&connlist_mutex); /* UNLOCK */

    return C;
}

static void conn_free(struct conn *C)
{
    if (C->streaming) {		/* remove from updatelist */
	struct conn *upc;

	pthread_mutex_lock(&mailboxes_mutex);

	if (C == updatelist) {
	    /* first thing in updatelist */
	    updatelist = C->updatelist_next;
	} else {
	    /* find in update list */
	    for (upc = updatelist; upc->updatelist_next != NULL; 
		 upc = upc->updatelist_next) {
		if (upc->updatelist_next == C) break;
	    }
	    /* must find it ! */
	    assert(upc->updatelist_next == C);

	    upc->updatelist_next = C->updatelist_next;
	}

	pthread_mutex_unlock(&mailboxes_mutex);
    }

    pthread_mutex_lock(&connlist_mutex); /* LOCK */
    /* remove from connlist */
    if (C == connlist) {
	connlist = connlist->next;
    } else {
	struct conn *t;

	for (t = connlist; t->next != NULL; t = t->next) {
	    if (t->next == C) break;
	}
	assert(t != NULL);
	t->next = C->next;
    }

    pthread_mutex_unlock(&connlist_mutex); /* UNLOCK */

    if (C->pin) prot_free(C->pin);
    if (C->pout) prot_free(C->pout);
    close(C->fd);
    if (C->saslconn) sasl_dispose(&C->saslconn);

    /* free update list */

    free(C);
}

/* should we allow users to proxy?  return SASL_OK if yes,
   SASL_BADAUTH otherwise */
static int mysasl_authproc(sasl_conn_t *conn,
			   void *context,
			   const char *requested_user, unsigned rlen,
			   const char *auth_identity, unsigned alen,
			   const char *def_realm, unsigned urlen,
			   struct propctx *propctx)
{
    const char *val;
    char *realm;
    int allowed=0;
    struct auth_state *authstate;

    /* check if remote realm */
    if ((realm = strchr(auth_identity, '@'))!=NULL) {
	realm++;
	val = config_getstring("loginrealms", "");
	while (*val) {
	    if (!strncasecmp(val, realm, strlen(realm)) &&
		(!val[strlen(realm)] || isspace((int) val[strlen(realm)]))) {
		break;
	    }
	    /* not this realm, try next one */
	    while (*val && !isspace((int) *val)) val++;
	    while (*val && isspace((int) *val)) val++;
	}
	if (!*val) {
	    sasl_seterror(conn, 0, "cross-realm login %s denied",
			  auth_identity);
	    return SASL_BADAUTH;
	}
    }

    /* ok, is auth_identity an admin? 
     * for now only admins can do mupdate from another machine
     */
    authstate = auth_newstate(auth_identity, NULL);
    allowed = authisa(authstate, "mupdate", "admins");
    auth_freestate(authstate);
    
    if (!allowed) {
	sasl_seterror(conn, 0, "only admins may authenticate");
	return SASL_BADAUTH;
    }

    return SASL_OK;
}

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, &mysasl_authproc, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc, char **argv, char **envp)
{
    int r;
    int opt;

    config_changeident("mupdate");
    
    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signals_add_handlers();
    signal(SIGPIPE, SIG_IGN);

    /* set the SASL allocation functions */
    sasl_set_alloc((sasl_malloc_t *) &xmalloc, 
		   (sasl_calloc_t *) &calloc, 
		   (sasl_realloc_t *) &xrealloc, 
		   (sasl_free_t *) &free);

    /* set the SASL mutex functions */
    sasl_set_mutex((sasl_mutex_alloc_t *) &my_mutex_new,
                   (sasl_mutex_lock_t *) &pthread_mutex_lock,
                   (sasl_mutex_unlock_t *) &pthread_mutex_unlock,
                   (sasl_mutex_free_t *) &my_mutex_destroy);

    /* load the SASL plugins */
    if ((r = sasl_server_init(mysasl_cb, "Cyrus")) != SASL_OK) {
	syslog(LOG_ERR, "SASL failed initializing: sasl_server_init(): %s", 
	       sasl_errstring(r, NULL, NULL));
	return EC_SOFTWARE;
    }

    if ((r = sasl_client_init(NULL)) != SASL_OK) {
	syslog(LOG_ERR, "SASL failed initializing: sasl_client_init(): %s", 
	       sasl_errstring(r, NULL, NULL));
	return EC_SOFTWARE;
    }

    /* see if we're the master or a slave */
    while ((opt = getopt(argc, argv, "C:m")) != EOF) {
	switch (opt) {
	case 'C':
	    break;
	case 'm':
	    masterp = 1;
	    break;
	default:
	    break;
	}
    }

    database_init();

    if (!masterp) {
	pthread_t t;
	
	r = pthread_create(&t, NULL, &mupdate_client_start, NULL);
	if(r == 0) {
	    pthread_detach(t);
	} else {
	    syslog(LOG_ERR, "could not start client thread");
	    return EC_SOFTWARE;
	}
    } else {
	mupdate_ready();
    }

    return 0;
}

/* called if 'service_init()' was called but not 'service_main()' */
void service_abort(int error)
{
    exit(error);
}

void fatal(const char *s, int code)
{
    syslog(LOG_ERR, "%s", s);
    exit(code);
}

#define CHECKNEWLINE(c, ch) do { if ((ch) == '\r') (ch)=prot_getc((c)->pin); \
                       		 if ((ch) != '\n') goto extraargs; } while (0)

void cmdloop(struct conn *c)
{
    struct buf tag, cmd, arg1, arg2, arg3;
    const char *mechs;
    int ret;
    unsigned int mechcount;

    syslog(LOG_DEBUG, "starting cmdloop() on fd %d", c->fd);
        
    /* zero out struct bufs */
    /* Note that since they live on the stack for the duration of the
     * connection we don't need to fill up the struct conn with them */
    memset(&tag, 0, sizeof(struct buf));
    memset(&cmd, 0, sizeof(struct buf));
    memset(&arg1, 0, sizeof(struct buf));
    memset(&arg2, 0, sizeof(struct buf));
    memset(&arg3, 0, sizeof(struct buf));

    ret=sasl_listmech(c->saslconn, NULL, "\r\n* AUTH ", " ", "", &mechs,
		      NULL, &mechcount);

    /* AUTH banner is mandatory, even if empty */
    prot_printf(c->pout,
		"* OK MUPDATE \"%s\" \"Cyrus Murder\" \"%s\" \"%s\"%s\r\n", 
		config_servername,
		CYRUS_VERSION, masterp ? "(master)" : "(slave)",
		(ret == SASL_OK && mechcount > 0) ? mechs : "* AUTH");
    for (;;) {
	int ch;
	char *p;

	signals_poll();
	
	if (c->streaming) {
	    /* if streaming updates, check if i have data to send */
	    sendupdates(c);
	}

	ch = getword(c->pin, &tag);
	if (ch == EOF && errno == EAGAIN) {
	    /* streaming and no input from client */
	    continue;
	}
	if (ch == EOF) {
	    const char *err;
	    
	    if ((err = prot_error(c->pin)) != NULL) {
		syslog(LOG_WARNING, "%s, closing connection", err);
		prot_printf(c->pout, "* BYE %s\r\n", err);
	    }
	    goto done;
	}

	if (ch != ' ') {
	    prot_printf(c->pout, "%s BAD \"Need command\"\r\n", tag.s);
	    eatline(c->pin, ch);
	    continue;
	}

	/* parse command name */
	ch = getword(c->pin, &cmd);
	if (!cmd.s[0]) {
	    prot_printf(c->pout, "%s BAD \"Null command\"\r\n", tag.s);
	    eatline(c->pin, ch);
	    continue;
	}

	if (islower((unsigned char) cmd.s[0])) {
	    cmd.s[0] = toupper((unsigned char) cmd.s[0]);
	}
	for (p = &cmd.s[1]; *p; p++) {
	    if (isupper((unsigned char) *p)) *p = tolower((unsigned char) *p);
	}
	
	switch (cmd.s[0]) {
	case 'A':
	    if (!strcmp(cmd.s, "Authenticate")) {
		int opt = 0;
		
		if (ch != ' ') goto missingargs;
		ch = getstring(c->pin, c->pout, &arg1);
		if (ch == ' ') {
		    ch = getstring(c->pin, c->pout, &arg2);
		    opt = 1;
		}
		CHECKNEWLINE(c, ch);

		if (c->userid) {
		    prot_printf(c->pout,
				"%s BAD \"already authenticated\"\r\n",
				tag.s);
		    continue;
		}

		cmd_authenticate(c, tag.s, arg1.s, opt ? arg2.s : NULL);
	    }
	    else if (!c->userid) goto nologin;
	    else if (!strcmp(cmd.s, "Activate")) {
		if (ch != ' ') goto missingargs;
		ch = getstring(c->pin, c->pout, &arg1);
		if (ch != ' ') goto missingargs;
		ch = getstring(c->pin, c->pout, &arg2);
		if (ch != ' ') goto missingargs;
		ch = getstring(c->pin, c->pout, &arg3);
		CHECKNEWLINE(c, ch);

		if (c->streaming) goto notwhenstreaming;
		if (!masterp) goto masteronly;

		cmd_set(c, tag.s, arg1.s, arg2.s, arg3.s, SET_ACTIVE);
	    }
	    else goto badcmd;
	    break;

	case 'D':
	    if (!c->userid) goto nologin;
	    else if (!strcmp(cmd.s, "Delete")) {
		if (ch != ' ') goto missingargs;
		ch = getstring(c->pin, c->pout, &arg1);
		CHECKNEWLINE(c, ch);

		if (c->streaming) goto notwhenstreaming;
		if (!masterp) goto masteronly;

		cmd_set(c, tag.s, arg1.s, NULL, NULL, SET_DELETE);
	    }
	    else goto badcmd;
	    break;

	case 'F':
	    if (!c->userid) goto nologin;
	    else if (!strcmp(cmd.s, "Find")) {
		if (ch != ' ') goto missingargs;
		ch = getstring(c->pin, c->pout, &arg1);
		CHECKNEWLINE(c, ch);

		if (c->streaming) goto notwhenstreaming;
		
		cmd_find(c, tag.s, arg1.s, 1);
	    }
	    else goto badcmd;
	    break;

	case 'L':
	    if (!strcmp(cmd.s, "Logout")) {
		CHECKNEWLINE(c, ch);

		prot_printf(c->pout, "%s OK \"bye-bye\"\r\n", tag.s);
		goto done;
	    }
	    else if (!c->userid) goto nologin;
	    else if (!strcmp(cmd.s, "List")) {
		int opt = 0;

		if (ch == ' ') {
		    /* Optional partition/host prefix parameter */
		    ch = getstring(c->pin, c->pout, &arg1);
		    opt = 1;
		}
		CHECKNEWLINE(c, ch);

		if (c->streaming) goto notwhenstreaming;

		cmd_list(c, tag.s, opt ? arg1.s : NULL);
		
		prot_printf(c->pout, "%s OK \"list complete\"\r\n", tag.s);
	    }
	    else goto badcmd;
	    break;

	case 'N':
	    if (!c->userid) goto nologin;
	    else if (!strcmp(cmd.s, "Noop")) {
		CHECKNEWLINE(c, ch);

		prot_printf(c->pout, "%s OK \"Noop done\"\r\n", tag.s);
	    }
	    else goto badcmd;
	    break;

	case 'R':
	    if (!c->userid) goto nologin;
	    else if (!strcmp(cmd.s, "Reserve")) {
		if (ch != ' ') goto missingargs;
		ch = getstring(c->pin, c->pout, &arg1);
		if (ch != ' ') goto missingargs;
		ch = getstring(c->pin, c->pout, &arg2);
		CHECKNEWLINE(c, ch);

		if (c->streaming) goto notwhenstreaming;
		if (!masterp) goto masteronly;
		
		cmd_set(c, tag.s, arg1.s, arg2.s, NULL, SET_RESERVE);
	    }
	    else goto badcmd;
	    break;

	case 'U':
	    if (!c->userid) goto nologin;
	    else if (!strcmp(cmd.s, "Update")) {
		CHECKNEWLINE(c, ch);
		if (c->streaming) goto notwhenstreaming;
		
		cmd_startupdate(c, tag.s);
	    }
	    else goto badcmd;
	    break;

	default:
	badcmd:
	    prot_printf(c->pout, "%s BAD \"Unrecognized command\"\r\n", tag.s);
	    eatline(c->pin, ch);
	    continue;

	extraargs:
	    prot_printf(c->pout, "%s BAD \"Extra arguments\"\r\n", tag.s);
	    eatline(c->pin, ch);
	    continue;
	    
	missingargs:
	    prot_printf(c->pout, "%s BAD \"Missing arguments\"\r\n", tag.s);
	    eatline(c->pin, ch);
	    continue;

	notwhenstreaming:
	    prot_printf(c->pout, "%s BAD \"not legal when streaming\"\r\n",
			tag.s);
	    continue;

	masteronly:
	    prot_printf(c->pout,
			"%s BAD \"read-only session\"\r\n",
			tag.s);
	    continue;
	}

	continue;

    nologin:
	prot_printf(c->pout, "%s BAD Please login first\r\n", tag.s);
	eatline(c->pin, ch);
	continue;
    }

 done:
    prot_flush(c->pout);

    /* free struct bufs */
    freebuf(&tag);
    freebuf(&cmd);
    freebuf(&arg1);
    freebuf(&arg2);
    freebuf(&arg3);

    syslog(LOG_DEBUG, "ending cmdloop() on fd %d", c->fd);
}

void *start(void *rock)
{
    struct conn *c = (struct conn *) rock;
    struct sockaddr_in localaddr, remoteaddr;
    int haveaddr = 0;
    int salen;
    int secflags, plaintext_result;
    sasl_security_properties_t *secprops = NULL;
    char localip[60], remoteip[60];
    char clienthost[250];
    struct hostent *hp;

    pthread_mutex_lock(&ready_for_connections_mutex);
    /* are we ready to take connections? */
    while(!ready_for_connections) {
	pthread_cond_wait(&ready_for_connections_cond,
			  &ready_for_connections_mutex);
    }
    pthread_mutex_unlock(&ready_for_connections_mutex);

    c->pin = prot_new(c->fd, 0);
    c->pout = prot_new(c->fd, 1);
    c->clienthost = clienthost;

    prot_setflushonread(c->pin, c->pout);
    prot_settimeout(c->pin, 30*60);

    /* Find out name of client host */
    salen = sizeof(remoteaddr);
    if (getpeername(c->fd, (struct sockaddr *)&remoteaddr, &salen) == 0 &&
	remoteaddr.sin_family == AF_INET) {
	hp = gethostbyaddr((char *)&remoteaddr.sin_addr,
			   sizeof(remoteaddr.sin_addr), AF_INET);
	if (hp != NULL) {
	    strncpy(clienthost, hp->h_name, sizeof(clienthost)-30);
	    clienthost[sizeof(clienthost)-30] = '\0';
	} else {
	    clienthost[0] = '\0';
	}
	strcat(clienthost, "[");
	strcat(clienthost, inet_ntoa(remoteaddr.sin_addr));
	strcat(clienthost, "]");
	salen = sizeof(localaddr);
	if (getsockname(c->fd, (struct sockaddr *)&localaddr, &salen) == 0
	    && iptostring((struct sockaddr *)&remoteaddr,
			  sizeof(struct sockaddr_in), remoteip, 60) == 0
	    && iptostring((struct sockaddr *)&localaddr,
			  sizeof(struct sockaddr_in), localip, 60) == 0) {
	    haveaddr = 1;
	}
    }

    if(haveaddr) {
	c->saslprops.ipremoteport = remoteip;
	c->saslprops.iplocalport = localip;
    }

    /* create sasl connection */
    if (sasl_server_new("mupdate",
			config_servername, NULL,
			(haveaddr ? localip : NULL),
			(haveaddr ? remoteip : NULL),
			NULL, 0, 
			&c->saslconn) != SASL_OK) {
	fatal("SASL failed initializing: sasl_server_new()", EC_TEMPFAIL);
    }

    /* set my allowable security properties */
    secflags = SASL_SEC_NOANONYMOUS;
    plaintext_result = config_getswitch("allowplaintext",1);
    if (!config_getswitch("mupdate_allowplaintext", plaintext_result)) {
	secflags |= SASL_SEC_NOPLAINTEXT;
    }
    secprops = mysasl_secprops(secflags);
    sasl_setprop(c->saslconn, SASL_SEC_PROPS, secprops);

    cmdloop(c);
    
    close(c->fd);
    conn_free(c);

    return NULL;
}

/*
 * run for each accepted connection
 */
int service_main_fd(int fd, int argc, char **argv, char **envp)
{
    /* spawn off a thread to handle this connection */
    pthread_t t;
    struct conn *c = conn_new(fd);
    int r;

    r = pthread_create(&t, NULL, &start, c);
    if (r == 0) {
	pthread_detach(t);
    }

    return 0;
}

/* read from disk database must be unlocked. */
void database_init()
{
    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    mboxlist_init(0);
    mboxlist_open(NULL);

    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */
}

static const char *translate(enum settype t)
{
    switch (t) {
    case SET_ACTIVE: return "ACTIVE";
    case SET_RESERVE: return "RESERVE";
    case SET_DELETE: return "DELETE";
    default: abort();
    }
}

/* log change to database. database must be locked. */
void database_log(const struct mbent *mb)
{
    switch (mb->t) {
    case SET_ACTIVE:
	mboxlist_insertremote(mb->mailbox, 0, mb->server, mb->acl, NULL);
	break;

    case SET_RESERVE:
	mboxlist_insertremote(mb->mailbox, MBTYPE_RESERVE, mb->server,
			      "", NULL);
	break;

    case SET_DELETE:
	mboxlist_deletemailbox(mb->mailbox, 1, "", NULL, 0);
	break;
    }
}

/* lookup in database. database must be locked */
/* This could probabally be more efficient and avoid some copies */
struct mbent *database_lookup(const char *name) 
{
    char *path, *acl;
    int type;
    struct mbent *out;
    
    if(!name) return NULL;
    
    if(mboxlist_detail(name, &type, &path, NULL, &acl, NULL))
	return NULL;

    if(type & MBTYPE_RESERVE) {
	out = xmalloc(sizeof(struct mbent) + 1);
	out->t = SET_RESERVE;
	out->acl[0] = '\0';
    } else {
	out = xmalloc(sizeof(struct mbent) + strlen(acl));
	out->t = SET_ACTIVE;
	strcpy(out->acl, acl);
    }

    strncpy(out->mailbox, name, sizeof(out->mailbox));
    strncpy(out->server, path, sizeof(out->server));

    return out;
}

void cmd_authenticate(struct conn *C,
		      const char *tag, const char *mech,
		      const char *clientstart)
{
    int r;
    char *in = NULL;
    const char *out = NULL;
    unsigned int inlen = 0, outlen = 0;
    
    if(clientstart && clientstart[0]) {
	unsigned len = strlen(clientstart);
	in = xmalloc(len);
	r = sasl_decode64(clientstart, len, in, len, &inlen);
	if(r != SASL_OK) {
	    prot_printf(C->pout, "%s NO \"cannot base64 decode\"\r\n",tag);
	    free(in);
	    return;
	}
    }

    r = sasl_server_start(C->saslconn, mech, in, inlen, &out, &outlen);
    free(in); in=NULL;
    if(r == SASL_NOMECH) {
	prot_printf(C->pout,
		    "%s NO \"unknown authentication mechanism\"\r\n",tag);
	return;
    }

    while(r == SASL_CONTINUE) {
	char buf[4096];
	char inbase64[4096];
	char *p;
	unsigned len;
	
	if(out) {
	    r = sasl_encode64(out, outlen,
			      inbase64, sizeof(inbase64), NULL);
	    if(r != SASL_OK) break;
	    
	    /* send out */
	    prot_printf(C->pout, "%s\r\n", inbase64);
	    prot_flush(C->pout);
	}
	
	/* read a line */
	if(!prot_fgets(buf, sizeof(buf)-1, C->pin))
	    return;

	p = buf + strlen(buf) - 1;
	if(p >= buf && *p == '\n') *p-- = '\0';
	if(p >= buf && *p == '\r') *p-- = '\0';

	if(buf[0] == '*') {
	    prot_printf(C->pout,
			"%s NO \"client canceled authentication\"\r\n",
			tag);
	    reset_saslconn(C);
	    return;
	}

	len = strlen(buf);
	in = xmalloc(len);
	r = sasl_decode64(buf, len, in, len, &inlen);
	if(r != SASL_OK) {
	    prot_printf(C->pout, "%s NO \"cannot base64 decode\"\r\n",tag);
	    free(in);
	    reset_saslconn(C);
	    return;
	}

	r = sasl_server_step(C->saslconn, in, inlen,
			     &out, &outlen);
	free(in); in=NULL;
    }

    if(r != SASL_OK) {
	sleep(3);
	
	syslog(LOG_ERR, "badlogin: %s %s %s",
	       C->clienthost,
	       mech, sasl_errdetail(C->saslconn));

	prot_printf(C->pout, "%s NO \"%s\"\r\n", tag,
		    sasl_errstring((r == SASL_NOUSER ? SASL_BADAUTH : r),
				   NULL, NULL));
	reset_saslconn(C);
	return;
    }

    /* Successful Authentication */
    r = sasl_getprop(C->saslconn, SASL_USERNAME, (const void **)&C->userid);
    if(r != SASL_OK) {
	prot_printf(C->pout, "%s NO \"SASL Error\"\r\n", tag);
	reset_saslconn(C);
	return;
    }

    syslog(LOG_NOTICE, "login: %s from %s",
	   C->userid, C->clienthost);

    prot_printf(C->pout, "%s OK \"Authenticated\"\r\n", tag);

    prot_setsasl(C->pin, C->saslconn);
    prot_setsasl(C->pout, C->saslconn);

    return;
}

void cmd_set(struct conn *C, 
	     const char *tag, const char *mailbox,
	     const char *server, const char *acl, enum settype t)
{
    struct mbent *m;
    struct conn *upc;

    syslog(LOG_DEBUG, "cmd_set(fd:%d, %s)", C->fd, mailbox);

    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    m = database_lookup(mailbox);
    if (m && t == SET_RESERVE) {
	/* failed; mailbox already exists */
	prot_printf(C->pout, "%s NO \"mailbox already exists\"\r\n", tag);
	goto done;
    }
    
    if (t == SET_DELETE) {
	if (!m) {
	    /* failed; mailbox doesn't exist */
            prot_printf(C->pout, "%s NO \"mailbox doesn't exist\"\r\n", tag);
	    goto done;
	}

	/* do the deletion */
	m->t = SET_DELETE;
    } else {
	if (m && (!acl || strlen(acl) < strlen(m->acl))) {
	    /* change what's already there */
	    strcpy(m->server, server);
	    if (acl) strcpy(m->acl, acl);
	    else m->acl[0] = '\0';

	    m->t = t;
	} else {
	    struct mbent *newm;
	    
	    /* allocate new mailbox */
	    if (acl) {
		newm = xrealloc(m, sizeof(struct mbent) + strlen(acl));
	    } else {
		newm = xrealloc(m, sizeof(struct mbent) + 1);
	    }
	    strcpy(newm->mailbox, mailbox);
	    strcpy(newm->server, server);
	    if (acl) {
		strcpy(newm->acl, acl);
	    } else {
		newm->acl[0] = '\0';
	    }

	    newm->t = t;

	    /* re-scope */
	    m = newm;
	}
    }

    /* write to disk */
    database_log(m);

    /* post pending changes */
    for (upc = updatelist; upc != NULL; upc = upc->updatelist_next) {
	/* for each connection, add to pending list */
	struct pending *p = (struct pending *) xmalloc(sizeof(struct pending));
	strcpy(p->mailbox, mailbox);
	p->t = t;
	
	pthread_mutex_lock(&upc->m);
	p->next = upc->plist;
	upc->plist = p;

	pthread_cond_signal(&upc->cond);
	pthread_mutex_unlock(&upc->m);
    }

    prot_printf(C->pout, "%s OK \"done\"\r\n", tag);
 done:
    free(m);
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */
}

void cmd_find(struct conn *C, const char *tag, const char *mailbox, int dook)
{
    struct mbent *m;

    syslog(LOG_DEBUG, "cmd_find(fd:%d, %s)", C->fd, mailbox);

    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */
    m = database_lookup(mailbox);

    if (m && m->t == SET_ACTIVE) {
	prot_printf(C->pout, "%s MAILBOX {%d+}\r\n%s {%d+}\r\n%s {%d+}\r\n%s\r\n",
		    tag,
		    strlen(m->mailbox), m->mailbox,
		    strlen(m->server), m->server,
		    strlen(m->acl), m->acl);
    } else if (m && m->t == SET_RESERVE) {
	prot_printf(C->pout, "%s RESERVE {%d+}\r\n%s {%d+}\r\n%s\r\n",
		    tag,
		    strlen(m->mailbox), m->mailbox,
		    strlen(m->server), m->server);
    } else {
	/* no output: not found */
    }

    free(m);
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */

    if (dook) {
	prot_printf(C->pout, "%s OK \"Search completed\"\r\n", tag);
    }
}

/* Callback for cmd_startupdate to be passed to mboxlist_findall. */
/* Requires that C->streaming be set to the tag to respond with */
static int sendupdate(char *name, int matchlen, int maycreate, void *rock)
{
    struct conn *C = (struct conn *)rock;
    struct mbent *m;
    
    if(!C) return -1;
    
    m = database_lookup(name);
    if(!m) return -1;

    if(!C->list_prefix ||
       !strncmp(m->server, C->list_prefix, C->list_prefix_len)) {
	/* Either there is not a prefix to test, or we matched it */
    
	switch (m->t) {
	case SET_ACTIVE:
	    prot_printf(C->pout,
			"%s MAILBOX {%d+}\r\n%s {%d+}\r\n%s {%d+}\r\n%s\r\n",
			C->streaming,
			strlen(m->mailbox), m->mailbox,
			strlen(m->server), m->server,
			strlen(m->acl), m->acl);
	    break;
	case SET_RESERVE:
	    prot_printf(C->pout, "%s RESERVE {%d+}\r\n%s {%d+}\r\n%s\r\n",
			C->streaming,
			strlen(m->mailbox), m->mailbox,
			strlen(m->server), m->server);
	    break;
	case SET_DELETE:
	    /* deleted item in the list !?! */
	    abort();
	}
    }
    
    free(m);
    return 0;
}

void cmd_list(struct conn *C, const char *tag, const char *host_prefix) 
{
    char pattern[2] = {'*','\0'};

    /* indicate interest in updates */
    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    /* since this isn't valid when streaming, just use the same callback */
    C->streaming = tag;
    C->list_prefix = host_prefix;
    if(C->list_prefix) C->list_prefix_len = strlen(C->list_prefix);
    else C->list_prefix_len = 0;
    
    mboxlist_findall(NULL, pattern, 1, NULL,
		     NULL, sendupdate, (void*)C);

    C->streaming = NULL;

    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */
}


void cmd_startupdate(struct conn *C, const char *tag)
{
    char pattern[2] = {'*','\0'};

    /* initialize my condition variable */
    pthread_cond_init(&C->cond, NULL);

    /* indicate interest in updates */
    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    C->updatelist_next = updatelist;
    updatelist = C;
    C->streaming = xstrdup(tag);

    /* dump initial list */
    mboxlist_findall(NULL, pattern, 1, NULL,
		     NULL, sendupdate, (void*)C);

    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */

    prot_printf(C->pout, "%s OK \"streaming starts\"\r\n", tag);
    prot_flush(C->pout);

    prot_NONBLOCK(C->pin);
}

void sendupdates(struct conn *C)
{
    struct pending *p, *q;
    struct timeval now;
    struct timespec timeout;
    int r;

    pthread_mutex_lock(&C->m);

    gettimeofday(&now, NULL);
    timeout.tv_sec = now.tv_sec + poll_interval;
    timeout.tv_nsec = now.tv_usec * 1000;
	    
    r = 0;
    while (r != ETIMEDOUT) {
	r = pthread_cond_timedwait(&C->cond, &C->m, &timeout);
    }

    /* just grab the update list and release the lock */
    p = C->plist;
    C->plist = NULL;
    pthread_mutex_unlock(&C->m);

    while (p != NULL) {
	/* send update */
	q = p;
	p = p->next;

	if (q->t == SET_DELETE) {
	    prot_printf(C->pout, "%s DELETE {%d+}\r\n%s\r\n",
			C->streaming, strlen(q->mailbox), q->mailbox);
	} else {
	    /* notify just like a FIND */
	    cmd_find(C, C->streaming, q->mailbox, 0);
	}
	free(q);
    }

    prot_flush(C->pout);
}

void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    exit(code);
}

/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(struct conn *c)
{
    int ret, secflags, plaintext_result;
    sasl_security_properties_t *secprops = NULL;

    sasl_dispose(&c->saslconn);
    /* do initialization typical of service_main */
    ret = sasl_server_new("mupdate", config_servername,
                         NULL, NULL, NULL,
                         NULL, 0, &c->saslconn);
    if(ret != SASL_OK) return ret;

    if(c->saslprops.ipremoteport)
       ret = sasl_setprop(c->saslconn, SASL_IPREMOTEPORT,
                          c->saslprops.ipremoteport);
    if(ret != SASL_OK) return ret;
    
    if(c->saslprops.iplocalport)
       ret = sasl_setprop(c->saslconn, SASL_IPLOCALPORT,
                          c->saslprops.iplocalport);
    if(ret != SASL_OK) return ret;
    
    secflags = SASL_SEC_NOANONYMOUS;
    plaintext_result = config_getswitch("allowplaintext",1);
    if (!config_getswitch("mupdate_allowplaintext", plaintext_result)) {
	secflags |= SASL_SEC_NOPLAINTEXT;
    }
    secprops = mysasl_secprops(secflags);
    ret = sasl_setprop(c->saslconn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    return SASL_OK;
}

int cmd_change(struct mupdate_mailboxdata *mdata,
	       const char *rock, void *context)
{
    struct mbent *m = NULL;
    struct conn *upc = NULL;
    enum settype t = -1;
    int ret = 0;

    if(!mdata || !rock || !mdata->mailbox) return 1;

    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    if(!strncmp(rock, "DELETE", 6)) {
	m = database_lookup(mdata->mailbox);

	if(!m) {
	    syslog(LOG_DEBUG, "attempt to delete unknown mailbox %s",
		   mdata->mailbox);
	    /* Mailbox doesn't exist */
	    ret = -1;
	    goto done;
	}
	m->t = t = SET_DELETE;
    } else {
	m = database_lookup(mdata->mailbox);
	
	if (m && (!mdata->acl || strlen(mdata->acl) < strlen(m->acl))) {
	    /* change what's already there */
	    strcpy(m->server, mdata->server);
	    if (mdata->acl) strcpy(m->acl, mdata->acl);
	    else m->acl[0] = '\0';

	    if(!strncmp(rock, "MAILBOX", 6)) {
		m->t = t = SET_ACTIVE;
	    } else if(!strncmp(rock, "RESERVE", 7)) {
		m->t = t = SET_RESERVE;
	    } else {
		syslog(LOG_DEBUG,
		       "bad mupdate command in cmd_change: %s", rock);
		ret = 1;
		goto done;
	    }
	} else {
	    struct mbent *newm;

	    /* allocate new mailbox */
	    if (mdata->acl) {
		newm = xrealloc(m, sizeof(struct mbent) + strlen(mdata->acl));
	    } else {
		newm = xrealloc(m, sizeof(struct mbent) + 1);
	    }
	    strcpy(newm->mailbox, mdata->mailbox);
	    strcpy(newm->server, mdata->server);
	    if (mdata->acl) {
		strcpy(newm->acl, mdata->acl);
	    } else {
		newm->acl[0] = '\0';
	    }

	    if(!strncmp(rock, "MAILBOX", 6)) {
		newm->t = t = SET_ACTIVE;
	    } else if(!strncmp(rock, "RESERVE", 7)) {
		newm->t = t = SET_RESERVE;
	    } else {
		syslog(LOG_DEBUG,
		       "bad mupdate command in cmd_change: %s", rock);
		ret = 1;
		goto done;
	    }
	    
	    /* Bring it back into scope */
	    m = newm;
	
	}
    }

    /* write to disk */
    database_log(m);
    
    /* post pending changes to anyone we are talking to */
    for (upc = updatelist; upc != NULL; upc = upc->updatelist_next) {
	/* for each connection, add to pending list */

	struct pending *p = (struct pending *) xmalloc(sizeof(struct pending));
	strcpy(p->mailbox, mdata->mailbox);
	p->t = t;
	
	pthread_mutex_lock(&upc->m);
	p->next = upc->plist;
	upc->plist = p;

	pthread_cond_signal(&upc->cond);
	pthread_mutex_unlock(&upc->m);
    }

 done:
    free(m);
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */

    return ret;
}

/* Read a series of MAILBOX and RESERVE commands and tack them onto a
 * queue */
int cmd_resync(struct mupdate_mailboxdata *mdata,
	       const char *rock, void *context)
{
    struct mbent_queue *remote_boxes = (struct mbent_queue *)context;
    struct mbent *newm = NULL;

    if(!mdata || !rock || !mdata->mailbox || !remote_boxes) return 1;

    /* allocate new mailbox */
    if (mdata->acl) {
	newm = xmalloc(sizeof(struct mbent) + strlen(mdata->acl));
    } else {
	newm = xmalloc(sizeof(struct mbent) + 1);
    }
    strcpy(newm->mailbox, mdata->mailbox);
    strcpy(newm->server, mdata->server);
    if (mdata->acl) {
	strcpy(newm->acl, mdata->acl);
    } else {
	newm->acl[0] = '\0';
    }
	
    if(!strncmp(rock, "MAILBOX", 6)) {
	newm->t = SET_ACTIVE;
    } else if(!strncmp(rock, "RESERVE", 7)) {
	newm->t = SET_RESERVE;
    } else {
	syslog(LOG_NOTICE,
	       "bad mupdate command in cmd_resync: %s", rock);
	return 1;
    }

    /* Insert onto queue */
    newm->next = NULL;
    *(remote_boxes->tail) = newm;
    remote_boxes->tail = &(newm->next);
    
    return 0;
}

/* Callback for mupdate_synchronize to be passed to mboxlist_findall. */
static int sync_findall_cb(char *name, int matchlen, int maycreate, void *rock)
{
    struct mbent_queue *local_boxes = (struct mbent_queue *)rock;
    struct mbent *m;

    if(!local_boxes) return 1;

    m = database_lookup(name);
    /* If it doesn't exist, fine... */
    if(!m) return 0;
    
    m->next = NULL;
    *(local_boxes->tail) = m;
    local_boxes->tail = &(m->next);

    return 0;
}

int mupdate_synchronize(mupdate_handle *handle) 
{
    struct mbent_queue local_boxes;
    struct mbent_queue remote_boxes;
    struct mbent *l,*r;
    char pattern[] = { '*', '\0' };

    if(!handle || !handle->saslcompleted) return 1;

    /* ask for updates and set nonblocking */
    prot_printf(handle->pout, "U01 UPDATE\r\n");

    /* Note that this prevents other people from running an UPDATE against
     * us for the duration.  this is a GOOD THING */
    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */
    
    syslog(LOG_NOTICE, 
	   "synchronizing mailbox list with master mupdate server");

    local_boxes.head = NULL;
    local_boxes.tail = &(local_boxes.head);
    remote_boxes.head = NULL;
    remote_boxes.tail = &(remote_boxes.head);

    /* If there is a fatal error, die, other errors ignore */
    if(mupdate_scarf(handle, cmd_resync, &remote_boxes, 1) > 0) {
	struct mbent *p=remote_boxes.head, *p_next=NULL;
	while(p) {
	    p_next = p->next;
	    free(p);
	    p = p_next;
	}
	
	pthread_mutex_unlock(&mailboxes_mutex);
	return 1;
    }

    /* Make socket nonblocking now */
    prot_NONBLOCK(handle->pin);

    mboxlist_findall(NULL, pattern, 1, NULL,
		     NULL, sync_findall_cb, (void*)&local_boxes);

    /* Traverse both lists, compare the names */
    /* If they match, ensure that server and acl are correct, if so,
       move on, if not, fix them */
    /* If the local is before the next remote, delete it */
    /* If the next remote is before theis local, insert it and try again */
    for(l = local_boxes.head, r = remote_boxes.head; l && r;
	l = local_boxes.head, r = remote_boxes.head) 
    {
	int ret = strcmp(l->mailbox, r->mailbox);
	if(!ret) {
	    /* Match */
	    if(l->t != r->t ||
	       strcmp(l->server, r->server) ||
	       strcmp(l->acl,r->acl)) {
		/* Something didn't match, replace it */
		mboxlist_insertremote(r->mailbox, 
				     (r->t == SET_RESERVE ?
				        MBTYPE_RESERVE : 0),
				      r->server, r->acl, NULL);
	    }
	    /* Okay, dump these two */
	    local_boxes.head = l->next;
	    remote_boxes.head = r->next;
	    free(l);
	    free(r);
	} else if (ret < 0) {
	    /* Local without corresponding remote, delete it */
	    mboxlist_deletemailbox(l->mailbox, 1, "", NULL, 0);
	    local_boxes.head = l->next;
	    free(l);
	} else /* (ret > 0) */ {
	    /* Remote without corresponding local, insert it */
	    mboxlist_insertremote(r->mailbox, 
				  (r->t == SET_RESERVE ?
				   MBTYPE_RESERVE : 0),
				  r->server, r->acl, NULL);
	    remote_boxes.head = r->next;
	    free(r);
	}
    }

    if(l && !r) {
	/* we have more deletes to do */
	while(l) {
	    mboxlist_deletemailbox(l->mailbox, 1, "", NULL, 0);
	    local_boxes.head = l->next;
	    free(l);
	    l = local_boxes.head;
	}
    } else if (r && !l) {
	/* we have more inserts to do */
	while(r) {
	    mboxlist_insertremote(r->mailbox, 
				  (r->t == SET_RESERVE ?
				   MBTYPE_RESERVE : 0),
				  r->server, r->acl, NULL);
	    remote_boxes.head = r->next;
	    free(r);
	    r = remote_boxes.head;
	}
    }

    /* All up to date! */
    syslog(LOG_NOTICE, "mailbox list synchronization complete");
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */
    return 0;
}

void mupdate_ready(void) 
{
    if(ready_for_connections) {
	syslog(LOG_CRIT, "mupdate_ready called when already ready");
	fatal("mupdate_ready called when already ready", EC_TEMPFAIL);
    }

    pthread_mutex_lock(&ready_for_connections_mutex);
    ready_for_connections = 1;
    pthread_cond_broadcast(&ready_for_connections_cond);
    pthread_mutex_unlock(&ready_for_connections_mutex);
}

void mupdate_unready(void)
{
    pthread_mutex_lock(&ready_for_connections_mutex);

    syslog(LOG_NOTICE, "unready for connections");

    /* close all connections to us */
    while(connlist) conn_free(connlist);
    ready_for_connections = 0;

    pthread_mutex_unlock(&ready_for_connections_mutex);
}
