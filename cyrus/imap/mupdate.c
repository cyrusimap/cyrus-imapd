/* mupdate.c -- cyrus murder database master 
 *
 * $Id: mupdate.c,v 1.60.4.25 2003/02/05 01:31:04 ken3 Exp $
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <stdlib.h>
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
#include "nonblock.h"
#include "prot.h"
#include "imapconf.h"
#include "imap_err.h"
#include "version.h"
#include "mpool.h"

/* Sent to clients that we can't accept a connection for. */
static const char SERVER_UNABLE_STRING[] = "* BYE \"Server Unable\"\r\n";

static const int NO_NEW_CONNECTION = -1;

static int masterp = 0;

typedef enum {
    DOCMD_OK = 0,
    DOCMD_CONN_FINISHED = 1
} mupdate_docmd_result_t;

enum {
    poll_interval = 1,
    update_wait = 5
};

struct pending {
    struct pending *next;

    char mailbox[MAX_MAILBOX_NAME];
};

struct conn {
    int fd;
    struct protstream *pin;
    struct protstream *pout;
    sasl_conn_t *saslconn;
    char *userid;

    int idle;
    
    char clienthost[250];

    struct 
    {
	char *ipremoteport;
	char ipremoteport_buf[60];
	char *iplocalport;
	char iplocalport_buf[60];
    } saslprops;

    /* pending changes to send, in reverse order */
    const char *streaming; /* tag */
    pthread_mutex_t m;
    pthread_cond_t cond;

    struct pending *plist;
    struct conn *updatelist_next;
    struct prot_waitevent *ev; /* invoked every 'update_wait' seconds
				  to send out updates */

    /* Prefix for list commands */
    const char *list_prefix;
    size_t list_prefix_len;

    /* For parsing */
    struct buf tag, cmd, arg1, arg2, arg3;

    /* For connection list management */
    struct conn *next;
    struct conn *next_idle;
};

static int ready_for_connections = 0;
static pthread_cond_t ready_for_connections_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t ready_for_connections_mutex = PTHREAD_MUTEX_INITIALIZER;

static int synced = 0;
static pthread_cond_t synced_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t synced_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t listener_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t listener_cond = PTHREAD_COND_INITIALIZER;
static int listener_lock = 0;

/* if you want to lick both listener and either of these two, you
 * must lock listener first.  You must have both listener_mutex and
 * idle_connlist_mutex locked to remove anything from the idle_connlist */
static pthread_mutex_t idle_connlist_mutex = PTHREAD_MUTEX_INITIALIZER;
struct conn *idle_connlist = NULL; /* protected by listener_mutex */
static pthread_mutex_t connection_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static int connection_count = 0;
static pthread_mutex_t idle_worker_mutex = PTHREAD_MUTEX_INITIALIZER;
static int idle_worker_count = 0;
static pthread_mutex_t worker_count_mutex = PTHREAD_MUTEX_INITIALIZER;
static int worker_count = 0;

pthread_mutex_t connlist_mutex = PTHREAD_MUTEX_INITIALIZER;
struct conn *connlist = NULL;

/* ---- connection signaling pipe */
static int conn_pipe[2];

/* ---- database access ---- */
pthread_mutex_t mailboxes_mutex = PTHREAD_MUTEX_INITIALIZER;
struct conn *updatelist = NULL;

/* --- prototypes --- */
static void conn_free(struct conn *C);
mupdate_docmd_result_t docmd(struct conn *c);
void cmd_authenticate(struct conn *C,
		      const char *tag, const char *mech,
		      const char *clientstart);
void cmd_set(struct conn *C, 
	     const char *tag, const char *mailbox,
	     const char *server, const char *acl, enum settype t);
void cmd_find(struct conn *C, const char *tag, const char *mailbox,
	      int dook, int send_delete);
void cmd_list(struct conn *C, const char *tag, const char *host_prefix);
void cmd_startupdate(struct conn *C, const char *tag);
void shut_down(int code);
static int reset_saslconn(struct conn *c);
void database_init();
void sendupdates(struct conn *C, int flushnow);

extern int saslserver(sasl_conn_t *conn, const char *mech,
		      const char *init_resp, const char *continuation,
		      struct protstream *pin, struct protstream *pout,
		      int *sasl_result,
		      char **success_data);

/* --- prototypes in mupdate-slave.c */
void *mupdate_client_start(void *rock);
void *mupdate_placebo_kick_start(void *rock);

/* --- main() for each thread */
static void *thread_main(void *rock);

/* --- for config.c */
const int config_need_data = 0;

static struct conn *conn_new(int fd)
{
    struct conn *C = xzmalloc(sizeof(struct conn));
    struct sockaddr_in localaddr, remoteaddr;
    int r;    
    int haveaddr = 0;
    int salen;
    int secflags;
    struct hostent *hp;
    
    C->fd = fd;
    
    C->pin = prot_new(C->fd, 0);
    C->pout = prot_new(C->fd, 1);
    
    prot_setflushonread(C->pin, C->pout);
    prot_settimeout(C->pin, 180*60);

    C->pin->userdata = C->pout->userdata = C;

    pthread_mutex_lock(&connlist_mutex); /* LOCK */
    C->next = connlist;
    connlist = C;
    pthread_mutex_unlock(&connlist_mutex); /* UNLOCK */

    pthread_mutex_lock(&connection_count_mutex); /* LOCK */
    connection_count++;
    pthread_mutex_unlock(&connection_count_mutex); /* UNLOCK */

    /* Find out name of client host */
    salen = sizeof(remoteaddr);
    if (getpeername(C->fd, (struct sockaddr *)&remoteaddr, &salen) == 0 &&
	remoteaddr.sin_family == AF_INET) {
	hp = gethostbyaddr((char *)&remoteaddr.sin_addr,
			   sizeof(remoteaddr.sin_addr), AF_INET);
	if (hp != NULL) {
	    strncpy(C->clienthost, hp->h_name, sizeof(C->clienthost)-30);
	    C->clienthost[sizeof(C->clienthost)-30] = '\0';
	} else {
	    C->clienthost[0] = '\0';
	}
	strcat(C->clienthost, "[");
	strcat(C->clienthost, inet_ntoa(remoteaddr.sin_addr));
	strcat(C->clienthost, "]");
	salen = sizeof(localaddr);
	if (getsockname(C->fd, (struct sockaddr *)&localaddr, &salen) == 0
	    && iptostring((struct sockaddr *)&remoteaddr,
			  sizeof(struct sockaddr_in),
			  C->saslprops.ipremoteport_buf,
			  sizeof(C->saslprops.ipremoteport_buf)) == 0
	    && iptostring((struct sockaddr *)&localaddr,
			  sizeof(struct sockaddr_in),
			  C->saslprops.iplocalport_buf,
			  sizeof(C->saslprops.iplocalport_buf)) == 0) {
	    haveaddr = 1;
	}
    }

    if(haveaddr) {
	C->saslprops.ipremoteport = C->saslprops.ipremoteport_buf;
	C->saslprops.iplocalport = C->saslprops.iplocalport_buf;
    }

    /* create sasl connection */
    r = sasl_server_new("mupdate",
			config_servername, NULL,
			C->saslprops.iplocalport,
			C->saslprops.ipremoteport,
			NULL, 0, 
			&C->saslconn);
    if(r != SASL_OK) {
	syslog(LOG_ERR, "failed to start sasl for connection: %s",
	       sasl_errstring(r, NULL, NULL));	
	prot_printf(C->pout, SERVER_UNABLE_STRING);

	C->idle = 0;
	conn_free(C);
	return NULL;
    }

    /* set my allowable security properties */
    secflags = SASL_SEC_NOANONYMOUS;
    if (!config_getswitch(IMAPOPT_ALLOWPLAINTEXT)) {
	secflags |= SASL_SEC_NOPLAINTEXT;
    }
    sasl_setprop(C->saslconn, SASL_SEC_PROPS, mysasl_secprops(secflags));

    /* Clear Buffers */
    memset(&(C->tag), 0, sizeof(struct buf));
    memset(&(C->cmd), 0, sizeof(struct buf));
    memset(&(C->arg1), 0, sizeof(struct buf));
    memset(&(C->arg2), 0, sizeof(struct buf));
    memset(&(C->arg3), 0, sizeof(struct buf));

    return C;
}

static void conn_free(struct conn *C)
{
    assert(!C->idle); /* Not allowed to free idle connections */
    
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

    /* decrease connection counter */
    pthread_mutex_lock(&connection_count_mutex);
    connection_count--;
    pthread_mutex_unlock(&connection_count_mutex); 

    /* remove from connlist */
    pthread_mutex_lock(&connlist_mutex); /* LOCK */
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

    if (C->ev) prot_removewaitevent(C->pin, C->ev);

    prot_flush(C->pout);

    if (C->pin) prot_free(C->pin);
    if (C->pout) prot_free(C->pout);
    cyrus_close_sock(C->fd);
    if (C->saslconn) sasl_dispose(&C->saslconn);

    /* free struct bufs */
    freebuf(&(C->tag));
    freebuf(&(C->cmd));
    freebuf(&(C->arg1));
    freebuf(&(C->arg2));
    freebuf(&(C->arg3));

    free(C);
}

static struct sasl_callback mysasl_cb[] = {
    { SASL_CB_GETOPT, &mysasl_config, NULL },
    { SASL_CB_PROXY_POLICY, &mysasl_proxy_policy, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc, char **argv,
		 char **envp __attribute__((unused)))
{
    int i, r, workers_to_start;
    int opt;
    pthread_t t;

    if (geteuid() == 0) fatal("must run as the Cyrus user", EC_USAGE);

    /* Do minor configuration checking */
    workers_to_start = config_getint(IMAPOPT_MUPDATE_WORKERS_START);

    if(config_getint(IMAPOPT_MUPDATE_WORKERS_MAX) < config_getint(IMAPOPT_MUPDATE_WORKERS_MINSPARE)) {
	syslog(LOG_CRIT, "Maximum total worker threads is less than minimum spare worker threads");
	return EC_SOFTWARE;
    }

    if(workers_to_start < config_getint(IMAPOPT_MUPDATE_WORKERS_MINSPARE)) {
	syslog(LOG_CRIT, "Starting worker threads is less than minimum spare worker threads");
	return EC_SOFTWARE;
    }

    if(config_getint(IMAPOPT_MUPDATE_WORKERS_MAXSPARE) < workers_to_start) {
	syslog(LOG_CRIT, "Maximum spare worker threads is less than starting worker threads");
	return EC_SOFTWARE;
    }

    if(config_getint(IMAPOPT_MUPDATE_WORKERS_MINSPARE) > workers_to_start) {
	syslog(LOG_CRIT, "Minimum spare worker threads is greater than starting worker threads");
	return EC_SOFTWARE;
    }

    if(config_getint(IMAPOPT_MUPDATE_WORKERS_MAX) < workers_to_start) {
	syslog(LOG_CRIT, "Maximum total worker threads is less than starting worker threads");
	return EC_SOFTWARE;
    }

    /* set signal handlers */
    signals_set_shutdown(&shut_down);
    signals_add_handlers();
    signal(SIGPIPE, SIG_IGN);

    config_sasl_init(1, 1, mysasl_cb);

    /* see if we're the master or a slave */
    while ((opt = getopt(argc, argv, "m")) != EOF) {
	switch (opt) {
	case 'm':
	    masterp = 1;
	    break;
	default:
	    break;
	}
    }

    if(pipe(conn_pipe) == -1) {
	syslog(LOG_ERR, "could not setup connection signaling pipe %m");
	return EC_OSERR;
    }

    database_init();

    if (!masterp) {
	r = pthread_create(&t, NULL, &mupdate_client_start, NULL);
	if(r == 0) {
	    pthread_detach(t);
	} else {
	    syslog(LOG_ERR, "could not start client thread");
	    return EC_SOFTWARE;
	}

	/* Wait until they sync the database */
	pthread_mutex_lock(&synced_mutex);
	if(!synced)
	    pthread_cond_wait(&synced_cond, &synced_mutex);
	pthread_mutex_unlock(&synced_mutex);
    } else {
	pthread_t t;
	
	r = pthread_create(&t, NULL, &mupdate_placebo_kick_start, NULL);
	if(r == 0) {
	    pthread_detach(t);
	} else {
	    syslog(LOG_ERR, "could not start placebo kick thread");
	    return EC_SOFTWARE;
	}

	mupdate_ready();
    }

    /* Now create the worker thread pool */
    for(i=0; i < workers_to_start; i++) {
	r = pthread_create(&t, NULL, &thread_main, NULL);  
        if(r == 0) {
            pthread_detach(t);
        } else {
            syslog(LOG_ERR, "could not start client thread");
            return EC_SOFTWARE;
        }
    }

    return 0;
}

/* called if 'service_init()' was called but not 'service_main()' */
void service_abort(int error)
{
    shut_down(error);
}

void fatal(const char *s, int code)
{
    static int recurse_code = 0;

    if(recurse_code) exit(code);
    else recurse_code = code;
    
    syslog(LOG_ERR, "%s", s);
    shut_down(code);

    /* NOTREACHED */
    exit(code); /* shut up GCC */
}

#define CHECKNEWLINE(c, ch) do { if ((ch) == '\r') (ch)=prot_getc((c)->pin); \
                       		 if ((ch) != '\n') goto extraargs; } while (0)

mupdate_docmd_result_t docmd(struct conn *c)
{
    mupdate_docmd_result_t ret = DOCMD_OK;
    int ch;
    int was_blocking = prot_IS_BLOCKING(c->pin);
    char *p;

 nextcmd:
    /* First we do a check for input */
    prot_NONBLOCK(c->pin);
    ch = prot_getc(c->pin);
        
    if (ch == EOF && errno == EAGAIN) {
	/* no input from client */
	goto done;
    } else if (ch == EOF) {
	goto lost_conn;
    } else {
	/* there's input waiting, put back our character */
	prot_ungetc(ch, c->pin);
    }

    /* Set it back to blocking so we don't get half a word */
    prot_BLOCK(c->pin);

    ch = getword(c->pin, &(c->tag));
    if (ch == EOF) goto lost_conn;
    
    /* send out any updates we have pending */
    if (c->streaming) {
	sendupdates(c, 0); /* don't flush pout though */
    }
    
    if (ch != ' ') {
	prot_printf(c->pout, "* BAD \"Need command\"\r\n");
	eatline(c->pin, ch);
	goto nextcmd;
    }
    
    /* parse command name */
    ch = getword(c->pin, &(c->cmd));
    if(ch == EOF) {
	goto lost_conn;
    } else if (!c->cmd.s[0]) {
	prot_printf(c->pout, "%s BAD \"Null command\"\r\n", c->tag.s);
	eatline(c->pin, ch);
	goto nextcmd;
    }
    
    if (islower((unsigned char) c->cmd.s[0])) {
	c->cmd.s[0] = toupper((unsigned char) c->cmd.s[0]);
    }
    for (p = &(c->cmd.s[1]); *p; p++) {
	if (isupper((unsigned char) *p)) *p = tolower((unsigned char) *p);
    }
    
    switch (c->cmd.s[0]) {
    case 'A':
	if (!strcmp(c->cmd.s, "Authenticate")) {
	    int opt = 0;
	    
	    if (ch != ' ') goto missingargs;
	    ch = getstring(c->pin, c->pout, &(c->arg1));
	    if (ch == ' ') {
		ch = getstring(c->pin, c->pout, &(c->arg2));
		opt = 1;
	    }
	    CHECKNEWLINE(c, ch);
	    
	    if (c->userid) {
		prot_printf(c->pout,
			    "%s BAD \"already authenticated\"\r\n",
			    c->tag.s);
		goto nextcmd;
	    }
	    
	    cmd_authenticate(c, c->tag.s, c->arg1.s,
			     opt ? c->arg2.s : NULL);
	}
	else if (!c->userid) goto nologin;
	else if (!strcmp(c->cmd.s, "Activate")) {
	    if (ch != ' ') goto missingargs;
	    ch = getstring(c->pin, c->pout, &(c->arg1));
	    if (ch != ' ') goto missingargs;
	    ch = getstring(c->pin, c->pout, &(c->arg2));
	    if (ch != ' ') goto missingargs;
	    ch = getstring(c->pin, c->pout, &(c->arg3));
	    CHECKNEWLINE(c, ch);
	    
	    if (c->streaming) goto notwhenstreaming;
	    if (!masterp) goto masteronly;
	    
	    cmd_set(c, c->tag.s, c->arg1.s, c->arg2.s,
		    c->arg3.s, SET_ACTIVE);
	}
	else goto badcmd;
	break;
	
    case 'D':
	if (!c->userid) goto nologin;
	else if (!strcmp(c->cmd.s, "Deactivate")) {
	    if (ch != ' ') goto missingargs;
	    ch = getstring(c->pin, c->pout, &(c->arg1));
	    if (ch != ' ') goto missingargs;
	    ch = getstring(c->pin, c->pout, &(c->arg2));
	    CHECKNEWLINE(c, ch);
	    
	    if (c->streaming) goto notwhenstreaming;
	    if (!masterp) goto masteronly;
	    
	    cmd_set(c, c->tag.s, c->arg1.s, c->arg2.s,
		    NULL, SET_DEACTIVATE);
	}
	else if (!strcmp(c->cmd.s, "Delete")) {
	    if (ch != ' ') goto missingargs;
	    ch = getstring(c->pin, c->pout, &(c->arg1));
	    CHECKNEWLINE(c, ch);
	    
	    if (c->streaming) goto notwhenstreaming;
	    if (!masterp) goto masteronly;
	    
	    cmd_set(c, c->tag.s, c->arg1.s, NULL, NULL, SET_DELETE);
	}
	else goto badcmd;
	break;
	
    case 'F':
	if (!c->userid) goto nologin;
	else if (!strcmp(c->cmd.s, "Find")) {
	    if (ch != ' ') goto missingargs;
	    ch = getstring(c->pin, c->pout, &(c->arg1));
	    CHECKNEWLINE(c, ch);
	    
	    if (c->streaming) goto notwhenstreaming;
	    
	    cmd_find(c, c->tag.s, c->arg1.s, 1, 0);
	}
	else goto badcmd;
	break;
	
    case 'L':
	if (!strcmp(c->cmd.s, "Logout")) {
	    CHECKNEWLINE(c, ch);
	    
	    prot_printf(c->pout, "%s OK \"bye-bye\"\r\n", c->tag.s);
	    ret = DOCMD_CONN_FINISHED;
	    goto done;
	}
	else if (!c->userid) goto nologin;
	else if (!strcmp(c->cmd.s, "List")) {
	    int opt = 0;
	    
	    if (ch == ' ') {
		/* Optional partition/host prefix parameter */
		ch = getstring(c->pin, c->pout, &(c->arg1));
		opt = 1;
	    }
	    CHECKNEWLINE(c, ch);
	    
	    if (c->streaming) goto notwhenstreaming;
	    
	    cmd_list(c, c->tag.s, opt ? c->arg1.s : NULL);
	    
	    prot_printf(c->pout, "%s OK \"list complete\"\r\n", c->tag.s);
	}
	else goto badcmd;
	break;
	
    case 'N':
	if (!c->userid) goto nologin;
	else if (!strcmp(c->cmd.s, "Noop")) {
	    CHECKNEWLINE(c, ch);
	    
	    prot_printf(c->pout, "%s OK \"Noop done\"\r\n", c->tag.s);
	}
	else goto badcmd;
	break;
	
    case 'R':
	if (!c->userid) goto nologin;
	else if (!strcmp(c->cmd.s, "Reserve")) {
	    if (ch != ' ') goto missingargs;
	    ch = getstring(c->pin, c->pout, &(c->arg1));
	    if (ch != ' ') goto missingargs;
	    ch = getstring(c->pin, c->pout, &(c->arg2));
	    CHECKNEWLINE(c, ch);
	    
	    if (c->streaming) goto notwhenstreaming;
	    if (!masterp) goto masteronly;
	    
	    cmd_set(c, c->tag.s, c->arg1.s, c->arg2.s, NULL, SET_RESERVE);
	}
	else goto badcmd;
	break;
	
    case 'U':
	if (!c->userid) goto nologin;
	else if (!strcmp(c->cmd.s, "Update")) {
	    CHECKNEWLINE(c, ch);
	    if (c->streaming) goto notwhenstreaming;
	    
	    cmd_startupdate(c, c->tag.s);
	}
	else goto badcmd;
	break;
	
    default:
    badcmd:
	prot_printf(c->pout, "%s BAD \"Unrecognized command\"\r\n",
		    c->tag.s);
	eatline(c->pin, ch);
	break;
	
    extraargs:
	prot_printf(c->pout, "%s BAD \"Extra arguments\"\r\n",
		    c->tag.s);
	eatline(c->pin, ch);
	break;
	
    missingargs:
	prot_printf(c->pout, "%s BAD \"Missing arguments\"\r\n",
		    c->tag.s);
	eatline(c->pin, ch);
	break;
	
    notwhenstreaming:
	prot_printf(c->pout, "%s BAD \"not legal when streaming\"\r\n",
		    c->tag.s);
	break;
	
    masteronly:
	prot_printf(c->pout,
		    "%s BAD \"read-only session\"\r\n",
		    c->tag.s);
	break;

    nologin:
	prot_printf(c->pout, "%s BAD Please login first\r\n", c->tag.s);
	eatline(c->pin, ch);
	break;
    }

    /* Check for more input */
    goto nextcmd;

 lost_conn:
    {
	const char *err;
	
	if ((err = prot_error(c->pin)) != NULL) {
	    syslog(LOG_WARNING, "%s, closing connection", err);
	    prot_printf(c->pout, "* BYE \"%s\"\r\n", err);
	}
	
	ret = DOCMD_CONN_FINISHED;
    }
    
 done:
    /* Restore the state of the input stream */
    if(was_blocking)
	prot_BLOCK(c->pin);
    else
	prot_NONBLOCK(c->pin);    

    /* Necessary since we don't ever do a prot_read on an idle connection
     * in mupdate */
    prot_flush(c->pout);
    
    return ret;
}

/*
 * run for each accepted connection
 */
int service_main_fd(int fd,
		    int argc __attribute__((unused)),
		    char **argv __attribute__((unused)),
		    char **envp __attribute__((unused)))
{
    int flag;

    /* First check that we can handle the new connection. */
    pthread_mutex_lock(&connection_count_mutex); /* LOCK */
    flag =
	(connection_count >= config_getint(IMAPOPT_MUPDATE_CONNECTIONS_MAX));
    pthread_mutex_unlock(&connection_count_mutex); /* UNLOCK */

    if (flag) {
	/* Do the nonblocking write, if it fails, too bad for them. */
	nonblock(fd, 1);
	write(fd,SERVER_UNABLE_STRING,sizeof(SERVER_UNABLE_STRING));
	close(fd);

	syslog(LOG_ERR,
	       "Server too busy, droping connection.");
    } else if(write(conn_pipe[1], &fd, sizeof(fd)) == -1) {
	/* signal that a new file descriptor is available.
	 * If it fails... */

	syslog(LOG_CRIT,
	       "write to conn_pipe to signal new connection failed: %m");
	return EC_TEMPFAIL;
    }
    return 0;
}

/*
 * The main thread loop
 */
/* Note that You Must Lock Listen mutex before idle worker mutex,
 * though you can lock them individually too */
static void *thread_main(void *rock __attribute__((unused))) 
{
    struct conn *C; /* used for loops */
    struct conn *currConn = NULL; /* the connection we care about currently */
    struct protgroup *protin = protgroup_new(PROTGROUP_SIZE_DEFAULT);
    struct protgroup *protout = NULL;
    struct timeval now;
    struct timespec timeout;
    int need_workers, too_many;
    int max_worker_flag;
    int do_a_command;
    int send_a_banner;    
    int connflag;
    int new_fd;
    int ret = 0;

    /* Lock Worker Count Mutex */
    pthread_mutex_lock(&worker_count_mutex); /* LOCK */
    /* Change total number of workers */
    worker_count++;
    syslog(LOG_DEBUG,
	   "New worker thread started, for a total of %d", worker_count);
    /* Unlock Worker Count Mutex */
    pthread_mutex_unlock(&worker_count_mutex); /* UNLOCK */
    
    /* This is a big infinite loop */
    while(1) {
	send_a_banner = do_a_command = 0;
	
	pthread_mutex_lock(&idle_worker_mutex);
	/* If we are over the limit on idle threads, die. */
	max_worker_flag = (idle_worker_count >=
			   config_getint(IMAPOPT_MUPDATE_WORKERS_MAXSPARE));
	/* Increment Idle Workers */
	if(!max_worker_flag) idle_worker_count++;
	pthread_mutex_unlock(&idle_worker_mutex);

	if(max_worker_flag) {
	    pthread_mutex_unlock(&idle_worker_mutex);
	    goto worker_thread_done;
	}

    retry_lock:

	/* Lock Listen Mutex - If locking takes more than 60 seconds,
	 * kill off this thread.  Ideally this is a FILO queue */
	pthread_mutex_lock(&listener_mutex); /* LOCK */
	ret = 0;
	while(listener_lock && ret != ETIMEDOUT) {
	    gettimeofday(&now, NULL);
	    timeout.tv_sec = now.tv_sec + 60;
	    timeout.tv_nsec = now.tv_usec * 1000;
	    ret = pthread_cond_timedwait(&listener_cond,
					 &listener_mutex,
					 &timeout);
	}
	if(!ret) {
	    /* Set listener lock until we decide what to do */
	    listener_lock = 1;
	}
	pthread_mutex_unlock(&listener_mutex); /* UNLOCK */

	if(ret == ETIMEDOUT) {
	    if(idle_worker_count <= config_getint(IMAPOPT_MUPDATE_WORKERS_MINSPARE)) {
		/* below number of spare workers, try to get the lock again */
		goto retry_lock;
	    } else {
		/* Decrement Idle Worker Count */
		pthread_mutex_lock(&idle_worker_mutex); /* LOCK */
		idle_worker_count--;
		pthread_mutex_unlock(&idle_worker_mutex); /* UNLOCK */
		
		syslog(LOG_DEBUG,
		       "Thread timed out waiting for listener_lock");
		goto worker_thread_done;
	    }
	}

	signals_poll();

	/* Check if we are ready for connections, if not, wait */
	pthread_mutex_lock(&ready_for_connections_mutex); /* LOCK */
	/* are we ready to take connections? */
	while(!ready_for_connections) {
	    pthread_cond_wait(&ready_for_connections_cond,
			      &ready_for_connections_mutex);
	}
	pthread_mutex_unlock(&ready_for_connections_mutex); /* UNLOCK */

	connflag = 0;

	/* Reset protin to all zeros (to preserve memory allocation) */
	protgroup_reset(protin);

	/* Clear protout if needed */
	protgroup_free(protout);
	protout = NULL;
	
	/* Build list of idle protstreams */
	pthread_mutex_lock(&idle_connlist_mutex); /* LOCK */
	for(C=idle_connlist; C; C=C->next_idle) {
	    assert(C->idle);

	    protgroup_insert(protin, C->pin);
	}
	pthread_mutex_unlock(&idle_connlist_mutex); /* UNLOCK */
	
	/* Select on Idle Conns + conn_pipe */
	if(prot_select(protin, conn_pipe[0],
		       &protout, &connflag, NULL) == -1) {
	    syslog(LOG_ERR, "prot_select() failed in thread_main: %m");
	    fatal("prot_select() failed in thread_main", EC_TEMPFAIL);
	}

	/* Decrement Idle Worker Count */
	pthread_mutex_lock(&worker_count_mutex); /* LOCK */
	pthread_mutex_lock(&idle_worker_mutex); /* LOCK */
	idle_worker_count--;

	need_workers = config_getint(IMAPOPT_MUPDATE_WORKERS_MINSPARE)
	                - idle_worker_count;

	if(need_workers > 0) {
	    too_many = (need_workers + worker_count) - 
		config_getint(IMAPOPT_MUPDATE_WORKERS_MAX);
	    need_workers -= too_many;
	}
	
	/* Do we need a new worker (or two, or three...)?
	 * (are we allowed to create one?) */
	while(need_workers > 0) {
	    pthread_t t;
	    int r = pthread_create(&t, NULL, &thread_main, NULL);
	    if(r == 0) {
		pthread_detach(t);
	    } else {
		syslog(LOG_ERR,
		       "could not start a new worker thread (not fatal)");
	    }
	    /* Even if we fail to create the new thread, keep going */
	    need_workers--;
	}
	pthread_mutex_unlock(&idle_worker_mutex); /* UNLOCK */
	pthread_mutex_unlock(&worker_count_mutex); /* UNLOCK */
	 
	/* If we've been signaled to be unready, drop all current connections
	 * in the idle list */
	if(!ready_for_connections) {
	    /* Free all connections on idle_connlist.  Note that
	     * any connection not currently on the idle_connlist will
	     * instead be freed when they drop out of their docmd() below */
	    pthread_mutex_lock(&idle_connlist_mutex); /* LOCK */
	    for(C=idle_connlist; C; C=C->next_idle) {
		prot_printf(C->pout,
			    "* BYE \"no longer ready for connections\"\r\n");

		C->idle = 0;
		conn_free(C);
	    }
	    idle_connlist = NULL;
	    pthread_mutex_unlock(&idle_connlist_mutex); /* UNLOCK */

	    goto nextlistener;
	}
	
	if(connflag) {
	    /* read the fd from the pipe, if needed */
	    if(read(conn_pipe[0], &new_fd, sizeof(new_fd)) == -1) {
		syslog(LOG_CRIT,
		       "read from conn_pipe for new connection failed: %m");
		fatal("conn_pipe read failed", EC_TEMPFAIL);
	    }
	} else {
	    new_fd = NO_NEW_CONNECTION;
	}
	
	if(new_fd != NO_NEW_CONNECTION) {
	    /* new_fd indicates a new connection */
	    currConn = conn_new(new_fd);
	    if(currConn)
		send_a_banner = 1;
	} else if(protout) {
	    /* Handle existing connection, we'll need to pull it off
	     * the idle_connlist */
	    struct protstream *ptmp;
	    struct conn **prev;

	    pthread_mutex_lock(&idle_connlist_mutex); /* LOCK */
	    prev = &(idle_connlist);

	    /* Grab the first connection out of the ready set, and use it */
	    ptmp = protgroup_getelement(protout, 0);
	    assert(ptmp);
	    currConn = ptmp->userdata;
	    assert(currConn);

	    currConn->idle = 0;
	    for(C=idle_connlist; C; prev = &(C->next_idle), C=C->next_idle) {
		if(C == currConn) {
		    *prev = C->next_idle;
		    C->next_idle = NULL;
		    break;
		}
	    }
	    pthread_mutex_unlock(&idle_connlist_mutex); /* UNLOCK */

	    do_a_command = 1;	    
	}

    nextlistener:
	/* Let another listener in */
	pthread_mutex_lock(&listener_mutex);
	assert(listener_lock);
	listener_lock = 0;
	pthread_cond_signal(&listener_cond);
	pthread_mutex_unlock(&listener_mutex);

	/* Do work in this thread, if needed */
	if(send_a_banner) {
	    char slavebuf[4096];
	    const char *mechs;
	    unsigned int mechcount;

	    /* send initial the banner + flush pout */
	    ret = sasl_listmech(currConn->saslconn, NULL,
				"* AUTH \"", "\" \"", "\"",
				&mechs, NULL, &mechcount);

	    /* Add mupdate:// tag if necessary */
	    if(!masterp) {
		if(!config_mupdate_server)
		    fatal("mupdate server was not specified for slave",
			  EC_TEMPFAIL);
		
		snprintf(slavebuf, sizeof(slavebuf), "mupdate://%s",
			 config_mupdate_server);
	    }
	    
	    prot_printf(currConn->pout,
			"%s\r\n* OK MUPDATE \"%s\" \"Cyrus Murder\" \"%s\" \"%s\"\r\n",
			(ret == SASL_OK && mechcount > 0) ? mechs : "* AUTH",
			config_servername,
			CYRUS_VERSION, masterp ? "(master)" : slavebuf);

	    prot_flush(currConn->pout);
	} else if(do_a_command) {
	    assert(currConn);
	    
	    if(docmd(currConn) == DOCMD_CONN_FINISHED) {
		conn_free(currConn);
		/* continue to top of loop here since we won't be adding
		 * this back to the idle list */
		continue;
	    }

	    /* Are we allowed to continue serving data? */
	    if(!ready_for_connections) {
		prot_printf(C->pout,
			    "* BYE \"no longer ready for connections\"\r\n");
		conn_free(currConn);
		/* continue to top of loop here since we won't be adding
		 * this back to the idle list */
		continue;
	    }
	} /* done handling command */

	if(send_a_banner || do_a_command) {
	    /* We did work in this thread, so we need to [re-]add the
	     * connection to the idle list and signal the current listner */

	    pthread_mutex_lock(&idle_connlist_mutex); /* LOCK */
	    currConn->idle = 1;
	    currConn->next_idle = idle_connlist;
	    idle_connlist = currConn;
	    pthread_mutex_unlock(&idle_connlist_mutex); /* UNLOCK */

	    /* Signal to our caller that we should add something
	     * to select() on, since this connection is ready again */
	    if(write(conn_pipe[1], &NO_NEW_CONNECTION,
		     sizeof(NO_NEW_CONNECTION)) == -1) {
		fatal("write to conn_pipe to signal docmd done failed",
		      EC_TEMPFAIL);
	    }
	}
	
    } /* while(1) */

 worker_thread_done:
    /* Remove this worker from the pool */
    /* Note that workers exiting the loop above should NOT be counted
     * in the idle_worker_count */
    pthread_mutex_lock(&worker_count_mutex); /* LOCK */
    worker_count--;
    syslog(LOG_DEBUG,
	   "Worker thread finished, for a total of %d (%d spare)",
	   worker_count, idle_worker_count);
    pthread_mutex_unlock(&worker_count_mutex); /* UNLOCK */

    protgroup_free(protin);
    protgroup_free(protout);

    return NULL;
}

/* read from disk database must be unlocked. */
void database_init()
{
    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    mboxlist_init(0);
    mboxlist_open(NULL);

    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */
}

/* log change to database. database must be locked. */
void database_log(const struct mbent *mb, struct txn **mytid)
{
    switch (mb->t) {
    case SET_ACTIVE:
	mboxlist_insertremote(mb->mailbox, 0, mb->server, mb->acl, mytid);
	break;

    case SET_RESERVE:
	mboxlist_insertremote(mb->mailbox, MBTYPE_RESERVE, mb->server,
			      "", mytid);
	break;

    case SET_DELETE:
	mboxlist_deleteremote(mb->mailbox, mytid);
	break;

    case SET_DEACTIVATE:
	/* SET_DEACTIVATE is not a real value that an actual
	   mailbox can have! */
	abort();
    }
}

/* lookup in database. database must be locked */
/* This could probabally be more efficient and avoid some copies */
/* passing in a NULL pool implies that we should use regular xmalloc,
 * a non-null pool implies we should use the mpool functionality */
struct mbent *database_lookup(const char *name, struct mpool *pool) 
{
    char *path, *acl;
    int type;
    struct mbent *out;
    
    if(!name) return NULL;
    
    if(mboxlist_detail(name, &type, &path, NULL, &acl, NULL))
	return NULL;

    if(type & MBTYPE_RESERVE) {
	if(!pool) out = xmalloc(sizeof(struct mbent) + 1);
	else out = mpool_malloc(pool, sizeof(struct mbent) + 1);
	out->t = SET_RESERVE;
	out->acl[0] = '\0';
    } else {
	if(!pool) out = xmalloc(sizeof(struct mbent) + strlen(acl));
	else out = mpool_malloc(pool, sizeof(struct mbent) + strlen(acl));
	out->t = SET_ACTIVE;
	strcpy(out->acl, acl);
    }

    out->mailbox = (pool) ? mpool_strdup(pool, name) : xstrdup(name);
    out->server = (pool) ? mpool_strdup(pool, path) : xstrdup(path);

    return out;
}

void cmd_authenticate(struct conn *C,
		      const char *tag, const char *mech,
		      const char *clientstart)
{
    int r, sasl_result;

    r = saslserver(C->saslconn, mech, clientstart, "", C->pin, C->pout,
		   &sasl_result, NULL);

    if (r) {
	const char *errorstring = NULL;

	switch (r) {
	case IMAP_SASL_CANCEL:
	    prot_printf(C->pout,
			"%s NO Client canceled authentication\r\n", tag);
	    break;
	case IMAP_SASL_PROTERR:
	    errorstring = prot_error(C->pin);

	    prot_printf(C->pout,
			"%s NO Error reading client response: %s\r\n",
			tag, errorstring ? errorstring : "");
	    break;
	default:
	    sleep(3);
	
	    syslog(LOG_ERR, "badlogin: %s %s %s",
		   C->clienthost,
		   mech, sasl_errdetail(C->saslconn));

	    prot_printf(C->pout, "%s NO \"%s\"\r\n", tag,
			sasl_errstring((r == SASL_NOUSER ? SASL_BADAUTH : r),
				       NULL, NULL));
	}

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

    /* Hold any output that we need to do */
    enum {
	EXISTS, NOTACTIVE, DOESNTEXIST, ISOK, NOOUTPUT
    } msg = NOOUTPUT;
    
    syslog(LOG_DEBUG, "cmd_set(fd:%d, %s)", C->fd, mailbox);

    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    m = database_lookup(mailbox, NULL);
    if (m && t == SET_RESERVE) {
	/* failed; mailbox already exists */
	msg = EXISTS;
	goto done;
    }

    if ((!m || m->t != SET_ACTIVE) && t == SET_DEACTIVATE) {
	/* failed; mailbox not currently active */
	msg = NOTACTIVE;
	goto done;
    } else if (t == SET_DEACTIVATE) {
	t = SET_RESERVE;
    }
    
    if (t == SET_DELETE) {
	if (!m) {
	    /* failed; mailbox doesn't exist */
	    msg = DOESNTEXIST;
	    goto done;
	}

	/* do the deletion */
	m->t = SET_DELETE;
    } else {
	if (m && (!acl || strlen(acl) < strlen(m->acl))) {
	    /* change what's already there */
	    free(m->server);
	    m->server = xstrdup(server);
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
	    newm->mailbox = xstrdup(mailbox);
	    newm->server = xstrdup(server);
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
    database_log(m, NULL);

    /* post pending changes */
    for (upc = updatelist; upc != NULL; upc = upc->updatelist_next) {
	/* for each connection, add to pending list */
	struct pending *p = (struct pending *) xmalloc(sizeof(struct pending));
	strcpy(p->mailbox, mailbox);
	
	pthread_mutex_lock(&upc->m);
	p->next = upc->plist;
	upc->plist = p;

	pthread_cond_signal(&upc->cond);
	pthread_mutex_unlock(&upc->m);
    }

    msg = ISOK;
 done:
    free_mbent(m);
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */

    /* Delay output until here to avoid blocking while holding
     * mailboxes_mutex */
    switch(msg) {
    case EXISTS:
	prot_printf(C->pout, "%s NO \"mailbox already exists\"\r\n", tag);
	break;
    case NOTACTIVE:
	prot_printf(C->pout, "%s NO \"mailbox not currently active\"\r\n",
		    tag);
	break;
    case DOESNTEXIST:
	prot_printf(C->pout, "%s NO \"mailbox doesn't exist\"\r\n", tag);
	break;
    case ISOK:
	prot_printf(C->pout, "%s OK \"done\"\r\n", tag);
	break;
    default:
	break;
    }    
}

void cmd_find(struct conn *C, const char *tag, const char *mailbox, int dook,
              int send_delete)
{
    struct mbent *m;

    syslog(LOG_DEBUG, "cmd_find(fd:%d, %s)", C->fd, mailbox);

    /* Only hold the mutex around database_lookup,
     * since the mbent stays valid even if the database changes,
     * and we don't want to block on network I/O */
    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */
    m = database_lookup(mailbox, NULL);
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */

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
    } else if (send_delete) {
	/* not found, if needed, send a delete */
	prot_printf(C->pout, "%s DELETE {%d+}\r\n%s\r\n",
		    tag, strlen(mailbox), mailbox);
    }

    free_mbent(m);

    if (dook) {
	prot_printf(C->pout, "%s OK \"Search completed\"\r\n", tag);
    }
}

/* Callback for cmd_startupdate to be passed to mboxlist_findall. */
/* Requires that C->streaming be set to the tag to respond with */
static int sendupdate(char *name,
		      int matchlen __attribute__((unused)),
		      int maycreate __attribute__((unused)),
		      void *rock)
{
    struct conn *C = (struct conn *)rock;
    struct mbent *m;
    
    if(!C) return -1;
    
    m = database_lookup(name, NULL);
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
	case SET_DEACTIVATE:
	    /* SET_DEACTIVATE is not a real value! */
	    abort();
	}
    }
    
    free_mbent(m);
    return 0;
}

void cmd_list(struct conn *C, const char *tag, const char *host_prefix) 
{
    char pattern[2] = {'*','\0'};

    /* List operations can result in a lot of output, let's do this
     * with the prot layer nonblocking so we don't hold the mutex forever*/
    prot_NONBLOCK(C->pout);

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

    prot_BLOCK(C->pout);
    prot_flush(C->pout);
}


/* 
 * we've registered this connection for streaming, and every X seconds
 * this will be invoked.  note that we always send out updates as soon
 * as we get a noop: that resets this counter back */
struct prot_waitevent *sendupdates_evt(struct protstream *s __attribute__((unused)), 
				       struct prot_waitevent *ev,
				       void *rock)
{
    struct conn *C = (struct conn *) rock;

    sendupdates(C, 1);

    /* 'sendupdates()' will update when we next trigger */
    return ev;
}

void cmd_startupdate(struct conn *C, const char *tag)
{
    char pattern[2] = {'*','\0'};

    /* initialize my condition variable */
    pthread_cond_init(&C->cond, NULL);

    /* The inital dump of the database can result in a lot of data,
     * let's do this nonblocking */
    prot_NONBLOCK(C->pout);

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

    prot_BLOCK(C->pout);
    prot_flush(C->pout);

    /* schedule our first update */
    C->ev = prot_addwaitevent(C->pin, time(NULL) + update_wait, 
			      sendupdates_evt, C);
}

/* send out any pending updates.
   if 'flushnow' is set, flush the output buffer */
void sendupdates(struct conn *C, int flushnow)
{
    struct pending *p, *q;

    pthread_mutex_lock(&C->m);

    /* just grab the update list and release the lock */
    p = C->plist;
    C->plist = NULL;
    pthread_mutex_unlock(&C->m);

    while (p != NULL) {
	/* send update */
	q = p;
	p = p->next;

	/* notify just like a FIND - except enable sending of DELETE
	 * notifications */
	cmd_find(C, C->streaming, q->mailbox, 0, 1);

	free(q);
    }

    /* reschedule event for 'update_wait' seconds */
    C->ev->mark = time(NULL) + update_wait;

    if (flushnow) {
	prot_flush(C->pout);
    }
}

void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    cyrus_done();
    
    exit(code);
}

/* Reset the given sasl_conn_t to a sane state */
static int reset_saslconn(struct conn *c)
{
    int ret, secflags;
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
    if (!config_getswitch(IMAPOPT_ALLOWPLAINTEXT)) {
	secflags |= SASL_SEC_NOPLAINTEXT;
    }
    secprops = mysasl_secprops(secflags);
    ret = sasl_setprop(c->saslconn, SASL_SEC_PROPS, secprops);
    if(ret != SASL_OK) return ret;
    /* end of service_main initialization excepting SSF */

    return SASL_OK;
}

int cmd_change(struct mupdate_mailboxdata *mdata,
	       const char *rock, void *context __attribute__((unused)))
{
    struct mbent *m = NULL;
    struct conn *upc = NULL;
    enum settype t = -1;
    int ret = 0;

    if(!mdata || !rock || !mdata->mailbox) return 1;

    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    if(!strncmp(rock, "DELETE", 6)) {
	m = database_lookup(mdata->mailbox, NULL);

	if(!m) {
	    syslog(LOG_DEBUG, "attempt to delete unknown mailbox %s",
		   mdata->mailbox);
	    /* Mailbox doesn't exist - this isn't as fatal as you might
	     * think. */
            /* ret = -1; */
	    goto done;
	}
	m->t = t = SET_DELETE;
    } else {
	m = database_lookup(mdata->mailbox, NULL);
	
	if (m && (!mdata->acl || strlen(mdata->acl) < strlen(m->acl))) {
	    /* change what's already there */
	    free(m->server);
	    m->server = xstrdup(mdata->server);

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

	    if(m) {
		free(m->mailbox);
		free(m->server);
	    }

	    /* allocate new mailbox */
	    if (mdata->acl) {
		newm = xrealloc(m, sizeof(struct mbent) + strlen(mdata->acl));
	    } else {
		newm = xrealloc(m, sizeof(struct mbent) + 1);
	    }

	    newm->mailbox = xstrdup(mdata->mailbox);
	    newm->server = xstrdup(mdata->server);

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
    database_log(m, NULL);
    
    /* post pending changes to anyone we are talking to */
    for (upc = updatelist; upc != NULL; upc = upc->updatelist_next) {
	/* for each connection, add to pending list */

	struct pending *p = (struct pending *) xmalloc(sizeof(struct pending));
	strcpy(p->mailbox, mdata->mailbox);
	
	pthread_mutex_lock(&upc->m);
	p->next = upc->plist;
	upc->plist = p;

	pthread_cond_signal(&upc->cond);
	pthread_mutex_unlock(&upc->m);
    }

 done:
    free_mbent(m);
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */

    return ret;
}

struct sync_rock 
{
    struct mpool *pool;
    struct mbent_queue *boxes;
};

/* Read a series of MAILBOX and RESERVE commands and tack them onto a
 * queue */
int cmd_resync(struct mupdate_mailboxdata *mdata,
	       const char *rock, void *context)
{
    struct sync_rock *r = (struct sync_rock *)context;
    struct mbent_queue *remote_boxes = r->boxes;
    struct mbent *newm = NULL;

    if(!mdata || !rock || !mdata->mailbox || !remote_boxes) return 1;

    /* allocate new mailbox */
    if (mdata->acl) {
	newm = mpool_malloc(r->pool,sizeof(struct mbent) + strlen(mdata->acl));
    } else {
	newm = mpool_malloc(r->pool,sizeof(struct mbent) + 1);
    }

    newm->mailbox = mpool_strdup(r->pool, mdata->mailbox);
    newm->server = mpool_strdup(r->pool, mdata->server);

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
static int sync_findall_cb(char *name,
			   int matchlen __attribute__((unused)),
			   int maycreate __attribute__((unused)),
			   void *rock)
{
    struct sync_rock *r = (struct sync_rock *)rock;
    struct mbent_queue *local_boxes = (struct mbent_queue *)r->boxes;
    struct mbent *m;

    if(!local_boxes) return 1;

    m = database_lookup(name, r->pool);
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
    struct mpool *pool;
    struct sync_rock rock;
    char pattern[] = { '*', '\0' };
    int ret = 0;    

    if(!handle || !handle->saslcompleted) return 1;

    pool = new_mpool(131072); /* Arbitrary, but large (128k) */
    rock.pool = pool;
    
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

    rock.boxes = &remote_boxes;

    /* If there is a fatal error, die, other errors ignore */
    if (mupdate_scarf(handle, cmd_resync, &rock, 1, NULL) != 0) {
	struct mbent *p=remote_boxes.head, *p_next=NULL;
	while(p) {
	    p_next = p->next;
	    p = p_next;
	}
	
	ret = 1;
	goto done;	
    }

    /* Make socket nonblocking now */
    prot_NONBLOCK(handle->pin);

    rock.boxes = &local_boxes;

    mboxlist_findall(NULL, pattern, 1, NULL,
		     NULL, sync_findall_cb, (void*)&rock);

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
	} else if (ret < 0) {
	    /* Local without corresponding remote, delete it */
	    mboxlist_deletemailbox(l->mailbox, 1, "", NULL, 0, 0, 0);
	    local_boxes.head = l->next;
	} else /* (ret > 0) */ {
	    /* Remote without corresponding local, insert it */
	    mboxlist_insertremote(r->mailbox, 
				  (r->t == SET_RESERVE ?
				   MBTYPE_RESERVE : 0),
				  r->server, r->acl, NULL);
	    remote_boxes.head = r->next;
	}
    }

    if(l && !r) {
	/* we have more deletes to do */
	while(l) {
	    mboxlist_deletemailbox(l->mailbox, 1, "", NULL, 0, 0, 0);
	    local_boxes.head = l->next;
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
	    r = remote_boxes.head;
	}
    }

    /* All up to date! */
    syslog(LOG_NOTICE, "mailbox list synchronization complete");

 done:
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */
    free_mpool(pool);
    return ret;
}

void mupdate_signal_db_synced(void) 
{
    pthread_mutex_lock(&synced_mutex);
    synced = 1;
    pthread_cond_broadcast(&synced_cond);
    pthread_mutex_unlock(&synced_mutex);
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

/* Signal unreadyness.  Next active worker will kill off all idle connections.
 * any non-idle connection will die off when it leaves docmd() */
void mupdate_unready(void)
{
    pthread_mutex_lock(&ready_for_connections_mutex);

    syslog(LOG_NOTICE, "unready for connections");

    ready_for_connections = 0;

    pthread_mutex_unlock(&ready_for_connections_mutex);
}

/* Used to free malloc'd mbent's (not for mpool'd mbents) */
void free_mbent(struct mbent *p) 
{
    if(!p) return;
    free(p->server);
    free(p->mailbox);
    free(p);
}
