/*
 * Work in progress by larry. compiles now but not useful yet.
 * 
 */


#include <config.h>

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

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <sasl.h>

#include <skip-list.h>

#include "xmalloc.h"
#include "mailbox.h"
#include "exitcodes.h"
#include "prot.h"
#include "imapconf.h"
#include "version.h"

static int masterp = 0;

enum settype {
    SET_ACTIVE,
    SET_RESERVE,
    SET_DELETE
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

    /* pending changes to send, in reverse order */
    int streaming;
    pthread_mutex_t m;
    struct pending *plist;
    struct conn *updatelist_next;

    struct conn *next;
};

pthread_mutex_t connlist_mutex = PTHREAD_MUTEX_INITIALIZER;
struct conn *connlist;

void cmd_set(struct conn *C, 
	     const char *tag, const char *mailbox,
	     const char *server, const char *acl, enum settype t);
void cmd_find(struct conn *C, const char *tag, const char *mailbox);
void shut_down(int code);
void database_init();

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
    if (C->streaming) {
	/* xxx remove from updatelist */


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

    if (C->userid) free(C->userid);
    if (C->pin) prot_free(C->pin);
    if (C->pout) prot_free(C->pout);
    if (C->saslconn) sasl_dispose(&C->saslconn);

    /* free update list */

    free(C);
}

/* should we allow users to proxy?  return SASL_OK if yes,
   SASL_BADAUTH otherwise */
static int mysasl_authproc(void *context __attribute__((unused)),
			   const char *auth_identity,
			   const char *requested_user,
			   const char **user,
			   const char **errstr)
{
    /* xxx verify this is a privileged user */

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
	/* spawn off listener thread to connect to the master */

    }

    return 0;
}

/* called if 'service_init()' was called but not 'service_main()' */
void service_abort(int error)
{
}

void fatal(const char *s, int code)
{
    exit(code);
}

#define CHECKNEWLINE(c, ch) do { if ((ch) == '\r') (ch)=prot_getc((c)->pin); \
                       		 if ((ch) != '\n') goto extraargs; } while (0)

void cmdloop(struct conn *c)
{
    struct buf tag, cmd, arg1, arg2, arg3;

    syslog(LOG_DEBUG, "starting cmdloop() on fd %d", c->fd);
    
    /* zero out struct bufs */
    memset(&tag, 0, sizeof(struct buf));
    memset(&cmd, 0, sizeof(struct buf));
    memset(&arg1, 0, sizeof(struct buf));
    memset(&arg2, 0, sizeof(struct buf));
    memset(&arg3, 0, sizeof(struct buf));

    prot_printf(c->pout, "* OK %s Cyrus Murder MUPDATE %s %s\r\n", 
		config_servername,
		CYRUS_VERSION, masterp ? "(master)" : "(slave)");
    for (;;) {
	int ch;
	char *p;

	signals_poll();

	if (c->streaming) {
	    /* if streaming updates, do the select */
	    ch = EOF;
	} else {
	    /* not streaming */
	    ch = getword(c->pin, &tag);
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
		ch = getastring(c->pin, c->pout, &arg1);
		if (ch == ' ') {
		    ch = getastring(c->pin, c->pout, &arg2);
		    opt = 1;
		}
		CHECKNEWLINE(c, ch);

		if (c->userid) {
		    prot_printf(c->pout, "%s BAD \"already authenticated\"\r\n",
				tag.s);
		    continue;
		}

		/* xxx do authentication */
		if (!strcasecmp(arg1.s, "backdoor") && opt) {
		    c->userid = xstrdup(arg2.s);
		    prot_printf(c->pout, "%s OK \"user logged in\"\r\n",
				tag.s);
		} else {
		    prot_printf(c->pout, "%s BAD \"unknown mechanism\"\r\n",
				tag.s);
		}
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

		cmd_find(c, tag.s, arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'L':
	    if (!strcmp(cmd.s, "Logout")) {
		CHECKNEWLINE(c, ch);

		prot_printf(c->pout, "%s OK \"bye-bye\"\r\n", tag.s);
		goto done;
	    }
	    else goto badcmd;
	    break;

	case 'N':
	    if (!strcmp(cmd.s, "Noop")) {
		CHECKNEWLINE(c, ch);

		prot_printf(c->pout, "%s \"Noop done\"\r\n", tag.s);
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

		cmd_set(c, tag.s, arg1.s, arg2.s, NULL, SET_RESERVE);
	    }
	    else goto badcmd;
	    break;

	case 'U':
	    if (!c->userid) goto nologin;
	    else if (!strcmp(cmd.s, "Update")) { /* xxx */
		cmd_update(c, tag.s);
		/* no other commands are legal after this */
		goto done;
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
	}

	continue;

    nologin:
	prot_printf(c->pout, "%s BAD Please login first\r\n", tag.s);
	eatline(c->pin, ch);
	continue;
    }

 done:
    /* free struct bufs */

    syslog(LOG_DEBUG, "ending cmdloop() on fd %d", c->fd);
}

void *start(void *rock)
{
    struct conn *c = (struct conn *) rock;
    struct sockaddr_in localaddr, remoteaddr;
    int haveaddr = 0;
    int salen;
    char clienthost[250];
    struct hostent *hp;

    c->pin = prot_new(c->fd, 0);
    c->pout = prot_new(c->fd, 1);
    prot_setflushonread(c->pin, c->pout);
    prot_settimeout(c->pin, 30*60);

    /* Find out name of client host */
    salen = sizeof(remoteaddr);
    if (getpeername(0, (struct sockaddr *)&remoteaddr, &salen) == 0 &&
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
	if (getsockname(0, (struct sockaddr *)&localaddr, &salen) == 0) {
	    haveaddr = 1;
	}
    }

    /* create sasl connection */
    if (sasl_server_new("imap", config_servername, 
			NULL, NULL, SASL_SECURITY_LAYER, 
			&c->saslconn) != SASL_OK) {
	fatal("SASL failed initializing: sasl_server_new()", EC_TEMPFAIL);
    }

    if (haveaddr) {
	sasl_setprop(c->saslconn, SASL_IP_REMOTE, &remoteaddr);
	sasl_setprop(c->saslconn, SASL_IP_LOCAL, &localaddr);
    }

    cmdloop(c);
    
    close (c->fd);
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

    return pthread_create(&t, NULL, &start, c);
}

/* ---- database access ---- */
skiplist *mailboxes;
pthread_mutex_t mailboxes_mutex = PTHREAD_MUTEX_INITIALIZER;
struct conn *updatelist;

/* mailbox name MUST be first, since it is the key */
struct mbent {
    char mailbox[MAX_MAILBOX_NAME];
    char server[MAX_MAILBOX_NAME];
    enum settype t;
    char acl[1];
};

static FILE *dblog;

/* this depends on mailbox name being first */
static int mycmp(const void *v1, const void *v2)
{
    return strcmp((const char *) v1, (const char *) v2);
}

/* read from disk
 database must be unlocked. */
void database_init()
{
    char dbname[1024];
    FILE *db;

    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    mailboxes = skiplist_new(20, 0.5, &mycmp);
    snprintf(dbname, sizeof dbname, "%s/%s", config_dir, "mupdate.log");
    db = fopen(dbname, "r");
    if (db != NULL) {
	while (!feof(db)) {
	    int c;
	    struct mbent m, *mptr;
	    int i = 0;

	    c = fgetc(db);
	    if (c == 'A') m.t = SET_ACTIVE;
	    else if (c == 'R') m.t = SET_RESERVE;
	    else if (c == 'D') m.t = SET_DELETE;
	    else if (c == -1) break;
	    else abort();

	    /* skip after \t */
	    while ((c = fgetc(db)) > 0) {
		if (c == '\t') break;
	    }
	    if (c < 0) break;

	    while ((c = fgetc(db)) > 0) {
		if (c == '\n' || c == '\t') break;
		m.mailbox[i++] = c;
		assert(i != MAX_MAILBOX_NAME);
	    }
	    m.mailbox[i] = '\0';

	    switch (m.t) {
	    case SET_ACTIVE:
	    {
		char *acl = NULL;
		int aclalloc = 0;

		i = 0;
		while ((c = fgetc(db)) > 0) {
		    if (c == '\n' || c == '\t') break;
		    m.server[i++] = c;
		    assert(i != MAX_MAILBOX_NAME);
		}
		m.server[i] = '\0';

		assert(c == '\t');
		i = 0;
		while ((c = fgetc(db)) > 0) {
		    if (c == '\n' || c == '\t') break;
		    if (i == aclalloc) {
			acl = xrealloc(acl, aclalloc += 500);
		    }
		    acl[i++] = c;
		}

		mptr = xmalloc(sizeof(struct mbent) + (i + 1));
		memcpy(mptr, &m, sizeof(struct mbent));
		memcpy(mptr->acl, acl, i);
		mptr->acl[i] = '\0';
		if (acl) free(acl);

		sinsert(mailboxes, mptr);
		break;
	    }
	    case SET_RESERVE:
		i = 0;
		while ((c = fgetc(db)) > 0) {
		    if (c == '\n' || c == '\t') break;
		    m.server[i++] = c;
		    assert(i != MAX_MAILBOX_NAME);
		}
		m.server[i] = '\0';

		mptr = xmalloc(sizeof(struct mbent));
		memcpy(mptr, &m, sizeof(struct mbent));
		sinsert(mailboxes, mptr);
		break;
	    case SET_DELETE:
		sdelete(mailboxes, &m);
		break;
	    }
	}

	fclose(db);
    }

    dblog = fopen(dbname, "a");
    if (dblog == NULL) {
	syslog(LOG_CRIT, "unable to open logfile %s: %m", dbname);
	abort();
    }

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

/* log change to database.
 database must be locked. */
void database_log(const struct mbent *new)
{
    switch (new->t) {
    case SET_ACTIVE:
	fprintf(dblog, "%s\t%s\t%s\t%s\n", translate(new->t),
		new->mailbox, new->server, new->acl);
	break;

    case SET_RESERVE:
	fprintf(dblog, "%s\t%s\t%s\n", translate(new->t),
		new->mailbox, new->server);
	break;

    case SET_DELETE:
	fprintf(dblog, "%s\t%s\n", translate(new->t), new->mailbox);
	break;
    }
    if (fflush(dblog) < 0) {
	syslog(LOG_ERR, "fflush mupdate log: %m");
    }
    if (fsync(fileno(dblog)) < 0) {
	syslog(LOG_ERR, "fsync mupdate log: %m");
    }
}

/* probabilistically compress database log.
 database must be locked. */
void database_compress()
{
    /* 2 chances in # of items */
    if ((rand() % skiplist_items(mailboxes)) < 2) {
	/* do the compression */

	char dbnamenew[1024];
	char dbname[1024];
	FILE *db;
	skipnode *ptr;
	struct mbent *m;

	syslog(LOG_DEBUG, "compressing mupdate log");
	
	snprintf(dbname, sizeof dbname, "%s/%s", config_dir, "mupdate.log");
	snprintf(dbnamenew, sizeof dbnamenew, "%s.NEW", dbname);
	db = fopen(dbnamenew, "w");
	if (db == NULL) {
	    syslog(LOG_ERR, "can't compress database: open(%s): %m", 
		   dbnamenew);
	    return;
	}
	assert(db != NULL);
	for (m = sfirst(mailboxes, &ptr); m != NULL; m = snext(&ptr)) {
	    switch (m->t) {
	    case SET_ACTIVE:
		fprintf(db, "%s\t%s\t%s\t%s\n", translate(m->t),
			m->mailbox, m->server, m->acl);
		break;
		
	    case SET_RESERVE:
		fprintf(db, "%s\t%s\t%s\n", translate(m->t),
			m->mailbox, m->server);
		break;

	    case SET_DELETE:
		/* deleted item in the list !?! */
		abort();
	    }
	}
	if ((fsync(fileno(db)) < 0) ||
	    (rename(dbnamenew, dbname) < 0)) {
	    syslog(LOG_ERR, "can't compress database: %m");
	    (void) unlink(dbnamenew);
	}
	fclose(db);

	/* reopen for logging purposes */
	fclose(dblog);
	dblog = fopen(dbname, "a");
	if (dblog == NULL) {
	    syslog(LOG_CRIT, "unable to open logfile %s: %m", dbname);
	    abort();
	}
    }
}

void cmd_set(struct conn *C, 
	     const char *tag, const char *mailbox,
	     const char *server, const char *acl, enum settype t)
{
    struct mbent *m;
    struct mbent *newm;
    struct conn *upc;

    syslog(LOG_DEBUG, "cmd_set(fd:%d, %s)", C->fd, mailbox);

    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    m = ssearch(mailboxes, mailbox);
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

	/* write to disk */
	database_log(m);

	/* remove from memory */
	sdelete(mailboxes, m);
	free(m);

	prot_printf(C->pout, "%s OK \"deleted\"\r\n", tag);
    } else {
	if (m && (!acl || strlen(acl) < strlen(m->acl))) {
	    /* change what's already there */
	    strcpy(m->server, server);
	    if (acl) strcpy(m->acl, acl);
	    m->t = t;
	} else {
	    if (m) {
		/* need bigger one */
		sdelete(mailboxes, m);
	    }

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

	    /* write to disk */
	    database_log(newm);

	    /* insert it in */
	    sinsert(mailboxes, newm);
	}
    }

    /* post pending changes */
    for (upc = updatelist; upc != NULL; upc = upc->updatelist_next) {
	/* for each connection, add to pending list */

	struct pending *p = (struct pending *) xmalloc(sizeof(struct pending));
	strcpy(p->mailbox, mailbox);
	p->t = t;
	
	pthread_mutex_lock(&upc->m);
	p->next = upc->plist;
	upc->plist = p;
	/* xxx notify server? */
	pthread_mutex_unlock(&upc->m);
    }

    prot_printf(C->pout, "%s OK \"done\"\r\n", tag);
 done:
    database_compress();
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */
}

void cmd_find(struct conn *C, const char *tag, const char *mailbox)
{
    struct mbent *m;

    syslog(LOG_DEBUG, "cmd_find(fd:%d, %s)", C->fd, mailbox);

    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */
    m = ssearch(mailboxes, mailbox);

    if (m && m->t == SET_ACTIVE) {
	prot_printf(C->pout, "%s MAILBOX {%d}\r\n%s {%d}\r\n%s {%d}\r\n%s\r\n",
		    tag,
		    strlen(m->mailbox), m->mailbox,
		    strlen(m->server), m->server,
		    strlen(m->acl), m->acl);
    } else if (m && m->t == SET_RESERVE) {
	prot_printf(C->pout, "%s RESERVE {%d}\r\n%s {%d}\r\n%s\r\n",
		    tag,
		    strlen(m->mailbox), m->mailbox,
		    strlen(m->server), m->server);
    } else {
	/* no output: not found */
    }
    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */

    prot_printf(C->pout, "%s OK \"Search completed\"\r\n", tag);
}

void cmd_update(struct conn *C, const char *tag)
{
    skipnode *ptr;
    struct mbent *m;

    /* indicate interest in updates */
    pthread_mutex_lock(&mailboxes_mutex); /* LOCK */

    C->updatelist_next = updatelist;
    updatelist = C;
    C->streaming = 1;

    /* send current database */
    for (m = sfirst(mailboxes, &ptr); m != NULL; m = snext(&ptr)) {
	switch (m->t) {
	case SET_ACTIVE:
	    prot_printf(C->pout, "%s MAILBOX {%d}\r\n%s {%d}\r\n%s {%d}\r\n%s\r\n",
			tag,
			strlen(m->mailbox), m->mailbox,
			strlen(m->server), m->server,
			strlen(m->acl), m->acl);
	    break;
	case SET_RESERVE:
	    prot_printf(C->pout, "%s RESERVE {%d}\r\n%s {%d}\r\n%s\r\n",
			tag,
			strlen(m->mailbox), m->mailbox,
			strlen(m->server), m->server);
	    break;
	case SET_DELETE:
	    /* deleted item in the list !?! */
	    abort();
	}
    }

    pthread_mutex_unlock(&mailboxes_mutex); /* UNLOCK */

    prot_printf(C->pout, "%s OK \"streaming starts\"\r\n", tag);

    /* start streaming updates */
    for (;;) {



    }
}

void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    exit(code);
}
