#include <pthread.h>
#include <sasl.h>

static int masterp = 0;

enum settype {
    SET_ACTIVE,
    SET_RESERVE
};

struct pending {
    char mailbox[MAX_MAILBOX_NAME];
    char server[MAX_MAILBOX_NAME];
    enum settype t;
    
    struct pending *next;
};

struct conn {
    int fd;
    struct protstream *pin;
    struct protstream *pout;
    sasl_conn_t *saslconn;
    char *userid;

    /* pending changes to send, in reverse order */
    struct pending *plist;
};

void cmd_set(struct conn *C, 
	     const char *tag, const char *mailbox,
	     const char *server, enum settype t);
void cmd_find(struct conn *C, const char *tag, const char *mailbox);

static struct conn *conn_new(int fd)
{
    struct conn *C = xzmalloc(sizeof(struct conn));
    
    C->fd = fd;

    return C;
}

static void conn_free(struct conn *C)
{
    if (C->userid) free(C->userid);
    if (C->pin) prot_free(C->pin);
    if (C->pout) prot_free(C->pout);
    if (C->saslconn) sasl_dispose(&C->saslconn);

    free(C);
}

/*
 * run once when process is forked;
 * MUST NOT exit directly; must return with non-zero error code
 */
int service_init(int argc, char **argv, char **envp)
{
    int r;

    config_changeident("mupdate");
    
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
	return EC_SOFTWARE;
    }

    if ((r = sasl_client_init(NULL)) != SASL_OK) {
	syslog(LOG_ERR, "SASL failed initializing: sasl_client_init(): %s", 
	       sasl_errstring(r, NULL, NULL));
	return EC_SOFTWARE;
    }

    /* see if we're the master or a slave */
    while ((opt = getopt(argc, argv, "C:m")) != EOF) {
    case 'C':
	break;
    case 'm':
	masterp = 1;
	break;
    default:
	break;
    }

    sprintf(shutdownfilename, "%s/msg/shutdown", config_dir);

    /* open the mboxlist, we'll need it for real work */
    mboxlist_init(0);
    mboxlist_open(NULL);

    if (!master) {
	/* spawn off listener thread to connect to the master */

    }

    return 0;
}

/* called if 'service_init()' was called but not 'service_main()' */
void service_abort(int error)
{
    mboxlist_close();
    mboxlist_done();
}

void fatal(const char *s, int code)
{
    exit(code);
}

#define CHECKNEWLINE(c, ch) do { if ((ch) == '\r') (ch)=prot_getc((c)->pin); \
                       		 if ((ch) != '\n') goto extraargs; } while (0)



void cmdloop(struct conn *c)
{
    struct buf tag, cmd, arg1, arg2;

    /* zero out struct bufs */
    memset(&tag, 0, sizeof(struct buf));
    memset(&cmd, 0, sizeof(struct buf));
    memset(&arg1, 0, sizeof(struct buf));
    memset(&arg2, 0, sizeof(struct buf));

    prot_printf(c->pout, "* OK %s Cyrus Murder MUPDATE %s %s\r\n", 
		config_servername,
		CYRUS_VERSION, masterp ? "(master)", "(slave)");
    for (;;) {
	int ch;

	signals_poll();

	if (c->streaming) {
	    /* if streaming updates, do the select */

	} else {
	    /* not streaming */
	    ch = getword(c->pin, &tag);
	}
	if (ch == EOF) {
	    if ((err = prot_error(c->pin)) != NULL) {
		syslog(LOG_WARNING, "%s, closing connection", err);
		prot_printf(&c->pout, "* BYE %s\r\n", err);
	    }
	    goto done;
	}

	if (ch != ' ') {
	    eatline(c->pin, ch);
	    continue;
	}

	/* parse command name */
	ch = getword(c->pin, &cmd);
	if (!cmd.s[0]) {
	    prot_printf(c->pout, "%s BAD Null command\r\n", tag.s);
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
		ch = getword(&arg1);
		if (ch == ' ') {
		    ch = getword(&arg2);
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
		ch = getword(&arg1);
		if (ch != ' ') goto missingargs;
		ch = getword(&arg2);
		CHECKNEWLINE(c, ch);

		cmd_set(c, tag.s, arg1.s, arg2.s, SET_ACTIVE);
	    }
	    else goto badcmd;

	    break;

	case 'F':
	    if (!c->userd) goto nologin;
	    else if (!strcmp(cmd.s, "Find")) {
		if (ch != ' ') goto missingargs;
		ch = getword(&arg1);
		CHECKNEWLINE(c, ch);

		cmd_find(c, tag.s, arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'L':
	    if (!strcmp(cmd.s, "Logout")) {
		CHECKNEWLINE(c, ch);

		prot_printf("%s OK \"bye-bye\"\r\n", tag.s);
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
		ch = getword(&arg1);
		if (ch != ' ') goto missingargs;
		ch = getword(&arg2);
		CHECKNEWLINE(c, ch);

		cmd_set(c, tag.s, arg1.s, arg2.s, SET_RESERVE);
	    }
	    else goto badcmd;
	    break;

	case 'U':
	    if (!c->userid) goto nologin;
	    else if (!strcmp(cmd.s, "Update")) {
		/* indicate interest in updates */

		/* send current database */

		/* start streaming updates */


	    }
	    else goto badcmd;
	    break;

	default:
	badcmd:
	    prot_printf(c->pout, "%s BAD Unrecognized command\r\n", tag.s);
	    eatline(c->pin, ch);
	}

	continue;

    nologin:
	prot_printf(c->pout, "%s BAD Please login first\r\n", tag.s);
	eatline(c->pin, ch);
	continue;
    }

 done:
    /* free struct bufs */

}

void *start(void *rock)
{
    struct conn *c = (struct conn *) rock;
    struct sockaddr_in localaddr, remoteaddr;
    int haveaddr = 0;
    char clienthost[250];

    c->pin = prot_new(c->fd, 0);
    c->pout = prot_new(c->fd, 1);

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

    return pthread_create(&t, NULL, &start, &c);
}

void cmd_set(struct conn *C, 
	     const char *tag, const char *mailbox,
	     const char *server, enum settype t)
{
    /* lock database */

    /* change the database */
    
    /* post pending changes */

    /* notify */

    /* unlock database */
}

void cmd_find(struct conn *C, const char *tag, const char *mailbox)
{
    int r;
    char *server;

    r = mboxlist_lookup(mailbox, &server, NULL, NULL);
    if (!r) {
	prot_printf(C->pout, "%s MAILBOX {%d}\r\n%s {%d}\r\n%s\r\n",
		    strlen(mailbox), mailbox,
		    strlen(server), server);

    }


}

