/* target-acap.c -- aggregator mailbox database manager
 *                  communicates with ACAP server to learn state of world
 * Larry Greenfield
 * 
 * Copyright 1999 Carnegie Mellon University
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
 *
 * $Id: target-acap.c,v 1.12 2000/04/20 16:30:03 leg Exp $
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <com_err.h>
#include <syslog.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <signal.h>

#include <sasl.h>
#include <acap.h>
#include <skip-list.h>

#include "imapconf.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "xmalloc.h"
#include "imapurl.h"
#include "acapmbox.h"

int noop = 0;

extern sasl_callback_t *mysasl_callbacks(const char *username,
					 const char *authname,
					 const char *realm,
					 const char *password);

static acap_conn_t *acap_conn;
static acap_context_t *mycontext;

static unsigned int getintattr(acap_entry_t *e, char *attrname)
{
    char *s = acap_entry_getattr_simple(e, attrname);
    if (s) return atoi(s);
    else return 0;
}

static char *getstrattr(acap_entry_t *e, char *attrname)
{
    return acap_entry_getattr_simple(e, attrname);
}

static int dissect_entry(acap_entry_t *e, acapmbox_data_t *data)
{
    acap_value_t *v;

    if (!e || !data) return ACAP_BAD_PARAM;

    data->name = acap_entry_getname(e);
    data->uidvalidity = getintattr(e, "mailbox.uidvalidity");

    v = acap_entry_getattr(e, "mailbox.status");
    data->status = mboxdata_convert_status(v);

    data->post = getstrattr(e, "mailbox.post");
    data->haschildren = getintattr(e, "mailbox.haschildren");
    data->url = getstrattr(e, "mailbox.url");
    data->acl = getstrattr(e, "mailbox.acl");

    data->answered = getintattr(e, "mailbox.answered");
    data->flagged = getintattr(e, "mailbox.flagged");
    data->deleted = getintattr(e, "mailbox.deleted");
    data->total = getintattr(e, "mailbox.total");

    return ACAP_OK;
}

void connect_acap(const char *server)
{
    const char *user, *authprog;
    char acapurl[1024];
    int r;
    sasl_callback_t *cb;

    user = config_getstring("acap_username", NULL);
    if (user == NULL) {
	syslog(LOG_ERR, "unable to find option acap_username");
	fatal("couldn't connect to acap server", EC_NOHOST);
    }

    cb = mysasl_callbacks(user,
			  config_getstring("acap_authname", user),
			  config_getstring("acap_realm", NULL),
			  config_getstring("acap_password", NULL));

    authprog = config_getstring("acap_getauth", NULL);
    if (authprog) {
	system(authprog);
    }

    /* probably should setup callbacks here if configured to! */
    r = sasl_client_init(cb);
    if (r != SASL_OK) {
	syslog(LOG_ERR, "sasl_client_init() failed: %s",
	       sasl_errstring(r, NULL, NULL));
	fatal("couldn't connect to acap server", EC_NOHOST);
    }

    snprintf(acapurl, sizeof(acapurl), "acap://%s@%s/", user, server);
    r = acap_conn_connect(acapurl, &acap_conn);
    if (r != ACAP_OK) {
	syslog(LOG_ERR, "couldn't connect to ACAP server: %s",
	       error_message(r));
	fatal("couldn't connect to acap server", EC_NOHOST);
    }
}

void myacap_addto(acap_entry_t *entry,
		  unsigned position,
		  void *rock)
{
    acapmbox_data_t d;
    char *name = acap_entry_getname(entry);
    char *server, *mailbox;
    int r;

    if (!name || !name[0]) return; /* null entry */
    r = dissect_entry(entry, &d);
    if (r) {
	syslog(LOG_ERR, "dissect_entry: %s", error_message(r));
	return;
    }
    if (d.status != ACAPMBOX_COMMITTED) {
	syslog(LOG_ERR,
	    "my context only allows committed mailboxes, but this one isn't!");
	return;
    }

    server = (char *) xmalloc(sizeof(char) * strlen(d.url));
    mailbox = (char *) xmalloc(sizeof(char) * 2 * strlen(d.url));
    imapurl_fromURL(server, mailbox, d.url);

    syslog(LOG_DEBUG, "creating mailbox %s", name);
    r = mboxlist_insertremote(mailbox, MBTYPE_REMOTE, server, d.acl, NULL);
    if (r) {
	syslog(LOG_ERR, "couldn't insert %s into mailbox list: %s\n",
	       d.name, error_message(r));
    }

    free(mailbox);
    free(server);
}

void myacap_removefrom(acap_entry_t *entry,
		       unsigned position,
		       void *rock)
{
    char *name = acap_entry_getname(entry);

    if (!name || !name[0]) return; /* null entry */

    /* need to reencode UTF-8 name into a UTF-7 IMAP name */

    syslog(LOG_DEBUG, "deleting mailbox %s", name);
    mboxlist_deletemailbox(name, 1, "", NULL, 0);
}

void myacap_change(acap_entry_t *entry,
		   unsigned oldpos, unsigned newpos,
		   void *rock)
{
    /* xxx ACL might've changed */
}

void myacap_modtime(char *modtime, void *rock)
{
    syslog(LOG_NOTICE, "synchronized new mailboxes file to '%s'", modtime);
}

static int mbox_comp(const void *v1, const void *v2)
{
    return strcmp((const char *)v1, (const char *)v2);
}

static int mboxadd(char *name, int matchlen, int maycreate, void *rock)
{
    skiplist *s = (skiplist *) rock;

    sinsert(s, xstrdup(name));
    return 0;
}

static int num = 0;

void myacap_entry(acap_entry_t *entry, void *rock)
{
    /* name is a UTF-8 encoded representation of the mailbox;
       technically we should reencode it into modified UTF-7. however,
       right now both my client and server will violate this. */
    char *name = acap_entry_getname(entry);
    acap_value_t *url = acap_entry_getattr(entry, "mailbox.url");
    acap_value_t *acl = acap_entry_getattr(entry, "mailbox.acl");
    char *server, *mailbox;
    skiplist *s = (skiplist *) rock;
    void *v;
    int r = 0;

    if (!name || !url || !acl) {
	if (name && (name[0] == '\0')) return; /* null entry, ok */
	syslog(LOG_NOTICE, "%s received with incomplete ACAP entry",
	       name ? name : "<entry?>");
	return;
    }

    num++;
    if (!(num % 1000)) syslog(LOG_NOTICE, "received %d mailboxes (on %s)",
			      num, name);

    server = (char *) xmalloc(sizeof(char) * url->len);
    mailbox = (char *) xmalloc(sizeof(char) * 2 * url->len);

    imapurl_fromURL(server, mailbox, url->data);

    v = ssearch(s, mailbox);
    if (v) { 
	sdelete(s, mailbox);
	free(v);
	r = 0;
    } else { /* we don't have it, add it */
	r = mboxlist_insertremote(mailbox, MBTYPE_REMOTE, server, 
				  acl->data, NULL);
    }

    if (r) {
	syslog(LOG_ERR, "failed to insert %s into new mailboxes file",
	       name);
	fatal("fatal mailboxes error", EC_DATAERR);
    }
    free(server);
    free(mailbox);
}

static void mboxdel(const void *v)
{
    char *name = (char *) v;
    int r = 0;

    syslog(LOG_DEBUG, "'%s' no longer exists", name);
    r = mboxlist_deletemailbox(name, 1, "", NULL, 0);
    if (r) {
	syslog(LOG_ERR, "error deleting '%s': %s", name, error_message(r));
    }
}

static struct acap_search_callback myacap_search_cb = {
    &myacap_entry, &myacap_modtime
};

static struct acap_requested myacap_request = {
    1, { "mailbox.*" }
};

static struct acap_context_callback myacap_context_cb = {
    &myacap_addto,
    &myacap_removefrom,
    &myacap_change,
    &myacap_modtime /* reuse modtime cb */
};

/* this code grabs the current list of mailboxes from the ACAP server,
   saves it into a brand new database, and then moves the database into
   place. it also initializes the callbacks */
void synchronize_mboxlist(void)
{
    acap_cmd_t *cmd;
    int r;
    skiplist *mailboxes = skiplist_new(10, 0.5, &mbox_comp);
    char s[30];

    if (!mailboxes) {
	syslog(LOG_ERR, "skiplist_new failed");
	fatal("skiplist_new failed", EC_TEMPFAIL);
    }

    mboxlist_open(NULL);
    
    syslog(LOG_NOTICE, "starting mailbox synchronization");

    strcpy(s, "*");
    r = mboxlist_findall(s, 1, "", NULL, &mboxadd, mailboxes);

    r = acap_search_dataset(acap_conn, global_dataset "/", 
		      "EQUAL \"mailbox.status\" \"i;octet\" \"committed\"", 0,
			    &myacap_request, NULL,
			    NULL,
			    &myacap_search_cb,
			    &mycontext, &myacap_context_cb, 
			    mailboxes, &cmd);
    if (r != ACAP_OK) {
	syslog(LOG_ERR, "acap_search_dataset() failed: %s\n", 
	       error_message(r));
	fatal("can't download list of datasets\n", EC_NOHOST);
    }
	
    r = acap_process_on_command(acap_conn, cmd, NULL);
    if (r != ACAP_OK) {
	syslog(LOG_ERR, "acap_process_on_command() failed: %s\n", 
	       error_message(r));
	fatal("can't download list of datasets\n", EC_NOHOST);
    }

    /* anything left over has been deleted */
    sforeach(mailboxes, &mboxdel);
    sforeach(mailboxes, &free);
    skiplist_free(mailboxes);

    mboxlist_close();

    syslog(LOG_NOTICE, "done synchronizing mailbox database: %d entries", num);
}

void fatal(const char *s, int code)
{
    static int recurse_code = 0;

    fprintf(stderr, "target-acap: %s\n", s);
    if (recurse_code) {
	/* We were called recursively. Just give up */
	exit(recurse_code);
    }
    recurse_code = code;
    mboxlist_done();
    exit(code);
}

void listen_for_kicks()
{
    struct sockaddr_un srvaddr;
    struct sockaddr_un clientaddr;
    char fnamebuf[1024];
    int s, r, len;
    mode_t oldumask;
    int acapsock = acap_conn_get_sock(acap_conn);
    fd_set read_set, rset;
    int nfds;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	syslog(LOG_ERR, "socket: %m");
	return;
    }

    strcpy(fnamebuf, config_dir);
    strcat(fnamebuf, FNAME_TARGET_SOCK);

    (void) unlink(fnamebuf);
    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, fnamebuf);
    len = strlen(srvaddr.sun_path) + sizeof(srvaddr.sun_family);
    oldumask = umask((mode_t) 0); /* for Linux */
    r = bind(s, (struct sockaddr *)&srvaddr, len);
    umask(oldumask); /* for Linux */
    chmod(fnamebuf, 0777); /* for DUX */
    if (r == -1) {
	syslog(LOG_ERR, "bind: %s: %m", fnamebuf);
	exit(1);
    }
    r = listen(s, 10);
    if (r == -1) {
	syslog(LOG_ERR, "listen: %m");
	exit(1);
    }

    /* get ready for select() */
    FD_ZERO(&read_set);
    FD_SET(s, &read_set);
    FD_SET(acapsock, &read_set);
    if (acapsock > s) nfds = acapsock + 1;
    else nfds = s + 1;

    for (;;) {
	int c, n;

	/* process any outstanding ACAP stuff */
	r = acap_process_outstanding(acap_conn);
	if (r != ACAP_OK) syslog(LOG_ERR, "acap_process_outstanding(): %s",
				 error_message(r));
	if (r == ACAP_NO_CONNECTION) return;

	/* check for the next input */
	rset = read_set;
	n = select(nfds, &rset, NULL, NULL, NULL);
	if (n < 0 && errno == EAGAIN) continue;
	if (n < 0 && errno == EINTR) continue;
	if (n == -1) {
	    /* uh oh */
	    syslog(LOG_ERR, "select(): %m");
	    close(s);
	    return;
	}

	/* if (FD_ISSET(acap_conn, &rfds)) 
	       when we loop we'll take care of it 
	 */

	if (FD_ISSET(s, &rset)) {
	    acap_cmd_t *cmd;

	    len = sizeof(clientaddr);
	    c = accept(s, (struct sockaddr *)&clientaddr, &len);
	    if (c == -1) {
		syslog(LOG_WARNING, "erg, accept(): %m");
		continue;
	    }
	    
	    /* c wants an update! */
	    r = acap_updatecontext(acap_conn, mycontext, NULL, NULL, &cmd);
	    if (r == ACAP_OK) {
		r = acap_process_on_command(acap_conn, cmd, NULL);
	    }
	    
	    if (r != ACAP_OK) {
		syslog(LOG_ERR, "unable to UPDATECONTEXT: %s",
		       error_message(r));
		/* we might as well tell the client ok now; if this is a
		   fatal error with the ACAP server, we'll detect it the
		   next time around */
	    }

	    if (write(c, "ok", 2) < 0) {
		syslog(LOG_WARNING, "can't write to IPC socket?");
	    }
	    close(c);
	}
    }
}

void handler(int sig)
{
    fatal("received signal", 1);
}

int main(int argc, char *argv[], char *envp[])
{
    const char *server;

    config_init("target");

    if (geteuid() == 0) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    acap_init();

    server = config_getstring("acap_server", NULL);
    if (!server) fatal("no ACAP servers specified", EC_USAGE);
    
    mboxlist_init(0);

    signal(SIGTERM, &handler);
    signal(SIGINT, &handler);
    signal(SIGPIPE, SIG_IGN);

    connect_acap(server);

    synchronize_mboxlist();

    /* we fork to return immediately */
    if (fork() == 0) {
	mboxlist_open(NULL);

	/* we now look for processes asking us to issue an UPDATECONTEXT,
	   presumably because they are looking for a mailbox that 
	   doesn't exist */
	listen_for_kicks();

	/* if this returns, we have a problem.  we should probably try
	   to reestablish the connection with the ACAP server and
	   resynchronize, but we're not that smart yet */
	return 1;
    }

    /* parent */
    return 0;
}
