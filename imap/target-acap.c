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
 * $Id: target-acap.c,v 1.4 2000/02/16 03:12:01 leg Exp $
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
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
#include <signal.h>

#include <sasl.h>
#include <acap.h>

#include "config.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "xmalloc.h"
#include "imapurl.h"
#include "acapmbox.h"

extern sasl_callback_t *mysasl_callbacks(const char *username,
					 const char *authname,
					 const char *realm,
					 const char *password);

static acap_conn_t *acap_conn;

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
	       strerror(r));
	fatal("couldn't connect to acap server", EC_NOHOST);
    }
}

void myacap_entry(acap_entry_t *entry, void *rock)
{
    /* name is a UTF-8 encoded representation of the mailbox;
       technically we should reencode it into modified UTF-7. however,
       right now both my client and server will violate this. */
    char *name = acap_entry_getname(entry);
    acap_value_t *url = acap_entry_getattr(entry, "mailbox.url");
    acap_value_t *acl = acap_entry_getattr(entry, "mailbox.acl");
    char *server, *mailbox;
    int r;

    if (!name || !url || !acl) {
	if (name && (name[0] == '\0')) return; /* null entry, ok */
	syslog(LOG_NOTICE, "%s received with incomplete ACAP entry",
	       name ? name : "<entry?>");
	return;
    }

    server = (char *) xmalloc(sizeof(char) * url->len);
    mailbox = (char *) xmalloc(sizeof(char) * 2 * url->len);
    imapurl_fromURL(server, mailbox, url->data);

    r = mboxlist_insertremote(mailbox, 0, server, acl->data, NULL);
    if (!r) {
	syslog(LOG_ERR, "failed to insert %s into new mailboxes file",
	       name);
	fatal("fatal mailboxes error", 0);
    }
}

void myacap_addto(acap_entry_t *entry,
		  unsigned position,
		  void *rock)
{
    acapmbox_data_t d;
    char *name = acap_entry_getname(entry);

    if (!name || !name[0]) return; /* null entry */
    if (dissect_entry(entry, &d) != ACAP_OK) return;
    if (d.status != ACAPMBOX_COMMITTED) return;

    mboxlist_insertremote(d.name, MBTYPE_REMOTE, d.url, d.acl, NULL);
}

void myacap_removefrom(acap_entry_t *entry,
		       unsigned position,
		       void *rock)
{
    char *name = acap_entry_getname(entry);

    if (!name || !name[0]) return; /* null entry */

    mboxlist_deletemailbox(name, 1, "", NULL, 0);

}

void myacap_change(acap_entry_t *entry,
		   unsigned oldpos, unsigned newpos,
		   void *rock)
{



}

void myacap_modtime(char *modtime, void *rock)
{
    syslog(LOG_NOTICE, "synchronized new mailboxes file to '%s'", modtime);
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

static acap_context_t *mycontext;

/* this code grabs the current list of mailboxes from the ACAP server,
   saves it into a brand new database, and then moves the database into
   place. it also initializes the callbacks */
void synchronize_mboxlist(void)
{
    char newmblist[1024];
    char mblist[1024];
    acap_cmd_t *cmd;
    int r;

    strcpy(newmblist, config_dir);
    sprintf(newmblist, "%s%s.NEW", config_dir, FNAME_MBOXLIST);
    unlink(newmblist);
    mboxlist_open(newmblist);
    
    /* xxx eventually need to fill in context stuff here */
    r = acap_search_dataset(acap_conn, "/mailbox/", 
			    "NOT EQUAL \"entry\" \"i;octet\" \"\"", 1,
			    &myacap_request, NULL,
			    NULL,
			    &myacap_search_cb,
			    &mycontext, &myacap_context_cb, NULL, &cmd);
    if (r != ACAP_OK) {
	printf("acap_search_dataset() failed with %d\n", r);
	fatal("can't download list of datasets\n", EC_NOHOST);
    }
	
    r = acap_process_on_command(acap_conn, cmd, NULL);
    if (r != ACAP_OK) {
	printf("acap_process_on_command() failed with %d\n", r);
	fatal("can't download list of datasets\n", EC_NOHOST);
    }

    mboxlist_close();

    sprintf(mblist, "%s%s", config_dir, FNAME_MBOXLIST);
    errno = 0;
    r = rename(newmblist, mblist);
    if (!r) {
	syslog(LOG_ERR, "couldn't rename mailboxes file: %m");
	fatal("couldn't rename mailboxes file", 0);
    }
}

void fatal(const char *s, int code)
{
    static int recurse_code = 0;

    printf("arg: %s\n", s);
    if (recurse_code) {
	/* We were called recursively. Just give up */
	exit(recurse_code);
    }
    recurse_code = code;
    mboxlist_done();
    exit(code);
}

static int do_update = 0;
static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

void *process_loop(void *v)
{
    int r;

    /* process from the ACAP server */
    for (;;) {
	r = acap_process_line(acap_conn, 0);
	if (r != ACAP_OK) break;
	if (do_update) {
	    pthread_mutex_lock(&mut);
	    /* xxx UPDATECONTEXT here */

	    do_update = 0;
	    pthread_cond_broadcast(&cond);
	    pthread_mutex_unlock(&mut);
	}
    }

    return NULL;
}

void listen_for_kicks()
{
    struct sockaddr_un srvaddr;
    struct sockaddr_un clientaddr;
    char fnamebuf[1024];
    int s, r, len;
    mode_t oldumask;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	syslog(LOG_ERR, "socket: %m");
	fatal("socket", 1);
    }

    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, FNAME_TARGET_SOCK);

    (void) unlink(fnamebuf);
    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, fnamebuf);
    oldumask = umask((mode_t) 0); /* for Linux */
    r = bind(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
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

    len = sizeof(clientaddr);
    for (;;) {
	int c = accept(s, (struct sockaddr *)&clientaddr, &len);
	char buf[64];

	if (c == -1) {
	    syslog(LOG_WARNING, "WARNING: accept: %m");
	    continue;
	}
	
	/* now talk to c */
	if (read(c, &buf, 1) < 0) {
	    syslog(LOG_ERR, "can't read from IPC socket?");
	}
	
	pthread_mutex_lock(&mut);
	/* c wants an update! */
	do_update = 1;
	while (do_update) {
	    /* xxx timedwait? */
	    pthread_cond_wait(&cond, &mut);
	}
	pthread_mutex_unlock(&mut);

	if (write(c, "ok", 2) < 0) {
	    syslog(LOG_WARNING, "can't write to IPC socket?");
	}
	close(c);
    }
}

void handler(int sig)
{
    fatal("received signal", 0);
}

int main(int argc, char *argv[], char *envp[])
{
    pthread_t acap_thread;

    config_init("target");

    if (geteuid() == 0) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    acap_init();

    if (argc != 2) {
	/* should be moved into config file ! */
	printf("please give me an ACAP server as an argument.\n");
	fatal("no ACAP servers specified", EC_USAGE);
    }
    
    mboxlist_init(0);

    signal(SIGTERM, &handler);
    signal(SIGINT, &handler);
    signal(SIGPIPE, SIG_IGN);

    connect_acap(argv[1]);

    synchronize_mboxlist();

    mboxlist_open(NULL);

    if (pthread_create(&acap_thread, NULL, process_loop, NULL) < 0) {
	perror("pthread_create");
	mboxlist_close();	
	mboxlist_done();
	return 2;
    }

    /* we now look for processes asking us to issue an UPDATECONTEXT,
       presumably because they are looking for a mailbox that doesn't exist */
    listen_for_kicks();

    return 0;
}
