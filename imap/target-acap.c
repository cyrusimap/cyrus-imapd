/* target-acap.c -- aggregator mailbox database manager
 *                  communicates with ACAP server to learn state of world
 * Larry Greenfield
 * 
 * Copyright (c) 1999-2000 Carnegie Mellon University.  All rights reserved.
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
 *
 * $Id: target-acap.c,v 1.25 2000/12/26 03:31:04 leg Exp $
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

static int debugmode = 0;

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

    strlcpy(data->name, acap_entry_getname(e), MAX_MAILBOX_NAME);
    data->uidvalidity = getintattr(e, "mailbox.uidvalidity");

    v = acap_entry_getattr(e, "mailbox.status");
    data->status = mboxdata_convert_status(v);

    strlcpy(data->post, getstrattr(e, "mailbox.post"), sizeof(data->post));
    strlcpy(data->url, getstrattr(e, "mailbox.url"), sizeof(data->url));
    data->haschildren = getintattr(e, "mailbox.haschildren");
    data->acl = getstrattr(e, "mailbox.acl");

    data->answered = getintattr(e, "mailbox.answered");
    data->flagged = getintattr(e, "mailbox.flagged");
    data->deleted = getintattr(e, "mailbox.deleted");
    data->total = getintattr(e, "mailbox.total");

    return ACAP_OK;
}

int connect_acap(const char *server)
{
    const char *user, *authprog;
    char acapurl[1024];
    int r;
    sasl_callback_t *cb;
    static int firsttime = 1;

    user = config_getstring("acap_username", NULL);
    if (user == NULL) {
        syslog(LOG_ERR, "unable to find option acap_username");
	fatal("couldn't connect to acap server", EC_UNAVAILABLE);
    }

    if (firsttime) {
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
	    fatal("couldn't connect to acap server", EC_UNAVAILABLE);
	}

	firsttime = 0;
    }

 loop:
    snprintf(acapurl, sizeof(acapurl), "acap://%s@%s/", user, server);
    r = ACAP_NO_CONNECTION;

    r = acap_conn_connect(acapurl, NULL, &acap_conn);
    if (r != ACAP_OK) {
	int t = config_getint("acap_retry_timeout", 60);
	
	acap_conn_close(acap_conn);
        syslog(LOG_WARNING, "couldn't connect to ACAP server: %s;"
	                    " will retry in %d sec",
	       error_message(r), t);
	sleep(t);
	goto loop;
    }
    return r;
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
    if (!debugmode) {
	r = mboxlist_insertremote(mailbox, MBTYPE_REMOTE, server, d.acl, NULL);
	if (r) {
	    syslog(LOG_ERR, "couldn't insert %s into mailbox list: %s",
		   d.name, error_message(r));
	}
    }

    free(mailbox);
    free(server);
}

void myacap_removefrom(acap_entry_t *entry,
		       unsigned position,
		       void *rock)
{
    char *ename = acap_entry_getname(entry);
    char name[MAX_MAILBOX_NAME];
    int r;

    if (!ename || !ename[0]) return; /* null entry */

    /* need to reencode UTF-8 name into a UTF-7 IMAP name */
    r = acapmbox_decode_entry(ename, name);
    if (r) {
	syslog(LOG_ERR, "invalid entry name '%s': %s", ename,
	       error_message(r));
    }

    syslog(LOG_DEBUG, "deleting mailbox %s", name);
    if (!debugmode) {
	r = mboxlist_deletemailbox(name, 1, "", NULL, 0);
	if (r) {
	    syslog(LOG_ERR, "couldn't delete %s from mailbox list: %s",
		   name, error_message(r));
	}
    }
}

void myacap_change(acap_entry_t *entry,
		   unsigned oldpos, unsigned newpos,
		   void *rock)
{
    /* ACL might've changed, but we can treat this just like an ADDTO.
       the major problem here is that, if the ACAP server is serving as
       a master update server, we'll be getting a lot of these and they
       don't convey any information. */
    myacap_addto(entry, newpos, rock);
}

void myacap_modtime(char *modtime, void *rock)
{
    syslog(LOG_NOTICE, "synchronized new mailboxes file to '%s'", modtime);
}

static int mbox_comp(const void *v1, const void *v2)
{
    return strcmp((const char *)v1, (const char *)v2);
}

static void mbox_dump(const void *v)
{
    printf("%s ", (const char *) v);
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

    if (debugmode) {
	printf("considering %s ", name ? name : "<entry?>");
    }

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
	if (debugmode) printf("have ");
	sdelete(s, mailbox);
	free(v);
	r = 0;
    } else { /* we don't have it, add it */
	if (debugmode) printf("inserting ");
	if (!debugmode) {
	    r = mboxlist_insertremote(mailbox, MBTYPE_REMOTE, server, 
				      acl->data, NULL);
	}
    }
    if (debugmode > 3) {
	printf("now: ");
	sforeach(s, &mbox_dump);
    }
    if (debugmode) {
	printf("\n");
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
    if (debugmode) {
	printf("deleting %s\n", name);
    } else {
	r = mboxlist_deletemailbox(name, 1, "", NULL, 0);
    }
    if (r) {
	syslog(LOG_ERR, "error deleting '%s': %s", name, error_message(r));
    }
}

static struct acap_search_callback myacap_search_cb = {
    &myacap_entry, &myacap_modtime
};

static struct acap_requested myacap_request = {
    1, { {"mailbox.*", 0x0} }
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
int synchronize_mboxlist(void)
{
    acap_cmd_t *cmd;
    int r;
    skiplist *mailboxes = skiplist_new(10, 0.5, &mbox_comp);
    char s[30];

    if (!mailboxes) {
	syslog(LOG_ERR, "skiplist_new failed");
	fatal("skiplist_new failed", EC_TEMPFAIL);
    }

    syslog(LOG_NOTICE, "starting mailbox synchronization");

    strcpy(s, "*");
    r = mboxlist_findall(s, 1, "", NULL, &mboxadd, mailboxes);
    if (r) {
	skiplist_free(mailboxes);
	return r;
    }

    num = 0;			/* reset mailbox count */
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
	goto ret;
    }
	
    r = acap_process_on_command(acap_conn, cmd, NULL);
    if (r != ACAP_OK) {
	syslog(LOG_ERR, "acap_process_on_command() failed: %s\n", 
	       error_message(r));
	goto ret;
    }

    /* anything left over has been deleted */
    sforeach(mailboxes, &mboxdel);

    syslog(LOG_NOTICE, "done synchronizing mailbox database: %d entries", num);
    r = 0;

 ret:
    skiplist_freeeach(mailboxes, (void (*)(const void *))&free);
    skiplist_free(mailboxes);

    return r;
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
    int s, r;
    socklen_t len;
    mode_t oldumask;
    int acapsock = acap_conn_get_sock(acap_conn);
    fd_set read_set, rset;
    int nfds;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
	syslog(LOG_ERR, "socket: %m");
	fatal("socket failed", EC_OSERR);
    }

    strcpy(fnamebuf, config_dir);
    strcat(fnamebuf, FNAME_TARGET_SOCK);

    (void) unlink(fnamebuf);
    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, fnamebuf);
    len = strlen(srvaddr.sun_path) + sizeof(srvaddr.sun_family) + 1;
    oldumask = umask((mode_t) 0); /* for Linux */
    r = bind(s, (struct sockaddr *)&srvaddr, len);
    umask(oldumask); /* for Linux */
    chmod(fnamebuf, 0777); /* for DUX */
    if (r == -1) {
	syslog(LOG_ERR, "bind: %s: %m", fnamebuf);
	fatal("bind failed", EC_OSERR);
    }
    r = listen(s, 10);
    if (r == -1) {
	syslog(LOG_ERR, "listen: %m");
	fatal("listen failed", EC_OSERR);
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
	if (r == ACAP_NO_CONNECTION) break;

	/* check for the next input */
	rset = read_set;
	n = select(nfds, &rset, NULL, NULL, NULL);
	if (n < 0 && errno == EAGAIN) continue;
	if (n < 0 && errno == EINTR) continue;
	if (n == -1) {
	    /* uh oh */
	    syslog(LOG_ERR, "select(): %m");
	    break;
	}

	/* if (FD_ISSET(acap_conn, &rfds)) 
	       when we loop we'll take care of it 
	 */

	if (FD_ISSET(s, &rset)) {
	    acap_cmd_t *cmd;

	    len = sizeof(clientaddr);
	    c = accept(s, (struct sockaddr *)&clientaddr, &len);
	    if (c == -1) {
		syslog(LOG_WARNING, "accept(): %m");
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

    close(s);
}

void handler(int sig)
{
    fatal("received signal", EC_TEMPFAIL);
}

int main(int argc, char *argv[], char *envp[])
{
    const char *server;
    int opt;
    int r;

    while ((opt = getopt(argc, argv, "d")) != EOF) {
	switch (opt) {
	case 'd': /* don't fork. debugging mode */
	    debugmode++;
	    break;
	default:
	    fprintf(stderr, "invalid argument\n");
	    exit(EC_USAGE);
	    break;
	}
    }


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

    mboxlist_open(NULL);

    r = connect_acap(server);
    if (!r) r = synchronize_mboxlist();

    if (r && debugmode) {
	fatal("can't download list of mailboxes\n", EC_UNAVAILABLE);
    }
    while (r) {
	acap_conn_close(acap_conn);
	
	r = connect_acap(server);
	if (!r) r = synchronize_mboxlist();
    }

    /* we fork to return immediately */
    if (!debugmode) {
	pid_t p = fork();
	
	if (p == -1) {
	    fatal("forked failed", EC_OSERR);
	}
	if (p) {		/* parent */
	    exit(0);
	}
    }

    for (;;) {
	/* we now look for processes asking us to issue an UPDATECONTEXT,
	   presumably because they are looking for a mailbox that 
	   doesn't exist */
	listen_for_kicks();
    
	/* if this returns, we have a problem.  we should probably try
	   to reestablish the connection with the ACAP server and
	   resynchronize */
	acap_conn_close(acap_conn);

	r = connect_acap(server);
	if (!r) r = synchronize_mboxlist();
    }

    mboxlist_close();

    return 1;
}
