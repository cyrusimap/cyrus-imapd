/* sendmail-map.c -- maintain a map of users -> machines for Sendmail
 * Larry Greenfield
 * 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 * $Id: sendmail-map.c,v 1.6 2003/04/01 19:13:54 rjs3 Exp $
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
#include <fcntl.h>

#include <sasl/sasl.h>
#include <acap.h>
#include <db.h>

#include "imapconf.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "xmalloc.h"
#include "imapurl.h"
#include "acapmbox.h"
#include "lock.h"

static int debugmode = 0;
static int lockfd = -1;
static DB *db;

#define MAPFILE "/etc/mail/cyrusmap.db"

void addmap(char *user, char *server)
{
    static DBT k, v;
    int r;

    k.data = user;
    k.size = strlen(k.data);
    v.data = server;
    v.size = strlen(v.data);
    r = db->put(db, NULL, &k, &v, 0);
    if (r) {
	syslog(LOG_ERR, "failed to insert %s -> %s into map: %s",
	       k.data, v.data, db_strerror(r));
    }
}

void delmap(char *user)
{
    static DBT k;
    int r;

    k.data = user;
    k.size = strlen(k.data);
    r = db->del(db, NULL, &k, 0);
    if (r) {
	syslog(LOG_ERR, "failed to delete %s from map: %s",
	       user, db_strerror(r));
    }
}

extern sasl_callback_t *mysasl_callbacks(const char *username,
					 const char *authname,
					 const char *realm,
					 const char *password);
void free_callbacks(sasl_callback_t *in);

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

int connect_acap(const char *server, const char *user)
{
    const char *authprog;
    char acapurl[1024];
    int r;
    sasl_callback_t *cb;

    if (!user) {
	user = config_getstring("acap_username", NULL);
    }
    if (user == NULL) {
	syslog(LOG_ERR, "unable to find option acap_username");
	fatal("couldn't connect to acap server", EC_UNAVAILABLE);
    }

    authprog = config_getstring("acap_getauth", NULL);
    if (authprog) {
	system(authprog);
    }

    /* probably should setup callbacks here if configured to! */
    r = sasl_client_init(NULL);
    if (r != SASL_OK) {
	syslog(LOG_ERR, "sasl_client_init() failed: %s",
	       sasl_errstring(r, NULL, NULL));
	fatal("couldn't connect to acap server", EC_UNAVAILABLE);
    }

    snprintf(acapurl, sizeof(acapurl), "acap://%s@%s/", user, server);
    r = ACAP_NO_CONNECTION;

    cb = mysasl_callbacks(user,
			  config_getstring("acap_authname", user),
			  config_getstring("acap_realm", NULL),
			  config_getstring("acap_password", NULL));
    r = acap_conn_connect(acapurl, cb, &acap_conn);
    free_callbacks(cb);
    if (r != ACAP_OK) {
	syslog(LOG_ERR, "couldn't connect to ACAP server: %s",
	       error_message(r));
    }
    return r;
}

void myacap_addto(acap_entry_t *entry,
		  unsigned position,
		  void *rock)
{
    char *name = acap_entry_getname(entry);
    acap_value_t *url = acap_entry_getattr(entry, "mailbox.url");
    char *server, *mailbox;
    int r;

    if (!name || !name[0] || !url) return; /* null entry */

    server = (char *) xmalloc(sizeof(char) * url->len);
    mailbox = (char *) xmalloc(sizeof(char) * 2 * url->len);
    imapurl_fromURL(server, mailbox, url->data);
    if (strncmp(mailbox, "user.", 5) || strchr(mailbox + 5, '.')) {
	syslog(LOG_NOTICE, "%s: not a user mailbox?!?", mailbox);
	goto ret;
    }

    /* lock map */
    r = lock_reopen(lockfd, MAPFILE, NULL, NULL);
    if (r) {
	fatal("lock_reopen() failed", EC_SOFTWARE);
    }

    r = db_create(&db, NULL, 0);
    if (r) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", MAPFILE, db_strerror(r));
	fatal("can't recreate database handle", EC_SOFTWARE);
    }

    r = db->open(db, MAPFILE, NULL, DB_HASH, 0, 0644);
    if (r) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", MAPFILE, db_strerror(r));
	fatal("can't reopen database", EC_SOFTWARE);
    }

    /* add to map */
    syslog(LOG_DEBUG, "adding %s -> %s", mailbox + 5, server);
    addmap(mailbox + 5, server);

    r = db->close(db, 0);
    if (r) {
	syslog(LOG_ERR, "DBERROR: closing %s: %s", MAPFILE, db_strerror(r));
    }
	
    /* unlock map */
    r = lock_unlock(lockfd);
    if (r) {
	fatal("lock_unlock() failed?!?", EC_SOFTWARE);
    }

 ret:
    free(mailbox);
    free(server);
}

void myacap_removefrom(acap_entry_t *entry,
		       unsigned position,
		       void *rock)
{
    char *ename = acap_entry_getname(entry);
    char mailbox[MAX_MAILBOX_NAME+1];
    int r;

    if (!ename || !ename[0]) return; /* null entry */

    /* need to reencode UTF-8 name into a UTF-7 IMAP name */
    r = acapmbox_decode_entry(ename, mailbox);
    if (r) {
	syslog(LOG_ERR, "invalid entry name '%s': %s", ename,
	       error_message(r));
    }

    if (strncmp(mailbox, "user.", 5) || strchr(mailbox + 5, '.')) {
	syslog(LOG_NOTICE, "%s: not a user mailbox?!?", mailbox);
	return;
    }

    /* lock map */
    r = lock_reopen(lockfd, MAPFILE, NULL, NULL);
    if (r) {
	fatal("lock_reopen() failed", EC_SOFTWARE);
    }

    r = db_create(&db, NULL, 0);
    if (r) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", MAPFILE, db_strerror(r));
	fatal("can't recreate database handle", EC_SOFTWARE);
    }

    r = db->open(db, MAPFILE, NULL, DB_HASH, 0, 0644);
    if (r) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", MAPFILE, db_strerror(r));
	fatal("can't reopen database", EC_SOFTWARE);
    }

    /* do deletion */
    syslog(LOG_DEBUG, "deleting mailbox %s", mailbox);
    delmap(mailbox + 5);

    r = db->close(db, 0);
    if (r) {
	syslog(LOG_ERR, "DBERROR: closing %s: %s", MAPFILE, db_strerror(r));
    }
	
    /* unlock map */
    r = lock_unlock(lockfd);
    if (r) {
	fatal("lock_unlock() failed?!?", EC_SOFTWARE);
    }
}

void myacap_change(acap_entry_t *entry,
		   unsigned oldpos, unsigned newpos,
		   void *rock)
{
    /* noop */
}

void myacap_modtime(char *modtime, void *rock)
{
    syslog(LOG_NOTICE, "synchronized map to '%s'", modtime);
}

static int num = 0;

void myacap_entry(acap_entry_t *entry, void *rock)
{
    /* name is a UTF-8 encoded representation of the mailbox;
       technically we should reencode it into modified UTF-7. however,
       right now both my client and server will violate this. */
    char *name = acap_entry_getname(entry);
    acap_value_t *url = acap_entry_getattr(entry, "mailbox.url");
    char *server, *mailbox;

    if (debugmode) {
	printf("considering %s\n", name ? name : "<entry?>");
    }

    if (!name || !url) {
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
    if (strncmp(mailbox, "user.", 5) || strchr(mailbox + 5, '.')) {
	syslog(LOG_NOTICE, "%s: not a user mailbox?!?", mailbox);
	goto ret;
    }

    addmap(mailbox + 5, server);

 ret:
    free(server);
    free(mailbox);
}

static struct acap_search_callback myacap_search_cb = {
    &myacap_entry, &myacap_modtime
};

static struct acap_requested myacap_request = {
    1, { {"mailbox.url", 0x0} }
};

static struct acap_context_callback myacap_context_cb = {
    &myacap_addto,
    &myacap_removefrom,
    &myacap_change,
    &myacap_modtime /* reuse modtime cb */
};

/* grabs the lock,
   grabs the current list of mailboxes from the ACAP server,
   rewrites the map,
   releases the lock
   
   it also initializes the callbacks for the context. */
int synchronize_map(void)
{
    acap_cmd_t *cmd;
    int r;
    int flags;
    
    /* open database */
    r = db_create(&db, NULL, 0);
    if (r) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", MAPFILE, db_strerror(r));
	return IMAP_IOERROR;
    }

    flags = DB_CREATE | DB_TRUNCATE;
    r = db->open(db, MAPFILE, NULL, DB_HASH, flags, 0644);
    if (r) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", MAPFILE, db_strerror(r));
	return IMAP_IOERROR;
    }

    /* rewrite map */
    syslog(LOG_NOTICE, "starting map synchronization");

    r = acap_search_dataset(acap_conn, global_dataset "/user/", 
		      "EQUAL \"mailbox.status\" \"i;octet\" \"committed\"", 1,
			    &myacap_request, NULL,
			    NULL,
			    &myacap_search_cb,
			    &mycontext, &myacap_context_cb, 
			    NULL, &cmd);
    if (r != ACAP_OK) {
	syslog(LOG_ERR, "acap_search_dataset() failed: %s\n", 
	       error_message(r));
	return r;
    }

    r = acap_process_on_command(acap_conn, cmd, NULL);
    if (r != ACAP_OK) {
	syslog(LOG_ERR, "acap_process_on_command() failed: %s\n", 
	       error_message(r));
	return r;
    }

    syslog(LOG_NOTICE, "done synchronizing map: %d entries", num);

    r = db->close(db, 0);
    if (r) {
	syslog(LOG_ERR, "DBERROR: closing %s: %s", MAPFILE, db_strerror(r));
	return IMAP_IOERROR;
    }
	
    return 0;
}

void fatal(const char *s, int code)
{
    static int recurse_code = 0;

    fprintf(stderr, "sendmail-map: %s\n", s);
    if (recurse_code) {
	/* We were called recursively. Just give up */
	exit(recurse_code);
    }
    recurse_code = code;
    exit(code);
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
    int fd;
    int forkmode = 0;
    char *user = NULL;
    char *alt_config = NULL;

    while ((opt = getopt(argc, argv, "C:dfu:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;
	case 'd': /* debugging mode */
	    debugmode++;
	    break;
	case 'f': /* fork mode */
	    forkmode++;
	    break;
	case 'u':
	{
	    char *at;
	    
	    user = optarg;
	    at = strchr(user, '@');
	    if (at) *at = '\0';
	    break;
	}
	default:
	    fprintf(stderr, "invalid argument\n");
	    exit(EC_USAGE);
	    break;
	}
    }


    config_init(alt_config, "sendmail-map");

    acap_init();

    server = config_getstring("acap_server", NULL);
    if (!server) fatal("no ACAP servers specified", EC_USAGE);
    
    signal(SIGTERM, &handler);
    signal(SIGINT, &handler);
    signal(SIGPIPE, SIG_IGN);

    /* grab the lock */
    fd = open(MAPFILE, O_RDWR | O_CREAT, 0644);
    r = lock_reopen(fd, MAPFILE, NULL, NULL);
    if (r) return r;

    lockfd = fd;

    r = connect_acap(server, user);
    if (!r) {
	r = synchronize_map();
    }

    if (r) {
	if (debugmode) {
	    fatal("can't download list of mailboxes\n", EC_UNAVAILABLE);
	} else {
	    acap_conn_close(acap_conn);
	    sleep(config_getint("acap_retry_timeout", 60));
	    execv(argv[0], argv);
	}
    }

    /* release lock */
    r = lock_unlock(lockfd);
    if (r) {
	fatal("lock_unlock() failed?!?", EC_SOFTWARE);
    }

    /* we fork to return immediately */
    if (!debugmode && forkmode) {
	pid_t p = fork();
	
	if (p == -1) {
	    fatal("forked failed", EC_OSERR);
	}
	if (p) {		/* parent */
	    exit(0);
	}
    }

    for (;;) {
	while (r == ACAP_OK) {
	    /* listen for updates from the acap server */
	    r = acap_process_line(acap_conn, 0);
	}

	/* if this returns, we have a problem.  we should probably try
	   to reestablish the connection with the ACAP server and
	   resynchronize */
	acap_conn_close(acap_conn);
	sleep(config_getint("acap_retry_timeout", 60));
	execv(argv[0], argv);
    }

    return 1;
}
