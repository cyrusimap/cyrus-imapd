/* 
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
 */

/* $Id: idled.c,v 1.14 2003/02/13 20:15:24 rjs3 Exp $ */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <signal.h>
#include <fcntl.h>

#include "idled.h"
#include "imapconf.h"
#include "mboxlist.h"
#include "xmalloc.h"
#include "hash.h"
#include "exitcodes.h"

extern int optind;
extern char *optarg;

static int verbose = 0;
static int debugmode = 0;
static time_t idle_timeout;

struct ientry {
    pid_t pid;
    time_t itime;
    struct ientry *next;
};
static struct hash_table itable;
static struct ientry *ifreelist;
static int itable_inc = 100;
void idle_done(char *mboxname, pid_t pid);

void fatal(const char *msg, int err)
{
    if (debugmode) fprintf(stderr, "dying with %s %d\n",msg,err);
    syslog(LOG_CRIT, "%s", msg);
    syslog(LOG_NOTICE, "exiting");
    exit(err);
}

static int mbox_count_p(void *rockp,
			const char *key, int keylen,
			const char *data, int datalen)
{
    return 1;
}

static int mbox_count_cb(void *rockp,
			 const char *key, int keylen,
			 const char *data, int datalen)
{
    int *ip = (int *) rockp;
    (*ip)++;

    return 0;
}

/* return a new 'ientry', either from the freelist or by malloc'ing it */
static struct ientry *get_ientry(void)
{
    struct ientry *t;

    if (!ifreelist) {
	/* create child_table_inc more and add them to the freelist */
	struct ientry *n;
	int i;

	n = xmalloc(itable_inc * sizeof(struct ientry));
	ifreelist = n;
	for (i = 0; i < itable_inc - 1; i++) {
	    n[i].next = n + (i + 1);
	}
	/* i == child_table_inc - 1, last item in block */
	n[i].next = NULL;
    }

    t = ifreelist;
    ifreelist = ifreelist->next;

    return t;
}

/* remove pid from list of those idling on mboxname */
void idle_done(char *mboxname, pid_t pid)
{
    struct ientry *t, *p = NULL;

    t = (struct ientry *) hash_lookup(mboxname, &itable);
    while (t && t->pid != pid) {
	p = t;
	t = t->next;
    }
    if (t) {
	if (!p) {
	    /* first pid in the linked list */

	    p = t->next; /* remove node */

	    /* we just removed the data that the hash entry
	       was pointing to, so insert the new data */
	    hash_insert(mboxname, p, &itable);
	}
	else {
	    /* not the first pid in the linked list */

	    p->next = t->next; /* remove node */
	}
	t->next = ifreelist; /* add to freelist */
	ifreelist = t;
    }
}

void process_msg(idle_data_t *idledata)
{
    struct ientry *t, *n;

    switch (idledata->msg) {
    case IDLE_INIT:
	if (verbose || debugmode)
	    syslog(LOG_DEBUG, "imapd[%ld]: IDLE_INIT '%s'\n",
		   idledata->pid, idledata->mboxname);

	/* add pid to list of those idling on mboxname */
	t = (struct ientry *) hash_lookup(idledata->mboxname, &itable);
	n = get_ientry();
	n->pid = idledata->pid;
	n->itime = time(NULL);
	n->next = t;
	hash_insert(idledata->mboxname, n, &itable);
	break;
	
    case IDLE_NOTIFY:
	if (verbose || debugmode)
	    syslog(LOG_DEBUG, "IDLE_NOTIFY '%s'\n", idledata->mboxname);

	/* send a message to all pids idling on mboxname */
	t = (struct ientry *) hash_lookup(idledata->mboxname, &itable);
	while (t) {
	    if ((t->itime + idle_timeout) < time(NULL)) {
		/* This process has been idling for longer than the timeout
		 * period, so it probably died.  Remove it from the list.
		 */
		if (verbose || debugmode)
		    syslog(LOG_DEBUG, "    TIMEOUT %d\n", t->pid);

		n = t;
		t = t->next;
		idle_done(idledata->mboxname, n->pid);
	    }
	    else { /* signal process to update */
		if (verbose || debugmode)
		    syslog(LOG_DEBUG, "    SIGUSR1 %d\n", t->pid);

		kill(t->pid, SIGUSR1);
		t = t->next;
	    }
	}
	break;
	
    case IDLE_DONE:
	if (verbose || debugmode)
	    syslog(LOG_DEBUG, "imapd[%ld]: IDLE_DONE '%s'\n",
		   idledata->pid, idledata->mboxname);

	/* remove pid from list of those idling on mboxname */
	idle_done(idledata->mboxname, idledata->pid);
	break;
	
    default:
	syslog(LOG_ERR, "unrecognized message: %lx", idledata->msg);
	break;
    }
}

void idle_alert(char *key, void *data, void *rock)
{
    struct ientry *t = (struct ientry *) data;

    while (t) {
	/* signal process to check ALERTs */
	if (verbose || debugmode)
	    syslog(LOG_DEBUG, "    SIGUSR2 %d\n", t->pid);
	kill(t->pid, SIGUSR2);

	t = t->next;
    }
}

int main(int argc, char **argv)
{
    char shutdownfilename[1024];
    char *p = NULL;
    int opt;
    int nmbox = 0;
    int s, len;
    struct sockaddr_un local;
    idle_data_t idledata;
    struct sockaddr_un from;
    socklen_t fromlen;
    mode_t oldumask;
    fd_set read_set, rset;
    int nfds;
    struct timeval timeout;
    pid_t pid;
    int fd;
    char *alt_config = NULL;
    const char *idle_sock;

    p = getenv("CYRUS_VERBOSE");
    if (p) verbose = atoi(p) + 1;

    while ((opt = getopt(argc, argv, "C:d")) != EOF) {
	switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
	case 'd': /* don't fork. debugging mode */
	    debugmode = 1;
	    break;
	default:
	    fprintf(stderr, "invalid argument\n");
	    exit(EC_USAGE);
	    break;
	}
    }

    if (debugmode) {
	openlog("idled", LOG_PID, LOG_LOCAL6);
    }

    config_init(alt_config, "idled");

    /* get name of shutdown file */
    snprintf(shutdownfilename, sizeof(shutdownfilename), "%s/msg/shutdown",
	     config_dir);

    /* Set inactivity timer (convert from minutes to seconds) */
    idle_timeout = config_getint("timeout", 30);
    if (idle_timeout < 30) idle_timeout = 30;
    idle_timeout *= 60;

    /* count the number of mailboxes */
    mboxlist_init(0);
    mboxlist_open(NULL);
    CONFIG_DB_MBOX->foreach(mbdb, "", 0, &mbox_count_p, &mbox_count_cb,
			    &nmbox, NULL);
    mboxlist_close();
    mboxlist_done();

    /* create idle table */
    construct_hash_table(&itable, nmbox, 1);
    ifreelist = NULL;

    /* create socket we are going to use for listening */
    if ((s = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1) {
	perror("socket");
	exit(1);
    }

    /* bind it to a local file */
    local.sun_family = AF_UNIX;
    idle_sock = config_getstring("idlesocket", NULL);
    if (idle_sock) {	
	strcpy(local.sun_path, idle_sock);
    }
    else {
	strcpy(local.sun_path, config_dir);
	strcat(local.sun_path, FNAME_IDLE_SOCK);
    }
    unlink(local.sun_path);
    len = sizeof(local.sun_family) + strlen(local.sun_path) + 1;

    oldumask = umask((mode_t) 0); /* for Linux */

    if (bind(s, (struct sockaddr *)&local, len) == -1) {
	perror("bind");
	exit(1);
    }
    umask(oldumask); /* for Linux */
    chmod(local.sun_path, 0777); /* for DUX */

    /* fork unless we were given the -d option */
    if (debugmode == 0) {
	
	pid = fork();
	
	if (pid == -1) {
	    perror("fork");
	    exit(1);
	}
	
	if (pid != 0) { /* parent */
	    exit(0);
	}
    }
    /* child */

    /* get ready for select() */
    FD_ZERO(&read_set);
    FD_SET(s, &read_set);
    nfds = s + 1;

    for (;;) {
	int n;

	/* check for shutdown file */
	if ((fd = open(shutdownfilename, O_RDONLY, 0)) != -1) {
	    /* signal all processes to shutdown */
	    if (verbose || debugmode)
		syslog(LOG_DEBUG, "IDLE_ALERT\n");

	    hash_enumerate(&itable, idle_alert, NULL);
	}

	/* timeout for select is 1 second */
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	/* check for the next input */
	rset = read_set;
	n = select(nfds, &rset, NULL, NULL, &timeout);
	if (n < 0 && errno == EAGAIN) continue;
	if (n < 0 && errno == EINTR) continue;
	if (n == -1) {
	    /* uh oh */
	    syslog(LOG_ERR, "select(): %m");
	    close(s);
	    fatal("select error",-1);
	}

	/* read on unix socket */
	if (FD_ISSET(s, &rset)) {
	    fromlen = sizeof(from);
	    n = recvfrom(s, (void*) &idledata, sizeof(idle_data_t), 0,
			 (struct sockaddr *) &from, &fromlen);

	    if (n > 0) {
		if (n <= IDLEDATA_BASE_SIZE ||
		    idledata.mboxname[n - 1 - IDLEDATA_BASE_SIZE] != '\0')
		    syslog(LOG_ERR, "Invalid message received, size=%d\n", n);
		else 
		    process_msg(&idledata);
	    }
	} else {
	    /* log some sort of error */	    
	}

    }

    /* never gets here */      
    exit(1);
}
