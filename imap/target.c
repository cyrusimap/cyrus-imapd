/* target.c -- proxy mailbox database manager
               callback target
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
 * $Id: target.c,v 1.2 2000/01/28 22:09:52 leg Exp $
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <syslog.h>
#include <sasl.h>
#include <assert.h>

#include "acl.h"
#include "config.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "xmalloc.h"
#include "prot.h"

#include "gun.h"

#define RETRY_TIMEOUT 60
#define POLL_TIMEOUT 5

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

struct be {
    char *hostname;
    sasl_conn_t *saslconn;
    struct protstream *in; /* from the be server */
    struct protstream *out; /* to the be server */
    int sock;
    enum {
	UP,
	DOWN
    } be_status;
    time_t lastcontact;

    struct mbox_txn *curtxn;

    struct be *next;
};

struct be_mblist {
    int num;
    int n;
    struct mbox_entry **ents;
    struct be *be;
    int *saw;
};

static struct be *head;
static time_t now;

void be_add(char *host)
{
    struct be *ptr = xmalloc(sizeof(struct be));

    ptr->hostname = xstrdup(host);
    ptr->saslconn = NULL;
    ptr->sock = 0;
    ptr->in = ptr->out = NULL;
    ptr->be_status = DOWN;
    ptr->lastcontact = 0;
    ptr->curtxn = NULL;

    ptr->next = head;
    head = ptr;
}

foreach_res process_mbox(void *rock, struct mbox_entry **mboxent)
{
    struct be_mblist *mblist = (struct be_mblist *) rock;
    struct mbox_entry *ret;
    int cmp, sz;

    for (;;) {
	if (mblist->n == mblist->num) {
	    cmp = 1;
	} else {
	    cmp = strcmp((*mboxent)->name, mblist->ents[mblist->n]->name);
	}

	if (cmp < 0) {
	    mblist->n++;
	    /* keep going */
	} else if (cmp == 0) {
	    mblist->saw[mblist->n] = 1;

	    if (strcmp((*mboxent)->partition, mblist->be->hostname)) {
		/* conflict!!! */
		syslog(LOG_ERR, "conflict detected: %s", (*mboxent)->name);
		sz = sizeof(struct mbox_entry) + strlen((*mboxent)->acls);
		ret = (struct mbox_entry *) xmalloc(sz);
		memcpy(ret, *mboxent, sz);

		ret->mbtype |= MBTYPE_CONFLICT;

		*mboxent = ret;
		return MB_UPDATE;
	    } else {
		struct mbox_entry *me = mblist->ents[mblist->n];

		/* we have a match & it's the right server; we want to 
		   update */
		sz = sizeof(struct mbox_entry) + strlen(me->acls);
		ret = (struct mbox_entry *) xmalloc(sz);
		memcpy(ret, me, sz);
		
		ret->mbtype |= MBTYPE_REMOTE;
		strcpy(ret->partition, mblist->be->hostname);
		
		*mboxent = ret;
		return MB_UPDATE;
	    }
	    break;
	} else /* cmp > 0 */ {
	    /* it's in our list, but it's not in what we just got */
	    
	    /* is it on the server we just connected to? */
	    if (!strcmp((*mboxent)->partition, mblist->be->hostname)) {
		/* dammit, got deleted behind my back */
		*mboxent = NULL;
		return MB_REMOVE;
	    } else {
		/* ok, this is some other server's mailbox */
		*mboxent = NULL;
		return MB_NEXT;
	    }
	    break;
	}
    }
}

void be_connect(struct be *ptr)
{
    struct sockaddr_in sin;
    struct hostent *hp;
    int cr; 			/* communication result */
    int r;
    struct mbox_entry **mboxent;
    int num = 0, n = 0;
    struct be_mblist *rock;
    int ch;
    
    /* ptr is currently DOWN.  let's try to make it UP */
    assert(ptr->be_status == DOWN);

    fprintf(stderr, "attempting connection to '%s'...\n", ptr->hostname);

    if ((hp = gethostbyname(ptr->hostname)) == NULL) {
	syslog(LOG_ERR, "gethostbyname(): unknown host: %s\n", ptr->hostname);
	return;
    }

    if ((ptr->sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
	/* can't get a socket */
	syslog(LOG_ERR, "socket() failed: %m");
	return;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);
    bcopy(hp->h_addr, &sin.sin_addr, hp->h_length);
    if (connect(ptr->sock, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
	syslog(LOG_ERR, "can't connect to %s: %m", ptr->hostname);
	return;
    }

    fprintf(stderr, "connected\n");

    ptr->in = prot_new(ptr->sock, 0);
    ptr->out = prot_new(ptr->sock, 1);
    ptr->saslconn = NULL;
    prot_setflushonread(ptr->in, ptr->out);

    for (;;) {
	int toread, got, sz;
	int r;

	ch = prot_getc(ptr->in);
	if (ch != 'M') {
	    break;
	}

	sz = 0;
	ch = prot_getc(ptr->in);
	while (isdigit(ch)) {
	    sz = 10 * sz + (ch - '0');
	    ch = prot_getc(ptr->in);
	}
	fprintf(stderr, "looking for %d bytes...", sz);
	if (ch != 'M') {
	    break;
	}
	toread = sz;
	if (n == num) {
	    mboxent = xrealloc(mboxent, sizeof(struct mbox_entry *) * 
			       (num += 1000));
	}
	mboxent[n] = (struct mbox_entry *) xmalloc(toread);
	got = 0;
	while (got < toread) {
	    r = prot_read(ptr->in, ((char *) mboxent[n]) + got, toread - got);
	    got += r;
	    if (r == 0) {
		goto out;
	    }
	}
	fprintf(stderr, "got '%s'\n", mboxent[n]->name);
	n++;
    }
  out:
    if (ch != '-') {
	/* protocol failure */
	cr = 1;
    } else {
        cr = 0;
    }
    /* ok, we now have to synchronize our mailboxes file with the information
       we just received */
    if (!cr) {
	rock = (struct be_mblist *) xmalloc(sizeof(struct be_mblist));

	fprintf(stderr, "got %d mailboxes\n", n);

	rock->ents = mboxent;
	rock->num = n;
	rock->saw = (int *) xmalloc(sizeof(int) * num);
	memset(rock->saw, 0, sizeof(int) * num);
	rock->n = 0;
	rock->be = ptr;

	cr = mboxlist_foreach(&process_mbox, (void *) rock, 1);
    }

    /* ok, now we add all the mailboxes that we didn't already have,
       and we free the memory up */
    while (n--) {
	if (!cr && !rock->saw[n]) {
	    /* insert it */
	    cr = mboxlist_insertremote(mboxent[n]->name,
				       mboxent[n]->mbtype,
				       ptr->hostname,
				       mboxent[n]->acls,
				       NULL);
	}
	
	free(mboxent[n]);
    }
    free(mboxent);
    if (rock) {
	free(rock->saw);
	free(rock);
    }

    if (!cr) fprintf(stderr, "about to send\n");
    
    /* done */
    if (!cr) cr = prot_putc('o', ptr->out);
    if (!cr) cr = prot_putc('k', ptr->out);
    if (!cr) cr = prot_flush(ptr->out);

    if (cr) { /* damn it */
	free(mboxent);
	prot_free(ptr->in);
	prot_free(ptr->out);
	close(ptr->sock);
	ptr->lastcontact = now;
        fprintf(stderr, "bad connection\n");
	return;
    }

    fprintf(stderr, "good connection\n");
    ptr->be_status = UP;
}

int do_txn(char *host, struct inmsg *msg, struct mbox_txn **txn)
{
    struct auth_state *authstate;
    struct mbox_txn *mytxn = NULL;
    int r;

    authstate = auth_newstate(msg->userid, NULL);
    switch (msg->mtype) {
    case CREATEMAILBOX:
	printf("got CREATEMAILBOX:\n");
	printf("\t(%s, %s, %d, %s, %d)\n", msg->name, msg->userid,
	       msg->isadmin, msg->u.cmb.partition, 
	       msg->u.cmb.mbtype);
	r = real_mboxlist_createmailbox(msg->name, 
					msg->u.cmb.mbtype | MBTYPE_REMOTE,
					host,
					msg->isadmin,
					msg->userid,
					authstate,
					&mytxn);
	break;
    case DELETEMAILBOX:
	printf("got DELETEMAILBOX:\n");
	printf("\t(%s, %s, %d, %d)\n", msg->name, msg->userid,
	       msg->isadmin, msg->u.dmb.checkacl);
	r = real_mboxlist_deletemailbox(msg->name,
					msg->isadmin,
					msg->userid,
					authstate,
					msg->u.dmb.checkacl,
					&mytxn);
	break;
	
    case RENAMEMAILBOX:
	printf("got RENAMEMAILBOX:\n");
	printf("\t(%s, %s, %d, %s, %s)\n", msg->name, msg->userid,
	       msg->isadmin, msg->u.rmb.newname, 
	       msg->u.rmb.partition);
	r = real_mboxlist_renamemailbox(msg->name,
					msg->u.rmb.newname,
					host,
					msg->isadmin,
					msg->userid,
					authstate,
					&mytxn);
	break;
	
    case SETACL:
	printf("got RENAMEMAILBOX:\n");
	printf("\t(%s, %s, %d, %s, %s)\n", msg->name, msg->userid,
	       msg->isadmin, msg->u.amb.ident, msg->u.amb.rights);
	r = real_mboxlist_setacl(msg->name,
				 msg->u.amb.ident,
				 msg->u.amb.rights,
				 msg->isadmin,
				 msg->userid,
				 authstate,
				 &mytxn);
	break;
	
    default:
	r = IMAP_IOERROR;
	break;
    }

    if (authstate) auth_freestate(authstate);
    *txn = mytxn;

    return r;
}


void be_process(struct be *ptr)
{
    int cr;			/* communication failure */

    assert(ptr->be_status == UP);

    cr = 0;
    if (ptr->curtxn != NULL) {
	/* we have an outstanding transaction; check for commit or abort */
	int ch1, ch2;

	ch1 = prot_getc(ptr->in);
	ch2 = prot_getc(ptr->in);
	if (ch1 == 'g' && ch2 == 'o') {	/* commit */
	    fprintf(stderr, "\tgot go\n");
	    mboxlist_commit(ptr->curtxn);
	    ptr->curtxn = NULL;
	} else if (ch1 == 'a' && ch2 == 'b') { /* abort */
	    fprintf(stderr, "\tgot ab\n");
	    mboxlist_abort(ptr->curtxn);
	    ptr->curtxn = NULL;
	} else {		/* communication failure */
	    fprintf(stderr, "\tcommunication failure\n");
	    cr = 1;
	}
    } else {			/* grab a new transaction */
	struct inmsg inbuf;
	int toread, got, r;
	struct mbox_txn *txn;

	toread = sizeof(struct inmsg);
	got = 0;
	while (!cr && (got < toread)) {
	    r = prot_read(ptr->in, ((char *) &inbuf) + got, toread - got);
	    got += r;
	    if (r == 0) {
		cr = 1; /* damn, problems */
	    }
	}

	if (!cr) {
	    r = do_txn(ptr->hostname, &inbuf, &txn);
	    assert(r || (txn != NULL));
	}

	if (!cr && r) {		/* say NO don't commit */
	    cr = prot_putc('n', ptr->out);
	    if (!cr) r = prot_putc('o', ptr->out);
	    if (!cr) r = prot_flush(ptr->out);
	} else if (!cr) {	/* we are OK for commit */
	    cr = prot_putc('o', ptr->out);
	    if (!cr) r = prot_putc('k', ptr->out);
	    if (!cr) r = prot_flush(ptr->out);
	    if (!cr) ptr->curtxn = txn;
	}
    }

    /* r represents the value from communication with the be server */
    if (cr) {		/* we had a failure */
	if (ptr->curtxn) {
	    mboxlist_abort(ptr->curtxn);
	}
	ptr->be_status = DOWN;
	prot_free(ptr->in);
	prot_free(ptr->out);
	close(ptr->sock);
    } else {
	ptr->lastcontact = now;
    }	
}

void fatal(const char *s, int code)
{
    static int recurse_code = 0;

    printf("arg: %s\n", s);
    if (recurse_code) {
	/* We were called recursively. Just give up */
	proc_cleanup();
	exit(recurse_code);
    }
    recurse_code = code;
    mboxlist_done();
    exit(code);
}

void handler(int sig)
{
    fatal("received signal", 0);
}

int main(int argc, char *argv[], char *envp[])
{
    char name[1024], host[1024], acl[1024];
    int i, n;
    fd_set rfds, efds;
    struct timeval tv;
    struct be *ptr;

    config_init("target");

    if (geteuid() == 0) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    if (argc == 1) {
	printf("please give me a list of backend servers as arguments.\n");
	fatal("no backend servers specified", EC_USAGE);
    }
    
    mboxlist_open();

    signal(SIGTERM, &handler);
    signal(SIGINT, &handler);
    signal(SIGPIPE, SIG_IGN);

    while (argc > 1) {
	/* add argv[argc] to our list */
	argc--;
	be_add(argv[argc]);
    }

    for (;;) {
	now = time(NULL);

	fprintf(stderr, "checking DOWN servers\n");

	/* check on all b.e. servers that we previously thought were DOWN */
	for (ptr = head; ptr != NULL; ptr = ptr->next) {
	    if (ptr->be_status == DOWN && 
		(now >= ptr->lastcontact + RETRY_TIMEOUT)) {
		be_connect(ptr);
	    }
	}
	
	/* check for input from any of the servers */
	n = 0;
	FD_ZERO(&rfds);
	FD_ZERO(&efds);
	for (ptr = head; ptr != NULL; ptr = ptr->next) {
	    if (ptr->be_status == UP) {
		FD_SET(ptr->sock, &rfds);
		FD_SET(ptr->sock, &efds);
		n = MAX(n, ptr->sock);
	    }
	}
	n++;
	tv.tv_sec = POLL_TIMEOUT;
	tv.tv_usec = 0;
	n = select(n, &rfds, NULL, &efds, &tv);

	if (n > 0) {
	    /* process input */
	    for (ptr = head; ptr != NULL; ptr = ptr->next) {
		if (FD_ISSET(ptr->sock, &rfds)) {
		    fprintf(stderr, "input from '%s'\n", ptr->hostname);
		    do {
			be_process(ptr);
		    } while (ptr->in->cnt > 0);
		}

		if (FD_ISSET(ptr->sock, &efds)) {
		    /* uh oh */
		}
	    }
	}
    }

    fatal("all done", 0);
}
