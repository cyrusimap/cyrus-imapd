/* gun.c -- Mailbox database guardian & callback manager
           (shoots at targets)
 * Larry Greenfield
 * SysV IPC implementation
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
 * $Id: gun.c,v 1.2 2000/01/28 22:09:44 leg Exp $
 */

/* we need to support 4 functions in this:
int mboxlist_createmailbox(char *name, int mbtype, char *partition, 
			   int isadmin, char *userid, 
			   struct auth_state *auth_state);
int mboxlist_deletemailbox(char *name, int isadmin, char *userid, 
			   struct auth_state *auth_state, int checkacl);
int mboxlist_renamemailbox(char *oldname, char *newname, char *partition, 
			   int isadmin, char *userid, 
			   struct auth_state *auth_state);
int mboxlist_setacl(char *name, char *identifier, char *rights, int isadmin, 
		    char *userid, struct auth_state *auth_state);
*/

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <syslog.h>
#include <sasl.h>

#include "acl.h"
#include "config.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "xmalloc.h"
#include "prot.h"

#include "gun.h"

#define POLL_TIME 5
#define PORT 2234

int listenfd = 0;

struct cb {
    char *hostname;
    sasl_conn_t *saslconn;
    struct protstream *in;  /* from the proxy */
    struct protstream *out; /* to the proxy */
    int sock;
    struct cb *next;
};

static struct cb *head;

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
    if (sig != SIGALRM) {
        fatal("received signal", 0);
    } else {
        signal(sig, &handler);
    }
}

int init_listen(void)
{
    struct sockaddr_in sin;
    int port, flag;

    listenfd = -1;

    port = htons(PORT);

    memset(&sin, 0L, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = port;
    sin.sin_addr.s_addr = INADDR_ANY;

    flag = 1;
    listenfd = socket(PF_INET, SOCK_STREAM, 0);
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
		   (const char *) &flag, sizeof(flag)) < 0) {
	fatal("can't setsockopt", 1);
    }
    if (bind(listenfd, (struct sockaddr *) &sin, sizeof(struct sockaddr_in))) {
	fatal("can't bind", 1);
    }

    if ((flag = fcntl(listenfd, F_GETFL)) < 0) {
	fatal("can't get socket flags", 1);
    }
    flag |= O_NONBLOCK;
    if (fcntl(listenfd, F_SETFL, flag) < 0) {
	fatal("can't set socket flags", 1);
    }

    if (listen(listenfd, 10) < 0) {
	fatal("listen() failed", 1);
    }

    return 0;
}

foreach_res send_mbox_to_proxy(void *rock, struct mbox_entry **mboxent)
{
    struct cb *prox = (struct cb *) rock;
    int r;
    int sz = sizeof(struct mbox_entry) + strlen((*mboxent)->acls);

    fprintf(stderr, "sending '%s'\n", (*mboxent)->name);

    /* we pay no attention to network byte order stuff here; we should */
    /* send size */
    r = prot_printf(prox->out, "M%dM", sz);
    if (!r) {
	prot_write(prox->out, (char *) *mboxent, sz);
    }

    *mboxent = NULL;

    if (r) {
	return MB_FATAL;
    } else {
	return MB_NEXT;
    }
}

void init_proxy(int sock)
{
    struct cb *ret = xmalloc(sizeof(struct cb));
    int r;
    int ch;
    int flag;

    fprintf(stderr, "sending to connection...\n");

    /* want blocking i/o */
    if ((flag = fcntl(sock, F_GETFL)) < 0) {
	close(sock);
	return;
    }
    flag &= ~O_NONBLOCK;

    if (fcntl(sock, F_SETFL, flag) < 0) {
	close(sock);
	return;
    }

    ret->in = prot_new(sock, 0);
    ret->out = prot_new(sock, 1);
    ret->saslconn = NULL;
    ret->sock = sock;
    prot_setflushonread(ret->in, ret->out);
#if 0
    prot_settimeout(ret->in, 60); /* only sixty seconds to respond */
#endif

    /* need to send list of our mailboxes to this prot server, and it
       can either like it or lump it */
    r = mboxlist_foreach(&send_mbox_to_proxy, (void *) ret, 0);
    if (!r) {
	r = prot_putc('-', ret->out);
    }
    fprintf(stderr, "done... now reading...\n");
    if (!r) {
	if (prot_getc(ret->in) == 'o' &&
	    prot_getc(ret->in) == 'k') {
	    r = 0;
	} else {
	    r = 1;
	}
    }

    if (!r) {
        fprintf(stderr, "adding to list\n");
	ret->next = head;
	head = ret;
    } else {
        fprintf(stderr, "something went wrong!\n");
	close(sock);
	free(ret);
    }
}

void free_cb(struct cb *ptr)
{
    prot_free(ptr->in);
    prot_free(ptr->out);
    if (ptr->saslconn) {
	sasl_dispose(&ptr->saslconn);
    }
    free(ptr);
}

void kill_cb(struct cb *ptr)
{
    struct cb *p2;

    syslog(LOG_ERR, "lost connection with proxy");
    fprintf(stderr, "lost connection with proxy\n");

    /* die proxy die
       well, hopefully you're already dead */
    close(ptr->sock);
    if (ptr == head) {
	p2 = ptr->next;
	free_cb(ptr);
	head = p2;
	ptr = p2;
    } else {
	p2 = head;
	while (p2->next != ptr) {
	    p2 = p2->next;
	}
	p2->next = ptr->next;
	free_cb(ptr);
	ptr = p2->next;
    }
}

int tell_proxies_txn(struct inmsg *buf)
{
    struct cb *ptr = head;
    int r;

    while (ptr != NULL) {
	fprintf(stderr, "writing to %x\n", ptr);
	r = prot_write(ptr->out, (char *) buf, sizeof(struct inmsg));
	if (!r) {
	    r = prot_flush(ptr->out);
	}

	if (r) {
	    struct cb *p2;

	    /* ok, we're declaring this server "down".
	       remove it from our list; it'll have to reconnect

	       make sure that ptr ends up as ptr->next */
	    p2 = ptr;
	    ptr = ptr->next;
	    kill_cb(p2);
	} else {
	    /* successfully sent data to proxy */
	    ptr = ptr->next;
	}
    }
    
    return 0;
}

/* returns non-zero if any proxies fail the transaction */
int listen_proxies(void)
{
    struct cb *ptr = head, *p2;
    int ch1, ch2;
    int r, c;

    r = 0;
    c = 0;
    while (ptr != NULL) {
	fprintf(stderr, "reading from %x...\n", ptr);
	ch1 = prot_getc(ptr->in);
	ch2 = prot_getc(ptr->in);
	if (ch1 == 'o' && ch2 == 'k') {
	    c++;
	    fprintf(stderr, "\tgot ok\n");
	    ptr = ptr->next;
	} else if (ch1 == 'n' && ch2 == 'o') {
	    c++;
	    r++;
	    fprintf(stderr, "\tgot no\n");
	    ptr = ptr->next;
	} else {
	    /* got an unrecognized response; kill this server */
	    p2 = ptr;
	    ptr = ptr->next;
	    kill_cb(p2);
	}
    }

    if (r > 0) {
	syslog(LOG_NOTICE, "transaction failed on %d/%d proxies", r, c);
	if (r != c) {
	    r = IMAP_AGAIN;
	} else {
	    r = IMAP_IOERROR;
	}
    }
    return r;
}

void tell_proxies_commit(void)
{
    struct cb *ptr = head, *p2;
    int ch1, ch2;
    int r;

    while (ptr != NULL) {
	fprintf(stderr, "writing 'go' to %x\n", ptr);
	r = prot_putc('g', ptr->out);
	if (!r) r = prot_putc('o', ptr->out);
	if (!r) r = prot_flush(ptr->out);
    
	if (r) {
	    /* server is down */
	    p2 = ptr;
	    ptr = ptr->next;
	    kill_cb(p2);
	} else {
	    ptr = ptr->next;
	}
    }
}

void tell_proxies_abort(void)
{
    struct cb *ptr = head, *p2;
    int ch1, ch2;
    int r;

    while (ptr != NULL) {
	fprintf(stderr, "writing 'ab' to %x\n", ptr);
	r = prot_putc('a', ptr->out);
	if (!r) r = prot_putc('b', ptr->out);
	if (!r) r = prot_flush(ptr->out);
    
	if (r) {
	    /* server is down */
	    p2 = ptr;
	    ptr = ptr->next;
	    kill_cb(p2);
	} else {
	    ptr = ptr->next;
	}
    }
}


int main(int argc, char *argv[], char *envp[])
{
    int msqin, msqout;
    struct inmsg inbuf;
    struct outmsg outbuf;
    int r;
    struct auth_state *authstate;

    config_init("gun");

    init_listen();

    mboxlist_open();

    signal(SIGTERM, &handler);
    signal(SIGINT, &handler);
    signal(SIGALRM, &handler);
    signal(SIGPIPE, SIG_IGN);

    if ((msqin = msgget(COMMANDS, IPC_CREAT | 0600)) < 0) {
        perror("msgget");
	fatal("msgget COMMANDS failed", 1);
    }

    if ((msqout = msgget(RESPONSES, IPC_CREAT | 0600)) < 0) {
        perror("msgget");
	fatal("msgget RESPONSES failed", 1);
    }

    for (;;) {
	errno = 0;
	alarm(POLL_TIME);
	if ((msgrcv(msqin, (struct msgbuf *) &inbuf, 
		    sizeof(struct inmsg), 0, 0) < 0) && (errno != EINTR)) {
	    fatal("msgrcv failed", 1);
	}
	if (errno != EINTR) {
	    struct mbox_txn *mytxn = NULL;

	    /* ok, do whatever the imapd wants */
	    alarm(0);

	    authstate = auth_newstate(inbuf.userid, NULL);
	    switch (inbuf.mtype) {
	    case CREATEMAILBOX:
		printf("got CREATEMAILBOX:\n");
		printf("\t(%s, %s, %d, %s, %d)\n", inbuf.name, inbuf.userid,
		       inbuf.isadmin, inbuf.u.cmb.partition, 
		       inbuf.u.cmb.mbtype);
		r = real_mboxlist_createmailbox(inbuf.name, 
						inbuf.u.cmb.mbtype,
						*inbuf.u.cmb.partition ?
						inbuf.u.cmb.partition : NULL, 
						inbuf.isadmin,
						inbuf.userid,
						authstate,
						&mytxn);
		break;
	    case DELETEMAILBOX:
		printf("got DELETEMAILBOX:\n");
		printf("\t(%s, %s, %d, %d)\n", inbuf.name, inbuf.userid,
		       inbuf.isadmin, inbuf.u.dmb.checkacl);
		r = real_mboxlist_deletemailbox(inbuf.name,
						inbuf.isadmin,
						inbuf.userid,
						authstate,
						inbuf.u.dmb.checkacl,
						&mytxn);
		break;
		
	    case RENAMEMAILBOX:
		printf("got RENAMEMAILBOX:\n");
		printf("\t(%s, %s, %d, %s, %s)\n", inbuf.name, inbuf.userid,
		       inbuf.isadmin, inbuf.u.rmb.newname, 
		       inbuf.u.rmb.partition);
		r = real_mboxlist_renamemailbox(inbuf.name,
						inbuf.u.rmb.newname,
						*inbuf.u.rmb.partition ?
						inbuf.u.rmb.partition : NULL, 
						inbuf.isadmin,
						inbuf.userid,
						authstate,
						&mytxn);
		break;
		
	    case SETACL:
		printf("got SETACL:\n");
		printf("\t(%s, %s, %d, %s, %s)\n", inbuf.name, inbuf.userid,
		       inbuf.isadmin, inbuf.u.amb.ident, inbuf.u.amb.rights);
		r = real_mboxlist_setacl(inbuf.name,
					 inbuf.u.amb.ident,
					 inbuf.u.amb.rights,
					 inbuf.isadmin,
					 inbuf.userid,
					 authstate,
					 &mytxn);
		break;
		
	    default:
		printf("huh???\n");
		r = IMAP_IOERROR;
		break;
	    }

	    /* if r != 0, the transaction has been prepared for commiting */

	    if (!r) {
		/* tell the proxies to do it */
		r = tell_proxies_txn(&inbuf);
	    }

	    if (!r) {
		/* get the proxies reactions */
		r = listen_proxies();
	    }

	    if (!r) {
		/* commit it */
		mboxlist_commit(mytxn);

		/* tell the proxies */
		tell_proxies_commit();
	    } else {
		/* abort it */
  	        if (mytxn) {
		    mboxlist_abort(mytxn);

		    /* tell the proxies */
		    tell_proxies_abort();
		}
	    }

	    outbuf.mtype = inbuf.pid;
	    outbuf.result = r;
	    
	    if (msgsnd(msqout, (struct msgbuf *) &outbuf, 
		       sizeof(struct outmsg), 0) < 0) {
		fatal("msgsnd failed", 1);
	    }
	} else {
	    struct sockaddr_in sin;
	    int len = sizeof(sin);
	    int fd;

	    printf("timed out waiting for queue...\n");

	    /* ok, we timed out waiting for a command from the IMAP server;
	       let's see if any new proxies have connected to me */
	    errno = 0;
	    if (((fd = accept(listenfd, (struct sockaddr *) &sin, &len)) < 0)
		&& (errno != EWOULDBLOCK)) { 
		fatal("listen returned an error", 1);
	    }

	    if (!errno) {
  	        printf("got connection\n");
		/* we got a new connection */
		syslog(LOG_NOTICE, "got connection from %s",
		       inet_ntoa(sin.sin_addr));
		init_proxy(fd);
	    }
	}
    }
}
