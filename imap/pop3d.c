/* pop3d.c -- POP3 server protocol parsing
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sysexits.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <syslog.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "acl.h"
#include "util.h"
#include "auth.h"
#include "acte.h"
#include "config.h"
#include "imap_err.h"
#include "mailbox.h"
#include "version.h"
#include "xmalloc.h"

extern int optind;
extern char *optarg;

extern int errno;

char *popd_userid = 0;
struct mailbox *popd_mailbox = 0;
char popd_clienthost[250] = "[local]";
int popd_exists = 0;
int popd_highest;
struct msg {
    int uid;
    int size;
    int deleted;
} *popd_msg;

/* Eudora kludge */
#define STATUS "Status: "
#define SLEN (sizeof (STATUS)-1+4)

static struct mailbox mboxstruct;

static int expungedeleted();

main(argc, argv, envp)
int argc;
char **argv;
char **envp;
{
    char hostname[MAXHOSTNAMELEN+1];
    int salen;
    struct hostent *hp;
    struct sockaddr_in sa;

    setproctitle_init(argc, argv, envp);
    config_init("pop3d");

    signal(SIGPIPE, SIG_IGN);
    gethostname(hostname, sizeof(hostname));

    /* Find out name of client host */
    salen = sizeof(sa);
    if (getpeername(0, &sa, &salen) == 0 &&
	sa.sin_family == AF_INET) {
	if (hp = gethostbyaddr((char *)&sa.sin_addr,
			       sizeof(sa.sin_addr), AF_INET)) {
	    if (strlen(hp->h_name) + 30 > sizeof(popd_clienthost)) {
		hp->h_name[sizeof(popd_clienthost)-30] = '\0';
	    }
	    strcpy(popd_clienthost, hp->h_name);
	}
	else {
	    popd_clienthost[0] = '\0';
	}
	strcat(popd_clienthost, "[");
	strcat(popd_clienthost, inet_ntoa(sa.sin_addr));
	strcat(popd_clienthost, "]");
    }

    proc_register("pop3d", popd_clienthost, (char *)0, (char *)0);

    fprintf(stdout,"+OK %s Cyrus POP3 %s server ready\r\n", hostname,
	    CYRUS_VERSION);
    cmdloop();
}

usage()
{
    fprintf(stdout, "-ERR usage: pop3d\r\n");
    fflush(stdout);
    exit(EX_USAGE);
}

/*
 * Cleanly shut down and exit
 */
shutdown(code)
int code;
{
    proc_cleanup();
    if (popd_mailbox) {
	mailbox_close(popd_mailbox);
    }
    fflush(stdout);
    exit(code);
}

fatal(s, code)
char *s;
int code;
{
    static int recurse_code = 0;

    if (recurse_code) {
	/* We were called recursively. Just give up */
	exit(recurse_code);
    }
    recurse_code = code;
    fprintf(stdout, "-ERR Fatal error: %s\r\n", s);
    fflush(stdout);
    shutdown(code);
}

/*
 * Top-level command loop parsing
 */
cmdloop()
{
    char inputbuf[8192];
    char *p, *arg;
    int msg;

    while (fflush(stdout), fgets(inputbuf, sizeof(inputbuf), stdin)) {
	p = inputbuf + strlen(inputbuf);
	if (p > inputbuf && p[-1] == '\n') *--p = '\0';
	if (p > inputbuf && p[-1] == '\r') *--p = '\0';

	/* Parse into keword and argument */
	for (p = inputbuf; *p && !isspace(*p); p++);
	if (*p) {
	    *p++ = '\0';
	    for (arg=p; *arg && isspace(*arg); arg++);
	    if (!*arg) {
		fprintf(stdout, "-ERR Syntax error\r\n");
		continue;
	    }
	}
	else {
	    arg = 0;
	}
	lcase(inputbuf);

	if (!strcmp(inputbuf, "quit")) {
	    if (!arg) {
		if (popd_mailbox) {
		    if (!mailbox_lock_index(popd_mailbox)) {
			popd_mailbox->pop3_last_uid = popd_highest ? 
			  popd_msg[popd_highest].uid : 0;
			mailbox_write_index_header(popd_mailbox);
			mailbox_unlock_index(popd_mailbox);
		    }

		    for (msg = 1; msg <= popd_exists; msg++) {
			if (popd_msg[msg].deleted) break;
		    }

		    if (msg <= popd_exists) {
			(void) mailbox_expunge(popd_mailbox, 1, expungedeleted, 0);
		    }
		}
		printf("+OK\r\n");
		shutdown(0);
	    }
	    else fprintf(stdout, "-ERR Unexpected extra argument\r\n");
	}
	if (!popd_mailbox) {
	    if (!strcmp(inputbuf, "user")) {
		if (popd_userid) {
		    fprintf(stdout, "-ERR Must give PASS command\r\n");
		}
		else if (!arg) {
		    fprintf(stdout, "-ERR Missing argument\r\n");
		}
		else if (!(p = auth_canonifyid(arg)) ||
			 strchr(p, '.') || strlen(p) + 6 > MAX_MAILBOX_PATH) {
		    fprintf(stdout, "-ERR Invalid user\r\n");
		    syslog(LOG_NOTICE,
			   "badlogin: %s plaintext %s invalid user",
			   popd_clienthost, beautify_string(arg));
		}
		else {
		    popd_userid = strsave(p);
		    fprintf(stdout, "+OK Name is a valid mailbox\r\n");
		}
	    }
	    else if (!strcmp(inputbuf, "pass")) {
		if (!arg) fprintf(stdout, "-ERR Missing argument\r\n");
		else cmd_pass(arg);
	    }
	    else {
		fprintf(stdout, "-ERR Unrecognized command\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "stat")) {
	    int nmsgs = 0, totsize = 0;
	    if (arg) {
		fprintf(stdout, "-ERR Unexpected extra argument\r\n");
	    }
	    else {
		for (msg = 1; msg <= popd_exists; msg++) {
		    if (!popd_msg[msg].deleted) {
			nmsgs++;
			totsize += popd_msg[msg].size;
		    }
		}
		fprintf(stdout, "+OK %d %d\r\n", nmsgs, totsize);
	    }
	}
	else if (!strcmp(inputbuf, "list")) {
	    if (arg) {
		msg = parsenum(&arg);
		if (arg) {
		    fprintf(stdout, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    fprintf(stdout, "-ERR No such message\r\n");
		}
		else {
		    fprintf(stdout, "+OK %d %d\r\n", msg, popd_msg[msg].size);
		}
	    }
	    else {
		fprintf(stdout, "+OK scan listing follows\r\n");
		for (msg = 1; msg <= popd_exists; msg++) {
		    if (!popd_msg[msg].deleted) {
			fprintf(stdout, "%d %d\r\n", msg, popd_msg[msg].size);
		    }
		}
		fprintf(stdout, ".\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "retr")) {
	    if (!arg) fprintf(stdout, "-ERR Missing argument\r\n");
	    else {
		msg = parsenum(&arg);
		if (arg) {
		    fprintf(stdout, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    fprintf(stdout, "-ERR No such message\r\n");
		}
		else {
		    if (msg > popd_highest) popd_highest = msg;
		    blat(msg, -1);
		}
	    }
	}
	else if (!strcmp(inputbuf, "dele")) {
	    if (!arg) fprintf(stdout, "-ERR Missing argument\r\n");
	    else {
		msg = parsenum(&arg);
		if (arg) {
		    fprintf(stdout, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    fprintf(stdout, "-ERR No such message\r\n");
		}
		else {
		    popd_msg[msg].deleted = 1;
		    if (msg > popd_highest) popd_highest = msg;
		    fprintf(stdout, "+OK message deleted\r\n");
		}
	    }
	}
	else if (!strcmp(inputbuf, "noop")) {
	    if (arg) {
		fprintf(stdout, "-ERR Unexpected extra argument\r\n");
	    }
	    else {
		fprintf(stdout, "+OK\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "last")) {
	    if (arg) {
		fprintf(stdout, "-ERR Unexpected extra argument\r\n");
	    }
	    else {
		fprintf(stdout, "+OK %d\r\n", popd_highest);
	    }
	}
	else if (!strcmp(inputbuf, "rset")) {
	    if (arg) {
		fprintf(stdout, "-ERR Unexpected extra argument\r\n");
	    }
	    else {
		popd_highest = 0;
		for (msg = 1; msg <= popd_exists; msg++) {
		    popd_msg[msg].deleted = 0;
		}
		fprintf(stdout, "+OK\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "top")) {
	    int lines;

	    if (arg) msg = parsenum(&arg);
	    if (!arg) fprintf(stdout, "-ERR Missing argument\r\n");
	    else {
		lines = parsenum(&arg);
		if (arg) {
		    fprintf(stdout, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    fprintf(stdout, "-ERR No such message\r\n");
		}
		else if (lines < 0) {
		    fprintf(stdout, "-ERR Invalid number of lines\r\n");
		}
		else {
		    blat(msg, lines);
		}
	    }
	}
	else {
	    fprintf(stdout, "-ERR Unrecognized command\r\n");
	}
    }		

    shutdown(0);
}

cmd_pass(pass)
char *pass;	
{
    char *reply;
    char inboxname[MAX_MAILBOX_PATH];
    int r, msg;
    struct index_record record;

    if (!popd_userid) {
	fprintf(stdout, "-ERR Must give USER command\r\n");
	return;
    }

    if (login_plaintext(popd_userid, pass, &reply) != 0) {
	if (reply) {
	    syslog(LOG_NOTICE, "badlogin: %s plaintext %s %s",
		   popd_clienthost, popd_userid, reply);
	}
	free(popd_userid);
	popd_userid = 0;
	fprintf(stdout, "-ERR Invalid login\r\n");
	return;
    }

    strcpy(inboxname, "user.");
    strcat(inboxname, popd_userid);
    r = mailbox_open_header(inboxname, &mboxstruct);
    if (r) {
	free(popd_userid);
	popd_userid = 0;
	fprintf(stdout, "-ERR Invalid login\r\n");
	return;
    }

    r = mailbox_open_index(&mboxstruct);
    if (!r) r = mailbox_lock_pop(&mboxstruct);
    if (r) {
	mailbox_close(&mboxstruct);
	free(popd_userid);
	popd_userid = 0;
	fprintf(stdout, "-ERR Unable to lock maildrop\r\n");
	return;
    }

    if (chdir(mboxstruct.path)) {
	syslog(LOG_ERR, "IOERROR: changing directory to %s: %m",
	       mboxstruct.path);
	r = IMAP_IOERROR;
    }
    if (!r) {
	popd_exists = mboxstruct.exists;
	popd_highest = 0;
	popd_msg = (struct msg *)xmalloc((popd_exists+1) * sizeof(struct msg));
	for (msg = 1; msg <= popd_exists; msg++) {
	    if (r = mailbox_read_index_record(&mboxstruct, msg, &record))
	      break;
	    popd_msg[msg].uid = record.uid;
	    popd_msg[msg].size = record.size /* XXX + SLEN */;
	    popd_msg[msg].deleted = 0;
	    if (record.uid <= mboxstruct.pop3_last_uid) popd_highest = msg;
	}
    }
    if (r) {
	mailbox_close(&mboxstruct);
	free(popd_userid);
	popd_userid = 0;
	free(popd_msg);
	popd_msg = 0;
	popd_exists = 0;
	fprintf(stdout, "-ERR Unable to read maildrop\r\n");
	return;
    }
    popd_mailbox = &mboxstruct;
    fprintf(stdout, "+OK Maildrop locked and ready\r\n");
}

blat(msg, lines)
int msg;
int lines;
{
    FILE *msgfile;
    char buf[4096];
    int thisline = -2;

    msgfile = fopen(mailbox_message_fname(popd_mailbox, popd_msg[msg].uid),
		    "r");
    if (!msgfile) {
	fprintf(stdout, "-ERR Could not read message file\r\n");
	return;
    }
    fprintf(stdout, "+OK Message follows\r\n");
    while (lines != thisline) {
	if (!fgets(buf, sizeof(buf), msgfile)) break;

	if (thisline < 0) {
	    if (buf[0] == '\r' && buf[1] == '\n') thisline = 0;
	}
	else thisline++;

	if (buf[0] == '.') putc('.', stdout);
	do {
	    fputs(buf, stdout);
	}
	while (buf[strlen(buf)-1] != '\n' && fgets(buf, sizeof(buf), msgfile));
    }
    fclose(msgfile);
    fprintf(stdout, ".\r\n");
}

int parsenum(ptr)
char **ptr;
{
    char *p = *ptr;
    int result = 0;

    if (!isdigit(*p)) {
	*ptr = 0;
	return -1;
    }
    while (*p && isdigit(*p)) {
	result = result * 10 + *p++ - '0';
    }

    if (*p) {
	while (*p && isspace(*p)) p++;
	*ptr = p;
    }
    else *ptr = 0;
    return result;
}

static int expungedeleted(rock, index)
char *rock;
char *index;
{
    int msg;
    int uid = ntohl(*((bit32 *)(index+OFFSET_UID)));

    for (msg = 1; msg <= popd_exists; msg++) {
	if (popd_msg[msg].uid == uid) {
	    return popd_msg[msg].deleted;
	}
    }
    return 0;
}
