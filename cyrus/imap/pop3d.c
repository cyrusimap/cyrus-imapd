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
#include "prot.h"
#include "imap_err.h"
#include "mailbox.h"
#include "version.h"
#include "xmalloc.h"

extern int optind;
extern char *optarg;

extern int errno;

/* The Eudora kludge */
#define STATUS "Status: "
#define SLEN (sizeof(STATUS)+2)

char *popd_userid = 0;
struct mailbox *popd_mailbox = 0;
char popd_clienthost[250] = "[local]";
struct protstream *popd_out, *popd_in;
int popd_exists = 0;
int popd_highest;
int popd_initialhighest;
struct msg {
    int uid;
    int size;
    int deleted;
} *popd_msg;

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
    int timeout;

    popd_in = prot_new(0, 0);
    popd_out = prot_new(1, 1);

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

    /* Set inactivity timer */
    timeout = config_getint("poptimeout", 10);
    if (timeout < 10) timeout = 10;
    prot_settimeout(popd_in, timeout*60);

    prot_printf(popd_out,"+OK %s Cyrus POP3 %s server ready\r\n",
		hostname, CYRUS_VERSION);
    cmdloop();
}

usage()
{
    prot_printf(popd_out, "-ERR usage: pop3d\r\n");
    prot_flush(popd_out);
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
    prot_flush(popd_out);
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
    prot_printf(popd_out, "-ERR Fatal error: %s\r\n", s);
    prot_flush(popd_out);
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

    for (;;) {
	prot_flush(popd_out);
	if (!prot_fgets(inputbuf, sizeof(inputbuf), popd_in)) {
	    shutdown(0);
	}

	p = inputbuf + strlen(inputbuf);
	if (p > inputbuf && p[-1] == '\n') *--p = '\0';
	if (p > inputbuf && p[-1] == '\r') *--p = '\0';

	/* Parse into keword and argument */
	for (p = inputbuf; *p && !isspace(*p); p++);
	if (*p) {
	    *p++ = '\0';
	    for (arg=p; *arg && isspace(*arg); arg++);
	    if (!*arg) {
		prot_printf(popd_out, "-ERR Syntax error\r\n");
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
	    else prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	}
	if (!popd_mailbox) {
	    if (!strcmp(inputbuf, "user")) {
		if (popd_userid) {
		    prot_printf(popd_out, "-ERR Must give PASS command\r\n");
		}
		else if (!arg) {
		    prot_printf(popd_out, "-ERR Missing argument\r\n");
		}
		else if (!(p = auth_canonifyid(arg)) ||
			 strchr(p, '.') || strlen(p) + 6 > MAX_MAILBOX_PATH) {
		    prot_printf(popd_out, "-ERR Invalid user\r\n");
		    syslog(LOG_NOTICE,
			   "badlogin: %s plaintext %s invalid user",
			   popd_clienthost, beautify_string(arg));
		}
		else {
		    popd_userid = strsave(p);
		    prot_printf(popd_out, "+OK Name is a valid mailbox\r\n");
		}
	    }
	    else if (!strcmp(inputbuf, "pass")) {
		if (!arg) prot_printf(popd_out, "-ERR Missing argument\r\n");
		else cmd_pass(arg);
	    }
	    else {
		prot_printf(popd_out, "-ERR Unrecognized command\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "stat")) {
	    int nmsgs = 0, totsize = 0;
	    if (arg) {
		prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	    }
	    else {
		for (msg = 1; msg <= popd_exists; msg++) {
		    if (!popd_msg[msg].deleted) {
			nmsgs++;
			totsize += popd_msg[msg].size;
		    }
		}
		prot_printf(popd_out, "+OK %d %d\r\n", nmsgs, totsize);
	    }
	}
	else if (!strcmp(inputbuf, "list")) {
	    if (arg) {
		msg = parsenum(&arg);
		if (arg) {
		    prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    prot_printf(popd_out, "-ERR No such message\r\n");
		}
		else {
		    prot_printf(popd_out, "+OK %d %d\r\n", msg, popd_msg[msg].size);
		}
	    }
	    else {
		prot_printf(popd_out, "+OK scan listing follows\r\n");
		for (msg = 1; msg <= popd_exists; msg++) {
		    if (!popd_msg[msg].deleted) {
			prot_printf(popd_out, "%d %d\r\n", msg, popd_msg[msg].size);
		    }
		}
		prot_printf(popd_out, ".\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "retr")) {
	    if (!arg) prot_printf(popd_out, "-ERR Missing argument\r\n");
	    else {
		msg = parsenum(&arg);
		if (arg) {
		    prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    prot_printf(popd_out, "-ERR No such message\r\n");
		}
		else {
		    if (msg > popd_highest) popd_highest = msg;
		    blat(msg, -1);
		}
	    }
	}
	else if (!strcmp(inputbuf, "dele")) {
	    if (!arg) prot_printf(popd_out, "-ERR Missing argument\r\n");
	    else {
		msg = parsenum(&arg);
		if (arg) {
		    prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    prot_printf(popd_out, "-ERR No such message\r\n");
		}
		else {
		    popd_msg[msg].deleted = 1;
		    if (msg > popd_highest) popd_highest = msg;
		    prot_printf(popd_out, "+OK message deleted\r\n");
		}
	    }
	}
	else if (!strcmp(inputbuf, "noop")) {
	    if (arg) {
		prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	    }
	    else {
		prot_printf(popd_out, "+OK\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "last")) {
	    if (arg) {
		prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	    }
	    else {
		prot_printf(popd_out, "+OK %d\r\n", popd_highest);
	    }
	}
	else if (!strcmp(inputbuf, "rset")) {
	    if (arg) {
		prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
	    }
	    else {
		popd_highest = 0;
		for (msg = 1; msg <= popd_exists; msg++) {
		    popd_msg[msg].deleted = 0;
		}
		prot_printf(popd_out, "+OK\r\n");
	    }
	}
	else if (!strcmp(inputbuf, "top")) {
	    int lines;

	    if (arg) msg = parsenum(&arg);
	    if (!arg) prot_printf(popd_out, "-ERR Missing argument\r\n");
	    else {
		lines = parsenum(&arg);
		if (arg) {
		    prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    prot_printf(popd_out, "-ERR No such message\r\n");
		}
		else if (lines < 0) {
		    prot_printf(popd_out, "-ERR Invalid number of lines\r\n");
		}
		else {
		    blat(msg, lines);
		}
	    }
	}
	else if (!strcmp(inputbuf, "uidl")) {
	    if (arg) {
		msg = parsenum(&arg);
		if (arg) {
		    prot_printf(popd_out, "-ERR Unexpected extra argument\r\n");
		}
		else if (msg < 1 || msg > popd_exists ||
			 popd_msg[msg].deleted) {
		    prot_printf(popd_out, "-ERR No such message\r\n");
		}
		else {
		    prot_printf(popd_out, "+OK %d %d\r\n", msg, popd_msg[msg].uid);
		}
	    }
	    else {
		prot_printf(popd_out, "+OK unique-id listing follows\r\n");
		for (msg = 1; msg <= popd_exists; msg++) {
		    if (!popd_msg[msg].deleted) {
			prot_printf(popd_out, "%d %d\r\n", msg, popd_msg[msg].uid);
		    }
		}
		prot_printf(popd_out, ".\r\n");
	    }
	}
	else {
	    prot_printf(popd_out, "-ERR Unrecognized command\r\n");
	}
    }		
}

cmd_pass(pass)
char *pass;	
{
    char *reply;
    char inboxname[MAX_MAILBOX_PATH];
    int r, msg;
    struct index_record record;
    char buf[MAX_MAILBOX_PATH];
    FILE *logfile;

    if (!popd_userid) {
	prot_printf(popd_out, "-ERR Must give USER command\r\n");
	return;
    }

    if (!strcmp(popd_userid, "anonymous")) {
	if (config_getswitch("allowanonymouslogin", 0)) {
	    pass = beautify_string(pass);
	    if (strlen(pass) > 500) pass[500] = '\0';
	    syslog(LOG_NOTICE, "login: %s anonymous %s",
		   popd_clienthost, pass);
	}
	else {
	    syslog(LOG_NOTICE, "badlogin: %s anonymous login refused",
		   popd_clienthost);
	    prot_printf(popd_out, "-ERR Invalid login\r\n");
	    return;
	}
    }
    else if (login_plaintext(popd_userid, pass, &reply) != 0) {
	if (reply) {
	    syslog(LOG_NOTICE, "badlogin: %s plaintext %s %s",
		   popd_clienthost, popd_userid, reply);
	}
	free(popd_userid);
	popd_userid = 0;
	prot_printf(popd_out, "-ERR Invalid login\r\n");
	return;
    }

    strcpy(inboxname, "user.");
    strcat(inboxname, popd_userid);
    r = mailbox_open_header(inboxname, &mboxstruct);
    if (r) {
	free(popd_userid);
	popd_userid = 0;
	prot_printf(popd_out, "-ERR Invalid login\r\n");
	return;
    }

    r = mailbox_open_index(&mboxstruct);
    if (!r) r = mailbox_lock_pop(&mboxstruct);
    if (r) {
	mailbox_close(&mboxstruct);
	free(popd_userid);
	popd_userid = 0;
	prot_printf(popd_out, "-ERR Unable to lock maildrop\r\n");
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
	    popd_msg[msg].size = record.size + SLEN;
	    popd_msg[msg].deleted = 0;
	    if (record.uid <= mboxstruct.pop3_last_uid) popd_highest = msg;
	}
	popd_initialhighest = popd_highest;
    }
    if (r) {
	mailbox_close(&mboxstruct);
	free(popd_userid);
	popd_userid = 0;
	free(popd_msg);
	popd_msg = 0;
	popd_exists = 0;
	prot_printf(popd_out, "-ERR Unable to read maildrop\r\n");
	return;
    }
    popd_mailbox = &mboxstruct;
    proc_register("pop3d", popd_clienthost, popd_userid, popd_mailbox->name);

    /* Create telemetry log */
    sprintf(buf, "%s%s%s/%d", config_dir, FNAME_LOGDIR, popd_userid,
	    getpid());
    logfile = fopen(buf, "w");
    if (logfile) {
	prot_setlog(popd_in, fileno(logfile));
	prot_setlog(popd_out, fileno(logfile));
    }

    prot_printf(popd_out, "+OK Maildrop locked and ready\r\n");
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
	prot_printf(popd_out, "-ERR Could not read message file\r\n");
	return;
    }
    prot_printf(popd_out, "+OK Message follows\r\n");
    printf("%s%c\r\n", STATUS, msg <= popd_initialhighest ? 'R' : 'U');
    while (lines != thisline) {
	if (!fgets(buf, sizeof(buf), msgfile)) break;

	if (thisline < 0) {
	    if (buf[0] == '\r' && buf[1] == '\n') thisline = 0;
	}
	else thisline++;

	if (buf[0] == '.') prot_putc('.', popd_out);
	do {
	    prot_printf(popd_out, "%s", buf);
	}
	while (buf[strlen(buf)-1] != '\n' && fgets(buf, sizeof(buf), msgfile));
    }
    fclose(msgfile);
    prot_printf(popd_out, ".\r\n");
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
