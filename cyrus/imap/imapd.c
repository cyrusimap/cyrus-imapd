/* imapd.c -- IMAP server protocol parsing
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
#include <sys/stat.h>
#include <syslog.h>
#include <com_err.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "acl.h"
#include "util.h"
#include "auth.h"
#include "imap_err.h"
#include "mailbox.h"
#include "imapd.h"
#include "charset.h"
#include "xmalloc.h"

extern int optind;
extern char *optarg;

extern int errno;

struct buf {
    char *s;
    int alloc;
};

char *imapd_userid;
int imapd_userisadmin;
struct mailbox *imapd_mailbox;
int imapd_exists;
char imapd_clienthost[250] = "[local]";

static struct mailbox mboxstruct;

static struct fetchargs zerofetchargs;

static char *monthname[] = {
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec"
};

static int mailboxdata();

main(argc, argv, envp)
int argc;
char **argv;
char **envp;
{
    char hostname[MAXHOSTNAMELEN+1];
    struct sockaddr_in sa;
    int salen = sizeof(sa);
    struct hostent *hp;

    setproctitle_init(argc, argv, envp);
    config_init("imapd");

    signal(SIGPIPE, SIG_IGN);
    gethostname(hostname, sizeof(hostname));

    /* Find out name of client host */
    if (getpeername(0, &sa, &salen) == 0 &&
	sa.sin_family == AF_INET) {
	if (hp = gethostbyaddr((char *)&sa.sin_addr, sizeof(sa.sin_addr),
			       AF_INET)) {
	    if (strlen(hp->h_name) + 30 > sizeof(imapd_clienthost)) {
		hp->h_name[sizeof(imapd_clienthost)-30] = '\0';
	    }
	    strcpy(imapd_clienthost, hp->h_name);
	}
	else {
	    imapd_clienthost[0] = '\0';
	}
	strcat(imapd_clienthost, "[");
	strcat(imapd_clienthost, inet_ntoa(sa.sin_addr));
	strcat(imapd_clienthost, "]");
    }

    proc_register("imapd", imapd_clienthost, (char *)0, (char *)0);

    printf("* OK %s Cyrus IMAP4 v0.4-ALPHA server ready\r\n", hostname);
    cmdloop();
}

usage()
{
    printf("* BYE usage: imapd\r\n");
    exit(EX_USAGE);
}

/*
 * Cleanly shut down and exit
 */
shutdown(code)
int code;
{
    proc_cleanup();
    if (imapd_mailbox) {
	index_checkseen(imapd_mailbox, 1, 0, imapd_exists);
	mailbox_close(imapd_mailbox);
    }
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
    printf("* BYE Fatal error: %s\r\n", s);
    shutdown(code);
}

/*
 * Top-level command loop parsing
 */
cmdloop()
{
    int c;
    int usinguid, havepartition, havenamespace;
    static struct buf tag, cmd, arg1, arg2, arg3, arg4;
    char *p;

    for (;;) {
	fflush(stdout);

	/* Parse tag */
	c = getword(&tag);
	if (c == EOF) {
	    shutdown(0);
	}
	if (c != ' ' || !isatom(tag.s) || (tag.s[0] == '*' && !tag.s[1])) {
	    printf("* BAD Invalid tag\r\n");
	    if (c != '\n') eatline();
	    continue;
	}

	/* Parse command name */
	c = getword(&cmd);
	if (!cmd.s[0]) {
	    printf("%s BAD Null command\r\n", tag.s);
	    if (c != '\n') eatline();
	    continue;
	}
	if (islower(cmd.s[0])) cmd.s[0] = toupper(cmd.s[0]);
	for (p = &cmd.s[1]; *p; p++) {
	    if (isupper(*p)) *p = tolower(*p);
	}

	/* Only Login/Logout/Noop allowed when not logged in */
	if (!imapd_userid && cmd.s[0] != 'L' && cmd.s[0] != 'N') goto nologin;
    
	switch (cmd.s[0]) {
	case 'A':
	    if (!strcmp(cmd.s, "Append")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;

		cmd_append(tag.s, arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'B':
	    if (!strcmp(cmd.s, "Bboard")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;

		cmd_select(tag.s, cmd.s, arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'C':
	    if (!strcmp(cmd.s, "Check")) {
		if (!imapd_mailbox) goto nomailbox;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_noop(tag.s, cmd.s);
	    }
	    else if (!strcmp(cmd.s, "Copy")) {
		if (!imapd_mailbox) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    copy:
		c = getword(&arg1);
		if (c != ' ' || !issequence(arg1.s)) goto badsequence;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;

		cmd_copy(tag.s, arg1.s, arg2.s, usinguid);
	    }
	    else if (!strcmp(cmd.s, "Create")) {
		havepartition = 0;
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == ' ') {
		    havepartition = 1;
		    c = getword(&arg2);
		    if (!isatom(arg2.s)) goto badpartition;
		}
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_create(tag.s, arg1.s, havepartition ? arg2.s : 0);
	    }
	    else goto badcmd;
	    break;

	case 'D':
	    if (!strcmp(cmd.s, "Delete")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_delete(tag.s, arg1.s);
	    }
	    else if (!strcmp(cmd.s, "Deleteacl")) {
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c != ' ') goto missingargs;
		c = getastring(&arg3);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_setacl(tag.s, arg1.s, arg2.s, arg3.s, (char *)0);
	    }
	    else goto badcmd;
	    break;

	case 'E':
	    if (!strcmp(cmd.s, "Expunge")) {
		if (!imapd_mailbox) goto nomailbox;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_expunge(tag.s);
	    }
	    else if (!strcmp(cmd.s, "Examine")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;

		cmd_select(tag.s, cmd.s, arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'F':
	    if (!strcmp(cmd.s, "Fetch")) {
		if (!imapd_mailbox) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    fetch:
		c = getword(&arg1);
		if (c != ' ' || !issequence(arg1.s)) goto badsequence;
		cmd_fetch(tag.s, arg1.s, usinguid);
	    }
	    else if (!strcmp(cmd.s, "Find")) {
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_find(tag.s, arg1.s, arg2.s);
	    }
	    else goto badcmd;
	    break;

	case 'G':
	    if (!strcmp(cmd.s, "Getacl")) {
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_getacl(tag.s, arg1.s, arg2.s);
	    }
	    else goto badcmd;
	    break;

	case 'L':
	    if (!strcmp(cmd.s, "Login")) {
		if (c != ' ' || (c = getastring(&arg1)) != ' ') {
		    goto missingargs;
		}
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		
		if (imapd_userid) {
		    printf("%s NO Already logged in\r\n", tag.s);
		    continue;
		}
		cmd_login(tag.s, arg1.s, arg2.s);
	    }
	    else if (!strcmp(cmd.s, "Logout")) {
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		
		printf("* BYE Server terminating connection\r\n");
		printf("%s OK Logout completed\r\n", tag.s);
		shutdown(0);
	    }
	    else if (!imapd_userid) goto nologin;
	    else goto badcmd;
	    break;

	case 'M':
	    if (!strcmp(cmd.s, "Myrights")) {
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_myrights(tag.s, arg1.s, arg2.s);
	    }
	    else goto badcmd;
	    break;

	case 'N':
	    if (!strcmp(cmd.s, "Noop")) {
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_noop(tag.s, cmd.s);
	    }
	    else if (!imapd_userid) goto nologin;
	    else goto badcmd;
	    break;

	case 'P':
	    if (!strcmp(cmd.s, "Partial")) {
		if (!imapd_mailbox) goto nomailbox;
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		c = getword(&arg2);
		if (c != ' ') goto missingargs;
		c = getword(&arg3);
		if (c != ' ') goto missingargs;
		c = getword(&arg4);
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_partial(tag.s, arg1.s, arg2.s, arg3.s, arg4.s);
	    }
	    else goto badcmd;
	    break;

	case 'R':
	    if (!strcmp(cmd.s, "Rename")) {
		havepartition = 0;
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == ' ') {
		    havepartition = 1;
		    c = getword(&arg3);
		    if (!isatom(arg3.s)) goto badpartition;
		}
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_rename(tag.s, arg1.s, arg2.s, havepartition ? arg3.s : 0);
	    }
	    else goto badcmd;
	    break;
	    
	case 'S':
	    if (!strcmp(cmd.s, "Store")) {
		if (!imapd_mailbox) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    store:
		c = getword(&arg1);
		if (c != ' ' || !issequence(arg1.s)) goto badsequence;
		c = getword(&arg2);
		if (c != ' ') goto badsequence;
		cmd_store(tag.s, arg1.s, arg2.s, usinguid);
	    }
	    else if (!strcmp(cmd.s, "Select")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;

		cmd_select(tag.s, cmd.s, arg1.s);
	    }
	    else if (!strcmp(cmd.s, "Search")) {
		if (!imapd_mailbox) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    search:
		cmd_search(tag.s, usinguid);
	    }
	    else if (!strcmp(cmd.s, "Subscribe")) {
		if (c != ' ') goto missingargs;
		havenamespace = 0;
		c = getastring(&arg1);
		if (c == ' ') {
		    havenamespace = 1;
		    c = getastring(&arg2);
		}
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		if (havenamespace) {
		    cmd_changesub(tag.s, arg1.s, arg2.s, 1);
		}
		else {
		    cmd_changesub(tag.s, (char *)0, arg1.s, 1);
		}
	    }		
	    else if (!strcmp(cmd.s, "Setacl")) {
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c != ' ') goto missingargs;
		c = getastring(&arg3);
		if (c != ' ') goto missingargs;
		c = getastring(&arg4);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_setacl(tag.s, arg1.s, arg2.s, arg3.s, arg4.s);
	    }
	    else goto badcmd;
	    break;

	case 'U':
	    if (!strcmp(cmd.s, "Uid")) {
		if (!imapd_mailbox) goto nomailbox;
		usinguid = 1;
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		lcase(arg1.s);
		if (!strcmp(arg1.s, "fetch")) {
		    goto fetch;
		}
		else if (!strcmp(arg1.s, "store")) {
		    goto store;
		}
		else if (!strcmp(arg1.s, "search")) {
		    goto search;
		}
		else if (!strcmp(arg1.s, "copy")) {
		    goto copy;
		}
		else {
		    printf("%s BAD Unrecognized UID subcommand\r\n", tag.s);
		    if (c != '\n') eatline();
		}
	    }
	    else if (!strcmp(cmd.s, "Unsubscribe")) {
		if (c != ' ') goto missingargs;
		havenamespace = 0;
		c = getastring(&arg1);
		if (c == ' ') {
		    havenamespace = 1;
		    c = getastring(&arg2);
		}
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		if (havenamespace) {
		    cmd_changesub(tag.s, arg1.s, arg2.s, 0);
		}
		else {
		    cmd_changesub(tag.s, (char *)0, arg1.s, 0);
		}
	    }		
	    else goto badcmd;
	    break;

	default:
	badcmd:
	    printf("%s BAD Unrecognized command\r\n", tag.s);
	    if (c != '\n') eatline();
	}

	continue;

    nologin:
	printf("%s BAD Please login first\r\n", tag.s);
	if (c != '\n') eatline();
	continue;

    nomailbox:
	printf("%s BAD Please select a mailbox first\r\n", tag.s);
	if (c != '\n') eatline();
	continue;

    missingargs:
	printf("%s BAD Missing required argument to %s\r\n", tag.s, cmd.s);
	if (c != '\n') eatline();
	continue;

    extraargs:
	printf("%s BAD Unexpected extra arguments to %s\r\n", tag.s, cmd.s);
	if (c != '\n') eatline();
	continue;

    badsequence:
	printf("%s BAD Invalid sequence in %s\r\n", tag.s, cmd.s);
	if (c != '\n') eatline();
	continue;

    badpartition:
	printf("%s BAD Invalid partition name in %s\r\n",
	       tag.s, cmd.s);
	if (c != '\n') eatline();
	continue;
    }
}

/*
 * Perform a LOGIN command
 */
cmd_login(tag, user, passwd)
char *tag;
char *user;
char *passwd;
{
    char *canon_user;
    char *reply = 0;

    canon_user = auth_canonifyid(user);
    if (!canon_user) {
	syslog(LOG_NOTICE, "badlogin: %s bad userid %s",
	       imapd_clienthost, beautify_string(user));
	printf("%s NO Invalid user %s\r\n", tag, beautify_string(user));
	return;
    }

    if (!strcmp(canon_user, "anonymous")) {
	if (config_getswitch("allowanonymouslogin", 0)) {
	    passwd = beautify_string(passwd);
	    if (strlen(passwd) > 500) passwd[500] = '\0';
	    syslog(LOG_NOTICE, "login: %s anonymous %s",
		   imapd_clienthost, passwd);
	    reply = "Anonymous access granted";
	}
	else {
	    syslog(LOG_NOTICE, "badlogin: %s anonymous login refused",
		   imapd_clienthost);
	    printf("%s NO Anonymous login not permitted\r\n", tag);
	    return;
	}
    }
    else if (login_authenticate(canon_user, passwd, &reply) != 0) {
	if (!reply) reply = "Login incorrect";
	printf("%s NO %s\r\n", tag, reply);
	return;
    }

    auth_setid(canon_user);
    imapd_userid = strsave(canon_user);
    proc_register("imapd", imapd_clienthost, imapd_userid, (char *)0);

    if (!reply) reply = "User logged in";
    
    printf("%s OK %s\r\n", tag, reply);
    return;
};

/*
 * Perform a NOOP command
 */
cmd_noop(tag, cmd)
char *tag;
char *cmd;
{
    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 1);
    }
    printf("%s OK %s completed\r\n", tag, cmd);
};

/*
 * Parse and perform an APPEND command.
 * The command has been parsed up to and including
 * the mailbox name.
 */
#define FLAGGROW 10
cmd_append(tag, name)
char *tag;
char *name;
{
    int c;
    char **flag = 0;
    int nflags = 0, flagalloc = 0;
    static struct buf arg;
    char *p;
    time_t internaldate = time(0);
    unsigned size = 0;
    int r;
    char inboxname[MAX_MAILBOX_PATH];
    struct mailbox mailbox;

    /* Parse flags */
    for (c = getword(&arg); c == ' ' && arg.s[0] != '{'; c = getword(&arg)) {
	if (arg.s[0] == '\\') {
	    lcase(arg.s);
	    if (!strcmp(arg.s, "\\seen") && !strcmp(arg.s, "\\answered") &&
		!strcmp(arg.s, "\\flagged") && !strcmp(arg.s, "\\deleted")) {
		printf("%s BAD Invalid system flag in Append command\r\n",tag);
		if (c != '\n') eatline();
		goto freeflags;
	    }
	}
	else if (!isatom(arg.s)) {
	    printf("%s BAD Invalid flag name %s in Append command\r\n",
		   tag, arg.s);
	    if (c != '\n') eatline();
	    goto freeflags;
	}
	if (nflags == flagalloc) {
	    flagalloc += FLAGGROW;
	    flag = (char **)xrealloc((char *)flag, flagalloc*sizeof(char *));
	}
	flag[nflags++] = strsave(arg.s);
    }

    /* Parse internaldate */
    if (c == '\"') {
	ungetc(c, stdin);
	c = getdatetime(&internaldate);
	if (c != ' ') {
	    printf("%s BAD Invalid date-time in Append command\r\n", tag);
	    if (c != '\n') eatline();
	    goto freeflags;
	}
	c = getword(&arg);
	if (arg.s[0] != '{') {
	    printf("%s BAD Missing required argument to Append command\r\n",
		   tag);
	    if (c != '\n') eatline();
	    goto freeflags;
	}
    }
    else if (arg.s[0] != '{') {
	printf("%s BAD Missing required argument to Append command\r\n",
	       tag);
	if (c != '\n') eatline();
	goto freeflags;
    }

    /* Read size from literal */
    for (p = arg.s + 1; *p && isdigit(*p); p++) {
	size = size*10 + *p - '0';
    }
    if (c == '\r') c = getc(stdin);
    if (*p != '}' || p[1] || c != '\n' || size < 2) {
	printf("%s BAD Invalid literal in Append command\r\n", tag);
	if (c != '\n') eatline();
	goto freeflags;
    }
    
    /* Set up the append */
    if (strcasecmp(name, "inbox") == 0 &&
	!strchr(imapd_userid, '.') &&
	strlen(imapd_userid) + 6 <= MAX_MAILBOX_PATH) {
	strcpy(inboxname, "user.");
	strcat(inboxname, imapd_userid);
	r = append_setup(&mailbox, inboxname, MAILBOX_FORMAT_NORMAL,
			 ACL_INSERT, size);
    }
    else {
	r = append_setup(&mailbox, name, MAILBOX_FORMAT_NORMAL,
			 ACL_INSERT, size);
    }
    if (r) {
	printf("%s NO %sAppend to %s failed: %s\r\n",
	       tag,
	       (r == IMAP_MAILBOX_NONEXISTENT &&
		mboxlist_createmailboxcheck(name, 0, imapd_userisadmin,
					    imapd_userid, (char **)0,
					    (char **)0) == 0)
	       ? "[TRYCREATE] " : "",
	       beautify_string(name), error_message(r));
	goto freeflags;
    }

    /* Tell client to send the message */
    printf("+ go ahead\r\n");
    fflush(stdout);

    /* Perform the rest of the append */
    r = append_fromstream(&mailbox, stdin, size, internaldate, flag, nflags,
			  imapd_userid);
    mailbox_close(&mailbox);

    if (imapd_mailbox) {
	/*
	 * We do a full check, to pick up any \Seen flag we might have
	 * set on the appended message.
	 * XXX full check isn't necessary--test removing it
	 */
	index_check(imapd_mailbox, 0, 1);
    }

    if (r) {
	printf("%s NO Append to %s failed: %s\r\n",
	       tag, beautify_string(name), error_message(r));
    }
    else {
	printf("%s OK Append completed\r\n", tag);
    }

 freeflags:
    while (nflags--) {
	free(flag[nflags]);
    }
    if (flag) free((char *)flag);
}

/*
 * Perform a SELECT/EXAMINE/BBOARD command
 */
cmd_select(tag, cmd, name)
char *tag;
char *cmd;
char *name;
{
    struct mailbox mailbox;
    char inboxname[MAX_MAILBOX_PATH];
    int r = 0;
    int i;
    int usage;
    int doclose = 0;

    inboxname[0] = '\0';

    if (cmd[0] == 'B') {
	/* BBoard namespace is empty */
	r = IMAP_MAILBOX_NONEXISTENT;
    }
    else if (strcasecmp(name, "inbox") == 0 &&
	     !strchr(imapd_userid, '.') &&
	     strlen(imapd_userid) + 6 <= MAX_MAILBOX_PATH) {
	strcpy(inboxname, "user.");
	strcat(inboxname, imapd_userid);
	r = mailbox_open_header(inboxname, &mailbox);
    }
    else {
	r = mailbox_open_header(name, &mailbox);
    }

    if (!r) {
	doclose = 1;
	r = mailbox_open_index(&mailbox);
    }
    if (!r && !(mailbox.myrights & ACL_READ)) {
	r = (mailbox.myrights & ACL_LOOKUP) ?
	  IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
    }
    if (!r && chdir(mailbox.path)) {
	syslog(LOG_ERR, "IOERROR: changing directory to %s: %m", mailbox.path);
	r = IMAP_IOERROR;
    }

    if (r) {
	printf("%s NO %s of %s failed: %s\r\n", tag, cmd,
	       beautify_string(name), error_message(r));
	if (doclose) mailbox_close(&mailbox);
	return;
    }

    if (imapd_mailbox) {
	/* Save \Seen state and close previously open mailbox */
	index_checkseen(imapd_mailbox, 1, 0, imapd_exists);
	mailbox_close(imapd_mailbox);
    }
    mboxstruct = mailbox;
    imapd_mailbox = &mboxstruct;

    index_newmailbox(imapd_mailbox);

    /* Examine command puts mailbox in read-only mode */
    if (cmd[0] == 'E') {
	imapd_mailbox->myrights &= ~(ACL_SEEN|ACL_WRITE|ACL_DELETE);
    }

    if (imapd_mailbox->myrights & ACL_DELETE) {
	/* Warn if mailbox is close to or over quota */
	mailbox_read_quota(imapd_mailbox);
	if (imapd_mailbox->quota_limit > 0) {
	    usage = imapd_mailbox->quota_used * 100 /
	      (imapd_mailbox->quota_limit * QUOTA_UNITS);
	    if (usage >= 100) {
		printf("* NO Mailbox %s is over quota\r\n", name);
	    }
	    else if (usage > config_getint("quotawarn", 90)) {
		printf("* NO Mailbox %s is at %d%% of quota\r\n",
		       name, usage);
	    }
	}
    }

    printf("%s OK [READ-%s] %s completed\r\n", tag,
	   imapd_mailbox->myrights & ACL_WRITE ? "WRITE" : "ONLY", cmd);

    proc_register("imapd", imapd_clienthost, imapd_userid,
		  inboxname[0] ? inboxname : name);
    syslog(LOG_INFO, "open: user %s opened %s", imapd_userid, name);
}
	  
/*
 * Parse and perform a FETCH/UID FETCH command
 * The command has been parsed up to and including
 * the sequence
 */
cmd_fetch(tag, sequence, usinguid)
char *tag;
char *sequence;
int usinguid;
{
    char *cmd = usinguid ? "UID Fetch" : "Fetch";
    static struct buf fetchatt, fieldname;
    int c, i;
    int inlist = 0;
    int fetchitems = 0;
    struct fetchargs fetchargs;
    char *p, *section;

    fetchargs = zerofetchargs;

    c = getword(&fetchatt);
    if (c == '(' && !fetchatt.s[0]) {
	inlist = 1;
	c = getword(&fetchatt);
    }
    for (;;) {
	lcase(fetchatt.s);
	switch (fetchatt.s[0]) {
	case 'a':
	    if (!inlist && !strcmp(fetchatt.s, "all")) {
		fetchitems |= FETCH_ALL;
	    }
	    else goto badatt;
	    break;

	case 'b':
	    if (!strcmp(fetchatt.s, "body")) {
		fetchitems |= FETCH_BODY;
	    }
	    else if (!strcmp(fetchatt.s, "bodystructure")) {
		fetchitems |= FETCH_BODYSTRUCTURE;
	    }
	    else if (!strncmp(fetchatt.s, "body[", 5) ||
		     !strncmp(fetchatt.s, "body.peek[", 10)) {
		p = section = fetchatt.s + 5;
		if (*p == 'p') {
		    p = section += 5;
		}
		else {
		    fetchitems |= FETCH_SETSEEN;
		}
		while (isdigit(*p) || *p == '.') {
		    if (*p == '.' && (p == section || !isdigit(p[1]))) break;
		    p++;
		}
		if (p == section || *p != ']' || p[1]) {
		    printf("%s BAD Invalid body section\r\n", tag);
		    if (c != '\n') eatline();
		    goto freeargs;
		}
		*p = '\0';
		appendstrlist(&fetchargs.bodysections, section);
	    }
	    else goto badatt;
	    break;

	case 'e':
	    if (!strcmp(fetchatt.s, "envelope")) {
		fetchitems |= FETCH_ENVELOPE;
	    }
	    else goto badatt;
	    break;

	case 'f':
	    if (!inlist && !strcmp(fetchatt.s, "fast")) {
		fetchitems |= FETCH_FAST;
	    }
	    else if (!inlist && !strcmp(fetchatt.s, "full")) {
		fetchitems |= FETCH_FULL;
	    }
	    else if (!strcmp(fetchatt.s, "flags")) {
		fetchitems |= FETCH_FLAGS;
	    }
	    else goto badatt;
	    break;

	case 'i':
	    if (!strcmp(fetchatt.s, "internaldate")) {
		fetchitems |= FETCH_INTERNALDATE;
	    }
	    else goto badatt;
	    break;

	case 'r':
	    if (!strcmp(fetchatt.s, "rfc822")) {
		fetchitems |= FETCH_RFC822|FETCH_SETSEEN;
	    }
	    else if (!strcmp(fetchatt.s, "rfc822.header")) {
		fetchitems |= FETCH_HEADER;
	    }
	    else if (!strcmp(fetchatt.s, "rfc822.peek")) {
		fetchitems |= FETCH_RFC822;
	    }
	    else if (!strcmp(fetchatt.s, "rfc822.size")) {
		fetchitems |= FETCH_SIZE;
	    }
	    else if (!strcmp(fetchatt.s, "rfc822.text")) {
		fetchitems |= FETCH_TEXT|FETCH_SETSEEN;
	    }
	    else if (!strcmp(fetchatt.s, "rfc822.text.peek")) {
		fetchitems |= FETCH_TEXT;
	    }
	    else if (!strcmp(fetchatt.s, "rfc822.header.lines") ||
		     !strcmp(fetchatt.s, "rfc822.header.lines.not")) {
		if (c != ' ') {
		    printf("%s BAD Missing required argument to %s %s\r\n",
			   tag, cmd, fetchatt.s);
		    if (c != '\n') eatline();
		    goto freeargs;
		}
		c = getc(stdin);
		if (c != '(') {
		    printf("%s BAD Missing required open parenthesis in %s %s\r\n",
			   tag, cmd, fetchatt.s);
		    if (c != '\n') eatline();
		    goto freeargs;
		}
		do {
		    c = getastring(&fieldname);
		    for (p = fieldname.s; *p; p++) {
			if (*p <= ' ' || *p & 0x80 || *p == ':') break;
		    }
		    if (*p || !*fieldname.s) {
			printf("%s BAD Invalid field-name in %s %s\r\n",
			       tag, cmd, fetchatt.s);
			if (c != '\n') eatline();
			goto freeargs;
		    }
		    appendstrlist(strlen(fetchatt.s) == 19 ?
				  &fetchargs.headers : &fetchargs.headers_not,
				  fieldname.s);
		    if (strlen(fetchatt.s) == 19 &&
			!(fetchitems & FETCH_UNCACHEDHEADER)) {
			for (i=0; i<mailbox_num_cache_header; i++) {
			    if (!strcasecmp(mailbox_cache_header_name[i],
					    fieldname.s)) break;
			}
			if (i == mailbox_num_cache_header) {
			    fetchitems |= FETCH_UNCACHEDHEADER;
			}
		   }
		} while (c == ' ');
		if (c != ')') {
		    printf("%s BAD Missing required close parenthesis in %s %s\r\n",
			   tag, cmd, fetchatt.s);
		    if (c != '\n') eatline();
		    goto freeargs;
		}
		c = getc(stdin);
	    }
	    else goto badatt;
	    break;

	case 'u':
	    if (!strcmp(fetchatt.s, "uid")) {
		fetchitems |= FETCH_UID;
	    }
	    else goto badatt;
	    break;

	default:
	badatt:
	    printf("%s BAD Invalid %s attribute %s\r\n", tag, cmd, fetchatt.s);
	    if (c != '\n') eatline();
	    goto freeargs;
	}

	if (inlist && c == ' ') c = getword(&fetchatt);
	else break;
    }
    
    if (inlist && c == ')') {
	inlist = 0;
	c = getc(stdin);
    }
    if (inlist) {
	printf("%s BAD Missing close parenthesis in %s\r\n", tag, cmd);
	if (c != '\n') eatline();
	goto freeargs;
    }
    if (c == '\r') c = getc(stdin);
    if (c != '\n') {
	printf("%s BAD Unexpected extra arguments to %s\r\n", tag, cmd);
	eatline();
	goto freeargs;
    }

    if (!fetchitems && !fetchargs.bodysections &&
	!fetchargs.headers && !fetchargs.headers_not) {
	printf("%s BAD Missing required argument to %s\r\n", tag, cmd);
	goto freeargs;
    }

    if (usinguid) {
	fetchitems |= FETCH_UID;
	index_check(imapd_mailbox, 1, 0);
    }

    fetchargs.fetchitems = fetchitems;
    index_fetch(imapd_mailbox, sequence, usinguid, &fetchargs);

    printf("%s OK %s completed\r\n", tag, cmd);

 freeargs:
    freestrlist(fetchargs.bodysections);
    freestrlist(fetchargs.headers);
    freestrlist(fetchargs.headers_not);
}

/*
 * Perform a PARTIAL command
 */
cmd_partial(tag, msgno, data, start, count)
char *tag;
char *msgno;
char *data;
char *start;
char *count;
{
    char *p;
    struct fetchargs fetchargs;
    int r;
    char *section;

    fetchargs = zerofetchargs;

    for (p = msgno; *p; p++) {
	if (!isdigit(*p)) break;
    }
    if (*p || !*msgno) {
	printf("%s BAD Invalid message number\r\n", tag);
	return;
    }

    lcase(data);
    if (!strcmp(data, "rfc822")) {
	fetchargs.fetchitems = FETCH_RFC822|FETCH_SETSEEN;
    }
    else if (!strcmp(data, "rfc822.header")) {
	fetchargs.fetchitems = FETCH_HEADER;
    }
    else if (!strcmp(data, "rfc822.peek")) {
	fetchargs.fetchitems = FETCH_RFC822;
    }
    else if (!strcmp(data, "rfc822.text")) {
	fetchargs.fetchitems = FETCH_TEXT|FETCH_SETSEEN;
    }
    else if (!strcmp(data, "rfc822.text.peek")) {
	fetchargs.fetchitems = FETCH_TEXT;
    }
    else if (!strncmp(data, "body[", 5) ||
	     !strncmp(data, "body.peek[", 10)) {
	p = section = data + 5;
	if (*p == 'p') {
	    p = section += 5;
	}
	else {
	    fetchargs.fetchitems = FETCH_SETSEEN;
	}
	while (isdigit(*p) || *p == '.') {
	    if (*p == '.' && (p == section || !isdigit(p[1]))) break;
	    p++;
	}
	if (p == section || *p != ']' || p[1]) {
	    printf("%s BAD Invalid body section\r\n", tag);
	    freestrlist(fetchargs.bodysections);
	    return;
	}
	*p = '\0';
	appendstrlist(&fetchargs.bodysections, section);
    }
    else {
	printf("%s BAD Invalid Partial item\r\n", tag);
	freestrlist(fetchargs.bodysections);
	return;
    }

    for (p = start; *p; p++) {
	if (!isdigit(*p)) break;
	fetchargs.start_octet = fetchargs.start_octet*10 + *p - '0';
    }
    if (*p || !fetchargs.start_octet) {
	printf("%s BAD Invalid starting octet\r\n", tag);
	freestrlist(fetchargs.bodysections);
	return;
    }
    
    for (p = count; *p; p++) {
	if (!isdigit(*p)) break;
	fetchargs.octet_count = fetchargs.octet_count*10 + *p - '0';
    }
    if (*p || !*count) {
	printf("%s BAD Invalid octet count\r\n", tag);
	freestrlist(fetchargs.bodysections);
	return;
    }

    index_fetch(imapd_mailbox, msgno, 0, &fetchargs);

    index_check(imapd_mailbox, 0, 0);

    printf("%s OK Partial completed\r\n", tag);
    freestrlist(fetchargs.bodysections);
}

/*
 * Parse and perform a STORE/UID STORE command
 * The command has been parsed up to and including
 * the FLAGS/+FLAGS/-FLAGS
 */
cmd_store(tag, sequence, operation, usinguid)
char *tag;
char *sequence;
char *operation;
int usinguid;
{
    char *cmd = usinguid ? "UID Store" : "Store";
    struct storeargs storeargs;
    static struct storeargs zerostoreargs;
    static struct buf flagname;
    int c;
    char **flag = 0;
    int nflags = 0, flagalloc = 0;
    int flagsparsed = 0, inlist = 0;
    int r;

    storeargs = zerostoreargs;

    lcase(operation);
    if (!strcmp(operation, "+flags")) {
	storeargs.operation = STORE_ADD;
    }
    else if (!strcmp(operation, "-flags")) {
	storeargs.operation = STORE_REMOVE;
    }
    else if (!strcmp(operation, "flags")) {
	storeargs.operation = STORE_REPLACE;
    }
    else {
	printf("%s BAD Invalid %s attribute\r\n", tag, cmd);
	eatline();
	return;
    }

    for (;;) {
	c = getword(&flagname);
	if (c == '(' && !flagname.s[0] && !flagsparsed && !inlist) {
	    inlist = 1;
	    continue;
	}

	if (flagname.s[0] == '\\') {
	    lcase(flagname.s);
	    if (!strcmp(flagname.s, "\\seen")) {
		storeargs.seen = 1;
	    }
	    else if (!strcmp(flagname.s, "\\answered")) {
		storeargs.system_flags |= FLAG_ANSWERED;
	    }
	    else if (!strcmp(flagname.s, "\\flagged")) {
		storeargs.system_flags |= FLAG_FLAGGED;
	    }
	    else if (!strcmp(flagname.s, "\\deleted")) {
		storeargs.system_flags |= FLAG_DELETED;
	    }
	    else {
		printf("%s BAD Invalid system flag in %s command\r\n",
		       tag, cmd);
		if (c != '\n') eatline();
		goto freeflags;
	    }
	}
	else if (!isatom(flagname.s)) {
	    printf("%s BAD Invalid flag name %s in %s command\r\n",
		   tag, flagname.s, cmd);
	    if (c != '\n') eatline();
	    goto freeflags;
	}
	else {
	    if (nflags == flagalloc) {
		flagalloc += FLAGGROW;
		flag = (char **)xrealloc((char *)flag,
					 flagalloc*sizeof(char *));
	    }
	    flag[nflags++] = strsave(flagname.s);
	}

	flagsparsed++;
	if (c != ' ') break;
    }

    if (inlist && c == ')') {
	inlist = 0;
	c = getc(stdin);
    }
    if (inlist) {
	printf("%s BAD Missing close parenthesis in %s\r\n", tag, cmd);
	if (c != '\n') eatline();
	return;
    }
    if (c == '\r') c = getc(stdin);
    if (c != '\n') {
	printf("%s BAD Unexpected extra arguments to %s\r\n", tag, cmd);
	eatline();
	return;
    }

    if (!flagsparsed) {
	printf("%s BAD Missing required argument to %s\r\n", tag, cmd);
	return;
    }

    r = index_store(imapd_mailbox, sequence, usinguid, &storeargs,
		    flag, nflags);
	
    if (usinguid) {
	index_check(imapd_mailbox, 1, 0);
    }

    if (r) {
	printf("%s NO %s failed: %s\r\n", tag, cmd, error_message(r));
    }
    else {
	printf("%s OK %s completed\r\n", tag, cmd);
    }

 freeflags:
    while (nflags--) {
	free(flag[nflags]);
    }
    if (flag) free((char *)flag);
}

cmd_search(tag, usinguid)
char *tag;
int usinguid;
{
    int c;
    int charset = 0;
    struct searchargs *searchargs;
    static struct searchargs zerosearchargs;

    searchargs = (struct searchargs *)xmalloc(sizeof(struct searchargs));
    *searchargs = zerosearchargs;

    c = getsearchprogram(tag, searchargs, &charset, 1);
    if (c == EOF) {
	eatline();
	freesearchargs(searchargs);
	return;
    }

    if (c == '\r') c = getc(stdin);
    if (c != '\n') {
	printf("%s BAD Unexpected extra arguments to Search\r\n", tag);
	eatline();
	freesearchargs(searchargs);
	return;
    }

    if (charset == -1) {
	printf("%s NO Search failed: %s\r\n", tag,
	       error_message(IMAP_UNRECOGNIZED_CHARSET));
    }
    else {
	index_search(imapd_mailbox, searchargs, usinguid);
	printf("%s OK Search completed\r\n", tag);
    }

    freesearchargs(searchargs);
}

/*
 * Perform a COPY/UID COPY command
 */    
cmd_copy(tag, sequence, name, usinguid)
char *tag;
char *sequence;
char *name;
int usinguid;
{
    char *cmd = usinguid ? "UID Copy" : "Copy";
    int r;
    char inboxname[MAX_MAILBOX_PATH];

    if (strcasecmp(name, "inbox") == 0 &&
	!strchr(imapd_userid, '.') &&
	strlen(imapd_userid) + 6 <= MAX_MAILBOX_PATH) {
	strcpy(inboxname, "user.");
	strcat(inboxname, imapd_userid);
	r = index_copy(imapd_mailbox, sequence, usinguid, inboxname);
    }
    else {
	r = index_copy(imapd_mailbox, sequence, usinguid, name);	
    }

    index_check(imapd_mailbox, usinguid, 0);

    if (r) {
	printf("%s NO %s failed: %s\r\n", tag, cmd, error_message(r));
    }
    else {
	printf("%s OK %s completed\r\n", tag, cmd);
    }
}    

/*
 * Perform an EXPUNGE command
 */
cmd_expunge(tag)
char *tag;
{
    int r;

    if (!(imapd_mailbox->myrights & ACL_DELETE)) r = IMAP_PERMISSION_DENIED;
    else {
	r = mailbox_expunge(imapd_mailbox, 1, (int (*)())0, (char *)0);
    }

    index_check(imapd_mailbox, 0, 0);

    if (r) {
	printf("%s NO Expunge failed: %s\r\n", tag, error_message(r));
    }
    else {
	printf("%s OK Expunge completed\r\n", tag);
    }
}    

/*
 * Perform a CREATE command
 */
cmd_create(tag, name, partition)
char *tag;
char *name;
char *partition;
{
    int r;

    if (partition && !imapd_userisadmin) {
	printf("%s NO Only administrators may specify partition\r\n", tag);
	return;
    }

    if (name[0] && name[strlen(name)-1] == '.') {
	printf("%s OK Create of non-terminal names is unnecessary\r\n", tag);
	return;
    }
    else {
	r = mboxlist_createmailbox(name, MAILBOX_FORMAT_NORMAL, partition,
				   imapd_userisadmin, imapd_userid);
    }

    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 0);
    }

    if (r) {
	printf("%s NO Create failed: %s\r\n", tag, error_message(r));
    }
    else {
	printf("%s OK Create completed\r\n", tag);
    }
}	

/*
 * Perform a DELETE command
 */
cmd_delete(tag, name)
char *tag;
char *name;
{
    int r;

    r = mboxlist_deletemailbox(name, imapd_userisadmin, imapd_userid, 1);

    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 0);
    }

    if (r) {
	printf("%s NO Delete failed: %s\r\n", tag, error_message(r));
    }
    else {
	printf("%s OK Delete completed\r\n", tag);
    }
}	

/*
 * Perform a RENAME command
 */
cmd_rename(tag, oldname, newname, partition)
char *tag;
char *oldname;
char *newname;
char *partition;
{
    int r;

    if (partition && !imapd_userisadmin) {
	printf("%s NO Only administrators may specify partition\r\n", tag);
	return;
    }

    r = mboxlist_renamemailbox(oldname, newname, partition,
			       imapd_userisadmin, imapd_userid);

    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 0);
    }

    if (r) {
	printf("%s NO Rename failed: %s\r\n", tag, error_message(r));
    }
    else {
	printf("%s OK Rename completed\r\n", tag);
    }
}	

/*
 * Perform a FIND command
 */
cmd_find(tag, namespace, pattern)
char *tag;
char *namespace;
char *pattern;
{
    lcase(namespace);
    if (!strcmp(namespace, "mailboxes")) {
	mboxlist_findsub(pattern, imapd_userisadmin, imapd_userid,
			 mailboxdata);
    }
    else if (!strcmp(namespace, "all.mailboxes")) {
	mboxlist_findall(pattern, imapd_userisadmin, imapd_userid,
			 mailboxdata);
    }
    else if (!strcmp(namespace, "bboards")
	     || !strcmp(namespace, "all.bboards")) {
	;
    }
    else {
	printf("%s BAD Invalid FIND subcommand\r\n", tag);
	return;
    }
    printf("%s OK Find completed\r\n", tag);
}
  
/*
 * Perform a SUBSCRIBE (add is nonzero) or
 * UNSUBSCRIBE (add is zero) command
 */
cmd_changesub(tag, namespace, name, add)
char *tag;
char *namespace;
char *name;
int add;
{
    int r;

    if (namespace) lcase(namespace);
    if (!namespace || !strcmp(namespace, "mailbox")) {
	r = mboxlist_changesub(name, imapd_userid, add);
    }
    else if (!strcmp(namespace, "bboard")) {
	r = add ? IMAP_MAILBOX_NONEXISTENT : IMAP_MAILBOX_UNSUBSCRIBED;
    }
    else {
	printf("%s BAD Invalid %s subcommand\r\n", tag,
	       add ? "Subscribe" : "Unsubscribe");
	return;
    }

    if (r) {
	printf("%s NO %s failed: %s\r\n", tag,
	       add ? "Subscribe" : "Unsubscribe", error_message(r));
    }
    else {
	printf("%s OK %s completed\r\n", tag,
	       add ? "Subscribe" : "Unsubscribe");
    }
}

/*
 * Perform a GETACL command
 */
cmd_getacl(tag, namespace, name)
char *tag;
char *namespace;
char *name;
{
    char inboxname[MAX_MAILBOX_PATH];
    int r, access;
    char *acl;
    char *rights, *nextid;

    lcase(namespace);
    if (!strcmp(namespace, "bboard")) {
	r = IMAP_MAILBOX_NONEXISTENT;
    }
    else if (!strcmp(namespace, "mailbox")) {
	if (strcasecmp(name, "inbox") == 0 &&
	    !strchr(imapd_userid, '.') &&
	    strlen(imapd_userid) + 6 <= MAX_MAILBOX_PATH) {
	    strcpy(inboxname, "user.");
	    strcat(inboxname, imapd_userid);
	    r = mboxlist_lookup(inboxname, (char **)0, &acl);
	}
	else {
	    r = mboxlist_lookup(name, (char **)0, &acl);
	}
    }
    else {
	printf("%s BAD Invalid Getacl subcommand\r\n", tag);
	return;
    }

    if (!r) {
	access = acl_myrights(acl);
	if (imapd_userisadmin) {
	    access |= ACL_ADMIN;
	}
	else if (!strchr(imapd_userid, '.') &&
		 !strncasecmp(name, "user.", 5) &&
		 !strncasecmp(name+5, imapd_userid, strlen(imapd_userid)) &&
		 name[5+strlen(imapd_userid)] == '.') {
	    access |= ACL_ADMIN;
	}

	if (!(access&(ACL_READ|ACL_ADMIN))) {
	    r = (access&ACL_LOOKUP) ?
	      IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	}
    }
    if (r) {
	printf("%s NO Getacl failed: %s\r\n", tag, error_message(r));
	return;
    }
    
    while (acl) {
	rights = strchr(acl, '\t');
	if (!rights) break;
	*rights++ = '\0';

	nextid = strchr(rights, '\t');
	if (!nextid) break;
	*nextid++ = '\0';

	printf("* ACL MAILBOX ");
	printastring(name);
	printf(" ");
	printastring(acl);
	printf(" ");
	printastring(rights);
	printf("\r\n");
	acl = nextid;
    }
    printf("%s OK Getacl completed\r\n", tag);
}

/*
 * Perform a MYRIGHTS command
 */
cmd_myrights(tag, namespace, name)
char *tag;
char *namespace;
char *name;
{
    char inboxname[MAX_MAILBOX_PATH];
    int r, rights;
    char *acl;
    char str[ACL_MAXSTR];

    lcase(namespace);
    if (!strcmp(namespace, "bboard")) {
	r = IMAP_MAILBOX_NONEXISTENT;
    }
    else if (!strcmp(namespace, "mailbox")) {
	if (strcasecmp(name, "inbox") == 0 &&
	    !strchr(imapd_userid, '.') &&
	    strlen(imapd_userid) + 6 <= MAX_MAILBOX_PATH) {
	    strcpy(inboxname, "user.");
	    strcat(inboxname, imapd_userid);
	    r = mboxlist_lookup(inboxname, (char **)0, &acl);
	}
	else {
	    r = mboxlist_lookup(name, (char **)0, &acl);
	}
    }
    else {
	printf("%s BAD Invalid Myrights subcommand\r\n", tag);
	return;
    }

    if (!r) {
	rights = acl_myrights(acl);

	/* Add in implicit rights */
	if (imapd_userisadmin || !strcasecmp(name, "inbox")) {
	    rights |= ACL_LOOKUP|ACL_ADMIN;
	}
	if (!strchr(imapd_userid, '.') &&
	    !strncasecmp(name, "user.", 5) &&
	    !strncasecmp(name+5, imapd_userid, strlen(imapd_userid)) &&
	    name[5+strlen(imapd_userid)] == '.') {
	    rights |= ACL_LOOKUP|ACL_ADMIN;
	}

	if (!rights) {
	    r = IMAP_MAILBOX_NONEXISTENT;
	}
    }
    if (r) {
	printf("%s NO Myrights failed: %s\r\n", tag, error_message(r));
	return;
    }
    
    printf("* MYRIGHTS MAILBOX ");
    printastring(name);
    printf(" ");
    printastring(acl_masktostr(rights, str));
    printf("\r\n%s OK Myrights completed\r\n", tag);
}

/*
 * Perform a SETACL command
 */
cmd_setacl(tag, namespace, name, identifier, rights)
char *tag;
char *namespace;
char *name;
char *identifier;
char *rights;
{
    int r;
    char *cmd = rights ? "Setacl" : "Deleteacl";

    lcase(namespace);
    if (!strcmp(namespace, "bboard")) {
	r = IMAP_MAILBOX_NONEXISTENT;
    }
    else if (!strcmp(namespace, "mailbox")) {
	r = mboxlist_setacl(name, identifier, rights,
			    imapd_userisadmin, imapd_userid);
    }
    else {
	printf("%s BAD Invalid %s subcommand\r\n", tag, cmd);
	return;
    }

    if (r) {
	printf("%s NO %s failed: %s\r\n", tag, cmd, error_message(r));
	return;
    }
    
    printf("%s OK %s completed\r\n", tag, cmd);
}

/*
 * Parse a word
 * (token not containing whitespace, parens, or double quotes)
 */
#define BUFGROWSIZE 100
int getword(buf)
struct buf *buf;
{
    int c;
    int len = 0;

    if (buf->alloc == 0) {
	buf->alloc = BUFGROWSIZE;
	buf->s = xmalloc(buf->alloc+1);
    }
	
    for (;;) {
	c = getc(stdin);
	if (c == EOF || isspace(c) || c == '(' || c == ')' || c == '\"') {
	    buf->s[len] = '\0';
	    return c;
	}
	if (len == buf->alloc) {
	    buf->alloc += BUFGROWSIZE;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
	}
	buf->s[len++] = c;
    }
}

/*
 * Parse an astring
 * (atom, quoted-string, or literal)
 */
int getastring(buf)
struct buf *buf;
{
    int c;
    int i, len = 0;

    if (buf->alloc == 0) {
	buf->alloc = BUFGROWSIZE;
	buf->s = xmalloc(buf->alloc+1);
    }
	
    c = getc(stdin);
    switch (c) {
    case EOF:
    case ' ':
    case '(':
    case ')':
    case '\r':
    case '\n':
	/* Invalid starting character */
	buf->s[0] = '\0';
	if (c != EOF) ungetc(c, stdin);
	return EOF;

    default:
	/*
	 * Atom -- server is liberal in accepting specials other
	 * than whitespace, parens, or double quotes
	 */
	for (;;) {
	    if (c == EOF || isspace(c) || c == '(' || c == ')' || c == '\"') {
		buf->s[len] = '\0';
		return c;
	    }
	    if (len == buf->alloc) {
		buf->alloc += BUFGROWSIZE;
		buf->s = xrealloc(buf->s, buf->alloc+1);
	    }
	    buf->s[len++] = c;
	    c = getc(stdin);
	}
	
    case '\"':
	/*
	 * Quoted-string.  Server is liberal in accepting qspecials
	 * other than double-quote, CR, and LF.
	 */
	for (;;) {
	    c = getc(stdin);
	    if (c == '\"') {
		buf->s[len] = '\0';
		return getc(stdin);
	    }
	    if (c == EOF || c == '\r' || c == '\n') {
		buf->s[len] = '\0';
		if (c != EOF) ungetc(c, stdin);
		return EOF;
	    }
	    if (len == buf->alloc) {
		buf->alloc += BUFGROWSIZE;
		buf->s = xrealloc(buf->s, buf->alloc+1);
	    }
	    buf->s[len++] = c;
	}
    case '{':
	/* Literal */
	buf->s[0] = '\0';
	while ((c = getc(stdin)) != EOF && isdigit(c)) {
	    len = len*10 + c - '0';
	}
	if (c != '}') {
	    if (c != EOF) ungetc(c, stdin);
	    return EOF;
	}
	if (len == 0) return EOF;
	c = getc(stdin);
	if (c == '\r') c = getc(stdin);
	if (c != '\n') {
	    if (c != EOF) ungetc(c, stdin);
	    return EOF;
	}
	if (len >= buf->alloc) {
	    buf->alloc = len+1;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
	}
	printf("+ go ahead\r\n");
	fflush(stdout);
	for (i = 0; i < len; i++) {
	    c = getc(stdin);
	    if (c == EOF) {
		buf->s[len] = '\0';
		return EOF;
	    }
	    buf->s[i] = c;
	}
	buf->s[len] = '\0';
	if (strlen(buf->s) != len) return EOF; /* Disallow imbedded NUL */
	return getc(stdin);
    }
}

/*
 * Parse a search program
 */
int getsearchprogram(tag, searchargs, charset, parsecharset)
char *tag;
struct searchargs *searchargs;
int *charset;
int parsecharset;
{
    int c;

    do {
	c = getsearchcriteria(tag, searchargs, charset, parsecharset);
	parsecharset = 0;
    } while (c == ' ');
    return c;
}

/*
 * Parse a search criteria
 */
int getsearchcriteria(tag, searchargs, charset, parsecharset)
char *tag;
struct searchargs *searchargs;
int *charset;
int parsecharset;
{
    static struct buf criteria, arg;
    static struct searchargs zerosearchargs;
    struct searchargs *sub1, *sub2;
    char *p, *str;
    int c, i, flag, size;
    time_t start, end;

    c = getword(&criteria);
    lcase(criteria.s);
    switch (criteria.s[0]) {
    case '\0':
	if (c != '(') goto badcri;
	c = getsearchprogram(tag, searchargs, charset, 0);
	if (c == EOF) return EOF;
	if (c != ')') {
	    printf("%s BAD Missing required close paren in Search command\r\n",
		   tag);
	    if (c != EOF) ungetc(c, stdin);
	    return EOF;
	}
	c = getc(stdin);
	break;

    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case '*':
	if (issequence(criteria.s)) {
	    appendstrlist(&searchargs->sequence, criteria.s);
	}
	else goto badcri;
	break;

    case 'a':
	if (!strcmp(criteria.s, "answered")) {
	    searchargs->system_flags_set |= FLAG_ANSWERED;
	}
	else if (!strcmp(criteria.s, "all")) {
	    break;
	}
	else goto badcri;
	break;

    case 'b':
	if (!strcmp(criteria.s, "before")) {
	    if (c != ' ') goto missingarg;		
	    c = getdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->before || searchargs->before > start) {
		searchargs->before = start;
	    }
	}
	else if (!strcmp(criteria.s, "bcc")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset);
	    if (strchr(str, EMPTY_CHAR)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlist(&searchargs->bcc, str);
	    }
	}
	else if (!strcmp(criteria.s, "body")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset);
	    if (strchr(str, EMPTY_CHAR)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlist(&searchargs->body, str);
	    }
	}
	else goto badcri;
	break;

    case 'c':
	if (!strcmp(criteria.s, "cc")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset);
	    if (strchr(str, EMPTY_CHAR)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlist(&searchargs->cc, str);
	    }
	}
	else if (parsecharset && !strcmp(criteria.s, "charset")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c != ' ') goto missingarg;
	    lcase(arg.s);
	    *charset = charset_lookupname(arg.s);
	}
	else goto badcri;
	break;

    case 'd':
	if (!strcmp(criteria.s, "deleted")) {
	    searchargs->system_flags_set |= FLAG_DELETED;
	}
	else goto badcri;
	break;

    case 'f':
	if (!strcmp(criteria.s, "flagged")) {
	    searchargs->system_flags_set |= FLAG_FLAGGED;
	}
	else if (!strcmp(criteria.s, "from")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset);
	    if (strchr(str, EMPTY_CHAR)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlist(&searchargs->from, str);
	    }
	}
	else goto badcri;
	break;

    case 'h':
	if (!strcmp(criteria.s, "header")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c != ' ') goto missingarg;
	    appendstrlist(&searchargs->header_name, arg.s);
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset);
	    if (strchr(str, EMPTY_CHAR)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlist(&searchargs->header, str);
	    }
	}
	else goto badcri;
	break;

    case 'k':
	if (!strcmp(criteria.s, "keyword")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(&arg);
	    if (!isatom(arg.s)) goto badflag;
	    lcase(arg.s);
	    for (flag=0; flag < MAX_USER_FLAGS; flag++) {
		if (imapd_mailbox->flagname[flag] &&
		    !strcmp(imapd_mailbox->flagname[flag], arg.s)) break;
	    }
	    if (flag == MAX_USER_FLAGS) {
		searchargs->recent_set = searchargs->recent_unset = 1;
		break;
	    }
	    searchargs->user_flags_set[flag/32] |= 1<<(flag&31);
	}
	else goto badcri;
	break;

    case 'l':
	if (!strcmp(criteria.s, "larger")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(&arg);
	    size = 0;
	    for (p = arg.s; *p && isdigit(*p); p++) {
		size = size * 10 + *p - '0';
	    }
	    if (!arg.s || *p) goto badnumber;
	    if (size > searchargs->larger) searchargs->larger = size;
	}
	else goto badcri;
	break;

    case 'n':
	if (!strcmp(criteria.s, "not")) {
	    if (c != ' ') goto missingarg;		
	    sub1 = (struct searchargs *)xmalloc(sizeof(struct searchargs));
	    *sub1 = zerosearchargs;
	    c = getsearchcriteria(tag, sub1, charset, 0);
	    if (c == EOF) {
		freesearchargs(sub1);
		return EOF;
	    }

#if 0 /* Have to pay attenton to DeMorgan's Law */
	    /* Pull the trivial stuff into searchargs */
	    if (sub1->smaller && sub1->smaller > searchargs->larger)
	      searchargs->larger = sub1->smaller - 1;
	    if (sub1->larger && sub1->larger < searchargs->smaller)
	      searchargs->smaller = sub1->larger + 1;
	    if (sub1->before && sub1->before > searchargs->after)
	      searchargs->after = sub1->before - 1;
	    if (sub1->after && sub1->after < searchargs->before)
	      searchargs->before = sub1->after + 1;
	    if (sub1->sentbefore && sub1->sentbefore > searchargs->sentafter)
	      searchargs->sentafter = sub1->sentbefore - 1;
	    if (sub1->sentafter && sub1->sentafter < searchargs->sentbefore)
	      searchargs->sentbefore = sub1->sentafter + 1;
	    searchargs->system_flags_set |= sub1->system_flags_unset;
	    searchargs->system_flags_unset |= sub1->system_flags_set;
	    searchargs->peruser_flags_set |= sub1->peruser_flags_unset;
	    searchargs->peruser_flags_unset |= sub1->peruser_flags_set;
	    searchargs->recent_set |= sub1->recent_unset;
	    searchargs->recent_unset |= sub1->recent_set;
	    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
		searchargs->user_flags_set[i] |= sub1->user_flags_unset[i];
		searchargs->user_flags_unset[i] |= sub1->user_flags_set[i];
		sub1->user_flags_set[i] = sub1->user_flags_unset[i] = 0;
	    }

	    /* See if we have to append this to the sublist */
	    if (sub1->sequence || sub1->uidsequence || sub1->from ||
		sub1->to || sub1->cc || sub1->bcc || sub1->subject ||
		sub1->body || sub1->text || sub1->header || sub1->sublist) {
 
		/* Clear out the trival stuff we moved up */
		sub1->smaller = sub1->larger = 0;
		sub1->before = sub1->after = 0;
		sub1->sentbefore = sub1->sentafter = 0;
		sub1->system_flags_set = sub1->system_flags_unset = 0;
		sub1->peruser_flags_set = sub1->peruser_flags_unset = 0;
		sub1->recent_set = sub1->recent_unset = 0;
		appendsearchargs(searchargs, sub1, (struct searchargs *)0);
	    }
	    else freesearchargs(sub1);
#else
	    appendsearchargs(searchargs, sub1, (struct searchargs *)0);
#endif
	}
	else if (!strcmp(criteria.s, "new")) {
	    searchargs->peruser_flags_unset = 1;
	    searchargs->recent_set = 1;
	}
	else goto badcri;
	break;

    case 'o':
	if (!strcmp(criteria.s, "or")) {
	    if (c != ' ') goto missingarg;		
	    sub1 = (struct searchargs *)xmalloc(sizeof(struct searchargs));
	    *sub1 = zerosearchargs;
	    c = getsearchcriteria(tag, sub1, charset, 0);
	    if (c == EOF) {
		freesearchargs(sub1);
		return EOF;
	    }
	    if (c != ' ') goto missingarg;		
	    sub2 = (struct searchargs *)xmalloc(sizeof(struct searchargs));
	    *sub2 = zerosearchargs;
	    c = getsearchcriteria(tag, sub2, charset, 0);
	    if (c == EOF) {
		freesearchargs(sub1);
		freesearchargs(sub2);
		return EOF;
	    }
	    appendsearchargs(searchargs, sub1, sub2);
	}
	else if (!strcmp(criteria.s, "old")) {
	    searchargs->recent_unset = 1;
	}
	else if (!strcmp(criteria.s, "on")) {
	    if (c != ' ') goto missingarg;		
	    c = getdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->before || searchargs->before > end) {
		searchargs->before = end;
	    }
	    if (!searchargs->after || searchargs->after < start) {
		searchargs->after = start;
	    }
	}
	else goto badcri;
	break;

    case 'r':
	if (!strcmp(criteria.s, "recent")) {
	    searchargs->recent_set = 1;
	}
	else goto badcri;
	break;

    case 's':
	if (!strcmp(criteria.s, "seen")) {
	    searchargs->peruser_flags_set = 1;
	}
	else if (!strcmp(criteria.s, "sentbefore")) {
	    if (c != ' ') goto missingarg;		
	    c = getdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->sentbefore || searchargs->sentbefore > start) {
		searchargs->sentbefore = start;
	    }
	}
	else if (!strcmp(criteria.s, "senton")) {
	    if (c != ' ') goto missingarg;		
	    c = getdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->sentbefore || searchargs->sentbefore > end) {
		searchargs->sentbefore = end;
	    }
	    if (!searchargs->sentafter || searchargs->sentafter < start) {
		searchargs->sentafter = start;
	    }
	}
	else if (!strcmp(criteria.s, "sentsince")) {
	    if (c != ' ') goto missingarg;		
	    c = getdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->sentafter || searchargs->sentafter < start) {
		searchargs->sentafter = start;
	    }
	}
	else if (!strcmp(criteria.s, "since")) {
	    if (c != ' ') goto missingarg;		
	    c = getdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->after || searchargs->after < start) {
		searchargs->after = start;
	    }
	}
	else if (!strcmp(criteria.s, "smaller")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(&arg);
	    size = 0;
	    for (p = arg.s; *p && isdigit(*p); p++) {
		size = size * 10 + *p - '0';
	    }
	    if (!arg.s || *p) goto badnumber;
	    if (size == 0) size = 1;
	    if (!searchargs->smaller || size < searchargs->smaller)
	      searchargs->smaller = size;
	}
	else if (!strcmp(criteria.s, "subject")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset);
	    if (strchr(str, EMPTY_CHAR)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlist(&searchargs->subject, str);
	    }
	}
	else goto badcri;
	break;

    case 't':
	if (!strcmp(criteria.s, "to")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset);
	    if (strchr(str, EMPTY_CHAR)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlist(&searchargs->to, str);
	    }
	}
	else if (!strcmp(criteria.s, "text")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset);
	    if (strchr(str, EMPTY_CHAR)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlist(&searchargs->text, str);
	    }
	}
	else goto badcri;
	break;

    case 'u':
	if (!strcmp(criteria.s, "uid")) {
	    if (c != ' ') goto missingarg;
	    c = getword(&arg);
	    if (!issequence(arg.s)) goto badcri;
	    appendstrlist(&searchargs->uidsequence, arg.s);
	}
	else if (!strcmp(criteria.s, "unseen")) {
	    searchargs->peruser_flags_unset = 1;
	}
	else if (!strcmp(criteria.s, "unanswered")) {
	    searchargs->system_flags_unset |= FLAG_ANSWERED;
	}
	else if (!strcmp(criteria.s, "undeleted")) {
	    searchargs->system_flags_unset |= FLAG_DELETED;
	}
	else if (!strcmp(criteria.s, "unflagged")) {
	    searchargs->system_flags_unset |= FLAG_FLAGGED;
	}
	else if (!strcmp(criteria.s, "unkeyword")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(&arg);
	    if (!isatom(arg.s)) goto badflag;
	    lcase(arg.s);
	    for (flag=0; flag < MAX_USER_FLAGS; flag++) {
		if (imapd_mailbox->flagname[flag] &&
		    !strcmp(imapd_mailbox->flagname[flag], arg.s)) break;
	    }
	    if (flag != MAX_USER_FLAGS) {
		searchargs->user_flags_unset[flag/32] |= 1<<(flag&31);
	    }
	}
	else goto badcri;
	break;

    default:
    badcri:
	printf("%s BAD Invalid Search criteria\r\n", tag);
	if (c != EOF) ungetc(c, stdin);
	return EOF;
    }

    return c;

 missingarg:
    printf("%s BAD Missing required argument to Search %s\r\n",
	   tag, criteria.s);
    if (c != EOF) ungetc(c, stdin);
    return EOF;

 badflag:
    printf("%s BAD Invalid flag name %s in Search command\r\n",
	   tag, arg.s);
    if (c != EOF) ungetc(c, stdin);
    return EOF;

 baddate:
    printf("%s BAD Invalid date in Search command\r\n", tag);
    if (c != EOF) ungetc(c, stdin);
    return EOF;

 badnumber:
    printf("%s BAD Invalid number in Search command\r\n", tag);
    if (c != EOF) ungetc(c, stdin);
    return EOF;
}

/*
 * Parse a "date", for SEARCH criteria
 * The time_t's pointed to by 'start' and 'end' are set to the
 * times of the start and end of the parsed date.
 */
int getdate(start, end)
time_t *start, *end;
{
    int c;
    struct tm tm;
    static struct tm zerotm;
    int quoted = 0;
    char month[4];

    tm = zerotm;

    c = getc(stdin);
    if (c == '\"') {
	quoted++;
	c = getc(stdin);
    }

    /* Day of month */
    if (!isdigit(c)) goto baddate;
    tm.tm_mday = c - '0';
    c = getc(stdin);
    if (isdigit(c)) {
	tm.tm_mday = tm.tm_mday * 10 + c - '0';
	c = getc(stdin);
    }
    
    if (c != '-') goto baddate;
    c = getc(stdin);

    /* Month name */
    if (!isalpha(c)) goto baddate;
    month[0] = c;
    c = getc(stdin);
    if (!isalpha(c)) goto baddate;
    month[1] = c;
    c = getc(stdin);
    if (!isalpha(c)) goto baddate;
    month[2] = c;
    c = getc(stdin);
    month[3] = '\0';
    lcase(month);

    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcmp(month, monthname[tm.tm_mon])) break;
    }
    if (tm.tm_mon == 12) goto baddate;

    if (c != '-') goto baddate;
    c = getc(stdin);

    /* Year */
    if (!isdigit(c)) goto baddate;
    tm.tm_year = c - '0';
    c = getc(stdin);
    if (!isdigit(c)) goto baddate;
    tm.tm_year = tm.tm_year * 10 + c - '0';
    c = getc(stdin);
    if (isdigit(c)) {
	if (tm.tm_year < 19) goto baddate;
	tm.tm_year -= 19;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = getc(stdin);
	if (!isdigit(c)) goto baddate;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = getc(stdin);
    }

    if (quoted) {
	if (c != '\"') goto baddate;
	c = getc(stdin);
    }

    tm.tm_isdst = -1;
    *start = mktime(&tm);

    tm.tm_sec = tm.tm_min = 59;
    tm.tm_hour = 23;
    *end = mktime(&tm);

    return c;

 baddate:
    ungetc(c, stdin);
    return EOF;
}

/*
 * Parse a date_time, for the APPEND command
 */
int getdatetime(date)
time_t *date;
{
    int c;
    struct tm tm, *ltm;
    int old_format = 0;
    static struct tm zerotm;
    char month[4], zone[4], *p;
    int zone_off;

    tm = zerotm;

    c = getc(stdin);
    if (c != '\"') goto baddate;
    
    /* Day of month */
    c = getc(stdin);
    if (c == ' ') c = '0';
    if (!isdigit(c)) goto baddate;
    tm.tm_mday = c - '0';
    c = getc(stdin);
    if (isdigit(c)) {
	tm.tm_mday = tm.tm_mday * 10 + c - '0';
	c = getc(stdin);
    }
    
    if (c != '-') goto baddate;
    c = getc(stdin);

    /* Month name */
    if (!isalpha(c)) goto baddate;
    month[0] = c;
    c = getc(stdin);
    if (!isalpha(c)) goto baddate;
    month[1] = c;
    c = getc(stdin);
    if (!isalpha(c)) goto baddate;
    month[2] = c;
    c = getc(stdin);
    month[3] = '\0';
    lcase(month);

    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcmp(month, monthname[tm.tm_mon])) break;
    }
    if (tm.tm_mon == 12) goto baddate;

    if (c != '-') goto baddate;
    c = getc(stdin);

    /* Year */
    if (!isdigit(c)) goto baddate;
    tm.tm_year = c - '0';
    c = getc(stdin);
    if (!isdigit(c)) goto baddate;
    tm.tm_year = tm.tm_year * 10 + c - '0';
    c = getc(stdin);
    if (isdigit(c)) {
	if (tm.tm_year < 19) goto baddate;
	tm.tm_year -= 19;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = getc(stdin);
	if (!isdigit(c)) goto baddate;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = getc(stdin);
    }
    else old_format++;

    /* Hour */
    if (c != ' ') goto baddate;
    c = getc(stdin);
    if (!isdigit(c)) goto baddate;
    tm.tm_hour = c - '0';
    c = getc(stdin);
    if (!isdigit(c)) goto baddate;
    tm.tm_hour = tm.tm_hour * 10 + c - '0';
    c = getc(stdin);
    if (tm.tm_hour > 23) goto baddate;

    /* Minute */
    if (c != ':') goto baddate;
    c = getc(stdin);
    if (!isdigit(c)) goto baddate;
    tm.tm_min = c - '0';
    c = getc(stdin);
    if (!isdigit(c)) goto baddate;
    tm.tm_min = tm.tm_min * 10 + c - '0';
    c = getc(stdin);
    if (tm.tm_min > 59) goto baddate;

    /* Second */
    if (c != ':') goto baddate;
    c = getc(stdin);
    if (!isdigit(c)) goto baddate;
    tm.tm_sec = c - '0';
    c = getc(stdin);
    if (!isdigit(c)) goto baddate;
    tm.tm_sec = tm.tm_sec * 10 + c - '0';
    c = getc(stdin);
    if (tm.tm_min > 60) goto baddate;

    /* Time zone */
    if (old_format) {
	if (c != '-') goto baddate;
	c = getc(stdin);

	if (!isalpha(c)) goto baddate;
	zone[0] = c;
	c = getc(stdin);

	if (c == '\"') {
	    /* Military (single-char) zones */
	    zone[1] = '\0';
	    lcase(zone);
	    if (zone[0] <= 'm') {
		zone_off = (zone[0] - 'a' + 1)*60;
	    }
	    else if (zone[0] < 'z') {
		zone_off = ('m' - zone[0])*60;
	    }
	    else zone_off = 0;
	}
	else {
	    /* UT (universal time) */
	    zone[1] = c;
	    c = getc(stdin);
	    if (c == '\"') {
		zone[2] = '\0';
		lcase(zone);
		if (!strcmp(zone, "ut")) goto baddate;
		zone_off = 0;
	    }
	    else {
		/* 3-char time zone */
		zone[2] = c;
		c = getc(stdin);
		if (c != '\"') goto baddate;
		zone[3] = '\0';
		lcase(zone);
		p = strchr("aecmpyhb", zone[0]);
		if (c != '\"' || zone[2] != 't' || !p) goto baddate;
		zone_off = (strlen(p) - 12)*60;
		if (zone[1] == 'd') zone_off -= 60;
		else if (zone[1] != 's') goto baddate;
	    }
	}
    }
    else {
	if (c != ' ') goto baddate;
	c = getc(stdin);

	if (c != '+' && c != '-') goto baddate;
	zone[0] = c;

	c = getc(stdin);
	if (!isdigit(c)) goto baddate;
	zone_off = c - '0';
	c = getc(stdin);
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 10 + c - '0';
	c = getc(stdin);
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 6 + c - '0';
	c = getc(stdin);
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 10 + c - '0';

	if (zone[0] == '-') zone_off = -zone_off;

	c = getc(stdin);
	if (c != '\"') goto baddate;

    }

    c = getc(stdin);

    tm.tm_isdst = -1;
    *date = mktime(&tm);
    ltm = localtime(date);
    *date += ltm->tm_gmtoff - zone_off*60;

    return c;

 baddate:
    ungetc(c, stdin);
    return EOF;
}
	
/*
 * Return nonzero if 's' matches the grammar for an atom
 */
int isatom(s)
char *s;
{
    if (!*s) return 0;
    for (; *s; s++) {
	if (*s & 0x80 || *s < 0x1f || *s == 0x7f ||
	    *s == ' ' || *s == '{' || *s == '(' || *s == ')' ||
	    *s == '\"' || *s == '%' || *s == '\\') return 0;
    }
    return 1;
}

/*
 * Return nonzero if 's' matches the grammar for a sequence
 */
int issequence(s)
char *s;
{
    int c;
    int len = 0;
    int sawcolon = 0;

    while (c = *s) {
	if (c == ',') {
	    if (!len) return 0;
	    if (!isdigit(s[-1]) && s[-1] != '*') return 0;
	    sawcolon = 0;
	}
	else if (c == ':') {
	    if (sawcolon || !len) return 0;
	    if (!isdigit(s[-1]) && s[-1] != '*') return 0;
	    sawcolon = 1;
	}
	else if (c == '*') {
	    if (len && s[-1] != ',' && s[-1] != ':') return 0;
	    if (isdigit(s[1])) return 0;
	}
	else if (!isdigit(c)) {
	    return 0;
	}
	s++;
	len++;
    }
    if (len == 0) return 0;
    if (!isdigit(s[-1]) && s[-1] != '*') return 0;
    return 1;
}

/*
 * Eat characters up to and including the next newline
 */
eatline()
{
    char c;

    while ((c = getc(stdin)) != EOF && c != '\n');
}

/*
 * Print 's' as an atom, quoted-string, or literal
 */
printastring(s)
char *s;
{
    char *p;

    if (isatom(s)) {
	printf("%s", s);
	return;
    }

    /* Look for any non-QCHAR characters */
    for (p = s; *p; p++) {
	if (*p & 0x80 || *p == '\r' || *p == '\n'
	    || *p == '\"' || *p == '%' || *p == '\\') break;
    }

    if (*p) {
	printf("{%d}\r\n%s", strlen(s), s);
    }
    else {
	printf("\"%s\"", s);
    }
}

/*
 * Append 's' to the strlist 'l'.
 */
appendstrlist(l, s)
struct strlist **l;
char *s;
{
    struct strlist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct strlist *)xmalloc(sizeof(struct strlist));
    (*tail)->s = strsave(s);
    (*tail)->next = 0;
}

/*
 * Free the strlist 'l'
 */
freestrlist(l)
struct strlist *l;
{
    struct strlist *n;

    while (l) {
	n = l->next;
	free(l->s);
	free((char *)l);
	l = n;
    }
}

/*
 * Append the searchargs 's1' and 's2' to the sublist of 's'
 */
appendsearchargs(s, s1, s2)
struct searchargs *s, *s1, *s2;
{
    struct searchsub **tail = &s->sublist;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct searchsub *)xmalloc(sizeof(struct searchsub));
    (*tail)->sub1 = s1;
    (*tail)->sub2 = s2;
    (*tail)->next = 0;
}


/*
 * Free the searchargs 's'
 */
freesearchargs(s)
struct searchargs *s;
{
    struct searchsub *sub, *n;

    if (!s) return;

    freestrlist(s->sequence);
    freestrlist(s->uidsequence);
    freestrlist(s->from);
    freestrlist(s->to);
    freestrlist(s->cc);
    freestrlist(s->bcc);
    freestrlist(s->subject);
    freestrlist(s->body);
    freestrlist(s->text);
    freestrlist(s->header_name);
    freestrlist(s->header);

    for (sub = s->sublist; sub; sub = n) {
	n = sub->next;
	freesearchargs(sub->sub1);
	freesearchargs(sub->sub2);
	free(sub);
    }
    free(s);
}

/*
 * Issue a MAILBOX untagged response
 */
static int mailboxdata(name)
char *name;
{
    printf("* MAILBOX %s\r\n", name);
    return 0;
}
