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
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <syslog.h>
#include <com_err.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "acl.h"
#include "util.h"
#include "auth.h"
#include "acte.h"
#include "config.h"
#include "version.h"
#include "charset.h"
#include "sysexits.h"
#include "imap_err.h"
#include "mailbox.h"
#include "imapd.h"
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
struct sockaddr_in imapd_localaddr, imapd_remoteaddr;
int imapd_haveaddr = 0;
char imapd_clienthost[250] = "[local]";
struct protstream *imapd_out, *imapd_in;

static struct mailbox mboxstruct;

static struct fetchargs zerofetchargs;

static char *monthname[] = {
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec"
};

static int mailboxdata(), listdata(), lsubdata();

main(argc, argv, envp)
int argc;
char **argv;
char **envp;
{
    char hostname[MAXHOSTNAMELEN+1];
    int salen;
    struct hostent *hp;
    int timeout;

    imapd_in = prot_new(0, 0);
    imapd_out = prot_new(1, 1);

    setproctitle_init(argc, argv, envp);
    config_init("imapd");

    signal(SIGPIPE, SIG_IGN);
    gethostname(hostname, sizeof(hostname));

    /* Find out name of client host */
    salen = sizeof(imapd_remoteaddr);
    if (getpeername(0, &imapd_remoteaddr, &salen) == 0 &&
	imapd_remoteaddr.sin_family == AF_INET) {
	if (hp = gethostbyaddr((char *)&imapd_remoteaddr.sin_addr,
			       sizeof(imapd_remoteaddr.sin_addr), AF_INET)) {
	    if (strlen(hp->h_name) + 30 > sizeof(imapd_clienthost)) {
		hp->h_name[sizeof(imapd_clienthost)-30] = '\0';
	    }
	    strcpy(imapd_clienthost, hp->h_name);
	}
	else {
	    imapd_clienthost[0] = '\0';
	}
	strcat(imapd_clienthost, "[");
	strcat(imapd_clienthost, inet_ntoa(imapd_remoteaddr.sin_addr));
	strcat(imapd_clienthost, "]");
	salen = sizeof(imapd_localaddr);
	if (getsockname(0, &imapd_localaddr, &salen) == 0) {
	    imapd_haveaddr = 1;
	}
    }

    proc_register("imapd", imapd_clienthost, (char *)0, (char *)0);

    /* Set inactivity timer */
    timeout = config_getint("timeout", 30);
    if (timeout < 30) timeout = 30;
    prot_settimeout(imapd_in, timeout*60);

    prot_printf(imapd_out,
		"* OK %s Cyrus IMAP4 %s server ready\r\n", hostname,
		CYRUS_VERSION);
    cmdloop();
}

usage()
{
    prot_printf(imapd_out, "* BYE usage: imapd\r\n");
    prot_flush(imapd_out);
    exit(EX_USAGE);
}

/*
 * Cleanly shut down and exit
 */
shut_down(code)
int code;
{
    proc_cleanup();
    if (imapd_mailbox) {
	index_closemailbox(imapd_mailbox);
	mailbox_close(imapd_mailbox);
    }
    prot_flush(imapd_out);
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
    prot_printf(imapd_out, "* BYE Fatal error: %s\r\n", s);
    prot_flush(imapd_out);
    shut_down(code);
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
	prot_flush(imapd_out);

	/* Parse tag */
	c = getword(&tag);
	if (c == EOF) {
	    if (p = prot_error(imapd_in)) {
		syslog(LOG_WARNING, "PROTERR: %s", p);
		prot_printf(imapd_out, "* BYE %s\r\n", p);
	    }
	    shut_down(0);
	}
	if (c != ' ' || !is_atom(tag.s) || (tag.s[0] == '*' && !tag.s[1])) {
	    prot_printf(imapd_out, "* BAD Invalid tag\r\n");
	    if (c != '\n') eatline();
	    continue;
	}

	/* Parse command name */
	c = getword(&cmd);
	if (!cmd.s[0]) {
	    prot_printf(imapd_out, "%s BAD Null command\r\n", tag.s);
	    if (c != '\n') eatline();
	    continue;
	}
	if (islower(cmd.s[0])) cmd.s[0] = toupper(cmd.s[0]);
	for (p = &cmd.s[1]; *p; p++) {
	    if (isupper(*p)) *p = tolower(*p);
	}

	/* Only Authenticate/Login/Logout/Noop allowed when not logged in */
	if (!imapd_userid && !strchr("ALNC", cmd.s[0])) goto nologin;
    
	switch (cmd.s[0]) {
	case 'A':
	    if (!strcmp(cmd.s, "Authenticate")) {
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (!is_atom(arg1.s)) {
		    prot_printf(imapd_out, "%s BAD Invalid authenticate mechanism\r\n", tag.s);
		    if (c != '\n') eatline();
		    continue;
		}
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		
		if (imapd_userid) {
		    prot_printf(imapd_out, "%s BAD Already authenticated\r\n", tag.s);
		    continue;
		}
		cmd_authenticate(tag.s, arg1.s);
	    }
	    else if (!imapd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "Append")) {
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
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;

		cmd_select(tag.s, cmd.s, arg1.s);
	    }
	    else goto badcmd;
	    break;

	case 'C':
	    if (!strcmp(cmd.s, "Capability")) {
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_capability(tag.s);
	    }
	    else if (!imapd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "Check")) {
		if (!imapd_mailbox) goto nomailbox;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_noop(tag.s, cmd.s);
	    }
	    else if (!strcmp(cmd.s, "Copy")) {
		if (!imapd_mailbox) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    copy:
		c = getword(&arg1);
		if (c != ' ' || !is_sequence(arg1.s)) goto badsequence;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
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
		    if (!is_atom(arg2.s)) goto badpartition;
		}
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_create(tag.s, arg1.s, havepartition ? arg2.s : 0);
	    }
	    else if (!strcmp(cmd.s, "Close")) {
		if (!imapd_mailbox) goto nomailbox;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_close(tag.s);
	    }
	    else goto badcmd;
	    break;

	case 'D':
	    if (!strcmp(cmd.s, "Delete")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
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
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_setacl(tag.s, arg1.s, arg2.s, arg3.s, (char *)0);
	    }
	    else goto badcmd;
	    break;

	case 'E':
	    if (!strcmp(cmd.s, "Expunge")) {
		if (!imapd_mailbox) goto nomailbox;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_expunge(tag.s);
	    }
	    else if (!strcmp(cmd.s, "Examine")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
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
		if (c != ' ' || !is_sequence(arg1.s)) goto badsequence;
		cmd_fetch(tag.s, arg1.s, usinguid);
	    }
	    else if (!strcmp(cmd.s, "Find")) {
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
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
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_getacl(tag.s, arg1.s, arg2.s);
	    }
	    else if (!strcmp(cmd.s, "Getquota")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_getquota(tag.s, arg1.s);
	    }
	    else if (!strcmp(cmd.s, "Getquotaroot")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_getquotaroot(tag.s, arg1.s);
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
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		
		if (imapd_userid) {
		    prot_printf(imapd_out, "%s BAD Already logged in\r\n", tag.s);
		    continue;
		}
		cmd_login(tag.s, arg1.s, arg2.s);
	    }
	    else if (!strcmp(cmd.s, "Logout")) {
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		
		prot_printf(imapd_out, "* BYE Server terminating connection\r\n");
		prot_printf(imapd_out, "%s OK Logout completed\r\n", tag.s);
		shut_down(0);
	    }
	    else if (!imapd_userid) goto nologin;
	    else if (!strcmp(cmd.s, "List")) {
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_list(tag.s, 0, arg1.s, arg2.s);
	    }
	    else if (!strcmp(cmd.s, "Lsub")) {
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_list(tag.s, 1, arg1.s, arg2.s);
	    }
	    else goto badcmd;
	    break;

	case 'M':
	    if (!strcmp(cmd.s, "Myrights")) {
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_myrights(tag.s, arg1.s, arg2.s);
	    }
	    else goto badcmd;
	    break;

	case 'N':
	    if (!strcmp(cmd.s, "Noop")) {
		if (c == '\r') c = prot_getc(imapd_in);
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
		if (c == '\r') c = prot_getc(imapd_in);
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
		    if (!is_atom(arg3.s)) goto badpartition;
		}
		if (c == '\r') c = prot_getc(imapd_in);
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
		if (c != ' ' || !is_sequence(arg1.s)) goto badsequence;
		c = getword(&arg2);
		if (c != ' ') goto badsequence;
		cmd_store(tag.s, arg1.s, arg2.s, usinguid);
	    }
	    else if (!strcmp(cmd.s, "Select")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = prot_getc(imapd_in);
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
		if (c == '\r') c = prot_getc(imapd_in);
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
		if (c == '\r') c = prot_getc(imapd_in);
		if (c != '\n') goto extraargs;
		cmd_setacl(tag.s, arg1.s, arg2.s, arg3.s, arg4.s);
	    }
	    else if (!strcmp(cmd.s, "Setquota")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		cmd_setquota(tag.s, arg1.s);
	    }
	    else if (!strcmp(cmd.s, "Status")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c != ' ') goto missingargs;
		cmd_status(tag.s, arg1.s);
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
		    prot_printf(imapd_out, "%s BAD Unrecognized UID subcommand\r\n", tag.s);
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
		if (c == '\r') c = prot_getc(imapd_in);
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
	    prot_printf(imapd_out, "%s BAD Unrecognized command\r\n", tag.s);
	    if (c != '\n') eatline();
	}

	continue;

    nologin:
	prot_printf(imapd_out, "%s BAD Please login first\r\n", tag.s);
	if (c != '\n') eatline();
	continue;

    nomailbox:
	prot_printf(imapd_out, "%s BAD Please select a mailbox first\r\n", tag.s);
	if (c != '\n') eatline();
	continue;

    missingargs:
	prot_printf(imapd_out, "%s BAD Missing required argument to %s\r\n", tag.s, cmd.s);
	if (c != '\n') eatline();
	continue;

    extraargs:
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to %s\r\n", tag.s, cmd.s);
	if (c != '\n') eatline();
	continue;

    badsequence:
	prot_printf(imapd_out, "%s BAD Invalid sequence in %s\r\n", tag.s, cmd.s);
	if (c != '\n') eatline();
	continue;

    badpartition:
	prot_printf(imapd_out, "%s BAD Invalid partition name in %s\r\n",
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
    int userlen;
    char *reply = 0;
    char *val;
    char buf[MAX_MAILBOX_PATH];
    FILE *logfile;

    canon_user = auth_canonifyid(user);
    if (!canon_user) {
	syslog(LOG_NOTICE, "badlogin: %s plaintext %s invalid user",
	       imapd_clienthost, beautify_string(user));
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(IMAP_INVALID_USER));
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
	    prot_printf(imapd_out, "%s NO %s\r\n", tag,
		   error_message(IMAP_ANONYMOUS_NOT_PERMITTED));
	    return;
	}
    }
    else if (login_plaintext(canon_user, passwd, &reply) != 0) {
	if (reply) {
	    syslog(LOG_NOTICE, "badlogin: %s plaintext %s %s",
		   imapd_clienthost, canon_user, reply);
	}
	sleep(3);
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(IMAP_INVALID_LOGIN));
	return;
    }
    else {
	syslog(LOG_NOTICE, "login: %s %s plaintext %s", imapd_clienthost,
	       canon_user, reply ? reply : "");
    }
    

    auth_setid(canon_user);
    imapd_userid = strsave(canon_user);
    proc_register("imapd", imapd_clienthost, imapd_userid, (char *)0);

    val = config_getstring("admins", "");
    userlen = strlen(canon_user);
    while (*val) {
	if (!strncmp(val, canon_user, userlen) &&
	    (!val[userlen] || isspace(val[userlen]))) {
	    break;
	}
	while (*val && !isspace(*val)) val++;
	while (*val && isspace(*val)) val++;
    }
    if (*val != '\0') imapd_userisadmin = 1;

    if (!reply) reply = "User logged in";

    /* Create telemetry log */
    sprintf(buf, "%s%s%s/%u", config_dir, FNAME_LOGDIR, imapd_userid,
	    getpid());
    logfile = fopen(buf, "w");
    if (logfile) {
	prot_setlog(imapd_in, fileno(logfile));
	prot_setlog(imapd_out, fileno(logfile));
    }

    prot_printf(imapd_out, "%s OK %s\r\n", tag, reply);
    return;
};

/*
 * Perform an AUTHENTICATE command
 */
cmd_authenticate(tag, authtype)
char *tag;
char *authtype;
{
    char *canon_user;
    int userlen;
    int r;
    struct acte_server *mech;
    int (*authproc)();
    int outputlen;
    char *output;
    int inputlen;
    static struct buf input;
    void *state;
    char *reply = 0;
    int protlevel;
    char *user;
    char *(*encodefunc)();
    char *(*decodefunc)();
    int maxplain;
    char *val;
    char buf[MAX_MAILBOX_PATH];
    FILE *logfile;

    lcase(authtype);
    r = login_authenticate(authtype, &mech, &authproc);
    if (!r) {
	r = mech->start("imap", authproc, ACTE_PROT_ANY, PROT_BUFSIZE,
			imapd_haveaddr ? &imapd_localaddr : 0,
			imapd_haveaddr ? &imapd_remoteaddr : 0,
			&outputlen, &output, &state, &reply);
    }
    if (r && r != ACTE_DONE) {
	if (reply) {
	    syslog(LOG_NOTICE, "badlogin: %s %s %s",
		   imapd_clienthost, authtype, reply);
	}
	prot_printf(imapd_out, "%s NO %s\r\n", tag,
		    error_message(IMAP_INVALID_LOGIN));
	return;
    }

    while (r == 0) {
	printauthready(outputlen, output);
	inputlen = getbase64string(&input);
	if (inputlen == -1) {
	    prot_printf(imapd_out, "%s BAD Invalid base64 string\r\n", tag);
	    mech->free_state(state);
	    return;
	}
	r = mech->auth(state, inputlen, input.s, &outputlen, &output, &reply);
    }
    
    if (r != ACTE_DONE) {
	mech->free_state(state);
	if (reply) {
	    syslog(LOG_NOTICE, "badlogin: %s %s %s",
		   imapd_clienthost, authtype, reply);
	}
	sleep(3);
	prot_printf(imapd_out, "%s NO %s\r\n", tag,
		    error_message(IMAP_INVALID_LOGIN));
	return;
    }

    mech->query_state(state, &user, &protlevel, &encodefunc, &decodefunc,
		      &maxplain);

    canon_user = auth_canonifyid(user);
    if (!canon_user) {
	syslog(LOG_NOTICE, "badlogin: %s %s %s bad userid",
	       imapd_clienthost, authtype, beautify_string(user));
	mech->free_state(state);
	prot_printf(imapd_out, "%s NO %s\r\n", tag,
		    error_message(IMAP_INVALID_USER));
	return;
    }

    auth_setid(canon_user);
    imapd_userid = strsave(canon_user);
    proc_register("imapd", imapd_clienthost, imapd_userid, (char *)0);

    val = config_getstring("admins", "");
    userlen = strlen(canon_user);
    while (*val) {
	if (!strncmp(val, canon_user, userlen) &&
	    (!val[userlen] || isspace(val[userlen]))) {
	    break;
	}
	while (*val && !isspace(*val)) val++;
	while (*val && isspace(*val)) val++;
    }
    if (*val != '\0') imapd_userisadmin = 1;

    if (!reply) reply = "User logged in";
    syslog(LOG_NOTICE, "login: %s %s %s %s", imapd_clienthost, canon_user,
	   authtype, reply ? reply : "");

    prot_printf(imapd_out, "%s OK %s\r\n", tag, reply);

    if (encodefunc || decodefunc) {
	prot_setfunc(imapd_in, decodefunc, state, 0);
	prot_setfunc(imapd_out, encodefunc, state, maxplain);
    }
    else {
	mech->free_state(state);
    }

    /* Create telemetry log */
    sprintf(buf, "%s%s%s/%u", config_dir, FNAME_LOGDIR, imapd_userid,
	    getpid());
    logfile = fopen(buf, "w");
    if (logfile) {
	prot_setlog(imapd_in, fileno(logfile));
	prot_setlog(imapd_out, fileno(logfile));
    }

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
    prot_printf(imapd_out, "%s OK %s completed\r\n", tag, cmd);
};

/*
 * Perform a CAPABILITY command
 */
cmd_capability(tag)
char *tag;
{
    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 0);
    }
    prot_printf(imapd_out, "* CAPABILITY IMAP4 STATUS\r\n%s OK Capability completed\r\n", tag);
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
    c = getword(&arg);
    if  (c == '(' && !arg.s[0]) {
	do {
	    c = getword(&arg);
	    if (arg.s[0] == '\\') {
		lcase(arg.s);
		if (!strcmp(arg.s, "\\seen") && !strcmp(arg.s, "\\answered") &&
		    !strcmp(arg.s, "\\flagged") && !strcmp(arg.s, "\\draft") &&
		    !strcmp(arg.s, "\\deleted")) {
		    prot_printf(imapd_out, "%s BAD Invalid system flag in Append command\r\n",tag);
		    if (c != '\n') eatline();
		    goto freeflags;
		}
	    }
	    else if (!is_atom(arg.s)) {
		prot_printf(imapd_out, "%s BAD Invalid flag name %s in Append command\r\n",
			    tag, arg.s);
		if (c != '\n') eatline();
		goto freeflags;
	    }
	    if (nflags == flagalloc) {
		flagalloc += FLAGGROW;
		flag = (char **)xrealloc((char *)flag, flagalloc*sizeof(char *));
	    }
	    flag[nflags++] = strsave(arg.s);
	} while (c == ' ');
	if (c != ')') {
	    prot_printf(imapd_out,
	    "%s BAD Missing space or ) after flag name in Append command\r\n",
			tag);
	    if (c != '\n') eatline();
	    goto freeflags;
	}
	c = prot_getc(imapd_in);
	if (c != ' ') {
	    prot_printf(imapd_out,
		  "%s BAD Missing space after flag list in Append command\r\n",
			tag);
	    if (c != '\n') eatline();
	    goto freeflags;
	}
	c = getword(&arg);
    }

    /* Parse internaldate */
    if (c == '\"' && !arg.s[0]) {
	prot_ungetc(c, imapd_in);
	c = getdatetime(&internaldate);
	if (c != ' ') {
	    prot_printf(imapd_out, "%s BAD Invalid date-time in Append command\r\n", tag);
	    if (c != '\n') eatline();
	    goto freeflags;
	}
	c = getword(&arg);
    }

    if (arg.s[0] != '{') {
	prot_printf(imapd_out, "%s BAD Missing required argument to Append command\r\n",
	       tag);
	if (c != '\n') eatline();
	goto freeflags;
    }

    /* Read size from literal */
    for (p = arg.s + 1; *p && isdigit(*p); p++) {
	size = size*10 + *p - '0';
    }
    if (c == '\r') c = prot_getc(imapd_in);
    if (*p != '}' || p[1] || c != '\n' || p == arg.s + 1) {
	prot_printf(imapd_out, "%s BAD Invalid literal in Append command\r\n", tag);
	if (c != '\n') eatline();
	goto freeflags;
    }
    if (size < 2) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag,
		    error_message(IMAP_MESSAGE_NOBLANKLINE));
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
	prot_printf(imapd_out, "%s NO %s%s\r\n",
	       tag,
	       (r == IMAP_MAILBOX_NONEXISTENT &&
		mboxlist_createmailboxcheck(name, 0, imapd_userisadmin,
					    imapd_userid, (char **)0,
					    (char **)0) == 0)
	       ? "[TRYCREATE] " : "", error_message(r));
	goto freeflags;
    }

    /* Tell client to send the message */
    prot_printf(imapd_out, "+ go ahead\r\n");
    prot_flush(imapd_out);

    /* Perform the rest of the append */
    r = append_fromstream(&mailbox, imapd_in, size, internaldate, flag, nflags,
			  imapd_userid);
    mailbox_close(&mailbox);

    /* Parse newline terminating command */
    c = prot_getc(imapd_in);
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, "* BAD Junk after literal in APPEND command\r\n");
	eatline();
    }

    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 0);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK Append completed\r\n", tag);
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

    if (imapd_mailbox) {
	index_closemailbox(imapd_mailbox);
	mailbox_close(imapd_mailbox);
	imapd_mailbox = 0;
    }

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
	r = (imapd_userisadmin || (mailbox.myrights & ACL_LOOKUP)) ?
	  IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
    }
    if (!r && chdir(mailbox.path)) {
	syslog(LOG_ERR, "IOERROR: changing directory to %s: %m", mailbox.path);
	r = IMAP_IOERROR;
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	if (doclose) mailbox_close(&mailbox);
	return;
    }

    mboxstruct = mailbox;
    imapd_mailbox = &mboxstruct;

    index_newmailbox(imapd_mailbox, cmd[0] == 'E');

    /* Examine command puts mailbox in read-only mode */
    if (cmd[0] == 'E') {
	imapd_mailbox->myrights &= ~(ACL_SEEN|ACL_WRITE|ACL_DELETE);
    }

    if (imapd_mailbox->myrights & ACL_DELETE) {
	/* Warn if mailbox is close to or over quota */
	mailbox_read_quota(&imapd_mailbox->quota);
	if (imapd_mailbox->quota.limit > 0) {
	    usage = imapd_mailbox->quota.used * 100 /
	      (imapd_mailbox->quota.limit * QUOTA_UNITS);
	    if (usage >= 100) {
		prot_printf(imapd_out, "* NO [ALERT] %s\r\n",
			    error_message(IMAP_NO_OVERQUOTA));
	    }
	    else if (usage > config_getint("quotawarn", 90)) {
		prot_printf(imapd_out, "* NO [ALERT] ");
		prot_printf(imapd_out, error_message(IMAP_NO_CLOSEQUOTA),
			    usage);
		prot_printf(imapd_out, "\r\n");
	    }
	}
    }

    prot_printf(imapd_out, "%s OK [READ-%s] %s completed\r\n", tag,
	   (imapd_mailbox->myrights & (ACL_WRITE|ACL_DELETE)) ?
		"WRITE" : "ONLY", cmd);

    proc_register("imapd", imapd_clienthost, imapd_userid,
		  inboxname[0] ? inboxname : name);
    syslog(LOG_INFO, "open: user %s opened %s", imapd_userid, name);
}
	  
/*
 * Perform a CLOSE command
 */
cmd_close(tag)
char *tag;
{
    int r;

    if (!(imapd_mailbox->myrights & ACL_DELETE)) r = 0;
    else {
	r = mailbox_expunge(imapd_mailbox, 1, (int (*)())0, (char *)0);
    }

    index_closemailbox(imapd_mailbox);
    mailbox_close(imapd_mailbox);
    imapd_mailbox = 0;

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK Close completed\r\n", tag);
    }
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
		    prot_printf(imapd_out, "%s BAD Invalid body section\r\n", tag);
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
		    prot_printf(imapd_out, "%s BAD Missing required argument to %s %s\r\n",
			   tag, cmd, fetchatt.s);
		    if (c != '\n') eatline();
		    goto freeargs;
		}
		c = prot_getc(imapd_in);
		if (c != '(') {
		    prot_printf(imapd_out, "%s BAD Missing required open parenthesis in %s %s\r\n",
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
			prot_printf(imapd_out, "%s BAD Invalid field-name in %s %s\r\n",
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
		    prot_printf(imapd_out, "%s BAD Missing required close parenthesis in %s %s\r\n",
			   tag, cmd, fetchatt.s);
		    if (c != '\n') eatline();
		    goto freeargs;
		}
		c = prot_getc(imapd_in);
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
	    prot_printf(imapd_out, "%s BAD Invalid %s attribute %s\r\n", tag, cmd, fetchatt.s);
	    if (c != '\n') eatline();
	    goto freeargs;
	}

	if (inlist && c == ' ') c = getword(&fetchatt);
	else break;
    }
    
    if (inlist && c == ')') {
	inlist = 0;
	c = prot_getc(imapd_in);
    }
    if (inlist) {
	prot_printf(imapd_out, "%s BAD Missing close parenthesis in %s\r\n", tag, cmd);
	if (c != '\n') eatline();
	goto freeargs;
    }
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to %s\r\n", tag, cmd);
	eatline();
	goto freeargs;
    }

    if (!fetchitems && !fetchargs.bodysections &&
	!fetchargs.headers && !fetchargs.headers_not) {
	prot_printf(imapd_out, "%s BAD Missing required argument to %s\r\n", tag, cmd);
	goto freeargs;
    }

    if (usinguid) {
	fetchitems |= FETCH_UID;
	index_check(imapd_mailbox, 1, 0);
    }

    fetchargs.fetchitems = fetchitems;
    index_fetch(imapd_mailbox, sequence, usinguid, &fetchargs);

    prot_printf(imapd_out, "%s OK %s completed\r\n", tag, cmd);

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
	prot_printf(imapd_out, "%s BAD Invalid message number\r\n", tag);
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
	    prot_printf(imapd_out, "%s BAD Invalid body section\r\n", tag);
	    freestrlist(fetchargs.bodysections);
	    return;
	}
	*p = '\0';
	appendstrlist(&fetchargs.bodysections, section);
    }
    else {
	prot_printf(imapd_out, "%s BAD Invalid Partial item\r\n", tag);
	freestrlist(fetchargs.bodysections);
	return;
    }

    for (p = start; *p; p++) {
	if (!isdigit(*p)) break;
	fetchargs.start_octet = fetchargs.start_octet*10 + *p - '0';
    }
    if (*p || !fetchargs.start_octet) {
	prot_printf(imapd_out, "%s BAD Invalid starting octet\r\n", tag);
	freestrlist(fetchargs.bodysections);
	return;
    }
    
    for (p = count; *p; p++) {
	if (!isdigit(*p)) break;
	fetchargs.octet_count = fetchargs.octet_count*10 + *p - '0';
    }
    if (*p || !*count) {
	prot_printf(imapd_out, "%s BAD Invalid octet count\r\n", tag);
	freestrlist(fetchargs.bodysections);
	return;
    }

    index_fetch(imapd_mailbox, msgno, 0, &fetchargs);

    index_check(imapd_mailbox, 0, 0);

    prot_printf(imapd_out, "%s OK Partial completed\r\n", tag);
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
    int len, c;
    char **flag = 0;
    int nflags = 0, flagalloc = 0;
    int flagsparsed = 0, inlist = 0;
    int r;

    storeargs = zerostoreargs;

    lcase(operation);

    len = strlen(operation);
    if (len > 7 && !strcmp(operation+len-7, ".silent")) {
	storeargs.silent = 1;
	operation[len-7] = '\0';
    }
    
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
	prot_printf(imapd_out, "%s BAD Invalid %s attribute\r\n", tag, cmd);
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
	    else if (!strcmp(flagname.s, "\\draft")) {
		storeargs.system_flags |= FLAG_DRAFT;
	    }
	    else {
		prot_printf(imapd_out, "%s BAD Invalid system flag in %s command\r\n",
		       tag, cmd);
		if (c != '\n') eatline();
		goto freeflags;
	    }
	}
	else if (!is_atom(flagname.s)) {
	    prot_printf(imapd_out, "%s BAD Invalid flag name %s in %s command\r\n",
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
	c = prot_getc(imapd_in);
    }
    if (inlist) {
	prot_printf(imapd_out, "%s BAD Missing close parenthesis in %s\r\n", tag, cmd);
	if (c != '\n') eatline();
	return;
    }
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to %s\r\n", tag, cmd);
	eatline();
	return;
    }

    if (!flagsparsed) {
	prot_printf(imapd_out, "%s BAD Missing required argument to %s\r\n", tag, cmd);
	return;
    }

    r = index_store(imapd_mailbox, sequence, usinguid, &storeargs,
		    flag, nflags);
	
    if (usinguid) {
	index_check(imapd_mailbox, 1, 0);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s completed\r\n", tag, cmd);
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

    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to Search\r\n", tag);
	eatline();
	freesearchargs(searchargs);
	return;
    }

    if (charset == -1) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag,
	       error_message(IMAP_UNRECOGNIZED_CHARSET));
    }
    else {
	index_search(imapd_mailbox, searchargs, usinguid);
	prot_printf(imapd_out, "%s OK Search completed\r\n", tag);
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
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s completed\r\n", tag, cmd);
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
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK Expunge completed\r\n", tag);
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
	r = IMAP_PERMISSION_DENIED;
    }
    else if (name[0] && name[strlen(name)-1] == '.') {
	prot_printf(imapd_out, "%s OK Create of non-terminal names is unnecessary\r\n", tag);
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
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK Create completed\r\n", tag);
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
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK Delete completed\r\n", tag);
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
	r = IMAP_PERMISSION_DENIED;
    }
    else {
	r = mboxlist_renamemailbox(oldname, newname, partition,
				   imapd_userisadmin, imapd_userid);
    }

    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 0);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK Rename completed\r\n", tag);
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
    char *p;
    lcase(namespace);

    for (p = pattern; *p; p++) {
	if (*p == '%') *p = '?';
    }

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
	prot_printf(imapd_out, "%s BAD Invalid FIND subcommand\r\n", tag);
	return;
    }
    prot_printf(imapd_out, "%s OK Find completed\r\n", tag);
}

/*
 * Perform a LIST or LSUB command
 */
cmd_list(tag, subscribed, reference, pattern)
char *tag;
int subscribed;
char *reference;
char *pattern;
{
    char buf[MAX_MAILBOX_PATH];

    /* Handle name-in-reference */
    if (pattern[0] == '.') {
	strcpy(buf, reference);
	if (*reference && reference[strlen(reference)-1] == '.') {
	    buf[strlen(reference)-1] = '\0';
	}
	strcat(buf, pattern);
	pattern = buf;
    }

    if (subscribed) {
	mboxlist_findsub(pattern, imapd_userisadmin, imapd_userid,
			 lsubdata);
	lsubdata((char *)0, 0, 0);
    }
    else {
	mboxlist_findall(pattern, imapd_userisadmin, imapd_userid,
			 listdata);
	listdata((char *)0, 0, 0);
    }
    prot_printf(imapd_out, "%s OK %s completed\r\n", tag, subscribed ? "LSUB" : "LIST");
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
	r = add ? IMAP_MAILBOX_NONEXISTENT : 0;
    }
    else {
	prot_printf(imapd_out, "%s BAD Invalid %s subcommand\r\n", tag,
	       add ? "Subscribe" : "Unsubscribe");
	return;
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag,
	       add ? "Subscribe" : "Unsubscribe", error_message(r));
    }
    else {
	prot_printf(imapd_out, "%s OK %s completed\r\n", tag,
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
	prot_printf(imapd_out, "%s BAD Invalid Getacl subcommand\r\n", tag);
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
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    while (acl) {
	rights = strchr(acl, '\t');
	if (!rights) break;
	*rights++ = '\0';

	nextid = strchr(rights, '\t');
	if (!nextid) break;
	*nextid++ = '\0';

	prot_printf(imapd_out, "* ACL MAILBOX ");
	printastring(name);
	prot_printf(imapd_out, " ");
	printastring(acl);
	prot_printf(imapd_out, " ");
	printastring(rights);
	prot_printf(imapd_out, "\r\n");
	acl = nextid;
    }
    prot_printf(imapd_out, "%s OK Getacl completed\r\n", tag);
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
	prot_printf(imapd_out, "%s BAD Invalid Myrights subcommand\r\n", tag);
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
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "* MYRIGHTS MAILBOX ");
    printastring(name);
    prot_printf(imapd_out, " ");
    printastring(acl_masktostr(rights, str));
    prot_printf(imapd_out, "\r\n%s OK Myrights completed\r\n", tag);
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
	prot_printf(imapd_out, "%s BAD Invalid %s subcommand\r\n", tag, cmd);
	return;
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK %s completed\r\n", tag, cmd);
}

/*
 * Perform a GETQUOTA command
 */
cmd_getquota(tag, name)
char *tag;
char *name;
{
    int r;
    struct quota quota;
    char buf[MAX_MAILBOX_PATH];

    lcase(name);
    quota.root = name;
    quota.file = 0;

    if (!imapd_userisadmin) r = IMAP_PERMISSION_DENIED;
    else {
	sprintf(buf, "%s%s%s", config_dir, FNAME_QUOTADIR, quota.root);
	quota.file = fopen(buf, "r+");
	if (!quota.file) {
	    r = IMAP_QUOTAROOT_NONEXISTENT;
	}
	else r = mailbox_read_quota(&quota);
    }
    
    if (!r) {
	prot_printf(imapd_out, "* QUOTA ");
	printastring(quota.root);
	prot_printf(imapd_out, " (");
	if (quota.limit >= 0) {
	    prot_printf(imapd_out, "STORAGE %u %d",
			quota.used/QUOTA_UNITS, quota.limit);
	}
	prot_printf(imapd_out, ")\r\n");
    }

    if (quota.file) fclose(quota.file);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK Getquotaroot completed\r\n", tag);
}


/*
 * Perform a GETQUOTAROOT command
 */
cmd_getquotaroot(tag, name)
char *tag;
char *name;
{
    char inboxname[MAX_MAILBOX_PATH];
    struct mailbox mailbox;
    int r;
    int doclose = 0;

    if (strcasecmp(name, "inbox") == 0 &&
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
	if (!imapd_userisadmin && !(mailbox.myrights & ACL_READ)) {
	    r = (mailbox.myrights & ACL_LOOKUP) ?
	      IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	}
    }

    if (!r) {
	prot_printf(imapd_out, "* QUOTAROOT ");
	printastring(name);
	if (mailbox.quota.root) {
	    prot_printf(imapd_out, " ");
	    printastring(mailbox.quota.root);
	    r = mailbox_read_quota(&mailbox.quota);
	    if (!r) {
		prot_printf(imapd_out, "\r\n* QUOTA ");
		printastring(mailbox.quota.root);
		prot_printf(imapd_out, " (");
		if (mailbox.quota.limit >= 0) {
		    prot_printf(imapd_out, "STORAGE %u %d",
				mailbox.quota.used/QUOTA_UNITS,
				mailbox.quota.limit);
		}
		prot_putc(')', imapd_out);
	    }
	}
	prot_printf(imapd_out, "\r\n");
    }

    if (doclose) mailbox_close(&mailbox);

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK Getquotaroot completed\r\n", tag);
}

/*
 * Parse and perform a SETQUOTA command
 * The command has been parsed up to the resource list
 */
cmd_setquota(tag, quotaroot)
char *tag;
char *quotaroot;
{
    int newquota = -1;
    int badresource = 0;
    int c;
    static struct buf arg;
    char *p;
    int r;

    c = prot_getc(imapd_in);
    if (c != '(') goto badlist;

    c = getword(&arg);
    if (c != ')' || arg.s[0] != '\0') {
	for (;;) {
	    if (c != ' ') goto badlist;
	    if (strcasecmp(arg.s, "storage") != 0) badresource = 1;
	    c = getword(&arg);
	    if (c != ' ' && c != ')') goto badlist;
	    if (arg.s[0] == '\0') goto badlist;
	    newquota = 0;
	    for (p = arg.s; *p; p++) {
		if (!isdigit(*p)) goto badlist;
		newquota = newquota * 10 + *p - '0';
	    }
	    if (c == ')') break;
	}
    }
    c = prot_getc(imapd_in);
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out, "%s BAD Unexpected extra arguments to SETQUOTA\r\n", tag);
	eatline();
	return;
    }

    if (badresource) r = IMAP_UNSUPPORTED_QUOTA;
    else if (!imapd_userisadmin) r = IMAP_PERMISSION_DENIED;
    else {
	r = mboxlist_setquota(quotaroot, newquota);
    }

    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK Setquota completed\r\n", tag);
    return;

 badlist:
    prot_printf(imapd_out, "%s BAD Invalid quota list in Setquota\r\n", tag);
    if (c != '\n') eatline();
}

/*
 * Parse and perform a STATUS command
 * The command has been parsed up to the attribute list
 */
cmd_status(tag, name)
char *tag;
char *name;
{
    int c;
    int statusitems = 0;
    static struct buf arg;
    struct mailbox mailbox;
    char inboxname[MAX_MAILBOX_PATH];
    int r = 0;
    int doclose = 0;

    c = prot_getc(imapd_in);
    if (c != '(') goto badlist;

    c = getword(&arg);
    if (arg.s[0] == '\0') goto badlist;
    for (;;) {
	lcase(arg.s);
	if (!strcmp(arg.s, "messages")) {
	    statusitems |= STATUS_MESSAGES;
	}
	else if (!strcmp(arg.s, "recent")) {
	    statusitems |= STATUS_RECENT;
	}
	else if (!strcmp(arg.s, "uid-next")) {
	    statusitems |= STATUS_UID_NEXT;
	}
	else if (!strcmp(arg.s, "uid-validity")) {
	    statusitems |= STATUS_UID_VALIDITY;
	}
	else if (!strcmp(arg.s, "unseen")) {
	    statusitems |= STATUS_UNSEEN;
	}
	else if (!strcmp(arg.s, "unseen")) {
	    statusitems |= STATUS_UNSEEN;
	}
	else if (!strcmp(arg.s, "update-number")) {
	    statusitems |= STATUS_UPDATE_NUMBER;
	}
	else {
	    prot_printf(imapd_out, "%s BAD Invalid Status attribute %s\r\n",
			tag, arg.s);
	    if (c != '\n') eatline();
	    return;
	}
	    
	if (c == ' ') c = getword(&arg);
	else break;
    }

    if (c != ')') {
	prot_printf(imapd_out,
		    "%s BAD Missing close parenthesis in Status\r\n", tag);
	if (c != '\n') eatline();
	return;
    }

    c = prot_getc(imapd_in);
    if (c == '\r') c = prot_getc(imapd_in);
    if (c != '\n') {
	prot_printf(imapd_out,
		    "%s BAD Unexpected extra arguments to Status\r\n", tag);
	eatline();
	return;
    }

    /*
     * Perform a full checkpoint of any open mailbox, in case we're
     * doing a STATUS check of the current mailbox.
     */
    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 1);
    }

    if (strcasecmp(name, "inbox") == 0 &&
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
	r = (imapd_userisadmin || (mailbox.myrights & ACL_LOOKUP)) ?
	  IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
    }

    if (!r) {
	r = index_status(&mailbox, name, statusitems);
    }

    if (doclose) mailbox_close(&mailbox);
    
    if (r) {
	prot_printf(imapd_out, "%s NO %s\r\n", tag, error_message(r));
	return;
    }
    
    prot_printf(imapd_out, "%s OK Status completed\r\n", tag);
    return;

 badlist:
    prot_printf(imapd_out, "%s BAD Invalid status list in Status\r\n", tag);
    if (c != '\n') eatline();
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
	c = prot_getc(imapd_in);
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
    int sawdigit = 0;

    if (buf->alloc == 0) {
	buf->alloc = BUFGROWSIZE;
	buf->s = xmalloc(buf->alloc+1);
    }
	
    c = prot_getc(imapd_in);
    switch (c) {
    case EOF:
    case ' ':
    case '(':
    case ')':
    case '\r':
    case '\n':
	/* Invalid starting character */
	buf->s[0] = '\0';
	if (c != EOF) prot_ungetc(c, imapd_in);
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
	    c = prot_getc(imapd_in);
	}
	
    case '\"':
	/*
	 * Quoted-string.  Server is liberal in accepting qspecials
	 * other than double-quote, CR, and LF.
	 */
	for (;;) {
	    c = prot_getc(imapd_in);
	    if (c == '\\') {
		c = prot_getc(imapd_in);
	    }
	    else if (c == '\"') {
		buf->s[len] = '\0';
		return prot_getc(imapd_in);
	    }
	    else if (c == EOF || c == '\r' || c == '\n') {
		buf->s[len] = '\0';
		if (c != EOF) prot_ungetc(c, imapd_in);
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
	while ((c = prot_getc(imapd_in)) != EOF && isdigit(c)) {
	    sawdigit = 1;
	    len = len*10 + c - '0';
	}
	if (!sawdigit || c != '}') {
	    if (c != EOF) prot_ungetc(c, imapd_in);
	    return EOF;
	}
	c = prot_getc(imapd_in);
	if (c == '\r') c = prot_getc(imapd_in);
	if (c != '\n') {
	    if (c != EOF) prot_ungetc(c, imapd_in);
	    return EOF;
	}
	if (len >= buf->alloc) {
	    buf->alloc = len+1;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
	}
	prot_printf(imapd_out, "+ go ahead\r\n");
	prot_flush(imapd_out);
	for (i = 0; i < len; i++) {
	    c = prot_getc(imapd_in);
	    if (c == EOF) {
		buf->s[len] = '\0';
		return EOF;
	    }
	    buf->s[i] = c;
	}
	buf->s[len] = '\0';
	if (strlen(buf->s) != len) return EOF; /* Disallow imbedded NUL */
	return prot_getc(imapd_in);
    }
}

#define XX 127
/*
 * Table for decoding base64
 */
static const char index_64[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,63,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,XX,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
    XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};
#define CHAR64(c)  (index_64[(unsigned char)(c)])

/*
 * Parse a base64_string
 */
int getbase64string(buf)
struct buf *buf;
{
    int c1, c2, c3, c4;
    int i, len = 0;

    if (buf->alloc == 0) {
	buf->alloc = BUFGROWSIZE;
	buf->s = xmalloc(buf->alloc+1);
    }
	
    for (;;) {
	c1 = prot_getc(imapd_in);
	if (c1 == '\r') {
	    c1 = prot_getc(imapd_in);
	    if (c1 != '\n') {
		eatline();
		return -1;
	    }
	    return len;
	}
	else if (c1 == '\n') return len;

	if (CHAR64(c1) == XX) {
	    eatline();
	    return -1;
	}
	
	c2 = prot_getc(imapd_in);
	if (CHAR64(c2) == XX) {
	    if (c2 != '\n') eatline();
	    return -1;
	}

	c3 = prot_getc(imapd_in);
	if (c3 != '=' && CHAR64(c3) == XX) {
	    if (c3 != '\n') eatline();
	    return -1;
	}

	c4 = prot_getc(imapd_in);
	if (c4 != '=' && CHAR64(c4) == XX) {
	    if (c4 != '\n') eatline();
	    return -1;
	}

	if (len+3 >= buf->alloc) {
	    buf->alloc = len+BUFGROWSIZE;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
	}

	buf->s[len++] = ((CHAR64(c1)<<2) | ((CHAR64(c2)&0x30)>>4));
	if (c3 == '=') {
	    c1 = prot_getc(imapd_in);
	    if (c1 == '\r') c1 = prot_getc(imapd_in);
	    if (c1 != '\n') {
		eatline();
		return -1;
	    }
	    if (c4 != '=') return -1;
	    return len;
	}
	buf->s[len++] = (((CHAR64(c2)&0xf)<<4) | ((CHAR64(c3)&0x3c)>>2));
	if (c4 == '=') {
	    c1 = prot_getc(imapd_in);
	    if (c1 == '\r') c1 = prot_getc(imapd_in);
	    if (c1 != '\n') {
		eatline();
		return -1;
	    }
	    return len;
	}
	buf->s[len++] = (((CHAR64(c3)&0x3)<<6) | CHAR64(c4));
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
	    prot_printf(imapd_out, "%s BAD Missing required close paren in Search command\r\n",
		   tag);
	    if (c != EOF) prot_ungetc(c, imapd_in);
	    return EOF;
	}
	c = prot_getc(imapd_in);
	break;

    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
    case '*':
	if (is_sequence(criteria.s)) {
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
	    c = getsearchdate(&start, &end);
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
	    if (strchr(str, EMPTY)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlistpat(&searchargs->bcc, str);
	    }
	}
	else if (!strcmp(criteria.s, "body")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset);
	    if (strchr(str, EMPTY)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlistpat(&searchargs->body, str);
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
	    if (strchr(str, EMPTY)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlistpat(&searchargs->cc, str);
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
	else if (!strcmp(criteria.s, "draft")) {
	    searchargs->system_flags_set |= FLAG_DRAFT;
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
	    if (strchr(str, EMPTY)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlistpat(&searchargs->from, str);
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
	    if (strchr(str, EMPTY)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlistpat(&searchargs->header, str);
	    }
	}
	else goto badcri;
	break;

    case 'k':
	if (!strcmp(criteria.s, "keyword")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(&arg);
	    if (!is_atom(arg.s)) goto badflag;
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
	    c = getsearchdate(&start, &end);
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
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->sentbefore || searchargs->sentbefore > start) {
		searchargs->sentbefore = start;
	    }
	}
	else if (!strcmp(criteria.s, "senton")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
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
	    c = getsearchdate(&start, &end);
	    if (c == EOF) goto baddate;
	    if (!searchargs->sentafter || searchargs->sentafter < start) {
		searchargs->sentafter = start;
	    }
	}
	else if (!strcmp(criteria.s, "since")) {
	    if (c != ' ') goto missingarg;		
	    c = getsearchdate(&start, &end);
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
	    if (strchr(str, EMPTY)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlistpat(&searchargs->subject, str);
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
	    if (strchr(str, EMPTY)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlistpat(&searchargs->to, str);
	    }
	}
	else if (!strcmp(criteria.s, "text")) {
	    if (c != ' ') goto missingarg;		
	    c = getastring(&arg);
	    if (c == EOF) goto missingarg;
	    str = charset_convert(arg.s, *charset);
	    if (strchr(str, EMPTY)) {
		searchargs->recent_set = searchargs->recent_unset = 1;
	    }
	    else {
		appendstrlistpat(&searchargs->text, str);
	    }
	}
	else goto badcri;
	break;

    case 'u':
	if (!strcmp(criteria.s, "uid")) {
	    if (c != ' ') goto missingarg;
	    c = getword(&arg);
	    if (!is_sequence(arg.s)) goto badcri;
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
	else if (!strcmp(criteria.s, "undraft")) {
	    searchargs->system_flags_unset |= FLAG_DRAFT;
	}
	else if (!strcmp(criteria.s, "unflagged")) {
	    searchargs->system_flags_unset |= FLAG_FLAGGED;
	}
	else if (!strcmp(criteria.s, "unkeyword")) {
	    if (c != ' ') goto missingarg;		
	    c = getword(&arg);
	    if (!is_atom(arg.s)) goto badflag;
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
	prot_printf(imapd_out, "%s BAD Invalid Search criteria\r\n", tag);
	if (c != EOF) prot_ungetc(c, imapd_in);
	return EOF;
    }

    return c;

 missingarg:
    prot_printf(imapd_out, "%s BAD Missing required argument to Search %s\r\n",
	   tag, criteria.s);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;

 badflag:
    prot_printf(imapd_out, "%s BAD Invalid flag name %s in Search command\r\n",
	   tag, arg.s);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;

 baddate:
    prot_printf(imapd_out, "%s BAD Invalid date in Search command\r\n", tag);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;

 badnumber:
    prot_printf(imapd_out, "%s BAD Invalid number in Search command\r\n", tag);
    if (c != EOF) prot_ungetc(c, imapd_in);
    return EOF;
}

/*
 * Parse a "date", for SEARCH criteria
 * The time_t's pointed to by 'start' and 'end' are set to the
 * times of the start and end of the parsed date.
 */
int getsearchdate(start, end)
time_t *start, *end;
{
    int c;
    struct tm tm;
    static struct tm zerotm;
    int quoted = 0;
    char month[4];

    tm = zerotm;

    c = prot_getc(imapd_in);
    if (c == '\"') {
	quoted++;
	c = prot_getc(imapd_in);
    }

    /* Day of month */
    if (!isdigit(c)) goto baddate;
    tm.tm_mday = c - '0';
    c = prot_getc(imapd_in);
    if (isdigit(c)) {
	tm.tm_mday = tm.tm_mday * 10 + c - '0';
	c = prot_getc(imapd_in);
    }
    
    if (c != '-') goto baddate;
    c = prot_getc(imapd_in);

    /* Month name */
    if (!isalpha(c)) goto baddate;
    month[0] = c;
    c = prot_getc(imapd_in);
    if (!isalpha(c)) goto baddate;
    month[1] = c;
    c = prot_getc(imapd_in);
    if (!isalpha(c)) goto baddate;
    month[2] = c;
    c = prot_getc(imapd_in);
    month[3] = '\0';
    lcase(month);

    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcmp(month, monthname[tm.tm_mon])) break;
    }
    if (tm.tm_mon == 12) goto baddate;

    if (c != '-') goto baddate;
    c = prot_getc(imapd_in);

    /* Year */
    if (!isdigit(c)) goto baddate;
    tm.tm_year = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_year = tm.tm_year * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (isdigit(c)) {
	if (tm.tm_year < 19) goto baddate;
	tm.tm_year -= 19;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = prot_getc(imapd_in);
    }

    if (quoted) {
	if (c != '\"') goto baddate;
	c = prot_getc(imapd_in);
    }

    tm.tm_isdst = -1;
    *start = mktime(&tm);

    tm.tm_sec = tm.tm_min = 59;
    tm.tm_hour = 23;
    *end = mktime(&tm);

    return c;

 baddate:
    prot_ungetc(c, imapd_in);
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

    c = prot_getc(imapd_in);
    if (c != '\"') goto baddate;
    
    /* Day of month */
    c = prot_getc(imapd_in);
    if (c == ' ') c = '0';
    if (!isdigit(c)) goto baddate;
    tm.tm_mday = c - '0';
    c = prot_getc(imapd_in);
    if (isdigit(c)) {
	tm.tm_mday = tm.tm_mday * 10 + c - '0';
	c = prot_getc(imapd_in);
    }
    
    if (c != '-') goto baddate;
    c = prot_getc(imapd_in);

    /* Month name */
    if (!isalpha(c)) goto baddate;
    month[0] = c;
    c = prot_getc(imapd_in);
    if (!isalpha(c)) goto baddate;
    month[1] = c;
    c = prot_getc(imapd_in);
    if (!isalpha(c)) goto baddate;
    month[2] = c;
    c = prot_getc(imapd_in);
    month[3] = '\0';
    lcase(month);

    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcmp(month, monthname[tm.tm_mon])) break;
    }
    if (tm.tm_mon == 12) goto baddate;

    if (c != '-') goto baddate;
    c = prot_getc(imapd_in);

    /* Year */
    if (!isdigit(c)) goto baddate;
    tm.tm_year = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_year = tm.tm_year * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (isdigit(c)) {
	if (tm.tm_year < 19) goto baddate;
	tm.tm_year -= 19;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	tm.tm_year = tm.tm_year * 10 + c - '0';
	c = prot_getc(imapd_in);
    }
    else old_format++;

    /* Hour */
    if (c != ' ') goto baddate;
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_hour = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_hour = tm.tm_hour * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (tm.tm_hour > 23) goto baddate;

    /* Minute */
    if (c != ':') goto baddate;
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_min = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_min = tm.tm_min * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (tm.tm_min > 59) goto baddate;

    /* Second */
    if (c != ':') goto baddate;
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_sec = c - '0';
    c = prot_getc(imapd_in);
    if (!isdigit(c)) goto baddate;
    tm.tm_sec = tm.tm_sec * 10 + c - '0';
    c = prot_getc(imapd_in);
    if (tm.tm_min > 60) goto baddate;

    /* Time zone */
    if (old_format) {
	if (c != '-') goto baddate;
	c = prot_getc(imapd_in);

	if (!isalpha(c)) goto baddate;
	zone[0] = c;
	c = prot_getc(imapd_in);

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
	    c = prot_getc(imapd_in);
	    if (c == '\"') {
		zone[2] = '\0';
		lcase(zone);
		if (!strcmp(zone, "ut")) goto baddate;
		zone_off = 0;
	    }
	    else {
		/* 3-char time zone */
		zone[2] = c;
		c = prot_getc(imapd_in);
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
	c = prot_getc(imapd_in);

	if (c != '+' && c != '-') goto baddate;
	zone[0] = c;

	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	zone_off = c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 10 + c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 6 + c - '0';
	c = prot_getc(imapd_in);
	if (!isdigit(c)) goto baddate;
	zone_off = zone_off * 10 + c - '0';

	if (zone[0] == '-') zone_off = -zone_off;

	c = prot_getc(imapd_in);
	if (c != '\"') goto baddate;

    }

    c = prot_getc(imapd_in);

    tm.tm_isdst = -1;
    *date = mktime(&tm);
    ltm = localtime(date);
    *date += gmtoff_of(ltm, *date) - zone_off*60;

    return c;

 baddate:
    prot_ungetc(c, imapd_in);
    return EOF;
}

/*
 * Eat characters up to and including the next newline
 */
eatline()
{
    int c;

    while ((c = prot_getc(imapd_in)) != EOF && c != '\n');
}

/*
 * Print 's' as an atom, quoted-string, or literal
 */
printastring(s)
char *s;
{
    char *p;

    if (is_atom(s)) {
	prot_printf(imapd_out, "%s", s);
	return;
    }

    /* Look for any non-QCHAR characters */
    for (p = s; *p; p++) {
	if (*p & 0x80 || *p == '\r' || *p == '\n'
	    || *p == '\"' || *p == '%' || *p == '\\') break;
    }

    if (*p) {
	prot_printf(imapd_out, "{%u}\r\n%s", strlen(s), s);
    }
    else {
	prot_printf(imapd_out, "\"%s\"", s);
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
    (*tail)->p = 0;
    (*tail)->next = 0;
}

/*
 * Append 's' to the strlist 'l', compiling it as a pattern.
 */
appendstrlistpat(l, s)
struct strlist **l;
char *s;
{
    struct strlist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct strlist *)xmalloc(sizeof(struct strlist));
    (*tail)->s = strsave(s);
    (*tail)->p = charset_compilepat(s);
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
	if (l->p) charset_freepat(l->p);
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
 * Print an authentication ready response
 */
static char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
printauthready(len, data)
int len;
unsigned char *data;
{
    int c1, c2, c3;

    prot_putc('+', imapd_out);
    prot_putc(' ', imapd_out);
    while (len) {
	c1 = *data++;
	len--;
	prot_putc(basis_64[c1>>2], imapd_out);
	if (len == 0) c2 = 0;
	else c2 = *data++;
	prot_putc(basis_64[((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)], imapd_out);
	if (len == 0) {
	    prot_putc('=', imapd_out);
	    prot_putc('=', imapd_out);
	    break;
	}

	if (--len == 0) c3 = 0;
	else c3 = *data++;
        prot_putc(basis_64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)], imapd_out);
	if (len == 0) {
	    prot_putc('=', imapd_out);
	    break;
	}
	
	--len;
        prot_putc(basis_64[c3 & 0x3F], imapd_out);
    }
    prot_putc('\r', imapd_out);
    prot_putc('\n', imapd_out);
    prot_flush(imapd_out);
}

/*
 * Issue a MAILBOX untagged response
 */
static int mailboxdata(name, matchlen, maycreate)
char *name;
int matchlen;
int maycreate;
{
    prot_printf(imapd_out, "* MAILBOX %s\r\n", name);
    return 0;
}

/*
 * Issue a LIST or LSUB untagged response
 */
static int mstringdata(cmd, name, matchlen, maycreate)
char *cmd;
char *name;
int matchlen;
int maycreate;
{
    static char lastname[MAX_MAILBOX_PATH];
    static int lastnamedelayed;
    static sawuser = 0;
    int lastnamehassub = 0;
    int c;

    if (lastnamedelayed) {
	if (name && strncasecmp(lastname, name, strlen(lastname)) == 0 &&
	    name[strlen(lastname)] == '.') {
	    lastnamehassub = 1;
	}
	prot_printf(imapd_out, "* %s (%s) \".\" ", cmd,
	       lastnamehassub ? "" : "\\Noinferiors");
	printastring(lastname);
	prot_printf(imapd_out, "\r\n");
	lastnamedelayed = 0;
    }

    /* Special-case to flush any final state */
    if (!name) {
	lastname[0] = '\0';
	return 0;
    }

    /* Suppress any output of a partial match */
    if (name[matchlen] && strncasecmp(lastname, name, matchlen) == 0) {
	return 0;
    }
	
    /*
     * We can get a partial match for "user" multiple times with
     * other matches inbetween.  Handle it as a special case
     */
    if (matchlen == 4 && strncasecmp(name, "user", 4) == 0) {
	if (sawuser) return 0;
	sawuser = 1;
    }

    strcpy(lastname, name);
    lastname[matchlen] = '\0';

    if (!name[matchlen] && !maycreate) {
	lastnamedelayed = 1;
	return 0;
    }

    c = name[matchlen];
    name[matchlen] = '\0';
    prot_printf(imapd_out, "* %s (%s) \".\" ", cmd, c ? "\\Noselect" : "");
    printastring(name);
    prot_printf(imapd_out, "\r\n");
    name[matchlen] = c;
    return 0;
}

/*
 * Issue a LIST untagged response
 */
static int listdata(name, matchlen, maycreate)
char *name;
int matchlen;
int maycreate;
{
    return mstringdata("LIST", name, matchlen, maycreate);
}

/*
 * Issue a LSUB untagged response
 */
static int lsubdata(name, matchlen, maycreate)
char *name;
int matchlen;
int maycreate;
{
    return mstringdata("LSUB", name, matchlen, maycreate);
}

