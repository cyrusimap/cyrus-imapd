/*
 * IMAP server
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

#include <acl.h>
#include <glob.h>
#include <util.h>
#include "auth.h"
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
char imapd_clienthost[250] = "[local]";

static struct mailbox mboxstruct;

static struct fetchargs zerofetchargs;

main(argc, argv)
{
    char hostname[MAXHOSTNAMELEN+1];
    struct sockaddr_in sa;
    int salen = sizeof(sa);
    struct hostent *hp;

    config_init("imapd");

    signal(SIGPIPE, SIG_IGN);
    gethostname(hostname, sizeof(hostname));

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

    printf("* OK %s Cyrus IMAP2bis v0.1-ALPHA server ready\r\n", hostname);
    cmdloop();
}

usage()
{
    printf("* BYE usage: imapd\r\n");
    exit(EX_USAGE);
}

fatal(s, code)
char *s;
int code;
{
    static int recurse_code = 0;

    if (recurse_code) {
	exit(recurse_code);
    }
    recurse_code = code;
    printf("* BYE Fatal error: %s\r\n", s);
    shutdown(code);
}

cmdloop()
{
    int c;
    int usinguid, havepartition;
    static struct buf tag, cmd, arg1, arg2, arg3, arg4;
    char *p;

    for (;;) {
	fflush(stdout);

	c = getword(&tag);
	if (c == EOF) {
	    shutdown(0);
	}
	if (c != ' ' || !isatom(tag.s) || (tag.s[0] == '*' && !tag.s[1])) {
	    printf("* BAD Invalid tag\r\n");
	    if (c != '\n') eatline();
	    continue;
	}

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
	    if (!strcmp(cmd.s, "Deleteacl")) {
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
	    if (!strcmp(cmd.s, "Examine")) {
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
		c = getsequence(&arg1);
		if (c != ' ') goto badsequence;
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

	case 'S':
	    if (!strcmp(cmd.s, "Select")) {
		if (c != ' ') goto missingargs;
		c = getastring(&arg1);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;

		cmd_select(tag.s, cmd.s, arg1.s);
	    }
	    else if (!strcmp(cmd.s, "Store")) {
		if (!imapd_mailbox) goto nomailbox;
		usinguid = 0;
		if (c != ' ') goto missingargs;
	    store:
		c = getsequence(&arg1);
		if (c != ' ') goto badsequence;
		c = getword(&arg2);
		if (c != ' ') goto badsequence;
		cmd_store(tag.s, arg1.s, arg2.s, usinguid);
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
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_changesub(tag.s, arg1.s, arg2.s, 1);
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
		/* XXX copy */
		else {
		    printf("%s BAD Unrecognized UID subcommand\r\n", tag.s);
		    if (c != '\n') eatline();
		}
	    }
	    else if (!strcmp(cmd.s, "Unsubscribe")) {
		if (c != ' ') goto missingargs;
		c = getword(&arg1);
		if (c != ' ') goto missingargs;
		c = getastring(&arg2);
		if (c == EOF) goto missingargs;
		if (c == '\r') c = getc(stdin);
		if (c != '\n') goto extraargs;
		cmd_changesub(tag.s, arg1.s, arg2.s, 0);
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

    if (!reply) reply = "User logged in";
    
    printf("%s OK %s\r\n", tag, reply);
    return;
};

cmd_noop(tag, cmd)
char *tag;
char *cmd;
{
    if (imapd_mailbox) {
	index_check(imapd_mailbox, 0, 1);
    }
    printf("%s OK %s completed\r\n", tag, cmd);
};

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
    unsigned size = 0;
    int r;
    char inboxname[MAX_MAILBOX_PATH];
    struct mailbox mailbox;

    /* Get flags */
    for (c = getword(&arg); arg.s[0] != '{'; c = getword(&arg)) {
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
	       tag, r == IMAP_MAILBOX_NONEXISTENT ? "[TRYCREATE] " : "",
	       beautify_string(name), error_message(r));
	/* XXX check create permissions for [TRYCREATE] */
	goto freeflags;
    }

    printf("+ go ahead\r\n");
    fflush(stdout);

    r = append_fromstream(&mailbox, stdin, size, flag, nflags, imapd_userid);
    mailbox_close(&mailbox);

    if (imapd_mailbox) {
	/*
	 * We do a full check to pick up any \Seen flag we might have
	 * set on the appended message.
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
	r = IMAP_IOERROR;
    }

    if (r) {
	printf("%s NO %s of %s failed: %s\r\n", tag, cmd,
	       beautify_string(name), error_message(r));
	if (doclose) mailbox_close(&mailbox);
	return;
    }

    if (imapd_mailbox) {
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

    syslog(LOG_INFO, "open: user %s opened %s", imapd_userid, name);
}
	  
cmd_fetch(tag, sequence, usinguid)
char *tag;
char *sequence;
int usinguid;
{
    char *cmd = usinguid ? "UID Fetch" : "Fetch";
    static struct buf fetchatt, fieldname;
    int c;
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
    else if (!strcmp(data, "rfc822.text")) {
	fetchargs.fetchitems = FETCH_TEXT|FETCH_SETSEEN;
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
    int c = ' ';
    static struct buf criteria, arg;
    struct searchargs searchargs;
    static struct searchargs zerosearchargs;
    int nothing_found = 0;
    int flag;
    time_t start, end;

    searchargs = zerosearchargs;

    while (c == ' ') {
	c = getword(&criteria);
	lcase(criteria.s);
	switch (criteria.s[0]) {
	case 'a':
	    if (!strcmp(criteria.s, "answered")) {
		searchargs.system_flags_set |= FLAG_ANSWERED;
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
		if (!searchargs.before || searchargs.before > start) {
		    searchargs.before = start;
		}
	    }
	    else if (!strcmp(criteria.s, "bcc")) {
		if (c != ' ') goto missingarg;		
		c = getastring(&arg);
		if (c == EOF) goto missingarg;
		appendstrlist(&searchargs.bcc, arg.s);
	    }
	    else if (!strcmp(criteria.s, "body")) {
		if (c != ' ') goto missingarg;		
		c = getastring(&arg);
		if (c == EOF) goto missingarg;
		appendstrlist(&searchargs.body, arg.s);
	    }
	    else goto badcri;
	    break;

	case 'c':
	    if (!strcmp(criteria.s, "cc")) {
		if (c != ' ') goto missingarg;		
		c = getastring(&arg);
		if (c == EOF) goto missingarg;
		appendstrlist(&searchargs.cc, arg.s);
	    }
	    else goto badcri;
	    break;

	case 'd':
	    if (!strcmp(criteria.s, "deleted")) {
		searchargs.system_flags_set |= FLAG_DELETED;
	    }
	    else goto badcri;
	    break;

	case 'f':
	    if (!strcmp(criteria.s, "flagged")) {
		searchargs.system_flags_set |= FLAG_FLAGGED;
	    }
	    else if (!strcmp(criteria.s, "from")) {
		if (c != ' ') goto missingarg;		
		c = getastring(&arg);
		if (c == EOF) goto missingarg;
		appendstrlist(&searchargs.from, arg.s);
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
		    nothing_found++;
		    break;
		}
		searchargs.user_flags_set[flag/32] |= 1<<(flag&31);
	    }
	    else goto badcri;
	    break;

	case 'n':
	    if (!strcmp(criteria.s, "new")) {
		if (searchargs.seen_state == SEARCH_SET ||
		    searchargs.recent_state == SEARCH_UNSET) nothing_found++;
		searchargs.seen_state = SEARCH_UNSET;
		searchargs.recent_state = SEARCH_SET;
	    }
	    else goto badcri;
	    break;

	case 'o':
	    if (!strcmp(criteria.s, "old")) {
		if (searchargs.recent_state == SEARCH_SET) nothing_found++;
		searchargs.recent_state = SEARCH_UNSET;
	    }
	    else if (!strcmp(criteria.s, "on")) {
		if (c != ' ') goto missingarg;		
		c = getdate(&start, &end);
		if (c == EOF) goto baddate;
		if (!searchargs.before || searchargs.before > end) {
		    searchargs.before = end;
		}
		if (!searchargs.after || searchargs.after < start) {
		    searchargs.after = start;
		}
	    }
	    else goto badcri;
	    break;

	case 'r':
	    if (!strcmp(criteria.s, "recent")) {
		if (searchargs.recent_state == SEARCH_UNSET) nothing_found++;
		searchargs.recent_state = SEARCH_SET;
	    }
	    else goto badcri;
	    break;

	case 's':
	    if (!strcmp(criteria.s, "seen")) {
		if (searchargs.seen_state == SEARCH_UNSET) nothing_found++;
		searchargs.seen_state = SEARCH_SET;
	    }
	    else if (!strcmp(criteria.s, "since")) {
		if (c != ' ') goto missingarg;		
		c = getdate(&start, &end);
		if (c == EOF) goto baddate;
		if (!searchargs.after || searchargs.after < start) {
		    searchargs.after = start;
		}
	    }
	    else if (!strcmp(criteria.s, "subject")) {
		if (c != ' ') goto missingarg;		
		c = getastring(&arg);
		if (c == EOF) goto missingarg;
		appendstrlist(&searchargs.subject, arg.s);
	    }
	    else goto badcri;
	    break;

	case 't':
	    if (!strcmp(criteria.s, "to")) {
		if (c != ' ') goto missingarg;		
		c = getastring(&arg);
		if (c == EOF) goto missingarg;
		appendstrlist(&searchargs.to, arg.s);
	    }
	    else if (!strcmp(criteria.s, "text")) {
		if (c != ' ') goto missingarg;		
		c = getastring(&arg);
		if (c == EOF) goto missingarg;
		appendstrlist(&searchargs.text, arg.s);
	    }
	    else goto badcri;
	    break;

	case 'u':
	    if (!strcmp(criteria.s, "unseen")) {
		if (searchargs.seen_state == SEARCH_SET) nothing_found++;
		searchargs.seen_state = SEARCH_UNSET;
	    }
	    else if (!strcmp(criteria.s, "unanswered")) {
		searchargs.system_flags_unset |= FLAG_ANSWERED;
	    }
	    else if (!strcmp(criteria.s, "undeleted")) {
		searchargs.system_flags_unset |= FLAG_DELETED;
	    }
	    else if (!strcmp(criteria.s, "unflagged")) {
		searchargs.system_flags_unset |= FLAG_FLAGGED;
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
		    searchargs.user_flags_unset[flag/32] |= 1<<(flag&31);
		}
	    }
	    else goto badcri;
	    break;

	default:
	badcri:
	    printf("%s BAD Invalid Search criteria\r\n", tag);
	    if (c != '\n') eatline();
	    goto freeargs;
	}
    }

    if (c == '\r') c = getc(stdin);
    if (c != '\n') {
	printf("%s BAD Unexpected extra arguments to Search\r\n", tag);
	eatline();
	goto freeargs;
    }

    if (nothing_found) {
	printf("* SEARCH\r\n");
    }
    else {
	index_search(imapd_mailbox, &searchargs, usinguid);
    }

    printf("%s OK Search completed\r\n", tag);

 freeargs:
    freestrlist(searchargs.from);
    freestrlist(searchargs.to);
    freestrlist(searchargs.cc);
    freestrlist(searchargs.bcc);
    freestrlist(searchargs.subject);
    freestrlist(searchargs.body);
    freestrlist(searchargs.text);
    return;

 missingarg:
    printf("%s BAD Missing required argument to Search %s\r\n",
	   tag, criteria.s);
    if (c != '\n') eatline();
    goto freeargs;

 badflag:
    printf("%s BAD Invalid flag name %s in Search command\r\n",
	   tag, arg.s);
    if (c != '\n') eatline();
    goto freeargs;

 baddate:
    printf("%s BAD Invalid date in Search command\r\n",
	   tag);
    if (c != '\n') eatline();
    goto freeargs;
}
    
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

    r = mboxlist_createmailbox(name, MAILBOX_FORMAT_NORMAL, partition,
			       imapd_userisadmin, imapd_userid);

    if (r) {
	printf("%s NO Create failed: %s\r\n", tag, error_message(r));
    }
    else {
	printf("%s OK Create completed\r\n", tag);
    }
}	

cmd_find(tag, namespace, pattern)
char *tag;
char *namespace;
char *pattern;
{
    lcase(namespace);
    if (!strcmp(namespace, "mailboxes")) {
	mboxlist_find(pattern, imapd_userisadmin, imapd_userid);
    }
    else if (!strcmp(namespace, "all.mailboxes")) {
	mboxlist_findall(pattern, imapd_userisadmin, imapd_userid);
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
  
cmd_changesub(tag, namespace, name, add)
char *tag;
char *namespace;
char *name;
int add;
{
    int r;

    lcase(namespace);
    if (!strcmp(namespace, "mailbox")) {
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
	if (imapd_userisadmin || strcasecmp(name, "inbox")) {
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
	buf->s[0] = '\0';
	if (c != EOF) ungetc(c, stdin);
	return EOF;

    default:
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
	buf->s[0] = '\0';
	while ((c = getc(stdin)) != EOF && isdigit(c)) {
	    len = len*10 + c - '0';
	}
	if (c != '}') {
	    if (c != EOF) ungetc(c, stdin);
	    return EOF;
	}
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

int getsequence(buf)
struct buf *buf;
{
    int c;
    int i, len = 0;
    int sawcolon = 0;

    if (buf->alloc == 0) {
	buf->alloc = BUFGROWSIZE;
	buf->s = xmalloc(buf->alloc+1);
    }
	
    for (;;) {
	c = getc(stdin);
	if (len == buf->alloc) {
	    buf->alloc += BUFGROWSIZE;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
	}
	buf->s[len] = c;
	if (c == ',') {
	    if (!len || !isdigit(buf->s[len-1])) return EOF;
	    sawcolon = 0;
	}
	else if (c == ':') {
	    if (sawcolon || !len || !isdigit(buf->s[len-1])) return EOF;
	    sawcolon = 1;
	}
	else if (!isdigit(c)) {
	    if (!len || !isdigit(buf->s[len-1])) return EOF;
	    buf->s[len] = '\0';
	    return c;
	}
	len++;
    }
}

int getdate(start, end)
time_t *start, *end;
{
    int c;
    struct tm tm;
    static struct tm zerotm;
    int quoted = 0;
    char month[4];
    static char *monthname[] = {
	"jan", "feb", "mar", "apr", "may", "jun",
	"jul", "aug", "sep", "oct", "nov", "dec" };

    tm = zerotm;

    c = getc(stdin);
    if (c == '\"') {
	quoted++;
	c = getc(stdin);
    }

    if (!isdigit(c)) goto baddate;
    tm.tm_mday = c - '0';
    c = getc(stdin);
    if (isdigit(c)) {
	tm.tm_mday = tm.tm_mday * 10 + c - '0';
	c = getc(stdin);
    }
    
    if (c != '-') goto baddate;
    c = getc(stdin);

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
    ungetc(c);
    return EOF;
}
	
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

eatline()
{
    char c;

    while ((c = getc(stdin)) != EOF && c != '\n');
}

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

appendstrlist(l, s)
struct strlist **l;
char *s;
{
    struct strlist **tail = l;

    while (*tail) tail = &(*tail)->next;

    *tail = (struct strlist *)xmalloc(sizeof(struct strlist));
    (*tail)->s = strsave(s);
    (*tail)->glob = 0;
    (*tail)->next = 0;
}

freestrlist(l)
struct strlist *l;
{
    struct strlist *n;

    while (l) {
	n = l->next;
	free(l->s);
	if (l->glob) glob_free(l->glob);
	free((char *)l);
	l = n;
    }
}

shutdown(code)
int code;
{
    if (imapd_mailbox) {
	index_checkseen(imapd_mailbox, 1, 0, imapd_exists);
	mailbox_close(imapd_mailbox);
    }
    exit(code);
}

