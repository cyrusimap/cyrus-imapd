/*
 * IMAP server
 */

#include <stdio.h>
#include <sysexits.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <syslog.h>
#include <com_err.h>

#include <acl.h>
#include "auth.h"
#include "imap_err.h"
#include "mailbox.h"
#include "imapd.h"
#include "xmalloc.h"

extern int optind;
extern char *optarg;

extern int errno;

extern char *lcase();

struct buf {
    char *s;
    int alloc;
};

char *imapd_userid;
int imapd_userisadmin;
struct mailbox *imapd_mailbox;
int imapd_exists;

static struct mailbox mboxstruct;

static struct fetchargs zerofetchargs;

main(argc, argv)
{
    char hostname[MAXHOSTNAMELEN+1];
    int opt;

    config_init("imapd");

#if 0
    while ((opt = getopt(argc, argv, "")) != EOF) {
	switch(opt) {
	default:
	    usage();
	}
    }
#endif

    signal(SIGPIPE, SIG_IGN);

    gethostname(hostname, sizeof(hostname));
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
    printf("* BYE Fatal error: %s\r\n", s);
    exit(code);
}

cmdloop()
{
    int c;
    int usinguid;
    static struct buf tag, cmd, arg1, arg2, arg3, arg4;
    char *p;

    for (;;) {
	fflush(stdout);

	c = getword(&tag);
	if (c == EOF) {
	    shutdown();
	}
	if (c != ' ' || !isatom(&tag) || (tag.s[0] == '*' && !tag.s[1])) {
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
		shutdown();
	    }
	    else if (!imapd_userid) goto nologin;
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
		else if (!strcmp(arg1.s, "after")) {
		    c = getword(&arg2);
		    if (c != '\n') goto extraargs;
		    cmd_uidafter(tag.s, arg2.s);
		}
		/* XXX store copy */
		else {
		    printf("%s BAD Unrecognized UID subcommand\r\n", tag.s);
		    if (c != '\n') eatline();
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
	printf("%s NO Invalid user %s\r\n", tag, user);	/* XXX beautify user */
	return;
    }

    if (!strcmp(canon_user, "anonymous")) {
	if (config_getswitch("allowanonymouslogin", 0)) {
	    syslog(LOG_NOTICE, "login: anonymous"); /* XXX Log cleaned passwd*/
	    reply = "Anonymous access granted";
	}
	else {
	    syslog(LOG_NOTICE, "badlogin: anonymous login refused");
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
{
    if (imapd_mailbox) {
	index_check(imapd_mailbox);
    }
    printf("%s OK %s completed\r\n", tag, cmd);
};

cmd_select(tag, cmd, name)
char *tag;
char *cmd;
char *name;
{
    struct mailbox mailbox;
    int r;
    int i;
    int usage;
    int doclose = 0;

    r = mailbox_open_header(name, &mailbox);
    if (!r) {
	doclose = 1;
	r = mailbox_open_index(&mailbox);
    }
    if (!r && !(mailbox.my_acl & ACL_READ)) r = IMAP_PERMISSION_DENIED;
    if (!r && chdir(mailbox.path)) {
	r = IMAP_IOERROR;
    }

    if (r) {
	printf("%s NO %s of %s failed: %s\r\n", tag, cmd,
	       name, error_message(r));
				/* XXX clean name, reply token */
	if (doclose) mailbox_close(&mailbox);
	return;
    }

    if (imapd_mailbox) mailbox_close(imapd_mailbox);
    mboxstruct = mailbox;
    imapd_mailbox = &mboxstruct;

    printf("* FLAGS (\\Answered \\Flagged \\Deleted");
    if (imapd_mailbox->my_acl & ACL_SEEN) {
	printf(" \\Seen");
    }
    for (i = 0; i < MAX_USER_FLAGS; i++) {
	if (imapd_mailbox->flagname[i]) {
	    printf(" %s", imapd_mailbox->flagname[i]);
	}
    }
    printf(")\r\n");

    index_newmailbox(imapd_mailbox);

    /* Examine command puts mailbox in read-only mode */
    if (cmd[0] == 'E') {
	imapd_mailbox->my_acl &= ~(ACL_SEEN|ACL_WRITE|ACL_DELETE);
    }

    if (imapd_mailbox->my_acl & ACL_DELETE) {
	mailbox_read_quota(imapd_mailbox);
	if (imapd_mailbox->quota_limit > 0) {
	    usage = imapd_mailbox->quota_used * 100 /
	      (imapd_mailbox->quota_limit * QUOTA_UNITS);
	    if (usage >= 100) {
		printf("* BAD Mailbox %s is over quota\r\n", name);
	    }
	    else if (usage > config_getint("quotawarn", 90)) {
		printf("* BAD Mailbox %s is at %d%% of quota\r\n",
		       name, usage);
	    }
	}
    }

    printf("%s OK [READ-%s] %s completed\r\n", tag,
	   imapd_mailbox->my_acl & ACL_WRITE ? "WRITE" : "ONLY", cmd);

    syslog(LOG_INFO, "open: user %s opened %s", imapd_userid, name);
}
	  
cmd_fetch(tag, sequence, usinguid)
char *tag;
char *sequence;
int usinguid;
{
    char *cmd = usinguid ? "UID Fetch" : "Fetch";
    static struct buf fetchatt;
    int c;
    int inlist = 0;
    int fetchitems = 0;
    struct fetchargs fetchargs;
    int r;

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
		fetchitems |= FETCH_RFC822;
	    }
	    else if (!strcmp(fetchatt.s, "rfc822.header")) {
		fetchitems |= FETCH_HEADER;
	    }
	    else if (!strcmp(fetchatt.s, "rfc822.size")) {
		fetchitems |= FETCH_SIZE;
	    }
	    else if (!strcmp(fetchatt.s, "rfc822.text")) {
		fetchitems |= FETCH_TEXT;
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
	    printf("%s BAD Invalid %s item %s\r\n", tag, cmd, fetchatt.s);
	    if (c != '\n') eatline();
	    return;
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
	return;
    }
    if (c != '\n') {
	printf("%s BAD Unexpected extra arguments to %s\r\n", tag, cmd);
	eatline();
	return;
    }

    if (!fetchitems) {
	printf("%s BAD Missing required argument to %s", tag, cmd);
	return;
    }

    if (usinguid) {
	fetchitems |= FETCH_UID;
	index_check(imapd_mailbox);
    }

    fetchargs.fetchitems = fetchitems;
    r = index_fetch(imapd_mailbox, sequence, usinguid, &fetchargs);

    if (r) {
	printf("%s NO %s failed: %s\r\n", tag, cmd, error_message(r));
    }
    else {
	printf("%s OK %s completed\r\n", tag, cmd);
    }
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
	fetchargs.fetchitems = FETCH_RFC822;
    }
    else if (!strcmp(data, "rfc822.header")) {
	fetchargs.fetchitems = FETCH_HEADER;
    }
    else if (!strcmp(data, "rfc822.text")) {
	fetchargs.fetchitems = FETCH_TEXT;
    }
    /* XXX body[n] */
    else {
	printf("%s BAD Invalid Partial item\r\n", tag);
	return;
    }

    for (p = start; *p; p++) {
	if (!isdigit(*p)) break;
	fetchargs.start_octet = fetchargs.start_octet*10 + *p - '0';
    }
    if (*p || !fetchargs.start_octet) {
	printf("%s BAD Invalid starting octet\r\n", tag);
	return;
    }
    
    for (p = count; *p; p++) {
	if (!isdigit(*p)) break;
	fetchargs.octet_count = fetchargs.octet_count*10 + *p - '0';
    }
    if (*p || !*count) {
	printf("%s BAD Invalid octet count\r\n", tag);
	return;
    }

    r = index_fetch(imapd_mailbox, msgno, 0, &fetchargs);

    index_check(imapd_mailbox);

    if (r) {
	printf("%s NO Partial failed: %s\r\n", tag, error_message(r));
    }
    else {
	printf("%s OK Partial completed\r\n", tag);
    }
}

cmd_uidafter(tag, arg)
char *tag;
char *arg;
{
    int c, num = 0;
    struct fetchargs fetchargs;
    int r = 0;
    char sequence[60];

    while (c = *arg++) {
	if (!isdigit(c)) {
	    printf("%s BAD Invalid number in UID After command\r\n", tag);
	    return;
	}
	num = num*10 + c - '0';
    }
    
    index_check(imapd_mailbox);

    fetchargs = zerofetchargs;
    fetchargs.fetchitems = FETCH_UID;

    num = index_finduid(num)+1;
    if (num <= imapd_exists) {
	sprintf(sequence, "%d:%d", num, imapd_exists);
	r = index_fetch(imapd_mailbox, sequence, 0, &fetchargs);
    }

    if (r) {
	printf("%s NO UID After failed: %s\r\n", tag, error_message(r));
    }
    else {
	printf("%s OK UID After completed\r\n", tag);
    }
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

int isatom(buf)
struct buf *buf;
{
    char *p;

    if (!buf->s[0]) return 0;
    for (p = buf->s; *p; p++) {
	if (*p & 0x80 || *p < 0x1f || *p == 0x7f ||
	    *p == ' ' || *p == '{' || *p == '(' || *p == ')' ||
	    *p == '\"' || *p == '%' || *p == '\\') return 0;
    }
    return 1;
}

eatline()
{
    char c;

    while ((c = getc(stdin)) != EOF && c != '\n');
}

shutdown()
{
    exit(0);
}

