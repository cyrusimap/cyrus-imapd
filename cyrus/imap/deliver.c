/* deliver.c -- Program to deliver mail to a mailbox
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <com_err.h>
#include <errno.h>
#ifdef HAVE_LIBDB
#include <db.h>
#else
#include <ndbm.h>
#endif

#include "acl.h"
#include "util.h"
#include "auth.h"
#include "prot.h"
#include "imparse.h"
#include "lock.h"
#include "config.h"
#include "sysexits.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"

extern int optind;
extern char *optarg;

extern int errno;

int dupelim = 0;

struct protstream *savemsg();
char *convert_lmtp();

main(argc, argv)
int argc;
char **argv;
{
    int opt;
    int r;
    int exitval = 0;
    char *return_path = 0;
    int lmtpflag = 0;
    char *mailboxname = 0;
    struct protstream *prot_f;
    unsigned size;
    char **flag = 0;
    int nflags = 0;
    char *authuser = 0;
    struct auth_state *authstate = 0;
    int quotaoverride = 0;
    char *id = 0;
    char *notifyheader = 0;

    config_init("deliver");

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);

    while ((opt = getopt(argc, argv, "df:r:m:a:F:eE:lq")) != EOF) {
	switch(opt) {
	case 'd':
	    /* Ignore -- /bin/mail compatibility flags */
	    break;

	case 'r':
	case 'f':
	    return_path = optarg;
	    break;

	case 'm':
	    if (mailboxname) {
		fprintf(stderr, "deliver: multiple -m options\n");
		usage();
	    }
	    if (*optarg) mailboxname = optarg;
	    break;

	case 'a':
	    if (authuser) {
		fprintf(stderr, "deliver: multiple -a options\n");
		usage();
	    }
	    authuser = optarg;
	    break;

	case 'F':
	    if (!isvalidflag(optarg)) break;
	    nflags++;
	    flag = (char **)xrealloc((char *)flag, nflags*sizeof(char *));
	    flag[nflags-1] = optarg;
	    break;

	case 'e':
	    dupelim = 1;
	    break;

	case 'E':
	    exit(prunedelivered(atoi(optarg)));

	case 'l':
	    lmtpflag = 1;
	    break;

	case 'q':
	    quotaoverride = 1;
	    break;

	default:
	    usage();
	}
    }

    if (lmtpflag) {
	lmtpmode(quotaoverride);
	exit(0);
    }

    if (authuser) {
	authuser = auth_canonifyid(authuser);
	if (authuser) authstate = auth_newstate(authuser, (char *)0);
    }

    /* Copy message to temp file */
    prot_f = savemsg(return_path, dupelim ? &id : (char **)0,
		     notify_wantheader() ? &notifyheader : (char **)0,
		     &size, 0);

    if (optind == argc) {
	/* deliver to global mailbox */
	r = deliver(prot_f, size, flag, nflags, authuser, authstate, id, notifyheader,
		    (char *)0, mailboxname, quotaoverride);
	
	if (r) {
	    com_err(mailboxname, r,
		    (r == IMAP_IOERROR) ? error_message(errno) : NULL);
	}

	exitval = convert_sysexit(r);
	exit(exitval);
    }
    while (optind < argc) {
	r = deliver(prot_f, size, flag, nflags, authuser, authstate, id, notifyheader,
		       argv[optind], mailboxname, quotaoverride);

	if (r) {
	    com_err(argv[optind], r,
		    (r == IMAP_IOERROR) ? error_message(errno) : NULL);
	}

	if (r && exitval != EX_TEMPFAIL) exitval = convert_sysexit(r);

	optind++;
    }
    exit(exitval);
}

usage()
{
    fprintf(stderr, 
"421-4.3.0 usage: deliver [-m mailbox] [-a auth] [-i] [-F flag]... [user]...\r\n");
    fprintf(stderr, "421 4.3.0        deliver -I age\n");
    exit(EX_USAGE);
}

char *parseaddr(s)
char *s;
{
    char *p;
    int len;

    p = s;

    if (*p++ != '<') return 0;

    /* at-domain-list */
    while (*p == '@') {
	p++;
	if (*p == '[') {
	    p++;
	    while (isdigit(*p) || *p == '.') p++;
	    if (*p++ != ']') return 0;
	}
	else {
	    while (isalnum(*p) || *p == '.' || *p == '-') p++;
	}
	if (*p == ',' && p[1] == '@') p++;
	else if (*p == ':' && p[1] != '@') p++;
	else return 0;
    }
    
    /* local-part */
    if (*p == '\"') {
	p++;
	while (*p && *p != '\"') {
	    if (*p == '\\') {
		if (!*++p) return 0;
	    }
	    p++;
	}
	if (!*p++) return 0;
    }
    else {
	while (*p && *p != '@' && *p != '>') {
	    if (*p == '\\') {
		if (!*++p) return 0;
	    }
	    else {
		if (*p <= ' ' || (*p & 128) ||
		    strchr("<>()[]\\,;:\"", *p)) return 0;
	    }
	    p++;
	}
    }

    /* @domain */
    if (*p == '@') {
	p++;
	if (*p == '[') {
	    p++;
	    while (isdigit(*p) || *p == '.') p++;
	    if (*p++ != ']') return 0;
	}
	else {
	    while (isalnum(*p) || *p == '.' || *p == '-') p++;
	}
    }
    
    if (*p++ != '>') return 0;
    if (*p && *p != ' ') return 0;
    len = p - s;

    s = xstrdup(s);
    s[len] = '\0';
    return s;
}

char *process_recipient(addr)
char *addr;
{
    char *dest = addr;
    char *user = addr;
    char *plus, *dot;
    char buf[1024];
    int r;

    if (*addr == '<') addr++;

    /* Skip at-domain-list */
    if (*addr == '@') {
	addr = strchr(addr, ':');
	if (!addr) return "501 5.5.4 Syntax error in parameters";
	addr++;
    }

    if (*addr == '\"') {
	addr++;
	while (*addr && *addr != '\"') {
	    if (*addr == '\\') addr++;
	    *dest++ = *addr++;
	}
    }
    else {
	while (*addr != '@' && *addr != '>') {
	    if (*addr == '\\') addr++;
	    *dest++ = *addr++;
	}
    }
    *dest = 0;

    dot = strchr(user, '.');
    plus = strchr (user, '+');
    if (plus && (!dot || plus < dot)) dot = plus;

    if (dot) *dot = '\0';
    if (*user) {
	if (strlen(user) > sizeof(buf)-10) {
	    return convert_lmtp(IMAP_MAILBOX_NONEXISTENT);
	}
	strcpy(buf, "user.");
	strcat(buf, user);
	r = mboxlist_lookup(buf, (char **)0, (char **)0);
    }
    else {
	r = mboxlist_lookup(user+1, (char **)0, (char **)0);
    }
    if (r) {
	return convert_lmtp(r);
    }
    if (dot) *dot = '.';

    return 0;
}    


#define RCPT_GROW 3 /* XXX 30 */

lmtpmode(quotaoverride)
int quotaoverride;
{
    char *return_path = 0;
    char **rcpt_addr = 0;
    int rcpt_num = 0;
    int rcpt_alloc = 0;
    char myhostname[1024];
    char buf[4096];
    int r;
    char *err;
    struct protstream *prot_f;
    unsigned size;
    char **flag = 0;
    int nflags = 0;
    char *authuser = 0;
    struct auth_state *authstate = 0;
    char *id = 0;
    char *notifyheader = 0;
    char *p;
    int i;

    gethostname(myhostname, sizeof(myhostname)-1);
    
    printf("220 %s LMTP ready\r\n", myhostname);
    for (;;) {
	fflush(stdout);
	if (!fgets(buf, sizeof(buf)-1, stdin)) {
	    exit(0);
	}
	p = buf + strlen(buf) - 1;
	if (p >= buf && *p == '\n') *p-- = '\0';
	if (p >= buf && *p == '\r') *p-- = '\0';

	switch (buf[0]) {

	case 'd':
	case 'D':
	    if (!strcasecmp(buf, "data")) {
		if (!rcpt_num) {
		    printf("503 5.5.1 No recipients\r\n");
		}
		prot_f = savemsg(return_path, dupelim ? &id : (char **)0,
				 notify_wantheader() ? &notifyheader : (char **)0,
				 &size, rcpt_num);
		if (!prot_f) continue;

		for (i = 0; i < rcpt_num; i++) {
		    p = strchr(rcpt_addr[i], '.');
		    if (p) *p++ = '\0';

		    r = deliver(prot_f, size, flag, nflags, authuser, authstate, id,
				notifyheader,
				rcpt_addr[i][0] ? rcpt_addr[i] : (char *)0, p,
				quotaoverride);
		    printf("%s\r\n", convert_lmtp(r));
		}
		prot_free(prot_f);
		goto rset;
	    }
	    goto syntaxerr;

	case 'l':
	case 'L':
	    if (!strncasecmp(buf, "lhlo ", 5)) {
		printf("250-%s\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n250 PIPELINING\r\n",
		       myhostname);
		continue;
	    }
	    goto syntaxerr;

	case 'm':
	case 'M':
	    if (!strncasecmp(buf, "mail ", 5)) {
		if (return_path) {
		    printf("503 5.5.1 Nested MAIL command\r\n");
		    continue;
		}
		if (strncasecmp(buf+5, "from:", 5) != 0 ||
		    !(return_path = parseaddr(buf+10))) {
		    printf("501 5.5.4 Syntax error in parameters\r\n");
		    continue;
		}
		printf("250 2.1.0 ok\r\n");
		continue;
	    }
	    goto syntaxerr;

	case 'n':
	case 'N':
	    if (!strcasecmp(buf, "noop")) {
		printf("250 2.0.0 ok\r\n");
		continue;
	    }
	    goto syntaxerr;

	case 'q':
	case 'Q':
	    if (!strcasecmp(buf, "quit")) {
		printf("221 2.0.0 bye\r\n");
		exit(0);
	    }
	    goto syntaxerr;
	    
	case 'r':
	case 'R':
	    if (!strncasecmp(buf, "rcpt ", 5)) {
		if (!return_path) {
		    printf("503 5.5.1 Need MAIL command\r\n");
		    continue;
		}
		if (rcpt_num == rcpt_alloc) {
		    rcpt_alloc += RCPT_GROW;
		    rcpt_addr = (char **)
			xrealloc((char *)rcpt_addr,
				 rcpt_alloc * sizeof(char **));
		}
		if (strncasecmp(buf+5, "to:", 3) != 0 ||
		    !(rcpt_addr[rcpt_num] = parseaddr(buf+8))) {
		    printf("501 5.5.4 Syntax error in parameters\r\n");
		    continue;
		}
		if (err = process_recipient(rcpt_addr[rcpt_num])) {
		    printf("%s\r\n", err);
		    continue;
		}
		rcpt_num++;
		printf("250 2.1.5 ok\r\n");
		continue;
	    }
	    else if (!strcasecmp(buf, "rset")) {
		printf("250 2.0.0 ok\r\n");

	      rset:
		while (rcpt_num) {
		    free(rcpt_addr[--rcpt_num]);
		}
		if (return_path) free(return_path);
		return_path = 0;
		continue;
	    }
	    goto syntaxerr;
	    
	case 'v':
	case 'V':
	    if (!strncasecmp(buf, "vrfy ", 5)) {
		printf("252 2.3.3 try RCPT to attempt delivery\r\n");
		continue;
	    }
	    goto syntaxerr;

	default:
	syntaxerr:
	    printf("500 5.5.2 Syntax error\r\n");
	    continue;
	}
    }
}


struct protstream *
savemsg(return_path, idptr, notifyptr, sizeptr, lmtpmode)
char *return_path;
char **idptr;
char **notifyptr;
unsigned *sizeptr;
int lmtpmode;
{
    FILE *f;
    char *hostname = 0;
    int scanheader = 1;
    int sawidhdr = 0, sawresentidhdr = 0;
    int sawnotifyheader = 0;
    char buf[4096], *p;
    struct stat sbuf;

    if (!idptr && !notifyptr) scanheader = 0;
    if (idptr) *idptr = 0;
    if (notifyptr) *notifyptr = 0;

    /* Copy to temp file */
    f = tmpfile();
    if (!f) {
	if (lmtpmode) {
	    printf("451 4.3.%c cannot create temporary file: %s\r\n",
		   (
#ifdef EDQUOT
		    errno == EDQUOT ||
#endif
		    errno == ENOSPC) ? '1' : '2',
		   error_message(errno));
	    return 0;
	}
	exit(EX_TEMPFAIL);
    }

    if (lmtpmode) {
	printf("354 go ahead\r\n");
	fflush(stdout);
    }

    if (return_path) {
	/* Remove any angle brackets around return path */
	if (*return_path == '<') {
	    return_path = xstrdup(return_path+1);
	    if (return_path[strlen(return_path)-1] == '>') {
		return_path[strlen(return_path)-1] = '\0';
	    }
	}

	/* Append our hostname if there's no domain in address */
	if (!strchr(return_path, '@')) {
	    gethostname(buf, sizeof(buf)-1);
	    hostname = buf;
	}

	fprintf(f, "Return-Path: <%s%s%s>\r\n",
		return_path,
		hostname ? "@" : "",
		hostname ? hostname : "");
    }

    while (fgets(buf, sizeof(buf)-1, stdin)) {
	p = buf + strlen(buf) - 1;
	if (*p == '\n') {
	    if (p == buf || p[-1] != '\r') {
		p[0] = '\r';
		p[1] = '\n';
		p[2] = '\0';
	    }
	}
	else if (*p == '\r') {
	    /*
	     * We were unlucky enough to get a CR just before we ran
	     * out of buffer--put it back.
	     */
	    ungetc('\r', stdin);
	    *p = '\0';
	}

	/* Remove any lone CR characters */
	while ((p = strchr(buf, '\r')) && p[1] != '\n') {
	    strcpy(p, p+1);
	}

	if (lmtpmode && buf[0] == '.') {
	    if (buf[1] == '\r' && buf[2] == '\n') {
		/* End of message */
		goto lmtpdot;
	    }
	    /* Remove the dot-stuffing */
	    fputs(buf+1, f);
	}
	else {
	    fputs(buf, f);
	}

	/* Look for message-id or resent-message-id headers */
	if (scanheader) {
	    p = 0;
	    if (*buf == '\r') scanheader = 0;
	    if (sawnotifyheader) {
		if (*buf == ' ' || *buf == '\t') {
		    *notifyptr =
			xrealloc(*notifyptr,
				 strlen(*notifyptr) + strlen(buf) + 1);
		    strcat(*notifyptr, buf);
		}
		else sawnotifyheader = 0;
	    }
	    if (sawidhdr || sawresentidhdr) {
		if (*buf == ' ' || *buf == '\t') p = buf+1;
		else sawidhdr = sawresentidhdr = 0;
	    }

	    if (idptr && !*idptr && !strncasecmp(buf, "message-id:", 11)) {
		sawidhdr = 1;
		p = buf + 11;
	    }
	    else if (idptr && !strncasecmp(buf, "resent-message-id:", 18)) {
		sawresentidhdr = 1;
		p = buf + 18;
	    }
	    else if (notifyptr &&
		     (!strncasecmp(buf, "from:", 5) ||
		      !strncasecmp(buf, "subject:", 8) ||
		      !strncasecmp(buf, "to:", 3))) {
		if (!*notifyptr) *notifyptr = xstrdup(buf);
		else {
		    *notifyptr =
			xrealloc(*notifyptr,
				 strlen(*notifyptr) + strlen(buf) + 1);
		    strcat(*notifyptr, buf);
		}
		sawnotifyheader = 1;
	    }

	    if (p) {
		clean822space(p);
		if (*p) {
		    *idptr = xstrdup(p);
		    /*
		     * If we got a resent-message-id header,
		     * we're done looking for *message-id headers.
		     */
		    if (sawresentidhdr) idptr = 0;
		    sawresentidhdr = sawidhdr = 0;
		}
	    }
	}

    }

    if (lmtpmode) {
	/* Got a premature EOF -- toss message and exit */
	exit(0);
    }

  lmtpdot:
    fflush(f);
    if (ferror(f)) {
	if (!lmtpmode) {
	    perror("deliver: copying message");
	    exit(EX_TEMPFAIL);
	}
	while (lmtpmode--) {
	    printf("451 4.3.%c cannot copy message to temporary file: %s\r\n",
		   (
#ifdef EDQUOT
		    errno == EDQUOT ||
#endif
		    errno == ENOSPC) ? '1' : '2',
		   error_message(errno));
	}
	fclose(f);
	return 0;
    }
    if (fstat(fileno(f), &sbuf) == -1) {
	if (!lmtpmode) {
	    perror("deliver: stating message");
	    exit(EX_TEMPFAIL);
	}
	while (lmtpmode--) {
	    printf("451 4.3.2 cannot stat message temporary file: %s\r\n",
		   error_message(errno));
	}
	fclose(f);
	return 0;
    }
    *sizeptr = sbuf.st_size;
	
    return prot_new(fileno(f), 0);
}


deliver(msg, size, flag, nflags, authuser, authstate, id, notifyheader,
	user, mailboxname, quotaoverride)
struct protstream *msg;
unsigned size;
char **flag;
int nflags;
char *authuser;
struct auth_state *authstate;
char *id;
char *notifyheader;
char *user;
char *mailboxname;
int quotaoverride;
{
    int r;
    struct mailbox mailbox;
    char namebuf[MAX_MAILBOX_PATH];
    char notifybuf[MAX_MAILBOX_PATH];
    char *submailbox = 0;
    
    if (user) {
	if (strchr(user, '.') ||
	    strlen(user) + 30 > MAX_MAILBOX_PATH) {
	    return IMAP_MAILBOX_NONEXISTENT;
	}
	if (!mailboxname ||
	    strlen(user) + strlen(mailboxname) + 30 > MAX_MAILBOX_PATH) {
	    r = IMAP_MAILBOX_NONEXISTENT;
	}
	else {
	    strcpy(namebuf, "user.");
	    strcat(namebuf, user);
	    strcat(namebuf, ".");
	    strcat(namebuf, mailboxname);
	    submailbox = mailboxname;

	    if (id && checkdelivered(id, namebuf)) {
		logdupelem(id, namebuf);
		return 0;
	    }

	    r = append_setup(&mailbox, namebuf, MAILBOX_FORMAT_NORMAL,
			     authstate, ACL_POST, quotaoverride ? -1 : 0);
	}
	if (r) {
	    strcpy(namebuf, "user.");
	    strcat(namebuf, user);
	    submailbox = 0;
	    
	    if (id && checkdelivered(id, namebuf)) {
		logdupelem(id, namebuf);
		return 0;
	    }
	    r = append_setup(&mailbox, namebuf, MAILBOX_FORMAT_NORMAL,
			     authstate, 0, quotaoverride ? -1 : 0);
	}
    }
    else if (mailboxname) {
	if (id && checkdelivered(id, mailboxname)) {
	    logdupelem(id, mailboxname);
	    return 0;
	}
	r = append_setup(&mailbox, mailboxname, MAILBOX_FORMAT_NORMAL,
			 authstate, ACL_POST, quotaoverride ? -1 : 0);
    }
    else {
	fprintf(stderr, "deliver: either -m or user required\n");
	usage();
    }

    if (!r) {
	prot_rewind(msg);
	r = append_fromstream(&mailbox, msg, size, time(0), flag, nflags,
			      user);
	mailbox_close(&mailbox);
    }

    if (!r && user) {
	strcpy(notifybuf, "INBOX");
	if (submailbox) {
	    strcat(notifybuf, ".");
	    strcat(notifybuf, submailbox);
	}
	notify(user, notifybuf, notifyheader ? notifyheader : "");
    }

    if (!r && dupelim && id) markdelivered(id, user ? namebuf : mailboxname);

    return r;
}

logdupelem(msgid, name)
char *msgid;
char *name;
{
    if (strlen(msgid) < 80) {
	syslog(LOG_INFO, "dupelim: elminated duplicate message to %s id %s",
	       name, msgid);
    }
    else {
	syslog(LOG_INFO, "dupelim: elminated duplicate message to %s",
	       name);
    }	
}

int convert_sysexit(r)
int r;
{
    switch (r) {
    case 0:
	return 0;
	
    case IMAP_IOERROR:
	return EX_IOERR;

    case IMAP_PERMISSION_DENIED:
	return EX_NOPERM;

    case IMAP_MAILBOX_BADFORMAT:
    case IMAP_MAILBOX_NOTSUPPORTED:
    case IMAP_QUOTA_EXCEEDED:
	return EX_TEMPFAIL;

    case IMAP_MESSAGE_CONTAINSNULL:
    case IMAP_MESSAGE_CONTAINSNL:
    case IMAP_MESSAGE_CONTAINS8BIT:
    case IMAP_MESSAGE_BADHEADER:
    case IMAP_MESSAGE_NOBLANKLINE:
	return EX_DATAERR;

    case IMAP_MAILBOX_NONEXISTENT:
	/* XXX Might have been moved to other server */
	return EX_NOUSER;
    }
	
    /* Some error we're not expecting. */
    return EX_SOFTWARE;
}	

char *convert_lmtp(r)
int r;
{
    switch (r) {
    case 0:
	return "250 2.1.5 Ok";
	
    case IMAP_IOERROR:
	return "451 4.3.0 System I/O error";
	
    case IMAP_PERMISSION_DENIED:
	return "550 5.7.1 Permission denied";

    case IMAP_QUOTA_EXCEEDED:
	return "452 4.2.2 Over quota";

    case IMAP_MAILBOX_BADFORMAT:
    case IMAP_MAILBOX_NOTSUPPORTED:
	return "451 4.2.0 Mailbox has an invalid format";

    case IMAP_MESSAGE_CONTAINSNULL:
	return "554 5.6.0 Message contains NUL characters";
	
    case IMAP_MESSAGE_CONTAINSNL:
	return "554 5.6.0 Message contains bare newlines";

    case IMAP_MESSAGE_CONTAINS8BIT:
	return "554 5.6.0 Message contains non-ASCII characters in headers";

    case IMAP_MESSAGE_BADHEADER:
	return "554 5.6.0 Message contains invalid header";

    case IMAP_MESSAGE_NOBLANKLINE:
	return "554 5.6.0 Message has no header/body separator";

    case IMAP_MAILBOX_NONEXISTENT:
	/* XXX Might have been moved to other server */
	return "550 5.1.1 User unknown";
    }
	
    /* Some error we're not expecting. */
    return "554 5.0.0 Unexpected internal error";
}

fatal(s, code)
char *s;
int code;
{
    printf("421 4.3.0 deliver: %s\r\n", s);
    exit(code);
}

int isvalidflag(f)
char *f;
{
    if (f[0] == '\\') {
	lcase(f);
	if (strcmp(f, "\\seen") && strcmp(f, "\\answered") &&
	    strcmp(f, "\\flagged") && strcmp(f, "\\draft") &&
	    strcmp(f, "\\deleted")) {
	    return 0;
	}
	return 1;
    }
    if (!imparse_isatom(f)) return 0;
    return 1;
}

/*
 * Destructively remove any whitespace and 822 comments
 * from string pointed to by 'buf'.  Does not handle continuation header
 * lines.
 */
clean822space(buf)
char *buf;
{
    char *from=buf, *to=buf;
    int c;
    int commentlevel = 0;

    while (c = *from++) {
	switch (c) {
	case '\r':
	case '\n':
	case '\0':
	    *to = '\0';
	    return;

	case ' ':
	case '\t':
	    continue;

	case '(':
	    commentlevel++;
	    break;

	case ')':
	    if (commentlevel) commentlevel--;
	    break;

	case '\\':
	    if (commentlevel && *from) from++;
	    /* FALL THROUGH */

	default:
	    if (!commentlevel) *to++ = c;
	    break;
	}
    }
}

#ifdef HAVE_LIBDB
static DB	*DeliveredDBptr;
#else
static DBM	*DeliveredDBptr;
#endif

checkdelivered(id, to)
char *id, *to;
{
#ifdef HAVE_LIBDB
    static int initialized = 0;
    char buf[MAX_MAILBOX_PATH];
    DBT date, delivery;
    int i;

    if (!initialized) {
	initialized++;

	sprintf(buf, "%s/delivered.db", config_dir);
	DeliveredDBptr = dbopen(buf, O_RDWR|O_CREAT, 0666, DB_HASH, NULL);
	if (!DeliveredDBptr) {
	    fprintf(stderr, "deliver: can't open %s: %s", buf,
		    error_message(errno));
	    
	}
    }

    if (!DeliveredDBptr) return 0;

    sprintf(buf, "%s%c%s", id, '\0', to);
    delivery.data = buf;
    delivery.size = strlen(id) + strlen(to) + 1;
    i = DeliveredDBptr->get(DeliveredDBptr, &delivery, &date, 0);
    return (i == 0);
#else /* HAVE_LIBDB */
    static int initialized = 0;
    char buf[MAX_MAILBOX_PATH];
    datum date, delivery;

    if (!initialized) {
	initialized++;

	sprintf(buf, "%s/delivered", config_dir);
	DeliveredDBptr = dbm_open(buf, O_RDWR|O_CREAT, 0666);
	if (!DeliveredDBptr) {
	    fprintf(stderr, "deliver: can't open %s DBM database: %s",
		    buf, error_message(errno));
	}
    }

    if (!DeliveredDBptr) return 0;

    sprintf(buf, "%s%c%s", id, '\0', to);
    delivery.dptr = buf;
    delivery.dsize = strlen(id) + strlen(to) + 1;
    date = dbm_fetch(DeliveredDBptr, delivery);
    return (date.dptr != 0);
#endif /* HAVE_LIBDB */
}

markdelivered(id, to)
char *id, *to;
{
    char buf[MAX_MAILBOX_PATH];
    int lockfd;
    char datebuf[40];
#ifdef HAVE_LIBDB
    DBT date, delivery;
#else /* HAVE_LIBDB */
    datum date, delivery;
#endif

    if (!DeliveredDBptr) return;

    sprintf(buf, "%s/delivered.lock", config_dir);
    lockfd = open(buf, O_RDWR|O_CREAT, 0666);
    if (lockfd == -1) {
	fprintf(stderr,
		"deliver: can't open delivered.lock file: %s\n",
		error_message(errno));
	return;
    }

    if (lock_blocking(lockfd)) {
	fprintf(stderr,
		"deliver: can't lock delivered.lock file: %s\n",
		error_message(errno));
	close(lockfd);
	return;
    }

#ifdef HAVE_LIBDB
    sprintf(buf, "%s%c%s", id, '\0', to);
    delivery.data = buf;
    delivery.size = strlen(id) + strlen(to) + 1;

    sprintf(datebuf, "%lu", time(0));
    date.data = datebuf;
    date.size = strlen(datebuf);

    (void) DeliveredDBptr->put(DeliveredDBptr, &delivery, &date, 0);
    (void) DeliveredDBptr->sync(DeliveredDBptr, 0);
#else /* HAVE_LIBDB */
    sprintf(buf, "%s%c%s", id, '\0', to);
    delivery.dptr = buf;
    delivery.dsize = strlen(id) + strlen(to) + 1;

    sprintf(datebuf, "%lu", time(0));
    date.dptr = datebuf;
    date.dsize = strlen(datebuf);

    (void) dbm_store(DeliveredDBptr, delivery, date, DBM_REPLACE);
#endif /* HAVE_LIBDB */

    close(lockfd);
}

prunedelivered(age)
int age;
{
    char buf[MAX_MAILBOX_PATH];
    int lockfd;
    int rcode = 0;
    char datebuf[40];
    int len;

#ifdef HAVE_LIBDB
    int rc, mode;
    DBT date, delivery;
    DBT *deletions = 0;
    int num_deletions = 0, alloc_deletions = 0;
#else /* HAVE_LIBDB */
    datum date, delivery;
#endif

    if (age < 1) {
	fatal("must specify positive number of days", EX_USAGE);
    }

    /* initialize database */
    checkdelivered("", "");

    if (!DeliveredDBptr) {
	return 1;
    }

    sprintf(buf, "%s/delivered.lock", config_dir);
    lockfd = open(buf, O_RDWR|O_CREAT, 0666);
    if (lockfd == -1) {
	fprintf(stderr,
		"deliver: can't open delivered.lock file: %s\n",
		error_message(errno));
	return 1;
    }

    if (lock_blocking(lockfd)) {
	fprintf(stderr,
		"deliver: can't lock delivered.lock file: %s\n",
		error_message(errno));
	close(lockfd);
	return 1;
    }

    sprintf(datebuf, "%d", time(0) - age*60*60*24);
    len = strlen(datebuf);

#ifdef HAVE_LIBDB
    mode = R_FIRST;

    while ((rc = DeliveredDBptr->seq(DeliveredDBptr, &delivery, &date, mode)) == 0) {
	mode = R_NEXT;
	if (date.size < len ||
	    (date.size == len && memcmp(date.data, datebuf, len) < 0)) {
	    if (num_deletions >= alloc_deletions) {
		alloc_deletions += 1000;
		deletions = (DBT *) xrealloc((char *)deletions,
					     alloc_deletions * sizeof(DBT));
	    }
	    deletions[num_deletions].size = delivery.size;
	    deletions[num_deletions].data = xmalloc(delivery.size);
	    memcpy(deletions[num_deletions].data, delivery.data, delivery.size);
	    num_deletions++;
	}
    }

    while (num_deletions--) {
	DeliveredDBptr->del(DeliveredDBptr, &deletions[num_deletions], 0);
    }
    DeliveredDBptr->close(DeliveredDBptr);
#else /* HAVE_LIBDB */
    for (delivery = dbm_firstkey(DeliveredDBptr); delivery.dptr;
	 delivery = dbm_nextkey(DeliveredDBptr)) {
	date = dbm_fetch(DeliveredDBptr, delivery);
	if (!date.dptr) continue;
	if (date.dsize < len ||
	    (date.dsize == len  && memcmp(date.dptr, datebuf, len) < 0)) {
	    if (dbm_delete(DeliveredDBptr, delivery)) {
		rcode = 1;
	    }
	}
    }
    dbm_close(DeliveredDBptr);

#endif /* HAVE_LIBDB */
    close(lockfd);

    return rcode;
 }
