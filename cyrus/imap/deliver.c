/* deliver.c -- Program to deliver mail to a mailbox
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
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <com_err.h>
#ifdef NEWDB
#include <db.h>
#else
#include <ndbm.h>
#endif

#include "acl.h"
#include "util.h"
#include "auth.h"
#include "prot.h"
#include "config.h"
#include "sysexits.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"

extern int optind;
extern char *optarg;

extern int errno;

char *mailboxname = 0;
char *authuser = 0;
char *id = 0;
int dupelim = 0;
char **flag = 0;
int nflags = 0;
struct protstream *prot_f;
unsigned size;

struct protstream *savemsg();

main(argc, argv)
int argc;
char **argv;
{
    int opt;
    int exitval = 0, code;
    int n;
    char buf[4096];
    char *msgid;
    char *return_path = 0;

    config_init("deliver");

    while ((opt = getopt(argc, argv, "df:r:m:a:F:eE:")) != EOF) {
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
	    if (!isvalidflag(flag)) break;
	    nflags++;
	    flag = (char **)xrealloc((char *)flag, nflags*sizeof(char *));
	    flag[nflags-1] = optarg;
	    break;

	case 'e':
	    dupelim = 1;
	    break;

	case 'E':
	    exit(prunedelivered(atoi(optarg)));

	default:
	    usage();
	}
    }

    if (authuser) {
	authuser = auth_canonifyid(authuser);
	if (authuser) auth_setid(authuser);
    }

    /* Copy message to temp file */
    prot_f = savemsg(return_path, dupelim ? &id : (char **)0, &size);

    if (optind == argc) {
	/* Deliver to global mailbox */
	exitval = deliver((char *)0);
	exit(exitval);
    }
    while (optind < argc) {
	code = deliver(argv[optind++]);
	if (code && exitval != EX_TEMPFAIL) exitval = code;
    }
    exit(exitval);
}

usage()
{
    fprintf(stderr, 
"usage: deliver [-m mailbox] [-a auth] [-i] [-F flag]... [user]...\n");
    fprintf(stderr, "       deliver -I age\n");
    exit(EX_USAGE);
}

struct protstream *
savemsg(return_path, idptr, sizeptr)
char *return_path;
char **idptr;
unsigned *sizeptr;
{
    FILE *f;
    char *hostname = 0;
    int scanheader = 1;
    int sawidhdr = 0, sawresentidhdr = 0;
    int n;
    char buf[4096], *p;
    struct stat sbuf;

    if (!idptr) scanheader = 0;

    /* Copy to temp file */
    f = tmpfile();
    if (!f) {
	exit(EX_TEMPFAIL);
    }

    if (return_path) {
	/* Remove any angle brackets around return path */
	if (*return_path == '<') {
	    return_path = strsave(return_path+1);
	    if (return_path[strlen(return_path)-1] == '>') {
		return_path[strlen(return_path)-1] == '\0';
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
	fputs(buf, f);

	/* Look for message-id or resent-message-id headers */
	if (scanheader) {
	    p = 0;
	    if (*buf == '\r') scanheader = 0;
	    else if (sawidhdr || sawresentidhdr) {
		if (*buf == ' ' || *buf == '\t') p = buf+1;
		else sawidhdr = sawresentidhdr = 0;
	    }
	    else if (!*idptr && !strncasecmp(buf, "message-id:", 11)) {
		sawidhdr = 1;
		p = buf + 11;
	    }
	    else if (!strncasecmp(buf, "resent-message-id:", 18)) {
		sawresentidhdr = 1;
		p = buf + 18;
	    }

	    if (p) {
		clean822space(p);
		if (*p) {
		    *idptr = strsave(p);
		    /*
		     * If we got a resent-message-id header,
		     * we're done looking at headers.
		     */
		    if (sawresentidhdr) scanheader = 0;
		    sawresentidhdr = sawidhdr = 0;
		}
	    }
	}

    }
    fflush(f);
    if (ferror(f)) {
	perror("deliver: copying message");
	exit(EX_TEMPFAIL);
    }
    if (fstat(fileno(f), &sbuf) == -1) {
	perror("deliver: stating message");
	exit(EX_TEMPFAIL);
    }
    *sizeptr = sbuf.st_size;
	
    return prot_new(fileno(f), 0);
}


deliver(user)
char *user;
{
    int r;
    struct mailbox mailbox;
    char namebuf[MAX_MAILBOX_PATH];
    
    if (user) {
	if (strchr(user, '.') ||
	    strlen(user) + 30 > MAX_MAILBOX_PATH) {
	    return EX_NOUSER;
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
	    if (id && checkdelivered(id, namebuf)) {
		logdupelem(id, namebuf);
		return 0;
	    }
	    r = append_setup(&mailbox, namebuf, MAILBOX_FORMAT_NORMAL,
			     ACL_POST, 0);
	}
	if (r) {
	    strcpy(namebuf, "user.");
	    strcat(namebuf, user);
	    
	    if (id && checkdelivered(id, namebuf)) {
		logdupelem(id, namebuf);
		return 0;
	    }
	    r = append_setup(&mailbox, namebuf, MAILBOX_FORMAT_NORMAL,
			     0, 0);
	}
    }
    else if (mailboxname) {
	if (id && checkdelivered(id, mailboxname)) {
	    logdupelem(id, mailboxname);
	    return 0;
	}
	r = append_setup(&mailbox, mailboxname, MAILBOX_FORMAT_NORMAL,
			 ACL_POST, 0);
    }
    else {
	fprintf(stderr, "deliver: either -m or user required\n");
	usage();
    }

    if (!r) {
	prot_rewind(prot_f);
	r = append_fromstream(&mailbox, prot_f, size, time(0), flag, nflags,
			      authuser);
	mailbox_close(&mailbox);
    }

    if (r) {
	com_err(user ? user : mailboxname,
		r, (r == IMAP_IOERROR) ? error_message(errno) : NULL);
    }

    if (!r && dupelim && id) markdelivered(id, user ? namebuf : mailboxname);

    return convert_code(r);
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

int convert_code(r)
int r;
{
    switch (r) {
    case 0:
	return 0;
	
    case IMAP_IOERROR:
	return EX_IOERR;

    case IMAP_PERMISSION_DENIED:
	return EX_NOPERM;

    case IMAP_QUOTA_EXCEEDED:
	return EX_TEMPFAIL;

    case IMAP_MAILBOX_NOTSUPPORTED:
	return EX_DATAERR;

    case IMAP_MAILBOX_NONEXISTENT:
	/* XXX Might have been moved to other server */
	return EX_NOUSER;
    }
	
    /* Some error we're not expecting. */
    return EX_SOFTWARE;
}	

fatal(s, code)
char *s;
int code;
{
    fprintf(stderr, "deliver: %s\n", s);
    exit(code);
}

int isvalidflag(f)
char *f;
{
    if (f[0] == '\0') {
	lcase(f);
	if (!strcmp(f, "\\seen") && !strcmp(f, "\\answered") &&
	    !strcmp(f, "\\flagged") && !strcmp(f, "\\draft") &&
	    !strcmp(f, "\\deleted")) {
	    return 0;
	}
	return 1;
    }
    if (!is_atom(f)) return 0;
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

#ifdef NEWDB
static DB	*DeliveredDBptr;
#else
static DBM	*DeliveredDBptr;
#endif

checkdelivered(id, to)
char *id, *to;
{
#ifdef NEWDB
    static int initialized = 0;
    char buf[MAX_MAILBOX_PATH];
    DBT date, delivery;
    int i;

    if (!initialized) {
	initialized++;

	sprintf(buf, "%s/delivered.db", CONFIG_DIR);
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
#else /* NEWDB */
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
#endif /* NEWDB */
}

markdelivered(id, to)
char *id, *to;
{
    char buf[MAX_MAILBOX_PATH];
    int lockfd;
    char datebuf[40];
#ifdef NEWDB
    DBT date, delivery;
#else /* NEWDB */
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

#ifdef NEWDB
    sprintf(buf, "%s%c%s", id, '\0', to);
    delivery.data = buf;
    delivery.size = strlen(id) + strlen(to) + 1;

    sprintf(datebuf, "%lu", time(0));
    date.data = datebuf;
    date.size = strlen(datebuf);

    (void) DeliveredDBptr->put(DeliveredDBptr, delivery, date, R_OVERWRITE);
#else /* NEWDB */
    sprintf(buf, "%s%c%s", id, '\0', to);
    delivery.dptr = buf;
    delivery.dsize = strlen(id) + strlen(to) + 1;

    sprintf(datebuf, "%lu", time(0));
    date.dptr = datebuf;
    date.dsize = strlen(datebuf);

    (void) dbm_store(DeliveredDBptr, delivery, date, DBM_REPLACE);
#endif /* NEWDB */

    close(lockfd);
}

prunedelivered(age)
int age;
{
    char buf[MAX_MAILBOX_PATH];
    int lockfd;
    int rcode = 0;
#ifdef NEWDB
not written
#else /* NEWDB */
    char datebuf[40];
    int len;
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
	return;
    }

    if (lock_blocking(lockfd)) {
	fprintf(stderr,
		"deliver: can't lock delivered.lock file: %s\n",
		error_message(errno));
	close(lockfd);
	return;
    }

#ifdef NEWDB
not written
#else /* NEWDB */
    sprintf(datebuf, "%d", time(0) - age*60*60*24);
    len = strlen(datebuf);

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

#endif /* NEWDB */
    close(lockfd);

    return rcode;
 }
