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
char **flag = 0;
int nflags = 0;

FILE *f;
struct protstream *prot_f;

main(argc, argv)
int argc;
char **argv;
{
    int opt;
    int exitval = 0, code;
    int n;
    char buf[4096];

    config_init("deliver");

    while ((opt = getopt(argc, argv, "df:r:m:a:i:F:I:")) != EOF) {
	switch(opt) {
	case 'd':
	case 'r':
	case 'f':
	    /* Ignore -- /bin/mail compatibility flags */
	    break;

	case 'm':
	    if (mailboxname) {
		fprintf(stderr, "deliver: multiple -m options");
		usage();
	    }
	    mailboxname = optarg;
	    break;

	case 'a':
	    if (authuser) {
		fprintf(stderr, "deliver: multiple -a options");
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

	case 'i':
	    if (id) {
		fprintf(stderr, "deliver: multiple -i options");
		usage();
	    }
	    if (*optarg) id = optarg;
	    break;

	case 'I':
	    exit(prunedelivered(atoi(optarg)));

	default:
	    usage();
	}
    }

    if (authuser) {
	authuser = auth_canonifyid(authuser);
	if (authuser) auth_setid(authuser);
    }

    /* Copy to temp file */
    f = tmpfile();
    if (!f) {
	exit(EX_TEMPFAIL);
    }
    while (n = fread(buf, 1, sizeof(buf), stdin)) {
	fwrite(buf, 1, n, f);
    }
    fflush(f);
    if (ferror(f)) {
	perror("deliver: copying message");
	exit(EX_TEMPFAIL);
    }
    prot_f = prot_new(fileno(f), 0);

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
"usage: deliver [-m mailbox] [-a auth] [-i msg-id] [-F flag]... [user]...\n");
    fprintf(stderr, "       deliver -I age\n");
    exit(EX_USAGE);
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
	    if (id && checkdelivered(id, namebuf)) return 0;
	    r = append_setup(&mailbox, namebuf, MAILBOX_FORMAT_NORMAL,
			     ACL_POST, 0);
	}
	if (r) {
	    strcpy(namebuf, "user.");
	    strcat(namebuf, user);
	    
	    if (id && checkdelivered(id, namebuf)) return 0;
	    r = append_setup(&mailbox, namebuf, MAILBOX_FORMAT_NORMAL,
			     0, 0);
	}
    }
    else if (mailboxname) {
	if (id && checkdelivered(id, mailboxname)) return 0;
	r = append_setup(&mailbox, mailboxname, MAILBOX_FORMAT_NORMAL,
			 ACL_POST, 0);
    }
    else {
	fprintf(stderr, "deliver: either -m or user required\n");
	usage();
    }

    if (!r) {
	prot_rewind(prot_f);
	r = append_fromstream(&mailbox, prot_f, 0, time(0), flag, nflags,
			      authuser);
	mailbox_close(&mailbox);
    }

    if (r) {
	com_err(user ? user : mailboxname,
		r, (r == IMAP_IOERROR) ? error_message(errno) : NULL);
    }

    if (!r && id) markdelivered(id, user ? namebuf : mailboxname);

    return convert_code(r);
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
	return EX_UNAVAILABLE;
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
#ifdef NEWDB
    char buf[MAX_MAILBOX_PATH];
    char datebuf[40];
    DBT date, delivery;

    if (!DeliveredDBptr) return;

    sprintf(buf, "%s%c%s", id, '\0', to);
    delivery.data = buf;
    delivery.size = strlen(id) + strlen(to) + 1;

    sprintf(datebuf, "%ld", time(0));
    date.data = datebuf;
    date.size = strlen(datebuf);

    if (lock_blocking(DeliveredDBptr->dont_know)) {
	fprintf(stderr, "deliver: can't lock DBM file: %s",
		error_message(errno));
	return;
    }
    (void) DeliveredDBptr->put(DeliveredDBptr, delivery, date, R_OVERWRITE);
    (void) lock_unlock(DeliveredDBptr->dont_know);
#else /* NEWDB */
    char buf[MAX_MAILBOX_PATH];
    char datebuf[40];
    datum date, delivery;

    if (!DeliveredDBptr) return;

    sprintf(buf, "%s%c%s", id, '\0', to);
    delivery.dptr = buf;
    delivery.dsize = strlen(id) + strlen(to) + 1;

    sprintf(datebuf, "%ld", time(0));
    date.dptr = datebuf;
    date.dsize = strlen(datebuf);

    if (lock_blocking(DeliveredDBptr->dbm_pagf)) {
	fprintf(stderr, "deliver: can't lock DBM file: %s",
		error_message(errno));
	return;
    }
    (void) dbm_store(DeliveredDBptr, delivery, date, DBM_REPLACE);
    (void) lock_unlock(DeliveredDBptr->dbm_pagf);
#endif /* NEWDB */
}

prunedelivered(age)
int age;
{
#ifdef NEWDB
not written
#else /* NEWDB */
    int rcode = 0;
    char datebuf[40];
    int len;
    datum date, delivery;

    if (age < 1) {
	fatal("must specify positive number of days", EX_USAGE);
    }

    /* initialize database */
    checkdelivered("", "");

    if (!DeliveredDBptr) {
	return 1;
    }

    if (lock_blocking(DeliveredDBptr->dbm_pagf)) {
	fprintf(stderr, "delivered: can't lock DBM file: %s",
		error_message(errno));
	return 1;
    }

    sprintf(datebuf, "%d", time(0) - age*60*60*24);
    len = strlen(datebuf);

    for (delivery = dbm_firstkey(DeliveredDBptr); delivery.dptr;
	 delivery = dbm_nextkey(DeliveredDBptr)) {
	date = dbm_fetch(DeliveredDBptr, delivery);
	if (!date.dptr) continue;
	if (date.dsize < len ||
	    (date.dsize == len  && bcmp(date.dptr, datebuf, len) < 0)) {
	    if (dbm_delete(DeliveredDBptr, delivery)) {
		rcode = 1;
	    }
	}
    }
    dbm_close(DeliveredDBptr);

    return rcode;
#endif /* NEWDB */
 }
