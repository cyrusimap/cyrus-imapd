/*
 * Program to deliver mail to a mailbox
 */

#include <stdio.h>
#include <sysexits.h>
#include <com_err.h>

#include <acl.h>
#include "imap_err.h"
#include "mailbox.h"

extern int optind;
extern char *optarg;

extern int errno;

main(argc, argv)
{
    int opt;
    char *name = "test";
    int touser = 0;

    config_init("deliver");

    while ((opt = getopt(argc, argv, "df:r:")) != EOF) {
	switch(opt) {
	case 'd':
	    touser = 1;
	    break;

	case 'r':
	case 'f':
	    /* Ignore -- /bin/mail compatibility flags */
	    break;

	default:
	    usage();
	}
    }
    /* XXX handle changing "name" */
    /* XXX handle multiple users & multiple bboards -- copy to temp file */
    deliver(name);
}

usage()
{
    fprintf(stderr, "usage: deliver [-r ignored] [-d ignored] [-d] user\n");
    exit(EX_USAGE);
}

deliver(name)
char *name;
{
    int r;
    struct mailbox mailbox;
    
    r = append_setup(&mailbox, name, MAILBOX_FORMAT_NORMAL, ACL_POST, 0);

    if (!r) {
	r = append_fromstream(&mailbox, stdin);
    }

    if (r) {
	com_err("deliver", r, (r == EX_IOERR) ? error_message(errno) : NULL);
    }

    exit(convert_code(r));
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
