/* toimsp.c -- Drop off information to be sent to IMSP server
 $Id: toimsp.c,v 1.26 1999/04/08 21:04:28 tjs Exp $
 
 # Copyright 1998 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
 *
 */
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#ifdef __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <com_err.h>

#include "config.h"
#include "mailbox.h"
#include "exitcodes.h"
#include "util.h"
#include "lock.h"
#include "retry.h"
#include "imap_err.h"
#include "xmalloc.h"

#define FNAME_TOIMSPFILE "/toimsp"

#define VECSIZE 15

static int toimsp_open();

/*
 * Drop off a request to send an IMSP LAST command stating the highest
 * uid for mailbox 'name' is 'uid' and has 'exists' messages.
 */
int
#ifdef __STDC__
toimsp(char *name, bit32 uidvalidity, ...)
#else
toimsp(va_alist)
va_dcl
#endif
{
    va_list pvar;
    int fd;
    struct iovec iov[VECSIZE];
    char iovbuf[VECSIZE][15];
    int num_iov = 0;
    char *tag;
    char *sval;
    bit32 nval;

#ifdef __STDC__
    va_start(pvar, uidvalidity);
#else
    char *name;
    bit32 uidvalidity;

    va_start(pvar);
    name = va_arg(pvar, char *);
    uidvalidity = va_arg(pvar, bit32);
#endif
    
    fd = toimsp_open();
    if (fd == -1) return 0;

    /* Start with newline */
    iov[num_iov].iov_base = "\n";
    iov[num_iov++].iov_len = 1;

    iov[num_iov].iov_base = name;
    iov[num_iov++].iov_len = strlen(name) + 1;

    sprintf(iovbuf[num_iov], "%lu", (unsigned long)uidvalidity);
    iov[num_iov].iov_base = iovbuf[num_iov];
    iov[num_iov].iov_len = strlen(iovbuf[num_iov]) + 1;
    num_iov++;

    while (tag = va_arg(pvar, char *)) {
	iov[num_iov].iov_base = tag;
	iov[num_iov++].iov_len = strlen(tag) + 1;

	while (*tag && isupper(*tag)) tag++;
	while (*tag) {
	    switch(*tag++) {
	    case 's':
		sval = va_arg(pvar, char *);
		iov[num_iov].iov_base = sval;
		iov[num_iov++].iov_len = strlen(sval) + 1;
		break;

	    case 'n':
		nval = va_arg(pvar, bit32);
		sprintf(iovbuf[num_iov], "%lu", (unsigned long)nval);
		iov[num_iov].iov_base = iovbuf[num_iov];
		iov[num_iov].iov_len = strlen(iovbuf[num_iov]) + 1;
		num_iov++;
		break;

	    default:
		abort("Internal error: unrecognized toimsp type", EC_SOFTWARE);
	    }
	}
    }

    va_end(pvar);

    /* End with newline */
    iov[num_iov].iov_base = "\n";
    iov[num_iov++].iov_len = 1;

    if (num_iov > VECSIZE) {
	abort("Internal error: toimsp arg list overflow", EC_SOFTWARE);
    }

    (void) retry_writev(fd, iov, num_iov);
    close(fd);
    
    return 0;
}
      
static int toimsp_open()
{
    int fd, r;
    char fnamebuf[MAX_MAILBOX_PATH];
    const char *lockfailaction;

    sprintf(fnamebuf, "%s%s", config_dir, FNAME_TOIMSPFILE);
    fd = open(fnamebuf, O_WRONLY, 0666);

    if (fd == -1) return -1;

    r = lock_reopen(fd, fnamebuf, (struct stat *)0, &lockfailaction);
    if (r == -1) {
	syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, fnamebuf);
	return -1;
    }

    lseek(fd, 0L, SEEK_END);
    return fd;
}
	
    
