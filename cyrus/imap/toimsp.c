/* toimsp.c -- Drop off information to be sent to IMSP server
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <com_err.h>

#include "config.h"
#include "mailbox.h"
#include "sysexits.h"
#include "util.h"
#include "imap_err.h"
#include "xmalloc.h"

#define FNAME_TOIMSPFILE "/toimsp"

#define VECSIZE 15

static int imsp_open();

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
    if (fd == -1) return;

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
		abort("Internal error: unrecognized toimsp type", EX_SOFTWARE);
	    }
	}
    }

    va_end(pvar);

    /* End with newline */
    iov[num_iov].iov_base = "\n";
    iov[num_iov++].iov_len = 1;

    if (num_iov > VECSIZE) {
	abort("Internal error: toimsp arg list overflow", EX_SOFTWARE);
    }

    (void) retry_writev(fd, iov, num_iov);
    close(fd);
    
    return 0;
}
      
static int toimsp_open()
{
    int fd, r;
    char fnamebuf[MAX_MAILBOX_PATH];
    char *lockfailaction;

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
	
    
