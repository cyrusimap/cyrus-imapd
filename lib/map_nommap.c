/* map_mmap.c -- memory-mapping routines.
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
#include <sysexits.h>
#include <sys/types.h>
#include <syslog.h>

#define SLOP (4*1024)

/*
 * Create/refresh mapping of file
 */
map_refresh(fd, base, len, newlen, name, mboxname)
char **base;
unsigned long *len;
unsigned long newlen;
char *name;
char *mboxname;
{
    char *p;
    int n, left;

    /* Need a larger buffer */
    if (*len < newlen) {
	if (*len) free(*base);
	*len = newlen + SLOP;
	*base = xmalloc(*len);
    }

    lseek(fd, 0L, SEEK_SET);
    left = newlen;
    p = *base;

    while (left) {
	n = read(fd, p, left);
	if (n <= 0) {
	    char buf[80];
	    if (n == 0) {
		syslog(LOG_ERR, "IOERROR: reading %s file for %s: end of file",
		       name, mboxname);
	    }
	    else {
		syslog(LOG_ERR, "IOERROR: reading %s file for %s: %m",
		       name, mboxname);
	    }
	    sprintf(buf, "failed to read %s file", name);
	    fatal(buf, EX_IOERR);
	}
	left -= n;
    }
}

/*
 * Destroy mapping of file
 */
map_free(base, len)
char **base;
unsigned long *len;
{
    if (*len) free(*base);
    *base = 0;
    *len = 0;
}
