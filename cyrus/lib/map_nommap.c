/* map_nommap.c -- dummy memory-mapping routines.
 $Id: map_nommap.c,v 1.14.2.1 2000/10/31 20:29:06 leg Exp $
 
 #        Copyright 1998 by Carnegie Mellon University
 #
 #                      All Rights Reserved
 #
 # Permission to use, copy, modify, and distribute this software and its
 # documentation for any purpose and without fee is hereby granted,
 # provided that the above copyright notice appear in all copies and that
 # both that copyright notice and this permission notice appear in
 # supporting documentation, and that the name of CMU not be
 # used in advertising or publicity pertaining to distribution of the
 # software without specific, written prior permission.
 #
 # CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 # ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 # CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 # ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 # WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 # ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 # SOFTWARE.
 *
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include "xmalloc.h"
#include "map.h"
#include "exitcodes.h"

#define SLOP (4*1024)

/*
 * Create/refresh mapping of file
 */
void
map_refresh(fd, onceonly, base, len, newlen, name, mboxname)
int fd;
int onceonly;
const char **base;
unsigned long *len;
unsigned long newlen;
const char *name;
const char *mboxname;
{
    char *p;
    int n, left;
    struct stat sbuf;
    char buf[80];

    if (newlen == MAP_UNKNOWN_LEN) {
	if (fstat(fd, &sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: fstating %s file%s%s: %m", name,
		   mboxname ? " for " : "", mboxname ? mboxname : "");
	    sprintf(buf, "failed to fstat %s file", name);
	    fatal(buf, EC_IOERR);
	}
	newlen = sbuf.st_size;
    }
	    
    /* Need a larger buffer */
    if (*len < newlen) {
	if (*len) free((char *)*base);
	*len = newlen + (onceonly ? 0 : SLOP);
	*base = xmalloc(*len);
    }

    lseek(fd, 0L, 0);
    left = newlen;
    p = *base;

    while (left) {
	n = read(fd, p, left);
	if (n <= 0) {
	    if (n == 0) {
		syslog(LOG_ERR, "IOERROR: reading %s file%s%s: end of file",
		       name,
		       mboxname ? " for " : "", mboxname ? mboxname : "");
	    }
	    else {
		syslog(LOG_ERR, "IOERROR: reading %s file%s%s: %m",
		       name, 
		       mboxname ? " for " : "", mboxname ? mboxname : "");
	    }
	    sprintf(buf, "failed to read %s file", name);
	    fatal(buf, EC_IOERR);
	}
	p += n;
	left -= n;
    }
}

/*
 * Destroy mapping of file
 */
void
map_free(base, len)
const char **base;
unsigned long *len;
{
    if (*len) free((char *)*base);
    *base = 0;
    *len = 0;
}
