/* map_nommap.c -- dummy memory-mapping routines.
 $Id: map_nommap.c,v 1.19.2.2 2003/02/13 20:33:13 rjs3 Exp $
 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 */
#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <syslog.h>

#include "xmalloc.h"
#include "map.h"
#include "exitcodes.h"

#define SLOP (4*1024)

const char *map_method_desc = "nommap";

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
	    snprintf(buf, sizeof(buf), "failed to fstat %s file", name);
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
    p = (char*) *base;

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
	    snprintf(buf, sizeof(buf), "failed to read %s file", name);
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
