/* map_stupidshared.c -- memory-mapping routines working around DEC stupidity.
 *
 * This file is like map_shared.c, but doesn't use any "SLOP", since
 * "Digital Unix" doesn't permit mapping a region past the end of a file.
 
 $Id: map_stupidshared.c,v 1.11 2002/07/24 20:27:41 rjs3 Exp $
 
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 */

#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syslog.h>

#include "map.h"
#include "exitcodes.h"

const char *map_method_desc = "stupidshared";

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
	    
    /* Already mapped in */
    if (*len >= newlen) return;

    if (*len) munmap((char *)*base, *len);

    *base = (char *)mmap((caddr_t)0, newlen, PROT_READ, MAP_SHARED
#ifdef MAP_FILE
| MAP_FILE
#endif
#ifdef MAP_VARIABLE
| MAP_VARIABLE
#endif
			 , fd, 0L);
    if (*base == (char *)-1) {
	syslog(LOG_ERR, "IOERROR: mapping %s file%s%s: %m", name,
	       mboxname ? " for " : "", mboxname ? mboxname : "");
	snprintf(buf, sizeof(buf), "failed to mmap %s file", name);
	fatal(buf, EC_IOERR);
    }
    *len = newlen;
}

/*
 * Destroy mapping of file
 */
void
map_free(base, len)
const char **base;
unsigned long *len;
{
    if (*len) munmap((char *)*base, *len);
    *base = 0;
    *len = 0;
}
