/* map_mmap.c -- memory-mapping routines.
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
#include <sys/types.h>
#include <sys/mman.h>
#include <syslog.h>

#include "sysexits.h"

#define SLOP (8*1024)

/*
 * Create/refresh mapping of file
 */
map_refresh(fd, onceonly, base, len, newlen, name, mboxname)
int fd;
int onceonly;
char **base;
unsigned long *len;
unsigned long newlen;
char *name;
char *mboxname;
{
    /* Already mapped in */
    if (*len >= newlen) return;

    if (*len) munmap(*base, *len);

    if (!onceonly) {
	newlen = (newlen + 2*SLOP - 1) & ~(SLOP-1);
    }	

    *base = (char *)mmap((caddr_t)0, newlen, PROT_READ, MAP_SHARED
#ifdef MAP_FILE
| MAP_FILE
#endif
#ifdef MAP_VARIABLE
| MAP_VARIABLE
#endif
			 , fd, 0L);
    if (*base == (char *)-1) {
	char buf[80];
	syslog(LOG_ERR, "IOERROR: mapping %s file%s%s: %m", name,
	       mboxname ? " for " : "", mboxname ? mboxname : "");
	sprintf(buf, "failed to mmap %s file", name);
	fatal(buf, EX_IOERR);
    }
    *len = newlen;
}

/*
 * Destroy mapping of file
 */
map_free(base, len)
char **base;
unsigned long *len;
{
    if (*len) munmap(*base, *len);
    *base = 0;
    *len = 0;
}
