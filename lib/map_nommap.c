/* map_mmap.c -- memory-mapping routines.
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

#include "xmalloc.h"
#include "map.h"
#include "sysexits.h"

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
	    fatal(buf, EX_IOERR);
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
	    fatal(buf, EX_IOERR);
	}
	p += left;
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
