/* map_private.c -- memory-mapping routines using MAP_PRIVATE.
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
#include <sys/mman.h>
#include <sys/stat.h>
#include <syslog.h>

#include "map.h"
#include "sysexits.h"

/*
 * Create/refresh mapping of file
 * Always removes old mapping and creates a new one.
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
	    sprintf(buf, "failed to fstat %s file", name);
	    fatal(buf, EX_IOERR);
	}
	newlen = sbuf.st_size;
    }
	    
    if (*len) munmap((char *)*base, *len);
    if (newlen == 0) {
	*base = 0;
	*len = 0;
	return;
    }
    *base = (char *)mmap((caddr_t)0, newlen, PROT_READ,
			 (onceonly ? MAP_SHARED : MAP_PRIVATE)
#ifdef MAP_FILE
| MAP_FILE
#endif
#ifdef MAP_VARIABLE
| MAP_VARIABLE
#endif
			 , fd, 0L);
    if (*base == (char *)-1) {
	if (onceonly) {
	    /* Try again without using MAP_SHARED */
	    *len = 0;
	    map_refresh(fd, 0, base, len, newlen, name, mboxname);
	    return;
	}

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
void
map_free(base, len)
const char **base;
unsigned long *len;
{
    if (*len) munmap((char *)*base, *len);
    *base = 0;
    *len = 0;
}
