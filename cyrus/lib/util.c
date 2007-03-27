/* util.c -- general utility functions
 * 
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
 */
/*
 * $Id: util.c,v 1.32 2007/03/27 19:05:16 murch Exp $
 */

#include <config.h>

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/socket.h>
#include <errno.h>

#include "exitcodes.h"
#include "libcyr_cfg.h"
#include "util.h"
#include "xmalloc.h"

#define BEAUTYBUFSIZE 4096

/* clean up control characters in a string while copying it
 *  returns pointer to end of dst string.
 *  dst must have twice the length of source
 */
char *beautify_copy(char* dst, const char* src)
{
    unsigned char c;

    while (*src) {
	c = *src++ & 0x7F;
	if (!isprint(c)) {
	    *dst++ = '^';
	    if (c > ' ') {
		c = '?';
	    } else {
		c += '@';
	    }
	}
	*dst++ = c;
    }
    *dst = '\0';

    return (dst);
}


/* clean up control characters in a string while copying it
 *  returns pointer to a static buffer containing the cleaned-up version
 *  returns NULL on malloc() error
 */
char *beautify_string(const char* src)
{
    static char *beautybuf = NULL;
    static int beautysize = 0;
    int len;

    len = strlen(src) * 2 + 1;
    if (beautysize < len) {
	if (!beautysize) {
	    beautysize = len > BEAUTYBUFSIZE ? len : BEAUTYBUFSIZE;
	    beautybuf = xmalloc(beautysize);
	} else {
	    beautysize *= 2;
	    if (len > beautysize) beautysize = len;
	    beautybuf = xrealloc(beautybuf, beautysize);
	}
	if (!beautybuf) {
	    beautysize = 0;
	    return "";
	}
    }
    (void) beautify_copy(beautybuf, src);

    return (beautybuf);
}

/* do a binary search in a keyvalue array
 *  nelem is the number of keyvalue elements in the kv array
 *  cmpf is the comparison function (strcmp, strcasecmp, etc).
 *  returns NULL if not found, or key/value pair if found.
 */
keyvalue *kv_bsearch(const char* key, keyvalue* kv, int nelem,
		     int (*cmpf) (const char *s1, const char *s2))
{
    int top, mid = 0, bot, cmp = 0;

    cmp = 1;
    bot = 0;
    top = nelem - 1;
    while (top >= bot && (cmp = (*cmpf)(key, kv[mid = (bot + top) >> 1].key)))
	if (cmp < 0) {
	    top = mid - 1;
	} else {
	    bot = mid + 1;
	}

    return (cmp ? NULL : kv + mid);
}

/* Examine the name of a file, and return a single character
 *  (as an int) that can be used as the name of a hash
 *  directory.  Stop before the first dot.  Caller is responsible
 *  for skipping any prefix of the name.
 */
int dir_hash_c(const char *name)
{
    int c;

    if (libcyrus_config_getswitch(CYRUSOPT_FULLDIRHASH)) {
	unsigned char *pt;
	unsigned int n;
	enum {
	    DIR_X = 3,
	    DIR_Y = 5,
	    DIR_P = 23,
	    DIR_A = 'A'
	};

	n = 0;
	pt = (unsigned char *)name;
	while (*pt && *pt != '.') {
	    n = ((n << DIR_X) ^ (n >> DIR_Y)) ^ *pt;
	    ++pt;
	}
	c = DIR_A + (n % DIR_P);
    }
    else {
	c = tolower(*name);
	if (!isascii(c) || !islower(c)) c = 'q';
    }

    return c;
}

int cyrus_close_sock(int fd) 
{
    shutdown(fd, SHUT_RD);
    return close(fd);
}

void cyrus_reset_stdio()
{
    int devnull = open("/dev/null", O_RDWR, 0);
    
    if (devnull == -1) {
        fatal("open() on /dev/null failed", EC_TEMPFAIL);
    }
    
    /* stdin */
    shutdown(0, SHUT_RD);
    dup2(devnull, 0);
    
    /* stdout */
    shutdown(1, SHUT_RD);
    dup2(devnull, 1);
    
    /* stderr */
    shutdown(2, SHUT_RD);
    dup2(devnull, 2);

    if (devnull > 2) close(devnull);
}

/* Given a mkstemp(3) pattern for a filename,
 * create the file and return the file descriptor.
 *
 * This routine also unlinks the file so it won't appear in the
 * directory listing (but you won't have to worry about cleaning up
 * after it)
 */
int create_tempfile() 
{
    int fd;
    char pattern[2048];
    const char *path = libcyrus_config_getstring(CYRUSOPT_TEMP_PATH);

    if(snprintf(pattern, sizeof(pattern), "%s/cyrus_tmpfile_XXXXXX",
		path) >= sizeof(pattern)){
	fatal("temporary file pathname is too long in prot_flush",
	      EC_TEMPFAIL);
    }

    fd = mkstemp(pattern);
    if(fd == -1) {
	return -1;
    } else if(unlink(pattern) == -1) {
	close(fd);
	return -1;
    }

    return fd;
}

/* Create all parent directories for the given path,
 * up to but not including the basename.
 */
int cyrus_mkdir(const char *path, mode_t mode __attribute__((unused)))
{
    char *p = (char *) path;
    int save_errno;
    struct stat sbuf;

    while ((p = strchr(p+1, '/'))) {
	*p = '\0';
	if (mkdir(path, 0755) == -1 && errno != EEXIST) {
	    save_errno = errno;
	    if (stat(path, &sbuf) == -1) {
		errno = save_errno;
		syslog(LOG_ERR, "IOERROR: creating directory %s: %m", path);
		return -1;
	    }
	}
	*p = '/';
    }

    return 0;
}
