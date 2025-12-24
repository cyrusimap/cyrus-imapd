/* map_stupidshared.c -- memory-mapping routines working around DEC stupidity. */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <syslog.h>

#include "map.h"
#include "slowio.h"
#include "xmalloc.h"

EXPORTED const char map_method_desc[] = "stupidshared";

#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif

/*
 * Create/refresh mapping of file
 */
void
EXPORTED map_refresh(int fd, int onceonly, const char **base,
                     size_t *len, size_t newlen, const char *name,
                     const char *mboxname)
{
    (void)onceonly;
    struct stat sbuf;
    int flags;
    char buf[256];

    if (newlen == MAP_UNKNOWN_LEN) {
        if (fstat(fd, &sbuf) == -1) {
            syslog(LOG_ERR, "IOERROR: fstating %s file%s%s: %m", name,
                   mboxname ? " for " : "", mboxname ? mboxname : "");
            snprintf(buf, sizeof(buf), "failed to fstat %s file", name);
            fatal(buf, EX_IOERR);
        }
        newlen = sbuf.st_size;
    }

    /* Already mapped in */
    if (*len >= newlen) return;

    if (*len) munmap((char *)*base, *len);

    flags = MAP_SHARED;
#ifdef MAP_FILE
    flags |= MAP_FILE;
#endif
#ifdef MAP_VARIABLE
    flags |= MAP_VARIABLE;
#endif

    *base = (char *)mmap((caddr_t)0, newlen, PROT_READ, flags, fd, 0L);
    if (*base == (char *)MAP_FAILED) {
        syslog(LOG_ERR, "IOERROR: mapping %s file%s%s: %m", name,
               mboxname ? " for " : "", mboxname ? mboxname : "");
        snprintf(buf, sizeof(buf), "failed to mmap %s file", name);
        fatal(buf, EX_IOERR);
    }
    *len = newlen;

    slowio_maybe_delay_read(newlen);
}

/*
 * Destroy mapping of file
 */
void
EXPORTED map_free(const char **base, size_t *len)
{
    if (*len) munmap((char *)*base, *len);
    *base = 0;
    *len = 0;
}
