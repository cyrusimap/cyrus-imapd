/* map_nommap.c -- dummy memory-mapping routines. */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <syslog.h>

#include "slowio.h"
#include "xmalloc.h"
#include "map.h"

#define SLOP (4*1024)

EXPORTED const char map_method_desc[] = "nommap";

/*
 * Create/refresh mapping of file
 */
void
EXPORTED map_refresh(int fd, int onceonly, const char **base,
                     size_t *len, size_t newlen, const char *name,
                     const char *mboxname)
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
    p = (char*) *base;

    /* XXX this should probably just use retry_read()... */
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
            fatal(buf, EX_IOERR);
        }
        p += n;
        left -= n;

        slowio_maybe_delay_read(n);
    }
}

/*
 * Destroy mapping of file
 */
void
EXPORTED map_free(const char **base, size_t *len)
{
    if (*len) free((char *)*base);
    *base = 0;
    *len = 0;
}
