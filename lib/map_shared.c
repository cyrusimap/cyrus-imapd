/* map_shared.c - memory-mapping routines. */
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

#define SLOP (8*1024)

EXPORTED const char map_method_desc[] = "shared";

/*
 * Create/refresh mapping of file
 */
EXPORTED void map_refresh(int fd, int onceonly, const char **base,
                 size_t *len, size_t newlen,
                 const char *name, const char *mboxname)
{
    struct stat sbuf;
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

    if (*len) {
        int r = munmap((char *)*base, *len);
        if (r) {
            syslog(LOG_ERR, "IOERROR: unmapping %s file%s%s: %m", name,
                   mboxname ? " for " : "", mboxname ? mboxname : "");
            snprintf(buf, sizeof(buf), "failed to munmap %s file", name);
            fatal(buf, EX_IOERR);
        }
    }

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
EXPORTED void map_free(const char **base, size_t *len)
{
    if (*len) {
        int r = munmap((char *)*base, *len);
        if (r) {
            syslog(LOG_ERR, "IOERROR: map_free");
            fatal("Failed to map_free", EX_IOERR);
        }
    }
    *base = 0;
    *len = 0;
}
