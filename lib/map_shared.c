/* map_shared.c -- memory-mapping routines.
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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
 */

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

    /* always map one extra byte so there's a trailing NULL to protect
     * us from overruns.  This does NOT mean that we should treat this
     * memory as a cstring */
    if (!onceonly)
        newlen = (newlen + 2*SLOP) & ~(SLOP-1);

    *base = (char *)mmap((caddr_t)0, onceonly ? newlen + 1 : newlen, PROT_READ, MAP_SHARED
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
