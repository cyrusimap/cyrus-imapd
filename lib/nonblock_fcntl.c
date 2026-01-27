/* nonblock_fcntl.c - Set nonblocking mode using fcntl() */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sysexits.h>

#include "xmalloc.h"
#include "nonblock.h"

#ifndef FNDELAY
#define FNDELAY         O_NDELAY
#endif

#ifdef O_NONBLOCK
#define NON_BLOCKING_MODE O_NONBLOCK
#else
#define NON_BLOCKING_MODE FNDELAY
#endif

EXPORTED const char nonblock_method_desc[] = "fcntl";

/*
 * Modifies the non-blocking mode on the file descriptor 'fd'.  If
 * 'mode' is nonzero, sets non-blocking mode, if 'mode' is zero
 * clears non-blocking mode.
 */
EXPORTED void nonblock(int fd, int mode)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) fatal("Internal error: fcntl F_GETFL failed", EX_IOERR);
    if (mode) {
        flags |= NON_BLOCKING_MODE;
    }
    else {
        flags &= ~NON_BLOCKING_MODE;
    }
    (void)fcntl(fd, F_SETFL, flags);
}
