/* nonblock_fcntl.c -- Set nonblocking mode using ioctl() */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <sys/ioctl.h>
#include <sysexits.h>

#include "nonblock.h"

/* for fatal */
#include "xmalloc.h"

EXPORTED const char nonblock_method_desc[] = "ioctl";

/*
 * Modifies the non-blocking mode on the file descriptor 'fd'.  If
 * 'mode' is nonzero, sets non-blocking mode, if 'mode' is zero
 * clears non-blocking mode.
 */
EXPORTED void nonblock(int fd, int mode)
{
    mode = mode ? 1 : 0;

    if (ioctl(fd, FIONBIO, (char *)&mode) < 0) {
        fatal("Internal error: ioctl FIONBIO failed", EX_SOFTWARE);
    }
}
