/* nonblock_fcntl.c -- Set nonblocking mode using fcntl()
 $Id: nonblock_fcntl.c,v 1.9 2000/01/28 22:09:55 leg Exp $
 
 #        Copyright 1998 by Carnegie Mellon University
 #
 #                      All Rights Reserved
 #
 # Permission to use, copy, modify, and distribute this software and its
 # documentation for any purpose and without fee is hereby granted,
 # provided that the above copyright notice appear in all copies and that
 # both that copyright notice and this permission notice appear in
 # supporting documentation, and that the name of CMU not be
 # used in advertising or publicity pertaining to distribution of the
 # software without specific, written prior permission.
 #
 # CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 # ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 # CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 # ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 # WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 # ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 # SOFTWARE.
 *
 */
#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>

#include "xmalloc.h"
#include "exitcodes.h"
#include "nonblock.h"

#ifndef	FNDELAY
#define FNDELAY		O_NDELAY
#endif

#ifdef O_NONBLOCK
#define NON_BLOCKING_MODE O_NONBLOCK
#else
#define NON_BLOCKING_MODE FNDELAY
#endif

/*
 * Modifies the non-blocking mode on the file descriptor 'fd'.  If
 * 'mode' is nonzero, sets non-blocking mode, if 'mode' is zero
 * clears non-blocking mode.
 */
void
nonblock(fd, mode)
int fd;
int mode;
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) fatal("Internal error: fcntl F_GETFL failed", EC_IOERR);
    if (mode) {
	flags |= NON_BLOCKING_MODE;
    }
    else {
	flags &= ~NON_BLOCKING_MODE;
    }
    fcntl(fd, F_SETFL, flags);
}
