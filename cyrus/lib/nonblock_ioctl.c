/* nonblock_fcntl.c -- Set nonblocking mode using ioctl()
 $Id: nonblock_ioctl.c,v 1.5 1998/05/15 21:52:37 neplokh Exp $
 
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
#include <sys/ioctl.h>

#include "nonblock.h"

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
    mode = mode ? 1 : 0;

    if (ioctl(fd, FIONBIO, (char *)&mode) < 0) {
	fatal("Internal error: ioctl FIONBIO failed");
    }
}
