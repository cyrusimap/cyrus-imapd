/* nonblock_fcntl.c -- Set nonblocking mode using ioctl()
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */
#include <sys/ioctl.h>

/*
 * Modifies the non-blocking mode on the file descriptor 'fd'.  If
 * 'mode' is nonzero, sets non-blocking mode, if 'mode' is zero
 * clears non-blocking mode.
 */
nonblock(fd, mode)
int fd;
int mode;
{
    mode = mode ? 1 : 0;

    if (ioctl(fd, FIONBIO, (char *)&mode) < 0) {
	fatal("Internal error: ioctl FIONBIO failed");
    }
}
