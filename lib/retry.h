/* retry.h -- Keep retrying write system calls
 $Id: retry.h,v 1.3 1998/05/15 21:52:58 neplokh Exp $
 
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
 */

#ifndef INCLUDED_RETRY_H
#define INCLUDED_RETRY_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

#include <sys/uio.h>

extern int retry_write P((int fd, const char *buf, unsigned nbyte));
extern int retry_writev P((int fd, struct iovec *iov, int iovcnt));

#endif /* INCLUDED_RETRY_H */
