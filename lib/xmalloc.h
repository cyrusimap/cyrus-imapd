/* xmalloc.h -- Allocation package that calls fatal() when out of memory
 * $Id: xmalloc.h,v 1.14 2000/01/28 22:09:55 leg Exp $
 *
 *        Copyright 1998 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 *
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#ifndef INCLUDED_XMALLOC_H
#define INCLUDED_XMALLOC_H

#ifndef __GNUC__
/* can't use attributes... */
#define __attribute__(foo)
#define __inline__
#endif


extern void *xmalloc (unsigned size);
extern void *xrealloc (void *ptr, unsigned size);
extern char *xstrdup (const char *str);
extern char *xstrndup (const char *str, unsigned len);
extern void *fs_get (unsigned size);
extern void fs_give (void **ptr);

/* Functions using xmalloc.h must provide a function called fatal() conforming
   to the following: */
extern void fatal(const char *fatal_message, int fatal_code)
   __attribute__ ((noreturn));

#endif /* INCLUDED_XMALLOC_H */
