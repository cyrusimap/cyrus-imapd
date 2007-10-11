/* comparator.h
 * Larry Greenfield
 * $Id: comparator.h,v 1.14 2007/10/11 16:52:11 murch Exp $
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#ifndef COMPARATOR_H
#define COMPARATOR_H

#ifdef ENABLE_REGEX
# ifdef HAVE_PCREPOSIX_H
#  include <pcreposix.h>
# else /* !HAVE_PCREPOSIX_H */
#  ifdef HAVE_RXPOSIX_H
#   include <rxposix.h>
#  else /* !HAVE_RXPOSIX_H */
#   include <sys/types.h>
#   include <regex.h>
#  endif /* HAVE_RXPOSIX_H */
# endif /* HAVE_PCREPOSIX_H */
#endif /* ENABLE_REGEX */

/* compares pat to text; returns 1 if it's true, 0 otherwise 
   first arg is text, second arg is pat, third arg is rock */
typedef int comparator_t(const char *, size_t, const char *, void *);

/* returns a pointer to a comparator function given it's name */
comparator_t *lookup_comp(int comp, int mode,
			  int relation, void **rock);

#endif /* COMPARATOR_H */
