/* comparator.h
 * Larry Greenfield
 * $Id: comparator.h,v 1.9.4.1 2003/02/27 18:13:52 rjs3 Exp $
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
#ifdef HAVE_RX
#include <rxposix.h>
#else
#include <sys/types.h>
#include <regex.h>
#endif
#endif

/* compares pat to text; returns 1 if it's true, 0 otherwise 
   first arg is text, second arg is pat, third arg is rock */
typedef int comparator_t(const char *, const char *, void *);

/* returns a pointer to a comparator function given it's name */
comparator_t *lookup_comp(int comp, int mode,
			  int relation, void **rock);

#endif
