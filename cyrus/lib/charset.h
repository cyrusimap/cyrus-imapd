/* 
	$Id: charset.h,v 1.12 1998/05/15 21:51:08 neplokh Exp $
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

#ifndef INCLUDED_CHARSET_H
#define INCLUDED_CHARSET_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

/* Marker to indicate characters that don't map to anything */
#define EMPTY 'X'
#define EMPTY_STRING "X"

#define ENCODING_NONE 0
#define ENCODING_QP 1
#define ENCODING_BASE64 2
#define ENCODING_UNKNOWN 255

typedef int comp_pat;

extern int charset_lookupname P((const char *name));
extern char *charset_convert P((const char *s, int charset));
extern char *charset_decode1522 P((const char *s));
extern comp_pat *charset_compilepat P((const char *s));
extern void charset_freepat P((comp_pat *pat));
extern int charset_searchstring P((const char *substr, comp_pat *pat,
				   const char *s, int len));
extern int charset_searchfile P((const char *substr, comp_pat *pat,
				 const char *msg_base, int mapnl,
				 int len, int charset, int encoding));

#endif /* INCLUDED_CHARSET_H */
