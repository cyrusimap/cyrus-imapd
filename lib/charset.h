/* 
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
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
