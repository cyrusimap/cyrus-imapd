/* Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 */
/*
 * $Id: charset.h,v 1.13 1999/03/02 01:03:48 tjs Exp $
 */

#ifndef INCLUDED_CHARSET_H
#define INCLUDED_CHARSET_H

/* Marker to indicate characters that don't map to anything */
#define EMPTY 'X'
#define EMPTY_STRING "X"

#define ENCODING_NONE 0
#define ENCODING_QP 1
#define ENCODING_BASE64 2
#define ENCODING_UNKNOWN 255

typedef int comp_pat;

/* ensure up to MAXTRANSLATION times expansion into buf */
extern char *charset_convert(const char *s, int charset, char *buf,
    int bufsz);
extern char *charset_decode1522(const char *s, char *buf, int bufsz);

extern int charset_lookupname(const char *name);
extern comp_pat *charset_compilepat(const char *s);
extern void charset_freepat(comp_pat *pat);
extern int charset_searchstring(const char *substr, comp_pat *pat,
    const char *s, int len);
extern int charset_searchfile(const char *substr, comp_pat *pat,
    const char *msg_base, int mapnl, int len, int charset, int encoding);

#endif /* INCLUDED_CHARSET_H */
