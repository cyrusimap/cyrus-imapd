/* xmalloc.h -- Allocation package that calls fatal() when out of memory
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

#ifndef INCLUDED_XMALLOC_H
#define INCLUDED_XMALLOC_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

extern char *xmalloc P((unsigned size));
extern char *xrealloc P((char *ptr, unsigned size));
extern char *xstrdup P((const char *str));
extern char *xstrndup P((const char *str, unsigned len));
extern void *fs_get P((unsigned size));
extern void fs_give P((void **ptr));

#endif /* INCLUDED_XMALLOC_H */
