/* bsearch.h -- binary search
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
 */

#ifndef INCLUDED_BSEARCH_H
#define INCLUDED_BSEARCH_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

extern int bsearch_mem P((const char *word, int caseSensitive,
			   const char *base, unsigned long len,
			   unsigned long hint,
			   unsigned long *linelenp));

extern int bsearch_compare P((const char *s1, const char *s2));

#endif /* INCLUDED_BSEARCH_H */
