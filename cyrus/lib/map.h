/* map.h -- memory mapping functions
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

#ifndef INCLUDED_MAP_H
#define INCLUDED_MAP_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

#define MAP_UNKNOWN_LEN ((unsigned long)-1)

extern void map_refresh P((int fd, int onceonly, const char **base,
		    unsigned long *len, unsigned long newlen,
		    const char *name, const char *mboxname));

extern void map_free P((const char **base, unsigned long *len));

#endif /* INCLUDED_MAP_H */
