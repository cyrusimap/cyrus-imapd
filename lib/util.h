/* util.h -- general utility functions
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
 * Author: Chris Newman
 * Start Date: 4/6/93
 */

#ifndef INCLUDED_UTIL_H
#define INCLUDED_UTIL_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

typedef struct keyvalue {
    char *key, *value;
} keyvalue;

extern const char convert_to_lowercase[256];

#define TOLOWER(c) (convert_to_lowercase[(unsigned char)(c)])

/* convert string to all lower case
 */
extern char *lcase P((char *str));

/* convert string to all upper case
 */
extern char *ucase P((char *str));

/* clean up control characters in a string while copying it
 *  returns pointer to end of dst string.
 *  dst must have twice the length of source
 */
extern char *beautify_copy P((char *dst, const char *src));

/* clean up control characters in a string while copying it
 *  returns pointer to a static buffer containing the cleaned-up version
 *  returns NULL on malloc() error
 */
extern char *beautify_string P((const char *src));

/* do a binary search in a keyvalue array
 *  nelem is the number of keyvalue elements in the kv array
 *  cmpf is the comparison function (strcmp, stricmp, etc).
 *  returns NULL if not found, or key/value pair if found.
 */
extern keyvalue *kv_bsearch P((const char *key, keyvalue *kv, int nelem,
			       int (*cmpf)(const char *s1, const char *s2)));

#endif /* INCLUDED_UTIL_H */
