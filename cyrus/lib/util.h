/* util.h -- general utility functions
 * $Id: util.h,v 1.8 1999/03/02 01:29:42 tjs Exp $
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
 *
 * Author: Chris Newman
 * Start Date: 4/6/93
 */

#ifndef INCLUDED_UTIL_H
#define INCLUDED_UTIL_H

extern const unsigned char convert_to_lowercase[256];
extern const unsigned char convert_to_uppercase[256];

#define TOUPPER(c) (charset_convert_to_uppercase[(unsigned char)(c)])
#define TOLOWER(c) (convert_to_lowercase[(unsigned char)(c)])

/* convert string to all lower case
 */
extern char *lcase (char *str);

/* convert string to all upper case
 */
extern char *ucase (char *str);

/* clean up control characters in a string while copying it
 *  returns pointer to end of dst string.
 *  dst must have twice the length of source
 */
extern char *beautify_copy (char *dst, const char *src);

/* clean up control characters in a string while copying it
 *  returns pointer to a static buffer containing the cleaned-up version
 *  returns NULL on malloc() error
 */
extern char *beautify_string (const char *src);

/* do a binary search in a keyvalue array
 *  nelem is the number of keyvalue elements in the kv array
 *  cmpf is the comparison function (strcmp, stricmp, etc).
 *  returns NULL if not found, or key/value pair if found.
 */
extern keyvalue *kv_bsearch (const char *key, keyvalue *kv, int nelem,
			       int (*cmpf)(const char *s1, const char *s2));

#endif /* INCLUDED_UTIL_H */
