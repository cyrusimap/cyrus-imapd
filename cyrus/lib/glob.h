/* glob.h -- fast globbing routine using '*', '%', and '?'
 *
 *	(C) Copyright 1993-1994 by Carnegie Mellon University
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
 * Start Date: 4/5/93
 */

/* "compiled" glob structure: may change
 */
typedef struct glob {
    int flags;
    char sep_char;
    char str[3];
} glob;

/* glob_init flags: */
#define GLOB_ICASE        0x01	/* case insensitive */
#define GLOB_SUBSTRING    0x02	/* match a substring */
#define GLOB_HIERARCHY    0x04	/* use '%' as hierarchy matching */

/* internal flags: */
#define GLOB_MULTIPARTIAL 0x10	/* multiple partial matches possible */

/* initialize globbing structure
 *  str -- globbing string
 *  flags -- see flag values above
 */
glob *glob_init( /* char *str, int flags */ );

/* free a glob structure
 */
void glob_free( /* glob **g */ );

/* returns -1 if no match, otherwise length of match or partial-match
 *  g         pre-processed glob string
 *  ptr       string to perform glob on
 *  len       length of ptr string
 *  min       pointer to minimum length of a valid partial-match.
 *            Set to -1 if no more matches.  Set to return value + 1
 *     	      if another match is possible.  If NULL, no partial-matches
 *            are returned.
 */
int glob_test( /* glob *g, char *str, long len, long *min */ );

/* macros */
#define GLOB_TEST(g, str) glob_test((g), (str), -1L, NULL)
#define GLOB_SET_SEPARATOR(g, c) ((g)->sep_char = (c))
