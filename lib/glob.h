/* glob.h -- fast globbing routine using '*', '%', and '?'
 *
 *	(C) Copyright 1993-1996 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 * Author: Chris Newman
 * Start Date: 4/5/93
 */

#ifndef INCLUDED_GLOB_H
#define INCLUDED_GLOB_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

/* "compiled" glob structure: may change
 */
typedef struct glob {
    int flags;			/* glob flags, see below */
    int slen;			/* suppress string length */
    char *suppress;		/* suppress string pointer */
    const char *gstar, *ghier, *gptr;	/* INBOX prefix comparison state */
    char sep_char;		/* separator character */
    char inbox[6];		/* INBOX in the correct case */
    char str[3];		/* glob string & suppress string */
} glob;

/* glob_init flags: */
#define GLOB_ICASE        0x01	/* case insensitive */
#define GLOB_SUBSTRING    0x02	/* match a substring */
#define GLOB_HIERARCHY    0x04	/* use '%' as hierarchy matching and no '?' */
#define GLOB_INBOXCASE    0x08  /* match "inbox" prefix case insensitive */

/* initialize globbing structure
 *  str      -- globbing string
 *  flags    -- see flag values above
 *  suppress -- prefix to suppress
 */
glob *glob_init_suppress P((const char *str, int flags, const char *suppress));

/* free a glob structure
 */
void glob_free P((glob **g));

/* returns -1 if no match, otherwise length of match or partial-match
 *  g         pre-processed glob string
 *  ptr       string to perform glob on
 *  len       length of ptr string (if 0, strlen() is used)
 *  min       pointer to minimum length of a valid partial-match.
 *            Set to -1 if no more matches.  Set to return value + 1
 *     	      if another match is possible.  If NULL, no partial-matches
 *            are returned.
 */
int glob_test P((glob *g, const char *str, long len, long *min));

/* macros */
#define glob_init(str, flags) glob_init_suppress((str), (flags), NULL)
#define glob_inboxcase(g) ((g)->inbox)
#define GLOB_TEST(g, str) glob_test((g), (str), 0, NULL)
#define GLOB_SET_SEPARATOR(g, c) ((g)->sep_char = (c))

#endif /* INCLUDED_GLOB_H */
