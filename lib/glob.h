/* glob.h -- fast globbing routine using '*', '%', and '?'
 $Id: glob.h,v 1.12 2003/02/13 20:15:40 rjs3 Exp $
 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
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
extern glob *glob_init_suppress P((const char *str, int flags,
				   const char *suppress));

/* free a glob structure
 */
extern void glob_free P((glob **g));

/* returns -1 if no match, otherwise length of match or partial-match
 *  g         pre-processed glob string
 *  ptr       string to perform glob on
 *  len       length of ptr string (if 0, strlen() is used)
 *  min       pointer to minimum length of a valid partial-match.
 *            Set to -1 if no more matches.  Set to return value + 1
 *     	      if another match is possible.  If NULL, no partial-matches
 *            are returned.
 */
extern int glob_test P((glob *g, const char *str, long len, long *min));

/* macros */
#define glob_init(str, flags) glob_init_suppress((str), (flags), NULL)
#define glob_inboxcase(g) ((g)->inbox)
#define GLOB_TEST(g, str) glob_test((g), (str), 0, NULL)
#define GLOB_SET_SEPARATOR(g, c) ((g)->sep_char = (c))

#endif /* INCLUDED_GLOB_H */
