/* glob.h -- fast globbing routine using '*', '%', and '?'
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
