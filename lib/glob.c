/* glob.c -- fast globbing routine using '*', '%', and '?'
 *
 *	(C) Copyright 1993-1995 by Carnegie Mellon University
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

#include <stdio.h>
#include <ctype.h>
#include "util.h"
#include "glob.h"

/* from utilities: */
extern void *fs_get( /* size_t */ );
extern void fs_give( /* void ** */ );

/* initialize globbing structure
 *  This makes the following changes to the input string:
 *   1) '*' added to each end if GLOB_SUBSTRING
 *   2) '%' converted to '?' if no GLOB_HIERARCHIAL
 *   3) '?'s moved to left of '*'
 *   4) '*' eats all '*'s and '%'s connected by any wildcard
 *   5) '%' eats all adjacent '%'s
 */
glob *glob_init_suppress(str, flags, suppress)
    char *str;
    int flags;
    char *suppress;
{
    glob *g;
    char *dst;
    int slen = 0, newglob;

    newglob = flags & GLOB_HIERARCHY;
    if (suppress) slen = strlen(suppress);
    g = (glob *) fs_get(sizeof (glob) + slen + strlen(str) + 1);
    if (g != NULL) {
	g->sep_char = '.';
	dst = g->str;
	/* if we're doing a substring match, put a '*' prefix (1) */
	if (flags & GLOB_SUBSTRING) {
	    /* skip over unneeded glob prefixes (3,4) */
	    if (newglob) {
		while (*str == '*' || (*str == '%' && str[1])) ++str;
	    } else {
		while (*str == '%' || *str == '*' || *str == '?') {
		    if (*str++ != '*') *dst++ = '?';
		}
	    }
	    *dst++ = '*';
	}
	if (!newglob) {
	    while (*str) {
		if (*str == '*') {
		    /* move '?' to left of '*' (3) */
		    while (*str == '*' || *str == '%' || *str == '?') {
			if (*str++ != '*') *dst++ = '?';
		    }
		    *dst++ = '*';
		} else {
		    *dst++ = (*str == '%') ? '?' : *str;
		    ++str;
		}
	    }
	} else {
	    while (*str) {
		if (*str == '*' || *str == '%') {
		    /* remove duplicate hierarchy match (5) */
		    while (*str == '%') ++str;
		    /* If we found a '*', treat '%' as '*' (4) */
		    if (*str == '*') {
			/* remove duplicate wildcards (4) */
			while (*str == '*' || (*str == '%' && str[1])) ++str;
			*dst++ = '*';
		    } else {
			*dst++ = '%';
		    }
		} else {
		    *dst++ = *str++;
		}
	    }
	}
	/* put a '*' suffix (1) */
	if (flags & GLOB_SUBSTRING && dst[-1] != '*') {
	    /* remove duplicate wildcards (4) */
	    if (newglob) while (dst[-1] == '%') --dst;
	    *dst++ = '*';
	}
	*dst++ = '\0';
	if (flags & GLOB_ICASE) lcase(g->str);
	g->flags = flags;

	/* set suppress string if:
	 *  1) the suppress string isn't a prefix of the glob pattern and
	 *  2) the suppress string prefix matches the glob pattern
	 */
	g->suppress = NULL;
	if (suppress) {
	    strcpy(dst, suppress);
	    str = g->str;
	    if (strncmp(suppress, str, slen) ||
		(str[slen] != '\0' && str[slen] != g->sep_char
		     && str[slen] != '*' && str[slen] != '%')) {
		while (*str && *str == *suppress) ++str, ++suppress;
		if (*str == '*' || *str == '%' || *suppress == '\0') {
		    g->suppress = dst;
		    g->slen = slen;
		}
	    }
	}
    }

    return (g);
}

/* free a glob structure
 */
void glob_free(g)
    glob **g;
{
    fs_give((void **) g);
}

/* returns -1 if no match, otherwise length of match or partial-match
 *  g         pre-processed glob string
 *  ptr       string to perform glob on
 *  len       length of ptr string
 *  min       pointer to minimum length of a valid partial-match
 *            set to return value + 1 on partial match, otherwise -1
 *            if NULL, partial matches not allowed
 */
int glob_test(g, ptr, len, min)
    glob *g;
    char *ptr;
    long len;
    long *min;
{
    char *gptr, *pend;		/* glob pointer, end of ptr string */
    char *gstar, *pstar;	/* pointers for '*' patterns */
    char *ghier, *phier;	/* pointers for '%' patterns */
    char *start;		/* start of input string */
    int newglob;

    /* check for remaining partial matches */
    if (min && *min < 0) return (-1);

    /* get length */
    if (!len) len = strlen(ptr);

    /* check for suppress string */
    if (g->suppress && !strncmp(g->suppress, ptr, g->slen) &&
	(ptr[g->slen] == '\0' || ptr[g->slen] == g->sep_char)) {
	if (min) *min = -1;
	return (-1);
    }
	
    /* initialize globbing */
    gptr = g->str;
    start = ptr;
    pend = ptr + len;
    gstar = ghier = NULL;
    newglob = g->flags & GLOB_HIERARCHY;
    if (!(g->flags & GLOB_ICASE)) {
	/* case sensitive version */

	/* loop to manage wildcards */
	do {
	    if (*gptr == '*') {
		/* if nothing after '*', we're done */
		if (!*++gptr) {
		    ptr = pend;
		    break;
		}
		ghier = NULL;
		gstar = gptr;
		pstar = ptr;
	    } else if (*gptr == '%') {
		/* if nothing after '%', we may be done */
		if (!*++gptr) {
		    while (ptr != pend && *ptr != g->sep_char) ++ptr;
		    if (min && ptr != pend && ptr - start >= *min) {
			*min = gstar ? ptr - start + 1 : -1;
			return (ptr - start);
		    }
		    if (gstar && *gstar == '%' && ptr < pend) {
			pstar = ++ptr;
			--gptr;
		    }
		} else {
		    ghier = gptr;
		    phier = ptr;
		}
	    }
	    if (ghier) {
		/* look for a match with first char following '%' */
		while (phier != pend && *ghier != *phier) ++phier;
		if (phier == pend) break;
		ptr = ++phier;
		gptr = ghier + 1;
	    } else if (gstar && *gstar != '%') {
		/* look for a match with first char following '*' */
		while (pstar != pend && *gstar != *pstar) ++pstar;
		if (pstar == pend) break;
		ptr = ++pstar;
		gptr = gstar + 1;
	    }
	    /* see if we match to the next '%' or '*' wildcard */
	    while (*gptr != '*' && *gptr != '%' && ptr != pend
		   && (*gptr == *ptr || (!newglob && *gptr == '?'))) {
		++ptr, ++gptr;
	    }
	    /* continue if at wildcard or we passed an asterisk */
	} while (*gptr == '*' || *gptr == '%' ||
		 ((gstar || ghier) && (*gptr || ptr != pend)));
    } else {
	/* case insensitive version (same as above, but with TOLOWER()) */

	/* loop to manage wildcards */
	do {
	    if (*gptr == '*') {
		/* if nothing after '*', we're done */
		if (!*++gptr) {
		    ptr = pend;
		    break;
		}
		ghier = NULL;
		gstar = gptr;
		pstar = ptr;
	    } else if (*gptr == '%') {
		/* if nothing after '%', we may be done */
		if (!*++gptr) {
		    while (ptr != pend && *ptr != g->sep_char) ++ptr;
		    if (min && ptr != pend && ptr - start >= *min) {
			*min = gstar ? ptr - start + 1 : -1;
			return (ptr - start);
		    }
		    if (gstar && *gstar == '%' && ptr < pend) {
			pstar = ++ptr;
			--gptr;
		    }
		} else {
		    ghier = gptr;
		    phier = ptr;
		}
	    }
	    if (ghier) {
		/* look for a match with first char following '%' */
		while (phier != pend && *ghier != TOLOWER(*phier)) ++phier;
		if (phier == pend) break;
		ptr = ++phier;
		gptr = ghier + 1;
	    } else if (gstar && *gstar != '%') {
		/* look for a match with first char following '*' */
		while (pstar != pend && *gstar != TOLOWER(*pstar)) ++pstar;
		if (pstar == pend) break;
		ptr = ++pstar;
		gptr = gstar + 1;
	    }
	    /* see if we match to the next '%' or '*' wildcard */
	    while (*gptr != '*' && *gptr != '%' && ptr != pend
		   && (*gptr == TOLOWER(*ptr) || (!newglob && *gptr == '?'))) {
		++ptr, ++gptr;
	    }
	    /* continue if at wildcard or we passed an asterisk */
	} while (*gptr == '*' || *gptr == '%' ||
		 ((gstar || ghier) && (*gptr || ptr != pend)));
    }

    if (min) *min = -1;
    return (*gptr == '\0' && ptr == pend ? ptr - start : -1);
}

#ifdef TEST_GLOB
fatal(str, val)
    char *str;
    int val;
{
    fprintf(stderr, "%s\n", str);
    exit(1);
}

main(argc, argv)
    int argc;
    char **argv;
{
    glob *g = glob_init_suppress(argv[1], GLOB_ICASE|GLOB_HIERARCHY,
				 "user.nifty");
    char text[1024];
    int len;
    long min;

    if (g) {
	printf("%d/%s\n", g->flags, g->str);
	while (fgets(text, sizeof (text), stdin) != NULL) {
	    len = strlen(text) - 1;
	    text[len] = '\0';
	    min = 0;
	    while (min >= 0) {
		printf("%d\n", glob_test(g, text, len, &min));
	    }
	}
    }
}
#endif
