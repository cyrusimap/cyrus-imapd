/* glob.c -- fast globbing routine using '*', '%', and '?'
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
 *   2) '%' converted to '*' if no GLOB_HIERARCHIAL
 *   3) '?'s moved to left of '*'
 *   4) '*' eats all '*'s and '%'s connected by any wildcard
 *   5) '%' eats all adjacent '%'s
 */
glob *glob_init(str, flags)
    char *str;
    int flags;
{
    glob *g;
    char *dst, *scan;
    int len;

    len = strlen(str);
    g = (glob *) fs_get(sizeof (glob) + len);
    if (g != NULL) {
	g->sep_char = '.';
	dst = g->str;
	/* if we're doing a substring match, put a '*' prefix (1) */
	if (flags & GLOB_SUBSTRING) {
	    /* skip over unneeded glob prefixes (3,4) */
	    while (*str == '%' || *str == '?' || *str == '*') {
		if (*str++ == '?') *dst++ = '?';
	    }
	    *dst++ = '*';
	}
	while (*str) {
	    if (*str == '*' || *str == '%') {
		/* remove duplicates (5) */
		while (str[0] == str[1]) ++str;
		/* Look for '*'.  If we find one, treat '%' as '*'. (2) */
		for (scan = str; *scan == '%' || *scan == '?'; ++scan);
		if (*scan != '*' && (flags & GLOB_HIERARCHY)) {
		    *dst++ = *str++;
		} else {
		    /* skip over unneeded globbing with '*' (3,4) */
		    while (*str == '%' || *str == '?' || *str == '*') {
			if (*str++ == '?') *dst++ = '?';
		    }
		    *dst++ = '*';
		}
	    } else {
		*dst++ = *str++;
	    }
	}
	/* put a '*' suffix (1) */
	if (flags & GLOB_SUBSTRING && dst[-1] != '*') {
	    while (dst[-1] == '%' || dst[-1] == '?') --dst;
	    *dst++ = '*';
	}
	*dst = '\0';
	if (flags & GLOB_HIERARCHY) {
	    for (dst = g->str; *dst && *dst != '*' && *dst != '?'; ++dst);
	    if (*dst) flags |= GLOB_MULTIPARTIAL;
	}
	if (flags & GLOB_ICASE) lcase(g->str);
	g->flags = flags;
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

/* recursive handling of "%" character -- match until end of string or a "*"
 *  This needs to be recursive for the degenerate case of "%...?...%"
 *  sequences.
 */
static int glob_recurse(pglob, pstr, g, start, pend, min)
    char **pglob, **pstr;
    glob *g;
    char *start, *pend;
    long *min;
{
    char *gptr, *ptr, *plev = *pstr;
    int result;

    /* handle special case of "%" at end of string */
    if (!**pglob) {
	while (plev != pend && *plev && *plev != g->sep_char) ++plev;
	*pstr = plev;
	if (plev == pend || !*plev) return (plev - start);
	if (min && plev - start >= *min) {
	    *min = (g->flags & GLOB_MULTIPARTIAL) ? plev - start + 1 : -1;
	    return (plev - start);
	}
	return (-1);
    }
    
    /* loop for each character the "%" eats */
    do {
	gptr = *pglob;
	ptr = plev;
	if (!(g->flags & GLOB_ICASE)) {
	    while (ptr != pend && *ptr && *gptr != '*' && *gptr != '%'
		   && (*gptr == '?' || *gptr == *ptr)) {
		++ptr, ++gptr;
	    }
	} else {
	    while (ptr != pend && *ptr && *gptr != '*' && *gptr != '%'
		   && (*gptr == '?' || *gptr == TOLOWER(*ptr))) {
		++ptr, ++gptr;
	    }
	}
	if (*gptr == '%') {
	    ++gptr;
	    result = glob_recurse(&gptr, &ptr, g, start, pend, min);
	    if (result >= 0) {
		*pglob = gptr;
		*pstr = ptr;
		return (result);
	    }
	}
    } while (*gptr != '*' && (*gptr || (ptr != pend && *ptr))
	     && plev != pend && *plev && *plev++ != g->sep_char);
    *pglob = gptr;
    *pstr = ptr;

    return (!*gptr && (ptr == pend || !*ptr) ? ptr - start : -1);
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
    char *start;		/* start of input string */
    int result;

    if (min && *min < 0) return (-1);
    gptr = g->str;
    start = ptr;
    pend = ptr + len;
    gstar = NULL;
    if (!(g->flags & GLOB_ICASE)) {
	/* case sensitive version */

	/* loop to manage '*' wildcards */
	do {
	    if (*gptr == '*') {
		/* if nothing after '*', we're done */
		if (!*++gptr) {
		    while (ptr != pend && *ptr) ++ptr;
		    break;
		}
		gstar = gptr;
		pstar = ptr;
	    } else if (*gptr == '%') {
		/* recurse in case we hit the "%...?...%" case */
		result = glob_recurse(&gptr, &ptr, g, start, pend, min);
		if (result >= 0) {
		    if (min && (ptr == pend || !*ptr)) *min = -1;
		    return (result);
		}
	    }
	    if (gstar) {
		/* look for a match with first char following '*' */
		while (pstar != pend && *pstar && *gstar != *pstar) ++pstar;
		if (pstar == pend || !*pstar) break;
		ptr = ++pstar;
		gptr = gstar + 1;
	    }
	    /* see if we match to the next '%' or '*' wildcard */
	    while (*gptr != '*' && *gptr != '%' && ptr != pend && *ptr
		   && (*gptr == '?' || *gptr == *ptr)) {
		++ptr, ++gptr;
	    }
	    /* continue if at wildcard or we passed an asterisk */
	} while (*gptr == '*' || *gptr == '%' || (gstar && *gptr)
		 || (gstar && ptr < pend && *ptr));
    } else {
	/* case insensitive version (same as above, but with TOLOWER()) */


	/* loop to manage '*' wildcards */
	do {
	    if (*gptr == '*') {
		/* if nothing after '*', we're done */
		if (!*++gptr) {
		    while (ptr != pend && *ptr) ++ptr;
		    break;
		}
		gstar = gptr;
		pstar = ptr;
	    } else if (*gptr == '%') {
		/* recurse in case we hit the "%...?...%" case */
		++gptr;
		result = glob_recurse(&gptr, &ptr, g, start, pend, min);
		if (result >= 0) {
		    if (min && (ptr == pend || !*ptr)) *min = -1;
		    return (result);
		}
	    }
	    if (gstar) {
		/* look for a match with first char following '*' */
		while (pstar != pend && *pstar
		       && *gstar != TOLOWER(*pstar)) ++pstar;
		if (pstar == pend || !*pstar) break;
		ptr = ++pstar;
		gptr = gstar + 1;
	    }
	    /* see if we match to the next '%' or '*' wildcard */
	    while (*gptr != '*' && *gptr != '%' && ptr != pend && *ptr
		   && (*gptr == '?' || *gptr == TOLOWER(*ptr))) {
		++ptr, ++gptr;
	    }
	    /* continue if at wildcard or we passed an asterisk */
	} while (*gptr == '*' || *gptr == '%' || (gstar && *gptr)
		 || (gstar && ptr < pend && *ptr));
    }

    if (min) *min = -1;
    return (*gptr == '\0' && (ptr == pend || *ptr == '\0') ? ptr - start : -1);
}

#ifdef TEST_GLOB
main(argc, argv)
    int argc;
    char **argv;
{
    glob *g = glob_init(argv[1], GLOB_ICASE|GLOB_HIERARCHY);
    char text[1024];
    int len;
    long min;

    if (g) {
	printf("%d/%s\n", g->flags, g->str);
	while (fgets(text, sizeof (text), stdin) != NULL) {
	    len = strlen(text);
	    text[len-1] = '\0';
	    min = 0;
	    while (min >= 0) {
		printf("%d\n", glob_test(g, text, len, &min));
	    }
	}
    }
}
#endif
