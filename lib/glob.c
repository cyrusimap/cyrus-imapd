/* glob.c -- fast globbing routine using '*', '%', and '?'
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 * Author: Chris Newman
 * Start Date: 4/5/93
 */
/*
 * $Id: glob.c,v 1.23 2002/09/20 16:57:29 rjs3 Exp $
 */

#include <config.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "util.h"
#include "glob.h"
#include "xmalloc.h"

#define SEPCHAR '.'

/* name of "INBOX" -- must have no repeated substrings */
static char inbox[] = "INBOX";
#define INBOXLEN (sizeof (inbox) - 1)

/* initialize globbing structure
 *  This makes the following changes to the input string:
 *   1) '*' added to each end if GLOB_SUBSTRING
 *   2) '%' converted to '?' if no GLOB_HIERARCHIAL
 *   3) '?'s moved to left of '*'
 *   4) '*' eats all '*'s and '%'s connected by any wildcard
 *   5) '%' eats all adjacent '%'s
 */
glob *glob_init_suppress (str, flags, suppress)
    const char *str;
    int flags;
    const char *suppress;
{
    glob *g;
    char *dst;
    int slen = 0, newglob;

    newglob = flags & GLOB_HIERARCHY;
    if (suppress) slen = strlen(suppress);
    g = (glob *) xmalloc(sizeof (glob) + slen + strlen(str) + 1);
    if (g != 0) {
        strcpy(g->inbox, inbox);
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
		    *dst++ = (char)((*str == '%') ? '?' : *str);
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

	/* pre-match "INBOX" to the pattern case insensitively and save state
	 * also keep track of the matching case for "INBOX"
	 * NOTE: this only works because "INBOX" has no repeated substrings
	 */
	if (flags & GLOB_INBOXCASE) {
	    str = g->str;
	    dst = g->inbox;
	    g->gstar = g->ghier = NULL;
	    do {
		while (*dst && TOLOWER(*str) == TOLOWER(*dst)) {
		    *dst++ = *str++;
		}
		if (*str == '*') g->gstar = ++str, g->ghier = 0;
		else if (*str == '%') g->ghier = ++str;
		else break;
		if (*str != '%') {
		    while (*dst && TOLOWER(*str) != TOLOWER(*dst)) ++dst;
		}
	    } while (*str && *dst);
	    g->gptr = str;
	    if (*dst) g->flags &= ~GLOB_INBOXCASE;
	}

	/* set suppress string if:
	 *  1) the suppress string isn't a prefix of the glob pattern and
	 *  2) the suppress string prefix matches the glob pattern
	 *     or GLOB_INBOXCASE is set
	 */
	g->suppress = 0;
	if (suppress) {
	    dst = g->str + strlen(g->str) + 1;
	    strcpy(dst, suppress);
	    str = g->str;
	    if (strncmp(suppress, str, slen) ||
		(str[slen] != '\0' && str[slen] != g->sep_char
		     && str[slen] != '*' && str[slen] != '%')) {
		while (*str && *str == *suppress) ++str, ++suppress;
		if ((g->flags & GLOB_INBOXCASE)
		    || *str == '*' || *str == '%' || *suppress == '\0') {
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
void glob_free (g)
    glob **g;
{
    free((void **) g);
}

/* returns -1 if no match, otherwise length of match or partial-match
 *  g         pre-processed glob string
 *  ptr       string to perform glob on
 *  len       length of ptr string
 *  min       pointer to minimum length of a valid partial-match
 *            set to return value + 1 on partial match, otherwise -1
 *            if NULL, partial matches not allowed
 */
int glob_test (g, ptr, len, min)
    glob* g;
    const char* ptr;
    long int len;
    long int *min;
{
    const char *gptr, *pend;	/* glob pointer, end of ptr string */
    const char *gstar, *pstar;	/* pointers for '*' patterns */
    const char *ghier, *phier;	/* pointers for '%' patterns */
    const char *start;		/* start of input string */
    int newglob;

    /* check for remaining partial matches */
    if (min && *min < 0) return (-1);

    /* get length */
    if (!len) len = strlen(ptr);

    /* initialize globbing */
    gptr = g->str;
    start = ptr;
    pend = ptr + len;
    gstar = ghier = NULL;
    newglob = g->flags & GLOB_HIERARCHY;
    phier = pstar = NULL;	/* initialize to eliminate warnings */

    /* check for INBOX prefix */
    if ((g->flags & GLOB_INBOXCASE) && !strncmp(ptr, inbox, INBOXLEN)) {
	pstar = phier = ptr += INBOXLEN;
	gstar = g->gstar;
	ghier = g->ghier;
	gptr = g->gptr;
    }

    /* check for suppress string */
    if (g->suppress && !strncmp(g->suppress, ptr, g->slen) &&
	(ptr[g->slen] == '\0' || ptr[g->slen] == g->sep_char)) {
	if (!(g->flags & GLOB_INBOXCASE)) {
	    if (min) *min = -1;
	    return (-1);
	}
	pstar = phier = ptr += g->slen;
	gstar = g->gstar;
	ghier = g->ghier;
	gptr = g->gptr;
    }
    
    /* main globbing loops */
    if (!(g->flags & GLOB_ICASE)) {
	/* case sensitive version */

	/* loop to manage wildcards */
	do {
	    /* see if we match to the next '%' or '*' wildcard */
	    while (*gptr != '*' && *gptr != '%' && ptr != pend
		   && (*gptr == *ptr || (!newglob && *gptr == '?'))) {
		++ptr, ++gptr;
	    }
	    if (*gptr == '\0' && ptr == pend) break;
	    if (*gptr == '*') {
		ghier = NULL;
		gstar = ++gptr;
		pstar = ptr;
	    }
	    if (*gptr == '%') {
		ghier = ++gptr;
		phier = ptr;
	    }
	    if (ghier) {
		/* look for a match with first char following '%',
		 * stop at a sep_char unless we're doing "*%"
		 */
		ptr = phier;
		while (ptr != pend && *ghier != *ptr
		       && (*ptr != g->sep_char ||
			   (!*ghier && gstar && *gstar == '%' && min
			    && ptr - start < *min))) {
		    ++ptr;
		}
		if (ptr == pend) {
		    gptr = ghier;
		    break;
		}
		if (*ptr == g->sep_char && *ptr != *ghier) {
		    if (!*ghier && min
			&& *min < ptr - start && ptr != pend
			&& *ptr == g->sep_char
			) {
			*min = gstar ? ptr - start + 1 : -1;
			return (ptr - start);
		    }
		    gptr = ghier;
		    ghier = NULL;
		} else {
		    phier = ++ptr;
		    gptr = ghier + 1;
		}
	    }
	    if (gstar && !ghier) {
		if (!*gstar) {
		    ptr = pend;
		    break;
		}
		/* look for a match with first char following '*' */
		while (pstar != pend && *gstar != *pstar) ++pstar;
		if (pstar == pend) {
		    gptr = gstar;
		    break;
		}
		ptr = ++pstar;
		gptr = gstar + 1;
	    }
	    if (*gptr == '\0' && min && *min < ptr - start && ptr != pend && *ptr == g->sep_char) {
		/* The pattern ended on a hierarchy separator
		 * return a partial match */
		*min = ptr - start + 1;
		return ptr - start;
	    }

	    /* continue if at wildcard or we passed an asterisk */
	} while (*gptr == '*' || *gptr == '%' ||
		 ((gstar || ghier) && (*gptr || ptr != pend)));
    } else {
	/* case insensitive version (same as above, but with TOLOWER()) */

	/* loop to manage wildcards */
	do {
	    /* see if we match to the next '%' or '*' wildcard */
	    while (*gptr != '*' && *gptr != '%' && ptr != pend
		   && ((unsigned char) *gptr == TOLOWER(*ptr) || 
			(!newglob && *gptr == '?'))) {
		++ptr, ++gptr;
	    }
	    if (*gptr == '\0' && ptr == pend) break;
	    if (*gptr == '*') {
		ghier = NULL;
		gstar = ++gptr;
		pstar = ptr;
	    }
	    if (*gptr == '%') {
		ghier = ++gptr;
		phier = ptr;
	    }
	    if (ghier) {
		/* look for a match with first char following '%',
		 * stop at a sep_char unless we're doing "*%"
		 */
		ptr = phier;
		while (ptr != pend && (unsigned char) *ghier != TOLOWER(*ptr)
		       && (*ptr != g->sep_char ||
			   (!*ghier && gstar && *gstar == '%' && min
			    && ptr - start < *min))) {
		    ++ptr;
		}
		if (ptr == pend) {
		    gptr = ghier;
		    break;
		}
		if (*ptr == g->sep_char) {
		    if (!*ghier && min
			&& *min < ptr - start && ptr != pend
			&& *ptr == g->sep_char
			) {
			*min = gstar ? ptr - start + 1 : -1;
			return (ptr - start);
		    }
		    ghier = NULL;
		} else {
		    phier = ++ptr;
		    gptr = ghier + 1;
		}
	    }
	    if (gstar && !ghier) {
		if (!*gstar) {
		    ptr = pend;
		    break;
		}
		/* look for a match with first char following '*' */
		while (pstar != pend && 
		       (unsigned char) *gstar != TOLOWER(*pstar)) ++pstar;
		if (pstar == pend) {
		    gptr = gstar;
		    break;
		}
		ptr = ++pstar;
		gptr = gstar + 1;
	    }
	    if (*gptr == '\0' && min && *min < ptr - start && ptr != pend && *ptr == g->sep_char) {
		/* The pattern ended on a hierarchy separator
		 * return a partial match */
		*min = ptr - start + 1;
		return ptr - start;
	    }

	    /* continue if at wildcard or we passed an asterisk */
	} while (*gptr == '*' || *gptr == '%' ||
		 ((gstar || ghier) && (*gptr || ptr != pend)));
    }

    if (min) *min = -1;
    return (*gptr == '\0' && ptr == pend ? ptr - start : -1);
}

#ifdef TEST_GLOB
int main (argc, argv)
    int argc;
    char* argv[];
{
    glob *g = glob_init_suppress(argv[1], GLOB_INBOXCASE|GLOB_HIERARCHY,
				 "user.nifty");
    char text[1024];
    int len;
    long min;

    if (g) {
	printf("%d/%s/%s\n", g->flags, g->inbox, g->str);
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
#endif /* TEST_GLOB */
