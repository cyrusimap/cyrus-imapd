/* comparator.c -- comparator functions
 * Larry Greenfield
 * $Id: comparator.c,v 1.12.2.2 2003/02/27 18:13:52 rjs3 Exp $
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "comparator.h"
#include "tree.h"
#include "sieve.h"
#include "bytecode.h"

/*!!! uses B_CONTAINS not CONTAINS, etc, only works with bytecode*/

extern int strcasecmp(const char *, const char *);

typedef int (*compare_t)(const void *, const void *);

/* --- relational comparators --- */

/* these are generic wrappers in which 'rock' is the compare function */

static int rel_eq(const char *text, const char *pat, void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, pat) == 0);
}

static int rel_ne(const char *text, const char *pat, void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, pat) != 0);
}

static int rel_gt(const char *text, const char *pat, void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, pat) > 0);
}

static int rel_ge(const char *text, const char *pat, void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, pat) >= 0);
}

static int rel_lt(const char *text, const char *pat, void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, pat) < 0);
}

static int rel_le(const char *text, const char *pat, void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, pat) <= 0);
}

/* --- i;octet comparators --- */

/* just compare the two; these should be NULL terminated */
static int octet_cmp(const char *text, const char *pat)
{
    size_t sl;
    int r;

    sl = strlen(text) < strlen(pat) ? strlen(text) : strlen(pat);

    r = memcmp(text, pat, sl);

    if (r == 0)
	return (strlen(text) - strlen(pat));
    else 
	return r;
}

/* we implement boyer-moore for hell of it, since this is probably
 not very useful for sieve */
#if 0
int boyer_moore(char *text, char *pat)
{
    int i, j; /* indexes */
    int M = strlen(pat); /* length of pattern */
    int N = strlen(text); /* length of text */
    int skip[256]; /* table of how much to skip, based on each character */

    /* initialize skip table */
    for (i = 0; i < 256; i++)
	skip[i] = M;
    for (i = 0; i < M; i++)
	skip[(int) pat[i]] = M-i-1;
    
    /* look for pat in text */
    i = j = M-1;
    do {
	if (pat[j] == text[i]) {
	    i--;
	    j--;
	} else {
	    if (M-j > skip[(int) text[i]]) {
		i = i + M - j;
	    } else {
		i = i + skip[(int) text[i]];
	    }
	    j = M-1;
	}
    } while (!((j < 0) || (i >= N)));
    /* i+1 is the position of the match if i < N */
    return (i < N) ? 1 : 0;
}
#endif

/* we do a brute force attack */
static int octet_contains(const char *text, const char *pat, 
                          void *rock __attribute__((unused)))
{
    return (strstr(text, pat) != NULL);
}

static int octet_matches_(const char *text, const char *pat, int casemap)
{
    const char *p;
    const char *t;
    char c;

    t = text;
    p = pat;
    for (;;) {
	if (*p == '\0') {
	    /* ran out of pattern */
	    return (*t == '\0');
	}
	c = *p++;
	switch (c) {
	case '?':
	    if (*t == '\0') {
		return 0;
	    }
	    t++;
	    break;
	case '*':
	    while (*p == '*' || *p == '?') {
		if (*p == '?') {
		    /* eat the character now */
		    if (*t == '\0') {
			return 0;
		    }
		    t++;
		}
		/* coalesce into a single wildcard */
		p++;
	    }
	    if (*p == '\0') {
		/* wildcard at end of string, any remaining text is ok */
		return 1;
	    }

	    while (*t != '\0') {
		/* recurse */
		if (octet_matches_(t, p, casemap)) return 1;
		t++;
	    }
	case '\\':
	    p++;
	    /* falls through */
	default:
	    if (casemap && (toupper(c) == toupper(*t))) {
		t++;
	    } else if (!casemap && (c == *t)) {
		t++;
	    } else {
		/* literal char doesn't match */
		return 0;
	    }
	}
    }
    /* never reaches */
    abort();
}

static int octet_matches(const char *text, const char *pat, 
                         void *rock __attribute__((unused)))
{
    return octet_matches_(text, pat, 0);
}


#ifdef ENABLE_REGEX
static int octet_regex(const char *text, const char *pat, 
                       void *rock __attribute__((unused)))
{
    return (!regexec((regex_t *) pat, text, 0, NULL, 0));
}
#endif


/* --- i;ascii-casemap comparators --- */


/* use strcasecmp() as the compare function */

/* sheer brute force */
static int ascii_casemap_contains(const char *text, const char *pat,
				  void *rock __attribute__((unused)))
{
    int N = strlen(text);
    int M = strlen(pat);
    int i, j;

    i = 0, j = 0;
    while ((j < M) && (i < N)) {
              if (toupper(text[i]) == toupper(pat[j])) {
	  	  i++; j++;
	} else {
	    i = i - j + 1;
	    j = 0;
	}
    }    

    return (j == M); /* we found a match! */
}

static int ascii_casemap_matches(const char *text, const char *pat, 
                                 void *rock __attribute__((unused)))
{
    return octet_matches_(text, pat, 1);
}

/* i;ascii-numeric; only supports relational tests
 *
 *  A \ B    number   not-num 
 *  number   A ? B    B > A 
 *  not-num  A > B    A == B
 */
static int ascii_numeric_cmp(const char *text, const char *pat)
{
    if (isdigit((int) *pat)) {
	if (isdigit((int) *text)) {
	    return (atoi(text) - atoi(pat));
	} else {
	    return 1;
	}
    } else if (isdigit((int) *text)) return -1;
    else return 0; /* both not digits */
}

static comparator_t *lookup_rel(int relation)
{
    comparator_t *ret;

    ret = NULL;
    switch (relation)
      {
      case B_EQ:
	ret = &rel_eq;
	break;
      case B_NE:
	ret = &rel_ne; 
	break;
      case B_GT: 
	ret = &rel_gt; 
	break;
      case B_GE:
         ret = &rel_ge; 
	 break;
      case B_LT:
	ret = &rel_lt; 
	break;
      case B_LE:
	ret = &rel_le; 
      }

    return ret;
}

comparator_t *lookup_comp(int comp, int mode, int relation,
			  void **comprock)
{
    comparator_t *ret;

    ret = NULL;
    *comprock = NULL;
#if VERBOSE
    printf("comp%d mode%d relat%d     \n", comp, mode, relation); 
#endif
    switch (comp)
      {
      case B_OCTET:    
 	switch (mode) {
	  case B_IS:
	    ret = &rel_eq;
	    *comprock = (void **) &octet_cmp;
	    break;
	  case B_CONTAINS:
	    ret = &octet_contains;
	    break;
	  case B_MATCHES:
	    ret = &octet_matches;
	    break;
#ifdef ENABLE_REGEX
	  case B_REGEX:
	    ret = &octet_regex;
	    break;
#endif
	  case B_VALUE:
	    ret = lookup_rel(relation);
	    *comprock = (void **) &octet_cmp;
	    break;
	}
	break; /*end of octet */
      case B_ASCIICASEMAP:
     	switch (mode) {
	case B_IS:
	    ret = &rel_eq;
	    *comprock = (void **) &strcasecmp;
	    break;
	case B_CONTAINS:
	    ret = &ascii_casemap_contains;
	    break;
	case B_MATCHES:
	    ret = &ascii_casemap_matches;
	    break;
#ifdef ENABLE_REGEX
	case B_REGEX:
	    /* the ascii-casemap destinction is made during
	       the compilation of the regex in verify_regex() */
	    ret = &octet_regex;
	    break;
#endif
	case B_VALUE:
	    ret = lookup_rel(relation);
	    *comprock = &strcasecmp;
	    break;
	}
	break;/*end of ascii casemap */
      case B_ASCIINUMERIC:
	switch (mode) {
	case B_IS:
	    ret = &rel_eq;
	    *comprock = (void **) &ascii_numeric_cmp;
	    break;
	case B_COUNT:
	case B_VALUE:
	    ret = lookup_rel(relation);
	    *comprock = (void **) &ascii_numeric_cmp;
	    break;
	}
	break;
      }
    return ret;
}
