/* comparator.c -- comparator functions
 * Larry Greenfield
 * Ken Murchison (rewritten to handle relational ops and non-terminated text)
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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
 * $Id: comparator.c,v 1.25 2009/12/21 12:34:30 murch Exp $
 */

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
#include "xmalloc.h"
#include "util.h"

/*!!! uses B_CONTAINS not CONTAINS, etc, only works with bytecode*/

typedef int (*compare_t)(const void *, size_t, const void *);

/* --- relational comparators --- */

/* these are generic wrappers in which 'rock' is the compare function */

static int rel_eq(const char *text, size_t tlen, const char *pat, void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, tlen, pat) == 0);
}

static int rel_ne(const char *text, size_t tlen, const char *pat, void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, tlen, pat) != 0);
}

static int rel_gt(const char *text, size_t tlen, const char *pat, void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, tlen, pat) > 0);
}

static int rel_ge(const char *text, size_t tlen, const char *pat, void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, tlen, pat) >= 0);
}

static int rel_lt(const char *text, size_t tlen, const char *pat, void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, tlen, pat) < 0);
}

static int rel_le(const char *text, size_t tlen, const char *pat, void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, tlen, pat) <= 0);
}

/* --- i;octet comparators --- */

/* just compare the two; pat should be NULL terminated */
static int octet_cmp_(const char *text, size_t tlen,
		      const char *pat, int casemap)
{
    size_t plen, sl, i;
    int r = 0;

    plen = strlen(pat);
    sl = tlen < plen ? tlen : plen;

    for (i = 0; !r && i < sl; i++) {
	r = casemap ? toupper(text[i]) - toupper(pat[i]) : text[i] - pat[i];
    }

    if (r == 0)
	return (tlen - plen);
    else 
	return r;
}

static int octet_cmp(const char *text, size_t tlen, const char *pat)
{
    return octet_cmp_(text, tlen, pat, 0);
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
static int octet_contains_(const char *text, size_t tlen,
			   const char *pat, int casemap)
{
    int N = tlen;
    int M = strlen(pat);
    int i, j;

    i = 0, j = 0;
    while ((j < M) && (i < N)) {
	if ((text[i] == pat[j]) ||
	    (casemap && (toupper(text[i]) == toupper(pat[j])))) {
	    i++; j++;
	} else {
	    i = i - j + 1;
	    j = 0;
	}
    }    

    return (j == M); /* we found a match! */
}

static int octet_contains(const char *text, size_t tlen, const char *pat,
                          void *rock __attribute__((unused)))
{
    return octet_contains_(text, tlen, pat, 0);
}

static int octet_matches_(const char *text, size_t tlen,
			  const char *pat, int casemap)
{
    const char *p;
    const char *t;
    char c;

    t = text;
    p = pat;
    for (;;) {
	if (*p == '\0') {
	    /* ran out of pattern */
	    return (!tlen);
	}
	c = *p++;
	switch (c) {
	case '?':
	    if (!tlen) {
		return 0;
	    }
	    t++; tlen--;
	    break;
	case '*':
	    while (*p == '*' || *p == '?') {
		if (*p == '?') {
		    /* eat the character now */
		    if (!tlen) {
			return 0;
		    }
		    t++; tlen--;
		}
		/* coalesce into a single wildcard */
		p++;
	    }
	    if (*p == '\0') {
		/* wildcard at end of string, any remaining text is ok */
		return 1;
	    }

	    while (tlen) {
		/* recurse */
		if (octet_matches_(t, tlen, p, casemap)) return 1;
		t++; tlen--;
	    }
	case '\\':
	    c = *p++;
	    /* falls through */
	default:
	    if ((c == *t) || (casemap && (toupper(c) == toupper(*t)))) {
		t++; tlen--;
	    } else {
		/* literal char doesn't match */
		return 0;
	    }
	}
    }

    /* never reaches */
}

static int octet_matches(const char *text, size_t tlen, const char *pat, 
                         void *rock __attribute__((unused)))
{
    return octet_matches_(text, tlen, pat, 0);
}


#ifdef ENABLE_REGEX
static int octet_regex(const char *text, size_t tlen, const char *pat,
                       void *rock __attribute__((unused)))
{
    int r;

#ifdef REG_STARTEND
    /* pcre, BSD, some linuxes support this handy trick */
    regmatch_t pm[1];

    pm[0].rm_so = 0;
    pm[0].rm_eo = tlen;
    r = !regexec((regex_t *) pat, text, 0, pm, REG_STARTEND);
#else
#ifdef HAVE_RX_POSIX_H
    /* rx provides regnexec, that will work too */
    r = !regnexec((regex_t *) pat, text, tlen, 0, NULL, 0);
#else
    /* regexec() requires a NUL-terminated string, and we have no
     * guarantee that "text" is one.  Also, it may be only exactly
     * tlen's length, so we can't safely check.  Always dup. */
    char *buf = (char *) xstrndup(text, tlen);
    r = !regexec((regex_t *) pat, buf, 0, NULL, 0);
    free(buf);
#endif /* HAVE_RX_POSIX_H */
#endif /* REG_STARTEND */

    return r;
}
#endif


/* --- i;ascii-casemap comparators --- */


static int ascii_casemap_cmp(const char *text, size_t tlen, const char *pat)
{
    return octet_cmp_(text, tlen, pat, 1);
}

static int ascii_casemap_contains(const char *text, size_t tlen,
				  const char *pat,
				  void *rock __attribute__((unused)))
{
    return octet_contains_(text, tlen, pat, 1);
}

static int ascii_casemap_matches(const char *text, size_t tlen,
				 const char *pat, 
                                 void *rock __attribute__((unused)))
{
    return octet_matches_(text, tlen, pat, 1);
}

/* i;ascii-numeric; only supports relational tests
 *
 *  A \ B    number   not-num 
 *  number   A ? B    A < B 
 *  not-num  A > B    A == B
 */

/* From RFC 2244:
 *
 * The i;ascii-numeric comparator interprets strings as decimal
 * positive integers represented as US-ASCII digits.  All values
 * which do not begin with a US-ASCII digit are considered equal
 * with an ordinal value higher than all non-NIL single-valued
 * attributes.  Otherwise, all US-ASCII digits (octet values
 * 0x30 to 0x39) are interpreted starting from the beginning of
 * the string to the first non-digit or the end of the string.
 */

static int ascii_numeric_cmp(const char *text, size_t tlen, const char *pat)
{
    unsigned text_digit_len;
    unsigned pat_digit_len;

    if (Uisdigit(*pat)) {
	if (Uisdigit(*text)) {
	    /* Count how many digits each string has */
	    for (text_digit_len = 0;
		 tlen-- && Uisdigit(text[text_digit_len]);
		 text_digit_len++);
	    for (pat_digit_len = 0;
		 Uisdigit(pat[pat_digit_len]);
		 pat_digit_len++);

	    if (text_digit_len < pat_digit_len) {
		/* Pad "text" with leading 0s */
		while (pat_digit_len > text_digit_len) {
		    /* "text" can only be less or equal to "pat" */
		    if ('0' < *pat) {
			return (-1); 
		    }
		    pat++;
		    pat_digit_len--;
		}
	    } else if (text_digit_len > pat_digit_len) {
		/* Pad "pad" with leading 0s */
		while (text_digit_len > pat_digit_len) {
		    /* "pad" can only be greater or equal to "text" */
		    if (*text > '0') {
			return 1;
		    }
		    text++;
		    text_digit_len--;
		}
	    }

	    /* CLAIM: If we here, we have two non-empty digital suffixes
	       of equal length */
	    while (text_digit_len > 0) {
		if (*text < *pat) {
		    return -1;
		} else if (*text > *pat) {
		    return 1;
		}
		/* Characters are equal, carry on */
		text++;
		pat++;
		text_digit_len--;
	    }

	    return (0);
	} else {
	    return 1;
	}
    } else if (Uisdigit(*text)) {
	return -1;
    } else {
	return 0; /* both not digits */
    }
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
	    *comprock = (void **) &ascii_casemap_cmp;
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
	    *comprock = (void **) &ascii_casemap_cmp;
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
