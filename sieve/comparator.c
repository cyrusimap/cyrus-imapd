/* comparator.c -- comparator functions
 * Larry Greenfield
 * $Id: comparator.c,v 1.7 2000/12/18 04:53:42 leg Exp $
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
#include <fnmatch.h>

#include "comparator.h"
#include "tree.h"
#include "sieve.h"

/* --- i;octet comparators --- */

/* just compare the two; these should be NULL terminated */
static int octet_is(const char *pat, const char *text)
{
    int sl;
    sl = strlen(pat);

    return (sl == strlen(text)) && !memcmp(pat, text, sl);
}

/* we implement boyer-moore for hell of it, since this is probably
 not very useful for sieve */
#if 0
int boyer_moore(char *pat, char *text)
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
static int octet_contains(const char *pat, const char *text)
{
    return (strstr(text, pat) != NULL);
}

static int octet_matches(const char *pat, const char *text)
{
    return !fnmatch(pat, text, 0);
}

#ifdef ENABLE_REGEX
static int octet_regex(const char *pat, const char *text)
{
    return (!regexec((regex_t *) pat, text, 0, NULL, 0));
}
#endif


/* --- i;ascii-casemap comparators --- */

static int ascii_casemap_is(const char *pat, const char *text)
{
    int sl;
    sl = strlen(pat);

    return (sl == strlen(text)) && !strncasecmp(pat, text, sl);
}

/* sheer brute force */
static int ascii_casemap_contains(const char *pat, const char *text)
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

static int ascii_casemap_matches(const char *pat, const char *text)
{
    int ret;
    char *p, *t;
    int i;

    /* sigh, i'll just make local copies of these guys */
    p = strdup(pat); t = strdup(text);
    for (i = 0; p[i] != '\0'; i++)
	p[i] = toupper(p[i]);
    for (i = 0; t[i] != '\0'; i++)
	t[i] = toupper(t[i]);

    ret = !fnmatch(p, t, 0);
    free(p); free(t);

    return ret;
}

/* i;ascii-numeric; only supports "is"
 equality: numerically equal, or both not numbers */
static int ascii_numeric_is(const char *pat, const char *text)
{
    if (isdigit((int) *pat)) {
	if (isdigit((int) *text)) {
	    return (atoi(pat) == atoi(text));
	} else {
	    return 0;
	}
    } else if (isdigit((int) *text)) return 0;
    else return 1; /* both not digits */
}

comparator_t *lookup_comp(const char *comp, int mode)
{
    comparator_t *ret;

    ret = NULL;
    if (!strcmp(comp, "i;octet")) {
	switch (mode) {
	case IS:
	    ret = &octet_is;
	    break;
	case CONTAINS:
	    ret = &octet_contains;
	    break;
	case MATCHES:
	    ret = &octet_matches;
	    break;
#ifdef ENABLE_REGEX
	case REGEX:
	    ret = &octet_regex;
	    break;
#endif
	}
    } else if (!strcmp(comp, "i;ascii-casemap")) {
	switch (mode) {
	case IS:
	    ret = &ascii_casemap_is;
	    break;
	case CONTAINS:
	    ret = &ascii_casemap_contains;
	    break;
	case MATCHES:
	    ret = &ascii_casemap_matches;
	    break;
#ifdef ENABLE_REGEX
	case REGEX:
	    /* the ascii-casemap destinction is made during
	       the compilation of the regex in verify_regex() */
	    ret = &octet_regex;
	    break;
#endif
	}
    } else if (!strcmp(comp, "i;ascii-numeric")) {
	switch (mode) {
	case IS:
	    ret = &ascii_numeric_is;
	    break;
	}
    }
    return ret;
}
