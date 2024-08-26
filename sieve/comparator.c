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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "comparator.h"
#include "charset.h"
#include "interp.h"
#include "tree.h"
#include "sieve/sieve_interface.h"
#include "sieve/sieve.h"
#include "bytecode.h"
#include "util.h"
#include "xmalloc.h"

/*!!! uses B_CONTAINS not CONTAINS, etc, only works with bytecode*/

typedef int (*compare_t)(const void *, size_t, const void *);

/* --- relational comparators --- */

/* these are generic wrappers in which 'rock' is the compare function */

static int rel_eq(const char *text, size_t tlen, const char *pat,
                  strarray_t *match_vars __attribute__((unused)),
                  void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, tlen, pat) == 0);
}

static int rel_ne(const char *text, size_t tlen, const char *pat,
                  strarray_t *match_vars __attribute__((unused)),
                  void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, tlen, pat) != 0);
}

static int rel_gt(const char *text, size_t tlen, const char *pat,
                  strarray_t *match_vars __attribute__((unused)),
                  void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, tlen, pat) > 0);
}

static int rel_ge(const char *text, size_t tlen, const char *pat,
                  strarray_t *match_vars __attribute__((unused)),
                  void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, tlen, pat) >= 0);
}

static int rel_lt(const char *text, size_t tlen, const char *pat,
                  strarray_t *match_vars __attribute__((unused)),
                  void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, tlen, pat) < 0);
}

static int rel_le(const char *text, size_t tlen, const char *pat,
                  strarray_t *match_vars __attribute__((unused)),
                  void *rock)
{
    compare_t compar = (compare_t) rock;

    return (compar(text, tlen, pat) <= 0);
}


/* --- i;octet comparators (RFC 4790, Section 9.3) --- */

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

/* we do a brute force attack */
static int octet_contains_(const char *text, size_t tlen,
                           const char *pat, int casemap)
{
    int N = tlen;
    int M = strlen(pat);
    int i = 0, j = 0;

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
                          strarray_t *match_vars __attribute__((unused)),
                          void *rock __attribute__((unused)))
{
    return octet_contains_(text, tlen, pat, 0);
}

static int new_var(strarray_t *match_vars)
{
    int size = strarray_size(match_vars);

    if (size-1 > MAX_MATCH_VARS) return size;

    return strarray_append(match_vars, "");
}

static void set_var(int var_num, const char* val_start, const char* val_end,
                    strarray_t *match_vars)
{
    if (var_num > MAX_MATCH_VARS) return;

    char *val = xstrndup(val_start, val_end - val_start);
    strarray_setm(match_vars, var_num, val);
}

static int append_var(const char* val_start, const char* val_end,
                       strarray_t *match_vars)
{
    int size = strarray_size(match_vars);

    if (size-1 > MAX_MATCH_VARS) return size;

    char *val = xstrndup(val_start, val_end - val_start);
    return strarray_appendm(match_vars, val);
}

static int octet_matches_(const char *text, size_t tlen,
                          const char *pat, int casemap, strarray_t *match_vars)
{
    const char *p;
    const char *t;
    char c;
    int var_num;
    int eaten_chars = 0;
    const char *val_start = text;
    strarray_t returned_vars = STRARRAY_INITIALIZER;

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
            var_num = new_var(match_vars);
            val_start = t;
            if (!tlen) {
                return 0;
            }
            t++; tlen--;
            set_var(var_num, val_start, t, match_vars);
            break;
        case '*':
            var_num = new_var(match_vars);
            val_start = t;
            while (*p == '*' || *p == '?') {
                if (*p == '?') {
                    /* eat the character now */
                    if (!tlen) {
                        return 0;
                    }
                    t++; tlen--; eaten_chars++;
                } else {
                    for (t -= eaten_chars; eaten_chars; eaten_chars--) {
                        t++;
                        var_num = append_var(val_start, t, match_vars);
                        val_start = t;
                    }
                    var_num = new_var(match_vars);
                    val_start = t;
                }
                /* coalesce into a single wildcard */
                p++;
            }
            if (*p == '\0') {
                /* wildcard at end of string, any remaining text is ok */
                t += tlen;
                t -= eaten_chars;
                set_var(var_num, val_start, t, match_vars);
                for (val_start = t; eaten_chars; eaten_chars--) {
                    t++;
                    var_num = append_var(val_start, t, match_vars);
                    val_start = t;
                }
                return 1;
            }

            while (tlen) {
                /* recurse */
                if (octet_matches_(t, tlen, p, casemap, &returned_vars)) {
                    int i;
                    t -= eaten_chars;
                    set_var(var_num, val_start, t, match_vars);
                    for (val_start = t; eaten_chars; eaten_chars--) {
                        t++;
                        var_num = append_var(val_start, t, match_vars);
                        val_start = t;
                    }
                    for (i = 0; i < returned_vars.count; i++) {
                        if (var_num < MAX_MATCH_VARS) {
                            var_num = strarray_append(match_vars,
                                                      returned_vars.data[i]);
                        }
                    }
                    strarray_fini(&returned_vars);
                    return 1;
                }
                strarray_fini(&returned_vars);
                t++; tlen--;
            }
            set_var(var_num, val_start, t, match_vars);
            break;
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

static int octet_matches_exec(const char *text, size_t tlen,
                              const char *pat, int casemap,
                              strarray_t *match_vars)
{
    int ret;
    int needs_free = 0;
    strarray_t temp = STRARRAY_INITIALIZER;
    if (match_vars) {
        strarray_fini(match_vars);
    } else {
        match_vars = &temp;
        needs_free = 1;
    }
    strarray_add(match_vars, text);
    ret = octet_matches_(text, tlen, pat, casemap, match_vars);
    if (!ret || needs_free) {
        strarray_fini(match_vars);
    }
    return ret;
}

static int octet_matches(const char *text, size_t tlen, const char *pat,
                         strarray_t *match_vars,
                         void *rock __attribute__((unused)))
{
    return octet_matches_exec(text, tlen, pat, 0, match_vars);
}


#ifdef ENABLE_REGEX
static int octet_regex(const char *text, size_t tlen, const char *pat,
                       strarray_t *match_vars,
                       void *rock __attribute__((unused)))
{
    regmatch_t pm[MAX_MATCH_VARS+1];
    size_t nmatch = 0;
    int r;

    if (match_vars) {
        strarray_fini(match_vars);
        nmatch = MAX_MATCH_VARS+1;
        memset(&pm, 0, sizeof(pm));
    }

#ifdef REG_STARTEND
    /* pcre, BSD, some linuxes support this handy trick */
    pm[0].rm_so = 0;
    pm[0].rm_eo = tlen;
    r = !regexec((regex_t *) pat, text, nmatch, pm, REG_STARTEND);
#elif defined(HAVE_RX_POSIX_H)
    /* rx provides regnexec, that will work too */
    r = !regnexec((regex_t *) pat, text, tlen, nmatch, pm, 0);
#else
    /* regexec() requires a NUL-terminated string, and we have no
     * guarantee that "text" is one.  Also, it may be only exactly
     * tlen's length, so we can't safely check.  Always dup. */
    char *buf = (char *) xstrndup(text, tlen);
    r = !regexec((regex_t *) pat, buf, nmatch, pm, 0);
    free(buf);
#endif /* REG_STARTEND */

    if (r) {
        /* populate match variables */
        size_t var_num;

        for (var_num = 0; var_num < nmatch; var_num++) {
            regmatch_t *m = &pm[var_num];

            if (m->rm_so < 0) new_var(match_vars);
            else append_var(text + m->rm_so, text + m->rm_eo, match_vars);
        }
    }
    return r;
}
#endif


/* --- i;ascii-casemap comparators (RFC 4790, Section 9.2) --- */

static int ascii_casemap_cmp(const char *text, size_t tlen, const char *pat)
{
    return octet_cmp_(text, tlen, pat, 1);
}

static int ascii_casemap_contains(const char *text, size_t tlen,
                                  const char *pat,
                                  strarray_t *match_vars __attribute__((unused)),
                                  void *rock __attribute__((unused)))
{
    return octet_contains_(text, tlen, pat, 1);
}

static int ascii_casemap_matches(const char *text, size_t tlen,
                                 const char *pat, strarray_t *match_vars,
                                 void *rock __attribute__((unused)))
{
    return octet_matches_exec(text, tlen, pat, 1, match_vars);
}


/* --- i;ascii-numeric comparator (RFC 4790, Section 9.1) --- */

/* only supports relational tests; pat should be NULL terminated
 *
 *  A \ B    number   not-num
 *  number   A ? B    A < B
 *  not-num  A > B    A == B
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
            pat_digit_len = strspn(pat, "0123456789");

            unsigned num_digits = MAX(text_digit_len, pat_digit_len);
            int r;

            do {
                /* Pad the shorter string with leading 0s */
                const char t = text_digit_len < num_digits ? '0' : *text++;
                const char p =  pat_digit_len < num_digits ? '0' : *pat++;

                r = t - p;

            } while (!r && --num_digits);

            return r;
        } else {
            return 1;
        }
    } else if (Uisdigit(*text)) {
        return -1;
    } else {
        return 0; /* both not digits */
    }
}


/* --- i;unicode-casemap comparators (RFC 5051, Section 2) --- */

static int unicode_casemap_xxx(const char *text, size_t tlen, const char *pat,
                               strarray_t *match_vars, void *rock)
{
    char *uni = unicode_casemap(text, tlen);
    long mode = (long) rock;
    int r;

    switch (mode) {
    case B_CONTAINS:
        r = octet_contains_(uni, strlen(uni), pat, 0);
        break;

    case B_MATCHES:
        r = octet_matches_exec(uni, strlen(uni), pat, 0, match_vars);
        break;

#ifdef ENABLE_REGEX
    case B_REGEX:
        r = octet_regex(uni, strlen(uni), pat, match_vars, NULL);
        break;
#endif

    default:
        r = octet_cmp_(uni, strlen(uni), pat, 0);
        break;
    }

    free(uni);

    return r;
}

static int unicode_casemap_cmp(const char *text, size_t tlen, const char *pat)
{
    return unicode_casemap_xxx(text, tlen, pat, NULL, 0);
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

EXPORTED comparator_t *lookup_comp(sieve_interp_t *i, int comp, int mode,
                                   int relation, void **comprock)
{
    comparator_t *ret;

    ret = NULL;
    *comprock = NULL;
#if VERBOSE
    printf("comp%d mode%d relat%d     \n", comp, mode, relation);
#endif
    if (mode == B_LIST) {
        *comprock = (void **) i->interp_context;
        return (comparator_t *) i->listcompare;
    }
    else if (mode == B_IS) {
        relation = B_EQ;
    }

    switch (comp) {
    case B_OCTET:
        switch (mode) {
        case B_IS:
        case B_VALUE:
            ret = lookup_rel(relation);
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
        }
        break;

    case B_ASCIICASEMAP:
        switch (mode) {
        case B_IS:
        case B_VALUE:
            ret = lookup_rel(relation);
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
            /* the ascii-casemap distinction is made during
               the compilation of the regex in verify_regex() */
            ret = &octet_regex;
            break;
#endif
        }
        break;

    case B_ASCIINUMERIC:
        ret = lookup_rel(relation);
        *comprock = (void **) &ascii_numeric_cmp;
        break;

    case B_UNICODECASEMAP:
        switch (mode) {
        case B_IS:
        case B_VALUE:
            ret = lookup_rel(relation);
            *comprock = (void **) &unicode_casemap_cmp;
            break;

        default:
            ret = &unicode_casemap_xxx;
            *comprock = (void *) ((long) mode);
            break;
        }
        break;
    }

    return ret;
}
