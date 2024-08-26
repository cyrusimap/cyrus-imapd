/* imparse.c -- IMxP client-side parsing routines
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

#include <config.h>
#include <errno.h>
#include <stdio.h>

#include "imparse.h"
#include "util.h"

/*
 * Parse a word from the string starting at the pointer pointed to by 's'.
 * Places a pointer to the parsed word in the pointer at 'retval',
 * returns the character following the word, and modifies the pointer at
 * 's' to point after the returned character.  Modifies the input buffer.
 */
EXPORTED int imparse_word(char **s, char **retval)
{
    int c;

    *retval = *s;
    for (;;) {
        c = *(*s)++;
        if (!c || Uisspace(c) || c == '(' || c == ')' || c == '\"') {
            (*s)[-1] = '\0';
            return c;
        }
    }
}

/*
 * Parse an astring from the string starting at the pointer pointed to
 * by 's'.  On success, places a pointer to the parsed word in the
 * pointer at 'retval', returns the character following the word, and
 * modifies the pointer at 's' to point after the returned character.
 * On failure, returns EOF, modifies the pointer at 'retval' to point
 * at the empty string, and modifies 's' to point around the syntax error.
 * Modifies the input buffer.
 */
EXPORTED int imparse_astring(char **s, char **retval)
{
    int c;
    char *d;
    int len = 0;
    int sawdigit = 0;

    switch (**s) {
    case '\0':
    case ' ':
    case '(':
    case ')':
    case '\r':
    case '\n':
        /* Invalid starting character */
        *retval = "";
        return EOF;

    default:
        /*
         * Atom -- parser is liberal in accepting specials other
         * than whitespace, parens, or double quotes
         */
        return imparse_word(s, retval);

    case '\"':
        /*
         * Quoted-string.  Parser is liberal in accepting qspecials
         * other than double-quote, CR, and LF.
         */
        *retval = d = ++(*s);
        for (;;) {
            c = *(*s)++;
            if (c == '\\') {
                c = *(*s)++;
            }
            else if (c == '\"') {
                *d = '\0';
                return *(*s)++;
            }
            else if (c == '\0' || c == '\r' || c == '\n') {
                *retval = "";
                return EOF;
            }
            *d++ = c;
        }

    case '{':
        /* Literal */
        (*s)++;
        while (Uisdigit(c = *(*s)++)) {
            sawdigit = 1;
            len = len*10 + c - '0';
        }
        if (!sawdigit || c != '}' || *(*s)++ != '\r' || *(*s)++ != '\n') {
            *retval = "";
            return EOF;
        }
        *retval = *s;
        *s += len;
        c = **s;
        *(*s)++ = '\0';  /* Note that 0 and '\0' mean the same thing */
        return c;
    }
}

/*
 * Return nonzero if 's' matches the grammar for an atom.  If 'len' is
 * zero then treat as a c string, \0 delimited.  Otherwise check the
 * entire map, and consider not an natom if there's a NULL byte in the
 * mapped space.
 */
EXPORTED int imparse_isnatom(const char *s, int len)
{
    int count = 0;

    if (!*s) return 0;
    for (; len || *s; s++) {
        count++;
        if (len && count > len) break;
        if (*s & 0x80 || *s < 0x1f || *s == 0x7f ||
            *s == ' ' || *s == '{' || *s == '(' || *s == ')' ||
            *s == '\"' || *s == '%' || *s == '*' || *s == '\\') return 0;
    }
    if (count >= 1024) return 0;
    return count;
}

EXPORTED int imparse_isatom(const char *s)
{
    return imparse_isnatom(s, 0);
}

/*
 * Return nonzero if 's' matches the grammar for a sequence
 */
EXPORTED int imparse_issequence(const char* s)
{
    int c;
    int len = 0;
    int sawcolon = 0;

    while ((c = *s)) {
        if (c == ',') {
            if (!len) return 0;
            if (!Uisdigit(s[-1]) && s[-1] != '*') return 0;
            sawcolon = 0;
        }
        else if (c == ':') {
            if (sawcolon || !len) return 0;
            if (!Uisdigit(s[-1]) && s[-1] != '*') return 0;
            sawcolon = 1;
        }
        else if (c == '*') {
            if (len && s[-1] != ',' && s[-1] != ':') return 0;
            if (Uisdigit(s[1])) return 0;
        }
        else if (!Uisdigit(c)) {
            return 0;
        }
        s++;
        len++;
    }
    if (len == 0) return 0;
    if (!Uisdigit(s[-1]) && s[-1] != '*') return 0;
    return 1;
}

/*
 * Return nonzero if 's' matches the grammar for a number
 */
EXPORTED int imparse_isnumber(const char *s)
{
    if (!*s) return 0;
    for (; *s; s++) {
        if (!Uisdigit(*s)) return 0;
    }
    return 1;
}

/*
 * Parse a range from the string starting at the pointer pointed to by 's'.
 * and populate the structure in the pointer at 'range'.
 * Returns 0 on success, and non-zero on failure.
 */
EXPORTED int imparse_range(char *s, range_t *range)
{
    if (*s == '-') {
        range->is_last = 1;
        s++;
    }
    if (!Uisdigit(*s)) return -1;

    errno = 0;
    range->low = strtoul(s, &s, 10);
    if (!range->low || range->low > UINT32_MAX || errno || *s != ':') {
        errno = 0;
        return -1;
    }

    if (*++s == '-') {
        if (!range->is_last) return -1;
        s++;
    }
    if (!Uisdigit(*s)) return -1;

    range->high = strtoul(s, &s, 10);
    if (!range->high || range->high > UINT32_MAX  || errno || *s) {
        errno = 0;
        return -1;
    }

    if (range->low > range->high) {
        unsigned long n = range->high;

        range->high = range->low;
        range->low = n;
    }

    return 0;
}
