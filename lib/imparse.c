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
#include <string.h>

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
 * On failure, returns EOF, sets the pointer at 'retval' to NULL,
 * and modifies 's' to point around the syntax error.
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
        *retval = NULL;
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
                *retval = NULL;
                return EOF;
            }
            *d++ = c;
        }

    case '{':
        /* Literal */
        (*s)++;
        while (Uisdigit(c = *(*s)++)) {
            sawdigit = 1;
            len = len * 10 + c - '0';
        }
        if (!sawdigit || c != '}' || *(*s)++ != '\r' || *(*s)++ != '\n') {
            *retval = NULL;
            return EOF;
        }
        *retval = *s;
        *s += len;
        c = **s;
        *(*s)++ = '\0'; /* Note that 0 and '\0' mean the same thing */
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

    if (!*s) {
        return 0;
    }
    for (; len || *s; s++) {
        count++;
        if (len && count > len) {
            break;
        }
        if (*s & 0x80 || *s <= 0x1f || *s == 0x7f || *s == ' ' || *s == '{'
            || *s == '(' || *s == ')' || *s == '\"' || *s == '%' || *s == '*'
            || *s == '\\')
        {
            return 0;
        }
    }
    if (count >= 1024) {
        return 0;
    }
    return count;
}

EXPORTED int imparse_isatom(const char *s)
{
    return imparse_isnatom(s, 0);
}

/*
 * Return nonzero if 's' matches the grammar for a sequence
 */
EXPORTED int imparse_issequence(const char *s)
{
    int c;
    int len = 0;
    int sawcolon = 0;

    while ((c = *s)) {
        if (c == ',') {
            if (!len) {
                return 0;
            }
            if (!Uisdigit(s[-1]) && s[-1] != '*') {
                return 0;
            }
            sawcolon = 0;
        }
        else if (c == ':') {
            if (sawcolon || !len) {
                return 0;
            }
            if (!Uisdigit(s[-1]) && s[-1] != '*') {
                return 0;
            }
            sawcolon = 1;
        }
        else if (c == '*') {
            if (len && s[-1] != ',' && s[-1] != ':') {
                return 0;
            }
            if (Uisdigit(s[1])) {
                return 0;
            }
        }
        else if (!Uisdigit(c)) {
            return 0;
        }
        s++;
        len++;
    }
    if (len == 0) {
        return 0;
    }
    if (!Uisdigit(s[-1]) && s[-1] != '*') {
        return 0;
    }
    return 1;
}

/*
 * Return nonzero if 's' matches the grammar for a number
 */
EXPORTED int imparse_isnumber(const char *s)
{
    if (!*s) {
        return 0;
    }
    for (; *s; s++) {
        if (!Uisdigit(*s)) {
            return 0;
        }
    }
    return 1;
}

static int reject_http_method_tag(const char *s)
{
    /* Don't like tags that match HTTP methods that accept a request body!
     * Keep this up to date with http_methods[] in httpd.c
     * and test_istag() in imparse.testc
     */
    switch (s[0]) {
    case 'A':
        if (0 == strcmp(s, "ACL")) {
            return 1;
        }
        break;
    case 'B':
        if (0 == strcmp(s, "BIND")) {
            return 1;
        }
        break;
    case 'L':
        if (0 == strcmp(s, "LOCK")) {
            return 1;
        }
        break;
    case 'M':
        if (0 == strcmp(s, "MKCALENDAR")) {
            return 1;
        }
        else if (0 == strcmp(s, "MKCOL")) {
            return 1;
        }
        break;
    case 'P':
        if (0 == strcmp(s, "PATCH")) {
            return 1;
        }
        else if (0 == strcmp(s, "POST")) {
            return 1;
        }
        else if (0 == strcmp(s, "PROPFIND")) {
            return 1;
        }
        else if (0 == strcmp(s, "PROPPATCH")) {
            return 1;
        }
        else if (0 == strcmp(s, "PUT")) {
            return 1;
        }
        break;
    case 'R':
        if (0 == strcmp(s, "REPORT")) {
            return 1;
        }
        break;
    case 'S':
        if (0 == strcmp(s, "SEARCH")) {
            return 1;
        }
        break;
    case 'U':
        if (0 == strcmp(s, "UNBIND")) {
            return 1;
        }
        break;
    }

    return 0;
}

/*
 * Return nonzero if we like 's' as an IMAP tag
 */
EXPORTED int imparse_istag(const char *s, unsigned command_count)
{
    static const char reject[] = {
        /*       0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F */
        /* 0_ */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        /* 1_ */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        /* 2_ */ 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0,
        /* 3_ */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0,
        /* 4_ */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 5_ */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        /* 6_ */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 7_ */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1,
    };
    const unsigned char *p;

    if (!s || !*s) {
        return 0;
    }

    for (p = (const unsigned char *) s; p && *p; p++) {
        if ((*p & 0x80) || reject[*p]) {
            return 0;
        }
    }

    if (command_count == 0 && reject_http_method_tag(s)) {
        return 0;
    }

    return 1;
}

/*
 * Parse a range from the string starting at the pointer pointed to by 's'.
 * and populate the structure in the pointer at 'range'.
 * Returns 0 on success, and non-zero on failure.
 */
EXPORTED int imparse_range(const char *s, range_t *range)
{
    char *rem;

    if (*s == '-') {
        range->is_last = 1;
        s++;
    }
    if (!Uisdigit(*s)) {
        return -1;
    }

    errno = 0;
    range->low = strtoul(s, &rem, 10);
    if (!range->low || range->low > UINT32_MAX || errno || *rem != ':') {
        errno = 0;
        return -1;
    }
    s = rem;

    if (*++s == '-') {
        if (!range->is_last) {
            return -1;
        }
        s++;
    }
    if (!Uisdigit(*s)) {
        return -1;
    }

    range->high = strtoul(s, &rem, 10);
    if (!range->high || range->high > UINT32_MAX || errno || *rem) {
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
