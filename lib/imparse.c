/* imparse.c -- IMxP client-side parsing routines
 $Id: imparse.c,v 1.12 2003/02/13 20:15:40 rjs3 Exp $
 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *
 */
#include <config.h>
#include <stdio.h>
#include <ctype.h>

#include "imparse.h"

/*
 * Parse a word from the string starting at the pointer pointed to by 's'.
 * Places a pointer to the parsed word in the pointer at 'retval',
 * returns the character following the word, and modifies the pointer at
 * 's' to point after the returned character.  Modifies the input buffer.
 */
int imparse_word(s, retval)
char **s;
char **retval;
{
    int c;
    
    *retval = *s;
    for (;;) {
	c = *(*s)++;
	if (!c || isspace(c) || c == '(' || c == ')' || c == '\"') {
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
int imparse_astring(s, retval)
char **s;
char **retval;
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
        while (isdigit(c = *(*s)++)) {
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
 * Return nonzero if 's' matches the grammar for an atom
 */
int imparse_isatom(s)
const char *s;
{
    int len = 0;

    if (!*s) return 0;
    for (; *s; s++) {
	len++;
	if (*s & 0x80 || *s < 0x1f || *s == 0x7f ||
	    *s == ' ' || *s == '{' || *s == '(' || *s == ')' ||
	    *s == '\"' || *s == '%' || *s == '*' || *s == '\\') return 0;
    }
    if (len >= 1024) return 0;
    return 1;
}

/*
 * Return nonzero if 's' matches the grammar for a sequence
 */
int imparse_issequence(const char* s)
{
    int c;
    int len = 0;
    int sawcolon = 0;

    while ((c = *s)) {
	if (c == ',') {
	    if (!len) return 0;
	    if (!isdigit((int) s[-1]) && s[-1] != '*') return 0;
	    sawcolon = 0;
	}
	else if (c == ':') {
	    if (sawcolon || !len) return 0;
	    if (!isdigit((int) s[-1]) && s[-1] != '*') return 0;
	    sawcolon = 1;
	}
	else if (c == '*') {
	    if (len && s[-1] != ',' && s[-1] != ':') return 0;
	    if (isdigit((int) s[1])) return 0;
	}
	else if (!isdigit(c)) {
	    return 0;
	}
	s++;
	len++;
    }
    if (len == 0) return 0;
    if (!isdigit((int) s[-1]) && s[-1] != '*') return 0;
    return 1;
}

/*
 * Return nonzero if 's' matches the grammar for a number
 */
int imparse_isnumber(const char *s)
{
    if (!*s) return 0;
    for (; *s; s++) {
	if (!isdigit((int) *s)) return 0;
    }
    return 1;
}
