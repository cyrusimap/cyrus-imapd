/* imparse.c -- IMxP client-side parsing routines
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */
#include <stdio.h>
#include <ctype.h>

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
    int sawdigit;

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
	while (isdigit(c = *(*s)++)) {
	    sawdigit = 1;
	    len = len*10 + c - '0';
	}
	if (!sawdigit || c != '}' || *(*s)++ != '\r' || *(*s)++ != '\n') {
	    *retval = "";
	    return EOF;
	}
	*retval = *s;
	c = (*s)[len];
	(*s)[len] = '\0';
	return c;
    }
}
