/* imparse.c -- IMxP client-side parsing routines
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */
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
int imparse_issequence(s)
const char *s;
{
    int c;
    int len = 0;
    int sawcolon = 0;

    while (c = *s) {
	if (c == ',') {
	    if (!len) return 0;
	    if (!isdigit(s[-1]) && s[-1] != '*') return 0;
	    sawcolon = 0;
	}
	else if (c == ':') {
	    if (sawcolon || !len) return 0;
	    if (!isdigit(s[-1]) && s[-1] != '*') return 0;
	    sawcolon = 1;
	}
	else if (c == '*') {
	    if (len && s[-1] != ',' && s[-1] != ':') return 0;
	    if (isdigit(s[1])) return 0;
	}
	else if (!isdigit(c)) {
	    return 0;
	}
	s++;
	len++;
    }
    if (len == 0) return 0;
    if (!isdigit(s[-1]) && s[-1] != '*') return 0;
    return 1;
}

/*
 * Return nonzero if 's' matches the grammar for a number
 */
int imparse_isnumber(s)
const char *s;
{
    if (!*s) return 0;
    for (; *s; s++) {
	if (!isdigit(*s)) return 0;
    }
    return 1;
}
