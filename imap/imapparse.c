/* 
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
 */

/* $Id: imapparse.c,v 1.11 2003/02/13 20:15:25 rjs3 Exp $ */

#include <config.h>

#include <ctype.h>
#include <string.h>
#include <limits.h>

#include "prot.h"
#include "xmalloc.h"
#include "imapconf.h"
#include "exitcodes.h"

enum {
    MAXQUOTED = 8192,
    MAXWORD = 8192,
    MAXLITERAL = INT_MAX / 20
};

void freebuf(struct buf *buf)
{
    if (buf->s) {
	free(buf->s);
	buf->s = NULL;
    }
    buf->len = 0;
    buf->alloc = 0;
}

/*
 * Parse a word
 * (token not containing whitespace, parens, or double quotes)
 */
#define BUFGROWSIZE 100
int getword(struct protstream *in, struct buf *buf)
{
    int c;
    int len = 0;

    if (buf->alloc == 0) {
	buf->alloc = BUFGROWSIZE;
	buf->s = xmalloc(buf->alloc+1);
    }
	
    for (;;) {
	c = prot_getc(in);
	if (c == EOF || isspace(c) || c == '(' || c == ')' || c == '\"') {
	    buf->s[len] = '\0';
	    buf->len = len;
	    return c;
	}
	if (len == buf->alloc) {
            /* xxx limit len */
	    buf->alloc += BUFGROWSIZE;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
            if (len > MAXWORD) {
                fatal("word too long", EC_IOERR);
            }
	}
	buf->s[len++] = c;
    }
}

/*
 * Parse an xstring
 * (astring, nstring or string based on type)
 */
int getxstring(struct protstream *pin, struct protstream *pout,
	       struct buf *buf, int type)
{
    int c;
    int i;
    int len = 0;
    int sawdigit = 0;
    int isnowait;

    if (buf->alloc == 0) {
	buf->alloc = BUFGROWSIZE;
	buf->s = xmalloc(buf->alloc+1);
    }
	
    c = prot_getc(pin);
    switch (c) {
    case EOF:
    case ' ':
    case '(':
    case ')':
    case '\r':
    case '\n':
	/* Invalid starting character */
	buf->s[0] = '\0';
	buf->len = 0;
	if (c != EOF) prot_ungetc(c, pin);
	return EOF;

    case '\"':
	/*
	 * Quoted-string.  Server is liberal in accepting qspecials
	 * other than double-quote, CR, and LF.
	 */
	for (;;) {
	    c = prot_getc(pin);
	    if (c == '\\') {
		c = prot_getc(pin);
	    }
	    else if (c == '\"') {
		buf->s[len] = '\0';
		buf->len = len;
		return prot_getc(pin);
	    }
	    else if (c == EOF || c == '\r' || c == '\n') {
		buf->s[len] = '\0';
		buf->len = len;
		if (c != EOF) prot_ungetc(c, pin);
		return EOF;
	    }
	    if (len == buf->alloc) {
		buf->alloc += BUFGROWSIZE;
		buf->s = xrealloc(buf->s, buf->alloc+1);

                if (len > MAXQUOTED) {
                    fatal("word too long", EC_IOERR);
                }
	    }
	    buf->s[len++] = c;
	}

    case '{':
	if (type == IMAP_QSTRING) {
	    /* Invalid starting character */
	    buf->s[0] = '\0';
	    buf->len = 0;
	    if (c != EOF) prot_ungetc(c, pin);
	    return EOF;
	}

	/* Literal */
	isnowait = 0;
	buf->s[0] = '\0';
	while ((c = prot_getc(pin)) != EOF && isdigit(c)) {
	    sawdigit = 1;
	    len = len*10 + c - '0';
            if (len > MAXLITERAL || len < 0) {
                /* we overflowed */
                fatal("literal too big", EC_IOERR);
            }
	}
	if (c == '+') {
	    isnowait++;
	    c = prot_getc(pin);
	}
	if (!sawdigit || c != '}') {
	    if (c != EOF) prot_ungetc(c, pin);
	    return EOF;
	}
	c = prot_getc(pin);
	if (c != '\r') {
	    if (c != EOF) prot_ungetc(c, pin);
	    return EOF;
	}
	c = prot_getc(pin);
	if (c != '\n') {
	    if (c != EOF) prot_ungetc(c, pin);
	    return EOF;
	}
        /* xxx limit len */

	if (len >= buf->alloc) {
	    buf->alloc = len+1;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
	}
	if (!isnowait) {
	    prot_printf(pout, "+ go ahead\r\n");
	    prot_flush(pout);
	}
	for (i = 0; i < len; i++) {
	    c = prot_getc(pin);
	    if (c == EOF) {
		buf->s[len] = '\0';
		buf->len = len;
		return EOF;
	    }
	    buf->s[i] = c;
	}
	buf->s[len] = '\0';
	buf->len = len;
	if (type != IMAP_BIN_ASTRING && strlen(buf->s) != len)
	    return EOF; /* Disallow imbedded NUL for non IMAP_BIN_ASTRING */
	return prot_getc(pin);

    default:
	switch (type) {
	case IMAP_BIN_ASTRING:   /* binary-allowed ASTRING */
	case IMAP_ASTRING:	 /* atom, quoted-string or literal */
	    /*
	     * Atom -- server is liberal in accepting specials other
	     * than whitespace, parens, or double quotes
	     */
	    for (;;) {
		if (c == EOF || isspace(c) || c == '(' || 
		          c == ')' || c == '\"') {
		    buf->s[len] = '\0';
		    buf->len = len;
		    return c;
		}
		if (len == buf->alloc) {
		    buf->alloc += BUFGROWSIZE;
		    buf->s = xrealloc(buf->s, buf->alloc+1);
                    /* xxx limit size of atoms */
		}
		buf->s[len++] = c;
		c = prot_getc(pin);
	    }
            /* never gets here */
	    break;

	case IMAP_NSTRING:	 /* "NIL", quoted-string or literal */
	    /*
	     * Look for "NIL"
	     */
	    if (c == 'N') {
		prot_ungetc(c, pin);
		c = getword(pin, buf);
		if (!strcmp(buf->s, "NIL"))
		    return c;
	    }
	    if (c != EOF) prot_ungetc(c, pin);
	    return EOF;
	    break;

	case IMAP_QSTRING:	 /* quoted-string */
	case IMAP_STRING:	 /* quoted-string or literal */
            /* atoms aren't acceptable */
            if (c != EOF) prot_ungetc(c, pin);
            return EOF;
	    break;
	}
    }

    return EOF;
}

/*
 * Eat characters up to and including the next newline
 * Also look for and eat non-synchronizing literals.
 */
void eatline(struct protstream *pin, int c)
{
    int state = 0;
    char *statediagram = " {+}\r";
    int size = -1;

    for (;;) {
	if (c == '\n') return;
	if (c == statediagram[state+1]) {
	    state++;
	    if (state == 1) size = 0;
	    else if (c == '\r') {
		/* Got a non-synchronizing literal */
		c = prot_getc(pin);/* Eat newline */
		while (size--) {
		    c = prot_getc(pin); /* Eat contents */
		}
		state = 0;	/* Go back to scanning for eol */
	    }
	}
	else if (state == 1 && isdigit(c)) {
	    size = size * 10 + c - '0';
	}
	else state = 0;

	c = prot_getc(pin);
	if (c == EOF) return;
    }
}
