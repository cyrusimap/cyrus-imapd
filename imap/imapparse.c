/*
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
 * $Id: imapparse.c,v 1.20 2010/01/06 17:01:34 murch Exp $
 */

#include <config.h>

#include <ctype.h>
#include <string.h>
#include <limits.h>

#include "exitcodes.h"
#include "global.h"
#include "prot.h"
#include "util.h"
#include "xmalloc.h"

/*
 * Parse a word
 * (token not containing whitespace, parens, or double quotes)
 */
int getword(struct protstream *in, struct buf *buf)
{
    int c;

    buf_reset(buf);
    for (;;) {
	c = prot_getc(in);
	if (c == EOF || isspace(c) || c == '(' || c == ')' || c == '\"') {
	    buf_cstring(buf); /* appends a '\0' */
	    return c;
	}
	buf_putc(buf, c);
	if (config_maxword && buf_len(buf) > config_maxword) {
	    fatal("word too long", EC_IOERR);
	}
    }
}

/*
 * Parse an xstring
 * (astring, nstring or string based on type)
 */
int getxstring(struct protstream *pin, struct protstream *pout,
	       struct buf *buf, enum getxstring_flags flags)
{
    int c;
    int i;
    int isnowait;
    int len;

    buf_reset(buf);

    c = prot_getc(pin);
    switch (c) {
    case EOF:
    case ' ':
    case '(':
    case ')':
    case '\r':
    case '\n':
	/* Invalid starting character */
	goto fail;

    case '\"':
	if (!(flags & GXS_QUOTED)) {
	    /* Invalid starting character */
	    goto fail;
	}

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
		buf_cstring(buf);
		return prot_getc(pin);
	    }
	    else if (c == EOF || c == '\r' || c == '\n') {
		buf_cstring(buf);
		if (c != EOF) prot_ungetc(c, pin);
		return EOF;
	    }
	    buf_putc(buf, c);
	    if (config_maxquoted && buf_len(buf) > config_maxquoted) {
		fatal("quoted value too long", EC_IOERR);
	    }
	}

    case '{':
	if (!(flags & GXS_LITERAL)) {
	    /* Invalid starting character */
	    goto fail;
	}

	/* Literal */
	isnowait = pin->isclient;
	buf_reset(buf);
	c = getint32(pin, &len);
	if (c == '+') {
	    isnowait++;
	    c = prot_getc(pin);
	}
	if (len == -1 || c != '}') {
	    buf_cstring(buf);
	    if (c != EOF) prot_ungetc(c, pin);
	    return EOF;
	}
	c = prot_getc(pin);
	if (c != '\r') {
	    buf_cstring(buf);
	    if (c != EOF) prot_ungetc(c, pin);
	    return EOF;
	}
	c = prot_getc(pin);
	if (c != '\n') {
	    buf_cstring(buf);
	    if (c != EOF) prot_ungetc(c, pin);
	    return EOF;
	}

	if (!isnowait) {
	    prot_printf(pout, "+ go ahead\r\n");
	    prot_flush(pout);
	}
	for (i = 0; i < len; i++) {
	    c = prot_getc(pin);
	    if (c == EOF) {
		buf_cstring(buf);
		return EOF;
	    }
	    buf_putc(buf, c);
	}
	buf_cstring(buf);
	if (!(flags & GXS_BINARY) && strlen(buf_cstring(buf)) != (unsigned)buf_len(buf))
	    return EOF; /* Disallow imbedded NUL */
	return prot_getc(pin);

    default:
	if ((flags & GXS_ATOM)) {
	    /*
	     * Atom -- server is liberal in accepting specials other
	     * than whitespace, parens, or double quotes
	     */
	    for (;;) {
		if (c == EOF || isspace(c) || c == '(' || 
		          c == ')' || c == '\"') {
		    buf_cstring(buf);
		    return c;
		}
		buf_putc(buf, c);
		c = prot_getc(pin);
	    }
	    /* never gets here */
	}
	else if ((flags & GXS_NIL)) {
	    /*
	     * Look for "NIL"
	     */
	    if (c == 'N') {
		prot_ungetc(c, pin);
		c = getword(pin, buf);
		if (!strcmp(buf_cstring(buf), "NIL"))
		    return c;
		return EOF;
	    }
	}
	goto fail;
    }

    return EOF;

fail:
    buf_cstring(buf);
    if (c != EOF) prot_ungetc(c, pin);
    return EOF;
}

int getint32(struct protstream *pin, int32_t *num)
{
    int32_t result = 0;
    char c;
    int gotchar = 0;

    /* INT_MAX == 2147483647 */
    while ((c = prot_getc(pin)) != EOF && cyrus_isdigit(c)) {
	if (result > 214748364 || (result == 214748364 && (c > '7')))
	    fatal("num too big", EC_IOERR);
	result = result * 10 + c - '0';
	gotchar = 1;
    }

    if (!gotchar)
	return EOF;

    *num = result;

    return c;
}

/* Like getint32() but explicitly signed, i.e. negative numbers
 * are accepted */
int getsint32(struct protstream *pin, int32_t *num)
{
    int c;
    int sgn = 1;

    c = prot_getc(pin);
    if (c == EOF)
	return EOF;

    if (c == '-')
	sgn = -1;
    else if (c == '+')
	sgn = 1;
    else
	prot_ungetc(c, pin);

    c = getint32(pin, num);
    if (c == EOF)
	return EOF;
    /* this is slightly buggy: the number INT_MIN = -2147483648
     * is a valid signed 32b int but is not accepted */
    if (sgn < 0)
	*num = - (*num);
    return c;
}

/* can't flag with -1 if there is no number here, so return EOF */
int getuint32(struct protstream *pin, uint32_t *num)
{
    uint32_t result = 0;
    char c;
    int gotchar = 0;

    /* UINT_MAX == 4294967295U */
    while ((c = prot_getc(pin)) != EOF && cyrus_isdigit(c)) {
	if (result > 429496729 || (result == 429496729 && (c > '5')))
	    fatal("num too big", EC_IOERR);
	result = result * 10 + c - '0';
	gotchar = 1;
    }

    if (!gotchar)
	return EOF;

    *num = result;

    return c;
}

/* This would be called getuint64() if
 * all were right with the world */
int getmodseq(struct protstream *pin, modseq_t *num)
{
    int c;
    unsigned int i = 0;
    char buf[32];
    int gotchar = 0;

    while (i < sizeof(buf) &&
	   (c = prot_getc(pin)) != EOF &&
	   cyrus_isdigit(c)) {
	buf[i++] = c;
	gotchar = 1;
    }

    if (!gotchar || i == sizeof(buf))
	return EOF;

    buf[i] = '\0';
    *num = strtoull(buf, NULL, 10);

    return c;
}

/*
 * Eat characters up to and including the next newline
 * Also look for and eat non-synchronizing literals.
 */
void eatline(struct protstream *pin, int c)
{
    int state = 0;
    char *statediagram = " {+}\r";
    uint32_t size = 0;

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
	else if (state == 1 && cyrus_isdigit(c)) {
	    if (size > 429496729 || (size == 429496729 && (c > '5')))
		fatal("num too big", EC_IOERR);
	    size = size * 10 + c - '0';
	}
	else state = 0;

	c = prot_getc(pin);
	if (c == EOF) return;
    }
}
