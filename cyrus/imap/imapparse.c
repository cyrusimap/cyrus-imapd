#include <config.h>

#include <ctype.h>
#include <string.h>

#include "prot.h"
#include "xmalloc.h"
#include "imapconf.h"

void freebuf(struct buf *buf)
{
    if (buf->s) {
	free(buf->s);
	buf->s = NULL;
    }
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
	    return c;
	}
	if (len == buf->alloc) {
	    buf->alloc += BUFGROWSIZE;
	    buf->s = xrealloc(buf->s, buf->alloc+1);
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
    int i, len = 0;
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
	if (c != EOF) prot_ungetc(c, pin);
	return EOF;

    default:
	switch (type) {
	case IMAP_ASTRING:	 /* atom, quoted-string or literal */
	    /*
	     * Atom -- server is liberal in accepting specials other
	     * than whitespace, parens, or double quotes
	     */
	    for (;;) {
		if (c == EOF || isspace(c) || c == '(' || 
		          c == ')' || c == '\"') {
		    buf->s[len] = '\0';
		    return c;
		}
		if (len == buf->alloc) {
		    buf->alloc += BUFGROWSIZE;
		    buf->s = xrealloc(buf->s, buf->alloc+1);
		}
		buf->s[len++] = c;
		c = prot_getc(pin);
	    }
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

	case IMAP_STRING:	 /* quoted-string or literal */
	    /*
	     * Nothing to do here - fall through.
	     */
	    break;
	}
	
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
		return prot_getc(pin);
	    }
	    else if (c == EOF || c == '\r' || c == '\n') {
		buf->s[len] = '\0';
		if (c != EOF) prot_ungetc(c, pin);
		return EOF;
	    }
	    if (len == buf->alloc) {
		buf->alloc += BUFGROWSIZE;
		buf->s = xrealloc(buf->s, buf->alloc+1);
	    }
	    buf->s[len++] = c;
	}
    case '{':
	/* Literal */
	isnowait = 0;
	buf->s[0] = '\0';
	while ((c = prot_getc(pin)) != EOF && isdigit(c)) {
	    sawdigit = 1;
	    len = len*10 + c - '0';
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
		return EOF;
	    }
	    buf->s[i] = c;
	}
	buf->s[len] = '\0';
	if (strlen(buf->s) != len) return EOF; /* Disallow imbedded NUL */
	return prot_getc(pin);
    }
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
