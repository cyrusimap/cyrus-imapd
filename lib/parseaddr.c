/* parseaddr.c -- RFC 822 address parser
 *
 *	(C) Copyright 1995 by Carnegie Mellon University
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
#include <string.h>

#include "parseaddr.h"
#include "xmalloc.h"

static char parseaddr_unspecified_domain[] = "unspecified-domain";

static void parseaddr_append P((struct address ***addrpp, char *name,
				char *route, char *mailbox, char *domain,
				char **freemep));
static int parseaddr_phrase P((char **inp, char **phrasep, char *specials));
static int parseaddr_domain P((char **inp, char **domainp, char **commmentp));
static int parseaddr_route P((char **inp, char **routep));

/*
 * Parse an address list in 's', appending address structures to
 * the list pointed to by 'addrp'.
 */
void
parseaddr_list(str, addrp)
const char *str;
struct address **addrp;
{
    char *s;
    int ingroup = 0;
    char *freeme;
    int tok = ' ';
    char *phrase, *route, *mailbox, *domain, *comment;

    /* Skip down to the tail */
    while (*addrp) {
	addrp = &(*addrp)->next;
    }

    s = freeme = xstrdup(str);

    while (tok) {
	tok = parseaddr_phrase(&s, &phrase, ingroup ? ",@<;" : ",@<:");
	switch (tok) {
	case ',':
	case '\0':
	case ';':
	    if (*phrase) {
		parseaddr_append(&addrp, 0, 0, phrase, "", &freeme);
	    }
	    if (tok == ';') {
		parseaddr_append(&addrp, 0, 0, 0, 0, &freeme);
		ingroup = 0;
	    }
	    continue;

	case ':':
	    parseaddr_append(&addrp, 0, 0, phrase, 0, &freeme);
	    ingroup++;
	    continue;

	case '@':
	    tok = parseaddr_domain(&s, &domain, &comment);
	    parseaddr_append(&addrp, comment, 0, phrase, domain, &freeme);
	    continue;

	case '<':
	    tok = parseaddr_phrase(&s, &mailbox, "@>");
	    if (tok == '@') {
		route = 0;
		if (!*mailbox) {
		    *--s = '@';
		    tok = parseaddr_route(&s, &route);
		    if (tok != ':') {
			parseaddr_append(&addrp, phrase, route, "", "", &freeme);
			while (tok && tok != '>') tok = *s++;
			continue;
		    }
		    tok = parseaddr_phrase(&s, &mailbox, "@>");
		    if (tok != '@') {
			parseaddr_append(&addrp, phrase, route, mailbox, "",
					 &freeme);
			continue;
		    }
		}
		tok = parseaddr_domain(&s, &domain, 0);
		parseaddr_append(&addrp, phrase, route, mailbox, domain,
				 &freeme);
		while (tok && tok != '>') tok = *s++;
		continue; /* effectively auto-inserts a comma */
	    }
	    else {
		parseaddr_append(&addrp, phrase, 0, mailbox, "", &freeme);
	    }
	}
    }
    if (ingroup) parseaddr_append(&addrp, 0, 0, 0, 0, &freeme);

    if (freeme) free(freeme);
}

/*
 * Free the address list 'addr'
 */
void
parseaddr_free(addr)
struct address *addr;
{
    struct address *next;

    while (addr) {
	if (addr->freeme) free(addr->freeme);
	next = addr->next;
	free((char *)addr);
	addr = next;
    }
}

/*
 * Helper function to append a new address structure to and address list.
 */
static void
parseaddr_append(addrpp, name, route, mailbox, domain, freemep)
struct address ***addrpp;
char *name;
char *route;
char *mailbox;
char *domain;
char **freemep;
{
    struct address *newaddr;

    newaddr = (struct address *)xmalloc(sizeof(struct address));
    if (name && *name) {
	newaddr->name = name;
    }
    else {
	newaddr->name = 0;
    }

    if (route && *route) {
	newaddr->route = route;
    }
    else {
	newaddr->route = 0;
    }

    newaddr->mailbox = mailbox;

    if (domain && !*domain) {
	domain = parseaddr_unspecified_domain;
    }
    newaddr->domain = domain;

    newaddr->next = 0;
    newaddr->freeme = *freemep;
    *freemep = 0;

    **addrpp = newaddr;
    *addrpp = &newaddr->next;
}

/* Macro to skip white space and rfc822 comments */

#define SKIPWHITESPACE(s) \
{ \
    int _c, _comment = 0; \
 \
    while (_c = *(s)) { \
	if (_c == '(') { \
	    _comment = 1; \
	    (s)++; \
	    while (_comment && (_c = *(s))) { \
		(s)++; \
		if (_c == '\\' && *(s)) (s)++; \
		else if (_c == '(') _comment++; \
		else if (_c == ')') _comment--; \
	    } \
	    (s)--; \
	} \
	else if (!isspace(_c)) break; \
	(s)++; \
    } \
}

/*
 * Parse an RFC 822 "phrase", stopping at 'specials'
 */
static int parseaddr_phrase(inp, phrasep, specials)
char **inp;
char **phrasep;
char *specials;
{
    int c;
    char *src = *inp;
    char *dst;

    SKIPWHITESPACE(src);

    *phrasep = dst = src;

    for (;;) {
        c = *src++;
	if (c == '\"') {
	    while (c = *src) {
		src++;
		if (c == '\"') break;
		if (c == '\\') {
		    if (!(c = *src)) break;
		    src++;
		}
		*dst++ = c;
	    }
	}
	else if (isspace(c) || c == '(') {
	    src--;
	    SKIPWHITESPACE(src);
	    *dst++ = ' ';
	}
	else if (!c || strchr(specials, c)) {
	    if (dst > *phrasep && dst[-1] == ' ') dst--;
	    *dst = '\0';
	    *inp = src;
	    return c;
	}
	else {
	    *dst++ = c;
	}
    }
}

/*
 * Parse a domain.  If 'commentp' is non-nil, parses any trailing comment
 */
static int parseaddr_domain(inp, domainp, commentp)
char **inp;
char **domainp;
char **commentp;
{
    int c;
    char *src = *inp;
    char *dst;
    char *cdst;
    int comment;

    if (commentp) *commentp = 0;
    SKIPWHITESPACE(src);

    *domainp = dst = src;

    for (;;) {
        c = *src++;
	if (isalnum(c) || c == '-' || c == '[' || c == ']') {
	    *dst++ = c;
	    if (commentp) *commentp = 0;
	}
	else if (c == '.') {
	    if (dst > *domainp && dst[-1] != '.') *dst++ = c;
	    if (commentp) *commentp = 0;
	}
	else if (c == '(') {
	    if (commentp) {
		*commentp = cdst = src;
		comment = 1;
		while (comment && (c = *src)) {
		    src++;
		    if (c == '(') comment++;
		    else if (c == ')') comment--;
		    else if (c == '\\' && (c = *src)) src++;

		    if (comment) *cdst++ = c;
		}
		*cdst = '\0';
	    }
	    else {
		src--;
		SKIPWHITESPACE(src);
	    }
	}
	else if (!isspace(c)) {
	    if (dst > *domainp && dst[-1] == '.') dst--;
	    *dst = '\0';
	    *inp = src;
	    return c;
	}
    }
}
	
/*
 * Parse a source route (at-domain-list)
 */
static int parseaddr_route(inp, routep)
char **inp;
char **routep;
{
    int c;
    char *src = *inp;
    char *dst;

    SKIPWHITESPACE(src);

    *routep = dst = src;

    for (;;) {
        c = *src++;
	if (isalnum(c) || c == '-' || c == '[' || c == ']' ||
	    c == ',' || c == '@') {
	    *dst++ = c;
	}
	else if (c == '.') {
	    if (dst > *routep && dst[-1] != '.') *dst++ = c;
	}
	else if (isspace(c) || c == '(') {
	    src--;
	    SKIPWHITESPACE(src);
	}
	else {
	    while (dst > *routep &&
		   (dst[-1] == '.' || dst[-1] == ',' || dst[-1] == '@')) dst--;
	    *dst = '\0';
	    *inp = src;
	    return c;
	}
    }
}

