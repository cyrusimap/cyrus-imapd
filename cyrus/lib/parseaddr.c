#include <stdio.h>
#include <ctype.h>

#include "parseaddr.h"
#include "xmalloc.h"

static char parseaddr_myhostname[128];

static void parseaddr_append();
static int parseaddr_phrase();
static int parseaddr_domain();
static int parseaddr_route();

parseaddr_list(s, addrp)
char *s;
struct address **addrp;
{
    int ingroup = 0;
    char *freeme;
    int tok = ' ';
    char *phrase, *route, *mailbox, *domain, *comment;

    /* Skip down to the tail */
    while ((*addrp)->next) {
	addrp = &(*addrp)->next;
    }

    s = freeme = strsave(s);

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
	if (!parseaddr_myhostname[0]) {
	    gethostname(parseaddr_myhostname, sizeof(parseaddr_myhostname)-1);
	}
	domain = parseaddr_myhostname;
    }
    newaddr->domain = domain;

    newaddr->next = 0;
    newaddr->freeme = *freemep;
    *freemep = 0;

    **addrpp = newaddr;
    *addrpp = &newaddr->next;
}

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
	    while (c = *src++) {
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
	    return c;
	}
	else {
	    *dst++ = c;
	}
    }
}

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
	    return c;
	}
    }
}
	
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
	    return c;
	}
    }
}


