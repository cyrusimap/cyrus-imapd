/* parseaddr.c -- RFC 822 address parser
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parseaddr.h"
#include "xmalloc.h"
#include "util.h"

static const char unknown_user[] = "unknown-user";
static const char unspecified_domain[] = "unspecified-domain";

static void parseaddr_append(struct address ***addrpp,
                             const char *name,
                             const char *route,
                             const char *mailbox,
                             const char *domain,
                             char **freemep,
                             int invalid);
static int parseaddr_phrase(char **inp,
                            const char **phrasep,
                            const char *specials);
static int parseaddr_domain(char **inp,
                            const char **domainp,
                            const char **commmentp,
                            int *invalid);
static int parseaddr_route(char **inp, const char **routep);

/*
 * Parse an address list in 's', appending address structures to
 * the list pointed to by 'addrp'.
 */
EXPORTED void parseaddr_list(const char *str, struct address **addrp)
{
    char *s;
    int ingroup = 0;
    char *freeme;
    int tok = ' ', invalid = 0;
    const char *phrase, *route, *mailbox, *domain, *comment;

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
                parseaddr_append(&addrp, 0, 0, phrase, "", &freeme, invalid);
            }
            if (tok == ';') {
                parseaddr_append(&addrp, 0, 0, 0, 0, &freeme, invalid);
                ingroup = 0;
            }
            continue;

        case ':':
            parseaddr_append(&addrp, 0, 0, phrase, 0, &freeme, invalid);
            ingroup++;
            continue;

        case '@':
            tok = parseaddr_domain(&s, &domain, &comment, &invalid);
            parseaddr_append(&addrp,
                             comment,
                             0,
                             phrase,
                             domain,
                             &freeme,
                             invalid);
            if (tok == ';') {
                parseaddr_append(&addrp, 0, 0, 0, 0, &freeme, invalid);
                ingroup = 0;
            }
            continue;

        case '<':
            tok = parseaddr_phrase(&s, &mailbox, "@>");
            if (tok == '@') {
                route = 0;
                if (!*mailbox) {
                    *--s = '@';
                    tok = parseaddr_route(&s, &route);
                    if (tok != ':') {
                        parseaddr_append(&addrp,
                                         phrase,
                                         route,
                                         "",
                                         "",
                                         &freeme,
                                         invalid);
                        while (tok && tok != '>') {
                            tok = *s++;
                        }
                        continue;
                    }
                    tok = parseaddr_phrase(&s, &mailbox, "@>");
                    if (tok != '@') {
                        parseaddr_append(&addrp,
                                         phrase,
                                         route,
                                         mailbox,
                                         "",
                                         &freeme,
                                         invalid);
                        continue;
                    }
                }
                tok = parseaddr_domain(&s, &domain, 0, &invalid);
                parseaddr_append(&addrp,
                                 phrase,
                                 route,
                                 mailbox,
                                 domain,
                                 &freeme,
                                 invalid);
                while (tok && tok != '>') {
                    tok = *s++;
                }
                continue; /* effectively auto-inserts a comma */
            }
            else {
                parseaddr_append(&addrp,
                                 phrase,
                                 0,
                                 mailbox,
                                 "",
                                 &freeme,
                                 invalid);
            }
        }
    }
    if (ingroup) {
        parseaddr_append(&addrp, 0, 0, 0, 0, &freeme, invalid);
    }

    if (freeme) {
        free(freeme);
    }
}

/*
 * Free the address list 'addr'
 */
EXPORTED void parseaddr_free(struct address *addr)
{
    struct address *next;

    while (addr) {
        if (addr->freeme) {
            free(addr->freeme);
        }
        next = addr->next;
        free((char *) addr);
        addr = next;
    }
}

/*
 * Helper function to append a new address structure to and address list.
 */
static void parseaddr_append(struct address ***addrpp,
                             const char *name,
                             const char *route,
                             const char *mailbox,
                             const char *domain,
                             char **freemep,
                             int invalid)
{
    struct address *newaddr;

    newaddr = (struct address *) xmalloc(sizeof(struct address));
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
        domain = unspecified_domain;
    }
    newaddr->domain = domain;

    newaddr->next = 0;
    newaddr->freeme = *freemep;
    *freemep = 0;

    newaddr->invalid = invalid;

    **addrpp = newaddr;
    *addrpp = &newaddr->next;
}

/* Macro to skip white space and RFC 822 comments */

#define SKIPWHITESPACE(s)                                                      \
    {                                                                          \
        int _c, _comment = 0;                                                  \
                                                                               \
        while ((_c = *(s))) {                                                  \
            if (_c == '(') {                                                   \
                _comment = 1;                                                  \
                (s)++;                                                         \
                while ((_comment && (_c = *(s)))) {                            \
                    (s)++;                                                     \
                    if (_c == '\\' && *(s))                                    \
                        (s)++;                                                 \
                    else if (_c == '(')                                        \
                        _comment++;                                            \
                    else if (_c == ')')                                        \
                        _comment--;                                            \
                }                                                              \
                (s)--;                                                         \
            }                                                                  \
            else if (!Uisspace(_c))                                            \
                break;                                                         \
            (s)++;                                                             \
        }                                                                      \
    }

/*
 * Parse an RFC 822 "phrase", stopping at 'specials'
 */
static int parseaddr_phrase(char **inp,
                            const char **phrasep,
                            const char *specials)
{
    int c;
    char *src = *inp;
    char *dst;

    SKIPWHITESPACE(src);

    *phrasep = dst = src;

    for (;;) {
        c = *src++;
        if (c == '"') {
            while ((c = *src)) {
                src++;
                if (c == '\\' && *src == '\r' && *(src + 1) == '\n') {
                    /* Ignore quote right in front of CR+LF. There's no
                     * point in accepting lone CR or stray LF, and there's
                     * clients out there that produce these bogus addresses. */
                    c = *src;
                    src++;
                }
                if (c == '\r' && *src == '\n') {
                    /* CR+LF combination */
                    src++;
                    if (*src == ' ' || *src == '\t') {
                        /* CR+LF+WSP - folded header field,
                         * unfold it by skipping ONLY the CR+LF */
                        continue;
                    }
                    /* otherwise we have CR+LF at the end of a header
                     * field, which means we have an unbalanced " */
                    goto fail;
                }
                else if (iscntrl(c)) {
                    if (c == '\r' || c == '\n') {
                        c = ' '; // replace CR and LF with space
                    }
                    else if (c != '\t') {
                        continue; // else ignore anything but TAB
                    }
                }
                if (c == '"') {
                    break; /* end of quoted string */
                }
                if (c == '\\') {
                    if (!(c = *src)) {
                        goto fail;
                    }
                    src++;
                }
                *dst++ = c;
            }
            if (c != '"') {
                goto fail; /* unbalanced " */
            }
        }
        else if (Uisspace(c) || c == '(') {
            src--;
            SKIPWHITESPACE(src);
            *dst++ = ' ';
        }
        else if (!c || strchr(specials, c)) {
            if (dst > *phrasep && dst[-1] == ' ') {
                dst--;
            }
            *dst = '\0';
            *inp = src;
            return c;
        }
        else {
            *dst++ = c;
        }
    }

fail:
    /* simulate end-of-string */
    *phrasep = "";
    return 0;
}

/*
 * Parse a domain.  If 'commentp' is non-nil, parses any trailing comment.
 * If the domain is invalid, set invalid to non-zero.
 */
static int parseaddr_domain(char **inp,
                            const char **domainp,
                            const char **commentp,
                            int *invalid)
{
    u_char c;
    char *src = *inp;
    char *dst;
    char *cdst;
    int comment;

    if (commentp) {
        *commentp = 0;
    }
    SKIPWHITESPACE(src);

    *domainp = dst = src;

    for (;;) {
        c = *src++;
        if (Uisalnum(c) || c == '-' || c == '[' || c == ']' || c == ':'
            || c > 127)
        {
            *dst++ = c;
            if (commentp) {
                *commentp = 0;
            }
        }
        else if (c == '.') {
            if (dst > *domainp && dst[-1] != '.') {
                *dst++ = c;
            }
            if (commentp) {
                *commentp = 0;
            }
        }
        else if (c == '(') {
            if (commentp) {
                *commentp = cdst = src;
                comment = 1;
                while (comment && (c = *src)) {
                    src++;
                    if (c == '(') {
                        comment++;
                    }
                    else if (c == ')') {
                        comment--;
                    }
                    else if (c == '\\' && (c = *src)) {
                        src++;
                    }

                    if (comment) {
                        *cdst++ = c;
                    }
                }
                *cdst = '\0';
            }
            else {
                src--;
                SKIPWHITESPACE(src);
            }
        }
        else if (c == '@') {
            /* This domain name is garbage. Continue eating up the characters
             * until we get to a sane state. */
            *invalid = 1;
            *dst++ = c;
            if (commentp) {
                *commentp = 0;
            }
        }
        else if (!Uisspace(c)) {
            if (dst > *domainp && dst[-1] == '.') {
                dst--;
            }
            *dst = '\0';
            *inp = src;
            return c;
        }
    }
}

/*
 * Parse a source route (at-domain-list)
 */
static int parseaddr_route(char **inp, const char **routep)
{
    int c;
    char *src = *inp;
    char *dst;

    SKIPWHITESPACE(src);

    *routep = dst = src;

    for (;;) {
        c = *src++;
        if (Uisalnum(c) || c == '-' || c == '[' || c == ']' || c == ','
            || c == '@')
        {
            *dst++ = c;
        }
        else if (c == '.') {
            if (dst > *routep && dst[-1] != '.') {
                *dst++ = c;
            }
        }
        else if (Uisspace(c) || c == '(') {
            src--;
            SKIPWHITESPACE(src);
        }
        else {
            while (dst > *routep
                   && (dst[-1] == '.' || dst[-1] == ',' || dst[-1] == '@'))
            {
                dst--;
            }
            *dst = '\0';
            *inp = src;
            return c;
        }
    }
}

EXPORTED char *address_get_all(const struct address *a, int canon_domain)
{
    char *s = NULL;

    if (a->mailbox || a->domain) {
        const char *m = a->mailbox ? a->mailbox : unknown_user;
        const char *d = a->domain ? a->domain : unspecified_domain;
        s = strconcat(m, "@", d, (char *) NULL);
        if (canon_domain) {
            lcase(s + strlen(m) + 1);
        }
    }

    return s;
}

EXPORTED char *address_get_localpart(const struct address *a)
{
    return xstrdupnull(a->mailbox);
}

EXPORTED char *address_get_domain(const struct address *a, int canon_domain)
{
    char *s = NULL;

    if (a->domain) {
        s = xstrdup(a->domain);
        if (canon_domain) {
            lcase(s);
        }
    }

    return s;
}

EXPORTED char *address_get_user(const struct address *a)
{
    char *s = NULL;

    if (a->mailbox) {
        char *p = strchr(a->mailbox, '+');
        int len = p ? p - a->mailbox : (int) strlen(a->mailbox);
        s = xstrndup(a->mailbox, len);
    }

    return s;
}

EXPORTED char *address_get_detail(const struct address *a)
{
    char *s = NULL;

    if (a->mailbox) {
        char *p = strchr(a->mailbox, '+');
        s = p ? xstrdup(p + 1) : NULL;
    }

    return s;
}

/*
 * Address iterator interface
 */

EXPORTED void address_itr_init(struct address_itr *ai,
                               const char *str,
                               int reverse_path)
{
    memset(ai, 0, sizeof(*ai));
    if (!*str && reverse_path) {
        /* Null reverse-path */
        ai->addrlist = (struct address *) xzmalloc(sizeof(struct address));
    }
    else {
        parseaddr_list(str, &ai->addrlist);
    }
    ai->anext = ai->addrlist;
}

EXPORTED const struct address *address_itr_next(struct address_itr *ai)
{
    struct address *a;
    if (ai->anext == NULL) {
        return NULL;
    }
    a = ai->anext;
    ai->anext = ai->anext->next;
    return a;
}

EXPORTED void address_itr_fini(struct address_itr *ai)
{
    parseaddr_free(ai->addrlist);
    memset(ai, 0, sizeof(*ai));
}

/*
 * Convenience function to return a single canonicalised address.
 */
EXPORTED char *address_canonicalise(const char *str)
{
    struct address *addrlist = NULL;
    char *s = NULL;

    parseaddr_list(str, &addrlist);
    if (addrlist) {
        s = address_get_all(addrlist, 1);
    }
    parseaddr_free(addrlist);

    return s;
}
