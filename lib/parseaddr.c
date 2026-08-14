/* parseaddr.c - RFC 822 address parser */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parseaddr.h"
#include "charset.h"
#include "stristr.h"
#include "xmalloc.h"
#include "util.h"

static const char unknown_user[] = "unknown-user";
static const char unspecified_domain[] = "unspecified-domain";

static void parseaddr_append(struct address ***addrpp, const char *name,
                             const char *route, const char *mailbox,
                             const char *domain, char **freemep, int invalid);
static int parseaddr_phrase(char **inp,
                            const char **phrasep,
                            const char *specials);
static int parseaddr_domain(char **inp,
                            const char **domainp,
                            const char **commmentp,
                            int *invalid,
                            const char *bufend);
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
    const char *bufend;
    int tok = ' ', invalid = 0;
    size_t len, size;
    const char *phrase, *route, *mailbox, *domain, *comment;

    /* Skip down to the tail */
    while (*addrp) {
        addrp = &(*addrp)->next;
    }

    /* The parse happens in place, so an a-label that turns into a
       longer u-label needs room to grow even if it very seldom grows.
       See the comment in parseaddr_to_ulabels. */
    len = strlen(str);
    size = stristr(str, "xn--") ? 4 * len + 1 : len + 1;
    freeme = xmalloc(size);
    memcpy(freeme, str, len + 1);
    s = freeme;
    bufend = freeme + size;

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
            tok = parseaddr_domain(&s, &domain, &comment, &invalid, bufend);
            parseaddr_append(&addrp, comment, 0, phrase, domain, &freeme, invalid);
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
                        parseaddr_append(&addrp, phrase, route, "", "", &freeme, invalid);
                        while (tok && tok != '>') tok = *s++;
                        continue;
                    }
                    tok = parseaddr_phrase(&s, &mailbox, "@>");
                    if (tok != '@') {
                        parseaddr_append(&addrp, phrase, route, mailbox, "",
                                         &freeme, invalid);
                        continue;
                    }
                }
                tok = parseaddr_domain(&s, &domain, 0, &invalid, bufend);
                parseaddr_append(&addrp, phrase, route, mailbox, domain,
                                 &freeme, invalid);
                while (tok && tok != '>') tok = *s++;
                continue; /* effectively auto-inserts a comma */
            }
            else {
                parseaddr_append(&addrp, phrase, 0, mailbox, "", &freeme, invalid);
            }
        }
    }
    if (ingroup) parseaddr_append(&addrp, 0, 0, 0, 0, &freeme, invalid);

    if (freeme) free(freeme);
}

/*
 * Free the address list 'addr'
 */
EXPORTED void parseaddr_free(struct address *addr)
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
static void parseaddr_append(struct address ***addrpp, const char *name,
                             const char *route, const char *mailbox,
                             const char *domain, char **freemep, int invalid)
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

#define SKIPWHITESPACE(s) \
{ \
    int _c, _comment = 0; \
 \
    while ((_c = *(s))) { \
        if (_c == '(') { \
            _comment = 1; \
            (s)++; \
            while ((_comment && (_c = *(s)))) { \
                (s)++; \
                if (_c == '\\' && *(s)) (s)++; \
                else if (_c == '(') _comment++; \
                else if (_c == ')') _comment--; \
            } \
            (s)--; \
        } \
        else if (!Uisspace(_c)) break; \
        (s)++; \
    } \
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
                if (c == '\\' && *src == '\r' && *(src+1) == '\n') {
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
                    if (c == '\r' || c == '\n')
                        c = ' '; // replace CR and LF with space
                    else if (c != '\t')
                        continue; // else ignore anything but TAB
                }
                if (c == '"') break;        /* end of quoted string */
                if (c == '\\') {
                    if (!(c = *src)) goto fail;
                    src++;
                }
                *dst++ = c;
            }
            if (c != '"') goto fail;        /* unbalanced " */
        }
        else if (Uisspace(c) || c == '(') {
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

fail:
    /* simulate end-of-string */
    *phrasep = "";
    return 0;
}

/* Does any label of 'domain' look like an a-label? */
static int parseaddr_has_alabel(const char *domain)
{
    while (domain) {
        if (!strncasecmp(domain, "xn--", 4)) return 1;
        domain = strchr(domain, '.');
        if (domain) domain++;
    }
    return 0;
}

/*
 * Convert the a-labels of the parsed, NUL-terminated 'domain' to
 * u-labels, in place. Punycode belongs in the DNS; everything above
 * this stores and shows the u-label, so that a search for grå.org
 * finds mail from xn--gr-zia.org.
 *
 * A domain that ICU won't decode is left exactly as it arrived, and so
 * is stored that way. This isn't ideal, but I don't see any better way to
 * handle errors like example@xn--zz.example.com.
 */
static void parseaddr_to_ulabels(char *domain, char **tailp,
                                 const char *bufend)
{
    char *tail = *tailp;
    char *utf8;
    size_t need, taillen;

    if (!parseaddr_has_alabel(domain)) return;

    utf8 = charset_idna_to_utf8(domain);
    if (!utf8) return;

    /* The u-label form may be longer than the a-label form, in which
       case the not yet parsed remainder has to move out of the way. */
    need = strlen(utf8);
    if (domain + need >= tail) {
        size_t extra = domain + need + 1 - tail;
        taillen = strlen(tail);
        if (tail + taillen + 1 + extra > bufend) {
            /* parseaddr_list() sizes the buffer so this cannot happen */
            free(utf8);
            return;
        }
        memmove(tail + extra, tail, taillen + 1);
        *tailp = tail + extra;
    }

    memcpy(domain, utf8, need + 1);
    free(utf8);
}

/*
 * Parse a domain.  If 'commentp' is non-nil, parses any trailing comment.
 * If the domain is invalid, set invalid to non-zero.
 */
static int parseaddr_domain(char **inp,
                            const char **domainp,
                            const char **commentp,
                            int *invalid,
                            const char *bufend)
{
    u_char c;
    char *src = *inp;
    char *dst;
    char *cdst;
    int comment;

    if (commentp) *commentp = 0;
    SKIPWHITESPACE(src);

    *domainp = dst = src;

    for (;;) {
        c = *src++;
        if (Uisalnum(c) || c == '-' || c == '[' || c == ']' || c == ':' || c > 127) {
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
        else if (c == '@') {
            /* This domain name is garbage. Continue eating up the characters
             * until we get to a sane state. */
            *invalid = 1;
            *dst++ = c;
            if (commentp) *commentp = 0;
        }
        else if (!Uisspace(c)) {
            char *tail;

            if (dst > *domainp && dst[-1] == '.') dst--;
            *dst = '\0';

            /* src has stepped past the terminating character, which at
               the end of the string is the NUL, with nothing after. */
            tail = c ? src : src - 1;
            parseaddr_to_ulabels((char *) *domainp, &tail, bufend);
            src = tail;

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
        if (Uisalnum(c) || c == '-' || c == '[' || c == ']' ||
            c == ',' || c == '@') {
            *dst++ = c;
        }
        else if (c == '.') {
            if (dst > *routep && dst[-1] != '.') *dst++ = c;
        }
        else if (Uisspace(c) || c == '(') {
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

EXPORTED char *address_get_all(const struct address *a, int canon_domain)
{
    char *s = NULL;

    if (a->mailbox || a->domain) {
        const char *m = a->mailbox ? a->mailbox : unknown_user;
        const char *d = a->domain ? a->domain : unspecified_domain;
        s = strconcat(m, "@", d, (char *)NULL);
        if (canon_domain)
            lcase(s + strlen(m) + 1);
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
        if (canon_domain)
            lcase(s);
    }

    return s;
}

EXPORTED char *address_get_user(const struct address *a)
{
    char *s = NULL;

    if (a->mailbox) {
        char *p = strchr(a->mailbox, '+');
        int len = p ? p - a->mailbox : (int)strlen(a->mailbox);
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

EXPORTED void address_itr_init(struct address_itr *ai, const char *str,
                               int reverse_path)
{
    memset(ai, 0, sizeof(*ai));
    if (!*str && reverse_path) {
        /* Null reverse-path */
        ai->addrlist = (struct address *)xzmalloc(sizeof(struct address));
    }
    else parseaddr_list(str, &ai->addrlist);
    ai->anext = ai->addrlist;
}

EXPORTED const struct address *address_itr_next(struct address_itr *ai)
{
    struct address *a;
    if (ai->anext == NULL)
        return NULL;
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
    if (addrlist)
        s = address_get_all(addrlist, 1);
    parseaddr_free(addrlist);

    return s;
}

