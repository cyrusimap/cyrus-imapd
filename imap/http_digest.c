/* http_digest.c - Digests of HTTP message content */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "assert.h"
#include "charset.h"
#include "http_digest.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

struct digest_alg {
    const char *name; /* NULL for Content-MD5, which isn't in a Dictionary */
    const EVP_MD *(*md)(void);
};

/* RFC 9530's active algorithms: the deprecated ones MUST NOT be used where
   an adversary may be present (Section 5) */
static const struct digest_alg digest_algs[] = {
    { "sha-256", &EVP_sha256 },
    { "sha-512", &EVP_sha512 },
};

#define NUM_ALGS (sizeof(digest_algs) / sizeof(digest_algs[0]))

static const struct digest_alg content_md5_alg = { NULL, &EVP_md5 };

struct http_digest {
    const char *field; /* Content-Digest, Unencoded-Digest or Content-MD5 */
    const struct digest_alg *alg;
    EVP_MD_CTX *ctx; /* NULL once final */
    char value[128]; /* "sha-512=:" + base64 of 64 octets + ":" */
};

/*
 * Just enough of a Structured Field Dictionary parser (RFC 8941 Section
 * 4.2.2) for the integrity fields: it validates every member, but keeps
 * only Integer and Byte Sequence values.
 */

enum sf_type { SF_OTHER, SF_INTEGER, SF_BYTES };

struct sf_item {
    enum sf_type type;
    long long integer;
    const char *bytes; /* base64 of a Byte Sequence, not NUL-terminated */
    size_t byteslen;
};

typedef void sf_member_cb(const char *key, size_t keylen,
                          const struct sf_item *item, void *rock);

static bool is_tchar(char c)
{
    return c && (Uisalnum(c) || strchr("!#$%&'*+-.^_`|~", c));
}

static void skip_sp(const char **p)
{
    while (**p == ' ') (*p)++;
}

static void skip_ows(const char **p)
{
    while (**p == ' ' || **p == '\t') (*p)++;
}

static bool parse_key(const char **p, const char **key, size_t *keylen)
{
    const char *s = *p;

    if (!Uislower(*s) && *s != '*') return false;

    for (s++; Uislower(*s) || Uisdigit(*s) || (*s && strchr("_-.*", *s)); s++)
        ;

    *key = *p;
    *keylen = s - *p;
    *p = s;

    return true;
}

static bool parse_bare_item(const char **p, struct sf_item *item)
{
    const char *s = *p;

    item->type = SF_OTHER;

    if (*s == '-' || Uisdigit(*s)) {
        bool neg = (*s == '-');

        if (neg) s++;

        const char *digits = s;
        while (Uisdigit(*s)) s++;
        if (s == digits) return false;

        if (*s == '.') {
            /* Decimal */
            if (s - digits > 12) return false;

            const char *frac = ++s;
            while (Uisdigit(*s)) s++;
            if (s == frac || s - frac > 3) return false;
        }
        else {
            if (s - digits > 15) return false;

            item->type = SF_INTEGER;
            item->integer = strtoll(digits, NULL, 10);
            if (neg) item->integer = -item->integer;
        }
    }
    else if (*s == '"') {
        /* String */
        for (s++; *s != '"'; s++) {
            if (*s == '\\') {
                s++;
                if (*s != '"' && *s != '\\') return false;
            }
            else if (*s < 0x20 || *s > 0x7e) {
                return false;
            }
        }
        s++;
    }
    else if (*s == ':') {
        /* Byte Sequence */
        const char *start = ++s;

        while (Uisalnum(*s) || *s == '+' || *s == '/' || *s == '=') {
            s++;
        }
        if (*s != ':') return false;

        item->type = SF_BYTES;
        item->bytes = start;
        item->byteslen = s - start;
        s++;
    }
    else if (*s == '?') {
        /* Boolean */
        s++;
        if (*s != '0' && *s != '1') return false;
        s++;
    }
    else if (Uisalpha(*s) || *s == '*') {
        /* Token */
        for (s++; is_tchar(*s) || *s == ':' || *s == '/'; s++)
            ;
    }
    else {
        return false;
    }

    *p = s;

    return true;
}

static bool parse_params(const char **p)
{
    while (**p == ';') {
        const char *key;
        size_t keylen;
        struct sf_item item;

        (*p)++;
        skip_sp(p);
        if (!parse_key(p, &key, &keylen)) return false;

        if (**p == '=') {
            (*p)++;
            if (!parse_bare_item(p, &item)) return false;
        }
    }

    return true;
}

static bool parse_item_or_inner_list(const char **p, struct sf_item *item)
{
    if (**p == '(') {
        item->type = SF_OTHER;

        for ((*p)++;;) {
            struct sf_item member;

            skip_sp(p);
            if (**p == ')') {
                (*p)++;
                break;
            }
            if (!parse_bare_item(p, &member) || !parse_params(p)) {
                return false;
            }
            if (**p != ' ' && **p != ')') return false;
        }
    }
    else if (!parse_bare_item(p, item)) {
        return false;
    }

    return parse_params(p);
}

/* Parse a Dictionary, calling cb (if any) for each member */
static bool sf_parse_dict(const char *field, sf_member_cb *cb, void *rock)
{
    const char *p = field;

    skip_sp(&p);

    while (*p) {
        const char *key;
        size_t keylen;
        struct sf_item item = { .type = SF_OTHER };

        if (!parse_key(&p, &key, &keylen)) return false;

        /* With no value, a member is Boolean true */
        if (*p == '=') {
            p++;
            if (!parse_item_or_inner_list(&p, &item)) return false;
        }
        else if (!parse_params(&p)) {
            return false;
        }

        if (cb) cb(key, keylen, &item, rock);

        skip_ows(&p);
        if (!*p) break;
        if (*p != ',') return false;
        p++;
        skip_ows(&p);
        if (!*p) return false; /* trailing comma */
    }

    return true;
}

/* Call cb for each member of the Dictionary field name in hdrs, whose
 * instances are combined as one.  A malformed field is ignored entirely
 * (RFC 8941 Section 4.2), so cb sees nothing of it.
 * Returns whether the field is present and well-formed. */
static bool parse_field(hdrcache_t hdrs, const char *name,
                        sf_member_cb *cb, void *rock)
{
    const char **vals = spool_getheader(hdrs, name);
    struct buf field = BUF_INITIALIZER;

    if (!vals) return false;

    for (size_t i = 0; vals[i]; i++) {
        if (i) buf_putc(&field, ',');
        buf_appendcstr(&field, vals[i]);
    }

    const char *s = buf_cstring(&field);
    bool ok = sf_parse_dict(s, NULL, NULL) && sf_parse_dict(s, cb, rock);

    buf_free(&field);

    return ok;
}

static int find_alg(const char *key, size_t keylen)
{
    for (size_t i = 0; i < NUM_ALGS; i++) {
        if (strlen(digest_algs[i].name) == keylen &&
            !strncmp(digest_algs[i].name, key, keylen)) {
            return i;
        }
    }

    return -1;
}

/* Preference of each algorithm in a Want-*-Digest, -1 if not named */
static void want_cb(const char *key, size_t keylen,
                    const struct sf_item *item, void *rock)
{
    int *pref = (int *) rock;
    int i = find_alg(key, keylen);

    if (i >= 0 && item->type == SF_INTEGER &&
        item->integer >= 0 && item->integer <= 10) {
        pref[i] = item->integer;
    }
}

static struct http_digest *digest_new(const char *field,
                                      const struct digest_alg *alg)
{
    struct http_digest *d = xzmalloc(sizeof(struct http_digest));

    d->field = field;
    d->alg = alg;
    d->ctx = EVP_MD_CTX_new();
    assert(d->ctx && EVP_DigestInit_ex(d->ctx, alg->md(), NULL));

    return d;
}

EXPORTED struct http_digest *http_digest_content_md5(void)
{
    return digest_new("Content-MD5", &content_md5_alg);
}

/* A digest for field, if the preference field want in hdrs asks for one */
static struct http_digest *want_digest(hdrcache_t hdrs, const char *want,
                                       const char *field)
{
    int pref[NUM_ALGS];
    const struct digest_alg *alg = NULL;
    int best = 0;

    for (size_t i = 0; i < NUM_ALGS; i++) pref[i] = -1;

    if (!parse_field(hdrs, want, &want_cb, pref)) return NULL;

    for (size_t i = 0; i < NUM_ALGS; i++) {
        if (pref[i] > best) {
            best = pref[i];
            alg = &digest_algs[i];
        }
    }

    for (size_t i = 0; !alg && i < NUM_ALGS; i++) {
        if (pref[i] < 0) alg = &digest_algs[i];
    }

    return alg ? digest_new(field, alg) : NULL;
}

EXPORTED struct http_digest *http_digest_want(hdrcache_t req_hdrs)
{
    return want_digest(req_hdrs, "Want-Content-Digest", "Content-Digest");
}

EXPORTED struct http_digest *http_digest_want_unencoded(hdrcache_t req_hdrs)
{
    return want_digest(req_hdrs, "Want-Unencoded-Digest", "Unencoded-Digest");
}

EXPORTED void http_digest_update(struct http_digest *d,
                                 const void *data, size_t len)
{
    assert(d->ctx);

    if (len) assert(EVP_DigestUpdate(d->ctx, data, len));
}

static void format_value(char *value, size_t size,
                         const struct digest_alg *alg,
                         const unsigned char *md, unsigned mdlen)
{
    char b64[4 * ((EVP_MAX_MD_SIZE + 2) / 3) + 1];

    EVP_EncodeBlock((unsigned char *) b64, md, mdlen);

    if (alg->name) snprintf(value, size, "%s=:%s:", alg->name, b64);
    else snprintf(value, size, "%s", b64);
}

EXPORTED const char *http_digest_final(struct http_digest *d)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned mdlen;

    assert(d->ctx);
    assert(EVP_DigestFinal_ex(d->ctx, md, &mdlen));
    EVP_MD_CTX_free(d->ctx);
    d->ctx = NULL;

    format_value(d->value, sizeof(d->value), d->alg, md, mdlen);

    return d->value;
}

EXPORTED const char *http_digest_field(const struct http_digest *d)
{
    return d ? d->field : NULL;
}

EXPORTED const char *http_digest_value(const struct http_digest *d)
{
    return (d && !d->ctx) ? d->value : NULL;
}

EXPORTED void http_digest_free(struct http_digest **dp)
{
    struct http_digest *d = *dp;

    if (!d) return;

    EVP_MD_CTX_free(d->ctx);
    free(d);
    *dp = NULL;
}

/* The (last) value of each supported algorithm in an integrity field */
static void verify_cb(const char *key, size_t keylen,
                      const struct sf_item *item, void *rock)
{
    struct buf *vals = (struct buf *) rock;
    int i = find_alg(key, keylen);

    if (i >= 0 && item->type == SF_BYTES) {
        buf_setmap(&vals[i], item->bytes, item->byteslen);
    }
}

/* Check data against the integrity field in hdrs, setting errstr to
   mismatch if a digest doesn't match */
static int verify_digest(hdrcache_t hdrs, const char *field,
                         const struct buf *data, const char *mismatch,
                         const char **errstr)
{
    struct buf vals[NUM_ALGS] = { BUF_INITIALIZER, BUF_INITIALIZER };
    struct buf claimed = BUF_INITIALIZER;
    int r = 0;

    if (!parse_field(hdrs, field, &verify_cb, vals)) return 0;

    for (size_t i = 0; !r && i < NUM_ALGS; i++) {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned mdlen;

        if (!buf_len(&vals[i])) continue;

        assert(EVP_Digest(buf_len(data) ? buf_base(data) : "",
                          buf_len(data), md, &mdlen,
                          digest_algs[i].md(), NULL));

        buf_reset(&claimed);
        if (charset_decode(&claimed, buf_base(&vals[i]), buf_len(&vals[i]),
                           ENCODING_BASE64) ||
            buf_len(&claimed) != mdlen ||
            memcmp(buf_base(&claimed), md, mdlen)) {
            *errstr = mismatch;
            r = HTTP_BAD_REQUEST;
        }
    }

    for (size_t i = 0; i < NUM_ALGS; i++) buf_free(&vals[i]);
    buf_free(&claimed);

    return r;
}

EXPORTED int http_digest_verify(hdrcache_t hdrs, const struct buf *content,
                                const char **errstr)
{
    return verify_digest(hdrs, "Content-Digest", content,
                         "Content-Digest does not match the content", errstr);
}

EXPORTED int http_digest_verify_unencoded(hdrcache_t hdrs,
                                          const struct buf *representation,
                                          const char **errstr)
{
    return verify_digest(hdrs, "Unencoded-Digest", representation,
                         "Unencoded-Digest does not match the representation",
                         errstr);
}
