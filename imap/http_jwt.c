/* http_jwt.c - HTTP JSON Web Token authentication
 *
 * Copyright (c) 1994-2021 Carnegie Mellon University.  All rights reserved.
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
 */

#include <config.h>

#include <string.h>
#include <syslog.h>

#include <sasl/saslutil.h>

#include "assert.h"
#include "global.h"
#include "http_err.h"
#include "util.h"

#include "http_jwt.h"

static int is_enabled = 0;

static struct buf key = BUF_INITIALIZER;

static time_t max_age = 0;

struct jwt {
    // Base64 parts
    const char *joh;
    size_t johlen;
    const char *jws;
    size_t jwslen;
    const char *sig;
    size_t siglen;

    struct buf buf;
};

static inline int is_base64url_char(char c)
{
    return ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c == '-' || c == '_'));
}

HIDDEN int http_jwt_init(const char *keystr, int age)
{
    is_enabled = 0;

    // Reset previous state
    size_t oldlen = buf_len(&key);
    if (oldlen) {
        char *oldkey = buf_release(&key);
        memset(oldkey, 0, oldlen);
        free(oldkey);
    }
    max_age = 0;

    if (!keystr) {
        xsyslog(LOG_ERR, "Unexpected null key", NULL);
        return HTTP_SERVER_ERROR;
    }

    if (strncmp(keystr, "HS256:", 6)) {
        xsyslog(LOG_ERR, "Unexpected key algo specifier", "key=<%s>", keystr);
        return HTTP_SERVER_ERROR;
    }

    if (charset_decode(&key, keystr + 6, strlen(keystr) - 6, ENCODING_BASE64URL)) {
        xsyslog(LOG_ERR, "Invalid base64url key", "key=<%s>", keystr);
        return HTTP_SERVER_ERROR;
    }

    static const size_t HS256_MINLEN = 32; // see RFC 2104, section 3
    static const size_t HS256_MAXLEN = 64;

    if (buf_len(&key) < HS256_MINLEN || buf_len(&key) > HS256_MAXLEN) {
        xsyslog(LOG_ERR, "Key length outside allowed range",
                "range=<[%zu:%zu]> keylength=<%zu>",
                HS256_MINLEN, HS256_MAXLEN, buf_len(&key));
        return HTTP_SERVER_ERROR;
    }

    if (age < 0) {
        xsyslog(LOG_ERR, "Maximum age must not be negative", "age=<%d>", age);
        return HTTP_SERVER_ERROR;
    }
    max_age = age;

    is_enabled = 1;

    return 0;
}

HIDDEN int http_jwt_is_enabled(void)
{
    return is_enabled;
}

static int parse_token(struct jwt *jwt, const char *in, size_t inlen)
{
    if (!in || !inlen || inlen >= INT_MAX) return 0;

    size_t dot[2] = { 0 };
    size_t ndot = 0;
    for (size_t i = 0; i < inlen; i++) {
        if (is_base64url_char(in[i]))
            continue;

        if (in[i] == '.' && ndot < 2) {
            dot[ndot++] = i;
            continue;
        }

        xsyslog(LOG_ERR, "Token contains invalid character",
                "char=<%c> hex=<%#0x> position=<%zu>",
                in[i] & 0xff, in[i] & 0xff, i);
        return 0;
    }
    if (ndot != 2 || dot[0] == 0 || dot[1] == inlen-1 || dot[1] - dot[0] <= 1) {
        xsyslog(LOG_ERR, "Token has invalid JWS structure", NULL);
        return 0;
    }

    jwt->joh = in;
    jwt->johlen = dot[0];
    jwt->jws = in + dot[0] + 1;
    jwt->jwslen = dot[1] - dot[0] - 1;
    jwt->sig = in + dot[1] + 1;
    jwt->siglen = inlen - dot[1] - 1;

    return 1;
}

static int validate_signature(struct jwt *jwt)
{
    buf_reset(&jwt->buf);

    const char *k = buf_base(&key);
    int klen = buf_len(&key);
    const unsigned char *d = (const unsigned char*) jwt->joh;
    int dlen = jwt->johlen + jwt->jwslen + 1;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;

    assert(k && klen);

    if (!HMAC(EVP_sha256(), k, klen, d, dlen, md, &mdlen) || !mdlen) {
        xsyslog(LOG_ERR, "Cannot generate HMAC", NULL);
        return 0;
    }

    if (charset_decode(&jwt->buf, jwt->sig, jwt->siglen, ENCODING_BASE64URL)) {
        xsyslog(LOG_ERR, "Cannot decode token signature", NULL);
        return 0;
    }

    if (mdlen != buf_len(&jwt->buf) || memcmp(md, buf_base(&jwt->buf), mdlen)) {
        xsyslog(LOG_ERR, "Token signature does not match HMAC", NULL);
        return 0;
    }

    return 1;
}

static int validate_header(struct jwt *jwt)
{
    buf_reset(&jwt->buf);

    if (charset_decode(&jwt->buf, jwt->joh, jwt->johlen, ENCODING_BASE64URL)) {
        xsyslog(LOG_ERR, "Cannot decode JOSE header", NULL);
        return 0;
    }

    int ret = 0;

    json_t *joh = json_loads(buf_cstring(&jwt->buf), 0, NULL);
    if (json_object_size(joh) != 2) {
        xsyslog(LOG_ERR, "Unexpected JOSE header structure", NULL);
        goto done;
    }

    const char *typ = json_string_value(json_object_get(joh, "typ"));
    if (strcmpsafe(typ, "JWT")) {
        xsyslog(LOG_ERR, "Invalid \"typ\" claim", "typ=<%s>", typ);
        goto done;
    }

    // also rejects the "none" algo
    const char *alg = json_string_value(json_object_get(joh, "alg"));
    if (strcmpsafe(alg, "HS256")) {
        xsyslog(LOG_ERR, "Invalid \"alg\" claim", "alg=<%s>", alg);
        goto done;
    }

    ret = 1;

done:
    json_decref(joh);
    return ret;
}

static int validate_payload(struct jwt *jwt, char *out, size_t outlen)
{
    buf_reset(&jwt->buf);

    if (charset_decode(&jwt->buf, jwt->jws, jwt->jwslen, ENCODING_BASE64URL)) {
        xsyslog(LOG_ERR, "Cannot decode JWS payload", NULL);
        return 0;
    }

    int ret = 0;

    json_t *jws = json_loads(buf_cstring(&jwt->buf), 0, NULL);
    if (!json_object_size(jws) || json_object_size(jws) > 2) {
        xsyslog(LOG_ERR, "Unexpected JWS payload structure", NULL);
        goto done;
    }

    const char *sub = json_string_value(json_object_get(jws, "sub"));
    if (!sub) {
        xsyslog(LOG_ERR, "Missing \"sub\" claim", NULL);
        goto done;
    }

    if (json_object_size(jws) == 2) {
        json_t *jiat = json_object_get(jws, "iat");
        if (!json_is_integer(jiat)) {
            if (jiat) {
                char *val = json_dumps(jiat, JSON_COMPACT|JSON_ENCODE_ANY);
                xsyslog(LOG_ERR, "Invalid \"iat\" claim", "iat=<%s>", val);
                free(val);
            }
            else xsyslog(LOG_ERR, "JWT contains unsupported claims", NULL);
            goto done;
        }

        if (max_age) {
            time_t iat = json_integer_value(jiat);
            time_t now = time(NULL);
            if (iat + max_age <= now || iat > now) {
                char *val = json_dumps(jiat, JSON_COMPACT|JSON_ENCODE_ANY);
                xsyslog(LOG_ERR, "Out-of-range \"iat\" claim", "iat=<%s>", val);
                free(val);
                goto done;
            }
        }
    }
    else if (max_age) {
        xsyslog(LOG_ERR, "Missing \"iat\" claim", NULL);
        goto done;
    }

    size_t sublen = strlen(sub);
    if (sublen >= outlen) {
        xsyslog(LOG_ERR, "Excessively long \"sub\" claim value",
                "length=<%zu> maxlength=<%zu>", sublen, outlen-1);
        goto done;
    }
    strncpy(out, sub, outlen);

    ret = 1;

done:
    json_decref(jws);
    return ret;
}

HIDDEN int http_jwt_auth(const char *in, size_t inlen, char *out, size_t outlen)
{
    if (!is_enabled) {
        xsyslog(LOG_INFO, "JSON Web Token authentication is disabled", NULL);
        return SASL_BADAUTH;
    }

    assert(in && inlen);
    assert(out && outlen);
    out[0] = '\0';

    struct jwt jwt = { 0 };
    int status = SASL_BADAUTH;

    if (!parse_token(&jwt, in, inlen))
        goto done;

    if (!validate_signature(&jwt))
        goto done;

    if (!validate_header(&jwt))
        goto done;

    if (!validate_payload(&jwt, out, outlen))
        goto done;

    // out now contains the 'sub' value
    status = SASL_OK;

done:
    buf_free(&jwt.buf);
    return status;
}
