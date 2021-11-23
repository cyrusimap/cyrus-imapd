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

#include <sys/stat.h>
#include <sys/types.h>

#include <fts.h>
#include <string.h>
#include <syslog.h>

#include <openssl/err.h>
#include <sasl/saslutil.h>

#include "assert.h"
#include "global.h"
#include "http_err.h"
#include "util.h"

#include "http_jwt.h"

static int is_enabled = 0;

static ptrarray_t pkeys = PTRARRAY_INITIALIZER;

static time_t max_age = 0;

struct jwt {
    // Base64 parts
    const char *joh;
    size_t johlen;
    const char *jws;
    size_t jwslen;
    const char *sig;
    size_t siglen;

    int nid;
    const EVP_MD *emd;
    struct buf buf;
};

static inline int is_base64url_char(char c)
{
    return ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c == '-' || c == '_'));
}

HIDDEN int http_jwt_reset(void)
{
    EVP_PKEY *pkey;
    while ((pkey = ptrarray_pop(&pkeys)))
        EVP_PKEY_free(pkey);
    is_enabled = 0;
    max_age = 0;
    return 0;
}

static EVP_PKEY *read_hmac_key(struct buf *b64)
{
    struct buf dec = BUF_INITIALIZER;
    EVP_PKEY *pkey = NULL;

    if (!charset_decode(&dec, buf_base(b64), buf_len(b64), ENCODING_BASE64)) {
        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL,
                (unsigned char*)buf_base(&dec), buf_len(&dec));
    }

    buf_free(&dec);
    return pkey;
}

static EVP_PKEY *read_public_key(struct buf *pem)
{
    BIO *bp = BIO_new_mem_buf(buf_base(pem), buf_len(pem));
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);

    if (pkey) {
        int nid = EVP_PKEY_base_id(pkey);
        if (nid != EVP_PKEY_RSA) {
            xsyslog(LOG_ERR, "Unsupported public key",
                    "type=<%s>", OBJ_nid2ln(nid));
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
    }

    BIO_free(bp);
    return pkey;
}

static int read_keyfile(const char *fname, ptrarray_t *keys)
{
    struct buf line = BUF_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    enum state { NONE, PUBLIC, HMAC } state = NONE;
    size_t linenum = 0;
    int r = -1;

    FILE *fp = fopen(fname, "r");
    if (!fp) {
        xsyslog(LOG_ERR, "Can not open key file", "fname=<%s>", fname);
        goto done;
    }

    while (buf_getline(&line, fp)) {
        linenum++;

        buf_trim(&line);
        if (!buf_len(&line))
            continue;

        if (!strcmp("-----BEGIN PUBLIC KEY-----", buf_cstring(&line))) {
            if (state != NONE) {
                xsyslog(LOG_ERR, "Unexpected line", "linenum=<%zu>", linenum);
                goto done;
            }
            buf_append(&buf, &line);
            buf_putc(&buf, '\n');
            state = PUBLIC;
            continue;
        }

        if (!strcmp("-----END PUBLIC KEY-----", buf_cstring(&line))) {
            if (state != PUBLIC) {
                xsyslog(LOG_ERR, "Unexpected line", "linenum=<%zu>", linenum);
                goto done;
            }
            buf_append(&buf, &line);
            buf_putc(&buf, '\n');

            EVP_PKEY *pkey = read_public_key(&buf);
            if (!pkey) {
                xsyslog(LOG_ERR, "Invalid public key", "linenum=<%zu>", linenum);
                goto done;
            }
            ptrarray_append(keys, pkey);

            buf_reset(&buf);
            state = NONE;
            continue;
        }

        if (!strcmp("-----BEGIN HMAC KEY-----", buf_cstring(&line))) {
            if (state != NONE) {
                xsyslog(LOG_ERR, "Unexpected line", "linenum=<%zu>", linenum);
                goto done;
            }
            state = HMAC;
            continue;
        }

        if (!strcmp("-----END HMAC KEY-----", buf_cstring(&line))) {
            if (state != HMAC) {
                xsyslog(LOG_ERR, "Unexpected line", "linenum=<%zu>", linenum);
                goto done;
            }

            EVP_PKEY *pkey = read_hmac_key(&buf);
            if (!pkey) {
                xsyslog(LOG_ERR, "Invalid hmac key", "linenum=<%zu>", linenum);
                goto done;
            }
            ptrarray_append(keys, pkey);

            buf_reset(&buf);
            state = NONE;
            continue;
        }

        if (state == NONE)
            continue;

        buf_append(&buf, &line);
        buf_putc(&buf, '\n');
    }

    r = 0;

done:
    if (fp) fclose(fp);
    buf_free(&buf);
    buf_free(&line);
    return r;
}

HIDDEN int http_jwt_init(const char *keydir, int age)
{
    http_jwt_reset();

    int r = -1;

    char *paths[2] = { (char *) keydir, NULL };
    FTS *fts = fts_open(paths, 0, NULL);
    if (!fts) {
        xsyslog(LOG_ERR, "Can not open keydir", "keydir=<%s>", keydir);
        goto done;
    }

    if (age < 0) {
        xsyslog(LOG_ERR, "Maximum age must not be negative", "age=<%d>", age);
        goto done;
    }
    max_age = age;

    FTSENT *fe;
    while ((fe = fts_read(fts))) {
        if (fe->fts_info == FTS_D && fe->fts_level > 0) {
            // do not descend into directories
            fts_set(fts, fe, FTS_SKIP);
            continue;
        }

        if (fe->fts_info == FTS_F || fe->fts_info == FTS_SL) {
            r = read_keyfile(fe->fts_accpath, &pkeys);
            if (r) {
                xsyslog(LOG_ERR, "Can not read keyfile", "keyfile=<%s>", fe->fts_accpath);
                goto done;
            }
        }
    }

    if (!ptrarray_size(&pkeys)) {
        xsyslog(LOG_ERR, "No keys found in keydir", "keydir=<%s>", keydir);
        goto done;
    }

    is_enabled = 1;
    r = 0;

done:
    if (fts) fts_close(fts);
    if (r) http_jwt_reset();
    return r;
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

    if (charset_decode(&jwt->buf, jwt->sig, jwt->siglen, ENCODING_BASE64URL)) {
        xsyslog(LOG_ERR, "Cannot decode token signature", NULL);
        return 0;
    }

    const unsigned char *tok = (const unsigned char*) jwt->joh;
    size_t toklen = jwt->johlen + jwt->jwslen + 1;
    const char *sig = buf_cstring(&jwt->buf);
    size_t siglen = buf_len(&jwt->buf);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ret = 0;

    int i;
    for (i = 0; i < ptrarray_size(&pkeys); i++) {
        EVP_PKEY *pkey = ptrarray_nth(&pkeys, i);
        EVP_MD_CTX_reset(ctx);

        if (jwt->nid != EVP_PKEY_base_id(pkey))
            continue;

        if (jwt->nid == EVP_PKEY_HMAC) {
            unsigned char md[EVP_MAX_MD_SIZE];
            size_t mdlen = sizeof(md);

            int r = EVP_DigestSignInit(ctx, NULL, jwt->emd, NULL, pkey);
            if (r != 1) {
                xsyslog(LOG_ERR, "Cannot initialize digest context",
                        "sslerr=<%s>", ERR_error_string(r, NULL));
                continue;
            }

            r = EVP_DigestSignUpdate(ctx, tok, toklen);
            if (r != 1) {
                xsyslog(LOG_ERR, "Cannot update digest context",
                        "sslerr=<%s>", ERR_error_string(r, NULL));
                continue;
            }

            r = EVP_DigestSignFinal(ctx, md, &mdlen);
            if (r != 1) {
                xsyslog(LOG_ERR, "Cannot finalize digest context",
                        "sslerr=<%s>", ERR_error_string(r, NULL));
                continue;
            }

            if (mdlen == siglen && !CRYPTO_memcmp(md, sig, mdlen)) {
                ret = 1;
                break;
            }
        }
        else {
            int r = EVP_DigestVerifyInit(ctx, NULL, jwt->emd, NULL, pkey);
            if (r != 1) {
                xsyslog(LOG_ERR, "Cannot initialize verify context",
                        "sslerr=<%s>", ERR_error_string(r, NULL));
                continue;
            }

            r = EVP_DigestVerifyUpdate(ctx, tok, toklen);
            if (r != 1) {
                xsyslog(LOG_ERR, "Cannot update verify context",
                        "sslerr=<%s>", ERR_error_string(r, NULL));
                continue;
            }

            ret = EVP_DigestVerifyFinal(ctx, (const unsigned char*)sig, siglen) == 1;
        }
    }

    EVP_MD_CTX_free(ctx);
    return ret;
}

static int validate_header(struct jwt *jwt)
{
    buf_reset(&jwt->buf);

    if (charset_decode(&jwt->buf, jwt->joh, jwt->johlen, ENCODING_BASE64URL)) {
        xsyslog(LOG_ERR, "Cannot decode JOSE header", NULL);
        return 0;
    }

    int ret = 0;

    json_t *joh = json_loads(buf_cstring(&jwt->buf), JSON_REJECT_DUPLICATES, NULL);
    if (json_object_size(joh) != 2) {
        xsyslog(LOG_ERR, "Unexpected JOSE header structure", NULL);
        goto done;
    }

    const char *typ = json_string_value(json_object_get(joh, "typ"));
    if (strcmpsafe(typ, "JWT")) {
        xsyslog(LOG_ERR, "Invalid \"typ\" claim", "typ=<%s>", typ);
        goto done;
    }

    const char *alg = json_string_value(json_object_get(joh, "alg"));
    jwt->nid = EVP_PKEY_NONE;
    jwt->emd = NULL;

    if (alg && strlen(alg) == 5 && alg[1] == 'S') {
        switch (alg[0]) {
            case 'H':
                jwt->nid = EVP_PKEY_HMAC;
                break;
            case 'R':
                jwt->nid = EVP_PKEY_RSA;
                break;
            default:
                ;
        }

        if (!strcmp(&alg[2], "256"))
            jwt->emd = EVP_sha256();
        else if (!strcmp(&alg[2], "384"))
            jwt->emd = EVP_sha384();
        else if (!strcmp(&alg[2], "512"))
            jwt->emd = EVP_sha512();
    }
    if (jwt->nid == EVP_PKEY_NONE || !jwt->emd) {
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

    json_t *jws = json_loads(buf_cstring(&jwt->buf), JSON_REJECT_DUPLICATES, NULL);
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

    if (!validate_header(&jwt))
        goto done;

    if (!validate_signature(&jwt))
        goto done;

    if (!validate_payload(&jwt, out, outlen))
        goto done;

    // out now contains the 'sub' value
    status = SASL_OK;

done:
    buf_free(&jwt.buf);
    return status;
}
