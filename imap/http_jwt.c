/* http_jwt.c - HTTP JSON Web Token authentication */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <fts.h>
#include <string.h>
#include <syslog.h>

#include <sasl/saslutil.h>

#include "assert.h"
#include "global.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#include "http_jwt.h"

#include <openssl/err.h>

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
        if (!EVP_PKEY_is_a(pkey, "RSA")) {
            xsyslog_ev(LOG_ERR, "jwt.publickey.unsupported");
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
        xsyslog_ev(LOG_ERR, "jwt.keyfile.open.failed",
                   lf_s("sys.path", fname));
        goto done;
    }

    while (buf_getline(&line, fp)) {
        linenum++;

        buf_trim(&line);
        if (!buf_len(&line))
            continue;

        if (!strcmp("-----BEGIN PUBLIC KEY-----", buf_cstring(&line))) {
            if (state != NONE) {
                xsyslog_ev(LOG_ERR, "jwt.keyfile.invalid",
                           lf_s("sys.path", fname),
                           lf_zu("jwt.lineno", linenum),
                           lf_s("jwt.reason", "unexpected_line"));
                goto done;
            }
            buf_append(&buf, &line);
            buf_putc(&buf, '\n');
            state = PUBLIC;
            continue;
        }

        if (!strcmp("-----END PUBLIC KEY-----", buf_cstring(&line))) {
            if (state != PUBLIC) {
                xsyslog_ev(LOG_ERR, "jwt.keyfile.invalid",
                           lf_s("sys.path", fname),
                           lf_zu("jwt.lineno", linenum),
                           lf_s("jwt.reason", "unexpected_line"));
                goto done;
            }
            buf_append(&buf, &line);
            buf_putc(&buf, '\n');

            EVP_PKEY *pkey = read_public_key(&buf);
            if (!pkey) {
                xsyslog_ev(LOG_ERR, "jwt.keyfile.invalid",
                           lf_s("sys.path", fname),
                           lf_zu("jwt.lineno", linenum),
                           lf_s("jwt.reason", "invalid_public_key"));
                goto done;
            }
            ptrarray_append(keys, pkey);

            buf_reset(&buf);
            state = NONE;
            continue;
        }

        if (!strcmp("-----BEGIN HMAC KEY-----", buf_cstring(&line))) {
            if (state != NONE) {
                xsyslog_ev(LOG_ERR, "jwt.keyfile.invalid",
                           lf_s("sys.path", fname),
                           lf_zu("jwt.lineno", linenum),
                           lf_s("jwt.reason", "unexpected_line"));
                goto done;
            }
            state = HMAC;
            continue;
        }

        if (!strcmp("-----END HMAC KEY-----", buf_cstring(&line))) {
            if (state != HMAC) {
                xsyslog_ev(LOG_ERR, "jwt.keyfile.invalid",
                           lf_s("sys.path", fname),
                           lf_zu("jwt.lineno", linenum),
                           lf_s("jwt.reason", "unexpected_line"));
                goto done;
            }

            EVP_PKEY *pkey = read_hmac_key(&buf);
            if (!pkey) {
                xsyslog_ev(LOG_ERR, "jwt.keyfile.invalid",
                           lf_s("sys.path", fname),
                           lf_zu("jwt.lineno", linenum),
                           lf_s("jwt.reason", "invalid_hmac_key"));
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

#ifndef HAVE_FTS
    return 0;
#else
    int r = -1;

    char *paths[2] = { (char *) keydir, NULL };
    FTS *fts = fts_open(paths, 0, NULL);
    if (!fts) {
        xsyslog_ev(LOG_ERR, "jwt.keydir.open.failed",
                   lf_s("sys.path", keydir));
        goto done;
    }

    if (age < 0) {
        xsyslog_ev(LOG_ERR, "jwt.maxage.invalid", lf_d("jwt.maxage", age));
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
                xsyslog_ev(LOG_ERR, "jwt.keyfile.read.failed",
                           lf_s("sys.path", fe->fts_accpath));
                goto done;
            }
        }
    }

    if (!ptrarray_size(&pkeys)) {
        xsyslog_ev(LOG_ERR, "jwt.keydir.empty", lf_s("sys.path", keydir));
        goto done;
    }

    is_enabled = 1;
    r = 0;

done:
    if (fts) fts_close(fts);
    if (r) http_jwt_reset();
    return r;
#endif /* HAVE_FTS */
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

        xsyslog_ev(LOG_WARNING, "jwt.token.invalid",
                   lf_s("jwt.reason", "invalid_character"),
                   lf_llx("jwt.token.byte", in[i] & 0xff),
                   lf_zu("jwt.token.offset", i));
        return 0;
    }
    if (ndot != 2 || dot[0] == 0 || dot[1] == inlen-1 || dot[1] - dot[0] <= 1) {
        xsyslog_ev(LOG_WARNING, "jwt.token.invalid",
                   lf_s("jwt.reason", "bad_jws_structure"));
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

static int validate_pkey_type(struct jwt *jwt, EVP_PKEY *pkey)
{
    if (!jwt->nid)
        return 0;

    if (jwt->nid == EVP_PKEY_HMAC && EVP_PKEY_is_a(pkey, "HMAC"))
        return 1;

    if (jwt->nid == EVP_PKEY_RSA && EVP_PKEY_is_a(pkey, "RSA"))
        return 1;

    return 0;
}

/* The message for the OpenSSL error that failed the last call, if any.
 *
 * The call's own return value is just a flag: the detail is on the thread's
 * error queue, and reading it clears it.
 */
static const char *ssl_error_string(void)
{
    unsigned long err = ERR_get_error();
    return err ? ERR_error_string(err, NULL) : NULL;
}

static int validate_signature(struct jwt *jwt)
{
    buf_reset(&jwt->buf);

    if (charset_decode(&jwt->buf, jwt->sig, jwt->siglen, ENCODING_BASE64URL)) {
        xsyslog_ev(LOG_WARNING, "jwt.token.invalid",
                   lf_s("jwt.reason", "undecodable_signature"));
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

        if (!validate_pkey_type(jwt, pkey))
            continue;

        if (jwt->nid == EVP_PKEY_HMAC) {
            unsigned char md[EVP_MAX_MD_SIZE];
            size_t mdlen = sizeof(md);

            int r = EVP_DigestSignInit(ctx, NULL, jwt->emd, NULL, pkey);
            if (r != 1) {
                xsyslog_ev(LOG_ERR, "jwt.signature.check.failed",
                           lf_s("jwt.step", "digest_init"),
                           lf_s_opt("error", ssl_error_string()));
                continue;
            }

            r = EVP_DigestSignUpdate(ctx, tok, toklen);
            if (r != 1) {
                xsyslog_ev(LOG_ERR, "jwt.signature.check.failed",
                           lf_s("jwt.step", "digest_update"),
                           lf_s_opt("error", ssl_error_string()));
                continue;
            }

            r = EVP_DigestSignFinal(ctx, md, &mdlen);
            if (r != 1) {
                xsyslog_ev(LOG_ERR, "jwt.signature.check.failed",
                           lf_s("jwt.step", "digest_final"),
                           lf_s_opt("error", ssl_error_string()));
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
                xsyslog_ev(LOG_ERR, "jwt.signature.check.failed",
                           lf_s("jwt.step", "verify_init"),
                           lf_s_opt("error", ssl_error_string()));
                continue;
            }

            r = EVP_DigestVerifyUpdate(ctx, tok, toklen);
            if (r != 1) {
                xsyslog_ev(LOG_ERR, "jwt.signature.check.failed",
                           lf_s("jwt.step", "verify_update"),
                           lf_s_opt("error", ssl_error_string()));
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
        xsyslog_ev(LOG_WARNING, "jwt.token.invalid",
                   lf_s("jwt.reason", "undecodable_header"));
        return 0;
    }

    int ret = 0;

    json_t *joh = json_loads(buf_cstring(&jwt->buf), JSON_REJECT_DUPLICATES, NULL);
    if (json_object_size(joh) != 2) {
        xsyslog_ev(LOG_WARNING, "jwt.token.invalid",
                   lf_s("jwt.reason", "bad_header_structure"));
        goto done;
    }

    const char *typ = json_string_value(json_object_get(joh, "typ"));
    if (strcmpsafe(typ, "JWT")) {
        xsyslog_ev(LOG_WARNING, "jwt.claim.invalid",
                   lf_s("jwt.claim", "typ"),
                   lf_s("jwt.reason", "unsupported"),
                   lf_s("jwt.claim.value", typ));
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
        xsyslog_ev(LOG_WARNING, "jwt.claim.invalid",
                   lf_s("jwt.claim", "alg"),
                   lf_s("jwt.reason", "unsupported"),
                   lf_s("jwt.claim.value", alg));
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
        xsyslog_ev(LOG_WARNING, "jwt.token.invalid",
                   lf_s("jwt.reason", "undecodable_payload"));
        return 0;
    }

    time_t now = time(NULL);
    int ret = 0;

    json_t *jws = json_loads(buf_cstring(&jwt->buf), JSON_REJECT_DUPLICATES, NULL);
    if (!json_object_size(jws)) {
        xsyslog_ev(LOG_WARNING, "jwt.token.invalid",
                   lf_s("jwt.reason", "bad_payload_structure"));
        goto done;
    }

    const char *sub = json_string_value(json_object_get(jws, "sub"));
    if (!sub) {
        xsyslog_ev(LOG_WARNING, "jwt.claim.invalid",
                   lf_s("jwt.claim", "sub"),
                   lf_s("jwt.reason", "missing"));
        goto done;
    }

    // Parse claims
    int has_err = 0;

    json_t *jnbf = json_object_get(jws, "nbf");
    if (jnbf && !json_is_integer(jnbf)) {
        xsyslog_ev(LOG_WARNING, "jwt.claim.invalid",
                   lf_s("jwt.claim", "nbf"),
                   lf_s("jwt.reason", "not_an_integer"));
        has_err = 1;
    }

    json_t *jexp = json_object_get(jws, "exp");
    if (jexp && !json_is_integer(jexp)) {
        xsyslog_ev(LOG_WARNING, "jwt.claim.invalid",
                   lf_s("jwt.claim", "exp"),
                   lf_s("jwt.reason", "not_an_integer"));
        has_err = 1;
    }

    json_t *jiat = json_object_get(jws, "iat");
    if (jiat && !json_is_integer(jiat)) {
        xsyslog_ev(LOG_WARNING, "jwt.claim.invalid",
                   lf_s("jwt.claim", "iat"),
                   lf_s("jwt.reason", "not_an_integer"));
        has_err = 1;
    }

    if (has_err)
        goto done;

    // Validate claims

    if (jnbf) {
        time_t nbf = json_integer_value(jnbf);
        if (!(now >= nbf)) {
            xsyslog_ev(LOG_WARNING, "jwt.claim.invalid",
                       lf_s("jwt.claim", "nbf"),
                       lf_s("jwt.reason", "out_of_range"));
            goto done;
        }
    }

    if (jexp) {
        time_t exp = json_integer_value(jexp);
        if (!(now < exp)) {
            xsyslog_ev(LOG_WARNING, "jwt.claim.invalid",
                       lf_s("jwt.claim", "exp"),
                       lf_s("jwt.reason", "out_of_range"));
            goto done;
        }
    }

    if (max_age && !jexp) { // exp has precedence over iat claim
        if (jiat) {
            time_t iat = json_integer_value(jiat);
            if (iat + max_age <= now || iat > now) {
                xsyslog_ev(LOG_WARNING, "jwt.claim.invalid",
                           lf_s("jwt.claim", "iat"),
                           lf_s("jwt.reason", "out_of_range"));
                goto done;
            }
        }
        else {
            xsyslog_ev(LOG_WARNING, "jwt.claim.invalid",
                       lf_s("jwt.claim", "iat"),
                       lf_s("jwt.reason", "missing"));
            goto done;
        }
    }

    size_t sublen = strlen(sub);
    if (sublen >= outlen) {
        xsyslog_ev(LOG_WARNING, "jwt.claim.invalid",
                   lf_s("jwt.claim", "sub"),
                   lf_s("jwt.reason", "too_long"),
                   lf_zu("jwt.claim.length", sublen),
                   lf_zu("jwt.claim.maxlength", outlen-1));
        goto done;
    }

    // All fine!
    strncpy(out, sub, outlen);
    ret = 1;

done:
    json_decref(jws);
    return ret;
}

HIDDEN int http_jwt_auth(const char *in, size_t inlen, char *out, size_t outlen)
{
    if (!is_enabled) {
        xsyslog_ev(LOG_INFO, "jwt.auth.disabled");
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
