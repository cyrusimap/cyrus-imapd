/* jmapauth.c -- Routines for JMAP authentication
 *
 * Copyright (c) 1994-2014 Carnegie Mellon University.  All rights reserved.
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

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#ifdef HAVE_SSL
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif /* HAVE_SSL */

#include "append.h"
#include "cyrusdb.h"
#include "hash.h"
#include "httpd.h"
#include "http_dav.h"
#include "http_proxy.h"
#include "mboxname.h"
#include "proxy.h"
#include "times.h"
#include "syslog.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#include "jmapauth.h"

#define FNAME_JMAPAUTH "/jmapauth.db"

#define DB config_jmapauth_db

#define JMAPAUTH_TOKEN_VERSION 1      /* version of token encoding scheme */
#define JMAPAUTH_KEY_LEN (JMAPAUTH_SESSIONID_LEN + 2) /* length of db key */

EXPORTED struct jmapauth_token *jmapauth_token_new(const char *userid,
               char kind, const void *data, size_t datalen)
{
    struct jmapauth_token *tok = xzmalloc(sizeof(struct jmapauth_token));

    tok->userid = xstrdup(userid);
    tok->version = JMAPAUTH_TOKEN_VERSION;
    tok->kind = kind;
    tok->lastuse = time(NULL);
    tok->data = data;
    tok->datalen = datalen;
    RAND_bytes((unsigned char *) tok->sessionid, JMAPAUTH_SESSIONID_LEN);
    RAND_bytes((unsigned char *) tok->secret, JMAPAUTH_SECRET_LEN);

    return tok;
}

EXPORTED void jmapauth_token_free(struct jmapauth_token *tok)
{
    if (tok) {
        free(tok->userid);
        free(tok);
    }
}

static int make_key(struct buf *buf, const struct jmapauth_token *tok)
{
    /* Concatenate version, kind and the session id */
    buf_putc(buf, tok->version);
    buf_putc(buf, tok->kind);
    buf_appendmap(buf, tok->sessionid, JMAPAUTH_SESSIONID_LEN);
    return 0;
}

EXPORTED char *jmapauth_tokenid(const struct jmapauth_token *tok)
{
    struct buf buf = BUF_INITIALIZER;
    unsigned mdlen, hexlen;
    char macbuf[EVP_MAX_MD_SIZE];
    char hexbuf[(JMAPAUTH_KEY_LEN + EVP_MAX_MD_SIZE)*2];
    int r;

    /* Build the key */
    r = make_key(&buf, tok);
    if (r) return NULL;

    /* Sign the extended key */
    if (!(HMAC(EVP_sha1(), tok->secret, JMAPAUTH_SECRET_LEN,
               (unsigned char*) buf.s, buf.len,
               (unsigned char*) macbuf, &mdlen))) {
        buf_free(&buf);
        return NULL;
    }
    buf_appendmap(&buf, macbuf, mdlen);

    /* And return it hex-encoded */
    hexlen = bin_to_hex(buf.s, buf.len, hexbuf, 0);
    if (hexlen != (mdlen + JMAPAUTH_KEY_LEN)*2) {
        buf_free(&buf);
        return NULL;
    }

    buf_free(&buf);
    return xstrndup(hexbuf, hexlen);
}

static char *decode_id(const char *raw)
{
    int hexlen;
    char hexbuf[(JMAPAUTH_KEY_LEN + EVP_MAX_MD_SIZE)*2];
    char *key = NULL;
    size_t lenraw = strlen(raw);

    /* Verify that the key is at least good for lookups */
    if (lenraw > sizeof(hexbuf)/sizeof(hexbuf[0])) {
        return NULL;
    }
    hexlen = hex_to_bin(raw, lenraw, hexbuf);
    if (hexlen < JMAPAUTH_KEY_LEN) {
        return NULL;
    }
    if ((hexbuf[0] != JMAPAUTH_TOKEN_VERSION) ||
        (hexbuf[1] != JMAPAUTH_LOGINID_KIND &&
         hexbuf[1] != JMAPAUTH_ACCESS_KIND)) {
        return NULL;
    }

    key = xmalloc(JMAPAUTH_KEY_LEN);
    memcpy(key, hexbuf, JMAPAUTH_KEY_LEN);
    return key;
}

EXPORTED int jmapauth_open(struct db **dbptr, int db_flags, const char *fname)
{
    int r = 0;
    char *tofree = NULL;

    assert(dbptr);

    if (!fname) {
        fname = config_getstring(IMAPOPT_JMAPAUTH_DB_PATH);
    }

    /* create db file name */
    if (!fname) {
        tofree = strconcat(config_dir, FNAME_JMAPAUTH, (char*)NULL);
        fname = tofree;
    }

    /* open the database */
    r = cyrusdb_open(DB, fname, db_flags, dbptr);
    if (r) {
        if (r != CYRUSDB_NOTFOUND) {
            syslog(LOG_ERR, "JMAP auth: cannot open db %s: %s",
                    fname, cyrusdb_strerror(r));
        }
        return r;
    }

    free(tofree);
    return r;
}

static int token_parse(const char *key, const char *data, size_t datalen,
                       struct jmapauth_token *tok)
{
    int r = CYRUSDB_INTERNAL;
    uint16_t u16;

    /* kind, version and id are derived from key */
    tok->version = key[0];
    tok->kind = key[1];
    memcpy(tok->sessionid, key + 2, JMAPAUTH_SESSIONID_LEN);

    /* userid */
    if (datalen < sizeof(uint16_t)) goto done;
    u16 = ntohs(*(uint16_t*) data);
    datalen -= sizeof(uint16_t);
    data += sizeof(uint16_t);

    if (datalen < u16) goto done;
    tok->userid = xstrndup(data, u16);
    datalen -= u16;
    data += u16;

    /* lastuse */
    if (datalen < sizeof(uint64_t)) goto done;
    tok->lastuse = (time_t) ntohll(*(uint64_t*) data);
    datalen -= sizeof(uint64_t);
    data += sizeof(uint64_t);

    /* flags */
    if (!datalen) goto done;
    tok->flags = *data++;
    datalen--;

    /* secret */
    if (datalen < JMAPAUTH_SECRET_LEN) goto done;
    memcpy(tok->secret, data, JMAPAUTH_SECRET_LEN);
    datalen -= JMAPAUTH_SECRET_LEN;
    data += JMAPAUTH_SECRET_LEN;

    /* payload data */
    tok->data = data;
    tok->datalen = datalen;

    /* all fine */
    r = 0;
done:
    return r;
}

EXPORTED int jmapauth_is_expired(struct jmapauth_token *tok)
{
    time_t ttl, now = time(NULL);

    switch (tok->kind) {
        case JMAPAUTH_LOGINID_KIND:
            ttl = config_jmapauth_loginid_ttl;
            break;
        case JMAPAUTH_ACCESS_KIND:
            if (!config_jmapauth_token_ttl) {
                return 0;
            }
            ttl = config_jmapauth_token_ttl + JMAPAUTH_TOKEN_TTL_WINDOW;
            break;
        default:
            syslog(LOG_ERR, "jmapauth: unexpected token kind: %c", tok->kind);
            return 1;
    }

    return now - tok->lastuse > ttl;
}

struct jmapauth_find_data {
    /* Internal callback data */
    struct db *db;
    struct txn **tidptr;
    struct jmapauth_token tok;

    /* Search criteria */
    const char *userid; /* match tokens owned by userid */
    int expired;        /* match tokens that are expired */
    time_t lastuse;     /* match tokens last used before lastuse */
    char kind;          /* match tokens with kind */

    /* User-supplied callback and data */
    jmapauth_find_proc_t proc;
    void *rock;
};

static int jmapauth_find_p(void *rock,
                           const char *key __attribute__((unused)),
                           size_t keylen __attribute__((unused)),
                           const char *data __attribute__((unused)),
                           size_t datalen __attribute__((unused)))
{
    struct jmapauth_find_data *cbdata = rock;

    if (keylen < JMAPAUTH_KEY_LEN) {
        return CYRUSDB_INTERNAL;
    }

    memset(&cbdata->tok, 0, sizeof(struct jmapauth_token));
    if (token_parse(key, data, datalen, &cbdata->tok)) {
        return 0;
    }

    if (cbdata->userid && strcmp(cbdata->userid, cbdata->tok.userid)) {
        return 0;
    }

    if (cbdata->lastuse && cbdata->tok.lastuse >= cbdata->lastuse) {
        return 0;
    }

    if (cbdata->kind && cbdata->tok.kind != cbdata->kind) {
        return 0;
    }

    if (cbdata->expired && !jmapauth_is_expired(&cbdata->tok)) {
        return 0;
    }

    return 1;
}

static int jmapauth_find_cb(void *rock,
                            const char *key __attribute__((unused)),
                            size_t keylen __attribute__((unused)),
                            const char *data __attribute__((unused)),
                            size_t datalen __attribute__((unused)))
{
    struct jmapauth_find_data *cbdata = rock;

    /* jmapauth_find_p already has unmarshalled data into a token */
    return cbdata->proc(cbdata->db, &cbdata->tok, cbdata->rock, cbdata->tidptr);
}

EXPORTED int jmapauth_find(struct db *db, const char *userid, int expired,
                           time_t lastuse, char kind,
                           jmapauth_find_proc_t proc, void *rock,
                           struct txn **tidptr)
{
    struct jmapauth_find_data cbdata;

    memset(&cbdata, 0, sizeof(struct jmapauth_find_data));
    cbdata.db = db;
    cbdata.tidptr = tidptr;
    cbdata.userid = userid;
    cbdata.expired = expired;
    cbdata.lastuse = lastuse;
    cbdata.kind = kind;
    cbdata.proc = proc;
    cbdata.rock = rock;

    return cyrusdb_foreach(db, NULL, 0,
                           jmapauth_find_p, jmapauth_find_cb,
                           &cbdata, tidptr);
}


/*
 * Fetch the auth token identified by tokenid from db
 *
 * Returns
 * - CYRUSDB_OK       on success
 * - CYRUSDB_NOTFOUND if tokenid does not exist
 * - CYRUSDB_EXISTS   if tokenid exists but is signed incorrectly
 * - CYRUSDB_INTERNAL if tokenid is invalid, or an internal error
 * or any other defined cyrusdb error.
 *
 * fetch_flags options:
 * - JMAPAUTH_FETCH_LOCK:    force a lock on db before fetching
 */
EXPORTED int jmapauth_fetch(struct db *db, const char *tokenid,
                            struct jmapauth_token **tokptr, int fetch_flags,
                            struct txn **tidptr)
{
    int r;
    const char *data;
    size_t datalen;
    struct jmapauth_token *tok = NULL;
    char *key = NULL, *signed_key = NULL;

    /* Split tokenid into key and signature */
    key = decode_id(tokenid);
    if (!key) {
        return CYRUSDB_NOTFOUND;
    }

    /* Fetch record */
    r = (fetch_flags & JMAPAUTH_FETCH_LOCK) ?
        cyrusdb_fetchlock(db, key, JMAPAUTH_KEY_LEN, &data, &datalen, tidptr) :
        cyrusdb_fetch(db, key, JMAPAUTH_KEY_LEN, &data, &datalen, tidptr);
    if (r) goto done;

    /* Parse db entry into token */
    tok = xzmalloc(sizeof(struct jmapauth_token));
    r = token_parse(key, data, datalen, tok);
    if (r) {
        jmapauth_token_free(tok);
        tok = NULL;
        goto done;
    }

    /* Verify token signature */
    signed_key = jmapauth_tokenid(tok);
    if (!signed_key || strcmp(tokenid, signed_key)) {
        jmapauth_token_free(tok);
        tok = NULL;
        r = CYRUSDB_EXISTS;
        goto done;
    }

done:
    free(signed_key);
    if (tok) *tokptr = tok;
    free(key);
    return r;
}

EXPORTED int jmapauth_store(struct db *db, struct jmapauth_token *tok,
                            struct txn **tidptr)
{
    int r;
    struct buf buf = BUF_INITIALIZER;
    uint16_t u16;
    uint64_t u64;
    size_t len;

    if (tok->datalen > UINT16_MAX) {
        return CYRUSDB_FULL;
    }

    /* userid */
    len = strlen(tok->userid);
    if  (len > UINT16_MAX) {
        r = CYRUSDB_FULL;
        goto done;
    }
    u16 = htons((uint16_t) len);
    buf_appendmap(&buf, (char*) &u16, sizeof(uint16_t));
    buf_appendmap(&buf, tok->userid, len);

    /* lastuse */
    u64 = htonll((uint64_t) tok->lastuse);
    buf_appendmap(&buf, (char*) &u64, sizeof(uint64_t));

    /* flags */
    buf_appendmap(&buf, &tok->flags, sizeof(char));

    /* secret */
    buf_appendmap(&buf, tok->secret, JMAPAUTH_SECRET_LEN);

    /* payload data */
    buf_appendmap(&buf, tok->data, tok->datalen);

    struct buf key = BUF_INITIALIZER;
    r = make_key(&key, tok);
    if (r) goto done;

    r = cyrusdb_store(db, key.s, key.len, buf.s, buf.len, tidptr);
    buf_free(&key);

done:
    buf_free(&buf);
    return r;
}

EXPORTED int jmapauth_delete(struct db *db, const char *tokenid, struct txn **tidptr)
{
    struct txn *mytid = NULL;
    struct jmapauth_token *tok = NULL;
    struct buf dbkey = BUF_INITIALIZER;
    int r;

    /* Always operate within a transaction */
    if (!tidptr) tidptr = &mytid;

    /* Lookup the token. This also validates the signature of tokenid. */
    r = jmapauth_fetch(db, tokenid, &tok, 0, tidptr);
    if (r) goto done;

    /* Remove the entry */
    make_key(&dbkey, tok);
    r = cyrusdb_delete(db, buf_cstring(&dbkey), JMAPAUTH_KEY_LEN, tidptr, 1);
    if (r) goto done;

    /* Commit, if we aren't within a transaction */
    if (tidptr == &mytid) {
        r = cyrusdb_commit(db, mytid);
    }

done:
    jmapauth_token_free(tok);
    if (r && tidptr == &mytid) {
        cyrusdb_abort(db, mytid);
    }
    buf_free(&dbkey);
    return r;
}

EXPORTED int jmapauth_close(struct db *db)
{
    return db ? cyrusdb_close(db) : 0;
}
