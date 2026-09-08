/* dkim2_mi.c - DKIM2 Message-Instance calculation */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <ctype.h>
#include <stdbool.h>
#include <string.h>

#include <jansson.h>
#include <openssl/evp.h>
#include <sasl/saslutil.h>

#include "bsearch.h"
#include "charset.h"
#include "dkim2_mi.h"
#include "strarray.h"
#include "util.h"
#include "xmalloc.h"

/* Section numbers below are draft-ietf-dkim-dkim2-spec-06. */

#define MI_HDR_NAME "message-instance"

/* Fold the emitted header field at this column.  Well short of the 998
 * octet line limit, and FWS is legal anywhere in the value - including
 * inside a base64string (§2.14), which the r= tag needs.
 */
#define MI_FOLD_COLUMN 76

/* ==================== header field block ==================== */

/* Split a header block into whole fields, each keeping its folds and its
 * terminating CRLF.  Stops at the blank line, so the same routine works on
 * a bare header block or on a complete message.
 */
static strarray_t *split_fields(const char *hdrs, size_t len)
{
    strarray_t *fields = strarray_new();
    const char *p = hdrs, *end = hdrs + len;

    while (p < end && *p != '\r' && *p != '\n') {
        const char *q = p;

        while (q < end) {
            const char *eol = memchr(q, '\n', end - q);
            if (!eol) { q = end; break; }
            q = eol + 1;
            if (q < end && (*q == ' ' || *q == '\t')) continue; /* folded */
            break;
        }

        strarray_appendm(fields, xstrndup(p, q - p));
        p = q;
    }

    return fields;
}

/* Lowercased field name of "Name: value", or NULL if there is no colon.
 * §6.2 deletes the WSP on both sides of the colon, so "Subject : x" has to
 * come back as the same name as "Subject: x".
 */
static char *field_name(const char *field)
{
    const char *colon = strchr(field, ':');
    if (!colon) return NULL;

    while (colon > field && (colon[-1] == ' ' || colon[-1] == '\t')) colon--;

    char *name = xstrndup(field, colon - field);
    lcase(name);

    return name;
}

/* Start of the value of "Name: value", past the colon and any leading WSP */
static const char *field_value(const char *field)
{
    const char *colon = strchr(field, ':');
    if (!colon) return NULL;

    const char *v = colon + 1;
    while (*v == ' ' || *v == '\t') v++;

    return v;
}

/* §4: header fields no DKIM2 hash or Recipe ever covers.  Message-Instance
 * and DKIM2-Signature join the list per §6.2 - they are covered by the
 * signature itself rather than by the hashes they carry.
 */
static bool field_is_unsigned(const char *lname)
{
    static const char *skip[] = {
        "apparently-to",
        "arc-authentication-results",
        "arc-message-signature",
        "arc-seal",
        "authentication-results",
        "auto-submitted",
        "delivered-to",
        "dkim-signature",
        "dkim2-signature",
        "dl-expansion-history",
        MI_HDR_NAME,
        "original-recipient",
        "received",
        "return-path",
        "sio-label-history",
        "vbr-info",
        "x400-received",
        "x400-trace",
        NULL
    };

    for (int i = 0; skip[i]; i++)
        if (!strcmp(lname, skip[i])) return true;

    /* x400-received and x400-trace match neither prefix, hence their entries */
    if (!strncmp(lname, "x-", 2)) return true;
    if (!strncmp(lname, "received-", 9)) return true;

    return false;
}

/* §6.2 canonicalisation: lowercase the name, unfold, collapse each run of
 * WSP to one SP, drop WSP around the colon and at the end of the value,
 * keep the final CRLF.  Returns NULL for a field that isn't hashed.
 */
static char *canon_field(const char *field)
{
    char *lname = field_name(field);
    if (!lname) return NULL;

    if (field_is_unsigned(lname)) {
        free(lname);
        return NULL;
    }

    struct buf buf = BUF_INITIALIZER;
    buf_appendcstr(&buf, lname);
    buf_putc(&buf, ':');
    free(lname);

    /* Starting inside a WSP run drops leading WSP wherever it sits: for a
     * field folded straight after the colon it is the continuation line's
     * own space, which only becomes leading once the CRLF is gone.
     */
    bool in_wsp = true;
    for (const char *v = strchr(field, ':') + 1; *v; v++) {
        if (*v == '\r' || *v == '\n') continue;
        if (*v == ' ' || *v == '\t') {
            if (!in_wsp) buf_putc(&buf, ' ');
            in_wsp = true;
        }
        else {
            buf_putc(&buf, *v);
            in_wsp = false;
        }
    }

    while (buf_len(&buf) && buf_base(&buf)[buf_len(&buf)-1] == ' ')
        buf_truncate(&buf, buf_len(&buf) - 1);

    buf_appendcstr(&buf, "\r\n");

    return buf_release(&buf);
}

/* ==================== hashing ==================== */

static void digest_b64(EVP_MD_CTX *ctx, struct buf *b64)
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = sizeof(digest);
    char enc[2 * EVP_MAX_MD_SIZE];
    unsigned enclen = 0;

    buf_reset(b64);

    if (EVP_DigestFinal_ex(ctx, digest, &dlen) != 1) return;
    if (sasl_encode64((char *) digest, dlen,
                      enc, sizeof(enc), &enclen) != SASL_OK) return;

    buf_setmap(b64, enc, enclen);
}

EXPORTED void dkim2_body_hash(const char *body, size_t bodylen, struct buf *b64)
{
    /* §6.1: "*CRLF" at the end of the body becomes "CRLF" */
    while (bodylen >= 2 && body[bodylen-2] == '\r' && body[bodylen-1] == '\n')
        bodylen -= 2;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, body, bodylen);
    EVP_DigestUpdate(ctx, "\r\n", 2);
    digest_b64(ctx, b64);
    EVP_MD_CTX_free(ctx);
}

/* Compare two canonicalised fields by name alone */
static int canon_name_cmp(const char *a, const char *b)
{
    const char *acolon = strchr(a, ':');
    const char *bcolon = strchr(b, ':');
    size_t alen = acolon - a, blen = bcolon - b;
    size_t cmplen = alen < blen ? alen : blen;

    int cmp = strncmp(a, b, cmplen);
    if (cmp) return cmp;

    return (alen > blen) - (alen < blen);
}

EXPORTED void dkim2_header_hash(const char *hdrs, size_t len, struct buf *b64)
{
    strarray_t *fields = split_fields(hdrs, len);
    strarray_t *canon = strarray_new();

    /* Collect bottom up so that same-name fields end up in the §6.2 order */
    for (int i = strarray_size(fields) - 1; i >= 0; i--) {
        char *c = canon_field(strarray_nth(fields, i));
        if (c) strarray_appendm(canon, c);
    }

    /* Insertion sort: §6.2 orders by name only, so same-name fields must
     * keep the order collected above and qsort(3) promises no such thing
     */
    for (int i = 1; i < strarray_size(canon); i++) {
        char *key = strarray_remove(canon, i);
        int j = i;
        while (j > 0 && canon_name_cmp(strarray_nth(canon, j-1), key) > 0) j--;
        strarray_insertm(canon, j, key);
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    for (int i = 0; i < strarray_size(canon); i++) {
        const char *c = strarray_nth(canon, i);
        EVP_DigestUpdate(ctx, c, strlen(c));
    }
    digest_b64(ctx, b64);
    EVP_MD_CTX_free(ctx);

    strarray_free(canon);
    strarray_free(fields);
}

/* ==================== Recipes (§5.1) ==================== */

/* Every instance of lname, bottom up (§5.1 numbers them from the last one
 * in the block upwards), canonicalised so that a refold isn't a change.
 */
static strarray_t *instances_of(const strarray_t *fields, const char *lname)
{
    strarray_t *out = strarray_new();

    for (int i = strarray_size(fields) - 1; i >= 0; i--) {
        const char *field = strarray_nth(fields, i);
        char *name = field_name(field);
        if (!name) continue;

        if (!strcmp(name, lname)) {
            char *c = canon_field(field);
            if (c) strarray_appendm(out, c);
        }
        free(name);
    }

    return out;
}

/* The value of a canonicalised field, without name, colon or CRLF: what a
 * "d" step emits.  Canonicalisation has already removed the CR and LF that
 * §5.1 forbids here.
 */
static char *recipe_value(const char *canon)
{
    const char *v = strchr(canon, ':') + 1;
    size_t len = strlen(v);

    while (len && (v[len-1] == '\r' || v[len-1] == '\n')) len--;

    return xstrndup(v, len);
}

/* Steps rebuilding want[] out of the instances in have[].  Copy the longest
 * run of have[] that matches at this point, otherwise emit values verbatim
 * until a run turns up again.
 *
 * §5.1 requires each "c" step to start beyond where the last one ended, so
 * the search only looks forward from there.  Anything already passed - a
 * reordering, most obviously - falls through to a "d" step, which can emit
 * any value in any order.
 */
static json_t *recipe_steps(const strarray_t *have, const strarray_t *want)
{
    json_t *steps = json_array();
    int wi = 0;
    int floor = 0;

    while (wi < strarray_size(want)) {
        int best_start = -1, best_run = 0;

        for (int hi = floor; hi < strarray_size(have); hi++) {
            int run = 0;
            while (wi + run < strarray_size(want) &&
                   hi + run < strarray_size(have) &&
                   !strcmp(strarray_nth(want, wi + run),
                           strarray_nth(have, hi + run))) run++;

            if (run > best_run) { best_run = run; best_start = hi; }
        }

        if (best_run) {
            json_t *c = json_array();
            json_array_append_new(c, json_integer(best_start + 1));
            json_array_append_new(c, json_integer(best_start + best_run));
            json_t *step = json_object();
            json_object_set_new(step, "c", c);
            json_array_append_new(steps, step);
            floor = best_start + best_run;
            wi += best_run;
        }
        else {
            json_t *d = json_array();

            /* best_run of 0 means want[wi] itself isn't copyable from here,
             * so this loop always consumes at least one instance
             */
            while (wi < strarray_size(want)) {
                bool copyable = false;
                for (int hi = floor; hi < strarray_size(have) && !copyable; hi++)
                    copyable = !strcmp(strarray_nth(want, wi),
                                       strarray_nth(have, hi));
                if (copyable) break;

                char *value = recipe_value(strarray_nth(want, wi));
                json_array_append_new(d, json_string(value));
                free(value);
                wi++;
            }
            json_t *step = json_object();
            json_object_set_new(step, "d", d);
            json_array_append_new(steps, step);
        }
    }

    return steps;
}

/* Names to consider, in either block, each once and none of them unsigned */
static strarray_t *signed_names(const strarray_t *a, const strarray_t *b)
{
    strarray_t *names = strarray_new();

    for (int pass = 0; pass < 2; pass++) {
        const strarray_t *fields = pass ? b : a;

        for (int i = 0; i < strarray_size(fields); i++) {
            char *name = field_name(strarray_nth(fields, i));
            if (!name) continue;

            if (field_is_unsigned(name) || strarray_find(names, name, 0) >= 0)
                free(name);
            else
                strarray_appendm(names, name);
        }
    }

    strarray_sort(names, cmpstringp_raw);

    return names;
}

EXPORTED char *dkim2_gen_recipes(const char *before_hdrs, size_t beforelen,
                                 const char *after_hdrs, size_t afterlen)
{
    strarray_t *before = split_fields(before_hdrs, beforelen);
    strarray_t *after = split_fields(after_hdrs, afterlen);
    strarray_t *names = signed_names(before, after);
    json_t *h = json_object();
    char *json = NULL;

    for (int i = 0; i < strarray_size(names); i++) {
        const char *name = strarray_nth(names, i);
        strarray_t *was = instances_of(before, name);
        strarray_t *now = instances_of(after, name);

        if (strarray_cmp(was, now))
            json_object_set_new(h, name, recipe_steps(now, was));

        strarray_free(was);
        strarray_free(now);
    }

    if (json_object_size(h)) {
        json_t *root = json_object();
        json_object_set_new(root, "h", h);
        json = json_dumps(root, JSON_COMPACT | JSON_PRESERVE_ORDER);
        json_decref(root);
    }
    else json_decref(h);

    strarray_free(names);
    strarray_free(after);
    strarray_free(before);

    return json;
}

/* ==================== Message-Instance header field (§7) ==================== */

/* Value of tag in a "m=1; h=sha256:x:y;" tag list, or NULL.  FWS around
 * both the tag name and the value is stripped; the value keeps any FWS
 * inside it, which only a base64string can have (§2.14) and which the
 * sha256 comparison below removes.
 */
static char *mi_tag(const char *value, const char *tag)
{
    size_t taglen = strlen(tag);

    for (const char *p = value; p && *p; p = strchr(p, ';')) {
        if (*p == ';') p++;
        while (Uisspace(*p)) p++;

        if (strncmp(p, tag, taglen)) continue;

        const char *v = p + taglen;
        while (Uisspace(*v)) v++;
        if (*v != '=') continue;

        v++;
        while (Uisspace(*v)) v++;

        const char *end = strchr(v, ';');
        if (!end) end = v + strlen(v);
        while (end > v && Uisspace(end[-1])) end--;

        return xstrndup(v, end - v);
    }

    return NULL;
}

/* The sha256 hash-set of an h= tag, as "headerhash:bodyhash" with the FWS
 * that folding may have left inside the base64 removed, or NULL if the
 * hop that wrote this Message-Instance didn't use sha256.
 */
static char *mi_sha256_hashes(const char *h)
{
    struct buf buf = BUF_INITIALIZER;
    const char *p = h;

    while (*p) {
        buf_reset(&buf);
        for (; *p && *p != ','; p++)
            if (!Uisspace(*p)) buf_putc(&buf, *p);
        if (*p == ',') p++;

        if (!strncmp(buf_cstring(&buf), "sha256:", 7)) {
            buf_remove(&buf, 0, 7);
            return buf_release(&buf);
        }
    }

    buf_free(&buf);

    return NULL;
}

/* Highest-numbered Message-Instance in a header block: its m= into *m, its
 * sha256 hashes as the return value (NULL if it has none).  Returns 0 with
 * *m unchanged if the message carries no Message-Instance at all.
 */
static bool mi_highest(const strarray_t *fields, int *m, char **hashes)
{
    bool found = false;

    *m = 0;
    *hashes = NULL;

    for (int i = 0; i < strarray_size(fields); i++) {
        const char *field = strarray_nth(fields, i);
        char *name = field_name(field);
        if (!name) continue;

        bool is_mi = !strcmp(name, MI_HDR_NAME);
        free(name);
        if (!is_mi) continue;

        const char *value = field_value(field);
        char *mtag = mi_tag(value, "m");
        if (!mtag) continue;

        int this_m = atoi(mtag);
        free(mtag);

        if (this_m > *m) {
            char *htag = mi_tag(value, "h");

            *m = this_m;
            found = true;
            free(*hashes);
            *hashes = htag ? mi_sha256_hashes(htag) : NULL;
            free(htag);
        }
    }

    return found;
}

/* Emit a tag list folded to a sane line length.  Only the r= tag is ever
 * long enough to need it, and FWS inside its base64 is ignored (§2.14).
 */
static void mi_append_folded(struct buf *out, const char *text, size_t *column)
{
    for (size_t i = 0; text[i]; i++) {
        if (*column >= MI_FOLD_COLUMN) {
            buf_appendcstr(out, "\r\n\t");
            *column = 8;
        }
        buf_putc(out, text[i]);
        (*column)++;
    }
}

EXPORTED enum dkim2_mi_result dkim2_mi_calculate(const char *before_hdrs,
                                                 size_t beforelen,
                                                 const char *after_hdrs,
                                                 size_t afterlen,
                                                 const char *body,
                                                 size_t bodylen,
                                                 bool verify,
                                                 struct buf *mi_out)
{
    struct buf body_hash = BUF_INITIALIZER;
    struct buf hdr_hash = BUF_INITIALIZER;
    struct buf b64 = BUF_INITIALIZER;
    enum dkim2_mi_result res = DKIM2_MI_NONE;
    char *recipes = NULL;
    char *hashes = NULL;
    int m = 0;

    /* Message-Instance fields pass through untouched, so either block
     * answers this; §9.1 requires one before any signature, so a message
     * without one has no chain for Cyrus to stay attached to.
     */
    strarray_t *fields = split_fields(after_hdrs, afterlen);
    bool have_chain = mi_highest(fields, &m, &hashes);
    strarray_free(fields);

    if (!have_chain) goto done;

    /* The body is never modified here, so one hash serves both the check
     * against the inherited Message-Instance and the one being written.
     */
    dkim2_body_hash(body, bodylen, &body_hash);

    if (verify) {
        struct buf was = BUF_INITIALIZER;

        dkim2_header_hash(before_hdrs, beforelen, &was);
        buf_printf(&b64, "%s:%s", buf_cstring(&was), buf_cstring(&body_hash));
        buf_free(&was);

        /* a missing sha256 hash-set is as unusable as a wrong one */
        if (!hashes || strcmp(hashes, buf_cstring(&b64))) {
            res = DKIM2_MI_CHAIN_MISMATCH;
            goto done;
        }
    }

    recipes = dkim2_gen_recipes(before_hdrs, beforelen, after_hdrs, afterlen);
    if (!recipes) goto done;   /* nothing this hop did needs declaring */

    dkim2_header_hash(after_hdrs, afterlen, &hdr_hash);

    buf_reset(&b64);
    charset_encode(&b64, recipes, strlen(recipes), ENCODING_BASE64);

    buf_reset(mi_out);
    buf_printf(mi_out, "m=%d; r=", m + 1);

    size_t column = strlen("Message-Instance: ") + buf_len(mi_out);
    mi_append_folded(mi_out, buf_cstring(&b64), &column);
    mi_append_folded(mi_out, "; ", &column);

    buf_reset(&b64);
    buf_printf(&b64, "h=sha256:%s:%s;",
               buf_cstring(&hdr_hash), buf_cstring(&body_hash));
    mi_append_folded(mi_out, buf_cstring(&b64), &column);

    res = DKIM2_MI_ADDED;

done:
    free(recipes);
    free(hashes);
    buf_free(&b64);
    buf_free(&hdr_hash);
    buf_free(&body_hash);

    return res;
}
