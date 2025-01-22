/* jmap_blob.c -- Routines for handling JMAP Blob requests
 *
 * Copyright (c) 1994-2024 Carnegie Mellon University.  All rights reserved.
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

#include <errno.h>

#include <syslog.h>

#include "append.h"
#include "caldav_db.h"
#include "carddav_db.h"
#include "http_jmap.h"
#include "times.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"
#include "imap/jmap_err.h"


static int jmap_blob_copy(jmap_req_t *req);
static int jmap_blob_get(jmap_req_t *req);
static int jmap_blob_lookup(jmap_req_t *req);
static int jmap_blob_upload(jmap_req_t *req);

static jmap_method_t jmap_blob_methods_standard[] = {
    /* RFC 8620 */
    {
        "Blob/copy",
        JMAP_URN_CORE,
        &jmap_blob_copy,
        JMAP_READ_WRITE // no conversations, we need to get lock ordering first
    },
    /* RFC 9404 */
    {
        "Blob/get",
        JMAP_URN_BLOB,
        &jmap_blob_get,
        JMAP_NEED_CSTATE
    },
    {
        "Blob/lookup",
        JMAP_URN_BLOB,
        &jmap_blob_lookup,
        JMAP_NEED_CSTATE
    },
    {
        "Blob/upload",
        JMAP_URN_BLOB,
        &jmap_blob_upload,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    { NULL, NULL, NULL, 0}
};

static jmap_method_t jmap_core_methods_nonstandard[] = {
    {
        "Blob/get",
        JMAP_BLOB_EXTENSION,
        &jmap_blob_get,
        JMAP_NEED_CSTATE
    },
    {
        "Blob/lookup",
        JMAP_BLOB_EXTENSION,
        &jmap_blob_lookup,
        JMAP_NEED_CSTATE
    },
    {
        "Blob/upload",
        JMAP_BLOB_EXTENSION,
        &jmap_blob_upload,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    { NULL, NULL, NULL, 0}
};

static json_t *blob_capabilities = NULL;

HIDDEN void jmap_blob_init(jmap_settings_t *settings)
{
    json_t *typenames = json_array();
    // XXX - have a way to register these from each object?  Would
    // also need to register the lookup logic at the same time though
    json_array_append_new(typenames, json_string("Mailbox"));
    json_array_append_new(typenames, json_string("Thread"));
    json_array_append_new(typenames, json_string("Email"));
    json_t *algorithms = json_array();
    json_array_append_new(algorithms, json_string("md5"));
    json_array_append_new(algorithms, json_string("sha"));
#ifdef HAVE_SSL
    json_array_append_new(algorithms, json_string("sha-256"));
#endif

    blob_capabilities =
        json_pack("{s:i, s:i, s:o, s:o}",
                  "maxSizeBlobSet",
                  settings->limits[MAX_SIZE_BLOB_SET] / 1024,
                  "maxdataSources",
                  settings->limits[MAX_CATENATE_ITEMS],
                  "supportedTypeNames",
                  typenames,
                  "supportedDigestAlgorithms",
                  algorithms);

    json_object_set_new(settings->server_capabilities,
                        JMAP_URN_BLOB, json_object());

    jmap_add_methods(jmap_blob_methods_standard, settings);

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(settings->server_capabilities,
                JMAP_BLOB_EXTENSION,
                json_pack("{s:i, s:i, s:O, s:O}",
                    "maxSizeBlobSet",
                    settings->limits[MAX_SIZE_BLOB_SET] / 1024,
                    "maxCatenateItems",
                    settings->limits[MAX_CATENATE_ITEMS],
                    "supportedTypeNames",
                    typenames,
                    "supportedDigestAlgorithms",
                    algorithms));

        jmap_add_methods(jmap_core_methods_nonstandard, settings);
    }

}

HIDDEN void jmap_blob_capabilities(json_t *account_capabilities)
{
    json_object_set(account_capabilities, JMAP_URN_BLOB, blob_capabilities);

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities,
                JMAP_BLOB_EXTENSION, json_object());
    }
}

static int jmap_copyblob(jmap_req_t *req,
                         const char *blobid,
                         const char *from_accountid,
                         struct mailbox *to_mbox)
{
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    struct body *body = NULL;
    const struct body *part = NULL;
    struct buf msg_buf = BUF_INITIALIZER;
    FILE *to_fp = NULL;
    struct stagemsg *stage = NULL;

    int r = jmap_findblob(req, from_accountid, blobid,
                          &mbox, &mr, &body, &part, &msg_buf);
    if (r) return r;

    /* Create staging file */
    time_t internaldate = time(NULL);
    if (!(to_fp = append_newstage(mailbox_name(to_mbox), internaldate, 0, &stage))) {
        syslog(LOG_ERR, "jmap_copyblob(%s): append_newstage(%s) failed",
                blobid, mailbox_name(mbox));
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Copy blob. Keep the original MIME headers, we wouldn't really
     * know which ones are safe to rewrite for arbitrary blobs. */
    if (part) {
        fwrite(buf_base(&msg_buf) + part->header_offset,
               part->header_size + part->content_size, 1, to_fp);
    }
    else {
        fwrite(buf_base(&msg_buf), buf_len(&msg_buf), 1, to_fp);
    }
    if (ferror(to_fp)) {
        syslog(LOG_ERR, "jmap_copyblob(%s): tofp=%s: %s",
               blobid, append_stagefname(stage), strerror(errno));
        r = IMAP_IOERROR;
        goto done;
    }
    fclose(to_fp);
    to_fp = NULL;

    /* Append blob to mailbox */
    struct body *to_body = NULL;
    struct appendstate as;
    r = append_setup_mbox(&as, to_mbox, httpd_userid, httpd_authstate,
            0, /*quota*/NULL, 0, 0, /*event*/0);
    if (r) {
        syslog(LOG_ERR, "jmap_copyblob(%s): append_setup_mbox: %s",
                blobid, error_message(r));
        goto done;
    }
    strarray_t flags = STRARRAY_INITIALIZER;
    strarray_append(&flags, "\\Deleted");
    strarray_append(&flags, "\\Expunged");  // custom flag to insta-expunge!
	r = append_fromstage(&as, &to_body, stage, 0, internaldate, &flags, 0, NULL);
    strarray_fini(&flags);
	if (r) {
        syslog(LOG_ERR, "jmap_copyblob(%s): append_fromstage: %s",
                blobid, error_message(r));
		append_abort(&as);
		goto done;
	}
	message_free_body(to_body);
	free(to_body);
	r = append_commit(&as);
	if (r) {
        syslog(LOG_ERR, "jmap_copyblob(%s): append_commit: %s",
                blobid, error_message(r));
        goto done;
    }

done:
    if (stage) append_removestage(stage);
    if (to_fp) fclose(to_fp);
    buf_free(&msg_buf);
    message_free_body(body);
    free(body);
    msgrecord_unref(&mr);
    mailbox_close(&mbox);
    return r;
}

/* Blob/copy method */
static int jmap_blob_copy(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_copy copy;
    json_t *val, *err = NULL;
    size_t i = 0;
    int r = 0;
    struct mailbox *to_mbox = NULL;
    struct mboxlock *srcnamespacelock = NULL;
    struct mboxlock *dstnamespacelock = NULL;

    /* Parse request */
    jmap_copy_parse(req, &parser, NULL, NULL, &copy, &err);
    if (err) {
        jmap_error(req, err);
        goto cleanup;
    }

    char *srcinbox = mboxname_user_mbox(copy.from_account_id, NULL);
    char *dstinbox = mboxname_user_mbox(req->accountid, NULL);
    if (strcmp(srcinbox, dstinbox) < 0) {
        srcnamespacelock = mboxname_usernamespacelock(srcinbox);
        dstnamespacelock = mboxname_usernamespacelock(dstinbox);
    }
    else {
        dstnamespacelock = mboxname_usernamespacelock(dstinbox);
        srcnamespacelock = mboxname_usernamespacelock(srcinbox);
    }
    free(srcinbox);
    free(dstinbox);

    // now we can open the cstate
    r = conversations_open_user(req->accountid, 0, &req->cstate);
    if (r) {
        syslog(LOG_ERR, "jmap_email_copy: can't open converstaions: %s",
                        error_message(r));
        jmap_error(req, jmap_server_error(r));
        goto cleanup;
    }

    /* Check if we can upload to toAccountId */
    r = jmap_open_upload_collection(req->accountid, &to_mbox);
    if (r == IMAP_PERMISSION_DENIED) {
        json_array_foreach(copy.create, i, val) {
            json_object_set(copy.not_created, json_string_value(val),
                    json_pack("{s:s}", "type", "toAccountNotFound"));
        }
        goto done;
    } else if (r) {
        syslog(LOG_ERR, "jmap_blob_copy: jmap_create_upload_collection(%s): %s",
               req->accountid, error_message(r));
        goto cleanup;
    }

    /* Copy blobs one by one. XXX should we batch copy here? */
    json_array_foreach(copy.create, i, val) {
        const char *blobid = json_string_value(val);
        r = jmap_copyblob(req, blobid, copy.from_account_id, to_mbox);
        if (r == IMAP_NOTFOUND || r == IMAP_PERMISSION_DENIED) {
            json_object_set_new(copy.not_created, blobid,
                    json_pack("{s:s}", "type", "blobNotFound"));
        }
        else if (r) goto cleanup;
        else json_object_set_new(copy.created, blobid, json_string(blobid));
    }

done:
    /* Build response */
    jmap_ok(req, jmap_copy_reply(&copy));
    r = 0;

cleanup:
    mailbox_close(&to_mbox);
    mboxname_release(&srcnamespacelock);
    mboxname_release(&dstnamespacelock);
    jmap_parser_fini(&parser);
    jmap_copy_fini(&copy);
    return r;
}

/* Blob/get method */

struct getblob_rec {
    const char *blob_id;
    uint32_t uid;
    char *part;
};

struct getblob_cb_rock {
    jmap_req_t *req;
    const char *blob_id;
    hash_table *getblobs_by_uniqueid;
};

static int getblob_cb(const conv_guidrec_t* rec, void* vrock)
{
    struct getblob_cb_rock *rock = vrock;

    const char *uniqueid = conv_guidrec_uniqueid(rec);
    if (!uniqueid) return 0;

    struct getblob_rec *getblob = xzmalloc(sizeof(struct getblob_rec));
    getblob->blob_id = rock->blob_id;
    getblob->uid = rec->uid;
    getblob->part = xstrdupnull(rec->part);

    ptrarray_t *getblobs = hash_lookup(uniqueid, rock->getblobs_by_uniqueid);
    if (!getblobs) {
        getblobs = ptrarray_new();
        hash_insert(uniqueid, getblobs, rock->getblobs_by_uniqueid);
    }
    ptrarray_append(getblobs, getblob);

    return 0;
}

static const jmap_property_t blob_xprops[] = {
    {
        "data",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "data:asBase64",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET
    },
    {
        "data:asText",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET
    },
    {
        "digest:md5",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET
    },
    {
        "digest:sha",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET
    },
#ifdef HAVE_SSL
    {
        "digest:sha-256",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET
    },
#endif
    {
        "size",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    { NULL, NULL, 0 }
};

struct blob_range {
    size_t offset;
    size_t length;
};

static int _parse_range(jmap_req_t *req __attribute__((unused)),
                         struct jmap_parser *parser,
                         const char *key,
                         json_t *arg,
                         void *rock)
{
    struct blob_range *rangep = rock;

    if (!strcmp(key, "offset")) {
        long long val = -1;
        if (json_is_integer(arg)) val = json_integer_value(arg);

        if (val < 0) jmap_parser_invalid(parser, "offset");
        else rangep->offset = val;

        return 1;
    }

    if (!strcmp(key, "length")) {
        long long val = -1;
        if (json_is_integer(arg)) val = json_integer_value(arg);

        if (val <= 0) jmap_parser_invalid(parser, "length");
        else rangep->length = val;

        return 1;
    }

    return 0;
}

static int jmap_blob_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    json_t *jval;
    size_t i;

    /* Parse request */
    struct blob_range range = { 0, 0 };
    jmap_get_parse(req, &parser, blob_xprops, /*allow_null_ids*/0,
                   &_parse_range, &range, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Lookup the content for each blob */
    json_array_foreach(get.ids, i, jval) {
        int is_truncated = 0;
        const char *blob_id = json_string_value(jval);
        jmap_getblob_context_t ctx;
        jmap_getblob_ctx_init(&ctx, req->accountid, blob_id, NULL, 1);
        int r = jmap_getblob(req, &ctx);
        if (r) {
            json_array_append_new(get.not_found, json_string(blob_id));
        }
        else {
            const char *base = buf_base(&ctx.blob);
            size_t len = buf_len(&ctx.blob);

            if (range.offset) {
                if (range.offset < len) {
                    base += range.offset;
                    len -= range.offset;
                }
                else {
                    is_truncated = 1;
                    len = 0;
                }
            }
            if (range.length) {
                if (len >= range.length) len = range.length;
                else is_truncated = 1;
            }

            json_t *item = json_object();
            json_array_append_new(get.list, item);
            json_object_set_new(item, "id", json_string(blob_id));

            if (is_truncated)
                json_object_set_new(item, "isTruncated", json_true());

            // the various data types, only output them if there's data to send
            int want_text = 0;
            int want_base64 = 0;
            if (jmap_wantprop(get.props, "data:asText")) want_text = 1;
            if (jmap_wantprop(get.props, "data:asBase64")) want_base64 = 1;
            if (jmap_wantprop(get.props, "data")) want_text = 2;

            if (want_text) {
                struct char_counts guess_counts = charset_count_validutf8(base, len);
                if (!guess_counts.invalid && !guess_counts.replacement) {
                    json_object_set_new(item, "data:asText", json_stringn(base, len));
                }
                else {
                    json_object_set_new(item, "isEncodingProblem", json_true());
                    // if we asked for 'data' then the encoding problem means we get base64
                    if (want_text == 2) want_base64 = 1;
                }
            }

            if (want_base64) {
                if (len) {
                    size_t len64 = 0;
                    charset_b64encode_mimebody(NULL, len, NULL, &len64, NULL, 0 /* no wrap */);
                    char *encbuf = xzmalloc(len64+1);
                    charset_b64encode_mimebody(base, len, encbuf, &len64, NULL, 0 /* no wrap */);
                    json_object_set_new(item, "data:asBase64", json_stringn(encbuf, len64));
                    free(encbuf);
                }
                else {
                    json_object_set_new(item, "data:asBase64", json_string(""));
                }
            }

            // always the size of the full blob
            if (jmap_wantprop(get.props, "size")) {
                json_object_set_new(item, "size", json_integer(buf_len(&ctx.blob)));
            }

            if (jmap_wantprop(get.props, "digest:md5")) {
                unsigned char data[16];
                memset(data, 0, sizeof(data));
                md5((unsigned char *)base, len, data);
                size_t len64 = 24;
                char output[24];
                charset_b64encode_mimebody((char *)data, 16, output, &len64, NULL, 0 /* no wrap */);
                json_object_set_new(item, "digest:md5", json_stringn(output, 24));
            }

            // this is "sha1" and we have a built-in so use that
            if (jmap_wantprop(get.props, "digest:sha")) {
                unsigned char data[20];
                xsha1((unsigned char *)base, len, data);
                size_t len64 = 28;
                char output[28];
                charset_b64encode_mimebody((char *)data, 20, output, &len64, NULL, 0 /* no wrap */);
                json_object_set_new(item, "digest:sha", json_stringn(output, 28));
            }

#ifdef HAVE_SSL
            if (jmap_wantprop(get.props, "digest:sha-256")) {
                unsigned char data[32];
                memset(data, 0, sizeof(data));
                xsha256((unsigned char *)base, len, data);
                size_t len64 = 44;
                char output[44];
                charset_b64encode_mimebody((char *)data, 32, output, &len64, NULL, 0 /* no wrap */);
                json_object_set_new(item, "digest:sha-256", json_stringn(output, 44));
            }

#endif
        }
        jmap_getblob_ctx_fini(&ctx);
    }

    /* Reply */
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

#define DATATYPE_MAILBOX         (1<<0)
#define DATATYPE_THREAD          (1<<1)
#define DATATYPE_EMAIL           (1<<2)
#define DATATYPE_ADDRESSBOOK     (1<<3)
#define DATATYPE_CONTACT         (1<<4)
#define DATATYPE_CALENDAR        (1<<5)
#define DATATYPE_CALENDAREVENT   (1<<6)

#define NUM_DATATYPES 7

struct datatype_name {
    const char *name;
    uint32_t typenum;
    uint32_t mbtype;
};

struct datatype_name known_datatypes[] = {
    { "Mailbox", DATATYPE_MAILBOX, MBTYPE_EMAIL },
    { "Thread", DATATYPE_THREAD, MBTYPE_EMAIL },
    { "Email", DATATYPE_EMAIL, MBTYPE_EMAIL },
    { "Addressbook", DATATYPE_ADDRESSBOOK, MBTYPE_ADDRESSBOOK },
    { "Contact", DATATYPE_CONTACT, MBTYPE_ADDRESSBOOK },
    { "Calendar", DATATYPE_CALENDAR, MBTYPE_CALENDAR },
    { "CalendarEvent", DATATYPE_CALENDAREVENT, MBTYPE_CALENDAR },
    { NULL, 0, 0 }
};

static int _parse_datatypes(jmap_req_t *req __attribute__((unused)),
                            struct jmap_parser *parser,
                            const char *key,
                            json_t *arg,
                            void *rock)
{
    int32_t *datatypesp = rock;

    // support both "types" and "typeNames" selectors for now
    if (!strcmp(key, "typeNames") ||
        (jmap_is_using(req, JMAP_BLOB_EXTENSION) && !strcmp(key, "types"))) {
        if (!json_is_array(arg)) {
            jmap_parser_invalid(parser, key);
            // field known, type wrong
            return 1;
        }

        size_t i;
        json_t *v;
        json_array_foreach(arg, i, v) {
            const char *val = json_string_value(v);
            const struct datatype_name *item;
            int typenum = 0;
            for (item = known_datatypes; item->name; item++) {
                if (strcmpsafe(val, item->name))
                    continue;
                typenum = item->typenum;
                break;
            }

            if (typenum) {
                *datatypesp |= typenum;
            }
            else {
                jmap_parser_push_index(parser, key, i, NULL);
                jmap_parser_invalid(parser, NULL);
                jmap_parser_pop(parser);
            }
        }

        return 1;
    }

    return 0;
}

static void _free_found(void *data)
{
    int i;
    strarray_t *values = data;
    for (i = 0; i < NUM_DATATYPES + 1; i++) {
        strarray_t *ids = values + i;
        strarray_fini(ids);
    }
    free(values);
}

struct caleventid_rock {
    struct buf *buf;
    strarray_t *ids;
};

static int caleventid_cb(void *vrock, struct caldav_jscal *jscal)
{
    struct caleventid_rock *rock = vrock;

    struct jmap_caleventid eid = {
        .ical_uid = jscal->cdata.ical_uid,
        .ical_recurid = jscal->ical_recurid,
    };
    strarray_append(rock->ids, jmap_caleventid_encode(&eid, rock->buf));

    buf_reset(rock->buf);
    return 0;
}

static int jmap_blob_lookup(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    int32_t datatypes = 0;
    json_t *err = NULL;
    struct buf buf = BUF_INITIALIZER;
    json_t *jval;
    size_t i;

    /* Parse request */
    jmap_get_parse(req, &parser, NULL, /*allow_null_ids*/0,
                   _parse_datatypes, &datatypes, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (!datatypes) {
        err = json_pack("{s:s s:[s]}", "type", "invalidArguments", "arguments", "typeNames");
        jmap_error(req, err);
        goto done;
    }

    // we'll just make this 'matchedIds' later
    const char *resname = json_object_get(req->args, "typeNames") ? "matchedIds" : "types";

    /* Sort blob lookups by mailbox */
    hash_table getblobs_by_uniqueid = HASH_TABLE_INITIALIZER;
    construct_hash_table(&getblobs_by_uniqueid, 128, 0);
    json_array_foreach(get.ids, i, jval) {
        const char *blob_id = json_string_value(jval);
        if (*blob_id == 'G') {
            struct getblob_cb_rock rock = { req, blob_id, &getblobs_by_uniqueid };
            int r = conversations_guid_foreach(req->cstate, blob_id + 1, getblob_cb, &rock);
            if (r) {
                syslog(LOG_ERR, "jmap_blob_get: can't lookup guid %s: %s",
                        blob_id, error_message(r));
            }
        }
        else if (*blob_id == 'I' || *blob_id == 'V') {
            char *uniqueid = NULL;
            uint32_t uid;
            if (jmap_decode_rawdata_blobid(blob_id, &uniqueid, &uid, NULL, NULL, NULL, NULL)) {
                struct getblob_rec *getblob = xzmalloc(sizeof(struct getblob_rec));
                getblob->blob_id = blob_id;
                getblob->uid = uid;
                ptrarray_t *getblobs = hash_lookup(uniqueid, &getblobs_by_uniqueid);
                if (!getblobs) {
                    getblobs = ptrarray_new();
                    hash_insert(uniqueid, getblobs, &getblobs_by_uniqueid);
                }
                ptrarray_append(getblobs, getblob);
            }
            free(uniqueid);
        }
        else {
            // we don't know how to parse other blob types yet, e.g. sieve has no mailbox
        }
    }

    hash_table found = HASH_TABLE_INITIALIZER;
    construct_hash_table(&found, json_array_size(get.ids), 0);

    /* Lookup blobs by mailbox */
    hash_iter *iter = hash_table_iter(&getblobs_by_uniqueid);
    while (hash_iter_next(iter)) {
        const char *uniqueid = hash_iter_key(iter);
        ptrarray_t *getblobs = hash_iter_val(iter);
        struct mailbox *mbox = NULL;
        const mbentry_t *mbentry = jmap_mbentry_by_uniqueid(req, uniqueid);
        int r = 0;

        /* Open mailbox */
        if (!jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
            r = IMAP_PERMISSION_DENIED;
        }
        else {
            r = mailbox_open_irl(mbentry->name, &mbox);
            if (r) {
                syslog(LOG_ERR, "jmap_blob_get: can't open mailbox %s: %s",
                       mbentry->name, error_message(r));
            }
        }
        if (r) continue;

        // these types both want to know the last item of the name
        mbname_t *mbname = NULL;
        const strarray_t *boxes = NULL;
        if (datatypes & (DATATYPE_ADDRESSBOOK|DATATYPE_CALENDAR)) {
            mbname = mbname_from_intname(mbentry->name);
            boxes = mbname_boxes(mbname);
        }

        // XXX: cache if userid is unchanged?  Should be always
        struct caldav_db *caldav_db = NULL;
        if (datatypes & DATATYPE_CALENDAREVENT)
            caldav_db = caldav_open_mailbox(mbox);

        struct carddav_db *carddav_db = NULL;
        if (datatypes & DATATYPE_CONTACT)
            carddav_db = carddav_open_mailbox(mbox);

        int j;
        for (j = 0; j < ptrarray_size(getblobs); j++) {
            struct getblob_rec *getblob = ptrarray_nth(getblobs, j);

            /* Read message record */
            struct message_guid guid;
            bit64 cid = 0;
            msgrecord_t *mr = NULL;
            r = msgrecord_find(mbox, getblob->uid, &mr);
            if (!r) r = msgrecord_get_guid(mr, &guid);
            if (!r) r = msgrecord_get_cid(mr, &cid);
            msgrecord_unref(&mr);
            if (r) {
                syslog(LOG_ERR, "jmap_blob_get: can't read msgrecord %s:%d: %s",
                        mailbox_name(mbox), getblob->uid, error_message(r));
                continue;
            }

            const struct datatype_name *item;
            int i = 0;
            for (item = known_datatypes; item->name; item++) {
                i++;
                // if we don't want this datatype, skip
                if (!(datatypes & item->typenum)) continue;
                // if this isn't the right type, skip
                if (mbtype_isa(mailbox_mbtype(mbox)) != item->mbtype) continue;

                /* only create the values store if we have found at least
                 * one item for this blobid */
                strarray_t *values = hash_lookup(getblob->blob_id, &found);
                if (!values) {
                    values = xzmalloc(sizeof(strarray_t) * (NUM_DATATYPES + 1));
                    hash_insert(getblob->blob_id, values, &found);
                }
                strarray_t *ids = values + i;

                switch (item->typenum) {
                case DATATYPE_MAILBOX:
                    strarray_add(ids, uniqueid);
                    break;

                case DATATYPE_THREAD: {
                    char threadid[JMAP_THREADID_SIZE];
                    jmap_set_threadid(cid, threadid);
                    strarray_add(ids, threadid);
                    break;
                    }

                case DATATYPE_EMAIL: {
                    char emailid[JMAP_EMAILID_SIZE];
                    jmap_set_emailid(&guid, emailid);
                    strarray_add(ids, emailid);
                    break;
                    }

                case DATATYPE_ADDRESSBOOK:
                    strarray_add(ids, strarray_nth(boxes, -1));
                    break;

                case DATATYPE_CONTACT: {
                    struct carddav_data *cdata = NULL;
                    carddav_lookup_imapuid(carddav_db, mbentry, getblob->uid, &cdata, 0);
                    if (cdata) strarray_add(ids, cdata->vcard_uid);
                    break;
                    }

                case DATATYPE_CALENDAR:
                    strarray_add(ids, strarray_nth(boxes, -1));
                    break;

                case DATATYPE_CALENDAREVENT: {
                    struct caldav_jscal_filter jscal_filter =
                        CALDAV_JSCAL_FILTER_INITIALIZER;
                    caldav_jscal_filter_by_imap_uid(&jscal_filter, getblob->uid);
                    caldav_jscal_filter_by_mbentry(&jscal_filter, mbentry);
                    struct caleventid_rock rock = { &buf, ids };
                    caldav_foreach_jscal(caldav_db, req->accountid, &jscal_filter,
                            NULL, NULL, 0, caleventid_cb, &rock);
                    caldav_jscal_filter_fini(&jscal_filter);
                    buf_reset(&buf);
                    break;
                    }
                }
            }
        }

        if (caldav_db) caldav_close(caldav_db);
        if (carddav_db) carddav_close(carddav_db);
        mbname_free(&mbname);
        mailbox_close(&mbox);
    }

    /* Clean up memory */
    hash_iter_reset(iter);
    while (hash_iter_next(iter)) {
        ptrarray_t *getblobs = hash_iter_val(iter);
        struct getblob_rec *getblob;
        while ((getblob = ptrarray_pop(getblobs))) {
            free(getblob->part);
            free(getblob);
        }
        ptrarray_free(getblobs);
    }
    hash_iter_free(&iter);
    free_hash_table(&getblobs_by_uniqueid, NULL);

    /* Report out blobs */
    json_array_foreach(get.ids, i, jval) {
        const char *blob_id = json_string_value(jval);
        strarray_t *values = hash_lookup(blob_id, &found);
        if (values) {
            json_t *dtvalue = json_object();
            const struct datatype_name *item;
            int j = 0;
            for (item = known_datatypes; item->name; item++) {
                j++;
                // if we don't want this datatype, skip
                if (!(datatypes & item->typenum)) continue;
                strarray_t *ids = values + j;
                json_t *list = json_array();
                int k = 0;
                for (k = 0; k < strarray_size(ids); k++)
                    json_array_append_new(list, json_string(strarray_nth(ids, k)));
                json_object_set_new(dtvalue, item->name, list);
            }
            json_array_append_new(get.list, json_pack("{s:s, s:o}", "id", blob_id, resname, dtvalue));
        }
        else {
            json_array_append_new(get.not_found, json_string(blob_id));
        }
    }

    // now clean all the found things!
    free_hash_table(&found, _free_found);

    /* Reply */
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    buf_free(&buf);
    return 0;
}

static const jmap_property_t blob_upload_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "data",
        NULL,
        0
    },
    {
        "type",
        NULL,
        0
    },

    { NULL, NULL, 0 }
};

static int _set_arg_to_buf(struct jmap_req *req, struct buf *buf, json_t *arg, int recurse, json_t **errp)
{
    json_t *jitem;
    int seen_one = 0;

    // plain text only
    jitem = json_object_get(arg, "data:asText");
    if (JNOTNULL(jitem) && json_is_string(jitem)) {
        buf_init_ro(buf, json_string_value(jitem), json_string_length(jitem));
    }

    // base64 text
    jitem = json_object_get(arg, "data:asBase64");
    if (JNOTNULL(jitem) && json_is_string(jitem)) {
        if (seen_one++) return IMAP_MAILBOX_EXISTS;
        int r = charset_decode(buf, json_string_value(jitem),
                               json_string_length(jitem), ENCODING_BASE64);
        if (r) {
            *errp = json_string("base64 decode failed");
            return r;
        }
    }

    if (recurse) {
        jitem = json_object_get(arg, "blobId");
        if (JNOTNULL(jitem) && json_is_string(jitem)) {
            if (seen_one++) return IMAP_MAILBOX_EXISTS;
            const char *blobid = json_string_value(jitem);
            if (blobid && blobid[0] == '#')
                blobid = jmap_lookup_id(req, blobid + 1);
            if (!blobid) {
                char *error = strconcat("Unknown reference ", json_string_value(jitem), (char *)NULL);
                *errp = json_string(error);
                free(error);
                return IMAP_INTERNAL;
            }
            // map in the existing blob, if there is one
            jmap_getblob_context_t ctx;
            jmap_getblob_ctx_init(&ctx, req->accountid, blobid, NULL, 1);
            int r = jmap_getblob(req, &ctx);
            if (!r) {
                const char *base = buf_base(&ctx.blob);
                size_t len = buf_len(&ctx.blob);
                json_t *joffset = json_object_get(arg, "offset");
                if (JNOTNULL(joffset) && json_is_integer(joffset)) {
                    size_t add = json_integer_value(joffset);
                    if (add <= len) {
                        base += add;
                        len -= add;
                    }
                    else {
                        r = -1;
                    }
                }
                json_t *jlength = json_object_get(arg, "length");
                if (JNOTNULL(jlength) && json_is_integer(jlength)) {
                    size_t limit = json_integer_value(jlength);
                    if (limit <= len) {
                        len = limit;
                    }
                    else {
                        r = -1;
                    }
                }
                if (!r) buf_appendmap(buf, base, len);
            }
            jmap_getblob_ctx_fini(&ctx);
            if (r) {
                char *error = strconcat("Missing blobId ", blobid, (char *)NULL);
                *errp = json_string(error);
                free(error);
                return IMAP_NOTFOUND;
            }
        }
    }
    else if (jmap_is_using(req, JMAP_BLOB_EXTENSION)) {
        jitem = json_object_get(arg, "catenate");
        if (JNOTNULL(jitem) && json_is_array(jitem)) {
            if (seen_one++) return IMAP_MAILBOX_EXISTS;
            size_t limit = config_getint(IMAPOPT_JMAP_MAX_CATENATE_ITEMS);
            if (json_array_size(jitem) > limit) {
                *errp = json_string("too many catenate items");
                return IMAP_QUOTA_EXCEEDED;
            }
            size_t i;
            json_t *val;
            json_array_foreach(jitem, i, val) {
                struct buf subbuf = BUF_INITIALIZER;
                // XXX: we might need to validate the properties here too?
                int r = _set_arg_to_buf(req, &subbuf, val, 1, errp);
                buf_appendmap(buf, buf_base(&subbuf), buf_len(&subbuf));
                buf_free(&subbuf);
                if (*errp) return r; // exact code doesn't matter, err will be checked
                if (r) return r;
            }
        }
    }

    return 0;
}

static int _upload_arg_to_buf(struct jmap_req *req, struct buf *buf, json_t *arg, json_t **errp)
{
    if (JNOTNULL(arg) && json_is_array(arg)) {
        size_t limit = config_getint(IMAPOPT_JMAP_MAX_CATENATE_ITEMS);
        if (json_array_size(arg) > limit) {
            *errp = json_string("too many catenate items");
            return IMAP_QUOTA_EXCEEDED;
        }
        size_t i;
        json_t *val;
        json_array_foreach(arg, i, val) {
            struct buf subbuf = BUF_INITIALIZER;
            // NOTE: we'll have to remove catenate later
            int r = _set_arg_to_buf(req, &subbuf, val, 1, errp);
            buf_appendmap(buf, buf_base(&subbuf), buf_len(&subbuf));
            buf_free(&subbuf);
            if (*errp) return r; // exact code doesn't matter, err will be checked
            if (r) return r;
        }
    }

    return 0;
}

static int jmap_blob_upload(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *jerr = NULL;
    int r = 0;
    time_t now = time(NULL);

    /* Parse arguments */
    jmap_set_parse(req, &parser, blob_upload_props, NULL, NULL, &set, &jerr);
    if (jerr) {
        jmap_error(req, jerr);
        goto done;
    }

    if (json_object_size(set.update)) {
        jerr = json_pack("{s:s}", "type", "invalidProperties");
        json_object_set_new(jerr, "description", json_string("may not specify update with Blob/upload"));
        jmap_error(req, jerr);
        goto done;
    }

    if (json_object_size(set.destroy)) {
        jerr = json_pack("{s:s}", "type", "invalidProperties");
        json_object_set_new(jerr, "description", json_string("may not specify destroy with Blob/upload"));
        jmap_error(req, jerr);
        goto done;
    }

    /* create */
    const char *key;
    json_t *arg;
    json_object_foreach(set.create, key, arg) {
        json_t *err = NULL;
        struct buf *buf = buf_new();
        struct message_guid guidobj;
        char datestr[RFC3339_DATETIME_MAX];
        char blob_id[JMAP_BLOBID_SIZE];

        json_t *jdata = json_object_get(arg, "data");
        int r = _upload_arg_to_buf(req, buf, jdata, &err);

        if (r || err) {
            jerr = json_pack("{s:s}", "type", "invalidProperties");
            if (!err && r == IMAP_MAILBOX_EXISTS)
                err = json_string("Multiple properties provided");
            if (r == IMAP_NOTFOUND)
                json_object_set_new(jerr, "type", json_string("blobNotFound"));
            if (err) json_object_set_new(jerr, "description", err);
            json_object_set_new(set.not_created, key, jerr);
            buf_destroy(buf);
            continue;
        }

        json_t *jtype = json_object_get(arg, "type");
        const char *type = json_string_value(jtype);
        if (!type) type = "application/octet-stream";

        message_guid_generate(&guidobj, buf_base(buf), buf_len(buf));
        jmap_set_blobid(&guidobj, blob_id);
        time_to_rfc3339(now, datestr, RFC3339_DATETIME_MAX);

        // json_string_value into the request lasts the lifetime of the request, so it's
        // safe to zerocopy these blobs!
        hash_insert(blob_id, buf, req->inmemory_blobs);

        json_object_set_new(set.created, key, json_pack("{s:s, s:s, s:i, s:s, s:s}",
            "id", blob_id,
            "blobId", blob_id,
            "size", buf_len(buf),
            "expires", datestr,
            "type", type));

        jmap_add_id(req, key, blob_id);
    }

    json_t *res = json_object();
    json_object_set(res, "created", json_object_size(set.created) ?
            set.created : json_null());
    json_object_set(res, "notCreated", json_object_size(set.not_created) ?
            set.not_created : json_null());
    jmap_ok(req, res);

done:
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    return r;
}
