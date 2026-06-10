/* jmap_blob.c - Routines for handling JMAP Blob requests */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
#include "imap/jmap_blob_props.h"
#include "imap/jmap_blob_upload_props.h"


static int jmap_blob_copy(jmap_req_t *req);
static int jmap_blob_get(jmap_req_t *req);
static int jmap_blob_lookup(jmap_req_t *req);
static int jmap_blob_upload(jmap_req_t *req);

// clang-format off
static jmap_method_t jmap_blob_methods_standard[] = {
    /* RFC 8620 */
    {
        "Blob/copy",
        JMAP_URN_CORE,
        &jmap_blob_copy,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
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
// clang-format on

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
    json_array_append_new(algorithms, json_string("sha-256"));

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
}

HIDDEN void jmap_blob_capabilities(json_t *account_capabilities)
{
    json_object_set(account_capabilities, JMAP_URN_BLOB, blob_capabilities);
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
    if (fflush(to_fp) || ferror(to_fp) || fdatasync(fileno(to_fp))) {
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
    struct jmap_copy copy = JMAP_COPY_INITIALIZER;
    json_t *val, *err = NULL;
    size_t i = 0;
    int r = 0;
    struct mailbox *to_mbox = NULL;

    /* Parse request */
    jmap_copy_parse(req, &parser, NULL, NULL, &copy, &err);
    if (err) {
        jmap_error(req, err);
        goto cleanup;
    }

    /* Check if we are allowed to write */
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
    struct jmap_get get = JMAP_GET_INITIALIZER;
    json_t *err = NULL;
    json_t *jval;
    size_t i;

    /* Parse request */
    struct blob_range range = { 0, 0 };
    jmap_get_parse(req, &parser, &blob_props, /*allow_null_ids*/0,
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

            if (jmap_wantprop(get.props, "digest:sha-256")) {
                unsigned char data[32];
                memset(data, 0, sizeof(data));
                xsha256((unsigned char *)base, len, data);
                size_t len64 = 44;
                char output[44];
                charset_b64encode_mimebody((char *)data, 32, output, &len64, NULL, 0 /* no wrap */);
                json_object_set_new(item, "digest:sha-256", json_stringn(output, 44));
            }
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

static int _parse_datatypes(jmap_req_t *req __attribute__((unused)),
                            struct jmap_parser *parser,
                            const char *key,
                            json_t *arg,
                            void *rock)
{
    uint32_t *datatypesp = rock;

    if (!strcmp(key, "typeNames")) {
        if (!json_is_array(arg)) {
            jmap_parser_invalid(parser, key);
            // field known, type wrong
            return 1;
        }

        size_t i;
        json_t *v;
        json_array_foreach(arg, i, v) {
            const char *val = json_string_value(v);
            const jmap_data_type_t *dtype =
                val ? jmap_data_types_lookup(val, strlen(val)) : NULL;

            if (dtype && (dtype->attributes & JMAP_TYPE_HAS_BLOB)) {
                *datatypesp |= dtype->kind;
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
    hashu64_table *values = data;
    free_hashu64_table(values, (void (*)(void*)) &strarray_free);
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

struct lookup_blob_rock {
    jmap_req_t *req;
    uint32_t datatypes;
    hash_table *found_ids;
    struct buf *buf;
    const mbentry_t *mbentry;
    const strarray_t *boxes;
    struct caldav_db *caldav_db;
    struct carddav_db *carddav_db;
    struct getblob_rec *getblob;
    struct message_guid guid;
    struct timespec internaldate;
    bit64 cid;
};

static void lookup_blob_cb(const jmap_data_type_t *dtype, void *rock)
{
    struct lookup_blob_rock *lrock = rock;

    // if we don't want this datatype, skip
    if (!(lrock->datatypes & dtype->kind)) return;

    // if this isn't the right type, skip
    if (mbtype_isa(lrock->mbentry->mbtype) != dtype->mbtype) return;

    /* only create the values store if we have found at least
     * one item for this blobid */
    hashu64_table *values =
        hash_lookup(lrock->getblob->blob_id, lrock->found_ids);
    if (!values) {
        values = xzmalloc(sizeof(hashu64_table));
        construct_hashu64_table(values, JMAP_NUM_TYPES, 0);
        hash_insert(lrock->getblob->blob_id, values, lrock->found_ids);
    }
    strarray_t *ids = hashu64_lookup(dtype->kind, values);
    if (!ids) {
        ids = strarray_new();
        hashu64_insert(dtype->kind, ids, values);
    }

    switch (dtype->kind) {
    case JMAP_TYPE_MAILBOX: {
        char mboxid[JMAP_MAX_MAILBOXID_SIZE];
        jmap_set_mailboxid(lrock->req->cstate, lrock->mbentry, mboxid);
        strarray_add(ids, mboxid);
        break;
    }

    case JMAP_TYPE_THREAD: {
        char threadid[JMAP_THREADID_SIZE];
        jmap_set_threadid(lrock->req->cstate, lrock->cid, threadid);
        strarray_add(ids, threadid);
        break;
    }

    case JMAP_TYPE_EMAIL: {
        char emailid[JMAP_MAX_EMAILID_SIZE];
        jmap_set_emailid(lrock->req->cstate, &lrock->guid,
                         0, &lrock->internaldate, emailid);
        strarray_add(ids, emailid);
        break;
    }

    case JMAP_TYPE_ADDRESSBOOK: {
        char abookid[JMAP_MAX_ADDRBOOKID_SIZE];
        jmap_set_addrbookid(lrock->req->cstate, lrock->mbentry, abookid);
        strarray_add(ids, abookid);
        break;
    }

    case JMAP_TYPE_CONTACTCARD: {
        struct carddav_data *cdata = NULL;
        carddav_lookup_imapuid(lrock->carddav_db, lrock->mbentry,
                               lrock->getblob->uid, &cdata, 0);
        if (cdata) {
            struct buf cardid = BUF_INITIALIZER;
            jmap_set_contactid(lrock->req->cstate, cdata, &cardid);
            strarray_add(ids, buf_cstring(&cardid));
            buf_free(&cardid);
        }
        break;
    }

    case JMAP_TYPE_CALENDAR:
        strarray_add(ids, strarray_nth(lrock->boxes, -1));
        break;

    case JMAP_TYPE_CALENDAREVENT: {
        struct caldav_jscal_filter jscal_filter =
            CALDAV_JSCAL_FILTER_INITIALIZER;
        caldav_jscal_filter_by_imap_uid(&jscal_filter, lrock->getblob->uid);
        caldav_jscal_filter_by_mbentry(&jscal_filter, lrock->mbentry);
        struct caleventid_rock rock = { lrock->buf, ids };
        caldav_foreach_jscal(lrock->caldav_db, lrock->req->accountid, &jscal_filter,
                             NULL, NULL, 0, caleventid_cb, &rock);
        caldav_jscal_filter_fini(&jscal_filter);
        buf_reset(lrock->buf);
        break;
    }
    }
}

struct report_blob_rock {
    uint32_t datatypes;
    hashu64_table *values;
    json_t *dtvalue;
};

static void report_blob_cb(const jmap_data_type_t *dtype, void *rock)
{
    struct report_blob_rock *rrock = rock;

    // if we don't want this datatype, skip
    if (!(rrock->datatypes & dtype->kind)) return;

    strarray_t *ids = hashu64_lookup(dtype->kind, rrock->values);
    json_t *list = json_array();
    for (int i = 0; i < strarray_size(ids); i++)
        json_array_append_new(list, json_string(strarray_nth(ids, i)));
    json_object_set_new(rrock->dtvalue, dtype->name, list);
}

static int jmap_blob_lookup(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get = JMAP_GET_INITIALIZER;
    uint32_t datatypes = 0;
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
        if (datatypes & (JMAP_TYPE_ADDRESSBOOK | JMAP_TYPE_CALENDAR)) {
            mbname = mbname_from_intname(mbentry->name);
            boxes = mbname_boxes(mbname);
        }

        // XXX: cache if userid is unchanged?  Should be always
        struct caldav_db *caldav_db = NULL;
        if (datatypes & JMAP_TYPE_CALENDAREVENT)
            caldav_db = caldav_open_mailbox(mbox);

        struct carddav_db *carddav_db = NULL;
        if (datatypes & JMAP_TYPE_CONTACTCARD)
            carddav_db = carddav_open_mailbox(mbox);

        int j;
        for (j = 0; j < ptrarray_size(getblobs); j++) {
            struct getblob_rec *getblob = ptrarray_nth(getblobs, j);
            struct lookup_blob_rock lrock = {
                .req = req,
                .datatypes = datatypes,
                .found_ids = &found,
                .buf = &buf,
                .mbentry = mbentry,
                .boxes = boxes,
                .caldav_db = caldav_db,
                .carddav_db = carddav_db,
                .getblob = getblob
            };

            /* Read message record */
            msgrecord_t *mr = NULL;
            r = msgrecord_find(mbox, getblob->uid, &mr);
            if (!r) r = msgrecord_get_guid(mr, &lrock.guid);
            if (!r) r = msgrecord_get_internaldate(mr, &lrock.internaldate);
            if (!r) r = msgrecord_get_cid(mr, &lrock.cid);
            msgrecord_unref(&mr);
            if (r) {
                syslog(LOG_ERR, "jmap_blob_get: can't read msgrecord %s:%d: %s",
                        mailbox_name(mbox), getblob->uid, error_message(r));
                continue;
            }

            jmap_data_types_foreach(&lookup_blob_cb, &lrock);
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
        hashu64_table *values = hash_lookup(blob_id, &found);
        if (values) {
            struct report_blob_rock rrock = {
                .datatypes = datatypes,
                .values = values,
                .dtvalue = json_object()
            };
            jmap_data_types_foreach(&report_blob_cb, &rrock);
            json_array_append_new(get.list,
                                  json_pack("{s:s, s:o}", "id",
                                            blob_id, resname, rrock.dtvalue));
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
    struct jmap_set set = JMAP_SET_INITIALIZER;
    json_t *jerr = NULL;
    int r = 0;
    time_t now = time(NULL);

    /* Parse arguments */
    jmap_set_parse(req, &parser, &blob_upload_props, NULL, NULL, &set, &jerr);
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
