/* jmap_core.c -- Routines for handling JMAP Core requests
 *
 * Copyright (c) 1994-2019 Carnegie Mellon University.  All rights reserved.
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

#include <string.h>
#include <syslog.h>

#include "acl.h"
#include "append.h"
#include "http_jmap.h"
#include "times.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"
#include "imap/jmap_err.h"


/* JMAP Core API Methods */
static int jmap_blob_copy(jmap_req_t *req);
static int jmap_core_echo(jmap_req_t *req);

/* JMAP extension methods */
static int jmap_blob_get(jmap_req_t *req);
static int jmap_blob_set(jmap_req_t *req);
static int jmap_quota_get(jmap_req_t *req);
static int jmap_usercounters_get(jmap_req_t *req);

jmap_method_t jmap_core_methods_standard[] = {
    {
        "Blob/copy",
        JMAP_URN_CORE,
        &jmap_blob_copy,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "Core/echo",
        JMAP_URN_CORE,
        &jmap_core_echo,
        0/*flags*/
    },
    { NULL, NULL, NULL, 0}
};

jmap_method_t jmap_core_methods_nonstandard[] = {
    {
        "Blob/get",
        JMAP_BLOB_EXTENSION,
        &jmap_blob_get,
        JMAP_NEED_CSTATE
    },
    {
        "Blob/set",
        JMAP_BLOB_EXTENSION,
        &jmap_blob_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "Quota/get",
        JMAP_QUOTA_EXTENSION,
        &jmap_quota_get,
        JMAP_NEED_CSTATE
    },
    {
        "UserCounters/get",
        JMAP_USERCOUNTERS_EXTENSION,
        &jmap_usercounters_get,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_core_init(jmap_settings_t *settings)
{
#define _read_opt(val, optkey) \
    val = config_getint(optkey); \
    if (val <= 0) { \
        syslog(LOG_ERR, "jmap: invalid property value: %s", \
                imapopts[optkey].optname); \
        val = 0; \
    }
    _read_opt(settings->limits[MAX_SIZE_UPLOAD],
              IMAPOPT_JMAP_MAX_SIZE_UPLOAD);
    settings->limits[MAX_SIZE_UPLOAD] *= 1024;
    _read_opt(settings->limits[MAX_CONCURRENT_UPLOAD],
              IMAPOPT_JMAP_MAX_CONCURRENT_UPLOAD);
    _read_opt(settings->limits[MAX_SIZE_REQUEST],
              IMAPOPT_JMAP_MAX_SIZE_REQUEST);
    settings->limits[MAX_SIZE_REQUEST] *= 1024;
    _read_opt(settings->limits[MAX_CONCURRENT_REQUESTS],
              IMAPOPT_JMAP_MAX_CONCURRENT_REQUESTS);
    _read_opt(settings->limits[MAX_CALLS_IN_REQUEST],
              IMAPOPT_JMAP_MAX_CALLS_IN_REQUEST);
    _read_opt(settings->limits[MAX_OBJECTS_IN_GET],
              IMAPOPT_JMAP_MAX_OBJECTS_IN_GET);
    _read_opt(settings->limits[MAX_OBJECTS_IN_SET],
              IMAPOPT_JMAP_MAX_OBJECTS_IN_SET);
    _read_opt(settings->limits[MAX_SIZE_BLOB_SET],
              IMAPOPT_JMAP_MAX_SIZE_BLOB_SET);
#undef _read_opt

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_CORE,
            json_pack("{s:i s:i s:i s:i s:i s:i s:i s:o}",
                "maxSizeUpload",
                settings->limits[MAX_SIZE_UPLOAD],
                "maxConcurrentUpload",
                settings->limits[MAX_CONCURRENT_UPLOAD],
                "maxSizeRequest",
                settings->limits[MAX_SIZE_REQUEST],
                "maxConcurrentRequests",
                settings->limits[MAX_CONCURRENT_REQUESTS],
                "maxCallsInRequest",
                settings->limits[MAX_CALLS_IN_REQUEST],
                "maxObjectsInGet",
                settings->limits[MAX_OBJECTS_IN_GET],
                "maxObjectsInSet",
                settings->limits[MAX_OBJECTS_IN_SET],
                "collationAlgorithms", json_array()));

    jmap_method_t *mp;
    for (mp = jmap_core_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(settings->server_capabilities,
                JMAP_QUOTA_EXTENSION, json_object());
        json_object_set_new(settings->server_capabilities,
                JMAP_PERFORMANCE_EXTENSION, json_object());
        json_object_set_new(settings->server_capabilities,
                JMAP_DEBUG_EXTENSION, json_object());
        json_object_set_new(settings->server_capabilities,
                JMAP_BLOB_EXTENSION,
                json_pack("{s:i}",
                    "maxSizeBlobSet",
                    settings->limits[MAX_SIZE_BLOB_SET]));
        json_object_set_new(settings->server_capabilities,
                JMAP_USERCOUNTERS_EXTENSION, json_object());

        for (mp = jmap_core_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }

}

HIDDEN void jmap_core_capabilities(json_t *account_capabilities)
{
    json_object_set_new(account_capabilities,
            JMAP_URN_CORE, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities,
                JMAP_QUOTA_EXTENSION, json_object());

        json_object_set_new(account_capabilities,
                JMAP_PERFORMANCE_EXTENSION, json_object());

        json_object_set_new(account_capabilities,
                JMAP_DEBUG_EXTENSION, json_object());

        json_object_set_new(account_capabilities,
                JMAP_BLOB_EXTENSION, json_object());

        json_object_set_new(account_capabilities,
                JMAP_USERCOUNTERS_EXTENSION, json_object());
    }
}

/*
 * JMAP Core API Methods
 */

/* Core/echo method */
static int jmap_core_echo(jmap_req_t *req)
{
    json_array_append_new(req->response,
                          json_pack("[s,O,s]", "Core/echo", req->args, req->tag));
    return 0;
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
    jmap_closembox(req, &mbox);
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

    /* Parse request */
    jmap_copy_parse(req, &parser, NULL, NULL, &copy, &err);
    if (err) {
        jmap_error(req, err);
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
    jmap_parser_fini(&parser);
    jmap_copy_fini(&copy);
    mailbox_close(&to_mbox);
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
    hash_table *getblobs_by_mailbox;
};

static int getblob_cb(const conv_guidrec_t* rec, void* vrock)
{
    struct getblob_cb_rock *rock = vrock;

    struct getblob_rec *getblob = xzmalloc(sizeof(struct getblob_rec));
    getblob->blob_id = rock->blob_id;
    getblob->uid = rec->uid;
    getblob->part = xstrdupnull(rec->part);

    ptrarray_t *getblobs = hash_lookup(rec->mailbox, rock->getblobs_by_mailbox);
    if (!getblobs) {
        getblobs = ptrarray_new();
        hash_insert(rec->mailbox, getblobs, rock->getblobs_by_mailbox);
    }
    ptrarray_append(getblobs, getblob);

    return 0;
}

static const jmap_property_t blob_props[] = {
    {
        "mailboxIds",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "threadIds",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "emailIds",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    { NULL, NULL, 0 }
};

static int jmap_blob_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    json_t *jval;
    size_t i;

    /* Parse request */
    jmap_get_parse(req, &parser, blob_props, /*allow_null_ids*/0,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Sort blob lookups by mailbox */
    hash_table getblobs_by_mailbox = HASH_TABLE_INITIALIZER;
    construct_hash_table(&getblobs_by_mailbox, 128, 0);
    json_array_foreach(get.ids, i, jval) {
        const char *blob_id = json_string_value(jval);
        if (*blob_id == 'G') {
            struct getblob_cb_rock rock = { req, blob_id, &getblobs_by_mailbox };
            int r = conversations_guid_foreach(req->cstate, blob_id + 1, getblob_cb, &rock);
            if (r) {
                syslog(LOG_ERR, "jmap_blob_get: can't lookup guid %s: %s",
                        blob_id, error_message(r));
            }
        }
    }

    /* Lookup blobs by mailbox */
    json_t *found = json_object();
    hash_iter *iter = hash_table_iter(&getblobs_by_mailbox);
    while (hash_iter_next(iter)) {
        const char *mailbox = hash_iter_key(iter);
        ptrarray_t *getblobs = hash_iter_val(iter);
        struct mailbox *mbox = NULL;
        mbentry_t *mbentry = NULL;
        int r = 0;

        if (req->cstate->folders_byname)
            jmap_mboxlist_lookup(mailbox, &mbentry, NULL);
        else
            mbentry = jmap_mbentry_by_uniqueid_copy(req, mailbox);

        /* Open mailbox */
        if (!jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
            r = IMAP_PERMISSION_DENIED;
        }
        else {
            r = jmap_openmbox(req, mbentry->name, &mbox, 0);
            if (r) {
                syslog(LOG_ERR, "jmap_blob_get: can't open mailbox %s: %s",
                       mbentry->name, error_message(r));
            }
        }
        mboxlist_entry_free(&mbentry);
        if (r) continue;

        int j;
        for (j = 0; j < ptrarray_size(getblobs); j++) {
            struct getblob_rec *getblob = ptrarray_nth(getblobs, j);

            /* Read message record */
            struct message_guid guid;
            bit64 cid;
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

            /* Report Blob entry */
            json_t *jblob = json_object_get(found, getblob->blob_id);
            if (!jblob) {
                jblob = json_object();
                json_object_set_new(found, getblob->blob_id, jblob);
            }
            if (jmap_wantprop(get.props, "mailboxIds")) {
                json_t *jmailboxIds = json_object_get(jblob, "mailboxIds");
                if (!jmailboxIds) {
                    jmailboxIds = json_object();
                    json_object_set_new(jblob, "mailboxIds", jmailboxIds);
                }
                json_object_set_new(jmailboxIds, mbox->uniqueid, json_true());
            }
            if (jmap_wantprop(get.props, "emailIds")) {
                json_t *jemailIds = json_object_get(jblob, "emailIds");
                if (!jemailIds) {
                    jemailIds = json_object();
                    json_object_set_new(jblob, "emailIds", jemailIds);
                }
                char emailid[JMAP_EMAILID_SIZE];
                jmap_set_emailid(&guid, emailid);
                json_object_set_new(jemailIds, emailid, json_true());
            }
            if (jmap_wantprop(get.props, "threadIds")) {
                json_t *jthreadIds = json_object_get(jblob, "threadIds");
                if (!jthreadIds) {
                    jthreadIds = json_object();
                    json_object_set_new(jblob, "threadIds", jthreadIds);
                }
                char threadid[JMAP_THREADID_SIZE];
                jmap_set_threadid(cid, threadid);
                json_object_set_new(jthreadIds, threadid, json_true());
            }
        }

       jmap_closembox(req, &mbox);
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
    free_hash_table(&getblobs_by_mailbox, NULL);

    /* Report found blobs */
    if (json_object_size(found)) {
        const char *blob_id;
        json_t *jblob;
        json_object_foreach(found, blob_id, jblob) {
            json_array_append(get.list, jblob);
        }
    }

    /* Report unknown or erroneous blobs */
    json_array_foreach(get.ids, i, jval) {
        const char *blob_id = json_string_value(jval);
        if (!json_object_get(found, blob_id)) {
            json_array_append_new(get.not_found, json_string(blob_id));
        }
    }

    json_decref(found);

    /* Reply */
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

static const jmap_property_t blob_set_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "content",
        NULL,
        0
    },
    {
        "content64",
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


static int jmap_blob_set(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *jerr = NULL;
    int r = 0;
    time_t now = time(NULL);

    /* Parse arguments */
    jmap_set_parse(req, &parser, blob_set_props, NULL, NULL, &set, &jerr);
    if (jerr) {
        jmap_error(req, jerr);
        goto done;
    }

    /* create */
    const char *key;
    json_t *arg;
    json_object_foreach(set.create, key, arg) {
        struct buf *buf = buf_new();
        struct message_guid guidobj;
        char datestr[RFC3339_DATETIME_MAX];
        char blob_id[JMAP_BLOBID_SIZE];

        json_t *jitem = json_object_get(arg, "content");
        if (JNOTNULL(jitem) && json_is_string(jitem)) {
            buf_init_ro(buf, json_string_value(jitem), json_string_length(jitem));
        }
        else {
            json_t *jitem64 = json_object_get(arg, "content64");
            if (JNOTNULL(jitem64) && json_is_string(jitem64)) {
                int r = charset_decode(buf, json_string_value(jitem64),
                                       json_string_length(jitem64), ENCODING_BASE64);
                if (r) buf_free(buf);
            }
        }

        if (!buf_base(buf)) {
            jerr = json_pack("{s:s}", "type", "invalidProperties");
            json_object_set_new(set.not_updated, key, jerr);
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

    const char *uid;
    json_object_foreach(set.update, uid, arg) {
        jerr = json_pack("{s:s}", "type", "notFound");
        json_object_set_new(set.not_updated, key, jerr);
    }

    size_t index;
    json_t *juid;
    json_array_foreach(set.destroy, index, juid) {
        jerr = json_pack("{s:s}", "type", "notFound");
        json_object_set_new(set.not_destroyed, json_string_value(juid), jerr);
    }

    set.old_state = set.new_state = 0;
    jmap_ok(req, jmap_set_reply(&set));

done:
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    return r;
}


/* Quota/get method */
static const jmap_property_t quota_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "used",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "total",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    { NULL, NULL, 0 }
};

static int jmap_quota_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    char *inboxname = mboxname_user_mbox(req->accountid, NULL);

    /* Parse request */
    jmap_get_parse(req, &parser, quota_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    int want_mail_quota = !get.ids || json_is_null(get.ids);
    size_t i;
    json_t *jval;
    json_array_foreach(get.ids, i, jval) {
        if (strcmp("mail", json_string_value(jval))) {
            json_array_append(get.not_found, jval);
        }
        else want_mail_quota = 1;
    }

    if (want_mail_quota) {
        struct quota quota;
        quota_init(&quota, inboxname);
        int r = quota_read_withconversations(&quota);
        if (!r) {
            quota_t total = quota.limits[QUOTA_STORAGE] * quota_units[QUOTA_STORAGE];
            quota_t used = quota.useds[QUOTA_STORAGE];
            json_t *jquota = json_object();
            json_object_set_new(jquota, "id", json_string("mail"));
            json_object_set_new(jquota, "used", json_integer(used));
            json_object_set_new(jquota, "total", json_integer(total));
            json_array_append_new(get.list, jquota);
        }
        else {
            syslog(LOG_ERR, "jmap_quota_get: can't read quota for %s: %s",
                    inboxname, error_message(r));
            json_array_append_new(get.not_found, json_string("mail"));
        }
        quota_free(&quota);
    }


    modseq_t quotamodseq = mboxname_readquotamodseq(inboxname);
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, quotamodseq);
    get.state = buf_release(&buf);

    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    free(inboxname);
    return 0;
}

/* UserCounters/get method */
static const jmap_property_t usercounters_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "highestModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mailModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "calendarModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "contactsModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "notesModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "submissionModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mailDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "calendarDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "contactsDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "notesDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "submissionDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mailFoldersModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "calendarFoldersModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "contactFoldersModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "notesFoldersModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "submissionFoldersModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mailFoldersDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "calendarFoldersDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "contactFoldersDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "notesFoldersDeletedModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "quotaModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "raclModSeq",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "uidValidity",
        NULL,
        JMAP_PROP_SERVER_SET
    },

    { NULL, NULL, 0 }
};

static void usercounters_get(jmap_req_t *req, struct jmap_get *get)
{
    /* Read script */
    json_t *res = json_pack("{s:s}", "id", "singleton");

    if (jmap_wantprop(get->props, "highestModSeq"))
        json_object_set_new(res, "highestModSeq",
                            json_integer(req->counters.highestmodseq));

    if (jmap_wantprop(get->props, "mailModSeq"))
        json_object_set_new(res, "mailModSeq",
                            json_integer(req->counters.mailmodseq));
    if (jmap_wantprop(get->props, "calendarModSeq"))
        json_object_set_new(res, "calendarModSeq",
                            json_integer(req->counters.caldavmodseq));
    if (jmap_wantprop(get->props, "contactsModSeq"))
        json_object_set_new(res, "contactsModSeq",
                            json_integer(req->counters.carddavmodseq));
    if (jmap_wantprop(get->props, "notesModSeq"))
        json_object_set_new(res, "notesModSeq",
                            json_integer(req->counters.notesmodseq));

    if (jmap_wantprop(get->props, "mailDeletedModSeq"))
        json_object_set_new(res, "mailDeletedModSeq",
                            json_integer(req->counters.maildeletedmodseq));
    if (jmap_wantprop(get->props, "calendarDeletedModSeq"))
        json_object_set_new(res, "calendarDeletedModSeq",
                            json_integer(req->counters.caldavdeletedmodseq));
    if (jmap_wantprop(get->props, "contactsDeletedModSeq"))
        json_object_set_new(res, "contactsDeletedModSeq",
                            json_integer(req->counters.carddavdeletedmodseq));
    if (jmap_wantprop(get->props, "notesDeletedModSeq"))
        json_object_set_new(res, "notesDeletedModSeq",
                            json_integer(req->counters.notesdeletedmodseq));

    if (jmap_wantprop(get->props, "mailFoldersModSeq"))
        json_object_set_new(res, "mailFoldersModSeq",
                            json_integer(req->counters.mailfoldersmodseq));
    if (jmap_wantprop(get->props, "calendarFoldersModSeq"))
        json_object_set_new(res, "calendarFoldersModSeq",
                            json_integer(req->counters.caldavfoldersmodseq));
    if (jmap_wantprop(get->props, "contactsFoldersModSeq"))
        json_object_set_new(res, "contactsFoldersModSeq",
                            json_integer(req->counters.carddavfoldersmodseq));
    if (jmap_wantprop(get->props, "notesFoldersModSeq"))
        json_object_set_new(res, "notesFoldersModSeq",
                            json_integer(req->counters.notesfoldersmodseq));

    if (jmap_wantprop(get->props, "mailFoldersDeletedModSeq"))
        json_object_set_new(res, "mailFoldersDeletedModSeq",
                            json_integer(req->counters.mailfoldersdeletedmodseq));
    if (jmap_wantprop(get->props, "calendarFoldersDeletedModSeq"))
        json_object_set_new(res, "calendarFoldersDeletedModSeq",
                            json_integer(req->counters.caldavfoldersdeletedmodseq));
    if (jmap_wantprop(get->props, "contactsFoldersDeletedModSeq"))
        json_object_set_new(res, "contactsFoldersDeletedModSeq",
                            json_integer(req->counters.carddavfoldersdeletedmodseq));
    if (jmap_wantprop(get->props, "notesFoldersDeletedModSeq"))
        json_object_set_new(res, "notesFoldersDeletedModSeq",
                            json_integer(req->counters.notesfoldersdeletedmodseq));

    if (jmap_wantprop(get->props, "quotaModSeq"))
        json_object_set_new(res, "quotaModSeq",
                            json_integer(req->counters.quotamodseq));
    if (jmap_wantprop(get->props, "raclModSeq"))
        json_object_set_new(res, "raclModSeq",
                            json_integer(req->counters.raclmodseq));

    if (jmap_wantprop(get->props, "uidValidity"))
        json_object_set_new(res, "uidValidity",
                            json_integer(req->counters.uidvalidity));

    json_array_append_new(get->list, res);
}

static int jmap_usercounters_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;

    /* Parse request */
    jmap_get_parse(req, &parser, usercounters_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Does the client request specific responses? */
    if (JNOTNULL(get.ids)) {
        json_t *jval;
        size_t i;

        json_array_foreach(get.ids, i, jval) {
            const char *id = json_string_value(jval);

            if (!strcmp(id, "singleton"))
                usercounters_get(req, &get);
            else
                json_array_append(get.not_found, jval);
        }
    }
    else usercounters_get(req, &get);

    /* Build response */
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, req->counters.highestmodseq);
    get.state = buf_release(&buf);
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);

    return 0;
}
