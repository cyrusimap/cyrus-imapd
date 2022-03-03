/* jmap_files.c -- Routines for handling JMAP files
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <errno.h>

#include "arrayu64.h"
#include "acl.h"
#include "append.h"
#include "cyr_qsort_r.h"
#include "dav_util.h"
#include "hash.h"
#include "http_jmap.h"
#include "http_proxy.h"
#include "jmap_mailbox.h"
#include "jmap_util.h"
#include "json_support.h"
#include "proxy.h"
#include "stristr.h"
#include "sync_support.h"
#include "user.h"
#include "util.h"
#include "webdav_db.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int jmap_files_get(jmap_req_t *req);
static int jmap_files_set(jmap_req_t *req);
static int jmap_files_query(jmap_req_t *req);

static jmap_method_t jmap_files_methods_standard[] = {
    { NULL, NULL, NULL, 0}
};

static jmap_method_t jmap_files_methods_nonstandard[] = {
    {
        "StorageNode/get",
        JMAP_FILES_EXTENSION,
        &jmap_files_get,
        JMAP_NEED_CSTATE
    },
    {
        "StorageNode/set",
        JMAP_FILES_EXTENSION,
        &jmap_files_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "StorageNode/query",
        JMAP_FILES_EXTENSION,
        &jmap_files_query,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_files_init(jmap_settings_t *settings)
{
    jmap_method_t *mp;
    for (mp = jmap_files_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    json_object_set_new(settings->server_capabilities,
            JMAP_FILES_EXTENSION, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        for (mp = jmap_files_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }
}

HIDDEN void jmap_files_capabilities(json_t *account_capabilities)
{
    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities,
                            JMAP_FILES_EXTENSION, json_object());
    }
}

static const jmap_property_t files_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "parentId",
        NULL,
        0
    },
    {
        "blobId",
        NULL,
        0
    },
    {
        "name",
        NULL,
        0
    },
    {
        "type",
        NULL,
        0
    },
    {
        "size",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "created",
        NULL,
        0
    },
    {
        "modified",
        NULL,
        0
    },
    {
        "width",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "height",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "orientation",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "title",
        NULL,
        0
    },
    {
        "comment",
        NULL,
        0
    },
    {
        "myRights",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "shareWith",
        NULL,
        0
    },
    { NULL, NULL, 0 }
};

static int _getargs_parse(jmap_req_t *req __attribute__((unused)),
                          struct jmap_parser *parser __attribute__((unused)),
                          const char *key,
                          json_t *arg,
                          void *rock)
{
    int *includeParentsLimit = (int *) rock;
    int r = 1;

    /* Non-JMAP spec addressbookId argument */
    if (!strcmp(key, "includeParentsLimit") && json_is_integer(arg)) {
        *includeParentsLimit = json_integer_value(arg);
    }

    else r = 0;

    return r;
}

static void _get_file(struct jmap_get *get, struct webdav_data *wdata,
                      const char *parentId, struct buf *buf)
{
    json_t *obj = json_pack("{s:s}", "id", wdata->res_uid);

    if (jmap_wantprop(get->props, "parentId")) {
        json_object_set_new(obj, "parentId", json_string(parentId));
    }

    if (jmap_wantprop(get->props, "blobId")) {
        buf_reset(buf);
        buf_printf(buf, "G%s", wdata->contentid);
        json_object_set_new(obj, "blobId", json_string(buf_cstring(buf)));
    }

    if (jmap_wantprop(get->props, "name")) {
        json_object_set_new(obj, "name", json_string(wdata->filename));
    }

    if (jmap_wantprop(get->props, "type")) {
        buf_reset(buf);
        buf_printf(buf, "%s/%s", wdata->type, wdata->subtype);
        json_object_set_new(obj, "type", json_string(buf_cstring(buf)));
    }

    if (jmap_wantprop(get->props, "size")) {
    }

    if (jmap_wantprop(get->props, "created")) {
    }

    if (jmap_wantprop(get->props, "modified")) {
    }

    if (jmap_wantprop(get->props, "width")) {
        json_object_set_new(obj, "width", json_null());
    }

    if (jmap_wantprop(get->props, "height")) {
        json_object_set_new(obj, "height", json_null());
    }

    if (jmap_wantprop(get->props, "orientation")) {
        json_object_set_new(obj, "orientation", json_null());
    }

    if (jmap_wantprop(get->props, "title")) {
    }

    if (jmap_wantprop(get->props, "comment")) {
    }

    if (jmap_wantprop(get->props, "myRights")) {
    }

    if (jmap_wantprop(get->props, "shareWith")) {
    }

    json_array_append_new(get->list, obj);
}

static void _get_folder(struct jmap_get *get, const mbentry_t *mbentry)
{
    mbname_t *mbname = mbname_from_intname(mbentry->name);
    const strarray_t *boxes = mbname_boxes(mbname);
    const char *name, *id, *parentId = NULL;

    if (strarray_size(boxes) < 2) {
        name = "My Files";
        id = "root";
    }
    else {
        name = strarray_nth(boxes, -1);
        id = mbentry->uniqueid;

        if (strarray_size(boxes) == 2) {
            parentId = "root";
        }
        else {
            /* Will determine parentId if actually requested */
        }
    }

    json_t *obj = json_pack("{s:s}", "id", id);

    if (jmap_wantprop(get->props, "parentId")) {
        mbentry_t *parent = NULL;

        if (strarray_size(boxes) > 2 &&
            !mboxlist_findparent(mbentry->name, &parent)) {
            parentId = parent->uniqueid;
        }

        json_object_set_new(obj, "parentId",
                            parentId ? json_string(parentId) : json_null());
        mboxlist_entry_free(&parent);
    }

    if (jmap_wantprop(get->props, "blobId")) {
        json_object_set_new(obj, "blobId", json_null());
    }

    if (jmap_wantprop(get->props, "name")) {
        json_object_set_new(obj, "name", json_string(name));
    }

    if (jmap_wantprop(get->props, "type")) {
        json_object_set_new(obj, "type", json_null());
    }

    if (jmap_wantprop(get->props, "size")) {
    }

    if (jmap_wantprop(get->props, "created")) {
    }

    if (jmap_wantprop(get->props, "modified")) {
    }

    if (jmap_wantprop(get->props, "width")) {
        json_object_set_new(obj, "width", json_null());
    }

    if (jmap_wantprop(get->props, "height")) {
        json_object_set_new(obj, "height", json_null());
    }

    if (jmap_wantprop(get->props, "orientation")) {
        json_object_set_new(obj, "orientation", json_null());
    }

    if (jmap_wantprop(get->props, "title")) {
        /* XXX  Check mailbox annotation */
        json_object_set_new(obj, "title", json_null());
    }

    if (jmap_wantprop(get->props, "comment")) {
        /* XXX  Check mailbox annotation */
        json_object_set_new(obj, "comment", json_null());
    }

    if (jmap_wantprop(get->props, "myRights")) {
    }

    if (jmap_wantprop(get->props, "shareWith")) {
    }

    json_array_append_new(get->list, obj);

    mbname_free(&mbname);
}

static int jmap_files_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    int includeParentsLimit = 0;
    struct webdav_db *db = NULL;

    jmap_get_parse(req, &parser, files_props, /*allow_null_ids*/0,
                   &_getargs_parse, &includeParentsLimit, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    db = webdav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR,
               "webdav_open_mailbox failed for user %s", req->accountid);
        jmap_error(req, jmap_server_error(IMAP_INTERNAL));
        goto done;
    }

    size_t i;
    json_t *jval;
    struct buf buf = BUF_INITIALIZER;
    char *root = webdav_mboxname(req->accountid, NULL);

    json_array_foreach(get.ids, i, jval) {
        const char *id = json_string_value(jval);
        struct webdav_data *wdata = NULL;
        mbentry_t *mbentry = NULL;
        int r = 0;

        if (!strcmp(id, "root")) {
            /* root */
            r = jmap_mboxlist_lookup(root, &mbentry, NULL);
        }
        else if (webdav_lookup_uid(db, id, &wdata) == 0) {
            /* file */
            mbentry = jmap_mbentry_from_dav(req, &wdata->dav);
        }
        else {
            /* folder */
            mbentry = jmap_mbentry_by_uniqueid_copy(req, id);
        }

        if (!r && mbentry &&
            /* Only DAV drive collections... */
            mboxname_isdavdrivemailbox(mbentry->name, mbentry->mbtype) &&
            /* ...that are NOT deleted... */
            !mboxname_isdeletedmailbox(mbentry->name, NULL) &&
            /* ...and which are at least readable or visible... */
            jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {

            if (wdata && wdata->dav.rowid) {
                const char *parentId =
                    !strcmp(root, mbentry->name) ? "root" : mbentry->uniqueid;

                _get_file(&get, wdata, parentId, &buf);
            }
            else {
                _get_folder(&get, mbentry);
            }
        }
        else {
            json_array_append(get.not_found, jval);
        }

        mboxlist_entry_free(&mbentry);
    }

    webdav_close(db);
    buf_free(&buf);
    free(root);

    /* Build response */
    json_t *jstate = jmap_getstate(req, MBTYPE_COLLECTION, /*refresh*/0);
    get.state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);

    return 0;
}

static void _set_args_parse(json_t *jargs,
                            struct jmap_parser *parser,
                            struct jmap_setmbox_args *args,
                            int is_create)
{
    /* Initialize arguments */
    memset(args, 0, sizeof(struct jmap_setmbox_args));
    args->type = JMAP_SETMBOX_NODE;
    args->jargs = json_incref(jargs);

    /* id */
    json_t *jid = json_object_get(jargs, "id");
    if (json_is_string(jid) && !is_create) {
        args->id = xstrdup(json_string_value(jid));
    }
    else if (JNOTNULL(jid) && is_create) {
        jmap_parser_invalid(parser, "id");
    }

    /* name */
    json_t *jname = json_object_get(jargs, "name");
    if (json_is_string(jname)) {
        char *name = charset_utf8_normalize(json_string_value(jname));
        size_t len = strlen(name);
        int is_valid = 0;
        size_t i;
        for (i = 0; i < len; i++) {
            if (iscntrl(name[i])) {
                is_valid = 0;
                break;
            }
            else if (!isspace(name[i])) {
                is_valid = 1;
            }
        }
        if (is_valid) {
            args->name = name;
        }
        else {
            /* Empty string, bogus characters or just whitespace */
            jmap_parser_invalid(parser, "name");
            free(name);
        }
    }
    else if (is_create) {
        jmap_parser_invalid(parser, "name");
    }

    /* parentId */
    json_t *jparentId = json_object_get(jargs, "parentId");
    if (json_is_string(jparentId)) {
        const char *parent_id = json_string_value(jparentId);
        if (parent_id && (*parent_id != '#' || *(parent_id + 1))) {
            args->parent_id = xstrdup(parent_id);
        }
        if (!args->parent_id) {
            jmap_parser_invalid(parser, "parentId");
        }
    }
    else if (jparentId) {
        jmap_parser_invalid(parser, "parentId");
    }

    /* blobId */
    json_t *jblobId = json_object_get(jargs, "blobId");
    if (json_is_string(jblobId)) {
        const char *blobid = json_string_value(jblobId);
        if (blobid && (*blobid != '#' || *(blobid + 1))) {
            args->u.node.blobid = xstrdup(blobid);
        }
        if (!args->u.node.blobid) {
            jmap_parser_invalid(parser, "blobId");
        }
    } else if (JNOTNULL(jblobId)) {
        jmap_parser_invalid(parser, "blobId");
    }

    /* type */
    json_t *jtype = json_object_get(jargs, "type");
    if (json_is_string(jtype) && args->u.node.blobid) {
        args->u.node.type = xstrdup(json_string_value(jtype));
    } else if (JNOTNULL(jtype)) {
        jmap_parser_invalid(parser, "blobId");
    }

    if (!is_create) {
        /* Is shareWith overwritten or patched? */
        json_t *shareWith = NULL;
        jmap_parse_sharewith_patch(jargs, &shareWith);
        if (shareWith) {
            args->u.mbox.overwrite_acl = 0;
            json_object_set_new(jargs, "shareWith", shareWith);
        }
    }

    /* shareWith */
    args->shareWith = json_object_get(jargs, "shareWith");
    if (args->shareWith && JNOTNULL(args->shareWith) &&
        !json_is_object(args->shareWith)) {
        jmap_parser_invalid(parser, "shareWith");
    }

    /* All of these are server-set. */
    json_t *jrights = json_object_get(jargs, "myRights");
    if (json_is_object(jrights) && !is_create) {
        /* Update allows clients to set myRights, as long as
         * it doesn't change their values. Don't bother with
         * that during parsing, just make sure that it is
         * syntactically valid. */
        const char *right;
        json_t *jval;
        jmap_parser_push(parser, "myRights");
        json_object_foreach(jrights, right, jval) {
            if (!json_is_boolean(jval))
                jmap_parser_invalid(parser, right);
        }
        jmap_parser_pop(parser);
    }
    else if (JNOTNULL(jrights)) {
        jmap_parser_invalid(parser, "myRights");
    }

    if (json_object_get(jargs, "size") && is_create)
        jmap_parser_invalid(parser, "size");
    if (json_object_get(jargs, "width") && is_create)
        jmap_parser_invalid(parser, "width");
    if (json_object_get(jargs, "height") && is_create)
        jmap_parser_invalid(parser, "height");
    if (json_object_get(jargs, "orientation") && is_create)
        jmap_parser_invalid(parser, "orientation");

}

static void _set_parse(jmap_req_t *req,
                       struct jmap_parser *parser,
                       struct jmap_setmbox_ctx *set,
                       json_t **err)
{
    json_t *jarg;
    size_t i;

    memset(set, 0, sizeof(struct jmap_setmbox_ctx));
    jmap_set_parse(req, parser, files_props, NULL, NULL, &set->super, err);

    /* create */
    const char *creation_id = NULL;
    json_object_foreach(set->super.create, creation_id, jarg) {
        struct jmap_parser myparser = JMAP_PARSER_INITIALIZER;
        struct jmap_setmbox_args *args = xzmalloc(sizeof(struct jmap_setmbox_args));
        json_t *set_err = NULL;

        _set_args_parse(jarg, &myparser, args, /*is_create*/1);
        args->creation_id = xstrdup(creation_id);
        if (json_array_size(myparser.invalid)) {
            set_err = json_pack("{s:s}", "type", "invalidProperties");
            json_object_set(set_err, "properties", myparser.invalid);
            json_object_set_new(set->super.not_created, creation_id, set_err);
            jmap_parser_fini(&myparser);
            jmap_setmbox_args_fini(args);
            free(args);
            continue;
        }
        ptrarray_append(&set->to_create, args);
        jmap_parser_fini(&myparser);
    }

    /* update */
    hash_table will_destroy = HASH_TABLE_INITIALIZER;
    size_t size = json_array_size(set->super.destroy);
    if (size) {
        construct_hash_table(&will_destroy, size, 0);
        json_array_foreach(set->super.destroy, i, jarg) {
            hash_insert(json_string_value(jarg), (void*)1, &will_destroy);
        }
    }
    const char *mbox_id = NULL;
    json_object_foreach(set->super.update, mbox_id, jarg) {
        /* Parse Mailbox/set arguments  */
        struct jmap_parser myparser = JMAP_PARSER_INITIALIZER;
        struct jmap_setmbox_args *args = xzmalloc(sizeof(struct jmap_setmbox_args));
        _set_args_parse(jarg, &myparser, args, /*is_create*/0);
        if (args->id && strcmp(args->id, mbox_id)) {
            jmap_parser_invalid(&myparser, "id");
        }
        if (!args->id) args->id = xstrdup(mbox_id);
        if (json_array_size(myparser.invalid)) {
            json_t *err = json_pack("{s:s}", "type", "invalidProperties");
            json_object_set(err, "properties", myparser.invalid);
            json_object_set_new(set->super.not_updated, mbox_id, err);
            jmap_parser_fini(&myparser);
            jmap_setmbox_args_fini(args);
            free(args);
            continue;
        }
        if (hash_lookup(args->id, &will_destroy)) {
            json_t *err = json_pack("{s:s}", "type", "willDestroy");
            json_object_set_new(set->super.not_updated, mbox_id, err);
            jmap_parser_fini(&myparser);
            jmap_setmbox_args_fini(args);
            free(args);
            continue;
        }
        ptrarray_append(&set->to_update, args);
        jmap_parser_fini(&myparser);
    }

    /* destroy */
    set->to_destroy = hash_keys(&will_destroy);
    free_hash_table(&will_destroy, NULL);
}

static const char *_findblob(struct jmap_req *req, const char *id,
                             struct buf *buf, json_t **err)
{
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    const char *orig_id = id;
    const char *content = NULL;
    int r = IMAP_NOTFOUND;

    if (id[0] == '#') {
        id = jmap_lookup_id(req, id + 1);
    }

    if (id) {
        r = jmap_findblob(req, NULL/*accountid*/, id, &mbox, &mr, NULL, NULL, buf);
    }

    if (r == IMAP_NOTFOUND) {
        *err = json_pack("{s:s s:[s]}", "type", "blobNotFound", "Id", orig_id);
    }
    else if (r) {
        *err = jmap_server_error(r);
    }
    else {
        content = buf_cstring(buf);

        if (mr) {
            /* Need to skip over header of rfc822 wrapper */
            struct index_record record;

            msgrecord_get_index_record(mr, &record);
            content += record.header_size;

            msgrecord_unref(&mr);
            jmap_closembox(req, &mbox);
        }
    }

    return content;
}

static void _set_create_file(jmap_req_t *req, struct jmap_setmbox_args *args,
                             enum jmap_setmbox_runmode mode __attribute__((unused)),
                             json_t **file,
                             struct jmap_setmbox_result *result )
{
    json_t *err = NULL;
    struct buf buf = BUF_INITIALIZER;
    const char *content = _findblob(req, args->u.node.blobid, &buf, &err);
    int size = buf_base(&buf) + buf_len(&buf) - content;
    const char *id = makeuuid();
    struct mailbox *mailbox = NULL;
    mbentry_t *mbentry = NULL;
    int r = 0;

    /* XXX  Look for conflicting name */

    if (!strcmp("root", args->parent_id)) {
        char *root = webdav_mboxname(req->accountid, NULL);
        r = jmap_mboxlist_lookup(root, &mbentry, NULL);
        free(root);
    }
    else {
        const char *parent_id = args->parent_id;

        if (*parent_id == '#') {
            parent_id = jmap_lookup_id(req, parent_id + 1);
        }
        if (parent_id) {
            mbentry = jmap_mbentry_by_uniqueid_copy(req, parent_id);
        }
    }

    if (r || !mbentry ||
        !jmap_hasrights_mbentry(req, mbentry, JACL_ADDITEMS)) {
        result->err = json_pack("{s:s}", "type", "forbidden");
        goto done;
    }

    r = jmap_openmbox(req, mbentry->name, &mailbox, 1);
    if (r) goto done;

    /* Create and cache RFC 5322 header fields for resource */
    spool_replace_header(xstrdup("Subject"),
                         xstrdup(args->name), req->txn->req_hdrs);

    json_t *jdesc = json_pack("{ s:s s:s }",
                              "uid", id, "filename", args->name);
    spool_replace_header(xstrdup("Content-Description"),
                         json_dumps(jdesc, JSON_COMPACT), req->txn->req_hdrs);
    json_decref(jdesc);

    buf_printf(&req->txn->buf, "<%s@%s>", id, config_servername);
    spool_replace_header(xstrdup("Message-ID"),
                         buf_release(&req->txn->buf), req->txn->req_hdrs);

    buf_printf(&req->txn->buf, "attachment;\r\n\tfilename=\"%s\"", args->name);
    spool_replace_header(xstrdup("Content-Disposition"),
                         buf_release(&req->txn->buf), req->txn->req_hdrs);

    /* Store the resource */
    r = dav_store_resource(req->txn, content, size, mailbox, NULL, 0, NULL, NULL);
    switch (r) {
    case 0:
    case HTTP_CREATED:
        r = 0;
        break;
    default:
        goto done;
    }

    *file = json_pack("{s:s}", "id", id);

    /* Set server defaults */
    json_object_set_new(*file, "size", json_integer(size));

  done:
    if (r && result->err == NULL) {
        result->err = jmap_server_error(r);
    }

    jmap_closembox(req, &mailbox);
    mboxlist_entry_free(&mbentry);
    buf_free(&buf);
}

static void _set_create_folder(jmap_req_t *req, struct jmap_setmbox_args *args,
                               enum jmap_setmbox_runmode mode,
                               json_t **mbox, struct jmap_setmbox_result *result,
                               strarray_t *update_intermediaries)
{
    char *mboxname = NULL;
    int r = 0;
    mbentry_t *mbroot = NULL, *mbentry = NULL;
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct mailbox *mailbox = NULL;

    char *root = webdav_mboxname(req->accountid, NULL);
    jmap_mboxlist_lookup(root, &mbroot, NULL);
    free(root);

    /* Lookup parent creation id, if any. This also deals with
     * bogus File/set operations that attempt to create
     * cycles in the mailbox tree: they'll all fail due to
     * unresolvable parentIds. */
    const char *parent_id = args->parent_id;
    if (!strcmp("root", parent_id)) {
        parent_id = mbroot->uniqueid;
    }
    else if (*parent_id == '#') {
        parent_id = jmap_lookup_id(req, parent_id + 1);
        if (!parent_id) {
            if (mode == JMAP_SETMBOX_SKIP) {
                result->skipped = 1;
            }
            else {
                jmap_parser_invalid(&parser, "parentId");
            }
            goto done;
        }
    }

    /* Check parent exists and has the proper ACL. */
    const mbentry_t *mbparent = jmap_mbentry_by_uniqueid(req, parent_id);
    if (!mbparent || !jmap_hasrights_mbentry(req, mbparent, JACL_CREATECHILD)) {
        jmap_parser_invalid(&parser, "parentId");
        goto done;
    }

    /* Encode the mailbox name for IMAP. */
    mboxname = jmap_mbox_newname(args->name, mbparent->name, 0);
    if (!mboxname) {
        syslog(LOG_ERR, "could not encode mailbox name");
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Check if a mailbox with this name exists */
    r = jmap_mboxlist_lookup(mboxname, NULL, NULL);
    if (r == 0) {
        if (mode == JMAP_SETMBOX_SKIP) {
            result->skipped = 1;
            goto done;
        }
        else if (mode == JMAP_SETMBOX_INTERIM) {
            result->new_imapname = xstrdup(mboxname);
            result->old_imapname = NULL;
            result->tmp_imapname = jmap_mbox_tmpname(args->name, mbparent->name, 0);
            if (!result->tmp_imapname) {
                syslog(LOG_ERR, "jmap: no mailbox tmpname for %s", mboxname);
                r = IMAP_INTERNAL;
                goto done;
            }
            free(mboxname);
            mboxname = xstrdup(result->tmp_imapname);
            /* Keep on processing with tmpname */
        }
        else {
            syslog(LOG_ERR, "jmap: mailbox already exists: %s", mboxname);
            jmap_parser_invalid(&parser, "name");
            goto done;
        }
    }
    else if (r != IMAP_MAILBOX_NONEXISTENT) {
        goto done;
    }
    r = 0;

    /* Create mailbox */
    mbentry_t newmbentry = MBENTRY_INITIALIZER;
    newmbentry.name = mboxname;
    newmbentry.mbtype = MBTYPE_COLLECTION;

    r = mboxlist_createmailbox(&newmbentry, 0/*options*/, 0/*highestmodseq*/,
                               0/*isadmin*/, req->userid, req->authstate,
                               MBOXLIST_CREATE_KEEP_INTERMEDIARIES,
                               args->shareWith ? &mailbox : NULL);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                mboxname, error_message(r));
        goto done;
    }
    strarray_add(update_intermediaries, mboxname);

     /* invalidate ACL cache */
    jmap_myrights_delete(req, mboxname);
    jmap_mbentry_cache_free(req);

    /* shareWith */
    if (args->shareWith) {
        r = jmap_set_sharewith(mailbox, args->shareWith,
                               args->u.mbox.overwrite_acl,
                               jmap_mbox_sharewith_to_rights);
        mailbox_close(&mailbox);
    }
    if (r) goto done;

    /* Write annotations */
//    r = _mbox_set_annots(req, args, mboxname);
    if (r) goto done;

    /* Lookup and return the new mailbox id */
    r = jmap_mboxlist_lookup(mboxname, &mbentry, NULL);
    if (r) goto done;
    *mbox = json_pack("{s:s}", "id", mbentry->uniqueid);
    /* Set server defaults */
//    if (args->u.mbox.is_subscribed < 0) {
//        json_object_set_new(*mbox, "isSubscribed", json_false());
//    }

done:
    if (json_array_size(parser.invalid)) {
        result->err = json_pack("{s:s}", "type", "invalidProperties");
        json_object_set(result->err, "properties", parser.invalid);
    }
    else if (r) {
        result->err = jmap_server_error(r);
    }
    free(mboxname);
    mboxlist_entry_free(&mbroot);
    mboxlist_entry_free(&mbentry);
    jmap_parser_fini(&parser);
}

static void _set_create(jmap_req_t *req, struct jmap_setmbox_args *args,
                        enum jmap_setmbox_runmode mode,
                        json_t **mbox, struct jmap_setmbox_result *result,
                        strarray_t *update_intermediaries)
{
    if (args->u.node.blobid) {
        return _set_create_file(req, args, mode, mbox, result);
    }

    return _set_create_folder(req, args, mode,
                              mbox, result, update_intermediaries);
}

static void _set_update_folder(jmap_req_t *req, struct jmap_setmbox_args *args,
                               enum jmap_setmbox_runmode mode,
                               struct jmap_setmbox_result *result,
                               strarray_t *update_intermediaries)
{
    /* So many names... manage them in our own string pool */
    ptrarray_t strpool = PTRARRAY_INITIALIZER;
    int r = 0;
    mbentry_t *mbroot = NULL, *mbparent = NULL, *mbentry = NULL;
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;

    char *root = webdav_mboxname(req->accountid, NULL);
    jmap_mboxlist_lookup(root, &mbroot, NULL);
    free(root);

    const char *parent_id = args->parent_id;
    if (!strcmpnull("root", parent_id)) {
        parent_id = mbroot->uniqueid;
    }
    else if (parent_id && *parent_id == '#') {
        parent_id = jmap_lookup_id(req, parent_id + 1);
        if (!parent_id) {
            if (mode == JMAP_SETMBOX_SKIP) {
                result->skipped = 1;
            }
            else {
                jmap_parser_invalid(&parser, "parentId");
            }
            goto done;
        }
    }

    /* Lookup current mailbox entry */
    mbentry = jmap_mbentry_by_uniqueid_copy(req, args->id);
    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_LOOKUP)) {
        mboxlist_entry_free(&mbentry);
        result->err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    /* Validate server-set properties */
//    _mbox_update_validate_serverset(req, args, &parser, mbentry);

    /* Determine current mailbox and parent names */
    char *oldmboxname = NULL;
    char *oldparentname = NULL;
    int was_toplevel = 0;
    int is_inbox = 0;
    if (strcmp(args->id, mbroot->uniqueid)) {
        oldmboxname = xstrdup(mbentry->name);
        r = jmap_mailbox_findparent(oldmboxname, &mbparent);
        if (r) {
            syslog(LOG_INFO, "_findparent(%s) failed: %s",
                            oldmboxname, error_message(r));
            goto done;
        }
        oldparentname = xstrdup(mbparent->name);
        ptrarray_append(&strpool, oldparentname);

        // calculate whether mailbox is toplevel
        mbname_t *mbname = mbname_from_intname(oldmboxname);
        was_toplevel = strarray_size(mbname_boxes(mbname)) == 1;
        mbname_free(&mbname);
    }
    else {
        if (parent_id || args->is_toplevel) {
            // thou shalt not move INBOX
           jmap_parser_invalid(&parser, "parentId");
           goto done;
        }
        is_inbox = 1;

        oldmboxname = xstrdup(mbroot->name);
    }
    ptrarray_append(&strpool, oldmboxname);

    /* Now parent_id always has a proper mailbox id */
    parent_id = args->is_toplevel ? mbroot->uniqueid : parent_id;

    /* Do we need to move this mailbox to a new parent? */
    const char *parentname = oldparentname;
    int is_toplevel = was_toplevel;
    int force_rename = 0;

    if (!is_inbox && (parent_id || args->is_toplevel)) {
        /* Compare old parent with new parent. */
        char *newparentname = NULL;

        mbentry_t *pmbentry = jmap_mbentry_by_uniqueid_copy(req, parent_id);
        if (pmbentry && jmap_hasrights_mbentry(req, pmbentry, JACL_LOOKUP)) {
            newparentname = xstrdup(pmbentry->name);
        }
        mboxlist_entry_free(&pmbentry);

        int new_toplevel = args->is_toplevel;
        if (!newparentname) {
            jmap_parser_invalid(&parser, "parentId");
            goto done;
        }
        ptrarray_append(&strpool, newparentname);

        /* Reject cycles in mailbox tree. */
        char *pname = xstrdup(newparentname);
        while (jmap_mailbox_findparent(pname, &pmbentry) == 0) {
            if (!strcmp(args->id, pmbentry->uniqueid)) {
                jmap_parser_invalid(&parser, "parentId");
                free(pname);
                mboxlist_entry_free(&pmbentry);
                goto done;
            }
            free(pname);
            pname = xstrdup(pmbentry->name);
            mboxlist_entry_free(&pmbentry);
        }
        mboxlist_entry_free(&pmbentry);
        free(pname);

        /* Is this a move to a new parent? */
        if (strcmpsafe(oldparentname, newparentname) || was_toplevel != new_toplevel) {
            /* Check ACL of mailbox */
            if (!jmap_hasrights(req, oldparentname, JACL_DELETE)) {
                result->err = json_pack("{s:s}", "type", "forbidden");
                goto done;
            }

            /* Reset pointers to parent */
            mboxlist_entry_free(&mbparent);
            jmap_mboxlist_lookup(newparentname, &mbparent, NULL);

            /* Check ACL of new parent - need WRITE to set displayname annot */
            if (!jmap_hasrights_mbentry(req, mbparent, JACL_CREATECHILD|JACL_SETKEYWORDS)) {
                jmap_parser_invalid(&parser, "parentId");
                goto done;
            }

            force_rename = 1;
            parentname = newparentname;
            is_toplevel = new_toplevel;
        }
    }

    const char *mboxname = oldmboxname;

    /* Do we need to rename the mailbox? But only if it isn't the INBOX! */
    if (!is_inbox && (args->name || force_rename)) {
        mbname_t *mbname = mbname_from_intname(oldmboxname);
        char *oldname = jmap_mbox_get_name(req->accountid, mbname);
        mbname_free(&mbname);
        ptrarray_append(&strpool, oldname);
        char *name = oldname;
        if (args->name && strcmp(name, args->name)) {
            name = args->name;
            force_rename = 1;
        }

        if (is_toplevel && !strcasecmp(name, "inbox")) {
            /* you can't write a top-level mailbox called "INBOX" in any case.  If the old
             * name wasn't "inbox" then the name is bad, otherwise it's the NULL parentId
             * that is the problem */
            jmap_parser_invalid(&parser, strcasecmp(oldname, "inbox") ? "name" : "parentId");
            goto done;
        }

        /* Do old and new mailbox names differ? */
        if (force_rename) {

            /* Determine the unique IMAP mailbox name. */
            char *newmboxname =
                jmap_mbox_newname(name, parentname, is_toplevel);
            if (!newmboxname) {
                syslog(LOG_ERR, "_mbox_newname returns NULL: can't rename %s", mboxname);
                r = IMAP_INTERNAL;
                goto done;
            }
            ptrarray_append(&strpool, newmboxname);

            r = jmap_mboxlist_lookup(newmboxname, NULL, NULL);
            if (r == 0) {
                if (mode == JMAP_SETMBOX_SKIP) {
                    result->skipped = 1;
                    goto done;
                }
                else if (mode == JMAP_SETMBOX_INTERIM) {
                    result->new_imapname = xstrdup(newmboxname);
                    result->old_imapname = xstrdup(oldmboxname);
                    result->tmp_imapname =
                        jmap_mbox_tmpname(name, parentname, is_toplevel);
                    if (!result->tmp_imapname) {
                        syslog(LOG_ERR, "jmap: no mailbox tmpname for %s", newmboxname);
                        r = IMAP_INTERNAL;
                        goto done;
                    }
                    newmboxname = xstrdup(result->tmp_imapname);
                    ptrarray_append(&strpool, newmboxname);
                    /* Keep on processing with tmpname */
                }
                else {
                    syslog(LOG_ERR, "jmap: mailbox already exists: %s", newmboxname);
                    jmap_parser_invalid(&parser, "name");
                    goto done;
                }
            }
            else if (r != IMAP_MAILBOX_NONEXISTENT) {
                goto done;
            }
            r = 0;

            /* Rename the mailbox. */
            if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
                r = mboxlist_promote_intermediary(oldmboxname);
                if (r) goto done;
            }
            struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_RENAME);
            r = mboxlist_renametree(oldmboxname, newmboxname,
                    NULL /* partition */, 0 /* uidvalidity */,
                    httpd_userisadmin, req->userid, httpd_authstate,
                    mboxevent,
                    0 /* local_only */, 0 /* forceuser */, 0 /* ignorequota */,
                    1 /* keep_intermediaries */, 1 /* move_subscription */);
            mboxevent_free(&mboxevent);
            mboxlist_entry_free(&mbentry);
            jmap_mboxlist_lookup(newmboxname, &mbentry, NULL);
            strarray_add(update_intermediaries, oldmboxname);
            strarray_add(update_intermediaries, newmboxname);

            /* Keep track of old IMAP name */
            if (!result->old_imapname)
                result->old_imapname = xstrdup(oldmboxname);

            /* invalidate ACL cache */
            jmap_myrights_delete(req, oldmboxname);
            jmap_myrights_delete(req, newmboxname);
            jmap_mbentry_cache_free(req);

            if (r) {
                syslog(LOG_ERR, "mboxlist_renametree(old=%s new=%s): %s",
                        oldmboxname, newmboxname, error_message(r));
                goto done;
            }
            mboxname = newmboxname;  // cheap and nasty change!
        }
    }

    /* Write annotations */

    int set_annots = 0;
#if 0
    if (args->name || args->u.mbox.specialuse) {
        // these set for everyone
        if (!jmap_hasrights_mbentry(req, mbentry, JACL_SETKEYWORDS)) {
            mboxlist_entry_free(&mbentry);
            result->err = json_pack("{s:s}", "type", "forbidden");
            goto done;
        }
        set_annots = 1;
    }
    if (args->u.mbox.sortorder >= 0 ||
        args->u.mbox.color || args->u.mbox.show_as_label >= 0) {
        // these are per-user, so you just need READ access
        if (!jmap_hasrights_mbentry(req, mbentry, ACL_READ)) {
            mboxlist_entry_free(&mbentry);
            result->err = json_pack("{s:s}", "type", "forbidden");
            goto done;
        }
        set_annots = 1;
    }
#endif
    if (set_annots) {
        if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
            r = mboxlist_promote_intermediary(mbentry->name);
            if (r) goto done;
            mboxlist_entry_free(&mbentry);
            jmap_mboxlist_lookup(mboxname, &mbentry, NULL);
        }
//        if (!r) r = _mbox_set_annots(req, args, mboxname);
    }

    if (!r && args->shareWith) {
        struct mailbox *mbox = NULL;

        r = jmap_openmbox(req, mboxname, &mbox, 1);
        if (r) goto done;

        r = jmap_set_sharewith(mbox, args->shareWith, 1,
                               jmap_mbox_sharewith_to_rights);

        jmap_closembox(req, &mbox);
    }
    if (r) goto done;

done:
    if (json_array_size(parser.invalid)) {
        result->err = json_pack("{s:s}", "type", "invalidProperties");
        json_object_set(result->err, "properties", parser.invalid);
    }
    else if (r && result->err == NULL) {
        result->err = jmap_server_error(r);
    }
    jmap_parser_fini(&parser);
    while (strpool.count) free(ptrarray_pop(&strpool));
    ptrarray_fini(&strpool);
    mboxlist_entry_free(&mbroot);
    mboxlist_entry_free(&mbparent);
    mboxlist_entry_free(&mbentry);
}

static void _set_update(jmap_req_t *req, struct jmap_setmbox_args *args,
                        enum jmap_setmbox_runmode mode,
                        struct jmap_setmbox_result *result,
                        strarray_t *update_intermediaries)
{
    if (args->u.node.blobid) {
    }

    return _set_update_folder(req, args, mode, result, update_intermediaries);
}

struct destroy_msg {
    char *jmap_id;
    uint32_t imap_uid;
};

static void _set_destroy_files(jmap_req_t *req __attribute__((unused)),
                               struct jmap_setmbox_ctx *set,
                               struct webdav_db *db)
{
    int size = strarray_size(set->to_destroy);

    if (!size) return;

    /* Create a hash table of mailbox ids and a list of message UIDs */
    hash_table uids_by_mboxid = HASH_TABLE_INITIALIZER;
    construct_hash_table(&uids_by_mboxid, size, 0);

    int i = 0;
    while (i < strarray_size(set->to_destroy)) {
        struct webdav_data *wdata = NULL;

        /* Is this a file? */
        int r = webdav_lookup_uid(db, strarray_nth(set->to_destroy, i), &wdata);

        if (!r && wdata && wdata->dav.imap_uid) {
            /* Remove this id from mailboxes list */
            char *id = strarray_remove(set->to_destroy, i);

            /* Add this msg to mboxid bucket */
            ptrarray_t *msgs = hash_lookup(wdata->dav.mailbox, &uids_by_mboxid);

            if (!msgs) {
                msgs = ptrarray_new();
                hash_insert(wdata->dav.mailbox, msgs, &uids_by_mboxid);
            }

            struct destroy_msg *msg = xmalloc(sizeof(struct destroy_msg));
            msg->jmap_id = id;
            msg->imap_uid = wdata->dav.imap_uid;
            ptrarray_append(msgs, msg);

        }
        else {
            /* Skip to next id */
            i++;
        }
    }

    /* Now delete files on a per-mailbox basis */
    const char *mboxid;
    hash_iter *iter = hash_table_iter(&uids_by_mboxid);
    while ((mboxid = hash_iter_next(iter))) {
        const mbentry_t *mbentry = jmap_mbentry_by_uniqueid(req, mboxid);
        ptrarray_t *msgs = hash_iter_val(iter);
        struct mailbox *mailbox = NULL;
        int r = 0;

        if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_REMOVEITEMS)) {
            r = IMAP_PERMISSION_DENIED;
        }
        else {
            r = jmap_openmbox_by_uniqueid(req, mboxid, &mailbox, 1);
        }

        while (ptrarray_size(msgs)) {
            struct destroy_msg *msg = ptrarray_pop(msgs);

            if (!r && mailbox) {
                r = dav_remove_resource(mailbox, msg->imap_uid, 0, req->accountid);
            }

            if (r) {
                json_object_set_new(set->super.not_destroyed, msg->jmap_id,
                                    jmap_server_error(r));
            }
            else {
                json_array_append_new(set->super.destroyed,
                                      json_string(msg->jmap_id));
            }

            free(msg->jmap_id);
            free(msg);
        }
        jmap_closembox(req, &mailbox);
        ptrarray_free(msgs);
    }

    hash_iter_free(&iter);
    free_hash_table(&uids_by_mboxid, NULL);
}

static int jmap_files_set(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_setmbox_ctx set;
    struct webdav_db *db;

    /* Parse arguments */
    json_t *arg_err = NULL;
    _set_parse(req, &parser, &set, &arg_err);
    if (arg_err) {
        jmap_error(req, arg_err);
        goto done;
    }
    if (set.super.if_in_state) {
        json_t *jstate = json_string(set.super.if_in_state);
        if (jmap_cmpstate(req, jstate, MBTYPE_EMAIL)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
        json_decref(jstate);
        set.super.old_state = xstrdup(set.super.if_in_state);
    }
    else {
        json_t *jstate = jmap_getstate(req, MBTYPE_COLLECTION, /*refresh*/0);
        set.super.old_state = xstrdup(json_string_value(jstate));
        json_decref(jstate);
    }

    db = webdav_open_userid(req->accountid);
    if (!db) {
        syslog(LOG_ERR,
               "webdav_open_mailbox failed for user %s", req->accountid);
        jmap_error(req, jmap_server_error(IMAP_INTERNAL));
        goto done;
    }

    struct mboxlock *namespacelock = user_namespacelock(req->accountid);

    /* Destroy files first */
    _set_destroy_files(req, &set, db);

    /* Now do the rest of the create/update/destroy */
    set.mbtype = MBTYPE_COLLECTION;
    set.create_proc = &_set_create;
    set.update_proc = &_set_update;
    jmap_setmbox(req, &set);

    mboxname_release(&namespacelock);
    jmap_ok(req, jmap_set_reply(&set.super));

    webdav_close(db);

  done:
    jmap_parser_fini(&parser);
    jmap_setmbox_fini(&set);
    return 0;
}

static void filter_validate(jmap_req_t *req __attribute__((unused)),
                            struct jmap_parser *parser,
                            json_t *filter,
                            json_t *unsupported __attribute__((unused)),
                            void *rock __attribute__((unused)),
                            json_t **err __attribute__((unused)))
{
    const char *field;
    json_t *arg;

    json_object_foreach(filter, field, arg) {
        if (!strcmp(field, "parentIds")) {
            jmap_parse_strings(arg, parser, field);
        }
        else if (!strcmp(field, "ancestorIds")) {
            jmap_parse_strings(arg, parser, field);
        }
        else if (!strcmp(field, "hasBlobId")) {
            if (!json_is_boolean(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "createdBefore")) {
            if (!json_is_date(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "createdAfter")) {
            if (!json_is_date(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "modifiedBefore")) {
            if (!json_is_date(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "modifiedAfter")) {
            if (!json_is_date(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "minSize")) {
            if (!json_is_integer(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "maxSize")) {
            if (!json_is_integer(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "name")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "type")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else {
            jmap_parser_invalid(parser, field);
        }
    }
}


static int comparator_validate(jmap_req_t *req __attribute__((unused)),
                               struct jmap_comparator *comp,
                               void *rock __attribute__((unused)),
                               json_t **err __attribute__((unused)))
{
    /* Reject any collation */
    if (comp->collation) {
        return 0;
    }
    if (!strcmp(comp->property, "id") ||
        !strcmp(comp->property, "hasBlobId") ||
        !strcmp(comp->property, "name") ||
        !strcmp(comp->property, "type") ||
        !strcmp(comp->property, "size") ||
        !strcmp(comp->property, "created") ||
        !strcmp(comp->property, "modified")) {
        return 1;
    }
    return 0;
}

typedef struct file_filter {
    hash_table *parentIds;
    strarray_t *ancestorIds;
    int hasBlobId;
    time_t createdBefore;
    time_t createdAfter;
    time_t modifiedBefore;
    time_t modifiedAfter;
    long long int minSize;
    long long int maxSize;
    const char *name;
    const char *type;
    int files_prefilter_result;
} file_filter_t;

/* Free the memory allocated by this filter. */
static void filter_free(void *vf)
{
    file_filter_t *f = (file_filter_t *) vf;

    if (f->parentIds) {
        free_hash_table(f->parentIds, NULL);
        free(f->parentIds);
    }
    strarray_free(f->ancestorIds);
    free(f);
}

static void *filter_build(json_t *arg, void *rock)
{
    file_filter_t *f = (file_filter_t *) xzmalloc(sizeof(file_filter_t));
    const char *root = (const char *) rock;
    json_t *ids;
    size_t i;
    json_t *val;
    const char *id;

    f->hasBlobId = -1;
    f->maxSize = ULLONG_MAX;
#if (SIZEOF_TIME_T == SIZEOF_LONG_LONG_INT)
    f->createdBefore  = LLONG_MAX;
    f->createdAfter   = LLONG_MIN;
    f->modifiedBefore = LLONG_MAX;
    f->modifiedAfter  = LLONG_MIN;
#else
    f->createdBefore  = LONG_MAX;
    f->createdAfter   = LONG_MIN;
    f->modifiedBefore = LONG_MAX;
    f->modifiedAfter  = LONG_MIN;
#endif

    /* parentIds */
    ids = json_object_get(arg, "parentIds");
    if (ids) {
        f->parentIds = xmalloc(sizeof(struct hash_table));
        construct_hash_table(f->parentIds,
                             json_array_size(ids)+1, 0);
        json_array_foreach(ids, i, val) {
            mbentry_t *mbentry = NULL;
            if (json_unpack(val, "s", &id) != -1) {
                if (!strcmp("root", id))
                    hash_insert(root, (void*)1, f->parentIds);
                else if (!mboxlist_lookup_by_uniqueid(id, &mbentry, NULL))
                    hash_insert(mbentry->name, (void*)1, f->parentIds);
            }
            mboxlist_entry_free(&mbentry);
        }
    }

    /* ancestorIds */
    ids = json_object_get(arg, "ancestorIds");
    if (ids) {
        f->ancestorIds = strarray_new();
        json_array_foreach(ids, i, val) {
            mbentry_t *mbentry = NULL;
            if (json_unpack(val, "s", &id) != -1 &&
                !mboxlist_lookup_by_uniqueid(id, &mbentry, NULL)) {
                strarray_append(f->ancestorIds, mbentry->name);
            }
            mboxlist_entry_free(&mbentry);
        }
    }

    /* hasBlobId */
    if (JNOTNULL(json_object_get(arg, "hasBlobId"))) {
        jmap_readprop(arg, "hasBlobId", 0, NULL, "b", &f->hasBlobId);
    }

    /* name */
    if (JNOTNULL(json_object_get(arg, "name"))) {
        jmap_readprop(arg, "name", 0, NULL, "s", &f->name);
    }

    /* type */
    if (JNOTNULL(json_object_get(arg, "type"))) {
        jmap_readprop(arg, "type", 0, NULL, "s", &f->type);
    }

    return f;
}

typedef struct file_info {
    char *id;
    char *name;
    char *type;
    size_t size;
    time_t created;
    time_t modified;
    unsigned hasBlobId : 1;
} file_info_t;

static void free_file_info(void *data)
{
    file_info_t *info = (file_info_t *) data;

    if (!info) return;

    free(info->id);
    free(info->name);
    free(info->type);
    free(info);
}

typedef struct filter_rock {
    struct jmap_query *query;
    jmap_filter *parsed_filter;
    struct webdav_db *db;
    const char *root;
    ptrarray_t matches;
    file_info_t *anchor;
} filter_rock_t;

typedef struct match_folder_rock {
    const mbentry_t *mbentry;
    mbname_t *mbname;
} match_folder_rock_t;

/* Match the folder in rock against filter. */
static int filter_match_folder(void *vf, void *rock)
{
    file_filter_t *f = (file_filter_t *) vf;
    match_folder_rock_t *mf = (match_folder_rock_t *) rock;

    /* hasBlobId */
    if (f->hasBlobId == 1) return 0;

    if (f->name || f->parentIds) {
        if (!mf->mbname) mf->mbname = mbname_from_intname(mf->mbentry->name);

        /* Pop off the name to generate parentId, but replace it when done */
        char *name = mbname_pop_boxes(mf->mbname);
        int r = 1;

        /* name */
        if (f->name && !stristr(name, f->name)) r = 0;  // XXX  FIXME

        /* parentIds */
        else if (f->parentIds &&
                 !hash_lookup(mbname_intname(mf->mbname), f->parentIds)) r = 0;

        mbname_push_boxes(mf->mbname, name);
        free(name);

        if (r == 0) return 0;
    }

    /* All matched. */
    return 1;
}

/* Match the file in rock against filter. */
static int prefilter_match_files(void *vf, void *rock)
{
    file_filter_t *f = (file_filter_t *) vf;
    const mbentry_t *mbentry = (const mbentry_t *) rock;
    int r = 1;

    /* hasBlobId */
    if (f->hasBlobId == 0) r = 0;

    /* parentIds */
    else if (f->parentIds && !hash_lookup(mbentry->name, f->parentIds)) r = 0;

    /* All matched. */
    return (f->files_prefilter_result = r);
}

/* Match the file in rock against filter. */
static int filter_match_file(void *vf, void *rock)
{
    file_filter_t *f = (file_filter_t *) vf;
    struct webdav_data *wdata = (struct webdav_data *) rock;

    /* hasBlobId and parentIds */
    if (f->files_prefilter_result == 0) return 0;

    /* name */
    if (f->name && !stristr(wdata->filename, f->name)) return 0;  // XXX  FIXME

    /* All matched. */
    return 1;
}

static int filter_files_cb(void *rock, struct webdav_data *wdata)
{
    filter_rock_t *frock = (filter_rock_t *) rock;
    struct jmap_query *query = frock->query;
    file_info_t *info;

    if (!query->filter ||
        jmap_filter_match(frock->parsed_filter, &filter_match_file, wdata)) {
        info = xzmalloc(sizeof(file_info_t));
        info->id = xstrdup(wdata->res_uid);
        info->name = xstrdup(wdata->filename);
        info->type = strconcat(wdata->type, "/", wdata->subtype, NULL);
        info->hasBlobId = 1;

        /* Add record of the match to our array */
        ptrarray_append(&frock->matches, info);

        if (query->anchor && !strcmp(query->anchor, info->id)) {
            /* Mark record corresponding to anchor */
            frock->anchor = info;
        }

        query->total++;
    }

    return 0;
}

static int filter_folders_cb(const mbentry_t *mbentry, void *rock)
{
    filter_rock_t *frock = (filter_rock_t *) rock;
    struct jmap_query *query = frock->query;
    match_folder_rock_t mf = { mbentry, NULL };
    file_info_t *info;

    /* Filter folder */
    if (strcmp(mbentry->name, frock->root) &&
        (!query->filter ||
         jmap_filter_match(frock->parsed_filter, &filter_match_folder, &mf))) {

        if (!mf.mbname) mf.mbname = mbname_from_intname(mbentry->name);

        info = xzmalloc(sizeof(file_info_t));
        info->id = xstrdup(mbentry->uniqueid);
        info->name = xstrdup(strarray_nth(mbname_boxes(mf.mbname), -1));

        /* Add record of the match to our array */
        ptrarray_append(&frock->matches, info);

        if (query->anchor && !strcmp(query->anchor, info->id)) {
            /* Mark record corresponding to anchor */
            frock->anchor = info;
        }

        query->total++;
    }

    /* Prefilter this folder for files */
    if (!query->filter ||
        jmap_filter_match(frock->parsed_filter,
                          &prefilter_match_files, (void *) mbentry)) {
        /* Now filter files in this folder */
        webdav_foreach(frock->db, mbentry, &filter_files_cb, frock);
    }

    mbname_free(&mf.mbname);

    return 0;
}

enum files_sort {
    FILES_SORT_NONE = 0,
    FILES_SORT_ID,
    FILES_SORT_HASBLOBID,
    FILES_SORT_NAME,
    FILES_SORT_TYPE,
    FILES_SORT_SIZE,
    FILES_SORT_CREATED,
    FILES_SORT_MODIFIED,
    FILES_SORT_DESC = 0x80 /* bit-flag for descending sort */
};

static int files_cmp QSORT_R_COMPAR_ARGS(const void *va, const void *vb,
                                         void *rock)
{
    arrayu64_t *sortcrit = (arrayu64_t *) rock;
    file_info_t *ma = (file_info_t *) *(void **) va;
    file_info_t *mb = (file_info_t *) *(void **) vb;
    size_t i, nsort = arrayu64_size(sortcrit);

    for (i = 0; i < nsort; i++) {
        enum files_sort sort = arrayu64_nth(sortcrit, i);
        int ret = 0;

        switch (sort & ~FILES_SORT_DESC) {
        case FILES_SORT_ID:
            ret = strcmp(ma->id, mb->id);
            break;

        case FILES_SORT_HASBLOBID:
            ret = ma->hasBlobId - mb->hasBlobId;
            break;

        case FILES_SORT_NAME:
            ret = strcmp(ma->name, mb->name);
            break;

        case FILES_SORT_TYPE:
            ret = strcmpnull(ma->type, mb->type);
            break;

        case FILES_SORT_SIZE:
            ret = ma->size - mb->size;
            break;

        case FILES_SORT_CREATED:
            ret = ma->created - mb->created;
            break;

        case FILES_SORT_MODIFIED:
            ret = ma->modified - mb->modified;
            break;
        }

        if (ret) return (sort & FILES_SORT_DESC) ? -ret : ret;
    }

    return 0;
}

static int jmap_files_query(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;
    jmap_filter *parsed_filter = NULL;
    arrayu64_t sortcrit = ARRAYU64_INITIALIZER;
    struct webdav_db *db = NULL;
    int r = 0;

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req, &parser, NULL, NULL, filter_validate, NULL,
                     comparator_validate, NULL, &query, &err);
    if (err) goto done;
    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidArguments");
        json_object_set(err, "arguments", parser.invalid);
        goto done;
    }

    db = webdav_open_userid(req->accountid);
    if (!db) {
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Build filter */
    char *root = webdav_mboxname(req->accountid, NULL);
    if (JNOTNULL(query.filter)) {
        parsed_filter = jmap_buildfilter(query.filter, filter_build, root);
    }

    /* Build sort */
    if (json_array_size(query.sort)) {
        json_t *jval;
        size_t i;
        json_array_foreach(query.sort, i, jval) {
            const char *prop =
                json_string_value(json_object_get(jval, "property"));
            enum files_sort sort = FILES_SORT_NONE;

            if (!strcmp(prop, "id")) {
                sort = FILES_SORT_ID;
            } else if (!strcmp(prop, "hasBlobId")) {
                sort = FILES_SORT_HASBLOBID;
            } else if (!strcmp(prop, "name")) {
                sort = FILES_SORT_NAME;
            } else if (!strcmp(prop, "type")) {
                sort = FILES_SORT_TYPE;
            } else if (!strcmp(prop, "size")) {
                sort = FILES_SORT_SIZE;
            } else if (!strcmp(prop, "created")) {
                sort = FILES_SORT_CREATED;
            } else if (!strcmp(prop, "modified")) {
                sort = FILES_SORT_MODIFIED;
            }

            if (json_object_get(jval, "isAscending") == json_false()) {
                sort |= FILES_SORT_DESC;
            }

            arrayu64_append(&sortcrit, sort);
        }
    }

    /* Filter the resources */
    filter_rock_t frock = {
        &query, parsed_filter, db, root, PTRARRAY_INITIALIZER, NULL };

    r = mboxlist_mboxtree(root, &filter_folders_cb, &frock, 0);
    free(root);

    /* Sort results */
    if (arrayu64_size(&sortcrit)) {
        cyr_qsort_r(frock.matches.data, frock.matches.count,
                    sizeof(void *), &files_cmp, &sortcrit);
    }
    arrayu64_fini(&sortcrit);

    /* Process results */
    if (query.anchor) {
        query.position = ptrarray_find(&frock.matches, frock.anchor, 0);
        if (query.position < 0) {
            query.position = query.total;
        }
        else {
            query.position += query.anchor_offset;
        }
    }
    else if (query.position < 0) {
        query.position += query.total;
    }
    if (query.position < 0) query.position = 0;

    size_t i;
    for (i = 0; i < query.total; i++) {
        file_info_t *match = ptrarray_nth(&frock.matches, i);

        /* Apply position and limit */
        if (i >= (size_t) query.position &&
            (!query.limit || query.limit > json_array_size(query.ids))) {
            /* Add the identifier */
            json_array_append_new(query.ids, json_string(match->id));
        }

        free_file_info(ptrarray_nth(&frock.matches, i));
    }
    ptrarray_fini(&frock.matches);

    /* Build response */
    json_t *jstate = jmap_getstate(req, MBTYPE_COLLECTION, /*refresh*/0);
    query.query_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    jmap_ok(req, jmap_query_reply(&query));

done:
    if (r) err = jmap_server_error(r);
    if (err) jmap_error(req, err);
    if (parsed_filter) jmap_filter_free(parsed_filter, filter_free);
    jmap_parser_fini(&parser);
    jmap_query_fini(&query);
    webdav_close(db);

    return 0;
}
