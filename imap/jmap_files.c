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

#include "acl.h"
#include "append.h"
#include "dav_util.h"
#include "http_jmap.h"
#include "http_proxy.h"
#include "jmap_util.h"
#include "json_support.h"
#include "proxy.h"
#include "sync_support.h"
#include "util.h"
#include "webdav_db.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int jmap_files_get(jmap_req_t *req);
static int jmap_files_set(jmap_req_t *req);

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
        int r;

        if (!strcmp(id, "root")) {
            /* root */
            r = mboxlist_lookup(root, &mbentry, NULL);
        }
        else if (webdav_lookup_uid(db, id, &wdata)) {
            /* folder */
            r = mboxlist_lookup_by_uniqueid(id, &mbentry, NULL);
        }
        else {
            /* file */
            if (wdata->dav.mailbox_byname) {
                r = mboxlist_lookup(wdata->dav.mailbox, &mbentry, NULL);
            }
            else {
                r = mboxlist_lookup_by_uniqueid(wdata->dav.mailbox, &mbentry, NULL);
            }
        }

        if (!r && mbentry &&
            /* Only DAV drive collections... */
            mboxname_isdavdrivemailbox(mbentry->name, mbentry->mbtype) &&
            /* ...which are at least readable or visible... */
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

static json_t *jmap_error_message(int r)
{
    json_t *err = NULL;

    switch (r) {
    case HTTP_FORBIDDEN:
    case IMAP_PERMISSION_DENIED:
        err = json_pack("{s:s}", "type", "forbidden");
        break;
    case IMAP_QUOTA_EXCEEDED:
        err = json_pack("{s:s}", "type", "overQuota");
        break;
    case IMAP_MESSAGE_TOO_LARGE:
        err = json_pack("{s:s}", "type", "tooLarge");
        break;
    default:
        err = jmap_server_error(r);
    }

    return err;
}

static int jmap_files_set(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    struct mailbox *mailbox = NULL;
    json_t *err = NULL;
    int r = 0;

    struct webdav_db *db = webdav_open_userid(req->accountid);
    if (!db) {
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Parse request */
    jmap_set_parse(req, &parser, files_props, NULL, NULL, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidProperties");
        json_object_set(err, "properties", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    if (set.if_in_state) {
        /* TODO rewrite state function to use char* not json_t* */
        json_t *jstate = json_string(set.if_in_state);
        if (jmap_cmpstate(req, jstate, MBTYPE_COLLECTION)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            json_decref(jstate);
            goto done;
        }
        json_decref(jstate);
        set.old_state = xstrdup(set.if_in_state);
    }
    else {
        json_t *jstate = jmap_getstate(req, MBTYPE_COLLECTION, /*refresh*/0);
        set.old_state = xstrdup(json_string_value(jstate));
        json_decref(jstate);
    }
    

    /* create */
    const char *key;
    json_t *arg;
    json_object_foreach(set.create, key, arg) {
        json_t *invalid = json_array();
        json_t *item = json_object();

//        r = _file_set_create(req, arg, NULL, &mailbox, item, &errors);

        if (r) {
            json_t *err = jmap_error_message(r);

            json_object_set_new(set.not_created, key, err);
            json_decref(item);
            json_decref(invalid);
            r = 0;
            continue;
        }
        if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s s:o}",
                                    "type", "invalidProperties",
                                    "properties", invalid);
            json_object_set_new(set.not_created, key, err);
            json_decref(item);
            continue;
        }
        json_decref(invalid);

        /* Report file as created. */
        json_object_set_new(set.created, key, item);

        /* Register creation id */
        jmap_add_id(req, key, json_string_value(json_object_get(item, "id")));
    }



    /* update */
    const char *uid;
    json_object_foreach(set.update, uid, arg) {
        struct webdav_data *wdata = NULL;

        r = webdav_lookup_uid(db, uid, &wdata);

        /* is it a valid contact? */
        if (r || !wdata || !wdata->dav.imap_uid) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_updated, uid, err);
            r = 0;
            continue;
        }

        json_t *item = json_object();
        json_t *invalid = json_array();
//        r = _file_set_update(req, arg, NULL, &mailbox, item, &errors);

        if (r) {
            json_t *err = jmap_error_message(r);

            json_object_set_new(set.not_updated, uid, err);
            json_decref(item);
            json_decref(invalid);
            r = 0;
            continue;
        }
        if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s s:O}",
                                    "type", "invalidProperties",
                                    "properties", invalid);
            json_object_set_new(set.not_updated, uid, err);
            json_decref(item);
            continue;
        }
        json_decref(invalid);

        /* Report file as updated. */
        json_object_set_new(set.updated, uid, item);
    }


    /* destroy */
    size_t index;
    for (index = 0; index < json_array_size(set.destroy); index++) {
        mbentry_t *mbentry = NULL;
        struct webdav_data *wdata = NULL;
        uint32_t olduid;
        const char *uid = json_array_get_string(set.destroy, index);

        if (!uid) {
            json_t *err = json_pack("{s:s}", "type", "invalidArguments");
            json_object_set_new(set.not_destroyed, uid, err);
            continue;
        }

        r = webdav_lookup_uid(db, uid, &wdata);

        /* is it a valid file? */
        if (r || !wdata || !wdata->dav.imap_uid) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_destroyed, uid, err);
            r = 0;
            continue;
        }

        olduid = wdata->dav.imap_uid;
        mbentry = jmap_mbentry_from_dav(req, &wdata->dav);

        if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_REMOVEITEMS)) {
            int rights = mbentry ? jmap_myrights_mbentry(req, mbentry) : 0;
            json_t *err = json_pack("{s:s}", "type",
                                    rights & JACL_READITEMS ?
                                    "accountReadOnly" : "notFound");
            json_object_set_new(set.not_destroyed, uid, err);
            mboxlist_entry_free(&mbentry);
            continue;
        }

        if (!mailbox || strcmp(mailbox_name(mailbox), mbentry->name)) {
            jmap_closembox(req, &mailbox);
            r = jmap_openmbox(req, mbentry->name, &mailbox, 1);
        }
        mboxlist_entry_free(&mbentry);
        if (r) goto done;

        syslog(LOG_NOTICE, "jmap: remove file %s/%s", req->accountid, uid);
        r = dav_remove_resource(mailbox, olduid, /*isreplace*/0, req->userid);
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: webdav remove failed",
                    "mailbox=<%s> olduid=<%u>", mailbox_name(mailbox), olduid);
            goto done;
        }

        json_array_append_new(set.destroyed, json_string(uid));
    }

    /* force modseq to stable */
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    /* Build response */
    json_t *jstate = jmap_getstate(req, MBTYPE_COLLECTION, /*refresh*/1);
    set.new_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    jmap_ok(req, jmap_set_reply(&set));
    r = 0;

done:
    if (r) jmap_error(req, jmap_server_error(r));
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    jmap_closembox(req, &mailbox);
    webdav_close(db);

    return 0;
}
