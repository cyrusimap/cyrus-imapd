/* jmap_sieve.c -- Routines for managing Sieve scripts via JMAP
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <dirent.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "arrayu64.h"
#include "cyr_qsort_r.h"
#include "hash.h"
#include "http_jmap.h"
#include "jmap_mail.h"
#include "jmap_mail_query.h"
#include "json_support.h"
#include "map.h"
#include "parseaddr.h"
#include "sieve_db.h"
#include "sievedir.h"
#include "sieve/sieve_interface.h"
#include "sieve/bc_parse.h"
#include "strarray.h"
#include "sync_log.h"
#include "times.h"
#include "tok.h"
#include "user.h"
#include "util.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int jmap_sieve_get(jmap_req_t *req);
static int jmap_sieve_set(jmap_req_t *req);
static int jmap_sieve_query(jmap_req_t *req);
static int jmap_sieve_validate(jmap_req_t *req);
static int jmap_sieve_test(jmap_req_t *req);

static int maxscripts = 0;
static json_int_t maxscriptsize = 0;

static jmap_method_t jmap_sieve_methods_standard[] = {
    { NULL, NULL, NULL, 0}
};

static jmap_method_t jmap_sieve_methods_nonstandard[] = {
    {
        "SieveScript/get",
        JMAP_SIEVE_EXTENSION,
        &jmap_sieve_get,
        /*flags*/0
    },
    {
        "SieveScript/set",
        JMAP_SIEVE_EXTENSION,
        &jmap_sieve_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "SieveScript/query",
        JMAP_SIEVE_EXTENSION,
        &jmap_sieve_query,
        /*flags*/0
    },
    {
        "SieveScript/validate",
        JMAP_SIEVE_EXTENSION,
        &jmap_sieve_validate,
        JMAP_NEED_CSTATE
    },
    {
        "SieveScript/test",
        JMAP_SIEVE_EXTENSION,
        &jmap_sieve_test,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_sieve_init(jmap_settings_t *settings)
{
    jmap_method_t *mp;
    for (mp = jmap_sieve_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    json_object_set_new(settings->server_capabilities,
            JMAP_SIEVE_EXTENSION, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        for (mp = jmap_sieve_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }

    maxscripts = config_getint(IMAPOPT_SIEVE_MAXSCRIPTS);
    maxscriptsize = config_getint(IMAPOPT_SIEVE_MAXSCRIPTSIZE) * 1024;
}

HIDDEN void jmap_sieve_capabilities(json_t *account_capabilities)
{
    static json_t *sieve_capabilities = NULL;

    if (!sieve_capabilities) {
        sieve_interp_t *interp = sieve_build_nonexec_interp();
        const strarray_t *ext = NULL;

        sieve_capabilities = json_pack("{s:b s:n s:i s:I}",
                                       "supportsTest", 1,
                                       "maxRedirects",
                                       "maxNumberScripts", maxscripts,
                                       "maxSizeScript", maxscriptsize);

        if (interp && (ext = sieve_listextensions(interp))) {
            int i;

            for (i = 0; i < strarray_size(ext); i += 2) {
                const char *key = strarray_nth(ext, i);

                if (!strcmp(key, "SIEVE")) key = "sieveExtensions";
                else if (!strcmp(key, "NOTIFY")) key = "notificationMethods";
                else if (!strcmp(key, "EXTLISTS")) key = "externalLists";
                else continue;

                tok_t tok = TOK_INITIALIZER(strarray_nth(ext, i+1),
                                            " ", TOK_TRIMLEFT|TOK_TRIMRIGHT);
                json_t *vals = json_array();
                const char *val;

                while ((val = tok_next(&tok))) {
                    json_array_append_new(vals, json_string(val));
                }
                tok_fini(&tok);

                json_object_set_new(sieve_capabilities, key, vals);
            }
        }
        if (interp) sieve_interp_free(&interp);
    }

    json_object_set(account_capabilities, JMAP_SIEVE_EXTENSION, sieve_capabilities);
}

static const jmap_property_t sieve_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "name",
        NULL,
        0
    },
    {
        "isActive",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "blobId",
        NULL,
        0
    },
    { NULL, NULL, 0 }
};

static int getscript(void *rock, struct sieve_data *sdata)
{
    struct jmap_get *get = (struct jmap_get *) rock;
    json_t *sieve = json_pack("{s:s}", "id", sdata->id);

    if (jmap_wantprop(get->props, "name")) {
        json_object_set_new(sieve, "name", json_string(sdata->name));
    }

    if (jmap_wantprop(get->props, "isActive")) {
        json_object_set_new(sieve, "isActive", json_boolean(sdata->isactive));
    }

    if (jmap_wantprop(get->props, "blobId")) {
        struct buf buf = BUF_INITIALIZER;
        struct message_guid uuid;

        message_guid_generate(&uuid, sdata->content, strlen(sdata->content));
        buf_printf(&buf, "G%s", message_guid_encode(&uuid));
        json_object_set_new(sieve, "blobId", json_string(buf_cstring(&buf)));
        buf_free(&buf);
    }

    /* Add object to list */
    json_array_append_new(get->list, sieve);

    return 0;
}

static int jmap_sieve_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    struct mailbox *mailbox = NULL;
    struct sieve_db *db = NULL;
    int r = 0;

    /* Parse request */
    jmap_get_parse(req, &parser, sieve_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    r = sieve_ensure_folder(req->accountid, &mailbox);
    if (r) goto done;

    mailbox_unlock_index(mailbox, NULL);

    db = sievedb_open_userid(req->accountid);
    if (!db) {
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Does the client request specific responses? */
    if (JNOTNULL(get.ids)) {
        json_t *jval;
        size_t i;

        json_array_foreach(get.ids, i, jval) {
            const char *id = json_string_value(jval);
            struct sieve_data *sdata = NULL;

            r = sievedb_lookup_id(db, id, &sdata, 0);
            if (r || !sdata->imap_uid) {
                json_array_append_new(get.not_found, json_string(id));
                r = 0;
            }
            else {
                getscript(&get, sdata);
            }
        }
    }
    else {
        sievedb_foreach(db, &getscript, &get);
    }

    /* Build response */
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, mailbox->i.highestmodseq);
    get.state = buf_release(&buf);
    jmap_ok(req, jmap_get_reply(&get));

done:
    if (r) jmap_error(req, jmap_server_error(r));
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);

    mailbox_close(&mailbox);
    sievedb_close(db);

    return 0;
}

static int putscript(struct mailbox *mailbox, struct sieve_data *sdata,
                     json_t **err)
{
    /* check script size */
    if ((json_int_t) strlen(sdata->content) > maxscriptsize) {
        *err = json_pack("{s:s}", "type", "tooLarge");
        return 0;
    }

    /* parse the script */
    char *errors = NULL;
    int r = sieve_script_parse_string(NULL, sdata->content, &errors, NULL);
    if (r) {
        *err = json_pack("{s:s, s:s}", "type", "invalidScript",
                         "description", errors);
        free(errors);
        return 0;
    }

    r = sieve_script_store(mailbox, sdata);
    if (r) *err = jmap_server_error(r);

    return 0;
}

static const char *script_findblob(struct jmap_req *req, const char *id,
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

static const char *set_create(struct jmap_req *req,
                              const char *creation_id, json_t *jsieve,
                              struct mailbox *mailbox, struct sieve_db *db,
                              struct jmap_set *set)
{
    json_t *arg, *invalid = json_array(), *err = NULL;
    const char *id = makeuuid(), *name = NULL, *content = NULL;
    struct buf buf = BUF_INITIALIZER;
    int r;

    arg = json_object_get(jsieve, "id");
    if (arg) json_array_append_new(invalid, json_string("id"));

    arg = json_object_get(jsieve, "name");
    if (!JNOTNULL(arg))
        name = id;
    else if (!json_is_string(arg))
        json_array_append_new(invalid, json_string("name"));
    else  {
        /* sanity check script name and check for name collision */
        struct buf buf = BUF_INITIALIZER;
        struct sieve_data *exists = NULL;

        name = json_string_value(arg);
        buf_init_ro_cstr(&buf, name);
        if (!sievedir_valid_name(&buf)) {
            json_array_append_new(invalid, json_string("name"));
        }
        else if (!strcmp(name, JMAP_URN_VACATION)) {
            json_array_append_new(invalid, json_string("name"));
        }
        else {
            r = sievedb_lookup_name(db, mailbox_name(mailbox), name, &exists, 0);
            if (!r)  {
                err = json_pack("{s:s}", "type", "alreadyExists");
                goto done;
            }
            else if (r != CYRUSDB_NOTFOUND) {
                err = jmap_server_error(IMAP_INTERNAL);
                goto done;
            }
        }
    }

    arg = json_object_get(jsieve, "blobId");
    if (!arg || !json_is_string(arg))
        json_array_append_new(invalid, json_string("blobId"));
    else {
        content = script_findblob(req, json_string_value(arg), &buf, &err);
        if (err) goto done;
    }

    /* Report any property errors and bail out */
    if (json_array_size(invalid)) {
        err = json_pack("{s:s, s:O}",
                        "type", "invalidProperties", "properties", invalid);
        goto done;
    }

    struct sieve_data sdata;
    memset(&sdata, 0, sizeof(sdata));
    sdata.id = id;
    sdata.name = name;
    sdata.content = content;
    r = putscript(mailbox, &sdata, &err);
    if (err) goto done;

    if (!r) {
        /* Report script as created, with server-set properties */
        struct message_guid uuid;

        message_guid_generate(&uuid, content, strlen(content));
        buf_reset(&buf);
        buf_printf(&buf, "G%s", message_guid_encode(&uuid));

        json_t *new_sieve = json_pack("{s:s s:b s:s}",
                                      "id", id, "isActive", 0,
                                      "blobId", buf_cstring(&buf));

        if (name == id) {
            json_object_set_new(new_sieve, "name", json_string(name));
        }

        json_object_set_new(set->created, creation_id, new_sieve);
    }

  done:
    if (err) {
        json_object_set_new(set->not_created, creation_id, err);
        id = NULL;
    }
    json_decref(invalid);
    buf_free(&buf);

    return id;
}

static void set_update(struct jmap_req *req,
                       const char *id, json_t *jsieve,
                       struct mailbox *mailbox, struct sieve_db *db,
                       struct jmap_set *set)
{
    json_t *arg, *invalid = json_array(), *err = NULL;
    const char *name = NULL, *content = NULL;
    struct buf buf = BUF_INITIALIZER;
    struct sieve_data *sdata = NULL;
    int r = 0;

    if (!id) return;

    arg = json_object_get(jsieve, "name");
    if (arg) {
        if (json_is_string(arg)) {
            /* sanity check script name and check for name collision */
            struct buf buf = BUF_INITIALIZER;

            name = json_string_value(arg);
            buf_init_ro_cstr(&buf, name);
            if (!sievedir_valid_name(&buf)) {
                json_array_append_new(invalid, json_string("name"));
            }
            else if (!strcmp(name, JMAP_URN_VACATION)) {
                err = json_pack("{s:s s:s}", "type", "forbidden",
                                "description",
                                "MUST use VacationResponse/set method");
                r = 0;
                goto done;
            }
            else {
                r = sievedb_lookup_name(db, mailbox_name(mailbox), name, &sdata, 0);
                if (!r && strcmp(id, sdata->id))  {
                    err = json_pack("{s:s}", "type", "alreadyExists");
                    r = 0;
                    goto done;
                }
                else if (r && r != CYRUSDB_NOTFOUND) {
                    r = IMAP_INTERNAL;
                    goto done;
                }
            }
        }
        else if (json_is_null(arg)) {
            name = id;
        }
        else {
            json_array_append_new(invalid, json_string("name"));
        }
    }

    r = sievedb_lookup_id(db, id, &sdata, 0);
    if (r == CYRUSDB_NOTFOUND) {
        err = json_pack("{s:s}", "type", "notFound");
        r = 0;
        goto done;
    }
    else if (r != CYRUSDB_OK) {
        r = IMAP_INTERNAL;
        goto done;
    }

    arg = json_object_get(jsieve, "isActive");
    if (arg) {
        if (!json_is_boolean(arg))
            json_array_append_new(invalid, json_string("isActive"));
        else if (json_boolean_value(arg) != sdata->isactive) {
            /* isActive MUST be current value, if present */
            json_array_append_new(invalid, json_string("isActive"));
        }
    }
 
    arg = json_object_get(jsieve, "blobId");
    if (arg) {
        if (!json_is_string(arg))
            json_array_append_new(invalid, json_string("blobId"));
        else {
            content = script_findblob(req, json_string_value(arg), &buf, &err);
            if (err) goto done;
        }
    }

    /* Report any property errors and bail out */
    if (json_array_size(invalid)) {
        err = json_pack("{s:s, s:O}",
                        "type", "invalidProperties", "properties", invalid);
        goto done;
    }

    if (name) sdata->name = name;
    if (content) sdata->content = content;

    r = putscript(mailbox, sdata, &err);
    if (err) goto done;

    /* Report script as updated, with server-set properties */
    json_t *new_sieve = NULL;
    if (content) {
        struct message_guid uuid;

        message_guid_generate(&uuid, content, strlen(content));
        buf_reset(&buf);
        buf_printf(&buf, "G%s", message_guid_encode(&uuid));

        new_sieve = json_pack("{s:s}", "blobId", buf_cstring(&buf));
    }
    else {
        new_sieve = json_null();
    }
    json_object_set_new(set->updated, id, new_sieve);

  done:
    if (r) {
        err = jmap_server_error(r);
    }
    if (err) {
        json_object_set_new(set->not_updated, id, err);
    }
    json_decref(invalid);
    buf_free(&buf);
}

static void set_destroy(const char *id,
                        struct mailbox *mailbox, struct sieve_db *db,
                        struct jmap_set *set)
{
    struct sieve_data *sdata = NULL;
    json_t *err = NULL;
    int r;

    r = sievedb_lookup_id(db, id, &sdata, 0);
    if (r == CYRUSDB_NOTFOUND) {
        err = json_pack("{s:s}", "type", "notFound");
    }
    else if (r != CYRUSDB_OK) {
        r = IMAP_INTERNAL;
    }
    else if (sdata->isactive) {
        err = json_pack("{s:s}", "type", "scriptIsActive");
    }
    else if (!strcmp(sdata->name, JMAP_URN_VACATION)) {
        err = json_pack("{s:s s:s}", "type", "forbidden",
                        "description", "MUST use VacationResponse/set method");
    }
    else if ((r = sieve_script_remove(mailbox, sdata))) {
        err = jmap_server_error(r);
    }

    if (err) {
        json_object_set_new(set->not_destroyed, id, err);
    }
    else {
        json_array_append_new(set->destroyed, json_string(id));
    }
}

static void set_activate(const char *id,
                         struct mailbox *mailbox, struct sieve_db *db,
                         struct jmap_set *set)
{
    struct sieve_data *sdata = NULL;
    char *old_id = NULL;
    json_t *created = NULL;
    int r;

    /* Lookup currently active script */
    r = sievedb_lookup_active(db, &sdata);
    if (!r) old_id = xstrdup(sdata->id);

    if (id) {
        if (id[0] == '#') {
            /* Resolve creation id */
            created = json_object_get(set->created, id+1);
            if (!created) {
                json_object_set_new(set->not_updated, id,
                                    json_pack("{s:s}", "type", "notFound"));
                goto done;
            }

            id = json_string_value(json_object_get(created, "id"));
        }
        if (id && json_array_find(set->destroyed, id) >= 0) {
            /* Don't try to activate a destroyed script */
            goto done;
        }

        r = sievedb_lookup_id(db, id, &sdata, 0);
        if (r || !sdata->imap_uid) {
            json_object_set_new(set->not_updated, id,
                                json_pack("{s:s}", "type", "notFound"));
            goto done;
        }
    }
    else {
        sdata = NULL;
    }

    if (id || old_id) {
        r = sieve_script_activate(mailbox, sdata);
        if (r) {
            json_object_set_new(set->not_updated, id ? id : old_id,
                                json_pack("{s:s s:s}",
                                          "type", "serverFail",
                                          "description", error_message(r)));
            goto done;
        }
    }

    if (old_id) {
        /* Report previous active script as updated */
        json_object_set_new(set->updated, old_id,
                            json_pack("{s:b}", "isActive", 0));
    }

    if (created) {
        /* Report new script as active */
        json_object_set_new(created, "isActive", json_true());
    }
    else if (id) {
        /* Report current active script as updated */
        json_object_set_new(set->updated, id,
                            json_pack("{s:b}", "isActive", 1));
    }

  done:
    free(old_id);
}

struct sieve_set_args {
    json_t *onSuccessActivate;
};

static int _sieve_setargs_parse(jmap_req_t *req __attribute__((unused)),
                                struct jmap_parser *parser __attribute__((unused)),
                                const char *key,
                                json_t *arg,
                                void *rock)
{
    struct sieve_set_args *set = (struct sieve_set_args *) rock;
    int r = 1;

    if (!strcmp(key, "onSuccessActivateScript")) {
        if (json_is_string(arg) || json_is_null(arg))
            set->onSuccessActivate = arg;
        else r = 0;
    }

    else r = 0;

    return r;
}

static int jmap_sieve_set(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    struct sieve_set_args sub_args = { NULL };
    json_t *jerr = NULL;
    struct mailbox *mailbox = NULL;
    struct sieve_db *db = NULL;
    struct buf buf = BUF_INITIALIZER;
    int r = 0;

    /* Parse arguments */
    jmap_set_parse(req, &parser, sieve_props,
                   &_sieve_setargs_parse, &sub_args, &set, &jerr);
    if (jerr) goto done;

    db = sievedb_open_userid(req->accountid);
    if (!db) {
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Validate scriptId in onSuccessActivateScript */
    if (JNOTNULL(sub_args.onSuccessActivate)) {
        const char *id = json_string_value(sub_args.onSuccessActivate);
        int found;

        jmap_parser_push(&parser, "onSuccessActivateScript");

        if (*id == '#') {
            found = json_object_get(set.create, id+1) != NULL;
        }
        else if ((found = json_array_find(set.destroy, id) < 0)) {
            struct sieve_data *sdata = NULL;

            r = sievedb_lookup_id(db, id, &sdata, 0);
            found = (!r && sdata->imap_uid);
        }

        if (!found) {
            jmap_parser_invalid(&parser, id);
            jerr = json_pack("{s:s s:O}", "type", "invalidArguments",
                             "arguments", parser.invalid);
        }

        jmap_parser_pop(&parser);
    }

    if (jerr) goto done;

    r = sieve_ensure_folder(req->accountid, &mailbox);
    if (r) goto done;

    buf_printf(&buf, MODSEQ_FMT, mailbox->i.highestmodseq);
    set.old_state = buf_release(&buf);

    if (set.if_in_state && strcmp(set.if_in_state, set.old_state)) {
        jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
        goto done;
    }


    /* create */
    const char *creation_id, *script_id;
    json_t *val;
    if (json_object_size(set.create)) {
        /* Count existing scripts */
        int num_scripts;

        r = sievedb_count(db, &num_scripts);
        if (r) {
            r = IMAP_INTERNAL;
            goto done;
        }

        json_object_foreach(set.create, creation_id, val) {
            if (num_scripts >= maxscripts) {
                json_object_set_new(set.not_created, creation_id,
                                    json_pack("{s:s}", "type", "overQuota"));
                continue;
            }

            script_id = set_create(req, creation_id, val, mailbox, db, &set);
            if (script_id) {
                /* Register creation id */
                jmap_add_id(req, creation_id, script_id);

                num_scripts++;
            }
        }
    }


    /* update */
    const char *id;
    json_object_foreach(set.update, id, val) {
        script_id = (id && id[0] == '#') ? jmap_lookup_id(req, id + 1) : id;
        if (!script_id) continue;

        set_update(req, script_id, val, mailbox, db, &set);
    }


    /* destroy */
    size_t i;
    json_array_foreach(set.destroy, i, val) {
        id = json_string_value(val);
        script_id = (id && id[0] == '#') ? jmap_lookup_id(req, id + 1) : id;
        if (!script_id) continue;

        set_destroy(script_id, mailbox, db, &set);
    }

    if (sub_args.onSuccessActivate &&
        !json_object_size(set.not_created) &&
        !json_object_size(set.not_updated) &&
        !json_array_size(set.not_destroyed)) {

        id = json_string_value(sub_args.onSuccessActivate);
        set_activate(id, mailbox, db, &set);
        sync_log_sieve(req->accountid);
    }
    else if (json_object_size(set.created) ||
             json_object_size(set.updated) ||
             json_array_size(set.destroyed)) {
        sync_log_sieve(req->accountid);
    }

    /* Build response */
    buf_reset(&buf);
    buf_printf(&buf, MODSEQ_FMT, mailbox->i.highestmodseq);
    set.new_state = buf_release(&buf);
    jmap_ok(req, jmap_set_reply(&set));

done:
    if (r) {
        jerr = jmap_server_error(r);
    }
    if (jerr) {
        jmap_error(req, jerr);
    }
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);

    mailbox_close(&mailbox);
    sievedb_close(db);

    return 0;
}

static void filter_parse(jmap_req_t *req __attribute__((unused)),
                         struct jmap_parser *parser,
                         json_t *filter,
                         json_t *unsupported __attribute__((unused)),
                         void *rock __attribute__((unused)),
                         json_t **err __attribute__((unused)))
{
    const char *field;
    json_t *arg;

    json_object_foreach(filter, field, arg) {
        if (!strcmp(field, "name")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "isActive")) {
            if (!json_is_boolean(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else {
            jmap_parser_invalid(parser, field);
        }
    }
}


static int comparator_parse(jmap_req_t *req __attribute__((unused)),
                            struct jmap_comparator *comp,
                            void *rock __attribute__((unused)),
                            json_t **err __attribute__((unused)))
{
    if (comp->collation) {
        return 0;
    }
    if (!strcmp(comp->property, "name") ||
        !strcmp(comp->property, "isActive")) {
        return 1;
    }
    return 0;
}

typedef struct filter {
    const char *name;
    int isactive;
} filter;

static void *filter_build(json_t *arg)
{
    filter *f = (filter *) xzmalloc(sizeof(struct filter));

    f->isactive = -1;

    /* name */
    if (JNOTNULL(json_object_get(arg, "name"))) {
        jmap_readprop(arg, "name", 0, NULL, "s", &f->name);
    }

    /* isActive */
    if (JNOTNULL(json_object_get(arg, "isActive"))) {
        jmap_readprop(arg, "isActive", 0, NULL, "b", &f->isactive);
    }

    return f;
}

/* Match the script in rock against filter. */
static int filter_match(void *vf, void *rock)
{
    filter *f = (filter *) vf;
    struct sieve_data *sdata = (struct sieve_data *) rock;

    /* name */
    if (f->name && !strstr(sdata->name, f->name)) return 0;

    /* isActive */
    if (f->isactive != -1 && ((int) sdata->isactive != f->isactive)) return 0;

    /* All matched. */
    return 1;
}

typedef struct script_info {
    char *id;
    char *name;
    int isactive;
} script_info;

static void free_script_info(void *data)
{
    script_info *info = (script_info *) data;

    if (!info) return;

    free(info->id);
    free(info->name);
    free(info);
}

typedef struct filter_rock {
    struct jmap_query *query;
    jmap_filter *parsed_filter;
    ptrarray_t matches;
    script_info *anchor;
} filter_rock;

static int filter_cb(void *rock, struct sieve_data *sdata)
{
    struct filter_rock *frock = (struct filter_rock *) rock;
    struct jmap_query *query = frock->query;
    script_info *info;

    if (query->filter &&
        !jmap_filter_match(frock->parsed_filter, &filter_match, sdata)) {
        return 0;
    }

    info = xmalloc(sizeof(script_info));

    info->id = xstrdup(sdata->id);
    info->name = xstrdup(sdata->name);
    info->isactive = sdata->isactive;

    /* Add record of the match to our array */
    ptrarray_append(&frock->matches, info);

    if (query->anchor && !strcmp(query->anchor, info->id)) {
        /* Mark record corresponding to anchor */
        frock->anchor = info;
    }

    query->total++;

    return 0;
}

enum sieve_sort {
    SIEVE_SORT_NONE = 0,
    SIEVE_SORT_NAME,
    SIEVE_SORT_ACTIVE,
    SIEVE_SORT_DESC = 0x80 /* bit-flag for descending sort */
};

static int sieve_cmp QSORT_R_COMPAR_ARGS(const void *va, const void *vb, void *rock)
{
    arrayu64_t *sortcrit = (arrayu64_t *) rock;
    script_info *ma = (script_info *) *(void **) va;
    script_info *mb = (script_info *) *(void **) vb;
    size_t i, nsort = arrayu64_size(sortcrit);

    for (i = 0; i < nsort; i++) {
        enum sieve_sort sort = arrayu64_nth(sortcrit, i);
        int ret = 0;

        switch (sort & ~SIEVE_SORT_DESC) {
        case SIEVE_SORT_NAME:
            ret = strcmp(ma->name, mb->name);
            break;

        case SIEVE_SORT_ACTIVE:
            if (ma->isactive < mb->isactive)
                ret = -1;
            else if (ma->isactive > mb->isactive)
                ret = 1;
            break;
        }

        if (ret) return (sort & SIEVE_SORT_DESC) ? -ret : ret;
    }

    return 0;
}

static int jmap_sieve_query(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;
    jmap_filter *parsed_filter = NULL;
    arrayu64_t sortcrit = ARRAYU64_INITIALIZER;
    struct mailbox *mailbox = NULL;
    struct sieve_db *db = NULL;
    int r = 0;

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req, &parser, NULL, NULL,
                     filter_parse, NULL, comparator_parse, NULL, &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build filter */
    if (JNOTNULL(query.filter)) {
        parsed_filter = jmap_buildfilter(query.filter, filter_build);
    }

    /* Build sort */
    if (json_array_size(query.sort)) {
        json_t *jval;
        size_t i;
        json_array_foreach(query.sort, i, jval) {
            const char *prop = json_string_value(json_object_get(jval, "property"));
            enum sieve_sort sort = SIEVE_SORT_NONE;

            if (!strcmp(prop, "name")) {
                sort = SIEVE_SORT_NAME;
            } else if (!strcmp(prop, "isActive")) {
                sort = SIEVE_SORT_ACTIVE;
            }

            if (json_object_get(jval, "isAscending") == json_false()) {
                sort |= SIEVE_SORT_DESC;
            }

            arrayu64_append(&sortcrit, sort);
        }
    }

    r = sieve_ensure_folder(req->accountid, &mailbox);
    if (r) goto done;

    mailbox_unlock_index(mailbox, NULL);

    db = sievedb_open_userid(req->accountid);
    if (!db) {
        r = IMAP_INTERNAL;
        goto done;
    }

    filter_rock frock = { &query, parsed_filter, PTRARRAY_INITIALIZER, NULL };

    /* Filter the scripts */
    sievedb_foreach(db, &filter_cb, &frock);

    /* Sort results */
    if (arrayu64_size(&sortcrit)) {
        cyr_qsort_r(frock.matches.data, frock.matches.count,
                    sizeof(void *), &sieve_cmp, &sortcrit);
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
        script_info *match = ptrarray_nth(&frock.matches, i);

        /* Apply position and limit */
        if (i >= (size_t) query.position &&
            (!query.limit || query.limit > json_array_size(query.ids))) {
            /* Add the submission identifier */
            json_array_append_new(query.ids, json_string(match->id));
        }

        free_script_info(match);
    }
    ptrarray_fini(&frock.matches);

    if (parsed_filter) jmap_filter_free(parsed_filter, &free);

    /* Build response */
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, mailbox->i.highestmodseq);
    query.query_state = buf_release(&buf);
    query.result_position = query.position;
    query.can_calculate_changes = 0;
    jmap_ok(req, jmap_query_reply(&query));

done:
    if (r) jmap_error(req, jmap_server_error(r));
    jmap_parser_fini(&parser);
    jmap_query_fini(&query);

    mailbox_close(&mailbox);
    sievedb_close(db);

    return 0;
}

static int jmap_sieve_validate(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    const char *key, *content = NULL;
    struct buf buf = BUF_INITIALIZER;
    json_t *arg, *err = NULL;

    /* Parse request */
    json_object_foreach(req->args, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        else if (!content && !strcmp(key, "blobId") && json_is_string(arg)) {
            content = script_findblob(req, json_string_value(arg), &buf, &err);
            if (err) {
                jmap_error(req, err);
                goto done;
            }
        }

        else {
            jmap_parser_invalid(&parser, key);
        }
    }

    if (!content) {
        jmap_parser_invalid(&parser, "content");
    }

    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s s:O}", "type", "invalidArguments",
                        "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    /* parse the script */
    char *errors = NULL;
    if (sieve_script_parse_string(NULL, content, &errors, NULL) == SIEVE_OK) {
        err = json_null();
    }
    else {
        err = json_pack("{s:s, s:s}", "type", "invalidScript",
                        "description", errors);
        free(errors);
    }

    /* Build response */
    json_t *res = json_pack("{s:o}", "error", err);
    jmap_ok(req, res);

done:
    jmap_parser_fini(&parser);
    buf_free(&buf);
    return 0;
}

typedef struct {
    struct message_content content;

    int cache_full;
    hdrcache_t cache;

    strarray_t *env_from;
    strarray_t *env_to;

    time_t last_vaca_resp;
    json_t *actions;
    json_t **err;
} message_data_t;

typedef struct {
    const char *userid;
    const struct auth_state *authstate;
    const struct namespace *ns;
    struct buf *buf;
} script_data_t;

static void free_msg(message_data_t *m)
{
    jmap_email_matchmime_free(&m->content.matchmime);
    spool_free_hdrcache(m->cache);
    buf_free(&m->content.map);
    if (m->content.body) {
        message_free_body(m->content.body);
        free(m->content.body);
    }
}

static void fill_cache(message_data_t *m)
{
    struct protstream *pin =
        prot_readmap(buf_base(&m->content.map), buf_len(&m->content.map));

    m->cache = spool_new_hdrcache();
    spool_fill_hdrcache(pin, NULL, m->cache, NULL);
    prot_free(pin);

    m->cache_full = 1;
}

static int getheader(void *v, const char *phead, const char ***body)
{
    message_data_t *m = (message_data_t *) v;

    *body = NULL;

    if (!m->cache_full) fill_cache(m);

    *body = spool_getheader(m->cache, phead);

    if (*body) {
        return SIEVE_OK;
    } else {
        return SIEVE_FAIL;
    }
}

static int getheadersection(void *mc __attribute__((unused)),
                            struct buf **contents)
{
    /* We don't currently do anything with the edited headers */
    *contents = NULL;

    return SIEVE_OK;
}

static int getenvelope(void *mc, const char *field, const char ***contents)
{
    message_data_t *m = (message_data_t *) mc;

    *contents = NULL;

    if (!strcasecmp(field, "from")) {
        if (strarray_size(m->env_from)) {
            *contents = (const char **) m->env_from->data;
        }
        else if (getheader(mc, "sender", contents) != SIEVE_OK) {
            getheader(mc, "from", contents);
        }
    } else if (!strcasecmp(field, "to")) {
        *contents = (const char **) m->env_to->data;
    }

    if (*contents) {
        return SIEVE_OK;
    } else {
        return SIEVE_FAIL;
    }
}

static int getsize(void *mc, int *size)
{
    message_data_t *m = (message_data_t *) mc;

    *size = buf_len(&m->content.map);

    return SIEVE_OK;
}

static int parse_body(message_data_t *m)
{
    m->content.body = xzmalloc(sizeof(struct body));

    return message_parse_mapped(buf_base(&m->content.map), buf_len(&m->content.map),
                                m->content.body, NULL);
}

static int getbody(void *mc, const char **content_types, sieve_bodypart_t ***parts)
{
    message_data_t *m = (message_data_t *) mc;
    int r = 0;

    if (!m->content.body) {
        /* parse the message body if we haven't already */
        r = parse_body(m);
    }

    /* XXX currently struct bodypart as defined in message.h is the same as
       sieve_bodypart_t as defined in sieve_interface.h, so we can typecast */
    if (!r) message_fetch_part(&m->content, content_types,
                               (struct bodypart ***) parts);
    return (!r ? SIEVE_OK : SIEVE_FAIL);
}

static int getmailboxexists(void *sc, const char *extname)
{
    script_data_t *sd = (script_data_t *) sc;
    char *intname = mboxname_from_externalUTF8(extname, sd->ns, sd->userid);
    int r = mboxlist_lookup(intname, NULL, NULL);

    free(intname);
    return r ? 0 : 1; /* 0 => exists */
}

static int getmailboxidexists(void *sc, const char *extname)
{
    script_data_t *sd = (script_data_t *)sc;
    char *intname = mboxlist_find_uniqueid(extname, sd->userid, sd->authstate);
    int exists = 0;

    if (intname && !mboxname_isnondeliverymailbox(intname, 0)) {
        exists = 1;
    }

    free(intname);

    return exists;
}

static int getspecialuseexists(void *sc, const char *extname, strarray_t *uses)
{
    script_data_t *sd = (script_data_t *)sc;
    int i, r = 1;

    if (extname) {
        char *intname = mboxname_from_externalUTF8(extname, sd->ns, sd->userid);
        struct buf attrib = BUF_INITIALIZER;

        annotatemore_lookup(intname, "/specialuse", sd->userid, &attrib);

        /* \\Inbox is magical */
        if (mboxname_isusermailbox(intname, 1) &&
            mboxname_userownsmailbox(sd->userid, intname)) {
            if (buf_len(&attrib)) buf_putc(&attrib, ' ');
            buf_appendcstr(&attrib, "\\Inbox");
        }

        if (buf_len(&attrib)) {
            strarray_t *haystack = strarray_split(buf_cstring(&attrib), " ", 0);

            for (i = 0; i < strarray_size(uses); i++) {
                if (strarray_find_case(haystack, strarray_nth(uses, i), 0) < 0) {
                    r = 0;
                    break;
                }
            }
            strarray_free(haystack);
        }
        else r = 0;

        buf_free(&attrib);
        free(intname);
    }
    else {
        for (i = 0; i < strarray_size(uses); i++) {
            char *intname =
                mboxlist_find_specialuse(strarray_nth(uses, i), sd->userid);
            if (!intname) r = 0;
            free(intname);
            if (!r) break;
        }
    }

    return r;
}

static int getmetadata(void *sc, const char *extname,
                       const char *keyname, char **res)
{
    script_data_t *sd = (script_data_t *) sc;
    struct buf attrib = BUF_INITIALIZER;
    char *intname = !extname ? xstrdup("") :
        mboxname_from_externalUTF8(extname, sd->ns, sd->userid);
    int r;

    if (!strncmp(keyname, "/private/", 9)) {
        r = annotatemore_lookup(intname, keyname+8, sd->userid, &attrib);
    }
    else if (!strncmp(keyname, "/shared/", 8)) {
        r = annotatemore_lookup(intname, keyname+7, "", &attrib);
    }
    else {
        r = IMAP_MAILBOX_NONEXISTENT;
    }

    *res = (r || !attrib.len) ? NULL : buf_release(&attrib);
    free(intname);
    buf_free(&attrib);

    return r ? 0 : 1;
}

struct sieve_interp_ctx {
    struct conversations_state *cstate;
    struct carddav_db *carddavdb;
};

static int jmapquery(void *ic, void *sc, void *mc, const char *json)
{
    struct sieve_interp_ctx *ctx = (struct sieve_interp_ctx *) ic;
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *md = (message_data_t *) mc;
    const char *userid = sd->userid;
    json_error_t jerr;
    json_t *jfilter, *err = NULL;
    int matches = 0;

    /* Create filter from json */
    jfilter = json_loads(json, 0, &jerr);
    if (!jfilter) return 0;

    int r = 0;

    if (!md->content.body) {
        /* parse the message body if we haven't already */
        r = parse_body(md);
        if (r) {
            json_decref(jfilter);
            return 0;
        }
    }

    if (!md->content.matchmime)
        md->content.matchmime = jmap_email_matchmime_new(&md->content.map, &err);

    /* Run query */
    if (md->content.matchmime)
        matches = jmap_email_matchmime(md->content.matchmime,
                                       jfilter, ctx->cstate, userid,
                                       sd->authstate,
                                       sd->ns,
                                       time(NULL), &err);

    if (err) {
        char *errstr = json_dumps(err, JSON_COMPACT);
        fprintf(stderr, "sieve: jmapquery: %s\n", errstr);

        free(errstr);
    }

    json_decref(jfilter);

    return matches;
}

static json_t *_strlist(json_t *args, const char *name, strarray_t *sl)
{
    if (strarray_size(sl)) {
        int i, n = strarray_size(sl);
        json_t *ja = json_array();

        for (i = 0; i < n; i++) {
            json_array_append_new(ja, json_string(strarray_nth(sl, i)));
        }
        json_object_set_new(args, name, ja);
    }

    return args;
}

static int keep(void *ac,
                void *ic __attribute__((unused)),
                void *sc __attribute__((unused)),
                void *mc,
                const char **errmsg __attribute__((unused)))
{
    sieve_keep_context_t *kc = (sieve_keep_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;

    if (!m) {
        /* just doing destination mailbox resolution */
        kc->resolved_mailbox = xstrdup("INBOX");
        return SIEVE_OK;
    }

    json_t *args = _strlist(json_object(), "flags", kc->imapflags);

    json_array_append_new(m->actions, json_pack("[s o []]", "keep", args));

    return SIEVE_OK;
}

static json_t *_fileinto(json_t *args, sieve_fileinto_context_t *fc)
{
    if (fc->specialuse)
        json_object_set_new(args, "specialuse", json_string(fc->specialuse));
    if (fc->mailboxid)
        json_object_set_new(args, "mailboxid", json_string(fc->mailboxid));
    if (fc->do_create)
        json_object_set_new(args, "create", json_true());

    return _strlist(args, "flags", fc->imapflags);
}

static int fileinto(void *ac,
                    void *ic __attribute__((unused)),
                    void *sc __attribute__((unused)),
                    void *mc,
                    const char **errmsg __attribute__((unused)))
{
    sieve_fileinto_context_t *fc = (sieve_fileinto_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;

    if (!m) {
        /* just doing destination mailbox resolution */
        fc->resolved_mailbox = xstrdup(fc->mailbox);
        return SIEVE_OK;
    }

    json_t *args = _fileinto(json_object(), fc);

    json_array_append_new(m->actions,
                          json_pack("[s o [s]]", "fileinto", args, fc->mailbox));

    return SIEVE_OK;
}

static int discard(void *ac __attribute__((unused)),
                   void *ic __attribute__((unused)),
                   void *sc __attribute__((unused)),
                   void *mc,
                   const char **errmsg __attribute__((unused)))
{
    message_data_t *m = (message_data_t *) mc;

    json_array_append_new(m->actions, json_pack("[s {} []]", "discard"));

    return SIEVE_OK;
}

static int redirect(void *ac,
                    void *ic __attribute__((unused)),
                    void *sc __attribute__((unused)),
                    void *mc,
                    const char **errmsg __attribute__((unused)))
{
    sieve_redirect_context_t *rc = (sieve_redirect_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;

    json_t *args = json_object();

    if (rc->dsn_notify)
        json_object_set_new(args, "notify", json_string(rc->dsn_notify));
    if (rc->dsn_ret)
        json_object_set_new(args, "ret", json_string(rc->dsn_ret));

    json_array_append_new(m->actions,
                          json_pack("[s o [s]]", "redirect", args, rc->addr));

    return SIEVE_OK;
}

static int reject(void *ac,
                  void *ic __attribute__((unused)),
                  void *sc __attribute__((unused)),
                  void *mc,
                  const char **errmsg __attribute__((unused)))
{
    sieve_reject_context_t *rc = (sieve_reject_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;

    json_array_append_new(m->actions,
                          json_pack("[s {} [s]]",
                                    rc->is_extended ? "ereject" : "reject",
                                    rc->msg));

    return SIEVE_OK;
}

static int autorespond(void *ac,
                       void *ic __attribute__((unused)),
                       void *sc __attribute__((unused)),
                       void *mc,
                       const char **errmsg __attribute__((unused)))
{
    sieve_autorespond_context_t *arc = (sieve_autorespond_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;

    if (m->last_vaca_resp &&
        time(0) < m->last_vaca_resp + arc->seconds) return SIEVE_DONE;

    return SIEVE_OK;
}

static int send_response(void *ac,
                         void *ic __attribute__((unused)),
                         void *sc __attribute__((unused)),
                         void *mc,
                         const char **errmsg __attribute__((unused)))

{
    sieve_send_response_context_t *src = (sieve_send_response_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;

    json_t *args = json_object();

    if (src->fcc.mailbox) {
        json_object_set_new(args, "fcc", json_string(src->fcc.mailbox));

        _fileinto(args, &src->fcc);
    }
    if (src->subj)
        json_object_set_new(args, "subject", json_string(src->subj));
    if (src->fromaddr)
        json_object_set_new(args, "from", json_string(src->fromaddr));
    if (src->mime)
        json_object_set_new(args, "mime", json_true());

    json_array_append_new(m->actions,
                          json_pack("[s o [s]]", "vacation", args, src->msg));

    return SIEVE_OK;
}

static sieve_vacation_t vacation = {
    1 * DAY2SEC,                /* min response */
    31 * DAY2SEC,               /* max response */
    &autorespond,               /* autorespond() */
    &send_response              /* send_response() */
};

static int addheader(void *mc, const char *head, const char *body, int index)
{
    message_data_t *m = (message_data_t *) mc;

    if (head == NULL || body == NULL) return SIEVE_FAIL;

    if (!m->cache_full) fill_cache(m);

    json_t *args = json_object();

    if (index < 0) {
        spool_append_header(xstrdup(head), xstrdup(body), m->cache);

        json_object_set_new(args, "last", json_true());
    }
    else {
        spool_prepend_header(xstrdup(head), xstrdup(body), m->cache);
    }

    json_array_append_new(m->actions,
                          json_pack("[s o [s s]]", "addheader", args, head, body));

    return SIEVE_OK;
}

static int deleteheader(void *mc, const char *head, int index)
{
    message_data_t *m = (message_data_t *) mc;

    if (head == NULL) return SIEVE_FAIL;

    if (!m->cache_full) fill_cache(m);

    json_t *args = json_object();

    if (index) {
        spool_remove_header_instance(xstrdup(head), index, m->cache);

        json_object_set_new(args, "index", json_integer(abs(index)));
        if (index < 0)
            json_object_set_new(args, "last", json_true());
    }
    else {
        spool_remove_header(xstrdup(head), m->cache);
    }

    json_array_append_new(m->actions,
                          json_pack("[s o]", "deleteheader", args, head));

    return SIEVE_OK;
}

static int notify(void *ac,
                  void *ic __attribute__((unused)),
                  void *sc __attribute__((unused)),
                  void *mc,
                  const char **errmsg __attribute__((unused)))
{
    sieve_notify_context_t *nc = (sieve_notify_context_t *) ac;
    message_data_t *m = (message_data_t *) mc;

    json_t *args = _strlist(json_object(), "options", nc->options);

    if (nc->from)
        json_object_set_new(args, "from", json_string(nc->from));

    if (nc->priority)
        json_object_set_new(args, "importance", json_string(nc->priority));

    if (nc->message)
        json_object_set_new(args, "message", json_string(nc->message));

    json_t *method = json_array();

    if (nc->method)
      json_array_append_new(method, json_string(nc->method));

    json_array_append_new(m->actions,
                          json_pack("[s o o]", "notify", args, method));

    return SIEVE_OK;
}

static int snooze(void *ac,
                  void *ic __attribute__((unused)),
                  void *sc, void *mc,
                  const char **errmsg __attribute__((unused)))
{
    sieve_snooze_context_t *sn = (sieve_snooze_context_t *) ac;
    script_data_t *sd = (script_data_t *) sc;
    message_data_t *m = (message_data_t *) mc;
    int i;

    json_t *args = json_object();

    if (sn->awaken_spluse)
        json_object_set_new(args, "specialuse", json_string(sn->awaken_spluse));
    if (sn->awaken_mboxid)
        json_object_set_new(args, "mailboxid", json_string(sn->awaken_mboxid));
    if (sn->do_create)
        json_object_set_new(args, "create", json_true());
    if (sn->awaken_mbox)
        json_object_set_new(args, "mailbox", json_string(sn->awaken_mbox));

    _strlist(args, "flags", sn->imapflags);
    _strlist(args, "addflags", sn->addflags);
    _strlist(args, "removeflags", sn->removeflags);

    if (sn->tzid) json_object_set_new(args, "tzid", json_string(sn->tzid));

    if (sn->days && (sn->days & SNOOZE_WDAYS_MASK) != SNOOZE_WDAYS_MASK) {
        json_t *jdays = json_array();

        for (i = 0; i < 7; i++) {
            if (sn->days & (1 << i)) {
                buf_reset(sd->buf);
                buf_printf(sd->buf, "%u", i);
                json_array_append_new(jdays, json_string(buf_cstring(sd->buf)));
            }
        }
        json_object_set_new(args, "weekdays", jdays);
    }
    
    int n = arrayu64_size(sn->times);
    json_t *jtimes = json_array();

    for (i = 0; i < n; i++) {
        uint64_t t = arrayu64_nth(sn->times, i);

        buf_reset(sd->buf);
        buf_printf(sd->buf, "%02lu:%02lu:%02lu",
                   t / 3600, (t % 3600) / 60, t % 60);
        json_array_append_new(jtimes, json_string(buf_cstring(sd->buf)));
    }

    json_array_append_new(m->actions,
                          json_pack("[s o [o]]", "snooze", args, jtimes));

    return SIEVE_OK;
}

static void sieve_log(void *sc __attribute__((unused)),
                      void *mc, const char *text)
{
    message_data_t *m = (message_data_t *) mc;

    json_array_append_new(m->actions, json_pack("[s {} [s]]", "log", text));
}

static int getinclude(void *sc __attribute__((unused)),
                      const char *script,
                      int isglobal __attribute__((unused)),
                      char *fpath, size_t size)
{
    strlcpy(fpath, script, size);
    strlcat(fpath, BYTECODE_SUFFIX, size);

    return SIEVE_OK;
}

static int execute_error(const char *msg,
                         void *ic __attribute__((unused)),
                         void *sc __attribute__((unused)),
                         void *mc)
{
    message_data_t *m = (message_data_t *) mc;

    *m->err = json_pack("{s:s s:s}", "type", "serverFail", "description", msg);

    return SIEVE_OK;
}

static const char *_envelope_address_parse(json_t *addr,
                                           struct jmap_parser *parser)
{
    const char *email = NULL;

    json_t *jemail = json_object_get(addr, "email");
    if (jemail && json_string_value(jemail)) {
        struct address *a = NULL;
        parseaddr_list(json_string_value(jemail), &a);
        if (a && !a->invalid && a->mailbox && a->domain && !a->next) {
            email = json_string_value(jemail);
        }
        parseaddr_free(a);
    }
    else {
        jmap_parser_invalid(parser, "email");
    }

    return email;
}

static int jmap_sieve_test(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    const char *key, *scriptid = NULL;
    const char *bcname = NULL, *tmpname = NULL;
    json_t *arg, *emailids = NULL, *envelope = NULL, *err = NULL;
    strarray_t env_from = STRARRAY_INITIALIZER;
    strarray_t env_to = STRARRAY_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    struct sieve_interp_ctx interp_ctx = { NULL, NULL };
    sieve_interp_t *interp = NULL;
    sieve_execute_t *exe = NULL;
    time_t last_vaca_resp = 0;
    int r;

    /* Parse request */
    json_object_foreach(req->args, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        else if (!strcmp(key, "scriptBlobId")) {
            scriptid = json_string_value(arg);
        }

        else if (!strcmp(key, "emailBlobIds")) {
            emailids = arg;
        }

        else if (!strcmp(key, "envelope")) {
            envelope = arg;
        }

        else if (!strcmp(key, "lastVacationResponse")) {
            if (json_is_utcdate(arg)) {
                time_from_iso8601(json_string_value(arg), &last_vaca_resp);
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(&parser, key);
            }
        }

        else {
            jmap_parser_invalid(&parser, key);
        }
    }

    if (!scriptid) {
        jmap_parser_invalid(&parser, "scriptBlobId");
    }

    if (!emailids) {
        jmap_parser_invalid(&parser, "emailBlobIds");
    }

    /* envelope */
    if (JNOTNULL(envelope)) {
        const char *email;

        jmap_parser_push(&parser, "envelope");
        json_t *from = json_object_get(envelope, "mailFrom");
        if (json_object_size(from)) {
            jmap_parser_push(&parser, "mailFrom");
            email = _envelope_address_parse(from, &parser);
            jmap_parser_pop(&parser);
            if (email) strarray_append(&env_from, email);
        }
        else {
            jmap_parser_invalid(&parser, "mailFrom");
        }
        json_t *rcpt = json_object_get(envelope, "rcptTo");
        if (json_array_size(rcpt)) {
            size_t i;
            json_t *addr;
            json_array_foreach(rcpt, i, addr) {
                jmap_parser_push_index(&parser, "rcptTo", i, NULL);
                email = _envelope_address_parse(addr, &parser);
                jmap_parser_pop(&parser);
                if (email) strarray_append(&env_to, email);
            }
        }
        else {
            jmap_parser_invalid(&parser, "rcptTo");
        }
        jmap_parser_pop(&parser);
    } else {
        envelope = NULL;
    }

    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s s:O}", "type", "invalidArguments",
                        "arguments", parser.invalid);
        goto done;
    }

    if (scriptid[0] == 'S') {
        const char *sievedir = user_sieve_path(req->accountid);
        struct sieve_data *sdata = NULL;

        struct sieve_db *db = sievedb_open_userid(req->accountid);
        if (!db) {
            err = jmap_server_error(IMAP_INTERNAL);
            goto done;
        }

        r = sievedb_lookup_id(db, scriptid+1, &sdata, 0);
        if (r || !sdata->imap_uid) {
            err = json_pack("{s:s}", "type", "notFound");
        }
        else {
            /* Use pre-compiled bytecode file */
            buf_printf(&buf, "%s/%s%s", sievedir, sdata->name, BYTECODE_SUFFIX);
            bcname = buf_cstring(&buf);
        }

        sievedb_close(db);
    }

    if (!bcname) {
        const char *content = script_findblob(req, scriptid, &buf, &err);
        if (err) goto done;

        /* Generate temporary bytecode file */
        static char template[] = "/tmp/sieve-test-bytecode-XXXXXX";
        sieve_script_t *s = NULL;
        bytecode_info_t *bc = NULL;
        char *errors = NULL;
        int fd = -1;

        r = sieve_script_parse_string(NULL, content, &errors, &s);
        msgrecord_unref(&mr);
        jmap_closembox(req, &mbox);

        if (r != SIEVE_OK) {
            err = json_pack("{s:s, s:s}", "type", "invalidScript",
                            "description", errors);
            free(errors);
        }
        else if (sieve_generate_bytecode(&bc, s) == -1) {
            err = json_pack("{s:s s:s}", "type", "serverFail",
                            "description", "unable to generate bytecode");
        }
        else if ((fd = mkstemp(template)) < 0) {
            err = json_pack("{s:s s:s}", "type", "serverFail",
                            "description", "unable to open temporary file");
        }
        else if (sieve_emit_bytecode(fd, bc) == -1) {
            err = json_pack("{s:s s:s}", "type", "serverFail",
                            "description", "unable to emit bytecode");
        }

        sieve_free_bytecode(&bc);
        sieve_script_free(&s);
        close(fd);

        bcname = tmpname = template;
    }

    if (err) goto done;

    /* load the script */
    r = sieve_script_load(bcname, &exe);
    if (r != SIEVE_OK) {
        err = json_pack("{s:s s:s}", "type", "serverFail",
                        "description", "unable to load bytecode");
        goto done;
    }

    /* create interpreter */
    interp = sieve_interp_alloc(&interp_ctx);
    sieve_register_header(interp, getheader);
    sieve_register_headersection(interp, getheadersection);
    sieve_register_envelope(interp, getenvelope);
    sieve_register_size(interp, getsize);
    sieve_register_body(interp, getbody);
    sieve_register_mailboxexists(interp, &getmailboxexists);
    sieve_register_mailboxidexists(interp, &getmailboxidexists);
    sieve_register_specialuseexists(interp, &getspecialuseexists);
    sieve_register_metadata(interp, &getmetadata);
    sieve_register_jmapquery(interp, &jmapquery);

    sieve_register_keep(interp, keep);
    sieve_register_fileinto(interp, fileinto);
    sieve_register_discard(interp, discard);
    sieve_register_redirect(interp, redirect);
    sieve_register_reject(interp, reject);
    sieve_register_vacation(interp, &vacation);  /* after getenvelope */
    sieve_register_addheader(interp, addheader); /* after getheadersection */
    sieve_register_deleteheader(interp, deleteheader);  /* after gethdrsec */
    sieve_register_notify(interp, notify, NULL);
    sieve_register_snooze(interp, snooze);
    sieve_register_logger(interp, sieve_log);
        
    sieve_register_include(interp, getinclude);
    sieve_register_execute_error(interp, execute_error);

    /* test against each email */
    size_t i;
    json_t *completed = json_object(), *not_completed = json_object();
    json_array_foreach(emailids, i, arg) {
        const char *emailid = json_string_value(arg);

        if (emailid[0] == '#') {
            emailid = jmap_lookup_id(req, emailid + 1);
        }

        /* load the email */
        message_data_t m = { { BUF_INITIALIZER, NULL, NULL},
            0, NULL, &env_from, &env_to, last_vaca_resp, NULL, &err };

        r = jmap_findblob(req, NULL/*accountid*/, emailid,
                          &mbox, &mr, NULL, NULL, &m.content.map);
        if (r) {
            if (r == IMAP_NOTFOUND)
                err = json_pack("{s:s}", "type", "blobNotFound");
            else
                err = jmap_server_error(r);

            json_object_set_new(not_completed, emailid, err);
        }
        else {
            if (!envelope) {
                buf_setcstr(&buf, req->userid);
                if (!strchr(req->userid, '@')) {
                    buf_printf(&buf, "@%s", config_servername);
                }
                strarray_append(&env_to, buf_cstring(&buf));
            }

            /* execute the script */
            script_data_t sd =
                { req->accountid, req->authstate, &jmap_namespace, &buf };

            err = NULL;
            m.actions = json_array();
            sieve_execute_bytecode(exe, interp, &sd, &m);

            if (err) {
                json_object_set_new(not_completed, emailid, err);
                json_decref(m.actions);
            }
            else {
                json_object_set_new(completed, emailid, m.actions);
            }

            free_msg(&m);
            msgrecord_unref(&mr);
            jmap_closembox(req, &mbox);
            if (!envelope) {
                strarray_fini(&env_from);
                strarray_fini(&env_to);
            }
        }
    }

    if (interp_ctx.cstate) conversations_commit(&interp_ctx.cstate);
    if (interp_ctx.carddavdb) carddav_close(interp_ctx.carddavdb);

    /* Build response */
    if (!json_object_size(completed)) {
        json_decref(completed);
        completed = json_null();
    }
    if (!json_object_size(not_completed)) {
        json_decref(not_completed);
        not_completed = json_null();
    }

    jmap_ok(req, json_pack("{s:s s:o s:o}",
                           "accountId", req->accountid,
                           "completed", completed,
                           "notCompleted", not_completed));

done:
    if (err) jmap_error(req, err);
    jmap_parser_fini(&parser);
    sieve_script_unload(&exe);
    sieve_interp_free(&interp);
    strarray_fini(&env_from);
    strarray_fini(&env_to);
    buf_free(&buf);
    if (tmpname) {
        /* Remove temp bytecode file */
        unlink(tmpname);
    }
    return 0;
}
