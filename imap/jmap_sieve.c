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
#include <errno.h>

#include "arrayu64.h"
#include "cyr_qsort_r.h"
#include "hash.h"
#include "http_jmap.h"
#include "jmap_mail.h"
#include "jmap_mail_query.h"
#include "json_support.h"
#include "map.h"
#include "parseaddr.h"
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

static int jmap_sieve_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx);

static int maxscripts = 0;
static json_int_t maxscriptsize = 0;

jmap_method_t jmap_sieve_methods_standard[] = {
    { NULL, NULL, NULL, 0}
};

jmap_method_t jmap_sieve_methods_nonstandard[] = {
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

    ptrarray_append(&settings->getblob_handlers, jmap_sieve_getblob);

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

#define SCRIPT_ID_PREFIX       ".JMAPID:"
#define SCRIPT_ID_PREFIX_LEN   8

#define SCRIPT_NAME_ONLY (1<<0)

static const char *script_from_id(const char *sievedir, const char *id,
                                  unsigned flags)
{
    static char target[PATH_MAX];
    char link[PATH_MAX];
    struct stat sbuf;
    char *name = NULL;

    snprintf(link, sizeof(link), "%s/%s%s", sievedir, SCRIPT_ID_PREFIX, id);

    if (!stat(link, &sbuf)) {
        ssize_t tgt_len = readlink(link, target, sizeof(target) - 1);

        target[tgt_len] = '\0';

        if (tgt_len > SCRIPT_SUFFIX_LEN &&
            !strcmp(target + (tgt_len - SCRIPT_SUFFIX_LEN), SCRIPT_SUFFIX)) {
            if (flags & SCRIPT_NAME_ONLY)
                target[tgt_len - SCRIPT_SUFFIX_LEN] = '\0';
            name = target;
        }
    }
    else if (!lstat(link, &sbuf)) {
        /* Dead link - remove it
           (script was probably deleted via ManageSieve) */
        unlink(link);
    }

    return name;
}

static int create_id_link(const char *sievedir, const char *id, const char *name)
{
    /* create script id link */
    char link[PATH_MAX];
    int r;

    snprintf(link, sizeof(link), "%s/%s%s", sievedir, SCRIPT_ID_PREFIX, id);

    r = unlink(link);
    if (r) {
        if (errno == ENOENT) r = 0;
        else syslog(LOG_ERR, "IOERROR: unlink(%s): %m", link);
    }

    if (!r) {
        char target[PATH_MAX];
        size_t namelen = strlen(name);

        if (namelen <= SCRIPT_SUFFIX_LEN ||
            strcmp(name + (namelen - SCRIPT_SUFFIX_LEN), SCRIPT_SUFFIX)) {
            snprintf(target, sizeof(target), "%s%s", name, SCRIPT_SUFFIX);
            name = target;
        }

        r = symlink(name, link);
        if (r) syslog(LOG_ERR, "IOERROR: symlink(%s, %s): %m", name, link);
    }

    return r;
}

static void getscript(const char *id, const char *script, int isactive,
                      const char *sievedir, struct jmap_get *get)
{
    if (!script) script = script_from_id(sievedir, id, 0);

    if (script) {
        json_t *sieve = json_pack("{s:s}", "id", id);
        struct buf buf = BUF_INITIALIZER;

        if (jmap_wantprop(get->props, "name")) {
            buf_setmap(&buf, script, strlen(script) - SCRIPT_SUFFIX_LEN);
            json_object_set_new(sieve, "name", json_string(buf_cstring(&buf)));
        }

        if (jmap_wantprop(get->props, "isActive")) {
            if (isactive < 0) {
                if (!buf_len(&buf))
                    buf_setmap(&buf, script, strlen(script) - SCRIPT_SUFFIX_LEN);
                isactive = sievedir_script_isactive(sievedir, buf_cstring(&buf));
            }

            json_object_set_new(sieve, "isActive", json_boolean(isactive));
        }

        if (jmap_wantprop(get->props, "blobId")) {
            buf_reset(&buf);
            buf_printf(&buf, "S%s", id);
            json_object_set_new(sieve, "blobId", json_string(buf_cstring(&buf)));
        }

        buf_free(&buf);

        /* Add object to list */
        json_array_append_new(get->list, sieve);
    }
    else {
        json_array_append_new(get->not_found, json_string(id));
    }
}

typedef struct script_info {
    char *id;
    char *name;
    int isActive;
} script_info;

static void free_script_info(void *data)
{
    script_info *info = (script_info *) data;

    if (!info) return;

    free(info->id);
    free(info->name);
    free(info);
}

struct list_rock {
    const char *sievedir;
    struct jmap_get *get;
};

static void get_cb(const char *script, void *data, void *rock)
{
    script_info *info = (script_info *) data;
    const char *id = info->id;
    struct list_rock *lrock = (struct list_rock *) rock;

    if (!id) {
        /* Create script id symlink */
        id = makeuuid();
        create_id_link(lrock->sievedir, id, script);
    }

    getscript(id, script, info->isActive, lrock->sievedir, lrock->get);
}

static int list_cb(const char *sievedir __attribute__((unused)),
                   const char *name, struct stat *sbuf,
                   const char *link_target, void *rock)
{
    hash_table *scripts = (hash_table *) rock;
    size_t namelen = strlen(name);
    script_info *info = NULL;

    if (S_ISLNK(sbuf->st_mode)) {
        if (namelen > SCRIPT_ID_PREFIX_LEN &&
            !strncmp(name, SCRIPT_ID_PREFIX, SCRIPT_ID_PREFIX_LEN)) {
            /* Script id symlink */
            const char *id = name + SCRIPT_ID_PREFIX_LEN;

            if (link_target && *link_target) {
                /* Map script name -> id */
                info = hash_lookup(link_target, scripts);
                if (!info) {
                    info = xzmalloc(sizeof(struct script_info));
                    hash_insert(link_target, info, scripts);
                }
                info->id = xstrdup(id);
            }
            else {
                /* Dead link - remove it
                   (script was probably deleted via ManageSieve) */
                char link[PATH_MAX];

                snprintf(link, sizeof(link), "%s/%s", sievedir, name);
                unlink(link);
            }
        }
        else if (!strcmp(name, DEFAULTBC_NAME) && link_target && *link_target) {
            /* Active bytecode - check if we have an entry for this name */
            char active[PATH_MAX];

            snprintf(active, sizeof(active), "%.*s%s",
                     (int) strlen(link_target) - BYTECODE_SUFFIX_LEN,
                     link_target, SCRIPT_SUFFIX);

            info = hash_lookup(active, scripts);
            if (!info) {
                /* Add script name -> NULL as a placeholder */
                info = xzmalloc(sizeof(struct script_info));
                hash_insert(active, info, scripts);
            }
            info->isActive = 1;
        }
    }
    else if (namelen > SCRIPT_SUFFIX_LEN &&
             !strcmp(name + (namelen - SCRIPT_SUFFIX_LEN), SCRIPT_SUFFIX)) {
        /* Actual script file - check if we have an entry for this name */
        info = hash_lookup(name, scripts);
        if (!info) {
            /* Add script name -> NULL as a placeholder
               (we will create an id symlink later, if necessary) */
            info = xzmalloc(sizeof(struct script_info));
            hash_insert(name, info, scripts);
        }
    }

    return SIEVEDIR_OK;
}

static void _listscripts(const char *sievedir, hash_table *scripts)
{
    /* Build a hash of script name -> script id */
    construct_hash_table(scripts, maxscripts, 0);

    sievedir_foreach(sievedir, SIEVEDIR_IGNORE_JUNK, &list_cb, scripts);
}

static void listscripts(const char *sievedir, struct jmap_get *get)
{
    hash_table scripts = HASH_TABLE_INITIALIZER;
    struct list_rock lrock = { sievedir, get };

    /* Build a list of scripts */
    _listscripts(sievedir, &scripts);

    /* Perform a get on each script */
    hash_enumerate(&scripts, &get_cb, &lrock);
    free_hash_table(&scripts, &free_script_info);
}

static char *sieve_state(const char *sievedir)
{
    struct buf buf = BUF_INITIALIZER;
    struct stat sbuf;
    int r;

    r = stat(sievedir, &sbuf);
    if (r && errno == ENOENT) {
        r = cyrus_mkdir(sievedir, 0755);
        if (!r) {
            r = mkdir(sievedir, 0755);
            if (!r) r = stat(sievedir, &sbuf);
        }
    }

    if (r) buf_setcstr(&buf, "0");
    else {
        buf_printf(&buf, "%ld.%ld-%ld",
                   sbuf.st_mtim.tv_sec, sbuf.st_mtim.tv_nsec, sbuf.st_size);
    }

    return buf_release(&buf);
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

static int jmap_sieve_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;

    /* Parse request */
    jmap_get_parse(req, &parser, sieve_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    const char *sievedir = user_sieve_path(req->accountid);

    /* Does the client request specific responses? */
    if (JNOTNULL(get.ids)) {
        json_t *jval;
        size_t i;

        json_array_foreach(get.ids, i, jval) {
            getscript(json_string_value(jval), NULL, -1, sievedir, &get);
        }
    }
    else {
        listscripts(sievedir, &get);
    }

    /* Build response */
    get.state = sieve_state(sievedir);
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);

    return 0;
}

static int putscript(const char *name, const char *content,
                     const char *sievedir, json_t **err)
{
    /* check script size */
    if ((json_int_t) strlen(content) > maxscriptsize) {
        *err = json_pack("{s:s}", "type", "tooLarge");
        return 0;
    }

    char *errors = NULL;
    int r = sievedir_put_script(sievedir, name, content, &errors);

    switch (r) {
    case SIEVEDIR_INVALID:
        *err = json_pack("{s:s, s:s}", "type", "invalidScript",
                         "description", errors);
        free(errors);
        break;
    case SIEVEDIR_FAIL:
        *err = json_pack("{s:s, s:s}", "type", "serverFail",
                         "description", "bytecode generation failed");
        break;
    case SIEVEDIR_IOERROR:
        *err = json_pack("{s:s, s:s}", "type", "serverFail",
                         "description", strerror(errno));
        break;
    }

    return r;
}

static int script_setactive(const char *id, const char *sievedir)
{
    int r;

    if (id) {
        const char *script = script_from_id(sievedir, id, SCRIPT_NAME_ONLY);
        r = sievedir_activate_script(sievedir, script);
    }
    else {
        r = sievedir_deactivate_script(sievedir);
    }

    return r;
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
                              const char *sievedir, struct jmap_set *set)
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
        name = json_string_value(arg);
        buf_init_ro_cstr(&buf, name);
        if (!sievedir_valid_name(&buf)) {
            json_array_append_new(invalid, json_string("name"));
        }
        else if (sievedir_script_exists(sievedir, name)) {
            err = json_pack("{s:s}", "type", "alreadyExists");
            goto done;
        }
        else if (!strcmp(name, "jmap_vacation")) {
            json_array_append_new(invalid, json_string("name"));
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

    r = putscript(name, content, sievedir, &err);
    if (err) goto done;

    if (!r) {
        /* create script id link */
        r = create_id_link(sievedir, id, name);
        if (!r) {
            /* Report script as created, with server-set properties */
            buf_reset(&buf);
            buf_printf(&buf, "S%s", id);

            json_t *new_sieve = json_pack("{s:s s:b s:s}",
                                          "id", id, "isActive", 0,
                                          "blobId", buf_cstring(&buf));

            if (name == id) {
                json_object_set_new(new_sieve, "name", json_string(name));
            }

            json_object_set_new(set->created, creation_id, new_sieve);
        }
    }

    if (r) {
        err = json_pack("{s:s, s:s}", "type", "serverFail",
                        "description", strerror(errno));
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
                       const char *sievedir, struct jmap_set *set)
{
    json_t *arg, *invalid = json_array(), *err = NULL;
    const char *script, *name = NULL, *content = NULL;
    struct buf buf = BUF_INITIALIZER;
    char *cur_name = NULL;
    int r = 0, is_active;

    if (!id) return;

    script = script_from_id(sievedir, id, SCRIPT_NAME_ONLY);
    if (!script) {
        err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }
    else if (!strcmp(script, "jmap_vacation")) {
        err = json_pack("{s:s s:s}", "type", "forbidden",
                        "description", "MUST use VacationResponse/set method");
        goto done;
    }

    cur_name = xstrdup(script);
    is_active = sievedir_script_isactive(sievedir, cur_name);

    arg = json_object_get(jsieve, "name");
    if (arg) {
        if (json_is_string(arg))
            name = json_string_value(arg);
        else if (json_is_null(arg))
            name = id;
        else
            json_array_append_new(invalid, json_string("name"));

        if (name) {
            /* sanity check script name and check for name collision */
            struct buf buf = BUF_INITIALIZER;

            buf_init_ro_cstr(&buf, name);
            if (!sievedir_valid_name(&buf)) {
                json_array_append_new(invalid, json_string("name"));
            }
            else if (strcmp(name, cur_name) &&
                     sievedir_script_exists(sievedir, name)) {
                err = json_pack("{s:s}", "type", "alreadyExists");
                goto done;
            }
        }
    }

    arg = json_object_get(jsieve, "isActive");
    if (arg) {
        if (!json_is_boolean(arg))
            json_array_append_new(invalid, json_string("isActive"));
        else if (json_boolean_value(arg) != is_active) {
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

    if (content) {
        r = putscript(cur_name, content, sievedir, &err);
        if (err) goto done;
    }
    if (!r && name && strcmp(name, cur_name)) {
        /* rename script and bytecode; move script id link; move active link */
        r = sievedir_rename_script(sievedir, cur_name, name);
        if (!r) {
            r = create_id_link(sievedir, id, name);
        }
    }
    if (!r) {
        /* Report script as updated */
        json_object_set_new(set->updated, id, json_null());
    }
    else {
        err = json_pack("{s:s, s:s}", "type", "serverFail",
                        "description", strerror(errno));
    }

  done:
    if (err) {
        json_object_set_new(set->not_updated, id, err);
    }
    json_decref(invalid);
    free(cur_name);
    buf_free(&buf);
}

static void set_destroy(const char *id,
                        const char *sievedir, struct jmap_set *set)
{
    const char *script = script_from_id(sievedir, id, SCRIPT_NAME_ONLY);
    json_t *err = NULL;

    if (!script) {
        err = json_pack("{s:s}", "type", "notFound");
    }
    else if (sievedir_script_isactive(sievedir, script)) {
        err = json_pack("{s:s}", "type", "scriptIsActive");
    }
    else if (!strcmp(script, "jmap_vacation")) {
        err = json_pack("{s:s s:s}", "type", "forbidden",
                        "description", "MUST use VacationResponse/set method");
    }
    else {
        char path[PATH_MAX];
        int r;

        snprintf(path, sizeof(path), "%s/%s%s", sievedir, SCRIPT_ID_PREFIX, id);
        r = unlink(path);
        if (r) {
            syslog(LOG_ERR, "IOERROR: unlink(%s): %m", path);
        }
        else {
            r = sievedir_delete_script(sievedir, script);
        }
        if (r) {
            err = json_pack("{s:s, s:s}", "type", "serverFail",
                            "description", strerror(errno));
        }
    }

    if (err) {
        json_object_set_new(set->not_destroyed, id, err);
    }
    else {
        json_array_append_new(set->destroyed, json_string(id));
    }
}

static int find_cb(const char *sievedir __attribute__((unused)),
                   const char *name, struct stat *sbuf,
                   const char *link_target, void *rock)
{
    script_info *info = (script_info *) rock;

    if (S_ISLNK(sbuf->st_mode) &&
        !strncmp(name, SCRIPT_ID_PREFIX, SCRIPT_ID_PREFIX_LEN)) {
        size_t tgt_len = strlen(link_target) - SCRIPT_SUFFIX_LEN;

        if (strlen(info->name) == tgt_len &&
            !strncmp(info->name, link_target, tgt_len)) {
            info->id = xstrdup(name + SCRIPT_ID_PREFIX_LEN);
            return SIEVEDIR_DONE;
        }
    }

    return SIEVEDIR_OK;
}

static void set_activate(const char *id, const char *sievedir,
                         struct jmap_set *set)
{
    const char *active;
    char *old_id = NULL;
    json_t *created = NULL;
    int r;

    /* Lookup currently active script */
    active = sievedir_get_active(sievedir);
    if (active) {
        /* get it's id */
        script_info info = { NULL, (char *) active, 1 };

        sievedir_foreach(sievedir, SIEVEDIR_IGNORE_JUNK, &find_cb, &info);
        old_id = info.id;
    }

    if (id) {
        if (id[0] == '#') {
            /* Resolve creation id */
            created = json_object_get(set->created, id+1);
            id = json_string_value(json_object_get(created, "id"));
        }
        if (id && json_array_find(set->destroyed, id) >= 0) {
            /* Don't try to activate a destroyed script */
            id = NULL;
        }
    }

    r = script_setactive(id, sievedir);
    if (r) {
        /* XXX  How do we report a failure here? */
        return;
    }

    if (old_id) {
        /* Report previous active script as updated */
        json_object_set_new(set->updated, old_id,
                            json_pack("{s:b}", "isActive", 0));
        free(old_id);
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

    const char *sievedir = user_sieve_path(req->accountid);

    /* Parse arguments */
    jmap_set_parse(req, &parser, sieve_props,
                   &_sieve_setargs_parse, &sub_args, &set, &jerr);

    /* Validate scriptId in onSuccessActivateScript */
    if (!jerr && JNOTNULL(sub_args.onSuccessActivate)) {
        const char *id = json_string_value(sub_args.onSuccessActivate);
        int found;

        jmap_parser_push(&parser, "onSuccessActivateScript");

        if (*id == '#') {
            found = json_object_get(set.create, id+1) != NULL;
        }
        else if ((found = json_array_find(set.destroy, id) < 0)) {
            found = script_from_id(sievedir, id, 0) != NULL;
        }

        if (!found) {
            jmap_parser_invalid(&parser, id);
            jerr = json_pack("{s:s s:O}", "type", "invalidArguments",
                             "arguments", parser.invalid);
        }

        jmap_parser_pop(&parser);
    }

    if (jerr) {
        jmap_error(req, jerr);
        goto done;
    }

    set.old_state = sieve_state(sievedir);

    if (set.if_in_state && strcmp(set.if_in_state, set.old_state)) {
        jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
        goto done;
    }


    /* create */
    const char *creation_id, *script_id;
    json_t *val;
    if (json_object_size(set.create)) {
        /* Count existing scripts */
        int num_scripts = sievedir_num_scripts(sievedir, NULL);

        json_object_foreach(set.create, creation_id, val) {
            if (num_scripts >= maxscripts) {
                json_object_set_new(set.not_created, creation_id,
                                    json_pack("{s:s}", "type", "overQuota"));
                continue;
            }

            script_id = set_create(req, creation_id, val, sievedir, &set);
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

        set_update(req, script_id, val, sievedir, &set);
    }


    /* destroy */
    size_t i;
    json_array_foreach(set.destroy, i, val) {
        id = json_string_value(val);
        script_id = (id && id[0] == '#') ? jmap_lookup_id(req, id + 1) : id;
        if (!script_id) continue;

        set_destroy(script_id, sievedir, &set);
    }

    if (sub_args.onSuccessActivate &&
        !json_object_size(set.not_created) &&
        !json_object_size(set.not_updated) &&
        !json_array_size(set.not_destroyed)) {

        id = json_string_value(sub_args.onSuccessActivate);
        set_activate(id, sievedir, &set);
    }

    if (json_object_size(set.created) || json_object_size(set.updated) ||
        json_array_size(set.destroyed)) {
        sync_log_sieve(req->accountid);
    }

    /* Build response */
    set.new_state = sieve_state(sievedir);
    jmap_ok(req, jmap_set_reply(&set));

done:
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
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
    int isActive;
} filter;

static void *filter_build(json_t *arg)
{
    filter *f = (filter *) xzmalloc(sizeof(struct filter));

    f->isActive = -1;

    /* name */
    if (JNOTNULL(json_object_get(arg, "name"))) {
        jmap_readprop(arg, "name", 0, NULL, "s", &f->name);
    }

    /* isActive */
    if (JNOTNULL(json_object_get(arg, "isActive"))) {
        jmap_readprop(arg, "isActive", 0, NULL, "b", &f->isActive);
    }

    return f;
}

/* Match the script in rock against filter. */
static int filter_match(void *vf, void *rock)
{
    filter *f = (filter *) vf;
    script_info *info = (script_info *) rock;

    /* name */
    if (f->name && !strstr(info->name, f->name)) return 0;

    /* isActive */
    if (f->isActive != -1 && (info->isActive != f->isActive)) return 0;

    /* All matched. */
    return 1;
}

typedef struct filter_rock {
    const char *sievedir;
    struct jmap_query *query;
    jmap_filter *parsed_filter;
    ptrarray_t matches;
    script_info *anchor;
} filter_rock;

static void filter_cb(const char *script, void *data, void *rock)
{
    script_info *info = (script_info *) data;
    struct filter_rock *frock = (struct filter_rock *) rock;
    struct jmap_query *query = frock->query;

    info->name = xstrdup(script);

    if (!info->id) {
        /* Create script id symlink */
        info->id = xstrdup(makeuuid());
        create_id_link(frock->sievedir, info->id, script);
    }

    if (query->filter &&
        !jmap_filter_match(frock->parsed_filter, &filter_match, info)) {
        return;
    }

    /* Add record of the match to our array */
    ptrarray_append(&frock->matches, info);

    if (query->anchor && !strcmp(query->anchor, info->id)) {
        /* Mark record corresponding to anchor */
        frock->anchor = info;
    }

    query->total++;
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
            if (ma->isActive < mb->isActive)
                ret = -1;
            else if (ma->isActive > mb->isActive)
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

    hash_table scripts = HASH_TABLE_INITIALIZER;
    const char *sievedir = user_sieve_path(req->accountid);
    filter_rock frock =
        { sievedir, &query, parsed_filter, PTRARRAY_INITIALIZER, NULL };

    /* Build a list of scripts */
    _listscripts(sievedir, &scripts);

    /* Filter the scripts */
    hash_enumerate(&scripts, &filter_cb, &frock);

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
    }
    ptrarray_fini(&frock.matches);

    free_hash_table(&scripts, &free_script_info);
    if (parsed_filter) jmap_filter_free(parsed_filter, &free);

    /* Build response */
    query.query_state = sieve_state(sievedir);
    query.result_position = query.position;
    query.can_calculate_changes = 0;
    jmap_ok(req, jmap_query_reply(&query));

done:
    jmap_parser_fini(&parser);
    jmap_query_fini(&query);
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
    sieve_script_t *s = NULL;
    (void) sieve_script_parse_string(NULL, content, &errors, &s);
    if (s) {
        sieve_script_free(&s);
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
        matches = jmap_email_matchmime(md->content.matchmime, jfilter,
                                       ctx->cstate, userid, time(NULL), &err);

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
    const char *key, *scriptid = NULL, *bcname = NULL, *tmpname = NULL;
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
        const char *script =
            script_from_id(sievedir, scriptid + 1, SCRIPT_NAME_ONLY);

        if (script) {
            /* Use pre-compiled bytecode file */
            buf_printf(&buf, "%s/%s%s", sievedir, script, BYTECODE_SUFFIX);
            bcname = buf_cstring(&buf);
        }
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

        if (err) goto done;
    }

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

static int jmap_sieve_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx)
{
    if (ctx->blobid[0] != 'S') return 0;

    /* Make sure client can handle blob type. */
    if (ctx->accept_mime) {
        if (strcmp(ctx->accept_mime, "application/octet-stream") &&
            strcmp(ctx->accept_mime, "application/sieve")) {
            return HTTP_NOT_ACCEPTABLE;
        }

        buf_setcstr(&ctx->content_type, ctx->accept_mime);
    }
    else buf_setcstr(&ctx->content_type, "application/sieve; charset=utf-8");

    buf_setcstr(&ctx->encoding, "8BIT");

    /* Lookup scriptid */
    const char *sievedir =
        user_sieve_path(ctx->from_accountid ? ctx->from_accountid : req->accountid);
    const char *script = script_from_id(sievedir, ctx->blobid+1, 0);
    struct buf *content = NULL;

    if (script) {
        /* Load the script */
        content = sievedir_get_script(sievedir, script);
    }
    if (!content) return HTTP_NOT_FOUND;

    buf_move(&ctx->blob, content);
    buf_destroy(content);

    return HTTP_OK;
}
