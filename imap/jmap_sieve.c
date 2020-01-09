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

#include "hash.h"
#include "http_jmap.h"
#include "json_support.h"
#include "map.h"
#include "sieve/sieve_interface.h"
#include "sieve/bc_parse.h"
#include "sync_log.h"
#include "user.h"
#include "util.h"
#include "xmalloc.h"

static int jmap_sieve_get(jmap_req_t *req);
static int jmap_sieve_set(jmap_req_t *req);

jmap_method_t jmap_sieve_methods_standard[] = {
    { NULL, NULL, NULL, 0}
};

jmap_method_t jmap_sieve_methods_nonstandard[] = {
    {
        "Sieve/get",
        JMAP_SIEVE_EXTENSION,
        &jmap_sieve_get,
        JMAP_SHARED_CSTATE
    },
    {
        "Sieve/set",
        JMAP_SIEVE_EXTENSION,
        &jmap_sieve_set,
        JMAP_SHARED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_sieve_init(jmap_settings_t *settings)
{
#ifdef USE_SIEVE
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
#endif /* USE_SIEVE */
}

HIDDEN void jmap_sieve_capabilities(json_t *account_capabilities)
{
#ifdef USE_SIEVE
    static json_t *sieve_capabilities = NULL;

    if (!sieve_capabilities) {
        json_t *extensions = json_object();
        sieve_interp_t *interp = sieve_build_nonexec_interp();
        const strarray_t *ext = NULL;

        if (interp && (ext = sieve_listextensions(interp))) {
            hash_table capa = HASH_TABLE_INITIALIZER;
            const char *key;
            strarray_t *sa;
            int i;

            construct_hash_table(&capa, 5, 0);

            for (i = 0; i < strarray_size(ext); i += 2) {
                key = strarray_nth(ext, i);
                sa = strarray_split(strarray_nth(ext, i+1), " ", 0);

                hash_insert(key, sa, &capa);
            }

            ext = hash_lookup("SIEVE", &capa);
            for (i = 0; ext && i < strarray_size(ext); i++) {
                key = strarray_nth(ext, i);
                json_t *params = NULL;

                if (!strcmp(key, "enotify")) {
                    params = json_array();
                    sa = hash_lookup("NOTIFY", &capa);
                }
                else if (!strcmp(key, "extlists")) {
                    params = json_array();
                    sa = hash_lookup("EXTLISTS", &capa);
                }
                else {
                    params = json_null();
                    sa = NULL;
                }

                if (json_is_array(params) && sa) {
                    int j;

                    for (j = 0; j < strarray_size(sa); j++) {
                        json_array_append_new(params,
                                              json_string(strarray_nth(sa, j)));
                    }
                }

                json_object_set_new(extensions, key, params);
            }

            free_hash_table(&capa, (void (*)(void *)) &strarray_free);
        }
        if (interp) sieve_interp_free(&interp);

        sieve_capabilities = json_pack("{s:o}", "sieveExtensions", extensions);
    }

    json_object_set(account_capabilities, JMAP_SIEVE_EXTENSION, sieve_capabilities);
#endif /* USE_SIEVE */

}

#define SCRIPT_ID_PREFIX       ".JMAPID:"
#define SCRIPT_ID_PREFIX_LEN   8
#define BYTECODE_SUFFIX        ".bc"
#define BYTECODE_SUFFIX_LEN    3
#define SCRIPT_SUFFIX          ".script"
#define SCRIPT_SUFFIX_LEN      7
#define DEFAULTBC_NAME         "defaultbc"

static int script_isactive(const char *name, const char *sievedir)
{
    char link[PATH_MAX];
    struct stat sbuf;
    int ret = 0;

    if (!name) return 0;

    snprintf(link, sizeof(link), "%s/%s", sievedir, DEFAULTBC_NAME);

    if (!stat(link, &sbuf)) {
        char target[PATH_MAX];
        ssize_t tgt_len = readlink(link, target, sizeof(target) - 1);

        if (tgt_len > BYTECODE_SUFFIX_LEN &&
            !strncmp(name, target, tgt_len - BYTECODE_SUFFIX_LEN)) {
            ret = 1;
        }
        else if (tgt_len == -1 && errno != ENOENT) {
            syslog(LOG_ERR, "readlink(%s): %m", link);
        }
    }

    return ret;
}

static const char *script_from_id(const char *sievedir, const char *id)
{
    static char target[PATH_MAX];
    char link[PATH_MAX];
    struct stat sbuf;
    char *name = NULL;

    snprintf(link, sizeof(link), "%s/%s%s", sievedir, SCRIPT_ID_PREFIX, id);

    if (!stat(link, &sbuf)) {
        ssize_t tgt_len = readlink(link, target, sizeof(target) - 1);

        if (tgt_len > SCRIPT_SUFFIX_LEN &&
            !strcmp(target + (tgt_len - SCRIPT_SUFFIX_LEN), SCRIPT_SUFFIX)) {
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

static void getscript(const char *id, const char *script, int isactive,
                      const char *sievedir, struct jmap_get *get)
{
    if (!script) script = script_from_id(sievedir, id);

    if (script) {
        json_t *sieve = json_pack("{s:s}", "id", id);
        struct buf buf = BUF_INITIALIZER;

        if (jmap_wantprop(get->props, "name")) {
            buf_setmap(&buf, script, strlen(script) - SCRIPT_SUFFIX_LEN);
            json_object_set_new(sieve, "name", json_string(buf_cstring(&buf)));
        }

        if (jmap_wantprop(get->props, "isActive")) {
            if (isactive < 0) {
                buf_setmap(&buf, script, strlen(script) - SCRIPT_SUFFIX_LEN);
                isactive = script_isactive(buf_cstring(&buf), sievedir);
            }

            json_object_set_new(sieve, "isActive", json_boolean(isactive));
        }

        if (jmap_wantprop(get->props, "content")) {
            int fd;

            buf_reset(&buf);
            buf_printf(&buf, "%s/%s", sievedir, script);
            fd = open(buf_cstring(&buf), 0);

            buf_free(&buf);
            buf_refresh_mmap(&buf, 1, fd, script, MAP_UNKNOWN_LEN, "sieve");
            json_object_set_new(sieve, "content",
                                json_string(buf_cstring(&buf)));
            close(fd);
        }
        buf_free(&buf);

        /* Add object to list */
        json_array_append_new(get->list, sieve);
    }
    else {
        json_array_append_new(get->not_found, json_string(id));
    }
}

struct list_rock {
    const char *sievedir;
    struct jmap_get *get;
    const char *defaultbc;
};

static void list_cb(const char *script, void *data, void *rock)
{
    const char *id = (const char *) data;
    struct list_rock *lrock = (struct list_rock *) rock;
    int isactive = 0;

    if (!id) {
        /* Create script id symlink */
        char link[PATH_MAX];

        id = makeuuid();
        snprintf(link, sizeof(link),
                 "%s/%s%s", lrock->sievedir, SCRIPT_ID_PREFIX, id);

        symlink(script, link);
    }

    if (lrock->defaultbc &&
        !strncmp(lrock->defaultbc, script, strlen(script) - SCRIPT_SUFFIX_LEN)) {
        isactive = 1;
    }

    getscript(id, script, isactive, lrock->sievedir, lrock->get);
}

static void listscripts(const char *sievedir, struct jmap_get *get)
{
    hash_table scripts = HASH_TABLE_INITIALIZER;
    struct list_rock lrock = { sievedir, get, NULL };
    char target[PATH_MAX];
    struct dirent *dir;
    DIR *dp;

    /* Open the directory */
    dp = opendir(sievedir);

    if (dp == NULL) return;

    /* Build a hash of script name -> script id */
    construct_hash_table(&scripts, 16, 0);

    while ((dir = readdir(dp)) != NULL) {
        const char *name = dir->d_name;
        size_t namelen = strlen(name);

        if (!strncmp(name, SCRIPT_ID_PREFIX, SCRIPT_ID_PREFIX_LEN)) {
            /* Script id symlink */
            const char *id = name + SCRIPT_ID_PREFIX_LEN;
            const char *script = script_from_id(sievedir, id);

            if (script) {
                /* Map script name -> id */
                hash_insert(script, xstrdup(id), &scripts);
            }
            else {
                /* Dead link - remove it
                   (script was probably deleted via ManageSieve) */
                char link[PATH_MAX];

                snprintf(link, sizeof(link), "%s/%s", sievedir, name);
                unlink(link);
            }
        }
        else if (namelen > SCRIPT_SUFFIX_LEN &&
                 !strcmp(name + (namelen - SCRIPT_SUFFIX_LEN), SCRIPT_SUFFIX)) {
            /* Actual script file - check if we have an entry for this name */
            if (!hash_lookup(name, &scripts)) {
                /* Add script name -> NULL as a placeholder
                   (we will create an id symlink later, if necessary) */
                hash_insert(name, NULL, &scripts);
            }
        }
        else if (!strcmp(name, DEFAULTBC_NAME)) {
            char link[PATH_MAX];
            ssize_t tgt_len;

            snprintf(link, sizeof(link), "%s/%s", sievedir, name);
            tgt_len = readlink(link, target, sizeof(target) - 1);

            if (tgt_len > BYTECODE_SUFFIX_LEN) {
                target[tgt_len - BYTECODE_SUFFIX_LEN] = '\0';
                lrock.defaultbc = target;
            }
        }
    }
    closedir(dp);

    /* Perform a get on each script */
    hash_enumerate(&scripts, &list_cb, &lrock);
    free_hash_table(&scripts, &free);
}

static char *sieve_state(const char *sievedir)
{
    struct buf buf = BUF_INITIALIZER;
    struct stat sbuf;
    time_t state = 0;
    int r;

    r = stat(sievedir, &sbuf);
    if (r && errno == ENOENT) {
        r = cyrus_mkdir(sievedir, 0755);
        if (!r) {
            r = mkdir(sievedir, 0755);
            if (!r) r = stat(sievedir, &sbuf);
        }
    }
    state = r ? 0 : sbuf.st_mtime;

    buf_printf(&buf, "%ld", state);

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
        0
    },
    {
        "content",
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
    int r, verify_only = !name;
    char new_path[PATH_MAX];
    FILE *f;

    if (verify_only) {
        f = tmpfile();
    }
    else {
        snprintf(new_path, sizeof(new_path),
                 "%s/%s%s.NEW", sievedir, name, SCRIPT_SUFFIX);

        f = fopen(new_path, "w+");
    }

    if (f == NULL) {
        syslog(LOG_ERR, "fopen(%s): %m", new_path);
        return -1;
    }

    size_t i, content_len = strlen(content);
    int saw_cr = 0;

    /* copy data to file - replacing any lone CR or LF with the
     * CRLF pair so notify messages are SMTP compatible */
    for (i = 0; i < content_len; i++) {
        if (saw_cr) {
            if (content[i] != '\n') putc('\n', f);
        }
        else if (content[i] == '\n')
            putc('\r', f);

        putc(content[i], f);
        saw_cr = (content[i] == '\r');
    }
    if (saw_cr) putc('\n', f);

    rewind(f);

    /* verify the script */
    char *errors = NULL;
    sieve_script_t *s = NULL;
    r = sieve_script_parse_only(f, &errors, &s);
    fflush(f);
    fclose(f);

    if (r != SIEVE_OK) {
        *err = json_pack("{s:s, s:s}", "type", "invalidScript",
                         "description", errors);
        free(errors);
        unlink(new_path);
        return 0;
    }

    if (verify_only) return 0;


    /* generate the bytecode */
    bytecode_info_t *bc = NULL;
    if (sieve_generate_bytecode(&bc, s) == -1) {
        unlink(new_path);
        sieve_script_free(&s);
        *err = json_pack("{s:s, s:s}", "type", "serverFail",
                         "description", "bytecode generate failed");
        return 0;
    }

    /* open the new file */
    char new_bcpath[PATH_MAX];
    snprintf(new_bcpath, sizeof(new_bcpath),
             "%s/%s%s.NEW", sievedir, name, BYTECODE_SUFFIX);
    int fd = open(new_bcpath, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
        unlink(new_path);
        sieve_free_bytecode(&bc);
        sieve_script_free(&s);
        *err = json_pack("{s:s, s:s}", "type", "serverFail",
                         "description", "couldn't open bytecode file");
        return 0;
    }

    /* emit the bytecode */
    if (sieve_emit_bytecode(fd, bc) == -1) {
        close(fd);
        unlink(new_path);
        unlink(new_bcpath);
        sieve_free_bytecode(&bc);
        sieve_script_free(&s);
        *err = json_pack("{s:s, s:s}", "type", "serverFail",
                         "description", "bytecode emit failed");
        return 0;
    }

    sieve_free_bytecode(&bc);
    sieve_script_free(&s);

    close(fd);

    /* rename */
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s%s", sievedir, name, SCRIPT_SUFFIX);
    r = rename(new_path, path);
    if (!r) {
        snprintf(path, sizeof(path), "%s/%s%s", sievedir, name, BYTECODE_SUFFIX);
        r = rename(new_bcpath, path);
    }

    return r;
}

static int script_setactive(const char *name, int isactive, const char *sievedir)
{
    char link[PATH_MAX], target[PATH_MAX];
    int r;

    snprintf(link, sizeof(link), "%s/%s", sievedir, DEFAULTBC_NAME);
    r = unlink(link);
    if (r && errno == ENOENT) r = 0;

    if (!r && isactive == 1) {
        snprintf(target, sizeof(target), "%s%s", name, BYTECODE_SUFFIX);
        r = symlink(target, link);
    }

    return r;
}

static const char *set_create(const char *creation_id, json_t *jsieve,
                              const char *sievedir, struct jmap_set *set)
{
    json_t *arg, *invalid = json_pack("[]"), *err = NULL;
    const char *id = NULL, *name = NULL, *content = NULL;
    int r, isactive = -1;
    char path[PATH_MAX];

    arg = json_object_get(jsieve, "id");
    if (arg) json_array_append_new(invalid, json_string("id"));

    arg = json_object_get(jsieve, "name");
    if (!arg || !json_is_string(arg))
        json_array_append_new(invalid, json_string("name"));
    else  {
        /* sanity check script name and check for name collision */
        struct stat sbuf;

        name = json_string_value(arg);
        snprintf(path, sizeof(path), "%s/%s%s", sievedir, name, SCRIPT_SUFFIX);

        if (!*name || strrchr(name, '/') || !stat(path, &sbuf))
            json_array_append_new(invalid, json_string("name"));
    }

    arg = json_object_get(jsieve, "isActive");
    if (arg) {
        if (!json_is_boolean(arg))
            json_array_append_new(invalid, json_string("isActive"));
        else
            isactive = json_boolean_value(arg);
    }

    arg = json_object_get(jsieve, "content");
    if (!arg || !json_is_string(arg))
        json_array_append_new(invalid, json_string("content"));
    else 
        content = json_string_value(arg);

    /* Report any property errors and bail out */
    if (json_array_size(invalid)) {
        err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
        goto done;
    }
    json_decref(invalid);

    r = putscript(name, content, sievedir, &err);
    if (!r && isactive == 1) {
        /* set as active script */
        r = script_setactive(name, isactive, sievedir);
    }
    if (!r) {
        /* create script id link */
        char link[PATH_MAX];

        id = makeuuid();
        snprintf(link, sizeof(link), "%s/%s%s", sievedir, SCRIPT_ID_PREFIX, id);
        snprintf(path, sizeof(path), "%s%s", name, SCRIPT_SUFFIX);
        r = symlink(path, link);

        if (!r) {
            /* Report script as created */
            json_t *new_sieve = json_pack("{s:s}", "id", id);

            if (isactive == -1)
                json_object_set(new_sieve, "isActive", json_false());
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
    }

    return id;
}

static void set_update(const char *id, json_t *jsieve,
                       const char *sievedir, struct jmap_set *set)
{
    json_t *arg, *invalid = json_pack("[]"), *err = NULL;
    const char *script, *name = NULL, *content = NULL;
    char newpath[PATH_MAX], *cur_name = NULL;
    int r = 0, isactive = -1;

    if (!id) return;

    script = script_from_id(sievedir, id);
    if (!script) {
        err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    cur_name = xstrndup(script, strlen(script) - SCRIPT_SUFFIX_LEN);

    arg = json_object_get(jsieve, "id");
    if (arg && strcmpnull(id, json_string_value(arg)))
        json_array_append_new(invalid, json_string("id"));

    arg = json_object_get(jsieve, "name");
    if (arg && !json_is_string(arg))
        json_array_append_new(invalid, json_string("name"));
    else if (arg) {
        /* sanity check script name and check for name collision */
        struct stat sbuf;

        name = json_string_value(arg);
        snprintf(newpath, sizeof(newpath),
                 "%s/%s%s", sievedir, name, SCRIPT_SUFFIX);

        if (!*name || strrchr(name, '/') ||
            (strcmp(name, cur_name) && !stat(newpath, &sbuf))) {
            json_array_append_new(invalid, json_string("name"));
        }
    }

    arg = json_object_get(jsieve, "isActive");
    if (arg) {
        if (!json_is_boolean(arg))
            json_array_append_new(invalid, json_string("isActive"));
        else
            isactive = json_boolean_value(arg);
    }

    arg = json_object_get(jsieve, "content");
    if (arg && !json_is_string(arg))
        json_array_append_new(invalid, json_string("content"));
    else 
        content = json_string_value(arg);

    /* Report any property errors and bail out */
    if (json_array_size(invalid)) {
        err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
        goto done;
    }
    json_decref(invalid);

    if (content) {
        r = putscript(cur_name, content, sievedir, &err);
    }
    if (!r && name && strcmp(name, cur_name)) {
        /* rename script and bytecode; move script id link */
        char oldpath[PATH_MAX];

        snprintf(oldpath, sizeof(oldpath),
                 "%s/%s%s", sievedir, cur_name, SCRIPT_SUFFIX);
        r = rename(oldpath, newpath);
        if (!r) {
            char link[PATH_MAX];

            snprintf(link, sizeof(link),
                     "%s/%s%s", sievedir, SCRIPT_ID_PREFIX, id);
            r = unlink(link);
            if (!r) r = symlink(newpath + strlen(sievedir) + 1, link);
        }
        if (!r) {
            snprintf(oldpath, sizeof(oldpath),
                     "%s/%s%s", sievedir, cur_name, BYTECODE_SUFFIX);
            snprintf(newpath, sizeof(newpath),
                     "%s/%s%s", sievedir, name, BYTECODE_SUFFIX);
            r = rename(oldpath, newpath);
        }
    }
    if (!r && isactive >= 0 && isactive != script_isactive(cur_name, sievedir)) {
        /* [de]activate script */
        r = script_setactive(name ? name : cur_name, isactive, sievedir);
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
    free(cur_name);
}

static void set_destroy(const char *id,
                        const char *sievedir, struct jmap_set *set)
{
    const char *script = script_from_id(sievedir, id);
    json_t *err = NULL;

    if (!script) {
        err = json_pack("{s:s}", "type", "notFound");
    }
    else if (script_isactive(script, sievedir)) {
        err = json_pack("{s:s}", "type", "scriptIsActive");
    }
    else {
        size_t dirlen = strlen(sievedir) + 1;
        char path[PATH_MAX];
        int r;

        snprintf(path, sizeof(path), "%s/%s%s", sievedir, SCRIPT_ID_PREFIX, id);
        r = unlink(path);
        if (!r) {
            snprintf(path+dirlen, sizeof(path)-dirlen, "%s", script);
            unlink(path);
        }
        if (!r) {
            snprintf(path + dirlen, sizeof(path) - dirlen, "%.*s%s",
                     (int) strlen(script) - SCRIPT_SUFFIX_LEN, script,
                     BYTECODE_SUFFIX);
            unlink(path);
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

static int jmap_sieve_set(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *jerr = NULL;
    int r = 0;

    /* Parse arguments */
    jmap_set_parse(req, &parser, sieve_props, NULL, NULL, &set, &jerr);
    if (jerr) {
        jmap_error(req, jerr);
        goto done;
    }

    const char *sievedir = user_sieve_path(req->accountid);
    set.old_state = sieve_state(sievedir);

    if (set.if_in_state && strcmp(set.if_in_state, set.old_state)) {
        jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
        goto done;
    }


    /* create */
    const char *creation_id, *script_id;
    json_t *val;
    json_object_foreach(set.create, creation_id, val) {
        script_id = set_create(creation_id, val, sievedir, &set);
        if (script_id) {
            /* Register creation id */
            jmap_add_id(req, creation_id, script_id);
        }
    }


    /* update */
    const char *id;
    json_object_foreach(set.update, id, val) {
        script_id = (id && id[0] == '#') ? jmap_lookup_id(req, id + 1) : id;
        if (!script_id) continue;

        set_update(script_id, val, sievedir, &set);
    }


    /* destroy */
    size_t i;
    json_array_foreach(set.destroy, i, val) {
        id = json_string_value(val);
        script_id = (id && id[0] == '#') ? jmap_lookup_id(req, id + 1) : id;
        if (!script_id) continue;

        set_destroy(script_id, sievedir, &set);
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
    return r;
}
