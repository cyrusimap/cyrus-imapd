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
#include "hash.h"
#include "http_err.h"
#include "http_jmap.h"
#include "imap_err.h"
#include "jmap_mail.h"
#include "jmap_mail_query.h"
#include "json_support.h"
#include "map.h"
#include "parseaddr.h"
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

static int jmap_sieve_get(jmap_req_t *req);
static int jmap_sieve_set(jmap_req_t *req);
static int jmap_sieve_validate(jmap_req_t *req);
static int jmap_sieve_test(jmap_req_t *req);

static int jmap_sieve_getblob(jmap_req_t *req,
                              const char *blobid, const char *accept);

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
        JMAP_SHARED_CSTATE
    },
    {
        "SieveScript/set",
        JMAP_SIEVE_EXTENSION,
        &jmap_sieve_set,
        /*flags*/0
    },
    {
        "SieveScript/validate",
        JMAP_SIEVE_EXTENSION,
        &jmap_sieve_validate,
        JMAP_SHARED_CSTATE
    },
    {
        "SieveScript/test",
        JMAP_SIEVE_EXTENSION,
        &jmap_sieve_test,
        /*flags*/0
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

    ptrarray_append(&settings->getblob_handlers, jmap_sieve_getblob);

    maxscripts = config_getint(IMAPOPT_SIEVE_MAXSCRIPTS);
    maxscriptsize = config_getint(IMAPOPT_SIEVE_MAXSCRIPTSIZE) * 1024;
#endif /* USE_SIEVE */
}

HIDDEN void jmap_sieve_capabilities(json_t *account_capabilities)
{
#ifdef USE_SIEVE
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
            syslog(LOG_ERR, "IOERROR: readlink(%s): %m", link);
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

        if (jmap_wantprop(get->props, "blobId")) {
            buf_reset(&buf);
            buf_printf(&buf, "S%s", id);
            json_object_set_new(sieve, "blobId", json_string(buf_cstring(&buf)));
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
        "blobId",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
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
    char new_path[PATH_MAX];
    FILE *f;

    /* parse the script */
    char *errors = NULL;
    sieve_script_t *s = NULL;
    (void) sieve_script_parse_string(NULL, content, &errors, &s);
    if (!s) {
        *err = json_pack("{s:s, s:s}", "type", "invalidScript",
                         "description", errors);
        free(errors);
        return 0;
    }

    /* open a new file for the script */
    snprintf(new_path, sizeof(new_path),
             "%s/%s%s.NEW", sievedir, name, SCRIPT_SUFFIX);

    f = fopen(new_path, "w+");

    if (f == NULL) {
        syslog(LOG_ERR, "IOERROR: fopen(%s): %m", new_path);
        sieve_script_free(&s);
        *err = json_pack("{s:s, s:s}", "type", "serverFail",
                         "description", "couldn't create script file");
        return 0;
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

    fflush(f);
    fclose(f);

    /* generate the bytecode */
    bytecode_info_t *bc = NULL;
    if (sieve_generate_bytecode(&bc, s) == -1) {
        unlink(new_path);
        sieve_script_free(&s);
        *err = json_pack("{s:s, s:s}", "type", "serverFail",
                         "description", "bytecode generate failed");
        return 0;
    }

    /* open the new bytecode file */
    char new_bcpath[PATH_MAX];
    snprintf(new_bcpath, sizeof(new_bcpath),
             "%s/%s%s.NEW", sievedir, name, BYTECODE_SUFFIX);
    int fd = open(new_bcpath, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
        syslog(LOG_ERR, "IOERROR: open(%s): %m", new_bcpath);
        unlink(new_path);
        sieve_free_bytecode(&bc);
        sieve_script_free(&s);
        *err = json_pack("{s:s, s:s}", "type", "serverFail",
                         "description", "couldn't create bytecode file");
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
    int r = rename(new_path, path);
    if (r) syslog(LOG_ERR, "IOERROR: rename(%s, %s): %m", new_path, path);
    else {
        snprintf(path, sizeof(path), "%s/%s%s", sievedir, name, BYTECODE_SUFFIX);
        r = rename(new_bcpath, path);
        if (r) syslog(LOG_ERR, "IOERROR: rename(%s, %s): %m", new_bcpath, path);
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

    if (r) syslog(LOG_ERR, "IOERROR: unlink(%s): %m", link);
    else if (isactive == 1) {
        snprintf(target, sizeof(target), "%s%s", name, BYTECODE_SUFFIX);
        r = symlink(target, link);
        if (r) syslog(LOG_ERR, "IOERROR: symlink(%s, %s): %m", target, link);
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
    if (err) goto done;

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

        if (r) syslog(LOG_ERR, "IOERROR: symlink(%s, %s): %m", path, link);
        else {
            /* Report script as created */
            json_t *new_sieve = json_pack("{s:s}", "id", id);

            if (isactive == -1)
                json_object_set_new(new_sieve, "isActive", json_false());

            snprintf(link, sizeof(link), "S%s", id);
            json_object_set_new(new_sieve, "blobId", json_string(link));
            
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
        if (err) goto done;
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

static int jmap_sieve_validate(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    const char *key, *content = NULL;
    json_t *arg, *err = NULL;
    int is_valid = 0;

    /* Parse request */
    json_object_foreach(req->args, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        else if (!content && !strcmp(key, "content")) {
            content = json_string_value(arg);
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
        is_valid = 1;
    }
    else {
        err = json_string(errors);
        free(errors);
    }

    /* Build response */
    json_t *res = json_pack("{s:b s:o}", "isValid", is_valid,
                            "errorDescription", err);
    jmap_ok(req, res);

done:
    jmap_parser_fini(&parser);
    return 0;
}

static int jmap_sieve_getblob(jmap_req_t *req,
                              const char *blobid, const char *accept_mime)
{
    struct buf buf = BUF_INITIALIZER;
    int res = HTTP_OK;

    if (*blobid != 'S') return 0;

    /* Lookup scriptid */
    const char *sievedir = user_sieve_path(req->accountid);
    const char *script = script_from_id(sievedir, blobid+1);
    if (script) {
        buf_printf(&buf, "%s/%s", sievedir, script);
    }
    else {
        res = HTTP_NOT_FOUND;
        goto done;
    }

    /* Make sure client can handle blob type. */
    if (accept_mime) {
        if (strcmp(accept_mime, "application/octet-stream") &&
            strcmp(accept_mime, "application/sieve")) {
            res = HTTP_NOT_ACCEPTABLE;
            goto done;
        }

        req->txn->resp_body.type = accept_mime;
    }
    else req->txn->resp_body.type = "application/sieve";

    /* Load the message */
    int fd = open(buf_cstring(&buf), 0);
    if (fd == -1) {
        req->txn->error.desc = "failed to load script";
        res = HTTP_SERVER_ERROR;
        goto done;
    }

    buf_free(&buf);
    buf_refresh_mmap(&buf, 1, fd, script, MAP_UNKNOWN_LEN, "sieve");

    /* Write body */
    req->txn->resp_body.len = buf_len(&buf);
    write_body(HTTP_OK, req->txn, buf_base(&buf), buf_len(&buf));
    close(fd);

done:
    buf_free(&buf);

    return res;
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

    if (intname &&
        !mboxname_isdeletedmailbox(intname, NULL) &&
        !mboxname_isnonimapmailbox(intname, 0)) {
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

static int jmapquery(void *sc, void *mc, const char *json)
{
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
        md->content.matchmime = jmap_email_matchmime_init(&md->content.map, &err);

    /* Run query */
    if (md->content.matchmime)
        matches = jmap_email_matchmime(md->content.matchmime,
                                       jfilter, userid, time(NULL), &err);

    if (err) {
        char *errstr = json_dumps(err, JSON_COMPACT);
        fprintf(stderr, "sieve: jmapquery: %s\n", errstr);

        free(errstr);
    }

    json_decref(jfilter);

    return matches;
}

static void _strlist(json_t *action, const char *name, strarray_t *sl)
{
    if (strarray_size(sl)) {
        int i, n = strarray_size(sl);
        json_t *ja = json_array();

        for (i = 0; i < n; i++) {
            json_array_append_new(ja, json_string(strarray_nth(sl, i)));
        }
        json_object_set_new(action, name, ja);
    }
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

    json_t *action = json_pack("{s:s}", "type", "keep");

    _strlist(action, ":flags", kc->imapflags);

    json_array_append_new(m->actions, action);

    return SIEVE_OK;
}

static void _fileinto(json_t *action, sieve_fileinto_context_t *fc)
{
    _strlist(action, ":flags", fc->imapflags);
    if (fc->specialuse)
        json_object_set_new(action, ":specialuse", json_string(fc->specialuse));
    if (fc->mailboxid)
        json_object_set_new(action, ":mailboxid", json_string(fc->mailboxid));
    if (fc->do_create)
        json_object_set_new(action, ":create", json_true());
    json_object_set_new(action, "mailbox", json_string(fc->mailbox));
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

    json_t *action = json_pack("{s:s}", "type", "fileinto");

    _fileinto(action, fc);

    json_array_append_new(m->actions, action);

    return SIEVE_OK;
}

static int discard(void *ac __attribute__((unused)),
                   void *ic __attribute__((unused)),
                   void *sc __attribute__((unused)),
                   void *mc,
                   const char **errmsg __attribute__((unused)))
{
    message_data_t *m = (message_data_t *) mc;

    json_t *action = json_pack("{s:s}", "type", "discard");

    json_array_append_new(m->actions, action);

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

    json_t *action = json_pack("{s:s}", "type", "redirect");

    if (rc->dsn_notify)
        json_object_set_new(action, ":notify", json_string(rc->dsn_notify));
    if (rc->dsn_ret)
        json_object_set_new(action, ":ret", json_string(rc->dsn_ret));
    json_object_set_new(action, "address", json_string(rc->addr));

    json_array_append_new(m->actions, action);

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

    json_t *action = json_pack("{s:s s:s}",
                               "type", rc->is_extended ? "ereject" : "reject",
                               "reason", rc->msg);

    json_array_append_new(m->actions, action);

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

    json_t *action = json_pack("{s:s}", "type", "vacation");

    if (src->fcc.mailbox) {
        json_t *fcc = json_object();

        _fileinto(fcc, &src->fcc);

        json_object_set_new(action, ":fcc", fcc);
    }
    if (src->subj)
        json_object_set_new(action, ":subject", json_string(src->subj));
    if (src->fromaddr)
        json_object_set_new(action, ":from", json_string(src->fromaddr));
    if (src->mime)
        json_object_set_new(action, ":mime", json_true());
    json_object_set_new(action, "message", json_string(src->msg));

    json_array_append_new(m->actions, action);

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

    json_t *action = json_pack("{s:s}", "type", "addheader");

    if (index < 0) {
        spool_append_header(xstrdup(head), xstrdup(body), m->cache);

        json_object_set_new(action, ":last", json_true());
    }
    else {
        spool_prepend_header(xstrdup(head), xstrdup(body), m->cache);
    }

    json_object_set_new(action, "field", json_string(head));
    json_object_set_new(action, "value", json_string(body));

    json_array_append_new(m->actions, action);

    return SIEVE_OK;
}

static int deleteheader(void *mc, const char *head, int index)
{
    message_data_t *m = (message_data_t *) mc;

    if (head == NULL) return SIEVE_FAIL;

    if (!m->cache_full) fill_cache(m);

    json_t *action = json_pack("{s:s}", "type", "deleteheader");

    if (index) {
        spool_remove_header_instance(xstrdup(head), index, m->cache);

        json_object_set_new(action, ":index", json_integer(abs(index)));
        if (index < 0)
            json_object_set_new(action, ":last", json_true());
    }
    else {
        spool_remove_header(xstrdup(head), m->cache);
    }

    json_object_set_new(action, "field", json_string(head));

    json_array_append_new(m->actions, action);

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

    json_t *action = json_pack("{s:s}", "type", "notify");

    if (nc->from)
        json_object_set_new(action, ":from", json_string(nc->from));

    if (nc->priority)
        json_object_set_new(action, ":importance", json_string(nc->priority));

    _strlist(action, ":options", nc->options);

    if (nc->message)
        json_object_set_new(action, ":message", json_string(nc->message));

    if (nc->method)
        json_object_set_new(action, "method", json_string(nc->method));

    json_array_append_new(m->actions, action);

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

    json_t *action = json_pack("{s:s}", "type", "snooze");

    if (sn->awaken_spluse)
        json_object_set_new(action, ":specialuse", json_string(sn->awaken_spluse));
    if (sn->awaken_mboxid)
        json_object_set_new(action, ":mailboxid", json_string(sn->awaken_mboxid));
    if (sn->do_create)
        json_object_set_new(action, ":create", json_true());
    if (sn->awaken_mbox)
        json_object_set_new(action, ":mailbox", json_string(sn->awaken_mbox));

    _strlist(action, ":flags", sn->imapflags);
    _strlist(action, ":addflags", sn->addflags);
    _strlist(action, ":removeflags", sn->removeflags);

    if (sn->tzid) json_object_set_new(action, ":tzid", json_string(sn->tzid));

    if (sn->days && (sn->days & SNOOZE_WDAYS_MASK) != SNOOZE_WDAYS_MASK) {
        json_t *jdays = json_array();

        for (i = 0; i < 7; i++) {
            if (sn->days & (1 << i)) {
                buf_reset(sd->buf);
                buf_printf(sd->buf, "%u", i);
                json_array_append_new(jdays, json_string(buf_cstring(sd->buf)));
            }
        }
        json_object_set_new(action, ":weekdays", jdays);
    }
    
    int n = arrayu64_size(sn->times);
    json_t *jtimes = json_array();

    for (i = 0; i < n; i++) {
        uint64_t t = arrayu64_nth(sn->times, i);

        buf_reset(sd->buf);
        buf_printf(sd->buf, "%02lu:%02lu:%02lu", t / 3600, (t % 3600) / 60, t % 60);
        json_array_append_new(jtimes, json_string(buf_cstring(sd->buf)));
    }
    json_object_set_new(action, "times", jtimes);

    json_array_append_new(m->actions, action);

    return SIEVE_OK;
}

static void sieve_log(void *sc __attribute__((unused)),
                      void *mc, const char *text)
{
    message_data_t *m = (message_data_t *) mc;

    json_t *action = json_pack("{s:s s:s}", "type", "log", "text", text);

    json_array_append_new(m->actions, action);
}

static int getinclude(void *sc __attribute__((unused)),
                      const char *script,
                      int isglobal __attribute__((unused)),
                      char *fpath, size_t size)
{
    strlcpy(fpath, script, size);
    strlcat(fpath, ".bc", size);

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
    const char *key, *scriptid = NULL, *emailid = NULL, *bcname, *tmpname = NULL;
    json_t *arg, *envelope = NULL, *err = NULL;
    strarray_t env_from = STRARRAY_INITIALIZER;
    strarray_t env_to = STRARRAY_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    struct carddav_db *carddavdb = NULL;
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

        else if (!strcmp(key, "emailBlobId")) {
            emailid = json_string_value(arg);
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
        jmap_parser_invalid(&parser, "scriptId");
    }
    else if (scriptid[0] == '#') {
        scriptid = jmap_lookup_id(req, scriptid + 1);
    }

    if (!emailid) {
        jmap_parser_invalid(&parser, "emailId");
    }
    else if (emailid[0] == '#') {
        emailid = jmap_lookup_id(req, emailid + 1);
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
        jmap_error(req, err);
        goto done;
    }

    /* Is scriptid an installed script? */
    const char *sievedir = user_sieve_path(req->accountid);
    const char *script = script_from_id(sievedir, scriptid+1);
    if (script) {
        /* Use pre-compiled bytecode file */
        buf_printf(&buf, "%s/%.*s%s", sievedir,
                   (int) strlen(script) - SCRIPT_SUFFIX_LEN, script,
                   BYTECODE_SUFFIX);
        bcname = buf_cstring(&buf);
    }
    else {
        /* Is scriptid an uploaded blob? */
        r = jmap_findblob(req, NULL/*accountid*/, scriptid,
                          &mbox, &mr, NULL, NULL, &buf);
        if (r == IMAP_NOTFOUND) {
            err = json_pack("{s:s s:[s]}",
                            "type", "blobNotFound", "Id", scriptid);
        }
        else if (r) {
            err = jmap_server_error(r);
        }
        else {
            /* Generate temporary bytecode file */
            static char template[] = "/tmp/sieve-test-bytecode-XXXXXX";
            sieve_script_t *s = NULL;
            bytecode_info_t *bc = NULL;
            char *errors = NULL;
            int fd = -1;

            r = sieve_script_parse_string(NULL, buf_cstring(&buf), &errors, &s);
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

        if (err) {
            jmap_error(req, err);
            goto done;
        }
    }

    /* load the script */
    r = sieve_script_load(bcname, &exe);
    if (r != SIEVE_OK) {
        err = json_pack("{s:s s:s}", "type", "serverFail",
                        "description", "unable to load bytecode");
        jmap_error(req, err);
        goto done;
    }

    /* create interpreter */
    interp = sieve_interp_alloc(&carddavdb);
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

    /* load the email */
    message_data_t m = { { BUF_INITIALIZER, NULL, NULL}, 0, NULL,
        &env_from, &env_to, last_vaca_resp, NULL, &err };

    r = jmap_findblob(req, NULL/*accountid*/, emailid,
                      &mbox, &mr, NULL, NULL, &m.content.map);
    if (r) {
        if (r == IMAP_NOTFOUND)
            err = json_pack("{s:s s:[s]}",
                            "type", "blobNotFound", "Id", emailid);
        else
            err = jmap_server_error(r);

        jmap_error(req, err);
        goto done;
    }

    if (!envelope) {
        buf_setcstr(&buf, req->userid);
        if (!strchr(req->userid, '@')) {
            buf_printf(&buf, "@%s", config_servername);
        }
        strarray_append(&env_to, buf_cstring(&buf));
    }

    /* execute the script */
    script_data_t sd = { req->accountid, req->authstate, &jmap_namespace, &buf };
    m.actions = json_array();
    sieve_execute_bytecode(exe, interp, &sd, &m);

    strarray_fini(&env_from);
    strarray_fini(&env_to);
    msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);

    /* Build response */
    json_t *res = json_pack("{s:o s:o}", "actions", m.actions,
                            "error", err ? err : json_null());
    jmap_ok(req, res);

    free_msg(&m);

done:
    jmap_parser_fini(&parser);
    sieve_script_unload(&exe);
    sieve_interp_free(&interp);
    buf_free(&buf);
    if (tmpname) {
        /* Remove temp bytecode file */
        unlink(tmpname);
    }
    return 0;
}
