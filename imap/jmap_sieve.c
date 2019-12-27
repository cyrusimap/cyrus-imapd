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
    json_object_set_new(account_capabilities, JMAP_SIEVE_EXTENSION, json_object());
#endif /* USE_SIEVE */

}

#define SCRIPT_ID_PREFIX       ".JMAPID:"
#define SCRIPT_ID_PREFIX_LEN   8
#define BYTECODE_SUFFIX        ".bc"
#define BYTECODE_SUFFIX_LEN    3
#define SCRIPT_SUFFIX          ".script"
#define SCRIPT_SUFFIX_LEN      7
#define DEFAULTBC_NAME         "defaultbc"

static int script_isactive(const char *sievedir, const char *script)
{
    char link[PATH_MAX];
    struct stat sbuf;
    int ret = 0;

    if (!script) return 0;

    snprintf(link, sizeof(link), "%s/%s", sievedir, DEFAULTBC_NAME);

    if (!stat(link, &sbuf)) {
        char target[PATH_MAX];
        ssize_t tgt_len = readlink(link, target, sizeof(target) - 1);

        if (tgt_len > BYTECODE_SUFFIX_LEN &&
            !strncmp(script, target, tgt_len - BYTECODE_SUFFIX_LEN + 1)) {
            ret = 1;
        }
        else if (errno != ENOENT) {
            syslog(LOG_ERR, "readlink(" DEFAULTBC_NAME "): %m");
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

    return name;
}

static void getscript(const char *id, const char *script,
                      const char *sievedir, struct jmap_get *get)
{
    if (!script) script = script_from_id(sievedir, id);

    if (script) {
        json_t *sieve = json_pack("{s:s}", "id", id);
        struct buf buf = BUF_INITIALIZER;

        if (jmap_wantprop(get->props, "name") &&
            jmap_wantprop(get->props, "isActive")) {
            buf_setmap(&buf, script, strlen(script) - SCRIPT_SUFFIX_LEN);
            const char *name = buf_cstring(&buf);

            if (jmap_wantprop(get->props, "name")) {
                json_object_set_new(sieve, "name", json_string(name));
            }

            if (jmap_wantprop(get->props, "isActive")) {
                json_object_set_new(sieve, "isActive",
                                    json_boolean(script_isactive(sievedir, name)));
            }
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
};

static void list_cb(const char *script, void *data, void *rock)
{
    const char *id = (const char *) data;
    struct list_rock *lrock = (struct list_rock *) rock;

    if (!id) {
        /* Create script id symlink */
        char link[PATH_MAX];

        id = makeuuid();
        snprintf(link, sizeof(link),
                 "%s/%s%s", lrock->sievedir, SCRIPT_ID_PREFIX, id);

        symlink(script, link);
    }

    getscript(id, script, lrock->sievedir, lrock->get);
}

static void listscripts(const char *sievedir, struct jmap_get *get)
{
    hash_table scripts = HASH_TABLE_INITIALIZER;
    struct list_rock lrock = { sievedir, get };
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

    if (!stat(sievedir, &sbuf)) state = sbuf.st_mtime;

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
            getscript(json_string_value(jval), NULL, sievedir, &get);
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

    set.new_state = sieve_state(sievedir);
    jmap_ok(req, jmap_set_reply(&set));

done:
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    return r;
}
