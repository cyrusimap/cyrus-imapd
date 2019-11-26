/* jmap_backup.c -- Routines for handling JMAP Backup/restoreXxx requests
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
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <errno.h>

#include "caldav_db.h"
#include "carddav_db.h"
#include "hash.h"
#include "http_jmap.h"
#include "json_support.h"
#include "map.h"
#include "sync_support.h"
#include "user.h"
#include "util.h"

static int jmap_backup_restore_contacts(jmap_req_t *req);
static int jmap_backup_restore_calendars(jmap_req_t *req);
static int jmap_backup_restore_notes(jmap_req_t *req);
static int jmap_backup_restore_mail(jmap_req_t *req);

jmap_method_t jmap_backup_methods_standard[] = {
    { NULL, NULL, NULL, 0}
};

jmap_method_t jmap_backup_methods_nonstandard[] = {
    {
        "Backup/restoreContacts",
        JMAP_BACKUP_EXTENSION,
        &jmap_backup_restore_contacts,
        JMAP_SHARED_CSTATE
    },
    {
        "Backup/restoreCalendars",
        JMAP_BACKUP_EXTENSION,
        &jmap_backup_restore_calendars,
        JMAP_SHARED_CSTATE
    },
    {
        "Backup/restoreNotes",
        JMAP_BACKUP_EXTENSION,
        &jmap_backup_restore_notes,
        JMAP_SHARED_CSTATE
    },
    {
        "Backup/restoreMail",
        JMAP_BACKUP_EXTENSION,
        &jmap_backup_restore_mail,
        JMAP_SHARED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_backup_init(jmap_settings_t *settings)
{
    jmap_method_t *mp;
    for (mp = jmap_backup_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(settings->server_capabilities,
                JMAP_BACKUP_EXTENSION, json_object());

        for (mp = jmap_backup_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }

}

HIDDEN void jmap_backup_capabilities(json_t *account_capabilities)
{
    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities, JMAP_BACKUP_EXTENSION, json_object());
    }
}

/* Backup/restoreXxx */

#define DESTROYS        0
#define UPDATES         1
#define CREATES         2
#define DRAFT_DESTROYS  1

struct jmap_restore {
    /* Request arguments */
    time_t cutoff;
    unsigned is_email     : 1;
    unsigned undo_create  : 1;
    unsigned undo_update  : 1;
    unsigned undo_destroy : 1;

    /* Response fields */
    unsigned num_undone[3];
};

static void jmap_restore_parse(jmap_req_t *req,
                               struct jmap_parser *parser,
                               int is_email,
                               struct jmap_restore *restore,
                               json_t **err)
{
    json_t *jargs = req->args;
    const char *key;
    json_t *arg;

    memset(restore, 0, sizeof(struct jmap_restore));

    restore->is_email = is_email;

    json_object_foreach(jargs, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        else if (!strcmp(key, "undoPeriod") && json_is_string(arg)) {
            struct icaldurationtype dur =
                icaldurationtype_from_string(json_string_value(arg));

            if (!icaldurationtype_is_bad_duration(dur)) {
                restore->cutoff = time(0) - icaldurationtype_as_int(dur);
            }
        }

        else if (is_email &&
                 !strcmp(key, "undoCreate") && json_is_boolean(arg)) {
            restore->undo_create = json_boolean_value(arg);
        }

        else if (is_email &&
                 !strcmp(key, "undoUpdate") && json_is_boolean(arg)) {
            restore->undo_update = json_boolean_value(arg);
        }

        else if (is_email &&
                 !strcmp(key, "undoDestroy") && json_is_boolean(arg)) {
            restore->undo_destroy = json_boolean_value(arg);
        }

        else {
            jmap_parser_invalid(parser, key);
        }
    }

    if (!restore->cutoff) {
        jmap_parser_invalid(parser, "undoPeriod");
    }

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                "arguments", parser->invalid);
    }
}

static void jmap_restore_fini(struct jmap_restore *restore __attribute__((unused)))
{
    return;
}

static json_t *jmap_restore_reply(struct jmap_restore *restore)
{
    json_t *res = json_object();

    if (restore->is_email) {
        json_object_set_new(res, "numDraftsRestored",
                            json_integer(restore->num_undone[DRAFT_DESTROYS]));
        json_object_set_new(res, "numNonDraftsRestored",
                            json_integer(restore->num_undone[DESTROYS]));
    }
    else {
        json_object_set_new(res, "numCreatesUndone",
                            json_integer(restore->num_undone[CREATES]));
        json_object_set_new(res, "numUpdatesUndone",
                            json_integer(restore->num_undone[UPDATES]));
        json_object_set_new(res, "numDestroysUndone",
                            json_integer(restore->num_undone[DESTROYS]));
    }

    return res;
}

static int jmap_backup_restore_contacts(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_restore restore;
    json_t *err = NULL;

    /* Parse request */
    jmap_restore_parse(req, &parser, /*is_mail*/ 0, &restore, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    jmap_ok(req, jmap_restore_reply(&restore));

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}

static int jmap_backup_restore_calendars(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_restore restore;
    json_t *err = NULL;

    /* Parse request */
    jmap_restore_parse(req, &parser, /*is_mail*/ 0, &restore, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    jmap_ok(req, jmap_restore_reply(&restore));

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}

static int jmap_backup_restore_notes(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_restore restore;
    json_t *err = NULL;

    /* Parse request */
    jmap_restore_parse(req, &parser, /*is_mail*/ 0, &restore, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    jmap_ok(req, jmap_restore_reply(&restore));

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}

static int jmap_backup_restore_mail(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_restore restore;
    json_t *err = NULL;

    /* Parse request */
    jmap_restore_parse(req, &parser, /*is_mail*/ 1, &restore, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    jmap_ok(req, jmap_restore_reply(&restore));

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}
