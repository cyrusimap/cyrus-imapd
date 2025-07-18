/* jmap_vacation.c -- Routines for handling JMAP vacation responses
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

#include "hash.h"
#include "http_jmap.h"
#include "json_support.h"
#include "map.h"
#include "sync_support.h"
#include "user.h"
#include "util.h"

#ifdef USE_SIEVE
#include "sieve/sieve_interface.h"
#include "sieve/bc_parse.h"
#include "sieve_db.h"
#include "sievedir.h"
#endif

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

static int jmap_vacation_get(jmap_req_t *req);
static int jmap_vacation_set(jmap_req_t *req);

// clang-format off
static jmap_method_t jmap_vacation_methods_standard[] = {
    {
        "VacationResponse/get",
        JMAP_URN_VACATION,
        &jmap_vacation_get,
        /*flags*/0
    },
    {
        "VacationResponse/set",
        JMAP_URN_VACATION,
        &jmap_vacation_set,
        JMAP_READ_WRITE
    },
    { NULL, NULL, NULL, 0}
};
// clang-format on

// clang-format off
static jmap_method_t jmap_vacation_methods_nonstandard[] = {
    { NULL, NULL, NULL, 0}
};
// clang-format on

static int sieve_vacation_enabled = 0;

HIDDEN void jmap_vacation_init(jmap_settings_t *settings)
{
    if (!config_getswitch(IMAPOPT_JMAP_VACATION)) return;

    if (config_getswitch(IMAPOPT_SIEVEUSEHOMEDIR)) {
        xsyslog(LOG_WARNING,
                "can't use home directories -- disabling module", NULL);
        return;
    }

    if (!sievedir_valid_path(config_getstring(IMAPOPT_SIEVEDIR))) {
        xsyslog(LOG_WARNING,
                "sievedir option is not defined or invalid -- disabling module",
                NULL);
        return;
    }

#ifdef USE_SIEVE
    uint64_t config_ext = config_getbitfield(IMAPOPT_SIEVE_EXTENSIONS);
    uint64_t required =
        IMAP_ENUM_SIEVE_EXTENSIONS_VACATION   |
        IMAP_ENUM_SIEVE_EXTENSIONS_RELATIONAL |
        IMAP_ENUM_SIEVE_EXTENSIONS_DATE;

    sieve_vacation_enabled = ((config_ext & required) == required);
#endif /* USE_SIEVE */

    if (!sieve_vacation_enabled) return;

    jmap_add_methods(jmap_vacation_methods_standard, settings);

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_VACATION, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        jmap_add_methods(jmap_vacation_methods_nonstandard, settings);
    }
}

HIDDEN void jmap_vacation_capabilities(json_t *account_capabilities)
{
    if (!sieve_vacation_enabled) return;

    json_object_set_new(account_capabilities, JMAP_URN_VACATION, json_object());
}

/* VacationResponse/get method */
// clang-format off
static const jmap_property_t vacation_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "isEnabled",
        NULL,
        0
    },
    {
        "fromDate",
        NULL,
        0
    },
    {
        "toDate",
        NULL,
        0
    },
    {
        "subject",
        NULL,
        0
    },
    {
        "textBody",
        NULL,
        0
    },
    {
        "htmlBody",
        NULL,
        0
    },

    { NULL, NULL, 0 }
};
// clang-format on

#define STATUS_ACTIVE    (1<<0)
#define STATUS_CUSTOM    (1<<1)
#define STATUS_ENABLE    (1<<2)

#define SCRIPT_HEADER    "/* Generated by Cyrus JMAP - DO NOT EDIT\r\n\r\n"

#define DEFAULT_MESSAGE  "I'm away at the moment." \
    "  I'll read your message and get back to you as soon as I can."

#define NO_INCLUDE_ERROR "Can not enable the vacation response" \
    " because the active Sieve script does not" \
    " properly include the '" JMAP_URN_VACATION "' script."

static json_t *vacation_read(jmap_req_t *req, struct mailbox *mailbox,
                             struct sieve_data *sdata, unsigned *status)
{
    const char *sieve_dir = user_sieve_path(req->accountid);
    struct buf content = BUF_INITIALIZER;
    json_t *vacation = NULL;

    sieve_script_fetch(mailbox, sdata, &content);

    /* Parse JMAP from vacation script */
    if (buf_len(&content)) {
        const char *json = strstr(buf_cstring(&content), SCRIPT_HEADER);

        if (json) {
            json_error_t jerr;

            json += strlen(SCRIPT_HEADER);
            vacation = json_loads(json, JSON_DISABLE_EOF_CHECK, &jerr);
        }
    }
    buf_free(&content);

    if (vacation) {
        int isEnabled =
            json_boolean_value(json_object_get(vacation, "isEnabled"));
        int isActive = sdata->isactive;

        if (isEnabled && !isActive) {
#ifdef USE_SIEVE
            /* Check if vacation script is really active */
            const char *activebc =  sievedir_get_active(sieve_dir);
            struct buf *buf = NULL;

            if (activebc && (buf = sievedir_get_script(sieve_dir, activebc))) {
                /* Parse active bytecode to see if vacation script is included */
                bytecode_input_t *bc = (bytecode_input_t *) buf_base(buf);
                int len = buf_len(buf);
                int i, version, requires;

                if (status) *status |= STATUS_CUSTOM;

                i = bc_header_parse(bc, &version, &requires);
                while (i > 0 && i < (int) len) {
                    commandlist_t cmd;

                    i = bc_action_parse(bc, i, version, &cmd);
                    if (cmd.type == B_INCLUDE &&
                        cmd.u.inc.location == B_PERSONAL &&
                        !strcmp(cmd.u.inc.script, JMAP_URN_VACATION)) {
                        /* Found it! */
                        isActive = 1;
                        break;
                    }
                    else if (cmd.type == B_IF) {
                        /* Skip over test */
                        i = cmd.u.i.testend;
                    }
                }

                buf_destroy(buf);
            }
        }
#endif /* USE_SIEVE */

        isEnabled = isActive && isEnabled;
        json_object_set_new(vacation, "isEnabled", json_boolean(isEnabled));

        if (status && isActive) *status |= STATUS_ACTIVE;
    }
    else {
        /* Build empty response */
        vacation = json_pack("{ s:s s:b s:n s:n s:n s:s s:n }",
                             "id", "singleton", "isEnabled", 0,
                             "fromDate", "toDate", "subject",
                             "textBody", DEFAULT_MESSAGE, "htmlBody");
    }

    return vacation;
}

static void vacation_get(jmap_req_t *req, struct mailbox *mailbox,
                         struct sieve_data *sdata, struct jmap_get *get)
{
    /* Read script */
    json_t *vacation = vacation_read(req, mailbox, sdata, NULL);

    /* Strip unwanted properties */
    if (!jmap_wantprop(get->props, "isEnabled"))
        json_object_del(vacation, "isEnabled");
    if (!jmap_wantprop(get->props, "fromDate"))
        json_object_del(vacation, "fromDate");
    if (!jmap_wantprop(get->props, "toDate"))
        json_object_del(vacation, "toDate");
    if (!jmap_wantprop(get->props, "subject"))
        json_object_del(vacation, "subject");
    if (!jmap_wantprop(get->props, "textBody"))
        json_object_del(vacation, "textBody");
    if (!jmap_wantprop(get->props, "htmlBody"))
        json_object_del(vacation, "htmlBody");

    /* Add object to list */
    json_array_append_new(get->list, vacation);
}

static int jmap_vacation_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get = JMAP_GET_INITIALIZER;
    json_t *err = NULL;
    struct sieve_db *db = NULL;
    struct mailbox *mailbox = NULL;
    struct sieve_data *sdata = NULL;
    int r = 0;

    /* Parse request */
    jmap_get_parse(req, &parser, vacation_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    r = sieve_ensure_folder(req->accountid, &mailbox, /*silent*/0);
    if (r) goto done;

    mailbox_unlock_index(mailbox, NULL);

    db = sievedb_open_userid(req->accountid);
    if (!db) {
        r = IMAP_INTERNAL;
        goto done;
    }

    r = sievedb_lookup_id(db, JMAP_URN_VACATION, &sdata, 0);
    if (r) {
        if (r == CYRUSDB_NOTFOUND) r = 0;
        else {
            r = IMAP_INTERNAL;
            goto done;
        }
    }

    /* Does the client request specific responses? */
    if (JNOTNULL(get.ids)) {
        json_t *jval;
        size_t i;

        json_array_foreach(get.ids, i, jval) {
            const char *id = json_string_value(jval);

            if (!strcmp(id, "singleton"))
                vacation_get(req, mailbox, sdata, &get);
            else
                json_array_append(get.not_found, jval);
        }
    }
    else vacation_get(req, mailbox, sdata, &get);

    /* Build response */
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, sdata->modseq);
    get.state = buf_release(&buf);
    jmap_ok(req, jmap_get_reply(&get));

done:
    if (r) {
        jmap_error(req, jmap_server_error(r));
    }
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);

    mailbox_close(&mailbox);
    sievedb_close(db);

    return 0;
}

static void vacation_update(struct jmap_req *req,
                            struct mailbox *mailbox, struct sieve_data *sdata,
                            json_t *patch, struct jmap_set *set)
{
    /* Parse and validate properties. */
    unsigned status = 0;
    json_t *vacation = NULL;
    json_t *prop, *jerr, *invalid = json_array();
    const char *err = NULL;
    int r;

    vacation = vacation_read(req, mailbox, sdata, &status);

    prop = json_object_get(patch, "isEnabled");
    if (!json_is_boolean(prop))
        json_array_append_new(invalid, json_string("isEnabled"));
    else if (json_is_true(prop) &&
             !json_equal(prop, json_object_get(vacation, "isEnabled"))) {
        /* isEnabled changing from false to true */
        status |= STATUS_ENABLE;
    }

    prop = json_object_get(patch, "fromDate");
    if (JNOTNULL(prop) && !json_is_utcdate(prop))
        json_array_append_new(invalid, json_string("fromDate"));

    prop = json_object_get(patch, "toDate");
    if (JNOTNULL(prop) && !json_is_utcdate(prop))
        json_array_append_new(invalid, json_string("toDate"));

    prop = json_object_get(patch, "subject");
    if (JNOTNULL(prop) && !json_is_string(prop))
        json_array_append_new(invalid, json_string("subject"));

    prop = json_object_get(patch, "textBody");
    if (JNOTNULL(prop) && !json_is_string(prop))
        json_array_append_new(invalid, json_string("textBody"));

    prop = json_object_get(patch, "htmlBody");
    if (JNOTNULL(prop) && !json_is_string(prop))
        json_array_append_new(invalid, json_string("htmlBody"));

    /* Report any property errors and bail out. */
    if (json_array_size(invalid)) {
        jerr = json_pack("{s:s, s:o}",
                         "type", "invalidProperties", "properties", invalid);
        json_object_set_new(set->not_updated, "singleton", jerr);
        json_decref(vacation);
        return;
    }
    json_decref(invalid);

    if (status == (STATUS_ENABLE | STATUS_CUSTOM)) {
        /* Custom script with no include -- fail */
        jerr = json_pack("{s:s, s:s}",
                         "type", "forbidden", "description", NO_INCLUDE_ERROR);
        json_object_set_new(set->not_updated, "singleton", jerr);
        json_decref(vacation);
        return;
    }

    /* Update VacationResponse object */

    json_t *new_vacation = jmap_patchobject_apply(vacation, patch, NULL, 0);
    json_decref(vacation);
    vacation = new_vacation;

    /* Dump VacationResponse JMAP object in a comment */
    size_t size = json_dumpb(vacation, NULL, 0, JSON_COMPACT);
    struct buf data = BUF_INITIALIZER;

    buf_setcstr(&data, SCRIPT_HEADER);
    buf_ensure(&data, size);
    json_dumpb(vacation,
               (char *) buf_base(&data) + buf_len(&data), size, JSON_COMPACT);
    buf_truncate(&data, buf_len(&data) + size);
    buf_appendcstr(&data, "\r\n\r\n*/\r\n\r\n");

    /* Create actual sieve rule */
    int isEnabled = json_boolean_value(json_object_get(vacation, "isEnabled"));
    const char *fromDate =
        json_string_value(json_object_get(vacation, "fromDate"));
    const char *toDate =
        json_string_value(json_object_get(vacation, "toDate"));
    const char *subject =
        json_string_value(json_object_get(vacation, "subject"));
    const char *textBody =
        json_string_value(json_object_get(vacation, "textBody"));
    const char *htmlBody =
        json_string_value(json_object_get(vacation, "htmlBody"));

    /* Add required extensions */
    buf_printf(&data, "require [ \"vacation\"%s ];\r\n\r\n",
               (fromDate || toDate) ? ", \"date\", \"relational\"" : "");

    /* Add isEnabled and date tests */
    buf_printf(&data, "if allof (%s", isEnabled ? "true" : "false");
    if (fromDate) {
        buf_printf(&data, ",\r\n%10scurrentdate :zone \"+0000\""
                   " :value \"ge\" \"iso8601\" \"%s\"", "", fromDate);
    }
    if (toDate) {
        buf_printf(&data, ",\r\n%10scurrentdate :zone \"+0000\""
                   " :value \"lt\" \"iso8601\" \"%s\"", "", toDate);
    }
    buf_appendcstr(&data, ")\r\n{\r\n");

    /* Add vacation action */
    buf_appendcstr(&data, "  vacation");
    if (subject) buf_printf(&data, " :subject \"%s\"", subject);
    /* XXX  Need to add :addresses */
    /* XXX  Should we add :fcc ? */

    if (htmlBody) {
        const char *boundary = makeuuid();
        char *text = NULL;

        if (!textBody) textBody = text = charset_extract_plain(htmlBody);

        buf_appendcstr(&data, " :mime text:\r\n");
        buf_printf(&data,
                   "Content-Type: multipart/alternative; boundary=%s\r\n"
                   "\r\n--%s\r\n", boundary, boundary);
        buf_appendcstr(&data,
                       "Content-Type: text/plain; charset=utf-8\r\n\r\n");
        buf_printf(&data, "%s\r\n\r\n--%s\r\n", textBody, boundary);
        buf_appendcstr(&data,
                       "Content-Type: text/html; charset=utf-8\r\n\r\n");
        buf_printf(&data, "%s\r\n\r\n--%s--\r\n", htmlBody, boundary);
        free(text);
    }
    else {
        buf_printf(&data, " text:\r\n%s",
                   textBody ? textBody : DEFAULT_MESSAGE);
    }
    buf_appendcstr(&data, "\r\n.\r\n;\r\n}\r\n");

    /* Store script */
    sdata->id = sdata->name = JMAP_URN_VACATION;

    r = sieve_script_store(mailbox, sdata, &data);

    buf_free(&data);
    json_decref(vacation);

    if (r) err = "Failed to update vacation response";
    else if (status == STATUS_ENABLE) {
        /* Activate vacation script */
        r = sieve_script_activate(mailbox, sdata);
        if (r) err = "Failed to enable vacation response";
    }

    if (r) {
        /* Failure to upload or activate */
        if (err) {
            jerr = json_pack("{s:s s:s}",
                             "type", "serverError", "description", err);
        }
        else {
            jerr = jmap_server_error(r);
        }
        json_object_set_new(set->not_updated, "singleton", jerr);
        r = 0;
    }
    else {
        /* Report vacation as updated. */
        json_object_set_new(set->updated, "singleton", json_null());
    }
}

static int jmap_vacation_set(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set = JMAP_SET_INITIALIZER;
    json_t *jerr = NULL;
    struct sieve_db *db = NULL;
    struct mailbox *mailbox = NULL;
    struct sieve_data *sdata = NULL;
    int r = 0;

    /* Parse arguments */
    jmap_set_parse(req, &parser, vacation_props, NULL, NULL, &set, &jerr);
    if (jerr) goto done;

    r = sieve_ensure_folder(req->accountid, &mailbox, /*silent*/0);
    if (r) goto done;

    db = sievedb_open_userid(req->accountid);
    if (!db) {
        r = IMAP_INTERNAL;
        goto done;
    }

    r = sievedb_lookup_id(db, JMAP_URN_VACATION, &sdata, 0);
    if (r) {
        if (r == CYRUSDB_NOTFOUND) r = 0;
        else {
            r = IMAP_INTERNAL;
            goto done;
        }
    }

    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, sdata->modseq);
    set.old_state = buf_release(&buf);

    if (set.if_in_state && strcmp(set.if_in_state, set.old_state)) {
        jerr = json_pack("{s:s}", "type", "stateMismatch");
        goto done;
    }


    /* create */
    const char *key;
    json_t *arg;
    json_object_foreach(set.create, key, arg) {
        json_object_set_new(set.not_created, key,
                            json_pack("{s:s}", "type", "singleton"));
    }


    /* update */
    const char *uid;
    json_object_foreach(set.update, uid, arg) {

        /* Validate uid */
        if (!uid) {
            continue;
        }
        if (strcmp(uid, "singleton")) {
            json_object_set_new(set.not_updated, uid,
                                json_pack("{s:s}", "type", "notFound"));
            continue;
        }

        vacation_update(req, mailbox, sdata, arg, &set);
    }


    /* destroy */
    size_t index;
    json_t *juid;

    json_array_foreach(set.destroy, index, juid) {
        json_object_set_new(set.not_destroyed, json_string_value(juid),
                            json_pack("{s:s}", "type", "singleton"));
    }

    sievedb_lookup_id(db, JMAP_URN_VACATION, &sdata, 0);
    buf_printf(&buf, MODSEQ_FMT, sdata->modseq);
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
