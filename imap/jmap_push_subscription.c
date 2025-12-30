/* jmap_push_subscription.c -- Routines for handling JMAP PushSubscription
 *
 * Copyright (c) 1994-2022 Carnegie Mellon University.  All rights reserved.
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
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>

#include "append.h"
#include "http_jmap.h"
#include "json_support.h"
#include "pushsub_db.h"
#include "times.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* PushSubscription/get method */
static const jmap_property_t pushsub_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "deviceClientId",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "url",
        NULL,
        JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET
    },
    {
        "keys",
        NULL,
        JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET
    },
    {
        "verificationCode",
        NULL,
        0
    },
    {
        "expires",
        NULL,
        0
    },
    {
        "types",
        NULL,
        0
    },

    { NULL, NULL, 0 }
};

static int getpushsub(void *rock, struct pushsub_data *psdata)
{
    struct jmap_get *get = (struct jmap_get *) rock;
    json_error_t jerr;
    json_t *pushsub = json_loads(psdata->subscription, 0, &jerr);

    if (pushsub) {
        if (!jmap_wantprop(get->props, "deviceClientId")) {
            json_object_del(pushsub, "deviceClientId");
        }

        /* MUST NOT return these */
        json_object_del(pushsub, "url");
        json_object_del(pushsub, "keys");

        if (!psdata->isverified ||
            !jmap_wantprop(get->props, "verificationCode")) {
            json_object_del(pushsub, "verificationCode");
        }

        if (!jmap_wantprop(get->props, "expires")) {
            json_object_del(pushsub, "expires");
        }

        if (!jmap_wantprop(get->props, "types")) {
            json_object_del(pushsub, "types");
        }

        /* Add object to list */
        json_array_append_new(get->list, pushsub);
    }
    else if (JNOTNULL(get->ids)) {
        json_array_append_new(get->not_found, json_string(psdata->id));
    }

    return 0;
}

HIDDEN int jmap_pushsub_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get = JMAP_GET_INITIALIZER;
    json_t *err = NULL;
    struct pushsub_db *db = NULL;
    struct mailbox *mailbox = NULL;
    json_t *res;
    int r = 0;

    /* Parse request */
    jmap_get_parse(req, &parser, pushsub_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (json_object_get(req->args, "accountId")) {
        jmap_parser_invalid(&parser, "accountId");

        if (err) json_decref(err);
        err = json_pack("{s:s s:O}", "type", "invalidArguments",
                        "arguments", parser.invalid);
    }
    else if (!err &&
             (jmap_wantprop(get.props, "url") ||
              jmap_wantprop(get.props, "keys"))) {
                 err = json_pack("{s:s, s:s}", "type", "forbidden",
                                 "description", "MUST NOT return private data");
             
    }
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    char *mboxname = pushsub_mboxname(req->accountid);
    r = mailbox_open_irl(mboxname, &mailbox);
    free(mboxname);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        r = 0;
        goto resp;
    }
    if (r) goto done;

    db = pushsubdb_open_userid(req->accountid);
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
            struct pushsub_data *psdata = NULL;

            r = pushsubdb_lookup_id(db, id, &psdata, 0);
            if (r || !psdata->imap_uid) {
                json_array_append_new(get.not_found, json_string(id));
                r = 0;
            }
            else {
                getpushsub(&get, psdata);
            }
        }
    }
    else {
        pushsubdb_foreach(db, &getpushsub, &get);
    }

resp:
    /* Build response */
    res = jmap_get_reply(&get);
    json_object_del(res, "state");
    req->accountid = NULL;  // suppress inclusion of 'accountId'
    jmap_ok(req, res);

done:
    if (r) {
        jmap_error(req, jmap_server_error(r));
    }
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);

    mailbox_close(&mailbox);
    pushsubdb_close(db);

    return 0;
}

#define THIRTY_DAYS  2592000  // 60 * 60 * 24 * 30

static int store_pushsub(const char *id, time_t *expires, strarray_t *types,
                         json_t *jpushsub, struct mailbox *mailbox)
{
    struct auth_state *authstate = NULL;
    struct buf buf = BUF_INITIALIZER;
    struct stagemsg *stage;
    struct appendstate as;
    char *data = json_dumps(jpushsub, JSON_INDENT(2));
    size_t datalen = strlen(data);
    time_t now = time(0);
    FILE *f;
    char *mimehdr;
    int r = 0;

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox_name(mailbox), now, 0, &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mailbox_name(mailbox));
        return CYRUSDB_IOERROR;
    }

    /* Create RFC 5322 header for subscription */
    char *userid = mboxname_to_userid(mailbox_name(mailbox));
    if (strchr(userid, '@')) {
        buf_printf(&buf, "<%s>", userid);
    }
    else {
        buf_printf(&buf, "<%s@%s>", userid, config_servername);
    }
    mimehdr = charset_encode_mimeheader(buf_cstring(&buf), buf_len(&buf), 0);
    fprintf(f, "From: %s\r\n", mimehdr);
    free(mimehdr);

    mimehdr = charset_encode_mimeheader(id, 0, 0);
    fprintf(f, "Subject: %s\r\n", mimehdr);
    free(mimehdr);

    char datestr[80];
    time_to_rfc5322(now, datestr, sizeof(datestr));
    fprintf(f, "Date: %s\r\n", datestr);

    /* Use id@servername as Message-ID */
    fprintf(f, "Message-ID: <%s@%s>\r\n", id, config_servername);

    fputs("Content-Type: application/json; charset=utf-8\r\n", f);
    fprintf(f, "Content-Length: " SIZE_T_FMT "\r\n", datalen);
    fputs("Content-Disposition: attachment\r\n", f);
    fputs("MIME-Version: 1.0\r\n", f);
    fputs("\r\n", f);

    /* Write the subscription data to the file */
    fwrite(data, datalen, 1, f);
    free(data);

    fclose(f);

    if (strarray_size(types)) {
        /* Need authstate in order to set flags */
        authstate = auth_newstate(userid);
    }

    if ((r = append_setup_mbox(&as, mailbox, userid, authstate,
                               0, NULL, NULL, 0, 0))) {
        syslog(LOG_ERR, "append_setup(%s) failed: %s",
               mailbox_name(mailbox), error_message(r));
    }
    else {
        struct body *body = NULL;

        /* Use internaldate to store expires time */
        if (*expires - now > THIRTY_DAYS) *expires = now + THIRTY_DAYS;

        struct timespec ts_expires = { *expires, 0 };
        r = append_fromstage(&as, &body, stage, &ts_expires, 0, types, 0, NULL);
        if (body) {
            message_free_body(body);
            free(body);
        }

        if (r) {
            syslog(LOG_ERR, "append_fromstage() failed: %s", error_message(r));
            append_abort(&as);
        }
        else {
            /* Commit the append to the pushsub mailbox */
            r = append_commit(&as);
            if (r) {
                syslog(LOG_ERR, "append_commit() failed: %s", error_message(r));
            }
        }
    }

    append_removestage(stage);
    auth_freestate(authstate);
    buf_free(&buf);
    free(userid);

    return r;
}

static strarray_t *allowed_push_types = NULL;

static const char *set_create(const char *creation_id, json_t *jpushsub,
                              struct mailbox *mailbox, struct jmap_set *set)
{
    json_t *arg, *invalid = json_array(), *err = NULL, *jtypes = NULL;
    strarray_t types = STRARRAY_INITIALIZER;
    const char *id = NULL;
#if (SIZEOF_TIME_T > 4)
    time_t expires = (time_t) LONG_MAX;
#else
    time_t expires = (time_t) INT_MAX;
#endif

    /* MUST NOT set id on create */
    arg = json_object_get(jpushsub, "id");
    if (arg)
        json_array_append_new(invalid, json_string("id"));
    else {
        json_t *jid = json_string(makeuuid());
        json_object_set_new(jpushsub, "id", jid);
        id = json_string_value(jid);
    }

    /* MUST set deviceClientId on create */
    arg = json_object_get(jpushsub, "deviceClientId");
    if (JNULL(arg) || !json_is_string(arg))
        json_array_append_new(invalid, json_string("deviceClientId"));

    /* MUST set url on create */
    arg = json_object_get(jpushsub, "url");
    if (JNULL(arg) || !json_is_string(arg))
        json_array_append_new(invalid, json_string("url"));

    /* If supplied, validate keys */
    arg = json_object_get(jpushsub, "keys");
    if (JNOTNULL(arg)) {
        if (!json_is_object(arg)) {
            json_array_append_new(invalid, json_string("keys"));
        }
        else if (!json_is_string(json_object_get(arg, "p256dh"))) {
            json_array_append_new(invalid, json_string("keys/p256dh"));
        }
        else if (!json_is_string(json_object_get(arg, "auth"))) {
            json_array_append_new(invalid, json_string("keys/auth"));
        }
    }
    else json_object_set_new(jpushsub, "keys", json_null());

    /* MUST NOT set verificationCode on create */
    arg = json_object_get(jpushsub, "verificationCode");
    if (JNOTNULL(arg))
        json_array_append_new(invalid, json_string("verificationCode"));
    else {
        json_object_set_new(jpushsub, "verificationCode",
                            json_string(makeuuid()));
    }

    /* If supplied, set expires */
    arg = json_object_get(jpushsub, "expires");
    if (JNOTNULL(arg)) {
        if (!json_is_utcdate(arg)) {
            json_array_append_new(invalid, json_string("expires"));
        }
        else {
            time_from_iso8601(json_string_value(arg), &expires);
        }
    }
    json_object_del(jpushsub, "expires");  // expires stored as internaldate

    /* If supplied, set types */
    arg = json_object_get(jpushsub, "types");
    if (JNOTNULL(arg)) {
        if (!json_is_array(arg)) {
            json_array_append_new(invalid, json_string("types"));
        }
        else {
            size_t i;
            json_t *val;
            json_array_foreach(arg, i, val) {
                const char *type = json_string_value(val);

                if (!type ||
                    strarray_find_case(allowed_push_types, type, 0) < 0) {
                    json_array_append_new(invalid,
                                          json_sprintf("types[%lu]", i));
                    break;
                }

                strarray_append(&types, type);
            }

            jtypes = json_incref(arg);
        }
    }
    json_object_del(jpushsub, "types");  // expires stored as user_flags

    /* Report any property errors and bail out */
    if (json_array_size(invalid)) {
        err = json_pack("{s:s, s:O}",
                        "type", "invalidProperties", "properties", invalid);
        goto done;
    }

    time_t orig_expires = expires;
    int r = store_pushsub(id, &expires, &types, jpushsub, mailbox);
    if (r) {
        err = jmap_server_error(r);
    }
    else {
        /* Report subscription as created, with server-set properties */
        json_t *new_pushsub = json_pack("{s:s}", "id", id);
        char datestr[RFC3339_DATETIME_MAX];

        time_to_rfc3339(expires, datestr, RFC3339_DATETIME_MAX);

        if (expires != orig_expires) {
            json_object_set_new(new_pushsub, "expires", json_string(datestr));
        }
        json_object_set_new(set->created, creation_id, new_pushsub);

        /* Send mboxevent */
        struct mboxevent *event = mboxevent_new(EVENT_PUSHSUB_CREATED);
        char *userid = mboxname_to_userid(mailbox_name(mailbox));

        /* Reinstate expires and type for the mboxevent */
        json_object_set_new(jpushsub, "expires", json_string(datestr));
        json_object_set_new(jpushsub, "types", jtypes ? jtypes : json_null());

        FILL_STRING_PARAM(event, EVENT_PUSHSUB_CREATED_USERID, userid);
        FILL_JSON_PARAM(event, EVENT_PUSHSUB_CREATED_CONTENT,
                        json_copy(jpushsub));

        mboxevent_notify(&event);
        mboxevent_free(&event);
    }

  done:
    if (err) {
        json_object_set_new(set->not_created, creation_id, err);
        id = NULL;
    }
    json_decref(invalid);
    strarray_fini(&types);

    return id;
}

static void set_update(const char *id, json_t *jpushsub,
                       struct mailbox *mailbox, struct pushsub_db *db,
                       struct jmap_set *set)
{
    json_t *arg, *invalid = json_array(), *err = NULL;
    strarray_t types = STRARRAY_INITIALIZER;
    struct pushsub_data *psdata = NULL;
    json_error_t jerr;
    json_t *old_pushsub;
    int r = 0;

    r = pushsubdb_lookup_id(db, id, &psdata, 0);
    if (r == CYRUSDB_NOTFOUND) {
        err = json_pack("{s:s}", "type", "notFound");
    }
    else if (r != CYRUSDB_OK ||
             !(old_pushsub = json_loads(psdata->subscription, 0, &jerr))) {
        r = IMAP_INTERNAL;
    }
    else {
        struct index_record record;
        time_t new_expires = 0;

        r = mailbox_find_index_record(mailbox, psdata->imap_uid, &record);
        if (r) {
            syslog(LOG_ERR, "reading record (%s:%u) failed: %s",
                   mailbox_name(mailbox), psdata->imap_uid, error_message(r));
            goto done;
        }

        /* If supplied, make sure id matches */
        arg = json_object_get(jpushsub, "id");
        if (arg && strcmpnull(json_string_value(arg), psdata->id))
            json_array_append_new(invalid, json_string("id"));

        /* If supplied, make sure deviceClientId matches */
        arg = json_object_get(jpushsub, "deviceClientId");
        if (arg) {
            json_t *cid = json_object_get(old_pushsub, "deviceClientId");
            if (strcmpnull(json_string_value(arg), json_string_value(cid))) {
                json_array_append_new(invalid, json_string("deviceClientId"));
            }
        }

        /* If supplied, make sure url matches */
        arg = json_object_get(jpushsub, "url");
        if (arg) {
            json_t *url = json_object_get(old_pushsub, "url");
            if (strcmpnull(json_string_value(arg), json_string_value(url))) {
                json_array_append_new(invalid, json_string("url"));
            }
        }

        /* If supplied, make sure key matches */
        arg = json_object_get(jpushsub, "keys");
        if (arg) {
            json_t *keys = json_object_get(old_pushsub, "keys");
            if (!keys) {
                json_array_append_new(invalid, json_string("keys"));
            }
            else if (strcmpnull(json_string_value(json_object_get(arg, "p256dh")),
                                json_string_value(json_object_get(keys, "p256dh")))) {
                json_array_append_new(invalid, json_string("keys/p256dh"));
            }
            else if (strcmpnull(json_string_value(json_object_get(arg, "auth")),
                                json_string_value(json_object_get(keys, "auth")))) {
                json_array_append_new(invalid, json_string("keys/auth"));
            }
        }

        /* If supplied, make sure verificationCode matches */
        arg = json_object_get(jpushsub, "verificationCode");
        if (arg) {
            json_t *vcode = json_object_get(old_pushsub, "verificationCode");

            if (!strcmpnull(json_string_value(arg), json_string_value(vcode))) {
                /* Code has been verified */
                record.system_flags |= FLAG_FLAGGED;
            }
            else {
                json_array_append_new(invalid, json_string("verificationCode"));
            }
        }

        /* If supplied, update expires */
        arg = json_object_get(jpushsub, "expires");
        if (JNOTNULL(arg)) {
            if (!json_is_utcdate(arg)) {
                json_array_append_new(invalid, json_string("expires"));
            }
            else {
                time_t now = time(0), expires = 0;
                time_from_iso8601(json_string_value(arg), &expires);
                if (expires - now > THIRTY_DAYS)
                    new_expires = expires = now + THIRTY_DAYS;
                record.internaldate.tv_sec = expires;
                record.internaldate.tv_nsec = 0;
            }
        }

        /* If supplied, replace types */
        arg = json_object_get(jpushsub, "types");
        if (arg) {
            if (!json_is_array(arg) && !json_is_null(arg)) {
                json_array_append_new(invalid, json_string("types"));
            }
            else {
                size_t i;
                json_t *val;
                int flagnum;

                memset(record.user_flags, 0, sizeof(record.user_flags));
                json_array_foreach(arg, i, val) {
                    const char *type = json_string_value(val);

                    if (!type ||
                        strarray_find_case(allowed_push_types, type, 0) < 0) {
                        json_array_append_new(invalid,
                                              json_sprintf("types[%lu]", i));
                        break;
                    }

                    r = mailbox_user_flag(mailbox, type, &flagnum, 1);
                    if (r) goto done;

                    record.user_flags[flagnum/32] |= 1<<(flagnum&31);
                }
            }
        }

        json_decref(old_pushsub);

        /* Report any property errors and bail out */
        if (json_array_size(invalid)) {
            err = json_pack("{s:s, s:O}",
                            "type", "invalidProperties", "properties", invalid);
            goto done;
        }

        /* Update index record */
        r = mailbox_rewrite_index_record(mailbox, &record);
        if (r) {
            syslog(LOG_ERR, "rewriting record (%s:%u) failed: %s",
                   mailbox_name(mailbox), psdata->imap_uid, error_message(r));
        }
        else {
            /* Report subscription as updated, with server-set properties */
            if (new_expires) {
                char datestr[RFC3339_DATETIME_MAX];
                time_to_rfc3339(new_expires, datestr, RFC3339_DATETIME_MAX);
                json_object_set_new(set->updated, id,
                                    json_pack("{s:s}", "expires", datestr));
            }
            else json_object_set_new(set->updated, id, json_null());
        }
    }

  done:
    if (r && !err) {
        err = jmap_server_error(r);
    }
    if (err) {
        json_object_set_new(set->not_updated, id, err);
    }
    json_decref(invalid);
    strarray_fini(&types);
}

static void set_destroy(const char *id,
                        struct mailbox *mailbox, struct pushsub_db *db,
                        struct jmap_set *set)
{
    struct pushsub_data *psdata = NULL;
    json_t *err = NULL;
    int r = 0;

    r = pushsubdb_lookup_id(db, id, &psdata, 0);
    if (r == CYRUSDB_NOTFOUND) {
        err = json_pack("{s:s}", "type", "notFound");
    }
    else if (r != CYRUSDB_OK) {
        r = IMAP_INTERNAL;
    }
    else {
        struct index_record record;

        r = mailbox_find_index_record(mailbox, psdata->imap_uid, &record);
        if (!r) {
            record.internal_flags |= FLAG_INTERNAL_EXPUNGED;

            r = mailbox_rewrite_index_record(mailbox, &record);
        }

        if (r) {
            syslog(LOG_ERR, "expunging record (%s:%u) failed: %s",
                   mailbox_name(mailbox), psdata->imap_uid, error_message(r));
        }
        else {
            /* Report subscription as destroyed */
            json_array_append_new(set->destroyed, json_string(id));
        }
    }

    if (r && !err) {
        err = jmap_server_error(r);
    }
    if (err) {
        json_object_set_new(set->not_destroyed, id, err);
    }
}

HIDDEN int jmap_pushsub_set(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set = JMAP_SET_INITIALIZER;
    json_t *jerr = NULL, *accountid;
    struct pushsub_db *db = NULL;
    struct mailbox *mailbox = NULL;
    int r = 0;

    if (!allowed_push_types) {
        allowed_push_types =
            strarray_split(config_getstring(IMAPOPT_JMAP_PUSH_TYPES),
                           " ", STRARRAY_TRIM);
    }

    /* Parse arguments */
    jmap_set_parse(req, &parser, pushsub_props, NULL, NULL, &set, &jerr);
    if ((accountid = json_object_get(req->args, "accountId")) || set.if_in_state) {
        if (accountid) jmap_parser_invalid(&parser, "accountId");
        else if (set.if_in_state) jmap_parser_invalid(&parser, "ifInState");
        if (jerr) json_decref(jerr);
        jerr = json_pack("{s:s s:O}", "type", "invalidArguments",
                         "arguments", parser.invalid);
    }
    if (jerr) goto done;

    r = pushsub_ensure_folder(req->accountid, &mailbox);
    if (r) goto done;

    db = pushsubdb_open_userid(req->accountid);
    if (!db) {
        r = IMAP_INTERNAL;
        goto done;
    }

    /* create */
    const char *creation_id, *id;
    json_t *val;
    json_object_foreach(set.create, creation_id, val) {
        id = set_create(creation_id, val, mailbox, &set);
        if (id) {
            /* Register creation id */
            jmap_add_id(req, creation_id, id);
        }
    }

    /* update */
    json_object_foreach(set.update, id, val) {
        set_update(id, val, mailbox, db, &set);
    }

    /* destroy */
    size_t i;
    json_array_foreach(set.destroy, i, val) {
        id = json_string_value(val);

        set_destroy(id, mailbox, db, &set);
    }

    /* Build response */
    json_t *res = jmap_set_reply(&set);
    json_object_del(res, "oldState");
    json_object_del(res, "newState");
    req->accountid = NULL;  // suppress inclusion of 'accountId'
    jmap_ok(req, res);

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
    pushsubdb_close(db);

    return 0;
}
