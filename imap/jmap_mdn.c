/* jmap_mdn.c -- Routines for handling JMAP MDNs
 *
 * Copyright (c) 1994-2020 Carnegie Mellon University.  All rights reserved.
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

#include "http_jmap.h"
#include "jmap_api.h"
#include "jmap_mail.h"
#include "json_support.h"
#include "util.h"

static int jmap_mdn_send(jmap_req_t *req);
static int jmap_mdn_parse(jmap_req_t *req);

jmap_method_t jmap_mdn_methods_standard[] = {
    {
        "MDN/send",
        JMAP_URN_MDN,
        &jmap_mdn_send,
        /*flags*/0
    },
    {
        "MDN/parse",
        JMAP_URN_MDN,
        &jmap_mdn_parse,
        /*flags*/0
    },
    { NULL, NULL, NULL, 0}
};

jmap_method_t jmap_mdn_methods_nonstandard[] = {
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_mdn_init(jmap_settings_t *settings)
{
    jmap_method_t *mp;
    for (mp = jmap_mdn_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_MDN, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        for (mp = jmap_mdn_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }

}

HIDDEN void jmap_mdn_capabilities(json_t *account_capabilities)
{
    json_object_set_new(account_capabilities, JMAP_URN_MDN, json_object());
}

struct mdn_t {
    const char *emailid;
    const char *subj;
    const char *body;
    const char *mua;
    int inc_msg;
    struct {
        const char *action;
        const char *sending;
        const char *type;
    } dispo;

    /* server-set */
    char *gateway;
    char *orig_msgid;
    char *orig_rcpt;
    char *final_rcpt;
    char *error;
};

static json_t *parse_mdn_props(json_t *jmdn, struct mdn_t *mdn)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    json_t *arg, *err = NULL;

    memset(mdn, 0, sizeof(struct mdn_t));

    mdn->emailid = json_string_value(json_object_get(jmdn, "forEmailId"));
    if (!mdn->emailid) {
        jmap_parser_invalid(&parser, "forEmailId");
    }

    arg = json_object_get(jmdn, "subject");
    if (json_is_string(arg)) {
        mdn->subj = json_string_value(arg);
    }
    else if (JNOTNULL(arg)) {
        jmap_parser_invalid(&parser, "subject");
    }

    arg = json_object_get(jmdn, "textBody");
    if (json_is_string(arg)) {
        mdn->body = json_string_value(arg);
    }
    else if (JNOTNULL(arg)) {
        jmap_parser_invalid(&parser, "textBody");
    }

    arg = json_object_get(jmdn, "includeOriginalMessage");
    if (json_is_boolean(arg)) {
        mdn->inc_msg = json_boolean_value(arg);
    }
    else {
        jmap_parser_invalid(&parser, "includeOriginalMessage");
    }

    arg = json_object_get(jmdn, "reportingUA");
    if (json_is_string(arg)) {
        mdn->mua = json_string_value(arg);
    }
    else if (JNOTNULL(arg)) {
        jmap_parser_invalid(&parser, "reportingUA");
    }

    arg = json_object_get(jmdn, "disposition");
    if (json_is_object(arg)) {
        const char *key;
        json_t *val;

        jmap_parser_push(&parser, "disposition");
        json_object_foreach(arg, key, val) {
            const char *s;

            mdn->dispo.action = s =
                json_string_value(json_object_get(val, "actionMode"));
            if (!s || (strcmp(s, "manual-action") &&
                       strcmp(s, "automatic-action"))) {
                jmap_parser_invalid(&parser, "actionMode");
            }

            mdn->dispo.sending = s =
                json_string_value(json_object_get(val, "sendingMode"));
            if (!s || (strcmp(s, "MDN-sent-manually") &&
                       strcmp(s, "MDN-sent-automatically"))) {
                jmap_parser_invalid(&parser, "sendingMode");
            }

            mdn->dispo.type = s =
                json_string_value(json_object_get(val, "type"));
            if (!s || (strcmp(s, "deleted") &&
                       strcmp(s, "dispatched") &&
                       strcmp(s, "displayed") &&
                       strcmp(s, "processed"))) {
                jmap_parser_invalid(&parser, "type");
            }
        }
        jmap_parser_pop(&parser);
    }
    else {
        jmap_parser_invalid(&parser, "disposition");
    }

    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidProperties");
        json_object_set(err, "properties", parser.invalid);
    }

    jmap_parser_fini(&parser);

    return err;
}

static int jmap_mdn_send(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    const char *key, *id;
    json_t *arg, *val, *send = NULL, *err = NULL;
    int r = 0;

    /* Parse request */
    json_object_foreach(req->args, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        else if (!strcmp(key, "send")) {
            if (json_is_object(arg)) {
                send = arg;

                jmap_parser_push(&parser, "send");
                json_object_foreach(send, id, val) {
                    if (!json_is_object(val)) {
                        jmap_parser_invalid(&parser, id);
                    }
                }
                jmap_parser_pop(&parser);
            }
            else {
                jmap_parser_invalid(&parser, "send");
            }
        }

        else {
            jmap_parser_invalid(&parser, key);
        }
    }

    /* send is a required argument */
    if (!send || !json_object_size(send)) jmap_parser_invalid(&parser, "send");

    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s s:O}", "type", "invalidArguments",
                        "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }


    /* Process request */
    json_t *sent = NULL;
    json_t *not_sent = NULL;
    smtpclient_t *sm = NULL;

    json_object_foreach(send, id, val) {
        /* Parse MDN props */
        struct mdn_t mdn;

        err = parse_mdn_props(val, &mdn);
        if (!err) {
            /* Generate MDN */
        }

        if (!err) {
            /* Send MDN */
            json_t *new_mdn = NULL;

            if (!err) {
                if (!sent) not_sent = json_object();
                json_object_set_new(sent, id, new_mdn);
            }
        }

        if (err) {
            if (!not_sent) not_sent = json_object();
            json_object_set_new(not_sent, id, err);
        }
    }
    if (sm) smtpclient_close(&sm);


    /* Reply */
    jmap_ok(req, json_pack("{s:s s:o s:o}",
                           "accountId", req->accountid,
                           "sent", sent ? sent : json_null(),
                           "notSent", not_sent ? not_sent : json_null()));

done:
    jmap_parser_fini(&parser);
    return r;
}

static int jmap_mdn_parse(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_parse parse;
    json_t *err = NULL;

    /* Parse request */
    jmap_parse_parse(req, &parser, NULL, NULL, &parse, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Process request */
    json_t *jval;
    size_t i;
    json_array_foreach(parse.blob_ids, i, jval) {
        const char *blobid = json_string_value(jval);
        struct mailbox *mbox = NULL;
        msgrecord_t *mr = NULL;
        struct body *body = NULL;
        const struct body *part = NULL;

        int r = jmap_findblob(req, NULL/*accountid*/, blobid,
                              &mbox, &mr, &body, &part, NULL);
        if (r) {
            json_array_append_new(parse.not_found, json_string(blobid));
            continue;
        }

        /* parse blob */
        json_t *mdn = NULL;

        if (mdn) {
            json_object_set_new(parse.parsed, blobid, mdn);
        }
        else {
            json_array_append_new(parse.not_parsable, json_string(blobid));
        }
        msgrecord_unref(&mr);
        jmap_closembox(req, &mbox);
        message_free_body(body);
        free(body);
    }

    /* Build response */
    jmap_ok(req, jmap_parse_reply(&parse));

done:
    jmap_parser_fini(&parser);
    jmap_parse_fini(&parse);
    return 0;
}
