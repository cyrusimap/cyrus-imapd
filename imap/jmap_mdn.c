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
#include "parseaddr.h"
#include "times.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int jmap_mdn_send(jmap_req_t *req);
static int jmap_mdn_parse(jmap_req_t *req);

static jmap_method_t jmap_mdn_methods_standard[] = {
    {
        "MDN/send",
        JMAP_URN_MDN,
        &jmap_mdn_send,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "MDN/parse",
        JMAP_URN_MDN,
        &jmap_mdn_parse,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};

static jmap_method_t jmap_mdn_methods_nonstandard[] = {
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
    strarray_t notify_to;
    char *gateway;
    char *orig_msgid;
    char *orig_rcpt;
    char *final_rcpt;
    char *error;
};

static void free_mdn(struct mdn_t *mdn)
{
    strarray_fini(&mdn->notify_to);
    free(mdn->gateway);
    free(mdn->orig_msgid);
    free(mdn->orig_rcpt);
    free(mdn->final_rcpt);
    free(mdn->error);
}

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
    else if (JNOTNULL(arg)) {
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
            if (!strcmp(key, "actionMode"))
                mdn->dispo.action = json_string_value(val);
            else if (!strcmp(key, "sendingMode"))
                mdn->dispo.sending = json_string_value(val);
            else if (!strcmp(key, "type"))
                mdn->dispo.type = json_string_value(val);
            else
                jmap_parser_invalid(&parser, key);
        }

        const char *s = mdn->dispo.action;
        if (!s || (strcmp(s, "manual-action") &&
                   strcmp(s, "automatic-action"))) {
            jmap_parser_invalid(&parser, "actionMode");
        }

        s = mdn->dispo.sending;
        if (!s || (strcmp(s, "MDN-sent-manually") &&
                   strcmp(s, "MDN-sent-automatically"))) {
            jmap_parser_invalid(&parser, "sendingMode");
        }

        s = mdn->dispo.type;
        if (!s || (strcmp(s, "deleted") &&
                   strcmp(s, "dispatched") &&
                   strcmp(s, "displayed") &&
                   strcmp(s, "processed"))) {
            jmap_parser_invalid(&parser, "type");
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

static json_t *generate_mdn(struct jmap_req *req,
                            struct mdn_t *mdn, struct buf *msgbuf)
{
    char datestr[RFC5322_DATETIME_MAX+1];
    const char *uuid = makeuuid(), *from;
    char *mboxname = NULL;
    struct mailbox *mbox = NULL;
    struct buf buf = BUF_INITIALIZER;
    msgrecord_t *mr = NULL;
    message_t *msg;
    uint32_t uid;
    json_t *err = NULL;
    int r = 0;

    buf_reset(msgbuf);

    /* Lookup the message */
    r = jmap_email_find(req, NULL, mdn->emailid, &mboxname, &uid);
    if (r) {
        if (r == IMAP_NOTFOUND) {
            err = json_pack("{s:s}", "type", "emailNotFound");
        }
        goto done;
    }

    /* Check ACL */
    int rights = jmap_myrights(req, mboxname);
    if ((rights & JACL_READITEMS) != JACL_READITEMS) {
        err = json_pack("{s:s}", "type", "emailNotFound");
        goto done;
    }
    if ((rights & JACL_SETKEYWORDS) != JACL_SETKEYWORDS) {
        err = json_pack("{s:s}", "type", "forbidden");
        goto done;
    }

    /* Open the mailbox */
    r = jmap_openmbox(req, mboxname, &mbox, 1);
    if (r) goto done;

    /* Load the message */
    mr = msgrecord_from_uid(mbox, uid);
    if (!mr) {
        /* That's a never-should-happen error */
        syslog(LOG_ERR, "Unexpected null msgrecord at %s:%d",
               __FILE__, __LINE__);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Have we already sent an MDN? */
    int mdnsent;
    r = msgrecord_hasflag(mr, "$MDNSent", &mdnsent);
    if (r) {
        r = IMAP_INTERNAL;
        goto done;
    }
    if (mdnsent) {
        err = json_pack("{s:s}", "type", "mdnAlreadySent");
        goto done;
    }

    /* Get recipients of the MDN */
    r = msgrecord_get_message(mr, &msg);
    if (r) {
        r = IMAP_INTERNAL;
        goto done;
    }

    r = message_get_field(msg, "disposition-notification-to", MESSAGE_RAW, &buf);
    if (r) {
        err = json_pack("{s:s}", "type", "noRecipients");
        goto done;
    }

    struct address *a, *al = NULL;
    parseaddr_list(buf_cstring(&buf), &al);
    for (a = al; a; a = a->next) {
        if (!a->invalid) {
            strarray_appendm(&mdn->notify_to, address_get_all(a, 1/*canon*/));
        }
    }
    parseaddr_free(al);

    if (!strarray_size(&mdn->notify_to)) {
        err = json_pack("{s:s}", "type", "noRecipients");
        goto done;
    }
    

    /* Build message */
    time_to_rfc5322(time(NULL), datestr, sizeof(datestr));

    /* XXX  Is this the best/only way to determine the Final-Recipient? */
    buf_setcstr(&buf, "rfc822; ");
    buf_appendcstr(&buf, req->userid);
    if (!strchr(req->userid, '@')) buf_printf(&buf, "@%s", config_servername);
    mdn->final_rcpt = buf_release(&buf);
    from = mdn->final_rcpt + 8; /* skip "rfc822; " */

    buf_printf(msgbuf, "Date: %s\r\n", datestr);
    buf_printf(msgbuf, "From: <%s>\r\n", from);

    int i;
    for (i = 0; i < strarray_size(&mdn->notify_to); i++) {
        buf_printf(msgbuf, "To: <%s>\r\n", strarray_nth(&mdn->notify_to, i));
    }

    buf_printf(msgbuf, "Message-ID: <%s@%s>\r\n", uuid, config_servername);

    if (mdn->subj) {
        char *subj = charset_encode_mimeheader(mdn->subj, 0, 0);
        buf_printf(msgbuf, "Subject: %s\r\n", subj);
        free(subj);
    }
    else {
        buf_printf(msgbuf, "Subject: Return Receipt (%s)", mdn->dispo.type);
        r = message_get_subject(msg, &buf);
        if (!r && buf_len(&buf)) {
            buf_printf(msgbuf, " for\r\n\t%s", buf_cstring(&buf));
        }
        buf_appendcstr(msgbuf, "\r\n");
    }

    buf_printf(msgbuf, "Content-Type: "
               "multipart/report; report-type=disposition-notification;"
               "\r\n\tboundary=\"%s\"\r\n", uuid);
    buf_appendcstr(msgbuf, "MIME-Version: 1.0\r\n"
                   "\r\nThis is a MIME-encapsulated message\r\n\r\n");

    /* This is the human readable status report */
    buf_printf(msgbuf, "--%s\r\n", uuid);
    buf_appendcstr(msgbuf, "Content-Type: text/plain; charset=utf-8\r\n");
    buf_appendcstr(msgbuf, "Content-Disposition: inline\r\n");
    buf_appendcstr(msgbuf, "Content-Transfer-Encoding: 8bit\r\n\r\n");

    if (mdn->body) buf_appendcstr(msgbuf, mdn->body);
    else {
        buf_printf(msgbuf,
                   "This is a Return Receipt for the mail that you sent to %s.",
                   from);
    }
    buf_appendcstr(msgbuf, "\r\n\r\n");

    /* This is the MDN status report */
    buf_printf(msgbuf, "--%s\r\n", uuid);
    buf_appendcstr(msgbuf,
                   "Content-Type: message/disposition-notification\r\n\r\n");
    if (mdn->mua) buf_printf(msgbuf, "Reporting-UA: %s\r\n", mdn->mua);

    r = message_get_field(msg, "original-recipient", MESSAGE_RAW, &buf);
    if (!r && buf_len(&buf)) {
        mdn->orig_rcpt = xstrdup(buf_cstring(&buf));
        buf_printf(msgbuf, "Original-Recipient: rfc822; %s\r\n", mdn->orig_rcpt);
    }
    buf_printf(msgbuf, "Final-Recipient: %s\r\n", mdn->final_rcpt);

    r = message_get_messageid(msg, &buf);
    if (!r && buf_len(&buf)) {
        mdn->orig_msgid = xstrdup(buf_cstring(&buf));
        buf_printf(msgbuf, "Original-Message-ID: %s\r\n", mdn->orig_msgid);
    }
    buf_printf(msgbuf, "Disposition: %s/%s; %s\r\n",
               mdn->dispo.action, mdn->dispo.sending, mdn->dispo.type);
    buf_appendcstr(msgbuf, "\r\n");

    if (mdn->inc_msg) {
        r = message_get_headers(msg, &buf);
        if (!r) {
            /* This is the original message */
            buf_printf(msgbuf, "--%s\r\n", uuid);
            buf_appendcstr(msgbuf, "Content-Type: text/rfc822-headers\r\n");
            buf_appendcstr(msgbuf, "Content-Disposition: inline\r\n\r\n");
            buf_appendcstr(msgbuf, buf_cstring(&buf));
        }
    }

    buf_printf(msgbuf, "--%s--\r\n", uuid);

  done:
    if (r && err == NULL) err = jmap_server_error(r);
    if (mr) msgrecord_unref(&mr);
    if (mbox) jmap_closembox(req, &mbox);
    free(mboxname);
    buf_free(&buf);

    return err;
}

static json_t *send_mdn(struct jmap_req *req, struct mdn_t *mdn,
                        struct buf *msgbuf, smtpclient_t **sm)
{
    json_t *err = NULL;
    int r;

    if (!*sm) {
        /* Open the SMTP connection */
        r = smtpclient_open(sm);
        if (r) goto done;
    }

    smtpclient_set_auth(*sm, req->userid);

    /* Prepare envelope */
    smtp_envelope_t smtpenv = SMTP_ENVELOPE_INITIALIZER;
    smtp_envelope_set_from(&smtpenv, "<>");

    int i;
    for (i = 0; i < strarray_size(&mdn->notify_to); i++) {
        smtp_envelope_add_rcpt(&smtpenv, strarray_nth(&mdn->notify_to, i));
    }

    r = smtpclient_send(*sm, &smtpenv, msgbuf);
    if (r) {
        const char *desc = smtpclient_get_resp_text(*sm);

        syslog(LOG_ERR, "MDN/send failed: %s", desc ? desc : error_message(r));

        if (desc) {
            err = json_pack("{s:s, s:s}", "type", "serverFail",
                            "description", desc);
        }
    }

    smtp_envelope_fini(&smtpenv);

  done:
    if (r && err == NULL) err = jmap_server_error(r);

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
    json_t *sent = NULL, *not_sent = NULL, *update = NULL;
    smtpclient_t *sm = NULL;
    struct buf msgbuf = BUF_INITIALIZER;

    json_object_foreach(send, id, val) {
        /* Parse MDN props */
        struct mdn_t mdn;

        err = parse_mdn_props(val, &mdn);
        if (!err) {
            /* Generate MDN */
            err = generate_mdn(req, &mdn, &msgbuf);
        }

        if (!err) {
            /* Send MDN */
            err = send_mdn(req, &mdn, &msgbuf, &sm);

            if (!err) {
                /* XXX  With Jansson 2.11 we can use json_pack() and s*
                   which will skip NULL values */
                json_t *jmdn = json_object();

                if (mdn.gateway) {
                    json_object_set_new(jmdn, "mdnGateway",
                                        json_string(mdn.gateway));
                }
                if (mdn.orig_rcpt) {
                    json_object_set_new(jmdn, "originalRecipient",
                                        json_string(mdn.orig_rcpt));
                }
                if (mdn.final_rcpt) {
                    json_object_set_new(jmdn, "finalRecipient",
                                        json_string(mdn.final_rcpt));
                }
                if (mdn.orig_msgid) {
                    json_object_set_new(jmdn, "originalMessageId",
                                        json_string(mdn.orig_msgid));
                }
                if (mdn.error) {
                    json_object_set_new(jmdn, "error", json_string(mdn.error));
                }

                /* Add this id to the sent list */
                if (!sent) sent = json_object();
                json_object_set_new(sent, id, jmdn);

                /* Add this emailid to the list to be updated */
                if (!update) update = json_object();
                json_object_set_new(update, mdn.emailid,
                                    json_pack("{s:b}", "keywords/$MDNSent", 1));
            }
        }

        if (err) {
            /* Add this id to the not_sent list */
            if (!not_sent) not_sent = json_object();
            json_object_set_new(not_sent, id, err);
        }

        free_mdn(&mdn);
    }

    if (sm) smtpclient_close(&sm);
    buf_free(&msgbuf);


    /* Reply */
    jmap_ok(req, json_pack("{s:s s:o s:o}",
                           "accountId", req->accountid,
                           "sent", sent ? sent : json_null(),
                           "notSent", not_sent ? not_sent : json_null()));

    /* Implicitly set the $MDNSent keyword for successful MDNs */
    if (update) {
        jmap_add_subreq(req, "Email/set",
                        json_pack("{s:o}", "update", update), NULL);
    }

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
        struct buf buf = BUF_INITIALIZER;

        int r = jmap_findblob(req, NULL/*accountid*/, blobid,
                              &mbox, &mr, &body, &part, &buf);
        if (r) {
            json_array_append_new(parse.not_found, json_string(blobid));
            continue;
        }

        /* parse blob */
        json_t *mdn = NULL;

        // XXX -> convert `buf` into an mdn

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
        buf_free(&buf);
    }

    /* Build response */
    jmap_ok(req, jmap_parse_reply(&parse));

done:
    jmap_parser_fini(&parser);
    jmap_parse_fini(&parse);
    return 0;
}
