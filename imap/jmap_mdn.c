/* jmap_mdn.c - Routines for handling JMAP MDNs */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>

#include "http_jmap.h"
#include "jmap_api.h"
#include "jmap_mail.h"
#include "json_support.h"
#include "jmap_util.h"
#include "message.h"
#include "parseaddr.h"
#include "prot.h"
#include "spool.h"
#include "times.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int jmap_mdn_send(jmap_req_t *req);
static int jmap_mdn_parse(jmap_req_t *req);

// clang-format off
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
// clang-format on

// clang-format off
static jmap_method_t jmap_mdn_methods_nonstandard[] = {
    { NULL, NULL, NULL, 0}
};
// clang-format on

HIDDEN void jmap_mdn_init(jmap_settings_t *settings)
{
    jmap_add_methods(jmap_mdn_methods_standard, settings);

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_MDN, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        jmap_add_methods(jmap_mdn_methods_nonstandard, settings);
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
    const char *client_final_rcpt; /* client-set finalRecipient, or NULL */
    json_t *extensions;            /* client-set extensionFields, or NULL */
    bool inc_msg;
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
    char *final_addr; /* bare address of the Final-Recipient */
    char *error;
};

static void free_mdn(struct mdn_t *mdn)
{
    strarray_fini(&mdn->notify_to);
    free(mdn->gateway);
    free(mdn->orig_msgid);
    free(mdn->orig_rcpt);
    free(mdn->final_addr);
    free(mdn->error);
}

/* The fields RFC 8098, Section 3.1 defines.  Anything else in a
 * disposition-notification block is an extension field. */
static const char *const mdn_standard_fields[] = { "Reporting-UA",
                                                   "MDN-Gateway",
                                                   "Original-Recipient",
                                                   "Final-Recipient",
                                                   "Original-Message-ID",
                                                   "Disposition",
                                                   "Error",
                                                   "Failure",
                                                   "Warning",
                                                   NULL };

static bool is_mdn_standard_field(const char *name)
{
    for (const char *const *f = mdn_standard_fields; *f; f++) {
        if (!strcasecmp(name, *f)) {
            return true;
        }
    }
    return false;
}

/* True if s has the shape "address-type ; ..." of RFC 8098's
 * Original-Recipient and Final-Recipient fields. */
static bool has_address_type(const char *s)
{
    const char *p = s;
    while (isalnum((unsigned char) *p) || *p == '-') {
        p++;
    }
    if (p == s) {
        return false;
    }
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    return *p == ';';
}

/* The address part of an "address-type; address" value, or the whole
 * value if it has no address-type. */
static const char *address_of(const char *s)
{
    if (!has_address_type(s)) {
        return s;
    }
    s = strchr(s, ';') + 1;
    while (*s == ' ' || *s == '\t') {
        s++;
    }
    return s;
}

static bool valid_field_name(const char *name)
{
    if (!*name) {
        return false;
    }
    for (const char *p = name; *p; p++) {
        /* RFC 5322 ftext: printable US-ASCII except colon */
        if (*p < 33 || *p > 126 || *p == ':') {
            return false;
        }
    }
    return true;
}

static bool valid_field_value(const char *val)
{
    return !strpbrk(val, "\r\n");
}

static json_t *parse_mdn_props(json_t *jmdn, struct mdn_t *mdn)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    const char *key;
    json_t *arg, *err = NULL;

    memset(mdn, 0, sizeof(struct mdn_t));

    json_object_foreach (jmdn, key, arg) {
        if (!strcmp(key, "forEmailId")) {
            mdn->emailid = json_string_value(arg);
            if (!mdn->emailid) {
                jmap_parser_invalid(&parser, key);
            }
        }
        else if (!strcmp(key, "subject")) {
            if (json_is_string(arg)) {
                mdn->subj = json_string_value(arg);
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(&parser, key);
            }
        }
        else if (!strcmp(key, "textBody")) {
            if (json_is_string(arg)) {
                mdn->body = json_string_value(arg);
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(&parser, key);
            }
        }
        else if (!strcmp(key, "includeOriginalMessage")) {
            if (json_is_boolean(arg)) {
                mdn->inc_msg = json_boolean_value(arg);
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(&parser, key);
            }
        }
        else if (!strcmp(key, "reportingUA")) {
            if (json_is_string(arg)) {
                mdn->mua = json_string_value(arg);
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(&parser, key);
            }
        }
        else if (!strcmp(key, "finalRecipient")) {
            if (json_is_string(arg)) {
                mdn->client_final_rcpt = json_string_value(arg);
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(&parser, key);
            }
        }
        else if (!strcmp(key, "extensionFields")) {
            if (json_is_object(arg)) {
                const char *name;
                json_t *val;
                jmap_parser_push(&parser, key);
                json_object_foreach (arg, name, val) {
                    if (!valid_field_name(name) || is_mdn_standard_field(name)
                        || !json_is_string(val)
                        || !valid_field_value(json_string_value(val)))
                    {
                        jmap_parser_invalid(&parser, name);
                    }
                }
                jmap_parser_pop(&parser);
                mdn->extensions = arg;
            }
            else if (JNOTNULL(arg)) {
                jmap_parser_invalid(&parser, key);
            }
        }
        else if (!strcmp(key, "disposition")) {
            if (!json_is_object(arg)) {
                jmap_parser_invalid(&parser, key);
                continue;
            }

            const char *dkey;
            json_t *val;

            jmap_parser_push(&parser, "disposition");
            json_object_foreach (arg, dkey, val) {
                if (!strcmp(dkey, "actionMode")) {
                    mdn->dispo.action = json_string_value(val);
                }
                else if (!strcmp(dkey, "sendingMode")) {
                    mdn->dispo.sending = json_string_value(val);
                }
                else if (!strcmp(dkey, "type")) {
                    mdn->dispo.type = json_string_value(val);
                }
                else {
                    jmap_parser_invalid(&parser, dkey);
                }
            }

            /* RFC 9007 spells these in lowercase; RFC 8098 does not care */
            const char *s = mdn->dispo.action;
            if (!s
                || (strcasecmp(s, "manual-action")
                    && strcasecmp(s, "automatic-action")))
            {
                jmap_parser_invalid(&parser, "actionMode");
            }

            s = mdn->dispo.sending;
            if (!s
                || (strcasecmp(s, "mdn-sent-manually")
                    && strcasecmp(s, "mdn-sent-automatically")))
            {
                jmap_parser_invalid(&parser, "sendingMode");
            }

            s = mdn->dispo.type;
            if (!s
                || (strcasecmp(s, "deleted") && strcasecmp(s, "dispatched")
                    && strcasecmp(s, "displayed")
                    && strcasecmp(s, "processed")))
            {
                jmap_parser_invalid(&parser, "type");
            }

            jmap_parser_pop(&parser);
        }
        else {
            /* server-set properties and anything RFC 9007 doesn't define */
            jmap_parser_invalid(&parser, key);
        }
    }

    if (!mdn->emailid) {
        jmap_parser_invalid(&parser, "forEmailId");
    }
    if (!mdn->dispo.action) {
        jmap_parser_invalid(&parser, "disposition");
    }

    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidProperties");
        json_object_set(err, "properties", parser.invalid);
    }

    jmap_parser_fini(&parser);

    return err;
}

/* The address MDN/send reports as Final-Recipient unless the client
 * names one: the identity's address, which is the user. */
static char *identity_address(struct jmap_req *req)
{
    if (strchr(req->userid, '@')) {
        return xstrdup(req->userid);
    }
    return strconcat(req->userid, "@", config_servername, NULL);
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

    /* RFC 9007, Section 2.1: notFound covers both a missing message and
     * one that never asked for a receipt */
    r = jmap_email_find(req, NULL, mdn->emailid, &mboxname, &uid, NULL);
    if (r) {
        if (r == IMAP_NOTFOUND) {
            err = json_pack("{s:s s:s}",
                            "type",
                            "notFound",
                            "description",
                            "no such forEmailId");
        }
        goto done;
    }

    /* Check ACL */
    int rights = jmap_myrights(req, mboxname);
    if ((rights & JACL_READITEMS) != JACL_READITEMS) {
        err = json_pack("{s:s s:s}",
                        "type",
                        "notFound",
                        "description",
                        "no such forEmailId");
        goto done;
    }
    if ((rights & JACL_SETKEYWORDS) != JACL_SETKEYWORDS) {
        err = json_pack("{s:s}", "type", "forbidden");
        goto done;
    }

    /* Open the mailbox */
    r = mailbox_open_iwl(mboxname, &mbox);
    if (r) goto done;

    /* Load the message */
    mr = msgrecord_from_uid(mbox, uid);
    if (!mr) {
        xsyslog_ev(LOG_ERR, "mdn.msgrecord.missing",
                   lf_s("mailbox", mboxname),
                   lf_u("uid", uid));
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
        err = json_pack("{s:s s:s}",
                        "type",
                        "notFound",
                        "description",
                        "no Disposition-Notification-To");
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
        err = json_pack("{s:s s:s}",
                        "type",
                        "notFound",
                        "description",
                        "no Disposition-Notification-To");
        goto done;
    }

    /* Final-Recipient: the identity's address, unless the client named one
     * of its own (RFC 9007, Section 5) */
    mdn->final_addr = identity_address(req);
    if (mdn->client_final_rcpt) {
        const char *want = address_of(mdn->client_final_rcpt);
        if (strcasecmp(want, mdn->final_addr)) {
            err = json_pack("{s:s}", "type", "forbiddenFrom");
            goto done;
        }
    }
    from = mdn->final_addr;

    /* Build message */
    time_to_rfc5322(time(NULL), datestr, sizeof(datestr));

    buf_printf(msgbuf, "Date: %s\r\n", datestr);
    buf_printf(msgbuf, "From: <%s>\r\n", from);

    for (int i = 0; i < strarray_size(&mdn->notify_to); i++) {
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

    /* The header and the MDN field share the "address-type; address" syntax */
    r = message_get_field(msg, "original-recipient",
                          MESSAGE_DECODED | MESSAGE_TRIM | MESSAGE_FIRST, &buf);
    if (!r && buf_len(&buf)) {
        mdn->orig_rcpt = xstrdup(buf_cstring(&buf));
        buf_printf(msgbuf, "Original-Recipient: %s\r\n", mdn->orig_rcpt);
    }
    buf_printf(msgbuf, "Final-Recipient: rfc822; %s\r\n", mdn->final_addr);

    r = message_get_messageid(msg, &buf);
    if (!r && buf_len(&buf)) {
        mdn->orig_msgid = xstrdup(buf_cstring(&buf));
        buf_printf(msgbuf, "Original-Message-ID: %s\r\n", mdn->orig_msgid);
    }
    buf_printf(msgbuf, "Disposition: %s/%s; %s\r\n",
               mdn->dispo.action, mdn->dispo.sending, mdn->dispo.type);

    if (mdn->extensions) {
        const char *name;
        json_t *val;
        json_object_foreach (mdn->extensions, name, val) {
            buf_printf(msgbuf, "%s: %s\r\n", name, json_string_value(val));
        }
    }
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
    mailbox_close(&mbox);
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
    smtp_envelope_set_from(&smtpenv, "");

    for (int i = 0; i < strarray_size(&mdn->notify_to); i++) {
        smtp_envelope_add_rcpt(&smtpenv, strarray_nth(&mdn->notify_to, i));
    }

    r = smtpclient_send(*sm, &smtpenv, msgbuf);
    if (r) {
        const char *desc = smtpclient_get_resp_text(*sm);

        xsyslog_ev(LOG_ERR, "mdn.send.failed",
                   lf_s("error", desc ? desc : error_message(r)));

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

/* True if the PatchObject sets the $mdnsent keyword, either as a
 * "keywords/$mdnsent" patch or inside a whole "keywords" value. */
static bool patch_sets_mdnsent(json_t *patch)
{
    const char *key;
    json_t *val;

    if (!json_is_object(patch)) {
        return false;
    }

    json_object_foreach (patch, key, val) {
        if (!strncmp(key, "keywords/", 9)) {
            if (!strcasecmp(key + 9, "$mdnsent") && json_is_true(val)) {
                return true;
            }
        }
        else if (!strcmp(key, "keywords") && json_is_object(val)) {
            const char *kw;
            json_t *set;
            json_object_foreach (val, kw, set) {
                if (!strcasecmp(kw, "$mdnsent") && json_is_true(set)) {
                    return true;
                }
            }
        }
    }
    return false;
}

static int jmap_mdn_send(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    const char *key, *id;
    json_t *arg, *val, *send = NULL, *on_success = NULL, *err = NULL;
    const char *identity = NULL;

    /* Parse request */
    json_object_foreach(req->args, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        else if (!strcmp(key, "identityId")) {
            identity = json_string_value(arg);
            if (!identity) {
                jmap_parser_invalid(&parser, key);
            }
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

        else if (!strcmp(key, "onSuccessUpdateEmail")) {
            if (json_is_object(arg)) {
                on_success = arg;
            }
            else {
                jmap_parser_invalid(&parser, key);
            }
        }

        else {
            jmap_parser_invalid(&parser, key);
        }
    }

    /* The only identity is the user (see Identity/get) */
    if (!identity || strcmp(identity, req->userid)) {
        jmap_parser_invalid(&parser, "identityId");
    }

    /* send is a required argument */
    if (!send || !json_object_size(send)) jmap_parser_invalid(&parser, "send");

    /* RFC 9007, Section 2.1: every MDN must come with a patch that sets
     * $mdnsent on its message, and the patches may only refer to MDNs
     * in this request. */
    if (!on_success) {
        jmap_parser_invalid(&parser, "onSuccessUpdateEmail");
    }
    else {
        jmap_parser_push(&parser, "onSuccessUpdateEmail");
        json_object_foreach (on_success, id, val) {
            if (*id != '#' || !send || !json_object_get(send, id + 1)
                || !patch_sets_mdnsent(val))
            {
                jmap_parser_invalid(&parser, id);
            }
        }
        if (send) {
            json_object_foreach (send, id, val) {
                struct buf ref = BUF_INITIALIZER;
                buf_printf(&ref, "#%s", id);
                if (!json_object_get(on_success, buf_cstring(&ref))) {
                    jmap_parser_invalid(&parser, buf_cstring(&ref));
                }
                buf_free(&ref);
            }
        }
        jmap_parser_pop(&parser);
    }

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
                /* Report the server-set properties */
                json_t *jmdn = json_object();

                if (mdn.gateway) {
                    json_object_set_new(jmdn, "mdnGateway",
                                        json_string(mdn.gateway));
                }
                if (mdn.orig_rcpt) {
                    json_object_set_new(jmdn, "originalRecipient",
                                        json_string(mdn.orig_rcpt));
                }
                if (!mdn.client_final_rcpt) {
                    struct buf final = BUF_INITIALIZER;
                    buf_printf(&final, "rfc822; %s", mdn.final_addr);
                    json_object_set_new(jmdn,
                                        "finalRecipient",
                                        json_string(buf_cstring(&final)));
                    buf_free(&final);
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

                /* Queue the client's patch for this email */
                struct buf ref = BUF_INITIALIZER;
                buf_printf(&ref, "#%s", id);
                if (!update) update = json_object();
                json_object_set(update,
                                mdn.emailid,
                                json_object_get(on_success, buf_cstring(&ref)));
                buf_free(&ref);
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

    /* Apply onSuccessUpdateEmail to the messages whose MDN went out */
    if (update) {
        jmap_add_subreq(req, "Email/set",
                        json_pack("{s:o}", "update", update), NULL);
    }

done:
    jmap_parser_fini(&parser);
    return 0;
}

/* Depth-first search for the first part matching type/subtype. */
static const struct body *_mdn_find_part(const struct body *body,
                                         const char *type,
                                         const char *subtype)
{
    if (!body) return NULL;

    if (!strcasecmpsafe(body->type, type) &&
        !strcasecmpsafe(body->subtype, subtype)) {
        return body;
    }

    if (!strcasecmpsafe(body->type, "MULTIPART")) {
        int i;
        for (i = 0; i < body->numparts; i++) {
            const struct body *found =
                _mdn_find_part(&body->subpart[i], type, subtype);
            if (found) return found;
        }
    }
    else if (!strcasecmpsafe(body->type, "MESSAGE") && body->subpart) {
        return _mdn_find_part(body->subpart, type, subtype);
    }

    return NULL;
}

/* spool_enum_hdrcache callback: fields RFC 8098 doesn't define go into
 * the extensionFields object. */
static void collect_extension_field(const char *name,
                                    const char *body,
                                    const char *raw __attribute__((unused)),
                                    void *rock)
{
    json_t *extensions = rock;
    if (is_mdn_standard_field(name)) {
        return;
    }
    /* a repeated extension field keeps its first value */
    if (json_object_get(extensions, name)) {
        return;
    }
    json_object_set_new(extensions, name, json_string(body));
}

/* Build an MDN object (RFC 9007, Section 2) from the fields of a
 * message/disposition-notification part (RFC 8098, Section 3.1). */
static json_t *_mdn_from_dn_fields(const char *base, size_t len)
{
    /* spool_fill_hdrcache wants a header block terminated by a blank line,
     * which the part's content is not guaranteed to have. */
    struct buf buf = BUF_INITIALIZER;
    buf_appendmap(&buf, base, len);
    buf_appendcstr(&buf, "\r\n\r\n");

    struct protstream *pin = prot_readmap(buf_base(&buf), buf_len(&buf));
    hdrcache_t hdrs = spool_new_hdrcache();
    json_t *mdn = NULL;

    if (spool_fill_hdrcache(pin, NULL, hdrs, NULL)) goto done;

    /* "Disposition" is the only mandatory field, and the one that makes this
     * a disposition notification rather than an arbitrary header block. */
    const char **val = spool_getheader(hdrs, "Disposition");
    if (!val || !val[0]) goto done;

    /* action-mode "/" sending-mode ";" disposition-type [ "/" modifiers ] */
    const char *slash = strchr(val[0], '/');
    const char *semi = slash ? strchr(slash, ';') : NULL;
    if (!slash || !semi) goto done;

    const char *type = semi + 1;

    /* A disposition-type may carry "/modifier" suffixes; JMAP wants the type.
     * RFC 8098 values are case-insensitive, RFC 9007 wants them lowercase. */
    struct buf action = BUF_INITIALIZER, sending = BUF_INITIALIZER;
    struct buf dtype = BUF_INITIALIZER;
    buf_setmap(&action, val[0], slash - val[0]);
    buf_setmap(&sending, slash + 1, semi - slash - 1);
    buf_setmap(&dtype, type, strcspn(type, "/"));
    buf_trim(&action);
    buf_trim(&sending);
    buf_trim(&dtype);
    buf_lcase(&action);
    buf_lcase(&sending);
    buf_lcase(&dtype);

    if (buf_len(&action) && buf_len(&sending) && buf_len(&dtype)) {
        mdn = json_object();
        json_object_set_new(mdn, "disposition",
                            json_pack("{s:s s:s s:s}",
                                      "actionMode", buf_cstring(&action),
                                      "sendingMode", buf_cstring(&sending),
                                      "type", buf_cstring(&dtype)));
    }
    buf_free(&action);
    buf_free(&sending);
    buf_free(&dtype);
    if (!mdn) goto done;

    /* forEmailId is allowed to be absent for MDN/parse: RFC 9007, Section 2.2
     * lets it be null when the original message cannot be resolved, and this
     * blob need not correspond to anything in the account. */
    json_object_set_new(mdn, "forEmailId", json_null());

    /* Recipient fields keep their "address-type;" prefix: RFC 9007's own
     * examples give finalRecipient as "rfc822; john@example.com". */
    static const struct { const char *hdr; const char *prop; } simple[] = {
        { "Reporting-UA",        "reportingUA"       },
        { "MDN-Gateway",         "mdnGateway"        },
        { "Original-Recipient",  "originalRecipient" },
        { "Final-Recipient",     "finalRecipient"    },
        { "Original-Message-ID", "originalMessageId" },
        { NULL, NULL }
    };
    int i;
    for (i = 0; simple[i].hdr; i++) {
        val = spool_getheader(hdrs, simple[i].hdr);
        json_object_set_new(mdn, simple[i].prop,
                            val && val[0] ? json_string(val[0]) : json_null());
    }

    /* "Error" may appear more than once */
    val = spool_getheader(hdrs, "Error");
    if (val && val[0]) {
        json_t *errors = json_array();
        for (i = 0; val[i]; i++) {
            json_array_append_new(errors, json_string(val[i]));
        }
        json_object_set_new(mdn, "error", errors);
    }
    else json_object_set_new(mdn, "error", json_null());

    json_t *extensions = json_object();
    spool_enum_hdrcache(hdrs, &collect_extension_field, extensions);
    json_object_set_new(mdn,
                        "extensionFields",
                        json_object_size(extensions) ? extensions
                                                     : json_null());
    if (!json_object_size(extensions)) {
        json_decref(extensions);
    }

done:
    spool_free_hdrcache(hdrs);
    prot_free(pin);
    buf_free(&buf);
    return mdn;
}

/* Convert an RFC 5322 message that is expected to be an MDN into an MDN
 * object, or NULL if it is not one. */
static json_t *_mdn_from_buf(const struct buf *raw)
{
    struct body *body = xzmalloc(sizeof(struct body));
    json_t *mdn = NULL;

    if (message_parse_mapped(buf_base(raw), buf_len(raw), body, NULL)) {
        goto done;
    }

    const struct body *dn =
        _mdn_find_part(body, "MESSAGE", "DISPOSITION-NOTIFICATION");
    if (!dn) goto done;

    mdn = _mdn_from_dn_fields(buf_base(raw) + dn->content_offset,
                              dn->content_size);
    if (!mdn) goto done;

    json_object_set_new(mdn, "subject", jmap_header_as_text(body->subject));

    /* The human-readable part, if the sender included one */
    const struct body *text = _mdn_find_part(body, "TEXT", "PLAIN");
    if (text) {
        struct buf tmp = BUF_INITIALIZER;
        int encoding_problem = 0;
        jmap_decode_to_utf8(text->charset_id ? text->charset_id : "us-ascii",
                            encoding_lookupname(text->encoding),
                            buf_base(raw) + text->content_offset,
                            text->content_size,
                            0.0,
                            &tmp,
                            &encoding_problem);
        buf_trim(&tmp);
        json_object_set_new(mdn, "textBody", json_string(buf_cstring(&tmp)));
        buf_free(&tmp);
    }
    else json_object_set_new(mdn, "textBody", json_null());

    /* RFC 8098 permits either the message or just its headers as the third
     * part; both mean the original message was included. */
    int included = _mdn_find_part(body, "MESSAGE", "RFC822") ||
                   _mdn_find_part(body, "TEXT", "RFC822-HEADERS");
    json_object_set_new(mdn, "includeOriginalMessage", json_boolean(included));

done:
    message_free_body(body);
    free(body);
    return mdn;
}

static int jmap_mdn_parse(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_parse parse = JMAP_QUERYCHANGES_INITIALIZER;
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
        json_t *mdn = _mdn_from_buf(&buf);

        if (mdn) {
            json_object_set_new(parse.parsed, blobid, mdn);
        }
        else {
            json_array_append_new(parse.not_parsable, json_string(blobid));
        }
        msgrecord_unref(&mr);
        mailbox_close(&mbox);
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
