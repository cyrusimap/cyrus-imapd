/* jmap_push_subscription.c -- Routines for handling JMAP PushSubscription */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>

#include "append.h"
#include "http_jmap.h"
#include "jmap_mail_query.h"
#include "jmap_mail_query_parse.h"
#include "json_support.h"
#include "pushsub_db.h"
#include "times.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
#include "imap/jmap_props/email.h"
#include "imap/jmap_props/push_subscription.h"

/* draft-ietf-jmap-emailpush properties, null when absent */
static const char *const emailpush_props[] = { "emailPush", "emailCount" };

struct getpushsub_rock
{
    jmap_req_t *req;
    struct jmap_get *get;
};

/* PushSubscription/get method */
static int getpushsub(void *vrock, struct pushsub_data *psdata)
{
    struct getpushsub_rock *rock = vrock;
    struct jmap_get *get = rock->get;

    /* cyr_expire destroys it later */
    if (psdata->expires <= time(NULL)) {
        if (JNOTNULL(get->ids)) {
            json_array_append_new(get->not_found, json_string(psdata->id));
        }
        return 0;
    }

    json_t *pushsub = json_loads(psdata->subscription, 0, NULL);

    if (!pushsub) {
        xsyslog_ev(LOG_ERR, "jmap.pushsub.parse.failed",
                   lf_s("jmap.pushsubid", psdata->id));
        if (JNOTNULL(get->ids)) {
            json_array_append_new(get->not_found, json_string(psdata->id));
        }
        return 0;
    }

    if (!json_object_get(pushsub, "types")) {
        json_object_set_new(pushsub, "types", json_null());
    }

    bool using_emailpush = jmap_is_using(rock->req, JMAP_URN_EMAILPUSH);
    for (size_t i = 0; i < sizeof(emailpush_props) / sizeof(*emailpush_props);
         i++)
    {
        if (!using_emailpush) {
            json_object_del(pushsub, emailpush_props[i]);
        }
        else if (!json_object_get(pushsub, emailpush_props[i])) {
            json_object_set_new(pushsub, emailpush_props[i], json_null());
        }
    }

    const char *name;
    json_t *jval;
    void *tmp;
    json_object_foreach_safe (pushsub, tmp, name, jval) {
        if (!strcmp(name, "id")) {
            continue;
        }

        /* MUST NOT return these */
        if (!strcmp(name, "url") || !strcmp(name, "keys")
            || !jmap_wantprop(get->props, name))
        {
            json_object_del(pushsub, name);
        }
        else if (!strcmp(name, "verificationCode") && !psdata->isverified) {
            /* the code only reaches the client by push */
            json_object_set_new(pushsub, name, json_null());
        }
    }

    json_array_append_new(get->list, pushsub);

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
    jmap_get_parse(req,
                   &parser,
                   &pushsub_props,
                   /*allow_null_ids*/ 1,
                   NULL,
                   NULL,
                   &get,
                   &err);
    if (json_object_get(req->args, "accountId")) {
        jmap_parser_invalid(&parser, "accountId");

        if (err) {
            json_decref(err);
        }
        err = json_pack("{s:s s:O}",
                        "type",
                        "invalidArguments",
                        "arguments",
                        parser.invalid);
    }
    else if (!err
             && (jmap_wantprop(get.props, "url")
                 || jmap_wantprop(get.props, "keys")))
    {
        err = json_pack("{s:s, s:s}",
                        "type",
                        "forbidden",
                        "description",
                        "MUST NOT return private data");
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
    if (r) {
        goto done;
    }

    db = pushsubdb_open_userid(req->accountid);
    if (!db) {
        r = IMAP_INTERNAL;
        goto done;
    }

    struct getpushsub_rock rock = { req, &get };

    /* Does the client request specific responses? */
    if (JNOTNULL(get.ids)) {
        json_t *jval;
        size_t i;

        json_array_foreach (get.ids, i, jval) {
            const char *id = json_string_value(jval);
            struct pushsub_data *psdata = NULL;

            r = pushsubdb_lookup_id(db, id, &psdata, 0);
            if (r || !psdata->imap_uid) {
                json_array_append_new(get.not_found, json_string(id));
                r = 0;
            }
            else {
                getpushsub(&rock, psdata);
            }
        }
    }
    else {
        pushsubdb_foreach(db, &getpushsub, &rock);
    }

resp:
    /* Build response */
    res = jmap_get_reply(&get);
    json_object_del(res, "state");
    req->accountid = NULL; // suppress inclusion of 'accountId'
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

/* RFC 8620 requires at least 48 hours and recommends at least 7 days */
#define PUSHSUB_MAX_LIFETIME (30 * 24 * 60 * 60)

/* Append jpushsub to the mailbox as a new message.  An expires that is
 * missing or too far out is set to the limit and returned in new_jexpires. */
static int store_pushsub(struct mailbox *mailbox,
                         const char *id,
                         json_t *jpushsub,
                         bool verified,
                         json_t **new_jexpires)
{
    struct auth_state *authstate = NULL;
    struct buf buf = BUF_INITIALIZER;
    struct stagemsg *stage;
    struct appendstate as;
    time_t now = time(0), expires = 0;
    FILE *f;
    char *mimehdr, datestr[RFC3339_DATETIME_MAX];
    strarray_t flags = STRARRAY_INITIALIZER;
    int r = 0;

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox_name(mailbox), now, 0, &stage))) {
        xsyslog_ev(LOG_ERR, "jmap.pushsub.stage.failed",
                   lf_mailbox(mailbox),
                   lf_s("jmap.pushsubid", id));
        return IMAP_IOERROR;
    }

    json_t *jexpires = json_object_get(jpushsub, "expires");
    if (json_is_string(jexpires)
        && time_from_iso8601(json_string_value(jexpires), &expires) < 0)
    {
        expires = 0;
    }
    if (!expires || expires - now > PUSHSUB_MAX_LIFETIME) {
        expires = now + PUSHSUB_MAX_LIFETIME;

        time_to_rfc3339(expires, datestr, RFC3339_DATETIME_MAX);
        *new_jexpires = json_string(datestr);
        json_object_set(jpushsub, "expires", *new_jexpires);
    }

    /* Serialize the subscription */
    char *data = json_dumps(jpushsub, JSON_INDENT(2));
    size_t datalen = strlen(data);

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

    time_to_rfc5322(now, datestr, sizeof(datestr));
    fprintf(f, "Date: %s\r\n", datestr);

    /* Use id@servername as Message-ID */
    fprintf(f, "Message-ID: <%s@%s>\r\n", id, config_servername);

    fputs("Content-Type: application/json; charset=utf-8\r\n", f);
    fprintf(f, "Content-Length: %zu\r\n", datalen);
    fputs("Content-Disposition: attachment\r\n", f);
    fputs("MIME-Version: 1.0\r\n", f);
    fputs("\r\n", f);

    /* Write the subscription data to the file */
    fwrite(data, datalen, 1, f);
    free(data);

    fclose(f);

    if (verified) {
        strarray_append(&flags, "\\flagged");

        /* Need authstate in order to set flags */
        authstate = auth_newstate(userid);
    }

    r = append_setup_mbox(&as,
                          mailbox,
                          userid,
                          authstate,
                          0,
                          NULL,
                          NULL,
                          0,
                          EVENT_MESSAGE_NEW);
    if (!r) {
        struct body *body = NULL;
        struct timespec ts_expires = { expires, 0 };

        /* Use internaldate to store expires time */
        r = append_fromstage(&as,
                             &body,
                             stage,
                             &ts_expires,
                             0,
                             &flags,
                             0,
                             NULL);
        if (body) {
            message_free_body(body);
            free(body);
        }

        if (r) {
            append_abort(&as);
        }
        else {
            r = append_commit(&as);
        }
    }
    if (r) {
        xsyslog_ev(LOG_ERR, "jmap.pushsub.store.failed",
                   lf_mailbox(mailbox),
                   lf_s("jmap.pushsubid", id),
                   lf_err("error", r));
    }

    append_removestage(stage);
    auth_freestate(authstate);
    strarray_fini(&flags);
    buf_free(&buf);
    free(userid);

    return r;
}

static bool push_type_allowed(const char *type)
{
    const struct enum_option_s *opt;

    for (opt = imapopts[IMAPOPT_JMAP_PUSH_TYPES].enum_options; opt->name; opt++)
    {
        if (!strcmp(opt->name, type)) {
            return config_getbitfield(IMAPOPT_JMAP_PUSH_TYPES) & opt->val;
        }
    }

    return false;
}

/* types is the property's value, or NULL if absent */
static void validate_types(json_t *types, json_t *invalid)
{
    if (!types || json_is_null(types)) {
        return;
    }

    if (!json_is_array(types)) {
        json_array_append_new(invalid, json_string("types"));
        return;
    }

    size_t i;
    json_t *val;
    json_array_foreach (types, i, val) {
        if (!json_is_string(val) || !push_type_allowed(json_string_value(val)))
        {
            json_array_append_new(invalid, json_sprintf("types[%zu]", i));
        }
    }
}

/* An urgency-option from RFC 8030, or absent for "normal" */
static bool urgency_is_valid(json_t *jval)
{
    if (!jval) {
        return true;
    }

    const char *s = json_string_value(jval);
    return s
           && (!strcmp(s, "very-low") || !strcmp(s, "low")
               || !strcmp(s, "normal") || !strcmp(s, "high"));
}

/* As jmap_email_matchmime() parses it, so the filter can be evaluated at
 * delivery */
static bool emailpush_filter_is_valid(jmap_req_t *req, json_t *filter)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    json_t *unsupported = json_array();
    struct jmap_email_filter_parser_rock frock = { &parser, unsupported };
    jmap_email_filter_parse_ctx_t ctx = {
        &jmap_email_filtercondition_validate,
        &jmap_filter_parser_invalid,
        &jmap_filter_parser_push_index,
        &jmap_filter_parser_pop,
        req->using_capabilities,
        &frock,
    };

    jmap_email_filter_parse(filter, &ctx);
    bool valid =
        !json_array_size(parser.invalid) && !json_array_size(unsupported);

    jmap_parser_fini(&parser);
    json_decref(unsupported);

    return valid;
}

/* Email/get supports it, and needs no further arguments to return it */
static bool emailpush_property_is_valid(jmap_req_t *req, json_t *jval)
{
    const char *name = json_string_value(jval);
    if (!name || !strcmp(name, "bodyValues")) {
        return false;
    }
    if (!strncmp(name, "header:", 7)) {
        return name[7] != '\0';
    }

    const jmap_property_t *prop = jmap_property_find(name, &email_props);
    return prop && (!prop->capability || jmap_is_using(req, prop->capability));
}

static void validate_emailpushconfig(jmap_req_t *req,
                                     json_t *jconfig,
                                     const char *path,
                                     json_t *invalid)
{
    json_t *jval = json_object_get(jconfig, "filter");
    if (JNOTNULL(jval) && !emailpush_filter_is_valid(req, jval)) {
        json_array_append_new(invalid, json_sprintf("%s/filter", path));
    }

    jval = json_object_get(jconfig, "properties");
    if (jval) {
        bool valid = json_is_array(jval);
        size_t i;
        json_t *jprop;
        json_array_foreach (jval, i, jprop) {
            valid = valid && emailpush_property_is_valid(req, jprop);
        }
        if (!valid) {
            json_array_append_new(invalid, json_sprintf("%s/properties", path));
        }
    }

    if (!urgency_is_valid(json_object_get(jconfig, "urgency"))) {
        json_array_append_new(invalid, json_sprintf("%s/urgency", path));
    }
}

static void validate_emailcountconfig(jmap_req_t *req,
                                      json_t *jconfig,
                                      const char *path,
                                      json_t *invalid)
{
    const char *mboxid =
        json_string_value(json_object_get(jconfig, "mailboxId"));
    const mbentry_t *mbentry =
        mboxid ? jmap_mbentry_by_mboxid(req, mboxid) : NULL;
    if (!mbentry || mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL
        || !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS))
    {
        json_array_append_new(invalid, json_sprintf("%s/mailboxId", path));
    }

    const char *prop = json_string_value(json_object_get(jconfig, "property"));
    if (!prop
        || (strcmp(prop, "totalEmails") && strcmp(prop, "unreadEmails")
            && strcmp(prop, "totalThreads") && strcmp(prop, "unreadThreads")))
    {
        json_array_append_new(invalid, json_sprintf("%s/property", path));
    }

    if (!urgency_is_valid(json_object_get(jconfig, "urgency"))) {
        json_array_append_new(invalid, json_sprintf("%s/urgency", path));
    }
}

/* Validate the emailPush and emailCount maps of jpushsub, unless they're
 * unchanged from jold.  Only the user's own account supports emailpush. */
static void validate_emailpush(jmap_req_t *req,
                               json_t *jpushsub,
                               json_t *jold,
                               json_t *invalid)
{
    for (size_t i = 0; i < sizeof(emailpush_props) / sizeof(*emailpush_props);
         i++)
    {
        const char *pname = emailpush_props[i];
        json_t *jmap = json_object_get(jpushsub, pname);

        if (!JNOTNULL(jmap)
            || (jold && json_equal(jmap, json_object_get(jold, pname))))
        {
            continue;
        }

        size_t ninvalid = json_array_size(invalid);

        if (!json_is_object(jmap)) {
            json_array_append_new(invalid, json_string(pname));
            continue;
        }

        const char *accountid;
        json_t *jconfig;
        json_object_foreach (jmap, accountid, jconfig) {
            char *enc = jmap_pointer_encode(accountid);
            char *path = strconcat(pname, "/", enc, (char *) NULL);

            if (strcmp(accountid, req->userid) || !json_is_object(jconfig)) {
                json_array_append_new(invalid, json_string(path));
            }
            else if (i == 0) {
                validate_emailpushconfig(req, jconfig, path, invalid);
            }
            else {
                validate_emailcountconfig(req, jconfig, path, invalid);
            }

            free(path);
            free(enc);
        }

        /* the pushes carry user data, so they MUST be encrypted */
        bool need_keys = !JNOTNULL(json_object_get(jpushsub, "keys"));
        if (need_keys) {
            json_array_append_new(invalid, json_string("keys"));
        }
        if (need_keys || json_array_size(invalid) > ninvalid) {
            json_array_append_new(invalid, json_string(pname));
        }
    }
}

/* jmap_set_parse() has already rejected a client-set id
 * and reported a missing deviceClientId or url */
static const char *set_create(jmap_req_t *req,
                              const char *creation_id,
                              json_t *jpushsub,
                              struct mailbox *mailbox,
                              struct jmap_set *set)
{
    json_t *arg, *invalid = json_array(), *err = NULL;
    json_t *new_jexpires = NULL;
    const char *id = NULL;

    if (!json_is_string(json_object_get(jpushsub, "deviceClientId"))) {
        json_array_append_new(invalid, json_string("deviceClientId"));
    }

    arg = json_object_get(jpushsub, "url");
    if (!json_is_string(arg)
        || strncasecmp(json_string_value(arg), "https://", 8)
        || !json_string_value(arg)[8])
    {
        json_array_append_new(invalid, json_string("url"));
    }

    arg = json_object_get(jpushsub, "keys");
    if (JNOTNULL(arg)) {
        if (!json_is_object(arg)) {
            json_array_append_new(invalid, json_string("keys"));
        }
        else {
            if (!json_is_string(json_object_get(arg, "p256dh"))) {
                json_array_append_new(invalid, json_string("keys/p256dh"));
            }
            if (!json_is_string(json_object_get(arg, "auth"))) {
                json_array_append_new(invalid, json_string("keys/auth"));
            }
        }
    }

    /* MUST be null or omitted on create */
    if (JNOTNULL(json_object_get(jpushsub, "verificationCode"))) {
        json_array_append_new(invalid, json_string("verificationCode"));
    }

    arg = json_object_get(jpushsub, "expires");
    if (JNOTNULL(arg) && !json_is_utcdate(arg)) {
        json_array_append_new(invalid, json_string("expires"));
    }

    validate_types(json_object_get(jpushsub, "types"), invalid);
    validate_emailpush(req, jpushsub, NULL, invalid);

    if (json_array_size(invalid)) {
        err = json_pack("{s:s, s:O}",
                        "type",
                        "invalidProperties",
                        "properties",
                        invalid);
        goto done;
    }

    json_object_set_new(jpushsub, "id", json_string(makeuuid()));
    id = json_string_value(json_object_get(jpushsub, "id"));
    json_object_set_new(jpushsub, "verificationCode", json_string(makeuuid()));
    if (!json_object_get(jpushsub, "keys")) {
        json_object_set_new(jpushsub, "keys", json_null());
    }

    int r = store_pushsub(mailbox, id, jpushsub, false, &new_jexpires);
    if (r) {
        err = jmap_server_error(r);
        goto done;
    }

    /* Report subscription as created, with server-set properties */
    json_object_set_new(
        set->created,
        creation_id,
        json_pack("{s:s s:O*}", "id", id, "expires", new_jexpires));

    /* The notification service sends the PushVerification */
    struct mboxevent *event = mboxevent_new(EVENT_PUSHSUB_CREATED);
    char *userid = mboxname_to_userid(mailbox_name(mailbox));

    FILL_STRING_PARAM(event, EVENT_PUSHSUB_USERID, userid);
    FILL_JSON_PARAM(event, EVENT_PUSHSUB_CONTENT, json_copy(jpushsub));

    mboxevent_notify(&event);
    mboxevent_free(&event);

done:
    if (err) {
        json_object_set_new(set->not_created, creation_id, err);
        id = NULL;
    }
    json_decref(invalid);
    json_decref(new_jexpires);

    return id;
}

/* readonly holds the patch's immutable properties, as jmap_set_parse()
 * collected them */
static void set_update(jmap_req_t *req,
                       const char *id,
                       json_t *jpatch,
                       json_t *readonly,
                       struct mailbox *mailbox,
                       struct pushsub_db *db,
                       struct jmap_set *set)
{
    json_t *invalid = json_array(), *err = NULL;
    json_t *jold = NULL, *jnew = NULL, *new_jexpires = NULL, *jval;
    struct pushsub_data *psdata = NULL;
    struct index_record record;

    int r = pushsubdb_lookup_id(db, id, &psdata, 0);
    if (r == CYRUSDB_NOTFOUND || (!r && psdata->expires <= time(NULL))) {
        err = json_pack("{s:s}", "type", "notFound");
        r = 0;
        goto done;
    }
    if (r || !(jold = json_loads(psdata->subscription, 0, NULL))) {
        r = IMAP_INTERNAL;
        goto done;
    }

    r = mailbox_find_index_record(mailbox, psdata->imap_uid, &record);
    if (r) {
        xsyslog_ev(LOG_ERR, "jmap.pushsub.read.failed",
                   lf_mailbox(mailbox),
                   lf_u("msg.imapuid", psdata->imap_uid),
                   lf_err("error", r));
        goto done;
    }

    if (readonly && (err = jmap_set_check_readonly(readonly, jold))) {
        goto done;
    }

    jnew = jmap_patchobject_apply(jold, jpatch, invalid, 0);
    if (!jnew) {
        goto done;
    }

    bool was_verified = record.system_flags & FLAG_FLAGGED;
    bool verified = was_verified;

    jval = json_object_get(jpatch, "verificationCode");
    if (jval) {
        if (json_equal(jval, json_object_get(jold, "verificationCode"))) {
            verified = true;
        }
        else {
            json_array_append_new(invalid, json_string("verificationCode"));
        }
    }

    jval = json_object_get(jnew, "expires");
    if (JNOTNULL(jval) && !json_is_utcdate(jval)) {
        json_array_append_new(invalid, json_string("expires"));
    }

    validate_types(json_object_get(jnew, "types"), invalid);
    validate_emailpush(req, jnew, jold, invalid);

    if (json_array_size(invalid)) {
        goto done;
    }

    if (!json_equal(jold, jnew)) {
        /* Replace the subscription with a new message */
        r = store_pushsub(mailbox, id, jnew, verified, &new_jexpires);
        if (!r) {
            record.internal_flags |= FLAG_INTERNAL_EXPUNGED;

            int r1 = mailbox_rewrite_index_record(mailbox, &record);
            if (r1) {
                xsyslog_ev(LOG_ERR, "jmap.pushsub.expunge.failed",
                           lf_mailbox(mailbox),
                           lf_msgrecord(&record),
                           lf_err("error", r1));
            }
        }
    }
    else if (verified && !was_verified) {
        record.system_flags |= FLAG_FLAGGED;

        r = mailbox_rewrite_index_record(mailbox, &record);
        if (r) {
            xsyslog_ev(LOG_ERR, "jmap.pushsub.verify.failed",
                       lf_mailbox(mailbox),
                       lf_msgrecord(&record),
                       lf_err("error", r));
        }
    }

    if (!r) {
        /* Report subscription as updated, with server-set properties */
        json_object_set_new(set->updated,
                            id,
                            !new_jexpires
                                ? json_null()
                                : json_pack("{s:O}", "expires", new_jexpires));
    }

done:
    if (!err && json_array_size(invalid)) {
        err = json_pack("{s:s, s:O}",
                        "type",
                        "invalidProperties",
                        "properties",
                        invalid);
    }
    if (!err && r) {
        err = jmap_server_error(r);
    }
    if (err) {
        json_object_set_new(set->not_updated, id, err);
    }
    json_decref(invalid);
    json_decref(jold);
    json_decref(jnew);
    json_decref(new_jexpires);
}

static void set_destroy(const char *id,
                        struct mailbox *mailbox,
                        struct pushsub_db *db,
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
            xsyslog_ev(LOG_ERR, "jmap.pushsub.expunge.failed",
                       lf_mailbox(mailbox),
                       lf_u("msg.imapuid", psdata->imap_uid),
                       lf_err("error", r));
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

    /* Parse arguments */
    jmap_set_parse(req, &parser, &pushsub_props, NULL, NULL, &set, &jerr);
    if ((accountid = json_object_get(req->args, "accountId"))
        || set.if_in_state)
    {
        if (accountid) {
            jmap_parser_invalid(&parser, "accountId");
        }
        else if (set.if_in_state) {
            jmap_parser_invalid(&parser, "ifInState");
        }
        if (jerr) {
            json_decref(jerr);
        }
        jerr = json_pack("{s:s s:O}",
                         "type",
                         "invalidArguments",
                         "arguments",
                         parser.invalid);
    }
    if (jerr) {
        goto done;
    }

    r = pushsub_ensure_folder(req->accountid, &mailbox);
    if (r) {
        goto done;
    }

    db = pushsubdb_open_userid(req->accountid);
    if (!db) {
        r = IMAP_INTERNAL;
        goto done;
    }

    /* create */
    const char *creation_id, *id;
    json_t *val;
    json_object_foreach (set.create, creation_id, val) {
        id = set_create(req, creation_id, val, mailbox, &set);
        if (id) {
            /* Register creation id */
            jmap_add_id(req, creation_id, id);
        }
    }

    /* update */
    json_object_foreach (set.update, id, val) {
        set_update(req,
                   id,
                   val,
                   json_object_get(set.update_readonly, id),
                   mailbox,
                   db,
                   &set);
    }

    /* destroy */
    size_t i;
    json_array_foreach (set.destroy, i, val) {
        id = json_string_value(val);

        set_destroy(id, mailbox, db, &set);
    }

    /* Build response */
    json_t *res = jmap_set_reply(&set);
    json_object_del(res, "oldState");
    json_object_del(res, "newState");
    req->accountid = NULL; // suppress inclusion of 'accountId'
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

HIDDEN void jmap_emailpush_capabilities(json_t *account_capabilities)
{
    if (!config_getswitch(IMAPOPT_JMAP_EMAILPUSH)) {
        return;
    }

    /* the mail capability requires all of Email/query's filter conditions
     * and every count property */
    json_object_set_new(account_capabilities,
                        JMAP_URN_EMAILPUSH,
                        json_pack("{s:n s:n s:n}",
                                  "filterConditions",
                                  "maxFilterDepth",
                                  "countProperties"));
}
