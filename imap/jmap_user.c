/* jmap_user.c -- Routines for handling JMAP user data
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

#include "global.h"
#include "hash.h"
#include "http_jmap.h"
#include "json_support.h"
#include "map.h"
#include "quota.h"
#include "sieve/sieve_interface.h"
#include "user.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int jmap_identity_get(jmap_req_t *req);
static int jmap_quota_get(jmap_req_t *req);
static int jmap_vacation_get(jmap_req_t *req);
static int jmap_vacation_set(jmap_req_t *req);

/*
 * Possibly to be implemented:
 * - Identity/changes
 * - Identity/set
 */

jmap_method_t jmap_user_methods[] = {
    { "Identity/get",         &jmap_identity_get, JMAP_SHARED_CSTATE },
    { "Quota/get",            &jmap_quota_get, JMAP_SHARED_CSTATE },
    { "VacationResponse/get", &jmap_vacation_get, JMAP_SHARED_CSTATE },
    { "VacationResponse/set", &jmap_vacation_set, JMAP_SHARED_CSTATE },
    { NULL,                   NULL, 0}
};


HIDDEN void jmap_user_init(jmap_settings_t *settings)
{
    jmap_method_t *mp;
    for (mp = jmap_user_methods; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    strarray_push(&settings->can_use, JMAP_URN_VACATION);
    strarray_push(&settings->can_use, JMAP_QUOTA_EXTENSION);
}

HIDDEN void jmap_user_capabilities(jmap_settings_t *settings)
{
    json_object_set_new(settings->capabilities,
                        JMAP_URN_VACATION, json_object());
    json_object_set_new(settings->capabilities,
                        JMAP_QUOTA_EXTENSION, json_object());
}


/* Identity/get method */
static const jmap_property_t identity_props[] = {
    { "id",                  JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE },
    { "name",                0 },
    { "email",               JMAP_PROP_IMMUTABLE },
    { "replyTo",             0 },
    { "bcc",                 0 },
    { "textSignature",       0 },
    { "htmlSignature",       0 },
    { "mayDelete",           JMAP_PROP_SERVER_SET },

    /* FM extensions (do ALL of these get through to Cyrus?) */
    { "displayName",         0 },
    { "addBccOnSMTP",        0 },
    { "saveSentToMailboxId", 0 },
    { "saveOnSMTP",          0 },
    { "useForAutoReply",     0 },
    { "isAutoConfigured",    0 },
    { "enableExternalSMTP",  0 },
    { "smtpServer",          0 },
    { "smtpPort",            0 },
    { "smtpSSL",             0 },
    { "smtpUser",            0 },
    { "smtpPassword",        0 },
    { "smtpRemoteService",   0 },
    { "popLinkId",           0 },

    { NULL,            0 }
};

static int jmap_identity_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;

    /* Parse request */
    jmap_get_parse(req->args, &parser, req, identity_props, NULL, NULL,
                   &get, /*allow_null_ids*/1, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    json_t *me = json_pack("{s:s s:s s:s s:b}",
            "id", req->userid,
            "name", "",
            "email", req->userid,
            "mayDelete", 0);
    if (!strchr(req->userid, '@')) {
        json_object_set_new(me, "email", json_string(""));
    }
    if (json_array_size(get.ids)) {
        size_t i;
        json_t *val;
        json_array_foreach(get.ids, i, val) {
            if (strcmp(json_string_value(val), req->userid)) {
                json_array_append(get.not_found, val);
            }
            else {
                json_array_append(get.list, me);
            }
        }
    } else if (!JNOTNULL(get.ids)) {
        json_array_append(get.list, me);
    }
    json_decref(me);

    /* Reply */
    get.state = xstrdup("0");
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}


/* Quota/get method */
static const jmap_property_t quota_props[] = {
    { "id",             JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE },
    { "used",           JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE },
    { "total",          JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE },

    { NULL,             0 }
};

static int jmap_quota_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    char *inboxname = mboxname_user_mbox(req->accountid, NULL);

    /* Parse request */
    jmap_get_parse(req->args, &parser, req, quota_props, NULL, NULL,
                   &get, /*allow_null_ids*/1, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    int want_mail_quota = !get.ids || json_is_null(get.ids);
    size_t i;
    json_t *jval;
    json_array_foreach(get.ids, i, jval) {
        if (strcmp("mail", json_string_value(jval))) {
            json_array_append(get.not_found, jval);
        }
        else want_mail_quota = 1;
    }

    if (want_mail_quota) {
        struct quota quota;
        quota_init(&quota, inboxname);
        int r = quota_read(&quota, NULL, 0);
        if (!r) {
            quota_t total = quota.limits[QUOTA_STORAGE] * quota_units[QUOTA_STORAGE];
            quota_t used = quota.useds[QUOTA_STORAGE];
            json_t *jquota = json_object();
            json_object_set_new(jquota, "id", json_string("mail"));
            json_object_set_new(jquota, "used", json_integer(used));
            json_object_set_new(jquota, "total", json_integer(total));
            json_array_append_new(get.list, jquota);
        }
        else {
            syslog(LOG_ERR, "jmap_quota_get: can't read quota for %s: %s",
                    inboxname, error_message(r));
            json_array_append_new(get.not_found, json_string("mail"));
        }
        quota_free(&quota);
    }


    modseq_t quotamodseq = mboxname_readquotamodseq(inboxname);
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, quotamodseq);
    get.state = buf_release(&buf);

    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    free(inboxname);
    return 0;
}


/* VacationResponse/get method */
static const jmap_property_t vacation_props[] = {
    { "id",             JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE },
    { "isEnabled",      0 },
    { "fromDate",       0 },
    { "toDate",         0 },
    { "subject",        0 },
    { "textBody",       0 },
    { "htmlBody",       0 },

    { NULL,             0 }
};

#define JMAP_VACATION_SCRIPT "jmap_vacation"

static int jmap_vacation_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL, *vacation = NULL;
    char *scriptname = NULL;
    int fd;

    /* Parse request */
    jmap_get_parse(req->args, &parser, req, vacation_props, NULL, NULL,
                   &get, /*allow_null_ids*/1, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    scriptname = strconcat(user_sieve_path(req->accountid),
                           "/" JMAP_VACATION_SCRIPT ".script", NULL);
    fd = open(scriptname, 0);
    if (fd != -1) {
        const char *base = NULL, *json;
        size_t len = 0;
        json_error_t jerr;

        map_refresh(fd, 1, &base, &len, MAP_UNKNOWN_LEN, scriptname, NULL);
        json = strchr(base, '{');
        if (json) {
            vacation = json_loadb(json, len - (json - base),
                                  JSON_DISABLE_EOF_CHECK, &jerr);
        }
        map_free(&base, &len);
        close(fd);
    }

    if (!vacation) {
        /* Build empty response */
        vacation = json_pack("{s:s s:b s:n s:n s:n s:n s:n}",
                             "id", "singleton",
                             "isEnabled", 0,
                             "fromDate", "toDate", "subject",
                             "textBody", "htmlBody");
    }

    json_array_append_new(get.list, vacation);

    /* Reply */
    get.state = xstrdup("0");
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    free(scriptname);
    return 0;
}

static int jmap_vacation_set(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    json_t *err = NULL;
    int r = 0;

    /* Parse arguments */
    jmap_set_parse(req->args, &parser, NULL, NULL, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
#if 0
    if (set.if_in_state) {
        /* TODO rewrite state function to use char* not json_t* */
        json_t *jstate = json_string(set.if_in_state);
        if (jmap_cmpstate(req, jstate, MBTYPE_CALENDAR)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            json_decref(jstate);
            goto done;
        }
        json_decref(jstate);
        set.old_state = xstrdup(set.if_in_state);
    }
    else {
        json_t *jstate = jmap_getstate(req, MBTYPE_CALENDAR, /*refresh*/0);
        set.old_state = xstrdup(json_string_value(jstate));
        json_decref(jstate);
    }
#endif

    /* create */
    const char *key;
    json_t *arg;
    json_object_foreach(set.create, key, arg) {
        json_t *err= json_pack("{s:s}", "type", "singleton");
        json_object_set_new(set.not_created, key, err);
    }


    /* update */
    const char *uid;
    json_object_foreach(set.update, uid, arg) {

        /* Validate uid */
        if (!uid) {
            continue;
        }
        if (strcmp(uid, "singleton")) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(set.not_updated, uid, err);
            continue;
        }

        /* Parse and validate properties. */
        json_t *prop, *invalid = json_pack("[]");
        int isEnabled = -1;
        const char *fromDate = NULL;
        const char *toDate = NULL;
        const char *subject = NULL;
        const char *textBody = NULL;
        const char *htmlBody = NULL;

        jmap_readprop(arg, "isEnabled", 1, invalid, "b", &isEnabled);

        prop = json_object_get(arg, "fromDate");
        if (json_is_string(prop))
            fromDate = json_string_value(prop);
        else if (JNOTNULL(prop))
            json_array_append_new(invalid, json_string("fromDate"));

        prop = json_object_get(arg, "toDate");
        if (json_is_string(prop))
            toDate = json_string_value(prop);
        else if (JNOTNULL(prop))
            json_array_append_new(invalid, json_string("toDate"));

        prop = json_object_get(arg, "subject");
        if (json_is_string(prop))
            subject = json_string_value(prop);
        else if (JNOTNULL(prop))
            json_array_append_new(invalid, json_string("subject"));

        prop = json_object_get(arg, "textBody");
        if (json_is_string(prop))
            textBody = json_string_value(prop);
        else if (JNOTNULL(prop))
            json_array_append_new(invalid, json_string("textBody"));

        prop = json_object_get(arg, "htmlBody");
        if (json_is_string(prop))
            htmlBody = json_string_value(prop);
        else if (JNOTNULL(prop))
            json_array_append_new(invalid, json_string("htmlBody"));

        /* Report any property errors and bail out. */
        if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s, s:o}",
                                    "type", "invalidProperties",
                                    "properties", invalid);
            json_object_set_new(set.not_updated, uid, err);
            continue;
        }
        json_decref(invalid);

        const char *sievedir = user_sieve_path(req->accountid);
        char *path = strconcat(sievedir,
                               "/" JMAP_VACATION_SCRIPT ".script", NULL);
        FILE *fp = fopen(path, "w");
        if (!fp && errno == ENOENT && !cyrus_mkdir(path, 0755)) {
            fp = fopen(path, "w");
        }
        if (!fp) {
            json_t *err = json_pack("{s:s s:s}", "type", "serverError",
                                    "description", "Failed to open script file");
            json_object_set_new(set.not_updated, uid, err);
            free(path);
            r = 0;
            continue;
        }

        /* Dump VacationResponse JMAP object in a comment */
        fputs("/* Generated by Cyrus JMAP - DO NOT EDIT\r\n\r\n", fp);
        json_dumpf(arg, fp, JSON_INDENT(2));
        fputs("\r\n*/\r\n\r\n", fp);

        /* Create actual sieve rule */
        /* Add required extensions */
        fputs("require [ \"vacation\"", fp);
        if (fromDate || toDate) fputs(", \"date\", \"relational\"", fp);
        fputs(" ];\r\n\r\n", fp);

        /* Add enabled and date tests */
        fprintf(fp, "if allof (%s", isEnabled ? "true" : "false");
        if (fromDate) {
            fprintf(fp, ",\r\n%10scurrentdate :zone \"+0000\""
                    " :value \"ge\" \"iso8601\" \"%s\"", "", fromDate);
        }
        if (toDate) {
            fprintf(fp, ",\r\n%10scurrentdate :zone \"+0000\""
                    " :value \"lt\" \"iso8601\" \"%s\"", "", toDate);
        }
        fputs(")\r\n{ ", fp);

        /* Add vacation action */
        fputs("vacation", fp);
        if (subject) fprintf(fp, " :subject \"%s\"", subject);
        if (htmlBody) {
            const char *boundary = makeuuid();
            char *text = NULL;

            if (!textBody) textBody = text = charset_extract_plain(htmlBody);

            fputs(" :mime text:\r\n", fp);
            fprintf(fp, "Content-Type: multipart/alternative; boundary=%s\r\n"
                    "\r\n--%s\r\n", boundary, boundary);
            fputs("Content-Type: text/plain; charset=utf-8\r\n\r\n", fp);
            fprintf(fp, "%s\r\n\r\n--%s\r\n", textBody, boundary);
            fputs("Content-Type: text/html; charset=utf-8\r\n\r\n", fp);
            fprintf(fp, "%s\r\n\r\n--%s--\r\n", htmlBody, boundary);
            free(text);
        }
        else {
            fprintf(fp, " text:\r\n%s", textBody ? textBody : "On vacation");
        }
        fputs(".\r\n;\r\n}\r\n", fp);

        fflush(fp);
        fclose(fp);

        r = sieve_rebuild(path, NULL, 1/*force*/, NULL);

        if (r) {
            json_t *err = json_pack("{s:s s:s}", "type", "serverError",
                                    "description", "Failed to compile bytecode");
            json_object_set_new(set.not_updated, uid, err);
            r = 0;
        }
        else {
            /* Report vacation as updated. */
            json_object_set_new(set.updated, uid, json_null());
        }

        free(path);
    }


    /* destroy */
    size_t index;
    json_t *juid;

    json_array_foreach(set.destroy, index, juid) {
        json_t *err= json_pack("{s:s}", "type", "singleton");
        json_object_set_new(set.not_destroyed, json_string_value(juid), err);
    }

#if 0
    // TODO refactor jmap_getstate to return a string, once
    // all code has been migrated to the new JMAP parser.
    json_t *jstate = jmap_getstate(req, MBTYPE_CALENDAR, /*refresh*/1);
    set.new_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
#endif

    jmap_ok(req, jmap_set_reply(&set));

done:
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    return r;
}
