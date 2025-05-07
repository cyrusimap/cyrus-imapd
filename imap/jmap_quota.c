/* jmap_quota.c -- Routines for handling JMAP Quota requests
 *
 * Copyright (c) 1994-2024 Carnegie Mellon University.  All rights reserved.
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

#include <syslog.h>

#include "cyr_qsort_r.h"
#include "http_jmap.h"
#include "jmap_api.h"
#include "sieve_db.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"
#include "imap/jmap_err.h"


static int jmap_legacy_quota_get(jmap_req_t *req);
static int jmap_quota_get(jmap_req_t *req);
static int jmap_quota_changes(jmap_req_t *req);
static int jmap_quota_query(jmap_req_t *req);

// clang-format off
static jmap_method_t jmap_quota_methods_standard[] = {
    {
        "Quota/get",
        JMAP_URN_QUOTA,
        &jmap_quota_get,
        JMAP_NEED_CSTATE
    },
    {
        "Quota/changes",
        JMAP_URN_QUOTA,
        &jmap_quota_changes,
        JMAP_NEED_CSTATE
    },
    {
        "Quota/query",
        JMAP_URN_QUOTA,
        &jmap_quota_query,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};
// clang-format on

// clang-format off
static jmap_method_t jmap_quota_methods_nonstandard[] = {
    {
        "Quota/get",
        JMAP_QUOTA_EXTENSION,
        &jmap_legacy_quota_get,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};
// clang-format on

HIDDEN void jmap_quota_init(jmap_settings_t *settings)
{
    json_object_set_new(settings->server_capabilities,
                        JMAP_URN_QUOTA, json_object());

    jmap_add_methods(jmap_quota_methods_standard, settings);

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(settings->server_capabilities,
                JMAP_QUOTA_EXTENSION, json_object());

        jmap_add_methods(jmap_quota_methods_nonstandard, settings);
    }
}

HIDDEN void jmap_quota_capabilities(json_t *account_capabilities)
{
    json_object_set_new(account_capabilities, JMAP_URN_QUOTA, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities,
                JMAP_QUOTA_EXTENSION, json_object());
    }
}

/* Legacy Quota/get method */
// clang-format off
static const jmap_property_t legacy_quota_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "used",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "total",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    { NULL, NULL, 0 }
};
// clang-format on

static int jmap_legacy_quota_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    char *inboxname = mboxname_user_mbox(req->accountid, NULL);

    /* Parse request */
    jmap_get_parse(req, &parser, legacy_quota_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
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
        int r = quota_read_withconversations(&quota);
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

/*
 * RFC 9425 methods
 */
#define JMAP_TYPE_EMAIL            (1<<0)
#define JMAP_TYPE_MAILBOX          (1<<1)
#define JMAP_TYPE_EMAILSUBMISSION  (1<<2)
#define JMAP_TYPE_VACATIONRESPONSE (1<<3)
#define JMAP_TYPE_SIEVESCRIPT      (1<<4)
#define JMAP_TYPE_CALENDAR         (1<<5)
#define JMAP_TYPE_CALENDAREVENT    (1<<6)
#define JMAP_TYPE_ADDRESSBOOK      (1<<7)
#define JMAP_TYPE_CONTACT          (1<<8)
#define JMAP_TYPE_CONTACTGROUP     (1<<9)

static const struct jtype_t {
    unsigned long bit;
    const char *name;

} jtypes[] = {
    { JMAP_TYPE_EMAIL,            "Email"            },
    { JMAP_TYPE_MAILBOX,          "Mailbox"          },
    { JMAP_TYPE_EMAILSUBMISSION,  "EmailSubmission"  },
    { JMAP_TYPE_VACATIONRESPONSE, "VacationResponse" },
    { JMAP_TYPE_SIEVESCRIPT,      "SieveScript"      },
    { JMAP_TYPE_CALENDAR,         "Calendar"         },
    { JMAP_TYPE_CALENDAREVENT,    "CalendarEvent"    },
    { JMAP_TYPE_ADDRESSBOOK,      "AddressBook"      },
    { JMAP_TYPE_CONTACT,          "Contact"          },
    { JMAP_TYPE_CONTACTGROUP,     "ContactGroup"     },
    { 0,                          NULL               }
};

static const struct jquota_type_t {
    const char idkey;
    const char *junits;

} jquota_types[QUOTA_NUMRESOURCES] = {
    { 'S', "octets" },
    { 'M', "count"  },
    {  0,  "octets" },
    { 'F', "count"  }
};

struct jquota_root_t {
    char *id;
    const char *name;
    const char *junits;
    quota_t used;
    quota_t limit;
    modseq_t modseq;
    unsigned long type_mask;
};

struct qrock_t {
    jmap_req_t *req;
    char *inboxname;
    struct jquota_root_t *roots[QUOTA_NUMRESOURCES];
    struct jquota_root_t *sieve_count;
    hash_table quotas;
};

static int fetch_quotas_cb(struct quota *q, void *rock)
{
    struct qrock_t *qrock = rock;
    unsigned long type_masks[QUOTA_NUMRESOURCES] = { 0 };
    enum quota_resource qres;
    struct buf buf = BUF_INITIALIZER;
    mbentry_t *mbentry = NULL;
    const char *name = NULL;
    char *id = NULL;

    mboxlist_lookup(q->root, &mbentry, NULL);
    if (!mbentry) return 0;

    /* Filter out unsupported quotas */
    switch (mbtype_isa(mbentry->mbtype)) {
    case MBTYPE_EMAIL:
        if (!jmap_is_using(qrock->req, JMAP_URN_MAIL)) goto done;

        /* We can only deal with INBOX */
        if (strcmp(mbentry->name, qrock->inboxname)) goto done;

        name = "root";
        type_masks[QUOTA_STORAGE]    |= JMAP_TYPE_EMAIL;
        type_masks[QUOTA_MESSAGE]    |= JMAP_TYPE_EMAIL;
        type_masks[QUOTA_NUMFOLDERS] |= JMAP_TYPE_MAILBOX;

        /* Add all other requests types
           and remove them if we find a type-specific quotaroot */
        if (jmap_is_using(qrock->req, JMAP_URN_SUBMISSION)) {
            type_masks[QUOTA_STORAGE] |= JMAP_TYPE_EMAILSUBMISSION;
            type_masks[QUOTA_MESSAGE] |= JMAP_TYPE_EMAILSUBMISSION;
        }
        if (jmap_is_using(qrock->req, JMAP_URN_VACATION)) {
            type_masks[QUOTA_STORAGE] |= JMAP_TYPE_VACATIONRESPONSE;
        }
        if (jmap_is_using(qrock->req, JMAP_URN_SIEVE)) {
            type_masks[QUOTA_STORAGE] |= JMAP_TYPE_SIEVESCRIPT;
        }
        if (jmap_is_using(qrock->req, JMAP_URN_CALENDARS)) {
            type_masks[QUOTA_STORAGE]    |= JMAP_TYPE_CALENDAREVENT;
            type_masks[QUOTA_MESSAGE]    |= JMAP_TYPE_CALENDAREVENT;
            type_masks[QUOTA_NUMFOLDERS] |= JMAP_TYPE_CALENDAR;
        }
        if (jmap_is_using(qrock->req, JMAP_CONTACTS_EXTENSION)) {
            type_masks[QUOTA_STORAGE] |=
                JMAP_TYPE_CONTACT | JMAP_TYPE_CONTACTGROUP;
            type_masks[QUOTA_MESSAGE] |=
                JMAP_TYPE_CONTACT | JMAP_TYPE_CONTACTGROUP;
            type_masks[QUOTA_NUMFOLDERS] |= JMAP_TYPE_ADDRESSBOOK;
        }
        break;

    case MBTYPE_JMAPSUBMIT:
        if (!jmap_is_using(qrock->req, JMAP_URN_MAIL)) goto done;

        name = "submission";
        type_masks[QUOTA_STORAGE] |= JMAP_TYPE_EMAILSUBMISSION;
        type_masks[QUOTA_MESSAGE] |= JMAP_TYPE_EMAILSUBMISSION;
        break;

    case MBTYPE_SIEVE:
        if (!jmap_is_using(qrock->req, JMAP_URN_VACATION) &&
            !jmap_is_using(qrock->req, JMAP_URN_SIEVE)) goto done;

        name = "sieve";
        if (jmap_is_using(qrock->req, JMAP_URN_VACATION)) {
            type_masks[QUOTA_STORAGE] |= JMAP_TYPE_VACATIONRESPONSE;
        }
        if (jmap_is_using(qrock->req, JMAP_URN_SIEVE)) {
            type_masks[QUOTA_STORAGE] |= JMAP_TYPE_SIEVESCRIPT;
            type_masks[QUOTA_MESSAGE] |= JMAP_TYPE_SIEVESCRIPT;
        }
        break;

    case MBTYPE_CALENDAR:
        /* Assuming this is calendar-home-set */
        if (!jmap_is_using(qrock->req, JMAP_URN_CALENDARS)) goto done;

        name = "calendars";
        type_masks[QUOTA_STORAGE]    |= JMAP_TYPE_CALENDAREVENT;
        type_masks[QUOTA_MESSAGE]    |= JMAP_TYPE_CALENDAREVENT;
        type_masks[QUOTA_NUMFOLDERS] |= JMAP_TYPE_CALENDAR;
        break;

    case MBTYPE_ADDRESSBOOK:
        /* Assuming this is addressbook-home-set */
        if (!jmap_is_using(qrock->req, JMAP_CONTACTS_EXTENSION)) goto done;

        name = "addressbooks";
        type_masks[QUOTA_STORAGE] |= JMAP_TYPE_CONTACT | JMAP_TYPE_CONTACTGROUP;
        type_masks[QUOTA_MESSAGE] |= JMAP_TYPE_CONTACT | JMAP_TYPE_CONTACTGROUP;
        type_masks[QUOTA_NUMFOLDERS] |= JMAP_TYPE_ADDRESSBOOK;
        break;
    }

    buf_printf(&buf, " %s", mbentry->uniqueid);
    id = buf_release(&buf);

    for (qres = 0; qres < QUOTA_NUMRESOURCES; qres++) {
        if (!type_masks[qres]) continue;
        if (q->limits[qres] == QUOTA_UNLIMITED) continue;

        struct jquota_root_t *jroot = xzmalloc(sizeof(struct jquota_root_t));

        *id = jquota_types[qres].idkey;
        hash_insert(id, jroot, &qrock->quotas);

        jroot->name = name;
        jroot->modseq = q->modseq;
        jroot->type_mask = type_masks[qres];
        jroot->junits = jquota_types[qres].junits;
        jroot->used = q->useds[qres];
        jroot->limit = q->limits[qres] * quota_units[qres];

        if (mbtype_isa(mbentry->mbtype) == MBTYPE_EMAIL) {
            /* Keep track of root quotas */
            qrock->roots[qres] = jroot;
        }
        else {
            if (qres == QUOTA_MESSAGE &&
                mbtype_isa(mbentry->mbtype) == MBTYPE_SIEVE) {
                /* Keep track of sieve count quota */
                qrock->sieve_count = jroot;
            }
            if (qrock->roots[qres]) {
                /* Remove these types from the root quota */
                qrock->roots[qres]->type_mask &= ~type_masks[qres];
            }
        }
    }

  done:
    mboxlist_entry_free(&mbentry);
    buf_free(&buf);
    free(id);

    return 0;
}

/* Quota/get method */
// clang-format off
static const jmap_property_t quota_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "resourceType",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "used",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "hardLimit",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "warnLimit",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "softLimit",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "scope",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "name",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "description",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "types",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    { NULL, NULL, 0 }
};
// clang-format on

static void fetch_quotas(struct qrock_t *qrock)
{
    int maxscripts = config_getint(IMAPOPT_SIEVE_MAXSCRIPTS);

    quota_foreach(qrock->inboxname,
                  &fetch_quotas_cb, qrock, NULL, QUOTA_USE_CONV);

    if (maxscripts) {
        /* Add sieve count quota limit */
        if (!qrock->sieve_count) {
            char *sieve_mbox = sieve_mboxname(qrock->req->accountid);
            mbentry_t *mbentry = NULL;

            mboxlist_lookup(sieve_mbox, &mbentry, NULL);
            free(sieve_mbox);

            if (mbentry) {
                struct buf id = BUF_INITIALIZER;

                qrock->sieve_count =
                    xzmalloc(sizeof(struct jquota_root_t));

                buf_printf(&id, "%c%s",
                           jquota_types[QUOTA_MESSAGE].idkey, mbentry->uniqueid);
                hash_insert(buf_cstring(&id),
                            qrock->sieve_count, &qrock->quotas);

                qrock->sieve_count->name = "sieve";
                qrock->sieve_count->type_mask = JMAP_TYPE_SIEVESCRIPT;
                qrock->sieve_count->junits = jquota_types[QUOTA_MESSAGE].junits;

                mboxlist_entry_free(&mbentry);
                buf_free(&id);
            }
        }

        if (qrock->sieve_count) {
            /* Get and set script count (used) */
            struct sieve_db *db = sievedb_open_userid(qrock->req->accountid);

            if (db) {
                int used;

                sievedb_count(db, &used);
                sievedb_close(db);
                qrock->sieve_count->used = used;
            }

            /* Set limit */
            qrock->sieve_count->limit = maxscripts;
        }
    }
}

static void getquota(const char *id, void *val, void *rock)
{
    json_t *jquota = json_pack("{s:s}", "id", id);
    struct jquota_root_t *jroot = val;
    struct jmap_get *get = rock;

    if (jmap_wantprop(get->props, "resourceType")) {
        json_object_set_new(jquota,
                            "resourceType",
                            json_string(jroot->junits));
    }

    if (jmap_wantprop(get->props, "used")) {
        json_object_set_new(jquota, "used", json_integer(jroot->used));
    }

    if (jmap_wantprop(get->props, "hardLimit")) {
        json_object_set_new(jquota, "hardLimit", json_integer(jroot->limit));
    }

    if (jmap_wantprop(get->props, "warnLimit")) {
        quota_t limit =
            jroot->limit * (config_getint(IMAPOPT_QUOTAWARNPERCENT) / 100.0);

        json_object_set_new(jquota, "warnLimit", json_integer(limit));
    }

    if (jmap_wantprop(get->props, "softLimit")) {
        json_object_set_new(jquota, "softLimit", json_null());
    }

    if (jmap_wantprop(get->props, "scope")) {
        json_object_set_new(jquota, "scope", json_string("account"));
    }

    if (jmap_wantprop(get->props, "name")) {
        json_object_set_new(jquota, "name", json_string(jroot->name));
    }

    if (jmap_wantprop(get->props, "description")) {
        json_object_set_new(jquota, "description", json_null());
    }

    if (jmap_wantprop(get->props, "types")) {
        json_t *types = json_array();
        const struct jtype_t *jtype;

        for (jtype = jtypes; jtype->name; jtype++) {
            if (jroot->type_mask & jtype->bit) {
                json_array_append_new(types, json_string(jtype->name));
            }
        }

        json_object_set_new(jquota, "types", types);
    }

    json_array_append_new(get->list, jquota);
}

static int jmap_quota_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    struct qrock_t qrock = { req, NULL, { 0 }, NULL, HASH_TABLE_INITIALIZER };

    /* Parse request */
    jmap_get_parse(req, &parser, quota_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    qrock.inboxname = mboxname_user_mbox(req->accountid, NULL);
    construct_hash_table(&qrock.quotas, 20, 0);

    /* Fetch quotaroots for the user */
    fetch_quotas(&qrock);

    /* Does the client request specific responses? */
    if (JNOTNULL(get.ids)) {
        json_t *jval;
        size_t i;

        json_array_foreach(get.ids, i, jval) {
            const char *id = json_string_value(jval);
            struct jquota_root_t *jroot = hash_lookup(id, &qrock.quotas);

            if (!jroot) {
                json_array_append_new(get.not_found, json_string(id));
            }
            else {
                getquota(id, jroot, &get);
            }
        }
    }
    else {
        /* Fetch all quotas */
        hash_enumerate(&qrock.quotas, &getquota, &get);
    }

    /* Build response */
    modseq_t quotamodseq = mboxname_readquotamodseq(qrock.inboxname);
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, quotamodseq);
    get.state = buf_release(&buf);

    jmap_ok(req, jmap_get_reply(&get));

done:
    free_hash_table(&qrock.quotas, &free);
    free(qrock.inboxname);
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

/* Quota/changes method */
static void changes_cb(const char *id, void *val, void *rock)
{
    struct jquota_root_t *jroot = val;
    struct jmap_changes *changes = rock;

    /* XXX  How to differentiate between created/updated/destroyed? */
    if (jroot->modseq > changes->since_modseq) {
        json_array_append_new(changes->updated, json_string(id));
    }
}

static int jmap_quota_changes(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes = JMAP_CHANGES_INITIALIZER;
    struct qrock_t qrock = { req, NULL, { 0 }, NULL, HASH_TABLE_INITIALIZER };

    json_t *err = NULL;
    jmap_changes_parse(req, &parser, 0, NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        return 0;
    }

    qrock.inboxname = mboxname_user_mbox(req->accountid, NULL);
    construct_hash_table(&qrock.quotas, 20, 0);

    /* Fetch quotaroots for the user */
    quota_foreach(qrock.inboxname,
                  &fetch_quotas_cb, &qrock, NULL, QUOTA_USE_CONV);

    hash_enumerate(&qrock.quotas, &changes_cb, &changes);

    /* Build response */
    changes.new_modseq = mboxname_readquotamodseq(qrock.inboxname);

    jmap_ok(req, jmap_changes_reply(&changes));

    free_hash_table(&qrock.quotas, &free);
    free(qrock.inboxname);
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    return 0;
}

static void filter_parse(jmap_req_t *req __attribute__((unused)),
                         struct jmap_parser *parser,
                         json_t *filter,
                         json_t *unsupported __attribute__((unused)),
                         void *rock __attribute__((unused)),
                         json_t **err __attribute__((unused)))
{
    const char *field;
    json_t *arg;

    json_object_foreach(filter, field, arg) {
        if (!strcmp(field, "name")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "scope")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "resourceType")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "type")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else {
            jmap_parser_invalid(parser, field);
        }
    }
}


static int comparator_parse(jmap_req_t *req __attribute__((unused)),
                            struct jmap_comparator *comp,
                            void *rock __attribute__((unused)),
                            json_t **err __attribute__((unused)))
{
    if (comp->collation) {
        return 0;
    }
    if (!strcmp(comp->property, "name") ||
        !strcmp(comp->property, "used")) {
        return 1;
    }
    return 0;
}

typedef struct filter {
    const char *name;
    const char *scope;
    const char *resourceType;
    const char *type;
} filter;

static void *filter_build(json_t *arg)
{
    filter *f = (filter *) xzmalloc(sizeof(struct filter));

    /* name */
    if (JNOTNULL(json_object_get(arg, "name"))) {
        jmap_readprop(arg, "name", 0, NULL, "s", &f->name);
    }

    /* scope */
    if (JNOTNULL(json_object_get(arg, "scope"))) {
        jmap_readprop(arg, "scope", 0, NULL, "s", &f->scope);
    }

    /* resourceType */
    if (JNOTNULL(json_object_get(arg, "resourceType"))) {
        jmap_readprop(arg, "resourceType", 0, NULL, "s", &f->resourceType);
    }

    /* type */
    if (JNOTNULL(json_object_get(arg, "type"))) {
        jmap_readprop(arg, "type", 0, NULL, "s", &f->type);
    }

    return f;
}

/* Match the script in rock against filter. */
static int filter_match(void *vf, void *rock)
{
    filter *f = (filter *) vf;
    struct jquota_root_t *jroot = (struct jquota_root_t *) rock;

    /* name */
    if (f->name && !strstr(jroot->name, f->name)) return 0;

    /* scope */
    if (f->scope && !strstr("account", f->scope)) return 0;

    /* resourceType */
    if (f->resourceType && !strstr(jroot->junits, f->resourceType)) return 0;

    /* type */
    if (f->type) {
        const struct jtype_t *jtype;

        for (jtype = jtypes; jtype->name; jtype++) {
            if ((jroot->type_mask & jtype->bit) && strstr(jtype->name, f->type)) {
                break;
            }
        }
        if (!jtype->name) return 0;
    }

    /* All matched. */
    return 1;
}

typedef struct filter_rock {
    struct jmap_query *query;
    jmap_filter *parsed_filter;
    ptrarray_t matches;
    struct jquota_root_t *anchor;
} filter_rock;

static void filter_cb(const char *id, void *val, void *rock)
{
    struct jquota_root_t *jroot = val;
    struct filter_rock *frock = (struct filter_rock *) rock;
    struct jmap_query *query = frock->query;

    if (query->filter &&
        !jmap_filter_match(frock->parsed_filter, &filter_match, jroot)) {
        return;
    }

    jroot->id = xstrdup(id);

    /* Add record of the match to our array */
    ptrarray_append(&frock->matches, jroot);

    if (query->anchor && !strcmp(query->anchor, jroot->id)) {
        /* Mark record corresponding to anchor */
        frock->anchor = jroot;
    }

    query->total++;
}

enum quota_sort {
    QUOTA_SORT_NONE = 0,
    QUOTA_SORT_NAME,
    QUOTA_SORT_USED,
    QUOTA_SORT_DESC = 0x80 /* bit-flag for descending sort */
};

static int quota_cmp QSORT_R_COMPAR_ARGS(const void *va, const void *vb,
                                         void *rock)
{
    arrayu64_t *sortcrit = (arrayu64_t *) rock;
    struct jquota_root_t *qa = (struct jquota_root_t *) *(void **) va;
    struct jquota_root_t *qb = (struct jquota_root_t *) *(void **) vb;
    size_t i, nsort = arrayu64_size(sortcrit);

    for (i = 0; i < nsort; i++) {
        enum quota_sort sort = arrayu64_nth(sortcrit, i);
        int ret = 0;

        switch (sort & ~QUOTA_SORT_DESC) {
        case QUOTA_SORT_NAME:
            ret = strcmp(qa->name, qb->name);
            break;

        case QUOTA_SORT_USED:
            ret = qa->used - qb->used;
            break;
        }

        if (ret) return (sort & QUOTA_SORT_DESC) ? -ret : ret;
    }

    return 0;
}

static int jmap_quota_query(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;
    jmap_filter *parsed_filter = NULL;
    arrayu64_t sortcrit = ARRAYU64_INITIALIZER;
    struct qrock_t qrock = { req, NULL, { 0 }, NULL, HASH_TABLE_INITIALIZER };
    int r = 0;

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req, &parser, NULL, NULL,
                     filter_parse, NULL, comparator_parse, NULL, &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build filter */
    if (JNOTNULL(query.filter)) {
        parsed_filter = jmap_buildfilter(query.filter, filter_build);
    }

    /* Build sort */
    if (json_array_size(query.sort)) {
        json_t *jval;
        size_t i;
        json_array_foreach(query.sort, i, jval) {
            const char *prop =
              json_string_value(json_object_get(jval, "property"));
            enum quota_sort sort = QUOTA_SORT_NONE;

            if (!strcmp(prop, "name")) {
                sort = QUOTA_SORT_NAME;
            } else if (!strcmp(prop, "used")) {
                sort = QUOTA_SORT_USED;
            }

            if (json_object_get(jval, "isAscending") == json_false()) {
                sort |= QUOTA_SORT_DESC;
            }

            arrayu64_append(&sortcrit, sort);
        }
    }
    qrock.inboxname = mboxname_user_mbox(req->accountid, NULL);
    construct_hash_table(&qrock.quotas, 20, 0);

    /* Fetch quotaroots for the user */
    fetch_quotas(&qrock);

    /* Filter the scripts */
    filter_rock frock = { &query, parsed_filter, PTRARRAY_INITIALIZER, NULL };

    hash_enumerate(&qrock.quotas, &filter_cb, &frock);

    /* Sort results */
    if (arrayu64_size(&sortcrit) && frock.matches.count) {
        cyr_qsort_r(frock.matches.data, frock.matches.count,
                    sizeof(void *), &quota_cmp, &sortcrit);
    }
    arrayu64_fini(&sortcrit);

    /* Process results */
    if (query.anchor) {
        query.position = ptrarray_find(&frock.matches, frock.anchor, 0);
        if (query.position < 0) {
            query.position = query.total;
        }
        else {
            query.position += query.anchor_offset;
        }
    }
    else if (query.position < 0) {
        query.position += query.total;
    }
    if (query.position < 0) query.position = 0;

    size_t i;
    for (i = 0; i < query.total; i++) {
        struct jquota_root_t *match = ptrarray_nth(&frock.matches, i);

        /* Apply position and limit */
        if (i >= (size_t) query.position &&
            (!query.limit || query.limit > json_array_size(query.ids))) {
            /* Add the quota identifier */
            json_array_append_new(query.ids, json_string(match->id));
        }

        free(match->id);
    }
    ptrarray_fini(&frock.matches);

    if (parsed_filter) jmap_filter_free(parsed_filter, &free);

    /* Build response */
    modseq_t quotamodseq = mboxname_readquotamodseq(qrock.inboxname);
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, quotamodseq);
    query.query_state = buf_release(&buf);
    query.result_position = query.position;
    query.can_calculate_changes = 0;
    jmap_ok(req, jmap_query_reply(&query));

done:
    if (r) jmap_error(req, jmap_server_error(r));
    jmap_parser_fini(&parser);
    jmap_query_fini(&query);

    free_hash_table(&qrock.quotas, &free);
    free(qrock.inboxname);

    return 0;
}
