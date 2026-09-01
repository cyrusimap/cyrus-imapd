/* jmap_admin.c - Routines for handling JMAP admin tasks */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>

#include "http_jmap.h"
#include "user.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"
#include "imap/jmap_props/account.h"

static int jmap_account_create(jmap_req_t *req);

// clang-format off
static jmap_method_t jmap_admin_methods_nonstandard[] = {
    {
        "Account/create",
        JMAP_ADMIN_EXTENSION,
        &jmap_account_create,
        JMAP_NO_USERLOCK,
    },
    { NULL, NULL, NULL, 0}
};
// clang-format on

HIDDEN void jmap_admin_init(jmap_settings_t *settings)
{
    json_object_set_new(settings->server_capabilities,
            JMAP_ADMIN_EXTENSION, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        jmap_add_methods(jmap_admin_methods_nonstandard, settings);
    }
}

HIDDEN void jmap_admin_capabilities(json_t *account_capabilities)
{
    if (!httpd_userisadmin) return;

    json_object_set_new(account_capabilities, JMAP_ADMIN_EXTENSION, json_object());
}

struct account_props {
    const char *email;
    bool isarchive;
    bool compactids;
    json_t *quotas;
    json_t *mailboxes;
    const char *def_calname;
    const char *def_abookname;
};

static void account_readprops(jmap_req_t *req __attribute__((unused)),
                              struct jmap_parser *parser,
                              struct account_props *props,
                              json_t *arg)
{
    memset(props, 0, sizeof(struct account_props));

    json_t *jprop = json_object_get(arg, "email");
    if (json_is_string(jprop)) {
        props->email = json_string_value(jprop);
        if (strnlen(props->email, 256) == 256) {
            jmap_parser_invalid(parser, "email");
        }
    }
    else {
        jmap_parser_invalid(parser, "email");
    }

    jprop = json_object_get(arg, "kind");
    if (json_is_string(jprop)) {
        const char *kind = json_string_value(jprop);

        if (!strcmp(kind, "archive")) {
            props->isarchive = true;
        }
        else if (strcmp(kind, "regular")) {
            jmap_parser_invalid(parser, "kind");
        }
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "kind");
    }

    jprop = json_object_get(arg, "compactIds");
    if (json_is_boolean(jprop)) {
        props->compactids = json_boolean_value(jprop);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "compactIds");
    }

    jprop = json_object_get(arg, "quotas");
    if (json_object_size(jprop)) {
        const char *key;
        json_t *jval;

        jmap_parser_push(parser, "quotas");
        json_object_foreach(jprop, key, jval) {
            int res = quota_name_to_resource(key);
            if (res < 0 || !json_is_integer(jval)) {
                jmap_parser_invalid(parser, key);
            }
        }
        jmap_parser_pop(parser);
        props->quotas = jprop;
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "quotas");
    }

    jprop = json_object_get(arg, "mailboxes");
    if (json_array_size(jprop)) {
        size_t index;
        json_t *jmailbox;
        json_array_foreach(jprop, index, jmailbox) {
            jmap_parser_push_index(parser, "mailboxes", index, NULL);

            if (json_object_size(jmailbox)) {
                const char *name = NULL;
                const char *role = NULL;
                const char *key;
                json_t *jval;

                json_object_foreach(jmailbox, key, jval) {
                    if (!strcmp(key, "name")) {
                        name = json_string_value(jval);
                    }
                    else if (!strcmp(key, "role")) {
                        role = json_string_value(jval);
                    }
                    else {
                        jmap_parser_invalid(parser, key);
                    }
                }

                if (!name) jmap_parser_invalid(parser, "name");
                if (!role) jmap_parser_invalid(parser, "role");
            }
            else if (JNOTNULL(jmailbox)) {
                jmap_parser_invalid(parser, NULL);
            }
            jmap_parser_pop(parser);
        }

        props->mailboxes = jprop;
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "mailboxes");
    }

    jprop = json_object_get(arg, "defaultCalendarName");
    if (json_is_string(jprop)) {
        props->def_calname = json_string_value(jprop);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "defaultCalendarName");
    }

    jprop = json_object_get(arg, "defaultAddressBookName");
    if (json_is_string(jprop)) {
        props->def_abookname = json_string_value(jprop);
    }
    else if (jprop) {
        jmap_parser_invalid(parser, "defaultAddressBookName");
    }
}

static void account_create(struct jmap_req *req,
                           const char *creation_id,
                           json_t *arg,
                           json_t **resp,
                           json_t **err)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct account_props props;
    user_nslock_t *user_nslock = NULL;
    struct mailbox *mailbox = NULL;
    mbname_t *mbname = NULL;
    int r = 0;

    /* Parse and validate properties. */
    account_readprops(req, &parser, &props, arg);
    if (json_array_size(parser.invalid)) {
        *err = json_pack("{s:s, s:O}",
                         "type", "invalidProperties",
                         "properties", parser.invalid);
        goto done;
    }

    user_nslock = user_nslock_lock_w(props.email);
    mbname = mbname_from_userid(props.email);

    mbentry_t mbentry = { .name = (char *) mbname_intname(mbname) };
    r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
                               1/*isadmin*/, req->userid, req->authstate,
                               0/*flags*/, &mailbox);
    if (r) {
        xsyslog(LOG_ERR, "failed to create mailbox",
                "mboxname=<%s> err=<%s>", mbentry.name, error_message(r));
        goto done;
    }

    if (props.compactids) {
        struct conversations_state *cstate = mailbox_get_cstate(mailbox);
        r = conversations_enable_compactids(cstate, 1);
        if (r) {
            xsyslog(LOG_NOTICE, "failed to enable compactids",
                    "userid=<%s> err=<%s>", props.email, error_message(r));
        }
    }
    mailbox_close(&mailbox);

    /* Set ACL on the Inbox:
       owner:
         regular: ACL_ALL minus ACL_ADMIN
         archive: ACL_LOOKUP, ACL_READ, ACL_SETSEEN, ACL_POST only
       admin:     ACL_ALL
       anyone:    ACL_POST only
    */
    char rights[100];
    if (props.isarchive) {
        cyrus_acl_masktostr(ACL_LOOKUP | ACL_READ | ACL_SETSEEN | ACL_POST,
                            rights);
    }
    else {
        cyrus_acl_masktostr(ACL_ALL & ~ACL_ADMIN, rights);
    }
    r = mboxlist_setacl(&httpd_namespace, mbentry.name, props.email, rights,
                        1, req->userid, req->authstate);
    if (r) {
        xsyslog(LOG_NOTICE, "failed to setacl",
                "mailbox=<%s> userid=<%s> err=<%s>",
                mbentry.name, props.email, error_message(r));
    }
    cyrus_acl_masktostr(ACL_ALL, rights);
    r = mboxlist_setacl(&httpd_namespace, mbentry.name, req->userid, rights,
                        1, req->userid, req->authstate);
    if (r) {
        xsyslog(LOG_NOTICE, "failed to setacl",
                "mailbox=<%s> userid=<%s> err=<%s>",
                mbentry.name, req->userid, error_message(r));
    }
    cyrus_acl_masktostr(ACL_POST, rights);
    r = mboxlist_setacl(&httpd_namespace, mbentry.name, "anyone", rights,
                        1, req->userid, req->authstate);
    if (r) {
        xsyslog(LOG_NOTICE, "failed to setacl",
                "mailbox=<%s> userid=<%s> err=<%s>",
                mbentry.name, "anyone", error_message(r));
    }

    /* Set quotas */
    if (props.quotas) {
        quota_t newquotas[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
        const char *name;
        json_t *val;

        json_object_foreach(props.quotas, name, val) {
            int res = quota_name_to_resource(name);
            if (res >= 0 && json_is_integer(val)) {
                newquotas[res] = json_integer_value(val) / quota_units[res];
            }
        }

        r = mboxlist_setquotas(mbentry.name, newquotas, 0, 0);
        if (r) {
            xsyslog(LOG_NOTICE, "failed to quotas",
                    "mailbox=<%s> err=<%s>", mbentry.name, error_message(r));
        }
    }

    /* Subscribe to the INBOX as the owner */
    r = mboxlist_changesub(mbentry.name, props.email,
                           httpd_authstate, 1, 1, 0, 0);
    if (r) {
        xsyslog(LOG_NOTICE, "failed to subscribe",
                "mailbox=<%s> userid=<%s> err=<%s>",
                mbentry.name, props.email, error_message(r));
    }

    /*
     * JMAP subreqs is a stack, so the following get executed in reverse order
     */

    /* Create default address book */
    if (props.def_abookname) {
        jmap_add_subreq(req, "AddressBook/set",
                        json_pack("{s:s s:{s:{s:s}} s:s}",
                                  "accountId", props.email,
                                  "create", "abook", "name", props.def_abookname,
                                  "onSuccessSetIsDefault", "#abook"),
                        NULL);
    }

    /* Create default calendar */
    if (props.def_calname) {
        jmap_add_subreq(req, "Calendar/set",
                        json_pack("{s:s s:{s:{s:s}} s:s}",
                                  "accountId", props.email,
                                  "create", "cal", "name", props.def_calname,
                                  "onSuccessSetIsDefault", "#cal"),
                        NULL);
    }

    /* Create special-use mailboxes */
    if (props.mailboxes) {
        json_t *create = json_object();
        size_t index = 0;
        json_t *jmailbox;

        json_array_foreach(props.mailboxes, index, jmailbox) {
            json_t *name = json_object_get(jmailbox, "name");
            json_t *role = json_object_get(jmailbox, "role");
            json_t *mailbox = json_pack("{s:O s:O* s:b}",
                                        "name", name,
                                        "role", role,
                                        "isSubscribed", true);

            json_object_set_new(create, json_string_value(role), mailbox);
        }

        jmap_add_subreq(req, "Mailbox/set",
                        json_pack("{s:s s:o}",
                                  "accountId", props.email,
                                  "create", create),
                        NULL);
    }

    /* Fetch the INBOX properties */
    jmap_add_subreq(req, "Mailbox/get",
                    json_pack("{s:s}", "accountId", props.email),
                    NULL);

    jmap_add_id(req, creation_id, props.email);

    *resp = json_pack("{s:s}", "id", props.email);

 done:
    if (r && *err == NULL) {
        if (r == IMAP_MAILBOX_EXISTS)
            *err = json_pack("{s:s}", "type", "alreadyExists");
        else
            *err = jmap_server_error(r);
    }
    user_nslock_release(&user_nslock);
    mbname_free(&mbname);
    jmap_parser_fini(&parser);
}

static int jmap_account_create(struct jmap_req *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    json_t *created = NULL;
    json_t *not_created = NULL;
    size_t size = json_object_size(req->args);

    if (size != 1) {
        jmap_error(req,
                   json_pack("{s:s s:s}",
                             "type",
                             "invalidArguments",
                             "description",
                             "one and only one account"
                             " can be created at a time"));
        return 0;
    }

    const char *key;
    json_t *arg;
    json_object_foreach(req->args, key, arg) {
        if (json_object_get(not_created, key)) {
            continue;
        }
        if (!strlen(key)) {
            json_t *err= json_pack("{s:s}", "type", "invalidArguments");
            json_object_set_new(not_created, key, err);
            continue;
        }

        json_t *resp = NULL;
        json_t *err = NULL;

        /* Make sure no property is set without its capability */
        jmap_set_validate_props(req, NULL, arg, &account_props, &err);

        if (!err) account_create(req, key, arg, &resp, &err);

        if (err) {
            if (!not_created) not_created = json_object(); 
            json_object_set_new(not_created, key, err);
        }
        else {
            if (!created) created = json_object();
            json_object_set_new(created, key, resp);
        }
    }

    json_t *res = json_pack("{s:O? s:O?}",
                            "created", created, "notCreated", not_created);
    jmap_ok(req, res);

    jmap_parser_fini(&parser);
    json_decref(created);
    json_decref(not_created);

    return 0;
}
