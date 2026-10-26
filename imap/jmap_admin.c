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
        JMAP_NO_ACCOUNTID | JMAP_NO_USERLOCK,
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
    json_t *groups;
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

    jprop = json_object_get(arg, "addToGroups");
    if (json_array_size(jprop)) {
        size_t index;
        json_t *jgroup;
        json_array_foreach(jprop, index, jgroup) {
            const char *group = json_string_value(jgroup);
            if (!group || strncmp(group, "group:", 6) || !group[6]) {
                jmap_parser_push_index(parser, "addToGroups", index, NULL);
                jmap_parser_invalid(parser, NULL);
                jmap_parser_pop(parser);
            }
        }

        props->groups = jprop;
    }
    else if (JNOTNULL(jprop)) {
        jmap_parser_invalid(parser, "addToGroups");
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
    mbentry_t *mbentry = NULL;
    const char *inboxid = NULL;
    int r = 0;

    /* Parse and validate properties. */
    account_readprops(req, &parser, &props, arg);
    if (json_array_size(parser.invalid)) {
        *err = json_pack("{s:s, s:O}",
                         "type", "invalidProperties",
                         "properties", parser.invalid);
        goto done;
    }

    /* Build ACL for the INBOX:
       owner:
         regular: ACL_ALL minus ACL_ADMIN
         archive: ACL_LOOKUP, ACL_READ, ACL_SETSEEN, ACL_POST only
       admin:     ACL_ALL
       anyone:    ACL_POST only
    */
    struct buf acl = BUF_INITIALIZER;
    char rightstr[ACL_MAXSTR];

    cyrus_acl_masktostr(props.isarchive ?
                        ACL_LOOKUP | ACL_READ | ACL_SETSEEN | ACL_POST :
                        ACL_ALL & ~ACL_ADMIN,
                        rightstr);
    buf_printf(&acl, "%s\t%s\t", props.email /*owner*/, rightstr);

    cyrus_acl_masktostr(ACL_ALL, rightstr);
    buf_printf(&acl, "%s\t%s\t", req->userid /*admin*/, rightstr);

    cyrus_acl_masktostr(ACL_POST, rightstr);
    buf_printf(&acl, "%s\t%s\t", "anyone", rightstr);

    mbentry = mboxlist_entry_create();
    mbentry->mbtype = MBTYPE_EMAIL;
    mbentry->name   = mboxname_user_mbox(props.email, NULL);
    mbentry->acl    = buf_release(&acl);

    user_nslock = user_nslock_lock_w(props.email);

    /* Create INBOX */
    r = mboxlist_createmailbox(mbentry, 0/*options*/, 0/*highestmodseq*/,
                               1/*isadmin*/, req->userid, req->authstate,
                               0/*flags*/, &mailbox);
    if (r) {
        xsyslog_ev(LOG_ERR, "jmap.account.create.failed",
                   lf_jmapreq(req), lf_intname("mbox.name", mbentry->name),
                   lf_err("error", r));
        goto done;
    }

    mboxlist_entry_free(&mbentry);
    mbentry = mboxlist_entry_copy(mailbox_mbentry(mailbox));

    if (props.compactids) {
        struct conversations_state *cstate = mailbox_get_cstate(mailbox);
        r = conversations_enable_compactids(cstate, 1);
        if (r) {
            xsyslog_ev(LOG_ERR, "jmap.account.compactids.failed",
                       lf_jmapreq(req), lf_mbentry(mbentry),
                       lf_err("error", r));
        }

        inboxid = mbentry->jmapid;
    }
    else {
        inboxid = mbentry->uniqueid;
    }
    mailbox_close(&mailbox);

    /* Add to groups */
    if (!r && props.groups) {
        size_t index;
        json_t *jgroup;
        json_array_foreach(props.groups, index, jgroup) {
            const char *group = json_string_value(jgroup);
            r = mboxlist_set_usergroup(props.email, group,
                                       1/*add*/, 0/*silent*/);
            if (r) {
                xsyslog_ev(LOG_ERR, "jmap.account.usergroup.failed",
                           lf_jmapreq(req), lf_mbentry(mbentry),
                           lf_s("u.group", group), lf_err("error", r));
            }
        }
    }

    /* Set quotas */
    if (!r && props.quotas) {
        quota_t newquotas[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
        const char *name;
        json_t *val;

        json_object_foreach(props.quotas, name, val) {
            int res = quota_name_to_resource(name);
            if (res >= 0 && json_is_integer(val)) {
                newquotas[res] = json_integer_value(val) / quota_units[res];
            }
        }

        r = mboxlist_setquotas(mbentry->name, newquotas,
                               0/*modseq*/, 0/*force*/);
        if (r) {
            xsyslog_ev(LOG_ERR, "jmap.account.quota.failed",
                       lf_jmapreq(req), lf_mbentry(mbentry),
                       lf_err("error", r));
        }
    }

    if (r) {
        /* Delete INBOX and metadata */
        int r2 = mboxlist_deletemailbox(mbentry->name, 1/*isadmin*/,
                                        req->userid, req->authstate,
                                        NULL/*mboxevent*/, 0/*flags*/);
        if (r2) {
            xsyslog_ev(LOG_WARNING, "jmap.account.cleanup.failed",
                       lf_jmapreq(req), lf_mbentry(mbentry),
                       lf_err("error", r2));
        }
        user_deletedata(mbentry, 1/*wipe_user*/);
        goto done;
    }

    /* Subscribe to the INBOX as the owner */
    r = mboxlist_changesub(mbentry->name, props.email, httpd_authstate,
                           1/*add*/, 1/*force*/, 0/*notify*/, 1/*silent*/);
    if (r) {
        xsyslog_ev(LOG_WARNING, "jmap.account.subscribe.failed",
                   lf_jmapreq(req), lf_mbentry(mbentry), lf_err("error", r));
    }

    /*
     * JMAP subreqs is a stack, so the following get executed in reverse order
     */

    /* Create default address book */
    if (props.def_abookname) {
        jmap_add_subreq(req, "AddressBook/set",
                        json_pack("{s:s s:{s:{s:s}} s:s}",
                                  "accountId", props.email,
                                  "create", "abook",
                                  "name", props.def_abookname,
                                  "onSuccessSetIsDefault", "#abook"),
                        NULL);
    }

    /* Create default calendar */
    if (props.def_calname) {
        jmap_add_subreq(req, "Calendar/set",
                        json_pack("{s:s s:{s:{s:s}} s:s}",
                                  "accountId", props.email,
                                  "create", "cal",
                                  "name", props.def_calname,
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
                    json_pack("{s:s s:[s] s:[s s s s]}",
                              "accountId", props.email,
                              "ids", inboxid,
                              "properties",
                              "uniqueId", "name", "role", "isSubscribed"),
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
    mboxlist_entry_free(&mbentry);
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
        jmap_set_validate_props(req, NULL, arg, &account_props, NULL, &err);

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
