/* jmap_mail.c -- Routines for handling JMAP mail messages
 *
 * Copyright (c) 1994-2014 Carnegie Mellon University.  All rights reserved.
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
#include <sys/mman.h>

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "http_dav.h"
#include "http_jmap.h"
#include "http_proxy.h"
#include "json_support.h"
#include "mailbox.h"
#include "mappedfile.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "msgrecord.h"
#include "notify.h"
#include "parseaddr.h"
#include "proxy.h"
#include "search_query.h"
#include "smtpclient.h"
#include "statuscache.h"
#include "stristr.h"
#include "sync_log.h"
#include "times.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrnchr.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int getMailboxes(jmap_req_t *req);
static int setMailboxes(jmap_req_t *req);
static int getMailboxesUpdates(jmap_req_t *req);
static int getMailboxesList(jmap_req_t *req);
static int getMailboxesListUpdates(jmap_req_t *req);
static int getEmailsList(jmap_req_t *req);
static int getEmailsListUpdates(jmap_req_t *req);
static int getEmails(jmap_req_t *req);
static int setEmails(jmap_req_t *req);
static int getEmailsUpdates(jmap_req_t *req);
static int importEmails(jmap_req_t *req);
static int getSearchSnippets(jmap_req_t *req);
static int getThreads(jmap_req_t *req);
static int getIdentities(jmap_req_t *req);
static int getThreadsUpdates(jmap_req_t *req);
static int getEmailSubmissions(jmap_req_t *req);
static int setEmailSubmissions(jmap_req_t *req);
static int getEmailSubmissionsUpdates(jmap_req_t *req);
static int getEmailSubmissionsList(jmap_req_t *req);
static int getEmailSubmissionsListUpdates(jmap_req_t *req);

/*
 * Possibly to be implemented:
 * - Email/copy
 * - VacationResponse/get
 * - VacationResponse/set
 * - Identity/changes
 * - Identity/set
 * - Email/report
 */

/*
 * TODO now with JMAP methods all following the core protocol,
 * we might want to refactor the existing codebase to make use
 * of it. As a minimum, we should use a generic approach for
 * validation as we are doing for example in validate_sort,
 * but the search window handling is also a good candidate.
 */

jmap_method_t jmap_mail_methods[] = {
    { "Mailbox/get",                  &getMailboxes },
    { "Mailbox/set",                  &setMailboxes },
    { "Mailbox/changes",              &getMailboxesUpdates },
    { "Mailbox/query",                &getMailboxesList },
    { "Mailbox/queryChanges",         &getMailboxesListUpdates },
    { "Email/query",                  &getEmailsList },
    { "Email/queryChanges",           &getEmailsListUpdates },
    { "Email/get",                    &getEmails },
    { "Email/set",                    &setEmails },
    { "Email/changes",                &getEmailsUpdates },
    { "Email/import",                 &importEmails },
    { "SearchSnippet/get",            &getSearchSnippets },
    { "Thread/get",                   &getThreads },
    { "Thread/changes",               &getThreadsUpdates },
    { "Identity/get",                 &getIdentities },
    { "EmailSubmission/get",          &getEmailSubmissions },
    { "EmailSubmission/set",          &setEmailSubmissions },
    { "EmailSubmission/changes",      &getEmailSubmissionsUpdates },
    { "EmailSubmission/query",        &getEmailSubmissionsList },
    { "EmailSubmission/queryChanges", &getEmailSubmissionsListUpdates },
    { NULL,                           NULL}
};

/* NULL terminated list of supported getEmailsList sort fields */
static const char *msglist_sortfields[];

int jmap_mail_init(hash_table *methods, json_t *capabilities)
{
    jmap_method_t *mp;
    for (mp = jmap_mail_methods; mp->name; mp++) {
        hash_insert(mp->name, mp, methods);
    }

    json_t *sortopts = json_array();
    const char **sp;
    for (sp = msglist_sortfields; *sp; sp++) {
        json_array_append_new(sortopts, json_string(*sp));
    }

    json_t *my_capabilities = json_pack("{s:o? s:i s:i s:O s:O}",
            "maxMailboxesPerEmail", json_null(),
            "maxSizeAttachmentsPerEmail", 0,
            "maxDelayedSend", 0,
            "emailsListSortOptions", sortopts,
            "submissionExtensions", json_object());

    json_object_set_new(capabilities, "ietf:jmapmail", my_capabilities);
    return 0;
}

#define JMAP_HAS_ATTACHMENT_FLAG "$HasAttachment"

typedef enum MsgType {
        MSG_IS_ROOT = 0,
        MSG_IS_ATTACHED = 1,
} MsgType;

static int _wantprop(hash_table *props, const char *name)
{
    if (!props) return 1;
    return hash_lookup(name, props) != NULL;
}

static int JNOTNULL(json_t *item)
{
   if (!item) return 0;
   if (json_is_null(item)) return 0;
   return 1;
}

static int readprop_full(json_t *root, const char *prefix, const char *name,
                         int mandatory, json_t *invalid, const char *fmt,
                         void *dst)
{
    int r = 0;
    json_t *jval = json_object_get(root, name);
    if (!jval && mandatory) {
        r = -1;
    } else if (jval) {
        json_error_t err;
        if (!mandatory && json_is_null(jval)) {
            /* XXX not all non-mandatory properties are nullable */
            r = 0;
        }
        else if (json_unpack_ex(jval, &err, 0, fmt, dst)) {
            r = -2;
        }
        else {
            r = 1;
        }
    }
    if (r < 0 && prefix) {
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%s.%s", prefix, name);
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_free(&buf);
    } else if (r < 0) {
        json_array_append_new(invalid, json_string(name));
    }
    return r;
}

#define readprop(root, name,  mandatory, invalid, fmt, dst) \
    readprop_full((root), NULL, (name), (mandatory), (invalid), (fmt), (dst))

static void validate_string_array(json_t *arg, const char *prefix, json_t *invalid) {
    /* FIXME probably use in getEmailsList */
    if (!JNOTNULL(arg)) {
        return;
    }
    if (!json_is_array(arg)) {
        json_array_append_new(invalid, json_string(prefix));
        return;
    }

    size_t i;
    json_t *val;
    struct buf buf = BUF_INITIALIZER;

    json_array_foreach(arg, i, val) {
        if (!json_is_string(val)) {
            buf_printf(&buf, "%s[%zu]", prefix, i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }

    buf_free(&buf);
}

typedef struct {
    const char *property;
    short is_ascending;
    const char *collation;
} jmap_comparator_t;

static void validate_sort(json_t *sort, json_t *invalid, json_t *unsupported,
                          int (*is_supported)(const jmap_comparator_t *comp))
{
    struct buf buf = BUF_INITIALIZER;
    struct buf prop = BUF_INITIALIZER;
    jmap_comparator_t comp;
    json_t *jcomp;
    size_t i;

    if (!JNOTNULL(sort)) {
        return;
    }

    if (!json_array_size(sort)) {
        json_array_append_new(invalid, json_string("sort"));
        return;
    }

    json_array_foreach(sort, i, jcomp) {
        /* Reset comparator */
        memset(&comp, 0, sizeof(jmap_comparator_t));

        /* Validate sort */
        if (!json_is_object(jcomp)) {
            buf_printf(&buf, "sort[%zu]", i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
            continue;
        }

        /* property */
        json_t *val = json_object_get(jcomp, "property");
        comp.property = json_string_value(val);
        if (!comp.property) {
            buf_printf(&buf, "sort[%zu].property", i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
            continue;
        }

        /* isAscending */
        comp.is_ascending = 1;
        val = json_object_get(jcomp, "isAscending");
        if (JNOTNULL(val)) {
            if (!json_is_boolean(val)) {
                buf_printf(&buf, "sort[%zu].isAscending", i);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
                continue;
            }
            comp.is_ascending = json_boolean_value(val);
        }

        /* collation */
        val = json_object_get(jcomp, "collation");
        if (JNOTNULL(val) && !json_is_string(val)) {
            buf_printf(&buf, "sort[%zu].collation", i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
            continue;
        }
        comp.collation = json_string_value(val);

        if (!is_supported(&comp)) {
            buf_printf(&buf, "sort[%zu]", i);
            json_array_append_new(unsupported, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }

    buf_free(&buf);
    buf_free(&prop);
}

/*
 * Mailboxes
 */

struct findmbox_data {
    const char *uniqueid;
    char **name;
};

static int findmbox_cb(const mbentry_t *mbentry, void *rock)
{
    struct findmbox_data *data = rock;
    if (strcmp(mbentry->uniqueid, data->uniqueid))
        return 0;
    *(data->name) = xstrdup(mbentry->name);
    return IMAP_OK_COMPLETED;
}

static char *jmapmbox_find_uniqueid(jmap_req_t *req, const char *id)
{
    char *name = NULL;
    struct findmbox_data rock = { id, &name };
    int r = jmap_mboxlist(req, findmbox_cb, &rock);
    if (r != IMAP_OK_COMPLETED) {
        free(name);
        name = NULL;
    }
    return name;
}

struct find_specialuse_data {
    const char *use;
    const char *userid;
    char *mboxname;
};

static int find_specialuse_cb(const mbentry_t *mbentry, void *rock)
{
    struct find_specialuse_data *d = (struct find_specialuse_data *)rock;
    struct buf attrib = BUF_INITIALIZER;

    annotatemore_lookup(mbentry->name, "/specialuse", d->userid, &attrib);

    if (attrib.len) {
        strarray_t *uses = strarray_split(buf_cstring(&attrib), " ", 0);
        if (strarray_find_case(uses, d->use, 0) >= 0)
            d->mboxname = xstrdup(mbentry->name);
        strarray_free(uses);
    }

    buf_free(&attrib);

    if (d->mboxname) return CYRUSDB_DONE;
    return 0;
}


static char *jmapmbox_find_specialuse(jmap_req_t *req, const char *use)
{
    /* \\Inbox is magical */
    if (!strcasecmp(use, "\\Inbox"))
        return mboxname_user_mbox(req->accountid, NULL);

    struct find_specialuse_data rock = { use, req->userid, NULL };
    jmap_mboxlist(req, find_specialuse_cb, &rock);
    return rock.mboxname;
}

static char *jmapmbox_role(jmap_req_t *req, const mbname_t *mbname)
{
    struct buf buf = BUF_INITIALIZER;
    const char *role = NULL;
    char *ret = NULL;

    /* Inbox is special. */
    if (!strarray_size(mbname_boxes(mbname)))
        return xstrdup("inbox");

    /* XXX How to determine the templates role? */

    /* Does this mailbox have an IMAP special use role? */
    annotatemore_lookup(mbname_intname(mbname), "/specialuse",
                        req->userid, &buf);
    if (buf.len) {
        strarray_t *uses = strarray_split(buf_cstring(&buf), " ", STRARRAY_TRIM);
        if (uses->count) {
            /* In IMAP, a mailbox may have multiple roles. But in JMAP we only
             * return the first specialuse flag. */
            const char *use = strarray_nth(uses, 0);
            if (!strcmp(use, "\\Archive")) {
                role = "archive";
            } else if (!strcmp(use, "\\Drafts")) {
                role = "drafts";
            } else if (!strcmp(use, "\\Junk")) {
                role = "spam";
            } else if (!strcmp(use, "\\Sent")) {
                role = "sent";
            } else if (!strcmp(use, "\\Trash")) {
                role = "trash";
            }
        }
        strarray_free(uses);
    }

    /* Otherwise, does it have the x-role annotation set? */
    if (!role) {
        buf_reset(&buf);
        annotatemore_lookup(mbname_intname(mbname),
                            IMAP_ANNOT_NS "x-role", req->userid, &buf);
        if (buf.len) {
            role = buf_cstring(&buf);
        }
    }

    /* Make the caller own role. */
    if (role) ret = xstrdup(role);

    buf_free(&buf);
    return ret;
}

static char *jmapmbox_name(jmap_req_t *req, const mbname_t *mbname)
{
    struct buf attrib = BUF_INITIALIZER;

    int r = annotatemore_lookup(mbname_intname(mbname),
                                IMAP_ANNOT_NS "displayname",
            req->userid, &attrib);
    if (!r && attrib.len) {
        /* We got a mailbox with a displayname annotation. Use it. */
        char *name = buf_release(&attrib);
        buf_free(&attrib);
        return name;
    }
    buf_free(&attrib);

    /* No displayname annotation. Most probably this mailbox was
     * created via IMAP. In any case, determine name from the the
     * last segment of the mailboxname hierarchy. */
    char *extname;

    const strarray_t *boxes = mbname_boxes(mbname);
    if (strarray_size(boxes)) {
        extname = xstrdup(strarray_nth(boxes, strarray_size(boxes)-1));
        /* Decode extname from IMAP UTF-7 to UTF-8. Or fall back to extname. */
        charset_t cs = charset_lookupname("imap-utf-7");
        char *decoded = charset_to_utf8(extname, strlen(extname),
                                        cs, ENCODING_NONE);
        if (decoded) {
            free(extname);
            extname = decoded;
        }
        charset_free(&cs);
    } else {
        extname = xstrdup("Inbox");
    }

    return extname;
}

static int jmapmbox_sort_order(jmap_req_t *req, const mbname_t *mbname)
{
    struct buf attrib = BUF_INITIALIZER;
    int sort_order = 0;
    char *role = NULL;

    /* Ignore lookup errors here. */
    annotatemore_lookup(mbname_intname(mbname),
                        IMAP_ANNOT_NS "sortOrder", req->userid, &attrib);
    if (attrib.len) {
        uint64_t t = str2uint64(buf_cstring(&attrib));
        if (t < INT_MAX) {
            sort_order = (int) t;
        } else {
            syslog(LOG_ERR, "%s: bogus sortOrder annotation value", mbname_intname(mbname));
        }
    }
    else {
        /* calculate based on role.  From FastMail:
           [  1, '*Inbox',     'inbox',   0,    1, [ 'INBOX' ], { PreviewModeId => 2, MessagesPerPage => 20 } ],
           [  2, 'Trash',      'trash',   0,    7, [ 'Trash', 'Deleted Items' ], { HasEmpty => 1 } ],
           [  3, 'Sent',       'sent',    0,    5, [ 'Sent', 'Sent Items' ], { DefSort => 2 } ],
           [  4, 'Drafts',     'drafts',  0,    4, [ 'Drafts' ] ],
           [  5, '*User',      undef,     0,   10, [ ] ],
           [  6, 'Junk',       'spam',    0,    6, [ 'Spam', 'Junk Mail', 'Junk E-Mail' ], { HasEmpty => 1 } ],
           [  7, 'XChats',     undef,     0,    8, [ 'Chats' ] ],
           [  8, 'Archive',    'archive', 0,    3, [ 'Archive' ] ],
           [  9, 'XNotes',     undef,     1,   10, [ 'Notes' ] ],
           [ 10, 'XTemplates', undef,     0,    9, [ 'Templates' ] ],
           [ 12, '*Shared',    undef,     0, 1000, [ 'user' ] ],
           [ 11, '*Restored',  undef,     0, 2000, [ 'RESTORED' ] ],
           */
        role = jmapmbox_role(req, mbname);
        if (!role)
            sort_order = 10;
        else if (!strcmp(role, "inbox"))
            sort_order = 1;
        else if (!strcmp(role, "archive"))
            sort_order = 3;
        else if (!strcmp(role, "drafts"))
            sort_order = 4;
        else if (!strcmp(role, "sent"))
            sort_order = 5;
        else if (!strcmp(role, "spam"))
            sort_order = 6;
        else if (!strcmp(role, "trash"))
            sort_order = 7;
        else
            sort_order = 8;
    }

    free(role);
    buf_free(&attrib);
    return sort_order;
}

static json_t *jmapmbox_from_mbentry(jmap_req_t *req,
                                     const mbentry_t *mbentry,
                                     hash_table *roles,
                                     hash_table *props)
{
    unsigned statusitems = STATUS_MESSAGES | STATUS_UNSEEN;
    struct statusdata sdata;
    int rights;
    int is_inbox = 0, parent_is_inbox = 0;
    int r;
    mbname_t *mbname = mbname_from_intname(mbentry->name);

    json_t *obj = NULL;

    /* Determine rights */
    rights = jmap_myrights(req, mbentry);

    /* INBOX requires special treatment */
    switch (strarray_size(mbname_boxes(mbname))) {
    case 0:
        is_inbox = 1;
        break;
    case 1:
        parent_is_inbox = 1;
        break;
    default:
        break;
    }

    char *role = jmapmbox_role(req, mbname);

    /* Lookup status. */
    r = status_lookup(mbname_intname(mbname), req->userid, statusitems, &sdata);
    if (r) goto done;

    /* Build JMAP mailbox response. */
    obj = json_pack("{}");
    json_object_set_new(obj, "id", json_string(mbentry->uniqueid));
    if (_wantprop(props, "name")) {
        char *name = jmapmbox_name(req, mbname);
        if (!name) goto done;
        json_object_set_new(obj, "name", json_string(name));
        free(name);
    }
    if (_wantprop(props, "mustBeOnlyMailbox")) {
        if (!strcmpsafe(role, "trash"))
            json_object_set_new(obj, "mustBeOnlyMailbox", json_true());
        else if (!strcmpsafe(role, "spam"))
            json_object_set_new(obj, "mustBeOnlyMailbox", json_true());
        else
            json_object_set_new(obj, "mustBeOnlyMailbox", json_false());
    }

    if (_wantprop(props, "mayReadItems")) {
        json_object_set_new(obj, "mayReadItems",
                            json_boolean(rights & ACL_READ));
    }
    if (_wantprop(props, "mayAddItems")) {
        json_object_set_new(obj, "mayAddItems",
                            json_boolean(rights & ACL_INSERT));
    }
    if (_wantprop(props, "mayRemoveItems")) {
        json_object_set_new(obj, "mayRemoveItems",
                            json_boolean(rights & ACL_DELETEMSG));
    }
    if (_wantprop(props, "mayCreateChild")) {
        json_object_set_new(obj, "mayCreateChild",
                            json_boolean(rights & ACL_CREATE));
    }

    if (_wantprop(props, "totalEmails")) {
        json_object_set_new(obj, "totalEmails", json_integer(sdata.messages));
    }
    if (_wantprop(props, "unreadEmails")) {
        json_object_set_new(obj, "unreadEmails", json_integer(sdata.unseen));
    }

    if (_wantprop(props, "totalThreads") || _wantprop(props, "unreadThreads")) {
        conv_status_t xconv = CONV_STATUS_INIT;
        if ((r = conversation_getstatus(req->cstate,
                                        mbname_intname(mbname), &xconv))) {
            syslog(LOG_ERR, "conversation_getstatus(%s): %s",
                   mbname_intname(mbname), error_message(r));
            goto done;
        }
        if (_wantprop(props, "totalThreads")) {
            json_object_set_new(obj, "totalThreads", json_integer(xconv.exists));
        }
        if (_wantprop(props, "unreadThreads")) {
            json_object_set_new(obj, "unreadThreads", json_integer(xconv.unseen));
        }
    }
    if (_wantprop(props, "mayRename") || _wantprop(props, "parentId")) {
        mbentry_t *parent = NULL;
        mboxlist_findparent(mbname_intname(mbname), &parent);
        if (_wantprop(props, "parentId")) {
            json_object_set_new(obj, "parentId",
                                (is_inbox || parent_is_inbox || !parent) ?
                                json_null() : json_string(parent->uniqueid));
        }
        if (_wantprop(props, "mayRename")) {
            int mayRename = 0;
            if (!is_inbox && (rights & ACL_DELETEMBOX)) {
                int parent_rights = jmap_myrights(req, parent);
                mayRename = parent_rights & ACL_CREATE;
            }
            json_object_set_new(obj, "mayRename", json_boolean(mayRename));
        }
        mboxlist_entry_free(&parent);
    }
    if (_wantprop(props, "mayDelete")) {
        int mayDelete = (rights & ACL_DELETEMBOX) && !is_inbox;
        json_object_set_new(obj, "mayDelete", json_boolean(mayDelete));
    }
    if (_wantprop(props, "role")) {
        if (role && !hash_lookup(role, roles)) {
            /* In JMAP, only one mailbox have a role. First one wins. */
            json_object_set_new(obj, "role", json_string(role));
            hash_insert(role, (void*)1, roles);
        } else {
            json_object_set_new(obj, "role", json_null());
        }
    }
    if (_wantprop(props, "sortOrder")) {
        int sortOrder = jmapmbox_sort_order(req, mbname);
        json_object_set_new(obj, "sortOrder", json_integer(sortOrder));
    }

done:
    if (r) {
        syslog(LOG_ERR, "jmapmbox_from_mbentry: %s", error_message(r));
    }
    free(role);
    mbname_free(&mbname);
    return obj;
}

static json_t *jmap_fmtstate(modseq_t modseq)
{
    struct buf buf = BUF_INITIALIZER;
    json_t *state = NULL;
    buf_printf(&buf, MODSEQ_FMT, modseq);
    state = json_string(buf_cstring(&buf));
    buf_free(&buf);
    return state;
}

struct getmailboxes_cb_data {
    jmap_req_t *req;
    json_t *list;
    hash_table *roles;
    hash_table *props;
    hash_table *ids;
    hash_table *want;
    size_t seen;
};

static int getmailboxes_cb(const mbentry_t *mbentry, void *rock)
{
    struct getmailboxes_cb_data *data = (struct getmailboxes_cb_data *) rock;
    json_t *list = (json_t *) data->list, *obj;
    jmap_req_t *req = data->req;
    int r = 0, rights;

    /* Don't list special-purpose mailboxes. */
    if ((mbentry->mbtype & MBTYPE_DELETED) ||
        (mbentry->mbtype & MBTYPE_MOVING) ||
        (mbentry->mbtype & MBTYPE_REMOTE) ||  /* XXX ?*/
        (mbentry->mbtype & MBTYPE_RESERVE) || /* XXX ?*/
        (mbentry->mbtype & MBTYPES_NONIMAP)) {
        goto done;
    }

    /* It's a legit mailbox, so count it */
    data->seen++;

    /* Do we need to process this mailbox? */
    if (data->want && !hash_lookup(mbentry->uniqueid, data->want))
        return 0;

    /* Are we done with looking up mailboxes by id? */
    if (data->want && !hash_numrecords(data->want))
        return IMAP_OK_COMPLETED;

    /* Check ACL on mailbox for current user */
    rights = jmap_myrights(req, mbentry);
    if ((rights & (ACL_LOOKUP | ACL_READ)) != (ACL_LOOKUP | ACL_READ)) {
        goto done;
    }

    /* Convert mbox to JMAP object. */
    obj = jmapmbox_from_mbentry(req, mbentry, data->roles, data->props);
    if (!obj) {
        syslog(LOG_INFO, "could not convert mailbox %s to JMAP", mbentry->name);
        r = IMAP_INTERNAL;
        goto done;
    }
    json_array_append_new(list, obj);

    /* Move this mailbox of the lookup list */
    if (data->want) {
        hash_del(mbentry->uniqueid, data->want);
    }

  done:
    return r;
}

static void getmailboxes_notfound(const char *id,
                                  void *data __attribute__((unused)),
                                  void *rock)
{
    json_t **listptr = rock;
    if (*listptr == json_null())
        *listptr = json_pack("[]");
    json_array_append_new(*listptr, json_string(id));
}

static int getMailboxes(jmap_req_t *req)
{
    json_t *found = json_pack("[]"), *notfound = json_null();
    struct getmailboxes_cb_data data = {
        req,
        found, /* list */
        (hash_table *) xmalloc(sizeof(hash_table)), /* roles */
        NULL, /* props */
        NULL, /* ids */
        NULL, /* want */
        0     /* seen */
    };
    construct_hash_table(data.roles, 8, 0);

    /* Determine which properties to fetch. */
    json_t *properties = json_object_get(req->args, "properties");
    if (properties && json_array_size(properties)) {
        int i;
        int size = json_array_size(properties);

        data.props = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(data.props, size + 1, 0);
        for (i = 0; i < size; i++) {
            const char *pn = json_string_value(json_array_get(properties, i));
            if (pn == NULL) {
                json_t *err = json_pack("{s:s, s:[s]}",
                        "type", "invalidArguments", "arguments", "properties");
                json_array_append_new(req->response, json_pack("[s,o,s]",
                            "error", err, req->tag));
                goto done;
            }
            hash_insert(pn, (void*)1, data.props);
        }
    }

    /* Does the client request specific mailboxes? */
    json_t *want = json_object_get(req->args, "ids");
    if (JNOTNULL(want)) {
        /* Keep note of which mailboxes the client is interested in, but
         * don't look them up by id within the loop. We are better off to
         * use the same code as if the client didn't ask for any specific
         * mailboxes. As soon as there's no more work to do, getmailboxes_cb
         * will end traversal. */
        size_t i;
        json_t *val;
        data.want = (hash_table *) xmalloc(sizeof(hash_table));
        construct_hash_table(data.want, json_array_size(want) + 1, 0);
        json_array_foreach(want, i, val) {
            const char *id = json_string_value(val);
            if (id == NULL) {
                json_t *err = json_pack("{s:s, s:[s]}",
                        "type", "invalidArguments", "arguments", "ids");
                json_array_append_new(req->response, json_pack("[s,o,s]",
                            "error", err, req->tag));
                goto done;
            }
            if (id[0] == '#') {
                const char *newid = hash_lookup(id + 1, &req->idmap->mailboxes);
                if (!newid) {
                    if (notfound == json_null()) {
                        notfound = json_pack("[]");
                    }
                    json_array_append_new(notfound, json_string(id));
                    continue;
                }
                id = newid;
            }
            hash_insert(id, (void*) 1, data.want);
        }
    }

    /* Lookup and process the mailboxes */
    jmap_mboxlist(req, getmailboxes_cb, &data);

   /* Report if any requested mailbox has not been found */
    if (data.want) {
        hash_enumerate(data.want, getmailboxes_notfound, &notfound);
    }

    /* Build response */
    json_t *item = json_pack("[s {s:s s:O s:O s:o} s]",
                     "Mailbox/get",
                     "accountId", req->accountid,
                     "list", found,
                     "notFound", notfound,
                     "state", jmap_getstate(req, 0/*mbtype*/),
                     req->tag);
    json_array_append_new(req->response, item);

done:
    json_decref(found);
    json_decref(notfound);
    if (data.roles) {
        free_hash_table(data.roles, NULL);
        free(data.roles);
    }
    if (data.props) {
        free_hash_table(data.props, NULL);
        free(data.props);
    }
    if (data.want) {
        free_hash_table(data.want, NULL);
        free(data.want);
    }
    return 0;
}

typedef struct {
    jmap_req_t *req;
    ptrarray_t filter;  /* Filters (mboxsearch_filter_t) */
    ptrarray_t sort;    /* Sort criteria (mboxsearch_sort_t) */
    ptrarray_t result;  /* Result records (mboxsearch_record_t) */

    int _need_name;
    int _need_sort_order;
    int _need_role;
} mboxsearch_t;

typedef struct {
    char *id;
    char *mboxname;
    char *jmapname;
    int sort_order;
} mboxsearch_record_t;

typedef struct {
    char *field;
    int desc;
} mboxsearch_sort_t;

typedef struct {
    char *field;
    union {
        char *s;
        short b;
    } val;
} mboxsearch_filter_t;

static mboxsearch_t *mboxsearch_new(jmap_req_t *req)
{
    mboxsearch_t *q = xzmalloc(sizeof(mboxsearch_t));
    q->req = req;
    return q;
}

static void mboxsearch_free(mboxsearch_t **qptr)
{
    int i;
    mboxsearch_t *q = *qptr;

    for (i = 0; i < q->result.count; i++) {
        mboxsearch_record_t *rec = ptrarray_nth(&q->result, i);
        free(rec->id);
        free(rec->mboxname);
        free(rec->jmapname);
        free(rec);
    }
    ptrarray_fini(&q->result);

    for (i = 0; i < q->filter.count; i++) {
        mboxsearch_filter_t *filter = ptrarray_nth(&q->filter, i);
        if (!strcmp(filter->field, "parentId"))
            free(filter->val.s);
        free(filter->field);
        free(filter);
    }
    ptrarray_fini(&q->filter);

    for (i = 0; i < q->sort.count; i++) {
        mboxsearch_sort_t *crit = ptrarray_nth(&q->sort, i);
        free(crit->field);
        free(crit);
    }
    ptrarray_fini(&q->sort);

    free(q);
    *qptr = NULL;
}

static int mboxsearch_compar(const void **a, const void **b, void *rock)
{
    const mboxsearch_record_t *pa = *a;
    const mboxsearch_record_t *pb = *b;
    ptrarray_t *criteria = rock;
    int i;

    for (i = 0; i < criteria->count; i++) {
        mboxsearch_sort_t *crit = ptrarray_nth(criteria, i);
        int cmp = 0;
        int sign = crit->desc ? -1 : 1;

        if (!strcmp(crit->field, "name"))
            cmp = strcmp(pa->jmapname, pb->jmapname) * sign;
        else if (!strcmp(crit->field, "sortOrder"))
            cmp = (pa->sort_order - pb->sort_order) * sign;

        if (cmp) return cmp;
    }

    return strcmp(pa->id, pb->id);
}

static int mboxsearch_cb(const mbentry_t *mbentry, void *rock)
{
    if (mbentry->mbtype & (MBTYPES_NONIMAP|MBTYPE_DELETED))
        return 0;

    mboxsearch_t *q = rock;
    mbname_t *mbname = mbname_from_intname(mbentry->name);

    /* Apply filters */
    int i;
    for (i = 0; i < q->filter.count; i++) {
        mboxsearch_filter_t *filter = ptrarray_nth(&q->filter, i);
        if (!strcmp(filter->field, "hasRole")) {
            char *role = jmapmbox_role(q->req, mbname);
            int has_role = role != NULL;
            free(role);
            if (!has_role) goto done;
        }
        if (!strcmp(filter->field, "parentId")) {
            mbentry_t *mbparent = NULL;
            int matches_parentid = 0;
            if (!mboxlist_findparent(mbentry->name, &mbparent)) {
                matches_parentid = !strcmp(mbparent->uniqueid, filter->val.s);
            }
            mboxlist_entry_free(&mbparent);
            if (!matches_parentid) goto done;
        }
    }

    /* Found a matching reccord. Add it to the result list. */
    mboxsearch_record_t *rec = xzmalloc(sizeof(mboxsearch_record_t));
    rec->id = xstrdup(mbentry->uniqueid);
    if (q->_need_name) {
        rec->mboxname = xstrdup(mbentry->name);
        rec->jmapname = jmapmbox_name(q->req, mbname);
    }
    if (q->_need_sort_order) {
        rec->sort_order = jmapmbox_sort_order(q->req, mbname);
    }
    ptrarray_append(&q->result, rec);

done:
    mbname_free(&mbname);
    return 0;
}

static int mboxsearch_run(mboxsearch_t *query)
{
    int i;

    /* Prepare internal query context. */
    for (i = 0; i < query->sort.count; i++) {
        mboxsearch_sort_t *crit = ptrarray_nth(&query->sort, i);
        if (!strcmp(crit->field, "name")) {
            query->_need_name = 1;
        }
        else if (!strcmp(crit->field, "sortOrder")) {
            query->_need_sort_order = 1;
        }
    }
    for (i = 0; i < query->filter.count; i++) {
        mboxsearch_filter_t *filter = ptrarray_nth(&query->filter, i);
        if (!strcmp(filter->field, "hasRole")) {
            query->_need_role = 1;
        }
    }

    /* Lookup all mailboxes */
    int r = jmap_mboxlist(query->req, mboxsearch_cb, query);
    if (r) goto done;

    /* Sort result */
    qsort_r(query->result.data, query->result.count, sizeof(void*),
            (int(*)(const void*, const void*, void*)) mboxsearch_compar,
            &query->sort);

done:
    return r;
}

typedef struct {
    ssize_t position;
    const char *anchor;
    int anchor_off;
    size_t limit;
    int cancalcupdates;
} getmboxlist_window_t;

static int jmapmbox_search(jmap_req_t *req, json_t *filter, json_t *sort,
                           getmboxlist_window_t *window,
                           size_t *total, json_t **ids)
{
    int r = 0;
    size_t j;
    json_t *val;

    /* Reject any attempt to calculcate updates for getMailboxesListUpdates.
     * All of the filter and sort criteria are mutable. That only leaves
     * an unsorted and unfiltered mailbox list which we internally sort
     * by mailbox ids, which isn't any better than getMailboxesUpdates. */
    window->cancalcupdates = 0;

    /* Prepare query */
    mboxsearch_t *query = mboxsearch_new(req);

    /* Prepare sort */
    json_array_foreach(sort, j, val) {
        mboxsearch_sort_t *crit = xzmalloc(sizeof(mboxsearch_sort_t));
        const char *prop = json_string_value(json_object_get(val, "property"));
        crit->field = xstrdup(prop);
        crit->desc = json_object_get(val, "isAscending") == json_false();
        ptrarray_append(&query->sort, crit);
    }

    /* Prepare filter */
    if ((val = json_object_get(filter, "parentId"))) {
        /* XXX JMAP mailboxList filter 'null' means: no mailbox filter? */
        mboxsearch_filter_t *filter = xzmalloc(sizeof(mboxsearch_filter_t));
        filter->field = xstrdup("parentId");
        filter->val.s = xstrdup(json_string_value(val));
        ptrarray_append(&query->filter, filter);
    }
    if ((val = json_object_get(filter, "hasRole"))) {
        mboxsearch_filter_t *filter = xzmalloc(sizeof(mboxsearch_filter_t));
        filter->field = xstrdup("hasRole");
        ptrarray_append(&query->filter, filter);
    }

    /* Run the query */
    r = mboxsearch_run(query);
    if (r) goto done;

    *ids = json_array();
    *total = query->result.count;

    /* Apply window */
    ssize_t i, frompos = 0;
    int seen_anchor = 0;
    ssize_t skip_anchor = 0;
    ssize_t result_pos = -1;

    /* Set position of first result */
    if (!window->anchor) {
        if (window->position > 0) {
            frompos = window->position;
        }
        else if (window->position < 0) {
            frompos = query->result.count + window->position ;
            if (frompos < 0) frompos = 0;
        }
    }

    for (i = frompos; i < query->result.count; i++) {
        mboxsearch_record_t *rec = ptrarray_nth(&query->result, i);

        /* Check anchor */
        if (window->anchor && !seen_anchor) {
            seen_anchor = !strcmp(rec->id, window->anchor);
            if (!seen_anchor) {
                continue;
            }
            /* Found the anchor! Now apply anchor offsets */
            if (window->anchor_off < 0) {
                skip_anchor = -window->anchor_off;
                continue;
            }
            else if (window->anchor_off > 0) {
                /* Prefill result list with all, but the current record */
                size_t lo = window->anchor_off < i ? i - window->anchor_off : 0;
                size_t hi = window->limit ? lo + window->limit : (size_t) i;
                result_pos = lo;
                while (lo < hi && lo < (size_t) i) {
                    mboxsearch_record_t *p = ptrarray_nth(&query->result, lo);
                    json_array_append_new(*ids, json_string(p->id));
                    lo++;
                }
            }
        }
        else if (window->anchor && skip_anchor) {
            if (--skip_anchor) continue;
        }

        /* Check limit. */
        if (window->limit && window->limit <= json_array_size(*ids)) {
            break;
        }

        /* Add to result list. */
        if (result_pos == -1) {
            result_pos = i;
        }
        json_array_append_new(*ids, json_string(rec->id));
    }
    if (window->anchor && !seen_anchor) {
        json_decref(*ids);
        *ids = json_array();
    }
    if (result_pos >= 0) {
        window->position = result_pos;
    }

done:
    mboxsearch_free(&query);
    if (r) json_decref(*ids);
    return r;
}

static int is_supported_mboxlist_sort(const jmap_comparator_t *comp)
{
    /* Reject unsupported properties */
    if (strcmp(comp->property, "sortOrder") &&
        strcmp(comp->property, "name")) {
        return 0;
    }
    /* Reject any collation */
    if (comp->collation) {
        return 0;
    }
    return 1;
}

typedef struct {
    json_t *filter;
    json_t *sort;
    getmboxlist_window_t window;
} getmboxlist_args_t;

static void getmboxlist_read_args(jmap_req_t *req __attribute__((unused)),
                                 json_t *jargs,
                                 getmboxlist_args_t *args,
                                 json_t *invalid,
                                 json_t *unsupported_filter,
                                 json_t *unsupported_sort)
{
    json_t *arg;
	json_int_t jint = 0;
    memset(args, 0, sizeof(getmboxlist_args_t));

    /* Validate filter */
    arg = json_object_get(jargs, "filter");
    if (JNOTNULL(arg)) {
        json_t *val;
        const char *field;
        json_object_foreach(arg, field, val) {
            if (!strcmp(field, "parentId")) {
                if (val != json_null() && !json_is_string(val)) {
                    json_array_append_new(invalid, json_string(field));
                }
            }
            else if (!strcmp(field, "hasRole")) {
                if (!json_is_boolean(val)) {
                    json_array_append_new(invalid, json_string(field));
                }
            }
            else {
                json_array_append_new(unsupported_filter, json_string(field));
            }
        }
        if (!json_is_object(arg)) {
            json_array_append_new(unsupported_filter, json_string("filter"));
        }
        args->filter = arg;
    }

    /* sort */
    arg = json_object_get(jargs, "sort");
    if (JNOTNULL(arg)) {
        validate_sort(arg, invalid, unsupported_sort, is_supported_mboxlist_sort);
        args->sort = arg;
    }

    /* windowing */
    readprop(jargs, "anchor", 0, invalid, "s", &args->window.anchor);
    readprop(jargs, "anchorOffset", 0, invalid, "i", &args->window.anchor_off);
    if (readprop(jargs, "position", 0, invalid, "I", &jint) > 0) {
        args->window.position = jint;
    }
    if (readprop(jargs, "limit", 0, invalid, "I", &jint) > 0) {
        if (jint < 0) json_array_append_new(invalid, json_string("limit"));
        args->window.limit = jint;
    }
}

static int getMailboxesList(jmap_req_t *req)
{
    int r = 0;
    json_t *ids = NULL, *item, *res;
    size_t total = 0;
    getmboxlist_args_t args;

    /* Parse and validate arguments. */
    json_t *invalid = json_pack("[]");
    json_t *unsupported_filter = json_pack("[]");
    json_t *unsupported_sort = json_pack("[]");
    getmboxlist_read_args(req, req->args, &args, invalid, unsupported_filter, unsupported_sort);

    /* Bail out for argument errors */
    json_t *err = NULL;
    if (json_array_size(invalid)) {
        err = json_pack("{s:s, s:O}", "type", "invalidArguments", "arguments", invalid);
    }
    else if (json_array_size(unsupported_filter)) {
        err = json_pack("{s:s, s:O}", "type", "unsupportedFilter", "filters", unsupported_filter);
    }
    else if (json_array_size(unsupported_sort)) {
        err = json_pack("{s:s, s:O}", "type", "unsupportedSort", "sort", unsupported_sort);
    }
    if (err) {
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        goto done;
    }

    /* Search for the mailboxes */
    r = jmapmbox_search(req, args.filter, args.sort, &args.window, &total, &ids);
    if (r) goto done;

    /* Prepare response. */
    res = json_pack("{}");
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_object_set_new(res, "state", jmap_getstate(req, 0/*mbtype*/));
    json_object_set_new(res, "canCalculateUpdates", json_boolean(args.window.cancalcupdates));
    json_object_set_new(res, "position", json_integer(args.window.position));
    json_object_set_new(res, "total", json_integer(total));
    json_object_set(res, "filter", args.filter);
    json_object_set(res, "sort", args.sort);
    json_object_set(res, "ids", ids);

    item = json_pack("[]");
    json_array_append_new(item, json_string("Mailbox/query"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    json_decref(invalid);
    json_decref(unsupported_filter);
    json_decref(unsupported_sort);
    json_decref(ids);
    return r;
}

static int getMailboxesListUpdates(jmap_req_t *req)
{
    int r = 0;
    getmboxlist_args_t args;

    /* Parse and validate arguments. */
    json_t *invalid = json_pack("[]");
    json_t *unsupported_filter = json_pack("[]");
    json_t *unsupported_sort = json_pack("[]");
    getmboxlist_read_args(req, req->args, &args, invalid, unsupported_filter, unsupported_sort);

    /* Bail out for argument errors */
    json_t *err = NULL;
    if (json_array_size(invalid)) {
        err = json_pack("{s:s, s:O}", "type", "invalidArguments", "arguments", invalid);
    }
    else if (json_array_size(unsupported_filter)) {
        err = json_pack("{s:s, s:O}", "type", "unsupportedFilter", "filters", unsupported_filter);
    }
    else if (json_array_size(unsupported_sort)) {
        err = json_pack("{s:s, s:O}", "type", "unsupportedSort", "sort", unsupported_sort);
    }
    if (err) {
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        goto done;
    }

    /* Refuse all attempts to calculcate list updates */
    json_array_append_new(req->response, json_pack("[s,{s:s},s]",
                "error", "type", "cannotCalculateChanges", req->tag));

done:
    json_decref(invalid);
    json_decref(unsupported_filter);
    json_decref(unsupported_sort);
    return r;
}

struct jmapmbox_newname_data {
    const char *mboxname;
    int highest;
    size_t len;
};

static int jmapmbox_newname_cb(const mbentry_t *mbentry, void *rock) {
    struct jmapmbox_newname_data *data = (struct jmapmbox_newname_data *) rock;
    const char *s, *lo, *hi;
    int n;

    if (!data->len) {
        data->len = strlen(data->mboxname);
        assert(data->len > 0);
    }
    if (strncmp(mbentry->name, data->mboxname, data->len)) {
        return 0;
    }

    /* Skip any grand-children. */
    s = mbentry->name + data->len;
    if (strchr(s, jmap_namespace.hier_sep)) {
        return 0;
    }

    /* Does this mailbox match exactly our mboxname? */
    if (*s == 0) {
        data->highest = 1;
        return 0;
    }

    /* If it doesn't end with pattern "_\d+", skip it. */
    if (*s++ != '_') {
        return 0;
    }

    /* Parse _\d+$ pattern */
    hi = lo = s;
    while (isdigit(*s++)) {
        hi++;
    }
    if (lo == hi || *hi != 0){
        return 0;
    }

    if ((n = atoi(lo)) && n > data->highest) {
        data->highest = n;
    }

    return 0;
}

/* Combine the UTF-8 encoded JMAP mailbox name and its parent IMAP mailbox
 * name to a unique IMAP mailbox name.
 *
 * Parentname must already be encoded in IMAP UTF-7. A parent by this name
 * must already exist. If a mailbox with the combined mailbox name already
 * exists, the new mailbox name is made unique to avoid IMAP name collisions.
 *
 * For example, if the name has been determined to be x and a mailbox with
 * this name already exists, then look for all mailboxes named x_\d+. The
 * new mailbox name will be x_<max+1> with max being he highest number found
 * for any such named mailbox.
 *
 * Return the malloced, combined name, or NULL on error. */
char *jmapmbox_newname(const char *name, const char *parentname)
{
    charset_t cs = CHARSET_UNKNOWN_CHARSET;
    char *mboxname = NULL;
    int r;

    cs = charset_lookupname("utf-8");
    if (cs == CHARSET_UNKNOWN_CHARSET) {
        /* huh? */
        syslog(LOG_INFO, "charset utf-8 is unknown");
        goto done;
    }

    /* Encode mailbox name in IMAP UTF-7 */
    char *s = charset_to_imaputf7(name, strlen(name), cs, ENCODING_NONE);
    if (!s) {
        syslog(LOG_ERR, "Could not convert mailbox name to IMAP UTF-7.");
        goto done;
    }
    mbname_t *mbname = mbname_from_intname(parentname);
    mbname_push_boxes(mbname, s);
    free(s);
    mboxname = xstrdup(mbname_intname(mbname));
    mbname_free(&mbname);

    /* Avoid any name collisions */
    struct jmapmbox_newname_data rock;
    memset(&rock, 0, sizeof(struct jmapmbox_newname_data));
    rock.mboxname = mboxname;
    r = mboxlist_mboxtree(parentname, &jmapmbox_newname_cb, &rock,
                          MBOXTREE_SKIP_ROOT);
    if (r) {
        syslog(LOG_ERR, "mboxlist_mboxtree(%s): %s",
                parentname, error_message(r));
        free(mboxname);
        mboxname = NULL;
        goto done;
    }
    if (rock.highest) {
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "%s_%d", mboxname, rock.highest + 1);
        free(mboxname);
        mboxname = buf_newcstring(&buf);
        buf_free(&buf);
    }

done:
    charset_free(&cs);
    return mboxname;
}

struct jmapmbox_findxrole_data {
    const char *xrole;
    const char *userid;
    char *mboxname;
};

static int jmapmbox_findxrole_cb(const mbentry_t *mbentry, void *rock)
{
    struct jmapmbox_findxrole_data *d = (struct jmapmbox_findxrole_data *)rock;
    struct buf attrib = BUF_INITIALIZER;

    annotatemore_lookup(mbentry->name, IMAP_ANNOT_NS "x-role", d->userid, &attrib);

    if (attrib.len && !strcmp(buf_cstring(&attrib), d->xrole)) {
        d->mboxname = xstrdup(mbentry->name);
    }

    buf_free(&attrib);

    if (d->mboxname) return CYRUSDB_DONE;
    return 0;
}

static char *jmapmbox_findxrole(jmap_req_t *req, const char *xrole)
{
    struct jmapmbox_findxrole_data rock = { xrole, req->userid, NULL };
    /* INBOX can never have an x-role. */
    jmap_mboxlist(req, jmapmbox_findxrole_cb, &rock);
    return rock.mboxname;
}

static int jmapmbox_isparent_cb(const mbentry_t *mbentry __attribute__ ((unused)), void *rock) {
    int *has_child = (int *) rock;
    *has_child = 1;
    return IMAP_OK_COMPLETED;
}

static int jmapmbox_isparent(const char *mboxname)
{
    int has_child = 0;
    mboxlist_mboxtree(mboxname, jmapmbox_isparent_cb, &has_child, MBOXTREE_SKIP_ROOT);
    return has_child;
}

struct setmailboxes_args {
    const char *id;
    const char *name;
    char *parentid;
    const char *role;
    const char *specialuse;
    int sortorder;
};

static void setmailboxes_free_args(struct setmailboxes_args *args)
{
    free(args->parentid);
}

static void setmailboxes_read_args(jmap_req_t *req,
                                   json_t *jargs,
                                   struct setmailboxes_args *args,
                                   int is_create,
                                   json_t *invalid)
{
    int pe;

    /* Initialize arguments */
    memset(args, 0, sizeof(struct setmailboxes_args));
    args->sortorder = -1;

    /* id */
    pe = readprop(jargs, "id", 0, invalid, "s", &args->id);
    if (pe > 0 && is_create) {
        json_array_append_new(invalid, json_string("id"));
    }

    /* name */
    pe = readprop(jargs, "name", is_create, invalid, "s", &args->name);
    if (pe > 0 && !(*(args->name))) {
        json_array_append_new(invalid, json_string("name"));
    }

    /* parentId */
    json_t *jparentid = json_object_get(jargs, "parentId");
    if (JNOTNULL(jparentid)) {
        const char *parentid = NULL;
        pe = readprop(jargs, "parentId", 1, invalid, "s", &parentid);
        if (pe > 0 && *parentid == '#') {
            parentid = hash_lookup(parentid + 1, &req->idmap->mailboxes);
            if (!parentid) {
                json_array_append_new(invalid, json_string("parentId"));
            }
        }
        if (parentid) {
            args->parentid = xstrdup(parentid);
        }
    } else if (jparentid == json_null() || (is_create && !jparentid)) {
        mbentry_t *inboxentry = NULL;
        mboxlist_lookup(req->inboxname, &inboxentry, NULL);
        args->parentid = xstrdup(inboxentry->uniqueid);
        mboxlist_entry_free(&inboxentry);
    }
    if (args->parentid) {
        char *tmp = jmapmbox_find_uniqueid(req, args->parentid);
        if (!tmp) json_array_append_new(invalid, json_string("parentId"));
        free(tmp);
    }

    /* role */
    if (JNOTNULL(json_object_get(jargs, "role"))) {
        pe = readprop(jargs, "role", is_create, invalid, "s", &args->role);
        if (pe > 0 && (!is_create || !strcmp(args->role, "inbox"))) {
            /* Roles are immutable and inbox must not be created */
            json_array_append_new(invalid, json_string("role"));
        }
    }

    /* sortOrder */
    if (readprop(jargs, "sortOrder", 0, invalid, "i", &args->sortorder) > 0) {
        if (args->sortorder < 0 || args->sortorder >= INT_MAX) {
            json_array_append_new(invalid, json_string("sortOrder"));
        }
    }

    /* mayXXX. These are immutable, but we ignore them during update. */
    if (json_object_get(jargs, "mustBeOnlyMailbox") && is_create) {
        json_array_append_new(invalid, json_string("mustBeOnlyMailbox"));
    }
    if (json_object_get(jargs, "mayReadItems") && is_create) {
        json_array_append_new(invalid, json_string("mayReadItems"));
    }
    if (json_object_get(jargs, "mayAddItems") && is_create) {
        json_array_append_new(invalid, json_string("mayAddItems"));
    }
    if (json_object_get(jargs, "mayRemoveItems") && is_create) {
        json_array_append_new(invalid, json_string("mayRemoveItems"));
    }
    if (json_object_get(jargs, "mayRename") && is_create) {
        json_array_append_new(invalid, json_string("mayRename"));
    }
    if (json_object_get(jargs, "mayDelete") && is_create) {
        json_array_append_new(invalid, json_string("mayDelete"));
    }
    if (json_object_get(jargs, "totalEmails") && is_create) {
        json_array_append_new(invalid, json_string("totalEmails"));
    }
    if (json_object_get(jargs, "unreadEmails") && is_create) {
        json_array_append_new(invalid, json_string("unreadEmails"));
    }
    if (json_object_get(jargs, "totalThreads") && is_create) {
        json_array_append_new(invalid, json_string("totalThreads"));
    }
    if (json_object_get(jargs, "unreadThreads") && is_create) {
        json_array_append_new(invalid, json_string("unreadThreads"));
    }
}

static int jmapmbox_write_annots(jmap_req_t *req,
                                 struct setmailboxes_args *args,
                                 const char *mboxname)
{
    int r = 0;
    struct buf buf = BUF_INITIALIZER;

    if (args->name) {
        /* Set displayname annotation on mailbox. */
        buf_setcstr(&buf, args->name);
        static const char *displayname_annot = IMAP_ANNOT_NS "displayname";
        r = annotatemore_write(mboxname, displayname_annot, req->userid, &buf);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    displayname_annot, error_message(r));
            goto done;
        }
        buf_reset(&buf);
    }

    /* Set specialuse or x-role. specialuse takes precedence. */
    if (args->specialuse) {
        buf_setcstr(&buf, args->specialuse);
        static const char *annot = "/specialuse";
        r = annotatemore_write(mboxname, annot, req->userid, &buf);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    annot, error_message(r));
            goto done;
        }
        buf_reset(&buf);
    }
    else if (args->role) {
        buf_setcstr(&buf, args->role);
        static const char *annot = IMAP_ANNOT_NS "x-role";
        r = annotatemore_write(mboxname, annot, req->userid, &buf);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    annot, error_message(r));
            goto done;
        }
        buf_reset(&buf);
    }

    if (args->sortorder >= 0) {
        /* Set sortOrder annotation on mailbox. */
        buf_printf(&buf, "%d", args->sortorder);
        static const char *sortorder_annot = IMAP_ANNOT_NS "sortOrder";
        r = annotatemore_write(mboxname, sortorder_annot, req->userid, &buf);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    sortorder_annot, error_message(r));
            goto done;
        }
    }

done:
    buf_free(&buf);
    return r;
}

static int jmapmbox_create(jmap_req_t *req,
                           struct setmailboxes_args *args,
                           json_t *invalid,
                           char **mboxid,
                           json_t **err __attribute__((unused)))
{
    char *mboxname = NULL, *parentname = NULL;
    int r = 0, rights = 0;
    mbentry_t *mbinbox = NULL, *mbparent = NULL, *mbentry = NULL;

    mboxlist_lookup(req->inboxname, &mbinbox, NULL);

    /* Check parent ACL */
    parentname = jmapmbox_find_uniqueid(req, args->parentid);
    if (!parentname) {
        json_array_append_new(invalid, json_string("parentId"));
        goto done;
    }
    r = mboxlist_lookup(parentname, &mbparent, NULL);
    if (r) {
        syslog(LOG_ERR, "failed to lookup parent mailbox %s: %s",
                parentname, error_message(r));
        goto done;
    }
    rights = jmap_myrights(req, mbparent);
    if (!(rights & ACL_CREATE)) {
        json_array_append_new(invalid, json_string("parentId"));
        goto done;
    }

    /* Sanity-check arguments */
    if (args->role) {
        /* Is it one of the known special use mailboxes? */
        if (!strcmp(args->role, "archive")) {
            args->specialuse = "\\Archive";
        } else if (!strcmp(args->role, "drafts")) {
            args->specialuse = "\\Drafts";
        } else if (!strcmp(args->role, "spam")) {
            args->specialuse = "\\Junk";
        } else if (!strcmp(args->role, "sent")) {
            args->specialuse = "\\Sent";
        } else if (!strcmp(args->role, "trash")) {
            args->specialuse = "\\Trash";
        } else if (strncmp(args->role, "x-", 2)) {
            /* Does it start with an "x-"? If not, reject it. */
            json_array_append_new(invalid, json_string("role"));
        }
        char *exists = NULL;
        if (args->specialuse) {
            /* Check that no such IMAP specialuse mailbox already exists. */
            exists = jmapmbox_find_specialuse(req, args->specialuse);
        } else if (!json_array_size(invalid)) {
            /* Check that no mailbox with this x-role exists. */
            exists = jmapmbox_findxrole(req, args->role);
        }
        if (exists) {
            json_array_append_new(invalid, json_string("role"));
        }
        free(exists);
    }
    if (json_array_size(invalid)) {
        r = 0;
        goto done;
    }

    /* Encode the mailbox name for IMAP. */
    mboxname = jmapmbox_newname(args->name, parentname);
    if (!mboxname) {
        syslog(LOG_ERR, "could not encode mailbox name");
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Create mailbox using parent ACL */
    r = mboxlist_createsync(mboxname, 0 /* MBTYPE */,
            NULL /* partition */,
            req->userid, req->authstate,
            0 /* options */, 0 /* uidvalidity */,
            0 /* highestmodseq */, mbparent->acl,
            NULL /* uniqueid */, 0 /* local_only */,
            NULL /* mboxptr */);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                mboxname, error_message(r));
        goto done;
    }

    /* Write annotations */
    r = jmapmbox_write_annots(req, args, mboxname);
    if (r) goto done;

    /* Lookup and return the new mailbox id */
    r = mboxlist_lookup(mboxname, &mbentry, NULL);
    if (r) goto done;
    *mboxid = xstrdup(mbentry->uniqueid);

done:
    free(mboxname);
    free(parentname);
    mboxlist_entry_free(&mbinbox);
    mboxlist_entry_free(&mbparent);
    mboxlist_entry_free(&mbentry);

    return r;
}

static int jmapmbox_update(jmap_req_t *req,
                           struct setmailboxes_args *args,
                           json_t *invalid,
                           const char *mboxid,
                           json_t **err)
{
    char *mboxname = NULL, *parentname = NULL;
    int r = 0, rights = 0;
    mbentry_t *mbinbox = NULL, *mbentry = NULL, *mbparent = NULL;
    mboxlist_lookup(req->inboxname, &mbinbox, NULL);

    /* Sanity-check arguments */
    if (args->id && strcmp(args->id, mboxid)) {
        json_array_append_new(invalid, json_string("id"));
    }
    if (json_array_size(invalid)) return 0;

    /* Determine current mailbox and parent names */
    if (strcmp(mboxid, mbinbox->uniqueid)) {
        mboxname = jmapmbox_find_uniqueid(req, mboxid);
        if (!mboxname) {
            *err = json_pack("{s:s}", "type", "notFound");
            goto done;
        }
        r = mboxlist_findparent(mboxname, &mbparent);
        if (r) {
            syslog(LOG_INFO, "mboxlist_findparent(%s) failed: %s",
                    mboxname, error_message(r));
            goto done;
        }
        parentname = xstrdup(mbparent->name);
    } else {
        parentname = NULL;
        mboxname = xstrdup(mbinbox->name);
        mboxlist_lookup(mboxname, &mbparent, NULL);
    }
    mboxlist_lookup(mboxname, &mbentry, NULL);

    /* Check ACL */
    rights = jmap_myrights(req, mbentry);
    if (!(rights & ACL_WRITE)) {
        *err = json_pack("{s:s}", "type", "readOnly");
        goto done;
    }

    /* Do we need to move this mailbox to a new parent? */
    int force_rename = 0;

    if (args->parentid) {
        /* Compare old parent with new parent. */
        char *newparentname = NULL;
        if (strcmpsafe(args->parentid, mbinbox->uniqueid)) {
            newparentname = jmapmbox_find_uniqueid(req, args->parentid);
        } else {
            newparentname = xstrdup(mbinbox->name);
        }
        if (!newparentname) {
            json_array_append_new(invalid, json_string("parentId"));
            goto done;
        }

        /* Is this a move ot a new parent? */
        if (strcmpsafe(parentname, newparentname)) {
            /* Check ACL of mailbox */
            if (!(rights & ACL_DELETEMBOX)) {
                *err = json_pack("{s:s}", "type", "readOnly");
                goto done;
            }

            /* Reset pointers to parent */
            free(parentname);
            mboxlist_entry_free(&mbparent);
            parentname = newparentname;
            mboxlist_lookup(mboxname, &mbparent, NULL);
            force_rename = 1;

            /* Check ACL of new parent */
            int parent_rights = jmap_myrights(req, mbparent);
            if (!(parent_rights & ACL_CREATE)) {
                json_array_append_new(invalid, json_string("parentId"));
                goto done;
            }
        } else {
            free(newparentname);
        }
    }

    /* Do we need to rename the mailbox? But only if it isn't the INBOX! */
    if ((args->name || force_rename) && strcmpsafe(mboxname, mbinbox->name)) {
        mbname_t *mbname = mbname_from_intname(mboxname);
        char *oldname = jmapmbox_name(req, mbname);
        mbname_free(&mbname);
        char *name = xstrdup(args->name ? args->name : oldname);

        /* Do old and new mailbox names differ? */
        if (force_rename || strcmpsafe(oldname, name)) {
            char *newmboxname, *oldmboxname;

            /* Determine the unique IMAP mailbox name. */
            newmboxname = jmapmbox_newname(name, parentname);
            if (!newmboxname) {
                syslog(LOG_ERR, "jmapmbox_newname returns NULL: can't rename %s", mboxname);
                r = IMAP_INTERNAL;
                free(oldname);
                goto done;
            }
            oldmboxname = mboxname;

            /* Rename the mailbox. */
            struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_RENAME);
            r = mboxlist_renamemailbox(oldmboxname, newmboxname,
                    NULL /* partition */, 0 /* uidvalidity */,
                    httpd_userisadmin, req->userid, httpd_authstate,
                    mboxevent,
                    0 /* local_only */, 0 /* forceuser */, 0 /* ignorequota */);
            mboxevent_free(&mboxevent);
            if (r) {
                syslog(LOG_ERR, "mboxlist_renamemailbox(old=%s new=%s): %s",
                        oldmboxname, newmboxname, error_message(r));
                free(newmboxname);
                free(oldname);
                goto done;
            }
            free(oldmboxname);
            mboxname = newmboxname;
        }
        free(oldname);
        free(name);
    }

    /* Write annotations */
    r = jmapmbox_write_annots(req, args, mboxname);
    if (r) goto done;

done:
    free(mboxname);
    free(parentname);
    mboxlist_entry_free(&mbentry);
    mboxlist_entry_free(&mbinbox);
    mboxlist_entry_free(&mbparent);

    return r;
}

static int jmapmbox_destroy(jmap_req_t *req, const char *mboxid, int removemsgs, json_t **err)
{
    int r = 0, rights = 0;
    char *mboxname = NULL;
    mbentry_t *mbinbox = NULL, *mbentry = NULL;
    mboxlist_lookup(req->inboxname, &mbinbox, NULL);

    /* Do not allow to remove INBOX. */
    if (!strcmpsafe(mboxid, mbinbox->uniqueid)) {
        *err = json_pack("{s:s}", "type", "forbidden");
        goto done;
    }

    /* Lookup mailbox by id. */
    mboxname = jmapmbox_find_uniqueid(req, mboxid);
    if (!mboxname) {
        *err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    /* Check ACL */
    mboxlist_lookup(mboxname, &mbentry, NULL);
    rights = jmap_myrights(req, mbentry);
    if (!(rights & ACL_DELETEMBOX)) {
        *err = json_pack("{s:s}", "type", "forbidden");
        goto done;
    }

    /* Check if the mailbox has any children. */
    if (jmapmbox_isparent(mboxname)) {
        *err = json_pack("{s:s}", "type", "mailboxHasChild");
        goto done;
    }

    if (!removemsgs) {
        /* Check if the mailbox has any messages */
        struct mailbox *mbox = NULL;
        struct mailbox_iter *iter = NULL;

        r = jmap_openmbox(req, mboxname, &mbox, 0);
        if (r) goto done;
        iter = mailbox_iter_init(mbox, 0, ITER_SKIP_EXPUNGED);
        if (mailbox_iter_step(iter) != NULL) {
            *err = json_pack("{s:s}", "type", "mailboxHasEmail");
        }
        mailbox_iter_done(&iter);
        jmap_closembox(req, &mbox);
        if (*err) goto done;
    }

    /* Destroy mailbox. */
    struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_DELETE);
    if (mboxlist_delayed_delete_isenabled()) {
        r = mboxlist_delayed_deletemailbox(mboxname,
                httpd_userisadmin || httpd_userisproxyadmin,
                req->userid, req->authstate, mboxevent,
                1 /* checkacl */, 0 /* local_only */, 0 /* force */);
    }
    else {
        r = mboxlist_deletemailbox(mboxname,
                httpd_userisadmin || httpd_userisproxyadmin,
                req->userid, req->authstate, mboxevent,
                1 /* checkacl */, 0 /* local_only */, 0 /* force */);
    }
    mboxevent_free(&mboxevent);
    if (r == IMAP_PERMISSION_DENIED) {
        *err = json_pack("{s:s}", "type", "forbidden");
        r = 0;
        goto done;
    }
    else if (r == IMAP_MAILBOX_NONEXISTENT) {
        *err = json_pack("{s:s}", "type", "notFound");
        r = 0;
        goto done;
    }
    else if (r) {
        syslog(LOG_ERR, "failed to delete mailbox(%s): %s",
                mboxname, error_message(r));
        goto done;
    }
    jmap_myrights_delete(req, mboxname);

done:
    mboxlist_entry_free(&mbinbox);
    mboxlist_entry_free(&mbentry);
    free(mboxname);
    return r;
}

static int setMailboxes(jmap_req_t *req)
{
    int r = 0;
    json_t *set = NULL;
    char *mboxname = NULL;
    char *parentname = NULL;
    json_t *state, *create, *update, *destroy;
    int bump_modseq = 0;

    mbentry_t *inboxentry = NULL;
    mboxlist_lookup(req->inboxname, &inboxentry, NULL);

    state = json_object_get(req->args, "ifInState");
    if (JNOTNULL(state)) {
        if (jmap_cmpstate(req, state, 0/*mbtype*/)) {
            json_array_append_new(req->response, json_pack("[s, {s:s}, s]",
                        "error", "type", "stateMismatch", req->tag));
            goto done;
        }
    }
    set = json_pack("{s:s}", "accountId", req->accountid);
    json_object_set_new(set, "oldState", state);

    create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");
        const char *key;
        json_t *arg;

        strarray_t todo = STRARRAY_INITIALIZER;

        /* sort keys topologically */
        json_object_foreach(create, key, arg) {
            /* Validate key. */
            if (!strlen(key)) {
                json_t *err= json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notCreated, key, err);
                continue;
            }

            strarray_append(&todo, key);
        }

        while (strarray_size(&todo)) {
            int didsome = 0;
            int i;

            for (i = 0; i < strarray_size(&todo); i++) {
                key = strarray_nth(&todo, i);
                arg = json_object_get(create, key);

                // check that parentId reference exists
                const char *parentId = json_string_value(json_object_get(arg, "parentId"));
                if (parentId && *parentId == '#' && !hash_lookup(parentId + 1, &req->idmap->mailboxes))
                    continue;

                didsome = 1;

                json_t *invalid = json_pack("[]");
                char *uid = NULL;
                json_t *err = NULL;
                struct setmailboxes_args args;

                /* Process arguments */
                setmailboxes_read_args(req, arg, &args, 1, invalid);
                if (!json_array_size(invalid)) {
                    r = jmapmbox_create(req, &args, invalid, &uid, &err);
                }
                setmailboxes_free_args(&args);

                /* Handle errors */
                if (r) {
                    goto done;
                }
                else if (err) {
                    json_object_set_new(notCreated, key, err);
                    json_decref(invalid);
                    free(strarray_remove(&todo, i--));
                    continue;
                } else if (json_array_size(invalid)) {
                    json_t *err = json_pack("{s:s, s:o}",
                            "type", "invalidProperties", "properties", invalid);
                    json_object_set_new(notCreated, key, err);
                    free(strarray_remove(&todo, i--));
                    continue;
                }
                json_decref(invalid);

                /* Done */
                json_object_set_new(created, key, json_pack("{s:s}", "id", uid));
                hash_insert(key, uid, &req->idmap->mailboxes);
                free(strarray_remove(&todo, i--));
            }

            if (!didsome)
                return IMAP_INTERNAL; // XXX - nice error for missing parent?
        }

        if (json_object_size(created)) {
            json_object_set(set, "created", created);
            bump_modseq = 1;
        }
        json_decref(created);

        if (json_object_size(notCreated)) {
            json_object_set(set, "notCreated", notCreated);
        }
        json_decref(notCreated);

        strarray_fini(&todo);
    }

    update = json_object_get(req->args, "update");
    if (update) {
        json_t *updated = json_pack("{}");
        json_t *notUpdated = json_pack("{}");
        const char *uid;
        json_t *arg;

        json_object_foreach(update, uid, arg) {
            json_t *invalid = json_pack("[]");
            json_t *err = NULL;
            struct setmailboxes_args args;

            /* Process arguments */
            setmailboxes_read_args(req, arg, &args, 0, invalid);
            if (!json_array_size(invalid)) {
                r = jmapmbox_update(req, &args, invalid, uid, &err);
            }
            setmailboxes_free_args(&args);

            /* Handle errors */
            if (r) {
                goto done;
            }
            else if (err) {
                json_object_set_new(notUpdated, uid, err);
                json_decref(invalid);
                continue;
            }
            else if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notUpdated, uid, err);
                continue;
            }
            json_decref(invalid);

            /* Done */
            json_object_set_new(updated, uid, json_null());
        }

        if (json_object_size(updated)) {
            json_object_set(set, "updated", updated);
            bump_modseq = 1;
        }
        json_decref(updated);

        if (json_object_size(notUpdated)) {
            json_object_set(set, "notUpdated", notUpdated);
        }
        json_decref(notUpdated);
    }

    destroy = json_object_get(req->args, "destroy");
    if (destroy) {
        json_t *destroyed = json_pack("[]");
        json_t *notDestroyed = json_pack("{}");

        size_t index;
        json_t *juid;
        int removemsgs =
            json_object_get(req->args, "onDestroyRemoveMessages") == json_true();

        json_array_foreach(destroy, index, juid) {

            /* Validate uid. */
            const char *uid = json_string_value(juid);
            if (!uid) {
                continue;
            }
            if (uid && uid[0] == '#') {
                const char *newuid = hash_lookup(uid + 1, &req->idmap->mailboxes);
                if (!newuid) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notDestroyed, uid, err);
                    continue;
                }
                uid = newuid;
            }

            json_t *err = NULL;
            r = jmapmbox_destroy(req, uid, removemsgs, &err);
            if (r)  {
                goto done;
            }
            else if (err) {
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }

            /* Report mailbox as destroyed. */
            json_array_append_new(destroyed, json_string(uid));
        }
        if (json_array_size(destroyed)) {
            json_object_set(set, "destroyed", destroyed);
            bump_modseq = 1;
        }
        json_decref(destroyed);
        if (json_object_size(notDestroyed)) {
            json_object_set(set, "notDestroyed", notDestroyed);
        }
        json_decref(notDestroyed);
    }

    if (bump_modseq) jmap_bumpstate(req, 0);
    json_object_set_new(set, "newState", jmap_getstate(req, 0/*mbtype*/));

    json_incref(set);
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("Mailbox/set"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    free(mboxname);
    free(parentname);
    mboxlist_entry_free(&inboxentry);
    if (set) json_decref(set);
    return r;
}

struct jmapmbox_getupdates_data {
    json_t *changed;        /* maps mailbox ids to {id:foldermodseq} */
    json_t *removed;        /* maps mailbox ids to {id:foldermodseq} */
    modseq_t sincemodseq;
    int *only_counts_changed;
    jmap_req_t *req;
};

static int jmapmbox_getupdates_cb(const mbentry_t *mbentry, void *rock)
{
    struct jmapmbox_getupdates_data *data = rock;
    json_t *updates, *update;
    struct statusdata sdata;
    modseq_t modseq, mbmodseq;
    jmap_req_t *req = data->req;

    /* Ignore anything but regular mailboxes */
    if (mbentry->mbtype & ~(MBTYPE_DELETED)) {
        return 0;
    }

    /* Lookup status. */
    if (!(mbentry->mbtype & MBTYPE_DELETED)) {
        int r = status_lookup(mbentry->name, data->req->userid,
                              STATUS_HIGHESTMODSEQ, &sdata);
        if (r) return r;
        mbmodseq = sdata.highestmodseq;
    } else {
        mbmodseq = mbentry->foldermodseq;
    }

    /* Ignore old changes */
    if (mbmodseq <= data->sincemodseq) {
        return 0;
    }

    /* Is this a more recent update for an id that we have already seen? */
    if ((update = json_object_get(data->removed, mbentry->uniqueid))) {
        modseq = (modseq_t)json_integer_value(json_object_get(update, "modseq"));
        if (modseq <= mbmodseq) {
            json_object_del(data->removed, mbentry->uniqueid);
        } else {
            return 0;
        }
    }
    if ((update = json_object_get(data->changed, mbentry->uniqueid))) {
        modseq = (modseq_t)json_integer_value(json_object_get(update, "modseq"));
        if (modseq <= mbmodseq) {
            json_object_del(data->changed, mbentry->uniqueid);
        } else {
            return 0;
        }
    }

    /* Did any of the mailbox metadata change? */
    if (mbentry->foldermodseq > data->sincemodseq) {
        *(data->only_counts_changed) = 0;
    }

    /* OK, report that update. Note that we even report hidden mailboxes
     * in order to allow clients remove unshared and deleted mailboxes */
    update = json_pack("{s:s s:i}", "id", mbentry->uniqueid, "modseq", mbmodseq);
    int rights = jmap_myrights(req, mbentry);
    if ((mbentry->mbtype & MBTYPE_DELETED) || !(rights & ACL_LOOKUP)) {
        updates = data->removed;
    } else {
        updates = data->changed;
    }
    json_object_set_new(updates, mbentry->uniqueid, update);

    return 0;
}

static int jmapmbox_getupdates_cmp(const void **pa, const void **pb)
{
    const json_t *a = *pa, *b = *pb;
    modseq_t ma, mb;

    ma = (modseq_t) json_integer_value(json_object_get(a, "modseq"));
    mb = (modseq_t) json_integer_value(json_object_get(b, "modseq"));

    if (ma < mb)
        return -1;
    if (ma > mb)
        return 1;
    return 0;
}

static int jmapmbox_getupdates(jmap_req_t *req, modseq_t sincemodseq,
                               size_t limit,
                              json_t **changed, json_t **removed,
                               int *has_more, json_t **newstate,
                               int *only_counts_changed)
{
    *only_counts_changed = 1;

    ptrarray_t updates = PTRARRAY_INITIALIZER;
    struct jmapmbox_getupdates_data data = {
        json_pack("{}"),
        json_pack("{}"),
        sincemodseq,
        only_counts_changed,
        req
    };
    modseq_t windowmodseq;
    const char *id;
    json_t *val;
    int r, i;


    /* Search for updates */
    r = jmap_allmbox(req, jmapmbox_getupdates_cb, &data);
    if (r) goto done;

    /* Sort updates by modseq */
    json_object_foreach(data.changed, id, val) {
        ptrarray_add(&updates, val);
    }
    json_object_foreach(data.removed, id, val) {
        ptrarray_add(&updates, val);
    }
    ptrarray_sort(&updates, jmapmbox_getupdates_cmp);

    /* Build result */
    *changed = json_pack("[]");
    *removed = json_pack("[]");
    *has_more = 0;
    windowmodseq = 0;
    for (i = 0; i < updates.count; i++) {
        json_t *update = ptrarray_nth(&updates, i);
        const char *id = json_string_value(json_object_get(update, "id"));
        modseq_t modseq = json_integer_value(json_object_get(update, "modseq"));

        if (limit && ((size_t) i) >= limit) {
            *has_more = 1;
            break;
        }

        if (windowmodseq < modseq)
            windowmodseq = modseq;

        if (json_object_get(data.changed, id)) {
            json_array_append_new(*changed, json_string(id));
        } else {
            json_array_append_new(*removed, json_string(id));
        }
    }

    if (!json_array_size(*changed) && !json_array_size(*removed)) {
        *only_counts_changed = 0;
    }
    *newstate = jmap_fmtstate(*has_more ? windowmodseq : jmap_highestmodseq(req, 0/*mbtype*/));

    if (!json_array_size(*changed)) {
        json_decref(*changed);
        *changed = json_null();
    }
    if (!json_array_size(*removed)) {
        json_decref(*removed);
        *removed = json_null();
    }

done:
    if (data.changed) json_decref(data.changed);
    if (data.removed) json_decref(data.removed);
    ptrarray_fini(&updates);
    return r;
}

static int getMailboxesUpdates(jmap_req_t *req)
{
    int r = 0, pe;
    int has_more = 0, only_counts_changed = 0;
    json_t *changed, *removed, *invalid, *item, *res;
    json_int_t max_changes = 0;
    json_t *oldstate, *newstate;
    const char *since;

    /* Parse and validate arguments. */
    invalid = json_pack("[]");

    /* sinceState */
    pe = readprop(req->args, "sinceState", 1, invalid, "s", &since);
    if (pe > 0 && !atomodseq_t(since)) {
        json_array_append_new(invalid, json_string("sinceState"));
    }
    /* maxChanges */
    pe = readprop(req->args, "maxChanges", 0, invalid, "I", &max_changes);
    if (pe > 0 && max_changes < 0) {
        json_array_append_new(invalid, json_string("maxChanges"));
    }

    /* Bail out for argument errors */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Search for updates */
    r = jmapmbox_getupdates(req, atomodseq_t(since), max_changes,
                            &changed, &removed, &has_more, &newstate,
                            &only_counts_changed);
    if (r) goto done;
    oldstate = json_string(since);

    /* Prepare response */
    res = json_pack("{}");
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_object_set_new(res, "oldState", oldstate);
    json_object_set_new(res, "newState", newstate);
    json_object_set_new(res, "hasMoreUpdates", json_boolean(has_more));
    json_object_set_new(res, "changed", changed);
    json_object_set_new(res, "removed", removed);
    json_object_set_new(res, "changedProperties", only_counts_changed ?
            json_pack("[s,s,s,s]", "totalEmails", "unreadEmails",
                                   "totalThreads", "unreadThreads") :
            json_null());
    item = json_pack("[]");
    json_array_append_new(item, json_string("Mailbox/changes"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    return r;
}

/*
 * Emails
 */

static json_t *emailer_from_addr(const struct address *a)
{
    json_t *emailers = json_pack("[]");
    struct buf buf = BUF_INITIALIZER;

    while (a) {
        json_t *e = json_pack("{}");
        const char *mailbox = a->mailbox ? a->mailbox : "";
        const char *domain = a->domain ? a->domain : "";

        if (!strcmp(domain, "unspecified-domain")) {
            domain = "";
        }
        buf_printf(&buf, "%s@%s", mailbox, domain);

        if (a->name) {
            char *dec = charset_decode_mimeheader(a->name, CHARSET_SNIPPET);
            if (dec) {
                json_object_set_new(e, "name", json_string(dec));
            }
            free(dec);
        } else {
            json_object_set_new(e, "name", json_string(""));
        }

        json_object_set_new(e, "email", json_string(buf_cstring(&buf)));

        json_array_append_new(emailers, e);
        buf_reset(&buf);
        a = a->next;
    }

    if (!json_array_size(emailers)) {
        json_decref(emailers);
        emailers = json_null();
    }

    buf_free(&buf);
    return emailers;
}

/* Generate a preview of text of at most len bytes, excluding the zero
 * byte.
 *
 * Consecutive whitespaces, including newlines, are collapsed to a single
 * blank. If text is longer than len and len is greater than 4, then return
 * a string  ending in '...' and holding as many complete UTF-8 characters,
 * that the total byte count of non-zero characters is at most len.
 *
 * The input string must be properly encoded UTF-8 */
static char *extract_preview(const char *text, size_t len)
{
    unsigned char *dst, *d, *t;
    size_t n;

    if (!text) {
        return NULL;
    }

    /* Replace all whitespace with single blanks. */
    dst = (unsigned char *) xzmalloc(len+1);
    for (t = (unsigned char *) text, d = dst; *t && d < (dst+len); ++t, ++d) {
        *d = isspace(*t) ? ' ' : *t;
        if (isspace(*t)) {
            while(isspace(*++t))
                ;
            --t;
        }
    }
    n = d - dst;

    /* Anything left to do? */
    if (n < len || len <= 4) {
        return (char*) dst;
    }

    /* Append trailing ellipsis. */
    dst[--n] = '.';
    dst[--n] = '.';
    dst[--n] = '.';
    while (n && (dst[n] & 0xc0) == 0x80) {
        dst[n+2] = 0;
        dst[--n] = '.';
    }
    if (dst[n] >= 0x80) {
        dst[n+2] = 0;
        dst[--n] = '.';
    }
    return (char *) dst;
}

static void extract_plain_cb(const struct buf *buf, void *rock)
{
    struct buf *dst = (struct buf*) rock;
    const char *p;
    int seenspace = 0;

    /* Just merge multiple space into one. That's similar to
     * charset_extract's MERGE_SPACE but since we don't want
     * it to canonify the text into search form */
    for (p = buf_base(buf); p < buf_base(buf) + buf_len(buf) && *p; p++) {
        if (*p == ' ') {
            if (seenspace) continue;
            seenspace = 1;
        } else {
            seenspace = 0;
        }
        buf_appendmap(dst, p, 1);
    }
}

static char *extract_plain(const char *html) {
    struct buf src = BUF_INITIALIZER;
    struct buf dst = BUF_INITIALIZER;
    charset_t utf8 = charset_lookupname("utf8");
    char *text;
    char *tmp, *q;
    const char *p;

    /* Replace <br> and <p> with newlines */
    q = tmp = xstrdup(html);
    p = html;
    while (*p) {
        if (!strncmp(p, "<br>", 4) || !strncmp(p, "</p>", 4)) {
            *q++ = '\n';
            p += 4;
        }
        else if (!strncmp(p, "p>", 3)) {
            p += 3;
        } else {
            *q++ = *p++;
        }
    }
    *q = 0;

    /* Strip html tags */
    buf_init_ro(&src, tmp, q - tmp);
    buf_setcstr(&dst, "");
    charset_extract(&extract_plain_cb, &dst,
            &src, utf8, ENCODING_NONE, "HTML", CHARSET_SNIPPET);
    buf_cstring(&dst);

    /* Trim text */
    buf_trim(&dst);
    text = buf_releasenull(&dst);
    if (!strlen(text)) {
        free(text);
        text = NULL;
    }

    buf_free(&src);
    free(tmp);
    charset_free(&utf8);

    return text;
}

struct jmapmsg_mailboxes_data {
    jmap_req_t *req;
    json_t *mboxs;
};

static int jmapmsg_mailboxes_cb(const conv_guidrec_t *rec, void *rock)
{
    struct jmapmsg_mailboxes_data *data = (struct jmapmsg_mailboxes_data*) rock;
    json_t *mboxs = data->mboxs;
    jmap_req_t *req = data->req;
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    uint32_t flags;
    int r;

    if (rec->part) return 0;

    r = jmap_openmbox(req, rec->mboxname, &mbox, 0);
    if (r) return r;

    r = msgrecord_find(mbox, rec->uid, &mr);
    if (r) goto done;

    r = msgrecord_get_systemflags(mr, &flags);
    if (r) goto done;

    if (!r && !(flags & (FLAG_EXPUNGED|FLAG_DELETED))) {
        json_object_set_new(mboxs, mbox->uniqueid, json_string(mbox->name));
    }


done:
    if (mr) msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);
    return r;
}

/*
 * Lookup all mailboxes where msgid is contained in.
 *
 * The return value is a JSON object keyed by the mailbox unique id,
 * and its mailbox name as value.
 */
static json_t* jmapmsg_mailboxes(jmap_req_t *req, const char *msgid)
{
    struct jmapmsg_mailboxes_data data = { req, json_pack("{}") };

    conversations_guid_foreach(req->cstate, msgid+1, jmapmsg_mailboxes_cb, &data);

    return data.mboxs;
}

struct attachment {
    struct body *body;
};

struct msgbodies {
    struct body *text;
    struct body *html;
    ptrarray_t atts;
    ptrarray_t msgs;
    ptrarray_t textlist;
    ptrarray_t htmllist;
};

#define MSGBODIES_INITIALIZER { \
    NULL, \
    NULL, \
    PTRARRAY_INITIALIZER, \
    PTRARRAY_INITIALIZER, \
    PTRARRAY_INITIALIZER, \
    PTRARRAY_INITIALIZER \
}

static int find_msgbodies(struct body *root, struct buf *msg_buf,
                          struct msgbodies *bodies)
{
    /* Dissect a message into its best text and html bodies, attachments
     * and embedded messages. Based on the IMAPTalk find_message function.
     * See
     * https://github.com/robmueller/mail-imaptalk/blob/master/IMAPTalk.pm
     */

    ptrarray_t *work = ptrarray_new();
    int i;

    struct partrec {
        int inside_alt;
        int inside_enc;
        int inside_rel;
        int partno;
        struct body *part;
        struct body *parent;
    } *rec;

    ptrarray_t *altlist = NULL;

    rec = xzmalloc(sizeof(struct partrec));
    rec->part = root;
    rec->partno = 1;
    ptrarray_push(work, rec);

    while ((rec = ptrarray_shift(work))) {
        char *disp = NULL, *dispfile = NULL;
        struct body *part = rec->part;
        struct param *param;
        int is_inline = 0;
        int is_attach = 1;

        /* Determine content disposition */
        if (part->disposition) {
            disp = ucase(xstrdup(part->disposition));
        }
        for (param = part->disposition_params; param; param = param->next) {
            if (!strncasecmp(param->attribute, "filename", 8)) {
                dispfile = ucase(xstrdup(param->value));
                break;
            }
        }

        /* Search for inline text */
        if ((!strcmp(part->type, "TEXT")) &&
            (!strcmp(part->subtype, "PLAIN") ||
             !strcmp(part->subtype, "TEXT")  ||
             !strcmp(part->subtype, "ENRICHED") ||
             !strcmp(part->subtype, "HTML")) &&
             (!disp || strcmp(disp, "ATTACHMENT"))) {
            /* Text that isn't an attachment */
            is_inline = 1;
        }
        if ((!strcmp(part->type, "APPLICATION")) &&
            (!strcmp(part->subtype, "OCTET-STREAM")) &&
            (rec->inside_enc && strstr(dispfile, "ENCRYPTED"))) {
            /* PGP octet-stream inside an pgp-encrypted part */
            is_inline = 1;
        }
        /* If not the first part and has filename, assume attachment */
        if (rec->partno > 0 && dispfile) {
            is_inline = 0;
        }

        if (is_inline) {
            /* The IMAPTalk code is a bit more sophisticated in determining
             * if a body is text or html (see its KnownTextParts variable).
             * But we don't care here: anything that is inlined and isn't
             * HTML is treated as text. */
            int is_html = !strcasecmp(part->subtype, "HTML");
            struct body **bodyp = is_html ? &bodies->html : &bodies->text;

            if (*bodyp == NULL) {
                /* Haven't yet found a body for this type */
                if (!is_html || rec->partno <= 1 || !rec->parent ||
                    strcmp(rec->parent->type, "MULTIPART") ||
                    strcmp(rec->parent->subtype, "MIXED")) {

                    /* Don't treat html parts in a multipart/mixed as an
                       alternative representation unless the first part */
                    *bodyp = part;
                }
            } else if ((*bodyp)->content_size <= 10 && part->content_size > 10) {
                /* Override very small parts e.g. five blank lines */
                *bodyp = part;
            } else if (msg_buf) {
                /* Override parts with zero lines with multi-lines */
                const char *base = msg_buf->s + (*bodyp)->content_offset;
                size_t len = (*bodyp)->content_size;

                if (!memchr(base, '\n', len)) {
                    base = msg_buf->s + part->content_offset;
                    len = part->content_size;
                    if (memchr(base, '\n', len)) {
                        *bodyp = part;
                    }
                }
            }

            /* Add to textlist/htmllist */
            if (!is_html || !rec->inside_alt) {
                ptrarray_append(&bodies->textlist, part);
                altlist = &bodies->textlist;
            }
            if (is_html || !rec->inside_alt) {
                ptrarray_append(&bodies->htmllist, part);
                altlist = &bodies->htmllist;
            }

            is_attach = 0;
        }
        else if (!strcmp(part->type, "IMAGE") &&
                (!disp || strcmp(disp, "ATTACHMENT")) &&
                altlist) {
            /* Add inline images in alternative parts, but
             * only to the alternative (text or html) we're in */
            ptrarray_append(altlist, part);
        }
        else if (!strcmp(part->type, "MULTIPART")) {
            int prio = 0;
            is_attach = 0;

            /* Determine the multipart type and priority */
            if (!strcmp(part->subtype, "SIGNED")) {
                prio = 1;
            }
            else if (!strcmp(part->subtype, "ALTERNATIVE")) {
                rec->inside_alt = 1;
                prio = 1;
            }
            else if (!strcmp(part->subtype, "RELATED")) {
                rec->inside_rel = 1;
                prio = 1;
            }
            else if (!disp || strcmp(disp, "ATTACHMENT")) {
                prio = 1;
            }
            else if (!strcmp(part->subtype, "ENCRYPTED")) {
                rec->inside_enc = 1;
            }

            /* Prioritize signed/alternative/related sub-parts, otherwise
             * look at it once we've seen all other parts at current level */
            for (i = 0; i < part->numparts; i++) {
                struct partrec *subrec;

                subrec = xzmalloc(sizeof(struct partrec));
                *subrec = *rec;
                subrec->parent = part;


                if (prio) {
                    subrec->partno = part->numparts - i;
                    subrec->part = part->subpart + subrec->partno - 1;
                    ptrarray_insert(work, 0, subrec);
                } else  {
                    subrec->partno = i + 1;
                    subrec->part = part->subpart + subrec->partno - 1;
                    ptrarray_push(work, subrec);
                }
            }
        }

        if (is_attach) {
            if (!strcmp(part->type, "MESSAGE") &&
                !strcmp(part->subtype, "RFC822") &&
                part != root) {
                ptrarray_push(&bodies->msgs, part);
            } else {
                ptrarray_push(&bodies->atts, part);
            }
        }

        if (disp) free(disp);
        if (dispfile) free(dispfile);
        free(rec);
    }

    assert(work->count == 0);
    ptrarray_free(work);

    return 0;
}

static int extract_headers(const char *key, const char *val, void *rock)
{
    json_t *headers = (json_t*) rock;
    json_t *curval;
    char *decodedval = NULL;
    char *lckey = xstrdup(key);
    char *p;
    for (p = lckey; *p; p++) {
        *p = tolower(*p);
    }

    if (isspace(*val)) val++;

    decodedval = charset_decode_mimeheader(val, CHARSET_SNIPPET);
    if (!decodedval) goto done;

    if ((curval = json_object_get(headers, lckey))) {
        char *newval = strconcat(json_string_value(curval), "\n", decodedval, NULL);
        json_object_set_new(headers, lckey, json_string(newval));
        free(newval);
    } else {
        json_object_set_new(headers, lckey, json_string(decodedval));
    }

done:
    free(lckey);
    free(decodedval);
    return  0;
}

static int extract_annotations(const char *mboxname __attribute__((unused)),
                               uint32_t uid __attribute__((unused)),
                               const char *entry,
                               const char *userid __attribute__((unused)),
                               const struct buf *value,
                               const struct annotate_metadata *mdata __attribute__((unused)),
                               void *rock)
{
    json_t *annotations = (json_t *)rock;

    const char *prefix = "/vendor/jmapio/";
    size_t prefixlen = strlen(prefix);

    if (!strncmp(entry, prefix, prefixlen)) {
        json_object_set_new(annotations, entry + prefixlen, json_string(buf_cstring(value)));
    }

    return 0;
}

static char *jmap_msgid(const struct message_guid *guid)
{
    char *msgid = xzmalloc(26);
    msgid[0] = 'M';
    memcpy(msgid+1, message_guid_encode(guid), 24);
    return msgid;
}

static char *jmap_thrid(conversation_id_t cid)
{
    char *thrid = xzmalloc(18);
    thrid[0] = 'T';
    memcpy(thrid+1, conversation_id_encode(cid), 16);
    return thrid;
}

static conversation_id_t jmap_decode_thrid(const char *thrid)
{
    conversation_id_t cid = 0;
    if (thrid[0] == 'T')
        conversation_id_decode(&cid, thrid+1);
    return cid;
}

static int is_valid_keyword(const char *keyword)
{
    const char *p;

    if (*keyword == '\0') {
        return 0;
    }
    if (strlen(keyword) > 255) {
        return 0;
    }
    for (p = keyword; *p; p++) {
        if (*p < 0x21 || *p > 0x7e) {
            return 0;
        }
        switch(*p) {
            case '(':
            case ')':
            case '{':
            case ']':
            case '%':
            case '*':
            case '"':
            case '\\':
                return 0;
            default:
                ;
        }
    }
    return 1;
}

static const char *jmap_keyword_from_imap(const char *flag)
{
    if (!strcmp(flag, "\\Seen")) {
        return "$Seen";
    }
    else if (!strcmp(flag, "\\Flagged")) {
        return "$Flagged";
    }
    else if (!strcmp(flag, "\\Answered")) {
        return "$Answered";
    }
    else if (!strcmp(flag, "\\Draft")) {
        return "$Draft";
    }
    else if (*flag != '\\') {
        return flag;
    }
    return NULL;
}

static const char *jmap_keyword_to_imap(const char *keyword)
{
    if (!strcmp(keyword, "$Seen")) {
        return "\\Seen";
    }
    else if (!strcmp(keyword, "$Flagged")) {
        return "\\Flagged";
    }
    else if (!strcmp(keyword, "$Answered")) {
        return "\\Answered";
    }
    else if (!strcmp(keyword, "$Draft")) {
        return "\\Draft";
    }
    else if (is_valid_keyword(keyword)) {
        return keyword;
    }
    return NULL;
}

static json_t *jmapmsg_annot_read(const jmap_req_t *req, msgrecord_t *mr,
                                  const char *annot, int structured)
{
    struct buf buf = BUF_INITIALIZER;
    json_t *annotvalue = NULL;

    if (!strncmp(annot, "/shared/", 8)) {
        msgrecord_annot_lookup(mr, annot+7, /*userid*/"", &buf);
    }
    else if (!strncmp(annot, "/private/", 9)) {
        msgrecord_annot_lookup(mr, annot+7, req->userid, &buf);
    }
    else {
        msgrecord_annot_lookup(mr, annot+7, "", &buf);
    }
    if (buf_len(&buf)) {
        if (structured) {
            json_error_t jerr;
            annotvalue = json_loads(buf_base(&buf), JSON_DECODE_ANY, &jerr);
            /* XXX - log error? */
        }
        else {
            annotvalue = json_string(buf_cstring(&buf));
        }

        if (!annotvalue) {
            syslog(LOG_ERR, "jmap: annotation %s has bogus value", annot);
        }
    }

    buf_free(&buf);

    return annotvalue;
}

/* Replace any <HTML> and </HTML> tags in t with <DIV> and </DIV>,
 * writing results into buf */
static void _extract_htmlbody(struct buf *buf, const char *t)
{
    const char *top = t + strlen(t);
    const char *p = t, *q = p;

    while (*q) {
        const char *tag = NULL;
        if (q < top - 5 && !strncasecmp(q, "<html", 5) &&
                (*(q+5) == '>' || isspace(*(q+5)))) {
            /* Found a <HTML> tag */
            tag = "<div>";
        }
        else if (q < top - 6 && !strncasecmp(q, "</html", 6) &&
                (*(q+6) == '>' || isspace(*(q+6)))) {
            /* Found a </HTML> tag */
            tag = "</div>";
        }

        /* No special tag? */
        if (!tag) {
            q++;
            continue;
        }

        /* Append whatever we saw since the last HTML tag. */
        buf_appendmap(buf, p, q - p);

        /* Look for the end of the tag and replace it, even if
         * it prematurely ends at the end of the buffer . */
        while (*q && *q != '>') { q++; }
        buf_appendcstr(buf, tag);
        if (*q) q++;

        /* Prepare for next loop */
        p = q;
    }
    buf_appendmap(buf, p, q - p);
}

static json_t *attachment_from_part(struct body *part,
                                    const struct buf *msg_buf,
                                    json_t *inlinedcids,
                                    json_t *imgsizes)
{
    struct param *param;
    charset_t ascii = charset_lookupname("us-ascii");
    const char *cid;
    strarray_t headers = STRARRAY_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    char *freeme;

    char *blobid = jmap_blobid(&part->content_guid);
    json_t *att = json_pack("{s:s}", "blobId", blobid);
    free(blobid);

    /* type */
    buf_setcstr(&buf, part->type);
    if (part->subtype) {
        buf_appendcstr(&buf, "/");
        buf_appendcstr(&buf, part->subtype);
    }
    json_object_set_new(att, "type", json_string(buf_lcase(&buf)));

    /* name */
    const char *fname = NULL;
    int is_extended = 0;
    for (param = part->disposition_params; param; param = param->next) {
        if (!strncasecmp(param->attribute, "filename", 8)) {
            is_extended = param->attribute[8] == '*';
            fname = param->value;
            break;
        }
    }
    if (!fname) {
        for (param = part->params; param; param = param->next) {
            if (!strncasecmp(param->attribute, "name", 4)) {
                is_extended = param->attribute[4] == '*';
                fname = param->value;
                break;
            }
        }
    }
    if (fname && is_extended) {
        char *s = charset_parse_mimexvalue(fname, NULL);
        json_object_set_new(att, "name", s ? json_string(s) : json_null());
        free(s);
    }
    else if (fname) {
        int mime_flags = charset_flags & CHARSET_MIME_UTF8;
        char *s = charset_parse_mimeheader(fname, mime_flags);
        json_object_set_new(att, "name", s ? json_string(s) : json_null());
        free(s);
    }
    else {
        json_object_set_new(att, "name", json_null());
    }

    /* size */
    if (part->charset_enc) {
        buf_reset(&buf);
        charset_decode(&buf, msg_buf->s + part->content_offset,
                part->content_size, part->charset_enc);
        json_object_set_new(att, "size", json_integer(buf_len(&buf)));
    } else {
        json_object_set_new(att, "size", json_integer(part->content_size));
    }

    /* cid */
    strarray_add(&headers, "Content-ID");
    freeme = xstrndup(msg_buf->s + part->header_offset, part->header_size);
    message_pruneheader(freeme, &headers, NULL);
    if ((cid = strchr(freeme, ':'))) {
        char *unfolded;
        if ((unfolded = charset_unfold(cid + 1, strlen(cid), 0))) {
            buf_setcstr(&buf, unfolded);
            free(unfolded);
            buf_trim(&buf);
            cid = buf_cstring(&buf);
        } else {
            cid = NULL;
        }
    }
    json_object_set_new(att, "cid", cid ? json_string(cid) : json_null());
    free(freeme);

    /* isInline */
    if (inlinedcids && cid && json_object_get(inlinedcids, cid)) {
        json_object_set_new(att, "isInline", json_true());
    }
    else {
        json_object_set_new(att, "isInline", json_false());
    }

    /* width, height */
    json_t *width = json_null(), *height = json_null(), *dim;
    if (imgsizes && (dim = json_object_get(imgsizes, part->part_id))) {
        if (json_array_size(dim) >= 2) {
            width = json_incref(json_array_get(dim, 0));
            height = json_incref(json_array_get(dim, 1));
        }
    }
    json_object_set_new(att, "width", width);
    json_object_set_new(att, "height", height);

    charset_free(&ascii);
    strarray_fini(&headers);
    buf_free(&buf);

    return att;
}

static int jmapmsg_from_body(jmap_req_t *req, hash_table *props,
                             struct body *body, struct buf *msg_buf,
                             msgrecord_t *mr, MsgType type,
                             json_t **msgp)
{
    struct msgbodies bodies = MSGBODIES_INITIALIZER;
    json_t *msg = NULL;
    json_t *headers = json_pack("{}");
    json_t *annotations = json_pack("{}");
    struct buf buf = BUF_INITIALIZER;
    char *text = NULL, *html = NULL;
    int r;

    const char *preview_annot = config_getstring(IMAPOPT_JMAP_PREVIEW_ANNOT);
    int render_multipart_bodies = config_getswitch(IMAPOPT_JMAP_RENDER_MULTIPART_BODIES);

    /* Dissect message into its parts */
    r = find_msgbodies(body, msg_buf, &bodies);
    if (r) goto done;

    /* Always read the message headers */
    r = message_foreach_header(msg_buf->s + body->header_offset,
                               body->header_size, extract_headers, headers);
    if (r) goto done;

    r = msgrecord_annot_findall(mr, "*", extract_annotations, annotations);
    if (r) goto done;

    msg = json_pack("{}");

    /* headers */
    if (_wantprop(props, "headers")) {
        json_object_set(msg, "headers", headers);
    }
    else {
        json_t *wantheaders = json_pack("{}");
        struct buf buf = BUF_INITIALIZER;
        buf_setcstr(&buf, "headers.");
        const char *key;
        json_t *val;
        json_object_foreach(headers, key, val) {
            buf_truncate(&buf, 8);
            buf_appendcstr(&buf, key);
            if (_wantprop(props, buf_cstring(&buf))) {
                json_object_set(wantheaders, key, val);
            }
        }

        buf_free(&buf);
        if (json_object_size(wantheaders))
            json_object_set_new(msg, "headers", wantheaders);
        else
            json_decref(wantheaders);
    }

    /* annotations */
    if (_wantprop(props, "annotations")) {
        json_object_set(msg, "annotations", annotations);
    }
    else {
        json_t *wantannotations = json_pack("{}");
        buf_setcstr(&buf, "annotations.");
        const char *key;
        json_t *val;
        json_object_foreach(annotations, key, val) {
            buf_truncate(&buf, 8);
            buf_appendcstr(&buf, key);
            if (_wantprop(props, buf_cstring(&buf))) {
                json_object_set(wantannotations, key, val);
            }
        }
        if (json_object_size(wantannotations))
            json_object_set_new(msg, "annotations", wantannotations);
        else
            json_decref(wantannotations);
    }


    /* sender */
    if (_wantprop(props, "sender")) {
        const char *key, *s = NULL;
        json_t *val, *sender = json_null();

        json_object_foreach(headers, key, val) {
            if (!strcasecmp(key, "Sender")) {
                s = json_string_value(val);
                break;
            }
        }
        if (s) {
            struct address *addr = NULL;
            parseaddr_list(s, &addr);
            if (addr) {
                json_t *senders = emailer_from_addr(addr);
                if (json_array_size(senders)) {
                    sender = json_array_get(senders, 0);
                    json_incref(sender);
                }
                json_decref(senders);
            }
            parseaddr_free(addr);
        }
        json_object_set_new(msg, "sender", sender);
    }
    /* from */
    if (_wantprop(props, "from")) {
        json_object_set_new(msg, "from", emailer_from_addr(body->from));
    }
    /* to */
    if (_wantprop(props, "to")) {
        json_object_set_new(msg, "to", emailer_from_addr(body->to));
    }
    /* cc */
    if (_wantprop(props, "cc")) {
        json_object_set_new(msg, "cc", emailer_from_addr(body->cc));
    }
    /*  bcc */
    if (_wantprop(props, "bcc")) {
        json_object_set_new(msg, "bcc", emailer_from_addr(body->bcc));
    }
    /* replyTo */
    if (_wantprop(props, "replyTo")) {
        json_t *reply_to = json_null();
        if (json_object_get(headers, "reply-to")) {
            reply_to = emailer_from_addr(body->reply_to);
        }
        json_object_set_new(msg, "replyTo", reply_to);
    }
    /* subject */
    if (_wantprop(props, "subject")) {
        char *subject = NULL;
        if (body->subject) {
            subject = charset_decode_mimeheader(body->subject, CHARSET_SNIPPET);
        }
        json_object_set_new(msg, "subject", json_string(subject ? subject : ""));
        free(subject);
    }
    /* receivedAt */
    if (_wantprop(props, "receivedAt")) {
        char datestr[RFC3339_DATETIME_MAX];
        time_t t;

        r = msgrecord_get_internaldate(mr, &t);
        if (r) return r;

        if (type == MSG_IS_ATTACHED)
            time_from_rfc5322(body->date, &t, DATETIME_FULL);

        time_to_rfc3339(t, datestr, RFC3339_DATETIME_MAX);
        json_object_set_new(msg, "receivedAt", json_string(datestr));
    }
    /* sentAt */
    if (_wantprop(props, "sentAt")) {
        json_t *jval = json_object_get(headers, "date");
        if (jval) {
            char *p, *headerval = xstrdup(json_string_value(jval));
            for (p = headerval; *p; p++) {
                if (*p == '\n') *p = ' ';
            }
            time_t t;
            if (time_from_rfc822(headerval, &t) != -1) {
                char datestr[RFC3339_DATETIME_MAX];
                time_to_rfc3339(t, datestr, RFC3339_DATETIME_MAX);
                json_object_set_new(msg, "sentAt", json_string(datestr));
            }
            free(headerval);
        }
    }

    if (_wantprop(props, "textBody") ||
        _wantprop(props, "htmlBody") ||
        (_wantprop(props, "preview") && !preview_annot) ||
        _wantprop(props, "body")) {

        if (bodies.textlist.count > 1 && render_multipart_bodies) {
            /* Concatenate all plain text bodies and replace any
             * inlined images with placeholders. */
            int i;
            for (i = 0; i < bodies.textlist.count; i++) {
                struct body *part = ptrarray_nth(&bodies.textlist, i);

                if (i) buf_appendcstr(&buf, "\n");

                if (!strcmp(part->type, "TEXT")) {
                    charset_t cs = charset_lookupname(part->charset_id);
                    char *t = charset_to_utf8(msg_buf->s + part->content_offset,
                                              part->content_size, cs, part->charset_enc);
                    if (t) buf_appendcstr(&buf, t);
                    charset_free(&cs);
                    free(t);
                }
                else if (!strcmp(part->type, "IMAGE")) {
					struct param *param;
                    const char *fname = NULL;
                    for (param = part->disposition_params; param; param = param->next) {
                        if (!strncasecmp(param->attribute, "filename", 8)) {
                            fname =param->value;
                            break;
                        }
                    }
                    buf_appendcstr(&buf, "[Inline image");
                    if (fname) {
                        buf_appendcstr(&buf, ":");
                        buf_appendcstr(&buf, fname);
                    }
                    buf_appendcstr(&buf, "]");
                }
            }
            text = buf_release(&buf);
        }
        else if (bodies.text) {
            charset_t cs = charset_lookupname(bodies.text->charset_id);
            text = charset_to_utf8(msg_buf->s + bodies.text->content_offset,
                    bodies.text->content_size, cs, bodies.text->charset_enc);
            charset_free(&cs);
        }

        if (bodies.htmllist.count > 1 && render_multipart_bodies) {
            /* Concatenate all TEXT bodies, enclosing PLAIN text
             * in <div> and replacing <html> tags in HTML bodies
             * with <div>. */
            int i;
            for (i = 0; i < bodies.htmllist.count; i++) {
                struct body *part = ptrarray_nth(&bodies.htmllist, i);

                /* XXX htmllist might include inlined images but we
                 * currently ignore them. After all, there should
                 * already be an <img> tag for their Content-Id
                 * header value. If this turns out to be not enough,
                 * we can insert the <img> tags here. */
                if (strcasecmp(part->type, "TEXT")) {
                    continue;
                }

                if (!i) buf_appendcstr(&buf, "<html>"); // XXX use HTML5?

                charset_t cs = charset_lookupname(part->charset_id);
                char *t = charset_to_utf8(msg_buf->s + part->content_offset,
                                          part->content_size, cs, part->charset_enc);

                if (!strcmp(part->subtype, "HTML")) {
                    _extract_htmlbody(&buf, t);
                }
                else {
                    buf_appendcstr(&buf, "<div>");
                    buf_appendcstr(&buf, t);
                    buf_appendcstr(&buf, "</div>");
                }
                charset_free(&cs);
                free(t);

                if (i == bodies.htmllist.count - 1) buf_appendcstr(&buf, "</html>");
            }
            html  = buf_release(&buf);
        }
        else if (bodies.html) {
            charset_t cs = charset_lookupname(bodies.html->charset_id);
            html = charset_to_utf8(msg_buf->s + bodies.html->content_offset,
                    bodies.html->content_size, cs, bodies.html->charset_enc);
            charset_free(&cs);
        }
    }

    /* textBody */
    if (_wantprop(props, "textBody") || (_wantprop(props, "body") && !html)) {
        if (!text && html) {
            text = extract_plain(html);
        }
        json_object_set_new(msg, "textBody", json_string(text ? text : ""));
    }
    /* htmlBody */
    if (_wantprop(props, "htmlBody") || (_wantprop(props, "body") && html)) {
        json_object_set_new(msg, "htmlBody", html ? json_string(html) : json_null());
    }

    if (_wantprop(props, "hasAttachment")) {
        int b = 0;
        if (type == MSG_IS_ATTACHED) {
            b = bodies.atts.count + bodies.msgs.count;
        } else {
            msgrecord_hasflag(mr, JMAP_HAS_ATTACHMENT_FLAG, &b);
        }
        json_object_set_new(msg, "hasAttachment", json_boolean(b));
    }

    /* attachments */
    if (_wantprop(props, "attachments")) {
        int i;
        json_t *atts = json_pack("[]");
        json_t *inlinedcids = NULL, *imgsizes = NULL;
        const char *annot;

        /* Load the message annotation with the hash of cid: urls */
        if ((annot = config_getstring(IMAPOPT_JMAP_INLINEDCIDS_ANNOT))) {
            inlinedcids = jmapmsg_annot_read(req, mr, annot, /*structured*/1);
        }

        /* Load the message annotation with the hash of image dimensions */
        if ((annot = config_getstring(IMAPOPT_JMAP_IMAGESIZE_ANNOT))) {
            imgsizes = jmapmsg_annot_read(req, mr, annot, /*structured*/1);
        }

        for (i = 0; i < bodies.atts.count; i++) {
            json_t *att = attachment_from_part(ptrarray_nth(&bodies.atts, i),
                                               msg_buf, inlinedcids, imgsizes);
            json_array_append_new(atts, att);
        }
        for (i = 0; i < bodies.msgs.count; i++) {
            json_t *att = attachment_from_part(ptrarray_nth(&bodies.msgs, i),
                                               msg_buf, inlinedcids, imgsizes);
            json_array_append_new(atts, att);
        }
        if (!json_array_size(atts)) {
            json_decref(atts);
            atts = json_null();
        }
        json_object_set_new(msg, "attachments", atts);

        if (inlinedcids) json_decref(inlinedcids);
    }

    /* attachedEmails */
    if (_wantprop(props, "attachedEmails")) {
        int i;
        json_t *msgs = json_pack("{}");

        for (i = 0; i < bodies.msgs.count; i++) {
            struct body *part = ptrarray_nth(&bodies.msgs, i);
            json_t *submsg = NULL;

            r = jmapmsg_from_body(req, props, part->subpart, msg_buf,
                                  mr, MSG_IS_ATTACHED, &submsg);
            if (r) goto done;

            char *blobid = jmap_blobid(&part->content_guid);
            json_object_set_new(msgs, blobid, submsg);
            free(blobid);
        }
        if (!json_object_size(msgs)) {
            json_decref(msgs);
            msgs = json_null();
        }
        json_object_set_new(msg, "attachedEmails", msgs);
    }

    if (type == MSG_IS_ROOT) {
        uint32_t system_flags;
        bit64 cid;
        uint32_t size;

        r = msgrecord_get_systemflags(mr, &system_flags);
        if (r) goto done;

        r = msgrecord_get_cid(mr, &cid);
        if (r) goto done;

        r = msgrecord_get_size(mr, &size);
        if (r) goto done;

        /* id */
        struct message_guid guid;

        r = msgrecord_get_guid(mr, &guid);
        if (r) goto done;

        char *msgid = jmap_msgid(&guid);
        json_object_set_new(msg, "id", json_string(msgid));

        /* blobId */
        if (_wantprop(props, "blobId")) {
            char *blobid = jmap_blobid(&guid);
            json_object_set_new(msg, "blobId", json_string(blobid));
            free(blobid);
        }
        /* threadId */
        if (_wantprop(props, "threadId")) {
            if (cid) {
                char *thrid = jmap_thrid(cid);
                json_object_set_new(msg, "threadId", json_string(thrid));
                free(thrid);
            }
            else {
                json_object_set_new(msg, "threadId", json_null());
            }
        }
        /* mailboxIds */
        if (_wantprop(props, "mailboxIds")) {
            json_t *mailboxes, *val, *ids = json_pack("{}");
            const char *mboxid;
            mailboxes = jmapmsg_mailboxes(req, msgid);
            json_object_foreach(mailboxes, mboxid, val) {
                json_object_set_new(ids, mboxid, json_true());
            }
            json_decref(mailboxes);
            json_object_set_new(msg, "mailboxIds", ids);
        }

        /* keywords */
        if (_wantprop(props, "keywords")) {
            strarray_t *flags = NULL;
            r = msgrecord_extract_flags(mr, req->accountid, &flags);
            if (r) goto done;

            int i;
            json_t *keywords = json_pack("{}");
            for (i = 0; i < flags->count; i++) {
                const char *flag = strarray_nth(flags, i);
                const char *keyword = jmap_keyword_from_imap(flag);
                if (keyword) {
                    json_object_set_new(keywords, keyword, json_true());
                }
            }
            json_object_set_new(msg, "keywords", keywords);
            strarray_free(flags);
        }

        /* size */
        if (_wantprop(props, "size")) {
            json_object_set_new(msg, "size", json_integer(size));
        }

        /* preview */
        if (_wantprop(props, "preview")) {
            if (preview_annot) {
                json_t *preview = jmapmsg_annot_read(req, mr, preview_annot, /*structured*/0);
                json_object_set_new(msg, "preview", preview ? preview : json_string(""));
            }
            else {
                /* Generate our own preview */
                char *preview = extract_preview(text,
                        config_getint(IMAPOPT_JMAP_PREVIEW_LENGTH));
                json_object_set_new(msg, "preview", json_string(preview));
                free(preview);
            }
        }
        free(msgid);
    }

    r = 0;

done:
    json_decref(annotations);
    json_decref(headers);
    buf_free(&buf);
    if (text) free(text);
    if (html) free(html);
    ptrarray_fini(&bodies.atts);
    ptrarray_fini(&bodies.msgs);
    ptrarray_fini(&bodies.textlist);
    ptrarray_fini(&bodies.htmllist);
    if (r) {
        if (msg) json_decref(msg);
        msg = NULL;
    }
    *msgp = msg;
    return r;
}

struct jmapmsg_find_data {
    jmap_req_t *req;
    char *mboxname;
    uint32_t uid;
};

static int jmapmsg_find_cb(const conv_guidrec_t *rec, void *rock)
{
    struct jmapmsg_find_data *d = (struct jmapmsg_find_data*) rock;
    jmap_req_t *req = d->req;
    int r = 0;

    if (rec->part) return 0;

    if (!d->mboxname || jmap_isopenmbox(req, rec->mboxname)) {
        struct mailbox *mbox = NULL;
        msgrecord_t *mr = NULL;
        uint32_t flags;
        mbentry_t *mbentry = NULL;

        /* Make sure we are allowed to read this mailbox */
        if (strcmp(req->accountid, req->userid)) {
            if (mboxlist_lookup(rec->mboxname, &mbentry, NULL))
                return 0;
            int rights = jmap_myrights(req, mbentry);
            mboxlist_entry_free(&mbentry);
            if (!(rights & ACL_READ))
                return 0;
        }

        /* Prefer to use messages in already opened mailboxes */

        r = jmap_openmbox(req, rec->mboxname, &mbox, 0);
        if (r) return r;

        r = msgrecord_find(mbox, rec->uid, &mr);
        if (!r) {
            r = msgrecord_get_systemflags(mr, &flags);
            if (!r && !(flags & (FLAG_EXPUNGED|FLAG_DELETED))) {
                if (d->mboxname) {
                    free(d->mboxname);
                    r = IMAP_OK_COMPLETED;
                }
                d->mboxname = xstrdup(rec->mboxname);
                d->uid = rec->uid;
            }
            msgrecord_unref(&mr);
        }

        jmap_closembox(req, &mbox);
    }

    return r;
}

static int jmapmsg_find(jmap_req_t *req, const char *msgid,
                        char **mboxnameptr, uint32_t *uid)
{
    struct jmapmsg_find_data data = { req, NULL, 0 };
    int r;

    /* must be prefixed with 'M' */
    if (msgid[0] != 'M')
        return IMAP_NOTFOUND;
    /* this is on a 24 character prefix only */
    if (strlen(msgid) != 25)
        return IMAP_NOTFOUND;

    r = conversations_guid_foreach(req->cstate, msgid+1, jmapmsg_find_cb, &data);
    if (r == IMAP_OK_COMPLETED) {
        r = 0;
    }
    else if (!data.mboxname) {
        r = IMAP_NOTFOUND;
    }
    *mboxnameptr = data.mboxname;
    *uid = data.uid;
    return r;
}

struct jmapmsg_count_data {
    jmap_req_t *req;
    size_t count;
};

static int jmapmsg_count_cb(const conv_guidrec_t *rec, void *rock)
{
    struct jmapmsg_count_data *d = (struct jmapmsg_count_data*) rock;
    jmap_req_t *req = d->req;
    msgrecord_t *mr = NULL;
    struct mailbox *mbox = NULL;
    uint32_t flags;
    int r = 0;

    if (rec->part) return 0;

    r = jmap_openmbox(req, rec->mboxname, &mbox, 0);
    if (r) return r;

    r = msgrecord_find(mbox, rec->uid, &mr);
    if (!r) {
        r = msgrecord_get_systemflags(mr, &flags);
        if (!r && !(flags & (FLAG_EXPUNGED|FLAG_DELETED))) {
            d->count++;
        }
        msgrecord_unref(&mr);
    }

    jmap_closembox(req, &mbox);

    return r;
}

static int jmapmsg_count(jmap_req_t *req, const char *msgid, size_t *count)
{
    struct jmapmsg_count_data data = { req, 0 };
    int r;

    if (msgid[0] != 'M')
        return IMAP_NOTFOUND;

    r = conversations_guid_foreach(req->cstate, msgid+1, jmapmsg_count_cb, &data);
    if (r == IMAP_OK_COMPLETED) {
        r = 0;
    } else if (!data.count) {
        r = IMAP_NOTFOUND;
    }
    *count = data.count;
    return r;
}

struct jmapmsg_isexpunged_data {
    jmap_req_t *req;
    int is_expunged;
};

static int jmapmsg_isexpunged_cb(const conv_guidrec_t *rec, void *rock)
{
    struct jmapmsg_isexpunged_data *d = (struct jmapmsg_isexpunged_data*) rock;
    jmap_req_t *req = d->req;
    msgrecord_t *mr = NULL;
    struct mailbox *mbox = NULL;
    uint32_t flags;
    int r = 0;

    if (rec->part) return 0;

    r = jmap_openmbox(req, rec->mboxname, &mbox, 0);
    if (r) return r;

    r = msgrecord_find(mbox, rec->uid, &mr);
    if (!r) {
        r = msgrecord_get_systemflags(mr, &flags);
        if (!r && !(flags & (FLAG_EXPUNGED|FLAG_DELETED))) {
            d->is_expunged = 0;
            r = IMAP_OK_COMPLETED;
        }
        msgrecord_unref(&mr);
    }

    jmap_closembox(req, &mbox);

    return r;
}

static int jmapmsg_isexpunged(jmap_req_t *req, const char *msgid, int *is_expunged)
{
    struct jmapmsg_isexpunged_data data = { req, 1 };
    int r;

    if (msgid[0] != 'M')
        return IMAP_NOTFOUND;

    if (strlen(msgid) != 25)
        return IMAP_NOTFOUND;

    r = conversations_guid_foreach(req->cstate, msgid+1, jmapmsg_isexpunged_cb, &data);
    if (r == IMAP_OK_COMPLETED) {
        r = 0;
    }

    *is_expunged = data.is_expunged;
    return r;
}

static int jmapmsg_from_record(jmap_req_t *req, hash_table *props,
                               msgrecord_t *mr, json_t **msgp)
{
    struct body *body = NULL;
    struct buf msg_buf = BUF_INITIALIZER;
    int r;

    r = msgrecord_get_body(mr, &msg_buf);
    if (r) return r;

    /* Parse message body structure */
    r = msgrecord_get_bodystructure(mr, &body);
    if (r) return r;

    r = jmapmsg_from_body(req, props, body, &msg_buf, mr, MSG_IS_ROOT,
                          msgp);
    message_free_body(body);
    free(body);
    buf_free(&msg_buf);

    return r;
}

static void match_string(search_expr_t *parent, const char *s, const char *name)
{
    charset_t utf8 = charset_lookupname("utf-8");
    search_expr_t *e;
    const search_attr_t *attr = search_attr_find(name);
    enum search_op op;

    assert(attr);

    op = search_attr_is_fuzzable(attr) ? SEOP_FUZZYMATCH : SEOP_MATCH;

    e = search_expr_new(parent, op);
    e->attr = attr;
    e->value.s = charset_convert(s, utf8, charset_flags);
    if (!e->value.s) {
        e->op = SEOP_FALSE;
        e->attr = NULL;
    }

    charset_free(&utf8);
}

static void match_mailbox(jmap_req_t *req, search_expr_t *parent,
                          json_t *mailbox, int is_not)
{
    search_expr_t *e;
    const char *s = json_string_value(mailbox);
    char *mboxname = jmapmbox_find_uniqueid(req, s);
    if (!mboxname) {
        /* XXX - add a "never match" terminal */
        return;
    }

    if (is_not) {
        parent = search_expr_new(parent, SEOP_NOT);
    }

    e = search_expr_new(parent, SEOP_MATCH);
    e->attr = search_attr_find("folder");
    e->value.s = mboxname; // takes ownership
}

static void match_keyword(search_expr_t *parent, const char *keyword)
{
    search_expr_t *e;
    if (!strcmp(keyword, "$Seen")) {
        e = search_expr_new(parent, SEOP_MATCH);
        e->attr = search_attr_find("indexflags");
        e->value.u = MESSAGE_SEEN;
    }
    else if (!strcmp(keyword, "$Draft")) {
        e = search_expr_new(parent, SEOP_MATCH);
        e->attr = search_attr_find("systemflags");
        e->value.u = FLAG_DRAFT;
    }
    else if (!strcmp(keyword, "$Flagged")) {
        e = search_expr_new(parent, SEOP_MATCH);
        e->attr = search_attr_find("systemflags");
        e->value.u = FLAG_FLAGGED;
    }
    else if (!strcmp(keyword, "$Answered")) {
        e = search_expr_new(parent, SEOP_MATCH);
        e->attr = search_attr_find("systemflags");
        e->value.u = FLAG_ANSWERED;
    }
    else {
        e = search_expr_new(parent, SEOP_MATCH);
        e->attr = search_attr_find("keyword");
        e->value.s = xstrdup(keyword);
    }
}

static void match_convkeyword(search_expr_t *parent, const char *keyword)
{
    const char *flag = jmap_keyword_to_imap(keyword);
    if (!flag) return;

    search_expr_t *e = search_expr_new(parent, SEOP_MATCH);
    e->attr = search_attr_find("convflags");
    e->value.s = xstrdup(flag);
}

static int is_supported_convkeyword(const char *keyword)
{
    /* \Seen is always supported */
    if (!strcasecmp(keyword, "$Seen"))
        return 1;

    const char *counted_flags = config_getstring(IMAPOPT_CONVERSATIONS_COUNTED_FLAGS);
    if (!counted_flags)
        return 0;

    /* We really shouldn't do all this string mangling for each keyword */
    strarray_t *flags = strarray_split(counted_flags, " ", STRARRAY_TRIM);
    int i, is_supported = 0;
    for (i = 0; i < flags->count; i++) {
        const char *flag = strarray_nth(flags, i);
        const char *kw = keyword;
        if (*flag == '\\') flag++;
        if (*kw == '$') kw++;
        if (!strcasecmp(flag, kw)) {
            is_supported = 1;
            break;
        }
    }
    strarray_free(flags);

    return is_supported;
}

static search_expr_t *buildsearch(jmap_req_t *req, json_t *filter,
                                  search_expr_t *parent)
{
    search_expr_t *this, *e;
    json_t *val;
    const char *s;
    size_t i;
    time_t t;

    if (!JNOTNULL(filter)) {
        return search_expr_new(parent, SEOP_TRUE);
    }

    if ((s = json_string_value(json_object_get(filter, "operator")))) {
        enum search_op op = SEOP_UNKNOWN;

        if (!strcmp("AND", s)) {
            op = SEOP_AND;
        } else if (!strcmp("OR", s)) {
            op = SEOP_OR;
        } else if (!strcmp("NOT", s)) {
            op = SEOP_NOT;
        }

        this = search_expr_new(parent, op);
        e = op == SEOP_NOT ? search_expr_new(this, SEOP_OR) : this;

        json_array_foreach(json_object_get(filter, "conditions"), i, val) {
            buildsearch(req, val, e);
        }
    } else {
        this = search_expr_new(parent, SEOP_AND);

        /* zero properties evaluate to true */
        search_expr_new(this, SEOP_TRUE);

        if ((s = json_string_value(json_object_get(filter, "after")))) {
            time_from_iso8601(s, &t);
            e = search_expr_new(this, SEOP_GE);
            e->attr = search_attr_find("internaldate");
            e->value.u = t;
        }
        if ((s = json_string_value(json_object_get(filter, "before")))) {
            time_from_iso8601(s, &t);
            e = search_expr_new(this, SEOP_LE);
            e->attr = search_attr_find("internaldate");
            e->value.u = t;
        }
        if ((s = json_string_value(json_object_get(filter, "body")))) {
            match_string(this, s, "body");
        }
        if ((s = json_string_value(json_object_get(filter, "cc")))) {
            match_string(this, s, "cc");
        }
        if ((s = json_string_value(json_object_get(filter, "from")))) {
            match_string(this, s, "from");
        }
        if (JNOTNULL((val = json_object_get(filter, "hasAttachment")))) {
            e = val == json_false() ? search_expr_new(this, SEOP_NOT) : this;
            e = search_expr_new(e, SEOP_MATCH);
            e->attr = search_attr_find("keyword");
            e->value.s = xstrdup(JMAP_HAS_ATTACHMENT_FLAG);
        }
        if ((s = json_string_value(json_object_get(filter, "attachmentName")))) {
            match_string(this, s, "attachmentname");
        }
        if (JNOTNULL((val = json_object_get(filter, "header")))) {
            const char *k, *v;
            charset_t utf8 = charset_lookupname("utf-8");
            search_expr_t *e;

            if (json_array_size(val) == 2) {
                k = json_string_value(json_array_get(val, 0));
                v = json_string_value(json_array_get(val, 1));
            } else {
                k = json_string_value(json_array_get(val, 0));
                v = ""; /* Empty string matches any value */
            }

            e = search_expr_new(this, SEOP_MATCH);
            e->attr = search_attr_find_field(k);
            e->value.s = charset_convert(v, utf8, charset_flags);
            if (!e->value.s) {
                e->op = SEOP_FALSE;
                e->attr = NULL;
            }
            charset_free(&utf8);
        }
        if ((val = json_object_get(filter, "inMailbox"))) {
            match_mailbox(req, this, val, /*is_not*/0);
        }

        json_array_foreach(json_object_get(filter, "inMailboxOtherThan"), i, val) {
            e = search_expr_new(this, SEOP_AND);
            match_mailbox(req, e, val, /*is_not*/1);
        }

        if (JNOTNULL((val = json_object_get(filter, "allInThreadHaveKeyword")))) {
            /* This shouldn't happen, validate_sort should have reported
             * allInThreadHaveKeyword as unsupported. Let's ignore this
             * filter and return false positives. */
            syslog(LOG_ERR, "jmapmsg_search: ignoring allInThreadHaveKeyword filter");
        }
        if (JNOTNULL((val = json_object_get(filter, "someInThreadHaveKeyword")))) {
            match_convkeyword(this, json_string_value(val));
        }
        if (JNOTNULL((val = json_object_get(filter, "noneInThreadHaveKeyword")))) {
            e = search_expr_new(this, SEOP_NOT);
            match_convkeyword(e, json_string_value(val));
        }

        if (JNOTNULL((val = json_object_get(filter, "hasKeyword")))) {
            match_keyword(this, json_string_value(val));
        }
        if (JNOTNULL((val = json_object_get(filter, "notHasKeyword")))) {
            e = search_expr_new(this, SEOP_NOT);
            match_keyword(e, json_string_value(val));
        }

        if (JNOTNULL((val = json_object_get(filter, "maxSize")))) {
            e = search_expr_new(this, SEOP_LE);
            e->attr = search_attr_find("size");
            e->value.u = json_integer_value(val);
        }
        if (JNOTNULL((val = json_object_get(filter, "minSize")))) {
            e = search_expr_new(this, SEOP_GE);
            e->attr = search_attr_find("size");
            e->value.u = json_integer_value(val);
        }
        if ((s = json_string_value(json_object_get(filter, "sinceEmailState")))) {
            /* non-standard */
            e = search_expr_new(this, SEOP_GT);
            e->attr = search_attr_find("modseq");
            e->value.u = atomodseq_t(s);
        }
        if ((s = json_string_value(json_object_get(filter, "subject")))) {
            match_string(this, s, "subject");
        }
        if ((s = json_string_value(json_object_get(filter, "text")))) {
            match_string(this, s, "text");
        }
        if ((s = json_string_value(json_object_get(filter, "to")))) {
            match_string(this, s, "to");
        }
    }

    return this;
}

static void validate_msgfilter(json_t *filter, const char *prefix, json_t *invalid, json_t *unsupported)
{
    struct buf buf = BUF_INITIALIZER;
    json_t *arg, *val;
    const char *s;
    json_int_t num;
    int b;
    size_t i;

    if (!JNOTNULL(filter) || json_typeof(filter) != JSON_OBJECT) {
        json_array_append_new(invalid, json_string(prefix));
    }

    if (readprop_full(filter, prefix, "operator", 0, invalid, "s", &s) > 0) {
        if (strcmp("AND", s) && strcmp("OR", s) && strcmp("NOT", s)) {
            buf_printf(&buf, "%s.%s", prefix, "operator");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }

        arg = json_object_get(filter, "conditions");
        if (!json_array_size(arg)) {
            buf_printf(&buf, "%s.conditions", prefix);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
        json_array_foreach(arg, i, val) {
            buf_printf(&buf, "%s.conditions[%zu]", prefix, i);
            validate_msgfilter(val, buf_cstring(&buf), invalid, unsupported);
            buf_reset(&buf);
        }

    } else {
        if (readprop_full(filter, prefix, "before", 0, invalid, "s", &s) > 0) {
            struct tm tm;
            const char *p = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
            if (!p || *p) {
                buf_printf(&buf, "%s.before", prefix);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }

        if (readprop_full(filter, prefix, "after", 0, invalid, "s", &s) > 0) {
            struct tm tm;
            const char *p = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
            if (!p || *p) {
                buf_printf(&buf, "%s.after", prefix);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }

        readprop_full(filter, prefix, "inMailbox", 0, invalid, "s", &s);
        readprop_full(filter, prefix, "minSize", 0, invalid, "I", &num);
        readprop_full(filter, prefix, "maxSize", 0, invalid, "I", &num);
        readprop_full(filter, prefix, "hasAttachment", 0, invalid, "b", &b);
        readprop_full(filter, prefix, "attachmentName", 0, invalid, "s", &s);
        readprop_full(filter, prefix, "text", 0, invalid, "s", &s);
        readprop_full(filter, prefix, "from", 0, invalid, "s", &s);
        readprop_full(filter, prefix, "to", 0, invalid, "s", &s);
        readprop_full(filter, prefix, "cc", 0, invalid, "s", &s);
        readprop_full(filter, prefix, "bcc", 0, invalid, "s", &s);
        readprop_full(filter, prefix, "subject", 0, invalid, "s", &s);
        readprop_full(filter, prefix, "body", 0, invalid, "s", &s);

        json_array_foreach(json_object_get(filter, "inMailboxOtherThan"), i, val) {
            if (!json_is_string(val)) {
                buf_printf(&buf, "%s.inMailboxOtherThan[%zu]", prefix, i);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }

        if (readprop_full(filter, prefix, "allInThreadHaveKeyword", 0, invalid, "s", &s) > 0) {
            if (!is_valid_keyword(s)) {
                buf_printf(&buf, "%s.allInThreadHaveKeyword", prefix);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
            /* XXX currently can't support this filter */
            json_array_append_new(unsupported, json_pack("{s:s}",
                        "allInThreadHaveKeyword", s));
        }
        if (readprop_full(filter, prefix, "someInThreadHaveKeyword", 0, invalid, "s", &s) > 0) {
            if (!is_valid_keyword(s)) {
                buf_printf(&buf, "%s.someInThreadHaveKeyword", prefix);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
            if (!is_supported_convkeyword(s)) {
                json_array_append_new(unsupported, json_pack("{s:s}",
                            "someInThreadHaveKeyword", s));
            }
        }
        if (readprop_full(filter, prefix, "noneInThreadHaveKeyword", 0, invalid, "s", &s) > 0) {
            if (!is_valid_keyword(s)) {
                buf_printf(&buf, "%s.noneInThreadHaveKeyword", prefix);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
            if (!is_supported_convkeyword(s)) {
                json_array_append_new(unsupported, json_pack("{s:s}",
                            "someInThreadHaveKeyword", s));
            }
        }

        if (readprop_full(filter, prefix, "hasKeyword", 0, invalid, "s", &s) > 0) {
            if (!is_valid_keyword(s)) {
                buf_printf(&buf, "%s.hasKeyword", prefix);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }
        if (readprop_full(filter, prefix, "notHasKeyword", 0, invalid, "s", &s) > 0) {
            if (!is_valid_keyword(s)) {
                buf_printf(&buf, "%s.notHasKeyword", prefix);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }

        arg = json_object_get(filter, "header");
        if (JNOTNULL(arg)) {
            switch (json_array_size(arg)) {
                case 2:
                    s = json_string_value(json_array_get(arg, 1));
                    if (!s || !strlen(s)) {
                        buf_printf(&buf, "%s.header[1]", prefix);
                        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                        buf_reset(&buf);
                    }
                    /* fallthrough */
                case 1:
                    s = json_string_value(json_array_get(arg, 0));
                    if (!s || !strlen(s)) {
                        buf_printf(&buf, "%s.header[0]", prefix);
                        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                        buf_reset(&buf);
                    }
                    break;
                default:
                    buf_printf(&buf, "%s.header", prefix);
                    json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                    buf_reset(&buf);
            }
        }
    }

    buf_free(&buf);
}

static struct sortcrit *buildsort(json_t *sort)
{
    json_t *jcomp;
    size_t i;
    struct sortcrit *sortcrit;

    if (!JNOTNULL(sort) || json_array_size(sort) == 0) {
        sortcrit = xzmalloc(2 * sizeof(struct sortcrit));
        sortcrit[0].flags |= SORT_REVERSE;
        sortcrit[0].key = SORT_ARRIVAL;
        sortcrit[1].key = SORT_SEQUENCE;
        return sortcrit;
    }

    sortcrit = xzmalloc((json_array_size(sort) + 1) * sizeof(struct sortcrit));

    json_array_foreach(sort, i, jcomp) {
        const char *prop = json_string_value(json_object_get(jcomp, "property"));

        if (json_object_get(jcomp, "isAscending") == json_false()) {
            sortcrit[i].flags |= SORT_REVERSE;
        }

        /* Note: add any new sort criteria also to is_supported_msglist_sort */

        if (!strcmp(prop, "receivedAt")) {
            sortcrit[i].key = SORT_ARRIVAL;
        }
        if (!strcmp(prop, "from")) {
            sortcrit[i].key = SORT_FROM;
        }
        if (!strcmp(prop, "id")) {
            sortcrit[i].key = SORT_GUID;
        }
        if (!strcmp(prop, "emailState")) {
            sortcrit[i].key = SORT_MODSEQ;
        }
        if (!strcmp(prop, "size")) {
            sortcrit[i].key = SORT_SIZE;
        }
        if (!strcmp(prop, "subject")) {
            /* FIXME JMAP spec requires support of RFC 5256 for sorting */
            sortcrit[i].key = SORT_SUBJECT;
        }
        if (!strcmp(prop, "to")) {
            sortcrit[i].key = SORT_TO;
        }
        if (!strncmp(prop, "hasKeyword:", 11)) {
            const char *name = jmap_keyword_to_imap(prop + 11);
            if (name) {
                sortcrit[i].key = SORT_HASFLAG;
                sortcrit[i].args.flag.name = xstrdup(name);
            }
        }
        if (!strncmp(prop, "someInThreadHaveKeyword:", 24)) {
            const char *name = jmap_keyword_to_imap(prop + 24);
            if (name) {
                sortcrit[i].key = SORT_HASFLAG;
                sortcrit[i].args.flag.name = xstrdup(name);
            }
        }
    }

    sortcrit[json_array_size(sort)].key = SORT_SEQUENCE;

    return sortcrit;
}

struct getmsglist_window {
    /* input arguments */
    int collapse;
    ssize_t position;
    const char *anchor;
    int anchor_off;
    size_t limit;
    modseq_t sincemodseq;
    const char *uptomsgid;

    /* output arguments */
    modseq_t highestmodseq;
    int cancalcupdates;

    /* internal state */
    size_t mdcount;
    size_t anchor_pos;
};

static void update_added(json_t *target, const char *msgid, int index)
{
    json_t *item = json_pack("{s:s,s:i}", "id", msgid, "index", index);
    json_array_append_new(target, item);
}

static void update_removed(json_t *target, const char *msgid)
{
    json_array_append_new(target, json_string(msgid));
}

static int jmapmsg_search(jmap_req_t *req, json_t *filter, json_t *sort,
                          struct getmsglist_window *window, int want_expunged,
                          size_t *total, size_t *total_threads,
                          json_t **messageids, json_t **expungedids,
                          json_t **threadids)
{
    hash_table ids = HASH_TABLE_INITIALIZER;
    hashu64_table cids = HASHU64_TABLE_INITIALIZER;
    struct index_state *state = NULL;
    search_query_t *query = NULL;
    struct sortcrit *sortcrit = NULL;
    struct searchargs *searchargs = NULL;
    struct index_init init;
    int foundupto = 0;
    char *msgid = NULL;
    int i, r;

    /* FIXME JMAP spec introduced negative positions for search results, and
     * this is what breaks the camel's neck for the mess jmapmsg_search got.
     * This function requires a massive refactor before we can add any new
     * functionality.
     * Until then, we fail hard for negative positions */
    assert(window->position >= 0);

    assert(!want_expunged || expungedids);

    *total = 0;
    *messageids = json_pack("[]");
    *threadids = json_pack("[]");
    if (want_expunged) *expungedids = json_pack("[]");

    /* Build searchargs */
    searchargs = new_searchargs(NULL/*tag*/, GETSEARCH_CHARSET_FIRST,
                                &jmap_namespace, req->accountid, req->authstate, 0);
    searchargs->root = buildsearch(req, filter, NULL);

    /* Run the search query */
    memset(&init, 0, sizeof(init));
    init.userid = req->accountid;
    init.authstate = req->authstate;
    init.want_expunged = want_expunged;

    r = index_open(req->inboxname, &init, &state);
    if (r) goto done;

    query = search_query_new(state, searchargs);
    query->sortcrit = sortcrit = buildsort(sort);
    query->multiple = 1;
    query->need_ids = 1;
    query->verbose = 1;
    query->want_expunged = want_expunged;

    if (search_is_mutable(sortcrit, searchargs)) {
        if (window->sincemodseq) {
            r = IMAP_SEARCH_MUTABLE;
            goto done;
        }
    }
    else {
        window->cancalcupdates = 1;
    }


    r = search_query_run(query);
    if (r) goto done;

    /* Initialize window state */
    window->mdcount = query->merged_msgdata.count;
    window->anchor_pos = (size_t)-1;
    window->highestmodseq = 0;

    memset(&ids, 0, sizeof(hash_table));
    construct_hash_table(&ids, window->mdcount + 1, 0);

    memset(&cids, 0, sizeof(hashu64_table));
    construct_hashu64_table(&cids, query->merged_msgdata.count/4+4,0);

    *total_threads = 0;

    for (i = 0 ; i < query->merged_msgdata.count ; i++) {
        MsgData *md = ptrarray_nth(&query->merged_msgdata, i);
        search_folder_t *folder = md->folder;
        json_t *msg = NULL;
        size_t idcount = json_array_size(*messageids);

        if (!folder) continue;

        /* Ignore expunged messages, if not requested by caller */
        int is_expunged = md->system_flags & (FLAG_EXPUNGED|FLAG_DELETED);
        if (is_expunged && !want_expunged)
            goto doneloop;

        /* Make sure we don't report any hidden messages */
        int rights = jmap_myrights_byname(req, folder->mboxname);
        if (!(rights & ACL_READ))
            goto doneloop;

        free(msgid);
        msgid = jmap_msgid(&md->guid);

        /* Have we seen this message already? */
        if (hash_lookup(msgid, &ids))
            goto doneloop;

        /* Add the message the list of reported messages */
        hash_insert(msgid, (void*)1, &ids);

        /* we're doing getEmailsListUpdates - we use the results differently */
        if (window->sincemodseq) {
            /* Keep track of the highest modseq */
            if (window->highestmodseq < md->modseq)
                window->highestmodseq = md->modseq;

            /* trivial case - not collapsing conversations */
            if (!window->collapse) {
                if (is_expunged) {
                    if (foundupto) goto doneloop;
                    if (md->modseq <= window->sincemodseq) goto doneloop;
                    update_removed(*expungedids, msgid);
                }
                else {
                    (*total)++;
                    if (foundupto) goto doneloop;
                    if (md->modseq <= window->sincemodseq) goto doneloop;
                    update_added(*messageids, msgid, *total-1);
                }
                goto doneloop;
            }

            /* OK, we need to deal with the following possibilities */

            /* cids:
             * 1: exemplar for this CID seen
             * 2: old exemplar for CID seen
             * 4: deleted new item exists that might have exposed old record
             *
             * The concept of "exemplar" comes from the xconv* commands in index.c.
             * The "exemplar" is the first message that matches the current sort/search
             * for a given conversation.  For getEmailsList this is fairly simple,
             * just show the first message you find with a given cid, but for
             * getEmailsListUpdates, you need to say "removed" for every message
             * which MIGHT have been the previous exemplar, because it will be in the
             * client cache, and you need to say both "removed" and "added" for the
             * new exemplar unless you can be sure it was also the old exemplar.
             *
             * Of particular interest is the exposed old exemplar case.  Imagine
             * 3 messages in the same conversation, A, C and D - delivered in that
             * order (B was a different conversation - this is an example in the
             * Cassandane test).  C and D are both in reply to A.  The sort is
             * internaldate desc, so the messages are in this order D C B A.
             * exemplars are D and B for the two conversations.
             *
             * Let's say the state is 1000 at this point.
             *
             * We then delete 'C' without changing D.  Since we know D must have been
             * the old exemplar, there is no change to show between 1000 and 1001.
             *
             * We then delete 'D'.  Now, 'C' was changed at 1001, so asking for changes
             * since 1001 we get removed: ['D', 'A'], added: ['A'] - because 'D' is now
             * gone, and 'A' is now the exemplar - but we aren't sure if it was also the
             * previous exemplay because we don't know if D was also deleted earlier and
             * touched again for some unreleated reason.
             *
             */
            off_t ciddata = (off_t)hashu64_lookup(md->cid, &cids);
            if (ciddata == 3) goto doneloop; /* this message clearly can't have been seen and can't be seen */

            if (!is_expunged && !(ciddata & 1)) {
                (*total)++; /* this is the exemplar */
                hashu64_insert(md->cid, (void*)(ciddata | 1), &cids);
            }

            if (foundupto) goto doneloop;

            if (md->modseq <= window->sincemodseq) {
                if (!is_expunged) {
                    /* this may have been the old exemplar but is not the new exemplar */
                    if (ciddata & 1) {
                        update_removed(*expungedids, msgid);
                    }
                    else if (ciddata & 4) {
                        /* we need to remove and re-add this record just in case we
                         * got unmasked by the previous */
                        update_removed(*expungedids, msgid);
                        update_added(*messageids, msgid, *total-1);
                    }
                    /* nothing later could be the old exemplar */
                    hashu64_insert(md->cid, (void *)3, &cids);
                }
                goto doneloop;
            }

            /* OK, so this message has changed since last time */

            /* we don't know that we weren't the old exemplar, so we always tell a removal */
            update_removed(*expungedids, msgid);

            /* not the new exemplar because expunged */
            if (is_expunged) {
                hashu64_insert(md->cid, (void*)(ciddata | 4), &cids);
                goto doneloop;
            }
            /* not the new exemplar because we've already seen that */
            if (ciddata & 1) goto doneloop;

            /* this is the new exemplar, so tell about it */
            update_added(*messageids, msgid, *total-1);

            goto doneloop;
        }

        /* Collapse threads, if requested */
        if (window->collapse && hashu64_lookup(md->cid, &cids))
            goto doneloop;

        /* OK, that's a legit message */
        (*total)++;

        /* Keep track of conversation ids, inside and outside the window */
        if (!hashu64_lookup(md->cid, &cids)) {
            (*total_threads)++;
            hashu64_insert(md->cid, (void*)1, &cids);
        }

        /* Check if the message is in the search window */
        if (window->anchor) {
            if (!strcmp(msgid, window->anchor)) {
                /* This message is the anchor. Recalculate the search result */
                json_t *anchored_ids = json_pack("[]");
                json_t *anchored_cids = json_pack("[]");
                size_t j;

                /* Set countdown to enter the anchor window */
                if (window->anchor_off < 0) {
                    window->anchor_pos = -window->anchor_off;
                } else {
                    window->anchor_pos = 0;
                }

                /* Readjust the message and thread list */
                for (j = idcount - window->anchor_off; j < idcount; j++) {
                    json_array_append(anchored_ids, json_array_get(*messageids, j));
                    json_array_append(anchored_cids, json_array_get(*threadids, j));
                }
                json_decref(*messageids);
                *messageids = anchored_ids;
                json_decref(*threadids);
                *threadids = anchored_cids;

                /* Adjust the window position for this anchor. This is
                 * "[...] the 0-based index of the first result in the
                 * threadIds array within the complete list". */
                window->position = *total - json_array_size(anchored_ids) - 1;

                /* Reset message counter */
                idcount = json_array_size(*messageids);
            }
            if (window->anchor_pos != (size_t)-1 && window->anchor_pos) {
                /* Found the anchor but haven't yet entered its window */
                window->anchor_pos--;
                /* But this message still counts to the window position */
                window->position++;
                goto doneloop;
            }
        }
        else if (window->position > 0 && *total < ((size_t) window->position) + 1) {
            goto doneloop;
        }

        if (window->limit && idcount && window->limit <= idcount)
            goto doneloop;

        /* Keep track of the highest modseq */
        if (window->highestmodseq < md->modseq)
            window->highestmodseq = md->modseq;

        /* Check if the message is expunged in all mailboxes */
        r = jmapmsg_isexpunged(req, msgid, &is_expunged);
        if (r) goto done;

        /* Add the message id to the result */
        if (is_expunged && expungedids) {
            json_array_append_new(*expungedids, json_string(msgid));
        } else {
            json_array_append_new(*messageids, json_string(msgid));
        }

        /* Add the thread id */
        if (window->collapse)
            hashu64_insert(md->cid, (void*)1, &cids);
        char *thrid = jmap_thrid(md->cid);
        json_array_append_new(*threadids, json_string(thrid));
        free(thrid);


doneloop:
        if (!foundupto && window->uptomsgid && !strcmp(msgid, window->uptomsgid))
            foundupto = 1;
        if (msg) json_decref(msg);
    }

    if (!json_array_size(*messageids)) {
        json_decref(*messageids);
        *messageids = json_null();
    }
    if (!json_array_size(*threadids)) {
        json_decref(*threadids);
        *threadids = json_null();
    }
    if (want_expunged) {
        if (!json_array_size(*expungedids)) {
            json_decref(*expungedids);
            *expungedids = json_null();
        }
    }

done:
    free(msgid);
    free_hash_table(&ids, NULL);
    free_hashu64_table(&cids, NULL);
    if (sortcrit) freesortcrit(sortcrit);
    if (query) search_query_free(query);
    if (searchargs) freesearchargs(searchargs);
    if (state) {
        state->mailbox = NULL;
        index_close(&state);
    }
    if (r) {
        json_decref(*messageids);
        *messageids = NULL;
        json_decref(*threadids);
        *threadids = NULL;
    }
    return r;
}

static const char *msglist_sortfields[] = {
    "receivedAt",
    "from",
    "id",
    "emailstate",
    "size",
    "subject",
    "to",
    "hasKeyword",
    "someInThreadHaveKeyword",
    NULL
};

static int is_supported_msglist_sort(const jmap_comparator_t *comp)
{
    /* Reject any collation */
    if (comp->collation) {
        return 0;
    }

    /* Special case: hasKeyword */
    if (!strncmp(comp->property, "hasKeyword:", 11)) {
        if (is_valid_keyword(comp->property + 11)) {
            return 1;
        }
    }
    /* Special case: someInThreadHaveKeyword */
    else if (!strncmp(comp->property, "someInThreadHaveKeyword:", 24)) {
        const char *s = comp->property + 24;
        if (is_valid_keyword(s) && is_supported_convkeyword(s)) {
            return 1;
        }
    }

    /* Search in list of supported sortFields */
    const char **sp;
    for (sp = msglist_sortfields; *sp; sp++) {
        if (!strcmp(*sp, comp->property)) {
            return 1;
        }
    }

    return 0;
}

static int getEmailsList(jmap_req_t *req)
{
    int r;
    json_t *filter, *sort;
    json_t *messageids = NULL, *threadids = NULL, *collapse = NULL, *item, *res;
    struct getmsglist_window window;
    json_int_t i = 0;
    size_t total, total_threads;

    /* Parse and validate arguments. */
    json_t *invalid = json_pack("[]");
    json_t *unsupported_filter = json_pack("[]");
    json_t *unsupported_sort = json_pack("[]");

    /* filter */
    filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        validate_msgfilter(filter, "filter", invalid, unsupported_filter);
    }

    /* sort */
    sort = json_object_get(req->args, "sort");
    if (JNOTNULL(sort)) {
        validate_sort(sort, invalid, unsupported_sort, is_supported_msglist_sort);
    }

    /* windowing */
    memset(&window, 0, sizeof(struct getmsglist_window));
    if ((collapse = json_object_get(req->args, "collapseThreads"))) {
        readprop(req->args, "collapseThreads", 0, invalid, "b", &window.collapse);
    }
    readprop(req->args, "anchor", 0, invalid, "s", &window.anchor);
    readprop(req->args, "anchorOffset", 0, invalid, "i", &window.anchor_off);

    if (readprop(req->args, "position", 0, invalid, "I", &i) > 0) {
        /* FIXME we should, but currently don't support negative
         * positions, because jmapmsg_search is a mess */
        if (i < 0) json_array_append_new(invalid, json_string("position"));
        window.position = i;
    }

    if (readprop(req->args, "limit", 0, invalid, "I", &i) > 0) {
        if (i < 0) json_array_append_new(invalid, json_string("limit"));
        window.limit = i;
    }

    /* Bail out for argument errors */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        json_decref(unsupported_filter);
        json_decref(unsupported_sort);
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Report unsupported filters and sorts */
    if (json_array_size(unsupported_filter)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "unsupportedFilter", "filters", unsupported_filter);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        json_decref(unsupported_sort);
        r = 0;
        goto done;
    }
    json_decref(unsupported_filter);
    if (json_array_size(unsupported_sort)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "unsupportedSort", "sort", unsupported_sort);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(unsupported_sort);

    r = jmapmsg_search(req, filter, sort, &window, 0, &total, &total_threads,
                       &messageids, /*expungedids*/NULL, &threadids);
    if (r == IMAP_NOTFOUND) {
        json_t *err = json_pack("{s:s}", "type", "unsupportedFilter");
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    else if (r) goto done;

    /* Prepare response. */
    res = json_pack("{}");
    json_object_set_new(res, "accountId", json_string(req->accountid));
    if (JNOTNULL(collapse)) {
        json_object_set_new(res, "collapseThreads", json_boolean(window.collapse));
    } else {
        json_object_set_new(res, "collapseThreads", json_null());
    }
    json_object_set_new(res, "state", jmap_getstate(req, 0/*mbtype*/));
    json_object_set_new(res, "canCalculateUpdates", window.cancalcupdates ? json_true() : json_false());
    json_object_set_new(res, "position", json_integer(window.position));
    json_object_set_new(res, "total", json_integer(total));
    json_object_set(res, "filter", filter);
    json_object_set(res, "sort", sort);
    json_object_set(res, "ids", messageids);
    json_object_set(res, "threadIds", threadids);

    item = json_pack("[]");
    json_array_append_new(item, json_string("Email/query"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (messageids) json_decref(messageids);
    if (threadids) json_decref(threadids);
    return r;
}

static int getEmailsListUpdates(jmap_req_t *req)
{
    int r;
    json_t *filter, *sort;
    json_t *added = NULL, *removed = NULL, *threadids = NULL, *collapse = NULL, *item, *res;
    int pe;
    const char *since = NULL, *upto = NULL;
    int max = 0;
    struct getmsglist_window window;
    size_t total, total_threads;

    /* Parse and validate arguments. */
    json_t *invalid = json_pack("[]");
    json_t *unsupported_filter = json_pack("[]");
    json_t *unsupported_sort = json_pack("[]");

    /* filter */
    filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        validate_msgfilter(filter, "filter", invalid, unsupported_filter);
    }

    /* sort */
    sort = json_object_get(req->args, "sort");
    if (JNOTNULL(sort)) {
        validate_sort(sort, invalid, unsupported_sort, is_supported_msglist_sort);
    }

    /* windowing */
    memset(&window, 0, sizeof(struct getmsglist_window));
    if ((collapse = json_object_get(req->args, "collapseThreads"))) {
        readprop(req->args, "collapseThreads", 0, invalid, "b", &window.collapse);
    }

    /* sinceState */
    pe = readprop(req->args, "sinceState", 1, invalid, "s", &since);
    if (pe > 0 && !atomodseq_t(since)) {
        json_array_append_new(invalid, json_string("sinceState"));
    }

    /* uptoEmailId */
    readprop(req->args, "uptoEmailId", 0, invalid, "s", &upto);

    /* maxChanges */
    readprop(req->args, "maxChanges", 0, invalid, "I", &max);
    if (max < 0) json_array_append_new(invalid, json_string("maxChanges"));

    /* Bail out for argument errors */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        json_decref(unsupported_filter);
        json_decref(unsupported_sort);
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Report unsupported filters and sorts */
    if (json_array_size(unsupported_filter)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "unsupportedFilter", "filters", unsupported_filter);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        json_decref(unsupported_sort);
        r = 0;
        goto done;
    }
    json_decref(unsupported_filter);
    if (json_array_size(unsupported_sort)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "unsupportedSort", "sort", unsupported_sort);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(unsupported_sort);

    /* XXX - add search_is_mutable tests */

    /* Set up search window */
    window.sincemodseq = atomodseq_t(since);
    window.uptomsgid = upto;

    r = jmapmsg_search(req, filter, sort, &window, /*include_expunged*/1, &total, &total_threads,
                       &added, &removed, &threadids);
    if (r == IMAP_SEARCH_MUTABLE) {
        json_t *err = json_pack("{s:s,s:s}", "type", "cannotCalculateChanges", "error", "Search is mutable");
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    if (r == IMAP_NOTFOUND) {
        json_t *err = json_pack("{s:s}", "type", "unsupportedFilter");
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    else if (r) goto done;

    if (max && json_array_size(added) + json_array_size(removed) > (unsigned)max) {
        json_t *err = json_pack("{s:s}", "type", "tooManyChanges");
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }

    json_t *oldstate = json_string(since);

    /* Prepare response. */
    res = json_pack("{}");
    json_object_set_new(res, "accountId", json_string(req->accountid));
    if (JNOTNULL(collapse)) {
        json_object_set_new(res, "collapseThreads", json_boolean(window.collapse));
    } else {
        json_object_set_new(res, "collapseThreads", json_null());
    }
    json_object_set_new(res, "oldState", oldstate);
    json_object_set_new(res, "newState", jmap_getstate(req, 0/*mbtype*/));
    json_object_set(res, "added", added);
    json_object_set(res, "removed", removed);
    json_object_set(res, "filter", filter);
    json_object_set(res, "sort", sort);
    json_object_set_new(res, "uptoEmailId", json_string(upto));
    json_object_set_new(res, "total", json_integer(total));

    item = json_pack("[]");
    json_array_append_new(item, json_string("Email/queryChanges"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (added) json_decref(added);
    if (removed) json_decref(removed);
    if (threadids) json_decref(threadids);
    return r;
}

static int getEmailsUpdates(jmap_req_t *req)
{
    int r = 0, pe;
    json_t *filter = NULL, *sort = NULL;
    json_t *changed = NULL, *removed = NULL, *invalid = NULL, *item = NULL, *res = NULL, *threads = NULL;
    json_int_t max = 0;
    size_t total, total_threads;
    int has_more = 0;
    json_t *oldstate, *newstate;
    struct getmsglist_window window;
    const char *since;

    /* Parse and validate arguments. */
    invalid = json_pack("[]");

    /* sinceState */
    pe = readprop(req->args, "sinceState", 1, invalid, "s", &since);
    if (pe > 0 && !atomodseq_t(since)) {
        json_array_append_new(invalid, json_string("sinceState"));
    }
    /* maxChanges */
    memset(&window, 0, sizeof(struct getmsglist_window));
    readprop(req->args, "maxChanges", 0, invalid, "I", &max);
    if (max < 0) json_array_append_new(invalid, json_string("maxChanges"));
    window.limit = max;

    /* Bail out for argument errors */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }

    json_decref(invalid);

    /* Search for updates */
    filter = json_pack("{s:s}", "sinceEmailState", since);
    sort = json_pack("[{s:s}]", "property", "emailState");

    r = jmapmsg_search(req, filter, sort, &window, /*want_expunge*/1,
                       &total, &total_threads, &changed, &removed, &threads);
    if (r == IMAP_NOTFOUND) {
        json_t *err = json_pack("{s:s}", "type", "unsupportedFilter");
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    else if (r) goto done;

    has_more = (json_array_size(changed) + json_array_size(removed)) < total;
    oldstate = json_string(since);
    if (has_more || json_array_size(changed) || json_array_size(removed)) {
        newstate = jmap_fmtstate(window.highestmodseq);
    }
    else {
        newstate = json_incref(oldstate);
    }

    /* Prepare response. */
    res = json_pack("{}");
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_object_set_new(res, "oldState", oldstate);
    json_object_set_new(res, "newState", newstate);
    json_object_set_new(res, "hasMoreUpdates", json_boolean(has_more));
    json_object_set(res, "changed", changed);
    json_object_set(res, "removed", removed);

    item = json_pack("[]");
    json_array_append_new(item, json_string("Email/changes"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (sort) json_decref(sort);
    if (filter) json_decref(filter);
    if (threads) json_decref(threads);
    if (changed) json_decref(changed);
    if (removed) json_decref(removed);
    return r;
}

static int getThreadsUpdates(jmap_req_t *req)
{
    int pe, has_more = 0, r = 0;
    json_int_t max = 0;
    json_t *invalid, *item, *res, *oldstate, *newstate;
    json_t *changed = NULL;
    json_t *removed = NULL;
    json_t *threads = NULL;
    json_t *val;
    size_t total, total_threads, i;
    struct getmsglist_window window;
    const char *since;
    conversation_t *conv = NULL;

    /* Parse and validate arguments. */
    invalid = json_pack("[]");

    /* sinceState */
    pe = readprop(req->args, "sinceState", 1, invalid, "s", &since);
    if (pe > 0 && !atomodseq_t(since)) {
        json_array_append_new(invalid, json_string("sinceState"));
    }
    /* maxChanges */
    memset(&window, 0, sizeof(struct getmsglist_window));
    readprop(req->args, "maxChanges", 0, invalid, "I", &max);
    if (max < 0) json_array_append_new(invalid, json_string("maxChanges"));
    window.limit = max;

    /* Bail out for argument errors */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Search for message updates and collapse threads */
    json_t *filter = json_pack("{s:s}", "sinceEmailState", since);
    json_t *sort = json_pack("[{s:s}]", "property", "emailState");
    window.collapse = 1;
    r = jmapmsg_search(req, filter, sort, &window, /*want_expunge*/1,
                       &total, &total_threads, &changed, &removed, &threads);
    json_decref(filter);
    json_decref(sort);
    if (r == IMAP_NOTFOUND) {
        json_t *err = json_pack("{s:s}", "type", "unsupportedFilter");
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    else if (r) goto done;

    /* Split the collapsed threads into changed and removed - the values from
       jmapmsg_search will be msgids */
    if (changed) json_decref(changed);
    if (removed) json_decref(removed);
    changed = json_pack("[]");
    removed = json_pack("[]");

    json_array_foreach(threads, i, val) {
        const char *threadid = json_string_value(val);
        conversation_id_t cid = jmap_decode_thrid(threadid);
        if (!cid) continue;

        r = conversation_load(req->cstate, cid, &conv);
        if (!conv) continue;
        if (r) {
            if (r == CYRUSDB_NOTFOUND) {
                continue;
            } else {
                goto done;
            }
        }

        json_array_append(conv->thread ? changed : removed, val);

        conversation_free(conv);
        conv = NULL;
    }

    has_more = (json_array_size(changed) + json_array_size(removed)) < total_threads;

    if (has_more) {
        newstate = jmap_fmtstate(window.highestmodseq);
    } else {
        newstate = jmap_fmtstate(jmap_highestmodseq(req, 0/*mbtype*/));
    }
    oldstate = json_string(since);

    if (!json_array_size(changed)) {
        json_decref(changed);
        changed = json_null();
    }
    if (!json_array_size(removed)) {
        json_decref(removed);
        removed = json_null();
    }

    /* Prepare response. */
    res = json_pack("{}");
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_object_set_new(res, "oldState", oldstate);
    json_object_set_new(res, "newState", newstate);
    json_object_set_new(res, "hasMoreUpdates", json_boolean(has_more));
    json_object_set(res, "changed", changed);
    json_object_set(res, "removed", removed);

    item = json_pack("[]");
    json_array_append_new(item, json_string("Thread/changes"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (conv) conversation_free(conv);
    if (changed) json_decref(changed);
    if (removed) json_decref(removed);
    if (threads) json_decref(threads);
    return r;
}

static int makesnippet(struct mailbox *mbox __attribute__((unused)),
                       uint32_t uid __attribute__((unused)),
                       int part, const char *s, void *rock)
{
    const char *propname = NULL;
    json_t *snippet = rock;


    if (part == SEARCH_PART_SUBJECT) {
        propname = "subject";
    }
    else if (part == SEARCH_PART_BODY) {
        propname = "preview";
    }

    if (propname) {
        json_object_set_new(snippet, propname, json_string(s));
    }

    return 0;
}

static int jmapmsg_snippets(jmap_req_t *req, json_t *filter, json_t *messageids,
                            json_t **snippets, json_t **notfound)
{
    struct index_state *state = NULL;
    void *intquery = NULL;
    search_builder_t *bx = NULL;
    search_text_receiver_t *rx = NULL;
    struct mailbox *mbox = NULL;
    struct searchargs *searchargs = NULL;
    struct index_init init;
    const char *msgid;
    json_t *snippet = NULL;
    int r = 0;
    json_t *val;
    size_t i;
    char *mboxname = NULL;
    static search_snippet_markup_t markup = { "<mark>", "</mark>", "..." };

    *snippets = json_pack("[]");
    *notfound = json_pack("[]");

    /* Build searchargs */
    searchargs = new_searchargs(NULL/*tag*/, GETSEARCH_CHARSET_FIRST,
                                &jmap_namespace, req->userid, req->authstate, 0);
    searchargs->root = buildsearch(req, filter, NULL);

    /* Build the search query */
    memset(&init, 0, sizeof(init));
    init.userid = req->userid;
    init.authstate = req->authstate;

    r = index_open(req->inboxname, &init, &state);
    if (r) goto done;

    bx = search_begin_search(state->mailbox, SEARCH_MULTIPLE);
    if (!bx) {
        r = IMAP_INTERNAL;
        goto done;
    }

    search_build_query(bx, searchargs->root);
    if (!bx->get_internalised) {
        r = IMAP_INTERNAL;
        goto done;
    }
    intquery = bx->get_internalised(bx);
    search_end_search(bx);
    if (!intquery) {
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Set up snippet callback context */
    snippet = json_pack("{}");
    rx = search_begin_snippets(intquery, 0, &markup, makesnippet, snippet);
    if (!rx) {
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Convert the snippets */
    json_array_foreach(messageids, i, val) {
        message_t *msg;
        msgrecord_t *mr = NULL;
        uint32_t uid;

        msgid = json_string_value(val);

        r = jmapmsg_find(req, msgid, &mboxname, &uid);
        if (r) {
            if (r == IMAP_NOTFOUND) {
                json_array_append_new(*notfound, json_string(msgid));
            }
            r = 0;
            continue;
        }

        r = jmap_openmbox(req, mboxname, &mbox, 0);
        if (r) goto done;

        r = rx->begin_mailbox(rx, mbox, /*incremental*/0);

        r = msgrecord_find(mbox, uid, &mr);
        if (r) goto doneloop;

        r = msgrecord_get_message(mr, &msg);
        if (r) goto doneloop;

        json_object_set_new(snippet, "emailId", json_string(msgid));
        json_object_set_new(snippet, "subject", json_null());
        json_object_set_new(snippet, "preview", json_null());
        index_getsearchtext(msg, rx, /*snippet*/1);
        json_array_append_new(*snippets, json_deep_copy(snippet));
        json_object_clear(snippet);
        msgrecord_unref(&mr);

        r = rx->end_mailbox(rx, mbox);
        if (r) goto done;

doneloop:
        if (mr) msgrecord_unref(&mr);
        jmap_closembox(req, &mbox);
        free(mboxname);
        mboxname = NULL;
    }

    if (!json_array_size(*notfound)) {
        json_decref(*notfound);
        *notfound = json_null();
    }

done:
    if (rx) search_end_snippets(rx);
    if (snippet) json_decref(snippet);
    if (intquery) search_free_internalised(intquery);
    if (mboxname) free(mboxname);
    if (mbox) jmap_closembox(req, &mbox);
    if (searchargs) freesearchargs(searchargs);
    if (state) {
        state->mailbox = NULL;
        index_close(&state);
    }

    return r;
}

static int filter_contains_text(json_t *filter)
{
    if (JNOTNULL(filter)) {
        json_t *val;
        size_t i;

        if (JNOTNULL(json_object_get(filter, "text"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "subject"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "body"))) {
            return 1;
        }

        /* We don't generate snippets for headers, but we
         * might find header text in the body or subject again. */
        if (JNOTNULL(json_object_get(filter, "header"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "from"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "to"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "cc"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "bcc"))) {
            return 1;
        }

        json_array_foreach(json_object_get(filter, "conditions"), i, val) {
            if (filter_contains_text(val)) {
                return 1;
            }
        }
    }
    return 0;
}

static int getSearchSnippets(jmap_req_t *req)
{
    int r = 0;
    json_t *filter, *messageids, *val, *snippets, *notfound, *res, *item;
    const char *s;
    struct buf buf = BUF_INITIALIZER;
    size_t i;

    /* Parse and validate arguments. */
    json_t *invalid = json_pack("[]");
    json_t *unsupported_filter = json_pack("[]");

    /* filter */
    filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        validate_msgfilter(filter, "filter", invalid, unsupported_filter);
    }

    /* messageIds */
    messageids = json_object_get(req->args, "emailIds");
    json_array_foreach(messageids, i, val) {
        if (!(s = json_string_value(val)) || !strlen(s)) {
            buf_printf(&buf, "emailIds[%zu]", i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }
    if (!json_is_array(messageids)) {
        json_array_append_new(invalid, json_string("emailIds"));
    }

    /* Bail out for argument errors */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        json_decref(unsupported_filter);
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Report unsupported filters */
    if (json_array_size(unsupported_filter)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "unsupportedFilter", "filters", unsupported_filter);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(unsupported_filter);

    if (json_array_size(messageids) && filter_contains_text(filter)) {
        /* Render snippets */
        r = jmapmsg_snippets(req, filter, messageids, &snippets, &notfound);
        if (r) goto done;
    } else {
        /* Trivial, snippets cant' match */
        snippets = json_pack("[]");
        notfound = json_null();

        json_array_foreach(messageids, i, val) {
            json_array_append_new(snippets, json_pack("{s:s s:n s:n}",
                        "emailId", json_string_value(val),
                        "subject", "preview"));
        }
    }

    /* Prepare response. */
    res = json_pack("{}");
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_object_set_new(res, "list", snippets);
    json_object_set_new(res, "notFound", notfound);
    json_object_set(res, "filter", filter);

    item = json_pack("[]");
    json_array_append_new(item, json_string("SearchSnippet/get"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    buf_free(&buf);
    return r;
}

static int jmapmsg_threads(jmap_req_t *req, json_t *threadids,
                           json_t **threads, json_t **notfound)
{
    conversation_t *conv = NULL;
    json_t *val;
    size_t i;
    int r = 0;

    *threads = json_pack("[]");
    *notfound = json_pack("[]");

    json_array_foreach(threadids, i, val) {
        conversation_id_t cid = 0;
        conv_thread_t *thread;

        const char *threadid = json_string_value(val);
        cid = jmap_decode_thrid(threadid);

        if (cid) r = conversation_load(req->cstate, cid, &conv);
        if (r) goto done;
        if (!conv) {
            json_array_append_new(*notfound, json_string(threadid));
            continue;
        }

        json_t *ids = json_pack("[]");
        for (thread = conv->thread; thread; thread = thread->next) {
            char *msgid = jmap_msgid(&thread->guid);
            json_array_append_new(ids, json_string(msgid));
            free(msgid);
        }

        json_t *jthread = json_pack("{s:s s:o}", "id", threadid, "emailIds", ids);
        json_array_append_new(*threads, jthread);

        conversation_free(conv);
        conv = NULL;
    }

    if (!json_array_size(*notfound)) {
        json_decref(*notfound);
        *notfound = json_null();
    }

    r = 0;

done:
    if (conv) conversation_free(conv);
    if (r) {
        json_decref(*threads);
        *threads = NULL;
        json_decref(*notfound);
        *notfound = NULL;
    }

    return r;
}

static int getThreads(jmap_req_t *req)
{
    int r;
    json_t *res, *item, *val, *threadids, *threads, *notfound;
    const char *s;
    struct buf buf = BUF_INITIALIZER;
    size_t i;

    /* Parse and validate arguments. */
    json_t *invalid = json_pack("[]");

    /* ids */
    threadids = json_object_get(req->args, "ids");
    json_array_foreach(threadids, i, val) {
        if (!(s = json_string_value(val)) || !strlen(s)) {
            buf_printf(&buf, "ids[%zu]", i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }
    if (JNOTNULL(threadids) && !json_is_array(threadids)) {
        json_array_append_new(invalid, json_string("ids"));
    }

    /* Bail out for argument errors */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Find threads */
    r = jmapmsg_threads(req, threadids, &threads, &notfound);
    if (r) goto done;

    /* Prepare response. */
    res = json_pack("{}");
    json_object_set_new(res, "state", jmap_getstate(req, 0/*mbtype*/));
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_object_set_new(res, "list", threads);
    json_object_set_new(res, "notFound", notfound);

    item = json_pack("[]");
    json_array_append_new(item, json_string("Thread/get"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    buf_free(&buf);
    return r;
}

static int getEmails(jmap_req_t *req)
{
    int r = 0;
    json_t *list = json_pack("[]");
    json_t *notfound = json_pack("[]");
    json_t *invalid = json_pack("[]");
    size_t i;
    json_t *ids, *val, *properties, *res, *item;
    hash_table *props = NULL;

    /* ids */
    ids = json_object_get(req->args, "ids");
    json_array_foreach(ids, i, val) {
        if (json_typeof(val) != JSON_STRING) {
            struct buf buf = BUF_INITIALIZER;
            buf_printf(&buf, "ids[%llu]", (unsigned long long) i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
            continue;
        }
    }
    if (!json_is_array(ids)) {
        json_array_append_new(invalid, json_string("ids"));
    }

    /* properties */
    properties = json_object_get(req->args, "properties");
    if (properties && json_array_size(properties)) {
        props = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(props, json_array_size(properties) + 1, 0);
        json_array_foreach(properties, i, val) {
            if (json_string_value(val)) {
                hash_insert(json_string_value(val), (void*)1, props);
            }
        }
    }

    /* Bail out for any property errors. */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Lookup and convert ids */
    json_array_foreach(ids, i, val) {
        const char *id = json_string_value(val);
        char *mboxname = NULL;
        msgrecord_t *mr = NULL;
        uint32_t uid;
        json_t *msg = NULL;
        struct mailbox *mbox = NULL;

        if (id[0] == '#') {
            const char *newid = hash_lookup(id + 1, &req->idmap->messages);
            if (!newid) {
                r = IMAP_NOTFOUND;
                goto doneloop;
            }
            id = newid;
        }

        r = jmapmsg_find(req, id, &mboxname, &uid);
        if (r) goto doneloop;

        r = jmap_openmbox(req, mboxname, &mbox, 0);
        if (r) goto done;

        r = msgrecord_find(mbox, uid, &mr);
        if (!r) jmapmsg_from_record(req, props, mr, &msg);

        jmap_closembox(req, &mbox);

doneloop:
        if (r == IMAP_NOTFOUND) {
            json_array_append_new(notfound, json_string(id));
            r = 0;
            continue;
        }
        if (mboxname) free(mboxname);
        if (msg) {
            json_array_append_new(list, msg);
        } else {
            json_array_append_new(notfound, json_string(id));
        }
        if (mr) msgrecord_unref(&mr);
        if (r) goto done;
    }

    if (!json_array_size(notfound)) {
        json_decref(notfound);
        notfound = json_null();
    }

    res = json_pack("{}");
    json_object_set_new(res, "state", jmap_getstate(req, 0/*mbtype*/));
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_object_set(res, "list", list);
    json_object_set(res, "notFound", notfound);

    item = json_pack("[]");
    json_array_append_new(item, json_string("Email/get"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    if (props) {
        free_hash_table(props, NULL);
        free(props);
    }
    json_decref(list);
    json_decref(notfound);
    return r;
}

static int validate_emailer(json_t *emailer,
                            const char *prefix,
                            int parseaddr,
                            json_t *invalid)
{
    struct buf buf = BUF_INITIALIZER;
    int r = 1;
    json_t *val;
    int valid = 1;

    val = json_object_get(emailer, "name");
    if (!val || json_typeof(val) != JSON_STRING) {
        buf_printf(&buf, "%s.%s", prefix, "name");
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_reset(&buf);
        r = 0;
    }
    val = json_object_get(emailer, "email");
    if (val && parseaddr && json_string_value(val)) {
        struct address *addr = NULL;
        parseaddr_list(json_string_value(val), &addr);
        if (!addr || addr->invalid || !addr->mailbox || !addr->domain || addr->next) {
            valid = 0;
        }
        parseaddr_free(addr);
    }
    if (!val || json_typeof(val) != JSON_STRING || !valid) {
        buf_printf(&buf, "%s.%s", prefix, "email");
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_reset(&buf);
        r = 0;
    }

    buf_free(&buf);
    return r;
}

static int jmapmsg_to_mime(jmap_req_t *req, FILE *out, void *rock);

#define JMAPMSG_HEADER_TO_MIME(k, v) \
    { \
       const char *_v = (v); \
       char *s = charset_encode_mimeheader(_v, strlen(_v)); \
       fprintf(out, "%s: %s\r\n", k, s); \
       free(s); \
    }

#define JMAPMSG_EMAILER_TO_MIME(b, m) \
    { \
        json_t *_m = (m); \
        const char *name = json_string_value(json_object_get(_m, "name")); \
        const char *email = json_string_value(json_object_get(_m, "email")); \
        if (strlen(name) && email) { \
            char *xname = charset_encode_mimeheader(name, strlen(name)); \
            buf_printf(b, "%s <%s>", xname, email); \
            free(xname); \
        } else if (email) { \
            buf_appendcstr(b, email); \
        } \
    }

static char* _make_boundary()
{
    char *boundary, *p, *q;

    boundary = xstrdup(makeuuid());
    for (p = boundary, q = boundary; *p; p++) {
        if (*p != '-') *q++ = *p;
    }
    *q = 0;

    return boundary;
}

static const char* split_plain(const char *s, size_t limit)
{
    const char *p = s + limit;
    while (p > s && !isspace(*p))
        p--;
    if (p == s)
        p = s + limit;
    return p;
}

static const char* split_html(const char *s, size_t limit)
{
    const char *p = s + limit;
    while (p > s && !isspace(*p) && *p != '<')
        p--;
    if (p == s)
        p = s + limit;
    return p;
}

static int writetext(const char *s, FILE *out,
                     const char* (*split)(const char *s, size_t limit))
{
    /*
     * RFC 5322 - 2.1.1.  Line Length Limits
     * There are two limits that this specification places on the number of
     * characters in a line.  Each line of characters MUST be no more than
     * 998 characters, and SHOULD be no more than 78 characters, excluding
     * the CRLF.
     */
    const char *p = s;
    const char *top = p + strlen(p);

    while (p < top) {
        const char *q = strchr(p, '\n');
        q = q ? q + 1 : top;

        if (q - p > 998) {
            /* Could split on 1000 bytes but let's have some leeway */
            q = split(p, 998);
        }

        if (fwrite(p, 1, q - p, out) < ((size_t)(q - p)))
            return -1;
        if (q < top && fputc('\n', out) == EOF)
            return -1;

        p = q;
    }

    return 0;
}

static int is_7bit_safe(const char *base, size_t len, const char *boundary __attribute__((unused)))
{
    /* XXX check if boundary exists in base - base+len ? */

    size_t linelen = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        if (base[i] == '\n') linelen = 0;
        else linelen++;

        // any long lines, reject
        if (linelen > 80) return 0;

        // any 8bit, reject
        if (base[i] & 0x80) return 0;

        // xxx - boundary match ?
    }

    return 1;
}

#define MIME_MAX_HEADER_LENGTH 78

static int writeparam(FILE *out, const char *name, const char *value,
                      int quote, int is_extended)
{
    /* Normalize arguments */
    if (quote) quote = 1;
    if (is_extended) is_extended = 1;

    if (strlen(name) + strlen(value) + 4 + quote*2 < MIME_MAX_HEADER_LENGTH) {
        /* It all fits in one line, great! */
        return fprintf(out, ";\r\n\t%s=%s%s%s",
                name,
                quote ? "\"" : "",
                value,
                quote ? "\"" : "");
    }
    else if (!is_extended && strchr(value, '\r')) {
        /* The non-extended value already includes continuations  */
        const char *p = value, *top = value + strlen(value);
        int section = 0;

        do {
            const char *q = strchr(p, '\r');
            if (!q) q = top;
            fprintf(out, ";\r\n\t%s*%d=", name, section);
            if (quote) fputc('"', out);
            fwrite(p, 1, q - p, out);
            if (quote) fputc('"', out);
            p = q + 3;
            section++;
        } while (p < top);

        return 0;
    }
    else {
        /* We have to break the values by ourselves into continuations */
        const char *p = value, *top = value + strlen(value);
        int section = 0;
        struct buf buf = BUF_INITIALIZER;

        while (p < top) {
            buf_printf(&buf, ";\r\n\t%s%s%d%s=", name,
                    is_extended ? "" : "*",
                    section,
                    is_extended ? "*" : "");

            size_t n = fwrite(buf_base(&buf), 1, buf_len(&buf), out);
            if (!n) return -1;
            buf_reset(&buf);

            if (n > MIME_MAX_HEADER_LENGTH) {
                /* We already overran the maximum length by just writing the
                 * parameter name. Let's insert a continuation so we can
                 * write any bytes of the parameter value */
                fprintf(out, "\r\n\t");
                n = 3;
            }

            const char *q, *eol = p + MIME_MAX_HEADER_LENGTH - n - quote*2;
            if (quote) fputc('"', out);
            for (q = p; q < top && q < eol; q++) {
                fputc(*q, out);
            }
            if (quote) fputc('"', out);
            p = q;
            section++;
        }
        buf_free(&buf);
    }

    return 0;
}

static int writeattach(jmap_req_t *req, json_t *att, const char *boundary, FILE *out)
{
    struct mailbox *mbox = NULL;
    struct body *body = NULL;
    const struct body *part = NULL;
    struct buf msg_buf = BUF_INITIALIZER;
    const char *blobid, *type, *cid, *name;
    strarray_t headers = STRARRAY_INITIALIZER;
    msgrecord_t *mr;
    char *ctenc = NULL, *content_type = NULL;
    uint32_t size;
    int r, name_is_ascii = 1;

    type = json_string_value(json_object_get(att, "type"));
    blobid = json_string_value(json_object_get(att, "blobId"));
    cid = json_string_value(json_object_get(att, "cid"));
    name = json_string_value(json_object_get(att, "name"));

    if (name) {
        const unsigned char *p;
        for (p = (const unsigned char*) name; *p; p++) {
            if (!isascii(*p)) {
                name_is_ascii = 0;
                break;
            }
        }
    }

    /* Find part containing blob */
    r = jmap_findblob(req, blobid, &mbox, &mr, &body, &part);
    if (r) goto done;

    /* Map the message into memory */
    r = msgrecord_get_body(mr, &msg_buf);
    if (r) goto done;

    r = msgrecord_get_size(mr, &size);
    if (r) goto done;

    if (boundary) {
        fprintf(out, "\r\n--%s\r\n", boundary);
    }

    /* Write headers */

    /* Content-Type */
    if (type) {
        content_type = xstrdup(type);
    }
    else if (part) {
        content_type = strconcat(part->type, "/", part->subtype, NULL);
        lcase(content_type);
    }
    else {
        content_type = xstrdup("email/rfc822");
    }

    fputs("Content-Type: ", out);
    fputs(content_type, out);

    if (name) {
        /* RFC 2045 dropped the "name" parameter value for Content-Type,
         * but the quasi-standard is to QP-encode any attachment name in
         * this parameter value */
        char *qpname = charset_encode_mimeheader(name, strlen(name));
        writeparam(out, "name", qpname, 1, 0);
        free(qpname);
    }
    if (part && part->params) {
        /* Copy any additional Content-Type parameters from original body */
        struct param *param;
        for (param = part->params; param; param = param->next) {
            char *param_name = lcase(xstrdup(param->attribute));
            if (strcmp(param_name, "name")) {
                const char *p;
                int need_quote = 0;
                for (p = param->value; p && *p; p++) {
                    if (strchr(MIME_TSPECIALS, *p)) {
                        need_quote = 1;
                        break;
                    }
                }
                writeparam(out, param_name, param->value, need_quote, 0);
            }
            free(param_name);
        }
    }
    fputs("\r\n", out);
    free(content_type);

    /* Content-ID */
    if (cid) {
        JMAPMSG_HEADER_TO_MIME("Content-ID", cid);
    }

    /* Content-Disposition */
    fputs("Content-Disposition: attachment", out);
    if (name) {
        /* XXX break excessively long parameter values */
        if (!name_is_ascii) {
            char *s = charset_encode_mimexvalue(name, NULL);
            writeparam(out, "filename*", s, 0, 1);
            free(s);
        } else {
            writeparam(out, "filename", name, 1, 0);
        }
    }
    fputs("\r\n", out);

    /* Raw file */
    if (!part) {
        fputs("\r\n", out);
        fwrite(msg_buf.s, 1, size, out);
    }
    /* MESSAGE parts mustn't be re-encoded, and maybe no encoding is required... */
    else if (!strcasecmp(part->type, "MESSAGE") ||
             is_7bit_safe(msg_buf.s + part->content_offset, part->content_size, boundary)) {

        strarray_add(&headers, "Content-Transfer-Encoding");
        ctenc = xstrndup(msg_buf.s + part->header_offset, part->header_size);
        message_pruneheader(ctenc, &headers, NULL);
        fwrite(ctenc, 1, strlen(ctenc), out);
        strarray_truncate(&headers, 0);
        free(ctenc);
        ctenc = NULL;

        fputs("\r\n", out);

        fwrite(msg_buf.s + part->content_offset, 1, part->content_size, out);
    }
    else if (!strcasecmp(part->type, "TEXT")) {
        size_t qplen;
        char *freeme = charset_qpencode_mimebody(msg_buf.s + part->content_offset,
                                                 body->content_size, &qplen);

        JMAPMSG_HEADER_TO_MIME("Content-Transfer-Encoding", "quoted-printable");

        fputs("\r\n", out);

        fwrite(freeme, 1, qplen, out);

        free(freeme);
    }
    else {
        size_t b64_size;

        /* Determine encoded size */
        charset_encode_mimebody(NULL, part->content_size, NULL,
                                &b64_size, NULL);

        /* Realloc buffer to accomodate encoding overhead */
        char *freeme = xmalloc(b64_size);

        /* Encode content into buffer at current position */
        charset_encode_mimebody(msg_buf.s + part->content_offset,
                                body->content_size,
                                freeme, NULL, NULL);

        JMAPMSG_HEADER_TO_MIME("Content-Transfer-Encoding", "base64");

        fputs("\r\n", out);

        fwrite(freeme, 1, b64_size, out);

        free(freeme);
    }

    r = 0;


done:
    if (mr) msgrecord_unref(&mr);
    if (mbox) jmap_closembox(req, &mbox);
    if (body) {
        message_free_body(body);
        free(body);
    }
    free(ctenc);
    buf_free(&msg_buf);
    strarray_fini(&headers);
    return r;
}

static int jmapmsg_to_mimebody(jmap_req_t *req, json_t *msg,
                             const char *boundary, FILE *out)
{
    char *freeme = NULL, *myboundary = NULL;
    size_t i;
    struct buf buf = BUF_INITIALIZER;
    int r;
    json_t *attachments = NULL, *cid_attachments = NULL, *attached_msgs = NULL;
    json_t *val = NULL, *text = NULL, *html = NULL, *mymsg = NULL;

    /* Make. a shallow copy of msg as scratchpad. */
    mymsg = json_copy(msg);

    /* Determine text bodies */
    text = json_object_get(mymsg, "textBody");
    html = json_object_get(mymsg, "htmlBody");
    json_incref(text);
    json_incref(html);

    /* Determine attached messages */
    attached_msgs = json_object_get(mymsg, "attachedEmails");
    json_incref(attached_msgs);

    /* Split attachments into ones with and without cid. If there's no
     * htmlBody defined, all attachments end up in a multipart. */
    cid_attachments = json_pack("[]");
    attachments = json_pack("[]");
    json_array_foreach(json_object_get(mymsg, "attachments"), i, val) {
        if (html && JNOTNULL(json_object_get(val, "cid")) &&
                    json_object_get(val, "isInline") == json_true()) {
            json_array_append(cid_attachments, val);
        } else {
            json_array_append(attachments, val);
        }
    }
    if (!json_array_size(cid_attachments)) {
        json_decref(cid_attachments);
        cid_attachments = NULL;
    }
    if (!json_array_size(attachments)) {
        json_decref(attachments);
        attachments = NULL;
    }

    if (boundary) {
        fprintf(out, "\r\n--%s\r\n", boundary);
    }

    if (json_array_size(attachments) || json_object_size(attached_msgs)) {
        /* Content-Type is multipart/mixed */
        json_t *submsg;
        const char *subid;
        myboundary = _make_boundary();

        buf_setcstr(&buf, "multipart/mixed; boundary=");
        buf_appendcstr(&buf, myboundary);
        JMAPMSG_HEADER_TO_MIME("Content-Type", buf_cstring(&buf));

        /* Remove any non-cid attachments and attached messages. We'll
         * write them after the trimmed down message is serialised. */
        json_object_del(mymsg, "attachments");
        json_object_del(mymsg, "attachedEmails");

        /* If there's attachments with CIDs pass them on so the
         * htmlBody can be serialised together with is attachments. */
        if (cid_attachments) {
            json_object_set(mymsg, "attachments", cid_attachments);
        }

        /* Write any remaining message bodies before the attachments */
        r = jmapmsg_to_mimebody(req, mymsg, myboundary, out);
        if (r) goto done;

        /* Write attachments */
        json_array_foreach(attachments, i, val) {
            r = writeattach(req, val, myboundary, out);
            if (r) goto done;
        }

        /* Write embedded RFC822 messages */
        json_object_foreach(attached_msgs, subid, submsg) {
            fprintf(out, "\r\n--%s\r\n", myboundary);
            fputs("Content-Type: message/rfc822;charset=UTF-8\r\n\r\n", out);
            r = jmapmsg_to_mime(req, out, submsg);
            if (r) goto done;
        }

        fprintf(out, "\r\n--%s--\r\n", myboundary);
    }
    else if (JNOTNULL(text) && JNOTNULL(html)) {
        /* Content-Type is multipart/alternative */
        myboundary = _make_boundary();

        buf_setcstr(&buf, "multipart/alternative; boundary=");
        buf_appendcstr(&buf, myboundary);
        JMAPMSG_HEADER_TO_MIME("Content-Type", buf_cstring(&buf));

        /* Remove the html body and any attachments it refers to. We'll write
         * them after the plain text body has been serialised. */
        json_object_del(mymsg, "htmlBody");
        json_object_del(mymsg, "attachments");

        /* Write the plain text body */
        r = jmapmsg_to_mimebody(req, mymsg, myboundary, out);
        if (r) goto done;

        /* Write the html body, including any of its related attachments */
        json_object_del(mymsg, "textBody");
        json_object_set(mymsg, "htmlBody", html);
        if (json_array_size(cid_attachments)) {
            json_object_set(mymsg, "attachments", cid_attachments);
        }
        r = jmapmsg_to_mimebody(req, mymsg, myboundary, out);
        if (r) goto done;

        fprintf(out, "\r\n--%s--\r\n", myboundary);
    }
    else if (html && json_array_size(cid_attachments)) {
        /* Content-Type is multipart/related */
        myboundary = _make_boundary();

        buf_setcstr(&buf, "multipart/related; type=\"text/html\"; boundary=");
        buf_appendcstr(&buf, myboundary);
        JMAPMSG_HEADER_TO_MIME("Content-Type", buf_cstring(&buf));

        /* Remove the attachments to serialise the html body */
        json_object_del(mymsg, "attachments");
        r = jmapmsg_to_mimebody(req, mymsg, myboundary, out);
        if (r) goto done;

        /* Write attachments */
        json_array_foreach(cid_attachments, i, val) {
            r = writeattach(req, val, myboundary, out);
            if (r) goto done;
        }

        fprintf(out, "\r\n--%s--\r\n", myboundary);

    }
    else if (JNOTNULL(html)) {
        /* Content-Type is text/html */
        JMAPMSG_HEADER_TO_MIME("Content-Type", "text/html;charset=UTF-8");
        fputs("\r\n", out);
        writetext(json_string_value(html), out, split_html);
    }
    else if (JNOTNULL(text)) {
        /* Content-Type is text/plain */
        JMAPMSG_HEADER_TO_MIME("Content-Type", "text/plain;charset=UTF-8");
        fputs("\r\n", out);
        writetext(json_string_value(text), out, split_plain);
    }

    /* All done */
    r = 0;

done:
    if (myboundary) free(myboundary);
    if (freeme) free(freeme);
    json_decref(attachments);
    json_decref(cid_attachments);
    json_decref(attached_msgs);
    json_decref(text);
    json_decref(html);
    json_decref(mymsg);
    buf_free(&buf);
    if (r) r = HTTP_SERVER_ERROR;
    return r;
}

/* Write the JMAP Email msg in RFC-5322 compliant wire format.
 *
 * The message is assumed to not contain value errors. If 'date' is neither
 * set in the message headers nor property, the current date is set. If
 * From isn't set, the userid of the current jmap request is used as
 * email address.
 *
 * Return 0 on success or non-zero if writing to the file failed */
static int jmapmsg_to_mime(jmap_req_t *req, FILE *out, void *rock)
{
    json_t *msg = rock;
    struct jmapmsgdata {
        char *subject;
        char *to;
        char *cc;
        char *bcc;
        char *replyto;
        char *sender;
        char *from;
        char *date;
        char *messageid;
        char *mua;

        char *references;
        char *inreplyto;
        json_t *headers;
    } d;

    json_t *val, *prop, *mymsg;
    const char *key, *s;
    size_t i;
    struct buf buf = BUF_INITIALIZER;
    int r = 0;
    memset(&d, 0, sizeof(struct jmapmsgdata));

    /* Weed out special header values. */
    d.headers = json_pack("{}");
    json_object_foreach(json_object_get(msg, "headers"), key, val) {
        s = json_string_value(val);
        if (!s) {
            continue;
        } else if (!strcasecmp(key, "Bcc")) {
            d.bcc = xstrdup(s);
        } else if (!strcasecmp(key, "Cc")) {
            d.cc = xstrdup(s);
        } else if (!strcasecmp(key, "Content-Transfer-Encoding")) {
            /* Ignore */
        } else if (!strcasecmp(key, "Content-Type")) {
            /* Ignore */
        } else if (!strcasecmp(key, "Date")) {
            d.date = xstrdup(s);
        } else if (!strcasecmp(key, "From")) {
            d.from = xstrdup(s);
        } else if (!strcasecmp(key, "In-Reply-To")) {
            d.inreplyto = xstrdup(s);
        } else if (!strcasecmp(key, "Message-ID")) {
            /* Ignore */
        } else if (!strcasecmp(key, "MIME-Version")) {
            /* Ignore */
        } else if (!strcasecmp(key, "References")) {
            d.references = xstrdup(s);
        } else if (!strcasecmp(key, "Reply-To")) {
            d.replyto = xstrdup(s);
        } else if (!strcasecmp(key, "Sender")) {
            d.sender = xstrdup(s);
        } else if (!strcasecmp(key, "Subject")) {
            d.subject = xstrdup(s);
        } else if (!strcasecmp(key, "To")) {
            d.to = xstrdup(s);
        } else if (!strcasecmp(key, "User-Agent")) {
            d.mua = xstrdup(s);
        } else {
            json_object_set(d.headers, key, val);
        }
    }

    /* Override the From header */
    if ((prop = json_object_get(msg, "from"))) {
        json_array_foreach(prop, i, val) {
            if (i) buf_appendcstr(&buf, ", ");
            JMAPMSG_EMAILER_TO_MIME(&buf, val);
        }
        if (d.from) free(d.from);
        d.from = buf_newcstring(&buf);
        buf_reset(&buf);
    }
    if (!d.from) d.from = xstrdup(req->userid);

    /* Override the Sender header */
    if ((prop = json_object_get(msg, "sender"))) {
        JMAPMSG_EMAILER_TO_MIME(&buf, prop);
        if (d.sender) free(d.sender);
        d.sender = buf_newcstring(&buf);
        buf_reset(&buf);
    }

    /* Override the To header */
    if ((prop = json_object_get(msg, "to"))) {
        json_array_foreach(prop, i, val) {
            if (i) buf_appendcstr(&buf, ", ");
            JMAPMSG_EMAILER_TO_MIME(&buf, val);
        }
        if (d.to) free(d.to);
        d.to = buf_newcstring(&buf);
        buf_reset(&buf);
    }

    /* Override the Cc header */
    if ((prop = json_object_get(msg, "cc"))) {
        json_array_foreach(prop, i, val) {
            if (i) buf_appendcstr(&buf, ", ");
            JMAPMSG_EMAILER_TO_MIME(&buf, val);
        }
        if (d.cc) free(d.cc);
        d.cc = buf_newcstring(&buf);
        buf_reset(&buf);
    }

    /* Override the Bcc header */
    if ((prop = json_object_get(msg, "bcc"))) {
        json_array_foreach(prop, i, val) {
            if (i) buf_appendcstr(&buf, ", ");
            JMAPMSG_EMAILER_TO_MIME(&buf, val);
        }
        if (d.bcc) free(d.bcc);
        d.bcc = buf_newcstring(&buf);
        buf_reset(&buf);
    }

    /* Override the Reply-To header */
    if ((prop = json_object_get(msg, "replyTo"))) {
        json_array_foreach(prop, i, val) {
            if (i) buf_appendcstr(&buf, ", ");
            JMAPMSG_EMAILER_TO_MIME(&buf, val);
        }
        if (d.replyto) free(d.replyto);
        d.replyto = buf_newcstring(&buf);
        buf_reset(&buf);
    }

    /* Override Subject header */
    if ((s = json_string_value(json_object_get(msg, "subject")))) {
        if (d.subject) free(d.subject);
        d.subject = xstrdup(s);
    }
    if (!d.subject) d.subject = xstrdup("");

    /* Override Date header */
    /* Precedence (highest first): "receivedAt" property, Date header, now */
    time_t date = time(NULL);
    if ((s = json_string_value(json_object_get(msg, "receivedAt")))) {
        struct tm tm;
        strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
        date = mktime(&tm);
    }
    if (json_object_get(msg, "receivedAt") || !d.date) {
        char fmt[RFC5322_DATETIME_MAX+1];
        memset(fmt, 0, RFC5322_DATETIME_MAX+1);
        time_to_rfc5322(date, fmt, RFC5322_DATETIME_MAX+1);
        if (d.date) free(d.date);
        d.date = xstrdup(fmt);
    }

    /* Set Message-ID header */
    buf_printf(&buf, "<%s@%s>", makeuuid(), config_servername);
    d.messageid = buf_release(&buf);

    /* Set User-Agent header */
    if (!d.mua) {
        /* Cyrus server-info is great but way to expressive. Cut of
         * anything after after the main server info */
        char *p;
        d.mua = buf_newcstring(&serverinfo);
        for (p = d.mua; *p; p++) {
            if (isspace(*p)) { *p = '\0'; break; }
        }
    }

    /* Build raw message */
    fputs("MIME-Version: 1.0\r\n", out);

    /* Mandatory headers according to RFC 5322 */
    JMAPMSG_HEADER_TO_MIME("From", d.from);
    JMAPMSG_HEADER_TO_MIME("Date", d.date);

    /* Common headers */
    if (d.to)      JMAPMSG_HEADER_TO_MIME("To", d.to);
    if (d.cc)      JMAPMSG_HEADER_TO_MIME("Cc", d.cc);
    if (d.bcc)     JMAPMSG_HEADER_TO_MIME("Bcc", d.bcc);
    if (d.sender)  JMAPMSG_HEADER_TO_MIME("Sender", d.sender);
    if (d.replyto) JMAPMSG_HEADER_TO_MIME("Reply-To", d.replyto);
    if (d.subject) JMAPMSG_HEADER_TO_MIME("Subject", d.subject);

    /* References, In-Reply-To and the custom X-JMAP header */
    if (d.inreplyto)  JMAPMSG_HEADER_TO_MIME("In-Reply-To", d.inreplyto);
    if (d.references) JMAPMSG_HEADER_TO_MIME("References", d.references);

    /* Custom headers */
    json_object_foreach(d.headers, key, val) {
        char *freeme, *p, *q;
        s = json_string_value(val);
        if (!s) continue;
        freeme = xstrdup(s);
        for (q = freeme, p = freeme; *p; p++) {
            if (*p == '\n' && (p == q || *(p-1) != '\r')) {
                *p = '\0';
                JMAPMSG_HEADER_TO_MIME(key, q);
                *p = '\n';
                q = p + 1;
            }
        }
        JMAPMSG_HEADER_TO_MIME(key, q);
        free(freeme);
    }

    /* Not mandatory but we'll always write these */
    JMAPMSG_HEADER_TO_MIME("Message-ID", d.messageid);
    JMAPMSG_HEADER_TO_MIME("User-Agent", d.mua);

    /* Make a shallow copy to alter */
    mymsg = json_copy(msg);

    /* Convert html body to plain text, if required */
    if (!json_object_get(mymsg, "textBody")) {
        const char *html = json_string_value(json_object_get(mymsg, "htmlBody"));
        if (html) {
            char *tmp = extract_plain(html);
            json_object_set_new(mymsg, "textBody", json_string(tmp));
            free(tmp);
        }
    }

    /* Write message body */
    r = jmapmsg_to_mimebody(req, mymsg, NULL, out);
    json_decref(mymsg);

    if (d.from) free(d.from);
    if (d.sender) free(d.sender);
    if (d.date) free(d.date);
    if (d.to) free(d.to);
    if (d.cc) free(d.cc);
    if (d.bcc) free(d.bcc);
    if (d.replyto) free(d.replyto);
    if (d.subject) free(d.subject);
    if (d.messageid) free(d.messageid);
    if (d.references) free(d.references);
    if (d.inreplyto) free(d.inreplyto);
    if (d.mua) free(d.mua);
    if (d.headers) json_decref(d.headers);
    buf_free(&buf);
    if (r) r = HTTP_SERVER_ERROR;
    return r;
}

#undef JMAPMSG_EMAILER_TO_MIME
#undef JMAPMSG_HEADER_TO_MIME

static void validate_createmsg(json_t *msg, json_t *invalid, int is_attached)
{
    int pe;
    json_t *prop;
    const char *sval;
    int bval, intval;
    struct buf buf = BUF_INITIALIZER;
    struct tm *date = xzmalloc(sizeof(struct tm));
    char *mboxname = NULL;
    char *mboxrole = NULL;
    int validate_addr = 1;

    if (json_object_get(msg, "id")) {
        json_array_append_new(invalid, json_string("id"));
    }

    if (json_object_get(msg, "blobId")) {
        json_array_append_new(invalid, json_string("blobId"));
    }

    if (json_object_get(msg, "threadId")) {
        json_array_append_new(invalid, json_string("threadId"));
    }

    prop = json_object_get(msg, "inReplyToEmailId");
    if (JNOTNULL(prop)) {
        if (!((sval = json_string_value(prop)) && strlen(sval))) {
            json_array_append_new(invalid, json_string("inReplyToEmailId"));
        }
    }

    if (!is_attached) {
        pe = readprop(msg, "keywords", 1, invalid, "o", &prop);
        if (pe > 0) {
            const char *keyword;
            json_t *jval;

            json_object_foreach(prop, keyword, jval) {
                if (jval != json_true() || !is_valid_keyword(keyword)) {
                    buf_printf(&buf, "keywords[%s]", keyword);
                    json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                    buf_reset(&buf);
                }
            }
            if (json_object_get(prop, "$Draft")) {
                validate_addr = 0;
            }
        }
    } else if (json_object_get(msg, "keywords")) {
        json_array_append_new(invalid, json_string("keywords"));
    }

    if (json_object_get(msg, "hasAttachment")) {
        json_array_append_new(invalid, json_string("hasAttachment"));
    }

    prop = json_object_get(msg, "headers");
    if (json_object_size(prop)) {
        const char *key;
        json_t *val;
        json_object_foreach(prop, key, val) {
            int valid = strlen(key) && val && json_typeof(val) == JSON_STRING;
            /* Keys MUST only contain A-Z,* a-z, 0-9 and hyphens. */
            const char *c;
            for (c = key; *c && valid; c++) {
                if (!((*c >= 'A' && *c <= 'Z') || (*c >= 'a' && *c <= 'z') ||
                      (*c >= '0' && *c <= '9') || (*c == '-'))) {
                    valid = 0;
                }
            }
            /* Validate mail addresses in overridden header */
            int ismailheader = (!strcasecmp(key, "From") ||
                                !strcasecmp(key, "Reply-To") ||
                                !strcasecmp(key, "Cc") ||
                                !strcasecmp(key, "Bcc") ||
                                !strcasecmp(key, "To"));
            if (valid && ismailheader && validate_addr) {
                struct address *ap, *addr = NULL;
                parseaddr_list(json_string_value(val), &addr);
                if (!addr) valid = 0;
                for (ap = addr; valid && ap; ap = ap->next) {
                    if (ap->invalid || !ap->mailbox || !ap->domain) {
                        valid = 0;
                    }
                }
                parseaddr_free(addr);
            }
            if (!valid) {
                buf_printf(&buf, "header[%s]", key);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
                break;
            }
        }
    } else if (prop && json_typeof(prop) != JSON_OBJECT) {
        json_array_append_new(invalid, json_string("headers"));
    }

    prop = json_object_get(msg, "from");
    if (json_array_size(prop)) {
        json_t *emailer;
        size_t i;
        json_array_foreach(prop, i, emailer) {
            buf_printf(&buf, "from[%zu]", i);
            validate_emailer(emailer, buf_cstring(&buf), validate_addr, invalid);
            buf_reset(&buf);
        }
    } else if (JNOTNULL(prop) && json_typeof(prop) != JSON_ARRAY) {
        json_array_append_new(invalid, json_string("from"));
    }

    prop = json_object_get(msg, "to");
    if (json_array_size(prop)) {
        json_t *emailer;
        size_t i;
        json_array_foreach(prop, i, emailer) {
            buf_printf(&buf, "to[%zu]", i);
            validate_emailer(emailer, buf_cstring(&buf), validate_addr, invalid);
            buf_reset(&buf);
        }
    } else if (JNOTNULL(prop) && json_typeof(prop) != JSON_ARRAY) {
        json_array_append_new(invalid, json_string("to"));
    }

    prop = json_object_get(msg, "cc");
    if (json_array_size(prop)) {
        json_t *emailer;
        size_t i;
        json_array_foreach(prop, i, emailer) {
            buf_printf(&buf, "cc[%zu]", i);
            validate_emailer(emailer, buf_cstring(&buf), validate_addr, invalid);
            buf_reset(&buf);
        }
    } else if (JNOTNULL(prop) && json_typeof(prop) != JSON_ARRAY) {
        json_array_append_new(invalid, json_string("cc"));
    }

    prop = json_object_get(msg, "bcc");
    if (json_array_size(prop)) {
        json_t *emailer;
        size_t i;
        json_array_foreach(prop, i, emailer) {
            buf_printf(&buf, "bcc[%zu]", i);
            validate_emailer(emailer, buf_cstring(&buf), validate_addr, invalid);
            buf_reset(&buf);
        }
    } else if (JNOTNULL(prop) && json_typeof(prop) != JSON_ARRAY) {
        json_array_append_new(invalid, json_string("bcc"));
    }

    prop = json_object_get(msg, "sender");
    if (JNOTNULL(prop)) {
        validate_emailer(prop, "sender", validate_addr, invalid);
    }

    prop = json_object_get(msg, "replyTo");
    if (json_array_size(prop)) {
        json_t *emailer;
        size_t i;
        json_array_foreach(prop, i, emailer) {
            buf_printf(&buf, "replyTo[%zu]", i);
            validate_emailer(emailer, buf_cstring(&buf), validate_addr, invalid);
            buf_reset(&buf);
        }
    } else if (JNOTNULL(prop) && json_typeof(prop) != JSON_ARRAY) {
        json_array_append_new(invalid, json_string("replyTo"));
    }

    if (json_object_get(msg, "size")) {
        json_array_append_new(invalid, json_string("size"));
    }

    if (json_object_get(msg, "preview")) {
        json_array_append_new(invalid, json_string("preview"));
    }

    readprop(msg, "subject", 0, invalid, "s", &sval);
    readprop(msg, "textBody", 0, invalid, "s", &sval);
    readprop(msg, "htmlBody", 0, invalid, "s", &sval);

    prop = json_object_get(msg, "attachedEmails");
    if (json_object_size(prop)) {
        json_t *submsg;
        const char *subid;
        json_object_foreach(prop, subid, submsg) {
            json_t *subinvalid = json_pack("[]");
            json_t *errprop;
            size_t j;

            validate_createmsg(submsg, subinvalid, 1/*is_attached*/);

            buf_printf(&buf, "attachedEmails[%s]", subid);
            json_array_foreach(subinvalid, j, errprop) {
                const char *s = json_string_value(errprop);
                buf_appendcstr(&buf, ".");
                buf_appendcstr(&buf, s);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_truncate(&buf, buf_len(&buf) - strlen(s) - 1);
            }
            json_decref(subinvalid);
            buf_reset(&buf);
        }
    }
    else if (JNOTNULL(prop)) {
        json_array_append_new(invalid, json_string("attachedEmails"));
    }

    prop = json_object_get(msg, "attachments");
    if (json_array_size(prop)) {
        json_t *att;
        size_t i;

        json_array_foreach(prop, i, att) {
            const char *prefix;
            buf_printf(&buf, "attachments[%zu]", i);
            prefix = buf_cstring(&buf);

            readprop_full(att, prefix, "blobId", 1, invalid, "s", &sval);
            readprop_full(att, prefix, "type", 0, invalid, "s", &sval);
            readprop_full(att, prefix, "name", 0, invalid, "s", &sval);

            if (readprop_full(att, prefix, "cid", 0, invalid, "s", &sval) > 0) {
                struct address *addr = NULL;
                parseaddr_list(sval, &addr);
                if (!addr || addr->next || addr->name) {
                    char *freeme = strconcat(prefix, ".", "cid", NULL);
                    json_array_append_new(invalid, json_string(freeme));
                    free(freeme);
                }
                parseaddr_free(addr);
            }

            readprop_full(att, prefix, "isInline", 0, invalid, "b", &bval);
            readprop_full(att, prefix, "width", 0, invalid, "i", &intval);
            readprop_full(att, prefix, "height", 0, invalid, "i", &intval);

            buf_reset(&buf);
        }

    }
    else if (JNOTNULL(prop)) {
        json_array_append_new(invalid, json_string("attachments"));
    }

    buf_free(&buf);
    if (mboxname) free(mboxname);
    if (mboxrole) free(mboxrole);
    if (date) free(date);
}

static int copyrecord(jmap_req_t *req, struct mailbox *src, struct mailbox *dst,
                      msgrecord_t *mrw)
{
    struct appendstate as;
    int r;
    int nolink = !config_getswitch(IMAPOPT_SINGLEINSTANCESTORE);
    ptrarray_t msgrecs = PTRARRAY_INITIALIZER;

    if (!strcmp(src->uniqueid, dst->uniqueid))
        return 0;

    r = append_setup_mbox(&as, dst, req->userid, httpd_authstate,
            ACL_INSERT, NULL, &jmap_namespace, 0, EVENT_MESSAGE_COPY);
    if (r) goto done;

    ptrarray_add(&msgrecs, mrw);

    r = append_copy(src, &as, &msgrecs, nolink,
                    mboxname_same_userid(src->name, dst->name));
    if (r) {
        append_abort(&as);
        goto done;
    }

    r = append_commit(&as);
    if (r) goto done;

    sync_log_mailbox_double(src->name, dst->name);
done:
    ptrarray_fini(&msgrecs);
    return r;
}

struct updateflags_data {
    jmap_req_t *req;
    json_t *mailboxes;
    uint32_t systemflags;
};

static int updateflags_cb(const conv_guidrec_t *rec, void *rock)
{
    struct updateflags_data *d = (struct updateflags_data *) rock;
    jmap_req_t *req = d->req;
    struct mailbox *mbox = NULL;
    msgrecord_t *mrw = NULL;
    int r = 0;

    if (rec->part) return 0;

    r = jmap_openmbox(req, rec->mboxname, &mbox, 1);
    if (r) goto done;

    if (!d->mailboxes || json_object_get(d->mailboxes, mbox->uniqueid)) {

        r = msgrecord_find(mbox, rec->uid, &mrw);
        if (r) goto done;

        /* XXX only mask for DRAFT/SEEN/... ?*/
        r = msgrecord_set_systemflags(mrw, d->systemflags);
        if (r) goto done;

        r = msgrecord_rewrite(mrw);
        if (r) goto done;

        msgrecord_unref(&mrw);
    }

done:
    if (mrw) msgrecord_unref(&mrw);
    if (mbox) jmap_closembox(req, &mbox);
    return r;
}

static int delrecord(jmap_req_t *req, struct mailbox *mbox, uint32_t uid)
{
    int r;
    struct mboxevent *mboxevent = NULL;
    msgrecord_t *mrw = NULL;
    uint32_t flags;

    r = msgrecord_find(mbox, uid, &mrw);
    if (r) return r;

    r = msgrecord_get_systemflags(mrw, &flags);
    if (r) goto done;

    if (flags & FLAG_EXPUNGED) {
        r = 0;
        goto done;
    }

    /* Expunge index record */
    r = msgrecord_add_systemflags(mrw, FLAG_DELETED | FLAG_EXPUNGED);
    if (r) goto done;

    r = msgrecord_rewrite(mrw);
    if (r) goto done;

    /* Report mailbox event. */
    mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);
    mboxevent_extract_msgrecord(mboxevent, mrw);
    mboxevent_extract_mailbox(mboxevent, mbox);
    mboxevent_set_numunseen(mboxevent, mbox, -1);
    mboxevent_set_access(mboxevent, NULL, NULL, req->userid, mbox->name, 0);
    mboxevent_notify(&mboxevent);
    mboxevent_free(&mboxevent);

done:
    if (mrw) msgrecord_unref(&mrw);
    return r;
}

struct delrecord_data {
    jmap_req_t *req;
    int deleted;
    json_t *mailboxes;
};

static int delrecord_cb(const conv_guidrec_t *rec, void *rock)
{
    struct delrecord_data *d = (struct delrecord_data *) rock;
    jmap_req_t *req = d->req;
    struct mailbox *mbox = NULL;
    int r = 0;

    r = jmap_openmbox(req, rec->mboxname, &mbox, 1);
    if (r) goto done;

    if (!d->mailboxes || json_object_get(d->mailboxes, mbox->uniqueid)) {
        r = delrecord(d->req, mbox, rec->uid);
        if (!r) d->deleted++;
    }

done:
    if (mbox) jmap_closembox(req, &mbox);
    return r;
}

static int jmapmsg_append(jmap_req_t *req,
                          json_t *mailboxids,
                          strarray_t *keywords,
                          time_t internaldate,
                          int has_attachment,
                          int(*writecb)(jmap_req_t*, FILE*, void*),
                          void *rock,
                          char **msgid)
{
    int fd;
    void *addr;
    FILE *f = NULL;
    char *mboxname = NULL;
    const char *id;
    struct stagemsg *stage = NULL;
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    json_t *val, *mailboxes = NULL;
    size_t len, msgcount = 0;
    int r = HTTP_SERVER_ERROR;

    if (!internaldate) internaldate = time(NULL);

    /* Pick the mailbox to create the message in, prefer Drafts */
    mailboxes = json_pack("{}"); /* maps mailbox ids to mboxnames */
    json_object_foreach(mailboxids, id, val) {
        if (id && *id == '#') {
            id = hash_lookup(id + 1, &req->idmap->mailboxes);
        }
        if (!id) continue;

        char *name = jmapmbox_find_uniqueid(req, id);
        if (!name) continue;

        mbname_t *mbname = mbname_from_intname(name);
        char *role = jmapmbox_role(req, mbname);
        mbname_free(&mbname);
        if (role) {
            if (!strcmp(role, "drafts")) {
                if (mboxname) {
                    free(mboxname);
                }
                mboxname = xstrdup(name);
            }
        }

        if (!mboxname) {
            mboxname = xstrdup(name);
        }
        json_object_set_new(mailboxes, id, json_string(name));
        if (name) free(name);
        if (role) free(role);
    }
    if (!mboxname) {
        char *s = json_dumps(mailboxids, 0);
        syslog(LOG_ERR, "jmapmsg_append: invalid mailboxids: %s", s);
        free(s);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Create the message in the destination mailbox */
    r = jmap_openmbox(req, mboxname, &mbox, 1);
    if (r) goto done;

    /* Write the message to the filesystem */
    if (!(f = append_newstage(mbox->name, internaldate, 0, &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mbox->name);
        r = HTTP_SERVER_ERROR;
        goto done;
    }
    r = writecb(req, f, rock);
    if (r) goto done;
    if (fflush(f)) {
        r = IMAP_IOERROR;
        goto done;
    }
    fseek(f, 0L, SEEK_END);
    len = ftell(f);

    /* Generate a GUID from the raw file content */
    fd = fileno(f);
    if ((addr = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0))) {
        struct message_guid guid;
        message_guid_generate(&guid, addr, len);
        *msgid = jmap_msgid(&guid);
        munmap(addr, len);
    } else {
        r = IMAP_IOERROR;
        goto done;
    }
    fclose(f);
    f = NULL;

    /*  Check if a message with this GUID already exists */
    r = jmapmsg_count(req, *msgid, &msgcount);
    if (r && r != IMAP_NOTFOUND) {
        goto done;
    }
    if (msgcount) {
        /* A message with this GUID already exists! */
        r = IMAP_MAILBOX_EXISTS;
        goto done;
    }

    /* Great, that's a new message! */
    struct body *body = NULL;
    struct appendstate as;

    /* Append the message to the mailbox */
    qdiffs[QUOTA_MESSAGE] = 1;
    r = append_setup_mbox(&as, mbox, req->userid, httpd_authstate,
            0, qdiffs, 0, 0, EVENT_MESSAGE_NEW);
    if (r) goto done;
    r = append_fromstage(&as, &body, stage, internaldate, NULL, 0, NULL);
    if (r) {
        append_abort(&as);
        goto done;
    }
    message_free_body(body);
    free(body);

    r = append_commit(&as);
    if (r) goto done;

    /* Set system and user flags for new record */
    r = msgrecord_find(mbox, mbox->i.last_uid, &mr);
    if (r) goto done;

    uint32_t system_flags = 0;
    uint32_t user_flags[MAX_USER_FLAGS/32];
    memset(user_flags, 0, sizeof(user_flags));
    int j;

    if (has_attachment) {
        /* Set the $HasAttachment flag. We mainly use that to support
         * the hasAttachment filter property in getEmailsList */
        int userflag;
        r = mailbox_user_flag(mbox, JMAP_HAS_ATTACHMENT_FLAG, &userflag, 1);
        if (r) goto done;
        user_flags[userflag/32] |= 1<<(userflag&31);
    }

    for (j = 0; j < keywords->count; j++) {
        const char *flag = strarray_nth(keywords, j);
        if (!strcmp(flag, "$Flagged")) {
            system_flags |= FLAG_FLAGGED;
        }
        else if (!strcmp(flag, "$Answered")) {
            system_flags |= FLAG_ANSWERED;
        }
        else if (!strcmp(flag, "$Seen")) {
            system_flags |= FLAG_SEEN;
        }
        else if (!strcmp(flag, "$Draft")) {
            system_flags |= FLAG_DRAFT;
        }
        else if (strcasecmp(flag, JMAP_HAS_ATTACHMENT_FLAG)) {
            /* $HasAttachment is read-only */
            int userflag;
            r = mailbox_user_flag(mbox, flag, &userflag, 1);
            if (r) goto done;
            user_flags[userflag/32] |= 1<<(userflag&31);
        }
    }

    r = msgrecord_add_systemflags(mr, system_flags);
    if (r) goto done;

    r = msgrecord_set_userflags(mr, user_flags);
    if (r) goto done;

    r = msgrecord_rewrite(mr);
    if (r) goto done;

    /* Complete message creation */
    if (stage) {
        append_removestage(stage);
        stage = NULL;
    }
    json_object_del(mailboxes, mbox->uniqueid);

    /* Make sure there is enough quota for all mailboxes */
    qdiffs[QUOTA_STORAGE] = len;
    if (json_object_size(mailboxes)) {
        char foundroot[MAX_MAILBOX_BUFFER];
        json_t *deltas = json_pack("{}");
        const char *mbname;

        /* Count message delta for each quota root */
        json_object_foreach(mailboxes, id, val) {
            mbname = json_string_value(val);
            if (quota_findroot(foundroot, sizeof(foundroot), mbname)) {
                json_t *delta = json_object_get(deltas, mbname);
                delta = json_integer(json_integer_value(delta) + 1);
                json_object_set_new(deltas, mbname, delta);
            }
        }

        /* Check quota for each quota root. */
        json_object_foreach(deltas, mbname, val) {
            struct quota quota;
            quota_t delta = json_integer_value(val);

            quota_init(&quota, mbname);
            r = quota_check(&quota, QUOTA_STORAGE, delta * qdiffs[QUOTA_STORAGE]);
            if (!r) r = quota_check(&quota, QUOTA_MESSAGE, delta);
            quota_free(&quota);
            if (r) break;
        }
        json_decref(deltas);
        if (r) goto done;
    }

    /* Copy the message to all remaining mailboxes */
    json_object_foreach(mailboxes, id, val) {
        const char *dstname = json_string_value(val);
        struct mailbox *dst = NULL;

        if (!strcmp(mboxname, dstname))
            continue;

        r = jmap_openmbox(req, dstname, &dst, 1);
        if (r) goto done;

        r = copyrecord(req, mbox, dst, mr);

        jmap_closembox(req, &dst);
        if (r) goto done;
    }

done:
    if (f) fclose(f);
    if (stage) append_removestage(stage);
    if (mr) msgrecord_unref(&mr);
    if (mbox) jmap_closembox(req, &mbox);
    if (mboxname) free(mboxname);
    if (mailboxes) json_decref(mailboxes);
    return r;
}

struct setanswered_rock {
    jmap_req_t* req;
    const char *inreplyto;
    int found;
};

static int setanswered_cb(const conv_guidrec_t *rec, void *rock)
{
    struct setanswered_rock *data = rock;
    jmap_req_t *req = data->req;

    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    struct buf buf = BUF_INITIALIZER;
    int r;

    if (rec->part) return 0;

    r = jmap_openmbox(req, rec->mboxname, &mbox, 1);
    if (r) return r;

    r = msgrecord_find(mbox, rec->uid, &mr);
    if (r) goto done;

    /* Does this message-id match the one we are looking for? */
    r = msgrecord_get_messageid(mr, &buf);
    if (r || strcmp(data->inreplyto, buf_cstring(&buf))) goto done;

    /* Ok, its the In-Reply-To message. Set the answered flag. */
    r = msgrecord_add_systemflags(mr, FLAG_ANSWERED);
    if (r) goto done;

    /* Mark the message as found, but keep iterating. We might have
     * the same message copied across mailboxes */
    /* XXX could multiple GUIDs have the same Message-ID header value?*/
    data->found = 1;

    r = msgrecord_rewrite(mr);
    if (r) goto done;

done:
    if (mr) msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);
    buf_free(&buf);
    return r;
}

static int setanswered(jmap_req_t *req, const char *inreplyto)
{
    int r = 0, i;
    arrayu64_t cids = ARRAYU64_INITIALIZER;
    conversation_t *conv = NULL;
    char *guid = NULL;
    struct setanswered_rock rock = { req, inreplyto, 0 /*found*/ };

    r = conversations_get_msgid(req->cstate, inreplyto, &cids);
    if (r) return r;

    /* Iterate the threads returned for the inreplyto message-id. One
     * of the entries is the message itself, which might have copies
     * across mailboxes. */
    for (i = 0; i < cids.count; i++) {
        conversation_id_t cid = arrayu64_nth(&cids, i);
        conversation_free(conv);
        conv = NULL;
        r = conversation_load(req->cstate, cid, &conv);
        if (r) continue;
        struct conv_thread *thread = conv->thread;
        do {
            guid = xstrdup(message_guid_encode(&thread->guid));
            r = conversations_guid_foreach(req->cstate, guid, setanswered_cb, &rock);
            if (r) goto done;

            thread = thread->next;
            free(guid);
            guid = NULL;
        } while (!rock.found);
    }
done:
    if (conv) conversation_free(conv);
    arrayu64_fini(&cids);
    free(guid);
    return r;

}

static int jmapmsg_create(jmap_req_t *req, json_t *msg, char **msgid,
                          json_t *invalid)
{
    const char *id = NULL;
    json_t *val;
    time_t internaldate = 0;
    json_t *mailboxids = NULL;
    strarray_t keywords = STRARRAY_INITIALIZER;
    const char *keyword;

    /* Validate mailboxids here, we need them anyway */
    mailboxids = json_object_get(msg, "mailboxIds");
    json_object_foreach(mailboxids, id, val) {
        if (json_true() != val) {
            struct buf buf = BUF_INITIALIZER;
            buf_printf(&buf, "mailboxIds{%s}", id);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_free(&buf);
            continue;
        }
        const char *mboxid = id;
        if (id && *id == '#') {
            mboxid = hash_lookup(id + 1, &req->idmap->mailboxes);
        }
        char *name = NULL;
        if (!mboxid || !(name = jmapmbox_find_uniqueid(req, mboxid))) {
            struct buf buf = BUF_INITIALIZER;
            buf_printf(&buf, "mailboxIds{%s}", id);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
        free(name);
    }
    if (!json_object_size(mailboxids) && !json_array_size(invalid)) {
        json_array_append_new(invalid, json_string("mailboxIds"));
    }
    validate_createmsg(msg, invalid, 0/*is_attached*/);
    if (json_array_size(invalid)) {
        return 0;
    }

    /* Gather keywords */
    json_object_foreach(json_object_get(msg, "keywords"), keyword, val) {
        strarray_append(&keywords, keyword);
    }
    if (keywords.count > MAX_USER_FLAGS) {
        return IMAP_USERFLAG_EXHAUSTED;
    }

    /* Determine if we need to set the $HasAttachment flag */
    int has_attachment = 0;
    if (json_array_size(json_object_get(msg, "attachments")) ||
        json_object_size(json_object_get(msg, "attachedEmails"))) {
        has_attachment = 1;
    }

    /* Write message */
    int r = jmapmsg_append(req, mailboxids, &keywords, internaldate,
                           has_attachment, jmapmsg_to_mime, msg, msgid);
    strarray_fini(&keywords);
    if (r) return r;

    /* Update ANSWERED flags of replied-to messages */
    const char *header;
    json_object_foreach(json_object_get(msg, "headers"), header, val) {
        if (!strcasecmp(header, "In-Reply-To")) {
            const char *inreplyto = json_string_value(val);
            if (inreplyto) r = setanswered(req, inreplyto);
            break;
        }
    }
    return r;
}

struct msgupdate_checkacl_rock {
    jmap_req_t *req;
    json_t *newmailboxes;
    json_t *delmailboxes;
    json_t *oldmailboxes;
};

static int msgupdate_checkacl_cb(const mbentry_t *mbentry, void *xrock)
{
    struct msgupdate_checkacl_rock *rock = xrock;
    int need_rights = 0, got_rights;
    const char *id = mbentry->uniqueid;
    jmap_req_t *req = rock->req;

    if (json_object_get(rock->newmailboxes, id))
        need_rights |= ACL_INSERT|ACL_ANNOTATEMSG;
    else if (json_object_get(rock->delmailboxes, id))
        need_rights |= ACL_DELETEMSG;
    else if (json_object_get(rock->oldmailboxes, id))
        need_rights |= ACL_ANNOTATEMSG;

    if (!need_rights)
        return 0;

    got_rights = jmap_myrights(req, mbentry);
    if ((need_rights & got_rights) != need_rights)
        return IMAP_PERMISSION_DENIED;

    return 0;
}

static int jmapmsg_update(jmap_req_t *req, const char *msgid, json_t *msg,
                          json_t *invalid)
{
    uint32_t uid;
    struct mailbox *mbox = NULL;
    char *mboxname = NULL;
    msgrecord_t *mrw = NULL;
    const char *id;
    int r;
    size_t i;
    const char *field;
    json_t *val;
    json_t *mailboxids = NULL;   /* mailboxIds argument or built from patch */
    json_t *dstmailboxes = NULL; /* destination mailboxes */
    json_t *srcmailboxes = NULL; /* current mailboxes */
    json_t *oldmailboxes = NULL; /* current mailboxes that are kept */
    json_t *newmailboxes = NULL; /* mailboxes to add the message to */
    json_t *delmailboxes = NULL; /* mailboxes to delete the message from */
    json_t *keywords = NULL;     /* keywords argument or built from patch */
    uint32_t old_systemflags, new_systemflags;
    strarray_t user_flagnames = STRARRAY_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;

    if (!strlen(msgid) || *msgid == '#') {
        return IMAP_NOTFOUND;
    }

    /* Pick record from any current mailbox. That's the master copy. */
    r = jmapmsg_find(req, msgid, &mboxname, &uid);
    if (r) return r;
    srcmailboxes = jmapmsg_mailboxes(req, msgid);

    /* Lookup the msgrecord, so we can compare current and new flags */
    r = jmap_openmbox(req, mboxname, &mbox, 1);
    if (r) goto done;

    r = msgrecord_find(mbox, uid, &mrw);
    if (r) goto done;

    r = msgrecord_get_systemflags(mrw, &old_systemflags);
    if (r) goto done;
    new_systemflags = old_systemflags;

    /* Are keywords overwritten or patched? */
    keywords = json_incref(json_object_get(msg, "keywords"));
    if (keywords == NULL) {
        /* Check if keywords are patched */
        int patch_keywords = 0;
        json_object_foreach(msg, field, val) {
            if (strncmp(field, "/keywords/", 10)) {
                continue;
            }
            patch_keywords = 1;
            break;
        }
        if (patch_keywords) {
            /* Fetch current keywords from message */
            hash_table props = HASH_TABLE_INITIALIZER;
            json_t *tmpmsg = NULL;
            construct_hash_table(&props, 1, 0);
            hash_insert("keywords", (void*)1, &props);
            r = jmapmsg_from_record(req, &props, mrw, &tmpmsg);
            if (!r) {
                keywords = json_incref(json_object_get(tmpmsg, "keywords"));
            }
            json_decref(tmpmsg);
            free_hash_table(&props, NULL);
            if (r) goto done;

            /* Patch keywords */
            json_object_foreach(msg, field, val) {
                if (strncmp(field, "/keywords/", 10)) {
                    continue;
                }
                if (val == json_null()) {
                    json_object_del(keywords, field + 10);
                }
                else if (val == json_true()) {
                    json_object_set(keywords, field + 10, json_true());
                }
                else {
                    json_array_append_new(invalid, json_string(field));
                }
            }
        }
    }
    if (json_array_size(invalid)) {
        r = 0;
        goto done;
    }

    /* Prepare keyword update */
    if (JNOTNULL(keywords)) {
        const char *keyword;
        new_systemflags &= ~(FLAG_DRAFT|FLAG_FLAGGED|FLAG_ANSWERED|FLAG_SEEN);

        json_object_foreach(keywords, keyword, val) {
            if (!is_valid_keyword(keyword) || val != json_true()) {
                buf_printf(&buf, "keywords[%s]", keyword);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
                continue;
            }
            if (!strcmp(keyword, "$Flagged")) {
                new_systemflags |= FLAG_FLAGGED;
            }
            else if (!strcmp(keyword, "$Answered")) {
                new_systemflags |= FLAG_ANSWERED;
            }
            else if (!strcmp(keyword, "$Seen")) {
                new_systemflags |= FLAG_SEEN;
            }
            else if (!strcmp(keyword, "$Draft")) {
                new_systemflags |= FLAG_DRAFT;
            }
            else if (strcasecmp(keyword, JMAP_HAS_ATTACHMENT_FLAG)) {
                /* $HasAttachment is read-only */
                strarray_append(&user_flagnames, keyword);
            }
        }

        /* Reject any attempt to change the $Draft flag */
        if ((old_systemflags & FLAG_DRAFT) != (new_systemflags & FLAG_DRAFT)) {
            buf_printf(&buf, "keywords[$Draft]");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }
    if (json_object_size(keywords) > MAX_USER_FLAGS) {
        r = IMAP_USERFLAG_EXHAUSTED;
        goto done;
    }

    /* Are mailboxes being overwritten or patched? */
    mailboxids = json_incref(json_object_get(msg, "mailboxIds"));
    if (mailboxids == NULL) {
        /* Check if mailboxIds are patched */
        int patch_mailboxids = 0;
        json_object_foreach(msg, field, val) {
            if (strncmp(field, "/mailboxIds/", 12)) {
                continue;
            }
            patch_mailboxids = 1;
            break;
        }
        if (patch_mailboxids) {
            /* Build current mailboxIds argument */
            mailboxids = json_object();
            json_object_foreach(srcmailboxes, field, val) {
                json_object_set(mailboxids, field, json_true());
            }
            /* Patch mailboxIds */
            json_object_foreach(msg, field, val) {
                if (strncmp(field, "/mailboxIds/", 12)) {
                    continue;
                }
                if (val == json_true()) {
                    json_object_set(mailboxids, field + 12, json_true());
                }
                else if (val == json_null()) {
                    json_object_del(mailboxids, field + 12);
                }
                else {
                    json_array_append_new(invalid, json_string(field));
                }
            }
        }
    }
    if (json_array_size(invalid)) {
        r = 0;
        goto done;
    }

    /* Prepare mailbox update */
    if (JNOTNULL(mailboxids)) {
        dstmailboxes = json_pack("{}");
        json_object_foreach(mailboxids, id, val) {
            if (json_true() != val) {
                struct buf buf = BUF_INITIALIZER;
                buf_printf(&buf, "mailboxIds{%s}", id);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_free(&buf);
                continue;
            }
            const char *mboxid = id;
            if (id && *id == '#') {
                mboxid = hash_lookup(id + 1, &req->idmap->mailboxes);
            }
            char *name = NULL;
            if (mboxid && (name = jmapmbox_find_uniqueid(req, mboxid))) {
                json_object_set_new(dstmailboxes, mboxid, json_string(name));
            } else {
                buf_reset(&buf);
                struct buf buf = BUF_INITIALIZER;
                buf_printf(&buf, "mailboxIds{%s}", id);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
            free(name);
        }
        if (!json_object_size(dstmailboxes)) {
            json_array_append_new(invalid, json_string("mailboxIds"));
        }
    } else {
        dstmailboxes = json_deep_copy(srcmailboxes);
    }
    if (json_array_size(invalid)) {
        r = 0;
        goto done;
    }

    /* Determine mailbox differences */
    newmailboxes = json_deep_copy(dstmailboxes);
    json_object_foreach(srcmailboxes, id, val) {
        json_object_del(newmailboxes, id);
    }
    delmailboxes = json_deep_copy(srcmailboxes);
    json_object_foreach(dstmailboxes, id, val) {
        json_object_del(delmailboxes, id);
    }
    oldmailboxes = json_deep_copy(srcmailboxes);
    json_object_foreach(newmailboxes, id, val) {
        json_object_del(oldmailboxes, id);
    }
    json_object_foreach(delmailboxes, id, val) {
        json_object_del(oldmailboxes, id);
    }

    /* Check mailbox ACL for shared accounts */
    if (strcmp(req->accountid, req->userid)) {
        struct msgupdate_checkacl_rock rock = {
            req, newmailboxes, delmailboxes, oldmailboxes
        };
        r = jmap_mboxlist(req, msgupdate_checkacl_cb, &rock);
        if (r) goto done;
    }

    /* Write system flags */
    if (old_systemflags != new_systemflags) {
        r = msgrecord_set_systemflags(mrw, new_systemflags);
        if (r) goto done;
    }

    /* Write user flags */
    uint32_t user_flags[MAX_USER_FLAGS/32];
    memset(user_flags, 0, sizeof(user_flags));
    for (i = 0; i < (size_t) user_flagnames.count; i++) {
        int userflag;
        const char *flag = strarray_nth(&user_flagnames, i);
        r = mailbox_user_flag(mbox, flag, &userflag, 1);
        if (r) goto done;
        user_flags[userflag/32] |= 1<<(userflag&31);
    }
    r = msgrecord_set_userflags(mrw, user_flags);
    if (r) goto done;

    r = msgrecord_rewrite(mrw);
    if (r) goto done;

    /* Update record in kept mailboxes, except its master copy. */
    json_object_del(oldmailboxes, mbox->uniqueid);
    if (json_object_size(oldmailboxes)) {
        struct updateflags_data data = {
            req, oldmailboxes, new_systemflags
        };

        r = conversations_guid_foreach(req->cstate, msgid+1, updateflags_cb, &data);
        if (r) goto done;
    }

    /* Copy master copy to new mailboxes */
    json_object_foreach(newmailboxes, id, val) {
        const char *dstname = json_string_value(val);
        struct mailbox *dst = NULL;

        if (!strcmp(mboxname, dstname))
            continue;

        r = jmap_openmbox(req, dstname, &dst, 1);
        if (r) goto done;

        r = copyrecord(req, mbox, dst, mrw);

        jmap_closembox(req, &dst);
        if (r) goto done;
    }

    /* Remove message from mailboxes. We've checked the required ACLs already,
     * so any error here is fatal */
    if (json_object_size(delmailboxes)) {
        struct delrecord_data data = { req, 0, delmailboxes };

        r = conversations_guid_foreach(req->cstate, msgid+1, delrecord_cb, &data);
        if (r) goto done;
    }

done:
    strarray_fini(&user_flagnames);
    if (mrw) msgrecord_unref(&mrw);
    if (mbox) jmap_closembox(req, &mbox);
    json_decref(oldmailboxes);
    json_decref(srcmailboxes);
    json_decref(dstmailboxes);
    json_decref(newmailboxes);
    json_decref(delmailboxes);
    json_decref(keywords);
    json_decref(mailboxids);
    free(mboxname);
    buf_free(&buf);

    if (r) syslog(LOG_ERR, "jmapmsg_update: %s", error_message(r));
    return r;
}

static int msgdelete_checkacl_cb(const conv_guidrec_t *rec, void *rock)
{
    jmap_req_t *req = rock;
    int r = 0;
    mbentry_t *mbentry = NULL;

    if (rec->part) return 0;

    r = mboxlist_lookup(rec->mboxname, &mbentry, NULL);
    if (r) return r;

    int rights = jmap_myrights(req, mbentry);
    if (!(rights & ACL_DELETEMSG)) {
        r = IMAP_PERMISSION_DENIED;
    }

    mboxlist_entry_free(&mbentry);
    return r;
}


static int jmapmsg_delete(jmap_req_t *req, const char *msgid)
{
    int r;
    struct delrecord_data data = { req, 0, NULL };

    if (msgid[0] != 'M')
        return IMAP_NOTFOUND;

    /* Check mailbox ACL for shared accounts */
    if (strcmp(req->accountid, req->userid)) {
        r = conversations_guid_foreach(req->cstate, msgid+1, msgdelete_checkacl_cb, req);
        if (r) return r;
    }

    /* Delete messages */
    r = conversations_guid_foreach(req->cstate, msgid+1, delrecord_cb, &data);
    if (r) return r;

    return data.deleted ? 0 : IMAP_NOTFOUND;
}

static int setEmails(jmap_req_t *req)
{
    int r = 0;
    json_t *set = NULL, *create, *update, *destroy, *state, *item;

    state = json_object_get(req->args, "ifInState");
    if (JNOTNULL(state)) {
        if (jmap_cmpstate(req, state, 0/*mbtype*/)) {
            json_array_append_new(req->response, json_pack("[s, {s:s}, s]",
                        "error", "type", "stateMismatch", req->tag));
            goto done;
        }
    }
    set = json_pack("{s:s}", "accountId", req->accountid);
    json_object_set_new(set, "oldState", state);

    create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");
        const char *key;
        json_t *msg;

        json_object_foreach(create, key, msg) {
            json_t *invalid = json_pack("[]");

            if (!strlen(key)) {
                json_t *err = json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notCreated, key, err);
                continue;
            }

            char *msgid = NULL;
            r = jmapmsg_create(req, msg, &msgid, invalid);
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notCreated, key, err);
                free(msgid);
                continue;
            }
            json_decref(invalid);

            if (r == IMAP_QUOTA_EXCEEDED) {
                json_t *err = json_pack("{s:s}", "type", "maxQuotaReached");
                json_object_set_new(notCreated, key, err);
                free(msgid);
                r = 0;
                continue;
            } else if (r == IMAP_USERFLAG_EXHAUSTED) {
                json_t *err = json_pack("{s:s}", "type", "tooManyKeywords");
                json_object_set_new(notCreated, key, err);
                free(msgid);
                r = 0;
                continue;
            } else if (r) {
                free(msgid);
                goto done;
            }

            json_object_set_new(created, key, json_pack("{s:s}", "id", msgid));
            hash_insert(key, msgid, &req->idmap->messages); // hash takes ownership of msgid
        }

        if (json_object_size(created)) {
            json_object_set(set, "created", created);
        }
        json_decref(created);

        if (json_object_size(notCreated)) {
            json_object_set(set, "notCreated", notCreated);
        }
        json_decref(notCreated);
    }

    update = json_object_get(req->args, "update");
    if (update) {
        json_t *updated = json_pack("{}");
        json_t *notUpdated = json_pack("{}");
        const char *id;
        json_t *msg;

        json_object_foreach(update, id, msg) {
            json_t *invalid = json_pack("[]");
            /* Validate id */
            if (!id) {
                continue;
            }
            if (id && id[0] == '#') {
                const char *newid = hash_lookup(id + 1, &req->idmap->messages);
                if (!newid) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notUpdated, id, err);
                    continue;
                }
                id = newid;
            }
            /* Update message */
            if ((r = jmapmsg_update(req, id, msg, invalid))) {
                json_decref(invalid);
                if (r == IMAP_NOTFOUND) {
                    json_t *err= json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notUpdated, id, err);
                    r = 0;
                    continue;
                }
                else if (r == IMAP_PERMISSION_DENIED) {
                    json_t *err= json_pack("{s:s}", "type", "forbidden");
                    json_object_set_new(notUpdated, id, err);
                    r = 0;
                    continue;
                } else if (r == IMAP_USERFLAG_EXHAUSTED) {
                    json_t *err = json_pack("{s:s}", "type", "tooManyKeywords");
                    json_object_set_new(notUpdated, id, err);
                    r = 0;
                    continue;
                }
                else {
                    goto done;
                }
            }
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notUpdated, id, err);
                continue;
            }
            json_object_set_new(updated, id, json_null());
            json_decref(invalid);
        }

        if (json_object_size(updated)) {
            json_object_set(set, "updated", updated);
        }
        json_decref(updated);

        if (json_object_size(notUpdated)) {
            json_object_set(set, "notUpdated", notUpdated);
        }
        json_decref(notUpdated);
    }

    destroy = json_object_get(req->args, "destroy");
    if (destroy) {
        json_t *destroyed = json_pack("[]");
        json_t *notDestroyed = json_pack("{}");
        json_t *id;
        size_t i;

        json_array_foreach(destroy, i, id) {
            const char *msgid = json_string_value(id);
            /* Validate msgid */
            if (!msgid) {
                continue;
            }
            if (msgid && msgid[0] == '#') {
                const char *newmsgid = hash_lookup(msgid + 1, &req->idmap->messages);
                if (!newmsgid) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notDestroyed, msgid, err);
                    continue;
                }
                msgid = newmsgid;
            }
            /* Delete message */
            if ((r = jmapmsg_delete(req, msgid))) {
                if (r == IMAP_NOTFOUND) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notDestroyed, msgid, err);
                    r = 0;
                    continue;
                } else if (r == IMAP_PERMISSION_DENIED) {
                    json_t *err = json_pack("{s:s}", "type", "forbidden");
                    json_object_set_new(notDestroyed, msgid, err);
                    r = 0;
                    continue;
                } else if (r) {
                    goto done;
                }
            }
            json_array_append_new(destroyed, json_string(msgid));
        }

        if (json_array_size(destroyed)) {
            json_object_set(set, "destroyed", destroyed);
        }
        json_decref(destroyed);
        if (json_object_size(notDestroyed)) {
            json_object_set(set, "notDestroyed", notDestroyed);
        }
        json_decref(notDestroyed);
    }

    json_object_set_new(set, "newState", jmap_getstate(req, 0/*mbtype*/));
    json_object_set_new(set, "accountId", json_string(req->accountid));

    json_incref(set);
    item = json_pack("[]");
    json_array_append_new(item, json_string("Email/set"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (set) json_decref(set);
    return r;
}

struct msgimport_data {
    struct buf buf;
    const struct body *part;
};

int msgimport_cb(jmap_req_t *req __attribute__((unused)),
                      FILE *out, void *rock)
{
    struct msgimport_data *data = (struct msgimport_data*) rock;

    // we never need to pre-decode rfc822 messages, they're always 7bit (right?)
    const char *base = data->buf.s;
    size_t len = data->buf.len;
    if (data->part) {
        base += data->part->content_offset;
        len = data->part->content_size;
    }

    struct protstream *stream = prot_readmap(base, len);

    int r = message_copy_strict(stream, out, len, 0);

    prot_free(stream);

    return r;
}

struct msgimport_checkacl_rock {
    jmap_req_t *req;
    json_t *mailboxes;
};

static int msgimport_checkacl_cb(const mbentry_t *mbentry, void *xrock)
{
    struct msgimport_checkacl_rock *rock = xrock;
    jmap_req_t *req = rock->req;

    if (!json_object_get(rock->mailboxes, mbentry->uniqueid))
        return 0;

    int rights = jmap_myrights(req, mbentry);
    int mask = ACL_INSERT|ACL_ANNOTATEMSG;

    if ((rights & mask) != mask) {
        return IMAP_PERMISSION_DENIED;
    }

    return 0;
}

int jmapmsg_import(jmap_req_t *req, json_t *msg, json_t **createdmsg)
{
    int r;
    json_t *mailboxids = json_object_get(msg, "mailboxIds");

    /* Check mailboxes for ACL */
    if (req->is_shared_account) {
        size_t i;
        json_t *val;
        struct msgimport_checkacl_rock rock = { req, json_pack("{}") };
        json_array_foreach(mailboxids, i, val) {
            json_object_set(rock.mailboxes, json_string_value(val), json_true());
        }
        r = jmap_mboxlist(req, msgimport_checkacl_cb, &rock);
        json_decref(rock.mailboxes);
        if (r) return r;
    }

    /* Start import */
    struct msgimport_data content = { BUF_INITIALIZER, NULL };
    hash_table props = HASH_TABLE_INITIALIZER;
    struct body *bodystructure = NULL;
    struct mailbox *mbox = NULL;
    char *msgid = NULL;
    char *mboxname = NULL;
    uint32_t uid;
    time_t internaldate = 0;
    strarray_t keywords = STRARRAY_INITIALIZER;
    struct msgbodies bodies = MSGBODIES_INITIALIZER;
    int has_attachment = 0;

    /* Lookup blob and check if it has any attachments */
    msgrecord_t *mr = NULL;
    const char *blobid = json_string_value(json_object_get(msg, "blobId"));
    r = jmap_findblob(req, blobid, &mbox, &mr, &bodystructure, &content.part);
    if (r) goto done;
    r = msgrecord_get_body(mr, &content.buf);
    if (r) goto done;
    r = find_msgbodies(bodystructure, &content.buf, &bodies);
    if (r) goto done;
    has_attachment = bodies.atts.count + bodies.msgs.count;
    jmap_closembox(req, &mbox);
    msgrecord_unref(&mr);

    /* Gather keywords */
    const json_t *val;
    const char *kw;
    json_object_foreach(json_object_get(msg, "keywords"), kw, val) {
        strarray_append(&keywords, kw);
    }

    /* check for internaldate */
    const char *datestr = json_string_value(json_object_get(msg, "receivedAt"));
    if (datestr) {
        time_from_iso8601(datestr, &internaldate);
    }

    /* Write the message to the file system */
    r = jmapmsg_append(req, mailboxids, &keywords, internaldate,
                       has_attachment, msgimport_cb, &content, &msgid);
    if (r) goto done;

    /* Load its index record and convert to JMAP */
    r = jmapmsg_find(req, msgid, &mboxname, &uid);
    if (r) goto done;

    r = jmap_openmbox(req, mboxname, &mbox, 0);
    if (r) goto done;

    r = msgrecord_find(mbox, uid, &mr);
    if (r) goto done;

    construct_hash_table(&props, 4, 0);
    hash_insert("id", (void*)1, &props);
    hash_insert("blobId", (void*)1, &props);
    hash_insert("threadId", (void*)1, &props);
    hash_insert("size", (void*)1, &props);

    r = jmapmsg_from_record(req, &props, mr, createdmsg);
    if (r) goto done;

    jmap_closembox(req, &mbox);

done:
    ptrarray_fini(&bodies.atts);
    ptrarray_fini(&bodies.msgs);
    ptrarray_fini(&bodies.textlist);
    ptrarray_fini(&bodies.htmllist);
    strarray_fini(&keywords);
    free_hash_table(&props, NULL);
    buf_free(&content.buf);
    if (mr) msgrecord_unref(&mr);
    if (mbox) jmap_closembox(req, &mbox);
    if (bodystructure) {
        message_free_body(bodystructure);
        free(bodystructure);
    }
    free(mboxname);
    free(msgid);
    return r;
}

static int importEmails(jmap_req_t *req)
{
    int r = 0;
    json_t *res, *item, *msgs, *msg, *created, *notcreated;
    json_t *invalid, *invalidmbox;
    struct buf buf = BUF_INITIALIZER;
    const char *id;

    /* Parse and validate arguments. */
    invalid = json_pack("[]");
    invalidmbox = json_pack("[]");

    /* Import messages */
    created = json_pack("{}");
    notcreated = json_pack("{}");

    /* messages */
    msgs = json_object_get(req->args, "emails");
    json_object_foreach(msgs, id, msg) {
        const char *prefix;
        size_t i;
        json_t *val;
        const char *s;

        buf_printf(&buf, "emails[%s]", id);
        prefix = buf_cstring(&buf);

        json_t *keywords;
        if (readprop_full(msg, prefix, "keywords", 1, invalid, "o", &keywords) > 0) {
            json_array_foreach(keywords, i, val) {
                const char *kw = json_string_value(val);
                if (val != json_true() || !kw || !is_valid_keyword(kw)) {
                    buf_printf(&buf, "keywords[%s]", kw);
                    json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                    buf_reset(&buf);
                }
            }
        }

        int pe = readprop_full(msg, prefix, "receivedAt", 0, invalid, "s", &s);
        if (pe > 0) {
            struct tm date;
            const char *p = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &date);
            if (!p || *p) {
                char *tmp = strconcat(prefix, ".date", (char *)NULL);
                json_array_append_new(invalid, json_string(tmp));
                free(tmp);
            }
        }
        json_object_foreach(json_object_get(msg, "mailboxIds"), id, val) {
            char *name = NULL;
            const char *mboxid = id;
            if (mboxid && *mboxid == '#') {
                mboxid = hash_lookup(mboxid + 1, &req->idmap->mailboxes);
            }
            if (!mboxid || !(name = jmapmbox_find_uniqueid(req, mboxid))) {
                buf_printf(&buf, ".mailboxIds{%s}", id);
                json_array_append_new(invalidmbox, json_string(buf_cstring(&buf)));
            }
            free(name);
        }
        if (json_object_size(json_object_get(msg, "mailboxIds")) == 0) {
            buf_printf(&buf, ".mailboxIds");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        }

        buf_reset(&buf);
    }
    if (!json_object_size(msgs)) {
        json_array_append_new(invalid, json_string("emails"));
    }

    /* Bail out for argument */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}",
                "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response,
                json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Bail out for mailbox errors */
    if (json_array_size(invalidmbox)) {
        json_t *err = json_pack("{s:s, s:o}",
                "type", "invalidMailboxes", "mailboxes", invalidmbox);
        json_array_append_new(req->response,
                json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalidmbox);

    json_object_foreach(msgs, id, msg) {
        json_t *mymsg;

        r = jmapmsg_import(req, msg, &mymsg);
        if (r) {
            /* Try to handle the error gracefully */
            const char *err = NULL;
            switch (r) {
                case IMAP_NOTFOUND:
                    err = "attachmentNotFound";
                    break;
                case IMAP_PERMISSION_DENIED:
                    err = "forbidden";
                    break;
                case IMAP_MAILBOX_EXISTS:
                    err = "emailExists";
                    break;
                case IMAP_QUOTA_EXCEEDED:
                    err = "maxQuotaReached";
                    break;
                case IMAP_MESSAGE_CONTAINSNULL:
                    err = "emailContainsNulByte";
                    break;
                case IMAP_MESSAGE_CONTAINSNL:
                    err = "emailContainsBareNewlines";
                    break;
                case IMAP_MESSAGE_CONTAINS8BIT:
                    err = "emailContainsNonASCIIHeader";
                    break;
                case IMAP_MESSAGE_BADHEADER:
                    err = "emailContainsInvalidHeader";
                    break;
                case IMAP_MESSAGE_NOBLANKLINE:
                    err = "emailHasNoHeaderBodySeparator";
                    break;
            }
            if (err) {
                json_object_set_new(notcreated, id, json_pack("{s:s}", "type", err));
                r = 0;
                continue;
            }
            /* Any other error is fatal */
            goto done;
        }
        json_object_set_new(created, id, mymsg);

        char *mymsgid = xstrdupnull(json_string_value(json_object_get(mymsg, "id")));
        hash_insert(id, mymsgid, &req->idmap->messages); /* idmap takes ownership */
    }

    if (!json_object_size(created)) {
        json_decref(created);
        created = json_null();
    }
    if (!json_object_size(notcreated)) {
        json_decref(notcreated);
        notcreated = json_null();
    }

    /* Prepare the response */
    res = json_pack("{}");
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_object_set(res, "created", created);
    json_object_set(res, "notCreated", notcreated);

    item = json_pack("[]");
    json_array_append_new(item, json_string("Email/import"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    json_decref(created);
    json_decref(notcreated);
    buf_free(&buf);
    return r;
}

static int getIdentities(jmap_req_t *req)
{
    int r = 0;
    json_t *res, *item, *val, *ids, *notfound, *identities, *me;
    struct buf buf = BUF_INITIALIZER;
    const char *s;
    size_t i;

    /* Parse and validate arguments. */
    json_t *invalid = json_pack("[]");

    /* ids */
    ids = json_object_get(req->args, "ids");
    json_array_foreach(ids, i, val) {
        if (!(s = json_string_value(val)) || !strlen(s)) {
            buf_printf(&buf, "ids[%zu]", i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }
    if (JNOTNULL(ids) && !json_is_array(ids)) {
        json_array_append_new(invalid, json_string("ids"));
    }

    /* Bail out for argument errors */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        goto done;
    }
    json_decref(invalid);

    notfound = json_pack("[]");
    identities = json_pack("[]");

    me = json_pack("{s:s s:s s:s s:b}",
            "id", req->userid,
            "name", "",
            "email", req->userid,
            "mayDelete", 0);
    if (!strchr(req->userid, '@')) {
        json_object_set_new(me, "email", json_string(""));
    }

    /* Build the identities */
    if (json_array_size(ids)) {
        json_array_foreach(ids, i, val) {
            if (strcmp(json_string_value(val), req->userid)) {
                json_array_append(notfound, val);
            }
            else {
                json_array_append(identities, me);
            }
        }
    } else if (!JNOTNULL(ids)) {
        json_array_append(identities, me);
    }
    json_decref(me);

    /* Prepare the response */
    res = json_pack("{}");
    json_object_set_new(res, "state", json_string("0"));
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_object_set_new(res, "list", identities);
    json_object_set_new(res, "notFound", notfound);

    item = json_pack("[]");
    json_array_append_new(item, json_string("Identity/get"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    buf_free(&buf);
    return r;
}

static int validate_address(json_t *addr, const char *prefix, json_t *invalid)
{
    struct buf buf = BUF_INITIALIZER;
    int is_valid = 0;

    json_t *email = json_object_get(addr, "email");
    if (email && json_string_value(email)) {
        struct address *a = NULL;
        parseaddr_list(json_string_value(email), &a);
        if (a && !a->invalid && a->mailbox && a->domain && !a->next) {
            is_valid = 1;
        }
        parseaddr_free(a);
    }
    else {
        buf_printf(&buf, "%s.%s", prefix, "email");
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    const char *key;
    json_t *val;
    json_t *parameters = json_object_get(addr, "parameters");
    json_object_foreach(parameters, key, val) {
        if (JNOTNULL(val) && !json_is_string(val)) {
            /* FIXME validate allowed esmtp characters */
            buf_printf(&buf, "%s.parameters[%s]", prefix, key);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }

    buf_free(&buf);
    return is_valid;
}

static void address_to_smtp(smtp_addr_t *smtpaddr, json_t *addr)
{
    smtpaddr->addr = xstrdup(json_string_value(json_object_get(addr, "email")));

    const char *key;
    json_t *val;
    json_object_foreach(json_object_get(addr, "parameters"), key, val) {
        /* We never take AUTH at face value */
        if (!strcasecmp(key, "AUTH")) {
            continue;
        }
        smtp_param_t *param = xzmalloc(sizeof(smtp_param_t));
        param->key = xstrdup(key);
        param->val = xstrdup(json_string_value(val));
        ptrarray_append(&smtpaddr->params, param);
    }
}

static void envelope_to_smtp(smtp_envelope_t *smtpenv, json_t *env)
{
    address_to_smtp(&smtpenv->from, json_object_get(env, "mailFrom"));
    size_t i;
    json_t *val;
    json_array_foreach(json_object_get(env, "rcptTo"), i, val) {
        smtp_addr_t *smtpaddr = xzmalloc(sizeof(smtp_addr_t));
        address_to_smtp(smtpaddr, val);
        ptrarray_append(&smtpenv->rcpts, smtpaddr);
    }
}

static int jmap_sendrecord(jmap_req_t *req, msgrecord_t *mr, json_t *envelope, char **msgsub_id)
{
    struct buf buf = BUF_INITIALIZER;
    uint32_t uid = 0;
    struct mailbox *mbox = NULL;
    smtpclient_t *sm = NULL;
    int r = 0;
    int fd_msg = -1;

    /* Open the message file */
    const char *fname;
    r = msgrecord_get_fname(mr, &fname);
    if (r) goto done;

    fd_msg = open(fname, 0);
    if (fd_msg == -1) {
        syslog(LOG_ERR, "jmap_sendrecord: can't open %s: %m", fname);
        r = IMAP_IOERROR;
        goto done;
    }
    r = msgrecord_get_uid(mr, &uid);
    if (r) goto done;
    r = msgrecord_get_mailbox(mr, &mbox);
    if (r) goto done;

    /* Open the SMTP connection */
    r = smtpclient_open(&sm);
    if (r) goto done;
    smtpclient_set_auth(sm, req->userid);

    /* Prepare envelope */
    smtp_envelope_t smtpenv = SMTP_ENVELOPE_INITIALIZER;
    envelope_to_smtp(&smtpenv, envelope);

    /* Write message */
    struct protstream *data = prot_new(fd_msg, /*write*/0);
    r = smtpclient_sendprot(sm, &smtpenv, data);
    smtp_envelope_fini(&smtpenv);
    prot_free(data);
    if (r) goto done;

    *msgsub_id = xstrdup(makeuuid());

done:
    if (sm) smtpclient_close(&sm);
    if (fd_msg != -1) close(fd_msg);
    buf_free(&buf);
    return r;
}

static int jmap_msgsubmission_create(jmap_req_t *req, json_t *msgsub,
                                     json_t *invalid, json_t **err)
{
    struct buf buf = BUF_INITIALIZER;

    /* messageId */
    const char *msgid = NULL;
    if (readprop(msgsub, "emailId", 1, invalid, "s", &msgid) > 0) {
        if (*msgid == '#') {
            const char *id = hash_lookup(msgid + 1, &req->idmap->messages);
            if (id) {
                msgid = id;
            } else {
                json_array_append_new(invalid, json_string(msgid));
            }
        }
    }

    /* identityId */
    const char *identityid = NULL;
    if (readprop(msgsub, "identityId", 1, invalid, "s", &identityid) > 0) {
        if (strcmp(identityid, req->userid)) {
            json_array_append_new(invalid, json_string(identityid));
        }
    }

    /* envelope */
    json_t *envelope = json_object_get(msgsub, "envelope");
    if (JNOTNULL(envelope)) {
        json_t *from = json_object_get(envelope, "mailFrom");
        if (json_object_size(from)) {
            validate_address(from, "envelope.mailFrom", invalid);
        }
        else {
            json_array_append_new(invalid, json_string("envelope.mailFrom"));
        }
        json_t *rcpt = json_object_get(envelope, "rcptTo");
        if (json_array_size(rcpt)) {
            size_t i;
            json_t *addr;
            json_array_foreach(rcpt, i, addr) {
                buf_printf(&buf, "envelope.rcptTo[%zu]", i);
                validate_address(addr, buf_cstring(&buf), invalid);
                buf_reset(&buf);
            }
        }
        else {
            json_array_append_new(invalid, json_string("envelope.rcptTo"));
        }
    }

    /* Reject read-only properties */
    if (json_object_get(msgsub, "id")) {
        json_array_append_new(invalid, json_string("id"));
    }
    if (json_object_get(msgsub, "threadId")) {
        json_array_append_new(invalid, json_string("threadId"));
    }
    if (json_object_get(msgsub, "sendAt")) {
        json_array_append_new(invalid, json_string("sendAt"));
    }
    if (json_object_get(msgsub, "undoStatus")) {
        json_array_append_new(invalid, json_string("undoStatus"));
    }
    if (json_object_get(msgsub, "deliveryStatus")) {
        json_array_append_new(invalid, json_string("deliveryStatus"));
    }
    if (json_object_get(msgsub, "dsnBlobIds")) {
        json_array_append_new(invalid, json_string("dsnBlobIds"));
    }
    if (json_object_get(msgsub, "mdnBlobIds")) {
        json_array_append_new(invalid, json_string("mdnBlobIds"));
    }

    if (json_array_size(invalid)) {
        buf_free(&buf);
        return 0;
    }

    /* No more returns from here on */
    char *mboxname = NULL;
    uint32_t uid = 0;
    struct mailbox *mbox = NULL;
    json_t *myenvelope = NULL;
    msgrecord_t *mr = NULL;
    json_t *msg = NULL;
    int r = 0;

    /* Lookup the message */
    r = jmapmsg_find(req, msgid, &mboxname, &uid);
    if (r) {
        if (r == IMAP_NOTFOUND) {
            *err = json_pack("{s:s}", "type", "emailNotFound");
        }
        goto done;
    }

    /* Check ACL */
    if (!(jmap_myrights_byname(req, mboxname) & ACL_READ)) {
        *err = json_pack("{s:s}", "type", "emailNotFound");
        goto done;
    }

    /* Open the mailboxes */
    r = jmap_openmbox(req, mboxname, &mbox, 1);
    if (r) goto done;

    /* Load the message */
    mr = msgrecord_from_uid(mbox, uid);
    if (!mr) {
        /* That's a never-should-happen error */
        syslog(LOG_ERR, "Unexpected null msgrecord at %s:%d", __FILE__, __LINE__);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Extract envelope from message */
    if (!envelope) {
        hash_table props = HASH_TABLE_INITIALIZER;
        construct_hash_table(&props, 8, 0);
        hash_insert("sender", (void*)1, &props);
        hash_insert("from", (void*)1, &props);
        hash_insert("to", (void*)1, &props);
        hash_insert("cc", (void*)1, &props);
        hash_insert("bcc", (void*)1, &props);
        hash_insert("replyTo", (void*)1, &props);
        r = jmapmsg_from_record(req, &props, mr, &msg);
        free_hash_table(&props, NULL);
        if (r) goto done;

        myenvelope = json_object();
        envelope = myenvelope;

        /* Determine MAIL FROM */
        json_t *jfrom = json_object_get(json_object_get(msg, "sender"), "email");
        if (!jfrom) {
            jfrom = json_object_get(msg, "from");
            jfrom = json_object_get(json_array_get(jfrom, 0), "email");
        }
        if (!jfrom) {
            *err = json_pack("{s:s}", "type", "notPermittedFrom");
            goto done;
        }
        const char *from = json_string_value(jfrom);
        /* FIXME If the address found from this is not allowed by the identity
         * associated with this submission, the email property from the identity
         * MUST be used instead. */
        json_object_set_new(myenvelope, "mailFrom", json_pack("{s:s}", "email", from));

        /* Determine RCPT TO */
        json_t *rcpts = json_pack("{}"); /* deduplicated set of recipients */
        json_t *rcptTo = json_array();   /* envelope rcptTo value */
        size_t i;
        const char *s;
        json_t *jval;
        json_array_foreach(json_object_get(msg, "to"), i, jval) {
            s = json_string_value(json_object_get(jval, "email"));
            if (s) json_object_set(rcpts, s, json_true());
        }
        json_array_foreach(json_object_get(msg, "cc"), i, jval) {
            s = json_string_value(json_object_get(jval, "email"));
            if (s) json_object_set(rcpts, s, json_true());
        }
        json_array_foreach(json_object_get(msg, "bcc"), i, jval) {
            s = json_string_value(json_object_get(jval, "email"));
            if (s) json_object_set(rcpts, s, json_true());
        }
        json_object_foreach(rcpts, s, jval) {
            json_array_append_new(rcptTo, json_pack("{s:s}", "email", s));
        }
        json_decref(rcpts);
        json_object_set_new(myenvelope, "rcptTo", rcptTo);
    }

    /* Validate envelope */
    if (!json_array_size(json_object_get(envelope, "rcptTo"))) {
        *err = json_pack("{s:s}", "type", "noRecipients");
        goto done;
    }

    /* Send the message submission */
    char *msgsub_id = NULL;
    r = jmap_sendrecord(req, mr, envelope, &msgsub_id);
    json_object_set_new(msgsub, "id", json_string(msgsub_id));
    free(msgsub_id);
    if (r) {
        *err = json_pack("{s:s}", "type", "smtpProtocolError");
        goto done;
    }
    /* All done */

done:
    if (msg) json_decref(msg);
    if (mr) msgrecord_unref(&mr);
    if (mbox) jmap_closembox(req, &mbox);
    if (myenvelope) json_decref(myenvelope);
    free(mboxname);
    buf_free(&buf);
    return r;
}

static int getEmailSubmissions(jmap_req_t *req)
{
    int r = 0;
    json_t *list = json_pack("[]");
    json_t *notfound = json_pack("[]");
    json_t *invalid = json_pack("[]");
    size_t i;
    json_t *ids, *val, *properties;

    /* ids */
    ids = json_object_get(req->args, "ids");
    json_array_foreach(ids, i, val) {
        if (json_typeof(val) != JSON_STRING) {
            struct buf buf = BUF_INITIALIZER;
            buf_printf(&buf, "ids[%llu]", (unsigned long long) i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
            continue;
        }
    }
    if (json_array_size(ids) == 0) {
        json_array_append_new(invalid, json_string("ids"));
    }

    /* properties */
    properties = json_object_get(req->args, "properties");
    json_array_foreach(properties, i, val) {
        if (json_typeof(val) != JSON_STRING) {
            struct buf buf = BUF_INITIALIZER;
            buf_printf(&buf, "properties[%llu]", (unsigned long long) i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
            continue;
        }
    }

    /* Bail out for any property errors. */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    json_array_foreach(ids, i, val) {
        json_array_append(notfound, val);
    }
    if (!json_array_size(notfound)) {
        json_decref(notfound);
        notfound = json_null();
    }

    json_t *res = json_pack("{}");
    json_object_set_new(res, "state", jmap_getstate(req, 0/*mbtype*/));
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_object_set(res, "list", list);
    json_object_set(res, "notFound", notfound);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("EmailSubmission/get"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    json_decref(list);
    json_decref(notfound);
    return r;
}

static int setEmailSubmissions(jmap_req_t *req)
{
    int r = 0;
    json_t *set = NULL, *create, *update, *destroy, *state, *item;
    json_t *onsuccess_update = NULL;
    json_t *onsuccess_destroy = NULL;
    json_t *update_msgs = NULL;
    json_t *destroy_msgs = NULL;
    struct buf buf = BUF_INITIALIZER;

    /* Validate top-level arguments */

    /* ifInState */
    state = json_object_get(req->args, "ifInState");

    /* ifInState never fails for message submission random states */
    set = json_pack("{s:s}", "accountId", req->accountid);
    json_object_set_new(set, "oldState", state);

    /* onSuccessUpdateEmail */
    json_t *invalid = json_pack("[]");
    onsuccess_update = json_object_get(req->args, "onSuccessUpdateEmail");
    if (JNOTNULL(onsuccess_update)) {
        if (json_is_object(onsuccess_update)) {
            const char *key;
            json_t *val;
            json_object_foreach(onsuccess_update, key, val) {
                if (!json_is_object(val)) {
                    buf_printf(&buf, "onSuccessUpdateEmail[%s]", key);
                    json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                    buf_reset(&buf);
                }
            }
        } else {
            json_array_append_new(invalid, json_string("onSuccessUpdateEmail"));
        }
    }
    /* onSuccessDestroyEmail */
    onsuccess_destroy = json_object_get(req->args, "onSuccessDestroyEmail");
    if (JNOTNULL(onsuccess_destroy)) {
        validate_string_array(onsuccess_destroy, "onSuccessDestroyEmail", invalid);
    }

    /* Return early for argument errors */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}",
                "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);
    invalid = NULL;

    /* Handle create, update, destroy */

    update_msgs = json_pack("{}");
    destroy_msgs = json_pack("[]");

    create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");
        const char *key;
        json_t *msgsub;

        json_object_foreach(create, key, msgsub) {
            json_t *invalid = json_pack("[]");

            /* Create the message submission or return on error. Process
             * errors in order of: fatal errors, setErrors, property errors */
            json_t *err = NULL;
            r = jmap_msgsubmission_create(req, msgsub, invalid, &err);
            if (err) {
                json_object_set_new(notCreated, key, err);
                r = 0;
                continue;
            }
            else if (r) {
                goto done;
            }
            else if (err) {
                json_object_set_new(notCreated, key, err);
                r = 0;
                continue;
            }
            else if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notCreated, key, err);
                continue;
            }
            json_decref(invalid);

            /* Report this message submission as created */
            const char *id = json_string_value(json_object_get(msgsub, "id"));
            json_object_set_new(created, key, json_pack("{s:s}", "id", id));

            /* Build its creation id */
            buf_setcstr(&buf, "#");
            buf_appendcstr(&buf, key);
            buf_cstring(&buf);
            const char *msgid = json_string_value(json_object_get(msgsub, "emailId"));

            /* Process onSuccessUpdateEmail */
            json_t *msg = json_object_get(onsuccess_update, buf_cstring(&buf));
            if (msg) {
                    json_object_set(update_msgs, msgid, msg);
            }
            /* Process onSuccessDestroyEmail */
            size_t i;
            json_t *jkey;
            json_array_foreach(onsuccess_destroy, i, jkey) {
                if (!strcmp(buf_cstring(&buf), json_string_value(jkey))) {
                    json_array_append(destroy_msgs, json_string(msgid));
                }
            }
            buf_reset(&buf);
        }

        if (json_object_size(created)) {
            json_object_set(set, "created", created);
        }
        json_decref(created);

        if (json_object_size(notCreated)) {
            json_object_set(set, "notCreated", notCreated);
        }
        json_decref(notCreated);
    }

    update = json_object_get(req->args, "update");
    if (update) {
        json_t *updated = json_pack("{}");
        json_t *notUpdated = json_pack("{}");
        const char *id;
        json_t *msgsub;

        json_object_foreach(update, id, msgsub) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(notUpdated, id, err);
            r = 0;
        }

        if (json_object_size(updated)) {
            json_object_set(set, "updated", updated);
        }
        json_decref(updated);

        if (json_object_size(notUpdated)) {
            json_object_set(set, "notUpdated", notUpdated);
        }
        json_decref(notUpdated);
    }

    destroy = json_object_get(req->args, "destroy");
    if (destroy) {
        json_t *destroyed = json_pack("[]");
        json_t *notDestroyed = json_pack("{}");
        json_t *jid;
        size_t i;

        json_array_foreach(destroy, i, jid) {
            const char *id = json_string_value(jid);
            if (!id) continue;

            json_object_set_new(notDestroyed, id,
                    json_pack("{s:s}", "type", "notFound"));
        }

        if (json_array_size(destroyed)) {
            json_object_set(set, "destroyed", destroyed);
        }
        json_decref(destroyed);

        if (json_object_size(notDestroyed)) {
            json_object_set(set, "notDestroyed", notDestroyed);
        }
        json_decref(notDestroyed);
    }

    if (json_object_size(json_object_get(set, "created")) ||
        json_object_size(json_object_get(set, "updated")) ||
        json_array_size(json_object_get(set, "destroyed"))) {
        /* Create a random new state */
        json_object_set_new(set, "newState", json_string(makeuuid()));
    }
    else {
        /* Keep the old state */
        json_object_set(set, "newState", state);
    }

    json_object_set_new(set, "accountId", json_string(req->accountid));

    json_incref(set);
    item = json_pack("[]");
    json_array_append_new(item, json_string("EmailSubmission/set"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

    if (json_object_size(update_msgs) || json_array_size(destroy_msgs)) {
        struct jmap_req subreq = *req;
        subreq.args = json_pack("{}");
        if (json_object_size(update_msgs)) {
            json_object_set(subreq.args, "update", update_msgs);
        }
        if (json_array_size(destroy_msgs)) {
            json_object_set(subreq.args, "destroy", destroy_msgs);
        }
        json_object_set_new(subreq.args, "accountId", json_string(req->accountid));
        r = setEmails(&subreq);
        json_decref(subreq.args);
        if (r) goto done;
    }

done:
    if (set) json_decref(set);
    json_decref(update_msgs);
    json_decref(destroy_msgs);
    buf_free(&buf);
    if (r) {
        syslog(LOG_ERR, "setEmailSubmissions: %s", error_message(r));
        r = HTTP_SERVER_ERROR;
    }
    return r;
}

static int getEmailSubmissionsUpdates(jmap_req_t *req)
{
    int pe;
    json_int_t max = 0;
    json_t *invalid, *res, *oldstate, *newstate;
    const char *since;

    /* Parse and validate arguments. */
    invalid = json_pack("[]");

    /* sinceState */
    pe = readprop(req->args, "sinceState", 1, invalid, "s", &since);
    if (pe > 0 && !atomodseq_t(since)) {
        json_array_append_new(invalid, json_string("sinceState"));
    }
    /* maxChanges */
    readprop(req->args, "maxChanges", 0, invalid, "I", &max);
    if (max < 0) json_array_append_new(invalid, json_string("maxChanges"));

    /* Bail out for argument errors */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        goto done;
    }
    json_decref(invalid);

    /* Trivially find no message submission updates at all. */
    oldstate = json_string(since);
    newstate = jmap_getstate(req, 0/*mbtype*/);

    /* Prepare response. */
    res = json_pack("{}");
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_object_set_new(res, "oldState", oldstate);
    json_object_set_new(res, "newState", newstate);
    json_object_set_new(res, "hasMoreUpdates", json_false());
    json_object_set_new(res, "changed", json_null());
    json_object_set_new(res, "removed", json_null());

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("EmailSubmission/changes"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    return 0;
}

static void validate_msgsub_filter(json_t *filter, const char *prefix, json_t *invalid)
{
    struct buf buf = BUF_INITIALIZER;
    json_t *arg;
    const char *s;

    if (!JNOTNULL(filter) || json_typeof(filter) != JSON_OBJECT) {
        json_array_append_new(invalid, json_string(prefix));
    }

    if (readprop_full(filter, prefix, "before", 0, invalid, "s", &s) > 0) {
        struct tm tm;
        const char *p = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
        if (!p || *p) {
            buf_printf(&buf, "%s.before", prefix);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }

    if (readprop_full(filter, prefix, "after", 0, invalid, "s", &s) > 0) {
        struct tm tm;
        const char *p = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
        if (!p || *p) {
            buf_printf(&buf, "%s.after", prefix);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }

    arg = json_object_get(filter, "emailIds");
    buf_printf(&buf, "%s.messageIds", prefix);
    validate_string_array(arg, buf_cstring(&buf), invalid);
    buf_reset(&buf);

    arg = json_object_get(filter, "threadIds");
    buf_printf(&buf, "%s.threadIds", prefix);
    validate_string_array(arg, buf_cstring(&buf), invalid);
    buf_reset(&buf);

    arg = json_object_get(filter, "emailSubmissionIds");
    buf_printf(&buf, "%s.messageSubmissionIds", prefix);
    validate_string_array(arg, buf_cstring(&buf), invalid);
    buf_reset(&buf);

    buf_free(&buf);
}

static int is_supported_msgsub_sort(const jmap_comparator_t *comp)
{
    if (comp->collation) {
        return 0;
    }
    if (!strcmp(comp->property, "emailId") ||
        !strcmp(comp->property, "threadId") ||
        !strcmp(comp->property, "sentAt")) {
        return 1;
    }
    return 0;
}

static int getEmailSubmissionsList(jmap_req_t *req)
{
    int r = 0;
    json_t *filter, *sort;
    json_t *messageids = NULL, *threadids = NULL, *msgsubids = NULL;
    json_int_t i = 0;

    /* Parse and validate arguments. */
    json_t *invalid = json_pack("[]");
    json_t *unsupported_filter = json_pack("[]");
    json_t *unsupported_sort = json_pack("[]");

    /* filter */
    filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        validate_msgsub_filter(filter, "filter", invalid);
    }

    /* sort */
    sort = json_object_get(req->args, "sort");
    if (JNOTNULL(sort)) {
        validate_sort(sort, invalid, unsupported_sort, is_supported_msgsub_sort);
    }

    if (readprop(req->args, "position", 0, invalid, "I", &i) > 0) {
        if (i < 0) json_array_append_new(invalid, json_string("position"));
    }

    if (readprop(req->args, "limit", 0, invalid, "I", &i) > 0) {
        if (i < 0) json_array_append_new(invalid, json_string("limit"));
    }

    /* Bail out for argument errors */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        json_decref(unsupported_filter);
        json_decref(unsupported_sort);
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Report unsupported filters and sorts */
    if (json_array_size(unsupported_filter)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "unsupportedFilter", "filters", unsupported_filter);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        json_decref(unsupported_sort);
        r = 0;
        goto done;
    }
    json_decref(unsupported_filter);
    if (json_array_size(unsupported_sort)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "unsupportedSort", "sort", unsupported_sort);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(unsupported_sort);

    /* Trivially find no message submissions at all. */
    threadids = json_pack("[]");
    messageids = json_pack("[]");
    msgsubids = json_pack("[]");

    /* Prepare response. */
    json_t *res = json_pack("{}");
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_object_set_new(res, "state", jmap_getstate(req, 0/*mbtype*/));
    json_object_set_new(res, "canCalculateUpdates", json_false());
    json_object_set_new(res, "position", json_integer(0));
    json_object_set_new(res, "total", json_integer(0));
    json_object_set(res, "filter", filter);
    json_object_set(res, "sort", sort);
    json_object_set(res, "ids", msgsubids);
    json_object_set(res, "emailIds", messageids);
    json_object_set(res, "threadIds", threadids);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("EmailSubmission/query"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (messageids) json_decref(messageids);
    if (threadids) json_decref(threadids);
    if (msgsubids) json_decref(msgsubids);
    return r;
}

static int getEmailSubmissionsListUpdates(jmap_req_t *req)
{
    int r = 0, pe;
    json_t *filter, *sort;
    json_t *added = NULL, *removed = NULL, *oldstate = NULL, *newstate = NULL;
    json_int_t max = 0;
    const char *since;

    /* Parse and validate arguments. */
    json_t *invalid = json_pack("[]");
    json_t *unsupported_filter = json_pack("[]");
    json_t *unsupported_sort = json_pack("[]");

    /* filter */
    filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        validate_msgsub_filter(filter, "filter", invalid);
    }

    /* sort */
    sort = json_object_get(req->args, "sort");
    if (JNOTNULL(sort)) {
        validate_sort(sort, invalid, unsupported_sort, is_supported_msgsub_sort);
    }

    /* sinceState */
    pe = readprop(req->args, "sinceState", 1, invalid, "s", &since);
    if (pe > 0 && !atomodseq_t(since)) {
        json_array_append_new(invalid, json_string("sinceState"));
    }
    /* maxChanges */
    readprop(req->args, "maxChanges", 0, invalid, "I", &max);
    if (max < 0) json_array_append_new(invalid, json_string("maxChanges"));

    /* Bail out for argument errors */
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        json_decref(unsupported_filter);
        json_decref(unsupported_sort);
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Report unsupported filters and sorts */
    if (json_array_size(unsupported_filter)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "unsupportedFilter", "filters", unsupported_filter);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        json_decref(unsupported_sort);
        r = 0;
        goto done;
    }
    json_decref(unsupported_filter);
    if (json_array_size(unsupported_sort)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "unsupportedSort", "sort", unsupported_sort);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(unsupported_sort);

    /* Trivially find no message submission list updates at all. */
    added = json_pack("[]");
    removed = json_pack("[]");
    oldstate = json_string(since);
    newstate = jmap_getstate(req, 0/*mbtype*/);

    /* Prepare response. */
    json_t *res = json_pack("{}");
    json_object_set_new(res, "accountId", json_string(req->accountid));
    json_object_set_new(res, "oldState", oldstate);
    json_object_set_new(res, "newState", newstate);
    json_object_set_new(res, "total", json_integer(0));

    json_object_set(res, "added", added);
    json_object_set(res, "removed", removed);
    json_object_set(res, "filter", filter);
    json_object_set(res, "sort", sort);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("EmailSubmissions/queryChanges"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (added) json_decref(added);
    if (removed) json_decref(removed);
    return r;
}
