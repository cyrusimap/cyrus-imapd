/* jmap_mailbox.c -- Routines for handling JMAP Mailboxes messages
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "bsearch.h"
#include "cyr_qsort_r.h"
#include "http_jmap.h"
#include "jmap_mail.h"
#include "jmap_mailbox.h"
#include "json_support.h"
#include "mailbox.h"
#include "mappedfile.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "msgrecord.h"
#include "statuscache.h"
#include "stristr.h"
#include "sync_log.h"
#include "user.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"


static int jmap_mailbox_get(jmap_req_t *req);
static int jmap_mailbox_set(jmap_req_t *req);
static int jmap_mailbox_changes(jmap_req_t *req);
static int jmap_mailbox_query(jmap_req_t *req);
static int jmap_mailbox_querychanges(jmap_req_t *req);

struct rolesort_data {
    const char *name;
    int order;
};

static struct rolesort_data ROLESORT[] = {
    { "inbox", 1 },
    { "archive", 3 },
    { "drafts", 4 },
    { "sent", 5 },
    { "junk", 6 },
    { "trash", 7 },
    { "xtemplates", 9 },
    { NULL, 10 }  // default
};

static jmap_method_t jmap_mailbox_methods_standard[] = {
    {
        "Mailbox/get",
        JMAP_URN_MAIL,
        &jmap_mailbox_get,
        JMAP_NEED_CSTATE
    },
    {
        "Mailbox/set",
        JMAP_URN_MAIL,
        &jmap_mailbox_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "Mailbox/changes",
        JMAP_URN_MAIL,
        &jmap_mailbox_changes,
        JMAP_NEED_CSTATE
    },
    {
        "Mailbox/query",
        JMAP_URN_MAIL,
        &jmap_mailbox_query,
        JMAP_NEED_CSTATE
    },
    {
        "Mailbox/queryChanges",
        JMAP_URN_MAIL,
        &jmap_mailbox_querychanges,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};

static jmap_method_t jmap_mailbox_methods_nonstandard[] = {
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_mailbox_init(jmap_settings_t *settings)
{
    jmap_method_t *mp;
    for (mp = jmap_mailbox_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        for (mp = jmap_mailbox_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }
}

HIDDEN void jmap_mailbox_capabilities(json_t *account_capabilities
                                      __attribute__((unused)))
{
}


/*
 * Mailboxes
 */

struct shared_mboxes {
    int is_owner;
    strarray_t mboxes;
    jmap_req_t *req;
};

/*
 * We distinguish shared mailboxes by the following types:
 *
 * it is trivially _MBOX_VISIBLE, without checking ACL rights.
 * - _SHAREDMBOX_HIDDEN: this mailbox is not visible at all to the
 *                       currently authenticated account
 * - _SHAREDMBOX_PARENT: this mailbox is not readable, but it is
 *                       the parent mailbox of a shared mailbox.
 *                       E.g. it is reported in Mailbox/get but
 *                       some of its properties are anonymised.
 * - _SHAREDMBOX_SHARED: this mailbox is fully readable by the current
 *                       user, that is, its ACL provides at least
 *                       JACL_READITEMS rights
 *
 * If the mailbox is a child of the authenticated user's INBOX,
 * it is trivially _SHAREDMBOX_SHARED, without checking ACL rights.
 */
enum shared_mbox_type {
    _SHAREDMBOX_HIDDEN,
    _SHAREDMBOX_PARENT,
    _SHAREDMBOX_SHARED
};

static int _shared_mboxes_cb(const mbentry_t *mbentry, void *rock)
{
    struct shared_mboxes *sm = rock;
    int needrights = JACL_READITEMS;

    if (jmap_hasrights_mbentry(sm->req, mbentry, needrights))
        strarray_append(&sm->mboxes, mbentry->name);

    return 0;
}

struct shared_mboxes *_shared_mboxes_new(jmap_req_t *req, int flags)
{
    struct shared_mboxes *sm = xzmalloc(sizeof(struct shared_mboxes));
    sm->req = req;

    if (!strcmp(req->userid, req->accountid)) {
        /* Trivial - all mailboxes are visible */
        sm->is_owner = 1;
        return sm;
    }

    /* Gather shared mailboxes */
    int r = mboxlist_usermboxtree(req->accountid, req->authstate,
                                  _shared_mboxes_cb, sm, flags);
    if (r) {
        free(sm);
        sm = NULL;
    }
    strarray_sort(&sm->mboxes, cmpstringp_raw);
    return sm;
}

static void _shared_mboxes_free(struct shared_mboxes *sm)
{
    if (!sm) return;
    strarray_fini(&sm->mboxes);
    free(sm);
}

static enum shared_mbox_type _shared_mbox_type(struct shared_mboxes *sm,
                                               const char *name)
{
    /* Handle trivial cases */
    if (sm->is_owner)
        return _SHAREDMBOX_SHARED;
    if (sm->mboxes.count == 0)
        return _SHAREDMBOX_HIDDEN;

    /* This is a worst case O(n) search, which *could* turn out to
     * be an issue if caller iterates over all mailboxes of an
     * account with lots of mailboxes. */
    int i = 0;
    for (i = 0; i < sm->mboxes.count; i++) {
        const char *sharedname = strarray_nth(&sm->mboxes, i);
        int cmp = strcmp(sharedname, name);
        if (!cmp)
            return _SHAREDMBOX_SHARED;

        if (cmp > 0 && mboxname_is_prefix(sharedname, name)) {
            // if this isn't a user's INBOX, then it's definitely a
            // parent, so show it
            mbname_t *mbname = mbname_from_intname(name);
            if (strarray_size(mbname_boxes(mbname))) {
                mbname_free(&mbname);
                return _SHAREDMBOX_PARENT;
            }
            mbname_free(&mbname);

            // if it is the INBOX, then only show if it's a parent of
            // a mailbox which is user.foo.INBOX.etc
            mbname_t *sharedmbname = mbname_from_intname(sharedname);
            if (!strcmpsafe(strarray_nth(mbname_boxes(sharedmbname), 0), "INBOX")) {
                mbname_free(&sharedmbname);
                return _SHAREDMBOX_PARENT;
            }
            mbname_free(&sharedmbname);

            // otherwise fall through, because there might be a later member
            // of mboxes for which this name is a parent.  We could theoretically
            // avoid recalculating "mbname" here, but the complexity of cleanup
            // isn't worth the trouble.
        }
    }

    return _SHAREDMBOX_HIDDEN;
}

struct _mbox_find_specialuse_rock {
    jmap_req_t *req;
    const char *use;
    char *mboxname;
    char *uniqueid;
};

static int _mbox_find_specialuse_cb(const mbentry_t *mbentry, void *rock)
{
    struct _mbox_find_specialuse_rock *d = (struct _mbox_find_specialuse_rock *)rock;
    struct buf attrib = BUF_INITIALIZER;
    jmap_req_t *req = d->req;

    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_LOOKUP)) {
        return 0;
    }

    annotatemore_lookup_mbe(mbentry, "/specialuse", req->accountid, &attrib);

    if (attrib.len) {
        strarray_t *uses = strarray_split(buf_cstring(&attrib), " ", STRARRAY_TRIM);
        if (strarray_find_case(uses, d->use, 0) >= 0) {
            d->mboxname = xstrdup(mbentry->name);
            d->uniqueid = xstrdup(mbentry->uniqueid);
        }
        strarray_free(uses);
    }

    buf_free(&attrib);

    if (d->mboxname) return CYRUSDB_DONE;
    return 0;
}

static int _mbox_find_specialuse(jmap_req_t *req, const char *use,
                                 char **mboxnameptr,
                                 char **uniqueidptr)
{
    /* \\Inbox is magical */
    if (!strcasecmp(use, "\\Inbox")) {
        char *inboxname = mboxname_user_mbox(req->accountid, NULL);
        mbentry_t *mbentry = NULL;
        int r = mboxlist_lookup(inboxname, &mbentry, NULL);
        if (!r) {
            if (mboxnameptr) *mboxnameptr = xstrdup(inboxname);
            if (uniqueidptr) *uniqueidptr = xstrdup(mbentry->uniqueid);
        }
        free(inboxname);
        mboxlist_entry_free(&mbentry);
        return r;
    }

    struct _mbox_find_specialuse_rock rock = { req, use, NULL, NULL };
    int ret = mboxlist_usermboxtree(req->accountid, req->authstate, _mbox_find_specialuse_cb, &rock, MBOXTREE_INTERMEDIATES);

    if (mboxnameptr) {
        *mboxnameptr = rock.mboxname;
    } else free(rock.mboxname);

    if (uniqueidptr) {
        *uniqueidptr = rock.uniqueid;
    } else free(rock.uniqueid);

    return ret == CYRUSDB_DONE ? 0 : IMAP_NOTFOUND;
}

static char *_mbox_get_role(jmap_req_t *req, const mbname_t *mbname)
{
    struct buf buf = BUF_INITIALIZER;
    char *role = NULL;

    /* Inbox is special. */
    if (!strarray_size(mbname_boxes(mbname)))
        return xstrdup("inbox");

    /* XXX How to determine the templates role? */

    /* Does this mailbox have an IMAP special use role? */
    annotatemore_lookup(mbname_intname(mbname), "/specialuse",
                        req->accountid, &buf);
    if (buf.len) {
        strarray_t *uses = strarray_split(buf_cstring(&buf), " ", STRARRAY_TRIM);
        if (uses->count) {
            /* In IMAP, a mailbox may have multiple roles. But in JMAP we only
             * return the first specialuse flag. */
            const char *use = strarray_nth(uses, 0);
            if (use[0] == '\\') {
                role = xstrdup(use+1);
                lcase(role);
            }
        }
        strarray_free(uses);
    }

    buf_free(&buf);

    return role;
}

static char *_mbox_get_name(const char *account_id __attribute__((unused)),
                            const mbname_t *mbname)
{
    /* Determine name from the last segment of the mailboxname hierarchy. */
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

static int _mbox_get_roleorder(jmap_req_t *req, const mbname_t *mbname)
{
    char *role = _mbox_get_role(req, mbname);
    int role_order = 10;

    if (role) {
        int i;
        for (i = 0; ROLESORT[i].name; i++) {
            if (!strcmp(role, ROLESORT[i].name)) {
                role_order = ROLESORT[i].order;
                break;
            }
        }
    }

    free(role);
    return role_order;
}

static char *_mbox_get_color(jmap_req_t *req, const mbname_t *mbname)
{
    struct buf buf = BUF_INITIALIZER;
    const char *annot = IMAP_ANNOT_NS "color";

    /* Does this mailbox have a defined color */
    // XXX: should we align with calendars and addressbooks?
    annotatemore_lookupmask(mbname_intname(mbname), annot, req->userid, &buf);
    if (buf.len) {
        return buf_release(&buf);
    }

    buf_free(&buf);

    return NULL;
}

static int _mbox_get_showaslabel(jmap_req_t *req, const mbname_t *mbname)
{
    int show_as_label = -1;
    struct buf attrib = BUF_INITIALIZER;
    const char *annot = IMAP_ANNOT_NS "showaslabel";
    int r = annotatemore_lookupmask(mbname_intname(mbname), annot, httpd_userid, &attrib);
    if (!r && attrib.len) {
        /* We got a mailbox with an annotation. Use it. */
        show_as_label = atoi(buf_cstring(&attrib));
    }
    buf_free(&attrib);

    // fallback: mailboxes with role other than 'inbox' get false, rest get true
    if (show_as_label == -1) {
        char *role = _mbox_get_role(req, mbname);
        if (!role || !strcmp(role, "inbox"))
            show_as_label = 1;
        else
            show_as_label = 0;
        free(role);
    }

    return show_as_label;
}

static int _mbox_get_sortorder(jmap_req_t *req, const mbname_t *mbname)
{
    struct buf attrib = BUF_INITIALIZER;
    int sort_order = -1;

    /* Ignore lookup errors here. */
    const char *annot = IMAP_ANNOT_NS "sortorder";
    annotatemore_lookupmask(mbname_intname(mbname), annot, httpd_userid, &attrib);
    if (attrib.len) {
        uint64_t t = str2uint64(buf_cstring(&attrib));
        if (t < INT_MAX) {
            sort_order = (int) t;
        } else {
            syslog(LOG_ERR, "%s: bogus sortorder annotation value for %s",
                   mbname_intname(mbname), httpd_userid);
        }
    }

    buf_free(&attrib);

    if (sort_order < 0)
        sort_order = _mbox_get_roleorder(req, mbname);

    return sort_order;
}

static int _findparent(const char *mboxname, mbentry_t **mbentryp)
{
    mbentry_t *mbentry = NULL;
    int r = mboxlist_findparent_allow_all(mboxname, &mbentry);
    if (r) return r;

    /* Ignore "reserved" entries, like they aren't there */
    if (mbentry->mbtype & MBTYPE_RESERVE) {
        mboxlist_entry_free(&mbentry);
        return IMAP_MAILBOX_NONEXISTENT;
    }

    /* Ignore "deleted" entries, like they aren't there */
    if (mbentry->mbtype & MBTYPE_DELETED) {
        mboxlist_entry_free(&mbentry);
        return IMAP_MAILBOX_NONEXISTENT;
    }

    *mbentryp = mbentry;
    return 0;
}

static int _mbox_get_readcounts(jmap_req_t *req,
                                mbname_t *mbname,
                                const mbentry_t *mbentry,
                                hash_table *props,
                                json_t *obj)
{
    conv_status_t convstatus = CONV_STATUS_INIT;
    int r = conversation_getstatus(req->cstate,
                                   CONV_FOLDER_KEY_MBE(req->cstate, mbentry),
                                   &convstatus);
    if (r) {
        syslog(LOG_ERR, "conversation_getstatus(%s): %s",
                mbname_intname(mbname), error_message(r));
        return r;
    }
    if (jmap_wantprop(props, "totalEmails")) {
        json_object_set_new(obj, "totalEmails",
                json_integer(convstatus.emailexists));
    }
    if (jmap_wantprop(props, "unreadEmails")) {
        json_object_set_new(obj, "unreadEmails",
                json_integer(convstatus.emailunseen));
    }
    if (jmap_wantprop(props, "totalThreads")) {
        json_object_set_new(obj, "totalThreads",
                json_integer(convstatus.threadexists));
    }
    if (jmap_wantprop(props, "unreadThreads")) {
        json_object_set_new(obj, "unreadThreads",
                json_integer(convstatus.threadunseen));
    }
    return 0;
}

static void _mbox_is_inbox(mbname_t *mbname, int *is_inbox, int *parent_is_inbox)
{
    if (is_inbox) {
        *is_inbox = strarray_size(mbname_boxes(mbname)) == 0;
    }
    if (parent_is_inbox) {
        *parent_is_inbox = strarray_size(mbname_boxes(mbname)) == 1;
    }
}

static json_t *_mbox_get_myrights(jmap_req_t *req, const mbentry_t *mbentry)
{
    int rights = jmap_myrights_mbentry(req, mbentry);
    mbname_t *mbname = mbname_from_intname(mbentry->name);
    mbentry_t *parent = NULL;
    _findparent(mbname_intname(mbname), &parent);
    int is_inbox = 0;
    _mbox_is_inbox(mbname, &is_inbox, NULL);

    json_t *jrights = json_object();
    json_object_set_new(jrights, "mayReadItems",
            json_boolean((rights & JACL_READITEMS) == JACL_READITEMS));
    json_object_set_new(jrights, "mayAddItems",
            json_boolean((rights & JACL_ADDITEMS) == JACL_ADDITEMS));
    json_object_set_new(jrights, "mayRemoveItems",
            json_boolean((rights & JACL_REMOVEITEMS) == JACL_REMOVEITEMS));
    json_object_set_new(jrights, "mayCreateChild",
            json_boolean((rights & JACL_CREATECHILD) == JACL_CREATECHILD));
    json_object_set_new(jrights, "mayDelete",
            json_boolean(!is_inbox && ((rights & JACL_DELETE) == JACL_DELETE)));
    json_object_set_new(jrights, "maySubmit",
            json_boolean((rights & JACL_SUBMIT) == JACL_SUBMIT));
    json_object_set_new(jrights, "maySetSeen",
            json_boolean((rights & JACL_SETSEEN) == JACL_SETSEEN));
    json_object_set_new(jrights, "maySetKeywords",
            json_boolean((rights & JACL_SETKEYWORDS) == JACL_SETKEYWORDS));
    // non-standard
    json_object_set_new(jrights, "mayAdmin",
            json_boolean((rights & JACL_ADMIN_MAILBOX) == JACL_ADMIN_MAILBOX));

    int mayRename = 0;
    if (!is_inbox && ((rights & JACL_DELETE) == JACL_DELETE)) {
        mayRename = jmap_hasrights_mbentry(req, parent, JACL_CREATECHILD);
    }
    json_object_set_new(jrights, "mayRename", json_boolean(mayRename));

    mboxlist_entry_free(&parent);
    mbname_free(&mbname);
    return jrights;
}

static json_t *_json_has(int rights, int need)
{
  return (((rights & need) == need) ? json_true() : json_false());
}

static json_t *_mboxrights_tosharewith(int rights)
{
    json_t *jrights = json_object();
    json_object_set_new(jrights, "mayRead", _json_has(rights, JACL_READITEMS));
    json_object_set_new(jrights, "mayWrite", _json_has(rights, JACL_WRITE));
    json_object_set_new(jrights, "mayAdmin", _json_has(rights, JACL_ADMIN_MAILBOX));
    return jrights;
}

static json_t *_mbox_get(jmap_req_t *req,
                         const mbentry_t *mbentry,
                         hash_table *roles,
                         hash_table *props,
                         enum shared_mbox_type share_type,
                         strarray_t *sublist)
{
    mbname_t *mbname = mbname_from_intname(mbentry->name);
    mbentry_t *parent = NULL;
    json_t *obj = NULL;
    int r = 0;

    int is_inbox = 0, parent_is_inbox = 0;
    _mbox_is_inbox(mbname, &is_inbox, &parent_is_inbox);
    char *role = _mbox_get_role(req, mbname);

    if (jmap_wantprop(props, "myRights") || jmap_wantprop(props, "parentId")) {
        /* Need to lookup parent mailbox */
        _findparent(mbname_intname(mbname), &parent);
    }

    /* Build JMAP mailbox response. */
    obj = json_object();

    json_object_set_new(obj, "id", json_string(mbentry->uniqueid));
    if (jmap_wantprop(props, "name")) {
        char *name = _mbox_get_name(req->accountid, mbname);
        if (!name) goto done;
        json_object_set_new(obj, "name", json_string(name));
        free(name);
    }

    if (jmap_wantprop(props, "parentId")) {
        json_object_set_new(obj, "parentId",
                (is_inbox || parent_is_inbox || !parent) ?
                json_null() : json_string(parent->uniqueid));
    }

    if (jmap_wantprop(props, "myRights")) {
        json_object_set_new(obj, "myRights", _mbox_get_myrights(req, mbentry));
    }
    if (jmap_wantprop(props, "role")) {
        if (role && !hash_lookup(role, roles)) {
            /* In JMAP, only one mailbox have a role. First one wins. */
            json_object_set_new(obj, "role", json_string(role));
            hash_insert(role, (void*)1, roles);
        } else {
            json_object_set_new(obj, "role", json_null());
        }
    }

    if (jmap_wantprop(props, "shareWith")) {
        json_t *sharewith = jmap_get_sharewith(mbentry,
                _mboxrights_tosharewith);
        json_object_set_new(obj, "shareWith", sharewith);
    }

    if (share_type == _SHAREDMBOX_SHARED && !(mbentry->mbtype & MBTYPE_INTERMEDIATE)) {
        if (jmap_wantprop(props, "totalThreads") || jmap_wantprop(props, "unreadThreads") ||
            jmap_wantprop(props, "totalEmails") || jmap_wantprop(props, "unreadEmails")) {
            r = _mbox_get_readcounts(req, mbname, mbentry, props, obj);
            if (r) goto done;
        }
        if (jmap_wantprop(props, "sortOrder")) {
            int sortOrder = _mbox_get_sortorder(req, mbname);
            json_object_set_new(obj, "sortOrder", json_integer(sortOrder));
        }
        if (jmap_wantprop(props, "isSeenShared") || jmap_wantprop(props, "storageUsed")) {
            struct statusdata sdata = STATUSDATA_INIT;
            int r = status_lookup_mbentry(mbentry, req->userid,
                                          STATUS_MBOPTIONS, &sdata);
            if (r) {
                syslog(LOG_ERR, "getstatus(%s): %s",
                        mbname_intname(mbname), error_message(r));
                goto done;
            }
            if (jmap_wantprop(props, "isSeenShared")) {
                json_object_set_new(obj, "isSeenShared",
                                    json_boolean(sdata.mboptions & OPT_IMAP_SHAREDSEEN));
            }
            if (jmap_wantprop(props, "storageUsed")) {
                json_object_set_new(obj, "storageUsed", json_integer(sdata.size));
            }
        }
        if (jmap_wantprop(props, "color")) {
            char *color = _mbox_get_color(req, mbname);
            json_object_set_new(obj, "color", color ? json_string(color) : json_null());
            free(color);
        }
        if (jmap_wantprop(props, "showAsLabel")) {
            int showAsLabel = _mbox_get_showaslabel(req, mbname);
            json_object_set_new(obj, "showAsLabel", showAsLabel ? json_true() : json_false());
        }
    }
    else {
        if (jmap_wantprop(props, "totalEmails")) {
            json_object_set_new(obj, "totalEmails", json_integer(0));
        }
        if (jmap_wantprop(props, "unreadEmails")) {
            json_object_set_new(obj, "unreadEmails", json_integer(0));
        }
        if (jmap_wantprop(props, "totalThreads")) {
            json_object_set_new(obj, "totalThreads", json_integer(0));
        }
        if (jmap_wantprop(props, "unreadThreads")) {
            json_object_set_new(obj, "unreadThreads", json_integer(0));
        }
        if (jmap_wantprop(props, "sortOrder")) {
            json_object_set_new(obj, "sortOrder", json_integer(0));
        }
        if (jmap_wantprop(props, "isSeenShared")) {
            json_object_set_new(obj, "isSeenShared", json_false());
        }
        if (jmap_wantprop(props, "storageUsed")) {
            json_object_set_new(obj, "storageUsed", json_integer(0));
        }
        if (jmap_wantprop(props, "color")) {
            json_object_set_new(obj, "color", json_null());
        }
        if (jmap_wantprop(props, "showAsLabel")) {
            json_object_set_new(obj, "showAsLabel", json_false());
        }
    }

    if (jmap_wantprop(props, "isSubscribed")) {
        int is_subscribed =
            sublist && strarray_find(sublist, mbentry->name, 0) >= 0;
        json_object_set_new(obj, "isSubscribed", json_boolean(is_subscribed));
    }

done:
    if (r) {
        syslog(LOG_ERR, "_mbox_get: %s", error_message(r));
    }
    free(role);
    mboxlist_entry_free(&parent);
    mbname_free(&mbname);
    return obj;
}

struct jmap_mailbox_get_cb_rock {
    jmap_req_t *req;
    struct jmap_get *get;
    hash_table *roles;
    hash_table *want;
    struct shared_mboxes *shared_mboxes;
    strarray_t *sublist;
};

static int is_jmap_mailbox(const mbentry_t *mbentry, int tombstones)
{
    /* Don't list special-purpose mailboxes. */
    if (mbtypes_unavailable(mbentry->mbtype) ||
        mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL ||
        ((mbentry->mbtype & MBTYPE_DELETED) && !tombstones))
        return 0;

    // No more returns from here

    mbname_t *mbname = mbname_from_intname(mbentry->name);
    const char *topbox = strarray_nth(mbname_boxes(mbname), 0);
    int ret = 0;

    /* skip INBOX.INBOX magic intermediate */
    if (strarray_size(mbname_boxes(mbname)) == 1 && !strcmp(topbox, "INBOX"))
        goto done;

    /* skip any of our magic mailboxes */
    if (!strcmpsafe(topbox, config_getstring(IMAPOPT_CALENDARPREFIX))
     || !strcmpsafe(topbox, config_getstring(IMAPOPT_ADDRESSBOOKPREFIX))
     || !strcmpsafe(topbox, config_getstring(IMAPOPT_DAVNOTIFICATIONSPREFIX))
     || !strcmpsafe(topbox, config_getstring(IMAPOPT_JMAPUPLOADFOLDER)))
        goto done;

    // Use this mailbox
    ret = 1;

done:
    mbname_free(&mbname);
    return ret;
}

static int jmap_mailbox_get_cb(const mbentry_t *mbentry, void *_rock)
{
    struct jmap_mailbox_get_cb_rock *rock = _rock;
    jmap_req_t *req = rock->req;
    json_t *list = (json_t *) rock->get->list, *obj;

    if (!is_jmap_mailbox(mbentry, 0)) return 0;

    /* Do we need to process this mailbox? */
    if (rock->want && !hash_lookup(mbentry->uniqueid, rock->want))
        return 0;

    /* Check share_type for this mailbox */
    enum shared_mbox_type share_type =
        _shared_mbox_type(rock->shared_mboxes, mbentry->name);
    if (share_type == _SHAREDMBOX_HIDDEN)
        return 0;

    /* Convert mbox to JMAP object. */
    obj = _mbox_get(req, mbentry, rock->roles, rock->get->props, share_type, rock->sublist);
    if (!obj) {
        syslog(LOG_INFO, "could not convert mailbox %s to JMAP", mbentry->name);
        return IMAP_INTERNAL;
    }
    json_array_append_new(list, obj);

    /* Move this mailbox of the lookup list */
    if (rock->want) {
        hash_del(mbentry->uniqueid, rock->want);
        // are we done looking?
        if (!hash_numrecords(rock->want))
            return IMAP_OK_COMPLETED;
    }

    return 0;
}

static void jmap_mailbox_get_notfound(const char *id, void *data __attribute__((unused)), void *rock)
{
    json_array_append_new((json_t*) rock, json_string(id));
}

static const jmap_property_t mailbox_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "name",
        NULL,
        0
    },
    {
        "parentId",
        NULL,
        0
    },
    {
        "role",
        NULL,
        0
    },
    {
        "sortOrder",
        NULL,
        0
    },
    {
        "totalEmails",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "unreadEmails",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "totalThreads",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "unreadThreads",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "myRights",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "isSubscribed",
        NULL,
        0
    },

    /* FM extensions (do ALL of these get through to Cyrus?) */
    {
        "isCollapsed",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "hidden",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "sort",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "identityRef",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "autoLearn",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "learnAsSpam",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "autoPurge",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "purgeOlderThanDays",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "onlyPurgeDeleted",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "suppressDuplicates",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "shareWith",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "isSeenShared",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "storageUsed",
        JMAP_MAIL_EXTENSION,
        JMAP_PROP_SERVER_SET
    },
    {
        "color",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "showAsLabel",
        JMAP_MAIL_EXTENSION,
        0
    },
    { NULL, NULL, 0 }
};

static int jmap_mailbox_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;

    /* Parse request */
    jmap_get_parse(req, &parser, mailbox_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        jmap_parser_fini(&parser);
        jmap_get_fini(&get);
        return 0;
    }

    /* Build callback data */
    struct shared_mboxes *shared_mboxes = _shared_mboxes_new(req, /*flags*/0);
    strarray_t *sublist = NULL;
    if (jmap_wantprop(get.props, "isSubscribed")) {
        sublist = mboxlist_sublist(req->userid);
    }
    struct jmap_mailbox_get_cb_rock rock = { req, &get, NULL, NULL, shared_mboxes, sublist };
    rock.roles = (hash_table *) xmalloc(sizeof(hash_table));
    construct_hash_table(rock.roles, 8, 0);

    /* Does the client request specific mailboxes? */
    if (JNOTNULL(get.ids)) {
        size_t i;
        json_t *val;
        /* Make a set of request ids to know when to stop mboxlist*/
        rock.want = (hash_table *) xmalloc(sizeof(hash_table));
        construct_hash_table(rock.want, json_array_size(get.ids) + 1, 0);
        json_array_foreach(get.ids, i, val) {
            hash_insert(json_string_value(val), (void*)1, rock.want);
        }
    }

    /* Lookup and process the mailboxes. Irrespective if the client
     * defined a subset of mailbox ids to fetch, we traverse the
     * complete mailbox list, until we either reach the end of the
     * list or have found all requested ids. This is probably more
     * performant than looking up each mailbox by unique id separately
     * but will degrade if clients just fetch a small subset of
     * all mailbox ids. XXX Optimise this codepath if the ids[] array
     * length is small */
    mboxlist_usermboxtree(req->accountid, req->authstate,
                          jmap_mailbox_get_cb, &rock, MBOXTREE_INTERMEDIATES);

    /* Report if any requested mailbox has not been found */
    if (rock.want) {
        hash_enumerate(rock.want, jmap_mailbox_get_notfound, get.not_found);
    }

    /* Build response */
    json_t *jstate = jmap_getstate(req, MBTYPE_EMAIL, /*refresh*/0);
    get.state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    jmap_ok(req, jmap_get_reply(&get));

    _shared_mboxes_free(shared_mboxes);
    free_hash_table(rock.want, NULL);
    free(rock.want);
    free_hash_table(rock.roles, NULL);
    free(rock.roles);
    strarray_free(rock.sublist);
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

typedef struct {
    /* op indicates the filter type:
     * - SEOP_AND/OR/NOT/TRUE/FALSE: if the filter is a filter operator
     * - SEOP_UNKNOWN: if the filter is a filter condition
     */
    enum search_op op;
    ptrarray_t args; /* array of mboxquery_filter_t */
    /* Arguments for the filter operator or condition. */
    json_t *jparent_id;
    const char *name;
    json_t *role;
    json_t *has_any_role;
    json_t *is_subscribed;
} mboxquery_filter_t;

typedef struct {
    int sort_as_tree;
    int filter_as_tree;
} mboxquery_args_t;

typedef struct {
    jmap_req_t *req;
    mboxquery_filter_t *filter;
    ptrarray_t sort;    /* Sort criteria (mboxquery_sort_t) */
    ptrarray_t result;  /* Result records (mboxquery_record_t) */
    struct shared_mboxes *shared_mboxes;
    strarray_t *sublist;
    int include_tombstones;
    int include_hidden;

    int need_name;
    int need_sort_order;
    int need_role;
    int need_role_order;
    int need_sublist;
    const mboxquery_args_t *args;
} mboxquery_t;

typedef struct {
    char *id;
    mbname_t *mbname;
    char *mboxname;
    char *jmapname;
    char *parent_id; // NULL for top-level
    int sort_order;
    int role_order;
    modseq_t foldermodseq;
    modseq_t createdmodseq;
    int mbtype;
    enum shared_mbox_type shared_mbtype;
    int matches; // non-zero, if filter matches
} mboxquery_record_t;

typedef struct {
    char *field;
    int desc;
} mboxquery_sort_t;

static void _mboxquery_filter_free(mboxquery_filter_t *filter)
{
    if (!filter) return;

    int i;
    for (i = 0; i < filter->args.count; i++) {
        if (filter->op != SEOP_UNKNOWN) {
            _mboxquery_filter_free(ptrarray_nth(&filter->args, i));
        }
    }
    ptrarray_fini(&filter->args);
    free(filter);
}

static void _mboxquery_record_fini(mboxquery_record_t *rec)
{
    if (!rec) return;

    free(rec->id);
    mbname_free(&rec->mbname);
    free(rec->mboxname);
    free(rec->parent_id);
    free(rec->jmapname);
}

static void _mboxquery_free(mboxquery_t **qptr)
{
    int i;
    mboxquery_t *q = *qptr;

    for (i = 0; i < q->result.count; i++) {
        mboxquery_record_t *rec = ptrarray_nth(&q->result, i);
        _mboxquery_record_fini(rec);
        free(rec);
    }
    ptrarray_fini(&q->result);

    _mboxquery_filter_free(q->filter);

    for (i = 0; i < q->sort.count; i++) {
        mboxquery_sort_t *crit = ptrarray_nth(&q->sort, i);
        free(crit->field);
        free(crit);
    }
    ptrarray_fini(&q->sort);
    _shared_mboxes_free(q->shared_mboxes);
    strarray_free(q->sublist);

    free(q);
    *qptr = NULL;
}

static int _mboxquery_eval_filter(mboxquery_t *query,
                                  mboxquery_filter_t *filter,
                                  mboxquery_record_t *rec)
{
    if (filter->op == SEOP_TRUE)
        return 1;
    if (filter->op == SEOP_FALSE)
        return 0;

    int i;
    if (filter->op != SEOP_UNKNOWN) {
        for (i = 0; i < filter->args.count; i++) {
            mboxquery_filter_t *arg = ptrarray_nth(&filter->args, i);
            int m = _mboxquery_eval_filter(query, arg, rec);
            if (m && filter->op == SEOP_OR)
                return 1;
            else if (m && filter->op == SEOP_NOT)
                return 0;
            else if (!m && filter->op == SEOP_AND)
                return 0;
        }
        return filter->op == SEOP_AND || filter->op == SEOP_NOT;
    }
    else {
        if (JNOTNULL(filter->has_any_role) || filter->role) {
            mbname_t *mbname = mbname_from_intname(rec->mboxname);
            char *role = _mbox_get_role(query->req, mbname);
            int has_role = role != NULL;
            int is_match = 1;
            if (has_role) {
                if (filter->has_any_role == json_false()) is_match = 0;
                else if (filter->role == json_null()) is_match = 0;
                else if (filter->role) {
                    is_match = !strcmp(json_string_value(filter->role), role);
                }
            }
            else {
                if (filter->has_any_role == json_true()) is_match = 0;
                else if (JNOTNULL(filter->role)) is_match = 0;
            }
            free(role);
            mbname_free(&mbname);
            if (!is_match) return 0;
        }
        if (filter->jparent_id) {
            if (rec->parent_id) {
                const char *want_parent = json_string_value(filter->jparent_id);
                if (strcmpsafe(rec->parent_id, want_parent)) return 0;
            }
            else if (!json_is_null(filter->jparent_id)) return 0;
        }
        if (filter->name && !stristr(rec->jmapname, filter->name)) {
            return 0;
        }
        if (JNOTNULL(filter->is_subscribed)) {
            int want_subscribed = json_boolean_value(filter->is_subscribed);
            int is_subscribed = strarray_find(query->sublist, rec->mboxname, 0);
            if (want_subscribed && is_subscribed < 0) return 0;
        }
        return 1;
    }
}

static mboxquery_filter_t *_mboxquery_build_filter(mboxquery_t *query, json_t *jfilter)
{
    mboxquery_filter_t *filter = xzmalloc(sizeof(mboxquery_filter_t));
    filter->op = SEOP_TRUE;

    const char *s = json_string_value(json_object_get(jfilter, "operator"));
    if (s) {
        if (!strcmp(s, "AND"))
            filter->op = SEOP_AND;
        else if (!strcmp(s, "OR"))
            filter->op = SEOP_OR;
        else if (!strcmp(s, "NOT"))
            filter->op = SEOP_NOT;
        size_t i;
        json_t *val;
        json_array_foreach(json_object_get(jfilter, "conditions"), i, val) {
            ptrarray_append(&filter->args, _mboxquery_build_filter(query, val));
        }
    }
    else {
        filter->op = SEOP_UNKNOWN;
        filter->jparent_id = json_object_get(jfilter, "parentId");
        filter->name = json_string_value(json_object_get(jfilter, "name"));
        filter->role = json_object_get(jfilter, "role");
        filter->has_any_role = json_object_get(jfilter, "hasAnyRole");
        filter->is_subscribed = json_object_get(jfilter, "isSubscribed");
        if (filter->role || filter->has_any_role) {
            query->need_role = 1;
        }
        if (filter->is_subscribed) {
            query->need_sublist = 1;
        }
        if (filter->name) {
            query->need_name = 1;
        }
    }
    return filter;
}

static mboxquery_t *_mboxquery_new(jmap_req_t *req, json_t *filter, json_t *sort)
{
    mboxquery_t *q = xzmalloc(sizeof(mboxquery_t));
    q->req = req;
    q->shared_mboxes = _shared_mboxes_new(req, /*flags*/0);

    /* Prepare filter */
    q->filter = _mboxquery_build_filter(q, filter);

    /* Prepare sort */
    size_t i;
    json_t *jval;
    json_array_foreach(sort, i, jval) {
        mboxquery_sort_t *crit = xzmalloc(sizeof(mboxquery_sort_t));
        const char *prop = json_string_value(json_object_get(jval, "property"));
        crit->field = xstrdup(prop);
        crit->desc = json_object_get(jval, "isAscending") == json_false();
        ptrarray_append(&q->sort, crit);
    }
    ptrarray_init(&q->result);

    return q;
}

static int _mboxquery_compar QSORT_R_COMPAR_ARGS(const void **a,
                                                 const void **b,
                                                 void *rock)
{
    const mboxquery_record_t *pa = *a;
    const mboxquery_record_t *pb = *b;
    const mboxquery_t *query = rock;
    int i;

    for (i = 0; i < query->sort.count; i++) {
        mboxquery_sort_t *crit = ptrarray_nth(&query->sort, i);
        int cmp = 0;
        int sign = crit->desc ? -1 : 1;

        if (!strcmp(crit->field, "name"))
            cmp = strcmp(pa->jmapname, pb->jmapname) * sign;
        else if (!strcmp(crit->field, "role"))
            cmp = (pa->role_order - pb->role_order) * sign;
        else if (!strcmp(crit->field, "sortOrder"))
            cmp = (pa->sort_order - pb->sort_order) * sign;

        if (cmp) return cmp;
    }

    return strcmp(pa->id, pb->id);
}

static int _mboxquery_cb(const mbentry_t *mbentry, void *rock)
{
    mboxquery_t *q = rock;

    if (!is_jmap_mailbox(mbentry, q->include_tombstones))
        return 0;

    enum shared_mbox_type shared_mbtype = _shared_mbox_type(q->shared_mboxes, mbentry->name);
    if (shared_mbtype == _SHAREDMBOX_HIDDEN && !q->include_hidden)
        return 0;

    mbname_t *mbname = mbname_from_intname(mbentry->name);
    int r = 0;

    /* Create record */
    mboxquery_record_t *rec = xzmalloc(sizeof(mboxquery_record_t));

    if (strarray_size(mbname_boxes(mbname)) > 1) {
        mbentry_t *mbparent = NULL;
        r = _findparent(mbentry->name, &mbparent);
        if (r && r != IMAP_MAILBOX_NONEXISTENT) {
            goto done;
        }
        else if (!r) {
            rec->parent_id = xstrdup(mbparent->uniqueid);
        }
        mboxlist_entry_free(&mbparent);
        r = 0;
    }

    rec->id = xstrdup(mbentry->uniqueid);
    rec->mbname = mbname;
    mbname = NULL; // takes ownership
    rec->foldermodseq = mbentry->foldermodseq;
    rec->createdmodseq = mbentry->createdmodseq;
    rec->mbtype = mbentry->mbtype;
    rec->shared_mbtype = shared_mbtype;
    rec->mboxname = xstrdup(mbentry->name);

    if (q->need_name) {
        rec->jmapname = _mbox_get_name(q->req->accountid, rec->mbname);
    }
    if (q->need_sort_order) {
        rec->sort_order = _mbox_get_sortorder(q->req, rec->mbname);
    }
    if (q->need_role_order) {
        rec->role_order = _mbox_get_roleorder(q->req, rec->mbname);
    }
    ptrarray_append(&q->result, rec);

done:
    if (mbname) mbname_free(&mbname);
    return r;
}

static int _mboxquery_run(mboxquery_t *query, const mboxquery_args_t *args)
{
    /* Prepare internal query context. */
    int i;
    for (i = 0; i < ptrarray_size(&query->sort); i++) {
        mboxquery_sort_t *crit = ptrarray_nth(&query->sort, i);
        if (!strcmp(crit->field, "name")) {
            query->need_name = 1;
        }
        else if (!strcmp(crit->field, "role")) {
            query->need_role_order = 1;
        }
        else if (!strcmp(crit->field, "sortOrder")) {
            query->need_sort_order = 1;
        }
    }
    query->args = args;
    if (query->need_sublist) {
        query->sublist = mboxlist_sublist(query->req->userid);
        if (!query->sublist) {
            syslog(LOG_ERR, "jmap: mboxquery_run: could not load sublist");
            return IMAP_INTERNAL;
        }
    }

    /* Lookup mailboxes */
    int flags = MBOXTREE_INTERMEDIATES;
    if (query->include_tombstones) flags |= MBOXTREE_TOMBSTONES|MBOXTREE_DELETED;
    int r = mboxlist_usermboxtree(query->req->accountid, query->req->authstate,
                                  _mboxquery_cb, query, flags);
    if (r) goto done;

    /* Apply comparators */
    cyr_qsort_r(query->result.data, query->result.count, sizeof(void*),
                (int(*)(const void*, const void*, void*)) _mboxquery_compar, query);

    /* Build in-memory tree */
    hash_table recs_by_parentid = HASH_TABLE_INITIALIZER;
    construct_hash_table(&recs_by_parentid, ptrarray_size(&query->result) + 1, 0);
    for (i = 0; i < ptrarray_size(&query->result); i++) {
        mboxquery_record_t *rec = ptrarray_nth(&query->result, i);
        const char *parent_id = rec->parent_id ? rec->parent_id : "";
        ptrarray_t *recs = hash_lookup(parent_id, &recs_by_parentid);
        if (!recs) {
            recs = ptrarray_new();
            hash_insert(parent_id, recs, &recs_by_parentid);
        }
        ptrarray_append(recs, rec);
    }

    /* Sort as tree */
    if (query->args->sort_as_tree) {
        /* Reset result list */
        ptrarray_truncate(&query->result, 0);
        /* Add top-level nodes */
        ptrarray_t work = PTRARRAY_INITIALIZER;
        ptrarray_t *root = hash_lookup("", &recs_by_parentid);
        if (root) {
            for (i = ptrarray_size(root) - 1; i >= 0; i--) {
                ptrarray_push(&work, ptrarray_nth(root, i));
            }
        }
        /* Descend tree */
        mboxquery_record_t *rec;
        while ((rec = ptrarray_pop(&work))) {
            ptrarray_push(&query->result, rec);
            ptrarray_t *children = hash_lookup(rec->id, &recs_by_parentid);
            if (!children) continue;
            for (i = ptrarray_size(children) - 1; i >= 0; i--) {
                ptrarray_push(&work, ptrarray_nth(children, i));
            }
        }
        ptrarray_fini(&work);
    }

    /* Apply filter */
    for (i = 0; i < ptrarray_size(&query->result); i++) {
        mboxquery_record_t *rec = ptrarray_nth(&query->result, i);
        rec->matches = _mboxquery_eval_filter(query, query->filter, rec);
    }

    /* Filter as tree */
    if (query->args->filter_as_tree) {
        /* Add top-level nodes */
        ptrarray_t work = PTRARRAY_INITIALIZER;
        ptrarray_t *root = hash_lookup("", &recs_by_parentid);
        if (root) {
            for (i = 0; i < ptrarray_size(root); i++) {
                ptrarray_push(&work, ptrarray_nth(root, i));
            }
        }
        /* Descend tree */
        mboxquery_record_t *rec;
        while ((rec = ptrarray_pop(&work))) {
            ptrarray_t *children = hash_lookup(rec->id, &recs_by_parentid);
            if (!children) continue;
            for (i = 0; i < ptrarray_size(children); i++) {
                mboxquery_record_t *child = ptrarray_nth(children, i);
                if (!rec->matches) child->matches = 0;
                ptrarray_push(&work, child);
            }
        }
        ptrarray_fini(&work);
    }

    /* Prune result */
    int newlen = 0;
    for (i = 0; i < ptrarray_size(&query->result); i++) {
        mboxquery_record_t *rec = ptrarray_nth(&query->result, i);
        if (!rec->matches) {
            _mboxquery_record_fini(rec);
            free(rec);
        }
        else ptrarray_set(&query->result, newlen++, rec);
    }
    ptrarray_truncate(&query->result, newlen);

    /* Free tree model */
    hash_iter *it = hash_table_iter(&recs_by_parentid);
    while (hash_iter_next(it)) {
        ptrarray_t *recs = hash_iter_val(it);
        ptrarray_free(recs);
    }
    hash_iter_free(&it);
    free_hash_table(&recs_by_parentid, NULL);

done:
    return r;
}


static int _mboxquery_can_calculate_changes(mboxquery_t *mbquery)
{
    /* XXX Mailbox/queryChanges currently has to overreport mailboxes
     * in removed if the filter criteria includes annotations. This
     * workaround is OK for a user's owned mailbox, but we don't want
     * to leak mailboxes for shared accounts */
    return !strcmp(mbquery->req->userid, mbquery->req->accountid);
}

static int _mbox_query(jmap_req_t *req, struct jmap_query *query,
                       const mboxquery_args_t *args)
{
    int r = 0;

    /* Prepare query */
    mboxquery_t *mbquery = _mboxquery_new(req, query->filter, query->sort);

    /* Run the query */
    r = _mboxquery_run(mbquery, args);
    if (r) goto done;

    query->total = mbquery->result.count;

    /* Apply query */
    ssize_t i, frompos = 0;
    int seen_anchor = 0;
    ssize_t skip_anchor = 0;
    ssize_t result_pos = -1;
    modseq_t highest_modseq = 0;

    /* Set position of first result */
    if (!query->anchor) {
        if (query->position > 0) {
            frompos = query->position;
        }
        else if (query->position < 0) {
            frompos = mbquery->result.count + query->position ;
            if (frompos < 0) frompos = 0;
        }
    }

    for (i = frompos; i < mbquery->result.count; i++) {
        mboxquery_record_t *rec = ptrarray_nth(&mbquery->result, i);

        /* Check anchor */
        if (query->anchor) {
            if (!seen_anchor) {
                seen_anchor = !strcmp(rec->id, query->anchor);
                if (!seen_anchor) {
                    continue;
                }
                /* Found the anchor! Now apply anchor offsets */
                if (query->anchor_offset > 0) {
                    skip_anchor = query->anchor_offset;
                    continue;
                }
                else if (query->anchor_offset < 0) {
                    /* Prefill result list with all, but the current record */
                    size_t lo = -query->anchor_offset < i ? i + query->anchor_offset : 0;
                    size_t hi = query->limit ? lo + query->limit : (size_t) i;
                    result_pos = lo;
                    while (lo < hi && lo < (size_t) i) {
                        mboxquery_record_t *p = ptrarray_nth(&mbquery->result, lo);
                        json_array_append_new(query->ids, json_string(p->id));
                        lo++;
                    }
                }
            }
            if (skip_anchor && --skip_anchor) continue;
        }

        /* Check limit. */
        if (query->limit && query->limit <= json_array_size(query->ids)) {
            break;
        }

        /* Add to result list. */
        if (result_pos == -1) {
            result_pos = i;
        }
        if (highest_modseq < rec->foldermodseq) {
            highest_modseq = rec->foldermodseq;
        }
        json_array_append_new(query->ids, json_string(rec->id));
    }
    if (query->anchor && !seen_anchor) {
        json_decref(query->ids);
        query->ids = json_array();
    }
    if (result_pos >= 0) {
        query->result_position = result_pos;
    }

    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, highest_modseq);
    query->query_state = buf_release(&buf);
    query->can_calculate_changes = _mboxquery_can_calculate_changes(mbquery);

done:
    _mboxquery_free(&mbquery);
    return r;
}

static int _mboxquery_parse_comparator(jmap_req_t *req __attribute__((unused)),
                                       struct jmap_comparator *comp,
                                       void *rock __attribute__((unused)),
                                       json_t **err __attribute__((unused)))
{
    /* Reject unsupported properties */
    if (strcmp(comp->property, "sortOrder") &&
        strcmp(comp->property, "role") &&
        strcmp(comp->property, "name")) {
        return 0;
    }
    /* Reject any collation */
    if (comp->collation) {
        return 0;
    }
    return 1;
}

static void _mboxquery_parse_filter(jmap_req_t *req __attribute__((unused)),
                                    struct jmap_parser *parser,
                                    json_t *filter,
                                    json_t *unsupported __attribute__((unused)),
                                    void *rock __attribute__((unused)),
                                    json_t **err __attribute__((unused)))
{
    json_t *val;
    const char *field;

    json_object_foreach(filter, field, val) {
        if (!strcmp(field, "parentId") ||
            !strcmp(field, "role")) {
            if (!(json_is_string(val) || json_is_null(val))) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "name")) {
            if (!json_is_string(val)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "isSubscribed") ||
                 !strcmp(field, "hasAnyRole")) {
            if (!json_is_boolean(val)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else {
            jmap_parser_invalid(parser, field);
        }
    }
}

static int _mboxquery_parse_args(jmap_req_t *req __attribute__((unused)),
                                 struct jmap_parser *parser __attribute__((unused)),
                                 const char *key,
                                 json_t *arg,
                                 void *rock)
{
    mboxquery_args_t *args = (mboxquery_args_t*) rock;

    if (!strcmp(key, "sortAsTree") && json_is_boolean(arg)) {
        args->sort_as_tree = json_boolean_value(arg);
        return 1;
    }
    else if (!strcmp(key, "filterAsTree") && json_is_boolean(arg)) {
        args->filter_as_tree = json_boolean_value(arg);
        return 1;
    }
    else return 0;
}

static int jmap_mailbox_query(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;
    mboxquery_args_t args = { 0, 0 };

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req, &parser,
                     _mboxquery_parse_args, &args,
                     _mboxquery_parse_filter, NULL,
                     _mboxquery_parse_comparator, NULL,
                     &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Search for the mailboxes */
    int r = _mbox_query(req, &query, &args);
    if (r) {
        jmap_error(req, jmap_server_error(r));
        goto done;
    }

    /* Build response */
    jmap_ok(req, jmap_query_reply(&query));

done:
    jmap_parser_fini(&parser);
    jmap_query_fini(&query);
    return 0;
}

struct mboxquerychanges_rock {
    hash_table *removed;
    modseq_t sincemodseq;
};

static int _mboxquerychanges_cb(const mbentry_t *mbentry, void *vrock)
{
    struct mboxquerychanges_rock *rock = vrock;
    if (mbentry->foldermodseq > rock->sincemodseq) {
        hash_insert(mbentry->uniqueid, (void*)1, rock->removed);
    }
    return 0;
}

static int jmap_mailbox_querychanges(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_querychanges query;
    mboxquery_args_t args = { 0, 0 };
    int r = 0;

    /* Parse arguments */
    json_t *err = NULL;
    jmap_querychanges_parse(req, &parser,
                            _mboxquery_parse_args, &args,
                            _mboxquery_parse_filter, NULL,
                            _mboxquery_parse_comparator, NULL,
                            &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    modseq_t sincemodseq = atomodseq_t(query.since_querystate);
    if (!sincemodseq) {
        jmap_error(req, json_pack("{s:s}", "type", "cannotCalculateChanges"));
        goto done;
    }

    /* Prepare query */
    mboxquery_t *mbquery = _mboxquery_new(req, query.filter, query.sort);
    if (!_mboxquery_can_calculate_changes(mbquery)) {
        jmap_error(req, json_pack("{s:s}", "type", "cannotCalculateChanges"));
        goto done;
    }

    /* Run the query */
    mbquery->include_tombstones = 1;
    mbquery->include_hidden = 1;
    mbquery->need_name = 1;
    r = _mboxquery_run(mbquery, &args);
    if (r) goto done;

    hash_table removed = HASH_TABLE_INITIALIZER;
    construct_hash_table(&removed, mbquery->result.count + 1, 0);
    if (mbquery->need_role) {
        /* The filter includes a condition on role (or hasAnyRole).
         * We don't keep a history of annotations, so we can't tell
         * if the mailbox was a match previously and now isn't.
         * XXX the workaround is to report all mailboxes in removed,
         * until we have a sane way of tracking annotation changes */

        struct mboxquerychanges_rock rock = { &removed, sincemodseq };
        int r = mboxlist_usermboxtree(req->accountid, req->authstate,
                                      _mboxquerychanges_cb, &rock,
                                      MBOXTREE_TOMBSTONES|
                                      MBOXTREE_DELETED|
                                      MBOXTREE_INTERMEDIATES);
        if (r) goto done;
    }

    modseq_t highestmodseq = sincemodseq;
    ssize_t i;
    for (i = 0; i < mbquery->result.count; i++) {
        mboxquery_record_t *mbrec = ptrarray_nth(&mbquery->result, i);
        if (mbrec->mbtype & MBTYPE_DELETED) {
            if (mbrec->foldermodseq > sincemodseq) {
                hash_insert(mbrec->id, (void*)1, &removed);
            }
        }
        else if (!jmap_hasrights(req, mbrec->mboxname, JACL_LOOKUP)) {
            if (mbrec->createdmodseq <= sincemodseq) {
                hash_insert(mbrec->id, (void*)1, &removed);
            }
        }
        else if (mbrec->foldermodseq > sincemodseq && mbrec->shared_mbtype != _SHAREDMBOX_HIDDEN) {
            json_array_append_new(query.added, json_pack("{s:s s:i}", "id", mbrec->id, "index", i));
            hash_insert(mbrec->id, (void*)1, &removed);
            if (highestmodseq < mbrec->foldermodseq) {
                highestmodseq = mbrec->foldermodseq;
            }
        }
    }
    hash_iter *iter = hash_table_iter(&removed);
    while (hash_iter_next(iter)) {
        json_array_append_new(query.removed, json_string(hash_iter_key(iter)));
    }
    hash_iter_free(&iter);
    free_hash_table(&removed, NULL);
    _mboxquery_free(&mbquery);

    /* Build response */
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, highestmodseq);
    query.new_querystate = buf_release(&buf);
    jmap_ok(req, jmap_querychanges_reply(&query));

done:
    if (r) {
        jmap_error(req, jmap_server_error(r));
    }
    jmap_querychanges_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

/* Combine the UTF-8 encoded JMAP mailbox name and its parent IMAP mailbox
 * name to a IMAP mailbox name. Does not check for uniqueness.
 *
 * Return the malloced, combined name, or NULL on error. */
static char *_mbox_newname(const char *name, const char *parentname, int is_toplevel)
{
    charset_t cs = CHARSET_UNKNOWN_CHARSET;
    char *mboxname = NULL;

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
    if (!is_toplevel && !strarray_size(mbname_boxes(mbname)))
        mbname_push_boxes(mbname, "INBOX");
    mbname_push_boxes(mbname, s);
    free(s);
    mboxname = xstrdup(mbname_intname(mbname));
    mbname_free(&mbname);

done:
    charset_free(&cs);
    return mboxname;
}

static char *_mbox_tmpname(const char *name, const char *parentname, int is_toplevel)
{
    int retries = 0;
    do {
        /* Make temporary name */
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "tmp_%s_%s", name, makeuuid());
        char *mboxname = _mbox_newname(buf_cstring(&buf), parentname, is_toplevel);
        buf_free(&buf);
        /* Make sure no such mailbox exists */
        int r = jmap_mboxlist_lookup(mboxname, NULL, NULL);
        if (r == IMAP_MAILBOX_NONEXISTENT) {
            return mboxname;
        }
        /* Log any error and retry. */
        if (r) {
            syslog(LOG_ERR, "jmap: _mbox_tmpname(%s): %s",
                    buf_cstring(&buf), error_message(r));
        }
    } while (retries < 3);
    return NULL;
}

static int _mbox_has_children_cb(const mbentry_t *mbentry __attribute__ ((unused)), void *rock) {
    int *has_child = (int *) rock;
    *has_child = 1;
    return IMAP_OK_COMPLETED;
}

static int _mbox_has_children(const char *mboxname)
{
    int has_child = 0;
    mboxlist_mboxtree(mboxname, _mbox_has_children_cb, &has_child, MBOXTREE_SKIP_ROOT);
    return has_child;
}

static void _mbox_setargs_fini(struct mboxset_args *args)
{
    free(args->creation_id);
    free(args->id);
    free(args->parent_id);
    free(args->name);

    switch (args->type) {
    case _MBOXSET_EMAIL:
        free(args->u.email.specialuse);
        free(args->u.email.color);
        break;

    case _MBOXSET_NODE:
        free(args->u.node.blobid);
        free(args->u.node.type);
        free(args->u.node.title);
        free(args->u.node.comment);
        break;
    }

    json_decref(args->jargs);
}

static char *_mbox_role_to_specialuse(const char *role)
{
    if (!role) return NULL;
    if (!role[0]) return NULL;
    char *specialuse = strconcat("\\", role, (char *)NULL);
    specialuse[1] = toupper(specialuse[1]);
    return specialuse;
}

EXPORTED int jmap_mailbox_find_role(jmap_req_t *req, const char *role,
                                    char **mboxnameptr,
                                    char **uniqueidptr)
{
    char *specialuse = _mbox_role_to_specialuse(role);
    int r = 0;

    if (specialuse) {
        r = _mbox_find_specialuse(req, specialuse, mboxnameptr, uniqueidptr);
    }

    free(specialuse);

    return r;
}

static void _mboxset_args_parse(json_t *jargs,
                                struct jmap_parser *parser,
                                struct mboxset_args *args,
                                jmap_req_t *req,
                                int is_create)
{
    /* Initialize arguments */
    memset(args, 0, sizeof(struct mboxset_args));
    args->type = _MBOXSET_EMAIL;
    args->u.email.sortorder = -1;
    args->u.email.overwrite_acl = 1;
    args->jargs = json_incref(jargs);

    /* id */
    json_t *jid = json_object_get(jargs, "id");
    if (json_is_string(jid) && !is_create) {
        args->id = xstrdup(json_string_value(jid));
    }
    else if (JNOTNULL(jid) && is_create) {
        jmap_parser_invalid(parser, "id");
    }

    /* name */
    json_t *jname = json_object_get(jargs, "name");
    if (json_is_string(jname)) {
        char *name = charset_utf8_normalize(json_string_value(jname));
        size_t len = strlen(name);
        int is_valid = 0;
        size_t i;
        for (i = 0; i < len; i++) {
            if (iscntrl(name[i])) {
                is_valid = 0;
                break;
            }
            else if (!isspace(name[i])) {
                is_valid = 1;
            }
        }
        if (is_valid) {
            args->name = name;
        }
        else {
            /* Empty string, bogus characters or just whitespace */
            jmap_parser_invalid(parser, "name");
            free(name);
        }
    }
    else if (is_create) {
        jmap_parser_invalid(parser, "name");
    }

    /* parentId */
    json_t *jparentId = json_object_get(jargs, "parentId");
    if (json_is_string(jparentId)) {
        const char *parent_id = json_string_value(jparentId);
        if (parent_id && (*parent_id != '#' || *(parent_id + 1))) {
            args->parent_id = xstrdup(parent_id);
        }
        if (!args->parent_id) {
            jmap_parser_invalid(parser, "parentId");
        }
    } else if (jparentId == json_null() || (is_create && !jparentId)) {
        args->is_toplevel = 1;
    }

    /* role */
    json_t *jrole = json_object_get(jargs, "role");
    if (json_is_string(jrole)) {
        const char *role = json_string_value(jrole);
        int is_valid = 1;
        if (!strcmp(role, "inbox")) {
            /* inbox role is server-set */
            is_valid = 0;
        } else {
            char *specialuse = _mbox_role_to_specialuse(role);
            struct buf buf = BUF_INITIALIZER;
            int r = specialuse_validate(NULL, req->userid, specialuse, &buf, 1);
            if (r) is_valid = 0;
            else args->u.email.specialuse = buf_release(&buf);
            free(specialuse);
            buf_free(&buf);
        }
        if (!is_valid) {
            jmap_parser_invalid(parser, "role");
        }
    }
    else if (jrole == json_null()) {
        args->u.email.specialuse = xstrdup("");
    }
    else if (JNOTNULL(jrole)) {
        jmap_parser_invalid(parser, "role");
    }

    /* sortOrder */
    json_t *jsortOrder = json_object_get(jargs, "sortOrder");
    if (json_is_integer(jsortOrder)) {
        args->u.email.sortorder = json_integer_value(jsortOrder);
        if (args->u.email.sortorder < 0 || args->u.email.sortorder >= INT_MAX) {
            jmap_parser_invalid(parser, "sortOrder");
        }
    }
    else if (JNOTNULL(jsortOrder)) {
        jmap_parser_invalid(parser, "sortOrder");
    }

    /* isSubscribed */
    json_t *jisSubscribed = json_object_get(jargs, "isSubscribed");
    if (json_is_boolean(jisSubscribed)) {
        args->u.email.is_subscribed = json_boolean_value(jisSubscribed);
    }
    else if (jisSubscribed) {
        jmap_parser_invalid(parser, "isSubscribed");
    }
    else {
        args->u.email.is_subscribed = -1;
    }

    /* isSeenShared */
    json_t *jisSeenShared = json_object_get(jargs, "isSeenShared");
    if (json_is_boolean(jisSeenShared)) {
        args->u.email.is_seenshared = json_boolean_value(jisSeenShared);
    }
    else if (jisSeenShared) {
        jmap_parser_invalid(parser, "isSeenShared");
    }
    else {
        args->u.email.is_seenshared = -1;
    }

    if (!is_create) {
        /* Is shareWith overwritten or patched? */
        json_t *shareWith = NULL;
        jmap_parse_sharewith_patch(jargs, &shareWith);
        if (shareWith) {
            args->u.email.overwrite_acl = 0;
            json_object_set_new(jargs, "shareWith", shareWith);
        }
    }

    /* shareWith */
    args->shareWith = json_object_get(jargs, "shareWith");
    if (args->shareWith && JNOTNULL(args->shareWith) &&
        !json_is_object(args->shareWith)) {
        jmap_parser_invalid(parser, "shareWith");
    }
    if (json_is_object(args->shareWith)) {
        // Validate rights
        const char *sharee;
        json_t *jrights;
        json_object_foreach(args->shareWith, sharee, jrights) {
            if (json_object_size(jrights)) {
                const char *right;
                json_t *jval;
                json_object_foreach(jrights, right, jval) {
                    if (!json_is_boolean(jval) ||
                        (strcmp(right, "mayRead") &&
                         strcmp(right, "mayWrite") &&
                         strcmp(right, "mayAdmin"))) {

                        jmap_parser_push(parser, "shareWith");
                        jmap_parser_push(parser, sharee);
                        jmap_parser_invalid(parser, right);
                        jmap_parser_pop(parser);
                        jmap_parser_pop(parser);
                    }
                }
            }
            else if (!json_is_null(jrights)) {
                jmap_parser_push(parser, "shareWith");
                jmap_parser_invalid(parser, sharee);
                jmap_parser_pop(parser);
            }
        }
    }

    /* All of these are server-set. */
    json_t *jrights = json_object_get(jargs, "myRights");
    if (json_is_object(jrights) && !is_create) {
        /* Update allows clients to set myRights, as long as
         * it doesn't change their values. Don't bother with
         * that during parsing, just make sure that it is
         * syntactically valid. */
        const char *right;
        json_t *jval;
        jmap_parser_push(parser, "myRights");
        json_object_foreach(jrights, right, jval) {
            if (!json_is_boolean(jval))
                jmap_parser_invalid(parser, right);
        }
        jmap_parser_pop(parser);
    }
    else if (JNOTNULL(jrights)) {
        jmap_parser_invalid(parser, "myRights");
    }

    if (json_object_get(jargs, "totalEmails") && is_create)
        jmap_parser_invalid(parser, "totalEmails");
    if (json_object_get(jargs, "unreadEmails") && is_create)
        jmap_parser_invalid(parser, "unreadEmails");
    if (json_object_get(jargs, "totalThreads") && is_create)
        jmap_parser_invalid(parser, "totalThreads");
    if (json_object_get(jargs, "unreadThreads") && is_create)
        jmap_parser_invalid(parser, "unreadThreads");

    /* color */
    json_t *jcolor = json_object_get(jargs, "color");
    if (json_is_string(jcolor) || jcolor == json_null()) {
        args->u.email.color =
            (jcolor == json_null()) ? xstrdup("") : xstrdup(json_string_value(jcolor));
    }
    else if (JNOTNULL(jcolor)) {
        jmap_parser_invalid(parser, "color");
    }

    /* showAsLabel */
    json_t *jshowAsLabel = json_object_get(jargs, "showAsLabel");
    if (json_is_boolean(jshowAsLabel)) {
        args->u.email.show_as_label = json_boolean_value(jshowAsLabel);
    }
    else if (jshowAsLabel) {
        jmap_parser_invalid(parser, "showAsLabel");
    }
    else {
        args->u.email.show_as_label = -1;
    }
}

static int _mbox_set_annots(jmap_req_t *req,
                            struct mboxset_args *args,
                            const char *mboxname)
{
    int r = 0;
    struct buf buf = BUF_INITIALIZER;

    /* Set specialuse.  This is a PRIVATE annotation on the account owner */
    if (args->u.email.specialuse) {
        buf_setcstr(&buf, args->u.email.specialuse);
        static const char *annot = "/specialuse";
        r = annotatemore_write(mboxname, annot, req->accountid, &buf);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    annot, error_message(r));
            goto done;
        }
        buf_reset(&buf);
    }

    if (args->u.email.sortorder >= 0) {
        /* Set sortOrder annotation on mailbox.  This is a masked private annotation
         * for the authenticated user */
        buf_printf(&buf, "%d", args->u.email.sortorder);
        static const char *sortorder_annot = IMAP_ANNOT_NS "sortorder";
        r = annotatemore_writemask(mboxname, sortorder_annot, httpd_userid, &buf);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    sortorder_annot, error_message(r));
            goto done;
        }
    }

    if (args->u.email.color) {
        /* Set color annotation on mailbox.  This is a masked private annotation
         * for the authenticated user */
        buf_setcstr(&buf, args->u.email.color);
        static const char *annot = IMAP_ANNOT_NS "color";
        r = annotatemore_writemask(mboxname, annot, httpd_userid, &buf);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    annot, error_message(r));
            goto done;
        }
        buf_reset(&buf);
    }

    if (args->u.email.show_as_label >= 0) {
        /* Set showAsLabel annotation on mailbox.  This is a masked private annotation
         * for the authenticated user */
        buf_printf(&buf, "%d", args->u.email.show_as_label);
        static const char *annot = IMAP_ANNOT_NS "showaslabel";
        r = annotatemore_writemask(mboxname, annot, httpd_userid, &buf);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    annot, error_message(r));
            goto done;
        }
    }

done:
    buf_free(&buf);
    return r;
}

static void _mboxset_result_fini(struct mboxset_result *result)
{
    json_decref(result->err);
    free(result->old_imapname);
    free(result->new_imapname);
    free(result->tmp_imapname);
}

static int _mbox_sharewith_to_rights(int rights, json_t *jsharewith)
{
    int newrights = rights;
    const char *name;
    json_t *jval;

    json_object_foreach(jsharewith, name, jval) {
        int mask;
        if (!strcmp(name, "mayAdmin"))
            mask = JACL_ADMIN_MAILBOX;
        else if (!strcmp(name, "mayWrite"))
            mask = JACL_WRITE;
        else if (!strcmp(name, "mayRead"))
            mask = JACL_READITEMS;
        else
            continue;

        if (json_boolean_value(jval))
            newrights |= mask;
        else
            newrights &= ~mask;
    }

    return newrights;
}

static void _mbox_create(jmap_req_t *req, struct mboxset_args *args,
                         enum mboxset_runmode mode,
                         json_t **mbox, struct mboxset_result *result,
                         strarray_t *update_intermediaries)
{
    char *mboxname = NULL;
    int r = 0;
    mbentry_t *mbinbox = NULL, *mbentry = NULL;
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct mailbox *mailbox = NULL;

    char *inboxname = mboxname_user_mbox(req->accountid, NULL);
    jmap_mboxlist_lookup(inboxname, &mbinbox, NULL);
    free(inboxname);

    /* Lookup parent creation id, if any. This also deals with
     * bogus Mailbox/set operations that attempt to create
     * cycles in the mailbox tree: they'll all fail due to
     * unresolvable parentIds. */
    const char *parent_id = args->parent_id;
    if (parent_id && *parent_id == '#') {
        parent_id = jmap_lookup_id(req, parent_id + 1);
        if (!parent_id) {
            if (mode == _MBOXSET_SKIP) {
                result->skipped = 1;
            }
            else {
                jmap_parser_invalid(&parser, "parentId");
            }
            goto done;
        }
    }
    parent_id = args->is_toplevel ? mbinbox->uniqueid : parent_id;

    /* Check parent exists and has the proper ACL. */
    const mbentry_t *mbparent = jmap_mbentry_by_uniqueid(req, parent_id);
    if (!mbparent || !jmap_hasrights_mbentry(req, mbparent, JACL_CREATECHILD)) {
        jmap_parser_invalid(&parser, "parentId");
        goto done;
    }

    if (args->is_toplevel && !strcasecmp(args->name, "inbox")) {
        // you can't write a top-level mailbox called "INBOX" in any case
        jmap_parser_invalid(&parser, "name");
        goto done;
    }

    /* Encode the mailbox name for IMAP. */
    mboxname = _mbox_newname(args->name, mbparent->name,
                             args->is_toplevel);
    if (!mboxname) {
        syslog(LOG_ERR, "could not encode mailbox name");
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Skip role updates in first iteration */
    if (args->u.email.specialuse && *args->u.email.specialuse) {
        if (mode == _MBOXSET_SKIP) {
            result->skipped = 1;
            goto done;
        }
    }

    /* Check if a mailbox with this name exists */
    r = jmap_mboxlist_lookup(mboxname, NULL, NULL);
    if (r == 0) {
        if (mode == _MBOXSET_SKIP) {
            result->skipped = 1;
            goto done;
        }
        else if (mode == _MBOXSET_INTERIM) {
            result->new_imapname = xstrdup(mboxname);
            result->old_imapname = NULL;
            result->tmp_imapname = _mbox_tmpname(args->name, mbparent->name,
                                                 args->is_toplevel);
            if (!result->tmp_imapname) {
                syslog(LOG_ERR, "jmap: no mailbox tmpname for %s", mboxname);
                r = IMAP_INTERNAL;
                goto done;
            }
            free(mboxname);
            mboxname = xstrdup(result->tmp_imapname);
            /* Keep on processing with tmpname */
        }
        else {
            syslog(LOG_ERR, "jmap: mailbox already exists: %s", mboxname);
            jmap_parser_invalid(&parser, "name");
            goto done;
        }
    }
    else if (r != IMAP_MAILBOX_NONEXISTENT) {
        goto done;
    }
    r = 0;

    /* Create mailbox */
    mbentry_t newmbentry = MBENTRY_INITIALIZER;
    newmbentry.name = mboxname;
    newmbentry.mbtype = MBTYPE_EMAIL;

    uint32_t options = 0;
    if (args->u.email.is_seenshared > 0) options |= OPT_IMAP_SHAREDSEEN;
    if (args->u.email.specialuse && !strcmp("\\Snoozed", args->u.email.specialuse))
        options |= OPT_IMAP_HAS_ALARMS;

    r = mboxlist_createmailbox(&newmbentry, options, 0/*highestmodseq*/,
                               0/*isadmin*/, req->userid, req->authstate,
                               MBOXLIST_CREATE_KEEP_INTERMEDIARIES,
                               args->shareWith ? &mailbox : NULL);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                mboxname, error_message(r));
        goto done;
    }
    strarray_add(update_intermediaries, mboxname);

     /* invalidate ACL cache */
    jmap_myrights_delete(req, mboxname);
    jmap_mbentry_cache_free(req);

    /* shareWith */
    if (args->shareWith) {
        r = jmap_set_sharewith(mailbox, args->shareWith, args->u.email.overwrite_acl,
                _mbox_sharewith_to_rights);
        mailbox_close(&mailbox);
    }
    if (r) goto done;

    /* Write annotations and isSubscribed */
    r = _mbox_set_annots(req, args, mboxname);
    if (!r && args->u.email.is_subscribed > 0) {
        r = mboxlist_changesub(mboxname, req->userid, httpd_authstate, 1, 0, 0);
    }
    if (r) goto done;

    /* Lookup and return the new mailbox id */
    r = jmap_mboxlist_lookup(mboxname, &mbentry, NULL);
    if (r) goto done;
    *mbox = json_pack("{s:s}", "id", mbentry->uniqueid);
    /* Set server defaults */
    if (args->u.email.is_subscribed < 0) {
        json_object_set_new(*mbox, "isSubscribed", json_false());
    }
    if (args->u.email.is_seenshared < 0) {
        json_object_set_new(*mbox, "isSeenShared", json_false());
    }
    if (args->u.email.sortorder < 0) {
        mbname_t *mbname = mbname_from_intname(mboxname);
        json_object_set_new(*mbox, "sortOrder", json_integer(_mbox_get_sortorder(req, mbname)));
        mbname_free(&mbname);
    }
    if (args->u.email.show_as_label < 0) {
        json_object_set_new(*mbox, "showAsLabel",
                            args->u.email.specialuse ? json_false() : json_true());
    }

done:
    if (json_array_size(parser.invalid)) {
        result->err = json_pack("{s:s}", "type", "invalidProperties");
        json_object_set(result->err, "properties", parser.invalid);
    }
    else if (r) {
        result->err = jmap_server_error(r);
    }
    free(mboxname);
    mboxlist_entry_free(&mbinbox);
    mboxlist_entry_free(&mbentry);
    jmap_parser_fini(&parser);
}

static int _mbox_update_validate_serverset(jmap_req_t *req,
                                           struct mboxset_args *args,
                                           struct jmap_parser *parser,
                                           mbentry_t *mbentry)
{
    /* Validate read counts */
    if (json_object_get(args->jargs, "totalEmails") ||
        json_object_get(args->jargs, "unreadEmails") ||
        json_object_get(args->jargs, "totalThreads") ||
        json_object_get(args->jargs, "unreadThreads")) {

        mbname_t *mbname = mbname_from_intname(mbentry->name);
        json_t *tmp = json_object();
        int r = _mbox_get_readcounts(req, mbname, mbentry, NULL, tmp);
        if (!r) {
            json_t *jval = json_object_get(args->jargs, "totalEmails");
            if (jval && !json_equal(jval, json_object_get(tmp, "totalEmails"))) {
                jmap_parser_invalid(parser, "totalEmails");
            }
            jval = json_object_get(args->jargs, "unreadEmails");
            if (jval && !json_equal(jval, json_object_get(tmp, "unreadEmails"))) {
                jmap_parser_invalid(parser, "unreadEmails");
            }
            jval = json_object_get(args->jargs, "totalThreads");
            if (jval && !json_equal(jval, json_object_get(tmp, "totalThreads"))) {
                jmap_parser_invalid(parser, "totalThreads");
            }
            jval = json_object_get(args->jargs, "unreadThreads");
            if (jval && !json_equal(jval, json_object_get(tmp, "unreadThreads"))) {
                jmap_parser_invalid(parser, "unreadThreads");
            }
        }
        json_decref(tmp);
        mbname_free(&mbname);
        if (r) return r;
    }

    /* Validate myRights */
    json_t *jpatch = json_copy(args->jargs);
    const char *propname;
    json_t *jval;
    void *vtmp;
    json_object_foreach_safe(jpatch, vtmp, propname, jval) {
        if (strcmp(propname, "myRights") && strncmp(propname, "myRights/", 9)) {
            json_object_del(jpatch, propname);
        }
    }
    json_t *jcurRights = _mbox_get_myrights(req, mbentry);
    json_t *jold = json_pack("{s:o}", "myRights", json_copy(jcurRights));
    json_t *invalid = json_array();
    json_t *jnew = jmap_patchobject_apply(jold, jpatch, invalid);
    if (json_array_size(invalid) == 0) {
        json_t *jnewRights = json_object_get(jnew, "myRights");
        if (!json_equal(jcurRights, jnewRights)) {
            jmap_parser_invalid(parser, "myRights");
        }
    }
    else json_array_extend(parser->invalid, invalid);
    json_decref(jnew);
    json_decref(jold);
    json_decref(invalid);
    json_decref(jpatch);
    json_decref(jcurRights);

    return 0;
}

static void _mbox_update(jmap_req_t *req, struct mboxset_args *args,
                         enum mboxset_runmode mode,
                         struct mboxset_result *result,
                         strarray_t *update_intermediaries)
{
    /* So many names... manage them in our own string pool */
    ptrarray_t strpool = PTRARRAY_INITIALIZER;
    int r = 0;
    mbentry_t *mbinbox = NULL, *mbparent = NULL, *mbentry = NULL;
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;

    char *inboxname = mboxname_user_mbox(req->accountid, NULL);
    jmap_mboxlist_lookup(inboxname, &mbinbox, NULL);
    free(inboxname);

    const char *parent_id = args->parent_id;
    if (parent_id && *parent_id == '#') {
        parent_id = jmap_lookup_id(req, parent_id + 1);
        if (!parent_id) {
            if (mode == _MBOXSET_SKIP) {
                result->skipped = 1;
            }
            else {
                jmap_parser_invalid(&parser, "parentId");
            }
            goto done;
        }
    }

    /* Lookup current mailbox entry */
    mbentry = jmap_mbentry_by_uniqueid_copy(req, args->id);
    if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_LOOKUP)) {
        mboxlist_entry_free(&mbentry);
        result->err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    /* Validate server-set properties */
    _mbox_update_validate_serverset(req, args, &parser, mbentry);

    /* Determine current mailbox and parent names */
    char *oldmboxname = NULL;
    char *oldparentname = NULL;
    int was_toplevel = 0;
    int is_inbox = 0;
    if (strcmp(args->id, mbinbox->uniqueid)) {
        oldmboxname = xstrdup(mbentry->name);
        r = _findparent(oldmboxname, &mbparent);
        if (r) {
            syslog(LOG_INFO, "_findparent(%s) failed: %s",
                            oldmboxname, error_message(r));
            goto done;
        }
        oldparentname = xstrdup(mbparent->name);
        ptrarray_append(&strpool, oldparentname);

        // calculate whether mailbox is toplevel
        mbname_t *mbname = mbname_from_intname(oldmboxname);
        was_toplevel = strarray_size(mbname_boxes(mbname)) == 1;
        mbname_free(&mbname);
    }
    else {
        if (parent_id || args->is_toplevel) {
            // thou shalt not move INBOX
           jmap_parser_invalid(&parser, "parentId");
           goto done;
        }
        is_inbox = 1;

        oldmboxname = xstrdup(mbinbox->name);
    }
    ptrarray_append(&strpool, oldmboxname);

    /* Must not set role on inbox */
    if (args->u.email.specialuse && is_inbox) {
        jmap_parser_invalid(&parser, "role");
        goto done;
    }

    /* Skip role updates in first iteration */
    if (mode == _MBOXSET_SKIP) {
        if (args->u.email.specialuse && *args->u.email.specialuse) {
            result->skipped = 1;
        }
        if (!result->skipped) {
            struct buf val = BUF_INITIALIZER;
            annotatemore_lookup_mbe(mbentry, "/specialuse", req->accountid, &val);
            if (buf_len(&val)) {
                result->skipped = 1;
            }
            buf_free(&val);
        }
        if (result->skipped) goto done;
    }

    /* Now parent_id always has a proper mailbox id */
    parent_id = args->is_toplevel ? mbinbox->uniqueid : parent_id;

    /* Do we need to move this mailbox to a new parent? */
    const char *parentname = oldparentname;
    int is_toplevel = was_toplevel;
    int force_rename = 0;

    if (!is_inbox && (parent_id || args->is_toplevel)) {
        /* Compare old parent with new parent. */
        char *newparentname = NULL;

        mbentry_t *pmbentry = jmap_mbentry_by_uniqueid_copy(req, parent_id);
        if (pmbentry && jmap_hasrights_mbentry(req, pmbentry, JACL_LOOKUP)) {
            newparentname = xstrdup(pmbentry->name);
        }
        mboxlist_entry_free(&pmbentry);

        int new_toplevel = args->is_toplevel;
        if (!newparentname) {
            jmap_parser_invalid(&parser, "parentId");
            goto done;
        }
        ptrarray_append(&strpool, newparentname);

        /* Reject cycles in mailbox tree. */
        char *pname = xstrdup(newparentname);
        while (_findparent(pname, &pmbentry) == 0) {
            if (!strcmp(args->id, pmbentry->uniqueid)) {
                jmap_parser_invalid(&parser, "parentId");
                free(pname);
                mboxlist_entry_free(&pmbentry);
                goto done;
            }
            free(pname);
            pname = xstrdup(pmbentry->name);
            mboxlist_entry_free(&pmbentry);
        }
        mboxlist_entry_free(&pmbentry);
        free(pname);

        /* Is this a move to a new parent? */
        if (strcmpsafe(oldparentname, newparentname) || was_toplevel != new_toplevel) {
            /* Check ACL of mailbox */
            if (!jmap_hasrights(req, oldparentname, JACL_DELETE)) {
                result->err = json_pack("{s:s}", "type", "forbidden");
                goto done;
            }

            /* Reset pointers to parent */
            mboxlist_entry_free(&mbparent);
            jmap_mboxlist_lookup(newparentname, &mbparent, NULL);

            /* Check ACL of new parent */
            if (!jmap_hasrights_mbentry(req, mbparent, JACL_CREATECHILD)) {
                jmap_parser_invalid(&parser, "parentId");
                goto done;
            }

            force_rename = 1;
            parentname = newparentname;
            is_toplevel = new_toplevel;
        }
    }

    const char *mboxname = oldmboxname;

    /* Do we need to rename the mailbox? But only if it isn't the INBOX! */
    if (!is_inbox && (args->name || force_rename)) {
        mbname_t *mbname = mbname_from_intname(oldmboxname);
        char *oldname = _mbox_get_name(req->accountid, mbname);
        mbname_free(&mbname);
        ptrarray_append(&strpool, oldname);
        char *name = oldname;
        if (args->name && strcmp(name, args->name)) {
            name = args->name;
            force_rename = 1;
        }

        if (is_toplevel && !strcasecmp(name, "inbox")) {
            /* you can't write a top-level mailbox called "INBOX" in any case.  If the old
             * name wasn't "inbox" then the name is bad, otherwise it's the NULL parentId
             * that is the problem */
            jmap_parser_invalid(&parser, strcasecmp(oldname, "inbox") ? "name" : "parentId");
            goto done;
        }

        /* Do old and new mailbox names differ? */
        if (force_rename) {

            /* Determine the unique IMAP mailbox name. */
            char *newmboxname = _mbox_newname(name, parentname, is_toplevel);
            if (!newmboxname) {
                syslog(LOG_ERR, "_mbox_newname returns NULL: can't rename %s", mboxname);
                r = IMAP_INTERNAL;
                goto done;
            }
            ptrarray_append(&strpool, newmboxname);

            r = jmap_mboxlist_lookup(newmboxname, NULL, NULL);
            if (r == 0) {
                if (mode == _MBOXSET_SKIP) {
                    result->skipped = 1;
                    goto done;
                }
                else if (mode == _MBOXSET_INTERIM) {
                    result->new_imapname = xstrdup(newmboxname);
                    result->old_imapname = xstrdup(oldmboxname);
                    result->tmp_imapname = _mbox_tmpname(name, parentname, is_toplevel);
                    if (!result->tmp_imapname) {
                        syslog(LOG_ERR, "jmap: no mailbox tmpname for %s", newmboxname);
                        r = IMAP_INTERNAL;
                        goto done;
                    }
                    newmboxname = xstrdup(result->tmp_imapname);
                    ptrarray_append(&strpool, newmboxname);
                    /* Keep on processing with tmpname */
                }
                else {
                    syslog(LOG_ERR, "jmap: mailbox already exists: %s", newmboxname);
                    jmap_parser_invalid(&parser, "name");
                    goto done;
                }
            }
            else if (r != IMAP_MAILBOX_NONEXISTENT) {
                goto done;
            }
            r = 0;

            /* Rename the mailbox. */
            if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
                r = mboxlist_promote_intermediary(oldmboxname);
                if (r) goto done;
            }
            struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_RENAME);
            r = mboxlist_renametree(oldmboxname, newmboxname,
                    NULL /* partition */, 0 /* uidvalidity */,
                    httpd_userisadmin, req->userid, httpd_authstate,
                    mboxevent,
                    0 /* local_only */, 0 /* forceuser */, 0 /* ignorequota */,
                    1 /* keep_intermediaries */, 1 /* move_subscription */);
            mboxevent_free(&mboxevent);
            mboxlist_entry_free(&mbentry);
            jmap_mboxlist_lookup(newmboxname, &mbentry, NULL);
            strarray_add(update_intermediaries, oldmboxname);
            strarray_add(update_intermediaries, newmboxname);

            /* Keep track of old IMAP name */
            if (!result->old_imapname)
                result->old_imapname = xstrdup(oldmboxname);

            /* invalidate ACL cache */
            jmap_myrights_delete(req, oldmboxname);
            jmap_myrights_delete(req, newmboxname);
            jmap_mbentry_cache_free(req);

            if (r) {
                syslog(LOG_ERR, "mboxlist_renametree(old=%s new=%s): %s",
                        oldmboxname, newmboxname, error_message(r));
                goto done;
            }
            mboxname = newmboxname;  // cheap and nasty change!
        }
    }

    /* Write annotations and isSubscribed */

    int set_annots = 0;
    if (args->name || args->u.email.specialuse) {
        // these set for everyone
        if (!jmap_hasrights_mbentry(req, mbentry, JACL_SETKEYWORDS)) {
            mboxlist_entry_free(&mbentry);
            result->err = json_pack("{s:s}", "type", "forbidden");
            goto done;
        }
        set_annots = 1;
    }
    if (args->u.email.sortorder >= 0 ||
        args->u.email.color || args->u.email.show_as_label >= 0) {
        // these are per-user, so you just need READ access
        if (!jmap_hasrights_mbentry(req, mbentry, ACL_READ)) {
            mboxlist_entry_free(&mbentry);
            result->err = json_pack("{s:s}", "type", "forbidden");
            goto done;
        }
        set_annots = 1;
    }
    if (set_annots) {
        if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
            r = mboxlist_promote_intermediary(mbentry->name);
            if (r) goto done;
            mboxlist_entry_free(&mbentry);
            jmap_mboxlist_lookup(mboxname, &mbentry, NULL);
        }
        if (!r) r = _mbox_set_annots(req, args, mboxname);
    }

    if (!r && args->u.email.is_subscribed >= 0) {
        r = mboxlist_changesub(mboxname, req->userid, httpd_authstate,
                               args->u.email.is_subscribed, 0, 0);
    }
    if (!r && (args->shareWith || args->u.email.is_seenshared >= 0)) {
        struct mailbox *mbox = NULL;
        uint32_t newopts;

        r = jmap_openmbox(req, mboxname, &mbox, 1);
        if (r) goto done;

        if (args->shareWith) {
            r = jmap_set_sharewith(mbox, args->shareWith, args->u.email.overwrite_acl,
                    _mbox_sharewith_to_rights);
        }

        if (!r && args->u.email.is_seenshared >= 0) {
            newopts = mbox->i.options;
            if (args->u.email.is_seenshared) newopts |= OPT_IMAP_SHAREDSEEN;
            else newopts &= ~OPT_IMAP_SHAREDSEEN;

            /* only mark dirty if there's been a change */
            if (mbox->i.options != newopts) {
                mailbox_index_dirty(mbox);
                mailbox_modseq_dirty(mbox);
                mbox->i.options = newopts;
                mboxlist_update_foldermodseq(mailbox_name(mbox), mbox->i.highestmodseq);
            }
        }
        jmap_closembox(req, &mbox);
    }
    if (r) goto done;

done:
    if (json_array_size(parser.invalid)) {
        result->err = json_pack("{s:s}", "type", "invalidProperties");
        json_object_set(result->err, "properties", parser.invalid);
    }
    else if (r && result->err == NULL) {
        result->err = jmap_server_error(r);
    }
    jmap_parser_fini(&parser);
    while (strpool.count) free(ptrarray_pop(&strpool));
    ptrarray_fini(&strpool);
    mboxlist_entry_free(&mbinbox);
    mboxlist_entry_free(&mbparent);
    mboxlist_entry_free(&mbentry);
}

static int in_otherfolder_cb(const conv_guidrec_t *rec, void *rock)
{
    intptr_t src_foldernum = (intptr_t)rock;

    if (rec->version < 1) {
        syslog(LOG_ERR, "%s:%s: outdated guid record in mailbox %s",
                __FILE__, __func__, conv_guidrec_mboxname(rec));
        return IMAP_INTERNAL;
    }

    if (rec->foldernum != src_foldernum &&
        (rec->system_flags & FLAG_DELETED) == 0 &&
        (rec->internal_flags & FLAG_INTERNAL_EXPUNGED) == 0) {
        return IMAP_MAILBOX_EXISTS;
    }

    return 0;
}

static int _mbox_on_destroy_move(jmap_req_t *req,
                                 struct mboxset *set,
                                 const mbentry_t *src_mbentry,
                                 struct mboxset_result *result)
{
    struct mailbox *src_mbox = NULL;
    struct mailbox *dst_mbox = NULL;
    ptrarray_t move_msgrecs = PTRARRAY_INITIALIZER;
    int r = 0;

    /* Open mailboxes */
    const mbentry_t *dst_mbentry =
        jmap_mbentry_by_uniqueid(req, set->on_destroy_move_to_mailboxid);
    if (!dst_mbentry) {
        syslog(LOG_ERR, "%s: can't find mailbox id %s", __func__,
                        set->on_destroy_move_to_mailboxid);
        r = IMAP_NOTFOUND;
        goto done;
    }
    r = jmap_openmbox(req, src_mbentry->name, &src_mbox, 0);
    if (r) {
        syslog(LOG_ERR, "%s: can't open %s", __func__, src_mbentry->name);
        goto done;
    }
    r = jmap_openmbox(req, dst_mbentry->name, &dst_mbox, 1);
    if (r) {
        syslog(LOG_ERR, "%s: can't open %s", __func__, dst_mbentry->name);
        goto done;
    }

    /* Find all messages that only exist in source mailbox */
    int src_foldernum =
        conversation_folder_number(req->cstate,
                                   CONV_FOLDER_KEY_MBE(req->cstate, src_mbentry),
                                   0);
    if (src_foldernum < 0) {
        // if the folder doesn't exist yet, it means there have never been any emails created in it!
        goto done;
    }
    struct mailbox_iter *iter = mailbox_iter_init(src_mbox, 0, ITER_SKIP_EXPUNGED);
    const message_t *msg;
    struct buf guid = BUF_INITIALIZER;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        buf_setcstr(&guid, message_guid_encode(&record->guid));
        r = conversations_guid_foreach(req->cstate, buf_cstring(&guid),
                                       in_otherfolder_cb,
                                       (void*)((intptr_t) src_foldernum));
        if (r) {
            if (r == IMAP_MAILBOX_EXISTS) {
                r = 0;
                continue;
            }
            else break;
        }
        msgrecord_t *mr = msgrecord_from_index_record(src_mbox, record);
        if (mr) ptrarray_append(&move_msgrecs, mr);
    }
    buf_free(&guid);
    mailbox_iter_done(&iter);
    if (r) goto done;

    /* Move messages */
    if (ptrarray_size(&move_msgrecs)) {
        struct appendstate as;
        int r;
        int nolink = !config_getswitch(IMAPOPT_SINGLEINSTANCESTORE);

        r = append_setup_mbox(&as, dst_mbox, req->userid, req->authstate,
                              JACL_ADDITEMS, NULL, &jmap_namespace, 0,
                              EVENT_MESSAGE_COPY);
        if (!r) {
            r = append_copy(src_mbox, &as, &move_msgrecs, nolink,
                    mboxname_same_userid(mailbox_name(src_mbox), mailbox_name(dst_mbox)));
            if (!r) {
                r = append_commit(&as);
                if (!r) sync_log_append(mailbox_name(dst_mbox));
            }
            else append_abort(&as);
        }
        msgrecord_t *mr;
        while ((mr = ptrarray_pop(&move_msgrecs))) {
            msgrecord_unref(&mr);
        }
        if (r) goto done;
    }

done:
    if (r && !result->err) {
        result->err = jmap_server_error(r);
    }
    jmap_closembox(req, &dst_mbox);
    jmap_closembox(req, &src_mbox);
    ptrarray_fini(&move_msgrecs);
    return r;
}

static void _mbox_destroy(jmap_req_t *req, const char *mboxid,
                          struct mboxset *set,
                          enum mboxset_runmode mode,
                          struct mboxset_result *result,
                          strarray_t *update_intermediaries)
{
    int r = 0;
    mbentry_t *mbinbox = NULL, *mbentry = NULL;
    int is_intermediate = 0;

    char *inboxname = mboxname_user_mbox(req->accountid, NULL);
    jmap_mboxlist_lookup(inboxname, &mbinbox, NULL);
    free(inboxname);

    /* Do not allow to remove INBOX. */
    if (!strcmpsafe(mboxid, mbinbox->uniqueid)) {
        result->err = json_pack("{s:s}", "type", "forbidden");
        goto done;
    }

    /* Lookup mailbox by id. */
    mbentry = jmap_mbentry_by_uniqueid_copy(req, mboxid);
    if (!mbentry) {
        result->err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }


    /* Check ACL */
    if (!jmap_hasrights_mbentry(req, mbentry, JACL_DELETE)) {
        result->err = json_pack("{s:s}", "type", "forbidden");
        goto done;
    }
    is_intermediate = mbentry->mbtype & MBTYPE_INTERMEDIATE;

    /* Check if the mailbox has any children. */
    if (_mbox_has_children(mbentry->name)) {
        if (mode == _MBOXSET_SKIP) {
            result->skipped = 1;
        }
        else {
            result->err = json_pack("{s:s}", "type", "mailboxHasChild");
        }
        goto done;
    }

    /* Skip role updates in first iteration */
    if (mode == _MBOXSET_SKIP) {
        struct buf val = BUF_INITIALIZER;
        annotatemore_lookup_mbe(mbentry, "/specialuse", req->accountid, &val);
        if (buf_len(&val)) {
            result->skipped = 1;
        }
        buf_free(&val);
        if (result->skipped) goto done;
    }

    if (!is_intermediate) {
        if (set->on_destroy_move_to_mailboxid) {
            /* Move messages if not in any other mailbox */
            _mbox_on_destroy_move(req, set, mbentry, result);
            if (result->err) goto done;
        }
        else if (!set->on_destroy_remove_msgs) {
            /* Check if the mailbox has any messages */
            struct mailbox *mbox = NULL;
            struct mailbox_iter *iter = NULL;

            r = jmap_openmbox(req, mbentry->name, &mbox, 0);
            if (r) goto done;
            iter = mailbox_iter_init(mbox, 0, ITER_SKIP_EXPUNGED);
            if (mailbox_iter_step(iter) != NULL) {
                result->err = json_pack("{s:s}", "type", "mailboxHasEmail");
            }
            mailbox_iter_done(&iter);
            jmap_closembox(req, &mbox);
            if (result->err) goto done;
        }
    }

    /* Read message count for logging */
    size_t msgcount = 0;
    conv_status_t convstatus = CONV_STATUS_INIT;
    r = conversation_getstatus(req->cstate,
            CONV_FOLDER_KEY_MBE(req->cstate, mbentry), &convstatus);
    if (r) {
        xsyslog(LOG_WARNING, "could not read msgcount, will default to 0",
                "mboxid=<%s> err=<%s>", mbentry->uniqueid, error_message(r));
        r = 0;
    }
    else msgcount = convstatus.emailexists;

    /* Destroy mailbox. */
    int delflags = MBOXLIST_DELETE_CHECKACL | MBOXLIST_DELETE_KEEP_INTERMEDIARIES;
    if (mode == _MBOXSET_INTERIM) {
        delflags |= MBOXLIST_DELETE_UNPROTECT_SPECIALUSE;
    }
    struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_DELETE);
    if (mboxlist_delayed_delete_isenabled()) {
        r = mboxlist_delayed_deletemailbox(mbentry->name,
                httpd_userisadmin || httpd_userisproxyadmin,
                req->userid, req->authstate, mboxevent, delflags);
    }
    else {
        r = mboxlist_deletemailbox(mbentry->name,
                httpd_userisadmin || httpd_userisproxyadmin,
                req->userid, req->authstate, mboxevent, delflags);
    }
    mboxevent_free(&mboxevent);

    if (r == IMAP_PERMISSION_DENIED) {
        result->err = json_pack("{s:s}", "type", "forbidden");
        r = 0;
        goto done;
    }
    else if (r == IMAP_MAILBOX_NONEXISTENT) {
        if (!is_intermediate) {
            result->err = json_pack("{s:s}", "type", "notFound");
        }
        r = 0;
        goto done;
    }
    else if (r) {
        goto done;
    }

    xsyslog(LOG_INFO, "Destroyed mailbox", "mboxid=<%s> msgcount=<%zu>",
            mbentry->uniqueid, msgcount);

    /* Remove subscription */
    int r2 = mboxlist_changesub(mbentry->name, req->userid, httpd_authstate, 0, 0, 0);
    if (r2) {
        syslog(LOG_ERR, "jmap: mbox_destroy: can't unsubscribe %s:%s",
                mbentry->name, error_message(r2));
    }

    strarray_add(update_intermediaries, mbentry->name);

    /* invalidate ACL cache */
    jmap_myrights_delete(req, mbentry->name);
    jmap_mbentry_cache_free(req);

    /* Keep track of the deleted mailbox name */
    result->old_imapname = xstrdup(mbentry->name);

done:
    if (r) {
        if (result->err == NULL)
            result->err = jmap_server_error(r);
        syslog(LOG_ERR, "failed to delete mailbox(%s): %s",
               mboxid, error_message(r));
    }
    mboxlist_entry_free(&mbinbox);
    mboxlist_entry_free(&mbentry);
}

struct toposort {
    hash_table *parent_id_by_id;
    strarray_t *dst;
    hash_table visited;
    int is_cyclic;
};

static void _toposort_cb(const char *id, void *data, void *rock)
{
    struct toposort *topo = rock;
    const char *parent_id = data;

    /* Return cyclic graphs in any order */
    if (topo->is_cyclic) {
        if (hash_lookup(id, &topo->visited) == NULL &&
            hash_lookup(id, topo->parent_id_by_id)) {
            strarray_append(topo->dst, id);
        }
        return;
    }
    /* Check if node is already visited */
    void *v = hash_lookup(id, &topo->visited);
    if (v) {
        if (v == (void*)1) {
            /* Temporary mark indiciates a cycle */
            topo->is_cyclic = 1;
        }
        return;
    }
    /* Mark this node temporarily */
    hash_insert(id, (void*)1, &topo->visited);
    /* Visit parent */
    char *grandparent_id = hash_lookup(parent_id, topo->parent_id_by_id);
    if (grandparent_id)
        _toposort_cb(parent_id, grandparent_id, rock);
    /* Mark this node permanently */
    hash_insert(id, (void*)2, &topo->visited);
    /* Append key node to list */
    if (hash_lookup(id, topo->parent_id_by_id)) {
        strarray_append(topo->dst, id);
    }
}

static int _toposort(hash_table *parent_id_by_id, strarray_t *dst)
{
    struct toposort topo = { parent_id_by_id, dst, HASH_TABLE_INITIALIZER, 0 };
    construct_hash_table(&topo.visited, hash_numrecords(parent_id_by_id) + 1, 0);
    hash_enumerate(topo.parent_id_by_id, _toposort_cb, &topo);
    free_hash_table(&topo.visited, NULL);
    free_hash_table(&topo.visited, NULL);
    return topo.is_cyclic ? -1 : 0;
}

struct mboxset_ops {
    ptrarray_t *put;
    strarray_t *del;
    int is_cyclic;
};

static void _mboxset_ops_free(struct mboxset_ops *ops)
{
    ptrarray_free(ops->put);
    strarray_free(ops->del);
    free(ops);
}

static struct mboxset_ops *_mboxset_newops(jmap_req_t *req, struct mboxset *set)
{
    int i;

    struct mboxset_ops *ops = xzmalloc(sizeof(struct mboxset_ops));
    ops->put = ptrarray_new();
    ops->del = strarray_new();

    /* Sort create and update operations, parent before child */
    if (ptrarray_size(&set->create) || ptrarray_size(&set->update)) {
        hash_table args_by_id = HASH_TABLE_INITIALIZER;
        hash_table parent_id_by_id = HASH_TABLE_INITIALIZER;
        construct_hash_table(&parent_id_by_id,
                ptrarray_size(&set->create) + ptrarray_size(&set->update), 0);
        construct_hash_table(&args_by_id,
                ptrarray_size(&set->create) + ptrarray_size(&set->update), 0);

        struct buf buf = BUF_INITIALIZER;
        for (i = 0; i < ptrarray_size(&set->create); i++) {
            struct mboxset_args *args = ptrarray_nth(&set->create, i);
            if (!args->parent_id) {
                ptrarray_append(ops->put, args);
                continue;
            }
            buf_putc(&buf, '#');
            buf_appendcstr(&buf, args->creation_id);
            hash_insert(buf_cstring(&buf), args->parent_id, &parent_id_by_id);
            hash_insert(buf_cstring(&buf), args, &args_by_id);
            buf_reset(&buf);
        }
        buf_free(&buf);
        for (i = 0; i < ptrarray_size(&set->update); i++) {
            struct mboxset_args *args = ptrarray_nth(&set->update, i);
            if (!args->parent_id) {
                ptrarray_append(ops->put, args);
                continue;
            }
            hash_insert(args->id, args->parent_id, &parent_id_by_id);
            hash_insert(args->id, args, &args_by_id);
        }
        strarray_t tmp = STRARRAY_INITIALIZER;
        if (_toposort(&parent_id_by_id, &tmp) < 0) {
            ops->is_cyclic = 1;
        }
        for (i = 0; i < strarray_size(&tmp); i++) {
            const char *id = strarray_nth(&tmp, i);
            ptrarray_append(ops->put, hash_lookup(id, &args_by_id));
        }
        strarray_fini(&tmp);
        free_hash_table(&parent_id_by_id, NULL);
        free_hash_table(&args_by_id, NULL);
    }

    /* Sort delete operations, children before parent */
    if (strarray_size(set->destroy)) {
        hash_table parent_id_by_id = HASH_TABLE_INITIALIZER;
        construct_hash_table(&parent_id_by_id, strarray_size(set->destroy) + 1, 0);
        for (i = 0; i < strarray_size(set->destroy); i++) {
            const char *mbox_id = strarray_nth(set->destroy, i);
            const mbentry_t *mbentry = jmap_mbentry_by_uniqueid(req, mbox_id);
            if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_LOOKUP)) {
                json_object_set_new(set->super.not_destroyed, mbox_id,
                        json_pack("{s:s}", "type", "notFound"));
                continue;
            }
            mbentry_t *parent = NULL;
            if (_findparent(mbentry->name, &parent) == 0) {
                hash_insert(mbox_id, xstrdup(parent->uniqueid), &parent_id_by_id);
            }
            else {
                strarray_append(ops->del, mbox_id);
            }
            mboxlist_entry_free(&parent);
        }
        strarray_t tmp = STRARRAY_INITIALIZER;
        _toposort(&parent_id_by_id, &tmp); /* destroy can't be cyclic */
        while (strarray_size(&tmp))
            strarray_appendm(ops->del, strarray_pop(&tmp));
        strarray_fini(&tmp);
        free_hash_table(&parent_id_by_id, free);
    }

    return ops;
}

static void _mboxset_run(jmap_req_t *req, struct mboxset *set,
                         struct mboxset_ops *ops,
                         enum mboxset_runmode mode,
                         strarray_t *update_intermediaries)
{
    int i;
    strarray_t skipped_del = STRARRAY_INITIALIZER;
    ptrarray_t skipped_put = PTRARRAY_INITIALIZER;
    ptrarray_t tmp_renames = PTRARRAY_INITIALIZER;
    struct tmp_rename {
        char *old_imapname;
        char *new_imapname;
        char *tmp_imapname;
    };

    /* Run create and update operations */
    for (i = 0; i < ptrarray_size(ops->put); i++) {
        struct mboxset_args *args = ptrarray_nth(ops->put, i);
        /* Create */
        if (args->creation_id) {
            json_t *mbox = NULL;
            struct mboxset_result result = MBOXSET_RESULT_INITIALIZER;
            set->create_cb(req, args, mode, &mbox, &result, update_intermediaries);
            if (result.err) {
                json_object_set(set->super.not_created,
                        args->creation_id, result.err);
            }
            else if (result.skipped) {
                ptrarray_append(&skipped_put, args);
            }
            else {
                json_object_set_new(set->super.created, args->creation_id, mbox);
                jmap_add_id(req, args->creation_id,
                        json_string_value(json_object_get(mbox, "id")));
                if (result.tmp_imapname) {
                    struct tmp_rename *tmp = xzmalloc(sizeof(struct tmp_rename));
                    tmp->old_imapname = xstrdupnull(result.old_imapname);
                    tmp->new_imapname = xstrdup(result.new_imapname);
                    tmp->tmp_imapname = xstrdup(result.tmp_imapname);
                    ptrarray_append(&tmp_renames, tmp);
                }
            }
            _mboxset_result_fini(&result);
        }
        /* Update */
        else {
            struct mboxset_result result = MBOXSET_RESULT_INITIALIZER;
            set->update_cb(req, args, mode, &result, update_intermediaries);
            if (result.err) {
                json_object_set(set->super.not_updated,
                        args->id, result.err);
            }
            else if (result.skipped) {
                ptrarray_append(&skipped_put, args);
            }
            else {
                json_object_set(set->super.updated, args->id, json_null());
                if (result.tmp_imapname) {
                    struct tmp_rename *tmp = xzmalloc(sizeof(struct tmp_rename));
                    tmp->old_imapname = xstrdupnull(result.old_imapname);
                    tmp->new_imapname = xstrdup(result.new_imapname);
                    tmp->tmp_imapname = xstrdup(result.tmp_imapname);
                    ptrarray_append(&tmp_renames, tmp);
                }
            }
            _mboxset_result_fini(&result);
        }
    }
    ptrarray_truncate(ops->put, 0);
    for (i = 0; i < ptrarray_size(&skipped_put); i++)
        ptrarray_append(ops->put, ptrarray_nth(&skipped_put, i));

    /* Run destroy operations */
    for (i = 0; i < strarray_size(ops->del); i++) {
        const char *mbox_id = strarray_nth(ops->del, i);
        struct mboxset_result result = MBOXSET_RESULT_INITIALIZER;
        _mbox_destroy(req, mbox_id, set, mode, &result, update_intermediaries);
        if (result.err) {
            json_object_set(set->super.not_destroyed, mbox_id, result.err);
        }
        else if (result.skipped) {
            strarray_append(&skipped_del, mbox_id);
        }
        else {
            json_array_append_new(set->super.destroyed, json_string(mbox_id));
        }
        _mboxset_result_fini(&result);
    }
    strarray_truncate(ops->del, 0);
    for (i = 0; i < strarray_size(&skipped_del); i++)
        strarray_append(ops->del, strarray_nth(&skipped_del, i));

    /* Handle renames */
    for (i = 0; i < ptrarray_size(&tmp_renames); i++) {
        struct tmp_rename *tmp = ptrarray_nth(&tmp_renames, i);
        struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_RENAME);
        int r = mboxlist_renametree(tmp->tmp_imapname, tmp->new_imapname,
                NULL /* partition */, 0 /* uidvalidity */,
                httpd_userisadmin, req->userid, httpd_authstate,
                mboxevent,
                0 /* local_only */, 0 /* forceuser */, 0 /* ignorequota */,
                1 /* keep_intermediaries */, 1 /* move_subscription */);
        strarray_add(update_intermediaries, tmp->tmp_imapname);
        strarray_add(update_intermediaries, tmp->new_imapname);
        mboxevent_free(&mboxevent);
        if (r) {
            syslog(LOG_ERR, "jmap: mailbox rename failed half-way: old=%s tmp=%s new=%s: %s",
                    tmp->old_imapname ? tmp->old_imapname : "null",
                    tmp->tmp_imapname, tmp->new_imapname, error_message(r));
        }
        /* invalidate ACL cache */
        if (tmp->old_imapname) jmap_myrights_delete(req, tmp->old_imapname);
        jmap_mbentry_cache_free(req);
        jmap_myrights_delete(req, tmp->tmp_imapname);
        jmap_myrights_delete(req, tmp->new_imapname);
        free(tmp->old_imapname);
        free(tmp->new_imapname);
        free(tmp->tmp_imapname);
        free(tmp);
    }

    ptrarray_fini(&skipped_put);
    strarray_fini(&skipped_del);
    ptrarray_fini(&tmp_renames);
}

struct mboxset_entry {
    char *parent_id;
    char *name;
    int changed_parent;
    int is_inbox;
    int is_toplevel;
    int is_deleted;
};

static void _mboxset_entry_free(void *entryp)
{
    struct mboxset_entry *entry = entryp;
    free(entry->parent_id);
    free(entry->name);
    free(entryp);
}

struct mboxset_state {
    jmap_req_t *req;
    int has_conflict;
    hash_table *id_by_imapname;
    hash_table *entry_by_id;
    hash_table *siblings_by_parent_id;
    hash_table *specialuses_by_id;
};

static int _mboxset_state_mboxlist_cb(const mbentry_t *mbentry, void *rock)
{
    struct mboxset_state *state = rock;

    if (mbtype_isa(mbentry->mbtype) == MBTYPE_EMAIL) {
        hash_insert(mbentry->name, xstrdup(mbentry->uniqueid), state->id_by_imapname);
    }
    return 0;
}

static void _mboxset_state_mkentry_cb(const char *imapname, void *idptr, void *rock)
{
    struct mboxset_state *state = rock;
    char *mbox_id = idptr;

    /* Make entry */
    struct mboxset_entry *entry = xzmalloc(sizeof(struct mboxset_entry));
    mbname_t *mbname = mbname_from_intname(imapname);
    entry->name = _mbox_get_name(state->req->accountid, mbname);

    /* Find parent */
    mbentry_t *pmbentry = NULL;

    size_t nboxes = strarray_size(mbname_boxes(mbname));
    switch (nboxes) {
    case 0:
        entry->is_inbox = 1;
        break;
    case 1:
        entry->is_toplevel = 1;
        break;
    default:
        assert(_findparent(imapname, &pmbentry) == 0);
        entry->parent_id = xstrdup(pmbentry->uniqueid);
        break;
    }

    mboxlist_entry_free(&pmbentry);

    /* Add entry */
    hash_insert(mbox_id, entry, state->entry_by_id);
    mbname_free(&mbname);
}

static void _mboxset_state_conflict_cb(const char *id, void *data, void *rock)
{
    struct mboxset_state *state = rock;
    struct mboxset_entry *entry = data;

    if (state->has_conflict || entry->is_deleted) {
        return;
    }
    if (entry->is_inbox) {
        /* This is the INBOX. There can't be a conflict. */
        return;
    }
    if (entry->parent_id) {
        struct mboxset_entry *parent = hash_lookup(entry->parent_id, state->entry_by_id);
        if (!parent) {
            /* This is an internal error in the state. It can't be valid. */
            state->has_conflict = 1;
            return;
        }
        /* A mailbox must not have a deleted parent. */
        if (parent->is_deleted) {
            state->has_conflict = 1;
            return;
        }
    }
    const char *parent_id = "";
    if (entry->parent_id) parent_id = entry->parent_id;

    /* A mailbox must not have siblings with the same name. */
    strarray_t *siblings = hash_lookup(parent_id, state->siblings_by_parent_id);
    if (!siblings) {
        siblings = strarray_new();
        hash_insert(parent_id, siblings, state->siblings_by_parent_id);
    }
    int i;
    for (i = 0; i < strarray_size(siblings); i++) {
        if (!strcmp(entry->name, strarray_nth(siblings, i))) {
            state->has_conflict = 1;
            return;
        }
    }
    strarray_append(siblings, entry->name);

    /* A mailbox must not be parent of its parents. */
    parent_id = entry->parent_id;
    while (parent_id) {
        if (!strcmp(id, parent_id)) {
            state->has_conflict = 1;
            return;
        }
        struct mboxset_entry *parent_entry = hash_lookup(parent_id, state->entry_by_id);
        if (!parent_entry || parent_entry->is_deleted) break;
        parent_id = parent_entry->parent_id;
    }
}

static void _mboxset_state_update_mboxtree(struct mboxset_state *state,
                                           struct mboxset *set __attribute__((unused)),
                                           struct mboxset_ops *ops)
{
    struct buf buf = BUF_INITIALIZER;

    /* Apply create and update */
    int i;
    for (i = 0; i < ptrarray_size(ops->put); i++) {
        struct mboxset_args *args = ptrarray_nth(ops->put, i);
        if (args->creation_id) {
            /* Create entry for in-memory mailbox tree */
            struct mboxset_entry *entry = xzmalloc(sizeof(struct mboxset_entry));
            // it's gotta have one or the other!
            if (args->is_toplevel)
                entry->is_toplevel = 1;
            else
                entry->parent_id = xstrdup(args->parent_id);
            entry->name = xstrdup(args->name);
            buf_putc(&buf, '#');
            buf_appendcstr(&buf, args->creation_id);
            hash_insert(buf_cstring(&buf), entry, state->entry_by_id);
            buf_reset(&buf);
        }
        else {
            /* Update entry in in-memory mailbox tree */
            struct mboxset_entry *entry = hash_lookup(args->id, state->entry_by_id);
            if (!entry) {
                state->has_conflict = 1;
                break;
            }
            if (args->name) {
                free(entry->name);
                entry->name = xstrdup(args->name);
            }
            if (args->is_toplevel) {
                if (!entry->is_toplevel)
                    entry->changed_parent = 1;
                free(entry->parent_id);
                entry->parent_id = NULL;
                entry->is_toplevel = 1;
            }
            if (args->parent_id) {
                if (entry->is_toplevel || !strcmpsafe(entry->parent_id, args->parent_id))
                    entry->changed_parent = 1;
                free(entry->parent_id);
                entry->parent_id = xstrdup(args->parent_id);
                entry->is_toplevel = 0;
            }
        }
    }

    /* Apply destroy */
    for (i = 0; i < strarray_size(ops->del); i++) {
        const char *mbox_id = strarray_nth(ops->del, i);
        struct mboxset_entry *entry = hash_lookup(mbox_id, state->entry_by_id);
        if (!entry) {
            state->has_conflict = 1;
            break;
        }
        entry->is_deleted = 1;
    }

    /* Check state for mailbox tree conflicts. */
    if (!state->has_conflict) {
        hash_enumerate(state->entry_by_id, _mboxset_state_conflict_cb, state);
    }

    buf_free(&buf);
}

static void _mboxset_state_update_specialuse(struct mboxset_state *state,
                                             struct mboxset *set __attribute__((unused)),
                                             struct mboxset_ops *ops)
{
    strarray_t have_specialuses = STRARRAY_INITIALIZER;
    strarray_t want_protected = STRARRAY_INITIALIZER;
    struct buf conflict_desc = BUF_INITIALIZER;
    int i;

    /* The rules for IMAP specialuse and JMAP roles differ:
     *
     * - IMAP allows a mailbox to have multiple specialuse flags.
     *   JMAP only supports one role per mailbox.
     * - IMAP allows multiple mailboxes to have the same specialuse.
     *   JMAP only allows at most one mailbox to have the same role.
     * - IMAP (Cyrus) defines protected specialuses, which must not
     *   be moved to another parent in the mailbox tree and which
     *   must not be deleted.
     *   JMAP has no notion of protected roles.
     *
     * When evaluating the final mailbox state to be valid, we check if the
     * resulting role assignments satisfy the most restrictive rules
     * imposed by both IMAP and JMAP:
     *
     * - A mailbox must not have more than one specialuse.
     * - Each specialuse must be assigned to at most one mailbox.
     * - A mailbox with protected specialuse must stay at its parent.
     * - Each protected specialuse must be preserved.
     *
     * If one of these rules is violated then all operations that alter
     * mailboxes with roles are rejected.
     */

    if (config_getstring(IMAPOPT_SPECIALUSE_PROTECT)) {
        const char *str = config_getstring(IMAPOPT_SPECIALUSE_PROTECT);
        strarray_t *protected_uses = strarray_split(str, NULL, STRARRAY_TRIM);
        /* Validate: no protected moved to other parent */
        for (i = 0; i < ptrarray_size(ops->put); i++) {
            struct mboxset_args *args = ptrarray_nth(ops->put, i);
            if (!args->id) {
                continue;
            }
            strarray_t *specialuses = hash_lookup(args->id, state->specialuses_by_id);
            if (!specialuses) {
                continue;
            }
            int j;
            for (j = 0; j < strarray_size(specialuses); j++) {
                const char *specialuse = strarray_nth(specialuses, j);
                if (strarray_find(protected_uses, specialuse, 0) < 0) {
                    continue;
                }
                struct mboxset_entry *entry = hash_lookup(args->id, state->entry_by_id);
                if (entry->changed_parent) {
                    state->has_conflict = 1;
                    buf_printf(&conflict_desc,
                            "\nMailbox %s has protected specialuse %s. "
                            "It must no be moved to another parentId",
                            args->id, specialuse);
                }
                strarray_add(&want_protected, specialuse);
            }
        }
        /* Gather currently used protected specialuse */
        hash_iter *iter = hash_table_iter(state->specialuses_by_id);
        while (hash_iter_next(iter)) {
            strarray_t *specialuses = hash_iter_val(iter);
            int j;
            for (j = 0; j < strarray_size(specialuses); j++) {
                const char *specialuse = strarray_nth(specialuses, j);
                if (strarray_find(protected_uses, specialuse, 0) >= 0) {
                    strarray_add(&want_protected, specialuse);
                }
            }
        }
        hash_iter_free(&iter);
        strarray_free(protected_uses);
    }

    /* Apply create and update */
    for (i = 0; i < ptrarray_size(ops->put); i++) {
        struct mboxset_args *args = ptrarray_nth(ops->put, i);
        if (!args->u.email.specialuse) {
            continue;
        }
        if (args->creation_id) {
            if (args->u.email.specialuse[0]) {
                strarray_t *specialuses = strarray_new();
                strarray_append(specialuses, args->u.email.specialuse);
                hash_insert(args->creation_id, specialuses, state->specialuses_by_id);
            }
        }
        else {
            if (args->u.email.specialuse[0]) {
                /* _mbox_set_annots replaces any existing specialuse annotation,
                 * so emulate the same here */
                strarray_t *specialuses = hash_lookup(args->id, state->specialuses_by_id);
                if (!specialuses) {
                    specialuses = strarray_new();
                    hash_insert(args->id, specialuses, state->specialuses_by_id);
                }
                else strarray_truncate(specialuses, 0);
                strarray_append(specialuses, args->u.email.specialuse);
            }
            else {
                strarray_t *specialuses = hash_lookup(args->id, state->specialuses_by_id);
                if (specialuses) strarray_truncate(specialuses, 0);
            }
        }
    }
    /* Apply destroy */
    for (i = 0; i < strarray_size(ops->del); i++) {
        const char *mbox_id = strarray_nth(ops->del, i);
        strarray_t *specialuses = hash_lookup(mbox_id, state->specialuses_by_id);
        if (specialuses) strarray_truncate(specialuses, 0);
    }

    /* Validate: one mailbox per specialuse, one specialuse per mailbox */
    hash_iter *iter = hash_table_iter(state->specialuses_by_id);
    while (hash_iter_next(iter)) {
        const char* mbox_id = hash_iter_key(iter);
        strarray_t *specialuses = hash_iter_val(iter);
        if (strarray_size(specialuses) > 1) {
            state->has_conflict = 1;
            buf_printf(&conflict_desc, "\nMailbox %s has multiple specialuses:", mbox_id);
            for (i = 0; i < strarray_size(specialuses); i++) {
                buf_putc(&conflict_desc, ' ');
                buf_appendcstr(&conflict_desc, strarray_nth(specialuses, i));
            }
        }
        else if (!strarray_size(specialuses)) {
            continue;
        }
        const char *specialuse = strarray_nth(specialuses, 0);
        if (strarray_find(&have_specialuses, specialuse, 0) >= 0) {
            state->has_conflict = 1;
            buf_printf(&conflict_desc, "\nMailbox %s has specialuse %s, but at "
                    "least one other mailbox also has this specialuse.",
                    mbox_id, specialuse);
        }
        strarray_append(&have_specialuses, specialuse);
    }
    hash_iter_free(&iter);

    /* Validate: all protected preserved */
    for (i = 0; i < strarray_size(&want_protected); i++) {
        const char *protected = strarray_nth(&want_protected, i);
        if (strarray_find(&have_specialuses, protected, 0) < 0) {
            if (buf_len(&conflict_desc))
                buf_putc(&conflict_desc, ' ');
            buf_printf(&conflict_desc, "\nA mailbox had protected specialuse %s "
                    "but this specialuse is missing in the new mailbox state.",
                    protected);
            state->has_conflict = 1;
        }
    }

    /* Handle conflicts */
    if (state->has_conflict) {
        struct buf desc = BUF_INITIALIZER;
        buf_appendcstr(&desc, "The final mailbox state is invalid due to role conflicts");
        if (buf_len(&conflict_desc)) {
            buf_putc(&desc, ':');
            buf_append(&desc, &conflict_desc);
        }

        /* Reject all operations that alter roles */
        for (i = 0; i < ptrarray_size(ops->put); i++) {
            struct mboxset_args *args = ptrarray_nth(ops->put, i);
            if (args->u.email.specialuse ||
                    (args->parent_id &&
                     hash_lookup(args->id, state->specialuses_by_id))) {
                json_t *errfield = args->creation_id ?
                    set->super.not_created : set->super.not_updated;
                const char *errkey = args->creation_id ?
                    args->creation_id : args->id;

                json_object_set_new(errfield, errkey,
                        json_pack("{s:s s:[s] s:s}",
                            "type", "invalidProperties", "properties", "role",
                            "description", buf_cstring(&desc)));

                ptrarray_remove(ops->put, i--);
            }
        }
        /* Apply destroy */
        for (i = 0; i < strarray_size(ops->del); i++) {
            const char *mbox_id = strarray_nth(ops->del, i);
            if (hash_lookup(mbox_id, state->specialuses_by_id)) {
                json_object_set_new(set->super.not_destroyed, mbox_id,
                        json_pack("{s:s s:s}",
                            "type", "serverFail", "description", buf_cstring(&desc)));
                free(strarray_remove(ops->del, i--));
            }
        }
        buf_free(&desc);
    }

    buf_free(&conflict_desc);
    strarray_fini(&have_specialuses);
    strarray_fini(&want_protected);
}

static int _mboxset_state_find_specialuse_cb(const char *mboxname,
                                             uint32_t uid __attribute__((unused)),
                                             const char *entry __attribute__((unused)),
                                             const char *userid __attribute__((unused)),
                                             const struct buf *value,
                                             const struct annotate_metadata *mdata __attribute__((unused)),
                                             void *rock)
{
    struct mboxset_state *state = rock;
    jmap_req_t *req = state->req;

    if (!strcmpsafe(userid, req->accountid)) { // FIXME userid or accountid?
        const char *mbox_id = hash_lookup(mboxname, state->id_by_imapname);
        if (mbox_id) {
            strarray_t *specialuses = strarray_split(buf_cstring(value), " ", STRARRAY_TRIM);
            if (specialuses) {
                hash_insert(mbox_id, specialuses, state->specialuses_by_id);
            }
        }
    }

    return 0;
}


static int _mboxset_state_validate(jmap_req_t *req,
                                   struct mboxset *set,
                                   struct mboxset_ops *ops)
{
    int is_valid = 0;

    /* Create in-memory mailbox tree */
    struct mboxset_state *state = xzmalloc(sizeof(struct mboxset_state));
    state->req = req;

    hash_table id_by_imapname = HASH_TABLE_INITIALIZER;
    construct_hash_table(&id_by_imapname, 1024, 0);
    state->id_by_imapname = &id_by_imapname;

    hash_table entry_by_id = HASH_TABLE_INITIALIZER;
    construct_hash_table(&entry_by_id, 1024, 0);
    state->entry_by_id = &entry_by_id;

    hash_table siblings_by_parent_id = HASH_TABLE_INITIALIZER;
    construct_hash_table(&siblings_by_parent_id, 1024, 0);
    state->siblings_by_parent_id = &siblings_by_parent_id;

    mboxlist_usermboxtree(req->accountid, NULL, _mboxset_state_mboxlist_cb, state,
                          MBOXTREE_INTERMEDIATES);
    hash_enumerate(&id_by_imapname, _mboxset_state_mkentry_cb, state);

    /* Create specialuse entries */
    hash_table specialuses_by_id = HASH_TABLE_INITIALIZER;
    construct_hash_table(&specialuses_by_id, 1024, 0);
    state->specialuses_by_id = &specialuses_by_id;
    struct buf pattern = BUF_INITIALIZER;
    buf_initmcstr(&pattern, mboxname_user_mbox(req->accountid, NULL));
    buf_putc(&pattern, '*');
    annotatemore_findall_pattern(buf_cstring(&pattern), 0, "/specialuse", 0,
                                 _mboxset_state_find_specialuse_cb, state, 0);
    buf_free(&pattern);

    /* Apply changes */
    if (!state->has_conflict) {
        _mboxset_state_update_mboxtree(state, set, ops);
    }
    /* Check mailbox roles */
    if (!state->has_conflict) {
        _mboxset_state_update_specialuse(state, set, ops);
    }
    is_valid = !state->has_conflict;

    /* Clean up state */
    free_hash_table(&entry_by_id, _mboxset_entry_free);
    free_hash_table(&id_by_imapname, free);
    free_hash_table(&siblings_by_parent_id, (void(*)(void*))strarray_free);
    free_hash_table(&specialuses_by_id, (void(*)(void*))strarray_free);
    free(state);

    return is_valid;
}


EXPORTED void jmap_mboxset(jmap_req_t *req, struct mboxset *set)
{
    /* Mailbox/set operations are allowed to introduce inconsistencies in the
     * mailbox tree, as long as they are resolved after applying all operations
     * in the request. However, if the final state is not valid, the spec
     * requires that "each creation, modification or destruction of an object
     * should be processed sequentially and accepted/rejected based on the
     * current server state."
     *
     * Cyrus IMAP neither supports transactions on mailboxes nor invalid
     * temporary states. To work around these limitations the Mailbox/set
     * command is implemented as follows:
     *
     * 1. Sort the Mailbox/set operations topologically: create and update
     * operations are sorted together by parentId, parent before child.
     * Destroy operations are sorted child to parent. A topological sort is not
     * possible for cyclic operations and can never result in a valid final
     * state. The sort routine will in this case return an arbitrary order,
     * and we'll fail early for any conflicts and are done.
     *
     * 2. Run all operations, skipping any that either
     * - depends on a non-existent parent
     * - results in a mailboxHasChild conflict
     * - introduces a name-clash between siblings
     * - updates the mailbox role.
     * All other operations either succeed or fail permanently, and are removed
     * from the working set of operations. If there's no more operations left,
     * we're done.
     *
     * 3. Generate an in-memory representation of the current mailbox state,
     * then apply all pending operations to this model. If the resulting state
     * is invalid, we'll run the operations, let them fail for any conflict
     * and are done.
     *
     * 4. Run the pending operations and work around name-conflicts by using
     * temporary mailbox names for name-clashes. As the final state is known
     * to be valid and the operations are still topologically sorted, this must
     * always resolve any remaining conflicts.
     *
     * 5. For any temporary renames in step 4, rename the temporary mailbox
     * name to the requested name.
     *
     * All operations must now have either resulted in success or a permanent
     * error.
     */
    struct mboxset_ops *ops = _mboxset_newops(req, set);
    strarray_t update_intermediaries = STRARRAY_INITIALIZER;

    /* Apply Mailbox/set operations */
    if (ops->is_cyclic) {
        /* Fail for any invalid state */
        _mboxset_run(req, set, ops, _MBOXSET_FAIL, &update_intermediaries);
    }
    else {
        _mboxset_run(req, set, ops, _MBOXSET_SKIP, &update_intermediaries);
        if (ptrarray_size(ops->put) || strarray_size(ops->del)) {
            if (_mboxset_state_validate(req, set, ops)) {
                /* Allow invalid interim state */
                _mboxset_run(req, set, ops, _MBOXSET_INTERIM, &update_intermediaries);
            }
            else {
                /* Fail for any invalid state */
                _mboxset_run(req, set, ops, _MBOXSET_FAIL, &update_intermediaries);
            }
        }
    }

    /* Fetch mailbox state */
    json_t *jstate = jmap_getstate(req, set->mbtype, /*refresh*/1);
    set->super.new_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    /* Prune intermediary mailbox trees without any children. Do this
     * after we fetched the mailbox state, so clients are forced to
     * resync their mailbox trees after the Mailbox/set. */
    int i;
    for (i = 0; i < strarray_size(&update_intermediaries); i++) {
        const char *old_imapname = strarray_nth(&update_intermediaries, i);
        /* XXX - we know these are mailboxes, so mbtype 0 is OK, but it's not an
         * ideal interface */
        mboxlist_update_intermediaries(old_imapname, set->mbtype, 0);
        /* XXX error handling? */
    }

    assert(ptrarray_size(ops->put) == 0);
    assert(strarray_size(ops->del) == 0);
    _mboxset_ops_free(ops);
    strarray_fini(&update_intermediaries);
}

static int _mboxset_req_parse(jmap_req_t *req,
                               struct jmap_parser *parser __attribute__((unused)),
                               const char *key,
                               json_t *arg,
                               void *rock)
{
    struct mboxset *set = (struct mboxset *) rock;
    int r = 0;

    if ((!strcmp(key, "onDestroyRemoveMessages") ||
         !strcmp(key, "onDestroyRemoveEmails")) && json_is_boolean(arg)) {
        set->on_destroy_remove_msgs = json_boolean_value(arg);
        r = 1;
    }
    else if (jmap_is_using(req, JMAP_MAIL_EXTENSION)) {
        if (!strcmp(key, "onDestroyMoveToMailboxIfNoMailbox")) {
            if (json_is_string(arg) || json_is_null(arg)) {
                set->on_destroy_move_to_mailboxid = json_string_value(arg);
                r = 1;
            }
        }
    }

    return r;
}

static void _mboxset_parse(jmap_req_t *req,
                           struct jmap_parser *parser,
                           struct mboxset *set,
                           json_t **err)
{
    json_t *jarg;
    size_t i;
    memset(set, 0, sizeof(struct mboxset));

    jmap_set_parse(req, parser, mailbox_props, &_mboxset_req_parse,
                   set, &set->super, err);

    /* Validate onDestroyMoveToMailboxIfNoMailbox */
    if (*err == NULL && set->on_destroy_move_to_mailboxid) {
        const char *dst_mboxid = set->on_destroy_move_to_mailboxid;
        const char *error_desc = NULL;
        int rights = jmap_myrights_mboxid(req, dst_mboxid);

        if ((rights & ACL_LOOKUP) == 0) {
            error_desc = "not found";
        }
        else if ((rights & ACL_READ_WRITE) != ACL_READ_WRITE) {
            error_desc = "no permission";
        }
        else {
            const char *mboxid;
            json_t *jval;
            json_object_foreach(set->super.update, mboxid, jval) {
                if (!strcmp(mboxid, dst_mboxid)) {
                    error_desc = "mailbox must not be updated";
                    break;
                }
            }
            size_t i;
            json_array_foreach(set->super.destroy, i, jval) {
                if (!strcmp(json_string_value(jval), dst_mboxid)) {
                    error_desc = "mailbox must not be destroyed";
                    break;
                }
            }
        }
        if (error_desc) {
            *err = json_pack("{s:s s:[s] s:s}",
                    "type",
                        "invalidArguments",
                    "arguments",
                        "onDestroyMoveToMailboxIfNoMailbox",
                    "description",
                        error_desc);
        }
    }
    if (*err) return;

    /* create */
    const char *creation_id = NULL;
    json_object_foreach(set->super.create, creation_id, jarg) {
        struct jmap_parser myparser = JMAP_PARSER_INITIALIZER;
        struct mboxset_args *args = xzmalloc(sizeof(struct mboxset_args));
        json_t *set_err = NULL;

        _mboxset_args_parse(jarg, &myparser, args, req, /*is_create*/1);
        args->creation_id = xstrdup(creation_id);
        if (json_array_size(myparser.invalid)) {
            set_err = json_pack("{s:s}", "type", "invalidProperties");
            json_object_set(set_err, "properties", myparser.invalid);
            json_object_set_new(set->super.not_created, creation_id, set_err);
            jmap_parser_fini(&myparser);
            _mbox_setargs_fini(args);
            free(args);
            continue;
        }
        ptrarray_append(&set->create, args);
        jmap_parser_fini(&myparser);
    }

    /* update */
    hash_table will_destroy = HASH_TABLE_INITIALIZER;
    size_t size = json_array_size(set->super.destroy);
    if (size) {
        construct_hash_table(&will_destroy, size, 0);
        json_array_foreach(set->super.destroy, i, jarg) {
            hash_insert(json_string_value(jarg), (void*)1, &will_destroy);
        }
    }
    const char *mbox_id = NULL;
    json_object_foreach(set->super.update, mbox_id, jarg) {
        /* Parse Mailbox/set arguments  */
        struct jmap_parser myparser = JMAP_PARSER_INITIALIZER;
        struct mboxset_args *args = xzmalloc(sizeof(struct mboxset_args));
        _mboxset_args_parse(jarg, &myparser, args, req, /*is_create*/0);
        if (args->id && strcmp(args->id, mbox_id)) {
            jmap_parser_invalid(&myparser, "id");
        }
        if (!args->id) args->id = xstrdup(mbox_id);
        if (json_array_size(myparser.invalid)) {
            json_t *err = json_pack("{s:s}", "type", "invalidProperties");
            json_object_set(err, "properties", myparser.invalid);
            json_object_set_new(set->super.not_updated, mbox_id, err);
            jmap_parser_fini(&myparser);
            _mbox_setargs_fini(args);
            free(args);
            continue;
        }
        if (hash_lookup(args->id, &will_destroy)) {
            json_t *err = json_pack("{s:s}", "type", "willDestroy");
            json_object_set_new(set->super.not_updated, mbox_id, err);
            jmap_parser_fini(&myparser);
            _mbox_setargs_fini(args);
            free(args);
            continue;
        }
        ptrarray_append(&set->update, args);
        jmap_parser_fini(&myparser);
    }

    /* destroy */
    set->destroy = hash_keys(&will_destroy);
    free_hash_table(&will_destroy, NULL);
}

static void _mboxset_fini(struct mboxset *set)
{
    jmap_set_fini(&set->super);

    struct mboxset_args *args = NULL;
    while ((args = ptrarray_pop(&set->create))) {
        _mbox_setargs_fini(args);
        free(args);
    }
    ptrarray_fini(&set->create);
    while ((args = ptrarray_pop(&set->update))) {
        _mbox_setargs_fini(args);
        free(args);
    }
    ptrarray_fini(&set->update);
    strarray_free(set->destroy);
}

static int jmap_mailbox_set(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct mboxset set;

    /* Parse arguments */
    json_t *arg_err = NULL;
    _mboxset_parse(req, &parser, &set, &arg_err);
    if (arg_err) {
        jmap_error(req, arg_err);
        goto done;
    }
    if (set.super.if_in_state) {
        json_t *jstate = json_string(set.super.if_in_state);
        if (jmap_cmpstate(req, jstate, MBTYPE_EMAIL)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
        json_decref(jstate);
        set.super.old_state = xstrdup(set.super.if_in_state);
    }
    else {
        json_t *jstate = jmap_getstate(req, MBTYPE_EMAIL, /*refresh*/0);
        set.super.old_state = xstrdup(json_string_value(jstate));
        json_decref(jstate);
    }
    struct mboxlock *namespacelock = user_namespacelock(req->accountid);
    set.mbtype = MBTYPE_EMAIL;
    set.create_cb = &_mbox_create;
    set.update_cb = &_mbox_update;
    jmap_mboxset(req, &set);
    mboxname_release(&namespacelock);
    jmap_ok(req, jmap_set_reply(&set.super));

done:
    jmap_parser_fini(&parser);
    _mboxset_fini(&set);
    return 0;
}

struct _mbox_changes_data {
    json_t *created;          /* maps mailbox ids to {id:foldermodseq} */
    json_t *updated;        /* maps mailbox ids to {id:foldermodseq} */
    json_t *destroyed;      /* maps mailbox ids to {id:foldermodseq} */
    modseq_t since_modseq;
    int *only_counts_changed;
    jmap_req_t *req;
};

static int _mbox_changes_cb(const mbentry_t *mbentry, void *rock)
{
    struct _mbox_changes_data *data = rock;
    modseq_t modseq, mbmodseq;
    jmap_req_t *req = data->req;

    /* Ignore anything but regular mailboxes */
    if (mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL) {
        return 0;
    }

    /* Lookup status. */
    if (!(mbentry->mbtype & (MBTYPE_DELETED | MBTYPE_INTERMEDIATE))) {
        struct statusdata sdata = STATUSDATA_INIT;
        int r = status_lookup_mbentry(mbentry, data->req->userid,
                                      STATUS_HIGHESTMODSEQ, &sdata);
        if (r) return r;
        mbmodseq = sdata.highestmodseq;
    } else {
        mbmodseq = mbentry->foldermodseq;
    }

    /* Ignore old changes */
    if (mbmodseq <= data->since_modseq) {
        return 0;
    }

    /* Did any of the mailbox metadata change? */
    if (mbentry->foldermodseq > data->since_modseq) {
        *(data->only_counts_changed) = 0;
    }

    /* Determine where to report that update. Note that we even report
     * hidden mailboxes in order to allow clients remove unshared and
     * deleted mailboxes */
    json_t *dest = NULL;
    if (mbentry->createdmodseq <= data->since_modseq) {
        if ((mbentry->mbtype & MBTYPE_DELETED) ||
                !jmap_hasrights_mbentry(req, mbentry, JACL_LOOKUP)) {
            dest = data->destroyed;
        }
        else dest = data->updated;
    }
    else dest = data->created;

    /* Is this a more recent update for an id that we have already seen?
     * (check all three) */
    json_t *old[3];
    old[0] = data->created;
    old[1] = data->updated;
    old[2] = data->destroyed;
    int i;
    for (i = 0; i < 3; i++) {
        json_t *val = json_object_get(old[i], mbentry->uniqueid);
        if (!val) continue;
        modseq = (modseq_t)json_integer_value(json_object_get(val, "modseq"));
        if (modseq < mbmodseq) {
            /* use new update */
            json_object_del(old[i], mbentry->uniqueid);
        } else if (modseq == mbmodseq) {
            /* most likely a rename: report it in 'updated' */
            if (dest == data->updated) {
                json_object_del(old[i], mbentry->uniqueid);
            }
            else if (i == 1) {
                return 0;
            }
        } else {
            /* keep old update */
            return 0;
        }
    }

    /* OK, report that update */
    if (dest)
        json_object_set_new(dest, mbentry->uniqueid,
                            json_pack("{s:s s:i}", "id",
                                mbentry->uniqueid, "modseq", mbmodseq));

    return 0;
}

static int _mbox_changes_cmp(const void **pa, const void **pb)
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

static int _mbox_changes(jmap_req_t *req,
                         struct jmap_changes *changes,
                         int *only_counts_changed)
{
    *only_counts_changed = 1;

    ptrarray_t updates = PTRARRAY_INITIALIZER;
    struct _mbox_changes_data data = {
        json_object(),
        json_object(),
        json_object(),
        changes->since_modseq,
        only_counts_changed,
        req
    };
    modseq_t windowmodseq;
    const char *id;
    json_t *val;
    int r, i;


    /* Search for updates */
    r = mboxlist_usermboxtree(req->accountid, req->authstate,
                              _mbox_changes_cb, &data,
                              MBOXTREE_TOMBSTONES|
                              MBOXTREE_INTERMEDIATES);
    if (r) goto done;

    /* Sort updates by modseq */
    json_object_foreach(data.created, id, val) {
        ptrarray_add(&updates, val);
    }
    json_object_foreach(data.updated, id, val) {
        ptrarray_add(&updates, val);
    }
    json_object_foreach(data.destroyed, id, val) {
        ptrarray_add(&updates, val);
    }
    ptrarray_sort(&updates, _mbox_changes_cmp);

    /* Build result */
    changes->has_more_changes = 0;
    windowmodseq = 0;
    for (i = 0; i < updates.count; i++) {
        json_t *update = ptrarray_nth(&updates, i);
        const char *id = json_string_value(json_object_get(update, "id"));
        modseq_t modseq = json_integer_value(json_object_get(update, "modseq"));

        if (changes->max_changes && ((size_t) i) >= changes->max_changes) {
            changes->has_more_changes = 1;
            break;
        }

        if (windowmodseq < modseq)
            windowmodseq = modseq;

        if (json_object_get(data.created, id)) {
            json_array_append_new(changes->created, json_string(id));
        } else if (json_object_get(data.updated, id)) {
            json_array_append_new(changes->updated, json_string(id));
        } else {
            json_array_append_new(changes->destroyed, json_string(id));
        }
    }

    if ((json_array_size(changes->created) == 0 &&
         json_array_size(changes->updated) == 0 &&
         json_array_size(changes->destroyed) == 0) ||
        (json_array_size(changes->created) > 0) ||
        (json_array_size(changes->destroyed) > 0)) {
        *only_counts_changed = 0;
    }

    changes->new_modseq = changes->has_more_changes ?
        windowmodseq : jmap_highestmodseq(req, 0);

done:
    if (data.created) json_decref(data.created);
    if (data.updated) json_decref(data.updated);
    if (data.destroyed) json_decref(data.destroyed);
    ptrarray_fini(&updates);
    return r;
}

static int jmap_mailbox_changes(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;
    json_t *err = NULL;

    /* Parse request */
    jmap_changes_parse(req, &parser, req->counters.mailfoldersdeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Search for updates */
    int only_counts_changed = 0;
    int r = _mbox_changes(req, &changes, &only_counts_changed);
    if (r) {
        syslog(LOG_ERR, "jmap: Mailbox/changes: %s", error_message(r));
        jmap_error(req, jmap_server_error(r));
        goto done;
    }

    /* Build response */
    json_t *res = jmap_changes_reply(&changes);
    json_t *changed_props = json_null();
    if (only_counts_changed) {
        changed_props = json_pack("[s,s,s,s]",
                "totalEmails", "unreadEmails", "totalThreads", "unreadThreads");
    }
    json_object_set_new(res, "updatedProperties", changed_props);
    jmap_ok(req, res);

done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    return 0;
}
