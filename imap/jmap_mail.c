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
#include <jansson.h>

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "http_dav.h"
#include "http_jmap.h"
#include "imap_err.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "parseaddr.h"
#include "statuscache.h"
#include "stristr.h"
#include "sync_log.h"
#include "times.h"
#include "util.h"
#include "xmalloc.h"

#include "jmap_common.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

static int getMailboxes(jmap_req_t *req);
static int setMailboxes(jmap_req_t *req);
static int getMessageList(jmap_req_t *req);
static int getMessages(jmap_req_t *req);
static int setMessages(jmap_req_t *req);
/* XXX getMessageUpdates */
/* XXX importMessages */
/* XXX copyMessages */
/* XXX reportMessages */
/* XXX getIdentities */
/* XXX getIdentityUpdates */
/* XXX setIdentities */
/* XXX getSearchSnippets */
/* XXX getVacationResponse */
/* XXX setVacationResponse */
/* XXX getThreads */
/* XXX getThreadUpdates */


jmap_msg_t jmap_mail_messages[] = {
    { "getMailboxes",           &getMailboxes },
    { "setMailboxes",           &setMailboxes },
    { "getMessageList",         &getMessageList },
    { "getMessages",            &getMessages },
    { "setMessages",            &setMessages },
    { NULL,                     NULL}
};

#define JMAP_INREPLYTO_HEADER "X-JMAP-In-Reply-To"

struct _mboxcache_rec {
    struct mailbox *mbox;
    int refcount;
    int rw;
};

struct _req_context {
    hash_table *props;
    ptrarray_t *cache;
};

static int _initreq(jmap_req_t *req)
{
    struct _req_context *ctx = xzmalloc(sizeof(struct _req_context));
    ctx->cache = ptrarray_new();
    req->rock = ctx;
    return 0;
}

static void _finireq(jmap_req_t *req)
{
    struct _req_context *ctx = (struct _req_context *) req->rock;

    if (!ctx) return;

    assert(ctx->cache->count == 0);
    ptrarray_free(ctx->cache);

    if (ctx->props) {
        free_hash_table(ctx->props, NULL);
        free(ctx->props);
    }

    free(ctx);
    req->rock = NULL;
}

static int _openmbox(jmap_req_t *req, const char *name, struct mailbox **mboxp, int rw)
{
    int i, r;
    ptrarray_t* cache = ((struct _req_context*)req->rock)->cache;
    struct _mboxcache_rec *rec;

    if (!strcmp(name, req->inbox->name)) {
        *mboxp = req->inbox;
        return 0;
    }

    for (i = 0; i < cache->count; i++) {
        rec = (struct _mboxcache_rec*) ptrarray_nth(cache, i);
        if (!strcmp(name, rec->mbox->name)) {
            if (rw && !rec->rw) {
                /* Lock promotions are not supported */
                syslog(LOG_ERR, "jmapmbox: won't reopen mailbox %s", name);
                return IMAP_INTERNAL;
            }
            rec->refcount++;
            *mboxp = rec->mbox;
            return 0;
        }
    }

    r = rw ? mailbox_open_iwl(name, mboxp) : mailbox_open_irl(name, mboxp);
    if (r) {
        syslog(LOG_ERR, "_openmbox(%s): %s", name, error_message(r));
        return r;
    }

    rec = xzmalloc(sizeof(struct _mboxcache_rec));
    rec->mbox = *mboxp;
    rec->refcount = 1;
    rec->rw = rw;
    ptrarray_add(cache, rec);

    return 0;
}

static void _closembox(jmap_req_t *req, struct mailbox **mboxp)
{
    ptrarray_t* cache = ((struct _req_context*)req->rock)->cache;
    struct _mboxcache_rec *rec = NULL;
    int i;

    if (*mboxp == req->inbox) {
        *mboxp = NULL;
        return;
    }

    for (i = 0; i < cache->count; i++) {
        rec = (struct _mboxcache_rec*) ptrarray_nth(cache, i);
        if (rec->mbox == *mboxp)
            break;
    }
    assert(i < cache->count);

    if (!(--rec->refcount)) {
        ptrarray_remove(cache, i);
        mailbox_close(&rec->mbox);
    }
    *mboxp = NULL;
}

static int _wantprop(jmap_req_t *req, const char *name)
{
    struct _req_context *ctx = (struct _req_context *) req->rock;
    if (!ctx->props) return 1;
    return hash_lookup(name, ctx->props) != NULL;
}

static void _addprop(jmap_req_t *req, const char *name)
{
    struct _req_context *ctx = (struct _req_context *) req->rock;

    if (!ctx->props) {
        ctx->props = xzmalloc(sizeof(hash_table));
        construct_hash_table(ctx->props, 64, 0);
    }
    hash_insert(name, (void *)1, ctx->props);
}

/* FIXME DUPLICATE START */

static int JNOTNULL(json_t *item)
{
   if (!item) return 0;
   if (json_is_null(item)) return 0;
   return 1;
}

/* Read the property named name into dst, formatted according to the json
 * unpack format fmt.
 *
 * If unpacking failed, or name is mandatory and not found in root, append
 * name (prefixed by any non-NULL prefix) to invalid.
 *
 * Return a negative value for a missing or invalid property.
 * Return a positive value if a property was read, zero otherwise. */
static int readprop_full(json_t *root,
                         const char *prefix,
                         const char *name,
                         int mandatory,
                         json_t *invalid,
                         const char *fmt,
                         void *dst)
{
    int r = 0;
    json_t *jval = json_object_get(root, name);
    if (!jval && mandatory) {
        r = -1;
    } else if (jval) {
        json_error_t err;
        if (json_unpack_ex(jval, &err, 0, fmt, dst)) {
            r = -2;
        } else {
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

static int _match_text(const char *haystack, const char *needle) {
    /* XXX This is just a very crude text matcher. */
    return stristr(haystack, needle) != NULL;
}

/* Return true if text matches the value of arg's property named name. If 
 * name is NULL, match text to any JSON string property of arg or those of
 * its enclosed JSON objects and arrays. */
static int jmap_match_jsonprop(json_t *arg, const char *name, const char *text) {
    if (name) {
        json_t *val = json_object_get(arg, name);
        if (json_typeof(val) != JSON_STRING) {
            return 0;
        }
        return _match_text(json_string_value(val), text);
    } else {
        const char *key;
        json_t *val;
        int m = 0;
        size_t i;
        json_t *entry;

        json_object_foreach(arg, key, val) {
            switch json_typeof(val) {
                case JSON_STRING:
                    m = _match_text(json_string_value(val), text);
                    break;
                case JSON_OBJECT:
                    m = jmap_match_jsonprop(val, NULL, text);
                    break;
                case JSON_ARRAY:
                    json_array_foreach(val, i, entry) {
                        switch json_typeof(entry) {
                            case JSON_STRING:
                                m = _match_text(json_string_value(entry), text);
                                break;
                            case JSON_OBJECT:
                                m = jmap_match_jsonprop(entry, NULL, text);
                                break;
                            default:
                                /* do nothing */
                                ;
                        }
                        if (m) break;
                    }
                default:
                    /* do nothing */
                    ;
            }
            if (m) return m;
        }
    }
    return 0;
}

/* FIXME DUPLICATE END */

char *jmapmbox_role(jmap_req_t *req, const char *mboxname)
{
    struct buf buf = BUF_INITIALIZER;
    const char *role = NULL;
    char *ret = NULL;
    int r;

    /* Inbox is special. */
    char *inboxname = mboxname_user_mbox(req->userid, NULL);
    if (!strcmp(mboxname, inboxname)) {
        free(inboxname);
        return xstrdup("inbox");
    }
    free(inboxname);

    /* Is it an outbox? */
    if (mboxname_isoutbox(mboxname)) return xstrdup("outbox");

    /* XXX How to determine the templates role? */

    /* Does this mailbox have an IMAP special use role? */
    r = annotatemore_lookup(mboxname, "/specialuse", req->userid, &buf);

    if (r) return NULL;
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
                role = "junk";
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
        r = annotatemore_lookup(mboxname, IMAP_ANNOT_NS "x-role", req->userid, &buf);
        if (r) return NULL;
        if (buf.len) {
            role = buf_cstring(&buf);
        }
    }

    /* Make the caller own role. */
    if (role) ret = xstrdup(role);

    buf_free(&buf);
    return ret;
}

static char *jmapmbox_name(jmap_req_t *req, const char *mboxname) {
    struct buf attrib = BUF_INITIALIZER;
    char *name;
    char *inboxname = mboxname_user_mbox(req->userid, NULL);

    int r = annotatemore_lookup(mboxname, IMAP_ANNOT_NS "displayname",
            req->userid, &attrib);
    if (!r && attrib.len) {
        /* We got a mailbox with a displayname annotation. Use it. */
        name = buf_newcstring(&attrib);
    } else {
        /* No displayname annotation. Most probably this mailbox was
         * created via IMAP. In any case, determine name from the the
         * last segment of the mailboxname hierarchy. */
        char *extname, *q = NULL;
        charset_t cs;

        if (strcmp(mboxname, inboxname)) {
            mbname_t *mbname = mbname_from_intname(mboxname);
            if (!mbname) {
                syslog(LOG_ERR, "mbname_from_intname(%s): returned NULL", mboxname);
                free(inboxname);
                return NULL;
            }
            extname = mbname_pop_boxes(mbname);
            /* Decode extname from IMAP UTF-7 to UTF-8. Or fall back to extname. */
            cs = charset_lookupname("imap-utf-7");
            if ((q = charset_to_utf8(extname, strlen(extname), cs, ENCODING_NONE))) {
                free(extname);
                extname = q;
            }
            charset_free(&cs);
            mbname_free(&mbname);
        } else {
            extname = xstrdup("Inbox");
        }
        name = extname;
    }
    buf_free(&attrib);
    free(inboxname);
    return name;
}

static json_t *jmapmbox_from_mbentry(jmap_req_t *req,
                                     const mbentry_t *mbentry,
                                     hash_table *roles)
{
    unsigned statusitems = STATUS_MESSAGES | STATUS_UNSEEN;
    struct statusdata sdata;
    struct buf specialuse = BUF_INITIALIZER;
    struct conversations_state *cstate = mailbox_get_cstate(req->inbox);
    int rights, parent_rights;
    struct mailbox *mbox = NULL;
    mbentry_t *mbparent = NULL;
    int is_inbox, parent_is_inbox;
    int r;

    json_t *obj = NULL;

    /* Determine parent. */
    r = mboxlist_findparent(mbentry->name, &mbparent);
    if (strcmp(mbentry->name, req->inbox->name)) {
        if (r && r != IMAP_MAILBOX_NONEXISTENT) {
            syslog(LOG_INFO, "mboxlist_findparent(%s) failed: %s",
                    mbentry->name, error_message(r));
            goto done;
        }
    }

    /* Determine rights */
    rights = httpd_myrights(req->authstate, mbentry);
    parent_rights = mbparent ? httpd_myrights(req->authstate, mbparent) : 0;

    /* INBOX requires special treatment */
    is_inbox = !strcmp(mbentry->name, req->inbox->name);
    parent_is_inbox = mbparent ? !strcmp(mbparent->name, req->inbox->name) : 0;

    /* Lookup status. */
    if ((r = _openmbox(req, mbentry->name, &mbox, 0)) == 0) {
        r = status_lookup_mailbox(mbox, req->userid, statusitems, &sdata);
        _closembox(req, &mbox);
    }
    if (r) goto done;

    /* Determine special use annotation. */
    annotatemore_lookup(mbentry->name, "/specialuse", req->userid, &specialuse);

    /* Build JMAP mailbox response. */
    obj = json_pack("{}");
    json_object_set_new(obj, "id", json_string(mbentry->uniqueid));
    if (_wantprop(req, "name")) {
        char *name = jmapmbox_name(req, mbentry->name);
        if (!name) goto done;
        json_object_set_new(obj, "name", json_string(name));
        free(name);
    }
    if (_wantprop(req, "mustBeOnlyMailbox")) {
        json_object_set_new(obj, "mustBeOnlyMailbox", json_false());
    }

    if (_wantprop(req, "mayReadItems")) {
        json_object_set_new(obj, "mayReadItems", json_boolean(rights & ACL_READ));
    }
    if (_wantprop(req, "mayAddItems")) {
        json_object_set_new(obj, "mayAddItems", json_boolean(rights & ACL_INSERT));
    }
    if (_wantprop(req, "mayRemoveItems")) {
        json_object_set_new(obj, "mayRemoveItems", json_boolean(rights & ACL_DELETEMSG));
    }
    if (_wantprop(req, "mayCreateChild")) {
        json_object_set_new(obj, "mayCreateChild", json_boolean(rights & ACL_CREATE));
    }

    if (_wantprop(req, "totalMessages")) {
        json_object_set_new(obj, "totalMessages", json_integer(sdata.messages));
    }
    if (_wantprop(req, "unreadMessages")) {
        json_object_set_new(obj, "unreadMessages", json_integer(sdata.unseen));
    }
    if (_wantprop(req, "totalThreads") || _wantprop(req, "unreadThreads")) {
        if (cstate) {
            conv_status_t xconv = CONV_STATUS_INIT;
            if ((r = conversation_getstatus(cstate, mbentry->name, &xconv))) {
                syslog(LOG_ERR, "conversation_getstatus(%s): %s", mbentry->name,
                        error_message(r));
                goto done;
            }
            if (_wantprop(req, "totalThreads")) {
                json_object_set_new(obj, "totalThreads", json_integer(xconv.exists));
            }
            if (_wantprop(req, "unreadThreads")) {
                json_object_set_new(obj, "unreadThreads", json_integer(xconv.unseen));
            }
        }
    }
    if (_wantprop(req, "mayRename")) {
        int mayRename = rights & ACL_DELETEMBOX && parent_rights & ACL_CREATE;
        json_object_set_new(obj, "mayRename", json_boolean(mayRename));
    }
    if (_wantprop(req, "mayDelete")) {
        int mayDelete = (rights & ACL_DELETEMBOX) && !is_inbox;
        json_object_set_new(obj, "mayDelete", json_boolean(mayDelete));
    }
    if (_wantprop(req, "role")) {
        char *role = jmapmbox_role(req, mbentry->name);
        if (role && !hash_lookup(role, roles)) {
            /* In JMAP, only one mailbox have a role. First one wins. */
            json_object_set_new(obj, "role", json_string(role));
            hash_insert(role, (void*)1, roles);
        } else {
            json_object_set_new(obj, "role", json_null());
        }
        if (role) free(role);
    }
    if (_wantprop(req, "sortOrder")) {
        struct buf attrib = BUF_INITIALIZER;
        int sortOrder = 0;
        /* Ignore lookup errors here. */
        annotatemore_lookup(mbentry->name, IMAP_ANNOT_NS "sortOrder", req->userid, &attrib);
        if (attrib.len) {
            uint64_t t = str2uint64(buf_cstring(&attrib));
            if (t < INT_MAX) {
                sortOrder = (int) t;
            } else {
                syslog(LOG_ERR, "%s: bogus sortOrder annotation value", mbentry->name);
            }
        }
        json_object_set_new(obj, "sortOrder", json_integer(sortOrder));
        buf_free(&attrib);
    }
    if (_wantprop(req, "parentId")) {
        json_object_set_new(obj, "parentId", (is_inbox || parent_is_inbox) ?
                json_null() : json_string(mbparent->uniqueid));
    }

done:
    if (r) {
        syslog(LOG_ERR, "jmapmbox_from_mbentry: %s", error_message(r));
    }
    if (mbparent) mboxlist_entry_free(&mbparent);
    buf_free(&specialuse);
    return obj;
}

struct jmapmbox_mboxlist_data {
    jmap_req_t *req;
    json_t *list;
    hash_table *roles;
    hash_table *ids;
};

int jmapmbox_mboxlist_cb(const mbentry_t *mbentry, void *rock)
{
    struct jmapmbox_mboxlist_data *data = (struct jmapmbox_mboxlist_data *) rock;
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

    /* Check ACL on mailbox for current user */
    rights = httpd_myrights(httpd_authstate, mbentry);
    if ((rights & (ACL_LOOKUP | ACL_READ)) != (ACL_LOOKUP | ACL_READ)) {
        goto done;
    }

    /* Convert mbox to JMAP object. */
    obj = jmapmbox_from_mbentry(req, mbentry, data->roles);
    if (!obj) {
        syslog(LOG_INFO, "could not convert mailbox %s to JMAP", mbentry->name);
        r = IMAP_INTERNAL;
        goto done;
    }
    json_array_append_new(list, obj);

  done:
    return r;
}

static int getMailboxes(jmap_req_t *req)
{
    json_t *item = NULL, *mailboxes, *state;
    struct jmapmbox_mboxlist_data data = {
        req,
        json_pack("[]"), /* list */
        (hash_table *) xmalloc(sizeof(hash_table)), /* roles */
        NULL  /* ids */
    };
    construct_hash_table(data.roles, 8, 0);

    _initreq(req);

    /* Determine current state. */
    state = jmap_getstate(0 /* MBTYPE */, req);

    /* Start constructing our response */
    item = json_pack("[s {s:s s:o} s]", "mailboxes",
                     "accountId", req->userid,
                     "state", state,
                     req->tag);

    /* Determine which properties to fetch. */
    json_t *properties = json_object_get(req->args, "properties");
    if (properties && json_array_size(properties)) {
        int i;
        int size = json_array_size(properties);
        for (i = 0; i < size; i++) {
            const char *pn = json_string_value(json_array_get(properties, i));
            if (pn == NULL) {
                json_t *err = json_pack("{s:s, s:[s]}",
                        "type", "invalidArguments", "arguments", "properties");
                json_array_append_new(req->response, json_pack("[s,o,s]",
                            "error", err, req->tag));
                goto done;
            }
            _addprop(req, pn);
        }
    }

    /* Process mailboxes. */
    mailboxes = json_array_get(item, 1);
    json_t *want = json_object_get(req->args, "ids");
    if (JNOTNULL(want)) {
        size_t i;
        json_t *val, *notFound = json_pack("[]");
        json_array_foreach(want, i, val) {
            const char *id = json_string_value(val);
            if (id == NULL) {
                json_t *err = json_pack("{s:s, s:[s]}",
                        "type", "invalidArguments", "arguments", "ids");
                json_array_append_new(req->response, json_pack("[s,o,s]",
                            "error", err, req->tag));
                json_decref(notFound);
                goto done;
            }
            /* Lookup mailbox by uniqueid. */
            char *mboxname = mboxlist_find_uniqueid(id, req->userid);
            if (mboxname) {
                struct mboxlist_entry *mbentry = NULL;
                int r = mboxlist_lookup(mboxname, &mbentry, NULL);
                if (!r && mbentry) {
                    jmapmbox_mboxlist_cb(mbentry, &data);
                    mboxlist_entry_free(&mbentry);
                } else {
                    syslog(LOG_ERR, "mboxlist_entry_lookup(%s): %s", mboxname,
                            error_message(r));
                    json_array_append_new(notFound, json_string(id));
                }
                free(mboxname);
            } else {
                json_array_append_new(notFound, json_string(id));
            }
        }
        json_object_set_new(mailboxes, "notFound", notFound);
    } else {
        mboxlist_usermboxtree(req->userid, jmapmbox_mboxlist_cb, &data, 0);
        json_object_set_new(mailboxes, "notFound", json_null());
    }
    json_object_set(mailboxes, "list", data.list);

    json_array_append(req->response, item);

done:
    if (item) json_decref(item);
    if (data.list) json_decref(data.list);
    if (data.roles) {
        free_hash_table(data.roles, NULL);
        free(data.roles);
    }
    _finireq(req);
    return 0;
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
char *jmapmbox_newname(const char *name, const char *parentname) {
    charset_t cs = CHARSET_UNKNOWN_CHARSET;
    char *mboxname = NULL;
    struct buf buf = BUF_INITIALIZER;
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
    buf_printf(&buf, "%s%c%s", parentname, jmap_namespace.hier_sep, s);
    free(s);
    mboxname = buf_newcstring(&buf);
    buf_reset(&buf);

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
        goto done;
    }
    if (rock.highest) {
        buf_printf(&buf, "%s_%d", mboxname, rock.highest + 1);
        free(mboxname);
        mboxname = buf_newcstring(&buf);
    }

done:
    buf_free(&buf);
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

static char *jmapmbox_findxrole(const char *xrole, const char *userid)
{
    struct jmapmbox_findxrole_data rock = { xrole, userid, NULL };
    /* INBOX can never have an x-role. */
    mboxlist_usermboxtree(userid, jmapmbox_findxrole_cb, &rock, MBOXTREE_SKIP_ROOT);
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


/* Create or update the JMAP mailbox as defined in arg.
 *
 * If uid points to NULL, create a new mailbox and make uid point to the newly
 * allocated uid on success. Otherwise update the existing mailbox with unique
 * id uid. Report any invalid properties in the invalid array. Store any other
 * JMAP set error in err.
 *
 * Return 0 for success or managed JMAP errors.
 */
static int jmapmbox_write(jmap_req_t *req, char **uid, json_t *arg,
                          json_t *invalid, json_t **err)
{
    const char *parentId = NULL, *id = NULL;
    char *name = NULL;
    const char *role = NULL, *specialuse = NULL;
    int sortOrder = 0;
    char *mboxname = NULL, *parentname = NULL;
    int r = 0, pe, is_create = (*uid == NULL);

    /* Validate properties. */

    /* id */
    pe = readprop(arg, "id", 0, invalid, "s", &id);
    if (pe > 0 && is_create) {
        json_array_append_new(invalid, json_string("id"));
    } else if (pe > 0 && strcmp(*uid, id)) {
        json_array_append_new(invalid, json_string("id"));
    }

    /* name */
    pe = readprop(arg, "name", is_create, invalid, "s", &name);
    if (pe > 0 && !strlen(name)) {
        json_array_append_new(invalid, json_string("name"));
    } else if (pe > 0) {
        /* Copy name to manage the memory of changed names. */
        if (name) name = xstrdup(name);
    }

    /* parentId */
    if (JNOTNULL(json_object_get(arg, "parentId"))) {
        pe = readprop(arg, "parentId", is_create, invalid, "s", &parentId);
        if (pe > 0 && strlen(parentId)) {
            if (strcmp(parentId, req->inbox->uniqueid)) {
                char *newparentname = NULL;
                int iserr = 0;
                /* Check if parentId is a creation id. If so, look up its uid. */
                if (*parentId == '#') {
                    const char *t = hash_lookup(parentId+1, req->idmap);
                    if (t) {
                        parentId = t;
                    } else {
                        iserr = 1;
                    }
                }
                /* Check if the parent mailbox exists. */
                if (!iserr) {
                    newparentname = mboxlist_find_uniqueid(parentId, req->userid);
                    if (!newparentname) iserr = 1;
                }
                /* Check if the mailbox accepts children. */
                if (!iserr) {
                    int may_create = 0;
                    struct mboxlist_entry *mbparent = NULL;
                    r = mboxlist_lookup(newparentname, &mbparent, NULL);
                    if (!r) {
                        int rights = httpd_myrights(req->authstate, mbparent);
                        may_create = (rights & (ACL_CREATE)) == ACL_CREATE;
                    }
                    if (mbparent) mboxlist_entry_free(&mbparent);
                    iserr = !may_create;
                }
                if (iserr) {
                    json_array_append_new(invalid, json_string("parentId"));
                }
                if (newparentname) free(newparentname);
            } else {
                parentId = req->inbox->uniqueid;
            }
        } else if (pe > 0) {
            /* An empty parentId is always an error. */
            json_array_append_new(invalid, json_string("parentId"));
        }
    } else {
        parentId = req->inbox->uniqueid;
    }

    /* role */
    if (JNOTNULL(json_object_get(arg, "role"))) {
        pe = readprop(arg, "role", is_create, invalid, "s", &role);
        if (pe > 0) {
            if (!strlen(role)) {
                json_array_append_new(invalid, json_string("role"));
            } else if (!is_create) {
                /* Roles are immutable for updates. */
                json_array_append_new(invalid, json_string("role"));
            } else {
                /* Check that this role is unique. */
                if (!strcmp(role, "inbox")) {
                    /* Creating a new inbox is always an error. */
                    json_array_append_new(invalid, json_string("role"));
                } else if (!strcmp(role, "outbox")) {
                    /* Outbox may only be created on top-level. */
                    if (!strcmp(parentId, req->inbox->uniqueid)) {
                        /* Check that no outbox exists. */
                        /* XXX mboxname_isoutbox checks for top-level mailbox 'Outbox' */
                        char *outboxname = mboxname_user_mbox(req->userid, "Outbox");
                        mbentry_t *mbentry = NULL;
                        if (mboxlist_lookup(outboxname, &mbentry, NULL) != IMAP_MAILBOX_NONEXISTENT)
                            json_array_append_new(invalid, json_string("role"));
                        if (mbentry) mboxlist_entry_free(&mbentry);
                        free(outboxname);
                    } else {
                        json_array_append_new(invalid, json_string("role"));
                    }
                } else {
                    /* Is is one of the known special use mailboxes? */
                    if (!strcmp(role, "archive")) {
                        specialuse = "\\Archive";
                    } else if (!strcmp(role, "drafts")) {
                        specialuse = "\\Drafts";
                    } else if (!strcmp(role, "junk")) {
                        specialuse = "\\Junk";
                    } else if (!strcmp(role, "sent")) {
                        specialuse = "\\Sent";
                    } else if (!strcmp(role, "trash")) {
                        specialuse = "\\Trash";
                    } else if (strncmp(role, "x-", 2)) {
                        /* Does it start with an "x-"? If not, reject it. */
                        json_array_append_new(invalid, json_string("role"));
                    }
                }
                char *exists = NULL;
                if (specialuse) {
                    /* Check that no such IMAP specialuse mailbox already exists. */
                    exists = mboxlist_find_specialuse(specialuse, req->userid);
                } else if (!json_array_size(invalid)) {
                    /* Check that no mailbox with this x-role exists. */
                    exists = jmapmbox_findxrole(role, req->userid);
                }
                if (exists) {
                    json_array_append_new(invalid, json_string("role"));
                    free(exists);
                }
            }
        }
    }

    /* sortOder */
    if (readprop(arg, "sortOrder", 0, invalid, "i", &sortOrder) > 0) {
        if (sortOrder < 0 || sortOrder >= INT_MAX) {
            json_array_append_new(invalid, json_string("sortOrder"));
        }
    }

    /* mayXXX. These are immutable, but we ignore them during update. */
    if (json_object_get(arg, "mustBeOnlyMailbox") && is_create) {
        json_array_append_new(invalid, json_string("mustBeOnlyMailbox"));
    }
    if (json_object_get(arg, "mayReadItems") && is_create) {
        json_array_append_new(invalid, json_string("mayReadItems"));
    }
    if (json_object_get(arg, "mayAddItems") && is_create) {
        json_array_append_new(invalid, json_string("mayAddItems"));
    }
    if (json_object_get(arg, "mayRemoveItems") && is_create) {
        json_array_append_new(invalid, json_string("mayRemoveItems"));
    }
    if (json_object_get(arg, "mayRename") && is_create) {
        json_array_append_new(invalid, json_string("mayRename"));
    }
    if (json_object_get(arg, "mayDelete") && is_create) {
        json_array_append_new(invalid, json_string("mayDelete"));
    }
    if (json_object_get(arg, "totalMessages") && is_create) {
        json_array_append_new(invalid, json_string("totalMessages"));
    }
    if (json_object_get(arg, "unreadMessages") && is_create) {
        json_array_append_new(invalid, json_string("unreadMessages"));
    }
    if (json_object_get(arg, "totalThreads") && is_create) {
        json_array_append_new(invalid, json_string("totalThreads"));
    }
    if (json_object_get(arg, "unreadThreads") && is_create) {
        json_array_append_new(invalid, json_string("unreadThreads"));
    }

    /* Bail out early for any property errors. */
    if (json_array_size(invalid)) {
        r = 0;
        goto done;
    }

    /* Determine the mailbox and its parent name. */
    if (!is_create) {
        /* Determine name of the existing mailbox with uniqueid uid. */
        if (strcmp(*uid, req->inbox->uniqueid)) {
            mboxname = mboxlist_find_uniqueid(*uid, req->userid);
            if (!mboxname) {
                *err = json_pack("{s:s}", "type", "notFound");
                goto done;
            }

            /* Determine parent name. */
            struct mboxlist_entry *mbparent = NULL;
            r = mboxlist_findparent(mboxname, &mbparent);
            if (r) {
                syslog(LOG_INFO, "mboxlist_findparent(%s) failed: %s",
                        mboxname, error_message(r));
                goto done;
            }
            parentname = xstrdup(mbparent->name);
            mboxlist_entry_free(&mbparent);
        } else {
            parentname = NULL;
            mboxname = xstrdup(req->inbox->name);
        }
    } else {
        /* Determine name for the soon-to-be created mailbox. */
        if (parentId && strcmp(parentId, req->inbox->uniqueid)) {
            parentname = mboxlist_find_uniqueid(parentId, req->userid);
            if (!parentname) {
                json_array_append_new(invalid, json_string("parentId"));
            }
        } else {
            /* parent must be INBOX */
            parentname = xstrdup(req->inbox->name);
        }
        if (role && !strcmp(role, "outbox")) {
            /* XXX mboxname_isoutbox checks for top-level mailbox 'Outbox' */
            mboxname = mboxname_user_mbox(req->userid, "Outbox");
        } else {
            /* Encode the mailbox name for IMAP. */
            mboxname = jmapmbox_newname(name, parentname);
            if (!mboxname) {
                syslog(LOG_ERR, "could not encode mailbox name");
                r = IMAP_INTERNAL;
                goto done;
            }
        }
    }

    if (is_create) {
        /* Create mailbox. */
        struct buf acl = BUF_INITIALIZER;
        char rights[100];
        buf_reset(&acl);
        cyrus_acl_masktostr(ACL_ALL | DACL_READFB, rights);
        buf_printf(&acl, "%s\t%s\t", req->userid, rights);
        r = mboxlist_createsync(mboxname, 0 /* MBTYPE */,
                NULL /* partition */,
                req->userid, req->authstate,
                0 /* options */, 0 /* uidvalidity */,
                0 /* highestmodseq */, buf_cstring(&acl),
                NULL /* uniqueid */, 0 /* local_only */,
                NULL /* mboxptr */);
        buf_free(&acl);
        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                    mboxname, error_message(r));
            goto done;
        }
        buf_free(&acl);
    } else {
        /* Do we need to move this mailbox to a new parent? */
        int force_rename = 0;

        if (parentId) {
            char *newparentname;
            if (strcmp(parentId, req->inbox->uniqueid)) {
                newparentname = mboxlist_find_uniqueid(parentId, req->userid);
                /* We already validated that parentId exists. */
                assert(newparentname);
            } else {
                newparentname = xstrdup(req->inbox->name);
            }

            /* Did the parent's name change? */
            if (strcmp(parentname, newparentname)) {
                free(parentname);
                parentname = newparentname;
                force_rename = 1;
            } else {
                free(newparentname);
            }
        }

        /* Do we need to rename the mailbox? But only if it isn't the INBOX! */
        if ((name || force_rename) && strcmp(mboxname, req->inbox->name)) {
            char *oldname = jmapmbox_name(req, mboxname);
            if (!name) name = xstrdup(oldname);

            /* Do old and new mailbox names differ? */
            if (force_rename || strcmp(oldname, name)) {
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
        }
    }

    /* Set displayname annotation on mailbox. */
    struct buf val = BUF_INITIALIZER;
    buf_setcstr(&val, name);
    static const char *displayname_annot = IMAP_ANNOT_NS "displayname";
    r = annotatemore_write(mboxname, displayname_annot, req->userid, &val);
    if (r) {
        syslog(LOG_ERR, "failed to write annotation %s: %s",
                displayname_annot, error_message(r));
        goto done;
    }
    buf_reset(&val);

    /* Set specialuse or x-role. specialuse takes precendence. */
    if (specialuse) {
        struct buf val = BUF_INITIALIZER;
        buf_setcstr(&val, specialuse);
        static const char *annot = "/specialuse";
        r = annotatemore_write(mboxname, annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    annot, error_message(r));
            goto done;
        }
        buf_free(&val);
    } else if (role) {
        struct buf val = BUF_INITIALIZER;
        buf_setcstr(&val, role);
        static const char *annot = IMAP_ANNOT_NS "x-role";
        r = annotatemore_write(mboxname, annot, req->userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    annot, error_message(r));
            goto done;
        }
        buf_free(&val);
    }

    /* Set sortOrder annotation on mailbox. */
    buf_printf(&val, "%d", sortOrder);
    static const char *sortorder_annot = IMAP_ANNOT_NS "sortOrder";
    r = annotatemore_write(mboxname, sortorder_annot, req->userid, &val);
    if (r) {
        syslog(LOG_ERR, "failed to write annotation %s: %s",
                sortorder_annot, error_message(r));
        goto done;
    }
    buf_free(&val);

    if (!*uid) {
        /* A newly created mailbox. Return it unique id. */
        mbentry_t *mbentry = NULL;
        r = mboxlist_lookup(mboxname, &mbentry, NULL);
        if (r) goto done;
        *uid = xstrdup(mbentry->uniqueid);
        mboxlist_entry_free(&mbentry);
    }

done:
    if (name) free(name);
    if (mboxname) free(mboxname);
    if (parentname) free(parentname);
    return r;
}

static int setMailboxes(jmap_req_t *req)
{
    int r = 0;
    json_t *set = NULL;
    char *mboxname = NULL;
    char *parentname = NULL;

    _initreq(req);

    json_t *state = json_object_get(req->args, "ifInState");
    if (state && jmap_checkstate(state, 0 /*MBTYPE*/, req)) {
        json_array_append_new(req->response, json_pack("[s, {s:s}, s]",
                    "error", "type", "stateMismatch", req->tag));
        goto done;
    }
    set = json_pack("{s:s}", "accountId", req->userid);
    json_object_set_new(set, "oldState", state);

    json_t *create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");
        const char *key;
        json_t *arg;

        json_object_foreach(create, key, arg) {
            json_t *invalid = json_pack("[]");
            char *uid = NULL;
            json_t *err = NULL;

            /* Validate key. */
            if (!strlen(key)) {
                json_t *err= json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notCreated, key, err);
                continue;
            }

            /* Create mailbox. */
            r = jmapmbox_write(req, &uid, arg, invalid, &err);
            if (r) goto done;

            /* Handle set errors. */
            if (err) {
                json_object_set_new(notCreated, key, err);
                json_decref(invalid);
                continue;
            }

            /* Handle invalid properties. */
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notCreated, key, err);
                continue;
            }
            json_decref(invalid);

            /* Report mailbox as created. */
            json_object_set_new(created, key, json_pack("{s:s}", "id", uid));

            /* hash_insert takes ownership of uid */
            hash_insert(key, uid, req->idmap);
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

    json_t *update = json_object_get(req->args, "update");
    if (update) {
        json_t *updated = json_pack("[]");
        json_t *notUpdated = json_pack("{}");
        const char *uid;
        json_t *arg;

        json_object_foreach(update, uid, arg) {
            json_t *invalid = json_pack("[]");
            json_t *err = NULL;

            /* Validate uid */
            if (!uid || !strlen(uid) || *uid == '#') {
                json_t *err= json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }

            /* Update mailbox. */
            r = jmapmbox_write(req, ((char **)&uid), arg, invalid, &err);
            if (r) goto done;

            /* Handle set errors. */
            if (err) {
                json_object_set_new(notUpdated, uid, err);
                json_decref(invalid);
                continue;
            }

            /* Handle invalid properties. */
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notUpdated, uid, err);
                continue;
            }
            json_decref(invalid);

            /* Report as updated. */
            json_array_append_new(updated, json_string(uid));
        }

        if (json_array_size(updated)) {
            json_object_set(set, "updated", updated);
        }
        json_decref(updated);

        if (json_object_size(notUpdated)) {
            json_object_set(set, "notUpdated", notUpdated);
        }
        json_decref(notUpdated);
    }

    json_t *destroy = json_object_get(req->args, "destroy");
    if (destroy) {
        json_t *destroyed = json_pack("[]");
        json_t *notDestroyed = json_pack("{}");

        size_t index;
        json_t *juid;
        json_array_foreach(destroy, index, juid) {

            /* Validate uid. */
            const char *uid = json_string_value(juid);
            if (!uid || !strlen(uid) || *uid == '#') {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }

            /* Do not allow to remove INBOX. */
            if (!strcmp(uid, req->inbox->uniqueid)) {
                json_t *err = json_pack("{s:s}", "type", "forbidden");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }

            /* Lookup mailbox by id. */
            mboxname = mboxlist_find_uniqueid(uid, req->userid);
            if (!mboxname) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }

            /* Check if the mailbox has any children. */
            if (jmapmbox_isparent(mboxname)) {
                json_t *err = json_pack("{s:s}", "type", "mailboxHasChild");
                json_object_set_new(notDestroyed, uid, err);
                if (mboxname) {
                    free(mboxname);
                    mboxname = NULL;
                }
                r = 0;
                continue;
            }

            /* Destroy mailbox. */
            struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_DELETE);
            if (mboxlist_delayed_delete_isenabled()) {
                r = mboxlist_delayed_deletemailbox(mboxname,
                        httpd_userisadmin || httpd_userisproxyadmin,
                        req->userid, req->authstate, mboxevent,
                        1 /* checkacl */, 0 /* local_only */, 0 /* force */);
            } else {
                r = mboxlist_deletemailbox(mboxname,
                        httpd_userisadmin || httpd_userisproxyadmin,
                        req->userid, req->authstate, mboxevent,
                        1 /* checkacl */, 0 /* local_only */, 0 /* force */);
            }
            mboxevent_free(&mboxevent);
            if (r == IMAP_PERMISSION_DENIED) {
                json_t *err = json_pack("{s:s}", "type", "forbidden");
                json_object_set_new(notDestroyed, uid, err);
                if (mboxname) {
                    free(mboxname);
                    mboxname = NULL;
                }
                r = 0;
                continue;
            } else if (r) {
                syslog(LOG_ERR, "failed to delete mailbox(%s): %s",
                        mboxname, error_message(r));
                goto done;
            }

            /* Report mailbox as destroyed. */
            json_array_append_new(destroyed, json_string(uid));

            /* Clean up memory. */
            free(mboxname);
            mboxname = NULL;
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

    /* Set newState field in calendarsSet. */
    if (json_object_get(set, "created") ||
        json_object_get(set, "updated") ||
        json_object_get(set, "destroyed")) {

        r = jmap_bumpstate(0 /*MBTYPE*/, req);
        if (r) goto done;
    }
    json_object_set_new(set, "newState", jmap_getstate(0 /*MBTYPE*/, req));

    json_incref(set);
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("mailboxesSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (mboxname) free(mboxname);
    if (parentname) free(parentname);
    if (set) json_decref(set);
    _finireq(req);
    return r;
}

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
            char *dec = charset_decode_mimeheader(a->name, CHARSET_NO_CANONIFY);
            if (dec) {
                json_object_set_new(e, "name", json_string(dec));
                free(dec);
            }
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
    for (p = buf_base(buf); p && *p; p++) {
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
            &src, utf8, ENCODING_NONE, "HTML", CHARSET_NO_CANONIFY);
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
    struct index_record record;
    int r;

    r = _openmbox(req, rec->mboxname, &mbox, 0);
    if (r) return r;

    r = mailbox_find_index_record(mbox, rec->uid, &record);
    if (!r && !(record.system_flags & (FLAG_EXPUNGED|FLAG_DELETED))) {
        json_object_set_new(mboxs, mbox->uniqueid, json_string(mbox->name));
    }

    _closembox(req, &mbox);
    return r;
}

static json_t* jmapmsg_mailboxes(jmap_req_t *req, const char *id)
{
    struct conversations_state *cstate = mailbox_get_cstate(req->inbox);
    struct jmapmsg_mailboxes_data data = { req, json_pack("{}") };

    if (cstate) {
        conversations_guid_foreach(cstate, id, jmapmsg_mailboxes_cb, &data);
    }

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
};

#define MSGBODIES_INITIALIZER \
    { NULL, NULL, PTRARRAY_INITIALIZER, PTRARRAY_INITIALIZER }

static int find_msgbodies(struct body *root, struct buf *msg_buf,
                          struct msgbodies *bodies)
{
    /* Dissect a message into its best text and html bodies, attachments
     * and embedded messages. Based on the IMAPTalk find_message function.
     * https://github.com/robmueller/mail-imaptalk/blob/master/IMAPTalk.pm
     *
     * Contrary to the IMAPTalk implementation, this function doesn't
     * generate textlist/htmllist fields.
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
            ((!disp || strcmp(disp, "ATTACHMENT")) && !dispfile)) {
            /* Text that isn't an attachment or has a filename */
            is_inline = 1;
        }
        if ((!strcmp(part->type, "APPLICATION")) &&
            (!strcmp(part->subtype, "OCTET-STREAM")) &&
            (rec->inside_enc && strstr(dispfile, "ENCRYPTED"))) {
            /* PGP octet-stream inside an pgp-encrypted part */
            is_inline = 1;
        }

        if (is_inline) {
            int is_html = !strcasecmp(part->subtype, "HTML");
            struct body **bodyp = is_html ? &bodies->html : &bodies->text;
            is_attach = 0;

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
                    ptrarray_unshift(work, subrec);
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

    if (isspace(*val)) val++;

    if ((curval = json_object_get(headers, key))) {
        char *newval = strconcat(json_string_value(curval), "\n", val, NULL);
        json_object_set_new(headers, key, json_string(newval));
        free(newval);
    } else {
        json_object_set_new(headers, key, json_string(val));
    }

    return  0;
}

static int jmapmsg_from_body(jmap_req_t *req, struct body *body,
                             struct buf *msg_buf,
                             struct mailbox *mbox,
                             const struct index_record *record,
                             int is_embedded, json_t **msgp)
{
    struct msgbodies bodies = MSGBODIES_INITIALIZER;
    json_t *msg = NULL;
    json_t *headers = json_pack("{}");
    struct buf buf = BUF_INITIALIZER;
    char *text = NULL, *html = NULL;
    int r;

    /* Disset message into its parts */
    r = find_msgbodies(body, msg_buf, &bodies);
    if (r) goto done;

    /* Always read the message headers */
    r = message_foreach_header(msg_buf->s + body->header_offset,
                               body->header_size, extract_headers, headers);
    if (r) goto done;

    msg = json_pack("{}");

    /* headers */
    if (_wantprop(req, "headers")) {
        json_object_set(msg, "headers", headers);
    }
    /* sender */
    if (_wantprop(req, "sender")) {
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
    if (_wantprop(req, "from")) {
        json_object_set_new(msg, "from", emailer_from_addr(body->from));
    }
    /* to */
    if (_wantprop(req, "to")) {
        json_object_set_new(msg, "to", emailer_from_addr(body->to));
    }
    /* cc */
    if (_wantprop(req, "cc")) {
        json_object_set_new(msg, "cc", emailer_from_addr(body->cc));
    }
    /*  bcc */
    if (_wantprop(req, "bcc")) {
        json_object_set_new(msg, "bcc", emailer_from_addr(body->bcc));
    }
    /* replyTo */
    if (_wantprop(req, "replyTo")) {
        json_t *reply_to = json_null();
        if (json_object_get(headers, "Reply-To")) {
            reply_to = emailer_from_addr(body->reply_to);
        }
        json_object_set_new(msg, "replyTo", reply_to);
    }
    /* subject */
    if (_wantprop(req, "subject")) {
        const char *subject = body->subject ? body->subject : "";
        json_object_set_new(msg, "subject", json_string(subject));
    }
    /* date */
    if (_wantprop(req, "date")) {
        time_t t;
        char datestr[RFC3339_DATETIME_MAX];

        time_from_rfc822(body->date, &t);
        time_to_rfc3339(t, datestr, RFC3339_DATETIME_MAX);
        json_object_set_new(msg, "date", json_string(datestr));
    }

    if (_wantprop(req, "textBody") ||
        _wantprop(req, "htmlBody") ||
        _wantprop(req, "preview") ||
        _wantprop(req, "body")) {

        if (bodies.text) {
            charset_t cs = charset_lookupname(bodies.text->charset_id);
            text = charset_to_utf8(msg_buf->s + bodies.text->content_offset,
                    bodies.text->content_size, cs, bodies.text->charset_enc);
            charset_free(&cs);
        }
        if (bodies.html) {
            charset_t cs = charset_lookupname(bodies.html->charset_id);
            html = charset_to_utf8(msg_buf->s + bodies.html->content_offset,
                    bodies.html->content_size, cs, bodies.html->charset_enc);
            charset_free(&cs);
        }
    }

    /* textBody */
    if (_wantprop(req, "textBody") || _wantprop(req, "body")) {
        const char *name = _wantprop(req, "textBody") ? "textBody" : "body";
        if (!text && html) {
            text = extract_plain(html);
        }
        json_object_set_new(msg, name, text ? json_string(text) : json_null());
    }
    /* htmlBody */
    if (_wantprop(req, "htmlBody") || _wantprop(req, "body")) {
        const char *name = _wantprop(req, "htmlBody") ? "htmlBody" : "body";
        if (!html && text) {
            html = xstrdup(text);
        }
        json_object_set_new(msg, name, html ? json_string(html) : json_null());
    }

    if (_wantprop(req, "hasAttachment")) {
        json_object_set_new(msg, "hasAttachment",
                json_boolean(bodies.atts.count + bodies.msgs.count));
    }

    /* attachments */
    if (_wantprop(req, "attachments")) {
        int i;
        json_t *atts = json_pack("{}");

        for (i = 0; i < bodies.atts.count; i++) {
            struct body *part = ptrarray_nth(&bodies.atts, i);
            json_t *att;
            char *tmp;

            tmp = strconcat(part->type, "/", part->subtype, NULL);
            att = json_pack("{s:s}", "type", tmp);
            free(tmp);

            /* FIXME set other fields */

            buf_reset(&buf);
            buf_printf(&buf, "att%d", i); /* FIXME need sha1 id from cachebody */
            json_object_set_new(atts, buf_cstring(&buf), att);
        }
        if (!json_object_size(atts)) {
            json_decref(atts);
            atts = json_null();
        }
        json_object_set_new(msg, "attachments", atts);
    }

    /* attachedMessages */
    if (_wantprop(req, "attachedMessages")) {
        int i;
        json_t *msgs = json_pack("{}");

        for (i = 0; i < bodies.msgs.count; i++) {
            struct body *part = ptrarray_nth(&bodies.msgs, i);
            json_t *submsg = NULL;

            r = jmapmsg_from_body(req, part->subpart, msg_buf, mbox, record, 1, &submsg);
            if (r) goto done;

            buf_reset(&buf);
            buf_printf(&buf, "msg%d", i); /* FIXME need sha1 id from cachebody */
            json_object_set_new(msgs, buf_cstring(&buf), submsg);
        }
        if (!json_object_size(msgs)) {
            json_decref(msgs);
            msgs = json_null();
        }
        json_object_set_new(msg, "attachedMessages", msgs);
    }

    if (!is_embedded) {
        uint32_t flags = record->system_flags;
        const char *msgid;

        /* id */
        msgid = message_guid_encode(&record->guid);
        json_object_set_new(msg, "id", json_string(msgid));

        /* blobId */
        if (_wantprop(req, "blobId")) {
            buf_setcstr(&buf, "m-");
            buf_appendcstr(&buf, msgid);
            json_object_set_new(msg, "blobId", json_string(buf_cstring(&buf)));
            buf_reset(&buf);

        }
        /* threadId */
        if (_wantprop(req, "threadId")) {
            conversation_id_t cid = record->cid;
            json_object_set_new(msg, "threadId", r ?
                    json_null() : json_string(conversation_id_encode(cid)));
        }
        /* mailboxIds */
        if (_wantprop(req, "mailboxIds")) {
            json_t *mailboxes, *val, *ids = json_pack("[]");
            const char *mboxid;
            mailboxes = jmapmsg_mailboxes(req, msgid);
            json_object_foreach(mailboxes, mboxid, val) {
                json_array_append_new(ids, json_string(mboxid));
            }
            json_decref(mailboxes);
            json_object_set_new(msg, "mailboxIds", ids);
        }

        /* inReplyToMessageId */
        if (_wantprop(req, "inReplyToMessageId")) {
            json_t *reply_id = json_null();
            if (flags & FLAG_DRAFT) {
                const char *key;
                json_t *val;

                json_object_foreach(headers, key, val) {
                    if (!strcasecmp(key, JMAP_INREPLYTO_HEADER)) {
                        reply_id = val;
                        break;
                    }
                }
            }
            json_object_set_new(msg, "inReplyToMessageId", reply_id);
        }
        /* isUnread */
        if (_wantprop(req, "isUnread")) {
            json_object_set_new(msg, "isUnread", json_boolean(!(flags & FLAG_SEEN)));
        }
        /* isFlagged */
        if (_wantprop(req, "isFlagged")) {
            json_object_set_new(msg, "isFlagged", json_boolean(flags & FLAG_FLAGGED));
        }
        /* isAnswered */
        if (_wantprop(req, "isAnswered")) {
            json_object_set_new(msg, "isAnswered", json_boolean(flags & FLAG_ANSWERED));
        }
        /* isDraft */
        if (_wantprop(req, "isDraft")) {
            json_object_set_new(msg, "isDraft", json_boolean(flags & FLAG_DRAFT));
        }

        /* size */
        if (_wantprop(req, "size")) {
            json_object_set_new(msg, "size", json_integer(record->size));
        }

        /* preview */
        if (_wantprop(req, "preview")) {
            const char *annot;
            buf_reset(&buf);
            if ((annot = config_getstring(IMAPOPT_JMAP_PREVIEW_ANNOT))) {
                annotatemore_msg_lookup(mbox->name, record->uid, annot, req->userid, &buf);
            }
            if (buf.len) {
                /* If there is a preview message annotations, use that one */
                json_object_set_new(msg, "preview", json_string(buf_cstring(&buf)));
            } else {
                /* Generate our own preview */
                char *preview = extract_preview(text,
                        config_getint(IMAPOPT_JMAP_PREVIEW_LENGTH));
                json_object_set_new(msg, "preview", json_string(preview));
                free(preview);
            }
            buf_reset(&buf);
        }
    }

    r = 0;

done:
    json_decref(headers);
    buf_free(&buf);
    if (text) free(text);
    if (html) free(html);
    ptrarray_fini(&bodies.atts);
    ptrarray_fini(&bodies.msgs);
    if (r) {
        if (msg) json_decref(msg);
        msg = NULL;
    }
    *msgp = msg;
    return r;
}

static int jmapmsg_from_record(jmap_req_t *req, struct mailbox *mbox,
                               const struct index_record *record,
                               json_t **msgp)
{
    struct body *body = NULL;
    struct buf msg_buf = BUF_INITIALIZER;
    int r;

    /* Fetch cache record for the message */
    r = mailbox_cacherecord(mbox, record);
    if (r) return r;

    /* Map the message into memory */
    r = mailbox_map_record(mbox, record, &msg_buf);
    if (r) return r;

    /* Parse message body structure */
    message_read_bodystructure(record, &body);
    r = jmapmsg_from_body(req, body, &msg_buf, mbox, record, 0, msgp);
    buf_free(&msg_buf);
    return r;
}


typedef struct jmapmsg_filter {
    hash_table *inMailboxes;
    hash_table *notInMailboxes;
    time_t before;
    time_t after;
    uint32_t minSize;
    uint32_t maxSize;
    json_t *isFlagged;
    json_t *isUnread;
    json_t *isAnswered;
    json_t *isDraft;
    json_t *hasAttachment;
    char *text;
    char *from;
    char *to;
    char *cc;
    char *bcc;
    char *subject;
    char *body;
    char *header;
    char *header_value;
} jmapmsg_filter_t;

static int jmapmsg_filter_match(void *vf, void *rock)
{
    jmapmsg_filter_t *f = (struct jmapmsg_filter *) vf;
    json_t *msg = (json_t *) rock;

    /* The following XXXs (and possibly also the boolean flags might be good
     * candidates to filter while only looking at the message's index record,
     * not fetching its headers and body. */
    /* XXX check inMailboxes and notInMailboxes before */
    /* XXX inMailboxes */
    /* XXX notInMailboxes */
    /* XXX before */
    /* XXX after */
    /* XXX minSize */
    /* XXX maxSize */

    /* isFlagged */
    if (f->isFlagged && f->isFlagged != json_object_get(msg, "isFlagged")) {
        return 0;
    }
    /* isUnread */
    if (f->isUnread && f->isUnread != json_object_get(msg, "isUnread")) {
        return 0;
    }
    /* isAnswered */
    if (f->isAnswered && f->isAnswered != json_object_get(msg, "isAnswered")) {
        return 0;
    }
    /* isDraft */
    if (f->isDraft && f->isDraft != json_object_get(msg, "isDraft")) {
        return 0;
    }
    /* hasAttachment */
    if (f->hasAttachment && f->hasAttachment != json_object_get(msg, "hasAttachment")) {
        return 0;
    }

    if (f->text && !jmap_match_jsonprop(msg, NULL, f->text)) {
        return 0;
    }
    /*  from */
    if (f->from && !jmap_match_jsonprop(msg, "from", f->from)) {
        return 0;
    }
    /*  to */
    if (f->to && !jmap_match_jsonprop(msg, "to", f->to)) {
        return 0;
    }
    /*  cc */
    if (f->cc && !jmap_match_jsonprop(msg, "cc", f->cc)) {
        return 0;
    }
    /*  bcc */
    if (f->bcc && !jmap_match_jsonprop(msg, "bcc", f->bcc)) {
        return 0;
    }
    /*  subject */
    if (f->subject && !jmap_match_jsonprop(msg, "subject", f->subject)) {
        return 0;
    }
    /*  body */
    if (f->body && !jmap_match_jsonprop(msg, "textBody", f->body)
                && !jmap_match_jsonprop(msg, "htmlBody", f->body)) {
        return 0;
    }
    /* header */
    /* header_value */
    if (f->header) {
        json_t *val = json_object_get(msg, f->header);
        if (!val) {
            return 0;
        }
        if (f->header_value && !_match_text(json_string_value(val), f->header_value)) {
            return 0;
        }
    }
    return 1;
}

static void jmapmsg_filter_free(void *vf)
{
    jmapmsg_filter_t *f = (jmapmsg_filter_t*) vf;
    if (f->inMailboxes) {
        free_hash_table(f->inMailboxes, NULL);
        free(f->inMailboxes);
    }
    if (f->notInMailboxes) {
        free_hash_table(f->notInMailboxes, NULL);
        free(f->notInMailboxes);
    }
    free(f);
}

static void* jmapmsg_filter_parse(json_t *arg,
                                  const char *prefix,
                                  json_t *invalid)
{

    jmapmsg_filter_t *f = (jmapmsg_filter_t*) xzmalloc(sizeof(struct jmapmsg_filter));
    struct buf buf = BUF_INITIALIZER;
    json_int_t i;
    const char *s;
    json_t *j;

    /* inMailboxes */
    json_t *inMailboxes = json_object_get(arg, "inMailboxes");
    if (inMailboxes && json_typeof(inMailboxes) != JSON_ARRAY) {
        buf_printf(&buf, "%s.inMailboxes", prefix);
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    } else if (inMailboxes) {
        f->inMailboxes = xmalloc(sizeof(struct hash_table));
        construct_hash_table(f->inMailboxes, json_array_size(inMailboxes)+1, 0);
        size_t i;
        json_t *val;
        json_array_foreach(inMailboxes, i, val) {
            buf_printf(&buf, "%s.inMailboxes[%zu]", prefix, i);
            const char *id;
            if (json_unpack(val, "s", &id) != -1) {
                hash_insert(id, (void*)1, f->inMailboxes);
            } else {
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            }
            buf_reset(&buf);
        }
    }

    /* notInMailboxes */
    json_t *notInMailboxes = json_object_get(arg, "notInMailboxes");
    if (notInMailboxes && json_typeof(notInMailboxes) != JSON_ARRAY) {
        buf_printf(&buf, "%s.notInMailboxes", prefix);
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    } else if (notInMailboxes) {
        f->notInMailboxes = xmalloc(sizeof(struct hash_table));
        construct_hash_table(f->notInMailboxes, json_array_size(notInMailboxes)+1, 0);
        size_t i;
        json_t *val;
        json_array_foreach(notInMailboxes, i, val) {
            buf_printf(&buf, "%s.notInMailboxes[%zu]", prefix, i);
            const char *id;
            if (json_unpack(val, "s", &id) != -1) {
                hash_insert(id, (void*)1, f->notInMailboxes);
            } else {
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            }
            buf_reset(&buf);
        }
    }

    /* before */
    if (JNOTNULL(json_object_get(arg, "before"))) {
        if (readprop_full(arg, prefix, "before", 0, invalid, "s", &s) > 0) {
            struct tm tm;
            const char *p = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
            if (!p || *p) {
                buf_printf(&buf, "%s.before", prefix);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
            f->before = mktime(&tm);
        }
    }
    /* after */
    if (JNOTNULL(json_object_get(arg, "after"))) {
        if (readprop_full(arg, prefix, "after", 0, invalid, "s", &s) > 0) {
            struct tm tm;
            const char *p = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
            if (!p || *p) {
                buf_printf(&buf, "%s.after", prefix);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
            f->after = mktime(&tm);
        }
    }
    /* minSize */
    if (JNOTNULL(json_object_get(arg, "minSize"))) {
        if (readprop_full(arg, prefix, "minSize", 0, invalid, "i", &i) > 0) {
            if (i < 0) {
                buf_printf(&buf, "%s.minSize", prefix);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            } else if (i > UINT32_MAX) {
                /* Can't store this in an uint32_t. Ignore. */
                i = 0;
            }
            f->minSize = i;
        }
    }
    /* maxSize */
    if (JNOTNULL(json_object_get(arg, "maxSize"))) {
        if (readprop_full(arg, prefix, "maxSize", 0, invalid, "i", &i) > 0) {
            if (i < 0) {
                buf_printf(&buf, "%s.maxSize", prefix);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            } else if (i > UINT32_MAX) {
                /* Can't store this in an uint32_t. Ignore. */
                i = 0;
            }
            f->maxSize = i;
        }
    }
    /* isFlagged */
    j = json_object_get(arg, "isFlagged");
    if (JNOTNULL(j)) {
        short b;
        if (readprop_full(arg, prefix, "isFlagged", 0, invalid, "b", &b) > 0) {
            f->isFlagged = j;
        }
    }
    /* isUnread */
    j = json_object_get(arg, "isUnread");
    if (JNOTNULL(j)) {
        short b;
        if (readprop_full(arg, prefix, "isUnread", 0, invalid, "b", &b) > 0) {
            f->isUnread = j;
        }
    }
    /* isAnswered */
    j = json_object_get(arg, "isAnswered");
    if (JNOTNULL(j)) {
        short b;
        if (readprop_full(arg, prefix, "isAnswered", 0, invalid, "b", &b) > 0) {
            f->isAnswered = j;
        }
    }
    /* isDraft */
    j = json_object_get(arg, "isDraft");
    if (JNOTNULL(j)) {
        short b;
        if (readprop_full(arg, prefix, "isDraft", 0, invalid, "b", &b) > 0) {
            f->isDraft = j;
        }
    }
    /* hasAttachment */
    j = json_object_get(arg, "hasAttachment");
    if (JNOTNULL(j)) {
        short b;
        if (readprop_full(arg, prefix, "hasAttachment", 0, invalid, "b", &b) > 0) {
            f->hasAttachment = j;
        }
    }
    /* text */
    if (JNOTNULL(json_object_get(arg, "text"))) {
        readprop_full(arg, prefix, "text", 0, invalid, "s", &f->text);
    }
    /* from */
    if (JNOTNULL(json_object_get(arg, "from"))) {
        readprop_full(arg, prefix, "from", 0, invalid, "s", &f->from);
    }
    /* to */
    if (JNOTNULL(json_object_get(arg, "to"))) {
        readprop_full(arg, prefix, "to", 0, invalid, "s", &f->to);
    }
    /* cc */
    if (JNOTNULL(json_object_get(arg, "cc"))) {
        readprop_full(arg, prefix, "cc", 0, invalid, "s", &f->cc);
    }
    /* bcc */
    if (JNOTNULL(json_object_get(arg, "bcc"))) {
        readprop_full(arg, prefix, "bcc", 0, invalid, "s", &f->bcc);
    }
    /* subject */
    if (JNOTNULL(json_object_get(arg, "subject"))) {
        readprop_full(arg, prefix, "subject", 0, invalid, "s", &f->subject);
    }
    /* body */
    if (JNOTNULL(json_object_get(arg, "body"))) {
        readprop_full(arg, prefix, "body", 0, invalid, "s", &f->body);
    }
    /* header */
    j = json_object_get(arg, "header");
    if (JNOTNULL(j)) {
        short iserr = 0;
        switch (json_array_size(j)) {
            case 2:
                iserr = json_unpack(json_array_get(j, 1), "s", &f->header_value);
                /* fallthrough */
            case 1:
                if (!iserr) iserr = json_unpack(json_array_get(j, 0), "s", &f->header);
                break;
            default:
                iserr = 1;
        }
        if (iserr) {
            buf_printf(&buf, "%s.header", prefix);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }

    buf_free(&buf);
    return f;
}

struct getmessagelist_data {
    jmap_req_t *req;
    json_t *messageIds;
    size_t position;
    size_t limit;
    size_t total;
    jmap_filter *filter;
};

static int getmessagelist(struct mailbox *mbox, struct getmessagelist_data *d) {
    struct mailbox_iter *mbiter;
    const struct index_record *record;
    int r = 0;

    mbiter = mailbox_iter_init(mbox, 0, ITER_SKIP_UNLINKED);
    if (!mbiter) {
        syslog(LOG_ERR, "mailbox_iter_init(%s) returned NULL", mbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }
    while ((record = mailbox_iter_step(mbiter))) {
        if (record->system_flags & FLAG_EXPUNGED) {
            continue;
        }
        const char *id = message_guid_encode(&record->guid);
        if (!id) {
            /* huh? */
            continue;
        }
        if (json_object_get(d->messageIds, id)) {
            /* Already seen this one */
            continue;
        }
        /* Match against filter. */
        if (d->filter) {
            json_t *msg;
            r = jmapmsg_from_record(d->req, mbox, record, &msg);
            if (r || !jmap_filter_match(d->filter, &jmapmsg_filter_match, msg)) {
                if (msg) json_decref(msg);
                continue;
            }
            if (msg) json_decref(msg);
        }
        json_object_set_new(d->messageIds, id, json_null());
    }
    mailbox_iter_done(&mbiter);
done:
    return r;
}

int getmessagelist_cb(const mbentry_t *mbentry, void *rock) {
    struct mailbox *mbox = NULL;
    struct getmessagelist_data *d = (struct getmessagelist_data*) rock;
    int r;

    r = _openmbox(d->req, mbentry->name, &mbox, 0);
    if (r) goto done;
    r = getmessagelist(mbox, d);
    _closembox(d->req, &mbox);

done:
    return r;
}

static json_t *_json_keys(json_t *object)
{
    const char *id;
    json_t *val, *keys = json_pack("[]");
    json_object_foreach(object, id, val) {
        json_array_append_new(keys, json_string(id));
    }
    return keys;
}

static int getMessageList(jmap_req_t *req)
{
    int r;
    int dofetch = 0;
    struct getmessagelist_data rock;
    memset(&rock, 0, sizeof(struct getmessagelist_data));
    rock.messageIds = json_pack("{}");
    rock.req = req;
    json_t *filter;

    _initreq(req);

    /* Parse and validate arguments. */
    json_t *invalid = json_pack("[]");
    /* FIXME lots of other arguments */
    filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        rock.filter = jmap_filter_parse(filter, "filter", invalid, jmapmsg_filter_parse);
    }
    readprop(req->args, "fetchMessages", 0, invalid, "b", &dofetch);
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Inspect messages of INBOX. */
    r = getmessagelist((struct mailbox*) req->inbox, &rock);
    if (r && r != CYRUSDB_DONE) goto done;
    /* Inspect any other mailboxes. */
    r = mboxlist_usermboxtree(req->userid, getmessagelist_cb, &rock, MBOXTREE_SKIP_ROOT);
    if (r && r != CYRUSDB_DONE) goto done;
    r = 0;

    /* Prepare response. */
    json_t *msgList = json_pack("{}");
    json_object_set_new(msgList, "accountId", json_string(req->userid));
    json_object_set_new(msgList, "state", jmap_getstate(0 /* MBTYPE */, req));
    json_object_set_new(msgList, "messageIds", _json_keys(rock.messageIds));

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("messageList"));
    json_array_append_new(item, msgList);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

    if (dofetch) {
        struct jmap_req subreq = *req;
        subreq.args = json_pack("{}");
        json_object_set_new(subreq.args, "ids", _json_keys(rock.messageIds));
        r = getMessages(&subreq);
        json_decref(subreq.args);
    }

done:
    json_decref(rock.messageIds);
    if (rock.filter) jmap_filter_free(rock.filter, jmapmsg_filter_free);
    _finireq(req);
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

    if (!d->mboxname || !strcmp(rec->mboxname, req->inbox->name)) {
        struct index_record record;
        struct mailbox *mbox = NULL;

        r = _openmbox(req, rec->mboxname, &mbox, 0);
        if (r) return r;

        r = mailbox_find_index_record(mbox, rec->uid, &record);
        if (!r && !(record.system_flags & (FLAG_EXPUNGED|FLAG_DELETED))) {
            if (d->mboxname) {
                free(d->mboxname);
                r = IMAP_OK_COMPLETED;
            }
            d->mboxname = xstrdup(rec->mboxname);
            d->uid = rec->uid;
        }

        _closembox(req, &mbox);
    }

    return r;
}

static int jmapmsg_find(jmap_req_t *req, const char *id,
                        char **mboxnameptr, uint32_t *uid)
{
    struct jmapmsg_find_data data = { req, NULL, 0 };
    struct conversations_state *cstate = mailbox_get_cstate(req->inbox);
    int r;

    if (!cstate) {
        syslog(LOG_INFO, "findmessage: cannot open conversations db");
        return IMAP_NOTFOUND;
    }

    r = conversations_guid_foreach(cstate, id, jmapmsg_find_cb, &data);
    if (r == IMAP_OK_COMPLETED) {
        r = 0;
    } else if (!data.mboxname) {
        r = IMAP_NOTFOUND;
    }
    *mboxnameptr = data.mboxname;
    *uid = data.uid;
    return r;
}

static int getMessages(jmap_req_t *req)
{
    int r = 0;
    json_t *list = json_pack("[]");
    json_t *notfound = json_pack("[]");
    json_t *invalid = json_pack("[]");
    size_t i;
    json_t *ids, *val, *props;

    _initreq(req);

    /* ids */
    ids = json_object_get(req->args, "ids");
    if (ids && json_array_size(ids)) {
        json_array_foreach(ids, i, val) {
            if (json_typeof(val) != JSON_STRING) {
                struct buf buf = BUF_INITIALIZER;
                buf_printf(&buf, "ids[%llu]", (unsigned long long) i);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
                continue;
            }
        }
    } else {
        json_array_append_new(invalid, json_string("ids"));
    }

    /* properties */
    props = json_object_get(req->args, "properties");
    if (props && json_array_size(props)) {
        json_array_foreach(props, i, val) {
            if (json_string_value(val)) {
                _addprop(req, json_string_value(val));
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
        struct index_record record;
        uint32_t uid;
        json_t *msg = NULL;
        struct mailbox *mbox = NULL;

        r = jmapmsg_find(req, id, &mboxname, &uid);
        if (r) goto doneloop;

        r = _openmbox(req, mboxname, &mbox, 0);
        if (r) goto done;

        r = mailbox_find_index_record(mbox, uid, &record);
        if (!r) jmapmsg_from_record(req, mbox, &record, &msg);

        _closembox(req, &mbox);

doneloop:
        if (r == IMAP_NOTFOUND) r = 0;
        if (mboxname) free(mboxname);
        if (msg) {
            json_array_append_new(list, msg);
        } else {
            json_array_append_new(notfound, json_string(id));
        }
        if (r) goto done;
    }

    if (!json_array_size(list)) {
        json_decref(list);
        list = json_null();
    }
    if (!json_array_size(notfound)) {
        json_decref(notfound);
        notfound = json_null();
    }

    json_t *messages = json_pack("{}");
    json_object_set_new(messages, "state", jmap_getstate(0 /*MBYTPE*/, req));
    json_object_set_new(messages, "accountId", json_string(req->userid));
    json_object_set(messages, "list", list);
    json_object_set(messages, "notFound", notfound);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("messages"));
    json_array_append_new(item, messages);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    json_decref(list);
    json_decref(notfound);
    _finireq(req);
    return r;
}

static int jmap_validate_emailer(json_t *emailer,
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

static int jmapmsg_get_messageid(jmap_req_t *req, const char *id, char **msgid)
{
    char *mboxname = NULL;
    struct mailbox *mbox = NULL;
    struct index_record record;
    uint32_t uid;
    message_t *m = NULL;
    struct buf buf = BUF_INITIALIZER;
    int r;

    r = jmapmsg_find(req, id, &mboxname, &uid);
    if (r) goto done;

    r = _openmbox(req, mboxname, &mbox, 0);
    if (r) goto done;

    r = mailbox_find_index_record(mbox, uid, &record);
    if (r || (record.system_flags & (FLAG_EXPUNGED|FLAG_DELETED))) {
        if (!r) r = IMAP_NOTFOUND;
        goto done;
    }

    m = message_new_from_record(mbox, &record);
    if (!m) goto done;

    r = message_get_messageid(m, &buf);
    if (r) goto done;

    buf_cstring(&buf);
    *msgid = buf_release(&buf);

done:
    if (m) message_unref(&m);
    if (mbox) _closembox(req, &mbox);
    if (mboxname) free(mboxname);
    buf_free(&buf);
    return r;
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


/* Write the JMAP Message msg in RFC-5322 compliant wire format.
 *
 * The message is assumed to not contain value errors. If 'date' is neither
 * set in the message headers nor property, the current date is set. If
 * From isn't set, the userid of the current jmap request is used as
 * email address.
 *
 * Return 0 on success or non-zero if writing to the file failed */
static int jmapmsg_write(jmap_req_t *req, json_t *msg, FILE *out)
{
    struct data {
        char *subject;
        char *to;
        char *cc;
        char *bcc;
        char *replyto;
        char *sender;
        char *from;
        char *date;
        char *msgid;
        char *contenttype;
        char *boundary;
        char *mua;

        char *references;
        char *inreplyto;
        char *replyto_id;

        const char *text;
        const char *html;

        json_t *atts;
        json_t *msgs;
        json_t *headers;

        size_t have_atts;
    } d;

    json_t *val, *prop;
    const char *key, *s;
    char *freeme = NULL;
    size_t i;
    struct buf buf = BUF_INITIALIZER;
    int r = 0;
    memset(&d, 0, sizeof(struct data));

    /* Weed out special header values. */
    d.headers = json_pack("{}");
    json_object_foreach(json_object_get(msg, "headers"), key, val) {
        s = json_string_value(val);
        if (!s) {
            continue;
        } else if (!strcasecmp(key, "From")) {
            d.from = xstrdup(s);
        } else if (!strcasecmp(key, "Sender")) {
            d.sender = xstrdup(s);
        } else if (!strcasecmp(key, "To")) {
            d.to = xstrdup(s);
        } else if (!strcasecmp(key, "Cc")) {
            d.cc = xstrdup(s);
        } else if (!strcasecmp(key, "Bcc")) {
            d.bcc = xstrdup(s);
        } else if (!strcasecmp(key, "Reply-To")) {
            d.replyto = xstrdup(s);
        } else if (!strcasecmp(key, "Subject")) {
            d.subject = xstrdup(s);
        } else if (!strcasecmp(key, "Message-ID")) {
            d.msgid = xstrdup(s);
        } else if (!strcasecmp(key, "In-Reply-To")) {
            d.inreplyto = xstrdup(s);
        } else if (!strcasecmp(key, "References")) {
            d.references = xstrdup(s);
        } else if (!strcasecmp(key, "Date")) {
            d.date = xstrdup(s);
        } else if (!strcasecmp(key, "User-Agent")) {
            d.mua = xstrdup(s);
        } else if (!strcasecmp(key, "MIME-Version")) {
            /* Ignore */
        } else if (!strcasecmp(key, "Content-Type")) {
            /* Ignore */
        } else if (!strcasecmp(key, "Content-Transfer-Encoding")) {
            /* Ignore */
        } else {
            json_object_set(d.headers, key, val);
        }
    }

#define JMAP_MESSAGE_EMAILER_TO_WIRE(b, m) \
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

    /* Override the From header */
    if ((prop = json_object_get(msg, "from"))) {
        json_array_foreach(prop, i, val) {
            if (i) buf_appendcstr(&buf, ", ");
            JMAP_MESSAGE_EMAILER_TO_WIRE(&buf, val);
        }
        if (d.from) free(d.from);
        d.from = buf_newcstring(&buf);
        buf_reset(&buf);
    }
    if (!d.from) d.from = xstrdup(req->userid);

    /* Override the Sender header */
    if ((prop = json_object_get(msg, "sender"))) {
        JMAP_MESSAGE_EMAILER_TO_WIRE(&buf, prop);
        if (d.sender) free(d.sender);
        d.sender = buf_newcstring(&buf);
        buf_reset(&buf);
    }

    /* Override the To header */
    if ((prop = json_object_get(msg, "to"))) {
        json_array_foreach(prop, i, val) {
            if (i) buf_appendcstr(&buf, ", ");
            JMAP_MESSAGE_EMAILER_TO_WIRE(&buf, val);
        }
        if (d.to) free(d.to);
        d.to = buf_newcstring(&buf);
        buf_reset(&buf);
    }

    /* Override the Cc header */
    if ((prop = json_object_get(msg, "cc"))) {
        json_array_foreach(prop, i, val) {
            if (i) buf_appendcstr(&buf, ", ");
            JMAP_MESSAGE_EMAILER_TO_WIRE(&buf, val);
        }
        if (d.cc) free(d.cc);
        d.cc = buf_newcstring(&buf);
        buf_reset(&buf);
    }

    /* Override the Bcc header */
    if ((prop = json_object_get(msg, "bcc"))) {
        json_array_foreach(prop, i, val) {
            if (i) buf_appendcstr(&buf, ", ");
            JMAP_MESSAGE_EMAILER_TO_WIRE(&buf, val);
        }
        if (d.bcc) free(d.bcc);
        d.bcc = buf_newcstring(&buf);
        buf_reset(&buf);
    }

    /* Override the Reply-To header */
    if ((prop = json_object_get(msg, "replyTo"))) {
        json_array_foreach(prop, i, val) {
            if (i) buf_appendcstr(&buf, ", ");
            JMAP_MESSAGE_EMAILER_TO_WIRE(&buf, val);
        }
        if (d.replyto) free(d.replyto);
        d.replyto = buf_newcstring(&buf);
        buf_reset(&buf);
    }
#undef JMAP_MESSAGE_EMAILER_TO_WIRE

    /* Override the In-Reply-To and References headers */
    if ((prop = json_object_get(msg, "inReplyToMessageId"))) {
        if ((s = json_string_value(prop))) {
            d.replyto_id = xstrdup(s);

            if (d.references) free(d.references);
            if (d.inreplyto) free(d.inreplyto);

            r = jmapmsg_get_messageid(req, d.replyto_id, &d.references);
            if (!r) d.inreplyto = xstrdup(d.references);
        }
    }

    /* Override Subject header */
    if ((s = json_string_value(json_object_get(msg, "subject")))) {
        if (d.subject) free(d.subject);
        d.subject = xstrdup(s);
    }
    if (!d.subject) d.subject = xstrdup("");

    /* Override Date header */
    /* Precedence (highes first): "date" property, Date header, now */
    time_t date = time(NULL);
    if ((s = json_string_value(json_object_get(msg, "date")))) {
        struct tm tm;
        strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
        date = mktime(&tm);
    }
    if (json_object_get(msg, "date") || !d.date) {
        char fmt[RFC822_DATETIME_MAX+1];
        memset(fmt, 0, RFC822_DATETIME_MAX+1);
        time_to_rfc822(date, fmt, RFC822_DATETIME_MAX+1);
        if (d.date) free(d.date);
        d.date = xstrdup(fmt);
    }

    d.text = json_string_value(json_object_get(msg, "textBody"));
    d.html = json_string_value(json_object_get(msg, "htmlBody"));
    if (!d.text && d.html) {
        freeme = extract_plain(d.html);
        d.text = freeme;
    }

    d.atts = json_object_get(msg, "attachments");
    d.msgs = json_object_get(msg, "attachedMessages");
    d.have_atts = json_object_size(d.atts) + json_object_size(d.msgs);

    /* Determine content-type and multipart boundary */
    buf_reset(&buf);
    d.boundary = _make_boundary();
    if (d.have_atts) {
        buf_setcstr(&buf, "multipart/mixed; boundary=");
        buf_appendcstr(&buf, d.boundary);
    } else if (d.html && d.text) {
        buf_setcstr(&buf, "multipart/alternative; boundary=");
        buf_appendcstr(&buf, d.boundary);
    } else {
        buf_setcstr(&buf, "text/");
        buf_appendcstr(&buf, d.html ? "html" : "plain");
        buf_appendcstr(&buf, "; charset=UTF-8");
        free(d.boundary);
        d.boundary = NULL;
    }
    d.contenttype = buf_release(&buf);

    /* Set Message-ID header */
    if (!d.msgid) {
        buf_printf(&buf, "<%s@%s>", makeuuid(), config_servername);
        d.msgid = buf_release(&buf);
    }

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

    /* Write headers */
#define JMAP_MESSAGE_WRITE_HEADER(k, v) \
    { \
       char *_v = (v); \
       char *s = charset_encode_mimeheader(_v, strlen(_v)); \
       fprintf(out, "%s: %s\r\n", k, s); \
       free(s); \
    }

    /* Mandatory headers according to RFC 5322 */
    JMAP_MESSAGE_WRITE_HEADER("From", d.from);
    JMAP_MESSAGE_WRITE_HEADER("Date", d.date);

    /* Common headers */
    if (d.to)      JMAP_MESSAGE_WRITE_HEADER("To", d.to);
    if (d.cc)      JMAP_MESSAGE_WRITE_HEADER("Cc", d.cc);
    if (d.bcc)     JMAP_MESSAGE_WRITE_HEADER("Bcc", d.bcc);
    if (d.sender)  JMAP_MESSAGE_WRITE_HEADER("Sender", d.sender);
    if (d.replyto) JMAP_MESSAGE_WRITE_HEADER("Reply-To", d.replyto);
    if (d.subject) JMAP_MESSAGE_WRITE_HEADER("Subject", d.subject);

    /* References, In-Reply-To and the custom X-JMAP header */
    if (d.inreplyto)  JMAP_MESSAGE_WRITE_HEADER("In-Reply-To", d.inreplyto);
    if (d.references) JMAP_MESSAGE_WRITE_HEADER("References", d.references);
    if (d.replyto_id) JMAP_MESSAGE_WRITE_HEADER(JMAP_INREPLYTO_HEADER, d.replyto_id);

    /* Custom headers */
    json_object_foreach(d.headers, key, val) {
        char *freeme, *p, *q;
        s = json_string_value(val);
        if (!s) continue;
        freeme = xstrdup(s);
        for (q = freeme, p = freeme; *p; p++) {
            if (*p == '\n' && (p == q || *(p-1) != '\r')) {
                *p = '\0';
                JMAP_MESSAGE_WRITE_HEADER(key, q);
                *p = '\n';
                q = p + 1;
            }
        }
        JMAP_MESSAGE_WRITE_HEADER(key, q);
        free(freeme);
    }

    /* Not mandatory but we'll always write these */
    JMAP_MESSAGE_WRITE_HEADER("Message-ID", d.msgid);
    JMAP_MESSAGE_WRITE_HEADER("User-Agent", d.mua);
    JMAP_MESSAGE_WRITE_HEADER("Content-Type", d.contenttype);
#undef JMAP_MESSAGE_WRITE_HEADER

    /* Write body parts */
    if (d.have_atts) {
        /* Content-Type is multipart/mixed */
        const char *subid;
        json_t *submsg;

        r = fprintf(out, "\r\n--%s\r\n", d.boundary);
        if (r < 0) goto done;

        if (d.html && d.text) {
            /* Write multipart/alternative part */
            char *alt = _make_boundary();
            fprintf(out, "Content-Type: multipart/alternative; boundary=%s\r\n", alt);
            fprintf(out, "\r\n--%s\r\n", alt);
            fputs("Content-Type: text/plain;charset=UTF-8\r\n\r\n", out);
            writetext(d.text, out, split_plain);
            fprintf(out, "\r\n--%s\r\n", alt);
            fputs("Content-Type: text/html;charset=UTF-8\r\n\r\n", out);
            writetext(d.html, out, split_html);
            fprintf(out, "\r\n--%s--\r\n", alt);
            free(alt);
        } else if (d.html) {
            fputs("Content-Type: text/html;charset=UTF-8\r\n\r\n", out);
            writetext(d.html, out, split_html);
        } else {
            fputs("Content-Type: text/plain;charset=UTF-8\r\n\r\n", out);
            writetext(d.text, out, split_plain);
        }

        /* Write embedded RFC822 messages */
        json_object_foreach(d.msgs, subid, submsg) {
            fprintf(out, "\r\n--%s\r\n", d.boundary);
            fputs("Content-Type: message/rfc822;charset=UTF-8\r\n\r\n", out);
            r = jmapmsg_write(req, submsg, out);
            if (r) goto done;
        }

        fprintf(out, "\r\n--%s--\r\n", d.boundary);

    } else if (d.html && d.text) {
        /* Content-Type is multipart/alternative */
        fprintf(out, "\r\n--%s\r\n", d.boundary);
        fputs("Content-Type: text/plain;charset=UTF-8\r\n\r\n", out);
        writetext(d.text, out, split_plain);
        fprintf(out, "\r\n--%s\r\n", d.boundary);
        fputs("Content-Type: text/html;charset=UTF-8\r\n\r\n", out);
        writetext(d.html, out, split_html);
        fprintf(out, "\r\n--%s--\r\n", d.boundary);
    } else if (d.html) {
        /* Content-Type is text/html */
        fputs("\r\n", out);
        writetext(d.html, out, split_html);
    } else {
        /* Content-Type is text/plain */
        fputs("\r\n", out);
        writetext(d.text, out, split_plain);
    }

done:
    if (freeme) free(freeme);
    if (d.from) free(d.from);
    if (d.sender) free(d.sender);
    if (d.date) free(d.date);
    if (d.to) free(d.to);
    if (d.cc) free(d.cc);
    if (d.bcc) free(d.bcc);
    if (d.replyto) free(d.replyto);
    if (d.subject) free(d.subject);
    if (d.msgid) free(d.msgid);
    if (d.references) free(d.references);
    if (d.inreplyto) free(d.inreplyto);
    if (d.replyto_id) free(d.replyto_id);
    if (d.mua) free(d.mua);
    if (d.contenttype) free(d.contenttype);
    if (d.boundary) free(d.boundary);
    if (d.headers) json_decref(d.headers);
    buf_free(&buf);
    if (r) r = HTTP_SERVER_ERROR;
    return r;
}

static void jmapmsg_validate(json_t *msg, json_t *invalid, int isdraft)
{
    int pe;
    json_t *prop;
    const char *sval;
    int bval;
    struct buf buf = BUF_INITIALIZER;
    struct tm *date = xzmalloc(sizeof(struct tm));
    char *mboxname = NULL;
    char *mboxrole = NULL;
    int validateaddr = !isdraft;

    pe = readprop(msg, "isDraft", 0, invalid, "b", &bval);
    if (pe > 0 && !bval) {
        json_array_append_new(invalid, json_string("isDraft"));
    }

    if (json_object_get(msg, "id")) {
        json_array_append_new(invalid, json_string("id"));
    }

    if (json_object_get(msg, "blobId")) {
        json_array_append_new(invalid, json_string("blobId"));
    }

    if (json_object_get(msg, "threadId")) {
        json_array_append_new(invalid, json_string("threadId"));
    }

    prop = json_object_get(msg, "inReplyToMessageId");
    if (JNOTNULL(prop)) {
        if (!((sval = json_string_value(prop)) && strlen(sval))) {
            json_array_append_new(invalid, json_string("inReplyToMessageId"));
        }
    }

    pe = readprop(msg, "isUnread", 0, invalid, "b", &bval);
    if (pe > 0 && bval) {
        json_array_append_new(invalid, json_string("isUnread"));
    }

    readprop(msg, "isFlagged", 0, invalid, "b", &bval);

    pe = readprop(msg, "isAnswered", 0, invalid, "b", &bval);
    if (pe > 0 && bval) {
        json_array_append_new(invalid, json_string("isAnswered"));
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
            /* Validate mail addresses in overriden header */
            int ismailheader = (!strcasecmp(key, "From") ||
                                !strcasecmp(key, "Reply-To") ||
                                !strcasecmp(key, "Cc") ||
                                !strcasecmp(key, "Bcc") ||
                                !strcasecmp(key, "To"));
            if (valid && ismailheader && validateaddr) {
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
    } else if (prop && json_typeof(prop) != JSON_ARRAY) {
        json_array_append_new(invalid, json_string("headers"));
    }

    prop = json_object_get(msg, "from");
    if (json_array_size(prop)) {
        json_t *emailer;
        size_t i;
        json_array_foreach(prop, i, emailer) {
            buf_printf(&buf, "from[%zu]", i);
            jmap_validate_emailer(emailer, buf_cstring(&buf), validateaddr, invalid);
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
            jmap_validate_emailer(emailer, buf_cstring(&buf), validateaddr, invalid);
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
            jmap_validate_emailer(emailer, buf_cstring(&buf), validateaddr, invalid);
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
            jmap_validate_emailer(emailer, buf_cstring(&buf), validateaddr, invalid);
            buf_reset(&buf);
        }
    } else if (JNOTNULL(prop) && json_typeof(prop) != JSON_ARRAY) {
        json_array_append_new(invalid, json_string("bcc"));
    }

    prop = json_object_get(msg, "sender");
    if (JNOTNULL(prop)) {
        jmap_validate_emailer(prop, "sender", validateaddr, invalid);
    }

    prop = json_object_get(msg, "replyTo");
    if (json_array_size(prop)) {
        json_t *emailer;
        size_t i;
        json_array_foreach(prop, i, emailer) {
            buf_printf(&buf, "replyTo[%zu]", i);
            jmap_validate_emailer(emailer, buf_cstring(&buf), validateaddr, invalid);
            buf_reset(&buf);
        }
    } else if (JNOTNULL(prop) && json_typeof(prop) != JSON_ARRAY) {
        json_array_append_new(invalid, json_string("replyTo"));
    }

    pe = readprop(msg, "date", 0, invalid, "s", &sval);
    if (pe > 0) {
        const char *p = strptime(sval, "%Y-%m-%dT%H:%M:%SZ", date);
        if (!p || *p) {
            json_array_append_new(invalid, json_string("date"));
        }
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

    if ((prop = json_object_get(msg, "attachedMessages"))) {
        json_t *submsg;
        const char *subid;
        json_object_foreach(prop, subid, submsg) {
            json_t *subinvalid = json_pack("[]");
            json_t *errprop;
            size_t j;

            jmapmsg_validate(submsg, subinvalid, 0);

            buf_printf(&buf, "attachedMessages[%s]", subid);
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
    prop = json_object_get(msg, "attachments");
    if (json_array_size(prop)) {
        /* XXX validate */
    }

    buf_free(&buf);
    if (mboxname) free(mboxname);
    if (mboxrole) free(mboxrole);
    if (date) free(date);
}

static int copyrecord(jmap_req_t *req, struct mailbox *src, struct mailbox *dst,
                      struct index_record *record)
{
    struct appendstate as;
    int r;
    int nolink = !config_getswitch(IMAPOPT_SINGLEINSTANCESTORE);

    if (!strcmp(src->uniqueid, dst->uniqueid))
        return 0;

    r = append_setup_mbox(&as, dst, req->userid, httpd_authstate,
            ACL_INSERT, NULL, &jmap_namespace, 0, EVENT_MESSAGE_COPY);
    if (r) goto done;

    r = append_copy(src, &as, 1, record, nolink,
            mboxname_same_userid(src->name, dst->name));
    if (r) {
        append_abort(&as);
        goto done;
    }

    r = append_commit(&as);
    if (r) goto done;

    sync_log_mailbox_double(src->name, dst->name);
done:
    return r;
}

static int updaterecord(struct index_record *record,
                        int flagged, int unread, int answered)
{
    if (flagged > 0)
        record->system_flags |= FLAG_FLAGGED;
    else if (!flagged)
        record->system_flags &= ~FLAG_FLAGGED;

    if (unread > 0)
        record->system_flags &= ~FLAG_SEEN;
    else if (!unread)
        record->system_flags |= FLAG_SEEN;

    if (answered > 0)
        record->system_flags |= FLAG_ANSWERED;
    else if (!answered)
        record->system_flags &= ~FLAG_ANSWERED;

    return 0;
}

struct updaterecord_data {
    jmap_req_t *req;
    json_t *mailboxes;
    int flagged;
    int unread;
    int answered;
};

static int updaterecord_cb(const conv_guidrec_t *rec, void *rock)
{
    struct updaterecord_data *d = (struct updaterecord_data *) rock;
    jmap_req_t *req = d->req;
    struct mailbox *mbox = NULL;
    int r = 0;

    r = _openmbox(req, rec->mboxname, &mbox, 1);
    if (r) goto done;

    if (!d->mailboxes || json_object_get(d->mailboxes, mbox->uniqueid)) {
        struct index_record record;

        r = mailbox_find_index_record(mbox, rec->uid, &record);
        if (r) goto done;

        r = updaterecord(&record, d->flagged, d->unread, d->answered);
        if (r) goto done;

        r = mailbox_rewrite_index_record(mbox, &record);
        if (r) goto done;
    }

done:
    if (mbox) _closembox(req, &mbox);
    return r;
}

static int delrecord(jmap_req_t *req, struct mailbox *mbox, uint32_t uid)
{
    int r;
    struct index_record record;
    struct mboxevent *mboxevent = NULL;

    r = mailbox_find_index_record(mbox, uid, &record);
    if (r) return r;

    if (record.system_flags & FLAG_EXPUNGED)
        return 0;

    /* Expunge index record */
    record.system_flags |= FLAG_DELETED | FLAG_EXPUNGED;

    r = mailbox_rewrite_index_record(mbox, &record);
    if (r) return r;

    /* Report mailbox event. */
    mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);
    mboxevent_extract_record(mboxevent, mbox, &record);
    mboxevent_extract_mailbox(mboxevent, mbox);
    mboxevent_set_numunseen(mboxevent, mbox, -1);
    mboxevent_set_access(mboxevent, NULL, NULL, req->userid, mbox->name, 0);
    mboxevent_notify(mboxevent);
    mboxevent_free(&mboxevent);

    return 0;
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

    r = _openmbox(req, rec->mboxname, &mbox, 1);
    if (r) goto done;

    if (!d->mailboxes || json_object_get(d->mailboxes, mbox->uniqueid)) {
        r = delrecord(d->req, mbox, rec->uid);
        if (!r) d->deleted++;
    }

done:
    if (mbox) _closembox(req, &mbox);
    return r;
}

static int jmapmsg_create(jmap_req_t *req, json_t *msg, char **uid,
                          json_t *invalid)
{

    FILE *f = NULL;
    char *mboxname = NULL;
    char *mboxrole = NULL;
    const char *id;
    struct stagemsg *stage = NULL;
    time_t now = time(NULL);
    struct body *body = NULL;
    struct appendstate as;
    struct mailbox *mbox = NULL;
    struct index_record record;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    json_t *val, *mailboxes;
    size_t i;
    int isdraft = 0, isflagged = 0;

    int r = HTTP_SERVER_ERROR;

    /* Pick the mailbox to create the message in, prefer Drafts */
    mailboxes = json_pack("{}"); /* maps mailbox ids to mboxnames */
    json_array_foreach(json_object_get(msg, "mailboxIds"), i, val) {
        char *name = NULL;
        char *role = NULL;

        id = json_string_value(val);
        if (id && *id == '#') {
            id = hash_lookup(id, req->idmap);
        }
        if (id) {
            name = mboxlist_find_uniqueid(id, req->userid);
            if ((role = jmapmbox_role(req, name))) {
                if (!strcmp(role, "drafts")) {
                    if (mboxname) {
                        free(mboxname);
                    }
                    if (mboxrole) {
                        free(mboxrole);
                    }
                    mboxname = xstrdup(name);
                    mboxrole = xstrdup(role);
                    isdraft = 1;
                }
                if (!strcmp(role, "outbox") && !mboxname) {
                    mboxname = xstrdup(name);
                    mboxrole = xstrdup(role);
                }
            }
        }
        if (!id) {
            struct buf buf = BUF_INITIALIZER;
            buf_printf(&buf, "mailboxIds[%zu]", i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_free(&buf);
        } else {
            json_object_set_new(mailboxes, id, json_string(name));
        }
        if (name) free(name);
        if (role) free(role);
    }
    if (!mboxname) {
        json_array_append_new(invalid, json_string("mailboxIds"));
    }
    jmapmsg_validate(msg, invalid, isdraft);
    if (json_array_size(invalid)) {
        return 0;
    }

    /* Create the message in the destination mailbox */
    isflagged = json_object_get(msg, "isFlagged") == json_true();
    r = _openmbox(req, mboxname, &mbox, 1);
    if (r) goto done;

    /* Write the message to the filesystem */
    if (!(f = append_newstage(mbox->name, now, 0, &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mbox->name);
        r = HTTP_SERVER_ERROR;
        goto done;
    }
    r = jmapmsg_write(req, msg, f);
    qdiffs[QUOTA_STORAGE] = ftell(f);
    fclose(f);
    if (r) {
        append_removestage(stage);
        goto done;
    }
    qdiffs[QUOTA_MESSAGE] = 1;

    /* Append the message to the mailbox */
    r = append_setup_mbox(&as, mbox, req->userid, httpd_authstate,
            0, qdiffs, 0, 0, EVENT_MESSAGE_NEW);
    if (r) goto done;
    r = append_fromstage(&as, &body, stage, now, NULL, 0, NULL);
    if (body) {
        *uid = xstrdup(message_guid_encode(&body->guid));
        message_free_body(body);
        free(body);
    }
    if (r) {
        append_abort(&as);
        goto done;
    }
    r = append_commit(&as);
    if (r) goto done;

    /* Read index record for new message */
    memset(&record, 0, sizeof(struct index_record));
    record.recno = mbox->i.num_records;
    record.uid = mbox->i.last_uid;
    r = mailbox_reload_index_record(mbox, &record);
    if (r) goto done;

    /* Save record */
    if (isdraft) record.system_flags |= FLAG_DRAFT;
    if (isflagged) record.system_flags |= FLAG_FLAGGED;
    r = mailbox_rewrite_index_record(mbox, &record);
    if (r) goto done;

    /* Complete message creation */
    if (stage) {
        append_removestage(stage);
        stage = NULL;
    }

    /* Copy the message to all other mailbox ids */
    json_object_del(mailboxes, mbox->uniqueid);
    json_object_foreach(mailboxes, id, val) {
        const char *dstname = json_string_value(val);
        struct mailbox *dst = NULL;

        if (!strcmp(mboxname, dstname))
            continue;

        r = _openmbox(req, dstname, &dst, 1);
        if (r) goto done;

        r = copyrecord(req, mbox, dst, &record);

        _closembox(req, &dst);
        if (r) goto done;
    }

done:
    if (stage) append_removestage(stage);
    if (mbox) _closembox(req, &mbox);
    if (mboxname) free(mboxname);
    if (mboxrole) free(mboxrole);
    json_decref(mailboxes);
    return r;
}

static int jmapmsg_update(jmap_req_t *req, const char *msgid, json_t *msg,
                          json_t *invalid)
{
    uint32_t uid;
    struct mailbox *mbox = NULL;
    char *mboxname = NULL;
    const char *id;
    struct index_record record;
    int unread = -1, flagged = -1, answered = -1;
    int r;
    size_t i;
    json_t *val;
    json_t *dstmailboxes = NULL; /* destination mailboxes */
    json_t *srcmailboxes = NULL; /* current mailboxes */
    json_t *oldmailboxes = NULL; /* current mailboxes that are kept */
    json_t *newmailboxes = NULL; /* mailboxes to add the message to */
    json_t *delmailboxes = NULL; /* mailboxes to remote the mesage from */

    if (!strlen(msgid) || *msgid == '#') {
        return IMAP_NOTFOUND;
    }

    /* Pick record from any current mailbox. That's the master copy. */
    r = jmapmsg_find(req, msgid, &mboxname, &uid);
    if (r) return r;
    srcmailboxes = jmapmsg_mailboxes(req, msgid);

    /* Validate properties */
    if (json_object_get(msg, "isFlagged")) {
        readprop(msg, "isFlagged", 1, invalid, "b", &flagged);
    }
    if (json_object_get(msg, "isUnread")) {
        readprop(msg, "isUnread", 1, invalid, "b", &unread);
    }
    if (json_object_get(msg, "isAnswered")) {
        readprop(msg, "isAnswered", 1, invalid, "b", &answered);
    }
    dstmailboxes = json_pack("{}");
    json_array_foreach(json_object_get(msg, "mailboxIds"), i, val) {
        char *name = NULL;
        id = json_string_value(val);
        if (id && *id == '#') {
            id = hash_lookup(id, req->idmap);
        }
        if (id && (name = mboxlist_find_uniqueid(id, req->userid))) {
            json_object_set_new(dstmailboxes, id, json_string(name));
            free(name);
        } else {
            struct buf buf = BUF_INITIALIZER;
            buf_printf(&buf, "mailboxIds[%zu]", i);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_free(&buf);
        }
    }
    if (!json_object_size(dstmailboxes)) {
        json_array_append_new(invalid, json_string("mailboxIds"));
    }
    if (json_array_size(invalid)) {
        return 0;
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
    if (json_object_size(newmailboxes)) {
        char foundroot[MAX_MAILBOX_BUFFER];
        json_t *deltas = json_pack("{}");
        const char *mbname;

        /* Find the quota delta for each quota root */
        json_object_foreach(newmailboxes, id, val) {
            mbname = json_string_value(val);
            if (quota_findroot(foundroot, sizeof(foundroot), mbname)) {
                json_t *delta = json_object_get(deltas, mbname);
                delta = json_integer(json_integer_value(delta) + 1);
                json_object_set_new(deltas, mbname, delta);
            }
        }

        /* FIXME deduct quota for deleted messages? */

        /* Check quota for each quota root. */
        json_object_foreach(deltas, mbname, val) {
            struct quota quota;
            quota_t delta = json_integer_value(val);

            quota_init(&quota, mbname);
            r = quota_check(&quota, QUOTA_MESSAGE, delta);
            quota_free(&quota);
            if (r) break;
        }
        json_decref(deltas);
        if (r) goto done;
    }

    /* Update index record system flags. */
    r = _openmbox(req, mboxname, &mbox, 1);
    if (r) goto done;

    r = mailbox_find_index_record(mbox, uid, &record);
    if (r) goto done;

    r = updaterecord(&record, flagged, unread, answered);
    if (r) goto done;

    r = mailbox_rewrite_index_record(mbox, &record);
    if (r) goto done;

    /* Update record in kept mailboxes, except its master copy. */
    json_object_del(oldmailboxes, mbox->uniqueid);
    if (json_object_size(oldmailboxes)) {
        struct conversations_state *cstate;
        struct updaterecord_data data = {
            req, oldmailboxes, flagged, unread, answered
        };

        if ((cstate = mailbox_get_cstate(req->inbox))) {
            r = conversations_guid_foreach(cstate, msgid, updaterecord_cb, &data);
            if (r) goto done;
        }
    }

    /* Copy master copy to new mailboxes */
    json_object_foreach(newmailboxes, id, val) {
        const char *dstname = json_string_value(val);
        struct mailbox *dst = NULL;

        if (!strcmp(mboxname, dstname))
            continue;

        r = _openmbox(req, dstname, &dst, 1);
        if (r) goto done;

        r = copyrecord(req, mbox, dst, &record);

        _closembox(req, &dst);
        if (r) goto done;
    }

    /* Remove message from mailboxes */
    if (json_object_size(delmailboxes)) {
        struct conversations_state *cstate;
        struct delrecord_data data = { req, 0, delmailboxes };

        if ((cstate = mailbox_get_cstate(req->inbox))) {
            r = conversations_guid_foreach(cstate, msgid, delrecord_cb, &data);
            if (r) goto done;
        }
    }

done:
    if (mbox) _closembox(req, &mbox);
    if (mboxname) free(mboxname);
    if (srcmailboxes) json_decref(srcmailboxes);
    if (dstmailboxes) json_decref(dstmailboxes);
    if (newmailboxes) json_decref(newmailboxes);
    if (delmailboxes) json_decref(delmailboxes);

    if (r) syslog(LOG_ERR, "jmapmsg_update: %s", error_message(r));
    return r;
}

static int jmapmsg_delete(jmap_req_t *req, const char *id)
{
    int r;
    struct conversations_state *cstate;
    struct delrecord_data data = { req, 0, NULL };

    if (!strlen(id) || *id == '#')
        return IMAP_NOTFOUND;

    if (!(cstate = mailbox_get_cstate(req->inbox)))
        return IMAP_NOTFOUND;

    r = conversations_guid_foreach(cstate, id, delrecord_cb, &data);
    if (r) return r;

    return data.deleted ? 0 : IMAP_NOTFOUND;
}

static int setMessages(jmap_req_t *req)
{
    int r = 0;
    json_t *set = NULL;

    _initreq(req);

    json_t *state = json_object_get(req->args, "ifInState");
    if (state && jmap_checkstate(state, 0 /*MBTYPE*/, req)) {
        json_array_append_new(req->response, json_pack("[s, {s:s}, s]",
                    "error", "type", "stateMismatch", req->tag));
        goto done;
    }
    set = json_pack("{s:s}", "accountId", req->userid);
    json_object_set_new(set, "oldState", state);

    json_t *create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");
        const char *key;
        json_t *msg;

        json_object_foreach(create, key, msg) {
            json_t *invalid = json_pack("[]");
            char *id = NULL;
            json_t *err = NULL;

            if (!strlen(key)) {
                err = json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notCreated, key, err);
                continue;
            }

            r = jmapmsg_create(req, msg, &id, invalid);
            if (r == IMAP_QUOTA_EXCEEDED) {
                err = json_pack("{s:s}", "type", "maxQuotaReached");
                json_object_set_new(notCreated, key, err);
                continue;
            } else if (r) {
                goto done;
            }
            if (json_array_size(invalid)) {
                err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notCreated, key, err);
                continue;
            }
            json_decref(invalid);
            if (err) {
                json_object_set_new(notCreated, key, err);
                json_decref(invalid);
                continue;
            }

            json_object_set_new(created, key, json_pack("{s:s}", "id", id));
            hash_insert(key, id, req->idmap);
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

    json_t *update = json_object_get(req->args, "update");
    if (update) {
        json_t *updated = json_pack("[]");
        json_t *notUpdated = json_pack("{}");
        const char *id;
        json_t *msg;

        json_object_foreach(update, id, msg) {
            json_t *invalid = json_pack("[]");
            if ((r = jmapmsg_update(req, id, msg, invalid))) {
                json_decref(invalid);
                if (r == IMAP_NOTFOUND) {
                    json_t *err= json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notUpdated, id, err);
                    r = 0;
                    continue;
                } else {
                    goto done;
                }
            }
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notUpdated, id, err);
                continue;
            }
            json_array_append_new(updated, json_string(id));
        }

        if (json_array_size(updated)) {
            json_object_set(set, "updated", updated);
        }
        json_decref(updated);

        if (json_object_size(notUpdated)) {
            json_object_set(set, "notUpdated", notUpdated);
        }
        json_decref(notUpdated);
    }

    json_t *destroy = json_object_get(req->args, "destroy");
    if (destroy) {
        json_t *destroyed = json_pack("[]");
        json_t *notDestroyed = json_pack("{}");
        json_t *msgid;
        size_t i;

        json_array_foreach(destroy, i, msgid) {
            const char *id = json_string_value(msgid);
            if ((r = jmapmsg_delete(req, id))) {
                if (r == IMAP_NOTFOUND) {
                    json_t *err = json_pack("{s:s}", "type", "notFound");
                    json_object_set_new(notDestroyed, id, err);
                    r = 0;
                    continue;
                } else {
                    goto done;
                }
            }
            json_array_append_new(destroyed, json_string(id));
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

    /* Bump mailbox state for any changes */
    if (json_object_get(set, "created") ||
        json_object_get(set, "updated") ||
        json_object_get(set, "destroyed")) {

        r = jmap_bumpstate(0 /*MBTYPE*/, req);
        if (r) goto done;
    }
    json_object_set_new(set, "newState", jmap_getstate(0 /*MBTYPE*/, req));

    json_incref(set);
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("messagesSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (set) json_decref(set);
    _finireq(req);
    return r;
}
