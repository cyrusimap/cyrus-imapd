/* http_jmap.c -- Routines for handling JMAP requests in httpd
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
#include "caldav_db.h"
#include "carddav_db.h"
#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "http_caldav.h"
#include "http_carddav.h"
#include "http_caldav_sched.h"
#include "http_dav.h"
#include "http_proxy.h"
#include "ical_support.h"
#include "json_support.h"
#include "imap_err.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "parseaddr.h"
#include "seen.h"
#include "statuscache.h"
#include "stristr.h"
#include "times.h"
#include "util.h"
#include "vcard_support.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "zoneinfo_db.h"

#include "jmapical.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

struct jmap_req {
    const char *userid;
    const struct mailbox *inbox;
    struct auth_state *authstate;
    struct hash_table *idmap;
    json_t *args;
    json_t *response;
    struct mboxname_counters counters;
    const char *tag;
    struct transaction_t *txn;
};

struct namespace jmap_namespace;

static time_t compile_time;
static void jmap_init(struct buf *serverinfo);
static void jmap_auth(const char *userid);
static int jmap_get(struct transaction_t *txn, void *params);
static int jmap_post(struct transaction_t *txn, void *params);

/* JMAP methods. */
static int getMailboxes(struct jmap_req *req);
static int setMailboxes(struct jmap_req *req);
static int getMessageList(struct jmap_req *req);
static int getMessages(struct jmap_req *req);
static int setMessages(struct jmap_req *req);
static int getContactGroups(struct jmap_req *req);
static int getContactGroupUpdates(struct jmap_req *req);
static int setContactGroups(struct jmap_req *req);
static int getContacts(struct jmap_req *req);
static int getContactUpdates(struct jmap_req *req);
static int getContactList(struct jmap_req *req);
static int setContacts(struct jmap_req *req);

static int getCalendars(struct jmap_req *req);
static int getCalendarUpdates(struct jmap_req *req);
static int setCalendars(struct jmap_req *req);
static int getCalendarEvents(struct jmap_req *req);
static int getCalendarEventUpdates(struct jmap_req *req);
static int getCalendarEventList(struct jmap_req *req);
static int setCalendarEvents(struct jmap_req *req);

/* JMAP methods not defined in the spec. */
static int getCalendarPreferences(struct jmap_req *req);
static int getPersonalities(struct jmap_req *req);
static int getPreferences(struct jmap_req *req);

/* Helper functions for state management. */
static json_t* jmap_getstate(int mbtype, struct jmap_req *req);
static int jmap_bumpstate(int mbtype, struct jmap_req *req);
static int jmap_checkstate(json_t *state, int mbtype, struct jmap_req *req);

/* Helper functions for property parsing. */
static int readprop_full(json_t *root, const char *prefix,
                         const char *name, int mandatory,
                         json_t *invalid, const char *fmt, void *dst);
static int _wantprop(hash_table *props, const char *name);

static const struct message_t {
    const char *name;
    int (*proc)(struct jmap_req *req);
} messages[] = {
    { "getMailboxes",           &getMailboxes },
    { "setMailboxes",           &setMailboxes },
    { "getMessageList",         &getMessageList },
    { "getMessages",            &getMessages },
    { "setMessages",            &setMessages },
    { "getContactGroups",       &getContactGroups },
    { "getContactGroupUpdates", &getContactGroupUpdates },
    { "setContactGroups",       &setContactGroups },
    { "getContacts",            &getContacts },
    { "getContactUpdates",      &getContactUpdates },
    { "getContactList",         &getContactList },
    { "setContacts",            &setContacts },
    { "getCalendars",           &getCalendars },
    { "getCalendarUpdates",     &getCalendarUpdates },
    { "setCalendars",           &setCalendars },
    { "getCalendarEvents",      &getCalendarEvents },
    { "getCalendarEventUpdates",&getCalendarEventUpdates },
    { "getCalendarEventList",   &getCalendarEventList },
    { "setCalendarEvents",      &setCalendarEvents },
    { "getCalendarPreferences", &getCalendarPreferences },
    { "getPersonalities",       &getPersonalities },
    { "getPreferences",         &getPreferences },
    { NULL,             NULL}
};


/* Namespace for JMAP */
struct namespace_t namespace_jmap = {
    URL_NS_JMAP, 0, "/jmap", "/.well-known/jmap", 1 /* auth */,
    /*mbtype*/0, 
    (ALLOW_READ | ALLOW_POST),
    &jmap_init, &jmap_auth, NULL, NULL, NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
        { &jmap_get,            NULL },                 /* GET          */
        { &jmap_get,            NULL },                 /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { &meth_options,        NULL },                 /* OPTIONS      */
        { NULL,                 NULL },                 /* PATCH        */
        { &jmap_post,           NULL },                 /* POST         */
        { NULL,                 NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { &meth_trace,          NULL },                 /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { NULL,                 NULL }                  /* UNLOCK       */
    }
};

static void jmap_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_jmap.enabled =
        config_httpmodules & IMAP_ENUM_HTTPMODULES_JMAP;

    if (!namespace_jmap.enabled) return;

    compile_time = calc_compile_time(__TIME__, __DATE__);
}


static void jmap_auth(const char *userid __attribute__((unused)))
{
    /* Set namespace */
    mboxname_init_namespace(&jmap_namespace,
                            httpd_userisadmin || httpd_userisproxyadmin);
}


/* Perform a GET/HEAD request */
static int jmap_get(struct transaction_t *txn __attribute__((unused)),
                     void *params __attribute__((unused)))
{
    return HTTP_NO_CONTENT;
}

/* Perform a POST request */
static int jmap_post(struct transaction_t *txn,
                     void *params __attribute__((unused)))
{
    const char **hdr;
    json_t *req, *resp = NULL;
    json_error_t jerr;
    const struct message_t *mp = NULL;
    struct mailbox *mailbox = NULL;
    struct hash_table idmap;
    size_t i, flags = JSON_PRESERVE_ORDER;
    int ret;
    char *buf, *inboxname = NULL;

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    ret = http_read_body(httpd_in, httpd_out,
                       txn->req_hdrs, &txn->req_body, &txn->error.desc);

    if (ret) {
        txn->flags.conn = CONN_CLOSE;
        return ret;
    }

    if (!buf_len(&txn->req_body.payload)) return HTTP_BAD_REQUEST;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
        !is_mediatype("application/json", hdr[0])) {
        txn->error.desc = "This method requires a JSON request body\r\n";
        return HTTP_BAD_MEDIATYPE;
    }

    /* Allocate map to store uids */
    construct_hash_table(&idmap, 1024, 0);

    /* Parse the JSON request */
    req = json_loads(buf_cstring(&txn->req_body.payload), 0, &jerr);
    if (!req || !json_is_array(req)) {
        txn->error.desc = "Unable to parse JSON request body\r\n";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Start JSON response */
    resp = json_array();
    if (!resp) {
        txn->error.desc = "Unable to create JSON response body\r\n";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    inboxname = mboxname_user_mbox(httpd_userid, NULL);

    /* we lock the user's INBOX before we start any operation, because that way we
     * guarantee (via conversations magic) that nothing changes the modseqs except
     * our operations */
    int r = mailbox_open_iwl(inboxname, &mailbox);
    if (r) {
        txn->error.desc = error_message(r);
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Process each message in the request */
    for (i = 0; i < json_array_size(req); i++) {
        json_t *msg = json_array_get(req, i);
        const char *name = json_string_value(json_array_get(msg, 0));
        json_t *args = json_array_get(msg, 1);
        json_t *id = json_array_get(msg, 2);
        /* XXX - better error reporting */
        if (!id) {
            txn->error.desc = "Missing id on request\n";
            ret = HTTP_BAD_REQUEST;
            goto done;
        }
        const char *tag = json_string_value(id);
        int r = 0;

        /* Find the message processor */
        for (mp = messages; mp->name && strcmp(name, mp->name); mp++);

        if (!mp || !mp->name) {
            json_array_append(resp, json_pack("[s {s:s} s]", "error", "type", "unknownMethod", tag));
            continue;
        }

        struct jmap_req req;
        req.userid = httpd_userid;
        req.inbox = mailbox;
        req.authstate = httpd_authstate;
        req.args = args;
        req.response = resp;
        req.tag = tag;
        req.idmap = &idmap;
        req.txn = txn;

        /* Read the modseq counters again, just in case something changed. */
        r = mboxname_read_counters(inboxname, &req.counters);
        if (r) goto done;

        /* Call the message processor. */
        r = mp->proc(&req);

        if (r) {
            txn->error.desc = error_message(r);
            ret = HTTP_SERVER_ERROR;
            goto done;
        }
    }

    /* unlock here so that we don't block on writing */
    mailbox_unlock_index(mailbox, NULL);

    /* Dump JSON object into a text buffer */
    flags |= (config_httpprettytelemetry ? JSON_INDENT(2) : JSON_COMPACT);
    buf = json_dumps(resp, flags);

    if (!buf) {
        txn->error.desc = "Error dumping JSON response object";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Output the JSON object */
    txn->resp_body.type = "application/json; charset=utf-8";
    write_body(HTTP_OK, txn, buf, strlen(buf));
    free(buf);

  done:
    free_hash_table(&idmap, free);
    mailbox_close(&mailbox);
    free(inboxname);
    if (req) json_decref(req);
    if (resp) json_decref(resp);

    return ret;
}

/* JMAP filters */
enum jmap_filter_kind {
    JMAP_FILTER_KIND_COND = 0,
    JMAP_FILTER_KIND_OPER
};
enum jmap_filter_op   {
    JMAP_FILTER_OP_NONE = 0,
    JMAP_FILTER_OP_AND,
    JMAP_FILTER_OP_OR,
    JMAP_FILTER_OP_NOT
};

typedef struct jmap_filter {
    enum jmap_filter_kind kind;
    enum jmap_filter_op op;

    struct jmap_filter **conditions;
    size_t n_conditions;

    void *cond;
} jmap_filter;

/* Callback to parse the filter condition arg. Append invalid arguments
 * by name into invalid, prefixed by prefix. Return the filter condition. */
typedef void* jmap_filterparse_cb(json_t* arg, const char* prefix, json_t*invalid);

/* Callback to match the condition cond to argument rock. Return true if
 * it matches. */
typedef int   jmap_filtermatch_cb(void* cond, void* rock);

/* Callback to free the memory of condition cond. */
typedef void  jmap_filterfree_cb(void* cond);

/* Match the JMAP filter f against rock according to the data-type specific
 * matcher match. Return true if it matches. */
static int jmap_filter_match(jmap_filter *f, jmap_filtermatch_cb *match, void *rock)
{
    if (f->kind == JMAP_FILTER_KIND_OPER) {
        size_t i;
        for (i = 0; i < f->n_conditions; i++) {
            int m = jmap_filter_match(f->conditions[i], match, rock);
            if (m && f->op == JMAP_FILTER_OP_OR) {
                return 1;
            } else if (m && f->op == JMAP_FILTER_OP_NOT) {
                return 0;
            } else if (!m && f->op == JMAP_FILTER_OP_AND) {
                return 0;
            }
        }
        return f->op == JMAP_FILTER_OP_AND || f->op == JMAP_FILTER_OP_NOT;
    } else {
        return match(f->cond, rock);
    }
}

/* Free the JMAP filter f. Call freecond to deallocate conditions. */
static void jmap_filter_free(jmap_filter *f, jmap_filterfree_cb *freecond)
{
    size_t i;
    for (i = 0; i < f->n_conditions; i++) {
        jmap_filter_free(f->conditions[i], freecond);
    }
    if (f->conditions) free(f->conditions);
    if (f->cond && freecond) {
        freecond(f->cond);
    }
    free(f);
}

static int JNOTNULL(json_t *item)
{
   if (!item) return 0;
   if (json_is_null(item)) return 0;
   return 1;
}

/* Parse the JMAP filter arg. Report any invalid filter arguments in invalid,
 * prefixed by prefix. */
static jmap_filter *jmap_filter_parse(json_t *arg,
                                      const char *prefix,
                                      json_t *invalid,
                                      jmap_filterparse_cb *parse)
{
    jmap_filter *f = (jmap_filter *) xzmalloc(sizeof(struct jmap_filter));
    int pe;
    const char *val;
    struct buf buf = BUF_INITIALIZER;
    int iscond = 1;

    /* operator */
    pe = readprop_full(arg, prefix, "operator", 0 /*mandatory*/, invalid, "s", &val);
    if (pe > 0) {
        f->kind = JMAP_FILTER_KIND_OPER;
        if (!strncmp("AND", val, 3)) {
            f->op = JMAP_FILTER_OP_AND;
        } else if (!strncmp("OR", val, 2)) {
            f->op = JMAP_FILTER_OP_OR;
        } else if (!strncmp("NOT", val, 3)) {
            f->op = JMAP_FILTER_OP_NOT;
        } else {
            buf_printf(&buf, "%s.%s", prefix, "operator");
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
    }
    iscond = f->kind == JMAP_FILTER_KIND_COND;

    /* conditions */
    json_t *conds = json_object_get(arg, "conditions");
    if (conds && !iscond && json_array_size(conds)) {
        f->n_conditions = json_array_size(conds);
        f->conditions = xmalloc(sizeof(struct jmap_filter) * f->n_conditions);
        size_t i;
        for (i = 0; i < f->n_conditions; i++) {
            json_t *cond = json_array_get(conds, i);
            buf_printf(&buf, "%s.conditions[%zu]", prefix, i);
            f->conditions[i] = jmap_filter_parse(cond, buf_cstring(&buf), invalid, parse);
            buf_reset(&buf);
        }
    } else if (JNOTNULL(conds)) {
        buf_printf(&buf, "%s.%s", prefix, "conditions");
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    /* Only parse the remainer of arg if it is known not to be an operator. */
    if (iscond) {
        f->cond = parse(arg, prefix, invalid);
    }

    buf_free(&buf);
    return f;
}

/* Return true if needle is found in haystack */
static int jmap_match_text(const char *haystack, const char *needle) {
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
        return jmap_match_text(json_string_value(val), text);
    } else {
        const char *key;
        json_t *val;
        int m = 0;
        size_t i;
        json_t *entry;

        json_object_foreach(arg, key, val) {
            switch json_typeof(val) {
                case JSON_STRING:
                    m = jmap_match_text(json_string_value(val), text);
                    break;
                case JSON_OBJECT:
                    m = jmap_match_jsonprop(val, NULL, text);
                    break;
                case JSON_ARRAY:
                    json_array_foreach(val, i, entry) {
                        switch json_typeof(entry) {
                            case JSON_STRING:
                                m = jmap_match_text(json_string_value(entry), text);
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

/* Check if state matches the current mailbox state for mailbox type
 * mbtype. Return zero if states match. */
static int jmap_checkstate(json_t *state, int mbtype, struct jmap_req *req) {
    if (JNOTNULL(state)) {
        const char *s = json_string_value(state);
        if (!s) {
            return -1;
        }
        modseq_t clientState = atomodseq_t(s);
        switch (mbtype) {
         case MBTYPE_CALENDAR:
             return clientState != req->counters.caldavmodseq;
         case MBTYPE_ADDRESSBOOK:
             return clientState != req->counters.carddavmodseq;
         default:
             return clientState != req->counters.mailmodseq;
        }
    }
    return 0;
}

/* Create a state token for the JMAP type mbtype in response res. */
static json_t* jmap_getstate(int mbtype, struct jmap_req *req) {
    struct buf buf = BUF_INITIALIZER;
    json_t *state = NULL;
    modseq_t modseq;

    /* Determine current counter by mailbox type. */
    switch (mbtype) {
        case MBTYPE_CALENDAR:
            modseq = req->counters.caldavmodseq;
            break;
        case MBTYPE_ADDRESSBOOK:
            modseq = req->counters.carddavmodseq;
            break;
        default:
            modseq = req->counters.highestmodseq;
    }

    buf_printf(&buf, MODSEQ_FMT, modseq);
    state = json_string(buf_cstring(&buf));
    buf_free(&buf);

    return state;
}

/* Bump the state for mailboxes of type mbtype. Return 0 on success. */
static int jmap_bumpstate(int mbtype, struct jmap_req *req) {
    int r = 0;
    modseq_t modseq;
    char *mboxname = mboxname_user_mbox(req->userid, NULL);

    /* Read counters. */
    r = mboxname_read_counters(mboxname, &req->counters);
    if (r) goto done;

    /* Determine current counter by mailbox type. */
    switch (mbtype) {
        case MBTYPE_CALENDAR:
            modseq = req->counters.caldavmodseq;
            break;
        case MBTYPE_ADDRESSBOOK:
            modseq = req->counters.carddavmodseq;
            break;
        default:
            modseq = req->counters.highestmodseq;
    }

    /* Bump current counter... */
    modseq = mboxname_nextmodseq(mboxname, modseq, mbtype, 1 /*dofolder*/);

    /* ...and update counters. */
    r = mboxname_read_counters(mboxname, &req->counters);
    if (r) goto done;

done:
    free(mboxname);
    return r;
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


static void _add_xhref(json_t *obj, const char *mboxname, const char *resource)
{
    /* XXX - look up root path from namespace? */
    struct buf buf = BUF_INITIALIZER;
    char *userid = mboxname_to_userid(mboxname);

    const char *prefix = NULL;
    if (mboxname_isaddressbookmailbox(mboxname, 0)) {
        prefix = namespace_addressbook.prefix;
    }
    else if (mboxname_iscalendarmailbox(mboxname, 0)) {
        prefix = namespace_calendar.prefix;
    }

    if (strchr(userid, '@') || !httpd_extradomain) {
        buf_printf(&buf, "%s/%s/%s/%s", prefix, USER_COLLECTION_PREFIX,
                   userid, strrchr(mboxname, '.')+1);
    }
    else {
        buf_printf(&buf, "%s/%s/%s@%s/%s", prefix, USER_COLLECTION_PREFIX,
                   userid, httpd_extradomain, strrchr(mboxname, '.')+1);
    }
    if (resource)
        buf_printf(&buf, "/%s", resource);

    json_object_set_new(obj, "x-href", json_string(buf_cstring(&buf)));
    free(userid);
    buf_free(&buf);
}


/*****************************************************************************
 * JMAP Mailboxes API
 ****************************************************************************/

struct getMailboxes_rock {
    const struct mailbox *inbox; /* The main user inbox. Do not unlock or close. */
    json_t *list;                /* List of the current http user mailboxes. */
    hash_table *props;           /* Which properties to fetch. */
    hash_table *roles;           /* Roles that were already reported for another
                                    mailbox during this getMailboxes request. */
    hash_table *ids;             /* The ids of folders seen so far */
    const struct jmap_req *req;  /* The context of this JMAP request. */
};

/* Determine the JMAP role of a Cyrus mailbox named mboxname based on the
 * specialuse annotation and HTTP users inbox name. The returned memory is
 * owned by the caller. */
char *jmap_mailbox_role(const char *mboxname)
{
    struct buf buf = BUF_INITIALIZER;
    const char *role = NULL;
    char *ret = NULL;
    int r;

    /* Inbox is special. */
    char *inboxname = mboxname_user_mbox(httpd_userid, NULL);
    if (!strcmp(mboxname, inboxname)) {
        free(inboxname);
        return xstrdup("inbox");
    }
    free(inboxname);

    /* Is it an outbox? */
    if (mboxname_isoutbox(mboxname)) return xstrdup("outbox");

    /* XXX How to determine the templates role? */

    /* Does this mailbox have an IMAP special use role? */
    r = annotatemore_lookup(mboxname, "/specialuse", httpd_userid, &buf);

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
        r = annotatemore_lookup(mboxname, IMAP_ANNOT_NS "x-role", httpd_userid, &buf);
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

/* Determine the JMAP mailbox name of the mailbox named mboxname. The returned
 * name is owned by the caller. Return NULL on error. */
static char *jmap_mailbox_name(const char *mboxname) {
    struct buf attrib = BUF_INITIALIZER;
    char *name;
    char *inboxname = mboxname_user_mbox(httpd_userid, NULL);

    int r = annotatemore_lookup(mboxname, IMAP_ANNOT_NS "displayname",
            httpd_userid, &attrib);
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

/* Convert the mailbox mbox to a JMAP mailbox object.
 *
 * Parent and inbox must point to the parent of mbox and the user's inbox,
 * respectively, and may be equal. Mbox and inbox may be equal as well, in
 * which case parent must be NULL. All mailbox comparison is by pointer. If
 * props is not NULL, only convert JMAP properties in props.
 *
 * Return NULL on error.
 */
static json_t *jmap_mailbox_from_mbox(struct mailbox *mbox,
                               const struct mailbox *parent,
                               const struct mailbox *inbox,
                               hash_table *props,
                               hash_table *roles,
                               const struct jmap_req *req)
{
    int r;
    unsigned statusitems = STATUS_MESSAGES | STATUS_UNSEEN;
    struct statusdata sdata;
    struct buf specialuse = BUF_INITIALIZER;
    json_t *obj = NULL;
    int rights = 0, parent_rights = 0;

    /* Determine rights */
    rights = mbox->acl ? cyrus_acl_myrights(req->authstate, mbox->acl) : 0;
    if (parent && parent->acl) {
        parent_rights = cyrus_acl_myrights(req->authstate, parent->acl);
    }

    /* Lookup status. */
    r = status_lookup_mailbox(mbox, httpd_userid, statusitems, &sdata);
    if (r) {
        syslog(LOG_INFO, "status_lookup_mailbox(%s) failed: %s",
                mbox->name, error_message(r));
        goto done;
    }

    /* Determine special use annotation. */
    annotatemore_lookup(mbox->name, "/specialuse", httpd_userid, &specialuse);

    /* Build JMAP mailbox response. */
    obj = json_pack("{}");
    json_object_set_new(obj, "id", json_string(mbox->uniqueid));
    if (_wantprop(props, "name")) {
        char *name = jmap_mailbox_name(mbox->name);
        if (!name) goto done;
        json_object_set_new(obj, "name", json_string(name));
        free(name);
    }
    if (_wantprop(props, "mustBeOnlyMailbox")) {
        json_object_set_new(obj, "mustBeOnlyMailbox", json_true());
    }

    if (_wantprop(props, "mayReadItems")) {
        json_object_set_new(obj, "mayReadItems", json_boolean(rights & ACL_READ));
    }
    if (_wantprop(props, "mayAddItems")) {
        json_object_set_new(obj, "mayAddItems", json_boolean(rights & ACL_INSERT));
    }
    if (_wantprop(props, "mayRemoveItems")) {
        json_object_set_new(obj, "mayRemoveItems", json_boolean(rights & ACL_DELETEMSG));
    }
    if (_wantprop(props, "mayCreateChild")) {
        json_object_set_new(obj, "mayCreateChild", json_boolean(rights & ACL_CREATE));
    }

    if (_wantprop(props, "totalMessages")) {
        json_object_set_new(obj, "totalMessages", json_integer(sdata.messages));
    }
    if (_wantprop(props, "unreadMessages")) {
        json_object_set_new(obj, "unreadMessages", json_integer(sdata.unseen));
    }
    if (_wantprop(props, "totalThreads") || _wantprop(props, "unreadThreads")) {
        /* we're always subfolders of INBOX, and we locked above, so this works */
        conv_status_t xconv = CONV_STATUS_INIT;
        conversation_getstatus(inbox->local_cstate, mbox->name, &xconv);

        if (_wantprop(props, "totalThreads")) {
            /* XXX */
            json_object_set_new(obj, "totalThreads", json_integer(xconv.exists));
        }
        if (_wantprop(props, "unreadThreads")) {
            /* XXX */
            json_object_set_new(obj, "unreadThreads", json_integer(xconv.unseen));
        }
    }
    if (_wantprop(props, "mayRename")) {
        int mayRename = rights & ACL_DELETEMBOX && parent_rights & ACL_CREATE;
        json_object_set_new(obj, "mayRename", json_boolean(mayRename));
    }
    if (_wantprop(props, "mayDelete")) {
        int mayDelete = rights & ACL_DELETEMBOX && mbox != inbox;
        json_object_set_new(obj, "mayDelete", json_boolean(mayDelete));
    }
    if (_wantprop(props, "role")) {
        char *role = jmap_mailbox_role(mbox->name);
        if (role && !hash_lookup(role, roles)) {
            json_object_set_new(obj, "role", json_string(role));
            hash_insert(role, (void*)1, roles);
        } else {
            json_object_set_new(obj, "role", json_null());
        }
        if (role) free(role);
    }
    if (_wantprop(props, "sortOrder")) {
        struct buf attrib = BUF_INITIALIZER;
        int sortOrder = 0;
        /* Ignore lookup errors here. */
        annotatemore_lookup(mbox->name, IMAP_ANNOT_NS "sortOrder", httpd_userid, &attrib);
        if (attrib.len) {
            uint64_t t = str2uint64(buf_cstring(&attrib));
            if (t < INT_MAX) {
                sortOrder = (int) t;
            } else {
                syslog(LOG_ERR, "%s: bogus sortOrder annotation value", mbox->name);
            }
        }
        json_object_set_new(obj, "sortOrder", json_integer(sortOrder));
        buf_free(&attrib);
    }
    if (_wantprop(props, "parentId")) {
        json_object_set_new(obj, "parentId", parent && parent != inbox ?
                json_string(parent->uniqueid) : json_null());
    }

done:
    buf_free(&specialuse);
    return obj;
}

int getMailboxes_cb(const mbentry_t *mbentry, void *vrock)
{
    struct getMailboxes_rock *rock = (struct getMailboxes_rock *) vrock;
    json_t *list = (json_t *) rock->list, *mbox;
    struct mailbox *mailbox = NULL, *parent = NULL;
    const struct mailbox *inbox = rock->inbox;
    const char *mboxname = mbentry->name;
    int r = 0, rights;
    struct mboxlist_entry *mbparent = NULL;

    /* Don't list special-purpose mailboxes. */
    if ((mbentry->mbtype & MBTYPE_DELETED) ||
        (mbentry->mbtype & MBTYPE_NETNEWS) ||
        (mbentry->mbtype & MBTYPE_CALENDAR) ||
        (mbentry->mbtype & MBTYPE_COLLECTION) ||
        (mbentry->mbtype & MBTYPE_ADDRESSBOOK)) {
        goto done;
    }

    /* Check ACL on mailbox for current user */
    rights = mbentry->acl ? cyrus_acl_myrights(httpd_authstate, mbentry->acl) : 0;
    if ((rights & (ACL_LOOKUP | ACL_READ)) != (ACL_LOOKUP | ACL_READ)) {
        goto done;
    }

    /* Open mailbox to get uniqueid. But make sure not to reopen INBOX. */
    if (strcmp(mboxname, inbox->name)) {
        if ((r = mailbox_open_irl(mboxname, &mailbox))) {
            syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
                    mboxname, error_message(r));
            goto done;
        }
        mailbox_unlock_index(mailbox, NULL);
    } else {
        mailbox = (struct mailbox *) inbox;
    }

    /* Determine parent. */
    r = mboxlist_findparent(mailbox->name, &mbparent);
    if (r && r != IMAP_MAILBOX_NONEXISTENT) {
        syslog(LOG_INFO, "mboxlist_findparent(%s) failed: %s",
                mailbox->name, error_message(r));
        goto done;
    }
    if (!r) {
        if (strcmp(mbparent->name, inbox->name)) {
            r = mailbox_open_irl(mbparent->name, &parent);
            if (r) {
                syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
                        mbparent->name, error_message(r));
                goto done;
            }
            mailbox_unlock_index(parent, NULL);
        } else {
            parent = (struct mailbox *) inbox;
        }
    }

    /* Convert mbox to JMAP object. */
    mbox = jmap_mailbox_from_mbox(mailbox, parent, inbox, rock->props, rock->roles, rock->req);
    if (!mbox) {
        syslog(LOG_INFO, "could not convert mailbox %s to JMAP", mailbox->name);
        goto done;
    }
    json_array_append_new(list, mbox);

  done:
    if (mailbox && mailbox != inbox) mailbox_close(&mailbox);
    if (parent && parent != inbox) mailbox_close(&parent);
    if (mbparent) mboxlist_entry_free(&mbparent);
    return 0;
}

/* Execute a getMailboxes message */
static int getMailboxes(struct jmap_req *req)
{
    json_t *item = NULL, *mailboxes, *state;
    struct getMailboxes_rock rock;
    rock.list = NULL;
    rock.inbox = req->inbox;
    rock.props = NULL;
    rock.roles = (hash_table *) xmalloc(sizeof(hash_table));
    rock.req = req;
    construct_hash_table(rock.roles, 8, 0);

    /* Determine current state. */
    state = jmap_getstate(0 /* MBTYPE */, req);

    /* Start constructing our response */
    item = json_pack("[s {s:s s:o} s]", "mailboxes",
                     "accountId", req->userid,
                     "state", state,
                     req->tag);

    /* Generate list of mailboxes */
    rock.list = json_array();

    /* Determine which properties to fetch. */
    json_t *properties = json_object_get(req->args, "properties");
    if (properties && json_array_size(properties)) {
        rock.props = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(rock.props, json_array_size(properties), 0);
        int i;
        int size = json_array_size(properties);
        for (i = 0; i < size; i++) {
            const char *prop = json_string_value(json_array_get(properties, i));
            if (prop == NULL) {
                json_t *err = json_pack("{s:s, s:[s]}",
                        "type", "invalidArguments", "arguments", "properties");
                json_array_append_new(req->response, json_pack("[s,o,s]",
                            "error", err, req->tag));
                goto done;
            }
            /* 1 == properties */
            hash_insert(prop, (void *)1, rock.props);
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
                    getMailboxes_cb(mbentry, &rock);
                    mboxlist_entry_free(&mbentry);
                } else {
                    syslog(LOG_ERR, "mboxlist_entry_free(%s): %s", mboxname,
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
        mboxlist_usermboxtree(req->userid, &getMailboxes_cb, &rock, 0 /*flags*/);
        json_object_set_new(mailboxes, "notFound", json_null());
    }
    json_object_set(mailboxes, "list", rock.list);

    json_array_append(req->response, item);

done:
    if (item) json_decref(item);
    if (rock.list) json_decref(rock.list);
    if (rock.props) {
        free_hash_table(rock.props, NULL);
        free(rock.props);
    }
    if (rock.roles) {
        free_hash_table(rock.roles, NULL);
        free(rock.roles);
    }
    return 0;
}

struct jmap_mailbox_newname_rock {
    const char *mboxname;
    int highest;
    size_t len;
};

static int jmap_mailbox_newname_cb(const mbentry_t *mbentry, void *vrock) {
    struct jmap_mailbox_newname_rock *rock = (struct jmap_mailbox_newname_rock *) vrock;
    const char *s;

    /* Only compute the length of mboxname once. */
    if (!rock->len) {
        rock->len = strlen(rock->mboxname);
        assert(rock->len > 0);
    }
    /* Only look for names starting with mboxname. */
    if (strncmp(mbentry->name, rock->mboxname, strlen(rock->mboxname))) {
        return 0;
    }
    s = mbentry->name + rock->len;
    /* Skip any grand-children. */
    if (strchr(s, jmap_namespace.hier_sep)) {
        return 0;
    }
    /* Does this mailbox match exactly our mboxname? */
    if (*s == 0) {
        rock->highest = 1;
        return 0;
    }
    /* Now check if it ends with pattern "_\d+". If not, skip it. */
    if (*s++ != '_') {
        return 0;
    }
    const char *lo = s, *hi = lo;
    while (isdigit(*s++)) { hi++; }
    if (lo == hi || *hi != 0) {
        return 0;
    }
    /* Gotcha! */
    int n = atoi(lo);
    if (n > rock->highest) {
        rock->highest = n;
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
 * For example, if the named has been determined to be x and a mailbox with
 * this name already exists, then look for all mailboxes named x_\d+. The
 * new mailbox name will be x_<max+1> with max being he highest number found
 * for any such named mailbox.
 *
 * Return the malloced, combined name, or NULL on error. */
char *jmap_mailbox_newname(const char *name, const char *parentname) {
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
    struct jmap_mailbox_newname_rock rock;
    memset(&rock, 0, sizeof(struct jmap_mailbox_newname_rock));
    rock.mboxname = mboxname;
    r = mboxlist_mboxtree(parentname, &jmap_mailbox_newname_cb, &rock,
            /* XXX need MBOXTREE_SKIP_GRANDCHILDREN */
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

struct _jmap_find_xrole_data {
    const char *xrole;
    const char *userid;
    char *mboxname;
};

static int _jmap_find_xrole_cb(const mbentry_t *mbentry, void *rock)
{
    struct _jmap_find_xrole_data *d = (struct _jmap_find_xrole_data *)rock;
    struct buf attrib = BUF_INITIALIZER;

    annotatemore_lookup(mbentry->name, IMAP_ANNOT_NS "x-role", d->userid, &attrib);

    if (attrib.len && !strcmp(buf_cstring(&attrib), d->xrole)) {
        d->mboxname = xstrdup(mbentry->name);
    }

    buf_free(&attrib);

    if (d->mboxname) return CYRUSDB_DONE;
    return 0;
}


static char *jmap_find_xrole(const char *xrole, const char *userid)
{
    struct _jmap_find_xrole_data rock = { xrole, userid, NULL };
    /* INBOX can never have an x-role. */
    mboxlist_usermboxtree(userid, _jmap_find_xrole_cb, &rock, MBOXTREE_SKIP_ROOT);
    return rock.mboxname;
}

static int _mbox_has_child_cb(const mbentry_t *mbentry __attribute__ ((unused)), void *rock) {
    int *has = (int *) rock;
    *has = 1;
    return CYRUSDB_DONE;
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
static int jmap_mailbox_write(char **uid,
                              json_t *arg,
                              json_t *invalid,
                              json_t **err,
                              struct jmap_req *req)
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
                        int rights = mbparent->acl ? cyrus_acl_myrights(httpd_authstate, mbparent->acl) : 0;
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
                    exists = jmap_find_xrole(role, req->userid);
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
            mboxname = jmap_mailbox_newname(name, parentname);
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
        buf_printf(&acl, "%s\t%s\t", httpd_userid, rights);
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
            char *oldname = jmap_mailbox_name(mboxname);
            if (!name) name = xstrdup(oldname);

            /* Do old and new mailbox names differ? */
            if (force_rename || strcmp(oldname, name)) {
                char *newmboxname, *oldmboxname;

                /* Determine the unique IMAP mailbox name. */
                newmboxname = jmap_mailbox_newname(name, parentname);
                if (!newmboxname) {
                    syslog(LOG_ERR, "jmap_mailbox_newname returns NULL: can't rename %s", mboxname);
                    r = IMAP_INTERNAL;
                    free(oldname);
                    goto done;
                }
                oldmboxname = mboxname;

                /* Rename the mailbox. */
                struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_RENAME);
                r = mboxlist_renamemailbox(oldmboxname, newmboxname,
                        NULL /* partition */, 0 /* uidvalidity */,
                        httpd_userisadmin, httpd_userid, httpd_authstate,
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
    r = annotatemore_write(mboxname, displayname_annot, httpd_userid, &val);
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
        r = annotatemore_write(mboxname, annot, httpd_userid, &val);
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
        r = annotatemore_write(mboxname, annot, httpd_userid, &val);
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
    r = annotatemore_write(mboxname, sortorder_annot, httpd_userid, &val);
    if (r) {
        syslog(LOG_ERR, "failed to write annotation %s: %s",
                sortorder_annot, error_message(r));
        goto done;
    }
    buf_free(&val);

    if (!*uid) {
        /* Return uniqueid. Must reopen mailbox to determine uniqueid. */
        struct mailbox *mbox = NULL;
        if ((r = mailbox_open_irl(mboxname, &mbox))) {
            syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
                    mboxname, error_message(r));
            goto done;
        }
        *uid = xstrdup(mbox->uniqueid);
        mailbox_close(&mbox);
    }

done:
    if (name) free(name);
    if (mboxname) free(mboxname);
    if (parentname) free(parentname);
    return r;
}

static int setMailboxes(struct jmap_req *req)
{
    int r = 0;
    json_t *set = NULL;

    char *mboxname = NULL;
    char *parentname = NULL;

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
            r = jmap_mailbox_write(&uid, arg, invalid, &err, req);
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
            r = jmap_mailbox_write(((char **)&uid), arg, invalid, &err, req);
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
            int has_child = 0;
            mboxlist_mboxtree(mboxname, &_mbox_has_child_cb,&has_child, MBOXTREE_SKIP_ROOT);
            if (has_child) {
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
                        httpd_userid, req->authstate, mboxevent,
                        1 /* checkacl */, 0 /* local_only */, 0 /* force */);
            } else {
                r = mboxlist_deletemailbox(mboxname,
                        httpd_userisadmin || httpd_userisproxyadmin,
                        httpd_userid, req->authstate, mboxevent,
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
    return r;
}

/* Convert the email addresses in addrs to a JSON array of
 * JMAP Emailer objects. */
static json_t *jmap_emailers_from_addresses(const char *addrs)
{
    json_t *emailers = json_pack("[]");
    struct address *a = NULL;
    struct address *freeme;
    struct buf buf = BUF_INITIALIZER;

    parseaddr_list(addrs, &a);
    freeme = a;
    while (a) {
        json_t *e = json_pack("{}");
        const char *mailbox = a->mailbox ? a->mailbox : "";
        const char *domain = a->domain ? a->domain : "";

        if (!strcmp(domain, "unspecified-domain")) {
            /* XXX the header of parseaddr doesn't document this. OK to use? */
            domain = "";
        }
        buf_printf(&buf, "%s@%s", mailbox, domain);

        json_object_set_new(e, "name", json_string(a->name ? a->name : ""));
        json_object_set_new(e, "email", json_string(buf_cstring(&buf)));

        json_array_append_new(emailers, e);
        buf_reset(&buf);
        a = a->next;
    }

    if (!json_array_size(emailers)) {
        json_decref(emailers);
        emailers = NULL;
    }

    if (freeme) parseaddr_free(freeme);
    buf_free(&buf);
    return emailers;

}

struct jmap_message_bodies_data {
    char *text;
    char *html;
};

static void jmap_message_bodies_extract_plain(const struct buf *buf, void *rock)
{
    char **dst = (char **) rock;
    *dst = buf_newcstring((struct buf*) buf);
}

/* Extract the plain text and HTML bodies of a Cyrus message to UTF-8 encoded
 * strings. Later parts in a multipart message of the same conten type
 * overwrite earlier ones. */
static int jmap_message_bodies_cb(int isbody,
                                  charset_t charset,
                                  int encoding,
                                  const char *subtype,
                                  struct buf *data,
                                  void *rock)
{
    struct jmap_message_bodies_data *d = (struct jmap_message_bodies_data *) rock;

    /* Skip headers. */
    if (!isbody) {
        return 0;
    }
    /* Extract plain and html bodies. */
    if (!strcmp(subtype, "PLAIN")) {
        char *body = charset_to_utf8(buf_base(data), buf_len(data), charset, encoding);
        if (body) {
            if (d->text) free(d->text);
            d->text = body;
        }
    } else if (!strcmp(subtype, "HTML")) {
        char *body = charset_to_utf8(buf_base(data), buf_len(data), charset, encoding);
        if (body) {
            if (d->html) free(d->html);
            d->html = body;
        }
    }
    return 0;
}

/* Generate a preview of text of at most len bytes, excluding the zero
 * byte.
 *
 * Consecutive whitespaces, including newlines, are collapsed to a single
 * blank. If text is longer than len and len is greater than 4, then return
 * a string  ending in '...' and holding as many complete UTF-8 characters,
 * that the total byte count of non-zero characters is at most len.
 *
 * The input string must be properly encoded UTF-8 and is not checked
 * for errors. */
static char *jmap_message_extract_preview(char *text, size_t len)
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

/* Convert the mail contained in record to a JMAP Message object. If props
 * is not NULL, only convert the properties defined in props.
 * Return NULL on error. */
static json_t *jmap_message_from_record(const char *id,
                                        struct mailbox *mbox,
                                        const struct index_record *record,
                                        hash_table *props)
{
    message_t *m;
    struct buf buf = BUF_INITIALIZER;
    json_t *msg;
    struct jmap_message_bodies_data d;
    uint32_t flags;
    int r;
    
    memset(&d, 0, sizeof(struct jmap_message_bodies_data));

    m = message_new_from_record(mbox, record);
    if (!m) return NULL;
    message_get_systemflags(m, &flags);

    msg = json_pack("{}");
    json_object_set_new(msg, "id", json_string(id));

    /* blobId */
    if (_wantprop(props, "blobId")) {
        buf_appendcstr(&buf, "m-");
        buf_appendcstr(&buf, id);
        json_object_set_new(msg, "blobId", json_string(buf_cstring(&buf)));
        buf_reset(&buf);

    }
    /* threadId */
    if (_wantprop(props, "threadId")) {
        conversation_id_t cid;
        r = message_get_cid(m, &cid);
        json_object_set_new(msg, "threadId", r ?
                json_null() : json_string(conversation_id_encode(cid)));
    }
    /* mailboxIds */
    if (_wantprop(props, "mailboxIds")) {
        json_object_set_new(msg, "mailboxIds", json_pack("[s]", mbox->uniqueid));
    }
    /* XXX inReplyToMessageId */
    /* XXX compiler error: undefined reference to `message_get_inreplyto' 
       message_get_inreplyto(m, &buf);
       buf_reset(&buf);
       */
    /* isUnread */
    if (_wantprop(props, "isUnread")) {
        json_object_set_new(msg, "isUnread", json_boolean(!(flags & FLAG_SEEN)));
    }
    /* isFlagged */
    if (_wantprop(props, "isFlagged")) {
        json_object_set_new(msg, "isFlagged", json_boolean(flags & FLAG_FLAGGED));
    }
    /* isAnswered */
    if (_wantprop(props, "isAnswered")) {
        json_object_set_new(msg, "isAnswered", json_boolean(flags & FLAG_ANSWERED));
    }
    /* isDraft */
    if (_wantprop(props, "isDraft")) {
        json_object_set_new(msg, "isDraft", json_boolean(flags & FLAG_DRAFT));
    }
    /* XXX hasAttachment */

    /* headers */
    /* XXX
     * JMAP Spec: getMessages:
     * headers.property: Instead of requesting all the headers (by requesting
     * the "headers" property, the client may specify the particular headers it
     * wants using the headers.property-name syntax, e.g.
     * "headers.X-Spam-Score", "headers.X-Spam-Hits"). The server will return a
     * headers property but with just the requested headers in the object
     * rather than all headers.
     */
    if (_wantprop(props, "headers")) {
        /* XXX compiler error: undefined reference to 'message_get_header'
        message_get_header(m, MESSAGE_DECODED, &buf);
        buf_reset(&buf);
        */
        struct buf msgbuf = BUF_INITIALIZER;
        if ((r = mailbox_map_record(mbox, record, &msgbuf))) {
            syslog(LOG_ERR, "mailbox_map_record(%s): %s",
                    mbox->name, error_message(r));
            json_decref(msg);
            return NULL;
        }

        /* Unfold continuation lines in headers. */
        char *hdrs = charset_unfold(buf_base(&msgbuf), record->header_size, 0);
        char *key = hdrs;
        json_t *headers = json_pack("{}");
        struct buf hdrbuf = BUF_INITIALIZER;
        while (key && *key) {
            /* Look for the key-value separator. */
            char *val = strchr(key, ':');
            if (!val || val == key) {
                break;
            }
            /* Terminate key. */
            *val++ = '\0';

            /* Look for end of header. */
            char *crlf = strchr(val, '\r');
            while (crlf && (*++crlf != '\n'))
                crlf = strchr(crlf, '\r');
            if (crlf) {
                *(crlf-1) = '\0';
                ++crlf;
            }

            /* Add or append the the header value to the JSON header object. */
            /* Header values tend to come with a leading blank. */
            if (*val == ' ') val++;
            json_t *curval = json_object_get(headers, key);
            if (!curval) {
                /* Header hasn't been defined yet. Add it to the map. */
                json_object_set_new(headers, key, json_string(val));
            } else {
                /* Concatenate values for recurring keys. This shouldn't
                 * occur too often, so let's just realloc */
                buf_setcstr(&hdrbuf, json_string_value(curval));
                buf_appendcstr(&hdrbuf, "\n");
                buf_appendcstr(&hdrbuf, val);
                json_object_set_new(headers, key, json_string(buf_cstring(&hdrbuf)));
                buf_reset(&hdrbuf);
            }
            key = crlf;
        }
        free(hdrs);
        buf_free(&hdrbuf);
        buf_free(&msgbuf);

        json_object_set_new(msg, "headers", headers);
    }
    /* from */
    if (_wantprop(props, "from")) {
        message_get_from(m, &buf);
        json_t *from = jmap_emailers_from_addresses(buf_cstring(&buf));
        json_object_set(msg, "from", from ? json_array_get(from, 0) : json_null());
        json_decref(from);
        buf_reset(&buf);
    }
    /* to */
    if (_wantprop(props, "to")) {
        message_get_to(m, &buf);
        json_t *to = jmap_emailers_from_addresses(buf_cstring(&buf));
        json_object_set(msg, "to", to ? to : json_null());
        json_decref(to);
        buf_reset(&buf);
    }
    /* cc */
    if (_wantprop(props, "cc")) {
        message_get_cc(m, &buf);
        json_t *cc = jmap_emailers_from_addresses(buf_cstring(&buf));
        json_object_set(msg, "cc", cc ? cc : json_null());
        json_decref(cc);
        buf_reset(&buf);
    }
    /*  bcc */
    if (_wantprop(props, "bcc")) {
        message_get_bcc(m, &buf);
        json_t *bcc = jmap_emailers_from_addresses(buf_cstring(&buf));
        json_object_set(msg, "bcc", bcc ? bcc : json_null());
        json_decref(bcc);
        buf_reset(&buf);
    }
    /* replyTo */
    if (_wantprop(props, "replyTo")) {
        message_get_field(m, "replyTo", MESSAGE_RAW, &buf);
        json_t *replyTo = jmap_emailers_from_addresses(buf_cstring(&buf));
        json_object_set(msg, "replyTo", replyTo ? replyTo : json_null());
        json_decref(replyTo);
        buf_reset(&buf);
    }
    /* subject */
    if (_wantprop(props, "subject")) {
        message_get_subject(m, &buf);
        json_object_set_new(msg, "subject", json_string(buf.len ? buf_cstring(&buf) : ""));
        buf_reset(&buf);
    }
    /* date */
    if (_wantprop(props, "date")) {
        char datestr[RFC3339_DATETIME_MAX];
        time_to_rfc3339(record->last_updated, datestr, RFC3339_DATETIME_MAX);
        json_object_set_new(msg, "date", json_string(datestr));
    }
    /* size */
    if (_wantprop(props, "size")) {
        uint32_t size = 0;
        message_get_size(m, &size);
        json_object_set_new(msg, "size", json_integer(size));
    }
    /* textBody */
    /* htmlBody */
    /* XXX
     * JMAP Spec: getMessages:
     * body: If "body" is included in the list of requested properties, it will
     * be interpreted by the server as a request for "htmlBody" if the message
     * has an HTML part, or "textBody" otherwise.
     */
    /* preview */
    if (_wantprop(props, "textBody") ||_wantprop(props, "htmlBody") || _wantprop(props, "preview")) {
        message_foreach_text_section(m, &jmap_message_bodies_cb, &d);

    }
    if (_wantprop(props, "textBody")) {
        if (!d.text && d.html) {
            /* JMAP spec: "If there is only an HTML version of the body, a
             * plain text version will be generated from this." */

            /* XXX Canonical search form replaces every HTML tag with a single
             * space and uppercases all characters, e.g.
             *     "<html><body><p>An html message.</p></body></html>"
             * becomes
             *     "   AN HTML MESSAGE.   "
             *
             * Might want to make striphtml in charset.c public to only get
             * rid of the HTML tags? */
            struct buf data = BUF_INITIALIZER;
            charset_t utf8 = charset_lookupname("utf8");
            buf_setcstr(&data, d.html);
            charset_extract(&jmap_message_bodies_extract_plain, &d.text,
                    &data, utf8, ENCODING_NONE, "HTML", 0);
            buf_free(&data);
            charset_free(&utf8);
        }
        json_object_set_new(msg, "textBody", d.text ? json_string(d.text) : json_null());
    }
    if (_wantprop(props, "htmlBody")) {
        if (!d.html && d.text) {
            /* JMAP spec: "If there is only a plain text version of the body,
             * an HTML version will be generated from this." */
            d.html = xstrdup(d.text);
        }
        json_object_set_new(msg, "htmlBody", d.html ? json_string(d.html) : json_null());
    }
    if (_wantprop(props, "preview")) {
        const char *annot;
        if ((annot = config_getstring(IMAPOPT_JMAP_PREVIEW_ANNOT))) {
            annotatemore_msg_lookup(mbox->name, record->uid, annot, httpd_userid, &buf);
        }
        if (buf.len) {
            /* FastMail store the preview as message annotations, so if there
             * is one defined, use that one. */
            json_object_set_new(msg, "preview", json_string(buf_cstring(&buf)));
        } else {
            char *preview = jmap_message_extract_preview(d.text, config_getint(IMAPOPT_JMAP_PREVIEW_LENGTH));
            json_object_set_new(msg, "preview", json_string(preview));
            free(preview);
        }
        buf_reset(&buf);
    }

    /* XXX attachments */
    /* XXX attachedMessages */

    message_unref(&m);
    if (d.text) free(d.text);
    if (d.html) free(d.html);
    buf_free(&buf);

    return msg;
}


typedef struct message_filter {
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
} message_filter;

/* Match the message in rock against filter. */
static int message_filter_match(void *vf, void *rock)
{
    struct message_filter *f = (struct message_filter *) vf;
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
        if (f->header_value && !jmap_match_text(json_string_value(val), f->header_value)) {
            return 0;
        }
    }
    return 1;
}

/* Free the memory allocated by this message filter. */
static void message_filter_free(void *vf)
{
    message_filter *f = (message_filter*) vf;
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

/* Parse the JMAP Message FilterCondition in arg.
 * Report any invalid properties in invalid, prefixed by prefix.
 * Return NULL on error. */
static void* message_filter_parse(json_t *arg,
                                  const char *prefix,
                                  json_t *invalid)
{

    message_filter *f = (message_filter *) xzmalloc(sizeof(struct message_filter));
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
        /* Match against filter. */
        if (d->filter) {
            json_t *msg = jmap_message_from_record(id, mbox, record, NULL);
            if (!msg || !jmap_filter_match(d->filter, &message_filter_match, msg)) {
                if (msg) json_decref(msg);
                continue;
            }
            if (msg) json_decref(msg);
        }
        json_array_append_new(d->messageIds, json_string(id));
    }
    mailbox_iter_done(&mbiter);
done:
    return r;
}

int getmessagelist_cb(const mbentry_t *mbentry, void *rock) {
    struct mailbox *mbox = NULL;
    struct getmessagelist_data *d = (struct getmessagelist_data*) rock;
    int r;

    if ((r = mailbox_open_irl(mbentry->name, &mbox))) {
        syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
                mbentry->name, error_message(r));
        goto done;
    }
    r = getmessagelist(mbox, d);
    mailbox_close(&mbox);

done:
    return r;
}

static int getMessageList(struct jmap_req *req)
{
    int r;
    struct getmessagelist_data rock;
    memset(&rock, 0, sizeof(struct getmessagelist_data));
    rock.messageIds = json_pack("[]");
    json_t *filter;


    /* XXX Parse and validate arguments. */
    json_t *invalid = json_pack("[]");

    /* filter */
    filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        rock.filter = jmap_filter_parse(filter, "filter", invalid, message_filter_parse);
    }

    /* Bail out for any property errors. */
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
    json_object_set(msgList, "messageIds", rock.messageIds);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("messageList"));
    json_array_append_new(item, msgList);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    json_decref(rock.messageIds);
    if (rock.filter) jmap_filter_free(rock.filter, message_filter_free);
    return r;
}

struct getmessages_data {
    hash_table *want;
    hash_table *found;
    hash_table *props;

    json_t *list;
    json_t *notFound;
};

static int getmessages(struct mailbox *mbox, struct getmessages_data *d)
{
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
        const char *id;
        /* Ignore expunged messages */
        if (record->system_flags & FLAG_EXPUNGED) {
            continue;
        }
        id = message_guid_encode(&record->guid);
        if (!id) {
            continue;
        }
        /* Are we even interested in that message? */
        if (!hash_lookup(id, d->want)) {
            continue;
        }
        /* Check if we've seen this message already in another mailbox. */
        json_t *msg = hash_lookup(id, d->found);
        if (!msg) {
            /* First time we see it. Convert and store it. */
            msg = jmap_message_from_record(id, mbox, record, d->props);
            if (msg) hash_insert(id, msg, d->found);
        } else if (_wantprop(d->props, "mailboxIds")) {
            /* We've already seen it. Just add this mailboxes unique id */
            json_t *mailboxIds = json_object_get(msg, "mailboxIds");
            json_array_append_new(mailboxIds, json_string(mbox->uniqueid));
        }
    }
    mailbox_iter_done(&mbiter);
done:
    return r;
}

int getmessages_cb(const mbentry_t *mbentry, void *rock)
{
    /* XXX This function allows to lookup multiple message ids in one
     * run and has O(N). Once there is a more performant lookup of
     * messages by guid, we might get rid of the current function. */
    struct mailbox *mbox = NULL;
    struct getmessages_data *d = (struct getmessages_data*) rock;
    int r;

    if ((r = mailbox_open_irl(mbentry->name, &mbox))) {
        syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
                mbentry->name, error_message(r));
        goto done;
    }
    r = getmessages(mbox, d);
    mailbox_close(&mbox);

done:
    return r;
}

struct find_indexrecord_data {
    struct message_guid guid;
    char *mboxname;
    uint32_t uid;
};


static int find_indexrecord(struct mailbox *mbox, struct find_indexrecord_data *d)
{
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
        /* Ignore expunged messages */
        if (record->system_flags & FLAG_EXPUNGED) {
            continue;
        }
        if (!message_guid_equal(&d->guid, &record->guid)) {
            /* Not the record we are looking for */
            continue;
        }
        /* Allright, this is the one. Keep the mailbox name and uid. */
        d->uid = record->uid;
        d->mboxname = xstrdup(mbox->name);
        r = CYRUSDB_DONE;
        break;
    }
    mailbox_iter_done(&mbiter);
done:
    return r;
}

int find_indexrecord_cb(const mbentry_t *mbentry, void *rock)
{
    struct mailbox *mbox = NULL;
    struct find_indexrecord_data *d = (struct find_indexrecord_data*) rock;
    int r;

    if ((r = mailbox_open_irl(mbentry->name, &mbox))) {
        syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
                mbentry->name, error_message(r));
        goto done;
    }
    r = find_indexrecord(mbox, d);
    mailbox_close(&mbox);

done:
    return r;
}

static int jmap_message_find_record(const char *id,
                                    const struct mailbox *inbox,
                                    const char *userid,
                                    char **mboxname,
                                    uint32_t *uid)
{
    /* XXX Need to lookup by message guid with O(1) or O(lgN).
     * Also: the JMAP-independent bits of this function should be refactored
     * to message.h or the like. */
    int r = 0;
    struct find_indexrecord_data d;
    d.mboxname = NULL;
    d.uid = 0;

    if (!message_guid_decode(&d.guid, id)) return 0;

    if (inbox) {
        r = find_indexrecord((struct mailbox*) inbox, &d);
        if (r == CYRUSDB_DONE) {
            *mboxname = d.mboxname;
            *uid = d.uid;
            return 0;
        } else if (r) {
            return r;
        }
    }

    /* Inspect any other mailboxes. */
    r = mboxlist_usermboxtree(userid, find_indexrecord_cb, &d, MBOXTREE_SKIP_ROOT);
    if (r && r != CYRUSDB_DONE) return r;
    *mboxname = d.mboxname;
    *uid = d.uid;
    return 0;
}

static void getmessages_report(const char *id,
                               void *data __attribute__((unused)),
                               void *rock)
{
    struct getmessages_data *d = (struct getmessages_data *) rock;
    json_t *msg = hash_lookup(id, d->found);
    if (msg) {
        json_array_append_new(d->list, msg);
    } else {
        json_array_append_new(d->notFound, json_string(id));
    }
}

static int getMessages(struct jmap_req *req)
{
    int r = 0;
    struct getmessages_data rock;
    memset(&rock, 0, sizeof(struct getmessages_data));
    hash_table want = HASH_TABLE_INITIALIZER;
    hash_table found = HASH_TABLE_INITIALIZER;
    hash_table props = HASH_TABLE_INITIALIZER;
    rock.list = json_pack("[]");
    rock.notFound = json_pack("[]");

    /* Parse and validate arguments. */
    json_t *invalid = json_pack("[]");

    /* ids */
    json_t *ids = json_object_get(req->args, "ids");
    if (ids && json_array_size(ids)) {
        size_t i;
        json_t *val;
        construct_hash_table(&want, json_array_size(ids), 0);
        construct_hash_table(&found, json_array_size(ids), 0);
        json_array_foreach(ids, i, val) {
            if (json_typeof(val) != JSON_STRING) {
                struct buf buf = BUF_INITIALIZER;
                buf_printf(&buf, "ids[%llu]", (unsigned long long) i);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
                continue;
            }
            hash_insert(json_string_value(val), (void*)1, &want);
        }
    } else {
        json_array_append_new(invalid, json_string("ids"));
    }

    /* properties */
    json_t *properties = json_object_get(req->args, "properties");
    if (properties && json_array_size(properties)) {
        construct_hash_table(&props, json_array_size(properties), 0);
        int i;
        int size = json_array_size(properties);
        for (i = 0; i < size; i++) {
            const char *p = json_string_value(json_array_get(properties, i));
            if (p == NULL) continue;
            hash_insert(p, (void *)1, &props);
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

    /* Inspect messages of INBOX. */
    rock.want = &want;
    rock.found = &found;
    if (hash_numrecords(&props)) {
        rock.props = &props;
    }
    r = getmessages((struct mailbox*) req->inbox, &rock);
    if (r && r != CYRUSDB_DONE) goto done;
    /* Inspect any other mailboxes. */
    r = mboxlist_usermboxtree(req->userid, getmessages_cb, &rock, MBOXTREE_SKIP_ROOT);
    if (r && r != CYRUSDB_DONE) goto done;
    r = 0;

    /* Report all requested message ids */
    hash_enumerate(&want, getmessages_report, &rock);

    json_t *messages = json_pack("{}");
    json_object_set_new(messages, "state", jmap_getstate(0 /*MBYTPE*/, req));
    json_object_set_new(messages, "accountId", json_string(req->userid));
    json_object_set(messages, "list", rock.list);
    json_object_set(messages, "notFound", json_array_size(rock.notFound) ?
            rock.notFound : json_null());

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("messages"));
    json_array_append_new(item, messages);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    free_hash_table(&props, NULL);
    free_hash_table(&want, NULL);
    free_hash_table(&found, NULL);
    json_decref(rock.list);
    json_decref(rock.notFound);
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

struct jmap_message_data {
    char *subject;
    char *to;
    char *cc;
    char *bcc;
    char *replyto;
    char *from;
    char *date;
    char *msgid;
    char *contenttype;
    char *boundary;
    char *mua;

    const char *textBody;
    const char *htmlBody;
};

/* Write the JMAP Message msg in RFC-5322 compliant wire format.
 *
 * The message is assumed to not contain value errors. If Date is neither
 * set in the message headers nor property, the current date is set. If
 * From isn't set, the userid of the current jmap request is used as
 * email address.
 *
 * Return 0 on success or non-zero if writing to the file failed */
static int jmap_message_write(json_t *msg, FILE *out, struct jmap_req *req)
{
    struct jmap_message_data d;
    const char *key, *s;
    json_t *val, *prop;
    size_t i;
    struct buf buf = BUF_INITIALIZER;
    int r;
    memset(&d, 0, sizeof(struct jmap_message_data));

    /* XXX
     * RFC 5322 - 2.1.1.  Line Length Limits
     * There are two limits that this specification places on the number of
     * characters in a line.  Each line of characters MUST be no more than
     * 998 characters, and SHOULD be no more than 78 characters, excluding
     * the CRLF.
     */

    /* Weed out special header values. The iteration allows to find and
     * remove headers case-insensitively */
    json_t *headers = json_pack("{}");
    json_object_foreach(json_object_get(msg, "headers"), key, val) {
        s = json_string_value(val);
        if (!s) {
            continue;
        } else if (!strcasecmp(key, "From")) {
            d.from = xstrdup(s);
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
            json_object_set(headers, key, val);
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
        JMAP_MESSAGE_EMAILER_TO_WIRE(&buf, prop);
        if (d.from) free(d.from);
        d.from = buf_newcstring(&buf);
        buf_reset(&buf);
    }
    if (!d.from) d.from = xstrdup(req->userid);

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
        JMAP_MESSAGE_EMAILER_TO_WIRE(&buf, prop);
        if (d.replyto) free(d.replyto);
        d.replyto = buf_newcstring(&buf);
        buf_reset(&buf);
    }

#undef JMAP_MESSAGE_EMAILER_TO_WIRE

    /* Override Subject header */
    if ((s = json_string_value(json_object_get(msg, "subject")))) {
        if (d.subject) free(d.subject);
        d.subject = xstrdup(s);
    }
    if (!d.subject) d.subject = xstrdup("");

    /* Override Date header */
    /* Precendence (high to low): "date" property, Date header, now */
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

    /* XXX inReplyToMessageId: set References and In-Reply-To */

    /* Determine Content-Type header and multi-part boundary */
    d.textBody = json_string_value(json_object_get(msg, "textBody"));
    d.htmlBody = json_string_value(json_object_get(msg, "htmlBody"));
    if (d.textBody && d.htmlBody) {
        char *p, *q, *uuid = xstrdup(makeuuid());
        d.boundary = xzmalloc(strlen(uuid));
        for (p = uuid, q = d.boundary; *p; p++) {
            if (*p != '-') *q++ = *p;
        }
        free(uuid);
    }

    /* Set Content-Type header */
    if (d.boundary) {
        buf_appendcstr(&buf, "multipart/mixed; boundary=");
        buf_appendcstr(&buf, d.boundary);
        d.contenttype = buf_release(&buf);
    } else if (d.htmlBody) {
        d.contenttype = xstrdup("text/html;charset=UTF-8");
    } else {
        d.contenttype = xstrdup("text/plain;charset=UTF-8");
    }

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
       r = fprintf(out, "%s: %s\r\n", k, s); \
       free(s); \
       if (r < 0) goto done; \
    }

    /* Mandatory headers according to RFC 5322 */
    JMAP_MESSAGE_WRITE_HEADER("From", d.from);
    JMAP_MESSAGE_WRITE_HEADER("Date", d.date);

    /* Optional headers */
    if (d.to)      JMAP_MESSAGE_WRITE_HEADER("To", d.to);
    if (d.cc)      JMAP_MESSAGE_WRITE_HEADER("Cc", d.cc);
    if (d.bcc)     JMAP_MESSAGE_WRITE_HEADER("Bcc", d.bcc);
    if (d.replyto) JMAP_MESSAGE_WRITE_HEADER("Reply-To", d.replyto);
    if (d.subject) JMAP_MESSAGE_WRITE_HEADER("Subject", d.subject);

    /* Custom headers */
    json_object_foreach(headers, key, val) {
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
    r = fputs("\r\n", out);
    if (r == EOF) goto done;

    /* Write body */
    if (d.textBody) {
        /* XXX JMAP spec: "If not supplied and an htmlBody is, the server
         * SHOULD generate a text version for the message from this." */
        if (d.boundary) {
            r = fprintf(out, "\r\n--%s\r\n", d.boundary);
            if (r < 0) goto done;
            r = fputs("Content-Type: text/plain;charset=UTF-8\r\n\r\n", out);
            if (r == EOF) goto done;
        }
        r = fputs(d.textBody, out);
        if (r == EOF) goto done;
    }
    if (d.htmlBody) {
        /* XXX JMAP spec: "If this contains internal links (cid:) the cid
         * value should be the attachment id." */
        if (d.boundary) {
            r = fprintf(out, "\r\n--%s\r\n", d.boundary);
            if (r < 0) goto done;
            r = fputs("Content-Type: text/html;charset=UTF-8\r\n\r\n", out);
            if (r == EOF) goto done;
        }
        r = fputs(d.htmlBody, out);
        if (r == EOF) goto done;
    }
    if (d.boundary) {
        r = fprintf(out, "\r\n--%s--\r\n", d.boundary);
        if (r < 0) goto done;
    }

    /* All done */
    r = 0;

done:
    if (d.from) free(d.from);
    if (d.date) free(d.date);
    if (d.to) free(d.to);
    if (d.cc) free(d.cc);
    if (d.bcc) free(d.bcc);
    if (d.replyto) free(d.replyto);
    if (d.subject) free(d.subject);
    if (d.msgid) free(d.msgid);
    if (d.mua) free(d.mua);
    if (d.contenttype) free(d.contenttype);
    if (d.boundary) free(d.boundary);
    buf_free(&buf);
    json_decref(headers);
    if (r) r = HTTP_SERVER_ERROR;
    return r;
}

/* Validate if the JMAP message arg is a valid draft of email.
 *
 * If From is not set in a draft, use the userid of the JMAP request req as
 * value. Use the id map in req to lookup creation ids.
 *
 * Report any invalid properties in the JSON array invalid, store any setError
 * in err.
 */
static void jmap_message_validate(json_t *arg,
                                  json_t **err,
                                  json_t *invalid,
                                  struct jmap_req *req)
{
    int pe;
    json_t *prop;
    const char *sval;
    int bval;
    struct buf buf = BUF_INITIALIZER;
    struct tm *date = xzmalloc(sizeof(struct tm));
    const char *inReplyToMessageId = NULL;
    /* XXX Support messages in multiple mailboxes */
    char *mboxname = NULL;
    char *mboxrole = NULL;
    int validateaddr = 0;

    /* Check if any of the mailboxes is an outbox. */
    prop = json_object_get(arg, "mailboxIds");
    if (json_array_size(prop) == 1 /* XXX Support multiple mailboxes */) {
        /* Check that first mailbox's role is either drafts or outbox */
        const char *id = json_string_value(json_array_get(prop, 0));
        if (id && *id == '#') id = hash_lookup(id, req->idmap);
        if (!id) {
            json_array_append_new(invalid, json_string("mailboxIds[0]"));
        }
        mboxname = mboxlist_find_uniqueid(id, req->userid);
        mboxrole = jmap_mailbox_role(mboxname);
        if (!mboxrole || (strcmp(mboxrole, "drafts") && strcmp(mboxrole, "outbox"))) {
            json_array_append_new(invalid, json_string("mailboxIds[0]"));
        }
        /* Enforce valid email address for to-be-sent messages */
        if (!strcmp(mboxrole, "outbox")) validateaddr = 1;
        /* XXX Check that none of mailboxes has mustBeOnlyMailbox set */
    } else {
        json_array_append_new(invalid, json_string("mailboxIds"));
    }

    /* Validate properties */
    if (json_object_get(arg, "id")) {
        json_array_append_new(invalid, json_string("id"));
    }
    if (json_object_get(arg, "blobId")) {
        json_array_append_new(invalid, json_string("blobId"));
    }
    if (json_object_get(arg, "threadId")) {
        json_array_append_new(invalid, json_string("threadId"));
    }
    prop = json_object_get(arg, "inReplyToMessageId");
    if (JNOTNULL(prop)) {
        inReplyToMessageId = json_string_value(prop);
        if ((sval = json_string_value(prop)) && sval && !strlen(sval)) {
            json_array_append_new(invalid, json_string("inReplyToMessageId"));
        }
    }
    pe = readprop(arg, "isUnread", 0, invalid, "b", &bval);
    if (pe > 0 && bval) {
        json_array_append_new(invalid, json_string("isUnread"));
    }
    readprop(arg, "isFlagged", 0, invalid, "b", &bval);
    pe = readprop(arg, "isAnswered", 0, invalid, "b", &bval);
    if (pe > 0 && bval) {
        json_array_append_new(invalid, json_string("isAnswered"));
    }
    pe = readprop(arg, "isDraft", 0, invalid, "b", &bval);
    if (pe > 0 && !bval) {
        json_array_append_new(invalid, json_string("isDraft"));
    }
    if (json_object_get(arg, "hasAttachment")) {
        json_array_append_new(invalid, json_string("hasAttachment"));
    }
    prop = json_object_get(arg, "headers");
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
    prop = json_object_get(arg, "from");
    if (JNOTNULL(prop)) {
        jmap_validate_emailer(prop, "from", validateaddr, invalid);
    }
    prop = json_object_get(arg, "to");
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
    prop = json_object_get(arg, "cc");
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
    prop = json_object_get(arg, "bcc");
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
    prop = json_object_get(arg, "replyTo");
    if (JNOTNULL(prop)) {
        jmap_validate_emailer(prop, "replyTo", validateaddr, invalid);
    }
    pe = readprop(arg, "date", 0, invalid, "s", &sval);
    if (pe > 0) {
        const char *p = strptime(sval, "%Y-%m-%dT%H:%M:%SZ", date);
        if (!p || *p) {
            json_array_append_new(invalid, json_string("date"));
        }
    }
    if (json_object_get(arg, "size")) {
        json_array_append_new(invalid, json_string("size"));
    }
    if (json_object_get(arg, "preview")) {
        json_array_append_new(invalid, json_string("preview"));
    }

    readprop(arg, "subject", 0, invalid, "s", &sval);
    readprop(arg, "textBody", 0, invalid, "s", &sval);
    readprop(arg, "htmlBody", 0, invalid, "s", &sval);

    if (json_object_get(arg, "attachedMessages")) {
        json_array_append_new(invalid, json_string("attachedMessages"));
    }
    prop = json_object_get(arg, "attachments");
    if (json_array_size(prop)) {
        /* XXX validate */
    }
    if (json_array_size(invalid)) {
        goto done;
    }

    if (inReplyToMessageId) {
        /* XXX Lookup message and validate inReplyToMessageId */
        if (0) {
            *err = json_pack("{s:s}", "type", "inReplyToNotFound");
            goto done;
        }
    }
    *err = NULL;

done:
    buf_free(&buf);
    if (mboxname) free(mboxname);
    if (mboxrole) free(mboxrole);
    if (date) free(date);
}

/* Create the JMAP message in all mailboxes as specified in the
 * mandatory mailboxIds property.
 *
 * Report any invalid properties in the JSON array invalid. Report
 * any other setErrors in err.
 *
 * On success, return 0 and store the message id in uid, which must
 * be freed by the caller. */
static int jmap_message_create(json_t *msg,
                               char **uid,
                               json_t **err,
                               json_t *invalid,
                               struct jmap_req *req)
{
    FILE *f = NULL;
    struct stagemsg *stage = NULL;
    time_t now = time(NULL);
    struct body *body = NULL;
    struct appendstate as;
    char *mboxname = NULL;
    char *mboxrole = NULL;
    const char *id;
    struct mailbox *mbox = NULL;
    int r = HTTP_SERVER_ERROR;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;

    /* Validate the message */
    jmap_message_validate(msg, err, invalid, req);
    if (json_array_size(invalid) || *err) return 0;

    /* XXX Support multiple mailboxes */
    id = json_string_value(json_array_get(json_object_get(msg, "mailboxIds"), 0));
    if (id && *id == '#') id = hash_lookup(id, req->idmap);
    if (!id) goto done;
    mboxname = mboxlist_find_uniqueid(id, req->userid);
    if (!mboxname) goto done;
    mboxrole = jmap_mailbox_role(mboxname);

    /* Open mailbox. */
    r = mailbox_open_iwl(mboxname, &mbox);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s): %s",
                mboxname, error_message(r));
        goto done;
    }

    /* Prepare to stage the message */
    if (!(f = append_newstage(mbox->name, now, 0, &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mbox->name);
        r = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Write the message to the file */
    r = jmap_message_write(msg, f, req);
    qdiffs[QUOTA_STORAGE] = ftell(f);
    fclose(f);
    if (r) {
        append_removestage(stage);
        goto done;
    }
    qdiffs[QUOTA_MESSAGE] = 1;

    /* Prepare to append the message to the mailbox */
    r = append_setup_mbox(&as, mbox, req->userid, httpd_authstate,
            0, qdiffs, 0, 0, EVENT_MESSAGE_NEW);
    if (r) goto done;

    /* Append the message to the mailbox */
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

    /* Read index record for new message (always the last one) */
    struct index_record record;
    memset(&record, 0, sizeof(struct index_record));
    record.recno = mbox->i.num_records;
    record.uid = mbox->i.last_uid;
    r = mailbox_reload_index_record(mbox, &record);
    if (r) goto done;

    /* Mark as draft */
    record.system_flags |= FLAG_DRAFT;
    /* Mark as flagged, if requested */
    if (json_object_get(msg, "isFlagged") == json_true()) {
        record.system_flags |= FLAG_FLAGGED;
    }

    /* Save record */
    r = mailbox_rewrite_index_record(mbox, &record);
    if (r) goto done;

done:
    if (stage) append_removestage(stage);
    if (mboxname) free(mboxname);
    if (mboxrole) free(mboxrole);
    if (mbox && mbox != req->inbox) mailbox_close(&mbox);
    return r;
}

static int setMessages(struct jmap_req *req)
{
    int r = 0;
    char *mboxname = NULL;
    struct mailbox *mbox = NULL;
    json_t *set = NULL;

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

            /* Create the message. */
            r = jmap_message_create(arg, &uid, &err, invalid, req);
            if (r) goto done;

            /* Handle invalid properties. */
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notCreated, key, err);
                continue;
            }
            json_decref(invalid);

            /* Handle set errors. */
            if (err) {
                json_object_set_new(notCreated, key, err);
                json_decref(invalid);
                continue;
            }

            /* Report message as created. */
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
        const char *id;
        json_t *arg;

        json_object_foreach(update, id, arg) {
            json_t *invalid = json_pack("[]");
            int unread = -1, flagged = -1, answered = -1;

            /* Validate uid */
            if (!strlen(id) || *id == '#') {
                json_t *err= json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, id, err);
                continue;
            }

            /* Parse properties */
            /* XXX Compare immutable message properties. */
            json_t *prop;
            prop = json_object_get(arg, "isFlagged");
            if (JNOTNULL(prop)) {
                readprop(arg, "isFlagged", 1, invalid, "b", &flagged);
            }
            prop = json_object_get(arg, "isUnread");
            if (JNOTNULL(prop)) {
                readprop(arg, "isUnread", 1, invalid, "b", &unread);
            }
            prop = json_object_get(arg, "isAnswered");
            if (JNOTNULL(prop)) {
                readprop(arg, "isAnswered", 1, invalid, "b", &answered);
            }

            /* Handle invalid properties. */
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notUpdated, id, err);
                continue;
            }
            json_decref(invalid);

            /* Lookup mailbox and message record */
            uint32_t uid;
            struct index_record record;
            r = jmap_message_find_record(id, req->inbox, req->userid, &mboxname, &uid);

            if (r) goto done;
            if (!mboxname || !uid) {
                json_t *err= json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, id, err);
                continue;
            }

            if (strcmp(mboxname, req->inbox->name)) {
                r = mailbox_open_iwl(mboxname, &mbox);
                if (r) goto done;
            } else {
                mbox = (struct mailbox *) req->inbox;
            }
            r = mailbox_find_index_record(mbox, uid, &record);
            if (r) goto done;

            /* XXX Support multiple mailboxes */
            /* XXX Support move */

            /* Update flags */
            if (flagged > 0)
                record.system_flags |= FLAG_FLAGGED;
            else if (!flagged)
                record.system_flags &= ~FLAG_FLAGGED;

            if (unread > 0)
                record.system_flags &= ~FLAG_SEEN;
            else if (!unread)
                record.system_flags |= FLAG_SEEN;

            if (answered > 0)
                record.system_flags |= FLAG_ANSWERED;
            else if (!answered)
                record.system_flags &= ~FLAG_ANSWERED;

            /* Rewrite index record */
            r = mailbox_rewrite_index_record(mbox, &record);
            if (r) {
                syslog(LOG_ERR, "mailbox_rewrite_index_record (%s) failed: %s",
                        mbox->name, error_message(r));
            }
            if (mbox != req->inbox) {
                mailbox_close(&mbox);
                mbox = NULL;
            }
            free(mboxname);
            mboxname = NULL;
            if (r) goto done;

            /* Report as updated. */
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

        size_t index;
        json_t *jid;
        json_array_foreach(destroy, index, jid) {

            /* Validate id. */
            const char *id = json_string_value(jid);
            if (!strlen(id) || *id == '#') {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, id, err);
                continue;
            }

            /* Lookup mailbox and message record */
            uint32_t uid;
            struct index_record record;
            r = jmap_message_find_record(id, req->inbox, req->userid, &mboxname, &uid);

            if (r) goto done;
            if (!mboxname || !uid) {
                json_t *err= json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, id, err);
                continue;
            }
            if (strcmp(mboxname, req->inbox->name)) {
                r = mailbox_open_iwl(mboxname, &mbox);
                if (r) goto done;
            } else {
                mbox = (struct mailbox *) req->inbox;
            }
            r = mailbox_find_index_record(mbox, uid, &record);
            if (r) goto done;

            /* Destroy message. */
            record.system_flags |= FLAG_EXPUNGED;

            /* Rewrite index record */
            r = mailbox_rewrite_index_record(mbox, &record);
            if (r) {
                syslog(LOG_ERR, "mailbox_rewrite_index_record (%s) failed: %s",
                        mbox->name, error_message(r));
                goto done;
            }

            /* Report mailbox event. */
            struct mboxevent *mboxevent = NULL;
            mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);
            mboxevent_extract_record(mboxevent, mbox, &record);
            mboxevent_extract_mailbox(mboxevent, mbox);
            mboxevent_set_numunseen(mboxevent, mbox, -1);
            mboxevent_set_access(mboxevent, NULL, NULL, req->userid, mbox->name, 0);
            mboxevent_notify(mboxevent);
            mboxevent_free(&mboxevent);

            /* Clean up */
            if (mbox != req->inbox) {
                mailbox_close(&mbox);
                mbox = NULL;
            }
            free(mboxname);
            mboxname = NULL;

            /* Report message as destroyed. */
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

    /* Set newState field in messageSet. */
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
    if (mboxname) free(mboxname);
    if (mbox && mbox != req->inbox) mailbox_close(&mbox);
    return r;
}

/*****************************************************************************
 * JMAP Contacts API
 ****************************************************************************/

struct cards_rock {
    struct jmap_req *req;
    json_t *array;
    struct hash_table *props;
    struct mailbox *mailbox;
    int rows;
};

static int getgroups_cb(void *rock, struct carddav_data *cdata)
{
    struct cards_rock *crock = (struct cards_rock *) rock;
    struct index_record record;
    int r;

    if (!crock->mailbox || strcmp(crock->mailbox->name, cdata->dav.mailbox)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(cdata->dav.mailbox, &crock->mailbox);
        if (r) return r;
    }

    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) return r;

    crock->rows++;

    struct vparse_entry *ventry = NULL;

    /* Load message containing the resource and parse vcard data */
    struct vparse_card *vcard = record_to_vcard(crock->mailbox, &record);
    if (!vcard || !vcard->objects) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                cdata->dav.imap_uid, crock->mailbox->name);
        vparse_free_card(vcard);
        return IMAP_INTERNAL;
    }

    json_t *obj = json_pack("{}");

    json_object_set_new(obj, "id", json_string(cdata->vcard_uid));

    json_object_set_new(obj, "addressbookId",
                        json_string(strrchr(cdata->dav.mailbox, '.')+1));

    json_t *contactids = json_pack("[]");
    json_t *otherids = json_pack("{}");

    _add_xhref(obj, cdata->dav.mailbox, cdata->dav.resource);

    for (ventry = vcard->objects->properties; ventry; ventry = ventry->next) {
        const char *name = ventry->name;
        const char *propval = ventry->v.value;

        if (!name) continue;
        if (!propval) continue;

        if (!strcasecmp(name, "fn")) {
            json_object_set_new(obj, "name", json_string(propval));
        }

        else if (!strcasecmp(name, "x-addressbookserver-member")) {
            if (strncmp(propval, "urn:uuid:", 9)) continue;
            json_array_append_new(contactids, json_string(propval+9));
        }

        else if (!strcasecmp(name, "x-fm-otheraccount-member")) {
            if (strncmp(propval, "urn:uuid:", 9)) continue;
            struct vparse_param *param = vparse_get_param(ventry, "userid");
            if (!param) continue;
            json_t *object = json_object_get(otherids, param->value);
            if (!object) {
                object = json_array();
                json_object_set_new(otherids, param->value, object);
            }
            json_array_append_new(object, json_string(propval+9));
        }
    }
    json_object_set_new(obj, "contactIds", contactids);
    json_object_set_new(obj, "otherAccountContactIds", otherids);

    json_array_append_new(crock->array, obj);

    vparse_free_card(vcard);

    return 0;
}

static int jmap_contacts_get(struct jmap_req *req, carddav_cb_t *cb,
                             int kind, const char *resname)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;

    char *mboxname = NULL;
    json_t *abookid = json_object_get(req->args, "addressbookId");
    if (abookid && json_string_value(abookid)) {
        /* XXX - invalid arguments */
        const char *addressbookId = json_string_value(abookid);
        mboxname = carddav_mboxname(req->userid, addressbookId);
    }

    struct cards_rock rock;
    int r = 0;

    r = carddav_create_defaultaddressbook(req->userid);
    if (r) goto done;

    rock.array = json_pack("[]");
    rock.props = NULL;
    rock.mailbox = NULL;

    json_t *properties = json_object_get(req->args, "properties");
    if (properties && json_array_size(properties)) {
        rock.props = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(rock.props, json_array_size(properties), 0);
        int i;
        int size = json_array_size(properties);
        for (i = 0; i < size; i++) {
            const char *id = json_string_value(json_array_get(properties, i));
            if (id == NULL) continue;
            /* 1 == properties */
            hash_insert(id, (void *)1, rock.props);
        }
    }

    json_t *want = json_object_get(req->args, "ids");
    json_t *notFound = json_array();
    if (want) {
        int i;
        int size = json_array_size(want);
        for (i = 0; i < size; i++) {
            rock.rows = 0;
            const char *id = json_string_value(json_array_get(want, i));
            if (!id) continue;
            r = carddav_get_cards(db, mboxname, id, kind, cb, &rock);
            if (r || !rock.rows) {
                json_array_append_new(notFound, json_string(id));
            }
        }
    }
    else {
        rock.rows = 0;
        r = carddav_get_cards(db, mboxname, NULL, kind, cb, &rock);
    }
    if (rock.props) {
        free_hash_table(rock.props, NULL);
        free(rock.props);
    }
    if (r) goto done;

    json_t *toplevel = json_pack("{}");
    json_object_set_new(toplevel, "accountId", json_string(req->userid));
    json_object_set_new(toplevel, "state", jmap_getstate(MBTYPE_ADDRESSBOOK, req));
    json_object_set_new(toplevel, "list", rock.array);
    if (json_array_size(notFound)) {
        json_object_set_new(toplevel, "notFound", notFound);
    }
    else {
        json_decref(notFound);
        json_object_set_new(toplevel, "notFound", json_null());
    }

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string(resname));
    json_array_append_new(item, toplevel);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

  done:
    free(mboxname);
    mailbox_close(&rock.mailbox);
    carddav_close(db);
    return r;
}

static int getContactGroups(struct jmap_req *req)
{
    return jmap_contacts_get(req, &getgroups_cb, CARDDAV_KIND_GROUP, "contactGroups");
}

static const char *_json_object_get_string(const json_t *obj, const char *key)
{
    const json_t *jval = json_object_get(obj, key);
    if (!jval) return NULL;
    const char *val = json_string_value(jval);
    return val;
}

static const char *_json_array_get_string(const json_t *obj, size_t index)
{
    const json_t *jval = json_array_get(obj, index);
    if (!jval) return NULL;
    const char *val = json_string_value(jval);
    return val;
}

struct updates_rock {
    json_t *changed;
    json_t *removed;

    size_t seen_records;
    size_t max_records;

    struct mailbox *mailbox;
    short fetchmodseq;
    modseq_t highestmodseq;
};

static void strip_spurious_deletes(struct updates_rock *urock)
{
    /* if something is mentioned in both DELETEs and UPDATEs, it's probably
     * a move.  O(N*M) algorithm, but there are rarely many, and the alternative
     * of a hash will cost more */
    unsigned i, j;

    for (i = 0; i < json_array_size(urock->removed); i++) {
        const char *del = json_string_value(json_array_get(urock->removed, i));

        for (j = 0; j < json_array_size(urock->changed); j++) {
            const char *up =
                json_string_value(json_array_get(urock->changed, j));
            if (!strcmpsafe(del, up)) {
                json_array_remove(urock->removed, i--);
                break;
            }
        }
    }
}

static void updates_rock_update(struct updates_rock *rock,
                                struct dav_data dav,
                                const char *uid) {

    /* Count, but don't process items that exceed the maximum record count. */
    if (rock->max_records && ++(rock->seen_records) > rock->max_records) {
        return;
    }

    /* Report item as updated or removed. */
    if (dav.alive) {
        json_array_append_new(rock->changed, json_string(uid));
    } else {
        json_array_append_new(rock->removed, json_string(uid));
    }

    /* Fetch record to determine modseq. */
    if (rock->fetchmodseq) {
        struct index_record record;
        int r;

        if (!rock->mailbox || strcmp(rock->mailbox->name, dav.mailbox)) {
            mailbox_close(&rock->mailbox);
            r = mailbox_open_irl(dav.mailbox, &rock->mailbox);
            if (r) {
                syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
                        dav.mailbox, error_message(r));
                return;
            }
        }
        r = mailbox_find_index_record(rock->mailbox, dav.imap_uid, &record);
        if (r) {
            syslog(LOG_INFO, "mailbox_find_index_record(%s,%d) failed: %s",
                    rock->mailbox->name, dav.imap_uid, error_message(r));
            mailbox_close(&rock->mailbox);
            return;
        }
        if (record.modseq > rock->highestmodseq) {
            rock->highestmodseq = record.modseq;
        }
    }
}

static int getcontactupdates_cb(void *rock, struct carddav_data *cdata)
{
    struct updates_rock *urock = (struct updates_rock *) rock;
    updates_rock_update(urock, cdata->dav, cdata->vcard_uid);
    return 0;
}

static int geteventupdates_cb(void *rock, struct caldav_data *cdata)
{
    struct updates_rock *urock = (struct updates_rock *) rock;
    updates_rock_update(urock, cdata->dav, cdata->ical_uid);
    return 0;
}

static int getContactGroupUpdates(struct jmap_req *req)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;
    struct buf buf = BUF_INITIALIZER;
    int r = -1;
    int pe; /* property parse error */
    modseq_t oldmodseq = 0;
    int dofetch = 0;

    /* Parse and validate arguments. */
    json_t *invalid = json_pack("[]");

    json_int_t max_records = 0;
    pe = readprop(req->args, "maxChanges", 0 /*mandatory*/, invalid, "i", &max_records);
    if (pe > 0) {
        if (max_records <= 0) {
            json_array_append_new(invalid, json_string("maxChanges"));
        }
    }

    const char *since = NULL;
    pe = readprop(req->args, "sinceState", 1 /*mandatory*/, invalid, "s", &since);
    if (pe > 0) {
        oldmodseq = atomodseq_t(since);
        if (!oldmodseq) {
            json_array_append_new(invalid, json_string("sinceState"));
        }
    }

    readprop(req->args, "fetchRecords", 0 /*mandatory*/, invalid, "b", &dofetch);

    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Non-JMAP spec addressbookId argument */
    char *mboxname = NULL;
    json_t *abookid = json_object_get(req->args, "addressbookId");
    if (abookid && json_string_value(abookid)) {
        const char *addressbookId = json_string_value(abookid);
        mboxname = carddav_mboxname(req->userid, addressbookId);
    }

    r = carddav_create_defaultaddressbook(req->userid);
    if (r) goto done;

    /* Lookup updates. */
    struct updates_rock rock;
    memset(&rock, 0, sizeof(struct updates_rock));
    rock.changed = json_array();
    rock.removed = json_array();
    rock.max_records = max_records;
    rock.fetchmodseq = 1;

    r = carddav_get_updates(db, oldmodseq, mboxname, CARDDAV_KIND_GROUP,
                            &getcontactupdates_cb, &rock);
    mailbox_close(&rock.mailbox);
    if (r) goto done;

    strip_spurious_deletes(&rock);

    /* Determine new state. */
    modseq_t newstate;
    int more = rock.max_records ? rock.seen_records > rock.max_records : 0;
    if (more) {
        newstate = rock.highestmodseq;
    } else {
        newstate = req->counters.carddavmodseq;
    }

    json_t *contactGroupUpdates = json_pack("{}");
    buf_printf(&buf, MODSEQ_FMT, newstate);
    json_object_set_new(contactGroupUpdates, "newState", json_string(buf_cstring(&buf)));
    buf_reset(&buf);

    json_object_set_new(contactGroupUpdates, "accountId", json_string(req->userid));
    json_object_set_new(contactGroupUpdates, "oldState", json_string(since));
    json_object_set_new(contactGroupUpdates, "hasMoreUpdates", json_boolean(more));
    json_object_set(contactGroupUpdates, "changed", rock.changed);
    json_object_set(contactGroupUpdates, "removed", rock.removed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactGroupUpdates"));
    json_array_append_new(item, contactGroupUpdates);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

    if (dofetch) {
        struct jmap_req subreq = *req; // struct copy, woot
        subreq.args = json_pack("{}");
        json_object_set(subreq.args, "ids", rock.changed);
        if (abookid) {
            json_object_set(subreq.args, "addressbookId", abookid);
        }
        r = getContactGroups(&subreq);
        json_decref(subreq.args);
    }

    json_decref(rock.changed);
    json_decref(rock.removed);

  done:
    buf_free(&buf);
    carddav_close(db);
    return r;
}

static const char *_resolveid(struct jmap_req *req, const char *id)
{
    const char *newid = hash_lookup(id, req->idmap);
    if (newid) return newid;
    return id;
}

static int _add_group_entries(struct jmap_req *req,
                              struct vparse_card *card, json_t *members,
                              json_t *invalid)
{
    vparse_delete_entries(card, NULL, "X-ADDRESSBOOKSERVER-MEMBER");
    int r = 0;
    size_t index;
    struct buf buf = BUF_INITIALIZER;

    for (index = 0; index < json_array_size(members); index++) {
        const char *item = _json_array_get_string(members, index);
        if (!item) {
            buf_printf(&buf, "contactIds[%zu]", index);
            json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
            continue;
        }
        const char *uid = _resolveid(req, item);
        buf_setcstr(&buf, "urn:uuid:");
        buf_appendcstr(&buf, uid);
        vparse_add_entry(card, NULL,
                         "X-ADDRESSBOOKSERVER-MEMBER", buf_cstring(&buf));
        buf_reset(&buf);
    }

    buf_free(&buf);
    return r;
}

static int _add_othergroup_entries(struct jmap_req *req,
                                   struct vparse_card *card, json_t *members,
                                   json_t *invalid)
{
    vparse_delete_entries(card, NULL, "X-FM-OTHERACCOUNT-MEMBER");
    int r = 0;
    struct buf buf = BUF_INITIALIZER;
    const char *key;
    json_t *arg;
    json_object_foreach(members, key, arg) {
        unsigned i;
        for (i = 0; i < json_array_size(arg); i++) {
            const char *item = json_string_value(json_array_get(arg, i));
            if (!item) {
                buf_printf(&buf, "otherContactIds[%s]", key);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
                continue;
            }
            const char *uid = _resolveid(req, item);
            buf_setcstr(&buf, "urn:uuid:");
            buf_appendcstr(&buf, uid);
            struct vparse_entry *entry =
                vparse_add_entry(card, NULL,
                                 "X-FM-OTHERACCOUNT-MEMBER", buf_cstring(&buf));
            vparse_add_param(entry, "userid", key);
            buf_reset(&buf);
        }
    }
    buf_free(&buf);
    return r;
}

static int setContactGroups(struct jmap_req *req)
{
    struct mailbox *mailbox = NULL;
    struct mailbox *newmailbox = NULL;
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;

    int r = 0;
    json_t *jcheckState = json_object_get(req->args, "ifInState");
    if (jcheckState && jmap_checkstate(jcheckState, MBTYPE_ADDRESSBOOK, req)) {
        json_t *item = json_pack("[s, {s:s}, s]",
                "error", "type", "stateMismatch", req->tag);
        json_array_append_new(req->response, item);
        goto done;
    }

    json_t *set = json_pack("{s:o,s:s}",
                            "oldState", jmap_getstate(MBTYPE_ADDRESSBOOK, req),
                            "accountId", req->userid);

    r = carddav_create_defaultaddressbook(req->userid);
    if (r) goto done;

    json_t *create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");
        json_t *record;

        const char *key;
        json_t *arg;
        json_object_foreach(create, key, arg) {
            char *uid = xstrdup(makeuuid());
            const char *name = NULL;
            json_t *invalid = json_pack("[]");

            readprop(arg, "name", 1, invalid, "s", &name);

            struct vparse_card *card = vparse_new_card("VCARD");
            vparse_add_entry(card, NULL, "VERSION", "3.0");
            vparse_add_entry(card, NULL, "N", name);
            vparse_add_entry(card, NULL, "FN", name);
            vparse_add_entry(card, NULL, "UID", uid);
            vparse_add_entry(card, NULL, "X-ADDRESSBOOKSERVER-KIND", "group");

            /* it's legal to create an empty group */
            json_t *members = json_object_get(arg, "contactIds");
            if (members) {
                _add_group_entries(req, card, members, invalid);
            }

            /* it's legal to create an empty group */
            json_t *others = json_object_get(arg, "otherAccountContactIds");
            if (others) {
                _add_othergroup_entries(req, card, others, invalid);
            }

            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notCreated, key, err);
                vparse_free_card(card);
                free(uid);
                continue;
            }
            json_decref(invalid);

            const char *addressbookId = "Default";
            json_t *abookid = json_object_get(arg, "addressbookId");
            if (abookid && json_string_value(abookid)) {
                /* XXX - invalid arguments */
                addressbookId = json_string_value(abookid);
            }
            char *mboxname = mboxname_abook(req->userid, addressbookId);
            json_object_del(arg, "addressbookId");
            addressbookId = NULL;

            /* we need to create and append a record */
            if (!mailbox || strcmp(mailbox->name, mboxname)) {
                mailbox_close(&mailbox);
                r = mailbox_open_iwl(mboxname, &mailbox);
            }

            syslog(LOG_NOTICE, "jmap: create group %s/%s/%s (%s)",
                   req->userid, mboxname, uid, name);
            free(mboxname);

            if (!r) r = carddav_store(mailbox, card, NULL, NULL, NULL,
                                      req->userid, req->authstate, ignorequota);
            vparse_free_card(card);

            if (r) {
                /* these are real "should never happen" errors */
                free(uid);
                goto done;
            }

            record = json_pack("{s:s}", "id", uid);
            json_object_set_new(created, key, record);

            /* hash_insert takes ownership of uid here, skanky I know */
            hash_insert(key, uid, req->idmap);
        }

        if (json_object_size(created))
            json_object_set(set, "created", created);
        json_decref(created);
        if (json_object_size(notCreated))
            json_object_set(set, "notCreated", notCreated);
        json_decref(notCreated);
    }

    json_t *update = json_object_get(req->args, "update");
    if (update) {
        json_t *updated = json_pack("[]");
        json_t *notUpdated = json_pack("{}");

        const char *uid;
        json_t *arg;
        json_object_foreach(update, uid, arg) {
            struct carddav_data *cdata = NULL;
            r = carddav_lookup_uid(db, uid, &cdata);
            uint32_t olduid;
            char *resource = NULL;

            /* is it a valid group? */
            if (r || !cdata || !cdata->dav.imap_uid || !cdata->dav.resource
                  || cdata->kind != CARDDAV_KIND_GROUP) {
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }
            olduid = cdata->dav.imap_uid;
            resource = xstrdup(cdata->dav.resource);

            if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
                mailbox_close(&mailbox);
                r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
                if (r) {
                    syslog(LOG_ERR, "IOERROR: failed to open %s",
                           cdata->dav.mailbox);
                    free(resource);
                    goto done;
                }
            }

            json_t *abookid = json_object_get(arg, "addressbookId");
            if (abookid && json_string_value(abookid)) {
                const char *mboxname =
                    mboxname_abook(req->userid, json_string_value(abookid));
                if (strcmp(mboxname, cdata->dav.mailbox)) {
                    /* move */
                    r = mailbox_open_iwl(mboxname, &newmailbox);
                    if (r) {
                        syslog(LOG_ERR, "IOERROR: failed to open %s", mboxname);
                        free(resource);
                        goto done;
                    }
                }
                json_object_del(arg, "addressbookId");
            }

            struct index_record record;

            r = mailbox_find_index_record(mailbox,
                                          cdata->dav.imap_uid, &record);
            if (r) {
                free(resource);
                goto done;
            }

            /* Load message containing the resource and parse vcard data */
            struct vparse_card *vcard = record_to_vcard(mailbox, &record);
            if (!vcard || !vcard->objects) {
                syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                       cdata->dav.imap_uid, mailbox->name);
                json_t *err = json_pack("{s:s}", "type", "parseError");
                json_object_set_new(notUpdated, uid, err);
                vparse_free_card(vcard);
                mailbox_close(&newmailbox);
                free(resource);
                continue;
            }
            struct vparse_card *card = vcard->objects;

            json_t *namep = json_object_get(arg, "name");
            if (namep) {
                const char *name = json_string_value(namep);
                if (!name) {
                    json_t *err = json_pack("{s:s}",
                                            "type", "invalidArguments");
                    json_object_set_new(notUpdated, uid, err);
                    vparse_free_card(vcard);
                    mailbox_close(&newmailbox);
                    free(resource);
                    continue;
                }
                /* both N and FN get the name */
                struct vparse_entry *entry = vparse_get_entry(card, NULL, "N");
                if (entry) {
                    if (entry->multivalue) {
                        strarray_free(entry->v.values);
                        entry->v.values = NULL;
                    } else {
                        free(entry->v.value);
                    }
                    entry->v.value = xstrdup(name);
                    entry->multivalue = 0;
                }
                else {
                    vparse_add_entry(card, NULL, "N", name);
                }
                entry = vparse_get_entry(card, NULL, "FN");
                if (entry) {
                    if (entry->multivalue) {
                        /* FN isn't allowed to be a multi-value, but let's
                         * rather check than deal with corrupt memory */
                        strarray_free(entry->v.values);
                        entry->v.values = NULL;
                    } else {
                        free(entry->v.value);
                    }
                    entry->v.value = xstrdup(name);
                    entry->multivalue = 0;
                }
                else {
                    vparse_add_entry(card, NULL, "FN", name);
                }
            }

            json_t *invalid = json_pack("[]");
            json_t *members = json_object_get(arg, "contactIds");
            if (members) {
                _add_group_entries(req, card, members, invalid);
            }

            json_t *others = json_object_get(arg, "otherAccountContactIds");
            if (others) {
                _add_othergroup_entries(req, card, others, invalid);
            }
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notUpdated, uid, err);
                vparse_free_card(vcard);
                mailbox_close(&newmailbox);
                free(resource);
                continue;
            }
            json_decref(invalid);

            syslog(LOG_NOTICE, "jmap: update group %s/%s",
                   req->userid, resource);

            r = carddav_store(newmailbox ? newmailbox : mailbox, card, resource,
                              NULL, NULL, req->userid, req->authstate, ignorequota);
            if (!r)
                r = carddav_remove(mailbox, olduid, /*isreplace*/!newmailbox, req->userid);
            mailbox_close(&newmailbox);

            vparse_free_card(vcard);
            free(resource);
            if (r) goto done;

            json_array_append_new(updated, json_string(uid));
        }

        if (json_array_size(updated))
            json_object_set(set, "updated", updated);
        json_decref(updated);
        if (json_object_size(notUpdated))
            json_object_set(set, "notUpdated", notUpdated);
        json_decref(notUpdated);
    }

    json_t *destroy = json_object_get(req->args, "destroy");
    if (destroy) {
        json_t *destroyed = json_pack("[]");
        json_t *notDestroyed = json_pack("{}");

        size_t index;
        for (index = 0; index < json_array_size(destroy); index++) {
            const char *uid = _json_array_get_string(destroy, index);
            if (!uid) {
                json_t *err = json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }
            struct carddav_data *cdata = NULL;
            uint32_t olduid;
            r = carddav_lookup_uid(db, uid, &cdata);

            /* is it a valid group? */
            if (r || !cdata ||
                !cdata->dav.imap_uid || cdata->kind != CARDDAV_KIND_GROUP) {
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }
            olduid = cdata->dav.imap_uid;

            if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
                mailbox_close(&mailbox);
                r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
                if (r) goto done;
            }

            /* XXX - alive check */

            syslog(LOG_NOTICE, "jmap: destroy group %s (%s)", req->userid, uid);
            r = carddav_remove(mailbox, olduid, /*isreplace*/0, req->userid);
            if (r) {
                syslog(LOG_ERR,
                       "IOERROR: setContactGroups remove failed for %s %u",
                       mailbox->name, cdata->dav.imap_uid);
                goto done;
            }

            json_array_append_new(destroyed, json_string(uid));
        }

        if (json_array_size(destroyed))
            json_object_set(set, "destroyed", destroyed);
        json_decref(destroyed);
        if (json_object_size(notDestroyed))
            json_object_set(set, "notDestroyed", notDestroyed);
        json_decref(notDestroyed);
    }

    /* force modseq to stable */
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    if (json_object_get(set, "created") ||
        json_object_get(set, "updated") ||
        json_object_get(set, "destroyed")) {

        r = jmap_bumpstate(MBTYPE_ADDRESSBOOK, req);
        if (r) goto done;
    }
    json_object_set_new(set, "newState", jmap_getstate(MBTYPE_ADDRESSBOOK, req));

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactGroupsSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    mailbox_close(&newmailbox);
    mailbox_close(&mailbox);

    carddav_close(db);
    return r;
}

static int _wantprop(hash_table *props, const char *name)
{
    if (!props) return 1;
    if (hash_lookup(name, props)) return 1;
    return 0;
}


/* Extract separate y,m,d from YYYY-MM-DD or (with ignore_hyphens) YYYYMMDD
 *
 * This handles birthday/anniversary and BDAY/ANNIVERSARY for JMAP and vCard
 *
 * JMAP dates are _always_ YYYY-MM-DD, so use require_hyphens = 1
 *
 * For vCard, this handles "date-value" from RFC2426 (which is "date" from
 * RFC2425), used by BDAY (ANNIVERSARY isn't in vCard 3). vCard 4 says BDAY and
 * ANNIVERSARY is date-and-or-time, which is far more complicated. I haven't
 * seen that in the wild yet and hope I never do.
 */
static int _parse_date(const char *date, unsigned *y, unsigned *m, unsigned *d, int require_hyphens)
{
    /* there isn't a convenient libc function that will let us convert parts of
     * a string to integer and only take digit characters, so we just pull it
     * apart ourselves */

    const char *yp = NULL, *mp = NULL, *dp = NULL;

    /* getting pointers to the ymd components, skipping hyphens if necessary.
     * format checking as we go. no need to strlen() beforehand, it will fall
     * out of the range checks. */
    yp = date;
    if (yp[0] < '0' || yp[0] > '9' ||
        yp[1] < '0' || yp[1] > '9' ||
        yp[2] < '0' || yp[2] > '9' ||
        yp[3] < '0' || yp[3] > '9') return -1;

    mp = &yp[4];

    if (*mp == '-') mp++;
    else if (require_hyphens) return -1;

    if (mp[0] < '0' || mp[0] > '9' ||
        mp[1] < '0' || mp[1] > '9') return -1;

    dp = &mp[2];

    if (*dp == '-') dp++;
    else if (require_hyphens) return -1;

    if (dp[0] < '0' || dp[0] > '9' ||
        dp[1] < '0' || dp[1] > '9') return -1;

    if (dp[2] != '\0') return -1;

    /* convert to integer. ascii digits are 0x30-0x37, so we can take bottom
     * four bits and multiply */
    *y =
        (yp[0] & 0xf) * 1000 +
        (yp[1] & 0xf) * 100 +
        (yp[2] & 0xf) * 10 +
        (yp[3] & 0xf);

    *m =
        (mp[0] & 0xf) * 10 +
        (mp[1] & 0xf);

    *d =
        (dp[0] & 0xf) * 10 +
        (dp[1] & 0xf);

    return 0;
}

static void _date_to_jmap(struct vparse_entry *entry, struct buf *buf)
{
    if (!entry)
        goto no_date;

    unsigned y, m, d;
    if (_parse_date(entry->v.value, &y, &m, &d, 0))
        goto no_date;

    if (y < 1604 || m > 12 || d > 31)
        goto no_date;

    const struct vparse_param *param;
    for (param = entry->params; param; param = param->next) {
        if (!strcasecmp(param->name, "x-apple-omit-year"))
            /* XXX compare value with actual year? */
            y = 0;
        if (!strcasecmp(param->name, "x-fm-no-month"))
            m = 0;
        if (!strcasecmp(param->name, "x-fm-no-day"))
            d = 0;
    }

    /* sigh, magic year 1604 has been seen without X-APPLE-OMIT-YEAR, making
     * me wonder what the bloody point is */
    if (y == 1604)
        y = 0;

    buf_reset(buf);
    buf_printf(buf, "%04d-%02d-%02d", y, m, d);
    return;

no_date:
    buf_setcstr(buf, "0000-00-00");
}

static const char *_servicetype(const char *type)
{
    /* add new services here */
    if (!strcasecmp(type, "aim")) return "AIM";
    if (!strcasecmp(type, "facebook")) return "Facebook";
    if (!strcasecmp(type, "flickr")) return "Flickr";
    if (!strcasecmp(type, "gadugadu")) return "GaduGadu";
    if (!strcasecmp(type, "github")) return "GitHub";
    if (!strcasecmp(type, "googletalk")) return "GoogleTalk";
    if (!strcasecmp(type, "icq")) return "ICQ";
    if (!strcasecmp(type, "jabber")) return "Jabber";
    if (!strcasecmp(type, "linkedin")) return "LinkedIn";
    if (!strcasecmp(type, "msn")) return "MSN";
    if (!strcasecmp(type, "myspace")) return "MySpace";
    if (!strcasecmp(type, "qq")) return "QQ";
    if (!strcasecmp(type, "skype")) return "Skype";
    if (!strcasecmp(type, "twitter")) return "Twitter";
    if (!strcasecmp(type, "yahoo")) return "Yahoo";

    syslog(LOG_NOTICE, "unknown service type %s", type);
    return type;
}

/* Convert the VCARD card, contained in record and cdata and mailbox 
 * mboxname. If props is not NULL, only convert properties in props. */
static json_t *jmap_contact_from_vcard(struct vparse_card *card,
                                       struct carddav_data *cdata,
                                       struct index_record *record,
                                       hash_table *props,
                                       const char *mboxname)
{
    strarray_t *empty = NULL;
    json_t *obj = json_pack("{}");
    struct buf buf = BUF_INITIALIZER;

    json_object_set_new(obj, "id", json_string(cdata->vcard_uid));

    json_object_set_new(obj, "addressbookId",
                        json_string(strrchr(cdata->dav.mailbox, '.')+1));

    if (_wantprop(props, "isFlagged")) {
        json_object_set_new(obj, "isFlagged",
                            record->system_flags & FLAG_FLAGGED ? json_true() :
                            json_false());
    }

    if (_wantprop(props, "x-href")) {
        _add_xhref(obj, cdata->dav.mailbox, cdata->dav.resource);
    }

    if (_wantprop(props, "x-importance")) {
        double val = 0;
        const char *ns = DAV_ANNOT_NS "<" XML_NS_CYRUS ">importance";

        buf_reset(&buf);
        annotatemore_msg_lookup(mboxname, record->uid,
                                ns, "", &buf);
        if (buf.len)
            val = strtod(buf_cstring(&buf), NULL);

        json_object_set_new(obj, "x-importance", json_real(val));
    }

    const strarray_t *n = vparse_multival(card, "n");
    const strarray_t *org = vparse_multival(card, "org");
    if (!n) n = empty ? empty : (empty = strarray_new());
    if (!org) org = empty ? empty : (empty = strarray_new());

    /* name fields: Family; Given; Middle; Prefix; Suffix. */

    if (_wantprop(props, "lastName")) {
        const char *family = strarray_safenth(n, 0);
        json_object_set_new(obj, "lastName", json_string(family));
    }

    if (_wantprop(props, "firstName")) {
        /* JMAP doesn't have a separate field for Middle (aka "Additional
         * Names"), so we just mash them into firstName. See reverse of this in
         * _json_to_card */
        const char *given = strarray_safenth(n, 1);
        const char *middle = strarray_safenth(n, 2);
        buf_setcstr(&buf, given);
        if (*middle) {
            buf_putc(&buf, ' ');
            buf_appendcstr(&buf, middle);
        }
        json_object_set_new(obj, "firstName", json_string(buf_cstring(&buf)));
    }
    if (_wantprop(props, "prefix")) {
        const char *prefix = strarray_safenth(n, 3);
        json_object_set_new(obj, "prefix",
                            json_string(prefix)); /* just prefix */
    }
    if (_wantprop(props, "suffix")) {
        const char *suffix = strarray_safenth(n, 4);
        json_object_set_new(obj, "suffix",
                            json_string(suffix)); /* just suffix */
    }

    /* org fields */
    if (_wantprop(props, "company"))
        json_object_set_new(obj, "company",
                            json_string(strarray_safenth(org, 0)));
    if (_wantprop(props, "department"))
        json_object_set_new(obj, "department",
                            json_string(strarray_safenth(org, 1)));
    if (_wantprop(props, "jobTitle")) {
        /* we used to store jobTitle in ORG[2] instead of TITLE, which confused
         * CardDAV clients. that's fixed, but there's now lots of cards with it
         * stored in the wrong place, so check both */
        const char *item = vparse_stringval(card, "title");
        if (!item)
            item = strarray_safenth(org, 2);
        json_object_set_new(obj, "jobTitle", json_string(item));
    }

    /* address - we need to open code this, because it's repeated */
    if (_wantprop(props, "addresses")) {
        json_t *adr = json_array();

        struct vparse_entry *entry;
        for (entry = card->properties; entry; entry = entry->next) {
            if (strcasecmp(entry->name, "adr")) continue;
            json_t *item = json_pack("{}");

            /* XXX - type and label */
            const strarray_t *a = entry->v.values;

            const struct vparse_param *param;
            const char *type = "other";
            const char *label = NULL;
            for (param = entry->params; param; param = param->next) {
                if (!strcasecmp(param->name, "type")) {
                    if (!strcasecmp(param->value, "home")) {
                        type = "home";
                    }
                    else if (!strcasecmp(param->value, "work")) {
                        type = "work";
                    }
                    else if (!strcasecmp(param->value, "billing")) {
                        type = "billing";
                    }
                    else if (!strcasecmp(param->value, "postal")) {
                        type = "postal";
                    }
                }
                else if (!strcasecmp(param->name, "label")) {
                    label = param->value;
                }
            }
            json_object_set_new(item, "type", json_string(type));
            if (label) json_object_set_new(item, "label", json_string(label));

            const char *pobox = strarray_safenth(a, 0);
            const char *extended = strarray_safenth(a, 1);
            const char *street = strarray_safenth(a, 2);
            buf_reset(&buf);
            if (*pobox) {
                buf_appendcstr(&buf, pobox);
                if (extended || street) buf_putc(&buf, '\n');
            }
            if (*extended) {
                buf_appendcstr(&buf, extended);
                if (street) buf_putc(&buf, '\n');
            }
            if (*street) {
                buf_appendcstr(&buf, street);
            }

            json_object_set_new(item, "street",
                                json_string(buf_cstring(&buf)));
            json_object_set_new(item, "locality",
                                json_string(strarray_safenth(a, 3)));
            json_object_set_new(item, "region",
                                json_string(strarray_safenth(a, 4)));
            json_object_set_new(item, "postcode",
                                json_string(strarray_safenth(a, 5)));
            json_object_set_new(item, "country",
                                json_string(strarray_safenth(a, 6)));

            json_array_append_new(adr, item);
        }

        json_object_set_new(obj, "addresses", adr);
    }

    /* address - we need to open code this, because it's repeated */
    if (_wantprop(props, "emails")) {
        json_t *emails = json_array();

        struct vparse_entry *entry;
        int defaultIndex = -1;
        int i = 0;
        for (entry = card->properties; entry; entry = entry->next) {
            if (strcasecmp(entry->name, "email")) continue;
            json_t *item = json_pack("{}");
            const struct vparse_param *param;
            const char *type = "other";
            const char *label = NULL;
            for (param = entry->params; param; param = param->next) {
                if (!strcasecmp(param->name, "type")) {
                    if (!strcasecmp(param->value, "home")) {
                        type = "personal";
                    }
                    else if (!strcasecmp(param->value, "work")) {
                        type = "work";
                    }
                    else if (!strcasecmp(param->value, "pref")) {
                        if (defaultIndex < 0)
                            defaultIndex = i;
                    }
                }
                else if (!strcasecmp(param->name, "label")) {
                    label = param->value;
                }
            }
            json_object_set_new(item, "type", json_string(type));
            if (label) json_object_set_new(item, "label", json_string(label));

            json_object_set_new(item, "value", json_string(entry->v.value));

            json_array_append_new(emails, item);
            i++;
        }

        if (defaultIndex < 0)
            defaultIndex = 0;
        int size = json_array_size(emails);
        for (i = 0; i < size; i++) {
            json_t *item = json_array_get(emails, i);
            json_object_set_new(item, "isDefault",
                                i == defaultIndex ? json_true() : json_false());
        }

        json_object_set_new(obj, "emails", emails);
    }

    /* address - we need to open code this, because it's repeated */
    if (_wantprop(props, "phones")) {
        json_t *phones = json_array();

        struct vparse_entry *entry;
        for (entry = card->properties; entry; entry = entry->next) {
            if (strcasecmp(entry->name, "tel")) continue;
            json_t *item = json_pack("{}");
            const struct vparse_param *param;
            const char *type = "other";
            const char *label = NULL;
            for (param = entry->params; param; param = param->next) {
                if (!strcasecmp(param->name, "type")) {
                    if (!strcasecmp(param->value, "home")) {
                        type = "home";
                    }
                    else if (!strcasecmp(param->value, "work")) {
                        type = "work";
                    }
                    else if (!strcasecmp(param->value, "cell")) {
                        type = "mobile";
                    }
                    else if (!strcasecmp(param->value, "mobile")) {
                        type = "mobile";
                    }
                    else if (!strcasecmp(param->value, "fax")) {
                        type = "fax";
                    }
                    else if (!strcasecmp(param->value, "pager")) {
                        type = "pager";
                    }
                }
                else if (!strcasecmp(param->name, "label")) {
                    label = param->value;
                }
            }
            json_object_set_new(item, "type", json_string(type));
            if (label) json_object_set_new(item, "label", json_string(label));

            json_object_set_new(item, "value", json_string(entry->v.value));

            json_array_append_new(phones, item);
        }

        json_object_set_new(obj, "phones", phones);
    }

    /* address - we need to open code this, because it's repeated */
    if (_wantprop(props, "online")) {
        json_t *online = json_array();

        struct vparse_entry *entry;
        for (entry = card->properties; entry; entry = entry->next) {
            if (!strcasecmp(entry->name, "url")) {
                json_t *item = json_pack("{}");
                const struct vparse_param *param;
                const char *label = NULL;
                for (param = entry->params; param; param = param->next) {
                    if (!strcasecmp(param->name, "label")) {
                        label = param->value;
                    }
                }
                json_object_set_new(item, "type", json_string("uri"));
                if (label) json_object_set_new(item, "label", json_string(label));
                json_object_set_new(item, "value", json_string(entry->v.value));
                json_array_append_new(online, item);
            }
            if (!strcasecmp(entry->name, "impp")) {
                json_t *item = json_pack("{}");
                const struct vparse_param *param;
                const char *label = NULL;
                for (param = entry->params; param; param = param->next) {
                    if (!strcasecmp(param->name, "x-service-type")) {
                        label = _servicetype(param->value);
                    }
                }
                json_object_set_new(item, "type", json_string("username"));
                if (label) json_object_set_new(item, "label", json_string(label));
                json_object_set_new(item, "value", json_string(entry->v.value));
                json_array_append_new(online, item);
            }
            if (!strcasecmp(entry->name, "x-social-profile")) {
                json_t *item = json_pack("{}");
                const struct vparse_param *param;
                const char *label = NULL;
                const char *value = NULL;
                for (param = entry->params; param; param = param->next) {
                    if (!strcasecmp(param->name, "type")) {
                        label = _servicetype(param->value);
                    }
                    if (!strcasecmp(param->name, "x-user")) {
                        value = param->value;
                    }
                }
                json_object_set_new(item, "type", json_string("username"));
                if (label) json_object_set_new(item, "label", json_string(label));
                json_object_set_new(item, "value",
                                    json_string(value ? value : entry->v.value));
                json_array_append_new(online, item);
            }
            if (!strcasecmp(entry->name, "x-fm-online-other")) {
                json_t *item = json_pack("{}");
                const struct vparse_param *param;
                const char *label = NULL;
                for (param = entry->params; param; param = param->next) {
                    if (!strcasecmp(param->name, "label")) {
                        label = param->value;
                    }
                }
                json_object_set_new(item, "type", json_string("other"));
                if (label) json_object_set_new(item, "label", json_string(label));
                json_object_set_new(item, "value", json_string(entry->v.value));
                json_array_append_new(online, item);
            }
        }

        json_object_set_new(obj, "online", online);
    }

    if (_wantprop(props, "nickname")) {
        const char *item = vparse_stringval(card, "nickname");
        json_object_set_new(obj, "nickname", json_string(item ? item : ""));
    }

    if (_wantprop(props, "anniversary")) {
        struct vparse_entry *entry = vparse_get_entry(card, NULL, "anniversary");
        _date_to_jmap(entry, &buf);
        json_object_set_new(obj, "anniversary", json_string(buf_cstring(&buf)));
    }

    if (_wantprop(props, "birthday")) {
        struct vparse_entry *entry = vparse_get_entry(card, NULL, "bday");
        _date_to_jmap(entry, &buf);
        json_object_set_new(obj, "birthday", json_string(buf_cstring(&buf)));
    }

    if (_wantprop(props, "notes")) {
        const char *item = vparse_stringval(card, "note");
        json_object_set_new(obj, "notes", json_string(item ? item : ""));
    }

    if (_wantprop(props, "x-hasPhoto")) {
        const char *item = vparse_stringval(card, "photo");
        json_object_set_new(obj, "x-hasPhoto",
                            item ? json_true() : json_false());
    }

    /* XXX - other fields */

    buf_free(&buf);
    if (empty) strarray_free(empty);
    return obj;
}

static int getcontacts_cb(void *rock, struct carddav_data *cdata)
{
    struct cards_rock *crock = (struct cards_rock *) rock;
    struct index_record record;
    int r = 0;

    if (!crock->mailbox || strcmp(crock->mailbox->name, cdata->dav.mailbox)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(cdata->dav.mailbox, &crock->mailbox);
        if (r) return r;
    }

    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) return r;

    crock->rows++;

    /* Load message containing the resource and parse vcard data */
    struct vparse_card *vcard = record_to_vcard(crock->mailbox, &record);
    if (!vcard || !vcard->objects) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                cdata->dav.imap_uid, crock->mailbox->name);
        vparse_free_card(vcard);
        return IMAP_INTERNAL;
    }

    /* Convert the VCARD to a JMAP contact. */
    json_t *obj = jmap_contact_from_vcard(vcard->objects, cdata, &record,
                                          crock->props, crock->mailbox->name);
    json_array_append_new(crock->array, obj);

    vparse_free_card(vcard);

    return 0;
}

static int getContacts(struct jmap_req *req)
{
    return jmap_contacts_get(req, &getcontacts_cb, CARDDAV_KIND_CONTACT, "contacts");
}

static int getContactUpdates(struct jmap_req *req)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;
    struct buf buf = BUF_INITIALIZER;
    int r = -1;
    json_t *invalid = NULL; /* invalid property array */
    int pe; /* property parse error */

    /* Parse and validate arguments. */
    invalid = json_pack("[]");

    json_int_t max_records = 0;
    pe = readprop(req->args, "maxChanges", 0 /*mandatory*/, invalid, "i", &max_records);
    if (pe > 0) {
        if (max_records <= 0) {
            json_array_append_new(invalid, json_string("maxChanges"));
        }
    }

    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    const char *since = _json_object_get_string(req->args, "sinceState");
    if (!since) goto done;
    modseq_t oldmodseq = atomodseq_t(since);

    char *mboxname = NULL;
    json_t *abookid = json_object_get(req->args, "addressbookId");
    if (abookid && json_string_value(abookid)) {
        /* XXX - invalid arguments */
        const char *addressbookId = json_string_value(abookid);
        mboxname = carddav_mboxname(req->userid, addressbookId);
    }

    r = carddav_create_defaultaddressbook(req->userid);
    if (r) goto done;

    /* Lookup updates. */
    struct updates_rock rock;
    memset(&rock, 0, sizeof(struct updates_rock));
    rock.changed = json_array();
    rock.removed = json_array();
    rock.fetchmodseq = 1;
    rock.max_records = max_records;

    r = carddav_get_updates(db, oldmodseq, mboxname, CARDDAV_KIND_CONTACT,
                            &getcontactupdates_cb, &rock);
    mailbox_close(&rock.mailbox);
    if (r) goto done;

    strip_spurious_deletes(&rock);

    /* Determine new state. */
    modseq_t newstate;
    int more = rock.max_records ? rock.seen_records > rock.max_records : 0;
    if (more) {
        newstate = rock.highestmodseq;
    } else {
        newstate = req->counters.carddavmodseq;
    }

    json_t *contactUpdates = json_pack("{}");
    buf_printf(&buf, MODSEQ_FMT, newstate);
    json_object_set_new(contactUpdates, "newState", json_string(buf_cstring(&buf)));
    buf_reset(&buf);
    json_object_set_new(contactUpdates, "accountId", json_string(req->userid));
    json_object_set_new(contactUpdates, "oldState", json_string(since));
    json_object_set_new(contactUpdates, "hasMoreUpdates", json_boolean(more));
    json_object_set(contactUpdates, "changed", rock.changed);
    json_object_set(contactUpdates, "removed", rock.removed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactUpdates"));
    json_array_append_new(item, contactUpdates);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

    json_t *dofetch = json_object_get(req->args, "fetchRecords");
    json_t *doprops = json_object_get(req->args, "fetchRecordProperties");
    if (dofetch && json_is_true(dofetch)) {
        struct jmap_req subreq = *req;
        subreq.args = json_pack("{}");
        json_object_set(subreq.args, "ids", rock.changed);
        if (doprops) json_object_set(subreq.args, "properties", doprops);
        if (abookid) {
            json_object_set(subreq.args, "addressbookId", abookid);
        }
        r = getContacts(&subreq);
        json_decref(subreq.args);
    }

    json_decref(rock.changed);
    json_decref(rock.removed);

  done:
    carddav_close(db);
    buf_free(&buf);
    return r;
}

typedef struct contact_filter {
    hash_table *inContactGroup;
    json_t *isFlagged;
    const char *text;
    const char *prefix;
    const char *firstName;
    const char *lastName;
    const char *suffix;
    const char *nickname;
    const char *company;
    const char *department;
    const char *jobTitle;
    const char *email;
    const char *phone;
    const char *online;
    const char *address;
    const char *notes;
} contact_filter;

typedef struct contact_filter_rock {
    struct carddav_db *carddavdb;
    struct carddav_data *cdata;
    json_t *contact;
} contact_filter_rock;

/* Match the contact in rock against filter. */
static int contact_filter_match(void *vf, void *rock)
{
    contact_filter *f = (contact_filter *) vf;
    contact_filter_rock *cfrock = (contact_filter_rock*) rock;
    json_t *contact = cfrock->contact;
    struct carddav_data *cdata = cfrock->cdata;
    struct carddav_db *db = cfrock->carddavdb;

    /* isFlagged */
    if (JNOTNULL(f->isFlagged)) {
        json_t *isFlagged = json_object_get(contact, "isFlagged");
        if (f->isFlagged != isFlagged) {
            return 0;
        }
    }
    /* text */
    if (f->text && !jmap_match_jsonprop(contact, NULL, f->text)) {
        return 0;
    }
    /*  prefix */
    if (f->prefix && !jmap_match_jsonprop(contact, "prefix", f->prefix)) {
        return 0;
    }
    /* firstName */
    if (f->firstName && !jmap_match_jsonprop(contact, "firstName", f->firstName)) {
        return 0;
    }
    /* lastName */
    if (f->lastName && !jmap_match_jsonprop(contact, "lastName", f->lastName)) {
        return 0;
    }
    /*  suffix */
    if (f->suffix && !jmap_match_jsonprop(contact, "suffix", f->suffix)) {
        return 0;
    }
    /*  nickname */
    if (f->nickname && !jmap_match_jsonprop(contact, "nickname", f->nickname)) {
        return 0;
    }
    /*  company */
    if (f->company && !jmap_match_jsonprop(contact, "company", f->company)) {
        return 0;
    }
    /*  department */
    if (f->department && !jmap_match_jsonprop(contact, "department", f->department)) {
        return 0;
    }
    /*  jobTitle */
    if (f->jobTitle && !jmap_match_jsonprop(contact, "jobTitle", f->jobTitle)) {
        return 0;
    }
    /* email */
    if (f->email && json_object_get(contact, "emails")) {
        size_t i;
        json_t *email;
        int m = 0;
        json_array_foreach(json_object_get(contact, "emails"), i, email) {
            m = jmap_match_jsonprop(email, NULL, f->email);
            if (m) break;
        }
        if (!m) return 0;
    }
    /*  phone */
    if (f->phone && json_object_get(contact, "phones")) {
        size_t i;
        json_t *phone;
        int m = 0;
        json_array_foreach(json_object_get(contact, "phones"), i, phone) {
            m = jmap_match_jsonprop(phone, NULL, f->phone);
            if (m) break;
        }
        if (!m) return 0;
    }
    /*  online */
    if (f->online && json_object_get(contact, "online")) {
        size_t i;
        json_t *online;
        int m = 0;
        json_array_foreach(json_object_get(contact, "online"), i, online) {
            m = jmap_match_jsonprop(online, NULL, f->online);
            if (m) break;
        }
        if (!m) return 0;
    }
    /* address */
    if (f->address && json_object_get(contact, "addresses")) {
        size_t i;
        json_t *address;
        int m = 0;
        json_array_foreach(json_object_get(contact, "addresses"), i, address) {
            m = jmap_match_jsonprop(address, NULL, f->address);
            if (m) break;
        }
        if (!m) return 0;
    }
    /*  notes */
    if (f->notes && !jmap_match_jsonprop(contact, "notes", f->notes)) {
        return 0;
    }
    /* inContactGroup */
    if (f->inContactGroup) {
        /* XXX Calling carddav_db for every contact isn't really efficient. If
         * this turns out to be a performance issue, the carddav_db API might
         * support lookup contacts by group ids. */
        strarray_t *gids = carddav_getuid_groups(db, cdata->vcard_uid);
        if (!gids) {
            syslog(LOG_INFO, "carddav_getuid_groups(%s) returned NULL group array",
                    cdata->vcard_uid);
            return 0;
        }
        int i, m = 0;
        for (i = 0; i < gids->count; i++) {
            if (hash_lookup(strarray_nth(gids, i), f->inContactGroup)) {
                m = 1;
                break;
            }
        }
        strarray_free(gids);
        if (!m) return 0;
    }

    /* All matched. */
    return 1;
}

/* Free the memory allocated by this contact filter. */
static void contact_filter_free(void *vf)
{
    contact_filter *f = (contact_filter*) vf;
    if (f->inContactGroup) {
        free_hash_table(f->inContactGroup, NULL);
        free(f->inContactGroup);
    }
    free(f);
}

/* Parse the JMAP Contact FilterCondition in arg.
 * Report any invalid properties in invalid, prefixed by prefix.
 * Return NULL on error. */
static void *contact_filter_parse(json_t *arg,
                                   const char *prefix,
                                   json_t *invalid)
{
    contact_filter *f = (contact_filter *) xzmalloc(sizeof(struct contact_filter));
    struct buf buf = BUF_INITIALIZER;

    /* inContactGroup */
    json_t *inContactGroup = json_object_get(arg, "inContactGroup");
    if (inContactGroup && json_typeof(inContactGroup) != JSON_ARRAY) {
        buf_printf(&buf, "%s.inContactGroup", prefix);
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    } else if (inContactGroup) {
        f->inContactGroup = xmalloc(sizeof(struct hash_table));
        construct_hash_table(f->inContactGroup, json_array_size(inContactGroup)+1, 0);
        size_t i;
        json_t *val;
        json_array_foreach(inContactGroup, i, val) {
            buf_printf(&buf, "%s.inContactGroup[%zu]", prefix, i);
            const char *id;
            if (json_unpack(val, "s", &id) != -1) {
                hash_insert(id, (void*)1, f->inContactGroup);
            } else {
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
            }
            buf_reset(&buf);
        }
    }

    /* isFlagged */
    f->isFlagged = json_object_get(arg, "isFlagged");

    /* text */
    if (JNOTNULL(json_object_get(arg, "text"))) {
        readprop_full(arg, prefix, "text", 0, invalid, "s", &f->text);
    }
    /* prefix */
    if (JNOTNULL(json_object_get(arg, "prefix"))) {
        readprop_full(arg, prefix, "prefix", 0, invalid, "s", &f->prefix);
    }
    /* firstName */
    if (JNOTNULL(json_object_get(arg, "firstName"))) {
        readprop_full(arg, prefix, "firstName", 0, invalid, "s", &f->firstName);
    }
    /* lastName */
    if (JNOTNULL(json_object_get(arg, "lastName"))) {
        readprop_full(arg, prefix, "lastName", 0, invalid, "s", &f->lastName);
    }
    /* suffix */
    if (JNOTNULL(json_object_get(arg, "suffix"))) {
        readprop_full(arg, prefix, "suffix", 0, invalid, "s", &f->suffix);
    }
    /* nickname */
    if (JNOTNULL(json_object_get(arg, "nickname"))) {
        readprop_full(arg, prefix, "nickname", 0, invalid, "s", &f->nickname);
    }
    /* company */
    if (JNOTNULL(json_object_get(arg, "company"))) {
        readprop_full(arg, prefix, "company", 0, invalid, "s", &f->company);
    }
    /* department */
    if (JNOTNULL(json_object_get(arg, "department"))) {
        readprop_full(arg, prefix, "department", 0, invalid, "s", &f->department);
    }
    /* jobTitle */
    if (JNOTNULL(json_object_get(arg, "jobTitle"))) {
        readprop_full(arg, prefix, "jobTitle", 0, invalid, "s", &f->jobTitle);
    }
    /* email */
    if (JNOTNULL(json_object_get(arg, "email"))) {
        readprop_full(arg, prefix, "email", 0, invalid, "s", &f->email);
    }
    /* phone */
    if (JNOTNULL(json_object_get(arg, "phone"))) {
        readprop_full(arg, prefix, "phone", 0, invalid, "s", &f->phone);
    }
    /* online */
    if (JNOTNULL(json_object_get(arg, "online"))) {
        readprop_full(arg, prefix, "online", 0, invalid, "s", &f->online);
    }
    /* address */
    if (JNOTNULL(json_object_get(arg, "address"))) {
        readprop_full(arg, prefix, "address", 0, invalid, "s", &f->address);
    }
    /* notes */
    if (JNOTNULL(json_object_get(arg, "notes"))) {
        readprop_full(arg, prefix, "notes", 0, invalid, "s", &f->notes);
    }

    buf_free(&buf);

    return f;
}

struct contactlist_rock {
    jmap_filter *filter;
    size_t position;
    size_t limit;
    size_t total;
    json_t *contacts;

    struct mailbox *mailbox;
    struct carddav_db *carddavdb;
};

static int getcontactlist_cb(void *rock, struct carddav_data *cdata) {
    struct contactlist_rock *crock = (struct contactlist_rock*) rock;
    struct index_record record;
    json_t *contact = NULL;
    int r = 0;

    if (!cdata->dav.alive || !cdata->dav.rowid || !cdata->dav.imap_uid) {
        return 0;
    }

    /* Ignore anything but contacts. */
    if (cdata->kind != CARDDAV_KIND_CONTACT) {
        return 0;
    }


    /* Open mailbox. */
    if (!crock->mailbox || strcmp(crock->mailbox->name, cdata->dav.mailbox)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(cdata->dav.mailbox, &crock->mailbox);
        if (r) goto done;
    }

    /* Load record. */
    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) goto done;

    /* Load contact from record. */
    struct vparse_card *vcard = record_to_vcard(crock->mailbox, &record);
    if (!vcard || !vcard->objects) {
        syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                cdata->dav.imap_uid, crock->mailbox->name);
        vparse_free_card(vcard);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Convert the VCARD to a JMAP contact. */
    /* XXX If this conversion turns out to waste too many cycles, then first
     * initialize props with any non-NULL field in filter f or its subconditions. */
    contact = jmap_contact_from_vcard(vcard->objects, cdata, &record,
                                      NULL /* props */, crock->mailbox->name);
    vparse_free_card(vcard);

    /* Match the contact against the filter and update statistics. */
    struct contact_filter_rock cfrock;
    cfrock.carddavdb = crock->carddavdb;
    cfrock.cdata = cdata;
    cfrock.contact = contact;
    if (crock->filter && !jmap_filter_match(crock->filter, &contact_filter_match, &cfrock)) {
        goto done;
    }
    crock->total++;
    if (crock->position > crock->total) {
        goto done;
    }
    if (crock->limit && crock->limit >= json_array_size(crock->contacts)) {
        goto done;
    }

    /* All done. Add the contact identifier. */
    json_array_append_new(crock->contacts, json_string(cdata->vcard_uid));

done:
    if (contact) json_decref(contact);
    return r;
}

static int getContactList(struct jmap_req *req)
{
    int r = 0, pe;
    json_t *invalid;
    int dofetch = 0;
    json_t *filter;
    struct contactlist_rock rock;
    struct carddav_db *db;

    memset(&rock, 0, sizeof(struct contactlist_rock));

    db = carddav_open_userid(req->userid);
    if (!db) {
        syslog(LOG_ERR, "carddav_open_userid failed for user %s", req->userid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Parse and validate arguments. */
    invalid = json_pack("[]");

    /* filter */
    filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        rock.filter = jmap_filter_parse(filter, "filter", invalid, contact_filter_parse);
    }

    /* position */
    json_int_t pos = 0;
    if (JNOTNULL(json_object_get(req->args, "position"))) {
        pe = readprop(req->args, "position", 0 /*mandatory*/, invalid, "i", &pos);
        if (pe > 0 && pos < 0) {
            json_array_append_new(invalid, json_string("position"));
        }
    }
    rock.position = pos;

    /* limit */
    json_int_t limit = 0;
    if (JNOTNULL(json_object_get(req->args, "limit"))) {
        pe = readprop(req->args, "limit", 0 /*mandatory*/, invalid, "i", &limit);
        if (pe > 0 && limit < 0) {
            json_array_append_new(invalid, json_string("limit"));
        }
    }
    rock.limit = limit;

    /* fetchRecords */
    if (JNOTNULL(json_object_get(req->args, "fetchRecords"))) {
        readprop(req->args, "fetchRecords", 0 /*mandatory*/, invalid, "b", &dofetch);
    }

    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Inspect every entry in this accounts addressbok mailboxes. */
    rock.contacts = json_pack("[]");
    rock.carddavdb = db;
    r = carddav_foreach(db, NULL, getcontactlist_cb, &rock);
    if (rock.mailbox) mailbox_close(&rock.mailbox);
    if (r) goto done;

    /* Prepare response. */
    json_t *contactList = json_pack("{}");
    json_object_set_new(contactList, "accountId", json_string(req->userid));
    json_object_set_new(contactList, "state", jmap_getstate(MBTYPE_CALENDAR, req));
    json_object_set_new(contactList, "position", json_integer(rock.position));
    json_object_set_new(contactList, "total", json_integer(rock.total));
    json_object_set(contactList, "contactIds", rock.contacts);
    if (filter) json_object_set(contactList, "filter", filter);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactList"));
    json_array_append_new(item, contactList);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

    /* Fetch updated records, if requested. */
    if (dofetch && json_array_size(rock.contacts)) {
        struct jmap_req subreq = *req;
        subreq.args = json_pack("{}");
        json_object_set(subreq.args, "ids", rock.contacts);
        r = getContacts(&subreq);
        json_decref(subreq.args);
    }

done:
    if (rock.filter) jmap_filter_free(rock.filter, contact_filter_free);
    if (rock.contacts) json_decref(rock.contacts);
    if (db) carddav_close(db);
    return r;
}

static struct vparse_entry *_card_multi(struct vparse_card *card,
                                        const char *name)
{
    struct vparse_entry *res = vparse_get_entry(card, NULL, name);
    if (!res) {
        res = vparse_add_entry(card, NULL, name, NULL);
        res->multivalue = 1;
        res->v.values = strarray_new();
    }
    return res;
}

static int _emails_to_card(struct vparse_card *card, json_t *arg, json_t *invalid)
{
    vparse_delete_entries(card, NULL, "email");

    int i;
    int size = json_array_size(arg);
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < size; i++) {
        json_t *item = json_array_get(arg, i);

        buf_printf(&buf, "emails[%d]", i);
        const char *prefix = buf_cstring(&buf);

        /* Parse properties. */
        const char *type = NULL;
        const char *label = NULL;
        const char *value = NULL;
        int pe; /* parse error */

        pe = readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        pe = readprop_full(item, prefix, "value", 1, invalid, "s", &value);
        pe = readprop_full(item, prefix, "label", 0, invalid, "s", &label);
        json_t *jisDefault = json_object_get(item, "isDefault");

        /* Bail out for any property errors. */
        if (!type || !value || pe < 0) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
        struct vparse_entry *entry =
            vparse_add_entry(card, NULL, "email", value);

        if (!strcmpsafe(type, "personal"))
            type = "home";
        if (strcmpsafe(type, "other"))
            vparse_add_param(entry, "type", type);

        if (label)
            vparse_add_param(entry, "label", label);

        if (jisDefault && json_is_true(jisDefault))
            vparse_add_param(entry, "type", "pref");

        buf_reset(&buf);
    }
    buf_free(&buf);
    return 0;
}

static int _phones_to_card(struct vparse_card *card, json_t *arg, json_t *invalid)
{
    vparse_delete_entries(card, NULL, "tel");

    int i;
    int size = json_array_size(arg);
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < size; i++) {
        json_t *item = json_array_get(arg, i);

        buf_printf(&buf, "phones[%d]", i);
        const char *prefix = buf_cstring(&buf);

        /* Parse properties. */
        const char *type = NULL;
        const char *label = NULL;
        const char *value = NULL;
        int pe; /* parse error */

        pe = readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        pe = readprop_full(item, prefix, "value", 1, invalid, "s", &value);
        if (JNOTNULL(json_object_get(item, "label"))) {
            pe = readprop_full(item, prefix, "label", 0, invalid, "s", &label);
        }

        /* Bail out for any property errors. */
        if (!type || !value || pe < 0) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
        struct vparse_entry *entry = vparse_add_entry(card, NULL, "tel", value);

        if (!strcmp(type, "mobile"))
            vparse_add_param(entry, "type", "cell");
        else if (strcmp(type, "other"))
            vparse_add_param(entry, "type", type);

        if (label)
            vparse_add_param(entry, "label", label);

        buf_reset(&buf);
    }
    buf_free(&buf);
    return 0;
}

static int _is_im(const char *type)
{
    /* add new services here */
    if (!strcasecmp(type, "aim")) return 1;
    if (!strcasecmp(type, "facebook")) return 1;
    if (!strcasecmp(type, "gadugadu")) return 1;
    if (!strcasecmp(type, "googletalk")) return 1;
    if (!strcasecmp(type, "icq")) return 1;
    if (!strcasecmp(type, "jabber")) return 1;
    if (!strcasecmp(type, "msn")) return 1;
    if (!strcasecmp(type, "qq")) return 1;
    if (!strcasecmp(type, "skype")) return 1;
    if (!strcasecmp(type, "twitter")) return 1;
    if (!strcasecmp(type, "yahoo")) return 1;

    return 0;
}

static int _online_to_card(struct vparse_card *card, json_t *arg, json_t *invalid)
{
    vparse_delete_entries(card, NULL, "url");
    vparse_delete_entries(card, NULL, "impp");
    vparse_delete_entries(card, NULL, "x-social-profile");
    vparse_delete_entries(card, NULL, "x-fm-online-other");

    int i;
    int size = json_array_size(arg);
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < size; i++) {
        json_t *item = json_array_get(arg, i);

        buf_printf(&buf, "online[%d]", i);
        const char *prefix = buf_cstring(&buf);

        /* Parse properties. */
        const char *type = NULL;
        const char *label = NULL;
        const char *value = NULL;
        int pe; /* parse error */

        pe = readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        pe = readprop_full(item, prefix, "value", 1, invalid, "s", &value);
        if (JNOTNULL(json_object_get(item, "label"))) {
            pe = readprop_full(item, prefix, "label", 0, invalid, "s", &label);
        }

        /* Bail out for any property errors. */
        if (!type || !value || pe < 0) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
        if (!strcmp(type, "uri")) {
            struct vparse_entry *entry =
                vparse_add_entry(card, NULL, "url", value);
            if (label)
                vparse_add_param(entry, "label", label);
        }
        else if (!strcmp(type, "username")) {
            if (label && _is_im(label)) {
                struct vparse_entry *entry =
                    vparse_add_entry(card, NULL, "impp", value);
                vparse_add_param(entry, "x-service-type", label);
            }
            else {
                struct vparse_entry *entry =
                    vparse_add_entry(card, NULL, "x-social-profile", ""); // XXX - URL calculated, ick
                if (label)
                    vparse_add_param(entry, "type", label);
                vparse_add_param(entry, "x-user", value);
            }
        }
        else if (!strcmp(type, "other")) {
            struct vparse_entry *entry = vparse_add_entry(card, NULL, "x-fm-online-other", value);
            if (label)
                vparse_add_param(entry, "label", label);
        }
    }
    buf_free(&buf);
    return 0;
}

static int _addresses_to_card(struct vparse_card *card, json_t *arg, json_t *invalid)
{
    vparse_delete_entries(card, NULL, "adr");

    int i;
    int size = json_array_size(arg);
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < size; i++) {
        json_t *item = json_array_get(arg, i);

        buf_printf(&buf, "addresses[%d]", i);
        const char *prefix = buf_cstring(&buf);

        /* Parse properties. */
        const char *type = NULL;
        const char *label = NULL;
        const char *street = NULL;
        const char *locality = NULL;
        const char *region = NULL;
        const char *postcode = NULL;
        const char *country = NULL;
        int pe; /* parse error */

        /* Mandatory */
        pe = readprop_full(item, prefix, "type", 1, invalid, "s", &type);
        pe = readprop_full(item, prefix, "street", 1, invalid, "s", &street);
        pe = readprop_full(item, prefix, "locality", 1, invalid, "s", &locality);
        pe = readprop_full(item, prefix, "region", 1, invalid, "s", &region);
        pe = readprop_full(item, prefix, "postcode", 1, invalid, "s", &postcode);
        pe = readprop_full(item, prefix, "country", 1, invalid, "s", &country);

        /* Optional */
        if (JNOTNULL(json_object_get(item, "label"))) {
            pe = readprop_full(item, prefix, "label", 0, invalid, "s", &label);
        }

        /* Bail out for any property errors. */
        if (!type || !street || !locality || !region || !postcode || !country || pe < 0) {
            buf_free(&buf);
            return -1;
        }

        /* Update card. */
        struct vparse_entry *entry = vparse_add_entry(card, NULL, "adr", NULL);

        if (strcmpsafe(type, "other"))
            vparse_add_param(entry, "type", type);

        if (label)
            vparse_add_param(entry, "label", label);

        entry->multivalue = 1;
        entry->v.values = strarray_new();
        strarray_append(entry->v.values, ""); // PO Box
        strarray_append(entry->v.values, ""); // Extended Address
        strarray_append(entry->v.values, street);
        strarray_append(entry->v.values, locality);
        strarray_append(entry->v.values, region);
        strarray_append(entry->v.values, postcode);
        strarray_append(entry->v.values, country);

        buf_reset(&buf);
    }

    buf_free(&buf);
    return 0;
}

static int _date_to_card(struct vparse_card *card,
                         const char *key, json_t *jval)
{
    if (!jval)
        return -1;
    const char *val = json_string_value(jval);
    if (!val)
        return -1;

    /* JMAP dates are always YYYY-MM-DD */
    unsigned y, m, d;
    if (_parse_date(val, &y, &m, &d, 1))
        return -1;

    /* range checks. month and day just get basic sanity checks because we're
     * not carrying a full calendar implementation here. JMAP says zero is valid
     * so we'll allow that and deal with it later on */
    if (m > 12 || d > 31)
        return -1;

    /* all years are valid in JMAP, but ISO8601 only allows Gregorian ie >= 1583.
     * moreover, iOS uses 1604 as a magic number for "unknown", so we'll say 1605
     * is the minimum */
    if (y > 0 && y < 1605)
        return -1;

    /* everything in range. now comes the fun bit. vCard v3 says BDAY is
     * YYYY-MM-DD. It doesn't reference ISO8601 (vCard v4 does) and make no
     * provision for "unknown" date components, so there's no way to represent
     * JMAP's "unknown" values. Apple worked around this for year by using the
     * year 1604 and adding the parameter X-APPLE-OMIT-YEAR=1604 (value
     * apparently ignored). We will use a similar hack for month and day so we
     * can convert it back into a JMAP date */

    int no_year = 0;
    if (y == 0) {
        no_year = 1;
        y = 1604;
    }

    int no_month = 0;
    if (m == 0) {
        no_month = 1;
        m = 1;
    }

    int no_day = 0;
    if (d == 0) {
        no_day = 1;
        d = 1;
    }

    vparse_delete_entries(card, NULL, key);

    /* no values, we're done! */
    if (no_year && no_month && no_day)
        return 0;

    /* build the value */
    static char buf[11];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d", y, m, d);
    struct vparse_entry *entry = vparse_add_entry(card, NULL, key, buf);

    /* set all the round-trip flags, sigh */
    if (no_year)
        vparse_add_param(entry, "x-apple-omit-year", "1604");
    if (no_month)
        vparse_add_param(entry, "x-fm-no-month", "1");
    if (no_day)
        vparse_add_param(entry, "x-fm-no-day", "1");

    return 0;
}

static int _kv_to_card(struct vparse_card *card, const char *key, json_t *jval)
{
    if (!jval)
        return -1;
    const char *val = json_string_value(jval);
    if (!val)
        return -1;
    vparse_replace_entry(card, NULL, key, val);
    return 0;
}

static void _make_fn(struct vparse_card *card)
{
    struct vparse_entry *n = vparse_get_entry(card, NULL, "n");
    strarray_t *name = strarray_new();
    const char *v;

    if (n) {
        v = strarray_safenth(n->v.values, 3); // prefix
        if (*v) strarray_append(name, v);

        v = strarray_safenth(n->v.values, 1); // first
        if (*v) strarray_append(name, v);

        v = strarray_safenth(n->v.values, 2); // middle
        if (*v) strarray_append(name, v);

        v = strarray_safenth(n->v.values, 0); // last
        if (*v) strarray_append(name, v);

        v = strarray_safenth(n->v.values, 4); // suffix
        if (*v) strarray_append(name, v);
    }

    if (!strarray_size(name)) {
        v = vparse_stringval(card, "nickname");
        if (v && v[0]) strarray_append(name, v);
    }

    char *fn = NULL;
    if (strarray_size(name))
        fn = strarray_join(name, " ");
    else
        fn = xstrdup(" ");

    strarray_free(name);
    vparse_replace_entry(card, NULL, "fn", fn);
    free(fn);
}

static int _json_to_card(const char *uid,
                         struct vparse_card *card,
                         json_t *arg, strarray_t *flags,
                         struct entryattlist **annotsp,
                         json_t *invalid)
{
    const char *key;
    json_t *jval;
    struct vparse_entry *fn = vparse_get_entry(card, NULL, "fn");
    int name_is_dirty = 0;
    int record_is_dirty = 0;
    /* we'll be updating you later anyway... create early so that it's
     * at the top of the card */
    if (!fn) {
        fn = vparse_add_entry(card, NULL, "fn", "No Name");
        name_is_dirty = 1;
    }

    json_object_foreach(arg, key, jval) {
        if (!strcmp(key, "isFlagged")) {
            if (json_is_true(jval)) {
                strarray_add_case(flags, "\\Flagged");
            } else if (json_is_false(jval)) {
                strarray_remove_all_case(flags, "\\Flagged");
            } else {
                json_array_append_new(invalid, json_string("isFlagged"));
                return -1;
            }
        }
        else if (!strcmp(key, "x-importance")) {
            double dval = json_number_value(jval);
            const char *ns = DAV_ANNOT_NS "<" XML_NS_CYRUS ">importance";
            const char *attrib = "value.shared";
            struct buf buf = BUF_INITIALIZER;
            if (dval) {
                buf_printf(&buf, "%e", dval);
            }
            setentryatt(annotsp, ns, attrib, &buf);
            buf_free(&buf);
        }
        else if (!strcmp(key, "avatar")) {
            /* XXX - file handling */
        }
        else if (!strcmp(key, "prefix")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("prefix"));
                return -1;
            }
            name_is_dirty = 1;
            struct vparse_entry *n = _card_multi(card, "n");
            strarray_set(n->v.values, 3, val);
        }
        else if (!strcmp(key, "firstName")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("firstName"));
                return -1;
            }
            name_is_dirty = 1;
            /* JMAP doesn't have a separate field for Middle (aka "Additional
             * Names"), so any extra names are probably in firstName, and we
             * should split them out. See reverse of this in getcontacts_cb */
            struct vparse_entry *n = _card_multi(card, "n");
            const char *middle = strchr(val, ' ');
            if (middle) {
                /* multiple worlds, first to First, rest to Middle */
                strarray_setm(n->v.values, 1, xstrndup(val, middle-val));
                strarray_set(n->v.values, 2, ++middle);
            }
            else {
                /* single word, set First, clear Middle */
                strarray_set(n->v.values, 1, val);
                strarray_set(n->v.values, 2, "");
            }
        }
        else if (!strcmp(key, "lastName")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("lastName"));
                return -1;
            }
            name_is_dirty = 1;
            struct vparse_entry *n = _card_multi(card, "n");
            strarray_set(n->v.values, 0, val);
        }
        else if (!strcmp(key, "suffix")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("suffix"));
                return -1;
            }
            name_is_dirty = 1;
            struct vparse_entry *n = _card_multi(card, "n");
            strarray_set(n->v.values, 4, val);
        }
        else if (!strcmp(key, "nickname")) {
            int r = _kv_to_card(card, "nickname", jval);
            if (r) {
                json_array_append_new(invalid, json_string("nickname"));
                return r;
            }
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "birthday")) {
            int r = _date_to_card(card, "bday", jval);
            if (r) {
                json_array_append_new(invalid, json_string("birthday"));
                return r;
            }
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "anniversary")) {
            int r = _date_to_card(card, "anniversary", jval);
            if (r) {
                json_array_append_new(invalid, json_string("anniversary"));
                return r;
            }
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "jobTitle")) {
            int r = _kv_to_card(card, "title", jval);
            if (r) {
                json_array_append_new(invalid, json_string("jobTitle"));
                return r;
            }
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "company")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("company"));
                return -1;
            }
            struct vparse_entry *org = _card_multi(card, "org");
            strarray_set(org->v.values, 0, val);
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "department")) {
            const char *val = json_string_value(jval);
            if (!val) {
                json_array_append_new(invalid, json_string("department"));
                return -1;
            }
            struct vparse_entry *org = _card_multi(card, "org");
            strarray_set(org->v.values, 1, val);
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "emails")) {
            int r = _emails_to_card(card, jval, invalid);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "phones")) {
            int r = _phones_to_card(card, jval, invalid);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "online")) {
            int r = _online_to_card(card, jval, invalid);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "addresses")) {
            int r = _addresses_to_card(card, jval, invalid);
            if (r) return r;
            record_is_dirty = 1;
        }
        else if (!strcmp(key, "notes")) {
            int r = _kv_to_card(card, "note", jval);
            if (r) {
                json_array_append_new(invalid, json_string("notes"));
                return r;
            }
            record_is_dirty = 1;
        } if (!strcmp(key, "id")) {
            const char *val = json_string_value(jval);
            if (!val || (uid && strcmp(uid, val))) {
                json_array_append_new(invalid, json_string("id"));
                return -1;
            }
        }
    }

    if (name_is_dirty) {
        _make_fn(card);
        record_is_dirty = 1;
    }

    if (!record_is_dirty)
        return 204;  /* no content */

    return 0;
}

static int setContacts(struct jmap_req *req)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;

    struct mailbox *mailbox = NULL;
    struct mailbox *newmailbox = NULL;

    int r = 0;
    json_t *jcheckState = json_object_get(req->args, "ifInState");
    if (jcheckState && jmap_checkstate(jcheckState, MBTYPE_ADDRESSBOOK, req)) {
        json_t *item = json_pack("[s, {s:s}, s]",
                "error", "type", "stateMismatch",
                req->tag);
        json_array_append_new(req->response, item);
        goto done;
    }
    json_t *set = json_pack("{s:o,s:s}",
                            "oldState", jmap_getstate(MBTYPE_ADDRESSBOOK, req),
                            "accountId", req->userid);

    r = carddav_create_defaultaddressbook(req->userid);
    if (r) goto done;

    json_t *create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");
        json_t *record;

        const char *key;
        json_t *arg;
        json_object_foreach(create, key, arg) {
            const char *uid = makeuuid();
            strarray_t *flags = strarray_new();
            struct entryattlist *annots = NULL;

            const char *addressbookId = "Default";
            json_t *abookid = json_object_get(arg, "addressbookId");
            if (abookid && json_string_value(abookid)) {
                /* XXX - invalid arguments */
                addressbookId = json_string_value(abookid);
            }
            char *mboxname = mboxname_abook(req->userid, addressbookId);
            json_object_del(arg, "addressbookId");
            addressbookId = NULL;

            struct vparse_card *card = vparse_new_card("VCARD");
            vparse_add_entry(card, NULL, "VERSION", "3.0");
            vparse_add_entry(card, NULL, "UID", uid);

            /* we need to create and append a record */
            if (!mailbox || strcmp(mailbox->name, mboxname)) {
                mailbox_close(&mailbox);
                r = mailbox_open_iwl(mboxname, &mailbox);
                if (r) {
                    free(mboxname);
                    vparse_free_card(card);
                    goto done;
                }
            }

            json_t *invalid = json_pack("[]");
            r = _json_to_card(uid, card, arg, flags, &annots, invalid);
            if (r || json_array_size(invalid)) {
                /* this is just a failure */
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "invalidProperties");
                if (json_array_size(invalid)) {
                    json_object_set(err, "properties", invalid);
                }
                json_decref(invalid);
                json_object_set_new(notCreated, key, err);
                strarray_free(flags);
                freeentryatts(annots);
                vparse_free_card(card);
                continue;
            }
            json_decref(invalid);

            syslog(LOG_NOTICE, "jmap: create contact %s/%s (%s)",
                   req->userid, mboxname, uid);
            r = carddav_store(mailbox, card, NULL,
                              flags, annots, req->userid, req->authstate, ignorequota);
            vparse_free_card(card);
            free(mboxname);
            strarray_free(flags);
            freeentryatts(annots);

            if (r) {
                goto done;
            }

            record = json_pack("{s:s}", "id", uid);
            json_object_set_new(created, key, record);

            /* hash_insert takes ownership of uid here, skanky I know */
            hash_insert(key, xstrdup(uid), req->idmap);
        }

        if (json_object_size(created))
            json_object_set(set, "created", created);
        json_decref(created);
        if (json_object_size(notCreated))
            json_object_set(set, "notCreated", notCreated);
        json_decref(notCreated);
    }

    json_t *update = json_object_get(req->args, "update");
    if (update) {
        json_t *updated = json_pack("[]");
        json_t *notUpdated = json_pack("{}");

        const char *uid;
        json_t *arg;
        json_object_foreach(update, uid, arg) {
            struct carddav_data *cdata = NULL;
            r = carddav_lookup_uid(db, uid, &cdata);
            uint32_t olduid;
            char *resource = NULL;

            if (r || !cdata || !cdata->dav.imap_uid
                  || cdata->kind != CARDDAV_KIND_CONTACT) {
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }
            olduid = cdata->dav.imap_uid;
            resource = xstrdup(cdata->dav.resource);

            if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
                mailbox_close(&mailbox);
                r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
                if (r) {
                    syslog(LOG_ERR, "IOERROR: failed to open %s",
                           cdata->dav.mailbox);
                    goto done;
                }
            }

            json_t *abookid = json_object_get(arg, "addressbookId");
            if (abookid && json_string_value(abookid)) {
                const char *mboxname =
                    mboxname_abook(req->userid, json_string_value(abookid));
                if (strcmp(mboxname, cdata->dav.mailbox)) {
                    /* move */
                    r = mailbox_open_iwl(mboxname, &newmailbox);
                    if (r) {
                        syslog(LOG_ERR, "IOERROR: failed to open %s", mboxname);
                        goto done;
                    }
                }
                json_object_del(arg, "addressbookId");
            }

            struct index_record record;

            r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record);
            if (r) goto done;

            strarray_t *flags =
                mailbox_extract_flags(mailbox, &record, req->userid);
            struct entryattlist *annots =
                mailbox_extract_annots(mailbox, &record);

            /* Load message containing the resource and parse vcard data */
            struct vparse_card *vcard = record_to_vcard(mailbox, &record);
            if (!vcard || !vcard->objects) {
                syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                       cdata->dav.imap_uid, mailbox->name);
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "parseError");
                json_object_set_new(notUpdated, uid, err);
                vparse_free_card(vcard);
                strarray_free(flags);
                freeentryatts(annots);
                mailbox_close(&newmailbox);
                free(resource);
                continue;
            }
            struct vparse_card *card = vcard->objects;

            json_t *invalid = json_pack("[]");

            r = _json_to_card(uid, card, arg, flags, &annots, invalid);
            if (r == 204) {
                r = 0;
                if (!newmailbox) {
                    /* just bump the modseq
                       if in the same mailbox and no data change */
                    syslog(LOG_NOTICE, "jmap: touch contact %s/%s",
                           req->userid, resource);
                    if (strarray_find_case(flags, "\\Flagged", 0) >= 0)
                        record.system_flags |= FLAG_FLAGGED;
                    else
                        record.system_flags &= ~FLAG_FLAGGED;
                    annotate_state_t *state = NULL;
                    r = mailbox_get_annotate_state(mailbox, record.uid, &state);
                    annotate_state_set_auth(state, 0,
                                            req->userid, req->authstate);
                    if (!r) r = annotate_state_store(state, annots);
                    if (!r) r = mailbox_rewrite_index_record(mailbox, &record);
                    json_decref(invalid);
                    goto finish;
                }
            }
            if (r || json_array_size(invalid)) {
                /* this is just a failure to create the JSON, not an error */
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "invalidProperties");
                if (json_array_size(invalid)) {
                    json_object_set(err, "properties", invalid);
                }
                json_decref(invalid);
                json_object_set_new(notUpdated, uid, err);
                vparse_free_card(vcard);
                strarray_free(flags);
                freeentryatts(annots);
                mailbox_close(&newmailbox);
                free(resource);
                continue;
            }
            json_decref(invalid);

            syslog(LOG_NOTICE, "jmap: update contact %s/%s",
                   req->userid, resource);
            r = carddav_store(newmailbox ? newmailbox : mailbox, card, resource,
                              flags, annots, req->userid, req->authstate, ignorequota);
            if (!r)
                r = carddav_remove(mailbox, olduid, /*isreplace*/!newmailbox, req->userid);

         finish:
            mailbox_close(&newmailbox);
            strarray_free(flags);
            freeentryatts(annots);

            vparse_free_card(vcard);
            free(resource);

            if (r) goto done;

            json_array_append_new(updated, json_string(uid));
        }

        if (json_array_size(updated))
            json_object_set(set, "updated", updated);
        json_decref(updated);
        if (json_object_size(notUpdated))
            json_object_set(set, "notUpdated", notUpdated);
        json_decref(notUpdated);
    }

    json_t *destroy = json_object_get(req->args, "destroy");
    if (destroy) {
        json_t *destroyed = json_pack("[]");
        json_t *notDestroyed = json_pack("{}");

        size_t index;
        for (index = 0; index < json_array_size(destroy); index++) {
            const char *uid = _json_array_get_string(destroy, index);
            if (!uid) {
                json_t *err = json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }
            struct carddav_data *cdata = NULL;
            uint32_t olduid;
            r = carddav_lookup_uid(db, uid, &cdata);

            if (r || !cdata || !cdata->dav.imap_uid
                  || cdata->kind != CARDDAV_KIND_CONTACT) {
                r = 0;
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }
            olduid = cdata->dav.imap_uid;

            if (!mailbox || strcmp(mailbox->name, cdata->dav.mailbox)) {
                mailbox_close(&mailbox);
                r = mailbox_open_iwl(cdata->dav.mailbox, &mailbox);
                if (r) goto done;
            }

            syslog(LOG_NOTICE, "jmap: remove contact %s/%s", req->userid, uid);
            r = carddav_remove(mailbox, olduid, /*isreplace*/0, req->userid);
            if (r) {
                syslog(LOG_ERR, "IOERROR: setContacts remove failed for %s %u",
                       mailbox->name, olduid);
                goto done;
            }

            json_array_append_new(destroyed, json_string(uid));
        }

        if (json_array_size(destroyed))
            json_object_set(set, "destroyed", destroyed);
        json_decref(destroyed);
        if (json_object_size(notDestroyed))
            json_object_set(set, "notDestroyed", notDestroyed);
        json_decref(notDestroyed);
    }

    /* force modseq to stable */
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    /* read the modseq again every time, just in case something changed it
     * in our actions */
    if (json_object_get(set, "created") ||
        json_object_get(set, "updated") ||
        json_object_get(set, "destroyed")) {

        r = jmap_bumpstate(MBTYPE_ADDRESSBOOK, req);
        if (r) goto done;
    }
    json_object_set_new(set, "newState", jmap_getstate(MBTYPE_ADDRESSBOOK, req));

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("contactsSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    mailbox_close(&newmailbox);
    mailbox_close(&mailbox);

    carddav_close(db);
    return r;
}


/*****************************************************************************
 * JMAP Calendars API
 ****************************************************************************/

/* Helper flags for setCalendarEvents */
#define JMAP_CREATE     (1<<0) /* Current request is a create. */
#define JMAP_UPDATE     (1<<1) /* Current request is an update. */
#define JMAP_DESTROY    (1<<2) /* Current request is a destroy. */
#define JMAP_EXC        (1<<8) /* Current component is a VEVENT exception .*/

typedef struct calevent_rock {
    struct jmap_req *req;    /* The current JMAP request. */
    int flags;               /* Flags indicating the request context. */
    const char *uid;         /* The iCalendar UID of this event. */
    int isAllDay;            /* This event is a whole-day event. */

    json_t *invalid;         /* A JSON array of any invalid properties. */

    icalcomponent *comp;     /* The current main event of an exception. */
    icalcomponent *oldcomp;  /* The former main event of an exception */

    icaltimetype dtstart;      /* The start of this or the main event. */
    icaltimetype dtend;        /* The end of this or the main event. */
    icaltimezone *tzstart_old; /* The former startTimeZone. */
    icaltimezone *tzstart;     /* The current startTimeZone. */
    icaltimezone *tzend_old;   /* The former endTimeZone. */
    icaltimezone *tzend;       /* The current endTimeZone. */

    icaltimezone **tzs;      /* Timezones required as VTIMEZONEs. */
    size_t n_tzs;            /* The count of timezones. */
    size_t s_tzs;            /* The size of the timezone array. */
} calevent_rock;

/* Return a non-zero value if uid maps to a special-purpose calendar mailbox,
 * that may not be read or modified by the user. */
static int jmap_calendar_ishidden(const char *uid) {
    if (!strcmp(uid, "#calendars")) return 1;
    /* SCHED_INBOX  and SCHED_OUTBOX end in "/", so trim them */
    if (!strncmp(uid, SCHED_INBOX, strlen(SCHED_INBOX)-1)) return 1;
    if (!strncmp(uid, SCHED_OUTBOX, strlen(SCHED_OUTBOX)-1)) return 1;
    if (!strncmp(uid, MANAGED_ATTACH, strlen(MANAGED_ATTACH)-1)) return 1;
    return 0;
}

struct calendars_rock {
    struct jmap_req *req;
    json_t *array;
    struct hash_table *props;
    struct mailbox *mailbox;
    int rows;
};

/* Determine, if mboxname is a Cyrus calendar mailbox AND is able to
 * store VEVENTs. Store the result in is_cal.
 *
 * By default, any Cyrus calendar mailbox is able to store VEVENTs,
 * unless this is explicitly ruled out by setting the
 * {CALDAV}:supported-calendar-component-set property on the mailbox.
 *
 * userid must be allowed to lookup annotations on mboxname.
 *
 * Return non-zero on error. */
static int jmap_mboxname_is_calendar(const char *mboxname, const char *userid, int *is_cal)
{
    struct buf attrib = BUF_INITIALIZER;
    static const char *calcompset_annot =
        DAV_ANNOT_NS "<" XML_NS_CALDAV ">supported-calendar-component-set";
    unsigned long types = -1; /* ALL component types by default. */

    if (!mboxname_iscalendarmailbox(mboxname, 0)) {
        *is_cal = 0;
        return 0;
    }

    int r = annotatemore_lookupmask(mboxname, calcompset_annot, userid, &attrib);
    if (r) goto done;
    if (attrib.len) {
        types = strtoul(buf_cstring(&attrib), NULL, 10);
    }
    *is_cal = types & CAL_COMP_VEVENT;
done:
    buf_free(&attrib);
    return r;
}

static int getcalendars_cb(const mbentry_t *mbentry, void *rock)
{
    struct calendars_rock *crock = (struct calendars_rock *)rock;
    int r;

    /* Only calendars... */
    if (!(mbentry->mbtype & MBTYPE_CALENDAR)) return 0;

    /* ...which are at least readable or visible... */
    int rights = httpd_myrights(crock->req->authstate, mbentry->acl);
    /* XXX - What if just READFB is set? */
    if (!(rights & (DACL_READ|DACL_READFB))) {
        return 0;
    }

    /* ...and contain VEVENTs. */
    int is_cal = 0;
    r = jmap_mboxname_is_calendar(mbentry->name, httpd_userid, &is_cal);
    if (r || !is_cal) {
        goto done;
    }

    /* OK, we want this one... */
    const char *collection = strrchr(mbentry->name, '.') + 1;

    /* ...unless it's one of the special names. */
    if (jmap_calendar_ishidden(collection)) return 0;

    crock->rows++;

    json_t *obj = json_pack("{}");

    json_object_set_new(obj, "id", json_string(collection));

    if (_wantprop(crock->props, "x-href")) {
        _add_xhref(obj, mbentry->name, NULL);
    }

    if (_wantprop(crock->props, "name")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *displayname_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
        r = annotatemore_lookupmask(mbentry->name, displayname_annot, httpd_userid, &attrib);
        /* fall back to last part of mailbox name */
        if (r || !attrib.len) buf_setcstr(&attrib, collection);
        json_object_set_new(obj, "name", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (_wantprop(crock->props, "color")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-color";
        r = annotatemore_lookupmask(mbentry->name, color_annot, httpd_userid, &attrib);
        if (!r && attrib.len)
            json_object_set_new(obj, "color", json_string(buf_cstring(&attrib)));
        buf_free(&attrib);
    }

    if (_wantprop(crock->props, "sortOrder")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *order_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-order";
        r = annotatemore_lookupmask(mbentry->name, order_annot, httpd_userid, &attrib);
        if (!r && attrib.len) {
            char *ptr;
            long val = strtol(buf_cstring(&attrib), &ptr, 10);
            if (ptr && *ptr == '\0') {
                json_object_set_new(obj, "sortOrder", json_integer(val));
            }
            else {
                /* Ignore, but report non-numeric calendar-order values */
                syslog(LOG_WARNING, "sortOrder: strtol(%s) failed", buf_cstring(&attrib));
            }
        }
        buf_free(&attrib);
    }

    if (_wantprop(crock->props, "isVisible")) {
        struct buf attrib = BUF_INITIALIZER;
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">X-FM-isVisible";
        r = annotatemore_lookupmask(mbentry->name, color_annot, httpd_userid, &attrib);
        if (!r && attrib.len) {
            const char *val = buf_cstring(&attrib);
            if (!strncmp(val, "true", 4) || !strncmp(val, "1", 1)) {
                json_object_set_new(obj, "isVisible", json_true());
            } else if (!strncmp(val, "false", 5) || !strncmp(val, "0", 1)) {
                json_object_set_new(obj, "isVisible", json_false());
            } else {
                /* Report invalid value and fall back to default. */
                syslog(LOG_WARNING, "isVisible: invalid annotation value: %s", val);
                json_object_set_new(obj, "isVisible", json_string("true"));
            }
        }
        buf_free(&attrib);
    }

    if (_wantprop(crock->props, "mayReadFreeBusy")) {
        int bool = rights & DACL_READFB;
        json_object_set_new(obj, "mayReadFreeBusy", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayReadItems")) {
        int bool = rights & DACL_READ;
        json_object_set_new(obj, "mayReadItems", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayAddItems")) {
        int bool = rights & DACL_WRITECONT;
        json_object_set_new(obj, "mayAddItems", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayModifyItems")) {
        int bool = rights & DACL_WRITECONT;
        json_object_set_new(obj, "mayModifyItems", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayRemoveItems")) {
        int bool = rights & DACL_RMRES;
        json_object_set_new(obj, "mayRemoveItems", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayRename")) {
        int bool = rights & DACL_RMCOL;
        json_object_set_new(obj, "mayRename", bool ? json_true() : json_false());
    }

    if (_wantprop(crock->props, "mayDelete")) {
        int bool = rights & DACL_RMCOL;
        json_object_set_new(obj, "mayDelete", bool ? json_true() : json_false());
    }

    json_array_append_new(crock->array, obj);

done:
    return r;
}


/* jmap calendar APIs */

/* Update the calendar properties in the calendar mailbox named mboxname.
 * NULL values and negative integers are ignored. Return 0 on success. */
static int jmap_update_calendar(const char *mboxname,
                                const struct jmap_req *req,
                                const char *name,
                                const char *color,
                                int sortOrder,
                                int isVisible)
{
    struct mailbox *mbox = NULL;
    int rights;
    annotate_state_t *astate = NULL;
    struct buf val = BUF_INITIALIZER;
    int r;

    r = mailbox_open_iwl(mboxname, &mbox);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                mboxname, error_message(r));
        return r;
    }
    rights = mbox->acl ? cyrus_acl_myrights(req->authstate, mbox->acl) : 0;
    if (!(rights & DACL_READ)) {
        r = IMAP_MAILBOX_NONEXISTENT;
    } else if (!(rights & DACL_WRITE)) {
        r = IMAP_PERMISSION_DENIED;
    }
    if (r) {
        return r;
    }

    r = mailbox_get_annotate_state(mbox, 0, &astate);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open annotations %s: %s",
                mbox->name, error_message(r));
    }
    /* name */
    if (!r && name) {
        buf_setcstr(&val, name);
        static const char *displayname_annot =
            DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
        r = annotate_state_writemask(astate, displayname_annot, httpd_userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    displayname_annot, error_message(r));
        }
        buf_reset(&val);
    }
    /* color */
    if (!r && color) {
        buf_setcstr(&val, color);
        static const char *color_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-color";
        r = annotate_state_writemask(astate, color_annot, httpd_userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    color_annot, error_message(r));
        }
        buf_reset(&val);
    }
    /* sortOrder */
    if (!r && sortOrder >= 0) {
        buf_printf(&val, "%d", sortOrder);
        static const char *sortOrder_annot =
            DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-order";
        r = annotate_state_writemask(astate, sortOrder_annot, httpd_userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    sortOrder_annot, error_message(r));
        }
        buf_reset(&val);
    }
    /* isVisible */
    if (!r && isVisible >= 0) {
        buf_setcstr(&val, isVisible ? "true" : "false");
        static const char *sortOrder_annot =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">X-FM-isVisible";
        r = annotate_state_writemask(astate, sortOrder_annot, httpd_userid, &val);
        if (r) {
            syslog(LOG_ERR, "failed to write annotation %s: %s",
                    sortOrder_annot, error_message(r));
        }
        buf_reset(&val);
    }

    buf_free(&val);

    if (r) {
        mailbox_abort(mbox);
    }
    mailbox_close(&mbox);
    return r;
}

/* Delete the calendar mailbox named mboxname for the userid in req. */
static int jmap_delete_calendar(const char *mboxname, const struct jmap_req *req) {
    struct mailbox *mbox = NULL;
    int r;

    r = mailbox_open_irl(mboxname, &mbox);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
                mboxname, error_message(r));
        return r;
    }
    int rights = mbox->acl ? cyrus_acl_myrights(req->authstate, mbox->acl) : 0;

    mailbox_close(&mbox);
    if (!(rights & DACL_READ)) {
        return IMAP_NOTFOUND;
    } else if (!(rights & DACL_RMCOL)) {
        return IMAP_PERMISSION_DENIED;
    }

    struct caldav_db *db = caldav_open_userid(req->userid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->userid);
        return IMAP_INTERNAL;
    }
    /* XXX 
     * JMAP spec says that: "A calendar MAY be deleted that is currently
     * associated with one or more events. In this case, the events belonging
     * to this calendar MUST also be deleted. Conceptually, this MUST happen
     * prior to the calendar itself being deleted, and MUST generate a push
     * event that modifies the calendarState for the account, and has a
     * clientId of null, to indicate that a change has been made to the
     * calendar data not explicitly requested by the client."
     *
     * Need the Events API for this requirement.
     */
    r = caldav_delmbox(db, mboxname);
    if (r) {
        syslog(LOG_ERR, "failed to delete mailbox from caldav_db: %s",
                error_message(r));
        return r;
    }

    struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_DELETE);
    if (mboxlist_delayed_delete_isenabled()) {
        r = mboxlist_delayed_deletemailbox(mboxname,
                httpd_userisadmin || httpd_userisproxyadmin,
                httpd_userid, req->authstate, mboxevent,
                1 /* checkacl */, 0 /* local_only */, 0 /* force */);
    } else {
        r = mboxlist_deletemailbox(mboxname,
                httpd_userisadmin || httpd_userisproxyadmin,
                httpd_userid, req->authstate, mboxevent,
                1 /* checkacl */, 0 /* local_only */, 0 /* force */);
    }
    mboxevent_free(&mboxevent);

    int rr = caldav_close(db);
    if (!r) r = rr;

    return r;
}

static int getCalendars(struct jmap_req *req)
{
    struct calendars_rock rock;
    int r = 0;

    r = caldav_create_defaultcalendars(req->userid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;

    rock.array = json_pack("[]");
    rock.req = req;
    rock.props = NULL;
    rock.rows = 0;

    json_t *properties = json_object_get(req->args, "properties");
    if (properties && json_array_size(properties)) {
        rock.props = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(rock.props, json_array_size(properties), 0);
        int i;
        int size = json_array_size(properties);
        for (i = 0; i < size; i++) {
            const char *id = json_string_value(json_array_get(properties, i));
            if (id == NULL) continue;
            /* 1 == properties */
            hash_insert(id, (void *)1, rock.props);
        }
    }

    json_t *want = json_object_get(req->args, "ids");
    json_t *notfound = json_array();
    if (want) {
        int i;
        int size = json_array_size(want);
        for (i = 0; i < size; i++) {
            const char *id = json_string_value(json_array_get(want, i));
            rock.rows = 0;
            char *mboxname = caldav_mboxname(req->userid, id);
            r = mboxlist_mboxtree(mboxname, &getcalendars_cb, &rock, MBOXTREE_SKIP_CHILDREN);
            free(mboxname);
            if (r) goto done;
            if (!rock.rows) {
                json_array_append_new(notfound, json_string(id));
            }
        }
    }
    else {
        r = mboxlist_usermboxtree(req->userid, &getcalendars_cb, &rock, /*flags*/0);
        if (r) goto done;
    }

    json_t *calendars = json_pack("{}");
    json_incref(rock.array);
    json_object_set_new(calendars, "accountId", json_string(req->userid));
    json_object_set_new(calendars, "state", jmap_getstate(MBTYPE_CALENDAR, req));
    json_object_set_new(calendars, "list", rock.array);
    if (json_array_size(notfound)) {
        json_object_set_new(calendars, "notFound", notfound);
    }
    else {
        json_decref(notfound);
        json_object_set_new(calendars, "notFound", json_null());
    }

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendars"));
    json_array_append_new(item, calendars);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    if (rock.props) {
        free_hash_table(rock.props, NULL);
        free(rock.props);
    }
    json_decref(rock.array);
    return r;
}

struct calendarupdates_rock {
    modseq_t oldmodseq;
    json_t *changed;
    json_t *removed;
};

static int getcalendarupdates_cb(const mbentry_t *mbentry, void *vrock) {
    struct calendarupdates_rock *rock = (struct calendarupdates_rock *) vrock;
    /* Ignore any mailboxes aren't (possibly deleted) calendars. */
    if (!(mbentry->mbtype & (MBTYPE_CALENDAR|MBTYPE_DELETED))) {
        return 0;
    }
    /* Ignore special-purpose calendar mailboxes. */
    const char *uid = strrchr(mbentry->name, '.');
    if (uid) {
        uid++;
    } else {
        uid = mbentry->name;
    }
    if (jmap_calendar_ishidden(uid)) {
        return 0;
    }
    int iscal;
    jmap_mboxname_is_calendar(mbentry->name, httpd_userid, &iscal);
    if (!iscal) {
        return 0;
    }

    /* Ignore old changes. */
    if (mbentry->foldermodseq <= rock->oldmodseq) {
        return 0;
    }

    /* Report this calendar as changed or removed. */
    if (mbentry->mbtype & MBTYPE_CALENDAR) {
        json_array_append_new(rock->changed, json_string(uid));
    } else if (mbentry->mbtype & MBTYPE_DELETED) {
        json_array_append_new(rock->removed, json_string(uid));
    }

    return 0;
}

static int getCalendarUpdates(struct jmap_req *req)
{
    int r, pe;
    json_t *invalid;
    struct caldav_db *db;
    const char *since = NULL;
    int dofetch = 0;
    struct buf buf = BUF_INITIALIZER;
    modseq_t oldmodseq = 0;

    r = caldav_create_defaultcalendars(req->userid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;


    db = caldav_open_userid(req->userid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->userid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Parse and validate arguments. */
    invalid = json_pack("[]");
    pe = readprop(req->args, "sinceState", 1 /*mandatory*/, invalid, "s", &since);
    if (pe > 0) {
        oldmodseq = atomodseq_t(since);
        if (!oldmodseq) {
            json_array_append_new(invalid, json_string("sinceState"));
        }
    }
    readprop(req->args, "fetchRecords", 0 /*mandatory*/, invalid, "b", &dofetch);
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Lookup any updates. */
    char *mboxname = caldav_mboxname(req->userid, NULL);
    struct calendarupdates_rock rock;
    memset(&rock, 0, sizeof(struct calendarupdates_rock));
    rock.oldmodseq = oldmodseq;
    rock.changed = json_pack("[]");
    rock.removed = json_pack("[]");
    r = mboxlist_mboxtree(mboxname, getcalendarupdates_cb, &rock,
            MBOXTREE_TOMBSTONES|MBOXTREE_SKIP_ROOT);
    free(mboxname);
    if (r) {
        json_t *err = json_pack("{s:s}", "type", "cannotCalculateChanges");
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        json_decref(rock.changed);
        json_decref(rock.removed);
        goto done;
    }

    /* Create response. */
    json_t *calendarUpdates = json_pack("{}");
    json_object_set_new(calendarUpdates, "accountId", json_string(req->userid));
    json_object_set_new(calendarUpdates, "oldState", json_string(since));
    json_object_set_new(calendarUpdates, "newState", jmap_getstate(MBTYPE_CALENDAR, req));

    json_object_set_new(calendarUpdates, "changed", rock.changed);
    json_object_set_new(calendarUpdates, "removed", rock.removed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarUpdates"));
    json_array_append_new(item, calendarUpdates);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

    if (dofetch) {
        struct jmap_req subreq = *req; // struct copy, woot
        subreq.args = json_pack("{}");
        json_object_set(subreq.args, "ids", rock.changed);
        r = getCalendars(&subreq);
        json_decref(subreq.args);
    }

  done:
    buf_free(&buf);
    if (db) caldav_close(db);
    return r;
}

static int setCalendars(struct jmap_req *req)
{
    int r = 0;
    json_t *set = NULL;

    json_t *state = json_object_get(req->args, "ifInState");
    if (state && jmap_checkstate(state, MBTYPE_CALENDAR, req)) {
        json_array_append_new(req->response, json_pack("[s, {s:s}, s]",
                    "error", "type", "stateMismatch", req->tag));
        goto done;
    }
    set = json_pack("{s:s}", "accountId", req->userid);
    json_object_set_new(set, "oldState", jmap_getstate(MBTYPE_CALENDAR, req));

    r = caldav_create_defaultcalendars(req->userid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;

    json_t *create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");
        json_t *record;

        const char *key;
        json_t *arg;
        json_object_foreach(create, key, arg) {
            /* Validate calendar id. */
            if (!strlen(key)) {
                json_t *err= json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notCreated, key, err);
                continue;
            }

            /* Parse and validate properties. */
            json_t *invalid = json_pack("[]");
            const char *name = NULL;
            const char *color = NULL;
            int32_t sortOrder = -1;
            int isVisible = 0;
            int pe; /* parse error */
            short flag;

            /* Mandatory properties. */
            pe = readprop(arg, "name", 1,  invalid, "s", &name);
            if (pe > 0 && strnlen(name, 256) == 256) {
                json_array_append_new(invalid, json_string("name"));
            }

            readprop(arg, "color", 1,  invalid, "s", &color);

            pe = readprop(arg, "sortOrder", 1,  invalid, "i", &sortOrder);
            if (pe > 0 && sortOrder < 0) {
                json_array_append_new(invalid, json_string("sortOrder"));
            }
            pe = readprop(arg, "isVisible", 1,  invalid, "b", &isVisible);
            if (pe > 0 && !isVisible) {
                json_array_append_new(invalid, json_string("isVisible"));
            }
            /* Optional properties. If present, these MUST be set to true. */
            flag = 1; readprop(arg, "mayReadFreeBusy", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayReadFreeBusy"));
            }
            flag = 1; readprop(arg, "mayReadItems", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayReadItems"));
            }
            flag = 1; readprop(arg, "mayAddItems", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayAddItems"));
            }
            flag = 1; readprop(arg, "mayModifyItems", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayModifyItems"));
            }
            flag = 1; readprop(arg, "mayRemoveItems", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayRemoveItems"));
            }
            flag = 1; readprop(arg, "mayRename", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayRename"));
            }
            flag = 1; readprop(arg, "mayDelete", 0,  invalid, "b", &flag);
            if (!flag) {
                json_array_append_new(invalid, json_string("mayDelete"));
            }

            /* Report any property errors and bail out. */
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notCreated, key, err);
                continue;
            }
            json_decref(invalid);

            /* Create a calendar named uid. */
            char *uid = xstrdup(makeuuid());
            char *mboxname = caldav_mboxname(req->userid, uid);
            char rights[100];
            struct buf acl = BUF_INITIALIZER;
            buf_reset(&acl);
            cyrus_acl_masktostr(ACL_ALL | DACL_READFB, rights);
            buf_printf(&acl, "%s\t%s\t", httpd_userid, rights);
            cyrus_acl_masktostr(DACL_READFB, rights);
            buf_printf(&acl, "%s\t%s\t", "anyone", rights);
            r = mboxlist_createsync(mboxname, MBTYPE_CALENDAR,
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
                if (r == IMAP_PERMISSION_DENIED) {
                    json_t *err = json_pack("{s:s}", "type", "accountReadOnly");
                    json_object_set_new(notCreated, key, err);
                }
                free(mboxname);
                goto done;
            }
            r = jmap_update_calendar(mboxname, req, name, color, sortOrder, isVisible);
            if (r) {
                free(uid);
                int rr = mboxlist_delete(mboxname);
                if (rr) {
                    syslog(LOG_ERR, "could not delete mailbox %s: %s",
                            mboxname, error_message(rr));
                }
                free(mboxname);
                goto done;
            }
            free(mboxname);

            /* Report calendar as created. */
            record = json_pack("{s:s}", "id", uid);
            json_object_set_new(created, key, record);
            /* hash_insert takes ownership of uid. */
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

            /* Validate uid */
            if (!uid || !strlen(uid) || *uid == '#') {
                json_t *err= json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }
            if (jmap_calendar_ishidden(uid)) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }

            /* Parse and validate properties. */
            json_t *invalid = json_pack("[]");

            const char *name = NULL;
            const char *color = NULL;
            int32_t sortOrder = -1;
            int isVisible = -1;
            int flag;
            int pe = 0; /* parse error */
            pe = readprop(arg, "name", 0,  invalid, "s", &name);
            if (pe > 0 && strnlen(name, 256) == 256) {
                json_array_append_new(invalid, json_string("name"));
            }
            readprop(arg, "color", 0,  invalid, "s", &color);
            pe = readprop(arg, "sortOrder", 0,  invalid, "i", &sortOrder);
            if (pe > 0 && sortOrder < 0) {
                json_array_append_new(invalid, json_string("sortOrder"));
            }
            readprop(arg, "isVisible", 0,  invalid, "b", &isVisible);

            /* The mayFoo properties are immutable and MUST NOT set. */
            pe = readprop(arg, "mayReadFreeBusy", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayReadFreeBusy"));
            }
            pe = readprop(arg, "mayReadItems", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayReadItems"));
            }
            pe = readprop(arg, "mayAddItems", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayAddItems"));
            }
            pe = readprop(arg, "mayModifyItems", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayModifyItems"));
            }
            pe = readprop(arg, "mayRemoveItems", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayRemoveItems"));
            }
            pe = readprop(arg, "mayRename", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayRename"));
            }
            pe = readprop(arg, "mayDelete", 0,  invalid, "b", &flag);
            if (pe > 0) {
                json_array_append_new(invalid, json_string("mayDelete"));
            }

            /* Report any property errors and bail out. */
            if (json_array_size(invalid)) {
                json_t *err = json_pack("{s:s, s:o}",
                        "type", "invalidProperties", "properties", invalid);
                json_object_set_new(notUpdated, uid, err);
                continue;
            }
            json_decref(invalid);

            /* Update the calendar named uid. */
            char *mboxname = caldav_mboxname(req->userid, uid);
            r = jmap_update_calendar(mboxname, req, name, color, sortOrder, isVisible);
            free(mboxname);
            if (r == IMAP_NOTFOUND || r == IMAP_MAILBOX_NONEXISTENT) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                r = 0;
                continue;
            }
            else if (r == IMAP_PERMISSION_DENIED) {
                json_t *err = json_pack("{s:s}", "type", "accountReadOnly");
                json_object_set_new(notUpdated, uid, err);
                r = 0;
                continue;
            }

            /* Report calendar as updated. */
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

            /* Validate uid */
            const char *uid = json_string_value(juid);
            if (!uid || !strlen(uid) || *uid == '#') {
                json_t *err= json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }
            if (jmap_calendar_ishidden(uid)) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }

            /* Do not allow to remove the default calendar. */
            char *mboxname = caldav_mboxname(req->userid, NULL);
            static const char *defaultcal_annot =
                DAV_ANNOT_NS "<" XML_NS_CALDAV ">schedule-default-calendar";
            struct buf attrib = BUF_INITIALIZER;
            r = annotatemore_lookupmask(mboxname, defaultcal_annot, httpd_userid, &attrib);
            free(mboxname);
            const char *defaultcal = "Default";
            if (!r && attrib.len) {
                defaultcal = buf_cstring(&attrib);
            }
            if (!strcmp(uid, defaultcal)) {
                /* XXX - The isDefault set error is not documented in the spec. */
                json_t *err = json_pack("{s:s}", "type", "isDefault");
                json_object_set_new(notDestroyed, uid, err);
                buf_free(&attrib);
                continue;
            }
            buf_free(&attrib);

            /* Destroy calendar. */
            mboxname = caldav_mboxname(req->userid, uid);
            r = jmap_delete_calendar(mboxname, req);
            free(mboxname);
            if (r == IMAP_NOTFOUND || r == IMAP_MAILBOX_NONEXISTENT) {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                r = 0;
                continue;
            } else if (r == IMAP_PERMISSION_DENIED) {
                json_t *err = json_pack("{s:s}", "type", "accountReadOnly");
                json_object_set_new(notDestroyed, uid, err);
                r = 0;
                continue;
            } else if (r) {
                goto done;
            }

            /* Report calendar as destroyed. */
            json_array_append_new(destroyed, json_string(uid));
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

        r = jmap_bumpstate(MBTYPE_CALENDAR, req);
        if (r) goto done;
    }
    json_object_set_new(set, "newState", jmap_getstate(MBTYPE_CALENDAR, req));

    json_incref(set);
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarsSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (set) json_decref(set);
    return r;
}

/* FIXME dup from jmapical.c */
/* Convert the JMAP local datetime in buf to tm time. Return non-zero on success. */
static int localdate_to_tm(const char *buf, struct tm *tm) {
    /* Initialize tm. We don't know about daylight savings time here. */
    memset(tm, 0, sizeof(struct tm));
    tm->tm_isdst = -1;

    /* Parse LocalDate. */
    const char *p = strptime(buf, "%Y-%m-%dT%H:%M:%S", tm);
    if (!p || *p) {
        return 0;
    }
    return 1;
}

/* FIXME dup from jmapical.c */
static int localdate_to_icaltime(const char *buf,
                                 icaltimetype *dt,
                                 icaltimezone *tz,
                                 int is_allday) {
    struct tm tm;
    int r;
    char *s = NULL;
    icaltimetype tmp;
    int is_utc;
    size_t n;

    r = localdate_to_tm(buf, &tm);
    if (!r) return 0;

    if (is_allday && (tm.tm_sec || tm.tm_min || tm.tm_hour)) {
        return 0;
    }

    is_utc = tz == icaltimezone_get_utc_timezone();

    /* Can't use icaltime_from_timet_with_zone since it tries to convert
     * t from UTC into tz. Let's feed ical a DATETIME string, instead. */
    s = xcalloc(19, sizeof(char));
    n = strftime(s, 18, "%Y%m%dT%H%M%S", &tm);
    if (is_utc) {
        s[n]='Z';
    }
    tmp = icaltime_from_string(s);
    free(s);
    if (icaltime_is_null_time(tmp)) {
        return 0;
    }
    tmp.zone = tz;
    tmp.is_date = is_allday;
    *dt = tmp;
    return 1;
}

/* FIXME dup from jmapical.c */
static int utcdate_to_icaltime(const char *src,
                               icaltimetype *dt)
{
    struct buf buf = BUF_INITIALIZER;
    size_t len = strlen(src);
    int r;
    icaltimezone *utc = icaltimezone_get_utc_timezone();

    if (!len || src[len-1] != 'Z') {
        return 0;
    }

    buf_setmap(&buf, src, len-1);
    r = localdate_to_icaltime(buf_cstring(&buf), dt, utc, 0);
    buf_free(&buf);
    return r;
}

static int getcalendarevents_cb(void *rock, struct caldav_data *cdata)
{
    struct calendars_rock *crock = (struct calendars_rock *)rock;
    struct index_record record;
    int r = 0;
    icalcomponent* ical = NULL;
    json_t *obj, *jprops = NULL;
    jmapical_err_t err;

    if (!cdata->dav.alive) {
        return 0;
    }

    /* Open calendar mailbox. */
    if (!crock->mailbox || strcmp(crock->mailbox->name, cdata->dav.mailbox)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(cdata->dav.mailbox, &crock->mailbox);
        if (r) goto done;
    }

    /* Locate calendar event ical data in mailbox. */
    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) goto done;

    crock->rows++;

    /* Load VEVENT from record. */
    ical = record_to_ical(crock->mailbox, &record, NULL);
    if (!ical) {
        syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, crock->mailbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Convert to JMAP */
    memset(&err, 0, sizeof(jmapical_err_t));
    if (crock->props) {
        /* XXX That's clumsy: the JMAP properties have already been converted
         * to a Cyrus hash, but the jmapical API requires a JSON object. */
        strarray_t *keys = hash_keys(crock->props);
        int i;
        for (i = 0; i < strarray_size(keys); i++) {
            json_object_set(jprops, strarray_nth(keys, i), json_null());
        }
        strarray_free(keys);
    }
    obj = jmapical_tojmap(ical, jprops,  &err);
    if (!obj || err.code) {
        syslog(LOG_ERR, "jmapical_tojson: %s\n", jmapical_strerror(err.code));
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Add participant id */
    if (_wantprop(crock->props, "participantId") && crock->req->userid) {
        const char *userid = crock->req->userid;
        const char *id;
        json_t *p;
        struct buf buf = BUF_INITIALIZER;

        json_object_foreach(json_object_get(obj, "participants"), id, p) {
            struct caldav_sched_param sparam;
            const char *addr;

            addr = json_string_value(json_object_get(p, "email"));
            if (!addr) continue;

            buf_setcstr(&buf, "mailto:");
            buf_appendcstr(&buf, addr);

            bzero(&sparam, sizeof(struct caldav_sched_param));
            if (caladdress_lookup(addr, &sparam, userid) || !sparam.isyou) {
                sched_param_free(&sparam);
                continue;
            }

            /* First participant that matches isyou wins */
            json_object_set_new(obj, "participantId", json_string(id));
            sched_param_free(&sparam);
            break;
        }

        buf_free(&buf);
    }

    /* Add JMAP-only fields. */
    if (_wantprop(crock->props, "x-href")) {
        _add_xhref(obj, cdata->dav.mailbox, cdata->dav.resource);
    }
    if (_wantprop(crock->props, "calendarId")) {
        json_object_set_new(obj, "calendarId", json_string(strrchr(cdata->dav.mailbox, '.')+1));
    }
    json_object_set_new(obj, "id", json_string(cdata->ical_uid));

    /* Add JMAP event to response */
    json_array_append_new(crock->array, obj);

done:
    if (ical) icalcomponent_free(ical);
    if (jprops) json_decref(jprops);
    return r;
}

static int getCalendarEvents(struct jmap_req *req)
{
    struct calendars_rock rock;
    int r = 0;

    r = caldav_create_defaultcalendars(req->userid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;

    rock.array = json_pack("[]");
    rock.req = req;
    rock.props = NULL;
    rock.rows = 0;
    rock.mailbox = NULL;

    json_t *properties = json_object_get(req->args, "properties");
    if (properties && json_array_size(properties)) {
        rock.props = xzmalloc(sizeof(struct hash_table));
        construct_hash_table(rock.props, json_array_size(properties), 0);
        int i;
        int size = json_array_size(properties);
        for (i = 0; i < size; i++) {
            const char *id = json_string_value(json_array_get(properties, i));
            if (id == NULL) continue;
            /* 1 == properties */
            hash_insert(id, (void *)1, rock.props);
        }
    }

    struct caldav_db *db = caldav_open_userid(req->userid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->userid);
        r = IMAP_INTERNAL;
        goto done;
    }

    json_t *want = json_object_get(req->args, "ids");
    json_t *notfound = json_array();
    if (want) {
        int i;
        int size = json_array_size(want);
        for (i = 0; i < size; i++) {
            rock.rows = 0;
            const char *id = json_string_value(json_array_get(want, i));
            r = caldav_get_events(db, NULL, id, &getcalendarevents_cb, &rock);
            if (r || !rock.rows) {
                json_array_append_new(notfound, json_string(id));
            }
        }
    } else {
        rock.rows = 0;
        r = caldav_get_events(db, NULL, NULL, &getcalendarevents_cb, &rock);
        if (r) goto done;
    }

    json_t *events = json_pack("{}");
    json_object_set_new(events, "state", jmap_getstate(MBTYPE_CALENDAR, req));

    json_incref(rock.array);
    json_object_set_new(events, "accountId", json_string(req->userid));
    json_object_set_new(events, "list", rock.array);
    if (json_array_size(notfound)) {
        json_object_set_new(events, "notFound", notfound);
    }
    else {
        json_decref(notfound);
        json_object_set_new(events, "notFound", json_null());
    }

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarEvents"));
    json_array_append_new(item, events);
    json_array_append_new(item, json_string(req->tag));

    json_array_append_new(req->response, item);

done:
    if (rock.props) {
        free_hash_table(rock.props, NULL);
        free(rock.props);
    }
    json_decref(rock.array);
    if (db) caldav_close(db);
    if (rock.mailbox) mailbox_close(&rock.mailbox);
    return r;
}

static int jmap_schedule_ical(struct jmap_req *req,
                              char **schedaddrp,
                              icalcomponent *oldical,
                              icalcomponent *ical,
                              int mode)
{
    /* Determine if any scheduling is required. */
    icalcomponent *src = mode&JMAP_DESTROY ? oldical : ical;
    icalcomponent *comp = icalcomponent_get_first_component(src, ICAL_VEVENT_COMPONENT);
    icalproperty *prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (!prop) return 0;
    const char *organizer = icalproperty_get_organizer(prop);
    if (!organizer) return 0;
    if (!strncasecmp(organizer, "mailto:", 7)) organizer += 7;

    if (!*schedaddrp) {
        const char **hdr = spool_getheader(req->txn->req_hdrs, "Schedule-Address");
        if (hdr) *schedaddrp = xstrdup(hdr[0]);
    }

    /* XXX - after legacy records are gone, we can strip this and just not send a
     * cancellation if deleting a record which was never replied to... */
    if (!*schedaddrp) {
        /* userid corresponding to target */
        *schedaddrp = xstrdup(req->userid);

        /* or overridden address-set for target user */
        const char *annotname = DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";
        char *mailboxname = caldav_mboxname(*schedaddrp, NULL);
        struct buf buf = BUF_INITIALIZER;
        int r = annotatemore_lookupmask(mailboxname, annotname,
                                        *schedaddrp, &buf);
        free(mailboxname);
        if (!r && buf.len > 7 && !strncasecmp(buf_cstring(&buf), "mailto:", 7)) {
            free(*schedaddrp);
            *schedaddrp = xstrdup(buf_cstring(&buf) + 7);
        }
        buf_free(&buf);
    }

    /* Validate create/update. */
    if (oldical && (mode & (JMAP_CREATE|JMAP_UPDATE))) {
        /* Don't allow ORGANIZER to be changed */
        const char *oldorganizer = NULL;

        icalcomponent *oldcomp = NULL;
        icalproperty *prop = NULL;
        oldcomp = icalcomponent_get_first_component(oldical, ICAL_VEVENT_COMPONENT);
        if (oldcomp) prop = icalcomponent_get_first_property(oldcomp, ICAL_ORGANIZER_PROPERTY);
        if (prop) oldorganizer = icalproperty_get_organizer(prop);
        if (oldorganizer) {
            if (!strncasecmp(oldorganizer, "mailto:", 7)) oldorganizer += 7;
            if (strcasecmp(oldorganizer, organizer)) {
                /* XXX This should become a set error. */
                return 0;
            }
        }
    }

    if (organizer &&
            /* XXX Hack for Outlook */ icalcomponent_get_first_invitee(comp)) {
        /* Send scheduling message. */
        if (!strcmpsafe(organizer, *schedaddrp)) {
            /* Organizer scheduling object resource */
            sched_request(req->userid, *schedaddrp, oldical, ical);
        } else {
            /* Attendee scheduling object resource */
            sched_reply(req->userid, *schedaddrp, oldical, ical);
        }
    }

    return 0;
}

/* Create, update or destroy the JMAP calendar event. Mode must be one of
 * JMAP_CREATE, JMAP_UPDATE or JMAP_DESTROY. Return 0 for success and non-
 * fatal errors. */
static int jmap_write_calendarevent(json_t *event,
                                    struct caldav_db *db,
                                    const char *id,
                                    const char *uid,
                                    int mode,
                                    json_t *notWritten,
                                    struct jmap_req *req)
{
    int r, rights, pe;
    int needrights = DACL_RMRES|DACL_WRITE;

    struct caldav_data *cdata = NULL;
    struct mailbox *mbox = NULL;
    char *mboxname = NULL;
    struct mailbox *dstmbox = NULL;
    char *dstmboxname = NULL;
    struct mboxevent *mboxevent = NULL;
    char *resource = NULL;

    icalcomponent *oldical = NULL;
    icalcomponent *ical = NULL;
    struct index_record record;
    const char *calendarId = NULL;

    char *schedule_address = NULL;

    if (!(mode & JMAP_DESTROY)) {
        json_t *invalid = json_pack("[]");
        /* Look up the calendarId property. */
        pe = readprop(event, "calendarId", mode & JMAP_CREATE,  invalid, "s", &calendarId);
        if (pe > 0 && !strlen(calendarId)) {
            json_array_append_new(invalid, json_string("calendarId"));
        } else if (pe > 0 && *calendarId == '#') {
            const char *id = (const char *) hash_lookup(calendarId, req->idmap);
            if (id != NULL) {
                calendarId = id;
            } else {
                json_array_append_new(invalid, json_string("calendarId"));
            }
        }
        if (calendarId && jmap_calendar_ishidden(calendarId)) {
            json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
            json_object_set_new(notWritten, id, err);
            r = 0; goto done;
        } else if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s, s:o}",
                    "type", "invalidProperties", "properties", invalid);
            json_object_set_new(notWritten, id, err);
            r = 0; goto done;
        }
        json_decref(invalid);
    }

    /* Handle any calendarId property errors and bail out. */

    /* Determine mailbox and resource name of calendar event. */
    if (mode & (JMAP_UPDATE|JMAP_DESTROY)) {
        r = caldav_lookup_uid(db, uid, &cdata);
        if (r && r != CYRUSDB_NOTFOUND) {
            syslog(LOG_ERR, "caldav_lookup_uid(%s) failed: %s",
                    uid, error_message(r));
            goto done;
        }
        if (r == CYRUSDB_NOTFOUND || !cdata->dav.alive ||
                !cdata->dav.rowid || !cdata->dav.imap_uid) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(notWritten, id, err);
            r = 0; goto done;
        }
        mboxname = xstrdup(cdata->dav.mailbox);
        resource = xstrdup(cdata->dav.resource);
    } else if (mode & JMAP_CREATE) {
        struct buf buf = BUF_INITIALIZER;
        mboxname = caldav_mboxname(req->userid, calendarId);
        buf_printf(&buf, "%s.ics", uid);
        resource = buf_newcstring(&buf);
        buf_free(&buf);
    }

    /* Open mailbox for writing */
    r = mailbox_open_iwl(mboxname, &mbox);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
        json_object_set_new(notWritten, id, err);
        r = 0; goto done;
    } else if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                mboxname, error_message(r));
        goto done;
    }

    /* Check permissions. */
    rights = httpd_myrights(req->authstate, mbox->acl);
    if (!(rights & needrights)) {
        /* Pretend this mailbox does not exist. */
        json_t *err = json_pack("{s:s}", "type", "notFound");
        json_object_set_new(notWritten, id, err);
        r = 0; goto done;
    }

    if (!(mode & JMAP_CREATE)) {
        /* Fetch index record for the resource */
        memset(&record, 0, sizeof(struct index_record));
        r = mailbox_find_index_record(mbox, cdata->dav.imap_uid, &record);
        if (r == IMAP_NOTFOUND) {
            json_t *err = json_pack("{s:s}", "type", "notFound");
            json_object_set_new(notWritten, id, err);
            r = 0; goto done;
        } else if (r) {
            syslog(LOG_ERR, "mailbox_index_record(0x%x) failed: %s",
                    cdata->dav.imap_uid, error_message(r));
            goto done;
        }
        /* Load VEVENT from record. */
        oldical = record_to_ical(mbox, &record, &schedule_address);
        if (!oldical) {
            syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                    cdata->dav.imap_uid, mbox->name);
            r = IMAP_INTERNAL;
            goto done;
        }
    }

    if (!(mode & JMAP_DESTROY)) {
        /* Convert the JMAP calendar event to ical. */
        jmapical_err_t err;
        memset(&err, 0, sizeof(jmapical_err_t));

        if (!json_object_get(event, "uid")) {
            json_object_set_new(event, "uid", json_string(uid));
        }
        ical = jmapical_toical(event, oldical, &err);

        if (err.code == JMAPICAL_ERROR_PROPS) {
            /* Handle any property errors and bail out. */
            json_t *jerr = json_pack("{s:s, s:o}",
                    "type", "invalidProperties", "properties", err.props);
            json_object_set_new(notWritten, id, jerr);
            r = 0; goto done;
        } else if (err.code) {
            syslog(LOG_ERR, "jmapical_toical: %s", jmapical_strerror(err.code));
            r = IMAP_INTERNAL;
            goto done;
        }
    }

    if ((mode & JMAP_UPDATE) && calendarId) {
        /* Check, if we need to move the event. */
        dstmboxname = caldav_mboxname(req->userid, calendarId);
        if (strcmp(mbox->name, dstmboxname)) {
            /* Open destination mailbox for writing. */
            r = mailbox_open_iwl(dstmboxname, &dstmbox);
            if (r == IMAP_MAILBOX_NONEXISTENT) {
                json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
                json_object_set_new(notWritten, id, err);
                r = 0; goto done;
            } else if (r) {
                syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                        dstmboxname, error_message(r));
                goto done;
            }
            /* Check permissions. */
            rights = httpd_myrights(req->authstate, dstmbox->acl);
            if (!(rights & (DACL_WRITE))) {
                json_t *err = json_pack("{s:s}", "type", "calendarNotFound");
                json_object_set_new(notWritten, id, err);
                r = 0; goto done;
            }
        }
    }

    /* Handle scheduling. */
    r = jmap_schedule_ical(req, &schedule_address, oldical, ical, mode);
    if (r) goto done;


    if (mode & JMAP_DESTROY || ((mode & JMAP_UPDATE) && dstmbox)) {
        /* Expunge the resource from mailbox. */
        record.system_flags |= FLAG_EXPUNGED;
        mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);
        r = mailbox_rewrite_index_record(mbox, &record);
        if (r) {
            syslog(LOG_ERR, "mailbox_rewrite_index_record (%s) failed: %s",
                    cdata->dav.mailbox, error_message(r));
            mailbox_close(&mbox);
            goto done;
        }
        mboxevent_extract_record(mboxevent, mbox, &record);
        mboxevent_extract_mailbox(mboxevent, mbox);
        mboxevent_set_numunseen(mboxevent, mbox, -1);
        mboxevent_set_access(mboxevent, NULL, NULL, req->userid, cdata->dav.mailbox, 0);
        mailbox_close(&mbox);
        mboxevent_notify(mboxevent);
        mboxevent_free(&mboxevent);

        if (mode & JMAP_DESTROY) {
            /* Keep the VEVENT in the database but set alive to 0, to report
             * with getCalendarEventUpdates. */
            cdata->dav.alive = 0;
            cdata->dav.modseq = record.modseq;
            cdata->dav.imap_uid = record.uid;
            r = caldav_write(db, cdata);
            goto done;
        } else {
            /* Close the mailbox we moved the event from. */
            mailbox_close(&mbox);
            mbox = dstmbox;
            dstmbox = NULL;
            free(mboxname);
            mboxname = dstmboxname;
            dstmboxname = NULL;
        }
    }

    if (mode & (JMAP_CREATE|JMAP_UPDATE)) {
        /* Store the updated VEVENT. */
        struct transaction_t txn;
        memset(&txn, 0, sizeof(struct transaction_t));
        txn.req_hdrs = spool_new_hdrcache();
        /* XXX - fix userid */
        r = caldav_store_resource(&txn, ical, mbox, resource, db, 0, schedule_address);
        spool_free_hdrcache(txn.req_hdrs);
        buf_free(&txn.buf);
        if (r && r != HTTP_CREATED && r != HTTP_NO_CONTENT) {
            json_t *err = json_pack("{s:s}", "type", "unknownError");
            json_object_set_new(notWritten, id, err);
            goto done;
        }
        r = 0;
    }

done:
    if (mbox) mailbox_close(&mbox);
    if (mboxname) free(mboxname);
    if (dstmbox) mailbox_close(&dstmbox);
    if (dstmboxname) free(dstmboxname);
    if (resource) free(resource);
    if (ical) icalcomponent_free(ical);
    if (oldical) icalcomponent_free(oldical);
    free(schedule_address);
    return r;
}

static int setCalendarEvents(struct jmap_req *req)
{
    struct caldav_db *db = NULL;
    json_t *set = NULL;
    int r = 0;

    json_t *state = json_object_get(req->args, "ifInState");
    if (state && jmap_checkstate(state, MBTYPE_CALENDAR, req)) {
        json_array_append_new(req->response, json_pack("[s, {s:s}, s]",
                    "error", "type", "stateMismatch", req->tag));
        goto done;
    }

    set = json_pack("{s:s}", "accountId", req->userid);
    json_object_set_new(set, "oldState", jmap_getstate(MBTYPE_CALENDAR, req));

    r = caldav_create_defaultcalendars(req->userid);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* The account exists but does not have a root mailbox. */
        json_t *err = json_pack("{s:s}", "type", "accountNoCalendars");
        json_array_append_new(req->response, json_pack("[s,o,s]",
                    "error", err, req->tag));
        return 0;
    } else if (r) return r;

    db = caldav_open_userid(req->userid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->userid);
        r = IMAP_INTERNAL;
        goto done;
    }

    json_t *create = json_object_get(req->args, "create");
    if (create) {
        json_t *created = json_pack("{}");
        json_t *notCreated = json_pack("{}");

        const char *key;
        json_t *arg;
        json_object_foreach(create, key, arg) {
            char *uid = NULL;

            /* Validate calendar event id. */
            if (!strlen(key)) {
                json_t *err= json_pack("{s:s}", "type", "invalidArguments");
                json_object_set_new(notCreated, key, err);
                continue;
            }

            if ((uid = (char *) json_string_value(json_object_get(arg, "uid")))) {
                /* Use custom iCalendar UID from request object */
                uid = xstrdup(uid);
            }  else {
                /* Create a iCalendar UID */
                uid = xstrdup(makeuuid());
            }

            /* Create the calendar event. */
            size_t error_count = json_object_size(notCreated);
            r = jmap_write_calendarevent(arg, db, key, uid, JMAP_CREATE, notCreated, req);
            if (r) {
                free(uid);
                goto done;
            }
            if (error_count != json_object_size(notCreated)) {
                /* Bail out for any setErrors. */
                free(uid);
                continue;
            }

            /* Report calendar event as created. */
            json_object_set_new(created, key, json_pack("{s:s}", "id", uid));
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
            const char *val = NULL;

            /* Validate uid. JMAP update does not allow creation uids here. */
            if (!uid || !strlen(uid) || *uid == '#') {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notUpdated, uid, err);
                continue;
            }

            if ((val = (char *) json_string_value(json_object_get(arg, "uid")))) {
                /* The uid property must match the current iCalendar UID */
                if (strcmp(val, uid)) {
                    json_t *err = json_pack(
                            "{s:s, s:o}",
                            "type", "invalidProperties",
                            "properties", json_pack("[s]"));
                    json_object_set_new(notUpdated, uid, err);
                    continue;
                }
            }

            /* Update the calendar event. */
            size_t error_count = json_object_size(notUpdated);
            r = jmap_write_calendarevent(arg, db, uid, uid, JMAP_UPDATE, notUpdated, req);
            if (r) goto done;
            if (error_count != json_object_size(notUpdated)) {
                /* Bail out for any setErrors. */
                continue;
            }

            /* Report calendar event as updated. */
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
            size_t error_count;
            /* Validate uid. JMAP destroy does not allow reference uids. */
            const char *uid = json_string_value(juid);
            if (!uid || !uid || !strlen(uid) || *uid == '#') {
                json_t *err = json_pack("{s:s}", "type", "notFound");
                json_object_set_new(notDestroyed, uid, err);
                continue;
            }

            /* Destroy the calendar event. */
            error_count = json_object_size(notDestroyed);
            r = jmap_write_calendarevent(NULL, db, uid, uid, JMAP_DESTROY, notDestroyed, req);
            if (r) goto done;
            if (error_count != json_object_size(notDestroyed)) {
                /* Bail out for any setErrors. */
                continue;
            }

            /* Report calendar event as destroyed. */
            json_array_append_new(destroyed, json_string(uid));
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

        r = jmap_bumpstate(MBTYPE_CALENDAR, req);
        if (r) goto done;
    }
    json_object_set_new(set, "newState", jmap_getstate(MBTYPE_CALENDAR, req));

    json_incref(set);
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarEventsSet"));
    json_array_append_new(item, set);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    if (db) caldav_close(db);
    if (set) json_decref(set);
    return r;
}

static int getCalendarEventUpdates(struct jmap_req *req)
{
    int r, pe;
    json_t *invalid;
    struct caldav_db *db;
    const char *since;
    modseq_t oldmodseq = 0;
    json_int_t maxChanges = 0;
    int dofetch = 0;
    struct updates_rock rock;
    struct buf buf = BUF_INITIALIZER;

    /* Initialize rock. */
    memset(&rock, 0, sizeof(struct updates_rock));

    db = caldav_open_userid(req->userid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->userid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Parse and validate arguments. */
    invalid = json_pack("[]");
    pe = readprop(req->args, "sinceState", 1 /*mandatory*/, invalid, "s", &since);
    if (pe > 0) {
        oldmodseq = atomodseq_t(since);
        if (!oldmodseq) {
            json_array_append_new(invalid, json_string("sinceState"));
        }
    }
    pe = readprop(req->args, "maxChanges", 0 /*mandatory*/, invalid, "i", &maxChanges);
    if (pe > 0) {
        if (maxChanges <= 0) {
            json_array_append_new(invalid, json_string("maxChanges"));
        }
    }
    readprop(req->args, "fetchRecords", 0 /*mandatory*/, invalid, "b", &dofetch);
    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    /* Lookup updates. */
    rock.fetchmodseq = 1;
    rock.changed = json_array();
    rock.removed = json_array();
    rock.max_records = maxChanges;
    r = caldav_get_updates(db, oldmodseq, NULL /*mboxname*/, CAL_COMP_VEVENT, 
            maxChanges ? maxChanges + 1 : -1, &geteventupdates_cb, &rock);
    mailbox_close(&rock.mailbox);
    if (r) goto done;
    strip_spurious_deletes(&rock);

    /* Determine new state. */
    modseq_t newstate;
    int more = rock.max_records ? rock.seen_records > rock.max_records : 0;
    if (more) {
        newstate = rock.highestmodseq;
    } else {
        newstate = req->counters.caldavmodseq;
    }

    /* Create response. */
    json_t *eventUpdates = json_pack("{}");
    json_object_set_new(eventUpdates, "accountId", json_string(req->userid));
    json_object_set_new(eventUpdates, "oldState", json_string(since));

    buf_printf(&buf, MODSEQ_FMT, newstate);
    json_object_set_new(eventUpdates, "newState", json_string(buf_cstring(&buf)));
    buf_reset(&buf);

    json_object_set_new(eventUpdates, "hasMoreUpdates", json_boolean(more));
    json_object_set(eventUpdates, "changed", rock.changed);
    json_object_set(eventUpdates, "removed", rock.removed);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarEventUpdates"));
    json_array_append_new(item, eventUpdates);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

    /* Fetch updated records, if requested. */
    if (dofetch) {
        json_t *props = json_object_get(req->args, "fetchRecordProperties");
        struct jmap_req subreq = *req;
        subreq.args = json_pack("{}");
        json_object_set(subreq.args, "ids", rock.changed);
        if (props) json_object_set(subreq.args, "properties", props);
        r = getCalendarEvents(&subreq);
        json_decref(subreq.args);
    }

  done:
    buf_free(&buf);
    if (rock.changed) json_decref(rock.changed);
    if (rock.removed) json_decref(rock.removed);
    if (db) caldav_close(db);
    return r;
}

typedef struct calevent_filter {
    hash_table *calendars;
    icaltimetype after;
    icaltimetype before;
    const char *text;
    const char *summary;
    const char *description;
    const char *location;
    const char *owner;
    const char *attendee;
} calevent_filter;

static int calevent_filter_match_textprop_value(icalproperty *prop,
                                                const char *text)
{
    const char *val = icalproperty_get_value_as_string(prop);
    if (val && jmap_match_text(val, text)) {
        return 1;
    }
    return 0;
}

static int calevent_filter_match_textprop_x(icalcomponent *comp,
                                           const char *text,
                                           const char *name)
{
    icalproperty *prop;
    icalcomponent *ical;

    if (icalcomponent_isa(comp) != ICAL_VEVENT_COMPONENT) {
        return 0;
    }

    ical = icalcomponent_get_parent(comp);
    if (!ical || icalcomponent_isa(ical) != ICAL_VCALENDAR_COMPONENT) {
        return 0;
    }

    /* Look for text in any VEVENT of comp. */
    for (comp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

        for (prop = icalcomponent_get_first_property(comp, ICAL_X_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(comp, ICAL_X_PROPERTY)) {

            if (strcmp(icalproperty_get_x_name(prop), name)) {
                continue;
            }
            if (calevent_filter_match_textprop_value(prop, text)) {
                return 1;
            }
        }
    }

    return 0;
}

/* Match text with icalproperty kind in VEVENT comp and its recurrences. */
static int calevent_filter_match_textprop(icalcomponent *comp,
                                          const char *text,
                                          icalproperty_kind kind)
{
    icalproperty *prop;
    icalcomponent *ical;

    if (icalcomponent_isa(comp) != ICAL_VEVENT_COMPONENT) {
        return 0;
    }

    ical = icalcomponent_get_parent(comp);
    if (!ical || icalcomponent_isa(ical) != ICAL_VCALENDAR_COMPONENT) {
        return 0;
    }

    /* Look for text in any VEVENT of comp. */
    for (comp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {

        for (prop = icalcomponent_get_first_property(comp, kind);
             prop;
             prop = icalcomponent_get_next_property(comp, kind)) {

            if (calevent_filter_match_textprop_value(prop, text)) {
                return 1;
            }
        }
    }

    return 0;
}

typedef struct calevent_filter_rock {
    icalcomponent *ical;
    struct caldav_data *cdata;
} calevent_filter_rock;

/* Match the VEVENTs contained in VCALENDAR component ical against filter. */
static int calevent_filter_match(void *vf, void *rock)
{
    calevent_filter *f = (calevent_filter *) vf;
    calevent_filter_rock *cfrock = (calevent_filter_rock*) rock;

    icalcomponent *ical = cfrock->ical;
    struct caldav_data *cdata = cfrock->cdata;
    icaltimezone *utc = icaltimezone_get_utc_timezone();

    /* Locate main VEVENT. */
    icalcomponent *comp;
    for (comp = icalcomponent_get_first_component(ical, ICAL_VEVENT_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_VEVENT_COMPONENT)) {
        if (!icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY)) {
            break;
        }
    }
    if (!comp) {
        return 0;
    }

    /* calendars */
    if (f->calendars && !hash_lookup(cdata->dav.mailbox, f->calendars)) {
        return 0;
    }
    /* after */
    if (icaltime_as_timet_with_zone(f->after, utc) != caldav_epoch) {
        /* String compare to match caldav_foreach_timerange */
        if (strcmp(cdata->dtend, icaltime_as_ical_string(f->after)) <= 0) {
            return 0;
        }
    }
    /* before */
    if (icaltime_as_timet_with_zone(f->before, utc) != caldav_eternity) {
        /* String compare to match caldav_foreach_timerange */
        if (strcmp(cdata->dtstart, icaltime_as_ical_string(f->before)) >= 0) {
            return 0;
        }
    }
    /* text */
    if (f->text) {
        int m = calevent_filter_match_textprop(comp, f->text, ICAL_SUMMARY_PROPERTY);
        if (!m) m = calevent_filter_match_textprop(comp, f->text, ICAL_DESCRIPTION_PROPERTY);
        if (!m) m = calevent_filter_match_textprop(comp, f->text, ICAL_LOCATION_PROPERTY);
        if (!m) m = calevent_filter_match_textprop(comp, f->text, ICAL_ORGANIZER_PROPERTY);
        if (!m) m = calevent_filter_match_textprop(comp, f->text, ICAL_ATTENDEE_PROPERTY);

        if (!m) m = calevent_filter_match_textprop_x(comp, f->text, JMAPICAL_XPROP_LOCATION);
        if (!m) m = calevent_filter_match_textprop_x(comp, f->text, "X-APPLE-STRUCTURED-LOCATION");

        if (!m) {
            return 0;
        }
    }
    if ((f->summary && !calevent_filter_match_textprop(comp, f->summary, ICAL_SUMMARY_PROPERTY)) ||
        (f->description && !calevent_filter_match_textprop(comp, f->description, ICAL_DESCRIPTION_PROPERTY)) ||
        (f->location && !calevent_filter_match_textprop(comp, f->location, ICAL_LOCATION_PROPERTY)) ||
        (f->owner && !calevent_filter_match_textprop(comp, f->owner, ICAL_ORGANIZER_PROPERTY)) ||
        (f->attendee && !calevent_filter_match_textprop(comp, f->attendee, ICAL_ATTENDEE_PROPERTY)
                     && !calevent_filter_match_textprop(comp, f->attendee, ICAL_ORGANIZER_PROPERTY))) {
        return 0;
    }

    /* All matched. */
    return 1;
}

/* Free the memory allocated by this calendar event filter. */
static void calevent_filter_free(void *vf)
{
    calevent_filter *f = (calevent_filter*) vf;
    if (f->calendars) {
        free_hash_table(f->calendars, NULL);
        free(f->calendars);
    }
    free(f);
}

static void
calevent_filter_gettimerange(jmap_filter *f, time_t *before, time_t *after)
{
    if (!f) return;

    if (f->kind == JMAP_FILTER_KIND_OPER) {
        size_t i;
        time_t bf, af;

        for (i = 0; i < f->n_conditions; i++) {
            bf = caldav_eternity;
            af = caldav_epoch;

            calevent_filter_gettimerange(f->conditions[i], &bf, &af);

            if (bf != caldav_eternity) {
                switch (f->op) {
                    case JMAP_FILTER_OP_OR:
                        if (*before == caldav_eternity || *before < bf)
                            *before = bf;
                        break;
                    case JMAP_FILTER_OP_AND:
                        if (*before == caldav_eternity || *before > bf)
                            *before = bf;
                        break;
                    case JMAP_FILTER_OP_NOT:
                        if (*after == caldav_epoch || *after < bf)
                            *after = bf;
                        break;
                    default: /* unknown operator */ ;
                }
            }

            if (af != caldav_epoch) {
                switch (f->op) {
                    case JMAP_FILTER_OP_OR:
                        if (*after == caldav_epoch || *after > af)
                            *after = af;
                        break;
                    case JMAP_FILTER_OP_AND:
                        if (*after == caldav_epoch || *after < af)
                            *after = af;
                        break;
                    case JMAP_FILTER_OP_NOT:
                        if (*before == caldav_eternity || *before < af)
                            *before = af;
                        break;
                    default: /* unknown operator */ ;
                }
            }
        }
    } else {
        calevent_filter *cond = (calevent_filter *) f->cond;
        icaltimezone *utc = icaltimezone_get_utc_timezone();

        *before = icaltime_as_timet_with_zone(cond->before, utc);
        *after = icaltime_as_timet_with_zone(cond->after, utc);
    }
}


/* Parse the JMAP calendar event FilterOperator or FilterCondition in arg.
 * Report any invalid properties in invalid, prefixed by prefix.
 * Return NULL on error. */
static void *calevent_filter_parse(json_t *arg,
                                   const char *prefix,
                                   json_t *invalid)
{
    calevent_filter *f = (calevent_filter *) xzmalloc(sizeof(struct calevent_filter));
    int pe;
    const char *val;
    struct buf buf = BUF_INITIALIZER;
    icaltimezone *utc = icaltimezone_get_utc_timezone();

    /* inCalendars */
    json_t *cals = json_object_get(arg, "inCalendars");
    if (cals && json_array_size(cals)) {
        f->calendars = xmalloc(sizeof(hash_table));
        construct_hash_table(f->calendars, json_array_size(cals), 0);
        size_t i;
        json_t *uid;
        json_array_foreach(cals, i, uid) {
            const char *id = json_string_value(uid);
            if (id && strlen(id) && (*id != '#')) {
                hash_insert(id, (void *)1, f->calendars);
            } else {
                buf_printf(&buf, "%s.calendars[%zu]", prefix, i);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }
    } else if (JNOTNULL(cals)) {
        buf_printf(&buf, "%s.%s", prefix, "inCalendars");
        json_array_append_new(invalid, json_string(buf_cstring(&buf)));
        buf_reset(&buf);
    }

    /* after */
    if (JNOTNULL(json_object_get(arg, "after"))) {
        pe = readprop_full(arg, prefix, "after", 1, invalid, "s", &val);
        if (pe > 0) {
            if (!utcdate_to_icaltime(val, &f->after)) {
                buf_printf(&buf, "%s.%s", prefix, "after");
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }
    } else {
        f->after = icaltime_from_timet_with_zone(caldav_epoch, 0, utc);
    }

    /* before */
    if (JNOTNULL(json_object_get(arg, "before"))) {
        pe = readprop_full(arg, prefix, "before", 1, invalid, "s", &val);
        if (pe > 0) {
            if (!utcdate_to_icaltime(val, &f->before)) {
                buf_printf(&buf, "%s.%s", prefix, "before");
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }
    } else {
        f->before = icaltime_from_timet_with_zone(caldav_eternity, 0, utc);
    }

    /* text */
    if (JNOTNULL(json_object_get(arg, "text"))) {
        pe = readprop_full(arg, prefix, "text", 0, invalid, "s", &f->text);
    }

    /* summary */
    if (JNOTNULL(json_object_get(arg, "summary"))) {
        pe = readprop_full(arg, prefix, "summary", 0, invalid, "s", &f->summary);
    }

    /* description */
    if (JNOTNULL(json_object_get(arg, "description"))) {
        pe = readprop_full(arg, prefix, "description", 0, invalid, "s", &f->description);
    }

    /* location */
    if (JNOTNULL(json_object_get(arg, "location"))) {
        pe = readprop_full(arg, prefix, "location", 0, invalid, "s", &f->location);
    }

    /* owner */
    if (JNOTNULL(json_object_get(arg, "owner"))) {
        pe = readprop_full(arg, prefix, "owner", 0, invalid, "s", &f->owner);
    }

    /* attendee */
    if (JNOTNULL(json_object_get(arg, "attendee"))) {
        pe = readprop_full(arg, prefix, "attendee", 0, invalid, "s", &f->attendee);
    }

    buf_free(&buf);

    return f;
}

struct caleventlist_rock {
    jmap_filter *filter;
    size_t position;
    size_t limit;
    size_t total;
    json_t *events;

    struct mailbox *mailbox;
};

static int getcalendareventlist_cb(void *rock, struct caldav_data *cdata) {
    struct caleventlist_rock *crock = (struct caleventlist_rock*) rock;
    struct index_record record;
    icalcomponent *ical = NULL;
    int r = 0;

    if (!cdata->dav.alive || !cdata->dav.rowid || !cdata->dav.imap_uid) {
        return 0;
    }

    /* Open mailbox. */
    if (!crock->mailbox || strcmp(crock->mailbox->name, cdata->dav.mailbox)) {
        mailbox_close(&crock->mailbox);
        r = mailbox_open_irl(cdata->dav.mailbox, &crock->mailbox);
        if (r) goto done;
    }

    /* Load record. */
    r = mailbox_find_index_record(crock->mailbox, cdata->dav.imap_uid, &record);
    if (r) goto done;

    /* Load VEVENT from record. */
    ical = record_to_ical(crock->mailbox, &record, NULL);
    if (!ical) {
        syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                cdata->dav.imap_uid, crock->mailbox->name);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Match the event against the filter and update statistics. */
    struct calevent_filter_rock cfrock;
    cfrock.cdata = cdata;
    cfrock.ical = ical;
    if (crock->filter && !jmap_filter_match(crock->filter,
                                            &calevent_filter_match,
                                            &cfrock)) {
        goto done;
    }
    crock->total++;
    if (crock->position > crock->total) {
        goto done;
    }
    if (crock->limit && crock->limit >= json_array_size(crock->events)) {
        goto done;
    }

    /* All done. Add the event identifier. */
    json_array_append_new(crock->events, json_string(cdata->ical_uid));

done:
    if (ical) icalcomponent_free(ical);
    return r;
}

static int getCalendarEventList(struct jmap_req *req)
{
    int r = 0, pe;
    json_t *invalid;
    int dofetch = 0;
    json_t *filter;
    struct caleventlist_rock rock;
    struct caldav_db *db;
    time_t before, after;

    memset(&rock, 0, sizeof(struct caleventlist_rock));

    db = caldav_open_userid(req->userid);
    if (!db) {
        syslog(LOG_ERR, "caldav_open_mailbox failed for user %s", req->userid);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Parse and validate arguments. */
    invalid = json_pack("[]");

    /* filter */
    filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        rock.filter = jmap_filter_parse(filter, "filter", invalid, calevent_filter_parse);
    }

    /* position */
    json_int_t pos = 0;
    if (JNOTNULL(json_object_get(req->args, "position"))) {
        pe = readprop(req->args, "position", 0 /*mandatory*/, invalid, "i", &pos);
        if (pe > 0 && pos < 0) {
            json_array_append_new(invalid, json_string("position"));
        }
    }
    rock.position = pos;

    /* limit */
    json_int_t limit = 0;
    if (JNOTNULL(json_object_get(req->args, "limit"))) {
        pe = readprop(req->args, "limit", 0 /*mandatory*/, invalid, "i", &limit);
        if (pe > 0 && limit < 0) {
            json_array_append_new(invalid, json_string("limit"));
        }
    }
    rock.limit = limit;

    /* fetchCalendarEvents */
    if (JNOTNULL(json_object_get(req->args, "fetchCalendarEvents"))) {
        readprop(req->args, "fetchCalendarEvents", 0 /*mandatory*/, invalid, "b", &dofetch);
    }

    if (json_array_size(invalid)) {
        json_t *err = json_pack("{s:s, s:o}", "type", "invalidArguments", "arguments", invalid);
        json_array_append_new(req->response, json_pack("[s,o,s]", "error", err, req->tag));
        r = 0;
        goto done;
    }
    json_decref(invalid);

    rock.events = json_pack("[]");
    before = caldav_eternity;
    after = caldav_epoch;
    calevent_filter_gettimerange(rock.filter, &before, &after);

    if (before != caldav_eternity || after != caldav_epoch) {
        /* Fast path. Filter by timerange. */
        r = caldav_foreach_timerange(db, NULL, after, before,
                getcalendareventlist_cb, &rock);
    } else {
        /* Inspect every entry in this accounts mailboxes. */
        r = caldav_foreach(db, NULL, getcalendareventlist_cb, &rock);
    }
    if (rock.mailbox) mailbox_close(&rock.mailbox);
    if (r) goto done;

    /* Prepare response. */
    json_t *eventList = json_pack("{}");
    json_object_set_new(eventList, "accountId", json_string(req->userid));
    json_object_set_new(eventList, "state", jmap_getstate(MBTYPE_CALENDAR, req));
    json_object_set_new(eventList, "position", json_integer(rock.position));
    json_object_set_new(eventList, "total", json_integer(rock.total));
    json_object_set(eventList, "calendarEventIds", rock.events);
    if (filter) json_object_set(eventList, "filter", filter);

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarEventList"));
    json_array_append_new(item, eventList);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

    /* Fetch updated records, if requested. */
    if (dofetch) {
        struct jmap_req subreq = *req;
        subreq.args = json_pack("{}");
        json_object_set(subreq.args, "ids", rock.events);
        r = getCalendarEvents(&subreq);
        json_decref(subreq.args);
    }

done:
    if (rock.filter) jmap_filter_free(rock.filter, calevent_filter_free);
    if (rock.events) json_decref(rock.events);
    if (db) caldav_close(db);
    return r;
}

/* The following JMAP methods are not defined in the spec. */

static int getCalendarPreferences(struct jmap_req *req)
{
    /* Just a dummy implementation to make the JMAP web client happy. */
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("calendarPreferences"));
    json_array_append_new(item, json_pack("{}"));
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);
    return 0;
}

static int getPersonalities(struct jmap_req *req)
{
    /* Just a dummy implementation to make the JMAP web client happy. */
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("personalities"));

    json_t *obj = json_pack("{}");
    json_object_set_new(obj, "id", json_string("1"));
    json_array_append_new(item, json_pack("{s:o}", "list", json_pack("[o]", obj)));

    /* Echo back the currently authenticated user's personality. */
    char *id = xstrdup(req->userid);
    char *p = strchr(id, '@'); if (p) { *p = 0; }
    json_object_set_new(obj, "name", json_string(id));
    free(id);
    json_object_set_new(obj, "email", json_string(req->userid));

    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);
    return 0;
}

static int getPreferences(struct jmap_req *req)
{
    /* Just a dummy implementation to make the JMAP web client happy. */
    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("preferences"));
    json_array_append_new(item, json_pack("{s:s}", "defaultPersonalityId", "1"));
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);
    return 0;
}
