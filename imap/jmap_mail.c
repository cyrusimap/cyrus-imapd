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

static int jmap_mailbox_get(jmap_req_t *req);
static int jmap_mailbox_set(jmap_req_t *req);
static int jmap_mailbox_changes(jmap_req_t *req);
static int jmap_mailbox_query(jmap_req_t *req);
static int jmap_mailbox_querychanges(jmap_req_t *req);
static int jmap_email_query(jmap_req_t *req);
static int jmap_email_querychanges(jmap_req_t *req);
static int jmap_email_get(jmap_req_t *req);
static int jmap_email_set(jmap_req_t *req);
static int jmap_email_changes(jmap_req_t *req);
static int jmap_email_import(jmap_req_t *req);
static int jmap_searchsnippet_get(jmap_req_t *req);
static int jmap_thread_get(jmap_req_t *req);
static int jmap_identity_get(jmap_req_t *req);
static int jmap_thread_changes(jmap_req_t *req);
static int jmap_emailsubmission_get(jmap_req_t *req);
static int jmap_emailsubmission_set(jmap_req_t *req);
static int jmap_emailsubmission_changes(jmap_req_t *req);
static int jmap_emailsubmission_query(jmap_req_t *req);
static int jmap_emailsubmission_querychanges(jmap_req_t *req);

/*
 * Possibly to be implemented:
 * - Email/copy
 * - VacationResponse/get
 * - VacationResponse/set
 * - Identity/changes
 * - Identity/set
 * - Email/report
 */

jmap_method_t jmap_mail_methods[] = {
    { "Mailbox/get",                  &jmap_mailbox_get },
    { "Mailbox/set",                  &jmap_mailbox_set },
    { "Mailbox/changes",              &jmap_mailbox_changes },
    { "Mailbox/query",                &jmap_mailbox_query },
    { "Mailbox/queryChanges",         &jmap_mailbox_querychanges },
    { "Email/query",                  &jmap_email_query },
    { "Email/queryChanges",           &jmap_email_querychanges },
    { "Email/get",                    &jmap_email_get },
    { "Email/set",                    &jmap_email_set },
    { "Email/changes",                &jmap_email_changes },
    { "Email/import",                 &jmap_email_import },
    { "SearchSnippet/get",            &jmap_searchsnippet_get },
    { "Thread/get",                   &jmap_thread_get },
    { "Thread/changes",               &jmap_thread_changes },
    { "Identity/get",                 &jmap_identity_get },
    { "EmailSubmission/get",          &jmap_emailsubmission_get },
    { "EmailSubmission/set",          &jmap_emailsubmission_set },
    { "EmailSubmission/changes",      &jmap_emailsubmission_changes },
    { "EmailSubmission/query",        &jmap_emailsubmission_query },
    { "EmailSubmission/queryChanges", &jmap_emailsubmission_querychanges },
    { NULL,                           NULL}
};

static int JNOTNULL(json_t *item)
{
   if (!item) return 0;
   if (json_is_null(item)) return 0;
   return 1;
}

struct jmap_get {
    /* Request arguments */
    json_t *ids;
    json_t *properties;
    hash_table *props;
    /* Response fields */
    char *state;
    json_t *list;
    json_t *not_found;
};

struct jmap_set {
    /* Request arguments */
    const char *if_in_state;
    json_t *create;
    json_t *update;
    json_t *destroy;
    /* Response fields */
    char *old_state;
    char *new_state;
    json_t *created;
    json_t *updated;
    json_t *destroyed;
    json_t *not_created;
    json_t *not_updated;
    json_t *not_destroyed;
};

struct jmap_changes {
    /* Request arguments */
    const char *since_state;
    size_t max_changes;
    /* Response fields */
    char *new_state;
    short has_more_changes;
    json_t *changed;
    json_t *destroyed;
};

struct jmap_query {
    /* Request arguments */
    json_t *filter;
    json_t *sort;
    ssize_t position;
    const char *anchor;
    ssize_t anchor_offset;
    size_t limit;
    int have_limit;
    /* Response fields */
    char *state;
    int can_calculate_changes;
    size_t result_position;
    size_t total;
    json_t *ids;
};

struct jmap_querychanges {
    /* Request arguments */
    json_t *filter;
    json_t *sort;
    const char *since_state;
    size_t max_changes;
    const char *up_to_id;
    /* Response fields */
    char *new_state;
    size_t total;
    json_t *removed;
    json_t *added;
};

struct jmap_parser {
    struct buf buf;
    strarray_t path;
    json_t *invalid;
};

#define JMAP_PARSER_INITIALIZER { BUF_INITIALIZER, STRARRAY_INITIALIZER, json_array() }

static void jmap_parser_fini(struct jmap_parser *parser)
{
    strarray_fini(&parser->path);
    json_decref(parser->invalid);
    buf_free(&parser->buf);
}

static void jmap_parser_push(struct jmap_parser *parser, const char *prop)
{
    strarray_push(&parser->path, prop);
}

static void jmap_parser_push_index(struct jmap_parser *parser,
                                   const char *prop,
                                   size_t index)
{
    /* TODO make this more clever: won't need to printf most of the time */
    buf_printf(&parser->buf, "%s[%zu]", prop, index);
    strarray_push(&parser->path, buf_cstring(&parser->buf));
    buf_reset(&parser->buf);
}

static void jmap_parser_pop(struct jmap_parser *parser)
{
    free(strarray_pop(&parser->path));
}

static const char* jmap_parser_path(struct jmap_parser *parser, struct buf *buf)
{
    int i;
    buf_reset(buf);

    for (i = 0; i < parser->path.count; i++) {
        const char *p = strarray_nth(&parser->path, i);
        if (json_pointer_needsencode(p)) {
            char *tmp = json_pointer_encode(p);
            buf_appendcstr(buf, tmp);
            free(tmp);
        } else {
            buf_appendcstr(buf, p);
        }
        if ((i + 1) < parser->path.count) {
            buf_appendcstr(buf, "/");
        }
    }

    return buf_cstring(buf);
}

static void jmap_parser_invalid(struct jmap_parser *parser, const char *prop)
{
    if (prop)
        jmap_parser_push(parser, prop);

    json_array_append_new(parser->invalid,
            json_string(jmap_parser_path(parser, &parser->buf)));

    if (prop)
        jmap_parser_pop(parser);
}

static int _parse_strings(json_t *arg, struct jmap_parser *parser, const char *prop) {
    if (!json_is_array(arg)) {
        jmap_parser_invalid(parser, prop);
        return 0;
    }
    int valid = 1;
    size_t i;
    json_t *val;
    json_array_foreach(arg, i, val) {
        if (!json_is_string(val)) {
            jmap_parser_push_index(parser, prop, i);
            jmap_parser_invalid(parser, NULL);
            jmap_parser_pop(parser);
            valid = 0;
        }
    }
    return valid;
}

static void jmap_ok(jmap_req_t *req, json_t *res)
{
    json_object_set_new(res, "accountId", json_string(req->accountid));

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string(req->method));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);
}

static void jmap_error(jmap_req_t *req, json_t *err)
{
    json_array_append_new(req->response,
            json_pack("[s,o,s]", "error", err, req->tag));
}

typedef void jmap_filter_parse_cb(json_t *filter, struct jmap_parser *parser, json_t *unsupported, void *rock);

static void jmap_filter_parse(json_t *filter, struct jmap_parser *parser,
                              jmap_filter_parse_cb parse_condition,
                              json_t *unsupported,
                              void *rock)
{
    json_t *arg, *val;
    const char *s;
    size_t i;

    if (!JNOTNULL(filter) || json_typeof(filter) != JSON_OBJECT) {
        jmap_parser_invalid(parser, NULL);
        return;
    }
    arg = json_object_get(filter, "operator");
    if ((s = json_string_value(arg))) {
        if (strcmp("AND", s) && strcmp("OR", s) && strcmp("NOT", s)) {
            jmap_parser_invalid(parser, "operator");
        }
        arg = json_object_get(filter, "conditions");
        if (!json_array_size(arg)) {
            jmap_parser_invalid(parser, "conditions");
        }
        json_array_foreach(arg, i, val) {
            jmap_parser_push_index(parser, "conditions", i);
            jmap_filter_parse(val, parser, parse_condition, unsupported, rock);
            jmap_parser_pop(parser);
        }
    } else if (arg) {
        jmap_parser_invalid(parser, "operator");
    } else {
        parse_condition(filter, parser, unsupported, rock);
    }
}

struct jmap_comparator {
    const char *property;
    short is_ascending;
    const char *collation;
};

typedef int jmap_comparator_parse_cb(struct jmap_comparator *comp, void *rock);

static void parse_comparator(json_t *jsort, struct jmap_parser *parser,
                       jmap_comparator_parse_cb comp_cb, json_t *unsupported,
                       void *rock)
{
    if (!json_is_object(jsort)) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    struct jmap_comparator comp = { NULL, 0, NULL };

    /* property */
    json_t *val = json_object_get(jsort, "property");
    comp.property = json_string_value(val);
    if (!comp.property) {
        jmap_parser_invalid(parser, "property");
    }

    /* isAscending */
    comp.is_ascending = 1;
    val = json_object_get(jsort, "isAscending");
    if (JNOTNULL(val)) {
        if (!json_is_boolean(val)) {
            jmap_parser_invalid(parser, "isAscending");
        }
        comp.is_ascending = json_boolean_value(val);
    }

    /* collation */
    val = json_object_get(jsort, "collation");
    if (JNOTNULL(val) && !json_is_string(val)) {
        jmap_parser_invalid(parser, "collation");
    }
    comp.collation = json_string_value(val);


    if (comp.property && !comp_cb(&comp, rock)) {
        struct buf buf = BUF_INITIALIZER;
        json_array_append_new(unsupported,
                json_string(jmap_parser_path(parser, &buf)));
        buf_free(&buf);
    }
}

/* Foo/get */

static void jmap_get_parse(json_t *jargs,
                           struct jmap_parser *parser,
                           hash_table *creation_ids,
                           struct jmap_get *get,
                           json_t **err)
{
    json_t *arg, *val;
    size_t i;

    memset(get, 0, sizeof(struct jmap_get));

    get->list = json_array();
    get->not_found = json_array();

    arg = json_object_get(jargs, "ids");
    if (json_is_array(arg)) {
        get->ids = json_array();
        /* JMAP spec requires: "If an identical id is included more than once
         * in the request, the server MUST only include it once in either the
         * list or notFound argument of the response."
         * So let's weed out duplicate ids here. */
        hash_table _dedup = HASH_TABLE_INITIALIZER;
        construct_hash_table(&_dedup, json_array_size(arg) + 1, 0);
        json_array_foreach(arg, i, val) {
            const char *id = json_string_value(val);
            if (!id) {
                jmap_parser_push_index(parser, "ids", i);
                jmap_parser_invalid(parser, NULL);
                jmap_parser_pop(parser);
                continue;
            }
            /* Weed out unknown creation ids and add the ids of known
             * creation ids to the requested ids list. THis might
             * cause a race if the Foo object pointed to by creation
             * id is deleted between parsing the request and answering
             * it. But re-checking creation ids for their existence
             * later in the control flow just shifts the problem */
            if (*id == '#') {
                const char *id2 = NULL;
                if (creation_ids)  {
                    id2 = hash_lookup(id+1, creation_ids);
                }
                if (!id2) {
                    json_array_append_new(get->not_found, json_string(id));
                    continue;
                }
                id = id2;
            }
            if (hash_lookup(id, &_dedup)) {
                continue;
            }
            json_array_append_new(get->ids, json_string(id));
        }
        free_hash_table(&_dedup, NULL);
    }
    else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "ids");
    }

    arg = json_object_get(jargs, "properties");
    if (json_is_array(arg)) {
        get->props = xzmalloc(sizeof(hash_table));
        construct_hash_table(get->props, json_array_size(arg) + 1, 0);
        json_array_foreach(arg, i, val) {
            const char *s = json_string_value(val);
            if (!s) {
                jmap_parser_push_index(parser, "properties", i);
                jmap_parser_invalid(parser, NULL);
                jmap_parser_pop(parser);
                continue;
            }
            hash_insert(s, (void*)1, get->props);
        }
    }
    else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "properties");
    }

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                "arguments", parser->invalid);
    }
}

static void jmap_get_fini(struct jmap_get *get)
{
    free_hash_table(get->props, NULL);
    free(get->props);
    free(get->state);
    json_decref(get->ids);
    json_decref(get->list);
    json_decref(get->not_found);
}

static json_t *jmap_get_reply(struct jmap_get *get)
{
    json_t *res = json_object();
    json_object_set_new(res, "state", json_string(get->state));
    json_object_set(res, "list", get->list);
    json_object_set(res, "notFound", json_array_size(get->not_found) ?
            get->not_found : json_null());
    return res;
}

/* Foo/set */


static void jmap_set_parse(json_t *jargs,
                           struct jmap_parser *parser,
                           void (*parseobject_cb)(
                               json_t *obj,
                               const char *id,
                               int is_create,
                               void *rock,
                               json_t **set_err
                            ),
                           void *rock,
                           struct jmap_set *set,
                           json_t **err)
{
    memset(set, 0, sizeof(struct jmap_set));
    set->create = json_object();
    set->update = json_object();
    set->destroy = json_array();
    set->created = json_object();
    set->updated = json_object();
    set->destroyed = json_array();
    set->not_created = json_object();
    set->not_updated = json_object();
    set->not_destroyed = json_object();

    json_t *arg, *val;

    /* ifInState */
    arg = json_object_get(jargs, "ifInState");
    if (json_is_string(arg)) {
        set->if_in_state = json_string_value(arg);
    }
    else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "ifInState");
    }

    /* create */
    arg = json_object_get(jargs, "create");
    if (json_is_object(arg)) {
        const char *id;
        json_object_foreach(arg, id, val) {
            if (!json_is_object(val)) {
                jmap_parser_push(parser, "create");
                jmap_parser_invalid(parser, id);
                jmap_parser_pop(parser);
                continue;
            }
            if (parseobject_cb) {
                json_t *set_err = NULL;
                parseobject_cb(val, id, /*is_create*/1, rock, &set_err);
                if (set_err) {
                    json_object_set_new(set->not_created, id, set_err);
                    continue;
                }
            }
            json_object_set(set->create, id, val);
        }
    }
    else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "create");
    }

    /* update */
    arg = json_object_get(jargs, "update");
    if (json_is_object(arg)) {
        const char *id;
        json_object_foreach(arg, id, val) {
            if (!json_is_object(val)) {
                jmap_parser_push(parser, "update");
                jmap_parser_invalid(parser, id);
                jmap_parser_pop(parser);
                continue;
            }
            if (parseobject_cb) {
                json_t *set_err = NULL;
                parseobject_cb(val, id, /*is_create*/0, rock, &set_err);
                if (set_err) {
                    json_object_set_new(set->not_updated, id, set_err);
                    continue;
                }
            }
            json_object_set(set->update, id, val);
        }
    }
    else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "update");
    }

    /* destroy */
    arg = json_object_get(jargs, "destroy");
    if (JNOTNULL(arg)) {
        _parse_strings(arg, parser, "destroy");
        if (!json_array_size(parser->invalid)) {
            json_decref(set->destroy);
            set->destroy = json_incref(arg);
        }
    }

    // TODO We could report the following set errors here:
    // -invalidPatch
    // - willDestroy

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                "arguments", parser->invalid);
    }
}


static void jmap_set_fini(struct jmap_set *set)
{
    free(set->new_state);
    json_decref(set->create);
    json_decref(set->update);
    json_decref(set->destroy);
    json_decref(set->created);
    json_decref(set->updated);
    json_decref(set->destroyed);
    json_decref(set->not_created);
    json_decref(set->not_updated);
    json_decref(set->not_destroyed);
}

static json_t *jmap_set_reply(struct jmap_set *set)
{
    json_t *res = json_object();
    json_object_set_new(res, "oldState",
            set->old_state ? json_string(set->old_state) : json_null());
    json_object_set_new(res, "newState", json_string(set->new_state));
    json_object_set(res, "created", json_object_size(set->created) ?
            set->created : json_null());
    json_object_set(res, "updated", json_object_size(set->updated) ?
            set->updated : json_null());
    json_object_set(res, "destroyed", json_array_size(set->destroyed) ?
            set->destroyed : json_null());
    json_object_set(res, "notCreated", json_object_size(set->not_created) ?
            set->not_created : json_null());
    json_object_set(res, "notUpdated", json_object_size(set->not_updated) ?
            set->not_updated : json_null());
    json_object_set(res, "notDestroyed", json_object_size(set->not_destroyed) ?
            set->not_destroyed : json_null());
    return res;
}

/* Foo/changes */

static void jmap_changes_parse(json_t *jargs,
                               struct jmap_parser *parser,
                               struct jmap_changes *changes,
                               json_t **err)
{
    memset(changes, 0, sizeof(struct jmap_changes));
    changes->changed = json_array();
    changes->destroyed = json_array();

    /* sinceState */
    json_t *arg = json_object_get(jargs, "sinceState");
    if (json_is_string(arg)) {
        changes->since_state = json_string_value(arg);
    } else {
        jmap_parser_invalid(parser, "sinceState");
    }

    /* maxChanges */
    arg = json_object_get(jargs, "maxChanges");
    if (json_is_integer(arg) && json_integer_value(arg) > 0) {
        changes->max_changes = json_integer_value(arg);
    } else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "maxChanges");
    }

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                "arguments", parser->invalid);
    }
}

static void jmap_changes_fini(struct jmap_changes *changes)
{
    free(changes->new_state);
    json_decref(changes->changed);
    json_decref(changes->destroyed);
}

static json_t *jmap_changes_reply(struct jmap_changes *changes)
{
    json_t *res = json_object();
    json_object_set_new(res, "oldState", json_string(changes->since_state));
    json_object_set_new(res, "newState", json_string(changes->new_state));
    json_object_set_new(res, "hasMoreChanges",
            json_boolean(changes->has_more_changes));
    json_object_set(res, "changed", changes->changed);
    json_object_set(res, "destroyed", changes->destroyed);
    return res;
}


/* Foo/query */

static void jmap_query_parse(json_t *jargs,
                             struct jmap_parser *parser,
                             jmap_filter_parse_cb filter_cb,
                             void *filter_rock,
                             jmap_comparator_parse_cb comp_cb,
                             void *sort_rock,
                             struct jmap_query *query,
                             json_t **err)
{
    json_t *arg, *val;
    size_t i;

    memset(query, 0, sizeof(struct jmap_query));
    query->ids = json_array();

    json_t *unsupported_filter = json_array();
    json_t *unsupported_sort = json_array();

    /* filter */
    arg = json_object_get(jargs, "filter");
    if (json_is_object(arg)) {
        jmap_parser_push(parser, "filter");
        jmap_filter_parse(arg, parser, filter_cb, unsupported_filter, filter_rock);
        jmap_parser_pop(parser);
        query->filter = arg;
    }
    else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "filter");
    }

    /* sort */
    arg = json_object_get(jargs, "sort");
    if (json_is_array(arg)) {
        json_array_foreach(arg, i, val) {
            jmap_parser_push_index(parser, "sort", i);
            parse_comparator(val, parser, comp_cb, unsupported_sort, sort_rock);
            jmap_parser_pop(parser);
        }
        if (json_array_size(arg)) {
            query->sort = arg;
        }
    }
    else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "sort");
    }

    arg = json_object_get(jargs, "position");
    if (json_is_integer(arg)) {
        query->position = json_integer_value(arg);
    }
    else if (arg) {
        jmap_parser_invalid(parser, "position");
    }

    arg = json_object_get(jargs, "anchor");
    if (json_is_string(arg)) {
        query->anchor = json_string_value(arg);
    } else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "anchor");
    }

    arg = json_object_get(jargs, "anchorOffset");
    if (json_is_integer(arg)) {
        query->anchor_offset = json_integer_value(arg);
    } else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "anchorOffset");
    }

    arg = json_object_get(jargs, "limit");
    if (json_is_integer(arg) && json_integer_value(arg) >= 0) {
        query->limit = json_integer_value(arg);
        query->have_limit = 1;
    } else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "limit");
    }

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                "arguments", parser->invalid);
    }
	else if (json_array_size(unsupported_filter)) {
		*err = json_pack("{s:s s:O}", "type", "unsupportedFilter",
                "filters", unsupported_filter);
	}
	else if (json_array_size(unsupported_sort)) {
		*err = json_pack("{s:s s:O}", "type", "unsupportedSort",
                "sort", unsupported_sort);
	}

    json_decref(unsupported_filter);
    json_decref(unsupported_sort);
}

static void jmap_query_fini(struct jmap_query *query)
{
    free(query->state);
    json_decref(query->ids);
}

static json_t *jmap_query_reply(struct jmap_query *query)
{

    json_t *res = json_object();
    json_object_set(res, "filter", query->filter);
    json_object_set(res, "sort", query->sort);
    json_object_set_new(res, "state", json_string(query->state));
    json_object_set_new(res, "canCalculateChanges", json_boolean(query->can_calculate_changes));
    json_object_set_new(res, "position", json_integer(query->position));
    json_object_set_new(res, "total", json_integer(query->total));
    /* Special case total */
    if (query->position > 0 && query->total < SSIZE_MAX) {
        if (query->position > (ssize_t) query->total) {
            json_decref(query->ids);
            query->ids = json_array();
        }
    }
    /* Special case limit 0 */
    if (query->have_limit && query->limit == 0) {
        json_array_clear(query->ids);
    }

    json_object_set(res, "ids", query->ids);
    return res;
}

/* Foo/queryChanges */

static void jmap_querychanges_parse(json_t *jargs,
                                   struct jmap_parser *parser,
                                   jmap_filter_parse_cb filter_cb,
                                   void *filter_rock,
                                   jmap_comparator_parse_cb comp_cb,
                                   void *sort_rock,
                                   struct jmap_querychanges *query,
                                   json_t **err)
{
    json_t *arg, *val;
    size_t i;

    memset(query, 0, sizeof(struct jmap_querychanges));
    query->removed = json_array();
    query->added = json_array();

    json_t *unsupported_filter = json_array();
    json_t *unsupported_sort = json_array();

    /* filter */
    arg = json_object_get(jargs, "filter");
    if (json_is_object(arg)) {
        jmap_parser_push(parser, "filter");
        jmap_filter_parse(arg, parser, filter_cb, unsupported_filter, filter_rock);
        jmap_parser_pop(parser);
        query->filter = arg;
    }
    else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "filter");
    }

    /* sort */
    arg = json_object_get(jargs, "sort");
    if (json_is_array(arg)) {
        json_array_foreach(arg, i, val) {
            jmap_parser_push_index(parser, "sort", i);
            parse_comparator(val, parser, comp_cb, unsupported_sort, sort_rock);
            jmap_parser_pop(parser);
        }
        if (json_array_size(arg)) {
            query->sort = arg;
        }
    }
    else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "sort");
    }

    /* sinceState */
    arg = json_object_get(jargs, "sinceState");
    if (json_is_string(arg)) {
        query->since_state = json_string_value(arg);
    } else {
        jmap_parser_invalid(parser, "sinceState");
    }

    /* maxChanges */
    arg = json_object_get(jargs, "maxChanges");
    if (json_is_integer(arg) && json_integer_value(arg) > 0) {
        query->max_changes = json_integer_value(arg);
    } else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "maxChanges");
    }

    /* upToId */
    arg = json_object_get(jargs, "upToId");
    if (json_is_string(arg)) {
        query->up_to_id = json_string_value(arg);
    } else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "upToId");
    }

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                "arguments", parser->invalid);
    }
	else if (json_array_size(unsupported_filter)) {
		*err = json_pack("{s:s s:O}", "type", "unsupportedFilter",
                "filters", unsupported_filter);
	}
	else if (json_array_size(unsupported_sort)) {
		*err = json_pack("{s:s s:O}", "type", "unsupportedSort",
                "sort", unsupported_sort);
	}

    json_decref(unsupported_filter);
    json_decref(unsupported_sort);
}

static void jmap_querychanges_fini(struct jmap_querychanges *query)
{
    free(query->new_state);
    json_decref(query->removed);
    json_decref(query->added);
}

static json_t *jmap_querychanges_reply(struct jmap_querychanges *query)
{
    json_t *res = json_object();
    json_object_set(res, "filter", query->filter);
    json_object_set(res, "sort", query->sort);
    json_object_set_new(res, "oldState", json_string(query->since_state));
    json_object_set_new(res, "newState", json_string(query->new_state));
    json_object_set_new(res, "upToId", query->up_to_id ?
            json_string(query->up_to_id) : json_null());
    json_object_set(res, "removed", query->removed);
    json_object_set(res, "added", query->added);
    json_object_set_new(res, "total", json_integer(query->total));
    return res;
}

/* NULL terminated list of supported jmap_email_query sort fields */
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

    long max_size_attachments_per_email =
        config_getint(IMAPOPT_JMAP_MAIL_MAX_SIZE_ATTACHMENTS_PER_EMAIL);

    max_size_attachments_per_email *= 1024;
    if (max_size_attachments_per_email <= 0) {
        syslog(LOG_ERR, "jmap: invalid property value: %s",
                imapopts[IMAPOPT_JMAP_MAIL_MAX_SIZE_ATTACHMENTS_PER_EMAIL].optname);
        max_size_attachments_per_email = 0;
    }

    json_t *my_capabilities = json_pack("{s:o? s:i s:i s:O s:O}",
            "maxMailboxesPerEmail", json_null(),
            "maxSizeAttachmentsPerEmail", max_size_attachments_per_email,
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

/* TODO sunset readprop and rewrite Foo/set methods to use jmap_set */
#define readprop(root, name,  mandatory, invalid, fmt, dst) \
    readprop_full((root), NULL, (name), (mandatory), (invalid), (fmt), (dst))

/*
 * Mailboxes
 */

struct _mbox_find_uniqueid_rock {
    const char *uniqueid;
    char **name;
};

static int _mbox_find_uniqueid_cb(const mbentry_t *mbentry, void *rock)
{
    struct _mbox_find_uniqueid_rock *data = rock;
    if (strcmp(mbentry->uniqueid, data->uniqueid))
        return 0;
    *(data->name) = xstrdup(mbentry->name);
    return IMAP_OK_COMPLETED;
}

static char *_mbox_find_uniqueid(jmap_req_t *req, const char *id)
{
    char *name = NULL;
    struct _mbox_find_uniqueid_rock rock = { id, &name };
    int r = jmap_mboxlist(req, _mbox_find_uniqueid_cb, &rock);
    if (r != IMAP_OK_COMPLETED) {
        free(name);
        name = NULL;
    }
    return name;
}

struct _mbox_find_specialuse_rock {
    const char *use;
    const char *userid;
    char *mboxname;
};

static int _mbox_find_specialuse_cb(const mbentry_t *mbentry, void *rock)
{
    struct _mbox_find_specialuse_rock *d = (struct _mbox_find_specialuse_rock *)rock;
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


static char *_mbox_find_specialuse(jmap_req_t *req, const char *use)
{
    /* \\Inbox is magical */
    if (!strcasecmp(use, "\\Inbox"))
        return mboxname_user_mbox(req->accountid, NULL);

    struct _mbox_find_specialuse_rock rock = { use, req->userid, NULL };
    jmap_mboxlist(req, _mbox_find_specialuse_cb, &rock);
    return rock.mboxname;
}

static char *_mbox_get_role(jmap_req_t *req, const mbname_t *mbname)
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

static char *_mbox_get_name(jmap_req_t *req, const mbname_t *mbname)
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

static int _mbox_get_sortorder(jmap_req_t *req, const mbname_t *mbname)
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

    free(role);
    buf_free(&attrib);
    return sort_order;
}

static json_t *_mbox_get(jmap_req_t *req,
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
    mbentry_t *parent = NULL;

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

    char *role = _mbox_get_role(req, mbname);

    if (_wantprop(props, "myRights") || _wantprop(props, "parentId")) {
        /* Need to lookup parent mailbox */
        mboxlist_findparent(mbname_intname(mbname), &parent);
    }

    /* Lookup status. */
    r = status_lookup(mbname_intname(mbname), req->userid, statusitems, &sdata);
    if (r) goto done;

    /* Build JMAP mailbox response. */
    obj = json_pack("{}");
    json_object_set_new(obj, "id", json_string(mbentry->uniqueid));
    if (_wantprop(props, "name")) {
        char *name = _mbox_get_name(req, mbname);
        if (!name) goto done;
        json_object_set_new(obj, "name", json_string(name));
        free(name);
    }

    if (_wantprop(props, "parentId")) {
        json_object_set_new(obj, "parentId",
                (is_inbox || parent_is_inbox || !parent) ?
                json_null() : json_string(parent->uniqueid));
    }


    if (_wantprop(props, "myRights")) {
        json_t *jrights = json_object();
        json_object_set_new(jrights, "mayReadItems",
                json_boolean(rights & ACL_READ));
        json_object_set_new(jrights, "mayAddItems",
                json_boolean(rights & ACL_INSERT));
        json_object_set_new(jrights, "mayRemoveItems",
                json_boolean(rights & ACL_DELETEMSG));
        json_object_set_new(jrights, "mayCreateChild",
                json_boolean(rights & ACL_CREATE));
        json_object_set_new(jrights, "mayDelete",
                json_boolean((rights & ACL_DELETEMBOX) && !is_inbox));
        json_object_set_new(jrights, "maySubmit",
                json_boolean(rights & ACL_POST));
        json_object_set_new(jrights, "maySetSeen",
                json_boolean(rights & ACL_SETSEEN));
        json_object_set_new(jrights, "maySetKeywords",
                json_boolean(rights & ACL_WRITE));

        int mayRename = 0;
        if (!is_inbox && (rights & ACL_DELETEMBOX)) {
            int parent_rights = jmap_myrights(req, parent);
            mayRename = parent_rights & ACL_CREATE;
        }
        json_object_set_new(jrights, "mayRename", json_boolean(mayRename));

        json_object_set_new(obj, "myRights", jrights);
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
        int sortOrder = _mbox_get_sortorder(req, mbname);
        json_object_set_new(obj, "sortOrder", json_integer(sortOrder));
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

static json_t *jmap_fmtstate(modseq_t modseq)
{
    struct buf buf = BUF_INITIALIZER;
    json_t *state = NULL;
    buf_printf(&buf, MODSEQ_FMT, modseq);
    state = json_string(buf_cstring(&buf));
    buf_free(&buf);
    return state;
}

struct jmap_mailbox_get_cb_rock {
    jmap_req_t *req;
    struct jmap_get *get;
    hash_table *roles;
    hash_table *want;
};

static int jmap_mailbox_get_cb(const mbentry_t *mbentry, void *_rock)
{
    struct jmap_mailbox_get_cb_rock *rock = _rock;
    jmap_req_t *req = rock->req;
    json_t *list = (json_t *) rock->get->list, *obj;
    int r = 0, rights;

    /* Don't list special-purpose mailboxes. */
    if ((mbentry->mbtype & MBTYPE_DELETED) ||
        (mbentry->mbtype & MBTYPE_MOVING) ||
        (mbentry->mbtype & MBTYPE_REMOTE) ||  /* XXX ?*/
        (mbentry->mbtype & MBTYPE_RESERVE) || /* XXX ?*/
        (mbentry->mbtype & MBTYPES_NONIMAP)) {
        goto done;
    }

    /* Do we need to process this mailbox? */
    if (rock->want && !hash_lookup(mbentry->uniqueid, rock->want))
        return 0;

    /* Are we done with looking up mailboxes by id? */
    if (rock->want && !hash_numrecords(rock->want))
        return IMAP_OK_COMPLETED;

    /* Check ACL on mailbox for current user */
    rights = jmap_myrights(req, mbentry);
    if ((rights & (ACL_LOOKUP | ACL_READ)) != (ACL_LOOKUP | ACL_READ)) {
        goto done;
    }

    /* Convert mbox to JMAP object. */
    obj = _mbox_get(req, mbentry, rock->roles, rock->get->props);
    if (!obj) {
        syslog(LOG_INFO, "could not convert mailbox %s to JMAP", mbentry->name);
        r = IMAP_INTERNAL;
        goto done;
    }
    json_array_append_new(list, obj);

    /* Move this mailbox of the lookup list */
    if (rock->want) {
        hash_del(mbentry->uniqueid, rock->want);
    }

  done:
    return r;
}

static void jmap_mailbox_get_notfound(const char *id, void *data __attribute__((unused)), void *rock)
{
    json_array_append_new((json_t*) rock, json_string(id));
}

static int jmap_mailbox_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;

    /* Build callback data */
    struct jmap_mailbox_get_cb_rock rock = { req, &get, NULL, NULL };
    rock.roles = (hash_table *) xmalloc(sizeof(hash_table));
    construct_hash_table(rock.roles, 8, 0);

    /* Parse request */
    jmap_get_parse(req->args, &parser, &req->idmap->mailboxes, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

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
    jmap_mboxlist(req, jmap_mailbox_get_cb, &rock);

    /* Report if any requested mailbox has not been found */
    if (rock.want) {
        hash_enumerate(rock.want, jmap_mailbox_get_notfound, get.not_found);
    }

    /* Build response */
    json_t *jstate = jmap_getstate(req, 0);
    get.state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    jmap_ok(req, jmap_get_reply(&get));

done:
    free_hash_table(rock.want, NULL);
    free(rock.want);
    free_hash_table(rock.roles, NULL);
    free(rock.roles);
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
    /* Arguments for the filter operator or condition. */
    ptrarray_t args;
} mboxquery_filter_t;

typedef struct {
    char *name;
    union {
        char *s;
        short b;
    } val;
} mboxquery_field_t;

typedef struct {
    jmap_req_t *req;
    mboxquery_filter_t *filter;
    ptrarray_t sort;    /* Sort criteria (mboxquery_sort_t) */
    ptrarray_t result;  /* Result records (mboxquery_record_t) */

    int _need_name;
    int _need_utf8mboxname;
    int _need_sort_order;
    int _need_role;
} mboxquery_t;

typedef struct {
    char *id;
    mbname_t *mbname;
    char *mboxname;
    char *utf8mboxname;
    char *jmapname;
    int sort_order;
} mboxquery_record_t;

typedef struct {
    char *field;
    int desc;
} mboxquery_sort_t;

static mboxquery_t *_mboxquery_new(jmap_req_t *req)
{
    mboxquery_t *q = xzmalloc(sizeof(mboxquery_t));
    q->req = req;
    return q;
}

static void _mboxquery_filter_free(mboxquery_filter_t *filter)
{
    if (!filter) return;

    int i;
    for (i = 0; i < filter->args.count; i++) {
        if (filter->op == SEOP_UNKNOWN) {
            mboxquery_field_t *field = ptrarray_nth(&filter->args, i);
            if (!strcmp(field->name, "parentId"))
                free(field->val.s);
            free(field->name);
            free(field);
        }
        else {
            _mboxquery_filter_free(ptrarray_nth(&filter->args, i));
        }
    }
    ptrarray_fini(&filter->args);
    free(filter);
}

static void _mboxquery_free(mboxquery_t **qptr)
{
    int i;
    mboxquery_t *q = *qptr;

    for (i = 0; i < q->result.count; i++) {
        mboxquery_record_t *rec = ptrarray_nth(&q->result, i);
        free(rec->id);
        mbname_free(&rec->mbname);
        free(rec->mboxname);
        free(rec->utf8mboxname);
        free(rec->jmapname);
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

    free(q);
    *qptr = NULL;
}

static int _mboxquery_eval_filter(mboxquery_t *query,
                                   mboxquery_filter_t *filter,
                                   const mbentry_t *mbentry,
                                   const mbname_t *mbname)
{
    if (filter->op == SEOP_TRUE)
        return 1;
    if (filter->op == SEOP_FALSE)
        return 0;

    int i;
    if (filter->op != SEOP_UNKNOWN) {
        for (i = 0; i < filter->args.count; i++) {
            mboxquery_filter_t *arg = ptrarray_nth(&filter->args, i);
            int m = _mboxquery_eval_filter(query, arg, mbentry, mbname);
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
        for (i = 0; i < filter->args.count; i++) {
            mboxquery_field_t *field = ptrarray_nth(&filter->args, i);
            if (!strcmp(field->name, "hasRole")) {
                mbname_t *mbname = mbname_from_intname(mbentry->name);
                char *role = _mbox_get_role(query->req, mbname);
                int has_role = role != NULL;
                free(role);
                mbname_free(&mbname);
                if ((has_role == 0) != (field->val.b == 0)) return 0;
            }
            if (!strcmp(field->name, "parentId")) {
                int matches_parentid = 0;
                if (field->val.s) {
                    mbentry_t *mbparent = NULL;
                    if (!mboxlist_findparent(mbentry->name, &mbparent)) {
                        matches_parentid = !strcmp(mbparent->uniqueid, field->val.s);
                    }
                    mboxlist_entry_free(&mbparent);
                } else {
                    /* parentId is null */
                    matches_parentid = strarray_size(mbname_boxes(mbname)) < 2;
                }
                if (!matches_parentid) return 0;
            }
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
        json_t *val;
        filter->op = SEOP_UNKNOWN;
        if ((val = json_object_get(jfilter, "parentId"))) {
            mboxquery_field_t *field = xzmalloc(sizeof(mboxquery_field_t));
            field->name = xstrdup("parentId");
            /* parentId may be null for top-level mailbox queries */
            field->val.s = xstrdupnull(json_string_value(val));
            ptrarray_append(&filter->args, field);
        }
        if ((val = json_object_get(jfilter, "hasRole"))) {
            mboxquery_field_t *field = xzmalloc(sizeof(mboxquery_field_t));
            field->name = xstrdup("hasRole");
            field->val.b = json_boolean_value(val);
            ptrarray_append(&filter->args, field);
            query->_need_role = 1;
        }
    }
    return filter;
}

static int _mboxquery_compar(const void **a, const void **b, void *rock)
{
    const mboxquery_record_t *pa = *a;
    const mboxquery_record_t *pb = *b;
    ptrarray_t *criteria = rock;
    int i;

    for (i = 0; i < criteria->count; i++) {
        mboxquery_sort_t *crit = ptrarray_nth(criteria, i);
        int cmp = 0;
        int sign = crit->desc ? -1 : 1;

        if (!strcmp(crit->field, "name"))
            cmp = strcmp(pa->jmapname, pb->jmapname) * sign;
        else if (!strcmp(crit->field, "sortOrder"))
            cmp = (pa->sort_order - pb->sort_order) * sign;
        else if (!strcmp(crit->field, "parent/name"))
            cmp = strcmp(pa->utf8mboxname, pb->utf8mboxname) * sign;

        if (cmp) return cmp;
    }

    return strcmp(pa->id, pb->id);
}

static int _mboxquery_cb(const mbentry_t *mbentry, void *rock)
{
    if (mbentry->mbtype & (MBTYPES_NONIMAP|MBTYPE_DELETED))
        return 0;

    mboxquery_t *q = rock;
    mbname_t *_mbname = mbname_from_intname(mbentry->name);

    int r = 0;

    /* Apply filters */
    int matches = 1;
    if (q->filter) {
        matches = _mboxquery_eval_filter(q, q->filter, mbentry, _mbname);
    }
    if (!matches) goto done;

    /* Found a matching reccord. Add it to the result list. */
    mboxquery_record_t *rec = xzmalloc(sizeof(mboxquery_record_t));
    rec->id = xstrdup(mbentry->uniqueid);
    rec->mbname = _mbname;
    _mbname = NULL; /* rec takes ownership for _mbname */

    if (q->_need_name) {
        rec->mboxname = xstrdup(mbentry->name);
        rec->jmapname = _mbox_get_name(q->req, rec->mbname);
    }
    if (q->_need_utf8mboxname) {
        charset_t cs = charset_lookupname("imap-mailbox-name");
        if (!cs) {
            syslog(LOG_ERR, "_mboxquery_cb: no imap-mailbox-name charset");
            r = IMAP_INTERNAL;
            goto done;
        }
        /* XXX this is best we can get without resorting to replicating the
         * mailbox tree in-memory. If mailbox siblings are not being allowed
         * to share the same name and IMAP mailboxes always resemble the
         * IMAP UTF-7 encoded hierarchical name, we are safe to compare the
         * UTF-8 decoded IMAP mailbox names. */
        rec->utf8mboxname =
            charset_to_utf8(mbentry->name, strlen(mbentry->name), cs, 0);
        if (!rec->utf8mboxname) {
            /* XXX should never happen */
            rec->utf8mboxname = xstrdup(mbentry->name);
        }
        charset_free(&cs);
    }
    if (q->_need_sort_order) {
        rec->sort_order = _mbox_get_sortorder(q->req, rec->mbname);
    }
    ptrarray_append(&q->result, rec);

done:
    if (_mbname) mbname_free(&_mbname);
    return r;
}

static int _mboxquery_run(mboxquery_t *query)
{
    int i;

    /* Prepare internal query context. */
    for (i = 0; i < query->sort.count; i++) {
        mboxquery_sort_t *crit = ptrarray_nth(&query->sort, i);
        if (!strcmp(crit->field, "name")) {
            query->_need_name = 1;
        }
        else if (!strcmp(crit->field, "sortOrder")) {
            query->_need_sort_order = 1;
        }
        else if (!strcmp(crit->field, "parent/name")) {
            query->_need_utf8mboxname = 1;
        }
    }

    /* Lookup all mailboxes */
    int r = jmap_mboxlist(query->req, _mboxquery_cb, query);
    if (r) goto done;

    /* Sort result */
    qsort_r(query->result.data, query->result.count, sizeof(void*),
            (int(*)(const void*, const void*, void*)) _mboxquery_compar,
            &query->sort);

done:
    return r;
}

static int _mbox_query(jmap_req_t *req, struct jmap_query *jquery)
{
    int r = 0;
    size_t j;
    json_t *val;

    /* Reject any attempt to calculcate updates for jmap_mailbox_querychanges.
     * All of the filter and sort criteria are mutable. That only leaves
     * an unsorted and unfiltere mailbox list which we internally sort
     * by mailbox ids, which isn't any better than jmap_mailbox_changes. */
    jquery->can_calculate_changes = 0;

    /* Prepare query */
    mboxquery_t *query = _mboxquery_new(req);

    /* Prepare sort */
    json_array_foreach(jquery->sort, j, val) {
        mboxquery_sort_t *crit = xzmalloc(sizeof(mboxquery_sort_t));
        const char *prop = json_string_value(json_object_get(val, "property"));
        crit->field = xstrdup(prop);
        crit->desc = json_object_get(val, "isAscending") == json_false();
        ptrarray_append(&query->sort, crit);
    }

    /* Prepare filter */
    query->filter = _mboxquery_build_filter(query, jquery->filter);

    /* Run the query */
    r = _mboxquery_run(query);
    if (r) goto done;

    jquery->total = query->result.count;

    /* Apply jquery */
    ssize_t i, frompos = 0;
    int seen_anchor = 0;
    ssize_t skip_anchor = 0;
    ssize_t result_pos = -1;

    /* Set position of first result */
    if (!jquery->anchor) {
        if (jquery->position > 0) {
            frompos = jquery->position;
        }
        else if (jquery->position < 0) {
            frompos = query->result.count + jquery->position ;
            if (frompos < 0) frompos = 0;
        }
    }

    for (i = frompos; i < query->result.count; i++) {
        mboxquery_record_t *rec = ptrarray_nth(&query->result, i);

        /* Check anchor */
        if (jquery->anchor && !seen_anchor) {
            seen_anchor = !strcmp(rec->id, jquery->anchor);
            if (!seen_anchor) {
                continue;
            }
            /* Found the anchor! Now apply anchor offsets */
            if (jquery->anchor_offset < 0) {
                skip_anchor = -jquery->anchor_offset;
                continue;
            }
            else if (jquery->anchor_offset > 0) {
                /* Prefill result list with all, but the current record */
                size_t lo = jquery->anchor_offset < i ? i - jquery->anchor_offset : 0;
                size_t hi = jquery->limit ? lo + jquery->limit : (size_t) i;
                result_pos = lo;
                while (lo < hi && lo < (size_t) i) {
                    mboxquery_record_t *p = ptrarray_nth(&query->result, lo);
                    json_array_append_new(jquery->ids, json_string(p->id));
                    lo++;
                }
            }
        }
        else if (jquery->anchor && skip_anchor) {
            if (--skip_anchor) continue;
        }

        /* Check limit. */
        if (jquery->limit && jquery->limit <= json_array_size(jquery->ids)) {
            break;
        }

        /* Add to result list. */
        if (result_pos == -1) {
            result_pos = i;
        }
        json_array_append_new(jquery->ids, json_string(rec->id));
    }
    if (jquery->anchor && !seen_anchor) {
        json_decref(jquery->ids);
        jquery->ids = json_array();
    }
    if (result_pos >= 0) {
        jquery->position = result_pos;
    }

done:
    _mboxquery_free(&query);
    return r;
}

static int _mbox_parse_comparator(struct jmap_comparator *comp, void *rock __attribute__((unused)))
{
    /* Reject unsupported properties */
    if (strcmp(comp->property, "sortOrder") &&
        strcmp(comp->property, "name") &&
        strcmp(comp->property, "parent/name")) {
        return 0;
    }
    /* Reject any collation */
    if (comp->collation) {
        return 0;
    }
    return 1;
}

static void _mbox_parse_filter(json_t *filter, struct jmap_parser *parser,
                               json_t *unsupported,
                               void *rock __attribute__((unused)))
{
    json_t *val;
    const char *field;
    struct buf path = BUF_INITIALIZER;
    json_object_foreach(filter, field, val) {
        if (!strcmp(field, "parentId")) {
            if (val != json_null() && !json_is_string(val)) {
                jmap_parser_invalid(parser, "parentId");
            }
        }
        else if (!strcmp(field, "hasRole")) {
            if (!json_is_boolean(val)) {
                jmap_parser_invalid(parser, "hasRole");
            }
        }
        else {
            jmap_parser_push(parser, field);
            jmap_parser_path(parser, &path);
            json_array_append_new(unsupported, json_string(buf_cstring(&path)));
            buf_reset(&path);
        }
    }
    buf_free(&path);
}


static int jmap_mailbox_query(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req->args, &parser,
            _mbox_parse_filter, NULL,
            _mbox_parse_comparator, NULL,
            &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Search for the mailboxes */
    int r = _mbox_query(req, &query);
    if (r) {
        jmap_error(req, json_pack("{s:s}", "type", "serverError"));
        goto done;
    }
    json_t *jstate = jmap_getstate(req, 0/*mbtype*/);
    query.state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    /* Build response */
    jmap_ok(req, jmap_query_reply(&query));

done:
    jmap_parser_fini(&parser);
    jmap_query_fini(&query);
    return 0;
}

static int jmap_mailbox_querychanges(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_querychanges query;

    /* Parse arguments */
    json_t *err = NULL;
    jmap_querychanges_parse(req->args, &parser,
            _mbox_parse_filter, NULL,
            _mbox_parse_comparator, NULL,
            &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Refuse all attempts to calculcate list updates */
    jmap_error(req, json_pack("{s:s}", "type", "cannotCalculateChanges"));

done:
    jmap_querychanges_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

/* Combine the UTF-8 encoded JMAP mailbox name and its parent IMAP mailbox
 * name to a IMAP mailbox name. Does not check for uniqueness.
 *
 * Return the malloced, combined name, or NULL on error. */
static char *_mbox_newname(const char *name, const char *parentname)
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
    mbname_push_boxes(mbname, s);
    free(s);
    mboxname = xstrdup(mbname_intname(mbname));
    mbname_free(&mbname);

done:
    charset_free(&cs);
    return mboxname;
}

struct _mbox_find_xrole_rock {
    const char *xrole;
    const char *userid;
    char *mboxname;
};

static int _mbox_find_xrole_cb(const mbentry_t *mbentry, void *rock)
{
    struct _mbox_find_xrole_rock *d = (struct _mbox_find_xrole_rock *)rock;
    struct buf attrib = BUF_INITIALIZER;

    annotatemore_lookup(mbentry->name, IMAP_ANNOT_NS "x-role", d->userid, &attrib);

    if (attrib.len && !strcmp(buf_cstring(&attrib), d->xrole)) {
        d->mboxname = xstrdup(mbentry->name);
    }

    buf_free(&attrib);

    if (d->mboxname) return CYRUSDB_DONE;
    return 0;
}

static char *_mbox_find_xrole(jmap_req_t *req, const char *xrole)
{
    struct _mbox_find_xrole_rock rock = { xrole, req->userid, NULL };
    /* INBOX can never have an x-role. */
    jmap_mboxlist(req, _mbox_find_xrole_cb, &rock);
    return rock.mboxname;
}

static int _mbox_isparent_cb(const mbentry_t *mbentry __attribute__ ((unused)), void *rock) {
    int *has_child = (int *) rock;
    *has_child = 1;
    return IMAP_OK_COMPLETED;
}

static int _mbox_isparent(const char *mboxname)
{
    int has_child = 0;
    mboxlist_mboxtree(mboxname, _mbox_isparent_cb, &has_child, MBOXTREE_SKIP_ROOT);
    return has_child;
}

struct jmap_mailbox_set {
    const char *id;
    char *name;
    char *parentid;
    const char *role;
    const char *specialuse;
    int sortorder;
};

static void jmap_mailbox_set_fini(struct jmap_mailbox_set *args)
{
    free(args->parentid);
    free(args->name);
}

static void jmap_mailbox_set_parse(jmap_req_t *req,
                                   json_t *jargs,
                                   struct jmap_mailbox_set *args,
                                   int is_create,
                                   json_t *invalid)
{
    int pe;

    /* Initialize arguments */
    memset(args, 0, sizeof(struct jmap_mailbox_set));
    args->sortorder = -1;

    /* id */
    pe = readprop(jargs, "id", 0, invalid, "s", &args->id);
    if (pe > 0 && is_create) {
        json_array_append_new(invalid, json_string("id"));
    }

    /* name */
    const char *s;
    pe = readprop(jargs, "name", is_create, invalid, "s", &s);
    if (pe > 0) {
        char *name = charset_utf8_normalize(s);
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
            json_array_append_new(invalid, json_string("name"));
        }
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
        char *tmp = _mbox_find_uniqueid(req, args->parentid);
        if (!tmp) json_array_append_new(invalid, json_string("parentId"));
        free(tmp);
    }

    /* role */
    if (JNOTNULL(json_object_get(jargs, "role"))) {
        pe = readprop(jargs, "role", is_create, invalid, "s", &args->role);
        if (pe > 0) {
            int is_valid = 1;
            if (!strcmp(args->role, "inbox")) {
                /* inbox role is server-set */
                is_valid = 0;
            } else if (!strcmp(args->role, "archive")) {
                args->specialuse = "\\Archive";
            } else if (!strcmp(args->role, "drafts")) {
                args->specialuse = "\\Drafts";
            } else if (!strcmp(args->role, "junk")) {
                args->specialuse = "\\Junk";
            } else if (!strcmp(args->role, "sent")) {
                args->specialuse = "\\Sent";
            } else if (!strcmp(args->role, "trash")) {
                args->specialuse = "\\Trash";
            } else if (strncmp(args->role, "x-", 2)) {
                /* Does it start with an "x-"? If not, reject it. */
                is_valid = 0;
            }
            if (is_valid) {
                char *exists = NULL;
                if (args->specialuse) {
                    /* Check that no such IMAP specialuse mailbox already exists. */
                    exists = _mbox_find_specialuse(req, args->specialuse);
                } else {
                    /* Check that no mailbox with this x-role exists. */
                    exists = _mbox_find_xrole(req, args->role);
                }
                is_valid = exists == NULL;
                free(exists);
            }
            if (!is_valid) {
                json_array_append_new(invalid, json_string("role"));
            }
        }
    }
    /* sortOrder */
    if (readprop(jargs, "sortOrder", 0, invalid, "i", &args->sortorder) > 0) {
        if (args->sortorder < 0 || args->sortorder >= INT_MAX) {
            json_array_append_new(invalid, json_string("sortOrder"));
        }
    }

    /* mayXXX. These are immutable, but we ignore them during update. */
    json_t *jrights = json_object_get(jargs, "myRights");
    if (JNOTNULL(jrights)) {
        if (json_object_get(jrights, "mayReadItems") && is_create) {
            json_array_append_new(invalid, json_string("myRights/mayReadItems"));
        }
        if (json_object_get(jrights, "mayAddItems") && is_create) {
            json_array_append_new(invalid, json_string("myRights/mayAddItems"));
        }
        if (json_object_get(jrights, "mayRemoveItems") && is_create) {
            json_array_append_new(invalid, json_string("myRights/mayRemoveItems"));
        }
        if (json_object_get(jrights, "mayRename") && is_create) {
            json_array_append_new(invalid, json_string("myRights/mayRename"));
        }
        if (json_object_get(jrights, "mayDelete") && is_create) {
            json_array_append_new(invalid, json_string("myRights/mayDelete"));
        }
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

static int _mbox_set_annots(jmap_req_t *req,
                            struct jmap_mailbox_set *args,
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

static int _mbox_create(jmap_req_t *req,
                           struct jmap_mailbox_set *args,
                           json_t *invalid,
                           char **mboxid,
                           json_t **err __attribute__((unused)))
{
    char *mboxname = NULL, *parentname = NULL;
    int r = 0, rights = 0;
    mbentry_t *mbinbox = NULL, *mbparent = NULL, *mbentry = NULL;

    mboxlist_lookup(req->inboxname, &mbinbox, NULL);

    /* Check parent ACL */
    parentname = _mbox_find_uniqueid(req, args->parentid);
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

    /* Encode the mailbox name for IMAP. */
    mboxname = _mbox_newname(args->name, parentname);
    if (!mboxname) {
        syslog(LOG_ERR, "could not encode mailbox name");
        r = IMAP_INTERNAL;
        goto done;
    }
    mbentry_t *mbexists = NULL;
    r = mboxlist_lookup(mboxname, &mbexists, NULL);
    mboxlist_entry_free(&mbexists);
    if (r != IMAP_MAILBOX_NONEXISTENT) {
        syslog(LOG_ERR, "jmap: mailbox already exists: %s", mboxname);
        json_array_append_new(invalid, json_string("name"));
        r = 0;
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
    r = _mbox_set_annots(req, args, mboxname);
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

static int _mbox_update(jmap_req_t *req,
                        struct jmap_mailbox_set *args,
                        json_t *invalid,
                        const char *mboxid,
                        json_t **err)
{
    /* So many names... manage them in our own string pool */
    ptrarray_t strpool = PTRARRAY_INITIALIZER;
    int r = 0, rights = 0;
    mbentry_t *mbinbox = NULL, *mbentry = NULL, *mbparent = NULL;
    mboxlist_lookup(req->inboxname, &mbinbox, NULL);

    /* Sanity-check arguments */
    if (args->id && strcmp(args->id, mboxid)) {
        json_array_append_new(invalid, json_string("id"));
    }
    if (json_array_size(invalid)) return 0;

    /* Determine current mailbox and parent names */
    char *mboxname = NULL;
    char *parentname = NULL;
    if (strcmp(mboxid, mbinbox->uniqueid)) {
        mboxname = _mbox_find_uniqueid(req, mboxid);
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
    ptrarray_append(&strpool, mboxname);
    ptrarray_append(&strpool, parentname);
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
            newparentname = _mbox_find_uniqueid(req, args->parentid);
        } else {
            newparentname = xstrdup(mbinbox->name);
        }
        if (!newparentname) {
            json_array_append_new(invalid, json_string("parentId"));
            goto done;
        }
        ptrarray_append(&strpool, newparentname);

        /* Is this a move ot a new parent? */
        if (strcmpsafe(parentname, newparentname)) {
            /* Check ACL of mailbox */
            if (!(rights & ACL_DELETEMBOX)) {
                *err = json_pack("{s:s}", "type", "readOnly");
                goto done;
            }

            /* Reset pointers to parent */
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
        }
    }

    /* Do we need to rename the mailbox? But only if it isn't the INBOX! */
    if ((args->name || force_rename) && strcmpsafe(mboxname, mbinbox->name)) {
        mbname_t *mbname = mbname_from_intname(mboxname);
        char *oldname = _mbox_get_name(req, mbname);
        ptrarray_append(&strpool, oldname);
        mbname_free(&mbname);
        char *name = xstrdup(args->name ? args->name : oldname);
        ptrarray_append(&strpool, name);

        /* Do old and new mailbox names differ? */
        if (force_rename || strcmpsafe(oldname, name)) {

            /* Determine the unique IMAP mailbox name. */
            char *newmboxname = _mbox_newname(name, parentname);
            if (!newmboxname) {
                syslog(LOG_ERR, "_mbox_newname returns NULL: can't rename %s", mboxname);
                r = IMAP_INTERNAL;
                free(oldname);
                goto done;
            }
            ptrarray_append(&strpool, newmboxname);

            mbentry_t *mbexists = NULL;
			r = mboxlist_lookup(newmboxname, &mbexists, NULL);
            mboxlist_entry_free(&mbexists);
			if (r != IMAP_MAILBOX_NONEXISTENT) {
				syslog(LOG_ERR, "jmap: mailbox already exists: %s", mboxname);
				json_array_append_new(invalid, json_string("name"));
				r = 0;
				goto done;
			}
            const char *oldmboxname = mboxname;

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
                goto done;
            }
            mboxname = newmboxname;
        }
    }

    /* Write annotations */
    r = _mbox_set_annots(req, args, mboxname);
    if (r) goto done;

done:
    while (strpool.count) free(ptrarray_pop(&strpool));
    ptrarray_fini(&strpool);
    mboxlist_entry_free(&mbentry);
    mboxlist_entry_free(&mbinbox);
    mboxlist_entry_free(&mbparent);

    return r;
}

static int _mbox_destroy(jmap_req_t *req, const char *mboxid, int removemsgs, json_t **err)
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
    mboxname = _mbox_find_uniqueid(req, mboxid);
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
    if (_mbox_isparent(mboxname)) {
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

static int jmap_mailbox_set(jmap_req_t *req)
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
        json_incref(state);
    }
    set = json_pack("{s:s}", "accountId", req->accountid);
    json_object_set_new(set, "oldState", state ? state : jmap_getstate(req, 0));

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
                struct jmap_mailbox_set args;

                /* Process arguments */
                jmap_mailbox_set_parse(req, arg, &args, 1, invalid);
                if (!json_array_size(invalid)) {
                    r = _mbox_create(req, &args, invalid, &uid, &err);
                }
                jmap_mailbox_set_fini(&args);

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
            struct jmap_mailbox_set args;

            /* Process arguments */
            jmap_mailbox_set_parse(req, arg, &args, 0, invalid);
            if (!json_array_size(invalid)) {
                r = _mbox_update(req, &args, invalid, uid, &err);
            }
            jmap_mailbox_set_fini(&args);

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
            r = _mbox_destroy(req, uid, removemsgs, &err);
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

struct _mbox_changes_data {
    json_t *changed;        /* maps mailbox ids to {id:foldermodseq} */
    json_t *destroyed;      /* maps mailbox ids to {id:foldermodseq} */
    modseq_t since_modseq;
    int *only_counts_changed;
    jmap_req_t *req;
};

static int _mbox_changes_cb(const mbentry_t *mbentry, void *rock)
{
    struct _mbox_changes_data *data = rock;
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
    if (mbmodseq <= data->since_modseq) {
        return 0;
    }

    /* Is this a more recent update for an id that we have already seen? */
    if ((update = json_object_get(data->destroyed, mbentry->uniqueid))) {
        modseq = (modseq_t)json_integer_value(json_object_get(update, "modseq"));
        if (modseq <= mbmodseq) {
            json_object_del(data->destroyed, mbentry->uniqueid);
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
    if (mbentry->foldermodseq > data->since_modseq) {
        *(data->only_counts_changed) = 0;
    }

    /* OK, report that update. Note that we even report hidden mailboxes
     * in order to allow clients remove unshared and deleted mailboxes */
    update = json_pack("{s:s s:i}", "id", mbentry->uniqueid, "modseq", mbmodseq);
    int rights = jmap_myrights(req, mbentry);
    if ((mbentry->mbtype & MBTYPE_DELETED) || !(rights & ACL_LOOKUP)) {
        updates = data->destroyed;
    } else {
        updates = data->changed;
    }
    json_object_set_new(updates, mbentry->uniqueid, update);

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
                         modseq_t since_modseq,
                         struct jmap_changes *changes,
                         int *only_counts_changed)
{
    *only_counts_changed = 1;

    ptrarray_t updates = PTRARRAY_INITIALIZER;
    struct _mbox_changes_data data = {
        json_pack("{}"),
        json_pack("{}"),
        since_modseq,
        only_counts_changed,
        req
    };
    modseq_t windowmodseq;
    const char *id;
    json_t *val;
    int r, i;


    /* Search for updates */
    r = jmap_allmbox(req, _mbox_changes_cb, &data);
    if (r) goto done;

    /* Sort updates by modseq */
    json_object_foreach(data.changed, id, val) {
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

        if (json_object_get(data.changed, id)) {
            json_array_append_new(changes->changed, json_string(id));
        } else {
            json_array_append_new(changes->destroyed, json_string(id));
        }
    }

    if (!json_array_size(changes->changed) && !json_array_size(changes->destroyed)) {
        *only_counts_changed = 0;
    }

    modseq_t next_modseq = changes->has_more_changes ?
        windowmodseq : jmap_highestmodseq(req, 0);
    json_t *jstate = jmap_fmtstate(next_modseq);
    changes->new_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

done:
    if (data.changed) json_decref(data.changed);
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
    jmap_changes_parse(req->args, &parser, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    modseq_t since_modseq = atomodseq_t(changes.since_state);
    if (!since_modseq) {
        jmap_error(req, json_pack("{s:s s:[s]}",
                    "type", "invalidArguments",
                    "arguments", "sinceState"));
        goto done;
    }

    /* Search for updates */
    int only_counts_changed = 0;
    int r = _mbox_changes(req, since_modseq, &changes, &only_counts_changed);
    if (r) {
        syslog(LOG_ERR, "jmap: Mailbox/changes: %s", error_message(r));
        jmap_error(req, json_pack("{s:s}", "type", "serverError"));
        goto done;
    }

    /* Build response */
    json_t *res = jmap_changes_reply(&changes);
    json_t *changed_props = json_null();
    if (only_counts_changed) {
        changed_props = json_pack("[s,s,s,s]",
                "totalEmails", "unreadEmails", "totalThreads", "unreadThreads");
    }
    json_object_set_new(res, "changedProperties", changed_props);
    jmap_ok(req, res);

done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    return 0;
}

/*
 * Emails
 */

struct headers {
    json_t *raw; /* JSON array of EmailHeader */
    json_t *all; /* JSON object: lower-case header name => list of values */
    struct buf buf;
};

#define HEADERS_INITIALIZER \
    { json_array(), json_object(), BUF_INITIALIZER }

static void _headers_fini(struct headers *headers) {
    assert(headers);
    json_decref(headers->all);
    json_decref(headers->raw);
    buf_free(&headers->buf);
}

static void _headers_put_new(struct headers *headers, json_t *header, int shift)
{
    const char *name = json_string_value(json_object_get(header, "name"));

    if (headers->raw == NULL)
        headers->raw = json_array();
    if (headers->all == NULL)
        headers->all = json_object();

    /* Append (or shift) the raw header to the in-order header list */
    if (shift)
        json_array_insert(headers->raw, 0, header);
    else
        json_array_append(headers->raw, header);

    /* Append the raw header to the list of all equal-named headers */
    buf_setcstr(&headers->buf, name);
    const char *lcasename = buf_lcase(&headers->buf);
    json_t *all = json_object_get(headers->all, lcasename);
    if (!all) {
        all = json_array();
        json_object_set_new(headers->all, lcasename, all);
    }

    if (shift)
        json_array_insert_new(all, 0, header);
    else
        json_array_append_new(all, header);
}

static void _headers_add_new(struct headers *headers, json_t *header)
{
    if (!header) return;
    _headers_put_new(headers, header, 0);
}

static void _headers_shift_new(struct headers *headers, json_t *header)
{
    if (!header) return;
    _headers_put_new(headers, header, 1);
}

static json_t* _headers_get(struct headers *headers, const char *name)
{
    char *lcasename = lcase(xstrdup(name));
    json_t *jheader = json_object_get(headers->all, lcasename);
    free(lcasename);
    return jheader;
}

static int _headers_have(struct headers *headers, const char *name)
{
    return _headers_get(headers, name) != NULL;
}

static int _headers_from_mime_cb(const char *key, const char *val, void *_rock)
{
    struct headers *headers = _rock;
    _headers_add_new(headers, json_pack("{s:s s:s}", "name", key, "value", val));
    return 0;
}

static void _headers_from_mime(const char *base, size_t len, struct headers *headers)
{
    message_foreach_header(base, len, _headers_from_mime_cb, headers);
}

static json_t *_header_as_raw(const char *raw)
{
    return raw ? json_string(raw) : json_null();
}

static json_t *_header_as_text(const char *raw)
{
    if (!raw) return json_null();

    /* TODO this could be optimised to omit unfolding, decoding
     * or normalisation, or all, if ASCII */
    /* Unfold and remove CRLF */
    char *unfolded = charset_unfold(raw, strlen(raw), 0);
    char *p = strchr(unfolded, '\r');
    while (p && *(p + 1) != '\n') {
        p = strchr(p + 1, '\r');
    }
    if (p) *p = '\0';
    /* Trim starting SP */
    const char *trimmed = unfolded;
    while (isspace(*trimmed)) {
        trimmed++;
    }
    /* Decode header */
    char *decoded = charset_decode_mimeheader(trimmed, CHARSET_SNIPPET);
    /* Convert to Unicode NFC */
    char *nfc = charset_utf8_normalize(decoded);

    json_t *result = json_string(nfc);
    free(nfc);
    free(decoded);
    free(unfolded);
    return result;
}

static json_t *_header_as_messageids(const char *raw)
{
    if (!raw) return json_null();

    json_t *msgids = json_array();
    struct buf buf = BUF_INITIALIZER;
    const char *lo = raw;
    while (*lo) {
        lo = strchr(lo, '<');
        if (!lo) break;
        const char *hi = strchr(lo + 1, '>');
        if (!hi) break;
        buf_setmap(&buf, lo + 1, hi - lo - 1);
        json_array_append_new(msgids, json_string(buf_cstring(&buf)));
        lo = hi + 1;
    }
    if (!json_array_size(msgids)) {
        json_decref(msgids);
        msgids = json_null();
    }
    buf_free(&buf);
    return msgids;
}

static json_t *_emailaddresses_from_addr(struct address *addr)
{
    if (!addr) return json_null();

    json_t *addresses = json_array();
    struct buf buf = BUF_INITIALIZER;

    while (addr) {
        json_t *e = json_pack("{}");

        /* name */
        if (addr->name) {
            char *tmp = charset_decode_mimeheader(addr->name, CHARSET_SNIPPET);
            if (tmp) json_object_set_new(e, "name", json_string(tmp));
            free(tmp);
        } else {
            json_object_set_new(e, "name", json_null());
        }

        /* email */
        const char *mailbox = addr->mailbox;
        if (mailbox) {
            buf_setcstr(&buf, mailbox);
            const char *domain = addr->domain;
            if (!strcmpsafe(domain, "unspecified-domain")) {
                domain = NULL;
            }
            if (domain) {
                buf_putc(&buf, '@');
                buf_appendcstr(&buf, domain);
            }
            json_object_set_new(e, "email", json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        } else {
            json_object_set_new(e, "email", json_null());
        }
        json_array_append_new(addresses, e);
        addr = addr->next;
    }

    if (!json_array_size(addresses)) {
        json_decref(addresses);
        addresses = json_null();
    }
    buf_free(&buf);
    return addresses;
}


static json_t *_header_as_addresses(const char *raw)
{
    if (!raw) return json_null();

    struct address *addrs = NULL;
    parseaddr_list(raw, &addrs);
    json_t *result = _emailaddresses_from_addr(addrs);
    parseaddr_free(addrs);
    return result;
}

static json_t *_header_as_urls(const char *raw)
{
    if (!raw) return json_null();

    /* A poor man's implementation of RFC 2369, returning anything
     * between < and >. */
    json_t *urls = json_array();
    struct buf buf = BUF_INITIALIZER;
    const char *base = raw;
    const char *top = raw + strlen(raw);
    while (base < top) {
        const char *lo = strchr(base, '<');
        if (!lo) break;
        const char *hi = strchr(lo, '>');
        if (!hi) break;
        buf_setmap(&buf, lo + 1, hi - lo - 1);
        json_array_append_new(urls, json_string(buf_cstring(&buf)));
        base = hi + 1;
    }
    if (!json_array_size(urls)) {
        json_decref(urls);
        urls = json_null();
    }
    buf_free(&buf);
    return urls;
}

enum _header_form {
    HEADER_FORM_UNKNOWN = 0, /* MUST be zero so we can cast to void* */
    HEADER_FORM_RAW,
    HEADER_FORM_TEXT,
    HEADER_FORM_ADDRESSES,
    HEADER_FORM_MESSAGEIDS,
    HEADER_FORM_DATE,
    HEADER_FORM_URLS
};

struct header_prop {
    char *lcasename;
    char *name;
    const char *prop;
    enum _header_form form;
    int all;
};

static void _header_prop_fini(struct header_prop *prop)
{
    free(prop->lcasename);
    free(prop->name);
}

static void _header_prop_free(struct header_prop *prop)
{
    _header_prop_fini(prop);
    free(prop);
}

static struct header_prop *_header_parseprop(const char *s)
{
    strarray_t *fields = strarray_split(s + 7, ":", 0);
    const char *f0, *f1, *f2;
    int is_valid = 1;
    enum _header_form form = HEADER_FORM_RAW;
    char *lcasename = NULL, *name = NULL;

    /* Initialize allowed header forms by lower-case header name. Any
     * header in this map is allowed to be requested either as Raw
     * or the form of the map value (casted to void* because C...).
     * Any header not found in this map is allowed to be requested
     * in any form. */
    static hash_table allowed_header_forms = HASH_TABLE_INITIALIZER;
    if (allowed_header_forms.size == 0) {
        /* TODO initialize with all headers in RFC5322 and RFC2369 */
        construct_hash_table(&allowed_header_forms, 32, 0);
        hash_insert("bcc", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("cc", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("content-type", (void*) HEADER_FORM_RAW, &allowed_header_forms);
        hash_insert("comment", (void*) HEADER_FORM_TEXT, &allowed_header_forms);
        hash_insert("date", (void*) HEADER_FORM_DATE, &allowed_header_forms);
        hash_insert("from", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("in-reply-to", (void*) HEADER_FORM_MESSAGEIDS, &allowed_header_forms);
        hash_insert("list-archive", (void*) HEADER_FORM_URLS, &allowed_header_forms);
        hash_insert("list-help", (void*) HEADER_FORM_URLS, &allowed_header_forms);
        hash_insert("list-owner", (void*) HEADER_FORM_URLS, &allowed_header_forms);
        hash_insert("list-post", (void*) HEADER_FORM_URLS, &allowed_header_forms);
        hash_insert("list-subscribe", (void*) HEADER_FORM_URLS, &allowed_header_forms);
        hash_insert("list-unsubscribe", (void*) HEADER_FORM_URLS, &allowed_header_forms);
        hash_insert("message-id", (void*) HEADER_FORM_MESSAGEIDS, &allowed_header_forms);
        hash_insert("references", (void*) HEADER_FORM_MESSAGEIDS, &allowed_header_forms);
        hash_insert("reply-to", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("resent-date", (void*) HEADER_FORM_DATE, &allowed_header_forms);
        hash_insert("resent-from", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("resent-message-id", (void*) HEADER_FORM_MESSAGEIDS, &allowed_header_forms);
        hash_insert("resent-reply-to", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("resent-sender", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("resent-to", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("resent-cc", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("resent-bcc", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("sender", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
        hash_insert("subject", (void*) HEADER_FORM_TEXT, &allowed_header_forms);
        hash_insert("to", (void*) HEADER_FORM_ADDRESSES, &allowed_header_forms);
    }

    /* Parse property string into fields */
    f0 = f1 = f2 = NULL;
    switch (fields->count) {
        case 3:
            f2 = strarray_nth(fields, 2);
            /* fallthrough */
        case 2:
            f1 = strarray_nth(fields, 1);
            /* fallthrough */
        case 1:
            f0 = strarray_nth(fields, 0);
            lcasename = lcase(xstrdup(f0));
            name = xstrdup(f0);
            break;
        default:
            strarray_free(fields);
            return NULL;
    }

    if (f2 && (strcmp(f2, "all") || !strcmp(f1, "all"))) {
        strarray_free(fields);
        return NULL;
    }
    if (f1) {
        if (!strcmp(f1, "asRaw"))
            form = HEADER_FORM_RAW;
        else if (!strcmp(f1, "asText"))
            form = HEADER_FORM_TEXT;
        else if (!strcmp(f1, "asAddresses"))
            form = HEADER_FORM_ADDRESSES;
        else if (!strcmp(f1, "asMessageIds"))
            form = HEADER_FORM_MESSAGEIDS;
        else if (!strcmp(f1, "asDate"))
            form = HEADER_FORM_DATE;
        else if (!strcmp(f1, "asURLs"))
            form = HEADER_FORM_URLS;
        else if (strcmp(f1, "all"))
            is_valid = 0;
    }

    /* Validate requested header form */
    if (is_valid && form != HEADER_FORM_RAW) {
        enum _header_form allowed_form = (enum _header_form) \
                                         hash_lookup(lcasename, &allowed_header_forms);
        if (allowed_form != HEADER_FORM_UNKNOWN && form != allowed_form) {
            is_valid = 0;
        }
    }

    struct header_prop *hprop = NULL;
    if (is_valid) {
        hprop = xzmalloc(sizeof(struct header_prop));
        hprop->lcasename = lcasename;
        hprop->name = name;
        hprop->prop = s;
        hprop->form = form;
        hprop->all = f2 != NULL || (f1 && !strcmp(f1, "all"));
    }
    else {
        free(lcasename);
        free(name);
    }
    strarray_free(fields);
    return hprop;
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
static char *_email_extract_preview(const char *text, size_t len)
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

struct _email_get_mailboxes_rock {
    jmap_req_t *req;
    json_t *mboxs;
};

static int _email_get_mailboxes_cb(const conv_guidrec_t *rec, void *rock)
{
    struct _email_get_mailboxes_rock *data = (struct _email_get_mailboxes_rock*) rock;
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

struct attachment {
    struct body *body;
};

struct emailbodies {
    struct body *text;
    struct body *html;
    ptrarray_t atts;
    ptrarray_t msgs;
    ptrarray_t textlist;
    ptrarray_t htmllist;
};

#define EMAILBODIES_INITIALIZER { \
    NULL, \
    NULL, \
    PTRARRAY_INITIALIZER, \
    PTRARRAY_INITIALIZER, \
    PTRARRAY_INITIALIZER, \
    PTRARRAY_INITIALIZER \
}

static void _emailbodies_fini(struct emailbodies *bodies)
{
    ptrarray_fini(&bodies->atts);
    ptrarray_fini(&bodies->msgs);
    ptrarray_fini(&bodies->textlist);
    ptrarray_fini(&bodies->htmllist);
}


static int _email_extract_bodies(struct body *root, struct buf *msg_buf,
                                 struct emailbodies *bodies)
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

static char *_emailbodies_to_plain(struct emailbodies *bodies, struct buf *msg_buf)
{
    if (bodies->textlist.count == 1) {
        struct body *textbody = ptrarray_nth(&bodies->textlist, 0);
        charset_t cs = charset_lookupname(textbody->charset_id);
        char *text = charset_to_utf8(msg_buf->s + textbody->content_offset,
                textbody->content_size, cs, textbody->charset_enc);
        charset_free(&cs);
        return text;
    }

    /* Concatenate all plain text bodies and replace any
     * inlined images with placeholders. */
    int i;
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < bodies->textlist.count; i++) {
        struct body *part = ptrarray_nth(&bodies->textlist, i);

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
    return buf_release(&buf);
}

/* Replace any <HTML> and </HTML> tags in t with <DIV> and </DIV>,
 * writing results into buf */
static void _html_concat_div(struct buf *buf, const char *t)
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


static char *_emailbodies_to_html(struct emailbodies *bodies, struct buf *msg_buf)
{
    if (bodies->htmllist.count == 1) {
        charset_t cs = charset_lookupname(bodies->html->charset_id);
        char *html = charset_to_utf8(msg_buf->s + bodies->html->content_offset,
                bodies->html->content_size, cs, bodies->html->charset_enc);
        charset_free(&cs);
        return html;
    }

    /* Concatenate all TEXT bodies, enclosing PLAIN text
     * in <div> and replacing <html> tags in HTML bodies
     * with <div>. */
    int i;
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < bodies->htmllist.count; i++) {
        struct body *part = ptrarray_nth(&bodies->htmllist, i);

        /* XXX htmllist might include inlined images but we
         * currently ignore them. After all, there should
         * already be an <img> tag for their Content-Id
         * header value. If this turns out to be not enough,
         * we can insert the <img> tags here. */
        if (strcasecmp(part->type, "TEXT")) {
            continue;
        }

        if (!i)
            buf_appendcstr(&buf, "<html>"); // XXX use HTML5?

        charset_t cs = charset_lookupname(part->charset_id);
        char *t = charset_to_utf8(msg_buf->s + part->content_offset,
                part->content_size, cs, part->charset_enc);

        if (!strcmp(part->subtype, "HTML")) {
            _html_concat_div(&buf, t);
        }
        else {
            buf_appendcstr(&buf, "<div>");
            buf_appendcstr(&buf, t);
            buf_appendcstr(&buf, "</div>");
        }
        charset_free(&cs);
        free(t);

        if (i == bodies->htmllist.count - 1)
            buf_appendcstr(&buf, "</html>");
    }
    return buf_release(&buf);
}

static void _html_to_plain_cb(const struct buf *buf, void *rock)
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

static char *_html_to_plain(const char *html) {
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
    charset_extract(&_html_to_plain_cb, &dst,
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

static char *_email_id_from_guid(const struct message_guid *guid)
{
    char *msgid = xzmalloc(26);
    msgid[0] = 'M';
    memcpy(msgid+1, message_guid_encode(guid), 24);
    return msgid;
}

static const char *_guid_from_id(const char *msgid)
{
    return msgid + 1;
}

static char *_thread_id_from_cid(conversation_id_t cid)
{
    char *thrid = xzmalloc(18);
    thrid[0] = 'T';
    memcpy(thrid+1, conversation_id_encode(cid), 16);
    return thrid;
}

static conversation_id_t _cid_from_id(const char *thrid)
{
    conversation_id_t cid = 0;
    if (thrid[0] == 'T')
        conversation_id_decode(&cid, thrid+1);
    return cid;
}

/*
 * Lookup all mailboxes where msgid is contained in.
 *
 * The return value is a JSON object keyed by the mailbox unique id,
 * and its mailbox name as value.
 */
static json_t *_email_get_mailboxes(jmap_req_t *req, const char *msgid)
{
    struct _email_get_mailboxes_rock data = { req, json_pack("{}") };
    conversations_guid_foreach(req->cstate, _guid_from_id(msgid), _email_get_mailboxes_cb, &data);
    return data.mboxs;
}



static int _email_keyword_is_valid(const char *keyword)
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

static char *jmap_keyword_from_imap(const char *flag)
{
    const char *kw = NULL;
    if (!strcmp(flag, "\\Seen"))
        kw = "$seen";
    else if (!strcmp(flag, "\\Flagged"))
        kw = "$flagged";
    else if (!strcmp(flag, "\\Answered"))
        kw = "$answered";
    else if (!strcmp(flag, "\\Draft"))
        kw = "$draft";
    else if (*flag != '\\')
        kw = flag;
    return kw ? lcase(xstrdup(kw)) : NULL;
}

static const char *jmap_keyword_to_imap(const char *keyword)
{
    if (!strcasecmp(keyword, "$Seen")) {
        return "\\Seen";
    }
    else if (!strcasecmp(keyword, "$Flagged")) {
        return "\\Flagged";
    }
    else if (!strcasecmp(keyword, "$Answered")) {
        return "\\Answered";
    }
    else if (!strcasecmp(keyword, "$Draft")) {
        return "\\Draft";
    }
    else if (_email_keyword_is_valid(keyword)) {
        return keyword;
    }
    return NULL;
}

static json_t *_email_get_annot(const jmap_req_t *req, msgrecord_t *mr,
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

struct _email_get_keywords_rock {
    jmap_req_t *req;
    json_t *keywords; /* map of keyword name to occurrence count */
    json_int_t message_count; /* count of unexpunged message */
};

static int _email_get_keywords_cb(const conv_guidrec_t *rec, void *rock)
{
    struct _email_get_keywords_rock *data = (struct _email_get_keywords_rock*) rock;
    jmap_req_t *req = data->req;
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    uint32_t system_flags;

    if (rec->part) return 0;

    /* Fetch system flags */
    int r = jmap_openmbox(req, rec->mboxname, &mbox, 0);
    if (r) return r;

    r = msgrecord_find(mbox, rec->uid, &mr);
    if (r) goto done;

    r = msgrecord_get_systemflags(mr, &system_flags);
    if (r) goto done;
    if (system_flags & (FLAG_EXPUNGED|FLAG_DELETED)) goto done;

    /* Count that message */
    data->message_count++;

    /* Extract and count message flags */
    strarray_t *flags = NULL;
    r = msgrecord_extract_flags(mr, req->accountid, &flags);
    if (r) goto done;
    char *flag;
    while ((flag = strarray_pop(flags))) {
        char *kw = jmap_keyword_from_imap(flag);
        if (!kw)
            continue;
        json_t *jval = json_object_get(data->keywords, kw);
        if (jval)
            json_integer_set(jval, json_integer_value(jval) + 1);
        else
            json_object_set_new(data->keywords, kw, json_integer(1));
        free(flag);
        free(kw);
    }
    strarray_free(flags);

done:
    msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);
    return r;
}

static int _email_get_keywords(jmap_req_t *req, const char *msgid, json_t **jkeywords)
{
    /* Gather counts per message flag */
    struct _email_get_keywords_rock data = { req, json_pack("{}"), 0 };
    int r = conversations_guid_foreach(req->cstate, _guid_from_id(msgid), _email_get_keywords_cb, &data);

    /* Handle special keywords */
    json_t *jcount = json_object_get(data.keywords, "$seen");
    if (jcount && json_integer_value(jcount) < data.message_count)
        json_object_del(data.keywords, "$seen");

    /* Convert to map to boolean */
    json_t *keywords = json_object();
    json_t *jval;
    const char *kw;
    json_object_foreach(data.keywords, kw, jval) {
        json_object_set_new(keywords, kw, json_true());
    }
    json_decref(data.keywords);

    *jkeywords = keywords;
    return r;
}

struct _email_find_rock {
    jmap_req_t *req;
    char *mboxname;
    uint32_t uid;
};

static int _email_find_cb(const conv_guidrec_t *rec, void *rock)
{
    struct _email_find_rock *d = (struct _email_find_rock*) rock;
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

static int _email_find(jmap_req_t *req, const char *msgid,
                     char **mboxnameptr, uint32_t *uid)
{
    struct _email_find_rock rock = { req, NULL, 0 };
    int r;

    /* must be prefixed with 'M' */
    if (msgid[0] != 'M')
        return IMAP_NOTFOUND;
    /* this is on a 24 character prefix only */
    if (strlen(msgid) != 25)
        return IMAP_NOTFOUND;

    r = conversations_guid_foreach(req->cstate, _guid_from_id(msgid), _email_find_cb, &rock);
    if (r == IMAP_OK_COMPLETED) {
        r = 0;
    }
    else if (!rock.mboxname) {
        r = IMAP_NOTFOUND;
    }
    *mboxnameptr = rock.mboxname;
    *uid = rock.uid;
    return r;
}

static int _email_is_expunged_cb(const conv_guidrec_t *rec, void *rock)
{
    jmap_req_t *req = rock;
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
            r = IMAP_OK_COMPLETED;
        }
        msgrecord_unref(&mr);
    }

    jmap_closembox(req, &mbox);
    return r;
}

static void _email_search_string(search_expr_t *parent, const char *s, const char *name)
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

static void _email_search_mbox(jmap_req_t *req, search_expr_t *parent,
                          json_t *mailbox, int is_not)
{
    search_expr_t *e;
    const char *s = json_string_value(mailbox);
    char *mboxname = _mbox_find_uniqueid(req, s);
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

static void _email_search_keyword(search_expr_t *parent, const char *keyword)
{
    search_expr_t *e;
    if (!strcasecmp(keyword, "$Seen")) {
        e = search_expr_new(parent, SEOP_MATCH);
        e->attr = search_attr_find("indexflags");
        e->value.u = MESSAGE_SEEN;
    }
    else if (!strcasecmp(keyword, "$Draft")) {
        e = search_expr_new(parent, SEOP_MATCH);
        e->attr = search_attr_find("systemflags");
        e->value.u = FLAG_DRAFT;
    }
    else if (!strcasecmp(keyword, "$Flagged")) {
        e = search_expr_new(parent, SEOP_MATCH);
        e->attr = search_attr_find("systemflags");
        e->value.u = FLAG_FLAGGED;
    }
    else if (!strcasecmp(keyword, "$Answered")) {
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

static void _email_search_threadkeyword(search_expr_t *parent, const char *keyword)
{
    const char *flag = jmap_keyword_to_imap(keyword);
    if (!flag) return;

    search_expr_t *e = search_expr_new(parent, SEOP_MATCH);
    e->attr = search_attr_find("convflags");
    e->value.s = xstrdup(flag);
}

static int _email_threadkeyword_is_valid(const char *keyword)
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

static search_expr_t *_email_buildsearch(jmap_req_t *req, json_t *filter,
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
            _email_buildsearch(req, val, e);
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
            _email_search_string(this, s, "body");
        }
        if ((s = json_string_value(json_object_get(filter, "cc")))) {
            _email_search_string(this, s, "cc");
        }
        if ((s = json_string_value(json_object_get(filter, "from")))) {
            _email_search_string(this, s, "from");
        }
        if (JNOTNULL((val = json_object_get(filter, "hasAttachment")))) {
            e = val == json_false() ? search_expr_new(this, SEOP_NOT) : this;
            e = search_expr_new(e, SEOP_MATCH);
            e->attr = search_attr_find("keyword");
            e->value.s = xstrdup(JMAP_HAS_ATTACHMENT_FLAG);
        }
        if ((s = json_string_value(json_object_get(filter, "attachmentName")))) {
            _email_search_string(this, s, "attachmentname");
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
            _email_search_mbox(req, this, val, /*is_not*/0);
        }

        json_array_foreach(json_object_get(filter, "inMailboxOtherThan"), i, val) {
            e = search_expr_new(this, SEOP_AND);
            _email_search_mbox(req, e, val, /*is_not*/1);
        }

        if (JNOTNULL((val = json_object_get(filter, "allInThreadHaveKeyword")))) {
            /* This shouldn't happen, validate_sort should have reported
             * allInThreadHaveKeyword as unsupported. Let's ignore this
             * filter and return false positives. */
            syslog(LOG_ERR, "_email_search: ignoring allInThreadHaveKeyword filter");
        }
        if (JNOTNULL((val = json_object_get(filter, "someInThreadHaveKeyword")))) {
            _email_search_threadkeyword(this, json_string_value(val));
        }
        if (JNOTNULL((val = json_object_get(filter, "noneInThreadHaveKeyword")))) {
            e = search_expr_new(this, SEOP_NOT);
            _email_search_threadkeyword(e, json_string_value(val));
        }

        if (JNOTNULL((val = json_object_get(filter, "hasKeyword")))) {
            _email_search_keyword(this, json_string_value(val));
        }
        if (JNOTNULL((val = json_object_get(filter, "notKeyword")))) {
            e = search_expr_new(this, SEOP_NOT);
            _email_search_keyword(e, json_string_value(val));
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
            _email_search_string(this, s, "subject");
        }
        if ((s = json_string_value(json_object_get(filter, "text")))) {
            _email_search_string(this, s, "text");
        }
        if ((s = json_string_value(json_object_get(filter, "to")))) {
            _email_search_string(this, s, "to");
        }
    }

    return this;
}

struct msgfilter_rock {
    jmap_req_t *req;
    json_t *unsupported;
};

static void _email_parse_filter(json_t *filter, struct jmap_parser *parser,
                                json_t *unsupported, void *rock)
{
    jmap_req_t *req = rock;
    json_t *arg, *val;
    const char *s;
    size_t i;

    if (!JNOTNULL(filter) || json_typeof(filter) != JSON_OBJECT) {
        jmap_parser_invalid(parser, NULL);
        return;
    }
    arg = json_object_get(filter, "inMailbox");
    if ((s = json_string_value(arg))) {
        char *n = _mbox_find_uniqueid(req, s);
        if (!n) {
            jmap_parser_invalid(parser, "inMailbox");
        }
        free(n);
    } else if (arg) {
        jmap_parser_invalid(parser, "inMailbox");
    }

    arg = json_object_get(filter, "before");
    if ((s = json_string_value(arg))) {
        struct tm tm;
        const char *p = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
        if (!p || *p) {
            jmap_parser_invalid(parser, "before");
        }
    } else if (arg) {
        jmap_parser_invalid(parser, "before");
    }
    arg = json_object_get(filter, "after");
    if ((s = json_string_value(arg))) {
        struct tm tm;
        const char *p = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
        if (!p || *p) {
            jmap_parser_invalid(parser, "after");
        }
    } else if (arg) {
        jmap_parser_invalid(parser, "after");
    }

    arg = json_object_get(filter, "minSize");
    if (arg && !json_is_integer(arg)) {
        jmap_parser_invalid(parser, "minSize");
    }
    arg = json_object_get(filter, "maxSize");
    if (arg && !json_is_integer(arg)) {
        jmap_parser_invalid(parser, "maxSize");
    }
    arg = json_object_get(filter, "hasAttachment");
    if (arg && !json_is_boolean(arg)) {
        jmap_parser_invalid(parser, "hasAttachment");
    }
    arg = json_object_get(filter, "attachmentName");
    if (arg && !json_is_string(arg)) {
        jmap_parser_invalid(parser, "attachmentName");
    }
    arg = json_object_get(filter, "text");
    if (arg && !json_is_string(arg)) {
        jmap_parser_invalid(parser, "text");
    }
    arg = json_object_get(filter, "from");
    if (arg && !json_is_string(arg)) {
        jmap_parser_invalid(parser, "from");
    }
    arg = json_object_get(filter, "to");
    if (arg && !json_is_string(arg)) {
        jmap_parser_invalid(parser, "to");
    }
    arg = json_object_get(filter, "cc");
    if (arg && !json_is_string(arg)) {
        jmap_parser_invalid(parser, "cc");
    }
    arg = json_object_get(filter, "bcc");
    if (arg && !json_is_string(arg)) {
        jmap_parser_invalid(parser, "bcc");
    }
    arg = json_object_get(filter, "subject");
    if (arg && !json_is_string(arg)) {
        jmap_parser_invalid(parser, "subject");
    }
    arg = json_object_get(filter, "body");
    if (arg && !json_is_string(arg)) {
        jmap_parser_invalid(parser, "body");
    }

    json_array_foreach(json_object_get(filter, "inMailboxOtherThan"), i, val) {
        char *n = NULL;
        if ((s = json_string_value(val))) {
            n = _mbox_find_uniqueid(req, s);
        }
        if (!n) {
            jmap_parser_push_index(parser, "inMailboxOtherThan", i);
            jmap_parser_invalid(parser, NULL);
            jmap_parser_pop(parser);
        }
        free(n);
    }

    arg = json_object_get(filter, "allInThreadHaveKeyword");
    if ((s = json_string_value(arg))) {
        if (!_email_keyword_is_valid(s)) {
            jmap_parser_invalid(parser, "allInThreadHaveKeyword");
        }
        else {
            /* XXX currently can't support this filter */
            json_array_append_new(unsupported, json_pack("{s:s}",
                        "allInThreadHaveKeyword", s));
        }
    } else if (arg) {
        jmap_parser_invalid(parser, "allInThreadHaveKeyword");
    }
    arg = json_object_get(filter, "someInThreadHaveKeyword");
    if ((s = json_string_value(arg))) {
        if (!_email_keyword_is_valid(s)) {
            jmap_parser_invalid(parser, "someInThreadHaveKeyword");
        }
        if (!_email_threadkeyword_is_valid(s)) {
            json_array_append_new(unsupported, json_pack("{s:s}",
                        "someInThreadHaveKeyword", s));
        }
    } else if (arg) {
        jmap_parser_invalid(parser, "someInThreadHaveKeyword");
    }
    arg = json_object_get(filter, "noneInThreadHaveKeyword");
    if ((s = json_string_value(arg))) {
        if (!_email_keyword_is_valid(s)) {
            jmap_parser_invalid(parser, "noneInThreadHaveKeyword");
        }
        if (!_email_threadkeyword_is_valid(s)) {
            json_array_append_new(unsupported, json_pack("{s:s}",
                        "noneInThreadHaveKeyword", s));
        }
    } else if (arg) {
        jmap_parser_invalid(parser, "noneInThreadHaveKeyword");
    }


    arg = json_object_get(filter, "hasKeyword");
    if ((s = json_string_value(arg))) {
        if (!_email_keyword_is_valid(s)) {
            jmap_parser_invalid(parser, "hasKeyword");
        }
    } else if (arg) {
        jmap_parser_invalid(parser, "hasKeyword");
    }
    arg = json_object_get(filter, "notKeyword");
    if ((s = json_string_value(arg))) {
        if (!_email_keyword_is_valid(s)) {
            jmap_parser_invalid(parser, "notKeyword");
        }
    } else if (arg) {
        jmap_parser_invalid(parser, "notKeyword");
    }

    arg = json_object_get(filter, "header");
    if (JNOTNULL(arg)) {
        switch (json_array_size(arg)) {
            case 2:
                s = json_string_value(json_array_get(arg, 1));
                if (!s || !strlen(s)) {
                    jmap_parser_push_index(parser, "header", 1);
                    jmap_parser_invalid(parser, NULL);
                    jmap_parser_pop(parser);
                }
                /* fallthrough */
            case 1:
                s = json_string_value(json_array_get(arg, 0));
                if (!s || !strlen(s)) {
                    jmap_parser_push_index(parser, "header", 0);
                    jmap_parser_invalid(parser, NULL);
                    jmap_parser_pop(parser);
                }
                break;
            default:
                jmap_parser_invalid(parser, "header");
        }
    }
}

static struct sortcrit *_email_buildsort(json_t *sort)
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

struct email_search_window {
    /* input arguments */
    ssize_t position;
    const char *anchor;
    int anchor_off;
    size_t limit;
    int collapse;
    modseq_t sincemodseq;
    uint32_t sinceuid; /* for queryChanges */
    const char *uptomsgid;

    /* output arguments */
    modseq_t highestmodseq;
    uint32_t highestuid; /* for queryChanges */
    int cancalcupdates;

    /* internal state */
    size_t mdcount;
    size_t anchor_pos;
};

static void _email_querychanges_added(json_t *target, const char *msgid, int index)
{
    json_t *item = json_pack("{s:s,s:i}", "id", msgid, "index", index);
    json_array_append_new(target, item);
}

static void _email_querychanges_destroyed(json_t *target, const char *msgid)
{
    json_array_append_new(target, json_string(msgid));
}

static int _email_search(jmap_req_t *req, json_t *filter, json_t *sort,
                         struct email_search_window *window, int want_expunged,
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

	/* TODO rework _email_search
     * - JMAP spec kicked out threadIds from the Email/query response
     *   somewhen late 2017. Now we should cache emailId -> threadId on the
     *   request context to save lookups on conversations.db
     * - JMAP spec introduced negative positions for search results, and
     *   this is what breaks the camel's neck for the mess _email_search got.
     *   This function requires a massive refactor before we can add any new
     *   functionality.
     *   Until then, we fail hard for negative positions
     */
    assert(window->position >= 0);

    assert(!want_expunged || expungedids);

    *total = 0;
    if (*messageids == NULL) *messageids = json_pack("[]");
    if (*threadids == NULL) *threadids = json_pack("[]");
    if (want_expunged && *expungedids == NULL) *expungedids = json_pack("[]");

    /* Build searchargs */
    searchargs = new_searchargs(NULL/*tag*/, GETSEARCH_CHARSET_FIRST,
                                &jmap_namespace, req->accountid, req->authstate, 0);
    searchargs->root = _email_buildsearch(req, filter, NULL);

    /* Run the search query */
    memset(&init, 0, sizeof(init));
    init.userid = req->accountid;
    init.authstate = req->authstate;
    init.want_expunged = want_expunged;

    r = index_open(req->inboxname, &init, &state);
    if (r) goto done;

    query = search_query_new(state, searchargs);
    query->sortcrit = sortcrit = _email_buildsort(sort);
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

    /* Special case: if threads are not collapsed and filter narrows
     * search down to a single mailbox, then we can unambiguously
     * identify in queryChanges if records need to be reported in
     * 'added', e.g. we don't have to report them in both 'added'
     * and 'removed'. */
    int one_mailbox_only = 0;
    if (!window->collapse) {
        if (json_is_string(json_object_get(filter, "inMailbox"))) {
            one_mailbox_only = 1;
        }
    }

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
        msgid = _email_id_from_guid(&md->guid);

        /* Have we seen this message already? */
        if (hash_lookup(msgid, &ids))
            goto doneloop;

        /* Add the message the list of reported messages */
        hash_insert(msgid, (void*)1, &ids);

        /* we're doing jmap_email_querychanges - we use the results differently */
        if (window->sincemodseq) {
            if (foundupto) goto doneloop;

            /* Keep track of the highest modseq */
            if (window->highestmodseq < md->modseq)
                window->highestmodseq = md->modseq;

            /* trivial case - not collapsing conversations */
            if (!window->collapse) {
                if (is_expunged) {
                    if (foundupto) goto doneloop;
                    if (md->modseq <= window->sincemodseq) goto doneloop;
                    _email_querychanges_destroyed(*expungedids, msgid);
                }
                else {
                    (*total)++;
                    if (foundupto) goto doneloop;
                    if (md->modseq <= window->sincemodseq) goto doneloop;
                    /* The modseq of this message is higher than the last
                     * client-seen state.
                     *
                     * The JMAP spec requires us to report
                     * "every foo that has been added to the results since the
                     * old state AND every foo in the current results that was
                     * included in the removed array (due to a filter or sort
                     * based upon a mutable property)"
                     *
                     * The latter case is a non-issue, because we reject
                     * mutable searches with "cannotCalculateChanges".
                     * But for the former case, we can't tell if the message
                     * is a truly new search result by looking at its modseq
                     * or index record. It might just have been an already
                     * seen result that got its modseq bumped. If all results
                     * are in the same mailbox, we can unambigously decide
                     * what to do based on the UID.
                     *
                     * If search isn't narrowed to a single mailbox, we'll
                     * report candiates both in removed AND added, as it's done
                     * in the codepath for collapsed threads.
                     */
                    if (one_mailbox_only) {
                        if (md->uid <= window->sinceuid) goto doneloop;
                        _email_querychanges_added(*messageids, msgid, *total-1);
                        /* Keep track of the highest uid */
                        if (window->highestuid < md->uid)
                            window->highestuid = md->uid;
                    } else {
                        _email_querychanges_destroyed(*expungedids, msgid);
                        _email_querychanges_added(*messageids, msgid, *total-1);
                    }
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
             * for a given conversation.  For jmap_email_query this is fairly simple,
             * just show the first message you find with a given cid, but for
             * jmap_email_querychanges, you need to say "destroyed" for every message
             * which MIGHT have been the previous exemplar, because it will be in the
             * client cache, and you need to say both "destroyed" and "added" for the
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
             * since 1001 we get destroyed: ['D', 'A'], added: ['A'] - because 'D' is now
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
                        _email_querychanges_destroyed(*expungedids, msgid);
                    }
                    else if (ciddata & 4) {
                        /* we need to remove and re-add this record just in case we
                         * got unmasked by the previous */
                        _email_querychanges_destroyed(*expungedids, msgid);
                        _email_querychanges_added(*messageids, msgid, *total-1);
                    }
                    /* nothing later could be the old exemplar */
                    hashu64_insert(md->cid, (void *)3, &cids);
                }
                goto doneloop;
            }

            /* OK, so this message has changed since last time */

            /* we don't know that we weren't the old exemplar, so we always tell a removal */
            _email_querychanges_destroyed(*expungedids, msgid);

            /* not the new exemplar because expunged */
            if (is_expunged) {
                hashu64_insert(md->cid, (void*)(ciddata | 4), &cids);
                goto doneloop;
            }
            /* not the new exemplar because we've already seen that */
            if (ciddata & 1) goto doneloop;

            /* this is the new exemplar, so tell about it */
            _email_querychanges_added(*messageids, msgid, *total-1);

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

        if (one_mailbox_only) {
            /* Keep track of the highest uid */
            if (window->highestuid < md->uid)
                window->highestuid = md->uid;
        }

        /* Check if the message is expunged in all mailboxes */
        r = conversations_guid_foreach(req->cstate, _guid_from_id(msgid),
                                       _email_is_expunged_cb, req);
        switch (r) {
            case IMAP_OK_COMPLETED:
                is_expunged = 0;
                break;
            case 0:
                is_expunged = 1;
                break;
            default:
                goto done;
        }
        r = 0;

        /* Add the message id to the result */
        if (is_expunged && expungedids) {
            json_array_append_new(*expungedids, json_string(msgid));
        } else {
            json_array_append_new(*messageids, json_string(msgid));
        }

        /* Add the thread id */
        if (window->collapse)
            hashu64_insert(md->cid, (void*)1, &cids);
        char *thrid = _thread_id_from_cid(md->cid);
        json_array_append_new(*threadids, json_string(thrid));
        free(thrid);


doneloop:
        if (!foundupto && window->uptomsgid && !strcmp(msgid, window->uptomsgid))
            foundupto = 1;
        if (msg) json_decref(msg);
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

static int _email_parse_comparator(struct jmap_comparator *comp, void *rock __attribute__((unused)))
{
    /* Reject any collation */
    if (comp->collation) {
        return 0;
    }

    /* Special case: hasKeyword */
    if (!strncmp(comp->property, "hasKeyword:", 11)) {
        if (_email_keyword_is_valid(comp->property + 11)) {
            return 1;
        }
    }
    /* Special case: someInThreadHaveKeyword */
    else if (!strncmp(comp->property, "someInThreadHaveKeyword:", 24)) {
        const char *s = comp->property + 24;
        if (_email_keyword_is_valid(s) && _email_threadkeyword_is_valid(s)) {
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

static int jmap_email_query(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;
    int collapse_threads = 0;

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req->args, &parser,
            _email_parse_filter, req,
            _email_parse_comparator, req,
            &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    if (query.position < 0) {
        /* we currently don't support negative positions */
        jmap_parser_invalid(&parser, "position");
    }
    json_t *arg = json_object_get(req->args, "collapseThreads");
    if (json_is_boolean(arg)) {
        collapse_threads = json_boolean_value(arg);
    } else if (arg) {
        jmap_parser_invalid(&parser, "collapseThreads");
    }
    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidArguments");
        json_object_set(err, "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    size_t total_threads = 0;
    json_t *threadids = NULL;
    struct email_search_window window;
    memset(&window, 0, sizeof(struct email_search_window));
    window.position = query.position;
    window.anchor = query.anchor;
    window.anchor_off = query.anchor_offset;
    window.limit = query.limit;
    window.collapse = collapse_threads;
    int r = _email_search(req, query.filter, query.sort, &window, 0,
            &query.total, &total_threads, &query.ids, NULL, &threadids);
    if (!JNOTNULL(query.ids)) query.ids = json_array();
    json_decref(threadids);
    if (r) {
        json_t *err = r == IMAP_NOTFOUND ?
            json_pack("{s:s}", "type", "unsupportedFilter") :
            json_pack("{s:s}", "type", "serverError");
        jmap_error(req, err);
        goto done;
    }
    query.can_calculate_changes = window.cancalcupdates;
    query.position = window.position;

    /* State token is current modseq ':' highestuid - because queryChanges... */
    json_t *jstate = jmap_getstate(req, 0);
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, "%s:%u", json_string_value(jstate), window.highestuid);
    query.state = buf_release(&buf);
    json_decref(jstate);

    /* Build response */
    json_t *res = jmap_query_reply(&query);
    json_object_set(res, "collapseThreads",
            json_object_get(req->args, "collapseThreads"));
    jmap_ok(req, res);

done:
    jmap_query_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static int jmap_email_querychanges(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_querychanges query;
    int collapse_threads = 0;

    /* Parse arguments */
    json_t *err = NULL;
    jmap_querychanges_parse(req->args, &parser,
            _email_parse_filter, req,
            _email_parse_comparator, req,
            &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    json_t *arg = json_object_get(req->args, "collapseThreads");
    if (json_is_boolean(arg)) {
        collapse_threads = json_boolean_value(arg);
    } else if (arg) {
        jmap_parser_invalid(&parser, "collapseThreads");
    }
	if (json_array_size(parser.invalid)) {
		err = json_pack("{s:s}", "type", "invalidArguments");
		json_object_set(err, "arguments", parser.invalid);
		jmap_error(req, err);
        goto done;
	}

    /* XXX Guess, we don't need total_threads anymore */
    size_t total_threads = 0;
    json_t *threadids = NULL;
    /* Set up search window */
    struct email_search_window window;
    memset(&window, 0, sizeof(struct email_search_window));

    /* State token is current modseq ':' highestuid - because queryChanges... */
    int nscan = sscanf(query.since_state, MODSEQ_FMT ":%u",
                       &window.sincemodseq, &window.sinceuid);
    if (nscan != 2) {
        jmap_error(req, json_pack("{s:s}", "type", "cannotCalculateChanges"));
        goto done;
    }
    window.uptomsgid = query.up_to_id;
    window.collapse = collapse_threads;
    int r = _email_search(req, query.filter, query.sort, &window, /*include_expunged*/1,
            &query.total, &total_threads, &query.added, &query.removed, &threadids);
    if (!JNOTNULL(query.added)) query.added = json_array();
    if (!JNOTNULL(query.removed)) query.removed = json_array();
    json_decref(threadids);
    if (r == IMAP_SEARCH_MUTABLE) {
        jmap_error(req, json_pack("{s:s,s:s}", "type", "cannotCalculateChanges",
                    "error", "Search is mutable"));
        goto done;
    }
    else if (r == IMAP_NOTFOUND) {
        jmap_error(req, json_pack("{s:s}", "type", "unsupportedFilter"));
        goto done;
    }
    else if (r) {
        jmap_error(req, json_pack("{s:s}", "type", "serverError"));
        goto done;
    }
    if (query.max_changes) {
        size_t nchanges = json_array_size(query.added) + json_array_size(query.removed);
        if (nchanges > query.max_changes) {
            jmap_error(req, json_pack("{s:s}", "type", "tooManyChanges"));
            goto done;
        }
    }

    /* State token is current modseq ':' highestuid - because queryChanges... */
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT ":%u", window.highestmodseq, window.highestuid);
    query.new_state = buf_release(&buf);

    /* Build response */
    json_t *res = jmap_querychanges_reply(&query);
    json_object_set(res, "collapseThreads",
            json_object_get(req->args, "collapseThreads"));
    jmap_ok(req, res);

done:
    jmap_querychanges_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static int jmap_email_changes(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;
	int collapse_threads = 0;

    /* Parse request */
    json_t *err = NULL;
    jmap_changes_parse(req->args, &parser, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    modseq_t since_modseq = atomodseq_t(changes.since_state);
    if (!since_modseq) {
        jmap_parser_invalid(&parser, "sinceState");
    }
	json_t *arg = json_object_get(req->args, "collapseThreads");
	if (json_is_boolean(arg)) {
		collapse_threads = json_boolean_value(arg);
	} else if (arg) {
		jmap_parser_invalid(&parser, "collapseThreads");
	}
	if (json_array_size(parser.invalid)) {
		err = json_pack("{s:s}", "type", "invalidArguments");
		json_object_set(err, "arguments", parser.invalid);
		jmap_error(req, err);
		goto done;
	}

    /* Search for updates */
    json_t *filter = json_pack("{s:s}", "sinceEmailState", changes.since_state);
    json_t *sort = json_pack("[{s:s}]", "property", "emailState");
    struct email_search_window window;
    memset(&window, 0, sizeof(struct email_search_window));
    window.collapse = collapse_threads;
    window.limit = changes.max_changes;
    size_t total = 0, total_threads = 0;
    json_t *threads = json_array();
    int r = _email_search(req, filter, sort, &window, /*want_expunge*/1,
            &total, &total_threads,
            &changes.changed, &changes.destroyed, &threads);
    json_decref(filter);
    json_decref(sort);
    json_decref(threads);
    if (r) {
        jmap_error(req, json_pack("{s:s}", "type", "serverError"));
        goto done;
    }

    changes.has_more_changes =
        (json_array_size(changes.changed) + json_array_size(changes.destroyed)) < total;
    if (changes.has_more_changes ||
        json_array_size(changes.changed) > 0 ||
        json_array_size(changes.destroyed) > 0) {
        /* Determine new state */
        json_t *val = jmap_fmtstate(window.highestmodseq);
        changes.new_state = xstrdup(json_string_value(val));
        json_decref(val);
    }
    else {
        changes.new_state = xstrdup(changes.since_state);
    }

    jmap_ok(req, jmap_changes_reply(&changes));

done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    return 0;
}

static int jmap_thread_changes(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;
    conversation_t *conv = NULL;
    json_t *threads = json_array();

    /* Parse request */
    json_t *err = NULL;
    jmap_changes_parse(req->args, &parser, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    modseq_t since_modseq = atomodseq_t(changes.since_state);
    if (!since_modseq) {
        jmap_parser_invalid(&parser, "sinceState");
    }

    /* Search for updates */
    json_t *filter = json_pack("{s:s}", "sinceEmailState", changes.since_state);
    json_t *sort = json_pack("[{s:s}]", "property", "emailState");
    struct email_search_window window;
    memset(&window, 0, sizeof(struct email_search_window));
    window.collapse = 1;
    window.limit = changes.max_changes;
    size_t total = 0, total_threads = 0;
    json_t *changed = json_array();
    json_t *destroyed = json_array();
    int r = _email_search(req, filter, sort, &window, /*want_expunge*/1,
            &total, &total_threads, &changed, &destroyed, &threads);
    json_decref(filter);
    json_decref(sort);
    json_decref(changed);
    json_decref(destroyed);
    if (r) {
        jmap_error(req, json_pack("{s:s}", "type", "serverError"));
        goto done;
    }

    /* Split the collapsed threads into changed and destroyed -
     * the values from _email_search are msgids */
    size_t i;
    json_t *val;
    json_array_foreach(threads, i, val) {
        const char *threadid = json_string_value(val);
        conversation_id_t cid = _cid_from_id(threadid);
        if (!cid) continue;

        r = conversation_load(req->cstate, cid, &conv);
        if (!conv) continue;
        if (r == CYRUSDB_NOTFOUND)
            continue;
        else if (r) {
            jmap_error(req, json_pack("{s:s}", "type", "serverError"));
            goto done;
        }

        json_array_append(conv->thread ? changes.changed : changes.destroyed, val);
        conversation_free(conv);
        conv = NULL;
    }

    changes.has_more_changes =
        (json_array_size(changes.changed) + json_array_size(changes.destroyed)) < total_threads;

    if (changes.has_more_changes) {
        json_t *val = jmap_fmtstate(window.highestmodseq);
        changes.new_state = xstrdup(json_string_value(val));
        json_decref(val);
    } else {
        json_t *val = jmap_fmtstate(jmap_highestmodseq(req, 0/*mbtype*/));
        changes.new_state = xstrdup(json_string_value(val));
        json_decref(val);
    }

    jmap_ok(req, jmap_changes_reply(&changes));

done:
    conversation_free(conv);
    json_decref(threads);
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    return 0;
}

static int _snippet_get_cb(struct mailbox *mbox __attribute__((unused)),
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

static int _snippet_get(jmap_req_t *req, json_t *filter, json_t *messageids,
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
    searchargs->root = _email_buildsearch(req, filter, NULL);

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
    rx = search_begin_snippets(intquery, 0, &markup, _snippet_get_cb, snippet);
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

        r = _email_find(req, msgid, &mboxname, &uid);
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

static int _email_filter_contains_text(json_t *filter)
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
            if (_email_filter_contains_text(val)) {
                return 1;
            }
        }
    }
    return 0;
}

static int jmap_searchsnippet_get(jmap_req_t *req)
{
    int r = 0;
    json_t *filter, *messageids, *val, *snippets, *notfound, *res, *item;
    struct buf buf = BUF_INITIALIZER;
    size_t i;
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;

    /* Parse and validate arguments. */
    json_t *unsupported_filter = json_pack("[]");

    /* filter */
    filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        jmap_parser_push(&parser, "filter");
        jmap_filter_parse(filter, &parser, _email_parse_filter, unsupported_filter, req);
        jmap_parser_pop(&parser);
    }

    /* messageIds */
    messageids = json_object_get(req->args, "emailIds");
    if (json_array_size(messageids)) {
        _parse_strings(messageids, &parser, "emailIds");
    }
    else if (!json_is_array(messageids)) {
        jmap_parser_invalid(&parser, "emailIds");
    }

    /* Bail out for argument errors */
    if (json_array_size(parser.invalid)) {
        jmap_error(req, json_pack("{s:s, s:O}", "type", "invalidArguments",
                    "arguments", parser.invalid));
        json_decref(unsupported_filter);
        goto done;
    }

    /* Report unsupported filters */
    if (json_array_size(unsupported_filter)) {
        jmap_error(req, json_pack("{s:s, s:o}", "type", "unsupportedFilter",
                    "filters", unsupported_filter));
        goto done;
    }
    json_decref(unsupported_filter);

    if (json_array_size(messageids) && _email_filter_contains_text(filter)) {
        /* Render snippets */
        r = _snippet_get(req, filter, messageids, &snippets, &notfound);
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
    jmap_parser_fini(&parser);
    buf_free(&buf);
    return r;
}

static int _thread_get(jmap_req_t *req, json_t *ids,
                       json_t *list, json_t *not_found)
{
    conversation_t *conv = NULL;
    json_t *val;
    size_t i;
    int r = 0;

    json_array_foreach(ids, i, val) {
        conversation_id_t cid = 0;
        conv_thread_t *thread;

        const char *threadid = json_string_value(val);
        cid = _cid_from_id(threadid);

        if (cid) r = conversation_load(req->cstate, cid, &conv);
        if (r) goto done;
        if (!conv) {
            json_array_append_new(not_found, json_string(threadid));
            continue;
        }

        json_t *ids = json_pack("[]");
        for (thread = conv->thread; thread; thread = thread->next) {
            char *msgid = _email_id_from_guid(&thread->guid);
            json_array_append_new(ids, json_string(msgid));
            free(msgid);
        }

        json_t *jthread = json_pack("{s:s s:o}", "id", threadid, "emailIds", ids);
        json_array_append_new(list, jthread);

        conversation_free(conv);
        conv = NULL;
    }

    r = 0;

done:
    if (conv) conversation_free(conv);
    return r;
}

static int jmap_thread_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;

    /* Parse request */
    jmap_get_parse(req->args, &parser, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    /* Refuse to fetch *all* Threads */
    if (!JNOTNULL(get.ids)) {
        jmap_error(req, json_pack("{s:s}", "type", "requestTooLarge"));
        goto done;
    }

    /* Find threads */
    int r = _thread_get(req, get.ids, get.list, get.not_found);
    if (r) {
        syslog(LOG_ERR, "jmap: Thread/get: %s", error_message(r));
        jmap_error(req, json_pack("{s:s}", "type", "serverError"));
        goto done;
    }

    json_t *jstate = jmap_getstate(req, 0);
    get.state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

struct email_get_args {
    hash_table *props; /* owned by JMAP get or process stack */
    hash_table *bodyprops;
    ptrarray_t want_headers;     /* array of header_prop */
    ptrarray_t want_bodyheaders; /* array of header_prop */
    short fetch_text_body;
    short fetch_html_body;
    short fetch_all_body;
    size_t max_body_bytes;
};

#define _EMAIL_GET_ARGS_INITIALIZER \
    { NULL, NULL, PTRARRAY_INITIALIZER, PTRARRAY_INITIALIZER, 0, 0, 0, 0 };

/* Initialized in email_get_parse. *Not* thread-safe */
static hash_table _email_get_default_props = HASH_TABLE_INITIALIZER;
static hash_table _email_get_default_bodyprops = HASH_TABLE_INITIALIZER;

static void _email_get_fini(struct email_get_args *args)
{
    if (args->bodyprops && args->bodyprops != &_email_get_default_bodyprops) {
        free_hash_table(args->bodyprops, NULL);
        free(args->bodyprops);
    }
    args->bodyprops = NULL;

    struct header_prop *prop;
    while ((prop = ptrarray_pop(&args->want_headers))) {
        _header_prop_fini(prop);
        free(prop);
    }
    ptrarray_fini(&args->want_headers);
    while ((prop = ptrarray_pop(&args->want_bodyheaders))) {
        _header_prop_fini(prop);
        free(prop);
    }
    ptrarray_fini(&args->want_bodyheaders);
}


static void _email_parse_wantheaders(json_t *jprops,
                                     struct jmap_parser *parser,
                                     const char *prop_name,
                                     ptrarray_t *want_headers)
{
    size_t i;
    json_t *jval;
    json_array_foreach(jprops, i, jval) {
        const char *s = json_string_value(jval);
        if (!s || strncmp(s, "header:", 7))
            continue;
        struct header_prop *hprop;
        if ((hprop = _header_parseprop(s))) {
            ptrarray_append(want_headers, hprop);
        }
        else {
            jmap_parser_push_index(parser, prop_name, i);
            jmap_parser_invalid(parser, NULL);
            jmap_parser_pop(parser);
        }
    }
}

static void _email_get_parse(json_t *req_args,
                           struct jmap_parser *parser,
                           struct email_get_args *args,
                           hash_table *props,
                           json_t **err)
{
    size_t i;
    json_t *val;

    /* properties - already parsed in jmap_get_parse */
    args->props = props;
    /* set default props, if not set by client */
    if (props == NULL) {
        if (_email_get_default_props.size == 0) {
            /* Initialize process-owned default property list */
            construct_hash_table(&_email_get_default_props, 32, 0);
            hash_insert("attachedEmails", (void*)1, &_email_get_default_props);
            hash_insert("attachedFiles", (void*)1, &_email_get_default_props);
            hash_insert("bcc", (void*)1, &_email_get_default_props);
            hash_insert("blobId", (void*)1, &_email_get_default_props);
            hash_insert("bodyValues", (void*)1, &_email_get_default_props);
            hash_insert("cc", (void*)1, &_email_get_default_props);
            hash_insert("from", (void*)1, &_email_get_default_props);
            hash_insert("hasAttachment", (void*)1, &_email_get_default_props);
            hash_insert("htmlBody", (void*)1, &_email_get_default_props);
            hash_insert("id", (void*)1, &_email_get_default_props);
            hash_insert("inReplyTo", (void*)1, &_email_get_default_props);
            hash_insert("keywords", (void*)1, &_email_get_default_props);
            hash_insert("mailboxIds", (void*)1, &_email_get_default_props);
            hash_insert("messageId", (void*)1, &_email_get_default_props);
            hash_insert("preview", (void*)1, &_email_get_default_props);
            hash_insert("receivedAt", (void*)1, &_email_get_default_props);
            hash_insert("references", (void*)1, &_email_get_default_props);
            hash_insert("replyTo", (void*)1, &_email_get_default_props);
            hash_insert("sender", (void*)1, &_email_get_default_props);
            hash_insert("sentAt", (void*)1, &_email_get_default_props);
            hash_insert("size", (void*)1, &_email_get_default_props);
            hash_insert("subject", (void*)1, &_email_get_default_props);
            hash_insert("textBody", (void*)1, &_email_get_default_props);
            hash_insert("threadId", (void*)1, &_email_get_default_props);
            hash_insert("to", (void*)1, &_email_get_default_props);
        }
        args->props = &_email_get_default_props;
    }

    /* bodyProperties */
    json_t *arg = json_object_get(req_args, "bodyProperties");
    if (JNOTNULL(arg)) {
        if (_parse_strings(arg, parser, "bodyProperties")) {
            args->bodyprops = xzmalloc(sizeof(hash_table));
            construct_hash_table(args->bodyprops, json_array_size(arg) + 1, 0);
            json_array_foreach(arg, i, val) {
                hash_insert(json_string_value(val), (void*)1, args->bodyprops);
            }
        }
        /* header:Xxx properties */
        _email_parse_wantheaders(arg, parser, "bodyProperties",
                                 &args->want_bodyheaders);
    }
    else {
        /* Set default body properties, if not set by client */
        if (_email_get_default_bodyprops.size == 0) {
            /* Initialize process-owned default body property list */
            construct_hash_table(&_email_get_default_bodyprops, 32, 0);
            hash_insert("blobId", (void*)1, &_email_get_default_bodyprops);
            hash_insert("charset", (void*)1, &_email_get_default_bodyprops);
            hash_insert("cid", (void*)1, &_email_get_default_bodyprops);
            hash_insert("disposition", (void*)1, &_email_get_default_bodyprops);
            hash_insert("language", (void*)1, &_email_get_default_bodyprops);
            hash_insert("location", (void*)1, &_email_get_default_bodyprops);
            hash_insert("name", (void*)1, &_email_get_default_bodyprops);
            hash_insert("partId", (void*)1, &_email_get_default_bodyprops);
            hash_insert("size", (void*)1, &_email_get_default_bodyprops);
            hash_insert("type", (void*)1, &_email_get_default_bodyprops);
        }
        args->bodyprops = &_email_get_default_bodyprops;
    }

    /* fetchTextBodyValues */
    arg = json_object_get(req_args, "fetchTextBodyValues");
    if (json_is_boolean(arg)) {
        args->fetch_text_body = json_boolean_value(arg);
    }
    else if (arg) {
        jmap_parser_invalid(parser, "fetchTextBodyValues");
    }
    /* fetchHTMLBodyValues */
    arg = json_object_get(req_args, "fetchHTMLBodyValues");
    if (json_is_boolean(arg)) {
        args->fetch_html_body = json_boolean_value(arg);
    }
    else if (arg) {
        jmap_parser_invalid(parser, "fetchHTMLBodyValues");
    }
    /* fetchAllBodyValues */
    arg = json_object_get(req_args, "fetchAllBodyValues");
    if (json_is_boolean(arg)) {
        args->fetch_all_body = json_boolean_value(arg);
    }
    else if (arg) {
        jmap_parser_invalid(parser, "fetchAllBodyValues");
    }
    /* maxBodyValueBytes */
    arg = json_object_get(req_args, "maxBodyValueBytes");
    if (json_is_integer(arg) && json_integer_value(arg) > 0) {
        args->max_body_bytes = json_integer_value(arg);
    }
    else if (arg) {
        jmap_parser_invalid(parser, "maxBodyValueBytes");
    }
    /* header:Xxx properties */
    json_t *jprops = json_object_get(req_args, "properties");
    if (JNOTNULL(jprops)) {
        _email_parse_wantheaders(jprops, parser, "properties",
                                 &args->want_headers);
    }
    /* Complete parse */
    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s}", "type", "invalidArguments");
        json_object_set(*err, "arguments", parser->invalid);
    }
}

static int _email_get_meta(jmap_req_t *req,
                           struct email_get_args *args,
                           struct body *body __attribute__((unused)),
                           struct buf *msg_buf __attribute__((unused)),
                           msgrecord_t *mr,
                           json_t *msg)
{
    int r = 0;
    hash_table *props = args->props;
    char *msgid = NULL;

    /* Determine message id */
    struct message_guid guid;
    r = msgrecord_get_guid(mr, &guid);
    if (r) goto done;
    msgid = _email_id_from_guid(&guid);

    /* id */
    json_object_set_new(msg, "id", json_string(msgid));

    /* blobId */
    if (_wantprop(props, "blobId")) {
        char *blobid = jmap_blobid(&guid);
        json_object_set_new(msg, "blobId", json_string(blobid));
        free(blobid);
    }

    /* threadid */
    if (_wantprop(props, "threadId")) {
        bit64 cid;
        r = msgrecord_get_cid(mr, &cid);
        if (r) goto done;
        char *threadid = _thread_id_from_cid(cid);
        json_object_set_new(msg, "threadId", json_string(threadid));
        free(threadid);
    }

    /* mailboxIds */
    if (_wantprop(props, "mailboxIds")) {
        json_t *mboxids = json_object();
        json_t *mailboxes = _email_get_mailboxes(req, msgid);

        json_t *val;
        const char *mboxid;
        json_object_foreach(mailboxes, mboxid, val) {
            json_object_set_new(mboxids, mboxid, json_true());
        }
        json_decref(mailboxes);
        json_object_set_new(msg, "mailboxIds", mboxids);
    }

    /* keywords */
    if (_wantprop(props, "keywords")) {
        json_t *keywords = NULL;
        r = _email_get_keywords(req, msgid, &keywords);
        if (r) goto done;
        json_object_set_new(msg, "keywords", keywords);
    }

    /* size */
    if (_wantprop(props, "size")) {
        uint32_t size;
        r = msgrecord_get_size(mr, &size);
        if (r) goto done;
        json_object_set_new(msg, "size", json_integer(size));
    }

    /* receivedAt */
    if (_wantprop(props, "receivedAt")) {
        char datestr[RFC3339_DATETIME_MAX];
        time_t t;

        r = msgrecord_get_internaldate(mr, &t);
        if (r) return r;
        time_to_rfc3339(t, datestr, RFC3339_DATETIME_MAX);
        json_object_set_new(msg, "receivedAt", json_string(datestr));
    }

done:
    free(msgid);
    return r;
}

static void _email_get_headerprops(json_t *jdst,
                                   struct headers *headers,
                                   ptrarray_t *want_headers)
{
    int i;
    for (i = 0; i < want_headers->count; i++) {
        struct header_prop *want_header = ptrarray_nth(want_headers, i);

        /* Lookup array of EmailHeader objects by name */
        json_t *jheaders = json_object_get(headers->all, want_header->lcasename);
        if (!jheaders) {
            json_object_set_new(jdst, want_header->prop,
                    want_header->all ? json_array() : json_null());
            continue;
        }

        /* Determine header form converter */
        json_t* (*cb)(const char *raw);
        switch (want_header->form) {
            case HEADER_FORM_TEXT:
                cb = _header_as_text;
                break;
            case HEADER_FORM_ADDRESSES:
                cb = _header_as_addresses;
                break;
            case HEADER_FORM_MESSAGEIDS:
                cb = _header_as_messageids;
                break;
            case HEADER_FORM_URLS:
                cb = _header_as_urls;
                break;
            default:
                cb = _header_as_raw;
        }

        /* Convert header values */
        json_t *allvals = json_array();
        size_t i = want_header->all ? 0 : json_array_size(jheaders) - 1;
        for (i = 0; i < json_array_size(jheaders); i++) {
            json_t *jheader = json_array_get(jheaders, i);
            json_t *jval = json_object_get(jheader, "value");
            json_array_append_new(allvals, cb(json_string_value(jval)));
        }
        json_object_set(jdst, want_header->prop,
                want_header->all ?  allvals : json_array_get(allvals, i - 1));
        json_decref(allvals);
    }
}

static int _email_get_headers(jmap_req_t *req __attribute__((unused)),
                              struct email_get_args *args,
                              struct body *body,
                              struct buf *msg_buf,
                              msgrecord_t *mr __attribute__((unused)),
                              json_t *msg)
{
    int r = 0;
    hash_table *props = args->props;

    // TODO support embedded messages for Email/parse

    /* Always fetch headers: the struct body type might contain
     * cached fields such as reply_to, sender, et al that are
     * not set in the original message, but the JMAP spec
     * requires us to return NULL if the header is not set. */
    /* TODO brong -> shall we deal with this in message.c? 
     * -> some headers are in the cache, use message_get_field 
     * -> for replyto and sender at the moment ignore spec */
    struct headers headers = HEADERS_INITIALIZER;
    _headers_from_mime(msg_buf->s + body->header_offset, body->header_size, &headers);

    /* headers */
    if (_wantprop(props, "headers")) {
        json_object_set(msg, "headers", headers.raw); /* incref! */
    }
    /* headers:Xxx */
    if (args->want_headers.count) {
        _email_get_headerprops(msg, &headers, &args->want_headers);
    }
    /* messageId */
    if (_wantprop(props, "messageId")) {
        json_object_set_new(msg, "messageId",
                _header_as_messageids(body->message_id));
    }
    /* inReplyTo */
    if (_wantprop(props, "inReplyTo")) {
        json_object_set_new(msg, "inReplyTo",
                _header_as_messageids(body->in_reply_to));
    }
    /* references */
    if (_wantprop(props, "references")) {
        json_object_set_new(msg, "references",
                _header_as_messageids(body->references));
    }
    /* from */
    if (_wantprop(props, "from")) {
        json_object_set_new(msg, "from",
                _emailaddresses_from_addr(body->from));
    }
    /* sender */
    if (_wantprop(props, "sender")) {
        json_object_set_new(msg, "sender",
                json_object_get(headers.all, "sender") ?
                _emailaddresses_from_addr(body->sender) : json_null());
    }
    /* replyTo */
    if (_wantprop(props, "replyTo")) {
        json_object_set_new(msg, "replyTo",
                json_object_get(headers.all, "reply-to") ?
                _emailaddresses_from_addr(body->reply_to) : json_null());
    }
    /* to */
    if (_wantprop(props, "to")) {
        json_object_set_new(msg, "to",
                _emailaddresses_from_addr(body->to));
    }
    /* cc */
    if (_wantprop(props, "cc")) {
        json_object_set_new(msg, "cc",
                _emailaddresses_from_addr(body->cc));
    }
    /* bcc */
    if (_wantprop(props, "bcc")) {
        json_object_set_new(msg, "bcc",
                _emailaddresses_from_addr(body->bcc));
    }
    /* subject */
    if (_wantprop(props, "subject")) {
        json_object_set_new(msg, "subject",
                _header_as_text(body->subject));
    }
    /* sentAt */
    if (_wantprop(props, "sentAt")) {
        json_t *jsent_at = json_null();
        time_t t;
        if (time_from_rfc822(body->date, &t) != -1) {
            char datestr[RFC3339_DATETIME_MAX];
            time_to_rfc3339(t, datestr, RFC3339_DATETIME_MAX);
            jsent_at = json_string(datestr);
        }
        json_object_set_new(msg, "sentAt", jsent_at);
    }

    _headers_fini(&headers);
    return r;
}

static json_t *_email_get_bodypart(struct body *part,
                                  struct email_get_args *args,
                                  struct buf *msg_buf)
{
    struct buf buf = BUF_INITIALIZER;
    struct param *param;

    hash_table *bodyprops = args->bodyprops;
    ptrarray_t *want_bodyheaders = &args->want_bodyheaders;

    json_t *jbodypart = json_object();

    /* partId */
    if (_wantprop(bodyprops, "partId")) {
        json_t *jpart_id = json_null();
        if (!strcasecmp(part->type, "TEXT"))
            jpart_id = json_string(part->part_id);
        json_object_set_new(jbodypart, "partId", jpart_id);
    }

    /* blobId */
    if (_wantprop(bodyprops, "blobId")) {
        json_t *jblob_id = json_null();
        if (!message_guid_isnull(&part->content_guid)) {
            char *tmp = jmap_blobid(&part->content_guid);
            jblob_id = json_string(tmp);
            free(tmp);
        }
        json_object_set_new(jbodypart, "blobId", jblob_id);
    }

    /* size */
    if (_wantprop(bodyprops, "size")) {
        size_t size;
        if (part->numparts) {
            /* Multi-part */
            size = part->content_size;
        }
        else if (part->charset_enc) {
            buf_reset(&buf);
            charset_decode(&buf, msg_buf->s + part->content_offset,
                    part->content_size, part->charset_enc);
            size = buf_len(&buf);
            buf_reset(&buf);
        }
        else {
            size = part->content_size;
        }
        json_object_set_new(jbodypart, "size", json_integer(size));
    }

    /* headers */
    if (_wantprop(bodyprops, "headers") || want_bodyheaders->count) {
        struct headers headers = HEADERS_INITIALIZER;
        _headers_from_mime(msg_buf->s + part->header_offset, part->header_size,
                           &headers);
        if (_wantprop(bodyprops, "headers")) {
            json_object_set(jbodypart, "headers", headers.raw);
        }
        if (want_bodyheaders->count) {
            _email_get_headerprops(jbodypart, &headers, want_bodyheaders);
        }
        _headers_fini(&headers);
    }

    /* name */
    if (_wantprop(bodyprops, "name")) {
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
            json_object_set_new(jbodypart, "name",
                    s ? json_string(s) : json_null());
            free(s);
        }
        else if (fname) {
            int mime_flags = charset_flags & CHARSET_MIME_UTF8;
            char *s = charset_parse_mimeheader(fname, mime_flags);
            json_object_set_new(jbodypart, "name",
                    s ? json_string(s) : json_null());
            free(s);
        }
        else {
            json_object_set_new(jbodypart, "name", json_null());
        }
    }

    /* type */
    if (_wantprop(bodyprops, "type")) {
        buf_setcstr(&buf, part->type);
        if (part->subtype) {
            buf_appendcstr(&buf, "/");
            buf_appendcstr(&buf, part->subtype);
        }
        json_object_set_new(jbodypart, "type", json_string(buf_lcase(&buf)));
    }

    /* charset */
    if (_wantprop(bodyprops, "charset")) {
        json_object_set_new(jbodypart, "charset", part->charset_id ?
                json_string(part->charset_id) : json_null());
    }

    /* disposition */
    if (_wantprop(bodyprops, "disposition")) {
        json_t *jdisp = json_null();
        if (part->disposition) {
            char *disp = lcase(xstrdup(part->disposition));
            jdisp = json_string(disp);
            free(disp);
        }
        json_object_set_new(jbodypart, "disposition", jdisp);
    }

    /* cid */
    if (_wantprop(bodyprops, "cid")) {
        /* Extract header */
        /* TODO this should be message_get_field */
        strarray_t headers = STRARRAY_INITIALIZER;
        strarray_add(&headers, "Content-ID");
        char *s = xstrndup(msg_buf->s + part->header_offset, part->header_size);
        message_pruneheader(s, &headers, NULL);

        /* Parse id */
        json_t *jcid = json_null();
        const char *cid = NULL;
        if ((cid = strchr(s, ':'))) {
            char *unfolded;
            if ((unfolded = charset_unfold(cid + 1, strlen(cid), 0))) {
                json_t *jheaders = _header_as_messageids(cid + 1);
                if (json_array_size(jheaders))
                    jcid = json_incref(json_array_get(jheaders, 0));
                json_decref(jheaders);
                free(unfolded);
            }
        }
        /* Set field */
        json_object_set_new(jbodypart, "cid", jcid);
        free(s);
        strarray_fini(&headers);
    }

    /* language */
    if (_wantprop(bodyprops, "language")) {
        /* Extract header */
        strarray_t headers = STRARRAY_INITIALIZER;
        strarray_add(&headers, "Content-Language");
        char *s = xstrndup(msg_buf->s + part->header_offset, part->header_size);
        message_pruneheader(s, &headers, NULL);
        /* Split by space and comma and aggregate into array */
        json_t *language = json_array();
        const char *p = strchr(s, ':');
        if (p) {
            int i;
            char *tmp = charset_unfold(p+1, strlen(p+1) - 1, 0);
            strarray_t *ls = strarray_split(tmp, "\t ,", STRARRAY_TRIM);
            for (i = 0; i < ls->count; i++) {
                json_array_append_new(language, json_string(strarray_nth(ls, i)));
            }
            strarray_free(ls);
            free(tmp);

            /* Set field */
            if (!json_array_size(language)) {
                json_decref(language);
                language = json_null();
            }
        }
        json_object_set_new(jbodypart, "language", language);
        free(s);
        strarray_fini(&headers);
    }

    /* location */
    if (_wantprop(bodyprops, "location")) {
        json_object_set_new(jbodypart, "location", part->location ?
                json_string(part->location) : json_null());
    }

    /* subParts */
    if (!strcmp(part->type, "MULTIPART")) {
        json_t *subparts = json_array();
        int i;
        for (i = 0; i < part->numparts; i++) {
            struct body *subpart = part->subpart + i;
            json_array_append_new(subparts,
                    _email_get_bodypart(subpart, args, msg_buf));

        }
        json_object_set_new(jbodypart, "subParts", subparts);
    }
    else if (_wantprop(bodyprops, "subParts")) {
        json_object_set_new(jbodypart, "subParts", json_array());
    }

    buf_free(&buf);
    return jbodypart;
}

struct _email_get_bodyvalue_rock {
    struct buf buf;
    size_t max_body_bytes;
    int is_truncated;
};

void _email_get_bodyvalue_cb(const struct buf *text, void *_rock)
{
    struct _email_get_bodyvalue_rock *rock = _rock;

    /* Skip remaining text bodies */
    if (rock->is_truncated) return;

    const char *p = buf_base(text);
    const char *top = p + buf_len(text);

    while (p < top) {
        const char *cr = memchr(p, '\r', top - p);
        if (cr) {
            /* Write bytes up to CR, but skip CR */
            buf_appendmap(&rock->buf, p, cr - p);
            p = cr + 1;
        }
        else {
            /* Write remaining bytes */
            buf_appendmap(&rock->buf, p, top - p);
            p = top;
        }
    }

    /* Truncate bytes */
    if (rock->max_body_bytes && buf_len(&rock->buf) > rock->max_body_bytes) {
        buf_truncate(&rock->buf, rock->max_body_bytes);
        rock->is_truncated = 1;
    }
}

static json_t * _email_get_bodyvalue(struct body *part,
                                     struct buf *msg_buf,
                                     size_t max_body_bytes,
                                     int is_html)
{
    /* Determine the start byte of this part's body */
    struct buf data = BUF_INITIALIZER;
    buf_init_ro(&data, msg_buf->s + part->content_offset, part->content_size);

    /* Extract up to max_body_bytes */
    struct _email_get_bodyvalue_rock rock = {
        BUF_INITIALIZER, max_body_bytes, /*is_truncated*/0
    };
    charset_t cs = charset_lookupname(part->charset_id);
    int flags = CHARSET_SNIPPET|CHARSET_KEEPHTML;
    int is_problem = !charset_extract(_email_get_bodyvalue_cb,
            &rock, &data, cs, part->charset_enc, part->subtype, flags);
    charset_free(&cs);
    buf_cstring(&rock.buf);

    /* Truncate UTF-8 (assuming sane UTF-8 to start from). */
    /* XXX do not split between combining characters */
    struct buf *txt = &rock.buf;
    if (buf_len(txt) && max_body_bytes) {
        const unsigned char *base = (unsigned char *) buf_base(txt);
        const unsigned char *top = base + buf_len(txt);
        const unsigned char *p = top - 1;
        while (p >= base && ((*p & 0xc0) == 0x80))
            p--;
        if (p >= base) {
            ssize_t have_bytes = top - p;
            ssize_t need_bytes = 0;
            unsigned char hi_nibble = *p & 0xf0;
            switch (hi_nibble) {
                case 0xf0:
                    need_bytes = 4;
                    break;
                case 0xe0:
                    need_bytes = 3;
                    break;
                case 0xc0:
                    need_bytes = 2;
                    break;
                default:
                    need_bytes = 1;
            }
            if (have_bytes < need_bytes)
                buf_truncate(txt, p - base);
        }
        else {
            buf_reset(txt);
        }
    }

    /* Truncate HTML */
    if (buf_len(txt) && max_body_bytes && is_html) {
        /* Truncate any trailing '<' start tag character without closing '>' */
        const char *base = buf_base(txt);
        const char *top  = base + buf_len(txt);
        const char *p;
        for (p = top - 1; *p != '>' && p >= base; p--) {
            if (*p == '<') {
                buf_truncate(txt, p - base + 1);
                break;
            }
        }
    }

    /* Build value */
    json_t *bodyvalue = json_object();
    json_object_set_new(bodyvalue, "value",
            json_string(buf_cstring(txt)));
    json_object_set_new(bodyvalue, "isEncodingProblem",
            json_boolean(is_problem));
    json_object_set_new(bodyvalue, "isTruncated",
            json_boolean(rock.is_truncated));

    buf_free(&rock.buf);
    return bodyvalue;
}


static int _email_get_bodies(jmap_req_t *req,
                             struct email_get_args *args,
                             struct body *msg_body,
                             struct buf *msg_buf,
                             msgrecord_t *mr,
                             json_t *msg)
{
    struct emailbodies bodies = EMAILBODIES_INITIALIZER;
    hash_table *props = args->props;
    int r = 0;

    // TODO sunset RENDER_MULTIPART in lib/imapoptions

    /* Dissect message into its parts */
    r = _email_extract_bodies(msg_body, msg_buf, &bodies);
    if (r) goto done;

    /* bodyStructure */
    if (_wantprop(props, "bodyStructure")) {
        json_object_set_new(msg, "bodyStructure",
                _email_get_bodypart(msg_body, args, msg_buf));
    }

    /* bodyValues */
    if (_wantprop(props, "bodyValues")) {
        json_t *body_values = json_object();

        /* Determine which body valuex to fetch */
        int i;
        ptrarray_t parts = PTRARRAY_INITIALIZER;
        if (args->fetch_text_body || args->fetch_all_body) {
            for (i = 0; i < bodies.textlist.count; i++)
                ptrarray_append(&parts, ptrarray_nth(&bodies.textlist, i));
        }
        if (args->fetch_html_body || args->fetch_all_body) {
            for (i = 0; i < bodies.htmllist.count; i++)
                ptrarray_append(&parts, ptrarray_nth(&bodies.htmllist, i));
        }

        /* Fetch body values */
        for (i = 0; i < parts.count; i++) {
            struct body *part = ptrarray_nth(&parts, i);
            if (strcmp("TEXT", part->type))
                continue;
            if (json_object_get(body_values, part->part_id))
                continue;
            json_object_set_new(body_values, part->part_id,
                    _email_get_bodyvalue(part, msg_buf, args->max_body_bytes,
                                         !strcmp("HTML", part->subtype)));
        }
        ptrarray_fini(&parts);

        json_object_set_new(msg, "bodyValues", body_values);
    }

    /* textBody */
    if (_wantprop(props, "textBody")) {
        json_t *text_body = json_array();
        int i;
        for (i = 0; i < bodies.textlist.count; i++) {
            struct body *part = ptrarray_nth(&bodies.textlist, i);
            json_array_append_new(text_body,
                    _email_get_bodypart(part, args, msg_buf));
        }
        json_object_set_new(msg, "textBody", text_body);
    }

    /* htmlBody */
    if (_wantprop(props, "htmlBody")) {
        json_t *html_body = json_array();
        int i;
        for (i = 0; i < bodies.htmllist.count; i++) {
            struct body *part = ptrarray_nth(&bodies.htmllist, i);
            json_array_append_new(html_body,
                    _email_get_bodypart(part, args, msg_buf));
        }
        json_object_set_new(msg, "htmlBody", html_body);
    }

    /* attachedEmails */
    if (_wantprop(props, "attachedEmails")) {
        json_t *attached_emails = json_array();
        int i;
        for (i = 0; i < bodies.msgs.count; i++) {
            struct body *part = ptrarray_nth(&bodies.msgs, i);
            json_array_append_new(attached_emails,
                    _email_get_bodypart(part, args, msg_buf));
        }
        json_object_set_new(msg, "attachedEmails", attached_emails);
    }

    /* attachedFiles */
    if (_wantprop(props, "attachedFiles")) {
        json_t *attached_files = json_array();
        int i;
        for (i = 0; i < bodies.atts.count; i++) {
            struct body *part = ptrarray_nth(&bodies.atts, i);
            json_array_append_new(attached_files,
                    _email_get_bodypart(part, args, msg_buf));
        }
        json_object_set_new(msg, "attachedFiles", attached_files);
    }

    /* hasAttachment */
    if (_wantprop(props, "hasAttachment")) {
        int b = 0;
        // TODO support embedded message for Email/parse
        msgrecord_hasflag(mr, JMAP_HAS_ATTACHMENT_FLAG, &b);
        json_object_set_new(msg, "hasAttachment", json_boolean(b));
    }

    /* preview */
    if (_wantprop(props, "preview")) {
        const char *preview_annot = config_getstring(IMAPOPT_JMAP_PREVIEW_ANNOT);
        if (preview_annot) {
            json_t *preview = _email_get_annot(req, mr, preview_annot, /*structured*/0);
            json_object_set_new(msg, "preview", preview ? preview : json_string(""));
        }
        else {
            /* TODO optimise for up to PREVIEW_LEN bytes */
            char *text = _emailbodies_to_plain(&bodies, msg_buf);
            if (!text) {
                char *html = _emailbodies_to_html(&bodies, msg_buf);
                text = _html_to_plain(html);
                free(html);
            }
            size_t len = config_getint(IMAPOPT_JMAP_PREVIEW_LENGTH);
            char *preview = _email_extract_preview(text, len);
            json_object_set_new(msg, "preview", json_string(preview));
            free(preview);
            free(text);
        }
    }

done:
    _emailbodies_fini(&bodies);
    return r;
}

static int _email_get(jmap_req_t *req,
                      struct email_get_args *args,
                      struct body *body,
                      struct buf *msg_buf,
                      msgrecord_t *mr,
                      json_t **msgptr)
{
    json_t *msg = json_object();
    int r = 0;

    r = _email_get_meta(req, args, body, msg_buf, mr, msg);
    if (r) goto done;
    r = _email_get_headers(req, args, body, msg_buf, mr, msg);
    if (r) goto done;
    r = _email_get_bodies(req, args, body, msg_buf, mr, msg);
    if (r) goto done;

    *msgptr = msg;
done:

    if (r) json_decref(msg);
    return r;
}

static int _email_get_record(jmap_req_t *req,
                              struct email_get_args *args,
                              msgrecord_t *mr,
                              json_t **msgp)
{
    struct body *body = NULL;
    struct buf msg_buf = BUF_INITIALIZER;
    int r;

    r = msgrecord_get_body(mr, &msg_buf);
    if (r) return r;
    r = msgrecord_get_bodystructure(mr, &body);
    if (r) return r;
    r = _email_get(req, args, body, &msg_buf, mr, msgp);

    message_free_body(body);
    free(body);
    buf_free(&msg_buf);
    return r;
}

static int _email_get_with_props(jmap_req_t *req,
                                 hash_table *props,
                                 msgrecord_t *mr,
                                 json_t **msgp)
{
    struct email_get_args args = _EMAIL_GET_ARGS_INITIALIZER;
    args.props = props;
    int r = _email_get_record(req, &args, mr, msgp);
    args.props = NULL;
    _email_get_fini(&args);
    return r;
}

static int jmap_email_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
	struct email_get_args args = _EMAIL_GET_ARGS_INITIALIZER;
    json_t *err = NULL;

    /* Parse request */
    jmap_get_parse(req->args, &parser, &req->idmap->messages, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
	_email_get_parse(req->args, &parser, &args, get.props, &err);
	if (err) {
		jmap_error(req, err);
		goto done;
	}

    /* Refuse to fetch *all* Email */
    if (!JNOTNULL(get.ids)) {
        jmap_error(req, json_pack("{s:s}", "type", "requestTooLarge"));
        goto done;
    }

    size_t i;
    json_t *val;
    json_array_foreach(get.ids, i, val) {
        const char *id = json_string_value(val);
        char *mboxname = NULL;
        msgrecord_t *mr = NULL;
        json_t *msg = NULL;
        struct mailbox *mbox = NULL;

        uint32_t uid;
        int r = _email_find(req, id, &mboxname, &uid);
        if (!r) {
            r = jmap_openmbox(req, mboxname, &mbox, 0);
            if (!r) {
                r = msgrecord_find(mbox, uid, &mr);
                if (!r) {
                    r = _email_get_record(req, &args, mr, &msg);
                }
                jmap_closembox(req, &mbox);
            }
        }
        if (!r && msg) {
            json_array_append_new(get.list, msg);
        }
        else {
            json_array_append_new(get.not_found, json_string(id));
        }
        if (r) {
            syslog(LOG_ERR, "jmap: Email/get(%s): %s", id, error_message(r));
        }

        free(mboxname);
        msgrecord_unref(&mr);
    }

    json_t *jstate = jmap_getstate(req, 0);
    get.state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    jmap_ok(req, jmap_get_reply(&get));

done:
	_email_get_fini(&args);
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

static char *_mime_make_boundary()
{
    char *boundary, *p, *q;

    boundary = xstrdup(makeuuid());
    for (p = boundary, q = boundary; *p; p++) {
        if (*p != '-') *q++ = *p;
    }
    *q = 0;

    return boundary;
}

/* A soft limit for MIME header lengths when generating MIME from JMAP.
 * See the header_from_Xxx functions for usage. */
#define MIME_MAX_HEADER_LENGTH 78

__attribute__((unused)) // FIXME
static int _mime_write_param(FILE *out, const char *name, const char *value,
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

static int _email_copy(jmap_req_t *req, struct mailbox *src,
                     struct mailbox *dst,
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

static int _email_expunge(jmap_req_t *req, struct mailbox *mbox, uint32_t uid)
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

struct _email_expunge_rock {
    jmap_req_t *req;
    int deleted;
    json_t *mailboxes;
};

static int _email_expunge_cb(const conv_guidrec_t *rec, void *rock)
{
    struct _email_expunge_rock *d = (struct _email_expunge_rock *) rock;
    jmap_req_t *req = d->req;
    struct mailbox *mbox = NULL;
    int r = 0;

    r = jmap_openmbox(req, rec->mboxname, &mbox, 1);
    if (r) goto done;

    if (!d->mailboxes || json_object_get(d->mailboxes, mbox->uniqueid)) {
        r = _email_expunge(d->req, mbox, rec->uid);
        if (!r) d->deleted++;
    }

done:
    if (mbox) jmap_closembox(req, &mbox);
    return r;
}

static int _email_append(jmap_req_t *req,
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
    size_t len;
    int r = HTTP_SERVER_ERROR;

    if (!internaldate) internaldate = time(NULL);

    /* Pick the mailbox to create the message in, prefer Drafts */
    mailboxes = json_pack("{}"); /* maps mailbox ids to mboxnames */
    json_object_foreach(mailboxids, id, val) {
        if (id && *id == '#') {
            id = hash_lookup(id + 1, &req->idmap->mailboxes);
        }
        if (!id) continue;

        char *name = _mbox_find_uniqueid(req, id);
        if (!name) continue;

        mbname_t *mbname = mbname_from_intname(name);
        char *role = _mbox_get_role(req, mbname);
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
        syslog(LOG_ERR, "_email_append: invalid mailboxids: %s", s);
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
        *msgid = _email_id_from_guid(&guid);
        munmap(addr, len);
    } else {
        r = IMAP_IOERROR;
        goto done;
    }
    fclose(f);
    f = NULL;

    /*  Check if a message with this GUID already exists and is
     *  visible for the authenticated user. */
    char *exist_mboxname = NULL;
    uint32_t exist_uid;
    r = _email_find(req, *msgid, &exist_mboxname, &exist_uid);
    free(exist_mboxname);
    if (r != IMAP_NOTFOUND) {
        if (!r) r = IMAP_MAILBOX_EXISTS;
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
         * the hasAttachment filter property in jmap_email_query */
        int userflag;
        r = mailbox_user_flag(mbox, JMAP_HAS_ATTACHMENT_FLAG, &userflag, 1);
        if (r) goto done;
        user_flags[userflag/32] |= 1<<(userflag&31);
    }

    for (j = 0; j < keywords->count; j++) {
        const char *flag = strarray_nth(keywords, j);
        if (!strcasecmp(flag, "$Flagged")) {
            system_flags |= FLAG_FLAGGED;
        }
        else if (!strcasecmp(flag, "$Answered")) {
            system_flags |= FLAG_ANSWERED;
        }
        else if (!strcasecmp(flag, "$Seen")) {
            system_flags |= FLAG_SEEN;
        }
        else if (!strcasecmp(flag, "$Draft")) {
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

        r = _email_copy(req, mbox, dst, mr);

        jmap_closembox(req, &dst);
        if (r) goto done;
    }

done:
    if (f) fclose(f);
    append_removestage(stage);
    msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);
    free(mboxname);
    json_decref(mailboxes);
    return r;
}

struct _email_set_answered_rock {
    jmap_req_t* req;
    const char *inreplyto;
    int found;
};

static int _email_set_answered_cb(const conv_guidrec_t *rec, void *rock)
{
    struct _email_set_answered_rock *data = rock;
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

static int _email_set_answered(jmap_req_t *req, const char *inreplyto)
{
    int r = 0, i;
    arrayu64_t cids = ARRAYU64_INITIALIZER;
    conversation_t *conv = NULL;
    char *guid = NULL;
    struct _email_set_answered_rock rock = { req, inreplyto, 0 /*found*/ };

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
            r = conversations_guid_foreach(req->cstate, guid, _email_set_answered_cb, &rock);
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

struct emailpart {
    /* Mandatory fields */
    struct headers headers;       /* raw headers */
    /* Optional fields */
    json_t *jpart;                /* original EmailBodyPart JSON object */
    json_t *jbody;                /* EmailBodyValue for text bodies */
    char *blob_id;                /* blobId to dump contents from */
    ptrarray_t subparts;          /* array of emailpart pointers */
    int is_attachment;            /* neither text nor inline */
    char *type;                   /* Content-Type main type */
    char *subtype;                /* Content-Type subtype */
    char *charset;                /* Content-Type charset parameter */
    char *boundary;               /* Content-Type boundary parameter */
    char *disposition;            /* Content-Disposition without parameters */
    char *filename;               /* Content-Disposition filename parameter */
};

static void _emailpart_fini(struct emailpart *part)
{
    if (!part) return;

    struct emailpart *subpart;
    while ((subpart = ptrarray_pop(&part->subparts))) {
        _emailpart_fini(subpart);
        free(subpart);
    }
    ptrarray_fini(&part->subparts);
    json_decref(part->jpart);
    json_decref(part->jbody);
    _headers_fini(&part->headers);
    free(part->type);
    free(part->subtype);
    free(part->boundary);
    free(part->charset);
    free(part->disposition);
    free(part->filename);
    free(part->blob_id);
}

struct email {
    struct headers headers; /* parsed headers */
    json_t *jemail;               /* original Email JSON object */
    struct emailpart *body;      /* top-level MIME part */
    int has_attachment;           /* set the HasAttachment flag */
};

static void _email_fini(struct email *email)
{
    if (!email) return;
    _headers_fini(&email->headers);
    json_decref(email->jemail);
    _emailpart_fini(email->body);
    free(email->body);
}

static json_t *_header_make(const char *header_name, const char *prop_name, struct buf *val)
{
    // FIXME encode specials? extended MIME? probably reuse _mime_write_param.
    char *tmp = buf_release(val);
    json_t *jheader = json_pack("{s:s s:s}", "name", header_name, "value", tmp);
    free(tmp);
    if (prop_name) json_object_set_new(jheader, "prop", json_string(prop_name));
    return jheader;
}

typedef json_t* (*header_from_t)(json_t *jval,
                                 struct jmap_parser *parser,
                                 const char *prop_name,
                                 const char *header_name);

static json_t *_header_from_raw(json_t *jraw,
                                struct jmap_parser *parser,
                                const char *prop_name,
                                const char *header_name)
{
    /* Verbatim use header value in raw form */
    if (json_is_string(jraw)) {
        json_t *jheader = json_pack("{s:s s:O s:s}",
                "name", header_name, "value", jraw, "prop", prop_name);
        return jheader;
    }
    else {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }
}

static json_t *_header_from_text(json_t *jtext,
                                 struct jmap_parser *parser,
                                 const char *prop_name,
                                 const char *header_name)
{
    /* Parse a Text header into raw form */
    if (json_is_string(jtext)) {
        size_t prefix_len = strlen(header_name) + 2;
        const char *s = json_string_value(jtext);
        /* Q-encoding will fold lines for us */
        int force_quote = prefix_len + strlen(s) > MIME_MAX_HEADER_LENGTH;
        char *tmp = charset_encode_mimeheader(s, strlen(s), force_quote);
        struct buf val = BUF_INITIALIZER;
        /* If text got force-quoted the first line of the Q-encoded
         * text might spill over the soft 78-character limit due to
         * the Header name prefix. Looking at how most of the mail
         * clients are doing this, this seems not to be an issue and
         * allows us to not start the header value with a line fold. */
        buf_setcstr(&val, tmp);
        free(tmp);
        return _header_make(header_name, prop_name, &val);
    }
    else {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }
}

static json_t *_header_from_jstrings(json_t *jstrings,
                                     struct jmap_parser *parser,
                                     const char *prop_name,
                                     const char *header_name,
                                     char sep)
{
    if (!json_array_size(jstrings)) {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }

    size_t sep_len  = sep ? 1 : 0;
    size_t line_len = strlen(header_name) + 2;
    size_t i;
    json_t *jval;
    struct buf val = BUF_INITIALIZER;

    json_array_foreach(jstrings, i, jval) {
        const char *s = json_string_value(jval);
        if (!s) {
            jmap_parser_invalid(parser, prop_name);
            goto fail;
        }
        size_t s_len = strlen(s);
        if (i && sep) {
            buf_putc(&val, sep);
            line_len++;
        }
        if (line_len + s_len + sep_len  + 1 > MIME_MAX_HEADER_LENGTH) {
            buf_appendcstr(&val, "\r\n ");
            line_len = 1;
        }
        else if (i) {
            buf_putc(&val, ' ');
            line_len++;
        }
        buf_appendcstr(&val, s);
        line_len += s_len;
    }

    return _header_make(header_name, prop_name, &val);

fail:
    buf_free(&val);
    return NULL;
}


static json_t *_header_from_addresses(json_t *addrs,
                                       struct jmap_parser *parser,
                                       const char *prop_name,
                                       const char *header_name)
{
    if (!json_array_size(addrs)) {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }

    size_t i;
    json_t *addr;
    struct buf adr = BUF_INITIALIZER;
    json_t *jstrings = json_array();
    json_t *ret = NULL;

    json_array_foreach(addrs, i, addr) {
        json_t *jname = json_object_get(addr, "name");
        if (!json_is_string(jname) && JNOTNULL(jname)) {
            jmap_parser_push_index(parser, prop_name, i);
            jmap_parser_invalid(parser, "name");
            jmap_parser_pop(parser);
        }

        json_t *jemail = json_object_get(addr, "email");
        if (!json_is_string(jemail) && JNOTNULL(jemail)) {
            jmap_parser_push_index(parser, prop_name, i);
            jmap_parser_invalid(parser, "email");
            jmap_parser_pop(parser);
        }

        if (json_array_size(parser->invalid))
            goto done;
        if (!JNOTNULL(jname) && !JNOTNULL(jemail))
            continue;

        const char *name = json_string_value(jname);
        const char *email = json_string_value (jemail);
        if (!name && !email) continue;

        if (name && strlen(name) && email) {
            char *xname = charset_encode_mimeheader(name, strlen(name), 0);
            buf_printf(&adr, "%s <%s>", xname, email);
            free(xname);
        } else if (email) {
            buf_setcstr(&adr, email);
        }
        json_array_append_new(jstrings, json_string(buf_cstring(&adr)));
        buf_reset(&adr);
    }
    ret = _header_from_jstrings(jstrings, parser, prop_name, header_name, ',');

done:
    json_decref(jstrings);
    buf_free(&adr);
    return ret;
}

static json_t *_header_from_messageids(json_t *jmessageids,
                                       struct jmap_parser *parser,
                                       const char *prop_name,
                                       const char *header_name)
{
    if (!json_array_size(jmessageids)) {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }

    size_t i;
    json_t *jval;
    struct buf val = BUF_INITIALIZER;
    json_t *jstrings = json_array();
    json_t *ret = NULL;

    json_array_foreach(jmessageids, i, jval) {
        const char *s = json_string_value(jval);
        if (!s) {
            jmap_parser_invalid(parser, prop_name);
            goto done;
        }
        buf_appendcstr(&val, "<");
        buf_appendcstr(&val, s);
        buf_appendcstr(&val, ">");
        json_array_append_new(jstrings, json_string(buf_cstring(&val)));
        buf_reset(&val);
    }
    ret = _header_from_jstrings(jstrings, parser, prop_name, header_name, 0);

done:
    json_decref(jstrings);
    buf_free(&val);
    return ret;
}

static json_t *_header_from_date(json_t *jdate,
                                 struct jmap_parser *parser,
                                 const char *prop_name,
                                 const char *header_name)
{
    const char *s = json_string_value(jdate);
    if (!s) {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }

    time_t t;
    int n = time_from_iso8601(s, &t);
    if (n <= 0 || s[n] != '\0') {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }
    char fmt[RFC5322_DATETIME_MAX+1];
    memset(fmt, 0, RFC5322_DATETIME_MAX+1);
    time_to_rfc5322(t, fmt, RFC5322_DATETIME_MAX+1);

    struct buf val = BUF_INITIALIZER;
    buf_setcstr(&val, fmt);
    return _header_make(header_name, prop_name, &val);
}

static json_t *_header_from_urls(json_t *jurls,
                                 struct jmap_parser *parser,
                                 const char *prop_name,
                                const char *header_name)
{
    if (!json_array_size(jurls)) {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }

    size_t i;
    json_t *jval;
    struct buf val = BUF_INITIALIZER;
    json_t *jstrings = json_array();
    json_t *ret = NULL;

    json_array_foreach(jurls, i, jval) {
        const char *s = json_string_value(jval);
        if (!s) {
            jmap_parser_invalid(parser, prop_name);
            goto done;
        }

        buf_appendcstr(&val, "<");
        buf_appendcstr(&val, s);
        buf_appendcstr(&val, ">");
        json_array_append_new(jstrings, json_string(buf_cstring(&val)));
        buf_reset(&val);
    }
    ret = _header_from_jstrings(jstrings, parser, prop_name, header_name, ',');

done:
    json_decref(jstrings);
    buf_free(&val);
    return ret;
}

static void _headers_parseprops(json_t *jobject,
                           struct jmap_parser *parser,
                           struct headers *headers)
{
    const char *field;
    json_t *jval;
    json_object_foreach(jobject, field, jval) {
        if (strncmp(field, "header:", 7))
            continue;
        /* Parse header or reject if invalid form */
        struct header_prop *hprop = _header_parseprop(field);
        if (!hprop) {
            jmap_parser_invalid(parser, field);
            continue;
        }
        /* Reject redefinition of header */
        if (json_object_get(headers->all, hprop->lcasename)) {
            _header_prop_free(hprop);
            jmap_parser_invalid(parser, field);
            continue;
        }
        /* Parse header value */
        header_from_t cb = NULL;
        switch (hprop->form) {
            case HEADER_FORM_RAW:
                cb = _header_from_raw;
                break;
            case HEADER_FORM_TEXT:
                cb = _header_from_text;
                break;
            case HEADER_FORM_ADDRESSES:
                cb = _header_from_addresses;
                break;
            case HEADER_FORM_MESSAGEIDS:
                cb = _header_from_messageids;
                break;
            case HEADER_FORM_DATE:
                cb = _header_from_date;
                break;
            case HEADER_FORM_URLS:
                cb = _header_from_urls;
                break;
            default:
                syslog(LOG_ERR, "jmap: unknown header form: %d", hprop->form);
                jmap_parser_invalid(parser, field);
        }
        if (hprop->all) {
            size_t i;
            json_t *jall = jval;
            json_array_foreach(jall, i, jval) {
                jmap_parser_push_index(parser, field, i);
                json_t *jheader = cb(jval, parser, field, hprop->name);
                if (jheader) _headers_add_new(headers, jheader);
                jmap_parser_pop(parser);
            }
        }
        else {
            json_t *jheader = cb(jval, parser, field, hprop->name);
            if (jheader) _headers_add_new(headers, jheader);
        }
        _header_prop_free(hprop);
    }
}

static void _emailpart_parse_headers(json_t *jpart,
                                     struct jmap_parser *parser,
                                     struct emailpart *part)
{
    /* headers */
    if (JNOTNULL(json_object_get(jpart, "headers"))) {
        jmap_parser_invalid(parser, "headers");
    }

    /* header:Xxx */
    const char *lcasename = NULL;
    json_t *jheaders;
    _headers_parseprops(jpart, parser, &part->headers);
    /* Validate Content-Xxx headers */
    json_object_foreach(part->headers.all, lcasename, jheaders) {
        if (strncmp(lcasename, "content-", 8))
            continue;

        json_t *jheader = json_array_get(jheaders, 0);
        const char *name = json_string_value(json_object_get(jheader, "name"));
        const char *val = json_string_value(json_object_get(jheader, "value"));
        const char *prop = json_string_value(json_object_get(jheader, "prop"));

        /* Reject re-definition of Content-Xxx headers */
        if (json_array_size(jheaders) > 1) {
            size_t j;
            json_array_foreach(jheaders, j, jheader) {
                prop = json_string_value(json_object_get(jheader, "prop"));
                jmap_parser_invalid(parser, prop);
            }
            continue;
        }
        if (!strcasecmp(name, "Content-Type")) {
            /* Validate Content-Type */
            struct param *type_params = NULL;
            message_parse_type(val, &part->type, &part->subtype, &type_params);
            if (part->type  && part->subtype) {
                struct param *param = type_params;
                while (param) {
                    if (!strcasecmp(param->attribute, "BOUNDARY")) {
                        part->boundary = xstrdupnull(param->value);
                    }
                    if (!strcasecmp(param->attribute, "CHARSET")) {
                        part->charset = xstrdupnull(param->value);
                    }
                    param = param->next;
                }
                /* Headers for multipart MUST specify a boundary */
                if (!strcasecmp(part->type, "MULTIPART") && !part->boundary)
                    jmap_parser_invalid(parser, prop);
                /* Headers for bodyparts with partId MUST NOT specify a charset */
                if (JNOTNULL(json_object_get(jpart, "partId")) && part->charset)
                    jmap_parser_invalid(parser, prop);
            }
            else {
                jmap_parser_invalid(parser, prop);
            }
            param_free(&type_params);
        }
        else if (!strcasecmp(name, "Content-Disposition")) {
            /* Validate Content-Disposition */
            struct param *disp_params = NULL;
            message_parse_disposition(val, &part->disposition, &disp_params);
            if (!part->disposition) {
                jmap_parser_invalid(parser, prop);
                continue;
            }
            param_free(&disp_params);
        }
        else if (!strcasecmp(name, "Content-Transfer-Encoding")) {
            /* Always reject Content-Transfer-Encoding */
            jmap_parser_invalid(parser, prop);
        }
    }
}

static struct emailpart *_emailpart_parse(json_t *jpart,
                                          struct jmap_parser *parser,
                                          json_t *bodies)
{
    if (!json_is_object(jpart)) {
        jmap_parser_invalid(parser, NULL);
        return NULL;
    }

    struct buf buf = BUF_INITIALIZER;
    struct emailpart *part = xzmalloc(sizeof(struct emailpart));
    part->jpart = json_incref(jpart);

    json_t *jval;

    /* partId */
    json_t *jpartId = json_object_get(jpart, "partId");
    if (JNOTNULL(jpartId) && !json_is_string(jpartId)) {
        jmap_parser_invalid(parser, "partId");
    }

    /* blobId */
    jval = json_object_get(jpart, "blobId");
    if (JNOTNULL(jval) && json_is_string(jval)) {
        part->blob_id = xstrdup(json_string_value(jval));
    }
    else if (JNOTNULL(jval)) {
        jmap_parser_invalid(parser, "blobId");
    }

    /* size */
    jval = json_object_get(jpart, "size");
    if (JNOTNULL(jval) && (!json_is_integer(jval) || JNOTNULL(jpartId))) {
        jmap_parser_invalid(parser, "size");
    }

    /* Parse headers */
    _emailpart_parse_headers(jpart, parser, part);

    /* Parse convenience header properties */
    int seen_header;

    /* cid */
    json_t *jcid = json_object_get(jpart, "cid");
    seen_header = _headers_have(&part->headers, "Content-Id");
    if (json_is_string(jcid) && !seen_header) {
        const char *cid = json_string_value(jcid);
        buf_setcstr(&buf, "<");
        buf_appendcstr(&buf, cid);
        buf_appendcstr(&buf, ">");
        _headers_add_new(&part->headers, _header_make("Content-Id", "cid", &buf));
    }
    else if (JNOTNULL(jcid)) {
        jmap_parser_invalid(parser, "cid");
    }

    /* language */
    json_t *jlanguage = json_object_get(jpart, "language");
    seen_header = _headers_have(&part->headers, "Content-Language");
    if (json_is_array(jlanguage) && !seen_header) {
        _headers_add_new(&part->headers, _header_from_jstrings(jlanguage,
                    parser, "language", "Content-Language", ','));
    }
    else if (JNOTNULL(jlanguage)) {
        jmap_parser_invalid(parser, "language");
    }

    /* location */
    json_t *jlocation = json_object_get(jpart, "location");
    seen_header = _headers_have(&part->headers, "Content-Location");
    if (json_is_string(jlocation) && !seen_header) {
        buf_setcstr(&buf, json_string_value(jlocation));
        _headers_add_new(&part->headers, _header_make("Content-Location", "location", &buf));
    }
    else if (JNOTNULL(jlocation)) {
        jmap_parser_invalid(parser, "location");
    }

    /* Check Content-Type and Content-Disposition header properties */
    int have_type_header = _headers_have(&part->headers, "Content-Type");
    int have_disp_header = _headers_have(&part->headers, "Content-Disposition");
    /* name */
    json_t *jname = json_object_get(jpart, "name");
    if (json_is_string(jname) && !have_type_header && !have_disp_header) {
        part->filename = xstrdup(json_string_value(jname));
    }
    else if (JNOTNULL(jname)) {
        jmap_parser_invalid(parser, "name");
    }
    /* disposition */
    json_t *jdisposition = json_object_get(jpart, "disposition");
    if (json_is_string(jdisposition) && !have_disp_header) {
        /* Build Content-Disposition header */
        part->disposition = xstrdup(json_string_value(jdisposition));
        buf_setcstr(&buf, part->disposition);
        if (part->filename) {
            buf_appendcstr(&buf, "; filename=\"");
            buf_appendcstr(&buf, part->filename);
            buf_appendcstr(&buf, "\"");
        }
        _headers_add_new(&part->headers,
                _header_make("Content-Disposition", "disposition", &buf));
    }
    else if (JNOTNULL(jdisposition)) {
        jmap_parser_invalid(parser, "disposition");
    }
    else if (jname) {
        /* No disposition but a name, make standard Content-Disposition */
        part->disposition = xstrdup("attachment");
        const char *name = json_string_value(jname);
        char *tmp = charset_encode_mimeheader(name, strlen(name), 0);
        buf_printf(&buf, "attachment;filename=\"%s\"", tmp);
        free(tmp);
        _headers_add_new(&part->headers,
                _header_make("Content-Disposition", "name", &buf));
    }
    /* charset */
    json_t *jcharset = json_object_get(jpart, "charset");
    if (json_is_string(jcharset) && !have_type_header && JNOTNULL(jpartId)) {
        part->charset = xstrdup(json_string_value(jcharset));
    }
    else if (JNOTNULL(jcharset)) {
        jmap_parser_invalid(parser, "charset");
    }
    /* type */
    json_t *jtype = json_object_get(jpart, "type");
    if (JNOTNULL(jtype) && json_is_string(jtype) && !have_type_header) {
		const char *type = json_string_value(jtype);
        struct param *type_params = NULL;
        /* Validate type value */
        message_parse_type(type, &part->type, &part->subtype, &type_params);
        if (part->type && part->subtype && !type_params) {
            /* Build Content-Type header */
            if (!strcasecmp(part->type, "MULTIPART")) {
                /* Make boundary */
                part->boundary = _mime_make_boundary();
            }
            buf_reset(&buf);
            buf_printf(&buf, "%s/%s", part->type, part->subtype);
            buf_lcase(&buf);
            if (part->boundary) {
                buf_appendcstr(&buf, "; boundary=");
                buf_appendcstr(&buf, part->boundary);
            }
            if (part->filename) {
                buf_appendcstr(&buf, "; name=\"");
                buf_appendcstr(&buf, part->filename);
                buf_appendcstr(&buf, "\"");
            }
            if (part->charset) {
                buf_appendcstr(&buf, "; charset=");
                buf_appendcstr(&buf, part->charset);
            }
            _headers_add_new(&part->headers,
                    _header_make("Content-Type", "type", &buf));
        }
        else {
            jmap_parser_invalid(parser, "type");
        }
        param_free(&type_params);
    }
    else if (JNOTNULL(jtype)) {
        jmap_parser_invalid(parser, "type");
    }

    /* Validate by type */
    const char *part_id = json_string_value(json_object_get(jpart, "partId"));
    const char *blob_id = json_string_value(json_object_get(jpart, "blobId"));
    json_t *subParts = json_object_get(jpart, "subParts");
    json_t *bodyValue = part_id ? json_object_get(bodies, part_id) : NULL;

    if (part_id && blob_id)
        jmap_parser_invalid(parser, "blobId");
    if (part_id && !bodyValue)
        jmap_parser_invalid(parser, "partId");

    if (subParts || (part->type && !strcasecmp(part->type, "MULTIPART"))) {
        /* Parse sub parts */
        if (json_array_size(subParts)) {
            size_t i;
            json_t *subPart;
            json_array_foreach(subParts, i, subPart) {
                jmap_parser_push_index(parser, "subParts", i);
                struct emailpart *subpart = _emailpart_parse(subPart, parser, bodies);
                if (subpart) ptrarray_append(&part->subparts, subpart);
                jmap_parser_pop(parser);
            }
        }
        else {
            jmap_parser_invalid(parser, "subParts");
        }
        /* Must not have a body value */
        if (JNOTNULL(bodyValue))
            jmap_parser_invalid(parser, "partId");
        /* Must not have a blobId */
        if (blob_id)
            jmap_parser_invalid(parser, "blobId");
    }
    else if (part_id || (part->type && !strcasecmp(part->type, "TEXT"))) {
        /* Must have a text body as blob or bodyValue */
        if ((bodyValue == NULL) == (blob_id == NULL))
            jmap_parser_invalid(parser, "blobId");
        /* Must not have sub parts */
        if (JNOTNULL(subParts))
            jmap_parser_invalid(parser, "subParts");
    }
    else {
        /* Must have a blob id */
        if (!blob_id)
            jmap_parser_invalid(parser, "blobId");
        /* Must not have a text body */
        if (bodyValue)
            jmap_parser_invalid(parser, "partId");
        /* Must not have sub parts */
        if (JNOTNULL(subParts))
            jmap_parser_invalid(parser, "subParts");
    }

    buf_free(&buf);

    if (json_array_size(parser->invalid)) {
        _emailpart_fini(part);
        free(part);
        return NULL;
    }

    /* Check if this part is marked as attachment */
    if (part->type) {
        if (strcasecmp(part->type, "TEXT") && strcasecmp(part->type, "MULTIPART")) {
            if (!part->disposition || strcasecmp(part->disposition, "INLINE"))
                part->is_attachment = 1;
        }
    }
    else if (part->blob_id) {
        part->is_attachment = 1;
    }

    /* Finalize part definition */
    part->jbody = json_incref(bodyValue);

    return part;
}

static struct emailpart *_emailpart_new_multi(const char *subtype,
                                               ptrarray_t *subparts)
{
    struct emailpart *part = xzmalloc(sizeof(struct emailpart));
    int i;

    part->type = xstrdup("multipart");
    part->subtype = xstrdup(subtype);
    part->boundary = _mime_make_boundary();
    struct buf val = BUF_INITIALIZER;
    buf_printf(&val, "%s/%s;boundary=%s",
            part->type, part->subtype, part->boundary);
    _headers_add_new(&part->headers,
            _header_make("Content-Type", NULL, &val));
    for (i = 0; i < subparts->count; i++)
        ptrarray_append(&part->subparts, ptrarray_nth(subparts, i));

    return part;
}

static struct emailpart *_email_buildbody(struct emailpart *text_body,
                                          struct emailpart *html_body,
                                          ptrarray_t *attached_emails,
                                          ptrarray_t *attached_files)
{
    /* Make MIME part for embedded emails. */
    struct emailpart *emails = NULL;
    if (attached_emails->count >= 2)
        emails = _emailpart_new_multi("digest", attached_emails);
    else if (attached_emails->count == 1)
        emails = ptrarray_nth(attached_emails, 0);

    /* Make MIME part for text bodies. */
    struct emailpart *text = NULL;
    if (text_body && html_body) {
        ptrarray_t alternatives = PTRARRAY_INITIALIZER;
        ptrarray_append(&alternatives, text_body);
        ptrarray_append(&alternatives, html_body);
        text = _emailpart_new_multi("alternative", &alternatives);
        ptrarray_fini(&alternatives);
    }
    else if (text_body)
        text = text_body;
    else if (html_body)
        text = html_body;

    /* Choose top-level MIME part. */
    if (attached_files->count) {
        struct emailpart *mixed = _emailpart_new_multi("mixed", attached_files);
        if (emails) ptrarray_insert(&mixed->subparts, 0, emails);
        if (text) ptrarray_insert(&mixed->subparts, 0, text);
        return mixed;
    }
    else if (text && emails) {
        struct emailpart *wrapper = NULL;
        ptrarray_t wrapped = PTRARRAY_INITIALIZER;
        ptrarray_append(&wrapped, text);
        ptrarray_append(&wrapped, emails);
        wrapper = _emailpart_new_multi("mixed", &wrapped);
        ptrarray_fini(&wrapped);
        return wrapper;
    }
    else if (text)
        return text;
    else if (emails)
        return emails;
    else
        return NULL;
}


static void _email_parse_bodies(json_t *jemail,
                                struct jmap_parser *parser,
                                struct email *email)
{
    /* bodyValues */
    json_t *bodyValues = json_object_get(jemail, "bodyValues");
    if (json_is_object(bodyValues)) {
        const char *part_id;
        json_t *bodyValue;
        jmap_parser_push(parser, "bodyValues");
        json_object_foreach(bodyValues, part_id, bodyValue) {
            jmap_parser_push(parser, part_id);
            if (json_is_object(bodyValue)) {
                json_t *jval = json_object_get(bodyValue, "value");
                if (!json_is_string(jval)) {
                    jmap_parser_invalid(parser, "value");
                }
                jval = json_object_get(bodyValue, "isEncodingProblem");
                if (JNOTNULL(jval) && jval != json_false()) {
                    jmap_parser_invalid(parser, "isEncodingProblem");
                }
                jval = json_object_get(bodyValue, "isTruncated");
                if (JNOTNULL(jval) && jval != json_false()) {
                    jmap_parser_invalid(parser, "isTruncated");
                }
            }
            else {
                jmap_parser_invalid(parser, NULL);
            }
            jmap_parser_pop(parser);
        }
        jmap_parser_pop(parser);
    }
    else if (JNOTNULL(bodyValues)) {
        jmap_parser_invalid(parser, "bodyValues");
    }

    /* bodyStructure */
    json_t *jbody = json_object_get(jemail, "bodyStructure");
    if (json_is_object(jbody)) {
        jmap_parser_push(parser, "bodyStructure");
        email->body = _emailpart_parse(jbody, parser, bodyValues);
        jmap_parser_pop(parser);
        /* Top-level body part MUST NOT redefine headers in Email */
        if (email->body) {
            const char *name;
            json_t *jheader;
            json_object_foreach(email->body->headers.all, name, jheader) {
                if (json_object_get(email->headers.all, name)) {
                    /* Report offending header property */
                    json_t *jprop = json_object_get(jheader, "prop");
                    const char *prop = json_string_value(jprop);
                    if (prop) prop = "bodyStructure";
                    jmap_parser_invalid(parser, prop);
                }
            }
        }
    }
    else if (JNOTNULL(jbody)) {
        jmap_parser_invalid(parser, "bodyStructure");
    }

    json_t *jtextBody = json_object_get(jemail, "textBody");
    json_t *jhtmlBody = json_object_get(jemail, "htmlBody");
    json_t *jattachedEmails = json_object_get(jemail, "attachedEmails");
    json_t *jattachedFiles = json_object_get(jemail, "attachedFiles");

    struct emailpart *text_body = NULL;
    struct emailpart *html_body = NULL;
    ptrarray_t attached_emails = PTRARRAY_INITIALIZER; /* array of struct emailpart* */
    ptrarray_t attached_files = PTRARRAY_INITIALIZER;  /* array of struct emailpart* */

    if (JNOTNULL(jbody)) {
        /* bodyStructure and fooBody are mutually exclusive */
        if (JNOTNULL(jtextBody)) {
            jmap_parser_invalid(parser, "textBody");
        }
        if (JNOTNULL(jhtmlBody)) {
            jmap_parser_invalid(parser, "htmlBody");
        }
        if (JNOTNULL(jattachedEmails)) {
            jmap_parser_invalid(parser, "attachedEmails");
        }
        if (JNOTNULL(jattachedFiles)) {
            jmap_parser_invalid(parser, "attachedFiles");
        }
    }
    else {
        /* textBody */
        if (json_array_size(jtextBody) == 1) {
            json_t *jpart = json_array_get(jtextBody, 0);
            jmap_parser_push_index(parser, "textBody", 0);
            text_body = _emailpart_parse(jpart, parser, bodyValues);
            jmap_parser_pop(parser);
            if (text_body) {
                if (!text_body->type) {
                    /* Set default type */
                    text_body->type = xstrdup("text");
                    text_body->subtype = xstrdup("plain");
                    struct buf val = BUF_INITIALIZER;
                    buf_setcstr(&val, "text/plain");
                    _headers_add_new(&text_body->headers,
                            _header_make("Content-Type", NULL, &val));
                }
                else if (strcasecmp(text_body->type, "text") ||
                         strcasecmp(text_body->subtype, "plain")) {
                    jmap_parser_invalid(parser, "textBody");
                }
            }
        }
        else if (JNOTNULL(jtextBody)) {
            jmap_parser_invalid(parser, "textBody");
        }
        /* htmlBody */
        if (json_array_size(jhtmlBody) == 1) {
            json_t *jpart = json_array_get(jhtmlBody, 0);
            jmap_parser_push_index(parser, "htmlBody", 0);
            html_body = _emailpart_parse(jpart, parser, bodyValues);
            jmap_parser_pop(parser);
            if (html_body) {
                if (!html_body->type) {
                    /* Set default type */
                    html_body->type = xstrdup("text");
                    html_body->subtype = xstrdup("html");
                    struct buf val = BUF_INITIALIZER;
                    buf_setcstr(&val, "text/html");
                    _headers_add_new(&html_body->headers,
                            _header_make("Content-Type", NULL, &val));
                }
                else if (strcasecmp(html_body->type, "text") ||
                         strcasecmp(html_body->subtype, "html")) {
                    jmap_parser_invalid(parser, "htmlBody");
                }
            }
        }
        else if (JNOTNULL(jhtmlBody)) {
            jmap_parser_invalid(parser, "htmlBody");
        }
        /* attachedEmails */
        if (json_is_array(jattachedEmails)) {
            size_t i;
            json_t *jpart;
            struct emailpart *attpart;
            json_array_foreach(jattachedEmails, i, jpart) {
                jmap_parser_push_index(parser, "attachedEmails", i);
                attpart = _emailpart_parse(jpart, parser, bodyValues);
                if (attpart) {
                    if (attpart->type && !strcasecmp(attpart->type, "message") &&
                        (!strcasecmp(attpart->subtype, "rfc822") ||
                         !strcasecmp(attpart->subtype, "global"))) {
                        /* It's aegit part */
                        ptrarray_append(&attached_emails, attpart);
                    }
                    else if (!attpart->type) {
                        /* Set default type */
                        attpart->type = xstrdup("message");
                        attpart->subtype = xstrdup("rfc822");
                        struct buf val = BUF_INITIALIZER;
                        buf_setcstr(&val, "message/rfc822");
                        _headers_add_new(&attpart->headers,
                                _header_make("Content-Type", NULL, &val));
                        ptrarray_append(&attached_emails, attpart);
                    }
                    else {
                        jmap_parser_invalid(parser, NULL);
                    }
                }
                jmap_parser_pop(parser);
            }
        }
        else if (JNOTNULL(jattachedEmails)) {
            jmap_parser_invalid(parser, "attachedEmails");
        }
        /* attachedFiles */
        if (json_is_array(jattachedFiles)) {
            size_t i;
            json_t *jpart;
            struct emailpart *attpart;
            json_array_foreach(jattachedFiles, i, jpart) {
                jmap_parser_push_index(parser, "attachedFiles", i);
                attpart = _emailpart_parse(jpart, parser, bodyValues);
                if (attpart) ptrarray_append(&attached_files, attpart);
                jmap_parser_pop(parser);
            }
        }
        else if (JNOTNULL(jattachedFiles)) {
            jmap_parser_invalid(parser, "attachedFiles");
        }
    }

    if (!email->body) {
        /* Build email body from convenience body properties */
        email->body = _email_buildbody(text_body, html_body,
                &attached_emails, &attached_files);
    }

    ptrarray_fini(&attached_emails);
    ptrarray_fini(&attached_files);

    /* Look through all parts if any part is an attachment.
     * If so, set the hasAttachment flag. */
    if (email->body) {
        ptrarray_t work = PTRARRAY_INITIALIZER;
        ptrarray_append(&work, email->body);

        struct emailpart *part;
        while ((part = ptrarray_pop(&work))) {
            int i;
            if (part->is_attachment) {
                email->has_attachment = 1;
                break;
            }
            for (i = 0; i < part->subparts.count; i++) {
                struct emailpart *subpart = ptrarray_nth(&part->subparts, i);
                ptrarray_append(&work, subpart);
            }
        }
        ptrarray_fini(&work);
    }
}

/* Parse a JMAP Email into its internal representation for creation. */
static void _email_parse(json_t *jemail,
                         struct jmap_parser *parser,
                         struct email *email)
{
    email->jemail = json_incref(jemail);

    /* mailboxIds */
    json_t *jmailboxIds = json_object_get(jemail, "mailboxIds");
    if (json_object_size(jmailboxIds)) {
        const char *mailboxid;
        json_t *jval;
        jmap_parser_push(parser, "mailboxIds");
        json_object_foreach(jmailboxIds, mailboxid, jval) {
            if (*mailboxid == '\0') {
                jmap_parser_invalid(parser, NULL);
                break;
            }
            if (jval != json_true()) {
                jmap_parser_invalid(parser, mailboxid);
            }
        }
        jmap_parser_pop(parser);
    }
    else {
        jmap_parser_invalid(parser, "mailboxIds");
    }

    /* keywords */
    json_t *jkeywords = json_object_get(jemail, "keywords");
    if (json_is_object(jkeywords)) {
        const char *keyword;
        json_t *jval;
        jmap_parser_push(parser, "keywords");
        json_object_foreach(jkeywords, keyword, jval) {
            if (jval != json_true() || !_email_keyword_is_valid(keyword)) {
                jmap_parser_invalid(parser, keyword);
            }
        }
        jmap_parser_pop(parser);
    }
    else if (JNOTNULL(jkeywords)) {
        jmap_parser_invalid(parser, "keywords");
    }

    /* headers */
    if (JNOTNULL(json_object_get(jemail, "headers"))) {
        jmap_parser_invalid(parser, "headers");
    }
    /* header:Xxx */
    _headers_parseprops(jemail, parser, &email->headers);
    size_t i;
    json_t *jheader;
    json_array_foreach(email->headers.raw, i, jheader) {
        const char *s = json_string_value(json_object_get(jheader, "name"));
        /* Reject Content-Xxx headers in Email/headers */
            if (!strncasecmp("Content-", s, 8)) {
                char *tmp = strconcat("header:", s, NULL);
                jmap_parser_invalid(parser, tmp);
                free(tmp);
            }
    }

    /* Parse convenience header properties - in order as serialised */
    struct buf buf = BUF_INITIALIZER;
    json_t *prop;
    int seen_header;

    /* messageId */
    prop = json_object_get(jemail, "messageId");
    seen_header = _headers_have(&email->headers, "Message-Id");
    if (json_array_size(prop) == 1 && !seen_header) {
        _headers_add_new(&email->headers, _header_from_messageids(prop,
                    parser, "messageId", "Message-Id"));
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "messageId");
    }
    /* inReplyTo */
    prop = json_object_get(jemail, "inReplyTo");
    seen_header = _headers_have(&email->headers, "In-Reply-To");
    if (json_is_array(prop) && !seen_header) {
        _headers_add_new(&email->headers, _header_from_messageids(prop,
                    parser, "inReplyTo", "In-Reply-To"));
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "inReplyTo");
    }
    /* references */
    prop = json_object_get(jemail, "references");
    seen_header = _headers_have(&email->headers, "References");
    if (json_is_array(prop) && !seen_header) {
        _headers_add_new(&email->headers, _header_from_messageids(prop,
                    parser, "references", "References"));
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "references");
    }
    /* sentAt */
    prop = json_object_get(jemail, "sentAt");
    seen_header = _headers_have(&email->headers, "Date");
    if (json_is_string(prop) && !seen_header) {
        _headers_add_new(&email->headers, _header_from_date(prop,
                    parser, "sentAt", "Date"));
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "sentAt");
    }
    /* from */
    prop = json_object_get(jemail, "from");
    seen_header = _headers_have(&email->headers, "From");
    if (json_is_array(prop) && !seen_header) {
        if ((jheader = _header_from_addresses(prop, parser, "from", "From"))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "from");
    }
    /* replyTo */
    prop = json_object_get(jemail, "replyTo");
    seen_header = _headers_have(&email->headers, "Reply-To");
    if (json_is_array(prop) && !seen_header) {
        if ((jheader = _header_from_addresses(prop, parser, "replyTo", "Reply-To"))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "replyTo");
    }
    /* sender */
    prop = json_object_get(jemail, "sender");
    seen_header = _headers_have(&email->headers, "Sender");
    if (json_is_array(prop) && !seen_header) {
        if ((jheader = _header_from_addresses(prop, parser, "sender", "Sender"))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "sender");
    }
    /* to */
    prop = json_object_get(jemail, "to");
    seen_header = _headers_have(&email->headers, "To");
    if (json_is_array(prop) && !seen_header) {
        if ((jheader = _header_from_addresses(prop, parser, "to", "To"))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "to");
    }
    /* cc */
    prop = json_object_get(jemail, "cc");
    seen_header = _headers_have(&email->headers, "Cc");
    if (json_is_array(prop) && !seen_header) {
        if ((jheader = _header_from_addresses(prop, parser, "cc", "Cc"))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "cc");
    }
    /* bcc */
    prop = json_object_get(jemail, "bcc");
    seen_header = _headers_have(&email->headers, "Bcc");
    if (json_is_array(prop) && !seen_header) {
        if ((jheader = _header_from_addresses(prop, parser, "bcc", "Bcc"))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "bcc");
    }
    /* subject */
    prop = json_object_get(jemail, "subject");
    seen_header = _headers_have(&email->headers, "Subject");
    if (json_is_string(prop) && !seen_header) {
        if ((jheader = _header_from_text(prop, parser, "subject", "Subject"))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "subject");
    }
    buf_free(&buf);

    /* Parse bodies */
    _email_parse_bodies(jemail, parser, email);
}

static void _emailpart_blob_to_mime(jmap_req_t *req,
                                    FILE *fp,
                                    struct emailpart *emailpart,
                                    json_t *missing_blobs)
{
    struct buf blob_buf = BUF_INITIALIZER;
    msgrecord_t *mr = NULL;
    struct mailbox *mbox = NULL;
    struct body *body = NULL;
    const struct body *part = NULL;

    /* Find body part containing blob */
    int r = jmap_findblob(req, emailpart->blob_id, &mbox, &mr, &body, &part);
    if (r) goto done;

    /* Map the blob into memory */
    r = msgrecord_get_body(mr, &blob_buf);
    if (r) goto done;

    uint32_t size;
    r = msgrecord_get_size(mr, &size);
    if (r) goto done;

    /* Write headers defined by client. */
    size_t i;
    json_t *jheader;
    json_array_foreach(emailpart->headers.raw, i, jheader) {
        json_t *jval = json_object_get(jheader, "name");
        const char *name = json_string_value(jval);
        jval = json_object_get(jheader, "value");
        const char *value = json_string_value(jval);
        fprintf(fp, "%s: %s\r\n", name, value);
    }

    /* Fetch blob contents and headers */
    const char *base = blob_buf.s;
    size_t len = blob_buf.len;

    if (part) {
        /* Map into body part */
        base += part->content_offset;
        len = part->content_size;

        /* Write encoding, if required */
        if (part->charset_enc & 0xff) {
            fputs("Content-Transfer-Encoding: ", fp);
            fputs(encoding_name(part->charset_enc & 0xff), fp);
            fputs("\r\n", fp);
        }
    }

    /* Write body */
    fputs("\r\n", fp);
    fwrite(base, 1, len, fp);

done:
    if (r) json_array_append_new(missing_blobs, json_string(emailpart->blob_id));
    if (body) {
        message_free_body(body);
        free(body);
    }
    msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);
    buf_free(&blob_buf);
}

static void _emailpart_text_to_mime(FILE *fp, struct emailpart *part)
{
    json_t *jval = json_object_get(part->jbody, "value");
    const char *text = json_string_value(jval);
    size_t len = strlen(text);

    /* Check and sanitise text */
    int has_long_lines = 0;
    int is_7bit = 1;
    const char *p = text;
    const char *base = text;
    const char *top = text + len;
    const char *last_lf = p;
    struct buf txtbuf = BUF_INITIALIZER;
    for (p = base; p < top; p++) {
        /* Keep track of line-length and high-bit bytes */
        if (p - last_lf > 998)
            has_long_lines = 1;
        if (*p == '\n')
            last_lf = p;
        if (*p & 0x80)
            is_7bit = 0;
        /* Omit CR */
        if (*p == '\r')
            continue;
        /* Expand LF to CRLF */
        if (*p == '\n')
            buf_putc(&txtbuf, '\r');
        buf_putc(&txtbuf, *p);
    }
    const char *charset = NULL;
    if (!is_7bit) charset = "utf-8";

    /* Write headers */
    size_t i;
    json_t *jheader;
    json_array_foreach(part->headers.raw, i, jheader) {
        json_t *jval = json_object_get(jheader, "name");
        const char *name = json_string_value(jval);
        jval = json_object_get(jheader, "value");
        const char *value = json_string_value(jval);
        if (!strcasecmp(name, "Content-Type") && charset) {
            /* Clients are forbidden to set charset on TEXT bodies,
             * so make sure we properly set the parameter value. */
            fprintf(fp, "%s: %s;charset=%s\r\n", name, value, charset);
        }
        else {
            fprintf(fp, "%s: %s\r\n", name, value);
        }
    }
    /* Write body */
    if (!is_7bit || has_long_lines) {
        /* Write quoted printable */
        size_t qp_len = 0;
        char *qp_text = charset_qpencode_mimebody(txtbuf.s, txtbuf.len, 1, &qp_len);
        fputs("Content-Transfer-Encoding : quoted-printable\r\n", fp);
        fputs("\r\n", fp);
        fwrite(qp_text, 1, qp_len, fp);
        free(qp_text);
    }
    else {
        /*  Write plain */
        fputs("\r\n", fp);
        fwrite(buf_cstring(&txtbuf), 1, buf_len(&txtbuf), fp);
    }

    buf_free(&txtbuf);
}

static void _emailpart_to_mime(jmap_req_t *req, FILE *fp,
                               struct emailpart *part,
                               json_t *missing_blobs)
{
    if (part->subparts.count) {
        /* Write raw headers */
        size_t i;
        json_t *jheader;
        json_array_foreach(part->headers.raw, i, jheader) {
            json_t *jval = json_object_get(jheader, "name");
            const char *name = json_string_value(jval);
            jval = json_object_get(jheader, "value");
            const char *value = json_string_value(jval);
            fprintf(fp, "%s: %s\r\n", name, value);
        }
        /* Write default Content-Type, if not set */
        if (!_headers_have(&part->headers, "Content-Type")) {
            part->boundary = _mime_make_boundary();
            fputs("Content-Type: multipart/mixed;boundary=", fp);
            fputs(part->boundary, fp);
            fputs("\r\n", fp);
        }
        /* Write sub parts */
        int j;
        for (j = 0; j < part->subparts.count; j++) {
            fprintf(fp, "\r\n--%s\r\n", part->boundary);
            _emailpart_to_mime(req, fp, ptrarray_nth(&part->subparts, j),
                               missing_blobs);
        }
        fprintf(fp, "\r\n--%s--\r\n", part->boundary);
    }
    else if (part->jbody) {
        _emailpart_text_to_mime(fp, part);
    }
    else if (part->blob_id) {
        _emailpart_blob_to_mime(req, fp, part, missing_blobs);
        return;
    }
}

struct email_to_mime_rock {
    struct email *email;
    json_t **set_err;
};

static int _email_to_mime(jmap_req_t *req, FILE *fp, void *_rock)
{
    struct email_to_mime_rock *rock = _rock;
    struct email *email = rock->email;
    json_t *header;
    size_t i;

    /* Set mandatory and quasi-mandatory headers */
    if (!json_object_get(email->headers.all, "user-agent")) {
        char *tmp = strconcat("Cyrus-JMAP/", CYRUS_VERSION, NULL);
        header = json_pack("{s:s s:s}", "name", "User-Agent", "value", tmp);
        _headers_shift_new(&email->headers, header);
        free(tmp);
    }
    if (!json_object_get(email->headers.all, "message-id")) {
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "<%s@%s>", makeuuid(), config_servername);
        header = json_pack("{s:s s:s}", "name", "Message-Id", "value", buf_cstring(&buf));
        _headers_shift_new(&email->headers, header);
        buf_free(&buf);
    }
    if (!json_object_get(email->headers.all, "date")) {
        char fmt[RFC5322_DATETIME_MAX+1];
        memset(fmt, 0, RFC5322_DATETIME_MAX+1);
        time_to_rfc5322(time(NULL), fmt, RFC5322_DATETIME_MAX+1);
        header = json_pack("{s:s s:s}", "name", "Date", "value", fmt);
        _headers_shift_new(&email->headers, header);
    }
    if (!json_object_get(email->headers.all, "from")) {
        header = json_pack("{s:s s:s}", "name", "From", "value", req->userid);
        _headers_shift_new(&email->headers, header);
    }

    /* Write headers */
    json_array_foreach(email->headers.raw, i, header) {
        json_t *jval;
        jval = json_object_get(header, "name");
        const char *name = json_string_value(jval);
        jval = json_object_get(header, "value");
        const char *value = json_string_value(jval);
        fprintf(fp, "%s: %s\r\n", name, value);
    }

    json_t *missing_blobs = json_array();
    if (email->body) _emailpart_to_mime(req, fp, email->body, missing_blobs);
    if (json_array_size(missing_blobs)) {
        *rock->set_err = json_pack("{s:s s:o}", "type", "blobNotFound",
                "notFound", missing_blobs);
    }
    else {
        json_decref(missing_blobs);
    }

    return 0;
}

static void _email_create(jmap_req_t *req,
                          json_t *jemail,
                          json_t **new_email,
                          json_t **set_err)
{
    strarray_t keywords = STRARRAY_INITIALIZER;
    int r = 0;
    *set_err = NULL;
    char *emailid = NULL;

    /* Parse Email object into internal representation */
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct email email = { HEADERS_INITIALIZER, NULL, NULL, 0 };
    _email_parse(jemail, &parser, &email);
    if (json_array_size(parser.invalid)) {
        *set_err = json_pack("{s:s s:O}", "type", "invalidProperties",
                "properties", parser.invalid);
        goto done;
    }

    /* Gather keywords */
    json_t *jkeywords = json_object_get(jemail, "keywords");
    if (json_object_size(jkeywords)) {
        json_t *jval;
        const char *keyword;
        json_object_foreach(jkeywords, keyword, jval) {
            strarray_append(&keywords, keyword);
        }
    }
    if (keywords.count > MAX_USER_FLAGS) {
        *set_err = json_pack("{s:s}",  "type", "tooManyKeywords");
        goto done;
    }

    /* Append MIME-encoded Email to mailboxes and write keywords */
    json_t *jmailboxids = json_object_get(jemail, "mailboxIds");
    struct email_to_mime_rock rock = { &email, set_err };
    r = _email_append(req, jmailboxids, &keywords, time(NULL),
                      email.has_attachment, _email_to_mime,
                      &rock, &emailid);
    if (r || *set_err) goto done;

    /* Update ANSWERED flags of replied-to messages */
    json_t *jheaders = _headers_get(&email.headers, "In-Reply-To");
    if (json_array_size(jheaders)) {
        json_t *jheader = json_array_get(jheaders, 0);
        struct buf buf = BUF_INITIALIZER;
        buf_setcstr(&buf, json_string_value(json_object_get(jheader, "value")));
        buf_trim(&buf);
        r = _email_set_answered(req, buf_cstring(&buf));
        buf_free(&buf);
        if (r) goto done;
    }

    /* Return newly created Email object */
    *new_email = json_pack("{s:s}", "id", emailid);
    *set_err = NULL;

done:
    if (r && *set_err == NULL) {
        syslog(LOG_ERR, "jmap: email_create: %s", error_message(r));
        if (r == IMAP_QUOTA_EXCEEDED)
            *set_err = json_pack("{s:s}", "type", "maxQuotaReached");
        else
            *set_err = json_pack("{s:s s:s}", "type", "serverError",
                    "description", error_message(r));
    }
    strarray_fini(&keywords);
    jmap_parser_fini(&parser);
    _email_fini(&email);
    free(emailid);
}

struct _email_update_checkacl_rock {
    jmap_req_t *req;
    json_t *newmailboxes;
    json_t *delmailboxes;
    json_t *oldmailboxes;
    int set_keywords;
    int set_seen;
};

static int _email_update_checkacl_cb(const mbentry_t *mbentry, void *xrock)
{
    struct _email_update_checkacl_rock *rock = xrock;
    const char *id = mbentry->uniqueid;
    jmap_req_t *req = rock->req;

    /* Determine required ACL rights, if any */
    int need_rights = 0;
    if (json_object_get(rock->newmailboxes, id))
        need_rights = ACL_INSERT|ACL_ANNOTATEMSG;
    else if (json_object_get(rock->delmailboxes, id))
        need_rights = ACL_DELETEMSG;
    else if (json_object_get(rock->oldmailboxes, id))
        need_rights = ACL_ANNOTATEMSG;

    if (!need_rights)
        return 0;

    if (need_rights != ACL_DELETEMSG) {
        if (rock->set_keywords) need_rights |= ACL_WRITE;
        if (rock->set_seen) need_rights |= ACL_SETSEEN;
    }

    int got_rights = jmap_myrights(req, mbentry);
    if ((need_rights & got_rights) != need_rights)
        return IMAP_PERMISSION_DENIED;

    return 0;
}

struct email_flagupdate {
    json_t *keywords;
    int is_patch;
    /* Callback data */
    jmap_req_t *_req;
    json_t *_cur_mailboxes;
    json_t *_new_mailboxes;
    json_t *_new_keywords;
};

#define _EMAIL_FLAGUPDATE_INITIALIZER { NULL, 0, NULL, NULL, NULL, NULL }

static void _email_flagupdate_fini(struct email_flagupdate *update)
{
    if (!update) return;
    json_decref(update->keywords);
    json_decref(update->_cur_mailboxes);
    json_decref(update->_new_mailboxes);
}

static void _email_flagupdate_parse(json_t *email,
                                    struct email_flagupdate *update,
                                    struct jmap_parser *parser)
{
    update->keywords = NULL;
    update->is_patch = 0;

    int is_patch = 0;

    /* Are keywords overwritten or patched? */
    json_t *keywords = json_incref(json_object_get(email, "keywords"));
    if (keywords == NULL) {
        /* Collect keywords as patch */
        const char *field = NULL;
        json_t *jval;
        keywords = json_object();
        json_object_foreach(email, field, jval) {
            if (strncmp(field, "keywords/", 9))  {
                continue;
            }
            const char *keyword = field + 9;
            if (!_email_keyword_is_valid(keyword) || (jval != json_true() && jval != json_null())) {
                jmap_parser_push(parser, "keywords");
                jmap_parser_invalid(parser, keyword);
                jmap_parser_pop(parser);
                continue;
            }
            /* At least one keyword gets patched */
            is_patch = 1;
            json_object_set(keywords, keyword, jval);
        }
        if (!json_object_size(keywords)) {
            json_decref(keywords);
            keywords = NULL;
        }
    }
    else if (json_is_object(keywords)) {
        /* Overwrite keywords */
        const char *keyword;
        json_t *jval;
        json_object_foreach(keywords, keyword, jval) {
            if (!_email_keyword_is_valid(keyword) || jval != json_true()) {
                jmap_parser_push(parser, "keywords");
                jmap_parser_invalid(parser, keyword);
                jmap_parser_pop(parser);
                continue;
            }
        }
    }
    else if (JNOTNULL(keywords)) {
        jmap_parser_invalid(parser, "keywords");
    }

    update->keywords = keywords;
    update->is_patch = is_patch;
}

static int _email_flagupdate_cb(const conv_guidrec_t *rec, void *rock)
{
    struct email_flagupdate *update = rock;
    jmap_req_t *req = update->_req;
    json_t *cur_mailboxes = update->_cur_mailboxes;

    /* Fetch record */
    struct mailbox *mbox = NULL;
    msgrecord_t *mrw = NULL;
    uint32_t system_flags = 0;

    int r = jmap_openmbox(req, rec->mboxname, &mbox, /*write*/1);
    if (r) return r;
    r = msgrecord_find(mbox, rec->uid, &mrw);
    if (r) goto done;
    r = msgrecord_get_systemflags(mrw, &system_flags);
    if (r) goto done;
    if (system_flags & (FLAG_EXPUNGED|FLAG_DELETED)) goto done;

    /* Determine if to patch or reset flags */
    uint32_t user_flags[MAX_USER_FLAGS/32];
    json_t *keywords = NULL;
    if (json_object_get(cur_mailboxes, mbox->uniqueid)) {
        if (update->is_patch) {
            memset(user_flags, 0, sizeof(user_flags));
            r = msgrecord_get_userflags(mrw, user_flags);
            if (r) goto done;
        }
        else {
            system_flags = 0;
            memset(user_flags, 0, sizeof(user_flags));
        }
        keywords = update->keywords;
    }
    else {
        system_flags = 0;
        memset(user_flags, 0, sizeof(user_flags));
        keywords = update->_new_keywords;
    }

    /* Update flags */
    json_t *jval;
    const char *keyword;
    json_object_foreach(keywords, keyword, jval) {
        if (!strcasecmp(keyword, "$Flagged")) {
            if (jval == json_true())
                system_flags |= FLAG_FLAGGED;
            else
                system_flags &= ~FLAG_FLAGGED;
        }
        else if (!strcasecmp(keyword, "$Answered")) {
            if (jval == json_true())
                system_flags |= FLAG_ANSWERED;
            else
                system_flags &= ~FLAG_ANSWERED;
        }
        else if (!strcasecmp(keyword, "$Seen")) {
            if (jval == json_true())
                system_flags |= FLAG_SEEN;
            else
                system_flags &= ~FLAG_SEEN;
        }
        else if (!strcasecmp(keyword, "$Draft")) {
            if (jval == json_true())
                system_flags |= FLAG_DRAFT;
            else
                system_flags &= ~FLAG_DRAFT;
        }
        else if (!strcasecmp(keyword, JMAP_HAS_ATTACHMENT_FLAG)) {
            /* $HasAttachment is read-only. Ignore. */
            continue;
        }
        else {
            int userflag;
            r = mailbox_user_flag(mbox, keyword, &userflag, 1);
            if (r) goto done;
            if (jval == json_true())
                user_flags[userflag/32] |= 1<<(userflag&31);
            else
                user_flags[userflag/32] &= ~(1<<(userflag&31));
        }
    }

    /* Write flags to record */
    r = msgrecord_set_systemflags(mrw, system_flags);
    if (r) goto done;
    r = msgrecord_set_userflags(mrw, user_flags);
    if (r) goto done;
    r = msgrecord_rewrite(mrw);
    if (r) goto done;

done:
    msgrecord_unref(&mrw);
    jmap_closembox(req, &mbox);
    return r;
}

static int _email_flagupdate_write(jmap_req_t *req, struct email_flagupdate *update,
                                 const char *msgid,
                                 json_t *cur_mailboxes,
                                 json_t *new_mailboxes)
{
    if (update->is_patch && !json_object_size(update->keywords))
        return 0;

    int r = 0;
    const char *keyword;
    json_t *jval;
    json_t *new_keywords = NULL; /* Keywords to set on new records */

    /* Set up callback data */
    update->_cur_mailboxes = json_incref(cur_mailboxes);
    update->_new_mailboxes = json_incref(new_mailboxes);
    update->_req = req;

    /* Prepare patch */
    if (update->is_patch && json_object_size(new_mailboxes)) {
        r = _email_get_keywords(req, msgid, &new_keywords);
        if (r) goto done;
        json_object_foreach(update->keywords, keyword, jval) {
            if (jval == json_null())
                json_object_del(new_keywords, keyword);
            else if (jval == json_true())
                json_object_set(new_keywords, keyword, json_true());
        }
    }
    else {
        new_keywords = json_incref(update->keywords);
    }
    update->_new_keywords = new_keywords;

    r = conversations_guid_foreach(req->cstate, _guid_from_id(msgid),
                                   _email_flagupdate_cb, update);
    if (r) goto done;


done:
    json_decref(new_keywords);
    return r;
}

static void _email_update(jmap_req_t *req,
                          json_t *email,
                          const char *msgid,
                          json_t **new_email,
                          json_t **set_err)
{
    uint32_t uid;
    struct mailbox *mbox = NULL;
    char *mboxname = NULL;
    msgrecord_t *mrw = NULL;
    const char *id;
    const char *field;
    json_t *val;
    json_t *mailboxids = NULL;    /* mailboxIds argument or built from patch */
    json_t *dst_mailboxes = NULL; /* destination mailboxes */
    json_t *src_mailboxes = NULL; /* current mailboxes */
    json_t *cur_mailboxes = NULL; /* current mailboxes that are kept */
    json_t *new_mailboxes = NULL; /* mailboxes to add the message to */
    json_t *del_mailboxes = NULL; /* mailboxes to delete the message from */
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    int r = 0;

    /* Make sure all helper routines open mailboxes exclusively. */
    req->force_openmbox_rw = 1;

    struct buf buf = BUF_INITIALIZER;
    struct email_flagupdate _email_flagupdate = _EMAIL_FLAGUPDATE_INITIALIZER;

    if (!strlen(msgid) || *msgid == '#') {
        *set_err = json_pack("{s:s}", "type", "notFound");
        goto done;
    }

    /* Pick record from any current mailbox. That's the master copy. */
    r = _email_find(req, msgid, &mboxname, &uid);
    if (r) goto done;
    src_mailboxes = _email_get_mailboxes(req, msgid);

    r = jmap_openmbox(req, mboxname, &mbox, 1);
    if (r) goto done;
    r = msgrecord_find(mbox, uid, &mrw);
    if (r) goto done;

    /* Parse keywords and keyword patches */
    _email_flagupdate_parse(email, &_email_flagupdate, &parser);

    /* Are mailboxes being overwritten or patched? */
    mailboxids = json_incref(json_object_get(email, "mailboxIds"));
    if (mailboxids == NULL) {
        /* Check if mailboxIds are patched */
        int patch_mailboxids = 0;
        json_object_foreach(email, field, val) {
            if (strncmp(field, "mailboxIds/", 11)) {
                continue;
            }
            patch_mailboxids = 1;
            break;
        }
        if (patch_mailboxids) {
            /* Build current mailboxIds argument */
            mailboxids = json_object();
            json_object_foreach(src_mailboxes, field, val) {
                json_object_set(mailboxids, field, json_true());
            }
            /* Patch mailboxIds */
            json_object_foreach(email, field, val) {
                if (strncmp(field, "mailboxIds/", 11)) {
                    continue;
                }
                if (val == json_true()) {
                    json_object_set(mailboxids, field + 11, json_true());
                }
                else if (val == json_null()) {
                    json_object_del(mailboxids, field + 11);
                }
                else {
                    jmap_parser_invalid(&parser, field);
                }
            }
        }
    }
    if (json_array_size(parser.invalid)) {
        r = 0;
        goto done;
    }

    /* Prepare mailbox update */
    if (JNOTNULL(mailboxids)) {
        dst_mailboxes = json_pack("{}");
        json_object_foreach(mailboxids, id, val) {
            if (json_true() != val) {
                jmap_parser_push(&parser, "mailboxIds");
                jmap_parser_invalid(&parser, id);
                jmap_parser_pop(&parser);
                continue;
            }
            const char *mboxid = id;
            if (id && *id == '#') {
                mboxid = hash_lookup(id + 1, &req->idmap->mailboxes);
            }
            char *name = NULL;
            if (mboxid && (name = _mbox_find_uniqueid(req, mboxid))) {
                json_object_set_new(dst_mailboxes, mboxid, json_string(name));
            } else {
                jmap_parser_push(&parser, "mailboxIds");
                jmap_parser_invalid(&parser, id);
                jmap_parser_pop(&parser);
            }
            free(name);
        }
        if (!json_object_size(dst_mailboxes)) {
            jmap_parser_invalid(&parser, "mailboxIds");
        }
    } else {
        dst_mailboxes = json_deep_copy(src_mailboxes);
    }
    if (json_array_size(parser.invalid)) {
        r = 0;
        goto done;
    }
    if (json_object_size(_email_flagupdate.keywords) > MAX_USER_FLAGS) {
        /* XXX Not really true for patches. */
        r = IMAP_USERFLAG_EXHAUSTED;
        goto done;
    }

    /* Determine mailbox differences */
    new_mailboxes = json_deep_copy(dst_mailboxes);
    json_object_foreach(src_mailboxes, id, val) {
        json_object_del(new_mailboxes, id);
    }
    del_mailboxes = json_deep_copy(src_mailboxes);
    json_object_foreach(dst_mailboxes, id, val) {
        json_object_del(del_mailboxes, id);
    }
    cur_mailboxes = json_deep_copy(src_mailboxes);
    json_object_foreach(new_mailboxes, id, val) {
        json_object_del(cur_mailboxes, id);
    }
    json_object_foreach(del_mailboxes, id, val) {
        json_object_del(cur_mailboxes, id);
    }

    /* Check mailbox ACL for shared accounts */
    if (strcmp(req->accountid, req->userid)) {
        int set_seen = !_email_flagupdate.is_patch || json_object_get(_email_flagupdate.keywords, "$seen");
        int set_keywords = !_email_flagupdate.is_patch || json_object_size(_email_flagupdate.keywords);
        struct _email_update_checkacl_rock rock = {
            req, new_mailboxes, del_mailboxes, cur_mailboxes, set_seen, set_keywords
        };
        r = jmap_mboxlist(req, _email_update_checkacl_cb, &rock);
        if (r) goto done;
    }

    /* Copy master copy to new mailboxes */
    json_object_foreach(new_mailboxes, id, val) {
        const char *dstname = json_string_value(val);
        struct mailbox *dst = NULL;

        if (!strcmp(mboxname, dstname))
            continue;
        r = jmap_openmbox(req, dstname, &dst, 1);
        if (r) goto done;
        r = _email_copy(req, mbox, dst, mrw);
        jmap_closembox(req, &dst);
        if (r) goto done;
    }

    /* Remove message from mailboxes. We've checked the required ACLs already,
     * so any error here is fatal */
    if (json_object_size(del_mailboxes)) {
        struct _email_expunge_rock data = { req, 0, del_mailboxes };
        r = conversations_guid_foreach(req->cstate, _guid_from_id(msgid), _email_expunge_cb, &data);
        if (r) goto done;
    }

    /* Clean up before we write flags */
    msgrecord_unref(&mrw);
    jmap_closembox(req, &mbox);

    /* Now update flags, if requested */
    r = _email_flagupdate_write(req, &_email_flagupdate, msgid, cur_mailboxes, new_mailboxes);
    if (r) goto done;

    *new_email = json_pack("{s:s}", "id", msgid);

done:
    jmap_parser_fini(&parser);
    jmap_closembox(req, &mbox);
    msgrecord_unref(&mrw);
    _email_flagupdate_fini(&_email_flagupdate);
    json_decref(cur_mailboxes);
    json_decref(src_mailboxes);
    json_decref(dst_mailboxes);
    json_decref(new_mailboxes);
    json_decref(del_mailboxes);
    json_decref(mailboxids);
    free(mboxname);
    buf_free(&buf);
    if (r) {
        *set_err = json_pack("{s:s}", "type", "serverError");
        syslog(LOG_ERR, "_email_update: %s", error_message(r));
    }
}

static int _email_expunge_checkacl_cb(const conv_guidrec_t *rec, void *rock)
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


static void _email_destroy(jmap_req_t *req, const char *msgid, json_t **set_err)
{
    int r = 0;

    if (msgid[0] != 'M') {
        r = IMAP_NOTFOUND;
        goto done;
    }
    /* Check mailbox ACL for shared accounts */
    if (strcmp(req->accountid, req->userid)) {
        r = conversations_guid_foreach(req->cstate, _guid_from_id(msgid),
                                       _email_expunge_checkacl_cb, req);
        if (r) goto done;
    }
    /* Delete messages */
    struct _email_expunge_rock rock = { req, 0, NULL };
    r = conversations_guid_foreach(req->cstate, _guid_from_id(msgid),
                                   _email_expunge_cb, &rock);
    if (r) goto done;
    r = rock.deleted ? 0 : IMAP_NOTFOUND;

done:
    if (r == IMAP_NOTFOUND) {
        *set_err = json_pack("{s:s}", "type", "notFound");
    }
    else if (r) {
        *set_err = json_pack("{s:s s:s}", "type", "serverError",
                "description", error_message(r));
    }
}

static int jmap_email_set(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;

    json_t *err = NULL;
    /* Just parse the generic set request. We'll validate
     * the Email object arguments during create and update. */
    jmap_set_parse(req->args, &parser, NULL, NULL, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (set.if_in_state) {
        /* TODO rewrite state function to use char* not json_t* */
        json_t *jstate = json_string(set.if_in_state);
        if (jmap_cmpstate(req, jstate, 0/*mbtype*/)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
        json_decref(jstate);
        set.old_state = xstrdup(set.if_in_state);
    }

    json_t *email;
    const char *creation_id;
    json_object_foreach(set.create, creation_id, email) {
        json_t *set_err = NULL;
        json_t *new_email = NULL;
        /* Create message */
        _email_create(req, email, &new_email, &set_err);
        if (set_err) {
            json_object_set_new(set.not_created, creation_id, set_err);
            continue;
        }
        /* Report message as created */
        json_object_set_new(set.created, creation_id, new_email);
        char *msg_id = xstrdup(json_string_value(json_object_get(new_email, "id")));
        hash_insert(creation_id, msg_id, &req->idmap->messages);
    }

    const char *email_id;
    json_object_foreach(set.update, email_id, email) {
        if (*email_id == '#') {
            const char *id = hash_lookup(email_id + 1, &req->idmap->messages);
            if (!id) {
                json_object_set_new(set.not_updated, email_id, json_pack("{s:s}",
                            "type", "notFound"));
                continue;
            }
            email_id = id;
        }
        json_t *set_err = NULL;
        json_t *new_email = NULL;
        _email_update(req, email, email_id, &new_email, &set_err);
        if (set_err) {
            json_object_set_new(set.not_updated, email_id, set_err);
            continue;
        }
        json_object_set_new(set.updated, email_id, new_email);
    }

    size_t i;
    json_t *jid;
    json_array_foreach(set.destroy, i, jid) {
        json_t *set_err = NULL;
        const char *email_id = json_string_value(jid);
        if (*email_id == '#') {
            const char *id = hash_lookup(email_id + 1, &req->idmap->messages);
            if (!id) {
                json_object_set_new(set.not_updated, email_id, json_pack("{s:s}",
                            "type", "notFound"));
                continue;
            }
            email_id = id;
        }
        _email_destroy(req, email_id, &set_err);
        if (set_err) {
            json_object_set_new(set.not_destroyed, email_id, set_err);
            continue;
        }
        json_array_append_new(set.destroyed, json_string(email_id));
    }

    // TODO refactor jmap_getstate to return a string, once
    // all code has been migrated to the new JMAP parser.
    json_t *jstate = jmap_getstate(req, 0/*mbtype*/);
    set.new_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    jmap_ok(req, jmap_set_reply(&set));

done:
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    return 0;
}

struct _email_import_rock {
    struct buf buf;
    const struct body *part;
};

static int _email_import_cb(jmap_req_t *req __attribute__((unused)),
                            FILE *out, void *rock)
{
    struct _email_import_rock *data = (struct _email_import_rock*) rock;

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

int _email_import(jmap_req_t *req, json_t *msg, json_t **createdmsg)
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
    struct _email_import_rock content = { BUF_INITIALIZER, NULL };
    hash_table props = HASH_TABLE_INITIALIZER;
    struct body *bodystructure = NULL;
    struct mailbox *mbox = NULL;
    char *msgid = NULL;
    char *mboxname = NULL;
    uint32_t uid;
    time_t internaldate = 0;
    strarray_t keywords = STRARRAY_INITIALIZER;
    struct emailbodies bodies = EMAILBODIES_INITIALIZER;
    int has_attachment = 0;

    /* Lookup blob and check if it has any attachments */
    msgrecord_t *mr = NULL;
    const char *blobid = json_string_value(json_object_get(msg, "blobId"));
    r = jmap_findblob(req, blobid, &mbox, &mr, &bodystructure, &content.part);
    if (r) goto done;
    r = msgrecord_get_body(mr, &content.buf);
    if (r) goto done;
    r = _email_extract_bodies(bodystructure, &content.buf, &bodies);
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
    r = _email_append(req, mailboxids, &keywords, internaldate,
                      has_attachment, _email_import_cb, &content, &msgid);
    if (r) goto done;

    /* Load its index record and convert to JMAP */
    r = _email_find(req, msgid, &mboxname, &uid);
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

    r = _email_get_with_props(req, &props, mr, createdmsg);
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

static int jmap_email_import(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    json_t *created = json_pack("{}");
    json_t *not_created = json_pack("{}");

    json_t *emails = json_object_get(req->args, "emails");
    const char *id;
    json_t *eimp;

    /* Parse request */
    json_object_foreach(emails, id, eimp) {
        json_t *val;
        const char *s;

        jmap_parser_push(&parser, "emails");

        /* blobId */
        s = json_string_value(json_object_get(eimp, "blobId"));
        if (!s) {
            jmap_parser_invalid(&parser, "blobId");
        }

        /* keywords */
        json_t *keywords = json_object_get(eimp, "keywords");
        if (json_is_object(keywords)) {
            json_t *val;
            jmap_parser_push(&parser, "keywords");
            json_object_foreach(keywords, s, val) {
                if (val != json_true() || !_email_keyword_is_valid(s)) {
                    jmap_parser_invalid(&parser, s);
                }
            }
            jmap_parser_pop(&parser);
        }
        else if (JNOTNULL(keywords)) {
            jmap_parser_invalid(&parser, "keywords");
        }

        /* receivedAt */
        json_t *jrecv = json_object_get(eimp, "receivedAt");
        if (json_is_string(jrecv)) {
            struct tm date;
            s = strptime(json_string_value(jrecv), "%Y-%m-%dT%H:%M:%SZ", &date);
            if (!s || *s) {
                jmap_parser_invalid(&parser, "receivedAt");
            }
        }
        else if (JNOTNULL(jrecv)) {
            jmap_parser_invalid(&parser, "receivedAt");
        }

        json_t *mboxids = json_object_get(eimp, "mailboxIds");
        if (json_object_size(mboxids)) {
            jmap_parser_push(&parser, "mailboxIds");
            json_object_foreach(mboxids, s, val) {
                const char *mboxid = s;
                if (*mboxid == '#') {
                    mboxid = hash_lookup(mboxid + 1, &req->idmap->mailboxes);
                }
                char *mboxname = _mbox_find_uniqueid(req, mboxid);
                if (!mboxid || !mboxname || val != json_true()) {
                    jmap_parser_invalid(&parser, s);
                }
                free(mboxname);
            }
            jmap_parser_pop(&parser);
        }
        else {
            jmap_parser_invalid(&parser, "mailboxIds");
        }

        jmap_parser_pop(&parser); /* emails */
    }
    if (!json_is_object(emails)) {
        jmap_parser_invalid(&parser, "emails");
    }

    /* Bail out for argument errors */
    if (json_array_size(parser.invalid)) {
        jmap_error(req, json_pack("{s:s, s:O}",
                "type", "invalidArguments", "arguments", parser.invalid));
        goto done;
    }

    /* Process request */
    json_object_foreach(emails, id, eimp) {
        json_t *email;
        int r = _email_import(req, eimp, &email);
        if (r) {
            const char *errtyp = NULL;
            switch (r) {
                case IMAP_NOTFOUND:
                    errtyp = "attachmentNotFound";
                    break;
                case IMAP_PERMISSION_DENIED:
                    errtyp = "forbidden";
                    break;
                case IMAP_MAILBOX_EXISTS:
                    errtyp = "alreadyExists";
                    break;
                case IMAP_QUOTA_EXCEEDED:
                    errtyp = "maxQuotaReached";
                    break;
                case IMAP_MESSAGE_CONTAINSNULL:
                    errtyp = "emailContainsNulByte";
                    break;
                case IMAP_MESSAGE_CONTAINSNL:
                    errtyp = "emailContainsBareNewlines";
                    break;
                case IMAP_MESSAGE_CONTAINS8BIT:
                    errtyp = "emailContainsNonASCIIHeader";
                    break;
                case IMAP_MESSAGE_BADHEADER:
                    errtyp = "emailContainsInvalidHeader";
                    break;
                case IMAP_MESSAGE_NOBLANKLINE:
                    errtyp = "emailHasNoHeaderBodySeparator";
                    break;
                default:
                    errtyp = "serverError";
            }
            syslog(LOG_ERR, "jmap: Email/import(%s): %s", id, error_message(r));
            json_object_set_new(not_created,
                    id, json_pack("{s:s}", "type", errtyp));
            continue;
        }
        json_object_set_new(created, id, email);

        const char *newmsgid = json_string_value(json_object_get(email, "id"));
        hash_insert(id, xstrdup(newmsgid), &req->idmap->messages);
    }

    /* Reply */
    jmap_ok(req, json_pack("{s:s s:O s:O}",
                "accountId", req->accountid,
                "created", created,
                "notCreated", not_created));

done:
    jmap_parser_fini(&parser);
    json_decref(created);
    json_decref(not_created);
    return 0;
}

static int jmap_identity_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;

    /* Parse request */
    jmap_get_parse(req->args, &parser, NULL, &get, &err);
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
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

static int _emailsubmission_address_parse(json_t *addr, const char *prefix, json_t *invalid)
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
            /* TODO validate allowed esmtp characters */
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

static void _emailsubmission_envelope_to_smtp(smtp_envelope_t *smtpenv, json_t *env)
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

static int _emailsubmission_create(jmap_req_t *req, json_t *emailsubmission,
                          json_t *invalid, json_t **err)
{
    struct buf buf = BUF_INITIALIZER;

    /* messageId */
    const char *msgid = NULL;
    if (readprop(emailsubmission, "emailId", 1, invalid, "s", &msgid) > 0) {
        if (*msgid == '#') {
            const char *id = hash_lookup(msgid + 1, &req->idmap->messages);
            if (id) {
                msgid = id;
            } else {
                json_array_append_new(invalid, json_string("emailId"));
            }
        }
    }

    /* identityId */
    const char *identityid = NULL;
    if (readprop(emailsubmission, "identityId", 1, invalid, "s", &identityid) > 0) {
        if (strcmp(identityid, req->userid)) {
            json_array_append_new(invalid, json_string("identityId"));
        }
    }

    /* envelope */
    json_t *envelope = json_object_get(emailsubmission, "envelope");
    if (JNOTNULL(envelope)) {
        json_t *from = json_object_get(envelope, "mailFrom");
        if (json_object_size(from)) {
            _emailsubmission_address_parse(from, "envelope.mailFrom", invalid);
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
                _emailsubmission_address_parse(addr, buf_cstring(&buf), invalid);
                buf_reset(&buf);
            }
        }
        else {
            json_array_append_new(invalid, json_string("envelope.rcptTo"));
        }
    } else {
        envelope = NULL;
    }

    /* Reject read-only properties */
    if (json_object_get(emailsubmission, "id")) {
        json_array_append_new(invalid, json_string("id"));
    }
    if (json_object_get(emailsubmission, "threadId")) {
        json_array_append_new(invalid, json_string("threadId"));
    }
    if (json_object_get(emailsubmission, "sendAt")) {
        json_array_append_new(invalid, json_string("sendAt"));
    }
    if (json_object_get(emailsubmission, "undoStatus")) {
        json_array_append_new(invalid, json_string("undoStatus"));
    }
    if (json_object_get(emailsubmission, "deliveryStatus")) {
        json_array_append_new(invalid, json_string("deliveryStatus"));
    }
    if (json_object_get(emailsubmission, "dsnBlobIds")) {
        json_array_append_new(invalid, json_string("dsnBlobIds"));
    }
    if (json_object_get(emailsubmission, "mdnBlobIds")) {
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
    int fd_msg = -1;

    /* Lookup the message */
    r = _email_find(req, msgid, &mboxname, &uid);
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
        r = _email_get_with_props(req, &props, mr, &msg);
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
        /* TODO If the address found from this is not allowed by the identity
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

    /* Close the message record and mailbox. There's a race
     * with us still keeping the file descriptor to the
     * message open. But we don't want to long-lock the
     * mailbox while sending the mail over to a SMTP host */
    msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);

    /* Open the SMTP connection */
    smtpclient_t *sm = NULL;
    r = smtpclient_open(&sm);
    if (r) goto done;
    smtpclient_set_auth(sm, req->userid);

    /* Prepare envelope */
    smtp_envelope_t smtpenv = SMTP_ENVELOPE_INITIALIZER;
    _emailsubmission_envelope_to_smtp(&smtpenv, envelope);

    /* Send message */
    struct protstream *data = prot_new(fd_msg, /*write*/0);
    r = smtpclient_sendprot(sm, &smtpenv, data);
    smtp_envelope_fini(&smtpenv);
    prot_free(data);
    smtpclient_close(&sm);
    if (r) {
        syslog(LOG_ERR, "jmap: can't create message submission: %s",
                error_message(r));
        *err = json_pack("{s:s}", "type", "smtpProtocolError");
        goto done;
    }

    /* All done */
    char *emailsubmission_id = NULL;
    emailsubmission_id = xstrdup(makeuuid());
    json_object_set_new(emailsubmission, "id", json_string(emailsubmission_id));
    free(emailsubmission_id);

done:
    if (fd_msg != -1) close(fd_msg);
    if (msg) json_decref(msg);
    if (mr) msgrecord_unref(&mr);
    if (mbox) jmap_closembox(req, &mbox);
    if (myenvelope) json_decref(myenvelope);
    free(mboxname);
    buf_free(&buf);
    return r;
}

static int jmap_emailsubmission_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;

    jmap_get_parse(req->args, &parser, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    size_t i;
    json_t *val;
    json_array_foreach(get.ids, i, val) {
        json_array_append(get.not_found, val);
    }

    json_t *jstate = jmap_getstate(req, 0);
    get.state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

static int jmap_emailsubmission_set(jmap_req_t *req)
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
    if (state) json_incref(state);

    /* ifInState never fails for message submission random states */
    set = json_pack("{s:s}", "accountId", req->accountid);
    json_object_set_new(set, "oldState", state ? state : jmap_getstate(req, 0));

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
    if (json_is_array(onsuccess_destroy)) {
        size_t i;
        json_t *val;
        json_array_foreach(onsuccess_destroy, i, val) {
            if (!json_is_string(val)) {
                buf_printf(&buf, "onSuccessDestroyEmail[%zu]", i);
                json_array_append_new(invalid, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }
    } else if (JNOTNULL(onsuccess_destroy)) {
        json_array_append_new(invalid, json_string("onSuccessDestroyEmail"));
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
        json_t *emailsubmission;

        json_object_foreach(create, key, emailsubmission) {
            json_t *invalid = json_pack("[]");

            /* Create the message submission or return on error. Process
             * errors in order of: fatal errors, setErrors, property errors */
            json_t *err = NULL;
            r = _emailsubmission_create(req, emailsubmission, invalid, &err);
            if (err) {
                json_object_set_new(notCreated, key, err);
                json_decref(invalid);
                r = 0;
                continue;
            }
            else if (r) {
                json_decref(invalid);
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
            const char *id = json_string_value(json_object_get(emailsubmission, "id"));
            json_object_set_new(created, key, json_pack("{s:s}", "id", id));

            /* Build its creation id */
            buf_setcstr(&buf, "#");
            buf_appendcstr(&buf, key);
            buf_cstring(&buf);
            const char *msgid = json_string_value(json_object_get(emailsubmission, "emailId"));

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
                    json_array_append_new(destroy_msgs, json_string(msgid));
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
        json_t *emailsubmission;

        json_object_foreach(update, id, emailsubmission) {
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
        subreq.method = "Email/set";
        if (json_object_size(update_msgs)) {
            json_object_set(subreq.args, "update", update_msgs);
        }
        if (json_array_size(destroy_msgs)) {
            json_object_set(subreq.args, "destroy", destroy_msgs);
        }
        json_object_set_new(subreq.args, "accountId", json_string(req->accountid));
        r = jmap_email_set(&subreq);
        json_decref(subreq.args);
        if (r) goto done;
    }

done:
    if (set) json_decref(set);
    json_decref(update_msgs);
    json_decref(destroy_msgs);
    buf_free(&buf);
    if (r) {
        syslog(LOG_ERR, "jmap_emailsubmission_set: %s", error_message(r));
        r = HTTP_SERVER_ERROR;
    }
    return r;
}

static int jmap_emailsubmission_changes(jmap_req_t *req)
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
    json_object_set_new(res, "hasMoreChanges", json_false());
    json_object_set_new(res, "changed", json_null());
    json_object_set_new(res, "destroyed", json_null());

    json_t *item = json_pack("[]");
    json_array_append_new(item, json_string("EmailSubmission/changes"));
    json_array_append_new(item, res);
    json_array_append_new(item, json_string(req->tag));
    json_array_append_new(req->response, item);

done:
    return 0;
}

static void _emailsubmission_parse_filter(json_t *filter, struct jmap_parser *parser,
                                 json_t *unsupported __attribute__((unused)),
                                 void *rock __attribute__((unused)))
{
    json_t *arg;
    const char *s;

    if (!JNOTNULL(filter) || json_typeof(filter) != JSON_OBJECT) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    arg = json_object_get(filter, "before");
    if ((s = json_string_value(arg))) {
        struct tm tm;
        const char *p = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
        if (!p || *p) {
            jmap_parser_invalid(parser, "before");
        }
    } else if (arg) {
        jmap_parser_invalid(parser, "before");
    }
    arg = json_object_get(filter, "after");
    if ((s = json_string_value(arg))) {
        struct tm tm;
        const char *p = strptime(s, "%Y-%m-%dT%H:%M:%SZ", &tm);
        if (!p || *p) {
            jmap_parser_invalid(parser, "after");
        }
    } else if (arg) {
        jmap_parser_invalid(parser, "after");
    }

    arg = json_object_get(filter, "emailIds");
    if (json_is_array(arg)) {
        _parse_strings(arg, parser, "emailIds");
    } else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "emailIds");
    }

    arg = json_object_get(filter, "threadIds");
    if (json_is_array(arg)) {
        _parse_strings(arg, parser, "threadIds");
    } else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "threadIds");
    }

    arg = json_object_get(filter, "emailSubmissionIds");
    if (json_is_array(arg)) {
        _parse_strings(arg, parser, "emailSubmissionIds");
    } else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "emailSubmissionIds");
    }
}


static int _emailsubmission_parse_comparator(struct jmap_comparator *comp, void *rock __attribute__((unused)))
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

static int jmap_emailsubmission_query(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req->args, &parser,
            _emailsubmission_parse_filter, NULL,
            _emailsubmission_parse_comparator, NULL,
            &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* We don't store EmailSubmissions */
    json_t *jstate = jmap_getstate(req, 0);
    query.state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    query.position = 0;
    query.total = 0;
    query.can_calculate_changes = 0;
    jmap_ok(req, jmap_query_reply(&query));

done:
    jmap_parser_fini(&parser);
    jmap_query_fini(&query);
    return 0;
}

static int jmap_emailsubmission_querychanges(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_querychanges query;

    /* Parse arguments */
    json_t *err = NULL;
    jmap_querychanges_parse(req->args, &parser,
            _emailsubmission_parse_filter, NULL,
            _emailsubmission_parse_comparator, NULL,
            &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Refuse all attempts to calculcate list updates */
    jmap_error(req, json_pack("{s:s}", "type", "cannotCalculateChanges"));

done:
    jmap_querychanges_fini(&query);
    jmap_parser_fini(&parser);
    return 0;

}
