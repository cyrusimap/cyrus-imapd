/* http_jmap.h -- Routines for handling JMAP requests in httpd
 *
 * Copyright (c) 1994-2016 Carnegie Mellon University.  All rights reserved.
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

#ifndef HTTP_JMAP_H
#define HTTP_JMAP_H

#include "auth.h"
#include "conversations.h"
#include "httpd.h"
#include "json_support.h"
#include "mailbox.h"
#include "mboxname.h"
#include "msgrecord.h"

#define JMAP_URN_CORE       "urn:ietf:params:jmap:core"
#define JMAP_URN_MAIL       "urn:ietf:params:jmap:mail"
#define JMAP_URN_SUBMISSION "urn:ietf:params:jmap:submission"
#define JMAP_URN_VACATION   "urn:ietf:params:jmap:vacationresponse"
#define JMAP_URN_CONTACTS   "urn:ietf:params:jmap:contacts"
#define JMAP_URN_CALENDARS  "urn:ietf:params:jmap:calendars"
#define JMAP_URN_WEBSOCKET  "urn:ietf:params:jmap:websocket"

#define _wantprop(props, name) ((props) ? (hash_lookup(name, props) != NULL) : 1)

extern struct namespace jmap_namespace;

typedef struct jmap_req {
    const char           *method;
    const char           *userid;
    const char           *accountid;
    const char           *inboxname;
    struct conversations_state *cstate;
    struct auth_state    *authstate;
    json_t               *args;
    json_t               *response;
    const char           *tag;
    struct transaction_t *txn;
    struct mboxname_counters counters;

    int do_perf;
    double real_start;
    double user_start;
    double sys_start;

    /* The JMAP request keeps its own cache of opened mailboxes,
     * which can be used by calling jmap_openmbox. If the
     * force_openmboxrw is set, this causes all following
     * mailboxes to be opened read-writeable, irrespective if
     * the caller asked for a read-only lock. This allows to
     * prevent lock promotion conflicts, in case a cached mailbox
     * was opened read-only by a helper but it now asked to be
     * locked exclusively. Since the mailbox lock does not
     * support lock promition, this would currently abort with
     * an error. */
    int force_openmbox_rw;

    /* Owned by JMAP HTTP handler */
    ptrarray_t *mboxes;
    hash_table *mboxrights;
    hash_table *client_creation_ids;
    hash_table *new_creation_ids;
} jmap_req_t;

typedef struct {
    const char *name;
    int (*proc)(struct jmap_req *req);
} jmap_method_t;

/* Protocol implementations */
extern int jmap_mail_init(hash_table *methods, json_t *capabilities);
extern int jmap_contact_init(hash_table *methods, json_t *capabilities);
extern int jmap_calendar_init(hash_table *methods, json_t *capabilities);

/* Request-scoped mailbox cache */
extern int  jmap_openmbox(jmap_req_t *req, const char *name,
                          struct mailbox **mboxp, int rw);
extern int  jmap_isopenmbox(jmap_req_t *req, const char *name);
extern void jmap_closembox(jmap_req_t *req, struct mailbox **mboxp);

/* Creation ids */
extern const char *jmap_lookup_id(jmap_req_t *req, const char *creation_id);
extern void jmap_add_id(jmap_req_t *req, const char *creation_id, const char *id);
extern int jmap_is_valid_id(const char *id);

/* usermbox-like mailbox tree traversal, scoped by accountid.
 * Reports only active (not deleted) mailboxes. Checks presence
 * of ACL_LOOKUP for shared accounts. */
extern int  jmap_mboxlist(jmap_req_t *req, mboxlist_cb *proc, void *rock);

/* Request-scoped cache of mailbox rights for authenticated user */

extern int  jmap_myrights(jmap_req_t *req, const mbentry_t *mbentry);
extern int  jmap_hasrights(jmap_req_t *req, const mbentry_t *mbentry,
                           int rights);
extern int  jmap_myrights_byname(jmap_req_t *req, const char *mboxname);
extern int  jmap_hasrights_byname(jmap_req_t *req, const char *mboxname,
                                  int rights);
extern void jmap_myrights_delete(jmap_req_t *req, const char *mboxname);

/* Blob services */
extern int jmap_upload(struct transaction_t *txn);
extern int jmap_download(struct transaction_t *txn);
extern int jmap_findblob(jmap_req_t *req, const char *blobid,
                         struct mailbox **mbox, msgrecord_t **mr,
                         struct body **body, const struct body **part,
                         struct buf *blob);
extern const struct body *jmap_contact_findblob(struct message_guid *content_guid,
                                                const char *part_id,
                                                struct mailbox *mbox,
                                                msgrecord_t *mr,
                                                struct buf *blob);
extern void jmap_set_blobid(const struct message_guid *guid, char *buf);

/* JMAP states */
extern json_t* jmap_getstate(jmap_req_t *req, int mbtype, int refresh);
extern json_t *jmap_fmtstate(modseq_t modseq);
extern int jmap_cmpstate(jmap_req_t *req, json_t *state, int mbtype);
extern modseq_t jmap_highestmodseq(jmap_req_t *req, int mbtype);

/* Helpers for DAV-based JMAP types */
extern char *jmap_xhref(const char *mboxname, const char *resource);

/* Patch-object support */

/* Apply patch to a deep copy of val and return the result. */
extern json_t* jmap_patchobject_apply(json_t *val, json_t *patch);

/* Create a patch-object that transforms a to b. */
extern json_t *jmap_patchobject_create(json_t *a, json_t *b);

/* Add performance stats to method response */
extern void jmap_add_perf(jmap_req_t *req, json_t *res);


/* JMAP request parser */
struct jmap_parser {
    struct buf buf;
    strarray_t path;
    json_t *invalid;
};

#define JMAP_PARSER_INITIALIZER { BUF_INITIALIZER, STRARRAY_INITIALIZER, json_array() }

extern void jmap_parser_fini(struct jmap_parser *parser);
extern void jmap_parser_push(struct jmap_parser *parser, const char *prop);
extern void jmap_parser_push_index(struct jmap_parser *parser,
                                   const char *prop, size_t index, const char *name);
extern void jmap_parser_pop(struct jmap_parser *parser);
extern const char* jmap_parser_path(struct jmap_parser *parser, struct buf *buf);
extern void jmap_parser_invalid(struct jmap_parser *parser, const char *prop);

extern void jmap_ok(jmap_req_t *req, json_t *res);
extern void jmap_error(jmap_req_t *req, json_t *err);

extern json_t *jmap_server_error(int r);

extern int jmap_parse_strings(json_t *arg,
                              struct jmap_parser *parser, const char *prop);

typedef struct jmap_property {
    const char *name;
    unsigned flags;
} jmap_property_t;

enum {
    JMAP_PROP_SERVER_SET = (1<<0),
    JMAP_PROP_IMMUTABLE  = (1<<1)
};

extern const jmap_property_t *jmap_property_find(const char *name,
                                                 const jmap_property_t props[]);


/* Foo/get */

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

extern void jmap_get_parse(json_t *jargs, struct jmap_parser *parser,
                           jmap_req_t *req, const jmap_property_t valid_props[],
                           int (*args_parse)(const char *, json_t *,
                                             struct jmap_parser *, void *),
                           void *args_rock,
                           struct jmap_get *get, json_t **err);
                           
extern void jmap_get_fini(struct jmap_get *get);
extern json_t *jmap_get_reply(struct jmap_get *get);


/* Foo/set */

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

extern void jmap_set_parse(json_t *jargs, struct jmap_parser *parser,
                           int (*args_parse)(const char *, json_t *,
                                             struct jmap_parser *, void *),
                           void *args_rock,
                           struct jmap_set *set, json_t **err);
extern void jmap_set_fini(struct jmap_set *set);
extern json_t *jmap_set_reply(struct jmap_set *set);


/* Foo/changes */

struct jmap_changes {
    /* Request arguments */
    modseq_t since_modseq;
    size_t max_changes;

    /* Response fields */
    modseq_t new_modseq;
    short has_more_changes;
    json_t *created;
    json_t *updated;
    json_t *destroyed;
};

extern void jmap_changes_parse(json_t *jargs, struct jmap_parser *parser,
                               struct jmap_changes *changes, json_t **err);
extern void jmap_changes_fini(struct jmap_changes *changes);
extern json_t *jmap_changes_reply(struct jmap_changes *changes);


/* Foo/query */

struct jmap_query {
    /* Request arguments */
    json_t *filter;
    json_t *sort;
    ssize_t position;
    const char *anchor;
    ssize_t anchor_offset;
    size_t limit;
    int have_limit;
    int calculate_total;

    /* Response fields */
    char *query_state;
    int can_calculate_changes;
    size_t result_position;
    size_t total;
    json_t *ids;
};

typedef void jmap_filter_parse_cb(json_t *filter, struct jmap_parser *parser,
                                  json_t *unsupported, void *rock);

extern void jmap_filter_parse(json_t *filter, struct jmap_parser *parser,
                              jmap_filter_parse_cb parse_condition,
                              json_t *unsupported, void *rock);

struct jmap_comparator {
    const char *property;
    short is_ascending;
    const char *collation;
};

typedef int jmap_comparator_parse_cb(struct jmap_comparator *comp, void *rock);

extern void jmap_parse_comparator(json_t *jsort, struct jmap_parser *parser,
                                  jmap_comparator_parse_cb comp_cb,
                                  json_t *unsupported, void *rock);

extern void jmap_query_parse(json_t *jargs, struct jmap_parser *parser,
                             jmap_filter_parse_cb filter_cb, void *filter_rock,
                             jmap_comparator_parse_cb comp_cb, void *sort_rock,
                             int (*args_parse)(const char *, json_t *,
                                               struct jmap_parser *, void *),
                             void *args_rock,
                             struct jmap_query *query, json_t **err);

extern void jmap_query_fini(struct jmap_query *query);

extern json_t *jmap_query_reply(struct jmap_query *query);

#endif /* HTTP_JMAP_H */
