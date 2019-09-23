/* http_api.h -- Routines for handling JMAP API requests
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

#ifndef JMAP_API_H
#define JMAP_API_H

#include "auth.h"
#include "conversations.h"
#include "hash.h"
#include "jmap_util.h"
#include "json_support.h"
#include "mailbox.h"
#include "mboxname.h"
#include "msgrecord.h"
#include "ptrarray.h"
#include "strarray.h"

#define JMAP_URN_CORE       "urn:ietf:params:jmap:core"
#define JMAP_URN_MAIL       "urn:ietf:params:jmap:mail"
#define JMAP_URN_SUBMISSION "urn:ietf:params:jmap:submission"
#define JMAP_URN_VACATION   "urn:ietf:params:jmap:vacationresponse"
#define JMAP_URN_WEBSOCKET  "urn:ietf:params:jmap:websocket"

#define JMAP_CONTACTS_EXTENSION      "https://cyrusimap.org/ns/jmap/contacts"
#define JMAP_CALENDARS_EXTENSION     "https://cyrusimap.org/ns/jmap/calendars"
#define JMAP_MAIL_EXTENSION          "https://cyrusimap.org/ns/jmap/mail"
#define JMAP_PERFORMANCE_EXTENSION   "https://cyrusimap.org/ns/jmap/performance"
#define JMAP_DEBUG_EXTENSION         "https://cyrusimap.org/ns/jmap/debug"
#define JMAP_QUOTA_EXTENSION         "https://cyrusimap.org/ns/jmap/quota"
#define JMAP_SEARCH_EXTENSION        "https://cyrusimap.org/ns/jmap/search"

enum {
    MAX_SIZE_REQUEST = 0,
    MAX_CALLS_IN_REQUEST,
    MAX_CONCURRENT_REQUESTS,
    MAX_OBJECTS_IN_GET,
    MAX_OBJECTS_IN_SET,
    MAX_SIZE_UPLOAD,
    MAX_CONCURRENT_UPLOAD,
    JMAP_NUM_LIMITS  /* MUST be last */
};

typedef struct jmap_req {
    const char           *method;
    const char           *userid;
    const char           *accountid;
    struct conversations_state *cstate;
    struct auth_state    *authstate;
    json_t               *args;
    json_t               *response;
    const char           *tag;
    struct transaction_t *txn;
    struct mboxname_counters counters;

    double real_start;
    double user_start;
    double sys_start;
    json_t *perf_details;

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

    /* Internal state */
    ptrarray_t *mboxes;
    hash_table *mboxrights;
    hash_table *created_ids;
    ptrarray_t *method_calls;
    const strarray_t *using_capabilities;
} jmap_req_t;

typedef struct {
    hash_table methods;
    json_t *server_capabilities;
    long limits[JMAP_NUM_LIMITS];
} jmap_settings_t;

typedef struct {
    const char *name;
    const char *capability;
    int (*proc)(struct jmap_req *req);
    int flags;
} jmap_method_t;

extern int jmap_api(struct transaction_t *txn, json_t **res,
                    jmap_settings_t *settings);

extern int jmap_initreq(jmap_req_t *req);
extern void jmap_finireq(jmap_req_t *req);

extern int jmap_is_using(jmap_req_t *req, const char *capa);

#define JMAP_SHARED_CSTATE 1 << 0

/* Protocol implementations */
extern void jmap_core_init(jmap_settings_t *settings);
extern void jmap_mail_init(jmap_settings_t *settings);
extern void jmap_contact_init(jmap_settings_t *settings);
extern void jmap_calendar_init(jmap_settings_t *settings);
extern void jmap_vacation_init(jmap_settings_t *settings);

extern void jmap_core_capabilities(json_t *account_capabilities);
extern void jmap_mail_capabilities(json_t *account_capabilities);
extern void jmap_emailsubmission_capabilities(json_t *account_capabilities);
extern void jmap_vacation_capabilities(json_t *account_capabilities);
extern void jmap_contact_capabilities(json_t *account_capabilities);
extern void jmap_calendar_capabilities(json_t *account_capabilities);
extern void jmap_vacation_capabilities(json_t *account_capabilities);

extern void jmap_accounts(json_t *accounts, json_t *primary_accounts);

/* Request-scoped mailbox cache */
extern int  jmap_openmbox(jmap_req_t *req, const char *name,
                          struct mailbox **mboxp, int rw);
extern int  jmap_isopenmbox(jmap_req_t *req, const char *name);
extern void jmap_closembox(jmap_req_t *req, struct mailbox **mboxp);

extern int jmap_mboxlist_lookup(const char *name,
                                mbentry_t **entryptr, struct txn **tid);

/* Adds a JMAP sub request to be processed after req has
 * finished. Method must be a regular JMAP method name,
 * args the JSON-encoded method arguments. If client_id
 * is NULL, the subrequest will use the same client id
 * as req. The args argument will be unreferenced after
 * completion. */
extern void jmap_add_subreq(jmap_req_t *req, const char *method,
                            json_t *args, const char *client_id);

/* Creation ids */
extern const char *jmap_lookup_id(jmap_req_t *req, const char *creation_id);
extern const char *jmap_id_string_value(jmap_req_t *req, json_t *item);
extern void jmap_add_id(jmap_req_t *req, const char *creation_id, const char *id);
extern int jmap_is_valid_id(const char *id);

/* Request-scoped cache of mailbox rights for authenticated user */

extern int  jmap_myrights(jmap_req_t *req, const mbentry_t *mbentry);
extern int  jmap_hasrights(jmap_req_t *req, const mbentry_t *mbentry,
                           int rights);
extern int  jmap_myrights_byname(jmap_req_t *req, const char *mboxname);
extern int  jmap_hasrights_byname(jmap_req_t *req, const char *mboxname,
                                  int rights);
extern void jmap_myrights_delete(jmap_req_t *req, const char *mboxname);

/* Blob services */
extern int jmap_findblob(jmap_req_t *req, const char *accountid,
                         const char *blobid,
                         struct mailbox **mbox, msgrecord_t **mr,
                         struct body **body, const struct body **part,
                         struct buf *blob);
extern int jmap_findblob_exact(jmap_req_t *req, const char *accountid,
                               const char *blobid,
                               struct mailbox **mbox, msgrecord_t **mr);

extern const struct body *jmap_contact_findblob(struct message_guid *content_guid,
                                                const char *part_id,
                                                struct mailbox *mbox,
                                                msgrecord_t *mr,
                                                struct buf *blob);

#define JMAP_BLOBID_SIZE 42
extern void jmap_set_blobid(const struct message_guid *guid, char *buf);

#define JMAP_EMAILID_SIZE 26
extern void jmap_set_emailid(const struct message_guid *guid, char *buf);

#define JMAP_THREADID_SIZE 18
extern void jmap_set_threadid(conversation_id_t cid, char *buf);

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


extern void jmap_ok(jmap_req_t *req, json_t *res);
extern void jmap_error(jmap_req_t *req, json_t *err);

extern int jmap_parse_strings(json_t *arg,
                              struct jmap_parser *parser, const char *prop);

typedef struct jmap_property {
    const char *name;
    const char *capability;
    unsigned flags;
} jmap_property_t;

enum {
    JMAP_PROP_SERVER_SET = (1<<0),
    JMAP_PROP_IMMUTABLE  = (1<<1),
    JMAP_PROP_SKIP_GET   = (1<<2), // skip in Foo/get if not requested by client
    JMAP_PROP_ALWAYS_GET = (1<<3)  // always include in Foo/get
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

typedef int jmap_args_parse_cb(jmap_req_t *, struct jmap_parser *,
                               const char *arg, json_t *val, void *);

extern void jmap_get_parse(jmap_req_t *req, struct jmap_parser *parser,
                           const jmap_property_t valid_props[],
                           int allow_null_ids,
                           jmap_args_parse_cb args_parse, void *args_rock,
                           struct jmap_get *get,
                           json_t **err);

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

extern void jmap_set_parse(jmap_req_t *req, struct jmap_parser *parser,
                           const jmap_property_t valid_props[],
                           jmap_args_parse_cb args_parse, void *args_rock,
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

extern void jmap_changes_parse(jmap_req_t *req, struct jmap_parser *parser,
                               jmap_args_parse_cb args_parse, void *args_rock,
                               struct jmap_changes *changes, json_t **err);
extern void jmap_changes_fini(struct jmap_changes *changes);
extern json_t *jmap_changes_reply(struct jmap_changes *changes);


/* Foo/copy */

struct jmap_copy {
    /* Request arguments */
    const char *from_account_id;
    json_t *create;
    int blob_copy;
    int on_success_destroy_original;

    /* Response fields */
    json_t *created;
    json_t *not_created;
};

extern void jmap_copy_parse(jmap_req_t *req, struct jmap_parser *parser,
                            jmap_args_parse_cb args_parse, void *args_rock,
                            struct jmap_copy *copy, json_t **err);
extern void jmap_copy_fini(struct jmap_copy *copy);
extern json_t *jmap_copy_reply(struct jmap_copy *copy);


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

enum jmap_filter_op   {
    JMAP_FILTER_OP_NONE = 0,
    JMAP_FILTER_OP_AND,
    JMAP_FILTER_OP_OR,
    JMAP_FILTER_OP_NOT
};

typedef struct jmap_filter {
    enum jmap_filter_op op;
    ptrarray_t conditions;
} jmap_filter;

typedef void* jmap_buildfilter_cb(json_t* arg);
typedef int   jmap_filtermatch_cb(void* cond, void* rock);
typedef void  jmap_filterfree_cb(void* cond);

extern jmap_filter *jmap_buildfilter(json_t *arg, jmap_buildfilter_cb *parse);
extern int jmap_filter_match(jmap_filter *f,
                             jmap_filtermatch_cb *match, void *rock);
extern void jmap_filter_free(jmap_filter *f, jmap_filterfree_cb *freecond);

typedef void jmap_filter_parse_cb(jmap_req_t *req, struct jmap_parser *parser,
                                  json_t *filter, json_t *unsupported,
                                  void *rock, json_t **err);

extern void jmap_filter_parse(jmap_req_t *req, struct jmap_parser *parser,
                              json_t *filter, json_t *unsupported,
                              jmap_filter_parse_cb parse_condition, void *cond_rock,
                              json_t **err /* fatal, non-parsing error */);

struct jmap_comparator {
    const char *property;
    short is_ascending;
    const char *collation;
};

typedef int jmap_comparator_parse_cb(jmap_req_t *req, struct jmap_comparator *comp,
                                     void *rock, json_t **err);

extern void jmap_comparator_parse(jmap_req_t *req, struct jmap_parser *parser,
                                  json_t *jsort, json_t *unsupported,
                                  jmap_comparator_parse_cb comp_cb, void *comp_rock,
                                  json_t **err);

extern void jmap_query_parse(jmap_req_t *req, struct jmap_parser *parser,
                             jmap_args_parse_cb args_parse, void *args_rock,
                             jmap_filter_parse_cb filter_cb, void *filter_rock,
                             jmap_comparator_parse_cb comp_cb, void *comp_rock,
                             struct jmap_query *query, json_t **err);

extern void jmap_query_fini(struct jmap_query *query);

extern json_t *jmap_query_reply(struct jmap_query *query);


/* Foo/queryChanges */

struct jmap_querychanges {
    /* Request arguments */
    json_t *filter;
    json_t *sort;
    const char *since_querystate;
    size_t max_changes;
    const char *up_to_id;
    int calculate_total;

    /* Response fields */
    char *new_querystate;
    size_t total;
    json_t *removed;
    json_t *added;
};

extern void jmap_querychanges_parse(jmap_req_t *req,
                                    struct jmap_parser *parser,
                                    jmap_args_parse_cb args_parse, void *args_rock,
                                    jmap_filter_parse_cb filter_cb, void *filter_rock,
                                    jmap_comparator_parse_cb comp_cb, void *sort_rock,
                                    struct jmap_querychanges *query,
                                    json_t **err);

extern void jmap_querychanges_fini(struct jmap_querychanges *query);

extern json_t *jmap_querychanges_reply(struct jmap_querychanges *query);

extern json_t *jmap_get_sharewith(const mbentry_t *mbentry);
extern int jmap_set_sharewith(struct mailbox *mbox,
                              json_t *shareWith, int overwrite);
extern void jmap_parse_sharewith_patch(json_t *arg, json_t **shareWith);

#endif /* JMAP_API_H */
