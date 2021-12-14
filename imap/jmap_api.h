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

#include "acl.h"
#include "auth.h"
#include "conversations.h"
#include "dav_db.h"
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
#define JMAP_URN_MDN        "urn:ietf:params:jmap:mdn"
#define JMAP_URN_CALENDARS  "urn:ietf:params:jmap:calendars"
#define JMAP_URN_PRINCIPALS "urn:ietf:params:jmap:principals"
#define JMAP_URN_CALENDAR_PREFERENCES "urn:ietf:params:jmap:calendars:preferences"

#define JMAP_BLOB_EXTENSION          "https://cyrusimap.org/ns/jmap/blob"
#define JMAP_CONTACTS_EXTENSION      "https://cyrusimap.org/ns/jmap/contacts"
#define JMAP_CALENDARS_EXTENSION     "https://cyrusimap.org/ns/jmap/calendars"
#define JMAP_MAIL_EXTENSION          "https://cyrusimap.org/ns/jmap/mail"
#define JMAP_PERFORMANCE_EXTENSION   "https://cyrusimap.org/ns/jmap/performance"
#define JMAP_DEBUG_EXTENSION         "https://cyrusimap.org/ns/jmap/debug"
#define JMAP_QUOTA_EXTENSION         "https://cyrusimap.org/ns/jmap/quota"
#define JMAP_BACKUP_EXTENSION        "https://cyrusimap.org/ns/jmap/backup"
#define JMAP_NOTES_EXTENSION         "https://cyrusimap.org/ns/jmap/notes"
#define JMAP_SIEVE_EXTENSION         "https://cyrusimap.org/ns/jmap/sieve"
#define JMAP_FILES_EXTENSION         "https://cyrusimap.org/ns/jmap/files"
#define JMAP_USERCOUNTERS_EXTENSION  "https://cyrusimap.org/ns/jmap/usercounters"

enum {
    MAX_SIZE_REQUEST = 0,
    MAX_CALLS_IN_REQUEST,
    MAX_CONCURRENT_REQUESTS,
    MAX_OBJECTS_IN_GET,
    MAX_OBJECTS_IN_SET,
    MAX_SIZE_UPLOAD,
    MAX_CONCURRENT_UPLOAD,
    MAX_SIZE_BLOB_SET,
    MAX_CATENATE_ITEMS,
    JMAP_NUM_LIMITS  /* MUST be last */
};

/* JMAP Mail (RFC 8621) privileges */
#define JACL_READITEMS      (ACL_READ|ACL_LOOKUP)
#define JACL_ADDITEMS       ACL_INSERT
#define JACL_REMOVEITEMS    (ACL_DELETEMSG|ACL_EXPUNGE)
#define JACL_SETSEEN        ACL_SETSEEN
#define JACL_SETKEYWORDS    ACL_WRITE
#define JACL_CREATECHILD    ACL_CREATE
#define JACL_DELETE         ACL_DELETEMBOX
#define JACL_RENAME         (JACL_CREATECHILD|JACL_DELETE)
#define JACL_SUBMIT         ACL_POST

/* JMAP Calendar (draft-ietf-jmap-calendars) privileges */
#define JACL_READFB         ACL_USER9      /* Keep sync'd with DACL_READFB */
#define JACL_RSVP           ACL_USER7      /* Keep sync'd with DACL_REPLY */
#define JACL_WRITEOWN       ACL_USER6
#define JACL_UPDATEPRIVATE  ACL_USER5
#define JACL_WRITEALL       (JACL_ADDITEMS|JACL_UPDATEITEMS|JACL_SETSEEN|JACL_SETMETADATA|JACL_REMOVEITEMS)

/* Cyrus-specific privileges */
#define JACL_LOOKUP         ACL_LOOKUP
#define JACL_ADMIN_MAILBOX   (ACL_ADMIN|JACL_DELETE|JACL_CREATECHILD)
#define JACL_ADMIN_CALENDAR ACL_ADMIN
#define JACL_SETPROPERTIES  ACL_ANNOTATEMSG
#define JACL_UPDATEITEMS    (JACL_ADDITEMS|JACL_REMOVEITEMS)
#define JACL_SETMETADATA    (JACL_SETKEYWORDS|JACL_SETPROPERTIES)
#define JACL_WRITE          (JACL_UPDATEITEMS|JACL_SETSEEN|JACL_SETMETADATA)
#define JACL_ALL            (JACL_READITEMS|JACL_WRITE|JACL_RENAME|JACL_SUBMIT\
                             |ACL_ADMIN|JACL_DELETE|JACL_CREATECHILD|JACL_READFB|JACL_RSVP)


typedef struct {
    hash_table methods;
    json_t *server_capabilities;
    long limits[JMAP_NUM_LIMITS];
    // internal state
    ptrarray_t getblob_handlers; // array of jmap_getblob_handler
    ptrarray_t event_handlers; // array of (malloced) jmap_handlers
} jmap_settings_t;

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
    jmap_settings_t      *settings;

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
    hash_table *mbstates;
    hash_table *created_ids;
    hash_table *inmemory_blobs;
    hash_table *mbentry_byid;
    ptrarray_t *method_calls;
    const strarray_t *using_capabilities;
} jmap_req_t;

/* Fetch the contents of the blob identified by blobid,
 * optionally returning a content type and an error string.
 *
 * If not NULL, accept_mime defines the requested MIME type,
 * either defined in the Accept header or {type} URI template
 * parameter.
 *
 * Return HTTP_OK if the blob has been found or any other
 * HTTP status on error.
 * Return zero if the next blob handler should be called.
 */
typedef struct {
    const char *from_accountid;  // input to the handler
    const char *blobid;          // input to the handler
    const char *accept_mime;     // input to the handler
    unsigned decode : 1;         // input to the handler
    struct buf blob;             // output from the handler
    struct buf content_type;     // output from the handler
    struct buf encoding;         // output from the handler
    const char *errstr;          // output from the handler
} jmap_getblob_context_t;

void jmap_getblob_ctx_init(jmap_getblob_context_t *ctx,
                           const char *from_accountid, const char *blobid,
                           const char *accept_mime, unsigned decode);
void jmap_getblob_ctx_reset(jmap_getblob_context_t *ctx);
void jmap_getblob_ctx_fini(jmap_getblob_context_t *ctx);

typedef int jmap_getblob_handler(jmap_req_t *req, jmap_getblob_context_t *ctx);

enum jmap_handler_event {
    JMAP_HANDLE_SHUTDOWN      = (1 << 0), /* executed when httpd is shutdown. req is NULL */
    JMAP_HANDLE_CLOSE_CONN    = (1 << 1), /* executed when connection is closed. req is NULL */
    JMAP_HANDLE_BEFORE_METHOD = (1 << 2)  /* executed before each method call. req is set */
};

struct jmap_handler {
    int eventmask;
    void(*handler)(enum jmap_handler_event event, jmap_req_t* req, void *rock);
    void *rock;
};

enum jmap_method_flags {
    JMAP_READ_WRITE  = (1 << 0),  /* user can change state with this method */
    JMAP_NEED_CSTATE = (1 << 1),  /* conv.db is required for this method
                                     (lock type determined by r/w flag) */
};

typedef struct {
    const char *name;
    const char *capability;
    int (*proc)(struct jmap_req *req);
    enum jmap_method_flags flags;
} jmap_method_t;

extern int jmap_error_response(struct transaction_t *txn,
                               long code, json_t **res);
extern int jmap_api(struct transaction_t *txn,
                    const json_t *jreq, json_t **res,
                    jmap_settings_t *settings);

extern int jmap_initreq(jmap_req_t *req);
extern void jmap_finireq(jmap_req_t *req);

extern int jmap_is_using(jmap_req_t *req, const char *capa);

/* Protocol implementations */
extern void jmap_core_init(jmap_settings_t *settings);
extern void jmap_mail_init(jmap_settings_t *settings);
extern void jmap_mdn_init(jmap_settings_t *settings);
extern void jmap_contact_init(jmap_settings_t *settings);
extern void jmap_calendar_init(jmap_settings_t *settings);
extern void jmap_vacation_init(jmap_settings_t *settings);
extern void jmap_backup_init(jmap_settings_t *settings);
extern void jmap_notes_init(jmap_settings_t *settings);
extern void jmap_files_init(jmap_settings_t *settings);
extern void jmap_sieve_init(jmap_settings_t *settings);

extern void jmap_core_capabilities(json_t *account_capabilities);
extern void jmap_mail_capabilities(json_t *account_capabilities, int mayCreateTopLevel);
extern void jmap_emailsubmission_capabilities(json_t *account_capabilities);
extern void jmap_mdn_capabilities(json_t *account_capabilities);
extern void jmap_vacation_capabilities(json_t *account_capabilities);
extern void jmap_contact_capabilities(json_t *account_capabilities);
extern void jmap_calendar_capabilities(json_t *account_capabilities,
                                       struct auth_state *authstate,
                                       const char *authuserid,
                                       const char *accountid);
extern void jmap_vacation_capabilities(json_t *account_capabilities);
extern void jmap_backup_capabilities(json_t *account_capabilities);
extern void jmap_notes_capabilities(json_t *account_capabilities);
extern void jmap_files_capabilities(json_t *account_capabilities);
extern void jmap_sieve_capabilities(json_t *account_capabilities);

extern void jmap_accounts(json_t *accounts, json_t *primary_accounts);

/* Request-scoped mailbox cache */
extern int  jmap_openmbox(jmap_req_t *req, const char *name,
                          struct mailbox **mboxp, int rw);
extern int jmap_openmbox_by_uniqueid(jmap_req_t *req, const char *id,
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

extern int  jmap_myrights_mbentry(jmap_req_t *req, const mbentry_t *mbentry);
extern int  jmap_hasrights_mbentry(jmap_req_t *req, const mbentry_t *mbentry,
                           int rights);
extern int  jmap_myrights(jmap_req_t *req, const char *mboxname);
extern int  jmap_hasrights(jmap_req_t *req, const char *mboxname, int rights);
extern int  jmap_myrights_mboxid(jmap_req_t *req, const char *mboxid);
extern int  jmap_hasrights_mboxid(jmap_req_t *req, const char *mboxid, int rights);
extern void jmap_myrights_delete(jmap_req_t *req, const char *mboxname);
extern int  jmap_mbtype(jmap_req_t *req, const char *mboxname);

/* Blob services */
extern int jmap_findblob(jmap_req_t *req, const char *accountid,
                         const char *blobid,
                         struct mailbox **mbox, msgrecord_t **mr,
                         struct body **body, const struct body **part,
                         struct buf *blob);
extern int jmap_findblob_exact(jmap_req_t *req, const char *accountid,
                               const char *blobid,
                               struct mailbox **mbox, msgrecord_t **mr,
                               struct buf *blob);

/* JMAP states */
extern json_t* jmap_getstate(jmap_req_t *req, int mbtype, int refresh);
extern json_t *jmap_fmtstate(modseq_t modseq);
extern int jmap_cmpstate(jmap_req_t *req, json_t *state, int mbtype);
extern modseq_t jmap_highestmodseq(jmap_req_t *req, int mbtype);

/* Helpers for DAV-based JMAP types */
extern char *jmap_xhref(const char *mboxname, const char *resource);

/* Patch-object support */

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
                               modseq_t minmodseq,
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
    int sort_savedate;

    /* Response fields */
    char *query_state;
    int can_calculate_changes;
    size_t result_position;
    size_t server_limit;
    size_t total;
    int have_total; /* for calculateTotal: false partial */
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


/* Foo/parse */

struct jmap_parse {
    /* Request arguments */
    const json_t *blob_ids;

    /* Response fields */
    json_t *parsed;
    json_t *not_parsable;
    json_t *not_found;
};

extern void jmap_parse_parse(jmap_req_t *req, struct jmap_parser *parser,
                                 jmap_args_parse_cb args_parse, void *args_rock,
                                 struct jmap_parse *parse,
                                 json_t **err);

extern void jmap_parse_fini(struct jmap_parse *parse);

extern json_t *jmap_parse_reply(struct jmap_parse *parse);


extern json_t *jmap_get_sharewith(const mbentry_t *mbentry, json_t*(*tojmap)(int rights));
extern int jmap_set_sharewith(struct mailbox *mbox,
                              json_t *shareWith, int overwrite,
                              int (*patchrights)(int, json_t*));
extern void jmap_parse_sharewith_patch(json_t *arg, json_t **shareWith);

extern void jmap_mbentry_cache_free(jmap_req_t *req);
extern const mbentry_t *jmap_mbentry_by_uniqueid(jmap_req_t *req, const char *id);
extern mbentry_t *jmap_mbentry_by_uniqueid_copy(jmap_req_t *req, const char *id);
extern mbentry_t *jmap_mbentry_from_dav(jmap_req_t *req, struct dav_data *dav);

#endif /* JMAP_API_H */
