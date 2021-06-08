/* http_dav.h -- Routines for dealing with DAV properties in httpd
 *
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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

#ifndef HTTP_DAV_H
#define HTTP_DAV_H

#include <stdint.h>
#include <libical/ical.h>
#include <libxml/tree.h>

#include "acl.h"
#include "annotate.h"
#include "caldav_db.h"
#include "dav_util.h"
#include "httpd.h"
#include "spool.h"
#include "quota.h"
#include "strarray.h"

#define NULL_ETAG       "da39a3ee5e6b4b0d3255bfef95601890afd80709"
                        /* SHA1("") */

#define SERVER_INFO     ".server-info"
#define SCHED_INBOX     "Inbox/"
#define SCHED_OUTBOX    "Outbox/"
#define SCHED_DEFAULT   "Default/"
#define MANAGED_ATTACH  "Attachments/"

/* XML namespace URIs */
#define XML_NS_DAV      "DAV:"
#define XML_NS_CALDAV   "urn:ietf:params:xml:ns:caldav"
#define XML_NS_CARDDAV  "urn:ietf:params:xml:ns:carddav"
#define XML_NS_ISCHED   "urn:ietf:params:xml:ns:ischedule"
#define XML_NS_CS       "http://calendarserver.org/ns/"
#define XML_NS_MECOM    "http://me.com/_namespace/"
#define XML_NS_MOBME    "urn:mobileme:davservices"
#define XML_NS_APPLE    "http://apple.com/ns/ical/"
#define XML_NS_USERFLAG "http://cyrusimap.org/ns/userflag/"
#define XML_NS_SYSFLAG  "http://cyrusimap.org/ns/sysflag/"
#define XML_NS_DAVMOUNT "http://purl.org/NET/webdav/mount/"

#define USER_COLLECTION_PREFIX  "user"
#define GROUP_COLLECTION_PREFIX "group"

#define LOCK_TOKEN_URL_SCHEME "urn:uuid:"
#define SYNC_TOKEN_URL_SCHEME "data:,"

#define SHARED_COLLECTION_DELIM '.'

/* Index into known namespace array */
enum {
    NS_REQ_ROOT = -1,   /* special case: ns of request root (not an index) */
    NS_DAV,
    NS_CALDAV,
    NS_CARDDAV,
    NS_ISCHED,
    NS_CS,
    NS_MECOM,
    NS_MOBME,
    NS_CYRUS,
};
#define NUM_NAMESPACE 8

/* Cyrus-specific privileges */
#define DACL_PROPCOL    ACL_WRITE       /* CY:write-properties-collection */
#define DACL_PROPRSRC   ACL_ANNOTATEMSG /* CY:write-properties-resource */
#define DACL_MKCOL      ACL_CREATE      /* CY:make-collection */
#define DACL_ADDRSRC    ACL_POST        /* CY:add-resource */
#define DACL_RMCOL      ACL_DELETEMBOX  /* CY:remove-collection */
#define DACL_RMRSRC     (ACL_DELETEMSG\
                         |ACL_EXPUNGE)  /* CY:remove-resource */
#define DACL_ADMIN      ACL_ADMIN       /* CY:admin (aggregates
                                           DAV:read-acl, DAV:write-acl,
                                           DAV:unlock and DAV:share) */
#define DACL_CHANGEORG  ACL_USER6       /* CY:change-organizer */

/* WebDAV (RFC 3744) privileges */
#define DACL_READ       (ACL_READ\
                         |ACL_LOOKUP)   /* DAV:read (aggregates
                                           DAV:read-current-user-privilege-set
                                           and CALDAV:read-free-busy) */
#define DACL_WRITECONT  ACL_INSERT      /* DAV:write-content */
#define DACL_WRITEPROPS (DACL_PROPCOL\
                         |DACL_PROPRSRC)/* DAV:write-properties */
#define DACL_BIND       (DACL_MKCOL\
                         |DACL_ADDRSRC) /* DAV:bind */
#define DACL_UNBIND     (DACL_RMCOL\
                         |DACL_RMRSRC)  /* DAV:unbind */
#define DACL_WRITE      (DACL_WRITECONT\
                         |DACL_WRITEPROPS\
                         |DACL_BIND\
                         |DACL_UNBIND)  /* DAV:write */
#define DACL_ALL        (DACL_READ\
                         |DACL_WRITE\
                         |DACL_ADMIN)   /* DAV:all */

/* CalDAV (RFC 4791) privileges */
#define DACL_READFB     ACL_USER9       /* CALDAV:read-free-busy
                                           (implicit if user has DAV:read) */

/* CalDAV Scheduling (RFC 6638) privileges

   We use the same ACLs for both schedule-deliver* and schedule-send* because
   functionality of Scheduling Inbox and Outbox are mutually exclusive.
   We use ACL_USER9 for both read-free-busy and schedule-*-freebusy because
   Scheduling Inbox and Outbox don't contribute to free-busy.
*/
#define DACL_SCHEDFB    ACL_USER9       /* For Scheduling Inbox:
                                           CALDAV:schedule-query-freebusy

                                           For Scheduling Outbox:
                                           CALDAV:schedule-send-freebusy */
#define DACL_INVITE     ACL_USER8       /* For Scheduling Inbox:
                                           CALDAV:schedule-deliver-invite

                                           For Scheduling Outbox:
                                           CALDAV:schedule-send-invite */
#define DACL_REPLY      ACL_USER7       /* For Scheduling Inbox:
                                           CALDAV:schedule-deliver-reply

                                           For Scheduling Outbox:
                                           CALDAV:schedule-send-reply */
#define DACL_SCHED      (DACL_SCHEDFB\
                         |DACL_INVITE\
                         |DACL_REPLY)   /* For Scheduling Inbox:
                                           CALDAV:schedule-deliver (aggregates
                                           CALDAV:schedule-deliver-invite,
                                           schedule-deliver-reply,
                                           schedule-query-freebusy);

                                           For Scheduling Outbox:
                                           CALDAV:schedule-send (aggregates
                                           CALDAV:schedule-send-invite,
                                           schedule-send-reply,
                                           schedule-send-freebusy) */

/* Preference bits */
enum {
    PREFER_MIN    = (1<<0),
    PREFER_REP    = (1<<1),
    PREFER_NOROOT = (1<<2)
};

#define NO_DUP_CHECK (1<<7)

/* PROPFIND modes */
enum {
    PROPFIND_NONE = 0,                  /* only used with REPORT */
    PROPFIND_ALL,
    PROPFIND_NAME,
    PROPFIND_PROP,
    PROPFIND_EXPAND                     /* only used with expand-prop REPORT */
};


extern struct meth_params princ_params;

/* Function to fetch resource validators */
typedef int (*get_validators_t)(struct mailbox *mailbox, void *data,
                                const char *userid, struct index_record *record,
                                const char **etag, time_t *lastmod);

/* Function to fetch resource modseq */
typedef modseq_t (*get_modseq_t)(struct mailbox *mailbox,
                                 void *data, const char *userid);

typedef void *(*db_open_proc_t)(struct mailbox *mailbox);
typedef int (*db_close_proc_t)(void *davdb);

/* Function to lookup DAV 'resource' in 'mailbox',
 * placing the record in 'data'
 */
typedef int (*db_lookup_proc_t)(void *davdb, const mbentry_t *mbentry,
                                const char *resource, void **data,
                                int tombstones);

/* Function to lookup DAV 'imapuid' in 'mailbox',
 * placing the record in 'data'
 */
typedef int (*db_imapuid_proc_t)(void *davdb, const mbentry_t *mbentry,
                                 int uid, void **data, int tombstones);

/* Function to process each DAV resource in 'mailbox' with 'cb' */
typedef int (*db_foreach_proc_t)(void *davdb, const mbentry_t *mbentry,
                                 int (*cb)(void *rock, void *data), void *rock);

/* Function to process 'limit' DAV resources
   updated since 'oldmodseq' in 'mailbox' with 'cb' */
typedef int (*db_updates_proc_t)(void *davdb, modseq_t oldmodseq,
                                 const mbentry_t *mbentry, int kind, int limit,
                                 int (*cb)(void *rock, void *data), void *rock);

/* Context for fetching properties */
struct propfind_entry_list;
struct prop_entry;
struct error_t;

/* Propfind return flags */
struct fctx_flags_t {
    unsigned long fetcheddata : 1;      /* Did we fetch iCalendar/vCard data? */
    unsigned long cs_sharing  : 1;      /* Is client using CS sharing? */
};

struct propfind_ctx {
    struct transaction_t *txn;          /* request transaction */
    struct request_target_t *req_tgt;   /* parsed target URL */
    unsigned mode;                      /* none, allprop, propname, prop */
    unsigned depth;                     /* 0 = root, 1 = calendar, 2 = resrc */
    unsigned prefer;                    /* bitmask of client preferences */
    const char *userid;                 /* userid client has logged in as */
    int userisadmin;                    /* is userid an admin */
    struct auth_state *authstate;       /* authorization state for userid */
    void *davdb;                        /* DAV DB corresponding to collection */
    const mbentry_t *mbentry;           /* mbentry corresponding to collection */
    struct mailbox *mailbox;            /* mailbox corresponding to collection */
    struct quota quota;                 /* quota info for collection */
    struct index_record *record;        /* cyrus.index record for resource */
    void *data;                         /* DAV record for resource */
    get_validators_t get_validators;    /* fetch resource validators */
    struct buf msg_buf;                 /* mmap()'d resource file */
    void *obj;                          /* parsed resource */
    void (*free_obj)(void *);           /* free parsed object */
    unsigned long reqd_privs;           /* privileges req'd on collections */
    int (*filter)(struct propfind_ctx *,
                  void *data);          /* callback to filter resources */
    void *filter_crit;                  /* criteria to filter resources */
    db_open_proc_t open_db;             /* open DAV DB for a given mailbox */
    db_close_proc_t close_db;           /* close DAV DB for a given mailbox */
    db_lookup_proc_t lookup_resource;   /* lookup a specific resource */
    db_foreach_proc_t foreach_resource; /* process all resources in a mailbox */
    int (*proc_by_resource)(void *rock, /* Callback to process a resource */
                            void *data);
    struct propfind_entry_list *elist;  /* List of props to fetch w/callbacks */
    const struct prop_entry *lprops;    /* Array of known "live" properties */
    xmlNodePtr root;                    /* root node to add to XML tree */
    xmlNsPtr *ns;                       /* Array of our known namespaces */
    struct hash_table *ns_table;        /* Table of all ns attached to resp */
    unsigned prefix_count;              /* Count of new ns added to resp */
    int *ret;                           /* Return code to pass up to caller */
    struct fctx_flags_t flags;          /* Return flags for this propfind */
    struct buf buf;                     /* Working buffer */
    xmlBufferPtr xmlbuf;                /* Buffer for dumping XML nodes */
};

/* Context for patching (writing) properties */
struct proppatch_ctx {
    struct transaction_t *txn;          /* request transaction */
    struct mailbox *mailbox;            /* mailbox related to the collection */
    struct index_record *record;        /* record of the specific resource */
    const struct prop_entry *lprops;    /* Array of known "live" properties */
    xmlNodePtr root;                    /* root node to add to XML tree */
    xmlNsPtr *ns;                       /* Array of our supported namespaces */
    struct txn *tid;                    /* Transaction ID for annot writes */
    int *ret;                           /* Return code to pass up to caller */
    struct buf buf;                     /* Working buffer */
    ptrarray_t postprocs;               /* Post-processors after patching */
};
/* Post processor function after properties are patched */
typedef void (*pctx_postproc_t)(struct proppatch_ctx *);

/* Structure for property status */
struct propstat {
    xmlNodePtr root;
    long status;
    unsigned precond;
};

/* Index into propstat array */
enum {
    PROPSTAT_OK = 0,
    PROPSTAT_UNAUTH,
    PROPSTAT_FORBID,
    PROPSTAT_NOTFOUND,
    PROPSTAT_CONFLICT,
    PROPSTAT_FAILEDDEP,
    PROPSTAT_ERROR,
    PROPSTAT_OVERQUOTA
};
#define NUM_PROPSTAT 8


/* Context for "live" properties */
struct prop_entry {
    const char *name;                   /* Property name */
    unsigned ns;                        /* Property namespace */
    unsigned char flags;                /* Flags for how/where props apply */
    int (*get)(const xmlChar *name,     /* Callback to fetch property */
               xmlNsPtr ns, struct propfind_ctx *fctx, xmlNodePtr prop,
               xmlNodePtr resp, struct propstat *propstat, void *rock);
    int (*put)(xmlNodePtr prop,         /* Callback to write property */
               unsigned set, struct proppatch_ctx *pctx,
               struct propstat *propstat, void *rock);
    void *rock;                         /* Add'l data to pass to callback */
};

/* Bitmask of property flags */
enum {
    PROP_ALLPROP =      (1<<0),         /* Returned in <allprop> request */
    PROP_COLLECTION =   (1<<1),         /* Returned for collection */
    PROP_RESOURCE =     (1<<2),         /* Returned for resource */
    PROP_PERUSER =      (1<<3),         /* Per-user property */
    PROP_PRESCREEN =    (1<<4),         /* Prescreen property using callback */
    PROP_CLEANUP =      (1<<5)          /* Cleanup property using callback */
};


/* Function to check headers for preconditions */
struct meth_params;
typedef int (*check_precond_t)(struct transaction_t *txn,
                               struct meth_params *params,
                               struct mailbox *mailbox, const void *data,
                               const char *etag, time_t lastmod);

/* Function to insert/update DAV resource in 'data' */
typedef int (*db_write_proc_t)(void *davdb, void *data);

/* Function to delete resource in 'rowid' */
typedef int (*db_delete_proc_t)(void *davdb, unsigned rowid);

typedef int (*db_proc_t)(void *davdb);

struct davdb_params {
    db_open_proc_t open_db;             /* open DAV DB for a given mailbox */
    db_close_proc_t close_db;           /* close DAV DB for a given mailbox */
    db_proc_t begin_transaction;
    db_proc_t commit_transaction;
    db_proc_t abort_transaction;
    db_lookup_proc_t lookup_resource;   /* lookup a specific resource */
    db_imapuid_proc_t lookup_imapuid;   /* lookup a specific resource */
    db_foreach_proc_t foreach_resource; /* process all resources in a mailbox */
    db_updates_proc_t foreach_update;   /* process updated resources in a mbox */
    /* XXX - convert these to lock management only.  For everything else,
     * we need to go via mailbox.c for replication support */
    db_write_proc_t write_resourceLOCKONLY;     /* write a specific resource */
    db_delete_proc_t delete_resourceLOCKONLY;   /* delete a specific resource */
};

/* Function to convert to/from MIME type */
struct mime_type_t {
    const char *content_type;
    const char *version;
    const char *file_ext;
    struct buf* (*from_object)(void *);
    void* (*to_object)(const struct buf *);
    void (*free)(void *);
    const char* (*begin_stream)(struct buf *, struct mailbox *mailbox,
                                const char *prodid, const char *name,
                                const char *desc, const char *color);
    void (*end_stream)(struct buf *);
};

/*
 * Process 'priv', augmenting 'rights' as necessary.
 * Returns 1 if processing is complete.
 * Returns 0 if processing should continue in meth_acl()
 */
typedef int (*acl_proc_t)(struct transaction_t *txn, xmlNodePtr priv,
                          int *rights);

/* Function to do special processing for DELETE method (optional) */
typedef int (*delete_proc_t)(struct transaction_t *txn, struct mailbox *mailbox,
                             struct index_record *record, void *data);

/* Function to do special processing for GET method (optional) */
typedef int (*get_proc_t)(struct transaction_t *txn, struct mailbox *mailbox,
                          struct index_record *record, void *data, void **obj,
                          struct mime_type_t *mime);

/* meth_mkcol() parameters */
typedef int (*mkcol_proc_t)(struct mailbox *mailbox);

struct mkcol_params {
    unsigned location_precond;          /* precond code for bad location */
    uint32_t mbtype;                    /* mailbox type collection */
    mkcol_proc_t proc;                  /* func to do post-create processing */
};

/*
 * Function to do special processing for POST method (optional).
 * Returns HTTP_CONTINUE if processing should continue in meth_post(),
 * otherwise processing is complete.
 */
typedef int (*post_proc_t)(struct transaction_t *txn);

typedef int (*import_proc_t)(struct transaction_t *txn, void *obj,
                             struct mailbox *mailbox, void *davdb,
                             xmlNodePtr root, xmlNsPtr *ns, unsigned flags);

/* POST "mode" bits */
enum {
    POST_ADDMEMBER = (1<<0),
    POST_SHARE     = (1<<1)
};

/* meth_put() parameters */
typedef int (*put_proc_t)(struct transaction_t *txn, void *obj,
                          struct mailbox *mailbox, const char *resource,
                          void *davdb, unsigned flags);

struct copy_params {
    unsigned uid_conf_precond;          /* precond code for UID conflict */
    put_proc_t proc;                    /* function to process & COPY a rsrc */
};

struct post_params {
    unsigned allowed;                   /* allowed generic POST "modes" */
    post_proc_t proc;                   /* special POST handling (optional) */
    struct {
        unsigned data_ns;               /* namespace of "data" property */
        const char *data_prop;          /* name of "data" prop for CRUD (opt) */
        import_proc_t import;           /* func to import multiple rsrcs (opt) */
    } bulk;
};

struct put_params {
    unsigned supp_data_precond;         /* precond code for unsupported data */
    put_proc_t proc;                    /* function to process & PUT a rsrc */
};

struct propfind_params {
    unsigned finite_depth_precond;      /* precond code for finite depth */
    const struct prop_entry *lprops;    /* array of "live" properties */
};

/* meth_report() parameters */
typedef int (*report_proc_t)(struct transaction_t *txn,
                             struct meth_params *rparams,
                             xmlNodePtr inroot, struct propfind_ctx *fctx);

struct report_type_t {
    const char *name;                   /* report name */
    unsigned ns;                        /* report namespace */
    const char *resp_root;              /* name of XML root element in resp */
    report_proc_t proc;                 /* function to generate the report */
    unsigned long reqd_privs;           /* privileges required to run report */
    unsigned flags;                     /* report-specific flags */
};

/* Report flags */
enum {
    REPORT_NEED_MBOX    = (1<<0),
    REPORT_NEED_PROPS   = (1<<1),
    REPORT_ALLOW_PROPS  = (1<<2),
    REPORT_DEPTH_ZERO   = (1<<3)
};

/* Overwrite flags */
enum {
    OVERWRITE_NO = 0,
    OVERWRITE_YES
};

struct meth_params {
    struct mime_type_t *mime_types;     /* array of MIME types and conv funcs */
    parse_path_t parse_path;            /* parse URI path & generate mboxname */
    get_validators_t get_validators;    /* fetch resource validators */
    get_modseq_t get_modseq;            /* fetch resource modseq */
    check_precond_t check_precond;      /* check headers for preconditions */
    struct davdb_params davdb;          /* DAV DB access functions */
    acl_proc_t acl_ext;                 /* special ACL handling (extensions) */
    struct copy_params copy;            /* params for copying a resource */
    delete_proc_t delete;               /* special DELETE handling (optional) */
    get_proc_t get;                     /* special GET handling (optional) */
    struct mkcol_params mkcol;          /* params for creating new collection */
    struct patch_doc_t *patch_docs;     /* array of patch docs & funcs (opt) */
    struct post_params post;            /* params for POST handling */
    struct put_params put;              /* params for putting a resource */
    struct propfind_params propfind;    /* params for finding properties */
    const struct report_type_t *reports;/* array of reports & proc functions */
};

extern struct meth_params webdav_params;

enum {
    MATCH_TYPE_CONTAINS = 0,
    MATCH_TYPE_EQUALS,
    MATCH_TYPE_PREFIX,
    MATCH_TYPE_SUFFIX
};

struct match_type_t {
    const char *name;
    unsigned value;
};

enum {
    COLLATION_UNICODE = 0,
    COLLATION_ASCII,
    COLLATION_OCTET
};

struct collation_t {
    const char *name;
    unsigned value;
};

struct text_match_t {
    xmlChar *text;
    unsigned negate    : 1;
    unsigned type      : 3;
    unsigned collation : 3;
    struct text_match_t *next;
};

struct param_filter {
    xmlChar *name;
    unsigned kind;
    unsigned not_defined : 1;
    struct text_match_t *match;
    struct param_filter *next;
};

struct prop_filter {
    xmlChar *name;
    unsigned kind;
    unsigned allof       : 1;
    unsigned not_defined : 1;
    void *other;                /* some other filter defined by caller */
    struct text_match_t *match;
    struct param_filter *param;
    struct prop_filter *next;
};

struct filter_profile_t {
    unsigned allof      : 1;
    unsigned collation  : 3;
    unsigned filter_precond;
    unsigned collation_precond;
    unsigned (*prop_string_to_kind)(const char *);
    unsigned no_prop_value;
    unsigned (*param_string_to_kind)(const char *);
    unsigned no_param_value;
    void (*parse_propfilter)(xmlNodePtr, struct prop_filter *,
                             struct error_t *);
};

#define DAV_FILTER_ISNOTDEF_ERR \
    "is-not-defined can NOT be combined with other elements"

void dav_get_synctoken(struct mailbox *mailbox,
                       struct buf *buf, const char *prefix);

void dav_parse_propfilter(xmlNodePtr root, struct prop_filter **prop,
                          struct filter_profile_t *profile,
                          struct error_t *error);
void dav_free_propfilter(struct prop_filter *prop);
int dav_apply_textmatch(xmlChar *text, struct text_match_t *match);

int report_expand_prop(struct transaction_t *txn, struct meth_params *rparams,
                       xmlNodePtr inroot, struct propfind_ctx *fctx);
int report_acl_prin_prop(struct transaction_t *txn, struct meth_params *rparams,
                         xmlNodePtr inroot, struct propfind_ctx *fctx);
int report_multiget(struct transaction_t *txn, struct meth_params *rparams,
                    xmlNodePtr inroot, struct propfind_ctx *fctx);
int report_sync_col(struct transaction_t *txn, struct meth_params *rparams,
                    xmlNodePtr inroot, struct propfind_ctx *fctx);


unsigned long calcarddav_allow_cb(struct request_target_t *tgt);
int dav_parse_req_target(struct transaction_t *txn,
                         struct meth_params *params);
int calcarddav_parse_path(const char *path, struct request_target_t *tgt,
                          const char *mboxprefix, const char **resultstr);
modseq_t dav_get_modseq(struct mailbox *mailbox,
                        void *data, const char *userid);
int dav_check_precond(struct transaction_t *txn, struct meth_params *params,
                      struct mailbox *mailbox, const void *data,
                      const char *etag, time_t lastmod);
int dav_premethod(struct transaction_t *txn);
unsigned get_preferences(struct transaction_t *txn);
struct mime_type_t *get_accept_type(const char **hdr, struct mime_type_t *types);

int parse_xml_body(struct transaction_t *txn, xmlNodePtr *root,
                   const char *mimetype);

size_t make_collection_url(struct buf *buf, const char *urlprefix, int haszzzz,
                           const mbname_t *mbname, const char *userid);

/* Initialize an XML tree */
xmlNodePtr init_xml_response(const char *resp, int ns,
                             xmlNodePtr req, xmlNsPtr *respNs);

xmlNodePtr xml_add_href(xmlNodePtr parent, xmlNsPtr ns, const char *href);
xmlNodePtr xml_add_error(xmlNodePtr root, struct error_t *err,
                         xmlNsPtr *avail_ns);
xmlNodePtr xml_add_prop(long status, xmlNsPtr davns,
                        struct propstat *propstat,
                        const xmlChar *name, xmlNsPtr ns,
                        xmlChar *content, unsigned precond);
void xml_add_lockdisc(xmlNodePtr node, const char *path, struct dav_data *data);
int ensure_ns(xmlNsPtr *respNs, int ns, xmlNodePtr node,
              const char *url, const char *prefix);

int xml_add_response(struct propfind_ctx *fctx, long code, unsigned precond,
                     const char *desc, const char *location);
int propfind_by_resource(void *rock, void *data);
int propfind_by_collection(const mbentry_t *mbentry, void *rock);
int expand_property(xmlNodePtr inroot, struct propfind_ctx *fctx,
                    struct namespace_t *namespace, const char *href,
                    parse_path_t parse_path, const struct prop_entry *lprops,
                    xmlNodePtr root, int depth);

int preload_proplist(xmlNodePtr proplist, struct propfind_ctx *fctx);
void free_entry_list(struct propfind_entry_list *elist);

void dav_precond_as_string(struct buf *buf, struct error_t *err);

/* DAV method processing functions */
int meth_acl(struct transaction_t *txn, void *params);
int meth_copy_move(struct transaction_t *txn, void *params);
int meth_delete(struct transaction_t *txn, void *params);
int meth_get_head(struct transaction_t *txn, void *params);
int meth_lock(struct transaction_t *txn, void *params);
int meth_mkcol(struct transaction_t *txn, void *params);
int meth_propfind(struct transaction_t *txn, void *params);
int meth_proppatch(struct transaction_t *txn, void *params);
int meth_patch(struct transaction_t *txn, void *params);
int meth_post(struct transaction_t *txn, void *params);
int meth_put(struct transaction_t *txn, void *params);
int meth_report(struct transaction_t *txn, void *params);
int meth_unlock(struct transaction_t *txn, void *params);


/* PROPFIND callbacks */

int propfind_getdata(const xmlChar *name, xmlNsPtr ns,
                     struct propfind_ctx *fctx,
                     xmlNodePtr prop, struct propstat propstat[],
                     struct mime_type_t *mime_types,
                     struct mime_type_t **out_type,
                     const char *data, unsigned long datalen);
int propfind_fromdb(const xmlChar *name, xmlNsPtr ns,
                    struct propfind_ctx *fctx,
                    xmlNodePtr prop, xmlNodePtr resp,
                    struct propstat propstat[], void *rock);
int propfind_fromhdr(const xmlChar *name, xmlNsPtr ns,
                     struct propfind_ctx *fctx,
                     xmlNodePtr prop, xmlNodePtr resp,
                     struct propstat propstat[], void *rock);
int propfind_creationdate(const xmlChar *name, xmlNsPtr ns,
                          struct propfind_ctx *fctx,
                          xmlNodePtr prop, xmlNodePtr resp,
                          struct propstat propstat[], void *rock);
int propfind_collectionname(const xmlChar *name, xmlNsPtr ns,
                            struct propfind_ctx *fctx,
                            xmlNodePtr prop, xmlNodePtr resp,
                            struct propstat propstat[], void *rock);
int propfind_getlength(const xmlChar *name, xmlNsPtr ns,
                       struct propfind_ctx *fctx,
                       xmlNodePtr prop, xmlNodePtr resp,
                       struct propstat propstat[], void *rock);
int propfind_getetag(const xmlChar *name, xmlNsPtr ns,
                     struct propfind_ctx *fctx,
                     xmlNodePtr prop, xmlNodePtr resp,
                     struct propstat propstat[], void *rock);
int propfind_getlastmod(const xmlChar *name, xmlNsPtr ns,
                        struct propfind_ctx *fctx,
                        xmlNodePtr prop, xmlNodePtr resp,
                        struct propstat propstat[], void *rock);
int propfind_lockdisc(const xmlChar *name, xmlNsPtr ns,
                      struct propfind_ctx *fctx,
                      xmlNodePtr prop, xmlNodePtr resp,
                      struct propstat propstat[], void *rock);
int propfind_suplock(const xmlChar *name, xmlNsPtr ns,
                     struct propfind_ctx *fctx,
                     xmlNodePtr prop, xmlNodePtr resp,
                     struct propstat propstat[], void *rock);

int propfind_reportset(const xmlChar *name, xmlNsPtr ns,
                       struct propfind_ctx *fctx,
                       xmlNodePtr prop, xmlNodePtr resp,
                       struct propstat propstat[], void *rock);

int propfind_methodset(const xmlChar *name, xmlNsPtr ns,
                       struct propfind_ctx *fctx,
                       xmlNodePtr prop, xmlNodePtr,
                       struct propstat propstat[], void *rock);

int propfind_collationset(const xmlChar *name, xmlNsPtr ns,
                          struct propfind_ctx *fctx,
                          xmlNodePtr prop, xmlNodePtr resp,
                          struct propstat propstat[], void *rock);

int propfind_principalurl(const xmlChar *name, xmlNsPtr ns,
                          struct propfind_ctx *fctx,
                          xmlNodePtr prop, xmlNodePtr resp,
                          struct propstat propstat[], void *rock);
int propfind_owner(const xmlChar *name, xmlNsPtr ns,
                   struct propfind_ctx *fctx,
                   xmlNodePtr prop, xmlNodePtr resp,
                   struct propstat propstat[], void *rock);
int propfind_supprivset(const xmlChar *name, xmlNsPtr ns,
                        struct propfind_ctx *fctx,
                        xmlNodePtr prop, xmlNodePtr resp,
                        struct propstat propstat[], void *rock);
int propfind_curprivset(const xmlChar *name, xmlNsPtr ns,
                        struct propfind_ctx *fctx,
                        xmlNodePtr prop, xmlNodePtr resp,
                        struct propstat propstat[], void *rock);
int propfind_acl(const xmlChar *name, xmlNsPtr ns,
                 struct propfind_ctx *fctx,
                 xmlNodePtr prop, xmlNodePtr resp,
                 struct propstat propstat[], void *rock);
int propfind_aclrestrict(const xmlChar *name, xmlNsPtr ns,
                         struct propfind_ctx *fctx,
                         xmlNodePtr prop, xmlNodePtr resp,
                         struct propstat propstat[], void *rock);
int propfind_princolset(const xmlChar *name, xmlNsPtr ns,
                        struct propfind_ctx *fctx,
                        xmlNodePtr prop, xmlNodePtr resp,
                        struct propstat propstat[], void *rock);

int propfind_quota(const xmlChar *name, xmlNsPtr ns,
                   struct propfind_ctx *fctx,
                   xmlNodePtr prop, xmlNodePtr resp,
                   struct propstat propstat[], void *rock);

int propfind_curprin(const xmlChar *name, xmlNsPtr ns,
                     struct propfind_ctx *fctx,
                     xmlNodePtr prop, xmlNodePtr resp,
                     struct propstat propstat[], void *rock);

int propfind_serverinfo(const xmlChar *name, xmlNsPtr ns,
                        struct propfind_ctx *fctx,
                        xmlNodePtr prop, xmlNodePtr resp,
                        struct propstat propstat[], void *rock);

int propfind_addmember(const xmlChar *name, xmlNsPtr ns,
                       struct propfind_ctx *fctx,
                       xmlNodePtr prop, xmlNodePtr resp,
                       struct propstat propstat[], void *rock);

int propfind_sync_token(const xmlChar *name, xmlNsPtr ns,
                        struct propfind_ctx *fctx,
                        xmlNodePtr prop, xmlNodePtr resp,
                        struct propstat propstat[], void *rock);

int propfind_bulkrequests(const xmlChar *name, xmlNsPtr ns,
                          struct propfind_ctx *fctx,
                          xmlNodePtr prop, xmlNodePtr resp,
                          struct propstat propstat[], void *rock);

int propfind_calurl(const xmlChar *name, xmlNsPtr ns,
                    struct propfind_ctx *fctx,
                    xmlNodePtr prop, xmlNodePtr resp,
                    struct propstat propstat[], void *rock);
int propfind_caluseraddr(const xmlChar *name, xmlNsPtr ns,
                         struct propfind_ctx *fctx,
                         xmlNodePtr prop, xmlNodePtr resp,
                         struct propstat propstat[], void *rock);
int propfind_caluseremail(const xmlChar *name, xmlNsPtr ns,
                         struct propfind_ctx *fctx,
                         xmlNodePtr prop, xmlNodePtr resp,
                         struct propstat propstat[], void *rock);
int proppatch_caluseraddr(xmlNodePtr prop, unsigned set,
                          struct proppatch_ctx *pctx,
                          struct propstat propstat[], void *rock);
int propfind_calusertype(const xmlChar *name, xmlNsPtr ns,
                         struct propfind_ctx *fctx,
                         xmlNodePtr prop, xmlNodePtr resp,
                         struct propstat propstat[], void *rock);
int propfind_abookhome(const xmlChar *name, xmlNsPtr ns,
                       struct propfind_ctx *fctx,
                       xmlNodePtr prop, xmlNodePtr resp,
                       struct propstat propstat[], void *rock);

int propfind_push_transports(const xmlChar *name, xmlNsPtr ns,
                             struct propfind_ctx *fctx,
                             xmlNodePtr prop, xmlNodePtr resp,
                             struct propstat propstat[], void *rock);
int propfind_pushkey(const xmlChar *name, xmlNsPtr ns,
                     struct propfind_ctx *fctx,
                     xmlNodePtr prop, xmlNodePtr resp,
                     struct propstat propstat[], void *rock);

/* PROPPATCH callbacks */
int proppatch_todb(xmlNodePtr prop, unsigned set, struct proppatch_ctx *pctx,
                   struct propstat propstat[], void *rock);
int proppatch_restype(xmlNodePtr prop, unsigned set, struct proppatch_ctx *pctx,
                      struct propstat propstat[], void *rock);

#endif /* HTTP_DAV_H */
