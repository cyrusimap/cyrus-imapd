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

#include "caldav_db.h"
#include "httpd.h"
#include "spool.h"
#include "quota.h"

#include <libical/ical.h>
#include <libxml/tree.h>


#define NULL_ETAG	"da39a3ee5e6b4b0d3255bfef95601890afd80709"
			/* SHA1("") */

#define DFLAG_UNBIND	"DAV:unbind"

#define ANNOT_NS	"/vendor/cmu/cyrus-httpd/"

#define SCHED_INBOX	"Inbox/"
#define SCHED_OUTBOX	"Outbox/"
#define SCHED_DEFAULT	"Default/"

/* XML namespace URIs */
#define XML_NS_DAV	"DAV:"
#define XML_NS_CALDAV	"urn:ietf:params:xml:ns:caldav"
#define XML_NS_CARDDAV	"urn:ietf:params:xml:ns:carddav"
#define XML_NS_ISCHED	"urn:ietf:params:xml:ns:ischedule"
#define XML_NS_CS	"http://calendarserver.org/ns/"
#define XML_NS_CYRUS	"http://cyrusimap.org/ns/"

/* Index into known namespace array */
enum {
    NS_DAV,
    NS_CALDAV,
    NS_CARDDAV,
    NS_ISCHED,
    NS_CS,
    NS_CYRUS,
};
#define NUM_NAMESPACE 6

/* Cyrus-specific privileges */
#define DACL_MKCOL	ACL_CREATE	/* CY:make-collection */
#define DACL_ADDRSRC	ACL_POST	/* CY:add-resource */
#define DACL_RMCOL	ACL_DELETEMBOX	/* CY:remove-collection */
#define DACL_RMRSRC	ACL_DELETEMSG	/* CY:remove-resource */
#define DACL_ADMIN	ACL_ADMIN	/* CY:admin (aggregates
					   DAV:read-acl, write-acl, unlock) */

/* WebDAV (RFC 3744) privileges */
#define DACL_READ	(ACL_READ\
			 |ACL_LOOKUP)	/* DAV:read (aggregates
					   DAV:read-current-user-privilege-set
					   and CALDAV:read-free-busy) */
#define DACL_WRITECONT	ACL_INSERT	/* DAV:write-content */
#define DACL_WRITEPROPS	ACL_WRITE	/* DAV:write-properties */
#define DACL_BIND	(DACL_MKCOL\
			 |DACL_ADDRSRC)	/* DAV:bind */
#define DACL_UNBIND	(DACL_RMCOL\
			 |DACL_RMRSRC)	/* DAV:unbind */
#define DACL_WRITE	(DACL_WRITECONT\
			 |DACL_WRITEPROPS\
			 |DACL_BIND\
			 |DACL_UNBIND)	/* DAV:write */
#define DACL_ALL	(DACL_READ\
			 |DACL_WRITE\
			 |DACL_ADMIN)	/* DAV:all */

/* CalDAV (RFC 4791) privileges */
#define DACL_READFB	ACL_USER9	/* CALDAV:read-free-busy
					   (implicit if user has DAV:read) */

/* CalDAV Scheduling (RFC 6638) privileges

   We use the same ACLs for both schedule-deliver* and schedule-send* because
   functionality of Scheduling Inbox and Outbox are mutually exclusive.
   We use ACL_USER9 for both read-free-busy and schedule-*-freebusy because
   Scheduling Inbox and Outbox don't contribute to free-busy.
*/
#define DACL_SCHEDFB	ACL_USER9	/* For Scheduling Inbox:
					   CALDAV:schedule-query-freebusy

					   For Scheduling Outbox:
					   CALDAV:schedule-send-freebusy */
#define DACL_INVITE	ACL_USER8	/* For Scheduling Inbox:
					   CALDAV:schedule-deliver-invite

					   For Scheduling Outbox:
					   CALDAV:schedule-send-invite */
#define DACL_REPLY	ACL_USER7	/* For Scheduling Inbox:
					   CALDAV:schedule-deliver-reply

					   For Scheduling Outbox:
					   CALDAV:schedule-send-reply */
#define DACL_SCHED	(DACL_SCHEDFB\
			 |DACL_INVITE\
			 |DACL_REPLY)	/* For Scheduling Inbox:
					   CALDAV:schedule-deliver (aggregates
					   CALDAV:schedule-deliver-invite,
					   schedule-deliver-reply,
					   schedule-query-freebusy);

					   For Scheduling Outbox:
					   CALDAV:schedule-send (aggregates
					   CALDAV:schedule-send-invite,
					   schedule-send-reply,
					   schedule-send-freebusy) */

/* Bitmask of calendar components */
enum {
    CAL_COMP_VCALENDAR =	0xf000,
    CAL_COMP_VEVENT =		(1<<0),
    CAL_COMP_VTODO =		(1<<1),
    CAL_COMP_VJOURNAL =		(1<<2),
    CAL_COMP_VFREEBUSY =	(1<<3),
    CAL_COMP_VTIMEZONE =	(1<<4),
    CAL_COMP_VALARM =		(1<<5)
};

/* Index into preconditions array */
enum {
    /* WebDAV (RFC 4918) preconditons */
    DAV_PROT_PROP = 1,
    DAV_BAD_LOCK_TOKEN,
    DAV_NEED_LOCK_TOKEN,
    DAV_LOCKED,

    /* WebDAV Versioning (RFC 3253) preconditions */
    DAV_SUPP_REPORT,
    DAV_RSRC_EXISTS,

    /* WebDAV ACL (RFC 3744) preconditions */
    DAV_NEED_PRIVS,
    DAV_NO_INVERT,
    DAV_NO_ABSTRACT,
    DAV_SUPP_PRIV,
    DAV_RECOG_PRINC,

    /* WebDAV Quota (RFC 4331) preconditions */
    DAV_OVER_QUOTA,
    DAV_NO_DISK_SPACE,

    /* WebDAV Extended MKCOL (RFC 5689) preconditions */
    DAV_VALID_RESTYPE,

    /* WebDAV Sync (RFC 6578) preconditions */
    DAV_SYNC_TOKEN,
    DAV_OVER_LIMIT,

    /* CalDAV (RFC 4791) preconditions */
    CALDAV_SUPP_DATA,
    CALDAV_VALID_DATA,
    CALDAV_VALID_OBJECT,
    CALDAV_SUPP_COMP,
    CALDAV_LOCATION_OK,
    CALDAV_UID_CONFLICT,
    CALDAV_SUPP_FILTER,
    CALDAV_VALID_FILTER,

    /* CalDAV Scheduling (RFC 6638) preconditions */
    CALDAV_VALID_SCHED,
    CALDAV_VALID_ORGANIZER,
    CALDAV_UNIQUE_OBJECT,
    CALDAV_SAME_ORGANIZER,
    CALDAV_ALLOWED_ORG_CHANGE,
    CALDAV_ALLOWED_ATT_CHANGE,

    /* iSchedule (draft-desruisseaux-ischedule) preconditions */
    ISCHED_UNSUPP_VERSION,
    ISCHED_UNSUPP_DATA,
    ISCHED_INVALID_DATA,
    ISCHED_INVALID_SCHED,
    ISCHED_ORIG_MISSING,
    ISCHED_MULTIPLE_ORIG,
    ISCHED_ORIG_INVALID,
    ISCHED_ORIG_DENIED,
    ISCHED_RECIP_MISSING,
    ISCHED_RECIP_MISMATCH,
    ISCHED_VERIFICATION_FAILED,

    /* CardDAV (RFC 6352) preconditions */
    CARDDAV_SUPP_DATA,
    CARDDAV_VALID_DATA,
    CARDDAV_UID_CONFLICT,
    CARDDAV_LOCATION_OK,
    CARDDAV_SUPP_FILTER
};

/* Preference bits */
enum {
    PREFER_MIN    = (1<<0),
    PREFER_REP    = (1<<1),
    PREFER_NOROOT = (1<<2)
};

#define NO_DUP_CHECK (1<<7)


/* Function to lookup DAV 'resource' in 'mailbox', with optional 'lock',
 * placing the record in 'data'
 */
typedef int (*db_lookup_proc_t)(void *davdb, const char *mailbox,
				const char *resource, int lock, void **data);

/* Function to process each DAV resource in 'mailbox' with 'cb' */
typedef int (*db_foreach_proc_t)(void *davdb, const char *mailbox,
				 int (*cb)(void *rock, void *data), void *rock);

/* Context for fetching properties */
struct propfind_entry_list;
struct prop_entry;
struct error_t;

struct propfind_ctx {
    struct request_target_t *req_tgt;	/* parsed request target URL */
    unsigned mode;	    		/* none, allprop, propname, prop */
    unsigned depth;	    		/* 0 = root, 1 = calendar, 2 = resrc */
    unsigned prefer;			/* bitmask of client preferences */
    const char *userid;			/* userid client has logged in as */
    const char *int_userid;		/* internal userid */
    int userisadmin;			/* is userid an admin */
    struct auth_state *authstate;	/* authorization state for userid */
    void *davdb;			/* DAV DB corresponding to userid */
    struct mailbox *mailbox;		/* mailbox correspondng to collection */
    struct quota quota;			/* quota info for collection */
    struct index_record *record;	/* cyrus.index record for resource */
    void *data;				/* DAV record for resource */
    const char *msg_base;		/* base of mmap()'d resource file */
    unsigned long msg_size;		/* size of mmap()'d resource file */
    unsigned long reqd_privs;		/* privileges req'd on collections */
    int (*filter)(struct propfind_ctx *,
		  void *data);		/* callback to filter resources */
    void *filter_crit;			/* criteria to filter resources */
    db_lookup_proc_t lookup_resource;
    db_foreach_proc_t foreach_resource;
    int (*proc_by_resource)(void *rock,	/* Callback to process a resource */
			    void *data);
    struct propfind_entry_list *elist;	/* List of props to fetch w/callbacks */
    const struct prop_entry *lprops;	/* Array of known "live" properties */
    xmlNodePtr root;			/* root node to add to XML tree */
    xmlNsPtr *ns;			/* Array of our known namespaces */
    struct hash_table *ns_table;	/* Table of all ns attached to resp */
    unsigned prefix_count;		/* Count of new ns added to resp */
    struct error_t *err;		/* Error info to pass up to caller */
    int *ret;  				/* Return code to pass up to caller */
    int fetcheddata;			/* Did we fetch iCalendar/vCard data? */
    struct buf buf;			/* Working buffer */
};


/* Context for patching (writing) properties */
struct proppatch_ctx {
    struct request_target_t *req_tgt;	/* parsed request target URL */
    unsigned meth;	    		/* requested Method */
    const char *mailboxname;		/* mailbox correspondng to collection */
    const struct prop_entry *lprops;	/* Array of known "live" properties */
    xmlNodePtr root;			/* root node to add to XML tree */
    xmlNsPtr *ns;			/* Array of our supported namespaces */
    struct txn *tid;			/* Transaction ID for annot writes */
    struct error_t *err;		/* Error info to pass up to caller */
    int *ret;  				/* Return code to pass up to caller */
    struct buf buf;			/* Working buffer */
};


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
    const char *name;			/* Property name */
    unsigned ns;			/* Property namespace */
    unsigned char flags;		/* Flags for how/where props apply */
    int (*get)(const xmlChar *name,	/* Callback to fetch property */
	       xmlNsPtr ns, struct propfind_ctx *fctx, xmlNodePtr resp,
	       struct propstat *propstat, void *rock);
    int (*put)(xmlNodePtr prop,		/* Callback to write property */
	       unsigned set, struct proppatch_ctx *pctx,
	       struct propstat *propstat, void *rock);
    void *rock;				/* Add'l data to pass to callback */
};

/* Bitmask of property flags */
enum {
    PROP_ALLPROP =	(1<<0),		/* Returned in <allprop> request */
    PROP_COLLECTION = 	(1<<1),		/* Returned for collection */
    PROP_RESOURCE =	(1<<2),		/* Returned for resource */
    PROP_PRESCREEN =	(1<<3),		/* Prescreen property using callback */
    PROP_NEEDPROP =	(1<<4),		/* Pass property node into callback */
};


/* Function to check headers for preconditions */
typedef int (*check_precond_t)(struct transaction_t *txn, const void *data,
			       const char *etag, time_t lastmod);

/* Function to insert/update DAV resource in 'data', optionally commiting txn */
typedef int (*db_write_proc_t)(void *davdb, void *data, int commit);

/* Function to delete resource in 'rowid', optionally commiting txn */
typedef int (*db_delete_proc_t)(void *davdb, unsigned rowid, int commit);

/* Function to delete all entries in 'mailbox', optionally commiting txn */
typedef int (*db_delmbox_proc_t)(void *davdb, const char *mailbox, int commit);

struct davdb_params {
    void **db;				/* DAV DB to use for resources */
    db_lookup_proc_t lookup_resource;	/* lookup a specific resource */
    db_foreach_proc_t foreach_resource;	/* process all resources in a mailbox */
    db_write_proc_t write_resource;	/* write a specific resource */
    db_delete_proc_t delete_resource;	/* delete a specific resource */
    db_delmbox_proc_t delete_mbox;	/* delete all resources in mailbox */
};

/*
 * Process 'priv', augmenting 'rights' as necessary.
 * Returns 1 if processing is complete.
 * Returns 0 if processing should continue in meth_acl()
 */
typedef int (*acl_proc_t)(struct transaction_t *txn, xmlNodePtr priv,
			  int *rights);

/* Function to process and COPY a resource */
typedef int (*copy_proc_t)(struct transaction_t *txn,
			   struct mailbox *src_mbox, struct index_record *src_rec,
			   struct mailbox *dest_mbox, const char *dest_rsrc,
			   unsigned overwrite, unsigned flags);

/* Function to do special processing for DELETE method (optional) */
typedef int (*delete_proc_t)(struct transaction_t *txn, struct mailbox *mailbox,
			     struct index_record *record, void *data);

/* Function to convert to/from MIME type */
struct mime_type_t {
    const char *content_type;
    const char *version;
    const char *file_ext;
    const char *file_ext2;
    char* (*to_string)(void *);
    void* (*from_string)(const char *);
    void (*free)(void *);
    const char* (*begin_stream)(struct buf *);
    void (*end_stream)(struct buf *);
};

/* meth_mkcol() parameters */
struct mkcol_params {
    unsigned mbtype;			/* mbtype to use for created mailbox */
    const char *xml_req;		/* toplevel XML request element */
    const char *xml_resp;		/* toplevel XML response element */
    unsigned xml_ns;			/* namespace of response element */
};

/*
 * Function to do special processing for POST method (optional).
 * Returns HTTP_CONTINUE if processing should continue in meth_post(),
 * otherwise processing is complete.
 */
typedef int (*post_proc_t)(struct transaction_t *txn);

/* meth_put() parameters */
typedef int (*put_proc_t)(struct transaction_t *txn,
			  struct mime_type_t *mime,
			  struct mailbox *mailbox, unsigned flags);

struct put_params {
    unsigned supp_data_precond;		/* precond code for unsupported data */
    put_proc_t proc;			/* function to process & PUT a rsrc */
};

/* meth_report() parameters */
typedef int (*report_proc_t)(struct transaction_t *txn, xmlNodePtr inroot,
			     struct propfind_ctx *fctx);

struct report_type_t {
    const char *name;			/* report name */
    report_proc_t proc;			/* function to generate the report */
    unsigned long reqd_privs;		/* privileges required to run report */
    unsigned flags;			/* report-specific flags */
};

/* Report flags */
enum {
    REPORT_NEED_MBOX	= (1<<0),
    REPORT_NEED_PROPS 	= (1<<1),
    REPORT_MULTISTATUS	= (1<<2)
};

/* Overwrite flags */
enum {
    OVERWRITE_CHECK = -1,
    OVERWRITE_NO,
    OVERWRITE_YES
};

struct meth_params {
    struct mime_type_t *mime_types;	/* array of MIME types and conv funcs */
    parse_path_t parse_path;		/* parse URI path & generate mboxname */
    check_precond_t check_precond;	/* check headers for preconditions */
    struct davdb_params davdb;		/* DAV DB access functions */
    acl_proc_t acl_ext;			/* special ACL handling (extensions) */
    copy_proc_t copy;			/* function to process & COPY a rsrc */
    delete_proc_t delete;		/* special DELETE handling (optional) */
    struct mkcol_params mkcol;		/* params for creating collection */
    post_proc_t post;			/* special POST handling (optional) */
    struct put_params put;		/* params for putting a resource */
    const struct prop_entry *lprops;	/* array of "live" properties */
    struct report_type_t reports[];	/* array of reports & proc functions */
};

int report_sync_col(struct transaction_t *txn, xmlNodePtr inroot,
		    struct propfind_ctx *fctx);


int parse_path(struct request_target_t *tgt, const char **errstr);
int target_to_mboxname(struct request_target_t *req_tgt, char *mboxname);
unsigned get_preferences(struct transaction_t *txn);
struct mime_type_t *get_accept_type(const char **hdr, struct mime_type_t *types);

int parse_xml_body(struct transaction_t *txn, xmlNodePtr *root);

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

int propfind_by_resource(void *rock, void *data);
int propfind_by_collection(char *mboxname, int matchlen,
			   int maycreate, void *rock);

/* DAV method processing functions */
int meth_acl(struct transaction_t *txn, void *params);
int meth_copy(struct transaction_t *txn, void *params);
int meth_delete(struct transaction_t *txn, void *params);
int meth_get_dav(struct transaction_t *txn, void *params);
int meth_lock(struct transaction_t *txn, void *params);
int meth_mkcol(struct transaction_t *txn, void *params);
int meth_propfind(struct transaction_t *txn, void *params);
int meth_proppatch(struct transaction_t *txn, void *params);
int meth_post(struct transaction_t *txn, void *params);
int meth_put(struct transaction_t *txn, void *params);
int meth_report(struct transaction_t *txn, void *params);
int meth_unlock(struct transaction_t *txn, void *params);


/* PROPFIND callbacks */
int propfind_getdata(const xmlChar *name, xmlNsPtr ns,
		     struct propfind_ctx *fctx,
		     struct propstat propstat[], xmlNodePtr prop,
		     struct mime_type_t *mime_types, int precond,
		     const char *data, unsigned long datalen);
int propfind_fromdb(const xmlChar *name, xmlNsPtr ns,
		    struct propfind_ctx *fctx, xmlNodePtr resp,
		    struct propstat propstat[], void *rock);
int propfind_fromhdr(const xmlChar *name, xmlNsPtr ns,
		     struct propfind_ctx *fctx, xmlNodePtr resp,
		     struct propstat propstat[], void *rock);
int propfind_creationdate(const xmlChar *name, xmlNsPtr ns,
			  struct propfind_ctx *fctx, xmlNodePtr resp,
			  struct propstat propstat[], void *rock);
int propfind_getlength(const xmlChar *name, xmlNsPtr ns,
		       struct propfind_ctx *fctx, xmlNodePtr resp,
		       struct propstat propstat[], void *rock);
int propfind_getetag(const xmlChar *name, xmlNsPtr ns,
		     struct propfind_ctx *fctx, xmlNodePtr resp,
		     struct propstat propstat[], void *rock);
int propfind_getlastmod(const xmlChar *name, xmlNsPtr ns,
			struct propfind_ctx *fctx, xmlNodePtr resp,
			struct propstat propstat[], void *rock);
int propfind_lockdisc(const xmlChar *name, xmlNsPtr ns,
		      struct propfind_ctx *fctx, xmlNodePtr resp,
		      struct propstat propstat[], void *rock);
int propfind_suplock(const xmlChar *name, xmlNsPtr ns,
		     struct propfind_ctx *fctx, xmlNodePtr resp,
		     struct propstat propstat[], void *rock);

int propfind_owner(const xmlChar *name, xmlNsPtr ns,
		   struct propfind_ctx *fctx, xmlNodePtr resp,
		   struct propstat propstat[], void *rock);
int propfind_supprivset(const xmlChar *name, xmlNsPtr ns,
			struct propfind_ctx *fctx, xmlNodePtr resp,
			struct propstat propstat[], void *rock);
int propfind_curprivset(const xmlChar *name, xmlNsPtr ns,
			struct propfind_ctx *fctx, xmlNodePtr resp,
			struct propstat propstat[], void *rock);
int propfind_acl(const xmlChar *name, xmlNsPtr ns,
		 struct propfind_ctx *fctx, xmlNodePtr resp,
		 struct propstat propstat[], void *rock);
int propfind_aclrestrict(const xmlChar *name, xmlNsPtr ns,
			 struct propfind_ctx *fctx, xmlNodePtr resp,
			 struct propstat propstat[], void *rock);
int propfind_princolset(const xmlChar *name, xmlNsPtr ns,
			struct propfind_ctx *fctx, xmlNodePtr resp,
			struct propstat propstat[], void *rock);

int propfind_quota(const xmlChar *name, xmlNsPtr ns,
		   struct propfind_ctx *fctx, xmlNodePtr resp,
		   struct propstat propstat[], void *rock);

int propfind_curprin(const xmlChar *name, xmlNsPtr ns,
		     struct propfind_ctx *fctx, xmlNodePtr resp,
		     struct propstat propstat[], void *rock);

int propfind_addmember(const xmlChar *name, xmlNsPtr ns,
		       struct propfind_ctx *fctx, xmlNodePtr resp,
		       struct propstat propstat[], void *rock);

int propfind_sync_token(const xmlChar *name, xmlNsPtr ns,
			struct propfind_ctx *fctx, xmlNodePtr resp,
			struct propstat propstat[], void *rock);

int propfind_calurl(const xmlChar *name, xmlNsPtr ns,
		    struct propfind_ctx *fctx, xmlNodePtr resp,
		    struct propstat propstat[], void *rock);
int propfind_caluseraddr(const xmlChar *name, xmlNsPtr ns,
			 struct propfind_ctx *fctx, xmlNodePtr resp,
			 struct propstat propstat[], void *rock);
int propfind_abookurl(const xmlChar *name, xmlNsPtr ns,
		      struct propfind_ctx *fctx, xmlNodePtr resp,
		      struct propstat propstat[], void *rock);

/* PROPPATCH callbacks */
int proppatch_todb(xmlNodePtr prop, unsigned set, struct proppatch_ctx *pctx,
		   struct propstat propstat[], void *rock);
int proppatch_restype(xmlNodePtr prop, unsigned set, struct proppatch_ctx *pctx,
		      struct propstat propstat[], void *rock);

#endif /* HTTP_DAV_H */
