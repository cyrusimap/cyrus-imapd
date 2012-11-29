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


#define DFLAG_UNBIND	"DAV:unbind"

#define ANNOT_NS	"/vendor/cmu/cyrus-imapd/"

#define SCHED_INBOX	"Inbox/"
#define SCHED_OUTBOX	"Outbox/"
#define SCHED_DEFAULT	"Default/"

/* XML namespace URIs */
#define XML_NS_DAV	"DAV:"
#define XML_NS_CALDAV	"urn:ietf:params:xml:ns:caldav"
#define XML_NS_ISCHED	"urn:ietf:params:xml:ns:ischedule"
#define XML_NS_CS	"http://calendarserver.org/ns/"
#define XML_NS_CYRUS	"http://cyrusimap.org/ns/"
#define XML_NS_ICAL	"http://apple.com/ns/ical/"

/* Index into known namespace array */
enum {
    NS_DAV,
    NS_CALDAV,
    NS_ISCHED,
    NS_CS,
    NS_CYRUS,
    NS_ICAL
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

/* CalDAV Scheduling (RFC 6638) privileges */
/* XXX  Can/should we use the same ACL for both schedule-deliver & schedule-send
   and can/should we use the same ACL as read-free-busy?
*/
#define DACL_SCHED	ACL_USER8	/* For Scheduling Inbox:
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
    CAL_COMP_VCALENDAR =	(0<<0),
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

    /* CalDAV Scheduling (draft-desruisseaux-caldav-sched) preconditions */
    CALDAV_VALID_SCHED,
    CALDAV_VALID_ORGANIZER,
    CALDAV_UNIQUE_OBJECT,
    CALDAV_SAME_ORGANIZER,
    CALDAV_ALLOWED_ORG_CHANGE,
    CALDAV_ALLOWED_ATT_CHANGE,

    /* iSchedule (draft-desruisseaux-ischedule) preconditions */
    ISCHED_VERIFICATION_FAILED
};

/* Preference bits */
enum {
    PREFER_MIN    = (1<<0),
    PREFER_REP    = (1<<1),
    PREFER_NOROOT = (1<<2)
};

/* Context for fetching properties */
struct propfind_entry_list;

/* Function to lookup DAV mailbox+resource (w/ optional lock) and return data */
typedef int (*lookup_proc_t)(void *davdb, const char *mailbox,
			     const char *resource, int lock, void **data);
/* Function to process each DAV resource in mailbox with cb() */
typedef int (*foreach_proc_t)(void *davdb, const char *mailbox,
			      int (*cb)(void *rock, void *data), void *rock);

struct propfind_ctx {
    struct request_target_t *req_tgt;	/* parsed request target URL */
    unsigned depth;	    		/* 0 = root, 1 = calendar, 2 = resrc */
    unsigned prefer;			/* bitmask of client preferences */
    const char *userid;			/* userid client has logged in as */
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
    lookup_proc_t lookup_resource;
    foreach_proc_t foreach_resource;
    int (*proc_by_resource)(void *rock,	/* Callback to process a resource */
			    void *data);
    struct propfind_entry_list *elist;	/* List of props to fetch w/callbacks */
    xmlNodePtr root;			/* root node to add to XML tree */
    xmlNsPtr *ns;			/* Array of our supported namespaces */
    const char **errstr;		/* Error string to pass up to caller */
    int *ret;  				/* Return code to pass up to caller */
    int fetcheddata;			/* Did we fetch iCalendar/vCard data? */
    struct buf buf;			/* Working buffer */
};

/* meth_acl() parameters */
struct acl_params {
    int (*acl_proc)(struct transaction_t *txn,
		    xmlNodePtr priv,
		    int *rights);	/* Process priv, augmenting *rights.
					 * Returns 1 if processing complete.
					 * Returns 0 if processing should
					 * continue in meth_acl()
					 */
};

/* meth_mkcol() parameters */
struct mkcol_params {
    unsigned mbtype;			/* mbtype to use for created mailbox */
    int (*mboxname)(const char *name,
		    const char *userid,
		    char *result);	/* create mboxname from name & userid */
    const char *xml_req;		/* toplevel XML request element */
    const char *xml_resp;		/* toplevel XML response element */
    unsigned xml_ns;			/* namespace of response element */
};

/* meth_propfind() parameters */
struct propfind_params {
    void **davdb;			/* DAV DB to use for lookup/foreach */
    lookup_proc_t lookup;		/* lookup a specific resource */
    foreach_proc_t foreach;		/* process all resources in a mailbox */
};

typedef int (*report_proc_t)(struct transaction_t *txn, xmlNodePtr inroot,
			     struct propfind_ctx *fctx,
			     char mailboxname[]);

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

int report_sync_col(struct transaction_t *txn, xmlNodePtr inroot,
		    struct propfind_ctx *fctx, char mailboxname[]);


int parse_path(struct request_target_t *tgt, const char **errstr);
int target_to_mboxname(struct request_target_t *req_tgt, char *mboxname);
unsigned get_preferences(struct transaction_t *txn);

int parse_xml_body(struct transaction_t *txn, xmlNodePtr *root);

/* Initialize an XML tree */
xmlNodePtr init_xml_response(const char *resp, int ns,
			     xmlNodePtr req, xmlNsPtr *respNs);

struct error_t;
xmlNodePtr xml_add_error(xmlNodePtr root, struct error_t *err,
			 xmlNsPtr *avail_ns);

int propfind_by_resource(void *rock, void *data);
int propfind_by_collection(char *mboxname, int matchlen,
			   int maycreate, void *rock);

/* DAV method processing functions */
int meth_acl(struct transaction_t *txn, void *params);
int meth_mkcol(struct transaction_t *txn, void *params);
int meth_propfind(struct transaction_t *txn, void *params);
int meth_proppatch(struct transaction_t *txn, void *params);
int meth_report(struct transaction_t *txn, void *params);

#endif /* HTTP_DAV_H */
