/* dav_prop.h -- Routines for dealing with DAV properties in httpd
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

#ifndef DAV_PROP_H
#define DAV_PROP_H

#include "caldav_db.h"
#include "httpd.h"
#include "spool.h"
#include "quota.h"

#include <libical/ical.h>
#include <libxml/tree.h>


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

/* CalDAV scheduling (draft-desruisseaux-caldav-sched) privileges */
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

/* Preference bits */
enum {
    PREFER_MIN    = (1<<0),
    PREFER_REP    = (1<<1),
    PREFER_NOROOT = (1<<2)
};

/* Context for fetching properties */
struct propfind_entry_list;

struct calquery_filter {
    unsigned comp;
    struct icaltimetype start;
    struct icaltimetype end;
    unsigned check_transp;
};

struct busytime {
    struct icalperiodtype *busy;
    unsigned len;
    unsigned alloc;
};

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
    struct calquery_filter *calfilter;	/* criteria to filter cal resources */
    int (*lookup_resource)(void *davdb,
			   const char *mailbox,
			   const char *resource,
			   int lock,
			   void **data);
    int (*foreach_resource)(void *davdb,
			    const char *mailbox,
			    int (*cb)(void *rock, void *data),
			    void *rock);
    int (*proc_by_resource)(void *rock,	/* Callback to process a resource */
			    void *data);
    struct propfind_entry_list *elist;	/* List of props to fetch w/callbacks */
    struct busytime busytime;    	/* array of found busytime periods */
    xmlNodePtr root;			/* root node to add to XML tree */
    xmlNsPtr *ns;			/* Array of our supported namespaces */
    const char **errstr;		/* Error string to pass up to caller */
    int *ret;  				/* Return code to pass up to caller */
    int fetcheddata;			/* Did we fetch iCalendar/vCard data? */
    struct buf buf;			/* Working buffer */
};


/* Context for patching (writing) properties */
struct proppatch_ctx {
    struct request_target_t *req_tgt;	/* parsed request target URL */
    unsigned meth;	    		/* requested Method */
    const char *mailboxname;		/* mailbox correspondng to collection */
    xmlNodePtr root;			/* root node to add to XML tree */
    xmlNsPtr *ns;			/* Array of our supported namespaces */
    struct txn *tid;			/* Transaction ID for annot writes */
    const char **errstr;		/* Error string to pass up to caller */
    int *ret;  				/* Return code to pass up to caller */
    struct buf buf;			/* Working buffer */
};


/* Linked-list of properties for fetching */
struct propfind_entry_list {
    xmlNodePtr prop;			/* Property */
    int (*get)(xmlNodePtr node,		/* Callback to fetch property */
	       struct propfind_ctx *fctx, xmlNodePtr resp,
	       struct propstat propstat[], void *rock);
    void *rock;				/* Add'l data to pass to callback */
    struct propfind_entry_list *next;
};


/* Parse the requested properties and create a linked list of fetch callbacks */
int preload_proplist(xmlNodePtr proplist, struct propfind_ctx *fctx);

/* Initialize an XML tree */
xmlNodePtr init_xml_response(const char *resp, int ns,
			     xmlNodePtr req, xmlNsPtr *respNs);

struct error_t;
xmlNodePtr xml_add_error(xmlNodePtr root, struct error_t *err,
			 xmlNsPtr *avail_ns);

/* Add a response tree to 'root' for the specified href and property list */
int xml_add_response(struct propfind_ctx *fctx, long code);

/* Execute given property patch instructions */
int do_proppatch(struct proppatch_ctx *pctx, xmlNodePtr instr);

#endif /* DAV_PROP_H */
