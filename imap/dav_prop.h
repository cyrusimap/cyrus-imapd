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

#include "httpd.h"
#include "spool.h"
#include "quota.h"
#include <libical/ical.h>
#include <libxml/tree.h>


/* XML namespace URIs */
#define XML_NS_DAV	"DAV:"
#define XML_NS_CALDAV	"urn:ietf:params:xml:ns:caldav"
#define XML_NS_CS	"http://calendarserver.org/ns/"
#define XML_NS_CYRUS	"http://cyrusimap.org/ns/"
#define XML_NS_ICAL	"http://apple.com/ns/ical/"

/* Index into known namespace array */
enum {
    NS_DAV,
    NS_CALDAV,
    NS_CS,
    NS_CYRUS,
    NS_ICAL
};
#define NUM_NAMESPACE 5

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
/* Index into preconditions array */
enum {
    DAV_PROT_PROP = 0,
    DAV_SUPP_REPORT,
    DAV_NEED_PRIVS,
    DAV_NO_INVERT,
    DAV_NO_ABSTRACT,
    DAV_SUPP_PRIV,
    DAV_RECOG_PRINC,
    DAV_OVER_QUOTA,
    DAV_NO_DISK_SPACE,
    DAV_VALID_RESTYPE,
    DAV_SYNC_TOKEN,
    DAV_OVER_LIMIT,
    CALDAV_SUPP_DATA,
    CALDAV_VALID_DATA,
    CALDAV_SUPP_COMP,
    CALDAV_LOCATION_OK,
    CALDAV_SUPP_FILTER,
    CALDAV_VALID_FILTER
};

/* Structure for precondition/postcondition errors */
struct precond {
    const char *name;			/* Property name */
    unsigned ns;			/* Index into known namespace array */
};

extern const struct precond preconds[];

/* Structure for property status */
struct propstat {
    xmlNodePtr root;
    long status;
    const struct precond *precond;
};

/* Index into propstat array */
enum {
    PROPSTAT_OK = 0,
    PROPSTAT_UNAUTH,
    PROPSTAT_FORBID,
    PROPSTAT_NOTFOUND,
    PROPSTAT_ERROR
};
#define NUM_PROPSTAT 5

/* Context for fetching properties */
struct propfind_entry_list;

struct calquery_filter {
    unsigned comp;
    struct icaltimetype start;
    struct icaltimetype end;
};

struct propfind_ctx {
    struct request_target_t *req_tgt;	/* parsed request target URL */
    unsigned depth;	    		/* 0 = root, 1 = calendar, 2 = resrc */
    unsigned brief;			/* omit 404 propstat elements */
    const char *userid;			/* userid client has logged in as */
    int userisadmin;			/* is userid an admin */
    struct auth_state *authstate;	/* authorization state for userid */
    struct mailbox *mailbox;		/* mailbox correspondng to collection */
    struct quota quota;			/* quota info for collection */
    struct index_record *record;	/* cyrus.index record for resource */
    const char *msg_base;		/* base of mmap()'d resource file */
    unsigned long msg_size;		/* size of mmap()'d resource file */
    struct calquery_filter *calfilter;	/* criteria to filter cal resources */
    int (*proc_by_resource)(void *rock,	/* Callback to process a resource */
		const char *resource, uint32_t uid);
    struct propfind_entry_list *elist;	/* List of props to fetch w/callbacks */
    xmlNodePtr root;			/* root node to add to XML tree */
    xmlNsPtr *ns;			/* Array of our supported namespaces */
    const char **errstr;		/* Error string to pass up to caller */
    int *ret;  				/* Return code to pass up to caller */
    struct buf buf;			/* Working buffer */
};


/* Context for patching (writing) properties */
struct proppatch_ctx {
    struct request_target_t *req_tgt;	/* parsed request target URL */
    const char *meth;	    		/* requested Method */
    const char *mailboxname;		/* mailbox correspondng to collection */
    xmlNodePtr root;			/* root node to add to XML tree */
    xmlNsPtr *ns;			/* Array of our supported namespaces */
    struct txn *tid;			/* Transaction ID for annot writes */
    const char **errstr;		/* Error string to pass up to caller */
    int *ret;  				/* Return code to pass up to caller */
    struct buf buf;			/* Working buffer */
};


/* Structure for known "live" properties */
struct prop_entry {
    const char *name;			/* Property name */
    const char *ns;			/* Property namespace */
    unsigned allprop;			/* Should we fetch for allprop? */
    int (*get)(xmlNodePtr node,		/* Callback to fetch property */
	       struct propfind_ctx *fctx, xmlNodePtr resp,
	       struct propstat propstat[], void *rock);
    int (*put)(xmlNodePtr prop,		/* Callback to write property */
	       unsigned set, struct proppatch_ctx *pctx,
	       struct propstat propstat[], void *rock);
    void *rock;				/* Add'l data to pass to callback */
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
xmlNodePtr init_xml_response(const char *resp,
			     xmlNsPtr reqNs, xmlNsPtr *respNs);

struct error_t;
xmlNodePtr xml_add_error(xmlNodePtr root, struct error_t *err,
			 xmlNsPtr *avail_ns);

/* Add a response tree to 'root' for the specified href and property list */
int xml_add_response(struct propfind_ctx *fctx, long code);

/* caldav_foreach() callback to find props on a resource */
int propfind_by_resource(void *rock, const char *resource, uint32_t uid);

/* mboxlist_findall() callback to find props on a collection */
int propfind_by_collection(char *mboxname,
			   int matchlen __attribute__((unused)),
			   int maycreate __attribute__((unused)),
			   void *rock);

/* Execute given property patch instructions */
int do_proppatch(struct proppatch_ctx *pctx, xmlNodePtr instr);

#endif /* DAV_PROP_H */
