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
#include <libxml/tree.h>


/* Index into known namespace array */
enum {
    NS_UNKNOWN = -1,
    NS_DAV,
    NS_CAL,
    NS_CS,
    NS_APPLE
};
#define NUM_NAMESPACE 4

/* Context for fetching properties */
struct propfind_entry_list;

struct propfind_ctx {
    struct request_target_t *req_tgt;	/* parsed request target URL */
    unsigned depth;	    		/* 0 = root, 1 = calendar, 2 = resrc */
    const char *userid;			/* authenticated user */
    struct mailbox *mailbox;		/* mailbox correspondng to collection */
    struct index_record *record;	/* cyrus.index record for resource */
    hdrcache_t hdrcache;		/* Parsed headers from cyrus.cache */
    struct propfind_entry_list *elist;	/* List of props to fetch w/callbacks */
    xmlNodePtr root;			/* root node to add to XML tree */
    xmlNsPtr *ns;			/* Array of our supported namespaces */
    const char **errstr;		/* Error string to pass up to caller */
    int *ret;  				/* Return code to pass up to caller */
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
};


/* Structure for known "live" properties */
struct prop_entry {
    const char *name;			/* Property name */
    unsigned namespace;			/* Index into known namespace array */
    unsigned allprop;			/* Should we fetch for allprop? */
    int (*get)(const xmlChar *name,	/* Callback to fetch property */
	       xmlNsPtr ns, struct propfind_ctx *fctx, xmlNodePtr resp,
	       xmlNodePtr *propstat, void *rock);
    int (*put)(xmlNodePtr prop,		/* Callback to write property */
	       unsigned set, xmlNsPtr ns, struct proppatch_ctx *pctx,
	       xmlNodePtr *propstat, void *rock);
    void *rock;				/* Add'l data to pass to callback */
};

/* Linked-list of properties for fetching */
struct propfind_entry_list {
    const xmlChar *name;		/* Property name */
    xmlNsPtr ns;  			/* Namespace of property */
    int (*get)(const xmlChar *name,	/* Callback to fetch property */
	       xmlNsPtr ns, struct propfind_ctx *fctx, xmlNodePtr resp,
	       xmlNodePtr *propstat, void *rock);
    void *rock;				/* Add'l data to pass to callback */
    struct propfind_entry_list *next;
};

/* Index into propstat array */
enum {
    PROPSTAT_OK = 0,
    PROPSTAT_FORBID,
    PROPSTAT_NOTFOUND
};
#define NUM_PROPSTAT 3


/* Parse the requested properties and create a linked list of fetch callbacks */
int preload_proplist(xmlNodePtr proplist, xmlNsPtr ns[],
		     struct propfind_entry_list **list);

/* Initialize an XML tree for a property response */
xmlDocPtr init_prop_response(const char *resp,
			     xmlNodePtr *root, xmlNsPtr *ns);

/* Add a response tree to 'root' for the specified href and property list */
void add_prop_response(struct propfind_ctx *fctx);

/* caldav_foreach() callback to find props on a resource */
int find_resource_props(void *rock, const char *resource, uint32_t uid);

/* mboxlist_findall() callback to find props on a collection */
int find_collection_props(char *mboxname,
			  int matchlen __attribute__((unused)),
			  int maycreate __attribute__((unused)),
			  void *rock);

/* Execute given property patch instructions */
int do_proppatch(struct proppatch_ctx *pctx, xmlNodePtr instr,
		 xmlNodePtr *propstat, const char **errstr);

#endif /* DAV_PROP_H */
