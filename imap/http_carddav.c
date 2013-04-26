/* http_carddav.c -- Routines for handling CardDAV collections in httpd
 *
 * Copyright (c) 1994-2013 Carnegie Mellon University.  All rights reserved.
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
/*
 * TODO:
 *   Support <filter> for addressbook-query Report
 *
 */

#include <config.h>

#include <syslog.h>

#include <libical/vcc.h>
#include <libxml/tree.h>
#include <libxml/uri.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "acl.h"
#include "append.h"
#include "carddav_db.h"
#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "http_dav.h"
#include "http_err.h"
#include "http_proxy.h"
#include "imap_err.h"
#include "index.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "message.h"
#include "message_guid.h"
#include "proxy.h"
#include "rfc822date.h"
#include "smtpclient.h"
#include "spool.h"
#include "stristr.h"
#include "util.h"
#include "version.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

static struct carddav_db *auth_carddavdb = NULL;

static void my_carddav_init(struct buf *serverinfo);
static void my_carddav_auth(const char *userid);
static void my_carddav_reset(void);
static void my_carddav_shutdown(void);

static int carddav_parse_path(const char *path,
			      struct request_target_t *tgt, const char **errstr);

static int carddav_copy(struct transaction_t *txn,
			struct mailbox *src_mbox, struct index_record *src_rec,
			struct mailbox *dest_mbox, const char *dest_rsrc,
			unsigned overwrite, unsigned flags);
static int carddav_put(struct transaction_t *txn, struct mailbox *mailbox,
		       unsigned flags);

static int report_card_query(struct transaction_t *txn, xmlNodePtr inroot,
			     struct propfind_ctx *fctx);
static int report_card_multiget(struct transaction_t *txn, xmlNodePtr inroot,
				struct propfind_ctx *fctx);

static int store_resource(struct transaction_t *txn, VObject *vcard,
			  struct mailbox *mailbox, const char *resource,
			  struct carddav_db *carddavdb, int overwrite,
			  unsigned flags);
static struct meth_params carddav_params = {
    "text/vcard; charset=utf-8",
    &carddav_parse_path,
    &check_precond,
    { (void **) &auth_carddavdb,
      (db_lookup_proc_t) &carddav_lookup_resource,
      (db_foreach_proc_t) &carddav_foreach,
      (db_write_proc_t) &carddav_write,
      (db_delete_proc_t) &carddav_delete,
      (db_delmbox_proc_t) &carddav_delmbox },
    NULL,					/* No ACL extensions */
    &carddav_copy,
    NULL,		  	      		/* No special DELETE handling */
    { MBTYPE_ADDRESSBOOK, NULL, NULL, 0 },	/* No special MK* method */
    NULL,		  	      		/* No special POST handling */
    { CARDDAV_SUPP_DATA, &carddav_put },
    { { "addressbook-query", &report_card_query, DACL_READ,
	REPORT_NEED_MBOX | REPORT_MULTISTATUS },
      { "addressbook-multiget", &report_card_multiget, DACL_READ,
	REPORT_NEED_MBOX | REPORT_MULTISTATUS },
      { "sync-collection", &report_sync_col, DACL_READ,
	REPORT_NEED_MBOX | REPORT_MULTISTATUS | REPORT_NEED_PROPS },
      { NULL, NULL, 0, 0 } }
};


/* Namespace for Carddav collections */
struct namespace_t namespace_addressbook = {
    URL_NS_ADDRESSBOOK, 0, "/addressbooks", "/.well-known/carddav", 1 /* auth */,
#if 0 /* Until Apple Contacts fixes their add-member implementation */
    (ALLOW_READ | ALLOW_POST | ALLOW_WRITE | ALLOW_DELETE |
     ALLOW_DAV | ALLOW_WRITECOL | ALLOW_CARD),
#else
    (ALLOW_READ | ALLOW_WRITE | ALLOW_DELETE |
     ALLOW_DAV | ALLOW_WRITECOL | ALLOW_CARD),
#endif
    &my_carddav_init, &my_carddav_auth, my_carddav_reset, &my_carddav_shutdown,
    { 
	{ &meth_acl,		&carddav_params },	/* ACL		*/
	{ &meth_copy,		&carddav_params },	/* COPY		*/
	{ &meth_delete,		&carddav_params },	/* DELETE	*/
	{ &meth_get_dav,	&carddav_params },	/* GET		*/
	{ &meth_get_dav,	&carddav_params },	/* HEAD		*/
	{ &meth_lock,		&carddav_params },	/* LOCK		*/
	{ NULL,			NULL },			/* MKCALENDAR	*/
	{ &meth_mkcol,		&carddav_params },	/* MKCOL	*/
	{ &meth_copy,		&carddav_params },	/* MOVE		*/
	{ &meth_options,	&carddav_parse_path },	/* OPTIONS	*/
#if 0 /* Until Apple Contacts fixes their add-member implementation */
	{ &meth_post,		&carddav_params },	/* POST		*/
#else
	{ NULL,			NULL },			/* POST		*/
#endif
	{ &meth_propfind,	&carddav_params },	/* PROPFIND	*/
	{ &meth_proppatch,	&carddav_params },	/* PROPPATCH	*/
	{ &meth_put,		&carddav_params },	/* PUT		*/
	{ &meth_report,		&carddav_params },	/* REPORT	*/
	{ &meth_trace,		&carddav_parse_path },	/* TRACE	*/
	{ &meth_unlock,		&carddav_params } 	/* UNLOCK	*/
    }
};


static struct namespace carddav_namespace;

static void my_carddav_init(struct buf *serverinfo)
{
    int r;

    namespace_addressbook.enabled =
	config_httpmodules & IMAP_ENUM_HTTPMODULES_CARDDAV;

    if (!namespace_addressbook.enabled) return;

    if (!config_getstring(IMAPOPT_ADDRESSBOOKPREFIX)) {
	fatal("Required 'addressbookprefix' option is not set", EC_CONFIG);
    }

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&carddav_namespace, 1))) {
	syslog(LOG_ERR, "%s", error_message(r));
	fatal(error_message(r), EC_CONFIG);
    }

    carddav_init();

    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON &&
	!strstr(buf_cstring(serverinfo), " libical/")) {
	buf_printf(serverinfo, " libicalvcal/%s", ICAL_VERSION);
    }
}


#define DEFAULT_ADDRBOOK "Default"

static void my_carddav_auth(const char *userid)
{
    int r;
    size_t len;
    char mailboxname[MAX_MAILBOX_BUFFER], rights[100], *partition = NULL;
    struct buf acl = BUF_INITIALIZER;

    if (config_mupdate_server && !config_getstring(IMAPOPT_PROXYSERVERS)) {
	/* proxy-only server - won't have DAV databases */
	return;
    }
    else if (httpd_userisadmin ||
	     global_authisa(httpd_authstate, IMAPOPT_PROXYSERVERS)) {
	/* admin or proxy from frontend - won't have DAV database */
	return;
    }

    /* Auto-provision an addressbook for 'userid' */

    /* Construct mailbox name corresponding to userid's Inbox */
    (*carddav_namespace.mboxname_tointernal)(&carddav_namespace, "INBOX",
					     userid, mailboxname);
    len = strlen(mailboxname);

    /* addressbook-home-set */
    len += snprintf(mailboxname+len, MAX_MAILBOX_BUFFER - len, ".%s",
		    config_getstring(IMAPOPT_ADDRESSBOOKPREFIX));
    r = mboxlist_createmailboxcheck(mailboxname, 0, NULL, 0,
				    userid, httpd_authstate, NULL,
				    &partition, 0);
    if (!r) {
	buf_reset(&acl);
	cyrus_acl_masktostr(ACL_ALL, rights);
	buf_printf(&acl, "%s\t%s\t", userid, rights);
	r = mboxlist_createmailbox_full(mailboxname, MBTYPE_ADDRESSBOOK,
					partition, 0,
					userid, httpd_authstate,
					OPT_POP3_NEW_UIDL, time(0),
					buf_cstring(&acl), NULL,
					0, 0, 0, NULL);
    }
    if (r && r != IMAP_MAILBOX_EXISTS) {
	if (partition) free(partition);
	buf_free(&acl);
	return;
    }

    /* Default addressbook */
    snprintf(mailboxname+len, MAX_MAILBOX_BUFFER - len, ".%s",
	     DEFAULT_ADDRBOOK);
    r = mboxlist_lookup(mailboxname, NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	buf_reset(&acl);
	cyrus_acl_masktostr(ACL_ALL, rights);
	buf_printf(&acl, "%s\t%s\t", userid, rights);
	r = mboxlist_createmailbox_full(mailboxname, MBTYPE_ADDRESSBOOK,
					partition, 0,
					userid, httpd_authstate,
					OPT_POP3_NEW_UIDL, time(0),
					buf_cstring(&acl), NULL,
					0, 0, 0, NULL);
    }

    auth_carddavdb = carddav_open(userid, CARDDAV_CREATE);
    if (!auth_carddavdb) fatal("Unable to open CardDAV DB", EC_IOERR);
}


static void my_carddav_reset(void)
{
    if (auth_carddavdb) carddav_close(auth_carddavdb);
    auth_carddavdb = NULL;
}


static void my_carddav_shutdown(void)
{
    carddav_done();
}


/* Parse request-target path in /calendars namespace */
static int carddav_parse_path(const char *path,
			      struct request_target_t *tgt, const char **errstr)
{
    char *p;
    size_t len, siz;
    static const char *prefix = NULL;

    /* Make a working copy of target path */
    strlcpy(tgt->path, path, sizeof(tgt->path));
    tgt->tail = tgt->path + strlen(tgt->path);

    p = tgt->path;
    if (!*p || !*++p) return 0;

    /* Sanity check namespace */
    len = strcspn(p, "/");
    if (len != strlen(namespace_addressbook.prefix)-1 ||
	strncmp(namespace_addressbook.prefix+1, p, len)) {
	*errstr = "Namespace mismatch request target path";
	return HTTP_FORBIDDEN;
    }

    /* Default to bare-bones Allow bits for toplevel collections */
    tgt->allow &= ~(ALLOW_POST|ALLOW_WRITE|ALLOW_DELETE);

    /* Skip namespace */
    p += len;
    if (!*p || !*++p) return 0;

    /* Check if we're in user space */
    len = strcspn(p, "/");
    if (!strncmp(p, "user", len)) {
	p += len;
	if (!*p || !*++p) return 0;

	/* Get user id */
	len = strcspn(p, "/");
	tgt->user = p;
	tgt->userlen = len;

	p += len;
	if (!*p || !*++p) goto done;

	len = strcspn(p, "/");
    }

    /* Get collection */
    tgt->collection = p;
    tgt->collen = len;

    p += len;
    if (!*p || !*++p) {
	/* Make sure collection is terminated with '/' */
	if (p[-1] != '/') *p++ = '/';
	goto done;
    }

    /* Get resource */
    len = strcspn(p, "/");
    tgt->resource = p;
    tgt->reslen = len;

    p += len;

    if (*p) {
	*errstr = "Too many segments in request target path";
	return HTTP_FORBIDDEN;
    }

  done:
    /* Set proper Allow bits based on path components */
    if (tgt->collection) {
	if (tgt->resource) {
	    tgt->allow &= ~ALLOW_WRITECOL;
	    tgt->allow |= (ALLOW_WRITE|ALLOW_DELETE);
	}
#if 0 /* Until Apple Contacts fixes their add-member implementation */
	else tgt->allow |= (ALLOW_POST|ALLOW_DELETE);
#else
	else tgt->allow |= ALLOW_DELETE;
#endif
    }
    else if (tgt->user) tgt->allow |= ALLOW_DELETE;


    /* Create mailbox name from the parsed path */ 
    if (!prefix) prefix = config_getstring(IMAPOPT_ADDRESSBOOKPREFIX);

    p = tgt->mboxname;
    siz = MAX_MAILBOX_BUFFER;
    if (tgt->user) {
	len = snprintf(p, siz, "user");
	p += len;
	siz -= len;

	if (tgt->userlen) {
	    len = snprintf(p, siz, ".%.*s", tgt->userlen, tgt->user);
	    p += len;
	    siz -= len;
	}
    }

    len = snprintf(p, siz, "%s%s", p != tgt->mboxname ? "." : "", prefix);
    p += len;
    siz -= len;

    if (tgt->collection) {
	snprintf(p, siz, ".%.*s", tgt->collen, tgt->collection);
    }

    return 0;
}


/* Perform a COPY/MOVE request
 *
 * preconditions:
 *   CARDDAV:supported-address-data
 *   CARDDAV:valid-address-data
 *   CARDDAV:no-uid-conflict (DAV:href)
 *   CARDDAV:addressbook-collection-location-ok
 *   CARDDAV:max-resource-size
 */
static int carddav_copy(struct transaction_t *txn,
			struct mailbox *src_mbox, struct index_record *src_rec,
			struct mailbox *dest_mbox, const char *dest_rsrc,
			unsigned overwrite, unsigned flags)
{
    int ret;
    const char *msg_base = NULL;
    unsigned long msg_size = 0;
    VObject *vcard;

    /* Load message containing the resource and parse vCard data */
    mailbox_map_message(src_mbox, src_rec->uid, &msg_base, &msg_size);
    vcard = Parse_MIME(msg_base + src_rec->header_size,
		       src_rec->size - src_rec->header_size);
    mailbox_unmap_message(src_mbox, src_rec->uid, &msg_base, &msg_size);

    if (!vcard) {
	txn->error.precond = CARDDAV_VALID_DATA;
	return HTTP_FORBIDDEN;
    }

    /* Finished our initial read of source mailbox */
    mailbox_unlock_index(src_mbox, NULL);

    /* Store source resource at destination */
    ret = store_resource(txn, vcard, dest_mbox, dest_rsrc, auth_carddavdb,
			 overwrite, flags);

    cleanVObject(vcard);
    cleanStrTbl();

    return ret;
}


/* Perform a PUT request
 *
 * preconditions:
 *   CARDDAV:valid-address-data
 *   CARDDAV:no-uid-conflict (DAV:href)
 *   CARDDAV:max-resource-size
 */
static int carddav_put(struct transaction_t *txn, struct mailbox *mailbox,
		       unsigned flags)
{
    int ret;
    VObject *vcard = NULL;

    /* Parse and validate the vCard data */
    vcard = Parse_MIME(buf_cstring(&txn->req_body), buf_len(&txn->req_body));
    if (!vcard || strcmp(vObjectName(vcard), "VCARD")) {
	txn->error.precond = CARDDAV_VALID_DATA;
	ret = HTTP_FORBIDDEN;
	goto done;
    }

    /* Store resource at target */
    ret = store_resource(txn, vcard, mailbox, txn->req_tgt.resource,
			 auth_carddavdb, OVERWRITE_CHECK, flags);

  done:
    if (vcard) {
	cleanVObject(vcard);
	cleanStrTbl();
    }

    return ret;
}


static int report_card_query(struct transaction_t *txn,
			     xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int ret = 0;
    xmlNodePtr node;

    fctx->davdb = auth_carddavdb;
    fctx->lookup_resource = (db_lookup_proc_t) &carddav_lookup_resource;
    fctx->foreach_resource = (db_foreach_proc_t) &carddav_foreach;
    fctx->proc_by_resource = &propfind_by_resource;

    /* Parse children element of report */
    for (node = inroot->children; node; node = node->next) {
	if (node->type == XML_ELEMENT_NODE) {
	    if (!xmlStrcmp(node->name, BAD_CAST "filter")) {
		txn->error.precond = CARDDAV_SUPP_FILTER;
		return HTTP_FORBIDDEN;
	    }
	}
    }

    if (fctx->depth > 0) {
	/* Calendar collection(s) */
	if (txn->req_tgt.collection) {
	    /* Add response for target calendar collection */
	    propfind_by_collection(txn->req_tgt.mboxname, 0, 0, fctx);
	}
	else {
	    /* Add responses for all contained calendar collections */
	    strlcat(txn->req_tgt.mboxname, ".%", sizeof(txn->req_tgt.mboxname));
	    mboxlist_findall(NULL,  /* internal namespace */
			     txn->req_tgt.mboxname, 1, httpd_userid, 
			     httpd_authstate, propfind_by_collection, fctx);
	}

	ret = *fctx->ret;
    }

    return ret;
}


static int report_card_multiget(struct transaction_t *txn,
				xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int r, ret = 0;
    struct request_target_t tgt;
    struct mailbox *mailbox = NULL;
    xmlNodePtr node;
    struct buf uri = BUF_INITIALIZER;

    memset(&tgt, 0, sizeof(struct request_target_t));
    tgt.namespace = URL_NS_CALENDAR;

    /* Get props for each href */
    for (node = inroot->children; node; node = node->next) {
	if ((node->type == XML_ELEMENT_NODE) &&
	    !xmlStrcmp(node->name, BAD_CAST "href")) {
	    xmlChar *href = xmlNodeListGetString(inroot->doc, node->children, 1);
	    int len = xmlStrlen(href);
	    struct carddav_data *cdata;

	    buf_ensure(&uri, len);
	    xmlURIUnescapeString((const char *) href, len, uri.s);

	    /* Parse the path */
	    if ((r = carddav_parse_path(uri.s, &tgt, fctx->errstr))) {
		ret = r;
		goto done;
	    }

	    fctx->req_tgt = &tgt;

	    /* Check if we already have this mailbox open */
	    if (!mailbox || strcmp(mailbox->name, tgt.mboxname)) {
		if (mailbox) mailbox_unlock_index(mailbox, NULL);

		/* Open mailbox for reading */
		if ((r = http_mailbox_open(tgt.mboxname, &mailbox, LOCK_SHARED))) {
		    syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
			   tgt.mboxname, error_message(r));
		    txn->error.desc = error_message(r);
		    ret = HTTP_SERVER_ERROR;
		    goto done;
		}

		fctx->mailbox = mailbox;
	    }

	    /* Find message UID for the resource */
	    carddav_lookup_resource(auth_carddavdb,
				   tgt.mboxname, tgt.resource, 0, &cdata);
	    cdata->dav.resource = tgt.resource;
	    /* XXX  Check errors */

	    propfind_by_resource(fctx, cdata);
	}
    }

  done:
    if (mailbox) mailbox_unlock_index(mailbox, NULL);
    buf_free(&uri);

    return ret;
}



/* Store the vCard data in the specified addressbook/resource */
static int store_resource(struct transaction_t *txn, VObject *vcard,
			  struct mailbox *mailbox, const char *resource,
			  struct carddav_db *carddavdb, int overwrite,
			  unsigned flags)
{
    int ret = HTTP_CREATED, r;
    VObjectIterator i;
    struct carddav_data *cdata;
    FILE *f = NULL;
    struct stagemsg *stage;
    const char *version = NULL, *uid = NULL, *fullname = NULL, *nickname = NULL;
    uquota_t size;
    time_t now = time(NULL);
    char datestr[80];
    struct appendstate as;

    /* Fetch some important properties */
    initPropIterator(&i, vcard);
    while (moreIteration(&i)) {
	VObject *prop = nextVObject(&i);
	const char *name = vObjectName(prop);

	syslog(LOG_INFO, "%s: %u", name, vObjectValueType(prop));
	if (!strcmp(name, "VERSION")) {
	    version = fakeCString(vObjectUStringZValue(prop));
	    if (strcmp(version, "3.0")) {
		txn->error.precond = CARDDAV_SUPP_DATA;
		return HTTP_FORBIDDEN;
	    }
	}
	else if (!strcmp(name, "UID")) {
	    uid = fakeCString(vObjectUStringZValue(prop));
	}
	else if (!strcmp(name, "FN")) {
	    fullname = fakeCString(vObjectUStringZValue(prop));
	}
	if (!strcmp(name, "NICKNAME")) {
	    nickname = fakeCString(vObjectUStringZValue(prop));
	}
    }

    /* Sanity check data */
    if (!version || !uid || !fullname) {
	txn->error.precond = CARDDAV_VALID_DATA;
	return HTTP_FORBIDDEN;
    }

    /* Check for existing vCard UID */
    carddav_lookup_uid(carddavdb, uid, 0, &cdata);
    if (cdata->dav.mailbox && !strcmp(cdata->dav.mailbox, mailbox->name) &&
	strcmp(cdata->dav.resource, resource)) {
	/* CARDDAV:no-uid-conflict */
	txn->error.precond = CARDDAV_UID_CONFLICT;
	assert(!buf_len(&txn->buf));
	buf_printf(&txn->buf, "/addressbooks/user/%s/%s/%s",
		   mboxname_to_userid(cdata->dav.mailbox),
		   strrchr(cdata->dav.mailbox, '.')+1, cdata->dav.resource);
	txn->error.resource = buf_cstring(&txn->buf);
	return HTTP_FORBIDDEN;
    }

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox->name, now, 0, &stage))) {
	syslog(LOG_ERR, "append_newstage(%s) failed", mailbox->name);
	txn->error.desc = "append_newstage() failed\r\n";
	return HTTP_SERVER_ERROR;
    }

    /* Create iMIP header for resource */

    /* XXX  This needs to be done via an LDAP/DB lookup */
    fprintf(f, "From: %s <>\r\n", httpd_userid);

    fprintf(f, "Subject: %s\r\n", fullname);

    rfc822date_gen(datestr, sizeof(datestr), now);  /* Use REV? */

    fprintf(f, "Date: %s\r\n", datestr);

    fprintf(f, "Message-ID: <%s@%s>\r\n", uid, config_servername);

    fprintf(f, "Content-Type: text/vcard; charset=utf-8\r\n");

    fprintf(f, "Content-Length: %u\r\n", buf_len(&txn->req_body));
    fprintf(f, "Content-Disposition: inline; filename=\"%s\"\r\n", resource);

    /* XXX  Check domain of data and use appropriate CTE */

    fprintf(f, "MIME-Version: 1.0\r\n");
    fprintf(f, "\r\n");

    /* Write the vCard data to the file */
    fprintf(f, "%s", buf_cstring(&txn->req_body));
    size = ftell(f);

    fclose(f);


    /* Prepare to append the iMIP message to calendar mailbox */
    if ((r = append_setup(&as, mailbox->name, NULL, NULL, 0, size))) {
	syslog(LOG_ERR, "append_setup(%s) failed: %s",
	       mailbox->name, error_message(r));
	ret = HTTP_SERVER_ERROR;
	txn->error.desc = "append_setup() failed\r\n";
    }
    else {
	struct body *body = NULL;

	/* Append the iMIP file to the calendar mailbox */
	if ((r = append_fromstage(&as, &body, stage, now, NULL, 0, 0))) {
	    syslog(LOG_ERR, "append_fromstage() failed");
	    ret = HTTP_SERVER_ERROR;
	    txn->error.desc = "append_fromstage() failed\r\n";
	}
	if (body) message_free_body(body);

	if (r) append_abort(&as);
	else {
	    /* Commit the append to the calendar mailbox */
	    if ((r = append_commit(&as, size, NULL, NULL, NULL, &mailbox))) {
		syslog(LOG_ERR, "append_commit() failed");
		ret = HTTP_SERVER_ERROR;
		txn->error.desc = "append_commit() failed\r\n";
	    }
	    else {
		/* append_commit() returns a write-locked index */
		struct index_record newrecord, oldrecord, *expunge;

		/* Read index record for new message (always the last one) */
		mailbox_read_index_record(mailbox, mailbox->i.num_records,
					  &newrecord);

		/* Find message UID for the current resource, if exists */
		carddav_lookup_resource(carddavdb,
				       mailbox->name, resource, 1, &cdata);
		/* XXX  check for errors */

		if (cdata->dav.imap_uid) {
		    /* Now that we have the replacement message in place
		       and the mailbox locked, re-read the old record
		       and see if we should overwrite it.  Either way,
		       one of our records will have to be expunged.
		    */
		    int userflag;

		    ret = (flags & PREFER_REP) ? HTTP_OK : HTTP_NO_CONTENT;

		    /* Fetch index record for the resource */
		    r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid,
						  &oldrecord);

		    if (overwrite == OVERWRITE_CHECK) {
			/* Check any preconditions */
			const char *etag = message_guid_encode(&oldrecord.guid);
			time_t lastmod = oldrecord.internaldate;
			int precond = check_precond(txn, cdata,
						    etag, lastmod, 0);

			overwrite = (precond == HTTP_OK);
		    }

		    if (overwrite) {
			/* Keep new resource - expunge the old one */
			expunge = &oldrecord;
		    }
		    else {
			/* Keep old resource - expunge the new one */
			expunge = &newrecord;
			ret = HTTP_PRECOND_FAILED;
		    }

		    /* Perform the actual expunge */
		    r = mailbox_user_flag(mailbox, DFLAG_UNBIND,  &userflag);
		    if (!r) {
			expunge->user_flags[userflag/32] |= 1<<(userflag&31);
			expunge->system_flags |= FLAG_EXPUNGED | FLAG_UNLINKED;
			r = mailbox_rewrite_index_record(mailbox, expunge);
		    }
		    if (r) {
			syslog(LOG_ERR, "expunging record (%s) failed: %s",
			       mailbox->name, error_message(r));
			txn->error.desc = error_message(r);
			ret = HTTP_SERVER_ERROR;
		    }
		}

		if (!r) {
		    /* Create mapping entry from resource name to UID */
		    cdata->dav.mailbox = mailbox->name;
		    cdata->dav.resource = resource;
		    cdata->dav.imap_uid = newrecord.uid;
		    cdata->vcard_uid = uid;
		    cdata->fullname = fullname;
		    cdata->nickname = nickname;

		    if (!cdata->dav.creationdate) cdata->dav.creationdate = now;

		    carddav_write(carddavdb, cdata, 1);
		    /* XXX  check for errors, if this fails, backout changes */

		    /* Tell client about the new resource */
		    txn->resp_body.etag = message_guid_encode(&newrecord.guid);

		    if (flags & PREFER_REP) {
			struct resp_body_t *resp_body = &txn->resp_body;

			resp_body->loc = txn->req_tgt.path;
			resp_body->type = "text/calendar; charset=utf-8";
			resp_body->len = buf_len(&txn->req_body);

			/* vCard data in response should not be transformed */
			txn->flags.cc |= CC_NOTRANSFORM;

			write_body(ret, txn,
				   buf_cstring(&txn->req_body), resp_body->len);
			ret = 0;
		    }
		}

		/* need to close mailbox returned to us by append_commit */
		mailbox_close(&mailbox);
	    }
	}
    }

    append_removestage(stage);

    return ret;
}
