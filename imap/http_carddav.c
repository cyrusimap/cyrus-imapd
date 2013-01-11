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

enum {
    OVERWRITE_CHECK = -1,
    OVERWRITE_NO,
    OVERWRITE_YES
};

static struct carddav_db *auth_carddavdb = NULL;

static void my_carddav_init(struct buf *serverinfo);
static void my_carddav_auth(const char *userid);
static void my_carddav_reset(void);
static void my_carddav_shutdown(void);

static int carddav_parse_path(struct request_target_t *tgt, const char **errstr);

static int carddav_put(struct transaction_t *txn, struct mailbox *mailbox,
		       unsigned flags);

static int report_card_query(struct transaction_t *txn, xmlNodePtr inroot,
			     struct propfind_ctx *fctx);
static int report_card_multiget(struct transaction_t *txn, xmlNodePtr inroot,
				struct propfind_ctx *fctx);

static int meth_copy(struct transaction_t *txn, void *params);
static int meth_delete(struct transaction_t *txn, void *params);
static int meth_post(struct transaction_t *txn, void *params);
static int store_resource(struct transaction_t *txn, VObject *vcard,
			  struct mailbox *mailbox, const char *resource,
			  struct carddav_db *carddavdb, int overwrite,
			  unsigned flags);
static struct meth_params carddav_params = {
    "text/vcard; charset=utf-8",
    &carddav_parse_path,
    &check_precond,
    (void **) &auth_carddavdb,
    (lookup_proc_t) &carddav_lookup_resource,
    (foreach_proc_t) &carddav_foreach,
    (write_proc_t) &carddav_write,
    (delete_proc_t) &carddav_delete,
    NULL,
    { MBTYPE_ADDRESSBOOK, NULL, NULL, 0 },
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
const struct namespace_t namespace_addressbook = {
    URL_NS_ADDRESSBOOK, "/addressbooks", "/.well-known/carddav", 1 /* auth */,
    (ALLOW_READ | ALLOW_POST | ALLOW_WRITE | ALLOW_DAV | ALLOW_CARD),
    &my_carddav_init, &my_carddav_auth, my_carddav_reset, &my_carddav_shutdown,
    { 
	{ &meth_acl,		&carddav_params },	/* ACL		*/
	{ &meth_copy,		NULL },			/* COPY		*/
	{ &meth_delete,		NULL },			/* DELETE	*/
	{ &meth_get_dav,	&carddav_params },	/* GET		*/
	{ &meth_get_dav,	&carddav_params },	/* HEAD		*/
	{ &meth_lock,		&carddav_params },	/* LOCK		*/
	{ NULL,			NULL },			/* MKCALENDAR	*/
	{ &meth_mkcol,		&carddav_params },	/* MKCOL	*/
	{ &meth_copy,		NULL },			/* MOVE		*/
	{ &meth_options,	NULL },			/* OPTIONS	*/
	{ &meth_post,		&carddav_params },	/* POST		*/
	{ &meth_propfind,	&carddav_params },	/* PROPFIND	*/
	{ &meth_proppatch,	&carddav_params },	/* PROPPATCH	*/
	{ &meth_put,		&carddav_params },	/* PUT		*/
	{ &meth_report,		&carddav_params },	/* REPORT	*/
	{ &meth_unlock,		&carddav_params } 	/* UNLOCK	*/
    }
};


static void my_carddav_init(struct buf *serverinfo)
{
    if (!config_getstring(IMAPOPT_ADDRESSBOOKPREFIX)) {
	fatal("Required 'addressbookprefix' option is not set", EC_CONFIG);
    }

    carddav_init();

    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	buf_printf(serverinfo, " libicalvcal/%s", ICAL_VERSION);
    }
}


static void my_carddav_auth(const char *userid)
{
    if (config_mupdate_server && !config_getstring(IMAPOPT_PROXYSERVERS)) {
	/* proxy-only server - won't have DAV databases */
	return;
    }
    else if (httpd_userisadmin ||
	     global_authisa(httpd_authstate, IMAPOPT_PROXYSERVERS)) {
	/* admin or proxy from frontend - won't have DAV database */
	return;
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
static int carddav_parse_path(struct request_target_t *tgt, const char **errstr)
{
    char *p = tgt->path;
    size_t len, siz;
    static const char *prefix = NULL;

    if (!*p || !*++p) return 0;

    /* Sanity check namespace */
    len = strcspn(p, "/");
    if (len != strlen(namespace_addressbook.prefix)-1 ||
	strncmp(namespace_addressbook.prefix+1, p, len)) {
	*errstr = "Namespace mismatch request target path";
	return HTTP_FORBIDDEN;
    }

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



/* Perform a COPY/MOVE request
 *
 * preconditions:
 *   CARDDAV:supported-address-data
 *   CARDDAV:valid-address-data
 *   CARDDAV:no-uid-conflict (DAV:href)
 *   CARDDAV:addressbook-collection-location-ok
 *   CARDDAV:max-resource-size
 */
static int meth_copy(struct transaction_t *txn,
		     void *params __attribute__((unused)))
{
    int ret = HTTP_CREATED, r, precond, rights, overwrite = OVERWRITE_YES;
    const char **hdr;
    struct request_target_t dest;  /* Parsed destination URL */
    char *server, *acl;
    struct backend *src_be = NULL, *dest_be = NULL;
    struct mailbox *src_mbox = NULL, *dest_mbox = NULL;
    struct carddav_data *cdata;
    struct index_record src_rec;
    const char *etag = NULL;
    time_t lastmod = 0;
    const char *msg_base = NULL;
    unsigned long msg_size = 0;
    VObject *vcard = NULL;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Make sure source is a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_DAV)) return HTTP_NOT_ALLOWED;

    /* Parse the source path */
    if ((r = carddav_parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* We don't yet handle COPY/MOVE on collections */
    if (!txn->req_tgt.resource) return HTTP_NOT_ALLOWED;

    /* Check for mandatory Destination header */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Destination"))) {
	txn->error.desc = "Missing Destination header\r\n";
	return HTTP_BAD_REQUEST;
    }

    /* Parse destination URI */
    if ((r = parse_uri(METH_UNKNOWN, hdr[0], &dest, &txn->error.desc))) return r;

    /* Make sure source and dest resources are NOT the same */
    if (!strcmp(txn->req_tgt.path, dest.path)) {
	txn->error.desc = "Source and destination resources are the same\r\n";
	return HTTP_FORBIDDEN;
    }

    /* Parse the destination path */
    if ((r = carddav_parse_path(&dest, &txn->error.desc))) return r;
    dest.namespace = txn->req_tgt.namespace;

    /* We don't yet handle COPY/MOVE on collections */
    if (!dest.resource) return HTTP_NOT_ALLOWED;

    /* Locate the source mailbox */
    if ((r = http_mlookup(txn->req_tgt.mboxname, &server, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);

	switch (r) {
	case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
	case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
	default: return HTTP_SERVER_ERROR;
	}
    }

    /* Check ACL for current user on source mailbox */
    rights = acl ? cyrus_acl_myrights(httpd_authstate, acl) : 0;
    if (((rights & DACL_READ) != DACL_READ) ||
	((txn->meth == METH_MOVE) && !(rights & DACL_RMRSRC))) {
	/* DAV:need-privileges */
	txn->error.precond = DAV_NEED_PRIVS;
	txn->error.resource = txn->req_tgt.path;
	txn->error.rights =
	    (rights & DACL_READ) != DACL_READ ? DACL_READ : DACL_RMRSRC;
	return HTTP_FORBIDDEN;
    }

    if (server) {
	/* Remote source mailbox */
	src_be = proxy_findserver(server, &http_protocol, httpd_userid,
				  &backend_cached, NULL, NULL, httpd_in);
	if (!src_be) return HTTP_UNAVAILABLE;
    }

    /* Locate the destination mailbox */
    if ((r = http_mlookup(dest.mboxname, &server, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       dest.mboxname, error_message(r));
	txn->error.desc = error_message(r);

	switch (r) {
	case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
	case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
	default: return HTTP_SERVER_ERROR;
	}
    }

    /* Check ACL for current user on destination */
    rights = acl ? cyrus_acl_myrights(httpd_authstate, acl) : 0;
    if (!(rights & DACL_ADDRSRC) || !(rights & DACL_WRITECONT)) {
	/* DAV:need-privileges */
	txn->error.precond = DAV_NEED_PRIVS;
	txn->error.resource = dest.path;
	txn->error.rights =
	    !(rights & DACL_ADDRSRC) ? DACL_ADDRSRC : DACL_WRITECONT;
	return HTTP_FORBIDDEN;
    }

    if (server) {
	/* Remote destination mailbox */
	dest_be = proxy_findserver(server, &http_protocol, httpd_userid,
				   &backend_cached, NULL, NULL, httpd_in);
	if (!dest_be) return HTTP_UNAVAILABLE;
    }

    if (src_be) {
	/* Remote source mailbox */
	/* XXX  Currently only supports standard Murder */

	if (!dest_be) return HTTP_NOT_ALLOWED;

	/* Replace cached Destination header with just the absolute path */
	hdr = spool_getheader(txn->req_hdrs, "Destination");
	strcpy((char *) hdr[0], dest.path);

	if (src_be == dest_be) {
	    /* Simply send the COPY to the backend */
	    return http_pipe_req_resp(src_be, txn);
	}

	/* This is the harder case: GET from source and PUT on destination */
	return http_proxy_copy(src_be, dest_be, txn);
    }

    /* Local Mailbox */

    /* Open dest mailbox for reading */
    if ((r = mailbox_open_irl(dest.mboxname, &dest_mbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       dest.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the dest resource, if exists */
    carddav_lookup_resource(auth_carddavdb,
			   dest.mboxname, dest.resource, 0, &cdata);
    /* XXX  Check errors */

    /* Finished our initial read of dest mailbox */
    mailbox_unlock_index(dest_mbox, NULL);

    /* Check any preconditions on destination */
    if ((hdr = spool_getheader(txn->req_hdrs, "Overwrite")) &&
	!strcmp(hdr[0], "F")) {

	if (cdata->dav.rowid) {
	    /* Don't overwrite the destination resource */
	    ret = HTTP_PRECOND_FAILED;
	    goto done;
	}
	overwrite = OVERWRITE_NO;
    }

    /* Open source mailbox for reading */
    if ((r = http_mailbox_open(txn->req_tgt.mboxname, &src_mbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the source resource */
    carddav_lookup_resource(auth_carddavdb, txn->req_tgt.mboxname,
			   txn->req_tgt.resource, 0, &cdata);
    if (!cdata->dav.rowid) {
	ret = HTTP_NOT_FOUND;
	goto done;
    }

    if (cdata->dav.imap_uid) {
	/* Mapped URL - Fetch index record for the resource */
	r = mailbox_find_index_record(src_mbox, cdata->dav.imap_uid, &src_rec);
	if (r) {
	    txn->error.desc = error_message(r);
	    ret = HTTP_SERVER_ERROR;
	    goto done;
	}

	etag = message_guid_encode(&src_rec.guid);
	lastmod = src_rec.internaldate;
    }
    else {
	/* Unmapped URL (empty resource) */
	etag = NULL_ETAG;
	lastmod = cdata->dav.creationdate;
    }

    /* Check any preconditions on source */
    precond = check_precond(txn, cdata, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
	break;

    case HTTP_LOCKED:
	txn->error.precond = DAV_NEED_LOCK_TOKEN;
	txn->error.resource = txn->req_tgt.path;

    default:
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    /* Load message containing the resource and parse iCal data */
    mailbox_map_message(src_mbox, src_rec.uid, &msg_base, &msg_size);
    vcard = Parse_MIME(msg_base + src_rec.header_size,
		       src_rec.size - src_rec.header_size);
    mailbox_unmap_message(src_mbox, src_rec.uid, &msg_base, &msg_size);

    /* Finished our initial read of source mailbox */
    mailbox_unlock_index(src_mbox, NULL);

    /* Store source resource at destination */
    ret = store_resource(txn, vcard, dest_mbox, dest.resource, auth_carddavdb,
			 overwrite, 0);

    /* For MOVE, we need to delete the source resource */
    if ((txn->meth == METH_MOVE) &&
	(ret == HTTP_CREATED || ret == HTTP_NO_CONTENT)) {
	/* Lock source mailbox */
	mailbox_lock_index(src_mbox, LOCK_EXCLUSIVE);

	/* Find message UID for the source resource */
	carddav_lookup_resource(auth_carddavdb, txn->req_tgt.mboxname,
			       txn->req_tgt.resource, 1, &cdata);
	/* XXX  Check errors */

	/* Fetch index record for the source resource */
	if (cdata->dav.imap_uid &&
	    !mailbox_find_index_record(src_mbox, cdata->dav.imap_uid,
				       &src_rec)) {

	    /* Expunge the source message */
	    src_rec.system_flags |= FLAG_EXPUNGED;
	    if ((r = mailbox_rewrite_index_record(src_mbox, &src_rec))) {
		syslog(LOG_ERR, "expunging src record (%s) failed: %s",
		       txn->req_tgt.mboxname, error_message(r));
		txn->error.desc = error_message(r);
		ret = HTTP_SERVER_ERROR;
		goto done;
	    }
	}

	/* Delete mapping entry for source resource name */
	carddav_delete(auth_carddavdb, cdata->dav.rowid, 1);
    }

  done:
    if (ret == HTTP_CREATED) {
	/* Tell client where to find the new resource */
	hdr = spool_getheader(txn->req_hdrs, "Destination");
	txn->location = hdr[0];
    }
    else {
	/* Don't confuse client by providing ETag of Destination resource */
	txn->resp_body.etag = NULL;
    }

    if (vcard) {
	cleanVObject(vcard);
	cleanStrTbl();
    }
    if (dest_mbox) mailbox_close(&dest_mbox);
    if (src_mbox) mailbox_unlock_index(src_mbox, NULL);

    return ret;
}


/* Perform a DELETE request */
static int meth_delete(struct transaction_t *txn,
		       void *params __attribute__((unused)))
{
    int ret = HTTP_NO_CONTENT, r, precond, rights;
    char *server, *acl;
    struct mailbox *mailbox = NULL;
    struct carddav_data *cdata;
    struct index_record record;
    const char *etag = NULL, *userid;
    time_t lastmod = 0;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = carddav_parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* Construct userid corresponding to mailbox */
    userid = mboxname_to_userid(txn->req_tgt.mboxname);

    /* Locate the mailbox */
    if ((r = http_mlookup(txn->req_tgt.mboxname, &server, &acl, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);

	switch (r) {
	case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
	case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
	default: return HTTP_SERVER_ERROR;
	}
    }

    /* Check ACL for current user */
    rights = acl ? cyrus_acl_myrights(httpd_authstate, acl) : 0;
    if ((txn->req_tgt.resource && !(rights & DACL_RMRSRC)) ||
	!(rights & DACL_RMCOL)) {
	/* DAV:need-privileges */
	txn->error.precond = DAV_NEED_PRIVS;
	txn->error.resource = txn->req_tgt.path;
	txn->error.rights = txn->req_tgt.resource ? DACL_RMRSRC : DACL_RMCOL;
	return HTTP_FORBIDDEN;
    }

    if (server) {
	/* Remote mailbox */
	struct backend *be;

	be = proxy_findserver(server, &http_protocol, httpd_userid,
			      &backend_cached, NULL, NULL, httpd_in);
	if (!be) return HTTP_UNAVAILABLE;

	return http_pipe_req_resp(be, txn);
    }

    /* Local Mailbox */

    if (!txn->req_tgt.resource) {
	/* DELETE collection */
	r = mboxlist_deletemailbox(txn->req_tgt.mboxname,
				   httpd_userisadmin || httpd_userisproxyadmin,
				   httpd_userid, httpd_authstate,
				   1, 0, 0);

	if (!r) carddav_delmbox(auth_carddavdb, txn->req_tgt.mboxname, 0);
	else if (r == IMAP_PERMISSION_DENIED) ret = HTTP_FORBIDDEN;
	else if (r == IMAP_MAILBOX_NONEXISTENT) ret = HTTP_NOT_FOUND;
	else if (r) ret = HTTP_SERVER_ERROR;

	return ret;
    }


    /* DELETE resource */

    /* Open mailbox for writing */
    if ((r = http_mailbox_open(txn->req_tgt.mboxname, &mailbox, LOCK_EXCLUSIVE))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Find message UID for the resource, if exists */
    carddav_lookup_resource(auth_carddavdb, txn->req_tgt.mboxname,
			   txn->req_tgt.resource, 1, &cdata);
    if (!cdata->dav.rowid) {
	ret = HTTP_NOT_FOUND;
	goto done;
    }

    memset(&record, 0, sizeof(struct index_record));
    if (cdata->dav.imap_uid) {
	/* Mapped URL - Fetch index record for the resource */
	r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record);
	if (r) {
	    txn->error.desc = error_message(r);
	    ret = HTTP_SERVER_ERROR;
	    goto done;
	}

	etag = message_guid_encode(&record.guid);
	lastmod = record.internaldate;
    }
    else {
	/* Unmapped URL (empty resource) */
	etag = NULL_ETAG;
	lastmod = cdata->dav.creationdate;
    }

    /* Check any preconditions */
    precond = check_precond(txn, cdata, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
	break;

    case HTTP_LOCKED:
	txn->error.precond = DAV_NEED_LOCK_TOKEN;
	txn->error.resource = txn->req_tgt.path;

    default:
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    if (record.uid) {
	/* Expunge the resource */
	record.system_flags |= FLAG_EXPUNGED;

	if ((r = mailbox_rewrite_index_record(mailbox, &record))) {
	    syslog(LOG_ERR, "expunging record (%s) failed: %s",
		   txn->req_tgt.mboxname, error_message(r));
	    txn->error.desc = error_message(r);
	    ret = HTTP_SERVER_ERROR;
	    goto done;
	}
    }

    /* Delete mapping entry for resource name */
    carddav_delete(auth_carddavdb, cdata->dav.rowid, 1);

  done:
    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    return ret;
}


/* Perform a POST request */
static int meth_post(struct transaction_t *txn, void *params)
{
    static unsigned post_count = 0;
    int r, ret;
    size_t len;
    char *p;

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Make sure its a DAV resource */
    if (!(txn->req_tgt.allow & ALLOW_WRITE)) return HTTP_NOT_ALLOWED; 

    /* Parse the path */
    if ((r = carddav_parse_path(&txn->req_tgt, &txn->error.desc))) return r;

    /* We only handle POST on calendar collections */
    if (!txn->req_tgt.collection ||
	txn->req_tgt.resource) return HTTP_NOT_ALLOWED;

    /* POST to regular calendar collection */

    /* Append a unique resource name to URL path and perform a PUT */
    len = strlen(txn->req_tgt.path);
    p = txn->req_tgt.path + len;

    snprintf(p, MAX_MAILBOX_PATH - len, "%x-%d-%ld-%u.ics",
	     strhash(txn->req_tgt.path), getpid(), time(0), post_count++);

    /* Tell client where to find the new resource */
    txn->location = txn->req_tgt.path;

    ret = meth_put(txn, params);

    if (ret != HTTP_CREATED) txn->location = NULL;

    return ret;
}


static int report_card_query(struct transaction_t *txn,
			     xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int ret = 0;
    xmlNodePtr node;

    fctx->davdb = auth_carddavdb;
    fctx->lookup_resource = (lookup_proc_t) &carddav_lookup_resource;
    fctx->foreach_resource = (foreach_proc_t) &carddav_foreach;
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
	    strlcpy(tgt.path, uri.s, sizeof(tgt.path));
	    if ((r = carddav_parse_path(&tgt, fctx->errstr))) {
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

    fprintf(f, "Content-Type: text/vcard; charset=UTF-8\r\n");

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
			int precond = check_precond(txn, cdata, etag, lastmod);

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
