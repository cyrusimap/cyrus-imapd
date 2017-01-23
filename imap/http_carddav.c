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

#include <libxml/tree.h>
#include <libxml/uri.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "acl.h"
#include "append.h"
#include "carddav_db.h"
#include "exitcodes.h"
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
#include "smtpclient.h"
#include "spool.h"
#include "stristr.h"
#include "times.h"
#include "util.h"
#include "version.h"
#include "vparse.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

static struct carddav_db *auth_carddavdb = NULL;

static struct carddav_db *my_carddav_open(struct mailbox *mailbox);
static void my_carddav_close(struct carddav_db *carddavdb);
static void my_carddav_init(struct buf *serverinfo);
static void my_carddav_auth(const char *userid);
static void my_carddav_reset(void);
static void my_carddav_shutdown(void);

static int carddav_parse_path(const char *path,
			      struct request_target_t *tgt, const char **errstr);

static int carddav_copy(struct transaction_t *txn,
			struct mailbox *src_mbox, struct index_record *src_rec,
			struct mailbox *dest_mbox, const char *dest_rsrc,
			struct carddav_db *dest_davdb,
			unsigned overwrite, unsigned flags);
static int carddav_put(struct transaction_t *txn, 
		       struct mime_type_t *mime,
		       struct mailbox *mailbox,
		       struct carddav_db *carddavdb,
		       unsigned flags);

static int propfind_getcontenttype(const xmlChar *name, xmlNsPtr ns,
				   struct propfind_ctx *fctx, xmlNodePtr resp,
				   struct propstat propstat[], void *rock);
static int propfind_restype(const xmlChar *name, xmlNsPtr ns,
			    struct propfind_ctx *fctx, xmlNodePtr resp,
			    struct propstat propstat[], void *rock);
static int propfind_addrdata(const xmlChar *name, xmlNsPtr ns,
			     struct propfind_ctx *fctx, xmlNodePtr resp,
			     struct propstat propstat[], void *rock);
static int propfind_suppaddrdata(const xmlChar *name, xmlNsPtr ns,
				 struct propfind_ctx *fctx, xmlNodePtr resp,
				 struct propstat propstat[], void *rock);

static int report_card_query(struct transaction_t *txn, xmlNodePtr inroot,
			     struct propfind_ctx *fctx);
static int report_card_multiget(struct transaction_t *txn, xmlNodePtr inroot,
				struct propfind_ctx *fctx);

static int store_resource(struct transaction_t *txn, struct vparse_card *vcard,
			  struct mailbox *mailbox, const char *resource,
			  struct carddav_db *carddavdb, int overwrite,
			  unsigned flags);

static struct vparse_state *vcard_string_as_vparser(const char *str) {
    struct vparse_state *vparser;
    int vr;

    vparser = (struct vparse_state *) xzmalloc(sizeof(struct vparse_state));
    vparser->base = str;
    vr = vparse_parse(vparser, 0);
    if (vr) return NULL; // XXX report error

    return vparser;
}

static void free_vparser(void *vparser) {
    vparse_free((struct vparse_state *) vparser);
    free(vparser);
}

static struct mime_type_t carddav_mime_types[] = {
    /* First item MUST be the default type and storage format */
    { "text/vcard; charset=utf-8", "3.0", NULL, "vcf", NULL,
      (void * (*)(const char*)) &vcard_string_as_vparser,
      (void (*)(void *)) &free_vparser, NULL, NULL
    },
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

/* Array of supported REPORTs */
static const struct report_type_t carddav_reports[] = {

    /* WebDAV Versioning (RFC 3253) REPORTs */
    { "expand-property", NS_DAV, "multistatus", &report_expand_prop,
      DACL_READ, 0 },

    /* WebDAV Sync (RFC 6578) REPORTs */
    { "sync-collection", NS_DAV, "multistatus", &report_sync_col,
      DACL_READ, REPORT_NEED_MBOX | REPORT_NEED_PROPS },

    /* CardDAV (RFC 6352) REPORTs */
    { "addressbook-query", NS_CARDDAV, "multistatus", &report_card_query,
      DACL_READ, REPORT_NEED_MBOX },
    { "addressbook-multiget", NS_CARDDAV, "multistatus", &report_card_multiget,
      DACL_READ, REPORT_NEED_MBOX },

    { NULL, 0, NULL, NULL, 0, 0 }
};

/* Array of known "live" properties */
static const struct prop_entry carddav_props[] = {

    /* WebDAV (RFC 4918) properties */
    { "creationdate", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_creationdate, NULL, NULL },
    { "displayname", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_fromdb, proppatch_todb, NULL },
    { "getcontentlanguage", NS_DAV, PROP_ALLPROP | PROP_RESOURCE,
      propfind_fromhdr, NULL, "Content-Language" },
    { "getcontentlength", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getlength, NULL, NULL },
    { "getcontenttype", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getcontenttype, NULL, "Content-Type" },
    { "getetag", NS_DAV, PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getetag, NULL, NULL },
    { "getlastmodified", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_getlastmod, NULL, NULL },
    { "lockdiscovery", NS_DAV, PROP_ALLPROP | PROP_RESOURCE,
      propfind_lockdisc, NULL, NULL },
    { "resourcetype", NS_DAV,
      PROP_ALLPROP | PROP_COLLECTION | PROP_RESOURCE,
      propfind_restype, proppatch_restype, "addressbook" },
    { "supportedlock", NS_DAV, PROP_ALLPROP | PROP_RESOURCE,
      propfind_suplock, NULL, NULL },

    /* WebDAV Versioning (RFC 3253) properties */
    { "supported-report-set", NS_DAV, PROP_COLLECTION,
      propfind_reportset, NULL, (void *) carddav_reports },

    /* WebDAV ACL (RFC 3744) properties */
    { "owner", NS_DAV, PROP_COLLECTION | PROP_RESOURCE | PROP_EXPAND,
      propfind_owner, NULL, NULL },
    { "group", NS_DAV, 0, NULL, NULL, NULL },
    { "supported-privilege-set", NS_DAV, PROP_COLLECTION | PROP_RESOURCE,
      propfind_supprivset, NULL, NULL },
    { "current-user-privilege-set", NS_DAV, PROP_COLLECTION | PROP_RESOURCE,
      propfind_curprivset, NULL, NULL },
    { "acl", NS_DAV, PROP_COLLECTION | PROP_RESOURCE,
      propfind_acl, NULL, NULL },
    { "acl-restrictions", NS_DAV, PROP_COLLECTION | PROP_RESOURCE,
      propfind_aclrestrict, NULL, NULL },
    { "inherited-acl-set", NS_DAV, 0, NULL, NULL, NULL },
    { "principal-collection-set", NS_DAV, PROP_COLLECTION | PROP_RESOURCE,
      propfind_princolset, NULL, NULL },

    /* WebDAV Quota (RFC 4331) properties */
    { "quota-available-bytes", NS_DAV, PROP_COLLECTION,
      propfind_quota, NULL, NULL },
    { "quota-used-bytes", NS_DAV, PROP_COLLECTION,
      propfind_quota, NULL, NULL },

    /* WebDAV Current Principal (RFC 5397) properties */
    { "current-user-principal", NS_DAV,
      PROP_COLLECTION | PROP_RESOURCE | PROP_EXPAND,
      propfind_curprin, NULL, NULL },

    /* WebDAV POST (RFC 5995) properties */
    { "add-member", NS_DAV, PROP_COLLECTION,
      NULL,  /* Until Apple Contacts is fixed */ NULL, NULL },

    /* WebDAV Sync (RFC 6578) properties */
    { "sync-token", NS_DAV, PROP_COLLECTION,
      propfind_sync_token, NULL, NULL },

    /* CardDAV (RFC 6352) properties */
    { "address-data", NS_CARDDAV,
      PROP_RESOURCE | PROP_PRESCREEN | PROP_NEEDPROP,
      propfind_addrdata, NULL, NULL },
    { "addressbook-description", NS_CARDDAV, PROP_COLLECTION,
      propfind_fromdb, proppatch_todb, NULL },
    { "supported-address-data", NS_CARDDAV, PROP_COLLECTION,
      propfind_suppaddrdata, NULL, NULL },
    { "max-resource-size", NS_CARDDAV, 0, NULL, NULL, NULL },

    /* Apple Calendar Server properties */
    { "getctag", NS_CS, PROP_ALLPROP | PROP_COLLECTION,
      propfind_sync_token, NULL, NULL },

    { NULL, 0, 0, NULL, NULL, NULL }
};

static struct meth_params carddav_params = {
    carddav_mime_types,
    &carddav_parse_path,
    &check_precond,
    { (db_open_proc_t) &my_carddav_open,
      (db_close_proc_t) &my_carddav_close,
      (db_lookup_proc_t) &carddav_lookup_resource,
      (db_foreach_proc_t) &carddav_foreach,
      (db_write_proc_t) &carddav_write,
      (db_delete_proc_t) &carddav_delete,
      (db_delmbox_proc_t) &carddav_delmbox },
    NULL,					/* No ACL extensions */
    (copy_proc_t) &carddav_copy,
    NULL,		  	      		/* No special DELETE handling */
    { MBTYPE_ADDRESSBOOK, NULL, NULL, 0 },	/* No special MK* method */
    NULL,		  	      		/* No special POST handling */
    { CARDDAV_SUPP_DATA, (put_proc_t) &carddav_put },
    carddav_props,
    carddav_reports
};


/* Namespace for Carddav collections */
struct namespace_t namespace_addressbook = {
    URL_NS_ADDRESSBOOK, 0, "/dav/addressbooks", "/.well-known/carddav",
    1 /* auth */,
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


static struct carddav_db *my_carddav_open(struct mailbox *mailbox)
{
    if (httpd_userid && mboxname_userownsmailbox(httpd_userid, mailbox->name)) {
	return auth_carddavdb;
    }
    else {
	return carddav_open_mailbox(mailbox, CALDAV_CREATE);
    }
}


static void my_carddav_close(struct carddav_db *carddavdb)
{
    if (carddavdb && (carddavdb != auth_carddavdb)) carddav_close(carddavdb);
}


static void my_carddav_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_addressbook.enabled =
	config_httpmodules & IMAP_ENUM_HTTPMODULES_CARDDAV;

    if (!namespace_addressbook.enabled) return;

    if (!config_getstring(IMAPOPT_ADDRESSBOOKPREFIX)) {
	fatal("Required 'addressbookprefix' option is not set", EC_CONFIG);
    }

    carddav_init();

    namespace_principal.enabled = 1;
    namespace_principal.allow |= ALLOW_CARD;
}


#define DEFAULT_ADDRBOOK "Default"

static void my_carddav_auth(const char *userid)
{
    int r;
    struct buf boxbuf = BUF_INITIALIZER;
    char *mailboxname;

    if (httpd_userisadmin ||
	global_authisa(httpd_authstate, IMAPOPT_PROXYSERVERS)) {
	/* admin or proxy from frontend - won't have DAV database */
	return;
    }
    else if (config_mupdate_server && !config_getstring(IMAPOPT_PROXYSERVERS)) {
	/* proxy-only server - won't have DAV databases */
    }
    else {
	/* Open CardDAV DB for 'userid' */
	my_carddav_reset();
	auth_carddavdb = carddav_open_userid(userid, CARDDAV_CREATE);
	if (!auth_carddavdb) fatal("Unable to open CardDAV DB", EC_IOERR);
    }

    buf_setcstr(&boxbuf, config_getstring(IMAPOPT_ADDRESSBOOKPREFIX));

    mailboxname = mboxname_user_mbox(userid, buf_cstring(&boxbuf));

    /* Auto-provision an addressbook for 'userid' */
    r = mboxlist_lookup(mailboxname, NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	if (config_mupdate_server) {
	    /* Find location of INBOX */
	    char *inboxname = mboxname_user_mbox(userid, NULL);
	    mbentry_t *mbentry = NULL;

	    r = http_mlookup(inboxname, &mbentry, NULL);
	    free(inboxname);

	    if (!r && mbentry->server) {
		proxy_findserver(mbentry->server, &http_protocol, proxy_userid,
				 &backend_cached, NULL, NULL, httpd_in);
		mboxlist_entry_free(&mbentry);
		return;
	    }
	    mboxlist_entry_free(&mbentry);
	}
	else r = 0;

	/* will have been overwritten */
	free(mailboxname);
	mailboxname = mboxname_user_mbox(userid, buf_cstring(&boxbuf));

	/* XXX - set rights */
	r = mboxlist_createmailbox(mailboxname, MBTYPE_ADDRESSBOOK,
				   NULL, 0,
				   userid, httpd_authstate,
				   0, 0, 0, 0, NULL);
	if (r) syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
		      mailboxname, error_message(r));
    }
    free(mailboxname);
    if (r) return;

    /* Default addressbook */
    buf_setcstr(&boxbuf, config_getstring(IMAPOPT_ADDRESSBOOKPREFIX));
    buf_printf(&boxbuf, ".%s", DEFAULT_ADDRBOOK);
    mailboxname = mboxname_user_mbox(userid, buf_cstring(&boxbuf));
    buf_free(&boxbuf);
    r = mboxlist_lookup(mailboxname, NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
	/* XXX - set rights */
	r = mboxlist_createmailbox(mailboxname, MBTYPE_ADDRESSBOOK,
				   NULL, 0,
				   userid, httpd_authstate,
				   0, 0, 0, 0, NULL);
	if (r) syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
		      mailboxname, error_message(r));
    }
    free(mailboxname);
}


static void my_carddav_reset(void)
{
    if (auth_carddavdb) carddav_close(auth_carddavdb);
    auth_carddavdb = NULL;
}


static void my_carddav_shutdown(void)
{
    my_carddav_reset();
    carddav_done();
}


/* Parse request-target path in CardDAV namespace */
static int carddav_parse_path(const char *path,
			      struct request_target_t *tgt, const char **errstr)
{
    char *p;
    size_t len;
    struct mboxname_parts parts;
    struct buf boxbuf = BUF_INITIALIZER;

    /* Make a working copy of target path */
    strlcpy(tgt->path, path, sizeof(tgt->path));
    tgt->tail = tgt->path + strlen(tgt->path);

    p = tgt->path;

    /* Sanity check namespace */
    len = strlen(namespace_addressbook.prefix);
    if (strlen(p) < len ||
	strncmp(namespace_addressbook.prefix, p, len) ||
	(path[len] && path[len] != '/')) {
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
//	*errstr = "Too many segments in request target path";
	return HTTP_NOT_FOUND;
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

    mboxname_init_parts(&parts);

    if (tgt->user && tgt->userlen) {
        /* holy "avoid copying" batman */
        char *userid = xstrndup(tgt->user, tgt->userlen);
        mboxname_userid_to_parts(userid, &parts);
        free(userid);
    }

    buf_setcstr(&boxbuf, config_getstring(IMAPOPT_ADDRESSBOOKPREFIX));
    if (tgt->collen) {
        buf_putc(&boxbuf, '.');
        buf_appendmap(&boxbuf, tgt->collection, tgt->collen);
    }
    parts.box = buf_release(&boxbuf); /* tricky, we now need to free parts.box separately */

    mboxname_parts_to_internal(&parts, tgt->mboxname);

    free((char *) parts.box); /* n.b. casting away constness */
    mboxname_free_parts(&parts);

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
			struct carddav_db *dest_davdb,
			unsigned overwrite, unsigned flags)
{
    int r;
    struct buf msg_buf = BUF_INITIALIZER;
    struct vparse_state *vparser;

    /* Load message containing the resource and parse vCard data */
    r = mailbox_map_record(src_mbox, src_rec, &msg_buf);
    if (r) return r;
    vparser = vcard_string_as_vparser(buf_base(&msg_buf) + src_rec->header_size);
    buf_free(&msg_buf);

    if (!vparser || !vparser->card || !vparser->card->objects) {
	txn->error.precond = CARDDAV_VALID_DATA;
	return HTTP_FORBIDDEN;
    }

    /* Finished our initial read of source mailbox */
    mailbox_unlock_index(src_mbox, NULL);

    /* Store source resource at destination */
    r = store_resource(txn, vparser->card->objects, dest_mbox, dest_rsrc, dest_davdb,
			 overwrite, flags);

    free_vparser(vparser);

    return r;
}


/* Perform a PUT request
 *
 * preconditions:
 *   CARDDAV:valid-address-data
 *   CARDDAV:no-uid-conflict (DAV:href)
 *   CARDDAV:max-resource-size
 */
static int carddav_put(struct transaction_t *txn, 
		       struct mime_type_t *mime,
		       struct mailbox *mailbox,
		       struct carddav_db *davdb,
		       unsigned flags)
{
    int ret;
    struct vparse_state *vparser = NULL;

    /* Parse and validate the vCard data */
    vparser = mime->from_string(buf_cstring(&txn->req_body.payload));
    if (!vparser ||
	!vparser->card ||
	!vparser->card->objects ||
	!vparser->card->objects->type ||
	strcmp(vparser->card->objects->type, "vcard")) {
	txn->error.precond = CARDDAV_VALID_DATA;
	ret = HTTP_FORBIDDEN;
	goto done;
    }

    /* Store resource at target */
    ret = store_resource(txn, vparser->card->objects, mailbox, txn->req_tgt.resource,
			 davdb, OVERWRITE_CHECK, flags);

    if (flags & PREFER_REP) {
	struct resp_body_t *resp_body = &txn->resp_body;
	const char *data;

	switch (ret) {
	case HTTP_NO_CONTENT:
	    ret = HTTP_OK;

	case HTTP_CREATED:
	    /* Use the request data */
	    data = buf_cstring(&txn->req_body.payload);

	    /* Fill in Content-Type, Content-Length */
	    resp_body->type = mime->content_type;
	    resp_body->len = strlen(data);

	    /* Fill in Content-Location */
	    resp_body->loc = txn->req_tgt.path;

	    /* Fill in Expires and Cache-Control */
	    resp_body->maxage = 3600;	/* 1 hr */
	    txn->flags.cc = CC_MAXAGE
		| CC_REVALIDATE		/* don't use stale data */
		| CC_NOTRANSFORM;	/* don't alter vCard data */

	    /* Output current representation */
	    write_body(ret, txn, data, resp_body->len);
	    ret = 0;
	    break;

	default:
	    /* failure - do nothing */
	    break;
	}
    }

  done:
    if (vparser)
	free_vparser(vparser);

    return ret;
}


/* Callback to fetch DAV:getcontenttype */
static int propfind_getcontenttype(const xmlChar *name, xmlNsPtr ns,
				   struct propfind_ctx *fctx,
				   xmlNodePtr resp __attribute__((unused)),
				   struct propstat propstat[],
				   void *rock __attribute__((unused)))
{
    buf_setcstr(&fctx->buf, "text/vcard; charset=utf-8");

    xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
		 name, ns, BAD_CAST buf_cstring(&fctx->buf), 0);

    return 0;
}


/* Callback to fetch DAV:resourcetype */
static int propfind_restype(const xmlChar *name, xmlNsPtr ns,
			    struct propfind_ctx *fctx,
			    xmlNodePtr resp,
			    struct propstat propstat[],
			    void *rock __attribute__((unused)))
{
    xmlNodePtr node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV],
				   &propstat[PROPSTAT_OK], name, ns, NULL, 0);

    if (!fctx->record) {
	xmlNewChild(node, NULL, BAD_CAST "collection", NULL);

	if (fctx->req_tgt->collection) {
	    ensure_ns(fctx->ns, NS_CARDDAV, resp->parent,
		      XML_NS_CARDDAV, "C");
	    xmlNewChild(node, fctx->ns[NS_CARDDAV],
			BAD_CAST "addressbook", NULL);
	}
    }

    return 0;
}


/* Callback to prescreen/fetch CARDDAV:address-data */
static int propfind_addrdata(const xmlChar *name, xmlNsPtr ns,
			     struct propfind_ctx *fctx,
			     xmlNodePtr resp __attribute__((unused)),
			     struct propstat propstat[],
			     void *rock)
{
    xmlNodePtr prop = (xmlNodePtr) rock;
    const char *data = NULL;
    size_t datalen = 0;

    if (propstat) {
	if (!fctx->record) return HTTP_NOT_FOUND;

	if (!fctx->msg_buf.len)
	    mailbox_map_record(fctx->mailbox, fctx->record, &fctx->msg_buf);
	if (!fctx->msg_buf.len) return HTTP_SERVER_ERROR;

	data = fctx->msg_buf.s + fctx->record->header_size;
	datalen = fctx->record->size - fctx->record->header_size;
    }

    return propfind_getdata(name, ns, fctx, propstat, prop, carddav_mime_types,
			    CARDDAV_SUPP_DATA, data, datalen);
}


/* Callback to fetch CARDDAV:addressbook-home-set */
int propfind_abookhome(const xmlChar *name, xmlNsPtr ns,
		       struct propfind_ctx *fctx,
		       xmlNodePtr resp __attribute__((unused)),
		       struct propstat propstat[],
		       void *rock)
{
    xmlNodePtr node;
    xmlNodePtr expand = (xmlNodePtr) rock;

    if (!(namespace_addressbook.enabled && fctx->req_tgt->user))
	return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			name, ns, NULL, 0);

    buf_reset(&fctx->buf);
    buf_printf(&fctx->buf, "%s/user/%.*s/", namespace_addressbook.prefix,
	       (int) fctx->req_tgt->userlen, fctx->req_tgt->user);

    if (expand) {
	/* Return properties for this URL */
	expand_property(expand, fctx, buf_cstring(&fctx->buf),
			&carddav_parse_path, carddav_props, node, 0);

    }
    else {
	/* Return just the URL */
	xml_add_href(node, fctx->ns[NS_DAV], buf_cstring(&fctx->buf));
    }

    return 0;
}


/* Callback to fetch CARDDAV:supported-address-data */
static int propfind_suppaddrdata(const xmlChar *name, xmlNsPtr ns,
				 struct propfind_ctx *fctx,
				 xmlNodePtr resp __attribute__((unused)),
				 struct propstat propstat[],
				 void *rock __attribute__((unused)))
{
    xmlNodePtr node;
    struct mime_type_t *mime;

    if (!fctx->req_tgt->collection) return HTTP_NOT_FOUND;

    node = xml_add_prop(HTTP_OK, fctx->ns[NS_DAV], &propstat[PROPSTAT_OK],
			name, ns, NULL, 0);

    for (mime = carddav_mime_types; mime->content_type; mime++) {
	xmlNodePtr type = xmlNewChild(node, fctx->ns[NS_CARDDAV],
				      BAD_CAST "address-data-type", NULL);

	/* Trim any charset from content-type */
	buf_reset(&fctx->buf);
	buf_printf(&fctx->buf, "%.*s",
		   (int) strcspn(mime->content_type, ";"), mime->content_type);

	xmlNewProp(type, BAD_CAST "content-type",
		   BAD_CAST buf_cstring(&fctx->buf));

	if (mime->version)
	    xmlNewProp(type, BAD_CAST "version", BAD_CAST mime->version);
    }

    buf_reset(&fctx->buf);

    return 0;
}


static int report_card_query(struct transaction_t *txn,
			     xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int ret = 0;
    xmlNodePtr node;

    fctx->filter_crit = (void *) 0xDEADBEEF;  /* placeholder until we filter */
    fctx->open_db = (db_open_proc_t) &my_carddav_open;
    fctx->close_db = (db_close_proc_t) &my_carddav_close;
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

    if (fctx->depth++ > 0) {
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

	if (fctx->davdb) my_carddav_close(fctx->davdb);

	ret = *fctx->ret;
    }

    return (ret ? ret : HTTP_MULTI_STATUS);
}


static int report_card_multiget(struct transaction_t *txn,
				xmlNodePtr inroot, struct propfind_ctx *fctx)
{
    int r, ret = 0;
    struct mailbox *mailbox = NULL;
    xmlNodePtr node;
    struct buf uri = BUF_INITIALIZER;

    /* Get props for each href */
    for (node = inroot->children; node; node = node->next) {
	if ((node->type == XML_ELEMENT_NODE) &&
	    !xmlStrcmp(node->name, BAD_CAST "href")) {
	    xmlChar *href = xmlNodeListGetString(inroot->doc, node->children, 1);
	    int len = xmlStrlen(href);
	    struct request_target_t tgt;
	    struct carddav_data *cdata;

	    buf_ensure(&uri, len);
	    xmlURIUnescapeString((const char *) href, len, uri.s);
	    xmlFree(href);

	    /* Parse the path */
	    memset(&tgt, 0, sizeof(struct request_target_t));
	    tgt.namespace = URL_NS_CALENDAR;

	    if ((r = carddav_parse_path(uri.s, &tgt, &fctx->err->desc))) {
		ret = r;
		goto done;
	    }

	    fctx->req_tgt = &tgt;

	    /* Check if we already have this mailbox open */
	    if (!mailbox || strcmp(mailbox->name, tgt.mboxname)) {
		if (mailbox) mailbox_unlock_index(mailbox, NULL);

		/* Open mailbox for reading */
		r = mailbox_open_irl(tgt.mboxname, &mailbox);
		if (r && r != IMAP_MAILBOX_NONEXISTENT) {
		    syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
			   tgt.mboxname, error_message(r));
		    txn->error.desc = error_message(r);
		    ret = HTTP_SERVER_ERROR;
		    goto done;
		}

		fctx->mailbox = mailbox;
	    }

	    if (!fctx->mailbox || !tgt.resource) {
		/* Add response for missing target */
		xml_add_response(fctx, HTTP_NOT_FOUND, 0);
		continue;
	    }

	    /* Open the DAV DB corresponding to the mailbox */
	    fctx->davdb = my_carddav_open(fctx->mailbox);

	    /* Find message UID for the resource */
	    carddav_lookup_resource(fctx->davdb,
				   tgt.mboxname, tgt.resource, 0, &cdata);
	    cdata->dav.resource = tgt.resource;
	    /* XXX  Check errors */

	    propfind_by_resource(fctx, cdata);

	    my_carddav_close(fctx->davdb);
	}
    }

  done:
    mailbox_close(&mailbox);
    buf_free(&uri);

    return (ret ? ret : HTTP_MULTI_STATUS);
}



/* Store the vCard data in the specified addressbook/resource */
static int store_resource(struct transaction_t *txn, struct vparse_card *vcard,
			  struct mailbox *mailbox, const char *resource,
			  struct carddav_db *carddavdb, int overwrite,
			  unsigned flags)
{
    int ret = HTTP_CREATED, r;
    struct vparse_entry *ventry;
    struct carddav_data *cdata;
    FILE *f = NULL;
    struct index_record oldrecord;
    struct stagemsg *stage;
    char *header;
    const char *version = NULL, *uid = NULL, *fullname = NULL;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    uint32_t expunge_uid = 0;
    time_t now = time(NULL);
    char datestr[80];
    struct appendstate as;

    /* Fetch some important properties */
    for (ventry = vcard->properties; ventry; ventry = ventry->next) {
	const char *name = ventry->name;
	const char *propval = ventry->v.value;

	if (!name) continue;
	if (!propval) continue;

	if (!strcmp(name, "version")) {
	    version = propval;
	    if (strcmp(version, "3.0")) {
		txn->error.precond = CARDDAV_SUPP_DATA;
		ret = HTTP_FORBIDDEN;
		goto done;
	    }
	}

	else if (!strcmp(name, "uid"))
	    uid = propval;

	else if (!strcmp(name, "fn"))
	    fullname = propval;
    }

    /* Sanity check data */
    if (!version || !uid || !fullname) {
	txn->error.precond = CARDDAV_VALID_DATA;
	ret = HTTP_FORBIDDEN;
	goto done;
    }

    /* Check for existing vCard UID */
    carddav_lookup_uid(carddavdb, uid, 0, &cdata);
    if (!(flags & NO_DUP_CHECK) &&
	cdata->dav.mailbox && !strcmp(cdata->dav.mailbox, mailbox->name) &&
	strcmp(cdata->dav.resource, resource)) {
	/* CARDDAV:no-uid-conflict */
	const char *owner = mboxname_to_userid(cdata->dav.mailbox);

	txn->error.precond = CARDDAV_UID_CONFLICT;
	assert(!buf_len(&txn->buf));
	buf_printf(&txn->buf, "%s/user/%s/%s/%s",
		   namespace_addressbook.prefix, owner,
		   strrchr(cdata->dav.mailbox, '.')+1, cdata->dav.resource);
	txn->error.resource = buf_cstring(&txn->buf);
	ret = HTTP_FORBIDDEN;
	goto done;
    }

    if (cdata->dav.imap_uid) {
	/* Fetch index record for the resource */
	r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &oldrecord);

	if (overwrite == OVERWRITE_CHECK) {
	    /* Check any preconditions */
	    const char *etag = message_guid_encode(&oldrecord.guid);
	    time_t lastmod = oldrecord.internaldate;
	    int precond = check_precond(txn, cdata, etag, lastmod);

	    if (precond != HTTP_OK) {
		ret = HTTP_PRECOND_FAILED;
		goto done;
	    }
	}

	expunge_uid = oldrecord.uid;
    }

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox->name, now, 0, &stage))) {
	syslog(LOG_ERR, "append_newstage(%s) failed", mailbox->name);
	txn->error.desc = "append_newstage() failed\r\n";
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Create iMIP header for resource */

    /* XXX  This needs to be done via an LDAP/DB lookup */
    header = charset_encode_mimeheader(proxy_userid, 0);
    fprintf(f, "From: %s <>\r\n", header);
    free(header);

    header = charset_encode_mimeheader(fullname, 0);
    fprintf(f, "Subject: %s\r\n", header);
    free(header);

    time_to_rfc822(now, datestr, sizeof(datestr));

    fprintf(f, "Date: %s\r\n", datestr);

    fprintf(f, "Message-ID: <%s@%s>\r\n", uid, config_servername);

    fprintf(f, "Content-Type: text/vcard; charset=utf-8\r\n");

    fprintf(f, "Content-Length: %u\r\n", (unsigned)buf_len(&txn->req_body.payload));
    fprintf(f, "Content-Disposition: inline; filename=\"%s\"\r\n", resource);

    /* XXX  Check domain of data and use appropriate CTE */

    fprintf(f, "MIME-Version: 1.0\r\n");
    fprintf(f, "\r\n");

    /* Write the vCard data to the file */
    fprintf(f, "%s", buf_cstring(&txn->req_body.payload));

    qdiffs[QUOTA_STORAGE] = ftell(f);
    qdiffs[QUOTA_MESSAGE] = 1;

    fclose(f);

    /* Prepare to append the iMIP message to calendar mailbox */
    if ((r = append_setup_mbox(&as, mailbox, NULL, NULL, 0, qdiffs, 0, 0, EVENT_MESSAGE_NEW|EVENT_CALENDAR))) {
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
	if (body) {
	    message_free_body(body);
	    free(body);
	}

	if (r) append_abort(&as);
	else {
	    /* Commit the append to the calendar mailbox */
	    r = append_commit(&as);
	    if (r) {
		syslog(LOG_ERR, "append_commit() failed");
		ret = HTTP_SERVER_ERROR;
		txn->error.desc = "append_commit() failed\r\n";
	    }
	    else {
		/* append_commit() returns a write-locked index */
		struct index_record newrecord;

		/* Read index record for new message (always the last one) */
		mailbox_read_index_record(mailbox, mailbox->i.num_records,
					  &newrecord);

		if (expunge_uid) {
		    /* Now that we have the replacement message in place
		       and the mailbox locked, re-read the old record
		       and see if we should overwrite it.  Either way,
		       one of our records will have to be expunged.
		    */
		    int userflag;

		    ret = HTTP_NO_CONTENT;

		    /* Perform the actual expunge */
		    r = mailbox_user_flag(mailbox, DFLAG_UNBIND, &userflag, 1);
		    if (!r) {
			oldrecord.user_flags[userflag/32] |= 1<<(userflag&31);
			oldrecord.system_flags |= FLAG_EXPUNGED;
			r = mailbox_rewrite_index_record(mailbox, &oldrecord);
		    }
		    if (r) {
			syslog(LOG_ERR, "expunging record (%s) failed: %s",
			       mailbox->name, error_message(r));
			txn->error.desc = error_message(r);
			ret = HTTP_SERVER_ERROR;
		    }
		}

		if (!r) {
		    struct resp_body_t *resp_body = &txn->resp_body;

		    /* Tell client about the new resource */
		    resp_body->lastmod = newrecord.internaldate;
		    resp_body->etag = message_guid_encode(&newrecord.guid);
		}
	    }
	}
    }

    append_removestage(stage);

done:
    return ret;
}
