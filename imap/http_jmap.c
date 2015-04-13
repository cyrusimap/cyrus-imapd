/* http_jmap.c -- Routines for handling JMAP requests in httpd
 *
 * Copyright (c) 1994-2014 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <jansson.h>

#include "acl.h"
#include "carddav_db.h"
#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "http_err.h"
#include "http_proxy.h"
#include "http_jmap.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "statuscache.h"
#include "util.h"
#include "version.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"


struct namespace jmap_namespace;

static time_t compile_time;
static void jmap_init(struct buf *serverinfo);
static void jmap_auth(const char *userid);
static int meth_get(struct transaction_t *txn, void *params);
static int meth_post(struct transaction_t *txn, void *params);
static int getMailboxes(struct jmap_req *req);
static int getContactGroups(struct jmap_req *req);
static int getContactGroupUpdates(struct jmap_req *req);
static int setContactGroups(struct jmap_req *req);
static int getContacts(struct jmap_req *req);
static int getContactUpdates(struct jmap_req *req);
static int setContacts(struct jmap_req *req);

static const struct message_t {
    const char *name;
    int (*proc)(struct jmap_req *req);
} messages[] = {
    { "getMailboxes",	&getMailboxes },
    { "getContactGroups",	&getContactGroups },
    { "getContactGroupUpdates",	&getContactGroupUpdates },
    { "setContactGroups",	&setContactGroups },
    { "getContacts",		&getContacts },
    { "getContactUpdates",	&getContactUpdates },
    { "setContacts",		&setContacts },
    { NULL,		NULL}
};


/* Namespace for JMAP */
struct namespace_t namespace_jmap = {
    URL_NS_JMAP, 0, "/jmap", NULL, 1 /* auth */, (ALLOW_READ | ALLOW_POST),
    /*type*/0, &jmap_init, &jmap_auth, NULL, NULL,
    {
	{ NULL,			NULL },			/* ACL		*/
	{ NULL,			NULL },			/* COPY		*/
	{ NULL,			NULL },			/* DELETE	*/
	{ &meth_get,		NULL },			/* GET		*/
	{ &meth_get,		NULL },			/* HEAD		*/
	{ NULL,			NULL },			/* LOCK		*/
	{ NULL,			NULL },			/* MKCALENDAR	*/
	{ NULL,			NULL },			/* MKCOL	*/
	{ NULL,			NULL },			/* MOVE		*/
	{ &meth_options,	NULL },			/* OPTIONS	*/
	{ &meth_post,		NULL },			/* POST	*/
	{ NULL,			NULL },			/* PROPFIND	*/
	{ NULL,			NULL },			/* PROPPATCH	*/
	{ NULL,			NULL },			/* PUT		*/
	{ NULL,			NULL },			/* REPORT	*/
	{ &meth_trace,		NULL },			/* TRACE	*/
	{ NULL,			NULL }			/* UNLOCK	*/
    }
};


static void jmap_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_jmap.enabled =
	config_httpmodules & IMAP_ENUM_HTTPMODULES_JMAP;

    if (!namespace_jmap.enabled) return;

    compile_time = calc_compile_time(__TIME__, __DATE__);
}


static void jmap_auth(const char *userid __attribute__((unused)))
{
    /* Set namespace */
    mboxname_init_namespace(&jmap_namespace,
			    httpd_userisadmin || httpd_userisproxyadmin);
}


/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn __attribute__((unused)),
		     void *params __attribute__((unused)))
{
    return HTTP_NO_CONTENT;
}

/* Perform a POST request */
static int meth_post(struct transaction_t *txn,
		     void *params __attribute__((unused)))
{
    const char **hdr;
    json_t *req, *resp = NULL;
    json_error_t jerr;
    const struct message_t *mp = NULL;
    struct mailbox *mailbox = NULL;
    struct hash_table idmap;
    size_t i, flags = JSON_PRESERVE_ORDER;
    int ret;
    char *buf;

    construct_hash_table(&idmap, 1024, 0);

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    ret = http_read_body(httpd_in, httpd_out,
		       txn->req_hdrs, &txn->req_body, &txn->error.desc);
    if (ret) {
	txn->flags.conn = CONN_CLOSE;
	return ret;
    }

    if (!buf_len(&txn->req_body.payload)) return HTTP_BAD_REQUEST;

    /* Check Content-Type */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Content-Type")) ||
	!is_mediatype("application/json", hdr[0])) {
	txn->error.desc = "This method requires a JSON request body\r\n";
	return HTTP_BAD_MEDIATYPE;
    }

    /* Parse the JSON request */
    req = json_loads(buf_cstring(&txn->req_body.payload), 0, &jerr);
    if (!req || !json_is_array(req)) {
	txn->error.desc = "Unable to parse JSON request body\r\n";
	ret = HTTP_BAD_REQUEST;
	goto done;
    }

    /* Start JSON response */
    resp = json_array();
    if (!resp) {
	txn->error.desc = "Unable to create JSON response body\r\n";
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    const char *inboxname = mboxname_user_mbox(httpd_userid, NULL);

    /* we lock the user's INBOX before we start any operation, because that way we
     * guarantee (via conversations magic) that nothing changes the modseqs except
     * our operations */
    int r = mailbox_open_iwl(inboxname, &mailbox);
    if (r) {
	txn->error.desc = "Unable to lock user INBOX\r\n";
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Process each message in the request */
    for (i = 0; i < json_array_size(req); i++) {
	json_t *msg = json_array_get(req, i);
	const char *name = json_string_value(json_array_get(msg, 0));
	json_t *args = json_array_get(msg, 1);
	json_t *id = json_array_get(msg, 2);
	/* XXX - better error reporting */
	if (!id) continue;
	const char *tag = json_string_value(id);
	int r = 0;

	/* Find the message processor */
	for (mp = messages; mp->name && strcmp(name, mp->name); mp++);

	if (!mp || !mp->name) {
	    json_array_append(resp, json_pack("[s {s:s} s]", "error", "type", "unknownMethod", tag));
	    continue;
	}

	/* read the modseq again every time, just in case something changed it
	 * in our actions */
	struct buf buf = BUF_INITIALIZER;
	modseq_t modseq = mboxname_readmodseq(inboxname);
	buf_printf(&buf, "%llu", modseq);

	struct jmap_req req;
	req.userid = httpd_userid;
	req.authstate = httpd_authstate;
	req.args = args;
	req.state = buf_cstring(&buf);
	req.response = resp;
	req.tag = tag;
	req.idmap = &idmap;

	r = mp->proc(&req);

	buf_free(&buf);

	if (r) {
	    txn->error.desc = "Unable to create JSON response body\r\n";
	    ret = HTTP_SERVER_ERROR;
	    goto done;
	}
    }

    /* unlock here so that we don't block on writing */
    mailbox_unlock_index(mailbox, NULL);

    /* Dump JSON object into a text buffer */
    flags |= (config_httpprettytelemetry ? JSON_INDENT(2) : JSON_COMPACT);
    buf = json_dumps(resp, flags);

    if (!buf) {
	txn->error.desc = "Error dumping JSON response object";
	ret = HTTP_SERVER_ERROR;
	goto done;
    }

    /* Output the JSON object */
    txn->resp_body.type = "application/json; charset=utf-8";
    write_body(HTTP_OK, txn, buf, strlen(buf));
    free(buf);

  done:
    free_hash_table(&idmap, free);
    mailbox_close(&mailbox);
    if (req) json_decref(req);
    if (resp) json_decref(resp);

    return ret;
}


/* mboxlist_findall() callback to list mailboxes */
int getMailboxes_cb(char *mboxname, int matchlen __attribute__((unused)),
		    int maycreate __attribute__((unused)),
		    void *rock)
{
    json_t *list = (json_t *) rock, *mbox;
    struct mboxlist_entry *mbentry = NULL;
    struct mailbox *mailbox = NULL;
    int r = 0, rights;
    unsigned statusitems = STATUS_MESSAGES | STATUS_UNSEEN;
    struct statusdata sdata;

    /* Check ACL on mailbox for current user */
    if ((r = mboxlist_lookup(mboxname, &mbentry, NULL))) {
	syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
	       mboxname, error_message(r));
	goto done;
    }

    rights = mbentry->acl ? cyrus_acl_myrights(httpd_authstate, mbentry->acl) : 0;
    if ((rights & (ACL_LOOKUP | ACL_READ)) != (ACL_LOOKUP | ACL_READ)) {
	goto done;
    }

    /* Open mailbox to get uniqueid */
    if ((r = mailbox_open_irl(mboxname, &mailbox))) {
	syslog(LOG_INFO, "mailbox_open_irl(%s) failed: %s",
	       mboxname, error_message(r));
	goto done;
    }
    mailbox_unlock_index(mailbox, NULL);

    r = status_lookup(mboxname, httpd_userid, statusitems, &sdata);

    mbox = json_pack("{s:s s:s s:n s:n s:b s:b s:b s:b s:i s:i}",
		     "id", mailbox->uniqueid,
		     "name", mboxname,
		     "parentId",
		     "role",
		     "mayAddMessages", rights & ACL_INSERT,
		     "mayRemoveMessages", rights & ACL_DELETEMSG,
		     "mayCreateChild", rights & ACL_CREATE,
		     "mayDeleteMailbox", rights & ACL_DELETEMBOX,
		     "totalMessages", sdata.messages,
		     "unreadMessages", sdata.unseen);
    json_array_append_new(list, mbox);

    mailbox_close(&mailbox);

  done:

    return 0;
}


/* Execute a getMailboxes message */
static int getMailboxes(struct jmap_req *req)
{
    json_t *item, *mailboxes, *list;

    /* Start constructing our response */
    item = json_pack("[s {s:s s:s} s]", "mailboxes",
		     "accountId", req->userid,
		     "state", req->state,
		     req->tag);

    list = json_array();

    /* Generate list of mailboxes */
    mboxlist_findall(&jmap_namespace, "*", httpd_userisadmin, req->userid,
		     httpd_authstate, &getMailboxes_cb, list);

    mailboxes = json_array_get(item, 1);
    json_object_set_new(mailboxes, "list", list);

    /* xxx - args */
    json_object_set_new(mailboxes, "notFound", json_null());

    json_array_append_new(req->response, item);

    return 0;
}

static int getContactGroups(struct jmap_req *req)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;
    int r = carddav_getContactGroups(db, req);
    carddav_close(db);
    return r;
}


static int getContactGroupUpdates(struct jmap_req *req)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;
    int r = carddav_getContactGroupUpdates(db, req);
    carddav_close(db);
    return r;
}

static int setContactGroups(struct jmap_req *req)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;
    int r = carddav_setContactGroups(db, req);
    carddav_close(db);
    return r;
}

static int getContacts(struct jmap_req *req)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;
    int r = carddav_getContacts(db, req);
    carddav_close(db);
    return r;
}

static int getContactUpdates(struct jmap_req *req)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;
    int r = carddav_getContactUpdates(db, req);
    carddav_close(db);
    return r;
}

static int setContacts(struct jmap_req *req)
{
    struct carddav_db *db = carddav_open_userid(req->userid);
    if (!db) return -1;
    int r = carddav_setContacts(db, req);
    carddav_close(db);
    return r;
}

