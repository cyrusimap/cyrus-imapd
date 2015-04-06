/* http_webdav.c -- Routines for handling WebDAV collections in httpd
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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

#include <string.h>
#include <syslog.h>

#include "httpd.h"
#include "http_dav.h"
#include "http_err.h"
#include "mailbox.h"
#include "spool.h"
#include "tok.h"
#include "util.h"
#include "webdav_db.h"

static struct webdav_db *my_webdav_open(struct mailbox *mailbox);

static int webdav_parse_path(const char *path,
			     struct request_target_t *tgt, const char **errstr);

static int webdav_get(struct transaction_t *txn, struct mailbox *mailbox,
		      struct index_record *record, void *data);
static int webdav_put(struct transaction_t *txn, struct buf *obj,
		      struct mailbox *mailbox, const char *resource,
		      struct webdav_db *davdb, unsigned flags);

struct meth_params webdav_params = {
    .mime_types = NULL,
    .parse_path = &webdav_parse_path,
    .check_precond = &dav_check_precond,
    .davdb = { .open_db = (db_open_proc_t) &my_webdav_open,
	       .close_db = (db_close_proc_t) &webdav_close,
	       .lookup_resource = (db_lookup_proc_t) &webdav_lookup_resource },
    .get = &webdav_get,
    .put = { 0, (put_proc_t) &webdav_put }
};


/* Parse request-target path in WebDAV namespace */
static int webdav_parse_path(const char *path __attribute__((unused)),
			     struct request_target_t *tgt, const char **errstr)
{
    if (*tgt->path) return 0;  /* Already parsed */

    *errstr = "Can't parse WebDAV request target path";
    return HTTP_SERVER_ERROR;
}


/* Open DAV DB corresponding to mailbox */
static struct webdav_db *my_webdav_open(struct mailbox *mailbox)
{
    return webdav_open_mailbox(mailbox);
}


/* Perform a GET/HEAD request on a WebDAV resource */
static int webdav_get(struct transaction_t *txn,
		      struct mailbox *mailbox __attribute__((unused)),
		      struct index_record *record, void *data)
{
    if (record && record->uid) {
	/* GET on a resource */
	struct webdav_data *wdata = (struct webdav_data *) data;

	assert(!buf_len(&txn->buf));
	buf_printf(&txn->buf, "%s/%s", wdata->type, wdata->subtype);
	txn->resp_body.type = buf_cstring(&txn->buf);
	txn->resp_body.fname = wdata->filename;
	return 0;
    }

    /* Get on a user/collection */
    return HTTP_NO_CONTENT;
}


/* Perform a PUT request on a WebDAV resource */
static int webdav_put(struct transaction_t *txn, struct buf *obj,
		      struct mailbox *mailbox, const char *resource,
		      struct webdav_db *webdavdb,
		      unsigned flags __attribute__((unused)))
{
    struct webdav_data *wdata;
    struct index_record *oldrecord = NULL, record;
    const char **hdr;
    char *filename = NULL;

    /* Validate the data */
    if (!obj || !obj->s) return HTTP_FORBIDDEN;

    /* Find message UID for the resource */
    webdav_lookup_resource(webdavdb, txn->req_tgt.mbentry->name,
			   txn->req_tgt.resource, 0, &wdata, 0);

    if (wdata->dav.imap_uid) {
	/* Fetch index record for the resource */
	oldrecord = &record;
	mailbox_find_index_record(mailbox, wdata->dav.imap_uid, oldrecord, 0);
    }

    /* Get filename of attachment */
    if ((hdr = spool_getheader(txn->req_hdrs, "Content-Disposition"))) {
	char *dparam;
	tok_t tok;
	
	tok_initm(&tok, (char *) *hdr, ";", TOK_TRIMLEFT|TOK_TRIMRIGHT);
	while ((dparam = tok_next(&tok))) {
	    if (!strncasecmp(dparam, "filename=", 9)) {
		filename = dparam+9;
		if (*filename++ == '"') filename[strlen(filename)-1] = '\0';
		break;
	    }
	}
	tok_fini(&tok);
    }

    /* Create and cache RFC 5322 header fields for resource */
    if (filename) {
	spool_cache_header(xstrdup("Subject"),
			   xstrdup(filename), txn->req_hdrs);
	spool_cache_header(xstrdup("Content-Description"),
			   xstrdup(filename), txn->req_hdrs);
    }

    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "<%s@%s>", resource, config_servername);
    spool_cache_header(xstrdup("Message-ID"),
		       buf_release(&txn->buf), txn->req_hdrs);

    buf_printf(&txn->buf, "attachment;\r\n\tfilename=\"%s\"", resource);
    spool_cache_header(xstrdup("Content-Disposition"),
		       buf_release(&txn->buf), txn->req_hdrs);

    /* Store the resource */
    return dav_store_resource(txn, buf_cstring(obj), buf_len(obj),
			      mailbox, oldrecord, NULL);
}
