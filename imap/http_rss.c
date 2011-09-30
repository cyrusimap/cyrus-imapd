/* rss.c -- Routines for handling RSS feeds of mailboxes in httpd
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

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <syslog.h>

#include <libxml/HTMLtree.h>
#include <libxml/tree.h>

#include "acl.h"
#include "global.h"
#include "httpd.h"
#include "http_err.h"
#include "imap_err.h"
#include "mailbox.h"
#include "map.h"
#include "mboxlist.h"
#include "message.h"
#include "parseaddr.h"
#include "rfc822date.h"
#include "util.h"
#include "version.h"
#include "xstrlcat.h"

/* Create a mailbox name from the request URL */ 
static int rss_to_mboxname(struct request_target_t *req_tgt,
			   char *mboxname, uint32_t *uid)
{
    char *start, *p, *end;
    size_t len;

    *uid = 0;

    /* Clip off RSS prefix */
    start = req_tgt->path + strlen("/rss");
    if (*start == '/') start++;
    end = start + strlen(start);

    if ((end > start) && (end[-1] == '.')) {
	/* Possible UID */
	for (p = end-1; (p > start) && isdigit(*--p););
	if ((*p == '/') && (p > start)) {
	    end = p;
	    *uid = strtoul(p+1, NULL, 0);
	}
    }
    if ((end > start) && (end[-1] == '/')) end--;

    len = end - start;
    if (len > MAX_MAILBOX_BUFFER) return IMAP_MAILBOX_BADNAME;

    strncpy(mboxname, start, len);
    mboxname[len] = '\0';

    mboxname_hiersep_tointernal(&httpd_namespace, mboxname, len);

    return 0;
}

/*
 * mboxlist_findall() callback function to list RSS feeds
 */
int list_cb(char *name, int matchlen, int maycreate __attribute__((unused)),
	    void *rock)
{
    static char lastname[MAX_MAILBOX_BUFFER];
    char href[MAX_MAILBOX_PATH+1];
    struct mboxlist_entry entry;
    xmlNodePtr list = (xmlNodePtr) rock, item, link;

    /* We have to reset the initial state.
     * Handle it as a dirty hack.
     */
    if (!name) {
	lastname[0] = '\0';
	return 0;
    }

    /* don't repeat */
    if (matchlen == (int) strlen(lastname) &&
	!strncmp(name, lastname, matchlen)) return 0;

    strncpy(lastname, name, matchlen);
    lastname[matchlen] = '\0';

    /* Lookup the mailbox and make sure its readable */
    mboxlist_lookup(name, &entry, NULL);
    if (!entry.acl ||
	!(cyrus_acl_myrights(httpd_authstate, entry.acl) & ACL_READ))
	return 0;

    /* Add mailbox to our HTML list */
    item = xmlNewChild(list, NULL, BAD_CAST "li", NULL);
    link = xmlNewChild(item, NULL, BAD_CAST "a", BAD_CAST name);

    snprintf(href, sizeof(href), ".rss.%s.", name);
    mboxname_hiersep_toexternal(&httpd_namespace, href, 0);
    xmlNewProp(link, BAD_CAST "href", BAD_CAST href);

    return 0;
}

/* Create a HTML document listing all RSS feeds available to the user */
static void list_rss_feeds(struct transaction_t *txn)
{
    int r;
    htmlDocPtr doc;
    xmlNodePtr root, head, body, list;

    /* XXX  Need to check for errors */
    doc = htmlNewDoc(NULL, NULL);
    root = xmlNewNode(NULL, BAD_CAST "html");
    xmlDocSetRootElement(doc, root);
    head = xmlNewChild(root, NULL, BAD_CAST "head", NULL);
    xmlNewChild(head, NULL, BAD_CAST "title", BAD_CAST "Cyrus RSS Feeds");

    body = xmlNewChild(root, NULL, BAD_CAST "body", NULL);
    xmlNewChild(body, NULL, BAD_CAST "h2", BAD_CAST "Cyrus RSS Feeds");
    list = xmlNewChild(body, NULL, BAD_CAST "ul", NULL);

    list_cb(NULL, 0, 0, NULL);
    r = mboxlist_findall(NULL, "*", httpd_userisadmin, NULL, httpd_authstate,
			 list_cb, list);

    html_response(HTTP_OK, txn, doc);
}

/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn)
{
    int ret = 0, r;
    char mailboxname[MAX_MAILBOX_BUFFER];
    uint32_t uid;
    struct mailbox *mailbox = NULL;
    xmlDocPtr outdoc;
    xmlNodePtr root, chan, item;
    const char **host;
    unsigned recno;
    struct buf buf = BUF_INITIALIZER;

    /* Construct mailbox name corresponding to request target URI */
    if ((r = rss_to_mboxname(&txn->req_tgt, mailboxname, &uid))) {
	txn->errstr = error_message(r);
	ret = HTTP_NOT_FOUND;
	goto done;
    }

    /* If no mailboxname, list all available feeds */
    if (!*mailboxname) {
	list_rss_feeds(txn);
	return 0;
    }

    /* If UID specified, display entire message */
    if (uid) {
	txn->errstr = "Full message display not yet implemented";
	return HTTP_NOT_IMPLEMENTED;
    }

    /* Open mailbox for reading */
    if ((r = mailbox_open_irl(mailboxname, &mailbox))) {
	syslog(LOG_ERR, "mailbox_open_irl(%s) failed: %s",
	       mailboxname, error_message(r));
	txn->errstr = error_message(r);
	switch (r) {
	case IMAP_PERMISSION_DENIED:
	    ret = HTTP_FORBIDDEN;
	    break;
	case IMAP_MAILBOX_NONEXISTENT:
	    ret = HTTP_NOT_FOUND;
	    break;
	default: 
	    ret = HTTP_SERVER_ERROR;
	}
	goto done;
    }

    /* Set up the RSS <channel> response for the mailbox */
    outdoc = xmlNewDoc(BAD_CAST "1.0");
    root = xmlNewNode(NULL, BAD_CAST "rss");
    xmlNewProp(root, BAD_CAST "version", BAD_CAST "2.0");
    xmlDocSetRootElement(outdoc, root);

    chan = xmlNewChild(root, NULL, BAD_CAST "channel", NULL);

    xmlNewChild(chan, NULL, BAD_CAST "title", BAD_CAST mailboxname);

    /* XXX  Add <description> if we have a /comment annotation? */

    host = spool_getheader(txn->req_hdrs, "Host");
    if (txn->req_tgt.path[strlen(txn->req_tgt.path)-1] != '/') {
	strlcat(txn->req_tgt.path, "/", MAX_MAILBOX_PATH);
    }

    buf_reset(&buf);
    buf_printf(&buf, "http://%s%s", host[0], txn->req_tgt.path);
    xmlNewChild(chan, NULL, BAD_CAST "link", BAD_CAST buf_cstring(&buf));

    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	buf_reset(&buf);
	buf_printf(&buf, "Cyrus HTTP %s", cyrus_version());
	xmlNewChild(chan, NULL, BAD_CAST "generator",
		    BAD_CAST buf_cstring(&buf));
    }

    /* Add an <item> for each message */
    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
	struct index_record record;
	const char *msg_base;
	unsigned long msg_size;
	struct body *body;
	char datestr[80];
	const char *content_types[] = { "text", NULL };
	struct message_content content;
	struct bodypart **parts;

	msg_base = NULL;
	body = NULL;
	parts = NULL;

	if (mailbox_read_index_record(mailbox, recno, &record)) {
	    syslog(LOG_ERR, "read index %d failed", recno);
	    continue;
	}

	if (record.system_flags & (FLAG_DELETED|FLAG_EXPUNGED)) {
	    syslog(LOG_DEBUG, "recno %d deleted", recno);
	    continue;
	}

	if (mailbox_cacherecord(mailbox, &record)) {
	    syslog(LOG_ERR, "read cache failed");
	    continue;
	}

	/* XXX  Need to check \Recent flag */

	/* Read message bodystructure */
	message_read_bodystructure(&record, &body);

	item = xmlNewChild(chan, NULL, BAD_CAST "item", NULL);

	xmlNewTextChild(item, NULL, BAD_CAST "title", BAD_CAST body->subject);

	buf_reset(&buf);
	buf_printf(&buf, "http://%s%s%u.",
		   host[0], txn->req_tgt.path, record.uid);
	xmlNewChild(item, NULL, BAD_CAST "link", BAD_CAST buf_cstring(&buf));

	if (body->from) {
	    struct address *addr = body->from;
	    buf_reset(&buf);
	    buf_printf(&buf, "%s@%s",
		       addr->mailbox ? addr->mailbox : "unknown-user",
		       addr->domain ? addr->domain : "unspecified-domain");
	    if (addr->name) buf_printf(&buf, " (%s)", addr->name);
	    xmlNewChild(item, NULL, BAD_CAST "author",
			BAD_CAST buf_cstring(&buf));
	}

	rfc822date_gen(datestr, sizeof(datestr), record.internaldate);
	xmlNewChild(item, NULL, BAD_CAST "pubDate", BAD_CAST datestr);

	/* Find and use the first text/ part as the <description> */
	mailbox_map_message(mailbox, record.uid, &msg_base, &msg_size);

	content.base = msg_base;
	content.len = msg_size;
	content.body = body;
	message_fetch_part(&content, content_types, &parts);

	if (parts && *parts) {
	    const char *c;

	    buf_reset(&buf);
	    /* Translate CR in body text to HTML <br> tag */
	    for (c = parts[0]->decoded_body; c && *c; c++) {
		if (*c == '\r') buf_appendcstr(&buf, "<br>");
		else buf_putc(&buf, *c);
	    }
	    /* XXX  truncate the message? */
	    xmlNewTextChild(item, NULL, BAD_CAST "description",
			    BAD_CAST buf_cstring(&buf));
	}

	/* free the results */
	if (parts) {
	    struct bodypart **p;

	    for (p = parts; *p; p++) free(*p);
	    free(parts);
	}

	mailbox_unmap_message(mailbox, record.uid, &msg_base, &msg_size);

	if (body) {
	    message_free_body(body);
	    free(body);
	}
    }

    buf_free(&buf);

    /* Output the XML response */
    xml_response(HTTP_OK, txn, outdoc);

  done:
    if (mailbox) mailbox_close(&mailbox);

    return ret;

}

/* Namespace for RSS feeds of mailboxes */
const struct namespace_t namespace_rss = {
    URL_NS_RSS, "/rss", 1 /* auth */, ALLOW_READ,
    {
	NULL,			/* ACL		*/
	NULL,			/* COPY		*/
	NULL,			/* DELETE	*/
	&meth_get,		/* GET		*/
	&meth_get,		/* HEAD		*/
	NULL,			/* LOCK		*/
	NULL,			/* MKCALENDAR	*/
	NULL,			/* MKCOL	*/
	NULL,			/* MOVE		*/
	&meth_options,		/* OPTIONS	*/
	NULL,			/* POST		*/
	NULL,			/* PROPFIND	*/
	NULL,			/* PROPPATCH	*/
	NULL,			/* PUT		*/
	NULL,			/* REPORT	*/
	NULL			/* UNLOCK	*/
    }
};
