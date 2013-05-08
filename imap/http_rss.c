/* http_rss.c -- Routines for handling RSS feeds of mailboxes in httpd
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
#include <assert.h>

#include "acl.h"
#include "charset.h"
#include "global.h"
#include "httpd.h"
#include "http_err.h"
#include "http_proxy.h"
#include "imap_err.h"
#include "mailbox.h"
#include "map.h"
#include "mboxlist.h"
#include "message.h"
#include "parseaddr.h"
#include "proxy.h"
#include "rfc822date.h"
#include "seen.h"
#include "tok.h"
#include "util.h"
#include "version.h"
#include "wildmat.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

#define RSS_SPEC	"http://www.rssboard.org/rss-specification"
#define XML_NS_ATOM	"http://www.w3.org/2005/Atom"
#define MAX_SECTION_LEN	128
#define FEEDLIST_VAR	"%RSS_FEEDLIST%"

static const char def_template[] =
    HTML_DOCTYPE
    "<html>\n<head>\n<title>Cyrus RSS Feeds</title>\n</head>\n"
    "<body>\n<h2>Cyrus RSS Feeds</h2>\n"
    FEEDLIST_VAR
    "</body>\n</html>\n";

static time_t compile_time;
static void rss_init(struct buf *serverinfo);
static int meth_get(struct transaction_t *txn, void *params);
static int rss_parse_path(const char *path,
			  struct request_target_t *tgt, const char **errstr);
static int is_feed(const char *mbox);
static int list_feeds(struct transaction_t *txn);
static int fetch_message(struct transaction_t *txn, struct mailbox *mailbox,
			 unsigned recno, uint32_t uid,
			 struct index_record *record, struct body **body,
			 const char **msg_base, unsigned long *msg_size);
static int list_messages(struct transaction_t *txn, struct mailbox *mailbox);
static void display_message(struct transaction_t *txn,
			    const char *mboxname, uint32_t uid,
			    struct body *body, const char *msg_base);
static void fetch_part(struct transaction_t *txn, struct body *body,
		       const char *findsection, const char *cursection,
		       const char *msg_base);


/* Namespace for RSS feeds of mailboxes */
struct namespace_t namespace_rss = {
    URL_NS_RSS, 0, "/rss", NULL, 1 /* auth */, ALLOW_READ,
    rss_init, NULL, NULL, NULL,
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
	{ &meth_options,	&rss_parse_path },	/* OPTIONS	*/
	{ NULL,			NULL },			/* POST		*/
	{ NULL,			NULL },			/* PROPFIND	*/
	{ NULL,			NULL },			/* PROPPATCH	*/
	{ NULL,			NULL },			/* PUT		*/
	{ NULL,			NULL },			/* REPORT	*/
	{ &meth_trace,		&rss_parse_path },	/* TRACE	*/
	{ NULL,			NULL }			/* UNLOCK	*/
    }
};

/* Calculate compile time of this file for use as ETag for capabilities */
static void calc_compile_time()
{
    struct tm tm;
    char month[4];
    const char *monthname[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    memset(&tm, 0, sizeof(struct tm));
    tm.tm_isdst = -1;
    sscanf(__TIME__, "%02d:%02d:%02d", &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    sscanf(__DATE__, "%s %2d %4d", month, &tm.tm_mday, &tm.tm_year);
    tm.tm_year -= 1900;
    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!strcmp(month, monthname[tm.tm_mon])) break;
    }

    compile_time = mktime(&tm);
}


static void rss_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_rss.enabled = config_httpmodules & IMAP_ENUM_HTTPMODULES_RSS;

    if (!namespace_rss.enabled) return;

    calc_compile_time();
}

/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn,
		    void *params __attribute__((unused)))
{
    int ret = 0, r;
    char *server, section[MAX_SECTION_LEN+1] = "";
    uint32_t uid = 0;
    struct mailbox *mailbox = NULL;

    /* Construct mailbox name corresponding to request target URI */
    if ((r = rss_parse_path(txn->req_uri->path,
			    &txn->req_tgt, &txn->error.desc))) {
	txn->error.desc = error_message(r);
	return HTTP_NOT_FOUND;
    }

    /* If no mailboxname, list all available feeds */
    if (!*txn->req_tgt.mboxname) return list_feeds(txn);

    /* Make sure its a mailbox that we are treating as an RSS feed */
    if (!is_feed(txn->req_tgt.mboxname)) return HTTP_NOT_FOUND;

    /* Locate the mailbox */
    if ((r = http_mlookup(txn->req_tgt.mboxname, &server, NULL, NULL))) {
	syslog(LOG_ERR, "mlookup(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);

	switch (r) {
	case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
	case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
	default: return HTTP_SERVER_ERROR;
	}
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

    /* Open mailbox for reading */
    if ((r = http_mailbox_open(txn->req_tgt.mboxname, &mailbox, LOCK_SHARED))) {
	syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
	       txn->req_tgt.mboxname, error_message(r));
	txn->error.desc = error_message(r);

	switch (r) {
	case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
	case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
	default: return HTTP_SERVER_ERROR;
	}
    }

    /* Parse query params, if any */
    if (URI_QUERY(txn->req_uri) &&
	!strncasecmp(URI_QUERY(txn->req_uri), "uid=", 4)) {
	/* UID */
	char *end;

	uid = strtoul(URI_QUERY(txn->req_uri)+4, &end, 10);
	if (!uid) uid = -1;

	if (!strncasecmp(end, ";section=", 9)) {
	    /* SECTION */
	    strlcpy(section, end+9, MAX_SECTION_LEN);
	}
    }

    /* If no UID specified, list messages as an RSS feed */
    if (!uid) ret = list_messages(txn, mailbox);
    else if (uid > mailbox->i.last_uid) {
	txn->error.desc = "Message does not exist\r\n";
	ret = HTTP_NOT_FOUND;
    }
    else {
	struct index_record record;
	const char *msg_base;
	unsigned long msg_size;
	struct body *body;

	/* Fetch the message */
	if (!(ret = fetch_message(txn, mailbox, 0, uid,
				  &record, &body, &msg_base, &msg_size))) {
	    int precond;
	    const char *etag = NULL;
	    time_t lastmod = 0;
	    struct resp_body_t *resp_body = &txn->resp_body;
	    unsigned long offset = 0, datalen = 0;

	    /* Check any preconditions */
	    if (!strcmp(section, "0")) {
		/* Entire raw message */
		txn->flags.ranges = !txn->flags.ce;
		datalen = msg_size;
	    }

	    etag = message_guid_encode(&record.guid);
	    lastmod = record.internaldate;
	    precond = check_precond(txn, NULL, etag, lastmod, datalen);

	    switch (precond) {
	    case HTTP_OK:
		break;

	    case HTTP_PARTIAL:
		/* Set data parameters for range */
		offset += resp_body->range->first;
		datalen = resp_body->range->last - resp_body->range->first + 1;
		break;

	    case HTTP_NOT_MODIFIED:
		/* Fill in ETag for 304 response */
		resp_body->etag = etag;

	    default:
		/* We failed a precondition - don't perform the request */
		ret = precond;
		goto done;
	    }

	    /* Fill in ETag and Last-Modified */
	    resp_body->etag = etag;
	    resp_body->lastmod = lastmod;
	    
	    if (!*section) {
		/* Return entire message formatted as text/html */
		display_message(txn, mailbox->name, record.uid, body, msg_base);
	    }
	    else if (!strcmp(section, "0")) {
		/* Return entire message as text/plain */
		resp_body->type = "text/plain";

		if (resp_body->range && resp_body->range->next) {
		    /* multiple ranges */
		    multipart_byteranges(txn, msg_base);
		}
		else write_body(precond, txn, msg_base + offset, datalen);
	    }
	    else {
		/* Fetch, decode, and return the specified MIME message part */
		fetch_part(txn, body, section, "1", msg_base);
	    }

	  done:
	    mailbox_unmap_message(mailbox, record.uid, &msg_base, &msg_size);

	    if (body) {
		message_free_body(body);
		free(body);
	    }
	}
    }

    if (mailbox) mailbox_unlock_index(mailbox, NULL);

    return ret;

}


/* Create a mailbox name from the request URL */ 
static int rss_parse_path(const char *path,
			  struct request_target_t *tgt,
			  const char **errstr __attribute__((unused)))
{
    const char *start, *end;
    size_t len;

    /* Clip off RSS prefix */
    start = path + strlen("/rss");
    if (*start == '/') start++;
    end = start + strlen(start);

    if ((end > start) && (end[-1] == '/')) end--;

    len = end - start;
    if (len > MAX_MAILBOX_BUFFER) return IMAP_MAILBOX_BADNAME;

    strncpy(tgt->mboxname, start, len);
    tgt->mboxname[len] = '\0';

    mboxname_hiersep_tointernal(&httpd_namespace, tgt->mboxname, len);

    return 0;
}


/*
 * Checks to make sure that the given mailbox is actually something
 * that we're treating as an RSS feed.  Returns 1 if yes, 0 if no.
 */
static int is_feed(const char *mbox)
{
    static struct wildmat *feeds = NULL;
    struct wildmat *wild;

    if (!feeds) {
	feeds = split_wildmats((char *) config_getstring(IMAPOPT_RSS_FEEDS),
			       NULL);
    }

    /* check mailbox against the 'rss_feeds' wildmat */
    wild = feeds;
    while (wild->pat && wildmat(mbox, wild->pat) != 1) wild++;

    /* if we don't have a match, or its a negative match, don't use it */
    if (!wild->pat || wild->not) return 0;

    /* otherwise, its usable */
    return 1;
}
    

/*
 * mboxlist_findall() callback function to list RSS feeds as a tree
 */
struct node {
    char name[MAX_MAILBOX_BUFFER];
    size_t len;
    struct node *parent;
    struct node *child;
};

struct list_rock {
    struct transaction_t *txn;
    struct node *last;
};

static int list_cb(char *name, int matchlen, int maycreate, void *rock)
{
    struct list_rock *lrock = (struct list_rock *) rock;
    struct node *last = lrock->last;
    struct buf *buf = &lrock->txn->resp_body.payload;

    if (name) {
	char *acl;

	/* Don't list mailboxes that we don't treat as RSS feeds */
	if (!is_feed(name)) return 0;

	/* Don't list deleted mailboxes */
	if (mboxname_isdeletedmailbox(name)) return 0;

	/* Lookup the mailbox and make sure its readable */
	http_mlookup(name, NULL, &acl, NULL);
	if (!acl || !(cyrus_acl_myrights(httpd_authstate, acl) & ACL_READ))
	    return 0;
    }

    if (name &&
	!strncmp(name, last->name, last->len) &&
	(!last->len || (name[last->len] == '.'))) {
	/* Found closest ancestor of 'name' */
	struct node *node;
	size_t len = matchlen;
	char *cp, *shortname, path[MAX_MAILBOX_PATH+1], *href = NULL;

	/* Send a body chunk once in a while */
	if (buf_len(buf) > PROT_BUFSIZE) {
	    write_body(0, lrock->txn, buf_cstring(buf), buf_len(buf));
	    buf_reset(buf);
	}

	if (last->child) {
	    /* Reuse our sibling */
	    buf_printf(buf, "</li>\n");
	    node = last->child;
	}
	else {
	    /* Create first child */
	    buf_printf(buf, "\n<ul%s>\n",
		       last->parent ? "" : " id='feed'"); /* needed by CSS */
	    node = xmalloc(sizeof(struct node));
	}

	/* See if we have a missing ancestor in the tree */
	if ((cp = strchr(&name[last->len+1], '.'))) len = cp - name;
	else href = path;

	/* Populate new/updated node */
	strncpy(node->name, name, len);
	node->name[len] = '\0';
	node->len = len;
	node->parent = last;
	node->child = NULL;
	lrock->last = last->child = node;

	/* Get last segment of mailbox name */
	if ((shortname = strrchr(node->name, '.'))) shortname++;
	else shortname = node->name;

	if (href) {
	    /* Add selectable feed with link */
	    snprintf(path, sizeof(path), ".rss.%s", node->name);
	    mboxname_hiersep_toexternal(&httpd_namespace, href, 0);
	    buf_printf(buf, "<li><a href=\"%s\">%s</a>",
		       href, shortname);
	}
	else {
	    /* Add missing ancestor and recurse down the tree */
	    buf_printf(buf, "<li>%s", shortname);

	    list_cb(name, matchlen, maycreate, rock);
	}
    }
    else {
	/* Remove child */
	if (last->child) {
	    buf_printf(buf, "</li>\n</ul>\n");
	    free(last->child);
	    last->child = NULL;
	}

	if (last->parent) {
	    /* Recurse back up the tree */
	    lrock->last = last->parent;
	    list_cb(name, matchlen, maycreate, rock);
	}
    }

    return 0;
}


/* Create a HTML document listing all RSS feeds available to the user */
static int list_feeds(struct transaction_t *txn)
{
    const char *template = config_getstring(IMAPOPT_RSS_FEEDLIST_TEMPLATE);
    const char *msg_base = NULL;
    unsigned long msg_size = 0, template_len;
    int fd = -1;
    const char *var = NULL;
    size_t varlen = strlen(FEEDLIST_VAR);
    struct message_guid guid;
    time_t lastmod;
    char mboxlist[MAX_MAILBOX_PATH+1];
    struct stat sbuf;
    int ret = 0, precond;
    struct buf *body = &txn->resp_body.payload;
    struct list_rock lrock;
    struct node root = { "", 0, NULL, NULL };

    if (template) {
	/* See if template exists and contains feedlist variable */
	if (!stat(template, &sbuf) && S_ISREG(sbuf.st_mode) &&
	    (fd = open(template, O_RDONLY)) != -1) {
	    map_refresh(fd, 1, &msg_base, &msg_size, sbuf.st_size,
			template, NULL);
	    var = (const char *) memmem(msg_base, msg_size,
					FEEDLIST_VAR, varlen);
	    if (var) {
		template = msg_base;
		template_len = msg_size;
		lastmod = sbuf.st_mtime;
	    }
	}
    }

    if (!var) {
	/* No usable template specified, use our default */
	template = def_template;
	template_len = strlen(def_template);
	var = (const char *) memmem(template, template_len,
				    FEEDLIST_VAR, varlen);
	lastmod = compile_time;
    }

    /* Begin to generate ETag */
    message_guid_generate(&guid, template, template_len);
    buf_setcstr(&txn->buf, message_guid_encode(&guid));

    /* stat() mailboxes.db for Last-Modified and ETag */
    snprintf(mboxlist, MAX_MAILBOX_PATH, "%s%s", config_dir, FNAME_MBOXLIST);
    stat(mboxlist, &sbuf);
    lastmod = MAX(lastmod, sbuf.st_mtime);
    buf_printf(&txn->buf, "-%ld-%ld", sbuf.st_mtime, sbuf.st_size);

    /* stat() imapd.conf for Last-Modified and ETag */
    stat(config_filename, &sbuf);
    lastmod = MAX(lastmod, sbuf.st_mtime);
    buf_printf(&txn->buf, "-%ld-%ld", sbuf.st_mtime, sbuf.st_size);

    /* Check any preconditions */
    precond = check_precond(txn, NULL, buf_cstring(&txn->buf), lastmod, 0);

    switch (precond) {
    case HTTP_OK:
	break;

    case HTTP_NOT_MODIFIED:
	/* Fill in ETag for 304 response */
	txn->resp_body.etag = buf_cstring(&txn->buf);

    default:
	/* We failed a precondition - don't perform the request */
	ret = precond;
	goto done;
    }

    /* Fill in ETag, Last-Modified, and Content-Type */
    txn->resp_body.etag = buf_cstring(&txn->buf);
    txn->resp_body.lastmod = lastmod;
    txn->resp_body.type = "text/html; charset=utf-8";

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;

    /* Short-circuit for HEAD request */
    if (txn->meth == METH_HEAD) {
	response_header(HTTP_OK, txn);
	goto done;
    }

    /* Send beginning of template */
    write_body(HTTP_OK, txn, template, var - template);

    /* Generate tree view of feeds */
    buf_reset(body);
    lrock.txn = txn;
    lrock.last = &root;
    mboxlist_findall(NULL, "*", httpd_userisadmin, NULL, httpd_authstate,
		     list_cb, &lrock);

    /* Close out the tree */
    list_cb(NULL, 0, 0, &lrock);
    if (buf_len(body)) write_body(0, txn, buf_cstring(body), buf_len(body));

    /* Send rest of template */
    write_body(0, txn, var + varlen, template_len - (var - template) - varlen);

    /* End of output */
    write_body(0, txn, NULL, 0);

  done:
    if (fd != -1) {
	map_free(&msg_base, &msg_size);
	close(fd);
    }

    return ret;
}


/* Fetch the index record & bodystructure, and mmap the message */
static int fetch_message(struct transaction_t *txn, struct mailbox *mailbox,
			 unsigned recno, uint32_t uid,
			 struct index_record *record, struct body **body,
			 const char **msg_base, unsigned long *msg_size)
{
    int r;

    *body = NULL;
    *msg_base = NULL;

    /* Fetch index record for the message */
    if (uid) r = mailbox_find_index_record(mailbox, uid, record);
    else r = mailbox_read_index_record(mailbox, recno, record);
    if ((r == CYRUSDB_NOTFOUND) ||
	(record->system_flags & (FLAG_DELETED|FLAG_EXPUNGED))) {
	txn->error.desc = "Message has been removed\r\n";
	return HTTP_GONE;
    }
    else if (r) {
	syslog(LOG_ERR, "find index record failed");
	txn->error.desc = error_message(r);
	return HTTP_SERVER_ERROR;
    }

    /* Fetch cache record for the message */
    if ((r = mailbox_cacherecord(mailbox, record))) {
	syslog(LOG_ERR, "read cache failed");
	txn->error.desc = error_message(r);
	return HTTP_SERVER_ERROR;
    }

    /* Read message bodystructure */
    message_read_bodystructure(record, body);

    /* Map the message into memory */
    mailbox_map_message(mailbox, record->uid, msg_base, msg_size);

    return 0;
}


static void buf_escapestr(struct buf *buf, const char *str, unsigned max,
			  unsigned replace)
{
    const char *c;
    unsigned buflen = buf_len(buf), len = 0;

    for (c = str; c && *c && (!max || len < max); c++, len++) {
	/* Translate CR to HTML <br> tag */
	if (*c == '\r') buf_appendcstr(buf, "<br>");

	/* Translate XML/HTML specials */
	else if (*c == '"') buf_appendcstr(buf, "&quot;");
	else if (*c == '\'') buf_appendcstr(buf, "&apos;");
	else if (*c == '&') buf_appendcstr(buf, "&amp;");
	else if (*c == '<') buf_appendcstr(buf, "&lt;");
	else if (*c == '>') buf_appendcstr(buf, "&gt;");

	/* Check for non-printable chars */
	else if (!(isspace(*c) || isprint(*c))) {
	    if (replace) {
		/* Replace entire string with a warning */
		buf_truncate(buf, buflen);
		buf_appendcstr(buf, "<blockquote><i><b>NOTE:</b> "
			       "This message contains characters "
			       "that can not be displayed in RSS"
			       "</i></blockquote>");
		return;
	    }
	    else {
		/* Translate non-printable chars to X */
		buf_putc(buf, 'X');
	    }
	}

	else buf_putc(buf, *c);
    }
}


/* List messages as an RSS feed */
static int list_messages(struct transaction_t *txn, struct mailbox *mailbox)
{
    const char **fwd, *proto = NULL, *host = NULL, *webmaster;
    uint32_t url_len, recno, recentuid = 0;
    int max_age, max_items, max_len, ttl, nitems, precond;
    time_t age_mark = 0, lastmod;
    char datestr[80];
    static char etag[33];
    struct buf *url = &txn->buf;
    struct buf *buf = &txn->resp_body.payload;

    /* Check any preconditions */
    lastmod = mailbox->i.last_appenddate;
    sprintf(etag, "%u-%u-%u",
	    mailbox->i.uidvalidity, mailbox->i.last_uid, mailbox->i.exists);
    precond = check_precond(txn, NULL, etag, lastmod, 0);

    switch (precond) {
    case HTTP_OK:
	break;

    case HTTP_NOT_MODIFIED:
	/* Fill in ETag for 304 response */
	txn->resp_body.etag = etag;

    default:
	/* We failed a precondition - don't perform the request */
	return precond;
    }

    /* Fill in ETag and Last-Modified */
    txn->resp_body.etag = etag;
    txn->resp_body.lastmod = lastmod;

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;
    txn->resp_body.type = "application/xml; charset=utf-8";

    /* Short-circuit for HEAD request */
    if (txn->meth == METH_HEAD) {
	response_header(HTTP_OK, txn);
	return 0;
    }

    /* Get maximum age of items to display */
    max_age = config_getint(IMAPOPT_RSS_MAXAGE);
    if (max_age > 0) age_mark = time(0) - (max_age * 60 * 60 * 24);

    /* Get number of items to display */
    max_items = config_getint(IMAPOPT_RSS_MAXITEMS);
    if (max_items < 0) max_items = 0;

    /* Get length of description to display */
    max_len = config_getint(IMAPOPT_RSS_MAXSYNOPSIS);
    if (max_len < 0) max_len = 0;

    /* Get TTL */
    ttl = config_getint(IMAPOPT_RSS_TTL);
    if (ttl < 0) ttl = 0;

#if 0
    /* Obtain recentuid */
    if (mailbox_internal_seen(mailbox, httpd_userid)) {
	recentuid = mailbox->i.recentuid;
    }
    else if (httpd_userid) {
	struct seen *seendb = NULL;
	struct seendata sd;

	r = seen_open(httpd_userid, SEEN_CREATE, &seendb);
	if (!r) r = seen_read(seendb, mailbox->uniqueid, &sd);
	seen_close(&seendb);

	/* handle no seen DB gracefully */
	if (r) {
	    recentuid = mailbox->i.last_uid;
	    syslog(LOG_ERR, "Could not open seen state for %s (%s)",
		   httpd_userid, error_message(r));
	}
	else {
	    recentuid = sd.lastuid;
	    free(sd.seenuids);
	}
    }
    else {
	recentuid = mailbox->i.last_uid; /* nothing is recent! */
    }
#endif

    /* Start XML */
    buf_setcstr(buf, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

    /* Set up the RSS <channel> response for the mailbox */
    buf_appendcstr(buf, "<rss xmlns:atom=\"" XML_NS_ATOM
		   "\" version=\"2.0\">\n");
    buf_appendcstr(buf, "<channel>\n");
    buf_printf(buf, "<title>%s</title>\n", mailbox->name);

    /* Construct base URL */
    if (config_mupdate_server && config_getstring(IMAPOPT_PROXYSERVERS) &&
	(fwd = spool_getheader(txn->req_hdrs, "Forwarded"))) {
	/* Proxied request - parse last Forwarded header for proto and host */
	/* XXX  This is destructive of the header but we don't care
	 * and more importantly, need the tokens available after tok_fini()
	 */
	tok_t tok;
	char *token;

	while (fwd[1]) ++fwd;  /* Skip to last Forwarded header */

	tok_initm(&tok, (char *) fwd[0], ";", 0);
	while ((token = tok_next(&tok))) {
	    if (!strncmp(token, "proto=", 6)) proto = token+6;
	    else if (!strncmp(token, "host=", 5)) host = token+5;
	}
	tok_fini(&tok);
    }
    else {
	/* Use our protocol and host */
	proto = https ? "https" : "http";
	host = *spool_getheader(txn->req_hdrs, "Host");
    }
    assert(!buf_len(url));
    buf_printf(url, "%s://%s%s", proto, host, txn->req_uri->path);
    url_len = buf_len(url);

    buf_printf(buf, "<link>%s</link>\n", buf_cstring(url));

    /* Recommended by http://www.rssboard.org/rss-profile */
    buf_printf(buf, "<atom:link href=\"%s\" rel=\"self\""
	       " type=\"application/rss+xml\"/>\n", buf_cstring(url));

    /* XXX  Use /comment annotation as description? */
    buf_appendcstr(buf, "<description/>\n");

    if ((webmaster = config_getstring(IMAPOPT_RSS_WEBMASTER))) {
      buf_printf(buf, "<webMaster>%s</webMaster>\n", webmaster);
    }

    rfc822date_gen(datestr, sizeof(datestr), time(NULL));
    buf_printf(buf, "<pubDate>%s</pubDate>\n", datestr);

    rfc822date_gen(datestr, sizeof(datestr), lastmod);
    buf_printf(buf, "<lastBuildDate>%s</lastBuildDate>\n", datestr);

    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
	buf_printf(buf, "<generator>Cyrus HTTP %s</generator>\n",
		   cyrus_version());
    }

    buf_printf(buf, "<docs>%s</docs>\n", RSS_SPEC);

    if (ttl) buf_printf(buf, "<ttl>%d</ttl>\n", ttl);

    write_body(HTTP_OK, txn, buf_cstring(buf), buf_len(buf));
    buf_reset(buf);

    /* Add an <item> for each message */
    for (recno = mailbox->i.num_records, nitems = 0;
	 recno >= 1 && (!max_items || nitems < max_items); recno--) {
	struct index_record record;
	const char *msg_base;
	unsigned long msg_size;
	struct body *body;
	char *subj;
	const char *content_types[] = { "text", NULL };
	struct message_content content;
	struct bodypart **parts;

	/* Send a body chunk once in a while */
	if (buf_len(buf) > PROT_BUFSIZE) {
	    write_body(0, txn, buf_cstring(buf), buf_len(buf));
	    buf_reset(buf);
	}

	/* Fetch the message */
	if (fetch_message(txn, mailbox, recno, 0,
			  &record, &body, &msg_base, &msg_size)) {
	    continue;
	}

	/* XXX  Are we going to do anything with \Recent? */
	if (record.uid <= recentuid) {
	    syslog(LOG_DEBUG, "recno %u not recent (%u/%u)",
		   recno, record.uid, recentuid);
	    continue;
	}

	/* Make sure the message is new enough */
	if (record.gmtime < age_mark) continue;

	/* Feeding this message, increment counter */
	nitems++;

	buf_appendcstr(buf, "<item>\n");

	subj = charset_parse_mimeheader(body->subject);
	buf_appendcstr(buf, "<title>");
	buf_escapestr(buf, subj && *subj ? subj : "[Untitled]", 0, 0);
	buf_appendcstr(buf, "</title>\n");
	free(subj);

	buf_truncate(url, url_len);
	buf_printf(url, "?uid=%u", record.uid);
	buf_printf(buf, "<link>%s</link>\n", buf_cstring(url));

	if (body->from || body->sender) {
	    struct address *addr;

	    if (body->from) addr = body->from;
	    else addr = body->sender;

	    if (*addr->mailbox) {
		buf_appendcstr(buf, "<author>");
		buf_escapestr(buf, addr->mailbox, 0, 0);
		buf_putc(buf, '@');
		buf_escapestr(buf, addr->domain, 0, 0);
		if (addr->name) {
		    buf_appendcstr(buf, " (");
		    buf_escapestr(buf, addr->name, 0, 0);
		    buf_putc(buf, ')');
		}
		buf_appendcstr(buf, "</author>\n");
	    }
	}

	buf_printf(buf, "<guid isPermaLink=\"false\">%s</guid>\n",
		   message_guid_encode(&record.guid));

	rfc822date_gen(datestr, sizeof(datestr), record.gmtime);
	buf_printf(buf, "<pubDate>%s</pubDate>\n", datestr);

	/* Find and use the first text/ part as the <description> */
	content.base = msg_base;
	content.len = msg_size;
	content.body = body;
	message_fetch_part(&content, content_types, &parts);

	if (parts && *parts) {
	    buf_appendcstr(buf, "<description><![CDATA[");
	    buf_escapestr(buf, parts[0]->decoded_body, max_len, 1);
	    buf_appendcstr(buf, "]]></description>\n");
	}

	buf_appendcstr(buf, "</item>\n");

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

    /* End of RSS <channel> */
    buf_appendcstr(buf, "</channel>\n</rss>\n");
    write_body(0, txn, buf_cstring(buf), buf_len(buf));

    /* End of output */
    write_body(0, txn, NULL, 0);

    return 0;
}


static void display_address(struct buf *buf, struct address *addr,
			    const char *sep)
{
    buf_printf(buf, "%s", sep);
    if (addr->name) buf_printf(buf, "\"%s\" ", addr->name);
    buf_printf(buf, "<a href=\"mailto:%s@%s\">&lt;%s@%s&gt;</a>\n",
	       addr->mailbox, addr->domain, addr->mailbox, addr->domain);
}


static void display_part(struct transaction_t *txn,
			 struct body *body, uint32_t uid,
			 const char *cursection, const char *msg_base)
{
    struct buf *buf = &txn->resp_body.payload;
    char nextsection[MAX_SECTION_LEN+1];

    if (!strcmp(body->type, "MULTIPART")) {
	int i;

	if (!strcmp(body->subtype, "ALTERNATIVE") &&
	    !strcmp(body->subpart[0].type, "TEXT")) {
	    /* Display a multpart/ or text/html subpart,
	       otherwise display first subpart */
	    for (i = body->numparts; --i;) {
		if (!strcmp(body->subpart[i].type, "MULTIPART") ||
		    !strcmp(body->subpart[i].subtype, "HTML")) break;
	    }
	    snprintf(nextsection, sizeof(nextsection), "%s%s%d",
		     cursection, *cursection ? "." : "", i+1);
	    display_part(txn, &body->subpart[i],
			 uid, nextsection, msg_base);
	}
	else {
	    /* Display all subparts */
	    for (i = 0; i < body->numparts; i++) {
		snprintf(nextsection, sizeof(nextsection), "%s%s%d",
			 cursection, *cursection ? "." : "", i+1);
		display_part(txn, &body->subpart[i],
			     uid, nextsection, msg_base);
	    }
	}
    }
    else if (!strcmp(body->type, "MESSAGE") &&
	     !strcmp(body->subtype, "RFC822")) {
	struct body *subpart = body->subpart;
	struct address *addr;
	char *sep;

	/* Display enclosed message header as a shaded table */
	buf_printf(buf, "<table width=\"100%%\" bgcolor=\"#CCCCCC\">\n");
	/* Subject header field */
	if (subpart->subject) {
	    char *subj;

	    subj = charset_parse_mimeheader(subpart->subject);
	    buf_printf(buf, "<tr><td align=right valign=top><b>Subject: </b>");
	    buf_printf(buf, "<td>%s\n", subj);
	    free(subj);
	}
	/* From header field */
	if (subpart->from && *subpart->from->mailbox) {
	    buf_printf(buf, "<tr><td align=right><b>From: </b><td>");
	    display_address(buf, subpart->from, "");
	}
	/* Sender header field (if different than From */
	if (subpart->sender && *subpart->sender->mailbox &&
	    (!subpart->from ||
	     strcmp(subpart->sender->mailbox, subpart->from->mailbox) ||
	     strcmp(subpart->sender->domain, subpart->from->domain))) {
	    buf_printf(buf, "<tr><td align=right><b>Sender: </b><td>");
	    display_address(buf, subpart->sender, "");
	}
	/* Reply-To header field (if different than From */
	if (subpart->reply_to && *subpart->reply_to->mailbox &&
	    (!subpart->from ||
	     strcmp(subpart->reply_to->mailbox, subpart->from->mailbox) ||
	     strcmp(subpart->reply_to->domain, subpart->from->domain))) {
	    buf_printf(buf, "<tr><td align=right><b>Reply-To: </b><td>");
	    display_address(buf, subpart->reply_to, "");
	}
	/* Date header field */
	buf_printf(buf, "<tr><td align=right><b>Date: </b>");
	buf_printf(buf, "<td width=\"100%%\">%s\n", subpart->date);
	/* To header field (possibly multiple addresses) */
	if (subpart->to) {
	    buf_printf(buf, "<tr><td align=right valign=top><b>To: </b><td>");
	    for (sep = "", addr = subpart->to; addr; addr = addr->next) {
		display_address(buf, addr, sep);
		sep = ", ";
	    }
	}
	/* Cc header field (possibly multiple addresses) */
	if (subpart->cc) {
	    buf_printf(buf, "<tr><td align=right valign=top><b>Cc: </b><td>");
	    for (sep = "", addr = subpart->cc; addr; addr = addr->next) {
		display_address(buf, addr, sep);
		sep = ", ";
	    }
	}
	buf_printf(buf, "</table><br>\n");

	/* Display subpart */
	snprintf(nextsection, sizeof(nextsection), "%s%s%d",
		 cursection, *cursection ? "." : "", 1);
	display_part(txn, subpart, uid, nextsection, msg_base);
    }
    else {
	/* Leaf part - display something */

	if (!strcmp(body->type, "TEXT")) {
	    /* Display text part */
	    int ishtml = !strcmp(body->subtype, "HTML");
	    int charset = body->charset_cte >> 16;
	    int encoding = body->charset_cte & 0xff;

	    if (charset < 0) charset = 0; /* unknown, try ASCII */
	    body->decoded_body =
		charset_to_utf8(msg_base + body->content_offset,
				body->content_size, charset, encoding);
	    if (!ishtml) buf_printf(buf, "<pre>");
	    write_body(0, txn, buf_cstring(buf), buf_len(buf));
	    buf_reset(buf);

	    write_body(0, txn, body->decoded_body, strlen(body->decoded_body));
	    if (!ishtml) buf_printf(buf, "</pre>");
	}
	else {
	    int is_image = !strcmp(body->type, "IMAGE");
	    struct param *param = body->params;
	    const char *file_attr = "NAME";

	    /* Anything else is shown as an attachment.
	     * Show images inline, using name/description as alternative text.
	     */
	    /* Look for a filename in parameters */
	    if (body->disposition) {
		if (!strcmp(body->disposition, "ATTACHMENT")) is_image = 0;
		param = body->disposition_params;
		file_attr = "FILENAME";
	    }
	    for (; param && strcmp(param->attribute, file_attr);
		 param = param->next);

	    buf_printf(buf, "<div align=center>");

	    /* Create link */
	    buf_printf(buf, "<a href=\"%s?uid=%u;section=%s\" type=\"%s/%s\">",
		       txn->req_tgt.path, uid, cursection,
		       body->type, body->subtype);

	    /* Add image */
	    if (is_image) {
		buf_printf(buf, "<img src=\"%s?uid=%u;section=%s\" alt=\"",
			   txn->req_tgt.path, uid, cursection);
	    }

	    /* Create text for link or alternative text for image */
	    if (param) buf_printf(buf, "%s", param->value);
	    else {
		buf_printf(buf, "[%s/%s %lu bytes]",
			   body->type, body->subtype, body->content_size);
	    }

	    if (is_image) buf_printf(buf, "\">");
	    buf_printf(buf, "</a></div>");
	}

	buf_printf(buf, "\n<hr>\n");
    }
}


/* Return entire message formatted as text/html */
static void display_message(struct transaction_t *txn,
			    const char *mboxname, uint32_t uid,
			    struct body *body, const char *msg_base)
{
    struct body toplevel;
    struct buf *buf = &txn->resp_body.payload;

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;
    txn->resp_body.type = "text/html; charset=utf-8";

    /* Short-circuit for HEAD request */
    if (txn->meth == METH_HEAD) {
	response_header(HTTP_OK, txn);
	return;
    }

    /* Start HTML */
    buf_setcstr(buf, HTML_DOCTYPE);
    buf_printf(buf, "<html><head><title>%s:%u</title></head><body>\n",
	       mboxname, uid);

    /* Create link to message source */
    buf_printf(buf, "<div align=center>");
    buf_printf(buf, "<a href=\"%s?uid=%u;section=0\" type=\"plain/text\">",
	       txn->req_tgt.path, uid);
    buf_printf(buf, "[View message source]</a></div><hr>\n");

    write_body(HTTP_OK, txn, buf_cstring(buf), buf_len(buf));
    buf_reset(buf);

    /* Encapsulate our body in a message/rfc822 to display toplevel hdrs */
    memset(&toplevel, 0, sizeof(struct body));
    toplevel.type = "MESSAGE";
    toplevel.subtype = "RFC822";
    toplevel.subpart = body;

    display_part(txn, &toplevel, uid, "", msg_base);

    /* End of HTML */
    buf_printf(buf, "</body></html>");
    write_body(0, txn, buf_cstring(buf), buf_len(buf));

    /* End of output */
    write_body(0, txn, NULL, 0);
}


/* Fetch, decode, and return the specified MIME message part */
static void fetch_part(struct transaction_t *txn, struct body *body,
		       const char *findsection, const char *cursection,
		       const char *msg_base)
{
    char nextsection[MAX_SECTION_LEN+1];

    if (!strcmp(body->type, "MULTIPART")) {
	int i;

	/* Recurse through all subparts */
	for (i = 0; i < body->numparts; i++) {
	    snprintf(nextsection, sizeof(nextsection), "%s%s%d",
		     cursection, *cursection ? "." : "", i+1);
	    fetch_part(txn, &body->subpart[i],
		       findsection, nextsection, msg_base);
	}
    }
    else if (!strcmp(body->type, "MESSAGE") &&
	     !strcmp(body->subtype, "RFC822")) {
	/* Recurse into supbart */
	snprintf(nextsection, sizeof(nextsection), "%s%s%d",
		 cursection, *cursection ? "." : "", 1);
	fetch_part(txn, body->subpart, findsection, nextsection, msg_base);
    }
    else if (!strcmp(findsection, cursection)) {
	int encoding = body->charset_cte & 0xff;
	const char *outbuf;
	size_t outsize;

	outbuf = charset_decode_mimebody(msg_base + body->content_offset,
					 body->content_size, encoding,
					 &body->decoded_body, 0, &outsize);

	if (!outbuf) {
	    txn->error.desc = "Unknown MIME encoding\r\n";
	    error_response(HTTP_SERVER_ERROR, txn);
	    return;

	}

	assert(!buf_len(&txn->buf));
	buf_printf(&txn->buf, "%s/%s", body->type, body->subtype);
	txn->resp_body.type = buf_cstring(&txn->buf);

	write_body(HTTP_OK, txn, outbuf, outsize);
    }
}
