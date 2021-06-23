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
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "acl.h"
#include "annotate.h"
#include "charset.h"
#include "global.h"
#include "httpd.h"
#include "http_proxy.h"
#include "mailbox.h"
#include "map.h"
#include "mboxlist.h"
#include "message.h"
#include "parseaddr.h"
#include "proxy.h"
#include "times.h"
#include "seen.h"
#include "tok.h"
#include "util.h"
#include "version.h"
#include "wildmat.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#define XML_NS_ATOM     "http://www.w3.org/2005/Atom"
#define GUID_URL_SCHEME "data:,"
#define MAX_SECTION_LEN 128
#define FEEDLIST_VAR    "%RSS_FEEDLIST%"

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
                         struct buf *msg_buf);
static int list_messages(struct transaction_t *txn, struct mailbox *mailbox);
static void display_message(struct transaction_t *txn,
                            const char *mboxname, const struct index_record *record,
                            struct body *body, const struct buf *msg_buf);
static struct body *body_fetch_section(struct body *body, const char *section);


/* Namespace for RSS feeds of mailboxes */
struct namespace_t namespace_rss = {
    URL_NS_RSS, 0, "rss", "/rss", NULL,
    http_allow_noauth_get, /*authschemes*/0,
    /*mbtype*/0,
    ALLOW_READ,
    rss_init, NULL, NULL, NULL, NULL, NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { NULL,                 NULL },                 /* CONNECT      */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
        { &meth_get,            NULL },                 /* GET          */
        { &meth_get,            NULL },                 /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { &meth_options,        &rss_parse_path },      /* OPTIONS      */
        { NULL,                 NULL },                 /* PATCH        */
        { NULL,                 NULL },                 /* POST         */
        { NULL,                 NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { &meth_trace,          &rss_parse_path },      /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { NULL,                 NULL }                  /* UNLOCK       */
    }
};


static void rss_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_rss.enabled = config_httpmodules & IMAP_ENUM_HTTPMODULES_RSS;

    if (!namespace_rss.enabled) return;

    compile_time = calc_compile_time(__TIME__, __DATE__);
}

/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn,
                    void *params __attribute__((unused)))
{
    int ret = 0, r, rights;
    struct strlist *param;
    char *section = NULL;
    uint32_t uid = 0;
    struct mailbox *mailbox = NULL;

    if (!httpd_userid) return HTTP_UNAUTHORIZED;

    /* Construct mailbox name corresponding to request target URI */
    if ((r = rss_parse_path(txn->req_uri->path,
                            &txn->req_tgt, &txn->error.desc))) {
        txn->error.desc = error_message(r);
        return HTTP_NOT_FOUND;
    }

    /* If no mailboxname, list all available feeds */
    if (!txn->req_tgt.mbentry) return list_feeds(txn);

    /* Make sure its a mailbox that we are treating as an RSS feed */
    if (!is_feed(txn->req_tgt.mbentry->name)) return HTTP_NOT_FOUND;

    /* Check ACL for current user */
    rights = httpd_myrights(httpd_authstate, txn->req_tgt.mbentry);
    if (!(rights & ACL_READ)) return HTTP_NO_PRIVS;

    if (txn->req_tgt.mbentry->server) {
        /* Remote mailbox */
        struct backend *be;

        be = proxy_findserver(txn->req_tgt.mbentry->server,
                              &http_protocol, httpd_userid,
                              &backend_cached, NULL, NULL, httpd_in);
        if (!be) return HTTP_UNAVAILABLE;

        return http_pipe_req_resp(be, txn);
    }

    /* Local Mailbox */

    /* Open mailbox for reading */
    r = mailbox_open_irl(txn->req_tgt.mbentry->name, &mailbox);
    if (r) {
        syslog(LOG_ERR, "http_mailbox_open(%s) failed: %s",
               txn->req_tgt.mbentry->name, error_message(r));
        txn->error.desc = error_message(r);

        switch (r) {
        case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
        case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
        default: return HTTP_SERVER_ERROR;
        }
    }

    /* Check for UID, if any */
    if (txn->req_tgt.resource) {
        uid = strtoul(txn->req_tgt.resource, NULL, 10);
        if (!uid) uid = -1;

        /* Check for section query param, if any */
        param = hash_lookup("section", &txn->req_qparams);
        if (param) section = param->s;
    }

    /* If no UID specified, list messages as an RSS feed */
    if (!uid) ret = list_messages(txn, mailbox);
    else if (uid > mailbox->i.last_uid) {
        txn->error.desc = "Message does not exist";
        ret = HTTP_NOT_FOUND;
    }
    else {
        struct index_record record;
        struct buf msg_buf = BUF_INITIALIZER;
        struct body *body = NULL;

        /* Fetch the message */
        if (!(ret = fetch_message(txn, mailbox, 0, uid,
                                  &record, &body, &msg_buf))) {
            int precond;
            const char *etag = NULL;
            time_t lastmod = 0;
            struct resp_body_t *resp_body = &txn->resp_body;

            /* Check any preconditions */
            if (section && !strcmp(section, "0")) {
                /* Entire raw message */
                txn->flags.ranges = 1;
            }

            etag = message_guid_encode(&record.guid);
            lastmod = record.internaldate;
            precond = check_precond(txn, etag, lastmod);

            switch (precond) {
            case HTTP_OK:
            case HTTP_PARTIAL:
            case HTTP_NOT_MODIFIED:
                /* Fill in ETag, Last-Modified, and Expires */
                resp_body->etag = etag;
                resp_body->lastmod = lastmod;
                resp_body->maxage = 31536000;  /* 1 year */
                txn->flags.cc |= CC_MAXAGE;
                if (httpd_userid) txn->flags.cc |= CC_PRIVATE;

                if (precond != HTTP_NOT_MODIFIED) break;

                GCC_FALLTHROUGH

            default:
                /* We failed a precondition - don't perform the request */
                ret = precond;
                goto done;
            }

            if (!section) {
                /* Return entire message formatted as text/html */
                display_message(txn, mailbox_name(mailbox), &record, body, &msg_buf);
            }
            else if (!strcmp(section, "0")) {
                /* Return entire message as text/plain */
                resp_body->type = "text/plain";
                write_body(precond, txn, buf_base(&msg_buf), buf_len(&msg_buf));
            }
            else {
                /* Fetch, decode, and return the specified MIME message part */
                struct body *part;
                const char *outbuf;
                size_t outsize;

                part = body_fetch_section(body, section);
                if (!part) {
                    ret = HTTP_NOT_FOUND;
                    goto done;
                }

                outbuf = charset_decode_mimebody(buf_base(&msg_buf) +
                                                 part->content_offset,
                                                 part->content_size,
                                                 part->charset_enc,
                                                 &part->decoded_body, &outsize);

                if (!outbuf) {
                    txn->error.desc = "Unknown MIME encoding";
                    ret = HTTP_SERVER_ERROR;
                    goto done;
                }

                assert(!buf_len(&txn->buf));
                buf_printf(&txn->buf, "%s/%s", part->type, part->subtype);
                txn->resp_body.type = buf_cstring(&txn->buf);

                write_body(precond, txn, outbuf, outsize);
            }

          done:
            buf_free(&msg_buf);

            if (body) {
                message_free_body(body);
                free(body);
            }
        }
    }

    mailbox_close(&mailbox);

    return ret;

}


/* Create a mailbox name from the request URL */
static int rss_parse_path(const char *path, struct request_target_t *tgt,
                          const char **resultstr)
{
    const char *start, *end;
    char mboxname[MAX_MAILBOX_BUFFER+1];
    size_t len;

    /* Clip off RSS prefix */
    start = path + strlen(namespace_rss.prefix);
    if (*start == '/') start++;
    end = start + strlen(start);

    if ((end > start) && (end[-1] == '/')) end--;

    /* Check for UID */
    if (end > start && end[-1] == '.') {
        const char *p;

        for (p = end-2; p > start && isdigit((int) *p); p--);
        if (*p == '/') {
            end = p;
            tgt->resource = (char *) ++p;
        }
    }

    len = end - start;
    if (len > MAX_MAILBOX_BUFFER) return IMAP_MAILBOX_BADNAME;

    strncpy(mboxname, start, len);
    mboxname[len] = '\0';

    /* Locate the mailbox */
    if (*mboxname) {
        /* Translate external (URL) mboxname to internal */
        for (; len > 0; len--) {
            if (mboxname[len-1] == '/') mboxname[len-1] = '.';
            else if (mboxname[len-1] == '.') mboxname[len-1] = '^';
        }

        int r = proxy_mlookup(mboxname, &tgt->mbentry, NULL, NULL);
        if (r) {
            syslog(LOG_ERR, "mlookup(%s) failed: %s",
                   mboxname, error_message(r));
            *resultstr = error_message(r);

            switch (r) {
            case IMAP_PERMISSION_DENIED: return HTTP_FORBIDDEN;
            case IMAP_MAILBOX_NONEXISTENT: return HTTP_NOT_FOUND;
            default: return HTTP_SERVER_ERROR;
            }
        }
    }

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

static int do_list(const char *name, void *rock)
{
    struct list_rock *lrock = (struct list_rock *) rock;
    struct node *last = lrock->last;
    struct buf *buf = &lrock->txn->resp_body.payload;

    if (name) {
        int rights;
        mbentry_t *mbentry = NULL;
        int r;

        /* Don't list mailboxes that we don't treat as RSS feeds */
        if (!is_feed(name)) return 0;

        /* Don't list deleted mailboxes */
        if (mboxname_isdeletedmailbox(name, NULL)) return 0;

        /* Lookup the mailbox and make sure its readable */
        r = proxy_mlookup(name, &mbentry, NULL, NULL);
        if (r) return 0;

        rights = httpd_myrights(httpd_authstate, mbentry);
        mboxlist_entry_free(&mbentry);

        if ((rights & ACL_READ) != ACL_READ)
            return 0;
    }

    if (name &&
        !strncmp(name, last->name, last->len) &&
        (!last->len || (name[last->len] == '.'))) {
        /* Found closest ancestor of 'name' */
        struct node *node;
        size_t len = strlen(name);
        char shortname[MAX_MAILBOX_NAME+1], path[MAX_MAILBOX_PATH+1];
        char *cp, *href = NULL;

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
        xstrncpy(node->name, name, len);
        node->name[len] = '\0';
        node->len = len;
        node->parent = last;
        node->child = NULL;
        lrock->last = last->child = node;

        /* Get last segment of mailbox name */
        if ((cp = strrchr(node->name, '.'))) cp++;
        else cp = node->name;

        /* Translate short mailbox name to external form */
        strlcpy(shortname, cp, sizeof(shortname));

        if (href) {
            /* Add selectable feed with link */
            struct buf *mboxname = &lrock->txn->buf;

            /* Translate internal mboxname to external (URL) */
            buf_setcstr(mboxname, node->name);
            for (; len > 0; len--) {
                if (mboxname->s[len-1] == '.') mboxname->s[len-1] = '/';
                else if (mboxname->s[len-1] == '^') mboxname->s[len-1] = '.';
            }

            snprintf(path, sizeof(path), "/rss/%s", buf_cstring(mboxname));
            buf_printf(buf, "<li><a href=\"%s\">%s</a>",
                       href, shortname);
        }
        else {
            /* Add missing ancestor and recurse down the tree */
            buf_printf(buf, "<li>%s", shortname);

            do_list(name, rock);
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
            do_list(name, rock);
        }
    }

    return 0;
}

static int list_cb(struct findall_data *data, void *rock)
{
    if (data && data->is_exactmatch)
        return do_list(mbname_intname(data->mbname), rock);
    return do_list(NULL, rock);
}


/* Create a HTML document listing all RSS feeds available to the user */
static int list_feeds(struct transaction_t *txn)
{
    const char *template_file = config_getstring(IMAPOPT_RSS_FEEDLIST_TEMPLATE);
    const char *var = NULL, *template = NULL, *prefix, *suffix;
    size_t template_len = 0, prefix_len, suffix_len;
    size_t varlen = strlen(FEEDLIST_VAR);
    int fd = -1;
    struct message_guid guid;
    time_t lastmod;
    char mboxlist[MAX_MAILBOX_PATH+1];
    struct stat sbuf;
    int ret = 0, precond;
    struct buf *body = &txn->resp_body.payload;
    struct list_rock lrock;
    struct node root = { "", 0, NULL, NULL };

    if (template_file) {
        struct buf *path = &txn->buf;

        buf_reset(path);
        prefix = config_getstring(IMAPOPT_HTTPDOCROOT);
        if (prefix) buf_printf(path, "%s/", prefix);
        buf_appendcstr(path, template_file);

        /* See if template exists and contains feedlist variable */
        if (!stat(buf_cstring(path), &sbuf) && S_ISREG(sbuf.st_mode) &&
            (size_t) sbuf.st_size >= varlen &&
            (fd = open(buf_cstring(path), O_RDONLY)) != -1) {
            const char *p;
            unsigned long len;

            map_refresh(fd, 1, &template, &template_len, sbuf.st_size,
                        template_file, NULL);

            for (p = template, len = template_len;
                 len >= varlen && strncmp(p, FEEDLIST_VAR, varlen); p++, len--);
            if (len >= varlen) {
                var = p;
                lastmod = sbuf.st_mtime;
            }
            else {
                map_free(&template, &template_len);
                close(fd);
                fd = -1;
            }
        }
    }

    if (!var) {
        /* No usable template specified, use our default */
        template = def_template;
        template_len = strlen(def_template);
        var = strstr(template, FEEDLIST_VAR);
        lastmod = compile_time;
    }

    prefix = template;
    prefix_len = var - template;
    suffix = template + prefix_len + varlen;
    suffix_len = template_len - (prefix_len + varlen);

    /* Begin to generate ETag */
    message_guid_generate(&guid, template, template_len);
    buf_setcstr(&txn->buf, message_guid_encode(&guid));

    /* stat() mailboxes.db for Last-Modified and ETag */
    snprintf(mboxlist, MAX_MAILBOX_PATH, "%s%s", config_dir, FNAME_MBOXLIST);
    stat(mboxlist, &sbuf);
    lastmod = MAX(lastmod, sbuf.st_mtime);
    buf_printf(&txn->buf, "-" TIME_T_FMT "-" OFF_T_FMT, sbuf.st_mtime, sbuf.st_size);

    /* stat() imapd.conf for Last-Modified and ETag */
    stat(config_filename, &sbuf);
    lastmod = MAX(lastmod, sbuf.st_mtime);
    buf_printf(&txn->buf, "-" TIME_T_FMT "-" OFF_T_FMT, sbuf.st_mtime, sbuf.st_size);

    /* Check any preconditions */
    precond = check_precond(txn, buf_cstring(&txn->buf), lastmod);

    switch (precond) {
    case HTTP_OK:
    case HTTP_NOT_MODIFIED:
        /* Fill in ETag, Last-Modified, and Expires */
        txn->resp_body.etag = buf_cstring(&txn->buf);
        txn->resp_body.lastmod = lastmod;
        txn->resp_body.maxage = 86400;  /* 24 hrs */
        txn->flags.cc |= CC_MAXAGE;

        if (precond != HTTP_NOT_MODIFIED) break;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        ret = precond;
        goto done;
    }

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;
    txn->resp_body.type = "text/html; charset=utf-8";

    /* Short-circuit for HEAD request */
    if (txn->meth == METH_HEAD) {
        response_header(HTTP_OK, txn);
        goto done;
    }

    /* Send beginning of template */
    write_body(HTTP_OK, txn, prefix, prefix_len);

    /* Generate tree view of feeds */
    buf_reset(body);
    lrock.txn = txn;
    lrock.last = &root;
    int isadmin = httpd_userisadmin||httpd_userisproxyadmin;
    mboxlist_findall(&httpd_namespace, "*", isadmin, httpd_userid,
                     httpd_authstate, list_cb, &lrock);

    /* Close out the tree */
    if (buf_len(body)) write_body(0, txn, buf_cstring(body), buf_len(body));

    /* Send rest of template */
    if (suffix_len) write_body(0, txn, suffix, suffix_len);

    /* End of output */
    write_body(0, txn, NULL, 0);

  done:
    if (fd != -1) {
        map_free(&template, &template_len);
        close(fd);
    }

    return ret;
}


/* Fetch the index record & bodystructure, and mmap the message */
static int fetch_message(struct transaction_t *txn, struct mailbox *mailbox,
                         unsigned recno, uint32_t uid,
                         struct index_record *record, struct body **body,
                         struct buf *msg_buf)
{
    int r;

    buf_reset(msg_buf);

    /* Fetch index record for the message */
    memset(record, 0, sizeof(struct index_record));
    record->recno = recno;
    record->uid = uid;
    r = mailbox_reload_index_record(mailbox, record);
    if ((r == CYRUSDB_NOTFOUND) ||
        ((record->system_flags & FLAG_DELETED) ||
         record->internal_flags & FLAG_INTERNAL_EXPUNGED)) {
        txn->error.desc = "Message has been removed";

        /* Fill in Expires */
        txn->resp_body.maxage = 31536000;  /* 1 year */
        txn->flags.cc |= CC_MAXAGE;
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
    mailbox_map_record(mailbox, record, msg_buf);

    return 0;
}


static void buf_escapestr(struct buf *buf, const char *str, unsigned max,
                          unsigned replace, unsigned level)
{
    const char *c;
    unsigned buflen = buf_len(buf), len = 0;

    if (!replace && config_httpprettytelemetry)
        buf_printf(buf, "%*s", level * MARKUP_INDENT, "");

    for (c = str; c && *c && (!max || len < max); c++, len++) {
        /* Translate CR to HTML <br> tag */
        if (*c == '\r') buf_appendcstr(buf, "<br>");
        else if (*c == '\n' && !config_httpprettytelemetry) continue;

        /* Translate XML/HTML specials */
        else if (*c == '"') buf_appendcstr(buf, "&quot;");
//      else if (*c == '\'') buf_appendcstr(buf, "&apos;");
        else if (*c == '&') buf_appendcstr(buf, "&amp;");
        else if (*c == '<') buf_appendcstr(buf, "&lt;");
        else if (*c == '>') buf_appendcstr(buf, "&gt;");

        /* Handle multi-byte UTF-8 sequences */
        else if ((*c & 0xc0) == 0xc0) {
            /* Code points larger than 127 are represented by
             * multi-byte sequences, composed of a leading byte and
             * one or more continuation bytes.  The leading byte has
             * two or more high-order 1s followed by a 0, while
             * continuation bytes all have '10' in the high-order
             * position.  The number of high-order 1s in the leading
             * byte of a multi-byte sequence indicates the number of
             * bytes in the sequence.
             */
            unsigned char lead = *c;

            do buf_putc(buf, *c);
            while (((lead <<= 1) & 0x80) && c++);
        }

        /* Check for non-printable chars */
        else if (!(isspace(*c) || isprint(*c))) {
            if (replace) {
                /* Replace entire string with a warning */
                buf_truncate(buf, buflen);
                buf_printf_markup(buf, level++, "<blockquote>");
                buf_printf_markup(buf, level, "<i><b>NOTE:</b> "
                                  "This message contains characters "
                                  "that can not be displayed in RSS</i>");
                buf_printf_markup(buf, --level, "</blockquote>");
                return;
            }
            else {
                /* Translate non-printable chars to X */
                buf_putc(buf, 'X');
            }
        }

        else buf_putc(buf, *c);
    }

    if (!replace && config_httpprettytelemetry) buf_appendcstr(buf, "\n");
}


/* List messages as an RSS feed */
static int list_messages(struct transaction_t *txn, struct mailbox *mailbox)
{
    const char *proto = NULL, *host = NULL;
    uint32_t url_len, recno, recentuid = 0;
    int max_age, max_items, max_len, nitems, precond;
    time_t age_mark = 0, lastmod;
    char datestr[80];
    static char etag[33];
    struct buf *url = &txn->buf;
    struct buf *buf = &txn->resp_body.payload;
    unsigned level = 0;
    char mboxname[MAX_MAILBOX_NAME+1];
    struct buf attrib = BUF_INITIALIZER;

    /* Check any preconditions */
    lastmod = mailbox->i.last_appenddate;
    sprintf(etag, "%u-%u-%u",
            mailbox->i.uidvalidity, mailbox->i.last_uid, mailbox->i.exists);
    precond = check_precond(txn, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
    case HTTP_NOT_MODIFIED:
        /* Fill in ETag, Last-Modified, and Expires */
        txn->resp_body.etag = etag;
        txn->resp_body.lastmod = lastmod;
        txn->resp_body.maxage = 3600;  /* 1 hr */
        txn->flags.cc |= CC_MAXAGE;

        if (precond != HTTP_NOT_MODIFIED) break;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        return precond;
    }

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;
    txn->resp_body.type = "application/atom+xml; charset=utf-8";

    /* Short-circuit for HEAD request */
    if (txn->meth == METH_HEAD) {
        response_header(HTTP_OK, txn);
        return 0;
    }

    /* Get maximum age of items to display */
    max_age = config_getduration(IMAPOPT_RSS_MAXAGE, 'd');
    if (max_age > 0) age_mark = time(0) - max_age;

    /* Get number of items to display */
    max_items = config_getint(IMAPOPT_RSS_MAXITEMS);
    if (max_items < 0) max_items = 0;

    /* Get length of description to display */
    max_len = config_getint(IMAPOPT_RSS_MAXSYNOPSIS);
    if (max_len < 0) max_len = 0;

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

    /* Translate mailbox name to external form */
    strlcpy(mboxname, mailbox_name(mailbox), sizeof(mboxname));

    /* Construct base URL */
    http_proto_host(txn->req_hdrs, &proto, &host);
    assert(!buf_len(url));
    buf_printf(url, "%s://%s%s", proto, host, txn->req_uri->path);
    url_len = buf_len(url);

    /* Start XML */
    buf_reset(buf);
    buf_printf_markup(buf, level, XML_DECLARATION);

    /* Set up the Atom <feed> response for the mailbox */
    buf_printf_markup(buf, level++,
                      "<feed xmlns=\"" XML_NS_ATOM "\">");

    /* <title> - required */
    buf_printf_markup(buf, level, "<title>%s</title>", mboxname);

    /* <id> - required */
    buf_printf_markup(buf, level, "<id>%s%s</id>",
                      GUID_URL_SCHEME, mailbox->uniqueid);

    /* <updated> - required */
    time_to_rfc3339(lastmod, datestr, sizeof(datestr));
    buf_printf_markup(buf, level, "<updated>%s</updated>", datestr);

    /* <author> - required (use 'Anonymous' as default <name>) */
    buf_printf_markup(buf, level++, "<author>");
    buf_printf_markup(buf, level, "<name>Anonymous</name>");
    buf_printf_markup(buf, --level, "</author>");

    /* <subtitle> - optional */
    annotatemore_lookup_mbox(mailbox, "/comment", "", &attrib);
    if (age_mark) {
        time_to_rfc5322(age_mark, datestr, sizeof(datestr));
        buf_printf_markup(buf, level,
                        "<subtitle>%s [posts since %s]</subtitle>",
                          buf_cstring(&attrib), datestr);
    }
    else {
        buf_printf_markup(buf, level,
                          "<subtitle>%s [%u most recent posts]</subtitle>",
                          buf_cstring(&attrib),
                          max_items ? (unsigned) max_items : mailbox->i.exists);
    }
    buf_free(&attrib);

    /* <link> - optional */
    buf_printf_markup(buf, level,
                      "<link rel=\"self\" type=\"application/atom+xml\""
                      " href=\"%s\"/>", buf_cstring(url));

    /* <generator> - optional */
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
        buf_printf_markup(buf, level, "<generator>Cyrus HTTP %s</generator>",
                          CYRUS_VERSION);
    }

    write_body(HTTP_OK, txn, buf_cstring(buf), buf_len(buf));
    buf_reset(buf);

    /* Add an <entry> for each message */
    for (recno = mailbox->i.num_records, nitems = 0;
         recno >= 1 && (!max_items || nitems < max_items); recno--) {
        struct index_record record;
        struct body *body = NULL;
        char *subj;
        struct address *addr = NULL;
        const char *content_types[] = { "text", NULL };
        struct message_content content = MESSAGE_CONTENT_INITIALIZER;
        struct bodypart **parts;

        /* Send a body chunk once in a while */
        if (buf_len(buf) > PROT_BUFSIZE) {
            write_body(0, txn, buf_cstring(buf), buf_len(buf));
            buf_reset(buf);
        }

        /* Fetch the message */
        if (fetch_message(txn, mailbox, recno, 0,
                          &record, &body, &content.map)) {
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

        buf_printf_markup(buf, level++, "<entry>");

        /* <title> - required */
        subj = charset_parse_mimeheader(body->subject, charset_flags);
        buf_printf_markup(buf, level++, "<title type=\"html\">");
        buf_escapestr(buf, subj && *subj ? subj : "[Untitled]", 0, 0, level);
        buf_printf_markup(buf, --level, "</title>");
        free(subj);

        /* <id> - required */
        buf_printf_markup(buf, level, "<id>%s%s</id>",
                          GUID_URL_SCHEME, message_guid_encode(&record.guid));

        /* <updated> - required */
        time_to_rfc3339(record.gmtime, datestr, sizeof(datestr));
        buf_printf_markup(buf, level, "<updated>%s</updated>", datestr);

        /* <published> - optional */
        buf_printf_markup(buf, level, "<published>%s</published>", datestr);

        /* <link> - optional */
        buf_truncate(url, url_len);
        buf_printf(url, "/%u.", record.uid);
        buf_printf_markup(buf, level, "<link rel=\"alternate\""
                          " type=\"text/html\" href=\"%s\"/>",
                          buf_cstring(url));

        /* <author> - optional */
        addr = body->from;
        if (!addr) addr = body->sender;
        if (addr && *addr->mailbox) {
            buf_printf_markup(buf, level++, "<author>");

            /* <name> - required */
            if (addr->name) {
                char *name = charset_parse_mimeheader(addr->name, charset_flags);
                buf_printf_markup(buf, level++, "<name>");
                buf_escapestr(buf, name, 0, 0, level);
                buf_printf_markup(buf, --level, "</name>");
                free(name);
            }
            else {
                buf_printf_markup(buf, level, "<name>%s@%s</name>",
                                  addr->mailbox, addr->domain);
            }

            /* <email> - optional */
            buf_printf_markup(buf, level, "<email>%s@%s</email>",
                              addr->mailbox, addr->domain);

            buf_printf_markup(buf, --level, "</author>");
        }

        /* <summary> - optional (find and use the first text/ part) */
        content.body = body;
        message_fetch_part(&content, content_types, &parts);

        if (parts && *parts) {
            buf_printf_markup(buf, level++, "<summary type=\"html\">");
            buf_printf_markup(buf, level++, "<![CDATA[");
            buf_escapestr(buf, parts[0]->decoded_body, max_len, 1, level);
            buf_printf_markup(buf, --level, "]]>");
            buf_printf_markup(buf, --level, "</summary>");
        }

        buf_printf_markup(buf, --level, "</entry>");

        /* free the results */
        if (parts) {
            struct bodypart **p;

            for (p = parts; *p; p++) free(*p);
            free(parts);
        }

        if (body) {
            message_free_body(body);
            free(body);
        }

        buf_free(&content.map);
    }

    /* End of Atom <feed> */
    buf_printf_markup(buf, --level, "</feed>");
    write_body(0, txn, buf_cstring(buf), buf_len(buf));

    /* End of output */
    write_body(0, txn, NULL, 0);

    return 0;
}


static void display_address(struct buf *buf, struct address *addr,
                            const char *sep, unsigned level)
{
    if (config_httpprettytelemetry)
        buf_printf(buf, "%*s", level * MARKUP_INDENT, "");

    buf_printf(buf, "%s", sep);
    if (addr->name) buf_printf(buf, "\"%s\" ", addr->name);
    buf_printf(buf, "<a href=\"mailto:%s@%s\">&lt;%s@%s&gt;</a>",
               addr->mailbox, addr->domain, addr->mailbox, addr->domain);

    if (config_httpprettytelemetry) buf_appendcstr(buf, "\n");
}


static void display_part(struct transaction_t *txn,
                         struct body *body, const struct index_record *record,
                         const char *cursection, const struct buf *msg_buf,
                         unsigned level)
{
    struct buf *buf = &txn->resp_body.payload;
    char nextsection[MAX_SECTION_LEN+1];

    if (body->numparts) {
        /* multipart */
        int i = 0;

        if (!strcmp(body->subtype, "ALTERNATIVE") &&
            !strcmp(body->subpart[0].type, "TEXT")) {
            /* Look for a multipart/ or text/html subpart to display first,
               otherwise start with first subpart */
            for (i = body->numparts; --i;) {
                if (!strcmp(body->subpart[i].type, "MULTIPART") ||
                    !strcmp(body->subpart[i].subtype, "HTML")) break;
            }
        }

        /* Display all/remaining subparts */
        for (; i < body->numparts; i++) {
            snprintf(nextsection, sizeof(nextsection), "%s%s%d",
                     cursection, *cursection ? "." : "", i+1);
            display_part(txn, &body->subpart[i],
                         record, nextsection, msg_buf, level);
        }
    }
    else if (body->subpart) {
        /* message/rfc822 */
        struct body *subpart = body->subpart;
        struct address *addr;
        char *sep;

        /* Display enclosed message header as a shaded table */
        buf_printf_markup(buf, level++,
                          "<table width=\"100%%\" bgcolor=\"#CCCCCC\">");
        /* Subject header field */
        if (subpart->subject) {
            char *subj;

            subj = charset_parse_mimeheader(subpart->subject, charset_flags);
            buf_printf_markup(buf, level++, "<tr>");
            buf_printf_markup(buf, level,
                              "<td align=right valign=top><b>Subject: </b></td>");
            buf_printf_markup(buf, level, "<td>%s</td>", subj);
            buf_printf_markup(buf, --level, "</tr>");
            free(subj);
        }
        /* From header field */
        if (subpart->from && *subpart->from->mailbox) {
            buf_printf_markup(buf, level++, "<tr>");
            buf_printf_markup(buf, level,
                              "<td align=right><b>From: </b></td>");
            buf_printf_markup(buf, level++, "<td>");
            display_address(buf, subpart->from, "", level);
            buf_printf_markup(buf, --level, "</td>");
            buf_printf_markup(buf, --level, "</tr>");
        }
        /* Sender header field (if different than From */
        if (subpart->sender && *subpart->sender->mailbox &&
            (!subpart->from ||
             strcmp(subpart->sender->mailbox, subpart->from->mailbox) ||
             strcmp(subpart->sender->domain, subpart->from->domain))) {
            buf_printf_markup(buf, level++, "<tr>");
            buf_printf_markup(buf, level,
                              "<td align=right><b>Sender: </b></td>");
            buf_printf_markup(buf, level++, "<td>");
            display_address(buf, subpart->sender, "", level);
            buf_printf_markup(buf, --level, "</td>");
            buf_printf_markup(buf, --level, "</tr>");
        }
        /* Reply-To header field (if different than From */
        if (subpart->reply_to && *subpart->reply_to->mailbox &&
            (!subpart->from ||
             strcmp(subpart->reply_to->mailbox, subpart->from->mailbox) ||
             strcmp(subpart->reply_to->domain, subpart->from->domain))) {
            buf_printf_markup(buf, level++, "<tr>");
            buf_printf_markup(buf, level,
                              "<td align=right><b>Reply-To: </b></td>");
            buf_printf_markup(buf, level++, "<td>");
            display_address(buf, subpart->reply_to, "", level);
            buf_printf_markup(buf, --level, "</td>");
            buf_printf_markup(buf, --level, "</tr>");
        }
        /* Date header field */
        buf_printf_markup(buf, level++, "<tr>");
        buf_printf_markup(buf, level,
                          "<td align=right><b>Date: </b></td>");
        buf_printf_markup(buf, level,
                          "<td width=\"100%%\">%s</td>", subpart->date);
        buf_printf_markup(buf, --level, "</tr>");
        /* To header field (possibly multiple addresses) */
        if (subpart->to) {
            buf_printf_markup(buf, level++, "<tr>");
            buf_printf_markup(buf, level,
                              "<td align=right valign=top><b>To: </b></td>");
            buf_printf_markup(buf, level++, "<td>");
            for (sep = "", addr = subpart->to; addr; addr = addr->next) {
                display_address(buf, addr, sep, level);
                sep = ", ";
            }
            buf_printf_markup(buf, --level, "</td>");
            buf_printf_markup(buf, --level, "</tr>");
        }
        /* Cc header field (possibly multiple addresses) */
        if (subpart->cc) {
            buf_printf_markup(buf, level++, "<tr>");
            buf_printf_markup(buf, level,
                              "<td align=right valign=top><b>Cc: </b></td>");
            buf_printf_markup(buf, level++, "<td>");
            for (sep = "", addr = subpart->cc; addr; addr = addr->next) {
                display_address(buf, addr, sep, level);
                sep = ", ";
            }
            buf_printf_markup(buf, --level, "</td>");
            buf_printf_markup(buf, --level, "</tr>");
        }
        buf_printf_markup(buf, --level, "</table>");
//      buf_printf_markup(buf, level, "<br>");

        /* Display subpart */
        snprintf(nextsection, sizeof(nextsection), "%s%s", cursection,
                 subpart->numparts ? "" : (*cursection ? ".1" : "1"));
        display_part(txn, subpart, record, nextsection, msg_buf, level);
    }
    else {
        /* Leaf part - display something */

        if (!strcmp(body->type, "TEXT") &&
            (!body->disposition || !strcmp(body->disposition, "INLINE"))) {
            /* Display non-attachment text part */
            int ishtml = !strcmp(body->subtype, "HTML");
            charset_t charset = charset_lookupname(body->charset_id);
            int encoding = body->charset_enc;

            if (charset == CHARSET_UNKNOWN_CHARSET) {
                /* unknown, try ASCII */
                charset = charset_lookupname("us-ascii");
            }
            body->decoded_body =
                charset_to_utf8(buf_base(msg_buf) + body->content_offset,
                                body->content_size, charset, encoding);
            charset_free(&charset);
            if (!ishtml) buf_printf_markup(buf, level, "<pre>");
            write_body(0, txn, buf_cstring(buf), buf_len(buf));
            buf_reset(buf);

            write_body(0, txn, body->decoded_body, strlen(body->decoded_body));
            if (!ishtml) buf_printf_markup(buf, level, "</pre>");
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

            buf_printf_markup(buf, level++, "<div align=center>");

            /* Create link */
            buf_printf_markup(buf, level++,
                              "<a href=\"%s?section=%s\" type=\"%s/%s\">",
                              txn->req_tgt.path, cursection,
                              body->type, body->subtype);

            if (config_httpprettytelemetry)
                buf_printf(buf, "%*s", level * MARKUP_INDENT, "");

            /* Add image */
            if (is_image) {
                buf_printf(buf, "<img src=\"%s?section=%s\" alt=\"",
                           txn->req_tgt.path, cursection);
            }

            /* Create text for link or alternative text for image */
            if (param) buf_printf(buf, "%s", param->value);
            else {
                buf_printf(buf, "[%s/%s %u bytes]",
                           body->type, body->subtype, body->content_size);
            }

            if (is_image) buf_printf(buf, "\">");

            if (config_httpprettytelemetry) buf_appendcstr(buf, "\n");

            buf_printf_markup(buf, --level, "</a>");
            buf_printf_markup(buf, --level, "</div>");
        }

        buf_printf_markup(buf, level, "<hr>");
    }
}


/* Return entire message formatted as text/html */
static void display_message(struct transaction_t *txn,
                            const char *mboxname, const struct index_record *record,
                            struct body *body, const struct buf *msg_buf)
{
    struct body toplevel;
    struct buf *buf = &txn->resp_body.payload;
    unsigned level = 0;

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;
    txn->resp_body.type = "text/html; charset=utf-8";

    /* Short-circuit for HEAD request */
    if (txn->meth == METH_HEAD) {
        response_header(HTTP_OK, txn);
        return;
    }

    /* Start HTML */
    buf_reset(buf);
    buf_printf_markup(buf, level, HTML_DOCTYPE);
    buf_printf_markup(buf, level++, "<html>");
    buf_printf_markup(buf, level++, "<head>");
    buf_printf_markup(buf, level, "<title>%s:%u</title>",
                      mboxname, record->uid);
    buf_printf_markup(buf, --level, "</head>");
    buf_printf_markup(buf, level++, "<body>");

    /* Create link to message source */
    buf_printf_markup(buf, level++, "<div align=center>");
    buf_printf_markup(buf, level,
                      "<a href=\"%s?section=0\" type=\"plain/text\">"
                      "[View message source]</a>",
                      txn->req_tgt.path);
    buf_printf_markup(buf, --level, "</div>");
    buf_printf_markup(buf, level, "<hr>");

    write_body(HTTP_OK, txn, buf_cstring(buf), buf_len(buf));
    buf_reset(buf);

    /* Encapsulate our body in a message/rfc822 to display toplevel hdrs */
    memset(&toplevel, 0, sizeof(struct body));
    toplevel.type = "MESSAGE";
    toplevel.subtype = "RFC822";
    toplevel.subpart = body;

    display_part(txn, &toplevel, record, "", msg_buf, level);

    /* End of HTML */
    buf_printf_markup(buf, --level, "</body>");
    buf_printf_markup(buf, --level, "</html>");

    write_body(0, txn, buf_cstring(buf), buf_len(buf));

    /* End of output */
    write_body(0, txn, NULL, 0);
}


/* Fetch, decode, and return the specified MIME message part */
static struct body *body_fetch_section(struct body *body, const char *section)
{
    const char *p = section;

    while (*p) {
        int32_t skip = 0;
        int r = parseint32(p, &p, &skip);

        if (r || !skip) return NULL;

        if (body->subpart && !body->numparts) {
            /* step inside message/rfc822 */
            body = body->subpart;
        }

        if ((skip > 1) && (skip > body->numparts)) return NULL;

        if (body->numparts) {
            /* step inside multipart */
            body = &body->subpart[--skip];
        }

        if (*p == '.') {
            if (!body->subpart) return NULL;
            p++;
        }
    }

    return (*p ? NULL : body);
}
