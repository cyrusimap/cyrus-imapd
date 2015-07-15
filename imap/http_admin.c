/* http_admin.c -- Routines for handling Cyrus admin/info requests in httpd
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

/*
 * TODO:
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "global.h"
#include "httpd.h"
#include "proc.h"
#include "util.h"
#include "version.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

static time_t compile_time;
static void admin_init(struct buf *serverinfo);
static int meth_get(struct transaction_t *txn, void *params);
static int action_proc(struct transaction_t *txn);


/* Namespace for admin service */
struct namespace_t namespace_admin = {
    URL_NS_ADMIN, 1, "/admin", NULL, 1 /* auth */,
    /*mbtype*/0,
    ALLOW_READ,
    admin_init, NULL, NULL, NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
        { &meth_get,            NULL },                 /* GET          */
        { &meth_get,            NULL },                 /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { &meth_options,        NULL },                 /* OPTIONS      */
        { NULL,                 NULL },                 /* POST */
        { NULL,                 NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { &meth_trace,          NULL },                 /* TRACE        */
        { NULL,                 NULL }                  /* UNLOCK       */
    }
};


static void admin_init(struct buf *serverinfo __attribute__((unused)))
{
//    namespace_admin.enabled =
//        config_httpmodules & IMAP_ENUM_HTTPMODULES_ADMIN;

    if (!namespace_admin.enabled) return;

    compile_time = calc_compile_time(__TIME__, __DATE__);
}


/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn,
                    void *params __attribute__((unused)))
{
    struct request_target_t *tgt = &txn->req_tgt;
    int (*action)(struct transaction_t *txn) = NULL;
    char *p;

    if (!httpd_userid) return HTTP_UNAUTHORIZED;

    /* Admins only */
    if (!httpd_userisadmin) return HTTP_FORBIDDEN;

    /* Make a working copy of target path */
    strlcpy(tgt->path, txn->req_uri->path, sizeof(tgt->path));
    p = tgt->path;

    /* Skip namespace */
    p += strlen(namespace_admin.prefix);
    if (*p == '/') *p++ = '\0';

    /* Check for path after prefix */
    if (*p) {
        /* Get collection (action) */
        tgt->collection = p;
        p += strcspn(p, "/");
        if (*p == '/') *p++ = '\0';

        if (!strcmp(tgt->collection, "proc")) {
            if (!*p) action = &action_proc;
        }
    }

    if (!action) return HTTP_NOT_FOUND;

    return action(txn);
}


/* Perform a proc action */
static int print_procinfo(pid_t pid,
                          const char *servicename, const char *host,
                          const char *user, const char *mailbox,
                          const char *cmdname,
                          void *rock)
{
    struct buf *body = (struct buf *) rock;

    buf_printf_markup(body, 3, "<tr><td>%d<td>%s<td>%s<td>%s<td>%s<td>%s",
                      (int) pid, servicename, host, user ? user : "",
                      mailbox ? mailbox : "", cmdname ? cmdname : "");
    return 0;
}

static int action_proc(struct transaction_t *txn)
{
    unsigned level = 0;
    struct buf *body = &txn->resp_body.payload;

    /* Setup for chunked response */
    txn->flags.te |= TE_CHUNKED;
    txn->resp_body.type = "text/html; charset=utf-8";

    /* Short-circuit for HEAD request */
    if (txn->meth == METH_HEAD) {
        response_header(HTTP_OK, txn);
        goto done;
    }

    /* Send HTML header */
    buf_reset(body);
    buf_printf_markup(body, level, HTML_DOCTYPE);
    buf_printf_markup(body, level++, "<html>");
    buf_printf_markup(body, level++, "<head>");
    buf_printf_markup(body, level, "<meta http-equiv=\"%s\" content=\"%s\">",
                      "Refresh", "1");
    buf_printf_markup(body, level, "<title>%s</title>",
                      "Currently Running Cyrus Services");
    buf_printf_markup(body, --level, "</head>");
    buf_printf_markup(body, level++, "<body>");
    buf_printf_markup(body, level, "<h2>%s</h2>",
                      "Currently Running Cyrus Services");
    buf_printf_markup(body, level++, "<table border cellpadding=5>");
    buf_printf_markup(body, level++, "<tr><th>PID<th>Service<th>"
                      "Client<th>User<th>Resource<th>Command");
    write_body(HTTP_OK, txn, buf_cstring(body), buf_len(body));
    buf_reset(body);

    /* Add running services */
    proc_foreach(print_procinfo, body);

    /* Finish list */
    buf_printf_markup(body, --level, "</table>");

    /* Finish HTML */
    buf_printf_markup(body, --level, "</body>");
    buf_printf_markup(body, --level, "</html>");
    write_body(0, txn, buf_cstring(body), buf_len(body));

    /* End of output */
    write_body(0, txn, NULL, 0);

 done:
    return 0;
}
