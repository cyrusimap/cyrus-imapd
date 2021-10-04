/* http_cgi.c -- Routines for handling Common Gateway Interface scripts in httpd
 *
 * Copyright (c) 1994-2019 Carnegie Mellon University.  All rights reserved.
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

#include "command.h"
#include "global.h"
#include "httpd.h"
#include "http_proxy.h"
#include "proxy.h"
#include "tok.h"
#include "util.h"
#include "version.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static void cgi_init(struct buf *serverinfo);
static int meth_get(struct transaction_t *txn, void *params);
static int meth_post(struct transaction_t *txn, void *params);


/* Namespace for CGI */
struct namespace_t namespace_cgi = {
    URL_NS_CGI, 0, "cgi", "/cgi-bin", NULL,
    http_allow_noauth, /*authschemes*/0,
    /*mbtype*/0,
    ALLOW_READ | ALLOW_POST,
    cgi_init, NULL, NULL, NULL, NULL, NULL,
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
        { &meth_options,        NULL },                 /* OPTIONS      */
        { NULL,                 NULL },                 /* PATCH        */
        { &meth_post,           NULL },                 /* POST         */
        { NULL,                 NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { &meth_trace,          NULL },                 /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { NULL,                 NULL }                  /* UNLOCK       */
    }
};


static void cgi_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_cgi.enabled = config_httpmodules & IMAP_ENUM_HTTPMODULES_CGI;
}

/* Add request headers to environment for script */
static void req_hdr_to_env(const char *name, const char *contents,
                           const char *raw __attribute__((unused)), void *rock)
{
    struct buf *environ = (struct buf *) rock;
    const char **hdr, *skip[] =
        { "authorization", "cookie", "expect", "http2-settings",
          "proxy-authorization", "transfer-encoding", "upgrade", NULL };

    /* Ignore private headers in our cache */
    if (name[0] == ':') return;

    for (hdr = skip; *hdr && strcasecmp(name, *hdr); hdr++);

    if (!*hdr) {
        static struct buf env_name = BUF_INITIALIZER;
        const char *env_str = buf_cstring(environ);
        const char *exists;

        buf_reset(&env_name);
        buf_printf(&env_name, "\tHTTP_%s=", name);
        buf_ucase(&env_name);
        buf_replace_all(&env_name, "-", "_");

        /* See if this name already exists */
        exists = strstr(env_str, buf_cstring(&env_name));
        if (exists) {
            /* Append value to existing value(s) */
            const char *next = strchr(exists + 1, '\t');
            unsigned offset = next ? next - env_str : (unsigned) strlen(env_str);

            buf_insertcstr(environ, offset, ", ");
            buf_insertcstr(environ, offset + 2, contents);
        }
        else {
            /* Add name and value */
            buf_appendcstr(environ, buf_cstring(&env_name));
            buf_appendcstr(environ, contents);
        }
    }
}

/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn,
                    void *params __attribute__((unused)))
{
    int ret = 0;
    const char *prefix, *urls, *errstr = NULL;
    const char **hdr, *extra, *port, *query;
    char *script, *cwd;
    struct stat sbuf;
    strarray_t *env = NULL;
    struct command *cmd = NULL;
    hdrcache_t resp_hdrs = NULL;
    struct body_t resp_body;
    long code = 0;
    extern char **environ;
    
    memset(&resp_body, 0, sizeof(struct body_t));

    prefix = config_getstring(IMAPOPT_HTTPDOCROOT);
    if (!prefix) return HTTP_NOT_FOUND;

    if ((urls = config_getstring(IMAPOPT_HTTPALLOWEDURLS))) {
        tok_t tok = TOK_INITIALIZER(urls, " \t", TOK_TRIMLEFT|TOK_TRIMRIGHT);
        const char *token;

        while ((token = tok_next(&tok)) && strcmp(token, txn->req_uri->path));
        tok_fini(&tok);

        if (!token) return HTTP_NOT_FOUND;
    }

    /* Construct path to script */
    extra = strchr(txn->req_uri->path + strlen(namespace_cgi.prefix) + 1, '/');
    buf_setcstr(&txn->buf, prefix);
    if (extra)
        buf_appendmap(&txn->buf, txn->req_uri->path, extra - txn->req_uri->path);
    else buf_appendcstr(&txn->buf, txn->req_uri->path);
    script = buf_release(&txn->buf);
    cwd = strconcat(prefix, namespace_cgi.prefix, NULL);

    /* See if script exists */
    if (stat(script, &sbuf) || !S_ISREG(sbuf.st_mode)) {
        ret = HTTP_NOT_FOUND;
        goto done;
    }

    /* See if script is executable */
    if (access(script, X_OK)) {
        syslog(LOG_ERR, "CGI script %s is not executable",
               txn->req_uri->path);
        txn->error.desc = "CGI script is not executable";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Construct environment for script */
    buf_setcstr(&txn->buf, "GATEWAY_INTERFACE=CGI/1.1");
    if ((hdr = spool_getheader(txn->req_hdrs, "Content-Length"))) {
        buf_printf(&txn->buf, "\tCONTENT_LENGTH=%s", hdr[0]);
    }
    if ((hdr = spool_getheader(txn->req_hdrs, "Content-Type"))) {
        buf_printf(&txn->buf, "\tCONTENT_TYPE=%s", hdr[0]);
    }
    buf_printf(&txn->buf, "\tPATH_INFO=%s", extra ? extra : "");
    if (extra) {
        buf_printf(&txn->buf, "\tPATH_TRANSLATED=%s%s", prefix, extra);
    }
    buf_printf(&txn->buf, "\tQUERY_STRING=%s",
               (query = URI_QUERY(txn->req_uri)) ? query : "");
    buf_printf(&txn->buf, "\tREMOTE_ADDR=%.*s",
               (int) (httpd_remoteip ? strcspn(httpd_remoteip, ";") : 0),
               httpd_remoteip);
    buf_printf(&txn->buf, "\tREMOTE_HOST=%.*s",
               (int) (txn->conn->clienthost ?
                      strcspn(txn->conn->clienthost, " ") : 0),
               txn->conn->clienthost);
    if (httpd_userid) {
        buf_printf(&txn->buf, "\tREMOTE_USER=%s", httpd_userid);

        if (txn->auth_chal.scheme) {
            buf_printf(&txn->buf, "\tAUTH_TYPE=%s", txn->auth_chal.scheme->name);
        }
    }
    buf_printf(&txn->buf, "\tREQUEST_METHOD=%s", http_methods[txn->meth].name);
    buf_printf(&txn->buf, "\tSCRIPT_NAME=%s", script + strlen(prefix));
    buf_printf(&txn->buf, "\tSERVER_NAME=%s", config_servername);
    buf_printf(&txn->buf, "\tSERVER_PORT=%s",
               (port = strchr(httpd_localip ? httpd_localip : "", ';')) ?
               port + 1 : (https ? "443" : "80"));
    buf_printf(&txn->buf, "\tSERVER_PROTOCOL=%s", HTTP_VERSION);
    buf_printf(&txn->buf, "\tSERVER_SOFTWARE=%s", buf_cstring(&serverinfo));

    /* Add some HTTP headers from request */
    spool_enum_hdrcache(txn->req_hdrs, &req_hdr_to_env, &txn->buf);

    env = strarray_splitm(buf_release(&txn->buf), "\t", 0);
    strarray_append(env, NULL);
    environ = env->data;

    /* Run script */
    if (command_popen(&cmd, "rw", cwd, script, NULL)) {
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Send request body */
    prot_putbuf(cmd->stdin_prot, &txn->req_body.payload);
    prot_flush(cmd->stdin_prot);

    /* Read response headers */
    ret = http_read_headers(cmd->stdout_prot,
                            0 /* read_sep */, &resp_hdrs, &errstr);
    if (ret) {
        syslog(LOG_ERR, "Failed to read headers from CGI script %s",
               txn->req_uri->path);
        txn->error.desc = "Failed to read headers from CGI script";
        ret = HTTP_SERVER_ERROR;
    }
    else {
        /* Read [CR]LF separating headers and body */
        int c = prot_getc(cmd->stdout_prot);

        if (c == '\r') c = prot_getc(cmd->stdout_prot);
        if (c != '\n') {
            syslog(LOG_ERR, "Failed to read newline from CGI script %s",
                   txn->req_uri->path);
            txn->error.desc = "Failed to read newline from CGI script";
            ret = HTTP_SERVER_ERROR;
        }

        if (!ret) {
            /* Check for and read response body */
            hdr = spool_getheader(resp_hdrs, "Content-Type");
            if (hdr) {
                txn->resp_body.type = hdr[0];

                resp_body.flags = BODY_RESPONSE | BODY_CLOSE;
                ret = http_read_body(cmd->stdout_prot,
                                     resp_hdrs, &resp_body, &errstr);
                if (ret) {
                    syslog(LOG_ERR, "Failed to body from CGI script %s",
                           txn->req_uri->path);
                    txn->error.desc = "Failed to read body from CGI script";
                    ret = HTTP_SERVER_ERROR;
                }
            }
        }
    }

    if (command_pclose(&cmd)) ret = HTTP_SERVER_ERROR;

    if (ret) goto done;

    /* Check for a status code */
    hdr = spool_getheader(resp_hdrs, "Status");
    if (hdr) code = http_status_to_code(atoi(hdr[0]));

    /* Check the type of the CGI response */
    hdr = spool_getheader(resp_hdrs, "Location");
    if (hdr) {
        /* Redirect */
        if (hdr[0][0] == '/') {
            /* Local Redirect */
            txn->flags.redirect = 1;

            /* Reset the URI part of our current transaction */
            xmlFreeURI(txn->req_uri);
            free_hash_table(&txn->req_qparams, (void (*)(void *)) &strarray_free);

            /* Examine new request */
            ret = examine_request(txn, hdr[0]);

            /* Reprocess the requested method on new URI */
            if (!ret) ret = process_request(txn);

            goto done;
        }
        else {
            /* Client Redirect */
            if (!code) code = HTTP_FOUND;
            txn->location = hdr[0];
        }
    }
    else {
        /* Document */
        if (!code) code = HTTP_OK;
    }

    /* Output response */
    txn->resp_body.extra_hdrs = resp_hdrs;
    write_body(code, txn,
               buf_base(&resp_body.payload), buf_len(&resp_body.payload));

  done:
    spool_free_hdrcache(resp_hdrs);
    buf_free(&resp_body.payload);
    strarray_free(env);
    free(script);
    free(cwd);

    return ret;
}

/* Perform a POST request */
static int meth_post(struct transaction_t *txn, void *params)
{
    int ret;

    /* Read request body */
    txn->req_body.flags |= BODY_DECODE;
    ret = http_read_req_body(txn);

    if (ret) {
        txn->flags.conn = CONN_CLOSE;
        return ret;
    }

    return meth_get(txn, params);
}
