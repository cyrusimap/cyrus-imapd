/* http_prometheus.c - Routines for handling Prometheus requests in httpd */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "imap/httpd.h"
#include "imap/http_err.h"
#include "imap/prometheus.h"

static int prom_need_auth(struct transaction_t *txn);
static void prom_init(struct buf *);
static int prom_auth(const char *);
static void prom_reset(void);
static void prom_shutdown(void);
static int prom_get(struct transaction_t *txn, void *params);

// clang-format off
struct namespace_t namespace_prometheus = {
    URL_NS_PROMETHEUS,
    /*enabled*/ 0,
    "prometheus",
    "/metrics",
    /* XXX .well-known url*/ NULL,
    prom_need_auth,
    /* XXX auth schemes*/ 0,
    /*mboxtype*/ 0,
    (ALLOW_READ),
    &prom_init,
    &prom_auth,
    &prom_reset,
    &prom_shutdown,
    /* XXX premethod */ NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { NULL,                 NULL },                 /* CONNECT      */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
        { &prom_get,            NULL },                 /* GET          */
        { NULL,                 NULL },                 /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { &meth_options,        NULL },                 /* OPTIONS      */
        { NULL,                 NULL },                 /* PATCH        */
        { NULL,                 NULL },                 /* POST         */
        { NULL,                 NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { NULL,                 NULL },                 /* SEARCH       */
        { &meth_trace,          NULL },                 /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { NULL,                 NULL },                 /* UNLOCK       */
    },
};
// clang-format on

static int prom_need_auth(struct transaction_t *txn __attribute__((unused)))
{
    const char *need_auth = config_getstring(IMAPOPT_PROMETHEUS_NEED_AUTH);

    if (!strcmp(need_auth, "none"))
        return 0;

    return HTTP_UNAUTHORIZED;
}

static void prom_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_prometheus.enabled =
        (config_httpmodules & IMAP_ENUM_HTTPMODULES_PROMETHEUS)
        && config_getswitch(IMAPOPT_PROMETHEUS_ENABLED);
}

static int prom_auth(const char *userid __attribute__((unused)))
{
    /* XXX */
    return 0;
}

static void prom_reset(void)
{
    /* XXX */
}

static void prom_shutdown(void)
{
    /* XXX */
}

static int prom_get(struct transaction_t *txn,
                    void *params __attribute__((unused)))
{
    struct buf buf = BUF_INITIALIZER;
    const char *mimetype = NULL;
    int r;

    if (strcmp(txn->req_uri->path, "/metrics"))
        return HTTP_NOT_FOUND;

    const char *need_auth = config_getstring(IMAPOPT_PROMETHEUS_NEED_AUTH);
    if (!strcmp(need_auth, "admin") && !httpd_userisadmin)
        return HTTP_UNAUTHORIZED;
    if (!strcmp(need_auth, "user") && !httpd_userid)
        return HTTP_UNAUTHORIZED;

    r = prometheus_text_report(&buf, &mimetype);
    if (r) {
        txn->error.desc = error_message(r);
        return HTTP_SERVER_ERROR;
    }

    txn->resp_body.type = mimetype;
    txn->resp_body.len = buf_len(&buf);

    write_body(HTTP_OK, txn, buf_cstring(&buf), buf_len(&buf));

    buf_free(&buf);
    return 0;
}
