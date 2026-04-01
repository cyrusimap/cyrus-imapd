/* http_convert.c -- Routines for converting media types over HTTP
 *
 * Copyright (c) 2025 Fastmail Pty Ltd
 *
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>

#include "acl.h"
#include "annotate.h"
#include "charset.h"
#include "global.h"
#include "httpd.h"
#include "mailbox.h"
#include "map.h"
#include "mboxlist.h"
#include "message.h"
#include "parseaddr.h"
#include "proxy.h"
#include "seen.h"
#include "times.h"
#include "tok.h"
#include "util.h"
#include "version.h"
#include "wildmat.h"
#include "xmalloc.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static void convert_init(struct buf *serverinfo);
static int meth_post(struct transaction_t *txn, void *params);

struct namespace_t namespace_convert = {
    URL_NS_DEFAULT,
    0,
    "convert",
    "/convert",
    NULL,
    http_allow_noauth_get,
 /*authschemes*/ 0,
 /*mbtype*/ 0,
    ALLOW_POST,
    convert_init,
    NULL,
    NULL,
    NULL,
    NULL,
    {
      {NULL, NULL}, /* ACL          */
        {NULL, NULL}, /* BIND         */
        {NULL, NULL}, /* CONNECT      */
        {NULL, NULL}, /* COPY         */
        {NULL, NULL}, /* DELETE       */
        {NULL, NULL}, /* GET          */
        {NULL, NULL}, /* HEAD         */
        {NULL, NULL}, /* LOCK         */
        {NULL, NULL}, /* MKCALENDAR   */
        {NULL, NULL}, /* MKCOL        */
        {NULL, NULL}, /* MOVE         */
        {NULL, NULL}, /* OPTIONS      */
        {NULL, NULL}, /* PATCH        */
        {&meth_post, NULL}, /* POST   */
        {NULL, NULL}, /* PROPFIND     */
        {NULL, NULL}, /* PROPPATCH    */
        {NULL, NULL}, /* PUT          */
        {NULL, NULL}, /* REPORT       */
        {NULL, NULL}, /* SEARCH       */
        {NULL, NULL}, /* TRACE        */
        {NULL, NULL}, /* UNBIND       */
        {NULL, NULL}        /* UNLOCK       */
    }
};

static void convert_init(struct buf *serverinfo __attribute__((unused)))
{
    namespace_convert.enabled =
        config_httpmodules & IMAP_ENUM_HTTPMODULES_CONVERT;
}

static int convert_parse_path(const char *path, struct request_target_t *tgt,
                              const char **resultstr)
{
    size_t len;
    char *p;

    if (*tgt->path)
        return 0; /* Already parsed */

    /* Make a working copy of target path */
    strlcpy(tgt->path, path, sizeof(tgt->path));
    p = tgt->path;

    /* Sanity check namespace */
    len = strlen(namespace_convert.prefix);
    if (strlen(p) < len || strncmp(namespace_convert.prefix, p, len) ||
        (path[len] && path[len] != '/')) {
        *resultstr = "Namespace mismatch request target path";
        return HTTP_FORBIDDEN;
    }

    /* Always allow read, even if no content */
    tgt->allow = ALLOW_READ;

    /* Skip namespace */
    p += len;

    /* Check for path after prefix */
    if (*p == '/')
        p++;
    if (*p)
        return HTTP_NOT_FOUND;

    tgt->allow |= ALLOW_POST;

    return 0;
}

/* Perform a POST request */
static int meth_post(struct transaction_t *txn,
                     void *params __attribute__((unused)))
{
    int ret =
        convert_parse_path(txn->req_uri->path, &txn->req_tgt, &txn->error.desc);
    if (ret)
        return ret;

    if (!(txn->req_tgt.allow & ALLOW_POST))
        return HTTP_NOT_ALLOWED;

    txn->error.desc = "This media type is not supported";
    return HTTP_BAD_MEDIATYPE;
}
