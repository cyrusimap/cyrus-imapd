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
#include "jscalendar.h"
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

static int convert_to_jscal(struct transaction_t *txn)
{
    icalcomponent *ical = NULL;
    json_t *jsgroup = NULL;
    char *resp_payload = NULL;
    jscalendar_cfg_t jscal_cfg = {
        .emailalert_default_uri = httpd_userid,
        .use_icalendar_convprops = true,
    };
    int ret = 0;

    /* Parse the request body */
    ical = icalparser_parse_string(buf_cstring(&txn->req_body.payload));
    if (!ical) {
        txn->error.desc = "Could not parse iCalendar data";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Convert to JSCalendar */
    jsgroup = jscalendar_from_ical(&jscal_cfg, ical);
    if (!jsgroup) {
        txn->error.desc = "Failed to convert to JSCalendar";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Write the response */
    resp_payload = json_dumps(
        jsgroup,
        JSON_PRESERVE_ORDER |
            (config_httpprettytelemetry ? JSON_INDENT(2) : JSON_COMPACT));
    if (!resp_payload) {
        txn->error.desc = "Error dumping JSON object";
        ret = HTTP_SERVER_ERROR;
        goto done;
    }
    txn->resp_body.type = "application/jscalendar+json;type=group";
    write_body(HTTP_OK, txn, resp_payload, strlen(resp_payload));

done:
    if (ical)
        icalcomponent_free(ical);
    json_decref(jsgroup);
    free(resp_payload);
    return ret;
}

static int convert_to_ical(struct transaction_t *txn)
{
    json_t *jobj = NULL;
    icalcomponent *ical = NULL;
    jscalendar_cfg_t jscal_cfg = {
        .emailalert_default_uri = httpd_userid,
        .use_icalendar_convprops = true,
    };
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    int ret = 0;

    /* Parse the request body */
    json_error_t jerr;
    jobj = json_loads(buf_cstring(&txn->req_body.payload), 0, &jerr);
    if (!jobj) {
        txn->error.desc = "Could not parse JSON data";
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Convert to iCalendar */
    ical = jscalendar_to_ical(&jscal_cfg, jobj, &parser);
    if (ical) {
        const char *resp_payload = icalcomponent_as_ical_string(ical);
        write_body(HTTP_OK, txn, resp_payload, strlen(resp_payload));
    }
    else if (json_array_size(parser.invalid)) {
        json_t *jerr = json_pack("{s:O}", "invalidProperties", parser.invalid);
        char *err = json_dumps(jerr, JSON_INDENT(2) | JSON_ENCODE_ANY);
        write_body(HTTP_BAD_REQUEST, txn, err, strlen(err));
        json_decref(jerr);
        goto done;
    }
    else {
        txn->error.desc = "Failed to convert to iCalendar";
        ret = HTTP_SERVER_ERROR;
    }

done:
    if (ical) icalcomponent_free(ical);
    json_decref(jobj);
    return ret;
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

    /* Read body */
    ret = http_read_req_body(txn);
    if (ret) {
        txn->flags.conn = CONN_CLOSE;
        return ret;
    }

    /* Parse the request body */
    const char **hdr = spool_getheader(txn->req_hdrs, "Content-Type");
    if (hdr && is_mediatype("text/calendar", hdr[0])) {
        return convert_to_jscal(txn);
    }
    else if (hdr && is_mediatype("application/jscalendar+json", hdr[0])) {
        return convert_to_ical(txn);
    }
    else {
        txn->error.desc = "This method requires a "
                          "text/calendar or application/jscalendar+json body";
        return HTTP_BAD_MEDIATYPE;
    }
}
