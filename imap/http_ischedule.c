/* http_ischedule.c -- Routines for handling iSchedule in httpd
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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
#include <errno.h>
#include <sysexits.h>
#include <syslog.h>

#include <libical/ical.h>

#include "global.h"
#include "httpd.h"
#include "http_caldav_sched.h"
#include "http_dav.h"
#include "http_proxy.h"
#include "jcal.h"
#include "map.h"
#include "proxy.h"
#include "tok.h"
#include "util.h"
#include "xmalloc.h"
#include "xcal.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

#include <sasl/saslutil.h>

#define ISCHED_WELLKNOWN_URI "/.well-known/ischedule"

#ifdef WITH_DKIM
#include <dkim.h>

//#define TEST

#define BASE64_LEN(inlen) ((((inlen) + 2) / 3) * 4)

static DKIM_LIB *dkim_lib = NULL;
static struct buf privkey = BUF_INITIALIZER;
static struct buf tmpbuf = BUF_INITIALIZER;
static struct buf b64req = BUF_INITIALIZER;
#endif /* WITH_DKIM */

static void isched_init(struct buf *serverinfo);
static void isched_shutdown(void);

static int meth_get_isched(struct transaction_t *txn, void *params);
static int meth_options_isched(struct transaction_t *txn, void *params);
static int meth_post_isched(struct transaction_t *txn, void *params);
static int dkim_auth(struct transaction_t *txn);
static int meth_get_domainkey(struct transaction_t *txn, void *params);
static time_t compile_time;

static struct mime_type_t isched_mime_types[] = {
    /* First item MUST be the default type and storage format */
    { "text/calendar; charset=utf-8", "2.0", "ics",
      (struct buf* (*)(void *)) &my_icalcomponent_as_ical_string,
      (void * (*)(const struct buf*)) &ical_string_as_icalcomponent,
      (void (*)(void *)) &icalcomponent_free, NULL, NULL
    },
    { "application/calendar+xml; charset=utf-8", NULL, "xcs",
      (struct buf* (*)(void *)) &icalcomponent_as_xcal_string,
      (void * (*)(const struct buf*)) &xcal_string_as_icalcomponent,
      NULL, NULL, NULL
    },
    { "application/calendar+json; charset=utf-8", NULL, "jcs",
      (struct buf* (*)(void *)) &icalcomponent_as_jcal_string,
      (void * (*)(const struct buf*)) &jcal_string_as_icalcomponent,
      NULL, NULL, NULL,
    },
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

struct namespace_t namespace_ischedule = {
    URL_NS_ISCHEDULE, 0, "ischedule", "/ischedule", ISCHED_WELLKNOWN_URI,
    http_allow_noauth, /*authschemes*/0,
    /*mbtype*/0,
    (ALLOW_READ | ALLOW_POST | ALLOW_ISCHEDULE),
    isched_init, NULL, NULL, isched_shutdown, NULL, NULL,
    {
        { NULL,                 NULL }, /* ACL          */
        { NULL,                 NULL }, /* BIND         */
        { NULL,                 NULL }, /* CONNECT      */
        { NULL,                 NULL }, /* COPY         */
        { NULL,                 NULL }, /* DELETE       */
        { &meth_get_isched,     NULL }, /* GET          */
        { &meth_get_isched,     NULL }, /* HEAD         */
        { NULL,                 NULL }, /* LOCK         */
        { NULL,                 NULL }, /* MKCALENDAR   */
        { NULL,                 NULL }, /* MKCOL        */
        { NULL,                 NULL }, /* MOVE         */
        { &meth_options_isched, NULL }, /* OPTIONS      */
        { NULL,                 NULL }, /* PATCH        */
        { &meth_post_isched,    NULL }, /* POST         */
        { NULL,                 NULL }, /* PROPFIND     */
        { NULL,                 NULL }, /* PROPPATCH    */
        { NULL,                 NULL }, /* PUT          */
        { NULL,                 NULL }, /* REPORT       */
        { &meth_trace,          NULL }, /* TRACE        */
        { NULL,                 NULL }, /* UNBIND       */
        { NULL,                 NULL }  /* UNLOCK       */
    }
};

struct namespace_t namespace_domainkey = {
    URL_NS_DOMAINKEY, 0, "domainkey", "/domainkeys", "/.well-known/domainkey",
    http_allow_noauth, /*authschemes*/0,
    /*mbtype*/0,
    ALLOW_READ,
    NULL, NULL, NULL, NULL, NULL, NULL,
    {
        { NULL,                 NULL }, /* ACL          */
        { NULL,                 NULL }, /* BIND         */
        { NULL,                 NULL }, /* CONNECT      */
        { NULL,                 NULL }, /* COPY         */
        { NULL,                 NULL }, /* DELETE       */
        { &meth_get_domainkey,  NULL }, /* GET          */
        { &meth_get_domainkey,  NULL }, /* HEAD         */
        { NULL,                 NULL }, /* LOCK         */
        { NULL,                 NULL }, /* MKCALENDAR   */
        { NULL,                 NULL }, /* MKCOL        */
        { NULL,                 NULL }, /* MOVE         */
        { &meth_options,        NULL }, /* OPTIONS      */
        { NULL,                 NULL }, /* POST         */
        { NULL,                 NULL }, /* PROPFIND     */
        { NULL,                 NULL }, /* PROPPATCH    */
        { NULL,                 NULL }, /* PUT          */
        { NULL,                 NULL }, /* REPORT       */
        { &meth_trace,          NULL }, /* TRACE        */
        { NULL,                 NULL }, /* UNBIND       */
        { NULL,                 NULL }  /* UNLOCK       */
    }
};


void isched_capa_hdr(struct transaction_t *txn, time_t *lastmod, struct stat *sb)
{
    struct stat sbuf;
    time_t mtime;

    stat(config_filename, &sbuf);
    mtime = MAX(compile_time, sbuf.st_mtime);
    txn->resp_body.iserial = mtime +
        (rscale_calendars ? rscale_calendars->num_elements : 0);
    if (lastmod) *lastmod = mtime;
    if (sb) *sb = sbuf;
}


/* iSchedule Receiver Capabilities */
static int meth_get_isched(struct transaction_t *txn,
                           void *params __attribute__((unused)))
{
    int precond;
    struct strlist *action;
    static struct message_guid prev_guid;
    struct message_guid guid;
    const char *etag;
    static time_t lastmod = 0;
    struct stat sbuf;
    static xmlChar *buf = NULL;
    static int bufsiz = 0;

    /* Initialize */
    if (!lastmod) message_guid_set_null(&prev_guid);

    /* Fill in iSchedule-Capabilities */
    isched_capa_hdr(txn, &lastmod, &sbuf);

    /* We don't handle GET on a anything other than ?action=capabilities */
    action = hash_lookup("action", &txn->req_qparams);
    if (!action || action->next || strcmp(action->s, "capabilities")) {
        txn->error.desc = "Invalid action";
        return HTTP_BAD_REQUEST;
    }

    /* Generate ETag based on compile date/time of this source file,
       the number of available RSCALEs and the config file size/mtime */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, TIME_T_FMT "-" SIZE_T_FMT "-" TIME_T_FMT "-" OFF_T_FMT, compile_time,
               rscale_calendars ? (size_t)rscale_calendars->num_elements : 0,
               sbuf.st_mtime, sbuf.st_size);

    message_guid_generate(&guid, buf_cstring(&txn->buf), buf_len(&txn->buf));
    etag = message_guid_encode(&guid);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, etag, lastmod);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
        /* Fill in Etag,  Last-Modified, and Expires */
        txn->resp_body.etag = etag;
        txn->resp_body.lastmod = lastmod;
        txn->resp_body.maxage = 86400;  /* 24 hrs */
        txn->flags.cc |= CC_MAXAGE;

        if (precond != HTTP_NOT_MODIFIED) break;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        return precond;
    }

    if (!message_guid_equal(&prev_guid, &guid)) {
        xmlNodePtr root, capa, node, comp, meth;
        xmlNsPtr ns[NUM_NAMESPACE];
        struct mime_type_t *mime;
        struct icaltimetype date;
        icaltimezone *utc = icaltimezone_get_utc_timezone();
        int i, n, maxlen;

        /* Start construction of our query-result */
        if (!(root = init_xml_response("query-result", NS_ISCHED, NULL, ns))) {
            txn->error.desc = "Unable to create XML response";
            return HTTP_SERVER_ERROR;
        }

        capa = xmlNewChild(root, NULL, BAD_CAST "capabilities", NULL);

        buf_reset(&txn->buf);
        buf_printf(&txn->buf, TIME_T_FMT, txn->resp_body.iserial);
        xmlNewChild(capa, NULL, BAD_CAST "serial-number",
                           BAD_CAST buf_cstring(&txn->buf));

        node = xmlNewChild(capa, NULL, BAD_CAST "versions", NULL);
        xmlNewChild(node, NULL, BAD_CAST "version", BAD_CAST "1.0");

        node = xmlNewChild(capa, NULL,
                           BAD_CAST "scheduling-messages", NULL);
        comp = xmlNewChild(node, NULL, BAD_CAST "component", NULL);
        xmlNewProp(comp, BAD_CAST "name", BAD_CAST "VEVENT");
        meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
        xmlNewProp(meth, BAD_CAST "name", BAD_CAST "REQUEST");
        meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
        xmlNewProp(meth, BAD_CAST "name", BAD_CAST "REPLY");
        meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
        xmlNewProp(meth, BAD_CAST "name", BAD_CAST "CANCEL");

        comp = xmlNewChild(node, NULL, BAD_CAST "component", NULL);
        xmlNewProp(comp, BAD_CAST "name", BAD_CAST "VTODO");
        meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
        xmlNewProp(meth, BAD_CAST "name", BAD_CAST "REQUEST");
        meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
        xmlNewProp(meth, BAD_CAST "name", BAD_CAST "REPLY");
        meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
        xmlNewProp(meth, BAD_CAST "name", BAD_CAST "CANCEL");

        comp = xmlNewChild(node, NULL, BAD_CAST "component", NULL);
        xmlNewProp(comp, BAD_CAST "name", BAD_CAST "VPOLL");
        meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
        xmlNewProp(meth, BAD_CAST "name", BAD_CAST "POLLSTATUS");
        meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
        xmlNewProp(meth, BAD_CAST "name", BAD_CAST "REQUEST");
        meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
        xmlNewProp(meth, BAD_CAST "name", BAD_CAST "REPLY");
        meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
        xmlNewProp(meth, BAD_CAST "name", BAD_CAST "CANCEL");

        comp = xmlNewChild(node, NULL, BAD_CAST "component", NULL);
        xmlNewProp(comp, BAD_CAST "name", BAD_CAST "VFREEBUSY");
        meth = xmlNewChild(comp, NULL, BAD_CAST "method", NULL);
        xmlNewProp(meth, BAD_CAST "name", BAD_CAST "REQUEST");

        node = xmlNewChild(capa, NULL,
                           BAD_CAST "calendar-data-types", NULL);
        for (mime = isched_mime_types; mime->content_type; mime++) {
            xmlNodePtr type = xmlNewChild(node, NULL,
                                          BAD_CAST "calendar-data-type", NULL);

            /* Trim any charset from content-type */
            buf_reset(&txn->buf);
            buf_printf(&txn->buf, "%.*s",
                       (int) strcspn(mime->content_type, ";"),
                       mime->content_type);

            xmlNewProp(type, BAD_CAST "content-type",
                       BAD_CAST buf_cstring(&txn->buf));

            if (mime->version)
                xmlNewProp(type, BAD_CAST "version", BAD_CAST mime->version);
        }

        node = xmlNewChild(capa, NULL, BAD_CAST "attachments", NULL);
        xmlNewChild(node, NULL, BAD_CAST "inline", NULL);

        node = xmlNewChild(capa, NULL, BAD_CAST "rscales", NULL);
        if (rscale_calendars) {
            for (i = 0, n = rscale_calendars->num_elements; i < n; i++) {
                const char **rscale = icalarray_element_at(rscale_calendars, i);

                xmlNewChild(node, NULL, BAD_CAST "rscale", BAD_CAST *rscale);
            }
        }

        maxlen = config_getint(IMAPOPT_MAXMESSAGESIZE);
        if (!maxlen) maxlen = INT_MAX;
        buf_reset(&txn->buf);
        buf_printf(&txn->buf, "%d", maxlen);
        xmlNewChild(capa, NULL, BAD_CAST "max-content-length",
                    BAD_CAST buf_cstring(&txn->buf));

        date = icaltime_from_timet_with_zone(caldav_epoch, 0, utc);
        xmlNewChild(capa, NULL, BAD_CAST "min-date-time",
                    BAD_CAST icaltime_as_ical_string(date));

        date = icaltime_from_timet_with_zone(caldav_eternity, 0, utc);
        xmlNewChild(capa, NULL, BAD_CAST "max-date-time",
                    BAD_CAST icaltime_as_ical_string(date));

        /* XXX  need to fill these with values */
        xmlNewChild(capa, NULL, BAD_CAST "max-recipients", NULL);
        xmlNewChild(capa, NULL, BAD_CAST "administrator", NULL);

        /* Dump XML response tree into a text buffer */
        xmlDocDumpFormatMemoryEnc(root->doc, &buf, &bufsiz, "utf-8", 1);
        xmlFreeDoc(root->doc);

        if (!buf) {
            txn->error.desc = "Error dumping XML tree";
            return HTTP_SERVER_ERROR;
        }

        message_guid_copy(&prev_guid, &guid);
    }

    /* Output the XML response */
    txn->resp_body.type = "application/xml; charset=utf-8";
    write_body(precond, txn, (char *) buf, bufsiz);

    xmlFree(buf);

    return 0;
}


static int meth_options_isched(struct transaction_t *txn, void *params)
{
    /* Fill in iSchedule-Capabilities */
    isched_capa_hdr(txn, NULL, NULL);

    return meth_options(txn, params);
}


/* iSchedule Receiver */
static int meth_post_isched(struct transaction_t *txn,
                            void *params __attribute__((unused)))
{
    int ret = 0, r, authd = 0;
    const char **hdr, **recipients;
    struct mime_type_t *mime = NULL;
    icalcomponent *ical = NULL, *comp;
    icalcomponent_kind kind = 0;
    icalproperty_method meth = 0;
    icalproperty *prop = NULL;
    const char *uid = NULL;

    /* Fill in iSchedule-Capabilities */
    isched_capa_hdr(txn, NULL, NULL);

    /* Response should not be cached */
    txn->flags.cc |= CC_NOCACHE;

    /* Check iSchedule-Version */
    if (!(hdr = spool_getheader(txn->req_hdrs, "iSchedule-Version")) ||
        strcmp(hdr[0], "1.0")) {
        txn->error.precond = ISCHED_UNSUPP_VERSION;
        return HTTP_BAD_REQUEST;
    }

    /* Check Content-Type */
    if ((hdr = spool_getheader(txn->req_hdrs, "Content-Type"))) {
        for (mime = isched_mime_types; mime->content_type; mime++) {
            if (is_mediatype(mime->content_type, hdr[0])) break;
        }
    }
    if (!mime || !mime->content_type) {
        txn->error.precond = ISCHED_UNSUPP_DATA;
        return HTTP_BAD_REQUEST;
    }

    /* Check Originator */
    if (!(hdr = spool_getheader(txn->req_hdrs, "Originator"))) {
        txn->error.precond = ISCHED_ORIG_MISSING;
        return HTTP_BAD_REQUEST;
    }
    else if (hdr[1]) {
        /* Multiple Originators */
        txn->error.precond = ISCHED_MULTIPLE_ORIG;
        return HTTP_BAD_REQUEST;
    }

    /* Check Recipients */
    if (!(recipients = spool_getheader(txn->req_hdrs, "Recipient"))) {
        txn->error.precond = ISCHED_RECIP_MISSING;
        return HTTP_BAD_REQUEST;
    }

    /* Read body */
    txn->req_body.flags |= BODY_DECODE;
    r = http_read_req_body(txn);
    if (r) {
        txn->flags.conn = CONN_CLOSE;
        return r;
    }

    /* Make sure we have a body */
    if (!buf_len(&txn->req_body.payload)) {
        txn->error.desc = "Missing request body";
        return HTTP_BAD_REQUEST;
    }

    /* Check authorization */
    if (httpd_userid &&
        config_mupdate_server && config_getstring(IMAPOPT_PROXYSERVERS)) {
        /* Allow frontends to HTTP auth to backends and use iSchedule */
        authd = 1;
    }
    else if (!spool_getheader(txn->req_hdrs, "DKIM-Signature")) {
        if (!config_getswitch(IMAPOPT_ISCHEDULE_DKIM_REQUIRED)) authd = 1;
        else txn->error.desc = "No signature";
    }
    else {
        authd = dkim_auth(txn);
    }

    if (!authd) {
        ret = HTTP_FORBIDDEN;
        txn->error.precond = ISCHED_VERIFICATION_FAILED;
        goto done;
    }

    /* Parse the iCal data for important properties */
    ical = mime->to_object(&txn->req_body.payload);
    if (!ical || (icalcomponent_isa(ical) != ICAL_VCALENDAR_COMPONENT)) {
        txn->error.precond = ISCHED_INVALID_DATA;
        return HTTP_BAD_REQUEST;
    }

    icalrestriction_check(ical);
    if ((txn->error.desc = get_icalcomponent_errstr(ical))) {
        assert(!buf_len(&txn->buf));
        buf_setcstr(&txn->buf, txn->error.desc);
        txn->error.desc = buf_cstring(&txn->buf);
        txn->error.precond = ISCHED_INVALID_DATA;
        return HTTP_BAD_REQUEST;
    }

    meth = icalcomponent_get_method(ical);
    comp = icalcomponent_get_first_real_component(ical);
    if (comp) {
        uid = icalcomponent_get_uid(comp);
        kind = icalcomponent_isa(comp);
        prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    }

    /* Check method preconditions */
    if (!meth || !comp || !uid || !prop) {
        txn->error.precond = ISCHED_INVALID_SCHED;
        ret = HTTP_BAD_REQUEST;
        goto done;
    }

    switch (kind) {
    case ICAL_VFREEBUSY_COMPONENT:
        if (meth == ICAL_METHOD_REQUEST)
            ret = sched_busytime_query(txn, mime, ical);
        else goto invalid_meth;
        break;

    case ICAL_VEVENT_COMPONENT:
    case ICAL_VTODO_COMPONENT:
    case ICAL_VPOLL_COMPONENT:
        switch (meth) {
        case ICAL_METHOD_POLLSTATUS:
            if (kind != ICAL_VPOLL_COMPONENT) goto invalid_meth;

            GCC_FALLTHROUGH

        case ICAL_METHOD_REQUEST:
        case ICAL_METHOD_REPLY:
        case ICAL_METHOD_CANCEL: {
            struct sched_data sched_data =
                { 1, meth == ICAL_METHOD_REPLY, 0,
                  ical, NULL, NULL, ICAL_SCHEDULEFORCESEND_NONE, NULL, NULL };
            xmlNodePtr root = NULL;
            xmlNsPtr ns[NUM_NAMESPACE];
            struct auth_state *authstate;
            int i;

            /* Start construction of our schedule-response */
            if (!(root = init_xml_response("schedule-response",
                                           NS_ISCHED, NULL, ns))) {
                ret = HTTP_SERVER_ERROR;
                txn->error.desc = "Unable to create XML response";
                goto done;
            }

            authstate = auth_newstate("anonymous");

            /* Process each recipient */
            for (i = 0; recipients[i]; i++) {
                tok_t tok =
                    TOK_INITIALIZER(recipients[i], ",", TOK_TRIMLEFT|TOK_TRIMRIGHT);
                const char *recipient;

                while ((recipient = tok_next(&tok))) {
                    /* Is recipient remote or local? */
                    struct caldav_sched_param sparam;
                    int r = caladdress_lookup(recipient, &sparam, /*schedule_addresses*/NULL);

                    /* Don't allow scheduling with remote users via iSchedule */
                    if (sparam.flags & SCHEDTYPE_REMOTE) r = HTTP_FORBIDDEN;
                    sched_param_fini(&sparam);

                    if (r) sched_data.status = REQSTAT_NOUSER;
                    else sched_deliver(httpd_userid, httpd_userid, recipient, &sched_data, authstate);

                    xml_add_schedresponse(root, NULL, BAD_CAST recipient,
                                          BAD_CAST sched_data.status);
                }
                tok_fini(&tok);
            }

            xml_response(HTTP_OK, txn, root->doc);
            xmlFreeDoc(root->doc);

            auth_freestate(authstate);
        }
            break;

        default:
        invalid_meth:
            txn->error.desc = "Unsupported iTIP method";
            txn->error.precond = ISCHED_INVALID_SCHED;
            ret = HTTP_BAD_REQUEST;
            goto done;
        }
        break;

    default:
        txn->error.desc = "Unsupported iCalendar component";
        txn->error.precond = ISCHED_INVALID_SCHED;
        ret = HTTP_BAD_REQUEST;
    }

  done:
    if (ical) icalcomponent_free(ical);

    return ret;
}


int isched_send(struct caldav_sched_param *sparam, const char *recipient,
                icalcomponent *ical, xmlNodePtr *xml)
{
    int r = 0;
    struct backend *be;
    static unsigned send_count = 0;
    static struct buf hdrs = BUF_INITIALIZER;
    const char *body, *uri, *originator;
    size_t bodylen;
    icalproperty_method method;
    icalcomponent *comp;
    icalcomponent_kind kind;
    icalproperty *prop;
    unsigned code;
    struct transaction_t txn;
    struct http_connection conn;

    *xml = NULL;
    memset(&txn, 0, sizeof(struct transaction_t));

    if (sparam->flags & SCHEDTYPE_REMOTE) uri = ISCHED_WELLKNOWN_URI;
    else uri = namespace_ischedule.prefix;

    /* Open connection to iSchedule receiver.
       Use header buffer to construct remote server[:port][/tls][/noauth] */
    buf_setcstr(&txn.buf, sparam->server);
    if (sparam->port) buf_printf(&txn.buf, ":%u", sparam->port);
    if (sparam->flags & SCHEDTYPE_SSL) buf_appendcstr(&txn.buf, "/tls");
    if (sparam->flags & SCHEDTYPE_REMOTE) {
        /* Using DKIM rather than HTTP Auth */
        buf_appendcstr(&txn.buf, "/noauth");
    }
    be = proxy_findserver(buf_cstring(&txn.buf), &http_protocol, httpd_userid,
                          &backend_cached, NULL, NULL, httpd_in);
    if (!be) return HTTP_UNAVAILABLE;

    /* Setup HTTP connection for reading response */
    memset(&conn, 0, sizeof(struct http_connection));
    conn.pin = be->in;
    txn.conn = &conn;

    /* Create iSchedule request body */
    body = icalcomponent_as_ical_string(ical);
    bodylen = strlen(body);

    /* Create iSchedule request header.
     * XXX  Make sure that we don't use multiple headers of the same name
     *      or add WSP around commas in signed headers
     *      to obey ischedule-relaxed canonicalization.
     */
    buf_reset(&hdrs);
    buf_printf(&hdrs, "Host: %s", sparam->server);
    if (sparam->port) buf_printf(&hdrs, ":%u", sparam->port);
    buf_printf(&hdrs, "\r\n");
    buf_printf(&hdrs, "Cache-Control: no-cache, no-transform\r\n");
    if (config_serverinfo == IMAP_ENUM_SERVERINFO_ON) {
        buf_printf(&hdrs, "User-Agent: %s\r\n", buf_cstring(&serverinfo));
    }
    buf_printf(&hdrs, "iSchedule-Version: 1.0\r\n");
    buf_printf(&hdrs, "iSchedule-Message-ID: <cmu-ischedule-%u-" TIME_T_FMT "-%u@%s>\r\n",
               getpid(), time(NULL), send_count++, config_servername);
    buf_printf(&hdrs, "Content-Type: text/calendar; charset=utf-8");

    method = icalcomponent_get_method(ical);
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);
    buf_printf(&hdrs, "; method=%s; component=%s\r\n",
               icalproperty_method_to_string(method),
               icalcomponent_kind_to_string(kind));

    buf_printf(&hdrs, "Content-Length: %u\r\n", (unsigned) bodylen);

    /* Determine Originator based on method and component */
    if (method == ICAL_METHOD_REPLY) {
        prop = icalcomponent_get_first_invitee(comp);
        originator = icalproperty_get_invitee(prop);
    }
    else {
        prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
        originator = icalproperty_get_organizer(prop);
    }
    buf_printf(&hdrs, "Originator: %s\r\n", originator);

    if (recipient) {
        /* Single recipient */
        buf_printf(&hdrs, "Recipient: %s\r\n", recipient);
    }
    else {
        /* VFREEBUSY REQUEST - use ATTENDEES as Recipients */
        char sep = ' ';

        buf_printf(&hdrs, "Recipient:");
        for (prop = icalcomponent_get_first_property(comp,
                                                     ICAL_ATTENDEE_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(comp,
                                                    ICAL_ATTENDEE_PROPERTY)) {
            buf_printf(&hdrs, "%c%s", sep, icalproperty_get_attendee(prop));
            sep = ',';
        }
        buf_printf(&hdrs, "\r\n");
    }

    /* Don't send body until told to */
    buf_appendcstr(&hdrs, "Expect: 100-continue\r\n");

    if (sparam->flags & SCHEDTYPE_REMOTE) {
#ifdef WITH_DKIM
        DKIM *dkim = NULL;
        DKIM_STAT stat;
        unsigned char *sig = NULL;
        size_t siglen;
        const char *selector = config_getstring(IMAPOPT_ISCHEDULE_DKIM_SELECTOR);
        const char *domain = config_getstring(IMAPOPT_ISCHEDULE_DKIM_DOMAIN);

        /* Create iSchedule/DKIM signature */
        if (dkim_lib &&
            (dkim = dkim_sign(dkim_lib, NULL /* id */, NULL,
                              (dkim_sigkey_t) buf_cstring(&privkey),
                              (const u_char *) selector,
                              (const u_char *) domain,
                              /* Requires modified version of OpenDKIM
                                 until we get OpenDOSETA */
                              DKIM_CANON_ISCHEDULE, DKIM_CANON_SIMPLE,
                              DKIM_SIGN_RSASHA256, -1 /* entire body */,
                              &stat))) {

            /* Suppress folding of DKIM header */
//          stat = dkim_set_margin(dkim, 0);

            /* Add our query method list */
            stat = dkim_add_querymethod(dkim, "private-exchange", NULL);
            stat = dkim_add_querymethod(dkim, "http", "well-known");
//          stat = dkim_add_querymethod(dkim, "dns", "txt");

            /* Process the headers and body */
            stat = dkim_chunk(dkim,
                              (u_char *) buf_cstring(&hdrs), buf_len(&hdrs));
            stat = dkim_chunk(dkim, (u_char *) "\r\n", 2);
            stat = dkim_chunk(dkim, (u_char *) body, bodylen);
            stat = dkim_chunk(dkim, NULL, 0);
            stat = dkim_eom(dkim, NULL);

            /* Generate the signature */
            stat = dkim_getsighdr_d(dkim, strlen(DKIM_SIGNHEADER) + 2,
                                    &sig, &siglen);
            /* Append a DKIM-Signature header */
            buf_printf(&hdrs, "%s: %s\r\n", DKIM_SIGNHEADER, sig);

            dkim_free(dkim);
        }
#else
        syslog(LOG_WARNING, "DKIM-Signature required, but DKIM isn't supported");
#endif /* WITH_DKIM */
    }

  redirect:
    /* Send request line */
    prot_printf(be->out, "POST %s %s\r\n", uri, HTTP_VERSION);

    /* Send request headers */
    prot_putbuf(be->out, &hdrs);
    prot_puts(be->out, "\r\n");

  response:
    /* Read response (req_hdr and req_body are actually the response) */
    txn.req_body.flags = BODY_DECODE;
    r = http_read_response(be, METH_POST, &code,
                           &txn.req_hdrs, &txn.req_body, &txn.error.desc);
    syslog(LOG_INFO, "isched_send(%s, %s) => %u",
           recipient, buf_cstring(&txn.buf), code);

    if (!r) {
        switch (code) {
        case 100:  /* Continue */
            /* Send request body (only ONCE for a given request) */
            prot_write(be->out, body, bodylen);
            bodylen = 0;

            GCC_FALLTHROUGH
            
        case 102:
        case 103:  /* Provisional */
            goto response;

        case 200:  /* Successful */
            /* Create XML parser context */
            if (!(conn.xml = xmlNewParserCtxt())) {
                fatal("Unable to create XML parser", EX_TEMPFAIL);
            }

            r = parse_xml_body(&txn, xml, NULL);
            xmlFreeParserCtxt(conn.xml);
            break;

        case 301:
        case 302:
        case 307:
        case 308:  /* Redirection */
            uri = spool_getheader(txn.req_hdrs, "Location")[0];
            if (txn.req_body.flags & BODY_CLOSE) {
                proxy_downserver(be);
                be = proxy_findserver(buf_cstring(&txn.buf), &http_protocol,
                                      NULL, &backend_cached,
                                      NULL, NULL, httpd_in);
                if (!be) {
                    r = HTTP_UNAVAILABLE;
                    break;
                }
            }

            if (!bodylen) bodylen = strlen(body);  /* Need to send body again */
            goto redirect;

        default:
            r = HTTP_UNAVAILABLE;
        }
    }

    if (txn.req_hdrs) spool_free_hdrcache(txn.req_hdrs);
    buf_free(&txn.req_body.payload);
    buf_free(&txn.buf);

    return r;
}


#ifdef WITH_DKIM
static DKIM_CBSTAT isched_get_key(DKIM *dkim, DKIM_SIGINFO *sig,
                                  u_char *buf, size_t buflen)
{
    DKIM_CBSTAT stat = DKIM_CBSTAT_NOTFOUND;
    const char *domain, *selector, *query;
    tok_t tok;
    char *type, *opts;

    assert(dkim != NULL);
    assert(sig != NULL);

    domain = (const char *) dkim_sig_getdomain(sig);
    selector = (const char *) dkim_sig_getselector(sig);
    if (!domain || !selector) return DKIM_CBSTAT_ERROR;

    query = (const char *) dkim_sig_gettagvalue(sig, 0, (u_char *) "q");
    if (!query) query = "dns/txt";  /* implicit default */

    /* Parse the q= tag */
    tok_init(&tok, query, ":", 0);
    while ((type = tok_next(&tok))) {
        /* Split type/options */
        if ((opts = strchr(type, '/'))) *opts++ = '\0';

#ifdef IOPTEST  /* CalConnect ioptest */
        if (1) {
#else
        if (!strcmp(type, "private-exchange")) {
#endif
            const char *prefix = config_getstring(IMAPOPT_HTTPDOCROOT);
            struct buf path = BUF_INITIALIZER;
            FILE *f;

            if (!prefix) continue;

            buf_setcstr(&path, prefix);
            buf_printf(&path, "%s/%s/%s",
                       namespace_domainkey.prefix, domain, selector);
            syslog(LOG_DEBUG, "using public key from path: %s",
                   buf_cstring(&path));

            if (!(f = fopen(buf_cstring(&path), "r"))) {
                syslog(LOG_NOTICE, "%s: fopen(): %s",
                       buf_cstring(&path), strerror(errno));
            }
            buf_free(&path);
            if (!f) continue;

            memset(buf, '\0', buflen);
            fgets((char *) buf, buflen, f);
            fclose(f);

            if (buf[0] != '\0') {
                stat = DKIM_CBSTAT_CONTINUE;
                break;
            }
        }
        else if (!strcmp(type, "http") && !strcmp(opts, "well-known")) {
        }
        else if (!strcmp(type, "dns") && !strcmp(opts, "txt")) {
            stat = DKIM_CBSTAT_DEFAULT;
            break;
        }
    }

    tok_fini(&tok);

    return stat;
}


static void dkim_cachehdr(const char *name, const char *contents,
                          const char *raw __attribute__((unused)), void *rock)
{
    struct buf *hdrfield = &tmpbuf;
    static const char *lastname = NULL;
    int dup_hdr = name && lastname && !strcmp(name, lastname);

    /* Ignore private headers in our cache */
    if (name && name[0] == ':') return;

    /* Combine header fields of the same name.
     * Our hash table will always feed us duplicate headers consecutively.
     */
    if (lastname && !dup_hdr) {
        dkim_header((DKIM *) rock,
                    (u_char *) buf_cstring(hdrfield), buf_len(hdrfield));
    }

    lastname = name;

    if (name) {
        tok_t tok;
        char *token, sep = ':';

        if (!dup_hdr) buf_setcstr(hdrfield, name);
        else sep = ',';

        /* Trim leading/trailing WSP around comma-separated values */
        tok_init(&tok, contents, ",", TOK_TRIMLEFT|TOK_TRIMRIGHT|TOK_EMPTY);
        while ((token = tok_next(&tok))) {
            buf_printf(hdrfield, "%c%s", sep, token);
            sep = ',';
        }
        tok_fini(&tok);
    }
}

static int dkim_auth(struct transaction_t *txn)
{
    int authd = 0;
    DKIM *dkim = NULL;
    DKIM_STAT stat;

    if (!dkim_lib) return 0;

    dkim = dkim_verify(dkim_lib, NULL /* id */, NULL, &stat);
    if (!dkim) return 0;

#ifdef TEST
    {
        /* XXX  Hack for local testing */
        dkim_query_t qtype = DKIM_QUERY_FILE;
        struct buf keyfile = BUF_INITIALIZER;

        stat = dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYMETHOD,
                            &qtype, sizeof(qtype));

        buf_printf(&keyfile, "%s/dkim.public", config_dir);
        stat = dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_QUERYINFO,
                            (void *) buf_cstring(&keyfile),
                            buf_len(&keyfile));
    }
#endif

    /* Process the cached headers and body */
    spool_enum_hdrcache(txn->req_hdrs, &dkim_cachehdr, dkim);
    dkim_cachehdr(NULL, NULL, dkim);  /* Force canon of last header */
    stat = dkim_eoh(dkim);
    if (stat == DKIM_STAT_OK) {
        stat = dkim_body(dkim, (u_char *) buf_cstring(&txn->req_body.payload),
                         buf_len(&txn->req_body.payload));
        stat = dkim_eom(dkim, NULL);
    }

    if (stat == DKIM_STAT_OK) authd = 1;
    else if (stat == DKIM_STAT_CBREJECT) {
        txn->error.desc =
            "Unable to verify: HTTP request-line mismatch";
    }
    else {
        DKIM_SIGINFO *sig = dkim_getsignature(dkim);

        if (sig) {
            const char *sigerr, *sslerr;

            if (dkim_sig_getbh(sig) == DKIM_SIGBH_MISMATCH)
                sigerr = "body hash mismatch";
            else {
                DKIM_SIGERROR err = dkim_sig_geterror(sig);

                sigerr = dkim_sig_geterrorstr(err);
            }

            assert(!buf_len(&txn->buf));
            buf_printf(&txn->buf, "%s: %s",
                       dkim_getresultstr(stat), sigerr);
            if ((sslerr = dkim_sig_getsslbuf(sig)))
                buf_printf(&txn->buf, ": %s", sslerr);
            txn->error.desc = buf_cstring(&txn->buf);
        }
        else txn->error.desc = dkim_getresultstr(stat);
    }

    dkim_free(dkim);

    return authd;
}
#else
static int dkim_auth(struct transaction_t *txn __attribute__((unused)))
{
    if (!config_getswitch(IMAPOPT_ISCHEDULE_DKIM_REQUIRED)) return 1;

    syslog(LOG_WARNING, "DKIM-Signature provided, but DKIM isn't supported");

    return 0;
}
#endif /* WITH_DKIM */


/* Perform a GET/HEAD request for a domainkey */
static int meth_get_domainkey(struct transaction_t *txn,
                              void *params __attribute__((unused)))
{
    int ret = 0, r, fd = -1, precond;
    const char *path;
    static struct buf pathbuf = BUF_INITIALIZER;
    struct stat sbuf;
    const char *msg_base = NULL;
    size_t msg_size = 0;
    struct resp_body_t *resp_body = &txn->resp_body;

    /* See if file exists and get Content-Length & Last-Modified time */
    buf_setcstr(&pathbuf, config_dir);
    buf_appendcstr(&pathbuf, txn->req_uri->path);
    path = buf_cstring(&pathbuf);
    r = stat(path, &sbuf);
    if (r || !S_ISREG(sbuf.st_mode)) return HTTP_NOT_FOUND;

    /* Generate Etag */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%ld-%ld", (long) sbuf.st_mtime, (long) sbuf.st_size);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, buf_cstring(&txn->buf), sbuf.st_mtime);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
        /* Fill in Content-Type, ETag, Last-Modified, and Expires */
        resp_body->type = "text/plain";
        resp_body->etag = buf_cstring(&txn->buf);
        resp_body->lastmod = sbuf.st_mtime;
        resp_body->maxage = 86400;  /* 24 hrs */
        txn->flags.cc |= CC_MAXAGE | CC_REVALIDATE;
        if (!httpd_userisanonymous) txn->flags.cc |= CC_PUBLIC;

        if (precond != HTTP_NOT_MODIFIED) break;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        resp_body->type = NULL;
        return precond;
    }

    if (txn->meth == METH_GET) {
        /* Open and mmap the file */
        if ((fd = open(path, O_RDONLY)) == -1) return HTTP_SERVER_ERROR;
        map_refresh(fd, 1, &msg_base, &msg_size, sbuf.st_size, path, NULL);
    }

    write_body(precond, txn, msg_base, sbuf.st_size);

    if (fd != -1) {
        map_free(&msg_base, &msg_size);
        close(fd);
    }

    return ret;
}


static void isched_init(struct buf *serverinfo)
{
    if (!(config_httpmodules & IMAP_ENUM_HTTPMODULES_CALDAV) ||
        !config_getenum(IMAPOPT_CALDAV_ALLOWSCHEDULING)) {
        /* Need CALDAV and CALDAV_SCHED in order to have ISCHEDULE */
        return;
    }

    compile_time = calc_compile_time(__TIME__, __DATE__);

    if (config_mupdate_server && config_getstring(IMAPOPT_PROXYSERVERS)) {
        /* If backend server, we require iSchedule (w/o DKIM) */
        namespace_ischedule.enabled = -1;
        buf_cstring(serverinfo);  // squash compiler warning when #undef WITH_DKIM
    }
    else {
        namespace_ischedule.enabled =
            config_httpmodules & IMAP_ENUM_HTTPMODULES_ISCHEDULE;
    }

#ifdef WITH_DKIM
    /* Add OpenDKIM version to serverinfo string */
    uint32_t ver = dkim_libversion();
    buf_printf(serverinfo, " OpenDKIM/%u.%u.%u",
               (ver >> 24) & 0xff, (ver >> 16) & 0xff, (ver >> 8) & 0xff);
    if (ver & 0xff) buf_printf(serverinfo, ".%u", ver & 0xff);

    if (namespace_ischedule.enabled) {
        int fd;
        unsigned flags = ( DKIM_LIBFLAGS_BADSIGHANDLES | DKIM_LIBFLAGS_CACHE |
//                         DKIM_LIBFLAGS_KEEPFILES | DKIM_LIBFLAGS_TMPFILES |
                           DKIM_LIBFLAGS_VERIFYONE );
        uint64_t ttl = 3600;  /* 1 hour */
        const char *requiredhdrs[] = { "Content-Type", "iSchedule-Version",
                                       "Originator", "Recipient", NULL };
        const char *signhdrs[] = { "iSchedule-Message-ID", "User-Agent", NULL };
        const char *skiphdrs[] = { "Cache-Control", "Connection",
                                   "Content-Length", "Host", "Keep-Alive",
                                   "Proxy-Authenticate", "Proxy-Authorization",
                                   "TE", "Trailer", "Transfer-Encoding",
                                   "Upgrade", "Via", NULL };
        const char *senderhdrs[] = { "Originator", NULL };
        const char *keyfile = config_getstring(IMAPOPT_ISCHEDULE_DKIM_KEY_FILE);
        unsigned need_dkim =
            namespace_ischedule.enabled == IMAP_ENUM_HTTPMODULES_ISCHEDULE;

        /* Initialize DKIM library */
        if (!(dkim_lib = dkim_init(NULL, NULL))) {
            syslog(LOG_ERR, "unable to initialize libopendkim");
            namespace_ischedule.enabled = !need_dkim;
            return;
        }

        /* Install our callback for doing key lookups */
        dkim_set_key_lookup(dkim_lib, isched_get_key);

        /* Setup iSchedule DKIM options */
#ifdef TEST
        flags |= ( DKIM_LIBFLAGS_SIGNLEN | DKIM_LIBFLAGS_ZTAGS );
#endif
        dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_FLAGS,
                     &flags, sizeof(flags));
        dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_SIGNATURETTL,
                     &ttl, sizeof(ttl));
        dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_REQUIREDHDRS,
                     requiredhdrs, sizeof(const char **));
        dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_MUSTBESIGNED,
                     requiredhdrs, sizeof(const char **));
        dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_SIGNHDRS,
                     signhdrs, sizeof(const char **));
        dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_SKIPHDRS,
                     skiphdrs, sizeof(const char **));
        dkim_options(dkim_lib, DKIM_OP_SETOPT, DKIM_OPTS_SENDERHDRS,
                     senderhdrs, sizeof(const char **));

        /* Fetch DKIM private key for signing */
        if (keyfile && (fd = open(keyfile, O_RDONLY)) != -1) {
            const char *base = NULL;
            size_t len = 0;

            map_refresh(fd, 1, &base, &len, MAP_UNKNOWN_LEN, keyfile, NULL);
            buf_setmap(&privkey, base, len);
            map_free(&base, &len);
            close(fd);
        }
        else {
            syslog(LOG_ERR, "unable to open private key file %s", keyfile);
            namespace_ischedule.enabled = !need_dkim;
        }

        namespace_domainkey.enabled =
            config_httpmodules & IMAP_ENUM_HTTPMODULES_DOMAINKEY;
    }
#endif /* WITH_DKIM */
}


static void isched_shutdown(void)
{
#ifdef WITH_DKIM
    buf_free(&privkey);
    buf_free(&tmpbuf);
    buf_free(&b64req);
    if (dkim_lib) dkim_close(dkim_lib);
#endif
}
