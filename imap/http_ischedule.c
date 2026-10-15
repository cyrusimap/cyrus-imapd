/* http_ischedule.c - Routines for handling iSchedule in httpd */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <sysexits.h>
#include <syslog.h>

#include <libical/ical.h>

#include <libxml/parser.h>

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
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"

static void isched_init(struct buf *serverinfo);

static int meth_post_isched(struct transaction_t *txn, void *params);

// clang-format off
static struct mime_type_t isched_mime_types[] = {
    /* First item MUST be the default type and storage format */
    { "text/calendar; charset=utf-8", "2.0", "ics",
      (struct buf* (*)(void *)) &my_icalcomponent_as_ical_string,
      (void * (*)(const struct buf*)) &ical_string_as_icalcomponent,
      (void (*)(void *)) &icalcomponent_free, NULL, NULL
    },
    { "application/calendar+json; charset=utf-8", NULL, "jcs",
      (struct buf* (*)(void *)) &icalcomponent_as_jcal_string,
      (void * (*)(const struct buf*)) &jcal_string_as_icalcomponent,
      NULL, NULL, NULL,
    },
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};
// clang-format on

// clang-format off
struct namespace_t namespace_ischedule = {
    URL_NS_ISCHEDULE, 0, "ischedule", "/ischedule", NULL,
    http_allow_noauth, /*authschemes*/0,
    /*mbtype*/0,
    (ALLOW_POST | ALLOW_ISCHEDULE),
    isched_init, NULL, NULL, NULL, NULL,
    {
        { NULL,                 NULL }, /* ACL          */
        { NULL,                 NULL }, /* BIND         */
        { NULL,                 NULL }, /* CONNECT      */
        { NULL,                 NULL }, /* COPY         */
        { NULL,                 NULL }, /* DELETE       */
        { NULL,                 NULL }, /* GET          */
        { NULL,                 NULL }, /* HEAD         */
        { NULL,                 NULL }, /* LOCK         */
        { NULL,                 NULL }, /* MKCALENDAR   */
        { NULL,                 NULL }, /* MKCOL        */
        { NULL,                 NULL }, /* MOVE         */
        { &meth_options,        NULL }, /* OPTIONS      */
        { NULL,                 NULL }, /* PATCH        */
        { &meth_post_isched,    NULL }, /* POST         */
        { NULL,                 NULL }, /* PROPFIND     */
        { NULL,                 NULL }, /* PROPPATCH    */
        { NULL,                 NULL }, /* PUT          */
        { NULL,                 NULL }, /* REPORT       */
        { NULL,                 NULL }, /* SEARCH       */
        { &meth_trace,          NULL }, /* TRACE        */
        { NULL,                 NULL }, /* UNBIND       */
        { NULL,                 NULL }  /* UNLOCK       */
    }
};
// clang-format on


static int caladdress_equal(const char *a, const char *b)
{
    if (!a || !b) return 0;
    if (!strncasecmp(a, "mailto:", 7)) a += 7;
    if (!strncasecmp(b, "mailto:", 7)) b += 7;

    return !strcasecmp(a, b);
}


/* Is the Originator the ORGANIZER of the scheduling message, or for a
 * REPLY one of its ATTENDEEs? */
static int originator_matches(const char *originator, icalcomponent *comp,
                              icalproperty_method meth)
{
    icalproperty *prop;

    if (meth == ICAL_METHOD_REPLY) {
        for (prop = icalcomponent_get_first_invitee(comp); prop;
             prop = icalcomponent_get_next_invitee(comp)) {
            if (caladdress_equal(originator,
                                 icalproperty_get_decoded_calendaraddress(prop)))
                return 1;
        }
        return 0;
    }

    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    return caladdress_equal(originator,
                            icalproperty_get_decoded_calendaraddress(prop));
}


/* iSchedule Receiver */
static int meth_post_isched(struct transaction_t *txn,
                            void *params __attribute__((unused)))
{
    int ret = 0, r;
    const char **hdr, **recipients;
    struct mime_type_t *mime = NULL;
    icalcomponent *ical = NULL, *comp;
    icalcomponent_kind kind = 0;
    icalproperty_method meth = 0;
    icalproperty *prop = NULL;
    const char *uid = NULL, *originator = NULL;

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
    originator = hdr[0];

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

    /* Require an authenticated sender */
    if (!httpd_userid) {
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
    if ((txn->error.desc = get_icalcomponent_errstr(ical, ICAL_SUPPORT_STRICT))) {
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

    if (!originator_matches(originator, comp, meth)) {
        txn->error.desc = "Originator is not the ORGANIZER or a replying ATTENDEE";
        txn->error.precond = ISCHED_ORIG_DENIED;
        ret = HTTP_FORBIDDEN;
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
            unsigned flags = SCHEDFLAG_ISCHEDULE;
            if (meth == ICAL_METHOD_REPLY) flags |= SCHEDFLAG_IS_REPLY;
            struct sched_data sched_data =
                { SCHED_MECH_ISCHEDULE, flags, ical, NULL, NULL,
                  ICAL_SCHEDULEFORCESEND_NONE, NULL, NULL, NULL, 0 };
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
                char *recipient;

                while ((recipient = tok_next(&tok))) {
                    /* Is recipient remote or local? */
                    struct caldav_sched_param sparam;
                    int r = caladdress_lookup(recipient, &sparam, /*schedule_addresses*/NULL);

                    /* Don't allow scheduling with remote users via iSchedule */
                    if (sparam.flags & SCHEDTYPE_REMOTE) r = HTTP_FORBIDDEN;

                    if (r) sched_data.status = REQSTAT_NOUSER;
                    else sched_deliver(sparam.userid, sparam.userid, originator,
                                       recipient, &sched_data, authstate);
                    sched_param_fini(&sparam);

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

    uri = namespace_ischedule.prefix;

    /* Open connection to the backend holding the recipient */
    buf_setcstr(&txn.buf, sparam->server);
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
        originator = icalproperty_get_decoded_calendaraddress(prop);
    }
    else {
        prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
        originator = icalproperty_get_decoded_calendaraddress(prop);
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
            buf_printf(&hdrs, "%c%s", sep,
                       icalproperty_get_decoded_calendaraddress(prop));
            sep = ',';
        }
        buf_printf(&hdrs, "\r\n");
    }

    /* Don't send body until told to */
    buf_appendcstr(&hdrs, "Expect: 100-continue\r\n");

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


static void isched_init(struct buf *serverinfo __attribute__((unused)))
{
    if (!(config_httpmodules & IMAP_ENUM_HTTPMODULES_CALDAV) ||
        !config_getenum(IMAPOPT_CALDAV_ALLOWSCHEDULING)) {
        /* Need CALDAV and CALDAV_SCHED in order to have ISCHEDULE */
        return;
    }

    /* iSchedule carries scheduling messages between Murder backends */
    if (config_mupdate_server && config_getstring(IMAPOPT_PROXYSERVERS)) {
        namespace_ischedule.enabled = -1;
    }
}
