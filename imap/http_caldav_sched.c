/* http_caldav_sched.c -- Routines for dealing with CALDAV scheduling in httpd
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


#include <config.h>

#include <syslog.h>

#include <jansson.h>
#include <libical/ical.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <libxml/HTMLparser.h>
#include <libxml/tree.h>

#include "httpd.h"
#include "http_caldav_sched.h"
#include "http_dav.h"
#include "http_proxy.h"
#include "jmap_ical.h"
#include "jmap_util.h"
#include "notify.h"
#include "crc32.h"
#include "smtpclient.h"
#include "strhash.h"
#include "times.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static const char *get_organizer(icalcomponent *comp);
static int partstat_changed(icalcomponent *oldcomp,
                            icalcomponent *newcomp, const char *attendee);

int caladdress_lookup(const char *addr, struct caldav_sched_param *param,
                      const strarray_t *schedule_addresses)
{
    const char *userid = addr;
    int i;

    memset(param, 0, sizeof(struct caldav_sched_param));

    if (!addr) return HTTP_NOT_FOUND;

    if (!strncasecmp(userid, "mailto:", 7)) userid += 7;

    char *addresses = schedule_addresses ? strarray_join(schedule_addresses, ",") : xstrdup("NULL");
    syslog(LOG_DEBUG,
           "caladdress_lookup(userid: '%s', schedule_addresses: '%s')",
           userid, addresses);
    free(addresses);

    param->userid = xstrdup(userid);

    if (schedule_addresses) {
        for (i = 0; i < strarray_size(schedule_addresses); i++) {
            const char *item = strarray_nth(schedule_addresses, i);
            if (!strncasecmp(item, "mailto:", 7)) item += 7;
            if (strcasecmp(item, userid)) continue;
            // found one!
            param->isyou = 1;
            return 0; // myself is always local
        }
    }

    // does this user have an inbox on this machine?

    /* XXX  Do LDAP/DB/socket lookup to see if user is local */
    /* XXX  Hack until real lookup stuff is written */
    int islocal = 0;

    char *at = strchr(param->userid, '@');
    if (at) {
        int i;
        for (i = 0; i < strarray_size(&cua_domains); i++) {
            const char *s = strarray_nth(&cua_domains, i);
            if (!strcmp(at+1, s)) {
                islocal = 1;

                if (!config_virtdomains) {
                    *at = '\0';  // trim off the domain
                }
                break;
            }
        }
    }

    if (islocal) {
        mbentry_t *mbentry = NULL;
        /* Lookup user's cal-home-set to see if its on this server */
        mbname_t *mbname = mbname_from_recipient(param->userid, NULL);
        mbname_push_boxes(mbname, config_getstring(IMAPOPT_CALENDARPREFIX));
        int r = proxy_mlookup(mbname_intname(mbname), &mbentry, NULL, NULL);
        mbname_free(&mbname);

        if (!r) {
            param->server = xstrdupnull(mbentry->server); /* freed by sched_param_fini */
            mboxlist_entry_free(&mbentry);
            if (param->server) param->flags |= SCHEDTYPE_ISCHEDULE;
            return 0;
        }
    }

    /* User is outside of our domain(s) -
       Do remote scheduling (default = iMIP) */
    param->flags |= SCHEDTYPE_REMOTE;

    /* Do iSchedule DNS SRV lookup */

    /* XXX  If success, set server, port,
       and flags |= SCHEDTYPE_ISCHEDULE [ | SCHEDTYPE_SSL ] */

#ifdef IOPTEST  /* CalConnect ioptest */
    if (!strcmp(p, "example.com")) {
        param->server = xstrdup("ischedule.example.com");
        param->port = 8008;
        param->flags |= SCHEDTYPE_ISCHEDULE;
    }
    else if (!strcmp(p, "mysite.edu")) {
        param->server = xstrdup("ischedule.mysite.edu");
        param->port = 8080;
        param->flags |= SCHEDTYPE_ISCHEDULE;
    }
    else if (!strcmp(p, "bedework.org")) {
        param->server = xstrdup("www.bedework.org");
        param->port = 80;
        param->flags |= SCHEDTYPE_ISCHEDULE;
    }
#endif /* IOPTEST */

    return 0;
}

struct address_t {
    const char *addr;
    const char *name;
    char *qpname;
    const char *role;
    const char *partstat;
    struct address_t *next;
};

static void add_address(struct address_t **recipients, icalproperty *prop,
                        const char* (*icalproperty_get_address)(icalproperty *))
{
    struct address_t *new = xzmalloc(sizeof(struct address_t));
    icalparameter *param;

    const char *address = icalproperty_get_address(prop);
    if (!address) return;
    if (!strncasecmp(address, "mailto:", 7))
        address += 7;

    new->addr = address;
    param = icalproperty_get_first_parameter(prop, ICAL_CN_PARAMETER);
    if (param) {
        new->name = icalparameter_get_cn(param);
        new->qpname = charset_encode_mimeheader(new->name, 0, 0);
    }
    param = icalproperty_get_first_parameter(prop, ICAL_ROLE_PARAMETER);
    if (param)
        new->role = icalparameter_enum_to_string(icalparameter_get_role(param));
    param = icalproperty_get_first_parameter(prop, ICAL_PARTSTAT_PARAMETER);
    if (param)
        new->partstat =
            icalparameter_enum_to_string(icalparameter_get_partstat(param));

    new->next = *recipients;
    *recipients = new;
}

static void HTMLencode(struct buf *output, const char *input)
{
    int inlen = strlen(input);
    int outlen = 8*inlen;  /* room for every char to become a named entity */

    buf_ensure(output, outlen+1);
    htmlEncodeEntities((unsigned char *) buf_base(output), &outlen,
                       (unsigned char *) input, &inlen, 0);
    buf_truncate(output, outlen);
    buf_replace_all(output, "\n", "\n  <br>");
}

#define TEXT_INDENT     "             "
#define HTML_ROW        "<tr><td><b>%s</b></td><td>%s</td></tr>\r\n"

/* Send an iMIP request for attendees in 'ical' */
static int imip_send_sendmail(const char *userid, icalcomponent *ical, const char *sender,
                              const char *recipient, int is_update)
{
    int r;
    icalcomponent *comp;
    icalproperty *prop;
    icalproperty_method meth;
    icalcomponent_kind kind;
    const char *uid, *summary, *location, *descrip, *status;
    const char *msg_type, *filename;
    struct address_t *recipients = NULL, *originator = NULL, *recip;
    struct icaltimetype start, end;
    char *cp, when[2*RFC5322_DATETIME_MAX+4], datestr[RFC5322_DATETIME_MAX+1];
    char boundary[100], *mimebody, *ical_str;
    size_t outlen;
    struct buf plainbuf = BUF_INITIALIZER, tmpbuf = BUF_INITIALIZER, msgbuf = BUF_INITIALIZER;
    pid_t p = getpid();
    time_t t = time(NULL);
    static unsigned send_count = 0;

    meth = icalcomponent_get_method(ical);
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);
    uid = icalcomponent_get_uid(comp);

    /* Determine Originator and Recipient(s) based on method and component */
    if (meth == ICAL_METHOD_REPLY) {
        msg_type = "a RSVP";
        filename = "RSVP";

        prop = icalcomponent_get_first_invitee(comp);
        add_address(&originator, prop, &icalproperty_get_invitee);

        prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
        add_address(&recipients, prop,
                    (const char*(*)(icalproperty *))&icalproperty_get_organizer);
    }
    else {
        if (meth == ICAL_METHOD_CANCEL) {
            msg_type = "a cancellation";
            filename = "Canceled";
        }
        else if (is_update) {
            msg_type = "an updated invitation";
            filename = "Update";
        }
        else {
            msg_type = "an invitation";
            filename = "Invitation";
        }

        prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
        add_address(&originator, prop,
                    (const char*(*)(icalproperty *))&icalproperty_get_organizer);

        for (prop = icalcomponent_get_first_invitee(comp);
             prop;
             prop = icalcomponent_get_next_invitee(comp)) {

            add_address(&recipients, prop, &icalproperty_get_invitee);
        }
    }

    /* Get other useful properties/values */
    summary = icalcomponent_get_summary(comp);
    location = icalcomponent_get_location(comp);
    descrip = icalcomponent_get_description(comp);
    if ((prop = icalcomponent_get_first_property(comp, ICAL_STATUS_PROPERTY))) {
        status = icalproperty_get_value_as_string(prop);
    }
    else status = NULL;

    start = icaltime_convert_to_zone(icalcomponent_get_dtstart(comp), utc_zone);
    end = icaltime_convert_to_zone(icalcomponent_get_dtend(comp), utc_zone);

    cp = when;
    cp += sprintf(cp, "%s, %02u %s %04u",
                  wday[icaltime_day_of_week(start)-1],
                  start.day, monthname[start.month-1], start.year);
    if (!icaltime_is_date(start)) {
        cp += sprintf(cp, " %02u:%02u", start.hour, start.minute);
        if (start.second) cp += sprintf(cp, ":%02u", start.second);
        strcpy(cp, " UTC");
    }
    else icaltime_adjust(&end, -1, 0, 0, 0);

    if (icaltime_compare(end, start)) {
        strcpy(cp, " -");
        cp += 2;
        if (icaltime_compare_date_only(end, start)) {
            cp += sprintf(cp, " %s, %02u %s %04u",
                          wday[icaltime_day_of_week(end)-1],
                          end.day, monthname[end.month-1], end.year);
        }
        if (!icaltime_is_date(end)) {
            cp += sprintf(cp, " %02u:%02u", end.hour, end.minute);
            if (end.second) cp += sprintf(cp, ":%02u", end.second);
            strcpy(cp, " UTC");
        }
    }

    /* Create multipart/mixed + multipart/alternative iMIP message */
    buf_printf(&msgbuf, "From: %s <%s>\r\n",
            originator->qpname ? originator->qpname : "", sender);

    for (recip = recipients; recip; recip = recip->next) {
        if (strcmp(recip->addr, sender) &&
            (!recipient || !strcasecmp(recip->addr, recipient))) {
            buf_printf(&msgbuf, "To: %s <%s>\r\n",
                    recip->qpname ? recip->qpname : "", recip->addr);
        }
    }

    buf_printf(&msgbuf, "Subject: %s: ", filename);
    if (summary) {
        char *mimehdr = charset_encode_mimeheader(summary, 0, 0);
        buf_appendcstr(&msgbuf, mimehdr);
        free(mimehdr);
    }
    else {
        buf_appendcstr(&msgbuf, icalcomponent_kind_to_string(kind));
    }
    buf_appendcstr(&msgbuf, "\r\n");

    time_to_rfc5322(t, datestr, sizeof(datestr));
    buf_printf(&msgbuf, "Date: %s\r\n", datestr);

    buf_printf(&msgbuf, "Message-ID: <cyrus-caldav-%u-" TIME_T_FMT "-%u@%s>\r\n",
            p, t, send_count++, config_servername);

    /* Create multipart boundary */
    snprintf(boundary, sizeof(boundary), "%s=_%ld=_%ld=_%ld",
             config_servername, (long) p, (long) t, (long) rand());

    buf_printf(&msgbuf, "Content-Type: multipart/mixed;"
            "\r\n\tboundary=\"%s_M\"\r\n", boundary);

    buf_printf(&msgbuf, "iMIP-Content-ID: <%s@%s>\r\n", uid, config_servername);

    buf_appendcstr(&msgbuf, "Auto-Submitted: auto-generated\r\n");
    buf_appendcstr(&msgbuf, "MIME-Version: 1.0\r\n");
    buf_appendcstr(&msgbuf, "\r\n");

    /* preamble */
    buf_appendcstr(&msgbuf, "This is a message with multiple parts in MIME format.\r\n");

    /* multipart/alternative */
    buf_printf(&msgbuf, "\r\n--%s_M\r\n", boundary);

    buf_printf(&msgbuf, "Content-Type: multipart/alternative;"
            "\r\n\tboundary=\"%s_A\"\r\n", boundary);

    /* plain text part */
    buf_printf(&msgbuf, "\r\n--%s_A\r\n", boundary);

    buf_appendcstr(&msgbuf, "Content-Type: text/plain; charset=utf-8\r\n");
    buf_appendcstr(&msgbuf, "Content-Disposition: inline\r\n");

    buf_printf(&plainbuf, "You have received %s from %s <%s>\r\n\r\n", msg_type,
               originator->name ? originator->name : "", originator->addr);
    if (summary) {
        buf_setcstr(&tmpbuf, summary);
        buf_replace_all(&tmpbuf, "\n", "\r\n" TEXT_INDENT);
        buf_printf(&plainbuf, "Summary    : %s\r\n", buf_cstring(&tmpbuf));
    }
    if (location) {
        buf_setcstr(&tmpbuf, location);
        buf_replace_all(&tmpbuf, "\n", "\r\n" TEXT_INDENT);
        buf_printf(&plainbuf, "Location   : %s\r\n", buf_cstring(&tmpbuf));
    }
    buf_printf(&plainbuf, "When       : %s\r\n", when);
    if (meth == ICAL_METHOD_REPLY) {
        if (originator->partstat)
            buf_printf(&plainbuf, "RSVP       : %s\r\n", originator->partstat);
    }
    else {
        if (status) buf_printf(&plainbuf, "Status     : %s\r\n", status);

        for (cp = "Attendees  : ", recip=recipients; recip; recip=recip->next) {
            buf_printf(&plainbuf, "%s* %s <%s>",
                       cp, recip->name ? recip->name : "", recip->addr);
            if (recip->role) buf_printf(&plainbuf, "\t(%s)", recip->role);
            buf_appendcstr(&plainbuf, "\r\n");

            cp = TEXT_INDENT;
        }

        if (descrip) {
            buf_setcstr(&tmpbuf, descrip);
            buf_replace_all(&tmpbuf, "\n", "\r\n" TEXT_INDENT);
            buf_printf(&plainbuf, "Description: %s\r\n", buf_cstring(&tmpbuf));
        }
    }

    mimebody = charset_qpencode_mimebody(buf_base(&plainbuf),
                                         buf_len(&plainbuf), 0, &outlen);

    if (outlen > buf_len(&plainbuf)) {
        buf_appendcstr(&msgbuf, "Content-Transfer-Encoding: quoted-printable\r\n");
    }
    buf_appendcstr(&msgbuf, "\r\n");

    buf_appendmap(&msgbuf, mimebody, outlen);
    free(mimebody);
    buf_free(&plainbuf);

    /* HTML part */
    buf_printf(&msgbuf, "\r\n--%s_A\r\n", boundary);

    buf_printf(&msgbuf, "Content-Type: text/html; charset=utf-8\r\n");
    buf_appendcstr(&msgbuf, "Content-Disposition: inline\r\n");
    buf_appendcstr(&msgbuf, "\r\n");

    buf_appendcstr(&msgbuf, HTML_DOCTYPE "\r\n<html><head><title></title></head><body>\r\n");

    if (originator->name) {
        HTMLencode(&tmpbuf, originator->name);
        originator->name = buf_cstring(&tmpbuf);
    }
    else originator->name = originator->addr;

    buf_printf(&msgbuf, "<b>You have received %s from"
            " <a href=\"mailto:%s\">%s</a></b><p>\r\n",
            msg_type, originator->addr, originator->name);

    buf_appendcstr(&msgbuf, "<table border cellpadding=5>\r\n");
    if (summary) {
        HTMLencode(&tmpbuf, summary);
        buf_printf(&msgbuf, HTML_ROW, "Summary", buf_cstring(&tmpbuf));
    }
    if (location) {
        HTMLencode(&tmpbuf, location);
        buf_printf(&msgbuf, HTML_ROW, "Location", buf_cstring(&tmpbuf));
    }
    buf_printf(&msgbuf, HTML_ROW, "When", when);
    if (meth == ICAL_METHOD_REPLY) {
        if (originator->partstat)
            buf_printf(&msgbuf, HTML_ROW, "RSVP", originator->partstat);
    }
    else {
        if (status) buf_printf(&msgbuf, HTML_ROW, "Status", status);

        buf_appendcstr(&msgbuf, "<tr><td><b>Attendees</b></td>");
        for (cp = "<td>", recip = recipients; recip; recip = recip->next) {
            if (recip->name) {
                HTMLencode(&tmpbuf, recip->name);
                recip->name = buf_cstring(&tmpbuf);
            }
            else recip->name = recip->addr;

            buf_printf(&msgbuf, "%s&#8226; <a href=\"mailto:%s\">%s</a>",
                    cp, recip->addr, recip->name);
            if (recip->role) buf_printf(&msgbuf, " <i>(%s)</i>", recip->role);

            cp = "\n  <br>";
        }
        buf_appendcstr(&msgbuf, "</td></tr>\r\n");

        if (descrip) {
            HTMLencode(&tmpbuf, descrip);
            buf_printf(&msgbuf, HTML_ROW, "Description", buf_cstring(&tmpbuf));
        }
    }
    buf_printf(&msgbuf, "</table></body></html>\r\n");

    /* iCalendar part */
    buf_printf(&msgbuf, "\r\n--%s_A\r\n", boundary);

    buf_printf(&msgbuf, "Content-Type: text/calendar; charset=utf-8");
    buf_printf(&msgbuf, "; method=%s; component=%s \r\n",
            icalproperty_method_to_string(meth),
            icalcomponent_kind_to_string(kind));

    buf_printf(&msgbuf, "Content-ID: <%s@%s>\r\n", uid, config_servername);

    ical_str = icalcomponent_as_ical_string(ical);
    mimebody = charset_qpencode_mimebody(ical_str, strlen(ical_str), 0, &outlen);

    if (outlen > strlen(ical_str)) {
        buf_appendcstr(&msgbuf, "Content-Transfer-Encoding: quoted-printable\r\n");
    }
    buf_appendcstr(&msgbuf, "\r\n");

    buf_appendmap(&msgbuf, mimebody, outlen);
    free(mimebody);

    /* end boundary (alternative) */
    buf_printf(&msgbuf, "\r\n--%s_A--\r\n", boundary);

    /* application/ics part */
    buf_printf(&msgbuf, "\r\n--%s_M\r\n", boundary);

    buf_printf(&msgbuf,
            "Content-Type: application/ics; charset=utf-8; name=\"%s.ics\"\r\n",
            filename);
    buf_printf(&msgbuf, "Content-Disposition: attachment; filename=\"%s.ics\"\r\n",
            filename);
    buf_appendcstr(&msgbuf, "Content-Transfer-Encoding: base64\r\n");
    buf_appendcstr(&msgbuf, "\r\n");

    charset_encode_mimebody(NULL, strlen(ical_str), NULL, &outlen,
                            NULL, 1 /* wrap */);
    buf_ensure(&tmpbuf, outlen);
    charset_encode_mimebody(ical_str, strlen(ical_str),
                            (char *) buf_base(&tmpbuf), &outlen,
                            NULL, 1 /* wrap */);
    buf_appendmap(&msgbuf, buf_base(&tmpbuf), outlen);

    /* end boundary (mixed) and epilogue */
    buf_printf(&msgbuf, "\r\n--%s_M--\r\n\r\nEnd of MIME multipart body.\r\n", boundary);

    /* Open SMTP connection */
    smtpclient_t *sm = NULL;
    r = smtpclient_open(&sm);
    if (r) {
        syslog(LOG_ERR,
               "imip_send_sendmail(%s): failed to open SMTP client", recipient);
        r = HTTP_UNAVAILABLE;
        goto done;
    }
    smtpclient_set_auth(sm, userid);
    smtpclient_set_notify(sm, "FAILURE,DELAY");

    /* Set SMTP envelope */
    smtp_envelope_t sm_env = SMTP_ENVELOPE_INITIALIZER;
    smtp_envelope_set_from(&sm_env, originator->addr);
    for (recip = recipients; recip; recip = recip->next) {
        if (strcmp(recip->addr, originator->addr) &&
            (!recipient || !strcasecmp(recip->addr, recipient))) {
            smtp_envelope_add_rcpt(&sm_env, recip->addr);
        }
    }

    /* Send message */
    r = smtpclient_send(sm, &sm_env, &msgbuf);
    syslog(LOG_INFO,
           "imip_send_sendmail(%s): %s", recipient, error_message(r));
    smtp_envelope_fini(&sm_env);

    int r2 = smtpclient_close(&sm);
    if (!r) r = r2;

  done:
    buf_free(&msgbuf);
    buf_free(&tmpbuf);
    free(originator->qpname);
    free(originator);
    do {
        struct address_t *freeme = recipients;
        recipients = recipients->next;
        free(freeme->qpname);
        free(freeme);
    } while (recipients);

    return r;
}


/* Send an iMIP request for attendees in 'ical' */
static int imip_send(const char *userid, struct sched_data *sched_data,
                     const char *sender, const char *recipient)
{
    const char *notifier = config_getstring(IMAPOPT_IMIPNOTIFIER);

    syslog(LOG_DEBUG, "imip_send(%s)", recipient);

    /* if no notifier, fall back to sendmail */
    if (!notifier) {
        return imip_send_sendmail(userid, sched_data->itip,
                                  sender, recipient,
                                  sched_data->is_update);
    }

    json_t *jsevent, *patch;

#ifdef WITH_JMAP
    if (sched_data->oldical) {
        jsevent = jmapical_tojmap(sched_data->oldical, NULL);

        if (sched_data->newical) {
            /* Updated event */
            json_t *new_jsevent = jmapical_tojmap(sched_data->newical, NULL);

            patch = jmap_patchobject_create(jsevent, new_jsevent);
            json_decref(new_jsevent);
        }
        else {
            /* Canceled event */
            patch = json_null();
        }
    }
    else {
        /* New event */
        jsevent = json_null();
        patch = jmapical_tojmap(sched_data->newical, NULL);
    }
#else
    jsevent = json_null();
    patch = json_null();
#endif

    /* Don't send a bogus message - check late to not allocate our own copy */
    const char *ical_str = icalcomponent_as_ical_string(sched_data->itip);
    if (!ical_str) return 0;

    json_t *val = json_pack("{s:s s:s s:s s:o s:o s:b}",
                            "recipient", recipient,
                            "sender", sender,
                            "ical", ical_str,
                            "jsevent", jsevent,
                            "patch", patch,
                            "is_update", sched_data->is_update);
    char *serial = json_dumps(val, JSON_COMPACT);
    notify(notifier, "IMIP", NULL, userid, NULL, 0, NULL, serial, NULL);
    free(serial);
    json_decref(val);

    return 0;
}


/* Add a <response> XML element for 'recipient' to 'root' */
xmlNodePtr xml_add_schedresponse(xmlNodePtr root, xmlNsPtr dav_ns,
                                 xmlChar *recipient, xmlChar *status)
{
    xmlNodePtr resp, recip;

    resp = xmlNewChild(root, NULL, BAD_CAST "response", NULL);
    recip = xmlNewChild(resp, NULL, BAD_CAST "recipient", NULL);

    if (dav_ns) xml_add_href(recip, dav_ns, (const char *) recipient);
    else xmlNodeAddContent(recip, recipient);

    if (status)
        xmlNewChild(resp, NULL, BAD_CAST "request-status", status);

    return resp;
}


struct remote_rock {
    struct transaction_t *txn;
    icalcomponent *ical;
    xmlNodePtr root;
    xmlNsPtr *ns;
};

/* Send an iTIP busytime request to remote attendees via iMIP or iSchedule */
static void busytime_query_remote(const char *server __attribute__((unused)),
                                  void *data, void *rock)
{
    struct caldav_sched_param *remote = (struct caldav_sched_param *) data;
    struct remote_rock *rrock = (struct remote_rock *) rock;
    icalcomponent *comp;
    struct proplist *list;
    xmlNodePtr resp;
    const char *status = NULL;
    int r;

    syslog(LOG_DEBUG, "busytime_query_remote(server: '%s', flags: 0x%x)",
           server, remote->flags);

    comp = icalcomponent_get_first_real_component(rrock->ical);

    /* Add the attendees to the iTIP request */
    for (list = remote->props; list; list = list->next) {
        icalcomponent_add_property(comp, list->prop);
    }

    if (remote->flags == SCHEDTYPE_REMOTE) {
        /* Use iMIP -
           don't bother sending, its not very useful and not well supported */
        status = REQSTAT_TEMPFAIL;
    }
    else {
        /* Use iSchedule */
        xmlNodePtr xml;

        r = isched_send(remote, NULL, rrock->ical, &xml);
        if (r) status = REQSTAT_TEMPFAIL;
        else if (xmlStrcmp(xml->name, BAD_CAST "schedule-response")) {
            if (r) status = REQSTAT_TEMPFAIL;
        }
        else {
            xmlNodePtr cur;

            /* Process each response element */
            for (cur = xml->children; cur; cur = cur->next) {
                xmlNodePtr node;
                xmlChar *recip = NULL, *status = NULL, *content = NULL;

                if (cur->type != XML_ELEMENT_NODE) continue;

                for (node = cur->children; node; node = node->next) {
                    if (node->type != XML_ELEMENT_NODE) continue;

                    if (!xmlStrcmp(node->name, BAD_CAST "recipient"))
                        recip = xmlNodeGetContent(node);
                    else if (!xmlStrcmp(node->name, BAD_CAST "request-status"))
                        status = xmlNodeGetContent(node);
                    else if (!xmlStrcmp(node->name, BAD_CAST "calendar-data"))
                        content = xmlNodeGetContent(node);
                }

                resp =
                    xml_add_schedresponse(rrock->root,
                                          !(rrock->txn->req_tgt.allow & ALLOW_ISCHEDULE) ?
                                          rrock->ns[NS_DAV] : NULL,
                                          recip, status);

                xmlFree(status);
                xmlFree(recip);

                if (content) {
                    xmlNodePtr cdata =
                        xmlNewTextChild(resp, NULL,
                                        BAD_CAST "calendar-data", NULL);
                    xmlAddChild(cdata,
                                xmlNewCDataBlock(rrock->root->doc,
                                                 content,
                                                 xmlStrlen(content)));
                    xmlFree(content);

                    /* iCal data in resp SHOULD NOT be transformed */
                    rrock->txn->flags.cc |= CC_NOTRANSFORM;
                }
            }

            xmlFreeDoc(xml->doc);
        }
    }

    /* Report request-status (if necessary)
     * Remove the attendees from the iTIP request and hash bucket
     */
    for (list = remote->props; list; list = list->next) {
        if (status) {
            const char *attendee = icalproperty_get_attendee(list->prop);
            xml_add_schedresponse(rrock->root,
                                  !(rrock->txn->req_tgt.allow & ALLOW_ISCHEDULE) ?
                                  rrock->ns[NS_DAV] : NULL,
                                  BAD_CAST attendee,
                                  BAD_CAST status);
        }

        icalcomponent_remove_property(comp, list->prop);
        icalproperty_free(list->prop);
    }

    if (remote->server) free(remote->server);
}


static void sched_param_cleanup(void *data)
{
    struct caldav_sched_param *sparam = (struct caldav_sched_param *) data;

    if (sparam) {
        sched_param_fini(sparam);
        free(sparam);
    }
}


/* Perform a Busy Time query based on given VFREEBUSY component */
/* NOTE: This function is destructive of 'ical' */
int sched_busytime_query(struct transaction_t *txn,
                         struct mime_type_t *mime, icalcomponent *ical)
{
    int ret = 0;
    static const char *calendarprefix = NULL;
    icalcomponent *comp;
    icalproperty *prop = NULL, *next;
    const char *uid = NULL, *organizer = NULL;
    struct caldav_sched_param sparam;
    struct auth_state *org_authstate = NULL;
    xmlNodePtr root = NULL;
    xmlNsPtr ns[NUM_NAMESPACE];
    struct propfind_ctx fctx;
    struct freebusy_filter calfilter;
    struct hash_table remote_table;
    struct caldav_sched_param *remote = NULL;

    if (!calendarprefix) {
        calendarprefix = config_getstring(IMAPOPT_CALENDARPREFIX);
    }

    comp = icalcomponent_get_first_real_component(ical);
    uid = icalcomponent_get_uid(comp);

    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    organizer = icalproperty_get_organizer(prop);

    /* XXX  Do we need to do more checks here? */
    if (caladdress_lookup(organizer, &sparam, NULL) ||
        (sparam.flags & SCHEDTYPE_REMOTE))
        org_authstate = auth_newstate("anonymous");
    else
        org_authstate = auth_newstate(sparam.userid);

    sched_param_fini(&sparam);

    /* Start construction of our schedule-response */
    if (!(root =
          init_xml_response("schedule-response",
                            (txn->req_tgt.allow & ALLOW_ISCHEDULE) ? NS_ISCHED :
                            NS_CALDAV, NULL, ns))) {
        ret = HTTP_SERVER_ERROR;
        txn->error.desc = "Unable to create XML response";
        goto done;
    }

    /* Need DAV for hrefs */
    ensure_ns(ns, NS_DAV, root, XML_NS_DAV, "D");

    /* Populate our filter and propfind context for local attendees */
    memset(&calfilter, 0, sizeof(struct freebusy_filter));
    calfilter.start = icalcomponent_get_dtstart(comp);
    calfilter.end = icalcomponent_get_dtend(comp);
    calfilter.flags = CHECK_CAL_TRANSP | CHECK_USER_AVAIL;

    memset(&fctx, 0, sizeof(struct propfind_ctx));
    fctx.txn = txn;
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = 2;
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = org_authstate;
    fctx.reqd_privs = 0;  /* handled by CALDAV:schedule-deliver on Inbox */
    fctx.filter_crit = &calfilter;
    fctx.ret = &ret;

    /* Create hash table for any remote attendee servers */
    construct_hash_table(&remote_table, 10, 1);

    /* Process each attendee */
    for (prop = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);
         prop;
         prop = next) {
        const char *attendee;
        int r;

        next = icalcomponent_get_next_property(comp, ICAL_ATTENDEE_PROPERTY);

        /* Remove each attendee so we can add in only those
           that reside on a given remote server later */
        icalcomponent_remove_property(comp, prop);

        /* Is attendee remote or local? */
        attendee = icalproperty_get_attendee(prop);
        r = caladdress_lookup(attendee, &sparam, NULL);

        /* Don't allow scheduling of remote users via an iSchedule request */
        if ((sparam.flags & SCHEDTYPE_REMOTE) &&
            (txn->req_tgt.allow & ALLOW_ISCHEDULE)) {
            r = HTTP_FORBIDDEN;
        }

        if (r) {
            xml_add_schedresponse(root,
                                  !(txn->req_tgt.allow & ALLOW_ISCHEDULE) ?
                                  ns[NS_DAV] : NULL,
                                  BAD_CAST attendee, BAD_CAST REQSTAT_NOUSER);

            icalproperty_free(prop);
        }
        else if (sparam.flags) {
            /* Remote attendee */
            struct proplist *newprop;
            const char *key;

            if (sparam.flags == SCHEDTYPE_REMOTE) {
                /* iMIP - collect attendees under empty key (no server) */
                key = "";
            }
            else {
                /* iSchedule - collect attendees by server */
                key = sparam.server;
            }

            remote = hash_lookup(key, &remote_table);
            if (!remote) {
                /* New remote - add it to the hash table */
                remote = xzmalloc(sizeof(struct caldav_sched_param));
                if (sparam.server) remote->server = xstrdup(sparam.server);
                remote->port = sparam.port;
                remote->flags = sparam.flags;
                hash_insert(key, remote, &remote_table);
            }
            newprop = xmalloc(sizeof(struct proplist));
            newprop->prop = prop;
            newprop->next = remote->props;
            remote->props = newprop;
        }
        else {
            /* Local attendee on this server */
            xmlNodePtr resp;
            const char *userid = sparam.userid;
            icalcomponent *busy = NULL;
            mbentry_t *mbentry = NULL;
            const char *status = REQSTAT_NOUSER;

            resp =
                xml_add_schedresponse(root,
                                      !(txn->req_tgt.allow & ALLOW_ISCHEDULE) ?
                                      ns[NS_DAV] : NULL,
                                      BAD_CAST attendee, NULL);

            /* Check ACL of ORGANIZER on attendee's Scheduling Inbox */
            char *inboxname = caldav_mboxname(userid, SCHED_INBOX);

            r = mboxlist_lookup(inboxname, &mbentry, NULL);
            if (r) {
                syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
                       inboxname, error_message(r));
                status = REQSTAT_REJECTED;
            }
            else if (!(httpd_myrights(org_authstate, mbentry) & DACL_SCHEDFB)) {
                status = REQSTAT_NOPRIVS;
            }
            else {
                /* Start query at attendee's calendar-home-set */
                char *mboxname = caldav_mboxname(userid, NULL);

                fctx.davdb = NULL;
                fctx.req_tgt->collection = NULL;
                calfilter.freebusy.len = 0;
                busy = busytime_query_local(txn, &fctx, mboxname,
                                            ICAL_METHOD_REPLY, uid,
                                            organizer, attendee);
                free(mboxname);
            }
            mboxlist_entry_free(&mbentry);
            free(inboxname);

            if (busy) {
                xmlNodePtr cdata;
                struct buf *fb_str = mime->from_object(busy);
                icalcomponent_free(busy);

                xmlNewChild(resp, NULL, BAD_CAST "request-status",
                            BAD_CAST REQSTAT_SUCCESS);

                cdata = xmlNewTextChild(resp, NULL,
                                        BAD_CAST "calendar-data", NULL);

                /* Trim any charset from content-type */
                buf_reset(&txn->buf);
                buf_printf(&txn->buf, "%.*s",
                           (int) strcspn(mime->content_type, ";"),
                           mime->content_type);

                xmlNewProp(cdata, BAD_CAST "content-type",
                           BAD_CAST buf_cstring(&txn->buf));

                if (mime->version)
                    xmlNewProp(cdata, BAD_CAST "version",
                               BAD_CAST mime->version);

                xmlAddChild(cdata,
                            xmlNewCDataBlock(root->doc,
                                             BAD_CAST buf_base(fb_str),
                                             buf_len(fb_str)));
                buf_destroy(fb_str);

                /* iCalendar data in response should not be transformed */
                txn->flags.cc |= CC_NOTRANSFORM;
            }
            else {
                xmlNewChild(resp, NULL, BAD_CAST "request-status",
                            BAD_CAST status);
            }

            icalproperty_free(prop);
        }

        sched_param_fini(&sparam);
    }

    buf_reset(&txn->buf);

    if (remote) {
        struct remote_rock rrock = { txn, ical, root, ns };
        hash_enumerate(&remote_table, busytime_query_remote, &rrock);
    }
    free_hash_table(&remote_table, sched_param_cleanup);

    /* Output the XML response */
    if (!ret) xml_response(HTTP_OK, txn, root->doc);

  done:
    if (org_authstate) auth_freestate(org_authstate);
    if (calfilter.freebusy.fb) free(calfilter.freebusy.fb);
    if (root) xmlFreeDoc(root->doc);

    return ret;
}



#define SCHEDSTAT_PENDING       "1.0"
#define SCHEDSTAT_SENT          "1.1"
#define SCHEDSTAT_DELIVERED     "1.2"
#define SCHEDSTAT_SUCCESS       "2.0"
#define SCHEDSTAT_PARAM         "2.3"
#define SCHEDSTAT_NOUSER        "3.7"
#define SCHEDSTAT_NOPRIVS       "3.8"
#define SCHEDSTAT_TEMPFAIL      "5.1"
#define SCHEDSTAT_PERMFAIL      "5.2"
#define SCHEDSTAT_REJECTED      "5.3"

/* Deliver scheduling object to a remote recipient */
static void sched_deliver_remote(const char *userid,
                                 const char *sender, const char *recipient,
                                 struct caldav_sched_param *sparam,
                                 struct sched_data *sched_data)
{
    int r;

    syslog(LOG_DEBUG, "sched_deliver_remote(%s, %X)", recipient, sparam->flags);

    icalcomponent_add_required_timezones(sched_data->itip);

    if (sparam->flags & SCHEDTYPE_ISCHEDULE) {
        /* Use iSchedule */
        xmlNodePtr xml;

        r = isched_send(sparam, recipient, sched_data->itip, &xml);
        if (r) {
            sched_data->status = sched_data->ischedule ?
                REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
        }
        else if (xmlStrcmp(xml->name, BAD_CAST "schedule-response")) {
            sched_data->status = sched_data->ischedule ?
                REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
        }
        else {
            xmlNodePtr cur;

            /* Process each response element */
            for (cur = xml->children; cur; cur = cur->next) {
                xmlNodePtr node;
                xmlChar *recip = NULL, *status = NULL;
                static char statbuf[1024];

                if (cur->type != XML_ELEMENT_NODE) continue;

                for (node = cur->children; node; node = node->next) {
                    if (node->type != XML_ELEMENT_NODE) continue;

                    if (!xmlStrcmp(node->name, BAD_CAST "recipient"))
                        recip = xmlNodeGetContent(node);
                    else if (!xmlStrcmp(node->name,
                                        BAD_CAST "request-status"))
                        status = xmlNodeGetContent(node);
                }

                if (!strncmp((const char *) status, "2.0", 3)) {
                    sched_data->status = sched_data->ischedule ?
                        REQSTAT_DELIVERED : SCHEDSTAT_DELIVERED;
                }
                else {
                    if (sched_data->ischedule)
                        strlcpy(statbuf, (const char *) status, sizeof(statbuf));
                    else
                        strlcpy(statbuf, (const char *) status, 4);

                    sched_data->status = statbuf;
                }

                xmlFree(status);
                xmlFree(recip);
            }
        }
    }
    else {
        r = imip_send(userid, sched_data, sender, recipient);
        if (!r) {
            sched_data->status =
                sched_data->ischedule ? REQSTAT_SENT : SCHEDSTAT_SENT;
        }
        else {
            sched_data->status = sched_data->ischedule ?
                REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
        }
    }
}


/*
 * deliver_merge_reply() helper function
 *
 * Merge VOTER responses into VPOLL subcomponents
 */
static void deliver_merge_vpoll_reply(icalcomponent *ical, icalcomponent *reply)
{
    icalcomponent *new_ballot, *vvoter;
    icalproperty *voterp;
    const char *voter;

    /* Get VOTER from reply */
    new_ballot =
        icalcomponent_get_first_component(reply, ICAL_VVOTER_COMPONENT);
    voterp = icalcomponent_get_first_property(new_ballot, ICAL_VOTER_PROPERTY);
    voter = icalproperty_get_voter(voterp);

    /* Locate VOTER in existing VPOLL */
    for (vvoter =
           icalcomponent_get_first_component(ical, ICAL_VVOTER_COMPONENT);
         vvoter;
         vvoter =
             icalcomponent_get_next_component(ical, ICAL_VVOTER_COMPONENT)) {

        voterp =
            icalcomponent_get_first_property(vvoter, ICAL_VOTER_PROPERTY);

        if (!strcmp(voter, icalproperty_get_voter(voterp))) {
            icalcomponent_remove_component(ical, vvoter);
            icalcomponent_free(vvoter);
            break;
        }
    }

    /* XXX  Actually need to compare POLL-ITEM-IDs */
    icalcomponent_add_component(ical, icalcomponent_clone(new_ballot));
}


/* sched_reply() helper function
 *
 * Add voter responses to VPOLL reply and remove candidate components
 *
 */
static void sched_vpoll_reply(icalcomponent *poll)
{
    icalcomponent *item, *next;

    for (item = icalcomponent_get_first_component(poll, ICAL_ANY_COMPONENT);
         item;
         item = next) {

        next = icalcomponent_get_next_component(poll, ICAL_ANY_COMPONENT);

        switch (icalcomponent_isa(item)) {
        case ICAL_VVOTER_COMPONENT:
            /* Our ballot, leave it */
            /* XXX  Need to compare against previous votes */
            break;

        default:
            /* Candidate component, remove it */
            icalcomponent_remove_component(poll, item);
            icalcomponent_free(item);
            break;
        }
    }
}


static int deliver_merge_pollstatus(icalcomponent *ical, icalcomponent *request)
{
    int deliver_inbox = 0;
    icalcomponent *oldpoll, *newpoll, *vvoter, *next;

    /* Remove each VVOTER from old object */
    oldpoll =
        icalcomponent_get_first_component(ical, ICAL_VPOLL_COMPONENT);
    for (vvoter =
             icalcomponent_get_first_component(oldpoll, ICAL_VVOTER_COMPONENT);
         vvoter;
         vvoter = next) {

        next = icalcomponent_get_next_component(oldpoll, ICAL_VVOTER_COMPONENT);

        icalcomponent_remove_component(oldpoll, vvoter);
        icalcomponent_free(vvoter);
    }

    /* Add each VVOTER in the iTIP request to old object */
    newpoll = icalcomponent_get_first_component(request, ICAL_VPOLL_COMPONENT);
    for (vvoter =
             icalcomponent_get_first_component(newpoll, ICAL_VVOTER_COMPONENT);
         vvoter;
         vvoter =
             icalcomponent_get_next_component(newpoll, ICAL_VVOTER_COMPONENT)) {

        icalcomponent_add_component(oldpoll, icalcomponent_clone(vvoter));
    }

    return deliver_inbox;
}


static void sched_pollstatus(const char *organizer,
                             struct caldav_sched_param *sparam, icalcomponent *ical,
                             const char *voter)
{
    struct auth_state *authstate;
    struct sched_data sched_data;
    icalcomponent *itip, *comp;
    icalproperty *prop;
    const char *userid = httpd_userid;

    /* XXX  Do we need to do more checks here? */
    if (sparam->flags & SCHEDTYPE_REMOTE)
        authstate = auth_newstate("anonymous");
    else
        authstate = auth_newstate(sparam->userid);

    memset(&sched_data, 0, sizeof(struct sched_data));
    sched_data.force_send = ICAL_SCHEDULEFORCESEND_NONE;

    /* Create a shell for our iTIP request objects */
    itip = icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT,
                               icalproperty_new_version("2.0"),
                               icalproperty_new_prodid(ical_prodid),
                               icalproperty_new_method(ICAL_METHOD_POLLSTATUS),
                               0);

    /* Copy over any CALSCALE property */
    prop = icalcomponent_get_first_property(ical, ICAL_CALSCALE_PROPERTY);
    if (prop) icalcomponent_add_property(itip, icalproperty_clone(prop));

    /* Process each VPOLL in resource */
    for (comp = icalcomponent_get_first_component(ical, ICAL_VPOLL_COMPONENT);
         comp;
         comp =icalcomponent_get_next_component(ical, ICAL_VPOLL_COMPONENT)) {

        icalcomponent *stat, *poll, *sub, *next;
        strarray_t voters = STRARRAY_INITIALIZER;
        int i;

        /* Make a working copy of the iTIP */
        stat = icalcomponent_clone(itip);

        /* Make a working copy of the VPOLL and add to pollstatus */
        poll = icalcomponent_clone(comp);
        icalcomponent_add_component(stat, poll);

        /* Process each sub-component of VPOLL */
        for (sub = icalcomponent_get_first_component(poll, ICAL_ANY_COMPONENT);
             sub; sub = next) {

            next = icalcomponent_get_next_component(poll, ICAL_ANY_COMPONENT);

            switch (icalcomponent_isa(sub)) {
            case ICAL_VVOTER_COMPONENT: {
                /* Make list of VOTERs (stripping SCHEDULE-STATUS) */
                const char *this_voter;

                prop =
                    icalcomponent_get_first_property(sub, ICAL_VOTER_PROPERTY);
                this_voter = icalproperty_get_voter(prop);

                /* Don't update organizer or voter that triggered POLLSTATUS */
                if (strcmp(this_voter, organizer) && strcmp(this_voter, voter))
                    strarray_append(&voters, this_voter);

                icalproperty_remove_parameter_by_name(prop, "SCHEDULE-STATUS");
                break;
            }

            default:
                /* Remove candidate components */
                icalcomponent_remove_component(poll, sub);
                icalcomponent_free(sub);
                break;
            }
        }

        /* Attempt to deliver to each voter in the list - removing as we go */
        for (i = 0; i < strarray_size(&voters); i++) {
            const char *voter = strarray_nth(&voters, i);

            sched_data.itip = stat;
            sched_deliver(userid, organizer, voter, &sched_data, authstate);
        }

        strarray_fini(&voters);
        icalcomponent_free(stat);
    }

    icalcomponent_free(itip);
    auth_freestate(authstate);
}

/* annoying copypaste from libical because it's not exposed */
static struct icaltimetype _get_datetime(icalcomponent *comp, icalproperty *prop)
{
    icalcomponent *c;
    icalparameter *param;
    struct icaltimetype ret;

    ret = icalvalue_get_datetime(icalproperty_get_value(prop));

    if ((param = icalproperty_get_first_parameter(prop, ICAL_TZID_PARAMETER)) != NULL) {
        const char *tzid = icalparameter_get_tzid(param);
        icaltimezone *tz = NULL;

        for (c = comp; c != NULL; c = icalcomponent_get_parent(c)) {
            tz = icalcomponent_get_timezone(c, tzid);
            if (tz != NULL)
                break;
        }

        if (tz == NULL)
            tz = icaltimezone_get_builtin_timezone_from_tzid(tzid);

        if (tz != NULL)
            ret = icaltime_set_timezone(&ret, tz);
    }

    return ret;
}


static icalcomponent *master_to_recurrence(icalcomponent *master, icalproperty *recurid)
{
    icalproperty *prop, *next;

    icalproperty *endprop = NULL;
    icalproperty *startprop = NULL;

    icalcomponent *comp = icalcomponent_clone(master);

    for (prop = icalcomponent_get_first_property(comp, ICAL_ANY_PROPERTY);
         prop; prop = next) {
        next = icalcomponent_get_next_property(comp, ICAL_ANY_PROPERTY);

        switch (icalproperty_isa(prop)) {
            /* extract start and end for later processing */
        case ICAL_DTEND_PROPERTY:
            endprop = prop;
            break;

        case ICAL_DTSTART_PROPERTY:
            startprop = prop;
            break;

            /* Remove all recurrence properties */
        case ICAL_RRULE_PROPERTY:
        case ICAL_RDATE_PROPERTY:
        case ICAL_EXDATE_PROPERTY:
            icalcomponent_remove_property(comp, prop);
            icalproperty_free(prop);
            break;

        default:
            break;
        }
    }

    /* Add RECURRENCE-ID */
    icalcomponent_add_property(comp, icalproperty_clone(recurid));

    /* calculate a new dtend based on recurid */
    struct icaltimetype start = _get_datetime(master, startprop);
    struct icaltimetype newstart = _get_datetime(master, recurid);

    icaltimezone *startzone = (icaltimezone *)icaltime_get_timezone(start);
    icalcomponent_set_dtstart(comp, icaltime_convert_to_zone(newstart, startzone));

    if (endprop) {
        struct icaltimetype end = _get_datetime(master, endprop);

        // calculate and re-apply the diff
        struct icaldurationtype diff = icaltime_subtract(end, start);
        struct icaltimetype newend = icaltime_add(newstart, diff);

        icaltimezone *endzone = (icaltimezone *)icaltime_get_timezone(end);
        icalcomponent_set_dtend(comp, icaltime_convert_to_zone(newend, endzone));
    }
    /* otherwise it will be a duration, which is still valid! */

    return comp;
}


static const char *deliver_merge_reply(icalcomponent *ical,
                                       icalcomponent *reply)
{
    struct hash_table comp_table;
    icalcomponent *comp, *itip, *master = NULL;
    icalcomponent_kind kind;
    icalproperty *prop, *att;
    icalparameter *param;
    icalparameter_partstat partstat = ICAL_PARTSTAT_NONE;
    icalparameter_rsvp rsvp = ICAL_RSVP_NONE;
    const char *recurid, *attendee = NULL, *req_stat = SCHEDSTAT_SUCCESS;

    /* Add each component of old object to hash table for comparison */
    construct_hash_table(&comp_table, 10, 1);
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);
    do {
        prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (prop) recurid = icalproperty_get_value_as_string(prop);
        else {
            master = comp;
            recurid = "";
        }

        hash_insert(recurid, comp, &comp_table);

    } while ((comp = icalcomponent_get_next_component(ical, kind)));


    /* Process each component in the iTIP reply */
    for (itip = icalcomponent_get_first_component(reply, kind);
         itip;
         itip = icalcomponent_get_next_component(reply, kind)) {

        /* Lookup this comp in the hash table */
        prop =
            icalcomponent_get_first_property(itip, ICAL_RECURRENCEID_PROPERTY);
        if (prop) recurid = icalproperty_get_value_as_string(prop);
        else recurid = "";

        comp = hash_lookup(recurid, &comp_table);
        if (!comp) {
            /* New recurrence overridden by attendee. */
            if (icalcomponent_get_status(master) == ICAL_STATUS_CANCELLED) {
                /* The master event has been cancelled - ignore this override. */
                continue;
            }

            /* create a new recurrence from master component. */
            comp = master_to_recurrence(master, prop);

            /* Replace DTSTART, DTEND, SEQUENCE */
            prop =
                icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY);
            if (prop) {
                icalcomponent_remove_property(comp, prop);
                icalproperty_free(prop);
            }
            prop =
                icalcomponent_get_first_property(itip, ICAL_DTSTART_PROPERTY);
            if (prop)
                icalcomponent_add_property(comp, icalproperty_clone(prop));

            prop =
                icalcomponent_get_first_property(comp, ICAL_DTEND_PROPERTY);
            if (prop) {
                icalcomponent_remove_property(comp, prop);
                icalproperty_free(prop);
            }
            prop =
                icalcomponent_get_first_property(itip, ICAL_DTEND_PROPERTY);
            if (prop)
                icalcomponent_add_property(comp, icalproperty_clone(prop));

            prop =
                icalcomponent_get_first_property(comp, ICAL_SEQUENCE_PROPERTY);
            if (prop) {
                icalcomponent_remove_property(comp, prop);
                icalproperty_free(prop);
            }
            prop =
                icalcomponent_get_first_property(itip, ICAL_SEQUENCE_PROPERTY);
            if (prop)
                icalcomponent_add_property(comp, icalproperty_clone(prop));

            icalcomponent_add_component(ical, comp);
        }
        else if (icalcomponent_get_status(comp) == ICAL_STATUS_CANCELLED) {
            /* This component has been cancelled - ignore the reply */
            continue;
        }

        /* Get the sending attendee */
        att = icalcomponent_get_first_invitee(itip);
        attendee = icalproperty_get_invitee(att);
        param = icalproperty_get_first_parameter(att, ICAL_PARTSTAT_PARAMETER);
        if (param) partstat = icalparameter_get_partstat(param);
        param = icalproperty_get_first_parameter(att, ICAL_RSVP_PARAMETER);
        if (param) rsvp = icalparameter_get_rsvp(param);

        prop =
            icalcomponent_get_first_property(itip, ICAL_REQUESTSTATUS_PROPERTY);
        if (prop) {
            struct icalreqstattype rq = icalproperty_get_requeststatus(prop);
            req_stat = icalenum_reqstat_code(rq.code);
        }

        /* Find matching attendee in existing object */
        for (prop = icalcomponent_get_first_invitee(comp);
             prop && strcmp(attendee, icalproperty_get_invitee(prop));
             prop = icalcomponent_get_next_invitee(comp));
        if (!prop) {
            /* Attendee added themselves to this recurrence */
            assert(icalproperty_isa(prop) != ICAL_VOTER_PROPERTY);
            prop = icalproperty_clone(att);
            icalcomponent_add_property(comp, prop);
        }

        /* Set PARTSTAT */
        if (partstat != ICAL_PARTSTAT_NONE) {
            param = icalparameter_new_partstat(partstat);
            icalproperty_set_parameter(prop, param);
        }

        /* Set RSVP */
        icalproperty_remove_parameter_by_kind(prop, ICAL_RSVP_PARAMETER);
        if (rsvp != ICAL_RSVP_NONE) {
            param = icalparameter_new_rsvp(rsvp);
            icalproperty_add_parameter(prop, param);
        }

        /* Set SCHEDULE-STATUS */
        param = icalparameter_new_schedulestatus(req_stat);
        icalproperty_set_parameter(prop, param);

        /* Handle VPOLL reply */
        if (kind == ICAL_VPOLL_COMPONENT) deliver_merge_vpoll_reply(comp, itip);
    }

    free_hash_table(&comp_table, NULL);

    return attendee;
}


static int deliver_merge_request(const char *attendee,
                                 icalcomponent *ical, icalcomponent *request)
{
    int deliver_inbox = 0;
    struct hash_table comp_table;
    icalcomponent *comp, *itip;
    icalcomponent_kind kind = ICAL_NO_COMPONENT;
    icalproperty *prop;
    icalparameter *param;
    const char *tzid, *recurid, *organizer = NULL;

    /* Add each VTIMEZONE of old object to hash table for comparison */
    construct_hash_table(&comp_table, 10, 1);
    for (comp =
             icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
         comp;
         comp =
             icalcomponent_get_next_component(ical, ICAL_VTIMEZONE_COMPONENT)) {
        prop = icalcomponent_get_first_property(comp, ICAL_TZID_PROPERTY);
        tzid = icalproperty_get_tzid(prop);
        if (!tzid) continue;

        hash_insert(tzid, comp, &comp_table);
    }

    /* Process each VTIMEZONE in the iTIP request */
    for (itip = icalcomponent_get_first_component(request,
                                                  ICAL_VTIMEZONE_COMPONENT);
         itip;
         itip = icalcomponent_get_next_component(request,
                                                 ICAL_VTIMEZONE_COMPONENT)) {
        /* Lookup this TZID in the hash table */
        prop = icalcomponent_get_first_property(itip, ICAL_TZID_PROPERTY);
        tzid = icalproperty_get_tzid(prop);
        if (!tzid) continue;

        comp = hash_lookup(tzid, &comp_table);
        if (comp) {
            /* Remove component from old object */
            icalcomponent_remove_component(ical, comp);
            icalcomponent_free(comp);
        }

        /* Add new/modified component from iTIP request */
        icalcomponent_add_component(ical, icalcomponent_clone(itip));
    }

    free_hash_table(&comp_table, NULL);

    /* Add each component of old object to hash table for comparison */
    construct_hash_table(&comp_table, 10, 1);
    comp = icalcomponent_get_first_real_component(ical);
    if (comp) {
        kind = icalcomponent_isa(comp);
        organizer = get_organizer(comp);
    }
    for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
        prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (prop) recurid = icalproperty_get_value_as_string(prop);
        else recurid = "";

        hash_insert(recurid, comp, &comp_table);
    }

    /* Process each component in the iTIP request */
    itip = icalcomponent_get_first_real_component(request);
    if (kind == ICAL_NO_COMPONENT) kind = icalcomponent_isa(itip);
    for (; itip; itip = icalcomponent_get_next_component(request, kind)) {
        icalcomponent *new_comp = icalcomponent_clone(itip);

        /* Lookup this comp in the hash table */
        prop =
            icalcomponent_get_first_property(itip, ICAL_RECURRENCEID_PROPERTY);
        if (prop) recurid = icalproperty_get_value_as_string(prop);
        else recurid = "";

        comp = hash_lookup(recurid, &comp_table);
        if (comp) {
            int old_seq, new_seq;

            /* Check if this is something more than an update */
            /* XXX  Probably need to check PARTSTAT=NEEDS-ACTION
               and RSVP=TRUE as well */
            old_seq = icalcomponent_get_sequence(comp);
            new_seq = icalcomponent_get_sequence(itip);
            if (new_seq > old_seq) deliver_inbox = 1;
            else if (partstat_changed(comp, itip, organizer)) deliver_inbox = 1;

            /* Copy over any COMPLETED, PERCENT-COMPLETE,
               or TRANSP properties */
            prop =
                icalcomponent_get_first_property(comp, ICAL_COMPLETED_PROPERTY);
            if (prop) {
                icalcomponent_add_property(new_comp,
                                           icalproperty_clone(prop));
            }
            prop =
                icalcomponent_get_first_property(comp,
                                                 ICAL_PERCENTCOMPLETE_PROPERTY);
            if (prop) {
                icalcomponent_add_property(new_comp,
                                           icalproperty_clone(prop));
            }
            prop =
                icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
            if (prop) {
                icalcomponent_add_property(new_comp,
                                           icalproperty_clone(prop));
            }

            /* Copy over any ORGANIZER;SCHEDULE-STATUS */
            /* XXX  Do we only do this iff PARTSTAT!=NEEDS-ACTION */
            prop =
                icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
            param = icalproperty_get_schedulestatus_parameter(prop);
            if (param) {
                param = icalparameter_clone(param);
                prop =
                    icalcomponent_get_first_property(new_comp,
                                                     ICAL_ORGANIZER_PROPERTY);
                icalproperty_add_parameter(prop, param);
            }

            /* Remove component from old object */
            icalcomponent_remove_component(ical, comp);
            icalcomponent_free(comp);
        }
        else {
            /* New component */
            deliver_inbox = 1;
        }

        if (config_allowsched == IMAP_ENUM_CALDAV_ALLOWSCHEDULING_APPLE &&
            kind == ICAL_VEVENT_COMPONENT) {
            /* Make VEVENT component transparent if recipient ATTENDEE
               PARTSTAT=NEEDS-ACTION (for compatibility with CalendarServer) */
            for (prop =
                     icalcomponent_get_first_property(new_comp,
                                                      ICAL_ATTENDEE_PROPERTY);
                 prop && strcmp(icalproperty_get_attendee(prop), attendee);
                 prop =
                     icalcomponent_get_next_property(new_comp,
                                                     ICAL_ATTENDEE_PROPERTY));
            param =
                icalproperty_get_first_parameter(prop, ICAL_PARTSTAT_PARAMETER);
            if (param &&
                icalparameter_get_partstat(param) ==
                ICAL_PARTSTAT_NEEDSACTION) {
                prop =
                    icalcomponent_get_first_property(new_comp,
                                                     ICAL_TRANSP_PROPERTY);
                if (prop)
                    icalproperty_set_transp(prop, ICAL_TRANSP_TRANSPARENT);
                else {
                    prop = icalproperty_new_transp(ICAL_TRANSP_TRANSPARENT);
                    icalcomponent_add_property(new_comp, prop);
                }
            }
        }

        /* Add new/modified component from iTIP request */
        icalcomponent_add_component(ical, new_comp);
    }

    free_hash_table(&comp_table, NULL);

    return deliver_inbox;
}


/* Deliver scheduling object to local recipient */
static void sched_deliver_local(const char *userid,
                                const char *sender, const char *recipient,
                                struct caldav_sched_param *sparam,
                                struct sched_data *sched_data,
                                struct auth_state *authstate)
{
    int r = 0, rights, reqd_privs, deliver_inbox = 1;
    const char *attendee = NULL;
    static struct buf resource = BUF_INITIALIZER;
    char *mailboxname = NULL;
    mbentry_t *mbentry = NULL;
    struct mailbox *mailbox = NULL, *inbox = NULL;
    struct caldav_db *caldavdb = NULL;
    struct caldav_data *cdata;
    icalcomponent *ical = NULL;
    icalproperty_method method;
    icalcomponent_kind kind;
    icalcomponent *comp;
    icalproperty *prop;
    struct transaction_t txn;

    syslog(LOG_DEBUG, "sched_deliver_local(%s, %s, %X)", sender, recipient, sparam->flags);

    /* Start with an empty (clean) transaction */
    memset(&txn, 0, sizeof(struct transaction_t));

    /* Check ACL of sender on recipient's Scheduling Inbox */
    mailboxname = caldav_mboxname(sparam->userid, SCHED_INBOX);
    r = mboxlist_lookup(mailboxname, &mbentry, NULL);
    if (r) {
        syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
               mailboxname, error_message(r));
        sched_data->status =
            sched_data->ischedule ? REQSTAT_REJECTED : SCHEDSTAT_REJECTED;
        goto done;
    }

    rights = httpd_myrights(authstate, mbentry);
    mboxlist_entry_free(&mbentry);

    reqd_privs = sched_data->is_reply ? DACL_REPLY : DACL_INVITE;
    if (!(rights & reqd_privs)) {
        sched_data->status =
            sched_data->ischedule ? REQSTAT_NOPRIVS : SCHEDSTAT_NOPRIVS;
        syslog(LOG_DEBUG, "No scheduling receive ACL for user %s on Inbox %s",
               httpd_userid, sparam->userid);
        goto done;
    }

    /* Open recipient's Inbox for writing */
    if ((r = mailbox_open_iwl(mailboxname, &inbox))) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
               mailboxname, error_message(r));
        sched_data->status =
            sched_data->ischedule ? REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
        goto done;
    }
    free(mailboxname);
    mailboxname = NULL;

    /* Get METHOD of the iTIP message */
    method = icalcomponent_get_method(sched_data->itip);

    /* Search for iCal UID in recipient's calendars */
    caldavdb = caldav_open_userid(sparam->userid);
    if (!caldavdb) {
        sched_data->status =
            sched_data->ischedule ? REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
        goto done;
    }

    caldav_lookup_uid(caldavdb,
                      icalcomponent_get_uid(sched_data->itip), &cdata);

    if (cdata->dav.mailbox) {
        if (cdata->dav.mailbox_byname)
            mailboxname = xstrdup(cdata->dav.mailbox);
        else {
            mboxlist_lookup_by_uniqueid(cdata->dav.mailbox, &mbentry, NULL);
            if (!mbentry) {
                sched_data->status = sched_data->ischedule ?
                    REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
                goto done;
            }
            mailboxname = xstrdup(mbentry->name);
            mboxlist_entry_free(&mbentry);
        }
        buf_setcstr(&resource, cdata->dav.resource);
    }
    else if (sched_data->is_reply) {
        /* Can't find object belonging to organizer - ignore reply */
        sched_data->status =
            sched_data->ischedule ? REQSTAT_PERMFAIL : SCHEDSTAT_PERMFAIL;
        goto done;
    }
    else if (method == ICAL_METHOD_CANCEL || method == ICAL_METHOD_POLLSTATUS) {
        /* Can't find object belonging to attendee - we're done */
        sched_data->status =
            sched_data->ischedule ? REQSTAT_SUCCESS : SCHEDSTAT_DELIVERED;
        goto done;
    }
    else {
        /* Can't find object belonging to attendee - use default calendar */
        char *scheddefault = caldav_scheddefault(sparam->userid);
        mailboxname = caldav_mboxname(sparam->userid, scheddefault);
        free(scheddefault);
        buf_reset(&resource);
        /* XXX - sanitize the uid? */
        buf_printf(&resource, "%s.ics",
                   icalcomponent_get_uid(sched_data->itip));

        /* Create new attendee object */
        ical = icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT, 0);

        /* Copy over VERSION property */
        prop = icalcomponent_get_first_property(sched_data->itip,
                                                ICAL_VERSION_PROPERTY);
        icalcomponent_add_property(ical, icalproperty_clone(prop));

        /* Copy over PRODID property */
        prop = icalcomponent_get_first_property(sched_data->itip,
                                                ICAL_PRODID_PROPERTY);
        icalcomponent_add_property(ical, icalproperty_clone(prop));

        /* Copy over any CALSCALE property */
        prop = icalcomponent_get_first_property(sched_data->itip,
                                                ICAL_CALSCALE_PROPERTY);
        if (prop) {
            icalcomponent_add_property(ical,
                                       icalproperty_clone(prop));
        }
    }

    /* Open recipient's calendar for writing */
    r = mailbox_open_iwl(mailboxname, &mailbox);
    if (r) {
        syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
               mailboxname, error_message(r));
        sched_data->status =
            sched_data->ischedule ? REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
        goto done;
    }

    if (cdata->dav.imap_uid) {
        /* Load message containing the resource and parse iCal data */
        ical = caldav_record_to_ical(mailbox, cdata, NULL, NULL);

        for (comp = icalcomponent_get_first_component(sched_data->itip,
                                                      ICAL_ANY_COMPONENT);
             comp;
             comp = icalcomponent_get_next_component(sched_data->itip,
                                                     ICAL_ANY_COMPONENT)) {
            /* Don't allow component type to be changed */
            int reject = 0;
            kind = icalcomponent_isa(comp);
            switch (kind) {
            case ICAL_VEVENT_COMPONENT:
                if (cdata->comp_type != CAL_COMP_VEVENT) reject = 1;
                break;
            case ICAL_VTODO_COMPONENT:
                if (cdata->comp_type != CAL_COMP_VTODO) reject = 1;
                break;
            case ICAL_VJOURNAL_COMPONENT:
                if (cdata->comp_type != CAL_COMP_VJOURNAL) reject = 1;
                break;
            case ICAL_VFREEBUSY_COMPONENT:
                if (cdata->comp_type != CAL_COMP_VFREEBUSY) reject = 1;
                break;
            case ICAL_VAVAILABILITY_COMPONENT:
                if (cdata->comp_type != CAL_COMP_VAVAILABILITY) reject = 1;
                break;
            case ICAL_VPOLL_COMPONENT:
                if (cdata->comp_type != CAL_COMP_VPOLL) reject = 1;
                break;
            default:
                break;
            }

            /* Don't allow ORGANIZER to be changed */
            if (!reject && cdata->organizer) {
                prop =
                    icalcomponent_get_first_property(comp,
                                                     ICAL_ORGANIZER_PROPERTY);
                if (prop) {
                    const char *organizer =
                        organizer = icalproperty_get_organizer(prop);
                    if (organizer) {
                        if (!strncasecmp(organizer, "mailto:", 7)) organizer += 7;
                        if (strcasecmp(cdata->organizer, organizer)) reject = 1;
                    }
                }
            }

            if (reject) {
                sched_data->status = sched_data->ischedule ?
                    REQSTAT_REJECTED : SCHEDSTAT_REJECTED;
                goto done;
            }
        }
    }

    switch (method) {
    case ICAL_METHOD_CANCEL:
        /* Get component type */
        comp = icalcomponent_get_first_real_component(ical);
        kind = icalcomponent_isa(comp);

        /* Set STATUS:CANCELLED on all components */
        do {
            icalcomponent_set_status(comp, ICAL_STATUS_CANCELLED);
            icalcomponent_set_sequence(comp,
                                       icalcomponent_get_sequence(comp)+1);
        } while ((comp = icalcomponent_get_next_component(ical, kind)));

        break;

    case ICAL_METHOD_REPLY:
        attendee = deliver_merge_reply(ical, sched_data->itip);

        break;

    case ICAL_METHOD_REQUEST:
        deliver_inbox = deliver_merge_request(recipient,
                                              ical, sched_data->itip);
        break;

    case ICAL_METHOD_POLLSTATUS:
        deliver_inbox = deliver_merge_pollstatus(ical, sched_data->itip);
        break;

    default:
        /* Unknown METHOD -- ignore it */
        syslog(LOG_ERR, "Unknown iTIP method: %s",
               icalenum_method_to_string(method));

        sched_data->is_reply = 0;
        goto inbox;
    }

    /* Create header cache */
    txn.req_hdrs = spool_new_hdrcache();
    if (!txn.req_hdrs) r = HTTP_SERVER_ERROR;

    /* Store the (updated) object in the recipients's calendar */
    strarray_t recipient_addresses = STRARRAY_INITIALIZER;
    strarray_append(&recipient_addresses, recipient);
    if (!r) r = caldav_store_resource(&txn, ical, mailbox,
                                      buf_cstring(&resource), cdata->dav.createdmodseq,
                                      caldavdb, NEW_STAG, recipient, &recipient_addresses);
    strarray_fini(&recipient_addresses);

    if (r == HTTP_CREATED || r == HTTP_NO_CONTENT) {
        sched_data->status =
            sched_data->ischedule ? REQSTAT_SUCCESS : SCHEDSTAT_DELIVERED;
    }
    else {
        syslog(LOG_ERR, "caldav_store_resource(%s) failed: %s (%s)",
               mailbox_name(mailbox), error_message(r), txn.error.resource);
        sched_data->status =
            sched_data->ischedule ? REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
        goto done;
    }

  inbox:
    if (deliver_inbox) {
        /* Create a name for the new iTIP message resource */
        buf_reset(&resource);
        buf_printf(&resource, "%s.ics", makeuuid());

        /* Store the message in the recipient's Inbox */
        r = caldav_store_resource(&txn, sched_data->itip, inbox,
                                  buf_cstring(&resource), 0, caldavdb, 0, NULL, NULL);
        /* XXX  What do we do if storing to Inbox fails? */
    }

    /* XXX  Should this be a config option? - it might have perf implications */
    if (sched_data->is_reply) {
        /* Send updates to attendees - skipping sender of reply */
        comp = icalcomponent_get_first_real_component(ical);
        if (icalcomponent_isa(comp) == ICAL_VPOLL_COMPONENT)
            sched_pollstatus(recipient, sparam, ical, attendee);
        else
            sched_request(userid, NULL, recipient, NULL, ical); // oldical?
    }

  done:
    if (ical) icalcomponent_free(ical);
    mailbox_close(&inbox);
    mailbox_close(&mailbox);
    if (caldavdb) caldav_close(caldavdb);
    spool_free_hdrcache(txn.req_hdrs);
    buf_free(&txn.buf);
    free(mailboxname);
}


/* Deliver scheduling object to recipient's Inbox */
void sched_deliver(const char *userid, const char *sender, const char *recipient, void *data, void *rock)
{
    struct sched_data *sched_data = (struct sched_data *) data;
    struct auth_state *authstate = (struct auth_state *) rock;
    struct caldav_sched_param sparam;
    int islegal;

    syslog(LOG_DEBUG, "sched_deliver(%s)", recipient);

    memset(&sparam, 0, sizeof(struct caldav_sched_param));

    /* Check SCHEDULE-FORCE-SEND value */
    switch (sched_data->force_send) {
    case ICAL_SCHEDULEFORCESEND_NONE:
        islegal = 1;
        break;

    case ICAL_SCHEDULEFORCESEND_REPLY:
        islegal = sched_data->is_reply;
        break;

    case ICAL_SCHEDULEFORCESEND_REQUEST:
        islegal = !sched_data->is_reply;
        break;

    default:
        islegal = 0;
        break;
    }

    if (!islegal) {
        sched_data->status = SCHEDSTAT_PARAM;
        return;
    }

    if (caladdress_lookup(recipient, &sparam, sched_data->schedule_addresses)) {
        sched_data->status =
            sched_data->ischedule ? REQSTAT_NOUSER : SCHEDSTAT_NOUSER;
        /* Unknown user */
        goto done;
    }

    /* don't schedule to yourself */
    if (sparam.isyou) goto done;

    if (sparam.flags) {
        /* Remote recipient */
        syslog(LOG_NOTICE, "%s scheduling delivery to %s",
               (sparam.flags & SCHEDTYPE_ISCHEDULE) ? "iSchedule" : "iMIP",
               recipient);

        sched_deliver_remote(userid, sender, recipient, &sparam, sched_data);
    }
    else {
        /* Local recipient */
        syslog(LOG_NOTICE, "CalDAV scheduling delivery to %s", recipient);

        sched_deliver_local(userid, sender, recipient, &sparam, sched_data, authstate);
    }

done:
    sched_param_fini(&sparam);
}

/*
 * sched_request/reply() helper function
 *
 * Update DTSTAMP, remove VALARMs, remove SCHEDULE-* parameters
 */
static void clean_component(icalcomponent *comp)
{
    icalcomponent *alarm, *next;
    icalproperty *prop;

    /* Replace DTSTAMP on component */
    prop = icalcomponent_get_first_property(comp, ICAL_DTSTAMP_PROPERTY);
    if (!prop) {
        prop = icalproperty_new(ICAL_DTSTAMP_PROPERTY);
        icalcomponent_add_property(comp, prop);
    }
    icalproperty_set_dtstamp(prop, icaltime_current_time_with_zone(utc_zone));

    /* Remove any VALARM components */
    for (alarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
         alarm; alarm = next) {
        next = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT);
        icalcomponent_remove_component(comp, alarm);
        icalcomponent_free(alarm);
    }

    /* Grab the organizer */
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);

    /* Remove CalDAV Scheduling parameters from organizer */
    icalproperty_remove_parameter_by_name(prop, "SCHEDULE-AGENT");
    icalproperty_remove_parameter_by_name(prop, "SCHEDULE-FORCE-SEND");

    /* Remove CalDAV Scheduling parameters from attendees */
    for (prop = icalcomponent_get_first_invitee(comp);
         prop;
         prop = icalcomponent_get_next_invitee(comp)) {
        icalproperty_remove_parameter_by_name(prop, "SCHEDULE-AGENT");
        icalproperty_remove_parameter_by_name(prop, "SCHEDULE-STATUS");
        icalproperty_remove_parameter_by_name(prop, "SCHEDULE-FORCE-SEND");
    }
}

/*****************************************************************************/

/*
 * Compare the properties of the given kind in two components.
 * Returns 0 if equal, 1 otherwise.
 *
 * If the property exists in neither comp, then they are equal.
 * If the property exists in only 1 comp, then they are not equal.
 * if the property is RDATE or EXDATE, create an XORed CRC32 of all
 *   property strings for each component (order irrelevant) and compare the CRCs.
 * Otherwise compare the two property strings.
 */
static unsigned propcmp(icalcomponent *oldical, icalcomponent *newical,
                        icalproperty_kind kind)
{
    icalproperty *oldprop = icalcomponent_get_first_property(oldical, kind);
    icalproperty *newprop = icalcomponent_get_first_property(newical, kind);

    if (!oldprop) return (newprop != NULL);
    else if (!newprop) return 1;
    else if (kind == ICAL_DURATION_PROPERTY) {
        struct icaldurationtype olddur = icalproperty_get_duration(oldprop);
        struct icaldurationtype newdur = icalproperty_get_duration(newprop);

        return (icaldurationtype_as_int(olddur) != icaldurationtype_as_int(newdur));
    }
    else if ((kind == ICAL_RDATE_PROPERTY) || (kind == ICAL_EXDATE_PROPERTY) ||
             (kind == ICAL_ATTACH_PROPERTY)) {
        const char *str;
        uint32_t old_crc = 0, new_crc = 0;

        do {
            str = icalproperty_get_value_as_string(oldprop);
            if (str) old_crc ^= crc32_cstring(str);
        } while ((oldprop = icalcomponent_get_next_property(oldical, kind)));

        do {
            str = icalproperty_get_value_as_string(newprop);
            if (str) new_crc ^= crc32_cstring(str);
        } while ((newprop = icalcomponent_get_next_property(newical, kind)));

        return (old_crc != new_crc);
    }
    else {
        return (strcmpsafe(icalproperty_get_value_as_string(oldprop),
                           icalproperty_get_value_as_string(newprop)) != 0);
    }
}

/*
 * sched_request() helper function
 *
 * Process all attendees in the given component and add them
 * to the request data
 */
static void add_attendees(icalcomponent *ical,
                          const char *organizer, strarray_t *attendees)
{
    if (!ical) return;

    icalcomponent *comp = icalcomponent_get_first_real_component(ical);

    /* if no organizer, this isn't a scheduling resource, so nothing else to do */
    if (!icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY))
        return;

    icalcomponent_kind kind = icalcomponent_isa(comp);

    for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
        icalproperty *prop;
        icalparameter *param;
        for (prop = icalcomponent_get_first_invitee(comp);
            prop;
            prop = icalcomponent_get_next_invitee(comp)) {

            const char *attendee = icalproperty_get_invitee(prop);
            if (!attendee) continue;

            if (!strncasecmp(attendee, "mailto:", 7)) attendee += 7;

            /* Skip where attendee == organizer */
            if (!strcasecmp(attendee, organizer)) continue;

            /* Skip where not the server's responsibility */
            param = icalproperty_get_scheduleagent_parameter(prop);
            if (param) {
                icalparameter_scheduleagent agent =
                    icalparameter_get_scheduleagent(param);
                if (agent != ICAL_SCHEDULEAGENT_SERVER) continue;
            }

            strarray_add_case(attendees, attendee);
        }
    }
}

static icalproperty *find_attendee(icalcomponent *comp, const char *match)
{
    if (!comp) return NULL;

    icalproperty *prop = icalcomponent_get_first_invitee(comp);

    for (; prop; prop = icalcomponent_get_next_invitee(comp)) {
        const char *attendee = icalproperty_get_invitee(prop);
        if (!attendee) continue;
        if (!strncasecmp(attendee, "mailto:", 7)) attendee += 7;

        /* Skip where not the server's responsibility */
        icalparameter *param = icalproperty_get_scheduleagent_parameter(prop);
        if (param) {
            icalparameter_scheduleagent agent =
                icalparameter_get_scheduleagent(param);
            if (agent != ICAL_SCHEDULEAGENT_SERVER) continue;
        }

        if (!strcasecmp(attendee, match)) return prop;
    }

    return NULL;
}

static icalcomponent *find_component(icalcomponent *ical, const char *match)
{
    if (!ical) return NULL;

    icalcomponent *comp = icalcomponent_get_first_real_component(ical);

    icalcomponent_kind kind = icalcomponent_isa(comp);

    for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        const char *recurid = "";
        if (prop) recurid = icalproperty_get_value_as_string(prop);
        if (!strcmpsafe(recurid, match)) return comp;
    }

    return NULL;
}

static icalcomponent *find_attended_component(icalcomponent *ical,
                                              const char *recurid,
                                              const char *attendee)
{
    icalcomponent *comp = find_component(ical, recurid);
    if (icalcomponent_get_status(comp) == ICAL_STATUS_CANCELLED) {
        /* Can't attend a cancelled event */
        return NULL;
    }
    if (find_attendee(comp, attendee))
        return comp;
    return NULL;
}

static int has_exdate(icalcomponent *ical, struct icaltimetype test)
{
    if (!ical) return 0;

    icalproperty *prop =
        icalcomponent_get_first_property(ical, ICAL_EXDATE_PROPERTY);
    for (; prop;
         prop = icalcomponent_get_next_property(ical, ICAL_EXDATE_PROPERTY)) {
        struct icaltimetype exdate = icalproperty_get_exdate(prop);
        if (!icaltime_compare(exdate, test)) return 1;
    }

    return 0;
}

static int check_changes_any(icalcomponent *old,
                             icalcomponent *comp, int *needs_actionp)
{
    if (!old) {
        if (needs_actionp) *needs_actionp = 1;
        return 1;
    }

    int is_changed = 0;
    int needs_action = 0;

    /* Per RFC 6638, Section 3.2.8: We need to compare
       DTSTART, DTEND, DURATION, DUE, RRULE, RDATE, EXDATE */
    if (propcmp(old, comp, ICAL_DTSTART_PROPERTY))
        needs_action = 1;
    else if (propcmp(old, comp, ICAL_DTEND_PROPERTY))
        needs_action = 1;
    else if (propcmp(old, comp, ICAL_DURATION_PROPERTY))
        needs_action = 1;
    else if (propcmp(old, comp, ICAL_DUE_PROPERTY))
        needs_action = 1;
    else if (propcmp(old, comp, ICAL_RRULE_PROPERTY))
        needs_action = 1;
    else if (propcmp(old, comp, ICAL_RDATE_PROPERTY))
        needs_action = 1;
    else if (propcmp(old, comp, ICAL_EXDATE_PROPERTY))
        needs_action = 1;

    if (needs_action)
        is_changed = 1;
    else if (propcmp(old, comp, ICAL_SUMMARY_PROPERTY))
        is_changed = 1;
    else if (propcmp(old, comp, ICAL_LOCATION_PROPERTY))
        is_changed = 1;
    else if (propcmp(old, comp, ICAL_DESCRIPTION_PROPERTY))
        is_changed = 1;
    else if (propcmp(old, comp, ICAL_ATTACH_PROPERTY))
        is_changed = 1;
    else if (propcmp(old, comp, ICAL_POLLWINNER_PROPERTY))
        is_changed = 1;
    else if (partstat_changed(old, comp, get_organizer(comp)))
        is_changed = 1;

    if (needs_actionp) *needs_actionp = needs_action;

    return is_changed;
}

static int check_changes(icalcomponent *old, icalcomponent *comp, const char *attendee)
{
    int needs_action = 0;
    int res = check_changes_any(old, comp, &needs_action);
    if (needs_action) {
        /* Make sure SEQUENCE is set properly */
        int oldseq = icalcomponent_get_sequence(old);
        int newseq = icalcomponent_get_sequence(comp);
        if (oldseq >= newseq) icalcomponent_set_sequence(comp, oldseq + 1);
        icalproperty *prop = find_attendee(comp, attendee);
        if (prop) {
            icalparameter *param =
                icalparameter_new_partstat(ICAL_PARTSTAT_NEEDSACTION);
            icalproperty_set_parameter(prop, param);
        }
    }
    return res;
}

icalcomponent *make_itip(icalproperty_method method, icalcomponent *ical)
{
    /* Create a shell for our iTIP request objects */
    icalcomponent *req = icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT,
                                             icalproperty_new_version("2.0"),
                                             icalproperty_new_prodid(ical_prodid),
                                             icalproperty_new_method(method),
                                             0);

    /* XXX  Make sure SEQUENCE is incremented */

    /* Copy over any CALSCALE property */
    icalproperty *prop =
        icalcomponent_get_first_property(ical, ICAL_CALSCALE_PROPERTY);
    if (prop) {
        icalcomponent_add_property(req, icalproperty_clone(prop));
    }

    /* Copy over any VTIMEZONE components */
    icalcomponent *comp;
    for (comp = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical, ICAL_VTIMEZONE_COMPONENT)) {
         icalcomponent_add_component(req, icalcomponent_clone(comp));
    }

    return req;
}

static void schedule_set_exdate(icalcomponent *master, icalcomponent *this)
{
    icalproperty *recurid, *exdate;
    struct icaltimetype exdt;
    icalparameter *param;

    /* Fetch the RECURRENCE-ID and use it to create a new EXDATE */
    recurid = icalcomponent_get_first_property(this, ICAL_RECURRENCEID_PROPERTY);
    exdt = icalproperty_get_recurrenceid(recurid);
    exdate = icalproperty_new_exdate(exdt);

    /* Copy any parameters from RECURRENCE-ID to EXDATE */
    param = icalproperty_get_first_parameter(recurid, ICAL_TZID_PARAMETER);
    if (param) {
        icalproperty_add_parameter(exdate, icalparameter_clone(param));
    }
    param = icalproperty_get_first_parameter(recurid, ICAL_VALUE_PARAMETER);
    if (param) {
        icalproperty_add_parameter(exdate, icalparameter_clone(param));
    }

    /* XXX  Need to handle RANGE parameter */

    /* Add the EXDATE */
    icalcomponent_add_property(master, exdate);
}

/* we've already tested that master contains this attendee */
static void update_attendee_status(icalcomponent *ical, strarray_t *onrecurids,
                                   const char *onattendee, const char *status)
{
    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
    icalcomponent_kind kind = icalcomponent_isa(comp);

    for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
        if (onrecurids) {
            /* this recurrenceid is attended by this attendee in the new data?
            * there's nothing to cancel */
            icalproperty *prop =
                icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
            const char *recurid = "";
            if (prop) recurid = icalproperty_get_value_as_string(prop);
            if (strarray_find(onrecurids, recurid, 0) < 0) continue;
        }

        icalproperty *prop = icalcomponent_get_first_invitee(comp);
        for (; prop; prop = icalcomponent_get_next_invitee(comp)) {
            const char *attendee = icalproperty_get_invitee(prop);
            if (!attendee) continue;
            if (!strncasecmp(attendee, "mailto:", 7)) attendee += 7;

            /* skip attendees other than the one we're updating */
            if (onattendee && strcasecmp(attendee, onattendee)) continue;

            /* mark the status */
            icalparameter *param = icalparameter_new_schedulestatus(status);
            icalproperty_set_parameter(prop, param);
        }
    }
}

static icaltimetype get_historical_cutoff()
{
    int age = config_getduration(IMAPOPT_CALDAV_HISTORICAL_AGE, 'd');
    icaltimetype cutoff;

    if (age < 0) return icaltime_null_time();

    /* Set cutoff to current time -age days */
    cutoff = icaltime_current_time_with_zone(icaltimezone_get_utc_timezone());
    icaltime_adjust(&cutoff, 0, 0, 0, -age);

    return cutoff;
}

static int icalcomponent_is_historical(icalcomponent *comp, icaltimetype cutoff)
{
    if (icaltime_is_null_time(cutoff)) return 0;

    icalcomponent_kind kind = icalcomponent_isa(comp);
    struct icalperiodtype span;

    if (icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY)) {
         /* span is just the span of the override */
        span = icalcomponent_get_utc_timespan(comp, kind, NULL);
    }
    else {
        /* span is entire span of the master */
        icalcomponent *ical = icalcomponent_new_vcalendar();

        icalcomponent_add_component(ical, icalcomponent_clone(comp));
        span = icalrecurrenceset_get_utc_timespan(ical, kind, NULL, NULL, NULL, NULL);
        icalcomponent_free(ical);
    }

    return (icaltime_compare(span.end, cutoff) < 0);
}

static void schedule_full_cancel(const char *userid, const strarray_t *schedule_addresses,
                                 const char *organizer, const char *attendee,
                                 icalcomponent *mastercomp, icaltimetype h_cutoff,
                                 icalcomponent *oldical, icalcomponent *newical)
{
    /* we need to send a cancel for all recurrences with this attendee,
       and add exdates to the master for all without this attendee */
    icalcomponent *itip = make_itip(ICAL_METHOD_CANCEL, oldical);

    icalcomponent *mastercopy = icalcomponent_clone(mastercomp);
    clean_component(mastercopy);
    icalcomponent_set_status(mastercopy, ICAL_STATUS_CANCELLED);
    icalcomponent_add_component(itip, mastercopy);

    int do_send = !icalcomponent_is_historical(mastercopy, h_cutoff);

    icalcomponent *comp = icalcomponent_get_first_real_component(oldical);
    icalcomponent_kind kind = icalcomponent_isa(comp);

    for (; comp; comp = icalcomponent_get_next_component(oldical, kind)) {
        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (!prop) continue; /* skip master */
        const char *recurid = icalproperty_get_value_as_string(prop);

        /* non matching are exdates on the master */
        if (!find_attendee(comp, attendee)) {
            schedule_set_exdate(mastercopy, comp);
            continue;
        }

        icalcomponent *newcomp =
            find_attended_component(newical, recurid, attendee);
        if (newcomp) continue; /* will be scheduled separately */

        icalcomponent *copy = icalcomponent_clone(comp);
        clean_component(copy);
        icalcomponent_set_status(copy, ICAL_STATUS_CANCELLED);
        icalcomponent_add_component(itip, copy);

        if (!do_send && !icalcomponent_is_historical(copy, h_cutoff))
            do_send = 1;
    }

    if (do_send) {
        struct sched_data sched =
            { 0, 0, 0, itip, oldical, newical, ICAL_SCHEDULEFORCESEND_NONE, schedule_addresses, NULL };
        sched_deliver(userid, organizer, attendee, &sched, httpd_authstate);
    }

    icalcomponent_free(itip);
}

/* we've already tested that master does NOT contain this attendee */
static void schedule_sub_cancels(const char *userid, const strarray_t *schedule_addresses,
                                 const char *organizer, const char *attendee,
                                 icaltimetype h_cutoff,
                                 icalcomponent *oldical, icalcomponent *newical)
{
    if (!oldical) return;

    /* we have to create this upfront because it walks the components too */
    icalcomponent *itip = make_itip(ICAL_METHOD_CANCEL, oldical);

    icalcomponent *comp = icalcomponent_get_first_real_component(oldical);
    icalcomponent_kind kind = icalcomponent_isa(comp);

    int do_send = 0;

    for (; comp; comp = icalcomponent_get_next_component(oldical, kind)) {
        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (!prop) continue;
        const char *recurid = icalproperty_get_value_as_string(prop);

        /* we're not attending, there's nothing to cancel */
        if (!find_attendee(comp, attendee))
            continue;

        /* this recurrenceid is attended by this attendee in the new data?
         * there's nothing to cancel */
        if (find_attended_component(newical, recurid, attendee))
            continue;

        icalcomponent *copy = icalcomponent_clone(comp);
        clean_component(copy);
        icalcomponent_set_status(copy, ICAL_STATUS_CANCELLED);
        icalcomponent_add_component(itip, copy);

        if (!do_send && !icalcomponent_is_historical(copy, h_cutoff))
            do_send = 1;
    }

    if (do_send) {
        struct sched_data sched =
            { 0, 0, 0, itip, oldical, newical, ICAL_SCHEDULEFORCESEND_NONE, schedule_addresses, NULL };
        sched_deliver(userid, organizer, attendee, &sched, httpd_authstate);

    }

    icalcomponent_free(itip);
}

icalparameter_scheduleforcesend get_forcesend(icalproperty *prop)
{
    icalparameter *param = icalproperty_get_scheduleforcesend_parameter(prop);
    if (!param) return ICAL_SCHEDULEFORCESEND_NONE;
    return icalparameter_get_scheduleforcesend(param);
}



/* we've already tested that master does NOT contain this attendee or that
 * master doesn't need to be scheduled */
static void schedule_sub_updates(const char *userid, const strarray_t *schedule_addresses,
                                 const char *organizer, const char *attendee,
                                 icaltimetype h_cutoff,
                                 icalcomponent *oldical, icalcomponent *newical)
{
    if (!newical) return;

    icalcomponent *itip = make_itip(ICAL_METHOD_REQUEST, newical);
    strarray_t recurids = STRARRAY_INITIALIZER;
    icalparameter_scheduleforcesend force_send = ICAL_SCHEDULEFORCESEND_NONE;
    int is_update = 0;

    icalcomponent *oldmaster = find_attended_component(oldical, "", attendee);

    icalcomponent *comp = icalcomponent_get_first_real_component(newical);
    icalcomponent_kind kind = icalcomponent_isa(comp);

    int do_send = 0;

    for (; comp; comp = icalcomponent_get_next_component(newical, kind)) {
        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (!prop) continue;
        const char *recurid = icalproperty_get_value_as_string(prop);

        /* we're not attending, nothing to do */
        icalproperty *att = find_attendee(comp, attendee);
        if (!att) continue;
        force_send = get_forcesend(att);

        icalcomponent *freeme = NULL;

        /* this recurrenceid was in the old data? if not we need to
         * generate a synthetic one */
        icalcomponent *oldcomp = find_component(oldical, recurid);
        if (!oldcomp && oldmaster) {
            oldcomp = freeme = master_to_recurrence(oldmaster, prop);
        }

        /* unchanged event - we don't need to send anything */
        if (!check_changes(oldcomp, comp, attendee)) {
            if (force_send == ICAL_SCHEDULEFORCESEND_NONE) {
                if (freeme) icalcomponent_free(freeme);
                continue;
            }
        }

        icalcomponent *copy = icalcomponent_clone(comp);
        clean_component(copy);

        if (find_attendee(oldcomp, attendee))
            is_update = 1;

        icalcomponent_add_component(itip, copy);

        strarray_add(&recurids, recurid);

        if (!do_send && !icalcomponent_is_historical(copy, h_cutoff))
            do_send = 1;

        if (freeme) icalcomponent_free(freeme);
    }

    if (do_send) {
        struct sched_data sched =
            { 0, 0, is_update, itip, oldical, newical, force_send, schedule_addresses, NULL };
        sched_deliver(userid, organizer, attendee, &sched, httpd_authstate);
        update_attendee_status(newical, &recurids, attendee, sched.status);
    }

    icalcomponent_free(itip);
    strarray_fini(&recurids);
}

/* we've already tested that master does contain this attendee */
static void schedule_full_update(const char *userid, const strarray_t *schedule_addresses,
                                 const char *organizer, const char *attendee,
                                 icalcomponent *mastercomp, icaltimetype h_cutoff,
                                 icalcomponent *oldical, icalcomponent *newical)
{
    /* create an itip for the complete event */
    icalcomponent *itip = make_itip(ICAL_METHOD_REQUEST, newical);

    icalcomponent *mastercopy = icalcomponent_clone(mastercomp);
    clean_component(mastercopy);
    icalcomponent_add_component(itip, mastercopy);

    int do_send = 0;
    int is_update = 0;

    icalcomponent *oldmaster = find_attended_component(oldical, "", attendee);
    if (check_changes(oldmaster, mastercopy, attendee)) {
        /* we only force the send if the top level event has changed */
        if (!icalcomponent_is_historical(mastercopy, h_cutoff)) do_send = 1;

        if (oldmaster) {
            is_update = 1;
            if (!do_send && !icalcomponent_is_historical(oldmaster, h_cutoff))
                do_send = 1;
        }
    }

    icalproperty *masteratt = find_attendee(mastercomp, attendee);
    icalparameter_scheduleforcesend force_send = get_forcesend(masteratt);

    /* force the matter */
    if (force_send != ICAL_SCHEDULEFORCESEND_NONE) do_send = 1;

    icalcomponent *comp = icalcomponent_get_first_real_component(newical);
    icalcomponent_kind kind = icalcomponent_isa(comp);
    for (; comp; comp = icalcomponent_get_next_component(newical, kind)) {
        /* this recurrenceid is attended by this attendee in the old data?
         * check if changed */
        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (!prop) continue;
        const char *recurid = icalproperty_get_value_as_string(prop);

        /* we can't just use "find_attended_component" here, because a previous
         * sub component without this attendee is an old EXDATE for us, while
         * no previous sub component means it was just a regular recurrence
         * of the master event */
        icalcomponent *oldcomp = find_component(oldical, recurid);

        int has_old = !!find_attendee(oldcomp, attendee);
        if (has_old) is_update = 1;
        if (!oldcomp && oldmaster)
            is_update = 1;

        /* non matching are exdates on the master */
        if (!find_attendee(comp, attendee)) {
            schedule_set_exdate(mastercopy, comp);

            /* different from last time? */
            if ((!oldcomp || has_old) &&
                !do_send && !icalcomponent_is_historical(comp, h_cutoff)) {
                do_send = 1;
            }
            continue;
        }

        icalcomponent *copy = icalcomponent_clone(comp);

        /* we don't care if it's changed, just using this for the
         * side effect changes to RSVP */
        check_changes(oldcomp, copy, attendee);

        clean_component(copy);
        icalcomponent_add_component(itip, copy);
    }

    if (do_send) {
        struct sched_data sched =
            { 0, 0, is_update, itip, oldical, newical, force_send, schedule_addresses, NULL };
        sched_deliver(userid, organizer, attendee, &sched, httpd_authstate);

        update_attendee_status(newical, NULL, attendee, sched.status);
    }
    else {
        /* just look for sub updates */
        schedule_sub_updates(userid, schedule_addresses, organizer, attendee, h_cutoff, oldical, newical);
    }

    icalcomponent_free(itip);
}

/* sched_request() helper
 * handles scheduling for a single attendee */
static void schedule_one_attendee(const char *userid, const strarray_t *schedule_addresses,
                                  const char *organizer, const char *attendee,
                                  icaltimetype h_cutoff,
                                  icalcomponent *oldical, icalcomponent *newical)
{
    /* case: this attendee is attending the master event */
    icalcomponent *mastercomp;
    if ((mastercomp = find_attended_component(newical, "", attendee))) {
        schedule_full_update(userid, schedule_addresses, organizer, attendee,
                             mastercomp, h_cutoff, oldical, newical);
        return;
    }

    /* otherwise we need to cancel for each sub event and then we'll still
     * send the updates if any */
    if ((mastercomp = find_attended_component(oldical, "", attendee))) {
        schedule_full_cancel(userid, schedule_addresses, organizer, attendee, mastercomp, h_cutoff, oldical, newical);
    }
    else {
        schedule_sub_cancels(userid, schedule_addresses, organizer, attendee, h_cutoff, oldical, newical);
    }

    schedule_sub_updates(userid, schedule_addresses, organizer, attendee, h_cutoff, oldical, newical);
}


/* Create and deliver an organizer scheduling request */
void sched_request(const char *userid, const strarray_t *schedule_addresses,
                   const char *organizer,
                   icalcomponent *oldical, icalcomponent *newical)
{
    /* Check ACL of auth'd user on userid's Scheduling Outbox */
    int rights = 0;

    mbentry_t *mbentry = NULL;
    char *outboxname = caldav_mboxname(userid, SCHED_OUTBOX);
    int r = mboxlist_lookup(outboxname, &mbentry, NULL);
    if (r) {
        syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
               outboxname, error_message(r));
    }
    else {
        rights = httpd_myrights(httpd_authstate, mbentry);
    }
    free(outboxname);
    mboxlist_entry_free(&mbentry);

    if (!(rights & DACL_INVITE)) {
        /* DAV:need-privileges */
        syslog(LOG_DEBUG, "No scheduling send ACL for user %s on Outbox %s",
               httpd_userid, organizer);

        update_attendee_status(newical, NULL, NULL, SCHEDSTAT_NOPRIVS);

        return;
    }

    /* ok, let's figure out who the attendees are */
    strarray_t attendees = STRARRAY_INITIALIZER;
    add_attendees(oldical, organizer, &attendees);
    add_attendees(newical, organizer, &attendees);

    icaltimetype h_cutoff = get_historical_cutoff();

    int i;
    for (i = 0; i < strarray_size(&attendees); i++) {
        const char *attendee = strarray_nth(&attendees, i);
        syslog(LOG_NOTICE, "iTIP scheduling request from %s to %s",
               organizer, attendee);
        schedule_one_attendee(userid, schedule_addresses, organizer, attendee, h_cutoff, oldical, newical);
    }

    strarray_fini(&attendees);
}

/*******************************************************************/
/* REPLIES */

struct reply_data {
    icalcomponent *itip;
    const char *organizer;
    strarray_t *didparts;
    int master_send;
    int do_send;
    icalparameter_scheduleforcesend force_send;
};


/*
 * sched_reply() helper function
 *
 * Remove all attendees from 'comp' other than the one corresponding to 'match'
 */
static void trim_attendees(icalcomponent *comp, const char *match)
{
    icalproperty *prop;
    ptrarray_t remove = PTRARRAY_INITIALIZER;

    /* Locate userid in the attendee list (stripping others) */
    for (prop = icalcomponent_get_first_invitee(comp);
         prop;
         prop = icalcomponent_get_next_invitee(comp)) {
        const char *attendee = icalproperty_get_invitee(prop);
        if (!attendee) continue;
        if (!strncasecmp(attendee, "mailto:", 7)) attendee += 7;

        /* keep my attendee */
        if (!strcasecmp(attendee, match)) continue;

        /* Some other attendee, remove it */
        ptrarray_append(&remove, prop);
    }

    int i;
    for (i = 0; i < remove.count; i++) {
        icalcomponent_remove_invitee(comp, ptrarray_nth(&remove, i));
    }
    ptrarray_fini(&remove);
}


/*
 * sched_reply() helper function
 *
 * Attendee removed this component, mark it as declined for the organizer.
 */
static int reply_mark_declined(icalcomponent *comp)
{
    icalproperty *myattendee;
    icalparameter *param;

    if (!comp) return 0;

    /* Don't send a decline for cancelled components */
    if (icalcomponent_get_status(comp) == ICAL_STATUS_CANCELLED)
        return 0;

    myattendee = icalcomponent_get_first_property(comp, ICAL_ATTENDEE_PROPERTY);

    param = icalparameter_new_partstat(ICAL_PARTSTAT_DECLINED);
    icalproperty_set_parameter(myattendee, param);

    return 1;
}

/* we've already tested that master contains this attendee */
static void update_organizer_status(icalcomponent *ical, strarray_t *onrecurids,
                                    const char *status)
{
    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
    icalcomponent_kind kind = icalcomponent_isa(comp);

    for (; comp; comp = icalcomponent_get_next_component(ical, kind)) {
        if (onrecurids) {
            icalproperty *prop =
                icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
            const char *recurid = "";
            if (prop) recurid = icalproperty_get_value_as_string(prop);
            if (strarray_find(onrecurids, recurid, 0) < 0) continue;
        }

        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);

        /* mark the status */
        icalparameter *param = icalparameter_new_schedulestatus(status);
        icalproperty_set_parameter(prop, param);
    }
}

static const char *get_organizer(icalcomponent *comp)
{
    icalproperty *prop =
        icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    const char *organizer = icalproperty_get_organizer(prop);
    if (!organizer) return NULL;
    if (!strncasecmp(organizer, "mailto:", 7)) organizer += 7;
    icalparameter *param = icalproperty_get_scheduleagent_parameter(prop);
    /* check if we're supposed to send replies to the organizer */
    if (param &&
        icalparameter_get_scheduleagent(param) != ICAL_SCHEDULEAGENT_SERVER)
        return NULL;
    return organizer;
}

static icalparameter_partstat get_partstat(icalcomponent *comp,
                                           const char *attendee)
{
    icalproperty *prop = find_attendee(comp, attendee);
    if (!prop) return ICAL_PARTSTAT_NEEDSACTION;
    icalparameter *param =
        icalproperty_get_first_parameter(prop, ICAL_PARTSTAT_PARAMETER);
    if (!param) return ICAL_PARTSTAT_NEEDSACTION;
    return icalparameter_get_partstat(param);
}

static int partstat_changed(icalcomponent *oldcomp,
                            icalcomponent *newcomp, const char *attendee)
{
    if (!attendee) return 1; // something weird is going on, treat it as a change
    return (get_partstat(oldcomp, attendee) != get_partstat(newcomp, attendee));
}

static void schedule_sub_declines(const char *attendee,
                                  icaltimetype h_cutoff,
                                  icalcomponent *oldical, icalcomponent *newical,
                                  struct reply_data *reply)
{
    if (!oldical) return;

    if (!reply->itip)
        reply->itip = make_itip(ICAL_METHOD_REPLY, oldical);

    icalcomponent *comp = icalcomponent_get_first_real_component(oldical);
    icalcomponent_kind kind = icalcomponent_isa(comp);

    for (; comp; comp = icalcomponent_get_next_component(oldical, kind)) {
        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (!prop) continue;
        const char *recurid = icalproperty_get_value_as_string(prop);

        /* we weren't attending, nothing to do */
        if (!find_attendee(comp, attendee))
            continue;

        /* no organizer, can't do anything */
        const char *organizer = get_organizer(comp);
        if (!organizer) continue;

        /* this recurrenceid is attended by this attendee in the new data?
           don't decline, we've already replied if necessary */
        icalcomponent *newcomp =
            find_attended_component(newical, recurid, attendee);
        if (newcomp) continue;

        /* we need to send an update for this recurrence */
        icalcomponent *copy = icalcomponent_clone(comp);
        trim_attendees(copy, attendee);
        if (kind == ICAL_VPOLL_COMPONENT) sched_vpoll_reply(copy);
        clean_component(copy);
        reply_mark_declined(copy);

        icalcomponent_add_component(reply->itip, copy);

        if (!reply->do_send && !icalcomponent_is_historical(comp, h_cutoff))
            reply->do_send = 1;
    }
}

/* we've already tested that master does NOT contain this attendee */
static void schedule_sub_replies(const char *attendee,
                                 icaltimetype h_cutoff,
                                 icalcomponent *oldical, icalcomponent *newical,
                                 struct reply_data *reply)
{
    if (!newical) return;

    if (!reply->itip) reply->itip = make_itip(ICAL_METHOD_REPLY, newical);

    icalcomponent *comp = icalcomponent_get_first_real_component(newical);
    icalcomponent_kind kind = icalcomponent_isa(comp);

    for (; comp; comp = icalcomponent_get_next_component(newical, kind)) {
        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (!prop) continue;
        const char *recurid = icalproperty_get_value_as_string(prop);

        /* we're not attending, nothing to do */
        if (!find_attendee(comp, attendee))
            continue;

        /* no organizer, can't do anything */
        const char *organizer = get_organizer(comp);
        if (!organizer) continue;

        icalparameter_scheduleforcesend force_send =
            get_forcesend(icalcomponent_get_first_property(comp,
                                                           ICAL_ORGANIZER_PROPERTY));

        /* this recurrenceid is attended by this attendee in the old data? */
        icalcomponent *oldcomp =
            find_attended_component(oldical, recurid, attendee);

        /* unchanged partstat - we don't need to send anything */
        if (!reply->master_send && !partstat_changed(oldcomp, comp, attendee)) {
            if (force_send == ICAL_SCHEDULEFORCESEND_NONE)
                continue;
        }

        /* XXX - test for changed between recurrences and error out?  Any point? */
        reply->force_send = force_send;
        reply->organizer = organizer;

        /* we need to send an update for this recurrence */
        icalcomponent *copy = icalcomponent_clone(comp);
        trim_attendees(copy, attendee);
        if (kind == ICAL_VPOLL_COMPONENT) sched_vpoll_reply(copy);
        clean_component(copy);

        icalcomponent_add_component(reply->itip, copy);

        if (!reply->master_send) {
            if (!reply->didparts) reply->didparts = strarray_new();
            strarray_add(reply->didparts, recurid);
        }

        if (!reply->do_send && !icalcomponent_is_historical(comp, h_cutoff))
            reply->do_send = 1;
    }
}

static void schedule_full_decline(const char *attendee,
                                  icaltimetype h_cutoff,
                                  icalcomponent *oldical, icalcomponent *newical __attribute__((unused)),
                                  struct reply_data *reply)
{
    /* we only get called if newical doesn't have an attended mastercomp */
    icalcomponent *mastercomp = find_attended_component(oldical, "", attendee);
    if (!mastercomp) return;

    reply->organizer = get_organizer(mastercomp);
    if (!reply->organizer) return;

    /* we need to send a reply for this recurrence for sure, because we know that the
     * that new master doesn't have this attendee */
    if (!reply->itip) reply->itip = make_itip(ICAL_METHOD_REPLY, oldical);

    reply->force_send =
        get_forcesend(icalcomponent_get_first_property(mastercomp,
                                                       ICAL_ORGANIZER_PROPERTY));

    icalcomponent *mastercopy = icalcomponent_clone(mastercomp);
    trim_attendees(mastercopy, attendee);
    if (icalcomponent_isa(mastercomp) == ICAL_VPOLL_COMPONENT) sched_vpoll_reply(mastercopy);
    clean_component(mastercopy);
    reply_mark_declined(mastercopy);

    icalcomponent_add_component(reply->itip, mastercopy);

    if (!reply->do_send && !icalcomponent_is_historical(mastercomp, h_cutoff))
        reply->do_send = 1;

    /* force ALL sub parts to be added */
    reply->master_send = 1;
}

/* we've already tested that master contains this attendee */
static void schedule_full_reply(const char *attendee,
                                icaltimetype h_cutoff,
                                icalcomponent *oldical, icalcomponent *newical,
                                struct reply_data *reply)
{
    icalcomponent *mastercomp = find_attended_component(newical, "", attendee);
    icalcomponent_kind kind;
    int add_master = 0;

    if (!mastercomp) {
        schedule_full_decline(attendee, h_cutoff, oldical, newical, reply);
        return;
    }

    reply->organizer = get_organizer(mastercomp);
    if (!reply->organizer) return;

    kind = icalcomponent_isa(mastercomp);

    reply->force_send =
        get_forcesend(icalcomponent_get_first_property(mastercomp,
                                                       ICAL_ORGANIZER_PROPERTY));

    /* calculate if we need to send a reply based on the master event */

    /* it's forced */
    if (reply->force_send != ICAL_SCHEDULEFORCESEND_NONE)
        add_master = 1;

    /* or it's a VPOLL */
    else if (kind == ICAL_VPOLL_COMPONENT)
        add_master = 1;

    else {
        /* or it's different */
        icalcomponent *oldmaster = find_attended_component(oldical, "", attendee);
        if (partstat_changed(oldmaster, mastercomp, attendee))
            add_master = 1;

        /* or it includes new EXDATEs */
        else {
            icalproperty *prop =
                icalcomponent_get_first_property(mastercomp, ICAL_EXDATE_PROPERTY);
            for (; prop; prop = icalcomponent_get_next_property(mastercomp,
                                                                ICAL_EXDATE_PROPERTY)) {
                struct icaltimetype exdate = icalproperty_get_exdate(prop);
                if (!has_exdate(oldmaster, exdate))
                    add_master = 1;
            }
        }
    }

    if (add_master) {
        if (!reply->itip) reply->itip = make_itip(ICAL_METHOD_REPLY, newical);

        /* add the master */
        icalcomponent *mastercopy = icalcomponent_clone(mastercomp);
        trim_attendees(mastercopy, attendee);
        if (kind == ICAL_VPOLL_COMPONENT) sched_vpoll_reply(mastercopy);
        clean_component(mastercopy);
        icalcomponent_add_component(reply->itip, mastercopy);

        /* force ALL sub parts to be added */
        reply->master_send = 1;

        /* master includes "recent" occurrence(s) - send it */
        if (!icalcomponent_is_historical(mastercopy, h_cutoff))
            reply->do_send = 1;
    }
}

/* Create and deliver an attendee scheduling reply */
void sched_reply(const char *userid, const strarray_t *schedule_addresses,
                 icalcomponent *oldical, icalcomponent *newical)
{
    /* Check ACL of auth'd user on userid's Scheduling Outbox */
    int rights = 0;

    mbentry_t *mbentry = NULL;
    char *outboxname = caldav_mboxname(userid, SCHED_OUTBOX);
    int r = mboxlist_lookup(outboxname, &mbentry, NULL);
    if (r) {
        syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
               outboxname, error_message(r));
    }
    else {
        rights = httpd_myrights(httpd_authstate, mbentry);
    }
    free(outboxname);
    mboxlist_entry_free(&mbentry);

    if (!(rights & DACL_REPLY)) {
        /* DAV:need-privileges */
        syslog(LOG_DEBUG, "No scheduling send ACL for user %s on Outbox %s",
               httpd_userid, userid);
        update_organizer_status(newical, NULL, SCHEDSTAT_NOPRIVS);
        return;
    }

    /* otherwise we need to decline for each sub event and then we'll still
     * send the accepts if any */
    icaltimetype h_cutoff = get_historical_cutoff();

    int i;
    for (i = 0; i < strarray_size(schedule_addresses); i++) {
        const char *attendee = strarray_nth(schedule_addresses, i);
        struct reply_data reply = { NULL, NULL, NULL, 0, 0, ICAL_SCHEDULEFORCESEND_NONE };
        if (!strncasecmp(attendee, "mailto:", 7)) attendee += 7;

        schedule_full_reply(attendee, h_cutoff, oldical, newical, &reply);
        schedule_sub_replies(attendee, h_cutoff, oldical, newical, &reply);
        schedule_sub_declines(attendee, h_cutoff, oldical, newical, &reply);

        if (reply.do_send) {
            struct sched_data sched =
                { 0, 1, 0, reply.itip, oldical, newical, reply.force_send, schedule_addresses, NULL };
            syslog(LOG_NOTICE, "iTIP scheduling reply from %s to %s",
                   attendee, reply.organizer ? reply.organizer : "<unknown>");
            sched_deliver(userid, attendee, reply.organizer, &sched, httpd_authstate);
            update_organizer_status(newical, reply.didparts, sched.status);
        }

        if (reply.didparts) strarray_free(reply.didparts);
        if (reply.itip) icalcomponent_free(reply.itip);
    }
}

void sched_param_fini(struct caldav_sched_param *sparam)
{
    free(sparam->userid);
    free(sparam->server);

    struct proplist *prop, *next;
    for (prop = sparam->props; prop; prop = next) {
        next = prop->next;
        free(prop);
    }

    memset(sparam, 0, sizeof(struct caldav_sched_param));
}


void get_schedule_addresses(hdrcache_t req_hdrs, const char *mboxname,
                            const char *userid, strarray_t *addresses)
{
    struct buf buf = BUF_INITIALIZER;

    /* allow override of schedule-address per-message (FM specific) */
    const char **hdr = spool_getheader(req_hdrs, "Schedule-Address");

    if (hdr) {
        if (!strncasecmp(hdr[0], "mailto:", 7))
            strarray_add(addresses, hdr[0]+7);
        else
            strarray_add(addresses, hdr[0]);
    }
    else {
        /* find schedule address based on the destination calendar's user */

        /* check calendar-user-address-set for target user's mailbox */
        const char *annotname =
            DAV_ANNOT_NS "<" XML_NS_CALDAV ">calendar-user-address-set";
        int r = annotatemore_lookupmask(mboxname, annotname,
                                        userid, &buf);
        if (r || !buf.len) {
            /* check calendar-user-address-set for target user's principal */
            char *calhomeset = caldav_mboxname(userid, NULL);
            buf_reset(&buf);
            r = annotatemore_lookupmask(calhomeset, annotname,
                                        userid, &buf);
            free(calhomeset);
        }

        if (!r && buf.len) {
            strarray_t *values =
                strarray_split(buf_cstring(&buf), ",", STRARRAY_TRIM);
            int i;
            for (i = 0; i < strarray_size(values); i++) {
                const char *item = strarray_nth(values, i);
                if (!strncasecmp(item, "mailto:", 7)) item += 7;
                strarray_add(addresses, item);
            }
            strarray_free(values);
        }
        else if (strchr(userid, '@')) {
            /* userid corresponding to target */
            strarray_add(addresses, userid);
        }
        else {
            /* append fully qualified userids */
            int i;
            for (i = 0; i < strarray_size(&cua_domains); i++) {
                const char *s = strarray_nth(&cua_domains, i);
                buf_reset(&buf);
                buf_printf(&buf, "%s@%s", userid, s);
                strarray_add(addresses, buf_cstring(&buf));
            }
        }
    }

    buf_free(&buf);
}
