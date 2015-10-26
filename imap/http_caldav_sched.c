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

#include <libical/ical.h>
#include <libxml/HTMLparser.h>
#include <libxml/tree.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "httpd.h"
#include "http_caldav_sched.h"
#include "http_dav.h"
#include "http_proxy.h"
#include "md5.h"
#include "smtpclient.h"
#include "strhash.h"
#include "times.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

int caladdress_lookup(const char *addr, struct sched_param *param, const char *myuserid)
{
    const char *userid = addr, *p;
    int islocal = 1, found = 1;
    size_t len;

    memset(param, 0, sizeof(struct sched_param));

    if (!addr) return HTTP_NOT_FOUND;

    if (!strncasecmp(userid, "mailto:", 7)) userid += 7;
    if (myuserid && !strcasecmp(userid, myuserid)) {
        param->isyou = 1;
        param->userid = xstrdupnull(userid); /* XXX - memleak */
        return 0; // myself is always local
    }
    len = strlen(userid);

    /* XXX  Do LDAP/DB/socket lookup to see if user is local */
    /* XXX  Hack until real lookup stuff is written */
    if ((p = strchr(userid, '@')) && *++p) {
        struct strlist *domains = cua_domains;

        for (; domains && strcmp(p, domains->s); domains = domains->next);

        if (!domains) islocal = 0;
        else if (!config_virtdomains) len = p - userid - 1;
    }

    if (islocal) {
        /* User is in a local domain */
        int r;
        const char *mboxname = NULL;
        mbentry_t *mbentry = NULL;
        mbname_t *mbname = NULL;

        if (!found) return HTTP_NOT_FOUND;
        else param->userid = xstrndup(userid, len); /* freed by sched_param_free */

        /* Lookup user's cal-home-set to see if its on this server */

        mbname = mbname_from_userid(param->userid);
        mbname_push_boxes(mbname, config_getstring(IMAPOPT_CALENDARPREFIX));
        mboxname = mbname_intname(mbname);

        r = http_mlookup(mboxname, &mbentry, NULL);
        mbname_free(&mbname);

        if (!r) {
            param->server = xstrdupnull(mbentry->server); /* freed by sched_param_free */
            mboxlist_entry_free(&mbentry);
            if (param->server) param->flags |= SCHEDTYPE_ISCHEDULE;
            return 0;
        }
        /* Fall through and try remote */
    }

    /* User is outside of our domain(s) -
       Do remote scheduling (default = iMIP) */
    if (param->userid) free(param->userid);
    param->userid = xstrdupnull(userid); /* freed by sched_param_free */
    param->flags |= SCHEDTYPE_REMOTE;

#ifdef WITH_DKIM
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
        param->server = xstrdrup("www.bedework.org");
        param->port = 80;
        param->flags |= SCHEDTYPE_ISCHEDULE;
    }
#endif /* IOPTEST */

#endif /* WITH_DKIM */

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

    new->addr = icalproperty_get_address(prop) + 7;
    param = icalproperty_get_first_parameter(prop, ICAL_CN_PARAMETER);
    if (param) {
        new->name = icalparameter_get_cn(param);
        new->qpname = charset_encode_mimeheader(new->name, 0);
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
static int imip_send(icalcomponent *ical)
{
    int r;
    icalcomponent *comp;
    icalproperty *prop;
    icalproperty_method meth;
    icalcomponent_kind kind;
    const char *argv[7], *uid, *msg_type, *summary, *location, *descrip, *status;
    struct address_t *recipients = NULL, *originator = NULL, *recip;
    struct icaltimetype start, end;
    char *cp, when[2*RFC822_DATETIME_MAX+4], datestr[RFC822_DATETIME_MAX+1];
    char boundary[100], *mimebody, *ical_str;
    size_t outlen;
    struct buf plainbuf = BUF_INITIALIZER, tmpbuf = BUF_INITIALIZER;
    FILE *sm;
    pid_t sm_pid, p = getpid();
    time_t t = time(NULL);
    static unsigned send_count = 0;
    const char *day_of_week[] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    };
    const char *month_of_year[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    meth = icalcomponent_get_method(ical);
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);
    uid = icalcomponent_get_uid(comp);

    /* Determine Originator and Recipient(s) based on method and component */
    if (meth == ICAL_METHOD_REPLY) {
        msg_type = "a RSVP";

        prop = icalcomponent_get_first_invitee(comp);
        add_address(&originator, prop, &icalproperty_get_invitee);

        prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
        add_address(&recipients, prop,
                    (const char*(*)(icalproperty *))&icalproperty_get_organizer);
    }
    else {
        msg_type =
            (meth == ICAL_METHOD_CANCEL) ? "a cancellation" : "an invitation";

        prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
        add_address(&originator, prop,
                    (const char*(*)(icalproperty *))&icalproperty_get_organizer);

        for (prop = icalcomponent_get_first_invitee(comp);
             prop;
             prop = icalcomponent_get_next_invitee(comp)) {

            add_address(&recipients, prop, &icalproperty_get_invitee);
        }
    }

    argv[0] = "sendmail";
    argv[1] = "-f";
    argv[2] = originator->addr;
    argv[3] = "-t";             /* get recipients from body */
    argv[4] = "-N";             /* notify on failure or delay */
    argv[5] = "failure,delay";
    argv[6] = NULL;

    sm_pid = open_sendmail(argv, &sm);

    if (sm == NULL) {
        r = HTTP_UNAVAILABLE;
        goto done;
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
                  day_of_week[icaltime_day_of_week(start)-1],
                  start.day, month_of_year[start.month-1], start.year);
    if (!start.is_date) {
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
                          day_of_week[icaltime_day_of_week(end)-1],
                          end.day, month_of_year[end.month-1], end.year);
        }
        if (!end.is_date) {
            cp += sprintf(cp, " %02u:%02u", end.hour, end.minute);
            if (end.second) cp += sprintf(cp, ":%02u", end.second);
            strcpy(cp, " UTC");
        }
    }

    /* Create multipart/alternative iMIP message */
    fprintf(sm, "From: %s <%s>\r\n",
            originator->qpname ? originator->qpname : "", originator->addr);

    for (recip = recipients; recip; recip = recip->next) {
        if (strcmp(recip->addr, originator->addr)) {
            fprintf(sm, "To: %s <%s>\r\n",
                    recip->qpname ? recip->qpname : "", recip->addr);
        }
    }

    if (summary) {
        char *mimehdr = charset_encode_mimeheader(summary, 0);
        fprintf(sm, "Subject: %s\r\n", mimehdr);
        free(mimehdr);
    }
    else {
        fprintf(sm, "Subject: %s %s\r\n", icalcomponent_kind_to_string(kind),
                icalproperty_method_to_string(meth));
    }

    time_to_rfc822(t, datestr, sizeof(datestr));
    fprintf(sm, "Date: %s\r\n", datestr);

    fprintf(sm, "Message-ID: <cyrus-caldav-%u-%ld-%u@%s>\r\n",
            p, t, send_count++, config_servername);

    /* Create multipart boundary */
    snprintf(boundary, sizeof(boundary), "%s=_%ld=_%ld=_%ld",
             config_servername, (long) p, (long) t, (long) rand());

    fprintf(sm, "Content-Type: multipart/alternative;"
            "\r\n\tboundary=\"%s\"\r\n", boundary);

    fprintf(sm, "iMIP-Content-ID: <%s@%s>\r\n", uid, config_servername);

    fputs("Auto-Submitted: auto-generated\r\n", sm);
    fputs("MIME-Version: 1.0\r\n", sm);
    fputs("\r\n", sm);

    /* preamble */
    fputs("This is a message with multiple parts in MIME format.\r\n", sm);

    /* plain text part */
    fprintf(sm, "\r\n--%s\r\n", boundary);

    fputs("Content-Type: text/plain; charset=utf-8\r\n", sm);
    fputs("Content-Transfer-Encoding: quoted-printable\r\n", sm);
    fputs("Content-Disposition: inline\r\n", sm);
    fputs("\r\n", sm);

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
                                         buf_len(&plainbuf), &outlen);
    buf_free(&plainbuf);
    fwrite(mimebody, outlen, 1, sm);
    free(mimebody);

    /* HTML part */
    fprintf(sm, "\r\n--%s\r\n", boundary);

    fprintf(sm, "Content-Type: text/html; charset=utf-8\r\n");
    fputs("Content-Disposition: inline\r\n", sm);
    fputs("\r\n", sm);

    fputs(HTML_DOCTYPE "\r\n<html><head><title></title></head><body>\r\n", sm);

    if (originator->name) {
        HTMLencode(&tmpbuf, originator->name);
        originator->name = buf_cstring(&tmpbuf);
    }
    else originator->name = originator->addr;

    fprintf(sm, "<b>You have received %s from"
            " <a href=\"mailto:%s\">%s</a></b><p>\r\n",
            msg_type, originator->addr, originator->name);

    fputs("<table border cellpadding=5>\r\n", sm);
    if (summary) {
        HTMLencode(&tmpbuf, summary);
        fprintf(sm, HTML_ROW, "Summary", buf_cstring(&tmpbuf));
    }
    if (location) {
        HTMLencode(&tmpbuf, location);
        fprintf(sm, HTML_ROW, "Location", buf_cstring(&tmpbuf));
    }
    fprintf(sm, HTML_ROW, "When", when);
    if (meth == ICAL_METHOD_REPLY) {
        if (originator->partstat)
            fprintf(sm, HTML_ROW, "RSVP", originator->partstat);
    }
    else {
        if (status) fprintf(sm, HTML_ROW, "Status", status);

        fputs("<tr><td><b>Attendees</b></td>", sm);
        for (cp = "<td>", recip = recipients; recip; recip = recip->next) {
            if (recip->name) {
                HTMLencode(&tmpbuf, recip->name);
                recip->name = buf_cstring(&tmpbuf);
            }
            else recip->name = recip->addr;

            fprintf(sm, "%s&#8226; <a href=\"mailto:%s\">%s</a>",
                    cp, recip->addr, recip->name);
            if (recip->role) fprintf(sm, " <i>(%s)</i>", recip->role);

            cp = "\n  <br>";
        }
        fputs("</td></tr>\r\n", sm);

        if (descrip) {
            HTMLencode(&tmpbuf, descrip);
            fprintf(sm, HTML_ROW, "Description", buf_cstring(&tmpbuf));
        }
    }
    fprintf(sm, "</table></body></html>\r\n");

    /* iCalendar part */
    fprintf(sm, "\r\n--%s\r\n", boundary);

    fprintf(sm, "Content-Type: text/calendar; charset=utf-8");
    fprintf(sm, "; method=%s; component=%s \r\n",
            icalproperty_method_to_string(meth),
            icalcomponent_kind_to_string(kind));

    fputs("Content-Transfer-Encoding: base64\r\n", sm);
    fputs("Content-Disposition: attachment\r\n", sm);

    fprintf(sm, "Content-ID: <%s@%s>\r\n", uid, config_servername);

    fputs("\r\n", sm);

    ical_str = icalcomponent_as_ical_string(ical);
    charset_encode_mimebody(NULL, strlen(ical_str), NULL, &outlen, NULL);
    buf_ensure(&tmpbuf, outlen);
    charset_encode_mimebody(ical_str, strlen(ical_str),
                            (char *) buf_base(&tmpbuf), &outlen, NULL);
    fwrite(buf_base(&tmpbuf), outlen, 1, sm);

    /* end boundary and epilogue */
    fprintf(sm, "\r\n--%s--\r\n\r\nEnd of MIME multipart body.\r\n", boundary);

    fclose(sm);

    while (waitpid(sm_pid, &r, 0) < 0);

  done:
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
    struct sched_param *remote = (struct sched_param *) data;
    struct remote_rock *rrock = (struct remote_rock *) rock;
    icalcomponent *comp;
    struct proplist *list;
    xmlNodePtr resp;
    const char *status = NULL;
    int r;

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

    /* Report request-status (if necesary)
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


static void free_sched_param_props(void *data)
{
    struct sched_param *sched_param = (struct sched_param *) data;

    if (sched_param) {
        struct proplist *prop, *next;

        for (prop = sched_param->props; prop; prop = next) {
            next = prop->next;
            free(prop);
        }
        free(sched_param);
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
    char mailboxname[MAX_MAILBOX_BUFFER];
    icalproperty *prop = NULL, *next;
    const char *uid = NULL, *organizer = NULL;
    struct sched_param sparam;
    struct auth_state *org_authstate = NULL;
    xmlNodePtr root = NULL;
    xmlNsPtr ns[NUM_NAMESPACE];
    struct propfind_ctx fctx;
    struct calquery_filter calfilter;
    struct hash_table remote_table;
    struct sched_param *remote = NULL;

    if (!calendarprefix) {
        calendarprefix = config_getstring(IMAPOPT_CALENDARPREFIX);
    }

    comp = icalcomponent_get_first_real_component(ical);
    uid = icalcomponent_get_uid(comp);

    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    organizer = icalproperty_get_organizer(prop);

    /* XXX  Do we need to do more checks here? */
    if (caladdress_lookup(organizer, &sparam, httpd_userid) ||
        (sparam.flags & SCHEDTYPE_REMOTE))
        org_authstate = auth_newstate("anonymous");
    else
        org_authstate = auth_newstate(sparam.userid);

    /* Start construction of our schedule-response */
    if (!(root =
          init_xml_response("schedule-response",
                            (txn->req_tgt.allow & ALLOW_ISCHEDULE) ? NS_ISCHED :
                            NS_CALDAV, NULL, ns))) {
        ret = HTTP_SERVER_ERROR;
        txn->error.desc = "Unable to create XML response\r\n";
        goto done;
    }

    /* Need DAV for hrefs */
    ensure_ns(ns, NS_DAV, root, XML_NS_DAV, "D");

    /* Populate our filter and propfind context for local attendees */
    memset(&calfilter, 0, sizeof(struct calquery_filter));
    calfilter.comp =
        CAL_COMP_VEVENT | CAL_COMP_VFREEBUSY | CAL_COMP_VAVAILABILITY;
    calfilter.start = icalcomponent_get_dtstart(comp);
    calfilter.end = icalcomponent_get_dtend(comp);
    calfilter.flags = BUSYTIME_QUERY | CHECK_CAL_TRANSP | CHECK_USER_AVAIL;

    memset(&fctx, 0, sizeof(struct propfind_ctx));
    fctx.req_tgt = &txn->req_tgt;
    fctx.depth = 2;
    fctx.userid = httpd_userid;
    fctx.userisadmin = httpd_userisadmin;
    fctx.authstate = org_authstate;
    fctx.reqd_privs = 0;  /* handled by CALDAV:schedule-deliver on Inbox */
    fctx.filter = apply_calfilter;
    fctx.filter_crit = &calfilter;
    fctx.err = &txn->error;
    fctx.ret = &ret;
    fctx.fetcheddata = 0;

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
        r = caladdress_lookup(attendee, &sparam, httpd_userid);

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
                remote = xzmalloc(sizeof(struct sched_param));
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

            resp =
                xml_add_schedresponse(root,
                                      !(txn->req_tgt.allow & ALLOW_ISCHEDULE) ?
                                      ns[NS_DAV] : NULL,
                                      BAD_CAST attendee, NULL);

            /* XXX - BROKEN WITH DOMAIN SPLIT, POS */
            /* Check ACL of ORGANIZER on attendee's Scheduling Inbox */
            snprintf(mailboxname, sizeof(mailboxname),
                     "user.%s.%s.Inbox", userid, calendarprefix);

            r = mboxlist_lookup(mailboxname, NULL, NULL);
            if (r) {
                syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
                       mailboxname, error_message(r));
                xmlNewChild(resp, NULL, BAD_CAST "request-status",
                            BAD_CAST REQSTAT_REJECTED);
            }
            else {
                /* Start query at attendee's calendar-home-set */
                snprintf(mailboxname, sizeof(mailboxname),
                         "user.%s.%s", userid, calendarprefix);

                fctx.davdb = NULL;
                fctx.req_tgt->collection = NULL;
                calfilter.freebusy.len = 0;
                busy = busytime_query_local(txn, &fctx, mailboxname,
                                            ICAL_METHOD_REPLY, uid,
                                            organizer, attendee);
            }

            if (busy) {
                xmlNodePtr cdata;
                char *fb_str = mime->to_string(busy, NULL);
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
                            xmlNewCDataBlock(root->doc, BAD_CAST fb_str,
                                             strlen(fb_str)));
                free(fb_str);

                /* iCalendar data in response should not be transformed */
                txn->flags.cc |= CC_NOTRANSFORM;
            }
            else {
                xmlNewChild(resp, NULL, BAD_CAST "request-status",
                            BAD_CAST REQSTAT_NOUSER);
            }

            icalproperty_free(prop);
        }
    }

    buf_reset(&txn->buf);

    if (remote) {
        struct remote_rock rrock = { txn, ical, root, ns };
        hash_enumerate(&remote_table, busytime_query_remote, &rrock);
    }
    free_hash_table(&remote_table, free_sched_param_props);

    /* Output the XML response */
    if (!ret) xml_response(HTTP_OK, txn, root->doc);

  done:
    if (org_authstate) auth_freestate(org_authstate);
    if (calfilter.freebusy.fb) free(calfilter.freebusy.fb);
    if (root) xmlFreeDoc(root->doc);

    return ret;
}


static void free_sched_data(void *data)
{
    struct sched_data *sched_data = (struct sched_data *) data;

    if (sched_data) {
        if (sched_data->itip) icalcomponent_free(sched_data->itip);
        free(sched_data);
    }
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
static void sched_deliver_remote(const char *recipient,
                                 struct sched_param *sparam,
                                 struct sched_data *sched_data)
{
    int r;

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
        /* Use iMIP */
        r = imip_send(sched_data->itip);
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


#ifdef HAVE_VPOLL
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
    icalcomponent_add_component(ical, icalcomponent_new_clone(new_ballot));
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

        icalcomponent_add_component(oldpoll, icalcomponent_new_clone(vvoter));
    }

    return deliver_inbox;
}


static void sched_pollstatus(const char *organizer,
                             struct sched_param *sparam, icalcomponent *ical,
                             const char *voter)
{
    struct auth_state *authstate;
    struct sched_data sched_data;
    icalcomponent *itip, *comp;
    icalproperty *prop;

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
    if (prop) icalcomponent_add_property(itip, icalproperty_new_clone(prop));

    /* Process each VPOLL in resource */
    for (comp = icalcomponent_get_first_component(ical, ICAL_VPOLL_COMPONENT);
         comp;
         comp =icalcomponent_get_next_component(ical, ICAL_VPOLL_COMPONENT)) {

        icalcomponent *stat, *poll, *sub, *next;
        struct strlist *voters = NULL;

        /* Make a working copy of the iTIP */
        stat = icalcomponent_new_clone(itip);

        /* Make a working copy of the VPOLL and add to pollstatus */
        poll = icalcomponent_new_clone(comp);
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
                    appendstrlist(&voters, (char *) this_voter);

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
        while (voters) {
            struct strlist *next = voters->next;

            sched_data.itip = stat;
            sched_deliver(voters->s, &sched_data, authstate);

            free(voters->s);
            free(voters);
            voters = next;
        }

        icalcomponent_free(stat);
    }

    icalcomponent_free(itip);
    auth_freestate(authstate);
}
#else  /* HAVE_VPOLL */
static void
deliver_merge_vpoll_reply(icalcomponent *ical __attribute__((unused)),
                          icalcomponent *reply __attribute__((unused)))
{
    return;
}

static void sched_vpoll_reply(icalcomponent *poll __attribute__((unused)))
{
    return;
}

static int
deliver_merge_pollstatus(icalcomponent *ical __attribute__((unused)),
                         icalcomponent *request __attribute__((unused)))
{
    return 0;
}

static void sched_pollstatus(const char *organizer __attribute__((unused)),
                             struct sched_param *sparam __attribute__((unused)),
                             icalcomponent *ical __attribute__((unused)),
                             const char *voter __attribute__((unused)))
{
    return;
}
#endif  /* HAVE_VPOLL */


static const char *deliver_merge_reply(icalcomponent *ical,
                                       icalcomponent *reply)
{
    struct hash_table comp_table;
    icalcomponent *comp, *itip;
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
        else recurid = "";

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
            /* New recurrence overridden by attendee.
               Create a new recurrence from master component. */
            comp = icalcomponent_new_clone(hash_lookup("", &comp_table));

            /* Add RECURRENCE-ID */
            icalcomponent_add_property(comp, icalproperty_new_clone(prop));

            /* Remove RRULE */
            prop = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
            if (prop) {
                icalcomponent_remove_property(comp, prop);
                icalproperty_free(prop);
            }

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
                icalcomponent_add_property(comp, icalproperty_new_clone(prop));

            prop =
                icalcomponent_get_first_property(comp, ICAL_DTEND_PROPERTY);
            if (prop) {
                icalcomponent_remove_property(comp, prop);
                icalproperty_free(prop);
            }
            prop =
                icalcomponent_get_first_property(itip, ICAL_DTEND_PROPERTY);
            if (prop)
                icalcomponent_add_property(comp, icalproperty_new_clone(prop));

            prop =
                icalcomponent_get_first_property(comp, ICAL_SEQUENCE_PROPERTY);
            if (prop) {
                icalcomponent_remove_property(comp, prop);
                icalproperty_free(prop);
            }
            prop =
                icalcomponent_get_first_property(itip, ICAL_SEQUENCE_PROPERTY);
            if (prop)
                icalcomponent_add_property(comp, icalproperty_new_clone(prop));

            icalcomponent_add_component(ical, comp);
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
            prop = icalproperty_new_clone(att);
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
    const char *tzid, *recurid;

    /* Add each VTIMEZONE of old object to hash table for comparison */
    construct_hash_table(&comp_table, 10, 1);
    for (comp =
             icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
         comp;
         comp =
             icalcomponent_get_next_component(ical, ICAL_VTIMEZONE_COMPONENT)) {
        prop = icalcomponent_get_first_property(comp, ICAL_TZID_PROPERTY);
        tzid = icalproperty_get_tzid(prop);

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

        comp = hash_lookup(tzid, &comp_table);
        if (comp) {
            /* Remove component from old object */
            icalcomponent_remove_component(ical, comp);
            icalcomponent_free(comp);
        }

        /* Add new/modified component from iTIP request */
        icalcomponent_add_component(ical, icalcomponent_new_clone(itip));
    }

    free_hash_table(&comp_table, NULL);

    /* Add each component of old object to hash table for comparison */
    construct_hash_table(&comp_table, 10, 1);
    comp = icalcomponent_get_first_real_component(ical);
    if (comp) kind = icalcomponent_isa(comp);
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
        icalcomponent *new_comp = icalcomponent_new_clone(itip);

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

            /* Copy over any COMPLETED, PERCENT-COMPLETE,
               or TRANSP properties */
            prop =
                icalcomponent_get_first_property(comp, ICAL_COMPLETED_PROPERTY);
            if (prop) {
                icalcomponent_add_property(new_comp,
                                           icalproperty_new_clone(prop));
            }
            prop =
                icalcomponent_get_first_property(comp,
                                                 ICAL_PERCENTCOMPLETE_PROPERTY);
            if (prop) {
                icalcomponent_add_property(new_comp,
                                           icalproperty_new_clone(prop));
            }
            prop =
                icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
            if (prop) {
                icalcomponent_add_property(new_comp,
                                           icalproperty_new_clone(prop));
            }

            /* Copy over any ORGANIZER;SCHEDULE-STATUS */
            /* XXX  Do we only do this iff PARTSTAT!=NEEDS-ACTION */
            prop =
                icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
            param = icalproperty_get_schedulestatus_parameter(prop);
            if (param) {
                param = icalparameter_new_clone(param);
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
static void sched_deliver_local(const char *recipient,
                                struct sched_param *sparam,
                                struct sched_data *sched_data,
                                struct auth_state *authstate)
{
    int r = 0, rights, reqd_privs, deliver_inbox = 1;
    const char *userid = sparam->userid, *attendee = NULL;
    static struct buf resource = BUF_INITIALIZER;
    static unsigned sched_count = 0;
    const char *mailboxname = NULL;
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

    /* Start with an empty (clean) transaction */
    memset(&txn, 0, sizeof(struct transaction_t));

    /* Check ACL of sender on recipient's Scheduling Inbox */
    mailboxname = caldav_mboxname(userid, SCHED_INBOX);
    r = mboxlist_lookup(mailboxname, &mbentry, NULL);
    if (r) {
        syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
               mailboxname, error_message(r));
        sched_data->status =
            sched_data->ischedule ? REQSTAT_REJECTED : SCHEDSTAT_REJECTED;
        goto done;
    }

    rights = httpd_myrights(authstate, mbentry->acl);
    mboxlist_entry_free(&mbentry);

    reqd_privs = sched_data->is_reply ? DACL_REPLY : DACL_INVITE;
    if (!(rights & reqd_privs)) {
        sched_data->status =
            sched_data->ischedule ? REQSTAT_NOPRIVS : SCHEDSTAT_NOPRIVS;
        syslog(LOG_DEBUG, "No scheduling receive ACL for user %s on Inbox %s",
               httpd_userid, userid);
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

    /* Get METHOD of the iTIP message */
    method = icalcomponent_get_method(sched_data->itip);

    /* Search for iCal UID in recipient's calendars */
    caldavdb = caldav_open_userid(userid);
    if (!caldavdb) {
        sched_data->status =
            sched_data->ischedule ? REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
        goto done;
    }

    caldav_lookup_uid(caldavdb,
                      icalcomponent_get_uid(sched_data->itip), &cdata);

    if (cdata->dav.mailbox) {
        mailboxname = cdata->dav.mailbox;
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
        mailboxname = caldav_mboxname(userid, SCHED_DEFAULT);
        buf_reset(&resource);
        buf_printf(&resource, "%s.ics",
                   icalcomponent_get_uid(sched_data->itip));

        /* Create new attendee object */
        ical = icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT, 0);

        /* Copy over VERSION property */
        prop = icalcomponent_get_first_property(sched_data->itip,
                                                ICAL_VERSION_PROPERTY);
        icalcomponent_add_property(ical, icalproperty_new_clone(prop));

        /* Copy over PRODID property */
        prop = icalcomponent_get_first_property(sched_data->itip,
                                                ICAL_PRODID_PROPERTY);
        icalcomponent_add_property(ical, icalproperty_new_clone(prop));

        /* Copy over any CALSCALE property */
        prop = icalcomponent_get_first_property(sched_data->itip,
                                                ICAL_CALSCALE_PROPERTY);
        if (prop) {
            icalcomponent_add_property(ical,
                                       icalproperty_new_clone(prop));
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
        struct index_record record;

        /* Load message containing the resource and parse iCal data */
        r = mailbox_find_index_record(mailbox, cdata->dav.imap_uid, &record);
        ical = record_to_ical(mailbox, &record);

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
#ifdef HAVE_VPOLL
            case ICAL_VPOLL_COMPONENT:
                if (cdata->comp_type != CAL_COMP_VPOLL) reject = 1;
                break;
#endif
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

                    if (!strncasecmp(organizer, "mailto:", 7)) organizer += 7;
                    if (strcmp(cdata->organizer, organizer)) reject = 1;
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
    if (!r) r = caldav_store_resource(&txn, ical, mailbox,
                                      buf_cstring(&resource), caldavdb, NEW_STAG);

    if (r == HTTP_CREATED || r == HTTP_NO_CONTENT) {
        sched_data->status =
            sched_data->ischedule ? REQSTAT_SUCCESS : SCHEDSTAT_DELIVERED;
    }
    else {
        syslog(LOG_ERR, "caldav_store_resource(%s) failed: %s (%s)",
               mailbox->name, error_message(r), txn.error.resource);
        sched_data->status =
            sched_data->ischedule ? REQSTAT_TEMPFAIL : SCHEDSTAT_TEMPFAIL;
        goto done;
    }

  inbox:
    if (deliver_inbox) {
        /* Create a name for the new iTIP message resource */
        buf_reset(&resource);
        buf_printf(&resource, "%x-%d-%ld-%u.ics",
                   strhash(icalcomponent_get_uid(sched_data->itip)), getpid(),
                   time(0), sched_count++);

        /* Store the message in the recipient's Inbox */
        r = caldav_store_resource(&txn, sched_data->itip, inbox,
                                  buf_cstring(&resource), caldavdb, 0);
        /* XXX  What do we do if storing to Inbox fails? */
    }

    /* XXX  Should this be a config option? - it might have perf implications */
    if (sched_data->is_reply) {
        /* Send updates to attendees - skipping sender of reply */
        comp = icalcomponent_get_first_real_component(ical);
        if (icalcomponent_isa(comp) == ICAL_VPOLL_COMPONENT)
            sched_pollstatus(recipient, sparam, ical, attendee);
        else
            sched_request(recipient, sparam, NULL, ical, attendee);
    }

  done:
    if (ical) icalcomponent_free(ical);
    mailbox_close(&inbox);
    mailbox_close(&mailbox);
    if (caldavdb) caldav_close(caldavdb);
    spool_free_hdrcache(txn.req_hdrs);
    buf_free(&txn.buf);
}


/* Deliver scheduling object to recipient's Inbox */
void sched_deliver(const char *recipient, void *data, void *rock)
{
    struct sched_data *sched_data = (struct sched_data *) data;
    struct auth_state *authstate = (struct auth_state *) rock;
    struct sched_param sparam;
    int islegal;

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

    if (caladdress_lookup(recipient, &sparam, httpd_userid)) {
        sched_data->status =
            sched_data->ischedule ? REQSTAT_NOUSER : SCHEDSTAT_NOUSER;
        /* Unknown user */
        return;
    }

    /* don't schedule to yourself */
    if (sparam.isyou) return;

    if (sparam.flags) {
        /* Remote recipient */
        sched_deliver_remote(recipient, &sparam, sched_data);
    }
    else {
        /* Local recipient */
        sched_deliver_local(recipient, &sparam, sched_data, authstate);
    }
}


struct comp_data {
    icalcomponent *comp;
    icalparameter_partstat partstat;
    int sequence;
};

static void free_comp_data(void *data) {
    struct comp_data *comp_data = (struct comp_data *) data;

    if (comp_data) {
        if (comp_data->comp) icalcomponent_free(comp_data->comp);
        free(comp_data);
    }
}


/*
 * sched_request/reply() helper function
 *
 * Update DTSTAMP, remove VALARMs,
 * optionally remove scheduling params from ORGANIZER
 */
static void clean_component(icalcomponent *comp, int clean_org)
{
    icalcomponent *alarm, *next;
    icalproperty *prop;

    /* Replace DTSTAMP on component */
    prop = icalcomponent_get_first_property(comp,
                                            ICAL_DTSTAMP_PROPERTY);
    icalcomponent_remove_property(comp, prop);
    icalproperty_free(prop);
    prop =
        icalproperty_new_dtstamp(icaltime_current_time_with_zone(utc_zone));
    icalcomponent_add_property(comp, prop);

    /* Remove any VALARM components */
    for (alarm = icalcomponent_get_first_component(comp, ICAL_VALARM_COMPONENT);
         alarm; alarm = next) {
        next = icalcomponent_get_next_component(comp, ICAL_VALARM_COMPONENT);
        icalcomponent_remove_component(comp, alarm);
        icalcomponent_free(alarm);
    }

    if (clean_org) {
        /* Grab the organizer */
        prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);

        /* Remove CalDAV Scheduling parameters from organizer */
        icalproperty_remove_parameter_by_name(prop, "SCHEDULE-AGENT");
        icalproperty_remove_parameter_by_name(prop, "SCHEDULE-FORCE-SEND");
    }
}


/*
 * sched_request() helper function
 *
 * Add EXDATE to master component if attendee is excluded from recurrence
 */
struct exclude_rock {
    unsigned ncomp;
    icalcomponent *comp;
};

static void sched_exclude(const char *attendee __attribute__((unused)),
                          void *data, void *rock)
{
    struct sched_data *sched_data = (struct sched_data *) data;
    struct exclude_rock *erock = (struct exclude_rock *) rock;

    if (!(sched_data->comp_mask & (1<<erock->ncomp))) {
        icalproperty *recurid, *exdate;
        struct icaltimetype exdt;
        icalparameter *param;

        /* Fetch the RECURRENCE-ID and use it to create a new EXDATE */
        recurid = icalcomponent_get_first_property(erock->comp,
                                                   ICAL_RECURRENCEID_PROPERTY);
        exdt = icalproperty_get_recurrenceid(recurid);

        exdate = icalproperty_new_exdate(exdt);

        /* Copy any parameters from RECURRENCE-ID to EXDATE */
        param = icalproperty_get_first_parameter(recurid, ICAL_TZID_PARAMETER);
        if (param) {
            icalproperty_add_parameter(exdate, icalparameter_new_clone(param));
        }
        param = icalproperty_get_first_parameter(recurid, ICAL_VALUE_PARAMETER);
        if (param) {
            icalproperty_add_parameter(exdate, icalparameter_new_clone(param));
        }
        /* XXX  Need to handle RANGE parameter */

        /* Add the EXDATE to the master component for this attendee */
        icalcomponent_add_property(sched_data->master, exdate);
    }
}


/*
 * sched_request() helper function
 *
 * Process all attendees in the given component and add a
 * properly modified component to the attendee's iTIP request if necessary
 */
static void process_attendees(icalcomponent *comp, unsigned ncomp,
                              const char *organizer, const char *att_update,
                              struct hash_table *att_table,
                              icalcomponent *itip, unsigned needs_action)
{
    icalcomponent *copy;
    icalproperty *prop;
    icalparameter *param;

    /* Strip SCHEDULE-STATUS from each attendee
       and optionally set PARTSTAT=NEEDS-ACTION */
    for (prop = icalcomponent_get_first_invitee(comp);
         prop;
         prop = icalcomponent_get_next_invitee(comp)) {

        const char *attendee = icalproperty_get_invitee(prop);

        /* Don't modify attendee == organizer */
        if (!strcmp(attendee, organizer)) continue;

        icalproperty_remove_parameter_by_name(prop, "SCHEDULE-STATUS");

        if (needs_action) {
            /* Set PARTSTAT */
            param = icalparameter_new_partstat(ICAL_PARTSTAT_NEEDSACTION);
            icalproperty_set_parameter(prop, param);
        }
    }

    /* Clone a working copy of the component */
    copy = icalcomponent_new_clone(comp);

    clean_component(copy, 0);

    /* Process each attendee */
    for (prop = icalcomponent_get_first_invitee(copy);
         prop;
         prop = icalcomponent_get_next_invitee(copy)) {
        unsigned do_sched = 1;
        icalparameter_scheduleforcesend force_send =
            ICAL_SCHEDULEFORCESEND_NONE;
        const char *attendee = icalproperty_get_invitee(prop);

        /* Don't schedule attendee == organizer */
        if (!strcmp(attendee, organizer)) continue;

        /* Don't send an update to the attendee that just sent a reply */
        if (att_update && !strcmp(attendee, att_update)) continue;

        /* Check CalDAV Scheduling parameters */
        param = icalproperty_get_scheduleagent_parameter(prop);
        if (param) {
            icalparameter_scheduleagent agent =
                icalparameter_get_scheduleagent(param);

            if (agent != ICAL_SCHEDULEAGENT_SERVER) do_sched = 0;
            icalproperty_remove_parameter_by_ref(prop, param);
        }

        param = icalproperty_get_scheduleforcesend_parameter(prop);
        if (param) {
            force_send = icalparameter_get_scheduleforcesend(param);
            icalproperty_remove_parameter_by_ref(prop, param);
        }

        /* Create/update iTIP request for this attendee */
        if (do_sched) {
            struct sched_data *sched_data;
            icalcomponent *new_comp;

            sched_data = hash_lookup(attendee, att_table);
            if (!sched_data) {
                /* New attendee - add it to the hash table */
                sched_data = xzmalloc(sizeof(struct sched_data));
                sched_data->itip = icalcomponent_new_clone(itip);
                sched_data->force_send = force_send;
                hash_insert(attendee, sched_data, att_table);
            }
            new_comp = icalcomponent_new_clone(copy);
            icalcomponent_add_component(sched_data->itip, new_comp);
            sched_data->comp_mask |= (1 << ncomp);

            /* XXX  We assume that the master component is always first */
            if (!ncomp) sched_data->master = new_comp;
        }
    }

    /* XXX  We assume that the master component is always first */
    if (ncomp) {
        /* Handle attendees that are excluded from this recurrence */
        struct exclude_rock erock = { ncomp, copy };

        hash_enumerate(att_table, sched_exclude, &erock);
    }

    icalcomponent_free(copy);
}


/*
 * sched_request() helper function
 *
 * Organizer removed this component, mark it as cancelled for all attendees
 */
struct cancel_rock {
    const char *organizer;
    struct hash_table *att_table;
    icalcomponent *itip;
};

static void sched_cancel(const char *recurid __attribute__((unused)),
                         void *data, void *rock)
{
    struct comp_data *old_data = (struct comp_data *) data;
    struct cancel_rock *crock = (struct cancel_rock *) rock;

    /* Deleting the object -- set STATUS to CANCELLED for component */
    icalcomponent_set_status(old_data->comp, ICAL_STATUS_CANCELLED);
    icalcomponent_set_sequence(old_data->comp, old_data->sequence+1);

    process_attendees(old_data->comp, 0, crock->organizer, NULL,
                      crock->att_table, crock->itip, 0);
}


/*
 * Compare the properties of the given kind in two components.
 * Returns 0 if equal, 1 otherwise.
 *
 * If the property exists in neither comp, then they are equal.
 * If the property exists in only 1 comp, then they are not equal.
 * if the property is RDATE or EXDATE, create an MD5 hash of all
 *   property strings for each component and compare the hashes.
 * Otherwise compare the two property strings.
 */
static unsigned propcmp(icalcomponent *oldical, icalcomponent *newical,
                        icalproperty_kind kind)
{
    icalproperty *oldprop = icalcomponent_get_first_property(oldical, kind);
    icalproperty *newprop = icalcomponent_get_first_property(newical, kind);

    if (!oldprop) return (newprop != NULL);
    else if (!newprop) return 1;
    else if ((kind == ICAL_RDATE_PROPERTY) || (kind == ICAL_EXDATE_PROPERTY)) {
        MD5_CTX ctx;
        const char *str;
        unsigned char old_md5[MD5_DIGEST_LENGTH], new_md5[MD5_DIGEST_LENGTH];

        MD5Init(&ctx);
        do {
            str = icalproperty_get_value_as_string(oldprop);
            MD5Update(&ctx, str, strlen(str));
        } while ((oldprop = icalcomponent_get_next_property(oldical, kind)));

        MD5Final(old_md5, &ctx);

        MD5Init(&ctx);
        do {
            str = icalproperty_get_value_as_string(newprop);
            MD5Update(&ctx, str, strlen(str));
        } while ((newprop = icalcomponent_get_next_property(newical, kind)));

        MD5Final(new_md5, &ctx);

        return (memcmp(old_md5, new_md5, MD5_DIGEST_LENGTH) != 0);
    }
    else {
        return (strcmp(icalproperty_get_value_as_string(oldprop),
                       icalproperty_get_value_as_string(newprop)) != 0);
    }
}


/* Create and deliver an organizer scheduling request */
void sched_request(const char *organizer, struct sched_param *sparam,
                   icalcomponent *oldical, icalcomponent *newical,
                   const char *att_update)
{
    int r;
    icalproperty_method method;
    struct auth_state *authstate;
    icalcomponent *ical, *req, *comp;
    icalproperty *prop;
    icalcomponent_kind kind;
    struct hash_table att_table, comp_table;
    const char *sched_stat = NULL, *recurid;
    struct comp_data *old_data;

    /* Check what kind of action we are dealing with */
    if (!newical) {
        /* Remove */
        ical = oldical;
        method = ICAL_METHOD_CANCEL;
    }
    else {
        /* Create / Modify */
        ical = newical;
        method = ICAL_METHOD_REQUEST;
    }

    if (!att_update) {
        int rights = 0;
        mbentry_t *mbentry = NULL;
        /* Check ACL of auth'd user on userid's Scheduling Outbox */
        char *outboxname = caldav_mboxname(sparam->userid, SCHED_OUTBOX);

        r = mboxlist_lookup(outboxname, &mbentry, NULL);
        if (r) {
            syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
                   outboxname, error_message(r));
        }
        else {
            rights = httpd_myrights(httpd_authstate, mbentry->acl);
        }
        free(outboxname);
        mboxlist_entry_free(&mbentry);

        if (!(rights & DACL_INVITE)) {
            /* DAV:need-privileges */
            sched_stat = SCHEDSTAT_NOPRIVS;
            syslog(LOG_DEBUG, "No scheduling send ACL for user %s on Outbox %s",
                   httpd_userid, sparam->userid);

            goto done;
        }
    }

    /* Create a shell for our iTIP request objects */
    req = icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT,
                              icalproperty_new_version("2.0"),
                              icalproperty_new_prodid(ical_prodid),
                              icalproperty_new_method(method),
                              0);

    /* XXX  Make sure SEQUENCE is incremented */

    /* Copy over any CALSCALE property */
    prop = icalcomponent_get_first_property(ical, ICAL_CALSCALE_PROPERTY);
    if (prop) {
        icalcomponent_add_property(req,
                                   icalproperty_new_clone(prop));
    }

    /* Copy over any VTIMEZONE components */
    for (comp = icalcomponent_get_first_component(ical,
                                                  ICAL_VTIMEZONE_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical,
                                                 ICAL_VTIMEZONE_COMPONENT)) {
         icalcomponent_add_component(req,
                                     icalcomponent_new_clone(comp));
    }

    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);

    /* Add each component of old object to hash table for comparison */
    construct_hash_table(&comp_table, 10, 1);

    if (!att_update && oldical) {
        comp = icalcomponent_get_first_real_component(oldical);

        /* If the existing object isn't a scheduling object,
           we don't need to compare components, treat them as new */
        if (icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY)) {
            do {
                old_data = xzmalloc(sizeof(struct comp_data));
                old_data->comp = comp;
                old_data->sequence = icalcomponent_get_sequence(comp);

                prop =
                    icalcomponent_get_first_property(comp,
                                                     ICAL_RECURRENCEID_PROPERTY);
                if (prop) recurid = icalproperty_get_value_as_string(prop);
                else recurid = "";

                hash_insert(recurid, old_data, &comp_table);

            } while ((comp = icalcomponent_get_next_component(oldical, kind)));
        }
    }

    /* Create hash table of attendees */
    construct_hash_table(&att_table, 10, 1);

    /* Process each component of new object */
    if (newical) {
        unsigned ncomp = 0;

        comp = icalcomponent_get_first_real_component(newical);
        do {
            unsigned changed = 1, needs_action = 0;

            prop = icalcomponent_get_first_property(comp,
                                                    ICAL_RECURRENCEID_PROPERTY);
            if (prop) recurid = icalproperty_get_value_as_string(prop);
            else recurid = "";

            old_data = hash_del(recurid, &comp_table);

            if (old_data) {
                /* Per RFC 6638, Section 3.2.8: We need to compare
                   DTSTART, DTEND, DURATION, DUE, RRULE, RDATE, EXDATE */
                if (propcmp(old_data->comp, comp, ICAL_DTSTART_PROPERTY))
                    needs_action = 1;
                else if (propcmp(old_data->comp, comp, ICAL_DTEND_PROPERTY))
                    needs_action = 1;
                else if (propcmp(old_data->comp, comp, ICAL_DURATION_PROPERTY))
                    needs_action = 1;
                else if (propcmp(old_data->comp, comp, ICAL_DUE_PROPERTY))
                    needs_action = 1;
                else if (propcmp(old_data->comp, comp, ICAL_RRULE_PROPERTY))
                    needs_action = 1;
                else if (propcmp(old_data->comp, comp, ICAL_RDATE_PROPERTY))
                    needs_action = 1;
                else if (propcmp(old_data->comp, comp, ICAL_EXDATE_PROPERTY))
                    needs_action = 1;
                else if (kind == ICAL_VPOLL_COMPONENT) {
                }

                if (needs_action &&
                    (old_data->sequence >= icalcomponent_get_sequence(comp))) {
                    /* Make sure SEQUENCE is set properly */
                    icalcomponent_set_sequence(comp,
                                               old_data->sequence + 1);
                }

                free(old_data);
            }

            if (changed) {
                /* Process all attendees in created/modified components */
                process_attendees(comp, ncomp++, organizer, att_update,
                                  &att_table, req, needs_action);
            }

        } while ((comp = icalcomponent_get_next_component(newical, kind)));
    }

    if (oldical) {
        /* Cancel any components that have been left behind in the old obj */
        struct cancel_rock crock = { organizer, &att_table, req };

        hash_enumerate(&comp_table, sched_cancel, &crock);
    }
    free_hash_table(&comp_table, free);

    icalcomponent_free(req);

    /* Attempt to deliver requests to attendees */
    /* XXX  Do we need to do more checks here? */
    if (sparam->flags & SCHEDTYPE_REMOTE)
        authstate = auth_newstate("anonymous");
    else
        authstate = auth_newstate(sparam->userid);

    hash_enumerate(&att_table, sched_deliver, authstate);
    auth_freestate(authstate);

  done:
    if (newical) {
        unsigned ncomp = 0;

        /* Set SCHEDULE-STATUS for each attendee in organizer object */
        comp = icalcomponent_get_first_real_component(newical);
        kind = icalcomponent_isa(comp);

        do {
            for (prop = icalcomponent_get_first_invitee(comp);
                 prop;
                 prop = icalcomponent_get_next_invitee(comp)) {
                const char *stat = NULL;
                const char *attendee = icalproperty_get_invitee(prop);

                /* Don't set status if attendee == organizer */
                if (!strcmp(attendee, organizer)) continue;

                if (sched_stat) stat = sched_stat;
                else {
                    struct sched_data *sched_data;

                    sched_data = hash_lookup(attendee, &att_table);
                    if (sched_data && (sched_data->comp_mask & (1 << ncomp)))
                        stat = sched_data->status;
                }

                if (stat) {
                    /* Set SCHEDULE-STATUS */
                    icalparameter *param;

                    param = icalparameter_new_schedulestatus(stat);
                    icalproperty_set_parameter(prop, param);
                }
            }

            ncomp++;
        } while ((comp = icalcomponent_get_next_component(newical, kind)));
    }

    /* Cleanup */
    if (!sched_stat) free_hash_table(&att_table, free_sched_data);
}


/*
 * sched_reply() helper function
 *
 * Remove all attendees from 'comp' other than the one corresponding to 'userid'
 *
 * Returns the new trimmed component (must be freed by caller)
 * Optionally returns the 'attendee' property, his/her 'propstat',
 * and the 'recurid' of the component
 */
static icalcomponent *trim_attendees(icalcomponent *comp, const char *userid,
                                     icalproperty **attendee,
                                     icalparameter_partstat *partstat,
                                     const char **recurid)
{
    icalcomponent *copy;
    icalproperty *prop, *nextprop, *myattendee = NULL;

    if (partstat) *partstat = ICAL_PARTSTAT_NONE;

    /* Clone a working copy of the component */
    copy = icalcomponent_new_clone(comp);

    /* Locate userid in the attendee list (stripping others) */
    for (prop = icalcomponent_get_first_invitee(copy);
         prop;
         prop = nextprop) {
        const char *att = icalproperty_get_invitee(prop);
        struct sched_param sparam;

        nextprop = icalcomponent_get_next_invitee(copy);

        if (!myattendee &&
            !caladdress_lookup(att, &sparam, httpd_userid) &&
            !(sparam.flags & SCHEDTYPE_REMOTE) &&
            !strcmpsafe(sparam.userid, userid)) {
            /* Found it */
            myattendee = prop;

            if (partstat) {
                /* Get the PARTSTAT */
                icalparameter *param =
                    icalproperty_get_first_parameter(myattendee,
                                                     ICAL_PARTSTAT_PARAMETER);
                if (param) *partstat = icalparameter_get_partstat(param);
            }
        }
        else {
            /* Some other attendee, remove it */
            icalcomponent_remove_invitee(copy, prop);
        }

        sched_param_free(&sparam);
    }

    if (attendee) *attendee = myattendee;

    if (recurid) {
        prop = icalcomponent_get_first_property(copy,
                                                ICAL_RECURRENCEID_PROPERTY);
        if (prop) *recurid = icalproperty_get_value_as_string(prop);
        else *recurid = "";
    }


    return copy;
}


/*
 * sched_reply() helper function
 *
 * Attendee removed this component, mark it as declined for the organizer.
 */
static void sched_decline(const char *recurid __attribute__((unused)),
                          void *data, void *rock)
{
    struct comp_data *old_data = (struct comp_data *) data;
    icalcomponent *itip = (icalcomponent *) rock;
    icalproperty *myattendee;
    icalparameter *param;

    /* Don't send a decline for cancelled components */
    if (icalcomponent_get_status(old_data->comp) == ICAL_STATUS_CANCELLED)
        return;

    myattendee = icalcomponent_get_first_property(old_data->comp,
                                                  ICAL_ATTENDEE_PROPERTY);

    param = icalparameter_new_partstat(ICAL_PARTSTAT_DECLINED);
    icalproperty_set_parameter(myattendee, param);

    clean_component(old_data->comp, 1);

    icalcomponent_add_component(itip, old_data->comp);
}


/* Create and deliver an attendee scheduling reply */
void sched_reply(const char *userid,
                 icalcomponent *oldical, icalcomponent *newical)
{
    int r, rights = 0;
    mbentry_t *mbentry = NULL;
    char *outboxname;
    icalcomponent *ical;
    struct sched_data *sched_data;
    struct auth_state *authstate;
    icalcomponent *comp;
    icalproperty *prop;
    icalparameter *param;
    icalcomponent_kind kind;
    icalparameter_scheduleforcesend force_send = ICAL_SCHEDULEFORCESEND_NONE;
    const char *organizer, *recurid;
    struct hash_table comp_table;
    struct comp_data *old_data;

    /* Check what kind of action we are dealing with */
    if (!newical) {
        /* Remove */
        ical = oldical;
    }
    else {
        /* Create / Modify */
        ical = newical;
    }

    /* Check CalDAV Scheduling parameters on the organizer */
    comp = icalcomponent_get_first_real_component(ical);
    kind = icalcomponent_isa(comp);
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    organizer = icalproperty_get_organizer(prop);

    param = icalproperty_get_scheduleagent_parameter(prop);
    if (param &&
        icalparameter_get_scheduleagent(param) != ICAL_SCHEDULEAGENT_SERVER) {
        /* We are not supposed to send replies to the organizer */
        return;
    }

    param = icalproperty_get_scheduleforcesend_parameter(prop);
    if (param) force_send = icalparameter_get_scheduleforcesend(param);

    sched_data = xzmalloc(sizeof(struct sched_data));
    sched_data->is_reply = 1;
    sched_data->force_send = force_send;

    /* Check ACL of auth'd user on userid's Scheduling Outbox */
    outboxname = caldav_mboxname(userid, SCHED_OUTBOX);

    r = mboxlist_lookup(outboxname, &mbentry, NULL);
    if (r) {
        syslog(LOG_INFO, "mboxlist_lookup(%s) failed: %s",
               outboxname, error_message(r));
    }
    else {
        rights = httpd_myrights(httpd_authstate, mbentry->acl);
    }
    free(outboxname);
    mboxlist_entry_free(&mbentry);

    if (!(rights & DACL_REPLY)) {
        /* DAV:need-privileges */
        if (newical) sched_data->status = SCHEDSTAT_NOPRIVS;
        syslog(LOG_DEBUG, "No scheduling send ACL for user %s on Outbox %s",
               httpd_userid, userid);

        goto done;
    }

    /* Create our reply iCal object */
    sched_data->itip =
        icalcomponent_vanew(ICAL_VCALENDAR_COMPONENT,
                            icalproperty_new_version("2.0"),
                            icalproperty_new_prodid(ical_prodid),
                            icalproperty_new_method(ICAL_METHOD_REPLY),
                            0);

    /* XXX  Make sure SEQUENCE is incremented */

    /* Copy over any CALSCALE property */
    prop = icalcomponent_get_first_property(ical, ICAL_CALSCALE_PROPERTY);
    if (prop) {
        icalcomponent_add_property(sched_data->itip,
                                   icalproperty_new_clone(prop));
    }

    /* Copy over any VTIMEZONE components */
    for (comp = icalcomponent_get_first_component(ical,
                                                  ICAL_VTIMEZONE_COMPONENT);
         comp;
         comp = icalcomponent_get_next_component(ical,
                                                 ICAL_VTIMEZONE_COMPONENT)) {
         icalcomponent_add_component(sched_data->itip,
                                     icalcomponent_new_clone(comp));
    }

    /* Add each component of old object to hash table for comparison */
    construct_hash_table(&comp_table, 10, 1);

    if (oldical) {
        comp = icalcomponent_get_first_real_component(oldical);
        do {
            old_data = xzmalloc(sizeof(struct comp_data));

            old_data->comp = trim_attendees(comp, userid, NULL,
                                            &old_data->partstat, &recurid);

            hash_insert(recurid, old_data, &comp_table);

        } while ((comp = icalcomponent_get_next_component(oldical, kind)));
    }

    /* Process each component of new object */
    if (newical) {
        unsigned ncomp = 0;

        comp = icalcomponent_get_first_real_component(newical);
        do {
            icalcomponent *copy;
            icalproperty *myattendee;
            icalparameter_partstat partstat;
            int changed = 1;

            copy = trim_attendees(comp, userid,
                                  &myattendee, &partstat, &recurid);
            if (myattendee) {
                /* Found our userid */
                old_data = hash_del(recurid, &comp_table);

                if (old_data) {
                    if (kind == ICAL_VPOLL_COMPONENT) {
                        /* VPOLL replies always override existing votes */
                        sched_vpoll_reply(copy);
                    }
                    else {
                        /* XXX  Need to check EXDATE */

                        /* Compare PARTSTAT in the two components */
                        if (old_data->partstat == partstat) {
                            changed = 0;
                        }
                    }

                    free_comp_data(old_data);
                }
            }
            else {
                /* Our user isn't in this component */
                /* XXX  Can this actually happen? */
                changed = 0;
            }

            if (changed) {
                clean_component(copy, 1);

                icalcomponent_add_component(sched_data->itip, copy);
                sched_data->comp_mask |= (1 << ncomp);
            }
            else icalcomponent_free(copy);

            ncomp++;
        } while ((comp = icalcomponent_get_next_component(newical, kind)));
    }

    /* Decline any components that have been left behind in the old obj */
    hash_enumerate(&comp_table, sched_decline, sched_data->itip);
    free_hash_table(&comp_table, free_comp_data);

  done:
    if (sched_data->itip &&
        icalcomponent_get_first_real_component(sched_data->itip)) {
        /* We built a reply object */

        if (!sched_data->status) {
            /* Attempt to deliver reply to organizer */
            authstate = auth_newstate(userid);
            sched_deliver(organizer, sched_data, authstate);
            auth_freestate(authstate);
        }

        if (newical) {
            unsigned ncomp = 0;

            /* Set SCHEDULE-STATUS for organizer in attendee object */
            comp = icalcomponent_get_first_real_component(newical);
            do {
                if (sched_data->comp_mask & (1 << ncomp)) {
                    prop =
                        icalcomponent_get_first_property(comp,
                                                         ICAL_ORGANIZER_PROPERTY);
                    param =
                        icalparameter_new_schedulestatus(sched_data->status);
                    icalproperty_add_parameter(prop, param);
                }

                ncomp++;
            } while ((comp = icalcomponent_get_next_component(newical, kind)));
        }
    }

    /* Cleanup */
    free_sched_data(sched_data);
}

void sched_param_free(struct sched_param *sparam) {
    if (sparam->userid) free(sparam->userid);
    if (sparam->server) free(sparam->server);
    if (sparam->props) {
        free_sched_param_props(sparam->props);
    }
    memset(sparam, 0, sizeof(struct sched_param));
}
