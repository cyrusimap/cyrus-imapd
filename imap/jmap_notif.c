/* jmap_notif.c
 *
 * Copyright (c) 1994-2018 Carnegie Mellon University.  All rights reserved.
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

#include "append.h"
#include "dav_util.h"
#include "caldav_util.h"
#include "http_err.h"
#include "imap_err.h"
#include "jmap_ical.h"
#include "strhash.h"
#include "times.h"
#include "user.h"


HIDDEN char *jmap_notifmboxname(const char *userid)
{
    /* Create notification mailbox name from the parsed path */
    mbname_t *mbname = mbname_from_userid(userid);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_JMAPNOTIFICATIONFOLDER));
    char *mboxname = xstrdup(mbname_intname(mbname));
    mbname_free(&mbname);
    return mboxname;
}

HIDDEN int jmap_create_notify_collection(const char *userid, mbentry_t **mbentryptr)
{
    /* notifications collection */
    char *notifmboxname = jmap_notifmboxname(userid);
    struct mailbox *notifmbox = NULL;
    struct mboxlock *namespacelock = NULL;

    int r = mboxlist_lookup(notifmboxname, mbentryptr, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* lock the namespace lock and try again */
        namespacelock = user_namespacelock(userid);

        mbentry_t mbentry = MBENTRY_INITIALIZER;
        mbentry.name = notifmboxname;
        mbentry.mbtype = MBTYPE_JMAPNOTIFY;
        r = mboxlist_createmailbox(&mbentry, 0/*options*/, 0/*highestmodseq*/,
                                   1/*isadmin*/, userid, NULL/*authstate*/,
                                   0/*flags*/, NULL/*mboxptr*/);

        /* we lost the race, that's OK */
        if (r == IMAP_MAILBOX_LOCKED) r = 0;
        if (r) syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                      notifmboxname, error_message(r));

        r = mboxlist_lookup(notifmboxname, mbentryptr, NULL);
        if (r) {
            xsyslog(LOG_ERR, "can not lookup notification mailbox",
                    "mboxname=<%s> err=<%s>", notifmboxname, error_message(r));
            goto done;
        }

        int expire = config_getduration(IMAPOPT_JMAP_NOTIFICATIONS_EXPIRE, 'd');

        if (expire > 0) {
            /* now set it to auto-expire old notifications */
            r = mailbox_open_iwl(notifmboxname, &notifmbox);
            if (r) {
                xsyslog(LOG_ERR, "failed to open notification mailbox",
                        "mboxname=<%s> err=<%s>",
                        notifmboxname, error_message(r));
                goto done;
            }

            annotate_state_t *astate = NULL;
            r = mailbox_get_annotate_state(notifmbox, 0, &astate);
            if (r) {
                xsyslog(LOG_ERR, "can not open annotate state",
                        "mboxname=<%s> err=<%s>",
                        notifmboxname, error_message(r));
                goto done;
            }

            static const char *expire_annot = IMAP_ANNOT_NS "expire";
            struct buf val = BUF_INITIALIZER;
            buf_printf(&val, "%ds", expire);
            r = annotate_state_writemask(astate, expire_annot, "", &val);
            buf_free(&val);
            if (r) {
                xsyslog(LOG_ERR, "failed to write annotation",
                        "annot=<%s> mboxname=<%s> err=<%s>",
                        expire_annot, notifmboxname, error_message(r));
                goto done;
            }
        }
    }

done:
    mailbox_close(&notifmbox);
    if (namespacelock)
        mboxname_release(&namespacelock);
    free(notifmboxname);
    return r;
}

HIDDEN char *jmap_caleventnotif_format_fromheader(const char *userid)
{
    struct buf buf = BUF_INITIALIZER;
    if (strchr(userid, '@')) {
        buf_printf(&buf, "<%s>", userid);
    }
    else {
        buf_printf(&buf, "<%s@%s>", userid, config_servername);
    }
    char *notfrom = charset_encode_mimeheader(buf_cstring(&buf), buf_len(&buf), 0);
    buf_free(&buf);
    return notfrom;
}

static int append_eventnotif(const char *from,
                             const char *authuserid,
                             const struct auth_state *authstate,
                             struct mailbox *notifmbox,
                             const char *calmboxname,
                             time_t created,
                             json_t *jnotif)
{
    struct stagemsg *stage = NULL;
    int r = 0;
    char *notifstr = json_dumps(jnotif, 0);
    struct buf buf = BUF_INITIALIZER;
    const char *type = json_string_value(json_object_get(jnotif, "type"));
    const char *ical_uid = json_string_value(json_object_get(jnotif, "calendarEventId"));

    if (!strcmp(type, "destroyed")) {
        /* Expunge all former event notifications for this UID */
        struct mailbox_iter *iter = mailbox_iter_init(notifmbox, 0, 0);
        message_t *msg;
        while ((msg = (message_t *) mailbox_iter_step(iter))) {
            buf_reset(&buf);
            if (message_get_subject(msg, &buf) ||
                    strcmp(JMAP_NOTIF_CALENDAREVENT, buf_cstring(&buf))) {
                continue;
            }
            const struct body *body;
            if (message_get_cachebody(msg, &body)) {
                continue;
            }
            int matches_uid = 0;
            struct dlist *dl = NULL;
            if (!dlist_parsemap(&dl, 1, 0, body->description,
                        strlen(body->description))) {
                const char *val;
                matches_uid = dlist_getatom(dl, "ID", &val) &&
                              !strcmp(val, ical_uid);
            }
            dlist_free(&dl);
            if (!matches_uid) continue;

            struct index_record record = *msg_record(msg);
            if (!(record.system_flags & FLAG_DELETED) &&
                !(record.internal_flags & FLAG_INTERNAL_EXPUNGED)) {
                record.internal_flags |= FLAG_INTERNAL_EXPUNGED;
                 mailbox_rewrite_index_record(notifmbox, &record);
            }
        }
        mailbox_iter_done(&iter);
    }
    buf_reset(&buf);

    FILE *fp = append_newstage(mailbox_name(notifmbox), created,
            strhash(ical_uid), &stage);
    if (!fp) {
        xsyslog(LOG_ERR, "append_newstage failed", "name=%s", mailbox_name(notifmbox));
        r = HTTP_SERVER_ERROR;
        goto done;
    }

    fputs("From: ", fp);
    fputs(from, fp);
    fputs("\r\n", fp);

    fputs("Subject: " JMAP_NOTIF_CALENDAREVENT "\r\n", fp);

    char date5322[RFC5322_DATETIME_MAX+1];
    time_to_rfc5322(created, date5322, RFC5322_DATETIME_MAX);
    fputs("Date: ", fp);
    fputs(date5322, fp);
    fputs("\r\n", fp);

    fprintf(fp, "Message-ID: <%s-%ld@%s>\r\n", makeuuid(), created, config_servername);
    fputs("Content-Type: application/json; charset=utf-8\r\n", fp);
    fputs("Content-Transfer-Encoding: 8bit\r\n", fp);

    struct dlist *dl = dlist_newkvlist(NULL, "N");
    dlist_setdate(dl, "S", created);
    dlist_setatom(dl, "T", JMAP_NOTIF_CALENDAREVENT);
    dlist_setatom(dl, "ID", ical_uid);
    dlist_setatom(dl, "NT", type);
    dlist_setatom(dl, "M", calmboxname);
    dlist_printbuf(dl, 1, &buf);
    fputs("Content-Description: ", fp);
    fputs(buf_cstring(&buf), fp);
    fputs("\r\n", fp);
    buf_reset(&buf);
    dlist_free(&dl);

    fprintf(fp, "Content-Length: %zu\r\n", strlen(notifstr));
    fputs("MIME-Version: 1.0\r\n", fp);

    fputs("\r\n", fp);
    fputs(notifstr, fp);

    fclose(fp);
    if (r) goto done;

    struct appendstate as;
    r = append_setup_mbox(&as, notifmbox, authuserid, authstate,
            0, NULL, 0, 0, EVENT_MESSAGE_NEW);
    if (r) goto done;

    struct body *body = NULL;
    r = append_fromstage(&as, &body, stage, created, 0, NULL, 0, NULL);
    message_free_body(body);
    free(body);
    if (!r) {
        append_commit(&as);
    }
    else {
        append_abort(&as);
    }

done:
    append_removestage(stage);
    buf_free(&buf);
    free(notifstr);
    return r;
}

static json_t *build_eventnotif(const char *type,
                                time_t created,
                                const char *byprincipal,
                                const char *byname,
                                const char *byemail,
                                const char *ical_uid,
                                const char *comment,
                                int is_draft,
                                json_t *jevent,
                                json_t *jpatch)
{
    json_t *jn = json_object();
    struct buf buf = BUF_INITIALIZER;

    json_object_set_new(jn, "type", json_string(type));
    json_object_set_new(jn, "isDraft", json_boolean(is_draft));

    struct jmap_caleventid eid = {
        .ical_uid = ical_uid
    };
    const char *id = jmap_caleventid_encode(&eid, &buf);
    json_object_set_new(jn, "calendarEventId", json_string(id));

    char date3339[RFC3339_DATETIME_MAX+1];
    time_to_rfc3339(created, date3339, RFC3339_DATETIME_MAX);
    json_object_set_new(jn, "created", json_string(date3339));

    json_t *jchangedby = json_object();
    if (byemail) {
        if (!strncasecmp(byemail, "mailto:", 7)) byemail += 7;
        json_object_set_new(jchangedby, "email", json_string(byemail));
    }
    if (byname) {
        json_object_set_new(jchangedby, "name", json_string(byname));
    }
    if (byprincipal) {
        json_object_set_new(jchangedby, "calendarPrincipalId",
                json_string(byprincipal));
    }
    if (!json_object_size(jchangedby)) {
        json_decref(jchangedby);
        jchangedby = json_null();
    }
    json_object_set_new(jn, "changedBy", jchangedby);

    if (comment) {
        json_object_set_new(jn, "comment", json_string(comment));
    }
    if (jpatch) {
        json_object_set(jn, "eventPatch", jpatch);
    }
    if (jevent) {
        json_object_set(jn, "event", jevent);
    }

    buf_free(&buf);
    return jn;
}


HIDDEN int jmap_create_caleventnotif(struct mailbox *notifmbox,
                                     const char *userid,
                                     const struct auth_state *authstate,
                                     const char *calmboxname,
                                     const char *type,
                                     const char *ical_uid,
                                     const strarray_t *schedule_addresses,
                                     const char *comment,
                                     int is_draft,
                                     json_t *jevent,
                                     json_t *jpatch)
{
    if (!notifmbox) {
        xsyslog(LOG_ERR, "can not create event notification (null notifmbox)",
                "calendar=%s ical_uid=%s", calmboxname, ical_uid);
        return 0;
    }

    time_t now = time(NULL);

    const char *byemail = schedule_addresses ?
        strarray_nth(schedule_addresses, 0) : NULL;

    struct buf byname = BUF_INITIALIZER;
    const char *annotname = DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
    char *calhomename = caldav_mboxname(userid, NULL);
    annotatemore_lookupmask(calhomename, annotname, userid, &byname);
    free(calhomename);

    json_t *jnotif = build_eventnotif(type, now, userid,
            buf_cstring(&byname), byemail, ical_uid, comment,
            is_draft, jevent, jpatch);

    char *from = jmap_caleventnotif_format_fromheader(userid);
    int r = append_eventnotif(from, userid, authstate, notifmbox,
            calmboxname, now, jnotif);
    free(from);

    json_decref(jnotif);
    buf_free(&byname);
    return r;
}

HIDDEN int jmap_create_caldaveventnotif(struct transaction_t *txn,
                                        const char *userid,
                                        const struct auth_state *authstate,
                                        const char *calmboxname,
                                        const char *ical_uid,
                                        const strarray_t *schedule_addresses,
                                        int is_draft,
                                        icalcomponent *oldical,
                                        icalcomponent *newical)
{
    mbname_t *mbname = mbname_from_intname(calmboxname);
    const char *accountid = mbname_userid(mbname);
    struct mailbox *notifmbox = NULL;
    mbentry_t *notifmb = NULL;
    time_t now = time(NULL);
    json_t *jevent = NULL;
    json_t *jpatch = NULL;
    int r = 0;

    assert(oldical || newical);

    if ((user_isnamespacelocked(accountid) == LOCK_SHARED) ||
        (user_isnamespacelocked(userid) == LOCK_SHARED)) {
        /* bail out, before notification mailbox crashes on invalid lock */
        xsyslog(LOG_ERR, "can not exlusively lock jmapnotify collection",
                "accountid=%s", accountid);
        goto done;
    }

    r = jmap_create_notify_collection(accountid, &notifmb);
    if (r) {
        xsyslog(LOG_ERR, "can not create jmapnotify collection",
                "accountid=%s error=%s", accountid, error_message(r));
        goto done;
    }

    r = mailbox_open_iwl(notifmb->name, &notifmbox);
    if (r) {
        xsyslog(LOG_ERR, "can not open notification mailbox",
                "name=%s", notifmb->name);
        goto done;
    }

    const char *type;
    if (oldical) {
        jevent = jmapical_tojmap(oldical, NULL, NULL);
        if (newical) {
            type = "updated";
            json_t *tmp = jmapical_tojmap(newical, NULL, NULL);
            jpatch = jmap_patchobject_create(jevent, tmp);
            json_decref(tmp);
        }
        else type = "destroyed";
    }
    else {
        type = "created";
        jevent = jmapical_tojmap(newical, NULL, NULL);
    }
    if (!jevent) goto done;

    jmapical_remove_peruserprops(jevent);
    jmapical_remove_peruserprops(jpatch);

    /* Determine who triggered that event notification */
    struct buf byname = BUF_INITIALIZER;
    const char *byemail = NULL;
    const char *byprincipal = NULL;
    const char **hdr;
    char *from = NULL;

    if ((hdr = spool_getheader(txn->req_hdrs, "Schedule-Sender-Address"))) {
        byemail = *hdr;
        if (!strncasecmp(byemail, "mailto:", 7)) {
            byemail += 7;
        }
        from = strconcat("<", byemail, ">", NULL);
        if ((hdr = spool_getheader(txn->req_hdrs, "Schedule-Sender-name"))) {
            char *val = charset_decode_mimeheader(*hdr, CHARSET_KEEPCASE);
            if (val) buf_initmcstr(&byname, val);
        }
    }
    else {
        from = jmap_caleventnotif_format_fromheader(userid);
        byprincipal = userid;
        static const char *annotname = DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
        char *calhomename = caldav_mboxname(userid, NULL);
        annotatemore_lookupmask(calhomename, annotname, userid, &byname);
        free(calhomename);
        byemail = strarray_nth(schedule_addresses, 0);
    }

    json_t *jnotif = build_eventnotif(type, now,
            byprincipal, buf_cstring(&byname), byemail,
            ical_uid, NULL, is_draft, jevent, jpatch);

    r = append_eventnotif(from, userid, authstate, notifmbox,
                          calmboxname, now, jnotif);

    json_decref(jnotif);
    buf_free(&byname);
    free(from);

done:
    json_decref(jevent);
    json_decref(jpatch);
    mailbox_close(&notifmbox);
    mboxlist_entry_free(&notifmb);
    mbname_free(&mbname);
    return r;
}


