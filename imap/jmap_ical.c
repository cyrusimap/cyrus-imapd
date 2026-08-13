/* jmap_ical.c - Common code for JMAP for Calendars */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

#include "caldav_db.h"
#include "caldav_util.h"
#include "calsched_support.h"
#include "global.h"
#include "httpd.h"
#include "http_dav.h"
#include "http_jmap.h"
#include "ical_support.h"
#include "json_support.h"
#include "mailbox.h"
#include "mboxname.h"
#include "times.h"
#include "util.h"
#include "webdav_db.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#include "jmap_ical.h"


static char *_emailalert_recipient(const char *userid)
{
    strarray_t caluseraddr = STRARRAY_INITIALIZER;
    char *mboxname = caldav_mboxname(userid, NULL);
    char *recipient = NULL;

    if (!caldav_caluseraddr_read(mboxname, userid, &caluseraddr)) {
        if (strarray_size(&caluseraddr)) {
            const char *item = strarray_nth(&caluseraddr, 0);
            if (!strncasecmp(item, "mailto:", 7)) item += 7;
            recipient = strconcat("mailto:", item, NULL);
        }
    }
    else if (strchr(userid, '@')) {
        recipient = strconcat("mailto:", userid, NULL);
    }
    else {
        recipient = strconcat("mailto:", userid, "@", config_defdomain, NULL);
    }

    free(mboxname);
    strarray_fini(&caluseraddr);
    return recipient;
}


#ifndef BUILD_LMTPD

HIDDEN int jmapical_context_open_attachments(struct jmapical_ctx *jmapctx)
{
    jmap_req_t *req = jmapctx->req;

    if (jmapctx->attachments.err)
        return jmapctx->attachments.err;

    if (!jmapctx->attachments.mbox) {
        char *mboxname = caldav_mboxname(req->accountid, MANAGED_ATTACH);
        int rw = jmapctx->attachments.lock;
        int r = rw ? mailbox_open_iwl(mboxname, &jmapctx->attachments.mbox)
                   : mailbox_open_irl(mboxname, &jmapctx->attachments.mbox);
        if (r) {
            xsyslog(LOG_ERR, "can't open attachments",
                    "mboxname=<%s> err<%s>", mboxname, error_message(r));
        }
        free(mboxname);
        if (r) {
            jmapctx->attachments.err = r;
            return jmapctx->attachments.err;
        }
    }
    if (!jmapctx->attachments.db) {
        jmapctx->attachments.db = webdav_open_mailbox(jmapctx->attachments.mbox);
        if (!jmapctx->attachments.db) {
            xsyslog(LOG_ERR, "mailbox_open_webdav failed",
                    "attachments=<%s>", mailbox_name(jmapctx->attachments.mbox));
            mailbox_close(&jmapctx->attachments.mbox);
            jmapctx->attachments.db = NULL;
            jmapctx->attachments.err = IMAP_INTERNAL;
            return jmapctx->attachments.err;
        }
    }

    return 0;
}

#endif // BUILD_LMTPD

HIDDEN struct jmapical_ctx *jmapical_context_new(jmap_req_t *req,
                                                 const strarray_t *schedule_addresses)
{
    struct jmapical_ctx *jmapctx = xzmalloc(sizeof(struct jmapical_ctx));

    jmapctx->req = req;
    jmapctx->schedule_addresses = schedule_addresses;

    const char *slash = strrchr(req->method, '/');
    jmapctx->attachments.lock = slash && !strcmp(slash, "/set");

    /* Initialize context for Link.blobId */
    const char *baseurl = config_getstring(IMAPOPT_WEBDAV_ATTACHMENTS_BASEURL);
    if (baseurl) {
        caldav_attachment_url(&jmapctx->attachments.url, req->accountid, baseurl, "");
    }

    jmapctx->to_ical.emailalert_recipient = _emailalert_recipient(req->userid);

    if (strarray_size(schedule_addresses)) {
        const char *imipaddr = strarray_nth(schedule_addresses, 0);
        struct buf buf = BUF_INITIALIZER;
        if (strncasecmp(imipaddr, "mailto:", 7)) {
            buf_setcstr(&buf, "mailto:");
            buf_appendcstr(&buf, imipaddr);
            imipaddr = buf_cstring(&buf);
        }
        jmapctx->to_ical.replyto = json_pack("{s:s}", "imip", imipaddr);
        buf_free(&buf);
    }

    return jmapctx;
}

HIDDEN void jmapical_context_free(struct jmapical_ctx **jmapctxp)
{
    if (!jmapctxp) return;

    struct jmapical_ctx *jmapctx = *jmapctxp;
    if (!jmapctx) return;

#ifndef BUILD_LMTPD
    mailbox_close(&jmapctx->attachments.mbox);
    if (jmapctx->attachments.db)
        webdav_close(jmapctx->attachments.db);
#endif // BUILD_LMTPD
    buf_free(&jmapctx->attachments.url);

    json_decref(jmapctx->to_ical.replyto);

    free(jmapctx->to_ical.emailalert_recipient);
    free(jmapctx);

    *jmapctxp = NULL;
}



HIDDEN void jmapical_remove_peruserprops(json_t *jevent)
{
    json_object_del(jevent, "keywords");
    json_object_del(jevent, "color");
    json_object_del(jevent, "freeBusyStatus");
    json_object_del(jevent, "useDefaultAlerts");
    json_object_del(jevent, "alerts");

    json_t *joverrides = json_object_get(jevent, "recurrenceOverrides");
    const char *recurid;
    json_t *joverride;
    void *tmp;
    json_object_foreach_safe(joverrides, tmp, recurid, joverride) {
        json_object_del(joverride, "keywords");
        json_object_del(joverride, "color");
        json_object_del(joverride, "freeBusyStatus");
        json_object_del(joverride, "useDefaultAlerts");
        json_object_del(joverride, "alerts");
        const char *prop;
        json_t *jpatch;
        void *tmp2;
        json_object_foreach_safe(joverride, tmp2, prop, jpatch) {
            if (!strncmp(prop, "alerts/", 7)) {
                json_object_del(joverride, prop);
            }
        }
        if (!json_object_size(joverride)) {
            json_object_del(joverrides, recurid);
        }
    }
}
