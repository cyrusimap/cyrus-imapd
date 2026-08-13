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


HIDDEN int jmapical_datetime_has_zero_time(const struct jmapical_datetime *dt)
{
    return dt->hour == 0 && dt->minute == 0 && dt->second == 0 && dt->nano == 0;
}

HIDDEN icaltimetype jmapical_datetime_to_icaltime(const struct jmapical_datetime *dt,
                                                  const icaltimezone* zone)
{
    struct icaltimetype icaldt = icaltime_null_time();
    icaldt.year = dt->year;
    icaldt.month = dt->month;
    icaldt.day = dt->day;
    icaldt.hour = dt->hour;
    icaldt.minute = dt->minute;
    icaldt.second = dt->second;
    icaldt.is_date = 0;
    icaldt.zone = zone;
    return icaldt;
}


HIDDEN void jmapical_datetime_from_icaltime(icaltimetype icaldt, struct jmapical_datetime *dt)
{
    memset(dt, 0, sizeof(struct jmapical_datetime));
    dt->year = icaldt.year;
    dt->month = icaldt.month;
    dt->day = icaldt.day;
    dt->hour = icaldt.hour;
    dt->minute = icaldt.minute;
    dt->second = icaldt.second;
}

HIDDEN int jmapical_datetime_compare(const struct jmapical_datetime *a,
                                     const struct jmapical_datetime *b)
{
    if (a->year != b->year)
        return a->year > b->year ? 1 : -1;
    if (a->month != b->month)
        return a->month > b->month ? 1 : -1;
    if (a->day != b->day)
        return a->day > b->day ? 1 : -1;
    if (a->hour != b->hour)
        return a->hour > b->hour ? 1 : -1;
    if (a->minute != b->minute)
        return a->minute > b->minute ? 1 : -1;
    if (a->second != b->second)
        return a->second > b->second ? 1 : -1;
    if (a->nano != b->nano)
        return a->nano > b->nano ? 1 : -1;
    return 0;
}

static void format_datetime(const struct jmapical_datetime *dt, struct buf *dst)
{
    buf_reset(dst);
    buf_printf(dst, "%04d-%02d-%02dT%02d:%02d:%02d",
            dt->year, dt->month, dt->day, dt->hour, dt->minute, dt->second);
    if (dt->nano) {
        buf_printf(dst, UINT64_NANOSEC_FMT, dt->nano);
        int n = buf_len(dst);
        const char *b = buf_base(dst);
        while (b[n-1] == '0') n--;
        buf_truncate(dst, n);
    }
    buf_cstring(dst);
}

HIDDEN void jmapical_localdatetime_as_string(const struct jmapical_datetime *dt, struct buf *dst)
{
    format_datetime(dt, dst);
    buf_cstring(dst);
}

HIDDEN void jmapical_utcdatetime_as_string(const struct jmapical_datetime *dt, struct buf *dst)
{
    format_datetime(dt, dst);
    buf_putc(dst, 'Z');
    buf_cstring(dst);
}

static const char *parse_fracsec(const char *val, bit64 *nanoptr)
{
    const char *end = NULL;
    bit64 nano = 0;
    if (parsenum(val, &end, 9, &nano) >= 0) {
        /* Normalize to nanoseconds */
        ssize_t i, n = end - val;
        for (i = 0; i < 9 - n; i++) {
            nano *= 10;
        }
        /* Skip remaining fractional seconds */
        while (isdigit(*end)) end++;
        /* No trailing zeros allowed */
        if (end[-1] == '0') {
            return NULL;
        }
        *nanoptr = nano;
        return end;
    }
    else return NULL;
}

static const char *parse_datetime(const char *val, struct jmapical_datetime *dt)
{
    struct tm tm;
    memset(&tm, 0, sizeof(struct tm));
    tm.tm_isdst = -1;

    const char *p = strptime(val, "%Y-%m-%dT%H:%M:%S", &tm);
    if (!p) return NULL;

    memset(dt, 0, sizeof(struct jmapical_datetime));
    dt->year = tm.tm_year + 1900;
    dt->month = tm.tm_mon + 1;
    dt->day = tm.tm_mday;
    dt->hour = tm.tm_hour;
    dt->minute = tm.tm_min;
    dt->second = tm.tm_sec;

    if (*p == '.') p = parse_fracsec(p+1, &dt->nano);

    return p;
}

HIDDEN int jmapical_localdatetime_from_string(const char *val, struct jmapical_datetime *dt)
{
    const char *p = parse_datetime(val, dt);
    return (!p || p[0] != '\0') ? -1 : 0;
}

HIDDEN int jmapical_utcdatetime_from_string(const char *val, struct jmapical_datetime *dt)
{
    const char *p = parse_datetime(val, dt);
    return (!p || p[0] != 'Z' || p[1] != '\0') ? -1 : 0;
}

HIDDEN int jmapical_datetime_from_icalprop(icalproperty *prop, struct jmapical_datetime *dt)
{
    icalvalue *val = icalproperty_get_value(prop);
    if (!(icalvalue_isa(val) == ICAL_DATETIME_VALUE) &&
        !(icalvalue_isa(val) == ICAL_DATE_VALUE)) {
        return -1;
    }

    jmapical_datetime_from_icaltime(icalvalue_get_datetimedate(val), dt);
    return 0;
}

HIDDEN int jmapical_duration_has_zero_time(const struct jmapical_duration *dur)
{
    return dur->hours == 0 && dur->minutes == 0 &&
           dur->seconds == 0 && dur->nanos == 0;
}

HIDDEN struct icaldurationtype jmapical_duration_to_icalduration(const struct jmapical_duration *dur)
{
    struct icaldurationtype icaldur = icaldurationtype_null_duration();

    icaldur.is_neg = dur->is_neg;
    icaldur.days = dur->days;
    icaldur.weeks = dur->weeks;
    icaldur.hours = dur->hours;
    icaldur.minutes = dur->minutes;
    icaldur.seconds = dur->seconds;

    return icaldur;
}

static void jmapical_duration_from_icalduration(struct icaldurationtype icaldur,
                                                struct jmapical_duration *dur)
{
    memset(dur, 0, sizeof(struct jmapical_duration));
    dur->is_neg = icaldur.is_neg;
    dur->days = icaldur.days;
    dur->weeks = icaldur.weeks;
    dur->hours = icaldur.hours;
    dur->minutes = icaldur.minutes;
    dur->seconds = icaldur.seconds;
}

static void jmapical_duration_between_unixtime(time_t t1, bit64 t1nanos,
                                               time_t t2, bit64 t2nanos,
                                               struct jmapical_duration *dur)
{
    const icaltimezone *utc = icaltimezone_get_utc_timezone();
    int is_neg = t1 > t2 || (t1 == t2 && t1nanos > t2nanos);
    bit64 nanos = 0;

    time_t tx = is_neg ? t2 : t1;
    bit64 txnanos = is_neg ? t2nanos : t1nanos;

    time_t ty = is_neg ? t1 : t2;
    bit64 tynanos = is_neg ? t1nanos : t2nanos;

    if (txnanos < tynanos) {
        nanos = tynanos - txnanos;
    }
    else if (txnanos > tynanos) {
        nanos = (1000000000 - txnanos) + tynanos;
        if (tx != ty) ty -= 1;
    }

    icaltimetype icaltx = icaltime_from_timet_with_zone(tx, 0, utc);
    icaltimetype icalty = icaltime_from_timet_with_zone(ty, 0, utc);
    struct icaldurationtype icaldur =
        icaldurationtype_normalize(icalduration_from_times(icalty, icaltx));
    icaldur.is_neg = is_neg;
    jmapical_duration_from_icalduration(icaldur, dur);
    dur->nanos = nanos;
}

HIDDEN void jmapical_duration_between_utctime(const struct jmapical_datetime *t1,
                                              const struct jmapical_datetime *t2,
                                              struct jmapical_duration *dur)
{
    const icaltimezone *utc = icaltimezone_get_utc_timezone();

    icaltimetype t1ical = jmapical_datetime_to_icaltime(t1, utc);
    icaltimetype t2ical = jmapical_datetime_to_icaltime(t2, utc);

    time_t t1unix = icaltime_as_timet_with_zone(t1ical, utc);
    time_t t2unix = icaltime_as_timet_with_zone(t2ical, utc);

    jmapical_duration_between_unixtime(t1unix, t1->nano, t2unix, t2->nano, dur);
}

HIDDEN int jmapical_duration_from_string(const char *val, struct jmapical_duration *dur)
{
    bit64 nanos = 0;
    char *myval = NULL;

    const char *fracsec = strchr(val, '.');
    if (fracsec) {
        // Parse fractional seconds.
        const char *p = parse_fracsec(fracsec + 1, &nanos);
        if (!p || p[0] != 'S' || p[1] != '\0') return -1;
        // Truncate to iCalendar duration.
        myval = xstrdup(val);
        myval[fracsec-val] = 'S';
        myval[fracsec-val+1] = '\0';
        val = myval;
    }

    // Parse iCalendar duration.
    struct icaldurationtype icaldur = icaldurationtype_from_string(val);
    free(myval);
    if (icaldurationtype_is_bad_duration(icaldur)) return -1;
    jmapical_duration_from_icalduration(icaldur, dur);
    dur->nanos = nanos;

    return 0;
}

HIDDEN void jmapical_duration_as_string(const struct jmapical_duration *dur, struct buf *buf)
{
    struct icaldurationtype icaldur = jmapical_duration_to_icalduration(dur);
    char *tmp = icaldurationtype_as_ical_string_r(icaldur);

    buf_setcstr(buf, tmp);
    if (dur->nanos) {
        const char *b = buf_base(buf);
        int n = buf_len(buf);
        /* Append fracsec part */
        if (b[n-1] == 'S') {
            buf_truncate(buf, n-1);
        }
        else {
            buf_putc(buf, '0');
        }
        buf_printf(buf, UINT64_NANOSEC_FMT, dur->nanos);
        /* Truncate trailing zeros */
        b = buf_base(buf);
        n = buf_len(buf);
        while (b[n-1] == '0') n--;
        buf_truncate(buf, n);
        buf_putc(buf, 'S');
    }

    free(tmp);
    buf_cstring(buf);
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
