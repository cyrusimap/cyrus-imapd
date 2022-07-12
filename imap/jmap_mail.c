/* jmap_mail.c -- Routines for handling JMAP mail messages
 *
 * Copyright (c) 1994-2014 Carnegie Mellon University.  All rights reserved.
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
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>

#include <sasl/saslutil.h>

#ifdef HAVE_LIBCHARDET
#include <chardet/chardet.h>
#endif

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "bsearch.h"
#include "carddav_db.h"
#include "cyr_qsort_r.h"
#include "hashset.h"
#include "http_dav.h"
#include "http_jmap.h"
#include "http_proxy.h"
#include "jmap_calendar.h"
#include "jmap_mail.h"
#include "jmap_mail_query.h"
#include "json_support.h"
#include "mailbox.h"
#include "mappedfile.h"
#include "mboxevent.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "msgrecord.h"
#include "notify.h"
#include "parseaddr.h"
#include "proxy.h"
#include "search_query.h"
#include "seen.h"
#include "smallarrayu64.h"
#include "smtpclient.h"
#include "statuscache.h"
#include "sync_log.h"
#include "times.h"
#include "util.h"
#include "xmalloc.h"
#include "xsha1.h"
#include "xstrnchr.h"


/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int jmap_email_query(jmap_req_t *req);
static int jmap_email_querychanges(jmap_req_t *req);
static int jmap_email_get(jmap_req_t *req);
static int jmap_email_set(jmap_req_t *req);
static int jmap_email_changes(jmap_req_t *req);
static int jmap_email_import(jmap_req_t *req);
static int jmap_email_parse(jmap_req_t *req);
static int jmap_email_copy(jmap_req_t *req);
static int jmap_email_matchmime_method(jmap_req_t *req);
static int jmap_searchsnippet_get(jmap_req_t *req);
static int jmap_thread_get(jmap_req_t *req);
static int jmap_thread_changes(jmap_req_t *req);

static int jmap_emailheader_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx);

/*
 * Possibly to be implemented:
 * - Email/removeAttachments
 * - Email/report
 * - Identity/changes
 * - Identity/set
 */

static jmap_method_t jmap_mail_methods_standard[] = {
    {
        "Email/query",
        JMAP_URN_MAIL,
        &jmap_email_query,
        JMAP_NEED_CSTATE
    },
    {
        "Email/queryChanges",
        JMAP_URN_MAIL,
        &jmap_email_querychanges,
        JMAP_NEED_CSTATE
    },
    {
        "Email/get",
        JMAP_URN_MAIL,
        &jmap_email_get,
        JMAP_NEED_CSTATE
    },
    {
        "Email/set",
        JMAP_URN_MAIL,
        &jmap_email_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "Email/changes",
        JMAP_URN_MAIL,
        &jmap_email_changes,
        JMAP_NEED_CSTATE
    },
    {
        "Email/import",
        JMAP_URN_MAIL,
        &jmap_email_import,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "Email/parse",
        JMAP_URN_MAIL,
        &jmap_email_parse,
        JMAP_NEED_CSTATE
    },
    {
        "Email/copy",
        JMAP_URN_MAIL,
        &jmap_email_copy,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "SearchSnippet/get",
        JMAP_URN_MAIL,
        &jmap_searchsnippet_get,
        JMAP_NEED_CSTATE
    },
    {
        "Thread/get",
        JMAP_URN_MAIL,
        &jmap_thread_get,
        JMAP_NEED_CSTATE
    },
    {
        "Thread/changes",
        JMAP_URN_MAIL,
        &jmap_thread_changes,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};

static jmap_method_t jmap_mail_methods_nonstandard[] = {
    {
        "Email/matchMime",
        JMAP_MAIL_EXTENSION,
        &jmap_email_matchmime_method,
        JMAP_NEED_CSTATE
    },
    { NULL, NULL, NULL, 0}
};

/* NULL terminated list of supported jmap_email_query sort fields */
struct email_sortfield {
    const char *name;
    const char *capability;
};

static struct email_sortfield email_sortfields[] = {
    {
        "receivedAt",
        NULL
    },
    {
        "sentAt",
        NULL
    },
    {
        "from",
        NULL
    },
    {
        "id",
        NULL
    },
    {
        "emailstate",
        NULL
    },
    {
        "size",
        NULL
    },
    {
        "subject",
        NULL
    },
    {
        "to",
        NULL
    },
    {
        "hasKeyword",
        NULL
    },
    {
        "someInThreadHaveKeyword",
        NULL
    },
    {
        "addedDates",
        JMAP_MAIL_EXTENSION
    },
    {
        "threadSize",
        JMAP_MAIL_EXTENSION
    },
    {
        "spamScore",
        JMAP_MAIL_EXTENSION
    },
    {
        "snoozedUntil",
        JMAP_MAIL_EXTENSION
    },
    {
        NULL,
        NULL
    }
};

#define jmap_openmbox_by_guidrec(req, rec, mbox, rw)           \
    ((rec->version > CONV_GUIDREC_BYNAME_VERSION) ?            \
     jmap_openmbox_by_uniqueid(req, conv_guidrec_uniqueid(rec), mbox, rw) :  \
     jmap_openmbox(req, conv_guidrec_mboxname(rec), mbox, rw))


#define JMAP_MAIL_MAX_MAILBOXES_PER_EMAIL 20
#define JMAP_MAIL_MAX_KEYWORDS_PER_EMAIL 100 /* defined in mailbox_user_flag */

static void emailquery_handler(enum jmap_handler_event event, jmap_req_t *req, void *rock);

static int emailquery_cache_max_age = 0;

HIDDEN void jmap_mail_init(jmap_settings_t *settings)
{
    jmap_method_t *mp;
    for (mp = jmap_mail_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_MAIL, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(settings->server_capabilities,
                JMAP_MAIL_EXTENSION, json_object());

        for (mp = jmap_mail_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }

    ptrarray_append(&settings->getblob_handlers, jmap_emailheader_getblob);

    emailquery_cache_max_age = config_getduration(IMAPOPT_JMAP_QUERYCACHE_MAX_AGE, 'm');
    if (emailquery_cache_max_age) {
        struct jmap_handler *h = xzmalloc(sizeof(struct jmap_handler));
        h->eventmask = JMAP_HANDLE_BEFORE_METHOD|
                       JMAP_HANDLE_CLOSE_CONN|
                       JMAP_HANDLE_SHUTDOWN;
        h->handler = emailquery_handler;
        ptrarray_append(&settings->event_handlers, h);
    }

    jmap_emailsubmission_init(settings);
    jmap_mailbox_init(settings);
#ifdef USE_SIEVE
    jmap_vacation_init(settings);
#endif
}

HIDDEN void jmap_mail_capabilities(json_t *account_capabilities, int mayCreateTopLevel)
{
    json_t *sortopts = json_array();
    struct email_sortfield *sp;
    int support_extensions = config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS);

    for (sp = email_sortfields; sp->name; sp++) {
        if (sp->capability && !support_extensions) continue;
        json_array_append_new(sortopts, json_string(sp->name));
    }

    long max_size_attachments_per_email =
        config_getint(IMAPOPT_JMAP_MAIL_MAX_SIZE_ATTACHMENTS_PER_EMAIL);

    max_size_attachments_per_email *= 1024;
    if (max_size_attachments_per_email <= 0) {
        syslog(LOG_ERR, "jmap: invalid property value: %s",
                imapopts[IMAPOPT_JMAP_MAIL_MAX_SIZE_ATTACHMENTS_PER_EMAIL].optname);
        max_size_attachments_per_email = 0;
    }

    json_t *email_capabilities = json_pack("{s:i s:i s:i s:o, s:b}",
            "maxMailboxesPerEmail", JMAP_MAIL_MAX_MAILBOXES_PER_EMAIL,
            "maxKeywordsPerEmail", JMAP_MAIL_MAX_KEYWORDS_PER_EMAIL,
            "maxSizeAttachmentsPerEmail", max_size_attachments_per_email,
            "emailsListSortOptions", sortopts,
            "mayCreateTopLevelMailbox", mayCreateTopLevel);

    json_object_set_new(account_capabilities, JMAP_URN_MAIL, email_capabilities);

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities, JMAP_MAIL_EXTENSION, json_object());
    }

    jmap_mailbox_capabilities(account_capabilities);
}

#define JMAP_HAS_ATTACHMENT_FLAG "$HasAttachment"

typedef enum MsgType {
        MSG_IS_ROOT = 0,
        MSG_IS_ATTACHED = 1,
} MsgType;

/*
 * Emails
 */

static char *_decode_to_utf8(const char *charset,
                             const char *data, size_t datalen,
                             const char *encoding,
                             int *is_encoding_problem)
{
    /* XXX - keep confidence 0.0 for regression? */
    struct buf buf = BUF_INITIALIZER;
    jmap_decode_to_utf8(charset,
            encoding_lookupname(encoding),
            data, datalen, 0.0, &buf,
            is_encoding_problem);
    return datalen && buf_len(&buf) ? buf_release(&buf) : NULL;
}

struct headers {
    json_t *raw; /* JSON array of EmailHeader */
    json_t *all; /* JSON object: lower-case header name => list of values */
    struct buf buf;
};

#define HEADERS_INITIALIZER \
    { json_array(), json_object(), BUF_INITIALIZER }

static void _headers_init(struct headers *headers) {
    headers->raw = json_array();
    headers->all = json_object();
    memset(&headers->buf, 0, sizeof(struct buf));
}

static void _headers_fini(struct headers *headers) {
    json_decref(headers->all);
    json_decref(headers->raw);
    buf_free(&headers->buf);
}

static void _headers_put_new(struct headers *headers, json_t *header, int shift)
{
    const char *name = json_string_value(json_object_get(header, "name"));

    if (headers->raw == NULL)
        headers->raw = json_array();
    if (headers->all == NULL)
        headers->all = json_object();

    /* Append (or shift) the raw header to the in-order header list */
    if (shift)
        json_array_insert(headers->raw, 0, header);
    else
        json_array_append(headers->raw, header);

    /* Append the raw header to the list of all equal-named headers */
    buf_setcstr(&headers->buf, name);
    const char *lcasename = buf_lcase(&headers->buf);
    json_t *all = json_object_get(headers->all, lcasename);
    if (!all) {
        all = json_array();
        json_object_set_new(headers->all, lcasename, all);
    }

    if (shift)
        json_array_insert_new(all, 0, header);
    else
        json_array_append_new(all, header);
}

static void _headers_add_new(struct headers *headers, json_t *header)
{
    if (!header) return;
    _headers_put_new(headers, header, 0);
}

static void _headers_shift_new(struct headers *headers, json_t *header)
{
    if (!header) return;
    _headers_put_new(headers, header, 1);
}

static json_t* _headers_get(struct headers *headers, const char *name)
{
    char *lcasename = lcase(xstrdup(name));
    json_t *jheader = json_object_get(headers->all, lcasename);
    free(lcasename);
    return jheader;
}

static int _headers_have(struct headers *headers, const char *name)
{
    return _headers_get(headers, name) != NULL;
}

static int _headers_from_mime_cb(const char *key, const char *val, void *_rock)
{
    struct headers *headers = _rock;
    _headers_add_new(headers, json_pack("{s:s s:s}", "name", key, "value", val));
    return 0;
}

static void _headers_from_mime(const char *base, size_t len, struct headers *headers)
{
    message_foreach_header(base, len, _headers_from_mime_cb, headers);
}

struct header_prop {
    char *lcasename;
    char *name;
    const char *prop;
    enum header_form form;
    int all;
};

static void _header_prop_fini(struct header_prop *prop)
{
    free(prop->lcasename);
    free(prop->name);
}

static void _header_prop_free(struct header_prop *prop)
{
    _header_prop_fini(prop);
    free(prop);
}

static struct header_prop *_header_parseprop(const char *s)
{
    strarray_t *fields = strarray_split(s + 7, ":", 0);
    const char *f0, *f1, *f2;
    int is_valid = 1;
    enum header_form form = HEADER_FORM_RAW;
    char *lcasename = NULL, *name = NULL;

    /* Initialize allowed header forms by lower-case header name. Any
     * header in this map is allowed to be requested either as Raw
     * or the form of the map value (casted to void* because C...).
     * Any header not found in this map is allowed to be requested
     * in any form. */
    static hash_table allowed_header_forms = HASH_TABLE_INITIALIZER;
    if (allowed_header_forms.size == 0) {
        /* TODO initialize with all headers in RFC 5322 and RFC 2369 */
        construct_hash_table(&allowed_header_forms, 32, 0);
        hash_insert("bcc",
                (void*) (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES),
                &allowed_header_forms);
        hash_insert("cc",
                (void*) (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES),
                &allowed_header_forms);
        hash_insert("content-type",
                (void*) HEADER_FORM_RAW,
                &allowed_header_forms);
        hash_insert("comment",
                (void*) HEADER_FORM_TEXT,
                &allowed_header_forms);
        hash_insert("date",
                (void*) HEADER_FORM_DATE,
                &allowed_header_forms);
        hash_insert("from",
                (void*) (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES),
                &allowed_header_forms);
        hash_insert("in-reply-to",
                (void*) HEADER_FORM_MESSAGEIDS,
                &allowed_header_forms);
        hash_insert("list-archive",
                (void*) HEADER_FORM_URLS,
                &allowed_header_forms);
        hash_insert("list-help",
                (void*) HEADER_FORM_URLS,
                &allowed_header_forms);
        hash_insert("list-owner",
                (void*) HEADER_FORM_URLS,
                &allowed_header_forms);
        hash_insert("list-post",
                (void*) HEADER_FORM_URLS,
                &allowed_header_forms);
        hash_insert("list-subscribe",
                (void*) HEADER_FORM_URLS,
                &allowed_header_forms);
        hash_insert("list-unsubscribe",
                (void*) HEADER_FORM_URLS,
                &allowed_header_forms);
        hash_insert("message-id",
                (void*) HEADER_FORM_MESSAGEIDS,
                &allowed_header_forms);
        hash_insert("references",
                (void*) HEADER_FORM_MESSAGEIDS,
                &allowed_header_forms);
        hash_insert("reply-to",
                (void*) (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES),
                &allowed_header_forms);
        hash_insert("resent-date",
                (void*) HEADER_FORM_DATE,
                &allowed_header_forms);
        hash_insert("resent-from",
                (void*) (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES),
                &allowed_header_forms);
        hash_insert("resent-message-id",
                (void*) HEADER_FORM_MESSAGEIDS,
                &allowed_header_forms);
        hash_insert("resent-reply-to",
                (void*) (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES),
                &allowed_header_forms);
        hash_insert("resent-sender",
                (void*) (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES),
                &allowed_header_forms);
        hash_insert("resent-to",
                (void*) (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES),
                &allowed_header_forms);
        hash_insert("resent-cc",
                (void*) (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES),
                &allowed_header_forms);
        hash_insert("resent-bcc",
                (void*) (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES),
                &allowed_header_forms);
        hash_insert("sender",
                (void*) (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES),
                &allowed_header_forms);
        hash_insert("subject",
                (void*) HEADER_FORM_TEXT,
                &allowed_header_forms);
        hash_insert("to",
                (void*) (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES),
                &allowed_header_forms);
    }

    /* Parse property string into fields */
    f0 = f1 = f2 = NULL;
    switch (fields->count) {
        case 3:
            f2 = strarray_nth(fields, 2);
            /* fallthrough */
        case 2:
            f1 = strarray_nth(fields, 1);
            /* fallthrough */
        case 1:
            f0 = strarray_nth(fields, 0);
            lcasename = lcase(xstrdup(f0));
            name = xstrdup(f0);
            break;
        default:
            strarray_free(fields);
            return NULL;
    }

    if (f2 && (strcmp(f2, "all") || !strcmp(f1, "all"))) {
        strarray_free(fields);
        free(lcasename);
        free(name);
        return NULL;
    }
    if (f1) {
        if (!strcmp(f1, "asRaw"))
            form = HEADER_FORM_RAW;
        else if (!strcmp(f1, "asText"))
            form = HEADER_FORM_TEXT;
        else if (!strcmp(f1, "asAddresses"))
            form = HEADER_FORM_ADDRESSES;
        else if (!strcmp(f1, "asGroupedAddresses"))
            form = HEADER_FORM_GROUPEDADDRESSES;
        else if (!strcmp(f1, "asMessageIds"))
            form = HEADER_FORM_MESSAGEIDS;
        else if (!strcmp(f1, "asDate"))
            form = HEADER_FORM_DATE;
        else if (!strcmp(f1, "asURLs"))
            form = HEADER_FORM_URLS;
        else if (strcmp(f1, "all"))
            is_valid = 0;
    }

    /* Validate requested header form */
    if (is_valid && form != HEADER_FORM_RAW) {
        enum header_form allowed_form =
            (enum header_form) ((uintptr_t) hash_lookup(lcasename, &allowed_header_forms));
        if (allowed_form != HEADER_FORM_UNKNOWN && !(form & allowed_form)) {
            is_valid = 0;
        }
    }

    struct header_prop *hprop = NULL;
    if (is_valid) {
        hprop = xzmalloc(sizeof(struct header_prop));
        hprop->lcasename = lcasename;
        hprop->name = name;
        hprop->prop = s;
        hprop->form = form;
        hprop->all = f2 != NULL || (f1 && !strcmp(f1, "all"));
    }
    else {
        free(lcasename);
        free(name);
    }
    strarray_free(fields);
    return hprop;
}

/* Generate a preview of text of at most len bytes, excluding the zero
 * byte.
 *
 * Consecutive whitespaces, including newlines, are collapsed to a single
 * blank. If text is longer than len and len is greater than 4, then return
 * a string  ending in '...' and holding as many complete UTF-8 characters,
 * that the total byte count of non-zero characters is at most len.
 *
 * The input string must be properly encoded UTF-8 */
static char *_email_extract_preview(const char *text, size_t len)
{
    unsigned char *dst, *d, *t;
    size_t n;

    if (!text) {
        return NULL;
    }

    /* Replace all whitespace with single blanks. */
    dst = (unsigned char *) xzmalloc(len+1);
    for (t = (unsigned char *) text, d = dst; *t && d < (dst+len); ++t, ++d) {
        *d = isspace(*t) ? ' ' : *t;
        if (isspace(*t)) {
            while(isspace(*++t))
                ;
            --t;
        }
    }
    n = d - dst;

    /* Anything left to do? */
    if (n < len || len <= 4) {
        return (char*) dst;
    }

    /* Append trailing ellipsis. */
    dst[--n] = '.';
    dst[--n] = '.';
    dst[--n] = '.';
    while (n && (dst[n] & 0xc0) == 0x80) {
        dst[n+2] = 0;
        dst[--n] = '.';
    }
    if (dst[n] >= 0x80) {
        dst[n+2] = 0;
        dst[--n] = '.';
    }
    return (char *) dst;
}

struct _email_mailboxes_rock {
    jmap_req_t *req;
    json_t *mboxs;
};

static int _email_mailboxes_cb(const conv_guidrec_t *rec, void *rock)
{
    struct _email_mailboxes_rock *data = (struct _email_mailboxes_rock*) rock;
    json_t *mboxs = data->mboxs;
    jmap_req_t *req = data->req;
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    uint32_t system_flags, internal_flags;
    mbentry_t *mbentry = NULL;
    int r;

    if (rec->part) return 0;

    conv_guidrec_mbentry(rec, &mbentry);

    // we only want regular mailboxes!
    static int needrights = JACL_READITEMS;
    if (!mbentry || (mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL) ||
        !jmap_hasrights_mbentry(req, mbentry, needrights)) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    r = jmap_openmbox(req, mbentry->name, &mbox, 0);
    mboxlist_entry_free(&mbentry);
    if (r) goto done;

    r = msgrecord_find(mbox, rec->uid, &mr);
    if (r) goto done;

    r = msgrecord_get_systemflags(mr, &system_flags);
    if (r) goto done;

    r = msgrecord_get_internalflags(mr, &internal_flags);
    if (r) goto done;

    if (!r) {
        char datestr[RFC3339_DATETIME_MAX];
        time_t t;
        int exists = 1;

        if (system_flags & FLAG_DELETED || internal_flags & FLAG_INTERNAL_EXPUNGED) {
            exists = 0;
            r = msgrecord_get_lastupdated(mr, &t);
        }
        else {
            r = msgrecord_get_savedate(mr, &t);
        }

        if (r) goto done;
        time_to_rfc3339(t, datestr, RFC3339_DATETIME_MAX);

        json_t *mboxdata = json_object_get(mboxs, mailbox_uniqueid(mbox));
        if (!mboxdata) {
            mboxdata = json_object();
            json_object_set_new(mboxs, mailbox_uniqueid(mbox), mboxdata);
        }

        if (exists) {
            json_t *prev = json_object_get(mboxdata, "added");
            if (prev) {
                const char *val = json_string_value(prev);
                // we want the FIRST date it was added to the mailbox, so skip if this is newer
                if (strcmp(datestr, val) >= 0) goto done;
            }

            json_object_set_new(mboxdata, "added", json_string(datestr));
        }
        else {
            json_t *prev = json_object_get(mboxdata, "removed");
            if (prev) {
                const char *val = json_string_value(prev);
                // we want the LAST date it was removed from the mailbox, so skip if this is older
                if (strcmp(datestr, val) <= 0) goto done;
            }

            json_object_set_new(mboxdata, "removed", json_string(datestr));
        }
    }


done:
    if (mr) msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);
    return r;
}

static char *_emailbodies_to_plain(struct emailbodies *bodies, const struct buf *msg_buf)
{
    if (bodies->textlist.count == 1) {
        int is_encoding_problem = 0;
        struct body *textbody = ptrarray_nth(&bodies->textlist, 0);
        return _decode_to_utf8(textbody->charset_id,
                               msg_buf->s + textbody->content_offset,
                               textbody->content_size,
                               textbody->encoding,
                               &is_encoding_problem);
    }

    /* Concatenate all plain text bodies and replace any
     * inlined images with placeholders. */
    int i;
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < bodies->textlist.count; i++) {
        struct body *part = ptrarray_nth(&bodies->textlist, i);

        if (i) buf_appendcstr(&buf, "\n");

        if (!strcmp(part->type, "TEXT")) {
            int is_encoding_problem = 0;
            char *t = _decode_to_utf8(part->charset_id,
                                      msg_buf->s + part->content_offset,
                                      part->content_size,
                                      part->encoding,
                                      &is_encoding_problem);
            if (t) buf_appendcstr(&buf, t);
            free(t);
        }
        else if (!strcmp(part->type, "IMAGE")) {
            struct param *param;
            const char *fname = NULL;
            for (param = part->disposition_params; param; param = param->next) {
                if (!strncasecmp(param->attribute, "filename", 8)) {
                    fname =param->value;
                    break;
                }
            }
            buf_appendcstr(&buf, "[Inline image");
            if (fname) {
                buf_appendcstr(&buf, ":");
                buf_appendcstr(&buf, fname);
            }
            buf_appendcstr(&buf, "]");
        }
    }
    return buf_release(&buf);
}

/* Replace any <HTML> and </HTML> tags in t with <DIV> and </DIV>,
 * writing results into buf */
static void _html_concat_div(struct buf *buf, const char *t)
{
    const char *top = t + strlen(t);
    const char *p = t, *q = p;

    while (*q) {
        const char *tag = NULL;
        if (q < top - 5 && !strncasecmp(q, "<html", 5) &&
                (*(q+5) == '>' || isspace(*(q+5)))) {
            /* Found a <HTML> tag */
            tag = "<div>";
        }
        else if (q < top - 6 && !strncasecmp(q, "</html", 6) &&
                (*(q+6) == '>' || isspace(*(q+6)))) {
            /* Found a </HTML> tag */
            tag = "</div>";
        }

        /* No special tag? */
        if (!tag) {
            q++;
            continue;
        }

        /* Append whatever we saw since the last HTML tag. */
        buf_appendmap(buf, p, q - p);

        /* Look for the end of the tag and replace it, even if
         * it prematurely ends at the end of the buffer . */
        while (*q && *q != '>') { q++; }
        buf_appendcstr(buf, tag);
        if (*q) q++;

        /* Prepare for next loop */
        p = q;
    }
    buf_appendmap(buf, p, q - p);
}


static char *_emailbodies_to_html(struct emailbodies *bodies, const struct buf *msg_buf)
{
    if (bodies->htmllist.count == 1) {
        const struct body *part = ptrarray_nth(&bodies->htmllist, 0);
        int is_encoding_problem = 0;
        char *html = _decode_to_utf8(part->charset_id,
                                     msg_buf->s + part->content_offset,
                                     part->content_size,
                                     part->encoding,
                                     &is_encoding_problem);
        return html;
    }

    /* Concatenate all TEXT bodies, enclosing PLAIN text
     * in <div> and replacing <html> tags in HTML bodies
     * with <div>. */
    int i;
    struct buf buf = BUF_INITIALIZER;
    for (i = 0; i < bodies->htmllist.count; i++) {
        struct body *part = ptrarray_nth(&bodies->htmllist, i);

        /* XXX htmllist might include inlined images but we
         * currently ignore them. After all, there should
         * already be an <img> tag for their Content-Id
         * header value. If this turns out to be not enough,
         * we can insert the <img> tags here. */
        if (strcasecmp(part->type, "TEXT")) {
            continue;
        }

        if (!i)
            buf_appendcstr(&buf, "<html>"); // XXX use HTML5?

        int is_encoding_problem = 0;
        char *t = _decode_to_utf8(part->charset_id,
                                  msg_buf->s + part->content_offset,
                                  part->content_size,
                                  part->encoding,
                                  &is_encoding_problem);
        if (t && !strcmp(part->subtype, "HTML")) {
            _html_concat_div(&buf, t);
        }
        else if (t) {
            buf_appendcstr(&buf, "<div>");
            buf_appendcstr(&buf, t);
            buf_appendcstr(&buf, "</div>");
        }
        free(t);

        if (i == bodies->htmllist.count - 1)
            buf_appendcstr(&buf, "</html>");
    }
    return buf_release(&buf);
}

static int _html_to_plain_cb(const struct buf *buf, void *rock)
{
    struct buf *dst = (struct buf*) rock;
    const char *p;
    int seenspace = 0;

    /* Just merge multiple space into one. That's similar to
     * charset_extract's MERGE_SPACE but since we don't want
     * it to canonify the text into search form */
    for (p = buf_base(buf); p < buf_base(buf) + buf_len(buf) && *p; p++) {
        if (*p == ' ') {
            if (seenspace) continue;
            seenspace = 1;
        } else {
            seenspace = 0;
        }
        buf_appendmap(dst, p, 1);
    }

    return 0;
}

static char *_html_to_plain(const char *html) {
    struct buf src = BUF_INITIALIZER;
    struct buf dst = BUF_INITIALIZER;
    charset_t utf8 = charset_lookupname("utf8");
    char *text;
    char *tmp, *q;
    const char *p;

    /* Replace <br> and <p> with newlines */
    q = tmp = xstrdup(html);
    p = html;
    while (*p) {
        if (!strncmp(p, "<br>", 4) || !strncmp(p, "</p>", 4)) {
            *q++ = '\n';
            p += 4;
        }
        else if (!strncmp(p, "p>", 3)) {
            p += 3;
        } else {
            *q++ = *p++;
        }
    }
    *q = 0;

    /* Strip html tags */
    buf_init_ro(&src, tmp, q - tmp);
    buf_setcstr(&dst, "");
    charset_extract(&_html_to_plain_cb, &dst,
            &src, utf8, ENCODING_NONE, "HTML", CHARSET_KEEPCASE);
    buf_cstring(&dst);

    /* Trim text */
    buf_trim(&dst);
    text = buf_releasenull(&dst);
    if (!strlen(text)) {
        free(text);
        text = NULL;
    }

    buf_free(&src);
    free(tmp);
    charset_free(&utf8);

    return text;
}

static const char *_guid_from_id(const char *msgid)
{
    return msgid + 1;
}

static conversation_id_t _cid_from_id(const char *thrid)
{
    conversation_id_t cid = 0;
    if (thrid[0] == 'T')
        conversation_id_decode(&cid, thrid+1);
    return cid;
}

/*
 * Lookup all mailboxes where msgid is contained in.
 *
 * The return value is a JSON object keyed by the mailbox unique id,
 * and its mailbox name as value.
 */
static json_t *_email_mailboxes(jmap_req_t *req, const char *msgid)
{
    struct _email_mailboxes_rock data = { req, json_object() };
    conversations_guid_foreach(req->cstate, _guid_from_id(msgid), _email_mailboxes_cb, &data);
    return data.mboxs;
}



static void _email_read_annot(const jmap_req_t *req, msgrecord_t *mr,
                              const char *annot, struct buf *buf)
{
    if (!strncmp(annot, "/shared/", 8)) {
        msgrecord_annot_lookup(mr, annot+7, /*userid*/"", buf);
    }
    else if (!strncmp(annot, "/private/", 9)) {
        msgrecord_annot_lookup(mr, annot+8, req->userid, buf);
    }
    else {
        msgrecord_annot_lookup(mr, annot, "", buf);
    }
}

static json_t *_email_read_jannot(const jmap_req_t *req, msgrecord_t *mr,
                                  const char *annot, int structured)
{
    struct buf buf = BUF_INITIALIZER;
    json_t *annotvalue = NULL;

    _email_read_annot(req, mr, annot, &buf);

    if (buf_len(&buf)) {
        if (structured) {
            json_error_t jerr;
            annotvalue = json_loadb(buf_base(&buf), buf_len(&buf), JSON_DECODE_ANY, &jerr);
            /* XXX - log error? */
        }
        else {
            annotvalue = json_string(buf_cstring(&buf));
        }

        if (!annotvalue) {
            syslog(LOG_ERR, "jmap: annotation %s has bogus value", annot);
        }
    }
    buf_free(&buf);
    return annotvalue;
}


struct _email_find_rock {
    jmap_req_t *req;
    char *mboxname;
    uint32_t uid;
};

static int _email_find_cb(const conv_guidrec_t *rec, void *rock)
{
    struct _email_find_rock *d = (struct _email_find_rock*) rock;
    jmap_req_t *req = d->req;
    mbentry_t *mbentry = NULL;

    if (rec->part) return 0;

    conv_guidrec_mbentry(rec, &mbentry);

    /* Make sure we are allowed to read this mailbox */
    if (!mbentry || mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL ||
        !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    int r = 0;
    struct mailbox *mbox = NULL;
    r = jmap_openmbox(req, mbentry->name, &mbox, 0);
    if (r) {
        // we want to keep looking and see if we can find a mailbox we can open
        syslog(LOG_ERR, "IOERROR: email_find_cb failed to open %s: %s",
               mbentry->name, error_message(r));
        goto done;
    }

    uint32_t system_flags = 0;
    uint32_t internal_flags = 0;

    if (rec->version < 1) {
        msgrecord_t *mr = NULL;
        r = msgrecord_find(mbox, rec->uid, &mr);
        if (!r) r = msgrecord_get_systemflags(mr, &system_flags);
        if (!r) r = msgrecord_get_internalflags(mr, &internal_flags);
        msgrecord_unref(&mr);
        if (r) goto done;
    }
    else {
        system_flags = rec->system_flags;
        internal_flags = rec->internal_flags;
    }

    // if it's deleted, skip
    if ((system_flags & FLAG_DELETED) || (internal_flags & FLAG_INTERNAL_EXPUNGED))
        goto done;

    d->mboxname = xstrdup(mbentry->name);
    d->uid = rec->uid;

done:
    mboxlist_entry_free(&mbentry);
    jmap_closembox(req, &mbox);
    return d->mboxname ? IMAP_OK_COMPLETED : 0;
}

static int _email_find_in_account(jmap_req_t *req,
                                  const char *account_id,
                                  const char *email_id,
                                  char **mboxnameptr,
                                  uint32_t *uidptr)
{
    struct _email_find_rock rock = { req, NULL, 0 };
    int r;

    /* must be prefixed with 'M' */
    if (email_id[0] != 'M')
        return IMAP_NOTFOUND;
    /* this is on a 24 character prefix only */
    if (strlen(email_id) != 25)
        return IMAP_NOTFOUND;
    /* Open conversation state, if not already open */
    struct conversations_state *mycstate = NULL;
    if (strcmp(req->accountid, account_id)) {
        r = conversations_open_user(account_id, 1/*shared*/, &mycstate);
        if (r) return r;
    }
    else {
        mycstate = req->cstate;
    }
    r = conversations_guid_foreach(mycstate, _guid_from_id(email_id),
                                   _email_find_cb, &rock);
    if (mycstate != req->cstate) {
        conversations_commit(&mycstate);
    }
    /* Set return values */
    if (r == IMAP_OK_COMPLETED)
        r = 0;
    else if (!rock.mboxname)
        r = IMAP_NOTFOUND;
    *mboxnameptr = rock.mboxname;
    *uidptr = rock.uid;
    return r;
}

HIDDEN int jmap_email_find(jmap_req_t *req,
                           const char *from_accountid,
                           const char *email_id,
                           char **mboxnameptr,
                           uint32_t *uidptr)
{
    const char *accountid = from_accountid ?  from_accountid : req->accountid;

    return _email_find_in_account(req, accountid, email_id, mboxnameptr, uidptr);
}

struct email_getcid_rock {
    jmap_req_t *req;
    int checkacl;
    conversation_id_t cid;
};

static int _email_get_cid_cb(const conv_guidrec_t *rec, void *rock)
{
    if (rec->part) return 0;
    if (!rec->cid) return 0;

    struct email_getcid_rock *d = (struct email_getcid_rock *)rock;
    mbentry_t *mbentry = NULL;

    conv_guidrec_mbentry(rec, &mbentry);

    if (!mbentry || mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL ||
        (d->checkacl && !jmap_hasrights_mbentry(d->req, mbentry, JACL_READITEMS))) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }
    mboxlist_entry_free(&mbentry);

    d->cid = rec->cid;
    return IMAP_OK_COMPLETED;
}

static int _email_get_cid(jmap_req_t *req, const char *msgid,
                           conversation_id_t *cidp)
{
    int r;

    /* must be prefixed with 'M' */
    if (msgid[0] != 'M')
        return IMAP_NOTFOUND;
    /* this is on a 24 character prefix only */
    if (strlen(msgid) != 25)
        return IMAP_NOTFOUND;

    int checkacl = strcmp(req->userid, req->accountid);
    struct email_getcid_rock rock = { req, checkacl, 0 };
    r = conversations_guid_foreach(req->cstate, _guid_from_id(msgid), _email_get_cid_cb, &rock);
    if (r == IMAP_OK_COMPLETED) {
        *cidp = rock.cid;
        r = 0;
    }
    return r;
}

struct email_expunge_check {
    jmap_req_t *req;
    modseq_t since_modseq;
    int status;
};

static int _email_is_expunged_cb(const conv_guidrec_t *rec, void *rock)
{
    struct email_expunge_check *check = rock;
    msgrecord_t *mr = NULL;
    struct mailbox *mbox = NULL;
    uint32_t flags;
    int r = 0;

    if (rec->part) return 0;

    r = jmap_openmbox_by_guidrec(check->req, rec, &mbox, 0);
    if (r == IMAP_MAILBOX_NONEXISTENT) return 0;
    if (r) return r;

    if (mbtype_isa(mailbox_mbtype(mbox)) == MBTYPE_EMAIL) {
        r = msgrecord_find(mbox, rec->uid, &mr);
        if (!r) {
            uint32_t internal_flags;
            modseq_t createdmodseq;
            r = msgrecord_get_systemflags(mr, &flags);
            if (!r) msgrecord_get_internalflags(mr, &internal_flags);
            if (!r) msgrecord_get_createdmodseq(mr, &createdmodseq);
            if (!r) {
                /* OK, this is a legit record, let's check it out */
                if (createdmodseq <= check->since_modseq)
                    check->status |= 1;  /* contains old messages */
                if (!((flags & FLAG_DELETED) || (internal_flags & FLAG_INTERNAL_EXPUNGED)))
                    check->status |= 2;  /* contains alive messages */
            }
            msgrecord_unref(&mr);
        }
    }

    jmap_closembox(check->req, &mbox);
    return 0;
}

static void _email_search_perf_attr(const search_attr_t *attr, strarray_t *perf_filters)
{
    const char *cost = NULL;

    switch (search_attr_cost(attr)) {
        case SEARCH_COST_INDEX:
            cost = "index";
            break;
        case SEARCH_COST_CONV:
            cost = "conversations";
            break;
        case SEARCH_COST_ANNOT:
            cost = "annotations";
            break;
        case SEARCH_COST_CACHE:
            cost = search_attr_is_fuzzable(attr) ? "xapian" : "cache";
            break;
        case SEARCH_COST_BODY:
            cost = search_attr_is_fuzzable(attr) ? "xapian" : "body";
            break;
        default:
            ; // ignore
    }

    if (cost) strarray_add(perf_filters, cost);
}

static void _email_search_string(search_expr_t *parent,
                                 const char *s,
                                 const char *name,
                                 strarray_t *perf_filters)
{
    search_expr_t *e;
    const search_attr_t *attr = search_attr_find(name);
    enum search_op op;

    assert(attr);

    op = search_attr_is_fuzzable(attr) ? SEOP_FUZZYMATCH : SEOP_MATCH;
    e = search_expr_new(parent, op);
    e->attr = attr;
    e->value.s = xstrdup(s);
    _email_search_perf_attr(attr, perf_filters);
}

static void _email_search_type(search_expr_t *parent, const char *s, strarray_t *perf_filters)
{
    if (!strcasecmp(s, "email") || !strcasecmp(s, "message/rfc822")) {
        // XXX these do not get indexed in Xapian
        search_expr_t *e = search_expr_new(parent, SEOP_MATCH);
        e->attr = search_attr_find("contenttype");
        e->value.s = xstrdup("message/rfc822");
        _email_search_perf_attr(e->attr, perf_filters);
        return;
    }

    strarray_t types = STRARRAY_INITIALIZER;

    /* Handle type wildcards */
    if (!strcasecmp(s, "image")) {
        strarray_append(&types, "image/gif");
        strarray_append(&types, "image/jpeg");
        strarray_append(&types, "image/pjpeg");
        strarray_append(&types, "image/jpg");
        strarray_append(&types, "image/png");
        strarray_append(&types, "image/bmp");
        strarray_append(&types, "image/tiff");
    }
    else if (!strcasecmp(s, "document")) {
        strarray_append(&types, "application/msword");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.wordprocessingml.template");
        strarray_append(&types, "application/vnd.sun.xml.writer");
        strarray_append(&types, "application/vnd.sun.xml.writer.template");
        strarray_append(&types, "application/vnd.oasis.opendocument.text");
        strarray_append(&types, "application/vnd.oasis.opendocument.text-template");
        strarray_append(&types, "application/x-iwork-pages-sffpages");
        strarray_append(&types, "application/vnd.apple.pages");
    }
    else if (!strcasecmp(s, "spreadsheet")) {
        strarray_append(&types, "application/vnd.ms-excel");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.spreadsheetml.template");
        strarray_append(&types, "application/vnd.sun.xml.calc");
        strarray_append(&types, "application/vnd.sun.xml.calc.template");
        strarray_append(&types, "application/vnd.oasis.opendocument.spreadsheet");
        strarray_append(&types, "application/vnd.oasis.opendocument.spreadsheet-template");
        strarray_append(&types, "application/x-iwork-numbers-sffnumbers");
        strarray_append(&types, "application/vnd.apple.numbers");
    }
    else if (!strcasecmp(s, "presentation")) {
        strarray_append(&types, "application/vnd.ms-powerpoint");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.presentationml.presentation");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.presentationml.template");
        strarray_append(&types, "application/vnd.openxmlformats-officedocument.presentationml.slideshow");
        strarray_append(&types, "application/vnd.sun.xml.impress");
        strarray_append(&types, "application/vnd.sun.xml.impress.template");
        strarray_append(&types, "application/vnd.oasis.opendocument.presentation");
        strarray_append(&types, "application/vnd.oasis.opendocument.presentation-template");
        strarray_append(&types, "application/x-iwork-keynote-sffkey");
        strarray_append(&types, "application/vnd.apple.keynote");
    }
    else if (!strcasecmp(s, "pdf")) {
        strarray_append(&types, "application/pdf");
    }
    else {
        strarray_append(&types, s);
    }

    /* Build expression */
    const search_attr_t *attr = search_attr_find("contenttype");
    search_expr_t *p = (types.count > 1) ? search_expr_new(parent, SEOP_OR) : parent;
    char *val;
    while ((val = strarray_pop(&types))) {
        search_expr_t *e = search_expr_new(p, SEOP_FUZZYMATCH);
        e->attr = attr;
        e->value.s = val;
    }
    _email_search_perf_attr(attr, perf_filters);

    strarray_fini(&types);
}

/* ====================================================================== */

struct jmapseen_attrdata {
    struct jmapseen_folder {
        seqset_t *seendb_uids;
        enum jmapseen_source {
            jmapseen_unknown = 0,
            jmapseen_flags,
            jmapseen_db
        } seen_source;
    } *folders;
    int numfolders;
    char *userid;
    struct seen *seendb;
    size_t refcount;
};

struct jmapseen_mboxdata {
    struct conversations_state *cstate;
    int foldernum;
};

static void emailsearch_jmapseen_internalise(struct index_state *state,
                                             const union search_value *v,
                                             void *data1,
                                             void **internalisedp)
{
    if (*internalisedp) {
        struct emailsearch_jmapseen_mboxdata *md = *internalisedp;
        free(md);
        *internalisedp = NULL;
    }

    if (state && v) {
        struct conversations_state *cstate = mailbox_get_cstate(state->mailbox);
        if (!cstate) {
            xsyslog(LOG_ERR, "could not read conversations state",
                    "mboxid=<%s>", mailbox_uniqueid(state->mailbox));
            return;
        }

        // Initialize attribute context
        struct jmapseen_attrdata *ad = data1;
        if (!ad->userid) {
            // Only support queries for a single user, e.g.
            // can't mix multiple 'jmapseen' filters for
            // different userids in the same search tree.
            ad->userid = xstrdup(v->s);
        }

        if (!ad->folders && state) {
            ad->numfolders = conversations_num_folders(cstate);
            if (ad->numfolders) {
                // assumes that conversations folders do not change
                // during the lifetime of the query. this should
                // hold since the JMAP request holds a read lock
                // on conversations.
                ad->folders = xzmalloc(ad->numfolders * sizeof(struct jmapseen_folder));
            }
            if (!ad->folders) {
                xsyslog(LOG_ERR, "could not initialize jmapseen attribute", NULL);
                xzfree(ad->userid);
                return;
            }
        }

        // Initialize mailbox context
        struct jmapseen_mboxdata *md = xzmalloc(sizeof(struct jmapseen_mboxdata));
        md->cstate = mailbox_get_cstate(state->mailbox);
        md->foldernum = conversation_folder_number(md->cstate,
                CONV_FOLDER_KEY_MBOX(md->cstate, state->mailbox), 0);
        *internalisedp = md;

        // Determine where to read seen flags from for this mailbox
        ad->folders[md->foldernum].seen_source =
            mailbox_internal_seen(state->mailbox, ad->userid) ?
            jmapseen_flags : jmapseen_db;
    }
}

static int jmapseen_has_seenflag(struct jmapseen_attrdata *ad,
                                 struct conversations_state *cstate,
                                 int foldernum,
                                 uint32_t uid,
                                 uint32_t system_flags)
{
    if (ad->folders[foldernum].seen_source == jmapseen_unknown) {
        // don't know where to read seen flags for this mailbox from
        const char *mboxname = conversations_folder_mboxname(cstate, foldernum);
        if (mboxname_userownsmailbox(ad->userid, mboxname)) {
            // owners always store seen in flags
            ad->folders[foldernum].seen_source = jmapseen_flags;
        }
        else {
            // need to open mailbox to read OPT_SHAREDSEEN
            struct mailbox *mbox = NULL;
            int r = mailbox_open_irlnb(mboxname, &mbox); // non-blocking
            if (!r) {
                ad->folders[foldernum].seen_source =
                    mailbox_internal_seen(mbox, ad->userid) ?
                    jmapseen_flags : jmapseen_db;
                mailbox_close(&mbox);
            }
            else if (r) {
                // could try later for locked mailboxes, but
                // let's not amplify mailbox open attempts
                xsyslog(LOG_ERR, "can not open mailbox, fall back to system flags",
                        "mboxname=<%s> err=<%s>", mboxname, error_message(r));
                ad->folders[foldernum].seen_source = jmapseen_flags;
            }
        }
    }

    if (ad->folders[foldernum].seen_source == jmapseen_flags) {
        // read seen flag from system flags
        return !!(system_flags & FLAG_SEEN);
    }

    if (ad->folders[foldernum].seen_source == jmapseen_db) {
        // read seen flag from seendb
        if (!ad->seendb) {
            int r = seen_open(ad->userid, SEEN_SILENT, &ad->seendb);
            if (r) {
                xsyslog(LOG_ERR, "can not open seendb, fall back to system flags",
                        "userid=<%s> err=<%s>", ad->userid, error_message(r));
                for (int i = 0; i < ad->numfolders; i++) {
                    // don't try to open seendb for any mailbox
                    ad->folders[i].seen_source = jmapseen_flags;
                }
            }
        }

        if (ad->seendb && !ad->folders[foldernum].seendb_uids) {
            // read sequence of seen uids from seendb,
            struct seendata sd = SEENDATA_INITIALIZER;
            const char *mboxid = conversations_folder_uniqueid(cstate, foldernum);
            int r = seen_read(ad->seendb, mboxid, &sd);
            if (!r) {
                ad->folders[foldernum].seendb_uids =
                    seqset_parse(sd.seenuids, NULL, sd.lastuid);
                seen_freedata(&sd);
            }
            else {
                xsyslog(LOG_ERR, "can not read seen data. fall back to system flags",
                        "userid=<%s> mboxid=<%s> err=<%s>",
                        ad->userid, mboxid, error_message(r));
                // don't try to read seen db for this mailbox
                ad->folders[foldernum].seen_source = jmapseen_flags;
            }
        }

        if (ad->folders[foldernum].seendb_uids) {
            return seqset_ismember(ad->folders[foldernum].seendb_uids, uid);
        }
    }

    // fall back
    return !!(system_flags & FLAG_SEEN);
}

struct jmapseen_guid_counts {
    struct jmapseen_attrdata *ad;
    struct jmapseen_mboxdata *md;
    unsigned exists;
    unsigned seen;
};

static int jmapseen_guid_cb(const conv_guidrec_t *rec, void *rock)
{
    struct jmapseen_guid_counts *counts = rock;

    if (!(rec->system_flags & FLAG_DELETED) &&
        !(rec->internal_flags & FLAG_INTERNAL_EXPUNGED)) {

        counts->exists++;

        if (jmapseen_has_seenflag(counts->ad, counts->md->cstate,
                    rec->foldernum, rec->uid, rec->system_flags))
            counts->seen++;
    }

    return 0;
}

static int emailsearch_jmapseen_match(message_t *m,
                                      const union search_value *v __attribute__((unused)),
                                      void *internalised,
                                      void *data1)
{
    if (!internalised) return 0;

    struct jmapseen_attrdata *ad = data1;
    struct jmapseen_mboxdata *md = internalised;

    if (!ad->userid || !ad->folders) {
        // invalid attribute state
        return 0;
    }

    uint32_t uid, flags;
    message_get_uid(m, &uid);
    message_get_systemflags(m, &flags);
    int has_seenflag = jmapseen_has_seenflag(ad, md->cstate, md->foldernum, uid, flags);

    // Trash only counts its own seen messages
    if (md->foldernum == md->cstate->trashfolder)
        return has_seenflag;

    // The mail is unseen if it unseen in this mailbox
    if (!has_seenflag)
        return 0;

    if (ad->folders[md->foldernum].seen_source == jmapseen_flags) {
        // The email is seen if we do not need to look at seendb and
        // the whole conversation is seen
        conversation_id_t cid = NULLCONVERSATION;
        if (!message_get_cid(m, &cid)) {
            conversation_t conv = CONVERSATION_INIT;
            if (!conversation_load_advanced(md->cstate, cid, &conv, 0)) {
                int is_seen = conv.exists && conv.unseen == 0;
                conversation_fini(&conv);
                if (is_seen) return 1;
            }
        }
    }

    // The email is seen if all G records for the guid are seen
    struct jmapseen_guid_counts counts = { .ad = ad, .md = md };
    const struct message_guid *guid;
    if (!message_get_guid(m, &guid)) {
        conversations_guid_foreach(md->cstate,
                message_guid_encode(guid), jmapseen_guid_cb, &counts);
    }
    return counts.exists == counts.seen;
}

static void emailsearch_jmapseen_serialise(struct buf *b, const union search_value *v)
{
    buf_printf(b, "\"%s\"", v->s);
}

static int emailsearch_jmapseen_unserialise(struct protstream *prot, union search_value *v)
{
    int c;
    char tmp[1024];

    c = search_getseword(prot, tmp, sizeof(tmp));
    v->s = xstrdup(tmp);
    return c;
}

static void emailsearch_jmapseen_duplicate(union search_value *new,
                                    const union search_value *old)
{
    new->s = xstrdup(old->s);
}

static void emailsearch_jmapseen_decref(struct search_attr **attrp)
{
    if (!attrp) return;
    search_attr_t *attr = *attrp;
    if (!attr) return;

    struct jmapseen_attrdata *ad = attr->data1;
    if (ad) {
        if (ad->refcount)
            --ad->refcount;
        if (!ad->refcount) {
            if (ad->seendb)
                seen_close(&ad->seendb);
            for (int i = 0; i < ad->numfolders; i++) {
                if (ad->folders[i].seendb_uids)
                    seqset_free(&ad->folders[i].seendb_uids);
            }
            free(ad->folders);
            free(ad->userid);
            xzfree(ad);
            free(*attrp);
            *attrp = NULL;
        }
    }
}

static search_attr_t *emailsearch_jmapseen_incref(search_attr_t *attr)
{
    if (!attr || !attr->data1) return attr;
    struct jmapseen_attrdata *ad = attr->data1;
    ad->refcount++;
    return attr;
}

static void emailsearch_jmapseen_free(union search_value *v, struct search_attr **attrp)
{
    emailsearch_jmapseen_decref(attrp);
    free(v->s);
    v->s = NULL;
}


static search_attr_t *emailsearch_jmapseen_new(void)
{
    static const search_attr_t template = {
        "jmapseen",
        SEA_MUTABLE,
        SEARCH_PART_NONE,
        SEARCH_COST_CONV,
        emailsearch_jmapseen_internalise,
        /*cmp*/NULL,
        emailsearch_jmapseen_match,
        emailsearch_jmapseen_serialise,
        emailsearch_jmapseen_unserialise,
        /*get_countability*/NULL,
        emailsearch_jmapseen_duplicate,
        emailsearch_jmapseen_free,
        emailsearch_jmapseen_decref,
        emailsearch_jmapseen_incref,
        (void *)0
    };

    search_attr_t *attr = xmalloc(sizeof(search_attr_t));
    memcpy(attr, &template, sizeof(search_attr_t));

    struct jmapseen_attrdata *ad = xzmalloc(sizeof(struct jmapseen_attrdata));
    ad->refcount++;
    attr->data1 = ad;

    return attr;
}

/* ====================================================================== */

static void _email_search_keyword(search_expr_t *parent,
                                  const char *keyword,
                                  const char *userid,
                                  ptrarray_t *search_attrs,
                                  strarray_t *perf_filters)
{
    search_expr_t *e;
    if (!strcasecmp(keyword, "$Seen")) {
        search_attr_t *attr = NULL;
        int i;
        for (i = 0; i < ptrarray_size(search_attrs); i++) {
            search_attr_t *sattr = ptrarray_nth(search_attrs, i);
            if (!strcmpsafe(sattr->name, "jmapseen")) {
                attr = sattr;
                break;
            }
        }
        if (!attr) {
            attr = emailsearch_jmapseen_new();
            ptrarray_append(search_attrs, attr);
        }
        e = search_expr_new(parent, SEOP_MATCH);
        e->attr = emailsearch_jmapseen_incref(attr);
        e->value.s = xstrdup(userid);
    }
    else if (!strcasecmp(keyword, "$Draft")) {
        e = search_expr_new(parent, SEOP_MATCH);
        e->attr = search_attr_find("systemflags");
        e->value.u = FLAG_DRAFT;
    }
    else if (!strcasecmp(keyword, "$Flagged")) {
        e = search_expr_new(parent, SEOP_MATCH);
        e->attr = search_attr_find("systemflags");
        e->value.u = FLAG_FLAGGED;
    }
    else if (!strcasecmp(keyword, "$Answered")) {
        e = search_expr_new(parent, SEOP_MATCH);
        e->attr = search_attr_find("systemflags");
        e->value.u = FLAG_ANSWERED;
    }
    else {
        e = search_expr_new(parent, SEOP_MATCH);
        e->attr = search_attr_find("keyword");
        e->value.s = xstrdup(keyword);
    }
    _email_search_perf_attr(e->attr, perf_filters);
}

static void _email_search_threadkeyword(search_expr_t *parent, const char *keyword,
                                        int matchall, strarray_t *perf_filters)
{
    const char *flag = jmap_keyword_to_imap(keyword);
    if (!flag) return;

    if (!strcasecmp(flag, "\\Seen"))
        flag = "\\SeenInclTrash";

    search_expr_t *e = search_expr_new(parent, SEOP_MATCH);
    e->attr = search_attr_find(matchall ? "allconvflags" : "convflags");
    e->value.s = xstrdup(flag);
    _email_search_perf_attr(e->attr, perf_filters);
}

static void _email_search_contactgroup(search_expr_t *parent,
                                       const char *groupid,
                                       const char *attrname,
                                       hash_table *contactgroups,
                                       strarray_t *perf_filters)
{
    if (!contactgroups || !contactgroups->size) return;

    strarray_t *members = hash_lookup(groupid, contactgroups);
    if (!members || !strarray_size(members)) {
        search_expr_new(parent, SEOP_FALSE);
        return;
    }

    charset_t utf8 = charset_lookupname("utf-8");
    strarray_t *val = strarray_new();
    int i;
    for (i = 0; i < strarray_size(members); i++) {
        const char *member = strarray_nth(members, i);
        if (!strchr(member, '@')) continue;
        strarray_append(val, member);
    }
    charset_free(&utf8);
    if (!strarray_size(val)) {
        strarray_free(val);
        search_expr_new(parent, SEOP_FALSE);
        return;
    }

    const search_attr_t *attr = search_attr_find(attrname);
    search_expr_t *e = search_expr_new(parent, SEOP_FUZZYMATCH);
    e->attr = attr;
    e->value.list = val;
    _email_search_perf_attr(e->attr, perf_filters);
}

/* ====================================================================== */

struct emailsearch_folders_value {
    strarray_t folderids;
    strarray_t foldernames;
    bitvector_t foldernums;
    int is_otherthan : 1;
    int want_expunged : 1;
};

static void emailsearch_folders_value_free(struct emailsearch_folders_value **valp)
{
    if (!valp || !*valp) return;

    struct emailsearch_folders_value *val = *valp;
    strarray_fini(&val->foldernames);
    strarray_fini(&val->folderids);
    bv_fini(&val->foldernums);

    free(val);
    *valp = NULL;
}

static struct emailsearch_folders_value *
emailsearch_folders_value_new(jmap_req_t *req,
                              json_t *jmboxids,
                              int is_otherthan,
                              int want_expunged)
{
    struct emailsearch_folders_value *val =
        xzmalloc(sizeof(struct emailsearch_folders_value));

    if (is_otherthan)
        val->is_otherthan = 1;
    if (want_expunged)
        val->want_expunged = 1;

    json_t *jmboxid;
    size_t i;
    json_array_foreach(jmboxids, i, jmboxid) {
        const char *mboxid = json_string_value(jmboxid);
        const mbentry_t *mbentry = jmap_mbentry_by_uniqueid(req, mboxid);
        if (mbentry && mbtype_isa(mbentry->mbtype) == MBTYPE_EMAIL &&
                jmap_hasrights_mbentry(req, mbentry, JACL_LOOKUP)) {
            int foldernum = conversation_folder_number(req->cstate,
                    CONV_FOLDER_KEY_MBE(req->cstate, mbentry), 0);
            if (foldernum >= 0) {
                bv_set(&val->foldernums, foldernum);
                strarray_append(&val->foldernames, mbentry->name);
                strarray_append(&val->folderids, mbentry->uniqueid);
            }
        }
    }

    if (!bv_count(&val->foldernums)) {
        emailsearch_folders_value_free(&val);
    }

    return val;
}

struct emailsearch_folders_internal
{
    struct conversations_state *cstate;
    int is_filtered_folder;
};

static void emailsearch_folders_internalise(struct index_state *state,
                                            const union search_value *v,
                                            void *data1 __attribute__((unused)),
                                            void **internalisedp)
{
    if (*internalisedp) {
        struct emailsearch_folders_internal *internal = *internalisedp;
        free(internal);
        *internalisedp = NULL;
    }
    if (state && v) {
        struct emailsearch_folders_internal *internal =
            xzmalloc(sizeof(struct emailsearch_folders_internal));
        internal->cstate = mailbox_get_cstate(state->mailbox);

        struct emailsearch_folders_value *val = v->v;
        if (strarray_size(&val->folderids) && !bv_count(&val->foldernums)) {
            /* This must be a deserialised value. Now that we have
             * an open conversation.db, convert it to a proper value. */
            int i;
            for (i = 0; i < strarray_size(&val->folderids); i++) {
                const char *mboxid = strarray_nth(&val->folderids, i);
                mbentry_t *mbentry = NULL;
                if (!mboxlist_lookup_by_uniqueid(mboxid, &mbentry, NULL)) {
                    int foldernum =
                        conversation_folder_number(internal->cstate,
                                CONV_FOLDER_KEY_MBE(internal->cstate, mbentry), 0);
                    if (foldernum >= 0) {
                        bv_set(&val->foldernums, foldernum);
                        strarray_append(&val->foldernames, mbentry->name);
                    }
                }
            }
        }


        int foldernum = conversation_folder_number(internal->cstate,
                CONV_FOLDER_KEY_MBOX(internal->cstate, state->mailbox), 0);
        if (foldernum >= 0) {
            internal->is_filtered_folder =
                bv_isset(&val->foldernums, foldernum);
        }
        *internalisedp = internal;
    }
}

static int emailsearch_folders_match_cb(const conv_guidrec_t *rec, void *rock)
{
    struct emailsearch_folders_value *val = rock;
    if (!val->want_expunged &&
            ((rec->system_flags & FLAG_DELETED) ||
             (rec->internal_flags & FLAG_INTERNAL_EXPUNGED))) {
        return 0;
    }
    int isset = bv_isset(&val->foldernums, rec->foldernum);
    return !isset == !val->is_otherthan ? 0 : IMAP_OK_COMPLETED;
}

static int emailsearch_folders_match(message_t *m,
                                     const union search_value *v,
                                     void *internalised,
                                     void *data1 __attribute__((unused)))
{
    struct emailsearch_folders_internal *internal = internalised;
    struct emailsearch_folders_value *val = v->v;

    if ((internal->is_filtered_folder && !val->is_otherthan) ||
        (!internal->is_filtered_folder && val->is_otherthan)) {
        /* Trivial match */
        return 1;
    }

    /* Match using conversations.db */
    if (!internal->cstate) return 0;
    const struct message_guid *guid = NULL;
    int r = message_get_guid(m, &guid);
    if (r) return 0;
    r = conversations_guid_foreach(internal->cstate,
            message_guid_encode(guid), emailsearch_folders_match_cb, val);
    return r == IMAP_OK_COMPLETED;
}

static void emailsearch_folders_serialise(struct buf *buf,
                                          const union search_value *v)
{
    struct emailsearch_folders_value *val = v->v;

    buf_appendcstr(buf, val->is_otherthan ?
            "inMailboxOtherThan" : "inMailbox");
    buf_putc(buf, ' ');

    buf_appendcstr(buf, val->want_expunged ?
            "wantExpunged" : "skipExpunged");
    buf_putc(buf, ' ');

    buf_putc(buf, '(');
    int i;
    for (i = 0; i < strarray_size(&val->folderids); i++) {
        buf_appendcstr(buf, strarray_nth(&val->folderids, i));
        if (i < strarray_size(&val->folderids) - 1)
            buf_putc(buf, ' ');
    }
    buf_putc(buf, ')');
}

static int emailsearch_folders_unserialise(struct protstream* prot,
                                           union search_value *v)
{
    struct dlist *dl = NULL;

    int c = dlist_parse_asatomlist(&dl, 0, prot);
    if (c == EOF) return c;

    struct dlist_print_iter *iter = dlist_print_iter_new(dl, 0);
    if (!iter) {
        xsyslog(LOG_ERR, "bogus value", NULL);
        return c;
    }

    struct emailsearch_folders_value *val =
        xzmalloc(sizeof(struct emailsearch_folders_value));

    struct buf buf = BUF_INITIALIZER;
    if (dlist_print_iter_step(iter, &buf)) {
        if (!strcmp(buf_cstring(&buf), "inMailboxOtherThan"))
            val->is_otherthan = 1;
        buf_reset(&buf);
    }
    else {
        xsyslog(LOG_ERR, "expected is_otherthan", NULL);
        emailsearch_folders_value_free(&val);
        goto done;
    }
    if (dlist_print_iter_step(iter, &buf)) {
        if (!strcmp(buf_cstring(&buf), "wantExpunged"))
            val->want_expunged = 1;
        buf_reset(&buf);
    }
    else {
        xsyslog(LOG_ERR, "expected want_expunged", NULL);
        emailsearch_folders_value_free(&val);
        goto done;
    }
    while (iter && dlist_print_iter_step(iter, &buf)) {
        if (buf_len(&buf)){
            strarray_append(&val->folderids, buf_cstring(&buf));
        }
        buf_reset(&buf);
    }
    buf_free(&buf);

done:
    dlist_print_iter_free(&iter);
    v->v = val;
    return c;
}

static void emailsearch_folders_duplicate(union search_value *new,
                                           const union search_value *old)
{
    struct emailsearch_folders_value *newv =
        xzmalloc(sizeof(struct emailsearch_folders_value));
    struct emailsearch_folders_value *oldv = old->v;

    strarray_cat(&newv->foldernames, &oldv->foldernames);
    strarray_cat(&newv->folderids, &oldv->folderids);
    bv_copy(&newv->foldernums, &oldv->foldernums);

    newv->is_otherthan = oldv->is_otherthan;
    newv->want_expunged = oldv->want_expunged;

    new->v = newv;
}

static void emailsearch_folders_free(union search_value *v,
                                     struct search_attr **attrp __attribute__((unused)))
{
    struct emailsearch_folders_value *val = v->v;
    emailsearch_folders_value_free(&val);
}

static const search_attr_t emailsearch_folders_attr = {
    "jmap_folders",
    SEA_MUTABLE,
    SEARCH_PART_NONE,
    SEARCH_COST_CONV,
    emailsearch_folders_internalise,
    /*cmp*/NULL,
    emailsearch_folders_match,
    emailsearch_folders_serialise,
    emailsearch_folders_unserialise,
    /*get_countability*/NULL,
    emailsearch_folders_duplicate,
    emailsearch_folders_free,
    /*freeattr*/NULL,
    /*dupattr*/NULL,
    (void*)0 /*is_otherthan*/
};

/* ====================================================================== */

static void emailsearch_headermatch_internalise(struct index_state *state __attribute__((unused)),
                                                 const union search_value *v __attribute__((unused)),
                                                 void *data1 __attribute__((unused)),
                                                 void **internalisedp __attribute__((unused)))
{
}

static int emailsearch_headermatch_match(message_t *msg,
                                          const union search_value *v,
                                          void *internalised __attribute__((unused)),
                                          void *data1 __attribute__((unused)))
{
    return jmap_headermatch_match((struct jmap_headermatch *)v->v, msg);
}

static void emailsearch_headermatch_serialise(struct buf *buf,
                                               const union search_value *v)
{
    struct jmap_headermatch *hm = v->v;
    struct dlist *dl = dlist_newlist(NULL, NULL);
    dlist_setatom(dl, NULL, hm->header);
    switch (hm->op) {
        case HEADERMATCH_EQUALS:
            dlist_setatom(dl, NULL, "equals");
            break;
        case HEADERMATCH_STARTS:
            dlist_setatom(dl, NULL, "starts");
            break;
        case HEADERMATCH_ENDS:
            dlist_setatom(dl, NULL, "ends");
            break;
        default:
            dlist_setatom(dl, NULL, "contains");
    }
    dlist_setatom(dl, NULL, hm->value);
    dlist_printbuf(dl, 0, buf);
    dlist_free(&dl);
}

static int emailsearch_headermatch_unserialise(struct protstream* prot,
                                                union search_value *v)
{
    struct dlist *dl = NULL;

    int c = dlist_parse_asatomlist(&dl, 0, prot);
    if (c == EOF) return EOF;

    struct buf header = BUF_INITIALIZER;
    struct buf op = BUF_INITIALIZER;
    struct buf value = BUF_INITIALIZER;
    struct dlist_print_iter *iter = dlist_print_iter_new(dl, 0);
    dlist_print_iter_step(iter, &header);
    dlist_print_iter_step(iter, &op);
    dlist_print_iter_step(iter, &value);
    struct jmap_headermatch *hm =
        jmap_headermatch_new(buf_cstring(&header), buf_cstring(&op),
                             buf_cstring(&value));
    v->v = hm;
    buf_free(&value);
    buf_free(&op);
    buf_free(&header);
    dlist_print_iter_free(&iter);

    dlist_free(&dl);
    return c;
}

static void emailsearch_headermatch_duplicate(union search_value *new,
                                               const union search_value *old)
{
    new->v = jmap_headermatch_dup((struct jmap_headermatch *)old->v);
}

static void emailsearch_headermatch_free(union search_value *v,
                                         struct search_attr **attrp __attribute__((unused)))
{
    struct jmap_headermatch *hm = v->v;
    jmap_headermatch_free(&hm);
    v->v = NULL;
}

static const search_attr_t emailsearch_headermatch_attr_uncached = {
    "jmap_headermatch_uncached",
    /*flags*/0,
    SEARCH_PART_NONE,
    SEARCH_COST_BODY,
    emailsearch_headermatch_internalise,
    /*cmp*/NULL,
    emailsearch_headermatch_match,
    emailsearch_headermatch_serialise,
    emailsearch_headermatch_unserialise,
    /*get_countability*/NULL,
    emailsearch_headermatch_duplicate,
    emailsearch_headermatch_free,
    /*freeattr*/NULL,
    /*dupattr*/NULL,
    NULL
};

static const search_attr_t emailsearch_headermatch_attr_cached = {
    "jmap_headermatch_cached",
    /*flags*/0,
    SEARCH_PART_NONE,
    SEARCH_COST_CACHE,
    emailsearch_headermatch_internalise,
    /*cmp*/NULL,
    emailsearch_headermatch_match,
    emailsearch_headermatch_serialise,
    emailsearch_headermatch_unserialise,
    /*get_countability*/NULL,
    emailsearch_headermatch_duplicate,
    emailsearch_headermatch_free,
    /*freeattr*/NULL,
    /*dupattr*/NULL,
    NULL
};

/* ====================================================================== */

static search_expr_t *_email_buildsearchexpr(jmap_req_t *req, json_t *filter,
                                             search_expr_t *parent,
                                             hash_table *contactgroups,
                                             int want_expunged,
                                             ptrarray_t *search_attrs,
                                             strarray_t *perf_filters)
{
    search_expr_t *this, *e;
    json_t *val;
    const char *s;
    size_t i;
    time_t t;

    if (!JNOTNULL(filter)) {
        return search_expr_new(parent, SEOP_TRUE);
    }

    if ((s = json_string_value(json_object_get(filter, "operator")))) {
        enum search_op op = SEOP_UNKNOWN;

        if (!strcmp("AND", s)) {
            op = SEOP_AND;
        } else if (!strcmp("OR", s)) {
            op = SEOP_OR;
        } else if (!strcmp("NOT", s)) {
            op = SEOP_NOT;
        }

        this = search_expr_new(parent, op);
        e = op == SEOP_NOT ? search_expr_new(this, SEOP_OR) : this;

        json_array_foreach(json_object_get(filter, "conditions"), i, val) {
            _email_buildsearchexpr(req, val, e, contactgroups, want_expunged,
                    search_attrs, perf_filters);
        }
    } else {
        this = search_expr_new(parent, SEOP_AND);

        /* zero properties evaluate to true */
        search_expr_new(this, SEOP_TRUE);

        if ((s = json_string_value(json_object_get(filter, "after")))) {
            time_from_iso8601(s, &t);
            e = search_expr_new(this, SEOP_GE);
            e->attr = search_attr_find("internaldate");
            e->value.u = t;
            _email_search_perf_attr(e->attr, perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "before")))) {
            time_from_iso8601(s, &t);
            e = search_expr_new(this, SEOP_LE);
            e->attr = search_attr_find("internaldate");
            e->value.u = t;
            _email_search_perf_attr(e->attr, perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "body")))) {
            _email_search_string(this, s, "body", perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "cc")))) {
            _email_search_string(this, s, "cc", perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "bcc")))) {
            _email_search_string(this, s, "bcc", perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "deliveredTo")))) {
            /* non-standard */
            _email_search_string(this, s, "deliveredto", perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "from")))) {
            _email_search_string(this, s, "from", perf_filters);
        }
        if (json_is_true(json_object_get(filter, "fromAnyContact"))) {
            _email_search_contactgroup(this, "", "fromlist", contactgroups, perf_filters);
        }
        if (json_is_true(json_object_get(filter, "toAnyContact"))) {
            _email_search_contactgroup(this, "", "tolist", contactgroups, perf_filters);
        }
        if (json_is_true(json_object_get(filter, "ccAnyContact"))) {
            _email_search_contactgroup(this, "", "cclist", contactgroups, perf_filters);
        }
        if (json_is_true(json_object_get(filter, "bccAnyContact"))) {
            _email_search_contactgroup(this, "", "bcclist", contactgroups, perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "fromContactGroupId")))) {
            _email_search_contactgroup(this, s, "fromlist", contactgroups, perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "toContactGroupId")))) {
            _email_search_contactgroup(this, s, "tolist", contactgroups, perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "ccContactGroupId")))) {
            _email_search_contactgroup(this, s, "cclist", contactgroups, perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "bccContactGroupId")))) {
            _email_search_contactgroup(this, s, "bcclist", contactgroups, perf_filters);
        }
        if (JNOTNULL((val = json_object_get(filter, "hasAttachment")))) {
            e = val == json_false() ? search_expr_new(this, SEOP_NOT) : this;
            e = search_expr_new(e, SEOP_MATCH);
            e->attr = search_attr_find("keyword");
            e->value.s = xstrdup(JMAP_HAS_ATTACHMENT_FLAG);
            _email_search_perf_attr(e->attr, perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "attachmentName")))) {
            _email_search_string(this, s, "attachmentname", perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "attachmentType")))) {
            _email_search_type(this, s, perf_filters);
        }
        if (JNOTNULL((val = json_object_get(filter, "header")))) {
            const char *hdr = NULL, *str = "", *cmp = NULL;
            search_expr_t *e;

            switch (json_array_size(val)) {
                case 3:
                    cmp = json_string_value(json_array_get(val, 2));
                    GCC_FALLTHROUGH
                case 2:
                    str = json_string_value(json_array_get(val, 1));
                    GCC_FALLTHROUGH
                case 1:
                    hdr = json_string_value(json_array_get(val, 0));
                    break;
                default:
                    assert(0); // validation must reject this
            }

            e = search_expr_new(this, SEOP_MATCH);
            // use the right cost, the query optimizer will need it
            const search_attr_t *attr = search_attr_find_field(hdr);
            e->attr = attr->cost == SEARCH_COST_CACHE ?
                &emailsearch_headermatch_attr_cached :
                &emailsearch_headermatch_attr_uncached;
            e->value.v = jmap_headermatch_new(hdr, str, cmp);

            _email_search_perf_attr(e->attr, perf_filters);
        }

        if (JNOTNULL((val = json_object_get(filter, "inMailbox")))) {
            json_t *myval = json_array();
            json_array_append(myval, val);
            struct emailsearch_folders_value *v =
                emailsearch_folders_value_new(req, myval, 0, want_expunged);
            if (v) {
                search_expr_t *e = search_expr_new(this, SEOP_MATCH);
                e->attr = &emailsearch_folders_attr;
                e->value.v = v;
                strarray_add(perf_filters, "mailbox");
            }
            else {
                e = search_expr_new(this, SEOP_FALSE);
            }
            json_decref(myval);
        }

        if (JNOTNULL((val = json_object_get(filter, "inMailboxOtherThan")))) {
            struct emailsearch_folders_value *v =
                emailsearch_folders_value_new(req, val, 1, want_expunged);
            if (v) {
                search_expr_t *e = search_expr_new(this, SEOP_MATCH);
                e->attr = &emailsearch_folders_attr;
                e->value.v = v;
                strarray_add(perf_filters, "mailbox");
            }
            else {
                e = search_expr_new(this, SEOP_TRUE);
            }
        }

        if (JNOTNULL((val = json_object_get(filter, "allInThreadHaveKeyword")))) {
            _email_search_threadkeyword(this, json_string_value(val), 1, perf_filters);
        }
        if (JNOTNULL((val = json_object_get(filter, "someInThreadHaveKeyword")))) {
            _email_search_threadkeyword(this, json_string_value(val), 0, perf_filters);
        }
        if (JNOTNULL((val = json_object_get(filter, "noneInThreadHaveKeyword")))) {
            e = search_expr_new(this, SEOP_NOT);
            _email_search_threadkeyword(e, json_string_value(val), 0, perf_filters);
        }

        if (JNOTNULL((val = json_object_get(filter, "hasKeyword")))) {
            _email_search_keyword(this, json_string_value(val), req->userid, search_attrs, perf_filters);
        }
        if (JNOTNULL((val = json_object_get(filter, "notKeyword")))) {
            e = search_expr_new(this, SEOP_NOT);
            _email_search_keyword(e, json_string_value(val), req->userid, search_attrs, perf_filters);
        }

        if (JNOTNULL((val = json_object_get(filter, "maxSize")))) {
            e = search_expr_new(this, SEOP_LE);
            e->attr = search_attr_find("size");
            e->value.u = json_integer_value(val);
            _email_search_perf_attr(e->attr, perf_filters);
        }
        if (JNOTNULL((val = json_object_get(filter, "minSize")))) {
            e = search_expr_new(this, SEOP_GE);
            e->attr = search_attr_find("size");
            e->value.u = json_integer_value(val);
            _email_search_perf_attr(e->attr, perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "sinceEmailState")))) {
            /* non-standard */
            e = search_expr_new(this, SEOP_GT);
            e->attr = search_attr_find("modseq");
            e->value.u = atomodseq_t(s);
            _email_search_perf_attr(e->attr, perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "subject")))) {
            _email_search_string(this, s, "subject", perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "text")))) {
            _email_search_string(this, s, "text", perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "attachmentBody")))) {
            _email_search_string(this, s, "attachmentbody", perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "to")))) {
            _email_search_string(this, s, "to", perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "language")))) {
            /* non-standard */
            search_expr_t *e = search_expr_new(this, SEOP_FUZZYMATCH);
            e->attr = search_attr_find("language");
            e->value.s = xstrdup(s);
            _email_search_perf_attr(e->attr, perf_filters);
        }
        if (JNOTNULL(val = json_object_get(filter, "isHighPriority"))) {
            /* non-standard */
            search_expr_t *parent = val != json_true() ?
                                    search_expr_new(this, SEOP_NOT) : this;
            search_expr_t *e = search_expr_new(parent, SEOP_FUZZYMATCH);
            e->attr = search_attr_find("priority");
            e->value.s = xstrdup("1");
            _email_search_perf_attr(e->attr, perf_filters);
        }
        if ((s = json_string_value(json_object_get(filter, "listId")))) {
            /* non-standard */
            struct buf buf = BUF_INITIALIZER;
            const char *val = s;
            if (!strchr(s, '<')) {
                buf_putc(&buf, '<');
                buf_appendcstr(&buf, s);
                buf_putc(&buf, '>');
                val = buf_cstring(&buf);
            }
            _email_search_string(this, val, "listid", perf_filters);
            buf_free(&buf);
        }
    }

    return this;
}

static int is_single_inmailbox_expr(search_expr_t *e)
{
    if (e->op != SEOP_MATCH || strcmp(e->attr->name, "jmap_folders")) {
        return 0;
    }
    struct emailsearch_folders_value *val = e->value.v;
    if (val->is_otherthan || strarray_size(&val->foldernames) != 1) {
        return 0;
    }
    return 1;
}

static int convert_foldermatch(search_expr_t *e,
                               strarray_t *preferred_folders,
                               int only_preferred)
{
    if (!is_single_inmailbox_expr(e)) return 0;

    struct emailsearch_folders_value *val = e->value.v;
    const char *folder = strarray_nth(&val->foldernames, 0);
    int is_preferred = strarray_find(preferred_folders, folder, 0) >= 0;
    if (!is_preferred && only_preferred) {
        return 0;
    }
    else if (!is_preferred) {
        strarray_append(preferred_folders, folder);
    }

    char *folderm = strarray_pop(&val->foldernames);
    emailsearch_folders_value_free(&val);
    e->attr = search_attr_find("folder");
    e->value.s = folderm;

    return 1;
}

static void convert_folderclause(search_expr_t *clause,
                                 strarray_t *preferred_folders,
                                 int *is_imapfolderptr)
{
    assert(clause->op != SEOP_OR);

    if (clause->op == SEOP_AND) {
        int found_foldermatch = 0;
        /* First pass. Convert preferred folder expression. */
        search_expr_t *c;
        for (c = clause->children; c; c = c->next) {
            if (convert_foldermatch(c, preferred_folders, 1)) {
                found_foldermatch = 1;
                break;
            }
        }
        if (!found_foldermatch) {
            /* Second pass. Convert any folder expression. */
            for (c = clause->children; c; c = c->next) {
                if (convert_foldermatch(c, preferred_folders, 0)) {
                    found_foldermatch = 1;
                    break;
                }
            }
        }
        if (found_foldermatch) {
            if (is_imapfolderptr) *is_imapfolderptr = 1;
            return;
        }
    }
    else if (convert_foldermatch(clause, preferred_folders, 0)) {
        if (is_imapfolderptr) *is_imapfolderptr = 1;
    }
}

static void convert_seentrash_clause(search_expr_t *clause, int trashnum)
{
    if (clause->op != SEOP_AND) return;

    // Determine if clause excludes Trash folder from search
    int excludes_trash = 0;
    search_expr_t *c;
    for (c = clause->children; c; c = c->next) {
        search_expr_t *e = c->op == SEOP_NOT ? c->children : c;
        int is_not = c->op == SEOP_NOT;

        if (e->op != SEOP_MATCH)
            continue;

        if (!strcmp(e->attr->name, "jmap_folders")) {
            struct emailsearch_folders_value *val = e->value.v;
            if (bv_isset(&val->foldernums, trashnum)) {
                excludes_trash = !!val->is_otherthan != is_not;
                if (excludes_trash) break;
            }
        }
    }
    if (!excludes_trash) return;

    // Rewrite convflags attributes flag value
    for (c = clause->children; c; c = c->next) {
        search_expr_t *e = c->op == SEOP_NOT ? c->children : c;

        if (e->op != SEOP_MATCH)
            continue;

        if ((!strcmp(e->attr->name, "allconvflags") ||
             !strcmp(e->attr->name, "convflags")) &&
                !strcasecmp(e->value.s, "\\SeenInclTrash")) {
            free(e->value.s);
            e->value.s = xstrdup("\\Seen");
        }
    }
}

struct emailsearch {
    int want_expunged;
    int want_partids;
    int ignore_timer;
    int is_mutable;
    search_expr_t *expr_dnf;
    search_expr_t *expr_orig;
    struct sortcrit *sort;
    strarray_t perf_filters;
    int sort_savedate;
    int is_imapfolder;
    ptrarray_t attrs; // list of heap-allocated search_attr_t
    /* Internal state for UID search */
    search_query_t *query;
    struct searchargs *args;
    struct index_state *state;
    struct index_init init;
};

static void emailsearch_fini(struct emailsearch *search)
{
    if (!search) return;

    search_expr_free(search->expr_dnf);
    search_expr_free(search->expr_orig);
    freesortcrit(search->sort);
    strarray_fini(&search->perf_filters);

    search_attr_t *attr;
    while ((attr = ptrarray_pop(&search->attrs))) {
        if (attr->freeattr)
            attr->freeattr(&attr);
    }
    ptrarray_fini(&search->attrs);

    index_close(&search->state);
    search_query_free(search->query);
    freesearchargs(search->args);

    memset(search, 0, sizeof(struct emailsearch));
}


static int emailsearch_normalise(struct emailsearch *search, jmap_req_t *req)
{
    if (!search->expr_orig) return 0;

    /* Convert tree to DNF */
    search_expr_t *dnf = search_expr_duplicate(search->expr_orig);
    if (search_expr_normalise(&dnf) < 0) {
        search_expr_free(dnf);
        return IMAP_SEARCH_SLOW;
    }

    /*
     * Rewrite DNF expression tree:
     * (1) workaround \Seen flag not being counted for conversations in Trash
     * (2) optimize inMailbox queries to use IMAP folder search where applicable
     */
    search->is_imapfolder = 0;
    strarray_t preferred_folders = STRARRAY_INITIALIZER;
    if (dnf->op == SEOP_OR) {
        search_expr_t *c;
        for (c = dnf->children; c; c = c->next) {
            convert_seentrash_clause(c, req->cstate->trashfolder);
            convert_folderclause(c, &preferred_folders, &search->is_imapfolder);
        }
    }
    else {
        convert_seentrash_clause(dnf, req->cstate->trashfolder);
        convert_folderclause(dnf, &preferred_folders, &search->is_imapfolder);
    }
    strarray_fini(&preferred_folders);

    search->expr_dnf = dnf;

    return 0;
}

static void _email_contactfilter_initreq(jmap_req_t *req, struct email_contactfilter *cfilter)
{
    const char *addressbookid = json_string_value(json_object_get(req->args, "addressbookId"));
    jmap_email_contactfilter_init(req->accountid, req->authstate,
            &jmap_namespace, addressbookid, cfilter);
}

static void _email_parse_filter_cb(jmap_req_t *req,
                                   struct jmap_parser *parser,
                                   json_t *filter,
                                   json_t *unsupported,
                                   void *rock,
                                   json_t **err)
{
    struct email_contactfilter *cfilter = rock;
    struct jmap_email_filter_parser_rock frock = { parser, unsupported } ;
    jmap_email_filter_parse_ctx_t parse_ctx = {
        &jmap_email_filtercondition_validate,
        &jmap_filter_parser_invalid,
        &jmap_filter_parser_push_index,
        &jmap_filter_parser_pop,
        req->using_capabilities,
        &frock
    };

    /* Parse filter */
    jmap_email_filtercondition_parse(filter, &parse_ctx);
    if (json_array_size(parser->invalid)) return;

    /* Gather contactgroups */
    int r = jmap_email_contactfilter_from_filtercondition(parser, filter, cfilter);
    if (r) {
        *err = jmap_server_error(r);
        return;
    }

    const char *field;
    json_t *arg;

    /* Validate permissions */
    json_object_foreach(filter, field, arg) {
        if (!strcmp(field, "inMailbox")) {
            if (json_is_string(arg)) {
                const mbentry_t *mbentry = jmap_mbentry_by_uniqueid(req, json_string_value(arg));
                if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_LOOKUP)) {
                    jmap_parser_invalid(parser, field);
                }
            }
        }
        else if (!strcmp(field, "inMailboxOtherThan")) {
            if (json_is_array(arg)) {
                size_t i;
                json_t *val;
                json_array_foreach(arg, i, val) {
                    const char *s = json_string_value(val);
                    int is_valid = 0;
                    if (s) {
                        const mbentry_t *mbentry = jmap_mbentry_by_uniqueid(req, s);
                        is_valid = mbentry && jmap_hasrights_mbentry(req, mbentry, JACL_LOOKUP);
                    }
                    if (!is_valid) {
                        jmap_parser_push_index(parser, field, i, s);
                        jmap_parser_invalid(parser, NULL);
                        jmap_parser_pop(parser);
                    }
                }
            }
        }
    }
}

static struct sortcrit *_email_buildsort(json_t *sort, int *sort_savedate)
{
    json_t *jcomp;
    size_t i, j = 0;
    struct sortcrit *sortcrit;

    sortcrit = xzmalloc((json_array_size(sort) + 3) * sizeof(struct sortcrit));

    json_array_foreach(sort, i, jcomp) {
        const char *prop = json_string_value(json_object_get(jcomp, "property"));

        if (json_object_get(jcomp, "isAscending") == json_false()) {
            sortcrit[j].flags |= SORT_REVERSE;
        }

        /* Note: add any new sort criteria also to is_supported_email_sort */

        if (!strcmp(prop, "receivedAt")) {
            sortcrit[j].key = SORT_ARRIVAL;
        }
        else if (!strcmp(prop, "sentAt")) {
            sortcrit[j].key = SORT_DATE;
        }
        else if (!strcmp(prop, "from")) {
            sortcrit[j].key = SORT_DISPLAYFROM;
        }
        else if (!strcmp(prop, "id")) {
            sortcrit[j].key = SORT_GUID;
        }
        else if (!strcmp(prop, "emailState")) {
            sortcrit[j].key = SORT_MODSEQ;
        }
        else if (!strcmp(prop, "size")) {
            sortcrit[j].key = SORT_SIZE;
        }
        else if (!strcmp(prop, "subject")) {
            sortcrit[j].key = SORT_SUBJECT;
        }
        else if (!strcmp(prop, "to")) {
            sortcrit[j].key = SORT_DISPLAYTO;
        }
        else if (!strcmp(prop, "hasKeyword")) {
            const char *name = json_string_value(json_object_get(jcomp, "keyword"));
            const char *flagname = jmap_keyword_to_imap(name);
            if (flagname) {
                sortcrit[j].key = SORT_HASFLAG;
                sortcrit[j].args.flag.name = xstrdup(flagname);
            }
        }
        else if (!strcmp(prop, "someInThreadHaveKeyword")) {
            const char *name = json_string_value(json_object_get(jcomp, "keyword"));
            const char *flagname = jmap_keyword_to_imap(name);
            if (flagname) {
                sortcrit[j].key = SORT_HASCONVFLAG;
                sortcrit[j].args.flag.name = xstrdup(flagname);
            }
        }
        // FM specific
        else if (!strcmp(prop, "addedDates") || !strcmp(prop, "snoozedUntil")) {
            const char *mboxid =
                json_string_value(json_object_get(jcomp, "mailboxId"));

            if (sort_savedate) *sort_savedate = 1;
            sortcrit[j].key = (*prop == 's') ? SORT_SNOOZEDUNTIL : SORT_SAVEDATE;
            sortcrit[j].args.mailbox.id = xstrdupnull(mboxid);
        }
        else if (!strcmp(prop, "threadSize")) {
            sortcrit[j].key = SORT_CONVSIZE;
        }
        else if (!strcmp(prop, "spamScore")) {
            sortcrit[j].key = SORT_SPAMSCORE;
        }

        j++;
    }

    sortcrit[j+0].key = SORT_ARRIVAL;
    sortcrit[j+0].flags |= SORT_REVERSE;
    sortcrit[j+1].key = SORT_GUID;
    sortcrit[j+1].flags |= SORT_REVERSE;
    sortcrit[j+2].key = SORT_SEQUENCE;
    sortcrit[j+2].flags |= SORT_REVERSE;

    return sortcrit;
}

static void _email_querychanges_added(struct jmap_querychanges *query,
                                      const char *email_id)
{
    json_t *item = json_pack("{s:s,s:i}", "id", email_id, "index", query->total-1);
    json_array_append_new(query->added, item);
}

static void _email_querychanges_destroyed(struct jmap_querychanges *query,
                                          const char *email_id)
{
    json_array_append_new(query->removed, json_string(email_id));
}

static int _jmap_checkfolder(const char *mboxname, void *rock)
{
    jmap_req_t *req = (jmap_req_t *)rock;

    // we only want to look in folders that the user is allowed to read
    if (jmap_hasrights(req, mboxname, JACL_READITEMS))
        return 1;

    return 0;
}

static void emailsearch_init(struct emailsearch *search,
                              jmap_req_t *req,
                              json_t *filter,
                              json_t *jsort,
                              hash_table *contactgroups,
                              int want_expunged,
                              int want_partids,
                              int ignore_timer,
                              json_t **err)
{
    memset(search, 0, sizeof(struct emailsearch));

    search->expr_orig = _email_buildsearchexpr(req, filter, NULL,
            contactgroups, want_expunged,
            &search->attrs, &search->perf_filters);
    if (!search->expr_orig) return;
    search_expr_detrivialise(&search->expr_orig);

    int r = emailsearch_normalise(search, req);
    if (r == IMAP_SEARCH_SLOW) {
        *err = json_pack("{s:s s:s}", "type", "unsupportedFilter",
                "description", "search too complex");
        return;
    }

    if (json_array_size(jsort)) {
        search->sort = _email_buildsort(jsort, &search->sort_savedate);
    }
    else {
        struct sortcrit *sort = search->sort;
        sort = xzmalloc(3 * sizeof(struct sortcrit));
        sort[0].key = SORT_ARRIVAL;
        sort[0].flags |= SORT_REVERSE;
        sort[1].key = SORT_GUID;
        sort[1].flags |= SORT_REVERSE;
        sort[2].key = SORT_SEQUENCE;
        sort[2].flags |= SORT_REVERSE;
        search->sort = sort;
    }

    search->is_mutable = search_is_mutable(search->sort, search->expr_dnf);
    search->want_expunged = want_expunged;
    search->want_partids = want_partids;
    search->ignore_timer = ignore_timer;
}

static int emailsearch_run_uidsearch(jmap_req_t *req, struct emailsearch *search)
{
    int r = 0;

    /* Build search args */
    search->args = new_searchargs(NULL/*tag*/, GETSEARCH_CHARSET_FIRST,
            &jmap_namespace, req->accountid, req->authstate, 0);
    search->args->root = search_expr_duplicate(search->expr_dnf);

    /* Build index state */
    search->init.userid = req->accountid;
    search->init.authstate = req->authstate;
    search->init.want_expunged = search->want_expunged;
    search->init.examine_mode = 1;

    // try to find a mailbox listed in the search expression if any
    char *mboxname = search_expr_firstmailbox(search->args->root);
    if (!mboxname) mboxname = mboxname_user_mbox(req->accountid, NULL);
    r = index_open(mboxname, &search->init, &search->state);
    if (r) {
        syslog(LOG_ERR, "jmap: %s: (%s) %s", __func__,
               mboxname, error_message(r));
        free(mboxname);
        goto done;
    }
    free(mboxname);

    /* Build query */
    search->query = search_query_new(search->state, search->args);
    search->query->sortcrit = search->sort;
    search->query->multiple = 1;
    search->query->need_ids = 1;
    search->query->verbose = 0;
    search->query->want_expunged = search->want_expunged;
    search->query->ignore_timer = search->ignore_timer;
    search->query->checkfolder = _jmap_checkfolder;
    search->query->checkfolderrock = req;
    search->query->attachments_in_any = search->want_partids;
    search->query->want_partids = search->want_partids;
    r = search_query_run(search->query);
    if (r) {
        syslog(LOG_ERR, "jmap: %s: %s", __func__, error_message(r));
        return r;
    }

done:
    return r;
}

static int _email_parse_comparator(jmap_req_t *req,
                                   struct jmap_comparator *comp,
                                   void *rock __attribute__((unused)),
                                   json_t **err __attribute__((unused)))
{
    /* Reject any collation */
    if (comp->collation) {
        return 0;
    }

    /* Search in list of supported sortFields */
    struct email_sortfield *sp = email_sortfields;
    for (sp = email_sortfields; sp->name; sp++) {
        if (!strcmp(sp->name, comp->property)) {
            return !sp->capability || jmap_is_using(req, sp->capability);
        }
    }

    return 0;
}

struct emailquery_match {
    struct message_guid guid;
    conversation_id_t cid;
    smallarrayu64_t partnums;
};


#define JMAP_EMAILQUERY_RESULT_INITIALIZER { 0 }

struct emailquery {
    // query fields
    struct jmap_query super;
    int collapse_threads;
    int want_partids;
    int disable_guidsearch;
    int findallinthread;
    // response fields
    json_t *partids;
    json_t *thread_emailids;
};

struct emailquery_cache;
struct emailquery_result {
    int is_mutable;
    int is_guidsearch;
    int is_imapfoldersearch;
    size_t total_ceiling;

    void(*ensure)(struct emailquery *q, struct emailquery_cache *qc, size_t n);
    const char *(*partid)(uint64_t partnum, void *rock);
    void(*free)(void *rock);
    void *rock;
};

struct emailquery_cache {
    struct emailquery_result qr;
    struct emailquery_match *uncollapsed_matches;
    size_t uncollapsed_len;
    struct emailquery_match *collapsed_matches;
    size_t collapsed_len;
    struct hashset *seen_threads;
    size_t *nextinthread;
    hashu64_table firstinthread;
    int have_total;
    char *fingerprint;
    time_t last_accessed;
};

static void jmap_emailquery_init(struct emailquery *q)
{
    memset(q, 0, sizeof(struct emailquery));
    q->partids = json_object();
}

static void jmap_emailquery_fini(struct emailquery *q)
{
    jmap_query_fini(&q->super);
    q->collapse_threads = 0;
    q->want_partids = 0;
    json_decref(q->partids);
    json_decref(q->thread_emailids);
}

static char *_email_make_querystate(modseq_t modseq, uint32_t uid,
                                    modseq_t addrbook_modseq)
{
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT ":%u", modseq, uid);
    if (addrbook_modseq) {
        buf_printf(&buf, ",addrbook:" MODSEQ_FMT, addrbook_modseq);
    }
    return buf_release(&buf);
}

static int _email_read_querystate(const char *s, modseq_t *modseq, uint32_t *uid,
                                  modseq_t *addrbook_modseq)
{
    char sentinel = 0;

    /* Parse mailbox modseq and uid */
    int n = sscanf(s, MODSEQ_FMT ":%u%c", modseq, uid, &sentinel);
    if (n <= 2) return n == 2;
    else if (sentinel != ',') return 0;

    /* Parse addrbook modseq */
    s = strchr(s, ',') + 1;
    if (strncmp(s, "addrbook:", 9)) return 0;
    s += 9;
    n = sscanf(s, MODSEQ_FMT "%c", addrbook_modseq, &sentinel);
    if (n != 1) return 0;

    /* Parsed successfully */
    return 1;
}

static int emailsearch_is_mutable(struct emailsearch *search)
{
    /* can calculate changes for mutable sort, but not mutable search */
    return search->is_mutable > 1 ? 0 : 1;
}

// GUID search

struct guidsearch_match {
    char guidrep[MESSAGE_GUID_SIZE*2+1];
    uint32_t system_flags;
    uint32_t internaldate;
    conversation_id_t cid;
    bitvector_t folders; // only set if numfolders > 0
};

static void guidsearch_match_init(struct guidsearch_match *match,
                                  uint32_t numfolders)
{
    memset(match, 0, sizeof(struct guidsearch_match));
    if (numfolders) {
        bv_init(&match->folders);
        bv_setsize(&match->folders, numfolders);
    }
}

static int guidsearch_match_cmp QSORT_R_COMPAR_ARGS(const void *va,
                                                     const void *vb,
                                                     void *rock)
{
    const struct guidsearch_match *a = va;
    const struct guidsearch_match *b = vb;
    const struct sortcrit *sort = rock;

    while (sort->key != SORT_SEQUENCE) {
        int ret;
        switch (sort->key) {
            case SORT_ARRIVAL:
                ret = a->internaldate < b->internaldate ? -1 :
                      a->internaldate > b->internaldate ?  1 : 0;
                break;
            case SORT_GUID:
                ret = memcmp(a->guidrep, b->guidrep, MESSAGE_GUID_SIZE*2);
                break;
            default:
                syslog(LOG_ERR, "%s: ignoring unexpected sort %d", __func__, sort->key);
                ret = 0;
        }
        if (ret) {
            return (sort->flags & SORT_REVERSE) ? -ret : ret;
        }
        sort++;
    }

    return 0;
}

static void guidsearch_match_fini(struct guidsearch_match *match)
{
    bv_fini(&match->folders);
}

enum guidsearch_expr_op {
    GSEOP_NONE = 0,
    GSEOP_TRUE,
    GSEOP_FALSE,
    GSEOP_INMAILBOX,
    GSEOP_INMAILBOX_OTHERTHAN,
    GSEOP_FLAGS,
    GSEOP_CONVFLAGS,
    GSEOP_ALLCONVFLAGS,
    GSEOP_AND,
    GSEOP_OR,
    GSEOP_NOT
};

union guidsearch_expr_value {
    uint32_t num;
    void *v;
    struct {
        uint32_t num;
        uint8_t include_trash;
    } convflag;
};

struct guidsearch_expr {
    enum guidsearch_expr_op op;
    ptrarray_t children;
    union guidsearch_expr_value v;
};

static void guidsearch_expr_free(struct guidsearch_expr *e)
{
    if (!e) return;

    int i;
    for (i = 0; i < ptrarray_size(&e->children); i++) {
        guidsearch_expr_free(ptrarray_nth(&e->children, i));
    }
    ptrarray_fini(&e->children);

    free(e);
}

static struct guidsearch_expr *guidsearch_expr_build(struct conversations_state *cstate,
                                                     search_expr_t *parent,
                                                     search_expr_t *e,
                                                     hash_table *foldernum_by_mboxname,
                                                     int *need_folders)
{
    if (!e) return NULL;

    struct guidsearch_expr *ge = NULL;

    switch (e->op) {
        case SEOP_AND:
            {
                ge = xzmalloc(sizeof(struct guidsearch_expr));
                ge->op = GSEOP_AND;
                search_expr_t *c;
                for (c = e->children ; c; c = c->next) {
                    struct guidsearch_expr *gc =
                        guidsearch_expr_build(cstate, e, c, foldernum_by_mboxname, need_folders);
                    if (!gc || gc->op == GSEOP_TRUE) {
                        guidsearch_expr_free(gc);
                        continue;
                    }
                    else if (gc->op == GSEOP_FALSE) {
                        guidsearch_expr_free(ge);
                        return gc;
                    }
                    else {
                        ptrarray_append(&ge->children, gc);
                    }
                }
                if (ptrarray_size(&ge->children) == 1) {
                    struct guidsearch_expr *gc = ptrarray_pop(&ge->children);
                    guidsearch_expr_free(ge);
                    ge = gc;
                }
                else if (!ptrarray_size(&ge->children)) {
                    guidsearch_expr_free(ge);
                    ge = NULL;
                }
            }
            break;
        case SEOP_OR:
            {
                ge = xzmalloc(sizeof(struct guidsearch_expr));
                ge->op = GSEOP_OR;
                search_expr_t *c;
                for (c = e->children ; c; c = c->next) {
                    struct guidsearch_expr *gc =
                        guidsearch_expr_build(cstate, e, c, foldernum_by_mboxname, need_folders);
                    if (!gc || gc->op == GSEOP_FALSE) {
                        guidsearch_expr_free(gc);
                        continue;
                    }
                    else if (gc->op == GSEOP_TRUE) {
                        guidsearch_expr_free(ge);
                        return gc;
                    }
                    else {
                        ptrarray_append(&ge->children, gc);
                    }
                }
                if (ptrarray_size(&ge->children) == 1) {
                    struct guidsearch_expr *gc = ptrarray_pop(&ge->children);
                    guidsearch_expr_free(ge);
                    ge = gc;
                }
                else if (!ptrarray_size(&ge->children)) {
                    guidsearch_expr_free(ge);
                    ge = NULL;
                }
            }
            break;
        case SEOP_NOT:
            {
                ge = xzmalloc(sizeof(struct guidsearch_expr));
                ge->op = GSEOP_NOT;
                search_expr_t *c;
                for (c = e->children ; c; c = c->next) {
                    struct guidsearch_expr *gc =
                        guidsearch_expr_build(cstate, e, c, foldernum_by_mboxname, need_folders);
                    if (!gc || gc->op == GSEOP_FALSE) {
                        guidsearch_expr_free(gc);
                        continue;
                    }
                    else if (gc->op == GSEOP_TRUE) {
                        guidsearch_expr_free(ge);
                        gc->op = GSEOP_FALSE;
                        return gc;
                    }
                    else {
                        ptrarray_append(&ge->children, gc);
                    }
                }
                if (!ptrarray_size(&ge->children)) {
                    guidsearch_expr_free(ge);
                    ge = NULL;
                }
            }
            break;
        case SEOP_TRUE:
        case SEOP_FALSE:
            {
                if (parent) {
                    ge = xzmalloc(sizeof(struct guidsearch_expr));
                    ge->op = e->op == SEOP_TRUE ? GSEOP_TRUE : GSEOP_FALSE;
                }
            }
            break;
        case SEOP_MATCH:
            {
                if (e->attr == search_attr_find("folder")) {
                    // inMailbox filter, IMAP-style
                    ge = xzmalloc(sizeof(struct guidsearch_expr));
                    ge->op = GSEOP_INMAILBOX;
                    void *vv = hash_lookup(e->value.s, foldernum_by_mboxname);
                    if (vv) {
                        ge->v.num = (uint32_t)((uintptr_t)vv - 1);
                        *need_folders = 1;
                    }
                    else {
                        ge->op = GSEOP_FALSE;
                    }
                }
                else if (e->attr == &emailsearch_folders_attr) {
                    // inMailbox or inMailboxOtherThan filter, JMAP-style
                    struct emailsearch_folders_value *val = e->value.v;
                    ge = xzmalloc(sizeof(struct guidsearch_expr));
                    ge->op = val->is_otherthan ? GSEOP_INMAILBOX_OTHERTHAN : GSEOP_INMAILBOX;
                    ge->v.v = val;
                    *need_folders = 1;
                }
                else if (e->attr == search_attr_find("systemflags")) {
                    if (e->value.u & (FLAG_DRAFT|FLAG_FLAGGED|FLAG_ANSWERED)) {
                        // hasKeyword or notKeyword
                        ge = xzmalloc(sizeof(struct guidsearch_expr));
                        ge->op = GSEOP_FLAGS;
                        ge->v.num = e->value.u;
                    }
                    else {
                        // most likely guidsearch_rank_clause must be
                        // updated to reject this unsupported flag
                        syslog(LOG_ERR, "%s: ignoring unsupported flag: %0lx",
                                __func__, e->value.u);
                    }
                }
                else if (e->attr == search_attr_find("allconvflags") ||
                         e->attr == search_attr_find("convflags")) {
                    ge = xzmalloc(sizeof(struct guidsearch_expr));
                    ge->op = e->attr == search_attr_find("allconvflags") ?
                        GSEOP_ALLCONVFLAGS : GSEOP_CONVFLAGS;
                    // set num: 0 for \Seen or index in counted_flags + 1
                    if (!strcasecmp(e->value.s, "\\Seen")) {
                        ge->v.convflag.num = 0;
                    }
                    else if (!strcasecmp(e->value.s, "\\SeenInclTrash")) {
                        ge->v.convflag.num = 0;
                        ge->v.convflag.include_trash = 1;
                    }
                    else {
                        // Determine maximum number of counted flags
                        conversation_t conv = CONVERSATION_INIT;
                        size_t ncounts = sizeof(conv.counts) / sizeof(conv.counts[0]);
                        assert(ncounts < UINT32_MAX-1); // must fit ge->v.num

                        int idx = 0;
                        if (cstate->counted_flags) {
                            idx = strarray_find_case(cstate->counted_flags, e->value.s, 0);

                        }
                        if (idx >= 0 && idx + 1 <= (int) ncounts) {
                            ge->v.convflag.num = (uint32_t) idx + 1;
                        }
                        else {
                            syslog(LOG_ERR, "%s: ignoring unsupported convflag: %s",
                                    __func__, e->value.s);
                            free(ge);
                            ge = NULL;
                        }
                    }
                }
            }
            break;
        default:
            ;
    }

    return ge;
}

__attribute__((unused)) // used for debugging
static void guidsearch_expr_serialise(struct buf *buf, struct guidsearch_expr *e)
{
    if (!e) return;

    switch (e->op) {
        case GSEOP_NONE:
            buf_appendcstr(buf, "NONE");
            break;
        case GSEOP_TRUE:
            buf_appendcstr(buf, "TRUE");
            break;
        case GSEOP_FALSE:
            buf_appendcstr(buf, "FALSE");
            break;
        case GSEOP_INMAILBOX:
            buf_appendcstr(buf, "INMAILBOX");
            break;
        case GSEOP_INMAILBOX_OTHERTHAN:
            buf_appendcstr(buf, "INMAILBOX_OTHERTHAN");
            break;
        case GSEOP_FLAGS:
            buf_appendcstr(buf, "FLAGS");
            break;
        case GSEOP_CONVFLAGS:
            buf_appendcstr(buf, "CONVFLAGS");
            break;
        case GSEOP_ALLCONVFLAGS:
            buf_appendcstr(buf, "ALLCONVFLAGS");
            break;
        case GSEOP_AND:
            buf_appendcstr(buf, "AND");
            break;
        case GSEOP_OR:
            buf_appendcstr(buf, "OR");
            break;
        case GSEOP_NOT:
            buf_appendcstr(buf, "NOT");
            break;
        default:
            buf_appendcstr(buf, "XXX");
            break;
    }

    if (ptrarray_size(&e->children)) {
        buf_putc(buf, '(');
        int i;
        for (i = 0; i < ptrarray_size(&e->children); i++) {
            struct guidsearch_expr *c = ptrarray_nth(&e->children, i);
            guidsearch_expr_serialise(buf, c);
            if (i < ptrarray_size(&e->children) - 1) {
                buf_putc(buf, ' ');
            }
        }
        buf_putc(buf, ')');
    }
}

static int guidsearch_expr_eval(struct conversations_state *cstate,
                                struct guidsearch_expr *e,
                                struct guidsearch_match *match)
{
    if (!e) return 1;

    switch (e->op) {
        case GSEOP_AND:
            {
                int i;
                for (i = 0; i < ptrarray_size(&e->children); i++) {
                    if (!guidsearch_expr_eval(cstate, ptrarray_nth(&e->children, i), match)) {
                        return 0;
                    }
                }
                return 1;
            }
        case GSEOP_OR:
            {
                int i;
                for (i = 0; i < ptrarray_size(&e->children); i++) {
                    if (guidsearch_expr_eval(cstate, ptrarray_nth(&e->children, i), match)) {
                        return 1;
                    }
                }
                return 0;
            }
        case GSEOP_NOT:
            {
                int i;
                for (i = 0; i < ptrarray_size(&e->children); i++) {
                    if (guidsearch_expr_eval(cstate, ptrarray_nth(&e->children, i), match)) {
                        return 0;
                    }
                }
                return 1;
            }
        case GSEOP_TRUE:
            return 1;
        case GSEOP_FALSE:
            return 0;
        case GSEOP_INMAILBOX:
        case GSEOP_INMAILBOX_OTHERTHAN:
            {
                struct emailsearch_folders_value *val = e->v.v;
                int i;
                for (i = bv_first_set(&match->folders); i != -1;
                     i = bv_next_set(&match->folders, i+1)) {
                    int isset = bv_isset(&val->foldernums, i);
                    if ((val->is_otherthan && !isset) ||
                        (!val->is_otherthan && isset)) {
                        return 1;
                    }
                }
                return 0;
            }
        case GSEOP_FLAGS:
            return (match->system_flags & e->v.num) != 0;
        case GSEOP_CONVFLAGS:
        case GSEOP_ALLCONVFLAGS:
            {
                conversation_t conv = CONVERSATION_INIT;
                int flags = e->v.convflag.include_trash ? CONV_WITHFOLDERS : 0;
                if (conversation_load_advanced(cstate, match->cid, &conv, flags)) {
                    syslog(LOG_ERR, "%s: can't load cid %llx",
                            __func__, match->cid);
                    return 1;
                }
                int ret = 0;
                if (conv.exists) {
                    if (e->v.convflag.num == 0) {
                        uint64_t unseen = conv.unseen;
                        if (e->v.convflag.include_trash) {
                            conv_folder_t *folder;
                            for (folder = conv.folders; folder; folder = folder->next) {
                                if (folder->number == cstate->trashfolder) {
                                    unseen += folder->unseen;
                                    break;
                                }
                            }
                        }
                        ret = e->op == GSEOP_ALLCONVFLAGS ?
                            !unseen : unseen != conv.exists;
                    }
                    else {
                        ret = e->op == GSEOP_ALLCONVFLAGS ?
                            conv.counts[e->v.convflag.num-1] == conv.exists :
                            conv.counts[e->v.convflag.num-1] > 0;
                    }
                }
                conversation_fini(&conv);
                return ret;
            }
        default:
            return 1;
    }
}

static inline void guidsearch_hash_expr(const search_expr_t *e, struct buf *buf)
{
    buf_putc(buf, '(');
    char *tmp = search_expr_serialise(e);
    buf_appendcstr(buf, tmp);
    free(tmp);
    buf_putc(buf, ')');
}

static int guidsearch_rank_clause(struct conversations_state *cstate,
                                  const search_expr_t *e,
                                  struct buf *nonxapian_hash,
                                  int *use_dnf)
{
    assert(e->op != SEOP_OR);

    if (nonxapian_hash) {
        buf_reset(nonxapian_hash);
    }

    switch (e->op) {
        case SEOP_AND:
        case SEOP_NOT:
            {
                int rank = 0;
                search_expr_t *child;
                strarray_t child_hashes = STRARRAY_INITIALIZER;
                for (child = e->children ; child ; child = child->next) {
                    int childrank = guidsearch_rank_clause(cstate, child,
                            nonxapian_hash, use_dnf);
                    if (childrank == -1) {
                        return -1;
                    }
                    else {
                        rank |= childrank;
                    }
                    if (nonxapian_hash && buf_len(nonxapian_hash)) {
                        strarray_append(&child_hashes, buf_cstring(nonxapian_hash));
                        buf_reset(nonxapian_hash);
                    }
                }
                /* Create hash as list sorted list of children hashes */
                if (strarray_size(&child_hashes)) {
                    strarray_sort(&child_hashes, cmpstringp_raw);
                    buf_setcstr(nonxapian_hash, e->op == SEOP_AND ? "AND" : "NOT");
                    buf_putc(nonxapian_hash, '(');
                    int i;
                    for (i = 0; i < strarray_size(&child_hashes); i++) {
                        buf_appendcstr(nonxapian_hash, strarray_nth(&child_hashes, i));
                    }
                    buf_putc(nonxapian_hash, ')');
                }
                strarray_fini(&child_hashes);
                return rank;
            }
        case SEOP_LT:
        case SEOP_LE:
        case SEOP_GT:
        case SEOP_GE:
            // TODO support receivedAt?
            return -1;
        case SEOP_MATCH:
            // check for supported MATCH expressions
            if (e->attr == search_attr_find("folder") ||
                e->attr == &emailsearch_folders_attr) {
                /* inMailbox
                 * inMailboxOtherThan */
                if (nonxapian_hash) {
                    guidsearch_hash_expr(e, nonxapian_hash);
                }
                return 1;
            }
            else if (e->attr == search_attr_find("systemflags") &&
                    (e->value.u & (FLAG_DRAFT|FLAG_FLAGGED|FLAG_ANSWERED))) {
                /* hasKeyword
                 * notKeyword */
                if (nonxapian_hash) {
                    guidsearch_hash_expr(e, nonxapian_hash);
                }
                return 1;
            }
            else if (e->attr == search_attr_find("convflags") ||
                     e->attr == search_attr_find("allconvflags")) {
                /* allInThreadHaveKeyword
                 * someInThreadHaveKeyword
                 * noneInThreadHaveKeyword */
                if (!strcasecmp(e->value.s, "\\Seen") ||
                    !strcasecmp(e->value.s, "\\SeenInclTrash")) {

                    if (nonxapian_hash) {
                        // Seen and SeenInclTrash must have the same hash
                        char c = e->value.s[5];
                        if (c) e->value.s[5] = '\0';
                        guidsearch_hash_expr(e, nonxapian_hash);
                        if (c) e->value.s[5] = 'I';
                    }

                    if (!strcasecmp(e->value.s, "\\Seen")) {
                        // normalise rewrote Seen flag search to exclude
                        // seen counts of Trash mailbox. Need to use DNF.
                        *use_dnf = 1;
                    }
                    return 1;
                }
                else  {
                    // check if conversation flag is counted
                    if (cstate->counted_flags &&
                        strarray_find_case(cstate->counted_flags, e->value.s, 0) >= 0) {
                        if (nonxapian_hash) {
                            guidsearch_hash_expr(e, nonxapian_hash);
                        }
                        return 1;
                    }
                    else {
                        return -1;
                    }
                }
            }
            // any other MATCH is unsupported
            else return -1;
        case SEOP_TRUE:
        case SEOP_FALSE:
            return 0;
        case SEOP_FUZZYMATCH:
            return 2;
        default:
            return -1;
    }

    return -1;
}

static int guidsearch_rank_expr(struct conversations_state *cstate,
                                const search_expr_t *e,
                                int *use_dnf)
{
    if (!e) return 0;

    /*
     * Returns -1 for unsupported expressions or a bitmask of:
     *  0x0  trivial expression
     *  0x1  supported but does not require Xapian
     *  0x2  requires Xapian
     */
    if (e->op == SEOP_OR) {
        if (!e->children) return 0;
        /* A DNF clause of a guidsearch expression must contain at least one
         * Xapian criteria. It may contain non-Xapian criteria, but these
         * must be the same for all DNF clauses due to the way we post-process
         * Xapian results. We assert this by comparing the hash of non-Xapian
         * criteria across the DNF clauses. */
        struct buf hash0 = BUF_INITIALIZER, hash = BUF_INITIALIZER;
        search_expr_t *child = e->children;
        int rank = guidsearch_rank_clause(cstate, child, &hash0, use_dnf);

        if (rank == 1 || rank == -1) {
            rank = -1;
        }
        else {
            for (child = child->next ; child; child = child->next) {
                int childrank = guidsearch_rank_clause(cstate, child, &hash, use_dnf);
                if (childrank == 1 || childrank == -1 || buf_cmp(&hash0, &hash)) {
                    rank = -1;
                    break;
                }
                else rank |= childrank;
            }
        }
        buf_free(&hash0);
        buf_free(&hash);
        return rank;
    }
    return guidsearch_rank_clause(cstate, e, NULL, use_dnf);
}

static int is_guidsearch_sort(struct sortcrit *sort)
{
    if (sort) {
        for ( ; sort->key != SORT_SEQUENCE; sort++) {
            if (sort->key != SORT_GUID && sort->key != SORT_ARRIVAL)
                return 0;
        }
    }
    return 1;
}

struct guidsearch_query {
    jmap_req_t *req;
    bitvector_t readable_folders;
    uint32_t numfolders;
    int want_expunged;
    struct guidsearch_expr *matchexpr;
    struct guidsearch_match *matches;
    size_t total;
    size_t collapsed_len;
};

static int guidsearch_add_guidrec(const conv_guidrec_t *rec,
                                  struct guidsearch_match *prev,
                                  struct guidsearch_match *next,
                                  struct guidsearch_query *gsq)
{
    /* Ignore parts */ // TODO could set partIds
    if (rec->part) return 0;

    /* Filter ACL and expunged messages */
    if (!bv_isset(&gsq->readable_folders, rec->foldernum) ||
       (!gsq->want_expunged &&
        ((rec->system_flags & FLAG_DELETED) ||
         (rec->internal_flags & FLAG_INTERNAL_EXPUNGED)))) {
            return 0;
    }

    if (prev && !memcmp(rec->guidrep, prev->guidrep, MESSAGE_GUID_SIZE*2)) {
        /* Update match for same guid */
        if (gsq->numfolders) bv_set(&prev->folders, rec->foldernum);
        prev->system_flags |= rec->system_flags;
        if (rec->internaldate < prev->internaldate) {
            prev->internaldate = rec->internaldate;
        }
        return 0;
    }

    /* Initialize match for new guid */
    guidsearch_match_init(next, gsq->numfolders);
    memcpy(next->guidrep, rec->guidrep, MESSAGE_GUID_SIZE*2);
    next->guidrep[MESSAGE_GUID_SIZE*2] = '\0';
    if (gsq->numfolders) bv_set(&next->folders, rec->foldernum);
    next->system_flags = rec->system_flags;
    next->internaldate = rec->internaldate;
    next->cid = rec->cid;
    return 1;
}

static int guidsearch_run_xapian_cb(const conv_guidrec_t *rec,
                                    size_t nguids, void *rock)
{
    if (!nguids) return 0; // not a single match!

    if (rec->version < 1) {
        /* Legacy conversations.db. Guid search was just a waste of time. */
        syslog(LOG_ERR, "jmap: %s: G record for %s:%d has legacy version 0. "
                "Aborting guidsearch.", __func__, conv_guidrec_mboxname(rec), rec->uid);
        return IMAP_SEARCH_NOT_SUPPORTED;
    }

    struct guidsearch_query *gsq = rock;

    if (gsq->matches == NULL) {
        /* First time we see any match candidate */
        gsq->matches = xmalloc(nguids * sizeof(struct guidsearch_match));
    }

    struct guidsearch_match *prevmatch = gsq->total ?
        &gsq->matches[gsq->total-1] : NULL;
    struct guidsearch_match *nextmatch = gsq->matches + gsq->total;

    if (guidsearch_add_guidrec(rec, prevmatch, nextmatch, gsq)) gsq->total++;

    return 0;
}

static int guidsearch_run_xapian(jmap_req_t *req, struct emailsearch *search,
                                 struct guidsearch_query *gsq)
{
    search_builder_t *bx = NULL;
    struct mailbox *mbox = NULL;
    mbname_t *mbname = mbname_from_userid(req->accountid);

    mbname_push_boxes(mbname, config_getstring(IMAPOPT_JMAPUPLOADFOLDER));
    int r = jmap_openmbox(req, mbname_intname(mbname), &mbox, 0);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        free(mbname_pop_boxes(mbname));
        r = jmap_openmbox(req, mbname_intname(mbname), &mbox, 0);
    }
    if (r) goto done;

    bx = search_begin_search(mbox, 0);
    if (!bx) {
        syslog(LOG_ERR, "jmap: %s: can't begin search for %s",
                __func__,  mailbox_name(mbox));
        r = IMAP_INTERNAL;
        goto done;
    }

    search_build_query(bx, search->expr_orig);
    r = bx->run_guidsearch(bx, guidsearch_run_xapian_cb, gsq);
    bv_fini(&gsq->readable_folders);
    if (r && r != IMAP_OK_COMPLETED) goto done;
    r = 0;
    gsq->collapsed_len = gsq->total;

    if (!gsq->total) goto done;

    /* Evaluate non-Xapian expressions */
    size_t i, j;
    for (i = 0, j = 0; i < gsq->total; i++) {
        struct guidsearch_match *match = gsq->matches + i;
        if (guidsearch_expr_eval(req->cstate, gsq->matchexpr, match)) {
            if (i != j) {
                // shallow-move match to its new slot
                gsq->matches[j] = *match;
                memset(match, 0, sizeof(struct guidsearch_match));
            }
            j++;
        }
        else {
            guidsearch_match_fini(match);
        }
    }
    gsq->total = gsq->collapsed_len = j;

done:
    if (bx) search_end_search(bx);
    jmap_closembox(req, &mbox);
    mbname_free(&mbname);
    return r;
}

static int guidsearch_run(jmap_req_t *req, struct emailsearch *search,
                          struct guidsearch_query *gsq)
{
    int use_dnf = 0;
    int exprrank = guidsearch_rank_expr(req->cstate, search->expr_dnf, &use_dnf);
    if (exprrank < 2 || !is_guidsearch_sort(search->sort)) {
        return IMAP_SEARCH_NOT_SUPPORTED;
    }

    search_expr_t *expr = use_dnf ? search->expr_dnf : search->expr_orig;

    /* Determine readable folders for userid */
    uint32_t numfolders = conversations_num_folders(req->cstate);
    bv_setsize(&gsq->readable_folders, numfolders);
    if (strcmp(req->userid, req->accountid)) {
        // filter all folders that can't be read by userid
        uint32_t num;
        for (num = 0; num < numfolders; num++) {
            const char *mboxname = conversations_folder_mboxname(req->cstate, num);
            if (!mboxname) continue;
            if (jmap_hasrights(req, mboxname, ACL_READ|ACL_LOOKUP)) {
                bv_set(&gsq->readable_folders, num);
            }
        }
    }
    else {
        // all user-owned mailboxes are readable
        bv_setall(&gsq->readable_folders);
    }

    // filter all folders that aren't regular mailboxes
    uint32_t num;
    for (num = 0; num < numfolders; num++) {
        const char *mboxname = conversations_folder_mboxname(req->cstate, num);
        mbentry_t *mbentry = NULL;
        if (!mboxname || mboxname_isnondeliverymailbox(mboxname, 0) ||
            mboxlist_lookup_allow_all(mboxname, &mbentry, NULL) ||
            mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL) {
            bv_clear(&gsq->readable_folders, num);
        }
        mboxlist_entry_free(&mbentry);
    }

    /* Prepare filter for post-processing */
    if (exprrank & 0x1) {
        hash_table foldernum_by_mboxname = HASH_TABLE_INITIALIZER;
        construct_hash_table(&foldernum_by_mboxname, numfolders+2, 0);
        uint32_t num;
        for (num = 0; num < numfolders; num++) {
            const char *mboxname = conversations_folder_mboxname(req->cstate, num);
            if (!mboxname) continue;
            hash_insert(mboxname, (void*)((uintptr_t)num+1), &foldernum_by_mboxname);
        }

        int need_folders = 0;
        gsq->matchexpr = guidsearch_expr_build(req->cstate, NULL, expr,
                                               &foldernum_by_mboxname,
                                               &need_folders);
        gsq->numfolders = need_folders ? numfolders : 0;
        free_hash_table(&foldernum_by_mboxname, NULL);
    }

    /* Run query */
    return guidsearch_run_xapian(req, search, gsq);
}

static void guidsearch_sort(jmap_req_t *req __attribute__((unused)),
                            struct sortcrit *sort,
                            struct guidsearch_query *gsq)
{
    if (!gsq->total) return;

    cyr_qsort_r(gsq->matches, gsq->total, sizeof(struct guidsearch_match),
                guidsearch_match_cmp, sort);
}

struct emailquery_guidsearch_result_rock {
    struct guidsearch_match *gsqmatches;
    size_t gsqtotal;
    size_t pos;
};

static void emailquery_guidsearch_result_ensure(struct emailquery *q, struct emailquery_cache *qc, size_t n)
{
    struct emailquery_guidsearch_result_rock *rrock = qc->qr.rock;

    size_t *want = q->collapse_threads ? &qc->collapsed_len : &qc->uncollapsed_len;
    while (rrock->pos < rrock->gsqtotal) {
        // do we have enough already?
        if (*want >= n) return;

        struct guidsearch_match *gsqmatch = &rrock->gsqmatches[rrock->pos++];
        struct emailquery_match *match = &qc->uncollapsed_matches[qc->uncollapsed_len++];
        message_guid_decode(&match->guid, gsqmatch->guidrep);
        match->cid = gsqmatch->cid;
        smallarrayu64_init(&match->partnums);
        if (q->collapse_threads && hashset_add(qc->seen_threads, &match->cid))
            qc->collapsed_matches[qc->collapsed_len++] = *match;
    }
    qc->have_total = 1;
}

static void emailquery_guidsearch_result_free(void *rock)
{
    struct emailquery_guidsearch_result_rock *rrock = rock;
    if (rrock->gsqmatches) {
        size_t i;
        for (i = 0; i < rrock->gsqtotal; i++) {
            guidsearch_match_fini(&rrock->gsqmatches[i]);
        }
        free(rrock->gsqmatches);
    }
    free(rrock);
}

static int emailquery_guidsearch(jmap_req_t *req,
                                 struct emailquery *q,
                                 struct emailsearch *search,
                                 struct emailquery_result *qr,
                                 json_t **err __attribute__((unused)))
{
    struct guidsearch_query gsq = {
        req,
        BV_INITIALIZER,
        0,
        search->want_expunged,
        NULL,
        0,
        0,
        0
    };

    int r = guidsearch_run(req, search, &gsq);
    if (r) return r;

    guidsearch_sort(req, search->sort, &gsq);

    struct emailquery_guidsearch_result_rock *rrock =
        xzmalloc(sizeof(struct emailquery_guidsearch_result_rock));

    rrock->gsqmatches = gsq.matches;
    gsq.matches = NULL; // rrock steals matches
    rrock->gsqtotal = gsq.total;

    qr->rock = rrock;
    qr->total_ceiling = gsq.total;
    qr->ensure = emailquery_guidsearch_result_ensure;
    qr->free = emailquery_guidsearch_result_free;
    qr->partid = NULL;

    if (q->want_partids) {
        xsyslog(LOG_ERR, "guidsearch does not support partid search", NULL);
    }

    guidsearch_expr_free(gsq.matchexpr);

    return 0;
}

struct emailquery_uidsearch_result_rock {
    search_query_t *query;
    struct hashset *savedates;
    struct hashset *seen_emails;
    size_t pos;

    int want_partids;
    hashu64_table partid_bynum;
    hash_table partnum_byid;
    uint64_t partnum_seq;
};

static void emailquery_uidsearch_result_ensure(struct emailquery *q, struct emailquery_cache *qc, size_t n)
{
    struct emailquery_uidsearch_result_rock *rrock = qc->qr.rock;
    ptrarray_t *msgdata = &rrock->query->merged_msgdata;

    size_t *want = q->collapse_threads ? &qc->collapsed_len : &qc->uncollapsed_len;
    while (rrock->pos < (size_t)msgdata->count) {
        // do we have enough already?
        if (*want >= n) return;

        MsgData *md = ptrarray_nth(msgdata, rrock->pos++);

        /* Skip expunged or hidden messages */
        if (md->system_flags & FLAG_DELETED ||
            md->internal_flags & FLAG_INTERNAL_EXPUNGED)
            continue;

        /* Is there another copy of this message with a targeted savedate? */
        if (!md->savedate &&
            rrock->savedates &&
            hashset_exists(rrock->savedates, &md->guid.value))
            continue;

        /* Have we seen this message already? */
        if (!hashset_add(rrock->seen_emails, &md->guid.value))
            continue;

        /* Add message to result */
        struct emailquery_match *match = &qc->uncollapsed_matches[qc->uncollapsed_len++];
        match->guid = md->guid;
        match->cid = md->cid;
        smallarrayu64_init(&match->partnums);

        /* Set partIds */
        if (rrock->want_partids && md->folder && md->folder->partnums.count) {
            /* Find partnums for this uid using binary search */
            ssize_t l = 0, r = md->folder->partnums.count - 1;
            struct search_folder_partnum *pnums = md->folder->partnums.data;
            while (l <= r) {
                ssize_t m = l + (r - l) / 2;
                if (pnums[m].uid == md->uid) {
                    /* Found it. Now add all partnums for this uid. */
                    ssize_t p;
                    for (p = m; p >= 0 && pnums[p].uid == md->uid; --p) {
                        smallarrayu64_append(&match->partnums, pnums[p].partnum);
                    }
                    for (p = m + 1; p < md->folder->partnums.count &&
                            pnums[p].uid == md->uid; ++p) {
                        smallarrayu64_append(&match->partnums, pnums[p].partnum);
                    }
                    break;
                }
                else if (pnums[m].uid < md->uid) {
                    l = m + 1;
                }
                else {
                    r = m - 1;
                }
            }
        }

        // calculate the collapsed version too
        if (q->collapse_threads && hashset_add(qc->seen_threads, &match->cid))
            qc->collapsed_matches[qc->collapsed_len++] = *match;
    }

    qc->have_total = 1;
}

static const char *emailquery_uidsearch_result_partid(uint64_t partnum, void *rock)
{
    struct emailquery_uidsearch_result_rock *rrock = rock;
    return hashu64_lookup(partnum, &rrock->query->partid_by_num);
}

static void emailquery_uidsearch_result_free(void *rock)
{
    if (!rock) return;

    struct emailquery_uidsearch_result_rock *rrock = rock;

    if (rrock->query)
        search_query_free(rrock->query);
    if (rrock->savedates)
        hashset_free(&rrock->savedates);
    if (rrock->seen_emails)
        hashset_free(&rrock->seen_emails);
    if (rrock->partid_bynum.size)
        free_hashu64_table(&rrock->partid_bynum, free);
    if (rrock->partnum_byid.size)
        free_hash_table(&rrock->partnum_byid, NULL);

    free(rrock);
}

static int emailquery_uidsearch(jmap_req_t *req,
                                struct emailquery *q,
                                struct emailsearch *search,
                                struct emailquery_result *qr,
                                json_t **err)
{
    int r = 0;

    /* Run search */
    r = emailsearch_run_uidsearch(req, search);
    if (r) {
        switch (r) {
            case IMAP_SEARCH_NOT_SUPPORTED:
                *err = json_pack("{s:s}", "type", "unsupportedFilter");
                break;
            case IMAP_SEARCH_SLOW:
                *err = json_pack("{s:s s:s}", "type", "unsupportedFilter",
                        "description", "search too slow");
                break;
            default:
                *err = jmap_server_error(r);
        }
        return r;
    }
    if (!search->query->merged_msgdata.count) return 0;

    struct emailquery_uidsearch_result_rock *rrock =
        xzmalloc(sizeof(struct emailquery_uidsearch_result_rock));

    rrock->seen_emails = hashset_new(MESSAGE_GUID_SIZE);
    if (q->want_partids) {
        construct_hashu64_table(&rrock->partid_bynum, 1024, 0);
        construct_hash_table(&rrock->partnum_byid, 1024, 0);
        rrock->want_partids = 1;
    }

    // move query data from search to rrock
    rrock->query = search->query;
    search->query = NULL;

    ptrarray_t *msgdata = &rrock->query->merged_msgdata;

    if (search->sort_savedate) {
        /* Build hashset of messages with savedates */
        rrock->savedates = hashset_new(MESSAGE_GUID_SIZE);

        int j;
        for (j = 0; j < msgdata->count; j++) {
            MsgData *md = ptrarray_nth(msgdata, j);

            /* Skip expunged or hidden messages */
            if (md->system_flags & FLAG_DELETED ||
                md->internal_flags & FLAG_INTERNAL_EXPUNGED)
                continue;

            if (md->savedate) hashset_add(rrock->savedates, &md->guid.value);
        }
    }

    qr->rock = rrock;
    qr->total_ceiling = msgdata->count;
    qr->ensure = emailquery_uidsearch_result_ensure;
    qr->partid = emailquery_uidsearch_result_partid;
    qr->free = emailquery_uidsearch_result_free;

    return r;
}

static int emailquery_search(jmap_req_t *req,
                             struct emailquery *q,
                             struct emailquery_result *qr,
                             hash_table *contactgroups,
                             json_t **errp)
{
    int r = 0;

    struct emailsearch search;
    emailsearch_init(&search, req, q->super.filter, q->super.sort,
            contactgroups, 0, q->want_partids, 0, errp);
    if (*errp) goto done;

    /* set search cost info */
    if (jmap_is_using(req, JMAP_PERFORMANCE_EXTENSION)) {
        int i;
        json_t *jfilters = json_array();
        for (i = 0; i < strarray_size(&search.perf_filters); i++) {
            const char *cost = strarray_nth(&search.perf_filters, i);
            json_array_append_new(jfilters, json_string(cost));
        }
        json_object_set_new(req->perf_details, "filters", jfilters);
    }

    /* Try to fetch matching guids directly from Xapian */
    int is_guidsearch = 0;
    if (!q->disable_guidsearch && !q->want_partids) {
        r = emailquery_guidsearch(req, q, &search, qr, errp);
        if (r == IMAP_SEARCH_NOT_SUPPORTED) {
            /* Fallback to UID search */
            r = 0;
        }
        else if (r) goto done;
        else is_guidsearch = 1;
    }
    if (!is_guidsearch) {
        r = emailquery_uidsearch(req, q, &search, qr, errp);
    }
    if (r) goto done;

    qr->is_mutable = emailsearch_is_mutable(&search);
    qr->is_imapfoldersearch = search.is_imapfolder;
    qr->is_guidsearch = is_guidsearch;

done:
    emailsearch_fini(&search);
    return r;
}

static void emailquery_cache_reset(struct emailquery_cache *qc)
{
    size_t i;
    for (i = 0; i < qc->uncollapsed_len; i++) {
        smallarrayu64_fini(&qc->uncollapsed_matches[i].partnums);
    }
    free(qc->uncollapsed_matches);
    free(qc->collapsed_matches); // members are shallow copy of uncollapsed
    free(qc->fingerprint);
    if (qc->seen_threads) hashset_free(&qc->seen_threads);
    if (qc->qr.free) {
        qc->qr.free(qc->qr.rock);
    }
    free(qc->nextinthread);
    if (qc->firstinthread.size) {
        free_hashu64_table(&qc->firstinthread, NULL);
    }
    memset(qc, 0, sizeof(struct emailquery_cache));
}

static void emailquery_cache_ensure(struct emailquery *q,
                                    struct emailquery_cache *qc,
                                    size_t n)
{
    if (qc->have_total) return; // all done

    if (!qc->uncollapsed_matches) {
        /* First preload. Allocate buffers all at once. */
        qc->uncollapsed_matches =
            xmalloc(sizeof(struct emailquery_match) * qc->qr.total_ceiling);
        qc->uncollapsed_len = 0;
    }
    if (q->collapse_threads) {
        if (!qc->collapsed_matches) {
            qc->collapsed_matches =
                xmalloc(sizeof(struct emailquery_match) * qc->qr.total_ceiling);
            qc->collapsed_len = 0;
        }
        if (!qc->seen_threads)
            qc->seen_threads = hashset_new(sizeof(conversation_id_t));
    }

    // fill the caches
    qc->qr.ensure(q, qc, n);

    /* Postprocess total matches */
    if (qc->have_total && qc->uncollapsed_len) {

        /* Realloc buffers to exact size */
        if (qc->qr.total_ceiling > qc->uncollapsed_len) {
            qc->uncollapsed_matches = realloc(qc->uncollapsed_matches,
                    sizeof(struct emailquery_match) * qc->uncollapsed_len);
            qc->collapsed_matches = realloc(qc->collapsed_matches,
                    sizeof(struct emailquery_match) * qc->collapsed_len);
        }

        if (q->findallinthread) {
            /* For each match, store the position of the next match
             * in the same conversation. Keep an index of the first
             * match for each conversation id. */
            qc->nextinthread = xmalloc(sizeof(size_t) * qc->uncollapsed_len);
            construct_hashu64_table(&qc->firstinthread, (qc->uncollapsed_len/2)+1, 0);
            size_t i = qc->uncollapsed_len - 1;
            do {
                conversation_id_t cid = qc->uncollapsed_matches[i].cid;
                size_t j = (size_t) hashu64_lookup(cid, &qc->firstinthread);
                qc->nextinthread[i] = j ? j : qc->uncollapsed_len;
                hashu64_insert(cid, (void*) i, &qc->firstinthread);
            } while (i-- > 0);
        }
    }
}

static void emailquery_cache_slice(struct emailquery *q,
                                   struct emailquery_cache *qc,
                                   size_t *posp, size_t *np,
                                   json_t **errp)
{
    if (!qc->have_total) {
        /* conditions for doing a partial load:
         * 1) we don't need the total
         * 2) we don't need to find an anchor
         * 3) the offset is from the start, not from the end
         * 4) we have a limit, so we're not fetching everything
         * 5) we don't need all in thread
         * if all these conditions are met, then we can fill just to the
         * end of the requested window */
        if (!q->super.calculate_total && !q->super.anchor &&
            q->super.position >= 0 && q->super.limit && !q->findallinthread) {
            size_t have_len = q->collapse_threads ?
                              qc->collapsed_len :
                              qc->uncollapsed_len;
            size_t need = q->super.position + q->super.limit;
            // is the window already within the loaded section?
            if (have_len < need) {
                // fill just to the end of the window
                emailquery_cache_ensure(q, qc, need);
            }
        }
        else {
            // load everything into cache
            emailquery_cache_ensure(q, qc, SIZE_MAX);
        }
    }

    struct emailquery_match *matches;
    size_t pos, n = 0;
    size_t total;
    if (q->collapse_threads) {
        matches = qc->collapsed_matches;
        total = qc->collapsed_len;
    }
    else {
        matches = qc->uncollapsed_matches;
        total = qc->uncollapsed_len;
    }
    if (q->super.anchor) {
        pos = 0;
    }
    else if (q->super.position < 0) {
        size_t delta = (size_t) -q->super.position;
        pos = delta < total ? total - delta : 0;
    }
    else if ((size_t)q->super.position < total) {
        pos = q->super.position;
    } else {
        pos = total;
    }
    if (q->super.anchor) {
        int found_anchor = 0;
        size_t i;
        for (i = pos; i < total; i++) {
            if (q->super.have_limit && n == q->super.limit) {
                break;
            }
            struct emailquery_match *match = matches + i;
            char emailid[JMAP_EMAILID_SIZE];
            jmap_set_emailid(&match->guid, emailid);
            if (!strcmp(emailid, q->super.anchor)) {
                /* Found anchor */
                found_anchor = 1;
                if (q->super.anchor_offset < 0) {
                    /* Extend lower end of slice */
                    size_t delta = -q->super.anchor_offset;
                    pos = delta < i ? i - delta : 0;
                }
                else if (q->super.anchor_offset > 0) {
                    /* Skip to anchor offset */
                    i += q->super.anchor_offset - 1;
                    pos = i + 1;
                }
                else {
                    /* Add anchor */
                    pos = i;
                }
                break;
            }
        }
        if (!found_anchor) {
            *errp = json_pack("{s:s}", "type", "anchorNotFound");
            return;
        }
    }
    n = total - pos;
    if (q->super.have_limit && q->super.limit < n) {
        n = q->super.limit;
    }

    *posp = pos;
    *np = n;
}

static void emailquery_buildresult(struct emailquery *q,
                                   struct emailquery_cache *qc,
                                   json_t **errp)
{
    if (!qc->qr.total_ceiling) {
        if (q->findallinthread) {
            q->thread_emailids = json_object();
        }
        if (q->want_partids) {
            q->partids = json_null();
        }
        return;
    }

    /* Slice matches to query window [pos,pos+n) */
    size_t pos = 0, n = 0;
    emailquery_cache_slice(q, qc, &pos, &n, errp);
    if (errp && *errp) return;

    /* Convert result to JSON */
    struct emailquery_match *matches;
    size_t len;
    if (q->collapse_threads) {
        matches = qc->collapsed_matches;
        len = qc->collapsed_len;
    }
    else {
        matches = qc->uncollapsed_matches;
        len = qc->uncollapsed_len;
    }
    if (q->findallinthread) {
        q->thread_emailids = json_object();
    }

    size_t top = pos + n;
    size_t i;
    for (i = pos; i < top; i++) {
        struct emailquery_match *match = &matches[i];
        /* Set email id */
        char emailid[JMAP_EMAILID_SIZE];
        jmap_set_emailid(&match->guid, emailid);
        json_array_append_new(q->super.ids, json_string(emailid));
        /* Set email-part ids */
        if (q->want_partids && qc->qr.partid) {
            json_t *jpartids = json_array();
            size_t j;
            for (j = 0; j < smallarrayu64_size(&match->partnums); j++) {
                uint64_t partnum = smallarrayu64_nth(&match->partnums, j);
                const char *partid = qc->qr.partid(partnum, qc->qr.rock);
                if (partid) {
                    json_array_append_new(jpartids, json_string(partid));
                }
            }
            if (!json_array_size(jpartids)) {
                json_decref(jpartids);
                jpartids = json_null();
            }
            json_object_set_new(q->partids, emailid, jpartids);
        }
        /* Set thread id by email id */
        if (q->findallinthread) {
            char threadid[JMAP_THREADID_SIZE];
            jmap_set_threadid(match->cid, threadid);
            if (!json_object_get(q->thread_emailids, threadid)) {
                /* First time we see this thread in the result */
                json_t *emailids = json_array();
                size_t tpos = (size_t) hashu64_lookup(match->cid, &qc->firstinthread);
                do {
                    char emailid[JMAP_EMAILID_SIZE];
                    jmap_set_emailid(&qc->uncollapsed_matches[tpos].guid, emailid);
                    json_array_append_new(emailids, json_string(emailid));
                    tpos = qc->nextinthread[tpos];
                } while (tpos < qc->uncollapsed_len);
                json_object_set_new(q->thread_emailids, threadid, emailids);
            }
        }
    }

    q->super.result_position = pos;
    if (q->super.calculate_total)
        assert(qc->have_total);

    if (qc->have_total) {
        q->super.total = len;
    }
    else {
        q->super.have_total = 0;
    }
}

static void emailquery_fingerprint(struct buf *fingerprint,
                                   const char *accountid,
                                   const char *userid,
                                   const char *querystate,
                                   struct emailquery *q)

{
    buf_reset(fingerprint);

    buf_putc(fingerprint, '<');
    buf_appendcstr(fingerprint, userid);
    buf_putc(fingerprint, '>');

    buf_putc(fingerprint, '<');
    buf_appendcstr(fingerprint, accountid);
    buf_putc(fingerprint, '>');

    buf_putc(fingerprint, '<');
    buf_appendcstr(fingerprint, querystate);
    buf_putc(fingerprint, '>');

    if (JNOTNULL(q->super.filter)) {
        buf_putc(fingerprint, '<');
        char *s = json_dumps(q->super.filter, JSON_COMPACT|JSON_SORT_KEYS);
        buf_appendcstr(fingerprint, s);
        free(s);
        buf_putc(fingerprint, '>');
    }

    if (JNOTNULL(q->super.sort)) {
        buf_putc(fingerprint, '<');
        char *s = json_dumps(q->super.sort, JSON_COMPACT|JSON_SORT_KEYS);
        buf_appendcstr(fingerprint, s);
        free(s);
        buf_putc(fingerprint, '>');
    }
    if (q->super.sort_savedate) {
        buf_putc(fingerprint, '<');
        buf_appendcstr(fingerprint, "sort_savedate");
        buf_putc(fingerprint, '>');
    }

    if (q->want_partids) {
        buf_putc(fingerprint, '<');
        buf_appendcstr(fingerprint, "want_partids");
        buf_putc(fingerprint, '>');
    }

    if (q->disable_guidsearch) {
        buf_putc(fingerprint, '<');
        buf_appendcstr(fingerprint, "disable_guidsearch");
        buf_putc(fingerprint, '>');
    }
}

static struct emailquery_cache emailquery_cache = { 0 };

static void emailquery_handler(enum jmap_handler_event event, jmap_req_t *req,
                               void *rock __attribute__((unused)))
{
    if (event == JMAP_HANDLE_BEFORE_METHOD) {
        if (strcmpsafe(req->method, "Email/query")) {
            /* Evict cached query result if it is over maximum age */
            int evict_before = time(NULL) - emailquery_cache_max_age;
            if (emailquery_cache.last_accessed &&
                    emailquery_cache.last_accessed < evict_before) {
                emailquery_cache_reset(&emailquery_cache);
            }
        }
    }
    else if (event & (JMAP_HANDLE_CLOSE_CONN|JMAP_HANDLE_SHUTDOWN)) {
        emailquery_cache_reset(&emailquery_cache);
    }
}

static json_t *emailquery_run(jmap_req_t *req, struct emailquery *q,
                              hash_table *contactgroups,
                              json_t **errp)
{
    json_t *res = NULL;
    int r = 0;

    modseq_t modseq = jmap_highestmodseq(req, MBTYPE_EMAIL);
    modseq_t addrbook_modseq = contactgroups->size ?
        jmap_highestmodseq(req, MBTYPE_ADDRESSBOOK) : 0;
    char *querystate = _email_make_querystate(modseq, 0, addrbook_modseq);

    struct buf fingerprint = BUF_INITIALIZER;
    emailquery_fingerprint(&fingerprint, req->userid, req->accountid, querystate, q);

    /* Try to reuse cached query result */
    int is_cached;
    if (strcmpsafe(emailquery_cache.fingerprint, buf_cstring(&fingerprint))) {
        /* Build new result */
        emailquery_cache_reset(&emailquery_cache);
        is_cached = 0;
        r = emailquery_search(req, q, &emailquery_cache.qr, contactgroups, errp);
        if (r || *errp) goto done;
        emailquery_cache.fingerprint = buf_release(&fingerprint);
        emailquery_cache.last_accessed = time(NULL);
    }
    else {
        /* set search cost info */
        if (jmap_is_using(req, JMAP_PERFORMANCE_EXTENSION)) {
            json_object_set_new(req->perf_details, "filters",
                        json_pack("[s]", "querycache"));
        }
        emailquery_cache.last_accessed = time(NULL);
        is_cached = 1;
    }

    /* Build response */
    emailquery_buildresult(q, &emailquery_cache, errp);
    if (*errp) goto done;
    q->super.can_calculate_changes = emailquery_cache.qr.is_mutable;
    q->super.query_state = xstrdupnull(querystate);

    if (jmap_is_using(req, JMAP_PERFORMANCE_EXTENSION)) {
        json_object_set_new(req->perf_details, "isImapFolderSearch",
                json_boolean(emailquery_cache.qr.is_imapfoldersearch));
        json_object_set_new(req->perf_details, "isCached", json_boolean(is_cached));
        json_object_set_new(req->perf_details, "isGuidSearch",
                json_boolean(emailquery_cache.qr.is_guidsearch));
    }
    res = jmap_query_reply(&q->super);
    if (jmap_is_using(req, JMAP_MAIL_EXTENSION)) {
        if (q->want_partids) {
            json_object_set(res, "partIds",
                    json_object_size(q->partids) ?  q->partids : json_null());
        }
    }
    if (q->thread_emailids) {
        json_object_set(res, "threadIdToEmailIds", q->thread_emailids);
    }
    json_object_set(res, "collapseThreads", json_boolean(q->collapse_threads));

    if (jmap_is_using(req, JMAP_DEBUG_EXTENSION)) {
        /* List language stats */
        const struct search_engine *engine = search_engine();
        if (engine->langstats) {
            size_t nolang = 0;
            ptrarray_t lstats = PTRARRAY_INITIALIZER;
            int r = engine->langstats(req->accountid, &lstats, &nolang);
            if (!r) {
                json_t *jstats = json_object();
                struct search_langstat *lstat;
                while ((lstat = ptrarray_pop(&lstats))) {
                    json_object_set_new(jstats, lstat->iso_lang,
                            json_integer(lstat->count));
                    free(lstat->iso_lang);
                    free(lstat);
                }
                json_object_set_new(res, "languageStats",
                        json_pack("{s:o s:I}", "iso", jstats, "unknown", nolang));
            }
            ptrarray_fini(&lstats);
        }
    }

done:
    if (!emailquery_cache_max_age) {
        emailquery_cache_reset(&emailquery_cache);
    }
    if (r && *errp == NULL) {
        if (r == IMAP_SEARCH_SLOW) {
            *errp = json_pack("{s:s s:s}", "type", "unsupportedFilter",
                    "description", "search too slow");
        }
        else *errp = jmap_server_error(r);
    }
    buf_free(&fingerprint);
    free(querystate);
    return res;
}

static int emailquery_args_parse(jmap_req_t *req,
                                 struct jmap_parser *parser __attribute__((unused)),
                                 const char *key,
                                 json_t *arg,
                                 void *rock)
{
    struct emailquery *query = rock;
    int r = 1;

    if (!strcmp(key, "collapseThreads") && json_is_boolean(arg)) {
        query->collapse_threads = json_boolean_value(arg);
    }
    else if (!strcmp(key, "addressbookId") && json_is_string(arg) &&
             jmap_is_using(req, JMAP_MAIL_EXTENSION)) {

        /* Lookup addrbook */
        char *addrbookname = carddav_mboxname(req->accountid, json_string_value(arg));
        mbentry_t *mbentry = NULL;
        int is_valid = 0;
        if (!mboxlist_lookup(addrbookname, &mbentry, NULL)) {
            is_valid = jmap_hasrights_mbentry(req, mbentry, JACL_LOOKUP) &&
                mbtype_isa(mbentry->mbtype) == MBTYPE_ADDRESSBOOK;
        }
        mboxlist_entry_free(&mbentry);
        free(addrbookname);
        return is_valid;
    }
    else if (!strcmp(key, "findMatchingParts") && json_is_boolean(arg) &&
            jmap_is_using(req, JMAP_MAIL_EXTENSION)) {
        query->want_partids = json_boolean_value(arg);
    }
    else if (!strcmp(key, "disableGuidSearch") && json_is_boolean(arg) &&
            jmap_is_using(req, JMAP_PERFORMANCE_EXTENSION)) {
        query->disable_guidsearch = json_boolean_value(arg);
    }
    else if (!strcmp(key, "findAllInThread") && json_is_boolean(arg) &&
            jmap_is_using(req, JMAP_MAIL_EXTENSION)) {
        query->findallinthread = json_boolean_value(arg);
    }
    else r = 0;

    return r;
}

static int jmap_email_query(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct emailquery query;
    struct email_contactfilter contactfilter;
    int r = 0;

    _email_contactfilter_initreq(req, &contactfilter);
    jmap_emailquery_init(&query);

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req, &parser,
                     emailquery_args_parse, &query,
                     _email_parse_filter_cb, &contactfilter,
                     _email_parse_comparator, NULL,
                     &query.super, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidArguments");
        json_object_set(err, "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }
    else if (r) {
        jmap_error(req, jmap_server_error(r));
        goto done;
    }

    /* Run query */
    json_t *res = emailquery_run(req, &query, &contactfilter.contactgroups, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }
    jmap_ok(req, res);

done:
    jmap_email_contactfilter_fini(&contactfilter);
    jmap_emailquery_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static void _email_querychanges_collapsed(jmap_req_t *req,
                                          struct jmap_querychanges *query,
                                          struct email_contactfilter *contactfilter,
                                          json_t **err)
{
    modseq_t since_modseq;
    uint32_t since_uid;
    uint32_t num_changes = 0;
    modseq_t addrbook_modseq = 0;
    int r = 0;

    if (!_email_read_querystate(query->since_querystate,
                                &since_modseq, &since_uid,
                                &addrbook_modseq)) {
        *err = json_pack("{s:s s:s}", "type", "cannotCalculateChanges",
                                      "description", "invalid query state");
        return;
    }
    if (addrbook_modseq && addrbook_modseq != jmap_highestmodseq(req, MBTYPE_ADDRESSBOOK)) {
        *err = json_pack("{s:s s:s}", "type", "cannotCalculateChanges",
                                      "description", "addressbook changed");

        return;
    }

    struct emailsearch search;
    emailsearch_init(&search, req, query->filter, query->sort,
                      &contactfilter->contactgroups,
                      /*want_expunged*/1,
                      /*want_partids*/0,
                      /*ignore_timer*/0, err);
    if (*err) goto done;

    if (!emailsearch_is_mutable(&search)) {
        *err = json_pack("{s:s s:s}", "type", "cannotCalculateChanges",
                                      "description", "mutable search");
        goto done;
    }

    /* Run search */
    r = emailsearch_run_uidsearch(req, &search);
    if (r) goto done;

    /* Prepare result loop */
    const ptrarray_t *msgdata = &search.query->merged_msgdata;
    char email_id[JMAP_EMAILID_SIZE];
    int found_up_to = 0;
    size_t mdcount = msgdata->count;

    hash_table touched_ids = HASH_TABLE_INITIALIZER;
    memset(&touched_ids, 0, sizeof(hash_table));
    construct_hash_table(&touched_ids, mdcount + 1, 0);

    hashu64_table touched_cids = HASHU64_TABLE_INITIALIZER;
    memset(&touched_cids, 0, sizeof(hashu64_table));
    construct_hashu64_table(&touched_cids, mdcount + 1, 0);

    /* touched_ids contains values for each email_id:
     * 1 - email has been modified
     * 2 - email has been seen (aka: non-expunged record shown)
     * 4 - email has been reported removed
     * 8 - email has been reported added
     */

    /* touched_cids contains values for each thread
     * 1 - thread has been modified
     * 2 - thread has been seen (aka: exemplar shown)
     * 4 - thread has had an expunged shown (aka: possible old exemplar passed)
     * 8 - thread is finished (aka: old exemplar definitely passed)
     */

    // phase 1: find messages and threads which have been modified
    size_t i;
    for (i = 0 ; i < mdcount; i++) {
        MsgData *md = ptrarray_nth(msgdata, i);

        // for this phase, we only care that it has a change
        if (md->modseq <= since_modseq) {
            if (search.is_mutable) {
                modseq_t modseq = md->convmodseq;
                if (!modseq) conversation_get_modseq(req->cstate, md->cid, &modseq);
                if (modseq > since_modseq)
                    hashu64_insert(md->cid, (void*)1, &touched_cids);
            }
            continue;
        }

        jmap_set_emailid(&md->guid, email_id);

        hash_insert(email_id, (void*)1, &touched_ids);
        hashu64_insert(md->cid, (void*)1, &touched_cids);
    }

    // phase 2: report messages that need it
    for (i = 0 ; i < mdcount; i++) {
        MsgData *md = ptrarray_nth(msgdata, i);

        jmap_set_emailid(&md->guid, email_id);

        int is_expunged = (md->system_flags & FLAG_DELETED) ||
                (md->internal_flags & FLAG_INTERNAL_EXPUNGED);

        size_t touched_id = (size_t)hash_lookup(email_id, &touched_ids);
        size_t new_touched_id = touched_id;

        size_t touched_cid = (size_t)hashu64_lookup(md->cid, &touched_cids);
        size_t new_touched_cid = touched_cid;

        if (is_expunged) {
            // don't need to tell changes any more
            if (found_up_to) goto doneloop;

            // nothing to do if not changed (could not be old exemplar)
            if (!(touched_id & 1)) goto doneloop;

            // could not possibly be old exemplar
            if (!search.is_mutable && (touched_cid & 8)) goto doneloop;

            // add the destroy notice
            if (!(touched_id & 4)) {
                _email_querychanges_destroyed(query, email_id);
                new_touched_id |= 4;
                new_touched_cid |= 4;
            }

            goto doneloop;
        }

        // this is the exemplar for the cid
        if (!(touched_cid & 2)) {
            query->total++;
            new_touched_cid |= 2;
        }

        if (found_up_to) goto doneloop;

        // if it's a changed cid, see if we should tell
        if ((touched_cid & 1)) {
            // haven't told the exemplar yet?  This is the exemplar!
            if (!(touched_cid & 2)) {
                // not yet told in any way, and this ID hasn't been told at all
                if (touched_cid == 1 && touched_id == 0 && !search.is_mutable) {
                    // this is both old AND new exemplar, horray.  We don't
                    // need to tell anything
                    new_touched_cid |= 8;
                    goto doneloop;
                }

                // have to tell both a remove and an add for the exemplar
                if (!(touched_id & 4)) {
                    _email_querychanges_destroyed(query, email_id);
                    new_touched_id |= 4;
                    num_changes++;
                }
                if (!(touched_id & 8)) {
                    _email_querychanges_added(query, email_id);
                    new_touched_id |= 8;
                    num_changes++;
                }
                new_touched_cid |= 4;
                goto doneloop;
            }
            // otherwise we've already told the exemplar.

            // could not possibly be old exemplar
            if (!search.is_mutable && (touched_cid & 8)) goto doneloop;

            // OK, maybe this alive message WAS the old examplar
            if (!(touched_id & 4)) {
                _email_querychanges_destroyed(query, email_id);
                new_touched_id |= 4;
                new_touched_cid |= 4;
            }

            // and if this message is a stopper (must have been a candidate
            // for old exemplar) then stop
            if (!(touched_id & 1)) {
                new_touched_cid |= 8;
            }
        }

    doneloop:
        if (query->max_changes && (num_changes > query->max_changes)) {
            *err = json_pack("{s:s}", "type", "tooManyChanges");
            break;
        }
        if (new_touched_id != touched_id)
            hash_insert(email_id, (void*)new_touched_id, &touched_ids);
        if (new_touched_cid != touched_cid)
            hashu64_insert(md->cid, (void*)new_touched_cid, &touched_cids);
        // if the search is mutable, later changes could have
        // been earlier once, so no up_to_id is possible
        if (!found_up_to && !search.is_mutable
                         && query->up_to_id
                         && !strcmp(email_id, query->up_to_id)) {
            found_up_to = 1;
        }
    }

    free_hash_table(&touched_ids, NULL);
    free_hashu64_table(&touched_cids, NULL);

    modseq_t modseq = jmap_highestmodseq(req, MBTYPE_EMAIL);
    query->new_querystate = _email_make_querystate(modseq, 0, addrbook_modseq);

done:
    if (r && *err == NULL) {
        if (r == IMAP_SEARCH_SLOW) {
            *err = json_pack("{s:s s:s}", "type", "cannotCalculateChanges",
                                          "description", "search too slow");
        }
        else *err = jmap_server_error(r);
    }
    emailsearch_fini(&search);
}

static void _email_querychanges_uncollapsed(jmap_req_t *req,
                                            struct jmap_querychanges *query,
                                            struct email_contactfilter *contactfilter,
                                            json_t **err)
{
    modseq_t since_modseq;
    uint32_t since_uid;
    uint32_t num_changes = 0;
    modseq_t addrbook_modseq = 0;
    int r = 0;

    if (!_email_read_querystate(query->since_querystate,
                                &since_modseq, &since_uid,
                                &addrbook_modseq)) {
        *err = json_pack("{s:s s:s}", "type", "cannotCalculateChanges",
                                      "description", "invalid query state");
        return;
    }
    if (addrbook_modseq && addrbook_modseq != jmap_highestmodseq(req, MBTYPE_ADDRESSBOOK)) {
        *err = json_pack("{s:s s:s}", "type", "cannotCalculateChanges",
                                      "description", "addressbook changed");
        return;
    }

    struct emailsearch search;
    emailsearch_init(&search, req, query->filter, query->sort,
                      &contactfilter->contactgroups,
                      /*want_expunged*/1,
                      /*want_partids*/0,
                      /*ignore_timer*/0, err);
    if (*err) goto done;

    if (!emailsearch_is_mutable(&search)) {
        *err = json_pack("{s:s s:s}", "type", "cannotCalculateChanges",
                                      "description", "mutable search");
        goto done;
    }

    /* Run search */
    r = emailsearch_run_uidsearch(req, &search);
    if (r) goto done;

    /* Prepare result loop */
    const ptrarray_t *msgdata = &search.query->merged_msgdata;
    char email_id[JMAP_EMAILID_SIZE];
    int found_up_to = 0;
    size_t mdcount = msgdata->count;

    hash_table touched_ids = HASH_TABLE_INITIALIZER;
    memset(&touched_ids, 0, sizeof(hash_table));
    construct_hash_table(&touched_ids, mdcount + 1, 0);

    /* touched_ids contains values for each email_id:
     * 1 - email has been modified
     * 2 - email has been seen (aka: non-expunged record shown)
     * 4 - email has been reported removed
     * 8 - email has been reported added
     */

    // phase 1: find messages which have been modified
    size_t i;
    for (i = 0 ; i < mdcount; i++) {
        MsgData *md = ptrarray_nth(msgdata, i);

        // for this phase, we only care that it has a change
        if (md->modseq <= since_modseq) continue;

        jmap_set_emailid(&md->guid, email_id);

        hash_insert(email_id, (void*)1, &touched_ids);
    }

    // phase 2: report messages that need it
    for (i = 0 ; i < mdcount; i++) {
        MsgData *md = ptrarray_nth(msgdata, i);

        jmap_set_emailid(&md->guid, email_id);

        int is_expunged = (md->system_flags & FLAG_DELETED) ||
                (md->internal_flags & FLAG_INTERNAL_EXPUNGED);

        size_t touched_id = (size_t)hash_lookup(email_id, &touched_ids);
        size_t new_touched_id = touched_id;

        if (is_expunged) {
            // don't need to tell changes any more
            if (found_up_to) continue;

            // nothing to do if not changed
            if (!(touched_id & 1)) continue;

            // add the destroy notice
            if (!(touched_id & 4)) {
                _email_querychanges_destroyed(query, email_id);
                new_touched_id |= 4;
            }

            goto doneloop;
        }

        // this is an exemplar
        if (!(touched_id & 2)) {
            query->total++;
            new_touched_id |= 2;
        }

        if (found_up_to) goto doneloop;

        // if it's changed, tell about that
        if ((touched_id & 1)) {
            if (!search.is_mutable && touched_id == 1 && md->modseq <= since_modseq) {
                // this is the exemplar, and it's unchanged,
                // and we haven't told a removed yet, so we
                // can just suppress everything
                new_touched_id |= 4 | 8;
                goto doneloop;
            }

            // otherwise we're going to have to tell both, if we haven't already
            if (!(touched_id & 4)) {
                _email_querychanges_destroyed(query, email_id);
                new_touched_id |= 4;
                num_changes++;
            }
            if (!(touched_id & 8)) {
                _email_querychanges_added(query, email_id);
                new_touched_id |= 8;
                num_changes++;
            }
        }

    doneloop:
        if (query->max_changes && (num_changes > query->max_changes)) {
            *err = json_pack("{s:s}", "type", "tooManyChanges");
            break;
        }
        if (new_touched_id != touched_id)
            hash_insert(email_id, (void*)new_touched_id, &touched_ids);
        // if the search is mutable, later changes could have
        // been earlier once, so no up_to_id is possible
        if (!found_up_to && !search.is_mutable
                         && query->up_to_id
                         && !strcmp(email_id, query->up_to_id)) {
            found_up_to = 1;
        }
    }

    free_hash_table(&touched_ids, NULL);

    modseq_t modseq = jmap_highestmodseq(req, MBTYPE_EMAIL);
    query->new_querystate = _email_make_querystate(modseq, 0, addrbook_modseq);

done:
    if (r && *err == NULL) {
        if (r == IMAP_SEARCH_SLOW) {
            *err = json_pack("{s:s s:s}", "type", "cannotCalculateChanges",
                                          "description", "search too slow");
        }
        else *err = jmap_server_error(r);
    }
    emailsearch_fini(&search);
}

static int jmap_email_querychanges(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_querychanges query;
    struct emailquery emailquery;
    struct email_contactfilter contactfilter;

    _email_contactfilter_initreq(req, &contactfilter);
    jmap_emailquery_init(&emailquery);

    /* Parse arguments */
    json_t *err = NULL;
    jmap_querychanges_parse(req, &parser,
                            emailquery_args_parse, &emailquery,
                            _email_parse_filter_cb, &contactfilter,
                            _email_parse_comparator, NULL,
                            &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidArguments");
        json_object_set(err, "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    /* Query changes */
    if (emailquery.collapse_threads)
        _email_querychanges_collapsed(req, &query, &contactfilter, &err);
    else
        _email_querychanges_uncollapsed(req, &query, &contactfilter, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    json_t *res = jmap_querychanges_reply(&query);
    json_object_set(res, "collapseThreads",
            json_boolean(emailquery.collapse_threads));
    jmap_ok(req, res);

done:
    jmap_email_contactfilter_fini(&contactfilter);
    jmap_emailquery_fini(&emailquery);
    jmap_querychanges_fini(&query);
    jmap_parser_fini(&parser);
    return 0;
}

static void _email_changes(jmap_req_t *req, struct jmap_changes *changes, json_t **err)
{
    int r = 0;

    /* Run search */
    json_t *filter = json_pack("{s:o}", "sinceEmailState",
                               jmap_fmtstate(changes->since_modseq));
    json_t *sort = json_pack("[{s:s}]", "property", "emailState");

    struct emailsearch search;
    emailsearch_init(&search, req, filter, sort,
                      /*contactgroups*/NULL,
                      /*want_expunged*/1,
                      /*want_partids*/0,
                      /*ignore_timer*/1, err);
    if (*err) goto done;

    r = emailsearch_run_uidsearch(req, &search);
    if (r) goto done;

    /* Process results */
    const ptrarray_t *msgdata = &search.query->merged_msgdata;
    char email_id[JMAP_EMAILID_SIZE];
    size_t changes_count = 0;
    modseq_t highest_modseq = 0;
    int i;
    hash_table seen_ids = HASH_TABLE_INITIALIZER;
    memset(&seen_ids, 0, sizeof(hash_table));
    construct_hash_table(&seen_ids, msgdata->count + 1, 0);

    for (i = 0 ; i < msgdata->count; i++) {
        MsgData *md = ptrarray_nth(msgdata, i);

        jmap_set_emailid(&md->guid, email_id);

        /* Skip already seen messages */
        if (hash_lookup(email_id, &seen_ids)) continue;
        hash_insert(email_id, (void*)1, &seen_ids);

        /* Apply limit, if any */
        if (changes->max_changes && ++changes_count > changes->max_changes) {
            changes->has_more_changes = 1;
            break;
        }

        /* Keep track of the highest modseq */
        if (highest_modseq < md->modseq)
            highest_modseq = md->modseq;

        struct email_expunge_check rock = { req, changes->since_modseq, 0 };
        int r = conversations_guid_foreach(req->cstate, _guid_from_id(email_id),
                                           _email_is_expunged_cb, &rock);
        if (r) {
            *err = jmap_server_error(r);
            goto done;
        }

        /* Check the message status - status is a bitfield with:
         * 1: a message exists which was created on or before since_modseq
         * 2: a message exists which is not deleted
         *
         * from those facts we can determine ephemeral / destroyed / created / updated
         * and we don't need to tell about ephemeral (all created since last time, but none left)
         */
        switch (rock.status) {
        default:
            break; /* all messages were created AND deleted since previous state! */
        case 1:
            /* only expunged messages exist */
            json_array_append_new(changes->destroyed, json_string(email_id));
            break;
        case 2:
            /* alive, and all messages are created since previous modseq */
            json_array_append_new(changes->created, json_string(email_id));
            break;
        case 3:
            /* alive, and old */
            json_array_append_new(changes->updated, json_string(email_id));
            break;
        }
    }
    free_hash_table(&seen_ids, NULL);

    /* Set new state */
    changes->new_modseq = changes->has_more_changes ?
        highest_modseq : jmap_highestmodseq(req, MBTYPE_EMAIL);

done:
    json_decref(filter);
    json_decref(sort);
    if (r && *err == NULL) {
        if (r == IMAP_SEARCH_SLOW) {
            *err = json_pack("{s:s s:s}", "type", "cannotCalculateChanges",
                                          "description", "search too slow");
        }
        else *err = jmap_server_error(r);
    }
    emailsearch_fini(&search);
}

static int jmap_email_changes(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;

    /* Parse request */
    json_t *err = NULL;
    jmap_changes_parse(req, &parser, req->counters.maildeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Search for updates */
    _email_changes(req, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    jmap_ok(req, jmap_changes_reply(&changes));

done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    return 0;
}

static void _thread_changes(jmap_req_t *req, struct jmap_changes *changes, json_t **err)
{
    conversation_t conv = CONVERSATION_INIT;
    int r = 0;

    /* Run search */
    json_t *filter = json_pack("{s:o}", "sinceEmailState",
                               jmap_fmtstate(changes->since_modseq));
    json_t *sort = json_pack("[{s:s}]", "property", "emailState");

    struct emailsearch search;
    emailsearch_init(&search, req, filter, sort,
                      /*contactgroups*/NULL,
                      /*want_expunged*/1,
                      /*want_partids*/0,
                      /*ignore_timer*/1, err);
    if (*err) goto done;

    r = emailsearch_run_uidsearch(req, &search);
    if (r) goto done;

    /* Process results */
    const ptrarray_t *msgdata = &search.query->merged_msgdata;
    size_t changes_count = 0;
    modseq_t highest_modseq = 0;
    int i;

    struct hashset *seen_threads = hashset_new(8);

    char thread_id[JMAP_THREADID_SIZE];

    for (i = 0 ; i < msgdata->count; i++) {
        MsgData *md = ptrarray_nth(msgdata, i);

        /* Skip already seen threads */
        if (!hashset_add(seen_threads, &md->cid)) continue;

        /* Apply limit, if any */
        if (changes->max_changes && ++changes_count > changes->max_changes) {
            changes->has_more_changes = 1;
            break;
        }

        /* Keep track of the highest modseq */
        if (highest_modseq < md->modseq)
            highest_modseq = md->modseq;

        /* Determine if the thread got changed or destroyed */
        if (conversation_load_advanced(req->cstate, md->cid, &conv, /*flags*/0))
            continue;

        /* Report thread */
        jmap_set_threadid(md->cid, thread_id);
        if (conv.exists) {
            if (conv.createdmodseq <= changes->since_modseq)
                json_array_append_new(changes->updated, json_string(thread_id));
            else
                json_array_append_new(changes->created, json_string(thread_id));
        }
        else {
            if (conv.createdmodseq <= changes->since_modseq)
                json_array_append_new(changes->destroyed, json_string(thread_id));
        }

        conversation_fini(&conv);
        memset(&conv, 0, sizeof(conversation_t));
    }
    hashset_free(&seen_threads);

    /* Set new state */
    changes->new_modseq = changes->has_more_changes ?
        highest_modseq : jmap_highestmodseq(req, MBTYPE_EMAIL);

done:
    conversation_fini(&conv);
    json_decref(filter);
    json_decref(sort);
    if (r && *err == NULL) {
        if (r == IMAP_SEARCH_SLOW) {
            *err = json_pack("{s:s s:s}", "type", "cannotCalculateChanges",
                                          "description", "search too slow");
        }
        else *err = jmap_server_error(r);
    }
    emailsearch_fini(&search);
}

static int jmap_thread_changes(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;

    /* Parse request */
    json_t *err = NULL;
    jmap_changes_parse(req, &parser, req->counters.maildeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Search for updates */
    _thread_changes(req, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    jmap_ok(req, jmap_changes_reply(&changes));

done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    return 0;
}

struct snippet_receiver {
    search_text_receiver_t tr;
    search_text_receiver_t *next;
    json_t *snippet;
    json_t *attachmatch;
    int search_part;
    struct buf buf;
    strarray_t *partids;
};

static int _snippet_get_cb(struct mailbox *mbox __attribute__((unused)),
                           uint32_t uid __attribute__((unused)),
                           int part, const char *part_id,
                           const char *s, void *rock)
{
    struct snippet_receiver *sr = rock;

    if (part == SEARCH_PART_SUBJECT) {
        json_object_set_new(sr->snippet, "subject", json_string(s));
    }
    else if (part == SEARCH_PART_BODY ||
                part == SEARCH_PART_ATTACHMENTBODY) {
        json_object_set_new(sr->snippet, "preview", json_string(s));
    }
    else if (sr->partids && part == SEARCH_PART_ATTACHMENTNAME && part_id) {
        json_t *jattachments = json_object_get(sr->snippet, "attachments");
        json_t *jmatch = json_object_get(jattachments, part_id);
        if (jmatch) {
            json_object_set_new(jmatch, "name", json_string(s));
            strarray_append(sr->partids, part_id);
        }
    }

    /* Avoid costly attachment body snippets, if possible */
    return part == SEARCH_PART_BODY ? IMAP_OK_COMPLETED : 0;
}

static int _snippet_tr_begin_mailbox(search_text_receiver_t *rx,
                                       struct mailbox *mailbox,
                                       int incremental)
{
    struct snippet_receiver *sr = (struct snippet_receiver*) rx;
    return sr->next->begin_mailbox ?
        sr->next->begin_mailbox(sr->next, mailbox, incremental) : 0;
}

static uint32_t _snippet_tr_first_unindexed_uid(search_text_receiver_t *rx)
{
    struct snippet_receiver *sr = (struct snippet_receiver*) rx;
    return sr->next->first_unindexed_uid ?
        sr->next->first_unindexed_uid(sr->next) : 0;
}

static uint8_t _snippet_tr_is_indexed(search_text_receiver_t *rx, message_t *msg)
{
    struct snippet_receiver *sr = (struct snippet_receiver*) rx;
    return sr->next->is_indexed ?
        sr->next->is_indexed(sr->next, msg) : 0;
}

static int _snippet_tr_begin_message(search_text_receiver_t *rx, message_t *msg)
{
    struct snippet_receiver *sr = (struct snippet_receiver*) rx;
    return sr->next->begin_message ?
        sr->next->begin_message(sr->next, msg) : 0;
}

static int _snippet_tr_begin_bodypart(search_text_receiver_t *rx,
                                      const char *part_id,
                                      const struct message_guid *content_guid,
                                      const char *type, const char *subtype)
{
    struct snippet_receiver *sr = (struct snippet_receiver*) rx;

    if (sr->partids && part_id) {
        char blob_id[JMAP_BLOBID_SIZE];
        jmap_set_blobid(content_guid, blob_id);

        buf_setcstr(&sr->buf, type);
        buf_putc(&sr->buf, '/');
        buf_appendcstr(&sr->buf, subtype);
        buf_lcase(&sr->buf);

        sr->attachmatch = json_pack("{s:s s:s s:s}",
                "partId", part_id,
                "blobId", blob_id,
                "type", buf_cstring(&sr->buf));

        buf_reset(&sr->buf);
    }

    return sr->next->begin_bodypart ?
        sr->next->begin_bodypart(sr->next, part_id, content_guid, type, subtype) : 0;
}

static void _snippet_tr_begin_part(search_text_receiver_t *rx, int part)
{
    struct snippet_receiver *sr = (struct snippet_receiver*) rx;
    sr->search_part = part;
    if (sr->next->begin_part) sr->next->begin_part(sr->next, part);
}

static int _snippet_tr_append_text(search_text_receiver_t *rx,
                                   const struct buf *text)
{
    struct snippet_receiver *sr = (struct snippet_receiver*) rx;

    if (sr->search_part == SEARCH_PART_ATTACHMENTNAME) {
        if (sr->attachmatch) {
            json_object_set_new(sr->attachmatch, "name",
                    json_string(buf_cstring(text)));
        }
    }

    return (sr->next->append_text) ?
        sr->next->append_text(sr->next, text) : 0;
}

static void _snippet_tr_end_part(search_text_receiver_t *rx, int part)
{
    struct snippet_receiver *sr = (struct snippet_receiver*) rx;
    sr->search_part = -1;
    if (sr->next->end_part) sr->next->end_part(sr->next, part);
}

static void _snippet_tr_end_bodypart(search_text_receiver_t *rx)
{
    struct snippet_receiver *sr = (struct snippet_receiver*) rx;
    if (sr->partids && sr->attachmatch) {
        if (json_object_size(sr->attachmatch) == 4) {
            json_t *jpart_id = json_object_get(sr->attachmatch, "partId");
            json_t *attachments = json_object_get(sr->snippet, "attachments");
            json_object_set_new(attachments,
                    json_string_value(jpart_id), sr->attachmatch);
            json_object_del(sr->attachmatch, "partId");
        }
        else {
            json_decref(sr->attachmatch);
        }
        sr->attachmatch = NULL;
    }
    if (sr->next->end_bodypart) sr->next->end_bodypart(sr->next);
}

static int _snippet_tr_end_message(search_text_receiver_t *rx, uint8_t indexlevel)
{
    struct snippet_receiver *sr = (struct snippet_receiver*) rx;
    return sr->next->end_message ?
        sr->next->end_message(sr->next, indexlevel) : 0;
}

static int _snippet_tr_end_mailbox(search_text_receiver_t *rx, struct mailbox *mailbox)
{
    struct snippet_receiver *sr = (struct snippet_receiver*) rx;
    return sr->next->end_mailbox ?
        sr->next->end_mailbox(sr->next, mailbox) : 0;
}

static int _snippet_tr_flush(search_text_receiver_t *rx)
{
    struct snippet_receiver *sr = (struct snippet_receiver*) rx;
    return sr->next->flush ? sr->next->flush(sr->next) : 0;
}

static int _snippet_tr_audit_mailbox(search_text_receiver_t *rx, bitvector_t *unindexed)
{
    struct snippet_receiver *sr = (struct snippet_receiver*) rx;
    return sr->next->audit_mailbox ?
        sr->next->audit_mailbox(sr->next, unindexed) : 0;
}

static int _snippet_tr_index_charset_flags(int base_flags)
{
    return base_flags | CHARSET_KEEPCASE;
}

static int _snippet_tr_index_message_format(int format __attribute__((unused)),
                                            int is_snippet __attribute__((unused)))
{
    return MESSAGE_SNIPPET;
}

static int _snippet_get(jmap_req_t *req, json_t *filter,
                        json_t *messageids, json_t *jemailpartids,
                        json_t **snippets, json_t **notfound)
{
    struct index_state *state = NULL;
    void *intquery = NULL;
    search_builder_t *bx = NULL;
    search_text_receiver_t *rx = NULL;
    struct mailbox *mbox = NULL;
    struct searchargs *searchargs = NULL;
    struct index_init init;
    json_t *snippet = NULL;
    int r = 0;
    json_t *val;
    size_t i;
    char *mboxname = NULL;
    static search_snippet_markup_t markup = { "<mark>", "</mark>", "..." };
    strarray_t partids = STRARRAY_INITIALIZER;

    strarray_t perf_filters = STRARRAY_INITIALIZER;
    ptrarray_t search_attrs = PTRARRAY_INITIALIZER;

    *snippets = json_array();
    *notfound = json_array();

    /* Set up custom search text receiver */
    struct snippet_receiver sr = {
        {
            _snippet_tr_begin_mailbox,
            _snippet_tr_first_unindexed_uid,
            _snippet_tr_is_indexed,
            _snippet_tr_begin_message,
            _snippet_tr_begin_bodypart,
            _snippet_tr_begin_part,
            _snippet_tr_append_text,
            _snippet_tr_end_part,
            _snippet_tr_end_bodypart,
            _snippet_tr_end_message,
            _snippet_tr_end_mailbox,
            _snippet_tr_flush,
            _snippet_tr_audit_mailbox,
            _snippet_tr_index_charset_flags,
            _snippet_tr_index_message_format
        },
        NULL, NULL, NULL, 0, BUF_INITIALIZER, NULL
    };

    /* Build searchargs */
    searchargs = new_searchargs(NULL/*tag*/, GETSEARCH_CHARSET_FIRST,
                                &jmap_namespace, req->userid, req->authstate, 0);
    searchargs->root = _email_buildsearchexpr(req, filter, NULL, NULL, 0, &search_attrs, &perf_filters);

    /* Build the search query */
    memset(&init, 0, sizeof(init));
    init.userid = req->userid;
    init.authstate = req->authstate;
    init.examine_mode = 1;

    char *qmboxname = search_expr_firstmailbox(searchargs->root);
    if (!qmboxname) qmboxname = mboxname_user_mbox(req->accountid, NULL);
    r = index_open(qmboxname, &init, &state);
    free(qmboxname);
    if (r) goto done;

    bx = search_begin_search(state->mailbox, SEARCH_MULTIPLE);
    if (!bx) {
        r = IMAP_INTERNAL;
        goto done;
    }

    search_build_query(bx, searchargs->root);
    if (!bx->get_internalised) {
        r = IMAP_INTERNAL;
        goto done;
    }
    intquery = bx->get_internalised(bx);
    search_end_search(bx);
    if (!intquery) {
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Initialize snippet callback context */
    snippet = json_object();
    struct search_text_receiver *srx = (struct search_text_receiver*) &sr;
    rx = search_begin_snippets(intquery, 0, &markup, _snippet_get_cb, &sr);
    if (!rx) {
        r = IMAP_INTERNAL;
        goto done;
    }
    sr.next = rx;
    sr.snippet = snippet;
    if (jemailpartids) sr.partids = &partids;


    /* Convert the snippets */
    json_array_foreach(messageids, i, val) {
        message_t *msg;
        msgrecord_t *mr = NULL;
        uint32_t uid;

        const char *msgid = json_string_value(val);

        r = jmap_email_find(req, NULL, msgid, &mboxname, &uid);
        if (r) {
            if (r == IMAP_NOTFOUND) {
                json_array_append_new(*notfound, json_string(msgid));
            }
            r = 0;
            continue;
        }

        r = jmap_openmbox(req, mboxname, &mbox, 0);
        if (r) goto doneloop;

        r = msgrecord_find(mbox, uid, &mr);
        if (r) goto doneloop;

        r = msgrecord_get_message(mr, &msg);
        if (r) goto doneloop;

        json_t *jpartids = json_object_get(jemailpartids, msgid);
        if (jpartids) {
            json_t *jpartid;
            size_t j;
            json_array_foreach(jpartids, j, jpartid) {
                strarray_append(&partids, json_string_value(jpartid));
            }
        }
        json_object_set_new(snippet, "emailId", json_string(msgid));
        json_object_set_new(snippet, "subject", json_null());
        json_object_set_new(snippet, "preview", json_null());
        json_object_set_new(snippet, "attachments", json_object());
        sr.snippet = snippet;

        r = srx->begin_mailbox(srx, mbox, /*incremental*/0);
        if (!r) r = index_getsearchtext(msg, jpartids ? &partids : NULL, srx,
                                        INDEX_GETSEARCHTEXT_SNIPPET);
        if (!r || r == IMAP_OK_COMPLETED) {
            // prune attachments
            json_t *jattachments = json_object_get(snippet, "attachments");
            json_t *jmatch;
            const char *part_id;
            void *tmp;
            json_object_foreach_safe(jattachments, tmp, part_id, jmatch){
                if (strarray_find(&partids, part_id, 0) < 0) {
                    json_object_del(jattachments, part_id);
                }
            }
            if (!json_object_size(jattachments)) {
                json_object_set_new(snippet, "attachments", json_null());
            }
            json_array_append_new(*snippets, json_deep_copy(snippet));
            r = 0;
        }
        int r2 = srx->end_mailbox(srx, mbox);
        if (!r) r = r2;

        json_object_clear(snippet);
        strarray_truncate(&partids, 0);
        msgrecord_unref(&mr);
        buf_reset(&sr.buf);

doneloop:
        if (mr) msgrecord_unref(&mr);
        jmap_closembox(req, &mbox);
        free(mboxname);
        mboxname = NULL;
        if (r) goto done;
    }

    if (!json_array_size(*notfound)) {
        json_decref(*notfound);
        *notfound = json_null();
    }

done:
    if (rx) search_end_snippets(rx);
    if (snippet) json_decref(snippet);
    if (intquery) search_free_internalised(intquery);
    if (mboxname) free(mboxname);
    if (mbox) jmap_closembox(req, &mbox);
    if (searchargs) freesearchargs(searchargs);
    strarray_fini(&perf_filters);
    if (ptrarray_size(&search_attrs)) {
        search_attr_t *attr;
        while ((attr = ptrarray_pop(&search_attrs))) {
            if (attr->freeattr)
                attr->freeattr(&attr);
        }
    }
    ptrarray_fini(&search_attrs);
    strarray_fini(&partids);
    index_close(&state);
    buf_free(&sr.buf);
    return r;
}

static int _email_filter_contains_text(json_t *filter)
{
    if (JNOTNULL(filter)) {
        json_t *val;
        size_t i;

        if (JNOTNULL(json_object_get(filter, "text"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "subject"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "body"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "attachmentBody"))) {
            return 1;
        }

        /* We don't generate snippets for headers, but we
         * might find header text in the body or subject again. */
        if (JNOTNULL(json_object_get(filter, "header"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "from"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "to"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "cc"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "bcc"))) {
            return 1;
        }
        if (JNOTNULL(json_object_get(filter, "deliveredTo"))) {
            return 1;
        }

        json_array_foreach(json_object_get(filter, "conditions"), i, val) {
            if (_email_filter_contains_text(val)) {
                return 1;
            }
        }
    }
    return 0;
}

static int jmap_searchsnippet_get(jmap_req_t *req)
{
    int r = 0;
    const char *key;
    json_t *arg, *jfilter = NULL, *jmessageids = NULL, *jemailpartids = NULL;
    json_t *snippets, *notfound;
    struct buf buf = BUF_INITIALIZER;
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct email_contactfilter contactfilter;
    json_t *err = NULL;

    _email_contactfilter_initreq(req, &contactfilter);

    /* Parse and validate arguments. */
    json_t *unsupported_filter = json_array();

    json_object_foreach(req->args, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        /* filter */
        else if (!strcmp(key, "filter")) {
            jfilter = arg;
            if (JNOTNULL(jfilter)) {
                jmap_parser_push(&parser, "filter");
                jmap_filter_parse(req, &parser, jfilter, unsupported_filter,
                                  _email_parse_filter_cb, &contactfilter, &err);
                jmap_parser_pop(&parser);
                if (err) break;
            }
        }

        /* messageIds */
        else if (!strcmp(key, "emailIds")) {
            jmessageids = arg;
            if (json_array_size(jmessageids)) {
                jmap_parse_strings(jmessageids, &parser, "emailIds");
            }
            else if (!json_is_array(jmessageids)) {
                jmap_parser_invalid(&parser, "emailIds");
            }
        }

        /* partIds */
        else if (jmap_is_using(req, JMAP_MAIL_EXTENSION) && !strcmp(key, "partIds")) {
            jemailpartids = arg;
            int is_valid = 1;
            if (json_is_object(jemailpartids)) {
                const char *email_id;
                json_t *jpartids;
                json_object_foreach(jemailpartids, email_id, jpartids) {
                    if (json_is_array(jpartids)) {
                        size_t i;
                        json_t *jpartid;
                        json_array_foreach(jpartids, i, jpartid) {
                            if (!json_is_string(jpartid)) {
                                is_valid = 0;
                                break;
                            }
                        }
                    }
                    else if (json_is_null(jpartids)) {
                        /* JSON null means: no parts */
                        continue;
                    }
                    if (!is_valid) break;
                }
            }
            else is_valid = json_is_null(jemailpartids);
            if (!is_valid) {
                jmap_parser_invalid(&parser, "partIds");
            }
        }
        else jmap_parser_invalid(&parser, key);
        if (!json_object_size(jemailpartids)) {
            jemailpartids = NULL;
        }
    }

    /* Bail out for argument errors */
    if (err) {
        jmap_error(req, err);
        json_decref(unsupported_filter);
        goto done;
    }
    else if (json_array_size(parser.invalid)) {
        jmap_error(req, json_pack("{s:s, s:O}", "type", "invalidArguments",
                    "arguments", parser.invalid));
        json_decref(unsupported_filter);
        goto done;
    }
    /* Report unsupported filters */
    if (json_array_size(unsupported_filter)) {
        jmap_error(req, json_pack("{s:s, s:o}", "type", "unsupportedFilter",
                    "filters", unsupported_filter));
        goto done;
    }
    json_decref(unsupported_filter);

    if (json_array_size(jmessageids) && _email_filter_contains_text(jfilter)) {
        /* Render snippets */
        r = _snippet_get(req, jfilter, jmessageids, jemailpartids, &snippets, &notfound);
        if (r) goto done;
    } else {
        /* Trivial, snippets cant' match */
        size_t i;
        json_t *val;

        snippets = json_array();
        notfound = json_null();

        json_array_foreach(jmessageids, i, val) {
            json_array_append_new(snippets, json_pack("{s:s s:n s:n}",
                        "emailId", json_string_value(val),
                        "subject", "preview"));
        }
    }

    /* Prepare response. */
    json_t *res = json_pack("{s:o s:o}",
                            "list", snippets, "notFound", notfound);
    if (jfilter) json_object_set(res, "filter", jfilter);
    jmap_ok(req, res);

done:
    jmap_email_contactfilter_fini(&contactfilter);
    jmap_parser_fini(&parser);
    buf_free(&buf);
    return r;
}

struct thread_get_rock {
    jmap_req_t *req;
    int is_own_account; /* input argument */
    int is_visible;     /* output argument */
};

static int _thread_get_cb(const conv_guidrec_t *rec, void *vrock)
{
    if (rec->part) return 0;
    if (rec->internal_flags & FLAG_INTERNAL_EXPUNGED) return 0;

    struct thread_get_rock *rock = vrock;
    static int needrights = JACL_READITEMS;
    mbentry_t *mbentry = NULL;

    conv_guidrec_mbentry(rec, &mbentry);

    if (!mbentry || mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL ||
        (!rock->is_own_account &&
         !jmap_hasrights_mbentry(rock->req, mbentry, needrights))) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }
    mboxlist_entry_free(&mbentry);

    rock->is_visible = 1;
    return IMAP_OK_COMPLETED;
}

static int _thread_get(jmap_req_t *req, json_t *ids,
                       json_t *list, json_t *not_found)
{
    conversation_t conv = CONVERSATION_INIT;
    json_t *val;
    size_t i;
    int r = 0;

    json_array_foreach(ids, i, val) {
        conv_thread_t *thread;
        char email_id[JMAP_EMAILID_SIZE];

        const char *threadid = json_string_value(val);

        memset(&conv, 0, sizeof(conversation_t));
        r = conversation_load_advanced(req->cstate, _cid_from_id(threadid),
                                       &conv, CONV_WITHTHREAD);
        if (r || !conv.thread) {
            json_array_append_new(not_found, json_string(threadid));
            continue;
        }

        int is_own_account = !strcmp(req->userid, req->accountid);
        json_t *ids = json_array();
        for (thread = conv.thread; thread; thread = thread->next) {
            struct thread_get_rock rock = { req, is_own_account, 0 };
            const char *guidrep = message_guid_encode(&thread->guid);
            int r = conversations_guid_foreach(req->cstate, guidrep,
                                              _thread_get_cb, &rock);
            if ((r && r != IMAP_OK_COMPLETED) || !rock.is_visible) {
                continue;
            }
            jmap_set_emailid(&thread->guid, email_id);
            json_array_append_new(ids, json_string(email_id));
        }

        /* if we didn't find any visible IDs, then the thread doesn't really
           exist for this user */
        if (!json_array_size(ids)) {
            json_decref(ids);
            json_array_append_new(not_found, json_string(threadid));
            continue;
        }

        json_t *jthread = json_pack("{s:s s:o}", "id", threadid, "emailIds", ids);
        json_array_append_new(list, jthread);

        conversation_fini(&conv);
    }

    r = 0;

    conversation_fini(&conv);
    return r;
}

static const jmap_property_t thread_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "emailIds",
        NULL,
        0
    },
    { NULL, NULL, 0 }
};

static int jmap_thread_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;

    /* Parse request */
    jmap_get_parse(req, &parser, thread_props, /*allow_null_ids*/0,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Find threads */
    int r = _thread_get(req, get.ids, get.list, get.not_found);
    if (r) {
        syslog(LOG_ERR, "jmap: Thread/get: %s", error_message(r));
        jmap_error(req, jmap_server_error(r));
        goto done;
    }

    get.state = jmap_getstate(req, MBTYPE_EMAIL, /*refresh*/0);
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

struct email_getcontext {
    struct seen *seendb;           /* Seen database for shared accounts */
    hash_table seenseq_by_mbox_id; /* Cached seen sequences */
};

static void _free_cached_seqset(void *p)
{
    seqset_t *seq = (seqset_t *)p;
    seqset_free(&seq);
}

static void _email_getcontext_fini(struct email_getcontext *ctx)
{
    free_hash_table(&ctx->seenseq_by_mbox_id, _free_cached_seqset);
    seen_close(&ctx->seendb);
}

struct email_getargs {
    /* Email/get arguments */
    hash_table *props; /* owned by JMAP get or process stack */
    hash_table *bodyprops;
    ptrarray_t want_headers;     /* array of header_prop */
    ptrarray_t want_bodyheaders; /* array of header_prop */
    short fetch_text_body;
    short fetch_html_body;
    short fetch_all_body;
    size_t max_body_bytes;
    /* Request-scoped context */
    struct email_getcontext ctx;
};

#define _EMAIL_GET_ARGS_INITIALIZER \
    { \
        NULL, \
        NULL, \
        PTRARRAY_INITIALIZER, \
        PTRARRAY_INITIALIZER, \
        0, \
        0, \
        0, \
        0, \
        { \
            NULL, \
            HASH_TABLE_INITIALIZER \
        } \
    };

/* Initialized in email_get_parse. *Not* thread-safe */
static hash_table _email_get_default_bodyprops = HASH_TABLE_INITIALIZER;
static hash_table _email_parse_default_props = HASH_TABLE_INITIALIZER;

static void _email_getargs_fini(struct email_getargs *args)
{
    if (args->bodyprops && args->bodyprops != &_email_get_default_bodyprops) {
        free_hash_table(args->bodyprops, NULL);
        free(args->bodyprops);
    }
    args->bodyprops = NULL;

    struct header_prop *prop;
    while ((prop = ptrarray_pop(&args->want_headers))) {
        _header_prop_fini(prop);
        free(prop);
    }
    ptrarray_fini(&args->want_headers);
    while ((prop = ptrarray_pop(&args->want_bodyheaders))) {
        _header_prop_fini(prop);
        free(prop);
    }
    ptrarray_fini(&args->want_bodyheaders);
    _email_getcontext_fini(&args->ctx);
}

/* A wrapper to aggregate JMAP keywords over a set of message records.
 * Notably the $seen keyword is a pain to map from IMAP to JMAP:
 * (1) it must only be reported if the IMAP \Seen flag is set on
 *     all non-deleted index records.
 * (2) it must be read from seen.db for shared mailboxes
 */
struct email_keywords {
    const char *userid;
    hash_table counts;
    size_t totalmsgs;
    hash_table *seenseq_by_mbox_id;
    struct seen *seendb;
};

#define _EMAIL_KEYWORDS_INITIALIZER { NULL, HASH_TABLE_INITIALIZER, 0, NULL, NULL }

/* Initialize the keyword aggregator for the authenticated userid.
 *
 * The seenseq hash table is used to read cached sequence sets
 * read from seen.db per mailbox. If the hash table does not
 * contain a sequence for the respective mailbox id, it is read
 * from seen.db and stored in the map.
 * Callers must free any entries in seenseq_by_mbox_id. */
static void _email_keywords_init(struct email_keywords *keywords,
                                 const char *userid,
                                 struct seen *seendb,
                                 hash_table *seenseq_by_mbox_id)
{
    construct_hash_table(&keywords->counts, 64, 0);
    keywords->userid = userid;
    keywords->seendb = seendb;
    keywords->seenseq_by_mbox_id = seenseq_by_mbox_id;
}

static void _email_keywords_fini(struct email_keywords *keywords)
{
    free_hash_table(&keywords->counts, NULL);
}

static void _email_keywords_add_keyword(struct email_keywords *keywords,
                                        const char *keyword)
{
    uintptr_t count = (uintptr_t) hash_lookup(keyword, &keywords->counts);
    hash_insert(keyword, (void*) count+1, &keywords->counts);
}

static int _email_keywords_add_msgrecord(struct email_keywords *keywords,
                                         msgrecord_t *mr)
{
    uint32_t uid, system_flags, internal_flags;
    uint32_t user_flags[MAX_USER_FLAGS/32];
    struct mailbox *mbox = NULL;

    int r = msgrecord_get_uid(mr, &uid);
    if (r) goto done;
    r = msgrecord_get_mailbox(mr, &mbox);
    if (r) goto done;
    r = msgrecord_get_systemflags(mr, &system_flags);
    if (r) goto done;
    r = msgrecord_get_internalflags(mr, &internal_flags);
    if (r) goto done;
    if (system_flags & FLAG_DELETED || internal_flags & FLAG_INTERNAL_EXPUNGED) goto done;
    r = msgrecord_get_userflags(mr, user_flags);
    if (r) goto done;

    int read_seendb = !mailbox_internal_seen(mbox, keywords->userid);
    if (read_seendb && !keywords->seendb) {
        xsyslog(LOG_ERR, "mailbox requires seen.db but no database found",
                "userid=<%s> mailbox_uniqueid=<%s> mailbox_name=<%s>",
                keywords->userid, mailbox_uniqueid(mbox), mailbox_name(mbox));
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Read system flags */
    if ((system_flags & FLAG_DRAFT))
        _email_keywords_add_keyword(keywords, "$draft");
    if ((system_flags & FLAG_FLAGGED))
        _email_keywords_add_keyword(keywords, "$flagged");
    if ((system_flags & FLAG_ANSWERED))
        _email_keywords_add_keyword(keywords, "$answered");
    if (!read_seendb && system_flags & FLAG_SEEN)
        _email_keywords_add_keyword(keywords, "$seen");

    /* Read user flags */
    struct buf buf = BUF_INITIALIZER;
    int i;
    for (i = 0 ; i < MAX_USER_FLAGS ; i++) {
        if (mbox->h.flagname[i] && (user_flags[i/32] & 1<<(i&31))) {
            buf_setcstr(&buf, mbox->h.flagname[i]);
            _email_keywords_add_keyword(keywords, buf_lcase(&buf));
        }
    }
    buf_free(&buf);

    if (read_seendb) {
        /* Read $seen keyword from seen.db for shared accounts */
        seqset_t *seenseq = hash_lookup(mailbox_uniqueid(mbox), keywords->seenseq_by_mbox_id);
        if (!seenseq) {
            struct seendata sd = SEENDATA_INITIALIZER;
            int r = seen_read(keywords->seendb, mailbox_uniqueid(mbox), &sd);
            if (!r) {
                seenseq = seqset_parse(sd.seenuids, NULL, sd.lastuid);
                hash_insert(mailbox_uniqueid(mbox), seenseq, keywords->seenseq_by_mbox_id);
                seen_freedata(&sd);
            }
            else {
                syslog(LOG_ERR, "Could not read seen state for %s (%s)",
                        keywords->userid, error_message(r));
            }
        }

        if (seenseq && seqset_ismember(seenseq, uid))
            _email_keywords_add_keyword(keywords, "$seen");
    }

    /* Count message */
    keywords->totalmsgs++;

done:
    return r;
}

static json_t *_email_keywords_to_jmap(struct email_keywords *keywords)
{
    json_t *jkeywords = json_object();
    hash_iter *kwiter = hash_table_iter(&keywords->counts);
    while (hash_iter_next(kwiter)) {
        const char *keyword = hash_iter_key(kwiter);
        uintptr_t count = (uintptr_t) hash_iter_val(kwiter);
        if (strcasecmp(keyword, "$seen") || count == keywords->totalmsgs) {
            json_object_set_new(jkeywords, keyword, json_true());
        }
    }
    hash_iter_free(&kwiter);
    return jkeywords;
}


struct email_get_keywords_rock {
    jmap_req_t *req;
    struct email_keywords keywords;
};

static int _email_get_keywords_cb(const conv_guidrec_t *rec, void *vrock)
{
    struct email_get_keywords_rock *rock = vrock;
    jmap_req_t *req = rock->req;
    struct mailbox *mbox = NULL;
    mbentry_t *mbentry = NULL;
    msgrecord_t *mr = NULL;

    if (rec->part) return 0;

    conv_guidrec_mbentry(rec, &mbentry);

    if (!mbentry || (mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL) ||
        !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    /* Fetch system flags */
    int r = jmap_openmbox(req, mbentry->name, &mbox, 0);
    mboxlist_entry_free(&mbentry);
    if (r) return r;

    r = msgrecord_find(mbox, rec->uid, &mr);
    if (r) goto done;

    r = _email_keywords_add_msgrecord(&rock->keywords, mr);

done:
    msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);
    return r;
}

static int _email_get_keywords(jmap_req_t *req,
                               struct email_getcontext *ctx,
                               const char *msgid,
                               json_t **jkeywords)
{
    /* Initialize seen.db and sequence set cache */
    if (ctx->seendb == NULL && strcmp(req->accountid, req->userid)) {
        int r = seen_open(req->userid, SEEN_CREATE, &ctx->seendb);
        if (r) return r;
    }
    if (ctx->seenseq_by_mbox_id.size == 0) {
        construct_hash_table(&ctx->seenseq_by_mbox_id, 128, 0);
    }
    /* Gather keywords for all message records */
    struct email_get_keywords_rock rock = { req, _EMAIL_KEYWORDS_INITIALIZER };
    _email_keywords_init(&rock.keywords, req->userid, ctx->seendb, &ctx->seenseq_by_mbox_id);
    int r = conversations_guid_foreach(req->cstate, _guid_from_id(msgid),
                                       _email_get_keywords_cb, &rock);
    *jkeywords = _email_keywords_to_jmap(&rock.keywords);
    _email_keywords_fini(&rock.keywords);
    return r;
}

struct email_get_snoozed_rock {
    jmap_req_t *req;
    json_t *snoozed;
};

static int _email_get_snoozed_cb(const conv_guidrec_t *rec, void *vrock)
{
    struct email_get_snoozed_rock *rock = vrock;
    mbentry_t *mbentry = NULL;

    if (rec->part) return 0;

    conv_guidrec_mbentry(rec, &mbentry);

    if (!mbentry || mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL ||
        !jmap_hasrights_mbentry(rock->req, mbentry, JACL_READITEMS)) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    if (FLAG_INTERNAL_SNOOZED ==
        (rec->internal_flags & (FLAG_INTERNAL_SNOOZED|FLAG_INTERNAL_EXPUNGED))) {
        /* Fetch snoozed annotation */
        rock->snoozed = jmap_fetch_snoozed(mbentry->name, rec->uid);
    }
    mboxlist_entry_free(&mbentry);

    /* Short-circuit the foreach if we find a snoozed message */
    return (rock->snoozed != NULL);
}

static void _email_parse_wantheaders(json_t *jprops,
                                     struct jmap_parser *parser,
                                     const char *prop_name,
                                     ptrarray_t *want_headers)
{
    size_t i;
    json_t *jval;
    json_array_foreach(jprops, i, jval) {
        const char *s = json_string_value(jval);
        if (!s || strncmp(s, "header:", 7))
            continue;
        struct header_prop *hprop;
        if ((hprop = _header_parseprop(s))) {
            ptrarray_append(want_headers, hprop);
        }
        else {
            jmap_parser_push_index(parser, prop_name, i, s);
            jmap_parser_invalid(parser, NULL);
            jmap_parser_pop(parser);
        }
    }
}

static void _email_init_default_props(hash_table *props)
{
    /* Initialize process-owned default property list */
    construct_hash_table(props, 32, 0);
    if (props == &_email_get_default_bodyprops) {
        hash_insert("blobId",      (void*)1, props);
        hash_insert("charset",     (void*)1, props);
        hash_insert("cid",         (void*)1, props);
        hash_insert("disposition", (void*)1, props);
        hash_insert("language",    (void*)1, props);
        hash_insert("location",    (void*)1, props);
        hash_insert("name",        (void*)1, props);
        hash_insert("partId",      (void*)1, props);
        hash_insert("size",        (void*)1, props);
        hash_insert("type",        (void*)1, props);
    }
    else {
        hash_insert("attachments",   (void*)1, props);
        hash_insert("bcc",           (void*)1, props);
        hash_insert("bodyValues",    (void*)1, props);
        hash_insert("cc",            (void*)1, props);
        hash_insert("from",          (void*)1, props);
        hash_insert("hasAttachment", (void*)1, props);
        hash_insert("htmlBody",      (void*)1, props);
        hash_insert("inReplyTo",     (void*)1, props);
        hash_insert("messageId",     (void*)1, props);
        hash_insert("preview",       (void*)1, props);
        hash_insert("references",    (void*)1, props);
        hash_insert("replyTo",       (void*)1, props);
        hash_insert("sender",        (void*)1, props);
        hash_insert("sentAt",        (void*)1, props);
        hash_insert("subject",       (void*)1, props);
        hash_insert("textBody",      (void*)1, props);
        hash_insert("to",            (void*)1, props);
    }
}

static int _email_getargs_parse(jmap_req_t *req __attribute__((unused)),
                                struct jmap_parser *parser,
                                const char *key,
                                json_t *arg,
                                void *rock)
{
    struct email_getargs *args = (struct email_getargs *) rock;
    int r = 1;

    /* bodyProperties */
    if (!strcmp(key, "bodyProperties")) {
        if (jmap_parse_strings(arg, parser, "bodyProperties")) {
            size_t i;
            json_t *val;

            args->bodyprops = xzmalloc(sizeof(hash_table));
            construct_hash_table(args->bodyprops, json_array_size(arg) + 1, 0);
            json_array_foreach(arg, i, val) {
                hash_insert(json_string_value(val), (void*)1, args->bodyprops);
            }
        }
        /* header:Xxx properties */
        _email_parse_wantheaders(arg, parser, "bodyProperties",
                                 &args->want_bodyheaders);
    }

    /* fetchTextBodyValues */
    else if (!strcmp(key, "fetchTextBodyValues") && json_is_boolean(arg)) {
        args->fetch_text_body = json_boolean_value(arg);
    }

    /* fetchHTMLBodyValues */
    else if (!strcmp(key, "fetchHTMLBodyValues") && json_is_boolean(arg)) {
        args->fetch_html_body = json_boolean_value(arg);
    }

    /* fetchAllBodyValues */
    else if (!strcmp(key, "fetchAllBodyValues") && json_is_boolean(arg)) {
        args->fetch_all_body = json_boolean_value(arg);
    }

    /* maxBodyValueBytes */
    else if (!strcmp(key, "maxBodyValueBytes") &&
             json_is_integer(arg) && json_integer_value(arg) > 0) {
        args->max_body_bytes = json_integer_value(arg);
    }

    else r = 0;

    return r;
}

struct cyrusmsg {
    msgrecord_t *mr;                 /* Message record for top-level message */
    const struct body *part0;        /* Root body-part */
    const struct body *rfc822part;   /* RFC 822 root part for embedded message */
    const struct buf *mime;          /* Raw MIME buffer */
    json_t *imagesize_by_partid;     /* FastMail-specific extension */

    message_t *_m;                   /* Message loaded from message record */
    struct body *_mybody;            /* Bodystructure */
    struct buf _mymime;              /* Raw MIME buffer */
    struct headers *_headers;        /* Parsed part0 headers. Don't free. */
    hash_table *_headers_by_part_id; /* Parsed subpart headers. Don't free. */
    ptrarray_t _headers_mempool;     /* Allocated headers memory */
};

static void _cyrusmsg_free(struct cyrusmsg **msgptr)
{
    if (msgptr == NULL || *msgptr == NULL) return;

    struct cyrusmsg *msg = *msgptr;
    if (msg->_mybody) {
        message_free_body(msg->_mybody);
        free(msg->_mybody);
    }
    buf_free(&msg->_mymime);
    json_decref(msg->imagesize_by_partid);
    if (msg->_headers_by_part_id) {
        free_hash_table(msg->_headers_by_part_id, NULL);
        free(msg->_headers_by_part_id);
    }
    struct headers *hdrs;
    while ((hdrs = ptrarray_pop(&msg->_headers_mempool))) {
        _headers_fini(hdrs);
        free(hdrs);
    }
    ptrarray_fini(&msg->_headers_mempool);
    free(*msgptr);
    *msgptr = NULL;
}

static int _cyrusmsg_from_record(msgrecord_t *mr, struct cyrusmsg **msgptr)
{
    struct cyrusmsg *msg = xzmalloc(sizeof(struct cyrusmsg));
    msg->mr = mr;
    *msgptr = msg;
    return 0;
}

static int _cyrusmsg_from_rfc822body(msgrecord_t *mr,
                                     const struct body *body,
                                     struct cyrusmsg **msgptr)
{
    struct cyrusmsg *msg = xzmalloc(sizeof(struct cyrusmsg));
    msg->mr = mr;
    msg->part0 = body;
    msg->rfc822part = body;
    *msgptr = msg;
    return 0;
}

static void _cyrusmsg_init_partids(struct body *body, const char *part_id)
{
    if (!body) return;

    if (!strcmp(body->type, "MULTIPART")) {
        struct buf buf = BUF_INITIALIZER;
        int i;
        for (i = 0; i < body->numparts; i++) {
            struct body *subpart = body->subpart + i;
            if (part_id) buf_printf(&buf, "%s.", part_id);
            buf_printf(&buf, "%d", i + 1);
            subpart->part_id = buf_release(&buf);
            _cyrusmsg_init_partids(subpart, subpart->part_id);
        }
        free(body->part_id);
        body->part_id = NULL;
    }
    else {
        struct buf buf = BUF_INITIALIZER;
        if (!body->part_id) {
            if (part_id) buf_printf(&buf, "%s.", part_id);
            buf_printf(&buf, "%d", 1);
            body->part_id = buf_release(&buf);
        }

        if (!strcmp(body->type, "MESSAGE") &&
            !strcmp(body->subtype, "RFC822")) {
            _cyrusmsg_init_partids(body->subpart, body->part_id);
        }
    }
}


static int _cyrusmsg_from_buf(const struct buf *buf, struct cyrusmsg **msgptr)
{
    /* No more return from here */
    struct body *mybody = xzmalloc(sizeof(struct body));
    struct protstream *pr = prot_readmap(buf_base(buf), buf_len(buf));

    /* Pre-run compliance check */
    int r = message_copy_strict(pr, /*to*/NULL, buf_len(buf), /*allow_null*/0);
    if (r) goto done;

    /* Parse message */
    r = message_parse_mapped(buf_base(buf), buf_len(buf), mybody, NULL);
    if (r || !mybody->subpart) {
        r = IMAP_MESSAGE_BADHEADER;
        goto done;
    }

    /* parse_mapped doesn't set part ids */
    _cyrusmsg_init_partids(mybody->subpart, NULL);

    struct cyrusmsg *msg = xzmalloc(sizeof(struct cyrusmsg));
    msg->_mybody = mybody;
    msg->part0 = mybody;
    msg->rfc822part = mybody;
    msg->mime = buf;
    *msgptr = msg;

done:
    if (pr) prot_free(pr);
    if (r && mybody) {
        message_free_body(mybody);
        free(mybody);
    }
    return r;
}

static int _cyrusmsg_need_msg(struct cyrusmsg *msg)
{
    if (msg->_m)
        return 0;
    if (!msg->mr)
        return IMAP_INTERNAL;

    int r = msgrecord_get_message(msg->mr, &msg->_m);
    if (r) return r;
    return 0;
}

static int _cyrusmsg_need_part0(struct cyrusmsg *msg)
{
    if (msg->part0)
        return 0;
    if (!msg->mr)
        return IMAP_INTERNAL;

    int r = msgrecord_extract_bodystructure(msg->mr, &msg->_mybody);
    if (r) return r;
    msg->part0 = msg->_mybody;
    return 0;
}

static int _cyrusmsg_need_mime(struct cyrusmsg *msg)
{
    if (msg->mime) return 0;
    if (msg->mr == NULL) {
        return IMAP_INTERNAL;
    }
    int r = msgrecord_get_body(msg->mr, &msg->_mymime);
    msg->mime = &msg->_mymime;
    if (r) return r;
    return 0;
}

static int _cyrusmsg_get_headers(struct cyrusmsg *msg,
                                 const struct body *part,
                                 struct headers **headersptr)
{

    if (part == NULL && msg->_headers) {
        *headersptr = msg->_headers;
        return 0;
    }
    else if (part && part->part_id) {
        if (msg->_headers_by_part_id) {
            *headersptr = hash_lookup(part->part_id, msg->_headers_by_part_id);
            if (*headersptr) return 0;
        }
        else {
            msg->_headers_by_part_id = xzmalloc(sizeof(hash_table));
            construct_hash_table(msg->_headers_by_part_id, 64, 0);
        }
    }

    /* Prefetch body structure */
    int r = _cyrusmsg_need_part0(msg);
    if (r) return r;

    /* Prefetch MIME message */
    r = _cyrusmsg_need_mime(msg);
    if (r) return r;
    const struct body *header_part = part ? part : msg->part0;

    struct headers *headers = xmalloc(sizeof(struct headers));
    _headers_init(headers);
    _headers_from_mime(msg->mime->s + header_part->header_offset,
                       header_part->header_size, headers);

    if (part && part->part_id)
        hash_insert(part->part_id, headers, msg->_headers_by_part_id);
    else if (part == NULL)
        msg->_headers = headers;
    ptrarray_append(&msg->_headers_mempool, headers);
    *headersptr = headers;
    return 0;
}

static json_t * _email_get_header(struct cyrusmsg *msg,
                                  const struct body *part,
                                  const char *lcasename,
                                  enum header_form want_form,
                                  int want_all)
{
    if (!part) {
        if (msg->rfc822part) {
            part = msg->rfc822part->subpart;
        }
        else {
            int r = _cyrusmsg_need_part0(msg);
            if (r) return json_null();
            part = msg->part0;
        }
    }

    /* Try to read the header from the parsed body part */
    if (part && !want_all && want_form != HEADER_FORM_RAW) {
        json_t *jval = NULL;
        if (!strcmp("messageId", lcasename)) {
            jval = want_form == HEADER_FORM_MESSAGEIDS ?
                jmap_header_as_messageids(part->message_id) : json_null();
        }
        else if (!strcmp("inReplyTo", lcasename)) {
            jval = want_form == HEADER_FORM_MESSAGEIDS ?
                jmap_header_as_messageids(part->in_reply_to) : json_null();
        }
        if (!strcmp("subject", lcasename)) {
            jval = want_form == HEADER_FORM_TEXT ?
                jmap_header_as_text(part->subject) : json_null();
        }
        if (!strcmp("from", lcasename)) {
            jval = want_form & (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES) ?
                jmap_emailaddresses_from_addr(part->from, want_form) : json_null();
        }
        else if (!strcmp("to", lcasename)) {
            jval = want_form & (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES) ?
                jmap_emailaddresses_from_addr(part->to, want_form) : json_null();
        }
        else if (!strcmp("cc", lcasename)) {
            jval = want_form & (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES) ?
                jmap_emailaddresses_from_addr(part->cc, want_form) : json_null();
        }
        else if (!strcmp("bcc", lcasename)) {
            jval = want_form & (HEADER_FORM_ADDRESSES|HEADER_FORM_GROUPEDADDRESSES) ?
                jmap_emailaddresses_from_addr(part->bcc, want_form) : json_null();
        }
        else if (!strcmp("sentAt", lcasename)) {
            jval = json_null();
            if (want_form == HEADER_FORM_DATE) {
                jval = jmap_header_as_date(part->date);
            }
        }
        if (jval) return jval;
    }

    /* Determine header form converter */
    json_t* (*conv)(const char *raw);
    switch (want_form) {
        case HEADER_FORM_TEXT:
            conv = jmap_header_as_text;
            break;
        case HEADER_FORM_DATE:
            conv = jmap_header_as_date;
            break;
        case HEADER_FORM_ADDRESSES:
            conv = jmap_header_as_addresses;
            break;
        case HEADER_FORM_GROUPEDADDRESSES:
            conv = jmap_header_as_groupedaddresses;
            break;
        case HEADER_FORM_MESSAGEIDS:
            conv = jmap_header_as_messageids;
            break;
        case HEADER_FORM_URLS:
            conv = jmap_header_as_urls;
            break;
        default:
            conv = jmap_header_as_raw;
    }

    /* Try to read the value from the index record or header cache */
    if (msg->mr && part == msg->part0 && !msg->rfc822part &&
            !want_all && want_form != HEADER_FORM_RAW) {
        struct buf buf = BUF_INITIALIZER;
        int r = _cyrusmsg_need_msg(msg);
        if (!r) r = message_get_field(msg->_m, lcasename, MESSAGE_RAW|MESSAGE_LAST, &buf);
        if (r) return json_null();
        json_t *jval = NULL;
        if (buf_len(&buf)) jval = conv(buf_cstring(&buf));
        buf_free(&buf);
        if (jval) return jval;
    }

    /* Read the raw MIME headers */
    struct headers *partheaders = NULL;
    int r = _cyrusmsg_get_headers(msg, part, &partheaders);
    if (r) return json_null();

    /* Lookup array of EmailHeader objects by name */
    json_t *jheaders = json_object_get(partheaders->all, lcasename);
    if (!jheaders || !json_array_size(jheaders)) {
        return want_all ? json_array() : json_null();
    }

    /* Convert header values */
    if (want_all) {
        json_t *allvals = json_array();
        size_t i;
        for (i = 0; i < json_array_size(jheaders); i++) {
            json_t *jheader = json_array_get(jheaders, i);
            json_t *jheaderval = json_object_get(jheader, "value");
            json_array_append_new(allvals, conv(json_string_value(jheaderval)));
        }
        return allvals;
    }

    json_t *jheader = json_array_get(jheaders, json_array_size(jheaders) - 1);
    json_t *jheaderval = json_object_get(jheader, "value");
    return conv(json_string_value(jheaderval));
}

static const struct blob_header_t {
    const char *name;
    const char *type;
} blob_headers[] = {
    { "bimi-indicator", "image/svg+xml" },
    { NULL, NULL }
};

static const char *_encode_emailheader_blobid(const char *emailid,
                                              const char *hdr,
                                              struct buf *dst)
{
    /* Get the index of the header */
    unsigned n = 0;
    while (blob_headers[n].name && strcasecmp(blob_headers[n].name, hdr)) n++;

    /* Smart blob prefix, emailid, hdrname index */
    buf_reset(dst);
    if (blob_headers[n].name) buf_printf(dst, "H%s-%u", emailid, n);

    return buf_cstring(dst);
}

static int _email_get_meta(jmap_req_t *req,
                           struct email_getargs *args,
                           struct cyrusmsg *msg,
                           json_t *email)
{
    int r = 0;
    hash_table *props = args->props;
    char email_id[JMAP_EMAILID_SIZE];

    if (msg->rfc822part) {
        if (jmap_wantprop(props, "id")) {
            json_object_set_new(email, "id", json_null());
        }
        if (jmap_wantprop(props, "blobId")) {
            char blob_id[JMAP_BLOBID_SIZE];
            jmap_set_blobid(&msg->rfc822part->content_guid, blob_id);
            json_object_set_new(email, "blobId", json_string(blob_id));
        }
        if (jmap_wantprop(props, "threadId"))
            json_object_set_new(email, "threadId", json_null());
        if (jmap_wantprop(props, "mailboxIds"))
            json_object_set_new(email, "mailboxIds", json_null());
        if (jmap_wantprop(props, "keywords"))
            json_object_set_new(email, "keywords", json_object());
        if (jmap_wantprop(props, "size")) {
            size_t size = msg->rfc822part->header_size + msg->rfc822part->content_size;
            json_object_set_new(email, "size", json_integer(size));
        }
        if (jmap_wantprop(props, "receivedAt"))
            json_object_set_new(email, "receivedAt", json_null());
        return 0;
    }

    /* This is a top-level messages with a regular index record. */

    /* Determine message id */
    struct message_guid guid;
    r = msgrecord_get_guid(msg->mr, &guid);
    if (r) goto done;

    jmap_set_emailid(&guid, email_id);

    /* id */
    if (jmap_wantprop(props, "id")) {
        json_object_set_new(email, "id", json_string(email_id));
    }

    /* blobId */
    if (jmap_wantprop(props, "blobId")) {
        char blob_id[JMAP_BLOBID_SIZE];
        jmap_set_blobid(&guid, blob_id);
        json_object_set_new(email, "blobId", json_string(blob_id));
    }

    /* threadid */
    if (jmap_wantprop(props, "threadId")) {
        bit64 cid;
        r = msgrecord_get_cid(msg->mr, &cid);
        if (r) goto done;
        char thread_id[JMAP_THREADID_SIZE];
        jmap_set_threadid(cid, thread_id);
        json_object_set_new(email, "threadId", json_string(thread_id));
    }

    /* mailboxIds */
    if (jmap_wantprop(props, "mailboxIds") ||
        jmap_wantprop(props, "addedDates") || jmap_wantprop(props, "removedDates")) {
        json_t *mboxids =
            jmap_wantprop(props, "mailboxIds") ? json_object() : NULL;
        json_t *added =
            jmap_wantprop(props, "addedDates") ? json_object() : NULL;
        json_t *removed =
            jmap_wantprop(props, "removedDates") ? json_object() : NULL;
        json_t *mailboxes = _email_mailboxes(req, email_id);

        json_t *val;
        const char *mboxid;
        json_object_foreach(mailboxes, mboxid, val) {
            json_t *exists = json_object_get(val, "added");

            if (exists) {
                if (mboxids) json_object_set_new(mboxids, mboxid, json_true());
                if (added) json_object_set(added, mboxid, exists);
            }
            else if (removed) {
                json_object_set(removed, mboxid, json_object_get(val, "removed"));
            }
        }
        json_decref(mailboxes);
        if (mboxids) json_object_set_new(email, "mailboxIds", mboxids);
        if (removed) json_object_set_new(email, "removedDates", removed);
        if (added) json_object_set_new(email, "addedDates", added);
    }

    /* keywords */
    if (jmap_wantprop(props, "keywords")) {
        json_t *keywords = NULL;
        r = _email_get_keywords(req, &args->ctx, email_id, &keywords);
        if (r) goto done;
        json_object_set_new(email, "keywords", keywords);
    }

    /* size */
    if (jmap_wantprop(props, "size")) {
        uint32_t size;
        r = msgrecord_get_size(msg->mr, &size);
        if (r) goto done;
        json_object_set_new(email, "size", json_integer(size));
    }

    /* receivedAt */
    if (jmap_wantprop(props, "receivedAt")) {
        char datestr[RFC3339_DATETIME_MAX];
        time_t t;
        r = msgrecord_get_internaldate(msg->mr, &t);
        if (r) goto done;
        time_to_rfc3339(t, datestr, RFC3339_DATETIME_MAX);
        json_object_set_new(email, "receivedAt", json_string(datestr));
    }

    /* FastMail-extension properties */
    if (jmap_wantprop(props, "trustedSender")) {
        json_t *trusted_sender = NULL;
        int has_trusted_flag = 0;
        r = msgrecord_hasflag(msg->mr, "$IsTrusted", &has_trusted_flag);
        if (r) goto done;
        if (has_trusted_flag) {
            struct buf buf = BUF_INITIALIZER;
            _email_read_annot(req, msg->mr, "/vendor/messagingengine.com/trusted", &buf);
            if (buf_len(&buf)) {
                trusted_sender = json_string(buf_cstring(&buf));
            }
            buf_free(&buf);
        }
        json_object_set_new(email, "trustedSender", trusted_sender ?
                trusted_sender : json_null());
    }

    if (jmap_wantprop(props, "spamScore")) {
        int r = 0;
        struct buf buf = BUF_INITIALIZER;
        json_t *jval = json_null();
        r = _cyrusmsg_need_msg(msg);
        if (!r) r = message_get_field(msg->_m, "x-spam-score", MESSAGE_RAW, &buf);
        if (!r && buf_len(&buf)) jval = json_real(atof(buf_cstring(&buf)));
        json_object_set_new(email, "spamScore", jval);
        buf_free(&buf);
    }

    if (jmap_wantprop(props, "snoozed")) {
        struct email_get_snoozed_rock rock = { req, NULL };

        /* Look for the first snoozed copy of this email_id */
        conversations_guid_foreach(req->cstate, _guid_from_id(email_id),
                                   _email_get_snoozed_cb, &rock);

        json_object_set_new(email, "snoozed",
                            rock.snoozed ? rock.snoozed : json_null());
    }

    if (jmap_wantprop(props, "bimiBlobId")) {
        int r = 0;
        const char *hdrname = "bimi-indicator";
        struct buf buf = BUF_INITIALIZER;
        json_t *jval = json_null();

        r = _cyrusmsg_need_msg(msg);
        if (!r) r = message_get_field(msg->_m, hdrname, MESSAGE_RAW, &buf);
        if (!r && buf_len(&buf)) {
            const char *blobid =
                _encode_emailheader_blobid(email_id, hdrname, &buf);
            if (*blobid) jval = json_string(blobid);
        }
        json_object_set_new(email, "bimiBlobId", jval);
        buf_free(&buf);
    }

done:
    return r;
}

static int _email_get_headers(jmap_req_t *req __attribute__((unused)),
                              struct email_getargs *args,
                              struct cyrusmsg *msg,
                              json_t *email)
{
    int r = 0;
    hash_table *props = args->props;

    if (jmap_wantprop(props, "headers") || args->want_headers.count) {
        /* headers */
        if (jmap_wantprop(props, "headers")) {
            struct headers *headers = NULL;
            r = _cyrusmsg_get_headers(msg, NULL, &headers);
            if (r) return r;
            json_object_set(email, "headers", headers->raw); /* incref! */
        }
        /* headers:Xxx */
        if (ptrarray_size(&args->want_headers)) {
            int i;
            for (i = 0; i < ptrarray_size(&args->want_headers); i++) {
                struct header_prop *want_header = ptrarray_nth(&args->want_headers, i);
                json_t *jheader = _email_get_header(msg, NULL, want_header->lcasename,
                                      want_header->form, want_header->all);
                json_object_set_new(email, want_header->prop, jheader);
            }
        }
    }

    /* references */
    if (jmap_wantprop(props, "references")) {
        json_t *references = _email_get_header(msg, NULL, "references",
                                               HEADER_FORM_MESSAGEIDS,/*all*/0);
        json_object_set_new(email, "references", references);
    }
    /* sender */
    if (jmap_wantprop(props, "sender")) {
        json_t *sender = _email_get_header(msg, NULL, "sender",
                                           HEADER_FORM_ADDRESSES,/*all*/0);
        json_object_set_new(email, "sender", sender);
    }
    /* replyTo */
    if (jmap_wantprop(props, "replyTo")) {
        json_t *replyTo = _email_get_header(msg, NULL, "reply-to",
                                            HEADER_FORM_ADDRESSES, /*all*/0);
        json_object_set_new(email, "replyTo", replyTo);
    }

    /* The following fields are all read from the body-part structure */
    const struct body *part = NULL;
    if (jmap_wantprop(props, "messageId") ||
        jmap_wantprop(props, "inReplyTo") ||
        jmap_wantprop(props, "from") ||
        jmap_wantprop(props, "to") ||
        jmap_wantprop(props, "cc") ||
        jmap_wantprop(props, "bcc") ||
        jmap_wantprop(props, "subject") ||
        jmap_wantprop(props, "sentAt")) {
        if (msg->rfc822part) {
            part = msg->rfc822part->subpart;
        }
        else {
            r = _cyrusmsg_need_part0(msg);
            if (r) return r;
            part = msg->part0;
        }
    }
    /* messageId */
    if (jmap_wantprop(props, "messageId")) {
        json_object_set_new(email, "messageId",
                jmap_header_as_messageids(part->message_id));
    }
    /* inReplyTo */
    if (jmap_wantprop(props, "inReplyTo")) {
        json_object_set_new(email, "inReplyTo",
                jmap_header_as_messageids(part->in_reply_to));
    }
    /* from */
    if (jmap_wantprop(props, "from")) {
        json_object_set_new(email, "from",
                jmap_emailaddresses_from_addr(part->from, HEADER_FORM_ADDRESSES));
    }
    /* to */
    if (jmap_wantprop(props, "to")) {
        json_object_set_new(email, "to",
                jmap_emailaddresses_from_addr(part->to, HEADER_FORM_ADDRESSES));
    }
    /* cc */
    if (jmap_wantprop(props, "cc")) {
        json_object_set_new(email, "cc",
                jmap_emailaddresses_from_addr(part->cc, HEADER_FORM_ADDRESSES));
    }
    /* bcc */
    if (jmap_wantprop(props, "bcc")) {
        json_object_set_new(email, "bcc",
                jmap_emailaddresses_from_addr(part->bcc, HEADER_FORM_ADDRESSES));
    }
    /* subject */
    if (jmap_wantprop(props, "subject")) {
        json_object_set_new(email, "subject",
                jmap_header_as_text(part->subject));
    }
    /* sentAt */
    if (jmap_wantprop(props, "sentAt")) {
        json_object_set_new(email, "sentAt",
                            jmap_header_as_date(part->date));
    }

    return r;
}


static void emailbodypart_read_name(struct buf *buf, const struct body *part)
{
    const char *fname = NULL;
    int is_extended = 0;

    /* Lookup name parameter. Disposition header has precedence */
    const struct param *param;
    for (param = part->disposition_params; param; param = param->next) {
        if (!strncasecmp(param->attribute, "filename", 8)) {
            is_extended = param->attribute[8] == '*';
            fname = param->value;
            break;
        }
    }
    /* Lookup Content-Type parameters */
    if (!fname) {
        for (param = part->params; param; param = param->next) {
            if (!strncasecmp(param->attribute, "name", 4)) {
                is_extended = param->attribute[4] == '*';
                fname = param->value;
                break;
            }
        }
    }

    /* Decode header value */
    char *val = NULL;
    if (fname && is_extended) {
        val = charset_parse_mimexvalue(fname, NULL);
    }
    if (fname && !val) {
        val = charset_parse_mimeheader(fname, CHARSET_KEEPCASE|CHARSET_MIME_UTF8);
    }
    if (val) {
        buf_setcstr(buf, val);
        buf_cstring(buf);
    }
    free(val);
}

static json_t *_email_get_bodypart(jmap_req_t *req,
                                   struct email_getargs *args,
                                   struct cyrusmsg *msg,
                                   const struct body *part)
{
    struct buf buf = BUF_INITIALIZER;

    hash_table *bodyprops = args->bodyprops;
    ptrarray_t *want_bodyheaders = &args->want_bodyheaders;

    json_t *jbodypart = json_object();

    /* partId */
    if (jmap_wantprop(bodyprops, "partId")) {
        json_t *jpart_id = json_null();
        if (strcasecmp(part->type, "MULTIPART"))
            jpart_id = json_string(part->part_id);
        json_object_set_new(jbodypart, "partId", jpart_id);
    }

    /* blobId */
    if (jmap_wantprop(bodyprops, "blobId")) {
        json_t *jblob_id = json_null();
        if (!message_guid_isnull(&part->content_guid)) {
            char blob_id[JMAP_BLOBID_SIZE];
            jmap_set_blobid(&part->content_guid, blob_id);
            jblob_id = json_string(blob_id);
        }
        json_object_set_new(jbodypart, "blobId", jblob_id);
    }

    /* size */
    if (jmap_wantprop(bodyprops, "size")) {
        size_t size = 0;
        if (part->numparts && strcasecmp(part->type, "MESSAGE")) {
            /* Multipart */
            size = 0;
        }
        else if (part->charset_enc & 0xff) {
            if (part->decoded_content_size == 0) {
                char *tmp = NULL;
                size_t tmp_size;
                int r = _cyrusmsg_need_mime(msg);
                if (!r)  {
                    charset_decode_mimebody(msg->mime->s + part->content_offset,
                            part->content_size, part->charset_enc, &tmp, &tmp_size);
                    size = tmp_size;
                    free(tmp);
                }
            }
            else {
                size = part->decoded_content_size;
            }
        }
        else {
            size = part->content_size;
        }
        json_object_set_new(jbodypart, "size", json_integer(size));
    }

    /* headers */
    if (jmap_wantprop(bodyprops, "headers") || want_bodyheaders->count) {
        /* headers */
        if (jmap_wantprop(bodyprops, "headers")) {
            struct headers *headers = NULL;
            int r = _cyrusmsg_get_headers(msg, part, &headers);
            if (!r) {
                json_object_set(jbodypart, "headers", headers->raw); /* incref! */
            }
            else {
                json_object_set(jbodypart, "headers", json_null());
            }
        }
        /* headers:Xxx */
        if (ptrarray_size(want_bodyheaders)) {
            int i;
            for (i = 0; i < ptrarray_size(want_bodyheaders); i++) {
                struct header_prop *want_header = ptrarray_nth(want_bodyheaders, i);
                json_t *jheader = _email_get_header(msg, part, want_header->lcasename,
                                                    want_header->form, want_header->all);
                json_object_set_new(jbodypart, want_header->prop, jheader);
            }
        }
    }

    /* name */
    if (jmap_wantprop(bodyprops, "name")) {
        emailbodypart_read_name(&buf, part);
        json_object_set_new(jbodypart, "name", buf_len(&buf) ?
                json_string(buf_cstring(&buf)) : json_null());
        buf_reset(&buf);
    }

    /* type */
    if (jmap_wantprop(bodyprops, "type")) {
        buf_setcstr(&buf, part->type);
        if (part->subtype) {
            buf_appendcstr(&buf, "/");
            buf_appendcstr(&buf, part->subtype);
        }
        json_object_set_new(jbodypart, "type", json_string(buf_lcase(&buf)));
    }

    /* charset */
    if (jmap_wantprop(bodyprops, "charset")) {
        json_t *jcharset = json_null();

        if (msg->mr) {
            int cache_version = 0;
            msgrecord_get_cache_version(msg->mr, &cache_version);
            if (cache_version >= 10) {
                /* Read charset from bodystructure */
                if (part->charset_id) {
                    jcharset = json_string(part->charset_id);
                }
            }
        }
        if (json_is_null(jcharset)) {
            /* Read charset from header */
            json_t *jrawheader = _email_get_header(msg, part, "content-type",
                                                   HEADER_FORM_RAW, /*all*/0);
            if (JNOTNULL(jrawheader)) {
                const char *hdr = json_string_value(jrawheader);
                char *type = NULL;
                char *subtype = NULL;
                struct param *param = NULL;
                charset_t cs = CHARSET_UNKNOWN_CHARSET;

                message_parse_type(hdr, &type, &subtype, &param);
                if (param)
                    message_parse_charset_params(param, &cs);
                if (cs != CHARSET_UNKNOWN_CHARSET)
                    jcharset = json_string(charset_alias_name(cs));

                charset_free(&cs);
                json_decref(jrawheader);
                param_free(&param);
                free(type);
                free(subtype);
            }
        }
        if (json_is_null(jcharset) && !strcasecmp(part->type, "TEXT")) {
            /* Use default text charset */
            jcharset = json_string("us-ascii");
        }
        json_object_set_new(jbodypart, "charset", jcharset);
    }

    /* disposition */
    if (jmap_wantprop(bodyprops, "disposition")) {
        json_t *jdisp = json_null();
        if (part->disposition) {
            char *disp = lcase(xstrdup(part->disposition));
            jdisp = json_string(disp);
            free(disp);
        }
        json_object_set_new(jbodypart, "disposition", jdisp);
    }


    /* cid */
    if (jmap_wantprop(bodyprops, "cid")) {
        json_t *jcid = _email_get_header(msg, part, "content-id",
                                         HEADER_FORM_MESSAGEIDS, /*all*/0);
        json_object_set(jbodypart, "cid", json_array_size(jcid) ?
                json_array_get(jcid, 0) : json_null());
        json_decref(jcid);
    }


    /* language */
    if (jmap_wantprop(bodyprops, "language")) {
        json_t *jlanguage = json_null();
        json_t *jrawheader = _email_get_header(msg, part, "content-language",
                                               HEADER_FORM_RAW, /*all*/0);
        if (JNOTNULL(jrawheader)) {
            /* Split by space and comma and aggregate into array */
            const char *s = json_string_value(jrawheader);
            jlanguage = json_array();
            int i;
            char *tmp = charset_unfold(s, strlen(s), 0);
            strarray_t *ls = strarray_split(tmp, "\t ,", STRARRAY_TRIM);
            for (i = 0; i < ls->count; i++) {
                json_array_append_new(jlanguage, json_string(strarray_nth(ls, i)));
            }
            strarray_free(ls);
            free(tmp);
        }
        if (!json_array_size(jlanguage)) {
            json_decref(jlanguage);
            jlanguage = json_null();
        }
        json_object_set_new(jbodypart, "language", jlanguage);
        json_decref(jrawheader);
    }


    /* location */
    if (jmap_wantprop(bodyprops, "location")) {
        json_object_set_new(jbodypart, "location", part->location ?
                json_string(part->location) : json_null());
    }

    /* subParts */
    if (!strcmp(part->type, "MULTIPART")) {
        json_t *subparts = json_array();
        int i;
        for (i = 0; i < part->numparts; i++) {
            struct body *subpart = part->subpart + i;
            json_array_append_new(subparts,
                    _email_get_bodypart(req, args, msg, subpart));

        }
        json_object_set_new(jbodypart, "subParts", subparts);
    }
    else if (jmap_wantprop(bodyprops, "subParts")) {
        json_object_set_new(jbodypart, "subParts", json_array());
    }


    /* FastMail extension properties */
    if (jmap_wantprop(bodyprops, "imageSize")) {
        json_t *imagesize = json_null();
        if (msg->mr && msg->imagesize_by_partid == NULL) {
            /* This is the first attempt to read the vendor annotation.
             * Load the annotation value, if any, for top-level messages.
             * Use JSON null for an unsuccessful attempt, so we know not
             * to try again. */
            msg->imagesize_by_partid = _email_read_jannot(req, msg->mr,
                    "/vendor/messagingengine.com/imagesize", 1);
            if (!msg->imagesize_by_partid)
                msg->imagesize_by_partid = json_null();
        }
        imagesize = json_object_get(msg->imagesize_by_partid, part->part_id);
        json_object_set(jbodypart, "imageSize", imagesize ? imagesize : json_null());
    }
    if (jmap_wantprop(bodyprops, "isDeleted")) {
        json_object_set_new(jbodypart, "isDeleted",
                json_boolean(!strcmp(part->type, "TEXT") &&
                             !strcmp(part->subtype, "X-ME-REMOVED-FILE")));
    }

    buf_free(&buf);
    return jbodypart;
}

static json_t * _email_get_bodyvalue(struct body *part,
                                     const struct buf *msg_buf,
                                     size_t max_body_bytes,
                                     int is_html)
{
    json_t *jbodyvalue = NULL;
    int is_encoding_problem = 0;
    int is_truncated = 0;
    struct buf buf = BUF_INITIALIZER;

    /* Decode into UTF-8 buffer */
    char *raw = _decode_to_utf8(part->charset_id,
            msg_buf->s + part->content_offset,
            part->content_size, part->encoding,
            &is_encoding_problem);
    if (!raw) goto done;

    /* In-place remove CR characters from buffer */
    size_t i, j, rawlen = strlen(raw);
    for (i = 0, j = 0; j < rawlen; j++) {
        if (raw[j] != '\r') raw[i++] = raw[j];
    }
    raw[i] = '\0';

    /* Initialize return value */
    buf_appendcstr(&buf, raw);
    free(raw);

    /* Truncate buffer */
    if (buf_len(&buf) && max_body_bytes && max_body_bytes < buf_len(&buf)) {
        /* Cut of excess bytes */
        buf_truncate(&buf, max_body_bytes);
        is_truncated = 1;
        /* Clip to sane UTF-8 */
        /* XXX do not split between combining characters */
        const unsigned char *base = (unsigned char *) buf_base(&buf);
        const unsigned char *top = base + buf_len(&buf);
        const unsigned char *p = top - 1;
        while (p >= base && ((*p & 0xc0) == 0x80))
            p--;
        if (p >= base) {
            ssize_t have_bytes = top - p;
            ssize_t need_bytes = 0;
            unsigned char hi_nibble = *p & 0xf0;
            switch (hi_nibble) {
                case 0xf0:
                    need_bytes = 4;
                    break;
                case 0xe0:
                    need_bytes = 3;
                    break;
                case 0xc0:
                    need_bytes = 2;
                    break;
                default:
                    need_bytes = 1;
            }
            if (have_bytes < need_bytes)
                buf_truncate(&buf, p - base);
        }
        else {
            buf_reset(&buf);
        }
    }

    /* Truncate HTML */
    if (buf_len(&buf) && max_body_bytes && is_html) {
        /* Truncate any trailing '<' start tag character without closing '>' */
        const char *base = buf_base(&buf);
        const char *top  = base + buf_len(&buf);
        const char *p;
        for (p = top - 1; *p != '>' && p >= base; p--) {
            if (*p == '<') {
                buf_truncate(&buf, p - base + 1);
                is_truncated = 1;
                break;
            }
        }
    }

done:
    jbodyvalue = json_pack("{s:s s:b s:b}",
            "value", buf_cstring(&buf),
            "isEncodingProblem", is_encoding_problem,
            "isTruncated", is_truncated);
    buf_free(&buf);
    return jbodyvalue;
}

static int _email_get_bodies(jmap_req_t *req,
                             struct email_getargs *args,
                             struct cyrusmsg *msg,
                             json_t *email)
{
    struct emailbodies bodies = EMAILBODIES_INITIALIZER;
    hash_table *props = args->props;
    int r = 0;

    const struct body *part;
    if (msg->rfc822part) {
        part = msg->rfc822part->subpart;
    }
    else {
        r = _cyrusmsg_need_part0(msg);
        if (r) return r;
        part =  msg->part0;
    }

    /* Load image sizes by bodypart, if required. */
    if (jmap_wantprop(args->props, "hasAttachment") ||
                jmap_wantprop(args->bodyprops, "imageSize")) {
        if (msg->mr && msg->imagesize_by_partid == NULL) {
            msg->imagesize_by_partid = _email_read_jannot(req, msg->mr,
                    "/vendor/messagingengine.com/imagesize", 1);
            if (!msg->imagesize_by_partid)
                msg->imagesize_by_partid = json_null();
        }
    }

    /* Dissect message into its parts */
    r = jmap_emailbodies_extract(part, &bodies);
    if (r) goto done;

    /* bodyStructure */
    if (jmap_wantprop(props, "bodyStructure")) {
        json_object_set_new(email, "bodyStructure",
                _email_get_bodypart(req, args, msg, part));
    }

    /* bodyValues */
    if (jmap_wantprop(props, "bodyValues")) {
        json_t *body_values = json_object();
        /* Determine which body value parts to fetch */
        int i;
        ptrarray_t parts = PTRARRAY_INITIALIZER;
        if (args->fetch_text_body || args->fetch_all_body) {
            for (i = 0; i < bodies.textlist.count; i++)
                ptrarray_append(&parts, ptrarray_nth(&bodies.textlist, i));
        }
        if (args->fetch_html_body || args->fetch_all_body) {
            for (i = 0; i < bodies.htmllist.count; i++)
                ptrarray_append(&parts, ptrarray_nth(&bodies.htmllist, i));
        }
        if (args->fetch_all_body) {
            for (i = 0; i < bodies.attslist.count; i++) {
                struct body *part = ptrarray_nth(&bodies.attslist, i);
                if (!strcmpsafe(part->type, "TEXT")) {
                    /* we weed out duplicate parts later */
                    ptrarray_append(&parts, ptrarray_nth(&bodies.attslist, i));
                }
            }
        }
        if (parts.count) {
            r = _cyrusmsg_need_mime(msg);
            if (r) goto done;
        }
        /* Fetch body values */
        for (i = 0; i < parts.count; i++) {
            struct body *part = ptrarray_nth(&parts, i);
            if (strcmp("TEXT", part->type)) {
                continue;
            }
            /* Ignore duplicate list entries */
            if (part->part_id && json_object_get(body_values, part->part_id)) {
                continue;
            }
            json_object_set_new(body_values, part->part_id,
                    _email_get_bodyvalue(part, msg->mime, args->max_body_bytes,
                                         !strcmp("HTML", part->subtype)));
        }
        ptrarray_fini(&parts);
        json_object_set_new(email, "bodyValues", body_values);
    }

    /* textBody */
    if (jmap_wantprop(props, "textBody")) {
        json_t *text_body = json_array();
        int i;
        for (i = 0; i < bodies.textlist.count; i++) {
            struct body *part = ptrarray_nth(&bodies.textlist, i);
            json_array_append_new(text_body,
                    _email_get_bodypart(req, args, msg, part));
        }
        json_object_set_new(email, "textBody", text_body);
    }

    /* htmlBody */
    if (jmap_wantprop(props, "htmlBody")) {
        json_t *html_body = json_array();
        int i;
        for (i = 0; i < bodies.htmllist.count; i++) {
            struct body *part = ptrarray_nth(&bodies.htmllist, i);
            json_array_append_new(html_body,
                    _email_get_bodypart(req, args, msg, part));
        }
        json_object_set_new(email, "htmlBody", html_body);
    }

    /* attachments */
    if (jmap_wantprop(props, "attachments")) {
        json_t *attachments = json_array();
        int i;
        for (i = 0; i < bodies.attslist.count; i++) {
            struct body *part = ptrarray_nth(&bodies.attslist, i);
            json_array_append_new(attachments,
                    _email_get_bodypart(req, args, msg, part));
        }
        json_object_set_new(email, "attachments", attachments);
    }

    /* calendarEvents -- non-standard */
    if (jmap_wantprop(props, "calendarEvents")) {
        hash_table icsbody_by_partid = HASH_TABLE_INITIALIZER;
        // Some MUAs send the same iTIP message both as a text/calendar
        // and as a base64-encoded application/ics body. Deduplicate these.
        struct hashset *icsguids = hashset_new(sizeof(struct message_guid));

        int i;
        for (i = 0; i < bodies.attslist.count; i++) {
            struct body *part = ptrarray_nth(&bodies.attslist, i);
            int is_icsbody = 0;

            /* Process calendar attachments and files ending with .ics */
            if ((!strcmp(part->type, "TEXT") && !strcmp(part->subtype, "CALENDAR")) ||
                (!strcmp(part->type, "APPLICATION") && !strcmp(part->subtype, "ICS"))) {
                is_icsbody = 1;
            }
            else {
                struct buf buf = BUF_INITIALIZER;
                emailbodypart_read_name(&buf, part);
                if (buf_len(&buf) > 4 &&
                        !strcasecmp(buf_cstring(&buf) + buf_len(&buf)-4, ".ICS")) {
                    is_icsbody = 1;
                }
                buf_free(&buf);
            }

            if (is_icsbody && hashset_add(icsguids, &part->content_guid)) {
                if (!icsbody_by_partid.size) {
                    construct_hash_table(&icsbody_by_partid, 32, 0);
                }
                hash_insert(part->part_id, part, &icsbody_by_partid);
            }
        }

        json_t *events = json_null();
        if (hash_numrecords(&icsbody_by_partid)) {
            r = _cyrusmsg_need_mime(msg);
            if (r) goto done;
            struct mailbox *mbox = NULL;
            uint32_t uid = 0;
            if (msg->mr) {
                msgrecord_get_mailbox(msg->mr, &mbox);
                msgrecord_get_uid(msg->mr, &uid);
            }
            events = jmap_calendar_events_from_msg(req,
                    mbox ? mailbox_uniqueid(mbox) : NULL, uid,
                    &icsbody_by_partid, msg->mime);
        }
        json_object_set_new(email, "calendarEvents", events);

        if (icsbody_by_partid.size) free_hash_table(&icsbody_by_partid, NULL);
        hashset_free(&icsguids);
    }

    /* previousCalendarEvent -- non-standard */
    if (jmap_wantprop(props, "previousCalendarEvent")) {
        json_t *event = json_null();
        struct buf buf = BUF_INITIALIZER;
        // cost is "load message body", so fetch with bodies
        r = _cyrusmsg_need_msg(msg);
        if (r) goto done;
        message_get_field(msg->_m, "X-ME-Cal-Previous", MESSAGE_RAW, &buf);
        if (buf_len(&buf)) {
           char *data = NULL;
           size_t datalen = 0;
            charset_decode_mimebody(buf_base(&buf), buf_len(&buf), ENCODING_BASE64, &data, &datalen);
           if (data) {
                json_error_t jerr;
                event = json_loadb(data, datalen, JSON_DECODE_ANY, &jerr);
            }
            free(data);
        }
        if (event) {
            buf_reset(&buf);
            // extract the UID from the header too
            message_get_field(msg->_m, "X-ME-Cal-UID", MESSAGE_DECODED|MESSAGE_TRIM, &buf);
            json_object_set_new(event, "uid", json_stringn(buf_base(&buf), buf_len(&buf)));
        }
        buf_free(&buf);
        json_object_set_new(email, "previousCalendarEvent", event);
    }

    /* hasAttachment */
    if (jmap_wantprop(props, "hasAttachment")) {
        static int check_annotations = -1;
        if (check_annotations < 0) {
            const char *rawflags = config_getstring(IMAPOPT_MAILBOX_INITIAL_FLAGS);
            if (rawflags) {
                strarray_t *flags = strarray_split(rawflags, NULL, 0);
                if (flags &&
                        strarray_find_case(flags, JMAP_HAS_ATTACHMENT_FLAG, 0) >= 0) {
                    check_annotations = 1;
                }
            }
            if (check_annotations < 0) {
                check_annotations = 0;
            }
        }
        int has_att = 0;
        if (!msg->rfc822part && check_annotations) {
            msgrecord_hasflag(msg->mr, JMAP_HAS_ATTACHMENT_FLAG, &has_att);
        }
        else has_att = jmap_email_hasattachment(part, msg->imagesize_by_partid);

        json_object_set_new(email, "hasAttachment", json_boolean(has_att));
    }

    /* preview */
    if (jmap_wantprop(props, "preview")) {
        const char *preview_annot = config_getstring(IMAPOPT_JMAP_PREVIEW_ANNOT);
        if (preview_annot && msg->rfc822part == NULL) {
            json_t *preview = _email_read_jannot(req, msg->mr, preview_annot, /*structured*/0);
            json_object_set_new(email, "preview", preview ? preview : json_string(""));
        }
        else {
            r = _cyrusmsg_need_mime(msg);
            if (r) goto done;
            /* TODO optimise for up to PREVIEW_LEN bytes */
            char *text = _emailbodies_to_plain(&bodies, msg->mime);
            if (!text) {
                char *html = _emailbodies_to_html(&bodies, msg->mime);
                if (html) text = _html_to_plain(html);
                free(html);
            }
            if (text) {
                size_t len = config_getint(IMAPOPT_JMAP_PREVIEW_LENGTH);
                char *preview = _email_extract_preview(text, len);
                json_object_set_new(email, "preview", json_string(preview));
                free(preview);
                free(text);
            }
        }
    }

done:
    jmap_emailbodies_fini(&bodies);
    return r;
}

static int _email_from_msg(jmap_req_t *req,
                           struct email_getargs *args,
                           struct cyrusmsg *msg,
                           json_t **emailptr)
{
    json_t *email = json_object();
    int r = 0;

    r = _email_get_meta(req, args, msg, email);
    if (r) goto done;

    r = _email_get_headers(req, args, msg, email);
    if (r) goto done;

    r = _email_get_bodies(req, args, msg, email);
    if (r) goto done;

    *emailptr = email;
done:

    if (r) json_decref(email);
    return r;
}


static int _email_from_record(jmap_req_t *req,
                              struct email_getargs *args,
                              msgrecord_t *mr,
                              json_t **emailptr)
{
    struct cyrusmsg *msg = NULL;
    int r = _cyrusmsg_from_record(mr, &msg);
    if (!r) r = _email_from_msg(req, args, msg, emailptr);
    _cyrusmsg_free(&msg);
    return r;
}

static int _email_from_rfc822body(jmap_req_t *req,
                                  struct email_getargs *args,
                                  msgrecord_t *mr,
                                  const struct body *body,
                                  json_t **emailptr)
{
    struct cyrusmsg *msg = NULL;
    int r = _cyrusmsg_from_rfc822body(mr, body, &msg);
    if (!r) r = _email_from_msg(req, args, msg, emailptr);
    _cyrusmsg_free(&msg);
    return r;
}

static int _email_from_buf(jmap_req_t *req,
                           struct email_getargs *args,
                           const struct buf *buf,
                           const char *encoding,
                           json_t **emailptr)
{
    struct buf mybuf = BUF_INITIALIZER;
    buf_setcstr(&mybuf, "Content-Type: message/rfc822\r\n");
    if (encoding) {
        if (!strcasecmp(encoding, "BASE64")) {
            char *tmp = NULL;
            size_t tmp_size = 0;
            charset_decode_mimebody(buf_base(buf), buf_len(buf),
                    ENCODING_BASE64, &tmp, &tmp_size);
            buf_appendcstr(&mybuf, "Content-Transfer-Encoding: binary\r\n");
            /* Append base64-decoded body */
            buf_appendcstr(&mybuf, "\r\n");
            buf_appendmap(&mybuf, tmp, tmp_size);
            free(tmp);
        }
        else {
            buf_appendcstr(&mybuf, "Content-Transfer-Encoding: ");
            buf_appendcstr(&mybuf, encoding);
            buf_appendcstr(&mybuf, "\r\n");
            /* Append encoded body */
            buf_appendcstr(&mybuf, "\r\n");
            buf_append(&mybuf, buf);
        }
    }
    else {
        /* Append raw body */
        buf_appendcstr(&mybuf, "\r\n");
        buf_append(&mybuf, buf);
    }

    struct cyrusmsg *msg = NULL;
    int r = _cyrusmsg_from_buf(&mybuf, &msg);
    if (!r) r = _email_from_msg(req, args, msg, emailptr);
    buf_free(&mybuf);
    _cyrusmsg_free(&msg);
    return r;
}

HIDDEN int jmap_email_get_with_props(jmap_req_t *req,
                                     hash_table *props,
                                     msgrecord_t *mr,
                                     json_t **msgp)
{
    struct email_getargs args = _EMAIL_GET_ARGS_INITIALIZER;
    args.props = props;
    int r = _email_from_record(req, &args, mr, msgp);
    args.props = NULL;
    _email_getargs_fini(&args);
    return r;
}

static int _isthreadsonly(json_t *jargs)
{
    json_t *arg = json_object_get(jargs, "properties");
    if (!json_is_array(arg)) return 0;
    if (json_array_size(arg) != 1) return 0;
    const char *s = json_string_value(json_array_get(arg, 0));
    if (strcmpsafe(s, "threadId")) return 0;
    return 1;
}

static void jmap_email_get_threadsonly(jmap_req_t *req, struct jmap_get *get)
{
    size_t i;
    json_t *val;
    json_array_foreach(get->ids, i, val) {
        const char *id = json_string_value(val);
        conversation_id_t cid = 0;

        int r = _email_get_cid(req, id, &cid);
        if (!r && cid) {
            char thread_id[JMAP_THREADID_SIZE];
            jmap_set_threadid(cid, thread_id);
            json_t *msg = json_pack("{s:s, s:s}", "id", id, "threadId", thread_id);
            json_array_append_new(get->list, msg);
        }
        else {
            json_array_append_new(get->not_found, json_string(id));
        }
        if (r) {
            syslog(LOG_ERR, "jmap: Email/get(%s): %s", id, error_message(r));
        }
    }
}

struct _warmup_mboxcache_cb_rock {
    jmap_req_t *req;
    ptrarray_t mboxes;
};

static int _warmup_mboxcache_cb(const conv_guidrec_t *rec, void* vrock)
{
    struct _warmup_mboxcache_cb_rock *rock = vrock;
    int i;
    for (i = 0; i < ptrarray_size(&rock->mboxes); i++) {
        struct mailbox *mbox = ptrarray_nth(&rock->mboxes, i);
        if (!conv_guidrec_mboxcmp(rec, mbox)) {
            return 0;
        }
    }
    struct mailbox *mbox = NULL;
    int r = jmap_openmbox_by_guidrec(rock->req, rec, &mbox, /*rw*/0);
    if (!r) {
        if (mbtype_isa(mailbox_mbtype(mbox)) == MBTYPE_EMAIL) {
            ptrarray_append(&rock->mboxes, mbox);
        }
        else jmap_closembox(rock->req, &mbox);
    }
    return r;
}

static void jmap_email_get_full(jmap_req_t *req, struct jmap_get *get, struct email_getargs *args)
{
    size_t i;
    json_t *val;

    /* Warm up the mailbox cache by opening all mailboxes */
    struct _warmup_mboxcache_cb_rock rock = { req, PTRARRAY_INITIALIZER };
    json_array_foreach(get->ids, i, val) {
        const char *email_id = json_string_value(val);
        if (email_id[0] != 'M' || strlen(email_id) != 25) {
            continue;
        }
        int r = conversations_guid_foreach(req->cstate, _guid_from_id(email_id),
                                           _warmup_mboxcache_cb, &rock);
        if (r) {
            /* Ignore errors, they'll be handled in email_find */
            syslog(LOG_WARNING, "__warmup_mboxcache_cb(%s): %s", email_id, error_message(r));
            continue;
        }
    }

    /* Process emails one after the other */
    json_array_foreach(get->ids, i, val) {
        const char *id = json_string_value(val);
        char *mboxname = NULL;
        msgrecord_t *mr = NULL;
        json_t *msg = NULL;
        struct mailbox *mbox = NULL;

        uint32_t uid;
        int r = jmap_email_find(req, NULL, id, &mboxname, &uid);
        if (!r) {
            r = jmap_openmbox(req, mboxname, &mbox, 0);
            if (!r) {
                r = msgrecord_find(mbox, uid, &mr);
                if (!r) {
                    r = _email_from_record(req, args, mr, &msg);
                }
                jmap_closembox(req, &mbox);
            }
        }
        if (!r && msg) {
            json_array_append_new(get->list, msg);
        }
        else {
            json_array_append_new(get->not_found, json_string(id));
        }
        if (r) {
            syslog(LOG_ERR, "jmap: Email/get(%s): %s", id, error_message(r));
        }

        free(mboxname);
        msgrecord_unref(&mr);
    }

    /* Close cached mailboxes */
    struct mailbox *mbox = NULL;
    while ((mbox = ptrarray_pop(&rock.mboxes))) {
        jmap_closembox(req, &mbox);
    }
    ptrarray_fini(&rock.mboxes);
}

static const jmap_property_t email_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "blobId",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "threadId",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "mailboxIds",
        NULL,
        0
    },
    {
        "keywords",
        NULL,
        0
    },
    {
        "size",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "receivedAt",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "headers",
        NULL,
        JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET
    },
    {
        "header:*",
        NULL,
        JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET
    },
    {
        "messageId",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "inReplyTo",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "references",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "sender",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "from",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "to",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "cc",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "bcc",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "replyTo",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "subject",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "sentAt",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "bodyStructure",
        NULL,
        JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET
    },
    {
        "bodyValues",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "textBody",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "htmlBody",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "attachments",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "hasAttachment",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "preview",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },

    /* FM extensions (do ALL of these get through to Cyrus?) */
    {
        "addedDates",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "removedDates",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "trustedSender",
        JMAP_MAIL_EXTENSION,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "spamScore",
        JMAP_MAIL_EXTENSION,
        JMAP_PROP_IMMUTABLE
    },
    {
        "calendarEvents",
        JMAP_MAIL_EXTENSION,
        JMAP_PROP_IMMUTABLE
    },
    {
        "previousCalendarEvent",
        JMAP_MAIL_EXTENSION,
        JMAP_PROP_IMMUTABLE
    },
    {
        "isDeleted",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "imageSize",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "snoozed",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "bimiBlobId",
        JMAP_MAIL_EXTENSION,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_SKIP_GET
    },
    { NULL, NULL, 0 }
};

static int jmap_email_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    struct email_getargs args = _EMAIL_GET_ARGS_INITIALIZER;
    json_t *err = NULL;

    /* Parse request */
    jmap_get_parse(req, &parser, email_props, /*allow_null_ids*/0,
                   &_email_getargs_parse, &args, &get, &err);
    if (!err) {
        /* header:Xxx properties */
        json_t *jprops = json_object_get(req->args, "properties");
        if (JNOTNULL(jprops)) {
            _email_parse_wantheaders(jprops, &parser, "properties",
                                     &args.want_headers);
        }

        if (json_array_size(parser.invalid)) {
            err = json_pack("{s:s s:O}", "type", "invalidArguments",
                            "arguments", parser.invalid);
        }
    }
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* properties - already parsed in jmap_get_parse */
    args.props = get.props;

    /* Set default body properties, if not set by client */
    if (args.bodyprops == NULL) {
        args.bodyprops = &_email_get_default_bodyprops;

        if (args.bodyprops->size == 0) {
            _email_init_default_props(args.bodyprops);
        }
    }

    if (_isthreadsonly(req->args))
        jmap_email_get_threadsonly(req, &get);
    else
        jmap_email_get_full(req, &get, &args);

    get.state = jmap_getstate(req, MBTYPE_EMAIL, /*refresh*/0);

    jmap_ok(req, jmap_get_reply(&get));

done:
    _email_getargs_fini(&args);
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

struct email_parseargs {
    /* Email/parse arguments */
    hash_table *props;
    struct email_getargs *getargs;
};

static int _email_parseargs_parse(jmap_req_t *req,
                                  struct jmap_parser *parser,
                                  const char *key,
                                  json_t *arg,
                                  void *rock)
{
    struct email_parseargs *args = (struct email_parseargs *) rock;

    if (!strcmp(key, "properties")) {
        if (json_is_array(arg)) {
            size_t i;
            json_t *val;
            hash_table *props = xzmalloc(sizeof(hash_table));
            construct_hash_table(props, json_array_size(arg) + 1, 0);
            json_array_foreach(arg, i, val) {
                const char *s = json_string_value(val);
                if (!s) {
                    jmap_parser_push_index(parser, "properties", i, s);
                    jmap_parser_invalid(parser, NULL);
                    jmap_parser_pop(parser);
                    continue;
                }
                hash_insert(s, (void*)1, props);
            }
            args->getargs->props = args->props = props;
        }
        else if (JNOTNULL(arg)) {
            return 0;
        }

        return 1;
    }

    return _email_getargs_parse(req, parser, key, arg, args->getargs);
}

static int jmap_email_parse(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_parse parse;
    struct email_getargs getargs = _EMAIL_GET_ARGS_INITIALIZER;
    struct email_parseargs parseargs = { NULL, &getargs };
    json_t *err = NULL;

    /* Parse request */
    jmap_parse_parse(req, &parser,
                     &_email_parseargs_parse, &parseargs, &parse, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Set default properties, if not set by client */
    if (getargs.props == NULL) {
        getargs.props = &_email_parse_default_props;

        if (getargs.props->size == 0) {
            _email_init_default_props(getargs.props);
        }
    }

    /* Set default body properties, if not set by client */
    if (getargs.bodyprops == NULL) {
        getargs.bodyprops = &_email_get_default_bodyprops;

        if (getargs.bodyprops->size == 0) {
            _email_init_default_props(getargs.bodyprops);
        }
    }

    /* Process request */
    json_t *jval;
    size_t i;
    json_array_foreach(parse.blob_ids, i, jval) {
        const char *blobid = json_string_value(jval);
        struct mailbox *mbox = NULL;
        msgrecord_t *mr = NULL;
        struct body *body = NULL;
        const struct body *part = NULL;
        json_t *email = NULL;
        int r = 0;

        struct buf *inmem = hash_lookup(blobid, req->inmemory_blobs);
        if (inmem) {
            r = _email_from_buf(req, &getargs, inmem, part->encoding, &email);
            if (r) {
                syslog(LOG_ERR, "jmap: Email/parse(%s): %s", blobid, error_message(r));
            }
            if (email) {
                json_object_set_new(parse.parsed, blobid, email);
            }
            else {
                json_array_append_new(parse.not_parsable, json_string(blobid));
            }
            continue;
        }

        r = jmap_findblob(req, NULL/*accountid*/, blobid,
                              &mbox, &mr, &body, &part, NULL);
        if (r) {
            json_array_append_new(parse.not_found, json_string(blobid));
            continue;
        }

        if (part && (strcmp(part->type, "MESSAGE") || !strcmpnull(part->encoding, "BASE64"))) {
            struct buf msg_buf = BUF_INITIALIZER;
            r = msgrecord_get_body(mr, &msg_buf);
            if (!r) {
                struct buf buf = BUF_INITIALIZER;
                buf_init_ro(&buf, buf_base(&msg_buf) + part->content_offset,
                        part->content_size);
                r = _email_from_buf(req, &getargs, &buf, part->encoding, &email);
                buf_free(&buf);
            }
            buf_free(&msg_buf);
            if (r) {
                syslog(LOG_ERR, "jmap: Email/parse(%s): %s", blobid, error_message(r));
            }
        }
        else if (part) {
            _email_from_rfc822body(req, &getargs, mr, part, &email);
        }
        else if (mr) {
            _email_from_record(req, &getargs, mr, &email);
        }

        if (email) {
            json_object_set_new(parse.parsed, blobid, email);
        }
        else {
            json_array_append_new(parse.not_parsable, json_string(blobid));
        }
        msgrecord_unref(&mr);
        jmap_closembox(req, &mbox);
        message_free_body(body);
        free(body);
    }

    /* Build response */
    jmap_ok(req, jmap_parse_reply(&parse));

done:
    _email_getargs_fini(&getargs);
    jmap_parser_fini(&parser);
    jmap_parse_fini(&parse);
    free_hash_table(parseargs.props, NULL);
    free(parseargs.props);
    return 0;
}

static char *_mime_make_boundary()
{
    char *boundary, *p, *q;

    boundary = xstrdup(makeuuid());
    for (p = boundary, q = boundary; *p; p++) {
        if (*p != '-') *q++ = *p;
    }
    *q = 0;

    return boundary;
}

/* A soft limit for MIME header lengths when generating MIME from JMAP.
 * See the header_from_Xxx functions for usage. */
#define MIME_MAX_HEADER_LENGTH 78

const char QSTRINGCHAR[256] = {
/* control chars 9 (TAB), 10 (LF), 13 (CR) and space (32)
 * are not permitted, all other control characters obsolete */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/* All printable ASCII characters (decimal values between 33 and 126) */
/* are safe to use in quoted string. 1=use verbatim, 2=escape */
/* XXX 32 (space) is allowed here, as most MUAs expect that */
    1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
/* all high bits are unsafe */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void _mime_write_xparam(struct buf *buf, const char *name, const char *value)
{
    /* Encode header value */
    struct buf valbuf = BUF_INITIALIZER;
    int is_qstring = 1;
    const char *p;
    for (p = value; *p && is_qstring; p++) {
        switch (QSTRINGCHAR[(unsigned char)*p]) {
            case 0:
                is_qstring = 0;
                break;
            case 2:
                buf_putc(&valbuf, '\\');
                /* fall through */
            default:
                buf_putc(&valbuf, *p);
        }
    }
    char *xvalue = is_qstring ? buf_release(&valbuf) : charset_encode_mimexvalue(value, NULL);

    /* Attempt to stuff header in one line */
    if (strlen(name) + strlen(xvalue) + 1 < MIME_MAX_HEADER_LENGTH) {
        if (is_qstring)
            buf_printf(buf, ";%s=\"%s\"", name, xvalue);
        else
            buf_printf(buf, ";%s*=%s", name, xvalue);
        goto done;
    }

    /* Break value into continuations */
    int section = 0;
    struct buf line = BUF_INITIALIZER;
    for (p = xvalue; *p; section++) {
        /* Build parameter continuation line. */
        buf_setcstr(&line, ";\r\n ");
        buf_printf(&line, "%s*%d", name, section);
        buf_appendcstr(&line, is_qstring ? "=\"" : "*=");
        /* Write at least one character of the value */
        int n = buf_len(&line) + 1;
        do {
            buf_putc(&line, *p);
            n++;
            p++;
            if (!is_qstring && *p == '%' && n >= MIME_MAX_HEADER_LENGTH - 2)
                break;
        } while (*p && n < MIME_MAX_HEADER_LENGTH);
        if (is_qstring)
            buf_putc(&line, '"');
        /* Write line */
        buf_append(buf, &line);
    }
    buf_free(&line);

done:
    buf_free(&valbuf);
    free(xvalue);
}

static int _copy_msgrecords(struct auth_state *authstate,
                            const char *user_id,
                            struct namespace *namespace,
                            struct mailbox *src,
                            struct mailbox *dst,
                            ptrarray_t *msgrecs,
                            long aclcheck)
{
    struct appendstate as;
    int r;
    int nolink = !config_getswitch(IMAPOPT_SINGLEINSTANCESTORE);

    r = append_setup_mbox(&as, dst, user_id, authstate,
                 aclcheck, NULL, namespace, 0, EVENT_MESSAGE_COPY);
    if (r) goto done;

    r = append_copy(src, &as, msgrecs, nolink,
                    mboxname_same_userid(mailbox_name(src), mailbox_name(dst)));
    if (r) {
        append_abort(&as);
        goto done;
    }

    r = append_commit(&as);
    if (r) goto done;

    /* we log the first name to get GUID-copy magic */
    sync_log_mailbox_double(mailbox_name(src), mailbox_name(dst));
    /* also want to log an append here, to make sure squatter notices */
    sync_log_append(mailbox_name(dst));

done:
    return r;
}

static int _copy_msgrecord(struct auth_state *authstate,
                           const char *user_id,
                           struct namespace *namespace,
                           struct mailbox *src,
                           struct mailbox *dst,
                           msgrecord_t *mrw)
{

    if (!strcmp(mailbox_uniqueid(src), mailbox_uniqueid(dst)))
        return 0;

    ptrarray_t msgrecs = PTRARRAY_INITIALIZER;
    ptrarray_add(&msgrecs, mrw);
    int r = _copy_msgrecords(authstate, user_id, namespace, src, dst, &msgrecs, JACL_ADDITEMS);
    ptrarray_fini(&msgrecs);
    return r;
}

/* A subset of all messages within an IMAP mailbox. */
struct email_mboxrec {
    char *mboxname;     /* IMAP mailbox name */
    char *mbox_id;      /* Cyrus-internal unique mailbox id */
    ptrarray_t uidrecs; /* Array of struct email_uidrec */
};

/* A single mailboxname/UID pair of the JMAP email identified by
 * email_id. Each email has 1 or more uid records, but uid
 * records may represent expunged messages. */
struct email_uidrec {
    struct email_mboxrec *mboxrec; /* owning mailboxrec */
    char *email_id;                /* JMAP email id */
    uint32_t uid;                  /* IMAP uid in mbox */
    int is_new;                    /* Used by Email/set{update} */
    int is_snoozed;                /* Used by Email/set{update} */
};

static void _email_multiexpunge(jmap_req_t *req, struct mailbox *mbox,
                                ptrarray_t *uidrecs, json_t *errors)
{
    int r;
    struct mboxevent *mboxevent = NULL;
    msgrecord_t *mrw = NULL;
    uint32_t system_flags, internal_flags;

    mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);

    int j;
    int didsome = 0;
    for (j = 0; j < ptrarray_size(uidrecs); j++) {
        struct email_uidrec *uidrec = ptrarray_nth(uidrecs, j);
        // skip known errors
        if (json_object_get(errors, uidrec->email_id)) {
             continue;
        }
        // load the record
        if (mrw) msgrecord_unref(&mrw);
        r = msgrecord_find(mbox, uidrec->uid, &mrw);
        if (!r) r = msgrecord_get_systemflags(mrw, &system_flags);
        if (!r) r = msgrecord_get_internalflags(mrw, &internal_flags);
        // already expunged, skip (aka: will be reported as success)
        if (internal_flags & FLAG_INTERNAL_EXPUNGED) continue;
        // update the flags
        if (!r) r = msgrecord_add_systemflags(mrw, FLAG_DELETED);
        if (!r) r = msgrecord_add_internalflags(mrw, FLAG_INTERNAL_EXPUNGED);
        if (!r) r = msgrecord_rewrite(mrw);
        if (!r) {
            mboxevent_extract_msgrecord(mboxevent, mrw);
            didsome++;
        }
        // if errors, record the issue
        if (r) json_object_set_new(errors, uidrec->email_id, jmap_server_error(r));
    }
    if (mrw) msgrecord_unref(&mrw);

    /* Report mailbox event if anything to say */
    if (didsome) {
        mboxevent_extract_mailbox(mboxevent, mbox);
        mboxevent_set_numunseen(mboxevent, mbox, -1);
        mboxevent_set_access(mboxevent, NULL, NULL, req->userid, mailbox_name(mbox), 0);
        mboxevent_notify(&mboxevent);
    }
    mboxevent_free(&mboxevent);
}

struct email_append_detail {
    char blob_id[JMAP_BLOBID_SIZE];
    char email_id[JMAP_EMAILID_SIZE];
    char thread_id[JMAP_THREADID_SIZE];
    size_t size;
};

static void _email_append(jmap_req_t *req,
                          json_t *mailboxids,
                          strarray_t *keywords,
                          time_t internaldate,
                          json_t *snoozed,
                          int has_attachment,
                          const char *sourcefile,
                          int(*writecb)(jmap_req_t* req, FILE* fp, void* rock, json_t **err),
                          void *rock,
                          struct email_append_detail *detail,
                          json_t **err)
{
    int fd;
    void *addr;
    FILE *f = NULL;
    char *mboxname = NULL, *last = NULL;
    const char *id;
    struct stagemsg *stage = NULL;
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_INITIALIZER;
    json_t *val, *mailboxes = NULL;
    size_t len;
    int r = 0;
    time_t savedate = 0;

    if (json_object_size(mailboxids) > JMAP_MAIL_MAX_MAILBOXES_PER_EMAIL) {
        *err = json_pack("{s:s}", "type", "tooManyMailboxes");
        goto done;
    }
    else if (strarray_size(keywords) > JMAP_MAIL_MAX_KEYWORDS_PER_EMAIL) {
        *err = json_pack("{s:s}", "type", "tooManyKeywords");
        goto done;
    }

    if (!internaldate) internaldate = time(NULL);

    /* Pick the mailbox to create the message in, prefer \Snoozed then \Drafts */
    mailboxes = json_object(); /* maps mailbox ids to mboxnames */
    json_object_foreach(mailboxids, id, val) {
        const char *mboxid = id;
        /* Lookup mailbox */
        if (mboxid && mboxid[0] == '#') {
            mboxid = jmap_lookup_id(req, mboxid + 1);
        }
        if (!mboxid) continue;
        const mbentry_t *mbentry = jmap_mbentry_by_uniqueid(req, mboxid);
        if (!mbentry || !jmap_hasrights_mbentry(req, mbentry, JACL_LOOKUP)) {
            r = IMAP_MAILBOX_NONEXISTENT;
            goto done;
        }

        /* Convert intermediary mailbox to real mailbox */
        if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
            struct mboxlock *namespacelock = mboxname_usernamespacelock(mbentry->name);
            r = mboxlist_promote_intermediary(mbentry->name);
            mboxname_release(&namespacelock);
            if (r) goto done;
        }

        if (json_is_string(val)) {
            /* We flagged this mailboxId as the $snoozed mailbox */
            if (mboxname) free(mboxname);
            mboxname = xstrdup(mbentry->name);
        }
        else if (!mboxname) {
            mbname_t *mbname = mbname_from_intname(mbentry->name);

            /* Is this the draft mailbox? */
            struct buf buf = BUF_INITIALIZER;
            annotatemore_lookup(mbname_intname(mbname), "/specialuse",
                                req->accountid, &buf);
            if (buf.len) {
                strarray_t *uses = strarray_split(buf_cstring(&buf), " ", STRARRAY_TRIM);
                if (strarray_find_case(uses, "\\Drafts", 0)) {
                    if (mboxname) free(mboxname);
                    mboxname = xstrdup(mbentry->name);
                }
                strarray_free(uses);
            }
            buf_free(&buf);
            mbname_free(&mbname);
        }

        /* If we haven't picked a mailbox, remember the last one. */
        if (last) {
            free(last);
            last = NULL;
        }
        if (!mboxname) last = xstrdup(mbentry->name);

        /* Map mailbox id to mailbox name. */
        json_object_set_new(mailboxes, mboxid, json_string(mbentry->name));
    }

    /* If we haven't picked a mailbox, pick the last one. */
    if (!mboxname) mboxname = last;
    if (!mboxname) {
        char *s = json_dumps(mailboxids, 0);
        syslog(LOG_ERR, "_email_append: invalid mailboxids: %s", s);
        free(s);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Create the message in the destination mailbox */
    r = jmap_openmbox(req, mboxname, &mbox, 1);
    if (r) goto done;

    if (sourcefile) {
        if (!(f = append_newstage_full(mailbox_name(mbox), internaldate, 0, &stage, sourcefile))) {
            syslog(LOG_ERR, "append_newstage(%s) failed", mailbox_name(mbox));
            r = HTTP_SERVER_ERROR;
            goto done;
        }
    }
    else {
        /* Write the message to the filesystem */
        if (!(f = append_newstage(mailbox_name(mbox), internaldate, 0, &stage))) {
            syslog(LOG_ERR, "append_newstage(%s) failed", mailbox_name(mbox));
            r = HTTP_SERVER_ERROR;
            goto done;
        }
        r = writecb(req, f, rock, err);
        if (r) goto done;
        if (fflush(f)) {
            r = IMAP_IOERROR;
            goto done;
        }
    }
    fseek(f, 0L, SEEK_END);
    len = ftell(f);

    /* Generate a GUID from the raw file content */
    fd = fileno(f);
    if ((addr = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0))) {
        struct message_guid guid;
        message_guid_generate(&guid, addr, len);
        jmap_set_emailid(&guid, detail->email_id);
        jmap_set_blobid(&guid, detail->blob_id);
        detail->size = len;
        munmap(addr, len);
    } else {
        r = IMAP_IOERROR;
        goto done;
    }
    fclose(f);
    f = NULL;

    /*  Check if a message with this GUID already exists and is
     *  visible for the authenticated user. */
    char *exist_mboxname = NULL;
    uint32_t exist_uid;
    r = jmap_email_find(req, NULL, detail->email_id, &exist_mboxname, &exist_uid);
    free(exist_mboxname);
    if (r != IMAP_NOTFOUND) {
        if (!r) r = IMAP_MAILBOX_EXISTS;
        goto done;
    }

    /* Great, that's a new message! */
    struct body *body = NULL;
    struct appendstate as;

    /* Prepare flags */
    strarray_t flags = STRARRAY_INITIALIZER;
    int i;
    for (i = 0; i < strarray_size(keywords); i++) {
        const char *flag = jmap_keyword_to_imap(strarray_nth(keywords, i));
        if (flag) strarray_append(&flags, flag);
    }
    if (has_attachment) {
        strarray_add(&flags, "$hasattachment");
    }

    /* Append the message to the mailbox. */
    if (config_getswitch(IMAPOPT_QUOTA_USE_CONVERSATIONS)) {
        // we'll only be charged for one copy
        qdiffs[QUOTA_STORAGE] = len;
        qdiffs[QUOTA_MESSAGE] = 1;
    }
    else {
        // count how many mailboxes we're adding it to
        qdiffs[QUOTA_STORAGE] = 0;
        qdiffs[QUOTA_MESSAGE] = 0;
        json_object_foreach(mailboxes, id, val) {
            qdiffs[QUOTA_STORAGE] += len;
            qdiffs[QUOTA_MESSAGE] += 1;
        }
    }
    r = append_setup_mbox(&as, mbox, req->userid, httpd_authstate,
            0, ignorequota ? NULL : qdiffs, 0, 0, EVENT_MESSAGE_NEW);
    if (r) goto done;

    struct entryattlist *annots = NULL;
    if (json_is_object(snoozed)) {
        const char *annot = IMAP_ANNOT_NS "snoozed";
        const char *attrib = "value.shared";
        struct buf buf = BUF_INITIALIZER;
        char *json = json_dumps(snoozed, JSON_COMPACT);

        buf_initm(&buf, json, strlen(json));
        setentryatt(&annots, annot, attrib, &buf);
        buf_free(&buf);

        /* Add \snoozed pseudo-flag */
        strarray_add(&flags, "\\snoozed");

        /* Extract until and use it as savedate */
        time_from_iso8601(json_string_value(json_object_get(snoozed, "until")),
                          &savedate);
    }
    r = append_fromstage_full(&as, &body, stage, internaldate, savedate, 0,
                         flags.count ? &flags : NULL, 0, &annots);
    freeentryatts(annots);
    if (r) {
        append_abort(&as);
        goto done;
    }
    strarray_fini(&flags);
    message_free_body(body);
    free(body);

    r = append_commit(&as);
    if (r) goto done;

    /* Load message record */
    r = msgrecord_find(mbox, mbox->i.last_uid, &mr);
    if (r) goto done;

    bit64 cid;
    r = msgrecord_get_cid(mr, &cid);
    if (r) goto done;
    jmap_set_threadid(cid, detail->thread_id);

    /* Complete message creation */
    if (stage) {
        append_removestage(stage);
        stage = NULL;
    }
    json_object_del(mailboxes, mailbox_uniqueid(mbox));

    /* Copy the message to all remaining mailboxes */
    json_object_foreach(mailboxes, id, val) {
        const char *dstname = json_string_value(val);
        struct mailbox *dst = NULL;

        if (!strcmp(mboxname, dstname))
            continue;

        r = jmap_openmbox(req, dstname, &dst, 1);
        if (r) goto done;

        r = _copy_msgrecord(httpd_authstate, req->userid, &jmap_namespace,
                            mbox, dst, mr);

        jmap_closembox(req, &dst);
        if (r) goto done;
    }

done:
    if (f) fclose(f);
    append_removestage(stage);
    msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);
    free(mboxname);
    json_decref(mailboxes);
    if (r && *err == NULL) {
        switch (r) {
            case IMAP_PERMISSION_DENIED:
                *err = json_pack("{s:s}", "type", "forbidden");
                break;
            case IMAP_MAILBOX_EXISTS:
                *err = json_pack("{s:s s:s}", "type", "alreadyExists", "existingId", detail->email_id);
                break;
            case IMAP_QUOTA_EXCEEDED:
                *err = json_pack("{s:s}", "type", "overQuota");
                break;
            case IMAP_MESSAGE_CONTAINSNULL:
            case IMAP_MESSAGE_CONTAINSNL:
            case IMAP_MESSAGE_CONTAINS8BIT:
            case IMAP_MESSAGE_BADHEADER:
            case IMAP_MESSAGE_NOBLANKLINE:
                *err = json_pack("{s:s s:s}", "type", "invalidEmail",
                        "description", error_message(r));
                break;
            default:
                *err = jmap_server_error(r);
        }
    }
}

struct emailpart {
    /* Mandatory fields */
    struct headers headers;       /* raw headers */
    /* Optional fields */
    json_t *jpart;                /* original EmailBodyPart JSON object */
    json_t *jbody;                /* EmailBodyValue for text bodies */
    char *blob_id;                /* blobId to dump contents from */
    ptrarray_t subparts;          /* array of emailpart pointers */
    char *type;                   /* Content-Type main type */
    char *subtype;                /* Content-Type subtype */
    char *charset;                /* Content-Type charset parameter */
    char *boundary;               /* Content-Type boundary parameter */
    char *disposition;            /* Content-Disposition without parameters */
    char *filename;               /* Content-Disposition filename parameter */
};

static void _emailpart_fini(struct emailpart *part)
{
    if (!part) return;

    struct emailpart *subpart;
    while ((subpart = ptrarray_pop(&part->subparts))) {
        _emailpart_fini(subpart);
        free(subpart);
    }
    ptrarray_fini(&part->subparts);
    json_decref(part->jpart);
    json_decref(part->jbody);
    _headers_fini(&part->headers);
    free(part->type);
    free(part->subtype);
    free(part->boundary);
    free(part->charset);
    free(part->disposition);
    free(part->filename);
    free(part->blob_id);
}

struct email {
    struct headers headers; /* parsed headers */
    json_t *jemail;               /* original Email JSON object */
    struct emailpart *body;       /* top-level MIME part */
    time_t internaldate;          /* RFC 3501 internaldate aka receivedAt */
    int has_attachment;           /* set the HasAttachment flag */
    json_t *snoozed;              /* set snoozed annotation */
};

static void _email_fini(struct email *email)
{
    if (!email) return;
    _headers_fini(&email->headers);
    json_decref(email->jemail);
    _emailpart_fini(email->body);
    free(email->body);
}

static json_t *_header_make(const char *header_name, const char *prop_name, struct buf *val)
{
    char *tmp = buf_release(val);
    json_t *jheader = json_pack("{s:s s:s}", "name", header_name, "value", tmp);
    free(tmp);
    if (prop_name) json_object_set_new(jheader, "prop", json_string(prop_name));
    return jheader;
}

typedef json_t* (*header_from_t)(json_t *jval,
                                 struct jmap_parser *parser,
                                 const char *prop_name,
                                 const char *header_name,
                                 enum header_form form);

static json_t *_header_from_raw(json_t *jraw,
                                struct jmap_parser *parser,
                                const char *prop_name,
                                const char *header_name,
                                enum header_form form __attribute__((unused)))
{
    /* Verbatim use header value in raw form */
    if (json_is_string(jraw)) {
        json_t *jheader = json_pack("{s:s s:O s:s}",
                "name", header_name, "value", jraw, "prop", prop_name);
        return jheader;
    }
    else {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }
}

static json_t *_header_from_text(json_t *jtext,
                                 struct jmap_parser *parser,
                                 const char *prop_name,
                                 const char *header_name,
                                 enum header_form form __attribute__((unused)))
{
    /* Parse a Text header into raw form */
    if (json_is_string(jtext)) {
        const char *s = json_string_value(jtext);
        char *tmp = charset_encode_mimeheader(s, strlen(s), 0);
        struct buf val = BUF_INITIALIZER;
        /* If text got folded, then the first line of the encoded
         * header might spill over the soft 78-character limit due to
         * the Header name prefix. Looking at how most of the mail
         * clients are doing this, this seems not to be an issue and
         * allows us to not start the header value with a line fold. */
        buf_setcstr(&val, tmp);
        free(tmp);
        return _header_make(header_name, prop_name, &val);
    }
    else {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }
}

static json_t *_header_from_strings(const strarray_t *vals,
                                    const char *prop_name,
                                    const char *header_name)
{
    size_t line_len = strlen(header_name) + 2;
    struct buf val = BUF_INITIALIZER;
    int i;

    for (i = 0; i < strarray_size(vals); i++) {
        const char *s = strarray_nth(vals, i);
        size_t s_len = strlen(s);
        if (line_len + s_len + 1 > MIME_MAX_HEADER_LENGTH) {
            buf_appendcstr(&val, "\r\n ");
            line_len = 1;
        }
        else if (i) {
            buf_putc(&val, ' ');
            line_len++;
        }
        buf_appendcstr(&val, s);
        line_len += s_len;
    }

    return _header_make(header_name, prop_name, &val);
}


static json_t *_header_from_addresses(json_t *addrs,
                                       struct jmap_parser *parser,
                                       const char *prop_name,
                                       const char *header_name,
                                       enum header_form form)
{
    json_t *groups = form == HEADER_FORM_GROUPEDADDRESSES ?
        addrs : json_pack("[{s:n s:O}]", "name", "addresses", addrs);

    json_t *group;
    size_t i;
    struct buf emailbuf = BUF_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    json_t *ret = NULL;
    strarray_t vals = STRARRAY_INITIALIZER;

    json_array_foreach(groups, i, group) {

        const char *groupname = NULL;
        json_t *jgroupname = json_object_get(group, "name");
        if (json_is_string(jgroupname)) {
            groupname = json_string_value(jgroupname);
        }
        else if (JNOTNULL(jgroupname)) {
            jmap_parser_push_index(parser, prop_name, i, NULL);
            jmap_parser_invalid(parser, "name");
            jmap_parser_pop(parser);
        }

        if (groupname) {
            buf_setcstr(&buf, groupname);
            buf_putc(&buf, ':');
            buf_putc(&buf, ' ');
            strarray_append(&vals, buf_cstring(&buf));
            buf_reset(&buf);
        }

        json_t *addrs = json_object_get(group, "addresses");
        if (!json_is_array(addrs)) {
            jmap_parser_push_index(parser, prop_name, i, NULL);
            jmap_parser_invalid(parser, "addresses");
            jmap_parser_pop(parser);
        }
        if (json_array_size(parser->invalid)) {
            goto done;
        }

        json_t *addr;
        size_t j;
        json_array_foreach(addrs, j, addr) {
            json_t *jname = json_object_get(addr, "name");
            if (!json_is_string(jname) && JNOTNULL(jname)) {
                if (form == HEADER_FORM_GROUPEDADDRESSES) {
                    jmap_parser_push_index(parser, prop_name, i, NULL);
                    jmap_parser_push_index(parser, "addresses", j, NULL);
                    jmap_parser_invalid(parser, "name");
                    jmap_parser_pop(parser);
                    jmap_parser_pop(parser);
                }
                else {
                    jmap_parser_push_index(parser, prop_name, j, NULL);
                    jmap_parser_invalid(parser, "name");
                    jmap_parser_pop(parser);
                }
            }

            json_t *jemail = json_object_get(addr, "email");
            if (!json_is_string(jemail) && JNOTNULL(jemail)) {
                if (form == HEADER_FORM_GROUPEDADDRESSES) {
                    jmap_parser_push_index(parser, prop_name, i, NULL);
                    jmap_parser_push_index(parser, "addresses", j, NULL);
                    jmap_parser_invalid(parser, "email");
                    jmap_parser_pop(parser);
                    jmap_parser_pop(parser);
                }
                else {
                    jmap_parser_push_index(parser, prop_name, j, NULL);
                    jmap_parser_invalid(parser, "email");
                    jmap_parser_pop(parser);
                }
            }

            if (json_array_size(parser->invalid))
                goto done;
            if (!JNOTNULL(jname) && !JNOTNULL(jemail))
                continue;

            const char *name = json_string_value(jname);
            const char *email = json_string_value (jemail);
            if (!name && !email) continue;

            /* Trim whitespace from email */
            if (email) {
                buf_setcstr(&emailbuf, email);
                buf_trim(&emailbuf);
                email = buf_cstring(&emailbuf);
            }

            if (name && strlen(name) && email) {
                enum name_type { ATOM, QUOTED_STRING, HIGH_BIT } name_type = ATOM;
                const char *p;
                for (p = name; *p; p++) {
                    unsigned char c = *p;
                    /* Check for ATOM characters */
                    if (('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z'))
                        continue;
                    if ('0' <= c && c <= '9')
                        continue;
                    if (strchr("!#$%&'*+-/=?^_`{|}~", c))
                        continue;
                    if (c > 127) {
                        /* Contains at least one high bit character. */
                        name_type = HIGH_BIT;
                        break;
                    }
                    else {
                        /* Requires at least a quoted string, but could
                         * still contain a high bit at a later position. */
                        name_type = QUOTED_STRING;
                    }
                }
                if (name_type == ATOM) {
                    buf_setcstr(&buf, name);
                }
                else if (name_type == QUOTED_STRING) {
                    buf_putc(&buf, '"');
                    for (p = name; *p; p++) {
                        if (*p == '"' || *p == '\\' || *p == '\r') {
                            buf_putc(&buf, '\\');
                        }
                        buf_putc(&buf, *p);
                    }
                    buf_putc(&buf, '"');
                }
                else if (name_type == HIGH_BIT) {
                    char *xname = charset_encode_mimephrase(name);
                    buf_appendcstr(&buf, xname);
                    free(xname);
                }
                buf_printf(&buf, " <%s>", email);
            } else if (email) {
                buf_setcstr(&buf, email);
            }
            if (j < json_array_size(addrs) - 1 || i < json_array_size(groups) - 1) {
                buf_putc(&buf, ',');
            }
            strarray_append(&vals, buf_cstring(&buf));
            buf_reset(&emailbuf);
            buf_reset(&buf);
        }

        if (groupname)
            strarray_append(&vals, ";");
    }

    ret = _header_from_strings(&vals, prop_name, header_name);

done:
    if (groups != addrs) json_decref(groups);
    strarray_fini(&vals);
    buf_free(&emailbuf);
    buf_free(&buf);
    return ret;
}

static json_t *_header_from_messageids(json_t *jmessageids,
                                       struct jmap_parser *parser,
                                       const char *prop_name,
                                       const char *header_name,
                                       enum header_form form __attribute__((unused)))
{
    if (!json_array_size(jmessageids)) {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }

    size_t i;
    json_t *jval;
    struct buf val = BUF_INITIALIZER;
    struct buf msgid = BUF_INITIALIZER;
    strarray_t vals = STRARRAY_INITIALIZER;
    json_t *ret = NULL;

    json_array_foreach(jmessageids, i, jval) {
        const char *s = json_string_value(jval);
        if (!s) {
            jmap_parser_invalid(parser, prop_name);
            goto done;
        }
        buf_setcstr(&msgid, s);
        buf_trim(&msgid);
        buf_putc(&val, '<');
        buf_appendcstr(&val, buf_cstring(&msgid));
        buf_putc(&val, '>');
        if (conversations_check_msgid(buf_base(&val), buf_len(&val))) {
            jmap_parser_invalid(parser, prop_name);
            goto done;
        }
        strarray_append(&vals, buf_cstring(&val));
        buf_reset(&val);
    }
    ret = _header_from_strings(&vals, prop_name, header_name);

done:
    strarray_fini(&vals);
    buf_free(&msgid);
    buf_free(&val);
    return ret;
}

static json_t *_header_from_date(json_t *jdate,
                                 struct jmap_parser *parser,
                                 const char *prop_name,
                                 const char *header_name,
                                 enum header_form form __attribute__((unused)))
{
    const char *s = json_string_value(jdate);
    if (!s) {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }

    struct offsettime t;
    int n = offsettime_from_iso8601(s, &t);
    if (n <= 0 || s[n] != '\0') {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }
    char fmt[RFC5322_DATETIME_MAX+1];
    memset(fmt, 0, RFC5322_DATETIME_MAX+1);
    offsettime_to_rfc5322(&t, fmt, RFC5322_DATETIME_MAX+1);

    struct buf val = BUF_INITIALIZER;
    buf_setcstr(&val, fmt);
    return _header_make(header_name, prop_name, &val);
}

static json_t *_header_from_urls(json_t *jurls,
                                 struct jmap_parser *parser,
                                 const char *prop_name,
                                 const char *header_name,
                                 enum header_form form __attribute__((unused)))
{
    if (!json_array_size(jurls)) {
        jmap_parser_invalid(parser, prop_name);
        return NULL;
    }

    size_t i;
    json_t *jval;
    struct buf val = BUF_INITIALIZER;
    strarray_t vals = STRARRAY_INITIALIZER;
    json_t *ret = NULL;

    json_array_foreach(jurls, i, jval) {
        const char *s = json_string_value(jval);
        if (!s) {
            jmap_parser_invalid(parser, prop_name);
            goto done;
        }

        buf_appendcstr(&val, "<");
        buf_appendcstr(&val, s);
        buf_appendcstr(&val, ">");
        if (i < json_array_size(jurls) - 1) {
            buf_putc(&val, ',');
        }
        strarray_append(&vals, buf_cstring(&val));
        buf_reset(&val);
    }
    ret = _header_from_strings(&vals, prop_name, header_name);

done:
    strarray_fini(&vals);
    buf_free(&val);
    return ret;
}

static void _headers_parseprops(json_t *jobject,
                           struct jmap_parser *parser,
                           struct headers *headers)
{
    const char *field;
    json_t *jval;
    json_object_foreach(jobject, field, jval) {
        if (strncmp(field, "header:", 7))
            continue;
        /* Parse header or reject if invalid form */
        struct header_prop *hprop = _header_parseprop(field);
        if (!hprop) {
            jmap_parser_invalid(parser, field);
            continue;
        }
        /* Reject redefinition of header */
        if (json_object_get(headers->all, hprop->lcasename)) {
            _header_prop_free(hprop);
            jmap_parser_invalid(parser, field);
            continue;
        }
        /* Parse header value */
        header_from_t cb = NULL;
        switch (hprop->form) {
            case HEADER_FORM_RAW:
                cb = _header_from_raw;
                break;
            case HEADER_FORM_TEXT:
                cb = _header_from_text;
                break;
            case HEADER_FORM_ADDRESSES:
            case HEADER_FORM_GROUPEDADDRESSES:
                cb = _header_from_addresses;
                break;
            case HEADER_FORM_MESSAGEIDS:
                cb = _header_from_messageids;
                break;
            case HEADER_FORM_DATE:
                cb = _header_from_date;
                break;
            case HEADER_FORM_URLS:
                cb = _header_from_urls;
                break;
            default:
                syslog(LOG_ERR, "jmap: unknown header form: %d", hprop->form);
                jmap_parser_invalid(parser, field);
        }
        if (!jval || jval == json_null()) {
            /* ignore null headers */
            _header_prop_free(hprop);
            continue;
        }
        if (hprop->all) {
            size_t i;
            json_t *jall = jval;
            json_array_foreach(jall, i, jval) {
                jmap_parser_push_index(parser, field, i, NULL);
                json_t *jheader = cb(jval, parser, field, hprop->name, hprop->form);
                if (jheader) _headers_add_new(headers, jheader);
                jmap_parser_pop(parser);
            }
        }
        else {
            json_t *jheader = cb(jval, parser, field, hprop->name, hprop->form);
            if (jheader) _headers_add_new(headers, jheader);
        }
        _header_prop_free(hprop);
    }
}

static void _emailpart_parse_headers(json_t *jpart,
                                     struct jmap_parser *parser,
                                     struct emailpart *part)
{
    /* headers */
    if (JNOTNULL(json_object_get(jpart, "headers"))) {
        jmap_parser_invalid(parser, "headers");
    }

    /* header:Xxx */
    const char *lcasename = NULL;
    json_t *jheaders;
    _headers_parseprops(jpart, parser, &part->headers);
    /* Validate Content-Xxx headers */
    json_object_foreach(part->headers.all, lcasename, jheaders) {
        if (strncmp(lcasename, "content-", 8))
            continue;

        json_t *jheader = json_array_get(jheaders, 0);
        const char *name = json_string_value(json_object_get(jheader, "name"));
        const char *val = json_string_value(json_object_get(jheader, "value"));
        const char *prop = json_string_value(json_object_get(jheader, "prop"));

        /* Reject re-definition of Content-Xxx headers */
        if (json_array_size(jheaders) > 1) {
            size_t j;
            json_array_foreach(jheaders, j, jheader) {
                prop = json_string_value(json_object_get(jheader, "prop"));
                jmap_parser_invalid(parser, prop);
            }
            continue;
        }
        if (!strcasecmp(name, "Content-Type")) {
            /* Validate Content-Type */
            struct param *type_params = NULL;
            message_parse_type(val, &part->type, &part->subtype, &type_params);
            if (part->type  && part->subtype) {
                struct param *param = type_params;
                while (param) {
                    if (!strcasecmp(param->attribute, "BOUNDARY")) {
                        part->boundary = xstrdupnull(param->value);
                    }
                    if (!strcasecmp(param->attribute, "CHARSET")) {
                        part->charset = xstrdupnull(param->value);
                    }
                    param = param->next;
                }
                /* Headers for multipart MUST specify a boundary */
                if (!strcasecmp(part->type, "MULTIPART") && !part->boundary)
                    jmap_parser_invalid(parser, prop);
                /* Headers for bodyparts with partId MUST NOT specify a charset */
                if (JNOTNULL(json_object_get(jpart, "partId")) && part->charset)
                    jmap_parser_invalid(parser, prop);
            }
            else {
                jmap_parser_invalid(parser, prop);
            }
            param_free(&type_params);
        }
        else if (!strcasecmp(name, "Content-Disposition")) {
            /* Validate Content-Disposition */
            struct param *disp_params = NULL;
            message_parse_disposition(val, &part->disposition, &disp_params);
            if (!part->disposition) {
                jmap_parser_invalid(parser, prop);
                continue;
            }
            param_free(&disp_params);
        }
        else if (!strcasecmp(name, "Content-Transfer-Encoding")) {
            /* Always reject Content-Transfer-Encoding */
            jmap_parser_invalid(parser, prop);
        }
    }
}

static struct emailpart *_emailpart_parse(jmap_req_t *req,
                                          json_t *jpart,
                                          struct jmap_parser *parser,
                                          json_t *bodies)
{
    if (!json_is_object(jpart)) {
        jmap_parser_invalid(parser, NULL);
        return NULL;
    }

    struct buf buf = BUF_INITIALIZER;
    struct emailpart *part = xzmalloc(sizeof(struct emailpart));
    part->jpart = json_incref(jpart);

    json_t *jval;

    /* partId */
    json_t *jpartId = json_object_get(jpart, "partId");
    if (JNOTNULL(jpartId) && !json_is_string(jpartId)) {
        jmap_parser_invalid(parser, "partId");
    }

    /* blobId */
    jval = json_object_get(jpart, "blobId");
    if (JNOTNULL(jval)) {
        const char *blob_id = jmap_id_string_value(req, jval);
        if (blob_id)
            part->blob_id = xstrdup(blob_id);
        else
            jmap_parser_invalid(parser, "blobId");
    }

    /* size */
    jval = json_object_get(jpart, "size");
    if (JNOTNULL(jval) && (!json_is_integer(jval) || JNOTNULL(jpartId))) {
        jmap_parser_invalid(parser, "size");
    }

    /* Parse headers */
    _emailpart_parse_headers(jpart, parser, part);

    /* Parse convenience header properties */
    int seen_header;

    /* cid */
    json_t *jcid = json_object_get(jpart, "cid");
    seen_header = _headers_have(&part->headers, "Content-Id");
    if (json_is_string(jcid) && !seen_header) {
        const char *cid = json_string_value(jcid);
        buf_setcstr(&buf, "<");
        buf_appendcstr(&buf, cid);
        buf_appendcstr(&buf, ">");
        _headers_add_new(&part->headers, _header_make("Content-Id", "cid", &buf));
    }
    else if (JNOTNULL(jcid)) {
        jmap_parser_invalid(parser, "cid");
    }

    /* language */
    json_t *jlanguage = json_object_get(jpart, "language");
    seen_header = _headers_have(&part->headers, "Content-Language");
    if (json_is_array(jlanguage) && !seen_header) {
        strarray_t vals = STRARRAY_INITIALIZER;
        size_t i;
        json_t *jval;
        struct buf buf = BUF_INITIALIZER;
        json_array_foreach(jlanguage, i, jval) {
            const char *lang = json_string_value(jval);
            if (!lang) {
                jmap_parser_push_index(parser, "language", i, NULL);
                jmap_parser_invalid(parser, NULL);
                jmap_parser_pop(parser);
                continue;
            }
            buf_setcstr(&buf, lang);
            if (i < json_array_size(jlanguage) - 1) {
                buf_putc(&buf, ',');
            }
            strarray_append(&vals, buf_cstring(&buf));
        }
        _headers_add_new(&part->headers, _header_from_strings(&vals, "language", "Content-Language"));
        buf_free(&buf);
        strarray_fini(&vals);
    }
    else if (JNOTNULL(jlanguage)) {
        jmap_parser_invalid(parser, "language");
    }

    /* location */
    json_t *jlocation = json_object_get(jpart, "location");
    seen_header = _headers_have(&part->headers, "Content-Location");
    if (json_is_string(jlocation) && !seen_header) {
        buf_setcstr(&buf, json_string_value(jlocation));
        _headers_add_new(&part->headers, _header_make("Content-Location", "location", &buf));
    }
    else if (JNOTNULL(jlocation)) {
        jmap_parser_invalid(parser, "location");
    }

    /* Check Content-Type and Content-Disposition header properties */
    int have_type_header = _headers_have(&part->headers, "Content-Type");
    int have_disp_header = _headers_have(&part->headers, "Content-Disposition");
    /* name */
    json_t *jname = json_object_get(jpart, "name");
    if (json_is_string(jname) && !have_type_header && !have_disp_header) {
        part->filename = xstrdup(json_string_value(jname));
    }
    else if (JNOTNULL(jname)) {
        jmap_parser_invalid(parser, "name");
    }
    /* disposition */
    json_t *jdisposition = json_object_get(jpart, "disposition");
    if (json_is_string(jdisposition) && !have_disp_header) {
        /* Build Content-Disposition header */
        part->disposition = xstrdup(json_string_value(jdisposition));
        buf_setcstr(&buf, part->disposition);
        if (part->filename) {
            _mime_write_xparam(&buf, "filename", part->filename);
        }
        _headers_add_new(&part->headers,
                _header_make("Content-Disposition", "disposition", &buf));
    }
    else if (JNOTNULL(jdisposition)) {
        jmap_parser_invalid(parser, "disposition");
    }
    else if (jname) {
        /* Make Content-Disposition header */
        part->disposition = xstrdup("attachment");
        buf_printf(&buf, "attachment");
        if (part->filename) {
            _mime_write_xparam(&buf, "filename", part->filename);
        }
        _headers_add_new(&part->headers,
                _header_make("Content-Disposition", "name", &buf));
    }
    /* charset */
    json_t *jcharset = json_object_get(jpart, "charset");
    if (json_is_string(jcharset) && !have_type_header && !JNOTNULL(jpartId)) {
        part->charset = xstrdup(json_string_value(jcharset));
    }
    else if (JNOTNULL(jcharset)) {
        jmap_parser_invalid(parser, "charset");
    }
    /* type */
    json_t *jtype = json_object_get(jpart, "type");
    if (JNOTNULL(jtype) && json_is_string(jtype) && !have_type_header) {
		const char *type = json_string_value(jtype);
        struct param *type_params = NULL;
        /* Validate type value */
        message_parse_type(type, &part->type, &part->subtype, &type_params);
        if (!part->type || !part->subtype || type_params) {
            jmap_parser_invalid(parser, "type");
        }
        param_free(&type_params);
    }
    else if (JNOTNULL(jtype)) {
        jmap_parser_invalid(parser, "type");
    }

    /* subParts */
    json_t *subParts = json_object_get(jpart, "subParts");
    if (json_array_size(subParts)) {
        size_t i;
        json_t *subPart;
        json_array_foreach(subParts, i, subPart) {
            jmap_parser_push_index(parser, "subParts", i, NULL);
            struct emailpart *subpart = _emailpart_parse(req, subPart, parser, bodies);
            if (subpart) ptrarray_append(&part->subparts, subpart);
            jmap_parser_pop(parser);
        }
    }

    if (part->type && part->subtype) {
        /* Build Content-Type header */
        if (!strcasecmp(part->type, "MULTIPART")) {
            /* Make boundary */
            part->boundary = _mime_make_boundary();
        }
        buf_reset(&buf);
        buf_printf(&buf, "%s/%s", part->type, part->subtype);
        buf_lcase(&buf);

        if (part->charset) {
            buf_appendcstr(&buf, "; charset=");
            buf_appendcstr(&buf, part->charset);
        }

        if (part->filename) {
            /* Check if filename can be encoded as quoted string */
            struct buf valbuf = BUF_INITIALIZER;
            int is_qstring = 1;
            const char *p;
            for (p = part->filename; *p && is_qstring; p++) {
                switch (QSTRINGCHAR[(unsigned char)*p]) {
                    case 0:
                        is_qstring = 0;
                        break;
                    case 2:
                        buf_putc(&valbuf, '\\');
                        /* fall through */
                    default:
                        buf_putc(&valbuf, *p);
                }
            }
            /* Encode and write header value */
            char *value;
            if (!is_qstring || buf_len(&valbuf) > MIME_MAX_HEADER_LENGTH) {
                value = charset_encode_mimeheader(part->filename, 0, /*qpencode*/1);
                if (strlen(value) > MIME_MAX_HEADER_LENGTH) {
                    buf_appendcstr(&buf, ";\r\n ");
                }
                else buf_appendcstr(&buf, "; ");
            }
            else {
                value = buf_release(&valbuf);
                buf_appendcstr(&buf, "; ");
            }
            buf_appendcstr(&buf, "name=\"");
            buf_appendcstr(&buf, value);
            buf_appendcstr(&buf, "\"");
            buf_free(&valbuf);
            free(value);
        }

        if (part->boundary) {
            buf_appendcstr(&buf, ";\r\n boundary=");
            buf_appendcstr(&buf, part->boundary);
        }

        if (!strcasecmp(part->type, "MULTIPART") &&
                !strcasecmp(part->subtype, "RELATED")) {
            /* RFC 2387 mandates a type parameter */
            struct emailpart *subpart = ptrarray_nth(&part->subparts, 0);
            if (subpart) {
                struct buf reltype = BUF_INITIALIZER;
                buf_printf(&reltype, "\"%s/%s\"",
                        subpart->type && subpart->subtype ?
                        subpart->type : "text",
                        subpart->type && subpart->subtype ?
                        subpart->subtype : "plain");
                buf_lcase(&reltype);
                buf_appendcstr(&buf, ";\r\n type=");
                buf_append(&buf, &reltype);
                buf_free(&reltype);
            }
        }

        _headers_add_new(&part->headers,
                _header_make("Content-Type", "type", &buf));
    }

    /* Validate by type */
    const char *part_id = json_string_value(json_object_get(jpart, "partId"));
    const char *blob_id = jmap_id_string_value(req, json_object_get(jpart, "blobId"));
    json_t *bodyValue = part_id ? json_object_get(bodies, part_id) : NULL;

    if (part_id && blob_id)
        jmap_parser_invalid(parser, "blobId");
    if (part_id && !bodyValue)
        jmap_parser_invalid(parser, "partId");

    if (subParts || (part->type && !strcasecmp(part->type, "MULTIPART"))) {
        /* Must have subParts */
        if (!json_array_size(subParts))
            jmap_parser_invalid(parser, "subParts");
        /* Must not have a body value */
        if (JNOTNULL(bodyValue))
            jmap_parser_invalid(parser, "partId");
        /* Must not have a blobId */
        if (blob_id)
            jmap_parser_invalid(parser, "blobId");
    }
    else if (part_id || (part->type && !strcasecmp(part->type, "TEXT"))) {
        /* Must have a text body as blob or bodyValue */
        if ((bodyValue == NULL) == (blob_id == NULL))
            jmap_parser_invalid(parser, "blobId");
        /* Must not have sub parts */
        if (JNOTNULL(subParts))
            jmap_parser_invalid(parser, "subParts");
    }
    else {
        /* Must have a blob id */
        if (!blob_id)
            jmap_parser_invalid(parser, "blobId");
        /* Must not have a text body */
        if (bodyValue)
            jmap_parser_invalid(parser, "partId");
        /* Must not have sub parts */
        if (JNOTNULL(subParts))
            jmap_parser_invalid(parser, "subParts");
    }

    buf_free(&buf);

    if (json_array_size(parser->invalid)) {
        _emailpart_fini(part);
        free(part);
        return NULL;
    }

    /* Finalize part definition */
    part->jbody = json_incref(bodyValue);

    return part;
}

static struct emailpart *_emailpart_new_multi(const char *subtype,
                                               ptrarray_t *subparts)
{
    struct emailpart *part = xzmalloc(sizeof(struct emailpart));
    int i;

    part->type = xstrdup("multipart");
    part->subtype = xstrdup(subtype);
    part->boundary = _mime_make_boundary();
    struct buf val = BUF_INITIALIZER;
    buf_printf(&val, "%s/%s;boundary=%s",
            part->type, part->subtype, part->boundary);
    _headers_add_new(&part->headers,
            _header_make("Content-Type", NULL, &val));
    for (i = 0; i < subparts->count; i++)
        ptrarray_append(&part->subparts, ptrarray_nth(subparts, i));

    return part;
}

static struct emailpart *_email_buildbody(struct emailpart *text_body,
                                          struct emailpart *html_body,
                                          ptrarray_t *attachments)
{
    struct emailpart *root = NULL;

    /* Split attachments into inlined, emails and other files */
    ptrarray_t attached_emails = PTRARRAY_INITIALIZER;
    ptrarray_t attached_files = PTRARRAY_INITIALIZER;
    ptrarray_t inlined_files = PTRARRAY_INITIALIZER;
    int i;
    for (i = 0; i < attachments->count; i++) {
        struct emailpart *part = ptrarray_nth(attachments, i);
        if (part->type && !strcasecmp(part->type, "MESSAGE")) {
            ptrarray_append(&attached_emails, part);
        }
        else if (part->disposition && !strcasecmp(part->disposition, "INLINE") &&
                 (text_body || html_body)) {
            ptrarray_append(&inlined_files, part);
        }
        else {
            ptrarray_append(&attached_files, part);
        }
    }

    /* Make MIME part for embedded emails. */
    struct emailpart *emails = NULL;
    if (attached_emails.count >= 2)
        emails = _emailpart_new_multi("digest", &attached_emails);
    else if (attached_emails.count == 1)
        emails = ptrarray_nth(&attached_emails, 0);

    /* Make MIME part for text bodies. */
    struct emailpart *text = NULL;
    if (text_body && html_body) {
        ptrarray_t alternatives = PTRARRAY_INITIALIZER;
        ptrarray_append(&alternatives, text_body);
        ptrarray_append(&alternatives, html_body);
        text = _emailpart_new_multi("alternative", &alternatives);
        ptrarray_fini(&alternatives);
    }
    else if (text_body)
        text = text_body;
    else if (html_body)
        text = html_body;

    /* Make MIME part for inlined attachments, if any. */
    if (text && inlined_files.count) {
        struct emailpart *related = _emailpart_new_multi("related", &inlined_files);
        ptrarray_insert(&related->subparts, 0, text);
        text = related;
    }

    /* Choose top-level MIME part. */
    if (attached_files.count) {
        struct emailpart *mixed = _emailpart_new_multi("mixed", &attached_files);
        if (emails) ptrarray_insert(&mixed->subparts, 0, emails);
        if (text) ptrarray_insert(&mixed->subparts, 0, text);
        root = mixed;
    }
    else if (text && emails) {
        ptrarray_t wrapped = PTRARRAY_INITIALIZER;
        ptrarray_append(&wrapped, text);
        ptrarray_append(&wrapped, emails);
        root = _emailpart_new_multi("mixed", &wrapped);
        ptrarray_fini(&wrapped);
    }
    else if (text)
        root = text;
    else if (emails)
        root = emails;
    else
        root = NULL;

    ptrarray_fini(&attached_emails);
    ptrarray_fini(&attached_files);
    ptrarray_fini(&inlined_files);
    return root;
}


static void _email_parse_bodies(jmap_req_t *req,
                                json_t *jemail,
                                struct jmap_parser *parser,
                                struct email *email)
{
    /* bodyValues */
    json_t *bodyValues = json_object_get(jemail, "bodyValues");
    if (json_is_object(bodyValues)) {
        const char *part_id;
        json_t *bodyValue;
        jmap_parser_push(parser, "bodyValues");
        json_object_foreach(bodyValues, part_id, bodyValue) {
            jmap_parser_push(parser, part_id);
            if (json_is_object(bodyValue)) {
                json_t *jval = json_object_get(bodyValue, "value");
                if (!json_is_string(jval)) {
                    jmap_parser_invalid(parser, "value");
                }
                jval = json_object_get(bodyValue, "isEncodingProblem");
                if (JNOTNULL(jval) && jval != json_false()) {
                    jmap_parser_invalid(parser, "isEncodingProblem");
                }
                jval = json_object_get(bodyValue, "isTruncated");
                if (JNOTNULL(jval) && jval != json_false()) {
                    jmap_parser_invalid(parser, "isTruncated");
                }
            }
            else {
                jmap_parser_invalid(parser, NULL);
            }
            jmap_parser_pop(parser);
        }
        jmap_parser_pop(parser);
    }
    else if (JNOTNULL(bodyValues)) {
        jmap_parser_invalid(parser, "bodyValues");
    }

    /* bodyStructure */
    json_t *jbody = json_object_get(jemail, "bodyStructure");
    if (json_is_object(jbody)) {
        jmap_parser_push(parser, "bodyStructure");
        email->body = _emailpart_parse(req, jbody, parser, bodyValues);
        jmap_parser_pop(parser);
        /* Top-level body part MUST NOT redefine headers in Email */
        if (email->body) {
            const char *name;
            json_t *jheader;
            json_object_foreach(email->body->headers.all, name, jheader) {
                if (json_object_get(email->headers.all, name)) {
                    /* Report offending header property */
                    json_t *jprop = json_object_get(jheader, "prop");
                    const char *prop = json_string_value(jprop);
                    if (prop) prop = "bodyStructure";
                    jmap_parser_invalid(parser, prop);
                }
            }
        }
    }
    else if (JNOTNULL(jbody)) {
        jmap_parser_invalid(parser, "bodyStructure");
    }

    json_t *jtextBody = json_object_get(jemail, "textBody");
    json_t *jhtmlBody = json_object_get(jemail, "htmlBody");
    json_t *jattachments = json_object_get(jemail, "attachments");

    struct emailpart *text_body = NULL;
    struct emailpart *html_body = NULL;
    ptrarray_t attachments = PTRARRAY_INITIALIZER; /* array of struct emailpart* */

    if (JNOTNULL(jbody)) {
        /* bodyStructure and fooBody are mutually exclusive */
        if (JNOTNULL(jtextBody)) {
            jmap_parser_invalid(parser, "textBody");
        }
        if (JNOTNULL(jhtmlBody)) {
            jmap_parser_invalid(parser, "htmlBody");
        }
        if (JNOTNULL(jattachments)) {
            jmap_parser_invalid(parser, "attachments");
        }
    }
    else {
        /* textBody */
        if (json_array_size(jtextBody) == 1) {
            json_t *jpart = json_array_get(jtextBody, 0);
            jmap_parser_push_index(parser, "textBody", 0, NULL);
            text_body = _emailpart_parse(req, jpart, parser, bodyValues);
            if (text_body) {
                if (!text_body->type) {
                    /* Set default type */
                    text_body->type = xstrdup("text");
                    text_body->subtype = xstrdup("plain");
                    struct buf val = BUF_INITIALIZER;
                    buf_setcstr(&val, "text/plain");
                    _headers_add_new(&text_body->headers,
                            _header_make("Content-Type", NULL, &val));
                }
                else if (strcasecmp(text_body->type, "text") ||
                         strcasecmp(text_body->subtype, "plain")) {
                    jmap_parser_invalid(parser, "type");
                }
            }
            jmap_parser_pop(parser);
        }
        else if (JNOTNULL(jtextBody)) {
            jmap_parser_invalid(parser, "textBody");
        }
        /* htmlBody */
        if (json_array_size(jhtmlBody) == 1) {
            json_t *jpart = json_array_get(jhtmlBody, 0);
            jmap_parser_push_index(parser, "htmlBody", 0, NULL);
            html_body = _emailpart_parse(req, jpart, parser, bodyValues);
            jmap_parser_pop(parser);
            if (html_body) {
                if (!html_body->type) {
                    /* Set default type */
                    html_body->type = xstrdup("text");
                    html_body->subtype = xstrdup("html");
                    struct buf val = BUF_INITIALIZER;
                    buf_setcstr(&val, "text/html");
                    _headers_add_new(&html_body->headers,
                            _header_make("Content-Type", NULL, &val));
                }
                else if (strcasecmp(html_body->type, "text") ||
                         strcasecmp(html_body->subtype, "html")) {
                    jmap_parser_invalid(parser, "htmlBody");
                }
            }
        }
        else if (JNOTNULL(jhtmlBody)) {
            jmap_parser_invalid(parser, "htmlBody");
        }
        /* attachments */
        if (json_is_array(jattachments)) {
            size_t i;
            json_t *jpart;
            struct emailpart *attpart;
            int have_inlined = 0;
            json_array_foreach(jattachments, i, jpart) {
                jmap_parser_push_index(parser, "attachments", i, NULL);
                attpart = _emailpart_parse(req, jpart, parser, bodyValues);
                if (attpart) {
                    if (!have_inlined && attpart->disposition) {
                        have_inlined = !strcasecmp(attpart->disposition, "INLINE");
                    }
                    ptrarray_append(&attachments, attpart);
                }
                jmap_parser_pop(parser);
            }
            if (have_inlined && !html_body) {
                /* Reject inlined attachments without a HTML body. The client
                 * is free to produce whatever it wants by setting bodyStructure,
                 * but for the convenience properties we require sane inputs. */
                jmap_parser_invalid(parser, "htmlBody");
            }
        }
        else if (JNOTNULL(jattachments)) {
            jmap_parser_invalid(parser, "attachments");
        }
    }

    /* calendarEvents is read-only */
    if (JNOTNULL(json_object_get(jemail, "calendarEvents"))) {
        jmap_parser_invalid(parser, "calendarEvents");
    }

    /* previousCalendarEvent is read-only */
    if (JNOTNULL(json_object_get(jemail, "previousCalendarEvent"))) {
        jmap_parser_invalid(parser, "previousCalendarEvent");
    }

    if (!email->body) {
        /* Build email body from convenience body properties */
        email->body = _email_buildbody(text_body, html_body, &attachments);
    }

    ptrarray_fini(&attachments);

    /* Look through all parts if any part is an attachment.
     * If so, set the hasAttachment flag. */
    if (email->body) {
        ptrarray_t work = PTRARRAY_INITIALIZER;
        ptrarray_append(&work, email->body);

        while (!email->has_attachment && work.count) {
            struct emailpart *part = ptrarray_pop(&work);
            if (part->disposition && strcasecmp(part->disposition, "INLINE")) {
                email->has_attachment = 1;
            }
            else if (part->filename) {
                email->has_attachment = 1;
            }
            else if (part->type && strcasecmp(part->type, "TEXT") &&
                     strcasecmp(part->type, "MULTIPART") &&
                     (!part->disposition || strcasecmp(part->disposition, "INLINE"))) {
                email->has_attachment = 1;
            }
            else if (part->blob_id && (!part->type || strcasecmp(part->type, "TEXT"))) {
                email->has_attachment = 1;
            }
            else {
                int i;
                for (i = 0; i < part->subparts.count; i++) {
                    struct emailpart *subpart = ptrarray_nth(&part->subparts, i);
                    ptrarray_append(&work, subpart);
                }
            }
        }
        ptrarray_fini(&work);
    }
}

static void _email_snoozed_parse(json_t *snoozed,
                                 struct jmap_parser *parser)
{
    const char *field;
    json_t *jval;

    jmap_parser_push(parser, "snoozed");
    json_object_foreach(snoozed, field, jval) {
        if (!strcmp(field, "until")) {
            if (!json_is_utcdate(jval)) {
                jmap_parser_invalid(parser, "until");
            }
        }
        else if (!strcmp(field, "setKeywords")) {
            const char *keyword;
            json_t *jbool;

            jmap_parser_push(parser, "setKeywords");
            json_object_foreach(jval, keyword, jbool) {
                if (!json_is_boolean(jbool) ||
                    !jmap_email_keyword_is_valid(keyword)) {
                    jmap_parser_invalid(parser, keyword);
                }
            }
            jmap_parser_pop(parser);
        }
        else if (strcmp(field, "moveToMailboxId")) {
            jmap_parser_invalid(parser, field);
        }
    }
    jmap_parser_pop(parser);
}

/* Parse a JMAP Email into its internal representation for creation. */
static void _parse_email(jmap_req_t *req,
                         json_t *jemail,
                         struct jmap_parser *parser,
                         struct email *email)
{
    email->jemail = json_incref(jemail);

    /* mailboxIds */
    json_t *jmailboxIds = json_object_get(jemail, "mailboxIds");
    if (json_object_size(jmailboxIds)) {
        const char *mailboxid;
        json_t *jval;
        jmap_parser_push(parser, "mailboxIds");
        json_object_foreach(jmailboxIds, mailboxid, jval) {
            if (*mailboxid == '\0' || jval != json_true()) {
                jmap_parser_invalid(parser, NULL);
                break;
            }
        }
        jmap_parser_pop(parser);
    }
    else {
        jmap_parser_invalid(parser, "mailboxIds");
    }

    /* keywords */
    json_t *jkeywords = json_object_get(jemail, "keywords");
    if (json_is_object(jkeywords)) {
        const char *keyword;
        json_t *jval;
        jmap_parser_push(parser, "keywords");
        json_object_foreach(jkeywords, keyword, jval) {
            if (jval != json_true() || !jmap_email_keyword_is_valid(keyword)) {
                jmap_parser_invalid(parser, keyword);
            }
        }
        jmap_parser_pop(parser);
    }
    else if (JNOTNULL(jkeywords)) {
        jmap_parser_invalid(parser, "keywords");
    }

    /* headers */
    if (JNOTNULL(json_object_get(jemail, "headers"))) {
        jmap_parser_invalid(parser, "headers");
    }
    /* header:Xxx */
    _headers_parseprops(jemail, parser, &email->headers);
    size_t i;
    json_t *jheader;
    json_array_foreach(email->headers.raw, i, jheader) {
        const char *name = json_string_value(json_object_get(jheader, "name"));
        const char *val = json_string_value(json_object_get(jheader, "value"));
        /* Reject Content-Xxx headers in Email/headers */
        if (!strncasecmp("Content-", name, 8)) {
            char *tmp = strconcat("header:", name, NULL);
            jmap_parser_invalid(parser, tmp);
            free(tmp);
        }
        else if (!strcasecmp("Message-ID", name) || !strcasecmp("In-Reply-To", name)) {
            /* conversations.db will barf if these are invalid raw headers,
             * so make sure we reject invalid values here. */
            if (conversations_check_msgid(val, strlen(val))) {
                char *tmp = strconcat("header:", name, NULL);
                jmap_parser_invalid(parser, tmp);
                free(tmp);
            }
        }
    }

    /* Parse convenience header properties - in order as serialised */
    struct buf buf = BUF_INITIALIZER;
    json_t *prop;
    int seen_header;

    /* messageId */
    prop = json_object_get(jemail, "messageId");
    seen_header = _headers_have(&email->headers, "Message-Id");
    if (json_array_size(prop) == 1 && !seen_header) {
        _headers_add_new(&email->headers, _header_from_messageids(prop,
                    parser, "messageId", "Message-Id", HEADER_FORM_MESSAGEIDS));
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "messageId");
    }
    /* inReplyTo */
    prop = json_object_get(jemail, "inReplyTo");
    seen_header = _headers_have(&email->headers, "In-Reply-To");
    if (json_is_array(prop) && !seen_header) {
        _headers_add_new(&email->headers, _header_from_messageids(prop,
                    parser, "inReplyTo", "In-Reply-To", HEADER_FORM_MESSAGEIDS));
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "inReplyTo");
    }
    /* references */
    prop = json_object_get(jemail, "references");
    seen_header = _headers_have(&email->headers, "References");
    if (json_is_array(prop) && !seen_header) {
        _headers_add_new(&email->headers, _header_from_messageids(prop,
                    parser, "references", "References", HEADER_FORM_MESSAGEIDS));
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "references");
    }
    /* sentAt */
    prop = json_object_get(jemail, "sentAt");
    seen_header = _headers_have(&email->headers, "Date");
    if (json_is_string(prop) && !seen_header) {
        _headers_add_new(&email->headers, _header_from_date(prop,
                    parser, "sentAt", "Date", HEADER_FORM_DATE));
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "sentAt");
    }
    /* receivedAt */
    prop = json_object_get(jemail, "receivedAt");
    if (json_is_utcdate(prop)) {
        time_from_iso8601(json_string_value(prop), &email->internaldate);
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "receivedAt");
    }
    /* from */
    prop = json_object_get(jemail, "from");
    seen_header = _headers_have(&email->headers, "From");
    if (json_is_array(prop) && !seen_header) {
        if ((jheader = _header_from_addresses(prop, parser, "from",
                        "From", HEADER_FORM_ADDRESSES))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "from");
    }
    /* replyTo */
    prop = json_object_get(jemail, "replyTo");
    seen_header = _headers_have(&email->headers, "Reply-To");
    if (json_is_array(prop) && !seen_header) {
        if ((jheader = _header_from_addresses(prop, parser, "replyTo",
                        "Reply-To", HEADER_FORM_ADDRESSES))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "replyTo");
    }
    /* sender */
    prop = json_object_get(jemail, "sender");
    seen_header = _headers_have(&email->headers, "Sender");
    if (json_is_array(prop) && !seen_header) {
        if ((jheader = _header_from_addresses(prop, parser, "sender",
                        "Sender", HEADER_FORM_ADDRESSES))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "sender");
    }
    /* to */
    prop = json_object_get(jemail, "to");
    seen_header = _headers_have(&email->headers, "To");
    if (json_is_array(prop) && !seen_header) {
        if ((jheader = _header_from_addresses(prop, parser, "to",
                        "To", HEADER_FORM_ADDRESSES))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "to");
    }
    /* cc */
    prop = json_object_get(jemail, "cc");
    seen_header = _headers_have(&email->headers, "Cc");
    if (json_is_array(prop) && !seen_header) {
        if ((jheader = _header_from_addresses(prop, parser, "cc",
                        "Cc", HEADER_FORM_ADDRESSES))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "cc");
    }
    /* bcc */
    prop = json_object_get(jemail, "bcc");
    seen_header = _headers_have(&email->headers, "Bcc");
    if (json_is_array(prop) && !seen_header) {
        if ((jheader = _header_from_addresses(prop, parser, "bcc",
                        "Bcc", HEADER_FORM_ADDRESSES))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "bcc");
    }
    /* subject */
    prop = json_object_get(jemail, "subject");
    seen_header = _headers_have(&email->headers, "Subject");
    if (json_is_string(prop) && !seen_header) {
        if ((jheader = _header_from_text(prop, parser, "subject",
                        "Subject", HEADER_FORM_TEXT))) {
            _headers_add_new(&email->headers, jheader);
        }
    }
    else if (JNOTNULL(prop)) {
        jmap_parser_invalid(parser, "subject");
    }
    buf_free(&buf);

    /* Parse bodies */
    _email_parse_bodies(req, jemail, parser, email);

    /* Is snoozed being set? */
    json_t *snoozed = json_object_get(jemail, "snoozed");
    if (json_is_object(snoozed)) {
        _email_snoozed_parse(snoozed, parser);
    }
    else if (JNOTNULL(snoozed)) {
        jmap_parser_invalid(parser, "snoozed");
    }
    email->snoozed = snoozed;
}

static void _emailpart_blob_to_mime(jmap_req_t *req,
                                    FILE *fp,
                                    struct emailpart *emailpart,
                                    json_t *missing_blobs)
{
    const char *content = NULL;
    size_t content_size = 0;
    const char *src_encoding = NULL;
    const char *encoding = NULL;
    char *encbuf = NULL;
    int r = 0;

    /* Find body part containing blob */
    jmap_getblob_context_t ctx;
    jmap_getblob_ctx_init(&ctx, NULL, emailpart->blob_id, NULL, 0);
    r = jmap_getblob(req, &ctx);
    if (r) goto done;

    /* Fetch blob contents and headers */
    content = buf_base(&ctx.blob);
    content_size = buf_len(&ctx.blob);

    /* Determine target encoding */
    encoding = src_encoding = buf_cstring(&ctx.encoding);

    if (!strcasecmpsafe(emailpart->type, "MESSAGE")) {
        if (!strcasecmpsafe(src_encoding, "BASE64")) {
            /* This is a MESSAGE and hence it is only allowed
             * to be in 7bit, 8bit or binary encoding. Base64
             * is not allowed, so let's decode the blob and
             * assume it to be in binary encoding. */
            encoding = "BINARY";
            content = charset_decode_mimebody(content, content_size,
                    ENCODING_BASE64, &encbuf, &content_size);
        }
    }
    else if (strcasecmpsafe(src_encoding, "QUOTED-PRINTABLE") &&
             strcasecmpsafe(src_encoding, "BASE64")) {
        /* Encode text to quoted-printable, if it isn't an attachment */
        if (!strcasecmpsafe(emailpart->type, "TEXT") &&
            (!strcasecmpsafe(emailpart->subtype, "PLAIN") ||
             !strcasecmpsafe(emailpart->subtype, "HTML")) &&
            (!emailpart->disposition || !strcasecmp(emailpart->disposition, "INLINE"))) {
            encoding = "QUOTED-PRINTABLE";
            size_t lenqp = 0;
            encbuf = charset_qpencode_mimebody(content, content_size, 0, &lenqp);
            content = encbuf;
            content_size = lenqp;
        }
        /* Encode all other types to base64 */
        else {
            encoding = "BASE64";
            size_t len64 = 0;
            /* Pre-flight encoder to determine length */
            charset_encode_mimebody(NULL, content_size, NULL, &len64, NULL, 1 /* wrap */);
            if (len64) {
                /* Now encode the body */
                encbuf = xmalloc(len64);
                charset_encode_mimebody(content, content_size, encbuf, &len64, NULL, 1 /* wrap */);
            }
            content = encbuf;
            content_size = len64;
        }
    }

    /* Write headers defined by client. */
    size_t i;
    json_t *jheader;
    json_array_foreach(emailpart->headers.raw, i, jheader) {
        json_t *jval = json_object_get(jheader, "name");
        const char *name = json_string_value(jval);
        jval = json_object_get(jheader, "value");
        const char *value = json_string_value(jval);
        fprintf(fp, "%s: %s\r\n", name, value);
    }

    /* Write encoding header, if required */
    if (encoding) {
        fputs("Content-Transfer-Encoding: ", fp);
        fputs(encoding, fp);
        fputs("\r\n", fp);
    }
    /* Write body */
    fputs("\r\n", fp);
    if (content_size) fwrite(content, 1, content_size, fp);
    free(encbuf);

done:
    if (r) json_array_append_new(missing_blobs, json_string(emailpart->blob_id));
    jmap_getblob_ctx_fini(&ctx);
}

static void _emailpart_text_to_mime(FILE *fp, struct emailpart *part)
{
    json_t *jval = json_object_get(part->jbody, "value");
    const char *text = json_string_value(jval);
    size_t len = strlen(text);

    /* Check and sanitise text */
    int has_long_lines = 0;
    int is_7bit = 1;
    const char *p = text;
    const char *base = text;
    const char *top = text + len;
    const char *last_lf = p;
    struct buf txtbuf = BUF_INITIALIZER;
    for (p = base; p < top; p++) {
        /* Keep track of line-length and high-bit bytes */
        if (p - last_lf > 998)
            has_long_lines = 1;
        if (*p == '\n')
            last_lf = p;
        if (*p & 0x80)
            is_7bit = 0;
        /* Omit CR */
        if (*p == '\r')
            continue;
        /* Expand LF to CRLF */
        if (*p == '\n')
            buf_putc(&txtbuf, '\r');
        buf_putc(&txtbuf, *p);
    }
    const char *charset = NULL;
    if (!is_7bit) charset = "utf-8";

    /* Write headers */
    size_t i;
    json_t *jheader;
    json_array_foreach(part->headers.raw, i, jheader) {
        json_t *jval = json_object_get(jheader, "name");
        const char *name = json_string_value(jval);
        jval = json_object_get(jheader, "value");
        const char *value = json_string_value(jval);
        if (!strcasecmp(name, "Content-Type") && charset) {
            /* Clients are forbidden to set charset on TEXT bodies,
             * so make sure we properly set the parameter value. */
            fprintf(fp, "%s: %s;charset=%s\r\n", name, value, charset);
        }
        else {
            fprintf(fp, "%s: %s\r\n", name, value);
        }
    }
    /* Write body */
    if (!is_7bit || has_long_lines) {
        /* Write quoted printable */
        size_t qp_len = 0;
        char *qp_text = charset_qpencode_mimebody(txtbuf.s, txtbuf.len, 1, &qp_len);
        fputs("Content-Transfer-Encoding: quoted-printable\r\n", fp);
        fputs("\r\n", fp);
        fwrite(qp_text, 1, qp_len, fp);
        free(qp_text);
    }
    else {
        /*  Write plain */
        fputs("\r\n", fp);
        fwrite(buf_cstring(&txtbuf), 1, buf_len(&txtbuf), fp);
    }

    buf_free(&txtbuf);
}

static void _emailpart_to_mime(jmap_req_t *req, FILE *fp,
                               struct emailpart *part,
                               json_t *missing_blobs)
{
    if (part->subparts.count) {
        /* Write raw headers */
        size_t i;
        json_t *jheader;
        json_array_foreach(part->headers.raw, i, jheader) {
            json_t *jval = json_object_get(jheader, "name");
            const char *name = json_string_value(jval);
            jval = json_object_get(jheader, "value");
            const char *value = json_string_value(jval);
            fprintf(fp, "%s: %s\r\n", name, value);
        }
        /* Write default Content-Type, if not set */
        if (!_headers_have(&part->headers, "Content-Type")) {
            part->boundary = _mime_make_boundary();
            fputs("Content-Type: multipart/mixed;boundary=", fp);
            fputs(part->boundary, fp);
            fputs("\r\n", fp);
        }
        /* Write sub parts */
        int j;
        int is_digest = part->type && !strcasecmp(part->type, "MULTIPART") &&
                        part->subtype && !strcasecmp(part->subtype, "DIGEST");
        for (j = 0; j < part->subparts.count; j++) {
            struct emailpart *subpart = ptrarray_nth(&part->subparts, j);
            if (is_digest && !subpart->type && subpart->blob_id) {
                /* multipart/digest changes the default content type of this
                 * part from text/plain to message/rfc822, so make sure that
                 * emailpart_blob_to_mime will properly deal with it */
                subpart->type = xstrdup("MESSAGE");
                subpart->subtype = xstrdup("RFC822");
            }
            fprintf(fp, "\r\n--%s\r\n", part->boundary);
            _emailpart_to_mime(req, fp, subpart, missing_blobs);
        }
        fprintf(fp, "\r\n--%s--\r\n", part->boundary);
    }
    else if (part->jbody) {
        _emailpart_text_to_mime(fp, part);
    }
    else if (part->blob_id) {
        _emailpart_blob_to_mime(req, fp, part, missing_blobs);
    }
}

static int _email_have_toplevel_header(struct email *email, const char *lcasename)
{
    json_t *header = json_object_get(email->headers.all, lcasename);
    if (!header && email->body) {
        header = json_object_get(email->body->headers.all, lcasename);
    }
    return JNOTNULL(header);
}

static int _email_to_mime(jmap_req_t *req, FILE *fp, void *rock, json_t **err)
{
    struct email *email = rock;
    json_t *header;
    size_t i;

    /* Set mandatory and quasi-mandatory headers */
    if (!_email_have_toplevel_header(email, "mime-version")) {
        header = json_pack("{s:s s:s}", "name", "Mime-Version", "value", "1.0");
        _headers_shift_new(&email->headers, header);
    }
    if (!_email_have_toplevel_header(email, "user-agent")) {
        char *tmp = strconcat("Cyrus-JMAP/", CYRUS_VERSION, NULL);
        header = json_pack("{s:s s:s}", "name", "User-Agent", "value", tmp);
        _headers_shift_new(&email->headers, header);
        free(tmp);
    }
    if (!_email_have_toplevel_header(email, "message-id")) {
        struct buf buf = BUF_INITIALIZER;
        buf_printf(&buf, "<%s@%s>", makeuuid(), config_servername);
        header = json_pack("{s:s s:s}", "name", "Message-Id", "value", buf_cstring(&buf));
        _headers_shift_new(&email->headers, header);
        buf_free(&buf);
    }
    if (!_email_have_toplevel_header(email, "date")) {
        char fmt[RFC5322_DATETIME_MAX+1];
        memset(fmt, 0, RFC5322_DATETIME_MAX+1);
        time_to_rfc5322(time(NULL), fmt, RFC5322_DATETIME_MAX+1);
        header = json_pack("{s:s s:s}", "name", "Date", "value", fmt);
        _headers_shift_new(&email->headers, header);
    }
    if (!_email_have_toplevel_header(email, "from")) {
        header = json_pack("{s:s s:s}", "name", "From", "value", req->userid);
        _headers_shift_new(&email->headers, header);
    }

    /* Write headers */
    json_array_foreach(email->headers.raw, i, header) {
        json_t *jval;
        jval = json_object_get(header, "name");
        const char *name = json_string_value(jval);
        jval = json_object_get(header, "value");
        const char *value = json_string_value(jval);
        fprintf(fp, "%s: %s\r\n", name, value);
    }

    json_t *missing_blobs = json_array();
    if (email->body) _emailpart_to_mime(req, fp, email->body, missing_blobs);
    if (json_array_size(missing_blobs)) {
        *err = json_pack("{s:s s:o}", "type", "blobNotFound",
                "notFound", missing_blobs);
    }
    else {
        json_decref(missing_blobs);
    }

    return 0;
}

static void _append_validate_mboxids(jmap_req_t *req,
                                     json_t *jmailboxids,
                                     struct jmap_parser *parser,
                                     int *have_snoozed_mboxid)
{
    const char *snoozed_mboxname = NULL, *snoozed_uniqueid = NULL;
    const mbentry_t *snoozed_mbe = NULL;
    const char *scheduled_uniqueid = NULL;
    const mbentry_t *scheduled_mbe = NULL;
    const char *mbox_id;
    json_t *jval;
    void *tmp;

    jmap_findmbox_role(req, "snoozed", &snoozed_mbe);
    if (snoozed_mbe) {
        snoozed_mboxname = snoozed_mbe->name;
        snoozed_uniqueid = snoozed_mbe->uniqueid;
    }
    jmap_findmbox_role(req, "scheduled", &scheduled_mbe);
    if (scheduled_mbe) {
        scheduled_uniqueid = scheduled_mbe->uniqueid;
    }

    jmap_parser_push(parser, "mailboxIds");
    json_object_foreach_safe(jmailboxids, tmp, mbox_id, jval) {
        int need_rights = JACL_LOOKUP|JACL_ADDITEMS;
        int is_valid = 1;
        if (*mbox_id == '$') {
            /* Lookup mailbox by role */
            const char *role = mbox_id + 1;
            const mbentry_t *mbentry = NULL;
            if (snoozed_uniqueid && !strcmp(role, "snoozed") &&
                jmap_hasrights(req, snoozed_mboxname, need_rights)) {
                /* Flag this mailboxId as being $snoozed */
                json_object_del(jmailboxids, mbox_id);
                json_object_set_new(jmailboxids,
                                    snoozed_uniqueid, json_string("$snoozed"));
                *have_snoozed_mboxid = 1;
            }
            else if (!strcmp(role, "scheduled")) {
                /* Don't allow create/import in $scheduled */
                jmap_parser_invalid(parser, NULL);
                is_valid = 0;
            }
            else if (!jmap_findmbox_role(req, role, &mbentry) &&
                jmap_hasrights(req, mbentry->name, need_rights)) {
                json_object_del(jmailboxids, mbox_id);
                json_object_set_new(jmailboxids, mbentry->uniqueid, json_true());
            }
            else {
                jmap_parser_invalid(parser, NULL);
                is_valid = 0;
            }
        }
        else {
            /* Lookup mailbox by id */
            const mbentry_t *mbentry = NULL;
            if (*mbox_id == '#') {
                mbox_id = jmap_lookup_id(req, mbox_id + 1);
            }
            if (mbox_id) {
                mbentry = jmap_mbentry_by_uniqueid(req, mbox_id);
            }
            if (!mbentry || mbentry->mbtype == MBTYPE_DELETED ||
                    mboxname_isdeletedmailbox(mbentry->name, NULL) ||
                    !jmap_hasrights_mbentry(req, mbentry, need_rights)) {
                jmap_parser_invalid(parser, NULL);
                is_valid = 0;
            }
            else if (!strcmpnull(snoozed_uniqueid, mbentry->uniqueid)) {
                /* Flag this mailboxId as being $snoozed */
                json_object_set_new(jmailboxids,
                                    mbox_id, json_string("$snoozed"));
                *have_snoozed_mboxid = 1;
            }
            else if (!strcmpnull(scheduled_uniqueid, mbentry->uniqueid)) {
                /* Don't allow create/import in $scheduled */
                jmap_parser_invalid(parser, NULL);
                is_valid = 0;
            }
        }
        if (!is_valid) break;
    }
    jmap_parser_pop(parser);
}

static void _email_create(jmap_req_t *req,
                          json_t *jemail,
                          json_t **new_email,
                          json_t **set_err)
{
    strarray_t keywords = STRARRAY_INITIALIZER;
    int r = 0, have_snoozed_mboxid = 0;
    *set_err = NULL;
    struct email_append_detail detail;
    memset(&detail, 0, sizeof(struct email_append_detail));

    /* Parse Email object into internal representation */
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct email email = { HEADERS_INITIALIZER, NULL, NULL, time(NULL), 0, NULL };
    _parse_email(req, jemail, &parser, &email);

    /* Validate mailboxIds */
    json_t *jmailboxids = json_copy(json_object_get(jemail, "mailboxIds"));
    _append_validate_mboxids(req, jmailboxids, &parser, &have_snoozed_mboxid);

    /* Validate snoozed + mailboxIds */
    if (json_is_object(email.snoozed) && !have_snoozed_mboxid) {
        jmap_parser_invalid(&parser, "snoozed");
    }
    if (json_array_size(parser.invalid)) {
        *set_err = json_pack("{s:s s:O}", "type", "invalidProperties",
                "properties", parser.invalid);
        goto done;
    }

    /* Gather keywords */
    json_t *jkeywords = json_object_get(jemail, "keywords");
    if (json_object_size(jkeywords)) {
        json_t *jval;
        const char *keyword;
        json_object_foreach(jkeywords, keyword, jval) {
            if (!strcasecmp(keyword, JMAP_HAS_ATTACHMENT_FLAG)) {
                continue;
            }
            strarray_append(&keywords, keyword);
        }
    }
    if (keywords.count > MAX_USER_FLAGS) {
        *set_err = json_pack("{s:s}",  "type", "tooManyKeywords");
        goto done;
    }

    /* Append MIME-encoded Email to mailboxes and write keywords */

    _email_append(req, jmailboxids, &keywords, email.internaldate, email.snoozed,
                  config_getswitch(IMAPOPT_JMAP_SET_HAS_ATTACHMENT) ?
                  email.has_attachment : 0, NULL, _email_to_mime, &email,
                  &detail, set_err);
    if (*set_err) goto done;

    /* Return newly created Email object */
    *new_email = json_pack("{s:s, s:s, s:s, s:i}",
         "id", detail.email_id,
         "blobId", detail.blob_id,
         "threadId", detail.thread_id,
         "size", detail.size);
    *set_err = NULL;

done:
    if (r && *set_err == NULL) {
        syslog(LOG_ERR, "jmap: email_create: %s", error_message(r));
        if (r == IMAP_QUOTA_EXCEEDED)
            *set_err = json_pack("{s:s}", "type", "overQuota");
        else
            *set_err = jmap_server_error(r);
    }
    json_decref(jmailboxids);
    strarray_fini(&keywords);
    jmap_parser_fini(&parser);
    _email_fini(&email);
}

static int _email_uidrec_compareuid_cb(const void **pa, const void **pb)
{
    const struct email_uidrec *a = *pa;
    const struct email_uidrec *b = *pb;
    if (a->uid < b->uid)
        return -1;
    else if (a->uid > b->uid)
        return 1;
    else
        return 0;
}

static void _email_mboxrec_free(struct email_mboxrec *mboxrec)
{
    struct email_uidrec *uidrec;
    while ((uidrec = ptrarray_pop(&mboxrec->uidrecs))) {
        free(uidrec->email_id);
        free(uidrec);
    }
    ptrarray_fini(&mboxrec->uidrecs);
    free(mboxrec->mboxname);
    free(mboxrec->mbox_id);
    free(mboxrec);
}

static void _email_mboxrecs_free(ptrarray_t **mboxrecsptr)
{
    if (mboxrecsptr == NULL || *mboxrecsptr == NULL) return;

    ptrarray_t *mboxrecs = *mboxrecsptr;
    int i;
    for (i = 0; i < ptrarray_size(mboxrecs); i++) {
        _email_mboxrec_free(ptrarray_nth(mboxrecs, i));
    }
    ptrarray_free(mboxrecs);
    *mboxrecsptr = NULL;
}

struct email_mboxrecs_make_rock {
    jmap_req_t *req;
    const char *email_id;
    ptrarray_t *mboxrecs;
};

static int _email_mboxrecs_read_cb(const conv_guidrec_t *rec, void *_rock)
{
    struct email_mboxrecs_make_rock *rock = _rock;
    ptrarray_t *mboxrecs = rock->mboxrecs;
    mbentry_t *mbentry = NULL;

    /* don't process emails that have this email attached! */
    if (rec->part) goto done;

    /* don't process emails that have been expunged */
    if ((rec->system_flags & FLAG_DELETED) ||
        (rec->internal_flags & FLAG_INTERNAL_EXPUNGED)) {
        goto done;
    }

    conv_guidrec_mbentry(rec, &mbentry);

    if (!jmap_hasrights_mbentry(rock->req, mbentry, JACL_READITEMS)) {
        goto done;
    }

    /* Check if there's already a mboxrec for this mailbox. */
    int i;
    struct email_mboxrec *mboxrec = NULL;
    for (i = 0; i < ptrarray_size(mboxrecs); i++) {
        struct email_mboxrec *p = ptrarray_nth(mboxrecs, i);
        if (!strcmp(mbentry->name, p->mboxname)) {
            mboxrec = p;
            break;
        }
    }
    if (mboxrec == NULL) {
        // we only want regular mailboxes!
        if (mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL) {
            goto done;
        }
        if (!jmap_hasrights_mbentry(rock->req, mbentry, JACL_READITEMS)) {
            goto done;
        }

        mboxrec = xzmalloc(sizeof(struct email_mboxrec));
        mboxrec->mboxname = xstrdup(mbentry->name);
        mboxrec->mbox_id = xstrdup(mbentry->uniqueid);
        ptrarray_append(mboxrecs, mboxrec);
    }

    struct email_uidrec *uidrec = xzmalloc(sizeof(struct email_uidrec));
    uidrec->mboxrec = mboxrec;
    uidrec->email_id = xstrdup(rock->email_id);
    uidrec->uid = rec->uid;
    uidrec->is_snoozed =
        ((rec->internal_flags & (FLAG_INTERNAL_SNOOZED | FLAG_INTERNAL_EXPUNGED))
         == FLAG_INTERNAL_SNOOZED);
    ptrarray_append(&mboxrec->uidrecs, uidrec);

done:
    mboxlist_entry_free(&mbentry);
    return 0;
}

static void _email_mboxrecs_read(jmap_req_t *req,
                                 struct conversations_state *cstate,
                                 strarray_t *email_ids,
                                 json_t *set_errors,
                                 ptrarray_t **mboxrecsptr)
{
    ptrarray_t *mboxrecs = ptrarray_new();

    int i;
    for (i = 0; i < strarray_size(email_ids); i++) {
        const char *email_id = strarray_nth(email_ids, i);
        if (email_id[0] != 'M' || strlen(email_id) != 25) {
            // not a valid emailId
            continue;
        }

        struct email_mboxrecs_make_rock rock = { req, email_id, mboxrecs };
        int r = conversations_guid_foreach(cstate, _guid_from_id(email_id),
                                           _email_mboxrecs_read_cb, &rock);
        if (r) {
            json_t *err = (r == IMAP_NOTFOUND || r == IMAP_PERMISSION_DENIED) ?
                json_pack("{s:s}", "notFound") : jmap_server_error(r);
            json_object_set_new(set_errors, email_id, err);
            _email_mboxrecs_free(&mboxrecs);
            return;
        }
    }

    // sort the UID lists
    for (i = 0; i < ptrarray_size(mboxrecs); i++) {
        struct email_mboxrec *p = ptrarray_nth(mboxrecs, i);
        ptrarray_sort(&p->uidrecs, _email_uidrec_compareuid_cb);
    }

    *mboxrecsptr = mboxrecs;
}

/* Parsed JMAP Email/set#{update} argument. */
struct email_update {
    const char *email_id;     /* Id of updated JMAP email */
    json_t *keywords;         /* JMAP Email/set keywords argument */
    int patch_keywords;       /* True if keywords is a patch object */
    json_t *full_keywords;    /* Patched JMAP keywords across index records */
    json_t *mailboxids;       /* JMAP Email/set mailboxIds argument */
    int patch_mailboxids;     /* True if mailboxids is a patch object */
    json_t *snoozed;          /* JMAP Email/set snoozed argument */
    int patch_snoozed;        /* True if snoozed is a patch object */
    struct email_uidrec *snoozed_uidrec; /* Currently snoozed email */
    char *snooze_in_mboxid;   /* Snooze the email in this mailboxid */
};

static void _email_update_free(struct email_update *update)
{
    json_decref(update->keywords);
    json_decref(update->full_keywords);
    json_decref(update->mailboxids);
    json_decref(update->snoozed);
    free(update->snooze_in_mboxid);
    free(update);
}

struct modified_flags {
    int added_flags;
    bit32 added_system_flags;
    bit32 added_user_flags[MAX_USER_FLAGS/32];
    int removed_flags;
    bit32 removed_system_flags;
    bit32 removed_user_flags[MAX_USER_FLAGS/32];
};

/* Overwrite or patch the JMAP keywords on message record mrw.
 * If add_seen_uids or del_seen_uids is not NULL, then
 * the record UID is added to respective sequence set,
 * if the flag must be set or deleted. */
static int _email_setflags(json_t *keywords, int patch_keywords,
                           msgrecord_t *mrw,
                           seqset_t *add_seen_uids,
                           seqset_t *del_seen_uids,
                           struct modified_flags *modflags)
{
    uint32_t internal_flags = 0;
    struct mailbox *mbox = NULL;
    uint32_t uid = 0;

    int r = msgrecord_get_mailbox(mrw, &mbox);
    if (r) return r;
    r = msgrecord_get_uid(mrw, &uid);
    if (r) goto done;
    r = msgrecord_get_internalflags(mrw, &internal_flags);
    if (r) goto done;
    if (internal_flags & FLAG_INTERNAL_EXPUNGED) goto done;

    uint32_t old_system_flags = 0;
    r = msgrecord_get_systemflags(mrw, &old_system_flags);
    if (r) goto done;

    uint32_t old_user_flags[MAX_USER_FLAGS/32];
    r = msgrecord_get_userflags(mrw, old_user_flags);
    if (r) goto done;

    /* Determine if to patch or reset flags */
    uint32_t new_system_flags = 0;
    uint32_t new_user_flags[MAX_USER_FLAGS/32];
    if (patch_keywords) {
        new_system_flags = old_system_flags;
        memcpy(new_user_flags, old_user_flags, sizeof(old_user_flags));
    }
    else {
        new_system_flags = (old_system_flags & ~FLAGS_SYSTEM) |
                           (old_system_flags & FLAG_DELETED);
        memset(new_user_flags, 0, sizeof(new_user_flags));
    }

    /* Update flags */
    json_t *jval;
    const char *keyword;
    json_object_foreach(keywords, keyword, jval) {
        if (!strcasecmp(keyword, "$Flagged")) {
            if (jval == json_true())
                new_system_flags |= FLAG_FLAGGED;
            else
                new_system_flags &= ~FLAG_FLAGGED;
        }
        else if (!strcasecmp(keyword, "$Answered")) {
            if (jval == json_true())
                new_system_flags |= FLAG_ANSWERED;
            else
                new_system_flags &= ~FLAG_ANSWERED;
        }
        else if (!strcasecmp(keyword, "$Seen")) {
            if (jval == json_true()) {
                if (add_seen_uids)
                    seqset_add(add_seen_uids, uid, 1);
                else
                    new_system_flags |= FLAG_SEEN;
            }
            else {
                if (del_seen_uids)
                    seqset_add(del_seen_uids, uid, 1);
                else
                    new_system_flags &= ~FLAG_SEEN;
            }
        }
        else if (!strcasecmp(keyword, "$Draft")) {
            if (jval == json_true())
                new_system_flags |= FLAG_DRAFT;
            else
                new_system_flags &= ~FLAG_DRAFT;
        }
        else {
            int userflag;
            r = mailbox_user_flag(mbox, keyword, &userflag, 1);
            if (r) goto done;
            if (jval == json_true())
                new_user_flags[userflag/32] |= 1<<(userflag&31);
            else
                new_user_flags[userflag/32] &= ~(1<<(userflag&31));
        }
    }
    if (!patch_keywords && del_seen_uids) {
        if (json_object_get(keywords, "$seen") == NULL) {
            seqset_add(del_seen_uids, uid, 1);
        }
    }

    /* Write flags to record */
    r = msgrecord_set_systemflags(mrw, new_system_flags);
    if (r) goto done;
    r = msgrecord_set_userflags(mrw, new_user_flags);
    if (r) goto done;
    r = msgrecord_rewrite(mrw);

    /* Determine flag delta */
    memset(modflags, 0, sizeof(struct modified_flags));
    modflags->added_system_flags = ~old_system_flags & new_system_flags & FLAGS_SYSTEM;
    if (modflags->added_system_flags) {
        modflags->added_flags = 1;
    }
    modflags->removed_system_flags = old_system_flags & ~new_system_flags & FLAGS_SYSTEM;
    if (modflags->removed_system_flags) {
        modflags->removed_flags = 1;
    }

    size_t i;
    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
        modflags->added_user_flags[i] = ~old_user_flags[i] & new_user_flags[i];
        if (modflags->added_user_flags[i]) {
            modflags->added_flags = 1;
        }
        modflags->removed_user_flags[i] = old_user_flags[i] & ~new_user_flags[i];
        if (modflags->removed_user_flags[i]) {
            modflags->removed_flags = 1;
        }
    }

done:
    return r;
}

struct email_bulkupdate {
    jmap_req_t *req;                /* JMAP Email/set request context */
    hash_table updates_by_email_id; /* Map to ptrarray of email_update */
    hash_table uidrecs_by_email_id; /* Map to ptrarray of email_uidrec, excluding expunged */
    hash_table plans_by_mbox_id;    /* Map to email_updateplan */
    json_t *set_errors;             /* JMAP SetError by email id */
    struct seen *seendb;            /* Seen database for shared mailboxes, or NULL */
    ptrarray_t *cur_mboxrecs;       /* List of current mbox and UI recs, including expunged */
    ptrarray_t *new_mboxrecs;       /* New mbox and UID records allocated by planner */
};

#define _EMAIL_BULKUPDATE_INITIALIZER {\
    NULL, \
    HASH_TABLE_INITIALIZER, \
    HASH_TABLE_INITIALIZER, \
    HASH_TABLE_INITIALIZER, \
    json_object(), \
    NULL, \
    NULL, \
    ptrarray_new() \
}

static void _email_update_parse(json_t *jemail,
                                struct jmap_parser *parser,
                                struct email_update *update)
{
    struct buf buf = BUF_INITIALIZER;

    /* Are keywords overwritten or patched? */
    json_t *keywords = json_object_get(jemail, "keywords");
    if (keywords == NULL) {
        /* Collect keywords as patch */
        const char *field = NULL;
        json_t *jval;
        keywords = json_object();
        json_object_foreach(jemail, field, jval) {
            if (strncmp(field, "keywords/", 9))  {
                continue;
            }
            const char *keyword = field + 9;
            if (!jmap_email_keyword_is_valid(keyword) || (jval != json_true() && jval != json_null())) {
                jmap_parser_push(parser, "keywords");
                jmap_parser_invalid(parser, keyword);
                jmap_parser_pop(parser);
                continue;
            }
            else if (!strcasecmp(keyword, JMAP_HAS_ATTACHMENT_FLAG)) {
                continue;
            }
            /* At least one keyword gets patched */
            update->patch_keywords = 1;
            /* Normalize keywords to lowercase */
            buf_setcstr(&buf, keyword);
            buf_lcase(&buf);
            json_object_set(keywords, buf_cstring(&buf), jval);
        }
        if (!json_object_size(keywords)) {
            json_decref(keywords);
            keywords = NULL;
        }
    }
    else if (json_is_object(keywords)) {
        /* Overwrite keywords */
        json_t *normalized_keywords = json_object();
        const char *keyword;
        json_t *jval;
        json_object_foreach(keywords, keyword, jval) {
            if (!jmap_email_keyword_is_valid(keyword) || jval != json_true()) {
                jmap_parser_push(parser, "keywords");
                jmap_parser_invalid(parser, keyword);
                jmap_parser_pop(parser);
                continue;
            }
            else if (!strcasecmp(keyword, JMAP_HAS_ATTACHMENT_FLAG)) {
                continue;
            }
            buf_setcstr(&buf, keyword);
            buf_lcase(&buf);
            json_object_set(normalized_keywords, buf_cstring(&buf), jval);
        }
        keywords = normalized_keywords;
    }
    else if (JNOTNULL(keywords)) {
        jmap_parser_invalid(parser, "keywords");
    }
    update->keywords = keywords;

    /* Are mailboxes being overwritten or patched? */
    json_t *mailboxids = json_copy(json_object_get(jemail, "mailboxIds"));
    if (mailboxids == NULL) {
        /* Collect mailboxids as patch */
        const char *field = NULL;
        json_t *jval;
        mailboxids = json_object();
        /* Check if mailboxIds are patched */
        json_object_foreach(jemail, field, jval) {
            if (strncmp(field, "mailboxIds/", 11)) {
                continue;
            }
            const char *mailboxid = field + 11;
            update->patch_mailboxids = 1;
            if (jval == json_true() || jval == json_null()) {
                json_object_set(mailboxids, mailboxid, jval);
            }
            else {
                jmap_parser_push(parser, "mailboxIds");
                jmap_parser_invalid(parser, mailboxid);
                jmap_parser_pop(parser);
            }
        }
        if (json_object_size(mailboxids) == 0) {
            json_decref(mailboxids);
            mailboxids = NULL;
        }
    }
    else if (!json_object_size(mailboxids)) {
        jmap_parser_invalid(parser, "mailboxIds");
    }
    else {
        const char *mailboxid = NULL;
        json_t *jval;
        json_object_foreach(mailboxids, mailboxid, jval) {
            if (jval != json_true()) {
                jmap_parser_push(parser, "mailboxIds");
                jmap_parser_invalid(parser, mailboxid);
                jmap_parser_pop(parser);
            }
        }
    }
    update->mailboxids = mailboxids;

    /* Is snoozed being overwritten or patched? */
    json_t *snoozed = json_copy(json_object_get(jemail, "snoozed"));
    if (snoozed == NULL) {
        /* Collect fields as patch */
        const char *field = NULL;
        json_t *jval;

        snoozed = json_object();
        json_object_foreach(jemail, field, jval) {
            int invalid = 0;

            if (strncmp(field, "snoozed/", 8)) {
                continue;
            }

            const char *subfield = field +8;
            if (!strcmp(subfield, "until")) {
                if (!json_is_utcdate(jval)) invalid = 1;
            }
            else if (!strncmp(subfield, "setKeywords/", 12)) {
                const char *keyword = subfield + 12;
                if (!(json_is_boolean(jval) || json_is_null(jval)) ||
                    !jmap_email_keyword_is_valid(keyword)) invalid = 1;
            }
            else if (!strcmp(subfield, "moveToMailboxId")) {
                if (!json_is_string(jval)) invalid = 1;
            }
            else invalid = 1;

            if (invalid) {
                jmap_parser_invalid(parser, field);
            }
            else {
                /* At least one field gets patched */
                update->patch_snoozed = 1;
                json_object_set(snoozed, subfield, jval);
            }
        }
        if (json_object_size(snoozed) == 0) {
            json_decref(snoozed);
            snoozed = NULL;
        }
    }
    else if (json_is_object(snoozed)) {
        _email_snoozed_parse(snoozed, parser);
    }
    else if (JNOTNULL(snoozed)) {
        jmap_parser_invalid(parser, "snoozed");
    }
    update->snoozed = snoozed;

    buf_free(&buf);
}

/* A plan to create, update or destroy messages per mailbox */
struct email_updateplan {
    char *mboxname;       /* Mailbox IMAP name */
    char *mbox_id;        /* Mailbox unique id */
    struct mailbox *mbox; /* Write-locked mailbox */
    ptrarray_t copy;      /* Array of array of email_uidrec, grouped by mailbox */
    ptrarray_t setflags;  /* Array of email_uidrec */
    ptrarray_t delete;    /* Array of email_uidrec */
    ptrarray_t snooze;    /* Array of email_uidrec */
    int needrights;       /* Required ACL bits set */
    int use_seendb;       /* Set if this mailbox requires seen.db */
    struct email_mboxrec *mboxrec; /* Mailbox record */
    struct seendata old_seendata;   /* Lock-read seen data from database */
    seqset_t *old_seenseq;     /* Parsed seen sequence before update */
};

void _email_updateplan_free_p(void* p)
{
    struct email_updateplan *plan = p;
    seqset_free(&plan->old_seenseq);
    seen_freedata(&plan->old_seendata);
    free(plan->mboxname);
    free(plan->mbox_id);
    ptrarray_t *tmp;
    while ((tmp = ptrarray_pop(&plan->copy))) {
        ptrarray_free((ptrarray_t*)tmp);
    }
    ptrarray_fini(&plan->copy);
    ptrarray_fini(&plan->setflags);
    ptrarray_fini(&plan->delete);
    ptrarray_fini(&plan->snooze);
    free(plan);
}

void _ptrarray_free_p(void *p)
{
    ptrarray_free((ptrarray_t*)p);
}


void _email_bulkupdate_close(struct email_bulkupdate *bulk)
{
    hash_iter *iter = hash_table_iter(&bulk->plans_by_mbox_id);
    while (hash_iter_next(iter)) {
        struct email_updateplan *plan = hash_iter_val(iter);
        jmap_closembox(bulk->req, &plan->mbox);
    }
    seen_close(&bulk->seendb); /* force-close on error */
    hash_iter_free(&iter);
    free_hash_table(&bulk->uidrecs_by_email_id, _ptrarray_free_p);
    free_hash_table(&bulk->updates_by_email_id, NULL);
    free_hash_table(&bulk->plans_by_mbox_id, _email_updateplan_free_p);
    _email_mboxrecs_free(&bulk->cur_mboxrecs);
    _email_mboxrecs_free(&bulk->new_mboxrecs);
    json_decref(bulk->set_errors);
}

static struct email_updateplan *_email_bulkupdate_addplan(struct email_bulkupdate *bulk,
                                                          struct mailbox *mbox,
                                                          struct email_mboxrec *mboxrec)
{
    struct email_updateplan *plan = xzmalloc(sizeof(struct email_updateplan));
    plan->mbox = mbox;
    plan->mbox_id = xstrdup(mailbox_uniqueid(mbox));
    plan->mboxname = xstrdup(mailbox_name(mbox));
    plan->mboxrec = mboxrec;
    plan->use_seendb = !mailbox_internal_seen(plan->mbox, bulk->req->userid);
    hash_insert(plan->mbox_id, plan, &bulk->plans_by_mbox_id);
    return plan;
}

static void _email_updateplan_error(struct email_updateplan *plan, int errcode, json_t *set_errors)
{
    json_t *err = jmap_server_error(errcode);
    int i;
    for (i = 0; i < ptrarray_size(&plan->copy); i++) {
        struct email_uidrec *uidrec = ptrarray_nth(&plan->copy, i);
        if (json_object_get(set_errors, uidrec->email_id)) {
            continue;
        }
        json_object_set(set_errors, uidrec->email_id, err);
    }
    for (i = 0; i < ptrarray_size(&plan->setflags); i++) {
        struct email_uidrec *uidrec = ptrarray_nth(&plan->setflags, i);
        if (json_object_get(set_errors, uidrec->email_id)) {
            continue;
        }
        json_object_set(set_errors, uidrec->email_id, err);
    }
    for (i = 0; i < ptrarray_size(&plan->delete); i++) {
        struct email_uidrec *uidrec = ptrarray_nth(&plan->delete, i);
        if (json_object_get(set_errors, uidrec->email_id)) {
            continue;
        }
        json_object_set(set_errors, uidrec->email_id, err);
    }
    for (i = 0; i < ptrarray_size(&plan->snooze); i++) {
        struct email_uidrec *uidrec = ptrarray_nth(&plan->snooze, i);
        if (json_object_get(set_errors, uidrec->email_id)) {
            continue;
        }
        json_object_set(set_errors, uidrec->email_id, err);
    }
    json_decref(err);
}

static int _email_bulkupdate_plan_mailboxids(struct email_bulkupdate *bulk, ptrarray_t *updates)
{
    hash_table copyupdates_by_mbox_id = HASH_TABLE_INITIALIZER;
    construct_hash_table(&copyupdates_by_mbox_id, ptrarray_size(updates)+1, 0);

    const mbentry_t *scheduled_mbe = NULL;
    const char *scheduled_id = NULL;

    jmap_findmbox_role(bulk->req, "scheduled", &scheduled_mbe);
    if (scheduled_mbe) {
        scheduled_id = scheduled_mbe->uniqueid;
    }

    int i;
    for (i = 0; i < ptrarray_size(updates); i++) {
        struct email_update *update = ptrarray_nth(updates, i);
        const char *email_id = update->email_id;

        if (json_object_get(bulk->set_errors, email_id)) {
            continue;
        }
        ptrarray_t *current_uidrecs = hash_lookup(email_id, &bulk->uidrecs_by_email_id);

        if (update->snooze_in_mboxid) {
            /* Update/delete existing snoozeDetails */

            if (update->snoozed) {
                /* Make a new copy of current snoozed message */
                ptrarray_t *copyupdates =
                    hash_lookup(update->snooze_in_mboxid,
                                &copyupdates_by_mbox_id);
                if (copyupdates == NULL) {
                    copyupdates = ptrarray_new();
                    hash_insert(update->snooze_in_mboxid,
                                copyupdates, &copyupdates_by_mbox_id);
                }
                ptrarray_append(copyupdates, update);
            }

            if (update->snoozed_uidrec &&
                !strcmp(update->snooze_in_mboxid,
                        update->snoozed_uidrec->mboxrec->mbox_id)) {
                /* Delete current snoozed message from mailbox */
                struct email_updateplan *plan =
                    hash_lookup(update->snooze_in_mboxid, &bulk->plans_by_mbox_id);
                ptrarray_append(&plan->delete, update->snoozed_uidrec);
                plan->needrights |= JACL_REMOVEITEMS;
            }
        }

        if (!update->mailboxids) {
            continue;
        }

        if (update->patch_mailboxids) {
            const char *mbox_id = NULL;
            json_t *jval = NULL;
            json_object_foreach(update->mailboxids, mbox_id, jval) {
                /* Patch the mailbox */
                if (jval == json_true()) {
                    /* Lookup the uid record of this email in this mailbox, can be NULL. */
                    struct email_uidrec *uidrec = NULL;
                    int j;
                    for (j = 0; j < ptrarray_size(current_uidrecs); j++) {
                        struct email_uidrec *tmp = ptrarray_nth(current_uidrecs, j);
                        if (!strcmp(mbox_id, tmp->mboxrec->mbox_id)) {
                            uidrec = tmp;
                            break;
                        }
                    }
                    if (uidrec) {
                        /* This email is patched to stay in it's mailbox. Whatever. */
                    }
                    else {
                        /* This is a new mailbox for this email. Copy it over. */
                        ptrarray_t *copyupdates = hash_lookup(mbox_id, &copyupdates_by_mbox_id);
                        if (copyupdates == NULL) {
                            copyupdates = ptrarray_new();
                            hash_insert(mbox_id, copyupdates, &copyupdates_by_mbox_id);
                        }
                        /* XXX  Use ptrarray_add() here to avoid duplicating
                           an update already done above via snooze */
                        ptrarray_add(copyupdates, update);
                    }
                }
                else {
                    /* Delete all instances of this email in this mailbox. */
                    struct email_updateplan *plan = hash_lookup(mbox_id, &bulk->plans_by_mbox_id);
                    int j;
                    for (j = 0; j < ptrarray_size(current_uidrecs); j++) {
                        struct email_uidrec *uidrec = ptrarray_nth(current_uidrecs, j);
                        if (!strcmp(mbox_id, uidrec->mboxrec->mbox_id)) {
                            ptrarray_append(&plan->delete, uidrec);

                            plan->needrights |=
                                !strcmpnull(scheduled_id, mbox_id) ? 0 : JACL_REMOVEITEMS;
                        }
                    }
                }
            }
        }
        else {
            json_t *mailboxids = json_deep_copy(update->mailboxids);
            int j;

            /* For all current uid records of this email, determine if to
             * keep, create or delete them in their respective mailbox. */

            for (j = 0; j < ptrarray_size(current_uidrecs); j++) {
                struct email_uidrec *uidrec = ptrarray_nth(current_uidrecs, j);
                struct email_mboxrec *mboxrec = uidrec->mboxrec;
                struct email_updateplan *plan = hash_lookup(mboxrec->mbox_id, &bulk->plans_by_mbox_id);
                json_t *keep = json_object_get(mailboxids, mboxrec->mbox_id);

                if (keep) {
                    /* Keep message in mailbox */
                    json_object_del(mailboxids, mboxrec->mbox_id);
                }
                else {
                    /* Delete message from mailbox */
                    ptrarray_append(&plan->delete, uidrec);
                    plan->needrights |=
                        !strcmpnull(scheduled_id, mboxrec->mbox_id) ? 0 : JACL_REMOVEITEMS;
                }
            }

            /* Copy message to any new mailboxes which weren't seen in uidrecs */
            const char *mbox_id;
            json_t *jval;
            json_object_foreach(mailboxids, mbox_id, jval) {
                ptrarray_t *copyupdates = hash_lookup(mbox_id, &copyupdates_by_mbox_id);
                if (copyupdates == NULL) {
                    copyupdates = ptrarray_new();
                    hash_insert(mbox_id, copyupdates, &copyupdates_by_mbox_id);
                }
                ptrarray_append(copyupdates, update);
            }
            json_decref(mailboxids);
        }
    }

    /* Cluster copy operations by mailbox */

    hash_iter *iter = hash_table_iter(&copyupdates_by_mbox_id);
    while (hash_iter_next(iter)) {
        const char *dst_mbox_id = hash_iter_key(iter);
        ptrarray_t *updates = hash_iter_val(iter);

        /* Determine the number of messages per source mailbox which
         * could be copied into the destination mailbox. */

        hash_table src_mbox_id_counts = HASH_TABLE_INITIALIZER;
        construct_hash_table(&src_mbox_id_counts, ptrarray_size(updates)*8+1, 0);
        int i;
        for (i = 0; i < ptrarray_size(updates); i++) {
            struct email_update *update = ptrarray_nth(updates, i);
            ptrarray_t *current_uidrecs = hash_lookup(update->email_id, &bulk->uidrecs_by_email_id);
            int j;
            for (j = 0; j < ptrarray_size(current_uidrecs); j++) {
                struct email_uidrec *uidrec = ptrarray_nth(current_uidrecs, j);
                const char *src_mbox_id = uidrec->mboxrec->mbox_id;
                uintptr_t count = (uintptr_t) hash_lookup(src_mbox_id, &src_mbox_id_counts);
                hash_insert(src_mbox_id, (void*) count++, &src_mbox_id_counts);
            }
        }

        /* For each copy update, pick the uid record from the source mailbox
         * that minimizes append_copy calls between mailboxes. */

        for (i = 0; i < ptrarray_size(updates); i++) {
            struct email_update *update = ptrarray_nth(updates, i);
            ptrarray_t *current_uidrecs = hash_lookup(update->email_id, &bulk->uidrecs_by_email_id);

            int j;
            struct email_uidrec *pick_uidrec = ptrarray_nth(current_uidrecs, 0);
            uintptr_t best_count = (uintptr_t) hash_lookup(pick_uidrec->mboxrec->mbox_id, &src_mbox_id_counts);
            for (j = 1; j < ptrarray_size(current_uidrecs); j++) {
                struct email_uidrec *tmp = ptrarray_nth(current_uidrecs, j);
                uintptr_t count = (uintptr_t) hash_lookup(tmp->mboxrec->mbox_id, &src_mbox_id_counts);
                if (count > best_count) {
                    pick_uidrec = tmp;
                    best_count = count;
                }
            }

            /* Add the picked uid record to its slot in the copy plan */
            struct email_updateplan *plan = hash_lookup(dst_mbox_id, &bulk->plans_by_mbox_id);
            ptrarray_t *pick_uidrecs = NULL;
            for (j = 0; j < ptrarray_size(&plan->copy); j++) {
                ptrarray_t *copy_uidrecs = ptrarray_nth(&plan->copy, j);
                struct email_uidrec *tmp = ptrarray_nth(copy_uidrecs, 0);
                if (!strcmp(tmp->mboxrec->mbox_id, pick_uidrec->mboxrec->mbox_id)) {
                    /* We found an existing slot in the copy plan */
                    pick_uidrecs = copy_uidrecs;
                    break;
                }
            }
            if (pick_uidrecs == NULL) {
                pick_uidrecs = ptrarray_new();
                ptrarray_append(&plan->copy, pick_uidrecs);
            }
            ptrarray_append(pick_uidrecs, pick_uidrec);
            plan->needrights |=
                !strcmpnull(scheduled_id, dst_mbox_id) ? 0 : JACL_ADDITEMS;
        }
        free_hash_table(&src_mbox_id_counts, NULL);
    }
    hash_iter_free(&iter);

    free_hash_table(&copyupdates_by_mbox_id, _ptrarray_free_p);

    return 0;
}

static void _email_bulkupdate_checklimits(struct email_bulkupdate *bulk)
{
    /* Validate mailbox counts per email */
    hash_table mbox_ids_by_email_id = HASH_TABLE_INITIALIZER;
    construct_hash_table(&mbox_ids_by_email_id, hash_numrecords(&bulk->uidrecs_by_email_id)+1, 0);

    /* Collect current mailboxes per email */
    hash_iter *iter = hash_table_iter(&bulk->uidrecs_by_email_id);
    while (hash_iter_next(iter)) {
        ptrarray_t *uidrecs = hash_iter_val(iter);
        int i;
        for (i = 0; i < ptrarray_size(uidrecs); i++) {
            struct email_uidrec *uidrec = ptrarray_nth(uidrecs, i);
            strarray_t *mbox_ids = hash_lookup(uidrec->email_id, &mbox_ids_by_email_id);
            if (!mbox_ids) {
                mbox_ids = strarray_new();
                hash_insert(uidrec->email_id, mbox_ids, &mbox_ids_by_email_id);
            }
            strarray_add(mbox_ids, uidrec->mboxrec->mbox_id);
        }
    }
    hash_iter_free(&iter);
    /* Apply plans to mailbox counts */
    iter = hash_table_iter(&bulk->plans_by_mbox_id);
    while (hash_iter_next(iter)) {
        struct email_updateplan *plan = hash_iter_val(iter);
        int i;
        for (i = 0; i < ptrarray_size(&plan->copy); i++) {
            ptrarray_t *uidrecs = ptrarray_nth(&plan->copy, i);
            int j;
            for (j = 0; j < ptrarray_size(uidrecs); j++) {
                struct email_uidrec *uidrec = ptrarray_nth(uidrecs, j);
                strarray_t *mbox_ids = hash_lookup(uidrec->email_id, &mbox_ids_by_email_id);
                if (!mbox_ids) {
                    mbox_ids = strarray_new();
                    hash_insert(uidrec->email_id, mbox_ids, &mbox_ids_by_email_id);
                }
                strarray_add(mbox_ids, plan->mbox_id);
            }
        }
        for (i = 0; i < ptrarray_size(&plan->delete); i++) {
            struct email_uidrec *uidrec = ptrarray_nth(&plan->delete, i);
            strarray_t *mbox_ids = hash_lookup(uidrec->email_id, &mbox_ids_by_email_id);
            if (!mbox_ids) {
                mbox_ids = strarray_new();
                hash_insert(uidrec->email_id, mbox_ids, &mbox_ids_by_email_id);
            }
            strarray_remove_all(mbox_ids, plan->mbox_id);
        }
    }
    hash_iter_free(&iter);
    /* Validate mailbox counts */
    iter = hash_table_iter(&mbox_ids_by_email_id);
    while (hash_iter_next(iter)) {
        const char *email_id = hash_iter_key(iter);
        strarray_t *mbox_ids = hash_iter_val(iter);
        if (!mbox_ids) continue;
        if (strarray_size(mbox_ids) > JMAP_MAIL_MAX_MAILBOXES_PER_EMAIL) {
            if (json_object_get(bulk->set_errors, email_id) == NULL) {
                json_object_set_new(bulk->set_errors, email_id,
                        json_pack("{s:s}", "type", "tooManyMailboxes"));
            }
        }
        strarray_free(mbox_ids);
    }
    hash_iter_free(&iter);
    free_hash_table(&mbox_ids_by_email_id, NULL);

    /* Validate keyword counts. This assumes keyword patches already
     * have been replaced with the complete set of patched keywords. */
    iter = hash_table_iter(&bulk->updates_by_email_id);
    while (hash_iter_next(iter)) {
        struct email_update *update = hash_iter_val(iter);
        if (json_object_get(bulk->set_errors, update->email_id)) {
            continue;
        }
        if (json_object_size(update->keywords) > JMAP_MAIL_MAX_KEYWORDS_PER_EMAIL) {
            json_object_set_new(bulk->set_errors, update->email_id,
                    json_pack("{s:s}", "type", "tooManyKeywords"));
        }
    }
    hash_iter_free(&iter);
}

static json_t *_email_bulkupdate_aggregate_keywords(struct email_bulkupdate *bulk,
                                                    const char *email_id,
                                                    hash_table *seenseq_by_mbox_id)
{
    ptrarray_t *current_uidrecs = hash_lookup(email_id, &bulk->uidrecs_by_email_id);
    struct email_keywords keywords = _EMAIL_KEYWORDS_INITIALIZER;
    _email_keywords_init(&keywords, bulk->req->userid, bulk->seendb, seenseq_by_mbox_id);

    int i;
    for (i = 0; i < ptrarray_size(current_uidrecs); i++) {
        struct email_uidrec *uidrec = ptrarray_nth(current_uidrecs, i);
        struct email_updateplan *plan = hash_lookup(uidrec->mboxrec->mbox_id,
                                                    &bulk->plans_by_mbox_id);
        msgrecord_t *mr = NULL;
        int r = msgrecord_find(plan->mbox, uidrec->uid, &mr);
        if (!r) _email_keywords_add_msgrecord(&keywords, mr);
        if (r) {
            if (!json_object_get(bulk->set_errors, uidrec->email_id)) {
                json_object_set_new(bulk->set_errors, uidrec->email_id,
                        jmap_server_error(r));
            }
        }
        msgrecord_unref(&mr);
    }
    json_t *aggregated_keywords = _email_keywords_to_jmap(&keywords);
    _email_keywords_fini(&keywords);
    return aggregated_keywords;
}

static int _flag_update_changes_seen(json_t *new, json_t *old)
{
    int is_seen = json_object_get(new, "$seen") ? 1 : 0;
    int was_seen = (old && json_object_get(old, "$seen")) ? 1 : 0;
    return is_seen != was_seen;
}

static int _flag_update_changes_not_seen(json_t *new, json_t *old)
{
    const char *name;
    json_t *val;

    json_object_foreach(new, name, val) {
        if (!strcmp(name, "$seen")) continue;
        int was_seen = (old && json_object_get(old, name)) ? 1 : 0;
        if (!was_seen) return 1;
    }

    if (old) {
        json_object_foreach(old, name, val) {
            if (!strcmp(name, "$seen")) continue;
            int is_seen = json_object_get(new, name) ? 1 : 0;
            if (!is_seen) return 1;
        }
    }


    return 0;
}

static int _email_bulkupdate_plan_keywords(struct email_bulkupdate *bulk, ptrarray_t *updates)
{
    int i;

    /* Open seen.db, if required */
    if (strcmp(bulk->req->accountid, bulk->req->userid)) {
        int r = seen_open(bulk->req->userid, SEEN_CREATE, &bulk->seendb);
        if (r) {
            /* There's something terribly wrong. Abort all updates. */
            syslog(LOG_ERR, "_email_bulkupdate_plan_keywords: can't open seen.db: %s",
                            error_message(r));
            return r;
        }
    }

    /* Add uid records to each mailboxes setflags plan */
    for (i = 0; i < ptrarray_size(updates); i++) {
        struct email_update *update = ptrarray_nth(updates, i);
        const char *email_id = update->email_id;

        if (!update->keywords || json_object_get(bulk->set_errors, email_id)) {
            continue;
        }
        ptrarray_t *current_uidrecs = hash_lookup(email_id, &bulk->uidrecs_by_email_id);

        int j;
        for (j = 0; j < ptrarray_size(current_uidrecs); j++) {
            struct email_uidrec *uidrec = ptrarray_nth(current_uidrecs, j);
            struct email_mboxrec *mboxrec = uidrec->mboxrec;
            struct email_updateplan *plan = hash_lookup(mboxrec->mbox_id, &bulk->plans_by_mbox_id);

            if (!jmap_hasrights(bulk->req, plan->mboxname, JACL_READITEMS)) {
                continue;
            }
            if (!update->mailboxids) {
                /* Add keyword update to all current uid records */
                ptrarray_append(&plan->setflags, uidrec);
            }
            else {
                /* Add keyword update to all current records that won't be deleted */
                json_t *jval = json_object_get(update->mailboxids, mboxrec->mbox_id);
                if (jval == json_true() || (jval == NULL && update->patch_mailboxids)) {
                    ptrarray_append(&plan->setflags, uidrec);
                }
            }
        }
    }

    hash_table seenseq_by_mbox_id = HASH_TABLE_INITIALIZER;
    construct_hash_table(&seenseq_by_mbox_id, hash_numrecords(&bulk->plans_by_mbox_id)+1, 0);

    /* Plan keyword updates per mailbox */
    hash_iter *iter = hash_table_iter(&bulk->plans_by_mbox_id);
    while (hash_iter_next(iter)) {
        struct email_updateplan *plan = hash_iter_val(iter);
        if (plan->use_seendb) {
            /* Read seen sequence set */
            int r = seen_read(bulk->seendb, mailbox_uniqueid(plan->mbox), &plan->old_seendata);
            if (!r) {
                plan->old_seenseq = seqset_parse(plan->old_seendata.seenuids, NULL, 0);
                if (!hash_lookup(plan->mbox_id, &seenseq_by_mbox_id))
                    hash_insert(plan->mbox_id, seqset_dup(plan->old_seenseq), &seenseq_by_mbox_id);
            }
            else {
                int j;
                for (j = 0; j < ptrarray_size(&plan->setflags); j++) {
                    struct email_uidrec *uidrec = ptrarray_nth(&plan->setflags, j);
                    if (json_object_get(bulk->set_errors, uidrec->email_id) == NULL) {
                        json_object_set_new(bulk->set_errors, uidrec->email_id,
                                jmap_server_error(r));
                    }
                }
            }
        }

        /* Determine the ACL and keywords for all new uid records */
        for (i = 0; i < ptrarray_size(&plan->copy); i++) {
            ptrarray_t *copy_uidrecs = ptrarray_nth(&plan->copy, i);
            int j;
            for (j = 0; j < ptrarray_size(copy_uidrecs); j++) {
                struct email_uidrec *uidrec = ptrarray_nth(copy_uidrecs, j);
                if (json_object_get(bulk->set_errors, uidrec->email_id)) {
                    continue;
                }
                struct email_update *update = hash_lookup(uidrec->email_id,
                                                          &bulk->updates_by_email_id);

                if (!update->full_keywords) {
                    /* Determine the full set of keywords to write on this record */
                    if (!update->keywords) {
                        /* Write the combined keywords of all records of this email */
                        update->full_keywords = _email_bulkupdate_aggregate_keywords(bulk,
                                                     uidrec->email_id, &seenseq_by_mbox_id);
                    }
                    else if (update->patch_keywords) {
                        /* Write the patched, combined keywords */
                        json_t *aggregated_keywords = _email_bulkupdate_aggregate_keywords(bulk,
                                uidrec->email_id, &seenseq_by_mbox_id);
                        update->full_keywords = jmap_patchobject_apply(aggregated_keywords,
                                update->keywords, NULL);
                        json_decref(aggregated_keywords);
                    }
                    else {
                        /* Write the keywords defined in the update */
                        update->full_keywords = json_incref(update->keywords);
                    }
                }

                /* Determine required ACL rights */
                if (_flag_update_changes_seen(update->full_keywords, NULL))
                    plan->needrights |= JACL_SETSEEN;
                if (_flag_update_changes_not_seen(update->full_keywords, NULL))
                    plan->needrights |= JACL_SETKEYWORDS;
                /* XXX - what about annotations? */
            }
        }

        /* Determine ACL for all existing uid records with updated keywords */
        for (i = 0; i < ptrarray_size(&plan->setflags); i++) {
            struct email_uidrec *uidrec = ptrarray_nth(&plan->setflags, i);
            if (json_object_get(bulk->set_errors, uidrec->email_id)) {
                continue;
            }
            struct email_update *update = hash_lookup(uidrec->email_id,
                                                      &bulk->updates_by_email_id);

            /* Convert flags to JMAP keywords */
            struct email_keywords keywords = _EMAIL_KEYWORDS_INITIALIZER;
            _email_keywords_init(&keywords, bulk->req->userid, bulk->seendb, &seenseq_by_mbox_id);
            msgrecord_t *mr = NULL;
            int r = msgrecord_find(plan->mbox, uidrec->uid, &mr);
            if (!r) _email_keywords_add_msgrecord(&keywords, mr);
            if (r) {
                json_object_set_new(bulk->set_errors, uidrec->email_id,
                        jmap_server_error(r));
            }
            msgrecord_unref(&mr);
            json_t *current_keywords = _email_keywords_to_jmap(&keywords);
            _email_keywords_fini(&keywords);
            json_t *new_keywords;
            if (update->patch_keywords) {
                new_keywords = jmap_patchobject_apply(current_keywords, update->keywords, NULL);
            }
            else {
                new_keywords = json_incref(update->keywords);
            }

            /* Determine required ACL rights */
            if (_flag_update_changes_seen(new_keywords, current_keywords))
                plan->needrights |= JACL_SETSEEN;
            if (_flag_update_changes_not_seen(new_keywords, current_keywords))
                plan->needrights |= JACL_SETKEYWORDS;
            /* XXX - what about annotations? */

            json_decref(new_keywords);
            json_decref(current_keywords);
        }
    }
    hash_iter_free(&iter);

    free_hash_table(&seenseq_by_mbox_id, _free_cached_seqset);

    return 0;
}

static int  _email_bulkupdate_plan_snooze(struct email_bulkupdate *bulk,
                                          ptrarray_t *updates)
{
    const mbentry_t *snoozed_mbe = NULL, *inbox_mbe = NULL;
    const char *snoozed_mboxid = NULL, *inboxid = NULL;

    jmap_findmbox_role(bulk->req, "snoozed", &snoozed_mbe);
    jmap_findmbox_role(bulk->req, "inbox", &inbox_mbe);
    if (snoozed_mbe) {
        snoozed_mboxid = snoozed_mbe->uniqueid;
    }
    if (inbox_mbe) {
        inboxid = inbox_mbe->uniqueid;
    }

    int i;
    for (i = 0; i < ptrarray_size(updates); i++) {
        struct email_update *update = ptrarray_nth(updates, i);
        const char *email_id = update->email_id;
        int invalid = 0, find_mbox = 0;

        if (json_object_get(bulk->set_errors, email_id)) {
            continue;
        }
        ptrarray_t *current_uidrecs =
            hash_lookup(email_id, &bulk->uidrecs_by_email_id);

        /* Lookup the currently snoozed copy of this email_id */
        int j;
        for (j = 0; j < ptrarray_size(current_uidrecs); j++) {
            struct email_uidrec *uidrec = ptrarray_nth(current_uidrecs, j);
            if (uidrec->is_snoozed) {
                update->snoozed_uidrec = uidrec;
                break;
            }
        }

        if (update->snoozed_uidrec) {
            const char *current_mboxid =
                update->snoozed_uidrec->mboxrec->mbox_id;
            struct email_updateplan *plan =
                hash_lookup(current_mboxid, &bulk->plans_by_mbox_id);

            if (update->snoozed) {
                /* Updating/removing snoozeDetails */
                json_t *jval = NULL;

                if (update->patch_snoozed) {
                    const char *current_mboxname =
                        update->snoozed_uidrec->mboxrec->mboxname;
                    json_t *orig =
                        jmap_fetch_snoozed(current_mboxname,
                                           update->snoozed_uidrec->uid);
                    json_t *patch = update->snoozed;
                  
                    update->snoozed = jmap_patchobject_apply(orig, patch, NULL);
                    json_decref(orig);
                    json_decref(patch);
                }

                if (update->mailboxids) {
                    jval = json_object_get(update->mailboxids, current_mboxid);
                }
                if (!update->mailboxids || jval == json_true() ||
                     (jval == NULL && update->patch_mailboxids)) {
                    /* This message is NOT being deleted -
                       Update/remove snoozed */
                    update->snooze_in_mboxid = xstrdup(current_mboxid);
                    update->snoozed_uidrec->is_snoozed = 0;
                    ptrarray_append(&plan->snooze, update->snoozed_uidrec);
                }
                else if (!json_is_null(update->snoozed)) {
                    /* Determine which mailbox to use for the snoozed email */
                    find_mbox = 1;
                }
            }
            else if (update->mailboxids) {
                /* No change to snoozeDetails -
                   Check if this message is being deleted */
                json_t *jval =
                    json_object_get(update->mailboxids, current_mboxid);

                if (jval == json_null() ||
                    (jval == NULL && !update->patch_mailboxids)) {
                    /* This message is being deleted - Remove snoozed */
                    update->snooze_in_mboxid = xstrdup(current_mboxid);
                    update->snoozed_uidrec->is_snoozed = 0;
                    ptrarray_append(&plan->snooze, update->snoozed_uidrec);
                }
            }
        }
        else if (json_is_object(update->snoozed)) {
            /* Setting snoozeDetails */
            if (!update->mailboxids) {
                /* invalidProperties */
                invalid = 1;
            }
            else {
                /* Determine which mailbox to use for the snoozed email */
                find_mbox = 1;
            }
        }

        if (find_mbox) {
            /* Determine which mailbox to use for the snoozed email */
            const char *movetoid =
                json_string_value(json_object_get(update->snoozed,
                                                  "moveToMailboxId"));

            if (json_is_true(json_object_get(update->mailboxids,
                                             snoozed_mboxid))) {
                /* Being added to \snoozed mailbox */
                update->snooze_in_mboxid = xstrdup(snoozed_mboxid);
            }
            else if (movetoid &&
                     json_is_true(json_object_get(update->mailboxids,
                                                  movetoid))) {
                /* Being added to moveToMailboxId */
                update->snooze_in_mboxid = xstrdup(movetoid);
            }
            else if (json_is_true(json_object_get(update->mailboxids,
                                                  inboxid))) {
                /* Being added to Inbox */
                update->snooze_in_mboxid = xstrdup(inboxid);
            }
            else {
                const char *mbox_id = NULL;
                json_t *jval = NULL;

                json_object_foreach(update->mailboxids, mbox_id, jval) {
                    if (json_is_true(jval)) {
                        /* Use the first mailbox being added to */
                        update->snooze_in_mboxid = xstrdup(mbox_id);
                        break;
                    }
                }

                if (!update->snooze_in_mboxid) {
                    /* invalidProperties */
                    invalid = 1;
                }
            }
        }

        if (invalid) {
            json_object_set_new(bulk->set_errors, email_id,
                                json_pack("{s:s s:[s,s]}",
                                          "type", "invalidProperties",
                                          "properties", "mailboxIds", "snoozed"));
        }
    }

    return 0;
}


static int _email_bulkupdate_plan(struct email_bulkupdate *bulk, ptrarray_t *updates)
{
    int i;

    /* Pre-process snooze updates */
    int r = _email_bulkupdate_plan_snooze(bulk, updates);
    if (r) return r;

    /* Plan mailbox copies, moves and deletes */
    r = _email_bulkupdate_plan_mailboxids(bulk, updates);
    if (r) return r;

    /* Pre-process keyword updates */
    r = _email_bulkupdate_plan_keywords(bulk, updates);
    if (r) return r;

    /* Check mailbox count and keyword limits per email */
    _email_bulkupdate_checklimits(bulk);

    /* Validate plans */
    hash_table erroneous_plans = HASH_TABLE_INITIALIZER;
    construct_hash_table(&erroneous_plans,
            hash_numrecords(&bulk->plans_by_mbox_id) + 1, 0);

    /* Check permissions and quota */
    int check_quota = !ignorequota && !config_getswitch(IMAPOPT_QUOTA_USE_CONVERSATIONS);
    hash_iter *plan_iter = hash_table_iter(&bulk->plans_by_mbox_id);
    while (hash_iter_next(plan_iter)) {
        struct email_updateplan *plan = hash_iter_val(plan_iter);
        if (!jmap_hasrights(bulk->req, plan->mboxname, plan->needrights)) {
            _email_updateplan_error(plan, IMAP_PERMISSION_DENIED, bulk->set_errors);
            hash_insert(plan->mbox_id, (void*)IMAP_PERMISSION_DENIED, &erroneous_plans);
        }
        else if (check_quota) {
            /* NOTE, we are only checking message counts here as we
             * don't have the size handy */
            quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
            qdiffs[QUOTA_MESSAGE] = 0;
            int i;
            for (i = 0; i < ptrarray_size(&plan->copy); i++) {
                qdiffs[QUOTA_MESSAGE] += ptrarray_size(ptrarray_nth(&plan->copy, i));
            }
            qdiffs[QUOTA_MESSAGE] -= ptrarray_size(&plan->delete);
            int r = mailbox_quota_check(plan->mbox, qdiffs);
            if (r) {
                _email_updateplan_error(plan, r, bulk->set_errors);
                hash_insert(plan->mbox_id, (void*)IMAP_QUOTA_EXCEEDED, &erroneous_plans);
            }
        }
    }
    if (hash_numrecords(&erroneous_plans)) {
        /* Fail any update where the email is an erroneous mailbox plan */
        hash_iter_reset(plan_iter);
        while (hash_iter_next(plan_iter)) {
            struct email_updateplan *plan = hash_iter_val(plan_iter);
            if (hash_lookup(plan->mbox_id, &erroneous_plans))
                continue;

            int i;
            for (i = 0; i < ptrarray_size(&plan->copy); i++) {
                ptrarray_t *uidrecs = ptrarray_nth(&plan->copy, i);
                int j;
                for (j = 0; j < ptrarray_size(uidrecs); j++) {
                    struct email_uidrec *uidrec = ptrarray_nth(uidrecs, j);
                    intptr_t errcode = (intptr_t)hash_lookup(uidrec->mboxrec->mbox_id, &erroneous_plans);
                    if (errcode && !json_object_get(bulk->set_errors, uidrec->email_id)) {
                        json_object_set_new(bulk->set_errors, uidrec->email_id,
                                jmap_server_error(errcode));
                    }
                }
            }
            ptrarray_t *uidrecs[3] = { &plan->setflags, &plan->delete, &plan->snooze };
            for (i = 0; i < 3; i++) {
                int j;
                for (j = 0; j < ptrarray_size(uidrecs[i]); j++) {
                    struct email_uidrec *uidrec = ptrarray_nth(uidrecs[i], j);
                    intptr_t errcode = (intptr_t)hash_lookup(uidrec->mboxrec->mbox_id, &erroneous_plans);
                    if (errcode && !json_object_get(bulk->set_errors, uidrec->email_id)) {
                        json_object_set_new(bulk->set_errors, uidrec->email_id,
                                jmap_server_error(errcode));
                    }
                }
            }
        }

        /* Remove erroneous plans */
        strarray_t *erroneous_mboxids = hash_keys(&erroneous_plans);
        for (i = 0; i < strarray_size(erroneous_mboxids); i++) {
            const char *mbox_id = strarray_nth(erroneous_mboxids, i);
            struct email_updateplan *plan = hash_del(mbox_id, &bulk->plans_by_mbox_id);
            if (!plan) continue;
            jmap_closembox(bulk->req, &plan->mbox);
            _email_updateplan_free_p(plan);
        }
        strarray_free(erroneous_mboxids);

        hash_iter_free(&plan_iter);
        plan_iter = hash_table_iter(&bulk->plans_by_mbox_id);
    }

    /* Sort UID records arrays */
    hash_iter_reset(plan_iter);
    while (hash_iter_next(plan_iter)) {
        struct email_updateplan *plan = hash_iter_val(plan_iter);
        for (i = 0; i < ptrarray_size(&plan->copy); i++) {
            ptrarray_t *uidrecs = ptrarray_nth(&plan->copy, i);
            ptrarray_sort(uidrecs, _email_uidrec_compareuid_cb);
        }
        ptrarray_sort(&plan->setflags, _email_uidrec_compareuid_cb);
        ptrarray_sort(&plan->delete, _email_uidrec_compareuid_cb);
        ptrarray_sort(&plan->snooze, _email_uidrec_compareuid_cb);
    }

    hash_iter_free(&plan_iter);
    free_hash_table(&erroneous_plans, NULL);

    return 0;
}

static int _email_bulkupdate_open(jmap_req_t *req, struct email_bulkupdate *bulk, ptrarray_t *updates)
{
    int i;
    const mbentry_t *scheduled_mbe = NULL;
    const char *scheduled_uniqueid = NULL;

    bulk->req = req;

    jmap_findmbox_role(bulk->req, "scheduled", &scheduled_mbe);
    if (scheduled_mbe) scheduled_uniqueid = scheduled_mbe->uniqueid;

    /* Map mailbox creation ids and role to mailbox identifiers */
    for(i = 0; i < ptrarray_size(updates); i++) {
        struct email_update *update = ptrarray_nth(updates, i);
        if (!update->mailboxids) continue;

        void *tmp;
        const char *mbox_id;
        json_t *jval;
        json_object_foreach_safe(update->mailboxids, tmp, mbox_id, jval) {
            int is_valid = 1;
            if (*mbox_id == '$') {
                const char *role = mbox_id + 1;
                const mbentry_t *mbentry = NULL;
                if (!jmap_findmbox_role(bulk->req, role, &mbentry)) {
                    json_object_del(update->mailboxids, mbox_id);
                    json_object_set(update->mailboxids, mbentry->uniqueid, jval);
                    mbox_id = mbentry->uniqueid;
                }
                else is_valid = 0;
            }
            else if (*mbox_id == '#') {
                const char *resolved_mbox_id = jmap_lookup_id(req, mbox_id + 1);
                if (resolved_mbox_id) {
                    json_object_del(update->mailboxids, mbox_id);
                    json_object_set(update->mailboxids, resolved_mbox_id, jval);
                    mbox_id = resolved_mbox_id;
                }
                else is_valid = 0;
            }

            /* If trying to move a message in/out of $scheduled
               it better be in our scheduled email cache */
            if (!strcmpnull(scheduled_uniqueid, mbox_id) &&
                strarray_find(req->scheduled_emails, update->email_id, 0) < 0) {
                is_valid = 0;
            }

            if (!is_valid) {
                if (json_object_get(bulk->set_errors, update->email_id) == NULL) {
                    json_object_set_new(bulk->set_errors, update->email_id,
                            json_pack("{s:s s:[s]}", "type", "invalidProperties",
                                "properties", "mailboxIds"));
                }
            }
        }
    }

    /* Map updates to their email id */
    construct_hash_table(&bulk->updates_by_email_id, ptrarray_size(updates)+1, 0);
    for (i = 0; i < ptrarray_size(updates); i++) {
        struct email_update *update = ptrarray_nth(updates, i);
        hash_insert(update->email_id, update, &bulk->updates_by_email_id);
    }

    /* Determine uid records per mailbox */
    strarray_t email_ids = STRARRAY_INITIALIZER;
    for (i = 0; i < ptrarray_size(updates); i++) {
        struct email_update *update = ptrarray_nth(updates, i);
        if (json_object_get(bulk->set_errors, update->email_id)) {
            continue;
        }
        strarray_append(&email_ids, update->email_id);
    }
    _email_mboxrecs_read(req, req->cstate, &email_ids, bulk->set_errors, &bulk->cur_mboxrecs);

    /* Open current mailboxes */
    size_t mboxhash_size = ptrarray_size(updates) * JMAP_MAIL_MAX_MAILBOXES_PER_EMAIL + 1;
    construct_hash_table(&bulk->plans_by_mbox_id, mboxhash_size, 0);
    construct_hash_table(&bulk->uidrecs_by_email_id, strarray_size(&email_ids)+1, 0);
    for (i = 0; i < ptrarray_size(bulk->cur_mboxrecs); i++) {
        struct email_mboxrec *mboxrec = ptrarray_nth(bulk->cur_mboxrecs, i);
        struct email_updateplan *plan = hash_lookup(mboxrec->mbox_id, &bulk->plans_by_mbox_id);
        if (!plan) {
            struct mailbox *mbox = NULL;
            const mbentry_t *mbentry = jmap_mbentry_by_uniqueid(req, mboxrec->mbox_id);
            int r = 0;
            if (mbentry && mbentry->mbtype & MBTYPE_INTERMEDIATE) {
                struct mboxlock *namespacelock = mboxname_usernamespacelock(mbentry->name);
                r = mboxlist_promote_intermediary(mbentry->name);
                mboxname_release(&namespacelock);
            }
            else if (!mbentry) {
                r = IMAP_MAILBOX_NONEXISTENT;
            }
            if (!r) r = jmap_openmbox(req, mboxrec->mboxname, &mbox, /*rw*/1);
            if (r) {
                int j;
                for (j = 0; j < ptrarray_size(&mboxrec->uidrecs); j++) {
                    struct email_uidrec *uidrec = ptrarray_nth(&mboxrec->uidrecs, j);
                    if (json_object_get(bulk->set_errors, uidrec->email_id) == NULL) {
                        json_object_set_new(bulk->set_errors, uidrec->email_id,
                                json_pack("{s:s s:[s]}", "type", "invalidProperties",
                                    "properties", "mailboxIds"));
                    }
                }
                continue;
            }
            plan = _email_bulkupdate_addplan(bulk, mbox, mboxrec);
        }
        /* Map email ids to their list of non-deleted uid records. */
        int j;
        for (j = 0; j < ptrarray_size(&mboxrec->uidrecs); j++) {
            struct email_uidrec *uidrec = ptrarray_nth(&mboxrec->uidrecs, j);
            if (json_object_get(bulk->set_errors, uidrec->email_id)) {
                continue;
            }
            /* Check if the uid record is expunged */
            msgrecord_t *mr = NULL;
            uint32_t system_flags = 0, internal_flags = 0;
            int r = msgrecord_find(plan->mbox, uidrec->uid, &mr);
            if (!r) r = msgrecord_get_systemflags(mr, &system_flags);
            if (!r) r = msgrecord_get_internalflags(mr, &internal_flags);
            if ((system_flags & FLAG_DELETED) || (internal_flags & FLAG_INTERNAL_EXPUNGED)) {
                r = IMAP_NOTFOUND;
            }
            msgrecord_unref(&mr);
            if (r) continue;

            ptrarray_t *current_uidrecs = hash_lookup(uidrec->email_id, &bulk->uidrecs_by_email_id);
            if (current_uidrecs == NULL) {
                current_uidrecs = ptrarray_new();
                hash_insert(uidrec->email_id, current_uidrecs, &bulk->uidrecs_by_email_id);
            }
            ptrarray_append(current_uidrecs, uidrec);
        }
    }
    /* An email with no current uidrecs is expunged */
    for (i = 0; i < strarray_size(&email_ids); i++) {
        const char *email_id = strarray_nth(&email_ids, i);
        if (json_object_get(bulk->set_errors, email_id)) {
            continue;
        }
        if (!hash_lookup(email_id, &bulk->uidrecs_by_email_id)) {
            json_object_set_new(bulk->set_errors, email_id,
                    json_pack("{s:s}", "type", "notFound"));
        }
    }
    strarray_fini(&email_ids);

    /* Open new mailboxes that haven't been opened already */
    for (i = 0; i < ptrarray_size(updates); i++) {
        struct email_update *update = ptrarray_nth(updates, i);
        if (!update->mailboxids) {
            continue;
        }
        json_t *jval;
        const char *mbox_id;
        void *tmp;
        json_object_foreach_safe(update->mailboxids, tmp, mbox_id, jval) {
            struct mailbox *mbox = NULL;
            const mbentry_t *mbentry = jmap_mbentry_by_uniqueid(req, mbox_id);
            if (mbentry && mbentry->mbtype != MBTYPE_DELETED &&
                    !mboxname_isdeletedmailbox(mbentry->name, NULL)) {
                int r = 0;
                if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
                    struct mboxlock *namespacelock = mboxname_usernamespacelock(mbentry->name);
                    r = mboxlist_promote_intermediary(mbentry->name);
                    mboxname_release(&namespacelock);
                }
                if (!r) jmap_openmbox(req, mbentry->name, &mbox, /*rw*/1);
            }
            if (mbox) {
                if (!hash_lookup(mailbox_uniqueid(mbox), &bulk->plans_by_mbox_id)) {
                    struct email_mboxrec *mboxrec = xzmalloc(sizeof(struct email_mboxrec));
                    mboxrec->mboxname = xstrdup(mailbox_name(mbox));
                    mboxrec->mbox_id = xstrdup(mailbox_uniqueid(mbox));
                    ptrarray_append(bulk->new_mboxrecs, mboxrec);
                    _email_bulkupdate_addplan(bulk, mbox, mboxrec);
                }
                else jmap_closembox(req, &mbox); // already reference counted
            }
            else {
                json_object_set_new(bulk->set_errors, update->email_id,
                        json_pack("{s:s s:[s]}", "type", "invalidProperties",
                            "properties", "mailboxIds"));
            }
        }
    }


    /* Map updates to update plan */
    return _email_bulkupdate_plan(bulk, updates);
}

static void _email_bulkupdate_dump(struct email_bulkupdate *bulk, json_t *jdump)
{
    int i;
    struct buf buf = BUF_INITIALIZER;

    json_t *jcur_mboxrecs = json_object();
    for (i = 0; i < ptrarray_size(bulk->cur_mboxrecs); i++) {
        struct email_mboxrec *mboxrec = ptrarray_nth(bulk->cur_mboxrecs, i);
        json_t *jrecs = json_array();
        int j;
        for (j = 0; j < ptrarray_size(&mboxrec->uidrecs); j++) {
            struct email_uidrec *uidrec = ptrarray_nth(&mboxrec->uidrecs, j);
            json_array_append_new(jrecs, json_pack("{s:s s:i}",
                        "emailId", uidrec->email_id, "uid", uidrec->uid));
        }
        json_object_set_new(jcur_mboxrecs, mboxrec->mboxname, jrecs);
    }
    json_object_set_new(jdump, "curMboxrecs", jcur_mboxrecs);

    json_t *jemails = json_object();
    hash_iter *iter = hash_table_iter(&bulk->uidrecs_by_email_id);
    while (hash_iter_next(iter)) {
        const char *email_id = hash_iter_key(iter);
        ptrarray_t *uidrecs = hash_iter_val(iter);
        json_t *juidrecs = json_array();
        int j;
        for (j = 0; j < ptrarray_size(uidrecs); j++) {
            struct email_uidrec *uidrec = ptrarray_nth(uidrecs, j);
            buf_printf(&buf, "%s:%d", uidrec->mboxrec->mboxname, uidrec->uid);
            json_array_append_new(juidrecs, json_string(buf_cstring(&buf)));
            buf_reset(&buf);
        }
        json_object_set_new(jemails, email_id, juidrecs);
    }
    hash_iter_free(&iter);
    json_object_set_new(jdump, "emails", jemails);

    json_t *jmailboxes = json_object();
    json_t *jplans = json_object();
    iter = hash_table_iter(&bulk->plans_by_mbox_id);
    while (hash_iter_next(iter)) {
        struct email_updateplan *plan = hash_iter_val(iter);
        json_object_set_new(jmailboxes, plan->mboxname, json_string(plan->mbox_id));

        json_t *jplan = json_object();

        json_t *jcopy = json_array();
        int j;
        for (j = 0; j < ptrarray_size(&plan->copy); j++) {
            ptrarray_t *uidrecs = ptrarray_nth(&plan->copy, j);
            int k;
            for (k = 0; k < ptrarray_size(uidrecs); k++) {
                struct email_uidrec *uidrec = ptrarray_nth(uidrecs, k);
                buf_printf(&buf, "%s:%d", uidrec->mboxrec->mboxname, uidrec->uid);
                json_array_append_new(jcopy, json_string(buf_cstring(&buf)));
                buf_reset(&buf);
            }
        }
        json_object_set_new(jplan, "copy", jcopy);

        json_t *jsetflags = json_array();
        for (j = 0; j < ptrarray_size(&plan->setflags); j++) {
            struct email_uidrec *uidrec = ptrarray_nth(&plan->setflags, j);
            json_array_append_new(jsetflags, json_integer(uidrec->uid));
        }
        json_object_set_new(jplan, "setflags", jsetflags);

        json_t *jdelete = json_array();
        for (j = 0; j < ptrarray_size(&plan->delete); j++) {
            struct email_uidrec *uidrec = ptrarray_nth(&plan->delete, j);
            json_array_append_new(jdelete, json_integer(uidrec->uid));
        }
        json_object_set_new(jplan, "delete", jdelete);

        json_t *jsnooze = json_array();
        for (j = 0; j < ptrarray_size(&plan->snooze); j++) {
            struct email_uidrec *uidrec = ptrarray_nth(&plan->snooze, j);
            json_array_append_new(jsnooze, json_integer(uidrec->uid));
        }
        json_object_set_new(jplan, "snooze", jsnooze);

        json_object_set_new(jplans, plan->mboxname, jplan);
    }
    hash_iter_free(&iter);
    json_object_set_new(jdump, "plans", jplans);
    json_object_set_new(jdump, "mailboxes", jmailboxes);

    buf_free(&buf);
}

static void _email_bulkupdate_exec_copy(struct email_bulkupdate *bulk)
{
    hash_iter *iter = hash_table_iter(&bulk->plans_by_mbox_id);
    while (hash_iter_next(iter)) {
        struct email_updateplan *plan = hash_iter_val(iter);
        struct mailbox *dst_mbox = plan->mbox;
        int j;
        for (j = 0; j < ptrarray_size(&plan->copy); j++) {
            ptrarray_t *src_uidrecs = ptrarray_nth(&plan->copy, j);
            ptrarray_t src_msgrecs = PTRARRAY_INITIALIZER;

            if (!ptrarray_size(src_uidrecs)) continue;

            /* Lookup the source mailbox plan of the first entry. */
            struct email_uidrec *tmp = ptrarray_nth(src_uidrecs, 0);
            const char *src_mbox_id = tmp->mboxrec->mbox_id;
            struct email_updateplan *src_plan = hash_lookup(src_mbox_id, &bulk->plans_by_mbox_id);
            if (!src_plan) {
                // source plan was erroneous and all email ids that
                // depended on it already were reported in set errors
                continue;
            }

            struct mailbox *src_mbox = src_plan->mbox;
            uint32_t last_uid_before_copy = dst_mbox->i.last_uid;

            /* Bulk copy messages per mailbox to destination */
            int k;
            for (k = 0; k < ptrarray_size(src_uidrecs); k++) {
                struct email_uidrec *src_uidrec = ptrarray_nth(src_uidrecs, k);
                if (json_object_get(bulk->set_errors, src_uidrec->email_id)) {
                    continue;
                }
                msgrecord_t *mrw = msgrecord_from_uid(src_mbox, src_uidrec->uid);
                ptrarray_append(&src_msgrecs, mrw);
            }
            int r = _copy_msgrecords(httpd_authstate, bulk->req->userid, &jmap_namespace,
                                     src_mbox, dst_mbox, &src_msgrecs, plan->needrights);
            if (r) {
                for (k = 0; k < ptrarray_size(src_uidrecs); k++) {
                    struct email_uidrec *src_uidrec = ptrarray_nth(src_uidrecs, k);
                    if (json_object_get(bulk->set_errors, src_uidrec->email_id)) {
                        continue;
                    }
                    json_object_set_new(bulk->set_errors, src_uidrec->email_id, jmap_server_error(r));
                }
            }
            for (k = 0; k < ptrarray_size(&src_msgrecs); k++) {
                msgrecord_t *mrw = ptrarray_nth(&src_msgrecs, k);
                msgrecord_unref(&mrw);
            }
            ptrarray_fini(&src_msgrecs);

            for (k = 0; k < ptrarray_size(src_uidrecs); k++) {
                struct email_uidrec *src_uidrec = ptrarray_nth(src_uidrecs, k);
                if (json_object_get(bulk->set_errors, src_uidrec->email_id)) {
                    continue;
                }

                /* Create new uid record */
                struct email_uidrec *new_uidrec = xzmalloc(sizeof(struct email_uidrec));
                new_uidrec->email_id = xstrdup(src_uidrec->email_id);
                new_uidrec->uid = last_uid_before_copy + k + 1;
                new_uidrec->mboxrec = plan->mboxrec;
                new_uidrec->is_new = 1;
                ptrarray_append(&plan->mboxrec->uidrecs, new_uidrec);

                /* Add new record to setflags plan if keywords are updated */
                /* XXX append_copy should take new flags as parameter */
                struct email_update *update = hash_lookup(src_uidrec->email_id,
                                                          &bulk->updates_by_email_id);
                if (update->keywords || update->full_keywords) {
                    ptrarray_append(&plan->setflags, new_uidrec);
                }

                /* Add new record to snooze plan if copied to snooze folder */
                if (update->snoozed) {
                    if (json_is_object(update->snoozed) &&
                        !strcmpnull(plan->mbox_id, update->snooze_in_mboxid)) {
                        /* Only flag as snoozed (add \snoozed and annotation) if:
                           - SnoozeDetails != json_null() AND
                           - this mailbox is the mailbox in which it is snoozed
                        */
                        new_uidrec->is_snoozed = 1;
                    }
                    ptrarray_append(&plan->snooze, new_uidrec);
                }
            }

        }
    }
    hash_iter_free(&iter);
}

static void _email_bulkupdate_exec_setflags(struct email_bulkupdate *bulk)
{
    hash_iter *iter = hash_table_iter(&bulk->plans_by_mbox_id);
    while (hash_iter_next(iter)) {
        struct email_updateplan *plan = hash_iter_val(iter);
        int j;
        seqset_t *add_seenseq = NULL;
        seqset_t *del_seenseq = NULL;
        uint32_t last_uid = plan->mbox->i.last_uid;

        struct mboxevent *flagsset = mboxevent_new(EVENT_FLAGS_SET);
        int notify_flagsset = 0;
        struct mboxevent *flagsclear = mboxevent_new(EVENT_FLAGS_CLEAR);
        int notify_flagsclear = 0;

        if (plan->use_seendb) {
            add_seenseq = seqset_init(0, SEQ_SPARSE);
            del_seenseq = seqset_init(0, SEQ_SPARSE);
        }

        /* Re-sort uid records before processing. */
        ptrarray_sort(&plan->setflags, _email_uidrec_compareuid_cb);

        /* Process uid records */
        for (j = 0; j < ptrarray_size(&plan->setflags); j++) {
            struct email_uidrec *uidrec = ptrarray_nth(&plan->setflags, j);
            if (json_object_get(bulk->set_errors, uidrec->email_id)) {
                continue;
            }
            const char *email_id = uidrec->email_id;
            struct email_update *update = hash_lookup(email_id, &bulk->updates_by_email_id);

            /* Determine if to write the aggregated or updated JMAP keywords */
            json_t *keywords = uidrec->is_new ? update->full_keywords : update->keywords;
            int patch_keywords = uidrec->is_new ? 0 : update->patch_keywords;

            /* Write keywords */
            struct modified_flags modflags;
            memset(&modflags, 0, sizeof(struct modified_flags));
            msgrecord_t *mrw = msgrecord_from_uid(plan->mbox, uidrec->uid);
            int r = _email_setflags(keywords, patch_keywords, mrw,
                                    add_seenseq, del_seenseq, &modflags);
            if (!r) {
                if (modflags.added_flags) {
                    mboxevent_add_flags(flagsset, plan->mbox->h.flagname,
                                        modflags.added_system_flags,
                                        modflags.added_user_flags);
                    mboxevent_extract_msgrecord(flagsset, mrw);
                    notify_flagsset = 1;
                }
                if (modflags.removed_flags) {
                    mboxevent_add_flags(flagsclear, plan->mbox->h.flagname,
                                        modflags.removed_system_flags,
                                        modflags.removed_user_flags);
                    mboxevent_extract_msgrecord(flagsclear, mrw);
                    notify_flagsclear = 1;
                }
                msgrecord_unref(&mrw);
                if (last_uid < uidrec->uid) {
                    last_uid = uidrec->uid;
                }
            }
            else {
                json_object_set_new(bulk->set_errors, email_id, jmap_server_error(r));
            }
        }
        /* Write seen db for shared mailboxes */
        if (plan->use_seendb) {
            if (add_seenseq || del_seenseq) {
                seqset_t *new_seenseq = seqset_init(0, SEQ_SPARSE);
                if (seqset_first(del_seenseq)) {
                    uint32_t uid;
                    while ((uid = seqset_getnext(plan->old_seenseq)))
                        if (!seqset_ismember(del_seenseq, uid))
                            seqset_add(new_seenseq, uid, 1);
                }
                else if (plan->old_seenseq) {
                    seqset_join(new_seenseq, plan->old_seenseq);
                }
                if (seqset_first(add_seenseq))
                    seqset_join(new_seenseq, add_seenseq);
                struct seendata sd = SEENDATA_INITIALIZER;
                sd.seenuids = seqset_cstring(new_seenseq);
                if (!sd.seenuids) sd.seenuids = xstrdup("");
                sd.lastread = time(NULL);
                sd.lastchange = plan->mbox->i.last_appenddate;
                sd.lastuid = last_uid;
                int r = seen_write(bulk->seendb, mailbox_uniqueid(plan->mbox), &sd);
                if (r) {
                    for (j = 0; j < ptrarray_size(&plan->setflags); j++) {
                        struct email_uidrec *uidrec = ptrarray_nth(&plan->setflags, j);
                        if (json_object_get(bulk->set_errors, uidrec->email_id) == NULL) {
                            json_object_set_new(bulk->set_errors, uidrec->email_id,
                                                jmap_server_error(r));
                        }
                    }
                }
                seqset_free(&add_seenseq);
                seqset_free(&del_seenseq);
                seqset_free(&new_seenseq);
                seen_freedata(&sd);
            }
        }
        if (notify_flagsset) {
            mboxevent_extract_mailbox(flagsset, plan->mbox);
            mboxevent_set_numunseen(flagsset, plan->mbox, -1);
            mboxevent_set_access(flagsset, NULL, NULL, bulk->req->userid,
                                 mailbox_name(plan->mbox), 0);
            mboxevent_notify(&flagsset);
        }
        if (notify_flagsclear) {
            mboxevent_extract_mailbox(flagsclear, plan->mbox);
            mboxevent_set_numunseen(flagsclear, plan->mbox, -1);
            mboxevent_set_access(flagsclear, NULL, NULL, bulk->req->userid,
                                 mailbox_name(plan->mbox), 0);
            mboxevent_notify(&flagsclear);
        }
        mboxevent_free(&flagsset);
        mboxevent_free(&flagsclear);
    }
    hash_iter_free(&iter);
}

static void _email_bulkupdate_exec_delete(struct email_bulkupdate *bulk)
{
    hash_iter *iter = hash_table_iter(&bulk->plans_by_mbox_id);
    while (hash_iter_next(iter)) {
        struct email_updateplan *plan = hash_iter_val(iter);
        _email_multiexpunge(bulk->req, plan->mbox, &plan->delete, bulk->set_errors);
    }
    hash_iter_free(&iter);
}

static void _email_bulkupdate_exec_snooze(struct email_bulkupdate *bulk)
{
    hash_iter *iter = hash_table_iter(&bulk->plans_by_mbox_id);
    while (hash_iter_next(iter)) {
        struct email_updateplan *plan = hash_iter_val(iter);
        int j;

        /* Process uid records */
        for (j = 0; j < ptrarray_size(&plan->snooze); j++) {
            struct email_uidrec *uidrec = ptrarray_nth(&plan->snooze, j);
            if (json_object_get(bulk->set_errors, uidrec->email_id)) {
                continue;
            }
            const char *email_id = uidrec->email_id;
            struct email_update *update =
                hash_lookup(email_id, &bulk->updates_by_email_id);

            /* Write annotation */
            msgrecord_t *mrw = msgrecord_from_uid(plan->mbox, uidrec->uid);
            uint32_t internalflags = 0;
            int r = IMAP_MAILBOX_NONEXISTENT;
            time_t savedate = 0;

            if (mrw) r = msgrecord_get_internalflags(mrw, &internalflags);
            if (!r) r = msgrecord_get_savedate(mrw, &savedate);

            if (!r) {
                const char *annot = IMAP_ANNOT_NS "snoozed";
                struct buf val = BUF_INITIALIZER;

                if (uidrec->is_snoozed) {
                    /* Set/update annotation */
                    char *json = json_dumps(update->snoozed, JSON_COMPACT|JSON_SORT_KEYS);

                    buf_initm(&val, json, strlen(json));

                    /* Extract until and use it as savedate */
                    time_from_iso8601(json_string_value(json_object_get(update->snoozed, "until")),
                                      &savedate);

                    internalflags |= FLAG_INTERNAL_SNOOZED;
                }
                else {
                    /* Delete annotation */
                    internalflags &= ~FLAG_INTERNAL_SNOOZED;
                }

                r = msgrecord_annot_write(mrw, annot, "", &val);
                if (!r) r = msgrecord_set_internalflags(mrw, internalflags);
                if (!r) r = msgrecord_set_savedate(mrw, savedate);
                if (!r) r = msgrecord_rewrite(mrw);
                msgrecord_unref(&mrw);
                buf_free(&val);
            }

            if (r) {
                json_object_set_new(bulk->set_errors, email_id, jmap_server_error(r));
            }
        }
    }
    hash_iter_free(&iter);
}


static void _email_bulkupdate_exec(struct email_bulkupdate *bulk,
                                   json_t *updated,
                                   json_t *not_updated,
                                   json_t *debug)
{
    /*  Execute plans */
    _email_bulkupdate_exec_copy(bulk);
    _email_bulkupdate_exec_setflags(bulk);
    _email_bulkupdate_exec_snooze(bulk);
    _email_bulkupdate_exec_delete(bulk);

    /* Report results */
    hash_iter *iter = hash_table_iter(&bulk->updates_by_email_id);
    while (hash_iter_next(iter)) {
        const char *email_id = hash_iter_key(iter);
        json_t *err = json_object_get(bulk->set_errors, email_id);
        if (err) {
            json_object_set(not_updated, email_id, err);
        }
        else {
            json_object_set_new(updated, email_id, json_null());
        }
    }
    hash_iter_free(&iter);

    if (debug) _email_bulkupdate_dump(bulk, debug);
}


/* Execute the sequence of JMAP Email/set/{update} arguments in bulk. */
static void _email_update_bulk(jmap_req_t *req,
                               json_t *update,
                               json_t *updated,
                               json_t *not_updated,
                               json_t *debug)
{
    struct email_bulkupdate bulkupdate = _EMAIL_BULKUPDATE_INITIALIZER;
    ptrarray_t updates = PTRARRAY_INITIALIZER;
    int i;

    /* Bulk updates are implemented to minimize the number of Cyrus mailbox
     * open and close calls. This is achieved by the following steps:
     *
     * (1) Parse all update arguments.
     *
     * (2) For each updated email, determine its mailboxes and UID records.
     *     Keep note of all mailboxes where the email is currently contained
     *     in, deleted from or copied to. Open all these mailboxes and create
     *     an empty update plan for each mailbox.
     *
     * (3) For each email, determine the required update operations per
     *     mailbox:
     *
     *     (3.1) If the email keywords are updated, add the email's
     *           UID record to the `setflags` field of the according
     *           mailbox update plan.
     *
     *     (3.2) If the email mailboxes are updated, determine which
     *           mailboxes to delete the UID record from, and where
     *           to copy an existing UID record to. For each mailbox,
     *           determine all the UID records that are copied into it.
     *           Cluster all these UID records such that the number
     *           of mailboxes to copy from is minimized.
     *
     * (4) Check required permissions and quota for each mailbox. For
     *     any failed mailbox check, mark all updates of emails that
     *     affect this mailbox as failed.
     *
     * (5) Check email-scoped limits such as mailbox count and keywords per
     *     email. Mark all erroneous emails as not updated.
     *
     * (6) Execute the update plans. Apply copy first, followed by setflags,
     *     followed by deletes.
     *
     * (7) Report all updated emails and close all mailboxes.
     *
     */

    /* Parse updates and add valid updates to todo list. */
    const char *email_id;
    json_t *jval;
    bulkupdate.req = req;
    json_object_foreach(update, email_id, jval) {
        struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
        struct email_update *update = xzmalloc(sizeof(struct email_update));
        update->email_id = email_id;
        _email_update_parse(jval, &parser, update);

        /* Validate patched mailbox ids */
        if (update->patch_mailboxids && !json_array_size(parser.invalid)) {
            json_t *cur = _email_mailboxes(req, email_id);
            if (!json_object_size(cur)) {
                json_object_set_new(not_updated, email_id,
                        json_pack("{s:s}", "type", "notFound"));
            }
            else {
                json_t *new = jmap_patchobject_apply(cur, update->mailboxids, NULL);
                if (!json_object_size(new)) {
                    jmap_parser_invalid(&parser, "mailboxIds");
                }
                json_decref(new);
            }
            json_decref(cur);
        }

        /* Report invalid properties */
        if (json_array_size(parser.invalid)) {
            json_object_set_new(not_updated, email_id,
                    json_pack("{s:s s:O}", "type", "invalidProperties",
                        "properties", parser.invalid));
        }

        /* Add update to batch */
        if (!json_array_size(parser.invalid) &&
                !json_object_get(not_updated, email_id)) {
            ptrarray_append(&updates, update);
        }
        else _email_update_free(update);

        jmap_parser_fini(&parser);
    }
    if (ptrarray_size(&updates)) {
        /* Build and execute bulk update */
        int r = _email_bulkupdate_open(req, &bulkupdate, &updates);
        if (!r) {
            _email_bulkupdate_exec(&bulkupdate, updated, not_updated, debug);
        }
        else {
            for (i = 0; i < ptrarray_size(&updates); i++) {
                struct email_update *update = ptrarray_nth(&updates, i);
                if (!json_object_get(not_updated, update->email_id)) {
                    json_object_set_new(not_updated, update->email_id,
                            jmap_server_error(r));
                }
            }
        }
        _email_bulkupdate_close(&bulkupdate);
    }
    else {
        /* just clean up the memory we allocated above */
        _email_mboxrecs_free(&bulkupdate.new_mboxrecs);
        json_decref(bulkupdate.set_errors);
    }

    for (i = 0; i < ptrarray_size(&updates); i++) {
        _email_update_free(ptrarray_nth(&updates, i));
    }
    ptrarray_fini(&updates);
}

static void _email_destroy_bulk(jmap_req_t *req,
                                json_t *destroy,
                                json_t *destroyed,
                                json_t *not_destroyed)
{
    ptrarray_t *mboxrecs = NULL;
    strarray_t email_ids = STRARRAY_INITIALIZER;
    const char *scheduled_uniqueid = NULL;
    const mbentry_t *scheduled_mbe = NULL;
    int is_shared = strcmp(req->accountid, req->userid);
    size_t iz;
    json_t *jval;
    int i;

    jmap_findmbox_role(req, "scheduled", &scheduled_mbe);
    if (scheduled_mbe) {
        scheduled_uniqueid = scheduled_mbe->uniqueid;
    }

    /* Map email ids to mailbox name and UID */
    json_array_foreach(destroy, iz, jval) {
        strarray_append(&email_ids, json_string_value(jval));
    }
    _email_mboxrecs_read(req, req->cstate, &email_ids, not_destroyed, &mboxrecs);

    /* Check mailbox ACL for shared accounts.
       Also prevent removal from $Scheduled mailbox */
    if (is_shared || scheduled_uniqueid) {
        for (i = 0; i < ptrarray_size(mboxrecs); i++) {
            struct email_mboxrec *mboxrec = ptrarray_nth(mboxrecs, i);
            if ((is_shared &&
                 !jmap_hasrights(req, mboxrec->mboxname, JACL_REMOVEITEMS)) ||
                !strcmpnull(scheduled_uniqueid, mboxrec->mbox_id)) {
                /* Mark all messages of this mailbox as failed */
                int j;
                for (j = 0; j < ptrarray_size(&mboxrec->uidrecs); j++) {
                    struct email_uidrec *uidrec = ptrarray_nth(&mboxrec->uidrecs, j);
                    if (!json_object_get(not_destroyed, uidrec->email_id)) {
                        json_object_set_new(not_destroyed, uidrec->email_id,
                                            json_pack("{s:s}", "type", "forbidden"));
                    }
                }
                /* Remove this mailbox from the todo list */
                ptrarray_remove(mboxrecs, i--);
                _email_mboxrec_free(mboxrec);
            }
        }
    }

    /* Expunge messages in bulk per mailbox */
    for (i = 0; i < ptrarray_size(mboxrecs); i++) {
        struct email_mboxrec *mboxrec = ptrarray_nth(mboxrecs, i);
        struct mailbox *mbox = NULL;
        int j;
        int r = jmap_openmbox(req, mboxrec->mboxname, &mbox, 1);
        if (!r) {
            /* Expunge messages one by one, marking any failed message */
            _email_multiexpunge(req, mbox, &mboxrec->uidrecs, not_destroyed);
        }
        else {
            /* Mark all messages of this mailbox as failed */
            for (j = 0; j < ptrarray_size(&mboxrec->uidrecs); j++) {
                struct email_uidrec *uidrec = ptrarray_nth(&mboxrec->uidrecs, j);
                if (!json_object_get(not_destroyed, uidrec->email_id)) {
                    json_object_set_new(not_destroyed, uidrec->email_id,
                            jmap_server_error(r));
                }
            }
        }
        jmap_closembox(req, &mbox);
    }

    /* Report successful destroys */
    json_array_foreach(destroy, iz, jval) {
        const char *email_id = json_string_value(jval);
        if (!json_object_get(not_destroyed, email_id))
            json_array_append(destroyed, jval);
    }

    _email_mboxrecs_free(&mboxrecs);
    strarray_fini(&email_ids);
}

static int jmap_email_set(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;

    json_t *err = NULL;
    jmap_set_parse(req, &parser, email_props, NULL, NULL, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (set.if_in_state) {
        /* TODO rewrite state function to use char* not json_t* */
        json_t *jstate = json_string(set.if_in_state);
        if (jmap_cmpstate(req, jstate, MBTYPE_EMAIL)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            goto done;
        }
        json_decref(jstate);
        set.old_state = xstrdup(set.if_in_state);
    }
    else {
        set.old_state = jmap_getstate(req, MBTYPE_EMAIL, /*refresh*/0);
    }

    json_t *email;
    const char *creation_id;
    json_object_foreach(set.create, creation_id, email) {
        json_t *set_err = NULL;
        json_t *new_email = NULL;
        /* Create message */
        _email_create(req, email, &new_email, &set_err);
        if (set_err) {
            json_object_set_new(set.not_created, creation_id, set_err);
            continue;
        }
        /* Report message as created */
        json_object_set_new(set.created, creation_id, new_email);
        const char *msg_id = json_string_value(json_object_get(new_email, "id"));
        jmap_add_id(req, creation_id, msg_id);
    }

    json_t *debug_bulkupdate = NULL;
    if (jmap_is_using(req, JMAP_DEBUG_EXTENSION)) {
        debug_bulkupdate = json_object();
    }
    _email_update_bulk(req, set.update, set.updated, set.not_updated, debug_bulkupdate);

    _email_destroy_bulk(req, set.destroy, set.destroyed, set.not_destroyed);

    set.new_state = jmap_getstate(req, MBTYPE_EMAIL, /*refresh*/1);

    json_t *reply = jmap_set_reply(&set);
    if (jmap_is_using(req, JMAP_DEBUG_EXTENSION)) {
        json_object_set_new(reply, "debug",
                json_pack("{s:o}", "bulkUpdate", debug_bulkupdate));
    }
    jmap_ok(req, reply);

done:
    /* Flush cache of scheduled emails */
    strarray_fini(req->scheduled_emails);

    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    return 0;
}

struct _email_import_rock {
    struct buf buf;
};

static int _email_import_cb(jmap_req_t *req __attribute__((unused)),
                            FILE *out,
                            void *rock,
                            json_t **err __attribute__((unused)))
{
    struct _email_import_rock *data = (struct _email_import_rock*) rock;
    const char *base = data->buf.s;
    size_t len = data->buf.len;
    struct protstream *stream = prot_readmap(base, len);
    int r = message_copy_strict(stream, out, len, 0);
    prot_free(stream);
    return r;
}

struct msgimport_checkacl_rock {
    jmap_req_t *req;
    json_t *mailboxes;
};

static int msgimport_checkacl_cb(const mbentry_t *mbentry, void *xrock)
{
    struct msgimport_checkacl_rock *rock = xrock;
    jmap_req_t *req = rock->req;

    if (!json_object_get(rock->mailboxes, mbentry->uniqueid))
        return 0;

    int needrights = JACL_ADDITEMS|JACL_SETKEYWORDS;
    if (!jmap_hasrights_mbentry(req, mbentry, needrights))
        return IMAP_PERMISSION_DENIED;

    return 0;
}

static void _email_import(jmap_req_t *req,
                          json_t *jemail_import,
                          json_t **new_email,
                          json_t **err)
{
    const char *blob_id = jmap_id_string_value(req, json_object_get(jemail_import, "blobId"));
    json_t *jmailbox_ids = json_object_get(jemail_import, "mailboxIds");
    char *mboxname = NULL;
    struct _email_import_rock content = { BUF_INITIALIZER };
    int has_attachment = 0;
    const char *sourcefile = NULL;

    /* Force write locks on mailboxes. */
    req->force_openmbox_rw = 1;

    /* Gather keywords */
    strarray_t keywords = STRARRAY_INITIALIZER;
    const json_t *val;
    const char *keyword;
    json_object_foreach(json_object_get(jemail_import, "keywords"), keyword, val) {
        if (!strcasecmp(keyword, JMAP_HAS_ATTACHMENT_FLAG)) {
            continue;
        }
        strarray_append(&keywords, keyword);
    }

    /* check for internaldate */
    time_t internaldate = 0;
    const char *received_at = json_string_value(json_object_get(jemail_import, "receivedAt"));
    if (received_at) {
        time_from_iso8601(received_at, &internaldate);
    }

    /* check for snoozed */
    json_t *snoozed = json_object_get(jemail_import, "snoozed");

    /* Check mailboxes for ACL */
    if (strcmp(req->userid, req->accountid)) {
        struct msgimport_checkacl_rock rock = { req, jmailbox_ids };
        int r = mboxlist_usermboxtree(req->accountid, req->authstate, msgimport_checkacl_cb, &rock, MBOXTREE_INTERMEDIATES);
        if (r) {
            *err = json_pack("{s:s s:[s]}", "type", "invalidProperties",
                    "properties", "mailboxIds");
            goto done;
        }
    }

    /* Start import */
    struct email_append_detail detail;
    memset(&detail, 0, sizeof(struct email_append_detail));

    /* Lookup blob */
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;

    /* see if we can get a direct email! */
    int r = jmap_findblob_exact(req, NULL/*accountid*/, blob_id,
                                &mbox, &mr, &content.buf);
    if (!r && mr) r = msgrecord_get_fname(mr, &sourcefile);
    if (!r) goto gotrecord;

    /* better clean up before we go the slow path */
    buf_reset(&content.buf);
    sourcefile = NULL;
    msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);

    struct body *body = NULL;
    const struct body *part = NULL;
    struct buf msg_buf = BUF_INITIALIZER;
    r = jmap_findblob(req, NULL/*accountid*/, blob_id,
                      &mbox, &mr, &body, &part, &msg_buf);
    if (r) {
        if (r == IMAP_NOTFOUND || r == IMAP_PERMISSION_DENIED)
            *err = json_pack("{s:s s:[s]}", "type", "invalidProperties",
                    "properties", "blobId");
        else
            *err = jmap_server_error(r);
        goto done;
    }

    /* Decode blob */
    const char *blob_base = buf_base(&msg_buf);
    size_t blob_len = buf_len(&msg_buf);
    if (part) {
        blob_base += part->content_offset;
        blob_len = part->content_size;

        int enc = encoding_lookupname(part->encoding);
        if (enc != ENCODING_NONE) {
            char *tmp;
            size_t dec_len;
            const char *dec = charset_decode_mimebody(blob_base, blob_len, enc, &tmp, &dec_len);
            buf_setmap(&content.buf, dec, dec_len);
            free(tmp);
        }
        else {
            buf_setmap(&content.buf, blob_base, blob_len);
        }
    }
    else {
        buf_setmap(&content.buf, blob_base, blob_len);
    }

    message_free_body(body);
    free(body);

gotrecord:

    /* Determine $hasAttachment flag */
    if (config_getswitch(IMAPOPT_JMAP_SET_HAS_ATTACHMENT)) {
        /* Parse email */
        json_t *email = NULL;
        struct email_getargs getargs = _EMAIL_GET_ARGS_INITIALIZER;
        getargs.props = xzmalloc(sizeof(hash_table));
        construct_hash_table(getargs.props, 1, 0);

        hash_insert("hasAttachment", (void*)1, getargs.props);
        _email_from_buf(req, &getargs, &content.buf, NULL, &email);
        has_attachment = json_boolean_value(json_object_get(email, "hasAttachment"));

        free_hash_table(getargs.props, NULL);
        free(getargs.props);
        getargs.props = NULL;
        _email_getargs_fini(&getargs);
        json_decref(email);
    }

    /* Write the message to the file system */
    _email_append(req, jmailbox_ids, &keywords, internaldate, snoozed,
                  has_attachment, sourcefile, _email_import_cb, &content, &detail, err);

    msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);

    if (*err) goto done;

    *new_email = json_pack("{s:s, s:s, s:s, s:i}",
         "id", detail.email_id,
         "blobId", detail.blob_id,
         "threadId", detail.thread_id,
         "size", detail.size);

done:
    strarray_fini(&keywords);
    buf_free(&content.buf);
    free(mboxname);
}

static int jmap_email_import(jmap_req_t *req)
{
    json_t *created = json_object();
    json_t *not_created = json_object();

    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    const char *key;
    json_t *arg, *emails = NULL;
    const char *id;
    json_t *jemail_import;
    int have_snoozed_mboxid = 0;

    /* Parse request */
    json_object_foreach(req->args, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        else if (!strcmp(key, "emails")) {
            if (json_is_object(arg)) {
                emails = arg;
                jmap_parser_push(&parser, "emails");
                json_object_foreach(emails, id, jemail_import) {
                    if (!json_is_object(jemail_import)) {
                        jmap_parser_invalid(&parser, id);
                    }
                }
                jmap_parser_pop(&parser);
            }
        }

        else {
            jmap_parser_invalid(&parser, key);
        }
    }

    /* emails is a required argument */
    if (!emails) jmap_parser_invalid(&parser, "emails");

    if (json_array_size(parser.invalid)) {
        json_t *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                                "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    json_object_foreach(emails, id, jemail_import) {
        /* Parse import */
        struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
        json_t *jval;
        const char *s;

        /* blobId */
        s = jmap_id_string_value(req, json_object_get(jemail_import, "blobId"));
        if (!s) {
            jmap_parser_invalid(&parser, "blobId");
        }

        /* keywords */
        json_t *keywords = json_object_get(jemail_import, "keywords");
        if (json_is_object(keywords)) {
            jmap_parser_push(&parser, "keywords");
            json_object_foreach(keywords, s, jval) {
                if (jval != json_true() || !jmap_email_keyword_is_valid(s)) {
                    jmap_parser_invalid(&parser, s);
                }
            }
            jmap_parser_pop(&parser);
        }
        else if (JNOTNULL(keywords)) {
            jmap_parser_invalid(&parser, "keywords");
        }

        /* receivedAt */
        json_t *jrecv = json_object_get(jemail_import, "receivedAt");
        if (JNOTNULL(jrecv)) {
            if (!json_is_utcdate(jrecv)) {
                jmap_parser_invalid(&parser, "receivedAt");
            }
        }

        /* Validate mailboxIds */
        json_t *jmailboxids = json_copy(json_object_get(jemail_import, "mailboxIds"));
        if (json_object_size(jmailboxids)) {
            _append_validate_mboxids(req, jmailboxids, &parser, &have_snoozed_mboxid);
        }
        else {
            jmap_parser_invalid(&parser, "mailboxIds");
        }

        /* Validate snoozed + mailboxIds */
        json_t *snoozed = json_object_get(jemail_import, "snoozed");
        if (JNOTNULL(snoozed) &&
            !(json_is_utcdate(json_object_get(snoozed, "until")) &&
              have_snoozed_mboxid)) {
            jmap_parser_invalid(&parser, "snoozed");
        }

        json_t *invalid = json_incref(parser.invalid);
        jmap_parser_fini(&parser);
        if (json_array_size(invalid)) {
            json_t *err = json_pack("{s:s}", "type", "invalidProperties");
            json_object_set_new(err, "properties", invalid);
            json_object_set_new(not_created, id, err);
            json_decref(jmailboxids);
            continue;
        }
        json_decref(invalid);

        /* Process import */
        json_t *orig_mailboxids = json_incref(json_object_get(jemail_import, "mailboxIds"));
        json_object_set_new(jemail_import, "mailboxIds", jmailboxids);
        json_t *new_email = NULL;
        json_t *err = NULL;
        _email_import(req, jemail_import, &new_email, &err);
        if (err) {
            json_object_set_new(not_created, id, err);
        }
        else {
            /* Successful import */
            json_object_set_new(created, id, new_email);
            const char *newid = json_string_value(json_object_get(new_email, "id"));
            jmap_add_id(req, id, newid);
        }
        json_object_set_new(jemail_import, "mailboxIds", orig_mailboxids);
    }

    /* Reply */
    jmap_ok(req, json_pack("{s:s s:O s:O}",
                "accountId", req->accountid,
                "created", created,
                "notCreated", not_created));

done:
    json_decref(created);
    json_decref(not_created);
    jmap_parser_fini(&parser);
    return 0;
}

struct _email_copy_checkmbox_rock {
    jmap_req_t *req;           /* JMAP request context */
    json_t *dst_mboxids;       /* mailboxIds argument */
    strarray_t *dst_mboxnames; /* array of destination mailbox names */
};

static int _email_copy_checkmbox_cb(const mbentry_t *mbentry, void *_rock)
{
    struct _email_copy_checkmbox_rock *rock = _rock;

    /* Ignore anything but regular and intermediate mailboxes */
    if (!mbentry || mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL ||
        mbtypes_unavailable(mbentry->mbtype) || (mbentry->mbtype & MBTYPE_DELETED)) {
        return 0;
    }
    if (!json_object_get(rock->dst_mboxids, mbentry->uniqueid)) {
        return 0;
    }

    /* Check read-write ACL rights */
    int needrights = JACL_READITEMS|JACL_ADDITEMS|ACL_SETSEEN|JACL_SETMETADATA;
    if (!jmap_hasrights_mbentry(rock->req, mbentry, needrights))
        return IMAP_PERMISSION_DENIED;

    /* Mark this mailbox as found */
    strarray_append(rock->dst_mboxnames, mbentry->name);
    size_t want_count = json_object_size(rock->dst_mboxids);
    size_t have_count = strarray_size(rock->dst_mboxnames);
    return want_count == have_count ? IMAP_OK_COMPLETED : 0;
}

struct _email_copy_writeprops_rock {
    /* Input values */
    jmap_req_t *req;
    const char *received_at;
    json_t *keywords;
    struct seen *seendb;
    /* Return values */
    conversation_id_t cid; /* Thread id of copied message */
    uint32_t size;         /* Byte size of copied message */
};

static int _email_copy_writeprops_cb(const conv_guidrec_t* rec, void* _rock)
{
    struct _email_copy_writeprops_rock *rock = _rock;
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    jmap_req_t *req = rock->req;
    struct mboxevent *flagsset = mboxevent_new(EVENT_FLAGS_SET);
    struct mboxevent *flagsclear = mboxevent_new(EVENT_FLAGS_CLEAR);
    int notify_flagsset = 0;
    int notify_flagsclear = 0;

    if (rec->part) {
        return 0;
    }

    /* Overwrite message record */
    int r = jmap_openmbox_by_guidrec(rock->req, rec, &mbox, /*rw*/1);
    if (r || mbtype_isa(mailbox_mbtype(mbox)) != MBTYPE_EMAIL) {
        goto done;
    }
    if (!r) r = msgrecord_find(mbox, rec->uid, &mr);
    if (!r && rock->received_at) {
        time_t internal_date;
        time_from_iso8601(rock->received_at, &internal_date);
        r = msgrecord_set_internaldate(mr, internal_date);
    }
    if (!r) {
        /* Write the keywords. There's lots of ceremony around seen.db */
        seqset_t *seenseq = NULL;
        seqset_t *addseen = NULL;
        seqset_t *delseen = NULL;

        /* Read the current seen sequence from seen.db */
        int need_seendb = !mailbox_internal_seen(mbox, req->userid);
        if (need_seendb) {
            delseen = seqset_init(0, SEQ_SPARSE);
            addseen = seqset_init(0, SEQ_SPARSE);
            struct seendata sd = SEENDATA_INITIALIZER;
            int r = seen_read(rock->seendb, mailbox_uniqueid(mbox), &sd);
            if (!r) {
                seenseq = seqset_parse(sd.seenuids, NULL, sd.lastuid);
                seen_freedata(&sd);
            }
        }

        /* Write the flags on the record */
        struct modified_flags modflags;
        memset(&modflags, 0, sizeof(struct modified_flags));
        if (!r) r = _email_setflags(rock->keywords, 0, mr, addseen, delseen, &modflags);
        if (!r) {
            if (modflags.added_flags) {
                mboxevent_extract_msgrecord(flagsset, mr);
                mboxevent_add_flags(flagsset, mbox->h.flagname,
                                    modflags.added_system_flags,
                                    modflags.added_user_flags);
                notify_flagsset = 1;
            }
            if (modflags.removed_flags) {
                mboxevent_extract_msgrecord(flagsclear, mr);
                mboxevent_add_flags(flagsclear, mbox->h.flagname,
                                    modflags.removed_system_flags,
                                    modflags.removed_user_flags);
                notify_flagsclear = 1;
            }
        }

        /* Write back changes to seen.db */
        if (!r && need_seendb && (seqset_first(addseen) || seqset_first(delseen))) {
            if (seqset_first(delseen)) {
                seqset_t *newseen = seqset_init(0, SEQ_SPARSE);
                uint32_t uid;
                while ((uid = seqset_getnext(seenseq))) {
                    if (!seqset_ismember(delseen, uid)) {
                        seqset_add(newseen, uid, 1);
                    }
                }
                seqset_free(&seenseq);
                seenseq = newseen;
            }
            else if (seqset_first(addseen)) {
                seqset_add(seenseq, rec->uid, 1);
            }

            struct seendata sd = SEENDATA_INITIALIZER;
            sd.seenuids = seqset_cstring(seenseq);
            if (!sd.seenuids) sd.seenuids = xstrdup("");
            sd.lastread = time(NULL);
            sd.lastchange = mbox->i.last_appenddate;
            sd.lastuid = mbox->i.last_uid;
            r = seen_write(rock->seendb, mailbox_uniqueid(mbox), &sd);
            seen_freedata(&sd);
        }

        seqset_free(&delseen);
        seqset_free(&addseen);
        seqset_free(&seenseq);
    }
    if (!r) r = msgrecord_rewrite(mr);
    if (r) goto done;

    /* Write mboxevents */
    if (notify_flagsset) {
        mboxevent_extract_mailbox(flagsset, mbox);
        mboxevent_set_numunseen(flagsset, mbox, -1);
        mboxevent_set_access(flagsset, NULL, NULL, req->userid, mailbox_name(mbox), 0);
        mboxevent_notify(&flagsset);
    }
    if (notify_flagsclear) {
        mboxevent_extract_mailbox(flagsclear, mbox);
        mboxevent_set_numunseen(flagsclear, mbox, -1);
        mboxevent_set_access(flagsclear, NULL, NULL, req->userid, mailbox_name(mbox), 0);
        mboxevent_notify(&flagsclear);
    }

    /* Read output values */
    if (!rock->cid) rock->cid = rec->cid;
    if (!rock->size) r = msgrecord_get_size(mr, &rock->size);

done:
    mboxevent_free(&flagsset);
    mboxevent_free(&flagsclear);
    if (mr) msgrecord_unref(&mr);
    jmap_closembox(rock->req, &mbox);
    return r;
}

struct _email_exists_rock {
    jmap_req_t *req;
    int exists;
};

static int _email_exists_cb(const conv_guidrec_t *rec, void *rock)
{
    struct _email_exists_rock *data = (struct _email_exists_rock*) rock;
    jmap_req_t *req = data->req;
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    uint32_t internal_flags;
    mbentry_t *mbentry = NULL;
    int r = 0;

    conv_guidrec_mbentry(rec, &mbentry);

    if (!mbentry || mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL) {
        goto done;
    }
    if (rec->version < 1) {
        r = jmap_openmbox(req, mbentry->name, &mbox, 0);
        if (r) goto done;

        r = msgrecord_find(mbox, rec->uid, &mr);
        if (r) goto done;

        r = msgrecord_get_internalflags(mr, &internal_flags);
        if (r) goto done;
    }
    else internal_flags = rec->internal_flags;

    if (!(internal_flags & FLAG_INTERNAL_EXPUNGED)) {
        data->exists = 1;
        r = CYRUSDB_DONE;
    }

done:
    if (mr) msgrecord_unref(&mr);
    mboxlist_entry_free(&mbentry);
    jmap_closembox(req, &mbox);
    return r;
}

struct emailcopy_pickrecord_rock {
    jmap_req_t *req;
    struct mailbox *mbox;
    msgrecord_t *mr;
    struct email_keywords keywords;
    int gather_keywords;
};

static int _email_copy_pickrecord_cb(const conv_guidrec_t *rec, void *vrock)
{
    struct emailcopy_pickrecord_rock *rock = vrock;
    jmap_req_t *req = rock->req;
    struct mailbox *mbox = NULL;
    msgrecord_t *mr = NULL;
    mbentry_t *mbentry = NULL;
    int r = 0;

    conv_guidrec_mbentry(rec, &mbentry);

    if (!mbentry || mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL ||
        !jmap_hasrights_mbentry(req, mbentry, JACL_READITEMS)) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    /* Lookup record */
    r = jmap_openmbox(req, mbentry->name, &mbox, 0);
    mboxlist_entry_free(&mbentry);
    if (r) goto done;
    r = msgrecord_find(mbox, rec->uid, &mr);
    if (r) goto done;

    /* Check if this record is expunged */
    uint32_t system_flags;
    uint32_t internal_flags;
    if (rec->version < 1) {
        r = msgrecord_get_systemflags(mr, &system_flags);
        if (!r) msgrecord_get_internalflags(mr, &internal_flags);
        if (r) goto done;
    }
    else {
        system_flags = rec->system_flags;
        internal_flags = rec->internal_flags;
    }
    if (r || system_flags & FLAG_DELETED || internal_flags & FLAG_INTERNAL_EXPUNGED) {
        goto done;
    }

    /* Aggregate message record flags into JMAP keywords */
    if (rock->gather_keywords) {
        _email_keywords_add_msgrecord(&rock->keywords, mr);
    }

    /* Keep this message record as source to copy from? */
    if (!rock->mbox) {
        rock->mbox = mbox;
        mbox = NULL;
        rock->mr = mr;
        mr = NULL;
    }

done:
    msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);
    return r;
}

static void _email_copy(jmap_req_t *req, json_t *copy_email,
                        const char *from_account_id,
                        struct seen *seendb,
                        json_t **new_email, json_t **err)
{
    strarray_t dst_mboxnames = STRARRAY_INITIALIZER;
    struct mailbox *src_mbox = NULL;
    msgrecord_t *src_mr = NULL;
    char *src_mboxname = NULL;
    int r = 0;
    char *blob_id = NULL;
    json_t *new_keywords = NULL;
    json_t *jmailboxids = json_copy(json_object_get(copy_email, "mailboxIds"));

    /* Support mailboxids by role */
    const char *mbox_id;
    json_t *jval;
    void *tmp;
    json_object_foreach_safe(jmailboxids, tmp, mbox_id, jval) {
        if (*mbox_id != '$') continue;
        const char *role = mbox_id + 1;
        const mbentry_t *mbentry = NULL;
        if (!jmap_findmbox_role(req, role, &mbentry)) {
            json_object_del(jmailboxids, mbox_id);
            json_object_set_new(jmailboxids, mbentry->uniqueid, jval);
        }
        else {
            *err = json_pack("{s:s s:[s]}", "type", "invalidProperties",
                    "properties", "mailboxIds");
        }
        if (*err) goto done;
    }

    const char *email_id = json_string_value(json_object_get(copy_email, "id"));
    uint32_t src_size = 0;

    /* Lookup source message record and gather JMAP keywords */
    new_keywords = json_deep_copy(json_object_get(copy_email, "keywords"));
    if (json_is_null(new_keywords)) {
        new_keywords = NULL;
    }
    hash_table seenseq_by_mbox_id = HASH_TABLE_INITIALIZER;
    construct_hash_table(&seenseq_by_mbox_id, 32, 0);
    struct emailcopy_pickrecord_rock pickrecord_rock = {
        req, NULL, NULL, _EMAIL_KEYWORDS_INITIALIZER, 0
    };
    if (!new_keywords) {
        _email_keywords_init(&pickrecord_rock.keywords, req->userid, seendb, &seenseq_by_mbox_id);
        pickrecord_rock.gather_keywords = 1;
    }
    if (strcmp(from_account_id, req->accountid)) {
        struct conversations_state *mycstate = NULL;
        r = conversations_open_user(from_account_id, 0/*shared*/, &mycstate);
        if (!r) r = conversations_guid_foreach(mycstate, _guid_from_id(email_id),
                _email_copy_pickrecord_cb, &pickrecord_rock);
        if (!r) r = conversations_commit(&mycstate);
    }
    else {
        r = conversations_guid_foreach(req->cstate, _guid_from_id(email_id),
                _email_copy_pickrecord_cb, &pickrecord_rock);
    }
    if (!r && pickrecord_rock.mbox) {
        src_mbox = pickrecord_rock.mbox;
        src_mr = pickrecord_rock.mr;
        if (!new_keywords) {
            new_keywords = _email_keywords_to_jmap(&pickrecord_rock.keywords);
        }
        r = msgrecord_get_size(src_mr, &src_size);
    }
    else if (!r) {
        r = IMAP_NOTFOUND;
    }
    free_hash_table(&seenseq_by_mbox_id, _free_cached_seqset);
    _email_keywords_fini(&pickrecord_rock.keywords);
    if (r) {
        if (r == IMAP_NOTFOUND || r == IMAP_PERMISSION_DENIED) {
            *err = json_pack("{s:s s:[s]}", "type", "invalidProperties",
                    "properties", "id");
            r = 0;
        }
        goto done;
    }

    /* Override hasAttachment flag */
    int has_attachment = 0;
    r = msgrecord_hasflag(src_mr, JMAP_HAS_ATTACHMENT_FLAG, &has_attachment);
    if (r) goto done;
    if (has_attachment)
        json_object_set_new(new_keywords, JMAP_HAS_ATTACHMENT_FLAG, json_true());
    else
        json_object_del(new_keywords, JMAP_HAS_ATTACHMENT_FLAG);


    struct message_guid guid;
    r = msgrecord_get_guid(src_mr, &guid);
    if (r) goto done;
    blob_id = xstrdup(message_guid_encode(&guid));

    /* Check if email already exists in to_account */
    struct _email_exists_rock data = { req, 0 };
    conversations_guid_foreach(req->cstate, blob_id, _email_exists_cb, &data);
    if (data.exists) {
        *err = json_pack("{s:s s:s}", "type", "alreadyExists", "existingId", email_id);
        goto done;
    }

    /* Lookup mailbox names and make sure they are all writeable */
    struct _email_copy_checkmbox_rock checkmbox_rock = {
        req, jmailboxids, &dst_mboxnames
    };
    r = mboxlist_usermboxtree(req->accountid, httpd_authstate,
                              _email_copy_checkmbox_cb, &checkmbox_rock,
                              MBOXTREE_INTERMEDIATES);
    if (r != IMAP_OK_COMPLETED) {
        if (r == 0 || r == IMAP_PERMISSION_DENIED) {
            *err = json_pack("{s:s s:[s]}", "type", "invalidProperties",
                    "properties", "mailboxIds");
            r = 0;
        }
        goto done;
    }

    /* Copy message record to mailboxes */
    char *dst_mboxname;
    while ((dst_mboxname = strarray_pop(&dst_mboxnames))) {
        mbentry_t *mbentry = NULL;
        r = jmap_mboxlist_lookup(dst_mboxname, &mbentry, NULL);
        if (!r && (mbentry->mbtype & MBTYPE_INTERMEDIATE)) {
            struct mboxlock *namespacelock = mboxname_usernamespacelock(mbentry->name);
            r = mboxlist_promote_intermediary(mbentry->name);
            mboxname_release(&namespacelock);
        }
        if (!r) {
            struct mailbox *dst_mbox = NULL;
            r = jmap_openmbox(req, dst_mboxname, &dst_mbox, /*rw*/1);
            if (!r) {
                r = _copy_msgrecord(httpd_authstate, req->accountid,
                        &jmap_namespace, src_mbox, dst_mbox, src_mr);
            }
            jmap_closembox(req, &dst_mbox);
            free(dst_mboxname);
        }
        mboxlist_entry_free(&mbentry);
        if (r) goto done;
    }

    /* Rewrite new message record properties and lookup thread id */
    const char *receivedAt = json_string_value(json_object_get(copy_email, "receivedAt"));
    struct _email_copy_writeprops_rock writeprops_rock = {
        req, receivedAt, new_keywords, seendb, /*cid*/0, /*size*/0
    };
    r = conversations_guid_foreach(req->cstate, email_id + 1,
                                   _email_copy_writeprops_cb, &writeprops_rock);

    if (!r) {
        char thread_id[JMAP_THREADID_SIZE];
        jmap_set_threadid(writeprops_rock.cid, thread_id);
        *new_email = json_pack("{s:s s:s s:s s:i}",
                "id", email_id,
                "blobId", blob_id,
                "threadId", thread_id,
                "size", src_size);
    }

done:
    json_decref(jmailboxids);
    if (r && *err == NULL) {
        *err = jmap_server_error(r);
    }
    free(src_mboxname);
    free(blob_id);
    strarray_fini(&dst_mboxnames);
    if (src_mr) msgrecord_unref(&src_mr);
    jmap_closembox(req, &src_mbox);
    json_decref(new_keywords);
}

static void _email_copy_validate_props(json_t *jemail,
                                       const char *scheduled_uniqueid, json_t **err)
{
    struct jmap_parser myparser = JMAP_PARSER_INITIALIZER;

    /* Validate properties */
    json_t *prop, *id = NULL, *mailboxids = NULL;
    const char *pname;
    json_object_foreach(jemail, pname, prop) {
        if (!strcmp(pname, "id")) {
            if (!json_is_string(prop)) {
                jmap_parser_invalid(&myparser, "id");
            }
            id = prop;
        }
        else if (!strcmp(pname, "mailboxIds")) {
            jmap_parser_push(&myparser, "mailboxIds");
            const char *mbox_id;
            json_t *jbool;
            json_object_foreach(prop, mbox_id, jbool) {
                if (!strlen(mbox_id) || jbool != json_true() ||
                    !strcmpnull(scheduled_uniqueid, mbox_id)) {
                    jmap_parser_invalid(&myparser, NULL);
                    break;
                }
            }
            jmap_parser_pop(&myparser);
            mailboxids = prop;
        }
        else if (!strcmp(pname, "keywords")) {
            if (json_is_object(prop)) {
                jmap_parser_push(&myparser, "keywords");
                const char *keyword;
                json_t *jbool;
                json_object_foreach(prop, keyword, jbool) {
                    if (!jmap_email_keyword_is_valid(keyword) ||
                        jbool != json_true()) {
                        jmap_parser_invalid(&myparser, keyword);
                    }
                }
                jmap_parser_pop(&myparser);
            }
            else {
                jmap_parser_invalid(&myparser, "keywords");
            }
        }
        else if (!strcmp(pname, "receivedAt")) {
            if (!json_is_utcdate(prop)) {
                jmap_parser_invalid(&myparser, "receivedAt");
            }
        }
        else {
            jmap_parser_invalid(&myparser, pname);
        }
    }
    /* Check mandatory properties */
    if (!id) {
        jmap_parser_invalid(&myparser, "id");
    }
    if (!mailboxids) {
        jmap_parser_invalid(&myparser, "mailboxIds");
    }
    /* Reject invalid properties... */
    if (json_array_size(myparser.invalid)) {
        *err = json_pack("{s:s s:O}",
                         "type", "invalidProperties",
                         "properties", myparser.invalid);
    }

    jmap_parser_fini(&myparser);
}

static int jmap_email_copy(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_copy copy;
    json_t *err = NULL;
    struct seen *seendb = NULL;
    json_t *destroy_emails = json_array();
    const char *scheduled_uniqueid = NULL;
    const mbentry_t *scheduled_mbe = NULL;

    /* Parse request */
    jmap_copy_parse(req, &parser, NULL, NULL, &copy, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    int r = seen_open(req->userid, SEEN_CREATE, &seendb);
    if (r) {
        syslog(LOG_ERR, "jmap_email_copy: can't open seen.db: %s",
                        error_message(r));
        jmap_error(req, jmap_server_error(r));
        goto done;
    }

    jmap_findmbox_role(req, "scheduled", &scheduled_mbe);
    if (scheduled_mbe) {
        scheduled_uniqueid = scheduled_mbe->uniqueid;
    }
 
    /* Process request */
    const char *creation_id;
    json_t *copy_email;
    json_object_foreach(copy.create, creation_id, copy_email) {
        json_t *set_err = NULL;
        json_t *new_email = NULL;

        /* Validate create */
        _email_copy_validate_props(copy_email, scheduled_uniqueid, &set_err);
        if (set_err) {
            json_object_set_new(copy.not_created, creation_id, set_err);
            continue;
        }

        /* Copy message */
        _email_copy(req, copy_email, copy.from_account_id,
                    seendb, &new_email, &set_err);
        if (set_err) {
            json_object_set_new(copy.not_created, creation_id, set_err);
            continue;
        }

        /* Note the source ID for deletion */
        json_array_append(destroy_emails, json_object_get(copy_email, "id"));

        /* Report the message as created */
        json_object_set_new(copy.created, creation_id, new_email);
        const char *msg_id = json_string_value(json_object_get(new_email, "id"));
        jmap_add_id(req, creation_id, msg_id);
    }

    /* Build response */
    jmap_ok(req, jmap_copy_reply(&copy));

    /* Destroy originals, if requested */
    if (copy.on_success_destroy_original && json_array_size(destroy_emails)) {
        json_t *subargs = json_object();
        json_object_set(subargs, "destroy", destroy_emails);
        json_object_set_new(subargs, "accountId", json_string(copy.from_account_id));
        jmap_add_subreq(req, "Email/set", subargs, NULL);
    }

done:
    json_decref(destroy_emails);
    jmap_parser_fini(&parser);
    jmap_copy_fini(&copy);
    seen_close(&seendb);
    return 0;
}

static int jmap_email_matchmime_method(jmap_req_t *req)
{
    json_t *jfilter = json_object_get(req->args, "filter");
    json_t *jmime = json_object_get(req->args, "mime");
    json_t *err = NULL;

    struct buf mime = BUF_INITIALIZER;
    buf_setcstr(&mime, json_string_value(jmime));
    matchmime_t *matchmime = jmap_email_matchmime_new(&mime, &err);
    int matches = matchmime ? jmap_email_matchmime(matchmime, jfilter, 
            req->cstate, req->accountid,
            req->authstate, &jmap_namespace, time(NULL), &err) : 0;
    jmap_email_matchmime_free(&matchmime);
    buf_free(&mime);
    if (!err) {
        json_t *res = json_pack("{s:O s:b}", "filter", jfilter, "matches", matches);
        jmap_ok(req, res);
    }
    else {
        jmap_error(req, err);
    }

    return 0;
}

static int _decode_emailheader_blobid(const char *blobid,
                                      char **emailidptr,
                                      const char **hdrnameptr,
                                      const char **mimetypeptr)
{
    char *emailid = NULL;
    int is_valid = 0;

    /* Decode emailid */
    const char *base = blobid+1;
    const char *p = strchr(base, '-');
    if (!p || p-base != JMAP_EMAILID_SIZE-1) goto done;
    emailid = xstrndup(base, p-base);
    base = p + 1;

    /* Decode hdrname */
    if (*base == '\0') goto done;
    unsigned index;
    char *endptr = NULL;
    errno = 0;
    index = strtoul(base, &endptr, 10);
    if (errno == ERANGE || *endptr) goto done;
    base = endptr;

    /* All done */
    *emailidptr = emailid;
    *hdrnameptr = blob_headers[index].name;
    *mimetypeptr = blob_headers[index].type;
    is_valid = 1;

done:
    if (!is_valid) free(emailid);

    return is_valid;
}

static int jmap_emailheader_getblob(jmap_req_t *req, jmap_getblob_context_t *ctx)
{
    struct mailbox *mailbox = NULL;
    char *emailid = NULL;
    const char *hdrname = NULL;
    const char *mimetype = NULL;
    char *mboxname = NULL;
    uid_t uid = 0;
    int res = HTTP_OK;
    int r;

    if (ctx->blobid[0] != 'H') return 0;

    if (!_decode_emailheader_blobid(ctx->blobid, &emailid, &hdrname, &mimetype)) {
        res = HTTP_BAD_REQUEST;
        goto done;
    }

    /* Lookup emailid */
    r = jmap_email_find(req, ctx->from_accountid, emailid, &mboxname, &uid);
    if (r) {
        if (r == IMAP_NOTFOUND) res = HTTP_NOT_FOUND;
        else {
            ctx->errstr = error_message(r);
            res = HTTP_SERVER_ERROR;
        }
        goto done;
    }
    if (!jmap_hasrights(req, mboxname, JACL_READITEMS)) {
        res = HTTP_NOT_FOUND;
        goto done;
    }

    /* Make sure client can handle blob type. */
    if (ctx->accept_mime) {
        if (strcmp(ctx->accept_mime, "application/octet-stream") &&
            strcmpnull(ctx->accept_mime, mimetype)) {
            res = HTTP_NOT_ACCEPTABLE;
            goto done;
        }

        buf_setcstr(&ctx->content_type, ctx->accept_mime);
    }
    else if (mimetype) buf_setcstr(&ctx->content_type, mimetype);

    /* Open mailbox, we need it now */
    if ((r = jmap_openmbox(req, mboxname, &mailbox, 0))) {
        ctx->errstr = error_message(r);
        res = HTTP_SERVER_ERROR;
        goto done;
    }

    /* Load the message */
    msgrecord_t *mr = msgrecord_from_uid(mailbox, uid);
    if (!mr) {
        ctx->errstr = "failed to load message";
        res = HTTP_SERVER_ERROR;
        goto done;
    }

    message_t *msg;
    struct buf *blob = &ctx->blob;
    r = msgrecord_get_message(mr, &msg);
    if (!r) r = message_get_field(msg, hdrname, MESSAGE_RAW, blob);
    if (!r && buf_len(blob)) {
        static int initialized_re = 0;
        static regex_t whitespace_re;
        unsigned outlen;

        if (!initialized_re) {
            r = regcomp(&whitespace_re, "([ \t\r\n]+|\xC2\xA0)", REG_EXTENDED);
            assert(r == 0);
            initialized_re = 1;
        }

        /* eliminate whitespace */
        buf_replace_all_re(blob, &whitespace_re, "");

        if (ctx->decode) {
            /* base64-decode the data */
            r = sasl_decode64(buf_base(blob), buf_len(blob),
                              (char *) buf_base(blob), buf_len(blob), &outlen);
            if (r == SASL_OK) {
                buf_truncate(blob, outlen);
                buf_setcstr(&ctx->encoding, "BINARY");
            }
            else {
                ctx->errstr = "failed to decode blob";
                res = HTTP_SERVER_ERROR;
            }
        }
        else buf_setcstr(&ctx->encoding, "BASE64");
    }
    else {
        res = HTTP_NOT_FOUND;
    }
    msgrecord_unref(&mr);

done:
    if (res != HTTP_OK && !ctx->errstr) {
        const char *desc = NULL;
        switch (res) {
            case HTTP_BAD_REQUEST:
                desc = "invalid header blobid";
                break;
            case HTTP_NOT_FOUND:
                desc = "failed to find blob by header blobid";
                break;
            default:
                desc = error_message(res);
        }
        ctx->errstr = desc;
    }
    if (mailbox) jmap_closembox(req, &mailbox);
    free(emailid);
    free(mboxname);
    return res;
}
