/* jmap_notes.c -- Routines for handling JMAP notes
 *
 * Copyright (c) 1994-2020 Carnegie Mellon University.  All rights reserved.
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

#include "acl.h"
#include "append.h"
#include "http_jmap.h"
#include "http_proxy.h"
#include "jmap_mail.h"
#include "jmap_util.h"
#include "json_support.h"
#include "proxy.h"
#include "sync_support.h"
#include "times.h"
#include "user.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#define APPLE_NOTES_ID  "com.apple.mail-note"

static int jmap_note_get(jmap_req_t *req);
static int jmap_note_set(jmap_req_t *req);
static int jmap_note_changes(jmap_req_t *req);

static jmap_method_t jmap_notes_methods_standard[] = {
    { NULL, NULL, NULL, 0}
};

static jmap_method_t jmap_notes_methods_nonstandard[] = {
    {
        "Note/get",
        JMAP_NOTES_EXTENSION,
        &jmap_note_get,
        /*flags*/0
    },
    {
        "Note/set",
        JMAP_NOTES_EXTENSION,
        &jmap_note_set,
        JMAP_READ_WRITE
    },
    {
        "Note/changes",
        JMAP_NOTES_EXTENSION,
        &jmap_note_changes,
        /*flags*/0
    },
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_notes_init(jmap_settings_t *settings)
{
    if (!config_getstring(IMAPOPT_NOTESMAILBOX)) return;

    jmap_method_t *mp;
    for (mp = jmap_notes_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    json_object_set_new(settings->server_capabilities,
            JMAP_NOTES_EXTENSION, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        for (mp = jmap_notes_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }
}

HIDDEN void jmap_notes_capabilities(json_t *account_capabilities)
{
    if (!config_getstring(IMAPOPT_NOTESMAILBOX)) return;

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities,
                            JMAP_NOTES_EXTENSION, json_object());
    }
}

static int lookup_notes_collection(const char *accountid, mbentry_t **mbentry)
{
    mbname_t *mbname;
    const char *notesname;
    int r;

    /* Create notes mailbox name from the parsed path */
    mbname = mbname_from_userid(accountid);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_NOTESMAILBOX));

    /* XXX - hack to allow @domain parts for non-domain-split users */
    if (httpd_extradomain) {
        /* not allowed to be cross domain */
        if (mbname_localpart(mbname) &&
            strcmpsafe(mbname_domain(mbname), httpd_extradomain)) {
            r = HTTP_NOT_FOUND;
            goto done;
        }
        mbname_set_domain(mbname, NULL);
    }

    /* Locate the mailbox */
    notesname = mbname_intname(mbname);
    r = proxy_mlookup(notesname, mbentry, NULL, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Find location of INBOX */
        char *inboxname = mboxname_user_mbox(accountid, NULL);

        int r1 = proxy_mlookup(inboxname, mbentry, NULL, NULL);
        free(inboxname);
        if (r1 == IMAP_MAILBOX_NONEXISTENT) {
            r = IMAP_INVALID_USER;
            goto done;
        }

        int rights = httpd_myrights(httpd_authstate, *mbentry);
        if ((rights & JACL_CREATECHILD) != JACL_CREATECHILD) {
            r = IMAP_PERMISSION_DENIED;
            goto done;
        }

        if (*mbentry) free((*mbentry)->name);
        else *mbentry = mboxlist_entry_create();
        (*mbentry)->name = xstrdup(notesname);
    }
    else if (!r) {
        int rights = httpd_myrights(httpd_authstate, *mbentry);
        if ((rights & JACL_ADDITEMS) != JACL_ADDITEMS) {
            r = IMAP_PERMISSION_DENIED;
            goto done;
        }
    }

  done:
    mbname_free(&mbname);
    return r;
}


static int ensure_notes_collection(const char *accountid, mbentry_t **mbentryp)
{
    mbentry_t *mbentry = NULL;

    /* notes collection */
    int r = lookup_notes_collection(accountid, &mbentry);
    if (!r) { // happy path
        if (mbentryp) *mbentryp = mbentry;
        else mboxlist_entry_free(&mbentry);
        return 0;
    }

    // otherwise, clean up ready for next attempt
    mboxlist_entry_free(&mbentry);

    struct mboxlock *namespacelock = user_namespacelock(accountid);

    // did we lose the race?
    r = lookup_notes_collection(accountid, &mbentry);

    if (r == IMAP_MAILBOX_NONEXISTENT) {
        if (!mbentry) goto done;
        else if (mbentry->server) {
            proxy_findserver(mbentry->server, &http_protocol, httpd_userid,
                             &backend_cached, NULL, NULL, httpd_in);
            goto done;
        }

        r = mboxlist_createmailbox(mbentry->name, MBTYPE_EMAIL,
                                   NULL, 1 /* admin */, accountid,
                                   httpd_authstate,
                                   0, 0, 0, 0, NULL);
        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                   mbentry->name, error_message(r));
        }
        else {
            char *userid = mboxname_to_userid(mbentry->name);
            static const char *annot = "/specialuse";
            struct buf buf = BUF_INITIALIZER;

            buf_init_ro_cstr(&buf, "\\XNotes");
            r = annotatemore_write(mbentry->name, annot, userid, &buf);
            free(userid);
            buf_reset(&buf);
            if (r) {
                syslog(LOG_ERR, "failed to write annotation %s: %s",
                       annot, error_message(r));
                goto done;
            }
        }
    }

 done:
    mboxname_release(&namespacelock);
    if (mbentryp && !r) *mbentryp = mbentry;
    else mboxlist_entry_free(&mbentry);
    return r;
}

struct get_rock {
    struct jmap_get *get;
    struct buf *buf;
};

static int _note_get(message_t *msg, json_t *note, hash_table *props,
                     int want_created, struct buf *buf)
{
    int r;

    /* created */
    if (want_created) {
        r = message_get_field(msg, "X-Mail-Created-Date",
                              MESSAGE_DECODED|MESSAGE_TRIM, buf);
        if (r) return r;

        json_object_set_new(note, "created", json_string(buf_cstring(buf)));
    }

    /* isFlagged */
    if (jmap_wantprop(props, "isFlagged")) {
        uint32_t system_flags;

        r = message_get_systemflags(msg, &system_flags);
        if (r) return r;

        json_object_set_new(note, "isFlagged",
                            json_boolean(system_flags & FLAG_FLAGGED));
    }

    /* lastSaved */
    if (jmap_wantprop(props, "lastSaved")) {
        char datestr[RFC3339_DATETIME_MAX];
        time_t t;

        r = message_get_savedate(msg, &t);
        if (r) return r;

        time_to_rfc3339(t, datestr, RFC3339_DATETIME_MAX);
        json_object_set_new(note, "lastSaved", json_string(datestr));
    }

    /* title */
    if (jmap_wantprop(props, "title")) {
        buf_reset(buf);
        r = message_get_subject(msg, buf);
        if (r) return r;

        json_object_set_new(note, "title", json_string(buf_cstring(buf)));
    }

    /* body */
    if (jmap_wantprop(props, "body")) {
        int encoding = 0;
        const char *charset_id = NULL;
        charset_t charset = CHARSET_UNKNOWN_CHARSET;

        buf_reset(buf);
        r = message_get_body(msg, buf);
        if (!r) r = message_get_encoding(msg, &encoding);
        if (!r) r = message_get_charset_id(msg, &charset_id);
        if (r) return r;

        charset = charset_lookupname(charset_id);
        if (encoding || strcasecmp(charset_canon_name(charset), "utf-8")) {
            char *dec = charset_to_utf8(buf_cstring(buf), buf_len(buf),
                                        charset, encoding);
            buf_setcstr(buf, dec);
            free(dec);
        }
        charset_free(&charset);

        json_object_set_new(note, "body", json_string(buf_cstring(buf)));
    }

    /* isHTML */
    if (jmap_wantprop(props, "isHTML")) {
        const char *type = NULL, *subtype = NULL;

        r = message_get_type(msg, &type);
        if (!r) r = message_get_subtype(msg, &subtype);
        if (r) return r;

        int isHTML =
            !strcasecmpsafe("text", type) && !strcasecmpsafe("html", subtype);
        json_object_set_new(note, "isHTML", json_boolean(isHTML));
    }

    return 0;
}

static void _notes_get_cb(const char *id, message_t *msg,
                          void *data __attribute__((unused)), void *rock)
{
    struct get_rock *grock = (struct get_rock *) rock;
    struct jmap_get *get = grock->get;
    json_t *note = json_pack("{s:s}", "id", id);

    int r = _note_get(msg, note, get->props, 0/*want_created*/, grock->buf);

    if (!r) {
        json_array_append_new(get->list, note);
    }
    else {
        syslog(LOG_ERR, "jmap: Notes/get(%s): %s", id, error_message(r));
        json_array_append_new(get->not_found, json_string(id));
        json_decref(note);
    }
}

static void foreach_note(struct mailbox *mbox, hash_table *ids,
                         void (*proc)(const char *, message_t *, void *, void *),
                         void *rock)
{
    struct mailbox_iter *iter = mailbox_iter_init(mbox, 0, ITER_SKIP_EXPUNGED);
    struct buf buf = BUF_INITIALIZER;
    message_t *msg;

    while ((msg = (message_t *) mailbox_iter_step(iter))) {
        int r = message_get_field(msg, "X-Uniform-Type-Identifier",
                                  MESSAGE_DECODED|MESSAGE_TRIM, &buf);
        if (r || strcmp(APPLE_NOTES_ID, buf_cstring(&buf))) continue;

        r = message_get_field(msg, "X-Universally-Unique-Identifier",
                              MESSAGE_DECODED|MESSAGE_TRIM, &buf);
        if (r) continue;

        void *data = NULL;
        const char *id = buf_cstring(&buf);
        if (ids->size) {
            /* Do we have this id? */
            data = hash_lookup(id, ids);
            if (!data) {
                /* Not in our list to act on */
                continue;
            }

            hash_del(id, ids);
        }

        proc(id, msg, data, rock);
    }

    mailbox_iter_done(&iter);
    buf_free(&buf);
}

static void not_found_cb(const char *id,
                         void *data __attribute__((unused)), void *rock)
{
    json_t *json = (json_t *) rock;

    if (json_is_object(json)) {
        json_t *err = json_pack("{s:s}", "type", "notFound");
        json_object_set_new(json, id, err);
    }
    else {
        json_array_append_new(json, json_string(id));
    }
}

static const jmap_property_t notes_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "isFlagged",
        NULL,
        0
    },
    {
        "lastSaved",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "title",
        NULL,
        0
    },
    {
        "body",
        NULL,
        0
    },
    {
        "isHTML",
        NULL,
        0
    },
    { NULL, NULL, 0 }
};

static int jmap_note_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    mbentry_t *mbentry = NULL;
    struct mailbox *mbox = NULL;
    hash_table ids = HASH_TABLE_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    int rights;

    jmap_get_parse(req, &parser, notes_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    int r = ensure_notes_collection(req->accountid, &mbentry);
    if (r) {
        syslog(LOG_ERR,
               "jmap_note_get: ensure_notes_collection(%s): %s",
               req->accountid, error_message(r));
        goto done;
    }

    rights = jmap_myrights_mbentry(req, mbentry);

    r = jmap_openmbox(req, mbentry->name, &mbox, 0);
    mboxlist_entry_free(&mbentry);
    if (r) goto done;

    /* Does the client request specific notes? */
    if (JNOTNULL(get.ids)) {
        size_t i;
        json_t *val;

        construct_hash_table(&ids, 32, 0);
        
        json_array_foreach(get.ids, i, val) {
            hash_insert(json_string_value(val), (void *) 1, &ids);
        }
    }

    if ((rights & JACL_READITEMS) == JACL_READITEMS) {
        struct get_rock grock = { &get, &buf };
        foreach_note(mbox, &ids, &_notes_get_cb, &grock);
    }

    /* Any remaining ids are not found */
    hash_enumerate(&ids, &not_found_cb, get.not_found);
    free_hash_table(&ids, NULL);

    /* Build response */
    buf_reset(&buf);
    buf_printf(&buf, MODSEQ_FMT, mbox->i.highestmodseq);
    get.state = buf_release(&buf);
    jmap_ok(req, jmap_get_reply(&get));

    jmap_closembox(req, &mbox);

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);

    return 0;
}

static int _notes_setargs_check(const char *id, json_t *args, json_t **err)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    int is_create = !id;
    json_t *arg;
    int r = 0;

    /* Reject read-only properties */
    if (json_object_get(args, "lastSaved")) {
        jmap_parser_invalid(&parser, "lastSaved");
    }

    arg = json_object_get(args, "id");
    if (arg && (is_create || strcmpnull(id, json_string_value(arg)))) {
        jmap_parser_invalid(&parser, "id");
    }

    /* Type-check other properties */
    arg = json_object_get(args, "isFlagged");
    if (arg && !json_is_boolean(arg)) {
        jmap_parser_invalid(&parser, "isFlagged");
    }

    arg = json_object_get(args, "title");
    if (arg && !json_is_string(arg)) {
        jmap_parser_invalid(&parser, "title");
    }

    arg = json_object_get(args, "body");
    if (arg && (!json_is_string(arg) || !json_object_get(args, "isHTML"))) {
        jmap_parser_invalid(&parser, "body");
    }

    arg = json_object_get(args, "isHTML");
    if (arg && (!json_is_boolean(arg) || !json_object_get(args, "body"))) {
        jmap_parser_invalid(&parser, "isHTML");
    }

    if (json_array_size(parser.invalid)) {
        *err = json_pack("{s:s}", "type", "invalidProperties");
        json_object_set(*err, "properties", parser.invalid);
        r = -1;
    }

    jmap_parser_fini(&parser);

    return r;
}

static int _note_create(struct mailbox *mailbox, json_t *note, json_t **new_note)
{
    struct stagemsg *stage = NULL;
    struct appendstate as;
    strarray_t flags = STRARRAY_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    struct body *bodypart = NULL;
    char datestr[80], *from, *title, *body;
    FILE *f = NULL;
    int r = 0, isFlagged = 0, isHTML = 0, qpencode = 0;
    time_t now = time(0);
    json_t *prop;
    const char *uid = NULL, *created = NULL;

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox->name, now, 0, &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mailbox->name);
        r = IMAP_IOERROR;
        goto done;
    }

    *new_note = json_object();

    prop = json_object_get(note, "id");
    if (prop) uid = json_string_value(prop);
    else {
        uid = makeuuid();
        json_object_set_new(*new_note, "id", json_string(uid));
    }

    time_to_rfc3339(now, datestr, sizeof(datestr));
    json_object_set_new(*new_note, "lastSaved", json_string(datestr));

    time_to_rfc5322(now, datestr, sizeof(datestr));

    prop = json_object_get(note, "created");
    if (prop) created = json_string_value(prop);
    else created = datestr;

    prop = json_object_get(note, "title");
    if (prop) {
        buf_init_ro_cstr(&buf, json_string_value(prop));
        title = charset_encode_mimeheader(buf_base(&buf), buf_len(&buf), 0);
    }
    else {
        title = xstrdup("");
        json_object_set_new(*new_note, "title", json_string(title));
    }

    prop = json_object_get(note, "body");
    if (prop) {
        buf_init_ro_cstr(&buf, json_string_value(prop));

        const char *cp;
        for (cp = buf_base(&buf); *cp; cp++) {
            if (*cp & 0x80) {
                qpencode = 1;
                break;
            }
        }
        if (qpencode) {
            body = charset_qpencode_mimebody(buf_base(&buf),
                                             buf_len(&buf), 0, NULL);
        }
        else body = buf_release(&buf);
    }
    else {
        body = xstrdup("");
        json_object_set_new(*new_note, "body", json_string(body));
    }

    prop = json_object_get(note, "isHTML");
    if (prop) isHTML = json_boolean_value(prop);
    else json_object_set_new(*new_note, "isHTML", json_false());

    prop = json_object_get(note, "isFlagged");
    if (prop) isFlagged = json_boolean_value(prop);
    else json_object_set_new(*new_note, "isFlagged", json_false());

    buf_reset(&buf);
    if (strchr(httpd_userid, '@')) {
        /* XXX  This needs to be done via an LDAP/DB lookup */
        buf_printf(&buf, "<%s>", httpd_userid);
    }
    else {
        buf_printf(&buf, "<%s@%s>", httpd_userid, config_servername);
    }
    from = charset_encode_mimeheader(buf_cstring(&buf), buf_len(&buf), 0);

    fprintf(f, "MIME-Version: 1.0 (Cyrus-JMAP/%s)\r\n"
            "X-Uniform-Type-Identifier: %s\r\n"
            "X-Universally-Unique-Identifier: %s\r\n"
            "X-Mail-Created-Date: %s\r\n"
            "Date: %s\r\n"
            "From: %s\r\n"
            "Subject: %s\r\n"
            "Content-Type: text/%s; charset=utf-8\r\n"
            "Content-Transfer-Encoding: %s\r\n\r\n"
            "%s",
            CYRUS_VERSION, APPLE_NOTES_ID, uid, created, datestr, from, title,
            isHTML ? "html" : "plain",
            qpencode ? "quoted-printable" : "7-bit",
            body);
    free(title);
    free(from);
    free(body);
    if (ferror(f) || fflush(f)) {
        r = IMAP_IOERROR;
    }
    fclose(f);
    if (r) goto done;

    /* Prepare to append the message to the mailbox */
    r = append_setup_mbox(&as, mailbox, httpd_userid, httpd_authstate,
                          0, /*quota*/NULL, 0, 0, /*event*/0);
    if (r) {
        syslog(LOG_ERR, "append_setup(%s) failed: %s",
               mailbox->name, error_message(r));
        goto done;
    }

    /* Append the message to the mailbox */
    if (isFlagged) strarray_append(&flags, "\\Flagged");
    r = append_fromstage(&as, &bodypart, stage, now, 0,
                         &flags, 0, /*annots*/NULL);

    if (r) {
        append_abort(&as);
        syslog(LOG_ERR, "append_fromstage(%s) failed: %s",
               mailbox->name, error_message(r));
        goto done;
    }

    r = append_commit(&as);
    if (r) {
        syslog(LOG_ERR, "append_commit(%s) failed: %s",
               mailbox->name, error_message(r));
        goto done;
    }

  done:
    buf_free(&buf);
    if (bodypart) {
        message_free_body(bodypart);
        free(bodypart);
    }
    strarray_fini(&flags);
    append_removestage(stage);
    if (mailbox) {
        if (r) mailbox_abort(mailbox);
        else r = mailbox_commit(mailbox);
    }
    if (r) {
        json_decref(*new_note);
        *new_note = NULL;
    }

    return r;
}

struct set_rock {
    struct jmap_set *set;
    struct buf *buf;
    int rights;
};

static void _notes_update_cb(const char *id, message_t *msg,
                             void *data, void *rock)
{
    json_t *patch = (json_t *) data;
    struct set_rock *srock = (struct set_rock *) rock;
    struct jmap_set *set = srock->set;
    json_t *err = NULL, *updated_note = NULL;
    int r;

    if ((srock->rights & JACL_UPDATEITEMS) != JACL_UPDATEITEMS) {
        int read_only = !(srock->rights & JACL_READITEMS);

        err = json_pack("{s:s}", "type",
                            read_only ? "notFound" : "forbidden");
    }
    else if (!_notes_setargs_check(id, patch, &err)) {
        json_t *note = json_pack("{s:s}", "id", id);

        r = _note_get(msg, note, NULL, 1/*want_created*/, srock->buf);

        if (r) {
            syslog(LOG_ERR, "jmap: Notes/update(%s) fetch: %s",
                   id, error_message(r));
        }
        else {
            json_t *new_note = jmap_patchobject_apply(note, patch, NULL);

            if (new_note) {
                r = _note_create(msg_mailbox(msg), new_note, &updated_note);
                json_decref(new_note);
            }
            else {
                r = IMAP_INTERNAL;
                syslog(LOG_ERR, "jmap: Notes/update(%s) patch: %s",
                       id, error_message(r));
            }
        }
        json_decref(note);

        if (!r) {
            const struct index_record *record = msg_record(msg);
            struct mailbox *mailbox = msg_mailbox(msg);
            struct index_record newrecord;
            int userflag;

            memcpy(&newrecord, record, sizeof(struct index_record));
            r = mailbox_user_flag(mailbox, DFLAG_UNBIND, &userflag, 1);
            if (!r) {
                newrecord.user_flags[userflag/32] |= 1 << (userflag & 31);
                newrecord.internal_flags |= FLAG_INTERNAL_EXPUNGED;

                r = mailbox_rewrite_index_record(mailbox, &newrecord);
            }
        }

        if (r) {
            err = json_pack("{s:s, s:s}", "type", "serverFail",
                                "description", error_message(r));
        }
    }

    if (err) {
        json_object_set_new(set->not_updated, id, err);
    }
    else {
        json_object_set_new(set->updated, id, updated_note);
    }
}

static void _notes_destroy_cb(const char *id, message_t *msg,
                              void *data __attribute__((unused)), void *rock)
{
    struct set_rock *srock = (struct set_rock *) rock;
    struct jmap_set *set = srock->set;
    json_t *err = NULL;

    if ((srock->rights & JACL_REMOVEITEMS) != JACL_REMOVEITEMS) {
        int read_only = !(srock->rights & JACL_READITEMS);

        err = json_pack("{s:s}", "type",
                            read_only ? "notFound" : "forbidden");
    }
    else {
        const struct index_record *record = msg_record(msg);
        struct index_record newrecord;

        memcpy(&newrecord, record, sizeof(struct index_record));
        newrecord.internal_flags |= FLAG_INTERNAL_EXPUNGED;

        int r = mailbox_rewrite_index_record(msg_mailbox(msg), &newrecord);
        if (r) {
            err = json_pack("{s:s, s:s}", "type", "serverFail",
                                "description", error_message(r));
        }
    }

    if (err) {
        json_object_set_new(set->not_destroyed, id, err);
    }
    else {
        json_array_append_new(set->destroyed, json_string(id));
    }
}

static int jmap_note_set(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    struct mailbox *mbox = NULL;
    mbentry_t *mbentry = NULL;
    struct buf buf = BUF_INITIALIZER;
    json_t *err = NULL;
    int rights, r;

    /* Parse request */
    jmap_set_parse(req, &parser, notes_props, NULL, NULL, &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidProperties");
        json_object_set(err, "properties", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    /* Process request */

    r = ensure_notes_collection(req->accountid, &mbentry);
    if (r) {
        syslog(LOG_ERR,
               "jmap_note_set: ensure_notes_collection(%s): %s",
               req->accountid, error_message(r));
        goto done;
    }

    rights = jmap_myrights_mbentry(req, mbentry);

    r = jmap_openmbox(req, mbentry->name, &mbox, 1);
    assert(mbox);
    mboxlist_entry_free(&mbentry);
    if (r) goto done;

    buf_printf(&buf, MODSEQ_FMT, mbox->i.highestmodseq);
    set.old_state = buf_release(&buf);

    if (set.if_in_state && strcmp(set.if_in_state, set.old_state)) {
        jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
        goto done;
    }

    
    /* create */
    const char *creation_id, *id;
    json_t *val;

    json_object_foreach(set.create, creation_id, val) {
        json_t *new_note = NULL;

        if ((rights & JACL_ADDITEMS) != JACL_ADDITEMS) {
            err = json_pack("{s:s}", "type", "forbidden");
        }
        else if (!_notes_setargs_check(NULL/*id*/, val, &err)) {
            r = _note_create(mbox, val, &new_note);
            if (r) err = jmap_server_error(r);
        }
        if (err) {
            json_object_set_new(set.not_created, creation_id, err);
        }
        else {
            /* Report note as created */
            json_object_set_new(set.created, creation_id, new_note);

            /* Register creation id */
            id = json_string_value(json_object_get(new_note, "id"));
            jmap_add_id(req, creation_id, id);
        }
    }


    /* update */
    hash_table ids = HASH_TABLE_INITIALIZER;
    struct set_rock srock = { &set, &buf, rights };

    construct_hash_table(&ids, 32, 0);

    /* Build hash of ids */
    json_object_foreach(set.update, id, val) {
        hash_insert(id, val, &ids);
    }

    /* Iterate through each message and update matching ids */
    foreach_note(mbox, &ids, &_notes_update_cb, &srock);

    /* Any remaining ids are not updated */
    hash_enumerate(&ids, &not_found_cb, set.not_updated);
    free_hash_table(&ids, NULL);

    
    /* destroy */
    construct_hash_table(&ids, 32, 0);

    /* Build hash of ids */
    size_t i;
    json_array_foreach(set.destroy, i, val) {
        hash_insert(json_string_value(val), (void *) 1, &ids);
    }

    /* Iterate through each message and destroy matching ids */
    foreach_note(mbox, &ids, &_notes_destroy_cb, &srock);

    /* Any remaining ids are not destroyed */
    hash_enumerate(&ids, &not_found_cb, set.not_destroyed);
    free_hash_table(&ids, NULL);


    /* force modseq to stable */
    mailbox_unlock_index(mbox, NULL);

    /* Build response */
    buf_reset(&buf);
    buf_printf(&buf, MODSEQ_FMT, mbox->i.highestmodseq);
    set.new_state = buf_release(&buf);
    jmap_ok(req, jmap_set_reply(&set));

done:
    jmap_closembox(req, &mbox);
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    return 0;
}

struct change {
    modseq_t modseq;
    json_t *id;
    json_t *list;
};

static int change_cmp(const void **a, const void **b)
{
    const struct change *chg_a = (const struct change *) *a;
    const struct change *chg_b = (const struct change *) *b;

    return (chg_a - chg_b);
}

static int jmap_note_changes(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;
    struct mailbox *mbox = NULL;
    mbentry_t *mbentry = NULL;
    int userflag;

    json_t *err = NULL;
    jmap_changes_parse(req, &parser, req->counters.notesdeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    int r = ensure_notes_collection(req->accountid, &mbentry);
    if (r) {
        syslog(LOG_ERR,
               "jmap_note_changes: ensure_submission_collection(%s): %s",
               req->accountid, error_message(r));
        goto done;
    }

    r = jmap_openmbox(req, mbentry->name, &mbox, 0);
    mboxlist_entry_free(&mbentry);

    r = mailbox_user_flag(mbox, DFLAG_UNBIND, &userflag, 0);
    if (r) userflag = -1;

    if (r) goto done;

    struct mailbox_iter *iter = mailbox_iter_init(mbox, changes.since_modseq, 0);
    modseq_t highest_modseq = mbox->i.highestmodseq;
    ptrarray_t changed_msgs = PTRARRAY_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    const message_t *msg;

    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        json_t *change_list;
        const char *id;

        /* Determine the type of change */
        if (record->internal_flags & FLAG_INTERNAL_EXPUNGED) {
            /* Skip any notes that have been replaced by an update */
            if (userflag >= 0 &&
                record->user_flags[userflag/32] & (1<<(userflag & 31))) continue;

            /* Skip any notes created AND deleted since modseq */
            if (record->createdmodseq > changes.since_modseq) continue;

            change_list = changes.destroyed;
        }
        else if (record->createdmodseq > changes.since_modseq) {
            change_list = changes.created;
        }
        else {
            change_list = changes.updated;
        }

        /* Fetch note uid */
        if (message_get_field((message_t *) msg,
                              "X-Universally-Unique-Identifier",
                              MESSAGE_DECODED|MESSAGE_TRIM, &buf)) continue;
        id = buf_cstring(&buf);

        if (changes.max_changes) {
            /* Add change to a list to be sorted nby modseq later */
            struct change *change = xmalloc(sizeof(struct change));

            ptrarray_append(&changed_msgs, change);
            change->modseq = record->modseq;
            change->id = json_string(id);
            change->list = change_list;
        }
        else {
            /* Add change to the proper array in the response */
            json_array_append_new(change_list, json_string(id));
        }
    }
    mailbox_iter_done(&iter);
    jmap_closembox(req, &mbox);
    buf_free(&buf);

    if (changes.max_changes) {
        int i;

        if ((size_t) ptrarray_size(&changed_msgs) > changes.max_changes) {
            /* Sort changes by modseq */
            changes.has_more_changes = 1;
            ptrarray_sort(&changed_msgs, &change_cmp);

            /* Determine where to cutoff our list of changes
               (MUST NOT split changes having the same modseq) */
            struct change *change =
                ptrarray_nth(&changed_msgs, changes.max_changes);
            highest_modseq = change->modseq;

            for (i = changes.max_changes - 1; i >= 0; i--) {
                change = ptrarray_nth(&changed_msgs, i);
                if (change->modseq < highest_modseq) {
                    highest_modseq = change->modseq;
                    changes.max_changes = i+1;
                    break;
                }
            }
            if (i < 0) {
                /* too many changes */
            }
        }

        /* Output and/or free the changes */
        for (i = 0; i < ptrarray_size(&changed_msgs); i++) {
            struct change *change = ptrarray_nth(&changed_msgs, i);

            if ((size_t) i < changes.max_changes) {
                /* Add change to the proper array in the response */
                json_array_append_new(change->list, change->id);
            }
            else {
                /* Throw this change away */
                json_decref(change->id);
            }

            free(change);
        }
    }
    ptrarray_fini(&changed_msgs);

    /* Set new state */
    changes.new_modseq = highest_modseq;

    jmap_ok(req, jmap_changes_reply(&changes));

done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    return 0;
}
