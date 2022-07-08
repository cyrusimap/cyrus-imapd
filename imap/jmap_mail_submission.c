/* jmap_mail_submission.c -- Routines for handling JMAP mail submission
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>

#include "acl.h"
#include "append.h"
#include "http_jmap.h"
#include "http_proxy.h"
#include "jmap_mail.h"
#include "jmap_util.h"
#include "json_support.h"
#include "parseaddr.h"
#include "proxy.h"
#include "smtpclient.h"
#include "sync_support.h"
#include "times.h"
#include "user.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

#define JMAP_SUBID_SIZE 12

static int jmap_emailsubmission_get(jmap_req_t *req);
static int jmap_emailsubmission_set(jmap_req_t *req);
static int jmap_emailsubmission_changes(jmap_req_t *req);
static int jmap_emailsubmission_query(jmap_req_t *req);
static int jmap_emailsubmission_querychanges(jmap_req_t *req);
static int jmap_identity_get(jmap_req_t *req);

static jmap_method_t jmap_emailsubmission_methods_standard[] = {
    {
        "EmailSubmission/get",
        JMAP_URN_SUBMISSION,
        &jmap_emailsubmission_get,
        JMAP_NEED_CSTATE
    },
    {
        "EmailSubmission/set",
        JMAP_URN_SUBMISSION,
        &jmap_emailsubmission_set,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "EmailSubmission/changes",
        JMAP_URN_SUBMISSION,
        &jmap_emailsubmission_changes,
        JMAP_NEED_CSTATE
    },
    {
        "EmailSubmission/query",
        JMAP_URN_SUBMISSION,
        &jmap_emailsubmission_query,
        JMAP_NEED_CSTATE
    },
    {
        "EmailSubmission/queryChanges",
        JMAP_URN_SUBMISSION,
        &jmap_emailsubmission_querychanges,
        JMAP_NEED_CSTATE
    },
    {
        "Identity/get",
        JMAP_URN_SUBMISSION,
        &jmap_identity_get,
        /*flags*/0
    },
    { NULL, NULL, NULL, 0}
};

static jmap_method_t jmap_emailsubmission_methods_nonstandard[] = {
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_emailsubmission_init(jmap_settings_t *settings)
{
    jmap_method_t *mp;
    for (mp = jmap_emailsubmission_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    json_object_set_new(settings->server_capabilities,
            JMAP_URN_SUBMISSION, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        for (mp = jmap_emailsubmission_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }
}

HIDDEN void jmap_emailsubmission_capabilities(json_t *account_capabilities)
{
    static json_t *submit_capabilities = NULL;
    smtpclient_t *smp = NULL;

    if (!submit_capabilities && !smtpclient_open(&smp)) {
        /* determine extensions from submission server */
        json_t *submit_ext = json_object();
        const char *smtp_capa[] = { "FUTURERELEASE", "SIZE", "DSN",
                                    "DELIVERBY", "MT-PRIORITY", NULL };
        const char **capa;
        struct buf buf = BUF_INITIALIZER;
        int delay_time = config_getduration(IMAPOPT_JMAP_MAX_DELAYED_SEND, 's');
        if (delay_time < 0) delay_time = 0;

        for (capa = smtp_capa; *capa; capa++) {
            const char *args = smtpclient_has_ext(smp, *capa);

            if (args) {
                strarray_t *sa = strarray_split(args, NULL, STRARRAY_TRIM);
                json_t *jargs = json_array();
                int i;

                for (i = 0; i < strarray_size(sa); i++) {
                    buf_setcstr(&buf, strarray_nth(sa, i));
                    json_array_append_new(jargs, json_string(buf_lcase(&buf)));
                }
                strarray_free(sa);

                buf_setcstr(&buf, *capa);
                json_object_set_new(submit_ext, buf_lcase(&buf), jargs);
            }
        }
        smtpclient_close(&smp);
        buf_free(&buf);
        submit_capabilities = json_pack("{s:i s:o}",
                                        "maxDelayedSend", delay_time,
                                        "submissionExtensions", submit_ext);
    }

    json_object_set(account_capabilities, JMAP_URN_SUBMISSION, submit_capabilities);
}

static int _emailsubmission_address_parse(json_t *addr,
                                          struct jmap_parser *parser,
                                          time_t *holduntil)
{
    int is_valid = 0;

    if (holduntil) *holduntil = 0;

    json_t *email = json_object_get(addr, "email");
    if (email && json_string_value(email)) {
        struct address *a = NULL;
        parseaddr_list(json_string_value(email), &a);
        if (a && !a->invalid && a->mailbox && a->domain && !a->next) {
            is_valid = 1;
        }
        parseaddr_free(a);
    }
    else {
        jmap_parser_invalid(parser, "email");
    }

    const char *key;
    json_t *jval;
    json_t *parameters = json_object_get(addr, "parameters");
    jmap_parser_push(parser, "parameters");
    json_object_foreach(parameters, key, jval) {
        if (!smtp_is_valid_esmtp_keyword(key)) {
            jmap_parser_invalid(parser, key);
        }
        else if (JNOTNULL(jval) && !json_is_string(jval)) {
            /* We'll xtext-encode any non-esmtp values later */
            jmap_parser_invalid(parser, key);
        }
        else if (holduntil) {
            const char *val = json_string_value(jval);

            if (!strcasecmp(key, "HOLDFOR")) {
                char *endptr = (char *) val;
                ulong interval = val ? strtoul(val, &endptr, 10) : ULONG_MAX;
                time_t now = time(0);

                if (endptr == val || *endptr != '\0' ||
                    interval > 99999999 /* per RFC 4865 */) {
                    jmap_parser_invalid(parser, key);
                }
                else *holduntil = now + interval;
            }
            else if (!strcasecmp(key, "HOLDUNTIL")) {
                if (!val || time_from_iso8601(val, holduntil) < 0) {
                    jmap_parser_invalid(parser, key);
                }
            }
        }
    }
    jmap_parser_pop(parser);

    return is_valid;
}

static int lookup_submission_collection(const char *accountid,
                                        mbentry_t **mbentry)
{
    mbname_t *mbname;
    const char *submissionname;
    int r;

    /* Create submission mailbox name from the parsed path */
    mbname = mbname_from_userid(accountid);
    mbname_push_boxes(mbname, config_getstring(IMAPOPT_JMAPSUBMISSIONFOLDER));

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
    submissionname = mbname_intname(mbname);
    r = proxy_mlookup(submissionname, mbentry, NULL, NULL);
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

        mboxlist_entry_free(mbentry);
        *mbentry = mboxlist_entry_create();
        (*mbentry)->name = xstrdup(submissionname);
        (*mbentry)->mbtype = MBTYPE_JMAPSUBMIT;
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


static int ensure_submission_collection(const char *accountid,
                                        mbentry_t **mbentryp,
                                        int *created)
{
    mbentry_t *mbentry = NULL;
    if (created) *created = 0;

    /* submission collection */
    int r = lookup_submission_collection(accountid, &mbentry);
    if (!r) { // happy path
        if (mbentryp) *mbentryp = mbentry;
        else mboxlist_entry_free(&mbentry);
        return 0;
    }

    // otherwise, clean up ready for next attempt
    mboxlist_entry_free(&mbentry);

    struct mboxlock *namespacelock = user_namespacelock(accountid);

    // did we lose the race?
    r = lookup_submission_collection(accountid, &mbentry);

    if (r == IMAP_MAILBOX_NONEXISTENT) {
        if (created) *created = 1;

        if (!mbentry) goto done;
        else if (mbentry->server) {
            proxy_findserver(mbentry->server, &http_protocol, httpd_userid,
                             &backend_cached, NULL, NULL, httpd_in);
            goto done;
        }

        int options = config_getint(IMAPOPT_MAILBOX_DEFAULT_OPTIONS)
            | OPT_POP3_NEW_UIDL | OPT_IMAP_HAS_ALARMS;
        r = mboxlist_createmailbox(mbentry, options, 0/*highestmodseq*/,
                                   1/*isadmin*/, accountid, httpd_authstate,
                                   0/*flags*/, NULL/*mailboxptr*/);
        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                   mbentry->name, error_message(r));
        }
    }

 done:
    mboxname_release(&namespacelock);
    if (mbentryp && !r) *mbentryp = mbentry;
    else mboxlist_entry_free(&mbentry);
    return r;
}

static int store_submission(jmap_req_t *req, struct mailbox *mailbox,
                            struct buf *msg, time_t holduntil,
                            json_t *emailsubmission,
                            json_t **new_submission)
{
    struct stagemsg *stage = NULL;
    struct appendstate as;
    strarray_t flags = STRARRAY_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    struct body *body = NULL;
    char datestr[80], *from;
    size_t msglen = buf_len(msg);
    FILE *f = NULL;
    int r;
    time_t now = time(0);
    time_t internaldate = holduntil;

    if (!holduntil) {
        /* Already sent */
        msglen = 0;
        internaldate = now;
        strarray_append(&flags, "\\Answered");
        if (config_getswitch(IMAPOPT_JMAPSUBMISSION_DELETEONSEND)) {
            /* delete the EmailSubmission object immediately */
            strarray_append(&flags, "\\Deleted");
            // this non-standard flag is magic and works on the append layer
            strarray_append(&flags, "\\Expunged");
        }
    }

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox_name(mailbox), internaldate, 0, &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mailbox_name(mailbox));
        r = IMAP_IOERROR;
        goto done;
    }

    /* Stage the message to send as message/rfc822 */
    time_to_rfc5322(now, datestr, sizeof(datestr));

    if (strchr(httpd_userid, '@')) {
        /* XXX  This needs to be done via an LDAP/DB lookup */
        buf_printf(&buf, "<%s>", httpd_userid);
    }
    else {
        buf_printf(&buf, "<%s@%s>", httpd_userid, config_servername);
    }

    from = charset_encode_mimeheader(buf_cstring(&buf), buf_len(&buf), 0);

    fprintf(f, "MIME-Version: 1.0\r\n"
            "Date: %s\r\n"
            "From: %s\r\n"
            "Subject: JMAP EmailSubmission for %s\r\n"
            "Content-Type: message/rfc822\r\n"
            "Content-Length: %ld\r\n"
            "%s: ", datestr, from,
            json_string_value(json_object_get(emailsubmission, "emailId")),
            msglen, JMAP_SUBMISSION_HDR);
    free(from);

    /* Add JMAP submission object as content of header field */
    size_t size = json_dumpb(emailsubmission, NULL, 0, 0);
    buf_truncate(&buf, size);
    size = json_dumpb(emailsubmission,
                      (char *) buf_base(&buf), size, JSON_COMPACT);
    r = fwrite(buf_base(&buf), size, 1, f);
    buf_free(&buf);
    if (!r) {
        r = IMAP_IOERROR;
        goto done;
    }
    fputs("\r\n\r\n", f);

    /* Add submitted message */
    if ((msglen && !fwrite(buf_base(msg), msglen, 1, f)) || fflush(f)) {
        r = IMAP_IOERROR;
        goto done;
    }
    fclose(f);

    /* Prepare to append the message to the mailbox */
    r = append_setup_mbox(&as, mailbox, httpd_userid, httpd_authstate,
                          0, /*quota*/NULL, 0, 0, /*event*/0);
    if (r) {
        syslog(LOG_ERR, "append_setup(%s) failed: %s",
               mailbox_name(mailbox), error_message(r));
        goto done;
    }

    /* Append the message to the mailbox */
    r = append_fromstage_full(&as, &body, stage, internaldate, now,
                              /*cmodseq*/0, &flags, /*nolink*/0, /*annots*/NULL);

    if (r) {
        append_abort(&as);
        syslog(LOG_ERR, "append_fromstage(%s) failed: %s",
               mailbox_name(mailbox), error_message(r));
        goto done;
    }

    r = append_commit(&as);
    if (r) {
        syslog(LOG_ERR, "append_commit(%s) failed: %s",
               mailbox_name(mailbox), error_message(r));
        goto done;
    }

    /* Create id from message UID, using 'S' prefix */
    char sub_id[JMAP_SUBID_SIZE];
    sprintf(sub_id, "S%u", mailbox->i.last_uid);

    char sendat[RFC3339_DATETIME_MAX];
    time_to_rfc3339(internaldate, sendat, RFC3339_DATETIME_MAX);

    // XXX: we should include all the other fields from the spec
    *new_submission = json_pack("{s:s, s:s, s:s}",
         "id", sub_id,
         "undoStatus", (holduntil ? "pending" : "final"),
         "sendAt", sendat
    );

    if (jmap_is_using(req, JMAP_MAIL_EXTENSION)) {
        char created[RFC3339_DATETIME_MAX];
        time_to_rfc3339(now, created, RFC3339_DATETIME_MAX);

        json_object_set_new(*new_submission, "created", json_string(created));
    }

  done:
    if (body) {
        message_free_body(body);
        free(body);
    }
    strarray_fini(&flags);
    append_removestage(stage);
    if (mailbox) {
        if (r) mailbox_abort(mailbox);
        else r = mailbox_commit(mailbox);
    }

    return r;
}

static void _emailsubmission_create(jmap_req_t *req,
                                    struct mailbox *submbox,
                                    json_t *emailsubmission,
                                    json_t **new_submission,
                                    json_t **set_err,
                                    smtpclient_t **sm, char **emailid)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;

    /* messageId */
    json_t *jemailId = json_object_get(emailsubmission, "emailId");
    const char *msgid = jmap_id_string_value(req, jemailId);
    if (!msgid) {
        jmap_parser_invalid(&parser, "emailId");
    }
    *emailid = xstrdupnull(msgid);

    /* identityId */
    const char *identityid = NULL;
    json_t *jidentityId = json_object_get(emailsubmission, "identityId");
    if (JNOTNULL(jidentityId)) {
        if (json_is_string(jidentityId)) {
            identityid = json_string_value(jidentityId);
        }
        else {
            jmap_parser_invalid(&parser, "identityId");
        }
    }

    /* envelope */
    time_t holduntil = 0;
    json_t *envelope = json_object_get(emailsubmission, "envelope");
    if (JNOTNULL(envelope)) {
        jmap_parser_push(&parser, "envelope");
        json_t *from = json_object_get(envelope, "mailFrom");
        if (json_object_size(from)) {
            jmap_parser_push(&parser, "mailFrom");
            _emailsubmission_address_parse(from, &parser, &holduntil);
            jmap_parser_pop(&parser);
        }
        else {
            jmap_parser_invalid(&parser, "mailFrom");
        }
        json_t *rcpt = json_object_get(envelope, "rcptTo");
        if (json_array_size(rcpt)) {
            size_t i;
            json_t *addr;
            json_array_foreach(rcpt, i, addr) {
                jmap_parser_push_index(&parser, "rcptTo", i, NULL);
                _emailsubmission_address_parse(addr, &parser, NULL);
                jmap_parser_pop(&parser);
            }
        }
        else {
            jmap_parser_invalid(&parser, "rcptTo");
        }

        /* Don't allow mailFrom IDENTITY param to be different than identityId */
        json_t *jmapid =
            json_object_get(json_object_get(json_object_get(envelope,
                                                            "mailFrom"),
                                            "parameters"),
                            "IDENTITY");
        if (jmapid && strcmpnull(identityid, json_string_value(jmapid))) {
            jmap_parser_invalid(&parser, "identity");
        }
        jmap_parser_pop(&parser);
    } else {
        envelope = NULL;
    }

    json_t *onSend = json_object_get(emailsubmission, "onSend");
    if (JNOTNULL(onSend)) {
        const char *field;
        json_t *jval;

        jmap_parser_push(&parser, "onSend");
        json_object_foreach(onSend, field, jval) {
            if (!strcmp(field, "moveToMailboxId")) {
                if (JNOTNULL(jval) && !json_is_string(jval)) {
                    jmap_parser_invalid(&parser, "moveToMailboxId");
                }
            }
            else if (!strcmp(field, "setKeywords")) {
                const char *keyword;
                json_t *jbool;

                jmap_parser_push(&parser, "setKeywords");
                json_object_foreach(jval, keyword, jbool) {
                    if (!json_is_boolean(jbool) ||
                        !jmap_email_keyword_is_valid(keyword)) {
                        jmap_parser_invalid(&parser, keyword);
                    }
                }
                jmap_parser_pop(&parser);
            }
            else {
                jmap_parser_invalid(&parser, field);
            }
        }
        jmap_parser_pop(&parser);
    }

    /* Reject read-only properties */
    if (json_object_get(emailsubmission, "id")) {
        jmap_parser_invalid(&parser, "id");
    }
    if (json_object_get(emailsubmission, "threadId")) {
        jmap_parser_invalid(&parser, "threadId");
    }
    if (json_object_get(emailsubmission, "created")) {
        jmap_parser_invalid(&parser, "created");
    }
    if (json_object_get(emailsubmission, "sendAt")) {
        jmap_parser_invalid(&parser, "sendAt");
    }
    if (json_object_get(emailsubmission, "undoStatus")) {
        jmap_parser_invalid(&parser, "undoStatus");
    }
    if (json_object_get(emailsubmission, "deliveryStatus")) {
        jmap_parser_invalid(&parser, "deliveryStatus");
    }
    if (json_object_get(emailsubmission, "dsnBlobIds")) {
        jmap_parser_invalid(&parser, "dsnBlobIds");
    }
    if (json_object_get(emailsubmission, "mdnBlobIds")) {
        jmap_parser_invalid(&parser, "mdnBlobIds");
    }

    if (json_array_size(parser.invalid)) {
        *set_err = json_pack("{s:s}", "type", "invalidProperties");
        json_object_set(*set_err, "properties", parser.invalid);
        jmap_parser_fini(&parser);
        return;
    }
    jmap_parser_fini(&parser);

    /* No more returns from here on */
    char *mboxname = NULL;
    uint32_t uid = 0;
    struct mailbox *mbox = NULL;
    json_t *myenvelope = NULL;
    msgrecord_t *mr = NULL;
    json_t *msg = NULL;
    int r = 0;
    int fd_msg = -1;

    /* Lookup the message */
    r = jmap_email_find(req, NULL, msgid, &mboxname, &uid);
    if (r) {
        if (r == IMAP_NOTFOUND) {
            *set_err = json_pack("{s:s}", "type", "emailNotFound");
        }
        goto done;
    }

    /* Check ACL */
    if (!jmap_hasrights(req, mboxname, JACL_READITEMS)) {
        *set_err = json_pack("{s:s}", "type", "emailNotFound");
        goto done;
    }

    /* Open the mailboxes */
    r = jmap_openmbox(req, mboxname, &mbox, 1);
    if (r) goto done;

    /* Load the message */
    mr = msgrecord_from_uid(mbox, uid);
    if (!mr) {
        /* That's a never-should-happen error */
        syslog(LOG_ERR, "Unexpected null msgrecord at %s:%d",
               __FILE__, __LINE__);
        r = IMAP_INTERNAL;
        goto done;
    }

    /* Extract envelope from message */
    if (!envelope) {
        hash_table props = HASH_TABLE_INITIALIZER;
        construct_hash_table(&props, 8, 0);
        hash_insert("sender", (void*)1, &props);
        hash_insert("from", (void*)1, &props);
        hash_insert("to", (void*)1, &props);
        hash_insert("cc", (void*)1, &props);
        hash_insert("bcc", (void*)1, &props);
        hash_insert("replyTo", (void*)1, &props);
        r = jmap_email_get_with_props(req, &props, mr, &msg);
        free_hash_table(&props, NULL);
        if (r) goto done;

        myenvelope = json_object();
        envelope = myenvelope;

        /* Determine MAIL FROM */
        json_t *jfrom = json_object_get(json_object_get(msg, "sender"), "email");
        if (!jfrom) {
            jfrom = json_object_get(msg, "from");
            jfrom = json_object_get(json_array_get(jfrom, 0), "email");
        }
        if (!jfrom) {
            *set_err = json_pack("{s:s}", "type", "notPermittedFrom");
            goto done;
        }
        const char *from = json_string_value(jfrom);
        /* TODO If the address found from this is not allowed by the identity
         * associated with this submission, the email property from the identity
         * MUST be used instead. */
        json_object_set_new(myenvelope, "mailFrom",
                            json_pack("{s:s}", "email", from));

        /* Determine RCPT TO */
        json_t *rcpts = json_object(); /* deduplicated set of recipients */
        json_t *rcptTo = json_array();   /* envelope rcptTo value */
        size_t i;
        const char *s;
        json_t *jval;
        json_array_foreach(json_object_get(msg, "to"), i, jval) {
            s = json_string_value(json_object_get(jval, "email"));
            if (s) json_object_set(rcpts, s, json_true());
        }
        json_array_foreach(json_object_get(msg, "cc"), i, jval) {
            s = json_string_value(json_object_get(jval, "email"));
            if (s) json_object_set(rcpts, s, json_true());
        }
        json_array_foreach(json_object_get(msg, "bcc"), i, jval) {
            s = json_string_value(json_object_get(jval, "email"));
            if (s) json_object_set(rcpts, s, json_true());
        }
        json_object_foreach(rcpts, s, jval) {
            json_array_append_new(rcptTo, json_pack("{s:s}", "email", s));
        }
        json_decref(rcpts);
        json_object_set_new(myenvelope, "rcptTo", rcptTo);
    }
    else if (holduntil) {
        hash_table props = HASH_TABLE_INITIALIZER;
        construct_hash_table(&props, 1, 0);
        hash_insert("from", (void*)1, &props);
        r = jmap_email_get_with_props(req, &props, mr, &msg);
        free_hash_table(&props, NULL);
        if (r) goto done;
    }

    /* Validate envelope */
    if (!json_array_size(json_object_get(envelope, "rcptTo"))) {
        *set_err = json_pack("{s:s}", "type", "noRecipients");
        goto done;
    }

    /* Open the message file */
    const char *fname;
    r = msgrecord_get_fname(mr, &fname);
    if (r) goto done;

    fd_msg = open(fname, 0);
    if (fd_msg == -1) {
        syslog(LOG_ERR, "_email_submissioncreate: can't open %s: %m", fname);
        r = IMAP_IOERROR;
        goto done;
    }

    struct stat sbuf;
    if (fstat(fd_msg, &sbuf) == -1) {
        syslog(LOG_ERR, "_email_submissioncreate: can't fstat %s: %m", fname);
        goto done;
    }

    buf_refresh_mmap(&buf, 1, fd_msg, fname, sbuf.st_size, mailbox_name(mbox));
    if (!buf_len(&buf)) {
        syslog(LOG_ERR, "_email_submissioncreate: can't mmap %s: %m", fname);
        r = IMAP_IOERROR;
        goto done;
    }

    /* Fetch and set threadId */
    char thread_id[JMAP_THREADID_SIZE];
    bit64 cid;

    r = msgrecord_get_cid(mr, &cid);
    if (r) goto done;

    jmap_set_threadid(cid, thread_id);
    json_object_set_new(emailsubmission, "threadId", json_string(thread_id));

    /* Close the message record and mailbox. There's a race
     * with us still keeping the file descriptor to the
     * message open. But we don't want to long-lock the
     * mailbox while sending the mail over to a SMTP host */
    msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);

    if (!*sm) {
        /* Open the SMTP connection */
        r = smtpclient_open(sm);
        if (r) goto done;
    }
    smtpclient_set_auth(*sm, req->userid);

    if (identityid) smtpclient_set_jmapid(*sm, identityid);

    /* Prepare envelope */
    smtp_envelope_t smtpenv = SMTP_ENVELOPE_INITIALIZER;
    jmap_emailsubmission_envelope_to_smtp(&smtpenv, envelope);

    if (holduntil) {
        /* Pre-flight the message */
        json_t *jfromaddr = json_object_get(msg, "from");
        strarray_t fromaddr = STRARRAY_INITIALIZER;
        if (jfromaddr) {
            size_t i;
            json_t *jval;
            json_array_foreach(jfromaddr, i, jval) {
                const char *s = json_string_value(json_object_get(jval, "email"));
                if (s) {
                    strarray_append(&fromaddr, s);
                }
            }
        }
        r = smtpclient_sendcheck(*sm, &smtpenv, buf_len(&buf), &fromaddr);
        strarray_fini(&fromaddr);
    }
    else {
        /* Send message */
        r = smtpclient_send(*sm, &smtpenv, &buf);
    }
    if (r) {
        int i, max = 0;
        json_t *invalid = NULL;
        const char *desc = smtpclient_get_resp_text(*sm);

        syslog(LOG_ERR, "jmap: can't create message submission: %s",
               desc ? desc : error_message(r));

        switch (r) {
        case IMAP_MESSAGE_TOO_LARGE:
            *set_err = json_pack("{s:s s:i}", "type", "tooLarge",
                                 "maxSize", smtpclient_get_maxsize(*sm));
            break;

        case IMAP_MAILBOX_DISABLED:
            for (i = 0; i < smtpenv.rcpts.count; i++) {
                smtp_addr_t *addr = ptrarray_nth(&smtpenv.rcpts, i);
                max += addr->completed;
            }
            *set_err = json_pack("{s:s s:i}", "type", "tooManyRecipients",
                                 "maxRecipients", max);
            break;

        case IMAP_MAILBOX_NONEXISTENT:
            invalid = json_array();
            for (i = 0; i < smtpenv.rcpts.count; i++) {
                smtp_addr_t *addr = ptrarray_nth(&smtpenv.rcpts, i);
                if (!addr->completed) {
                    json_array_append_new(invalid, json_string(addr->addr));
                }
            }
            *set_err = json_pack("{s:s s:o}", "type", "invalidRecipients",
                                 "invalidRecipients", invalid);
            break;

        case IMAP_REMOTE_DENIED: {
            char *err = NULL;
            const char *p;

            if (desc) {
                if (smtpclient_has_ext(*sm, "ENHANCEDSTATUSCODES")) {
                    p = strchr(desc, ' ');
                    if (p) {
                        desc = p+1;
                        while (*desc == ' ') desc++;  /* trim leading whitespace */
                    }
                }
                if ((p = strstr(desc, "[jmapError:"))) {
                    p += 11;
                    const char *q = strchr(p, ']');
                    if (q) {
                        err = xstrndup(p, q - p);
                        desc = q+1;
                        while (*desc == ' ') desc++;  /* trim leading whitespace */
                    }
                }
            }
            if (!err) err = xstrdup("forbiddenToSend");
            *set_err = json_pack("{s:s s:s}",
                                 "type", err,
                                 "description", desc ? desc : error_message(r));
            free(err);
            break;
        }

        default:
            *set_err = json_pack("{s:s s:s}", "type", "forbiddenToSend",
                                 "description", desc ? desc : error_message(r));
            break;
        }
    }
    smtp_envelope_fini(&smtpenv);

    if (r) goto done;

    /* Replace any creation id with actual emailId */
    json_object_set_new(emailsubmission, "emailId", json_string(msgid));

    r = store_submission(req, submbox, &buf, holduntil,
                         emailsubmission, new_submission);

done:
    if (r && *set_err == NULL) {
       *set_err = jmap_server_error(r);
    }
    if (fd_msg != -1) close(fd_msg);
    if (msg) json_decref(msg);
    if (mr) msgrecord_unref(&mr);
    if (mbox) jmap_closembox(req, &mbox);
    if (myenvelope) json_decref(myenvelope);
    free(mboxname);
    buf_free(&buf);
}

static message_t *msg_from_subid(struct mailbox *submbox, const char *id)
{
    message_t *msg = NULL;
    uint32_t uid = 0;

    if (id[0] == 'S' && id[1] != '-' && strlen(id) < JMAP_SUBID_SIZE) {
        char *endptr = NULL;

        uid = strtoul(id+1, &endptr, 10);

        if (*endptr || errno == ERANGE || uid > UINT_MAX) uid = 0;
    }

    if (uid) {
        struct index_record record;
        int r = mailbox_find_index_record(submbox, uid, &record);

        if (!r && record.uid && !(record.internal_flags & FLAG_INTERNAL_EXPUNGED)) {
            msg = message_new_from_record(submbox, &record);
        }
    }

    return msg;
}

static json_t *fetch_submission(message_t *msg)
{
    struct buf buf = BUF_INITIALIZER;
    json_t *sub = NULL;

    int r = message_get_field(msg, JMAP_SUBMISSION_HDR,
                              MESSAGE_DECODED|MESSAGE_TRIM, &buf);

    if (!r && buf_len(&buf)) {
        json_error_t jerr;
        sub = json_loadb(buf_base(&buf), buf_len(&buf),
                         JSON_DISABLE_EOF_CHECK, &jerr);
    }
    buf_free(&buf);

    return sub;
}

static void _emailsubmission_update(struct mailbox *submbox,
                                    const char *id,
                                    json_t *emailsubmission,
                                    json_t **set_err,
                                    char **emailid)
{
    message_t *msg = msg_from_subid(submbox, id);
    const struct index_record *record;
    json_t *sub = NULL;
    int r = 0;

    if (!msg) {
        /* Not a valid id */
        *set_err = json_pack("{s:s}", "type", "notFound");
        return;
    }
    record = msg_record(msg);

    sub = fetch_submission(msg);
    if (!sub) {
        if (!r) r = IMAP_IOERROR;

        *set_err = json_pack("{s:s, s:s}", "type", "serverFail", "description", error_message(r));
        goto done;
    }

    *emailid = xstrdupnull(json_string_value(json_object_get(sub, "emailId")));

    const char *arg;
    json_t *val;
    int do_cancel = 0;
    json_object_foreach(emailsubmission, arg, val) {
        /* Make sure values in update match */
        if (!json_equal(val, json_object_get(sub, arg))) {
            /* Check the values that /get adds to the object */
            switch (json_typeof(val)) {
            case JSON_STRING:
            {
                const char *strval = json_string_value(val);

                if (!strcmp(arg, "id") && !strcmp(strval, id)) {
                    continue;
                }
                else if (!strcmp(arg, "sendAt")) {
                    time_t t = 0;
                    if (time_from_iso8601(strval, &t) == (int) strlen(strval) &&
                        t == record->internaldate) {
                        continue;
                    }
                }
                else if (!strcmp(arg, "undoStatus")) {
                    if (record->system_flags & FLAG_ANSWERED) {
                        if (!strcmp(strval, "final")) continue;

                        /* Already sent */
                        *set_err = json_pack("{s:s}", "type", "cannotUnsend");
                    }
                    else if (record->system_flags & FLAG_FLAGGED) {
                        if (!strcmp(strval, "canceled")) continue;
                    }
                    else if (!strcmp(strval, "pending")) {
                        continue;
                    }
                    else if (!strcmp(strval, "canceled")) {
                        do_cancel = 1;
                        continue;
                    }
                }
                break;
            }

            case JSON_NULL:
                if (!strcmp(arg, "deliveryStatus")) continue;
                break;

            case JSON_ARRAY:
                if (json_array_size(val) == 0 &&
                    (!strcmp(arg, "dsnBlobIds") ||
                     !strcmp(arg, "mdnBlobIds"))) {
                    continue;
                }
                break;

            default:
                break;
            }

            if (!*set_err)
                *set_err = json_pack("{s:s}", "type", "invalidProperties");
            break;
        }
    }
    json_decref(sub);

    if (*set_err) goto done;

    if (do_cancel) {
        struct index_record newrecord;

        memcpy(&newrecord, record, sizeof(struct index_record));
        newrecord.system_flags |= FLAG_FLAGGED;
        if (config_getswitch(IMAPOPT_JMAPSUBMISSION_DELETEONSEND)) {
            newrecord.system_flags |= FLAG_DELETED;
            newrecord.internal_flags |= FLAG_INTERNAL_EXPUNGED;
        }

        r = mailbox_rewrite_index_record(submbox, &newrecord);
        if (r) *set_err = json_pack("{s:s, s:s}", "type", "serverFail", "description", error_message(r));
    }

  done:
    message_unref(&msg);
}

static void _emailsubmission_destroy(struct mailbox *submbox,
                                     const char *id,
                                     json_t **set_err,
                                     char **emailid)
{
    message_t *msg = msg_from_subid(submbox, id);
    struct index_record newrecord;
    json_t *sub = NULL;
    int r = 0;

    if (!msg) {
        /* Not a valid id */
        *set_err = json_pack("{s:s}", "type", "notFound");
        return;
    }
    const struct index_record *record = msg_record(msg);

    sub = fetch_submission(msg);
    if (!sub) {
        if (!r) r = IMAP_IOERROR;

        *set_err = json_pack("{s:s, s:s}", "type", "serverFail", "description", error_message(r));
        goto done;
    }

    *emailid = xstrdupnull(json_string_value(json_object_get(sub, "emailId")));

    memcpy(&newrecord, record, sizeof(struct index_record));
    newrecord.internal_flags |= FLAG_INTERNAL_EXPUNGED;

    r = mailbox_rewrite_index_record(submbox, &newrecord);
    if (r) *set_err = json_pack("{s:s, s:s}", "type", "serverFail", "description", error_message(r));

done:
    json_decref(sub);
    message_unref(&msg);
}

static int getsubmission(jmap_req_t *req, struct jmap_get *get,
                         const char *id, message_t *msg)
{
    json_t *sub = NULL;
    int r = 0;

    sub = fetch_submission(msg);
    if (sub) {
        /* id */
        json_object_set_new(sub, "id", json_string(id));

        /* identityId */
        if (!jmap_wantprop(get->props, "identityId")) {
            json_object_del(sub, "identityId");
        }

        /* emailId */
        if (!jmap_wantprop(get->props, "emailId")) {
            json_object_del(sub, "emailId");
        }

        /* threadId */
        if (!jmap_wantprop(get->props, "threadId")) {
            json_object_del(sub, "threadId");
        }

        /* envelope */
        if (!jmap_wantprop(get->props, "envelope")) {
            json_object_del(sub, "envelope");
        }

        if (jmap_is_using(req, JMAP_MAIL_EXTENSION)) {
            /* onSend */
            if (!jmap_wantprop(get->props, "onSend")) {
                json_object_del(sub, "onSend");
            }

            /* created */
            if (jmap_wantprop(get->props, "created")) {
                char datestr[RFC3339_DATETIME_MAX];
                time_t t;

                r = message_get_savedate(msg, &t);
                if (r) goto done;

                time_to_rfc3339(t, datestr, RFC3339_DATETIME_MAX);
                json_object_set_new(sub, "created", json_string(datestr));
            }
        }
        else {
            json_object_del(sub, "onSend");
        }

        /* sendAt */
        if (jmap_wantprop(get->props, "sendAt")) {
            char datestr[RFC3339_DATETIME_MAX];
            time_t t;

            r = message_get_internaldate(msg, &t);
            if (r) goto done;

            time_to_rfc3339(t, datestr, RFC3339_DATETIME_MAX);
            json_object_set_new(sub, "sendAt", json_string(datestr));
        }

        /* undoStatus */
        if (jmap_wantprop(get->props, "undoStatus")) {
            uint32_t system_flags;
            const char *status = "pending";

            r = message_get_systemflags(msg, &system_flags);
            if (r) goto done;

            if (system_flags & FLAG_ANSWERED) {
                status = "final";
            }
            else if (system_flags & FLAG_FLAGGED) {
                status = "canceled";
            }

            json_object_set_new(sub, "undoStatus", json_string(status));
        }

        /* deliveryStatus */
        if (jmap_wantprop(get->props, "deliveryStatus")) {
            json_object_set_new(sub, "deliveryStatus", json_null());
        }

        /* dsnBlobIds */
        if (jmap_wantprop(get->props, "dsnBlobIds")) {
            json_object_set_new(sub, "dsnBlobIds", json_array());
        }

        /* mdnBlobIds */
        if (jmap_wantprop(get->props, "mdnBlobIds")) {
            json_object_set_new(sub, "mdnBlobIds", json_array());
        }
    }

  done:
    if (!r && sub) {
        json_array_append_new(get->list, sub);
    }
    else {
        json_array_append_new(get->not_found, json_string(id));

        if (sub) json_decref(sub);

        if (r) {
            syslog(LOG_ERR,
                   "jmap: EmailSubmission/get(%s): %s", id, error_message(r));
        }
    }

    return r;
}

static const jmap_property_t submission_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "identityId",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "emailId",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "threadId",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "envelope",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "sendAt",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    {
        "undoStatus",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "deliveryStatus",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "dsnBlobIds",
        NULL,
        JMAP_PROP_SERVER_SET
    },
    {
        "mdnBlobIds",
        NULL,
        JMAP_PROP_SERVER_SET
    },

    /* FM extensions */
    {
        "onSend",
        JMAP_MAIL_EXTENSION,
        JMAP_PROP_IMMUTABLE
    },
    {
        "created",
        JMAP_MAIL_EXTENSION,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE
    },
    { NULL, NULL, 0 }
};

static int jmap_emailsubmission_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    mbentry_t *mbentry = NULL;
    int created = 0;
    struct mailbox *mbox = NULL;

    jmap_get_parse(req, &parser, submission_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* submission collection */
    int r = lookup_submission_collection(req->accountid, &mbentry);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        r = 0; // that's OK, we'll skip trying to open the mailbox
    }
    else if (r) {
        syslog(LOG_ERR,
               "jmap_emailsubmission_get: lookup_submission_collection(%s): %s",
               req->accountid, error_message(r));
        goto done;
    }
    else {
        r = jmap_openmbox(req, mbentry->name, &mbox, 0);
    }
    mboxlist_entry_free(&mbentry);
    if (r) goto done;

    /* Does the client request specific events? */
    if (JNOTNULL(get.ids)) {
        size_t i;
        json_t *val;

        json_array_foreach(get.ids, i, val) {
            const char *id = json_string_value(val);
            message_t *msg = mbox ? msg_from_subid(mbox, id) : NULL;

            if (!msg) {
                /* Not a valid id */
                json_array_append_new(get.not_found, json_string(id));
                continue;
            }

            r = getsubmission(req, &get, id, msg);
            message_unref(&msg);
        }
    }
    else if (mbox) {
        struct mailbox_iter *iter = mailbox_iter_init(mbox, 0, ITER_SKIP_EXPUNGED);
        const message_t *msg;
        while ((msg = mailbox_iter_step(iter))) {
            char id[JMAP_SUBID_SIZE];
            uint32_t uid;

            r = message_get_uid((message_t *) msg, &uid);
            if (r) continue;

            /* Create id from message UID, using 'S' prefix */
            sprintf(id, "S%u", uid);
            r = getsubmission(req, &get, id, (message_t *) msg);
        }
        mailbox_iter_done(&iter);
    }

    if (mbox) jmap_closembox(req, &mbox);

    /* Build response */
    json_t *jstate = jmap_getstate(req, MBTYPE_JMAPSUBMIT, /*refresh*/ created);
    get.state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}

struct submission_set_args {
    json_t *onSuccessUpdate;
    json_t *onSuccessDestroy;
};

static int _submission_setargs_parse(jmap_req_t *req,
                                     struct jmap_parser *parser,
                                     const char *key,
                                     json_t *arg,
                                     void *rock)
{
    struct submission_set_args *set = (struct submission_set_args *) rock;
    int r = 1;

    if (!strcmp(key, "onSuccessUpdateEmail")) {
        // need urn:ietf:params:jmap:mail to update emails
        if (!jmap_is_using(req, JMAP_URN_MAIL)) return 0;
        if (json_is_object(arg)) {
            json_t *jval;
            const char *emailsubmission_id;
            json_object_foreach(arg, emailsubmission_id, jval) {
                if (!json_is_object(jval)) {
                    jmap_parser_push(parser, "onSuccessUpdateEmail");
                    jmap_parser_invalid(parser, emailsubmission_id);
                    jmap_parser_pop(parser);
                }
            }
            set->onSuccessUpdate = arg;
        }
        else if (JNOTNULL(arg)) r = 0;
    }

    else if (!strcmp(key, "onSuccessDestroyEmail") && JNOTNULL(arg)) {
        // need urn:ietf:params:jmap:mail to destroy emails
        if (!jmap_is_using(req, JMAP_URN_MAIL)) return 0;
        jmap_parse_strings(arg, parser, "onSuccessDestroyEmail");
        set->onSuccessDestroy = arg;
    }

    else r = 0;

    return r;
}

static int jmap_emailsubmission_set(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    struct submission_set_args sub_args = { NULL, NULL };
    json_t *err = NULL;
    struct mailbox *submbox = NULL;
    mbentry_t *mbentry = NULL;
    json_t *success_emailids = json_object();

    /* Parse request */
    jmap_set_parse(req, &parser, submission_props,
                   &_submission_setargs_parse, &sub_args,
                   &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Validate submissionIds in onSuccessXxxEmail */
    if (JNOTNULL(sub_args.onSuccessUpdate)) {
        const char *id;
        json_t *jemail;

        jmap_parser_push(&parser, "onSuccessUpdateEmail");
        json_object_foreach(sub_args.onSuccessUpdate, id, jemail) {
            int found;

            if (*id == '#') {
                found = json_object_get(set.create, id+1) != NULL;
            }
            else {
                found = json_object_get(set.update, id) != NULL;
                if (!found) found = json_array_find(set.destroy, id) >= 0;
            }

            if (!found) jmap_parser_invalid(&parser, id);
        }
        jmap_parser_pop(&parser);
    }

    if (JNOTNULL(sub_args.onSuccessDestroy)) {
        size_t i;
        json_t *jid;

        jmap_parser_push(&parser, "onSuccessDestroyEmail");
        json_array_foreach(sub_args.onSuccessDestroy, i, jid) {
            const char *id = json_string_value(jid);
            int found;

            if (*id == '#') {
                found = json_object_get(set.create, id+1) != NULL;
            }
            else {
                found = json_object_get(set.update, id) != NULL;
                if (!found) found = json_array_find(set.destroy, id) >= 0;
            }

            if (!found) jmap_parser_invalid(&parser, id);
        }
        jmap_parser_pop(&parser);
    }

    if (json_array_size(parser.invalid)) {
        err = json_pack("{s:s}", "type", "invalidProperties");
        json_object_set(err, "properties", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    /* Process request */

    int r = ensure_submission_collection(req->accountid, &mbentry, NULL);
    if (r) {
        syslog(LOG_ERR,
               "jmap_emailsubmission_set: ensure_submission_collection(%s): %s",
               req->accountid, error_message(r));
        goto done;
    }

    r = jmap_openmbox(req, mbentry->name, &submbox, 1);
    assert(submbox);
    mboxlist_entry_free(&mbentry);
    if (r) goto done;

    if (set.if_in_state) {
        /* TODO rewrite state function to use char* not json_t* */
        json_t *jstate = json_string(set.if_in_state);
        if (jmap_cmpstate(req, jstate, MBTYPE_JMAPSUBMIT)) {
            jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
            json_decref(jstate);
            goto done;
        }
        json_decref(jstate);
        set.old_state = xstrdup(set.if_in_state);
    }
    else {
        json_t *jstate = jmap_getstate(req, MBTYPE_JMAPSUBMIT, /*refresh*/0);
        set.old_state = xstrdup(json_string_value(jstate));
        json_decref(jstate);
    }

    /* create */
    json_t *jsubmission;
    const char *creation_id;
    smtpclient_t *sm = NULL;
    json_object_foreach(set.create, creation_id, jsubmission) {
        json_t *set_err = NULL;
        json_t *new_submission = NULL;
        char *emailid = NULL;
        _emailsubmission_create(req, submbox, jsubmission,
                                &new_submission, &set_err, &sm, &emailid);
        if (set_err) {
            json_object_set_new(set.not_created, creation_id, set_err);
            free(emailid);
            continue;
        }
        const char *id = json_string_value(json_object_get(new_submission, "id"));
        json_object_set_new(set.created, creation_id, new_submission);
        json_object_set_new(success_emailids, id, json_string(emailid));
        free(emailid);
    }
    if (sm) smtpclient_close(&sm);

    /* update */
    const char *id;
    json_object_foreach(set.update, id, jsubmission) {
        json_t *set_err = NULL;
        char *emailid = NULL;
        _emailsubmission_update(submbox, id, jsubmission, &set_err, &emailid);
        if (set_err) {
            json_object_set_new(set.not_updated, id, set_err);
            free(emailid);
            continue;
        }
        json_object_set_new(set.updated, id, json_pack("{s:s}", "id", id));
        json_object_set_new(success_emailids, id, json_string(emailid));
        free(emailid);
    }

    /* destroy */
    size_t i;
    json_t *jsubmissionId;
    json_array_foreach(set.destroy, i, jsubmissionId) {
        const char *id = json_string_value(jsubmissionId);
        json_t *set_err = NULL;
        char *emailid = NULL;
        _emailsubmission_destroy(submbox, id, &set_err, &emailid);
        if (set_err) {
            json_object_set_new(set.not_destroyed, id, set_err);
            free(emailid);
            continue;
        }
        json_array_append_new(set.destroyed, json_string(id));
        json_object_set_new(success_emailids, id, json_string(emailid));
        free(emailid);
    }

    /* force modseq to stable */
    if (submbox) mailbox_unlock_index(submbox, NULL);

    // TODO refactor jmap_getstate to return a string, once
    // all code has been migrated to the new JMAP parser.
    json_t *jstate = jmap_getstate(req, MBTYPE_JMAPSUBMIT, /*refresh*/1);
    set.new_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);

    jmap_ok(req, jmap_set_reply(&set));

    /* Process onSuccessXxxEmail */
    if (JNOTNULL(sub_args.onSuccessUpdate) ||
        JNOTNULL(sub_args.onSuccessDestroy)) {
        json_t *subargs = json_object();

        json_object_set_new(subargs, "accountId", json_string(req->accountid));

        if (JNOTNULL(sub_args.onSuccessUpdate)) {
            json_t *updateEmails = json_object();
            const char *jid;
            json_t *jemail;

            json_object_foreach(sub_args.onSuccessUpdate, jid, jemail) {
                const char *id = jid;
                if (*id == '#') {
                    json_t *jsuccess = json_object_get(set.created, id+1);
                    if (jsuccess)
                        id = json_string_value(json_object_get(jsuccess, "id"));
                }
                const char *emailid = json_string_value(json_object_get(success_emailids, id));
                if (emailid) {
                    json_object_set(updateEmails, emailid, jemail);

                    /* Add this email to scheduled email cache so Email/set{update}
                       can override ACL check on $scheduled mailbox */
                    strarray_append(req->scheduled_emails, emailid);
                }
            }

            json_object_set_new(subargs, "update", updateEmails);
        }

        if (JNOTNULL(sub_args.onSuccessDestroy)) {
            json_t *destroyEmails = json_array();
            size_t i;
            json_t *jid;
            json_array_foreach(sub_args.onSuccessDestroy, i, jid) {
                const char *id = json_string_value(jid);
                if (*id == '#') {
                    json_t *jsuccess = json_object_get(set.created, id+1);
                    if (jsuccess)
                        id = json_string_value(json_object_get(jsuccess, "id"));
                }
                const char *emailid = json_string_value(json_object_get(success_emailids, id));
                if (emailid) json_array_append_new(destroyEmails, json_string(emailid));
            }

            json_object_set_new(subargs, "destroy", destroyEmails);
        }

        jmap_add_subreq(req, "Email/set", subargs, NULL);
    }

done:
    jmap_closembox(req, &submbox);
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    json_decref(success_emailids);
    return 0;
}

static int jmap_emailsubmission_changes(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;
    struct mailbox *mbox = NULL;
    mbentry_t *mbentry = NULL;

    json_t *err = NULL;
    jmap_changes_parse(req, &parser, req->counters.submissiondeletedmodseq,
                       NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        return 0;
    }

    int r = lookup_submission_collection(req->accountid, &mbentry);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        mboxlist_entry_free(&mbentry);
        r = 0;
        changes.new_modseq = jmap_highestmodseq(req, MBTYPE_JMAPSUBMIT);
        jmap_ok(req, jmap_changes_reply(&changes));
        goto done;
    }
    if (r) {
        syslog(LOG_ERR,
               "jmap_emailsubmission_changes: lookup_submission_collection(%s): %s",
               req->accountid, error_message(r));
        goto done;
    }

    r = jmap_openmbox(req, mbentry->name, &mbox, 0);
    mboxlist_entry_free(&mbentry);
    if (r) goto done;

    struct mailbox_iter *iter = mailbox_iter_init(mbox, changes.since_modseq, 0);
    const message_t *msg;
    size_t changes_count = 0;
    modseq_t highest_modseq = 0;
    while ((msg = mailbox_iter_step(iter))) {
        char id[JMAP_SUBID_SIZE];
        const struct index_record *record = msg_record(msg);

        /* Create id from message UID, using 'S' prefix */
        sprintf(id, "S%u", record->uid);

        /* Skip any submissions created AND deleted since modseq */
        if ((record->internal_flags & FLAG_INTERNAL_EXPUNGED) &&
            record->createdmodseq > changes.since_modseq) continue;

        /* Apply limit, if any */
        if (changes.max_changes && ++changes_count > changes.max_changes) {
            changes.has_more_changes = 1;
            break;
        }

        /* Keep track of the highest modseq */
        if (highest_modseq < record->modseq) highest_modseq = record->modseq;

        /* Add change to the proper array */
        if (record->internal_flags & FLAG_INTERNAL_EXPUNGED) {
            json_array_append_new(changes.destroyed, json_string(id));
        }
        else if (record->createdmodseq > changes.since_modseq) {
            json_array_append_new(changes.created, json_string(id));
        }
        else {
            json_array_append_new(changes.updated, json_string(id));
        }
    }
    mailbox_iter_done(&iter);

    jmap_closembox(req, &mbox);

    /* Set new state */
    // XXX - this is wrong!  If we want to do this, we need to sort all the changes by
    // their modseq and then only send some of them.  Otherwise consider the following:
    // UID=1 HMS=5
    // UID=3 HMS=15
    // UID=4 HMS=10
    // if we issued a query for changes since 6, max_changes 1 - we'd get back
    // has_more_changes: true, new_modseq 15, and we'd never see UID=4 as having changed.
    changes.new_modseq = changes.has_more_changes ?
        highest_modseq : jmap_highestmodseq(req, MBTYPE_JMAPSUBMIT);

    jmap_ok(req, jmap_changes_reply(&changes));

done:
    jmap_changes_fini(&changes);
    jmap_parser_fini(&parser);
    return 0;
}

static void _emailsubmission_filter_parse(jmap_req_t *req __attribute__((unused)),
                                          struct jmap_parser *parser,
                                          json_t *filter,
                                          json_t *unsupported __attribute__((unused)),
                                          void *rock __attribute__((unused)),
                                          json_t **err __attribute__((unused)))
{
    const char *field;
    json_t *arg;

    json_object_foreach(filter, field, arg) {
        if (!strcmp(field, "emailIds") ||
            !strcmp(field, "identityIds") ||
            !strcmp(field, "threadIds")) {
            if (!json_is_array(arg)) {
                jmap_parser_invalid(parser, field);
            }
            else {
                jmap_parse_strings(arg, parser, field);
            }
        }
        else if (!strcmp(field, "undoStatus")) {
            if (!json_is_string(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (!strcmp(field, "before") ||
                 !strcmp(field, "after")) {
            if (!json_is_utcdate(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else if (jmap_is_using(req, JMAP_MAIL_EXTENSION) &&
                 (!strcmp(field, "createdBefore") ||
                  !strcmp(field, "createdAfter"))) {
            if (!json_is_utcdate(arg)) {
                jmap_parser_invalid(parser, field);
            }
        }
        else {
            jmap_parser_invalid(parser, field);
        }
    }
}


static int _emailsubmission_comparator_parse(jmap_req_t *req __attribute__((unused)),
                                             struct jmap_comparator *comp,
                                             void *rock __attribute__((unused)),
                                             json_t **err __attribute__((unused)))
{
    if (comp->collation) {
        return 0;
    }
    if (!strcmp(comp->property, "emailId") ||
        !strcmp(comp->property, "threadId") ||
        !strcmp(comp->property, "sentAt")) {
        return 1;
    }
    if (!strcmp(comp->property, "created")) {
        return jmap_is_using(req, JMAP_MAIL_EXTENSION);
    }
    return 0;
}

#if (SIZEOF_TIME_T > 4)
static time_t epoch    = (time_t) LONG_MIN;
static time_t eternity = (time_t) LONG_MAX;
#else
static time_t epoch    = (time_t) INT_MIN;
static time_t eternity = (time_t) INT_MAX;
#endif

typedef struct submission_filter {
    strarray_t *identityIds;
    strarray_t *emailIds;
    strarray_t *threadIds;
    const char *undoStatus;
    time_t before;
    time_t after;
    time_t createdBefore;
    time_t createdAfter;
} submission_filter;

/* Parse the JMAP EmailSubmission FilterCondition in arg.
 * Report any invalid properties in invalid, prefixed by prefix.
 * Return NULL on error. */
static void *submission_filter_build(json_t *arg)
{
    submission_filter *f =
        (submission_filter *) xzmalloc(sizeof(struct submission_filter));

    f->createdBefore = f->before = eternity;
    f->createdAfter  = f->after  = epoch;

    /* identityIds */
    json_t *identityIds = json_object_get(arg, "identityIds");
    if (identityIds) {
        f->identityIds = strarray_new();
        size_t i;
        json_t *val;
        json_array_foreach(identityIds, i, val) {
            const char *id;
            if (json_unpack(val, "s", &id) != -1) {
                strarray_append(f->identityIds, id);
            }
        }
    }

    /* emailIds */
    json_t *emailIds = json_object_get(arg, "emailIds");
    if (emailIds) {
        f->emailIds = strarray_new();
        size_t i;
        json_t *val;
        json_array_foreach(emailIds, i, val) {
            const char *id;
            if (json_unpack(val, "s", &id) != -1) {
                strarray_append(f->emailIds, id);
            }
        }
    }

    /* threadIds */
    json_t *threadIds = json_object_get(arg, "threadIds");
    if (threadIds) {
        f->threadIds = strarray_new();
        size_t i;
        json_t *val;
        json_array_foreach(threadIds, i, val) {
            const char *id;
            if (json_unpack(val, "s", &id) != -1) {
                strarray_append(f->threadIds, id);
            }
        }
    }

    /* undoStatus */
    if (JNOTNULL(json_object_get(arg, "undoStatus"))) {
        jmap_readprop(arg, "undoStatus", 0, NULL, "s", &f->undoStatus);
    }

    /* before */
    if (JNOTNULL(json_object_get(arg, "before"))) {
        const char *utcDate;
        jmap_readprop(arg, "before", 0, NULL, "s", &utcDate);
        time_from_iso8601(utcDate, &f->before);
    }

    /* after */
    if (JNOTNULL(json_object_get(arg, "after"))) {
        const char *utcDate;
        jmap_readprop(arg, "after", 0, NULL, "s", &utcDate);
        time_from_iso8601(utcDate, &f->after);
    }

    /* createdBefore */
    if (JNOTNULL(json_object_get(arg, "createdBefore"))) {
        const char *utcDate;
        jmap_readprop(arg, "createdBefore", 0, NULL, "s", &utcDate);
        time_from_iso8601(utcDate, &f->createdBefore);
    }

    /* createdAfter */
    if (JNOTNULL(json_object_get(arg, "createdAfter"))) {
        const char *utcDate;
        jmap_readprop(arg, "createdAfter", 0, NULL, "s", &utcDate);
        time_from_iso8601(utcDate, &f->createdAfter);
    }

    return f;
}

typedef struct submission_filter_rock {
    const message_t *msg;
    const char *emailId;
    const char *threadId;
    json_t *submission;
} submission_filter_rock;

/* Match the submission in rock against filter. */
static int submission_filter_match(void *vf, void *rock)
{
    submission_filter *f = (submission_filter *) vf;
    submission_filter_rock *sfrock = (submission_filter_rock*) rock;
    const struct index_record *record = msg_record(sfrock->msg);

    /* before */
    if (record->internaldate >= f->before) return 0;

    /* after */
    if (record->internaldate < f->after) return 0;

    /* createdBefore */
    if (record->savedate >= f->createdBefore) return 0;

    /* createdAfter */
    if (record->savedate < f->createdAfter) return 0;

    /* undoStatus */
    if (f->undoStatus) {
        if (record->system_flags & FLAG_ANSWERED) {
            if (strcmp(f->undoStatus, "final")) return 0;
        }
        else if (record->system_flags & FLAG_FLAGGED) {
            if (strcmp(f->undoStatus, "canceled")) return 0;
        }
        else {
            if (strcmp(f->undoStatus, "pending")) return 0;
        }
    }

    /* identityIds / emailIds / ThreadIds */
    if (f->identityIds || f->emailIds || f->threadIds) {
        sfrock->submission = fetch_submission((message_t *) sfrock->msg);

        if (!sfrock->submission) return 0;

        if (f->identityIds) {
            const char *identityId =
                json_string_value(json_object_get(sfrock->submission,
                                                  "identityId"));

            if (strarray_find(f->identityIds, identityId, 0) == -1) return 0;
        }
        if (f->emailIds) {
            sfrock->emailId =
                json_string_value(json_object_get(sfrock->submission,
                                                  "emailId"));

            if (strarray_find(f->emailIds, sfrock->emailId, 0) == -1) return 0;
        }
        if (f->threadIds) {
            sfrock->threadId =
                json_string_value(json_object_get(sfrock->submission,
                                                  "threadId"));

            if (strarray_find(f->threadIds, sfrock->threadId, 0) == -1) return 0;
        }
    }

    /* All matched. */
    return 1;
}

/* Free the memory allocated by this submission filter. */
static void submission_filter_free(void *vf)
{
    submission_filter *f = (submission_filter*) vf;
    if (f->identityIds) strarray_free(f->identityIds);
    if (f->emailIds) strarray_free(f->emailIds);
    if (f->threadIds) strarray_free(f->threadIds);
    free(f);
}

static struct sortcrit *sub_buildsort(json_t *sort, int *need_submission)
{
    json_t *jcomp;
    size_t i;
    struct sortcrit *sortcrit;

    *need_submission = 0;

    sortcrit = xzmalloc((json_array_size(sort) + 1) * sizeof(struct sortcrit));

    json_array_foreach(sort, i, jcomp) {
        const char *prop = json_string_value(json_object_get(jcomp, "property"));

        if (json_object_get(jcomp, "isAscending") == json_false()) {
            sortcrit[i].flags |= SORT_REVERSE;
        }

        /* Note: add any new sort criteria also to is_supported_msglist_sort */

        if (!strcmp(prop, "emailId")) {
            sortcrit[i].key = SORT_EMAILID;
            *need_submission = 1;
        }
        else if (!strcmp(prop, "threadId")) {
            sortcrit[i].key = SORT_THREADID;
            *need_submission = 1;
        }
        else if (!strcmp(prop, "sentAt")) {
            sortcrit[i].key = SORT_ARRIVAL;
        }
        else if (!strcmp(prop, "created")) {
            sortcrit[i].key = SORT_SAVEDATE;
        }
    }

    i = json_array_size(sort);
    sortcrit[i].key = SORT_UID;

    return sortcrit;
}

struct sub_match {
    char id[JMAP_SUBID_SIZE];
    uint32_t uid;
    time_t created;
    time_t sentAt;
    const char *emailId;
    const char *threadId;
    json_t *submission;
    struct sortcrit *sortcrit;
};

/*
 * Comparison function for sorting EmailSubmissions.
 */
static int sub_sort_compare(const void **vp1, const void **vp2)
{
    struct sub_match *m1 = (struct sub_match *) *vp1;
    struct sub_match *m2 = (struct sub_match *) *vp2;
    const struct sortcrit *sortcrit = m1->sortcrit;
    int reverse, ret = 0, i = 0;

    for (i = 0; !ret && sortcrit[i].key != SORT_UID; i++) {
        /* determine sort order from reverse flag bit */
        reverse = sortcrit[i].flags & SORT_REVERSE;

        switch (sortcrit[i].key) {
        case SORT_SAVEDATE:
            ret = m1->created - m2->created;
            break;
        case SORT_ARRIVAL:
            ret = m1->sentAt - m2->sentAt;
            break;
        case SORT_EMAILID:
            if (!m1->emailId) {
                m1->emailId =
                    json_string_value(json_object_get(m1->submission,
                                                      "emailId"));
            }
            if (!m2->emailId) {
                m2->emailId =
                    json_string_value(json_object_get(m2->submission,
                                                      "emailId"));
            }
            ret = strcmpsafe(m1->emailId, m2->emailId);
            break;
        case SORT_THREADID:
            if (!m1->threadId) {
                m1->threadId =
                    json_string_value(json_object_get(m1->submission,
                                                      "threadId"));
            }
            if (!m2->threadId) {
                m2->threadId =
                    json_string_value(json_object_get(m2->submission,
                                                      "threadId"));
            }
            ret = strcmpsafe(m1->threadId, m2->threadId);
            break;
        }
    }

    // tiebreaker is UID
    if (!ret) return (m1->uid - m2->uid);

    return (reverse ? -ret : ret);
}

static int jmap_emailsubmission_query(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;
    struct mailbox *mbox = NULL;
    mbentry_t *mbentry = NULL;
    int created = 0;
    jmap_filter *parsed_filter = NULL;
    struct sortcrit *sortcrit = NULL;

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req, &parser, NULL, NULL,
                     _emailsubmission_filter_parse, NULL,
                     _emailsubmission_comparator_parse, NULL,
                     &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    int r = lookup_submission_collection(req->accountid, &mbentry);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        mboxlist_entry_free(&mbentry);
        r = 0;
        /* Build response */
        json_t *jstate = jmap_getstate(req, MBTYPE_JMAPSUBMIT, /*refresh*/ created);
        query.query_state = xstrdup(json_string_value(jstate));
        json_decref(jstate);
        query.result_position = 0;
        query.can_calculate_changes = 0;
        jmap_ok(req, jmap_query_reply(&query));
        goto done;
    }
    if (r) {
        syslog(LOG_ERR,
               "jmap_emailsubmission_changes: lookup_submission_collection(%s): %s",
               req->accountid, error_message(r));
        goto done;
    }

    r = jmap_openmbox(req, mbentry->name, &mbox, 0);
    mboxlist_entry_free(&mbentry);
    if (r) goto done;

    /* Build filter */
    json_t *filter = json_object_get(req->args, "filter");
    if (JNOTNULL(filter)) {
        parsed_filter = jmap_buildfilter(filter, submission_filter_build);
    }

    /* Build sortcrit */
    int need_submission = 0;
    json_t *sort = json_object_get(req->args, "sort");
    if (JNOTNULL(sort)) {
        sortcrit = sub_buildsort(sort, &need_submission);
    }

    ptrarray_t matches = PTRARRAY_INITIALIZER;
    struct sub_match *anchor = NULL;
    struct mailbox_iter *iter = mailbox_iter_init(mbox, 0, ITER_SKIP_EXPUNGED);
    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        submission_filter_rock sfrock = { msg, NULL, NULL, NULL };

        if (query.filter) {
            int match = jmap_filter_match(parsed_filter,
                                          &submission_filter_match, &sfrock);
            if (!match) {
                if (sfrock.submission) json_decref(sfrock.submission);
                continue;
            }
        }

        /* Add record of the match to our array */
        struct sub_match *match = xmalloc(sizeof(struct sub_match));

        /* Create id from message UID, using 'S' prefix */
        sprintf(match->id, "S%u", record->uid);
        match->uid = record->uid;
        match->created = record->savedate;
        match->sentAt = record->internaldate;
        match->emailId = sfrock.emailId;
        match->threadId = sfrock.threadId;
        match->submission = sfrock.submission;
        if (!match->submission && need_submission)
            match->submission = fetch_submission((message_t *) msg);
        match->sortcrit = sortcrit;
        ptrarray_append(&matches, match);

        if (query.anchor && !strcmp(query.anchor, match->id)) {
            /* Mark record corresponding to anchor */
            anchor = match;
        }

        query.total++;
    }
    mailbox_iter_done(&iter);

    jmap_closembox(req, &mbox);

    /* Sort results */
    if (sortcrit) {
        ptrarray_sort(&matches, &sub_sort_compare);
    }

    /* Process results */
    if (query.anchor) {
        query.position = ptrarray_find(&matches, anchor, 0);
        if (query.position < 0) {
            query.position = query.total;
        }
        else {
            query.position += query.anchor_offset;
        }
    }
    else if (query.position < 0) {
        query.position += query.total;
    }
    if (query.position < 0) query.position = 0;

    size_t i;
    for (i = 0; i < query.total; i++) {
        struct sub_match *match = ptrarray_nth(&matches, i);

        /* Apply position and limit */
        if (i >= (size_t) query.position &&
            (!query.limit || query.limit > json_array_size(query.ids))) {
            /* Add the submission identifier */
            json_array_append_new(query.ids, json_string(match->id));
        }

        json_decref(match->submission);
        free(match);
    }
    ptrarray_fini(&matches);
    free(sortcrit);

    /* Build response */
    json_t *jstate = jmap_getstate(req, MBTYPE_JMAPSUBMIT, /*refresh*/ created);
    query.query_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    query.result_position = query.position;
    query.can_calculate_changes = 0;
    jmap_ok(req, jmap_query_reply(&query));

done:
    jmap_parser_fini(&parser);
    jmap_query_fini(&query);
    if (parsed_filter) jmap_filter_free(parsed_filter, submission_filter_free);
    return 0;
}

static int jmap_emailsubmission_querychanges(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_querychanges query;

    /* Parse arguments */
    json_t *err = NULL;
    jmap_querychanges_parse(req, &parser, NULL, NULL,
                            _emailsubmission_filter_parse, NULL,
                            _emailsubmission_comparator_parse, NULL,
                            &query, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Refuse all attempts to calculcate list updates */
    jmap_error(req, json_pack("{s:s}", "type", "cannotCalculateChanges"));

done:
    jmap_querychanges_fini(&query);
    jmap_parser_fini(&parser);
    return 0;

}

/* Identity/get method */
static const jmap_property_t identity_props[] = {
    {
        "id",
        NULL,
        JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE | JMAP_PROP_ALWAYS_GET
    },
    {
        "name",
        NULL,
        0
    },
    {
        "email",
        NULL,
        JMAP_PROP_IMMUTABLE
    },
    {
        "replyTo",
        NULL,
        0
    },
    {
        "bcc",
        NULL,
        0
    },
    {
        "textSignature",
        NULL,
        0
    },
    {
        "htmlSignature",
        NULL,
        0
    },
    {
        "mayDelete",
        NULL,
        JMAP_PROP_SERVER_SET
    },

    /* FM extensions (do ALL of these get through to Cyrus?) */
    {
        "displayName",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "addBccOnSMTP",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "saveSentToMailboxId",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "saveOnSMTP",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "useForAutoReply",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "isAutoConfigured",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "enableExternalSMTP",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "smtpServer",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "smtpPort",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "smtpSSL",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "smtpUser",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "smtpPassword",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "smtpRemoteService",
        JMAP_MAIL_EXTENSION,
        0
    },
    {
        "popLinkId",
        JMAP_MAIL_EXTENSION,
        0
    },

    { NULL, NULL, 0 }
};

static int jmap_identity_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;

    /* Parse request */
    jmap_get_parse(req, &parser, identity_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    json_t *me = json_pack("{s:s}", "id", req->userid);
    if (jmap_wantprop(get.props, "name")) {
        json_object_set_new(me, "name", json_string(""));
    }
    if (jmap_wantprop(get.props, "email")) {
        json_object_set_new(me, "email",
                json_string(strchr(req->userid, '@') ? req->userid : ""));
    }

    if (jmap_wantprop(get.props, "mayDelete")) {
        json_object_set_new(me, "mayDelete", json_false());
    }
    if (json_array_size(get.ids)) {
        size_t i;
        json_t *val;
        json_array_foreach(get.ids, i, val) {
            if (strcmp(json_string_value(val), req->userid)) {
                json_array_append(get.not_found, val);
            }
            else {
                json_array_append(get.list, me);
            }
        }
    } else if (!JNOTNULL(get.ids)) {
        json_array_append(get.list, me);
    }
    json_decref(me);

    /* Reply */
    get.state = xstrdup("0");
    jmap_ok(req, jmap_get_reply(&get));

done:
    jmap_parser_fini(&parser);
    jmap_get_fini(&get);
    return 0;
}
