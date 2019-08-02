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
#include "jmap_support.h"
#include "json_support.h"
#include "parseaddr.h"
#include "proxy.h"
#include "smtpclient.h"
#include "sync_support.h"
#include "times.h"
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

static jmap_method_t jmap_emailsubmission_methods_standard[] = {
    {
        "EmailSubmission/get",
        JMAP_URN_SUBMISSION,
        &jmap_emailsubmission_get,
        JMAP_SHARED_CSTATE
    },
    {
        "EmailSubmission/set",
        JMAP_URN_SUBMISSION,
        &jmap_emailsubmission_set,
       /*flags*/0
    },
    {
        "EmailSubmission/changes",
        JMAP_URN_SUBMISSION,
        &jmap_emailsubmission_changes,
        JMAP_SHARED_CSTATE
    },
    {
        "EmailSubmission/query",
        JMAP_URN_SUBMISSION,
        &jmap_emailsubmission_query,
        JMAP_SHARED_CSTATE
    },
    {
        "EmailSubmission/queryChanges",
        JMAP_URN_SUBMISSION,
        &jmap_emailsubmission_querychanges,
        JMAP_SHARED_CSTATE
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
                                        "maxDelayedSend", 0,
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
    json_t *val;
    json_t *parameters = json_object_get(addr, "parameters");
    jmap_parser_push(parser, "parameters");
    json_object_foreach(parameters, key, val) {
        /* TODO validate allowed esmtp characters */
        if (JNOTNULL(val) && !json_is_string(val)) {
            jmap_parser_invalid(parser, key);
        }
        else if (holduntil) {
            if (!strcasecmp(key, "HOLDFOR")) {
                const char *nptr = json_string_value(val);
                char *endptr = NULL;
                unsigned long interval = strtoul(nptr, &endptr, 10);
                time_t now = time(0);

                if (*endptr != '\0' || interval > 99999999 /* per RFC 4865 */) {
                    jmap_parser_invalid(parser, key);
                }
                else *holduntil = now + interval;
            }
            else if (!strcasecmp(key, "HOLDUNTIL")) {
                if (time_from_iso8601(json_string_value(val), holduntil) < 0) {
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
    const char *uploadname;
    int r;

    /* Create upload mailbox name from the parsed path */
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
    uploadname = mbname_intname(mbname);
    r = http_mlookup(uploadname, mbentry, NULL);
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Find location of INBOX */
        char *inboxname = mboxname_user_mbox(accountid, NULL);

        int r1 = http_mlookup(inboxname, mbentry, NULL);
        free(inboxname);
        if (r1 == IMAP_MAILBOX_NONEXISTENT) {
            r = IMAP_INVALID_USER;
            goto done;
        }

        int rights = httpd_myrights(httpd_authstate, *mbentry);
        if (!(rights & ACL_CREATE)) {
            r = IMAP_PERMISSION_DENIED;
            goto done;
        }

        if (*mbentry) free((*mbentry)->name);
        else *mbentry = mboxlist_entry_create();
        (*mbentry)->name = xstrdup(uploadname);
    }
    else if (!r) {
        int rights = httpd_myrights(httpd_authstate, *mbentry);
        if (!(rights & ACL_INSERT)) {
            r = IMAP_PERMISSION_DENIED;
            goto done;
        }
    }

  done:
    mbname_free(&mbname);
    return r;
}


static int create_submission_collection(const char *accountid,
                                        struct mailbox **mailbox)
{
    /* upload collection */
    mbentry_t *mbentry = NULL;
    int r = lookup_submission_collection(accountid, &mbentry);

    if (r == IMAP_INVALID_USER) {
        goto done;
    }
    else if (r == IMAP_PERMISSION_DENIED) {
        goto done;
    }
    else if (r == IMAP_MAILBOX_NONEXISTENT) {
        if (!mbentry) goto done;
        else if (mbentry->server) {
            proxy_findserver(mbentry->server, &http_protocol, httpd_userid,
                             &backend_cached, NULL, NULL, httpd_in);
            goto done;
        }

        int options = config_getint(IMAPOPT_MAILBOX_DEFAULT_OPTIONS)
            | OPT_POP3_NEW_UIDL | OPT_IMAP_HAS_ALARMS;
        r = mboxlist_createmailbox_opts(mbentry->name, MBTYPE_SUBMISSION,
                                        NULL, 1 /* admin */, accountid,
                                        httpd_authstate,
                                        options, 0, 0, 0, 0, NULL, mailbox);
        /* we lost the race, that's OK */
        if (r == IMAP_MAILBOX_LOCKED) r = 0;
        else {
            if (r) {
                syslog(LOG_ERR, "IOERROR: failed to create %s (%s)",
                        mbentry->name, error_message(r));
            }
            goto done;
        }
    }
    else if (r) goto done;

    if (mailbox) {
        /* Open mailbox for writing */
        r = mailbox_open_iwl(mbentry->name, mailbox);
        if (r) {
            syslog(LOG_ERR, "mailbox_open_iwl(%s) failed: %s",
                   mbentry->name, error_message(r));
        }
    }

 done:
    mboxlist_entry_free(&mbentry);
    return r;
}

static int stage_futurerelease(struct mailbox *mailbox,
                               struct buf *msg, time_t holduntil,
                               json_t *emailsubmission,
                               json_t **new_submission,
                               json_t **set_err __attribute__((unused)))
{
    struct stagemsg *stage = NULL;
    struct appendstate as;
    strarray_t flags = STRARRAY_INITIALIZER;
    struct body *body = NULL;
    FILE *f = NULL;
    int r;

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox->name, holduntil, 0, &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mailbox->name);
        r = IMAP_IOERROR;
        goto done;
    }

    /* Add JMAP submission object as first header */
    char *json = json_dumps(emailsubmission, JSON_COMPACT);
    size_t json_len = strlen(json);
    r = fprintf(f, "%s: %s\r\n", JMAP_SUBMISSION_HDR, json);
    free(json);

    if (r < (int) (strlen(JMAP_SUBMISSION_HDR) + json_len + 4)) {
        r = IMAP_IOERROR;
        goto done;
    }

    /* Add submitted message */
    if (!fwrite(buf_base(msg), buf_len(msg), 1, f) || fflush(f)) {
        r = IMAP_IOERROR;
        goto done;
    }
    fclose(f);

    /* Prepare to append the message to the mailbox */
    r = append_setup_mbox(&as, mailbox, httpd_userid, httpd_authstate,
                          0, /*quota*/NULL, 0, 0, /*event*/0);
    if (r) {
        syslog(LOG_ERR, "append_setup(%s) failed: %s",
               mailbox->name, error_message(r));
        goto done;
    }

    /* Append the message to the mailbox */
    r = append_fromstage(&as, &body, stage, holduntil, 0, &flags, 0, /*annots*/NULL);

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

    /* Create id from message UID, using 'S' prefix */
    char sub_id[JMAP_SUBID_SIZE];
    sprintf(sub_id, "S%u", mailbox->i.last_uid);
    *new_submission = json_pack("{s:s}", "id", sub_id);

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
                                    smtpclient_t **sm)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;

    /* messageId */
    json_t *jemailId = json_object_get(emailsubmission, "emailId");
    const char *msgid = jmap_id_string_value(req, jemailId);
    if (!msgid) {
        jmap_parser_invalid(&parser, "emailId");
    }

    /* identityId */
    const char *identityid = NULL;
    json_t *jidentityId = json_object_get(emailsubmission, "identityId");
    if (json_is_string(jidentityId)) {
        identityid = json_string_value(jidentityId);
        if (strcmp(identityid, req->userid)) {
            jmap_parser_invalid(&parser, "identityId");
        }
    }
    else {
        jmap_parser_invalid(&parser, "identityId");
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
        jmap_parser_pop(&parser);
    } else {
        envelope = NULL;
    }

    /* Reject read-only properties */
    if (json_object_get(emailsubmission, "id")) {
        jmap_parser_invalid(&parser, "id");
    }
    if (json_object_get(emailsubmission, "threadId")) {
        jmap_parser_invalid(&parser, "threadId");
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
    r = jmap_email_find(req, msgid, &mboxname, &uid);
    if (r) {
        if (r == IMAP_NOTFOUND) {
            *set_err = json_pack("{s:s}", "type", "emailNotFound");
        }
        goto done;
    }

    /* Check ACL */
    if (!jmap_hasrights_byname(req, mboxname, ACL_READ)) {
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
        json_t *rcpts = json_pack("{}"); /* deduplicated set of recipients */
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

    buf_init_mmap(&buf, 1, fd_msg, fname, sbuf.st_size, mbox->name);
    if (!buf_len(&buf)) {
        syslog(LOG_ERR, "_email_submissioncreate: can't mmap %s: %m", fname);
        r = IMAP_IOERROR;
        goto done;
    }

    if (holduntil) {
        /* Fetch and set threadId */
        char thread_id[JMAP_THREADID_SIZE];
        bit64 cid;

        r = msgrecord_get_cid(mr, &cid);
        if (r) goto done;

        jmap_set_threadid(cid, thread_id);
        json_object_set_new(emailsubmission, "threadId", json_string(thread_id));
    }

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

    /* Prepare envelope */
    smtp_envelope_t smtpenv = SMTP_ENVELOPE_INITIALIZER;
    jmap_emailsubmission_envelope_to_smtp(&smtpenv, envelope);

    if (holduntil) {
        /* Pre-flight the message */
        smtpclient_set_size(*sm, buf_len(&buf));
        r = smtpclient_sendprot(*sm, &smtpenv, NULL);
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
            if (!err) err = xstrdup("forbiddenToSend");
            *set_err = json_pack("{s:s s:s}",
                                 "type", err, "description", desc);
            free(err);
            break;
        }

        default:
            *set_err = json_pack("{s:s s:s}", "type", "smtpProtocolError",
                                 "description", desc);
            break;
        }
    }
    smtp_envelope_fini(&smtpenv);

    if (r) goto done;

    if (holduntil) {
        r = stage_futurerelease(submbox, &buf, holduntil, emailsubmission,
                                new_submission, set_err);
        goto done;
    }

    /* All done */
    char *new_id = xstrdup(makeuuid());
    *new_submission = json_pack("{s:s}", "id", new_id);
    free(new_id);

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

static uint32_t imap_uid_from_subid(const char *id)
{
    uint32_t uid = 0;

    if (id[0] == 'S' && id[1] != '-' && strlen(id) < JMAP_SUBID_SIZE) {
        char *endptr = NULL;

        uid = strtoul(id+1, &endptr, 10);

        if (*endptr || errno == ERANGE || uid > UINT_MAX) uid = 0;
    }

    return uid;
}

static void _emailsubmission_update(struct mailbox *submbox,
                                    const char *id,
                                    json_t *emailsubmission,
                                    json_t **set_err)
{
    uint32_t uid = imap_uid_from_subid(id);
    struct buf buf = BUF_INITIALIZER;
    struct index_record record;
    message_t *msg = NULL;
    json_t *sub = NULL;
    int r = 0;

    /* Lookup message by IMAP UID */
    if (uid) {
        r = mailbox_find_index_record(submbox, uid, &record);

        if (!r) msg = message_new_from_record(submbox, &record);
    }

    if (!msg) {
        /* Not a valid id */
        *set_err = json_pack("{s:s}", "type", "notFound");
        return;
    }

    r = message_get_field(msg, JMAP_SUBMISSION_HDR,
                          MESSAGE_DECODED|MESSAGE_TRIM, &buf);
    message_unref(&msg);

    if (!r && buf_len(&buf)) {
        json_error_t jerr;
        sub = json_loadb(buf_base(&buf), buf_len(&buf),
                         JSON_DISABLE_EOF_CHECK, &jerr);
    }
    buf_free(&buf);

    if (!sub) {
        if (!r) r = IMAP_IOERROR;

        *set_err = json_pack("{s:s}", "type", error_message(r));
        return;
    }

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
                        t == record.internaldate) {
                        continue;
                    }
                }
                else if (!strcmp(arg, "undoStatus")) {
                    if (record.internal_flags & FLAG_INTERNAL_EXPUNGED) {
                        if (!(record.system_flags & FLAG_DELETED)) {
                            /* Already sent */
                            *set_err = json_pack("{s:s}", "type", "cannotUnsend");
                        }
                        else if (!strcmp(strval, "canceled")) {
                            /* Already canceled */
                            continue;
                        }
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

    if (*set_err) return;

    if (do_cancel) {
        record.system_flags |= FLAG_DELETED;
        record.internal_flags |= FLAG_INTERNAL_EXPUNGED;

        r = mailbox_rewrite_index_record(submbox, &record);
        if (r) *set_err = json_pack("{s:s}", "type", error_message(r));
    }
}

static int getsubmission(struct jmap_get *get,
                         const char *id, message_t *msg)
{
    struct buf buf = BUF_INITIALIZER;
    json_t *sub = NULL;

    int r = message_get_field(msg, JMAP_SUBMISSION_HDR,
                              MESSAGE_DECODED|MESSAGE_TRIM, &buf);
    if (!r && buf.len) {
        json_error_t jerr;
        sub = json_loadb(buf_base(&buf), buf_len(&buf),
                         JSON_DISABLE_EOF_CHECK, &jerr);
    }
    buf_free(&buf);

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

        /* senddAt */
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
            uint32_t internal, system;
            const char *status = "pending";

            r = message_get_internalflags(msg, &internal);
            if (r) goto done;

            if (internal & FLAG_INTERNAL_EXPUNGED) {
                r = message_get_systemflags(msg, &system);
                if (r) goto done;

                status = (system & FLAG_DELETED) ? "canceled" : "final";
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
    { NULL, NULL, 0 }
};

static int jmap_emailsubmission_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;
    struct mailbox *mbox = NULL;

    jmap_get_parse(req, &parser, submission_props, /*allow_null_ids*/1,
                   NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    mbentry_t *mbentry = NULL;
    int r = lookup_submission_collection(req->accountid, &mbentry);
    r = jmap_openmbox(req, mbentry->name, &mbox, 0);
    mboxlist_entry_free(&mbentry);
    if (r) goto done;

    /* Does the client request specific events? */
    if (JNOTNULL(get.ids)) {
        size_t i;
        json_t *val;

        json_array_foreach(get.ids, i, val) {
            const char *id = json_string_value(val);
            uint32_t uid = imap_uid_from_subid(id);
            message_t *msg = NULL;

            /* Lookup message by IMAP UID */
            if (uid) {
                struct index_record record;
                int r = mailbox_find_index_record(mbox, uid, &record);

                if (!r) msg = message_new_from_record(mbox, &record);
            }
            if (!msg) {
                /* Not a valid id */
                json_array_append_new(get.not_found, json_string(id));
                continue;
            }

            r = getsubmission(&get, id, msg);
            message_unref(&msg);
        }
    }
    else {
        struct mailbox_iter *iter = mailbox_iter_init(mbox, 0, 0);
        const message_t *msg;
        while ((msg = mailbox_iter_step(iter))) {
            char id[JMAP_SUBID_SIZE];
            uint32_t uid;

            r = message_get_uid((message_t *) msg, &uid);
            if (r) continue;

            /* Create id from message UID, using 'S' prefix */
            sprintf(id, "S%u", uid);
            r = getsubmission(&get, id, (message_t *) msg);
        }
        mailbox_iter_done(&iter);
    }

    jmap_closembox(req, &mbox);

    json_t *jstate = jmap_getstate(req, MBTYPE_EMAIL, /*refresh*/0);
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

static int _submission_setargs_parse(jmap_req_t *req __attribute__((unused)),
                                     struct jmap_parser *parser,
                                     const char *key,
                                     json_t *arg,
                                     void *rock)
{
    struct submission_set_args *set = (struct submission_set_args *) rock;
    int r = 1;

    if (!strcmp(key, "onSuccessUpdateEmail")) {
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

    /* Parse request */
    jmap_set_parse(req, &parser, submission_props,
                   &_submission_setargs_parse, &sub_args,
                   &set, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Process request */

    /* As long as EmailSubmission/set returns random states, we
     * never can guarantee the EmailSubmission state not to have
     * changed. Reject all ifInState requests. */
    if (set.if_in_state) {
        jmap_error(req, json_pack("{s:s}", "type", "stateMismatch"));
        goto done;
    }

    int r = create_submission_collection(req->accountid, &submbox);
    if (r) {
        syslog(LOG_ERR,
               "jmap_emailsubmission_set: create_submission_collection(%s): %s",
               req->accountid, error_message(r));
        goto done;
    }

    json_t *jsubmission;
    const char *creation_id;
    smtpclient_t *sm = NULL;
    json_object_foreach(set.create, creation_id, jsubmission) {
        json_t *set_err = NULL;
        json_t *new_submission = NULL;
        _emailsubmission_create(req, submbox, jsubmission,
                                &new_submission, &set_err, &sm);
        if (set_err) {
            json_object_set_new(set.not_created, creation_id, set_err);
            continue;
        }
        json_object_set_new(set.created, creation_id, new_submission);
    }
    if (sm) smtpclient_close(&sm);

    const char *id;
    json_object_foreach(set.update, id, jsubmission) {
        json_t *set_err = NULL;
        _emailsubmission_update(submbox, id, jsubmission, &set_err);
        if (set_err) {
            json_object_set_new(set.not_updated, id, set_err);
            continue;
        }
        json_object_set_new(set.updated, id, json_pack("{s:s}", "id", id));
    }

    size_t i;
    json_t *jsubmissionId;
    json_array_foreach(set.destroy, i, jsubmissionId) {
        json_t *set_err = json_pack("{s:s}", "type", "notFound");
        json_object_set_new(set.not_destroyed,
                json_string_value(jsubmissionId), set_err);
    }

    /* Process onSuccessXxxEmail */
    json_t *updateEmails = json_object();
    if (JNOTNULL(sub_args.onSuccessUpdate)) {
        const char *id;
        json_t *jemail;
        json_object_foreach(sub_args.onSuccessUpdate, id, jemail) {
            /* Ignore updates, we rejected all of them */
            if (*id != '#') continue;

            json_t *jsubmission = json_object_get(set.create, id+1);
            if (!jsubmission) continue;
            json_t *jsuccess = json_object_get(set.created, id+1);
            if (!jsuccess) continue;
            json_t *jemailId = json_object_get(jsubmission, "emailId");
            if (!jemailId) continue;
            const char *msgid = jmap_id_string_value(req, jemailId);
            if (!msgid) continue;
            json_object_set(updateEmails, msgid, jemail);
        }
    }
    json_t *destroyEmails = json_array();
    if (JNOTNULL(sub_args.onSuccessDestroy)) {
        size_t i;
        json_t *jid;
        json_array_foreach(sub_args.onSuccessDestroy, i, jid) {
            const char *id = json_string_value(jid);
            /* Ignore updates, we rejected all of them */
            if (*id != '#') continue;

            json_t *jsubmission = json_object_get(set.create, id+1);
            if (!jsubmission) continue;
            json_t *jsuccess = json_object_get(set.created, id+1);
            if (!jsuccess) continue;
            json_t *jemailId = json_object_get(jsubmission, "emailId");
            if (!jemailId) continue;
            const char *msgid = jmap_id_string_value(req, jemailId);
            if (!msgid) continue;
            json_array_append_new(destroyEmails, json_string(msgid));
        }
    }

    /* Create a random new state. /changes will return empty changes. */
    set.new_state = xstrdup(makeuuid());

    jmap_ok(req, jmap_set_reply(&set));

    if (json_object_size(updateEmails) || json_array_size(destroyEmails)) {
        json_t *subargs = json_object();
        json_object_set(subargs, "update", updateEmails);
        json_object_set(subargs, "destroy", destroyEmails);
        json_object_set_new(subargs, "accountId", json_string(req->accountid));
        jmap_add_subreq(req, "Email/set", subargs, NULL);
    }
    json_decref(updateEmails);
    json_decref(destroyEmails);

done:
    if (submbox) mailbox_close(&submbox);
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    return 0;
}

static int jmap_emailsubmission_changes(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;

    json_t *err = NULL;
    jmap_changes_parse(req, &parser, NULL, NULL, &changes, &err);
    if (err) {
        jmap_error(req, err);
        return 0;
    }

    /* Trivially find no message submission updates at all. */
    changes.new_modseq = jmap_highestmodseq(req, MBTYPE_EMAIL);
    jmap_ok(req, jmap_changes_reply(&changes));
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
            if (!json_is_string(arg) ||
                jmap_is_valid_utcdate(json_string_value(arg))) {
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
    return 0;
}

static int jmap_emailsubmission_query(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;

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

    /* We don't store EmailSubmissions */
    json_t *jstate = jmap_getstate(req, MBTYPE_EMAIL, /*refresh*/0);
    query.query_state = xstrdup(json_string_value(jstate));
    json_decref(jstate);
    query.position = 0;
    query.total = 0;
    query.can_calculate_changes = 0;
    jmap_ok(req, jmap_query_reply(&query));

done:
    jmap_parser_fini(&parser);
    jmap_query_fini(&query);
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
