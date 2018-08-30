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

#include "acl.h"
#include "http_jmap.h"
#include "jmap_mail.h"
#include "json_support.h"
#include "parseaddr.h"
#include "smtpclient.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int _emailsubmission_address_parse(json_t *addr,
                                          struct jmap_parser *parser)
{
    int is_valid = 0;

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
    }
    jmap_parser_pop(parser);

    return is_valid;
}

static void address_to_smtp(smtp_addr_t *smtpaddr, json_t *addr)
{
    smtpaddr->addr = xstrdup(json_string_value(json_object_get(addr, "email")));

    const char *key;
    json_t *val;
    json_object_foreach(json_object_get(addr, "parameters"), key, val) {
        /* We never take AUTH at face value */
        if (!strcasecmp(key, "AUTH")) {
            continue;
        }
        smtp_param_t *param = xzmalloc(sizeof(smtp_param_t));
        param->key = xstrdup(key);
        param->val = xstrdup(json_string_value(val));
        ptrarray_append(&smtpaddr->params, param);
    }
}

static void _emailsubmission_envelope_to_smtp(smtp_envelope_t *smtpenv,
                                              json_t *env)
{
    address_to_smtp(&smtpenv->from, json_object_get(env, "mailFrom"));
    size_t i;
    json_t *val;
    json_array_foreach(json_object_get(env, "rcptTo"), i, val) {
        smtp_addr_t *smtpaddr = xzmalloc(sizeof(smtp_addr_t));
        address_to_smtp(smtpaddr, val);
        ptrarray_append(&smtpenv->rcpts, smtpaddr);
    }
}

static void _emailsubmission_create(jmap_req_t *req,
                                   json_t *emailsubmission,
                                   json_t **new_submission,
                                   json_t **set_err)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;

    /* messageId */
    const char *msgid = NULL;
    json_t *jemailId = json_object_get(emailsubmission, "emailId");
    if (json_is_string(jemailId)) {
        msgid = json_string_value(jemailId);
        if (*msgid == '#') {
            const char *id = jmap_lookup_id(req, msgid + 1);
            if (id) {
                msgid = id;
            } else {
                jmap_parser_invalid(&parser, "emailId");
            }
        }
    }
    else {
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
    json_t *envelope = json_object_get(emailsubmission, "envelope");
    if (JNOTNULL(envelope)) {
        jmap_parser_push(&parser, "envelope");
        json_t *from = json_object_get(envelope, "mailFrom");
        if (json_object_size(from)) {
            jmap_parser_push(&parser, "mailFrom");
            _emailsubmission_address_parse(from, &parser);
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
                _emailsubmission_address_parse(addr, &parser);
                jmap_parser_pop(&parser);
            }
        }
        else {
            jmap_parser_invalid(&parser, "mailFrom");
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
        syslog(LOG_ERR, "jmap_sendrecord: can't open %s: %m", fname);
        r = IMAP_IOERROR;
        goto done;
    }

    /* Close the message record and mailbox. There's a race
     * with us still keeping the file descriptor to the
     * message open. But we don't want to long-lock the
     * mailbox while sending the mail over to a SMTP host */
    msgrecord_unref(&mr);
    jmap_closembox(req, &mbox);

    /* Open the SMTP connection */
    smtpclient_t *sm = NULL;
    r = smtpclient_open(&sm);
    if (r) goto done;
    smtpclient_set_auth(sm, req->userid);

    /* Prepare envelope */
    smtp_envelope_t smtpenv = SMTP_ENVELOPE_INITIALIZER;
    _emailsubmission_envelope_to_smtp(&smtpenv, envelope);

    /* Set size */
    struct stat stat;
    fstat(fd_msg, &stat);
    smtpclient_set_size(sm, stat.st_size);

    /* Send message */
    struct protstream *data = prot_new(fd_msg, /*write*/0);
    r = smtpclient_sendprot(sm, &smtpenv, data);
    prot_free(data);
    if (r) {
        int i, max = 0;
        json_t *invalid = NULL;

        syslog(LOG_ERR, "jmap: can't create message submission: %s",
                error_message(r));

        switch (r) {
        case IMAP_MESSAGE_TOO_LARGE:
            *set_err = json_pack("{s:s s:i}", "type", "tooLarge",
                                 "maxSize", smtpclient_get_maxsize(sm));
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
            const char *desc = smtpclient_get_resp_text(sm);
            if (smtpclient_has_ext(sm, "ENHANCEDSTATUSCODES")) {
                const char *p = strchr(desc, ' ');
                if (p) desc = p+1;
            }
            *set_err = json_pack("{s:s s:s}", "type", "forbiddenToSend",
                                 "description", desc);
            break;
        }

        default:
            *set_err = json_pack("{s:s}", "type", "smtpProtocolError");
            break;
        }
    }
    smtp_envelope_fini(&smtpenv);
    smtpclient_close(&sm);

    if (r) goto done;

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

static const jmap_property_t submission_props[] = {
    { "id",             JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE },
    { "identityId",     JMAP_PROP_IMMUTABLE },
    { "emailId",        JMAP_PROP_IMMUTABLE },
    { "threadId",       JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE },
    { "envelope",       JMAP_PROP_IMMUTABLE },
    { "sendAt",         JMAP_PROP_SERVER_SET | JMAP_PROP_IMMUTABLE },
    { "undoStatus",     JMAP_PROP_SERVER_SET },
    { "deliveryStatus", JMAP_PROP_SERVER_SET },
    { "dsnBlobIds",     JMAP_PROP_SERVER_SET },
    { "mdnBlobIds",     JMAP_PROP_SERVER_SET },
    { NULL,             0 }
};

extern int jmap_emailsubmission_get(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_get get;
    json_t *err = NULL;

    jmap_get_parse(req->args, &parser, req,
                   submission_props, NULL, NULL, &get, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    size_t i;
    json_t *val;
    json_array_foreach(get.ids, i, val) {
        json_array_append(get.not_found, val);
    }

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

static int _submission_setargs_parse(const char *key,
                                     json_t *arg,
                                     struct jmap_parser *parser,
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

extern int jmap_emailsubmission_set(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_set set;
    struct submission_set_args sub_args = { NULL, NULL };
    json_t *err = NULL;

    /* Parse request */
    jmap_set_parse(req->args, &parser,
                   &_submission_setargs_parse, &sub_args, &set, &err);
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

    json_t *jsubmission;
    const char *creation_id;
    json_object_foreach(set.create, creation_id, jsubmission) {
        json_t *set_err = NULL;
        json_t *new_submission = NULL;
        _emailsubmission_create(req, jsubmission, &new_submission, &set_err);
        if (set_err) {
            json_object_set_new(set.not_created, creation_id, set_err);
            continue;
        }
        json_object_set_new(set.created, creation_id, new_submission);
    }

    const char *id;
    json_object_foreach(set.update, id, jsubmission) {
        json_t *set_err = json_pack("{s:s}", "type", "notFound");
        json_object_set_new(set.not_updated, id, set_err);
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
            json_object_set(updateEmails, json_string_value(jemailId), jemail);
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
            json_array_append(destroyEmails, jemailId);
        }
    }

    /* Create a random new state. /changes will return empty changes. */
    set.new_state = xstrdup(makeuuid());

    jmap_ok(req, jmap_set_reply(&set));

    if (json_object_size(updateEmails) || json_array_size(destroyEmails)) {
        struct jmap_req subreq = *req;
        subreq.args = json_pack("{}");
        subreq.method = "Email/set";
        json_object_set(subreq.args, "update", updateEmails);
        json_object_set(subreq.args, "destroy", destroyEmails);
        json_object_set_new(subreq.args, "accountId",
                            json_string(req->accountid));
        jmap_email_set(&subreq);
        json_decref(subreq.args);
    }
    json_decref(updateEmails);
    json_decref(destroyEmails);

done:
    jmap_parser_fini(&parser);
    jmap_set_fini(&set);
    return 0;
}

extern int jmap_emailsubmission_changes(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_changes changes;

    json_t *err = NULL;
    jmap_changes_parse(req->args, &parser, NULL, NULL, &changes, &err);
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

static void _emailsubmission_parse_filter(json_t *filter,
                                          struct jmap_parser *parser,
                                          json_t *unsupported __attribute__((unused)),
                                          void *rock __attribute__((unused)))
{
    json_t *arg;
    const char *s;

    if (!JNOTNULL(filter) || json_typeof(filter) != JSON_OBJECT) {
        jmap_parser_invalid(parser, NULL);
        return;
    }

    arg = json_object_get(filter, "before");
    if ((s = json_string_value(arg))) {
        if (!jmap_is_valid_utcdate(s)) {
            jmap_parser_invalid(parser, "before");
        }
    } else if (arg) {
        jmap_parser_invalid(parser, "before");
    }
    arg = json_object_get(filter, "after");
    if ((s = json_string_value(arg))) {
        if (!jmap_is_valid_utcdate(s)) {
            jmap_parser_invalid(parser, "after");
        }
    } else if (arg) {
        jmap_parser_invalid(parser, "after");
    }

    arg = json_object_get(filter, "emailIds");
    if (json_is_array(arg)) {
        jmap_parse_strings(arg, parser, "emailIds");
    } else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "emailIds");
    }

    arg = json_object_get(filter, "threadIds");
    if (json_is_array(arg)) {
        jmap_parse_strings(arg, parser, "threadIds");
    } else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "threadIds");
    }

    arg = json_object_get(filter, "emailSubmissionIds");
    if (json_is_array(arg)) {
        jmap_parse_strings(arg, parser, "emailSubmissionIds");
    } else if (JNOTNULL(arg)) {
        jmap_parser_invalid(parser, "emailSubmissionIds");
    }
}


static int _emailsubmission_parse_comparator(struct jmap_comparator *comp,
                                             void *rock __attribute__((unused)))
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

extern int jmap_emailsubmission_query(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_query query;

    /* Parse request */
    json_t *err = NULL;
    jmap_query_parse(req->args, &parser,
                     _emailsubmission_parse_filter, NULL,
                     _emailsubmission_parse_comparator, NULL,
                     NULL, NULL,
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

extern int jmap_emailsubmission_querychanges(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_querychanges query;

    /* Parse arguments */
    json_t *err = NULL;
    jmap_querychanges_parse(req->args, &parser,
                            _emailsubmission_parse_filter, NULL,
                            _emailsubmission_parse_comparator, NULL,
                            NULL, NULL,
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
