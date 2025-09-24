/* auditlog - audit logging API
 *
 * Copyright (c) 1994-2025 Carnegie Mellon University.  All rights reserved.
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
 */
#include <config.h>

#include "imap/auditlog.h"

#include "imap/jmap_util.h"

#include "lib/assert.h"
#include "lib/sessionid.h"

#include <syslog.h>

static inline void auditlog_begin(struct buf *buf, const char *action)
{
    const char *traceid = trace_id();

    buf_reset(buf);
    buf_printf(buf, "auditlog: %s", action);

    if (session_have_id()) {
        buf_appendmap(buf, " sessionid=<", 12);
        buf_appendcstr(buf, session_id());
        buf_putc(buf, '>');
    }
    if (traceid) {
        buf_appendmap(buf, " r.tid=<", 8);
        buf_appendcstr(buf, traceid);
        buf_putc(buf, '>');
    }
}

static inline void auditlog_push(struct buf *buf,
                                 const char *key,
                                 const char *value)
{
    int len = 0;

    assert(key && *key);
    if (!value) value = "";

    len = strlen(value);
    if (len > 1 && value[0] == '<' && value[len - 1] == '>') {
        value += 1;
        len -= 2;
    }

    buf_printf(buf, " %s=<%.*s>", key, len, value);
}

static inline void auditlog_finish(struct buf *buf)
{
    syslog(LOG_NOTICE, "%s", buf_cstring(buf));
    buf_free(buf);
}

/*
 * Partially-exposed internals for cunit tests
 */

HIDDEN void hidden_auditlog_begin(struct buf *buf, const char *action)
{
    return auditlog_begin(buf, action);
}

HIDDEN void hidden_auditlog_push(struct buf *buf,
                                 const char *key,
                                 const char *value)
{
    return auditlog_push(buf, key, value);
}

HIDDEN void hidden_auditlog_finish(struct buf *buf)
{
    return auditlog_finish(buf);
}

/*
 * Public API
 */

EXPORTED void auditlog_acl(const char *mboxname,
                           const mbentry_t *oldmbentry,
                           const mbentry_t *mbentry)
{
    struct buf buf = BUF_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&buf, "acl");

    /* XXX convert mboxname to consistent namespace? */
    auditlog_push(&buf, "mailbox", mboxname);
    auditlog_push(&buf, "uniqueid", mbentry->uniqueid);
    auditlog_push(&buf, "jmapid", mbentry->jmapid);
    auditlog_push(&buf, "mbtype", mboxlist_mbtype_to_string(mbentry->mbtype));
    auditlog_push(&buf, "oldacl", oldmbentry ? oldmbentry->acl : "NONE");
    auditlog_push(&buf, "acl", mbentry->acl);
    buf_printf(&buf, " foldermodseq=<" MODSEQ_FMT ">", mbentry->foldermodseq);

    auditlog_finish(&buf);
}

EXPORTED void auditlog_client(const char *action,
                              const char *userid,
                              const char *client)
{
    struct buf buf = BUF_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&buf, action);

    auditlog_push(&buf, "userid", userid);
    auditlog_push(&buf, "client", client);

    auditlog_finish(&buf);
}

/* n.b. you probably want to call duplicate_log()! */
HIDDEN void auditlog_duplicate(const char *action,
                               const duplicate_key_t *dkey)
{
    struct buf buf = BUF_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&buf, "duplicate");

    auditlog_push(&buf, "action", action);
    auditlog_push(&buf, "message-id", dkey->id);
    auditlog_push(&buf, "uniqueid-or-scope", dkey->to);
    auditlog_push(&buf, "date", dkey->date);

    auditlog_finish(&buf);
}

EXPORTED void auditlog_imip(const char *message_id,
                            const char *outcome,
                            const char *errstr)
{
    struct buf buf = BUF_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&buf, "processed iMIP");

    auditlog_push(&buf, "message-id", message_id ? message_id : "nomsgid");
    auditlog_push(&buf, "outcome", outcome);
    if (errstr)
        auditlog_push(&buf, "errstr", errstr);

    auditlog_finish(&buf);
}

EXPORTED void auditlog_mailbox(const char *action,
                               const struct mailbox *oldmailbox,
                               const struct mailbox *mailbox,
                               const char *newpartition)
{
    struct buf buf = BUF_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&buf, action);

    if (oldmailbox && strcmpsafe(mailbox_name(oldmailbox),
                                 mailbox_name(mailbox)))
    {
        auditlog_push(&buf, "oldmailbox", mailbox_name(oldmailbox));
    }

    auditlog_push(&buf, "mailbox", mailbox_name(mailbox));
    auditlog_push(&buf, "uniqueid", mailbox_uniqueid(mailbox));
    auditlog_push(&buf, "mboxid", mailbox_jmapid(mailbox));
    buf_printf(&buf, " uidvalidity=<%u>", mailbox->i.uidvalidity);

    if (oldmailbox && strcmpsafe(mailbox_partition(oldmailbox),
                                 mailbox_partition(mailbox)))
    {
        auditlog_push(&buf, "oldpart", mailbox_partition(oldmailbox));
        auditlog_push(&buf, "newpart", mailbox_partition(mailbox));
    }
    else if (newpartition && strcmpsafe(mailbox_partition(mailbox),
                                        newpartition))
    {
        auditlog_push(&buf, "oldpart", mailbox_partition(mailbox));
        auditlog_push(&buf, "newpart", newpartition);
    }

    auditlog_finish(&buf);
}

EXPORTED void auditlog_mboxname(const char *action,
                                const char *userid,
                                const char *mboxname)
{
    struct buf buf = BUF_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&buf, action);

    if (userid) {
        auditlog_push(&buf, "userid", userid);
    }

    if (mboxname) {
        /* XXX convert to consistent namespace? */
        auditlog_push(&buf, "mailbox", mboxname);
    }

    auditlog_finish(&buf);
}

EXPORTED void auditlog_message(const char *action,
                               struct mailbox *mailbox,
                               const struct index_record *record,
                               const char *message_id)
{
    struct buf buf = BUF_INITIALIZER;
    struct conversations_state *cstate;
    char flagstr[FLAGMAPSTR_MAXLEN] = {0};
    char emailid[JMAP_MAX_EMAILID_SIZE] = {0};
    char threadid[JMAP_THREADID_SIZE] = {0};

    if (!config_auditlog) return;

    cstate = mailbox_get_cstate(mailbox);
    jmap_set_emailid(cstate, &record->guid, 0, &record->internaldate, emailid);
    jmap_set_threadid(cstate, record->cid, threadid);
    flags_to_str(record, flagstr);

    auditlog_begin(&buf, action);

    auditlog_push(&buf, "mailbox", mailbox_name(mailbox));
    auditlog_push(&buf, "uniqueid", mailbox_uniqueid(mailbox));
    auditlog_push(&buf, "mboxid", mailbox_jmapid(mailbox));
    buf_printf(&buf, " uid=<%u> modseq=<" MODSEQ_FMT ">",
                     record->uid, record->modseq);
    auditlog_push(&buf, "sysflags", flagstr);
    auditlog_push(&buf, "guid", message_guid_encode(&record->guid));
    auditlog_push(&buf, "emailid", emailid);
    auditlog_push(&buf, "cid", threadid);

    if (message_id) {
        auditlog_push(&buf, "message-id", message_id);
    }

    buf_printf(&buf, " size=<" UINT64_FMT ">", record->size);
    auditlog_finish(&buf);
}

EXPORTED void auditlog_message_uid(const char *action,
                                   const struct mailbox *mailbox,
                                   uint32_t uid,
                                   const char *flagstr)
{
    struct buf buf = BUF_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&buf, action);

    auditlog_push(&buf, "mailbox", mailbox_name(mailbox));
    auditlog_push(&buf, "uniqueid", mailbox_uniqueid(mailbox));
    auditlog_push(&buf, "mboxid", mailbox_jmapid(mailbox));
    buf_printf(&buf, " uid=<%" PRIu32 ">", uid);
    auditlog_push(&buf, "sysflags", flagstr);

    auditlog_finish(&buf);
}

EXPORTED void auditlog_modseq(const struct mailbox *mailbox)
{
    struct buf buf = BUF_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&buf, "modseq");

    auditlog_push(&buf, "mailbox", mailbox_name(mailbox));
    auditlog_push(&buf, "uniqueid", mailbox_uniqueid(mailbox));
    auditlog_push(&buf, "mboxid", mailbox_jmapid(mailbox));

    buf_printf(&buf, " highestmodseq=<" MODSEQ_FMT ">",
                     mailbox->i.highestmodseq);
    buf_printf(&buf, " deletedmodseq=<" MODSEQ_FMT ">",
                     mailbox->i.deletedmodseq);
    buf_printf(&buf, " crcs=<%u/%u>",
                     mailbox->i.synccrcs.basic,
                     mailbox->i.synccrcs.annot);

    auditlog_finish(&buf);
}

EXPORTED void auditlog_proxy(const char *userid, const char *status)
{
    struct buf buf = BUF_INITIALIZER;
    char rsessionid[MAX_SESSIONID_SIZE];

    if (!config_auditlog) return;

    parse_sessionid(status, rsessionid);

    auditlog_begin(&buf, "proxy");

    if (userid)
        auditlog_push(&buf, "userid", userid);
    auditlog_push(&buf, "remote", rsessionid);

    auditlog_finish(&buf);
}

EXPORTED void auditlog_quota(const char *action,
                             const char *root,
                             const quota_t *oldquotas,
                             const quota_t *newquotas)
{
    struct buf buf = BUF_INITIALIZER;
    int resource;

    if (!config_auditlog) return;

    auditlog_begin(&buf, action);
    auditlog_push(&buf, "root", root);

    for (resource = 0; resource < QUOTA_NUMRESOURCES; resource++) {
        if (oldquotas) {
            buf_printf(&buf, " old%s=<%lld>",
                             quota_names[resource],
                             oldquotas[resource]);
        }

        if (newquotas) {
            buf_printf(&buf, " new%s=<%lld>",
                             quota_names[resource],
                             newquotas[resource]);
        }
    }

    auditlog_finish(&buf);
}

EXPORTED void auditlog_sieve(const char *action,
                             const char *userid,
                             const char *in_msgid,
                             const char *out_msgid,
                             const char *target,
                             const char *from_addr,
                             const char *to_addr)
{
    struct buf buf = BUF_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&buf, action);

    if (userid)
        auditlog_push(&buf, "userid", userid);

    auditlog_push(&buf, "in.msgid", in_msgid ? in_msgid : "nomsgid");
    if (out_msgid)
        auditlog_push(&buf, "out.msgid", out_msgid);

    if (target)
        auditlog_push(&buf, "target", target);

    if (from_addr)
        auditlog_push(&buf, "from", from_addr);

    if (to_addr)
        auditlog_push(&buf, "to", to_addr);

    auditlog_finish(&buf);
}

EXPORTED void auditlog_traffic(uint64_t bytes_in, uint64_t bytes_out)
{
    struct buf buf = BUF_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&buf, "traffic");
    buf_printf(&buf, " bytes_in=<%" PRIu64 ">"
                     " bytes_out=<%" PRIu64 ">",
                     bytes_in, bytes_out);
    auditlog_finish(&buf);
}
