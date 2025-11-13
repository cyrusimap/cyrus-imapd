/* auditlog - audit logging API */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "imap/auditlog.h"

#include "imap/mailbox.h"
#include "imap/mboxname.h"
#include "imap/jmap_util.h"

#include "lib/assert.h"
#include "lib/logfmt.h"
#include "lib/sessionid.h"

#include <syslog.h>

static inline void auditlog_begin(struct logfmt *lf, const char *action)
{
    char *event;

    event = strconcat("auditlog.", action, NULL);
    logfmt_init(lf, event);
    free(event);

    logfmt_push_session(lf);
}

static inline void auditlog_finish(struct logfmt *lf)
{
    syslog(LOG_NOTICE, "%s", logfmt_cstring(lf));
    logfmt_fini(lf);
}

/*
 * Public API
 */

EXPORTED void auditlog_acl(const char *mboxname,
                           const mbentry_t *oldmbentry,
                           const mbentry_t *mbentry)
{
    struct logfmt lf = LOGFMT_INITIALIZER;
    mbname_t *mbname = NULL;

    if (!config_auditlog) return;

    mbname = mbname_from_intname(mboxname);
    auditlog_begin(&lf, "acl");

    logfmt_push_mbname(&lf, "mbox.name", mbname);
    logfmt_push(&lf, "uniqueid", mbentry->uniqueid);
    logfmt_push(&lf, "jmapid", mbentry->jmapid);
    logfmt_push(&lf, "mbtype", mboxlist_mbtype_to_string(mbentry->mbtype));
    logfmt_push(&lf, "oldacl", oldmbentry ? oldmbentry->acl : "NONE");
    logfmt_push(&lf, "acl", mbentry->acl);
    logfmt_pushf(&lf, "foldermodseq", MODSEQ_FMT, mbentry->foldermodseq);

    auditlog_finish(&lf);
    mbname_free(&mbname);
}

EXPORTED void auditlog_client(const char *action,
                              const char *userid,
                              const char *client)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&lf, action);

    logfmt_push(&lf, "userid", userid);
    logfmt_push(&lf, "client", client);

    auditlog_finish(&lf);
}

/* n.b. you probably want to call duplicate_log()! */
HIDDEN void auditlog_duplicate(const char *action,
                               const duplicate_key_t *dkey)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&lf, "duplicate");

    logfmt_push(&lf, "action", action);
    logfmt_push(&lf, "message-id", dkey->id);
    logfmt_push(&lf, "uniqueid-or-scope", dkey->to);
    logfmt_push(&lf, "date", dkey->date);

    auditlog_finish(&lf);
}

EXPORTED void auditlog_imip(const char *message_id,
                            const char *outcome,
                            const char *errstr)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&lf, "processed iMIP");

    logfmt_push(&lf, "message-id", message_id ? message_id : "nomsgid");
    logfmt_push(&lf, "outcome", outcome);
    if (errstr)
        logfmt_push(&lf, "errstr", errstr);

    auditlog_finish(&lf);
}

EXPORTED void auditlog_mailbox(const char *action,
                               const struct mailbox *oldmailbox,
                               const struct mailbox *mailbox,
                               const char *newpartition)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&lf, action);

    if (oldmailbox && strcmpsafe(mailbox_name(oldmailbox),
                                 mailbox_name(mailbox)))
    {
        mbname_t *mbname = mbname_from_intname(mailbox_name(oldmailbox));
        logfmt_push_mbname(&lf, "old.mbox.name", mbname);
        mbname_free(&mbname);
    }

    logfmt_push_mailbox(&lf, mailbox);
    logfmt_pushf(&lf, "uidvalidity", "%u", mailbox->i.uidvalidity);

    if (oldmailbox && strcmpsafe(mailbox_partition(oldmailbox),
                                 mailbox_partition(mailbox)))
    {
        logfmt_push(&lf, "oldpart", mailbox_partition(oldmailbox));
        logfmt_push(&lf, "newpart", mailbox_partition(mailbox));
    }
    else if (newpartition && strcmpsafe(mailbox_partition(mailbox),
                                        newpartition))
    {
        logfmt_push(&lf, "oldpart", mailbox_partition(mailbox));
        logfmt_push(&lf, "newpart", newpartition);
    }

    auditlog_finish(&lf);
}

EXPORTED void auditlog_mboxname(const char *action,
                                const char *userid,
                                const char *mboxname)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&lf, action);

    if (userid) {
        logfmt_push(&lf, "userid", userid);
    }

    if (mboxname) {
        mbname_t *mbname = mbname_from_intname(mboxname);
        logfmt_push_mbname(&lf, "mbox.name", mbname);
        mbname_free(&mbname);
    }

    auditlog_finish(&lf);
}

EXPORTED void auditlog_message(const char *action,
                               struct mailbox *mailbox,
                               const struct index_record *oldrecord,
                               const struct index_record *record,
                               const char *message_id)
{
    struct logfmt lf = LOGFMT_INITIALIZER;
    struct conversations_state *cstate;
    char flagstr[FLAGMAPSTR_MAXLEN] = {0};
    char emailid[JMAP_MAX_EMAILID_SIZE] = {0};
    char threadid[JMAP_THREADID_SIZE] = {0};

    if (!config_auditlog) return;

    cstate = mailbox_get_cstate(mailbox);
    jmap_set_emailid(cstate, &record->guid, 0, &record->internaldate, emailid);
    jmap_set_threadid(cstate, record->cid, threadid);
    flags_to_str(record, flagstr);

    auditlog_begin(&lf, action);

    logfmt_push_mailbox(&lf, mailbox);
    logfmt_pushf(&lf, "uid", "%u", record->uid);
    logfmt_pushf(&lf, "modseq", MODSEQ_FMT, record->modseq);
    logfmt_push(&lf, "sysflags", flagstr);

    if (oldrecord) {
        flags_to_str(oldrecord, flagstr);
        logfmt_push(&lf, "oldflags", flagstr);
    }

    logfmt_push(&lf, "guid", message_guid_encode(&record->guid));
    logfmt_push(&lf, "emailid", emailid);
    logfmt_push(&lf, "cid", threadid);

    if (message_id) {
        logfmt_push(&lf, "message-id", message_id);
    }

    logfmt_pushf(&lf, "size", UINT64_FMT, record->size);
    auditlog_finish(&lf);
}

EXPORTED void auditlog_message_uid(const char *action,
                                   const struct mailbox *mailbox,
                                   uint32_t uid,
                                   const char *flagstr)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&lf, action);

    logfmt_push_mailbox(&lf, mailbox);
    logfmt_pushf(&lf, "uid", "%" PRIu32, uid);
    logfmt_push(&lf, "sysflags", flagstr);

    auditlog_finish(&lf);
}

EXPORTED void auditlog_modseq(const struct mailbox *mailbox)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&lf, "modseq");

    logfmt_push_mailbox(&lf, mailbox);

    logfmt_pushf(&lf, "highestmodseq", MODSEQ_FMT, mailbox->i.highestmodseq);
    logfmt_pushf(&lf, "deletedmodseq", MODSEQ_FMT, mailbox->i.deletedmodseq);
    logfmt_pushf(&lf, "crcs.basic", "%u", mailbox->i.synccrcs.basic);
    logfmt_pushf(&lf, "crcs.annot", "%u", mailbox->i.synccrcs.annot);

    auditlog_finish(&lf);
}

EXPORTED void auditlog_proxy(const char *userid, const char *status)
{
    struct logfmt lf = LOGFMT_INITIALIZER;
    char rsessionid[MAX_SESSIONID_SIZE];

    if (!config_auditlog) return;

    parse_sessionid(status, rsessionid);

    auditlog_begin(&lf, "proxy");

    if (userid)
        logfmt_push(&lf, "userid", userid);
    logfmt_push(&lf, "remote", rsessionid);

    auditlog_finish(&lf);
}

EXPORTED void auditlog_quota(const char *action,
                             const char *root,
                             const quota_t *oldquotas,
                             const quota_t *newquotas)
{
    struct logfmt lf = LOGFMT_INITIALIZER;
    char name[32];
    int resource;

    if (!config_auditlog) return;

    auditlog_begin(&lf, action);
    logfmt_push(&lf, "root", root);

    for (resource = 0; resource < QUOTA_NUMRESOURCES; resource++) {
        if (oldquotas) {
            snprintf(name, sizeof(name), "old.%s", quota_names[resource]);
            logfmt_pushf(&lf, name, "%lld", oldquotas[resource]);
        }

        if (newquotas) {
            snprintf(name, sizeof(name), "new.%s", quota_names[resource]);
            logfmt_pushf(&lf, name, "%lld", newquotas[resource]);
        }
    }

    auditlog_finish(&lf);
}

EXPORTED void auditlog_sieve(const char *action,
                             const char *userid,
                             const char *in_msgid,
                             const char *out_msgid,
                             const char *target,
                             const char *from_addr,
                             const char *to_addr)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&lf, action);

    if (userid)
        logfmt_push(&lf, "userid", userid);

    logfmt_push(&lf, "in.msgid", in_msgid ? in_msgid : "nomsgid");
    if (out_msgid)
        logfmt_push(&lf, "out.msgid", out_msgid);

    if (target)
        logfmt_push(&lf, "target", target);

    if (from_addr)
        logfmt_push(&lf, "from", from_addr);

    if (to_addr)
        logfmt_push(&lf, "to", to_addr);

    auditlog_finish(&lf);
}

EXPORTED void auditlog_traffic(uint64_t bytes_in, uint64_t bytes_out)
{
    struct logfmt lf = LOGFMT_INITIALIZER;

    if (!config_auditlog) return;

    auditlog_begin(&lf, "traffic");
    logfmt_pushf(&lf, "bytes_in", "%" PRIu64, bytes_in);
    logfmt_pushf(&lf, "bytes_out", "%" PRIu64, bytes_out);
    auditlog_finish(&lf);
}
