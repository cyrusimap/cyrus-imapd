/* emailid_flags.c - keep flags in step across copies of an email */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "bsearch.h"
#include "conversations.h"
#include "emailid_flags.h"
#include "hash.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "msgrecord.h"
#include "ptrarray.h"
#include "user.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* The copies of queued emails in one mailbox */
struct emailid_flags_mbox
{
    arrayu64_t uids;
    ptrarray_t changes; /* struct conv_flagchange *, pairs with uids */
};

struct collect_rock
{
    struct conversations_state *cstate;
    const struct conv_flagchange *change;
    hash_table *mboxes;
};

struct apply_rock
{
    int r;
};

static void emailid_flags_mbox_free(void *data)
{
    struct emailid_flags_mbox *mbox = data;

    arrayu64_fini(&mbox->uids);
    ptrarray_fini(&mbox->changes);
    free(mbox);
}

static bool is_origin(const struct conv_flagchange *change,
                      const char *mboxname,
                      uint32_t uid)
{
    for (size_t i = 0; i < arrayu64_size(&change->origin_uids); i++) {
        if (arrayu64_nth(&change->origin_uids, i) == uid
            && !strcmp(strarray_nth(&change->origin_mboxnames, i), mboxname))
        {
            return true;
        }
    }
    return false;
}

static int collect_cb(const conv_guidrec_t *rec, void *vrock)
{
    struct collect_rock *rock = vrock;
    mbentry_t *mbentry = NULL;

    if (rec->part) {
        return 0;
    }
    if (rec->version >= 1
        && ((rec->system_flags & FLAG_DELETED)
            || (rec->internal_flags & FLAG_INTERNAL_EXPUNGED)))
    {
        return 0;
    }

    if (conv_guidrec_mbentry(rec, &mbentry)) {
        return 0;
    }

    if (!mboxname_isnondeliverymailbox(mbentry->name, mbentry->mbtype)
        && !is_origin(rock->change, mbentry->name, rec->uid))
    {
        struct emailid_flags_mbox *mbox =
            hash_lookup(mbentry->name, rock->mboxes);
        if (!mbox) {
            mbox = xzmalloc(sizeof(*mbox));
            hash_insert(mbentry->name, mbox, rock->mboxes);
        }
        arrayu64_append(&mbox->uids, rec->uid);
        ptrarray_append(&mbox->changes, (void *) rock->change);
    }

    mboxlist_entry_free(&mbentry);
    return 0;
}

static void collect_change(const char *guidrep, void *data, void *rock)
{
    const struct conv_flagchange *change = data;
    struct collect_rock *crock = rock;

    /* an arrival with nothing added or removed has nothing to fan out */
    if (!strarray_size(&change->added) && !strarray_size(&change->removed)) {
        return;
    }

    crock->change = change;
    conversations_guid_foreach(crock->cstate, guidrep, collect_cb, crock);
}

/* The MsgFlags bit for a system flag name, or 0 for \Deleted and unknowns */
static uint32_t system_flag(const char *name)
{
    if (!strcasecmp(name, "\\Answered")) {
        return FLAG_ANSWERED;
    }
    if (!strcasecmp(name, "\\Flagged")) {
        return FLAG_FLAGGED;
    }
    if (!strcasecmp(name, "\\Draft")) {
        return FLAG_DRAFT;
    }
    if (!strcasecmp(name, "\\Seen")) {
        return FLAG_SEEN;
    }
    return 0;
}

static int apply_change(struct mailbox *mailbox,
                        uint32_t uid,
                        const struct conv_flagchange *change)
{
    msgrecord_t *mr = NULL;
    uint32_t system_flags = 0, internal_flags = 0;
    uint32_t user_flags[MAX_USER_FLAGS / 32];
    bool changed = false;

    int r = msgrecord_find(mailbox, uid, &mr);
    if (r == IMAP_NOTFOUND) {
        return 0;
    }
    if (!r) {
        r = msgrecord_get_systemflags(mr, &system_flags);
    }
    if (!r) {
        r = msgrecord_get_internalflags(mr, &internal_flags);
    }
    if (!r) {
        r = msgrecord_get_userflags(mr, user_flags);
    }
    if (r) {
        goto done;
    }

    if ((system_flags & FLAG_DELETED)
        || (internal_flags & FLAG_INTERNAL_EXPUNGED))
    {
        goto done;
    }

    const char *flag;
    int i;
    strarray_foreach(&change->added, i, flag)
    {
        if (flag[0] == '\\') {
            uint32_t bit = system_flag(flag);
            if (bit && !(system_flags & bit)) {
                system_flags |= bit;
                changed = true;
            }
            continue;
        }

        int num;
        int r2 = mailbox_user_flag(mailbox, flag, &num, 1);
        if (r2) {
            xsyslog_ev(LOG_WARNING, "emailid.flags.userflag.failed",
                       lf_mailbox(mailbox),
                       lf_u("msg.imapuid", uid),
                       lf_s("msg.flag", flag),
                       lf_err("error", r2));
            continue;
        }
        uint32_t mask = 1U << (num & 31);
        if (!(user_flags[num / 32] & mask)) {
            user_flags[num / 32] |= mask;
            changed = true;
        }
    }

    strarray_foreach(&change->removed, i, flag)
    {
        if (flag[0] == '\\') {
            uint32_t bit = system_flag(flag);
            if (system_flags & bit) {
                system_flags &= ~bit;
                changed = true;
            }
            continue;
        }

        int num;
        if (mailbox_user_flag(mailbox, flag, &num, 0)) {
            continue;
        }
        uint32_t mask = 1U << (num & 31);
        if (user_flags[num / 32] & mask) {
            user_flags[num / 32] &= ~mask;
            changed = true;
        }
    }

    if (changed) {
        r = msgrecord_set_systemflags(mr, system_flags);
        if (!r) {
            r = msgrecord_set_userflags(mr, user_flags);
        }
        if (!r) {
            r = msgrecord_rewrite(mr);
        }
    }

done:
    if (r) {
        xsyslog_ev(LOG_ERR, "emailid.flags.apply.failed",
                   lf_mailbox(mailbox),
                   lf_u("msg.imapuid", uid),
                   lf_err("error", r));
    }
    msgrecord_unref(&mr);
    return r;
}

static void apply_mbox(const char *mboxname, void *data, void *vrock)
{
    struct emailid_flags_mbox *group = data;
    struct apply_rock *rock = vrock;
    struct mailbox *mailbox = NULL;

    if (rock->r) {
        return;
    }

    /* opening a mailbox that is open but unlocked locks it, and our close
     * won't unlock it while another reference holds it */
    struct mailbox *outer = mailbox_findopen(mboxname);
    bool unlock_outer = outer && !mailbox_index_islocked(outer, /*write*/ 0);

    int r = mailbox_open_iwl(mboxname, &mailbox);
    if (r) {
        xsyslog_ev(LOG_WARNING, "emailid.flags.open.failed",
                   lf_intname("mbox.name", mboxname),
                   lf_err("error", r));
        return;
    }

    for (size_t i = 0; i < arrayu64_size(&group->uids); i++) {
        r = apply_change(mailbox,
                         arrayu64_nth(&group->uids, i),
                         ptrarray_nth(&group->changes, i));
        if (r) {
            break;
        }
    }

    mailbox_close(&mailbox);
    if (unlock_outer) {
        mailbox_unlock_index(outer, NULL);
    }

    rock->r = r;
}

EXPORTED int emailid_flags_drain(struct conversations_state *cstate)
{
    if (cstate->draining_flags) {
        return 0;
    }
    if (!hash_constructed(&cstate->flagchanges)) {
        return 0;
    }
    if (!hash_count(&cstate->flagchanges)) {
        conversations_clear_flagchanges(cstate);
        return 0;
    }

    assert(!cstate->userid || user_nslock_islocked(cstate->userid));

    cstate->draining_flags = true;

    hash_table mboxes = HASH_TABLE_INITIALIZER;
    construct_hash_table(&mboxes, 16, 0);

    struct collect_rock crock = { cstate, NULL, &mboxes };
    hash_enumerate(&cstate->flagchanges, collect_change, &crock);

    struct apply_rock arock = { 0 };
    hash_enumerate_sorted(&mboxes, apply_mbox, &arock, cmpstringp_raw);

    free_hash_table(&mboxes, emailid_flags_mbox_free);
    conversations_clear_flagchanges(cstate);
    cstate->draining_flags = false;

    return arock.r;
}
