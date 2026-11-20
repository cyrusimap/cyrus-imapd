/* emailid_flags.c - keep flags in step across copies of an email */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "acl.h"
#include "auth.h"
#include "bsearch.h"
#include "conversations.h"
#include "emailid_flags.h"
#include "hash.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "msgrecord.h"
#include "ptrarray.h"
#include "seen.h"
#include "seqset.h"
#include "user.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* The user whose change is being drained; NULL authstate means any user */
static struct
{
    char *userid;
    const struct auth_state *authstate;
    bool isadmin;
} actor;

/* The copies of queued emails in one mailbox */
struct emailid_flags_mbox
{
    bool hidden;   /* the actor can't read the mailbox */
    bool skip;     /* the actor may change nothing here */
    bool mayseen;  /* the actor may set \Seen */
    bool maywrite; /* the actor may set every other flag */
    arrayu64_t uids;
    ptrarray_t changes; /* struct conv_flagchange *, pairs with uids */
};

/* A new copy's merge with the other copies of its email */
struct merge
{
    /* first, so a pointer to it is a pointer to the merge: added is the
     * union of every flag but \Seen, and removed is \Seen unless every
     * copy is seen */
    struct conv_flagchange change;
    bool allseen;
    bool keepseen;     /* leave \Seen as each copy has it */
    ptrarray_t groups; /* struct emailid_flags_mbox *, pairs with uids */
    arrayu64_t uids;
};

struct collect_rock
{
    struct conversations_state *cstate;
    const struct conv_flagchange *change;
    hash_table *mboxes;
    struct merge *merge; /* collecting the copies a merge counts */
};

struct apply_rock
{
    int r;
};

/* The actor's seen.db state for one mailbox, where \Seen isn't the record's */
struct seen_change
{
    struct seen *db; /* NULL if it couldn't be locked: leave \Seen alone */
    struct seendata sd;
    seqset_t *old;
    arrayu64_t add;
    arrayu64_t del;
};

static void emailid_flags_mbox_free(void *data)
{
    struct emailid_flags_mbox *mbox = data;

    arrayu64_fini(&mbox->uids);
    ptrarray_fini(&mbox->changes);
    free(mbox);
}

static void merge_free(void *data)
{
    struct merge *merge = data;

    strarray_fini(&merge->change.added);
    strarray_fini(&merge->change.removed);
    strarray_fini(&merge->change.origin_mboxnames);
    arrayu64_fini(&merge->change.origin_uids);
    ptrarray_fini(&merge->groups);
    arrayu64_fini(&merge->uids);
    free(merge);
}

EXPORTED void emailid_flags_set_actor(const char *userid,
                                      const struct auth_state *authstate,
                                      bool isadmin)
{
    free(actor.userid);
    actor.userid = xstrdupnull(userid);
    actor.authstate = authstate;
    actor.isadmin = isadmin;
}

static struct emailid_flags_mbox *new_mbox(const mbentry_t *mbentry)
{
    struct emailid_flags_mbox *mbox = xzmalloc(sizeof(*mbox));

    if (!actor.authstate || actor.isadmin) {
        mbox->mayseen = mbox->maywrite = true;
        return mbox;
    }

    int rights = cyrus_acl_myrights(actor.authstate, mbentry->acl);
    mbox->hidden = !(rights & ACL_READ);
    mbox->mayseen = (rights & ACL_SETSEEN);
    mbox->maywrite = (rights & ACL_WRITE);
    mbox->skip = mbox->hidden || !(mbox->mayseen || mbox->maywrite);
    if (mbox->skip || !mbox->mayseen || !mbox->maywrite) {
        char rightstr[ACL_MAXSTR];
        xsyslog_ev(LOG_DEBUG, "emailid.flags.restricted",
                   lf_s("u.username", actor.userid),
                   lf_intname("mbox.name", mbentry->name),
                   lf_s("acl.rights", cyrus_acl_masktostr(rights, rightstr)));
    }
    return mbox;
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
            mbox = new_mbox(mbentry);
            hash_insert(mbentry->name, mbox, rock->mboxes);
        }
        if (rock->merge) {
            if (!mbox->hidden) {
                ptrarray_append(&rock->merge->groups, mbox);
                arrayu64_append(&rock->merge->uids, rec->uid);
            }
        }
        else if (!mbox->skip) {
            arrayu64_append(&mbox->uids, rec->uid);
            ptrarray_append(&mbox->changes, (void *) rock->change);
        }
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

struct arrival_rock
{
    struct collect_rock *crock;
    ptrarray_t *merges;
};

static void collect_arrival(const char *guidrep, void *data, void *rock)
{
    const struct conv_flagchange *change = data;
    struct arrival_rock *arock = rock;
    struct collect_rock *crock = arock->crock;

    if (!change->arrival) {
        return;
    }

    struct merge *merge = xzmalloc(sizeof(*merge));
    merge->allseen = true;
    merge->keepseen = !change->seen_merge;
    crock->change = &merge->change;
    crock->merge = merge;
    conversations_guid_foreach(crock->cstate, guidrep, collect_cb, crock);
    crock->merge = NULL;

    /* a copy on its own is already merged */
    if (arrayu64_size(&merge->uids) < 2) {
        merge_free(merge);
        return;
    }

    for (size_t i = 0; i < arrayu64_size(&merge->uids); i++) {
        struct emailid_flags_mbox *mbox = ptrarray_nth(&merge->groups, i);
        arrayu64_append(&mbox->uids, arrayu64_nth(&merge->uids, i));
        ptrarray_append(&mbox->changes, &merge->change);
    }
    ptrarray_append(arock->merges, merge);
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

static bool may_set(const struct emailid_flags_mbox *group, const char *flag)
{
    return strcasecmp(flag, "\\Seen") ? group->maywrite : group->mayseen;
}

static int apply_change(struct mailbox *mailbox,
                        const struct emailid_flags_mbox *group,
                        struct seen_change *seen,
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
        if (!may_set(group, flag)) {
            continue;
        }
        if (seen && !strcasecmp(flag, "\\Seen")) {
            if (seen->db && !seqset_ismember(seen->old, uid)) {
                arrayu64_append(&seen->add, uid);
                changed = true;
            }
            continue;
        }
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
        if (!may_set(group, flag)) {
            continue;
        }
        if (seen && !strcasecmp(flag, "\\Seen")) {
            if (seen->db && seqset_ismember(seen->old, uid)) {
                arrayu64_append(&seen->del, uid);
                changed = true;
            }
            continue;
        }
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

static bool group_has_seen(const struct emailid_flags_mbox *group)
{
    for (int i = 0; i < ptrarray_size(&group->changes); i++) {
        const struct conv_flagchange *change = ptrarray_nth(&group->changes, i);
        if (strarray_find_case(&change->added, "\\Seen", 0) >= 0
            || strarray_find_case(&change->removed, "\\Seen", 0) >= 0)
        {
            return true;
        }
    }
    return false;
}

/* Lock the actor's seen.db record for @mailbox, as index_writeseen does */
static void seen_begin(struct mailbox *mailbox, struct seen_change *seen)
{
    int r = seen_open(actor.userid, SEEN_CREATE, &seen->db);
    if (!r) {
        r = seen_lockread(seen->db, mailbox_uniqueid(mailbox), &seen->sd);
    }
    if (r) {
        xsyslog_ev(LOG_ERR, "emailid.flags.seen.failed",
                   lf_s("u.username", actor.userid),
                   lf_mailbox(mailbox),
                   lf_err("error", r));
        seen_close(&seen->db);
        return;
    }

    seen->old = seqset_parse(seen->sd.seenuids, NULL, mailbox->i.last_uid);
}

static void seen_end(struct mailbox *mailbox, struct seen_change *seen)
{
    int r = 0;

    if (arrayu64_size(&seen->add) || arrayu64_size(&seen->del)) {
        seqset_t *new = seqset_init(0, SEQ_SPARSE);
        unsigned uid;

        /* both ascending, so walk them together */
        arrayu64_sort(&seen->del, NULL);
        size_t d = 0;
        seqset_reset(seen->old);
        while ((uid = seqset_getnext(seen->old))) {
            while (d < arrayu64_size(&seen->del)
                   && arrayu64_nth(&seen->del, d) < uid)
            {
                d++;
            }
            if (d == arrayu64_size(&seen->del)
                || arrayu64_nth(&seen->del, d) != uid)
            {
                seqset_add(new, uid, 1);
            }
        }
        arrayu64_sort(&seen->add, NULL);
        for (size_t i = 0; i < arrayu64_size(&seen->add); i++) {
            seqset_add(new, arrayu64_nth(&seen->add, i), 1);
        }

        free(seen->sd.seenuids);
        seen->sd.seenuids = seqset_cstring(new);
        if (!seen->sd.seenuids) {
            seen->sd.seenuids = xstrdup("");
        }
        seen->sd.lastread = time(NULL);
        seen->sd.lastchange = mailbox->i.last_appenddate.tv_sec;
        r = seen_write(seen->db, mailbox_uniqueid(mailbox), &seen->sd);
        seqset_free(&new);
    }

    seen_close(&seen->db);
    if (r) {
        xsyslog_ev(LOG_ERR, "emailid.flags.seen.failed",
                   lf_s("u.username", actor.userid),
                   lf_mailbox(mailbox),
                   lf_err("error", r));
    }

    seen_freedata(&seen->sd);
    seqset_free(&seen->old);
    arrayu64_fini(&seen->add);
    arrayu64_fini(&seen->del);
}

/* Open a sibling mailbox, write-locked.  Returns the mailbox another
 * reference holds open but unlocked, which close_sibling must unlock. */
static int open_sibling(const char *mboxname,
                        struct mailbox **mailboxp,
                        struct mailbox **outerp)
{
    /* opening a mailbox that is open but unlocked locks it, and our close
     * won't unlock it while another reference holds it */
    struct mailbox *outer = mailbox_findopen(mboxname);
    *outerp =
        outer && !mailbox_index_islocked(outer, /*write*/ 0) ? outer : NULL;

    int r = mailbox_open_iwl(mboxname, mailboxp);
    if (r) {
        xsyslog_ev(LOG_WARNING, "emailid.flags.open.failed",
                   lf_intname("mbox.name", mboxname),
                   lf_err("error", r));
    }
    return r;
}

static void close_sibling(struct mailbox **mailboxp, struct mailbox *outer)
{
    mailbox_close(mailboxp);
    if (outer) {
        mailbox_unlock_index(outer, NULL);
    }
}

/* Whether the actor's \Seen is the record's flag */
static bool actor_internal_seen(const struct mailbox *mailbox)
{
    return !actor.userid || mailbox_internal_seen(mailbox, actor.userid);
}

/* Where the actor's \Seen comes from when reading a copy for a merge */
enum merge_seen {
    MERGE_SEEN_RECORD,
    MERGE_SEEN_DB,      /* the actor's seen.db */
    MERGE_SEEN_UNKNOWN, /* left out, so it can't unsee the other copies */
};

/* Add one copy's flags to its merge */

static void read_copy(struct mailbox *mailbox,
                      uint32_t uid,
                      struct merge *merge,
                      enum merge_seen seen,
                      const seqset_t *seenuids)
{
    static const struct
    {
        uint32_t bit;
        const char *name;
    } sysflags[] = {
        { FLAG_ANSWERED, "\\Answered" },
        { FLAG_FLAGGED,  "\\Flagged"  },
        { FLAG_DRAFT,    "\\Draft"    },
    };
    struct index_record record;

    if (mailbox_find_index_record(mailbox, uid, &record)
        || (record.system_flags & FLAG_DELETED)
        || (record.internal_flags & FLAG_INTERNAL_EXPUNGED))
    {
        return;
    }

    for (size_t i = 0; i < sizeof(sysflags) / sizeof(sysflags[0]); i++) {
        if (record.system_flags & sysflags[i].bit) {
            strarray_add_case(&merge->change.added, sysflags[i].name);
        }
    }
    for (int i = 0; i < MAX_USER_FLAGS; i++) {
        if (mailbox->h.flagname[i]
            && (record.user_flags[i / 32] & (1U << (i & 31))))
        {
            strarray_add_case(&merge->change.added, mailbox->h.flagname[i]);
        }
    }

    if ((seen == MERGE_SEEN_RECORD && !(record.system_flags & FLAG_SEEN))
        || (seen == MERGE_SEEN_DB && !seqset_ismember(seenuids, uid)))
    {
        merge->allseen = false;
    }
}

/* Add the flags of the copies in one mailbox to their merges */
static void read_mbox(const char *mboxname,
                      void *data,
                      void *rock __attribute__((unused)))
{
    struct emailid_flags_mbox *group = data;
    struct mailbox *mailbox = NULL, *outer = NULL;

    if (!arrayu64_size(&group->uids)
        || open_sibling(mboxname, &mailbox, &outer))
    {
        return;
    }

    enum merge_seen seen = MERGE_SEEN_RECORD;
    seqset_t *seenuids = NULL;
    if (!actor_internal_seen(mailbox)) {
        struct seen *db = NULL;
        struct seendata sd = SEENDATA_INITIALIZER;
        int r = seen_open(actor.userid, SEEN_CREATE, &db);
        if (!r) {
            r = seen_read(db, mailbox_uniqueid(mailbox), &sd);
        }
        seen_close(&db);
        if (r) {
            xsyslog_ev(LOG_ERR, "emailid.flags.seen.failed",
                       lf_s("u.username", actor.userid),
                       lf_mailbox(mailbox),
                       lf_err("error", r));
            seen = MERGE_SEEN_UNKNOWN;
        }
        else {
            seen = MERGE_SEEN_DB;
            seenuids = seqset_parse(sd.seenuids, NULL, mailbox->i.last_uid);
        }
        seen_freedata(&sd);
    }

    for (size_t i = 0; i < arrayu64_size(&group->uids); i++) {
        read_copy(mailbox,
                  arrayu64_nth(&group->uids, i),
                  (struct merge *) ptrarray_nth(&group->changes, i),
                  seen,
                  seenuids);
    }

    seqset_free(&seenuids);
    close_sibling(&mailbox, outer);
}

static void apply_mbox(const char *mboxname, void *data, void *vrock)
{
    struct emailid_flags_mbox *group = data;
    struct apply_rock *rock = vrock;
    struct mailbox *mailbox = NULL, *outer = NULL;

    if (rock->r || group->skip || !arrayu64_size(&group->uids)) {
        return;
    }

    int r = open_sibling(mboxname, &mailbox, &outer);
    if (r) {
        return;
    }

    /* a non-owner's \Seen lives in their seen.db, not the record */
    struct seen_change seenchange = { .sd = SEENDATA_INITIALIZER };
    struct seen_change *seen = NULL;
    if (!actor_internal_seen(mailbox)) {
        seen = &seenchange;
        if (group->mayseen && group_has_seen(group)) {
            seen_begin(mailbox, seen);
        }
    }

    for (size_t i = 0; i < arrayu64_size(&group->uids); i++) {
        r = apply_change(mailbox,
                         group,
                         seen,
                         arrayu64_nth(&group->uids, i),
                         ptrarray_nth(&group->changes, i));
        if (r) {
            break;
        }
    }

    if (seen) {
        seen_end(mailbox, seen);
    }

    close_sibling(&mailbox, outer);

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

    struct collect_rock crock = { cstate, NULL, &mboxes, NULL };
    hash_enumerate(&cstate->flagchanges, collect_change, &crock);

    struct apply_rock arock = { 0 };
    hash_enumerate_sorted(&mboxes, apply_mbox, &arock, cmpstringp_raw);

    free_hash_table(&mboxes, emailid_flags_mbox_free);

    /* then merge each new copy with the email's other copies */
    if (!arock.r) {
        ptrarray_t merges = PTRARRAY_INITIALIZER;
        construct_hash_table(&mboxes, 16, 0);

        struct arrival_rock rrock = { &crock, &merges };
        hash_enumerate(&cstate->flagchanges, collect_arrival, &rrock);

        if (ptrarray_size(&merges)) {
            hash_enumerate_sorted(&mboxes, read_mbox, NULL, cmpstringp_raw);
            for (int i = 0; i < ptrarray_size(&merges); i++) {
                struct merge *merge = ptrarray_nth(&merges, i);
                if (!merge->keepseen && !merge->allseen) {
                    strarray_append(&merge->change.removed, "\\Seen");
                }
            }
            hash_enumerate_sorted(&mboxes, apply_mbox, &arock, cmpstringp_raw);
        }

        free_hash_table(&mboxes, emailid_flags_mbox_free);
        for (int i = 0; i < ptrarray_size(&merges); i++) {
            merge_free(ptrarray_nth(&merges, i));
        }
        ptrarray_fini(&merges);
    }
    conversations_clear_flagchanges(cstate);
    cstate->draining_flags = false;

    return arock.r;
}
