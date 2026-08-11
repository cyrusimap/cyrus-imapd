/* audit.c - mailstore consistency auditing */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <jansson.h>

#include "audit.h"
#include "libconfig.h"
#include "imap/imap_err.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "user.h"
#include "xmalloc.h"

struct audit_state {
    struct audit_config config;
    struct buf *out;        /* borrowed from config, or NULL for stdout */
    unsigned count;

    /* Repairs are accumulated during the checks and applied afterwards in
     * one transaction, so that a failure part-way through leaves the
     * database as it was rather than half-fixed.  The scan itself holds a
     * read transaction, so nothing can be written while it runs. */
    strarray_t deletes;     /* raw keys to remove */
    strarray_t fix_jmapids; /* uniqueids needing a J record */
    ptrarray_t prunes;      /* struct audit_prune */
};

/* A tombstone judged old enough to remove, and the I record it refers
 * to.  What happens to that I record depends on whether it still carries
 * the tombstoned name -- see audit_apply_prunes(). */
struct audit_prune {
    char *mboxname;
    char *uniqueid;
};

static void free_prune(void *data);

EXPORTED struct audit_state *audit_begin(const struct audit_config *config)
{
    struct audit_state *state = xzmalloc(sizeof(struct audit_state));

    state->config = *config;
    state->out = config->out;

    return state;
}

EXPORTED unsigned audit_finding_count(const struct audit_state *state)
{
    return state ? state->count : 0;
}

static void audit_emit(struct audit_state *state, struct buf *line)
{
    if (state->out) {
        buf_append(state->out, line);
        buf_putc(state->out, '\n');
    }
    else {
        printf("%s\n", buf_cstring(line));
    }
}

static void audit_emit_json(struct audit_state *state,
                            const struct audit_finding *finding)
{
    json_t *obj = json_object();
    struct buf line = BUF_INITIALIZER;
    char *dumped;

    /* Absent fields are omitted rather than emitted as null, so that a
     * consumer can simply test for presence. */
    json_object_set_new(obj, "code", json_string(finding->code));
    if (finding->uniqueid)
        json_object_set_new(obj, "uniqueid", json_string(finding->uniqueid));
    if (finding->mboxname)
        json_object_set_new(obj, "mboxname", json_string(finding->mboxname));
    if (finding->userid)
        json_object_set_new(obj, "user", json_string(finding->userid));
    if (finding->path)
        json_object_set_new(obj, "path", json_string(finding->path));
    if (finding->tier)
        json_object_set_new(obj, "tier", json_string(finding->tier));
    if (finding->metaname)
        json_object_set_new(obj, "metaname", json_string(finding->metaname));
    if (finding->guid)
        json_object_set_new(obj, "guid", json_string(finding->guid));
    if (finding->detail)
        json_object_set_new(obj, "detail", json_string(finding->detail));
    if (finding->has_uid)
        json_object_set_new(obj, "uid", json_integer(finding->uid));
    if (finding->has_size)
        json_object_set_new(obj, "size", json_integer(finding->size));

    dumped = json_dumps(obj, JSON_COMPACT | JSON_PRESERVE_ORDER);
    if (dumped) {
        buf_setcstr(&line, dumped);
        audit_emit(state, &line);
        free(dumped);
    }

    buf_free(&line);
    json_decref(obj);
}

static void audit_emit_text(struct audit_state *state,
                            const struct audit_finding *finding)
{
    struct buf line = BUF_INITIALIZER;

    buf_setcstr(&line, finding->code);
    if (finding->mboxname) buf_printf(&line, " %s", finding->mboxname);
    if (finding->uniqueid) buf_printf(&line, " (%s)", finding->uniqueid);
    if (finding->has_uid) buf_printf(&line, " uid %u", finding->uid);
    if (finding->path) buf_printf(&line, " %s", finding->path);
    if (finding->detail) buf_printf(&line, " - %s", finding->detail);

    audit_emit(state, &line);
    buf_free(&line);
}

EXPORTED void audit_report(struct audit_state *state,
                           const struct audit_finding *finding)
{
    if (!state || !finding) return;

    /* A finding with no code is a programming error upstream.  Drop it
     * rather than emitting something a consumer cannot dispatch on. */
    if (!finding->code) return;

    state->count++;

    if (state->config.json) audit_emit_json(state, finding);
    else audit_emit_text(state, finding);

    syslog(LOG_NOTICE, "audit: %s mailbox=<%s> uniqueid=<%s> path=<%s>",
           finding->code,
           finding->mboxname ? finding->mboxname : "",
           finding->uniqueid ? finding->uniqueid : "",
           finding->path ? finding->path : "");
}

EXPORTED void audit_done(struct audit_state **statep)
{
    if (!statep || !*statep) return;

    strarray_fini(&(*statep)->deletes);
    strarray_fini(&(*statep)->fix_jmapids);

    while (ptrarray_size(&(*statep)->prunes))
        free_prune(ptrarray_pop(&(*statep)->prunes));
    ptrarray_fini(&(*statep)->prunes);

    free(*statep);
    *statep = NULL;
}

/* ------------------------------------------------------------------ */
/* repairs                                                            */

/* Queue a key for removal.  Nothing is written during the scan: the
 * checks run inside a read transaction, and a repair may touch several
 * keys that must land together or not at all. */
static void queue_delete(struct audit_state *state, const struct buf *key)
{
    if (!state->config.do_delete) return;

    strarray_appendm(&state->deletes,
                     xstrndup(buf_base(key), buf_len(key)));
}

static void queue_delete_id(struct audit_state *state, const char *uniqueid)
{
    struct buf key = BUF_INITIALIZER;

    mboxlist_key_for_id(uniqueid, &key);
    queue_delete(state, &key);

    buf_free(&key);
}

static void queue_delete_jmapid(struct audit_state *state,
                                const char *userid, const char *jmapid)
{
    struct buf key = BUF_INITIALIZER;

    mboxlist_key_for_jmapid(userid, jmapid, &key);
    queue_delete(state, &key);

    buf_free(&key);
}

/* Queue a mailbox for jmapid repair.  Unlike the deletions this is not a
 * raw key write -- mboxlist_fix_jmapid() may have to open the mailbox and
 * bump its modseq -- so it is applied outside the delete transaction. */
static void queue_fix_jmapid(struct audit_state *state, const char *uniqueid)
{
    if (!state->config.do_fix) return;

    strarray_append(&state->fix_jmapids, uniqueid);
}

static void queue_prune(struct audit_state *state, const char *mboxname,
                        const char *uniqueid)
{
    struct audit_prune *p;

    if (!state->config.prune_days) return;

    p = xzmalloc(sizeof(struct audit_prune));
    p->mboxname = xstrdupnull(mboxname);
    p->uniqueid = xstrdupnull(uniqueid);

    ptrarray_append(&state->prunes, p);
}

static void free_prune(void *data)
{
    struct audit_prune *p = (struct audit_prune *)data;

    if (!p) return;
    free(p->mboxname);
    free(p->uniqueid);
    free(p);
}

/* Remove a tombstone, and whatever refers to it.
 *
 * Rename tombstones the old name and moves the I record to the new one;
 * delete tombstones the current name.  So for a tombstone at name X with
 * uniqueid U:
 *
 *   I(U) exists and names X   the mailbox is entirely gone -- drop both
 *   I(U) exists, names other  the mailbox lives elsewhere -- drop the
 *                             tombstone and the matching history item
 *   I(U) absent               an orphan -- drop the tombstone alone
 *
 * All within one transaction, so the database is never left describing a
 * name that no longer exists.
 */
static int prune_one(const struct audit_prune *p, struct txn **tid)
{
    mbentry_t *byid = NULL;
    struct buf key = BUF_INITIALIZER;
    int i, r;

    /* the tombstone itself, in every case */
    mboxlist_key_for_name(p->mboxname, &key);
    r = mboxlist_rawkey_delete(buf_base(&key), buf_len(&key), tid);
    if (r) goto done;

    r = mboxlist_lookup_by_uniqueid(p->uniqueid, &byid, tid);
    if (r == IMAP_MAILBOX_NONEXISTENT) { r = 0; goto done; }
    if (r) goto done;

    if (!strcmpsafe(byid->name, p->mboxname)) {
        /* nothing refers to this mailbox any more */
        buf_reset(&key);
        mboxlist_key_for_id(p->uniqueid, &key);
        r = mboxlist_rawkey_delete(buf_base(&key), buf_len(&key), tid);
        goto done;
    }

    /* the mailbox survives under another name: drop just the history
     * item, rather than the record that still describes a live mailbox */
    for (i = 0; i < ptrarray_size(&byid->name_history); i++) {
        former_name_t *h = ptrarray_nth(&byid->name_history, i);

        if (strcmpsafe(h->name, p->mboxname)) continue;

        ptrarray_remove(&byid->name_history, i);
        free(h->name);
        free(h->partition);
        free(h);

        r = mboxlist_rewrite_id_record(byid, tid);
        break;
    }

  done:
    mboxlist_entry_free(&byid);
    buf_free(&key);

    return r;
}

static int audit_apply_prunes(struct audit_state *state)
{
    struct txn *tid = NULL;
    int i, r = 0;

    if (!ptrarray_size(&state->prunes)) return 0;

    if (!state->config.really) {
        for (i = 0; i < ptrarray_size(&state->prunes); i++) {
            const struct audit_prune *p = ptrarray_nth(&state->prunes, i);
            struct audit_finding finding = AUDIT_FINDING_INITIALIZER;
            finding.code = "would-prune-tombstone";
            finding.mboxname = p->mboxname;
            finding.uniqueid = p->uniqueid;
            audit_report(state, &finding);
        }
        return 0;
    }

    for (i = 0; i < ptrarray_size(&state->prunes); i++) {
        r = prune_one(ptrarray_nth(&state->prunes, i), &tid);
        if (r) break;
    }

    if (r) {
        if (tid) mboxlist_abort(tid);
        return r;
    }

    if (tid) r = mboxlist_commit(tid);

    return r;
}

/* Apply everything queued, in one transaction.  Returns 0 on success. */
static int audit_apply_repairs(struct audit_state *state)
{
    struct txn *tid = NULL;
    int i, r = 0;

    if (!strarray_size(&state->deletes)) return 0;

    /* Without --really the intent has already been reported and there is
     * nothing to write. */
    if (!state->config.really) {
        for (i = 0; i < strarray_size(&state->deletes); i++) {
            struct audit_finding finding = AUDIT_FINDING_INITIALIZER;
            finding.code = "would-delete-key";
            finding.detail = strarray_nth(&state->deletes, i);
            audit_report(state, &finding);
        }
        return 0;
    }

    for (i = 0; i < strarray_size(&state->deletes); i++) {
        const char *key = strarray_nth(&state->deletes, i);

        r = mboxlist_rawkey_delete(key, strlen(key), &tid);
        if (r) {
            xsyslog(LOG_ERR, "audit: failed to delete key",
                    "error=<%s>", cyrusdb_strerror(r));
            break;
        }
    }

    if (r) {
        /* leave the database as it was rather than half-repaired */
        if (tid) mboxlist_abort(tid);
        return r;
    }

    if (tid) r = mboxlist_commit(tid);

    return r;
}

/* Assign jmapids to the mailboxes that need one.  Separate from the
 * delete transaction because mboxlist_fix_jmapid() opens the mailbox and
 * bumps its modseq, and holds its own locks while doing so. */
static int audit_apply_jmapid_fixes(struct audit_state *state)
{
    int i, r = 0;

    for (i = 0; i < strarray_size(&state->fix_jmapids); i++) {
        const char *uniqueid = strarray_nth(&state->fix_jmapids, i);
        mbentry_t *mbentry = NULL;
        user_nslock_t *nslock = NULL;
        int r2;

        /* Re-verify: the sweep produced a candidate list, not a decision,
         * and the mailbox may have changed since. */
        r2 = mboxlist_lookup_by_uniqueid(uniqueid, &mbentry, NULL);
        if (r2 || !mbentry) {
            mboxlist_entry_free(&mbentry);
            continue;
        }

        if (!state->config.really) {
            struct audit_finding finding = AUDIT_FINDING_INITIALIZER;
            finding.code = "would-fix-jmapid";
            finding.uniqueid = uniqueid;
            finding.mboxname = mbentry->name;
            audit_report(state, &finding);
            mboxlist_entry_free(&mbentry);
            continue;
        }

        nslock = user_nslock_lockmb_w(mbentry->name);
        r2 = mboxlist_fix_jmapid(mbentry);
        user_nslock_release(&nslock);

        if (r2) {
            xsyslog(LOG_ERR, "audit: failed to fix jmapid",
                    "mboxname=<%s> error=<%s>",
                    mbentry->name, error_message(r2));
            if (!r) r = r2;
        }

        mboxlist_entry_free(&mbentry);
    }

    return r;
}

/* ------------------------------------------------------------------ */
/* level 0: the mailboxes.db keyspace                                 */

static void free_dbentry(void *data)
{
    struct audit_dbentry *entry = (struct audit_dbentry *)data;

    if (!entry) return;
    free(entry->uniqueid);
    free(entry->dbname);
    free(entry->jmapid);
    free(entry);
}

static void free_jmapid(void *data)
{
    struct audit_jmapid *j = (struct audit_jmapid *)data;

    if (!j) return;
    free(j->userid);
    free(j->jmapid);
    free(j->uniqueid);
    free(j);
}

static void free_tombstone(void *data)
{
    struct audit_tombstone *t = (struct audit_tombstone *)data;

    if (!t) return;
    free(t->dbname);
    free(t->uniqueid);
    free(t);
}

static void free_history(void *data)
{
    struct audit_history *h = (struct audit_history *)data;

    if (!h) return;
    free(h->uniqueid);
    free(h->dbname);
    free(h);
}

EXPORTED void audit_keyspace_init(struct audit_keyspace *ks)
{
    memset(ks, 0, sizeof(*ks));

    /* not mpool-backed: entries are freed individually in fini */
    construct_hash_table(&ks->byid, 4096, 0);
    construct_hash_table(&ks->byname, 4096, 0);
    ptrarray_init(&ks->jmapids);
    ptrarray_init(&ks->tombstones);
    ptrarray_init(&ks->history);
}

EXPORTED void audit_keyspace_fini(struct audit_keyspace *ks)
{
    void *item;

    free_hash_table(&ks->byid, free_dbentry);
    free_hash_table(&ks->byname, free_dbentry);

    while ((item = ptrarray_pop(&ks->jmapids)))
        free_jmapid(item);
    ptrarray_fini(&ks->jmapids);

    while ((item = ptrarray_pop(&ks->tombstones)))
        free_tombstone(item);
    ptrarray_fini(&ks->tombstones);

    while ((item = ptrarray_pop(&ks->history)))
        free_history(item);
    ptrarray_fini(&ks->history);
}

static struct audit_dbentry *new_dbentry(const char *uniqueid,
                                         const char *dbname,
                                         uint32_t mbtype,
                                         const char *jmapid)
{
    struct audit_dbentry *entry = xzmalloc(sizeof(struct audit_dbentry));

    entry->uniqueid = xstrdupnull(uniqueid);
    entry->dbname = xstrdupnull(dbname);
    entry->jmapid = xstrdupnull(jmapid);
    entry->mbtype = mbtype;

    return entry;
}

EXPORTED void audit_keyspace_add_id(struct audit_keyspace *ks,
                                    const char *uniqueid, const char *dbname,
                                    uint32_t mbtype, const char *jmapid)
{
    if (!uniqueid) return;
    hash_insert(uniqueid, new_dbentry(uniqueid, dbname, mbtype, jmapid),
                &ks->byid);
}

EXPORTED void audit_keyspace_add_name(struct audit_keyspace *ks,
                                      const char *dbname, const char *uniqueid,
                                      uint32_t mbtype, const char *jmapid)
{
    if (!dbname) return;
    hash_insert(dbname, new_dbentry(uniqueid, dbname, mbtype, jmapid),
                &ks->byname);
}

EXPORTED void audit_keyspace_add_jmapid(struct audit_keyspace *ks,
                                        const char *userid, const char *jmapid,
                                        const char *uniqueid)
{
    struct audit_jmapid *j = xzmalloc(sizeof(struct audit_jmapid));

    j->userid = xstrdupnull(userid);
    j->jmapid = xstrdupnull(jmapid);
    j->uniqueid = xstrdupnull(uniqueid);

    ptrarray_append(&ks->jmapids, j);
}

EXPORTED void audit_keyspace_add_tombstone(struct audit_keyspace *ks,
                                           const char *dbname,
                                           const char *uniqueid,
                                           time_t mtime)
{
    struct audit_tombstone *t = xzmalloc(sizeof(struct audit_tombstone));

    t->dbname = xstrdupnull(dbname);
    t->uniqueid = xstrdupnull(uniqueid);
    t->mtime = mtime;

    ptrarray_append(&ks->tombstones, t);
}

EXPORTED void audit_keyspace_add_history(struct audit_keyspace *ks,
                                         const char *uniqueid,
                                         const char *dbname,
                                         time_t mtime)
{
    struct audit_history *h = xzmalloc(sizeof(struct audit_history));

    h->uniqueid = xstrdupnull(uniqueid);
    h->dbname = xstrdupnull(dbname);
    h->mtime = mtime;

    ptrarray_append(&ks->history, h);
}

/* Does this I record carry the given name as a former name? */
static int find_history_item(const struct audit_keyspace *ks,
                             const char *uniqueid, const char *dbname)
{
    int i;

    for (i = 0; i < ptrarray_size(&ks->history); i++) {
        const struct audit_history *h = ptrarray_nth(&ks->history, i);
        if (strcmpsafe(h->uniqueid, uniqueid)) continue;
        if (strcmpsafe(h->dbname, dbname)) continue;
        return 1;
    }

    return 0;
}

static int find_tombstone(const struct audit_keyspace *ks, const char *dbname)
{
    int i;

    for (i = 0; i < ptrarray_size(&ks->tombstones); i++) {
        const struct audit_tombstone *t = ptrarray_nth(&ks->tombstones, i);
        if (!strcmpsafe(t->dbname, dbname)) return 1;
    }

    return 0;
}

/* Does a J key exist for this entry, naming this mailbox?
 *
 * The match is on all three of (userid, jmapid, uniqueid): a J record
 * that names a different mailbox does not make this one reachable by
 * jmapid.  That is only a safe thing to require because the caller has
 * told us conversations are enabled -- see check_jmapids.
 */
static int find_jmapid_key(const struct audit_keyspace *ks,
                           const struct audit_dbentry *entry,
                           struct buf *founduser)
{
    mbname_t *mbname;
    const char *userid;
    int i, found = 0;

    if (!entry->dbname) return 0;

    mbname = mbname_from_intname(entry->dbname);
    userid = mbname_userid(mbname);
    if (!userid) userid = "";

    if (founduser) buf_setcstr(founduser, userid);

    for (i = 0; i < ptrarray_size(&ks->jmapids); i++) {
        const struct audit_jmapid *j = ptrarray_nth(&ks->jmapids, i);
        if (strcmpsafe(j->jmapid, entry->jmapid)) continue;
        if (strcmpsafe(j->userid, userid)) continue;
        if (strcmpsafe(j->uniqueid, entry->uniqueid)) continue;
        found = 1;
        break;
    }

    mbname_free(&mbname);

    return found;
}

struct checkrock {
    struct audit_keyspace *ks;
    struct audit_state *state;
};

static void check_id_cb(const char *uniqueid, void *data, void *rock)
{
    struct checkrock *crock = (struct checkrock *)rock;
    struct audit_dbentry *entry = (struct audit_dbentry *)data;
    struct audit_finding finding = AUDIT_FINDING_INITIALIZER;

    finding.uniqueid = uniqueid;
    finding.mboxname = entry->dbname;

    /* A legacy-layout mailbox lives in a name-hashed directory that no
     * UUID sweep will ever visit.  Report it so an operator knows it is
     * there, but never let it reach the orphan checks -- treating it as
     * missing would invite deleting a healthy mailbox's record. */
    if (entry->mbtype & MBTYPE_LEGACY_DIRS) {
        finding.code = "db-entry-legacy-layout";
        audit_report(crock->state, &finding);
        return;
    }

    if (!entry->dbname || !hash_lookup(entry->dbname, &crock->ks->byname)) {
        finding.code = "db-missing-n-key";
        audit_report(crock->state, &finding);
        /* an I record nothing can reach by name */
        queue_delete_id(crock->state, uniqueid);
    }

    /* The J keyspace is only meaningful with conversations enabled. */
    if (!crock->state->config.check_jmapids) return;

    if (!entry->jmapid) {
        finding.code = "db-missing-j-property";
        audit_report(crock->state, &finding);
        queue_fix_jmapid(crock->state, uniqueid);
    }
    else {
        struct buf owner = BUF_INITIALIZER;

        if (!find_jmapid_key(crock->ks, entry, &owner)) {
            finding.code = "db-missing-j-key";
            finding.userid = buf_cstring(&owner);
            audit_report(crock->state, &finding);
            queue_fix_jmapid(crock->state, uniqueid);
        }

        buf_free(&owner);
    }
}

static void check_name_cb(const char *dbname, void *data, void *rock)
{
    struct checkrock *crock = (struct checkrock *)rock;
    struct audit_dbentry *entry = (struct audit_dbentry *)data;
    struct audit_finding finding = AUDIT_FINDING_INITIALIZER;

    /* already reported by check_id_cb */
    if (entry->mbtype & MBTYPE_LEGACY_DIRS) return;

    if (!entry->uniqueid || !hash_lookup(entry->uniqueid, &crock->ks->byid)) {
        finding.code = "db-missing-i-key";
        finding.mboxname = dbname;
        finding.uniqueid = entry->uniqueid;
        finding.detail = "run reconstruct";
        audit_report(crock->state, &finding);
    }
}

EXPORTED void audit_keyspace_check(struct audit_keyspace *ks,
                                   struct audit_state *state)
{
    struct checkrock crock = { ks, state };
    int i;

    hash_enumerate(&ks->byid, check_id_cb, &crock);
    hash_enumerate(&ks->byname, check_name_cb, &crock);

    for (i = 0; state->config.check_jmapids &&
                i < ptrarray_size(&ks->jmapids); i++) {
        struct audit_jmapid *j = ptrarray_nth(&ks->jmapids, i);
        struct audit_dbentry *entry = hash_lookup(j->uniqueid, &ks->byid);
        struct audit_finding finding = AUDIT_FINDING_INITIALIZER;

        finding.uniqueid = j->uniqueid;
        finding.userid = j->userid;

        if (!entry) {
            finding.code = "db-bogus-jmapid";
            audit_report(state, &finding);
            queue_delete_jmapid(state, j->userid, j->jmapid);
            continue;
        }

        /* a J key that disagrees with the entry it names is worse than a
         * missing one: a lookup by jmapid returns the wrong mailbox */
        if (strcmpsafe(entry->jmapid, j->jmapid)) {
            finding.code = "db-bad-jmapid";
            finding.mboxname = entry->dbname;
            audit_report(state, &finding);
            queue_delete_jmapid(state, j->userid, j->jmapid);
        }
    }

    /* Every tombstone must be explained: either the I record still carries
     * the tombstoned name (the mailbox was deleted), or one of its history
     * items does (the mailbox was renamed away from it). */
    for (i = 0; i < ptrarray_size(&ks->tombstones); i++) {
        struct audit_tombstone *t = ptrarray_nth(&ks->tombstones, i);
        struct audit_dbentry *entry = hash_lookup(t->uniqueid, &ks->byid);
        struct audit_finding finding = AUDIT_FINDING_INITIALIZER;

        finding.uniqueid = t->uniqueid;
        finding.mboxname = t->dbname;

        /* Pruning is off unless an age was given: a tombstone removed
         * before a replica has synced past it means that replica never
         * learns the name is gone, and the safe threshold is a property
         * of the deployment rather than something Cyrus can know. */
        if (state->config.prune_days &&
            t->mtime &&
            t->mtime < time(NULL) - (state->config.prune_days * 86400)) {
            finding.code = "db-stale-tombstone";
            audit_report(state, &finding);
            queue_prune(state, t->dbname, t->uniqueid);
            continue;
        }

        /* no I record at all: an orphan tombstone.  Prunable, but not an
         * inconsistency -- there is nothing left for it to disagree with */
        if (!entry) continue;

        if (!strcmpsafe(entry->dbname, t->dbname)) continue;    /* deleted */
        if (find_history_item(ks, t->uniqueid, t->dbname)) continue; /* renamed */

        finding.code = "db-tombstone-no-history";
        audit_report(state, &finding);
    }

    /* And every history item must have its tombstone, or a replica will
     * never learn that the old name is gone. */
    for (i = 0; i < ptrarray_size(&ks->history); i++) {
        struct audit_history *h = ptrarray_nth(&ks->history, i);
        struct audit_finding finding = AUDIT_FINDING_INITIALIZER;

        if (find_tombstone(ks, h->dbname)) continue;

        finding.code = "db-history-no-tombstone";
        finding.uniqueid = h->uniqueid;
        finding.mboxname = h->dbname;
        audit_report(state, &finding);
    }
}

/* ------------------------------------------------------------------ */
/* per-user structure                                                 */

struct userinfo {
    char *userid;
    char *inboxid;      /* uniqueid of the INBOX, if we found one */
    int live_folders;   /* folders outside the DELETED namespace */
};

static void free_userinfo(void *data)
{
    struct userinfo *u = (struct userinfo *)data;

    if (!u) return;
    free(u->userid);
    free(u->inboxid);
    free(u);
}

struct userrock {
    hash_table *users;
    struct audit_state *state;
};

static void collect_user_cb(const char *uniqueid, void *data, void *rock)
{
    struct userrock *urock = (struct userrock *)rock;
    struct audit_dbentry *entry = (struct audit_dbentry *)data;
    mbname_t *mbname;
    const char *userid;
    struct userinfo *u;

    if (!entry->dbname) return;

    mbname = mbname_from_intname(entry->dbname);
    userid = mbname_userid(mbname);

    /* shared mailboxes have no owning user, so there is no per-user
     * structure to check */
    if (!userid) goto done;

    u = hash_lookup(userid, urock->users);
    if (!u) {
        u = xzmalloc(sizeof(struct userinfo));
        u->userid = xstrdup(userid);
        hash_insert(userid, u, urock->users);
    }

    if (mbname_isdeleted(mbname)) goto done;

    u->live_folders++;

    /* the INBOX is the user's mailbox with no sub-boxes below it */
    if (!strarray_size(mbname_boxes(mbname)))
        if (!u->inboxid) u->inboxid = xstrdup(uniqueid);

  done:
    mbname_free(&mbname);
}

/* With no userlist we cannot know, so we assume the user belongs here.
 * That is the safe reading: it means we report structural damage but
 * never propose removing a user we have no evidence about. */
static int user_is_expected(struct audit_state *state, const char *userid)
{
    if (!state->config.userlist) return 1;
    return strarray_contains(state->config.userlist, userid);
}

static void check_user_cb(const char *userid, void *data, void *rock)
{
    struct userrock *urock = (struct userrock *)rock;
    struct userinfo *u = (struct userinfo *)data;
    struct audit_state *state = urock->state;
    struct audit_finding finding = AUDIT_FINDING_INITIALIZER;

    if (state->config.skipusers &&
        strarray_contains(state->config.skipusers, userid))
        return;

    finding.userid = userid;

    if (!u->inboxid) {
        /* folders entirely within the DELETED namespace are just a
         * deleted user's remains, not damage */
        if (u->live_folders) {
            if (user_is_expected(state, userid)) {
                /* unrecoverable in UUID space: needs a human */
                finding.code = "user-missing-inbox";
            }
            else {
                finding.code = "user-stale-folders";
            }
            audit_report(state, &finding);
        }
        return;
    }

    /* The user has an INBOX but the driver says they do not belong here.
     * Report only: removing a whole user rests entirely on external
     * truth, so that decision stays with the caller. */
    if (state->config.userlist &&
        !strarray_contains(state->config.userlist, userid)) {
        finding.code = "user-not-expected";
        finding.uniqueid = u->inboxid;
        audit_report(state, &finding);
    }
}

EXPORTED void audit_check_users(struct audit_keyspace *ks,
                                struct audit_state *state)
{
    hash_table users = HASH_TABLE_INITIALIZER;
    struct userrock urock = { &users, state };

    construct_hash_table(&users, 1024, 0);

    hash_enumerate(&ks->byid, collect_user_cb, &urock);
    hash_enumerate(&users, check_user_cb, &urock);

    free_hash_table(&users, free_userinfo);
}

/* ------------------------------------------------------------------ */
/* level 1: on-disk roots                                             */

struct namerock {
    const char *prefix;
    const char *want;       /* NULL for all */
    strarray_t *names;
};

/* Collect the names defined by options of one prefix.  Matched on an
 * exact prefix rather than a substring search, so that options merely
 * containing the word -- such as defaultpartition -- are not mistaken for
 * definitions, and "partition-" does not also match "metapartition-". */
static void collect_name_cb(const char *key, const char *value, void *rock)
{
    struct namerock *nrock = (struct namerock *)rock;
    size_t len = strlen(nrock->prefix);

    if (strncmp(key, nrock->prefix, len)) return;
    if (!key[len]) return;
    if (!value || !*value) return;

    /* "partition-x" must not be reached via the tail of
     * "metapartition-x"; config_foreachoverflowstring hands us whole
     * option names, so an exact prefix match is enough */
    if (nrock->want && strcmp(key + len, nrock->want)) return;

    if (strarray_contains(nrock->names, key + len)) return;

    strarray_append(nrock->names, key + len);
}

static void collect_names(const char *prefix, const char *want,
                          strarray_t *names)
{
    struct namerock nrock = { prefix, want, names };

    config_foreachoverflowstring(collect_name_cb, &nrock);
}

static void add_root(strarray_t *roots, const char *dir)
{
    if (!dir || !*dir) return;

    /* Deduplicate by disk path.  A site that has not configured a
     * metapartition gets the data partition back from
     * config_metapartitiondir()'s fallback, so the same path legitimately
     * arrives more than once; sweeping it twice would report every
     * mailbox on it as its own duplicate. */
    if (strarray_contains(roots, dir)) return;

    strarray_append(roots, dir);
}

EXPORTED void audit_collect_roots(const char *partition, int types,
                                  strarray_t *roots)
{
    strarray_t names = STRARRAY_INITIALIZER;
    int i;

    if (types & AUDIT_ROOT_SEARCH) {
        /* search tiers are named independently of mail partitions */
        strarray_t tiers = STRARRAY_INITIALIZER;

        collect_names("searchpartition-", NULL, &tiers);
        for (i = 0; i < strarray_size(&tiers); i++) {
            struct buf key = BUF_INITIALIZER;
            buf_printf(&key, "searchpartition-%s", strarray_nth(&tiers, i));
            add_root(roots, config_getoverflowstring(buf_cstring(&key), NULL));
            buf_free(&key);
        }

        strarray_fini(&tiers);
    }

    if (!(types & (AUDIT_ROOT_DATA | AUDIT_ROOT_META | AUDIT_ROOT_ARCHIVE)))
        return;

    collect_names("partition-", partition, &names);

    for (i = 0; i < strarray_size(&names); i++) {
        const char *name = strarray_nth(&names, i);

        /* Resolve through Cyrus's own accessors so that the fallbacks
         * match mboxname_metapath(): with no metapartition configured the
         * meta files live on the data partition, and auditing the
         * unconfigured location would report every mailbox as missing. */
        if (types & AUDIT_ROOT_DATA)
            add_root(roots, config_partitiondir(name));

        if (types & AUDIT_ROOT_META) {
            const char *dir = config_metapartitiondir(name);
            add_root(roots, dir ? dir : config_partitiondir(name));
        }

        if (types & AUDIT_ROOT_ARCHIVE) {
            const char *dir = config_archivepartitiondir(name);
            add_root(roots, dir ? dir : config_partitiondir(name));
        }
    }

    strarray_fini(&names);
}

/* ------------------------------------------------------------------ */
/* level 1: the UUID-layout scanner                                   */

/* A uniqueid shorter than this would hash to a path that is the PARENT of
 * many mailbox directories rather than a mailbox directory.  A mailbox
 * with uniqueid "0" existed in the wild; treating it as valid would mean
 * removing a whole slice of the store. */
#define AUDIT_MIN_UNIQUEID_LEN 3

static int all_lowerhex(const char *s, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)s[i])) return 0;
        if (isupper((unsigned char)s[i])) return 0;
    }

    return 1;
}

EXPORTED int audit_valid_uniqueid(const char *id)
{
    size_t len, i;
    int dashes = 0, lower = 0, upper = 0;

    if (!id) return 0;

    len = strlen(id);
    if (len < AUDIT_MIN_UNIQUEID_LEN) return 0;

    /* really old format: namehash + uidvalidity */
    if (len == 16) return all_lowerhex(id, len);

    /* non-libuuid random format */
    if (len == 24) {
        for (i = 0; i < len; i++) {
            if (islower((unsigned char)id[i])) continue;
            if (isdigit((unsigned char)id[i])) continue;
            return 0;
        }
        return 1;
    }

    /* uuid format, either builtin (lowercase) or imported (uppercase),
     * but never a mix of the two */
    if (len == 36) {
        for (i = 0; i < len; i++) {
            if (id[i] == '-') { dashes++; continue; }
            if (!isxdigit((unsigned char)id[i])) return 0;
            if (islower((unsigned char)id[i])) lower = 1;
            if (isupper((unsigned char)id[i])) upper = 1;
        }
        if (lower && upper) return 0;
        return dashes == 4;
    }

    return 0;
}

static int valid_hashchar(const char *name)
{
    return name[0] && !name[1] && isalnum((unsigned char)name[0]);
}

/* A mailbox directory holding an INBOX subdirectory is a known bogus
 * artifact.  The mailbox itself is still valid. */
static void check_bogus_inbox(const char *leaf, struct audit_state *state)
{
    struct buf path = BUF_INITIALIZER;
    struct stat sbuf;

    buf_printf(&path, "%s/INBOX", leaf);

    if (!stat(buf_cstring(&path), &sbuf) && S_ISDIR(sbuf.st_mode)) {
        struct audit_finding finding = AUDIT_FINDING_INITIALIZER;
        finding.code = "fs-bogus-inbox-dir";
        finding.path = buf_cstring(&path);
        audit_report(state, &finding);
    }

    buf_free(&path);
}

struct scandir {
    const char *root;
    strarray_t *found;
    struct audit_state *state;
};

static void scan_leaf_dir(struct scandir *sd, const char *dirpath,
                          char c0, char c1)
{
    DIR *dh = opendir(dirpath);
    struct dirent *de;

    if (!dh) return;

    while ((de = readdir(dh))) {
        struct buf leaf = BUF_INITIALIZER;
        struct audit_finding finding = AUDIT_FINDING_INITIALIZER;

        if (de->d_name[0] == '.') continue;

        buf_printf(&leaf, "%s/%s", dirpath, de->d_name);
        finding.path = buf_cstring(&leaf);

        if (!audit_valid_uniqueid(de->d_name)) {
            finding.code = "fs-invalid-uniqueid";
            audit_report(sd->state, &finding);
            buf_free(&leaf);
            continue;
        }

        /* mboxname_id_hash() places a mailbox under the first two
         * characters of its uniqueid; anywhere else and nothing will
         * ever look for it here */
        if (de->d_name[0] != c0 || de->d_name[1] != c1) {
            finding.code = "fs-misfiled-uniqueid";
            finding.uniqueid = de->d_name;
            audit_report(sd->state, &finding);
            buf_free(&leaf);
            continue;
        }

        strarray_append(sd->found, de->d_name);
        check_bogus_inbox(buf_cstring(&leaf), sd->state);

        buf_free(&leaf);
    }

    closedir(dh);
}

EXPORTED void audit_scan_uuid_root(const char *root, strarray_t *found,
                                   struct audit_state *state)
{
    struct scandir sd = { root, found, state };
    struct buf base = BUF_INITIALIZER;
    DIR *d0;
    struct dirent *e0;

    buf_printf(&base, "%s/uuid", root);

    /* A missing root is not a finding: a site may simply not have this
     * partition populated. */
    d0 = opendir(buf_cstring(&base));
    if (!d0) goto done;

    while ((e0 = readdir(d0))) {
        struct buf lvl1 = BUF_INITIALIZER;
        DIR *d1;
        struct dirent *e1;

        if (e0->d_name[0] == '.') continue;

        buf_printf(&lvl1, "%s/%s", buf_cstring(&base), e0->d_name);

        if (!valid_hashchar(e0->d_name)) {
            struct audit_finding finding = AUDIT_FINDING_INITIALIZER;
            finding.code = "fs-bad-hash-dir";
            finding.path = buf_cstring(&lvl1);
            audit_report(state, &finding);
            buf_free(&lvl1);
            continue;
        }

        d1 = opendir(buf_cstring(&lvl1));
        if (!d1) { buf_free(&lvl1); continue; }

        while ((e1 = readdir(d1))) {
            struct buf lvl2 = BUF_INITIALIZER;

            if (e1->d_name[0] == '.') continue;

            buf_printf(&lvl2, "%s/%s", buf_cstring(&lvl1), e1->d_name);

            if (!valid_hashchar(e1->d_name)) {
                struct audit_finding finding = AUDIT_FINDING_INITIALIZER;
                finding.code = "fs-bad-hash-dir";
                finding.path = buf_cstring(&lvl2);
                audit_report(state, &finding);
                buf_free(&lvl2);
                continue;
            }

            scan_leaf_dir(&sd, buf_cstring(&lvl2),
                          e0->d_name[0], e1->d_name[0]);

            buf_free(&lvl2);
        }

        closedir(d1);
        buf_free(&lvl1);
    }

    closedir(d0);

  done:
    buf_free(&base);
}

/* ------------------------------------------------------------------ */
/* removal, and the guards on it                                      */

EXPORTED int audit_path_is_young(const char *path)
{
    struct stat sbuf;

    /* already gone: nothing to protect */
    if (stat(path, &sbuf) < 0) return 0;

    return time(NULL) < sbuf.st_mtime + AUDIT_MIN_AGE;
}

EXPORTED void audit_remove_path(struct audit_state *state, const char *path)
{
    struct audit_finding finding = AUDIT_FINDING_INITIALIZER;

    /* a plain audit never touches anything */
    if (!state->config.do_delete) return;

    /* Anything this new may belong to an operation still in flight.  No
     * flag overrides this; tests backdate mtimes instead. */
    if (audit_path_is_young(path)) {
        finding.code = "skipped-too-young";
        finding.path = path;
        audit_report(state, &finding);
        return;
    }

    if (!state->config.really) {
        finding.code = "would-remove";
        finding.path = path;
        audit_report(state, &finding);
        return;
    }

    if (removedir(path)) {
        xsyslog(LOG_ERR, "audit: failed to remove", "path=<%s>", path);
        finding.code = "remove-failed";
        finding.path = path;
        audit_report(state, &finding);
    }
}

/* ------------------------------------------------------------------ */
/* level 1: db entries vs directories on disk                         */

/* The on-disk view, one set of uniqueids per kind of location. */
struct audit_fsview {
    hash_table meta;
    hash_table data;
    hash_table archive;
    hash_table search;
    hash_table user;
    hash_table sieve;
};

static void fsview_init(struct audit_fsview *fs)
{
    memset(fs, 0, sizeof(*fs));
    construct_hash_table(&fs->meta, 4096, 0);
    construct_hash_table(&fs->data, 4096, 0);
    construct_hash_table(&fs->archive, 4096, 0);
    construct_hash_table(&fs->search, 4096, 0);
    construct_hash_table(&fs->user, 4096, 0);
    construct_hash_table(&fs->sieve, 4096, 0);
}

static void fsview_fini(struct audit_fsview *fs)
{
    /* values are the directory paths, owned by the table */
    free_hash_table(&fs->meta, free);
    free_hash_table(&fs->data, free);
    free_hash_table(&fs->archive, free);
    free_hash_table(&fs->search, free);
    free_hash_table(&fs->user, free);
    free_hash_table(&fs->sieve, free);
}

/* Sweep every root of one kind into a set.  Hashed rather than kept as a
 * list: a large store has millions of mailboxes and every cross-check
 * below is a membership test. */
/* Record each uniqueid found under base, with the directory it was found
 * in as the value.  The layout is deterministic -- it is what
 * mboxname_id_hash() builds -- so the path is rebuilt rather than carried
 * back out of the scanner. */
static void collect_found(hash_table *set, const char *base,
                          const strarray_t *found)
{
    int i;

    for (i = 0; i < strarray_size(found); i++) {
        const char *id = strarray_nth(found, i);
        struct buf path = BUF_INITIALIZER;

        if (hash_lookup(id, set)) continue;

        buf_printf(&path, "%s/uuid/%c/%c/%s", base, id[0], id[1], id);
        hash_insert(id, buf_release(&path), set);

        buf_free(&path);
    }
}

static void sweep_into(hash_table *set, const char *partition, int type,
                       const char *suffix, struct audit_state *state)
{
    strarray_t roots = STRARRAY_INITIALIZER;
    int i;

    audit_collect_roots(partition, type, &roots);

    for (i = 0; i < strarray_size(&roots); i++) {
        strarray_t found = STRARRAY_INITIALIZER;
        struct buf base = BUF_INITIALIZER;

        buf_setcstr(&base, strarray_nth(&roots, i));
        if (suffix) buf_printf(&base, "/%s", suffix);

        audit_scan_uuid_root(buf_cstring(&base), &found, state);
        collect_found(set, buf_cstring(&base), &found);

        buf_free(&base);
        strarray_fini(&found);
    }

    strarray_fini(&roots);
}

/* Sweep a single directory that is not a partition, such as the
 * per-user and sieve trees under configdirectory. */
static void sweep_dir_into(hash_table *set, const char *dir,
                           struct audit_state *state)
{
    strarray_t found = STRARRAY_INITIALIZER;

    audit_scan_uuid_root(dir, &found, state);
    collect_found(set, dir, &found);

    strarray_fini(&found);
}

static void audit_sweep_filesystem(struct audit_fsview *fs,
                                   struct audit_state *state)
{
    const char *partition = state->config.partition;
    const char *confdir = config_getstring(IMAPOPT_CONFIGDIRECTORY);
    struct buf dir = BUF_INITIALIZER;

    /* Scan order is load-bearing.  Every cross-check below asks "does X
     * exist without Y", so sweeping spool and archive before meta -- and
     * all of them before the database -- means a mailbox created or
     * deleted mid-run can only produce a false orphan, which we then
     * re-verify, never a false "safe to delete".  Do not reorder. */
    sweep_into(&fs->data, partition, AUDIT_ROOT_DATA, NULL, state);
    sweep_into(&fs->archive, partition, AUDIT_ROOT_ARCHIVE, NULL, state);
    sweep_into(&fs->meta, partition, AUDIT_ROOT_META, NULL, state);

    /* search tiers keep their per-user trees below a "user" directory */
    sweep_into(&fs->search, partition, AUDIT_ROOT_SEARCH, "user", state);

    if (confdir) {
        buf_printf(&dir, "%s/user", confdir);
        sweep_dir_into(&fs->user, buf_cstring(&dir), state);

        buf_reset(&dir);
        buf_printf(&dir, "%s/sieve", confdir);
        sweep_dir_into(&fs->sieve, buf_cstring(&dir), state);
    }

    buf_free(&dir);
}

struct orphanrock {
    hash_table *against;
    const char *code;
    struct audit_state *state;
    int removable;      /* is the path this refers to ours to remove? */
};

static void orphan_cb(const char *uniqueid, void *data, void *rock)
{
    struct orphanrock *orock = (struct orphanrock *)rock;
    const char *path = (const char *)data;
    struct audit_finding finding = AUDIT_FINDING_INITIALIZER;

    if (hash_lookup(uniqueid, orock->against)) return;

    finding.code = orock->code;
    finding.uniqueid = uniqueid;
    finding.path = path;
    audit_report(orock->state, &finding);

    if (!orock->removable || !path) return;

    /* Re-verify before acting: the sweep produced a candidate list, not a
     * decision, and a mailbox may have been created since. */
    if (!mboxlist_lookup_by_uniqueid(uniqueid, NULL, NULL)) {
        struct audit_finding race = AUDIT_FINDING_INITIALIZER;
        race.code = "race-detected";
        race.uniqueid = uniqueid;
        audit_report(orock->state, &race);
        return;
    }

    audit_remove_path(orock->state, path);
}

/* Report each uniqueid in `set` that is absent from `against`. */
static void report_orphans(hash_table *set, hash_table *against,
                           const char *code, int removable,
                           struct audit_state *state)
{
    struct orphanrock rock = { against, code, state, removable };

    hash_enumerate(set, orphan_cb, &rock);
}

struct dbcheckrock {
    struct audit_fsview *fs;
    struct audit_state *state;
};

static void check_ondisk_cb(const char *uniqueid, void *data, void *rock)
{
    struct dbcheckrock *drock = (struct dbcheckrock *)rock;
    struct audit_dbentry *entry = (struct audit_dbentry *)data;
    struct audit_finding finding = AUDIT_FINDING_INITIALIZER;

    /* A legacy-layout mailbox lives in a name-hashed directory that the
     * UUID sweep never visits, so its absence here means nothing.  It is
     * already reported as db-entry-legacy-layout. */
    if (entry->mbtype & MBTYPE_LEGACY_DIRS) return;

    /* Remote and intermediate mailboxes have no data of their own. */
    if (entry->mbtype & (MBTYPE_REMOTE | MBTYPE_INTERMEDIATE)) return;

    if (hash_lookup(uniqueid, &drock->fs->meta)) return;

    finding.code = "db-entry-no-meta-dir";
    finding.uniqueid = uniqueid;
    finding.mboxname = entry->dbname;
    audit_report(drock->state, &finding);
}

static void audit_check_filesystem(struct audit_fsview *fs,
                                   struct audit_keyspace *ks,
                                   struct audit_state *state)
{
    struct dbcheckrock drock = { fs, state };

    /* A mailbox directory with no database entry.  Nothing else in Cyrus
     * looks inward from the filesystem, so this is the direction only the
     * audit covers. */
    report_orphans(&fs->meta, &ks->byid, "meta-dir-no-db-entry", 1, state);

    /* Spool and archive without meta.  When those partitions share a disk
     * path with meta -- which is common -- the sets are identical and
     * these can never fire. */
    report_orphans(&fs->data, &fs->meta, "spool-dir-no-meta-dir", 1, state);
    report_orphans(&fs->archive, &fs->meta, "archive-dir-no-meta-dir", 1,
                   state);

    /* Only whole-uniqueid orphans are reported for search: adjudicating
     * individual xapian directories of a live mailbox needs to know
     * whether a repack is in flight, and getting that wrong destroys a
     * live index. */
    report_orphans(&fs->search, &ks->byid, "search-dir-no-db-entry", 1, state);

    report_orphans(&fs->user, &ks->byid, "user-files-no-db-entry", 1, state);
    report_orphans(&fs->sieve, &ks->byid, "sieve-files-no-db-entry", 1, state);

    hash_enumerate(&ks->byid, check_ondisk_cb, &drock);
}

/* ------------------------------------------------------------------ */
/* driving the scan                                                   */

struct scanrock {
    struct audit_keyspace *ks;
    struct audit_state *state;
};

/* Is this entry one we should consider at all, given --partition and
 * --user?  A partition-scoped run must ignore entries elsewhere, or it
 * would report every mailbox on another partition as an orphan. */
static int entry_in_scope(struct audit_state *state, const mbentry_t *mbentry)
{
    if (state->config.partition) {
        if (strcmpsafe(mbentry->partition, state->config.partition))
            return 0;
    }

    if (state->config.userid) {
        mbname_t *mbname = mbname_from_intname(mbentry->name);
        int match = !strcmpsafe(mbname_userid(mbname), state->config.userid);
        mbname_free(&mbname);
        if (!match) return 0;
    }

    return 1;
}

static int scan_cb(void *rock, const char *rawkey, size_t rawkeylen,
                   const struct mboxlist_rawkey *key,
                   const mbentry_t *mbentry,
                   const char *data __attribute__((unused)),
                   size_t datalen __attribute__((unused)))
{
    struct scanrock *srock = (struct scanrock *)rock;
    struct audit_finding finding = AUDIT_FINDING_INITIALIZER;
    struct buf keybuf = BUF_INITIALIZER;
    int i;

    buf_init_ro(&keybuf, rawkey, rawkeylen);

    /* A value that will not parse cannot be interpreted or repaired, only
     * removed.  Reporting it is the whole reason this scan reads the
     * keyspace raw rather than through the lookup API. */
    if (key->type != MBOXLIST_KEY_UNKNOWN &&
        key->type != MBOXLIST_KEY_RACL && !mbentry) {
        finding.code = "db-unparseable-entry";
        finding.uniqueid = key->uniqueid;
        finding.mboxname = key->dbname;
        finding.userid = key->userid;
        audit_report(srock->state, &finding);
        queue_delete(srock->state, &keybuf);
        goto done;
    }

    switch (key->type) {
    case MBOXLIST_KEY_UNKNOWN:
        finding.code = "db-unknown-key";
        audit_report(srock->state, &finding);
        queue_delete(srock->state, &keybuf);
        break;

    case MBOXLIST_KEY_RACL:
        /* collected but not yet cross-checked; see the racl work */
        break;

    case MBOXLIST_KEY_JMAPID:
        audit_keyspace_add_jmapid(srock->ks, key->userid, key->jmapid,
                                  mbentry->uniqueid);
        break;

    case MBOXLIST_KEY_ID:
        if (!entry_in_scope(srock->state, mbentry)) break;

        audit_keyspace_add_id(srock->ks, key->uniqueid, mbentry->name,
                              mbentry->mbtype, mbentry->jmapid);

        /* the former names this record remembers */
        for (i = 0; i < ptrarray_size(&mbentry->name_history); i++) {
            const former_name_t *h = ptrarray_nth(&mbentry->name_history, i);
            audit_keyspace_add_history(srock->ks, key->uniqueid,
                                       h->name, h->mtime);
        }
        break;

    case MBOXLIST_KEY_NAME:
        if (!entry_in_scope(srock->state, mbentry)) break;

        /* A tombstone records a name that is gone.  It is not a live
         * mailbox, so it must not satisfy the I-without-N check. */
        if (mbentry->mbtype & MBTYPE_DELETED) {
            audit_keyspace_add_tombstone(srock->ks, mbentry->name,
                                         mbentry->uniqueid, mbentry->mtime);
            break;
        }

        audit_keyspace_add_name(srock->ks, mbentry->name, mbentry->uniqueid,
                                mbentry->mbtype, mbentry->jmapid);
        break;
    }

  done:
    buf_free(&keybuf);

    return 0;
}

/* ------------------------------------------------------------------ */
/* levels 2-4: message and meta damage                                */

/* Forward reconstruct's structured findings to the audit's emitter. */
static void reconstruct_finding_cb(void *rock,
                                   const struct reconstruct_finding *rf)
{
    struct audit_state *state = (struct audit_state *)rock;
    struct audit_finding finding = AUDIT_FINDING_INITIALIZER;
    mbname_t *mbname = NULL;

    finding.code = rf->code;
    finding.mboxname = rf->mboxname;
    finding.uniqueid = rf->uniqueid;
    finding.path = rf->path;
    finding.tier = rf->tier;
    finding.metaname = rf->metaname;
    finding.guid = rf->guid;
    finding.uid = rf->uid;
    finding.size = rf->size;
    finding.has_uid = rf->has_uid;
    finding.has_size = rf->has_size;

    /* a driver fetching a replacement needs the owner */
    if (rf->mboxname) {
        mbname = mbname_from_intname(rf->mboxname);
        finding.userid = mbname_userid(mbname);
    }

    audit_report(state, &finding);

    mbname_free(&mbname);
}

struct mbcheckrock {
    struct audit_state *state;
    int flags;
};

static int check_mailbox_cb(const mbentry_t *mbentry, void *rock)
{
    struct mbcheckrock *mrock = (struct mbcheckrock *)rock;
    struct reconstruct_report report = { reconstruct_finding_cb,
                                         mrock->state };
    mbname_t *mbname = NULL;
    const char *userid;
    int r;

    if (mbentry->mbtype & (MBTYPE_DELETED | MBTYPE_REMOTE |
                           MBTYPE_INTERMEDIATE))
        return 0;

    if (!entry_in_scope(mrock->state, mbentry)) return 0;

    mbname = mbname_from_intname(mbentry->name);
    userid = mbname_userid(mbname);

    if (userid && mrock->state->config.skipusers &&
        strarray_contains(mrock->state->config.skipusers, userid))
        goto done;

    /* Never RECONSTRUCT_MAKE_CHANGES.  Allowed to make changes it would
     * expunge the index record for a missing file, destroying the very
     * guid a driver needs to fetch the message back. */
    r = mailbox_reconstruct_report(mbentry->name, mrock->flags, NULL, &report);

    /* A mailbox that cannot even be opened is exactly what these levels
     * exist to surface, and reconstruct cannot report it through the
     * observer: with no changes allowed it stops at the failed open.
     * Deleted mid-run is the exception -- that is not damage. */
    if (r && r != IMAP_MAILBOX_NONEXISTENT) {
        struct audit_finding finding = AUDIT_FINDING_INITIALIZER;
        finding.code = "mailbox-unreadable";
        finding.mboxname = mbentry->name;
        finding.uniqueid = mbentry->uniqueid;
        finding.userid = userid;
        finding.detail = error_message(r);
        audit_report(mrock->state, &finding);
    }

  done:
    mbname_free(&mbname);

    return 0;
}

static void audit_check_mailboxes(struct audit_state *state)
{
    struct mbcheckrock mrock = { state, 0 };

    if (state->config.level >= 3) mrock.flags |= RECONSTRUCT_DO_STAT;
    if (state->config.level >= 4) mrock.flags |= RECONSTRUCT_ALWAYS_PARSE;

    if (state->config.userid) {
        mboxlist_usermboxtree(state->config.userid, NULL, check_mailbox_cb,
                              &mrock, 0);
    }
    else {
        mboxlist_allmbox("", check_mailbox_cb, &mrock, 0);
    }
}

EXPORTED int audit_run(struct audit_state *state)
{
    struct audit_keyspace ks;
    struct audit_fsview fs;
    struct scanrock srock = { &ks, state };
    struct txn *tid = NULL;
    int dofs = state->config.level >= 1;
    int r;

    audit_keyspace_init(&ks);
    if (dofs) fsview_init(&fs);

    /* Sweep the filesystem before reading the database.  See the comment
     * in audit_sweep_filesystem(): the order is what makes a mid-run
     * create or delete produce a false orphan rather than a false "safe
     * to delete". */
    if (dofs) audit_sweep_filesystem(&fs, state);

    /* One transaction for the whole scan: the cross-checks compare keys of
     * different types against each other, so they need a snapshot that is
     * consistent across all of them. */
    r = mboxlist_foreach_raw(scan_cb, &srock, &tid);

    /* read-only: nothing to commit */
    if (tid) mboxlist_abort(tid);

    if (!r) {
        audit_keyspace_check(&ks, state);
        audit_check_users(&ks, state);
        if (dofs) audit_check_filesystem(&fs, &ks, state);

        /* Only now, with the read transaction closed and every check
         * done, do we write anything. */
        r = audit_apply_repairs(state);
        if (!r) r = audit_apply_prunes(state);
        if (!r) r = audit_apply_jmapid_fixes(state);

        /* Levels 2-4 are report-only, so they run after the repairs and
         * take no part in them. */
        if (!r && state->config.level >= 2) audit_check_mailboxes(state);
    }

    if (dofs) fsview_fini(&fs);
    audit_keyspace_fini(&ks);

    return r;
}
