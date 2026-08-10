/* audit.c - mailstore consistency auditing */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <jansson.h>

#include "audit.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "xmalloc.h"

struct audit_state {
    struct audit_config config;
    struct buf *out;        /* borrowed from config, or NULL for stdout */
    unsigned count;
};

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

    free(*statep);
    *statep = NULL;
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

/* Does a J key exist pointing at this entry with the entry's own jmapid? */
static int find_jmapid_key(const struct audit_keyspace *ks,
                           const struct audit_dbentry *entry)
{
    int i;

    for (i = 0; i < ptrarray_size(&ks->jmapids); i++) {
        const struct audit_jmapid *j = ptrarray_nth(&ks->jmapids, i);
        if (strcmpsafe(j->uniqueid, entry->uniqueid)) continue;
        if (strcmpsafe(j->jmapid, entry->jmapid)) continue;
        return 1;
    }

    return 0;
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
    }

    if (!entry->jmapid) {
        finding.code = "db-missing-j-property";
        finding.detail = "run ctl_mboxlist -k";
        audit_report(crock->state, &finding);
    }
    else if (!find_jmapid_key(crock->ks, entry)) {
        finding.code = "db-missing-j-key";
        finding.detail = "run ctl_mboxlist -k";
        audit_report(crock->state, &finding);
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

    for (i = 0; i < ptrarray_size(&ks->jmapids); i++) {
        struct audit_jmapid *j = ptrarray_nth(&ks->jmapids, i);
        struct audit_dbentry *entry = hash_lookup(j->uniqueid, &ks->byid);
        struct audit_finding finding = AUDIT_FINDING_INITIALIZER;

        finding.uniqueid = j->uniqueid;
        finding.userid = j->userid;

        if (!entry) {
            finding.code = "db-bogus-jmapid";
            audit_report(state, &finding);
            continue;
        }

        /* a J key that disagrees with the entry it names is worse than a
         * missing one: a lookup by jmapid returns the wrong mailbox */
        if (strcmpsafe(entry->jmapid, j->jmapid)) {
            finding.code = "db-bad-jmapid";
            finding.mboxname = entry->dbname;
            audit_report(state, &finding);
        }
    }

    /* Every tombstone must be explained: either the I record still carries
     * the tombstoned name (the mailbox was deleted), or one of its history
     * items does (the mailbox was renamed away from it). */
    for (i = 0; i < ptrarray_size(&ks->tombstones); i++) {
        struct audit_tombstone *t = ptrarray_nth(&ks->tombstones, i);
        struct audit_dbentry *entry = hash_lookup(t->uniqueid, &ks->byid);
        struct audit_finding finding = AUDIT_FINDING_INITIALIZER;

        /* no I record at all: an orphan tombstone.  Prunable, but not an
         * inconsistency -- there is nothing left for it to disagree with */
        if (!entry) continue;

        if (!strcmpsafe(entry->dbname, t->dbname)) continue;    /* deleted */
        if (find_history_item(ks, t->uniqueid, t->dbname)) continue; /* renamed */

        finding.code = "db-tombstone-no-history";
        finding.uniqueid = t->uniqueid;
        finding.mboxname = t->dbname;
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
