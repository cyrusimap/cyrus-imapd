/* audit.h - mailstore consistency auditing */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_AUDIT_H
#define INCLUDED_AUDIT_H

#include <stdint.h>

#include "hash.h"
#include "ptrarray.h"
#include "strarray.h"
#include "util.h"

/* Directories and files younger than this are never removed: they may
 * belong to an operation still in flight.  There is deliberately no flag
 * to override this; tests backdate mtimes instead.
 */
#define AUDIT_MIN_AGE 600

struct audit_finding {
    const char *code;       /* stable slug, eg "message-file-missing" */
    const char *uniqueid;
    const char *mboxname;   /* internal name */
    const char *userid;
    const char *path;
    const char *tier;       /* "spool" | "archive" */
    const char *metaname;   /* "index" | "header" | ... */
    const char *guid;       /* expected guid from the index record */
    const char *detail;     /* free text for the human renderer */
    uint32_t uid;
    uint64_t size;
    int has_uid;
    int has_size;
};

#define AUDIT_FINDING_INITIALIZER \
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0 }

struct audit_config {
    int level;              /* 0-4 */
    int json;
    int do_delete;
    int do_fix;
    int really;
    int prune_days;         /* 0 disables tombstone pruning */

    /* Whether the J keyspace is worth auditing at all.  jmapids are
     * derived from createdmodseq, and mboxname_domodseq() never consults
     * the per-user counter when conversations are disabled, so every
     * mailbox on such an install is created with modseq 1 and the same
     * jmapid.  The keyspace is degenerate there and JMAP is unusable
     * anyway, so there is nothing to check.  Set from the conversations
     * switch by the caller. */
    int check_jmapids;
    const char *partition;  /* NULL for all */
    const char *userid;     /* NULL for all */
    strarray_t *userlist;   /* NULL: every db user is treated as expected */
    strarray_t *skipusers;
    struct buf *out;        /* NULL means stdout */
};

#define AUDIT_CONFIG_INITIALIZER \
    { 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL }

struct audit_state;

/* The accumulated mailboxes.db keyspace, built during a single scan and
 * cross-checked afterwards.  Cross-checking cannot happen during the scan
 * because a key seen early may only be explicable by one seen late.
 */
struct audit_keyspace {
    hash_table byid;        /* uniqueid -> struct audit_dbentry */
    hash_table byname;      /* dbname   -> struct audit_dbentry */
    ptrarray_t jmapids;     /* struct audit_jmapid */
    ptrarray_t tombstones;  /* struct audit_tombstone */
    ptrarray_t history;     /* struct audit_history */
};

struct audit_dbentry {
    char *uniqueid;
    char *dbname;
    char *jmapid;
    uint32_t mbtype;
};

struct audit_jmapid {
    char *userid;
    char *jmapid;
    char *uniqueid;
};

/* A tombstone N record: a name the mailbox used to be known by. */
struct audit_tombstone {
    char *dbname;
    char *uniqueid;
    time_t mtime;
};

/* A name_history item hanging off an I record. */
struct audit_history {
    char *uniqueid;     /* the I record this item belongs to */
    char *dbname;       /* the former name */
    time_t mtime;
};

void audit_keyspace_init(struct audit_keyspace *ks);
void audit_keyspace_fini(struct audit_keyspace *ks);

void audit_keyspace_add_id(struct audit_keyspace *ks, const char *uniqueid,
                           const char *dbname, uint32_t mbtype,
                           const char *jmapid);
void audit_keyspace_add_name(struct audit_keyspace *ks, const char *dbname,
                             const char *uniqueid, uint32_t mbtype,
                             const char *jmapid);
void audit_keyspace_add_jmapid(struct audit_keyspace *ks, const char *userid,
                               const char *jmapid, const char *uniqueid);
void audit_keyspace_add_tombstone(struct audit_keyspace *ks,
                                  const char *dbname, const char *uniqueid,
                                  time_t mtime);
void audit_keyspace_add_history(struct audit_keyspace *ks,
                                const char *uniqueid, const char *dbname,
                                time_t mtime);

void audit_keyspace_check(struct audit_keyspace *ks,
                          struct audit_state *state);
void audit_check_users(struct audit_keyspace *ks, struct audit_state *state);

/* Which kind of partition option a root came from.  A single disk path
 * can serve several: it is common for meta and spool to share one. */
enum {
    AUDIT_ROOT_DATA    = (1<<0),    /* partition-* */
    AUDIT_ROOT_META    = (1<<1),    /* metapartition-* */
    AUDIT_ROOT_ARCHIVE = (1<<2),    /* archivepartition-* */
    AUDIT_ROOT_SEARCH  = (1<<3),    /* searchpartition-* */
    AUDIT_ROOT_ANY     = 0xf,
};

/* Collect the distinct on-disk roots to sweep, deduplicated by disk path.
 * Only roots whose kind is in the types mask are collected.  If partition
 * is non-NULL only that partition's roots are collected. */
void audit_collect_roots(const char *partition, int types, strarray_t *roots);

/* Is this a plausible mailbox uniqueid?  Rejects anything shorter than
 * three characters: a mailbox with uniqueid "0" existed in the wild, and
 * mboxname_id_hash() would place it at a path that is the PARENT of many
 * other mailbox directories. */
int audit_valid_uniqueid(const char *id);

/* Walk <root>/uuid/<c0>/<c1>/<uniqueid>, the inverse of
 * mboxname_id_hash(), appending each uniqueid found to *found and
 * reporting anything that does not belong. */
void audit_scan_uuid_root(const char *root, strarray_t *found,
                          struct audit_state *state);

/* Is this path too new to touch?  See AUDIT_MIN_AGE. */
int audit_path_is_young(const char *path);

/* Remove a path, subject to --delete, --really and the young-guard.
 * Does nothing at all unless --delete was given. */
void audit_remove_path(struct audit_state *state, const char *path);

/* Run the audit at the configured level.  Returns 0 on success; findings
 * are reported through the emitter and counted by audit_finding_count(). */
int audit_run(struct audit_state *state);

struct audit_state *audit_begin(const struct audit_config *config);
void audit_report(struct audit_state *state,
                  const struct audit_finding *finding);
unsigned audit_finding_count(const struct audit_state *state);
void audit_done(struct audit_state **statep);

#endif /* INCLUDED_AUDIT_H */
