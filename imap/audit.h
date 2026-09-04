/* audit.h - mailstore consistency auditing */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_AUDIT_H
#define INCLUDED_AUDIT_H

#include <stdbool.h>
#include <stdint.h>

#include "hash.h"
#include "ptrarray.h"
#include "strarray.h"
#include "util.h"

/**
 * @file audit.h
 *
 * Mailstore consistency auditing: the checks chk_cyrus runs, and the
 * repairs it can be asked to apply.
 */

/**
 * Directories and files younger than this are never removed: they may
 * belong to an operation still in flight.  There is deliberately no flag
 * to override this; tests backdate mtimes instead.
 */
#define AUDIT_MIN_AGE 600

/** One thing found wrong, as handed to the emitter */
struct audit_finding {
    const char *code;       /**< stable slug, eg "message-file-missing" */
    const char *uniqueid;
    const char *mboxname;   /**< internal name */
    const char *userid;
    const char *path;
    const char *tier;       /**< "spool" | "archive" */
    const char *metaname;   /**< "index" | "header" | ... */
    const char *guid;       /**< expected guid from the index record */
    const char *detail;     /**< free text for the human renderer */
    uint32_t uid;
    uint64_t size;
    bool has_uid;
    bool has_size;
};

#define AUDIT_FINDING_INITIALIZER \
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, false, false }

/** What to check, and what to do about it */
struct audit_config {
    int level;              /**< 0-4 */
    bool json;
    bool do_delete;
    bool do_fix;
    bool really;
    int prune_days;         /**< 0 disables tombstone pruning */

    /**
     * Whether the J keyspace is worth auditing at all.  With conversations
     * disabled every mailbox is created with modseq 1, so every jmapid is
     * the same and the keyspace is degenerate.  Set from the conversations
     * switch by the caller.
     */
    bool check_jmapids;
    const char *partition;  /**< NULL for all */
    const char *userid;     /**< NULL for all */
    strarray_t *userlist;   /**< NULL: every db user is treated as expected */
    strarray_t *skipusers;
    struct buf *out;        /**< NULL means stdout */
};

#define AUDIT_CONFIG_INITIALIZER \
    { 0, false, false, false, false, 0, false, NULL, NULL, NULL, NULL, NULL }

struct audit_state;

/**
 * The accumulated mailboxes.db keyspace, built during a single scan and
 * cross-checked afterwards.  Cross-checking cannot happen during the scan
 * because a key seen early may only be explicable by one seen late.
 */
struct audit_keyspace {
    hash_table byid;        /**< uniqueid -> struct audit_dbentry */
    hash_table byname;      /**< dbname   -> struct audit_dbentry */
    ptrarray_t jmapids;     /**< struct audit_jmapid */
    ptrarray_t tombstones;  /**< struct audit_tombstone */
    ptrarray_t history;     /**< struct audit_history */
};

/** An I or N record's mailbox */
struct audit_dbentry {
    char *uniqueid;
    char *dbname;
    char *jmapid;
    uint32_t mbtype;
};

/** A J record: a mailbox reachable by jmapid */
struct audit_jmapid {
    char *userid;
    char *jmapid;
    char *uniqueid;
};

/** A tombstone N record: a name the mailbox used to be known by */
struct audit_tombstone {
    char *dbname;
    char *uniqueid;
    time_t mtime;
};

/** A name_history item hanging off an I record */
struct audit_history {
    char *uniqueid;     /**< the I record this item belongs to */
    char *dbname;       /**< the former name */
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

/**
 * Cross-check an accumulated keyspace, reporting through @a state.
 *
 * @param ks the keyspace, complete
 * @param state the running audit
 */
void audit_keyspace_check(struct audit_keyspace *ks,
                          struct audit_state *state);

/**
 * Check each user the keyspace mentions against the configured user list.
 *
 * @param ks the keyspace, complete
 * @param state the running audit
 */
void audit_check_users(struct audit_keyspace *ks, struct audit_state *state);

/**
 * Which kind of partition option a root came from.  A single disk path
 * can serve several: it is common for meta and spool to share one.
 */
enum {
    AUDIT_ROOT_DATA    = (1<<0),    /**< partition-* */
    AUDIT_ROOT_META    = (1<<1),    /**< metapartition-* */
    AUDIT_ROOT_ARCHIVE = (1<<2),    /**< archivepartition-* */
    AUDIT_ROOT_SEARCH  = (1<<3),    /**< searchpartition-* */
    AUDIT_ROOT_ANY     = 0xf,
};

/**
 * Collect the distinct on-disk roots to sweep, deduplicated by disk path.
 *
 * @param partition only this partition's roots, or NULL for all
 * @param types mask of AUDIT_ROOT_* kinds to collect
 * @param[out] roots the paths found
 */
void audit_collect_roots(const char *partition, int types, strarray_t *roots);

/**
 * Is this a plausible mailbox uniqueid?  Rejects anything shorter than
 * three characters: a mailbox with uniqueid "0" existed in the wild, and
 * mboxname_id_hash() would place it at a path that is the PARENT of many
 * other mailbox directories.
 *
 * @param id the candidate
 * @return true if it could be a uniqueid
 */
bool audit_valid_uniqueid(const char *id);

/**
 * Walk <root>/uuid/<c0>/<c1>/<uniqueid>, the inverse of
 * mboxname_id_hash(), reporting anything that does not belong.
 *
 * @param root the on-disk root to walk
 * @param[out] found each uniqueid seen, appended
 * @param state the running audit
 */
void audit_scan_uuid_root(const char *root, strarray_t *found,
                          struct audit_state *state);

/**
 * Is this path too new to touch?  See AUDIT_MIN_AGE.
 *
 * @param path the path to stat
 * @return true if it must be left alone
 */
bool audit_path_is_young(const char *path);

/**
 * Remove a path, subject to --delete, --really and the young-guard.  Does
 * nothing at all unless --delete was given.
 *
 * @param state the running audit
 * @param path the path to remove
 */
void audit_remove_path(struct audit_state *state, const char *path);

/**
 * Run the audit at the configured level.  Findings are reported through
 * the emitter and counted by audit_finding_count().
 *
 * @param state the running audit
 * @return 0 on success
 */
int audit_run(struct audit_state *state);

/**
 * Begin an audit.
 *
 * @param config what to check and what to repair; copied
 * @return the running audit, to be freed with audit_done()
 */
struct audit_state *audit_begin(const struct audit_config *config);

/**
 * Emit one finding.
 *
 * @param state the running audit
 * @param finding what was found; nothing is retained
 */
void audit_report(struct audit_state *state,
                  const struct audit_finding *finding);

/**
 * @param state the running audit
 * @return how many findings have been emitted
 */
unsigned audit_finding_count(const struct audit_state *state);

/**
 * Finish an audit, applying any queued repairs.
 *
 * @param[in,out] statep the running audit, set to NULL
 */
void audit_done(struct audit_state **statep);

#endif /* INCLUDED_AUDIT_H */
