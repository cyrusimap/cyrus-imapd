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
    const char *partition;  /* NULL for all */
    const char *userid;     /* NULL for all */
    strarray_t *userlist;   /* NULL: every db user is treated as expected */
    strarray_t *skipusers;
    struct buf *out;        /* NULL means stdout */
};

#define AUDIT_CONFIG_INITIALIZER \
    { 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL }

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

struct audit_state *audit_begin(const struct audit_config *config);
void audit_report(struct audit_state *state,
                  const struct audit_finding *finding);
unsigned audit_finding_count(const struct audit_state *state);
void audit_done(struct audit_state **statep);

#endif /* INCLUDED_AUDIT_H */
