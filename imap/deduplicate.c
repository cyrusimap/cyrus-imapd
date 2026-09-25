/* deduplicate.c - hardlink message files that share a GUID (content hash) */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/*  Two-step utility:
 *   step 1 (-B <db>): scan mailbox indexes and build a database keyed
 *                     by message GUID, with each value a list of fixed
 *                     8-byte (uid, mailbox-id) records. Mailbox ids are
 *                     new identifiers assigned to each mailbox from their
 *                     uniqueid, so identities are stored once and survive
 *                     rename / delayed-delete. These can be recovered from
 *                     the dictionary saved in the metadata of the database.
 *   step 2 (-L <db>): read such a database, resolve each (uid, mailbox-id)
 *                     to a live mailbox under a write-lock to derive the
 *                     canonical spool path, then hardlink together every
 *                     set of files that share a GUID and live on the same
 *                     filesystem, collapsing them onto a single inode.
 *
 * Auxiliary modes: -P prunes singleton GUIDs, -Z dumps the database in
 * human-readable form (the binary records are otherwise opaque). */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include "append.h"
#include "cyrusdb.h"
#include "dynarray.h"
#include "global.h"
#include "mailbox.h"
#include "message.h"
#include "message_guid.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "strarray.h"
#include "util.h"
#include "xmalloc.h"
#include "xunlink.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* default cyrusdb backend for the skiplist (override with -D) */
#define DEDUP_DB_BACKEND "twoskip"

/* commit the build-mode transaction after this many fresh records, so
 * a long scan does not pile up unbounded twoskip state in memory */
#define DEDUP_COMMIT_EVERY 1000

/* Reserved key namespace. Every metadata key starts with '!' (0x21),
 * which sorts before any 40-char hex GUID key (alphanumeric > !).
 *
 *   !count               : decimal count of mailbox ids assigned at build
 *   !deduplicate_version : format version marker (this constant)
 *   !m<id>               : mailbox dictionary, decimal id -> uniqueid
 *   <40-hex GUID>        : one or more fixed-size records (see below)
 *
 * The link / dump / prune phases load and validate all metadata up front
 * with a single foreach over the DEDUP_META_PREFIX keyspace, reading !count
 * to preallocate the dictionary before any operation begins. These keys
 * are required for the database format to be valid. */
#define DEDUP_DB_VERSION     "1"
/* Most comments already refer to '!' but its modular just in case */
#define DEDUP_META_PREFIX    "!"
#define DEDUP_DB_VERSION_KEY DEDUP_META_PREFIX "deduplicate_version"
#define DEDUP_MBOX_PREFIX    DEDUP_META_PREFIX "m"
#define DEDUP_COUNT_KEY      DEDUP_META_PREFIX "count"

/* Each GUID value is a concatenation of fixed-size records. A record is
 * two big-endian uint32 fields with no separator:
 *   <uid (4B)><mailbox id (4B)>
 * The mailbox id indexes the !m<id> dictionary, which resolves to the
 * mailbox uniqueid (stable across rename and delayed-delete), which the
 * link phase resolves to a live mailbox via mboxlist_lookup_by_uniqueid().
 * Storing an interned 4-byte id rather than the uniqueid string keeps each
 * record at 8 fixed bytes. */
 /* XXX is there a future where we would be interested in 64bit mailbox ids? */
#define DEDUP_RECORD_SIZE    8

/* current namespace */
static struct namespace dedup_namespace;

/* program name */
static const char *progname = NULL;

/* cyrusdb backend used for the skiplist (-D) */
static const char *db_backend = DEDUP_DB_BACKEND;

/* restrict the build scan to a single partition (-p). NULL means all */
static const char *build_partition = NULL;

/* output options */
/* -v (repeatable). Level 0 (the default) is quiet: no per-record (build)
 * or per-link (link/prune) chatter, just errors and any -c / -d summary.
 * Level 1 enables that chatter. In build mode, levels 2 and 3 add more
 * detail per record (mailbox+uid, then dev:ino+nlink). */
static int verbosity = 0;
static int show_savings = 0;            /* -c */
static int dry_run = 0;                 /* -d */
static int verify = 0;                  /* -V */
static int skip_deleted = 0;            /* -x */
/* Expunged but not yet unlinked records still have spool files on disk,
 * so they are dedup candidates by default. -e drops them. Unlinked
 * records have no file to link and are always skipped. */
static unsigned iter_flags = ITER_SKIP_UNLINKED;
static enum dedup_mode {
    NO_MODE,
    BAD_MODE, /* duplicate flags */
    BUILD_MODE,
    DUMP_MODE,
    PRUNE_MODE,
    LINK_MODE
} dedup_mode = NO_MODE;
static const char *dedup_fname = NULL;

/* build-mode database handle */
static struct db *dedup_db = NULL;
static struct txn *dedup_tid = NULL;
static unsigned dedup_uncommitted = 0;  /* records since last commit */

/* build-mode mailbox id counter. Each mailbox visited during the scan is
 * assigned the next id and written to the !m<id> dictionary, and the
 * per-record value then carries that 4-byte id instead of the uniqueid string.
 * Overlapping patterns will produce new ids pointing to the same mailbox. */
static uint32_t mbox_id = 0;

/* running total of bytes reclaimed by hardlinking (link mode) */
static off_t bytes_saved = 0;

/* running total of inodes freed by hardlinking (link mode): every
 * distinct inode whose last remaining link was collapsed away */
static unsigned long inodes_freed = 0;

/* entries that could not be relinked for reasons other than benign
 * staleness since build (link mode) */
static unsigned link_failures = 0;


/* ==========================================================================
 * Mailbox dictionary and shared metadata load / validation
 *
 * The mailbox dictionary maps a mailbox id to its uniqueid string. It is a
 * single global instance (mbox_dict), and its representation is private to
 * this section, touched only through dict_init() / dict_fini() / dict_size() /
 * dict_nth(), so no strarray call is made outside these functions. It is
 * populated and validated up front by dict_init() before any record is
 * processed, shared by the link, dump and prune phases.
 * ========================================================================== */

/* Opaque mailbox dictionary. The underlying storage is private to the
 * dict_* functions below. Slot id holds the uniqueid string, or NULL if
 * that id was never written (e.g. a mailbox skipped at build for a missing
 * uniqueid). dict_init() rejects such gaps before returning. */
typedef struct dedup_dict dedup_dict;
struct dedup_dict {
    strarray_t ids;     /* indexed by mailbox id: ids[id] -> uniqueid */
};

/* the single mailbox dictionary, shared by the read phases. Must be 
 * populated with dict_init() and cleared with dict_fini() */
static dedup_dict mbox_dict;

/* Refuse to interpret a DB whose format we do not recognise.
 * Returns 0 on success, or an EX_* code the caller propagates. */
static int verify_db_version(void)
{
    const char *vdata = NULL;
    size_t vdatalen = 0;
    int r = cyrusdb_fetch(dedup_db,
                          DEDUP_DB_VERSION_KEY,
                          strlen(DEDUP_DB_VERSION_KEY),
                          &vdata, &vdatalen, NULL);
    if (r) {
        fprintf(stderr,
                "%s: missing version marker, not a deduplicate database\n",
                dedup_fname);
        return EX_DATAERR;
    }
    if (vdatalen != strlen(DEDUP_DB_VERSION) ||
        memcmp(vdata, DEDUP_DB_VERSION, vdatalen) != 0) {
        fprintf(stderr,
                "%s: unsupported version '%.*s' (expected '%s')\n",
                dedup_fname, (int) vdatalen, vdata, DEDUP_DB_VERSION);
        return EX_DATAERR;
    }
    return 0;
}

/* Read the mandatory !count metadata: the number of mailbox ids the build
 * assigned. Used to preallocate the dictionary before the foreach scan.
 * Returns 0 and *countp on success, or an EX_* code the caller propagates. */
static int fetch_mbox_count(uint32_t *countp)
{
    const char *data = NULL;
    size_t datalen = 0;
    char buf[16];
    char *endptr = NULL;
    unsigned long c;

    int r = cyrusdb_fetch(dedup_db,
                          DEDUP_COUNT_KEY, strlen(DEDUP_COUNT_KEY),
                          &data, &datalen, NULL);
    if (r || datalen == 0 || datalen >= sizeof(buf)) {
        fprintf(stderr, "%s: missing or malformed %s key\n",
                dedup_fname, DEDUP_COUNT_KEY);
        return EX_DATAERR;
    }

    memcpy(buf, data, datalen);
    buf[datalen] = '\0';
    c = strtoul(buf, &endptr, 10);
    if (endptr == buf || *endptr != '\0' ||
        c > (unsigned long) INT_MAX) {
        fprintf(stderr, "%s: malformed %s value '%s'\n",
                dedup_fname, DEDUP_COUNT_KEY, buf);
        return EX_DATAERR;
    }

    *countp = (uint32_t) c;
    return 0;
}

/* Fill the dictionary from !m<id> keys and validate every metadata key.
 * !count and !version should be already read. Anything else under '!' is
 * corruption, which aborts the utility. The dictionary should be preallocated
 * to !count and its size is the id bound. */
static int dict_init_cb(void *rock __attribute__((unused)),
                        const char *key, size_t keylen,
                        const char *data, size_t datalen)
{
    size_t pfx = strlen(DEDUP_MBOX_PREFIX);

    signals_poll();

    /* !m<id>: populate the uniqueid at internal id. */
    if (keylen > pfx && memcmp(key, DEDUP_MBOX_PREFIX, pfx) == 0) {
        char buf[16];
        size_t n = keylen - pfx;
        char *endptr = NULL;
        unsigned long id;

        if (n < sizeof(buf)) {
            memcpy(buf, key + pfx, n);
            buf[n] = '\0';
            id = strtoul(buf, &endptr, 10);
            if (endptr != buf && *endptr == '\0' &&
                id < (uint32_t) strarray_size(&mbox_dict.ids)) {
                strarray_setm(&mbox_dict.ids, (int) id,
                              xstrndup(data, datalen));
                return 0;
            }
        }
        /* malformed !m<id>, or an id past the preallocated size (the
         * dictionary and !count disagree): fall through to the
         * corruption path */
    }

    /* !version and !count were already validated by dict_init() */
    if ((keylen == strlen(DEDUP_DB_VERSION_KEY) &&
         memcmp(key, DEDUP_DB_VERSION_KEY, keylen) == 0) ||
        (keylen == strlen(DEDUP_COUNT_KEY) &&
         memcmp(key, DEDUP_COUNT_KEY, keylen) == 0))
        return 0;

    fprintf(stderr, "unexpected metadata key %.*s\n", (int) keylen, key);
    return CYRUSDB_INTERNAL;
}

/* Release the dictionary, leaving it empty and reusable. */
static void dict_fini(void)
{
    strarray_fini(&mbox_dict.ids);
}

/* Number of mailbox ids in the dictionary (ids run [0, dict_size)). */
static int dict_size(void)
{
    return strarray_size(&mbox_dict.ids);
}

/* Resolve a mailbox id to its uniqueid, or NULL if out of range. */
static const char *dict_nth(uint32_t id)
{
    return strarray_nth(&mbox_dict.ids, (int) id);
}

/* Init the global dict struct and validate dedup db */
static int dict_init(void)
{
    uint32_t count;
    int r, i;

    if ((r = verify_db_version())) return r;
    if ((r = fetch_mbox_count(&count))) return r;

    /* Preallocate the dict */
    strarray_truncate(&mbox_dict.ids, (int) count);

    r = cyrusdb_foreach(dedup_db,
                        DEDUP_META_PREFIX, strlen(DEDUP_META_PREFIX),
                        NULL, dict_init_cb, NULL, NULL);
    if (r) {
        fprintf(stderr, "%s: dictionary load failed: %s\n",
                dedup_fname, cyrusdb_strerror(r));
        dict_fini();
        return EX_DATAERR;
    }

    /* Dict is dense, make sure everything is populated */
    for (i = 0; i < dict_size(); i++) {
        if (!dict_nth(i)) {
            fprintf(stderr, "%s: dictionary missing mailbox id %d\n",
                    dedup_fname, i);
            dict_fini();
            return EX_DATAERR;
        }
    }

    return 0;
}

/* Read one big-endian uint32 record field at an arbitrary (possibly
 * unaligned) offset into a DB-mapped value. */
static uint32_t record_ntohl(const char *p)
{
    bit32 v;

    memcpy(&v, p, sizeof(v));
    return ntohl(v);
}


/* ==========================================================================
 * Build mode (-B): scan mailbox indexes and record every message file
 * ========================================================================== */

/* one (uid, guid) pair captured from an index record while the mailbox
 * is locked, so the cyrusdb work in record_file() can happen afterward
 * with no lock held */
struct pending_record {
    struct message_guid guid;
    uint32_t uid;
};

/*`
 * Record one (uid, mailbox-id) pair under its GUID in the db.
 * The mailbox id indexes the !m<id> dictionary written by build_cb.
 * If a build picks up two index records that are already hardlinked,
 * we record both pairs, and the link phase rediscovers the shared inode
 * via stat and skips the redundant link.
 */
static int record_file(const struct message_guid *guid, uint32_t uid,
                       uint32_t mboxid)
{
    const char *key = message_guid_encode(guid);
    size_t keylen = strlen(key);
    const char *data = NULL;
    size_t datalen = 0;
    struct buf val = BUF_INITIALIZER;
    int r;

    r = cyrusdb_fetch(dedup_db, key, keylen, &data, &datalen, &dedup_tid);
    if (r && r != CYRUSDB_NOTFOUND) {
        fprintf(stderr, "fetch %s: %s\n", key, cyrusdb_strerror(r));
        return r;
    }
    if (!r) buf_setmap(&val, data, datalen);

    /* Append one fixed DEDUP_RECORD_SIZE record: <uid (4B)><mboxid (4B)>,
     * both network byte order, no separator. */
    buf_appendbit32(&val, uid);
    buf_appendbit32(&val, mboxid);

    r = cyrusdb_store(dedup_db, key, keylen,
                      buf_base(&val), buf_len(&val), &dedup_tid);
    buf_free(&val);
    if (r) {
        fprintf(stderr, "store %s: %s\n", key, cyrusdb_strerror(r));
        return r;
    }

    if (++dedup_uncommitted >= DEDUP_COMMIT_EVERY && dedup_tid) {
        /* periodic commit to avoid constant writes */
        r = cyrusdb_commit(dedup_db, dedup_tid);
        dedup_tid = NULL;
        dedup_uncommitted = 0;
        if (r) {
            /* We lost the whole batch */
            fatal("deduplicate: build commit failed, aborting scan",
                  EX_TEMPFAIL);
            /* NOTREACHED */
        }
    }

    return 0;
}

/* mboxlist_findall() callback: traverse a mailbox index and record every
 * message file in the dedup db. */
static int build_cb(struct findall_data *data, void *rock)
{
    int r = 0;
    struct mailbox *mailbox = NULL;
    int *count = (int *) rock;

    /* Don't want partial matches */
    if (!data) return 0;
    if (!data->is_exactmatch) return 0;

    /* No spool entries */
    if (data->mbentry->mbtype &
        (MBTYPE_DELETED | MBTYPE_INTERMEDIATE | MBTYPE_REMOTE))
        return 0;

    /* restrict the scan to a single partition (-p) */
    if (build_partition && strcmpsafe(build_partition, data->mbentry->partition))
        return 0;

    /* skip the delayed-delete hierarchy (DELETED.*)? */
    if (skip_deleted && mbname_isdeleted(data->mbname))
        return 0;

    signals_poll();

    const char *extname = mbname_extname(data->mbname, &dedup_namespace, "cyrus");
    const char *name = mbname_intname(data->mbname);

    r = mailbox_open_irl(name, &mailbox);
    if (r) {
        /* log and keep going so one broken mailbox does not abort the whole scan */
        fprintf(stderr, "%s: %s\n", extname, error_message(r));
        return 0;
    }

    /* XXX maybe add a check for version? GUIDs were introduced a while back though */

    const char *uniqueid = mailbox_uniqueid(mailbox);
    if (!uniqueid) { /* Avoid corruption */
        fprintf(stderr, "%s: no uniqueid (reconstruct it?), skipping\n", extname);
        mailbox_close(&mailbox);
        return 0;
    }

    /* Assign this mailbox the next dictionary id and persist
     * !m<id> -> uniqueid, so the link/dump phases can resolve records
     * back to a live mailbox. The uniqueid is also stable across 
     * rename and delayed-delete.
     *
     * Cap the id space at INT_MAX: the link/dump dictionary is a strarray,
     * which is indexed by signed int. Overflowing it is not a runtime 
     * condition we can recover from, so fail the build outright rather 
     * than write records we can't read.
     *
     * This is written in 2026 where ~80GB of ram for a dict is a bit much, if you see
     * this in 2036 and ram is cheaper maybe we should remake this tool :P */
    if (mbox_id >= (uint32_t) INT_MAX)
        fatal("mailbox id space exhausted (exceeds INT_MAX)", EX_SOFTWARE);

    /* Store the translation in the dict */
    uint32_t id = mbox_id++;
    char mkey[32];
    int mn = snprintf(mkey, sizeof(mkey), DEDUP_MBOX_PREFIX "%u", id);
    r = cyrusdb_store(dedup_db, mkey, mn,
                      uniqueid, strlen(uniqueid), &dedup_tid);
    if (r) {
        /* dictionary must be concrete, we can't ignore failures here */
        fprintf(stderr, "store %s: %s\n", mkey, cyrusdb_strerror(r));
        mailbox_close(&mailbox);
        return IMAP_IOERROR;
    }

    /* Pass 1: walk the index under the read lock, capturing just the
     * (uid, guid) pairs we need. mailbox_iter_step() reads lazily off
     * the locked mailbox's mapped index, so it cannot be interleaved
     * with the cyrusdb work below, which has its own commit latency
     * and must not hold this mailbox's lock while it runs. */
    struct dynarray pending = DYNARRAY_INITIALIZER(sizeof(struct pending_record));

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, iter_flags);
    const message_t *msg;
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        struct pending_record p = { record->guid, record->uid };

        dynarray_append(&pending, &p);

        /* Print information about the records (mostly for debugging),
         * one line of increasingly more detail per -v level:
         *   1: guid
         *   2: + mailbox name, uid
         *   3: + dev:ino, nlink (needs a stat() of the spool file) */
        if (verbosity > 0) {
            struct stat sbuf;
            int have_stat = 0;

            if (verbosity >= 3) {
                const char *fname = mailbox_record_fname(mailbox, record);
                have_stat = (stat(fname, &sbuf) == 0);
                if (!have_stat)
                    fprintf(stderr, "%s: cannot stat %s: %s\n",
                            extname, fname, strerror(errno));
            }

            if (verbosity >= 2)
                printf("%s %u ", extname, record->uid);
            /* (st_dev, st_ino) together uniquely identify a file
             * even when mailboxes span multiple filesystems */
            if (verbosity >= 3 && have_stat)
                printf("%llu:%llu %llu ",
                       (unsigned long long) sbuf.st_dev,
                       (unsigned long long) sbuf.st_ino,
                       (unsigned long long) sbuf.st_nlink);
            printf("%s\n", message_guid_encode(&record->guid));
        }
    }
    mailbox_iter_done(&iter);
    mailbox_close(&mailbox);

    /* Pass 2: record each buffered pair now that the mailbox is
     * unlocked. */
    int i, npending = dynarray_size(&pending);
    for (i = 0; i < npending; i++) {
        struct pending_record *p = dynarray_nth(&pending, i);

        if (record_file(&p->guid, p->uid, id)) {
            dynarray_fini(&pending);
            return IMAP_IOERROR;
        }
    }
    dynarray_fini(&pending);

    if (count) (*count)++;

    return 0;
}

/* Traverse user patterns and store all relevant records + dict */
static int do_build(int argc, char **argv, int idx)
{
    char cbuf[16];
    int count = 0;
    int i, r, cn;

    /* Stamp the DB with current format version */
    r = cyrusdb_store(dedup_db,
                      DEDUP_DB_VERSION_KEY, strlen(DEDUP_DB_VERSION_KEY),
                      DEDUP_DB_VERSION, strlen(DEDUP_DB_VERSION),
                      &dedup_tid);
    if (r) {
        fprintf(stderr, "store version: %s\n", cyrusdb_strerror(r));
        return EX_TEMPFAIL;
    }

    int err = 0;

    /* No user pattern */
    if (idx == argc) {
        r = mboxlist_findall(&dedup_namespace, "*", 1, 0, 0,
                             &build_cb, &count);
        if (r) {
            fprintf(stderr, "*: traversal failed: %s\n", error_message(r));
            err = r;
        }
    }

    /* User specified patterns */
    for (i = idx; i < argc; i++) { /* won't run without extra args */
        r = mboxlist_findall(&dedup_namespace, argv[i], 1, 0, 0,
                             &build_cb, &count);
        if (r) {
            fprintf(stderr, "%s: traversal failed: %s\n",
                    argv[i], error_message(r));
            err = r;
        }
    }

    /* a partial database silently missing mailboxes is worse than a
     * retry, so any failed traversal fails the whole build */
    if (err) return EX_TEMPFAIL;

    if (!count) {
        fprintf(stderr, "No matching mailboxes found\n");
        return EX_NOUSER;
    }

    /* Save the dictionary size for later phases */
    cn = snprintf(cbuf, sizeof(cbuf), "%u", mbox_id);
    r = cyrusdb_store(dedup_db, DEDUP_COUNT_KEY, strlen(DEDUP_COUNT_KEY),
                      cbuf, cn, &dedup_tid);
    if (r) {
        fprintf(stderr, "store count: %s\n", cyrusdb_strerror(r));
        return EX_TEMPFAIL;
    }

    return 0;
}


/* ==========================================================================
 * Dump mode (-Z): print the database in human-readable form
 * ========================================================================== */

/* cyrusdb_foreach callback for dump mode: print one GUID record per call in
 * human-readable form, resolving each record's mailbox id to its uniqueid
 * via the preloaded dictionary. Metadata was printed as a header by
 * do_dump() and is skipped here. */
static int dump_cb(void *rock __attribute__((unused)),
                   const char *key, size_t keylen,
                   const char *data, size_t datalen)
{
    const char *p, *end;

    signals_poll();

    if (keylen > 0 && key[0] == DEDUP_META_PREFIX[0]) return 0;

    /* every non-metadata key is a 40-char hex GUID */
    if (keylen != 2 * MESSAGE_GUID_SIZE) {
        fprintf(stderr, "unexpected record key %.*s\n", (int) keylen, key);
        return CYRUSDB_INTERNAL;
    }

    /* GUID record: print the guid, then one line per (uid, mailbox id) */
    printf("%.*s:\n", (int) keylen, key);
    for (p = data, end = data + datalen;
         p + DEDUP_RECORD_SIZE <= end;
         p += DEDUP_RECORD_SIZE) {
        uint32_t uid = record_ntohl(p);
        uint32_t mboxid = record_ntohl(p + 4);
        const char *uniqueid = dict_nth(mboxid);
        if (!uniqueid) {
            fprintf(stderr, "invalid mid found %u\n", mboxid);
            return CYRUSDB_INTERNAL;
        }
        printf("-> uid=%u mailbox=%u (%s)\n", uid, mboxid, uniqueid);
    }
    if (p != end) {
        fprintf(stderr, "  (%zu trailing bytes)\n", (size_t) (end - p));
        return CYRUSDB_INTERNAL;
    }

    return 0;
}

/* Dump phase entry point. Loads and validates the dictionary, prints it
 * (plus version and count) as a header, then walks the GUID records. The
 * binary record format is otherwise opaque to cyr_dbtool. */
static int do_dump(void)
{
    int r, i;

    if ((r = dict_init())) return r;

    /* header from the loaded metadata. The record scan below skips it */
    printf("%s: %s\n", DEDUP_DB_VERSION_KEY, DEDUP_DB_VERSION);
    printf("%s: %d\n", DEDUP_COUNT_KEY, dict_size());
    for (i = 0; i < dict_size(); i++)
        printf("mailbox %d: %s\n", i, dict_nth(i));

    r = cyrusdb_foreach(dedup_db, "", 0, NULL, dump_cb, NULL, NULL);
    dict_fini();
    if (r) {
        fprintf(stderr, "%s: %s\n", dedup_fname, cyrusdb_strerror(r));
        return EX_TEMPFAIL;
    }
    return 0;
}


/* ==========================================================================
 * Prune mode (-P): drop singleton GUIDs and compact
 * ========================================================================== */

/* cyrusdb_foreach callback used by prune mode: any GUID whose value
 * holds exactly one record is a singleton, nothing to deduplicate
 * against, so the entry serves no purpose. Append the key to the
 * caller's strarray. The actual delete happens after the iteration. */
static int prune_cb(void *rock, const char *key, size_t keylen,
                    const char *data __attribute__((unused)), size_t datalen)
{
    strarray_t *to_prune = (strarray_t *) rock;

    /* skip all metadata */
    if (keylen > 0 && key[0] == DEDUP_META_PREFIX[0]) return 0;

    signals_poll();

    /* every non-metadata key is a 40-char hex GUID, do not delete
     * anything we cannot identify */
    if (keylen != 2 * MESSAGE_GUID_SIZE) {
        fprintf(stderr, "unexpected record key %.*s\n", (int) keylen, key);
        return CYRUSDB_INTERNAL;
    }

    /* records are fixed DEDUP_RECORD_SIZE bytes, so a single-record value
     * is a singleton, with nothing to deduplicate against */
    if (datalen == DEDUP_RECORD_SIZE)
        strarray_appendm(to_prune, xstrndup(key, keylen));

    return 0;
}

/* Prune phase entry point. Walks the DB, collects every GUID key
 * whose value has only one record, deletes them, then compacts. */
static int do_prune(void)
{
    int r;

    /* validate the whole DB (version, count, complete dictionary) before
     * pruning, we don't resolve mailboxes, so the dictionary is
     * loaded only to reject a corrupted database */
    if ((r = dict_init())) return r;
    dict_fini();

    strarray_t to_prune = STRARRAY_INITIALIZER;
    r = cyrusdb_foreach(dedup_db, "", 0, NULL, prune_cb, &to_prune, NULL);
    if (r) {
        fprintf(stderr, "%s: foreach: %s\n", dedup_fname, cyrusdb_strerror(r));
        strarray_fini(&to_prune);
        return EX_TEMPFAIL;
    }

    int pruned = 0;
    unsigned batch = 0;
    int i;
    for (i = 0; i < strarray_size(&to_prune); i++) {
        const char *k = strarray_nth(&to_prune, i);
        if (dry_run) {
            if (verbosity > 0) printf("would prune %s\n", k);
            pruned++;
            continue;
        }
        r = cyrusdb_delete(dedup_db, k, strlen(k), &dedup_tid, 0);
        if (r) {
            fprintf(stderr, "delete %s: %s\n", k, cyrusdb_strerror(r));
            continue;
        }
        if (verbosity > 0) printf("prune %s\n", k);
        pruned++;

        /* periodic commit to avoid constant writes */
        if (++batch >= DEDUP_COMMIT_EVERY && dedup_tid) {
            r = cyrusdb_commit(dedup_db, dedup_tid);
            dedup_tid = NULL;
            batch = 0;
            if (r) {
                fprintf(stderr, "%s: commit: %s\n",
                        dedup_fname, cyrusdb_strerror(r));
                strarray_fini(&to_prune);
                return EX_TEMPFAIL;
            }
        }
    }

    strarray_fini(&to_prune);

    /* commit pending deletes before repack. Repack rewrites the
     * underlying file and is its own atomic operation */
    if (dedup_tid) {
        r = cyrusdb_commit(dedup_db, dedup_tid);
        dedup_tid = NULL;
        if (r) {
            fprintf(stderr, "%s: commit: %s\n", dedup_fname, cyrusdb_strerror(r));
            return EX_TEMPFAIL;
        }
    }

    if (!dry_run) {
        r = cyrusdb_repack(dedup_db);
        if (r) {
            fprintf(stderr, "%s: repack: %s\n", dedup_fname, cyrusdb_strerror(r));
            return EX_TEMPFAIL;
        }
    }

    if (verbosity > 0)
        printf("%d singleton entries %s\n",
               pruned, dry_run ? "would be pruned" : "pruned");

    return 0;
}


/* ==========================================================================
 * Link mode (-L): hardlink files that share a GUID onto a single inode
 * ========================================================================== */

/* Compare two files byte for byte. Used by -V to guard against the
 * (cryptographically possible) case of distinct messages sharing a
 * GUID or possible corruption. */
static int files_equal(const char *a, const char *b)
{
    FILE *fa, *fb;
    char bufa[8192], bufb[8192];
    int equal = 0;

    fa = fopen(a, "rb");
    if (!fa) {
        fprintf(stderr, "cannot open %s: %s\n", a, strerror(errno));
        return 0;
    }
    fb = fopen(b, "rb");
    if (!fb) {
        fprintf(stderr, "cannot open %s: %s\n", b, strerror(errno));
        fclose(fa);
        return 0;
    }

    for (;;) {
        size_t na = fread(bufa, 1, sizeof(bufa), fa);
        size_t nb = fread(bufb, 1, sizeof(bufb), fb);

        if (na != nb) break;                        /* differing lengths */
        if (na == 0) {
            equal = !ferror(fa) && !ferror(fb);     /* matched to EOF */
            break;
        }
        if (memcmp(bufa, bufb, na) != 0) break;     /* differing contents */
    }

    fclose(fa);
    fclose(fb);
    return equal;
}

/* one record as listed in the skiplist value */
struct dedup_entry {
    char *mboxname;     /* internal name of the mailbox holding this record */
    uint32_t uid;       /* IMAP uid of the record */

    /* the fields below are filled in at link time, after we open the
     * mailbox and resolve the canonical spool path */
    char *path;         /* NULL until resolved, cleared to NULL when
                         * claimed by a canonical group */
    dev_t dev;
    ino_t ino;
    nlink_t nlink;
    off_t size;
    int usable;         /* resolve + stat() succeeded */
};

/* tracks how many links to a given inode are still to be collapsed */
struct inode_count {
    dev_t dev;
    ino_t ino;
    long remaining;
};

/* Collapse one link to (dev, ino) and return the number of links that
 * still remain afterwards. The data behind an inode is only freed once
 * its last link is collapsed away, so callers count bytes saved when
 * this returns 0. */
static long collapse_inode(struct dynarray *list,
                           dev_t dev, ino_t ino, nlink_t nlink)
{
    int n = dynarray_size(list);
    int i;

    for (i = 0; i < n; i++) {
        struct inode_count *ic = dynarray_nth(list, i);
        if (ic->dev == dev && ic->ino == ino)
            return --ic->remaining;
    }

    struct inode_count fresh = {
        .dev = dev,
        .ino = ino,
        .remaining = (long) nlink - 1,
    };
    dynarray_append(list, &fresh);

    return fresh.remaining;
}

/* Sort entries by mboxname so consecutive resolve / link operations in
 * the same mailbox share one mailbox open. We don't have dev/ino
 * until we resolve. Cross-device mismatches within a mailbox group are
 * caught at link time by the e->dev != canon->dev check. */
static int entry_cmp(const void *a, const void *b)
{
    const struct dedup_entry *x = a;
    const struct dedup_entry *y = b;

    return strcmp(x->mboxname, y->mboxname);
}

/* cyrusdb_foreach() callback: hardlink every record sharing this GUID
 * that lives on the same filesystem onto a single inode. */
static int link_cb(void *rock __attribute__((unused)),
                        const char *key,
                        size_t keylen,
                        const char *data, size_t datalen)
{
    struct dynarray entries = DYNARRAY_INITIALIZER(sizeof(struct dedup_entry));
    struct dynarray icounts = DYNARRAY_INITIALIZER(sizeof(struct inode_count));
    struct mailbox *open_mb = NULL;
    const char *open_mb_name = NULL;
    const char *p, *end;
    int nentries, i, j;

    /* the dictionary and all metadata were loaded and validated up front by
     * dict_init(). Skip every metadata key and process only records */
    if (keylen > 0 && key[0] == DEDUP_META_PREFIX[0]) return 0;

    signals_poll();

    /* every non-metadata key is a 40-char hex GUID. Anything else is
     * corruption, skip it but surface it in the exit code */
    if (keylen != 2 * MESSAGE_GUID_SIZE) {
        fprintf(stderr, "unexpected record key %.*s\n", (int) keylen, key);
        link_failures++;
        return 0;
    }

    /* trailing garbage means corruption. Parse the complete records
     * that are present, but surface it in the exit code */
    if (datalen % DEDUP_RECORD_SIZE) {
        fprintf(stderr, "%.*s: %zu trailing bytes\n",
                (int) keylen, key, datalen % DEDUP_RECORD_SIZE);
        link_failures++;
    }

    /* nothing to do with singleton records */
    if (datalen / DEDUP_RECORD_SIZE < 2) return 0;

    /* Pass 1: parse the value into one dedup_entry per fixed-size record.
     * Each record is <uid (4B)><mboxid (4B)> in network order. The mboxid
     * resolves through the dictionary to a uniqueid and then, via
     * mboxlist_lookup_by_uniqueid(), to a live mailbox name. A record
     * that doesn't resolve (unknown id, or the mailbox is gone since
     * build) is skipped rather than aborting the whole GUID. The full
     * path/dev/ino/nlink/size are resolved later in Pass 2. */
    for (p = data, end = data + datalen;
         p + DEDUP_RECORD_SIZE <= end;
         p += DEDUP_RECORD_SIZE) {
        uint32_t uid = record_ntohl(p);
        uint32_t mboxid = record_ntohl(p + 4);
        mbentry_t *mbentry = NULL;

        /* ids are capped to INT_MAX at build and !count is verified on
         * load, so mboxid is a valid index. dict_nth() returns NULL past
         * the end or for an id whose mailbox was skipped at build. Either
         * way the record can't be resolved, so skip it. */
        const char *uniqueid = dict_nth(mboxid);
        if (!uniqueid) {
            fprintf(stderr, "%.*s: unresolved mailbox id %u\n",
                    (int) keylen, key, mboxid);
            continue;
        }
        if (mboxlist_lookup_by_uniqueid(uniqueid, &mbentry, NULL)) {
            fprintf(stderr, "%.*s: mailbox %s gone\n",
                    (int) keylen, key, uniqueid);
            continue;
        }

        struct dedup_entry e = {
            .mboxname = xstrdup(mbentry->name),
            .uid = uid,
        };
        dynarray_append(&entries, &e);

        mboxlist_entry_free(&mbentry);
    }

    nentries = dynarray_size(&entries);

    /* The raw-length check above already dropped singleton values. Getting
     * here with fewer than two entries means records fell out during Pass 1
     * (unresolved mailbox id, or the mailbox is gone since build). Nothing
     * left to deduplicate against, so skip the resolve and link passes (no
     * stat() syscalls, no mailbox open/close) and go straight to cleanup. */
    if (nentries < 2) goto done;

    /* sort by mboxname so same-mailbox entries are adjacent and one
     * mailbox_open_iwl() covers their resolve and link passes
     * probably will never happen, but just in case. */
    dynarray_sort(&entries, entry_cmp);

    /* Pass 2: resolve each entry's current spool path + stat under
     * a read lock. We release the lock between mailboxes: the link
     * pass acquires its own write lock and revalidates the destination,
     * so a window here is harmless. */
    for (i = 0; i < nentries; i++) {
        struct dedup_entry *e = dynarray_nth(&entries, i);
        struct index_record record;
        struct stat sbuf;
        const char *fname;

        if (open_mb && strcmp(open_mb_name, e->mboxname) != 0) {
            mailbox_close(&open_mb);
            libcyrus_run_delayed();
            open_mb_name = NULL;
        }
        if (!open_mb) {
            int lr = mailbox_open_irl(e->mboxname, &open_mb);
            if (lr) {
                fprintf(stderr, "cannot lock %s: %s\n",
                        e->mboxname, error_message(lr));
                /* a mailbox deleted since build is benign staleness */
                if (lr != IMAP_MAILBOX_NONEXISTENT) link_failures++;
                continue;
            }
            open_mb_name = e->mboxname;
        }

        if (mailbox_find_index_record(open_mb, e->uid, &record)) {
            fprintf(stderr, "%s uid %u: record gone\n",
                    e->mboxname, e->uid);
            continue;
        }

        fname = mailbox_record_fname(open_mb, &record);
        if (!fname || stat(fname, &sbuf) != 0) {
            int serrno = errno;
            fprintf(stderr, "%s uid %u: cannot stat %s: %s\n",
                    e->mboxname, e->uid,
                    fname ? fname : "(null)",
                    fname ? strerror(serrno) : "no fname");
            /* a spool file unlinked since build (e.g. by cyr_expire)
             * is benign staleness */
            if (!fname || serrno != ENOENT) link_failures++;
            continue;
        }

        e->path = xstrdup(fname);
        e->dev = sbuf.st_dev;
        e->ino = sbuf.st_ino;
        e->nlink = sbuf.st_nlink;
        e->size = sbuf.st_size;
        e->usable = 1;
    }
    if (open_mb) {
        mailbox_close(&open_mb);
        libcyrus_run_delayed();
        open_mb_name = NULL;
    }

    /* Pass 3: group by device. Within each group take the first usable
     * file as the canonical copy, stage one hardlink of it in the
     * partition's stage directory, then relink every other member of the
     * group from that stage file, exactly how delivery lays down a
     * single-instance store. Staging from a private, same-partition file
     * means the survivor's own mailbox need not stay locked: we only ever
     * hold the destination mailbox's write lock, one at a time, while we
     * replace its spool file. Entries whose path was set to NULL have
     * already been claimed by an earlier group. */
    for (i = 0; i < nentries; i++) {
        struct dedup_entry *canon = dynarray_nth(&entries, i);
        struct stagemsg *stage = NULL;
        const char *stagefile = NULL;
        struct stat stagest;

        if (!canon->usable || canon->path == NULL) continue;

        for (j = i + 1; j < nentries; j++) {
            struct dedup_entry *e = dynarray_nth(&entries, j);
            char *epath;

            if (!e->usable || e->path == NULL) continue;
            if (e->dev != canon->dev) continue;     /* different filesystem */

            epath = e->path;
            e->path = NULL;                         /* claim into this group */

            if (e->ino == canon->ino) {
                /* already hardlinked to the canonical copy */
                free(epath);
                continue;
            }

            if (e->size != canon->size) {
                fprintf(stderr,
                        "size mismatch for shared GUID, skipping %s\n",
                        epath);
                link_failures++;
                free(epath);
                continue;
            }

            if (verify && !files_equal(canon->path, epath)) {
                fprintf(stderr,
                        "content mismatch for shared GUID, skipping %s\n",
                        epath);
                link_failures++;
                free(epath);
                continue;
            }

            if (dry_run) {
                if (verbosity > 0)
                    printf("would link %s -> %s\n", epath, canon->path);
            }
            else {
                struct stat now;

                /* Stage the canonical content once per group, lazily on
                 * the first real link. append_newstage_full() hardlinks
                 * canon into <partition>/stage./, so the shared inode stays
                 * alive from here on regardless of what happens to canon's
                 * own mailbox, so no lock on the survivor is needed. */
                if (!stage) {
                    FILE *f = append_newstage_full(canon->mboxname, 0, 0,
                                                   &stage, canon->path);
                    if (!f) {
                        fprintf(stderr, "cannot stage %s, skipping group\n",
                                canon->path);
                        link_failures++;
                        free(epath);
                        break;
                    }
                    fclose(f);
                    stagefile = append_stagefname(stage);

                    /* The stage must hold the very inode we resolved and
                     * verified in Pass 2: anything else means canon was
                     * replaced in the unlocked window, or the staging
                     * degraded to a byte copy. */
                    if (stat(stagefile, &stagest) != 0 ||
                        stagest.st_dev != canon->dev ||
                        stagest.st_ino != canon->ino) {
                        fprintf(stderr, "%s changed, skipping group\n",
                                canon->path);
                        link_failures++;
                        free(epath);
                        break;
                    }
                }

                /* Hold the destination mailbox write-locked so nothing else
                 * can touch this spool file while we relink it. That lock is 
                 * what makes the link+rename replacement below safe here,
                 * exactly as it is for delivery. Entries are sorted
                 * by mboxname, so consecutive links into the same mailbox
                 * reuse one open. */
                if (open_mb && strcmp(open_mb_name, e->mboxname) != 0) {
                    mailbox_close(&open_mb);
                    libcyrus_run_delayed();
                    open_mb_name = NULL;
                }
                if (!open_mb) {
                    int lr = mailbox_open_iwl(e->mboxname, &open_mb);
                    if (lr) {
                        fprintf(stderr, "cannot lock %s: %s\n",
                                e->mboxname, error_message(lr));
                        /* a mailbox deleted since build is benign staleness */
                        if (lr != IMAP_MAILBOX_NONEXISTENT) link_failures++;
                        free(epath);
                        continue;
                    }
                    open_mb_name = e->mboxname;
                }

                /* Revalidate under the lock: the file must still be the
                 * one we resolved to. Anything else means the world
                 * changed between resolve and now. */
                if (stat(epath, &now) != 0 ||
                    now.st_dev != e->dev ||
                    now.st_ino != e->ino ||
                    now.st_size != e->size) {
                    fprintf(stderr,
                            "state changed for %s, skipping\n", epath);
                    free(epath);
                    continue;
                }

                if (verbosity > 0)
                    printf("link %s -> %s\n", epath, canon->path);

                /* relink the destination from the stage file: link to a
                 * temporary name, then rename over the spool file, so it
                 * is replaced atomically and can never end up missing.
                 * A failed link (e.g. hardlink limit) leaves it untouched,
                 * since mailbox_copyfile is unusable here because it
                 * silently falls back to a byte copy and unlinks the
                 * destination before writing it. */
                char tmp[MAX_MAILBOX_PATH+1];
                int tn = snprintf(tmp, sizeof(tmp), "%s.dedup", epath);
                if (tn < 0 || (size_t) tn >= sizeof(tmp)) {
                    fprintf(stderr, "path too long, skipping %s\n", epath);
                    link_failures++;
                    free(epath);
                    continue;
                }
                xunlink(tmp);       /* stale leftover from a crashed run */
                if (link(stagefile, tmp) != 0) {
                    fprintf(stderr, "link %s -> %s failed: %s\n",
                            epath, canon->path, strerror(errno));
                    link_failures++;
                    free(epath);
                    continue;
                }
                if (rename(tmp, epath) != 0) {
                    fprintf(stderr, "rename %s -> %s failed: %s\n",
                            tmp, epath, strerror(errno));
                    xunlink(tmp);
                    link_failures++;
                    free(epath);
                    continue;
                }
            }

            if (collapse_inode(&icounts, e->dev, e->ino, e->nlink) == 0) {
                /* last link to this inode collapsed: its data is freed */
                bytes_saved += e->size;
                inodes_freed++;
            }

            free(epath);
        }

        /* Drop the stage file: the mailbox links we created keep the
         * shared inode alive, so removing our staging link is just
         * cleanup. */
        if (stage) append_removestage(stage);
    }

 done:
    if (open_mb) {
        mailbox_close(&open_mb);
        libcyrus_run_delayed();
    }

    for (i = 0; i < nentries; i++) {
        struct dedup_entry *e = dynarray_nth(&entries, i);
        free(e->mboxname);
        free(e->path);
    }
    dynarray_fini(&entries);
    dynarray_fini(&icounts);

    return 0;
}

static int do_link(void)
{
    int r;

    if ((r = dict_init())) return r;

    /* the dictionary is fully loaded and validated, so link_guid_cb skips
     * every metadata key and processes only records */
    r = cyrusdb_foreach(dedup_db, "", 0, NULL, link_cb, NULL, NULL);
    dict_fini();
    if (r)
        fprintf(stderr, "%s: %s\n", dedup_fname, cyrusdb_strerror(r));

    if (show_savings) {
        printf("%lld bytes %s by hardlinking\n",
               (long long) bytes_saved,
               dry_run ? "would be saved" : "saved");
        printf("%lu inodes %s by hardlinking\n",
               inodes_freed,
               dry_run ? "would be freed" : "freed");
    }

    if (link_failures)
        fprintf(stderr, "%u entries failed to link\n", link_failures);

    return (r || link_failures) ? EX_TEMPFAIL : 0;
}


/* ==========================================================================
 * main and mode-independent setup / teardown
 * ========================================================================== */

/* Cleanly shut down and exit. Aborts any pending build transaction so
 * partial twoskip state doesn't leak, runs any deferred libcyrus work,
 * then defers the rest of the subsystem teardown to cyrus_done(), the
 * same shape as reconstruct(8)'s shut_down. */
static void shut_down(int code) __attribute__((noreturn));
static void shut_down(int code)
{
    in_shutdown = 1;

    if (dedup_db) {
        if (dedup_tid) cyrusdb_abort(dedup_db, dedup_tid);
        cyrusdb_close(dedup_db);
    }

    libcyrus_run_delayed();

    cyrus_done();

    exit(code);
}

static void usage(FILE *out, int rc) __attribute__((noreturn));
static void usage(FILE *out, int rc)
{
    fprintf(out,
            "usage: %s [-C <alt_config>] [-D <backend>] -B -f <db> [-ex] [-v...] [-p <partition>] [mailbox]...\n"
            "       %s [-C <alt_config>] [-D <backend>] -L -f <db> [-c] [-d] [-V] [-v...]\n"
            "       %s [-C <alt_config>] [-D <backend>] -P -f <db> [-d] [-v...]\n"
            "       %s [-C <alt_config>] [-D <backend>] -Z -f <db>\n"
            "\n"
            "  -C <alt_config>  use alternate imapd.conf\n"
            "  -f <db>          path of the deduplicate database (required)\n"
            "  -B               build mode: scan mailboxes and write the GUID\n"
            "                   database to <db>\n"
            "  -L               link mode: read <db> and hardlink files that\n"
            "                   share a GUID and live on the same filesystem\n"
            "  -P               prune mode: drop singleton (one-record) entries\n"
            "                   from <db> and compact it\n"
            "  -Z               dump mode: print <db> (version, mailbox dictionary\n"
            "                   and per-GUID records) in human-readable form\n"
            "  -D <backend>     cyrusdb backend for the skiplist (default: twoskip)\n"
            "  -p <partition>, --partition=<partition>\n"
            "                   (build) only scan mailboxes on this partition\n"
            "  -c               print the total bytes saved and inodes freed by\n"
            "                   hardlinking\n"
            "  -d               dry run: report what would be done, change nothing\n"
            "  -V, --verify     verify file contents are byte-identical before linking.\n"
            "                   Very slow (reads every candidate file in full) and\n"
            "                   usually unnecessary, the GUID match is enough unless\n"
            "                   you are guarding against collisions or corruption\n"
            "  -v, --verbose    print per-record (build) or per-link/per-prune (link,\n"
            "                   prune) output. Repeat for more detail in build mode:\n"
            "                   -v guid, -vv + mailbox and uid, -vvv + dev:ino and\n"
            "                   nlink of the spool file. Quiet (errors only) by default\n"
            "  -x, --skip-deleted\n"
            "                   (build) skip the DELETED.* delayed-delete hierarchy\n"
            "  -e, --skip-expunged\n"
            "                   (build) skip expunged but not unlinked records\n"
            "                   (included by default)\n"
            "  -h, --help       print this message and exit\n"
            "\n"
            "In build mode, with no mailbox arguments every mailbox is traversed.\n",
            progname, progname, progname, progname);
    exit(rc);
}

int main(int argc, char **argv)
{
    int opt, r = 0;
    char *alt_config = NULL;

    progname = argv[0];


    /* keep this in alphabetical order */
    static const char short_options[] = "BC:D:LPVZcdef:hp:vx";

    static const struct option long_options[] = {
        { "altconf", required_argument, NULL, 'C'},
        { "build", no_argument, NULL, 'B' },
        { "link", no_argument, NULL, 'L' },
        { "prune", no_argument, NULL, 'P' },
        { "dump", no_argument, NULL, 'Z' },
        { "backend", required_argument, NULL, 'D' },
        { "count", no_argument, NULL, 'c' },
        { "filename", required_argument, NULL, 'f'},
        { "dry-run", no_argument, NULL, 'd' },
        { "help", no_argument, NULL, 'h' },
        { "partition", required_argument, NULL, 'p' },
        { "skip-deleted", no_argument, NULL, 'x' },
        { "skip-expunged", no_argument, NULL, 'e' },
        { "verbose", no_argument, NULL, 'v' },
        { "verify", no_argument, NULL, 'V' },

        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'B': /* build mode: write skiplist to this db */
            dedup_mode = (dedup_mode == NO_MODE) ? BUILD_MODE : BAD_MODE;
            break;

        case 'L': /* link mode: read skiplist from this db */
            dedup_mode = (dedup_mode == NO_MODE) ? LINK_MODE : BAD_MODE;
            break;

        case 'P': /* prune mode: drop singleton entries and compact */
            dedup_mode = (dedup_mode == NO_MODE) ? PRUNE_MODE : BAD_MODE;
            break;

        case 'Z': /* dump mode: print the database in readable form */
            dedup_mode = (dedup_mode == NO_MODE) ? DUMP_MODE : BAD_MODE;
            break;

        case 'D': /* cyrusdb backend for the skiplist */
            db_backend = optarg;
            break;

        case 'c': /* print total bytes saved by hardlinking */
            show_savings = 1;
            break;

        case 'd': /* dry run: report what would be linked, change nothing */
            dry_run = 1;
            break;

        case 'e': /* skip expunged-but-not-yet-unlinked records */
            iter_flags |= ITER_SKIP_EXPUNGED;
            break;
        
        case 'f':
            dedup_fname = optarg;
            break;

        case 'h': /* print usage to stdout and exit successfully */
            usage(stdout, 0);
            /* NOTREACHED */

        case 'p': /* build mode: restrict the scan to this partition */
            build_partition = optarg;
            break;

        case 'v': /* increase per-record / per-link / per-prune verbosity */
            verbosity++;
            break;

        case 'V': /* verify file contents are identical before linking */
            verify = 1;
            break;

        case 'x': /* skip the DELETED.* delayed-delete hierarchy */
            skip_deleted = 1;
            break;

        default:
            usage(stderr, EX_USAGE);
            /* NOTREACHED */
        }
    }

    if (dedup_mode == BAD_MODE) {
        fprintf(stderr, "-B, -L, -P and -Z are mutually exclusive\n");
        usage(stderr, EX_USAGE);
    }
    if (dedup_mode == NO_MODE) {
        fprintf(stderr, "one of -B, -L, -P or -Z is required\n");
        usage(stderr, EX_USAGE);
    }
    if (!dedup_fname) {
        fprintf(stderr, "-f option must be defined\n");
        usage(stderr, EX_USAGE);
    }
    if (dedup_mode != BUILD_MODE && optind != argc) {
        fprintf(stderr, "-L, -P and -Z take no mailbox arguments\n");
        usage(stderr, EX_USAGE);
    }

    /* For safety abort if the -B target already exists */
    if (dedup_mode == BUILD_MODE) {
        struct stat dbstat;
        if (stat(dedup_fname, &dbstat) == 0) {
            fprintf(stderr, "%s already exists\n", dedup_fname);
            return EX_CANTCREAT;
        }
    }

    /* We obviously need a spool to act on */
    cyrus_init(alt_config, "deduplicate", 0, CONFIG_NEED_PARTITION_DATA);

    /* Set admin namespace, we are working directly with the spools */
    if ((r = mboxname_init_namespace(&dedup_namespace, NAMESPACE_OPTION_ADMIN))) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EX_CONFIG);
    }

    /* Handle signals to ensure graceful shutdown if possible */
    signals_set_shutdown(&shut_down);
    signals_add_handlers(0 /* handle alarm */);

    /* link/prune/dump modes just need a plain open. CYRUSDB_SHARED would
     * require cyrusdb_lockopen() and a long-lived tid (asserted in
     * lib/cyrusdb.c:_myopen) */
    int flags = (dedup_mode == BUILD_MODE) ? CYRUSDB_CREATE : 0;

    r = cyrusdb_open(db_backend, dedup_fname, flags, &dedup_db);
    if (r) {
        fprintf(stderr, "can't open %s: %s\n", dedup_fname, cyrusdb_strerror(r));
        /* a failed create may leave a partial file that would block the
         * next -B. The pre-existence check above guarantees any file
         * present now is this run's */
        if (dedup_mode == BUILD_MODE) xunlink(dedup_fname);
        cyrus_done();
        return (dedup_mode == BUILD_MODE) ? EX_CANTCREAT : EX_TEMPFAIL;
    }

    /* Now we can continue with the actual work */
    switch (dedup_mode) {
    case BUILD_MODE:
        r = do_build(argc, argv, optind);
        break;
    case DUMP_MODE:
        r = do_dump();
        break;
    case PRUNE_MODE:
        r = do_prune();
        break;
    case LINK_MODE:
        r = do_link();
        break;
    default: /* Should be unreachable */
        fatal("internal error: invalid deduplicate mode", EX_SOFTWARE);
        /* NOTREACHED */
    }

    /* commit (or abort) any pending build-mode transaction. dedup_tid
     * is only set during build mode, so this is a no-op in link mode. */
    if (dedup_tid) {
        if (r) cyrusdb_abort(dedup_db, dedup_tid);
        else if (cyrusdb_commit(dedup_db, dedup_tid)) r = EX_TEMPFAIL;
        dedup_tid = NULL;
    }

    cyrusdb_close(dedup_db);
    dedup_db = NULL;

    /* a failed build leaves a half-written DB (batch commits persist)
     * that every mode rejects. Remove it so -B can run again. The
     * pre-existence check above guarantees this run created it. */
    if (r && dedup_mode == BUILD_MODE)
        xunlink(dedup_fname);

    cyrus_done();
    return r;
}
