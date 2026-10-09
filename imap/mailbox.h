/* mailbox.h - Mailbox format definitions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/**
 * @file mailbox.h
 * @brief Mailboxes: the in-memory API and the on-disk format
 *
 * A mailbox is a directory of message files plus a few metadata files.
 * Nothing but Cyrus itself should touch them: the supported ways in are the
 * protocols and the command-line tools.
 *
 * **Where the files live**
 *
 * A mailbox lives on a partition.  Unless its mbtype has MBTYPE_LEGACY_DIRS,
 * its directory is named for its uniqueid, as
 * `<partition>/uuid/<u1>/<u2>/<uniqueid>`, where u1 and u2 are the first two
 * characters of the uniqueid; a legacy mailbox's directory is named for the
 * hashed mailbox name.  The `metapartition_files` option can move each
 * metadata file to the same relative path on a metapartition.  An archived
 * message (FLAG_INTERNAL_ARCHIVED) lives on the archive partition, and its
 * cache record is in that partition's own cyrus.cache.
 *
 * A message file is named for its UID followed by a dot, so UID 423 is
 * `423.`.  It holds the message as delivered, with CRLF line endings.
 *
 * The metadata files, named by the FNAME_* macros:
 *
 * - **cyrus.header**: mailbox-wide data that rarely changes
 * - **cyrus.index**: a fixed-size header, then a fixed-size record per
 *   message; the only copy of flags, modseqs and the like
 * - **cyrus.cache**: data parsed from the message files, including some
 *   header fields, so FETCH, SEARCH and SORT needn't reparse them
 * - **cyrus.annotations**: the annotations on the mailbox's messages; the
 *   mailbox's own annotations are in the global annotations.db, keyed by its
 *   uniqueid
 * - **cyrus.dav**: the DAV database, only for a mailbox outside any user's
 *   tree; a user's DAV database is per-user (see dav_getpath())
 * - **cyrus.squat**: the search index, only when %search_engine is squat
 * - **cyrus.expunge**: obsolete; read only to recover UIDs during
 *   reconstruct
 *
 * **cyrus.header**
 *
 * MAILBOX_HEADER_MAGIC, then a single line holding a DLIST kvlist, with
 * these keys:
 *
 * - `T`: the mbtype, as mboxlist_mbtype_to_string() names it
 * - `N`: the mailbox name
 * - `I`: the uniqueid
 * - `J`: the JMAP id
 * - `Q`: the quota root, if any
 * - `A`: the ACL, as a kvlist of identifier and rights
 * - `U`: the user flag names, as a list; a flag's position is its bit in
 *   index_record::user_flags, so a removed flag leaves a NIL behind
 *
 * An older format, still read, has three lines after the magic: the quota
 * root and uniqueid separated by a tab, the user flag names separated by
 * spaces, and the ACL as tab-separated identifier and rights pairs.
 *
 * The file is only ever replaced whole, by writing a new copy and renaming it
 * into place.  Its CRC32 is stored in index_header::header_file_crc, so
 * changing it needs the exclusive index lock.
 *
 * **cyrus.index**
 *
 * A header of index_header::start_offset bytes, then
 * index_header::num_records records of index_header::record_size bytes, in
 * UID order.  Record number N (counting from 1) is at
 * `start_offset + (N-1) * record_size`.  Every field is in network byte order.
 * The header and each record end with a CRC32 of all the bytes before it.  In
 * the current version, times are 64-bit counts of nanoseconds since the
 * epoch, and every 64-bit field is 8-byte aligned.
 *
 * The OFFSET_* macros give the current version's layout.  The layout of every
 * version that can still be read, 6 through MAILBOX_MINOR_VERSION, is in the
 * templates in imap/index_file.c; mailbox_setversion() converts between them.
 *
 * Expunging a message doesn't remove its record, only sets
 * FLAG_INTERNAL_EXPUNGED on it.  When the message is going to be removed for
 * good (which is "right now" an immediate expunge and otherwise later) by
 * cyr_expire, the record also gets FLAG_INTERNAL_UNLINKED and the message file
 * is deleted.  A repack rewrites the index without the unlinked records, which
 * is the only time a record changes position.
 *
 * Two record fields encode more than their names say.  The high 16 bits of
 * the stored system_flags are the internal flags (MsgInternalFlags), and the
 * high 16 bits of the stored cache_version are bits 32-47 of cache_offset.
 *
 * **cyrus.cache**
 *
 * The first four bytes are the index_header::generation_no of the index the
 * file belongs to.  Then come the cache records, each appended at the end of
 * the file and found through index_record::cache_offset.  A record is
 * NUM_CACHE_FIELDS items, in the order of the CACHE_* enum, each a 32-bit
 * length followed by that many bytes, padded to a multiple of four (see
 * CACHE_ITEM_NEXT()).
 *
 * index_record::cache_crc is the CRC32 of the whole cache record, and
 * index_record::cache_version says what's in it, notably which header fields
 * CACHE_HEADERS holds: those imap/mailbox_header_cache.gperf lists with a
 * minimum version no higher than it, plus any field it doesn't list whose
 * name doesn't start with "X-" (see mailbox_cached_header()).  Replacing a
 * record leaves the old one behind, counted in
 * index_header::leaked_cache_records, until the next repack.  Everything here
 * can be rebuilt from the message files by reconstruct.
 *
 * A repack writes cyrus.index.NEW, and a cyrus.cache.NEW stamped with the
 * next generation, then renames the index into place and then the cache.
 *
 * **Locking and commit order**
 *
 * Opening a mailbox takes a shared namelock on it, held until the struct
 * mailbox is closed.  A repack needs the exclusive namelock, so a record
 * doesn't move under anyone who has the mailbox open.  Reading the index
 * needs at least the shared index lock, so the CRCs can be checked, and
 * changing any of the metadata files needs the exclusive one.
 *
 * Changes to cyrus.header and cyrus.index are held in memory until
 * mailbox_commit(), so an error or crash before then leaves both untouched.
 * New cache records are the exception: they're appended to cyrus.cache as
 * they're made, but nothing refers to them until the index records naming
 * them are written.
 *
 * mailbox_commit() syncs the cache, writes cyrus.header, then the index
 * records, and last the index header.  cyrus.header is synced before the
 * index is written, and the index after.  The index header is what makes a
 * change visible: readers see only num_records records, so records appended
 * before a crash but not yet published by the header are ignored, and later
 * overwritten.
 */

#ifndef INCLUDED_MAILBOX_H
#define INCLUDED_MAILBOX_H

#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <config.h>

#include "byteorder.h"
#include "conversations.h"
#include "logfmt.h"
#include "message_guid.h"
#include "message.h"
#include "ptrarray.h"
#include "quota.h"
#include "seqset.h"
#include "util.h"

#define MAX_MAILBOX_CREATENAME 490
/* enough space for all possible rewrites and DELETED.* and stuff */
#define MAX_MAILBOX_NAME 510
#define MAX_MAILBOX_BUFFER 1024
#define MAX_MAILBOX_PATH 4096
#define MAX_USER_FLAGS (16*8)

#define MAILBOX_HEADER_MAGIC ("\241\002\213\015Cyrus mailbox header\n" \
     "\"The best thing about this system was that it had lots of goals.\"\n" \
     "\t--Jim Morris on Andrew\n")


/**
 * The cyrus.index format version that new and repacked mailboxes get.
 *
 * NOTE: the mailbox minor version must be changed whenever any on-disk
 * format changes are made to any mailbox files.  It is also important to
 * make sure all the mailbox upgrade and downgrade code in mailbox.c is
 * changed to be able to convert both backwards and forwards between the
 * new version and all supported previous versions.
 * If you change MAILBOX_MINOR_VERSION you MUST also make corresponding
 * changes to backend_version() in backend.c.
 */
#define MAILBOX_MINOR_VERSION       (20) /* read comment above! */
/** The index_record::cache_version that new cache records get */
#define MAILBOX_CACHE_MINOR_VERSION (14)

#define FNAME_HEADER "/cyrus.header"
#define FNAME_INDEX "/cyrus.index"
#define FNAME_CACHE "/cyrus.cache"
#define FNAME_SQUAT "/cyrus.squat"
#define FNAME_EXPUNGE "/cyrus.expunge"
#define FNAME_DAV "/cyrus.dav"
#define FNAME_ANNOTATIONS "/cyrus.annotations"

#define CRC_INIT_BASIC 0
// annot value should be visible as an integer via replication protocol,
// so let's make it easy to see there
#define CRC_INIT_ANNOT 12345678

enum meta_filename {
  META_HEADER = 1,
  META_INDEX,
  META_CACHE,
  META_SQUAT,
  META_EXPUNGE,
  META_ANNOTATIONS,
  META_DAV,
  META_ARCHIVECACHE  /* MUST be last for relocate.c */
};

#define MAILBOX_FNAME_LEN 256

#define LOCK_NONE 0
#define LOCK_SHARED 1
#define LOCK_EXCLUSIVE 2
#define LOCK_NONBLOCK   4   /* flag to OR in */
#define LOCK_NONBLOCKING (LOCK_NONBLOCK|LOCK_EXCLUSIVE)

#define NUM_CACHE_FIELDS 10

struct cacheitem {
    size_t offset;
    size_t len;
};

struct cacherecord {
    const struct buf *buf;
    size_t offset;
    size_t len;
    struct cacheitem item[NUM_CACHE_FIELDS];
};

struct statusdata {
    const char *userid;
    unsigned statusitems;

    uint32_t messages;
    uint32_t recent;
    uint32_t uidnext;
    uint32_t uidvalidity;
    const char *mailboxid;
    const char *uniqueid;
    uint32_t unseen;
    uint32_t mboptions;
    quota_t size;
    modseq_t createdmodseq;
    modseq_t highestmodseq;
    uint32_t deleted;
    quota_t deleted_storage;
    conv_status_t xconv;
};

#define STATUSDATA_INIT { NULL, 0, 0, 0, 0, 0, NULL, NULL, 0, 0, 0, 0, 0, 0, 0, CONV_STATUS_INIT }

/**
 * One message's cyrus.index record, as it is in memory.
 *
 * The fields down to guid are stored on disk, at the OFFSET_* positions; the
 * rest are working state.
 */
// sorting for good packing rather than on-disk file order, since not
// all target datastructures are neat sizes
struct index_record {
    uint32_t uid;               /**< the message's UID */
    uint32_t header_size;       /**< octets of the message's header */
    uint32_t system_flags;      /**< MsgFlags */
    uint32_t internal_flags;    /**< MsgInternalFlags; stored in the high
                                     bits of system_flags */
    uint32_t cache_crc;         /**< CRC32 of the cyrus.cache record */
    uint32_t cache_version;     /**< format of the cyrus.cache record */
    uint64_t cache_offset;      /**< where the cyrus.cache record starts */
    uint64_t size;              /**< octets of the whole message */
    uint64_t modseq;            /**< modseq of the last change (CONDSTORE) */
    uint64_t createdmodseq;     /**< modseq when the record was created */
    uint64_t cid;               /**< conversation id */
    uint64_t basecid;           /**< the conversation id before a split by
                                     conversations_max_thread, if any */
    struct timespec internaldate; /**< IMAP INTERNALDATE; where possible,
                                       also the message file's mtime */
    struct timespec sentdate;   /**< the Date header, at day resolution and
                                     with no zone, for SEARCH SENTON etc. */
    struct timespec gmtime;     /**< the Date header, in UTC, for SORT */
    struct timespec last_updated; /**< when the record last changed */
    struct timespec savedate;   /**< when the message was saved to this
                                     mailbox (RFC 8514) */
    // this is 4x uint32_t
    uint32_t user_flags[MAX_USER_FLAGS/32]; /**< a bit per user flag, in
                                                 the cyrus.header order */
    // this is 21x char - how annoyingly offset
    struct message_guid guid;   /**< SHA-1 of the message file */

    /* metadata */
    uint32_t recno;
    unsigned silentupdate:1;
    unsigned ignorelimits:1;
    struct cacherecord crec;
};

/** The sync CRCs replication compares to find mailboxes that differ */
struct synccrcs {
    uint32_t basic;     /**< XOR of the CRCs of the unexpunged records */
    uint32_t annot;     /**< XOR of the CRCs of the annotations */
};

/**
 * The cyrus.index header, as it is in memory.
 *
 * Everything but dirty is stored on disk, at the OFFSET_* positions.
 */
struct index_header {
    /* track if it's been changed */
    int dirty;

    /* header fields */
    bit32 generation_no;        /**< bumped by each repack; must match the
                                     first four bytes of cyrus.cache */
    int format;                 /**< obsolete */
    int minor_version;          /**< the index format version */
    uint32_t start_offset;      /**< octets of header before the first record */
    uint32_t record_size;       /**< octets in each record */
    uint32_t num_records;       /**< records in the file, expunged or not */
    struct timespec last_appenddate; /**< time of the last append */
    uint32_t last_uid;          /**< the highest UID used, so UIDNEXT - 1 */
    quota_t quota_mailbox_used; /**< octets of the unexpunged messages */
    struct timespec pop3_last_login; /**< the owner's last POP3 login, for
                                          the poptimeout option */
    uint32_t uidvalidity;       /**< the IMAP UIDVALIDITY */

    uint32_t deleted;           /**< unexpunged messages with \\Deleted */
    uint32_t answered;          /**< unexpunged messages with \\Answered */
    uint32_t flagged;           /**< unexpunged messages with \\Flagged */
    uint32_t unseen;            /**< unexpunged messages without FLAG_SEEN: the
                                     owner's \\Seen, or everyone's with
                                     OPT_IMAP_SHAREDSEEN */

    uint32_t options;           /**< OPT_* flags */
    uint32_t leaked_cache_records; /**< dead records in cyrus.cache */
    modseq_t highestmodseq;     /**< the IMAP HIGHESTMODSEQ */
    modseq_t deletedmodseq;     /**< modseq below which expunges may have been
                                     forgotten, for QRESYNC and replication */
    uint32_t exists;            /**< unexpunged records: the IMAP EXISTS */
    struct timespec first_expunged; /**< last_updated of the oldest expunged
                                         record, to decide when to repack */
    struct timespec last_repack_time; /**< time of the last repack */
    struct timespec changes_epoch; /**< time from which changes can be
                                        calculated; see deletedmodseq */

    modseq_t createdmodseq;     /**< the modseq when the mailbox was
                                     created; a new mailbox's JMAP id is made
                                     from it (see mailbox_create()) */

    bit32 header_file_crc;      /**< CRC32 of cyrus.header */
    struct synccrcs synccrcs;   /**< for replication */

    uint32_t recentuid;         /**< the highest UID the owner has been
                                     shown, for \\Recent */
    struct timespec recenttime; /**< when recentuid last changed */

    struct timespec pop3_show_after; /**< POP3 hides messages whose
                                          internaldate is no later */
    quota_t quota_annot_used;   /**< octets of annotations */
    quota_t quota_deleted_used; /**< octets of messages with \\Deleted */
    quota_t quota_expunged_used; /**< octets of expunged, not unlinked,
                                      messages */
};

#define CHANGE_ISAPPEND (1<<0)
#define CHANGE_WASEXPUNGED (1<<1)
#define CHANGE_WASUNLINKED (1<<2)

struct index_change {
    struct index_record record;
    char *msgid;
    uint32_t mapnext;
    uint32_t flags;
};

#define INDEX_MAP_SIZE 65536

struct mailbox_header {
    char *name;
    char *acl;
    char *uniqueid;
    char *jmapid;
    char *quotaroot;
    char *flagname[MAX_USER_FLAGS];
    int mbtype;
};

enum cstate_flags_val {
    CSTATE_FLAG_UNSET = 0,
    CSTATE_FLAG_NOCONV = 1,
    CSTATE_FLAG_EXTERN = 2,
    CSTATE_FLAG_LOCAL = 3
};

struct mailbox {
    int index_fd;
    int header_fd;

    ptrarray_t caches;
    const char *index_base;
    size_t index_len;   /* mapped size */

    int index_locktype; /* 0 = none, 1 = shared, 2 = exclusive */
    int is_readonly; /* tells us whether the index_fd is opened RW or RO */

    ino_t header_file_ino;
    bit32 header_file_crc;

    time_t index_mtime;
    ino_t index_ino;
    size_t index_size;

    /* Information in mailbox list */
    struct mboxlist_entry *mbentry;

    struct index_header i;

    /* Information in header */
    struct mailbox_header h;

    /* track open time */
    struct timeval starttime;

    /* annotations */
    struct annotate_state *annot_state;

    /* conversations */
    unsigned cstate_flag;
    struct conversations_state *cstate_value;

    /* namespace lock */
    struct usernamespacelocks *user_nslock;

    struct caldav_db *local_caldav;
    struct carddav_db *local_carddav;
    struct webdav_db *local_webdav;
#ifdef USE_SIEVE
    struct sieve_db *local_sieve;
    char *sievedir;
#endif

    /* change management */
    int silentchanges;
    int modseq_dirty;
    int header_dirty;
    int quota_dirty;
    int has_changed;
    int spool_dirfd;
    int archive_dirfd;
    time_t last_updated; /* for appends*/
    quota_t quota_previously_used[QUOTA_NUMRESOURCES]; /* for quota change */

    /* index change map */
    uint32_t index_change_map[INDEX_MAP_SIZE];
    struct index_change *index_changes;
    uint32_t index_change_alloc;
    uint32_t index_change_count;

    /* refcounting */
    int refcount;
    char *lockname;
    struct mboxlock *namelock;
    struct mailbox *next;
};

#define ITER_SKIP_UNLINKED (1<<0)
#define ITER_SKIP_EXPUNGED (1<<1)
#define ITER_SKIP_DELETED  (1<<2)
#define ITER_STEP_BACKWARD (1<<3)

/* pre-declare message_t to avoid circular dependency problems */
typedef struct message message_t;

struct mailbox_iter;

/* Offsets of index/expunge header fields
 *
 * NOTE: Since we might be using a 64-bit MODSEQ in the index record,
 *       the size of the index header MUST be a multiple of 8 bytes.
 *
 * There's sanity tests for these offsets in mailbox.testc.  If you
 * add new fields to the header, don't forget to add them to the tests
 * too!
 */
#define OFFSET_GENERATION_NO           0
#define OFFSET_FORMAT                  4
#define OFFSET_MINOR_VERSION           8
#define OFFSET_START_OFFSET           12
#define OFFSET_RECORD_SIZE            16
#define OFFSET_NUM_RECORDS            20
#define OFFSET_LAST_APPENDDATE        24 /**< grew to 64-bit in v20 */
#define OFFSET_QUOTA_MAILBOX_USED     32 /**< offset for 64bit quotas */
#define OFFSET_POP3_LAST_LOGIN        40 /**< grew to 64-bit in v20 */
#define OFFSET_DELETED                48 /**< added for ACAP */
#define OFFSET_ANSWERED               52
#define OFFSET_FLAGGED                56
#define OFFSET_EXISTS                 60 /**< Non-expunged records */
#define OFFSET_MAILBOX_OPTIONS        64
#define OFFSET_LEAKED_CACHE           68 /**< Number of leaked records in cache file */
#define OFFSET_HIGHESTMODSEQ          72 /**< CONDSTORE (64-bit modseq) */
#define OFFSET_DELETEDMODSEQ          80 /**< CONDSTORE (64-bit modseq) */
#define OFFSET_LAST_UID               88
#define OFFSET_UIDVALIDITY            92
#define OFFSET_HEADER_FILE_CRC        96 /**< CRC32 of cyrus.header */
#define OFFSET_SYNCCRCS_BASIC        100 /**< XOR of SYNC CRCs of unexpunged records */
#define OFFSET_RECENTTIME            104 /**< last timestamp for seen data
                                          * (grew to 64-bit in v20) */
#define OFFSET_POP3_SHOW_AFTER       112 /**< time after which to show messages 
                                          * to POP3 (grew to 64-bit in v20) */
#define OFFSET_SYNCCRCS_ANNOT        120 /**< SYNC_CRC of the annotations */
#define OFFSET_UNSEEN                124 /**< total number of UNSEEN messages (owner) */
#define OFFSET_MAILBOX_CREATEDMODSEQ 128 /**< MODSEQ at creation time */
#define OFFSET_QUOTA_DELETED_USED    136 /**< bytes of \\Deleted messages
                                           * for this mailbox (64-bit) */
#define OFFSET_QUOTA_EXPUNGED_USED   144 /**< bytes of \\Expunged messages
                                          * for this mailbox (64-bit) */
#define OFFSET_QUOTA_ANNOT_USED      152 /**< bytes of per-mailbox and per-message
                                          * annotations for this mailbox */
#define OFFSET_CHANGES_EPOCH         160 /**< time from which we can calculate changes
                                          * (grew to 64-bit in v20) */
#define OFFSET_FIRST_EXPUNGED        168 /**< last_updated of oldest expunged message
                                          * (grew to 64-bit in v20) */
#define OFFSET_LAST_REPACK_TIME      176 /**< time of last expunged cleanup
                                          * (grew to 64-bit in v20) */
#define OFFSET_RECENTUID             184 /**< last UID the owner was told about */
#define OFFSET_HEADER_CRC            188

/* Offsets of index_record fields in index/expunge file
 *
 * NOTE: Since we might be using a 64-bit MODSEQ in the index record,
 *       OFFSET_MODSEQ_64 and the size of the index record MUST be
 *       multiples of 8 bytes.
 *
 * There's sanity tests for these offsets in mailbox.testc.  If you
 * add new fields to the record, don't forget to add them to the tests
 * too!
 */
#define OFFSET_UID              0
#define OFFSET_CACHE_OFFSET     4
#define OFFSET_INTERNALDATE     8 /**< grew to 64-bit in v20 (nsec since epoch) */
#define OFFSET_SENTDATE        16 /**< grew to 64-bit in v20 */
#define OFFSET_SIZE            24 /**< grew to 64-bit in v20 */
#define OFFSET_HEADER_SIZE     32
#define OFFSET_SYSTEM_FLAGS    36
#define OFFSET_USER_FLAGS      40
#define OFFSET_CACHE_VERSION   56
#define OFFSET_MESSAGE_GUID    60
#define OFFSET_MODSEQ          80 /**< CONDSTORE (64-bit modseq) */
#define OFFSET_CID             88 /**< conversation id, added in v13 */
#define OFFSET_CREATEDMODSEQ   96 /**< modseq of creation time, added in v16 */
#define OFFSET_GMTIME         104 /**< grew to 64-bit in v20 */
#define OFFSET_LAST_UPDATED   112 /**< grew to 64-bit in v20 */
#define OFFSET_SAVEDATE       120 /**< added in v15 */
#define OFFSET_BASECID        128 /**< base conversation id, added in v20 */
#define OFFSET_CACHE_CRC      136 /**< CRC32 of cache record */
#define OFFSET_RECORD_CRC     140

#define INDEX_HEADER_SIZE (OFFSET_HEADER_CRC+4)
#define INDEX_RECORD_SIZE (OFFSET_RECORD_CRC+4)

/** The IMAP system flags, in index_record::system_flags */
typedef enum _MsgFlags {
    FLAG_ANSWERED           = (1<<0),
    FLAG_FLAGGED            = (1<<1),
    FLAG_DELETED            = (1<<2),
    FLAG_DRAFT              = (1<<3),
    FLAG_SEEN               = (1<<4), /**< the owner's \\Seen, or everyone's
                                           with OPT_IMAP_SHAREDSEEN */
} MsgFlags;

/* NOTE: you can only use up to 1<<15 for MsgFlags and down to 1<<16 for
 * InternalFlags unless you change the code in mailbox_buf_to_index_record
 * which is currently:
 *     record->system_flags = stored_system_flags & 0x0000ffff;
 *     record->internal_flags = stored_system_flags & 0xffff0000;
 */

/** Cyrus's own per-message state, in index_record::internal_flags */
typedef enum _MsgInternalFlags {
    FLAG_INTERNAL_SNOOZED            = (1<<26), /**< snoozed, by JMAP */
    FLAG_INTERNAL_SPLITCONVERSATION  = (1<<27), /**< index_record::basecid
                                                     is meaningful */
    FLAG_INTERNAL_NEEDS_CLEANUP      = (1<<28), /**< the message file must be
                                                     moved to or from the
                                                     archive partition, or
                                                     deleted */
    FLAG_INTERNAL_ARCHIVED           = (1<<29), /**< the message file is on
                                                     the archive partition */
    FLAG_INTERNAL_UNLINKED           = (1<<30), /**< the message file is gone,
                                                     or about to be */
    FLAG_INTERNAL_EXPUNGED           = (1U<<31), /**< expunged */
} MsgInternalFlags;

#define FLAGS_SYSTEM   (FLAG_ANSWERED|FLAG_FLAGGED|FLAG_DELETED|FLAG_DRAFT|FLAG_SEEN)

#define OPT_POP3_NEW_UIDL (1<<0)        /**< added for Outlook stupidity */
/* NOTE: not used anymore - but don't reuse it */
#define OPT_IMAP_CONDSTORE (1<<1)       /**< added for CONDSTORE extension */

/* these two are annotations, if you add more, update annotate.c
 * struct annotate_mailbox_flags */
#define OPT_IMAP_SHAREDSEEN (1<<2)      /**< added for shared \\Seen flag */
#define OPT_IMAP_DUPDELIVER (1<<3)      /**< added to allow duplicate delivery */

#define OPT_IMAP_HAS_ALARMS (1<<4)      /**< messages in mailbox have alarms */

#define OPT_MAILBOX_NEEDS_UNLINK (1<<29)        /**< files to be unlinked */
#define OPT_MAILBOX_NEEDS_REPACK (1<<30)        /**< repacking to do */
#define OPT_MAILBOX_DELETED (1U<<31)    /**< mailbox is deleted an awaiting cleanup */

#define MAILBOX_OPTIONS_MASK (OPT_POP3_NEW_UIDL | \
                              OPT_IMAP_SHAREDSEEN | \
                              OPT_IMAP_DUPDELIVER | \
                              OPT_IMAP_HAS_ALARMS) 
#define MAILBOX_CLEANUP_MASK (OPT_MAILBOX_NEEDS_UNLINK | \
                              OPT_MAILBOX_NEEDS_REPACK | \
                              OPT_MAILBOX_DELETED)
#define MAILBOX_OPT_VALID (MAILBOX_OPTIONS_MASK | \
                           MAILBOX_CLEANUP_MASK)

/* reconstruct flags */
#define RECONSTRUCT_QUIET           (1<<1)
#define RECONSTRUCT_MAKE_CHANGES    (1<<2)
#define RECONSTRUCT_DO_STAT         (1<<3)
#define RECONSTRUCT_ALWAYS_PARSE    (1<<4)
#define RECONSTRUCT_GUID_REWRITE    (1<<5)
#define RECONSTRUCT_GUID_UNLINK     (1<<6)
#define RECONSTRUCT_REMOVE_ODDFILES (1<<7)
#define RECONSTRUCT_IGNORE_ODDFILES (1<<8)
#define RECONSTRUCT_PREFER_MBOXLIST (1<<9)
#define RECONSTRUCT_RECALC_NANOSEC  (1<<10)
#define RECONSTRUCT_KEEP_CACHE      (1<<11)
#define RECONSTRUCT_ALWAYS_DIRTY    (1<<12)

#define MAX_CACHED_HEADER_SIZE 32 /* Max size of a cached header name */

/* Aligned buffer for manipulating index header/record fields */
typedef union {
    unsigned char buf[INDEX_HEADER_SIZE > INDEX_RECORD_SIZE ?
                      INDEX_HEADER_SIZE : INDEX_RECORD_SIZE];
    bit64 align8; /* align on 8-byte boundary */
} indexbuffer_t;

/* Access assistance macros for memory-mapped cache file data */
/* CACHE_ITEM_BIT32: Convert to host byte order */
/* CACHE_ITEM_LEN: Get the length out */
/* CACHE_ITEM_NEXT: Return a pointer to the next entry.  Sizes are
 * 4-byte aligned, so round up to the next 4 byte boundary */
#define CACHE_ITEM_BIT32(ptr) (ntohl(*((bit32 *)(ptr))))
#define CACHE_ITEM_LEN(ptr) CACHE_ITEM_BIT32(ptr)
#define CACHE_ITEM_NEXT(ptr) ((ptr)+4+((3+CACHE_ITEM_LEN(ptr))&~3))

/* Size of a bit32 to skip when jumping over cache item sizes */
#define CACHE_ITEM_SIZE_SKIP sizeof(bit32)

/**
 * Cache item positions: the items of a cyrus.cache record, in order.
 *
 * CACHE_SECTION is binary, built from 32-bit values in network byte order
 * by message_write_section(), and it nests.  A section for a part with no
 * subparts is a single 0.  Otherwise it is N+1, for N subparts; a
 * description of part 0, the header, which a multipart lacks; a description
 * of each subpart; and then a section for each subpart.  A description is
 * the offset and size of the part's header and of its content in the message
 * file, with a size of -1 for a part that doesn't exist; a word holding the
 * length of the charset name (high 16 bits) and the encoding (low 8 bits,
 * 0xff for none); the charset name, NUL-padded to that length; the content
 * GUID (20 bytes); and the decoded size and line count of the content.
 */
enum cache_item_index {
    CACHE_ENVELOPE = 0,     /**< the IMAP ENVELOPE */
    CACHE_BODYSTRUCTURE,    /**< the IMAP BODYSTRUCTURE */
    CACHE_BODY,             /**< the IMAP BODY */
    CACHE_SECTION,          /**< where each MIME part is; see above */
    CACHE_HEADERS,          /**< the cached header fields, as in the
                                 message; see mailbox_cached_header() */
    CACHE_FROM,             /**< the From addresses, for SEARCH */
    CACHE_TO,               /**< the To addresses, for SEARCH */
    CACHE_CC,               /**< the Cc addresses, for SEARCH */
    CACHE_BCC,              /**< the Bcc addresses, for SEARCH */
    CACHE_SUBJECT           /**< the decoded Subject, for SEARCH and SORT */
};

/* Cached envelope token positions */
enum {
    ENV_DATE = 0,
    ENV_SUBJECT,
    ENV_FROM,
    ENV_SENDER,
    ENV_REPLYTO,
    ENV_TO,
    ENV_CC,
    ENV_BCC,
    ENV_INREPLYTO,
    ENV_MSGID
};
#define NUMENVTOKENS (10)

/*
 * This structure maintains a list of FLAG_ to the string literal mapping.
 * The defines are validated at compile time in mailbox.c
 */
struct MsgFlagMap {
    const char *code;
    MsgFlags flag;
};
#define N_MSGFLAGMAP (11)
#define FLAGMAPSTR_MAXLEN (1 + 3 * N_MSGFLAGMAP)
extern void flags_to_str(const struct index_record *record, char *flagstr);

unsigned mailbox_cached_header(const char *s);
unsigned mailbox_cached_header_inline(const char *text);

typedef unsigned mailbox_decideproc_t(struct mailbox *mailbox,
                                      const struct index_record *index,
                                      void *rock);

/* file names on disk */
#define META_FNAME_NEW 1
extern const char *mailbox_meta_fname(const struct mailbox *mailbox, int metafile);
extern const char *mailbox_meta_newfname(const struct mailbox *mailbox, int metafile);
extern int mailbox_meta_rename(struct mailbox *mailbox, int metafile);

extern const char *mailbox_record_fname(struct mailbox *mailbox,
                                        const struct index_record *record);
extern const char *mailbox_datapath(struct mailbox *mailbox, uint32_t uid);
extern unsigned mailbox_should_archive(struct mailbox *mailbox,
                                       const struct index_record *record,
                                       void *rock);

extern int open_mailboxes_exist();
extern int open_mailboxes_namelocked(const char *userid);

/* map individual messages in */
extern int mailbox_map_record(struct mailbox *mailbox, const struct index_record *record, struct buf *buf);

/* cache record API */
int mailbox_cacherecord(struct mailbox *mailbox,
                        const struct index_record *record);
char *mailbox_cache_get_env(struct mailbox *mailbox,
                            const struct index_record *record,
                            int field);

/* field-based lookup functions */
const char *cacheitem_base(const struct index_record *record, int field);
unsigned cacheitem_size(const struct index_record *record, int field);
struct buf *cacheitem_buf(const struct index_record *record, int field);

/* opening and closing */
extern int mailbox_open_iwl(const char *name,
                            struct mailbox **mailboxptr);
extern int mailbox_open_irlnb(const char *name, struct mailbox **);
extern int mailbox_open_irl(const char *name,
                            struct mailbox **mailboxptr);
extern int mailbox_open_exclusive(const char *name,
                                  struct mailbox **mailboxptr);
extern int mailbox_open_from_mbe(const struct mboxlist_entry *mbe,
                                 struct mailbox **mailboxptr);
extern void mailbox_close(struct mailbox **mailboxptr);
extern int mailbox_delete(struct mailbox **mailboxptr);

/* reading details */
extern const struct mboxlist_entry *mailbox_mbentry(const struct mailbox *mailbox);
extern const char *mailbox_name(const struct mailbox *mailbox);
extern const char *mailbox_uniqueid(const struct mailbox *mailbox);
extern const char *mailbox_jmapid(const struct mailbox *mailbox);
extern const char *mailbox_partition(const struct mailbox *mailbox);
extern const char *mailbox_acl(const struct mailbox *mailbox);
extern const char *mailbox_quotaroot(const struct mailbox *mailbox);
extern uint32_t mailbox_mbtype(const struct mailbox *mailbox);
extern modseq_t mailbox_foldermodseq(const struct mailbox *mailbox);
extern uint32_t mailbox_uidvalidity(const struct mailbox *mailbox);

/* caller must free - tab separated lists of userids */
extern char *mailbox_visible_users(const struct mailbox *mailbox);

struct caldav_db *mailbox_open_caldav(struct mailbox *mailbox);
struct carddav_db *mailbox_open_carddav(struct mailbox *mailbox);
struct webdav_db *mailbox_open_webdav(struct mailbox *mailbox);

/* reading bits and pieces */
extern int mailbox_refresh_index_header(struct mailbox *mailbox);
extern int mailbox_write_header(struct mailbox *mailbox, int force);
extern void mailbox_index_dirty(struct mailbox *mailbox);
extern modseq_t mailbox_modseq_dirty(struct mailbox *mailbox);
extern int mailbox_reload_index_record(struct mailbox *mailbox,
                                       struct index_record *record);
extern int mailbox_reload_index_record_dirty(struct mailbox *mailbox,
                                             struct index_record *record);
extern int mailbox_rewrite_index_record(struct mailbox *mailbox,
                                        struct index_record *record);
extern int mailbox_append_index_record(struct mailbox *mailbox,
                                       struct index_record *record);
extern int mailbox_find_index_record(struct mailbox *mailbox, uint32_t uid,
                                     struct index_record *record);
extern int mailbox_read_basecid(struct mailbox *mailbox,
                                const struct index_record *record);


// header updates
extern void mailbox_set_acl(struct mailbox *mailbox, const char *acl);
extern void mailbox_set_quotaroot(struct mailbox *mailbox, const char *quotaroot);

extern int mailbox_user_flag(struct mailbox *mailbox, const char *flag,
                             int *flagnum, int create);
extern int mailbox_remove_user_flag(struct mailbox *mailbox, int flagnum);
extern int mailbox_record_hasflag(struct mailbox *mailbox,
                                  const struct index_record *record,
                                  const char *flag);
extern strarray_t *mailbox_extract_flags(const struct mailbox *mailbox,
                                         const struct index_record *record,
                                         const char *userid);
extern struct entryattlist *mailbox_extract_annots(const struct mailbox *mailbox,
                                                   const struct index_record *record);
extern int mailbox_commit(struct mailbox *mailbox);
extern int mailbox_abort(struct mailbox *mailbox);

/* seen state check */
extern int mailbox_internal_seen(const struct mailbox *mailbox, const char *userid);

extern unsigned mailbox_count_unseen(struct mailbox *mailbox);

/* index locking operations */
extern int mailbox_lock_index(struct mailbox *mailbox, int locktype);
extern int mailbox_index_islocked(struct mailbox *mailbox, int write);

extern int mailbox_expunge_cleanup(struct mailbox *mailbox, struct mailbox_iter *iter,
                                   time_t expunge_mark, unsigned *ndeleted, int limit);
extern int mailbox_expunge(struct mailbox *mailbox, struct mailbox_iter *iter,
                           mailbox_decideproc_t *decideproc, void *deciderock,
                           unsigned *nexpunged, int event_type, int limit);
extern void mailbox_archive(struct mailbox *mailbox, struct mailbox_iter *iter,
                            mailbox_decideproc_t *decideproc, void *deciderock);
extern void mailbox_unlock_index(struct mailbox *mailbox, struct statusdata *sd);

extern int mailbox_create(const char *name, uint32_t mbtype, int minor_version,
                          const char *part, const char *acl,
                          const char *uniqueid, const char *jmapid,
                          int options, unsigned uidvalidity,
                          modseq_t createdmodseq, modseq_t highestmodseq,
                          struct mailbox **mailboxptr);

extern int mailbox_copy_files(struct mailbox *mailbox, const char *newpart,
                              const char *newname, const char *newuniqueid);
extern int mailbox_delete_cleanup(const char *part, const char *name, const char *uniqueid);

extern int mailbox_rename_nocopy(struct mailbox *oldmailbox,
                                 struct mboxlist_entry *newmbentry, int silent);

extern int mailbox_rename_copy(struct mailbox *oldmailbox,
                               const char *newname, const char *newpart,
                               unsigned uidvalidity,
                               int ignorequota, int silent,
                               struct mailbox **newmailboxptr);
extern int mailbox_rename_cleanup(struct mailbox **mailboxptr);

extern int mailbox_copyfile_fdptr(const char *from, const char *to, int nolink, int *dirfdp);

extern int mailbox_reconstruct(const char *name, int flags, struct mailbox **mailboxp);

/*
 * Create the unique identifier for a mailbox named 'name' with
 * uidvalidity 'uidvalidity'.  We use Ted Ts'o's libuuid if available,
 * otherwise we use some random bits.
 */
#define mailbox_make_uniqueid(mailbox) mailbox_set_uniqueid(mailbox, makeuuid())

extern void mailbox_set_uniqueid(struct mailbox *mailbox, const char *uniqueid);
extern void mailbox_set_jmapid(struct mailbox *mailbox, const char *jmapid);
extern void mailbox_set_mbtype(struct mailbox *mailbox, uint32_t mbtype);

extern int mailbox_setversion(struct mailbox *mailbox,
                              int version, unsigned flags, ptrarray_t *records);

extern int mailbox_index_recalc(struct mailbox *mailbox);

#define mailbox_quota_check(mailbox, delta) \
        (mailbox_quotaroot(mailbox) ? quota_check_useds(mailbox_quotaroot(mailbox), delta) : 0)
void mailbox_get_usage(struct mailbox *mailbox,
                        quota_t usage[QUOTA_NUMRESOURCES]);
void mailbox_annot_changed(struct mailbox *mailbox,
                           unsigned int uid,
                           const char *entry,
                           const char *userid,
                           const struct buf *oldval,
                           const struct buf *newval,
                           int silent);

extern int mailbox_get_annotate_state(struct mailbox *mailbox,
                                      unsigned int uid,
                                      struct annotate_state **statep);

extern int mailbox_annotation_write(struct mailbox *mailbox, uint32_t uid,
                                    const char *entry, const char *userid,
                                    const struct buf *value);

extern int mailbox_annotation_writemask(struct mailbox *mailbox, uint32_t uid,
                                        const char *entry, const char *userid,
                                        const struct buf *value);

extern int mailbox_annotation_lookup(struct mailbox *mailbox, uint32_t uid,
                                     const char *entry, const char *userid,
                                     struct buf *value);


extern int mailbox_annotation_lookupmask(struct mailbox *mailbox, uint32_t uid,
                                         const char *entry, const char *userid,
                                         struct buf *value);

extern struct mailbox_iter *mailbox_iter_init(struct mailbox *mailbox,
                                              modseq_t changedsince,
                                              unsigned flags);
/* Set a timer on the iterator, after which it returns no more messages.
 * The time is measured in CLOCK_MONOTONIC time as returned by
 * cyrus_gettime. The nchecktime argument defines how many records are
 * processed before the clock is checked again. */
extern void mailbox_iter_timer(struct mailbox_iter *iter,
                               struct timespec until, unsigned nchecktime);
extern void mailbox_iter_startuid(struct mailbox_iter *iter, uint32_t uid);
extern void mailbox_iter_uidset(struct mailbox_iter *iter, seqset_t *seq);
extern const message_t *mailbox_iter_step(struct mailbox_iter *iter);
extern void mailbox_iter_done(struct mailbox_iter **iterp);

struct synccrcs mailbox_synccrcs(struct mailbox *mailbox, int recalc);

extern int mailbox_add_dav(struct mailbox *mailbox, hashu64_table *cmodseqs);
extern int mailbox_delete_dav(struct mailbox *mailbox);
extern int mailbox_add_sieve(struct mailbox *mailbox, hashu64_table *cmodseqs);
extern int mailbox_add_email_alarms(struct mailbox *mailbox,
                                    hashu64_table *cmodseqs);

extern int mailbox_add_conversations(struct mailbox *mailbox, int silent);
__attribute__((nonnull))
extern int mailbox_get_xconvmodseq(struct mailbox *mailbox, modseq_t *);
extern int mailbox_update_xconvmodseq(struct mailbox *mailbox, modseq_t, int force);
#define mailbox_has_conversations(m) mailbox_has_conversations_full(m, 0)
extern int mailbox_has_conversations_full(struct mailbox *mailbox, int allow_deleted);

#define mailbox_get_cstate(m) mailbox_get_cstate_full(m, 0)
extern struct conversations_state *mailbox_get_cstate_full(struct mailbox *mailbox, int allow_deleted);

typedef void mailbox_wait_cb_t(void *rock);
extern void mailbox_set_wait_cb(mailbox_wait_cb_t *cb, void *rock);

extern void mailbox_cleanup_uid(struct mailbox *mailbox, uint32_t uid, const char *flagstr);

extern int mailbox_crceq(struct synccrcs a, struct synccrcs b);

extern struct dlist *mailbox_acl_to_dlist(const char *aclstr);

extern int mailbox_changequotaroot(struct mailbox *mailbox,
                                   const char *root, int silent);

extern int mailbox_parse_datafilename(const char *name, uint32_t *uidp);

extern struct mboxlist_entry *mailbox_mbentry_from_path(const char *header_path);

extern int mailbox_set_datafile_timestamps(struct mailbox *mailbox,
                                           struct index_record *record);

/* data-type aware logging */
extern void logfmt_push_mailbox(struct logfmt *lf,
                                const struct mailbox *mailbox);
extern void logfmt_push_msgrecord(struct logfmt *lf,
                                  const struct index_record *record);

extern void logfmt_arg_mailbox(struct logfmt *lf,
                               const char *key, const void *value);
extern void logfmt_arg_msgrecord(struct logfmt *lf,
                                 const char *key, const void *value);

/* Log a mailbox's identity -- mbox.name, mbox.uniqueid, mbox.mailboxid --
 * or mbox=~null~ if it's NULL.  For xsyslog_ev().
 */
#define lf_mailbox(mailboxp) lf_fn("mbox", logfmt_arg_mailbox, (mailboxp))

/* Log a message record -- msg.imapuid, msg.modseq, msg.sysflags, msg.guid,
 * msg.size.  For xsyslog_ev().
 */
#define lf_msgrecord(recordp) lf_fn("msg", logfmt_arg_msgrecord, (recordp))

#endif /* INCLUDED_MAILBOX_H */
