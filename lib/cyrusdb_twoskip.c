/* cyrusdb_twoskip.c - brand new twoskip implementation, not backwards anything
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "assert.h"
#include "bsearch.h"
#include "byteorder.h"
#include "cyrusdb.h"
#include "crc32.h"
#include "libcyr_cfg.h"
#include "mappedfile.h"
#include "util.h"
#include "xmalloc.h"

/*
 * twoskip disk format.
 *
 * GOALS:
 *  a) 64 bit through
 *  b) Fast recovery after crashes
 *  c) integrity checks throughout
 *  d) simple format
 *
 * ACHIEVED BY:
 *  a)
 *   - 64 bit offsets for all values
 *   - smaller initial keylen and vallen, but they can
 *     can be extended up to 64 bits as well.
 *   - no timestamps stored in the file.
 *   - XXX - may behave strangely with large files on
 *     32 bit architectures, particularly if size_t is
 *     not 64 bit.
 *
 *  b)
 *   - "dirty flag" is always set in the header and
 *     fsynced BEFORE writing anything else.
 *   - a header field for "current size", after which
 *     all changes are considered suspect until commit.
 *   - two "lowest level" offsets, used in alternating
 *     order, so the highest value less than "current_size"
 *     is always the correct pointer - this means we
 *     never lose linkage, so never need to rewrite more
 *     than the affected records during a recovery.
 *   - all data is fsynced BEFORE rewriting the header to
 *     remove the dirty flag.
 *   - As long as the first 64 bytes of the file are
 *     guaranteed to write all together or not at all,
 *     we're crash-safe.
 *
 *  c)
 *   - every byte in the file is covered by one of the
 *     crc32 values stored throughout.
 *   - header CRC is checked on every header read (open/lock)
 *   - record head CRCs are checked on every record read,
 *     including skiplist traverse.
 *   - record tail CRCs (key/value) are check on every exact
 *     key match result, during traverse for read or write.
 *
 *  d)
 *   - there are no special commit, inorder, etc records.
 *     just add records and ghost "delete" records to give
 *     somewhere to point to on deletes.  These are only
 *     at the lowest level, so don't have a significant
 *     seek impact.
 *   - modular code makes the logic much clearer.
 */

/*
 * FORMAT:
 *
 * HEADER: 64 bytes
 *  magic: 20 bytes: "4 bytes same as skiplist" "twoskip file\0\0\0\0"
 *  version: 4 bytes
 *  generation: 8 bytes
 *  num_records: 8 bytes
 *  repack_size: 8 bytes
 *  current_size: 8 bytes
 *  flags: 4 bytes
 *  crc32: 4 bytes
 *
 * RECORDS:
 *  type 1 byte
 *  level: 1 byte
 *  keylen: 2 bytes
 *  vallen: 4 bytes
 *  <optionally: 64 bit keylen if keylen == UINT16_MAX>
 *  <optionally: 64 bit vallen if vallen == UINT32_MAX>
 *  ptrs: 8 bytes * (level+1)
 *  crc32_head: 4 bytes
 *  crc32_tail: 4 bytes
 *  key: (keylen bytes)
 *  val: (vallen bytes)
 *  padding: enough zeros to round up to an 8 byte multiple
 *
 * defined types, in skiplist language are:
 * '=' -> DUMMY
 * '+' -> ADD/INORDER
 * '-' -> DELETE (kind of)
 * '$' -> COMMIT
 * but note that delete records behave differently - they're
 * part of the pointer hierarchy, so that back offsets will
 * always point somewhere past the 'end' until commit.
 *
 * The DUMMY is always MAXLEVEL level, with zero keylen and vallen
 * The DELETE is always zero level, with zero keylen and vallen
 * crc32_head is calculated on all bytes before it in the record
 * crc32_tail is calculated on all bytes after, INCLUDING padding
 *
 * The COMMIT is inserted at the end of each transaction, and its
 * single pointer points back to the start of the transaction.
 */

/* OPERATION:
 *
 * Finding a record works very much like skiplist, but we have
 * a datastructure, 'struct skiploc', to help find it.  There
 * is one of these embedded directly in the 'struct db', and
 * it's the only one we ever use.
 *
 * skiploc contains two complete sets of offsets - at every
 * level the offset of the previous record, and the offset of
 * the next record, in relation to the requested key.  If the
 * key is an exact match, it also contains a copy of the
 * struct skiprecord.  If not, it contains the struct
 * skiprecord for the previous record at level zero.
 *
 * It also contains a 'struct buf' with a copy of the requested
 * key, which allows for efficient relocation of the position in
 * the file when nothing is changed.
 *
 * So nothing is really changed with finding, except the special
 * "level zero" alternative pointer.  We'll see that in action
 * later.
 *
 * TRANSACTIONS:
 * 1) before writing anything else, the header is updated with the
 *    DIRTY flag set, and then fdatasync is run.
 * 2) after all changes, fdatasync is run again.
 * 3) finally, the header is updated with a new current_size and
 *    the DIRTY flag clear, then fdatasync is run for a third time.
 *
 * ADDING A NEW RECORD:
 * a new record is created with forward locations pointing to the
 * next pointers in the skiploc.  This is appended to the file.
 * This works for either a create OR replace, since in both cases
 * the nextlocs are correct.  Level zero is set to zero on a new
 * record.
 *
 * If it's not a replace, a "random" level will be chosen for the
 * record.  All update operations below apply only up to this level,
 * pointers above are unaffected - and continue over the location
 * of this change.
 *
 * For each backloc, the record at that offset is read, and the
 * forward pointers at each level are replaced with the offset
 * of the new record.  NOTE: see special level zero logic below.
 *
 * Again, if this was a replace, the backlocs don't point to the
 * current record, so it just silently disappears from the lists.
 *
 * DELETING A RECORD:
 * The logic is almost identical to adding, but a delete record
 * always has a level of zero, with only a single pointer forward
 * to the next record.
 *
 * Because of this, the updates are done up to the level of the
 * old record instead.
 *
 * THE SPECIAL "level zero":
 * To allow a "fast fsck" after an aborted transaction, rather
 * than having only a single level 1 pointer, we have two.  The
 * following algorithm is used to select which one to change.
 *
 * The definition of "current_size" is the size of the database
 * at last commit, it does not get updated during a transaction.
 *
 * So: when updating level 1 - if either level 1 or level 0 has
 * a value >= current_size, then that value gets updated again.
 * otherwise, the lowest value gets replaced with the new value.
 *
 * when reading, the highest value is used - except during
 * recovery when it's the highest value less than current_size,
 * since any "future" offsets are bogus.
 *
 * This means that there is always at least one offset which
 * points to the "next" record as if the current transaction
 * had never occured - allowing recovery to find all alive
 * records without scanning and updating the rest of the file.
 * This guarantee exists regardless of any ordering of writes
 * within the transaction, any page could be inconsistent and
 * the result is still a clean recovery.
 *
 * CHECKPOINT:
 * Over time, a twoskip database accumulates cruft - replaced
 * records and delete records.  Records out of order, slowing
 * down sequential access.  When the size at last repack
 * is sufficiently smaller than the current size (see the
 * TUNING constants below) then the file is checkpointed.
 * A checkpoint is achieved by creating a new file, and
 * copying all the current records, in order, into it, then
 * renaming the new file over the old.  The "generation"
 * counter in the header is incremented to tell other users
 * that offsets into the file are no longer valid.  This is
 * more reliable than just using the inode, because inodes
 * can be reused.
 *
 * LOCATION OPTIMISATION:
 * If the generation is unchanged AND the size of the file
 * is unchanged, then all offsets stored in the skiploc are
 * still valid.  This is used to optimise finding the current
 * key, advancing to the "next" key, and also to optimise
 * regular fetches that happen to hit either the current key,
 * the gap immediately after, or the next key.  All other
 * locations cause a full relocate.
 */


/********** TUNING *************/

/* don't bother rewriting if the database has less than this much data */
#define MINREWRITE 16834
/* number of skiplist levels - 31 gives us binary search to 2^32 records.
 * limited to 255 by file format, but skiplist had 20, and that was enough
 * for most real uses.  31 is heaps. */
#define MAXLEVEL 31
/* should be 0.5 for binary search semantics */
#define PROB 0.5

/* release lock in foreach at least every N records */
#define FOREACH_LOCK_RELEASE 256

/* format specifics */
#undef VERSION /* defined in config.h */
#define VERSION 1

/* type aliases */
#define LLU long long unsigned int
#define LU long unsigned int

/* record types */
#define DUMMY '='
#define RECORD '+'
#define DELETE '-'
#define COMMIT '$'

/* magic 8-byte pad - space for type, easy to read on hexdump
 * and with both low and high bits to be unlikely in real data */
#define BLANK " BLANK\x07\xa0"

/********** DATA STRUCTURES *************/

/* A single "record" in the twoskip file.  This could be a
 * DUMMY, a KEYRECORD, a VALRECORD or even a DELETE - they
 * all read and write with the same functions */
struct skiprecord {
    /* location on disk (not part of the on-disk format as such) */
    size_t offset;
    size_t len;

    /* what are our header fields */
    uint8_t type;
    uint8_t level;
    size_t keylen;
    size_t vallen;

    /* where to do we go from here? */
    size_t nextloc[MAXLEVEL+1];

    /* what do our integrity checks say? */
    uint32_t crc32_head;
    uint32_t crc32_tail;

    /* our key and value */
    size_t keyoffset;
    size_t valoffset;
};

/* a location in the twoskip file.  We always have:
 * record: if "is_exactmatch" this points to the record
 *         with the matching key, otherwise it points to
 *         the 'compar' order previous record.
 * backloc: the records that point TO this location
 *          at each level.  If is_exactmatch, they
 *          point to the record, otherwise they are
 *          the record.
 * forwardloc: the records pointed to by the record
 *             at 'backloc' at the same level.  Kept
 *             here for efficiency
 * keybuf: a copy of the requested key - we always keep
 *         this so we can re-seek after the file has been
 *         checkpointed under us (say a read-only foreach)
 *
 * generation and end can be used to see if anything in
 * the file may have changed and needs re-reading.
 */
struct skiploc {
    /* requested, may not match actual record */
    struct buf keybuf;
    int is_exactmatch;

    /* current or next record */
    struct skiprecord record;

    /* we need both sets of offsets to cheaply insert */
    size_t backloc[MAXLEVEL+1];
    size_t forwardloc[MAXLEVEL+1];

    /* need a generation so we know if the location is still valid */
    uint64_t generation;
    size_t end;
};

#define DIRTY (1<<0)

struct txn {
    /* logstart is where we start changes from on commit, where we truncate
       to on abort */
    int num;
    int shared;
};

struct db_header {
    /* header info */
    uint32_t version;
    uint32_t flags;
    uint64_t generation;
    uint64_t num_records;
    size_t repack_size;
    size_t current_size;
};

struct dbengine {
    /* file data */
    struct mappedfile *mf;

    struct db_header header;
    struct skiploc loc;

    /* tracking info */
    int is_open;
    size_t end;
    int txn_num;
    struct txn *current_txn;

    /* comparator function to use for sorting */
    int open_flags;
    int (*compar) (const char *s1, int l1, const char *s2, int l2);
};

struct db_list {
    struct dbengine *db;
    struct db_list *next;
    int refcount;
};

#define HEADER_MAGIC ("\241\002\213\015twoskip file\0\0\0\0")
#define HEADER_MAGIC_SIZE (20)

/* offsets of header files */
enum {
    OFFSET_HEADER = 0,
    OFFSET_VERSION = 20,
    OFFSET_GENERATION = 24,
    OFFSET_NUM_RECORDS = 32,
    OFFSET_REPACK_SIZE = 40,
    OFFSET_CURRENT_SIZE = 48,
    OFFSET_FLAGS = 56,
    OFFSET_CRC32 = 60,
};

#define HEADER_SIZE 64
#define DUMMY_OFFSET HEADER_SIZE
#define MAXRECORDHEAD ((MAXLEVEL + 5)*8)
// NOTE: MAXLEVEL should be chosen so that MAXRECORDHEAD always
// fits within BLOCKSIZE so header rewrites are atomic.
#define BLOCKSIZE 512

/* mount a scratch monkey */
static union skipwritebuf {
    uint64_t align;
    char s[MAXRECORDHEAD];
} scratchspace;

static struct db_list *open_twoskip = NULL;

static int mycommit(struct dbengine *db, struct txn *tid);
static int myabort(struct dbengine *db, struct txn *tid);
static int mycheckpoint(struct dbengine *db);
static int myconsistent(struct dbengine *db, struct txn *tid);
static int recovery(struct dbengine *db);
static int recovery1(struct dbengine *db, int *count);
static int recovery2(struct dbengine *db, int *count);

/************** HELPER FUNCTIONS ****************/

#define BASE(db) mappedfile_base((db)->mf)
#define KEY(db, rec) (BASE(db) + (rec)->keyoffset)
#define VAL(db, rec) (BASE(db) + (rec)->valoffset)
#define SIZE(db) mappedfile_size((db)->mf)
#define FNAME(db) mappedfile_fname((db)->mf)

/* calculate padding size */
static size_t roundup(size_t record_size, int howfar)
{
    if (record_size % howfar)
        record_size += howfar - (record_size % howfar);
    return record_size;
}

/* choose a level appropriately randomly */
static uint8_t randlvl(uint8_t lvl, uint8_t maxlvl)
{
    while (((float) rand() / (float) (RAND_MAX)) < PROB) {
        lvl++;
        if (lvl == maxlvl) break;
    }
    return lvl;
}

/************** HEADER ****************/

/* given an open, mapped db, read in the header information */
static int read_header(struct dbengine *db)
{
    uint32_t crc;

    assert(db && db->mf && db->is_open);

    if (SIZE(db) < HEADER_SIZE) {
        syslog(LOG_ERR,
               "twoskip: file not large enough for header: %s", FNAME(db));
        return CYRUSDB_IOERROR;
    }

    if (memcmp(BASE(db), HEADER_MAGIC, HEADER_MAGIC_SIZE)) {
        syslog(LOG_ERR, "twoskip: invalid magic header: %s", FNAME(db));
        return CYRUSDB_IOERROR;
    }

    db->header.version
        = ntohl(*((uint32_t *)(BASE(db) + OFFSET_VERSION)));

    if (db->header.version > VERSION) {
        syslog(LOG_ERR, "twoskip: version mismatch: %s has version %d",
               FNAME(db), db->header.version);
        return CYRUSDB_IOERROR;
    }

    db->header.generation
        = ntohll(*((uint64_t *)(BASE(db) + OFFSET_GENERATION)));

    db->header.num_records
        = ntohll(*((uint64_t *)(BASE(db) + OFFSET_NUM_RECORDS)));

    db->header.repack_size
        = ntohll(*((uint64_t *)(BASE(db) + OFFSET_REPACK_SIZE)));

    db->header.current_size
        = ntohll(*((uint64_t *)(BASE(db) + OFFSET_CURRENT_SIZE)));

    db->header.flags
        = ntohl(*((uint32_t *)(BASE(db) + OFFSET_FLAGS)));

    crc = ntohl(*((uint32_t *)(BASE(db) + OFFSET_CRC32)));

    db->end = db->header.current_size;

    if ((db->open_flags & CYRUSDB_NOCRC))
        return 0;

    if (crc32_map(BASE(db), OFFSET_CRC32) != crc) {
        syslog(LOG_ERR, "DBERROR: %s: twoskip header CRC failure",
               FNAME(db));
        return CYRUSDB_IOERROR;
    }

    return 0;
}

/* given an open, mapped, locked db, write the header information */
static int write_header(struct dbengine *db)
{
    char *buf = scratchspace.s;

    /* format one buffer */
    memcpy(buf, HEADER_MAGIC, HEADER_MAGIC_SIZE);
    *((uint32_t *)(buf + OFFSET_VERSION)) = htonl(db->header.version);
    *((uint64_t *)(buf + OFFSET_GENERATION)) = htonll(db->header.generation);
    *((uint64_t *)(buf + OFFSET_NUM_RECORDS)) = htonll(db->header.num_records);
    *((uint64_t *)(buf + OFFSET_REPACK_SIZE)) = htonll(db->header.repack_size);
    *((uint64_t *)(buf + OFFSET_CURRENT_SIZE)) = htonll(db->header.current_size);
    *((uint32_t *)(buf + OFFSET_FLAGS)) = htonl(db->header.flags);
    *((uint32_t *)(buf + OFFSET_CRC32)) = htonl(crc32_map(buf, OFFSET_CRC32));

    /* write it out */
    if (mappedfile_pwrite(db->mf, buf, HEADER_SIZE, 0) < 0)
        return CYRUSDB_IOERROR;

    return 0;
}

/* simple wrapper to write with an fsync */
static int commit_header(struct dbengine *db)
{
    int r = write_header(db);
    if (!r) r = mappedfile_commit(db->mf);
    return r;
}

/******************** RECORD *********************/

static int check_tailcrc(struct dbengine *db, struct skiprecord *record)
{
    uint32_t crc;

    if ((db->open_flags & CYRUSDB_NOCRC))
        return 0;

    crc = crc32_map(BASE(db) + record->keyoffset,
                             roundup(record->keylen + record->vallen, 8));
    if (crc != record->crc32_tail) {
        syslog(LOG_ERR, "DBERROR: invalid tail crc %s at %llX",
               FNAME(db), (LLU)record->offset);
        return CYRUSDB_IOERROR;
    }

    return 0;
}

/* read a single skiprecord at the given offset */
#ifdef HAVE_DECLARE_OPTIMIZE
static int read_onerecord(struct dbengine *db, size_t offset,
           struct skiprecord *record)
    __attribute__((optimize("-O3")));
#endif
static int read_onerecord(struct dbengine *db, size_t offset,
                          struct skiprecord *record)
{
    const char *base;
    int i;
    uint32_t crc;

    memset(record, 0, sizeof(struct skiprecord));

    if (!offset) return 0;

    record->offset = offset;
    record->len = 24; /* absolute minimum */

    /* need space for at least the header plus some details */
    if (record->offset + record->len > SIZE(db))
        goto badsize;

    base = BASE(db) + offset;

    /* read in the record header */
    record->type = base[0];
    record->level = base[1];
    record->keylen = ntohs(*((uint16_t *)(base + 2)));
    record->vallen = ntohl(*((uint32_t *)(base + 4)));
    offset += 8;

    /* make sure we fit */
    if (record->level > MAXLEVEL) {
        syslog(LOG_ERR, "DBERROR: twoskip invalid level %d for %s at %08llX",
               record->level, FNAME(db), (LLU)offset);
        return CYRUSDB_IOERROR;
    }

    /* long key */
    if (record->keylen == UINT16_MAX) {
        base = BASE(db) + offset;
        record->keylen = ntohll(*((uint64_t *)base));
        offset += 8;
    }

    /* long value */
    if (record->vallen == UINT32_MAX) {
        base = BASE(db) + offset;
        record->vallen = ntohll(*((uint64_t *)base));
        offset += 8;
    }

    /* we know the length now */
    record->len = (offset - record->offset) /* header including lengths */
                + 8 * (1 + record->level)   /* ptrs */
                + 8                         /* crc32s */
                + roundup(record->keylen + record->vallen, 8);  /* keyval */

    if (record->offset + record->len > SIZE(db))
        goto badsize;

    for (i = 0; i <= record->level; i++) {
        base = BASE(db) + offset;
        record->nextloc[i] = ntohll(*((uint64_t *)base));
        offset += 8;
    }

    base = BASE(db) + offset;
    record->crc32_head = ntohl(*((uint32_t *)base));
    record->crc32_tail = ntohl(*((uint32_t *)(base+4)));
    record->keyoffset = offset + 8;
    record->valoffset = record->keyoffset + record->keylen;

    if ((db->open_flags & CYRUSDB_NOCRC))
        return 0;

    crc = crc32_map(BASE(db) + record->offset, (offset - record->offset));
    if (crc != record->crc32_head) {
        syslog(LOG_ERR, "DBERROR: twoskip checksum head error for %s at %08llX",
               FNAME(db), (LLU)offset);
        return CYRUSDB_IOERROR;
    }

    return 0;

badsize:
    syslog(LOG_ERR, "twoskip: attempt to read past end of file %s: %08llX > %08llX",
           FNAME(db), (LLU)record->offset + record->len, (LLU)SIZE(db));
    return CYRUSDB_IOERROR;
}

static int read_skipdelete(struct dbengine *db, size_t offset,
                           struct skiprecord *record)
{
    int r;

    r = read_onerecord(db, offset, record);
    if (r) return r;

    if (record->type == DELETE)
        r = read_onerecord(db, record->nextloc[0], record);

    return r;
}

/* prepare the header part of the record (everything except the key, value
 * and padding).  Used for both writes and rewrites. */
static void prepare_record(struct skiprecord *record, char *buf, size_t *sizep)
{
    int len = 8;
    int i;

    assert(record->level <= MAXLEVEL);

    buf[0] = record->type;
    buf[1] = record->level;
    if (record->keylen < UINT16_MAX) {
        *((uint16_t *)(buf+2)) = htons(record->keylen);
    }
    else {
        *((uint16_t *)(buf+2)) = htons(UINT16_MAX);
        *((uint64_t *)(buf+len)) = htonll(record->keylen);
        len += 8;
    }

    if (record->vallen < UINT32_MAX) {
        *((uint32_t *)(buf+4)) = htonl(record->vallen);
    }
    else {
        *((uint32_t *)(buf+4)) = htonl(UINT32_MAX);
        *((uint64_t *)(buf+len)) = htonll(record->vallen);
        len += 8;
    }

    /* got pointers? */
    for (i = 0; i <= record->level; i++) {
        *((uint64_t *)(buf+len)) = htonll(record->nextloc[i]);
        len += 8;
    }

    /* NOTE: crc32_tail does not change */
    record->crc32_head = crc32_map(buf, len);
    *((uint32_t *)(buf+len)) = htonl(record->crc32_head);
    *((uint32_t *)(buf+len+4)) = htonl(record->crc32_tail);
    len += 8;

    *sizep = len;
}

/* only changing the record head, so only rewrite that much */
static int rewrite_record(struct dbengine *db, struct skiprecord *record)
{
    char *buf = scratchspace.s;
    size_t len;

    /* we must already be in a transaction before updating records */
    assert(db->header.flags & DIRTY);
    assert(record->offset);

    prepare_record(record, buf, &len);

    if (mappedfile_pwrite(db->mf, buf, len, record->offset) < 0)
        return CYRUSDB_IOERROR;

    return 0;
}

/* Add BLANK padding sets of 8 bytes until the entire header will write
 * in a single disk block for safety.
 * This ONLY works if the header is small enough obviously (should always be)
 * the algorithm checks if the end % BLOCKSIZE is smaller than the start % BLOCKSIZE
 * in which case we've wrapped a block */
static int add_padding(struct dbengine *db, size_t iolen) {
    // if it will always span a block, there's no point padding (and besides the
    // algorithm won't work)
    if (iolen > BLOCKSIZE - 8) return 0;

    // start with 8 byte offset, because the first 8 bytes never get rewritten
    // and end with 8 before, because if it fits exactly that's OK too
    // consider 480 bytes in, 32 bytes to write
    // 480+8 == 488, 480 - 8 + 32 == 504, so no padding
    // consider 488 bytes in:
    // 488+8 == 496, 488 - 8 + 32 == 512 -> 0 so we pad
    // 496+8 == 504 to 8, so we pad again
    // 504+8 == 512 -> 0, so we don't pad any more!
    // we write the new record from 504 onwards, with the header line before the
    // block boundary, maximising use of space!

    while (((db->end + 8) % BLOCKSIZE) > ((db->end - 8 + iolen) % BLOCKSIZE)) {
        int n = mappedfile_pwrite(db->mf, BLANK, 8, db->end);
        if (n < 0) return CYRUSDB_IOERROR;
        db->end += 8;
    }

    return 0;
}

/* you can only write records at the end */
static int write_record(struct dbengine *db, struct skiprecord *record,
                        const char *key, const char *val)
{
    char zeros[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t len;
    size_t iolen = 0;
    struct iovec io[4];
    int n;
    int r;

    assert(!record->offset);

    /* we'll put the HEAD on later */
    io[0].iov_base = scratchspace.s;
    io[0].iov_len = 0;

    io[1].iov_base = (char *)key;
    io[1].iov_len = record->keylen;

    io[2].iov_base = (char *)val;
    io[2].iov_len = record->vallen;

    /* pad to 8 bytes */
    len = record->vallen + record->keylen;
    io[3].iov_base = zeros;
    io[3].iov_len = roundup(len, 8) - len;

    /* calculate the CRC32 of the tail first */
    record->crc32_tail = crc32_iovec(io+1, 3);

    /* prepare the record once we know the crc32 of the tail */
    prepare_record(record, scratchspace.s, &iolen);
    io[0].iov_base = scratchspace.s;
    io[0].iov_len = iolen;

    /* ensure that the record header be contained within a single disk block */
    r = add_padding(db, iolen);
    if (r) return r;

    /* write to the mapped file, getting the offset updated */
    n = mappedfile_pwritev(db->mf, io, 4, db->end);
    if (n < 0) return CYRUSDB_IOERROR;

    /* locate the record */
    record->offset = db->end;
    record->keyoffset = db->end + io[0].iov_len;
    record->valoffset = record->keyoffset + record->keylen;
    record->len = n;

    /* and advance the known file size */
    db->end += n;

    return 0;
}

/* helper to append a record, starting the transaction by dirtying the
 * header first if required */
static int append_record(struct dbengine *db, struct skiprecord *record,
                         const char *key, const char *val)
{
    int r;

    assert(db->current_txn);

    /* dirty the header if not already dirty */
    if (!(db->header.flags & DIRTY)) {
        db->header.flags |= DIRTY;
        r = commit_header(db);
        if (r) return r;
    }

    return write_record(db, record, key, val);
}

/************************** LOCATION MANAGEMENT ***************************/

/* find the next record at a given level, encapsulating the
 * level 0 magic */
#ifdef HAVE_DECLARE_OPTIMIZE
static size_t _getloc(struct dbengine *db, struct skiprecord *record,
                      uint8_t level)
    __attribute__((optimize("-O3")));
#endif
static size_t _getloc(struct dbengine *db, struct skiprecord *record,
                      uint8_t level)
{
    if (level)
        return record->nextloc[level + 1];

    /* if one is past, must be the other */
    if (record->nextloc[0] >= db->end)
        return record->nextloc[1];
    if (record->nextloc[1] >= db->end)
        return record->nextloc[0];

    /* highest remaining */
    if (record->nextloc[0] > record->nextloc[1])
        return record->nextloc[0];
    return record->nextloc[1];
}

/* set the next record at a given level, encapsulating the
 * level 0 magic */
#ifdef HAVE_DECLARE_OPTIMIZE
static void _setloc(struct dbengine *db, struct skiprecord *record,
                    uint8_t level, size_t offset)
    __attribute__((optimize("-O3")));
#endif
static void _setloc(struct dbengine *db, struct skiprecord *record,
                    uint8_t level, size_t offset)
{
    if (level) {
        record->nextloc[level+1] = offset;
        return;
    }

    /* level zero is special */
    /* already this transaction, update this one */
    if (record->nextloc[0] >= db->header.current_size)
        record->nextloc[0] = offset;
    else if (record->nextloc[1] >= db->header.current_size)
        record->nextloc[1] = offset;
    /* otherwise, update older one */
    else if (record->nextloc[1] > record->nextloc[0])
        record->nextloc[0] = offset;
    else
        record->nextloc[1] = offset;
}

/* finds a record, either an exact match or the record
 * immediately before */
#ifdef HAVE_DECLARE_OPTIMIZE
static int relocate(struct dbengine *db)
    __attribute__((optimize("-O3")));
#endif
static int relocate(struct dbengine *db)
{
    struct skiploc *loc = &db->loc;
    struct skiprecord newrecord;
    size_t offset;
    size_t oldoffset = 0;
    uint8_t level;
    uint8_t i;
    int cmp = -1; /* never found a thing! */
    int r;

    /* pointer validity */
    loc->generation = db->header.generation;
    loc->end = db->end;

    /* start with the dummy */
    r = read_onerecord(db, DUMMY_OFFSET, &loc->record);
    loc->is_exactmatch = 0;

    /* initialise pointers */
    level = loc->record.level;
    newrecord.offset = 0;
    loc->backloc[level] = loc->record.offset;
    loc->forwardloc[level] = 0;

    /* special case start pointer for efficiency */
    if (!loc->keybuf.len) {
        for (i = 0; i < loc->record.level; i++) {
            loc->backloc[i] = loc->record.offset;
            loc->forwardloc[i] = _getloc(db, &loc->record, i);
        }
        return 0;
    }

    while (level) {
        offset = _getloc(db, &loc->record, level-1);

        loc->backloc[level-1] = loc->record.offset;
        loc->forwardloc[level-1] = offset;

        if (offset != oldoffset) {
            oldoffset = offset;
            r = read_skipdelete(db, offset, &newrecord);
            if (r) return r;

            if (newrecord.offset) {
                assert(newrecord.level >= level);

                cmp = db->compar(KEY(db, &newrecord), newrecord.keylen,
                                 loc->keybuf.s, loc->keybuf.len);

                /* not there?  stay at this level */
                if (cmp < 0) {
                    /* move the offset range along */
                    loc->record = newrecord;
                    continue;
                }
            }
        }

        level--;
    }

    if (cmp == 0) { /* we found it exactly */
        loc->is_exactmatch = 1;
        loc->record = newrecord;

        for (i = 0; i < loc->record.level; i++)
            loc->forwardloc[i] = _getloc(db, &loc->record, i);

        /* make sure this record is complete */
        r = check_tailcrc(db, &loc->record);

        if (r) return r;
    }

    return 0;
}

/* helper function to find a location, either by using the existing
 * location if it's close enough, or using the full relocate above */
static int find_loc(struct dbengine *db, const char *key, size_t keylen)
{
    struct skiprecord newrecord;
    struct skiploc *loc = &db->loc;
    int cmp, i, r;

    if (key != loc->keybuf.s)
        buf_setmap(&loc->keybuf, key, keylen);
    else if (keylen != loc->keybuf.len)
        buf_truncate(&loc->keybuf, keylen);

    /* can we special case advance? */
    if (keylen && loc->end == db->end
               && loc->generation == db->header.generation) {
        cmp = db->compar(KEY(db, &loc->record), loc->record.keylen,
                         loc->keybuf.s, loc->keybuf.len);
        /* same place, and was exact.  Otherwise we're going back,
         * and the reverse pointers are no longer valid... */
        if (db->loc.is_exactmatch && cmp == 0) {
            return 0;
        }

        /* we're looking after this record */
        if (cmp < 0) {
            for (i = 0; i < db->loc.record.level; i++)
                loc->backloc[i] = db->loc.record.offset;

            /* read the next record */
            r = read_skipdelete(db, loc->forwardloc[0], &newrecord);
            if (r) return r;

            /* nothing afterwards? */
            if (!newrecord.offset) {
                db->loc.is_exactmatch = 0;
                return 0;
            }

            /* now where is THIS record? */
            cmp = db->compar(KEY(db, &newrecord), newrecord.keylen,
                             loc->keybuf.s, loc->keybuf.len);

            /* exact match? */
            if (cmp == 0) {
                db->loc.is_exactmatch = 1;
                db->loc.record = newrecord;

                for (i = 0; i < newrecord.level; i++)
                    loc->forwardloc[i] = _getloc(db, &newrecord, i);

                /* make sure this record is complete */
                return check_tailcrc(db, &loc->record);
            }

            /* or in the gap */
            if (cmp > 0) {
                db->loc.is_exactmatch = 0;
                return 0;
            }
        }
        /* if we fell out here, it's not a "local" record, just search */
    }

    return relocate(db);
}

/* helper function to advance to the "next" record.  Used by foreach,
 * fetchnext, and internal functions */
static int advance_loc(struct dbengine *db)
{
    struct skiploc *loc = &db->loc;
    uint8_t i;
    int r;

    /* has another session made changes?  Need to re-find the location */
    if (loc->end != db->end || loc->generation != db->header.generation) {
        r = relocate(db);
        if (r) return r;
    }

    /* update back pointers */
    for (i = 0; i < loc->record.level; i++)
        loc->backloc[i] = loc->record.offset;

    /* ADVANCE */
    r = read_skipdelete(db, loc->forwardloc[0], &loc->record);
    if (r) return r;

    /* reached the end? */
    if (!loc->record.offset) {
        buf_reset(&loc->keybuf);
        return relocate(db);
    }

    /* update forward pointers */
    for (i = 0; i < loc->record.level; i++)
        loc->forwardloc[i] = _getloc(db, &loc->record, i);

    /* keep our location */
    buf_setmap(&loc->keybuf, KEY(db, &loc->record), loc->record.keylen);
    loc->is_exactmatch = 1;

    /* make sure this record is complete */
    r = check_tailcrc(db, &loc->record);
    if (r) return r;

    return 0;
}

/* helper function to update all the back records efficiently
 * after appending a new record, either create or delete.  The
 * caller must set forwardloc[] correctly for each level it has
 * changed */
static int stitch(struct dbengine *db, uint8_t maxlevel, size_t newoffset)
{
    struct skiploc *loc = &db->loc;
    struct skiprecord oldrecord;
    uint8_t i;
    int r;

    oldrecord.level = 0;
    while (oldrecord.level < maxlevel) {
        uint8_t level = oldrecord.level;

        r = read_onerecord(db, loc->backloc[level], &oldrecord);
        if (r) return r;

        /* always getting higher */
        assert(oldrecord.level > level);

        for (i = level; i < maxlevel; i++)
            _setloc(db, &oldrecord, i, loc->forwardloc[i]);

        r = rewrite_record(db, &oldrecord);
        if (r) return r;
    }

    /* re-read the "current record" */
    r = read_onerecord(db, newoffset, &loc->record);
    if (r) return r;

    /* and update the forward locations */
    for (i = 0; i < loc->record.level; i++)
        loc->forwardloc[i] = _getloc(db, &loc->record, i);

    return 0;
}

/* overall "store" function - update the value in the current loc.
   All new values funnel through here.  Check delete_here for
   deletion.   Force is implied here, it gets checked higher. */
static int store_here(struct dbengine *db, const char *val, size_t vallen)
{
    struct skiploc *loc = &db->loc;
    struct skiprecord newrecord;
    uint8_t level = 0;
    uint8_t i;
    int r;

    if (loc->is_exactmatch) {
        level = loc->record.level;
        db->header.num_records--;
    }

    /* build a new record */
    memset(&newrecord, 0, sizeof(struct skiprecord));
    newrecord.type = RECORD;
    newrecord.level = randlvl(1, MAXLEVEL);
    newrecord.keylen = loc->keybuf.len;
    newrecord.vallen = vallen;
    for (i = 0; i < newrecord.level; i++)
        newrecord.nextloc[i+1] = loc->forwardloc[i];
    if (newrecord.level > level)
        level = newrecord.level;

    /* append to the file */
    r = append_record(db, &newrecord, loc->keybuf.s, val);
    if (r) return r;

    /* get the nextlevel to point here for all this record's levels */
    for (i = 0; i < newrecord.level; i++)
        loc->forwardloc[i] = newrecord.offset;

    /* update all backpointers */
    r = stitch(db, level, newrecord.offset);
    if (r) return r;

    /* update header to know details of new record */
    db->header.num_records++;

    loc->is_exactmatch = 1;
    loc->end = db->end;

    return 0;
}

/* delete a record */
static int delete_here(struct dbengine *db)
{
    struct skiploc *loc = &db->loc;
    struct skiprecord newrecord;
    struct skiprecord nextrecord;
    int r;

    if (!loc->is_exactmatch)
        return CYRUSDB_NOTFOUND;

    db->header.num_records--;

    /* by the magic of zeroing, this even works for zero */
    r = read_skipdelete(db, loc->forwardloc[0], &nextrecord);
    if (r) return r;

    /* build a delete record */
    memset(&newrecord, 0, sizeof(struct skiprecord));
    newrecord.type = DELETE;
    newrecord.nextloc[0] = nextrecord.offset;

    /* append to the file */
    r = append_record(db, &newrecord, NULL, NULL);
    if (r) return r;

    /* get the nextlevel to point here */
    loc->forwardloc[0] = newrecord.offset;

    /* update all backpointers right up to the old record's
     * level, so that they all point past */
    r = stitch(db, loc->record.level, loc->backloc[0]);
    if (r) return r;

    /* update location */
    loc->is_exactmatch = 0;
    loc->end = db->end;

    return 0;
}

/************ DATABASE STRUCT AND TRANSACTION MANAGEMENT **************/

static int db_is_clean(struct dbengine *db)
{
    if (db->header.current_size != SIZE(db))
        return 0;

    if (db->header.flags & DIRTY)
        return 0;

    return 1;
}

static int unlock(struct dbengine *db)
{
    return mappedfile_unlock(db->mf);
}

static int write_lock(struct dbengine *db)
{
    int r = mappedfile_writelock(db->mf);
    if (r) return r;

    /* reread header */
    if (db->is_open) {
        r = read_header(db);
        if (r) return r;

        /* recovery checks for consistency */
        r = recovery(db);
        if (r) return r;
    }

    return 0;
}

static int read_lock(struct dbengine *db)
{
    int r = mappedfile_readlock(db->mf);
    if (r) return r;

    /* reread header */
    if (db->is_open) {
        r = read_header(db);
        if (r) return r;

        /* we just take and keep a write lock if inconsistent,
         * the write lock will fix it up */
        if (!db_is_clean(db)) {
            unlock(db);
            r = write_lock(db);
            if (r) return r;
            /* downgrade to a read lock again, since that what
             * was requested */
            unlock(db);
            return read_lock(db);
        }
    }

    return 0;
}

static int newtxn(struct dbengine *db, int shared, struct txn **tidptr)
{
    int r;
    struct txn *txn;

    assert(!db->current_txn);
    assert(!*tidptr);

    /* grab a lock */
    r = shared ? read_lock(db) : write_lock(db);
    if (r) return r;

    db->txn_num++;

    /* create the transaction */
    txn = xzmalloc(sizeof(struct txn));
    txn->num = db->txn_num;
    txn->shared = shared;
    db->current_txn = txn;

    /* pass it back out */
    *tidptr = txn;

    return 0;
}

static void dispose_db(struct dbengine *db)
{
    if (!db) return;

    if (db->mf) {
        if (mappedfile_islocked(db->mf))
            unlock(db);
        mappedfile_close(&db->mf);
    }

    buf_free(&db->loc.keybuf);

    free(db);
}

/************************************************************/

static int opendb(const char *fname, int flags, struct dbengine **ret, struct txn **mytid)
{
    struct dbengine *db;
    int r;
    int mappedfile_flags = MAPPEDFILE_RW;

    assert(fname);
    assert(ret);

    db = (struct dbengine *) xzmalloc(sizeof(struct dbengine));

    if (flags & CYRUSDB_CREATE)
        mappedfile_flags |= MAPPEDFILE_CREATE;

    db->open_flags = flags & ~CYRUSDB_CREATE;
    db->compar = (flags & CYRUSDB_MBOXSORT) ? bsearch_ncompare_mbox
                                            : bsearch_ncompare_raw;

    r = mappedfile_open(&db->mf, fname, mappedfile_flags);
    if (r) {
        /* convert to CYRUSDB errors*/
        if (r == -ENOENT) r = CYRUSDB_NOTFOUND;
        else r = CYRUSDB_IOERROR;
        goto done;
    }

    db->is_open = 0;

    /* grab a read lock, only reading the header */
    r = read_lock(db);
    if (r) goto done;

    /* if there's any issue which requires fixing, get a write lock */
    if (0) {
    retry_write:
        unlock(db);
        db->is_open = 0;
        r = write_lock(db);
        if (r) goto done;
    }

    /* if the map size is zero, it's a new file - we need to create an
     * initial header */
    if (mappedfile_size(db->mf) == 0) {
        struct skiprecord dummy;

        if (!mappedfile_iswritelocked(db->mf))
            goto retry_write;

        /* create the dummy! */
        memset(&dummy, 0, sizeof(struct skiprecord));
        dummy.type = DUMMY;
        dummy.level = MAXLEVEL;

        /* append dummy after header location */
        db->end = DUMMY_OFFSET;
        r = write_record(db, &dummy, NULL, NULL);
        if (r) {
            syslog(LOG_ERR, "DBERROR: writing dummy node for %s: %m",
                   fname);
            goto done;
        }

        /* create the header */
        db->header.version = VERSION;
        db->header.generation = 1;
        db->header.repack_size = db->end;
        db->header.current_size = db->end;
        r = commit_header(db);
        if (r) {
            syslog(LOG_ERR, "DBERROR: writing header for %s: %m",
                   fname);
            goto done;
        }
    }

    db->is_open = 1;

    r = read_header(db);
    if (r) goto done;

    if (!db_is_clean(db)) {
        if (!mappedfile_iswritelocked(db->mf))
            goto retry_write;

        /* recovery will clean the flag once it's committed the fixes */
        r = recovery(db);
        if (r) goto done;
    }

    /* unlock the DB */
    unlock(db);

    *ret = db;

    if (mytid) {
        r = newtxn(db, flags & CYRUSDB_SHARED, mytid);
        if (r) goto done;
    }

done:
    if (r) dispose_db(db);
    return r;
}

static int myopen(const char *fname, int flags, struct dbengine **ret, struct txn **mytid)
{
    struct db_list *ent;
    struct dbengine *mydb;
    int r = 0;

    /* do we already have this DB open? */
    for (ent = open_twoskip; ent; ent = ent->next) {
        if (strcmp(FNAME(ent->db), fname)) continue;
        if (ent->db->current_txn) {
            /* XXX we could gracefully handle attempts to open
             * a shared-lock database multiple times.e.g by
             * ref-counting transactions. But it's likely that
             * multiple open attempts are a bug in the caller's
             * logic, so error out here */
            return CYRUSDB_LOCKED;
        }
        if (mytid) {
            r = newtxn(ent->db, flags & CYRUSDB_SHARED, mytid);
            if (r) return r;
        }
        ent->refcount++;
        *ret = ent->db;
        return 0;
    }

    r = opendb(fname, flags, &mydb, mytid);
    if (r) return r;

    /* track this database in the open list */
    ent = (struct db_list *) xzmalloc(sizeof(struct db_list));
    ent->db = mydb;
    ent->refcount = 1;
    ent->next = open_twoskip;
    open_twoskip = ent;

    /* return the open DB */
    *ret = mydb;

    return 0;
}

static int myclose(struct dbengine *db)
{
    struct db_list *ent = open_twoskip;
    struct db_list *prev = NULL;

    assert(db);

    /* remove this DB from the open list */
    while (ent && ent->db != db) {
        prev = ent;
        ent = ent->next;
    }
    assert(ent);

    if (--ent->refcount <= 0) {
        if (prev) prev->next = ent->next;
        else open_twoskip = ent->next;
        free(ent);
        if (mappedfile_islocked(db->mf))
            syslog(LOG_ERR, "twoskip: %s closed while still locked", FNAME(db));
        dispose_db(db);
    }

    return 0;
}

/*************** EXTERNAL APIS ***********************/

static int myfetch(struct dbengine *db,
            const char *key, size_t keylen,
            const char **foundkey, size_t *foundkeylen,
            const char **data, size_t *datalen,
            struct txn **tidptr, int fetchnext)
{
    int r = 0;

    assert(db);
    if (datalen) assert(data);

    if (data) *data = NULL;
    if (datalen) *datalen = 0;

    /* Hacky workaround:
     *
     * If no transaction was passed, but we're in a transaction,
     * then just do the read within that transaction.
     */
    if (!tidptr && db->current_txn)
        tidptr = &db->current_txn;

    if (tidptr) {
        if (!*tidptr) {
            r = newtxn(db, 0/*shared*/, tidptr);
            if (r) return r;
        }
    } else {
        /* grab a r lock */
        r = read_lock(db);
        if (r) return r;
    }

    r = find_loc(db, key, keylen);
    if (r) goto done;

    if (fetchnext) {
        r = advance_loc(db);
        if (r) goto done;
    }

    if (foundkey) *foundkey = db->loc.keybuf.s;
    if (foundkeylen) *foundkeylen = db->loc.keybuf.len;

    if (db->loc.is_exactmatch) {
        if (data) *data = VAL(db, &db->loc.record);
        if (datalen) *datalen = db->loc.record.vallen;
    }
    else {
        /* we didn't get an exact match */
        r = CYRUSDB_NOTFOUND;
    }

done:
    if (!tidptr) {
        /* release read lock */
        int r1;
        if ((r1 = unlock(db)) < 0) {
            return r1;
        }
    }

    return r;
}

/* foreach allows for subsidiary mailbox operations in 'cb'.
   if there is a txn, 'cb' must make use of it.
*/
static int myforeach(struct dbengine *db,
                     const char *prefix, size_t prefixlen,
                     foreach_p *goodp,
                     foreach_cb *cb, void *rock,
                     struct txn **tidptr)
{
    int r = 0, cb_r = 0;
    int num_misses = 0;
    int need_unlock = 0;
    const char *val;
    size_t vallen;
    struct buf keybuf = BUF_INITIALIZER;

    assert(db);
    assert(cb);
    if (prefixlen) assert(prefix);

    /* Hacky workaround:
     *
     * If no transaction was passed, but we're in a transaction,
     * then just do the read within that transaction.
     */
    if (!tidptr && db->current_txn)
        tidptr = &db->current_txn;
    if (tidptr) {
        if (!*tidptr) {
            r = newtxn(db, 0/*shared*/, tidptr);
            if (r) return r;
        }
    } else {
        /* grab a r lock */
        r = read_lock(db);
        if (r) return r;
        need_unlock = 1;
    }

    r = find_loc(db, prefix, prefixlen);
    if (r) goto done;

    if (!db->loc.is_exactmatch) {
        /* advance to the first match */
        r = advance_loc(db);
        if (r) goto done;
    }

    while (db->loc.is_exactmatch) {
        /* does it match prefix? */
        if (prefixlen) {
            if (db->loc.record.keylen < prefixlen) break;
            if (db->compar(KEY(db, &db->loc.record), prefixlen, prefix, prefixlen)) break;
        }

        val = VAL(db, &db->loc.record);
        vallen = db->loc.record.vallen;

        if (!goodp || goodp(rock, db->loc.keybuf.s, db->loc.keybuf.len,
                                  val, vallen)) {
            /* take a copy of they key - just in case cb does actions on this database
             * and clobbers loc */
            buf_copy(&keybuf, &db->loc.keybuf);

            if (!tidptr) {
                /* release read lock */
                r = unlock(db);
                if (r) goto done;
                need_unlock = 0;
            }

            /* make callback */
            cb_r = cb(rock, db->loc.keybuf.s, db->loc.keybuf.len,
                            val, vallen);
            if (cb_r) break;

            if (!tidptr) {
                /* grab a r lock */
                r = read_lock(db);
                if (r) goto done;
                need_unlock = 1;

                num_misses = 0;
            }

            /* should be cheap if we're already here */
            r = find_loc(db, keybuf.s, keybuf.len);
            if (r) goto done;
        }
        else if (!tidptr) {
            num_misses++;
            if (num_misses > FOREACH_LOCK_RELEASE) {
                /* take a copy of they key - just in case cb does actions on this database
                 * and clobbers loc */
                buf_copy(&keybuf, &db->loc.keybuf);

                /* release read lock */
                r = unlock(db);
                if (r) goto done;
                need_unlock = 0;

                /* grab a r lock */
                r = read_lock(db);
                if (r) goto done;
                need_unlock = 1;

                /* should be cheap if we're already here */
                r = find_loc(db, keybuf.s, keybuf.len);
                if (r) goto done;

                num_misses = 0;
            }
        }

        /* move to the next one */
        r = advance_loc(db);
        if (r) goto done;
    }

 done:

    buf_free(&keybuf);

    if (need_unlock) {
        /* release read lock */
        int r1 = unlock(db);
        if (r1) return r1;
    }

    return r ? r : cb_r;
}

/* helper function for all writes - wraps create and delete and the FORCE
 * logic for each */
static int skipwrite(struct dbengine *db,
                     const char *key, size_t keylen,
                     const char *data, size_t datalen,
                     int force)
{
    int r = find_loc(db, key, keylen);
    if (r) return r;

    /* could be a delete or a replace */
    if (db->loc.is_exactmatch) {
        if (!data) return delete_here(db);
        if (!force) return CYRUSDB_EXISTS;
        /* unchanged?  Save the IO */
        if (!db->compar(data, datalen,
                        VAL(db, &db->loc.record),
                        db->loc.record.vallen))
            return 0;
        return store_here(db, data, datalen);
    }

    /* only create if it's not a delete, obviously */
    if (data) return store_here(db, data, datalen);

    /* must be a delete - are we forcing? */
    if (!force) return CYRUSDB_NOTFOUND;

    return 0;
}

static int mycommit(struct dbengine *db, struct txn *tid)
{
    struct skiprecord newrecord;
    int r = 0;

    assert(db);
    assert(tid == db->current_txn);

    /* no need to commit if we're not dirty */
    if (!(db->header.flags & DIRTY))
        goto done;

    assert(db->current_txn);

    if (db->current_txn->shared) goto done;

    /* build a commit record */
    memset(&newrecord, 0, sizeof(struct skiprecord));
    newrecord.type = COMMIT;
    newrecord.nextloc[0] = db->header.current_size;

    /* append to the file */
    r = append_record(db, &newrecord, NULL, NULL);
    if (r) goto done;

    /* commit ALL outstanding changes first, before
     * rewriting the header */
    r = mappedfile_commit(db->mf);
    if (r) goto done;

    /* finally, update the header and commit again */
    db->header.current_size = db->end;
    db->header.flags &= ~DIRTY;
    r = commit_header(db);

 done:
    if (r) {
        int r2;

        /* error during commit; we must abort */
        r2 = myabort(db, tid);
        if (r2) {
            syslog(LOG_ERR, "DBERROR: twoskip %s: commit AND abort failed",
                   FNAME(db));
        }
    }
    else {
        if (db->current_txn && !db->current_txn->shared
            && !(db->open_flags & CYRUSDB_NOCOMPACT)
            && db->header.current_size > MINREWRITE
            && db->header.current_size > 2 * db->header.repack_size) {
            int r2 = mycheckpoint(db);
            if (r2) {
                syslog(LOG_NOTICE, "twoskip: failed to checkpoint %s: %m",
                       FNAME(db));
            }
        }
        else {
            unlock(db);
        }

        free(tid);
        db->current_txn = NULL;
    }

    return r;
}

static int myabort(struct dbengine *db, struct txn *tid)
{
    int r;

    assert(db);
    assert(tid == db->current_txn);

    /* free the tid */
    free(tid);
    db->current_txn = NULL;
    db->end = db->header.current_size;

    /* recovery will clean up */
    r = recovery1(db, NULL);

    buf_free(&db->loc.keybuf);
    memset(&db->loc, 0, sizeof(struct skiploc));

    unlock(db);

    return r;
}

static int mystore(struct dbengine *db,
            const char *key, size_t keylen,
            const char *data, size_t datalen,
            struct txn **tidptr, int force)
{
    struct txn *localtid = NULL;
    int r = 0;

    assert(db);
    assert(key && keylen);

    /* reject store for shared locks */
    if (tidptr && *tidptr && (*tidptr)->shared)
        return CYRUSDB_READONLY;

    /* not keeping the transaction, just create one local to
     * this function */
    if (!tidptr) tidptr = &localtid;

    /* make sure we're write locked and up to date */
    if (!*tidptr) {
        r = newtxn(db, 0/*shared*/, tidptr);
        if (r) return r;
    }

    r = skipwrite(db, key, keylen, data, datalen, force);

    if (r) {
        int r2 = myabort(db, *tidptr);
        *tidptr = NULL;
        return r2 ? r2 : r;
    }
    if (localtid) {
        /* commit the store, which releases the write lock */
        r = mycommit(db, localtid);
    }

    return r;
}

/* compress 'db', closing at the end.  Uses foreach to copy into a new
 * database, then rewrites over the old one */

struct copy_rock {
    struct dbengine *db;
    struct txn *tid;
};

static int copy_cb(void *rock,
                   const char *key, size_t keylen,
                   const char *val, size_t vallen)
{
    struct copy_rock *cr = (struct copy_rock *)rock;

    return mystore(cr->db, key, keylen, val, vallen, &cr->tid, 0);
}

static int mycheckpoint(struct dbengine *db)
{
    size_t old_size = db->header.current_size;
    char newfname[1024];
    clock_t start = sclock();
    struct copy_rock cr;
    int r = 0;

    r = myconsistent(db, db->current_txn);
    if (r) {
        syslog(LOG_ERR, "db %s, inconsistent pre-checkpoint, bailing out",
               FNAME(db));
        unlock(db);
        return r;
    }

    /* open fname.NEW */
    snprintf(newfname, sizeof(newfname), "%s.NEW", FNAME(db));
    unlink(newfname);

    cr.db = NULL;
    cr.tid = NULL;
    r = opendb(newfname, db->open_flags | CYRUSDB_CREATE, &cr.db, &cr.tid);
    if (r) return r;

    r = myforeach(db, NULL, 0, NULL, copy_cb, &cr, &db->current_txn);
    if (r) goto err;

    r = myconsistent(cr.db, cr.tid);
    if (r) {
        syslog(LOG_ERR, "db %s, inconsistent post-checkpoint, bailing out",
               FNAME(db));
        goto err;
    }

    /* remember the repack size */
    cr.db->header.repack_size = cr.db->end;

    /* increase the generation count */
    cr.db->header.generation = db->header.generation + 1;

    r = mycommit(cr.db, cr.tid);
    if (r) goto err;

    cr.tid = NULL;  /* avoid later errors trying to call abort, it's too late! */

    /* move new file to original file name */
    r = mappedfile_rename(cr.db->mf, FNAME(db));
    if (r) goto err;

    /* OK, we're committed now - clean up */
    unlock(db);

    /* gotta clean it all up */
    mappedfile_close(&db->mf);
    buf_free(&db->loc.keybuf);

    *db = *cr.db;
    free(cr.db); /* leaked? */

    {
        syslog(LOG_INFO,
               "twoskip: checkpointed %s (%llu record%s, %llu => %llu bytes) in %2.3f seconds",
               FNAME(db), (LLU)db->header.num_records,
               db->header.num_records == 1 ? "" : "s", (LLU)old_size,
               (LLU)(db->header.current_size),
               (sclock() - start) / (double) CLOCKS_PER_SEC);
    }

    return 0;

 err:
    if (cr.tid) myabort(cr.db, cr.tid);
    unlink(FNAME(cr.db));
    dispose_db(cr.db);
    unlock(db);
    return CYRUSDB_IOERROR;
}


/* dump the database.
   if detail == 1, dump all records.
   if detail == 2, also dump pointers for active records.
   if detail == 3, dump all records/all pointers.
*/
static int dump(struct dbengine *db, int detail)
{
    struct skiprecord record;
    struct buf scratch = BUF_INITIALIZER;
    size_t offset = DUMMY_OFFSET;
    int r = 0;
    int i;

    printf("HEADER: v=%lu fl=%lu num=%llu sz=(%08llX/%08llX)\n",
          (LU)db->header.version,
          (LU)db->header.flags,
          (LLU)db->header.num_records,
          (LLU)db->header.current_size,
          (LLU)db->header.repack_size);

    while (offset < db->header.current_size) {
        printf("%08llX ", (LLU)offset);

        // skip over blanks
        if (!memcmp(BASE(db) + offset, BLANK, 8)) {
            printf("BLANK\n");
            offset += 8;
            continue;
        }

        r = read_onerecord(db, offset, &record);

        if (r) {
            if (record.keyoffset)
                printf("ERROR [HEADCRC %08lX %08lX]\n",
                        (long unsigned) record.crc32_head,
                        (long unsigned) crc32_map(BASE(db) + record.offset,
                                                 record.keyoffset - 8));
            else
                printf("ERROR\n");
            break;
        }

        if (check_tailcrc(db, &record)) {
            printf("ERROR [TAILCRC %08lX %08lX] ",
                    (long unsigned) record.crc32_tail,
                    (long unsigned) crc32_map(BASE(db) + record.keyoffset,
                        roundup(record.keylen + record.vallen, 8)));
        }

        switch (record.type) {
        case DELETE:
            printf("DELETE ptr=%08llX\n", (LLU)record.nextloc[0]);
            break;

        case COMMIT:
            printf("COMMIT start=%08llX\n", (LLU)record.nextloc[0]);
            break;

        case RECORD:
        case DUMMY:
            buf_setmap(&scratch, KEY(db, &record), record.keylen);
            buf_replace_char(&scratch, '\0', '-');
            printf("%s kl=%llu dl=%llu lvl=%d (%s)\n",
                   (record.type == RECORD ? "RECORD" : "DUMMY"),
                   (LLU)record.keylen, (LLU)record.vallen,
                   record.level, buf_cstring(&scratch));
            printf("\t");
            for (i = 0; i <= record.level; i++) {
                printf("%08llX ", (LLU)record.nextloc[i]);
                if (!(i % 8))
                    printf("\n\t");
            }
            printf("\n");
            if (detail > 2) {
                buf_setmap(&scratch, VAL(db, &record), record.vallen);
                buf_replace_char(&scratch, '\0', '-');
                printf("\tv=(%s)\n", buf_cstring(&scratch));
            }
            break;
        }

        offset += record.len;
    }

    buf_free(&scratch);

    return r;
}

static int consistent(struct dbengine *db)
{
    int r;

    r = read_lock(db);
    if (r) return r;

    r = myconsistent(db, NULL);

    unlock(db);

    return r;
}

/* perform some basic consistency checks */
static int myconsistent(struct dbengine *db, struct txn *tid)
{
    struct skiprecord prevrecord;
    struct skiprecord record;
    size_t fwd[MAXLEVEL];
    size_t num_records = 0;
    int r = 0;
    int cmp;
    int i;

    assert(db->current_txn == tid); /* could both be null */

    /* read in the dummy */
    r = read_onerecord(db, DUMMY_OFFSET, &prevrecord);
    if (r) return r;

    /* set up the location pointers */
    for (i = 0; i < MAXLEVEL; i++)
        fwd[i] = _getloc(db, &prevrecord, i);

    while (fwd[0]) {
        r = read_onerecord(db, fwd[0], &record);
        if (r) return r;

        if (record.type == DELETE) {
            fwd[0] = record.nextloc[0];
            continue;
        }

        cmp = db->compar(KEY(db, &record), record.keylen,
                         KEY(db, &prevrecord), prevrecord.keylen);
        if (cmp <= 0) {
            xsyslog(LOG_ERR, "DBERROR: twoskip out of order",
                    "fname=<%s> key=<%.*s> offset=<%08llX>"
                    " prevkey=<%.*s> prevoffset=<%08llX)",
                    FNAME(db), (int)record.keylen, KEY(db, &record),
                    (LLU)record.offset,
                    (int)prevrecord.keylen, KEY(db, &prevrecord),
                    (LLU)prevrecord.offset);
            return CYRUSDB_INTERNAL;
        }

        for (i = 0; i < record.level; i++) {
            /* check the old pointer was to here */
            if (fwd[i] != record.offset) {
                syslog(LOG_ERR, "DBERROR: twoskip broken linkage %s: %08llX at %d, expected %08llX",
                       FNAME(db), (LLU)record.offset, i, (LLU)fwd[i]);
                return CYRUSDB_INTERNAL;
            }
            /* and advance to the new pointer */
            fwd[i] = _getloc(db, &record, i);
        }

        /* keep a copy for comparison purposes */
        num_records++;
        prevrecord = record;
    }

    for (i = 0; i < MAXLEVEL; i++) {
        if (fwd[i]) {
            syslog(LOG_ERR, "DBERROR: twoskip broken tail %s: %08llX at %d",
                   FNAME(db), (LLU)fwd[i], i);
            return CYRUSDB_INTERNAL;
        }
    }

    /* we walked the whole file and saw every pointer */

    if (num_records != db->header.num_records) {
        syslog(LOG_ERR, "DBERROR: twoskip record count mismatch %s: %llu should be %llu",
               FNAME(db), (LLU)num_records, (LLU)db->header.num_records);
        return CYRUSDB_INTERNAL;
    }

    return 0;
}

static int _copy_commit(struct dbengine *db, struct dbengine *newdb,
                        struct skiprecord *commit)
{
    struct txn *tid = NULL;
    struct skiprecord record;
    size_t offset;
    int r = 0;

    for (offset = commit->nextloc[0]; offset < commit->offset; offset += record.len) {
        // skip over blanks
        if (!memcmp(BASE(db) + offset, BLANK, 8)) {
            record.len = 8;
            continue;
        }

        r = read_onerecord(db, offset, &record);
        if (r) goto err;

        switch (record.type) {
        case DELETE:
            /* find the record we are deleting */
            r = read_onerecord(db, record.nextloc[0], &record);
            if (r) goto err;
            /* and delete it from the new DB */
            r = mystore(newdb, KEY(db, &record), record.keylen, NULL, 0, &tid, 1);
            if (r) goto err;
            break;
        case RECORD:
            /* store into the new DB */
            r = mystore(newdb, KEY(db, &record), record.keylen, VAL(db, &record), record.vallen, &tid, 1);
            if (r) goto err;
            break;
        default:
            r = CYRUSDB_IOERROR;
            goto err;
        }
    }

    return tid ? mycommit(newdb, tid) : 0;

err:
    if (tid) myabort(newdb, tid);
    return r;
}

/* recovery2 - the file is really screwed.  Basically, we
 * failed to run recovery.  Try reading out records from
 * the top and applying commits to a new file instead */
static int recovery2(struct dbengine *db, int *count)
{
    uint64_t oldcount = db->header.num_records;
    struct skiprecord record;
    struct dbengine *newdb = NULL;
    char newfname[1024];
    size_t offset;
    int r = 0;
    int dirty;

    /* open fname.NEW */
    snprintf(newfname, sizeof(newfname), "%s.NEW", FNAME(db));
    unlink(newfname);

    r = opendb(newfname, db->open_flags | CYRUSDB_CREATE, &newdb, NULL);
    if (r) return r;

    /* increase the generation count */
    newdb->header.generation = db->header.generation + 1;

    /* start with the dummy */
    dirty = 0;
    for (offset = DUMMY_OFFSET; offset < SIZE(db); offset += record.len) {
        // skip over blanks
        if (!memcmp(BASE(db) + offset, BLANK, 8)) {
            record.len = 8;
            continue;
        }
        // if this record fails to read, keep looking ahead for a commit,
        // and mark this entire transaction as dirty
        r = read_onerecord(db, offset, &record);
        if (r) {
            dirty++;
            syslog(LOG_ERR, "DBERROR: %s failed to read at %08llX in recovery2, continuing",
                   FNAME(db), (LLU)offset);
            record.len = 8;
            continue;
        }
        if (record.type == COMMIT) {
            if (!dirty) {
                r = _copy_commit(db, newdb, &record);
                if (r) {
                    syslog(LOG_ERR, "DBERROR: %s failed to apply commit at %08llX in recovery2, continuing",
                           FNAME(db), (LLU)offset);
                }
            }
            dirty = 0;
        }
    }

    if (!newdb->header.num_records) {
        /* no records found - almost certainly bogus, and even if not,
         * there's no point recovering a zero record file */
        syslog(LOG_ERR, "DBERROR: %s no records found in recovery2, aborting",
               FNAME(db));
        r = CYRUSDB_NOTFOUND;
        goto err;
    }

    /* regardless, we had a commit during create, and in any _copy_commit, so
     * rename into place */

    /* move new file to original file name */
    r = mappedfile_rename(newdb->mf, FNAME(db));
    if (r) goto err;

    /* OK, we're committed now - clean up */
    unlock(db);

    /* gotta clean it all up */
    mappedfile_close(&db->mf);
    buf_free(&db->loc.keybuf);

    *db = *newdb;
    free(newdb); /* leaked? */

    syslog(LOG_NOTICE, "twoskip: recovery2 %s - rescued %llu of %llu records",
           FNAME(db), (LLU)db->header.num_records, (LLU)oldcount);

    if (count) *count = db->header.num_records;

    return 0;

 err:
    unlink(FNAME(newdb));
    myclose(newdb);
    return r;
}

/* run recovery on this file.
 * always called with a write lock. */
static int recovery1(struct dbengine *db, int *count)
{
    size_t prev[MAXLEVEL+1];
    size_t next[MAXLEVEL+1];
    struct skiprecord record;
    struct skiprecord prevrecord;
    struct skiprecord fixrecord;
    size_t nextoffset = 0;
    uint64_t num_records = 0;
    int changed = 0;
    int r = 0;
    int cmp;
    int i;

    /* no need to run recovery if we're consistent */
    if (db_is_clean(db))
        return 0;

    assert(mappedfile_iswritelocked(db->mf));

    /* we can't recovery a file that's not created yet */
    assert(db->header.current_size > HEADER_SIZE);

    /* dirty the header if not already dirty */
    if (!(db->header.flags & DIRTY)) {
        db->header.flags |= DIRTY;
        r = commit_header(db);
        if (r) return r;
    }

    /* start with the dummy */
    r = read_onerecord(db, DUMMY_OFFSET, &prevrecord);
    if (r) return r;

    /* and pointers forwards */
    for (i = 2; i <= MAXLEVEL; i++) {
        prev[i] = prevrecord.offset;
        next[i] = prevrecord.nextloc[i];
    }

    /* check for broken level - pointers */
    for (i = 0; i < 2; i++) {
        if (prevrecord.nextloc[i] >= db->end) {
            prevrecord.nextloc[i] = 0;
            r = rewrite_record(db, &prevrecord);
            changed++;
        }
    }

    nextoffset = _getloc(db, &prevrecord, 0);

    while (nextoffset) {
        r = read_onerecord(db, nextoffset, &record);
        if (r) return r;

        /* just skip over delete records */
        if (record.type == DELETE) {
            nextoffset = record.nextloc[0];
            continue;
        }

        cmp = db->compar(KEY(db, &record), record.keylen,
                         KEY(db, &prevrecord), prevrecord.keylen);
        if (cmp <= 0) {
            syslog(LOG_ERR, "DBERROR: twoskip out of order %s: %.*s (%08llX) <= %.*s (%08llX)",
                   FNAME(db), (int)record.keylen, KEY(db, &record),
                   (LLU)record.offset,
                   (int)prevrecord.keylen, KEY(db, &prevrecord),
                   (LLU)prevrecord.offset);
            return CYRUSDB_INTERNAL;
        }

        /* check for old offsets needing fixing */
        for (i = 2; i <= record.level; i++) {
            if (next[i] != record.offset) {
                /* need to fix up the previous record to point here */
                r = read_onerecord(db, prev[i], &fixrecord);
                if (r) return r;

                /* XXX - optimise adjacent same records */
                fixrecord.nextloc[i] = record.offset;
                r = rewrite_record(db, &fixrecord);
                if (r) return r;
                changed++;
            }
            prev[i] = record.offset;
            next[i] = record.nextloc[i];
        }

        /* check for broken level - pointers */
        for (i = 0; i < 2; i++) {
            if (record.nextloc[i] >= db->end) {
                record.nextloc[i] = 0;
                r = rewrite_record(db, &record);
                if (r) return r;
                changed++;
            }
        }

        num_records++;

        /* find the next record */
        nextoffset = _getloc(db, &record, 0);

        prevrecord = record;
    }

    /* check for remaining offsets needing fixing */
    for (i = 2; i <= MAXLEVEL; i++) {
        if (next[i]) {
            /* need to fix up the previous record to point to the end */
            r = read_onerecord(db, prev[i], &fixrecord);
            if (r) return r;

            /* XXX - optimise, same as above */
            fixrecord.nextloc[i] = 0;
            r = rewrite_record(db, &fixrecord);
            if (r) return r;
            changed++;
        }
    }

    r = mappedfile_truncate(db->mf, db->header.current_size);
    if (r) return r;

    r = mappedfile_commit(db->mf);
    if (r) return r;

    /* clear the dirty flag */
    db->header.flags &= ~DIRTY;
    db->header.num_records = num_records;
    r = commit_header(db);
    if (r) return r;

    if (count) *count = changed;

    return 0;
}

static int recovery(struct dbengine *db)
{
    clock_t start = sclock();
    int count = 0;
    int r;

    /* no need to run recovery if we're consistent */
    if (db_is_clean(db))
        return 0;

    r = recovery1(db, &count);
    if (r) {
        syslog(LOG_ERR, "DBERROR: recovery1 failed %s, trying recovery2", FNAME(db));
        count = 0;
        r = recovery2(db, &count);
        if (r) return r;
    }

    {
        syslog(LOG_INFO,
               "twoskip: recovered %s (%llu record%s, %llu bytes) in %2.3f seconds - fixed %d offset%s",
               FNAME(db), (LLU)db->header.num_records,
               db->header.num_records == 1 ? "" : "s",
               (LLU)(db->header.current_size),
               (sclock() - start) / (double) CLOCKS_PER_SEC,
               count, count == 1 ? "" : "s");
    }

    return 0;
}

static int fetch(struct dbengine *mydb,
                 const char *key, size_t keylen,
                 const char **data, size_t *datalen,
                 struct txn **tidptr)
{
    assert(key);
    assert(keylen);
    return myfetch(mydb, key, keylen, NULL, NULL,
                   data, datalen, tidptr, 0);
}

static int fetchnext(struct dbengine *mydb,
                 const char *key, size_t keylen,
                 const char **foundkey, size_t *fklen,
                 const char **data, size_t *datalen,
                 struct txn **tidptr)
{
    return myfetch(mydb, key, keylen, foundkey, fklen,
                   data, datalen, tidptr, 1);
}

static int create(struct dbengine *db,
                  const char *key, size_t keylen,
                  const char *data, size_t datalen,
                  struct txn **tid)
{
    if (datalen) assert(data);
    return mystore(db, key, keylen, data ? data : "", datalen, tid, 0);
}

static int store(struct dbengine *db,
                 const char *key, size_t keylen,
                 const char *data, size_t datalen,
                 struct txn **tid)
{
    if (datalen) assert(data);
    return mystore(db, key, keylen, data ? data : "", datalen, tid, 1);
}

static int delete(struct dbengine *db,
                 const char *key, size_t keylen,
                 struct txn **tid, int force)
{
    return mystore(db, key, keylen, NULL, 0, tid, force);
}

/* twoskip compar function is set at open */
static int mycompar(struct dbengine *db, const char *a, int alen,
                    const char *b, int blen)
{
    return db->compar(a, alen, b, blen);
}

HIDDEN struct cyrusdb_backend cyrusdb_twoskip =
{
    "twoskip",                  /* name */

    &cyrusdb_generic_init,
    &cyrusdb_generic_done,
    &cyrusdb_generic_sync,
    &cyrusdb_generic_archive,
    &cyrusdb_generic_unlink,

    &myopen,
    &myclose,

    &fetch,
    &fetch,
    &fetchnext,

    &myforeach,
    &create,
    &store,
    &delete,

    &mycommit,
    &myabort,

    &dump,
    &consistent,
    &mycheckpoint,
    &mycompar
};
