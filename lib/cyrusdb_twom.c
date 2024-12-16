/* cyrusdb_twom.c - twoskip implementation with MVCC capability
 *
 * Copyright (c) 1994-2024 Carnegie Mellon University.  All rights reserved.
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
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "assert.h"
#include "bsearch.h"
#include "byteorder.h"
#include "cyrusdb.h"
#include "cyr_lock.h"
#include "libcyr_cfg.h"
#include "util.h"
#include "xmalloc.h"
#include "xunlink.h"

#define XXH_STATIC_LINKING_ONLY /* access advanced declarations */
#define XXH_INLINE_ALL          /* maximum optimise */
#define XXH_IMPLEMENTATION      /* access definitions */
#include "xxhash.h"

/********** TUNING *************/

/* don't bother rewriting if the database has less than this much extra */
#define MINREWRITE 16834
/* number of skiplist levels - 31 gives us binary search to 2^32 records.
 * limited to 255 by file format, but skiplist had 20, and that was enough
 * for most real uses.  31 is heaps. */
#define MAXLEVEL 31
/* should be 0.5 for binary search semantics */
#define PROB 0.5

/* release lock in foreach at least every N records */
#define FOREACH_LOCK_RELEASE 4096

/* format specifics */
#undef VERSION /* defined in config.h */
#define VERSION 1

/* type aliases */
#define LLU long long unsigned int
#define LU long unsigned int

/* record types */
#define DUMMY '*'
#define ADD '+'
#define REPLACE '='
#define DELETE '-'
#define COMMIT '$'

/********** DATA STRUCTURES *************/

/* A single "record" in the twom file.  This could be a
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
    size_t ancestor;
    size_t nextloc[MAXLEVEL+1];

    /* what do our integrity checks say? */
    uint32_t xxh_head;
    uint32_t xxh_tail;

    /* our key and value */
    size_t keyoffset;
    size_t valoffset;
};

/* a location in the twom file.  We always have:
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
    uint64_t generation;
    size_t end;
    uint32_t counter;
    unsigned readonly:1;
};

struct db_header {
    /* header info */
    uint32_t version;
    uint32_t flags;
    unsigned char uuid[16];
    uint64_t generation;
    uint64_t num_records;
    size_t dirty_size;
    size_t repack_size;
    size_t current_size;
    uint32_t maxlevel;
};

struct dbengine {
    /* file data */

    // mapped file
    int fd;
    char *fname;
    char *map_base;
    size_t map_size;

    struct db_header header;
    struct skiploc loc;
    struct skiprecord recs[2];

    /* tracking info */
    size_t end;
    struct txn *current_txn;

    unsigned char has_lock;
    unsigned int readonly:1;
    unsigned int noxxh:1;
    unsigned int nocompact:1;
};

struct db_list {
    struct dbengine *db;
    struct db_list *next;
    int refcount;
};

#define HEADER_MAGIC ("\241\002\213\015twomfile\0\0\0\0")
#define HEADER_MAGIC_SIZE (16)

/* offsets of header files */
enum {
    OFFSET_HEADER = 0,
    OFFSET_VERSION = 16,
    OFFSET_FLAGS = 20,
    OFFSET_UUID = 24,
    OFFSET_GENERATION = 40,
    OFFSET_NUM_RECORDS = 48,
    OFFSET_DIRTY_SIZE = 56,
    OFFSET_REPACK_SIZE = 64,
    OFFSET_CURRENT_SIZE = 72,
    OFFSET_MAXLEVEL = 80,
    OFFSET_XXH = 84,
};

#define HEADER_SIZE 88
#define DUMMY_OFFSET HEADER_SIZE
#define MAXRECORDHEAD ((MAXLEVEL + 6)*8)

/* mount a scratch monkey */
static union skipwritebuf {
    uint64_t align;
    char s[MAXRECORDHEAD];
} scratchspace;

static struct db_list *open_twom = NULL;

static int mycommit(struct dbengine *db, struct txn *tid);
static int myabort(struct dbengine *db, struct txn *tid);
static int mycheckpoint(struct dbengine *db);
static int myconsistent(struct dbengine *db, struct txn *tid);
static int recovery(struct dbengine *db);
static int recovery1(struct dbengine *db, int *count);

/************** HELPER FUNCTIONS ****************/

#define BASE(db) ((const char *)db->map_base)
#define KEY(db, rec) (BASE(db) + (rec)->keyoffset)
#define VAL(db, rec) (BASE(db) + (rec)->valoffset)
#define SIZE(db) (db->map_size)
#define FNAME(db) (db->fname)
#define LOCKED(db) (db->has_lock != 0)
#define WRITELOCKED(db) (db->has_lock == 2)
#define HASVALUE(type) ((type) == ADD || (type) == REPLACE)
#define HASANCESTOR(type) ((type) == REPLACE || (type) == DELETE)

// pad out to an 8 byte boundary
#define PAD8(n) (((n)+7)&~7)

/* choose a level appropriately randomly */
static inline uint8_t randlvl(uint8_t lvl, uint8_t maxlvl)
{
    while (((float) rand() / (float) (RAND_MAX)) < PROB) {
        lvl++;
        if (lvl == maxlvl) break;
    }
    return lvl;
}

/************** HEADER ****************/

#define xxh_map(base, len) (uint32_t)XXH3_64bits((base), (len))

#ifdef HAVE_DECLARE_OPTIMIZE
static uint32_t xxh_iovec(const struct iovec *iov, int nio)
    __attribute__((optimize("-O3")));
#endif
static uint32_t xxh_iovec(const struct iovec *iov, int nio)
{
    XXH3_state_t *state = XXH3_createState();
    XXH3_64bits_reset(state);
    int i;
    for (i = 0; i < nio; i++) {
        if (!iov[i].iov_len) continue;
        XXH3_64bits_update(state, iov[i].iov_base, iov[i].iov_len);
    }
    XXH64_hash_t const hash = XXH3_64bits_digest(state);
    XXH3_freeState(state);
    return (uint32_t)hash;
}

/* given an open, mapped db, read in the header information */
static int read_header(struct dbengine *db, struct db_header *header)
{
    const char *base = BASE(db);

    assert(db && base);

    if (SIZE(db) < HEADER_SIZE) {
        syslog(LOG_ERR,
               "twom: file not large enough for header: %s", FNAME(db));
        return CYRUSDB_IOERROR;
    }

    if (memcmp(base, HEADER_MAGIC, HEADER_MAGIC_SIZE)) {
        syslog(LOG_ERR, "twom: invalid magic header: %s", FNAME(db));
        return CYRUSDB_IOERROR;
    }

    header->version
        = ntohl(*((uint32_t *)(base + OFFSET_VERSION)));

    if (header->version > VERSION) {
        syslog(LOG_ERR, "twom: version mismatch: %s has version %d",
               FNAME(db), header->version);
        return CYRUSDB_IOERROR;
    }

    header->flags
        = ntohl(*((uint32_t *)(base + OFFSET_FLAGS)));

    memcpy(header->uuid, base + OFFSET_UUID, 16);

    header->generation
        = ntohll(*((uint64_t *)(base + OFFSET_GENERATION)));

    header->num_records
        = ntohll(*((uint64_t *)(base + OFFSET_NUM_RECORDS)));

    header->dirty_size
        = ntohll(*((uint64_t *)(base + OFFSET_DIRTY_SIZE)));

    header->repack_size
        = ntohll(*((uint64_t *)(base + OFFSET_REPACK_SIZE)));

    header->current_size
        = ntohll(*((uint64_t *)(base + OFFSET_CURRENT_SIZE)));

    header->maxlevel
        = ntohl(*((uint32_t *)(base + OFFSET_MAXLEVEL)));

    if (db->noxxh)
        return 0;

    uint32_t xxh = ntohl(*((uint32_t *)(base + OFFSET_XXH)));
    if (xxh_map(base, OFFSET_XXH) != xxh) {
        xsyslog(LOG_ERR, "DBERROR: twom header XXH failure",
                         "filename=<%s>",
                         FNAME(db));
        return CYRUSDB_IOERROR;
    }

    return 0;
}

static size_t mm_roundup(size_t offset)
{
    size_t page_size = 1<<14; // 16k
    return ((offset + offset / 4) + page_size - 1) & ~(page_size - 1);
}

static void mm_ensure(struct dbengine *db, size_t offset)
{
    if (offset <= db->map_size) return;

    assert(WRITELOCKED(db));

    offset = mm_roundup(offset);

    // XXX - error handling of truncate?
    ftruncate(db->fd, offset);
    munmap(db->map_base, db->map_size);
    db->map_size = offset;
    db->map_base = mmap((caddr_t)0, db->map_size, PROT_READ|PROT_WRITE, MAP_SHARED, db->fd, 0L);
}

static int twom_commit(struct dbengine *db)
{
    return msync(db->map_base, db->end, MS_SYNC|MS_INVALIDATE);
}

static size_t twom_writev(struct dbengine *db, const struct iovec *iov, int nio, size_t offset)
{
    int i;

    // first pass to calculate used space
    size_t len = 0;
    for (i = 0; i < nio; i++) {
        len += iov[i].iov_len;
    }
    mm_ensure(db, offset+len);

    // second pass to copy data
    len = 0;
    for (i = 0; i < nio; i++) {
        if (!iov[i].iov_len) continue;
        memcpy(db->map_base + offset + len, iov[i].iov_base, iov[i].iov_len);
        len += iov[i].iov_len;
    }

    return len;
}

static void twom_write(struct dbengine *db, const char *val, size_t len, size_t offset)
{
    mm_ensure(db, offset + len);
    memcpy(db->map_base + offset, val, len);
}

/* given an open, mapped, locked db, write the header information */
static int write_header(struct dbengine *db, struct db_header *header)
{
    char *buf = scratchspace.s;

    /* format one buffer */
    memcpy(buf, HEADER_MAGIC, HEADER_MAGIC_SIZE);
    *((uint32_t *)(buf + OFFSET_VERSION)) = htonl(header->version);
    *((uint32_t *)(buf + OFFSET_FLAGS)) = htonl(header->flags);
    *((uint64_t *)(buf + OFFSET_GENERATION)) = htonll(header->generation);
    memcpy(buf + OFFSET_UUID, header->uuid, 16);
    *((uint64_t *)(buf + OFFSET_NUM_RECORDS)) = htonll(header->num_records);
    *((uint64_t *)(buf + OFFSET_DIRTY_SIZE)) = htonll(header->dirty_size);
    *((uint64_t *)(buf + OFFSET_REPACK_SIZE)) = htonll(header->repack_size);
    *((uint64_t *)(buf + OFFSET_CURRENT_SIZE)) = htonll(header->current_size);
    *((uint32_t *)(buf + OFFSET_MAXLEVEL)) = htonl(header->maxlevel);
    *((uint32_t *)(buf + OFFSET_XXH)) = htonl(xxh_map(buf, OFFSET_XXH));

    /* write it out */
    twom_write(db, buf, HEADER_SIZE, 0);

    return 0;
}

/* simple wrapper to write with an fsync */
static int commit_header(struct dbengine *db)
{
    int r = write_header(db, &db->header);
    if (!r) r = twom_commit(db);
    return r;
}

/******************** RECORD *********************/

#ifdef HAVE_DECLARE_OPTIMIZE
static int check_tailxxh(struct dbengine *db, struct skiprecord *record)
    __attribute__((optimize("-O3")));
#endif
static int check_tailxxh(struct dbengine *db, struct skiprecord *record)
{
    if (db->noxxh)
        return 0;

    uint32_t xxh = record->keylen ? xxh_map(BASE(db) + record->keyoffset, PAD8(record->keylen + record->vallen + 2)) : 0;
    if (xxh != record->xxh_tail) {
        xsyslog(LOG_ERR, "DBERROR: invalid tail xxh",
                         "filename=<%s> offset=<%llX>",
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
    const char *base = BASE(db);
    size_t size = db->end;
    const char *ptr = base + offset;
    int i;

    // we set all the necessary fields during a read
    // memset(record, 0, sizeof(struct skiprecord));

    record->offset = offset;
    if (!offset) return 0;

    record->len = 24; /* absolute minimum */

    /* need space for at least the header plus some details */
    if (record->offset + record->len > size)
        goto badsize;

    /* read in the record header */
    record->type = ptr[0];
    record->level = ptr[1];
    record->keylen = ntohs(*((uint16_t *)(ptr + 2)));
    record->vallen = ntohl(*((uint32_t *)(ptr + 4)));
    offset += 8;

    /* make sure we fit */
    if (record->level > MAXLEVEL) {
        xsyslog(LOG_ERR, "DBERROR: twom invalid level",
                         "filename=<%s> level=<%d> offset=<%08llX>",
                         FNAME(db), record->level, (LLU)offset);
        return CYRUSDB_IOERROR;
    }

    /* long key */
    if (record->keylen == UINT16_MAX) {
        ptr = base + offset;
        record->keylen = ntohll(*((uint64_t *)ptr));
        offset += 8;
    }

    /* long value */
    if (record->vallen == UINT32_MAX) {
        ptr = base + offset;
        record->vallen = ntohll(*((uint64_t *)ptr));
        offset += 8;
    }

    /* we know the length now */
    record->len = (offset - record->offset) /* header including lengths */
                + 8 * (1 + record->level)   /* ptrs */
                + 8;                        /* xxhs */

    if (record->keylen)
        record->len += PAD8(record->keylen + record->vallen + 2);  /* keyval fields */
 
    /* ancestor pointer is extra */
    if (HASANCESTOR(record->type))
        record->len += 8;

    if (record->offset + record->len > size)
        goto badsize;

    if (HASANCESTOR(record->type)) {
        ptr = base + offset;
        record->ancestor = ntohll(*((uint64_t *)ptr));
        offset += 8;
    }

    for (i = 0; i <= record->level; i++) {
        ptr = base + offset;
        record->nextloc[i] = ntohll(*((uint64_t *)ptr));
        offset += 8;
    }

    ptr = base + offset;
    record->xxh_head = ntohl(*((uint32_t *)ptr));
    record->xxh_tail = ntohl(*((uint32_t *)(ptr+4)));
    if (record->keylen) {
        record->keyoffset = offset + 8;
        record->valoffset = record->keyoffset + record->keylen + 1;
    }

    if (db->noxxh)
        return 0;

    uint32_t xxh = xxh_map(base + record->offset, (offset - record->offset));
    if (xxh != record->xxh_head) {
        xsyslog(LOG_ERR, "DBERROR: twom checksum head error",
                         "filename=<%s> offset=<%08llX>",
                         FNAME(db), (LLU)offset);
        return CYRUSDB_IOERROR;
    }

    return 0;

badsize:
    syslog(LOG_ERR, "twom: attempt to read past end of file %s: %08llX > %08llX",
           FNAME(db), (LLU)record->offset + record->len, (LLU)SIZE(db));
    return CYRUSDB_IOERROR;
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

    if (HASANCESTOR(record->type)) {
        *((uint64_t *)(buf+len)) = htonll(record->ancestor);
        len += 8;
    }

    /* got pointers? */
    for (i = 0; i <= record->level; i++) {
        *((uint64_t *)(buf+len)) = htonll(record->nextloc[i]);
        len += 8;
    }

    /* NOTE: xxh_tail does not change */
    record->xxh_head = xxh_map(buf, len);
    *((uint32_t *)(buf+len)) = htonl(record->xxh_head);
    *((uint32_t *)(buf+len+4)) = htonl(record->xxh_tail);
    len += 8;

    *sizep = len;
}

/* only changing the record head, so only rewrite that much */
static void rewrite_record(struct dbengine *db, struct skiprecord *record)
{
    char *buf = scratchspace.s;
    size_t len;

    /* we must already be in a transaction before updating records */
    assert(db->header.flags & DIRTY);
    assert(record->offset);

    prepare_record(record, buf, &len);

    twom_write(db, buf, len, record->offset);
}

static void write_nokeyrecord(struct dbengine *db, struct skiprecord *record)
{
    size_t iolen = 0;

    assert(!record->offset);

    record->xxh_tail = 0;
    prepare_record(record, scratchspace.s, &iolen);

    /* write to the mapped file, getting the offset updated */
    twom_write(db, scratchspace.s, iolen, db->end);

    /* locate the record */

    record->offset = db->end;
    record->keyoffset = 0;
    record->valoffset = 0;
    record->len = iolen;

    /* and advance the known file size */
    db->end += iolen;
}

/* you can only write records at the end */
static void write_record(struct dbengine *db, struct skiprecord *record,
                         const char *key, const char *val)
{
    char zeros[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t len;
    size_t iolen = 0;
    struct iovec io[6];

    assert(!record->offset);

    /* we'll put the HEAD on later */
    io[0].iov_base = scratchspace.s;
    io[0].iov_len = 0;

    io[1].iov_base = (char *)key;
    io[1].iov_len = record->keylen;

    io[2].iov_base = zeros;
    io[2].iov_len = 1;

    io[3].iov_base = (char *)val;
    io[3].iov_len = record->vallen;

    io[4].iov_base = zeros;
    io[4].iov_len = 1;

    /* pad to 8 bytes */
    len = record->vallen + record->keylen + 2;
    io[5].iov_base = zeros;
    io[5].iov_len = PAD8(len) - len;

    /* calculate the XXH of the tail first */
    record->xxh_tail = xxh_iovec(io+1, 5);

    /* prepare the record once we know the xxh of the tail */
    prepare_record(record, scratchspace.s, &iolen);
    io[0].iov_base = scratchspace.s;
    io[0].iov_len = iolen;

    /* write to the mapped file, getting the offset updated */
    size_t n = twom_writev(db, io, 6, db->end);

    /* locate the record */
    record->offset = db->end;
    record->keyoffset = db->end + io[0].iov_len;
    record->valoffset = record->keyoffset + record->keylen;
    record->len = n;

    /* and advance the known file size */
    db->end += n;
}

/* helper to append a record, starting the transaction by dirtying the
 * header first if required */
static int append_record(struct dbengine *db, struct skiprecord *record,
                         const char *key, const char *val)
{
    assert(db->current_txn);

    /* dirty the header if not already dirty */
    if (!(db->header.flags & DIRTY)) {
        db->header.flags |= DIRTY;
        int r = commit_header(db);
        if (r) return r;
    }

    if (key) write_record(db, record, key, val);
    else write_nokeyrecord(db, record);

    return 0;
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
static int relocate(struct dbengine *db, struct skiploc *loc)
    __attribute__((optimize("-O3")));
#endif
static int relocate(struct dbengine *db, struct skiploc *loc)
{
    struct skiprecord *rec = &db->recs[0];
    struct skiprecord *next = &db->recs[1];
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
    r = read_onerecord(db, DUMMY_OFFSET, rec);
    loc->is_exactmatch = 0;

    /* initialise pointers */
    level = rec->level;
    loc->backloc[level] = rec->offset;
    loc->forwardloc[level] = 0;

    /* special case start pointer for efficiency */
    if (!loc->keybuf.len) {
        for (i = 0; i < level; i++) {
            loc->backloc[i] = rec->offset;
            loc->forwardloc[i] = _getloc(db, rec, i);
        }
        loc->record = *rec;
        return 0;
    }

    while (level) {
        offset = _getloc(db, rec, level-1);

        loc->backloc[level-1] = rec->offset;
        loc->forwardloc[level-1] = offset;

        if (offset != oldoffset) {
            oldoffset = offset;
            r = read_onerecord(db, offset, next);
            if (r) return r;

            if (next->offset) {
                assert(next->level >= level);

                cmp = bsearch_ncompare_raw(KEY(db, next), next->keylen,
                                           loc->keybuf.s, loc->keybuf.len);

                /* not there?  stay at this level */
                if (cmp < 0) {
                    /* move the offset range along */
                    struct skiprecord *temp = rec;
                    rec = next;
                    next = temp;
                    continue;
                }
            }
        }

        level--;
    }

    if (cmp == 0) { /* we found it exactly */
        loc->is_exactmatch = 1;

        for (i = 0; i < next->level; i++)
            loc->forwardloc[i] = _getloc(db, next, i);

        /* make sure this record is complete */
        r = check_tailxxh(db, next);

        loc->record = *next;

        if (r) return r;
    }
    else {
        // we didn't get a match, so point to the previous record
        loc->record = *rec;
    }


    return 0;
}

/* helper function to find a location, either by using the existing
 * location if it's close enough, or using the full relocate above */
static int find_loc(struct dbengine *db, struct skiploc *loc, const char *key, size_t keylen)
{
    struct skiprecord *rec = &db->recs[0];
    int cmp, i, r;

    if (key != loc->keybuf.s)
        buf_setmap(&loc->keybuf, key, keylen);
    else if (keylen != loc->keybuf.len)
        buf_truncate(&loc->keybuf, keylen);

    /* can we special case advance? */
    if (keylen && loc->end == db->end
               && loc->generation == db->header.generation) {
        cmp = bsearch_ncompare_raw(KEY(db, &loc->record), loc->record.keylen,
                         loc->keybuf.s, loc->keybuf.len);
        /* same place, and was exact.  Otherwise we're going back,
         * and the reverse pointers are no longer valid... */
        if (loc->is_exactmatch && cmp == 0) {
            return 0;
        }

        /* we're looking after this record */
        if (cmp < 0) {
            for (i = 0; i < loc->record.level; i++)
                loc->backloc[i] = loc->record.offset;

            /* read the next record */
            r = read_onerecord(db, loc->forwardloc[0], rec);
            if (r) return r;

            /* nothing afterwards? */
            if (!rec->offset) {
                loc->is_exactmatch = 0;
                return 0;
            }

            /* now where is THIS record? */
            cmp = bsearch_ncompare_raw(KEY(db, rec), rec->keylen,
                                       loc->keybuf.s, loc->keybuf.len);

            /* exact match? */
            if (cmp == 0) {
                loc->is_exactmatch = 1;
                loc->record = *rec;

                for (i = 0; i < rec->level; i++)
                    loc->forwardloc[i] = _getloc(db, rec, i);

                /* make sure this record is complete */
                return check_tailxxh(db, rec);
            }

            /* or in the gap */
            if (cmp > 0) {
                loc->is_exactmatch = 0;
                return 0;
            }
        }
        /* if we fell out here, it's not a "local" record, just search */
    }

    return relocate(db, loc);
}

/* helper function to advance to the "next" record.  Used by foreach,
 * fetchnext, and internal functions */
static int advance_loc(struct dbengine *db, struct skiploc *loc)
{
    uint8_t i;
    int r;

    /* has another session made changes?  Need to re-find the location */
    if (loc->end != db->end || loc->generation != db->header.generation) {
        r = relocate(db, loc);
        if (r) return r;
    }

    /* update back pointers */
    for (i = 0; i < loc->record.level; i++)
        loc->backloc[i] = loc->record.offset;

    /* ADVANCE */
    r = read_onerecord(db, loc->forwardloc[0], &loc->record);
    if (r) return r;

    /* reached the end? */
    if (!loc->record.offset) {
        buf_reset(&loc->keybuf);
        return relocate(db, loc);
    }

    /* update forward pointers */
    for (i = 0; i < loc->record.level; i++)
        loc->forwardloc[i] = _getloc(db, &loc->record, i);

    /* keep our location */
    buf_setmap(&loc->keybuf, KEY(db, &loc->record), loc->record.keylen);
    loc->is_exactmatch = 1;

    /* make sure this record is complete */
    r = check_tailxxh(db, &loc->record);
    if (r) return r;

    return 0;
}

/* helper function to update all the back records efficiently
 * after appending a new record, either create or delete.  The
 * caller must set forwardloc[] correctly for each level it has
 * changed */
static int stitch(struct dbengine *db, struct skiploc *loc, uint8_t maxlevel, size_t newoffset)
{
    struct skiprecord *rec = &db->recs[0];
    uint8_t i;
    int r;

    rec->level = 0;
    while (rec->level < maxlevel) {
        uint8_t level = rec->level;

        r = read_onerecord(db, loc->backloc[level], rec);
        if (r) return r;

        /* always getting higher */
        assert(rec->level > level);

        for (i = level; i < maxlevel; i++)
            _setloc(db, rec, i, loc->forwardloc[i]);

        rewrite_record(db, rec);
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
   All updates funnel through here.  NULL val means
   deletion.   Force is implied here, it gets checked higher. */
static int store_here(struct dbengine *db, const char *val, size_t vallen)
{
    struct skiploc *loc = &db->loc;
    struct skiprecord newrecord;
    uint64_t ancestor = 0;
    uint8_t level = 0;
    uint8_t i;
    int r;
    int type = ADD;

    if (vallen) assert(val);

    if (loc->is_exactmatch) {
        level = loc->record.level;
        ancestor = loc->record.offset;
        // if it's not already a delete
        if (HASVALUE(loc->record.type)) {
            db->header.num_records--;
            db->header.dirty_size += loc->record.len;
        }
        // new type might be a delete too
        type = val ? REPLACE : DELETE;
    }
    else {
        assert(val);
    }

    /* build a new record */
    memset(&newrecord, 0, sizeof(struct skiprecord));
    newrecord.type = type;
    newrecord.level = level ? level : randlvl(1, MAXLEVEL);
    newrecord.keylen = loc->keybuf.len;
    newrecord.vallen = vallen;
    newrecord.ancestor = ancestor;
    for (i = 0; i < newrecord.level; i++)
        newrecord.nextloc[i+1] = loc->forwardloc[i];

    /* append to the file */
    r = append_record(db, &newrecord, loc->keybuf.s, val);
    if (r) return r;

    /* get the nextlevel to point here for all this record's levels */
    for (i = 0; i < newrecord.level; i++)
        loc->forwardloc[i] = newrecord.offset;

    /* update all backpointers */
    r = stitch(db, loc, newrecord.level, newrecord.offset);
    if (r) return r;

    /* update header to know details of new record */
    if (val) db->header.num_records++;
    else db->header.dirty_size += newrecord.len;

    /* track the highest level in this DB */
    if (newrecord.level > db->header.maxlevel)
        db->header.maxlevel = newrecord.level;

    loc->is_exactmatch = 1;
    loc->end = db->end;

    return 0;
}

/************ DATABASE STRUCT AND TRANSACTION MANAGEMENT **************/

static int db_is_clean(struct dbengine *db)
{
    if (db->header.flags & DIRTY)
        return 0;

    return 1;
}

static int unlock(struct dbengine *db)
{
    struct flock fl;

    if (db->current_txn)
        assert(db->current_txn->readonly);

    for (;;) {
        fl.l_type= F_UNLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        if (fcntl(db->fd, F_SETLKW, &fl) < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        break;
    }

    db->has_lock = 0;

    return 0;
}

static int write_lock(struct dbengine *db)
{
    if (db->readonly) return CYRUSDB_LOCKED;

    assert (!db->current_txn);

    struct stat sbuf, sbuffile;
    struct flock fl;

    for (;;) {
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        if (fcntl(db->fd, F_SETLKW, &fl) < 0) {
            if (errno = EINTR) continue;
            xsyslog(LOG_ERR, "IOERROR: lock_exclusive failed",
                             "filename=<%s>", db->fname);
            return -EIO;
        }

        if (fstat(db->fd, &sbuf) == -1) {
            xsyslog(LOG_ERR, "IOERROR: fstat failed",
                             "filename=<%s>", db->fname);
            unlock(db);
            return -EIO;
        }

        if (stat(db->fname, &sbuffile) == -1) {
            xsyslog(LOG_ERR, "IOERROR: stat failed",
                             "filename=<%s>", db->fname);
            unlock(db);
            return -EIO;
        }

        if (sbuf.st_ino == sbuffile.st_ino) break;

        // new file, unmap the old one
        if (db->map_size) {
            munmap(db->map_base, db->map_size);
            db->map_base = NULL;
            db->map_size = 0;
        }

        int newfd = open(db->fname, O_RDWR, 0644);
        if (newfd == -1) {
            xsyslog(LOG_ERR, "IOERROR: open failed",
                             "filename=<%s>", db->fname);
            unlock(db);
            return -EIO;
        }
        dup2(newfd, db->fd);
        close(newfd);
    }

    db->has_lock = 2;

    // opening a new file only
    if (!sbuf.st_size) return 0;

    if (db->map_size < (size_t)sbuf.st_size) {
        if (db->map_size) munmap(db->map_base, db->map_size);
        db->map_size = sbuf.st_size;
        db->map_base = mmap((caddr_t)0, db->map_size, PROT_READ|PROT_WRITE, MAP_SHARED, db->fd, 0L);
    }

    /* reread header */
    int r = read_header(db, &db->header);
    if (r) return r;
    db->end = db->header.current_size;

    /* recovery checks for consistency */
    if (!db_is_clean(db)) {
        r = recovery(db);
        if (r) return r;
    }

    return 0;
}

static int read_lock(struct dbengine *db)
{
    struct stat sbuf, sbuffile;
    int r = 0;
    struct flock fl;

    for (;;) {
        fl.l_type = F_RDLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0; 
        if (fcntl(db->fd, F_SETLKW, &fl) < 0) {
            if (errno = EINTR) continue;
            xsyslog(LOG_ERR, "IOERROR: lock_shared failed",
                             "filename=<%s>", db->fname);
            return -EIO;
        }

        if (fstat(db->fd, &sbuf) == -1) {
            xsyslog(LOG_ERR, "IOERROR: fstat failed",
                             "filename=<%s>", db->fname);
            unlock(db);
            return -EIO;
        }

        // re-locking in a transaction, we never change files
        if (db->current_txn) {
            db->current_txn->counter = 0; // we start counting again
            break;
        }

        if (stat(db->fname, &sbuffile) == -1) {
            xsyslog(LOG_ERR, "IOERROR: stat failed",
                             "filename=<%s>", db->fname);
            unlock(db);
            return -EIO;
        }
        if (sbuf.st_ino == sbuffile.st_ino) break;

        // new file, unmap the old one
        if (db->map_size) {
            munmap(db->map_base, db->map_size);
            db->map_base = NULL;
            db->map_size = 0;
        }

        int newfd = open(db->fname, db->readonly ? O_RDONLY : O_RDWR, 0644);
        if (newfd == -1) {
            xsyslog(LOG_ERR, "IOERROR: open failed",
                             "filename=<%s>", db->fname);
            unlock(db);
            return -EIO;
        }
        dup2(newfd, db->fd);
        close(newfd);
    }

    db->has_lock = 1;

    if (db->map_size < (size_t)sbuf.st_size) {
        if (db->map_size) munmap(db->map_base, db->map_size);
        db->map_size = sbuf.st_size;
        db->map_base = mmap((caddr_t)0, db->map_size, db->readonly ? PROT_READ : PROT_READ|PROT_WRITE, MAP_SHARED, db->fd, 0L);
    }

    /* reread header */
    r = read_header(db, &db->header);
    if (r) return r;
    db->end = db->header.current_size;

    /* we can't read an unclean database */
    if (!db_is_clean(db)) {
        /* we nave to be able to re-lock safely */
        if (db->current_txn) return -EIO;
        if (db->readonly) return -EIO;
        /* if we take a write lock, that will repair it */
        unlock(db);
        r = write_lock(db);
        if (r) return r;
        /* downgrade to a read lock again, since that what
         * was requested */
        unlock(db);
        return read_lock(db);
    }

    return 0;
}

static void _newtxn_helper(struct dbengine *db, int readonly, struct txn **tidptr)
{
    /* create the transaction */
    struct txn *txn = xzmalloc(sizeof(struct txn));
    txn->generation = db->header.generation;
    txn->end = db->end;
    txn->readonly = readonly;
    db->current_txn = txn;

    /* pass it back out */
    *tidptr = txn;
}

static int newtxn(struct dbengine *db, int readonly, struct txn **tidptr)
{
    int r;

    assert(!db->current_txn);
    assert(!*tidptr);

    /* grab a lock */
    r = readonly ? read_lock(db) : write_lock(db);
    if (r) return r;

    _newtxn_helper(db, readonly, tidptr);

    return 0;
}

static void dispose_db(struct dbengine *db)
{
    if (!db) return;

    if (db->fd != -1) {
        close(db->fd);
        db->fd = -1;
        db->has_lock = 0;
    }

    if (db->map_size) {
        munmap(db->map_base, db->map_size);
        db->map_base = NULL;
        db->map_size = 0;
    }

    buf_free(&db->loc.keybuf);

    free(db);
}

/************************************************************/

static int mylock(struct dbengine *db, struct txn **mytid, int flags)
{
    return newtxn(db, flags & CYRUSDB_SHARED, mytid);
}

static int opendb(const char *fname, int flags, struct dbengine **ret, struct txn **mytid)
{
    struct dbengine *db;
    int r;
    int create = (flags & CYRUSDB_CREATE) ? 1 : 0;

    assert(fname);
    assert(ret);

    db = (struct dbengine *) xzmalloc(sizeof(struct dbengine));
    db->readonly = (flags & CYRUSDB_SHARED) ? 1 : 0;
    db->nocompact = (flags & CYRUSDB_NOCOMPACT) ? 1 : 0;
    db->noxxh = (flags & CYRUSDB_NOCRC) ? 1 : 0;
    db->fname = xstrdup(fname);

    // XXX - open readonly for readonly DB?
    int fflags = db->readonly ? O_RDONLY : (create ? O_RDWR|O_CREAT : O_RDWR);
    db->fd = open(db->fname, fflags, 0644);
    if (db->fd < 0 && errno == ENOENT) {
        if (!create || db->readonly) {
            r = CYRUSDB_NOTFOUND;
            goto done;
        }
        r = cyrus_mkdir(db->fname, 0755);
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: cyrus_mkdir failed",
                             "filename=<%s>", db->fname);
            goto done;
        }
        db->fd = open(db->fname, fflags, 0644);
        if (db->fd < 0) {
            r = CYRUSDB_IOERROR;
            goto done;
        }
    }

    if (db->readonly) {
        /* grab a read lock to read the header */
        r = read_lock(db);
        if (r) goto done;
    }
    else {
        /* we either need a write lock or are fixing */
        r = write_lock(db);
        if (r) goto done;
    }

    /* if the map size is zero, it's a new file - we need to create an
     * initial header */
    if (!db->map_size) {
        struct skiprecord dummy;

        /* create the dummy! */
        memset(&dummy, 0, sizeof(struct skiprecord));
        dummy.type = DUMMY;
        dummy.level = MAXLEVEL;

        /* append dummy after header location */
        db->end = DUMMY_OFFSET;
        write_nokeyrecord(db, &dummy);

        /* create the header */
        db->header.version = VERSION;
        db->header.flags = 0;
        int i;
        for (i = 0; i < 16; i++) {
            db->header.uuid[i] = rand() % 256;
        }
        db->header.generation = 1;
        db->header.num_records = 0;
        db->header.dirty_size = 0;
        db->header.repack_size = db->end;
        db->header.current_size = db->end;
        db->header.maxlevel = 0;
        r = commit_header(db);
        if (r) {
            xsyslog(LOG_ERR, "DBERROR: error writing header",
                             "filename=<%s>",
                             fname);
            goto done;
        }
    }

    if (!db_is_clean(db)) {
        if (db->readonly) return CYRUSDB_IOERROR;

        /* recovery will clean the flag once it's committed the fixes */
        r = recovery(db);
        if (r) goto done;
    }

    if (mytid) {
        _newtxn_helper(db, db->readonly, mytid);
    }
    else {
        unlock(db);
    }

    *ret = db;

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
    for (ent = open_twom; ent; ent = ent->next) {
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
    ent->next = open_twom;
    open_twom = ent;

    /* return the open DB */
    *ret = mydb;

    return 0;
}

static int myclose(struct dbengine *db)
{
    struct db_list *ent = open_twom;
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
        else open_twom = ent->next;
        free(ent);
        if (LOCKED(db))
            syslog(LOG_ERR, "twom: %s closed while still locked", FNAME(db));
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
    struct txn *localtid = NULL;
    struct skiploc *loc = &db->loc;

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
            r = newtxn(db, db->readonly, tidptr);
            if (r) return r;
        }
        else if (!db->has_lock) {
            r = read_lock(db);
            if (r) return r;
            (*tidptr)->counter = 0;
        }
    } else {
        /* grab a r lock */
        tidptr = &localtid;
        r = newtxn(db, 1/*shared*/, tidptr);
        if (r) return r;
    }

    (*tidptr)->counter++;

    r = find_loc(db, loc, key, keylen);
    if (r) goto done;

    if (fetchnext) {
        r = advance_loc(db, loc);
        if (r) goto done;
    }

    if (foundkey) *foundkey = loc->keybuf.s;
    if (foundkeylen) *foundkeylen = loc->keybuf.len;

    // if there's no match, this key never existed
    if (!db->loc.is_exactmatch) {
        /* we didn't get an exact match */
        r = CYRUSDB_NOTFOUND;
        goto done;
    }

    struct skiprecord *rec = &loc->record;
    while (rec->offset >= (*tidptr)->end) {
        // no ancestor, it's not found
        if (!HASANCESTOR(rec->type)) {
            r = CYRUSDB_NOTFOUND;
            goto done;
        }
        // let's check the ancestor;
        int r = read_onerecord(db, rec->ancestor, &db->recs[0]);
        if (r) goto done;
        rec = &db->recs[0];
    }

    if (HASVALUE(rec->type)) {
        if (data) *data = VAL(db, rec);
        if (datalen) *datalen = rec->vallen;
    }
    else {
        /* active ancestor must have been a delete */
        r = CYRUSDB_NOTFOUND;
    }

done:
    // commit is fine for empty transactions
    if (localtid) {
        int r1 = mycommit(db, localtid);
        if (r1) return r1;
    }
    else if ((*tidptr)->readonly && (*tidptr)->counter > FOREACH_LOCK_RELEASE) {
        int r1 = unlock(db);
        if (r1) return r1;
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
    struct txn *localtid = NULL;
    const char *val;
    size_t vallen;
    struct buf keybuf = BUF_INITIALIZER;
    struct skiploc myloc;

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
            r = newtxn(db, db->readonly, tidptr);
            if (r) return r;
        }
        else if (!db->has_lock) {
            r = read_lock(db);
            if (r) return r;
            (*tidptr)->counter = 0;
        }
    } else {
        /* grab a r lock */
        tidptr = &localtid;
        r = newtxn(db, 1/*shared*/, tidptr);
        if (r) return r;
    }

    memset(&myloc, 0, sizeof(struct skiploc));
    struct skiploc *loc = &myloc;

    r = find_loc(db, loc, prefix, prefixlen);
    if (r) goto done;

    if (!loc->is_exactmatch) {
        /* advance to the first match */
        r = advance_loc(db, loc);
        if (r) goto done;
    }

    while (loc->is_exactmatch) {
        /* does it match prefix? */
        if (prefixlen) {
            if (loc->record.keylen < prefixlen) break;
            if (bsearch_ncompare_raw(KEY(db, &loc->record), prefixlen, prefix, prefixlen)) break;
        }

        // release locks every N records 
        if ((*tidptr)->readonly && (*tidptr)->counter > FOREACH_LOCK_RELEASE) {
            r = unlock(db);
            if (r) goto done;

            r = read_lock(db);
            if (r) goto done;

            (*tidptr)->counter = 0;

            /* should be cheap if we're already here */
            r = relocate(db, loc);
            if (r) goto done;
        }

        (*tidptr)->counter++;

        struct skiprecord *rec = &loc->record;
        while (rec->offset >= (*tidptr)->end) {
            if (!HASANCESTOR(rec->type)) goto next;
            r = read_onerecord(db, rec->ancestor, &db->recs[0]);
            if (r) goto done;
            rec = &db->recs[0];
        }

        if (!HASVALUE(rec->type)) goto next;

        val = VAL(db, rec);
        vallen = rec->vallen;

        if ((!goodp || goodp(rock, loc->keybuf.s, loc->keybuf.len,
                                  val, vallen))) {
            if (localtid) {
                r = mycommit(db, localtid);
                localtid = NULL;
                if (r) goto done;

                /* make callback */
                cb_r = cb(rock, loc->keybuf.s, loc->keybuf.len,
                          val, vallen);
                if (cb_r) break;

                r = newtxn(db, 1/*shared*/, tidptr);
                if (r) goto done;
            }
            else {
                /* just make the callback */
                cb_r = cb(rock, loc->keybuf.s, loc->keybuf.len,
                          val, vallen);
                if (cb_r) break;
            }

            r = find_loc(db, loc, loc->keybuf.s, loc->keybuf.len);
            if (r) goto done;
        }

    next:
        /* move to the next one */
        r = advance_loc(db, loc);
        if (r) goto done;
    }

 done:

    buf_free(&keybuf);
    buf_free(&myloc.keybuf);

    if (localtid) {
        /* release read lock */
        int r1 = mycommit(db, localtid);
        if (r1) return r1;
    }
    else if ((*tidptr)->readonly && (*tidptr)->counter > FOREACH_LOCK_RELEASE) {
        int r1 = unlock(db);
        if (r1) goto done;
    }

    return r ? r : cb_r;
}

static int myyield(struct dbengine *db)
{
    if (WRITELOCKED(db))
        return CYRUSDB_LOCKED;
    if (LOCKED(db))
        return unlock(db);
    return 0;
}

static int myreplay(struct dbengine *db,
                    foreach_cb *cb, void *rock)
{
    struct skiprecord *recp = &db->recs[0];
    int r;

    while (db->current_txn->end < db->end) {
        if (db->current_txn->counter > FOREACH_LOCK_RELEASE && db->current_txn->readonly) {
            r = unlock(db);
            if (r) return r;
            r = read_lock(db);
            if (r) return r;
            db->current_txn->counter = 0;
        }
        db->current_txn->counter++;
        r = read_onerecord(db, db->current_txn->end, recp);
        if (r) return r;
        const char *val = HASVALUE(recp->type) ? VAL(db, recp) : NULL;
        r = cb(rock, KEY(db, recp), recp->keylen, val, recp->vallen);
        if (r) return r;
        db->current_txn->end += recp->len;
    }

    return 0;
}

/* helper function for all writes - wraps create and delete and the FORCE
 * logic for each */
static int skipwrite(struct dbengine *db,
                     const char *key, size_t keylen,
                     const char *data, size_t datalen,
                     int force)
{
    struct skiploc *loc = &db->loc;
    int r = find_loc(db, loc, key, keylen);
    if (r) return r;

    /* could be a delete or a replace */
    if (loc->is_exactmatch && HASVALUE(loc->record.type)) {
        if (!data) return store_here(db, NULL, 0);
        if (!force) return CYRUSDB_EXISTS;
        /* unchanged?  Save the IO */
        if (!bsearch_ncompare_raw(data, datalen,
                        VAL(db, &loc->record),
                        loc->record.vallen))
            return 0;
        return store_here(db, data, datalen);
    }

    /* only create if it's not a delete, obviously */
    if (data) return store_here(db, data, datalen);

    /* must be a delete - are we forcing? */
    if (!force) return CYRUSDB_NOTFOUND;

    return 0;
}

struct dcrock {
    char *fname;
    int flags;
    uint64_t generation;
};

static void _delayed_checkpoint_free(void *rock)
{
    struct dcrock *drock = rock;
    free(drock->fname);
    free(drock);
}

static void _delayed_checkpoint(void *rock)
{
    struct dcrock *drock = rock;
    struct dbengine *db = NULL;
    int r = myopen(drock->fname, drock->flags, &db, NULL);
    if (r == CYRUSDB_NOTFOUND) {
        syslog(LOG_INFO, "twom: no file to delayed checkpoint for %s",
               drock->fname);
    }
    else if (r) {
        syslog(LOG_ERR, "DBERROR: opening %s for checkpoint: %s",
               drock->fname, cyrusdb_strerror(r));
    }
    else if (db->header.generation == drock->generation) {
        // if it hasn't already happened
        mycheckpoint(db);
    }
    else {
        syslog(LOG_INFO, "twom: delayed checkpoint already done %s (%llu %llu)",
               drock->fname, (LLU)db->header.generation, (LLU)drock->generation);
    }
    if (db) myclose(db);
}

static int myabort_locked(struct dbengine *db, struct txn *tid)
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

    return r;
}

static int mycommit_locked(struct dbengine *db, struct txn *tid)
{
    struct skiprecord newrecord;
    int r = 0;

    assert(db);
    assert(tid == db->current_txn);

    /* no need to commit if we're not dirty */
    if (!(db->header.flags & DIRTY))
        goto done;

    assert(db->current_txn);

    if (db->current_txn->readonly) goto done;

    /* build a commit record */
    memset(&newrecord, 0, sizeof(struct skiprecord));
    newrecord.type = COMMIT;
    newrecord.nextloc[0] = db->header.current_size;

    /* append to the file */
    r = append_record(db, &newrecord, NULL, NULL);
    if (r) goto done;

    /* commit ALL outstanding changes first, before
     * rewriting the header */
    r = twom_commit(db);
    if (r) goto done;

    /* finally, update the header and commit again */
    db->header.current_size = db->end;
    db->header.flags &= ~DIRTY;
    r = commit_header(db);
    if (r) goto done;

    if (!db->nocompact 
           && db->header.dirty_size > MINREWRITE
           && db->header.current_size < 4 * db->header.dirty_size) {
        // delay the checkpoint until the user isn't waiting
        struct dcrock *drock = xzmalloc(sizeof(struct dcrock));
        drock->fname = xstrdup(FNAME(db));
        drock->flags = 0;
        libcyrus_delayed_action(drock->fname, _delayed_checkpoint,
                                _delayed_checkpoint_free, drock);
    }

 done:
    if (r) {
        int r2;

        /* error during commit; we must abort */
        r2 = myabort_locked(db, tid);
        if (r2) {
            xsyslog(LOG_ERR, "DBERROR: commit AND abort failed",
                             "filename=<%s>",
                             FNAME(db));
        }
    }
    else {
        free(tid);
        db->current_txn = NULL;
    }

    return r;
}

static int myabort(struct dbengine *db, struct txn *tid)
{
    int r = myabort_locked(db, tid);
    unlock(db);
    return r;
}

static int mycommit(struct dbengine *db, struct txn *tid)
{
    int r = mycommit_locked(db, tid);
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
    if (tidptr && *tidptr && (*tidptr)->readonly)
        return CYRUSDB_READONLY;

    /* or readonly database */
    if (db->readonly)
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
    else {
        (*tidptr)->end = db->end;
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
                   const char *data, size_t datalen)
{
    struct copy_rock *cr = (struct copy_rock *)rock;
    int i;

    /* minimal logic from find_loc and stitch knowing that we're
     * always writing at the end of a file */
    struct skiploc *loc = &cr->db->loc;
    for (i = 0; i < loc->record.level; i++)
        loc->backloc[i] = loc->record.offset;
    loc->is_exactmatch = 0;
    buf_setmap(&loc->keybuf, key, keylen);
    return store_here(cr->db, data, datalen);
}

static int replay_cb(void *rock,
                     const char *key, size_t keylen,
                     const char *data, size_t datalen)
{
    struct copy_rock *cr = (struct copy_rock *)rock;
    return skipwrite(cr->db, key, keylen, data, datalen, 1);
}

static int mm_rename(struct dbengine *new, struct dbengine *db)
{
    char *copy = xstrdup(db->fname);
    const char *dir = dirname(copy);
    int r = 0;

    #if defined(O_DIRECTORY)
    int dirfd = open(dir, O_RDONLY|O_DIRECTORY, 0600);
#else
    int dirfd = open(dir, O_RDONLY, 0600);
#endif
    if (dirfd < 0) {
        xsyslog(LOG_ERR, "IOERROR: open directory failed",
                         "filename=<%s> newname=<%s> directory=<%s>",
                         db->fname, new->fname, dir);
        r = dirfd;
        goto done;
    }

    r = rename(new->fname, db->fname);
    if (r) goto done;

    if (fsync(dirfd) < 0) {
        xsyslog(LOG_ERR, "IOERROR: fsync directory failed",
                         "filename=<%s> newname=<%s> directory=<%s>",
                         db->fname, new->fname, dir);
        // but we can't abort now, we've already renamed, so we need to
        // carry on and update our object
    }

    // now that the rename is done, we can unlock the file; knowing that it's
    // consistent and complete
    unlock(new);

    free(new->fname);
    new->fname = NULL;

    if (db->fd >= 0) {
        close(db->fd);
        db->fd = -1;
    }
    db->has_lock = 0;
    if (db->map_base) {
        munmap(db->map_base, db->map_size);
        db->map_base = NULL;
        db->map_size = 0;
    }
    buf_free(&db->loc.keybuf);

    char *fname = db->fname;
    *db = *new;
    db->fname = fname;
    free(new);

done:
    if (dirfd >= 0) close(dirfd);
    free(copy);
    return r;
}

static int mycheckpoint(struct dbengine *db)
{
    size_t old_size = db->header.current_size;
    char newfname[1024];
    clock_t start = sclock();
    struct copy_rock cr;
    int r = 0;
    struct txn *txn = NULL;

    r = newtxn(db, 1/*shared*/, &txn);

    r = myconsistent(db, txn);
    if (r) {
        syslog(LOG_ERR, "db %s, inconsistent pre-checkpoint, bailing out",
               FNAME(db));
        int r2 = mycommit(db, txn);
        return r2 ? r2 : r;
    }

    /* open fname.NEW */
    snprintf(newfname, sizeof(newfname), "%s.NEW", FNAME(db));
    xunlink(newfname);

    cr.db = NULL;
    cr.tid = NULL;
    r = opendb(newfname, CYRUSDB_CREATE, &cr.db, &cr.tid);
    if (r) return r;

    // this MUST be an empty file
    assert(!cr.db->header.num_records);
    assert(cr.db->header.generation == 1);

    // set up the pointers so copy_cb logic can work
    relocate(cr.db, &cr.db->loc);

    // mvcc process all the existing records
    r = myforeach(db, NULL, 0, NULL, copy_cb, &cr, &txn);
    if (r) goto err;

    // replay all the remaining changes to the end of the file
    r = myreplay(db, replay_cb, &cr);

    // we still need a read-lock at this point
    assert(LOCKED(db));

    // nobody rewrote under us (shouldn't be possible, but if there is a bug this
    // will protect us from losing records)
    assert(db->header.generation == txn->generation);

    /* remember the repack size */
    cr.db->header.repack_size = cr.db->end;

    /* same uuid */
    memcpy(cr.db->header.uuid, db->header.uuid, 16);

    /* increase the generation count */
    cr.db->header.generation = db->header.generation + 1;

    r = mycommit_locked(cr.db, cr.tid);
    if (r) goto err;

    cr.tid = NULL;  /* avoid later errors trying to call abort, it's too late! */

    /* move new file to original file name */
    r = mm_rename(cr.db, db);
    if (r) goto err;

    {
        syslog(LOG_INFO,
               "twom: checkpointed %s (%llu record%s, %llu => %llu bytes) in %2.3f seconds",
               FNAME(db), (LLU)db->header.num_records,
               db->header.num_records == 1 ? "" : "s", (LLU)old_size,
               (LLU)(db->header.current_size),
               (sclock() - start) / (double) CLOCKS_PER_SEC);
    }

    return 0;

 err:
    if (cr.tid) myabort_locked(cr.db, cr.tid);
    xunlink(FNAME(cr.db));
    unlock(cr.db);
    dispose_db(cr.db);
    unlock(db);
    return CYRUSDB_IOERROR;
}


/* dump the database.
   if detail == 1, dump all records.
   if detail == 2, also dump pointers for active records.
   if detail == 3, dump all records/all pointers.
*/
const char *typestr(int type)
{
     if (type == ADD) return "ADD";
     if (type == REPLACE) return "REPLACE";
     if (type == DELETE) return "DELETE";
     if (type == DUMMY) return "DUMMY";
     if (type == COMMIT) return "COMMIT";
     return "UNKNOWN";
}

static int dump(struct dbengine *db, int detail)
{
    struct skiprecord record;
    struct buf scratch = BUF_INITIALIZER;
    size_t offset = DUMMY_OFFSET;
    int r = 0;
    int i;

    printf("HEADER: v=%lu fl=%lu num=%llu sz=(%08llX/%08llX/%08llX)\n",
          (LU)db->header.version,
          (LU)db->header.flags,
          (LLU)db->header.num_records,
          (LLU)db->header.dirty_size,
          (LLU)db->header.current_size,
          (LLU)db->header.repack_size);

    while (offset < db->header.current_size) {
        printf("%08llX ", (LLU)offset);

        r = read_onerecord(db, offset, &record);

        if (r) {
            if (record.keyoffset)
                printf("ERROR [HEADXXH %08lX %08lX]\n",
                        (long unsigned) record.xxh_head,
                        (long unsigned) xxh_map(BASE(db) + record.offset,
                                                 record.keyoffset - 8));
            else
                printf("ERROR\n");
            break;
        }

        if (check_tailxxh(db, &record)) {
            printf("ERROR [TAILXXH %08lX %08lX] ",
                    (long unsigned) record.xxh_tail,
                    (long unsigned) xxh_map(BASE(db) + record.keyoffset,
                        PAD8(record.keylen + record.vallen + 2)));
        }

        switch (record.type) {
        case COMMIT:
            printf("COMMIT start=%08llX\n", (LLU)record.nextloc[0]);
            break;

        case ADD:
        case REPLACE:
        case DELETE:
        case DUMMY:
            buf_setmap(&scratch, KEY(db, &record), record.keylen);
            buf_replace_char(&scratch, '\0', '-');
            printf("%s kl=%llu dl=%llu lvl=%d (%s)\n",
                   typestr(record.type),
                   (LLU)record.keylen, (LLU)record.vallen,
                   record.level, buf_cstring(&scratch));
            if (HASANCESTOR(record.type)) {
                printf("\t%08llX <-\n", (LLU)record.ancestor);
            }
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
    struct skiprecord *prevp = &db->recs[0];
    struct skiprecord *curp = &db->recs[1];
    size_t fwd[MAXLEVEL];
    size_t num_records = 0;
    size_t dirty_size = 0;
    int r = 0;
    int cmp;
    int i;

    assert(db->current_txn == tid); /* could both be null */

    /* read in the dummy */
    r = read_onerecord(db, DUMMY_OFFSET, prevp);
    if (r) return r;

    /* set up the location pointers */
    for (i = 0; i < MAXLEVEL; i++)
        fwd[i] = _getloc(db, prevp, i);

    while (fwd[0]) {
        r = read_onerecord(db, fwd[0], curp);
        if (r) {
            xsyslog(LOG_ERR, "DBERROR: failed to read record for consistent",
                    "fname=<%s> offset=<%08llX>",
                    FNAME(db), (LLU)fwd[0]);
            return r;
        }

        cmp = bsearch_ncompare_raw(KEY(db, curp), curp->keylen,
                                   KEY(db, prevp), prevp->keylen);
        if (cmp <= 0) {
            xsyslog(LOG_ERR, "DBERROR: twom out of order",
                    "fname=<%s> key=<%.*s> offset=<%08llX>"
                    " prevkey=<%.*s> prevoffset=<%08llX)",
                    FNAME(db), (int)curp->keylen, KEY(db, curp),
                    (LLU)curp->offset,
                    (int)prevp->keylen, KEY(db, prevp),
                    (LLU)prevp->offset);
            return CYRUSDB_INTERNAL;
        }

        size_t ancestor = curp->ancestor;
        while (ancestor) {
            r = read_onerecord(db, ancestor, prevp);
            if (r) {
                xsyslog(LOG_ERR, "DBERROR: failed to read ancestor for consistent",
                        "fname=<%s> key=<%.*s> offset=<%08llX>",
                        FNAME(db), (int)curp->keylen, KEY(db, curp),
                        (LLU)ancestor);
                return r;
            }
            cmp = bsearch_ncompare_raw(KEY(db, curp), curp->keylen,
                                       KEY(db, prevp), prevp->keylen);
            if (cmp) {
                xsyslog(LOG_ERR, "DBERROR: twom mismatched ancestor",
                        "fname=<%s> key=<%.*s> offset=<%08llX>"
                        " parentkey=<%.*s> parentoffset=<%08llX)",
                        FNAME(db), (int)curp->keylen, KEY(db, curp),
                        (LLU)curp->offset,
                        (int)prevp->keylen, KEY(db, prevp),
                        (LLU)prevp->offset);
                return CYRUSDB_INTERNAL;
            }
            ancestor = prevp->ancestor;
            dirty_size += prevp->len;
        }

        for (i = 0; i < curp->level; i++) {
            /* check the old pointer was to here */
            if (fwd[i] != curp->offset) {
                xsyslog(LOG_ERR, "DBERROR: twom broken linkage",
                                 "filename=<%s> offset=<%08llX> level=<%d>"
                                 " expected=<%08llX>",
                                 FNAME(db), (LLU)curp->offset, i, (LLU)fwd[i]);
                return CYRUSDB_INTERNAL;
            }
            /* and advance to the new pointer */
            fwd[i] = _getloc(db, curp, i);
        }

        // count if record or tombstone
        if (curp->type == DELETE) dirty_size += curp->len;
        else num_records++;

        /* switch pointers for next time */
        struct skiprecord *temp = prevp;
        prevp = curp;
        curp = temp;
    }

    for (i = 0; i < MAXLEVEL; i++) {
        if (fwd[i]) {
            xsyslog(LOG_ERR, "DBERROR: twom broken tail",
                             "filename=<%s> offset=<%08llX> level=<%d>",
                             FNAME(db), (LLU)fwd[i], i);
            return CYRUSDB_INTERNAL;
        }
    }

    /* we walked the whole file and saw every pointer */

    if (num_records != db->header.num_records) {
        xsyslog(LOG_ERR, "DBERROR: twom record count mismatch",
                         "filename=<%s> num_records=<%llu> expected_records=<%llu>",
                         FNAME(db), (LLU)num_records, (LLU)db->header.num_records);
        return CYRUSDB_INTERNAL;
    }

    if (dirty_size != db->header.dirty_size) {
        xsyslog(LOG_ERR, "DBERROR: twom dirty_size mismatch",
                         "filename=<%s> dirty_size=<%llu> expected_size=<%llu>",
                         FNAME(db), (LLU)dirty_size, (LLU)db->header.dirty_size);
        return CYRUSDB_INTERNAL;
    }

    return 0;
}

/* run recovery on this file.
 * always called with a write lock. */
static int recovery1(struct dbengine *db, int *count)
{
    size_t prev[MAXLEVEL+1];
    size_t next[MAXLEVEL+1];
    struct skiprecord *prevrec = &db->recs[0];
    struct skiprecord *nextrec = &db->recs[1];
    size_t nextoffset = 0;
    uint64_t num_records = 0;
    uint64_t dirty_size = 0;
    int changed = 0;
    int r = 0;
    int cmp;
    int i;

    /* no need to run recovery if we're consistent */
    if (db_is_clean(db))
        return 0;

    assert(WRITELOCKED(db));

    /* we can't recovery a file that's not created yet */
    assert(db->header.current_size > HEADER_SIZE);

    /* dirty the header if not already dirty */
    if (!(db->header.flags & DIRTY)) {
        db->header.flags |= DIRTY;
        r = commit_header(db);
        if (r) return r;
    }

    /* start with the dummy */
    r = read_onerecord(db, DUMMY_OFFSET, nextrec);
    if (r) return r;

    /* and pointers forwards */
    for (i = 2; i <= MAXLEVEL; i++) {
        prev[i] = nextrec->offset;
        next[i] = nextrec->nextloc[i];
    }

    /* check for broken level - pointers */
    for (i = 0; i < 2; i++) {
        if (nextrec->nextloc[i] >= db->end) {
            nextrec->nextloc[i] = 0;
            rewrite_record(db, nextrec);
            changed++;
        }
    }

    nextoffset = _getloc(db, nextrec, 0);

    while (nextoffset) {
        // switch up records
        struct skiprecord *temp = prevrec;
        prevrec = nextrec;
        nextrec = temp;

        r = read_onerecord(db, nextoffset, nextrec);
        if (r) return r;

        cmp = bsearch_ncompare_raw(KEY(db, nextrec), nextrec->keylen,
                                   KEY(db, prevrec), prevrec->keylen);
        if (cmp <= 0) {
            xsyslog(LOG_ERR, "DBERROR: twom out of order",
                             "filename=<%s>"
                             " record_key=<%.*s> record_offset=<%08llX>"
                             " prev_key=<%.*s> prev_offset=<%08llX>",
                             FNAME(db),
                             (int)nextrec->keylen, KEY(db, nextrec),
                             (LLU)nextrec->offset,
                             (int)prevrec->keylen, KEY(db, prevrec),
                             (LLU)prevrec->offset);
            return CYRUSDB_INTERNAL;
        }

        size_t ancestor = nextrec->ancestor;
        while (ancestor) {
            r = read_onerecord(db, ancestor, prevrec);
            if (r) return r;
            cmp = bsearch_ncompare_raw(KEY(db, nextrec), nextrec->keylen,
                                       KEY(db, prevrec), prevrec->keylen);
            if (cmp) {
                xsyslog(LOG_ERR, "DBERROR: twom mismatched ancestor",
                        "fname=<%s> key=<%.*s> offset=<%08llX>"
                        " parentkey=<%.*s> parentoffset=<%08llX)",
                        FNAME(db), (int)nextrec->keylen, KEY(db, nextrec),
                        (LLU)nextrec->offset,
                        (int)prevrec->keylen, KEY(db, prevrec),
                        (LLU)prevrec->offset);
                return CYRUSDB_INTERNAL;
            }
            ancestor = prevrec->ancestor;
            dirty_size += prevrec->len;
        }

        /* check for old offsets needing fixing */
        for (i = 2; i <= nextrec->level; i++) {
            if (next[i] != nextrec->offset) {
                /* need to fix up the previous record to point here */
                r = read_onerecord(db, prev[i], prevrec);
                if (r) return r;

                /* XXX - optimise adjacent same records */
                prevrec->nextloc[i] = nextrec->offset;
                rewrite_record(db, prevrec);
                changed++;
            }
            prev[i] = nextrec->offset;
            next[i] = nextrec->nextloc[i];
        }

        /* check for broken level - pointers */
        for (i = 0; i < 2; i++) {
            if (nextrec->nextloc[i] >= db->end) {
                nextrec->nextloc[i] = 0;
                rewrite_record(db, nextrec);
                changed++;
            }
        }

        if (HASVALUE(nextrec->type)) num_records++;
        else dirty_size += nextrec->len;

        nextoffset = _getloc(db, nextrec, 0);
    }

    /* check for remaining offsets needing fixing */
    for (i = 2; i <= MAXLEVEL; i++) {
        if (next[i]) {
            /* need to fix up the previous record to point to the end */
            r = read_onerecord(db, prev[i], prevrec);
            if (r) return r;

            /* XXX - optimise, same as above */
            prevrec->nextloc[i] = 0;
            rewrite_record(db, prevrec);
            changed++;
        }
    }

    r = twom_commit(db);
    if (r) return r;

    /* clear the dirty flag */
    db->header.flags &= ~DIRTY;
    db->header.num_records = num_records;
    db->header.dirty_size = dirty_size;
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
        xsyslog(LOG_ERR, "DBERROR: recovery1 failed",
                         "filename=<%s>",
                         FNAME(db));
        if (r) return r;
    }

    {
        syslog(LOG_INFO,
               "twom: recovered %s (%llu record%s, %llu bytes) in %2.3f seconds - fixed %d offset%s",
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

HIDDEN struct cyrusdb_backend cyrusdb_twom =
{
    "twom",                  /* name */

    &cyrusdb_generic_init,
    &cyrusdb_generic_done,
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

    &mylock,
    &mycommit,
    &myabort,

    &dump,
    &consistent,
    &mycheckpoint,
    &bsearch_ncompare_raw,
    &myyield,
};
