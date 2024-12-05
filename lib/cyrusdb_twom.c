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
#include "crc32.h"
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
#define FOREACH_LOCK_RELEASE 256

/* format specifics */
#undef VERSION /* defined in config.h */
#define VERSION 1

/* type aliases */
#define LLU long long unsigned int
#define LU long unsigned int

/* record types */
#define DUMMY 0
#define COMMIT 1
#define ADD 2
#define FATADD 3
#define REPLACE 4
#define FATREPLACE 5
#define DELETE 6
#define FATDELETE 7
const char *typestr[] = { "DUMMY", "COMMIT", "ADD", "FATADD",
                          "REPLACE", "FATREPLACE", "DELETE", "FATDELETE" };
uint8_t ptroffset[8]   = { 1, 1, 1, 3, 2, 4, 2, 4 };
uint8_t hasancestor[8] = { 0, 0, 0, 0, 1, 1, 1, 1 };
uint8_t fatrecord[8]   = { 0, 0, 0, 1, 0, 1, 0, 1 };
uint8_t haskey[8]      = { 0, 0, 1, 1, 1, 1, 1, 1 };
uint8_t hasval[8]      = { 0, 0, 1, 1, 1, 1, 0, 0 };

/********** DATA STRUCTURES *************/

struct db_header {
    /* header info */
    uint16_t version;
    uint16_t checksum_engine;
    uint32_t flags;
    unsigned char uuid[16];
    uint64_t generation;
    uint64_t num_records;
    size_t dirty_size;
    size_t repack_size;
    size_t current_size;
    uint32_t maxlevel;
};

struct tm_file {
    int fd;
    unsigned char has_lock;
    int refcount;
    struct tm_file *next;
};

/* a mmaped file, with reference counter */
struct tm_map {
    struct tm_file *file;
    char *base;
    size_t size;
    int refcount;
    int dirty;
    struct tm_map *next;
};

/* a location in the twom file.  We always have:
 * offset: if "is_exactmatch" this points to the record
 *         with the matching key, otherwise it points to
 *         the 'compar' order previous record.
 * backloc: the records that point TO this location
 *          at each level.
 * end can be used to see if anything in
 * the file may have changed and needs relocation.
 */
struct tm_loc {
    struct tm_map *map;
    int is_exactmatch; // key was passed in; did we match it?
    size_t offset;     // current position

    // location
    size_t end;  // pointers are only valid when end matches
    const char *ptr;
    size_t backloc[MAXLEVEL+1];
};

#define DIRTY (1<<0)

struct txn {
    struct tm_file *file;
    struct db_header header;
    size_t end;
    unsigned readonly:1;
    uint64_t counter;
    struct txn *next;
};

struct dbengine {
    /* file data */
    char *fname;
    struct db_header header;

    // checksum engine
    uint32_t (*csum)(const char *base, size_t len);

    // comparison function
    int (*compar)(const char *a, int alen, const char *b, int blen);

    /* tracking info */
    struct tm_file *openfile;
    struct tm_map *openmap;
    struct tm_loc *openloc;
    struct txn *write_txn;
    struct txn *read_txn;

    unsigned int readonly:1;
    unsigned int nocsum:1;
    unsigned int nocompact:1;
    uint64_t foreach_lock_release;
    int refcount;
    struct dbengine *next;
};

#define HEADER_MAGIC ("\241\002\213\015twomfile\0\0\0\0")
#define HEADER_MAGIC_SIZE (16)

/* offsets of header files */
enum {
    OFFSET_HEADER = 0,
    OFFSET_UUID = 16,
    OFFSET_VERSION = 32,
    OFFSET_CHECKSUM_ENGINE = 34,
    OFFSET_FLAGS = 36,
    OFFSET_GENERATION = 40,
    OFFSET_NUM_RECORDS = 48,
    OFFSET_DIRTY_SIZE = 56,
    OFFSET_REPACK_SIZE = 64,
    OFFSET_CURRENT_SIZE = 72,
    OFFSET_MAXLEVEL = 80,
    OFFSET_CSUM = 84,
};

#define HEADER_SIZE 88
#define DUMMY_OFFSET HEADER_SIZE
#define MAXRECORDHEAD ((MAXLEVEL + 6)*8)

enum {
    TWOM_CHECKSUM_NULL = 0,
    TWOM_CHECKSUM_CRC32 = 1,
    TWOM_CHECKSUM_XXH32 = 2,
    TWOM_CHECKSUM_XXH64 = 3,
};

static struct dbengine *open_twom = NULL;
static uint16_t twom_default_checksum_engine = 0;

static int mycommit(struct dbengine *db, struct txn *txn);
static int myabort(struct dbengine *db, struct txn *txn);
static int mycheckpoint(struct dbengine *db);
static int myconsistent(struct dbengine *db, struct txn *txn);
static int recovery(struct dbengine *db);
static int recovery1(struct dbengine *db, struct tm_loc *loc, int *count);

/************** HELPER FUNCTIONS ****************/

// pad out to an 8 byte boundary
#define PAD8(n) (((n)+7)&~7)
#define LOCKED(f) ((f)->has_lock)
#define WRITELOCKED(f) ((f)->has_lock == 2)

// lots of direct accessors for every part of a message!
#define TYPE(ptr) (*((uint8_t *)(ptr)))
#define LEVEL(ptr) (*((uint8_t *)(ptr+1)))
// replace and delete records have an extra offset
#define HLCALC(type, level) (8 * (ptroffset[type] + 1 + level))
#define TLCALC(type, keylen, vallen) (haskey[type] ? PAD8(keylen + 1 + (hasval[type] ? (vallen + 1) : 0)) : 0)
#define HEADLEN(ptr) HLCALC(TYPE(ptr), LEVEL(ptr))
#define TAILLEN(ptr) TLCALC(TYPE(ptr), KEYLEN(ptr), VALLEN(ptr))
#define KEYLEN(ptr) ((ptr && haskey[TYPE(ptr)]) ? (fatrecord[TYPE(ptr)] ? ntohll(*((uint64_t *)(ptr+8))) : ntohs(*((uint16_t *)(ptr+2)))) : 0)
#define KEYPTR(ptr) ((ptr && haskey[TYPE(ptr)]) ? (ptr + HEADLEN(ptr) + 8) : NULL)
#define VALLEN(ptr) (fatrecord[TYPE(ptr)] ? ntohll(*((uint64_t *)(ptr+16))) : ntohl(*((uint32_t *)(ptr+4))))
#define VALPTR(ptr) (ptr + HEADLEN(ptr) + 8 + KEYLEN(ptr) + 1)
#define RECLEN(ptr) (HEADLEN(ptr) + /*crcs*/8 + TAILLEN(ptr))
#define ANCESTOR(ptr) (hasancestor[TYPE(ptr)] ? ntohll(*((uint64_t *)(ptr+(fatrecord[TYPE(ptr)] ? 24 : 8)))) : 0)
#define NEXT0(ptr, alt) ntohll(*((uint64_t *)(ptr + 8 * (ptroffset[TYPE(ptr)] + (alt ? 1 : 0)))))
#define NEXTN(ptr, n) ntohll(*((uint64_t *)(ptr + 8 * (ptroffset[TYPE(ptr)] + n + 1))))
#define HEADCSUM(ptr) ntohl(*((uint32_t *)(ptr + HEADLEN(ptr))))
#define TAILCSUM(ptr) ntohl(*((uint32_t *)(ptr + HEADLEN(ptr) + 4)))

/* return a "safe" pointer - that's one where it's guaranteed that the entire record
 * fits inside the mapped space for the transaction */
static inline const char *safeptr(struct tm_loc *loc, size_t offset)
{
    if (!offset) return NULL;
    assert(loc->map->size >= offset + 24);
    if (loc->end < offset + 24) return NULL;  // need space for the head info
    const char *base = loc->map->base + offset;
    if (*base & ~7) return NULL; // invalid type
    if (loc->end < offset + RECLEN(base)) return NULL; // no space for entire record
    return base;
}

static inline size_t advance(struct tm_loc *loc, const char *ptr, uint8_t level)
{
    if (level) {
        size_t val = NEXTN(ptr, level);
        return val;
    }
    size_t next0 = NEXT0(ptr, 0);
    size_t next1 = NEXT0(ptr, 1);
    if (next0 >= loc->end) return next1;
    if (next1 >= loc->end) return next0;
    if (next0 > next1) return next0;
    return next1;
}

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


static uint32_t csum_null(const char *base __attribute__((unused)),
                          size_t len __attribute__((unused)))
{
    return 0;
}

static uint32_t csum_crc32(const char *base, size_t len)
{
    if (!len) return 0;
    return crc32_map(base, len);
}

static uint32_t csum_xxh32(const char *base, size_t len)
{
    if (!len) return 0;
    return (uint32_t)XXH32(base, len, 0);
}

static uint32_t csum_xxh64(const char *base, size_t len)
{
    if (!len) return 0;
    return (uint32_t)XXH3_64bits(base, len);
}

static void set_csum_engine(struct dbengine *db, int engine)
{
    switch (engine) {
    case TWOM_CHECKSUM_NULL:
        db->csum = csum_null;
        return;
    case TWOM_CHECKSUM_CRC32:
        db->csum = csum_crc32;
        return;
    case TWOM_CHECKSUM_XXH32:
        db->csum = csum_xxh32;
        return;
    case TWOM_CHECKSUM_XXH64:
        db->csum = csum_xxh64;
        return;
    }
    assert(0); // BAD, unknown engine.
}

/* given an open, mapped db, read in the header information */
static int read_header(struct dbengine *db, struct tm_map *map, struct db_header *header)
{
    assert(db && map);
    const char *base = map->base;

    if (map->size < HEADER_SIZE) {
        syslog(LOG_ERR,
               "twom: file not large enough for header: %s", db->fname);
        return CYRUSDB_IOERROR;
    }

    if (memcmp(base, HEADER_MAGIC, HEADER_MAGIC_SIZE)) {
        syslog(LOG_ERR, "twom: invalid magic header: %s", db->fname);
        return CYRUSDB_IOERROR;
    }

    memcpy(header->uuid, base + OFFSET_UUID, 16);

    header->version
        = ntohs(*((uint16_t *)(base + OFFSET_VERSION)));

    header->checksum_engine
        = ntohs(*((uint16_t *)(base + OFFSET_CHECKSUM_ENGINE)));

    set_csum_engine(db, header->checksum_engine);

    if (header->version > VERSION) {
        syslog(LOG_ERR, "twom: version mismatch: %s has version %d",
               db->fname, header->version);
        return CYRUSDB_IOERROR;
    }

    header->flags
        = ntohl(*((uint32_t *)(base + OFFSET_FLAGS)));

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

    if (db->nocsum) return 0;

    uint32_t csum = ntohl(*((uint32_t *)(base + OFFSET_CSUM)));
    if (db->csum(base, OFFSET_CSUM) != csum) {
        xsyslog(LOG_ERR, "DBERROR: twom header checksum failure",
                         "filename=<%s>",
                         db->fname);
        return CYRUSDB_IOERROR;
    }

    return 0;
}

static size_t tm_roundup(size_t offset)
{
    size_t page_size = 1<<14; // 16k
    return ((offset + offset / 4) + page_size - 1) & ~(page_size - 1);
}

/* we keep open ONLY the current file and current map,
 * and any others which still have a reference to them */

static void _remove_txn(struct txn **ptr)
{
    struct txn *this = *ptr;
    struct txn *next = this->next;
    this->file->refcount--;
    free(this);
    *ptr = next;
}

static void _remove_map(struct tm_map **ptr)
{
    struct tm_map *this = *ptr;
    struct tm_map *next = (*ptr)->next;
    if (this->base) munmap(this->base, this->size);
    this->file->refcount--;
    free(this);
    *ptr = next;
}

static void _remove_file(struct tm_file **ptr)
{
    struct tm_file *this = *ptr;
    struct tm_file *next = (*ptr)->next;
    if (this->fd != -1) close(this->fd);
    free(this);
    *ptr = next;
}

static void empty_db(struct dbengine *db)
{
    while (db->write_txn)
        _remove_txn(&db->write_txn);
    while (db->read_txn)
        _remove_txn(&db->read_txn);
    if (db->openloc) {
        if (db->openloc->map) db->openloc->map->refcount--;
        free(db->openloc);
        db->openloc = NULL;
    }
    while (db->openmap)
        _remove_map(&db->openmap);
    while (db->openfile)
        _remove_file(&db->openfile);
}

static void tm_cleanup_map(struct dbengine *db)
{
    if (!db->openmap) return;
    struct tm_map **ptr = &db->openmap->next;
    while (*ptr) {
        if (!(*ptr)->refcount) {
            _remove_map(ptr);
        }
        else {
            ptr = &((*ptr)->next);
        }
    }
}

static void tm_cleanup_file(struct dbengine *db)
{
    if (!db->openfile) return;
    struct tm_file **ptr = &db->openfile->next;
    while (*ptr) {
        if (!(*ptr)->refcount) {
            _remove_file(ptr);
        }
        else {
            ptr = &((*ptr)->next);
        }
    }
}

static void tm_cleanup(struct dbengine *db)
{
    tm_cleanup_map(db);
    tm_cleanup_file(db);
}

/* end cleanup */

static inline int tm_commit(struct dbengine *db, size_t len)
{
    assert(db->openmap);
    if (!db->openmap->dirty) return 0;
    assert(db->openfile);
    assert(db->openmap->file == db->openfile);
    assert(WRITELOCKED(db->openfile));
    db->openmap->dirty = 0;
    return msync(db->openmap->base, len, MS_SYNC|MS_INVALIDATE);
}

static inline int tm_ensure(struct dbengine *db, struct tm_loc *loc, size_t offset)
{
    if (db->openmap && offset <= db->openmap->size) return 0;

    assert(db->openfile);
    assert(WRITELOCKED(db->openfile));
    if (db->openmap) assert(db->openmap->file == db->openfile);

    offset = tm_roundup(offset);

    if (loc && loc->map)
        assert(loc->map->file == db->openfile);

    // make sure anything we have mapped in has committed to disk
    struct tm_map *oldmap = db->openmap;
    if (oldmap && oldmap->dirty) {
        if (msync(oldmap->base, oldmap->size, MS_ASYNC)) {
            xsyslog(LOG_ERR, "DBERROR: twom failed to msync during tm_ensure",
                             "filename=<%s> oldsize=<%08llX>",
                             db->fname, (LLU)oldmap->size);
            return CYRUSDB_IOERROR;
        }
        oldmap->dirty = 0;
    }

    // maybe free the old location!
    if (loc && loc->map) {
        loc->map->refcount--;
        tm_cleanup(db);
    }

    // XXX - error handling of truncate?
    if (ftruncate(db->openfile->fd, offset)) {
        xsyslog(LOG_ERR, "DBERROR: twom failed to extend file during tm_ensure",
                         "filename=<%s> oldsize=<%08llX> offset=<%08llX>",
                         db->fname, (LLU)oldmap->size, (LLU)offset);
        return CYRUSDB_IOERROR;
    }

    // map the larger file into new memory
    db->openmap = xzmalloc(sizeof(struct tm_map));
    db->openmap->base = mmap((caddr_t)0, offset, PROT_READ|PROT_WRITE, MAP_SHARED, db->openfile->fd, 0L);
    db->openmap->size = offset;
    db->openmap->next = oldmap;
    db->openmap->file = db->openfile;
    db->openfile->refcount++;

    // and update the pointer in the location to be based on the new base
    if (loc) {
        loc->map = db->openmap;
        loc->map->refcount++;
        loc->ptr = loc->map->base + loc->offset;
    }

    return 0;
}

/* given an open, mapped, locked db, write the header information */
static inline int write_header(struct dbengine *db, struct db_header *header)
{
    int r = tm_ensure(db, db->openloc, HEADER_SIZE);
    if (r) return r;

    char *base = db->openmap->base;

    memcpy(base, HEADER_MAGIC, HEADER_MAGIC_SIZE);
    memcpy(base + OFFSET_UUID, header->uuid, 16);
    *((uint16_t *)(base + OFFSET_VERSION)) = htons(header->version);
    *((uint16_t *)(base + OFFSET_CHECKSUM_ENGINE)) = htons(header->checksum_engine);
    *((uint32_t *)(base + OFFSET_FLAGS)) = htonl(header->flags);
    *((uint64_t *)(base + OFFSET_GENERATION)) = htonll(header->generation);
    *((uint64_t *)(base + OFFSET_NUM_RECORDS)) = htonll(header->num_records);
    *((uint64_t *)(base + OFFSET_DIRTY_SIZE)) = htonll(header->dirty_size);
    *((uint64_t *)(base + OFFSET_REPACK_SIZE)) = htonll(header->repack_size);
    *((uint64_t *)(base + OFFSET_CURRENT_SIZE)) = htonll(header->current_size);
    *((uint32_t *)(base + OFFSET_MAXLEVEL)) = htonl(header->maxlevel);
    *((uint32_t *)(base + OFFSET_CSUM)) = htonl(db->csum(base, OFFSET_CSUM));

    db->openmap->dirty = 1;

    return 0;
}

/* simple wrapper to write with an fsync */
static inline int commit_header(struct dbengine *db, struct db_header *header)
{
    int r = write_header(db, header);
    if (r) return r;
    return tm_commit(db, header->current_size);
}

/******************** RECORD *********************/

static inline int check_tailcsum(struct dbengine *db, const char *ptr, size_t offset)
{
    if (db->nocsum) return 0;
    size_t taillen = TAILLEN(ptr);
    if (!taillen) return 0;
    uint32_t csum = db->csum(KEYPTR(ptr), taillen);
    if (csum != TAILCSUM(ptr)) {
        xsyslog(LOG_ERR, "DBERROR: invalid tail checksum",
                         "filename=<%s> offset=<%08llX>",
                         db->fname, (LLU)offset);
        return CYRUSDB_IOERROR;
    }

    return 0;
}

static inline int check_headcsum(struct dbengine *db, const char *ptr, size_t offset)
{
    if (db->nocsum) return 0;
    uint32_t csum = db->csum(ptr, HEADLEN(ptr));
    if (csum != HEADCSUM(ptr)) {
        xsyslog(LOG_ERR, "DBERROR: invalid head checksum",
                         "filename=<%s> offset=<%08llX>",
                         db->fname, (LLU)offset);
        return CYRUSDB_IOERROR;
    }

    return 0;
}

static inline void _setloc(struct txn *txn, char *ptr, uint8_t level, size_t offset)
{
    char *addr = ptr + (8 * (ptroffset[TYPE(ptr)]));

    if (level) {
        // positions past the start
        addr += 8 * (level + 1);
    }
    else {
        /* level zero is special */
        size_t val0 = NEXT0(ptr, 0);
        size_t val1 = NEXT0(ptr, 1);

        size_t end = txn->header.current_size;
        /* already this transaction, update this one */
        if (val0 < end && (val1 >= end || val0 > val1))
            addr += 8; // conditions to write to val1
    }

    *((uint64_t *)(addr)) = htonll(offset);
}

static inline void _recsum(struct dbengine *db, char *ptr)
{
    size_t headlen = HEADLEN(ptr);
    uint32_t newcsum = db->csum(ptr, headlen);
    *((uint32_t *)(ptr + headlen)) = htonl(newcsum);
}

/* finds a record, either an exact match or the record
 * immediately before */
#ifdef HAVE_DECLARE_OPTIMIZE
static int locate(struct dbengine *db, struct tm_loc *loc, const char *key, size_t keylen)
    __attribute__((optimize("-O3")));
#endif
static int locate(struct dbengine *db, struct tm_loc *loc, const char *key, size_t keylen)
{
    size_t offset = 0;
    uint8_t level = MAXLEVEL;
    int cmp = -1; /* never found a thing! */
    const char *ptr = NULL;

    // refcount the map where this location is placed
    loc->offset = DUMMY_OFFSET;
    loc->backloc[level] = DUMMY_OFFSET;
    loc->is_exactmatch = 0;

    /* start with the dummy */
    loc->ptr = safeptr(loc, DUMMY_OFFSET);
    if (!loc->ptr) return CYRUSDB_IOERROR; // invalid ptr

    /* special case start pointer for efficiency */
    if (!keylen) {
        while (level) {
            loc->backloc[level-1] = DUMMY_OFFSET;
            level--;
        }
        return 0;
    }

    while (level) {
        size_t next = advance(loc, loc->ptr, level-1);

        loc->backloc[level-1] = loc->offset;

        if (next != offset) {
            offset = next;
            if (offset) {
                ptr = safeptr(loc, offset);
                if (!ptr) return CYRUSDB_IOERROR;
                assert(LEVEL(ptr) >= level);

                cmp = db->compar(KEYPTR(ptr), KEYLEN(ptr),
                                 key, keylen);

                /* not there?  stay at this level */
                if (cmp < 0) {
                    loc->offset = offset;
                    loc->ptr = ptr;
                    continue;
                }
            }
        }

        level--;
    }

    // found an exact match?  Great
    if (!cmp) {
        loc->is_exactmatch = 1;
        loc->offset = offset;
        loc->ptr = ptr;
        return check_tailcsum(db, loc->ptr, offset);
    }

    return 0;
}

static int relocate(struct dbengine *db, struct txn *txn, struct tm_loc *loc)
{
    // find the latest mmap for the transaction's file
    struct tm_map *newmap = db->openmap;
    while (newmap->file != txn->file) newmap = newmap->next;

    // changed file? We need to update our file
    if (!loc->map || txn->file != loc->map->file || loc->end != txn->end) {
        // new file, or updated by another process? we need to relocate
        if (loc->map) loc->map->refcount--;
        loc->map = newmap;
        loc->map->refcount++;
        loc->end = txn->end;
        int r = locate(db, loc, KEYPTR(loc->ptr), KEYLEN(loc->ptr));
        if (r) return r;
        tm_cleanup(db);
    }
    else if (newmap != loc->map) {
        // same file being extended without outside changes, just update our ptr
        if (loc->map) loc->map->refcount--;
        loc->map = newmap;
        loc->map->refcount++;
        loc->ptr = loc->map->base + loc->offset;
        tm_cleanup(db);
    }
    return 0;
}

static int find_loc(struct dbengine *db, struct txn *txn, struct tm_loc *loc, const char *key, size_t keylen)
{
    struct tm_map *newmap = db->openmap;
    while (newmap->file != txn->file) newmap = newmap->next;

    // the old location is for an old map or pointers have been invalidated
    if (loc->end != txn->end || newmap != loc->map) {
        loc->map = newmap;
        loc->map->refcount++;
        loc->end = txn->end;
        return locate(db, loc, key, keylen);
    }

    int cmp = db->compar(KEYPTR(loc->ptr), KEYLEN(loc->ptr), key, keylen);
    if (!cmp) {
        // found it exactly!
        loc->is_exactmatch = 1;
        return 0;
    }

    // key is in the future?  let's see if it's next!
    if (cmp < 0) {
        size_t offset = advance(loc, loc->ptr, 0);
        if (!offset) {
            // EOF
            loc->is_exactmatch = 0;
            return 0;
        }
        const char *ptr = safeptr(loc, offset);
        if (!ptr) return CYRUSDB_IOERROR;
        cmp = db->compar(KEYPTR(ptr), KEYLEN(ptr), key, keylen);
        if (cmp > 0) {
            // it's in the gap
            loc->is_exactmatch = 0;
            return 0;
        }
        else if (cmp == 0) {
            // found it
            uint8_t level = LEVEL(loc->ptr);
            int i;
            for (i = 0; i < level; i++)
                loc->backloc[i] = loc->offset;
            loc->offset = offset;
            loc->is_exactmatch = 1;
            loc->ptr = ptr;
            return 0;
        }
    }

    // not immediately here or next, locate from scratch
    return locate(db, loc, key, keylen);
}

/* helper function to advance to the "next" record.  Used by foreach,
 * fetchnext, and internal functions */
static int advance_loc(struct dbengine *db, struct txn *txn, struct tm_loc *loc)
{
    int r = relocate(db, txn, loc);
    if (r) return r;

    const char *ptr = loc->ptr;

    /* update back pointers */
    uint8_t level = LEVEL(ptr);
    int i;
    for (i = 0; i < level; i++)
        loc->backloc[i] = loc->offset;

    loc->offset = advance(loc, loc->ptr, 0);

    /* reached the end? */
    if (!loc->offset) {
        // reset back to the start
        locate(db, loc, NULL, 0);
        return 0; // will have is_exactmatch == 0; which breaks the path
    }

    loc->ptr = safeptr(loc, loc->offset);
    if (!loc->ptr) return CYRUSDB_IOERROR;

    /* make sure this record is complete */
    loc->is_exactmatch = 1;
    return check_tailcsum(db, loc->ptr, loc->offset);
}

/* overall "store" function - update the value in the current loc.
   All updates funnel through here.  NULL val means
   deletion.   Force is implied here, it gets checked higher. */
static int store_here(struct dbengine *db, const char *key, size_t keylen, const char *val, size_t vallen)
{
    struct tm_loc *loc = db->openloc;
    struct txn *txn = db->write_txn;

    assert(txn);
    if (vallen) assert(val);

    uint64_t ancestor = 0;
    int r;
    int type = ADD;

    /* dirty the header if not already dirty */
    if (!(db->header.flags & DIRTY)) {
        db->header.flags |= DIRTY;
        r = commit_header(db, &db->header);
        if (r) return r;
        txn->header = db->header;
        txn->end = txn->header.current_size;
        loc->end = txn->end;
    }

    if (loc->is_exactmatch) {
        ancestor = loc->offset;
        // if it's not already a delete
        if (hasval[TYPE(loc->ptr)]) {
            txn->header.num_records--;
            txn->header.dirty_size += RECLEN(loc->ptr);
        }
        // new type might be a delete too
        type = val ? REPLACE : DELETE;
    }
    else {
        assert(val);
    }

    if (keylen > UINT16_MAX || vallen > UINT32_MAX)
        type++; // the FAT versions are all one more than the non-FAT versions

    uint8_t level = randlvl(1, MAXLEVEL);
    size_t headlen = HLCALC(type, level);
    size_t taillen = TLCALC(type, keylen, vallen);
    size_t reclen = headlen + 8 + taillen;

    r = tm_ensure(db, loc, txn->end + reclen);
    if (r) return r;

    // this may have re-mapped
    char *base = loc->map->base + txn->end;
    memset(base, 0, reclen);
    char *addr = base;
    *((uint8_t *)(addr)) = type;
    *((uint8_t *)(addr+1)) = level;
    if (fatrecord[type]) {
        *((uint64_t *)(addr+8)) = htonll(keylen);
        *((uint64_t *)(addr+16)) = htonll(vallen);
        addr += 24;
    }
    else {
        *((uint16_t *)(addr+2)) = htons(keylen);
        *((uint32_t *)(addr+4)) = htonl(vallen);
        addr += 8;
    }
    if (hasancestor[type]) {
        *((uint64_t *)(addr)) = htonll(ancestor);
        addr += 8;
    }

    // skip alternate level 0 pointer
    addr += 8;

    // store all the backwards and forwards locations
    size_t oldlevel = LEVEL(loc->ptr);
    uint8_t i;
    char *prevptr = NULL;

    // if it wasn't an exact match, we'll be adding afterwards
    if (!loc->is_exactmatch)
        for (i = 0; i < oldlevel; i++)
            loc->backloc[i] = loc->offset;

    // we need to update the backpointers to this new location,
    // and the forward pointers to the old pointer's next location
    for (i = 0; i < oldlevel && i < level; i++) {
        char *backptr = loc->map->base + loc->backloc[i];
        if (backptr != prevptr) {
            if (prevptr) _recsum(db, prevptr);
            prevptr = backptr;
        }
        size_t next = advance(loc, loc->ptr, i);
        *((uint64_t *)(addr)) = htonll(next);
        _setloc(txn, backptr, i, txn->end);
        addr += 8;
    }

    // old level stuck up higher?  If we're removing it then we need to
    // stitch across
    for (; loc->is_exactmatch && i < oldlevel; i++) {
        char *backptr = loc->map->base + loc->backloc[i];
        if (backptr != prevptr) {
            if (prevptr) _recsum(db, prevptr);
            prevptr = backptr;
        }
        size_t next = advance(loc, loc->ptr, i);
        _setloc(txn, backptr, i, next);
    }

    // new record sticks up higher?  We need to intercept the existing pointers
    for (; i < level; i++) {
        char *backptr = loc->map->base + loc->backloc[i];
        if (backptr != prevptr) {
            if (prevptr) _recsum(db, prevptr);
            prevptr = backptr;
        }
        size_t next = advance(loc, backptr, i);
        *((uint64_t *)(addr)) = htonll(next);
        addr += 8;
        _setloc(txn, backptr, i, txn->end);
    }

    // update the last old checksum
    if (prevptr) _recsum(db, prevptr);

    // head checksum
    *((uint32_t *)(addr)) = htonl(db->csum(base, headlen));

    if (taillen) {
        memcpy(addr + 8, key, keylen);
        addr[8+keylen] = 0;
        if (hasval[type]) {
            memcpy(addr + 8 + keylen + 1, val, vallen);
            addr[8+keylen+1+vallen] = 0;
        }
        *((uint32_t *)(addr+4)) = htonl(db->csum(addr+8, taillen));
    }

    /* update header to know details of new record */
    if (hasval[type]) txn->header.num_records++;
    else txn->header.dirty_size += reclen;

    /* track the highest level in this DB */
    if (level > txn->header.maxlevel)
        txn->header.maxlevel = level;

    // track that we've added the record
    loc->ptr = base;
    loc->offset = txn->end;
    txn->end += reclen;
    loc->end = txn->end;
    loc->is_exactmatch = 1;
    loc->map->dirty = 1;

    return 0;
}

/************ DATABASE STRUCT AND TRANSACTION MANAGEMENT **************/

static int db_is_clean(struct dbengine *db)
{
    if (db->header.flags & DIRTY)
        return 0;

    return 1;
}

static int unlock(struct dbengine *db, struct tm_file *file)
{
    struct flock fl;

    if (!file) file = db->openfile;

    for (;;) {
        fl.l_type= F_UNLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        if (fcntl(file->fd, F_SETLKW, &fl) < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        break;
    }

    file->has_lock = 0;

    return 0;
}

static struct txn *_newtxn_write(struct dbengine *db)
{
    assert(db->openmap);
    assert(!db->write_txn);
    assert(db->openfile);
    assert(db->openfile->has_lock == 2);

    /* create the transaction */
    struct txn *txn = xzmalloc(sizeof(struct txn));
    txn->header = db->header;
    txn->file = db->openfile;
    db->openfile->refcount++;
    txn->end = db->header.current_size;
    db->write_txn = txn;

    return txn;
}

// read transaction doesn't need to have a map open, just a file
// that we can grab a reference to and hence keep open and keep
// reading from until the end!
static struct txn *_newtxn_read(struct dbengine *db)
{
    assert(db->openmap);
    assert(db->openfile);

    /* create the transaction */
    struct txn *txn = xzmalloc(sizeof(struct txn));
    txn->header = db->header;
    txn->file = db->openfile;
    db->openfile->refcount++;
    txn->end = db->header.current_size;
    txn->readonly = 1;
    txn->next = db->read_txn;
    db->read_txn = txn;

    return txn;
}

static int write_lock(struct dbengine *db, struct txn **tidptr)
{
    if (db->readonly) return CYRUSDB_LOCKED;

    struct stat sbuf, sbuffile;
    struct flock fl;

    if (!db->openfile) goto newfile;

    for (;;) {
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        if (fcntl(db->openfile->fd, F_SETLKW, &fl) < 0) {
            if (errno = EINTR) continue;
            xsyslog(LOG_ERR, "IOERROR: lock_exclusive failed",
                             "filename=<%s>", db->fname);
            return -EIO;
        }

        if (fstat(db->openfile->fd, &sbuf) == -1) {
            xsyslog(LOG_ERR, "IOERROR: fstat failed",
                             "filename=<%s>", db->fname);
            unlock(db, NULL);
            return -EIO;
        }

        if (stat(db->fname, &sbuffile) == -1) {
            xsyslog(LOG_ERR, "IOERROR: stat failed",
                             "filename=<%s>", db->fname);
            unlock(db, NULL);
            return -EIO;
        }

        if (sbuf.st_ino == sbuffile.st_ino) break;

    newfile:
        int newfd = open(db->fname, O_RDWR, 0644);
        if (newfd == -1) {
            xsyslog(LOG_ERR, "IOERROR: open failed",
                             "filename=<%s>", db->fname);
            unlock(db, NULL);
            return -EIO;
        }

        // new file, create a new mapping
        struct tm_file *file = db->openfile;
        db->openfile = xzmalloc(sizeof(struct tm_file));
        db->openfile->fd = newfd;
        db->openfile->next = file;
    }

    db->openfile->has_lock = 2;

    // opening a new file, create the header
    if (!sbuf.st_size) {
        struct db_header header;
        int i;
        size_t headlen = HLCALC(DUMMY, MAXLEVEL);
        size_t reclen = headlen + /*crcs*/8;

        // make sure we have a checksum engine when we make the header
        set_csum_engine(db, twom_default_checksum_engine);

        // make sure there's space in the file
        int r = tm_ensure(db, db->openloc, HEADER_SIZE + reclen);
        if (r) return r;

        // write a blank dummy record
        char *base = db->openmap->base + HEADER_SIZE;
        memset(base, 0, reclen);
        *((uint8_t *)(base)) = DUMMY;
        *((uint8_t *)(base+1)) = MAXLEVEL;
        *((uint32_t *)(base+headlen)) = htonl(db->csum(base, headlen));

        // prepare the header
        header.version = VERSION;
        header.checksum_engine = twom_default_checksum_engine;
        header.flags = 0;
        header.num_records = 0;
        for (i = 0; i < 16; i++) {
            header.uuid[i] = rand() % 256;
        }
        header.generation = 1;
        header.dirty_size = 0;
        header.repack_size = HEADER_SIZE + reclen;
        header.current_size = HEADER_SIZE + reclen;
        header.maxlevel = 0;
        r = commit_header(db, &header);
        if (r) return r;
    }
    else if (!db->openmap || db->openmap->file != db->openfile) {
        // we need to open a new mmap too
        struct tm_map *map = db->openmap;
        db->openmap = xzmalloc(sizeof(struct tm_map));
        db->openmap->base = mmap((caddr_t)0, sbuf.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, db->openfile->fd, 0L);
        db->openmap->size = sbuf.st_size;
        db->openmap->file = db->openfile;
        db->openmap->next = map;
        tm_cleanup(db);
    }

    /* reread header */
    int r = read_header(db, db->openmap, &db->header);
    if (r) return r;

    if (!db_is_clean(db)) {
        r = recovery(db);
        if (r) return r;
    }

    if (tidptr) {
        *tidptr = _newtxn_write(db);
    }
    else {
        unlock(db, NULL);
    }

    return 0;
}

static int read_lock(struct dbengine *db, struct txn **tidptr, struct tm_file *forcefile)
{
    struct stat sbuf, sbuffile;
    int r = 0;
    struct flock fl;
    struct tm_file *file = forcefile ? forcefile : db->openfile;

    for (;;) {
        fl.l_type = F_RDLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;
        if (fcntl(file->fd, F_SETLKW, &fl) < 0) {
            if (errno = EINTR) continue;
            xsyslog(LOG_ERR, "IOERROR: lock_shared failed",
                             "filename=<%s>", db->fname);
            return -EIO;
        }

        if (fstat(file->fd, &sbuf) == -1) {
            xsyslog(LOG_ERR, "IOERROR: fstat failed",
                             "filename=<%s>", db->fname);
            unlock(db, file);
            return -EIO;
        }

        if (sbuf.st_size < HEADER_SIZE + HLCALC(DUMMY, MAXLEVEL) + 8)
            goto badfile;

        // we're not interested in getting the latest file
        if (forcefile) break;

        if (stat(db->fname, &sbuffile) == -1) {
            xsyslog(LOG_ERR, "IOERROR: stat failed",
                             "filename=<%s>", db->fname);
            unlock(db, NULL);
            return -EIO;
        }
        if (sbuf.st_ino == sbuffile.st_ino) break;

        int newfd = open(db->fname, db->readonly ? O_RDONLY : O_RDWR, 0644);
        if (newfd == -1) {
            xsyslog(LOG_ERR, "IOERROR: open failed",
                             "filename=<%s>", db->fname);
            unlock(db, NULL);
            return -EIO;
        }

        // new file!
        file = xzmalloc(sizeof(struct tm_file));
        file->fd = newfd;
        file->next = db->openfile;
        db->openfile = file;
    }

    file->has_lock = 1;

    // lots of ways that the map could be not the right type...
    if (!db->openmap || db->openmap->file != file || db->openmap->size < (size_t)sbuf.st_size) {
        struct tm_map *map = xzmalloc(sizeof(struct tm_map));
        map->next = db->openmap;
        map->file = file;
        file->refcount++;
        db->openmap = map;
        // cleanup first to remove unused maps before creating a new one
        tm_cleanup(db);
        /* map the new space (note: we map READ|WRITE even for readonly locks,
         * if we might lock for write later and want to reuse the mmap */
        int flags = db->readonly ? PROT_READ : PROT_READ|PROT_WRITE;
        map->base = mmap((caddr_t)0, sbuf.st_size, flags, MAP_SHARED, file->fd, 0L);
        map->size = sbuf.st_size;
    }

    /* reread header */
    r = read_header(db, db->openmap, &db->header);
    if (r) return r;

    /* we can't read an unclean database */
    if (!db_is_clean(db)) {
    badfile:
        /* we have to be able to re-lock safely */
        if (db->readonly) return -EIO;
        if (forcefile) return -EIO; // bogus; you can't have an unclean old file!
        /* if we take a write lock, that will repair it */
        unlock(db, file);
        // no txn, release the write_lock after repairing if needed
        r = write_lock(db, NULL);
        if (r) return r;
        /* if we want a transaction, we'll need to re-lock with the readlock */
        if (tidptr) return read_lock(db, tidptr, NULL);
    }

    if (tidptr) {
        if (!*tidptr) *tidptr = _newtxn_read(db);
    }
    else {
        unlock(db, file);
    }

    return 0;
}

static int refreshtxn(struct dbengine *db, int readonly, struct txn **tidptr)
{
    if (*tidptr) {
        if ((*tidptr)->readonly || readonly) {
            if (db->openfile->has_lock) return 0;
            return read_lock(db, tidptr, (*tidptr)->file);
        }
        if (db->openfile->has_lock == 2) return 0;
        return CYRUSDB_LOCKED;
    }

    if (readonly) {
        /* if we're already in a lock, that's fine! */
        if (db->openfile->has_lock) {
            *tidptr = _newtxn_read(db);
            return 0;
        }
        return read_lock(db, tidptr, NULL);
    }

    return write_lock(db, tidptr);
}

static void dispose_db(struct dbengine *db)
{
    if (!db) return;
    empty_db(db);
    free(db->fname);
    free(db);
}

/************************************************************/

static int mylock(struct dbengine *db, struct txn **tidptr, int flags)
{
    return refreshtxn(db, flags & CYRUSDB_SHARED, tidptr);
}

static int opendb(const char *fname, int flags, struct dbengine **ret, struct txn **tidptr)
{
    struct dbengine *db;
    int r;
    int create = (flags & CYRUSDB_CREATE) ? 1 : 0;

    assert(fname);
    assert(ret);

    db = (struct dbengine *) xzmalloc(sizeof(struct dbengine));
    db->readonly = (flags & CYRUSDB_SHARED) ? 1 : 0;
    db->nocompact = (flags & CYRUSDB_NOCOMPACT) ? 1 : 0;
    db->nocsum = (flags & CYRUSDB_NOCRC) ? 1 : 0;
    db->fname = xstrdup(fname);
    db->compar = bsearch_ncompare_raw;
    db->foreach_lock_release = FOREACH_LOCK_RELEASE;

    int fflags = db->readonly ? O_RDONLY : (create ? O_RDWR|O_CREAT : O_RDWR);
    int fd = open(db->fname, fflags, 0644);
    if (fd < 0 && errno == ENOENT) {
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
        fd = open(db->fname, fflags, 0644);
        if (fd < 0) {
            r = CYRUSDB_IOERROR;
            goto done;
        }
    }

    db->openfile = xzmalloc(sizeof(struct tm_file));
    db->openfile->fd = fd;

    if (db->readonly || !tidptr) {
        /* grab a read lock to read the header */
        r = read_lock(db, tidptr, NULL);
        if (r) goto done;
    }
    else {
        /* go straight for a write lock and hold it */
        r = write_lock(db, tidptr);
        if (r) goto done;
    }

    *ret = db;

done:
    if (r) dispose_db(db);
    return r;
}

static int myopen(const char *fname, int flags, struct dbengine **ret, struct txn **tidptr)
{
    struct dbengine *mydb;
    int r = 0;

    /* do we already have this DB open? */
    for (mydb = open_twom; mydb; mydb = mydb->next) {
        if (strcmp(mydb->fname, fname)) continue;
        if (tidptr) {
            r = refreshtxn(mydb, flags & CYRUSDB_SHARED, tidptr);
            if (r) return r;
        }
        mydb->refcount++;
        *ret = mydb;
        return 0;
    }

    r = opendb(fname, flags, &mydb, tidptr);
    if (r) return r;

    /* track this database in the open list */
    mydb->refcount = 1;
    mydb->next = open_twom;
    open_twom = mydb;

    /* return the open DB */
    *ret = mydb;

    return 0;
}

static int myclose(struct dbengine *db)
{
    struct dbengine *mydb = open_twom;
    struct dbengine *prev = NULL;

    assert(db);

    /* remove this DB from the open list */
    while (mydb && mydb != db) {
        prev = mydb;
        mydb = mydb->next;
    }
    assert(mydb);

    if (--mydb->refcount <= 0) {
        if (prev) prev->next = mydb->next;
        else open_twom = mydb->next;
        dispose_db(mydb);
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

    assert(db);
    if (datalen) assert(data);

    if (data) *data = NULL;
    if (datalen) *datalen = 0;

    if (tidptr) {
        r = refreshtxn(db, db->readonly, tidptr);
    } else {
        /* grab a r lock */
        tidptr = &localtid;
        r = refreshtxn(db, 1/*shared*/, tidptr);
    }
    if (r) return r;

    (*tidptr)->counter++;

    if (!db->openloc)
        db->openloc = xzmalloc(sizeof(struct tm_loc));

    r = find_loc(db, (*tidptr), db->openloc, key, keylen);
    if (r) goto done;

    if (fetchnext) {
        r = advance_loc(db, (*tidptr), db->openloc);
        if (r) goto done;
    }

    if (foundkey) *foundkey = KEYPTR(db->openloc->ptr);
    if (foundkeylen) *foundkeylen = KEYLEN(db->openloc->ptr);

    // if there's no match, this key never existed
    if (!db->openloc->is_exactmatch) {
        /* we didn't get an exact match */
        r = CYRUSDB_NOTFOUND;
        goto done;
    }

    const char *ptr = db->openloc->ptr;
    size_t offset = db->openloc->offset;
    while (offset >= (*tidptr)->end) {
        offset = ANCESTOR(ptr);
        if (!offset) {
            r = CYRUSDB_NOTFOUND;
            goto done;
        }
        ptr = safeptr(db->openloc, offset);
        if (!ptr) {
            r = CYRUSDB_IOERROR;
            goto done;
        }
    }

    if (hasval[TYPE(ptr)]) {
        r = check_tailcsum(db, ptr, offset);
        if (r) goto done;
        if (data) *data = VALPTR(ptr);
        if (datalen) *datalen = VALLEN(ptr);
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

    assert(db);
    assert(cb);
    if (prefixlen) assert(prefix);

    if (tidptr) {
        r = refreshtxn(db, db->readonly, tidptr);
    } else {
        /* grab a r lock */
        tidptr = &localtid;
        r = refreshtxn(db, 1/*shared*/, tidptr);
    }
    if (r) return r;

    struct tm_loc *loc = xzmalloc(sizeof(struct tm_loc));

    r = find_loc(db, *tidptr, loc, prefix, prefixlen);
    if (r) goto done;

    if (!loc->is_exactmatch) {
        /* advance to the first match */
        r = advance_loc(db, *tidptr, loc);
        if (r) goto done;
    }

    while (loc->is_exactmatch) {
        /* does it match prefix? */
        if (prefixlen) {
            if (KEYLEN(loc->ptr) < prefixlen) break;
            if (db->compar(KEYPTR(loc->ptr), prefixlen, prefix, prefixlen)) break;
        }

        // release locks every N records
        if ((*tidptr)->readonly && (*tidptr)->counter > db->foreach_lock_release) {
            r = unlock(db, (*tidptr)->file);
            if (r) goto done;

            (*tidptr)->counter = 0;

            r = read_lock(db, tidptr, (*tidptr)->file);
            if (r) goto done;

            /* should be cheap if we're already here */
            r = relocate(db, *tidptr, loc);
            if (r) goto done;
        }

        (*tidptr)->counter++;

        size_t offset = loc->offset;
        const char *ptr = loc->ptr;
        while (offset >= (*tidptr)->end) {
            offset = ANCESTOR(ptr);
            if (!offset) goto next;
            ptr = safeptr(loc, offset);
            if (!ptr) {
                r = CYRUSDB_IOERROR;
                goto done;
            }
        }

        if (!hasval[TYPE(ptr)]) goto next;

        const char *key = KEYPTR(ptr);
        size_t keylen = KEYLEN(ptr);
        const char *val = VALPTR(ptr);
        size_t vallen = VALLEN(ptr);

        if ((!goodp || goodp(rock, key, keylen, val, vallen))) {
            if (localtid) {
                r = mycommit(db, localtid);
                localtid = NULL;
                if (r) goto done;

                /* make callback */
                cb_r = cb(rock, key, keylen, val, vallen);
                if (cb_r) break;

                r = refreshtxn(db, 1/*shared*/, &localtid);
                if (r) goto done;
            }
            else {
                /* just make the callback */
                cb_r = cb(rock, key, keylen, val, vallen);
                if (cb_r) break;
            }
        }

    next:
        /* move to the next one */
        r = advance_loc(db, *tidptr, loc);
        if (r) goto done;
    }

 done:

    if (loc->map) loc->map->refcount--;
    free(loc);

    if (localtid) {
        /* release read lock */
        int r1 = mycommit(db, localtid);
        if (r1) return r1;
    }

    return r ? r : cb_r;
}

static int myreplay(struct dbengine *db, struct txn *txn,
                    foreach_cb *cb, void *rock)
{
    int r;

    while (txn->end < db->header.current_size) {
        if (txn->counter > db->foreach_lock_release) {
            r = unlock(db, NULL);
            if (r) return r;
            r = read_lock(db, &txn, NULL);
            if (r) return r;
            txn->counter = 0;
        }
        txn->counter++;
        const char *ptr = db->openmap->base + txn->end;
        if (hasval[TYPE(ptr)]) {
            r = cb(rock, KEYPTR(ptr), KEYLEN(ptr), VALPTR(ptr), VALLEN(ptr));
        }
        else {
            r = cb(rock, KEYPTR(ptr), KEYLEN(ptr), NULL, 0);
        }
        if (r) return r;
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
    struct tm_loc *loc = db->openloc;
    struct txn *txn = db->write_txn;

    assert(txn);

    int r = find_loc(db, txn, loc, key, keylen);
    if (r) return r;

    /* could be a delete or a replace */
    if (loc->is_exactmatch && hasval[TYPE(loc->ptr)]) {
        if (!data) return store_here(db, key, keylen, NULL, 0);
        if (!force) return CYRUSDB_EXISTS;
        /* unchanged?  Save the IO */
        if (!db->compar(data, datalen, VALPTR(loc->ptr), VALLEN(loc->ptr)))
            return 0;
    }

    /* only create if it's not a delete, obviously */
    if (data) return store_here(db, key, keylen, data, datalen);

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

static int myabort_locked(struct dbengine *db, struct txn *txn)
{
    if (txn != db->write_txn) {
        struct txn **ptr;
        for (ptr = &db->read_txn; *ptr; ptr = &(*ptr)->next)
            if (*ptr == txn) break;
        assert(*ptr);
        _remove_txn(ptr);
        tm_cleanup(db);
        return 0;
    }

    int r = recovery(db);
    txn->file->refcount--;
    free(txn);
    db->write_txn = NULL;
    tm_cleanup(db);

    return r;
}

static int mycommit_locked(struct dbengine *db, struct txn *txn)
{
    if (txn != db->write_txn) {
        struct txn **ptr;
        for (ptr = &db->read_txn; *ptr; ptr = &(*ptr)->next)
            if (*ptr == txn) break;
        assert(*ptr);
        _remove_txn(ptr);
        tm_cleanup(db);
        return 0;
    }

    int r = 0;

    assert(db);
    assert(txn);

    /* no need to commit if we're not dirty */
    if (!(txn->header.flags & DIRTY))
        goto done;

    assert(txn->header.current_size == db->header.current_size);
    assert(txn->header.generation == db->header.generation);

    struct tm_loc *loc = db->openloc;

    size_t headlen = 16;
    size_t reclen = 24;

    r = tm_ensure(db, loc, txn->end + reclen);
    if (r) goto done;

    char *base = loc->map->base + txn->end;
    memset(base, 0, reclen); // zero out the whole thing before we set just the bits we want

    *((uint8_t *)(base)) = COMMIT;
    *((uint64_t *)(base+8)) = htonll(txn->header.current_size);
    *((uint32_t *)(base+16)) = htonl(db->csum(base, headlen));

    txn->end += reclen;
    loc->end = txn->end;
    loc->map->dirty = 1;

    /* commit ALL outstanding changes first, before
     * rewriting the header */
    r = tm_commit(db, txn->end);
    if (r) goto done;

    /* finally, update the header and commit again */
    txn->header.current_size = txn->end;
    txn->header.flags &= ~DIRTY;
    db->header = txn->header;
    r = commit_header(db, &db->header);
    if (r) goto done;

    if (!db->nocompact
           && txn->header.dirty_size > MINREWRITE
           && txn->header.current_size < 4 * txn->header.dirty_size) {
        // delay the checkpoint until the user isn't waiting
        struct dcrock *drock = xzmalloc(sizeof(struct dcrock));
        drock->fname = xstrdup(db->fname);
        drock->flags = 0;
        libcyrus_delayed_action(drock->fname, _delayed_checkpoint,
                                _delayed_checkpoint_free, drock);
    }

 done:
    if (r) {
        int r2;

        /* error during commit; we must abort */
        r2 = myabort_locked(db, txn);
        if (r2) {
            xsyslog(LOG_ERR, "DBERROR: commit AND abort failed",
                             "filename=<%s>",
                             db->fname);
        }
        return r;
    }

    txn->file->refcount--;
    free(txn);
    db->write_txn = NULL;
    tm_cleanup(db);

    return 0;
}

static int myabort(struct dbengine *db, struct txn *tid)
{
    if (!tid) return 0;
    int r = myabort_locked(db, tid);
    unlock(db, NULL);
    return r;
}

static int mycommit(struct dbengine *db, struct txn *tid)
{
    if (!tid) return 0;
    int r = mycommit_locked(db, tid);
    unlock(db, NULL);
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

    /* no writing a readonly database */
    if (db->readonly)
        return CYRUSDB_READONLY;

    /* not keeping the transaction, just create one local to
     * this function or use the existing one */
    if (!tidptr) {
        if (db->write_txn) tidptr = &db->write_txn;
        else tidptr = &localtid;
    }

    /* make sure we're write locked and up to date */
    if (!*tidptr) {
        r = refreshtxn(db, 0/*shared*/, tidptr);
        if (r) return r;
    }

    assert (*tidptr = db->write_txn);

    if (!db->openloc)
        db->openloc = xzmalloc(sizeof(struct tm_loc));

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
                   const char *data, size_t datalen)
{
    struct copy_rock *cr = (struct copy_rock *)rock;
    int i;

    /* minimal logic from find_loc and stitch knowing that we're
     * always writing at the end of a file */
    struct tm_loc *loc = cr->db->openloc;
    uint8_t level = LEVEL(loc->ptr);
    for (i = 0; i < level; i++)
        loc->backloc[i] = loc->offset;
    loc->is_exactmatch = 0;
    return store_here(cr->db, key, keylen, data, datalen);
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

    // now that the rename is done, we can move everything over
    unlock(db, NULL);
    char *fname = db->fname;
    empty_db(db);
    *db = *new;
    free(db->fname);
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

    r = refreshtxn(db, 1/*shared*/, &txn);
    if (r) return r;

    r = myconsistent(db, txn);
    if (r) {
        syslog(LOG_ERR, "db %s, inconsistent pre-checkpoint, bailing out",
               db->fname);
        int r2 = mycommit(db, txn);
        return r2 ? r2 : r;
    }

    /* open fname.NEW */
    snprintf(newfname, sizeof(newfname), "%s.NEW", db->fname);
    xunlink(newfname);

    cr.db = NULL;
    cr.tid = NULL;
    r = opendb(newfname, CYRUSDB_CREATE, &cr.db, &cr.tid);
    if (r) return r;

    // this MUST be an empty file
    assert(!cr.db->header.num_records);
    assert(cr.db->header.generation == 1);
    cr.db->openloc = xzmalloc(sizeof(struct tm_loc));

    // we'll likely need about this much space, pre-allocate
    tm_ensure(cr.db, cr.db->openloc, db->header.current_size - db->header.dirty_size);

    r = relocate(cr.db, cr.tid, cr.db->openloc);
    if (r) goto err;

    // we're just doing small copies, release less frequently
    db->foreach_lock_release *= 256;

    // mvcc process all the existing records
    r = myforeach(db, NULL, 0, NULL, copy_cb, &cr, &txn);
    if (r) goto err;

    // replay all the remaining changes to the end of the file
    r = myreplay(db, txn, replay_cb, &cr);

    // we still need a read-lock at this point
    assert(LOCKED(db->openfile));

    // nobody rewrote under us (shouldn't be possible, but if there is a bug this
    // will protect us from losing records)
    assert(db->header.generation == txn->header.generation);

    /* remember the repack size */
    cr.db->header.repack_size = cr.tid->end;

    /* same uuid */
    memcpy(cr.db->header.uuid, db->header.uuid, 16);

    /* increase the generation count */
    cr.db->header.generation = db->header.generation + 1;
    cr.tid->header.generation = cr.db->header.generation;

    r = mycommit_locked(cr.db, cr.tid);
    if (r) goto err;

    /* move new file to original file name */
    r = mm_rename(cr.db, db);
    if (r) goto err;

    {
        syslog(LOG_INFO,
               "twom: checkpointed %s (%llu record%s, %llu => %llu bytes) in %2.3f seconds",
               db->fname, (LLU)db->header.num_records,
               db->header.num_records == 1 ? "" : "s", (LLU)old_size,
               (LLU)(db->header.current_size),
               (sclock() - start) / (double) CLOCKS_PER_SEC);
    }

    unlock(db, NULL);
    return 0;

 err:
    xunlink(cr.db->fname);
    myclose(cr.db);
    unlock(db, NULL);
    return CYRUSDB_IOERROR;
}

static int dump(struct dbengine *db, int detail)
{
    struct buf scratch = BUF_INITIALIZER;
    const char *ptr;
    size_t offset = DUMMY_OFFSET;
    struct txn *txn = NULL;
    int r = 0;
    int i;

    r = read_lock(db, &txn, NULL);
    if (r) goto done;

    if (!db->openloc)
        db->openloc = xzmalloc(sizeof(struct tm_loc));

    r = find_loc(db, txn, db->openloc, NULL, 0);
    if (r) goto done;

    printf("HEADER: v=%lu g=%llu fl=%lu num=%llu sz=(%08llX/%08llX/%08llX)\n",
          (LU)db->header.version,
          (LLU)db->header.generation,
          (LU)db->header.flags,
          (LLU)db->header.num_records,
          (LLU)db->header.dirty_size,
          (LLU)db->header.current_size,
          (LLU)db->header.repack_size);

    while (offset < db->header.current_size) {
        printf("%08llX ", (LLU)offset);

        ptr = safeptr(db->openloc, offset);
        if (!ptr) {
            printf("ERROR\n");
            break;
        }

        if (check_headcsum(db, ptr, offset)) {
            printf("ERROR [HEADCSUM %08lX %08lX] ",
                    (long unsigned) HEADCSUM(ptr),
                    (long unsigned) db->csum(ptr, HEADLEN(ptr)));
        }

        if (check_tailcsum(db, ptr, offset)) {
            printf("ERROR [TAILCSUM %08lX %08lX] ",
                    (long unsigned) TAILCSUM(ptr),
                    (long unsigned) db->csum(KEYPTR(ptr), TAILLEN(ptr)));
        }

        uint8_t type = TYPE(ptr);
        if (type == COMMIT) {
            printf("COMMIT start=%08llX\n", (LLU)NEXT0(ptr, 0));
        }
        else {
            buf_setmap(&scratch, KEYPTR(ptr), KEYLEN(ptr));
            buf_replace_char(&scratch, '\0', '-');
            printf("%s kl=%llu dl=%llu lvl=%d (%s)\n",
                   typestr[type],
                   (LLU)KEYLEN(ptr), (LLU)VALLEN(ptr),
                   LEVEL(ptr), buf_cstring(&scratch));
            if (hasancestor[type]) {
                printf("\t%08llX <-\n", (LLU)ANCESTOR(ptr));
            }
            printf("\t%08llX %08llX", (LLU)NEXT0(ptr, 0), (LLU)NEXT0(ptr, 1));
            uint8_t level = LEVEL(ptr);
            for (i = 1; i < level; i++) {
                if (!((i-1) % 8))
                    printf("\n\t");
                printf("%08llX ", (LLU)NEXTN(ptr, i));
            }
            printf("\n");
            if (detail > 2) {
                buf_setmap(&scratch, VALPTR(ptr), VALLEN(ptr));
                buf_replace_char(&scratch, '\0', '-');
                printf("\tv=(%s)\n", buf_cstring(&scratch));
            }
        }

        offset += RECLEN(ptr);
    }
done:

    buf_free(&scratch);
    myabort(db, txn);

    return r;
}

static int consistent(struct dbengine *db)
{
    int r;
    struct txn *txn = NULL;

    r = read_lock(db, &txn, NULL);
    if (r) return r;

    r = myconsistent(db, txn);

    myabort(db, txn);

    return r;
}

/* perform some basic consistency checks */
static int consistent1(struct dbengine *db, struct tm_loc *loc, struct txn *txn)
{
    size_t next[MAXLEVEL];
    size_t num_records = 0;
    size_t dirty_size = 0;
    const char *ptr;
    int cmp;
    int i;

    assert(db->openmap);
    assert(db->openmap->size >= txn->end);

    /* set up the location pointers */
    ptr = safeptr(loc, DUMMY_OFFSET);
    if (!ptr) {
        xsyslog(LOG_ERR, "DBERROR: failed to read DUMMY for consistent",
                "fname=<%s>", db->fname);
        return CYRUSDB_IOERROR;
    }
    for (i = 0; i < MAXLEVEL; i++)
        next[i] = advance(loc, ptr, i);

    while (next[0]) {
        const char *nextptr = safeptr(loc, next[0]);
        if (!nextptr) {
            xsyslog(LOG_ERR, "DBERROR: failed to read next record for consistent",
                    "fname=<%s> prev_key=<%.*s> offset=<%08llX>",
                    db->fname, (int)KEYLEN(ptr), KEYPTR(ptr), (LLU)next[0]);
            return CYRUSDB_IOERROR;
        }

        cmp = db->compar(KEYPTR(nextptr), KEYLEN(nextptr),
                         KEYPTR(ptr), KEYLEN(ptr));
        if (cmp <= 0) {
            xsyslog(LOG_ERR, "DBERROR: twom out of order",
                    "fname=<%s> key=<%.*s> offset=<%08llX>"
                    " prev_key=<%.*s>",
                    db->fname, (int)KEYLEN(nextptr), KEYPTR(nextptr), (LLU)next[0],
                    (int)KEYLEN(ptr), KEYPTR(ptr));
            return CYRUSDB_INTERNAL;
        }

        size_t ancestor = ANCESTOR(nextptr);
        while (ancestor) {
            const char *aptr = safeptr(loc, ancestor);
            if (!aptr) {
                xsyslog(LOG_ERR, "DBERROR: failed to read ancestor for consistent",
                        "fname=<%s> key=<%.*s> offset=<%08llX>",
                        db->fname, (int)KEYLEN(nextptr), KEYPTR(nextptr),
                        (LLU)ancestor);
                return CYRUSDB_IOERROR;
            }
            cmp = db->compar(KEYPTR(aptr), KEYLEN(aptr),
                             KEYPTR(nextptr), KEYLEN(nextptr));
            if (cmp) {
                xsyslog(LOG_ERR, "DBERROR: twom mismatched ancestor",
                        "fname=<%s> key=<%.*s> offset=<%08llX>"
                        " parent_key=<%.*s> parent_offset=<%08llX)",
                        db->fname, (int)KEYLEN(nextptr), KEYPTR(nextptr), (LLU)next[0],
                        (int)KEYLEN(aptr), KEYPTR(aptr), (LLU)ancestor);
                return CYRUSDB_IOERROR;
            }
            dirty_size += RECLEN(aptr);
            ancestor = ANCESTOR(aptr);
        }

        uint8_t type = TYPE(nextptr);
        uint8_t level = LEVEL(nextptr);
        size_t offset = next[0];
        for (i = 0; i < level; i++) {
            /* check the old pointer was to here */
            if (next[i] != offset) {
                xsyslog(LOG_ERR, "DBERROR: twom broken linkage",
                                 "fname=<%s> offset=<%08llX> level=<%d>"
                                 " expected=<%08llX>",
                                 db->fname, (LLU)offset, i, (LLU)next[i]);
                return CYRUSDB_INTERNAL;
            }
            /* and advance to the new pointer */
            next[i] = advance(loc, nextptr, i);
        }

        // count if record or tombstone
        if (hasval[type]) num_records++;
        else dirty_size += RECLEN(nextptr);

        ptr = nextptr;
    }

    for (i = 0; i < MAXLEVEL; i++) {
        if (next[i]) {
            xsyslog(LOG_ERR, "DBERROR: twom broken tail",
                             "filename=<%s> offset=<%08llX> level=<%d>",
                             db->fname, (LLU)next[i], i);
            return CYRUSDB_INTERNAL;
        }
    }

    /* we walked the whole file and saw every pointer */

    if (num_records != txn->header.num_records) {
        xsyslog(LOG_ERR, "DBERROR: twom record count mismatch",
                         "filename=<%s> num_records=<%llu> expected_records=<%llu>",
                         db->fname, (LLU)num_records, (LLU)txn->header.num_records);
        return CYRUSDB_INTERNAL;
    }

    if (dirty_size != txn->header.dirty_size) {
        xsyslog(LOG_ERR, "DBERROR: twom dirty_size mismatch",
                         "filename=<%s> dirty_size=<%llu> expected_size=<%llu>",
                         db->fname, (LLU)dirty_size, (LLU)txn->header.dirty_size);
        return CYRUSDB_INTERNAL;
    }

    return 0;
}

static int myconsistent(struct dbengine *db, struct txn *txn)
{
    struct tm_loc *loc = xzmalloc(sizeof(struct tm_loc));
    loc->map = db->openmap;
    loc->end = db->header.current_size;
    loc->map->refcount++;
    int r = consistent1(db, loc, txn);
    loc->map->refcount--;
    free(loc);
    return r;
}

/* run recovery on this file.
 * always called with a write lock. */
static int recovery1(struct dbengine *db, struct tm_loc *loc, int *count)
{
    size_t prev[MAXLEVEL+1];
    size_t next[MAXLEVEL+1];
    uint64_t num_records = 0;
    uint64_t dirty_size = 0;
    int changed = 0;
    int r = 0;
    int cmp;
    int i;

    /* no need to run recovery if we're consistent */
    if (db_is_clean(db))
        return 0;

    assert(WRITELOCKED(db->openfile));

    const char *ptr = safeptr(loc, DUMMY_OFFSET);
    if (!ptr) {
        xsyslog(LOG_ERR, "DBERROR: failed to read DUMMY for recovery",
                "fname=<%s>", db->fname);
        return CYRUSDB_IOERROR;
    }

    for (i = 1; i < MAXLEVEL; i++) {
        prev[i] = DUMMY_OFFSET;
        next[i] = NEXTN(ptr, i);
    }

    /* and pointers forwards */
    prev[0] = DUMMY_OFFSET;
    next[0] = 0;
    for (i = 0; i < 2; i++) {
        size_t this = NEXT0(ptr, i);
        /* check for broken level - pointers, and extract the best next pointer */
        if (this >= loc->end) {
            // zero out bogus pointer
            *((uint64_t *)(ptr + (8 * (ptroffset[DUMMY]+i)))) = 0;
            _recsum(db, (char *)ptr);
            changed++;
        }
        else if (this > next[0]) {
            next[0] = this;
        }
    }

    while (next[0]) {
        const char *nextptr = safeptr(loc, next[0]);
        if (!nextptr) {
            xsyslog(LOG_ERR, "DBERROR: failed to read next record for recovery",
                    "fname=<%s> prev_key=<%.*s> offset=<%08llX>",
                    db->fname, (int)KEYLEN(ptr), KEYPTR(ptr),
                    (LLU)next[0]);
            return CYRUSDB_IOERROR;
        }

        cmp = db->compar(KEYPTR(nextptr), KEYLEN(nextptr),
                         KEYPTR(ptr), KEYLEN(ptr));
        if (cmp <= 0) {
            xsyslog(LOG_ERR, "DBERROR: twom out of order",
                             "fname=<%s> prev_key=<%.*s> key=<%.*s> offset=<%08llX>",
                             db->fname,
                             (int)KEYLEN(ptr), KEYPTR(ptr),
                             (int)KEYLEN(nextptr), KEYPTR(nextptr),
                             (LLU)next[0]);
            return CYRUSDB_INTERNAL;
        }

        size_t ancestor = ANCESTOR(nextptr);
        while (ancestor) {
            const char *aptr = safeptr(loc, ancestor);
            if (!aptr) {
                xsyslog(LOG_ERR, "DBERROR: failed to read ancestor for recovery",
                        "fname=<%s> key=<%.*s> offset=<%08llX>",
                        db->fname, (int)KEYLEN(nextptr), KEYPTR(nextptr),
                        (LLU)ancestor);
                return CYRUSDB_IOERROR;
            }
            cmp = db->compar(KEYPTR(aptr), KEYLEN(aptr),
                             KEYPTR(nextptr), KEYLEN(nextptr));
            if (cmp) {
                xsyslog(LOG_ERR, "DBERROR: twom mismatched ancestor",
                        "fname=<%s> key=<%.*s> offset=<%08llX>"
                        " parent_key=<%.*s> parent_offset=<%08llX)",
                        db->fname, (int)KEYLEN(nextptr), KEYPTR(nextptr), (LLU)next[0],
                        (int)KEYLEN(aptr), KEYPTR(aptr), (LLU)ancestor);
                return CYRUSDB_IOERROR;
            }
            dirty_size += RECLEN(aptr);
            ancestor = ANCESTOR(aptr);
        }

        /* check for old offsets needing fixing */
        uint8_t type = TYPE(nextptr);
        uint8_t level = LEVEL(nextptr);

        for (i = 1; i < level; i++) {
            if (next[i] != next[0]) {
                char *rec = loc->map->base + prev[i];
                *((uint64_t *)(rec + (8 * (ptroffset[TYPE(rec)]+i+1)))) = htonll(next[0]);
                _recsum(db, rec);
                changed++;
            }
            prev[i] = next[0];
            next[i] = NEXTN(nextptr, i);
        }

        prev[0] = next[0];
        next[0] = 0;
        for (i = 0; i < 2; i++) {
            size_t this = NEXT0(nextptr, i);
            /* check for broken level - pointers, and extract the best next pointer */
            if (this >= loc->end) {
                // zero out bogus pointer
                *((uint64_t *)(nextptr + (8 * (ptroffset[type]+i)))) = 0;
                _recsum(db, (char *)nextptr);
                changed++;
            }
            else if (this > next[0]) {
                next[0] = this;
            }
        }

        if (hasval[type]) num_records++;
        else dirty_size += RECLEN(nextptr);

        ptr = nextptr;
    }

    /* check for remaining offsets needing zeroing */
    for (i = 1; i < MAXLEVEL; i++) {
        if (next[i]) {
            char *rec = loc->map->base + prev[i];
            *((uint64_t *)(rec + (8 * (ptroffset[TYPE(rec)]+i+1)))) = htonll(next[0]);
            _recsum(db, rec);
            changed++;
        }
    }

    /* commmit first so all other bits are committed before we undirty the header */
    r = tm_commit(db, loc->end);
    if (r) return r;

    /* clear the dirty flag */
    db->header.flags &= ~DIRTY;
    db->header.num_records = num_records;
    db->header.dirty_size = dirty_size;
    r = commit_header(db, &db->header);
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

    struct tm_loc *loc = xzmalloc(sizeof(struct tm_loc));
    loc->map = db->openmap;
    loc->end = db->header.current_size;
    loc->map->refcount++;

    r = recovery1(db, loc, &count);
    if (r) {
        xsyslog(LOG_ERR, "DBERROR: recovery1 failed",
                         "filename=<%s>",
                         db->fname);
    }
    else {
        syslog(LOG_INFO,
               "twom: recovered %s (%llu record%s, %llu bytes) in %2.3f seconds - fixed %d offset%s",
               db->fname, (LLU)db->header.num_records,
               db->header.num_records == 1 ? "" : "s",
               (LLU)(db->header.current_size),
               (sclock() - start) / (double) CLOCKS_PER_SEC,
               count, count == 1 ? "" : "s");
    }

    loc->map->refcount--;
    free(loc);

    return r;
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

static int myinit(const char *dbdir __attribute__((unused)), int flags __attribute__((unused)))
{
    const char *checksum_engine = libcyrus_config_getstring(CYRUSOPT_TWOM_CHECKSUM_ENGINE);
    if (!checksum_engine) return TWOM_CHECKSUM_XXH64;
    if (!strcmp(checksum_engine, "null")) {
        twom_default_checksum_engine = TWOM_CHECKSUM_NULL;
    }
    else if (!strcmp(checksum_engine, "crc32")) {
        twom_default_checksum_engine = TWOM_CHECKSUM_CRC32;
    }
    else if (!strcmp(checksum_engine, "xxh32")) {
        twom_default_checksum_engine = TWOM_CHECKSUM_XXH32;
    }
    else {
        // default
        twom_default_checksum_engine = TWOM_CHECKSUM_XXH64;
    }
    return 0;
    return 0;
}

HIDDEN struct cyrusdb_backend cyrusdb_twom =
{
    "twom",                  /* name */

    &myinit,
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
};
