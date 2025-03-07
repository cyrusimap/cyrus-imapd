/* twom.c - twoskip implementation with MVCC capability
 *
 * Copyright (c) 2025 Fastmail Pty Ltd
 *
 * https://creativecommons.org/publicdomain/zero/1.0/
 *
 *   The person who associated a work with this deed has dedicated the work to the
 *   public domain by waiving all of his or her rights to the work worldwide under
 *   copyright law, including all related and neighboring rights, to the extent
 *   allowed by law.
 *
 *   You can copy, modify, distribute and perform the work, even for commercial
 *   purposes, all without asking permission.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "twom.h"

#define XXH_STATIC_LINKING_ONLY /* access advanced declarations */
#define XXH_INLINE_ALL          /* maximum optimise */
#define XXH_IMPLEMENTATION      /* access definitions */
#include "xxhash.h"

/********** TUNING *************/

/* don't bother rewriting if the database has less than this much extra */
#define MINREWRITE 16834
/* number of skiplist levels - 31 gives us binary search to 2^32 records.
 * This is the limit to what we can calculate from a single call to random(),
 * but skiplist had 20, and that was enough
 * for most real uses.  31 is heaps. */
#define MAXLEVEL 31

/* release lock in foreach at least every N records */
#define FOREACH_LOCK_RELEASE 1024

/* type aliases */
#define LLU long long unsigned int
#define LU long unsigned int

/* we want to use little endian numbers, most users are on little endian machines */

/* record types */
#define DUMMY 1
#define ADD 2
#define FATADD 3
#define REPLACE 4
#define FATREPLACE 5
#define DELETE 6
#define COMMIT 7
static const char *typestr[] = { NULL, "DUMMY", "ADD", "FATADD",
                          "REPLACE", "FATREPLACE", "DELETE", "COMMIT" };
static uint8_t ptroffset[8]      = { 0,  8,  8, 24, 16, 32,  8,  8 };
static uint8_t ancestoroffset[8] = { 0,  0,  0,  0,  8, 24,  8,  0 };
static uint8_t fatrecord[8]      = { 0,  0,  0,  1,  0,  1,  0,  0 };
static uint8_t hastail[8]        = { 0,  0,  1,  1,  1,  1,  0,  0 };

/********** DATA STRUCTURES *************/

struct tm_header {
    /* header info */
    uuid_t uuid;
    uint32_t version;
    uint32_t flags;
    uint64_t generation;
    uint64_t num_records;
    uint64_t num_commits;
    size_t dirty_size;
    size_t repack_size;
    size_t current_size;
    uint8_t maxlevel;
};

struct tm_file {
    struct tm_header header;
    // header info
    uint32_t (*csum)(const char *base, size_t len);
    int (*compar)(const char *a, size_t alen, const char *b, size_t blen);
    // file descriptor
    int fd;
    // mmap
    char *base;
    size_t size; // the mmap size
    size_t committed_size;  // the end of committed data
    size_t written_size;    // the end of written data (pointers will match)
    int refcount;
    uint8_t has_headlock;
    uint8_t has_datalock;
    unsigned dirty:1;
    // tracking
    struct tm_file *next;
};

/* a location in the twom file.  We always have:
 * offset: if a match this points to the record
 *         with the matching key, otherwise it is zero.
 * deleted_offset: if this is a deleted record, then
 *         deleted_offset points at the DELETE record
 *         and offset points at the ADD or REPLACE
 *         record with the matching key.  The
 *         ANCESTOR of the DELETE record will always
 *         be the same as 'offset'.
 * backloc: the records that point TO this location
 *          at each level, so the `compar` previous
 *          key.
 * end: can be used to see if anything in the file may
 *      have changed and needs relocation.
 */
struct tm_loc {
    struct tm_file *file;
    size_t end;               // pointers are only valid when end matches file end
    size_t offset;            // current position
    size_t deleted_offset;    // was there a deletion in front of the current record?
    size_t backloc[MAXLEVEL+1]; // previous record at every level
};

#define DIRTY (1<<0)

struct twom_txn {
    struct twom_db *db;
    struct tm_file *file;
    size_t end;
    uint64_t counter;
    unsigned readonly:1;
    unsigned nosync:1;
    unsigned noyield:1;
    unsigned mvcc:1;
    struct twom_txn *next;
};

struct twom_cursor {
    struct tm_loc loc;
    struct twom_txn *txn;
    unsigned alwaysyield:1;
};

struct twom_db {
    /* file data */
    char *fname;

    /* tracking info */
    struct tm_loc loc;
    struct tm_file *openfile;
    struct twom_txn *write_txn;
    struct twom_txn *read_txn;

    // init info
    uint32_t (*external_csum)(const char *base, size_t len);
    int (*external_compar)(const char *a, size_t alen, const char *b, size_t blen);
    void (*error)(const char *msg, const char *fmt, ...);

    // scratch space
    char uuidstr[UUID_STR_LEN];

    // flags
    unsigned readonly:1;
    unsigned nocsum:1;
    unsigned nosync:1;
    unsigned noyield:1;
    unsigned nocompact:1;
    int refcount;

    uint64_t foreach_lock_release;

    struct twom_db *next;
};

#define TWOM_VERSION 1

#define HEADER_MAGIC ("\241\002\213\015twomfile\0\0\0\0")
#define HEADER_MAGIC_SIZE (16)

/* offsets of header files */
enum {
    OFFSET_HEADER = 0,
    OFFSET_UUID = 16,
    OFFSET_VERSION = 32,
    OFFSET_FLAGS = 36,
    OFFSET_GENERATION = 40,
    OFFSET_NUM_RECORDS = 48,
    OFFSET_NUM_COMMITS = 56,
    OFFSET_DIRTY_SIZE = 64,
    OFFSET_REPACK_SIZE = 72,
    OFFSET_CURRENT_SIZE = 80,
    OFFSET_MAXLEVEL = 88,
    OFFSET_CSUM = 92,
};

#define HEADER_SIZE 96
#define DUMMY_OFFSET HEADER_SIZE
#define DUMMY_SIZE (24 + (8 * MAXLEVEL))

static struct twom_db *open_twom = NULL;

/********************* LIBRARY SUPPORT FUNCTIONS *******************************/

#ifdef HAVE_DECLARE_OPTIMIZE
static inline void *twom_zmalloc(size_t bytes)
    __attribute__((optimize("-O3")));
#endif
static inline void *twom_zmalloc(size_t bytes)
{
    void *res = malloc(bytes);
    memset(res, 0, bytes);
    return res;
}
/********************** POINTER MANAGEMENT WITHIN THE FILES *********************/

// pad out to an 8 byte boundary
#define PAD8(n) (((n)+7)&~7)

// lots of direct accessors for every part of a message!
#define LOCBACKPTR(loc, n) ((loc)->file->base + (loc)->backloc[n])
#define LOCPTR(loc) ((loc)->file->base + (loc)->offset)
#define TYPE(ptr) (*((uint8_t *)(ptr)))
#define LEVEL(ptr) (*((uint8_t *)(ptr+1)))
// replace and delete records have an extra offset
#define KLSKINNY(ptr) le16toh(*((uint16_t *)(ptr+2)))
#define KLFAT(ptr) le64toh(*((uint64_t *)(ptr+8)))
#define VLSKINNY(ptr) le32toh(*((uint32_t *)(ptr+4)))
#define VLFAT(ptr) le64toh(*((uint64_t *)(ptr+16)))
#define HLCALC(type, level) (ptroffset[type] + (8 * (1 + level)))
#define HEADLEN(ptr) HLCALC(TYPE(ptr), LEVEL(ptr))
#define HEADCSUM(ptr) le32toh(*((uint32_t *)(ptr + HEADLEN(ptr))))
#define TLCALC(type, keylen, vallen) (hastail[type] ? PAD8(keylen + vallen + 2) : 0)
#define TAILLEN(ptr) TLCALC(TYPE(ptr), KEYLEN(ptr), VALLEN(ptr))
#define TAILCSUM(ptr) le32toh(*((uint32_t *)(ptr + HEADLEN(ptr) + 4)))
#define KEYLEN(ptr) (hastail[TYPE(ptr)] ? (fatrecord[TYPE(ptr)] ? KLFAT(ptr) : KLSKINNY(ptr)) : 0)
#define KEYPTR(ptr) (hastail[TYPE(ptr)] ? (ptr + HEADLEN(ptr) + 8) : "")
#define VALLEN(ptr) (fatrecord[TYPE(ptr)] ? VLFAT(ptr) : VLSKINNY(ptr))
#define VALPTR(ptr) (ptr + HEADLEN(ptr) + 8 + KEYLEN(ptr) + 1)
#define ANCESTOR(ptr) (ancestoroffset[TYPE(ptr)] ? le64toh(*((uint64_t *)(ptr+(ancestoroffset[TYPE(ptr)])))) : 0)
#define NEXT0PTR(ptr, alt) (ptr + ptroffset[TYPE(ptr)] + (alt ? 8 : 0))
#define NEXTNPTR(ptr, lvl) (ptr + ptroffset[TYPE(ptr)] + 8 * (1 + lvl))
#define NEXT0(ptr, alt) le64toh(*((uint64_t *)NEXT0PTR(ptr, alt)))
#define NEXTN(ptr, lvl) le64toh(*((uint64_t *)NEXTNPTR(ptr, lvl)))
#define SET0(file, ptr, offset) _setloc0(file, ptr, offset)
#define SETN(ptr, level, offset)  *((uint64_t *)((ptr) + ptroffset[TYPE(ptr)] + 8 * ((level) + 1))) = htole64(offset)

#ifdef HAVE_DECLARE_OPTIMIZE
static size_t reclen_dummy(const char *ptr);
    __attribute__((optimize("-O3")));
#endif
static size_t reclen_dummy(const char *ptr __attribute__((unused)))
{
    return DUMMY_SIZE;
}

#ifdef HAVE_DECLARE_OPTIMIZE
static size_t reclen_add(const char *ptr);
    __attribute__((optimize("-O3")));
#endif
static size_t reclen_add(const char *ptr)
{
    uint8_t level = LEVEL(ptr);
    return 24 + (8 * level) + PAD8(KLSKINNY(ptr) + VLSKINNY(ptr) + 2);
}

#ifdef HAVE_DECLARE_OPTIMIZE
static size_t reclen_fatadd(const char *ptr);
    __attribute__((optimize("-O3")));
#endif
static size_t reclen_fatadd(const char *ptr)
{
    uint8_t level = LEVEL(ptr);
    return 40 + (8 * level) + PAD8(KLFAT(ptr) + VLFAT(ptr) + 2);
}

#ifdef HAVE_DECLARE_OPTIMIZE
static size_t reclen_replace(const char *ptr);
    __attribute__((optimize("-O3")));
#endif
static size_t reclen_replace(const char *ptr)
{
    uint8_t level = LEVEL(ptr);
    return 32 + (8 * level) + PAD8(KLSKINNY(ptr) + VLSKINNY(ptr) + 2);
}

#ifdef HAVE_DECLARE_OPTIMIZE
static size_t reclen_fatreplace(const char *ptr);
    __attribute__((optimize("-O3")));
#endif
static size_t reclen_fatreplace(const char *ptr)
{
    uint8_t level = LEVEL(ptr);
    return 48 + (8 * level) + PAD8(KLFAT(ptr) + VLFAT(ptr) + 2);
}

#ifdef HAVE_DECLARE_OPTIMIZE
static size_t reclen_delete(const char *ptr);
    __attribute__((optimize("-O3")));
#endif
static size_t reclen_delete(const char *ptr __attribute__((unused)))
{
    return 24;
}

#ifdef HAVE_DECLARE_OPTIMIZE
static size_t reclen_commit(const char *ptr);
    __attribute__((optimize("-O3")));
#endif
static size_t reclen_commit(const char *ptr __attribute__((unused)))
{
    return 24;
}

static size_t(*reclenfn[])(const char *) = {
    NULL, reclen_dummy, reclen_add, reclen_fatadd,
    reclen_replace, reclen_fatreplace, reclen_delete, reclen_commit
};

#define RECLEN(ptr) (reclenfn[TYPE(ptr)](ptr))

/* return a "safe" pointer - that's one where it's guaranteed that the entire record
 * fits inside the mapped space for the file */
#ifdef HAVE_DECLARE_OPTIMIZE
static inline const char *safeptr(struct tm_loc *loc, size_t offset)
    __attribute__((optimize("-O3")));
#endif
static inline const char *safeptr(struct tm_loc *loc, size_t offset)
{
    if (!offset) return NULL;
    if (loc->end < offset + 24) return NULL;  // need space for the head info
    const char *base = loc->file->base + offset;
    if (!*base) return NULL; // no type
    if (*base & ~7) return NULL; // invalid type
    if (loc->end < offset + RECLEN(base)) return NULL; // no space for entire record
    return base;
}

/* find the more recent of the forward pointers at level 0 */
#ifdef HAVE_DECLARE_OPTIMIZE
static size_t advance0(const char *ptr, size_t end)
    __attribute__((optimize("-O3")));
#endif
static size_t advance0(const char *ptr, size_t end)
{
    size_t next0 = NEXT0(ptr, 0);
    size_t next1 = NEXT0(ptr, 1);
    if (next0 >= end) return next1;
    if (next1 >= end) return next0;
    if (next0 > next1) return next0;
    return next1;
}

// find random level 1-maxlevel (up to 31 on Linux)
static inline uint8_t randlvl(uint8_t lvl, uint8_t maxlvl)
{
    uint32_t v = random();
    uint8_t i;
    for(i = lvl-1; i < maxlvl-1; i++)
        if (v & (1<<i)) break;
    return i+1;
}

/****************************** COMPARITORS**************************************/

#ifdef HAVE_DECLARE_OPTIMIZE
static int compar_raw(const char *s1, size_t l1, const char *s2, size_t l2)
    __attribute__((optimize("-O3")));
#endif
static int compar_raw(const char *s1, size_t l1, const char *s2, size_t l2)
{
    int min = l1 < l2 ? l1 : l2;
    int r = min ? memcmp(s1, s2, min) : 0;
    if (r) return r;
    if (l1 > l2) return 1;
    if (l2 > l1) return -1;
    return 0;
}

/************** CHECKSUMS ****************/

#ifdef HAVE_DECLARE_OPTIMIZE
static uint32_t csum_null(const char *base, size_t len)
    __attribute__((optimize("-O3")));
#endif
static uint32_t csum_null(const char *base __attribute__((unused)),
                          size_t len __attribute__((unused)))
{
    return 0;
}

#ifdef HAVE_DECLARE_OPTIMIZE
static uint32_t csum_xxh64(const char *base, size_t len)
    __attribute__((optimize("-O3")));
#endif
static uint32_t csum_xxh64(const char *base, size_t len)
{
    if (!len) return 0;
    return (uint32_t)XXH3_64bits(base, len);
}

static uint32_t set_csum_engine(struct twom_db *db, struct tm_file *file, uint32_t flags)
{
    if (flags & TWOM_CSUM_EXTERNAL) {
        file->csum = db->external_csum;
        return TWOM_CSUM_EXTERNAL;
    }
    if (flags & TWOM_CSUM_NULL) {
        file->csum = csum_null;
        return TWOM_CSUM_NULL;
    }
    if (flags & TWOM_CSUM_XXH64) {
        file->csum = csum_xxh64;
        return TWOM_CSUM_XXH64;
    }

    // default
    file->csum = csum_xxh64;
    return TWOM_CSUM_XXH64;
}

static const char *checksum_engine(struct tm_file *file)
{
    if (file->header.flags & TWOM_CSUM_EXTERNAL)
        return "EXTERNAL";
    if (file->header.flags & TWOM_CSUM_NULL)
        return "NULL";
    if (file->header.flags & TWOM_CSUM_XXH64)
        return "XXH64";

    return "UNKNOWN";
}

#ifdef HAVE_DECLARE_OPTIMIZE
static inline int check_headcsum(struct twom_txn *txn, struct tm_file *file, const char *ptr, size_t offset)
    __attribute__((optimize("-O3")));
#endif
static inline int check_headcsum(struct twom_txn *txn, struct tm_file *file, const char *ptr, size_t offset)
{
    if (txn->db->nocsum) return 0;
    uint32_t csum = file->csum(ptr, HEADLEN(ptr));
    if (csum != HEADCSUM(ptr)) {
        txn->db->error("invalid head checksum",
                       "filename=<%s> offset=<%08llX>",
                       txn->db->fname, (LLU)offset);
        return TWOM_BADCHECKSUM;
    }

    return 0;
}

#ifdef HAVE_DECLARE_OPTIMIZE
static inline int check_tailcsum(struct twom_txn *txn, struct tm_file *file, const char *ptr, size_t offset)
    __attribute__((optimize("-O3")));
#endif
static inline int check_tailcsum(struct twom_txn *txn, struct tm_file *file, const char *ptr, size_t offset)
{
    if (txn->db->nocsum) return 0;
    size_t taillen = TAILLEN(ptr);
    if (!taillen) return 0;
    uint32_t csum = file->csum(KEYPTR(ptr), taillen);
    if (csum != TAILCSUM(ptr)) {
        txn->db->error("invalid tail checksum",
                       "filename=<%s> offset=<%08llX>",
                       txn->db->fname, (LLU)offset);
        return TWOM_BADCHECKSUM;
    }

    return 0;
}

/**********************  MMAP MANAGEMENT **************************/

static size_t tm_roundup(size_t offset)
{
    size_t page_size = 1<<14; // 16k
    return ((offset + offset / 4) + page_size - 1) & ~(page_size - 1);
}

static inline int tm_commit(struct twom_db *db, size_t len)
{
    assert(db->openfile);
    if (!db->openfile->dirty) return 0;
    assert(db->openfile->has_datalock == 2);
    // this could clear dirty if msync fails, but we don't have a real
    // way to recover and clearing it now stops us failing asserts later
    // while erroring out and leaving the file dirty.
    db->openfile->dirty = 0;
    if (db->nosync) return 0;
    if (db->write_txn && db->write_txn->nosync) return 0;
    return msync(db->openfile->base, len, MS_SYNC);
}

static inline int tm_ensure(struct twom_db *db, size_t offset)
{
    struct tm_file *file = db->openfile;
    if (offset <= file->size) return 0;

    assert(file);
    assert(file->has_datalock == 2);

    size_t newoffset = tm_roundup(offset);
    assert(newoffset >= offset);

    // unmap first
    if (file->size) munmap(file->base, file->size);

    // extend (could also use fseek and write a NULL byte, or
    if (ftruncate(file->fd, newoffset)) {
        db->error("twom failed to extend file during tm_ensure",
                   "filename=<%s> size=<%08llX> newsize=<%08llX>",
                   db->fname, (LLU)file->size, (LLU)newoffset);
        return TWOM_IOERROR;
    }

    // map the larger file into new memory
    file->size = newoffset;
    file->base = (char *)mmap((caddr_t)0, file->size, PROT_READ|PROT_WRITE, MAP_SHARED, db->openfile->fd, 0L);
    if (!file->base) {
        db->error("twom failed to mmap during tm_ensure",
                   "filename=<%s> newsize=<%08llX>",
                   db->fname, (LLU)file->size);
        return TWOM_IOERROR;
    }

    return 0;
}

/**************** OBJECT CLEANUP ******************/

static void _remove_txn(struct twom_txn **ptr)
{
    struct twom_txn *cur = *ptr;
    struct twom_txn *next = cur->next;
    cur->file->refcount--;
    free(cur);
    *ptr = next;
}

static void _remove_file(struct tm_file **ptr)
{
    struct tm_file *cur = *ptr;
    struct tm_file *next = (*ptr)->next;
    assert(!cur->refcount);
    assert(!cur->has_datalock);
    assert(!cur->has_headlock);
    if (cur->base) munmap(cur->base, cur->size);
    if (cur->fd != -1) close(cur->fd);
    free(cur);
    *ptr = next;
}

static void empty_db(struct twom_db *db)
{
    if (db->loc.file) {
        db->loc.file->refcount--;
        db->loc.file = NULL;
    }
    while (db->write_txn)
        _remove_txn(&db->write_txn);
    while (db->read_txn)
        _remove_txn(&db->read_txn);
    while (db->openfile)
        _remove_file(&db->openfile);
}

static void tm_cleanup(struct twom_db *db)
{
    // close any open files with a zero refcount (no loc or txn
    // still points there) except the first one
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

/************** DATABASE HEADER MANAGEMENT ****************/

/* given an open, mapped db, read in the header information */
static int read_header(struct twom_db *db, struct tm_file *file, struct tm_header *header)
{
    assert(db && file);
    const char *base = file->base;

    if (file->size < HEADER_SIZE + DUMMY_SIZE)
        return TWOM_BADFORMAT;

    if (memcmp(base, HEADER_MAGIC, HEADER_MAGIC_SIZE))
        return TWOM_BADFORMAT;

    memcpy(header->uuid, base + OFFSET_UUID, 16);

    header->version
        = le32toh(*((uint32_t *)(base + OFFSET_VERSION)));

    if (header->version > TWOM_VERSION) {
        db->error("invalid version",
                  "filename=<%s> version=<%d>",
                  db->fname, header->version);
        return TWOM_BADFORMAT;
    }

    header->flags
        = le32toh(*((uint32_t *)(base + OFFSET_FLAGS)));

    if (header->flags & TWOM_CSUM_EXTERNAL) {
        if (!db->external_csum) {
            db->error("missing external csum function",
                      "filename=<%s>", db->fname);
            return TWOM_BADUSAGE;
        }
    }
    set_csum_engine(db, file, header->flags);

    // XXX - check flags for other comparison engines?
    if (header->flags & TWOM_COMPAR_EXTERNAL) {
        if (!db->external_compar) {
            db->error("missing external compar function",
                      "filename=<%s>", db->fname);
            return TWOM_BADUSAGE;
        }
        file->compar = db->external_compar;
    }
    else  {
        file->compar = compar_raw;
    }

    header->generation
        = le64toh(*((uint64_t *)(base + OFFSET_GENERATION)));

    header->num_records
        = le64toh(*((uint64_t *)(base + OFFSET_NUM_RECORDS)));

    header->num_commits
        = le64toh(*((uint64_t *)(base + OFFSET_NUM_COMMITS)));

    header->dirty_size
        = le64toh(*((uint64_t *)(base + OFFSET_DIRTY_SIZE)));

    header->repack_size
        = le64toh(*((uint64_t *)(base + OFFSET_REPACK_SIZE)));

    header->current_size
        = le64toh(*((uint64_t *)(base + OFFSET_CURRENT_SIZE)));

    assert(file->size >= header->current_size);

    header->maxlevel
        = le32toh(*((uint32_t *)(base + OFFSET_MAXLEVEL)));

    if (db->nocsum) return 0;

    uint32_t csum = le32toh(*((uint32_t *)(base + OFFSET_CSUM)));
    if (file->csum(base, OFFSET_CSUM) != csum) {
        db->error("header checksum failure",
                  "filename=<%s>", db->fname);
        return TWOM_BADCHECKSUM;
    }

    return 0;
}

/* given an open, mapped, locked db, write the header information */
static void pack_header(struct tm_header *header, struct tm_file *file, char *base)
{
    memcpy(base, HEADER_MAGIC, HEADER_MAGIC_SIZE);
    memcpy(base + OFFSET_UUID, header->uuid, 16);
    *((uint32_t *)(base + OFFSET_VERSION)) = htole32(header->version);
    *((uint32_t *)(base + OFFSET_FLAGS)) = htole32(header->flags);
    *((uint64_t *)(base + OFFSET_GENERATION)) = htole64(header->generation);
    *((uint64_t *)(base + OFFSET_NUM_RECORDS)) = htole64(header->num_records);
    *((uint64_t *)(base + OFFSET_NUM_COMMITS)) = htole64(header->num_commits);
    *((uint64_t *)(base + OFFSET_DIRTY_SIZE)) = htole64(header->dirty_size);
    *((uint64_t *)(base + OFFSET_REPACK_SIZE)) = htole64(header->repack_size);
    *((uint64_t *)(base + OFFSET_CURRENT_SIZE)) = htole64(header->current_size);
    *((uint32_t *)(base + OFFSET_MAXLEVEL)) = htole32(header->maxlevel);
    *((uint32_t *)(base + OFFSET_CSUM)) = htole32(file->csum(base, OFFSET_CSUM));
}

/* simple wrapper to write with an fsync */
static int commit_header(struct twom_db *db, struct tm_header *header)
{
    struct tm_file *file = db->openfile;
    pack_header(header, file, file->base);
    file->dirty = 1;
    return tm_commit(db, HEADER_SIZE);
}

/******************** RECORD MANAGEMENT *********************/

// Setting the next location at level 0 is special within twom (and
// twoskip before it).  The logic is:
// * if the higher value is past the committed length of the file, update
//   the higher value, because it's been changed within this transaction.
// * otherwise, update the lower value
//
// This means that the highest value that's NOT past the end of the
// committed file is correct, so when we do a recovery or a transaction
// abort, we can zero out the pointer that's past the "end" of the file,
// and the remaining value will always point to the next committed record
// in the valid file.
//
// The recovery operation then checks all the higher-level pointers to make
// sure they still point to the correct next record as it walks the entire
// linked list at level zero, which fixes any other values that were updated
// in the aborted transaction.
#ifdef HAVE_DECLARE_OPTIMIZE
static inline void _setloc0(struct tm_file *file, char *ptr, size_t offset)
    __attribute__((optimize("-O3")));
#endif
static inline void _setloc0(struct tm_file *file, char *ptr, size_t offset)
{
    char *addr = ptr + ptroffset[TYPE(ptr)];

    /* level zero is special */
    size_t val0 = NEXT0(ptr, 0);
    size_t val1 = NEXT0(ptr, 1);

    size_t end = file->committed_size;
    /* already this transaction, update this one */
    if (val0 < end && (val1 >= end || val0 > val1))
        addr += 8; // conditions to write to val1

    *((uint64_t *)(addr)) = htole64(offset);
}

#ifdef HAVE_DECLARE_OPTIMIZE
static inline void _recsum(struct tm_file *file, char *ptr)
    __attribute__((optimize("-O3")));
#endif
static inline void _recsum(struct tm_file *file, char *ptr)
{
    size_t headlen = HEADLEN(ptr);
    uint32_t newcsum = file->csum(ptr, headlen);
    *((uint32_t *)(ptr + headlen)) = htole32(newcsum);
}

/******************** LOCATION MANAGEMENT *********************/

/* locate()
 *
 * db: a database, with a read or write locked file (not necessarily the most recent)
 * loc: a location pointer which points to the locked file; with and "end" which is the MVCC
 *      transaction end for the records we're looking through
 * key, keylen: find either this key or the key immediately before it (may be the DUMMY) if
 *      the database is empty or this key is before any key in the database.
 */
#ifdef HAVE_DECLARE_OPTIMIZE
static int locate(struct twom_txn *txn, struct tm_loc *loc, const char *key, size_t keylen)
    __attribute__((optimize("-O3")));
#endif
static int locate(struct twom_txn *txn, struct tm_loc *loc, const char *key, size_t keylen)
{
    size_t offset = DUMMY_OFFSET;
    uint8_t level = MAXLEVEL-1;
    int cmp = -1; /* never found a thing! */
    struct tm_file *file = loc->file;
    size_t end = loc->end;
    const char *ptr = NULL;

    // reset the location
    loc->offset = 0;
    loc->deleted_offset = 0;

    /* if we don't even have space for the DUMMY record in our mapped file,
     * we can't locate anything */
    const char *locptr = safeptr(loc, DUMMY_OFFSET);
    if (!locptr) return TWOM_IOERROR;

    /* the empty string is always first, so every back pointer will be the dummy,
     * - there's no need to compare records, shortcircuit here */
    if (!keylen) {
        while (level) {
            loc->backloc[level] = DUMMY_OFFSET;
            level--;
        }
        loc->backloc[0] = DUMMY_OFFSET;
        return 0;
    }

    /* at every level except zero, walk the pointers at this level until we either hit a record
     * at or past the one we're looking for. */
    size_t futureoffset = 0; // efficiency hack, remember the offset we just saw in the future
    while (level) {
        size_t next = NEXTN(locptr, level);
        /* optimisation: if the next address is the same on levels N and N-1,
         * we don't need to compar the key again */
        if (next && next != futureoffset && next < end) {
            ptr = safeptr(loc, next);
            if (!ptr) return TWOM_IOERROR;

            cmp = file->compar(KEYPTR(ptr), KEYLEN(ptr),
                               key, keylen);

            /* not there?  stay at this level */
            if (cmp < 0) {
                locptr = ptr;
                offset = next;
                continue;
            }
            /* NOTE: if we match exactly, we still need to make sure all the back
             * pointers at the lower levels are correct, so we still drop down to
             * the next level and repeat the algorithm */
            futureoffset = next;
        }

        loc->backloc[level] = offset;
        level--;
    }

    while (offset) {
        size_t next = advance0(locptr, end);
        if (!next) {
            // hit the end!  No match
            loc->backloc[0] = offset;
            return 0;
        }

        size_t deleted_offset = 0;
        ptr = safeptr(loc, next);
        if (!ptr) return TWOM_IOERROR;
        if (TYPE(ptr) == DELETE) {
            deleted_offset = next;
            next = ANCESTOR(ptr);
            if (!next) return TWOM_IOERROR;
            ptr = safeptr(loc, next);
            if (!ptr) return TWOM_IOERROR;
        }

        cmp = file->compar(KEYPTR(ptr), KEYLEN(ptr),
                           key, keylen);

        // if we match exactly or see into the future, we're there!
        if (cmp > 0) {
            // we're past, no match
            loc->backloc[0] = offset;
            return 0;
        }
        else if (!cmp) {
            // we found it, track the previous offset
            loc->backloc[0] = offset;
            offset = next;
            loc->offset = offset;
            loc->deleted_offset = deleted_offset;
            return check_headcsum(txn, loc->file, ptr, next);
        }
        locptr = ptr;
        offset = next;
    }

    return TWOM_INTERNAL;
}

/* advance_loc()
 * db: a database, with a read or write locked file (not necessarily the most recent)
 * txn: a transaction which points to a locked file, which may or may not be the most
 *      recent (for a read-only transaction in MVCC it could be an older file), and
 *      which has an 'end' value which is the MVCC end for the view we're in
 * loc: a previously 'locate'd location which contains a file (possibly not locked)
 *      and an offset into the mmap on on that file for a record which contains the
 *      key data for that location.
 * Will update loc to txn if needed (with relocate), then move loc to point to the next
 * record (or offset == 0 at EOF)
 * Used by foreach, fetchnext, and internal functions */
#ifdef HAVE_DECLARE_OPTIMIZE
static int advance_loc(struct twom_txn *txn, struct tm_loc *loc)
    __attribute__((optimize("-O3")));
#endif
static int advance_loc(struct twom_txn *txn, struct tm_loc *loc)
{
    // need to read ptr BEFORE we potentially switch the file pointer
    // below
    const char *ptr = loc->offset ? LOCPTR(loc) : LOCBACKPTR(loc, 0);

    // update to the new file if the transaction has refreshed
    if (loc->file != txn->file) {
        loc->file->refcount--;
        loc->file = txn->file;
        loc->file->refcount++;
        loc->end = 0;
    }

    // if file has changed, either new file or extended,
    // then we need to re-calculate our location
    if (loc->end != loc->file->written_size) {
        int was_inexact = !loc->offset;
        const char *key = KEYPTR(ptr);
        size_t keylen = KEYLEN(ptr);
        loc->end = loc->file->written_size;
        int r = locate(txn, loc, key, keylen);
        if (r) return r;
        if (was_inexact) {
            loc->deleted_offset = 0;
            loc->offset = 0;
        }
        ptr = loc->offset ? LOCPTR(loc) : LOCBACKPTR(loc, 0);
        // now we've re-mapped, we might have something to clean up
        tm_cleanup(txn->db);
    }

    /* If we had an offset, advance the backloc to this record, so the location now points
     * immediately after this record as if we had found a key in the gap */
    if (loc->offset) {
        uint8_t n;
        uint8_t level = LEVEL(ptr);
        for (n = 0; n < level; n++)
            loc->backloc[n] = loc->offset;
        loc->deleted_offset = 0;
        loc->offset = 0;
    }

    /* advance0 always get the exactly next record in the series, since it finds the level0
     * pointer after using the skip math to pick the highest value */
    size_t offset = advance0(ptr, loc->end);

    /* reached the end:
     * will have offset == 0, so will break foreach */
    if (!offset) return TWOM_DONE;

    ptr = safeptr(loc, offset);
    if (!ptr) return TWOM_IOERROR;
    if (TYPE(ptr) == DELETE) {
        loc->deleted_offset = offset;
        offset = ANCESTOR(ptr);
        if (!offset) return TWOM_IOERROR;
        ptr = safeptr(loc, offset);
        if (!ptr) return TWOM_IOERROR;
    }

    /* make sure this record is complete */
    loc->offset = offset;
    return check_headcsum(txn, loc->file, ptr, offset);
}

// find_loc is an optimisation on locate.  In the cases where the file hasn't changed and
// either the current key matches exactly, or is in the gap, or is the immediately next
// record, we can avoid the full cost of filling out the location.
//
// This function can also be used to initialise a blank location, since it will detect
// that as a "file has changed" and fill out the right values
static int find_loc(struct twom_txn *txn, struct tm_loc *loc, const char *key, size_t keylen)
{
    // the old location is for an old file or this file has been extended
    if (loc->file != txn->file || loc->end != loc->file->written_size) {
        if (loc->file) loc->file->refcount--;
        loc->file = txn->file;
        loc->file->refcount++;
        loc->end = loc->file->written_size;
        int r = locate(txn, loc, key, keylen);
        if (r) return r;
        // we may have released the last reference, so clean up
        tm_cleanup(txn->db);
        return 0;
    }

    const char *ptr = loc->offset ? LOCPTR(loc) : LOCBACKPTR(loc, 0);
    int cmp = loc->file->compar(KEYPTR(ptr), KEYLEN(ptr), key, keylen);
    if (!cmp && loc->offset) {
        // we haven't moved
        return 0;
    }

    // key is in the future?  let's see if it's next!
    if (cmp < 0) {
        loc->deleted_offset = 0;
        if (loc->offset) {
            uint8_t n;
            uint8_t level = LEVEL(ptr);
            for (n = 0; n < level; n++)
                loc->backloc[n] = loc->offset;
            loc->offset = 0;
        }
        size_t deleted_offset = 0;
        size_t offset = advance0(ptr, loc->end);

        // did we reach the end?
        if (!offset) return 0;

        ptr = safeptr(loc, offset);
        if (!ptr) return TWOM_IOERROR;
        if (TYPE(ptr) == DELETE) {
            deleted_offset = offset;
            offset = ANCESTOR(ptr);
            if (!offset) return TWOM_IOERROR;
            ptr = safeptr(loc, offset);
            if (!ptr) return TWOM_IOERROR;
        }
        cmp = loc->file->compar(KEYPTR(ptr), KEYLEN(ptr), key, keylen);
        // it's in the gap?
        if (cmp > 0) return 0;
        // found it?
        if (cmp == 0) {
            loc->deleted_offset = deleted_offset;
            loc->offset = offset;
            return check_headcsum(txn, loc->file, ptr, offset);
        }
    }

    // not immediately here or next, locate from scratch
    return locate(txn, loc, key, keylen);
}

static int delete_here(struct twom_txn *txn, struct tm_loc *loc)
{
    struct twom_db *db = txn->db;
    struct tm_file *file = loc->file;
    size_t offset = file->written_size;
    struct tm_header *header = &file->header;

    size_t headlen = 16;
    size_t reclen = 24;

    int r = tm_ensure(db, offset + reclen);
    if (r) return r;

    // loca may have refreshed
    char *base = file->base + offset;
    memset(base, 0, reclen);

    char *addr = base;

    *((uint8_t *)(addr)) = DELETE;
    addr += 8;

    // update the level0 back record and re-checksum
    char *backptr = LOCBACKPTR(loc, 0);
    SET0(file, backptr, offset);
    _recsum(file, backptr);

    // set ancestor to current record
    *((uint64_t *)(addr)) = htole64(loc->offset);
    addr += 8;

    // calculate checksum of current record
    *((uint32_t *)(addr)) = htole32(file->csum(base, headlen));

    /* update header to know details of new record */
    header->dirty_size += reclen;

    // track that we've added the record
    loc->deleted_offset = offset;
    file->written_size += reclen;
    txn->end = file->written_size;
    loc->end = file->written_size;

    // file definitely needs to be flushed now
    file->dirty = 1;

    return 0;
}

/* overall "store" function - update the value in the current loc.
   All updates funnel through here.  NULL val means
   deletion.   Force is implied here, it gets checked higher.
   Can be used to replace, add or delete a record */
static int store_here(struct twom_txn *txn, const char *key, size_t keylen, const char *val, size_t vallen)
{
    if (vallen) assert(val);

    struct twom_db *db = txn->db;
    struct tm_loc *loc = &db->loc;
    size_t end = loc->end;
    struct tm_file *file = loc->file;
    assert(file == txn->file);
    assert(file == db->openfile);
    assert(file->written_size == end);
    struct tm_header *header = &file->header;
    size_t keyoffset = 0;
    size_t valoffset = 0;
    uint64_t ancestor = 0;
    int r;
    int type = ADD;

    size_t offset = end;

    // it's a pointer into our map!  we'll magically re-map it
    if (key > file->base && key < file->base + offset)
        keyoffset = key - file->base;
    if (val > file->base && val < file->base + offset)
        valoffset = val - file->base;

    /* dirty the header if not already dirty */
    if (!(header->flags & DIRTY)) {
        assert(offset == header->current_size);
        header->flags |= DIRTY;
        r = commit_header(db, header);
        if (r) return r;
    }

    uint8_t level;
    if (loc->offset) {
        const char *locptr = LOCPTR(loc);
        // if was a delete we'll point back to that
        if (loc->deleted_offset) {
            assert(val); // can't replace a delete with another delete!
            ancestor = loc->deleted_offset;
        }
        // if it's not already a delete, we replace it
        else {
            ancestor = loc->offset;
            header->num_records--;
            header->dirty_size += RECLEN(locptr);
        }
        // new type
        type = val ? REPLACE : DELETE;
        level = LEVEL(locptr);
    }
    else {
        assert(val); // can't start with a delete
        level = randlvl(1, MAXLEVEL);
    }

    if (type == DELETE) return delete_here(txn, loc);

    size_t headlen = HLCALC(type, level);
    size_t taillen = TLCALC(type, keylen, vallen);
    size_t reclen = headlen + 8 + taillen;

    r = tm_ensure(db, offset + reclen);
    if (r) return r;

    // the file may have been re-mapped, so grab the locptr AFTER ensuring space
    char *base = file->base + offset;
    memset(base, 0, reclen);
    char *addr = base;

    // the first 1-3 blocks are metadata.  Fat records have extra for the key
    // and value lengths
    *((uint8_t *)(addr)) = type;
    *((uint8_t *)(addr+1)) = level;
    if (fatrecord[type]) {
        *((uint64_t *)(addr+8)) = htole64(keylen);
        *((uint64_t *)(addr+16)) = htole64(vallen);
        addr += 24;
    }
    else {
        *((uint16_t *)(addr+2)) = htole16(keylen);
        *((uint32_t *)(addr+4)) = htole32(vallen);
        addr += 8;
    }

    // replacement records have an ancestor for MVCC chaining
    if (ancestoroffset[type]) {
        *((uint64_t *)(addr)) = htole64(ancestor);
        addr += 8;
    }

    // the first alternate level0 pointer is always zero - we've already
    // wiped the space, so just skip it.
    addr += 8;

    if (loc->offset) {
        // store all the backwards and forwards locations
        const char *locptr = LOCPTR(loc);

        // we need to update the backpointers to this new location,
        // and the forward pointers to the old pointer's next location
        char *backptr = LOCBACKPTR(loc, 0);
        char *prevptr = backptr;
        *((uint64_t *)(addr)) = htole64(advance0(locptr, end));
        addr += 8;
        SET0(file, backptr, offset);

        uint8_t n;
        for (n = 1; n < level; n++) {
            backptr = LOCBACKPTR(loc, n);
            if (backptr != prevptr) _recsum(file, prevptr);
            prevptr = backptr;
            *((uint64_t *)(addr)) = htole64(NEXTN(locptr, n));
            addr += 8;
            SETN(backptr, n, offset);
        }

        // update the last old checksum
        _recsum(file, prevptr);
    }
    else {
        // we need to update the backpointers to this new location,
        // and the forward pointers to the old pointer's next location
        char *backptr = LOCBACKPTR(loc, 0);
        char *prevptr = backptr;
        *((uint64_t *)(addr)) = htole64(advance0(backptr, end));
        addr += 8;
        SET0(file, backptr, offset);

        uint8_t n;
        for (n = 1; n < level; n++) {
            backptr = LOCBACKPTR(loc, n);
            if (backptr != prevptr) _recsum(file, prevptr);
            prevptr = backptr;
            *((uint64_t *)(addr)) = htole64(NEXTN(backptr, n));
            addr += 8;
            SETN(backptr, n, offset);
        }

        // update the last old checksum
        _recsum(file, prevptr);
    }

    // head checksum
    *((uint32_t *)(addr)) = htole32(file->csum(base, headlen));

    // if we have a KEY then we add a tail (key, maybe value, plus padding),
    // otherwise we've already zeroed out the tailcsum field.
    if (taillen) {
        if (keyoffset) key = file->base + keyoffset;
        memcpy(addr + 8, key, keylen);
        addr[8+keylen] = 0;
        if (hastail[type]) {
            if (valoffset) val = file->base + valoffset;
            memcpy(addr + 8 + keylen + 1, val, vallen);
            addr[8+keylen+1+vallen] = 0;
        }
        *((uint32_t *)(addr+4)) = htole32(file->csum(addr+8, taillen));
    }

    /* update header to know details of new record */
    header->num_records++;

    /* track the highest level in this DB */
    if (level > header->maxlevel)
        header->maxlevel = level;

    // track that we've added the record
    loc->offset = offset;
    loc->deleted_offset = 0;
    file->written_size += reclen;
    txn->end = file->written_size;
    loc->end = file->written_size;

    // file definitely needs to be flushed now
    file->dirty = 1;

    return 0;
}

/************ DATABASE RECOVERY **************/

static int db_is_clean(struct twom_db *db, struct tm_file *file)
{
    if (!file) file = db->openfile;
    if (file->header.flags & DIRTY)
        return 0;

    return 1;
}

/* run recovery on this file.
 * always called with a write lock.  This goes through and zeros out any
 * level0 pointers past the end, plus re-stitches any higher level pointers
 * to their matching next location */
static int recovery1(struct twom_db *db, struct tm_loc *loc, int *count)
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
    if (db_is_clean(db, db->openfile))
        return 0;

    assert(db->openfile->has_datalock == 2);
    assert(loc->file == db->openfile);
    struct tm_file *file = loc->file;

    const char *ptr = safeptr(loc, DUMMY_OFFSET);
    if (!ptr) {
        db->error("failed to read DUMMY for recovery",
                  "fname=<%s>", db->fname);
        return TWOM_IOERROR;
    }

    /* and pointers forwards */
    prev[0] = DUMMY_OFFSET;
    next[0] = 0;
    for (i = 0; i < 2; i++) {
        size_t cur = NEXT0(ptr, i);
        /* check for broken level - pointers, and extract the best next pointer */
        if (cur >= loc->end) {
            // zero out bogus pointer
            *((uint64_t *)(NEXT0PTR(ptr, i))) = 0;
            _recsum(file, (char *)ptr);
            changed++;
        }
        else if (cur > next[0]) {
            next[0] = cur;
        }
    }

    for (i = 1; i < MAXLEVEL; i++) {
        prev[i] = DUMMY_OFFSET;
        next[i] = NEXTN(ptr, i);
    }

    while (next[0]) {
        size_t deleted_offset = 0;
        const char *nextptr = safeptr(loc, next[0]);
        if (!nextptr) {
            db->error("failed to read next record for recovery",
                      "fname=<%s> prev_key=<%.*s> offset=<%08llX>",
                      db->fname, (int)KEYLEN(ptr), KEYPTR(ptr),
                      (LLU)next[0]);
            return TWOM_IOERROR;
        }
        if (TYPE(nextptr) == DELETE) {
            deleted_offset = next[0];
            dirty_size += 24;
            next[0] = ANCESTOR(nextptr);
            if (!next[0]) return TWOM_IOERROR;
            nextptr = safeptr(loc, next[0]);
            if (!nextptr) return TWOM_IOERROR;
        }

        cmp = file->compar(KEYPTR(nextptr), KEYLEN(nextptr),
                           KEYPTR(ptr), KEYLEN(ptr));
        if (cmp <= 0) {
            db->error("out of order for recovery",
                      "fname=<%s> prev_key=<%.*s> key=<%.*s> offset=<%08llX>",
                      db->fname,
                      (int)KEYLEN(ptr), KEYPTR(ptr),
                      (int)KEYLEN(nextptr), KEYPTR(nextptr),
                      (LLU)next[0]);
            return TWOM_INTERNAL;
        }

        size_t ancestor = ANCESTOR(nextptr);
        while (ancestor) {
            const char *aptr = safeptr(loc, ancestor);
            if (!aptr) {
                db->error("failed to read next record for recovery",
                          "fname=<%s> key=<%.*s> offset=<%08llX>",
                          db->fname, (int)KEYLEN(nextptr), KEYPTR(nextptr),
                          (LLU)ancestor);
                return TWOM_IOERROR;
            }
            if (TYPE(aptr) == DELETE) {
                dirty_size += 24;
                ancestor = ANCESTOR(aptr);
                if (!ancestor) return TWOM_IOERROR;
                aptr = safeptr(loc, ancestor);
                if (!aptr) return TWOM_IOERROR;
            }
            cmp = file->compar(KEYPTR(aptr), KEYLEN(aptr),
                               KEYPTR(nextptr), KEYLEN(nextptr));
            if (cmp) {
                db->error("twom mismatched ancestor for recovery",
                        "fname=<%s> key=<%.*s> offset=<%08llX>"
                        " parent_key=<%.*s> parent_offset=<%08llX)",
                        db->fname, (int)KEYLEN(nextptr), KEYPTR(nextptr), (LLU)next[0],
                        (int)KEYLEN(aptr), KEYPTR(aptr), (LLU)ancestor);
                return TWOM_IOERROR;
            }
            dirty_size += RECLEN(aptr);
            ancestor = ANCESTOR(aptr);
        }

        /* check for old offsets needing fixing */
        uint8_t level = LEVEL(nextptr);

        for (i = 1; i < level; i++) {
            if (next[i] != next[0]) {
                char *rec = file->base + prev[i];
                *((uint64_t *)(NEXTNPTR(rec, i))) = htole64(next[0]);
                _recsum(file, rec);
                changed++;
            }
            prev[i] = next[0];
            next[i] = NEXTN(nextptr, i);
        }

        prev[0] = next[0];
        next[0] = 0;
        for (i = 0; i < 2; i++) {
            size_t cur = NEXT0(nextptr, i);
            /* check for broken level - pointers, and extract the best next pointer */
            if (cur >= loc->end) {
                // zero out bogus pointer
                *((uint64_t *)(NEXT0PTR(nextptr, i))) = 0;
                _recsum(file, (char *)nextptr);
                changed++;
            }
            else if (cur > next[0]) {
                next[0] = cur;
            }
        }

        if (deleted_offset) dirty_size += RECLEN(nextptr);
        else num_records++;

        ptr = nextptr;
    }

    /* check for remaining offsets needing zeroing */
    for (i = 1; i < MAXLEVEL; i++) {
        if (next[i]) {
            char *rec = file->base + prev[i];
            *((uint64_t *)(NEXTNPTR(rec, i))) = htole64(next[0]);
            _recsum(file, rec);
            changed++;
        }
    }

    /* commit first so all other bits are committed before we undirty the header */
    r = tm_commit(db, loc->end);
    if (r) return r;

    /* clear the dirty flag */
    struct tm_header *header = &file->header;
    header->flags &= ~DIRTY;
    header->num_records = num_records;
    header->dirty_size = dirty_size;
    r = commit_header(db, header);
    if (r) return r;

    if (count) *count = changed;

    return 0;
}

// NOTE: it would be possible to add a 'recovery2' option which replayed the entire
// database like a transaction log (like the repack does after finishing the MVCC read).
// this would allow recovery from having lost an external COMPAR function and also from
// having lost an external CSUM function if you blindly trust and hope that the file
// isn't otherwise corrupted!
static int recovery(struct twom_db *db, struct tm_file *file)
{
    int count = 0;
    int r;

    /* no need to run recovery if we're consistent */
    if (db_is_clean(db, file))
        return 0;

    // recovery is run before allocating transactions, but we need a 'loc' for
    // all the safeptr logic, so create a synthetic one with the correct
    // offsets.
    struct tm_loc *loc = (struct tm_loc *)twom_zmalloc(sizeof(struct tm_loc));
    loc->file = file;
    loc->end = loc->file->header.current_size;
    loc->file->refcount++;

    r = recovery1(db, loc, &count);
    if (r) {
        db->error("recovery1 failed",
                  "filename=<%s>",
                  db->fname);
    }

    loc->file->refcount--;
    free(loc);

    return r;
}

/*********************** FILE LOCKING ********************/

static struct twom_txn *_newtxn_write(struct twom_db *db)
{
    assert(!db->write_txn);
    assert(db->openfile);
    assert(db->openfile->has_datalock == 2);

    /* create the transaction */
    struct twom_txn *txn = (struct twom_txn *)twom_zmalloc(sizeof(struct twom_txn));
    txn->db = db;
    txn->file = db->openfile;
    txn->file->refcount++;
    assert(txn->file->committed_size == txn->file->written_size);
    txn->end = txn->file->committed_size;
    db->write_txn = txn;

    return txn;
}

static struct twom_txn *_newtxn_read(struct twom_db *db)
{
    // it's OK to have a write transaction as well, we'll just use the same file
    assert(db->openfile);
    assert(db->openfile->has_datalock);

    /* create the transaction */
    struct twom_txn *txn = (struct twom_txn *)twom_zmalloc(sizeof(struct twom_txn));
    txn->db = db;
    txn->file = db->openfile;
    txn->file->refcount++;
    assert(txn->file->committed_size == txn->file->written_size);
    txn->end = txn->file->committed_size;
    txn->readonly = 1;
    txn->next = db->read_txn;
    db->read_txn = txn;

    return txn;
}

static int unlock(struct twom_db *db, struct tm_file *file)
{
    if (!file) file = db->openfile;
    if (!file->has_headlock && !file->has_datalock) return 0;
    if (file == db->openfile) assert(!db->write_txn);

    struct flock fl;
    fl.l_type= F_UNLCK;
    fl.l_whence = SEEK_SET;

    fl.l_start = 0;
    fl.l_len = HEADER_MAGIC_SIZE;
    for (;file->has_headlock;) {
        if (fcntl(file->fd, F_SETLKW, &fl) < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        file->has_headlock = 0;
    }

    fl.l_start = DUMMY_OFFSET;
    fl.l_len = DUMMY_SIZE;
    for (;file->has_datalock;) {
        if (fcntl(file->fd, F_SETLKW, &fl) < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        file->has_datalock = 0;
    }

    return 0;
}

static int write_lock(struct twom_db *db, struct twom_txn **txnp,
                      struct tm_file *forcefile, int flags)
{
    if (db->readonly) return TWOM_LOCKED;
    if (txnp) assert(!*txnp);

    struct stat sbuf, sbuffile;
    struct flock fl;
    int r = 0;
    int cmd = (flags & TWOM_NONBLOCKING) ? F_SETLK : F_SETLKW;
    struct tm_file *file = forcefile ? forcefile : db->openfile;

    if (file->has_headlock || file->has_datalock) return TWOM_INTERNAL;

    for (;;) {
        // lock the head section
        for (;!file->has_headlock;) {
            fl.l_type = F_WRLCK;
            fl.l_whence = SEEK_SET;
            fl.l_start = 0;
            fl.l_len = HEADER_MAGIC_SIZE;
            if (fcntl(file->fd, cmd, &fl) < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN && cmd == F_SETLK)
                    return TWOM_LOCKED;
                db->error("write_lock headlock fcntl failed",
                        "filename=<%s>", db->fname);
                return TWOM_IOERROR;
            }
            file->has_headlock = 2;
        }

        // lock the data section
        for (;!file->has_datalock;) {
            fl.l_type = F_WRLCK;
            fl.l_whence = SEEK_SET;
            fl.l_start = DUMMY_OFFSET;
            fl.l_len = DUMMY_SIZE;
            if (fcntl(file->fd, cmd, &fl) < 0) {
                if (errno == EAGAIN && cmd == F_SETLK) {
                    r = TWOM_LOCKED;
                    goto done;
                }
                if (errno == EINTR) continue;
                db->error("write_lock datalock fcntl failed",
                        "filename=<%s>", db->fname);
                r = TWOM_IOERROR;
                goto done;
            }
            file->has_datalock = 2;
        }

        // release the head section (so readers don't starve)
        for (;file->has_headlock;) {
            fl.l_type= F_UNLCK;
            fl.l_start = 0;
            fl.l_whence = SEEK_SET;
            fl.l_len = HEADER_MAGIC_SIZE;
            if (fcntl(file->fd, F_SETLKW, &fl) < 0) {
                if (errno == EINTR) continue;
                db->error("write_lock headunlock fcntl failed",
                        "filename=<%s>", db->fname);
                r = TWOM_IOERROR;
                goto done;
            }
            file->has_headlock = 0;
        }

        if (fstat(file->fd, &sbuf) == -1) {
            db->error("write_lock fstat failed",
                      "filename=<%s>", db->fname);
            r = TWOM_IOERROR;
            goto done;
        }

        if (forcefile) break;

        if (stat(db->fname, &sbuffile) == -1) {
            db->error("write_lock stat failed",
                      "filename=<%s>", db->fname);
            r = TWOM_IOERROR;
            goto done;
        }

        if (sbuf.st_ino == sbuffile.st_ino) break;

        r = unlock(db, file);
        if (r) goto done;

        int newfd = open(db->fname, O_RDWR, 0644);
        if (newfd == -1) {
            db->error("write_lock open failed",
                      "filename=<%s>", db->fname);
            r = TWOM_IOERROR;
            goto done;
        }

        // new file, create a new mapping
        file = (struct tm_file *)twom_zmalloc(sizeof(struct tm_file));
        file->fd = newfd;
        file->next = db->openfile;
        db->openfile = file;
    }

    // if we haven't mapped enough space, do it now
    if (file->size < (size_t)sbuf.st_size) {
        if (file->size) munmap(file->base, file->size);
        file->size = sbuf.st_size;
        file->base = (char *)mmap((caddr_t)0, file->size, PROT_READ|PROT_WRITE, MAP_SHARED, file->fd, 0L);
        if (!file->base) {
            db->error("write_lock mmap failed",
                      "filename=<%s> size=<%08llX>", db->fname, (LLU)file->size);
            r = TWOM_IOERROR;
            goto done;
        }
    }

    /* reread header */
    r = read_header(db, file, &file->header);
    if (r) goto done;

    file->committed_size = file->header.current_size;
    file->written_size = file->committed_size;

    if (!db_is_clean(db, file)) {
        r = recovery(db, file);
        if (r) goto done;
    }

    if (txnp) {
        *txnp = _newtxn_write(db);
        return 0;
    }

 done:
    unlock(db, file);
    return r;
}

static int read_lock(struct twom_db *db, struct twom_txn **txnp,
                     struct tm_file *forcefile, int flags)
{
    struct stat sbuf, sbuffile;
    int r = 0;
    struct flock fl;
    struct tm_file *file = forcefile ? forcefile : db->openfile;
    int cmd = (flags & TWOM_NONBLOCKING) ? F_SETLK : F_SETLKW;

    if (file->has_headlock || file->has_datalock) return TWOM_INTERNAL;

    for (;;) {
        // take the headlock
        for (;!file->has_headlock;) {
            fl.l_type = F_RDLCK;
            fl.l_whence = SEEK_SET;
            fl.l_start = 0;
            fl.l_len = HEADER_MAGIC_SIZE;
            if (fcntl(file->fd, cmd, &fl) < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN && cmd == F_SETLK)
                    return TWOM_LOCKED;
                db->error("read_lock fcntl failed",
                        "filename=<%s>", db->fname);
                return TWOM_IOERROR;
            }
            file->has_headlock = 1;
        }

        // lock the data section
        for (;!file->has_datalock;) {
            fl.l_type = F_RDLCK;
            fl.l_whence = SEEK_SET;
            fl.l_start = DUMMY_OFFSET;
            fl.l_len = DUMMY_SIZE;
            if (fcntl(file->fd, cmd, &fl) < 0) {
                if (errno == EAGAIN && cmd == F_SETLK) {
                    r = TWOM_LOCKED;
                    goto done;
                }
                if (errno == EINTR) continue;
                db->error("read_lock datalock fcntl failed",
                        "filename=<%s>", db->fname);
                r = TWOM_IOERROR;
                goto done;
            }
            file->has_datalock = 1;
        }

        // release the head section (so writers don't starve)
        for (;file->has_headlock;) {
            fl.l_type= F_UNLCK;
            fl.l_whence = SEEK_SET;
            fl.l_start = 0;
            fl.l_len = HEADER_MAGIC_SIZE;
            if (fcntl(file->fd, F_SETLKW, &fl) < 0) {
                if (errno == EINTR) continue;
                db->error("read_lock headunlock fcntl failed",
                        "filename=<%s>", db->fname);
                r = TWOM_IOERROR;
                goto done;
            }
            file->has_headlock = 0;
        }

        if (fstat(file->fd, &sbuf) == -1) {
            db->error("read_lock fstat failed",
                      "filename=<%s>", db->fname);
            r = TWOM_IOERROR;
            goto done;
        }

        if (sbuf.st_size < HEADER_SIZE + DUMMY_SIZE) {
            r = TWOM_BADFORMAT;
            goto done;
        }

        // we're not interested in getting the latest file
        if (forcefile) break;

        if (stat(db->fname, &sbuffile) == -1) {
            db->error("read_lock stat failed",
                      "filename=<%s>", db->fname);
            r = TWOM_IOERROR;
            goto done;
        }

        // file is unchanged, we have successfully locked
        if (sbuf.st_ino == sbuffile.st_ino) break;

        // unlock the old file
        r = unlock(db, file);
        if (r) goto done;

        int newfd = open(db->fname, db->readonly ? O_RDONLY : O_RDWR, 0644);
        if (newfd == -1) {
            db->error("read_lock open failed",
                      "filename=<%s>", db->fname);
            return TWOM_IOERROR;
        }

        // new file
        file = (struct tm_file *)twom_zmalloc(sizeof(struct tm_file));
        file->fd = newfd;
        file->next = db->openfile;
        db->openfile = file;
    }

    // if the existing map it too small, replace it
    if (file->size < (size_t)sbuf.st_size) {
        /* map the new space (note: we map READ|WRITE even for readonly locks,
         * if we might lock for write later and want to reuse the mmap */
        if (file->size) munmap(file->base, file->size);
        int flags = db->readonly ? PROT_READ : PROT_READ|PROT_WRITE;
        file->size = sbuf.st_size;
        file->base = (char *)mmap((caddr_t)0, file->size, flags, MAP_SHARED, file->fd, 0L);
        if (!file->base) {
            db->error("read_lock mmap failed",
                      "filename=<%s> size=<%08llX>", db->fname, (LLU)file->size);
            r = TWOM_IOERROR;
            goto done;
        }
    }

    // reread header
    r = read_header(db, file, &file->header);
    if (r) goto done;

    file->committed_size = file->header.current_size;
    file->written_size = file->committed_size;

    if (txnp) {
        if (!*txnp) *txnp = _newtxn_read(db);
        else if (!(*txnp)->mvcc) {
            // if we're not on this file, change file
            if ((*txnp)->file != file) {
                (*txnp)->file->refcount--;
                (*txnp)->file = file;
                (*txnp)->file->refcount++;
            }
            (*txnp)->end = file->written_size;
        }

        return 0;
    }

 done:
    unlock(db, file);
    return r;
}

/***********************  OPEN AND CLOSE *************************************/

static void errors_to_stderr(const char *msg, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void errors_to_stderr(const char *msg, const char *fmt, ...)
{
    va_list args;

    fprintf(stderr, "DBERROR: %s ", msg);
    if (fmt) {
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }
    if (errno)
        fprintf(stderr, " errno=<%s>", strerror(errno));
    fprintf(stderr, "%s", "\n");
}

static void dispose_db(struct twom_db *db)
{
    if (!db) return;
    empty_db(db);
    free(db->fname);
    free(db);
}

static int initdb(struct twom_db *db, int flags)
{
    char scratch[512]; // this is big enough, header plus dummy fits in 512
    struct tm_header header;
    size_t filesize = HEADER_SIZE + DUMMY_SIZE;
    struct tm_file *file = db->openfile;

    // zero out our workspace
    memset(scratch, 0, 512);

    // prepare the header
    uuid_generate(header.uuid);
    header.version = TWOM_VERSION;
    // XXX: other persistent flags?
    header.flags = set_csum_engine(db, file, flags);
    header.generation = 1;
    header.num_records = 0;
    header.num_commits = 0;
    header.dirty_size = 0;
    header.repack_size = filesize;
    header.current_size = filesize;
    header.maxlevel = 0;
    pack_header(&header, file, scratch);

    // write a blank dummy record
    size_t headlen = HLCALC(DUMMY, MAXLEVEL);
    char *base = scratch + DUMMY_OFFSET;
    *((uint8_t *)(base)) = DUMMY;
    *((uint8_t *)(base+1)) = MAXLEVEL;
    *((uint32_t *)(base+headlen)) = htole32(file->csum(base, headlen));

    // ensure that the data is written to the file!
    size_t written;
    for (written = 0; written < filesize; ) {
        ssize_t n = write(file->fd, scratch + written, filesize - written);
        if (n == -1) {
            if (errno == EINTR) continue;
            db->error("db creation failed",
                      "filename=<%s>", db->fname);
            return TWOM_IOERROR;
        }
        written += n;
    }

    return 0;
}

static int opendb(const char *fname, struct twom_open_data *setup, struct twom_db **ret, struct twom_txn **txnp)
{
    assert(setup);
    int r = TWOM_IOERROR;

    assert(fname);
    assert(ret);

    struct twom_db *db = (struct twom_db *)twom_zmalloc(sizeof(struct twom_db));
    db->readonly = (setup->flags & TWOM_SHARED) ? 1 : 0;
    db->nocsum = (setup->flags & TWOM_NOCSUM) ? 1 : 0;
    db->nosync = (setup->flags & TWOM_NOSYNC) ? 1 : 0;
    db->noyield = (setup->flags & TWOM_NOYIELD) ? 1 : 0;
    db->fname = strdup(fname);
    db->foreach_lock_release = FOREACH_LOCK_RELEASE;
    db->error = setup->error ? setup->error : errors_to_stderr;
    db->external_csum = setup->csum;
    db->external_compar = setup->compar;

    db->openfile = (struct tm_file *)twom_zmalloc(sizeof(struct tm_file));

    int fd = open(db->fname, db->readonly ? O_RDONLY : O_RDWR, 0644);
    db->openfile->fd = fd;
    if (fd < 0) {
        if (setup->flags & TWOM_CREATE) {
            fd = open(db->fname, O_RDWR|O_CREAT, 0644);
            db->openfile->fd = fd;
            if (fd < 0) {
                if (errno == ENOENT) r = TWOM_NOTFOUND;
                goto done;
            }
            r = initdb(db, setup->flags);
            if (r) goto done;
        }
        else {
            if (errno == ENOENT) r = TWOM_NOTFOUND;
            goto done;
        }
    }

    if (db->readonly || !txnp) {
        /* grab a read lock to read the header */
        r = read_lock(db, txnp, NULL, setup->flags);
        if (r) goto done;
    }
    else {
        /* go straight for a write lock and hold it */
        r = write_lock(db, txnp, NULL, setup->flags);
        if (r) goto done;
    }

    *ret = db;

 done:
    if (r) dispose_db(db);
    return r;
}

static int abort_locked(struct twom_txn **txnp)
{
    if (!*txnp) return 0;
    struct twom_txn *txn = *txnp;
    struct twom_db *db = txn->db;
    if (txn != db->write_txn) {
        struct twom_txn **ptr;
        for (ptr = &db->read_txn; *ptr; ptr = &(*ptr)->next)
            if (*ptr == txn) break;
        assert(*ptr);
        _remove_txn(ptr);
        tm_cleanup(db);
        return 0;
    }

    // we use recovery to abort - it will undo any pointers past the end.
    //
    // NOTE: we don't (currently) truncate the file afterwards, so there
    // could be junk at the end of the file until new transactions overwrite
    // it or it gets repacked.
    int r = recovery(db, txn->file);
    txn->file->refcount--;
    free(txn);
    *txnp = NULL;
    db->write_txn = NULL;
    tm_cleanup(db);

    return r;
}

static int commit_locked(struct twom_txn **txnp)
{
    if (!*txnp) return 0;
    struct twom_txn *txn = *txnp;
    struct twom_db *db = txn->db;
    if (txn != db->write_txn) {
        struct twom_txn **ptr;
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

    struct tm_file *file = txn->file;
    struct tm_header *header = &file->header;

    /* no need to commit if we're not dirty */
    if (!(header->flags & DIRTY))
        goto done;

    /* if we're committing we have a location */
    struct tm_loc *loc = &db->loc;
    assert(file == txn->file);
    assert(file->has_datalock == 2);

    size_t headlen = 16;
    size_t reclen = 24;

    // could re-map, but it WON'T change the header
    r = tm_ensure(db, file->written_size + reclen);
    if (r) goto done;

    char *base = file->base + file->written_size;
    memset(base, 0, reclen); // zero out the whole thing before we set just the bits we want

    *((uint8_t *)(base)) = COMMIT;
    *((uint64_t *)(base+8)) = htole64(header->current_size);
    *((uint32_t *)(base+16)) = htole32(file->csum(base, headlen));

    file->written_size += reclen;
    txn->end = file->written_size;
    loc->end = file->written_size;
    file->dirty = 1;

    /* commit ALL outstanding changes first, before
     * rewriting the header */
    r = tm_commit(db, file->written_size);
    if (r) goto done;

    /* finally, update the header and commit again */
    header->num_commits++;
    header->current_size = file->written_size;
    header->flags &= ~DIRTY;
    r = commit_header(db, header);
    if (r) goto done;

    file->committed_size = file->written_size;

 done:
    if (r) {
        /* error during commit; we must abort */
        int r2 = abort_locked(txnp);
        if (r2) {
            db->error("commit AND abort failed",
                      "filename=<%s>", db->fname);
        }
        return r;
    }

    txn->file->refcount--;
    free(txn);
    *txnp = NULL;
    db->write_txn = NULL;
    tm_cleanup(db);

    return 0;
}

/**************** NOT YET SORTED *******************/

// play the rest of the records in a file from any point (used by repack
// and could also be used by a recovery2 or similar to fix a file where
// an external compar function had been lost)
static int myreplay(struct twom_txn *txn,
                    twom_cb *cb, void *rock)
{
    int r;

    struct twom_db *db = txn->db;
    struct tm_file *file = txn->file;

    while (txn->end + 24 <= file->committed_size) {
        const char *ptr = file->base + txn->end;
        size_t reclen = RECLEN(ptr);
        // ensure the entire record fits!
        if (txn->end + reclen > file->committed_size)
            return TWOM_IOERROR;

        // skip over commits, but replay all ADD, REPLACE or DELETE
        if (TYPE(ptr) == COMMIT) {
            // skip over
        }
        else if (TYPE(ptr) == DELETE) {
            const char *aptr = file->base + ANCESTOR(ptr);
            r = cb(rock, KEYPTR(aptr), KEYLEN(aptr), NULL, 0);
            if (r) return r;
        }
        else {
            r = cb(rock, KEYPTR(ptr), KEYLEN(ptr), VALPTR(ptr), VALLEN(ptr));
            if (r) return r;
        }
        // advance to the next record
        txn->end += reclen;

        // release every so often
        txn->counter++;
        if (txn->counter > db->foreach_lock_release) {
            r = unlock(db, file);
            if (r) return r;
            r = read_lock(db, &txn, file, /*flags*/0);
            if (r) return r;
            txn->counter = 0;
        }
    }

    return 0;
}

/* helper function for all writes - wraps create and delete and the FORCE
 * logic for each */
static int skipwrite(struct twom_txn *txn,
                     const char *key, size_t keylen,
                     const char *data, size_t datalen,
                     int flags)
{
    struct tm_loc *loc = &txn->db->loc;

    int r = find_loc(txn, loc, key, keylen);
    if (r) return r;

    const char *ptr = LOCPTR(loc);
    /* could be a delete or a replace */
    if (loc->offset && !loc->deleted_offset) {
        // replacing existing record
        if (flags & TWOM_IFNOTEXIST) return TWOM_EXISTS;
        if (!data) return store_here(txn, key, keylen, NULL, 0);
        /* unchanged?  Save the IO */
        if (!loc->file->compar(data, datalen, VALPTR(ptr), VALLEN(ptr)))
            return 0;
        return store_here(txn, key, keylen, data, datalen);
    }

    if (flags & TWOM_IFEXIST) return TWOM_NOTFOUND;

    /* delete of already deleted is a NOOP */
    if (data) return store_here(txn, key, keylen, data, datalen);

    return 0;
}

/* compress 'db', closing at the end.  Uses foreach to copy into a new
 * database, then rewrites over the old one */
static int copy_cb(void *rock,
                   const char *key, size_t keylen,
                   const char *data, size_t datalen)
{
    struct twom_txn *txn = (struct twom_txn *)rock;
    int i;

    /* minimal logic from find_loc and advance_loc knowing that we're
     * always writing in order at the end of a file */
    struct tm_loc *loc = &txn->db->loc;
    if (loc->offset) {
        const char *ptr = LOCPTR(loc);
        uint8_t level = LEVEL(ptr);
        for (i = 0; i < level; i++)
            loc->backloc[i] = loc->offset;
        loc->offset = 0;
    }
    return store_here(txn, key, keylen, data, datalen);
}

static int replay_cb(void *rock,
                     const char *key, size_t keylen,
                     const char *data, size_t datalen)
{
    struct twom_txn *txn = (struct twom_txn *)rock;
    return skipwrite(txn, key, keylen, data, datalen, 0);
}

static int tm_rename(struct twom_db *db, struct tm_file *oldfile, const char *newname)
{
    struct stat sbuf, sbuffile;
    char *copy = strdup(db->fname);
    const char *dir = dirname(copy);
    int r = 0;
    int dirfd = -1;

    if (!db->nosync) {
    #if defined(O_DIRECTORY)
        dirfd = open(dir, O_RDONLY|O_DIRECTORY, 0600);
#else
        dirfd = open(dir, O_RDONLY, 0600);
#endif
        if (dirfd < 0) {
            db->error("open directory failed",
                      "filename=<%s> newname=<%s> directory=<%s>",
                      db->fname, newname, dir);
            r = TWOM_IOERROR;
            goto done;
        }
    }

    if (fstat(oldfile->fd, &sbuf) == -1) {
        db->error("tm_rename fstat failed",
                  "filename=<%s>", db->fname);
        r = TWOM_IOERROR;
        goto done;
    }

    if (stat(db->fname, &sbuffile) == -1) {
        db->error("tm_rename stat failed",
                  "filename=<%s>", db->fname);
        r = TWOM_IOERROR;
        goto done;
    }

    if (sbuf.st_ino != sbuffile.st_ino) {
        db->error("tm_rename file has changed under us",
                  "filename=<%s>", db->fname);
        r = TWOM_IOERROR;
        goto done;
    }

    r = rename(newname, db->fname);
    if (r) goto done;

    if (!db->nosync) {
        if (fsync(dirfd) < 0) {
            db->error("fsync directory failed",
                      "filename=<%s> newname=<%s> directory=<%s>",
                      db->fname, newname, dir);
            // but we can't abort now, we've already renamed, so we need to
            // carry on and update our object
        }
    }

 done:
    if (dirfd >= 0) close(dirfd);
    free(copy);
    return r;
}

/* perform some basic consistency checks - key order, ancestor key match,
 * links in order at every level */
static int consistent1(struct twom_txn *txn, struct tm_loc *loc)
{
    size_t next[MAXLEVEL];
    size_t num_records = 0;
    size_t dirty_size = 0;
    const char *ptr;
    int cmp;
    int i;

    assert(txn->file->size >= txn->end);

    struct tm_file *file = txn->file;
    struct twom_db *db = txn->db;

    /* set up the location pointers */
    ptr = safeptr(loc, DUMMY_OFFSET);
    if (!ptr) {
        txn->db->error("failed to read DUMMY for consistent",
                  "fname=<%s>", db->fname);
        return TWOM_IOERROR;
    }
    next[0] = advance0(ptr, loc->end);
    for (i = 1; i < MAXLEVEL; i++)
        next[i] = NEXTN(ptr, i);

    while (next[0]) {
        const char *nextptr = safeptr(loc, next[0]);
        size_t deleted_offset = 0;
        if (!nextptr) {
            db->error("failed to read next record for consistent",
                      "fname=<%s> prev_key=<%.*s> offset=<%08llX>",
                    db->fname, (int)KEYLEN(ptr), KEYPTR(ptr), (LLU)next[0]);
            return TWOM_IOERROR;
        }
        if (TYPE(nextptr) == DELETE) {
            deleted_offset = next[0];
            dirty_size += 24;
            next[0] = ANCESTOR(nextptr);
            if (!next[0]) return TWOM_IOERROR;
            nextptr = safeptr(loc, next[0]);
            if (!nextptr) return TWOM_IOERROR;
        }

        cmp = file->compar(KEYPTR(nextptr), KEYLEN(nextptr),
                           KEYPTR(ptr), KEYLEN(ptr));
        if (cmp <= 0) {
            db->error("out of order for consistent",
                      "fname=<%s> key=<%.*s> offset=<%08llX> prev_key=<%.*s>",
                      db->fname, (int)KEYLEN(nextptr), KEYPTR(nextptr),
                      (LLU)next[0], (int)KEYLEN(ptr), KEYPTR(ptr));
            return TWOM_IOERROR;
        }

        size_t ancestor = ANCESTOR(nextptr);
        while (ancestor) {
            const char *aptr = safeptr(loc, ancestor);
            if (!aptr) {
                db->error("failed to read ancestor for consistent",
                          "fname=<%s> key=<%.*s> offset=<%08llX>",
                          db->fname, (int)KEYLEN(nextptr), KEYPTR(nextptr),
                          (LLU)ancestor);
                return TWOM_IOERROR;
            }
            if (TYPE(aptr) == DELETE) {
                dirty_size += 24;
                ancestor = ANCESTOR(aptr);
                if (!ancestor) return TWOM_IOERROR;
                aptr = safeptr(loc, ancestor);
                if (!aptr) return TWOM_IOERROR;
            }
            cmp = file->compar(KEYPTR(aptr), KEYLEN(aptr),
                               KEYPTR(nextptr), KEYLEN(nextptr));
            if (cmp) {
                db->error("mismatched ancestor for consistent",
                          "fname=<%s> key=<%.*s> offset=<%08llX>"
                          " parent_key=<%.*s> parent_offset=<%08llX)",
                          db->fname, (int)KEYLEN(nextptr), KEYPTR(nextptr), (LLU)next[0],
                          (int)KEYLEN(aptr), KEYPTR(aptr), (LLU)ancestor);
                return TWOM_IOERROR;
            }
            dirty_size += RECLEN(aptr);
            ancestor = ANCESTOR(aptr);
        }

        uint8_t level = LEVEL(nextptr);
        for (i = 1; i < level; i++) {
            /* check the old pointer was to here */
            if (next[i] != next[0]) {
                db->error("broken linkage for consistent",
                          "fname=<%s> offset=<%08llX> level=<%d>"
                          " expected=<%08llX>",
                          db->fname, (LLU)next[0], i, (LLU)next[i]);
                return TWOM_IOERROR;
            }
            /* and advance to the new pointer */
            next[i] = NEXTN(nextptr, i);
        }
        next[0] = advance0(nextptr, loc->end);

        // count if record or tombstone
        if (deleted_offset) dirty_size += RECLEN(nextptr);
        else num_records++;

        ptr = nextptr;
    }

    for (i = 0; i < MAXLEVEL; i++) {
        if (next[i]) {
            db->error("broken tail for consistent",
                      "filename=<%s> offset=<%08llX> level=<%d>",
                      db->fname, (LLU)next[i], i);
            return TWOM_IOERROR;
        }
    }

    /* we walked the whole file and saw every pointer */

    if (num_records != txn->file->header.num_records) {
        db->error("record count mismatch for consistent",
                  "filename=<%s> num_records=<%llu> expected_records=<%llu>",
                  db->fname, (LLU)num_records, (LLU)txn->file->header.num_records);
        return TWOM_IOERROR;
    }

    if (dirty_size != txn->file->header.dirty_size) {
        db->error("dirty_size mismatch for consistent",
                  "filename=<%s> dirty_size=<%llu> expected_size=<%llu>",
                  db->fname, (LLU)dirty_size, (LLU)txn->file->header.dirty_size);
        return TWOM_IOERROR;
    }

    return 0;
}

/*********************** PUBLIC API ******************************/

// we refcount the database object by filename, so if you open twice in
// the same process, we don't have flock shenanigans, because flock state
// is process-wise, not file-descriptor specific, so it's not safe to just
// open the file in separate objects and lock it separately.
int twom_db_open(const char *fname, struct twom_open_data *setup,
                 struct twom_db **ret, struct twom_txn **txnp)
{
    struct twom_db *mydb;
    int r = 0;

    /* do we already have this DB open? */
    for (mydb = open_twom; mydb; mydb = mydb->next) {
        if (strcmp(mydb->fname, fname)) continue;
        if (txnp) {
            r = twom_db_begin_txn(mydb, setup->flags, txnp);
            if (r) return r;
        }
        // FIXME: we should check that setup->flags are compatible with the
        // flags that the DB was originally opened with and reject if they
        // aren't, e.g. NOSYNC
        mydb->refcount++;
        *ret = mydb;
        return 0;
    }

    r = opendb(fname, setup, &mydb, txnp);
    if (r) return r;

    /* track this database in the open list */
    mydb->refcount = 1;
    mydb->next = open_twom;
    open_twom = mydb;

    /* return the open DB */
    *ret = mydb;

    return 0;
}

int twom_db_close(struct twom_db **dbp)
{
    struct twom_db *mydb = open_twom;
    struct twom_db *prev = NULL;

    if (!*dbp) return 0;

    /* remove this DB from the open list */
    while (mydb && mydb != *dbp) {
        prev = mydb;
        mydb = mydb->next;
    }
    assert(mydb);

    if (--mydb->refcount <= 0) {
        if (prev) prev->next = mydb->next;
        else open_twom = mydb->next;
        dispose_db(mydb);
    }

    *dbp = NULL;

    return 0;
}

// if this is called instead of the txn_yield, it yields all
// readonly-locked files in the database, not just the current one.
int twom_db_yield(struct twom_db *db)
{
    if (!db) return 0;
    if (db->write_txn) return TWOM_LOCKED;
    // we don't check transactions for noyield, because they don't
    // control yield on other transactions; if you want to restrict
    // it entirely, it's only at the DB level that you we check
    if (db->noyield) return TWOM_LOCKED;
    struct tm_file *file;
    for (file = db->openfile; file; file = file->next)
        if (file->has_datalock == 1) unlock(db, file);
    return 0;
}

// with a readonly transaction, call this if you know you have
// a lot of other work to do, so other processes can make
// changes which you will either see or ignore depending on the
// TWOM_MVCC flag used to create the transaction.
int twom_txn_yield(struct twom_txn *txn)
{
    if (!txn) return 0;
    if (!txn->readonly) return TWOM_LOCKED;
    if (txn->file->has_datalock == 1) unlock(txn->db, txn->file);
    return 0;
}

// all database activity happens through transactions, either explicitly
// or via one implicitly created for a single call
int twom_db_begin_txn(struct twom_db *db, int flags, struct twom_txn **txnp)
{
    struct twom_txn *txn = *txnp;
    // you can call begin on an existing transaction, and it just refreshes
    // the read_lock if yield or another action has released it meanwhile
    if (txn) {
        assert (txn->file);
        if (txn->file->has_datalock == 2) return 0;
        if (!txn->readonly) return TWOM_LOCKED;
        if (txn->file->has_datalock) return 0;
        return read_lock(db, txnp, txn->file, flags);
    }

    // you can have multiple read-only transactions on a single database
    if (flags & TWOM_SHARED) {
        /* if we're already in a lock, that's fine! */
        if (db->openfile->has_datalock) {
            *txnp = _newtxn_read(db);
        }
        else {
            int r = read_lock(db, txnp, NULL, flags);
            if (r) return r;
        }
    }
    else {
        // you can't start another writable transaction if the file is
        // already locked for writing!
        if (db->openfile->has_datalock == 2) return TWOM_LOCKED;

        // if it's already read-locked, then we're fine to release that
        // lock, the caller will notice and refresh on next read if the
        // file has changed or extended; and it's fine to read from a
        // exclusively locked file.
        if (db->openfile->has_datalock == 1) unlock(db, db->openfile);

        int r = write_lock(db, txnp, NULL, flags);
        if (r) return r;
    }

    if (flags & TWOM_MVCC)
        (*txnp)->mvcc = 1;
    if (flags & TWOM_NOSYNC)
        (*txnp)->nosync = 1;
    if (flags & TWOM_NOYIELD)
        (*txnp)->noyield = 1;

    return 0;
}

int twom_txn_abort(struct twom_txn **txnp)
{
    if (!txnp || !*txnp) return 0;
    struct twom_db *db = (*txnp)->db;
    int r = abort_locked(txnp);
    *txnp = 0;
    if (!db->write_txn) unlock(db, NULL);
    return r;
}

int twom_txn_commit(struct twom_txn **txnp)
{
    if (!txnp || !*txnp) return 0;
    struct twom_db *db = (*txnp)->db;
    int r = commit_locked(txnp);
    *txnp = 0;
    if (!db->write_txn) unlock(db, NULL);
    return r;
}

// this API is a bit weird, but allows us to return the actual
// key if we were a FETCHNEXT.
int twom_txn_fetch(struct twom_txn *txn,
                   const char *key, size_t keylen,
                   const char **foundkey, size_t *foundkeylen,
                   const char **data, size_t *datalen,
                   int flags)
{
    struct twom_db *db = txn->db;
    int r = 0;

    if (datalen) assert(data);

    if (data) *data = NULL;
    if (datalen) *datalen = 0;

    struct tm_loc *loc = &db->loc;

    r = find_loc(txn, loc, key, keylen);
    if (r) return r;

    if (flags & TWOM_FETCHNEXT) {
        r = advance_loc(txn, loc);
        if (r == TWOM_DONE) return TWOM_NOTFOUND;
        if (r) return r;
    }

    // if there's no match, this key never existed
    if (!loc->offset) return TWOM_NOTFOUND;

    // if we're in an MVCC read, might need to find an ancestor

    size_t offset = loc->deleted_offset ? loc->deleted_offset : loc->offset;
    const char *ptr = safeptr(loc, offset);
    if (!ptr) return TWOM_IOERROR;
    while (offset >= txn->end) {
        offset = ANCESTOR(ptr);
        if (!offset) return TWOM_NOTFOUND;
        ptr = safeptr(loc, offset);
        if (!ptr) return TWOM_IOERROR;
    }

    /* active ancestor is a delete */
    if (TYPE(ptr) == DELETE) return TWOM_NOTFOUND;

    r = check_tailcsum(txn, loc->file, ptr, offset);
    if (r) return r;

    if (foundkey) *foundkey = KEYPTR(ptr);
    if (foundkeylen) *foundkeylen = KEYLEN(ptr);
    if (data) *data = VALPTR(ptr);
    if (datalen) *datalen = VALLEN(ptr);

    return 0;
}

int twom_db_begin_cursor(struct twom_db *db,
                         const char *prefix, size_t prefixlen,
                         struct twom_cursor **curp, int flags)
{
    struct twom_txn *txn = NULL;
    int r = twom_db_begin_txn(db, flags & TWOM_SHARED, &txn);
    if (r) return r;
    r = twom_txn_begin_cursor(txn, prefix, prefixlen, curp, flags);
    if (r) {
        int r2 = twom_txn_abort(&txn);
        return r2 ? r2 : r;
    }
    return 0;
}

// advance an existing cursor
int twom_cursor_next(struct twom_cursor *cur,
                     const char **foundkey, size_t *foundkeylen,
                     const char **data, size_t *datalen)
{
    int r;

    struct twom_txn *txn = cur->txn;
    struct tm_loc *loc = &cur->loc;

 again:
    if (txn->readonly) {
        // release locks every N records if readonly
        if (!txn->db->noyield && !txn->noyield && txn->counter++ > txn->db->foreach_lock_release) {
            r = twom_txn_yield(txn);
            if (r) return r;
        }

        if (!txn->file->has_datalock) {
            r = read_lock(txn->db, &txn, txn->mvcc ? txn->file : NULL, /*flags*/0);
            if (r) return r;
            txn->counter = 0;
        }
    }

    // otherwise we need to get the next key
    // (returns TWOM_DONE at end of file)
    r = advance_loc(txn, loc);
    if (r) return r;

    // do we need an MVCC ancestor?
    size_t offset = loc->deleted_offset ? loc->deleted_offset : loc->offset;
    const char *ptr = safeptr(loc, offset);
    if (!ptr) return TWOM_IOERROR;
    while (offset >= txn->end) {
        offset = ANCESTOR(ptr);
        if (!offset) goto again; // record didn't exist
        ptr = safeptr(loc, offset);
        if (!ptr) return TWOM_IOERROR;
    }

    // latest is a delete?  move along
    if (TYPE(ptr) == DELETE) goto again;

    // we have a returnable value!
    r = check_tailcsum(txn, loc->file, ptr, offset);
    if (r) return r;

    // we have to check the tailcsum BEFORE yielding, because another
    // process could change pointers, but we can yield now because the
    // lengths and contents are never changed after being written, so
    // it's safe to access them unlocked.
    if (txn->readonly && cur->alwaysyield) {
        r = twom_txn_yield(txn);
        if (r) return r;
        txn->counter = 0;
    }

    if (foundkey) *foundkey = KEYPTR(ptr);
    if (foundkeylen) *foundkeylen = KEYLEN(ptr);
    if (data) *data = VALPTR(ptr);
    if (datalen) *datalen = VALLEN(ptr);

    return 0;
}

// note: unused so far!  But this seems a useful API to provide
int twom_cursor_replace(struct twom_cursor *cur,
                        const char *data, size_t datalen, int flags)
{
    if (cur->txn->readonly) return TWOM_READONLY;
    if (!cur->loc.offset) return TWOM_NOTFOUND;
    const char *ptr = LOCPTR(&cur->loc);
    const char *key = KEYPTR(ptr);
    size_t keylen = KEYLEN(ptr);
    /* could be a delete or a replace */
    if (hastail[TYPE(ptr)]) {
        // replacing existing record
        if (flags & TWOM_IFNOTEXIST) return TWOM_EXISTS;
        if (!data) return store_here(cur->txn, key, keylen, NULL, 0);
        /* unchanged?  Save the IO */
        if (!cur->loc.file->compar(data, datalen, VALPTR(ptr), VALLEN(ptr)))
            return 0;
        return store_here(cur->txn, key, keylen, data, datalen);
    }

    if (flags & TWOM_IFEXIST) return TWOM_NOTFOUND;

    /* delete of already deleted is a NOOP */
    if (data) return store_here(cur->txn, key, keylen, data, datalen);

    return 0;
}

int twom_cursor_abort(struct twom_cursor **curp)
{
    struct twom_cursor *cur = *curp;
    if (cur->loc.file) {
        cur->loc.file->refcount--;
        cur->loc.file = NULL;
    }
    int r = twom_txn_abort(&cur->txn);
    free(cur);
    *curp = NULL;
    return r;
}

int twom_cursor_commit(struct twom_cursor **curp)
{
    struct twom_cursor *cur = *curp;
    if (cur->loc.file) {
        cur->loc.file->refcount--;
        cur->loc.file = NULL;
    }
    int r = twom_txn_commit(&cur->txn); // will call abort itself on error
    *curp = NULL;
    return r;
}

// begin a transaction with a cursor (use _fini below to close it)
int twom_txn_begin_cursor(struct twom_txn *txn,
                          const char *prefix, size_t prefixlen,
                          struct twom_cursor **curp, int flags)
{
    struct twom_cursor *cur = (struct twom_cursor *)twom_zmalloc(sizeof(struct twom_cursor));
    cur->txn = txn;
    if (flags & TWOM_ALWAYSYIELD) cur->alwaysyield = 1;

    int r = find_loc(cur->txn, &cur->loc, prefix, prefixlen);
    if (r) goto done;

    // unless we're skipping the first record, mark this location
    // as inexact, so advance_loc will find the key first, which
    // allows us to still re-seek all the way back to this record
    // and then advance from there if the file gets changed between
    // starting the cursor and our first read.
    if (!(flags & TWOM_SKIPROOT)) {
        cur->loc.deleted_offset = 0;
        cur->loc.offset = 0;
    }

 done:
    if (r) twom_cursor_fini(&cur);
    else *curp = cur;

    return r;
}

// useful for when you started with an external transaction that you're
// not finished with, just clean up the cursor
void twom_cursor_fini(struct twom_cursor **curp)
{
    struct twom_cursor *cur = *curp;
    if (!cur) return;
    if (cur->loc.file) {
        cur->loc.file->refcount--;
        cur->loc.file = NULL;
    }
    free(cur);
    *curp = NULL;
    return;
}

/* foreach allows for subsidiary operations in 'cb',
 * if there's a transaction then cb must use it.
 * If cb returns a non-zero result, then it gets
 * returned to the caller.  NOTE the values -128 to +1
 * are reserved.  This is a sucky interface really,
 * there should be another way to return errors.
 *
 * If you really need to return anything more complex, you
 * can store the return value inside 'rock' instead.
*/
int twom_txn_foreach(struct twom_txn *txn,
                     const char *prefix, size_t prefixlen,
                     twom_cb *goodp, twom_cb *cb, void *rock,
                     int flags)
{
    int r = 0, cb_r = 0;
    const char *key = NULL;
    size_t keylen = 0;
    const char *data = NULL;
    size_t datalen = 0;
    struct twom_cursor *cur = NULL;

    assert(cb);
    if (prefixlen) assert(prefix);

    r = twom_txn_begin_cursor(txn, prefix, prefixlen, &cur, flags);
    if (r) goto done;

    while ((r = twom_cursor_next(cur, &key, &keylen, &data, &datalen)) == 0) {
        /* does it match prefix? */
        if (prefixlen) {
            if (keylen < prefixlen) break;
            if (txn->file->compar(key, prefixlen, prefix, prefixlen)) break;
        }

        if ((!goodp || goodp(rock, key, keylen, data, datalen))) {
            /* make callback */
            cb_r = cb(rock, key, keylen, data, datalen);
            if (cb_r) break;
        }
    }

    // safely finished
    if (r == TWOM_DONE) r = 0;

 done:
    twom_cursor_fini(&cur);

    return r ? r : cb_r;
}

int twom_txn_store(struct twom_txn *txn,
                   const char *key, size_t keylen,
                   const char *data, size_t datalen,
                   int flags)
{
    /* no writing a readonly database */
    if (txn->db->readonly)
        return TWOM_READONLY;

    assert(txn == txn->db->write_txn);
    assert(key && keylen);

    return skipwrite(txn, key, keylen, data, datalen, flags);
}

const char *twom_db_fname(struct twom_db *db)
{
    return db->fname;
}

int twom_db_sync(struct twom_db *db)
{
    if (!db->openfile) return 0;
    return tm_commit(db, db->openfile->size);
}

size_t twom_db_generation(struct twom_db *db)
{
    return db->openfile->header.generation;
}

size_t twom_db_num_records(struct twom_db *db)
{
    return db->openfile->header.num_records;
}

size_t twom_db_size(struct twom_db *db)
{
    return db->openfile->header.current_size;
}

const char *twom_db_uuid(struct twom_db *db)
{
    uuid_unparse(db->openfile->header.uuid, db->uuidstr);
    return db->uuidstr;
}

// check if the file is fully consistent (all the records are
// in the right order, and all the skip levels link up)
static int twom_txn_consistent(struct twom_txn *txn)
{
    struct tm_loc *loc = (struct tm_loc *)twom_zmalloc(sizeof(struct tm_loc));
    loc->file = txn->file;
    loc->end = loc->file->written_size;
    int r = consistent1(txn, loc);
    free(loc);
    return r;
}

// dump the content of the database to stdout in a somewhat human
// understandable shape which gives offsets and details for
// each record.
static int twom_txn_dump(struct twom_txn *txn, int detail)
{
    char scratch[80];
    const char *ptr;
    size_t offset = DUMMY_OFFSET;
    size_t i;

    struct tm_header *header = &txn->file->header;
    struct twom_db *db = txn->db;
    struct tm_loc *loc = &db->loc;

    int r = find_loc(txn, loc, NULL, 0);
    if (r) return r;

    scratch[79] = 0; // avoid overruns

    printf("UUID: uuid=%s\nFNAME: fname=%s\n", twom_db_uuid(db), twom_db_fname(db));
    printf("CHECKSUM ENGINE: %s\n", checksum_engine(txn->file));
    printf("HEADER: v=%lu g=%llu fl=%08lX num=(%llu/%llu) sz=(%08llX/%08llX/%08llX) ml=%lu\n",
          (LU)header->version,
          (LLU)header->generation,
          (LU)header->flags,
          (LLU)header->num_records,
          (LLU)header->num_commits,
          (LLU)header->dirty_size,
          (LLU)header->current_size,
          (LLU)header->repack_size,
          (LU)header->maxlevel);

    while (offset + 24 <= loc->file->size) {
        if (!loc->file->base[offset]) {
            // skip NULL blocks
            offset += 8;
            continue;
        }
        printf("%08llX ", (LLU)offset);

        ptr = loc->file->base + offset;
        if (*ptr & ~7) {
            printf("BAD TYPE %d AT %08llX\n", (int)*ptr, (LLU)offset);
        }
        if (loc->file->size < offset + RECLEN(ptr)) break;

        if (check_headcsum(txn, loc->file, ptr, offset)) {
            printf("ERROR [HEADCSUM %08lX %08lX] ",
                    (long unsigned) HEADCSUM(ptr),
                    (long unsigned) loc->file->csum(ptr, HEADLEN(ptr)));
        }

        if (check_tailcsum(txn, loc->file, ptr, offset)) {
            printf("ERROR [TAILCSUM %08lX %08lX] ",
                    (long unsigned) TAILCSUM(ptr),
                    (long unsigned) loc->file->csum(KEYPTR(ptr), TAILLEN(ptr)));
        }

        uint8_t type = TYPE(ptr);
        if (type == COMMIT) {
            printf("COMMIT start=%08llX\n", (LLU)NEXT0(ptr, 0));
        }
        else if (type == DELETE) {
            size_t parent_offset = NEXT0(ptr, 0);
            const char *key = KEYPTR(loc->file->base + parent_offset);
            size_t len = KEYLEN(loc->file->base + parent_offset);
            if (len > 79) len = 79;
            if (key) strncpy(scratch, key, len);
            scratch[len] = 0;
            for (i = 0; i < len; i++)
                if (!scratch[i]) scratch[i] = '-';
            printf("DELETE kl=%llu (%s)\n", (LLU)KEYLEN(loc->file->base + parent_offset), scratch);
            printf("\t%08llX <-\n", (LLU)parent_offset);
        }
        else {
            const char *key = KEYPTR(ptr);
            size_t len = KEYLEN(ptr);
            if (len > 79) len = 79;
            if (key) strncpy(scratch, key, len);
            scratch[len] = 0;
            for (i = 0; i < len; i++)
                if (!scratch[i]) scratch[i] = '-';
            printf("%s kl=%llu dl=%llu lvl=%d (%s)\n",
                   typestr[type],
                   (LLU)KEYLEN(ptr), (LLU)VALLEN(ptr),
                   LEVEL(ptr), scratch);
            if (ancestoroffset[type]) {
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
                const char *val = VALPTR(ptr);
                size_t len = VALLEN(ptr);
                if (len > 79) len = 79;
                if (val) strncpy(scratch, val, len);
                scratch[len] = 0;
                printf("\tv=(%s)\n", scratch);
            }
        }

        offset += RECLEN(ptr);
    }

    return 0;
}

int twom_db_fetch(struct twom_db *db,
                  const char *key, size_t keylen,
                  const char **foundkey, size_t *foundkeylen,
                  const char **data, size_t *datalen,
                  int flags)
{
    // if we're inside a write txn, use that
    if (db->write_txn)
        return twom_txn_fetch(db->write_txn, key, keylen, foundkey, foundkeylen, data, datalen, flags);

    // otherwise a readonly transaction just for the duration and abort when done.
    struct twom_txn *txn = NULL;
    int r = twom_db_begin_txn(db, TWOM_SHARED, &txn);
    if (r) return r;
    r = twom_txn_fetch(txn, key, keylen, foundkey, foundkeylen, data, datalen, flags);
    twom_txn_abort(&txn);
    return r;
}

int twom_db_foreach(struct twom_db *db,
                    const char *prefix, size_t prefixlen,
                    twom_cb *goodp, twom_cb *cb, void *rock,
                    int flags)
{
    // if we're inside a write txn, use that
    if (db->write_txn)
        return twom_txn_foreach(db->write_txn, prefix, prefixlen, goodp, cb, rock, flags);

    // otherwise a readonly transaction just for the duration and abort when done.
    struct twom_txn *txn = NULL;
    int r = twom_db_begin_txn(db, TWOM_SHARED, &txn);
    if (r) return r;
    r = twom_txn_foreach(txn, prefix, prefixlen, goodp, cb, rock, flags);
    twom_txn_abort(&txn);
    return r;
}

int twom_db_store(struct twom_db *db,
                  const char *key, size_t keylen,
                  const char *data, size_t datalen,
                  int flags)
{
    // if we're inside a write txn, use that
    if (db->write_txn)
        return twom_txn_store(db->write_txn, key, keylen, data, datalen, flags);

    // otherwise a write transaction just for the duration, and commit or abort
    // immediately
    struct twom_txn *txn = NULL;
    int r = twom_db_begin_txn(db, 0, &txn);
    if (r) return r;
    r = twom_txn_store(txn, key, keylen, data, datalen, flags);
    if (r) {
        int r2 = twom_txn_abort(&txn);
        if (r2) r = r2;
    }
    else {
        r = twom_txn_commit(&txn);
    }
    return r;
}

int twom_db_dump(struct twom_db *db, int detail)
{
    struct twom_txn *txn = NULL;
    int r = twom_db_begin_txn(db, TWOM_SHARED, &txn);
    if (r) return r;
    r = twom_txn_dump(txn, detail);
    twom_txn_abort(&txn);
    return r;
}

int twom_db_check_consistency(struct twom_db *db)
{
    struct twom_txn *txn = NULL;
    int r = twom_db_begin_txn(db, TWOM_SHARED, &txn);
    if (r) return r;
    r = twom_txn_consistent(txn);
    twom_txn_abort(&txn);
    return r;
}

bool twom_db_should_repack(struct twom_db *db)
{
    struct tm_file *file = db->openfile;
    struct tm_header *header = &file->header;
    if (header->dirty_size > MINREWRITE
        && header->current_size < 4 * header->dirty_size) return 1;
    return 0;
}

// twom_db_repack: given an existing database, repack the content
// to save space.  This can be called explicitly, and you can
// check twom_db_should_repack to see if it's advised.
//
// We use an MVCC read transaction first to (with unlocks along
// the way) go through all the records in order at the time we
// started, then replay any new commits which happened in the
// meantime until we hit the end of the file.
//
// Once we're finished, we keep the read-only transaction so no
// more writes can happen while we update the generation number
// and tracking stats, then rename the .NEW file over the existing
// file, meaning that any other reader gets either of those two
// files and a consistent read without lost writes.
//
// This does mean that the resulting DB may contain some
// REPLACE or DELETE records as well, but we can do this
// without ever holding a long lock, and the REPLACE and
// DELETES will only be whatever happened after we started
// this repack.
//
// Since we ONLY lock the .NEW file exclusively, we could lose
// a race - but we lock with a non-blocking lock, so one process
// will return immediately and the other will finish the task.
//
// We also cross check the generation and UUID to make sure we
// don't accidentally pick up a file from another process which
// was doing the repack.
int twom_db_repack(struct twom_db *db)
{
    char newfname[1024];
    struct twom_txn *txn = NULL;
    struct twom_txn *newtxn = NULL;
    int oldfd = db->openfile->fd;
    int newfd = -1;

    // lock exclusively against another process repacking
    struct flock fl;
    fl.l_type= F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = OFFSET_GENERATION;
    fl.l_len = 8;
    for (;;) {
        if (fcntl(oldfd, F_SETLK, &fl) < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) return TWOM_LOCKED;
            return TWOM_IOERROR;
        }
        break;
    }

    int r = twom_db_begin_txn(db, TWOM_SHARED|TWOM_MVCC, &txn);
    if (r) return r;

    if (txn->file->fd != oldfd) {
        // we lost a race here! When the transaction locked the file,
        // it got a new inode, so another process has repacked meanwhile.
        r = TWOM_LOCKED;
        goto badfile;
    }

    // don't make things worse with a broken file
    r = twom_txn_consistent(txn);
    if (r) {
        db->error("inconsistent pre-repack",
                  "filename=<%s>", db->fname);
        goto badfile;
    }

    /* open fname.NEW */
    snprintf(newfname, sizeof(newfname), "%s.NEW", db->fname);

    int flags = TWOM_NONBLOCKING; // if another file has already locked it, something is broken
    if (db->external_csum)
        flags |= TWOM_CSUM_EXTERNAL;
    else if (db->nocsum)
        flags |= TWOM_CSUM_NULL;
    else
        flags |= TWOM_CSUM_XXH64;
    if (db->external_compar)
        flags |= TWOM_COMPAR_EXTERNAL;
    if (db->nosync)
        flags |= TWOM_NOSYNC;

    /* we hand-open the new file and make it the first openfile, so it has
     * the write_txn against it and all the sanity checks make sense */
    unlink(newfname);
    newfd = open(newfname, O_RDWR|O_CREAT, 0644);
    if (newfd < 0) {
        r = TWOM_IOERROR;
        goto badfile;
    }

    struct tm_file *oldfile = db->openfile;
    db->openfile = (struct tm_file *)twom_zmalloc(sizeof(struct tm_file));
    db->openfile->fd = newfd;
    db->openfile->next = oldfile;

    // we're just doing small copies, release less frequently
    db->foreach_lock_release *= 64;

    // initdb will create a new header on the new file:
    // It will have a different UUID, no records, and be generation 1
    r = initdb(db, flags);
    if (r) goto fail;

    // make sure we have all the locks set up
    r = write_lock(db, &newtxn, db->openfile, flags);
    if (r) goto fail;

    // we'll likely need about enough space for the current
    // database, minus the dirty bytes, minus 24 bytes per
    // extra commit.  This isn't exact, because new records
    // will have diferent random levels
    tm_ensure(db, oldfile->header.current_size
                - oldfile->header.dirty_size
                - (oldfile->header.num_commits-1) * 24);

    // initialise the writer location on the new file
    r = find_loc(newtxn, &db->loc, NULL, 0);
    if (r) goto fail;

    // mvcc process all the existing records
    r = twom_txn_foreach(txn, NULL, 0, NULL, copy_cb, newtxn, /*flags*/0);
    if (r) goto fail;

    /* remember the repack size at this point, because that's everything
     * which is in order!  The remaing replayed items might be deletes or
     * replaces, so they still dirty up the ordering as much as new changes. */
    newtxn->file->header.repack_size = newtxn->end;

    // replay all the remaining changes to the end of the file
    r = myreplay(txn, replay_cb, newtxn);
    if (r) goto fail;

    // we still need a read-lock at this point.  This is the critical
    // section; we must either abort, or hold the lock until the rename
    // is completed
    assert(oldfile->has_datalock);

    /* same uuid */
    memcpy(newtxn->file->header.uuid, oldfile->header.uuid, 16);

    /* increase the generation count */
    newtxn->file->header.generation = oldfile->header.generation + 1;

    r = commit_locked(&newtxn);
    if (r) goto fail;

    /* move new file to original file name */
    r = tm_rename(db, oldfile, newfname);
    if (r) goto fail;

    // rename is done, we can now safely unlock the old file
    unlock(db, oldfile);
    abort_locked(&txn);

    fl.l_type= F_UNLCK;
    for (;;) {
        if (fcntl(oldfd, F_SETLKW, &fl) < 0)
            if (errno == EINTR) continue;
        break;
    }

    // and unlock the new file too - this is the point that new
    // processes will start work
    unlock(db, NULL);

    db->foreach_lock_release /= 64; // don't leave things weird!

    return 0;

 fail:
    // unwind the new file and new txn.  This is for if we abort AFTER
    // we start writing to the new file.  In this case, the new file
    // contains rubish so we'll unlink it before unlocking.
    if (db->loc.file) db->loc.file->refcount--;
    memset(&db->loc, 0, sizeof(struct tm_loc));
    unlink(newfname);
    abort_locked(&newtxn);
    // we patch out the new file again, so db contains the oldfile again
    // (read locked) before we clean it up.  Caller will still have oldfile
    // open for its next operation, but unlocked.
    close(newfd);
    free(db->openfile);
    db->openfile = oldfile;

 badfile:
    fl.l_type= F_UNLCK;
    for (;;) {
        if (fcntl(oldfd, F_SETLKW, &fl) < 0)
            if (errno == EINTR) continue;
        break;
    }
    db->foreach_lock_release /= 64; // don't leave things weird!
    twom_txn_abort(&txn);
    return r;
}

const char *twom_strerror(int r)
{
    switch (r) {
    case TWOM_OK: return "OK";
    case TWOM_DONE: return "Done";
    case TWOM_IOERROR: return "IO Error";
    case TWOM_EXISTS: return "Exists";
    case TWOM_INTERNAL: return "Internal Error";
    case TWOM_NOTFOUND: return "Not Found";
    case TWOM_LOCKED: return "Database is locked";
    case TWOM_READONLY: return "Database is read-only";
    default: return "Unknown error";
    }
}
