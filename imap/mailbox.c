/* mailbox.c -- Mailbox manipulation routines
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <errno.h>
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#elif defined(HAVE_STDINT_H)
# include <stdint.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <utime.h>

#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "annotate.h"
#include "assert.h"
#ifdef WITH_DAV
#include "caldav_db.h"
#include "caldav_alarm.h"
#include "carddav_db.h"
#include "webdav_db.h"
#include "ical_support.h"
#include "vcard_support.h"
#endif /* WITH_DAV */
#include "crc32.h"
#include "md5.h"
#include "global.h"
#include "imparse.h"
#include "cyr_lock.h"
#include "mailbox.h"
#include "mappedfile.h"
#include "message.h"
#include "map.h"
#include "mboxevent.h"
#include "mboxlist.h"
#include "parseaddr.h"
#include "proc.h"
#include "retry.h"
#include "seen.h"
#include "user.h"
#include "util.h"
#include "sequence.h"
#include "statuscache.h"
#include "strarray.h"
#include "sync_log.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "xstats.h"


#if defined ENABLE_OBJECTSTORE
#include "objectstore.h"
#include "objectstore_db.h"
#endif

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
#include "imap/mailbox_header_cache.h"

static mailbox_wait_cb_t *mailbox_wait_cb = NULL;
static void *mailbox_wait_cb_rock = NULL;

struct mailboxlist {
    struct mailboxlist *next;
    struct mailbox m;
    struct mboxlock *l;
    int nopen;
};

static struct mailboxlist *open_mailboxes = NULL;

#define zeromailbox(m) do { memset(&m, 0, sizeof(struct mailbox)); \
                            (m).index_fd = -1; \
                            (m).header_fd = -1; \
} while (0)

/* for repack */
struct mailbox_repack {
    struct mailbox *mailbox;
    struct mailbox newmailbox;
    struct seqset *seqset;
    struct synccrcs crcs;
    char *userid;
    ptrarray_t caches;
};

static struct MsgFlagMap msgflagmap[] = {
    {"AN", (int)FLAG_ANSWERED},
    {"FL", (int)FLAG_FLAGGED},
    {"DE", (int)FLAG_DELETED},
    {"DR", (int)FLAG_DRAFT},
    {"SE", (int)FLAG_SEEN},
    {"SN", (int)FLAG_INTERNAL_SNOOZED},
    {"SP", (int)FLAG_INTERNAL_SPLITCONVERSATION},
    {"NC", (int)FLAG_INTERNAL_NEEDS_CLEANUP},
    {"AR", (int)FLAG_INTERNAL_ARCHIVED},
    {"UN", (int)FLAG_INTERNAL_UNLINKED},
    {"EX", (int)FLAG_INTERNAL_EXPUNGED}
    /* ZZ -> invalid file found on disk */
};
/* The length of the msgflagmap list * 2 +
 * Total number of separators possible
 * = 33 bytes
 */
#define FLAGMAPSTR_MAXLEN (1 + 3 *(sizeof(msgflagmap) / sizeof(struct MsgFlagMap)))

static int mailbox_index_unlink(struct mailbox *mailbox);
static int mailbox_index_repack(struct mailbox *mailbox, int version);
static void mailbox_repack_abort(struct mailbox_repack **repackptr);
static int mailbox_lock_index_internal(struct mailbox *mailbox,
                                       int locktype);
static void cleanup_stale_expunged(struct mailbox *mailbox);
static bit32 mailbox_index_record_to_buf(struct index_record *record, int version,
                                         unsigned char *buf);

#ifdef WITH_DAV
static struct webdav_db *mailbox_open_webdav(struct mailbox *);
static int mailbox_commit_dav(struct mailbox *mailbox);
static int mailbox_abort_dav(struct mailbox *mailbox);
static int mailbox_delete_dav(struct mailbox *mailbox);
#endif

static inline void flags_to_str_internal(uint32_t flags, char *flagstr)
{
    size_t i, len = 0;
    size_t map_size;
    char *p;

    p = flagstr;
    memset(p, 0, FLAGMAPSTR_MAXLEN);
    map_size = sizeof(msgflagmap) / sizeof(struct MsgFlagMap);

    for (i = 0; i <  map_size && len < FLAGMAPSTR_MAXLEN; i++) {
        if (flags & msgflagmap[i].flag) {
            if (p != flagstr) {
                *p++ = '|';
                len++;
            }

            *p++ = msgflagmap[i].code[0];
            *p++ = msgflagmap[i].code[1];
            len += 2;
        }
    }
}

static void flags_to_str(struct index_record *record, char *flagstr)
{
    uint32_t flags = record->system_flags | record->internal_flags;

    flags_to_str_internal(flags, flagstr);
}

EXPORTED int open_mailboxes_exist()
{
    return open_mailboxes ? 1 : 0;
}

static struct mailboxlist *create_listitem(const char *name)
{
    struct mailboxlist *item = xzmalloc(sizeof(struct mailboxlist));
    item->next = open_mailboxes;
    open_mailboxes = item;

    item->nopen = 1;
    zeromailbox(item->m);
    item->m.name = xstrdup(name);
    /* ensure we never print insane times */
    gettimeofday(&item->m.starttime, 0);

#if defined ENABLE_OBJECTSTORE
    if (config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED))
        keep_user_message_db_open (1);
#endif

    return item;
}

static struct mailboxlist *find_listitem(const char *name)
{
    struct mailboxlist *item;

    for (item = open_mailboxes; item; item = item->next) {
        if (!strcmp(name, item->m.name))
            return item;
    }

    return NULL;
}

static void remove_listitem(struct mailboxlist *remitem)
{
    struct mailboxlist *item;
    struct mailboxlist *previtem = NULL;

    for (item = open_mailboxes; item; item = item->next) {
        if (item == remitem) {

            if (previtem)
                previtem->next = item->next;
            else
                open_mailboxes = item->next;
            free(item);

#if defined ENABLE_OBJECTSTORE
            if (!open_mailboxes && config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED))  // time to close the database
                 keep_user_message_db_open (0);
#endif
            return;
        }
        previtem = item;
    }

    fatal("didn't find item in list", EX_SOFTWARE);
}

EXPORTED const char *mailbox_meta_fname(struct mailbox *mailbox, int metafile)
{
    static char fnamebuf[MAX_MAILBOX_PATH];
    uint32_t legacy_dirs = (mailbox->mbtype & MBTYPE_LEGACY_DIRS);
    const char *src;

    src = mboxname_metapath(mailbox->part, mailbox->name,
                            legacy_dirs ? NULL : mailbox->uniqueid,
                            metafile, 0);
    if (!src) return NULL;

    xstrncpy(fnamebuf, src, MAX_MAILBOX_PATH);
    return fnamebuf;
}

EXPORTED const char *mailbox_meta_newfname(struct mailbox *mailbox, int metafile)
{
    static char fnamebuf[MAX_MAILBOX_PATH];
    uint32_t legacy_dirs = (mailbox->mbtype & MBTYPE_LEGACY_DIRS);
    const char *src;

    src = mboxname_metapath(mailbox->part, mailbox->name,
                            legacy_dirs ? NULL : mailbox->uniqueid,
                            metafile, 1);
    if (!src) return NULL;

    xstrncpy(fnamebuf, src, MAX_MAILBOX_PATH);
    return fnamebuf;
}

EXPORTED int mailbox_meta_rename(struct mailbox *mailbox, int metafile)
{
    const char *fname = mailbox_meta_fname(mailbox, metafile);
    const char *newfname = mailbox_meta_newfname(mailbox, metafile);

    if (rename(newfname, fname))
        return IMAP_IOERROR;

    return 0;
}

static const char *mailbox_spool_fname(struct mailbox *mailbox, uint32_t uid)
{
    uint32_t legacy_dirs = (mailbox->mbtype & MBTYPE_LEGACY_DIRS);
    return mboxname_datapath(mailbox->part, mailbox->name,
                             legacy_dirs ? NULL : mailbox->uniqueid,
                             uid);
}

static const char *mailbox_archive_fname(struct mailbox *mailbox, uint32_t uid)
{
    uint32_t legacy_dirs = (mailbox->mbtype & MBTYPE_LEGACY_DIRS);
    return mboxname_archivepath(mailbox->part, mailbox->name,
                                legacy_dirs ? NULL : mailbox->uniqueid,
                                uid);
}

EXPORTED const char *mailbox_record_fname(struct mailbox *mailbox,
                                          const struct index_record *record)
{
    int object_storage_enabled = 0 ;
#if defined ENABLE_OBJECTSTORE
    object_storage_enabled = config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED) ;
#endif

    if (!object_storage_enabled && (record->internal_flags & FLAG_INTERNAL_ARCHIVED))
        return mailbox_archive_fname(mailbox, record->uid);
    else
        return mailbox_spool_fname(mailbox, record->uid);
}

EXPORTED const char *mailbox_datapath(struct mailbox *mailbox, uint32_t uid)
{
    static char localbuf[MAX_MAILBOX_PATH];
    uint32_t legacy_dirs = (mailbox->mbtype & MBTYPE_LEGACY_DIRS);
    const char *src;

    src = mboxname_datapath(mailbox->part, mailbox->name,
                            legacy_dirs ? NULL : mailbox->uniqueid,
                            uid);
    if (!src) return NULL;

    xstrncpy(localbuf, src, MAX_MAILBOX_PATH);
    return localbuf;
}

/*
 *  Function to test if a header is in the cache
 *
 *  Assume cache entry version 1, unless other data is found
 *  in the table.
 */
static inline unsigned is_cached_header(const char *hdr)
{
    size_t len;
    struct mailbox_header_cache *thdr;

    len = strlen(hdr);
    if (len >= MAX_CACHED_HEADER_SIZE)
        return BIT32_MAX;

    thdr = mailbox_header_cache_lookup(hdr, len);

    if (thdr)
        return thdr->min_cache_version;

    /* Don't Cache X- headers unless explicitly configured to*/
    if (((hdr[0] == 'x') || (hdr[0] == 'X')) &&
        (hdr[1] == '-')) return BIT32_MAX;

    /* Everything else we cache in version 1 */
    return 1;
}

/*  External API to is_cached_header that prepares the string
 *
 *   Returns minimum version required for lookup to succeed
 *   or BIT32_MAX if header not cached
 */
EXPORTED unsigned mailbox_cached_header(const char *s)
{
    return is_cached_header(s);
}

/* Same as mailbox_cached_header, but for use on a header
 * as it appears in the message (i.e. :-terminated, not NUL-terminated)
 */
HIDDEN unsigned mailbox_cached_header_inline(const char *text)
{
    char buf[MAX_CACHED_HEADER_SIZE];
    int i;

    /* Scan for header */
    for (i=0; i < MAX_CACHED_HEADER_SIZE; i++) {
        if (!text[i] || text[i] == '\r' || text[i] == '\n') break;

        if (text[i] == ':') {
            buf[i] = '\0';
            return is_cached_header(buf);
        } else {
            buf[i] = text[i];
        }
    }

    return BIT32_MAX;
}

static const char *cache_base(const struct index_record *record)
{
    const char *base = record->crec.buf->s;
    return base + record->crec.offset;
}

static size_t cache_len(const struct index_record *record)
{
    return record->crec.len;
}

static struct buf *cache_buf(const struct index_record *record)
{
    static struct buf staticbuf;

    buf_init_ro(&staticbuf,
                cache_base(record),
                cache_len(record));

    return &staticbuf;
}

EXPORTED const char *cacheitem_base(const struct index_record *record, int field)
{
    const char *base = record->crec.buf->s;
    return base + record->crec.item[field].offset;
}

EXPORTED unsigned cacheitem_size(const struct index_record *record, int field)
{
    return record->crec.item[field].len;
}

EXPORTED struct buf *cacheitem_buf(const struct index_record *record, int field)
{
    static struct buf staticbuf;

    buf_init_ro(&staticbuf,
                cacheitem_base(record, field),
                cacheitem_size(record, field));

    return &staticbuf;
}

/* parse a single cache record from the mapped file - creates buf
 * records which point into the map, so you can't free it while
 * you still have them around! */
static int cache_parserecord(struct mappedfile *cachefile, uint64_t cache_offset,
                             struct cacherecord *crec)
{
    const struct buf *buf = mappedfile_buf(cachefile);
    size_t buf_size = mappedfile_size(cachefile);
    const char *cacheitem, *next;
    size_t offset;
    int cache_ent;

    offset = cache_offset;

    for (cache_ent = 0; cache_ent < NUM_CACHE_FIELDS; cache_ent++) {
        cacheitem = buf->s + offset;

        /* bounds checking */
        if (offset >= buf_size) {
            xsyslog(LOG_ERR, "IOERROR: offset greater than cache size",
                             "offset=<" SIZE_T_FMT "> "
                             "buf_size=<" SIZE_T_FMT "> "
                             "cache_ent=<%d>",
                             offset, buf_size, cache_ent);
            return IMAP_IOERROR;
        }

        if (offset + CACHE_ITEM_SIZE_SKIP + CACHE_ITEM_LEN(cacheitem) > buf_size) {
            xsyslog(LOG_ERR, "IOERROR: cache entry truncated",
                             "offset=<" SIZE_T_FMT "> "
                             "length=<%u> "
                             "buf_size=<" SIZE_T_FMT "> "
                             "cache_ent=<%d>",
                             offset, CACHE_ITEM_LEN(cacheitem),
                             buf_size, cache_ent);
            return IMAP_IOERROR;
        }

        /* copy locations */
        crec->item[cache_ent].len = CACHE_ITEM_LEN(cacheitem);
        crec->item[cache_ent].offset = offset + CACHE_ITEM_SIZE_SKIP;

        /* moving on */
        next = CACHE_ITEM_NEXT(cacheitem);
        if (next < cacheitem) {
            xsyslog(LOG_ERR, "IOERROR: cache offset negative", NULL);
            return IMAP_IOERROR;
        }

        offset = next - buf->s;
    }

    /* all fit within the cache, it's gold as far as we can tell */
    crec->buf = buf;
    crec->len = offset - cache_offset;
    crec->offset = cache_offset;

    return 0;
}

EXPORTED char *mailbox_cache_get_env(struct mailbox *mailbox,
                                     const struct index_record *record,
                                     int token)
{
    char *env;
    char *envtokens[NUMENVTOKENS];
    char *field;

    if (mailbox_cacherecord(mailbox, record))
        return NULL;

    if (cacheitem_size(record, CACHE_ENVELOPE) <= 2)
        return NULL;

    /* get field out of the envelope
     *
     * get a working copy; strip outer ()'s
     * +1 -> skip the leading paren
     * -2 -> don't include the size of the outer parens
     */
    env = xstrndup(cacheitem_base(record, CACHE_ENVELOPE) + 1,
                   cacheitem_size(record, CACHE_ENVELOPE) - 2);
    parse_cached_envelope(env, envtokens, VECTOR_SIZE(envtokens));

    field = xstrdupnull(envtokens[token]);

    /* free stuff */
    free(env);

    return field;
}

EXPORTED int mailbox_index_islocked(struct mailbox *mailbox, int write)
{
    if (mailbox->index_locktype == LOCK_EXCLUSIVE) return 1;
    if (mailbox->index_locktype == LOCK_SHARED && !write) return 1;
    return 0;
}

static int cache_append_record(struct mappedfile *mf, struct index_record *record)
{
    const struct buf *buf = cache_buf(record);
    size_t offset = mappedfile_size(mf);
    int n;

    n = mappedfile_pwritebuf(mf, buf, offset);
    if (n < 0) {
        syslog(LOG_ERR, "failed to append " SIZE_T_FMT " bytes to cache", buf->len);
        return IMAP_IOERROR;
    }

    record->cache_offset = offset;

    return 0;
}

static struct mappedfile *cache_getfile(ptrarray_t *list, const char *fname,
                                        int readonly, uint32_t generation)
{
    struct mappedfile *cachefile = NULL;
    int openflags = readonly ? 0 : MAPPEDFILE_CREATE | MAPPEDFILE_RW;
    int i;

    for (i = 0; i < list->count; i++) {
        cachefile = ptrarray_nth(list, i);
        if (!strcmp(fname, mappedfile_fname(cachefile)))
            return cachefile;
    }

    /* guess we didn't find it - open a new one */
    cachefile = NULL;
    if (mappedfile_open(&cachefile, fname, openflags)) {
        xsyslog(LOG_ERR, "IOERROR: failed to open cache file",
                         "fname=<%s>",
                         fname);
        return NULL;
    }

    if (!readonly && !mappedfile_size(cachefile)) {
        /* zero byte file?  Set the generation */
        uint32_t netgen = htonl(generation);
        mappedfile_pwrite(cachefile, (const char *) &netgen, 4, 0);
        mappedfile_commit(cachefile);
    }

    ptrarray_append(list, cachefile);

    return cachefile;
}

static struct mappedfile *mailbox_cachefile(struct mailbox *mailbox,
                                            const struct index_record *record)
{
    const char *fname;

    if (record->internal_flags & FLAG_INTERNAL_ARCHIVED)
        fname = mailbox_meta_fname(mailbox, META_ARCHIVECACHE);
    else
        fname = mailbox_meta_fname(mailbox, META_CACHE);

    return cache_getfile(&mailbox->caches, fname, mailbox->is_readonly, mailbox->i.generation_no);
}

static struct mappedfile *repack_cachefile(struct mailbox_repack *repack,
                                           const struct index_record *record)
{
    const char *fname;

    if (record->internal_flags & FLAG_INTERNAL_ARCHIVED)
        fname = mailbox_meta_newfname(repack->mailbox, META_ARCHIVECACHE);
    else
        fname = mailbox_meta_newfname(repack->mailbox, META_CACHE);

    return cache_getfile(&repack->caches, fname, /*readonly*/0, repack->newmailbox.i.generation_no);
}

/* return the offset for the start of the record! */
static int mailbox_append_cache(struct mailbox *mailbox,
                                struct index_record *record)
{
    struct mappedfile *cachefile;
    int r;

    assert(mailbox_index_islocked(mailbox, 1));

    /* already been written */
    if (record->cache_offset)
        return 0;

    /* no cache content */
    if (!record->crec.len) {
        /* make one! */
        const char *fname = mailbox_record_fname(mailbox, record);
        xsyslog(LOG_ERR, "IOERROR: no cache content, parsing and saving",
                         "mailbox=<%s> record=<%u>",
                         mailbox->name, record->uid);
        r = message_parse(fname, record);
        if (r) return r;
        mailbox_index_dirty(mailbox);
        mailbox->i.options |= OPT_MAILBOX_NEEDS_REPACK;
    }

    cachefile = mailbox_cachefile(mailbox, record);
    if (!cachefile) {
        syslog(LOG_ERR, "Failed to open cache to %s for %u",
                mailbox->name, record->uid);
        return IMAP_IOERROR; /* unable to append */
    }

    r = cache_append_record(cachefile, record);
    if (r) {
        syslog(LOG_ERR, "Failed to append cache to %s for %u",
               mailbox->name, record->uid);
        return r;
    }

    return 0;
}

enum mbcache_rewrite_t {
    MBCACHE_NOPARSE,
    MBCACHE_PARSEONLY,
    MBCACHE_REWRITE
};

static int mailbox_cacherecord_internal(struct mailbox *mailbox,
                                        const struct index_record *record,
                                        enum mbcache_rewrite_t rewrite)
{
    struct mappedfile *cachefile;
    bit32 crc = 0;
    int r = IMAP_IOERROR;

    /* we do something nasty here to work around lazy loading while still
     * giving const protection to records which are only used for read */
    struct index_record *backdoor = (struct index_record *)record;

    /* do we already have a record loaded? */
    if (record->crec.len)
        return 0;

    /* make sure there's a file to read from */
    cachefile = mailbox_cachefile(mailbox, record);
    if (!cachefile)
        goto err;

    /* do we have an offset? */
    if (!record->cache_offset)
        goto err;

    /* try to parse the cache record */
    r = cache_parserecord(cachefile, record->cache_offset, &backdoor->crec);
    if (r) goto err;

    /* old-style record */
    if (!record->cache_crc)
        goto err;

    crc = crc32_buf(cache_buf(record));
    if (crc != record->cache_crc)
        r = IMAP_MAILBOX_CHECKSUM;

    if (r) goto err;
    return 0;

err:
    if (!cachefile)
        xsyslog(LOG_ERR, "IOERROR: missing cache file",
                         "mailbox=<%s> uid=<%u>",
                         mailbox->name, record->uid);
    else if (!record->cache_offset)
        xsyslog(LOG_ERR, "IOERROR: missing cache offset",
                         "mailbox=<%s> uid=<%u>",
                         mailbox->name, record->uid);
    else if (r)
        xsyslog(LOG_ERR, "IOERROR invalid cache record",
                         "mailbox=<%s> uid=<%u> error=<%s> crc=<%d> cache_offset=<%llu>",
                         mailbox->name, record->uid, error_message(r),
                         crc, (unsigned long long) record->cache_offset);

    if (rewrite == MBCACHE_NOPARSE)
        return r;

    /* parse the file again */

    /* parse directly into the cache for this record */
    const char *fname = mailbox_record_fname(mailbox, record);
    if (!fname) {
        xsyslog(LOG_ERR, "IOERROR: no spool file",
                         "mailbox=<%s> uid=<%u>",
                         mailbox->name, record->uid);
        return IMAP_IOERROR;
    }

    /* parse into the file and zero the cache offset */
    r = message_parse(fname, backdoor);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: failed to parse message",
                         "mailbox=<%s> uid=<%u>",
                         mailbox->name, record->uid);
        return r;
    }
    backdoor->cache_offset = 0;

    if (rewrite == MBCACHE_REWRITE) {
        r = mailbox_append_cache(mailbox, backdoor);
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: failed to append cache",
                             "mailbox=<%s> uid=<%u>",
                             mailbox->name, record->uid);
            return r;
        }
    }

    return 0;
}

EXPORTED int mailbox_cacherecord(struct mailbox *mailbox, const struct index_record *record)
{
    enum mbcache_rewrite_t rewrite = mailbox_index_islocked(mailbox, 1) ? MBCACHE_REWRITE : MBCACHE_PARSEONLY;
    return mailbox_cacherecord_internal(mailbox, record, rewrite);
}

static int mailbox_abort_cache(struct mailbox *mailbox)
{
    if (!mailbox->caches.count)
        return 0;

    /* XXX - we need offsets into each file to use
       mappedfile_truncate */

    return 0;
}

static int mailbox_commit_cache(struct mailbox *mailbox)
{
    int i;

    for (i = 0; i < mailbox->caches.count; i++) {
        struct mappedfile *cachefile = ptrarray_nth(&mailbox->caches, i);
        int r = mappedfile_commit(cachefile);
        if (r) return r;
    }

    return 0;
}

/* function to be used for notification of mailbox changes/updates */
static mailbox_notifyproc_t *updatenotifier = NULL;

/*
 * Set the updatenotifier function
 */
HIDDEN void mailbox_set_updatenotifier(mailbox_notifyproc_t *notifyproc)
{
    updatenotifier = notifyproc;
}

/*
 * Get the updatenotifier function
 */
mailbox_notifyproc_t *mailbox_get_updatenotifier(void)
{
    return updatenotifier;
}

static void mailbox_set_uniqueid(struct mailbox *mailbox, const char *uniqueid)
{
    free(mailbox->uniqueid);
    mailbox->uniqueid = xstrdup(uniqueid);
    mailbox->header_dirty = 1;
}

/*
 * Create the unique identifier for a mailbox named 'name' with
 * uidvalidity 'uidvalidity'.  We use Ted Ts'o's libuuid if available,
 * otherwise we use some random bits.
 */
EXPORTED void mailbox_make_uniqueid(struct mailbox *mailbox)
{
    mailbox_set_uniqueid(mailbox, makeuuid());
}

static int _map_local_record(const struct mailbox *mailbox, const char *fname, struct buf *buf)
{
    struct stat sbuf;
    int msgfd;

    msgfd = open(fname, O_RDONLY, 0666);
    if (msgfd == -1) return errno;

    if (fstat(msgfd, &sbuf) == -1) {
        xsyslog(LOG_ERR, "IOERROR: fstat failed",
                         "fname=<%s>",
                         fname);
        fatal("can't fstat message file", EX_OSFILE);
    }

    buf_refresh_mmap(buf, /*onceonly*/1, msgfd, fname, sbuf.st_size, mailbox->name);
    close(msgfd);

    return 0;
}

EXPORTED int mailbox_map_record(struct mailbox *mailbox, const struct index_record *record, struct buf *buf)
{
    xstats_inc(MESSAGE_MAP);

    const char *fname = mailbox_record_fname(mailbox, record);
    int r = _map_local_record(mailbox, fname, buf);
    if (!r) return 0;

#if defined ENABLE_OBJECTSTORE
    if (config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED)){
        r = objectstore_get(mailbox, record, fname);
        if (r) return r;
        r = _map_local_record(mailbox, fname, buf);
        remove(fname);
    }
#endif

    return r;
}


static void mailbox_release_resources(struct mailbox *mailbox)
{
    int i;

    if (mailbox->i.dirty)
        abort();

    /* just close the header */
    xclose(mailbox->header_fd);

    /* release and unmap index */
    xclose(mailbox->index_fd);
    mailbox->index_locktype = 0; /* lock was released by closing fd */
    if (mailbox->index_base)
        map_free(&mailbox->index_base, &mailbox->index_len);

    /* release caches */
    for (i = 0; i < mailbox->caches.count; i++) {
        struct mappedfile *cachefile = ptrarray_nth(&mailbox->caches, i);
        mappedfile_close(&cachefile);
    }
    ptrarray_fini(&mailbox->caches);
}

/*
 * Open the index file for 'mailbox'
 */
static int mailbox_open_index(struct mailbox *mailbox)
{
    struct stat sbuf;
    const char *fname;
    int openflags = mailbox->is_readonly ? O_RDONLY : O_RDWR;

    mailbox_release_resources(mailbox);

    /* open and map the index file */
    fname = mailbox_meta_fname(mailbox, META_INDEX);
    if (!fname)
        return IMAP_MAILBOX_BADNAME;

    mailbox->index_fd = open(fname, openflags, 0);
    if (mailbox->index_fd == -1)
        return IMAP_IOERROR;

    /* don't open the cache yet, it will be loaded by lazy-loading
     * later */

    fstat(mailbox->index_fd, &sbuf);
    mailbox->index_ino = sbuf.st_ino;
    mailbox->index_mtime = sbuf.st_mtime;
    mailbox->index_size = sbuf.st_size;
    map_refresh(mailbox->index_fd, 0, &mailbox->index_base,
                &mailbox->index_len, mailbox->index_size,
                "index", mailbox->name);

    return 0;
}

static int mailbox_mboxlock_reopen(struct mailboxlist *listitem, int locktype, int index_locktype)
{
    struct mailbox *mailbox = &listitem->m;
    int r;

    mailbox_release_resources(mailbox);

    mboxname_release(&listitem->l);
    mboxname_release(&mailbox->local_namespacelock);

    char *userid = mboxname_to_userid(mailbox->name);
    if (userid) {
        int haslock = user_isnamespacelocked(userid);
        if (haslock) {
            if (index_locktype != LOCK_SHARED) assert(haslock != LOCK_SHARED);
        }
        else {
            mailbox->local_namespacelock = user_namespacelock_full(userid, index_locktype);
        }
        free(userid);
    }

    r = mboxname_lock(mailbox->name, &listitem->l, locktype);
    if (r) return r;

    return r;
}

/*
 * Open and read the header of the mailbox with name 'name'
 * The structure pointed to by 'mailbox' is initialized.
 */
static int mailbox_open_advanced(const char *name,
                                 int locktype,
                                 int index_locktype,
                                 struct mailbox **mailboxptr)
{
    mbentry_t *mbentry = NULL;
    struct mailboxlist *listitem;
    struct mailbox *mailbox = NULL;
    int r = 0;

    assert(*mailboxptr == NULL);

    listitem = find_listitem(name);

    /* already open?  just use this one */
    if (listitem) {
        /* can't reuse an exclusive locked mailbox */
        if (listitem->l->locktype == LOCK_EXCLUSIVE)
            return IMAP_MAILBOX_LOCKED;
        if (locktype == LOCK_EXCLUSIVE)
            return IMAP_MAILBOX_LOCKED;
        /* can't reuse an already locked index */
        if (listitem->m.index_locktype)
            return IMAP_MAILBOX_LOCKED;

        listitem->nopen++;
        mailbox = &listitem->m;

        goto lockindex;
    }

    listitem = create_listitem(name);
    mailbox = &listitem->m;

    // lock the user namespace FIRST before the mailbox namespace
    char *userid = mboxname_to_userid(name);
    if (userid) {
        int haslock = user_isnamespacelocked(userid);
        if (haslock) {
            if (index_locktype != LOCK_SHARED) assert(haslock != LOCK_SHARED);
        }
        else {
            int locktype = index_locktype;
            mailbox->local_namespacelock = user_namespacelock_full(userid, locktype);
        }
        free(userid);
    }

    r = mboxname_lock(name, &listitem->l, locktype);
    if (r) {
        /* locked is not an error - just means we asked for NONBLOCKING */
        if (r != IMAP_MAILBOX_LOCKED)
            xsyslog(LOG_ERR, "IOERROR: lock failed",
                             "mailbox=<%s> error=<%s>",
                             mailbox->name, error_message(r));
        goto done;
    }

    r = mboxlist_lookup_allow_all(name, &mbentry, NULL);
    if (r) goto done;

    if (mbentry->mbtype & MBTYPE_MOVING) {
        mboxlist_entry_free(&mbentry);
        r = IMAP_MAILBOX_MOVED;
        goto done;
    }

    if (!mbentry->partition) {
        mboxlist_entry_free(&mbentry);
        r = IMAP_MAILBOX_NONEXISTENT;
        goto done;
    }

    mailbox->part = xstrdup(mbentry->partition);

    /* Note that the header does have the uniqueid and ACL information,
     * but it is only backup, and the mboxlist data is considered authoritative,
     * so we will just use what we were passed */
    mailbox->uniqueid = xstrdup(mbentry->uniqueid);
    mailbox->acl = xstrdup(mbentry->acl);
    mailbox->mbtype = mbentry->mbtype;
    mailbox->foldermodseq = mbentry->foldermodseq;

    mboxlist_entry_free(&mbentry);

    if (index_locktype == LOCK_SHARED)
        mailbox->is_readonly = 1;

    r = mailbox_open_index(mailbox);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: opening index failed",
                         "mailbox=<%s> error=<%s>",
                         mailbox->name, error_message(r));
        goto done;
    }

lockindex:
    r = mailbox_lock_index(mailbox, index_locktype);

    /* we always nuke expunged if the version is less than 12 */
    if (mailbox->i.minor_version < 12)
        cleanup_stale_expunged(mailbox);

done:
    if (r) mailbox_close(&mailbox);
    else *mailboxptr = mailbox;

    return r;
}

EXPORTED int mailbox_open_irl(const char *name, struct mailbox **mailboxptr)
{
    return mailbox_open_advanced(name, LOCK_SHARED, LOCK_SHARED,
                                 mailboxptr);
}

EXPORTED int mailbox_open_iwl(const char *name, struct mailbox **mailboxptr)
{
    return mailbox_open_advanced(name, LOCK_SHARED, LOCK_EXCLUSIVE,
                                 mailboxptr);
}

EXPORTED int mailbox_open_irlnb(const char *name, struct mailbox **mailboxptr)
{
    return mailbox_open_advanced(name,
                                 LOCK_SHARED|LOCK_NONBLOCK,
                                 /* cannot do nonblocking lock on index...why? */
                                 LOCK_SHARED,
                                 mailboxptr);
}

EXPORTED int mailbox_open_exclusive(const char *name, struct mailbox **mailboxptr)
{
    return mailbox_open_advanced(name, LOCK_EXCLUSIVE, LOCK_EXCLUSIVE,
                                 mailboxptr);
}

EXPORTED void mailbox_index_dirty(struct mailbox *mailbox)
{
    assert(mailbox_index_islocked(mailbox, 1));
    mailbox->i.dirty = 1;
}

EXPORTED modseq_t mailbox_modseq_dirty(struct mailbox *mailbox)
{
    assert(mailbox_index_islocked(mailbox, 1));

    if (mailbox->silentchanges) {
        mailbox->modseq_dirty = 1;
        mailbox_index_dirty(mailbox);
        return mailbox->i.highestmodseq;
    }

    if (!mailbox->modseq_dirty) {
        mailbox->i.highestmodseq = mboxname_setmodseq(mailbox->name,
                                   mailbox->i.highestmodseq,
                                   mailbox->mbtype, /*flags*/0);
        mailbox->last_updated = time(0);
        mailbox->modseq_dirty = 1;
        mailbox_index_dirty(mailbox);
    }

    mailbox->i.highestmodseq++;

    return mailbox->i.highestmodseq;
}

EXPORTED int mailbox_setversion(struct mailbox *mailbox, int version)
{
    int r = 0;

    if (version && mailbox->i.minor_version != version) {
        /* need to re-set the version! */
        struct mailboxlist *listitem = find_listitem(mailbox->name);

        assert(listitem);
        assert(&listitem->m == mailbox);

        /* we need an exclusive lock on the listitem because we're renaming
         * index files, so release locks and then go full exclusive */
        mailbox_unlock_index(mailbox, NULL);
        r = mailbox_mboxlock_reopen(listitem, LOCK_EXCLUSIVE, LOCK_EXCLUSIVE);

        /* we need to re-open the index because we dropped the mboxname lock,
         * so the file may have changed */
        if (!r) r = mailbox_open_index(mailbox);

        /* lock_internal so DELETED doesn't cause it to appear to be
         * NONEXISTENT */
        if (!r) r = mailbox_lock_index_internal(mailbox, LOCK_EXCLUSIVE);

        /* perform the actual repack! */
        if (!r) r = mailbox_index_repack(mailbox, version);

        /* NOTE: this leaves the mailbox in an unlocked state internally, so
         * let's release all the acutal locks */
        mailbox_unlock_index(mailbox, NULL);

        /* we're also still holding an exclusive namelock in the listitem,
         * but that's OK because the only caller will be calling mailbox_close
         * immediately afterwards */
    }

    return r;
}

/*
 * Close the mailbox 'mailbox', freeing all associated resources.
 */
EXPORTED void mailbox_close(struct mailbox **mailboxptr)
{
    int flag;
    struct mailbox *mailbox = *mailboxptr;
    struct mailboxlist *listitem;

    /* be safe against double-close */
    if (!mailbox) return;

    listitem = find_listitem(mailbox->name);
    assert(listitem && &listitem->m == mailbox);

    *mailboxptr = NULL;

    /* open multiple times?  Just close this one */
    if (listitem->nopen > 1) {
        listitem->nopen--;
        mailbox_unlock_index(mailbox, NULL);
        return;
    }

    int was_ro = !mailbox_index_islocked(mailbox, /*write*/1);

    /* get a re-read of the options field for cleanup purposes */
    if (mailbox->index_fd != -1) {
        /* drop the index lock here because we'll lose our right to it
         * when try to upgrade the mboxlock anyway. */
        mailbox_unlock_index(mailbox, NULL);
    }

    int need_cleanup = 0;
    if (mailbox->i.options & OPT_MAILBOX_DELETED) {
        // we ALWAYS cleanup deleted
        need_cleanup = 1;
    }
    else if (!was_ro && !in_shutdown && (mailbox->i.options & MAILBOX_CLEANUP_MASK)) {
        need_cleanup = 1;
    }

    /* do we need to try and clean up? (not if doing a shutdown,
     * speed is probably more important!) */
    if (need_cleanup) {
        int locktype = LOCK_NONBLOCKING;
        /* if we deleted the mailbox we MUST clean it up or the files will leak,
         * so wait until the other locks are cleared */
        if (mailbox->i.options & OPT_MAILBOX_DELETED) locktype = LOCK_EXCLUSIVE;
        int r = mailbox_mboxlock_reopen(listitem, locktype, LOCK_EXCLUSIVE);
        /* we need to re-open the index because we dropped the mboxname lock,
         * so the file may have changed */
        if (!r) r = mailbox_open_index(mailbox);
        /* lock_internal so DELETED doesn't cause it to appear to be
         * NONEXISTENT - but we still need conversations so we can write changes! */
        if (!r) r = mailbox_lock_index_internal(mailbox, LOCK_EXCLUSIVE);
        if (!r) {
            /* finish cleaning up */
            if (mailbox->i.options & OPT_MAILBOX_DELETED)
                mailbox_delete_cleanup(mailbox, mailbox->part, mailbox->name,
                                       (mailbox->mbtype & MBTYPE_LEGACY_DIRS) ?
                                       NULL : mailbox->uniqueid);
            else if (mailbox->i.options & OPT_MAILBOX_NEEDS_REPACK)

                mailbox_index_repack(mailbox, mailbox->i.minor_version);
            else if (mailbox->i.options & OPT_MAILBOX_NEEDS_UNLINK)
                mailbox_index_unlink(mailbox);
            /* or we missed out - someone else beat us to it */

            /* anyway, unlock again */
            mailbox_unlock_index(mailbox, NULL);
        }
        /* otherwise someone else has the mailbox locked
         * already, so they can handle the cleanup in
         * THEIR mailbox_close call */
    }

    mailbox_release_resources(mailbox);

    free(mailbox->name);
    free(mailbox->part);
    free(mailbox->acl);
    free(mailbox->uniqueid);
    free(mailbox->quotaroot);

    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
        free(mailbox->flagname[flag]);
    }

    if (listitem->l) mboxname_release(&listitem->l);

    if (mailbox->local_namespacelock)
        mboxname_release(&mailbox->local_namespacelock);

    remove_listitem(listitem);
}

struct parseentry_rock {
    struct mailbox *mailbox;
    struct buf *aclbuf;
    int doingacl;
    int doingflags;
    int nflags;
};

static int parseentry_cb(int type, struct dlistsax_data *d)
{
    struct parseentry_rock *rock = (struct parseentry_rock *)d->rock;

    switch(type) {
    case DLISTSAX_KVLISTSTART:
        if (!strcmp(buf_cstring(&d->kbuf), "A")) {
            rock->doingacl = 1;
        }
        break;
    case DLISTSAX_KVLISTEND:
        if (rock->doingacl) {
            rock->doingacl = 0;
        }
        break;
    case DLISTSAX_LISTSTART:
        if (!strcmp(buf_cstring(&d->kbuf), "U")) {
            rock->doingflags = 1;
        }
        break;
    case DLISTSAX_LISTEND:
        if (rock->doingflags) {
            rock->doingflags = 0;

            /* zero out the rest */
            for (; rock->nflags < MAX_USER_FLAGS; rock->nflags++) {
                free(rock->mailbox->flagname[rock->nflags]);
                rock->mailbox->flagname[rock->nflags] = NULL;
            }
        }
        break;
    case DLISTSAX_STRING:
        if (rock->doingacl) {
            if (rock->aclbuf) {
                buf_append(rock->aclbuf, &d->kbuf);
                buf_putc(rock->aclbuf, '\t');
                buf_appendcstr(rock->aclbuf, d->data);
                buf_putc(rock->aclbuf, '\t');
            }
        }
        else if (rock->doingflags) {
            free(rock->mailbox->flagname[rock->nflags]);
            rock->mailbox->flagname[rock->nflags++] = xstrdupnull(d->data);
        }
        else {
            const char *key = buf_cstring(&d->kbuf);
            if (!strcmp(key, "I")) {
                if (!rock->mailbox->uniqueid)
                    rock->mailbox->uniqueid = xstrdupnull(d->data);
            }
            else if (!strcmp(key, "N")) {
                if (!rock->mailbox->name)
                    rock->mailbox->name = xstrdupnull(d->data);
            }
            else if (!strcmp(key, "T")) {
                rock->mailbox->mbtype = mboxlist_string_to_mbtype(d->data);
            }
            else if (!strcmp(key, "Q")) {
                free(rock->mailbox->quotaroot);
                rock->mailbox->quotaroot = xstrdupnull(d->data);
            }
        }
    }

    return 0;
}

/*
 * parse data read from cyrus.header into its parts.
 *
 * full dlist format is:
 *  A: _a_cl
 *  I: unique_i_d
 *  N: _n_ame
 *  Q: _q_uotaroot
 *  T: _t_ype
 *  U: user_f_lags
 */
static int mailbox_parse_header_data(struct mailbox *mailbox,
                                     const char *data, size_t datalen,
                                     char **aclptr)
{
    static struct buf aclbuf;

    if (!datalen) return IMAP_MAILBOX_BADFORMAT;

    struct parseentry_rock rock;
    memset(&rock, 0, sizeof(struct parseentry_rock));
    rock.mailbox = mailbox;
    if (aclptr) {
        rock.aclbuf = &aclbuf;
        buf_reset(&aclbuf);
    }

    int r = dlist_parsesax(data, datalen, 0, parseentry_cb, &rock);
    if (!r && aclptr) *aclptr = buf_newcstring(&aclbuf);

    return r;
}

/*
 * Read the header of 'mailbox'
 * new format:
 * MAGIC
 * dlist (see above)
 *
 * old format:
 * MAGIC
 * quotaroot TAB uniqueid
 * userflag1 SPACE userflag2 SPACE userflag3 [...] (with no trailing space)
 * user1 TAB user1acl TAB user2 TAB user2acl TAB (with trailing tab!)
 */
static int mailbox_read_header(struct mailbox *mailbox, char **aclptr)
{
    int r = 0;
    int flag;
    const char *name, *p, *tab, *eol;
    const char *fname;
    struct stat sbuf;
    const char *base = NULL;
    size_t len = 0;
    unsigned magic_size = sizeof(MAILBOX_HEADER_MAGIC) - 1;

    /* can't be dirty if we're reading it */
    if (mailbox->header_dirty)
        abort();

    xclose(mailbox->header_fd);

    fname = mailbox_meta_fname(mailbox, META_HEADER);
    mailbox->header_fd = open(fname, O_RDONLY, 0);

    if (mailbox->header_fd == -1) {
        r = IMAP_IOERROR;
        goto done;
    }

    if (fstat(mailbox->header_fd, &sbuf) == -1) {
        xclose(mailbox->header_fd);
        r = IMAP_IOERROR;
        goto done;
    }

    map_refresh(mailbox->header_fd, 1, &base, &len,
                sbuf.st_size, "header", mailbox->name);
    mailbox->header_file_ino = sbuf.st_ino;
    mailbox->header_file_crc = crc32_map(base, sbuf.st_size);

    /* Check magic number */
    if ((unsigned) sbuf.st_size < magic_size ||
        strncmp(base, MAILBOX_HEADER_MAGIC, magic_size)) {
        r = IMAP_MAILBOX_BADFORMAT;
        goto done;
    }

    /* Read quota data line */
    p = base + sizeof(MAILBOX_HEADER_MAGIC)-1;
    tab = memchr(p, '\t', sbuf.st_size - (p - base));
    eol = memchr(p, '\n', sbuf.st_size - (p - base));
    if (!eol) {
        r = IMAP_MAILBOX_BADFORMAT;
        goto done;
    }

    free(mailbox->quotaroot);
    mailbox->quotaroot = NULL;
    free(mailbox->uniqueid);
    mailbox->uniqueid = NULL;

    /* check for DLIST mboxlist */
    if (*p == '%') {
        r = mailbox_parse_header_data(mailbox, p, eol - p, aclptr);
        goto done;
    }

    /* quotaroot (if present) */
    if (!tab || tab > eol) {
        syslog(LOG_DEBUG, "mailbox '%s' has old cyrus.header",
               mailbox->name);
        tab = eol;
    }
    if (p < tab) {
        mailbox->quotaroot = xstrndup(p, tab - p);
    }

    /* read uniqueid (should always exist unless old format) */
    if (tab < eol) {
        p = tab + 1;
        if (p == eol) {
            r = IMAP_MAILBOX_BADFORMAT;
            goto done;
        }
        tab = memchr(p, '\t', sbuf.st_size - (p - base));
        if (!tab || tab > eol) tab = eol;
        mailbox->uniqueid = xstrndup(p, tab - p);
    }
    /* else, uniqueid needs to be generated when we know the uidvalidity */

    /* Read names of user flags */
    p = eol + 1;
    eol = memchr(p, '\n', sbuf.st_size - (p - base));
    if (!eol) {
        r = IMAP_MAILBOX_BADFORMAT;
        goto done;
    }
    name = p;
    /* read the names of flags */
    for (flag = 0; name <= eol && flag < MAX_USER_FLAGS; flag++) {
        free(mailbox->flagname[flag]);
        mailbox->flagname[flag] = NULL;
        p = memchr(name, ' ', eol-name);
        if (!p) p = eol;
        if (name != p)
            mailbox->flagname[flag] = xstrndup(name, p-name);
        name = p+1;
    }
    /* zero out the rest */
    for (; flag < MAX_USER_FLAGS; flag++) {
        free(mailbox->flagname[flag]);
        mailbox->flagname[flag] = NULL;
    }

    /* Read ACL */
    p = eol + 1;
    eol = memchr(p, '\n', sbuf.st_size - (p - base));
    if (!eol) {
        r = IMAP_MAILBOX_BADFORMAT;
        goto done;
    }

    if (aclptr)
        *aclptr = xstrndup(p, eol-p);

done:
    if (base) map_free(&base, &len);
    return r;
}

/* set a new ACL - only dirty if changed */
EXPORTED int mailbox_set_acl(struct mailbox *mailbox, const char *acl)
{
    if (!strcmpsafe(mailbox->acl, acl))
        return 0; /* no change */
    free(mailbox->acl);
    mailbox->acl = xstrdup(acl);
    mailbox->header_dirty = 1;
    return 0;
}

/* set a new QUOTAROOT - only dirty if changed */
EXPORTED int mailbox_set_quotaroot(struct mailbox *mailbox, const char *quotaroot)
{
    if (mailbox->quotaroot) {
        if (quotaroot && !strcmp(mailbox->quotaroot, quotaroot))
            return 0; /* no change */
        free(mailbox->quotaroot);
        mailbox->quotaroot = NULL;
    }
    else {
        if (!quotaroot)
            return 0; /* no change */
    }

    if (quotaroot)
        mailbox->quotaroot = xstrdup(quotaroot);

    /* either way, it's changed, so dirty */
    mailbox->header_dirty = 1;

    return 0;
}

static int _too_many_flags(const char *flag, int num)
{
    if (num < 100) return 0;
    if (num >= MAX_USER_FLAGS) return 1;
    int too_many = 1;

    /* check if this is a required user flag */
    const char *val = config_getstring(IMAPOPT_MAILBOX_INITIAL_FLAGS);
    if (val) {
        strarray_t *flags = strarray_split(val, NULL, 0);
        // it's not too many if there's still space and it's an initial flag
        if (strarray_find_case(flags, flag, 0) >= 0)
            too_many = 0;
        strarray_free(flags);
    }

    return too_many;
}

/* find or create a user flag - dirty header if change needed.  If 'create'
 * is 1, then only 100 flags may be created.  If >1, then you can use all 128 */
EXPORTED int mailbox_user_flag(struct mailbox *mailbox, const char *flag,
                      int *flagnum, int create)
{
    int userflag;
    int emptyflag = -1;

    for (userflag = 0; userflag < MAX_USER_FLAGS; userflag++) {
        if (mailbox->flagname[userflag]) {
            if (!strcasecmp(flag, mailbox->flagname[userflag]))
                break;
        }
        else if (emptyflag == -1) {
            emptyflag = userflag;
        }
    }

    if (userflag == MAX_USER_FLAGS) {
        if (!create)
            return IMAP_NOTFOUND;

        if (emptyflag == -1)
            return IMAP_USERFLAG_EXHAUSTED;

        /* stop imapd exhausting flags */
        if (create == 1 && _too_many_flags(flag, emptyflag)) {
            xsyslog(LOG_ERR, "IOERROR: out of flags",
                             "mailbox=<%s> flag=<%s>",
                             mailbox->name, flag);
            return IMAP_USERFLAG_EXHAUSTED;
        }

        /* need to be index locked to make flag changes */
        if (!mailbox_index_islocked(mailbox, 1))
            return IMAP_MAILBOX_LOCKED;

        if (!imparse_isatom(flag))
            return IMAP_INVALID_IDENTIFIER;

        /* set the flag and mark the header dirty */
        userflag = emptyflag;
        mailbox->flagname[userflag] = xstrdup(flag);
        mailbox->header_dirty = 1;
    }

    if (flagnum) *flagnum = userflag;

    return 0;
}

/* Remove a user flag from the mailbox, so that the slot can
 * be reused.  Called from cyr_expire when we've made certain
 * that no record uses the flag anymore. */
EXPORTED int mailbox_remove_user_flag(struct mailbox *mailbox, int flagnum)
{
    if (flagnum < 0 || flagnum >= MAX_USER_FLAGS)
        return IMAP_INTERNAL;   /* invalid flag number */

    if (!mailbox->flagname[flagnum])
        return 0;               /* already gone */

    /* need to be index locked to make flag changes */
    if (!mailbox_index_islocked(mailbox, 1))
        return IMAP_MAILBOX_LOCKED;

    free(mailbox->flagname[flagnum]);
    mailbox->flagname[flagnum] = NULL;
    mailbox->header_dirty = 1;
    return 0;
}

EXPORTED int mailbox_record_hasflag(struct mailbox *mailbox,
                           const struct index_record *record,
                           const char *flag)
{
    int userflag;

    if (!mailbox) return 0;
    if (!flag) return 0;
    if (!record) return 0;

    if (flag[0] == '\\') {
        if (!strcasecmp(flag, "\\answered"))
            return ((record->system_flags & FLAG_ANSWERED) ? 1 : 0);
        if (!strcasecmp(flag, "\\deleted"))
            return ((record->system_flags & FLAG_DELETED) ? 1 : 0);
        if (!strcasecmp(flag, "\\draft"))
            return ((record->system_flags & FLAG_DRAFT) ? 1 : 0);
        if (!strcasecmp(flag, "\\flagged"))
            return ((record->system_flags & FLAG_FLAGGED) ? 1 : 0);
        if (!strcasecmp(flag, "\\seen")) {
            /* NOTE: this is a special case because it depends
             * who the userid is.  We will only return the user
             * or global seen value */
            return ((record->system_flags & FLAG_SEEN) ? 1 : 0);
        }
        /* unknown system flag is never present */
        return 0;
    }

    if (mailbox_user_flag(mailbox, flag, &userflag, 0))
        return 0;

    return ((record->user_flags[userflag/32] & (1<<(userflag&31))) ? 1 : 0);
}

EXPORTED strarray_t *mailbox_extract_flags(const struct mailbox *mailbox,
                                           const struct index_record *record,
                                           const char *userid)
{
    int i;
    strarray_t *flags = strarray_new();

    /* Note: we don't handle the external seen db here, on
     * the grounds that it would add complexity without
     * actually being useful to annotators */
    if (mailbox_internal_seen(mailbox, userid) && (record->system_flags & FLAG_SEEN))
        strarray_append(flags, "\\Seen");

    if ((record->system_flags & FLAG_DELETED))
        strarray_append(flags, "\\Deleted");
    if ((record->system_flags & FLAG_DRAFT))
        strarray_append(flags, "\\Draft");
    if ((record->system_flags & FLAG_FLAGGED))
        strarray_append(flags, "\\Flagged");
    if ((record->system_flags & FLAG_ANSWERED))
        strarray_append(flags, "\\Answered");

    for (i = 0 ; i < MAX_USER_FLAGS ; i++) {
        if (mailbox->flagname[i] &&
            (record->user_flags[i/32] & 1<<(i&31)))
            strarray_append(flags, mailbox->flagname[i]);
    }

    return flags;
}

static int load_annot_cb(const char *mailbox __attribute__((unused)),
                         uint32_t uid __attribute__((unused)),
                         const char *entry, const char *userid,
                         const struct buf *value,
                         const struct annotate_metadata *mdata __attribute__((unused)),
                         void *rock)
{
    struct entryattlist **eal = (struct entryattlist **)rock;
    const char *attrib = (userid[0] ? "value.priv" : "value.shared");
    setentryatt(eal, entry, attrib, value);
    return 0;
}

EXPORTED struct entryattlist *mailbox_extract_annots(const struct mailbox *mailbox,
                                                     const struct index_record *record)
{
    struct entryattlist *annots = NULL;
    int r = annotatemore_findall(mailbox->name, record->uid, "*", /*modseq*/0,
                                 load_annot_cb, &annots, /*flags*/0);
    if (r) return NULL;
    return annots;
}

static int mailbox_buf_to_index_header(const char *buf, size_t len,
                                       struct index_header *i)
{
    uint32_t crc;
    bit32 qannot;
    size_t headerlen;

    if (len < OFFSET_MINOR_VERSION+4)
        return IMAP_MAILBOX_BADFORMAT;

    memset(i, 0, sizeof(struct index_header));

    i->generation_no = ntohl(*((bit32 *)(buf+OFFSET_GENERATION_NO)));
    i->format = ntohl(*((bit32 *)(buf+OFFSET_FORMAT)));
    i->minor_version = ntohl(*((bit32 *)(buf+OFFSET_MINOR_VERSION)));
    switch (i->minor_version) {
    case 6:
    case 7:
        headerlen = 76;
        break;
    case 8:
        headerlen = 92;
        break;
    case 9:
    case 10:
        headerlen = 96;
        break;
    case 12:
    case 13:
        headerlen = 128;
        break;
    case 14:
    case 15:
    case 16:
    case 17:
        headerlen = 160;
        break;
    default:
        return IMAP_MAILBOX_BADFORMAT;
    }
    if (len < headerlen)
        return IMAP_MAILBOX_BADFORMAT;

    i->start_offset = ntohl(*((bit32 *)(buf+OFFSET_START_OFFSET)));
    i->record_size = ntohl(*((bit32 *)(buf+OFFSET_RECORD_SIZE)));
    i->num_records = ntohl(*((bit32 *)(buf+OFFSET_NUM_RECORDS)));
    i->last_appenddate = ntohl(*((bit32 *)(buf+OFFSET_LAST_APPENDDATE)));
    i->last_uid = ntohl(*((bit32 *)(buf+OFFSET_LAST_UID)));
    i->quota_mailbox_used = align_ntohll(buf+OFFSET_QUOTA_MAILBOX_USED);
    i->pop3_last_login = ntohl(*((bit32 *)(buf+OFFSET_POP3_LAST_LOGIN)));
    i->uidvalidity = ntohl(*((bit32 *)(buf+OFFSET_UIDVALIDITY)));
    i->deleted = ntohl(*((bit32 *)(buf+OFFSET_DELETED)));
    i->answered = ntohl(*((bit32 *)(buf+OFFSET_ANSWERED)));
    i->flagged = ntohl(*((bit32 *)(buf+OFFSET_FLAGGED)));
    i->options = ntohl(*((bit32 *)(buf+OFFSET_MAILBOX_OPTIONS)));
    i->leaked_cache_records = ntohl(*((bit32 *)(buf+OFFSET_LEAKED_CACHE)));
    if (i->minor_version < 8) goto done;

    i->highestmodseq = align_ntohll(buf+OFFSET_HIGHESTMODSEQ);
    if (i->minor_version < 12) goto done;

    i->deletedmodseq = align_ntohll(buf+OFFSET_DELETEDMODSEQ);
    i->exists = ntohl(*((bit32 *)(buf+OFFSET_EXISTS)));
    i->first_expunged = ntohl(*((bit32 *)(buf+OFFSET_FIRST_EXPUNGED)));
    i->last_repack_time = ntohl(*((bit32 *)(buf+OFFSET_LAST_REPACK_TIME)));
    i->header_file_crc = ntohl(*((bit32 *)(buf+OFFSET_HEADER_FILE_CRC)));
    i->synccrcs.basic = ntohl(*((bit32 *)(buf+OFFSET_SYNCCRCS_BASIC)));
    i->recentuid = ntohl(*((bit32 *)(buf+OFFSET_RECENTUID)));
    i->recenttime = ntohl(*((bit32 *)(buf+OFFSET_RECENTTIME)));

    if (i->minor_version < 13) goto crc;

    i->pop3_show_after = ntohl(*((bit32 *)(buf+OFFSET_POP3_SHOW_AFTER)));
    qannot = ntohl(*((bit32 *)(buf+OFFSET_QUOTA_ANNOT_USED)));
    /* this field is stored as a 32b unsigned on disk but 64b signed
     * in memory, so we need to be careful about sign extension */
    i->quota_annot_used = (quota_t)((unsigned long long)qannot);
    i->synccrcs.annot = ntohl(*((bit32 *)(buf+OFFSET_SYNCCRCS_ANNOT)));

    if (i->minor_version < 14) goto crc;

    i->unseen = ntohl(*((bit32 *)(buf+OFFSET_UNSEEN)));

    if (i->minor_version < 16) goto crc;

    i->createdmodseq = align_ntohll(buf+OFFSET_MAILBOX_CREATEDMODSEQ);

    if (i->minor_version < 17) goto crc;

    i->changes_epoch = ntohl(*((bit32 *)(buf+OFFSET_CHANGES_EPOCH)));

crc:
    /* CRC is always the last 4 bytes */
    crc = ntohl(*((bit32 *)(buf+headerlen-4)));
    if (crc != crc32_map(buf, headerlen-4))
        return IMAP_MAILBOX_CHECKSUM;

done:
    if (!i->exists)
        i->options |= OPT_POP3_NEW_UIDL;

    if (!i->highestmodseq)
        i->highestmodseq = 1;

    if (i->minor_version < 12) {
        i->deletedmodseq = i->highestmodseq;
        i->exists = i->num_records;
    }

    if (i->minor_version < 17) {
        i->changes_epoch = i->last_repack_time ? i->last_repack_time : time(0);
    }

    return 0;
}

static int mailbox_refresh_index_map(struct mailbox *mailbox)
{
    size_t need_size;
    struct stat sbuf;

    /* check if we need to extend the mmaped space for the index file
     * (i.e. new records appended since last read) */
    need_size = mailbox->i.start_offset +
                mailbox->i.num_records * mailbox->i.record_size;
    if (mailbox->index_size < need_size) {
        if (fstat(mailbox->index_fd, &sbuf) == -1)
            return IMAP_IOERROR;

        if (sbuf.st_size < (int)need_size)
            return IMAP_MAILBOX_BADFORMAT;

        mailbox->index_size = sbuf.st_size;

    }

    /* always refresh, we may be using map_nommap */
    map_refresh(mailbox->index_fd, 1, &mailbox->index_base,
                &mailbox->index_len, mailbox->index_size,
                "index", mailbox->name);

    return 0;
}

static int mailbox_read_index_header(struct mailbox *mailbox)
{
    int r;

    /* no dirty mailboxes please */
    if (mailbox->i.dirty)
        abort();

    /* need to be locked to ensure a consistent read - otherwise
     * a busy mailbox will get CRC errors due to rewrite happening
     * under our feet! */
    if (!mailbox_index_islocked(mailbox, 0))
        return IMAP_MAILBOX_LOCKED;

    /* and of course it needs to exist and have at least enough
     * header to read the version number */
    if (!mailbox->index_base)
        return IMAP_MAILBOX_BADFORMAT;

    /* need to make sure we're reading fresh data! */
    map_refresh(mailbox->index_fd, 1, &mailbox->index_base,
                &mailbox->index_len, mailbox->index_size,
                "index", mailbox->name);

    r = mailbox_buf_to_index_header(mailbox->index_base, mailbox->index_len,
                                    &mailbox->i);
    if (r) return r;

    r = mailbox_refresh_index_map(mailbox);
    if (r) return r;

    return 0;
}

/*
 * Read an index record from a mapped index file
 */
#ifdef HAVE_DECLARE_OPTIMIZE
static int mailbox_buf_to_index_record(const char *buf, int version,
                                       struct index_record *record, int dirty)
    __attribute__((optimize("-O3")));
#endif
static int mailbox_buf_to_index_record(const char *buf, int version,
                                       struct index_record *record, int dirty)
{
    uint32_t crc;
    uint32_t stored_system_flags = 0;
    int n;

    /* tracking fields - initialise */
    memset(record, 0, sizeof(struct index_record));

    /* parse the shared bits first */
    record->uid = ntohl(*((bit32 *)(buf+OFFSET_UID)));
    record->internaldate = ntohl(*((bit32 *)(buf+OFFSET_INTERNALDATE)));
    record->sentdate = ntohl(*((bit32 *)(buf+OFFSET_SENTDATE)));
    record->size = ntohl(*((bit32 *)(buf+OFFSET_SIZE)));
    record->header_size = ntohl(*((bit32 *)(buf+OFFSET_HEADER_SIZE)));
    record->gmtime = ntohl(*((bit32 *)(buf+OFFSET_GMTIME)));
    uint64_t cache_offset_field = ntohl(*((bit32 *)(buf+OFFSET_CACHE_OFFSET)));
    record->last_updated = ntohl(*((bit32 *)(buf+OFFSET_LAST_UPDATED)));
    stored_system_flags = ntohl(*((bit32 *)(buf+OFFSET_SYSTEM_FLAGS)));

    /* de-serialise system flags and internal flags */
    record->system_flags = stored_system_flags & 0x000000ff;
    record->internal_flags = stored_system_flags & 0xff000000;

    for (n = 0; n < MAX_USER_FLAGS/32; n++) {
        record->user_flags[n] = ntohl(*((bit32 *)(buf+OFFSET_USER_FLAGS+4*n)));
    }
    uint64_t cache_version_field = ntohl(*((bit32 *)(buf+OFFSET_CACHE_VERSION)));

    /* keep the low bits of the version field for the version */
    record->cache_version = cache_version_field & 0xffff;
    /* use the high bits of the version field to extend the cache offset */
    record->cache_offset = cache_offset_field | ((cache_version_field & 0xffff0000) << 16);

    if (version < 8)
        return 0;

    if (version < 10) {
        /* modseq was at 72 before the GUID move */
        record->modseq = ntohll(*((bit64 *)(buf+72)));
        return 0;
    }

    message_guid_import(&record->guid, buf+OFFSET_MESSAGE_GUID);
    record->modseq = ntohll(*((bit64 *)(buf+OFFSET_MODSEQ)));
    if (version < 12)
        return 0;

    /* THRID got inserted before cache_crc32 in version 12 */
    if (version < 13) {
        record->cache_crc = ntohl(*((bit32 *)(buf+88)));

        if (dirty) return 0;
        /* check CRC32 */
        crc = crc32_map(buf, 92);
        if (crc != ntohl(*((bit32 *)(buf+92))))
            return IMAP_MAILBOX_CHECKSUM;
        return 0;
    }

    record->cid = ntohll(*(bit64 *)(buf+OFFSET_THRID));
    if (version > 14) {
        record->savedate = ntohl(*((bit32 *)(buf+OFFSET_SAVEDATE)));
    }

    /* createdmodseq was added in version 16, pushing the CRCs down */
    if (version < 16) {
        record->cache_crc = ntohl(*((bit32 *)(buf+96)));

        if (dirty) return 0;
        /* check CRC32 */
        crc = crc32_map(buf, 100);
        if (crc != ntohl(*((bit32 *)(buf+100))))
            return IMAP_MAILBOX_CHECKSUM;
        return 0;
    }

    record->createdmodseq = ntohll(*(bit64 *)(buf+OFFSET_CREATEDMODSEQ));
    record->cache_crc = ntohl(*((bit32 *)(buf+OFFSET_CACHE_CRC)));

    if (dirty) return 0;
    /* check CRC32 */
    crc = crc32_map(buf, OFFSET_RECORD_CRC);
    if (crc != ntohl(*((bit32 *)(buf+OFFSET_RECORD_CRC))))
        return IMAP_MAILBOX_CHECKSUM;

    return 0;
}

static struct index_change *_find_change(struct mailbox *mailbox, uint32_t recno)
{
    uint32_t changeno = mailbox->index_change_map[recno % INDEX_MAP_SIZE];

    while (changeno) {
        if (mailbox->index_changes[changeno-1].record.recno == recno)
            return &mailbox->index_changes[changeno-1];
        changeno = mailbox->index_changes[changeno-1].mapnext;
    }

    return NULL;
}

static int _store_change(struct mailbox *mailbox, struct index_record *record, int flags)
{
    struct index_change *change = _find_change(mailbox, record->recno);

    if (!change) {
        mailbox->index_change_count++;

        /* allocate a space if required */
        if (mailbox->index_change_count > mailbox->index_change_alloc) {
            mailbox->index_change_alloc += 256;
            mailbox->index_changes = xrealloc(mailbox->index_changes, sizeof(struct index_change) * mailbox->index_change_alloc);
        }

        change = &mailbox->index_changes[mailbox->index_change_count-1];
        memset(change, 0, sizeof(struct index_change));

        /* stitch into place */
        uint32_t pos = record->recno % INDEX_MAP_SIZE;
        change->mapnext = mailbox->index_change_map[pos];
        mailbox->index_change_map[pos] = mailbox->index_change_count; /* always non-zero */
    }

    /* finally always copy the data into place */
    change->record = *record;
    change->flags = flags;

    if (mailbox_cacherecord(mailbox, record)) {
        /* failed to load cache record */
        free(change->msgid);
        change->msgid = xstrdup("unknown");
    }
    else {
        char *c_env = xstrndup(cacheitem_base(record, CACHE_ENVELOPE) + 1,
                               cacheitem_size(record, CACHE_ENVELOPE) - 2);
        char *envtokens[NUMENVTOKENS];
        parse_cached_envelope(c_env, envtokens, NUMENVTOKENS);
        free(change->msgid);
        change->msgid = xstrdup(envtokens[ENV_MSGID] ? envtokens[ENV_MSGID] : "unknown");
        free(c_env);
    }

    annotate_state_t *astate = NULL;
    int r = mailbox_get_annotate_state(mailbox, record->uid, &astate);
    if (r) return r;

    struct buf annotval = BUF_INITIALIZER;
    if (record->cid && record->basecid && record->basecid != record->cid)
        buf_printf(&annotval, "%016llx", record->basecid);

    r = annotate_state_writesilent(astate, IMAP_ANNOT_NS "basethrid", "", &annotval);
    buf_free(&annotval);

    if (r) return r;

    return 0;
}

static int _commit_one(struct mailbox *mailbox, struct index_change *change)
{
    indexbuffer_t ibuf;
    unsigned char *buf = ibuf.buf;
    size_t offset;
    struct index_record *record = &change->record;
    uint32_t recno = record->recno;

    mailbox_index_record_to_buf(&change->record, mailbox->i.minor_version, buf);

    offset = mailbox->i.start_offset + ((recno-1) * mailbox->i.record_size);

    /* any failure here is a disaster! */
    if (lseek(mailbox->index_fd, offset, SEEK_SET) == -1) {
        xsyslog(LOG_ERR, "IOERROR: seeking index record failed",
                         "mailbox=<%s> record=<%u>",
                         mailbox->name, recno);
        return IMAP_IOERROR;
    }

    if (retry_write(mailbox->index_fd, buf, mailbox->i.record_size)
        != mailbox->i.record_size)
    {
        xsyslog(LOG_ERR, "IOERROR: writing index record failed",
                         "mailbox=<%s> record=<%u>",
                         mailbox->name, recno);
        return IMAP_IOERROR;
    }

    /* audit logging */
    if (config_auditlog) {
        char flagstr[FLAGMAPSTR_MAXLEN];
        flags_to_str(record, flagstr);
        if (change->flags & CHANGE_ISAPPEND)
            /* note: messageid doesn't have <> wrappers because it already includes them */
            syslog(LOG_NOTICE, "auditlog: append sessionid=<%s> "
                   "mailbox=<%s> uniqueid=<%s> uid=<%u> modseq=<%llu> "
                   "sysflags=<%s> guid=<%s> messageid=%s",
                   session_id(), mailbox->name, mailbox->uniqueid, record->uid,
                   record->modseq, flagstr,
                   message_guid_encode(&record->guid), change->msgid);

        if ((record->internal_flags & FLAG_INTERNAL_EXPUNGED) && !(change->flags & CHANGE_WASEXPUNGED))
            syslog(LOG_NOTICE, "auditlog: expunge sessionid=<%s> "
                   "mailbox=<%s> uniqueid=<%s> uid=<%u> modseq=<%llu> "
                   "sysflags=<%s> guid=<%s>",
                   session_id(), mailbox->name, mailbox->uniqueid, record->uid,
                   record->modseq, flagstr,
                   message_guid_encode(&record->guid));

        if ((record->internal_flags & FLAG_INTERNAL_UNLINKED) && !(change->flags & CHANGE_WASUNLINKED))
            syslog(LOG_NOTICE, "auditlog: unlink sessionid=<%s> "
                   "mailbox=<%s> uniqueid=<%s> uid=<%u> modseq=<%llu> "
                   "sysflags=<%s> guid=<%s>",
                   session_id(), mailbox->name, mailbox->uniqueid, record->uid,
                   record->modseq, flagstr,
                   message_guid_encode(&record->guid));
    }

    return 0;
}

static void _cleanup_changes(struct mailbox *mailbox)
{
    uint32_t i;
    for (i = 0; i < mailbox->index_change_count; i++) {
        free(mailbox->index_changes[i].msgid);
    }
    free(mailbox->index_changes);
    mailbox->index_changes = NULL;
    mailbox->index_change_count = 0;
    mailbox->index_change_alloc = 0;
    memset(mailbox->index_change_map, 0, sizeof(uint32_t)*INDEX_MAP_SIZE);
}

/* qsort function for changes */
static int change_compar(const void *a, const void *b)
{
    struct index_change *ac = (struct index_change *)a;
    struct index_change *bc = (struct index_change *)b;

    if (ac->record.recno > bc->record.recno)
        return 1;
    if (ac->record.recno < bc->record.recno)
        return -1;
    return 0;
}

static int _commit_changes(struct mailbox *mailbox)
{
    uint32_t i;
    int r;

    if (!mailbox->index_change_count) return 0;
    mailbox->i.dirty = 1;

    /* in which we throw away all our next pointers, but we don't care any more.
     * we just want to write in sensible order.  Otherwise, there's no need to
     * do this sort at all */
    qsort(mailbox->index_changes, mailbox->index_change_count,
          sizeof(struct index_change), change_compar);

    for (i = 0; i < mailbox->index_change_count; i++) {
        r = _commit_one(mailbox, &mailbox->index_changes[i]);
        if (r) return r; /* DAMN, we're screwed */
    }

    _cleanup_changes(mailbox);

    /* recalculate the size */
    mailbox->index_size = mailbox->i.start_offset + (mailbox->i.num_records * mailbox->i.record_size);

    r = mailbox_refresh_index_map(mailbox);
    if (r) return r;

    return 0;
}

EXPORTED int mailbox_reload_index_record_dirty(struct mailbox *mailbox,
                                               struct index_record *record)
{
    unsigned recno = record->recno;
    unsigned offset = mailbox->i.start_offset + (recno-1) * mailbox->i.record_size;

    if (offset + mailbox->i.record_size > mailbox->index_size) {
        xsyslog(LOG_ERR, "IOERROR: index record past end of file",
                         "mailbox=<%s> record=<%u>",
                         mailbox->name, recno);
        return IMAP_IOERROR;
    }

    const char *buf = mailbox->index_base + offset;
    mailbox_buf_to_index_record(buf, mailbox->i.minor_version, record, 1);
    record->recno = recno;

    return 0;
}


/*
 * Read an index record from a mailbox
 */
static int mailbox_read_index_record(struct mailbox *mailbox,
                                     uint32_t recno,
                                     struct index_record *record)
{
    const char *buf;
    unsigned offset;
    int r;
    struct index_change *change = _find_change(mailbox, recno);

    if (change) {
        *record = change->record;
        return 0;
    }

    offset = mailbox->i.start_offset + (recno-1) * mailbox->i.record_size;

    if (offset + mailbox->i.record_size > mailbox->index_size) {
        xsyslog(LOG_ERR, "IOERROR: index record past end of file",
                         "mailbox=<%s> record=<%u>",
                         mailbox->name, recno);
        return IMAP_IOERROR;
    }

    buf = mailbox->index_base + offset;

    r = mailbox_buf_to_index_record(buf, mailbox->i.minor_version, record, 0);

    record->recno = recno;

    return r;
}

EXPORTED int mailbox_read_basecid(struct mailbox *mailbox, const struct index_record *record)
{
    if (record->basecid) return 0;

    if (record->internal_flags & FLAG_INTERNAL_SPLITCONVERSATION) {
        struct buf annotval = BUF_INITIALIZER;
        mailbox_annotation_lookup(mailbox, record->uid, IMAP_ANNOT_NS "basethrid", "", &annotval);
        if (annotval.len == 16) {
            const char *p = buf_cstring(&annotval);
            /* we have a new canonical CID */
            struct index_record *backdoor = (struct index_record *)record;
            parsehex(p, &p, 16, &backdoor->basecid);
        }
        buf_free(&annotval);
    }

    return 0;
}

EXPORTED int mailbox_has_conversations(struct mailbox *mailbox)
{
    char *path;

    /* not needed */
    if (!config_getswitch(IMAPOPT_CONVERSATIONS))
        return 0;

    /* we never store data about deleted mailboxes */
    if (mboxname_isdeletedmailbox(mailbox->name, NULL))
        return 0;

    /* we never store data about submission mailboxes */
    if (mboxname_issubmissionmailbox(mailbox->name, mailbox->mbtype))
        return 0;

    path = conversations_getmboxpath(mailbox->name);
    if (!path) return 0;
    free(path);

    return 1;
}

#ifdef WITH_DAV
HIDDEN struct caldav_db *mailbox_open_caldav(struct mailbox *mailbox)
{
    if (!mailbox->local_caldav) {
        mailbox->local_caldav = caldav_open_mailbox(mailbox);
        int r = caldav_begin(mailbox->local_caldav);
        if (r) {
            caldav_abort(mailbox->local_caldav);
            caldav_close(mailbox->local_caldav);
            mailbox->local_caldav = NULL;
        }
    }
    return mailbox->local_caldav;
}

HIDDEN struct carddav_db *mailbox_open_carddav(struct mailbox *mailbox)
{
    if (!mailbox->local_carddav) {
        mailbox->local_carddav = carddav_open_mailbox(mailbox);
        int r = carddav_begin(mailbox->local_carddav);
        if (r) {
            carddav_abort(mailbox->local_carddav);
            carddav_close(mailbox->local_carddav);
            mailbox->local_carddav = NULL;
        }
    }
    return mailbox->local_carddav;
}

static struct webdav_db *mailbox_open_webdav(struct mailbox *mailbox)
{
    if (!mailbox->local_webdav) {
        mailbox->local_webdav = webdav_open_mailbox(mailbox);
        int r = webdav_begin(mailbox->local_webdav);
        if (r) {
            webdav_abort(mailbox->local_webdav);
            webdav_close(mailbox->local_webdav);
            mailbox->local_webdav = NULL;
        }
    }
    return mailbox->local_webdav;
}
#endif

static uint32_t mailbox_getuid(struct mailbox *mailbox, uint32_t recno)
{
    struct index_record record;
    record.uid = 0;
    /* XXX - cheaper memory-access reads? */
    mailbox_read_index_record(mailbox, recno, &record);
    return record.uid;
}


/*
 * Returns the recno of the message with UID 'uid'.
 * If no message with UID 'uid', returns the message with
 * the highest UID not greater than 'uid'.
 */
static uint32_t mailbox_finduid(struct mailbox *mailbox, uint32_t uid)
{
    uint32_t low = 1;
    uint32_t high = mailbox->i.num_records;
    uint32_t mid;
    uint32_t miduid;

    while (low <= high) {
        mid = (high - low)/2 + low;
        miduid = mailbox_getuid(mailbox, mid);
        if (miduid == uid)
            return mid;
        else if (miduid > uid)
            high = mid - 1;
        else
            low = mid + 1;
    }
    return high;
}

/*
 * Perform a binary search on the mailbox index file to read the record
 * for uid 'uid' into 'record'.  If 'oldrecord' is not NULL then it is
 * assumed to point a correct and current index record from an earlier
 * call, and the search is bounded by that record.  Returns 0 on success
 * or an IMAP error code on failure.
 */
EXPORTED int mailbox_find_index_record(struct mailbox *mailbox, uint32_t uid,
                                       struct index_record *record)
{
    uint32_t recno = mailbox_finduid(mailbox, uid);
    /* no records? */
    if (!recno) return IMAP_NOTFOUND;

    int r = mailbox_read_index_record(mailbox, recno, record);
    /* failed read? */
    if (r) return r;

    /* wasn't the actual record? */
    if (record->uid != uid) return IMAP_NOTFOUND;

    return 0;
}

/*
 * Lock the index file for 'mailbox'.  Reread index file header if necessary.
 */
static int mailbox_lock_index_internal(struct mailbox *mailbox, int locktype)
{
    struct stat sbuf;
    int r = 0;
    const char *header_fname = mailbox_meta_fname(mailbox, META_HEADER);
    const char *index_fname = mailbox_meta_fname(mailbox, META_INDEX);

    assert(mailbox->index_fd != -1);
    assert(!mailbox->index_locktype);

    char *userid = mboxname_to_userid(mailbox->name);
    if (userid) {
        if (!user_isnamespacelocked(userid)) {
            struct mailboxlist *listitem = find_listitem(mailbox->name);
            assert(listitem);
            assert(&listitem->m == mailbox);
            r = mailbox_mboxlock_reopen(listitem, LOCK_SHARED, locktype);
            if (locktype == LOCK_SHARED)
                mailbox->is_readonly = 1;
            if (!r) r = mailbox_open_index(mailbox);
        }
        free(userid);
        if (r) return r;
    }

    if (locktype == LOCK_EXCLUSIVE) {
        /* handle read-only case cleanly - we need to re-open read-write first! */
        if (mailbox->is_readonly) {
            mailbox->is_readonly = 0;
            r = mailbox_open_index(mailbox);
        }
        if (!r) r = lock_blocking(mailbox->index_fd, index_fname);
    }
    else if (locktype == LOCK_SHARED) {
        r = lock_shared(mailbox->index_fd, index_fname);
    }
    else {
        /* this function does not support nonblocking locks */
        fatal("invalid locktype for index", EX_SOFTWARE);
    }

    /* double check that the index exists and has at least enough
     * data to check the version number */
    if (!r) {
        if (!mailbox->index_base)
            r = IMAP_MAILBOX_BADFORMAT;
        else if (mailbox->index_size < OFFSET_NUM_RECORDS)
            r = IMAP_MAILBOX_BADFORMAT;
        if (r)
            lock_unlock(mailbox->index_fd, index_fname);
    }

    if (r) {
        xsyslog(LOG_ERR, "IOERROR: lock index failed",
                         "mailbox=<%s> error=<%s>",
                         mailbox->name, error_message(r));
        return IMAP_IOERROR;
    }

    mailbox->index_locktype = locktype;
    gettimeofday(&mailbox->starttime, 0);

    r = stat(header_fname, &sbuf);
    if (r == -1) {
        xsyslog(LOG_ERR, "IOERROR: stat header failed",
                         "mailbox=<%s> header=<%s>",
                         mailbox->name, header_fname);
        mailbox_unlock_index(mailbox, NULL);
        return IMAP_IOERROR;
    }

    /* has the header file changed? */
    if (sbuf.st_ino != mailbox->header_file_ino) {
        r = mailbox_read_header(mailbox, NULL);
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: read header failed",
                             "mailbox=<%s> error=<%s>",
                             mailbox->name, error_message(r));
            mailbox_unlock_index(mailbox, NULL);
            return r;
        }
    }

    /* release caches */
    int i;
    for (i = 0; i < mailbox->caches.count; i++) {
        struct mappedfile *cachefile = ptrarray_nth(&mailbox->caches, i);
        mappedfile_close(&cachefile);
    }
    ptrarray_fini(&mailbox->caches);

    /* note: it's guaranteed by our outer cyrus.lock lock that the
     * cyrus.index and cyrus.cache files are never rewritten, so
     * we're safe to just extend the map if needed */
    r = mailbox_read_index_header(mailbox);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: refreshing index failed",
                         "mailbox=<%s> error=<%s>",
                         mailbox->name, error_message(r));
        mailbox_unlock_index(mailbox, NULL);
        return r;
    }

    /* check the CRC */
    if (mailbox->header_file_crc && mailbox->i.header_file_crc &&
        mailbox->header_file_crc != mailbox->i.header_file_crc) {
        syslog(LOG_WARNING, "Header CRC mismatch for mailbox %s: %08X %08X",
               mailbox->name, (unsigned int)mailbox->header_file_crc,
               (unsigned int)mailbox->i.header_file_crc);
    }

    return 0;
}

EXPORTED int mailbox_lock_index(struct mailbox *mailbox, int locktype)
{
    int r = 0;

    r = mailbox_lock_index_internal(mailbox, locktype);
    if (r) return r;

    /* otherwise, sanity checks for regular use, but not for internal
     * use during cleanup */

    /* we may be in the process of deleting this mailbox */
    if (mailbox->i.options & OPT_MAILBOX_DELETED) {
        mailbox_unlock_index(mailbox, NULL);
        return IMAP_MAILBOX_NONEXISTENT;
    }

    return 0;
}

/*
 * Release lock on the index file for 'mailbox'
 */
EXPORTED void mailbox_unlock_index(struct mailbox *mailbox, struct statusdata *sdata)
{
    struct statusdata mysdata = STATUSDATA_INIT;
    struct timeval endtime;
    double timediff;
    int r;
    const char *index_fname = mailbox_meta_fname(mailbox, META_INDEX);

    /* this is kinda awful, but too much code expects it to work, and the
     * refcounting isn't good about partial commit/abort and all the
     * unwinding, so here you are.  At least if you mailbox_abort, then
     * it resets the dirty flags, so this becomes a NOOP during close */
    /* naughty - you can't unlock a dirty mailbox! */
    r = mailbox_commit(mailbox);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: failed to commit mailbox, "
                            "probably need to reconstruct",
                         "mailbox=<%s>",
                         mailbox->name);
        abort();
    }

    if (mailbox->has_changed) {
        if (updatenotifier) updatenotifier(mailbox->name);
        sync_log_mailbox(mailbox->name);

        if (!sdata) {
            status_fill_mailbox(mailbox, &mysdata);
            sdata = &mysdata;
        }

        mailbox->has_changed = 0;
    }

    // we always write if given new statusdata, or if we changed the mailbox
    if (sdata)
        statuscache_invalidate(mailbox->name, sdata);

    if (mailbox->index_locktype) {
        if (lock_unlock(mailbox->index_fd, index_fname))
            xsyslog(LOG_ERR, "IOERROR: unlocking index failed",
                             "mailbox=<%s>",
                             mailbox->name);
        mailbox->index_locktype = 0;

        gettimeofday(&endtime, 0);
        timediff = timesub(&mailbox->starttime, &endtime);
        if (timediff > 1.0) {
            syslog(LOG_NOTICE, "mailbox: longlock %s for %0.1f seconds",
                mailbox->name, timediff);
        }
    }

    if (mailbox->local_cstate) {
        int r = conversations_commit(&mailbox->local_cstate);
        if (r)
            syslog(LOG_ERR, "Error committing to conversations database for mailbox %s: %s",
                   mailbox->name, error_message(r));
    }

    // release the namespacelock here
    if (mailbox->local_namespacelock) {
        mboxname_release(&mailbox->local_namespacelock);
    }
}

static char *mailbox_header_data_cstring(struct mailbox *mailbox)
{
    struct buf buf = BUF_INITIALIZER;
    struct dlist *dl = dlist_newkvlist(NULL, mailbox->name);

    dlist_setatom(dl, "T", mboxlist_mbtype_to_string(mailbox->mbtype));

    dlist_setatom(dl, "N", mailbox->name);

    dlist_setatom(dl, "I", mailbox->uniqueid);

    if (mailbox->quotaroot)
        dlist_setatom(dl, "Q", mailbox->quotaroot);

    if (mailbox->acl)
        dlist_stitch(dl, mailbox_acl_to_dlist(mailbox->acl));

    if (mailbox->flagname[0]) {
        int flag = 0;
        struct dlist *fl = dlist_newlist(dl, "U");

        do {
            dlist_setatom(fl, "U", mailbox->flagname[flag]);
        } while (++flag < MAX_USER_FLAGS && mailbox->flagname[flag]);
    }

    dlist_printbuf(dl, 0, &buf);

    dlist_free(&dl);

    return buf_release(&buf);
}

/*
 * Write the header file for 'mailbox'
 */
static int mailbox_commit_header(struct mailbox *mailbox)
{
    int fd;
    int r = 0;
    const char *newfname;
    struct iovec iov[10];
    int niov;

    if (!mailbox->header_dirty)
        return 0; /* nothing to write! */

    /* we actually do all header actions under an INDEX lock, because
     * we need to write the crc32 to be consistent! */
    assert(mailbox_index_islocked(mailbox, 1));

    newfname = mailbox_meta_newfname(mailbox, META_HEADER);

    fd = open(newfname, O_CREAT | O_TRUNC | O_RDWR, 0666);
    if (fd == -1) {
        xsyslog(LOG_ERR, "IOERROR: open failed",
                         "newfname=<%s>",
                         newfname);
        return IMAP_IOERROR;
    }

    /* Write magic header, do NOT write the trailing NUL */
    r = write(fd, MAILBOX_HEADER_MAGIC,
              sizeof(MAILBOX_HEADER_MAGIC) - 1);

    if (r != -1) {
        char *data = mailbox_header_data_cstring(mailbox);
        niov = 0;
        WRITEV_ADDSTR_TO_IOVEC(iov, niov, data);
        WRITEV_ADD_TO_IOVEC(iov, niov, "\n", 1);
        r = retry_writev(fd, iov, niov);
        free(data);
    }

    if (r == -1 || fsync(fd)) {
        xsyslog(LOG_ERR, "IOERROR: write failed",
                         "newfname=<%s>",
                         newfname);
        close(fd);
        unlink(newfname);
        return IMAP_IOERROR;
    }

    close(fd);

    /* rename the new header file over the old one */
    r = mailbox_meta_rename(mailbox, META_HEADER);
    if (r) return r;
    mailbox->header_dirty = 0; /* we wrote it out, so not dirty any more */

    /* re-read the header */
    r = mailbox_read_header(mailbox, NULL);
    if (r) return r;

    /* copy the new CRC into the index header */
    mailbox->i.header_file_crc = mailbox->header_file_crc;
    mailbox_index_dirty(mailbox);

    return 0;
}

static bit32 mailbox_index_header_to_buf(struct index_header *i, unsigned char *buf)
{
    bit32 crc;
    bit32 options = i->options & MAILBOX_OPT_VALID;
    size_t headerlen = INDEX_HEADER_SIZE;

    memset(buf, 0, INDEX_HEADER_SIZE); /* buffer is always this big, and aligned */

    assert (i->minor_version >= 6);

    *((bit32 *)(buf+OFFSET_GENERATION_NO)) = htonl(i->generation_no);
    *((bit32 *)(buf+OFFSET_FORMAT)) = htonl(i->format);
    *((bit32 *)(buf+OFFSET_MINOR_VERSION)) = htonl(i->minor_version);
    *((bit32 *)(buf+OFFSET_START_OFFSET)) = htonl(i->start_offset);
    *((bit32 *)(buf+OFFSET_RECORD_SIZE)) = htonl(i->record_size);
    /* this was moved to make upgrades clean, because num_records was
     * the same as exists back then, we didn't keep expunged in the
     * record - but we always have to write NUM_RECORDS so that expunged
     * handing over repack works */
    *((bit32 *)(buf+OFFSET_NUM_RECORDS)) = htonl(i->num_records);
    *((bit32 *)(buf+OFFSET_LAST_APPENDDATE)) = htonl(i->last_appenddate);
    *((bit32 *)(buf+OFFSET_LAST_UID)) = htonl(i->last_uid);

    /* quotas may be 64bit now */
    align_htonll(buf+OFFSET_QUOTA_MAILBOX_USED, i->quota_mailbox_used);

    *((bit32 *)(buf+OFFSET_POP3_LAST_LOGIN)) = htonl(i->pop3_last_login);
    *((bit32 *)(buf+OFFSET_UIDVALIDITY)) = htonl(i->uidvalidity);
    *((bit32 *)(buf+OFFSET_DELETED)) = htonl(i->deleted);
    *((bit32 *)(buf+OFFSET_ANSWERED)) = htonl(i->answered);
    *((bit32 *)(buf+OFFSET_FLAGGED)) = htonl(i->flagged);
    if (i->minor_version < 8) {
        /* this was called OFFSET_POP3_NEW_UIDL and was only zero or one */
        *((bit32 *)(buf+OFFSET_MAILBOX_OPTIONS)) = htonl(options&1);
        return 0; /* no CRC32 support */
    }

    /* otherwise we have options and modseqs */
    *((bit32 *)(buf+OFFSET_MAILBOX_OPTIONS)) = htonl(options);
    *((bit32 *)(buf+OFFSET_LEAKED_CACHE)) = htonl(i->leaked_cache_records);
    align_htonll(buf+OFFSET_HIGHESTMODSEQ, i->highestmodseq);

    /* and that's where it stopped until version 2.4.0 with index version 12 (ignoring
     * version 11, which doesn't exist in the wild */
    if (i->minor_version < 12) {
        return 0;
    }

    align_htonll(buf+OFFSET_DELETEDMODSEQ, i->deletedmodseq);
    *((bit32 *)(buf+OFFSET_EXISTS)) = htonl(i->exists);
    *((bit32 *)(buf+OFFSET_FIRST_EXPUNGED)) = htonl(i->first_expunged);
    *((bit32 *)(buf+OFFSET_LAST_REPACK_TIME)) = htonl(i->last_repack_time);
    *((bit32 *)(buf+OFFSET_HEADER_FILE_CRC)) = htonl(i->header_file_crc);
    *((bit32 *)(buf+OFFSET_SYNCCRCS_BASIC)) = htonl(i->synccrcs.basic);
    *((bit32 *)(buf+OFFSET_RECENTUID)) = htonl(i->recentuid);
    *((bit32 *)(buf+OFFSET_RECENTTIME)) = htonl(i->recenttime);
    if (i->minor_version > 12) {
        /* these were added in version 13, but replaced zero-byte fields in
         * in version 12, so if we don't write them then the CRC will still
         * be correct for version 12, since the header size didn't change */
        *((bit32 *)(buf+OFFSET_POP3_SHOW_AFTER)) = htonl(i->pop3_show_after);
        /* this field is 64b in memory but 32b on disk - as it counts
        * bytes stored in dbs and the dbs are 32b anyway there should
        * be no problem */
        *((bit32 *)(buf+OFFSET_QUOTA_ANNOT_USED)) = htonl((bit32)i->quota_annot_used);
        *((bit32 *)(buf+OFFSET_SYNCCRCS_ANNOT)) = htonl(i->synccrcs.annot);
    }

    if (i->minor_version > 13) {
        *((bit32 *)(buf+OFFSET_UNSEEN)) = htonl(i->unseen);
    }
    else {
        /* we expanded the file size in version 14 */
        headerlen = 128;
    }

    if (i->minor_version > 15) {
        align_htonll(buf+OFFSET_MAILBOX_CREATEDMODSEQ, i->createdmodseq);
    }

    if (i->minor_version > 16) {
        *((bit32 *)(buf+OFFSET_CHANGES_EPOCH)) = htonl(i->changes_epoch);
    }

    /* Update checksum */
    crc = htonl(crc32_map((char *)buf, headerlen-4));
    *((bit32 *)(buf+headerlen-4)) = crc;

    return crc;
}

HIDDEN int mailbox_commit_quota(struct mailbox *mailbox)
{
    int res;
    int changed = 0;
    quota_t quota_usage[QUOTA_NUMRESOURCES];

    /* not dirty */
    if (!mailbox->quota_dirty)
        return 0;

    mailbox->quota_dirty = 0;

    /* no quota root means we don't track quota.  That's OK */
    if (!mailbox->quotaroot)
        return 0;

    mailbox_get_usage(mailbox, quota_usage);
    for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
        quota_usage[res] -= mailbox->quota_previously_used[res];
        if (quota_usage[res] != 0) {
            changed++;
        }
    }
    /* unchanged */
    if (!changed)
        return 0;

    assert(mailbox_index_islocked(mailbox, 1));

    quota_update_useds(mailbox->quotaroot, quota_usage,
                       mailbox->name, mailbox->silentchanges);
    /* XXX - fail upon issue?  It's tempting */

    return 0;
}


/*
 * Abort the changes to a mailbox
 */
EXPORTED int mailbox_abort(struct mailbox *mailbox)
{
    int r;

#ifdef WITH_DAV
    r = mailbox_abort_dav(mailbox);
    if (r) return r;
#endif

    /* try to commit sub parts first */
    r = mailbox_abort_cache(mailbox);
    if (r) return r;

    annotate_state_abort(&mailbox->annot_state);

    if (mailbox->local_cstate)
        conversations_abort(&mailbox->local_cstate);

    if (!mailbox->i.dirty)
        return 0;

    assert(mailbox_index_islocked(mailbox, 1));

    /* remove all dirty flags! */
    mailbox->i.dirty = 0;
    mailbox->modseq_dirty = 0;
    mailbox->header_dirty = 0;

    /* removed cached changes */
    _cleanup_changes(mailbox);

    /* we re-read the header and index header to wipe
     * away all the changed values */
    r = mailbox_read_header(mailbox, NULL);
    if (r) return r;

    r = mailbox_read_index_header(mailbox);
    if (r) return r;

    return 0;
}

/*
 * Write the index header for 'mailbox'
 */
EXPORTED int mailbox_commit(struct mailbox *mailbox)
{
    /* XXX - ibuf for alignment? */
    static unsigned char buf[INDEX_HEADER_SIZE];
    int n, r;

    /* try to commit sub parts first */
#ifdef WITH_DAV
    r = mailbox_commit_dav(mailbox);
    if (r) return r;
#endif

    r = mailbox_commit_cache(mailbox);
    if (r) return r;

    r = mailbox_commit_quota(mailbox);
    if (r) return r;

    r = annotate_state_commit(&mailbox->annot_state);
    if (r) return r;

    r = mailbox_commit_header(mailbox);
    if (r) return r;

    if (!mailbox->i.dirty)
        return 0;

    mboxname_setmodseq(mailbox->name,
                       mailbox->i.highestmodseq,
                       mailbox->mbtype, /*flags*/0);

    assert(mailbox_index_islocked(mailbox, 1));

    r = _commit_changes(mailbox);
    if (r) return r;

    /* always update xconvmodseq, it might have been done by annotations */
    r = mailbox_update_xconvmodseq(mailbox, mailbox->i.highestmodseq, /*force*/0);
    if (r) return r;

    mailbox_index_header_to_buf(&mailbox->i, buf);

    lseek(mailbox->index_fd, 0, SEEK_SET);
    n = retry_write(mailbox->index_fd, buf, mailbox->i.start_offset);
    if (n < 0 || fsync(mailbox->index_fd)) {
        xsyslog(LOG_ERR, "IOERROR: writing index header failed",
                         "mailbox=<%s>",
                         mailbox->name);
        return IMAP_IOERROR;
    }

    if (config_auditlog && mailbox->modseq_dirty)
        syslog(LOG_NOTICE, "auditlog: modseq sessionid=<%s> "
               "mailbox=<%s> uniqueid=<%s> highestmodseq=<" MODSEQ_FMT
               "> deletedmodseq=<" MODSEQ_FMT ">",
            session_id(), mailbox->name, mailbox->uniqueid,
            mailbox->i.highestmodseq, mailbox->i.deletedmodseq);

    if (mailbox->modseq_dirty) {
        struct mboxevent *mboxevent = mboxevent_new(EVENT_MAILBOX_MODSEQ);
        mboxevent_extract_mailbox(mboxevent, mailbox);
        mboxevent_set_access(mboxevent, NULL, NULL, "", mailbox->name, 0);
        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);
    }

    /* remove all dirty flags! */
    mailbox->i.dirty = 0;
    mailbox->modseq_dirty = 0;
    mailbox->header_dirty = 0;

    /* label changes for later logging */
    mailbox->has_changed = 1;

    return 0;
}

/*
 * Put an index record into a buffer suitable for writing to a file.
 */
static bit32 mailbox_index_record_to_buf(struct index_record *record, int version,
                                  unsigned char *buf)
{
    int n;
    bit32 crc;
    uint32_t system_flags = 0;

    memset(buf, 0, INDEX_RECORD_SIZE);

    /* keep the low bits of the offset in the offset field */
    uint32_t cache_offset_field = record->cache_offset & 0xffffffff;
    /* mix in the high bits of the offset to the top half of the version field */
    uint32_t cache_version_field = (uint32_t)record->cache_version | (record->cache_offset & 0xffff00000000) >> 16;

    *((bit32 *)(buf+OFFSET_UID)) = htonl(record->uid);
    *((bit32 *)(buf+OFFSET_INTERNALDATE)) = htonl(record->internaldate);
    *((bit32 *)(buf+OFFSET_SENTDATE)) = htonl(record->sentdate);
    *((bit32 *)(buf+OFFSET_SIZE)) = htonl(record->size);
    *((bit32 *)(buf+OFFSET_HEADER_SIZE)) = htonl(record->header_size);
    if (version >= 12) {
        *((bit32 *)(buf+OFFSET_GMTIME)) = htonl(record->gmtime);
    }
    else {
        /* content_offset was always the same */
        *((bit32 *)(buf+OFFSET_GMTIME)) = htonl(record->header_size);
    }
    *((bit32 *)(buf+OFFSET_CACHE_OFFSET)) = htonl(cache_offset_field);
    *((bit32 *)(buf+OFFSET_LAST_UPDATED)) = htonl(record->last_updated);

    /* serialise system flags and internal flags */
    system_flags = record->system_flags | record->internal_flags;
    *((bit32 *)(buf+OFFSET_SYSTEM_FLAGS)) = htonl(system_flags);

    for (n = 0; n < MAX_USER_FLAGS/32; n++) {
        *((bit32 *)(buf+OFFSET_USER_FLAGS+4*n)) = htonl(record->user_flags[n]);
    }
    if (version > 14) {
        *((bit32 *)(buf+OFFSET_SAVEDATE)) = htonl(record->savedate);
    }
    else {
        *((bit32 *)(buf+OFFSET_SAVEDATE)) = 0; // blank out old content_lines
    }
    *((bit32 *)(buf+OFFSET_CACHE_VERSION)) = htonl(cache_version_field);

    /* versions less than 8 had no modseq */
    if (version < 8) {
        return 0;
    }

    /* versions 8 and 9 only had a smaller UUID, which we will ignore,
     * but the modseq existed and was at offset 72 and 76 */
    if (version < 10) {
        *((bit64 *)(buf+72)) = htonll(record->modseq);
        return 0;
    }

    /* otherwise we have the GUID and MODSEQ in their current place */
    message_guid_export(&record->guid, (char *)buf+OFFSET_MESSAGE_GUID);
    *((bit64 *)(buf+OFFSET_MODSEQ)) = htonll(record->modseq);

    /* version 12 added the CACHE_CRC and RECORD_CRC, but at a lower point */
    if (version < 13) {
        *((bit32 *)(buf+88)) = htonl(record->cache_crc);
        /* calculate the checksum */
        crc = crc32_map((char *)buf, 92);
        *((bit32 *)(buf+92)) = htonl(crc);
        return crc;
    }

    *((bit64 *)(buf+OFFSET_THRID)) = htonll(record->cid);

    /* version 16 added createdmodseq, pushing the CRCs down */
    if (version < 16) {
        *((bit32 *)(buf+96)) = htonl(record->cache_crc);
        crc = crc32_map((char *)buf, 100);
        *((bit32 *)(buf+100)) = htonl(crc);
        return crc;
    }

    *((bit64 *)(buf+OFFSET_CREATEDMODSEQ)) = htonll(record->createdmodseq);
    *((bit32 *)(buf+OFFSET_CACHE_CRC)) = htonl(record->cache_crc);

    /* calculate the checksum */
    crc = crc32_map((char *)buf, OFFSET_RECORD_CRC);
    *((bit32 *)(buf+OFFSET_RECORD_CRC)) = htonl(crc);

    return crc;
}


static void mailbox_quota_dirty(struct mailbox *mailbox)
{
    /* track quota use */
    if (!mailbox->quota_dirty) {
        mailbox->quota_dirty = 1;
        mailbox_get_usage(mailbox, mailbox->quota_previously_used);
    }
}

static void header_update_counts(struct index_header *i,
                                 const struct index_record *record,
                                 int is_add)
{
    int num = is_add ? 1 : -1;

    /* we don't track counts for EXPUNGED records */
    if (record->internal_flags & FLAG_INTERNAL_EXPUNGED)
        return;

    /* update mailbox header fields */
    if (record->system_flags & FLAG_ANSWERED)
        i->answered += num;

    if (record->system_flags & FLAG_FLAGGED)
        i->flagged += num;

    if (record->system_flags & FLAG_DELETED)
        i->deleted += num;

    if (!(record->system_flags & FLAG_SEEN))
        i->unseen += num;

    if (is_add) {
        i->exists++;
        i->quota_mailbox_used += record->size;
    }
    else {
        if (i->exists) i->exists--;

        /* corruption prevention - check we don't go negative */
        if (i->quota_mailbox_used > record->size)
            i->quota_mailbox_used -= record->size;
        else
            i->quota_mailbox_used = 0;
    }
}

/*************************** Sync CRC ***************************/

struct annot_calc_rock
{
    struct mailbox *mailbox;
    uint32_t annot;
    quota_t used;
};

/* this is the algorithm from version 2.4, it's locked in */
static uint32_t crc_basic(const struct mailbox *mailbox,
                          const struct index_record *record)
{
    char buf[4096];
    uint32_t flagcrc = 0;
    int flag;

    /* expunged flags have no sync CRC */
    if (record->internal_flags & FLAG_INTERNAL_EXPUNGED)
        return 0;

    /* calculate an XORed CRC32 over all the flags on the message, so no
     * matter what order they are store in the header, the final value
     * is the same */
    if (record->system_flags & FLAG_DELETED)
        flagcrc ^= crc32_cstring("\\deleted");
    if (record->system_flags & FLAG_ANSWERED)
        flagcrc ^= crc32_cstring("\\answered");
    if (record->system_flags & FLAG_FLAGGED)
        flagcrc ^= crc32_cstring("\\flagged");
    if (record->system_flags & FLAG_DRAFT)
        flagcrc ^= crc32_cstring("\\draft");
    if (record->system_flags & FLAG_SEEN)
        flagcrc ^= crc32_cstring("\\seen");

    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
        if (!mailbox->flagname[flag])
            continue;
        if (!(record->user_flags[flag/32] & (1<<(flag&31))))
            continue;
        /* need to compare without case being significant */
        strlcpy(buf, mailbox->flagname[flag], 4096);
        lcase(buf);
        flagcrc ^= crc32_cstring(buf);
    }

    snprintf(buf, sizeof(buf), "%u " MODSEQ_FMT " " TIME_T_FMT " (%u) " TIME_T_FMT " %s",
            record->uid, record->modseq, record->last_updated,
            flagcrc,
            record->internaldate,
            message_guid_encode(&record->guid));

    return crc32_cstring(buf);
}

static uint32_t crc_annot(unsigned int uid, const char *entry,
                          const char *userid, const struct buf *value)
{
    struct buf buf = BUF_INITIALIZER;
    uint32_t res = 0;

    // ignore everything with a NULL userid, it's bogus!
    if (!userid) return 0;

    buf_printf(&buf, "%u %s %s ", uid, entry, userid);
    buf_append(&buf, value);
    res = crc32_buf(&buf);
    buf_free(&buf);

    return res;
}

static int mailbox_is_virtannot(struct mailbox *mailbox, const char *entry)
{
    if (mailbox->i.minor_version < 13) return 0;
    // thrid was introduced in v13
    if (!strcmp(entry, IMAP_ANNOT_NS "thrid")) return 1;

    if (mailbox->i.minor_version < 15) return 0;
    // savedate was introduced in v15
    if (!strcmp(entry, IMAP_ANNOT_NS "savedate")) return 1;

    if (mailbox->i.minor_version < 16) return 0;
    // createdmodseq was introduced in v16
    if (!strcmp(entry, IMAP_ANNOT_NS "createdmodseq")) return 1;

    return 0;
}


static uint32_t crc_virtannot(struct mailbox *mailbox,
                              const struct index_record *record)
{
    if (record->internal_flags & FLAG_INTERNAL_EXPUNGED)
        return 0;

    uint32_t crc = 0;
    struct buf buf = BUF_INITIALIZER;

    if (record->cid && mailbox->i.minor_version >= 13) {
        buf_printf(&buf, "%llx", record->cid);
        crc ^= crc_annot(record->uid, IMAP_ANNOT_NS "thrid", "", &buf);
        buf_reset(&buf);
    }

    if (record->savedate && mailbox->i.minor_version >= 15) {
        buf_printf(&buf, TIME_T_FMT, record->savedate);
        crc ^= crc_annot(record->uid, IMAP_ANNOT_NS "savedate", "", &buf);
        buf_reset(&buf);
    }

    if (record->createdmodseq && mailbox->i.minor_version >= 16) {
        buf_printf(&buf, "%llu", record->createdmodseq);
        crc ^= crc_annot(record->uid, IMAP_ANNOT_NS "createdmodseq", "", &buf);
        buf_reset(&buf);
    }

    buf_free(&buf);
    return crc;
}

EXPORTED void mailbox_annot_changed(struct mailbox *mailbox,
                           unsigned int uid,
                           const char *entry,
                           const char *userid,
                           const struct buf *oldval,
                           const struct buf *newval,
                           int silent)
{
    /* update sync_crc - NOTE, only per-message annotations count */
    if (uid) {
        /* check that the record isn't already expunged */
        struct index_record record;
        int r = mailbox_find_index_record(mailbox, uid, &record);
        if (r || record.internal_flags & FLAG_INTERNAL_EXPUNGED)
            return;
        if (!mailbox_is_virtannot(mailbox, entry)) {
            if (oldval->len)
                mailbox->i.synccrcs.annot ^= crc_annot(uid, entry, userid, oldval);
            if (newval->len)
                mailbox->i.synccrcs.annot ^= crc_annot(uid, entry, userid, newval);
        }
    }

    if (!silent) {
        /* we are dirtying modseq for any annotation change */
        mailbox_modseq_dirty(mailbox);
        /* and we're dirtying foldermodseq if it's a mailbox level annotation */
        if (!uid) mboxlist_update_foldermodseq(mailbox->name, mailbox->i.highestmodseq);
    }
    /* we always dirty the quota */
    mailbox_quota_dirty(mailbox);

    /* corruption prevention - check we don't go negative */
    if (mailbox->i.quota_annot_used > (quota_t)oldval->len)
        mailbox->i.quota_annot_used -= oldval->len;
    else
        mailbox->i.quota_annot_used = 0;

    mailbox->i.quota_annot_used += newval->len;
}

static int calc_one_annot(const char *mboxname __attribute__((unused)),
                          uint32_t uid,
                          const char *entry,
                          const char *userid,
                          const struct buf *value,
                          const struct annotate_metadata *mdata __attribute__((unused)),
                          void *rock)
{
    struct annot_calc_rock *cr = (struct annot_calc_rock *)rock;

    /* update sync_crc - NOTE, only per-message annotations count */
    if (uid && !mailbox_is_virtannot(cr->mailbox, entry))
        cr->annot ^= crc_annot(uid, entry, userid, value);

    /* always count the size */
    cr->used += value->len;

    return 0;
}

static void mailbox_annot_update_counts(struct mailbox *mailbox,
                                        const struct index_record *record,
                                        int is_add)
{
    struct annot_calc_rock cr = { mailbox, 0, 0 };

    /* expunged records don't count */
    if (record && record->internal_flags & FLAG_INTERNAL_EXPUNGED) return;

    annotatemore_findall(mailbox->name, record ? record->uid : 0, /* all entries*/"*",
                         /*modseq*/0, calc_one_annot, &cr, /*flags*/0);

    if (record)
        mailbox->i.synccrcs.annot ^= cr.annot;

    if (is_add)
        mailbox->i.quota_annot_used += cr.used;
    else {
        /* corruption prevention - check we don't go negative */
        if (mailbox->i.quota_annot_used > cr.used)
            mailbox->i.quota_annot_used -= cr.used;
        else
            mailbox->i.quota_annot_used = 0;
    }
}

/*
 * Calculate a sync CRC for the entire @mailbox using CRC algorithm
 * version @vers, optionally forcing recalculation
 */
EXPORTED struct synccrcs mailbox_synccrcs(struct mailbox *mailbox, int force)
{
    annotate_state_t *astate = NULL;
    const message_t *msg;
    struct synccrcs crcs = { CRC_INIT_BASIC, CRC_INIT_ANNOT };

    if (!force)
        return mailbox->i.synccrcs;

    /* hold annotations DB open - failure to load is an error */
    if (mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, &astate))
        return crcs;

    /* and make sure it stays locked for the whole process */
    annotate_state_begin(astate);

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        crcs.basic ^= crc_basic(mailbox, record);
        crcs.annot ^= crc_virtannot(mailbox, record);

        struct annot_calc_rock cr = { mailbox, 0, 0 };
        annotatemore_findall(mailbox->name, record->uid, /* all entries*/"*",
                             /*modseq*/0, calc_one_annot, &cr, /*flags*/0);

        crcs.annot ^= cr.annot;
    }
    mailbox_iter_done(&iter);

    /* possibly upgrade the stored value */
    if (mailbox_index_islocked(mailbox, /*write*/1)) {
        mailbox->i.synccrcs = crcs;
        mailbox_index_dirty(mailbox);
    }

    /* return the newly calculated CRC */
    return crcs;
}

static void mailbox_index_update_counts(struct mailbox *mailbox,
                                        const struct index_record *record,
                                        int is_add)
{
    mailbox_quota_dirty(mailbox);
    mailbox_index_dirty(mailbox);
    header_update_counts(&mailbox->i, record, is_add);

    mailbox->i.synccrcs.basic ^= crc_basic(mailbox, record);
    mailbox->i.synccrcs.annot ^= crc_virtannot(mailbox, record);
}

EXPORTED int mailbox_index_recalc(struct mailbox *mailbox)
{
    annotate_state_t *astate = NULL;
    const message_t *msg;
    int r = 0;

    assert(mailbox_index_islocked(mailbox, 1));

    /* cache the old used quota */
    mailbox_quota_dirty(mailbox);
    mailbox_index_dirty(mailbox);

    mailbox->i.answered = 0;
    mailbox->i.flagged = 0;
    mailbox->i.deleted = 0;
    mailbox->i.unseen = 0;
    mailbox->i.exists = 0;
    mailbox->i.quota_mailbox_used = 0;
    mailbox->i.quota_annot_used = 0;
    mailbox->i.synccrcs.basic = CRC_INIT_BASIC;
    mailbox->i.synccrcs.annot = CRC_INIT_ANNOT;

    /* mailbox level annotations */
    mailbox_annot_update_counts(mailbox, NULL, 1);

    /* hold annotations DB open */
    r = mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, &astate);
    if (r) goto out;

    /* and make sure it stays locked for the whole process */
    annotate_state_begin(astate);

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        mailbox_index_update_counts(mailbox, record, 1);
        mailbox_annot_update_counts(mailbox, record, 1);
    }
    mailbox_iter_done(&iter);

out:
    return r;
}

#ifdef WITH_DAV
static int mailbox_update_carddav(struct mailbox *mailbox,
                                  const struct index_record *old,
                                  const struct index_record *new)
{
    struct carddav_db *carddavdb = NULL;
    struct param *param;
    struct body *body = NULL;
    struct carddav_data *cdata = NULL;
    const char *resource = NULL;
    int r = 0;

    /* conditions in which there's nothing to do */
    if (!new) goto done;

    /* phantom record - never really existed here */
    if (!old && (new->internal_flags & FLAG_INTERNAL_UNLINKED))
        goto done;

    r = mailbox_cacherecord(mailbox, new);
    if (r) goto done;

    /* Get resource URL from filename param in Content-Disposition header */
    message_read_bodystructure(new, &body);
    for (param = body->disposition_params; param; param = param->next) {
        if (!strcmp(param->attribute, "FILENAME")) {
            resource = param->value;
        }
    }

    assert(resource);

    carddavdb = mailbox_open_carddav(mailbox);

    /* find existing record for this resource */
    const mbentry_t mbentry = { .name = mailbox->name,
                                .uniqueid = mailbox->uniqueid };

    carddav_lookup_resource(carddavdb, &mbentry, resource, &cdata, /*tombstones*/1);

    /* does it still come from this UID? */
    if (cdata->dav.imap_uid > new->uid) goto done;

    if (new->internal_flags & FLAG_INTERNAL_UNLINKED) {
        /* is there an existing record? */
        if (!cdata->dav.imap_uid) goto done;

        /* delete entry */
        r = carddav_delete(carddavdb, cdata->dav.rowid);
    }
    else if (cdata->dav.imap_uid == new->uid) {
        /* just a flag change on an existing record */
        struct vparse_card *vcard = record_to_vcard(mailbox, new);
        int ispinned = (new->system_flags & FLAG_FLAGGED) ? 1 : 0;

        if (!vcard || !vcard->objects) {
            syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                   cdata->dav.imap_uid, mailbox->name);
            r = IMAP_MAILBOX_BADFORMAT; // XXX better error?
            vparse_free_card(vcard);
            goto done;
        }

        cdata->dav.modseq = new->modseq;
        cdata->dav.alive = (new->internal_flags & FLAG_INTERNAL_EXPUNGED) ? 0 : 1;
        r = carddav_writecard(carddavdb, cdata, vcard->objects, ispinned);
        vparse_free_card(vcard);
    }
    else {
        /* Load message containing the resource and parse vcard data */
        struct vparse_card *vcard = record_to_vcard(mailbox, new);
        int ispinned = (new->system_flags & FLAG_FLAGGED) ? 1 : 0;

        if (!vcard || !vcard->objects) {
            syslog(LOG_ERR, "record_to_vcard failed for record %u:%s",
                   cdata->dav.imap_uid, mailbox->name);
            r = IMAP_MAILBOX_BADFORMAT; // XXX better error?
            vparse_free_card(vcard);
            goto done;
        }

        /* Create mapping entry from resource name to UID */
        cdata->dav.imap_uid = new->uid;
        cdata->dav.modseq = new->modseq;
        cdata->dav.createdmodseq = new->createdmodseq;
        cdata->dav.alive = (new->internal_flags & FLAG_INTERNAL_EXPUNGED) ? 0 : 1;

        if (!cdata->dav.creationdate)
            cdata->dav.creationdate = new->internaldate;

        r = carddav_writecard(carddavdb, cdata, vcard->objects, ispinned);

        vparse_free_card(vcard);
    }

done:
    message_free_body(body);
    free(body);

    return r;
}

static int mailbox_update_caldav(struct mailbox *mailbox,
                                 const struct index_record *old,
                                 const struct index_record *new)
{
    struct caldav_db *caldavdb = NULL;
    struct param *param;
    struct body *body = NULL;
    struct caldav_data *cdata = NULL;
    const char *resource = NULL;
    const char *sched_tag = NULL;
    unsigned tzbyref = 0, shared = 0;
    int r = 0;

    /* conditions in which there's nothing to do */
    if (!new) goto done;

    /* phantom record - never really existed at all */
    if (!old && (new->internal_flags & FLAG_INTERNAL_UNLINKED))
        goto done;

    r = mailbox_cacherecord(mailbox, new);
    if (r) goto done;

    /* get resource URL from filename param in Content-Disposition header */
    message_read_bodystructure(new, &body);
    for (param = body->disposition_params; param; param = param->next) {
        if (!strcmp(param->attribute, "FILENAME")) {
            resource = param->value;
        }
        else if (!strcmp(param->attribute, "SCHEDULE-TAG")) {
            sched_tag = param->value;
        }
        else if (!strcmp(param->attribute, "TZ-BY-REF")) {
            tzbyref = !strcasecmp(param->value, "TRUE");
        }
        else if (!strcmp(param->attribute, "PER-USER-DATA")) {
            shared = !strcasecmp(param->value, "TRUE");
        }
    }

    caldavdb = mailbox_open_caldav(mailbox);

    /* Find existing record for this resource */
    const mbentry_t mbentry = { .name = mailbox->name,
                                .uniqueid = mailbox->uniqueid };

    caldav_lookup_resource(caldavdb, &mbentry, resource, &cdata, /*tombstones*/1);

    /* has this record already been replaced?  Don't write anything */
    if (cdata->dav.imap_uid > new->uid) goto done;

    if (new->internal_flags & FLAG_INTERNAL_UNLINKED) {
        /* is there an existing record? */
        if (!cdata->dav.imap_uid) goto done;

        /* remove associated alarms */
        caldav_alarm_delete_record(cdata->dav.mailbox, cdata->dav.imap_uid);

        /* delete entry */
        r = caldav_delete(caldavdb, cdata->dav.rowid);
    }
    else if (cdata->dav.imap_uid == new->uid) {
        if (new->internal_flags & FLAG_INTERNAL_EXPUNGED) {
            /* remove associated alarms */
            caldav_alarm_delete_record(cdata->dav.mailbox, cdata->dav.imap_uid);
        }
        else if (!new->silentupdate) {
            /* make sure record is up to date - see add below for description of
             * why we don't touch silent records */
            caldav_alarm_touch_record(mailbox, new);
        }

        /* just a flags update to an existing record */
        cdata->dav.modseq = new->modseq;
        cdata->dav.alive = (new->internal_flags & FLAG_INTERNAL_EXPUNGED) ? 0 : 1;
        r = caldav_write(caldavdb, cdata);
    }
    else {
        /* Load message containing the resource and parse ical data */
        icalcomponent *ical = record_to_ical(mailbox, new, NULL);

        if (!ical) {
            syslog(LOG_ERR, "record_to_ical failed for record %u:%s",
                   cdata->dav.imap_uid, mailbox->name);
            r = IMAP_MAILBOX_BADFORMAT; // XXX better error?
            goto done;
        }

        /* remove old ones */
        if (cdata->dav.imap_uid) {
            r = caldav_alarm_delete_record(cdata->dav.mailbox, cdata->dav.imap_uid);
            if (r) goto alarmdone;
        }

        cdata->dav.creationdate = new->internaldate;
        cdata->dav.imap_uid = new->uid;
        cdata->dav.modseq = new->modseq;
        cdata->dav.createdmodseq = new->createdmodseq;
        cdata->dav.alive = (new->internal_flags & FLAG_INTERNAL_EXPUNGED) ? 0 : 1;
        cdata->sched_tag = sched_tag;
        cdata->comp_flags.tzbyref = tzbyref;
        cdata->comp_flags.shared = shared;

        /* add new ones unless this record is expunged */
        /* we need to skip silent records (replication)
         * because the lastalarm annotation won't be set yet -
         * instead, we have an explicit sync from the annotation
         * which is done after the annotations are written in sync_support.c */
        if (cdata->dav.alive && !new->silentupdate) {
            r = caldav_alarm_add_record(mailbox, new, ical);
            if (r) goto alarmdone;
        }

        r = caldav_writeentry(caldavdb, cdata, ical);

     alarmdone:
        icalcomponent_free(ical);
    }

done:
    message_free_body(body);
    free(body);

    return r;
}

static int mailbox_update_webdav(struct mailbox *mailbox,
                                 const struct index_record *old,
                                 const struct index_record *new)
{
    struct webdav_db *webdavdb = NULL;
    struct param *param;
    struct body *body = NULL;
    struct webdav_data *wdata = NULL;
    const char *resource = NULL;
    int r = 0;

    /* conditions in which there's nothing to do */
    if (!new) goto done;

    /* phantom record - never really existed here */
    if (!old && new->internal_flags & FLAG_INTERNAL_EXPUNGED)
        goto done;

    r = mailbox_cacherecord(mailbox, new);
    if (r) goto done;

    /* Get resource URL from filename param in Content-Disposition header */
    message_read_bodystructure(new, &body);
    for (param = body->disposition_params; param; param = param->next) {
        if (!strcmp(param->attribute, "FILENAME")) {
            resource = param->value;
        }
    }

    webdavdb = mailbox_open_webdav(mailbox);

    /* Find existing record for this resource */
    const mbentry_t mbentry = { .name = mailbox->name,
                                .uniqueid = mailbox->uniqueid };

    webdav_lookup_resource(webdavdb, &mbentry, resource, &wdata, /*tombstones*/1);

    /* if updated by a newer UID, skip - this record doesn't refer to the current item */
    if (wdata->dav.imap_uid > new->uid) goto done;

    if (new->internal_flags & FLAG_INTERNAL_UNLINKED) {
        /* is there an existing record? */
        if (!wdata->dav.imap_uid) goto done;

        /* delete entry */
        r = webdav_delete(webdavdb, wdata->dav.rowid);
    }
    else if (wdata->dav.imap_uid == new->uid) {
        /* just a flags update to an existing record */
        wdata->dav.modseq = new->modseq;
        wdata->dav.alive = (new->internal_flags & FLAG_INTERNAL_EXPUNGED) ? 0 : 1;
        wdata->ref_count *= wdata->dav.alive;
        r = webdav_write(webdavdb, wdata);
    }
    else {
        struct buf msg_buf = BUF_INITIALIZER;
        struct message_guid guid;

        /* Load message containing the resource */
        r = mailbox_map_record(mailbox, new, &msg_buf);
        if (r) goto done;

        /* Calculate GUID for body content only */
        message_guid_generate(&guid, buf_base(&msg_buf) + new->header_size,
                              buf_len(&msg_buf) - new->header_size);
        buf_free(&msg_buf);

        wdata->dav.creationdate = new->internaldate;
        wdata->dav.imap_uid = new->uid;
        wdata->dav.modseq = new->modseq;
        wdata->dav.createdmodseq = new->createdmodseq;
        wdata->dav.alive = (new->internal_flags & FLAG_INTERNAL_EXPUNGED) ? 0 : 1;
        wdata->ref_count *= wdata->dav.alive;
        wdata->filename = body->description;
        wdata->type = lcase(body->type);
        wdata->subtype = lcase(body->subtype);
        wdata->res_uid = message_guid_encode(&guid);

        r = webdav_write(webdavdb, wdata);
    }

done:
    if (body) {
        message_free_body(body);
        free(body);
    }

    return r;
}

static int mailbox_update_dav(struct mailbox *mailbox,
                              const struct index_record *old,
                              const struct index_record *new)
{
    /* never have DAV on deleted mailboxes */
    if (mboxname_isdeletedmailbox(mailbox->name, NULL))
        return 0;

    switch (mbtype_isa(mailbox->mbtype)) {
    case MBTYPE_ADDRESSBOOK:
        return mailbox_update_carddav(mailbox, old, new);
    case MBTYPE_CALENDAR:
        return mailbox_update_caldav(mailbox, old, new);
    case MBTYPE_COLLECTION:
        return mailbox_update_webdav(mailbox, old, new);
    }

    return 0;
}

static int mailbox_commit_dav(struct mailbox *mailbox)
{
    int r;

    if (mailbox->local_caldav) {
        r = caldav_commit(mailbox->local_caldav);
        caldav_close(mailbox->local_caldav);
        mailbox->local_caldav = NULL;
        if (r) return r;
    }

    if (mailbox->local_carddav) {
        r = carddav_commit(mailbox->local_carddav);
        carddav_close(mailbox->local_carddav);
        mailbox->local_carddav = NULL;
        if (r) return r;
    }

    if (mailbox->local_webdav) {
        r = webdav_commit(mailbox->local_webdav);
        webdav_close(mailbox->local_webdav);
        mailbox->local_webdav = NULL;
        if (r) return r;
    }

    return 0;
}

static int mailbox_abort_dav(struct mailbox *mailbox)
{
    int r;

    if (mailbox->local_caldav) {
        r = caldav_abort(mailbox->local_caldav);
        caldav_close(mailbox->local_caldav);
        mailbox->local_caldav = NULL;
        if (r) return r;
    }

    if (mailbox->local_carddav) {
        r = carddav_abort(mailbox->local_carddav);
        carddav_close(mailbox->local_carddav);
        mailbox->local_carddav = NULL;
        if (r) return r;
    }

    if (mailbox->local_webdav) {
        r = webdav_abort(mailbox->local_webdav);
        webdav_close(mailbox->local_webdav);
        mailbox->local_webdav = NULL;
        if (r) return r;
    }

    return 0;
}

#endif // WITH_DAV

#ifdef WITH_JMAP
static int mailbox_update_email_alarms(struct mailbox *mailbox,
                                       const struct index_record *old,
                                       const struct index_record *new)
{
    int r = 0;

    if (!(mailbox->i.options & OPT_IMAP_HAS_ALARMS))
        return 0;

    /* never have alarms on deleted mailboxes */
    if (mboxname_isdeletedmailbox(mailbox->name, NULL))
        return 0;

    /* remove associated alarms if deleted */
    if (!new || new->internal_flags & FLAG_INTERNAL_EXPUNGED) {
        r = caldav_alarm_delete_record(mailbox->name, new->uid);
    }

    /* remove associated alarms if canceled or final */
    else if (mbtype_isa(mailbox->mbtype) == MBTYPE_JMAPSUBMIT &&
             (new->system_flags & (FLAG_FLAGGED | FLAG_ANSWERED))) {
        r = caldav_alarm_delete_record(mailbox->name, new->uid);
    }

    /* touch or create otherwise */
    else if (old && (old->uid == new->uid)) {
        r = caldav_alarm_touch_record(mailbox, new);
    }
    else {
        r = caldav_alarm_add_record(mailbox, new, NULL);
    }

    return r;
}

EXPORTED int mailbox_add_email_alarms(struct mailbox *mailbox)
{
    const message_t *msg;
    int r = 0;

    if (!(mailbox->i.options & OPT_IMAP_HAS_ALARMS))
        return 0;

    if (mboxname_isdeletedmailbox(mailbox->name, NULL))
        return 0;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        r = mailbox_update_email_alarms(mailbox, NULL, record);
        if (r) break;
    }
    mailbox_iter_done(&iter);

    return r;
}
#endif // WITH_JMAP

EXPORTED struct conversations_state *mailbox_get_cstate(struct mailbox *mailbox)
{
    if (!mailbox_has_conversations(mailbox))
        return NULL;

    /* we already own it? */
    if (mailbox->local_cstate)
        return mailbox->local_cstate;

    /* already exists, use that one */
    struct conversations_state *cstate = conversations_get_mbox(mailbox->name);
    if (cstate) {
        /* but make sure it's not read-only unless we are */
        if (!mailbox->is_readonly) assert (!cstate->is_shared);
        return cstate;
    }

    /* open the conversations DB - don't bother checking return code since it'll
     * only be set if it opens successfully, and we can only return NULL or an
     * object */
    conversations_open_mbox(mailbox->name, mailbox->is_readonly, &mailbox->local_cstate);

    return mailbox->local_cstate;
}

static int mailbox_update_conversations(struct mailbox *mailbox,
                                        const struct index_record *old,
                                        struct index_record *new)
{
    struct conversations_state *cstate = mailbox_get_cstate(mailbox);

    if (!cstate)
        return 0;

    /* handle unlinked items as if they didn't exist */
    if (old && (old->internal_flags & FLAG_INTERNAL_UNLINKED)) old = NULL;
    if (new && (new->internal_flags & FLAG_INTERNAL_UNLINKED)) new = NULL;

    if (!old && !new)
        return 0;

    int ignorelimits = new ? new->ignorelimits : 1;
    return conversations_update_record(cstate, mailbox, old, new,
                                       /*allowrenumber*/1, ignorelimits);
}


EXPORTED int mailbox_get_xconvmodseq(struct mailbox *mailbox, modseq_t *modseqp)
{
    conv_status_t status = CONV_STATUS_INIT;
    int r;

    if (modseqp)
        *modseqp = 0;

    struct conversations_state *cstate = mailbox_get_cstate(mailbox);
    if (!cstate) return 0;

    r = conversation_getstatus(cstate,
                               CONV_FOLDER_KEY_MBOX(cstate, mailbox), &status);
    if (r) return r;

    *modseqp = status.threadmodseq;

    return 0;
}

/* Used in replication */
EXPORTED int mailbox_update_xconvmodseq(struct mailbox *mailbox, modseq_t newmodseq, int force)
{
    conv_status_t status = CONV_STATUS_INIT;
    int r;

    struct conversations_state *cstate = mailbox_get_cstate(mailbox);
    if (!cstate) return 0;

    r = conversation_getstatus(cstate,
                               CONV_FOLDER_KEY_MBOX(cstate, mailbox), &status);
    if (r) return r;

    if (newmodseq > status.threadmodseq || (force && newmodseq < status.threadmodseq)) {
        status.threadmodseq = newmodseq;
        r = conversation_setstatus(cstate,
                                   CONV_FOLDER_KEY_MBOX(cstate, mailbox), &status);
    }

    return r;
}

/* NOTE: maybe make this able to return error codes if we have
 * support for transactional mailbox updates later.  For now,
 * we expect callers to have already done all sanity checking */
static int mailbox_update_indexes(struct mailbox *mailbox,
                                  const struct index_record *old,
                                  struct index_record *new)
{
    int r = 0;

    // 'new' is not static because conversations might change the CID
    r = mailbox_update_conversations(mailbox, old, new);
    if (r) return r;

#ifdef WITH_DAV
    r = mailbox_update_dav(mailbox, old, new);
    if (r) return r;
#endif

#ifdef WITH_JMAP
    r = mailbox_update_email_alarms(mailbox, old, new);
    if (r) return r;
#endif

    /* NOTE - we do these last, once the counts are updated */

    if (old)
        mailbox_index_update_counts(mailbox, old, 0);
    if (new)
        mailbox_index_update_counts(mailbox, new, 1);

    return 0;
}

EXPORTED int mailbox_reload_index_record(struct mailbox *mailbox,
                                         struct index_record *record)
{
    if (record->recno)
        return mailbox_read_index_record(mailbox, record->recno, record);
    else
        return mailbox_find_index_record(mailbox, record->uid, record);
}

/*
 * Rewrite an index record in a mailbox - updates all
 * necessary tracking fields automatically.
 */
EXPORTED int mailbox_rewrite_index_record(struct mailbox *mailbox,
                                          struct index_record *record)
{
    int r;
    struct index_record oldrecord;
    int expunge_mode = config_getenum(IMAPOPT_EXPUNGE_MODE);
    int immediate = (expunge_mode == IMAP_ENUM_EXPUNGE_MODE_IMMEDIATE ||
                     expunge_mode == IMAP_ENUM_EXPUNGE_MODE_SEMIDELAYED ||
                     mailbox->i.minor_version < 12);
    int changeflags = 0;

    assert(mailbox_index_islocked(mailbox, 1));
    assert(record->recno > 0 &&
           record->recno <= mailbox->i.num_records);

    r = mailbox_read_index_record(mailbox, record->recno, &oldrecord);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: re-reading record failed",
                         "mailbox=<%s> record=<%u>",
                         mailbox->name, record->uid);
        return r;
    }
    mailbox_read_basecid(mailbox, &oldrecord);

    /* OK, we need to decide how to handle basecid.  Three cases here:
     * 1) basecid is already set - keep it
     * 2) basecid is zero, but the system flag says it should be readable, set it from oldrecord
     * 3) basecid is zero, system flag is zero - keep zero
     * we only need code for case #2
     */
    if (!record->basecid && (record->internal_flags & FLAG_INTERNAL_SPLITCONVERSATION))
        record->basecid = oldrecord.basecid;

    if (oldrecord.internal_flags & FLAG_INTERNAL_EXPUNGED)
        changeflags |= CHANGE_WASEXPUNGED;
    if (oldrecord.internal_flags & FLAG_INTERNAL_UNLINKED)
        changeflags |= CHANGE_WASUNLINKED;

    /* the UID has to match, of course, for it to be the same
     * record.  XXX - test fields like "internaldate", etc here
     * too?  Maybe replication should be more strict about it */
    assert(record->uid == oldrecord.uid);
    assert(message_guid_equal(&oldrecord.guid, &record->guid));

    if (oldrecord.internal_flags & FLAG_INTERNAL_EXPUNGED) {
        /* it is a sin to unexpunge a message.  unexpunge.c copies
         * the data from the old record and appends it with a new
         * UID, which is righteous in the eyes of the IMAP client */
        assert(record->internal_flags & FLAG_INTERNAL_EXPUNGED);
    }

    if (oldrecord.internal_flags & FLAG_INTERNAL_ARCHIVED) {
        /* it is also a sin to unarchive a message, except in the
         * the very odd case of a reconstruct.  So let's see about
         * that */
        if (!(record->internal_flags & FLAG_INTERNAL_ARCHIVED))
            xsyslog(LOG_ERR, "IOERROR: bogus removal of archived flag",
                             "mailbox=<%s> record=<%u>",
                             mailbox->name, record->uid);
    }

    /* handle immediate expunges here... */
    if (immediate && (record->internal_flags & FLAG_INTERNAL_EXPUNGED)) {
        record->internal_flags |= FLAG_INTERNAL_UNLINKED | FLAG_INTERNAL_NEEDS_CLEANUP;
    }

    /* make sure highestmodseq gets updated unless we're
     * being silent about it (i.e. marking an already EXPUNGED
     * message as UNLINKED, or just updating the content_lines
     * field or cache_offset) */
    if (record->silentupdate) {
        mailbox_index_dirty(mailbox);
    }
    else {
        mailbox_modseq_dirty(mailbox);
        record->modseq = mailbox->i.highestmodseq;
        record->last_updated = mailbox->last_updated;
    }
    assert(record->modseq >= oldrecord.modseq);

    if (record->internal_flags & FLAG_INTERNAL_UNLINKED) {
        /* mark required actions */
        if (expunge_mode == IMAP_ENUM_EXPUNGE_MODE_IMMEDIATE
            || mailbox->i.minor_version < 12)
            mailbox->i.options |= OPT_MAILBOX_NEEDS_REPACK;
        mailbox->i.options |= OPT_MAILBOX_NEEDS_UNLINK;
    }
    else {
        /* rewrite the cache record if required anyway */
        r = mailbox_append_cache(mailbox, record);
        if (r) return r;
    }

    r = mailbox_update_indexes(mailbox, &oldrecord, record);
    if (r) return r;

    if ((record->internal_flags & FLAG_INTERNAL_EXPUNGED) && !(changeflags & CHANGE_WASEXPUNGED)) {
        if (!mailbox->i.first_expunged || mailbox->i.first_expunged > record->last_updated)
            mailbox->i.first_expunged = record->last_updated;
        mailbox_annot_update_counts(mailbox, &oldrecord, 0);
    }

    r = _store_change(mailbox, record, changeflags);
    if (r) return r;

    if (config_auditlog) {
        char oldflags[FLAGMAPSTR_MAXLEN], sysflags[FLAGMAPSTR_MAXLEN];
        flags_to_str(&oldrecord, oldflags);
        flags_to_str(record, sysflags);
        syslog(LOG_NOTICE, "auditlog: touched sessionid=<%s> "
               "mailbox=<%s> uniqueid=<%s> uid=<%u> guid=<%s> cid=<%s> "
               "modseq=<" MODSEQ_FMT "> oldflags=<%s> sysflags=<%s>",
               session_id(), mailbox->name, mailbox->uniqueid,
               record->uid, message_guid_encode(&record->guid),
               conversation_id_encode(record->cid), record->modseq,
               oldflags, sysflags);
    }

    /* expunged tracking */
    if (record->internal_flags & FLAG_INTERNAL_EXPUNGED && (!mailbox->i.first_expunged || mailbox->i.first_expunged > record->last_updated))
        mailbox->i.first_expunged = record->last_updated;

    return 0;
}

/* append a single message to a mailbox - also updates everything
 * automatically.  These two functions are the ONLY way to modify
 * the contents or tracking fields of a message */
EXPORTED int mailbox_append_index_record(struct mailbox *mailbox,
                                struct index_record *record)
{
    int r;
    struct utimbuf settime;
    uint32_t changeflags = CHANGE_ISAPPEND;

    assert(mailbox_index_islocked(mailbox, 1));

    /* Append MUST be a higher UID than any we've yet seen */
    assert(record->uid > mailbox->i.last_uid)

    /* Append MUST have a message with data */
    assert(record->size);

    /* GUID must not be null */
    assert(!message_guid_isnull(&record->guid));

    /* Check mailbox type size limits */
    if (mailbox->i.exists && !record->ignorelimits) {
        if (mailbox->mbtype & MBTYPE_ADDRESSBOOK) {
            int limit = config_getint(IMAPOPT_MAILBOX_MAXMESSAGES_ADDRESSBOOK);
            if (limit > 0 && limit <= (int)mailbox->i.exists) {
                xsyslog(LOG_ERR, "IOERROR: client hit per-addressbook exists limit",
                                 "mailbox=<%s>",
                                 mailbox->name);
                return IMAP_NO_OVERQUOTA;
            }
        }
        else if (mailbox->mbtype & MBTYPE_CALENDAR) {
            int limit = config_getint(IMAPOPT_MAILBOX_MAXMESSAGES_CALENDAR);
            if (limit > 0 && limit <= (int)mailbox->i.exists) {
                xsyslog(LOG_ERR, "IOERROR: client hit per-calendar exists limit",
                                 "mailbox=<%s>",
                                 mailbox->name);
                return IMAP_NO_OVERQUOTA;
            }
        }
        else if (!mailbox->mbtype) { // default == email
            int limit = config_getint(IMAPOPT_MAILBOX_MAXMESSAGES_EMAIL);
            if (limit > 0 && limit <= (int)mailbox->i.exists) {
                xsyslog(LOG_ERR, "IOERROR: client hit per-mailbox exists limit",
                                 "mailbox=<%s>",
                                 mailbox->name);
                return IMAP_NO_OVERQUOTA;
            }
        }
        else {
            /* no limits for other types defined yet */
        }
    }

    /* belt AND suspenders - check the previous record too */
    if (mailbox->i.num_records) {
        struct index_record prev;
        r = mailbox_read_index_record(mailbox, mailbox->i.num_records, &prev);
        if (r) return r;
        assert(prev.uid <= mailbox->i.last_uid);
        if (message_guid_equal(&prev.guid, &record->guid)) {
            syslog(LOG_INFO, "%s: same message appears twice %u %u",
                   mailbox->name, prev.uid, record->uid);
            /* but it's OK, we won't reject it */
        }
    }

    if (!record->internaldate)
        record->internaldate = time(NULL);
    if (!record->gmtime)
        record->gmtime = record->internaldate;
    if (!record->sentdate) {
        struct tm *tm = localtime(&record->internaldate);
        /* truncate to the day */
        tm->tm_sec = 0;
        tm->tm_min = 0;
        tm->tm_hour = 0;
        record->sentdate = mktime(tm);
    }

    /* update the highestmodseq if needed */
    if (record->silentupdate) {
        mailbox_index_dirty(mailbox);
    }
    else {
        mailbox_modseq_dirty(mailbox);
        record->modseq = mailbox->i.highestmodseq;
        if (!record->createdmodseq || record->createdmodseq > record->modseq)
            record->createdmodseq = record->modseq;
        record->last_updated = mailbox->last_updated;
        if (!record->savedate) {
            // store the time of actual append if requested
            record->savedate = mailbox->last_updated;
        }
    }

    int object_storage_enabled = 0 ;
#if defined ENABLE_OBJECTSTORE
    object_storage_enabled = config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED) ;
#endif

    if (!(record->internal_flags & FLAG_INTERNAL_UNLINKED)) {
        /* make the file timestamp correct */
        settime.actime = settime.modtime = record->internaldate;
        if (!(object_storage_enabled && (record->internal_flags & FLAG_INTERNAL_ARCHIVED)))  // mabe there is no file in directory.
            if (utime(mailbox_record_fname(mailbox, record), &settime) == -1)
                return IMAP_IOERROR;

        /* write the cache record before buffering the message, it
         * will set the cache_offset field. */
        r = mailbox_append_cache(mailbox, record);
        if (r) return r;
    }

    r = mailbox_update_indexes(mailbox, NULL, record);
    if (r) return r;

    record->recno = mailbox->i.num_records + 1;

    mailbox->i.last_uid = record->uid;
    mailbox->i.num_records = record->recno;

    r = _store_change(mailbox, record, changeflags);
    if (r) return r;

    /* expunged tracking */
    if ((record->internal_flags & FLAG_INTERNAL_EXPUNGED) && (!mailbox->i.first_expunged || mailbox->i.first_expunged > record->last_updated))
        mailbox->i.first_expunged = record->last_updated;

    return 0;
}

EXPORTED void mailbox_cleanup_uid(struct mailbox *mailbox, uint32_t uid, const char *flagstr)
{
    const char *spoolfname = mailbox_spool_fname(mailbox, uid);
    const char *archivefname = mailbox_archive_fname(mailbox, uid);

    if (unlink(spoolfname) == 0) {
        if (config_auditlog) {
            syslog(LOG_NOTICE, "auditlog: unlink sessionid=<%s> "
                   "mailbox=<%s> uniqueid=<%s> uid=<%u> sysflags=<%s>",
                   session_id(), mailbox->name, mailbox->uniqueid,
                   uid, flagstr);
        }
    }

    if (strcmp(spoolfname, archivefname)) {
        if (unlink(archivefname) == 0) {
            if (config_auditlog) {
                syslog(LOG_NOTICE, "auditlog: unlinkarchive sessionid=<%s> "
                       "mailbox=<%s> uniqueid=<%s> uid=<%u> sysflags=<%s>",
                       session_id(), mailbox->name, mailbox->uniqueid,
                       uid, flagstr);
            }
        }
    }
}

static void mailbox_record_cleanup(struct mailbox *mailbox,
                                   struct index_record *record)
{
#if defined ENABLE_OBJECTSTORE
    if (config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED)) {
        /* we always remove the spool file here, because we've archived it */
        if (record->system_flags & FLAG_INTERNAL_ARCHIVED)
            unlink(spoolfname);

        /* if the record is also deleted, we remove the objectstore copy */
        if (record->system_flags & FLAG_INTERNAL_UNLINKED)
            objectstore_delete(mailbox, record);

        return;
    }
#endif

    if (record->internal_flags & FLAG_INTERNAL_UNLINKED) {
        char flagstr[FLAGMAPSTR_MAXLEN];
        flags_to_str(record, flagstr);

        /* remove both files */
        mailbox_cleanup_uid(mailbox, record->uid, flagstr);

        int r = mailbox_get_annotate_state(mailbox, record->uid, NULL);
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: failed to open annotations",
                             "mailbox=<%s> record=<%u> error=<%s>",
                             mailbox->name, record->uid, error_message(r));
        }

        r = annotate_msg_cleanup(mailbox, record->uid);
        if (r) {
            xsyslog(LOG_ERR, "IOERROR: failed to cleanup annotations",
                             "mailbox=<%s> record=<%u> error=<%s>",
                             mailbox->name, record->uid, error_message(r));
        }

        return;
    }

    /* file is still alive - check if there's anything to clean up */

    const char *spoolfname = mailbox_spool_fname(mailbox, record->uid);
    const char *archivefname = mailbox_archive_fname(mailbox, record->uid);

    /* don't cleanup if it's the same file! */
    if (strcmp(spoolfname, archivefname)) {
        if (record->internal_flags & FLAG_INTERNAL_ARCHIVED) {
            /* XXX - stat to make sure the other file exists first? - we mostly
            *  trust that we didn't do stupid things everywhere else, so maybe not */
            unlink(spoolfname);
        }

        else {
            unlink(archivefname);
        }
    }
}

/* need a mailbox exclusive lock, we're removing files */
static int mailbox_index_unlink(struct mailbox *mailbox)
{
    syslog(LOG_INFO, "Unlinking files in mailbox %s", mailbox->name);

    /* NOTE: this gets called for two different cases:
     * 1) file is actually ready for unlinking (immediate expunge or
     *    cyr_expire).
     * 2) file has been archived/unarchived, and the other one needs
     *    to be removed.
     */
    const message_t *msg;
    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, 0);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        /* still gotta check for FLAG_INTERNAL_UNLINKED, because it may have been
         * created by old code.  Woot */
        if ((record->internal_flags & FLAG_INTERNAL_NEEDS_CLEANUP) ||
            record->internal_flags & FLAG_INTERNAL_UNLINKED) {
            struct index_record copyrecord = *record;
            mailbox_record_cleanup(mailbox, &copyrecord);
            copyrecord.internal_flags &= ~FLAG_INTERNAL_NEEDS_CLEANUP;
            copyrecord.silentupdate = 1;
            copyrecord.ignorelimits = 1;
            /* XXX - error handling */
            mailbox_rewrite_index_record(mailbox, &copyrecord);
        }
    }
    mailbox_iter_done(&iter);

    /* need to clear the flag, even if nothing needed unlinking! */
    mailbox_index_dirty(mailbox);
    mailbox->i.options &= ~OPT_MAILBOX_NEEDS_UNLINK;
    mailbox_commit(mailbox);

    return 0;
}


static int mailbox_repack_setup(struct mailbox *mailbox, int version,
                                struct mailbox_repack **repackptr)
{
    struct mailbox_repack *repack = xzmalloc(sizeof(struct mailbox_repack));
    const char *fname;
    indexbuffer_t ibuf;
    unsigned char *buf = ibuf.buf;
    int n;

    /* if we're changing version at all, recalculate counts up-front */
    if (version != mailbox->i.minor_version) {
        /* NOTE: this maps in annot_state in mailbox, which will get copied
         * into newmailbox below, which means all the annotate stuff later
         * is going to be good!  The counters will be updated in the original
         * mailbox index, but that's OK because we recalc everything at the
         * end */
        int r = mailbox_index_recalc(mailbox);
        if (r) goto fail;
    }

    /* init */
    repack->mailbox = mailbox;
    repack->crcs = mailbox->i.synccrcs;
    repack->newmailbox = *mailbox; // struct copy
    repack->newmailbox.index_fd = -1;

    /* new files */
    fname = mailbox_meta_newfname(mailbox, META_INDEX);
    repack->newmailbox.index_fd = open(fname, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (repack->newmailbox.index_fd == -1) {
        xsyslog(LOG_ERR, "IOERROR: create failed",
                         "fname=<%s>",
                         fname);
        goto fail;
    }

    /* update the generation number */
    repack->newmailbox.i.generation_no++;

    /* track the version number */
    repack->newmailbox.i.minor_version = version;
    switch (version) {
    case 6:
        repack->newmailbox.i.start_offset = 76;
        repack->newmailbox.i.record_size = 60;
        break;
    case 7:
        repack->newmailbox.i.start_offset = 76;
        repack->newmailbox.i.record_size = 72;
        break;
    case 8:
        repack->newmailbox.i.start_offset = 92;
        repack->newmailbox.i.record_size = 80;
        break;
    case 9:
        repack->newmailbox.i.start_offset = 96;
        repack->newmailbox.i.record_size = 80;
        break;
    case 10:
        repack->newmailbox.i.start_offset = 96;
        repack->newmailbox.i.record_size = 88;
        break;
    /* 11 was FastMail internal */
    case 12:
        repack->newmailbox.i.start_offset = 128;
        repack->newmailbox.i.record_size = 96;
        break;
    case 13:
        repack->newmailbox.i.start_offset = 128;
        repack->newmailbox.i.record_size = 104;
        break;
    case 14:
        /* version 15 just repurposed a field */
    case 15:
        repack->newmailbox.i.start_offset = 160;
        repack->newmailbox.i.record_size = 104;
        break;
    case 16:
    case 17:
        repack->newmailbox.i.start_offset = 160;
        repack->newmailbox.i.record_size = 112;
        break;
    default:
        fatal("index version not supported", EX_SOFTWARE);
    }

    /* upgrades or downgrades across version 12 boundary?  Sort out seen state */
    if (version >= 12 && mailbox->i.minor_version < 12) {
        /* we need to read the current seen state for the owner */
        struct seendata sd = SEENDATA_INITIALIZER;
        int r = IMAP_MAILBOX_NONEXISTENT;
        if (mailbox->i.options & OPT_IMAP_SHAREDSEEN)
            repack->userid = xstrdup("anyone");
        else
            repack->userid = mboxname_to_userid(mailbox->name);

        if (repack->userid) {
            struct seen *seendb = NULL;
            r = seen_open(repack->userid, SEEN_SILENT, &seendb);
            if (!r) r = seen_read(seendb, mailbox->uniqueid, &sd);
            seen_close(&seendb);
        }

        if (!r) {
            repack->newmailbox.i.recentuid = sd.lastuid;
            repack->newmailbox.i.recenttime = sd.lastchange;
            repack->seqset = seqset_parse(sd.seenuids, NULL, sd.lastuid);
            seen_freedata(&sd);
        }
    }
    else if (version < 12 && mailbox->i.minor_version >= 12) {
        if (mailbox->i.options & OPT_IMAP_SHAREDSEEN)
            repack->userid = xstrdup("anyone");
        else
            repack->userid = mboxname_to_userid(mailbox->name);

        /* we need to create the seen state for the owner from the mailbox */
        if (repack->userid)
            repack->seqset = seqset_init(mailbox->i.last_uid, SEQ_MERGE);
    }

    /* we'll count the records as they get added */
    repack->newmailbox.i.num_records = 0;
    /* we're recreating caches, so there'll be nothing leaked */
    repack->newmailbox.i.leaked_cache_records = 0;

    /* prepare initial header buffer */
    mailbox_index_header_to_buf(&repack->newmailbox.i, buf);

    n = retry_write(repack->newmailbox.index_fd, buf, repack->newmailbox.i.start_offset);
    if (n == -1) goto fail;

    if (version != mailbox->i.minor_version) {
        /* we're might be reading this file as we go, so let's
         * start the job by mapping the new file into the newmailbox!
         */
        repack->newmailbox.index_size = 0;
        repack->newmailbox.index_base = NULL;
        repack->newmailbox.index_len = 0;
        int r = mailbox_refresh_index_map(&repack->newmailbox);
        if (r) goto fail;
    }

    *repackptr = repack;
    return 0;

 fail:
    mailbox_repack_abort(&repack);
    return IMAP_IOERROR;
}

static int mailbox_repack_add(struct mailbox_repack *repack,
                              struct index_record *record)
{
    struct mappedfile *cachefile;
    indexbuffer_t ibuf;
    unsigned char *buf = ibuf.buf;
    int r;
    int n;

    cachefile = repack_cachefile(repack, record);

    /* write out the new cache record - need to clear the cache_offset
     * so it gets reset in the new record */
    record->cache_offset = 0;
    r = cache_append_record(cachefile, record);
    if (r) return r;

    /* write the index record out */
    mailbox_index_record_to_buf(record, repack->newmailbox.i.minor_version, buf);
    n = retry_write(repack->newmailbox.index_fd, buf, repack->newmailbox.i.record_size);
    if (n == -1)
        return IMAP_IOERROR;

    repack->newmailbox.i.num_records++;

    return 0;
}

static void mailbox_repack_abort(struct mailbox_repack **repackptr)
{
    struct mailbox_repack *repack = *repackptr;
    int i;

    if (!repack) return; /* safe against double-free */

    seqset_free(repack->seqset);

    /* close and remove index */
    xclose(repack->newmailbox.index_fd);
    unlink(mailbox_meta_newfname(repack->mailbox, META_INDEX));

    /* close and remove all new caches */
    for (i = 0; i < repack->caches.count; i++) {
        struct mappedfile *cachefile = ptrarray_nth(&repack->caches, i);
        char *fname = xstrdup(mappedfile_fname(cachefile));
        mappedfile_commit(cachefile);  /* gotta commit to clear the dirty flag.  Alternative would be an unlink function */
        mappedfile_unlock(cachefile);
        mappedfile_close(&cachefile);
        unlink(fname);
        free(fname);
    }
    ptrarray_fini(&repack->caches);

    // drop the map if we've mapped in the newmailbox index separately
    if (repack->newmailbox.index_base != repack->mailbox->index_base) {
        map_free(&repack->newmailbox.index_base, &repack->newmailbox.index_len);
    }

    mailbox_abort(repack->mailbox);

    free(repack->userid);
    free(repack);
    *repackptr = NULL;

    return;
}

HIDDEN int mailbox_repack_commit(struct mailbox_repack **repackptr)
{
    strarray_t cachefiles = STRARRAY_INITIALIZER;
    indexbuffer_t ibuf;
    unsigned char *buf = ibuf.buf;
    struct mailbox_repack *repack = *repackptr;
    int r = IMAP_IOERROR;
    int i;

    assert(repack);

    /* if we changed versions, we'll re-calculate counts on the new mailbox too */
    if (repack->newmailbox.i.minor_version != repack->mailbox->i.minor_version) {
        r = mailbox_refresh_index_map(&repack->newmailbox);
        if (r) goto fail;
        r = mailbox_index_recalc(&repack->newmailbox);
        if (r) goto fail;
    }

    if (repack->newmailbox.i.minor_version >= 10 &&
            repack->mailbox->i.minor_version >= 10 &&
            !mailbox_crceq(repack->newmailbox.i.synccrcs, repack->crcs)) {
        xsyslog(LOG_ERR, "IOERROR: CRC mismatch on repack commit",
                         "mailbox=<%s> oldbasic=<%u> newbasic=<%u> "
                             "oldannot=<%u> newannot=<%u>",
                         repack->mailbox->name,
                         repack->crcs.basic, repack->newmailbox.i.synccrcs.basic,
                         repack->crcs.annot, repack->newmailbox.i.synccrcs.annot);
        r = IMAP_MAILBOX_CHECKSUM;
        goto fail;
    }

    repack->newmailbox.i.last_repack_time = time(0);

    if (repack->mailbox->i.minor_version >= 12 && repack->newmailbox.i.minor_version < 12
        && repack->seqset && repack->userid) {
        struct seendata sd = SEENDATA_INITIALIZER;
        struct seen *seendb = NULL;
        int r = seen_open(repack->userid, SEEN_CREATE, &seendb);
        if (!r) r = seen_lockread(seendb, repack->mailbox->uniqueid, &sd);
        if (!r) {
            sd.lastuid = repack->newmailbox.i.last_uid;
            sd.seenuids = seqset_cstring(repack->seqset);
            if (!sd.seenuids) sd.seenuids = xstrdup("");
            sd.lastread = time(NULL);
            sd.lastchange = repack->newmailbox.i.last_appenddate;
            r = seen_write(seendb, repack->mailbox->uniqueid, &sd);
            /* XXX - syslog on errors? */
        }
        seen_close(&seendb);
        seen_freedata(&sd);
    }

    /* rewrite the header with updated details */
    mailbox_index_header_to_buf(&repack->newmailbox.i, buf);

    if (lseek(repack->newmailbox.index_fd, 0, SEEK_SET) < 0)
        goto fail;

    if (retry_write(repack->newmailbox.index_fd, buf, repack->newmailbox.i.start_offset) < 0)
        goto fail;

    /* ensure everything is committed to disk */
    if (fsync(repack->newmailbox.index_fd) < 0)
        goto fail;

    xclose(repack->newmailbox.index_fd);

    /* NOTE: cache files need committing before index is renamed */
    for (i = 0; i < repack->caches.count; i++) {
        struct mappedfile *cachefile = ptrarray_nth(&repack->caches, i);
        r = mappedfile_commit(cachefile);
        if (r) goto fail;
    }

    /* rename index first - loader will handle un-renamed cache if
     * the generation is lower */
    r = mailbox_meta_rename(repack->mailbox, META_INDEX);
    if (r) goto fail;

    /* which cache files might currently exist? */
    strarray_add(&cachefiles, mailbox_meta_fname(repack->mailbox, META_CACHE));
    strarray_add(&cachefiles, mailbox_meta_fname(repack->mailbox, META_ARCHIVECACHE));

    /* now the cache files can be renamed */
    for (i = 0; i < repack->caches.count; i++) {
        struct mappedfile *cachefile = ptrarray_nth(&repack->caches, i);
        char *newname = xstrdup(mappedfile_fname(cachefile));
        size_t len = strlen(newname)-4;
        assert(!strcmp(newname+len, ".NEW"));
        newname[len] = '\0'; /* STRIP .NEW */
        mappedfile_rename(cachefile, newname);
        mappedfile_close(&cachefile);
        strarray_remove_all(&cachefiles, newname);
        free(newname);
    }
    ptrarray_fini(&repack->caches);

    for (i = 0; i < cachefiles.count; i++) {
        const char *fname = strarray_nth(&cachefiles, i);
        if (!unlink(fname))
            syslog(LOG_NOTICE, "Removed unused cache file %s", fname);
    }

    strarray_fini(&cachefiles);

    // drop the map if we've mapped in the newmailbox index separately
    if (repack->newmailbox.index_base != repack->mailbox->index_base) {
        map_free(&repack->newmailbox.index_base, &repack->newmailbox.index_len);
    }

    seqset_free(repack->seqset);
    free(repack->userid);
    free(repack);
    *repackptr = NULL;
    return 0;

 fail:
    strarray_fini(&cachefiles);
    mailbox_repack_abort(repackptr);
    if (!r) r = IMAP_IOERROR;
    return r;
}

/* need a mailbox exclusive lock, we're rewriting files */
static int mailbox_index_repack(struct mailbox *mailbox, int version)
{
    struct mailbox_repack *repack = NULL;
    const message_t *msg;
    struct mailbox_iter *iter = NULL;
    struct buf buf = BUF_INITIALIZER;
    int r = IMAP_IOERROR;

    syslog(LOG_INFO, "Repacking mailbox %s version %d", mailbox->name, version);

    r = mailbox_repack_setup(mailbox, version, &repack);
    if (r) goto done;

    iter = mailbox_iter_init(mailbox, 0, 0);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        struct index_record copyrecord = *record;
        int needs_cache_upgrade = 0;
        annotate_state_t *astate = NULL;

        r = mailbox_get_annotate_state(mailbox, record->uid, &astate);
        if (r) goto done;

        /* version changes? */
        if (mailbox->i.minor_version < 12 && repack->newmailbox.i.minor_version >= 12) {
            if (seqset_ismember(repack->seqset, copyrecord.uid))
                copyrecord.system_flags |= FLAG_SEEN;
            else
                copyrecord.system_flags &= ~FLAG_SEEN;

            needs_cache_upgrade = 1;

        }
        if (mailbox->i.minor_version >= 12 && repack->newmailbox.i.minor_version < 12) {
            if (repack->seqset)
                seqset_add(repack->seqset, copyrecord.uid, copyrecord.system_flags & FLAG_SEEN ? 1 : 0);
            copyrecord.system_flags &= ~FLAG_SEEN;
        }

        /* force cache upgrade across version 15 repack */
        if (repack->newmailbox.i.minor_version >= 15 && record->cache_version < 9)
            needs_cache_upgrade = 1;

        /* better handle the cleanup just in case it's unlinked too */
        /* still gotta check for FLAG_INTERNAL_UNLINKED, because it may have been
         * created by old code.  Woot */
        if (copyrecord.internal_flags & (FLAG_INTERNAL_NEEDS_CLEANUP | FLAG_INTERNAL_UNLINKED)) {
            mailbox_record_cleanup(mailbox, &copyrecord);
            copyrecord.internal_flags &= ~FLAG_INTERNAL_NEEDS_CLEANUP;
            /* no need to rewrite - it's already being written to the new file */
        }

        /* we aren't keeping unlinked files, that's kind of the point */
        if (copyrecord.internal_flags & FLAG_INTERNAL_UNLINKED) {
            /* track the modseq for QRESYNC purposes */
            if (copyrecord.modseq > repack->newmailbox.i.deletedmodseq) {
                repack->newmailbox.i.deletedmodseq = copyrecord.modseq;
                repack->newmailbox.i.changes_epoch = copyrecord.last_updated;
            }
            continue;
        }

        if (needs_cache_upgrade) {
            const char *fname = mailbox_record_fname(mailbox, &copyrecord);

            if (message_parse(fname, &copyrecord)) {
                /* failed to parse, don't try to write out record */
                copyrecord.crec.len = 0;
                /* and the record is expunged too! */
                copyrecord.internal_flags |= FLAG_INTERNAL_EXPUNGED | FLAG_INTERNAL_UNLINKED;
                xsyslog(LOG_ERR, "IOERROR: FATAL - failed to parse file, expunging",
                                 "mailbox=<%s> record=<%u>",
                                 repack->mailbox->name, copyrecord.uid);
            }
        }

        /* virtual annotations */
        if (mailbox->i.minor_version < 13 && repack->newmailbox.i.minor_version >= 13) {
            /* extract CID */
            buf_reset(&buf);
            mailbox_annotation_lookup(mailbox, record->uid, IMAP_ANNOT_NS "thrid", "", &buf);
            if (buf.len == 16) {
                const char *p = buf_cstring(&buf);
                parsehex(p, &p, 16, &copyrecord.cid);
            }
            buf_reset(&buf);
            r = annotate_state_writesilent(astate, IMAP_ANNOT_NS "thrid", "", &buf);
            if (r) goto done;
        }
        if (mailbox->i.minor_version >= 13 && repack->newmailbox.i.minor_version < 13) {
            if (record->cid) {
                buf_reset(&buf);
                buf_printf(&buf, "%llx", record->cid);
                r = annotate_state_writesilent(astate, IMAP_ANNOT_NS "thrid", "", &buf);
                if (r) goto done;
            }
        }

        if (mailbox->i.minor_version < 15 && repack->newmailbox.i.minor_version >= 15) {
            /* extract CID */
            buf_reset(&buf);
            mailbox_annotation_lookup(mailbox, record->uid, IMAP_ANNOT_NS "savedate", "", &buf);
            if (buf.len) {
                const char *p = buf_cstring(&buf);
                bit64 newval;
                parsenum(p, &p, 0, &newval);
                copyrecord.savedate = newval;
            }
            buf_reset(&buf);
            r = annotate_state_writesilent(astate, IMAP_ANNOT_NS "savedate", "", &buf);
            if (r) goto done;
        }
        if (mailbox->i.minor_version >= 15 && repack->newmailbox.i.minor_version < 15) {
            if (record->savedate) {
                buf_reset(&buf);
                buf_printf(&buf, TIME_T_FMT, record->savedate);
                r = annotate_state_writesilent(astate, IMAP_ANNOT_NS "savedate", "", &buf);
                if (r) goto done;
            }
        }

        if (mailbox->i.minor_version < 16 && repack->newmailbox.i.minor_version >= 16) {
            /* extract CID */
            buf_reset(&buf);
            mailbox_annotation_lookup(mailbox, record->uid, IMAP_ANNOT_NS "createdmodseq", "", &buf);
            if (buf.len) {
                const char *p = buf_cstring(&buf);
                bit64 newval;
                parsenum(p, &p, 0, &newval);
                copyrecord.createdmodseq = newval;
            }
            buf_reset(&buf);
            r = annotate_state_writesilent(astate, IMAP_ANNOT_NS "createdmodseq", "", &buf);
            if (r) goto done;
        }
        if (mailbox->i.minor_version >= 16 && repack->newmailbox.i.minor_version < 16) {
            if (record->createdmodseq) {
                buf_reset(&buf);
                buf_printf(&buf, "%llu", record->createdmodseq);
                r = annotate_state_writesilent(astate, IMAP_ANNOT_NS "createdmodseq", "", &buf);
                if (r) goto done;
            }
        }

        /* read in the old cache record */
        r = mailbox_cacherecord(mailbox, &copyrecord);
        if (r) goto done;

        r = mailbox_repack_add(repack, &copyrecord);
        if (r) goto done;
    }

    /* we unlinked any "needs unlink" in the process */
    repack->newmailbox.i.options &= ~(OPT_MAILBOX_NEEDS_REPACK|OPT_MAILBOX_NEEDS_UNLINK);

done:
    mailbox_iter_done(&iter);
    buf_free(&buf);
    if (r) mailbox_repack_abort(&repack);
    else {
        modseq_t deletedmodseq = repack->newmailbox.i.deletedmodseq;

        r = mailbox_repack_commit(&repack);
        if (!r) {
            mboxname_setmodseq(mailbox->name, deletedmodseq, mailbox->mbtype,
                               MBOXMODSEQ_ISDELETE);
        }
    }       

    return r;
}

/*
 * Used by mailbox_rename() to expunge all messages in INBOX
 */
static unsigned expungeall(struct mailbox *mailbox __attribute__((unused)),
                           const struct index_record *record __attribute__((unused)),
                           void *rock __attribute__((unused)))
{
    return 1;
}

/*
 * Expunge decision proc used by mailbox_expunge()
 * to expunge \Deleted messages.
 */
static unsigned expungedeleted(struct mailbox *mailbox __attribute__((unused)),
                               const struct index_record *record,
                               void *rock __attribute__((unused)))
{
    if (record->system_flags & FLAG_DELETED)
        return 1;

    return 0;
}

EXPORTED unsigned mailbox_should_archive(struct mailbox *mailbox,
                                         const struct index_record *record,
                                         void *rock)
{
    int archive_after = config_getduration(IMAPOPT_ARCHIVE_AFTER, 'd');
    time_t cutoff = time(0) - archive_after;
    if (rock) cutoff = *((time_t *)rock);

    int archive_size = config_getint(IMAPOPT_ARCHIVE_MAXSIZE);
    size_t maxsize = archive_size * 1024;

    int keepflagged = config_getswitch(IMAPOPT_ARCHIVE_KEEPFLAGGED);

    /* never pull messages back from the archives */
    if (record->internal_flags & FLAG_INTERNAL_ARCHIVED)
        return 1;

    /* first check if we're archiving anything */
    if (!config_getswitch(IMAPOPT_ARCHIVE_ENABLED))
        return 0;

    /* always archive big messages */
    if (record->size >= maxsize)
        return 1;

    /* archive everything in DELETED mailboxes */
    if (mboxname_isdeletedmailbox(mailbox->name, NULL))
        return 1;

    /* Calendar and Addressbook are small files and need to be hot */
    switch (mbtype_isa(mailbox->mbtype)) {
    case MBTYPE_ADDRESSBOOK:
        return 0;
    case MBTYPE_CALENDAR:
        return 0;
    }

    /* don't archive flagged messages */
    if (keepflagged && (record->system_flags & FLAG_FLAGGED))
        return 0;

    /* archive all other old messages */
    if (record->internaldate <= cutoff)
        return 1;

    /* and don't archive anything else! */
    return 0;
}

/*
 * Move messages between spool and archive partition
 * function pointed to by 'decideproc' is called (with 'deciderock') to
 * determine which messages to move.  If deciderock return 0, the message
 * should be in the spool - if 1, the message should be in the archive.
 */
EXPORTED void mailbox_archive(struct mailbox *mailbox,
                              mailbox_decideproc_t *decideproc, void *deciderock, unsigned flags)

{
    int r;
    int dirtycache = 0;
    const message_t *msg;
    struct index_record copyrecord;
    const char *srcname;
    const char *destname;
    char *spoolcache = xstrdup(mailbox_meta_fname(mailbox, META_CACHE));
    char *archivecache = xstrdup(mailbox_meta_fname(mailbox, META_ARCHIVECACHE));
    int differentcache = strcmp(spoolcache, archivecache);
    int object_storage_enabled = 0;
#if defined ENABLE_OBJECTSTORE
    object_storage_enabled = config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED) ;
#endif
    free(spoolcache);
    free(archivecache);

    assert(mailbox_index_islocked(mailbox, 1));
    if (!decideproc) decideproc = &mailbox_should_archive;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, flags);

    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        const char *action = NULL;
        if (decideproc(mailbox, record, deciderock)) {
            if (record->internal_flags & FLAG_INTERNAL_ARCHIVED)
                continue;
            copyrecord = *record;
            srcname = mailbox_spool_fname(mailbox, copyrecord.uid);
            destname = mailbox_archive_fname(mailbox, copyrecord.uid);

            /* load cache before changing the flags */
            r = mailbox_cacherecord(mailbox, &copyrecord);
            if (r) {
                xsyslog(LOG_ERR, "IOERROR: failed to read cache",
                                 "mailbox=<%s> record=<%u> error=<%s>",
                                 mailbox->name, copyrecord.uid, error_message(r));
                continue;
            }
#if defined ENABLE_OBJECTSTORE
            if (object_storage_enabled){
                /* upload on the blob store */
                r = objectstore_put(mailbox, &copyrecord, srcname);
                if (r) {
                    xsyslog(LOG_ERR, "IOERROR: objectstorage put failed",
                                     "mailbox=<%s> record=<%u> "
                                        "srcname=<%s> error=<%s>",
                                     mailbox->name, copyrecord.uid,
                                     srcname, error_message(r));
                    // didn't manage to store it, so remove the ARCHIVED flag
                    continue;
                }
                r = unlink (srcname);
                if (r < 0)
                    syslog(LOG_ERR, "unlink(%s) failed: %m", srcname);
            }
#endif
            copyrecord.internal_flags |= FLAG_INTERNAL_ARCHIVED | FLAG_INTERNAL_NEEDS_CLEANUP;
            action = "archive";
        }
        else
        {
            if (!(record->internal_flags & FLAG_INTERNAL_ARCHIVED))
                continue;
            copyrecord = *record;
            destname = mailbox_spool_fname(mailbox, copyrecord.uid);
            srcname = mailbox_archive_fname(mailbox, copyrecord.uid);

            /* load cache before changing the flags */
            r = mailbox_cacherecord(mailbox, &copyrecord);
            if (r) {
                xsyslog(LOG_ERR, "IOERROR: failed to read cache",
                                 "mailbox=<%s> record=<%u> error=<%s>",
                                 mailbox->name, copyrecord.uid, error_message(r));
                continue;
            }

#if defined ENABLE_OBJECTSTORE
            if (object_storage_enabled){
                /* recover from the blob store */
                r = objectstore_get(mailbox, &copyrecord, destname);
                if (r) {
                    xsyslog(LOG_ERR, "IOERROR: objectstorage get failed",
                                     "mailbox=<%s> record=<%u> "
                                        "destname=<%s> error=<%s>",
                                     mailbox->name, copyrecord.uid,
                                     destname, error_message(r));
                    continue;
                }
                objectstore_delete(mailbox, &copyrecord); // this should only lower ref count.
            }
#endif

            copyrecord.internal_flags &= ~FLAG_INTERNAL_ARCHIVED;
            copyrecord.internal_flags |= FLAG_INTERNAL_NEEDS_CLEANUP;
            action = "unarchive";
        }

        if (!object_storage_enabled){
            /* got a file to copy! */
            if (strcmp(srcname, destname)) {
                r = cyrus_copyfile(srcname, destname, COPYFILE_MKDIR|COPYFILE_KEEPTIME);
                if (r) {
                    xsyslog(LOG_ERR, "IOERROR: copyfile failed",
                                     "mailbox=<%s> record=<%u> "
                                        "srcname=<%s> destname=<%s> error=<%s>",
                                     mailbox->name, copyrecord.uid,
                                     srcname, destname, error_message(r));
                    continue;
                }
            }
        }

        /* got a new cache record to write */
        if (differentcache)
        {
            dirtycache = 1;
            copyrecord.cache_offset = 0;
            if (mailbox_append_cache(mailbox, &copyrecord))
                continue;
        }

        /* rewrite the index record */
        copyrecord.silentupdate = 1;
        copyrecord.ignorelimits = 1;
        if (mailbox_rewrite_index_record(mailbox, &copyrecord))
            continue;
        mailbox->i.options |= OPT_MAILBOX_NEEDS_UNLINK;

        if (config_auditlog) {
            char flagstr[FLAGMAPSTR_MAXLEN];
            flags_to_str(&copyrecord, flagstr);
            syslog(LOG_NOTICE, "auditlog: %s sessionid=<%s> mailbox=<%s> "
                   "uniqueid=<%s> uid=<%u> guid=<%s> cid=<%s> sysflags=<%s>",
                   action, session_id(), mailbox->name, mailbox->uniqueid,
                   copyrecord.uid, message_guid_encode(&copyrecord.guid),
                   conversation_id_encode(copyrecord.cid), flagstr);
        }
    }
    mailbox_iter_done(&iter);

    /* if we have stale cache records, we'll need a repack */
    if (dirtycache) {
        mailbox_index_dirty(mailbox);
        mailbox->i.options |= OPT_MAILBOX_NEEDS_REPACK;
    }
}

EXPORTED void mailbox_remove_files_from_object_storage(struct mailbox *mailbox,
                              unsigned flags)

{
    const message_t *msg;
#if defined ENABLE_OBJECTSTORE
    int object_storage_enabled = config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED) ;
#endif

    assert(mailbox_index_islocked(mailbox, 1));
    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, flags);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        if (!(record->internal_flags & FLAG_INTERNAL_ARCHIVED))
            continue;
#if defined ENABLE_OBJECTSTORE
        if (object_storage_enabled)
            objectstore_delete(mailbox, record);  // this should only lower ref count.
#endif
    }
    mailbox_iter_done(&iter);
}


/*
 * Perform an expunge operation on 'mailbox'.  If nonzero, the
 * function pointed to by 'decideproc' is called (with 'deciderock') to
 * determine which messages to expunge.  If 'decideproc' is a null pointer,
 * then messages with the \Deleted flag are expunged.
 *
 *      event_type - the event among MessageExpunge, MessageExpire (zero means
 *                   don't send notification)
 */
EXPORTED int mailbox_expunge(struct mailbox *mailbox,
                    mailbox_decideproc_t *decideproc, void *deciderock,
                    unsigned *nexpunged, int event_type)
{
    int r = 0;
    int numexpunged = 0;
    const message_t *msg;
    struct mboxevent *mboxevent = NULL;

    assert(mailbox_index_islocked(mailbox, 1));

    /* anything to do? */
    if (!mailbox->i.num_records) {
        if (nexpunged) *nexpunged = 0;
        return 0;
    }

    if (event_type)
        mboxevent = mboxevent_new(event_type);

    if (!decideproc) decideproc = expungedeleted;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        if (decideproc(mailbox, record, deciderock)) {
            numexpunged++;

            struct index_record copyrecord = *record;
            /* mark deleted */
            copyrecord.internal_flags |= FLAG_INTERNAL_EXPUNGED;

            r = mailbox_rewrite_index_record(mailbox, &copyrecord);
            if (r) {
                mboxevent_free(&mboxevent);
                mailbox_iter_done(&iter);
                return IMAP_IOERROR;
            }

            mboxevent_extract_record(mboxevent, mailbox, &copyrecord);
        }
    }
    mailbox_iter_done(&iter);

    if (numexpunged > 0) {
        syslog(LOG_NOTICE, "Expunged %d messages from %s",
               numexpunged, mailbox->name);

        /* send the MessageExpunge or MessageExpire event notification */
        mboxevent_extract_mailbox(mboxevent, mailbox);
        mboxevent_set_access(mboxevent, NULL, NULL, "", mailbox->name, 0);
        mboxevent_set_numunseen(mboxevent, mailbox, -1);
        mboxevent_notify(&mboxevent);
    }
    mboxevent_free(&mboxevent);

    if (nexpunged) *nexpunged = numexpunged;

    return 0;
}

EXPORTED int mailbox_expunge_cleanup(struct mailbox *mailbox, time_t expunge_mark,
                            unsigned *ndeleted)
{
    int dirty = 0;
    unsigned numdeleted = 0;
    const message_t *msg;
    time_t first_expunged = 0;
    int r = 0;

    /* run the actual expunge phase */
    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, 0);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        /* already unlinked, skip it (but dirty so we mark a repack is needed) */
        if (record->internal_flags & FLAG_INTERNAL_UNLINKED) {
            dirty = 1;
            continue;
        }

        /* not actually expunged, skip it */
        if (!(record->internal_flags & FLAG_INTERNAL_EXPUNGED))
            continue;

        /* not stale enough yet, skip it - but track the updated time
         * so we know when to run again */
        if (record->last_updated > expunge_mark) {
            if (!first_expunged || (first_expunged > record->last_updated))
                first_expunged = record->last_updated;
            continue;
        }

        dirty = 1;

        numdeleted++;

        struct index_record copyrecord = *record;
        copyrecord.internal_flags |= FLAG_INTERNAL_UNLINKED;
        copyrecord.silentupdate = 1;
        copyrecord.ignorelimits = 1;
        if (mailbox_rewrite_index_record(mailbox, &copyrecord)) {
            xsyslog(LOG_ERR, "IOERROR: failed to mark unlinked",
                             "mailbox=<%s> uid=<%u> recno=<%u>",
                             mailbox->name, copyrecord.uid, copyrecord.recno);
            break;
        }
    }
    mailbox_iter_done(&iter);

    if (dirty) {
        mailbox_index_dirty(mailbox);
        mailbox->i.options |= OPT_MAILBOX_NEEDS_REPACK;
        mailbox->i.first_expunged = first_expunged;
    }

    if (ndeleted) *ndeleted = numdeleted;

    return r;
}

EXPORTED int mailbox_internal_seen(const struct mailbox *mailbox, const char *userid)
{
    /* old mailboxes don't have internal seen at all */
    if (mailbox->i.minor_version < 12)
        return 0;

    /* shared seen - everyone's state is internal */
    if (mailbox->i.options & OPT_IMAP_SHAREDSEEN)
        return 1;

    /* no username => use internal as well */
    if (!userid)
        return 1;

    /* otherwise the owner's seen state is internal */
    return mboxname_userownsmailbox(userid, mailbox->name);
}

/*
 * Return the number of message without \Seen flag in a mailbox.
 * Suppose that authenticated user is the owner or sharedseen is enabled
 */
unsigned mailbox_count_unseen(struct mailbox *mailbox)
{
    assert(mailbox_index_islocked(mailbox, 0));

    if (mailbox->i.minor_version > 13)
        return mailbox->i.unseen;

    const message_t *msg;
    unsigned count = 0;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_EXPUNGED);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        if (!(record->system_flags & FLAG_SEEN))
            count++;
    }
    mailbox_iter_done(&iter);

    return count;
}

/* returns a mailbox locked in MAILBOX EXCLUSIVE mode, so you
 * don't need to lock the index file to work with it :) */
EXPORTED int mailbox_create(const char *name,
                   uint32_t mbtype,
                   const char *part,
                   const char *acl,
                   const char *uniqueid,
                   int options,
                   unsigned uidvalidity,
                   modseq_t createdmodseq,
                   modseq_t highestmodseq,
                   struct mailbox **mailboxptr)
{
    int r = 0;
    char quotaroot[MAX_MAILBOX_BUFFER];
    int hasquota;
    const char *fname;
    struct mailbox *mailbox = NULL;
    int n;
    int createfnames[] = { META_INDEX, META_HEADER, 0 };
    struct mailboxlist *listitem;

    if (!uniqueid) uniqueid = makeuuid();

    /* if we already have this name open then that's an error too */
    listitem = find_listitem(name);
    if (listitem) return IMAP_MAILBOX_LOCKED;

    listitem = create_listitem(name);
    mailbox = &listitem->m;

    /* needs to be an exclusive namelock to create a mailbox */
    char *userid = mboxname_to_userid(name);
    if (userid) {
        int haslock = user_isnamespacelocked(userid);
        if (haslock) {
            assert(haslock != LOCK_SHARED);
        }
        else {
            mailbox->local_namespacelock = user_namespacelock_full(userid, LOCK_EXCLUSIVE);
        }
        free(userid);
    }

    r = mboxname_lock(name, &listitem->l, LOCK_EXCLUSIVE);
    if (r) goto done;

    mailbox->part = xstrdup(part);
    mailbox->acl = xstrdup(acl);
    mailbox->mbtype = mbtype;
    mailbox->uniqueid = xstrdup(uniqueid);
    // if we've been given a highestmodseq, we don't update it
    if (highestmodseq) mailbox->silentchanges = 1;

    hasquota = quota_findroot(quotaroot, sizeof(quotaroot), name);

    /* ensure all paths exist */
    for (n = 0; createfnames[n]; n++) {
        fname = mailbox_meta_fname(mailbox, createfnames[n]);
        if (!fname) {
            xsyslog(LOG_ERR, "IOERROR: Mailbox name too long",
                             "mailbox=<%s>",
                             mailbox->name);
            r = IMAP_MAILBOX_BADNAME;
            goto done;
        }
        if (cyrus_mkdir(fname, 0755) == -1) {
            xsyslog(LOG_ERR, "IOERROR: mkdir failed",
                             "fname=<%s>",
                             fname);
            r = IMAP_IOERROR;
            goto done;
        }
    }

    /* ensure we can fit the longest possible file name */
    fname = mailbox_datapath(mailbox, 0);
    if (!fname) {
        xsyslog(LOG_ERR, "IOERROR: Mailbox name too long",
                         "mailbox=<%s>",
                         mailbox->name);
        r = IMAP_MAILBOX_BADNAME;
        goto done;
    }
    /* and create the directory too :) */
    if (cyrus_mkdir(fname, 0755) == -1) {
        xsyslog(LOG_ERR, "IOERROR: mkdir failed",
                         "fname=<%s>",
                         fname);
        r = IMAP_IOERROR;
        goto done;
    }

    fname = mailbox_meta_fname(mailbox, META_INDEX);
    if (!fname) {
        xsyslog(LOG_ERR, "IOERROR: Mailbox name too long",
                         "mailbox=<%s>",
                         mailbox->name);
        r = IMAP_MAILBOX_BADNAME;
        goto done;
    }
    mailbox->index_fd = open(fname, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (mailbox->index_fd == -1) {
        xsyslog(LOG_ERR, "IOERROR: create index failed",
                         "fname=<%s>",
                         fname);
        r = IMAP_IOERROR;
        goto done;
    }
    r = lock_blocking(mailbox->index_fd, fname);
    if (r) {
        xsyslog(LOG_ERR, "IOERROR: lock index failed",
                         "fname=<%s>",
                         fname);
        r = IMAP_IOERROR;
        goto done;
    }
    mailbox->index_locktype = LOCK_EXCLUSIVE;

    if (hasquota) {
        mailbox_set_quotaroot(mailbox, quotaroot);
        memset(mailbox->quota_previously_used, 0, sizeof(mailbox->quota_previously_used));
        mailbox->quota_dirty = 1;
    }

    /* ensure a UIDVALIDITY is set */
    if (!uidvalidity)
        uidvalidity = mboxname_nextuidvalidity(name, time(0));
    else
        mboxname_setuidvalidity(mailbox->name, uidvalidity);

    /* and highest modseq */
    if (!highestmodseq)
        highestmodseq = mboxname_nextmodseq(mailbox->name, 0, mbtype,
                                            MBOXMODSEQ_ISFOLDER);
    else
        mboxname_setmodseq(mailbox->name, highestmodseq, mbtype,
                           MBOXMODSEQ_ISFOLDER);

    /* and created modseq */
    if (!createdmodseq || createdmodseq > highestmodseq)
        createdmodseq = highestmodseq;

    /* init non-zero fields */
    mailbox_index_dirty(mailbox);
    mailbox->i.minor_version = MAILBOX_MINOR_VERSION;
    mailbox->i.start_offset = INDEX_HEADER_SIZE;
    mailbox->i.record_size = INDEX_RECORD_SIZE;
    mailbox->i.options = options;
    mailbox->i.uidvalidity = uidvalidity;
    mailbox->i.createdmodseq = createdmodseq;
    mailbox->i.highestmodseq = highestmodseq;
    mailbox->i.changes_epoch = time(0);
    mailbox->i.synccrcs.basic = CRC_INIT_BASIC;
    mailbox->i.synccrcs.annot = CRC_INIT_ANNOT;

    /* initialise header size field so appends calculate the
     * correct map size */
    mailbox->index_size = INDEX_HEADER_SIZE;

    mailbox->header_dirty = 1;

    r = seen_create_mailbox(NULL, mailbox);
    if (r) goto done;
    r = mailbox_commit(mailbox);
    if (r) goto done;

    if (config_auditlog)
        syslog(LOG_NOTICE, "auditlog: create sessionid=<%s> "
                           "mailbox=<%s> uniqueid=<%s> uidvalidity=<%u>",
                           session_id(), mailbox->name,
                           mailbox->uniqueid, mailbox->i.uidvalidity);

done:
    if (!r && mailboxptr)
        *mailboxptr = mailbox;
    else
        mailbox_close(&mailbox);

    return r;
}

/*
 * Remove all files in directory
 */
static void mailbox_delete_files(const char *path)
{
    DIR *dirp;
    struct dirent *f;
    char buf[MAX_MAILBOX_PATH+1];
    char *tail;

    strlcpy(buf, path, sizeof(buf));

    if (strlen(buf) >= sizeof(buf) - 2) {
        xsyslog(LOG_ERR, "IOERROR: path too long",
                         "buf=<%s>",
                         buf);
        fatal("path too long", EX_OSFILE);
    }

    tail = buf + strlen(buf);
    *tail++ = '/';
    *tail = '\0';
    dirp = opendir(path);
    if (dirp) {
        while ((f = readdir(dirp))!=NULL) {
            if (f->d_name[0] == '.'
                && (f->d_name[1] == '\0'
                    || (f->d_name[1] == '.' &&
                        f->d_name[2] == '\0'))) {
                /* readdir() can return "." or "..", and I got a bug report
                   that SCO might blow the file system to smithereens if we
                   unlink("..").  Let's not do that. */
                continue;
            }

            if(strlen(buf) + strlen(f->d_name) >= sizeof(buf)) {
                xsyslog(LOG_ERR, "IOERROR: path too long",
                                 "buf=<%s> d_name=<%s>",
                                 buf, f->d_name);
                fatal("Path too long", EX_OSFILE);
            }
            strcpy(tail, f->d_name);
            unlink(buf);
            *tail = '\0';
        }
        closedir(dirp);
    }
}

/* Callback for use by cmd_delete */
static int chkchildren(const mbentry_t *mbentry,
                       void *rock)
{
    const char *part = (const char *)rock;

    if (!strcmpnull(part, mbentry->partition))
        return CYRUSDB_DONE;

    return 0;
}

#ifdef WITH_DAV
EXPORTED int mailbox_add_dav(struct mailbox *mailbox)
{
    const message_t *msg;
    int r = 0;

    if (!mbtypes_dav(mailbox->mbtype))
        return 0;

    if (mboxname_isdeletedmailbox(mailbox->name, NULL))
        return 0;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        r = mailbox_update_dav(mailbox, NULL, record);
        if (r) break;
    }
    mailbox_iter_done(&iter);

    return r;
}

#endif /* WITH_DAV */

EXPORTED int mailbox_add_conversations(struct mailbox *mailbox, int silent)
{
    const message_t *msg;
    int r = 0;

    struct conversations_state *cstate = mailbox_get_cstate(mailbox);

    if (!cstate) return 0;

    /* add record for mailbox */
    conv_status_t status = CONV_STATUS_INIT;
    status.threadmodseq = mailbox->i.highestmodseq;
    r = conversation_setstatus(cstate,
                               CONV_FOLDER_KEY_MBOX(cstate, mailbox), &status);
    if (r) return r;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        /* not assigned, skip */
        if (!record->cid)
            continue;

        struct index_record copyrecord = *record;
        copyrecord.silentupdate = silent;
        r = conversations_update_record(cstate, mailbox, NULL, &copyrecord, 1,
                                        /*ignorelimits*/1);
        if (r) break;

        if (copyrecord.cid == record->cid)
            continue;

        assert(!silent); // can't change cid if silent!

        /* remove this record again */
        r = conversations_update_record(cstate, mailbox, &copyrecord, NULL, 0,
                                        /*ignorelimits*/1);
        if (r) break;

        /* we had a cid change, so rewrite will try to correct the counts, so we
         * need to add this one in again */
        struct index_record oldrecord = *record;
        /* add the old record that's going away */
        r = conversations_update_record(cstate, mailbox, NULL, &oldrecord, 0,
                                        /*ignorelimits*/1);
        if (r) break;

        /* and finally to the update that will reverse those two actions again */
        r = mailbox_rewrite_index_record(mailbox, &copyrecord);
        if (r) break;
    }
    mailbox_iter_done(&iter);

    return r;
}

static int mailbox_delete_conversations(struct mailbox *mailbox)
{
    struct conversations_state *cstate = mailbox_get_cstate(mailbox);
    const message_t *msg;
    int r = 0;

    if (!cstate) return 0;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        /* not assigned, skip */
        if (!record->cid)
            continue;

        r = conversations_update_record(cstate, mailbox, record, NULL,
                                        /*allowrenumber*/0, /*ignorelimits*/1);
        if (r) break;
    }
    mailbox_iter_done(&iter);
    if (r) return r;

    return conversations_rename_folder(cstate, mailbox->name, NULL);
}

static int mailbox_delete_internal(struct mailbox **mailboxptr)
{
    int r = 0;
    struct mailbox *mailbox = *mailboxptr;

    /* mark the quota removed */
    mailbox_quota_dirty(mailbox);

    /* mark the mailbox deleted */
    mailbox_index_dirty(mailbox);
    mailbox->i.options |= OPT_MAILBOX_DELETED;

#ifdef WITH_DAV
    /* remove any DAV records */
    r = mailbox_delete_dav(mailbox);
    if (r) return r;
#endif

    /* clean up annotations */
    r = annotate_delete_mailbox(mailbox);
    if (r) return r;

    /* commit the changes */
    r = mailbox_commit(mailbox);
    if (r) return r;

    /* remove any seen */
    seen_delete_mailbox(NULL, mailbox);

    /* can't unlink any files yet, because our promise to other
     * users of the mailbox applies! Can only unlink with an
     * exclusive lock.  mailbox_close will try to get one of
     * those.
     */

    syslog(LOG_NOTICE, "Deleted mailbox %s", mailbox->name);

    if (config_auditlog)
        syslog(LOG_NOTICE, "auditlog: delete sessionid=<%s> "
                           "mailbox=<%s> uniqueid=<%s>",
                           session_id(),
                           mailbox->name, mailbox->uniqueid);

    proc_killmbox(mailbox->name);

    mailbox_close(mailboxptr);

    return 0;
}

#ifdef WITH_JMAP
static int mailbox_delete_alarms(struct mailbox *mailbox)
{
    if (!(mailbox->i.options & OPT_IMAP_HAS_ALARMS))
        return 0;

    return caldav_alarm_delete_mailbox(mailbox->name);
}
#endif /* WITH_JMAP */

#ifdef WITH_DAV
static int mailbox_delete_caldav(struct mailbox *mailbox)
{
    struct caldav_db *caldavdb = NULL;

    caldavdb = caldav_open_mailbox(mailbox);
    if (caldavdb) {
        const mbentry_t mbentry = { .name = mailbox->name,
                                    .uniqueid = mailbox->uniqueid };
        int r = caldav_delmbox(caldavdb, &mbentry);
        caldav_close(caldavdb);
        if (r) return r;
    }

    int r = caldav_alarm_delete_mailbox(mailbox->name);
    if (r) return r;

    return 0;
}

static int mailbox_delete_carddav(struct mailbox *mailbox)
{
    struct carddav_db *carddavdb = NULL;

    carddavdb = carddav_open_mailbox(mailbox);
    if (carddavdb) {
        const mbentry_t mbentry = { .name = mailbox->name,
                                    .uniqueid = mailbox->uniqueid };
        int r = carddav_delmbox(carddavdb, &mbentry);
        carddav_close(carddavdb);
        if (r) return r;
    }

    return 0;
}

static int mailbox_delete_webdav(struct mailbox *mailbox)
{
    struct webdav_db *webdavdb = NULL;

    webdavdb = webdav_open_mailbox(mailbox);
    if (webdavdb) {
        const mbentry_t mbentry = { .name = mailbox->name,
                                    .uniqueid = mailbox->uniqueid };
        int r = webdav_delmbox(webdavdb, &mbentry);
        webdav_close(webdavdb);
        if (r) return r;
    }

    return 0;
}

static int mailbox_delete_dav(struct mailbox *mailbox)
{
    switch (mbtype_isa(mailbox->mbtype)) {
    case MBTYPE_ADDRESSBOOK:
        return mailbox_delete_carddav(mailbox);
    case MBTYPE_CALENDAR:
        return mailbox_delete_caldav(mailbox);
    case MBTYPE_COLLECTION:
        return mailbox_delete_webdav(mailbox);
    }

    return 0;
}
#endif /* WITH_DAV */

/*
 * Delete and close the mailbox 'mailbox'.  Closes 'mailbox' whether
 * or not the deletion was successful.  Requires a locked mailbox.
 */
EXPORTED int mailbox_delete(struct mailbox **mailboxptr)
{
    struct mailbox *mailbox = *mailboxptr;
    int r;

    r = mailbox_delete_conversations(mailbox);
    if (r) return r;

#ifdef WITH_JMAP
    r = mailbox_delete_alarms(mailbox);
    if (r) return r;
#endif /* WITH_JMAP */

#ifdef WITH_DAV
    r = mailbox_delete_dav(mailbox);
    if (r) return r;
#endif /* WITH_DAV */

    return mailbox_delete_internal(mailboxptr);
}

struct meta_file {
    unsigned long metaflag;
    int optional;
    int nolink;
};

static struct meta_file meta_files[] = {
    { META_HEADER,       0, 1 },
    { META_INDEX,        0, 1 },
    { META_CACHE,        1, 1 },
    { META_SQUAT,        1, 0 },
    { META_ANNOTATIONS,  1, 1 },
    { META_ARCHIVECACHE, 1, 1 },
    { 0, 0, 0 }
};

/* XXX - move this part of cleanup into mboxlist.  Really
 * needs to be done with mailboxes.db locked so nobody can
 * try to create a mailbox while the delete is underway.
 * VERY tight race condition exists right now... */
/* we need an exclusive namelock for this */
HIDDEN int mailbox_delete_cleanup(struct mailbox *mailbox, const char *part, const char *name, const char *uniqueid)
{
    strarray_t paths = STRARRAY_INITIALIZER;
    int i;
    mbentry_t *mbentry;
    struct meta_file *mf;
    int r;
    char nbuf[MAX_MAILBOX_NAME];
    char *ntail;
    char *p;

    int object_storage_enabled = 0 ;
#if defined ENABLE_OBJECTSTORE
    object_storage_enabled = config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED);
#endif

    xstrncpy(nbuf, name, sizeof(nbuf));
    ntail = nbuf + strlen(nbuf);

    if (mailbox && object_storage_enabled){
        mailbox_remove_files_from_object_storage (mailbox, 0) ;
    }

    /* XXX - double XXX - this is a really ugly function.  It should be
     * using mboxname_parts and walking back up the 'boxes' list */

    strarray_add(&paths, mboxname_datapath(part, name, uniqueid, 0));

    /* find the directory for every one of the meta files */
    for (mf = meta_files; mf->metaflag; mf++) {
        char *fname = xstrdup(mboxname_metapath(part, name, uniqueid, mf->metaflag, 0));
        p = strrchr(fname, '/');
        if (p) *p = '\0';
        strarray_add(&paths, fname);
        free(fname);
    }

    for (i = 0; i < paths.count; i++) {
        const char *path = strarray_nth(&paths, i);
        mailbox_delete_files(path);
    }

    do {
        if (!uniqueid) {
            /* paths by mboxname - Check if the mailbox has children */
            r = mboxlist_mboxtree(nbuf, chkchildren, (void *)part, MBOXTREE_SKIP_ROOT);
            if (r != 0) break; /* We short-circuit with CYRUSDB_DONE */
        }

        /* no children, remove the directories */
        for (i = 0; i < paths.count; i++) {
            char *path = paths.data[i]; /* need direct reference, because we're fiddling */
            r = rmdir(path);
            if (r && errno != ENOENT)
                syslog(LOG_NOTICE,
                       "Remove of supposedly empty directory %s failed: %m",
                       path);
            p = strrchr(path, '/');
            if (p) *p = '\0';
        }

        /* Check if parent mailbox exists */
        ntail = strrchr(nbuf, '.');
        if (!ntail || strchr(ntail, '!')) {
            /* Hit top of hierarchy or domain separator */
            break;
        }
        *ntail = '\0';
        if (!strcmp(nbuf, "user") ||
            ((ntail - nbuf > 5) && !strcmp(ntail-5, "!user"))) {
            /* Hit top of 'user' hierarchy */
            break;
        }

        r = mboxlist_lookup(nbuf, &mbentry, NULL);
        /* if it's not being moved, and not the same partition, then it's safe to
         * clean up the parent directory too */
        if (!r) {
            if (!(mbentry->mbtype & MBTYPE_MOVING) && strcmp(mbentry->partition, part))
                r = IMAP_MAILBOX_NONEXISTENT;
            mboxlist_entry_free(&mbentry);
        }
    } while (r == IMAP_MAILBOX_NONEXISTENT);

    strarray_fini(&paths);

    return 0;
}

EXPORTED int mailbox_copy_files(struct mailbox *mailbox, const char *newpart,
                                const char *newname, const char *newuniqueid)
{
    char oldbuf[MAX_MAILBOX_PATH], newbuf[MAX_MAILBOX_PATH];
    struct meta_file *mf;
    const message_t *msg;
    int r = 0;

    int object_storage_enabled = 0 ;
#if defined ENABLE_OBJECTSTORE
    object_storage_enabled = config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED);
#endif

    /* Copy over meta files */
    for (mf = meta_files; mf->metaflag; mf++) {
        struct stat sbuf;

        xstrncpy(oldbuf, mailbox_meta_fname(mailbox, mf->metaflag),
                MAX_MAILBOX_PATH);
        xstrncpy(newbuf, mboxname_metapath(newpart, newname, newuniqueid, mf->metaflag, 0),
                MAX_MAILBOX_PATH);

        unlink(newbuf); /* Make link() possible */

        if (!mf->optional || stat(oldbuf, &sbuf) != -1) {
            r = mailbox_copyfile(oldbuf, newbuf, mf->nolink);
            if (r) return r;
        }
    }

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        xstrncpy(oldbuf, mailbox_record_fname(mailbox, record),
                MAX_MAILBOX_PATH);
        if (!object_storage_enabled && record->internal_flags & FLAG_INTERNAL_ARCHIVED)
            xstrncpy(newbuf, mboxname_archivepath(newpart, newname, newuniqueid, record->uid),
                    MAX_MAILBOX_PATH);
        else
            xstrncpy(newbuf, mboxname_datapath(newpart, newname, newuniqueid, record->uid),
                    MAX_MAILBOX_PATH);

        if (!(object_storage_enabled && record->internal_flags & FLAG_INTERNAL_ARCHIVED))    // if object storage do not move file
           r = mailbox_copyfile(oldbuf, newbuf, 0);

        if (r) break;

#if defined ENABLE_OBJECTSTORE
        if (object_storage_enabled && record->internal_flags & FLAG_INTERNAL_ARCHIVED) {
            static struct mailbox new_mailbox;
            memset(&new_mailbox, 0, sizeof(struct mailbox));
            new_mailbox.name = (char*) newname;
            new_mailbox.part = (char*) config_defpartition ;
            r = objectstore_put(&new_mailbox, record, newbuf);   // put should just add to refcount.
            if (r) break;
        }
#endif
    }
    mailbox_iter_done(&iter);

    return r;
}


HIDDEN int mailbox_rename_nocopy(struct mailbox *oldmailbox,
                                 const char *newname, int silent)
{
    char quotaroot[MAX_MAILBOX_BUFFER];
    int hasquota = quota_findroot(quotaroot, sizeof(quotaroot), newname);

    /* Move any quota usage */
    int r = mailbox_changequotaroot(oldmailbox,
                                    hasquota ? quotaroot: NULL, silent);

    if (!r) {
        /* copy any mailbox annotations */
        struct mailbox newmailbox = { .name = (char *) newname,
                                      .index_locktype = LOCK_EXCLUSIVE };
        r = annotate_rename_mailbox(oldmailbox, &newmailbox);
    }

    if (!r && mailbox_has_conversations(oldmailbox)) {
        struct conversations_state *oldcstate =
            conversations_get_mbox(oldmailbox->name);

        assert(oldcstate);

        if (mboxname_isdeletedmailbox(newname, NULL)) {
            /* we never store data about deleted mailboxes */
            r = mailbox_delete_conversations(oldmailbox);
        }
        else {
            /* we can just rename within the same user */
            r = conversations_rename_folder(oldcstate, oldmailbox->name, newname);
            syslog(LOG_INFO, "XXXXX  convb rename: %d", r);
        }
    }

    return r;
}

/* if 'userid' is set, we perform the funky RENAME INBOX INBOX.old
   semantics, regardless of whether or not the name of the mailbox is
   'user.foo'.*/
/* requires a write-locked oldmailbox pointer, since we delete it
   immediately afterwards */
HIDDEN int mailbox_rename_copy(struct mailbox *oldmailbox,
                        const char *newname,
                        const char *newpartition,
                        unsigned uidvalidity,
                        const char *userid, int ignorequota,
                        int silent,
                        struct mailbox **newmailboxptr)
{
    int r;
    struct mailbox *newmailbox = NULL;
    struct conversations_state *oldcstate = NULL;
    struct conversations_state *newcstate = NULL;
    char *newquotaroot = NULL;
    char *newuniqueid;

    assert(mailbox_index_islocked(oldmailbox, 1));

    /* we can't rename back from a deleted mailbox, because the conversations
     * information will be wrong.  Ideally we might re-calculate, but for now
     * we just throw a big fat error */
    if (config_getswitch(IMAPOPT_CONVERSATIONS) &&
        mboxname_isdeletedmailbox(oldmailbox->name, NULL)) {
        syslog(LOG_ERR, "can't rename a deleted mailbox %s", oldmailbox->name);
        return IMAP_MAILBOX_BADNAME;
    }

    /* create uidvalidity if not explicitly requested */
    if (!uidvalidity)
        uidvalidity = mboxname_nextuidvalidity(newname, oldmailbox->i.uidvalidity);

    modseq_t highestmodseq = silent ? oldmailbox->i.highestmodseq : 0;

    /* Create new mailbox */
    r = mailbox_create(newname, oldmailbox->mbtype, newpartition,
                       oldmailbox->acl, (userid ? NULL : oldmailbox->uniqueid),
                       oldmailbox->i.options, uidvalidity,
                       oldmailbox->i.createdmodseq,
                       highestmodseq, &newmailbox);

    if (r) return r;

    /* Check quota if necessary */
    if (!ignorequota && newmailbox->quotaroot &&
        strcmpsafe(oldmailbox->quotaroot, newmailbox->quotaroot)) {

        quota_t usage[QUOTA_NUMRESOURCES];
        mailbox_get_usage(oldmailbox, usage);
        r = mailbox_quota_check(newmailbox, usage);
        /* then we abort - no space to rename */
        if (r)
            goto fail;
    }
    newquotaroot = xstrdupnull(newmailbox->quotaroot);

    r = mailbox_copy_files(oldmailbox, newpartition,
                           newname, newmailbox->mbtype & MBTYPE_LEGACY_DIRS ?
                           NULL : newmailbox->uniqueid);
    if (r) goto fail;

    /* Re-open index file  */
    r = mailbox_open_index(newmailbox);
    if (r) goto fail;

    /* cyrus.header has been copied with old uniqueid.
       make a copy of new uniqueid so we can reset it */
    newuniqueid = xstrdup(newmailbox->uniqueid);

    /* Re-lock index */
    r = mailbox_lock_index_internal(newmailbox, LOCK_EXCLUSIVE);

    /* Reset new uniqueid */
    free(newmailbox->uniqueid);
    newmailbox->uniqueid = newuniqueid;
    newmailbox->header_dirty = 1;

    /* INBOX rename - change uniqueid */
    if (userid) {
        r = seen_copy(userid, oldmailbox, newmailbox);
        if (r) goto fail;
    }

    /* copy any mailbox annotations (but keep the known quota
     * amount, because we already counted that usage.  XXX horrible
     * hack */
    quota_t annotused = newmailbox->i.quota_annot_used;
    r = annotate_rename_mailbox(oldmailbox, newmailbox);
    if (r) goto fail;
    newmailbox->i.quota_annot_used = annotused;

    /* mark the "used" back to zero, so it updates the new quota! */
    mailbox_set_quotaroot(newmailbox, newquotaroot);
    mailbox_quota_dirty(newmailbox);
    memset(newmailbox->quota_previously_used, 0, sizeof(newmailbox->quota_previously_used));
    /* except this one... because we've counted it when we created the folder */
    newmailbox->quota_previously_used[QUOTA_NUMFOLDERS] = 1;

    /* re-set the UIDVALIDITY, it will have been the old one in the index header */
    mailbox_index_dirty(newmailbox);
    newmailbox->i.uidvalidity = uidvalidity;
    /* unless on a replica, bump the modseq too */
    if (!silent) mailbox_modseq_dirty(newmailbox);

    /* NOTE: in the case of renaming a user to another user, we
     * don't rename the conversations DB - instead we re-create
     * the records in the target user.  Sorry, was too complex
     * otherwise handling all the special cases */
    if (mailbox_has_conversations(oldmailbox)) {
        oldcstate = mailbox_get_cstate(oldmailbox);
        assert(oldcstate);
    }

    if (mailbox_has_conversations(newmailbox)) {
        newcstate = mailbox_get_cstate(newmailbox);
        assert(newcstate);
    }

    if (oldcstate && newcstate && !strcmp(oldcstate->path, newcstate->path)) {
        /* we can just rename within the same user */
        r = conversations_rename_folder(oldcstate, oldmailbox->name, newname);
    }
    else {
        /* have to handle each one separately */
        if (newcstate)
            r = mailbox_add_conversations(newmailbox, /*silent*/0);
        if (oldcstate)
            r = mailbox_delete_conversations(oldmailbox);
    }
    if (r) goto fail;

    /* commit the index changes */
    r = mailbox_commit(newmailbox);
    if (r) goto fail;

    if (config_auditlog)
        syslog(LOG_NOTICE, "auditlog: rename sessionid=<%s> "
                           "oldmailbox=<%s> newmailbox=<%s> uniqueid=<%s>",
                           session_id(),
                           oldmailbox->name, newname, newmailbox->uniqueid);

    if (newmailboxptr) *newmailboxptr = newmailbox;
    else mailbox_close(&newmailbox);
    free(newquotaroot);

    return 0;

fail:
    /* first unlock so we don't need to write anything new down */
    mailbox_unlock_index(newmailbox, NULL);
    /* then remove all the files */
    mailbox_delete_cleanup(NULL, newmailbox->part, newmailbox->name,
                           (newmailbox->mbtype & MBTYPE_LEGACY_DIRS) ?
                           NULL : newmailbox->uniqueid);
    /* and finally, abort */
    mailbox_abort(newmailbox);
    mailbox_close(&newmailbox);
    free(newquotaroot);

    return r;
}

EXPORTED int mailbox_rename_cleanup(struct mailbox **mailboxptr, int isinbox)
{

    int r = 0;
    struct mailbox *oldmailbox = *mailboxptr;
    char *name = xstrdup(oldmailbox->name);

    if (isinbox) {
        /* Expunge old mailbox */
        r = mailbox_expunge(oldmailbox, expungeall, (char *)0, NULL, 0);
        if (!r) r = mailbox_commit(oldmailbox);
        mailbox_close(mailboxptr);
    } else {
        r = mailbox_delete_internal(mailboxptr);
    }

    if (r) {
        syslog(LOG_CRIT,
               "Rename Failure during mailbox_rename_cleanup (%s), " \
               "potential leaked space (%s)", name,
               error_message(r));
    }
    free(name);

    return r;
}

/*
 * Copy (or link) the file 'from' to the file 'to'
 */
EXPORTED int mailbox_copyfile(const char *from, const char *to, int nolink)
{
    int flags = COPYFILE_MKDIR|COPYFILE_KEEPTIME;
    if (nolink) flags |= COPYFILE_NOLINK;

    if (mailbox_wait_cb) mailbox_wait_cb(mailbox_wait_cb_rock);

    if (cyrus_copyfile(from, to, flags))
        return IMAP_IOERROR;

    return 0;
}

/* ---------------------------------------------------------------------- */
/*                      RECONSTRUCT SUPPORT                               */
/* ---------------------------------------------------------------------- */

#define UIDGROW 300

struct found_uid {
    uint32_t uid;
    unsigned isarchive:1;
    unsigned issnoozed:1;
};

struct found_uids {
    struct found_uid *found;
    unsigned nalloc;
    unsigned nused;
    unsigned pos;
};
#define FOUND_UIDS_INITIALIZER \
    { NULL, 0, 0, 0 }

static int sort_found(const void *a, const void *b)
{
    struct found_uid *fa = (struct found_uid *)a;
    struct found_uid *fb = (struct found_uid *)b;
    if (fa->uid != fb->uid)
        return fa->uid - fb->uid;
    return fa->isarchive - fb->isarchive;
}

static void add_found(struct found_uids *ff, uint32_t uid, int isarchive)
{
    /* make sure there's space */
    if (ff->nused >= ff->nalloc) {
        ff->nalloc += UIDGROW;
        ff->found = xrealloc(ff->found, ff->nalloc * sizeof(ff->found[0]));
    }
    ff->found[ff->nused].uid = uid;
    ff->found[ff->nused].isarchive = !!isarchive;
    ff->found[ff->nused].issnoozed = 0;
    ff->nused++;
}

static void free_found(struct found_uids *ff)
{
    free(ff->found);
    ff->found = NULL;
    ff->nalloc = 0;
    ff->nused = 0;
    ff->pos = 0;
}

static int parse_datafilename(const char *name, uint32_t *uidp)
{
    const char *p = name;

    /* must be at least one digit */
    if (!cyrus_isdigit(*p)) return IMAP_MAILBOX_BADNAME;
    do {
        p++;
    } while cyrus_isdigit(*p);

    /* has to end with a dot */
    if (*p != '.') return IMAP_MAILBOX_BADNAME;
    if (p[1]) return IMAP_MAILBOX_BADNAME;

    return parseuint32(name, &p, uidp);
}

static int find_files(struct mailbox *mailbox, struct found_uids *files,
                      int flags)
{
    strarray_t paths = STRARRAY_INITIALIZER;
    DIR *dirp;
    struct dirent *dirent;
    uint32_t uid;
    const char *p;
    char buf[MAX_MAILBOX_PATH];
    struct stat sbuf;
    int r;
    int i;

    strarray_add(&paths, mailbox_datapath(mailbox, 0));

#if defined ENABLE_OBJECTSTORE
    if (config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED))
    {
        uint32_t i , count = 0 ;
        struct message *list = get_list_of_message (mailbox, &count) ;
        for (i = 0; i < count; i++) {
            add_found(files, list [i].message_uid, 1 /* isarchive */ );
        }
        discard_list( ) ;
    }
    else
#endif
        strarray_add(&paths, mboxname_archivepath(mailbox->part, mailbox->name, mailbox->uniqueid, 0));

    for (i = 0; i < paths.count; i++) {
        const char *dirpath = strarray_nth(&paths, i);
        int isarchive = strcmp(dirpath, mailbox_datapath(mailbox, 0));

        dirp = opendir(dirpath);
        if (!dirp) continue;

        /* data directory is fine */
        while ((dirent = readdir(dirp)) != NULL) {
            p = dirent->d_name;
            if (*p == '.') continue; /* dot files */
            if (!strncmp(p, "cyrus.", 6)) continue; /* cyrus.* files */

            r = parse_datafilename(p, &uid);

            if (r) {
                /* check if it's a directory */
                snprintf(buf, MAX_MAILBOX_PATH, "%s/%s", dirpath, dirent->d_name);
                if (stat(buf, &sbuf) == -1) continue; /* ignore ephemeral */
                if (!S_ISDIR(sbuf.st_mode)) {
                    if (!(flags & RECONSTRUCT_IGNORE_ODDFILES)) {
                        printf("%s odd file %s\n", mailbox->name, buf);
                        syslog(LOG_ERR, "%s odd file %s", mailbox->name, buf);
                        if (flags & RECONSTRUCT_REMOVE_ODDFILES)
                            unlink(buf);
                        else {
                            printf("run reconstruct with -O to remove odd files\n");
                            syslog(LOG_ERR, "run reconstruct with -O to "
                                            "remove odd files");
                        }
                    }
                }
            }
            else {
                /* it's one of ours :) */
                add_found(files, uid, isarchive);
            }
        }

        closedir(dirp);
    }

    /* make sure UIDs are sorted for comparison */
    qsort(files->found, files->nused, sizeof(files->found[0]), sort_found);

    strarray_fini(&paths);

    return 0;
}

static void cleanup_stale_expunged(struct mailbox *mailbox)
{
    const char *fname;
    int expunge_fd = -1;
    const char *expunge_base = NULL;
    size_t expunge_len = 0;   /* mapped size */
    unsigned long expunge_num;
    unsigned long emapnum;
    uint32_t erecno;
    uint32_t eversion;
    bit32 eoffset, expungerecord_size;
    const char *bufp;
    struct stat sbuf;
    int r;

    /* it's always read-writes */
    fname = mailbox_meta_fname(mailbox, META_EXPUNGE);
    expunge_fd = open(fname, O_RDWR, 0);
    if (expunge_fd == -1)
        goto done; /* yay, no crappy expunge file */

    /* boo - gotta read and find out the UIDs */
    r = fstat(expunge_fd, &sbuf);
    if (r == -1)
        goto done;

    if (sbuf.st_size < INDEX_HEADER_SIZE)
        goto done;

    map_refresh(expunge_fd, 1, &expunge_base,
                &expunge_len, sbuf.st_size, "expunge",
                mailbox->name);

    /* use the expunge file's header information just in case
     * versions are skewed for some reason */
    eoffset = ntohl(*((bit32 *)(expunge_base+OFFSET_START_OFFSET)));
    expungerecord_size = ntohl(*((bit32 *)(expunge_base+OFFSET_RECORD_SIZE)));

    /* bogus data at the start of the expunge file? */
    if (!eoffset || !expungerecord_size)
        goto done;

    expunge_num = ntohl(*((bit32 *)(expunge_base+OFFSET_NUM_RECORDS)));
    eversion = ntohl(*((bit32 *)(expunge_base+OFFSET_MINOR_VERSION)));
    emapnum = (sbuf.st_size - eoffset) / expungerecord_size;
    if (emapnum < expunge_num) {
        expunge_num = emapnum;
    }

    /* add every UID to the files list */
    for (erecno = 1; erecno <= expunge_num; erecno++) {
        struct index_record record;
        bufp = expunge_base + eoffset + (erecno-1)*expungerecord_size;
        mailbox_buf_to_index_record(bufp, eversion, &record, 0);
        record.internal_flags |= FLAG_INTERNAL_EXPUNGED | FLAG_INTERNAL_UNLINKED;
        mailbox_record_cleanup(mailbox, &record);
    }

    fname = mailbox_meta_fname(mailbox, META_EXPUNGE);
    unlink(fname);

done:
    if (expunge_base) map_free(&expunge_base, &expunge_len);
    xclose(expunge_fd);
}

/* this is kind of like mailbox_create, but we try to rescue
 * what we can from the filesystem! */
static int mailbox_reconstruct_create(const char *name, struct mailbox **mbptr)
{
    struct mailbox *mailbox = NULL;
    int options = config_getint(IMAPOPT_MAILBOX_DEFAULT_OPTIONS)
                | OPT_POP3_NEW_UIDL;
    mbentry_t *mbentry = NULL;
    struct mailboxlist *listitem;
    int r;

    /* make sure it's not already open.  Very odd, since we already
     * discovered it's not openable! */
    listitem = find_listitem(name);
    if (listitem) return IMAP_MAILBOX_LOCKED;

    listitem = create_listitem(name);
    mailbox = &listitem->m;

    // lock the user namespace FIRST before the mailbox namespace
    char *userid = mboxname_to_userid(name);
    if (userid) {
        int haslock = user_isnamespacelocked(userid);
        if (haslock) {
            assert(haslock != LOCK_SHARED);
        }
        else {
            int locktype = LOCK_EXCLUSIVE;
            mailbox->local_namespacelock = user_namespacelock_full(userid, locktype);
        }
        free(userid);
    }

    /* if we can't get an exclusive lock first try, there's something
     * racy going on! */
    r = mboxname_lock(name, &listitem->l, LOCK_EXCLUSIVE);
    if (r) goto done;

    /* Start by looking up current data in mailbox list */
    /* XXX - no mboxlist entry?  Can we recover? */
    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) goto done;

    mailbox->part = xstrdup(mbentry->partition);
    mailbox->acl = xstrdup(mbentry->acl);
    mailbox->mbtype = mbentry->mbtype;

    syslog(LOG_NOTICE, "create new mailbox %s", name);

    /* Attempt to open index */
    r = mailbox_open_index(mailbox);
    if (!r) r = mailbox_read_index_header(mailbox);
    if (r) {
        printf("%s: failed to read index header\n", mailbox->name);
        syslog(LOG_ERR, "failed to read index header for %s", mailbox->name);
        /* no cyrus.index file at all - well, we're in a pickle!
         * no point trying to rescue anything else... */
        mailbox_close(&mailbox);
        r = mailbox_create(name, mbentry->mbtype, mbentry->partition, mbentry->acl,
                           mbentry->uniqueid, options, 0, 0, 0, mbptr);
        mboxlist_entry_free(&mbentry);
        return r;
    }

    mboxlist_entry_free(&mbentry);

    /* read header, if it is not there, we need to create it */
    r = mailbox_read_header(mailbox, NULL);
    if (r) {
        /* Header failed to read - recreate it */
        printf("%s: failed to read header file\n", mailbox->name);
        syslog(LOG_ERR, "failed to read header file for %s", mailbox->name);

        mailbox_make_uniqueid(mailbox);
        r = mailbox_commit(mailbox);
        if (r) goto done;
    }

    if (mailbox->header_file_crc != mailbox->i.header_file_crc) {
        mailbox->i.header_file_crc = mailbox->header_file_crc;
        printf("%s: header file CRC mismatch, correcting\n", mailbox->name);
        syslog(LOG_ERR, "%s: header file CRC mismatch, correcting", mailbox->name);
        mailbox_index_dirty(mailbox);
        r = mailbox_commit(mailbox);
        if (r) goto done;
    }

done:
    if (r) mailbox_close(&mailbox);
    else *mbptr = mailbox;

    return r;
}

static int mailbox_reconstruct_uniqueid(struct mailbox *mailbox, int flags)
{
    int make_changes = flags & RECONSTRUCT_MAKE_CHANGES;
    mbentry_t *mbentry = NULL;

    int r = mboxlist_lookup(mailbox->name, &mbentry, 0);
    if (r) return r;

    if (strcmpsafe(mbentry->uniqueid, mailbox->uniqueid)) {
        printf("%s: update uniqueid from header %s => %s\n", mailbox->name,
               mbentry->uniqueid, mailbox->uniqueid);
        if (make_changes) {
            if ((flags & RECONSTRUCT_PREFER_MBOXLIST) && mbentry->uniqueid) {
                mailbox_set_uniqueid(mailbox, mbentry->uniqueid);
            }
            else {
                free(mbentry->uniqueid);
                mbentry->uniqueid = xstrdup(mailbox->uniqueid);
                r = mboxlist_update(mbentry, 0);
            }
        }
    }

    mboxlist_entry_free(&mbentry);

    return r;
}

static int mailbox_reconstruct_acl(struct mailbox *mailbox, int flags)
{
    int make_changes = flags & RECONSTRUCT_MAKE_CHANGES;
    char *acl = NULL;
    int r;

    r = mailbox_read_header(mailbox, &acl);
    if (r) return r;

    if (strcmp(mailbox->acl, acl)) {
        printf("%s: update acl from header %s => %s\n", mailbox->name,
               mailbox->acl, acl);
        if (make_changes) {
            mbentry_t *mbentry = NULL;
            r = mboxlist_lookup(mailbox->name, &mbentry, NULL);
            if (!r) {
                if ((flags & RECONSTRUCT_PREFER_MBOXLIST) && mbentry->acl) {
                    mailbox_set_acl(mailbox, mbentry->acl);
                }
                else {
                    free(mbentry->acl);
                    mbentry->acl = xstrdup(acl);
                    r = mboxlist_update(mbentry, 0);
                }
            }
            mboxlist_entry_free(&mbentry);
        }
    }

    free(acl);

    return r;
}

static int records_match(const char *mboxname,
                         struct index_record *old,
                         struct index_record *new)
{
    int i;
    int match = 1;
    int userflags_dirty = 0;

    if (old->internaldate != new->internaldate) {
        printf("%s uid %u mismatch: internaldate\n",
               mboxname, new->uid);
        match = 0;
    }
    if (old->sentdate != new->sentdate) {
        printf("%s uid %u mismatch: sentdate\n",
               mboxname, new->uid);
        match = 0;
    }
    if (old->size != new->size) {
        printf("%s uid %u mismatch: size\n",
               mboxname, new->uid);
        match = 0;
    }
    if (old->header_size != new->header_size) {
        printf("%s uid %u mismatch: header_size\n",
               mboxname, new->uid);
        match = 0;
    }
    if (old->gmtime != new->gmtime) {
        printf("%s uid %u mismatch: gmtime\n",
               mboxname, new->uid);
        match = 0;
    }
    if (old->savedate != new->savedate) {
        printf("%s uid %u mismatch: savedate\n",
               mboxname, new->uid);
        match = 0;
    }
    if (old->createdmodseq != new->createdmodseq) {
        printf("%s uid %u mismatch: createdmodseq\n",
               mboxname, new->uid);
        match = 0;
    }
    if (old->system_flags != new->system_flags) {
        printf("%s uid %u mismatch: systemflags\n",
               mboxname, new->uid);
        match = 0;
    }
    if (old->internal_flags != new->internal_flags) {
        printf("%s uid %u mismatch: internalflags\n",
               mboxname, new->uid);
        match = 0;
    }
    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
        if (old->user_flags[i] != new->user_flags[i])
            userflags_dirty = 1;
    }
    if (userflags_dirty) {
        printf("%s uid %u mismatch: userflags\n",
               mboxname, new->uid);
        match = 0;
    }
    if (!message_guid_equal(&old->guid, &new->guid)) {
        printf("%s uid %u mismatch: guid\n",
               mboxname, new->uid);
        match = 0;
    }

    if (!match) {
        syslog(LOG_ERR, "%s uid %u record mismatch, rewriting",
               mboxname, new->uid);
    }

    /* cache issues - don't print, probably just a version
     * upgrade... */
    if (old->cache_version != new->cache_version) {
        match = 0;
    }
    if (old->cache_crc != new->cache_crc) {
        match = 0;
    }
    if (cache_len(old) != cache_len(new)) {
        match = 0;
    }
    /* only compare cache records if size matches */
    else if (memcmp(cache_base(old), cache_base(new), cache_len(new))) {
        match = 0;
    }

    return match;
}

static int mailbox_reconstruct_compare_update(struct mailbox *mailbox,
                                              struct index_record *record,
                                              bit32 *valid_user_flags,
                                              int flags, int have_file,
                                              int has_snoozedannot,
                                              struct found_uids *discovered)
{
    const char *fname = mailbox_record_fname(mailbox, record);
    int r = 0;
    int i;
    struct index_record copy;
    struct stat sbuf;
    int make_changes = flags & RECONSTRUCT_MAKE_CHANGES;
    int re_parse = flags & RECONSTRUCT_ALWAYS_PARSE;
    int do_stat = flags & RECONSTRUCT_DO_STAT;
    int re_pack = 0;
    int did_stat = 0;

    int remove_temp_spool_file = 0 ;
#if defined ENABLE_OBJECTSTORE
    int object_storage_enabled = config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED) ;

    if (object_storage_enabled && record->system_flags & FLAG_INTERNAL_ARCHIVED){  // put the file on spool temporarily
        remove_temp_spool_file = 1;
        r = objectstore_get(mailbox, record, fname);
    }
#endif

    /* does the file actually exist? */
    if (have_file && do_stat) {
        if (stat(fname, &sbuf) == -1 || (sbuf.st_size == 0)) {
            have_file = 0;
        }
        else if (record->size != (unsigned) sbuf.st_size) {
            re_parse = 1;
        }
        did_stat = 1;
    }

    if (!have_file) {
        /* well, that's OK if it's supposed to be missing! */
        if (record->internal_flags & FLAG_INTERNAL_UNLINKED) {
            r = 0 ;
            goto out;
        }

        printf("%s uid %u not found\n", mailbox->name, record->uid);
        syslog(LOG_ERR, "%s uid %u not found", mailbox->name, record->uid);

        if (!make_changes) {
            r = 0 ;
            goto out;
        }

        /* otherwise we have issues, mark it unlinked */
        unlink(fname);
        record->internal_flags |= FLAG_INTERNAL_EXPUNGED | FLAG_INTERNAL_UNLINKED;
        mailbox->i.options |= OPT_MAILBOX_NEEDS_REPACK;
        r = mailbox_rewrite_index_record(mailbox, record);
        goto out;
    }

    if (mailbox_cacherecord_internal(mailbox, record, MBCACHE_NOPARSE) || record->crec.len == 0) {
        re_parse = 1;
        re_pack = 1; /* cache record will have to be rewritten */
    }

    /* copy once the cache record is read in... */
    copy = *record;

    if (!record->internaldate) {
        re_parse = 1;
    }

    /* re-calculate all the "derived" fields by parsing the file on disk */
    if (re_parse) {
        /* set NULL in case parse finds a new value */
        record->internaldate = 0;

        r = message_parse(fname, record);
        if (r) goto out;

        /* unchanged, keep the old value */
        if (!record->internaldate)
            record->internaldate = copy.internaldate;

        /* it's not the same message! */
        if (!message_guid_equal(&record->guid, &copy.guid)) {
            int do_unlink = 0;

            printf("%s uid %u guid mismatch\n",
                   mailbox->name, record->uid);
            syslog(LOG_ERR, "%s uid %u guid mismatch",
                   mailbox->name, record->uid);

            if (!make_changes) {
                r = 0 ;
                goto out;
            }

            if (record->internal_flags & FLAG_INTERNAL_EXPUNGED) {
                /* already expunged, just unlink it */
                printf("%s uid %u already expunged, unlinking\n",
                       mailbox->name, record->uid);
                syslog(LOG_ERR, "%s uid %u already expunged, unlinking",
                       mailbox->name, record->uid);
                do_unlink = 1;
            }
            else if (flags & RECONSTRUCT_GUID_REWRITE) {
                /* treat this file as discovered */
                add_found(discovered, record->uid,
                          (record->internal_flags & FLAG_INTERNAL_ARCHIVED));
                printf("%s uid %u marking for uid upgrade\n",
                       mailbox->name, record->uid);
                syslog(LOG_ERR, "%s uid %u marking for uid upgrade",
                       mailbox->name, record->uid);
                do_unlink = 1;
            }
            else if (flags & RECONSTRUCT_GUID_UNLINK) {
                printf("%s uid %u unlinking as requested with -U\n",
                       mailbox->name, record->uid);
                syslog(LOG_ERR, "%s uid %u unlinking as requested with -U",
                       mailbox->name, record->uid);
                do_unlink = 1;
            }

            if (do_unlink) {
                /* rewrite with the original so we don't break the
                 * expectation that GUID never changes */
                copy.internal_flags |= FLAG_INTERNAL_EXPUNGED | FLAG_INTERNAL_UNLINKED;
                mailbox->i.options |= OPT_MAILBOX_NEEDS_UNLINK;
                r = mailbox_rewrite_index_record(mailbox, &copy);
                goto out;
            }

            /* otherwise we just report it and move on - hopefully the
             * correct file can be restored from backup or something */
            printf("run reconstruct with -R to fix or -U to remove\n");
            syslog(LOG_ERR, "run reconstruct with -R to fix or -U to remove");
            r = 0 ;
            goto out;
        }
    }

    if (!record->size) {
        /* dang, guess it failed to parse */

        printf("%s uid %u failed to parse\n", mailbox->name, record->uid);
        syslog(LOG_ERR, "%s uid %u failed to parse", mailbox->name, record->uid);

        if (!make_changes) {
            r = 0 ;
            goto out;
        }

        /* otherwise we have issues, mark it unlinked */
        unlink(fname);
        record->internal_flags |= FLAG_INTERNAL_EXPUNGED | FLAG_INTERNAL_UNLINKED;
        mailbox->i.options |= OPT_MAILBOX_NEEDS_REPACK;
        r = mailbox_rewrite_index_record(mailbox, record);
        goto out;
    }

    /* get internaldate from the file if not set */
    if (!record->internaldate) {
        if (did_stat || stat(fname, &sbuf) != -1)
            record->internaldate = sbuf.st_mtime;
        else
            record->internaldate = time(NULL);
    }

    /* XXX - conditions under which modseq or uid or internaldate could be bogus? */
    if (record->modseq > mailbox->i.highestmodseq) {
        printf("%s uid %u future modseq " MODSEQ_FMT " found\n",
                   mailbox->name, record->uid, record->modseq);
        syslog(LOG_ERR, "%s uid %u future modseq " MODSEQ_FMT " found",
                   mailbox->name, record->uid, record->modseq);
        mailbox_index_dirty(mailbox);
        mailbox->i.highestmodseq = mboxname_setmodseq(mailbox->name,
                                                      record->modseq,
                                                      mailbox->mbtype, /*flags*/0);
    }

    if (record->uid > mailbox->i.last_uid) {
        printf("%s future uid %u found\n",
               mailbox->name, record->uid);
        syslog(LOG_ERR, "%s future uid %u found",
               mailbox->name, record->uid);
        mailbox_index_dirty(mailbox);
        mailbox->i.last_uid = record->uid;
    }

    /* remove any user_flags that are missing from the header */
    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
        record->user_flags[i] &= valid_user_flags[i];
    }

    /* check if the snoozed status matches */
    if (!!(record->internal_flags & FLAG_INTERNAL_SNOOZED) != !!has_snoozedannot) {
        printf("%s uid %u snoozed mismatch\n", mailbox->name, record->uid);
        syslog(LOG_ERR, "%s uid %u snoozed mismatch", mailbox->name, record->uid);
        if (has_snoozedannot) record->internal_flags |= FLAG_INTERNAL_SNOOZED;
        else record->internal_flags &= ~FLAG_INTERNAL_SNOOZED;
    }


    /* after all this - if it still matches in every respect, we don't need
     * to rewrite the record - just return */
    if (records_match(mailbox->name, &copy, record)) {
        r = 0 ;
        goto out;
    }

    /* XXX - inform of changes */
    if (!make_changes) {
        r = 0 ;
        goto out;
    }

    /* rewrite the cache record */
    if (re_pack || !record->cache_offset || record->cache_crc != copy.cache_crc) {
        int32_t oldcrc = copy.cache_crc;
        int32_t newcrc = record->cache_crc;
        size_t oldoff = record->cache_offset;
        mailbox->i.options |= OPT_MAILBOX_NEEDS_REPACK;
        record->cache_offset = 0;
        r = mailbox_append_cache(mailbox, record);
        if (r) goto out ;
        printf("%s rewrote cache for %u (offset %llu to %llu, crc %u to %u/%u)\n",
               mailbox->name, record->uid,
               (long long unsigned)oldoff, (long long unsigned)record->cache_offset,
               oldcrc, newcrc, record->cache_crc);
        syslog(LOG_NOTICE, "%s rewrote cache for %u (offset %llu to %llu, crc %u to %u/%u)",
               mailbox->name, record->uid,
               (long long unsigned)oldoff, (long long unsigned)record->cache_offset,
               oldcrc, newcrc, record->cache_crc);
    }

    r = mailbox_rewrite_index_record(mailbox, record);

out:
    if (remove_temp_spool_file)
        remove(fname);
    return r;
}


static int mailbox_reconstruct_append(struct mailbox *mailbox, uint32_t uid, int isarchive,
                                      int has_snoozedannot, int flags)
{
    /* XXX - support archived */
    const char *fname;
    int r = 0;
    struct index_record record;
    struct stat sbuf;
    int make_changes = flags & RECONSTRUCT_MAKE_CHANGES;

    memset(&record, 0, sizeof(struct index_record));

    int remove_temp_spool_file = 0;
    int object_storage_enabled = 0;
#if defined ENABLE_OBJECTSTORE
    object_storage_enabled = config_getswitch(IMAPOPT_OBJECT_STORAGE_ENABLED);
#endif

    if (isarchive && !object_storage_enabled)
        fname = mboxname_archivepath(mailbox->part, mailbox->name, mailbox->uniqueid, uid);
    else
        fname = mboxname_datapath(mailbox->part, mailbox->name, mailbox->uniqueid, uid);

#if defined ENABLE_OBJECTSTORE
    if (object_storage_enabled)
    {
        uint32_t i , count = 0;
        struct message *list = get_list_of_message (mailbox, &count);
        for (i = 0; i < count; i++) {
            if (uid == list[i].message_uid){

                record.uid = uid;
                record.guid = list[i].message_guid;
                remove_temp_spool_file = 1;
                r = objectstore_get(mailbox, &record, fname);
                break;
            }
        }
        discard_list();
    }
#endif

    /* possible if '0.' file exists */
    if (!uid) {
        /* filthy hack - copy the path to '1.' and replace 1 with 0 */
        char *hack;
        fname = mboxname_datapath(mailbox->part, mailbox->name, mailbox->uniqueid, 1);
        hack = (char *)fname;
        hack[strlen(fname)-2] = '0';
    }

    if (stat(fname, &sbuf) == -1) r = IMAP_MAILBOX_NONEXISTENT;
    else if (sbuf.st_size == 0) r = IMAP_MAILBOX_NONEXISTENT;

    /* no file, nothing to do! */
    if (r) {
        syslog(LOG_ERR, "%s uid %u not found", mailbox->name, uid);
        printf("%s uid %u not found", mailbox->name, uid);
        r = 0;

        if (make_changes)
            unlink(fname);

        goto out;
    }

    r = message_parse(fname, &record);
    if (r) goto out;

    if (isarchive)
        record.internal_flags |= FLAG_INTERNAL_ARCHIVED;

    if (has_snoozedannot)
        record.internal_flags |= FLAG_INTERNAL_SNOOZED;

    /* copy the timestamp from the file if not calculated */
    if (!record.internaldate)
        record.internaldate = sbuf.st_mtime;

    if (uid > mailbox->i.last_uid) {
        printf("%s uid %u found - adding\n", mailbox->name, uid);
        syslog(LOG_ERR, "%s uid %u found - adding", mailbox->name, uid);
        record.uid = uid;
    }
    else {
        char *oldfname;
        char *newfname;

        printf("%s uid %u rediscovered - appending\n", mailbox->name, uid);
        syslog(LOG_ERR, "%s uid %u rediscovered - appending", mailbox->name, uid);
        /* XXX - check firstexpunged? */
        record.uid = mailbox->i.last_uid + 1;

        if (!make_changes) {
            r = 0 ;
            goto out;
        }

        oldfname = xstrdup(fname);
        newfname = xstrdup(mailbox_record_fname(mailbox, &record));
        r = rename(oldfname, newfname);
        free(oldfname);
        free(newfname);
        if (r) {
            r = IMAP_IOERROR;
            goto out ;
        }
    }

    /* XXX - inform of changes */
    if (!make_changes){
        r = 0 ;
        goto out;
    }

    /* always allow reconstruct to add records, even if we'd hit GUID limits */
    record.ignorelimits = 1;

    r = mailbox_append_index_record(mailbox, &record);

    /* XXX - copy per-message annotations? */

out:
    if (remove_temp_spool_file)
        remove(fname);
    return r;
}


static void reconstruct_compare_headers(struct mailbox *mailbox,
                                        struct index_header *old,
                                        struct index_header *new)
{
    if (old->quota_mailbox_used != new->quota_mailbox_used) {
        printf("%s updating quota_mailbox_used: "
               QUOTA_T_FMT " => " QUOTA_T_FMT "\n", mailbox->name,
               old->quota_mailbox_used, new->quota_mailbox_used);
        syslog(LOG_ERR, "%s updating quota_mailbox_used: "
               QUOTA_T_FMT " => " QUOTA_T_FMT, mailbox->name,
               old->quota_mailbox_used, new->quota_mailbox_used);
    }

    if (old->quota_annot_used != new->quota_annot_used) {
        printf("%s updating quota_annot_used: "
               QUOTA_T_FMT " => " QUOTA_T_FMT "\n", mailbox->name,
               old->quota_annot_used, new->quota_annot_used);
        syslog(LOG_ERR, "%s updating quota_annot_used: "
               QUOTA_T_FMT " => " QUOTA_T_FMT, mailbox->name,
               old->quota_annot_used, new->quota_annot_used);
    }

    if (old->answered != new->answered) {
        syslog(LOG_ERR, "%s: updating answered %u => %u",
               mailbox->name, old->answered, new->answered);
        printf("%s: updating answered %u => %u\n",
               mailbox->name, old->answered, new->answered);
    }

    if (old->flagged != new->flagged) {
        syslog(LOG_ERR, "%s: updating flagged %u => %u",
               mailbox->name, old->flagged, new->flagged);
        printf("%s: updating flagged %u => %u\n",
               mailbox->name, old->flagged, new->flagged);
    }

    if (old->deleted != new->deleted) {
        syslog(LOG_ERR, "%s: updating deleted %u => %u",
               mailbox->name, old->deleted, new->deleted);
        printf("%s: updating deleted %u => %u\n",
               mailbox->name, old->deleted, new->deleted);
    }

    if (old->exists != new->exists) {
        syslog(LOG_ERR, "%s: updating exists %u => %u",
               mailbox->name, old->exists, new->exists);
        printf("%s: updating exists %u => %u\n",
               mailbox->name, old->exists, new->exists);
    }

    if (old->synccrcs.basic != new->synccrcs.basic) {
        syslog(LOG_ERR, "%s: updating sync_crc %u => %u",
               mailbox->name, old->synccrcs.basic, new->synccrcs.basic);
        printf("%s: updating sync_crc %u => %u\n",
               mailbox->name, old->synccrcs.basic, new->synccrcs.basic);
    }

    if (old->synccrcs.annot != new->synccrcs.annot) {
        syslog(LOG_ERR, "%s: updating sync_crc_annot %u => %u",
               mailbox->name, old->synccrcs.annot, new->synccrcs.annot);
        printf("%s: updating sync_crc_annot %u => %u\n",
               mailbox->name, old->synccrcs.annot, new->synccrcs.annot);
    }

}

static int mailbox_wipe_index_record(struct mailbox *mailbox,
                                     struct index_record *record)
{
    int n;
    indexbuffer_t ibuf;
    unsigned char *buf = ibuf.buf;
    size_t offset;

    assert(mailbox_index_islocked(mailbox, 1));
    assert(record->recno > 0 &&
           record->recno <= mailbox->i.num_records);

    record->uid = 0;
    record->internal_flags |= FLAG_INTERNAL_EXPUNGED | FLAG_INTERNAL_UNLINKED;

    mailbox->i.options |= OPT_MAILBOX_NEEDS_REPACK;
    mailbox_index_dirty(mailbox);

    mailbox_index_record_to_buf(record, mailbox->i.minor_version, buf);

    offset = mailbox->i.start_offset +
             (record->recno-1) * mailbox->i.record_size;

    off_t p = lseek(mailbox->index_fd, offset, SEEK_SET);
    if (p == -1) {
        xsyslog(LOG_ERR, "IOERROR: seeking index record failed",
                         "mailbox=<%s> record=<%u>",
                         mailbox->name, record->recno);
        return IMAP_IOERROR;
    }

    n = retry_write(mailbox->index_fd, buf, mailbox->i.record_size);
    if (n < 0) {
        xsyslog(LOG_ERR, "IOERROR: writing index record failed",
                         "mailbox=<%s> record=<%u>",
                         mailbox->name, record->recno);
        return IMAP_IOERROR;
    }

    return 0;
}

static int addannot_uid(const char *mailbox __attribute__((unused)),
                        uint32_t uid,
                        const char *entry,
                        const char *userid,
                        const struct buf *value,
                        const struct annotate_metadata *mdata __attribute__((unused)),
                        void *rock)
{
    struct found_uids *annots = (struct found_uids *)rock;

    /* take advantage of the guarantee that all annotations with the same UID
     * will be together in a 'foreach' response */
    if (!annots->nused || annots->found[annots->nused-1].uid != uid) {
        /* we don't support an archive annotations DB yet */
        add_found(annots, uid, /*isarchive*/0);
    }

    /* the last item will be for this UID regardless, check if we have the snoozed annotation */
    if (!strcmpsafe(userid, "") && buf_len(value) &&
        !strcmp(entry, IMAP_ANNOT_NS "snoozed")) {
        annots->found[annots->nused-1].issnoozed = 1;
    }

    return 0;
}


static int find_annots(struct mailbox *mailbox, struct found_uids *annots)
{
    int r = 0;

    r = annotatemore_findall(mailbox->name, ANNOTATE_ANY_UID, "*",
                             /*modseq*/0, addannot_uid, annots, /*flags*/0);
    if (r) return r;

    /* make sure UIDs are sorted for comparison */
    qsort(annots->found, annots->nused, sizeof(annots->found[0]), sort_found);

    return 0;
}

static int reconstruct_delannots(struct mailbox *mailbox,
                                 struct found_uids *delannots,
                                 int flags)
{
    int make_changes = (flags & RECONSTRUCT_MAKE_CHANGES);
    int r = 0;

    r = mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, NULL);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open annotations %s: %s",
               mailbox->name, error_message(r));
        goto out;
    }

    while (delannots->pos < delannots->nused) {
        uint32_t uid = delannots->found[delannots->pos].uid;
        syslog(LOG_NOTICE, "removing stale annotations for %u", uid);
        printf("removing stale annotations for %u\n", uid);
        if (make_changes) {
            r = annotate_msg_cleanup(mailbox, uid);
            if (r) goto out;
        }
        delannots->pos++;
    }

out:
    return r;
}


/*
 * Reconstruct the single mailbox named 'name'
 */
EXPORTED int mailbox_reconstruct(const char *name, int flags)
{
    /* settings */
    int make_changes = (flags & RECONSTRUCT_MAKE_CHANGES);

    int r = 0;
    int i, flag;
    struct mailbox *mailbox = NULL;
    struct found_uids files = FOUND_UIDS_INITIALIZER;
    struct found_uids discovered = FOUND_UIDS_INITIALIZER;
    struct found_uids annots = FOUND_UIDS_INITIALIZER;
    struct found_uids delannots = FOUND_UIDS_INITIALIZER;
    struct index_header old_header;
    int have_file;
    uint32_t last_seen_uid = 0;
    bit32 valid_user_flags[MAX_USER_FLAGS/32];
    struct buf buf = BUF_INITIALIZER;

    if (make_changes && !(flags & RECONSTRUCT_QUIET)) {
        syslog(LOG_NOTICE, "reconstructing %s", name);
    }

    r = mailbox_open_iwl(name, &mailbox);
    if (r) {
        if (!make_changes) return r;
        /* returns a locktype == LOCK_EXCLUSIVE mailbox */
        r = mailbox_reconstruct_create(name, &mailbox);
    }
    if (r) return r;

    /* NOTE: we have to do this first, because it reads the header */
    r = mailbox_reconstruct_acl(mailbox, flags);
    if (r) goto close;

    r = mailbox_reconstruct_uniqueid(mailbox, flags);
    if (r) goto close;

    /* open and lock the annotation state */
    r = mailbox_get_annotate_state(mailbox, ANNOTATE_ANY_UID, NULL);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open annotations %s: %s",
               mailbox->name, error_message(r));
        goto close;
    }

    /* Validate user flags */
    for (i = 0; i < MAX_USER_FLAGS/32; i++) {
        valid_user_flags[i] = 0;
    }
    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
        if (!mailbox->flagname[flag]) continue;
        if ((flag && !mailbox->flagname[flag-1]) ||
            !imparse_isatom(mailbox->flagname[flag])) {
            printf("%s: bogus flag name %d:%s",
                   mailbox->name, flag, mailbox->flagname[flag]);
            syslog(LOG_ERR, "%s: bogus flag name %d:%s",
                   mailbox->name, flag, mailbox->flagname[flag]);
            mailbox->header_dirty = 1;
            free(mailbox->flagname[flag]);
            mailbox->flagname[flag] = NULL;
            continue;
        }
        valid_user_flags[flag/32] |= 1<<(flag&31);
    }

    /* find cyrus.expunge file if present */
    cleanup_stale_expunged(mailbox);

    r = find_files(mailbox, &files, flags);
    if (r) goto close;

    r = find_annots(mailbox, &annots);
    if (r) goto close;

    uint32_t recno;
    struct index_record record;
    for (recno = 1; recno <= mailbox->i.num_records; recno++) {
        r = mailbox_read_index_record(mailbox, recno, &record);
        if (r || record.uid <= last_seen_uid) {
            if (!r && record.uid)
                syslog(LOG_ERR, "%s out of order uid %u at record %u, wiping",
                       mailbox->name, record.uid, record.recno);
            if (r)
                syslog(LOG_ERR, "%s failed to read at record %u (%s), wiping",
                       mailbox->name, record.recno, error_message(r));
            mailbox_wipe_index_record(mailbox, &record);
            continue;
        }

        last_seen_uid = record.uid;

        /* bogus annotations? XXX: should we try to keep them if we found a file? */
        while (annots.pos < annots.nused && annots.found[annots.pos].uid < record.uid) {
            add_found(&delannots, annots.found[annots.pos].uid, /*isarchive*/0);
            annots.pos++;
        }

        /* skip over current */
        int has_snoozedannot = 0;
        while (annots.pos < annots.nused && annots.found[annots.pos].uid == record.uid) {
            if (annots.found[annots.pos].issnoozed) has_snoozedannot = 1;
            annots.pos++;
        }

        /* lower UID file exists */
        while (files.pos < files.nused && files.found[files.pos].uid < record.uid) {
            add_found(&discovered, files.found[files.pos].uid, files.found[files.pos].isarchive);
            files.pos++;
        }

        /* if they match, advance the pointer */
        have_file = 0;
        while (files.pos < files.nused && files.found[files.pos].uid == record.uid) {
            if (have_file) {
                /* we can just unlink this one, already processed one copy */
                const char *fname = mboxname_archivepath(mailbox->part, mailbox->name,
                                                         mailbox->uniqueid, record.uid);
                printf("Removing duplicate archive file %s\n", fname);
                unlink(fname);
            }
            else {
                if (files.found[files.pos].isarchive) {
                    if (!(record.internal_flags & FLAG_INTERNAL_ARCHIVED)) {
                        /* oops, it's really archived - let's fix that right now */
                        record.internal_flags |= FLAG_INTERNAL_ARCHIVED;
                        printf("Marking file as archived %s %u\n", mailbox->name, record.uid);
                        mailbox_rewrite_index_record(mailbox, &record);
                    }
                }
                else {
                    if (record.internal_flags & FLAG_INTERNAL_ARCHIVED) {
                        /* oops, non-archived copy exists, let's use that */
                        record.internal_flags &= ~FLAG_INTERNAL_ARCHIVED;
                        printf("Marking file as not archived %s %u\n", mailbox->name, record.uid);
                        mailbox_rewrite_index_record(mailbox, &record);
                    }
                }
                have_file = 1;
            }
            files.pos++;
        }

        r = mailbox_reconstruct_compare_update(mailbox, &record,
                                               valid_user_flags,
                                               flags, have_file,
                                               has_snoozedannot,
                                               &discovered);
        if (r) goto close;

        if (mailbox->i.minor_version >= 13) {
            buf_reset(&buf);
            mailbox_annotation_lookup(mailbox, record.uid, IMAP_ANNOT_NS "thrid", "", &buf);
            if (!buf.len) mailbox_annotation_lookup(mailbox, record.uid, IMAP_ANNOT_NS "thrid", NULL, &buf);
            if (buf.len) {
                syslog(LOG_NOTICE, "removing stale thrid for %u", record.uid);
                printf("removing stale thrid for %u\n", record.uid);
                buf_reset(&buf);
                r = mailbox_annotation_write(mailbox, record.uid, IMAP_ANNOT_NS "thrid", "", &buf);
                if (r) goto close;
            }
        }

        if (mailbox->i.minor_version >= 15) {
            buf_reset(&buf);
            mailbox_annotation_lookup(mailbox, record.uid, IMAP_ANNOT_NS "savedate", "", &buf);
            if (!buf.len) mailbox_annotation_lookup(mailbox, record.uid, IMAP_ANNOT_NS "savedate", NULL, &buf);
            if (buf.len) {
                syslog(LOG_NOTICE, "removing stale savedate for %u", record.uid);
                printf("removing stale savedate for %u\n", record.uid);
                buf_reset(&buf);
                r = mailbox_annotation_write(mailbox, record.uid, IMAP_ANNOT_NS "savedate", "", &buf);
                if (r) goto close;
            }
        }

        if (mailbox->i.minor_version >= 16) {
            buf_reset(&buf);
            mailbox_annotation_lookup(mailbox, record.uid, IMAP_ANNOT_NS "createdmodseq", "", &buf);
            if (!buf.len) mailbox_annotation_lookup(mailbox, record.uid, IMAP_ANNOT_NS "createdmodseq", NULL, &buf);
            if (buf.len) {
                syslog(LOG_NOTICE, "removing stale createdmodseq for %u", record.uid);
                printf("removing stale createdmodseq for %u\n", record.uid);
                buf_reset(&buf);
                r = mailbox_annotation_write(mailbox, record.uid, IMAP_ANNOT_NS "createdmodseq", "", &buf);
                if (r) goto close;
            }
        }
    }

    /* add discovered messages before last_uid to the list in order */
    while (files.pos < files.nused && files.found[files.pos].uid <= mailbox->i.last_uid) {
        add_found(&discovered, files.found[files.pos].uid, files.found[files.pos].isarchive);
        files.pos++;
    }

    /* messages AFTER last_uid can keep the same UID (see also, restore
     * from lost .index file) - so don't bother moving those */
    while (files.pos < files.nused) {
        uint32_t uid = files.found[files.pos].uid;

        /* bogus annotations? */
        while (annots.pos < annots.nused && annots.found[annots.pos].uid < uid) {
            add_found(&delannots, annots.found[annots.pos].uid, /*isarchive*/0);
            annots.pos++;
        }

        int has_snoozedannot = 0;
        /* we can keep this annotation too... */
        while (annots.pos < annots.nused && annots.found[annots.pos].uid == uid) {
            if (annots.found[annots.pos].issnoozed) has_snoozedannot = 1;
            annots.pos++;
        }


        r = mailbox_reconstruct_append(mailbox, files.found[files.pos].uid,
                                       files.found[files.pos].isarchive,
                                       has_snoozedannot, flags);
        if (r) goto close;
        files.pos++;

    }

    /* bogus annotations after the end? */
    while (annots.pos < annots.nused) {
        add_found(&delannots, annots.found[annots.pos].uid, /*isarchive*/0);
        annots.pos++;
    }

    /* handle new list - note, we don't copy annotations for these */
    while (discovered.pos < discovered.nused) {
        r = mailbox_reconstruct_append(mailbox, discovered.found[discovered.pos].uid,
                                       discovered.found[discovered.pos].isarchive,
                                       /*has_snoozedannot*/0, flags);
        if (r) goto close;
        discovered.pos++;
    }

    if (delannots.nused) {
        r = reconstruct_delannots(mailbox, &delannots, flags);
        if (r) goto close;
    }

    /* make sure we have enough index file mmaped */
    r = mailbox_refresh_index_map(mailbox);

    old_header = mailbox->i;

    /* re-calculate derived fields */
    r = mailbox_index_recalc(mailbox);
    if (r) goto close;

    /* inform users of any changed header fields */
    reconstruct_compare_headers(mailbox, &old_header, &mailbox->i);

    /* fix up 2.4.0 bug breakage */
    if (!mailbox->i.uidvalidity) {
        if (make_changes) {
            mailbox->i.uidvalidity = mboxname_nextuidvalidity(mailbox->name, time(0));
            mailbox_index_dirty(mailbox);
        }
        syslog(LOG_ERR, "%s: zero uidvalidity", mailbox->name);
    }
    if (!mailbox->i.highestmodseq) {
        if (make_changes) {
            mailbox_index_dirty(mailbox);
            mailbox->i.highestmodseq = mboxname_nextmodseq(mailbox->name, 0, mailbox->mbtype,
                                                           MBOXMODSEQ_ISFOLDER);
        }
        syslog(LOG_ERR, "%s:  zero highestmodseq", mailbox->name);
    }
    else {
        mboxname_setmodseq(mailbox->name, mailbox->i.highestmodseq, mailbox->mbtype,
                           MBOXMODSEQ_ISFOLDER);
    }

    if (make_changes) {
        r = mailbox_commit(mailbox);
    }
    else {
        r = mailbox_abort(mailbox);
    }

close:
    free_found(&files);
    free_found(&discovered);
    free_found(&annots);
    free_found(&delannots);
    mailbox_close(&mailbox);
    buf_free(&buf);
    return r;
}

EXPORTED struct mailbox_iter *mailbox_iter_init(struct mailbox *mailbox,
                                                modseq_t changedsince,
                                                unsigned flags)
{
    struct mailbox_iter *iter = xzmalloc(sizeof(struct mailbox_iter));
    iter->mailbox = mailbox;
    iter->changedsince = changedsince;
    iter->num_records = mailbox->i.num_records;
    iter->msg = message_new();

    /* calculate which system_flags to skip over */
    if (flags & ITER_SKIP_UNLINKED)
        iter->skipflags |= FLAG_INTERNAL_UNLINKED;
    if (flags & ITER_SKIP_EXPUNGED)
        iter->skipflags |= FLAG_INTERNAL_EXPUNGED;
    if (flags & ITER_SKIP_DELETED)
        iter->skipflags |= FLAG_DELETED;

    return iter;
}

EXPORTED void mailbox_iter_startuid(struct mailbox_iter *iter, uint32_t uid)
{
    struct mailbox *mailbox = iter->mailbox;
    iter->recno = uid ? mailbox_finduid(mailbox, uid-1) : 0;
}

EXPORTED const message_t *mailbox_iter_step(struct mailbox_iter *iter)
{
    if (mailbox_wait_cb) mailbox_wait_cb(mailbox_wait_cb_rock);

    for (iter->recno++; iter->recno <= iter->num_records; iter->recno++) {
        message_set_from_mailbox(iter->mailbox, iter->recno, iter->msg);
        const struct index_record *record = msg_record(iter->msg);
        if (!record->uid) continue; /* can happen on damaged mailboxes */
        if ((record->system_flags & iter->skipflags)) continue;
        if ((record->internal_flags & iter->skipflags)) continue;
        if (iter->changedsince && record->modseq <= iter->changedsince) continue;
        return iter->msg;
    }

    /* guess we're done */
    return NULL;
}

EXPORTED void mailbox_iter_done(struct mailbox_iter **iterp)
{
    struct mailbox_iter *iter = *iterp;
    if (!iter) return;
    message_unref(&iter->msg);
    free(iter);
    *iterp = NULL;
}

/*
 * Gets messages usage.
 */
EXPORTED void mailbox_get_usage(struct mailbox *mailbox,
                        quota_t usage[QUOTA_NUMRESOURCES])
{
    int res;

    for (res = 0; res < QUOTA_NUMRESOURCES; res++) {
        usage[res] = 0;
    }

    if (!(mailbox->i.options & OPT_MAILBOX_DELETED)) {
        usage[QUOTA_STORAGE] = mailbox->i.quota_mailbox_used;
        usage[QUOTA_MESSAGE] = mailbox->i.exists;
        usage[QUOTA_ANNOTSTORAGE] = mailbox->i.quota_annot_used;
        usage[QUOTA_NUMFOLDERS] = 1;
    }
    /* else: mailbox is being deleted, thus its new usage is 0 */
}

EXPORTED int mailbox_get_annotate_state(struct mailbox *mailbox,
                               unsigned int uid,
                               annotate_state_t **statep)
{
    int r = 0;

    if (statep) *statep = NULL;

    if (!mailbox->annot_state)
        mailbox->annot_state = annotate_state_new();

    r = annotate_state_set_message(mailbox->annot_state, mailbox, uid);
    if (r) return r;

    /* lock immediately if we have a write lock */
    if (mailbox_index_islocked(mailbox, /*write*/1))
        annotate_state_begin(mailbox->annot_state);

    if (statep) *statep = mailbox->annot_state;

    return 0;
}

EXPORTED int mailbox_annotation_write(struct mailbox *mailbox, uint32_t uid,
                                      const char *entry, const char *userid,
                                      const struct buf *value)
{
    annotate_state_t *state = NULL;
    int r = 0;
    struct buf oldvalue = BUF_INITIALIZER;

    annotatemore_msg_lookup(mailbox, uid, entry, userid, &oldvalue);
    if (oldvalue.len == value->len && (!value->len || !memcmp(oldvalue.s, value->s, value->len)))
        goto done;

    struct index_record record;
    memset(&record, 0, sizeof(struct index_record));
    r = mailbox_find_index_record(mailbox, uid, &record);
    if (r) goto done;

    r = mailbox_get_annotate_state(mailbox, uid, &state);
    if (r) goto done;

    r = annotate_state_write(state, entry, userid, value);
    if (r) goto done;

    /* need to touch the modseq */
    r = mailbox_rewrite_index_record(mailbox, &record);
    if (r) goto done;

done:
    buf_free(&oldvalue);
    return r;
}

EXPORTED int mailbox_annotation_writemask(struct mailbox *mailbox, uint32_t uid,
                                          const char *entry, const char *userid,
                                          const struct buf *value)
{
    annotate_state_t *state = NULL;
    int r = 0;
    struct buf oldvalue = BUF_INITIALIZER;

    /* we don't lookupmask here - because we want to still write the value as the
     * user's own value rather than the masked value, regardless of whether they
     * have the same content */
    annotatemore_msg_lookup(mailbox, uid, entry, userid, &oldvalue);
    if (oldvalue.len == value->len && (!value->len || !memcmp(oldvalue.s, value->s, value->len)))
        goto done;

    struct index_record record;
    memset(&record, 0, sizeof(struct index_record));
    r = mailbox_find_index_record(mailbox, uid, &record);
    if (r) goto done;

    r = mailbox_get_annotate_state(mailbox, uid, &state);
    if (r) goto done;

    r = annotate_state_writemask(state, entry, userid, value);
    if (r) goto done;

    /* need to touch the modseq */
    r = mailbox_rewrite_index_record(mailbox, &record);
    if (r) goto done;

done:
    buf_free(&oldvalue);
    return r;
}

EXPORTED int mailbox_annotation_lookup(struct mailbox *mailbox, uint32_t uid,
                                       const char *entry, const char *userid,
                                       struct buf *value)
{
    return annotatemore_msg_lookup(mailbox, uid, entry, userid, value);
}

EXPORTED int mailbox_annotation_lookupmask(struct mailbox *mailbox, uint32_t uid,
                                           const char *entry, const char *userid,
                                           struct buf *value)
{
    return annotatemore_msg_lookupmask(mailbox, uid, entry, userid, value);
}


int mailbox_cid_rename(struct mailbox *mailbox,
                       conversation_id_t from_cid,
                       conversation_id_t to_cid)
{
    const message_t *msg;
    int r = 0;

    if (!config_getswitch(IMAPOPT_CONVERSATIONS))
        return 0;

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, ITER_SKIP_UNLINKED);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        if (record->cid != from_cid)
            continue;

        /*
         * Just rename the CID in place - injecting a copy at the end
         * messes with clients that just use UID ordering, like Apple's
         * IOS email client */

        struct index_record copyrecord = *record;
        copyrecord.cid = to_cid;
        r = mailbox_rewrite_index_record(mailbox, &copyrecord);

        if (r) {
            syslog(LOG_ERR, "mailbox_cid_rename: error "
                            "rewriting record %u, mailbox %s: %s from %llu to %llu",
                            record->recno, mailbox->name, error_message(r), from_cid, to_cid);
            break;
        }
    }
    mailbox_iter_done(&iter);

    return r;
}

EXPORTED void mailbox_set_wait_cb(void (*cb)(void *), void *rock)
{
    mailbox_wait_cb = cb;
    mailbox_wait_cb_rock = rock;
}

/* if either CRC is zero for a field, then we consider it to match.
 * this lets us bootstrap the case where CRCs weren't being calculated,
 * and also allows a client with incomplete local information to request
 * a change be made on a sync_server without having to fetch all the
 * data first just to calculate the CRC */
EXPORTED int mailbox_crceq(struct synccrcs a, struct synccrcs b)
{
    if (a.basic && b.basic && a.basic != b.basic) return 0;
    if (a.annot && b.annot && a.annot != b.annot) return 0;
    return 1;
}

EXPORTED struct dlist *mailbox_acl_to_dlist(const char *aclstr)
{
    const char *p, *q;
    struct dlist *al = dlist_newkvlist(NULL, "A");

    p = aclstr;

    while (p && *p) {
        char *name,*val;

        q = strchr(p, '\t');
        if (!q) break;

        name = xstrndup(p, q-p);
        q++;

        p = strchr(q, '\t');
        if (p) {
            val = xstrndup(q, p-q);
            p++;
        }
        else
            val = xstrdup(q);

        dlist_setatom(al, name, val);

        free(name);
        free(val);
    }

    return al;
}

HIDDEN int mailbox_changequotaroot(struct mailbox *mailbox,
                                   const char *root, int silent)
{
    int r = 0;
    int res;
    quota_t quota_usage[QUOTA_NUMRESOURCES];

    mailbox_get_usage(mailbox, quota_usage);

    if (mailbox->quotaroot) {
        quota_t quota_diff[QUOTA_NUMRESOURCES];

        if (root && strlen(mailbox->quotaroot) >= strlen(root)) {
            /* Part of a child quota root - skip */
            goto done;
        }

        /* remove usage from the old quotaroot */
        for (res = 0; res < QUOTA_NUMRESOURCES ; res++) {
            quota_diff[res] = -quota_usage[res];
        }
        r = quota_update_useds(mailbox->quotaroot, quota_diff,
                               mailbox->name, silent);
    }

    /* update (or set) the quotaroot */
    r = mailbox_set_quotaroot(mailbox, root);
    if (r) goto done;

    if (root) {
        /* update the new quota root */
      r = quota_update_useds(root, quota_usage, mailbox->name, silent);
    }

  done:
    return r;
}
