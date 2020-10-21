/* mailbox.h -- Mailbox format definitions
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

#ifndef INCLUDED_MAILBOX_H
#define INCLUDED_MAILBOX_H

#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <config.h>

#include "byteorder.h"
#include "conversations.h"
#include "message_guid.h"
#include "message.h"
#include "ptrarray.h"
#include "quota.h"
#include "seqset.h"
#include "util.h"

#define MAX_MAILBOX_NAME 490
/* enough space for all possible rewrites and DELETED.* and stuff */
#define MAX_MAILBOX_BUFFER 1024
#define MAX_MAILBOX_PATH 4096

#define MAX_USER_FLAGS (16*8)

#define MAILBOX_HEADER_MAGIC ("\241\002\213\015Cyrus mailbox header\n" \
     "\"The best thing about this system was that it had lots of goals.\"\n" \
     "\t--Jim Morris on Andrew\n")


/* NOTE: the mailbox minor version must be changed whenever any on-disk
 * format changes are made to any mailbox files.  It is also important to
 * make sure all the mailbox upgrade and downgrade code in mailbox.c is
 * changed to be able to convert both backwards and forwards between the
 * new version and all supported previous versions.
 * If you change MAILBOX_MINOR_VERSION you MUST also make corresponding
 * changes to backend_version() in backend.c, AND backport those changes to
 * all supported older versions, to avoid breaking XFER.  Annoyingly, older
 * versions placed this function in imapd.c FYI!
 */
#define MAILBOX_MINOR_VERSION   17
#define MAILBOX_CACHE_MINOR_VERSION 11

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
    uint32_t unseen;
    uint32_t mboptions;
    quota_t size;
    modseq_t createdmodseq;
    modseq_t highestmodseq;
    conv_status_t xconv;
};

#define STATUSDATA_INIT { NULL, 0, 0, 0, 0, 0, NULL, 0, 0, 0, 0, 0, CONV_STATUS_INIT }

struct index_record {
    uint32_t uid;
    time_t internaldate;
    time_t sentdate;
    uint32_t size;
    uint32_t header_size;
    time_t gmtime;
    size_t cache_offset;
    time_t last_updated;
    uint32_t system_flags;
    uint32_t internal_flags;
    uint32_t user_flags[MAX_USER_FLAGS/32];
    time_t savedate;
    uint16_t cache_version;
    struct message_guid guid;
    modseq_t modseq;
    bit64 cid;
    modseq_t createdmodseq;
    bit32 cache_crc;

    /* metadata */
    uint32_t recno;
    unsigned silentupdate:1;
    unsigned ignorelimits:1;
    bit64 basecid;
    struct cacherecord crec;
};

struct synccrcs {
    uint32_t basic;
    uint32_t annot;
};

struct index_header {
    /* track if it's been changed */
    int dirty;

    /* header fields */
    bit32 generation_no;
    int format;
    int minor_version;
    uint32_t start_offset;
    uint32_t record_size;
    uint32_t num_records;
    time_t last_appenddate;
    uint32_t last_uid;
    quota_t quota_mailbox_used;
    time_t pop3_last_login;
    uint32_t uidvalidity;

    uint32_t deleted;
    uint32_t answered;
    uint32_t flagged;
    uint32_t unseen;

    uint32_t options;
    uint32_t leaked_cache_records;
    modseq_t highestmodseq;
    modseq_t deletedmodseq;
    uint32_t exists;
    time_t first_expunged;
    time_t last_repack_time;
    time_t changes_epoch;

    modseq_t createdmodseq;

    bit32 header_file_crc;
    struct synccrcs synccrcs;

    uint32_t recentuid;
    time_t recenttime;

    time_t pop3_show_after;
    quota_t quota_annot_used;
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
    char *quotaroot;
    char *flagname[MAX_USER_FLAGS];
    int mbtype;
};

struct mailbox {
    int index_fd;
    int header_fd;

    ptrarray_t caches;
    const char *index_base;
    size_t index_len;   /* mapped size */

    int index_locktype; /* 0 = none, 1 = shared, 2 = exclusive */
    int is_readonly; /* true = open index and cache files readonly */

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
    struct conversations_state *local_cstate;

    /* namespace lock */
    struct mboxlock *local_namespacelock;

#ifdef WITH_DAV
    struct caldav_db *local_caldav;
    struct carddav_db *local_carddav;
    struct webdav_db *local_webdav;
#endif
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
    time_t last_updated; /* for appends*/
    quota_t quota_previously_used[QUOTA_NUMRESOURCES]; /* for quota change */

    /* index change map */
    uint32_t index_change_map[INDEX_MAP_SIZE];
    struct index_change *index_changes;
    uint32_t index_change_alloc;
    uint32_t index_change_count;
};

#define ITER_SKIP_UNLINKED (1<<0)
#define ITER_SKIP_EXPUNGED (1<<1)
#define ITER_SKIP_DELETED (1<<2)

/* pre-declare message_t to avoid circular dependency problems */
typedef struct message message_t;

struct mailbox_iter;

/* Offsets of index/expunge header fields
 *
 * NOTE: Since we might be using a 64-bit MODSEQ in the index record,
 *       the size of the index header MUST be a multiple of 8 bytes.
 */
#define OFFSET_GENERATION_NO 0
#define OFFSET_FORMAT 4
#define OFFSET_MINOR_VERSION 8
#define OFFSET_START_OFFSET 12
#define OFFSET_RECORD_SIZE 16
#define OFFSET_NUM_RECORDS 20
#define OFFSET_LAST_APPENDDATE 24
#define OFFSET_LAST_UID 28
#define OFFSET_QUOTA_MAILBOX_USED 32  /* offset for 64bit quotas */
#define OFFSET_POP3_LAST_LOGIN 40
#define OFFSET_UIDVALIDITY 44
#define OFFSET_DELETED 48      /* added for ACAP */
#define OFFSET_ANSWERED 52
#define OFFSET_FLAGGED 56
#define OFFSET_MAILBOX_OPTIONS 60
#define OFFSET_LEAKED_CACHE 64     /* Number of leaked records in cache file */
#define OFFSET_HIGHESTMODSEQ 68    /* CONDSTORE (64-bit modseq) */
#define OFFSET_DELETEDMODSEQ 76    /* CONDSTORE (64-bit modseq) */
#define OFFSET_EXISTS 84           /* Non-expunged records */
#define OFFSET_FIRST_EXPUNGED 88   /* last_updated of oldest expunged message */
#define OFFSET_LAST_REPACK_TIME 92 /* time of last expunged cleanup  */
#define OFFSET_HEADER_FILE_CRC 96  /* CRC32 of the index header file */
#define OFFSET_SYNCCRCS_BASIC 100  /* XOR of SYNC CRCs of unexpunged records */
#define OFFSET_RECENTUID 104       /* last UID the owner was told about */
#define OFFSET_RECENTTIME 108      /* last timestamp for seen data */
#define OFFSET_POP3_SHOW_AFTER 112 /* time after which to show messages
                                    * to POP3 */
#define OFFSET_QUOTA_ANNOT_USED 116 /* bytes of per-mailbox and per-message
                                     * annotations for this mailbox */
                          /* Spares - only use these if the index */
                          /*  record size remains the same */
#define OFFSET_SYNCCRCS_ANNOT 120 /* SYNC_CRC of the annotations */
#define OFFSET_UNSEEN 124         /* total number of UNSEEN messages (owner) */
/* NEXT UPDATE - add Bug #3562 "TOTAL_MAILBOX_USED" field, 64 bit
 * value which counts the total size of all files included expunged
 * files. We've created the header space now, but will also need code
 * changes, so holding off */
#define OFFSET_MAILBOX_CREATEDMODSEQ 128 /* MODSEQ at creation time */
#define OFFSET_CHANGES_EPOCH 136   /* time from which we can calculate changes */
#define OFFSET_SPARE1 140
#define OFFSET_SPARE2 144
#define OFFSET_SPARE3 148
#define OFFSET_SPARE4 152
#define OFFSET_HEADER_CRC 156 /* includes all zero for the spares! */

/* Offsets of index_record fields in index/expunge file
 *
 * NOTE: Since we might be using a 64-bit MODSEQ in the index record,
 *       OFFSET_MODSEQ_64 and the size of the index record MUST be
 *       multiples of 8 bytes.
 */
#define OFFSET_UID 0
#define OFFSET_INTERNALDATE 4
#define OFFSET_SENTDATE 8
#define OFFSET_SIZE 12
#define OFFSET_HEADER_SIZE 16
#define OFFSET_GMTIME 20
#define OFFSET_CACHE_OFFSET 24
#define OFFSET_LAST_UPDATED 28
#define OFFSET_SYSTEM_FLAGS 32
#define OFFSET_USER_FLAGS 36
#define OFFSET_SAVEDATE 52 /* added in v15 */
#define OFFSET_CACHE_VERSION 56
#define OFFSET_MESSAGE_GUID 60
#define OFFSET_MODSEQ 80 /* CONDSTORE (64-bit modseq) */
#define OFFSET_THRID 88       /* conversation id, added in v13 */
#define OFFSET_CREATEDMODSEQ 96 /* modseq of creation time, added in v16 */
#define OFFSET_CACHE_CRC 104 /* CRC32 of cache record */
#define OFFSET_RECORD_CRC 108

#define INDEX_HEADER_SIZE (OFFSET_HEADER_CRC+4)
#define INDEX_RECORD_SIZE (OFFSET_RECORD_CRC+4)

typedef enum _MsgFlags {
    FLAG_ANSWERED           = (1<<0),
    FLAG_FLAGGED            = (1<<1),
    FLAG_DELETED            = (1<<2),
    FLAG_DRAFT              = (1<<3),
    FLAG_SEEN               = (1<<4),
} MsgFlags;

/* NOTE: you can only use up to 1<<15 for MsgFlags and down to 1<<16 for
 * InternalFlags unless you change the code in mailbox_buf_to_index_record
 * which is currently:
 *     record->system_flags = stored_system_flags & 0x0000ffff;
 *     record->internal_flags = stored_system_flags & 0xffff0000;
 */

typedef enum _MsgInternalFlags {
    FLAG_INTERNAL_SNOOZED            = (1<<26),
    FLAG_INTERNAL_SPLITCONVERSATION  = (1<<27),
    FLAG_INTERNAL_NEEDS_CLEANUP      = (1<<28),
    FLAG_INTERNAL_ARCHIVED           = (1<<29),
    FLAG_INTERNAL_UNLINKED           = (1<<30),
    FLAG_INTERNAL_EXPUNGED           = (1U<<31),
} MsgInternalFlags;

#define FLAGS_SYSTEM   (FLAG_ANSWERED|FLAG_FLAGGED|FLAG_DELETED|FLAG_DRAFT|FLAG_SEEN)

#define OPT_POP3_NEW_UIDL (1<<0)        /* added for Outlook stupidity */
/* NOTE: not used anymore - but don't reuse it */
#define OPT_IMAP_CONDSTORE (1<<1)       /* added for CONDSTORE extension */

/* these two are annotations, if you add more, update annotate.c
 * struct annotate_mailbox_flags */
#define OPT_IMAP_SHAREDSEEN (1<<2)      /* added for shared \Seen flag */
#define OPT_IMAP_DUPDELIVER (1<<3)      /* added to allow duplicate delivery */

#define OPT_IMAP_HAS_ALARMS (1<<4)      /* messages in mailbox have alarms */

#define OPT_MAILBOX_NEEDS_UNLINK (1<<29)        /* files to be unlinked */
#define OPT_MAILBOX_NEEDS_REPACK (1<<30)        /* repacking to do */
#define OPT_MAILBOX_DELETED (1U<<31)    /* mailbox is deleted an awaiting cleanup */

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

/* Cache item positions */
enum {
    CACHE_ENVELOPE = 0,
    CACHE_BODYSTRUCTURE,
    CACHE_BODY,
    CACHE_SECTION,
    CACHE_HEADERS,
    CACHE_FROM,
    CACHE_TO,
    CACHE_CC,
    CACHE_BCC,
    CACHE_SUBJECT
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
 */
struct MsgFlagMap {
    const char *code;
    MsgFlags flag;
};

unsigned mailbox_cached_header(const char *s);
unsigned mailbox_cached_header_inline(const char *text);

typedef unsigned mailbox_decideproc_t(struct mailbox *mailbox,
                                      const struct index_record *index,
                                      void *rock);

typedef void mailbox_notifyproc_t(const char *mboxname);

extern void mailbox_set_updatenotifier(mailbox_notifyproc_t *notifyproc);
extern mailbox_notifyproc_t *mailbox_get_updatenotifier(void);

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
extern void mailbox_close(struct mailbox **mailboxptr);
extern int mailbox_delete(struct mailbox **mailboxptr);

/* reading details */
extern const char *mailbox_name(const struct mailbox *mailbox);
extern const char *mailbox_uniqueid(const struct mailbox *mailbox);
extern const char *mailbox_partition(const struct mailbox *mailbox);
extern const char *mailbox_acl(const struct mailbox *mailbox);
extern const char *mailbox_quotaroot(const struct mailbox *mailbox);
extern uint32_t mailbox_mbtype(const struct mailbox *mailbox);
extern modseq_t mailbox_foldermodseq(const struct mailbox *mailbox);

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

extern int mailbox_expunge_cleanup(struct mailbox *mailbox, time_t expunge_mark,
                                   unsigned *ndeleted);
extern int mailbox_expunge(struct mailbox *mailbox,
                           mailbox_decideproc_t *decideproc, void *deciderock,
                           unsigned *nexpunged, int event_type);
extern void mailbox_archive(struct mailbox *mailbox,
                            mailbox_decideproc_t *decideproc, void *deciderock, unsigned flags);
extern void mailbox_remove_files_from_object_storage(struct mailbox *mailbox, unsigned flags);
extern int mailbox_cleanup(struct mailbox *mailbox, int iscurrentdir,
                           mailbox_decideproc_t *decideproc, void *deciderock);
extern void mailbox_unlock_index(struct mailbox *mailbox, struct statusdata *sd);

extern int mailbox_create(const char *name, uint32_t mbtype, const char *part, const char *acl,
                          const char *uniqueid, int options, unsigned uidvalidity,
                          modseq_t createdmodseq, modseq_t highestmodseq,
                          struct mailbox **mailboxptr);

extern int mailbox_copy_files(struct mailbox *mailbox, const char *newpart,
                              const char *newname, const char *newuniqueid);
extern int mailbox_delete_cleanup(struct mailbox *mailbox, const char *part, const char *name, const char *uniqueid);

extern int mailbox_rename_nocopy(struct mailbox *oldmailbox,
                                 const char *newname, int silent);

extern int mailbox_rename_copy(struct mailbox *oldmailbox,
                               const char *newname, const char *newpart,
                               unsigned uidvalidity,
                               int ignorequota, int silent,
                               struct mailbox **newmailboxptr);
extern int mailbox_rename_cleanup(struct mailbox **mailboxptr);


extern int mailbox_copyfile(const char *from, const char *to, int nolink);

extern int mailbox_reconstruct(const char *name, int flags, struct mailbox **mailboxp);
extern void mailbox_make_uniqueid(struct mailbox *mailbox);

extern int mailbox_setversion(struct mailbox *mailbox, int version);

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
extern void mailbox_iter_startuid(struct mailbox_iter *iter, uint32_t uid);
extern void mailbox_iter_uidset(struct mailbox_iter *iter, seqset_t *seq);
extern const message_t *mailbox_iter_step(struct mailbox_iter *iter);
extern void mailbox_iter_done(struct mailbox_iter **iterp);

struct synccrcs mailbox_synccrcs(struct mailbox *mailbox, int recalc);

extern int mailbox_add_dav(struct mailbox *mailbox);
extern int mailbox_delete_dav(struct mailbox *mailbox);
extern int mailbox_add_sieve(struct mailbox *mailbox);
extern int mailbox_add_email_alarms(struct mailbox *mailbox);

/* Rename a CID.  Note - this is just one mailbox! */
extern int mailbox_cid_rename(struct mailbox *mailbox,
                              conversation_id_t from_cid,
                              conversation_id_t to_cid);
extern int mailbox_add_conversations(struct mailbox *mailbox, int silent);
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

#endif /* INCLUDED_MAILBOX_H */
