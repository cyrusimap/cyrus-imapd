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
 *
 * $Id: mailbox.h,v 1.98 2010/06/28 12:04:20 brong Exp $
 */

#ifndef INCLUDED_MAILBOX_H
#define INCLUDED_MAILBOX_H

#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <config.h>

#include "auth.h"
#include "byteorder64.h"
#include "message_guid.h"
#include "prot.h"
#include "quota.h"
#include "sequence.h"

#define MAX_MAILBOX_NAME 490
/* enough space for all possible rewrites and DELETED.* and stuff */
#define MAX_MAILBOX_BUFFER 1024
#define MAX_MAILBOX_PATH 4096

#define MAX_USER_FLAGS (16*8)

#define MAILBOX_HEADER_MAGIC ("\241\002\213\015Cyrus mailbox header\n" \
     "\"The best thing about this system was that it had lots of goals.\"\n" \
     "\t--Jim Morris on Andrew\n")

#define MAILBOX_MINOR_VERSION	12
#define MAILBOX_CACHE_MINOR_VERSION 3

#define FNAME_HEADER "/cyrus.header"
#define FNAME_INDEX "/cyrus.index"
#define FNAME_CACHE "/cyrus.cache"
#define FNAME_SQUAT "/cyrus.squat"
#define FNAME_EXPUNGE "/cyrus.expunge"
#define FNAME_DAV "/cyrus.dav"

enum meta_filename {
  META_HEADER = 1,
  META_INDEX,
  META_CACHE,
  META_SQUAT,
  META_EXPUNGE,
  META_DAV
};

#define MAILBOX_FNAME_LEN 256

#define LOCK_NONE 0
#define LOCK_SHARED 1
#define LOCK_EXCLUSIVE 2
#define LOCK_NONBLOCKING 3

#define NUM_CACHE_FIELDS 10

struct cacheitem {
    unsigned offset;
    unsigned len;
};

struct cacherecord {
    struct buf *base;
    unsigned offset;
    unsigned len;
    struct cacheitem item[NUM_CACHE_FIELDS];
};

struct statusdata {
    const char *userid;
    unsigned statusitems;

    unsigned messages;
    unsigned recent;
    unsigned uidnext;
    unsigned uidvalidity;
    unsigned unseen;
    modseq_t highestmodseq;
};

struct index_record {
    uint32_t uid;
    time_t internaldate;
    time_t sentdate;
    uint32_t size;
    uint32_t header_size;
    time_t gmtime;
    uint32_t cache_offset;
    time_t last_updated;
    bit32 system_flags;
    bit32 user_flags[MAX_USER_FLAGS/32];
    uint32_t content_lines;
    uint32_t cache_version;
    struct message_guid guid;
    modseq_t modseq;
    bit32 cache_crc;
    bit32 record_crc;

    /* metadata */
    uint32_t recno;
    int silent;
    struct cacherecord crec;
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
    uquota_t quota_mailbox_used;
    time_t pop3_last_login;
    uint32_t uidvalidity;

    uint32_t deleted;
    uint32_t answered;
    uint32_t flagged;

    uint32_t options;
    uint32_t leaked_cache_records;
    modseq_t highestmodseq;
    modseq_t deletedmodseq;
    uint32_t exists;
    time_t first_expunged;
    time_t last_repack_time;

    bit32 header_file_crc;
    bit32 sync_crc;

    uint32_t recentuid;
    time_t recenttime;

    uint32_t header_crc;
};

struct mailbox {
    int index_fd;
    int cache_fd;
    int lock_fd;
    int header_fd;

    const char *index_base;
    unsigned long index_len;	/* mapped size */
    struct buf cache_buf;
    unsigned long cache_len;	/* mapped size */

    int index_locktype; /* 0 = none, 1 = shared, 2 = exclusive */

    ino_t header_file_ino;
    bit32 header_file_crc;

    time_t index_mtime;
    ino_t index_ino;
    size_t index_size;
    int need_cache_refresh;

    /* Information in mailbox list */
    char *name;
    int mbtype;
    char *part;
    char *acl;

    struct index_header i;

    /* Information in header */
    char *uniqueid;
    char *quotaroot;
    char *flagname[MAX_USER_FLAGS];

    /* change management */
    int modseq_dirty;
    int header_dirty;
    int cache_dirty;
    int quota_dirty;
    int has_changed;
    time_t last_updated; /* for appends*/
    quota_t quota_previously_used; /* for quota change */
};

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
#define OFFSET_QUOTA_MAILBOX_USED64 32  /* offset for 64bit quotas */
#define OFFSET_QUOTA_MAILBOX_USED 36    /* offset for 32bit quotas */
#define OFFSET_POP3_LAST_LOGIN 40
#define OFFSET_UIDVALIDITY 44
#define OFFSET_DELETED 48      /* added for ACAP */
#define OFFSET_ANSWERED 52
#define OFFSET_FLAGGED 56
#define OFFSET_MAILBOX_OPTIONS 60
#define OFFSET_LEAKED_CACHE 64     /* Number of leaked records in cache file */
#define OFFSET_HIGHESTMODSEQ_64 68 /* CONDSTORE (64-bit modseq) */
#define OFFSET_HIGHESTMODSEQ 72    /* CONDSTORE (32-bit modseq) */
#define OFFSET_DELETEDMODSEQ_64 76 /* CONDSTORE (64-bit modseq) */
#define OFFSET_DELETEDMODSEQ 80    /* CONDSTORE (32-bit modseq) */
#define OFFSET_EXISTS 84           /* Non-expunged records */
#define OFFSET_FIRST_EXPUNGED 88   /* last_updated of oldest expunged message */
#define OFFSET_LAST_REPACK_TIME 92 /* time of last expunged cleanup  */
#define OFFSET_HEADER_FILE_CRC 96  /* CRC32 of the index header file */
#define OFFSET_SYNC_CRC 100        /* XOR of SYNC CRCs of unexpunged records */
#define OFFSET_RECENTUID 104       /* last UID the owner was told about */
#define OFFSET_RECENTTIME 108      /* last timestamp for seen data */
#define OFFSET_SPARE0 112 /* Spares - only use these if the index */
#define OFFSET_SPARE1 116 /*  record size remains the same */
#define OFFSET_SPARE2 120 /*  (see note above about spares) */
#define OFFSET_HEADER_CRC 124 /* includes all zero for the spares! */

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
#define OFFSET_CONTENT_LINES 52 /* added for nntpd */
#define OFFSET_CACHE_VERSION 56
#define OFFSET_MESSAGE_GUID 60
#define OFFSET_MODSEQ_64 80 /* CONDSTORE (64-bit modseq) */
#define OFFSET_MODSEQ 84 /* CONDSTORE (32-bit modseq) */
#define OFFSET_CACHE_CRC 88 /* CRC32 of cache record */
#define OFFSET_RECORD_CRC 92


#define INDEX_HEADER_SIZE (OFFSET_HEADER_CRC+4)
#define INDEX_RECORD_SIZE (OFFSET_RECORD_CRC+4)

#define FLAG_ANSWERED (1<<0)
#define FLAG_FLAGGED (1<<1)
#define FLAG_DELETED (1<<2)
#define FLAG_DRAFT (1<<3)
#define FLAG_SEEN (1<<4)
#define FLAG_UNLINKED (1<<30)
#define FLAG_EXPUNGED (1U<<31)

#define OPT_POP3_NEW_UIDL (1<<0)	/* added for Outlook stupidity */
/* NOTE: not used anymore - but don't reuse it */
#define OPT_IMAP_CONDSTORE (1<<1)	/* added for CONDSTORE extension */

/* these two are annotations, if you add more, update annotate.c
 * struct annotate_mailbox_flags */
#define OPT_IMAP_SHAREDSEEN (1<<2)	/* added for shared \Seen flag */
#define OPT_IMAP_DUPDELIVER (1<<3)	/* added to allow duplicate delivery */
#define OPT_MAILBOX_NEEDS_UNLINK (1<<29)	/* files to be unlinked */
#define OPT_MAILBOX_NEEDS_REPACK (1<<30)	/* repacking to do */
#define OPT_MAILBOX_DELETED (1U<<31)	/* mailbox is deleted an awaiting cleanup */

#define MAILBOX_OPTIONS_MASK (OPT_POP3_NEW_UIDL | \
			      OPT_IMAP_SHAREDSEEN | \
			      OPT_IMAP_DUPDELIVER)
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

struct mailbox_header_cache {
    const char *name; /* Name of header */
    bit32 min_cache_version; /* Cache version it appeared in */
};

#define MAX_CACHED_HEADER_SIZE 32 /* Max size of a cached header name */
extern const struct mailbox_header_cache mailbox_cache_headers[];
extern const int MAILBOX_NUM_CACHE_HEADERS;

/* Aligned buffer for manipulating index header/record fields */
typedef union {
    unsigned char buf[INDEX_HEADER_SIZE > INDEX_RECORD_SIZE ?
		      INDEX_HEADER_SIZE : INDEX_RECORD_SIZE];
#ifdef HAVE_LONG_LONG_INT
    bit64 align8; /* align on 8-byte boundary */
#else
    bit32 align4; /* align on 4-byte boundary */
#endif
} indexbuffer_t;

/* Access assistance macros for memory-mapped cache file data */
/* CACHE_ITEM_BIT32: Convert to host byte order */
/* CACHE_ITEM_LEN: Get the length out */
/* CACHE_ITEM_NEXT: Return a pointer to the next entry.  Sizes are
 * 4-byte aligned, so round up to the next 4 byte boundry */
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

unsigned mailbox_cached_header(const char *s);
unsigned mailbox_cached_header_inline(const char *text);

typedef unsigned mailbox_decideproc_t(struct mailbox *mailbox,
				      struct index_record *index,
				      void *rock);

typedef void mailbox_notifyproc_t(const char *mboxname);

extern void mailbox_set_updatenotifier(mailbox_notifyproc_t *notifyproc);
extern mailbox_notifyproc_t *mailbox_get_updatenotifier(void);

/* file names on disk */
#define META_FNAME_NEW 1
extern char *mailbox_meta_fname(struct mailbox *mailbox, int metafile);
extern char *mailbox_meta_newfname(struct mailbox *mailbox, int metafile);
extern int mailbox_meta_rename(struct mailbox *mailbox, int metafile);

extern char *mailbox_message_fname(struct mailbox *mailbox, 
				   unsigned long uid);
extern char *mailbox_datapath(struct mailbox *mailbox);

/* map individual messages in */
extern int mailbox_map_message(struct mailbox *mailbox, unsigned long uid,
				  const char **basep, unsigned long *lenp);
extern void mailbox_unmap_message(struct mailbox *mailbox,
				  unsigned long uid,
				  const char **basep, unsigned long *lenp);

/* cache record API */
int mailbox_open_cache(struct mailbox *mailbox);
int cache_parserecord(struct buf *cachebase,
		      unsigned cache_offset, struct cacherecord *crec);
int mailbox_cacherecord(struct mailbox *mailbox,
			struct index_record *record);
int cache_append_record(int fd, struct index_record *record);
int mailbox_append_cache(struct mailbox *mailbox,
			 struct index_record *record);
const char *cacheitem_base(struct index_record *record, int field);
unsigned cacheitem_size(struct index_record *record, int field);
struct buf *cacheitem_buf(struct index_record *record, int field);
const char *cache_base(struct index_record *record);
unsigned cache_size(struct index_record *record);
struct buf *cache_buf(struct index_record *record);
/* opening and closing */
extern int mailbox_open_iwl(const char *name,
			    struct mailbox **mailboxptr);
extern int mailbox_open_irl(const char *name,
			    struct mailbox **mailboxptr);
extern int mailbox_open_exclusive(const char *name,
			          struct mailbox **mailboxptr);
extern void mailbox_close(struct mailbox **mailboxptr);
extern int mailbox_delete(struct mailbox **mailboxptr);

/* reading bits and pieces */
extern int mailbox_read_header(struct mailbox *mailbox, char **aclptr);
extern int mailbox_refresh_index_header(struct mailbox *mailbox);
extern int mailbox_write_header(struct mailbox *mailbox, int force);
extern void mailbox_index_dirty(struct mailbox *mailbox);
extern void mailbox_modseq_dirty(struct mailbox *mailbox);
extern int mailbox_read_index_record(struct mailbox *mailbox,
				     uint32_t recno,
				     struct index_record *record);
extern int mailbox_rewrite_index_record(struct mailbox *mailbox,
				        struct index_record *record);
extern int mailbox_append_index_record(struct mailbox *mailbox,
				       struct index_record *record);
extern int mailbox_find_index_record(struct mailbox *mailbox, uint32_t uid,
				     struct index_record *record);

extern int mailbox_set_acl(struct mailbox *mailbox, const char *acl,
			   int dirty_modseq);
extern int mailbox_set_quotaroot(struct mailbox *mailbox, const char *quotaroot);
extern int mailbox_user_flag(struct mailbox *mailbox, const char *flag,
			     int *flagnum);
extern int mailbox_commit(struct mailbox *mailbox);

/* seen state check */
extern int mailbox_internal_seen(struct mailbox *mailbox, const char *userid);

/* index locking operations */
extern int mailbox_lock_index(struct mailbox *mailbox, int locktype);

extern int mailbox_expunge_cleanup(struct mailbox *mailbox, time_t expunge_mark,
				   unsigned *ndeleted);
extern int mailbox_expunge(struct mailbox *mailbox,
			   mailbox_decideproc_t *decideproc, void *deciderock,
			   unsigned *nexpunged);
extern int mailbox_cleanup(struct mailbox *mailbox, int iscurrentdir,
			   mailbox_decideproc_t *decideproc, void *deciderock);
extern void mailbox_unlock_index(struct mailbox *mailbox, struct statusdata *sd);

extern int mailbox_create(const char *name, uint32_t mbtype, const char *part,
			  const char *acl, const char *uniqueid, int options,
			  unsigned uidvalidity, struct mailbox **mailboxptr);

extern int mailbox_copy_files(struct mailbox *mailbox, const char *newpart,
			      const char *newname);
extern int mailbox_delete_cleanup(const char *part, const char *name);

extern int mailbox_rename_copy(struct mailbox *oldmailbox, 
			       const char *newname, const char *newpart,
			       const char *userid, int ignorequota,
			       struct mailbox **newmailboxptr);
extern int mailbox_rename_cleanup(struct mailbox **mailboxptr, int isinbox);


extern int mailbox_copyfile(const char *from, const char *to, int nolink);

extern int mailbox_reconstruct(const char *name, int flags);

extern int mailbox_index_recalc(struct mailbox *mailbox);

/* for upgrade index */
extern int mailbox_open_index(struct mailbox *mailbox);
extern int mailbox_buf_to_index_record(const char *buf,
				       struct index_record *record);
extern int mailbox_buf_to_index_header(const char *buf,
				       struct index_header *i);

/* for repack */
struct mailbox_repack {
    struct mailbox *mailbox;
    struct index_header i;
    int newindex_fd;
    int newcache_fd;
};

extern int mailbox_repack_setup(struct mailbox *mailbox,
			        struct mailbox_repack **repackptr);
extern int mailbox_repack_add(struct mailbox_repack *repack,
			      struct index_record *record);
extern void mailbox_repack_abort(struct mailbox_repack **repackptr);
extern int mailbox_repack_commit(struct mailbox_repack **repackptr);

#endif /* INCLUDED_MAILBOX_H */
