/* mailbox.h -- Mailbox format definitions
 * $Id: mailbox.h,v 1.82 2006/11/30 17:11:19 murch Exp $
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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

#include "auth.h"
#include "quota.h"
#include "message_uuid.h"
#include "byteorder64.h"


#define BIT32_MAX 4294967295U

#if UINT_MAX == BIT32_MAX
typedef unsigned int bit32;
#elif ULONG_MAX == BIT32_MAX
typedef unsigned long bit32;
#elif USHRT_MAX == BIT32_MAX
typedef unsigned short bit32;
#else
#error dont know what to use for bit32
#endif

#ifdef HAVE_LONG_LONG_INT
typedef unsigned long long int bit64;
typedef unsigned long long int modseq_t;
#define MODSEQ_FMT "%llu"
#else 
typedef unsigned long int modseq_t;
#define MODSEQ_FMT "%lu"
#endif

#define MAX_MAILBOX_NAME 490
#define MAX_MAILBOX_PATH 4096

#define MAX_USER_FLAGS (16*8)

#define MAILBOX_HEADER_MAGIC ("\241\002\213\015Cyrus mailbox header\n" \
     "\"The best thing about this system was that it had lots of goals.\"\n" \
     "\t--Jim Morris on Andrew\n")

#define MAILBOX_FORMAT_NORMAL	0
#define MAILBOX_FORMAT_NETNEWS	1

#define MAILBOX_MINOR_VERSION	9
#define MAILBOX_CACHE_MINOR_VERSION 2

#define FNAME_HEADER "/cyrus.header"
#define FNAME_INDEX "/cyrus.index"
#define FNAME_CACHE "/cyrus.cache"
#define FNAME_SQUAT_INDEX "/cyrus.squat"
#define FNAME_EXPUNGE_INDEX "/cyrus.expunge"

#define MAILBOX_FNAME_LEN 256

struct mailbox {
    int header_fd;
    int index_fd;
    int cache_fd;

    const char *header_base;
    unsigned long header_len;
    const char *index_base;
    unsigned long index_len;	/* mapped size */
    const char *cache_base;
    unsigned long cache_len;	/* mapped size */
    unsigned long cache_size;	/* actual size */

    int header_lock_count;
    int index_lock_count;
    int seen_lock_count;
    int pop_lock_count;

    ino_t header_ino;
    time_t index_mtime;
    ino_t index_ino;
    off_t index_size;

    /* Information in mailbox list */
    char *name;
    char *path;
    char *mpath;
    char *acl;
    long myrights;

    /* Information in header */
    /* quota.root */
    char *uniqueid;
    char *flagname[MAX_USER_FLAGS];

    /* Information in index file */
    bit32 generation_no;
    int format;
    int minor_version;
    unsigned long start_offset;
    unsigned long record_size;
    unsigned long exists;
    time_t last_appenddate;
    unsigned long last_uid;
    uquota_t quota_mailbox_used;
    unsigned long pop3_last_login;
    unsigned long uidvalidity;

    unsigned long deleted;
    unsigned long answered;
    unsigned long flagged;
    int dirty;

    unsigned long options;
    unsigned long leaked_cache_records;
    modseq_t highestmodseq;

    /*
     * future expansion -- won't need expand the header
     *
     * If the change to the index header change also includes a change
     * to the index record, there is no benefit to using a spare.  In
     * this case, just add a new field, and optionally add some more
     * spares.
     */
    unsigned long spares[4];

    struct quota quota;

    /* Information in current session */
    int examining;	/* Nonzero if opened with EXAMINE command */
    int keepingseen;	/* Nonzero if /Seen is meaningful */
    unsigned allseen;	/* Last UID if all msgs /Seen last checkpoint */
    unsigned recentuid;	/* UID of last non-\Recent message */
};

struct index_record {
    unsigned long uid;
    time_t internaldate;
    time_t sentdate;
    unsigned long size;
    unsigned long header_size;
    unsigned long content_offset;
    unsigned long cache_offset;
    time_t last_updated;
    bit32 system_flags;
    bit32 user_flags[MAX_USER_FLAGS/32];
    unsigned long content_lines;
    unsigned long cache_version;
    struct message_uuid uuid;
    modseq_t modseq;
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
#define OFFSET_EXISTS 20
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
#define OFFSET_LEAKED_CACHE 64 /* Number of leaked records in cache file */
#define OFFSET_HIGHESTMODSEQ_64 68 /* CONDSTORE (64-bit modseq) */
#define OFFSET_HIGHESTMODSEQ 72    /* CONDSTORE (32-bit modseq) */
#define OFFSET_SPARE0 76 /* Spares - only use these if the index */
#define OFFSET_SPARE1 80 /*  record size remains the same */
#define OFFSET_SPARE2 84 /*  (see note above about spares) */
#define OFFSET_SPARE3 88
#define OFFSET_SPARE4 92

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
#define OFFSET_CONTENT_OFFSET 20
#define OFFSET_CACHE_OFFSET 24
#define OFFSET_LAST_UPDATED 28
#define OFFSET_SYSTEM_FLAGS 32
#define OFFSET_USER_FLAGS 36
#define OFFSET_CONTENT_LINES (OFFSET_USER_FLAGS+MAX_USER_FLAGS/8) /* added for nntpd */
#define OFFSET_CACHE_VERSION OFFSET_CONTENT_LINES+sizeof(bit32)
#define OFFSET_MESSAGE_UUID OFFSET_CACHE_VERSION+sizeof(bit32)
#define OFFSET_MODSEQ_64 (OFFSET_MESSAGE_UUID+MESSAGE_UUID_PACKED_SIZE) /* CONDSTORE (64-bit modseq) */
#define OFFSET_MODSEQ (OFFSET_MODSEQ_64+sizeof(bit32)) /* CONDSTORE (32-bit modseq) */

#define INDEX_HEADER_SIZE (OFFSET_SPARE4+sizeof(bit32))
#define INDEX_RECORD_SIZE (OFFSET_MODSEQ+sizeof(bit32))

/* Number of fields in an individual message's cache record */
#define NUM_CACHE_FIELDS 10

#define FLAG_ANSWERED (1<<0)
#define FLAG_FLAGGED (1<<1)
#define FLAG_DELETED (1<<2)
#define FLAG_DRAFT (1<<3)

#define OPT_POP3_NEW_UIDL (1<<0)	/* added for Outlook stupidity */
#define OPT_IMAP_CONDSTORE (1<<1)	/* added for CONDSTORE extension */


struct mailbox_header_cache {
    const char *name; /* Name of header */
    bit32 min_cache_version; /* Cache version it appeared in */
};

#define MAX_CACHED_HEADER_SIZE 32 /* Max size of a cached header name */
extern const struct mailbox_header_cache mailbox_cache_headers[];
extern const int MAILBOX_NUM_CACHE_HEADERS;

/* Bitmasks for expunging */
enum {
    EXPUNGE_FORCE =		(1<<0),
    EXPUNGE_CLEANUP =		(1<<1)
};

int mailbox_cached_header(const char *s);
int mailbox_cached_header_inline(const char *text);

unsigned long mailbox_cache_size(struct mailbox *mailbox, unsigned msgno);

typedef int mailbox_decideproc_t(struct mailbox *mailbox, void *rock,
				 char *indexbuf, int expunge_flags);

typedef void mailbox_notifyproc_t(struct mailbox *mailbox);

extern void mailbox_set_updatenotifier(mailbox_notifyproc_t *notifyproc);
extern mailbox_notifyproc_t *mailbox_get_updatenotifier(void);

extern int mailbox_initialize(void);

extern char *mailbox_message_fname(struct mailbox *mailbox,
				   unsigned long uid);

/* 'len(out) >= MAILBOX_FNAME_LEN' */
extern void mailbox_message_get_fname(struct mailbox *mailbox,
				      unsigned long uid,
				      char *out, size_t size);

extern int mailbox_map_message(struct mailbox *mailbox, unsigned long uid,
				  const char **basep, unsigned long *lenp);
extern void mailbox_unmap_message(struct mailbox *mailbox,
				  unsigned long uid,
				  const char **basep, unsigned long *lenp);

extern void mailbox_reconstructmode(void);

extern int mailbox_stat(const char *mbpath, const char *metapath,
			struct stat *header, struct stat *index,
			struct stat *cache);

extern int mailbox_open_header(const char *name, struct auth_state *auth_state,
			       struct mailbox *mailbox);
extern int mailbox_open_header_path(const char *name, const char *path,
				    const char *mpath, const char *acl, 
				    struct auth_state *auth_state,
				    struct mailbox *mailbox,
				    int suppresslog);
extern int mailbox_open_locked(const char *mbname,
			       const char *mbpath,
			       const char *metapath,
			       const char *mbacl,
			       struct auth_state *auth_state,
			       struct mailbox *mb,
			       int suppresslog);
extern int mailbox_open_index(struct mailbox *mailbox);
extern void mailbox_close(struct mailbox *mailbox);

extern int mailbox_read_header(struct mailbox *mailbox);
extern int mailbox_read_header_acl(struct mailbox *mailbox);
extern int mailbox_read_acl(struct mailbox *mailbox, 
			    struct auth_state *auth_state);
extern int mailbox_read_index_header(struct mailbox *mailbox);
extern int mailbox_read_index_record(struct mailbox *mailbox,
				     unsigned msgno,
				     struct index_record *record);
extern int mailbox_lock_header(struct mailbox *mailbox);
extern int mailbox_lock_index(struct mailbox *mailbox);
extern int mailbox_lock_pop(struct mailbox *mailbox);

extern void mailbox_unlock_header(struct mailbox *mailbox);
extern void mailbox_unlock_index(struct mailbox *mailbox);
extern void mailbox_unlock_pop(struct mailbox *mailbox);

extern int mailbox_write_header(struct mailbox *mailbox);
extern int mailbox_write_index_header(struct mailbox *mailbox);
extern void mailbox_index_record_to_buf(struct index_record *record, char *buf);
extern int mailbox_write_index_record(struct mailbox *mailbox,
				      unsigned msgno,
				      struct index_record *record, int sync);
extern int mailbox_append_index(struct mailbox *mailbox,
				struct index_record *record,
				unsigned start, unsigned num, int sync);

extern int mailbox_expunge(struct mailbox *mailbox,
			   mailbox_decideproc_t *decideproc, void *deciderock,
			   int flags);
extern int mailbox_cleanup(struct mailbox *mailbox, int iscurrentdir,
			   mailbox_decideproc_t *decideproc, void *deciderock);

extern void mailbox_make_uniqueid(char *name, unsigned long uidvalidity,
				  char *uniqueid, size_t outlen);

extern int mailbox_create(const char *name, char *partition,
			  const char *acl, const char *uniqueid, int format,
			  struct mailbox *mailboxp);
extern int mailbox_delete(struct mailbox *mailbox, int delete_quota_root);

extern int mailbox_rename_copy(struct mailbox *oldmailbox, 
			       const char *newname, char *newpartition,
			       bit32 *olduidvalidityp, bit32 *newuidvalidityp,
			       struct mailbox *mailboxp);
extern int mailbox_rename_cleanup(struct mailbox *oldmailbox, int isinbox);

extern int mailbox_sync(const char *oldname, const char *oldpath, 
			const char *oldmpath, const char *oldacl, 
			const char *newname, char *newpath, char *newmpath,
			int docreate,
			bit32 *olduidvalidityp, bit32 *newuidvalidtyp,
			struct mailbox *mailboxp);

extern int mailbox_copyfile(const char *from, const char *to, int nolink);
extern void mailbox_hash_mbox(char *buf, size_t buf_len,
			      const char *root, const char *name);

#endif /* INCLUDED_MAILBOX_H */
