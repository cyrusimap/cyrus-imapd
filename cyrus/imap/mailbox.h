/* mailbox.h -- Mailbox format definitions
 $Id: mailbox.h,v 1.68.4.5 2003/01/11 04:01:21 ken3 Exp $
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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

#include "auth.h"

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

#define MAX_MAILBOX_NAME 490
#define MAX_MAILBOX_PATH 4096

#define MAX_USER_FLAGS (16*8)

#define MAILBOX_HEADER_MAGIC ("\241\002\213\015Cyrus mailbox header\n" \
     "\"The best thing about this system was that it had lots of goals.\"\n" \
     "\t--Jim Morris on Andrew\n")

#define MAILBOX_FORMAT_NORMAL	0
#define MAILBOX_FORMAT_NETNEWS	1

#define MAILBOX_MINOR_VERSION	4

#define FNAME_HEADER "/cyrus.header"
#define FNAME_INDEX "/cyrus.index"
#define FNAME_CACHE "/cyrus.cache"
#define FNAME_SQUAT_INDEX "/cyrus.squat"
#define FNAME_QUOTADIR "/quota/"

#define MAILBOX_FNAME_LEN 256

#define QUOTA_UNITS (1024)

struct quota {
    int fd;

    int lock_count;
    char *root;

    /* Information in quota file */
    unsigned long used;
    int limit;			/* in QUOTA_UNITS */
};

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

    unsigned long header_ino;
    time_t index_mtime;
    unsigned long index_ino;
    off_t index_size;

    /* Information in mailbox list */
    char *name;
    char *path;
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
    unsigned long quota_mailbox_used;
    unsigned long pop3_last_login;
    unsigned long uidvalidity;

    unsigned long deleted;
    unsigned long answered;
    unsigned long flagged;
    int dirty;

    int pop3_new_uidl;

    /* future expansion -- won't need expand the header */
    unsigned long spares[4];

    struct quota quota;
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
};

/* Offsets of index header fields */
#define OFFSET_GENERATION_NO 0
#define OFFSET_FORMAT 4
#define OFFSET_MINOR_VERSION 8
#define OFFSET_START_OFFSET 12
#define OFFSET_RECORD_SIZE 16
#define OFFSET_EXISTS 20
#define OFFSET_LAST_APPENDDATE 24
#define OFFSET_LAST_UID 28
#define OFFSET_QUOTA_MAILBOX_USED 32
#define OFFSET_POP3_LAST_LOGIN 36
#define OFFSET_UIDVALIDITY 40
#define OFFSET_DELETED 44	/* added for ACAP */
#define OFFSET_ANSWERED 48
#define OFFSET_FLAGGED 52
#define OFFSET_POP3_NEW_UIDL 56	/* added for Outlook stupidity */
#define OFFSET_SPARE0 60
#define OFFSET_SPARE1 64
#define OFFSET_SPARE2 68
#define OFFSET_SPARE3 72

/* Offsets of index_record fields in index file */
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

#define INDEX_HEADER_SIZE (OFFSET_SPARE3+4)
#define INDEX_RECORD_SIZE (OFFSET_USER_FLAGS+MAX_USER_FLAGS/8)

#define FLAG_ANSWERED (1<<0)
#define FLAG_FLAGGED (1<<1)
#define FLAG_DELETED (1<<2)
#define FLAG_DRAFT (1<<3)

extern char *mailbox_cache_header_name[];
extern int mailbox_num_cache_header;

typedef int mailbox_decideproc_t(struct mailbox *mailbox, 
				 void *rock, char *indexbuf);

typedef void mailbox_notifyproc_t(struct mailbox *mailbox);

extern void mailbox_set_updatenotifier(mailbox_notifyproc_t *notifyproc);

extern int mailbox_initialize(void);

extern char *mailbox_message_fname(struct mailbox *mailbox,
				   unsigned long uid);

/* 'len(out) >= MAILBOX_FNAME_LEN' */
extern void mailbox_message_get_fname(struct mailbox *mailbox,
				      unsigned long uid,
				      char *out);

extern int mailbox_map_message(struct mailbox *mailbox,
				  int iscurrentdir,
				  unsigned long uid,
				  const char **basep, unsigned long *lenp);
extern void mailbox_unmap_message(struct mailbox *mailbox,
				  unsigned long uid,
				  const char **basep, unsigned long *lenp);

extern void mailbox_reconstructmode(void);

extern int mailbox_stat(const char *mbpath,
			struct stat *header,
			struct stat *index,
			struct stat *cache);

extern int mailbox_open_header(const char *name, struct auth_state *auth_state,
			       struct mailbox *mailbox);
extern int mailbox_open_header_path(const char *name, const char *path,
				    const char *acl, 
				    struct auth_state *auth_state,
				    struct mailbox *mailbox,
				    int suppresslog);
extern int mailbox_open_locked(const char *mbname,
			       const char *mbpath,
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
extern int mailbox_read_quota(struct quota *quota);
extern void mailbox_hash_quota(char *buf, unsigned size, const char *qr);
extern int mailbox_lock_header(struct mailbox *mailbox);
extern int mailbox_lock_index(struct mailbox *mailbox);
extern int mailbox_lock_pop(struct mailbox *mailbox);
extern int mailbox_lock_quota(struct quota *quota);

extern void mailbox_unlock_header(struct mailbox *mailbox);
extern void mailbox_unlock_index(struct mailbox *mailbox);
extern void mailbox_unlock_pop(struct mailbox *mailbox);
extern void mailbox_unlock_quota(struct quota *quota);

extern int mailbox_write_header(struct mailbox *mailbox);
extern int mailbox_write_index_header(struct mailbox *mailbox);
extern int mailbox_write_index_record(struct mailbox *mailbox,
				      unsigned msgno,
				      struct index_record *record, int sync);
extern int mailbox_append_index(struct mailbox *mailbox,
				struct index_record *record,
				unsigned start, unsigned num, int sync);
extern int mailbox_write_quota(struct quota *quota);

extern int mailbox_delete_quota(struct quota *quota);

extern int mailbox_expunge(struct mailbox *mailbox,
			   int iscurrentdir,
			   mailbox_decideproc_t *decideproc,
			   void *deciderock);
extern int mailbox_expungenews(struct mailbox *mailbox);

extern int mailbox_findquota(char *ret, const char *name);
extern void mailbox_make_uniqueid(char *name, unsigned long uidvalidity,
				  char *uniqueid);

extern int mailbox_create(const char *name, char *path,
			  const char *acl, const char *uniqueid, int format,
			  struct mailbox *mailboxp);
extern int mailbox_delete(struct mailbox *mailbox, int delete_quota_root);

extern int mailbox_rename_copy(struct mailbox *oldmailbox, 
			       const char *newname, char *newpath,
			       bit32 *olduidvalidityp, bit32 *newuidvalidityp,
			       struct mailbox *mailboxp);
extern int mailbox_rename_cleanup(struct mailbox *oldmailbox,
				  int isinbox);

extern int mailbox_sync(const char *oldname, const char *oldpath, 
			const char *oldacl, 
			const char *newname, char *newpath, 
			int docreate,
			bit32 *olduidvalidityp, bit32 *newuidvalidtyp,
			struct mailbox *mailboxp);

extern int mailbox_copyfile(const char *from, const char *to);
extern void mailbox_hash_mbox(char *buf, const char *root, const char *name);

#endif /* INCLUDED_MAILBOX_H */
