/* mailbox.h -- Mailbox format definitions
 $Id: mailbox.h,v 1.48 2000/01/28 22:09:47 leg Exp $
 
 # Copyright 1998 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
 *
 */
#ifndef INCLUDED_MAILBOX_H
#define INCLUDED_MAILBOX_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

#include <sys/types.h>
#include <limits.h>

#include "auth.h"

#ifdef __STDC__
#define BIT32_MAX 4294967295U
#else
#define BIT32_MAX 4294967295
#endif

#if UINT_MAX == BIT32_MAX
typedef unsigned int bit32;
#else
#if ULONG_MAX == BIT32_MAX
typedef unsigned long bit32;
#else
#if USHRT_MAX == BIT32_MAX
typedef unsigned short bit32;
#else
dont know what to use for bit32
#endif
#endif
#endif

#define MAX_MAILBOX_NAME 490
#define MAX_MAILBOX_PATH 4096

#define MAX_USER_FLAGS (16*8)

#define MAILBOX_HEADER_MAGIC "\241\002\213\015Cyrus mailbox header\n\"The best thing about this system was that it had lots of goals.\"\n\t--Jim Morris on Andrew\n"

#define MAILBOX_FORMAT_NORMAL	0
#define MAILBOX_FORMAT_NETNEWS	1

#define MAILBOX_MINOR_VERSION	2

#define FNAME_HEADER "/cyrus.header"
#define FNAME_INDEX "/cyrus.index"
#define FNAME_CACHE "/cyrus.cache"
#define FNAME_QUOTADIR "/quota/"
#define FNAME_LOGDIR "/log/"

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
    unsigned long index_len;
    const char *cache_base;
    unsigned long cache_len;

    int header_lock_count;
    int index_lock_count;
    int seen_lock_count;
    int pop_lock_count;

    long header_ino;
    time_t index_mtime;
    long index_ino;

    /* Information in mailbox list */
    char *name;
    char *path;
    char *acl;
    long myrights;

    /* Information in header */
    /* quota.root */
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

#define INDEX_HEADER_SIZE (OFFSET_UIDVALIDITY+4)
#define INDEX_RECORD_SIZE (OFFSET_USER_FLAGS+MAX_USER_FLAGS/8)

#define FLAG_ANSWERED (1<<0)
#define FLAG_FLAGGED (1<<1)
#define FLAG_DELETED (1<<2)
#define FLAG_DRAFT (1<<3)

extern char *mailbox_cache_header_name[];
extern int mailbox_num_cache_header;

typedef int mailbox_decideproc_t P((void *rock, char *indexbuf));

extern char *mailbox_message_fname P((struct mailbox *mailbox,
				      unsigned long uid));
extern int mailbox_map_message P((struct mailbox *mailbox,
				  int iscurrentdir,
				  unsigned long uid,
				  const char **basep, unsigned long *lenp));
extern void mailbox_unmap_message P((struct mailbox *mailbox,
				    unsigned long uid,
				    const char **basep, unsigned long *lenp));

extern void mailbox_reconstructmode P((void));
extern int mailbox_open_header P((const char *name, struct auth_state *auth_state,
				  struct mailbox *mailbox));
extern int mailbox_open_header_path P((const char *name, const char *path,
				       const char *acl, struct auth_state *auth_state,
				       struct mailbox *mailbox,
				       int suppresslog));
extern int mailbox_open_index P((struct mailbox *mailbox));
extern void mailbox_close P((struct mailbox *mailbox));

extern int mailbox_read_header P((struct mailbox *mailbox));
extern int mailbox_read_header_acl P((struct mailbox *mailbox));
extern int mailbox_read_acl P((struct mailbox *mailbox, struct auth_state *auth_state));
extern int mailbox_read_index_header P((struct mailbox *mailbox));
extern int mailbox_read_index_record P((struct mailbox *mailbox,
					unsigned msgno,
					struct index_record *record));
extern int mailbox_read_quota(struct quota *quota);
extern void mailbox_hash_quota(char *buf, const char *quotaroot);

extern int mailbox_lock_header P((struct mailbox *mailbox));
extern int mailbox_lock_index P((struct mailbox *mailbox));
extern int mailbox_lock_pop P((struct mailbox *mailbox));
extern int mailbox_lock_quota P((struct quota *quota));

extern void mailbox_unlock_header P((struct mailbox *mailbox));
extern void mailbox_unlock_index P((struct mailbox *mailbox));
extern void mailbox_unlock_pop P((struct mailbox *mailbox));
extern void mailbox_unlock_quota P((struct quota *quota));

extern int mailbox_write_header P((struct mailbox *mailbox));
extern int mailbox_write_index_header P((struct mailbox *mailbox));
extern int mailbox_write_index_record P((struct mailbox *mailbox,
					 unsigned msgno,
					 struct index_record *record));
extern int mailbox_append_index P((struct mailbox *mailbox,
				   struct index_record *record,
				   unsigned start, unsigned num));
extern int mailbox_write_quota P((struct quota *quota));

extern int mailbox_delete_quota P((struct quota *quota));

extern int mailbox_expunge P((struct mailbox *mailbox,
			      int iscurrentdir,
			      mailbox_decideproc_t *decideproc,
			      void *deciderock));
extern int mailbox_expungenews P((struct mailbox *mailbox));

extern char *mailbox_findquota P((const char *name));

extern int mailbox_create P((const char *name, char *path,
			     const char *acl, int format,
			     struct mailbox *mailboxp));
extern int mailbox_delete(struct mailbox *mailbox, int delete_quota_root);
extern int mailbox_rename(const char *oldname, const char *oldpath, 
			  const char *oldacl, 
			  const char *newname, char *newpath, 
			  int isinbox,
			  bit32 *olduidvalidityp, bit32 *newuidvalidtyp);

extern int mailbox_copyfile P((const char *from, const char *to));
extern void mailbox_hash_mbox(char *buf, const char *root, const char *name);

#endif /* INCLUDED_MAILBOX_H */
