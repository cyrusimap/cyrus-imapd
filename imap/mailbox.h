/* mailbox.h -- Mailbox format definitions
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */
#include <sys/types.h>

typedef unsigned bit32;

#define MAX_MAILBOX_PATH 4096

#define MAX_USER_FLAGS (16*8)


#define MAILBOX_HEADER_MAGIC "\241\002\213\015Cyrus mailbox header\n\"The best thing about this system was that it had lots of goals.\"\n\t--Jim Morris on Andrew\n"

#define MAILBOX_FORMAT_NORMAL	0
#define MAILBOX_FORMAT_NETNEWS	1

#define MAILBOX_MINOR_VERSION	0

#define FNAME_HEADER "/cyrus.header"
#define FNAME_INDEX "/cyrus.index"
#define FNAME_CACHE "/cyrus.cache"
#define FNAME_QUOTA "/cyrus.quota"

#define QUOTA_UNITS (1024)

struct mailbox {
    FILE *header;
    FILE *index;
    FILE *cache;
    FILE *quota;

    int header_lock_count;
    int index_lock_count;
    int seen_lock_count;
    int quota_lock_count;

    time_t header_mtime;
    time_t index_mtime;
    long index_ino;

    /* Information in mailbox list */
    char *name;
    char *path;
    char *acl;
    long myrights;

    /* Information in header */
    char *quota_root;
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

    /* Information in quota file */
    unsigned long quota_used;
    int quota_limit;		/* in QUOTA_UNITS */
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

#define INDEX_HEADER_SIZE (9*4)
#define INDEX_RECORD_SIZE (OFFSET_USER_FLAGS+MAX_USER_FLAGS/8)

#define FLAG_ANSWERED (1<<0)
#define FLAG_FLAGGED (1<<1)
#define FLAG_DELETED (1<<2)

extern char *mailbox_cache_header_name[];
extern int mailbox_num_cache_header;

extern char *mailbox_message_fname();

