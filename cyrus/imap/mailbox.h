/* mailbox.h -- Mailbox format definitions
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */
#include <sys/types.h>
#include <limits.h>

#if UINT_MAX == 4294967295
typedef unsigned int bit32;
#else
#if ULONG_MAX == 4294967295
typedef unsigned long bit32;
#else
#if USHRT_MAX == 4294967295
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

#define MAILBOX_MINOR_VERSION	1

#define FNAME_HEADER "/cyrus.header"
#define FNAME_INDEX "/cyrus.index"
#define FNAME_CACHE "/cyrus.cache"
#define FNAME_QUOTADIR "/quota/"
#define FNAME_LOGDIR "/log/"

#define QUOTA_UNITS (1024)

struct quota {
    FILE *file;
    int lock_count;
    char *root;

    /* Information in quota file */
    unsigned long used;
    int limit;			/* in QUOTA_UNITS */
};

struct mailbox {
    FILE *header;
    FILE *index;
    FILE *cache;

    int header_lock_count;
    int index_lock_count;
    int seen_lock_count;
    int pop_lock_count;

    time_t header_mtime;
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

extern char *mailbox_message_fname();

