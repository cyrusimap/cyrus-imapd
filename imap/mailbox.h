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

#define INDEX_HEADER_SIZE (9*4)
#define INDEX_RECORD_SIZE (8*4+MAX_USER_FLAGS/4)

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
    char *quota_path;
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
    unsigned long size;
    unsigned long header_size;
    unsigned long content_offset;
    unsigned long cache_offset;
    time_t last_updated;
    bit32 system_flags;
    bit32 user_flags[MAX_USER_FLAGS/32];
};

#define FLAG_ANSWERED (1<<0)
#define FLAG_FLAGGED (1<<1)
#define FLAG_DELETED (1<<2)

extern char *mailbox_message_fname();

