#include <sys/types.h>

typedef unsigned bit32;

#define MAX_MAILBOX_PATH 4096

#define MAX_USER_FLAGS (16*8)


#define MAILBOX_HEADER_MAGIC "\241\002\213\015Cyrus mailbox header\n\"The best thing about this system was that it had lots of goals.\"\n\t--Jim Morris on Andrew\n"

#define MAILBOX_FORMAT_NORMAL	0
#define MAILBOX_FORMAT_NETNEWS	1

#define FNAME_HEADER "/cyrus.header"
#define FNAME_INDEX "/cyrus.index"
#define FNAME_CACHE "/cyrus.cache"
#define FNAME_SEEN "/cyrus.seen"
#define FNAME_QUOTA "/cyrus.quota"

#define QUOTA_UNITS (1024*1024)

struct mailbox {
    FILE *header;
    FILE *index;
    FILE *cache;
    FILE *seen;
    FILE *quota;

    char *name;
    char *path;

    int header_lock_count;
    int index_lock_count;
    int seen_lock_count;
    int quota_lock_count;

    time_t header_mtime;
    time_t index_mtime;
    long index_ino;
    long index_size;

    /* Information in header */
    char *quota_path;
    char *flagname[MAX_USER_FLAGS];
    char *acl;
    long my_acl;

    /* Information in index file */
    unsigned long generation_no;
    int format;
    int minor_version;
    unsigned long start_offset;
    unsigned long record_size;
    time_t last_internaldate;
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


