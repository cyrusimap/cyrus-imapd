#include <sys/types.h>

typedef unsigned long bit32;	/* TODO: different on 64bit machines */

#define MAX_FOLDER_PATH 4096

#define MAX_USER_FLAGS (16*8)


#define FOLDER_HEADER_MAGIC "\241\002\213\015Cyrus folder header\n\"The great thing about this project was that it had so many goals.\"\n\t--Jim Morris on the Andrew project\n"

#define FOLDER_FORMAT_NORMAL	0
#define FOLDER_FORMAT_NETNEWS	1

#define FNAME_HEADER "/cyrus.header"
#define FNAME_INDEX "/cyrus.index"
#define FNAME_CACHE "/cyrus.cache"
#define FNAME_SEEN "/cyrus.seen"
#define FNAME_QUOTA "/cyrus.quota"

#define QUOTA_UNITS (1024*1024)

struct folder {
    FILE *header;
    FILE *index;
    FILE *cache;
    FILE *seen;
    FILE *quota;

    char *path;

    int header_lock_count;
    int index_lock_count;
    int seen_lock_count;
    int quota_lock_count;

    time_t header_mtime;
    time_t index_mtime;
    long index_blksize;

    /* Information in header */
    char *quota_path;
    char *flagname[MAX_USER_FLAGS];
    char *acl;
    long my_acl;

    /* Information in index file */
    unsigned long generation_no;
    int format;
    unsigned long start_offset;
    unsigned long record_size;
    time_t last_internaldate;
    unsigned long last_uid;
    unsigned long quota_folder_used;

    /* Information in quota file */
    unsigned long quota_used;
    int quota_limit;		/* in QUOTA_UNITS */
};

struct index_record {
    unsigned long uid;
    time_t internaldate;
    unsigned long size;
    unsigned long content_offset;
    unsigned long cache_offset;
    time_t last_updated;
    bit32 system_flags;
    bit32 user_flags[MAX_USER_FLAGS/32];
};

    
