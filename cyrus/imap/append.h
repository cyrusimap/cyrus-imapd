/*
 * Description of messages to be copied
 */
struct copymsg {
    unsigned long uid;
    time_t internaldate;
    unsigned long size;
    unsigned long header_size;
    char *cache_begin;
    int cache_len;		/* 0 if need to copy & parse message */
    int seen;
    bit32 system_flags;
    char *flag[MAX_USER_FLAGS+1];
};

    
