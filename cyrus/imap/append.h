/*
 * Description of messages to be copied
 */
struct copymsg {
    int msgno;
    unsigned long uid;
    time_t internaldate;
    unsigned long size;
    unsigned long header_size;
    char *cache_begin;
    int cache_len;
    int seen;
    bit32 system_flags;
    char *flag[MAX_USER_FLAGS+1];
};

    
