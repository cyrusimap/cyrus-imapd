/*
 * Description of messages to be copied
 */
struct copymsg {
    int msgno;
    time_t internaldate;
    unsigned long size;
    unsigned long header_size;
    char *cache_begin;
    int cache_len;
    int seen;
    bit32 system_flags;
    char *flags[MAX_USER_FLAGS+10];
};

    
