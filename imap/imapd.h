/*
 * Common state for IMAP daemon
 */

/* Userid client has logged in as */
extern char *imapd_userid;

/* True if user is an admin */
extern int imapd_userisadmin;

/* Currently open mailbox */
extern struct mailbox *imapd_mailbox;

/* Number of messages in currently open mailbox */
extern int imapd_exists;


/* List of strings, for fetch and search argument blocks */
struct strlist {
    char *s;			/* String */
    struct strlist *next;
};


/* Items that may be fetched */
struct fetchargs {
    int fetchitems;		/* Bitmask */
    struct strlist *bodysections; /* BODY[x] values */
    struct strlist *headers;	/* RFC822.HEADER.LINES */
    struct strlist *headers_not; /* RFC822.HEADER.LINES.NOT */
    int start_octet;		/* start_octet for partial fetch, or 0 */
    int octet_count;		/* octet_count for partial fetch */
};

/* Bitmasks for fetchitems */
#define FETCH_UID		(1<<0)
#define FETCH_INTERNALDATE	(1<<1)
#define FETCH_SIZE		(1<<2)
#define FETCH_FLAGS		(1<<3)
#define FETCH_ENVELOPE		(1<<4)
#define FETCH_BODYSTRUCTURE	(1<<5)
#define FETCH_BODY		(1<<6)
#define FETCH_HEADER		(1<<7)
#define FETCH_TEXT		(1<<8)
#define FETCH_RFC822		(1<<9)
#define FETCH_FAST (FETCH_FLAGS|FETCH_INTERNALDATE|FETCH_SIZE)
#define FETCH_ALL  (FETCH_FLAGS|FETCH_INTERNALDATE|FETCH_SIZE|FETCH_ENVELOPE)
#define FETCH_FULL (FETCH_ALL|FETCH_BODY)

/* Arguments to Store functions */
struct storeargs {
    int operation;
    int seen;
    bit32 system_flags;
    /* private to index.c */
    bit32 user_flags[MAX_USER_FLAGS/32];
    time_t update_time;
    int exists;
    int usinguid;
    /* private to index_storeflag() */
    int last_msgno;
    int last_found;
};

/* values for operation */
#define STORE_ADD	1
#define STORE_REMOVE	2
#define STORE_REPLACE	3

/* Things that may be searched for */
struct searchargs {
    time_t before, after;
    bit32 system_flags_set;
    bit32 system_flags_unset;
    bit32 user_flags_set[MAX_USER_FLAGS/32];
    bit32 user_flags_unset[MAX_USER_FLAGS/32];
    int seen_state;
    int recent_state;
    /* XXX bcc, cc, from, subject, to, body, text */
};

/* values for seen_state and recent_state */
#define SEARCH_DONTCARE		0
#define SEARCH_SET		1
#define SEARCH_UNSET		2
