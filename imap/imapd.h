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

/* Items that may be fetched */
struct fetchargs {
    int fetchitems;		/* Bitmask */
    char *bodyparts;		/* BODY[x] values */
    char *headers;		/* RFC822.HEADER.LINES */
    char *headers_not;		/* RFC822.HEADER.LINES.NOT */
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
