/* imapd.h -- Common state for IMAP daemon
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

#include "prot.h"
#include "charset.h"

/* Userid client has logged in as */
extern char *imapd_userid;

/* True if user is an admin */
extern int imapd_userisadmin;

/* Currently open mailbox */
extern struct mailbox *imapd_mailbox;

/* Number of messages in currently open mailbox */
extern int imapd_exists;

/* Name of client host */
extern char imapd_clienthost[];

/* List of strings, for fetch and search argument blocks */
struct strlist {
    char *s;			/* String */
    comp_pat *p;		/* Compiled pattern, for search */
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
#define FETCH_SETSEEN		(1<<10)
#define FETCH_UNCACHEDHEADER	(1<<11)
#define FETCH_FAST (FETCH_FLAGS|FETCH_INTERNALDATE|FETCH_SIZE)
#define FETCH_ALL  (FETCH_FLAGS|FETCH_INTERNALDATE|FETCH_SIZE|FETCH_ENVELOPE)
#define FETCH_FULL (FETCH_ALL|FETCH_BODY)

/* Arguments to Store functions */
struct storeargs {
    int operation;
    int silent;
    int seen;
    bit32 system_flags;
    /* private to index.c */
    bit32 user_flags[MAX_USER_FLAGS/32];
    time_t update_time;
    int usinguid;
    /* private to index_storeflag() */
    int last_msgno;
    int last_found;
};

/* values for operation */
#define STORE_ADD	1
#define STORE_REMOVE	2
#define STORE_REPLACE	3

struct searchsub {
    struct searchsub *next;
    struct searchargs *sub1;
    /*
     * If sub2 is null, then sub1 is NOT'ed.
     * Otherwise sub1 and sub2 are OR'ed.
     */
    struct searchargs *sub2;
};

/* Things that may be searched for */
struct searchargs {
    int recent_set;
    int recent_unset;
    int peruser_flags_set;
    int peruser_flags_unset;
    unsigned smaller, larger;
    time_t before, after;
    time_t sentbefore, sentafter;
    bit32 system_flags_set;
    bit32 system_flags_unset;
    bit32 user_flags_set[MAX_USER_FLAGS/32];
    bit32 user_flags_unset[MAX_USER_FLAGS/32];
    struct strlist *sequence;
    struct strlist *uidsequence;
    struct strlist *from;
    struct strlist *to;
    struct strlist *cc;
    struct strlist *bcc;
    struct strlist *subject;
    struct strlist *body;
    struct strlist *text;
    struct strlist *header_name, *header;
    struct searchsub *sublist;
};

extern struct protstream *imapd_out, *imapd_in;
