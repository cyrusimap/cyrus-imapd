/* imapd.h -- Common state for IMAP daemon
 $Id: imapd.h,v 1.30 1998/05/15 21:48:38 neplokh Exp $
 
 # Copyright 1998 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
 *
 */

#ifndef INCLUDED_IMAPD_H
#define INCLUDED_IMAPD_H

#include "prot.h"
#include "charset.h"
#include "mailbox.h"

/* Userid client has logged in as */
extern char *imapd_userid;

/* Authorization state for logged in userid */
extern struct auth_state *imapd_authstate;

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

/* List of HEADER.FIELDS[.NOT] fetch specifications */
struct fieldlist {
    char *section;		/* First part of BODY[x] value */
    struct strlist *fields;	/* List of field-names */
    char *trail;		/* Last part of BODY[x] value */
    struct fieldlist *next;
};

/* Items that may be fetched */
struct fetchargs {
    int fetchitems;		/* Bitmask */
    struct strlist *bodysections; /* BODY[x]<x> values */
    struct fieldlist *fsections;  /* BODY[xHEADER.FIELDSx]<x> values */
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

#define SEARCH_RECENT_SET	(1<<0)
#define SEARCH_RECENT_UNSET	(1<<1)
#define SEARCH_SEEN_SET		(1<<2)
#define SEARCH_SEEN_UNSET	(1<<3)
#define SEARCH_UNCACHEDHEADER	(1<<4)

/* Things that may be searched for */
struct searchargs {
    int flags;
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

/* Bitmask for status queries */
#define STATUS_MESSAGES		(1<<0)
#define STATUS_RECENT		(1<<1)
#define STATUS_UIDNEXT		(1<<2)
#define STATUS_UIDVALIDITY	(1<<3)
#define STATUS_UNSEEN		(1<<4)

extern struct protstream *imapd_out, *imapd_in;


extern void index_closemailbox P((struct mailbox *mailbox));
extern void index_newmailbox P((struct mailbox *mailbox, int examine_mode));
extern void index_check P((struct mailbox *mailbox, int usinguid,
			   int checkseen));
extern void index_checkseen P((struct mailbox *mailbox, int quiet,
			       int usinguid, int oldexists));

extern void index_fetch P((struct mailbox *mailbox, char *sequence,
			   int usinguid, struct fetchargs *fetchargs));
extern int index_store P((struct mailbox *mailbox, char *sequence,
			  int usinguid, struct storeargs *storeargs,
			  char **flag, int nflags));
extern void index_search P((struct mailbox *mailbox,
			    struct searchargs *searchargs, int usinguid));
extern int index_copy P((struct mailbox *mailbox, char *sequence,
			 int usinguid, char *name, char **copyuidp));
extern int index_status P((struct mailbox *mailbox, char *name,
			   int statusitems));

extern int index_getuids P((struct mailbox *mailbox, unsigned lowuid));
extern int index_getstate P((struct mailbox *mailbox));
extern int index_checkstate P((struct mailbox *mailbox, unsigned indexdate,
			       unsigned seendate));

extern int index_finduid P((unsigned uid));

extern mailbox_decideproc_t index_expungeuidlist;

#endif /* INCLUDED_IMAPD_H */
