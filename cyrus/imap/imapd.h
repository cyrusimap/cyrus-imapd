/* imapd.h -- Common state for IMAP daemon
 * $Id: imapd.h,v 1.46 2001/03/15 22:56:18 leg Exp $
 *
 * Copyright (c) 1999-2000 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
enum {
    FETCH_UID =                 (1<<0),
    FETCH_INTERNALDATE =        (1<<1),
    FETCH_SIZE =                (1<<2),
    FETCH_FLAGS =               (1<<3),
    FETCH_ENVELOPE =	        (1<<4),
    FETCH_BODYSTRUCTURE =	(1<<5),
    FETCH_BODY =                (1<<6),
    FETCH_HEADER =	        (1<<7),
    FETCH_TEXT =                (1<<8),
    FETCH_RFC822 =              (1<<9),
    FETCH_SETSEEN =             (1<<10),
    FETCH_UNCACHEDHEADER =      (1<<11)
};

enum {
    FETCH_FAST = (FETCH_FLAGS|FETCH_INTERNALDATE|FETCH_SIZE),
    FETCH_ALL = (FETCH_FLAGS|FETCH_INTERNALDATE|FETCH_SIZE|FETCH_ENVELOPE),
    FETCH_FULL = (FETCH_ALL|FETCH_BODY)
};

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
enum {
    STORE_ADD = 1,
    STORE_REMOVE = 2,
    STORE_REPLACE = 3
};

struct searchsub {
    struct searchsub *next;
    struct searchargs *sub1;
    /*
     * If sub2 is null, then sub1 is NOT'ed.
     * Otherwise sub1 and sub2 are OR'ed.
     */
    struct searchargs *sub2;
};

enum {
    SEARCH_RECENT_SET =         (1<<0),
    SEARCH_RECENT_UNSET	=       (1<<1),
    SEARCH_SEEN_SET =           (1<<2),
    SEARCH_SEEN_UNSET =	        (1<<3),
    SEARCH_UNCACHEDHEADER =	(1<<4)
};

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
    struct strlist *messageid;
    struct strlist *body;
    struct strlist *text;
    struct strlist *header_name, *header;
    struct searchsub *sublist;
};

/* Sort criterion */
struct sortcrit {
    unsigned key;		/* sort key */
    int flags;			/* key modifiers as defined below */
    union {			/* argument(s) to the sort key */
	struct {
	    char *entry;
	    char *attrib;
	} annot;
    } args;
};

/* Values for sort keys */
enum {
    SORT_SEQUENCE = 0,
    SORT_ARRIVAL,
    SORT_CC,
    SORT_DATE,
    SORT_FROM,
    SORT_SIZE,
    SORT_SUBJECT,
    SORT_TO,
    SORT_ANNOTATION
    /* values > 255 are reserved for internal use */
};

/* Sort key modifier flag bits */
#define SORT_REVERSE		(1<<0)

/* Bitmask for status queries */
enum {
    STATUS_MESSAGES =	        (1<<0),
    STATUS_RECENT =		(1<<1),
    STATUS_UIDNEXT =		(1<<2),
    STATUS_UIDVALIDITY =	(1<<3),
    STATUS_UNSEEN =		(1<<4)
};

extern struct protstream *imapd_out, *imapd_in;


extern void index_closemailbox(struct mailbox *mailbox);
extern void index_newmailbox(struct mailbox *mailbox, int examine_mode);
extern void index_operatemailbox(struct mailbox *mailbox);
extern void index_check(struct mailbox *mailbox, int usinguid,
			   int checkseen);
extern void index_checkseen(struct mailbox *mailbox, int quiet,
			       int usinguid, int oldexists);

extern void index_fetch(struct mailbox *mailbox, char *sequence,
			int usinguid, struct fetchargs *fetchargs,
			int* fetchedsomething);
extern int index_store(struct mailbox *mailbox, char *sequence,
			  int usinguid, struct storeargs *storeargs,
			  char **flag, int nflags);
extern void index_search(struct mailbox *mailbox,
			    struct searchargs *searchargs, int usinguid);
extern int find_thread_algorithm(char *arg);
extern void index_sort(struct mailbox *mailbox, struct sortcrit *sortcrit,
		       struct searchargs *searchargs, int usinguid);
extern void index_thread(struct mailbox *mailbox, int algorithm,
			 struct searchargs *searchargs, int usinguid);
extern int index_copy(struct mailbox *mailbox, char *sequence,
			 int usinguid, char *name, char **copyuidp);
extern int index_status(struct mailbox *mailbox, char *name,
			   int statusitems);

extern int index_getuids(struct mailbox *mailbox, unsigned lowuid);
extern int index_getstate(struct mailbox *mailbox);
extern int index_checkstate(struct mailbox *mailbox, unsigned indexdate,
			       unsigned seendate);

extern int index_finduid(unsigned uid);

extern mailbox_decideproc_t index_expungeuidlist;

#endif /* INCLUDED_IMAPD_H */
