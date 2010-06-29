/* index.h -- Routines for dealing with the index file in the imapd
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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
 * $Id: index.h,v 1.18 2010/01/06 17:01:35 murch Exp $
 */

/* Header for internal usage of index.c + programs that make raw access
 * to index files */

#ifndef INDEX_H
#define INDEX_H

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>

#include "annotate.h" /* for strlist functionality */
#include "message_guid.h"
#include "sequence.h"

/* Special "sort criteria" to load message-id and references/in-reply-to
 * into msgdata array for threaders that need them.
 */
#define LOAD_IDS	256

struct vanished_params {
    unsigned long uidvalidity;
    modseq_t modseq;
    const char *match_seq;
    const char *match_uid;
    const char *sequence;
};

struct index_init {
    const char *userid;
    struct auth_state *authstate;
    struct protstream *out;
    int examine_mode;
    int qresync;
    int select;
    struct vanished_params vanished;
};

struct index_map {
    struct index_record record;
    modseq_t told_modseq;
    int isseen:1;
    int isrecent:1;
};

struct index_state {
    struct mailbox *mailbox;
    unsigned num_records;
    unsigned exists;
    unsigned long last_uid;
    modseq_t highestmodseq;
    modseq_t delayed_modseq;
    struct index_map *map;
    unsigned mapsize;
    int internalseen;
    int skipped_expunge;
    int seen_dirty;
    int keepingseen;
    int examining;
    int myrights;
    unsigned numrecent;
    unsigned numunseen;
    unsigned firstnotseen;
    int havenewrecords;
    char *flagname[MAX_USER_FLAGS];
    char *userid;
    struct protstream *out;
    int qresync;
    struct auth_state *authstate;
};

struct copyargs {
    struct copymsg *copymsg;
    int nummsg;
    int msgalloc;
};

struct mapfile {
    const char *base;
    unsigned long size;
};

typedef struct msgdata {
    bit32 uid;                  /* UID for output purposes */
    unsigned msgno;		/* message number */
    char *msgid;		/* message ID */
    char **ref;			/* array of references */
    int nref;			/* number of references */
    time_t date;		/* sent date & time of message
				   from Date: header (adjusted by time zone) */
    time_t internaldate;        /* internaldate */
    size_t size;                /* message size */
    modseq_t modseq;            /* modseq of record*/
    char *cc;			/* local-part of first "cc" address */
    char *from;			/* local-part of first "from" address */
    char *to;			/* local-part of first "to" address */
    char *xsubj;		/* extracted subject text */
    unsigned xsubj_hash;	/* hash of extracted subject text */
    int is_refwd;		/* is message a reply or forward? */
    char **annot;		/* array of annotation attribute values
				   (stored in order of sortcrit) */
    int nannot;			/* number of annotation values */
    struct msgdata *next;
} MsgData;

typedef struct thread {
    MsgData *msgdata;		/* message data */
    struct thread *parent;	/* parent message */
    struct thread *child;	/* first child message */
    struct thread *next;	/* next sibling message */
} Thread;

struct rootset {
    Thread *root;
    unsigned nroot;
};

struct thread_algorithm {
    char *alg_name;
    void (*threader)(struct index_state *state, unsigned *msgno_list, int nmsg, int usinguid);
};

struct nntp_overview {
    unsigned long uid;
    char *subj;
    char *from;
    char *date;
    char *msgid;
    char *ref;
    unsigned long bytes;
    unsigned long lines;
};

extern int index_fetch(struct index_state *state,
		       const char* sequence,
		       int usinguid,
		       struct fetchargs* fetchargs,
		       int* fetchedsomething);
extern int index_store(struct index_state *state,
		       char *sequence,
		       int usinguid,
		       struct storeargs *storeargs,
		       char **flag, int nflags);
extern int index_sort(struct index_state *state, struct sortcrit *sortcrit,
		      struct searchargs *searchargs, int usinguid);
extern int index_thread(struct index_state *state, int algorithm,
			struct searchargs *searchargs, int usinguid);
extern int index_search(struct index_state *state,
			struct searchargs *searchargs,
			int usinguid);
extern int index_scan(struct index_state *state,
		      const char *contents);
extern int index_copy(struct index_state *state,
		      char *sequence, 
		      int usinguid,
		      char *name, 
		      char **copyuidp,
		      int nolink);
extern int find_thread_algorithm(char *arg);

extern int index_open(const char *name, struct index_init *init,
		      struct index_state **stateptr);
extern int index_status(struct index_state *state, struct statusdata *sdata);
extern int index_close(struct index_state **stateptr);
extern unsigned index_finduid(struct index_state *state, unsigned uid);
extern unsigned index_getuid(struct index_state *state, unsigned msgno);
extern modseq_t index_highestmodseq(struct index_state *state);
extern int index_check(struct index_state *state, int usinguid, int printuid);
extern int index_urlfetch(struct index_state *state, unsigned msgno,
			  unsigned params, const char *section,
			  unsigned long start_octet, unsigned long octet_count,
			  struct protstream *pout, unsigned long *size);
extern char *index_get_msgid(struct index_state *state, unsigned msgno);
extern struct nntp_overview *index_overview(struct index_state *state,
					    unsigned msgno);
extern char *index_getheader(struct index_state *state, unsigned msgno,
			     char *hdr);
extern unsigned long index_getsize(struct index_state *state, unsigned msgno);
extern unsigned long index_getlines(struct index_state *state, unsigned msgno);
extern int index_copy_remote(struct index_state *state, char *sequence, 
			     int usinguid, struct protstream *pout);

void appendsequencelist(struct index_state *state, struct seqset **l,
			char *sequence, int usinguid);
void freesequencelist(struct seqset *l);
extern int index_expunge(struct index_state *state, int usinguid,
			 char *uidsequence, int isclose);

/* See lib/charset.h for the definition of receiver. */
extern void index_getsearchtext_single(struct index_state *state, unsigned msgno,
                                       index_search_text_receiver_t receiver,
                                       void* rock);

extern void index_getsearchtext(struct index_state *state,
                                index_search_text_receiver_t receiver,
                                void* rock);

extern int index_getuidsequence(struct index_state *state,
				struct searchargs *searchargs,
				unsigned **uid_list);

#endif /* INDEX_H */
