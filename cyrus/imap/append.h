/* append.h -- Description of messages to be copied 
 * $Id: append.h,v 1.21.4.2 2003/02/27 18:10:30 rjs3 Exp $ 
 *
 * Copyright (c) 1998, 2000 Carnegie Mellon University.  All rights reserved.
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
 *
 */

#ifndef INCLUDED_APPEND_H
#define INCLUDED_APPEND_H

#include "mailbox.h"
#include "prot.h"

struct copymsg {
    unsigned long uid;
    time_t internaldate;
    time_t sentdate;
    unsigned long size;
    unsigned long header_size;
    const char *cache_begin;
    int cache_len;		/* 0 if need to copy & parse message */
    int seen;
    bit32 system_flags;
    char *flag[MAX_USER_FLAGS+1];
};

/* it's ridiculous i have to expose this structure if i want to allow
   clients to stack-allocate it */
struct appendstate {
    /* mailbox we're appending to */
    struct mailbox m;
    char userid[MAX_MAILBOX_NAME];

    enum { APPEND_READY, APPEND_DONE } s;
				/* current state of append */

    /* if we abort, where should we truncate the cache file? */
    unsigned long orig_cache_len;

    int writeheader;		/* did we change the mailbox header? */

    int nummsg;    /* number of messages appended pending commit.
		      from m.last_uid + 1 ... m.last_uid + nummsg */

    /* summary information to change on commit */
    int numanswered, numdeleted, numflagged;

    /* set seen on these message on commit */
    char *seen_msgrange;
    int seen_alloced;

    /* the amount of quota we've used so far in this append */
    int quota_used;
};

/* add helper function to determine uid range appended? */

struct stagemsg;

extern int append_check(const char *name, int format, 
			struct auth_state *auth_state,
			long aclcheck, long quotacheck);

/* appendstate must be allocated by client */
extern int append_setup(struct appendstate *mailbox, const char *name,
			int format, 
			const char *userid, struct auth_state *auth_state,
			long aclcheck, long quotacheck);

extern int append_commit(struct appendstate *mailbox,
			 unsigned long *uidvalidity, 
			 unsigned long *startuid, 
			 unsigned long *num);
extern int append_abort(struct appendstate *mailbox);

int append_stageparts(struct stagemsg *stagep);

/* creates a new stage and returns stage file corresponding to mailboxname */
extern FILE *append_newstage(const char *mailboxname, time_t internaldate,
			     struct stagemsg **stagep);

/* adds a new mailbox to the stage initially created by append_newstage() */
extern int append_fromstage(struct appendstate *mailbox,
			    struct protstream *messagefile,
			    unsigned long size, time_t internaldate,
			    const char **flag, int nflags,
			    struct stagemsg *stage);

/* removes the stage (frees memory, deletes the staging files) */
extern int append_removestage(struct stagemsg *stage);

extern int append_fromstream(struct appendstate *as,
			     struct protstream *messagefile,
			     unsigned long size, time_t internaldate,
			     const char **flag, int nflags);

extern int append_copy(struct mailbox *mailbox,
		       struct appendstate *append_mailbox,
		       int nummsg, struct copymsg *copymsg);

extern int append_collectnews(struct appendstate *mailbox,
			      const char *group, unsigned long feeduid);

#define append_getuidvalidity(as) ((as)->m.uidvalidity);
#define append_getlastuid(as) ((as)->m.last_uid);

#endif /* INCLUDED_APPEND_H */
