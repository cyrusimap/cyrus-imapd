/* append.h -- Description of messages to be copied 
 $Id: append.h,v 1.15 2000/04/06 15:14:30 leg Exp $
 
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

#ifndef INCLUDED_APPEND_H
#define INCLUDED_APPEND_H

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

    enum { APPEND_READY, APPEND_DONE } s;
				/* current state of append */

    /* if we abort, where should we truncate the cache file? */
    unsigned long orig_cache_len;

    int writeheader;		/* did we change the mailbox header? */

    int nummsg;    /* number of messages appended pending commit.
		      from m.last_uid + 1 ... m.last_uid + nummsg */

    /* summary information to change on commit */
    int numanswered, numdeleted, numflagged;

    /* the amount of quota we've used so far in this append */
    int quota_used;
};

/* add helper function to determine uid range appended? */

struct stagemsg;

/* appendstate must be allocated by client */
extern int append_setup(struct appendstate *mailbox, const char *name,
			int format, struct auth_state *auth_state,
			long aclcheck, long quotacheck);

extern int append_commit(struct appendstate *mailbox,
			 int *uidvalidity, int *startuid, int *num);
extern int append_abort(struct appendstate *mailbox);

/* adds a new mailbox to the stage. creates the stage if *stagep == NULL. */
extern int append_fromstage(struct appendstate *mailbox,
			    struct protstream *messagefile,
			    unsigned long size, time_t internaldate,
			    const char **flag, int nflags,
			    const char *userid,
			    struct stagemsg **stagep);

/* removes the stage (frees memory, deletes the staging files) */
extern int append_removestage(struct stagemsg *stage);

extern int append_fromstream(struct appendstate *as,
			     struct protstream *messagefile,
			     unsigned long size, time_t internaldate,
			     const char **flag, int nflags,
			     const char *userid);

extern int append_copy(struct mailbox *mailbox,
		       struct appendstate *append_mailbox,
		       int nummsg, struct copymsg *copymsg,
		       const char *userid);

extern int append_collectnews(struct appendstate *mailbox,
			      const char *group, unsigned long feeduid);

#define append_getuidvalidity(as) ((as)->m.uidvalidity);
#define append_getlastuid(as) ((as)->m.last_uid);

#endif /* INCLUDED_APPEND_H */
