/* append.h -- Description of messages to be copied 
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */

#ifndef INCLUDED_APPEND_H
#define INCLUDED_APPEND_H

#include "prot.h"

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

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

extern int append_setup P((struct mailbox *mailbox, const char *name,
			   int format, struct auth_state *auth_state,
			   long aclcheck, long quotacheck));

extern int append_fromstream P((struct mailbox *mailbox,
				struct protstream *messagefile,
				unsigned long size, time_t internaldate,
				const char **flag, int nflags,
				const char *userid));

extern int append_copy P((struct mailbox *mailbox,
			  struct mailbox *append_mailbox,
			  int nummsg, struct copymsg *copymsg,
			  const char *userid));

extern int append_collectnews P((struct mailbox *mailbox,
				 const char *group, unsigned long feeduid));

#endif /* INCLUDED_APPEND_H */
