/* append.h -- Description of messages to be copied 
 $Id: append.h,v 1.12 1998/05/15 21:48:03 neplokh Exp $
 
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
