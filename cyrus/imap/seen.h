/* seen.h -- abstract interface for /Recent and /Seen information
   $Id: seen.h,v 1.1 2000/02/10 08:00:27 leg Exp $
 
 # Copyright 2000 Carnegie Mellon University
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


#ifndef SEEN_H
#define SEEN_H

struct seen;

int seen_open(struct mailbox *mailbox, const char *user, 
	      struct seen **seendbptr);

int seen_lockread(struct seen *seendb, 
		  time_t *lastreadptr, unsigned int *lastuidptr, 
		  time_t *lastchangeptr, char **seenuidsptr);

int seen_write(struct seen *seendb, time_t lastread, unsigned int lastuid, 
	       time_t lastchange, char *seenuids);

int seen_close(struct seen *seendb);

int seen_create(struct mailbox *mailbox);

int seen_delete(struct mailbox *mailbox);

int seen_copy(struct mailbox *oldmailbox,struct mailbox *newmailbox);

int seen_unlock(struct seen *seendb);

int seen_reconstruct(struct mailbox *mailbox,
		     time_t report_time,
		     time_t prune_time,
		     int (*report_proc)(),
		     void *report_rock);

#endif /* SEEN_LOCAL_H */
