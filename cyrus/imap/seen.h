/* seen.h -- abstract interface for /Recent and /Seen information
   $Id: seen.h,v 1.10.4.1 2002/08/21 19:52:41 ken3 Exp $
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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


#ifndef SEEN_H
#define SEEN_H

struct seen;

/* get a database handle corresponding to (mailbox, user) pair */
int seen_open(struct mailbox *mailbox, 
	      const char *user, 
	      struct seen **seendbptr);

/* read an entry from 'seendb' */
int seen_read(struct seen *seendb, 
	      time_t *lastreadptr, unsigned int *lastuidptr, 
	      time_t *lastchangeptr, char **seenuidsptr);

/* read an entry from 'seendb' and leave that record (or some superset
   of it) locked for update */
int seen_lockread(struct seen *seendb, 
		  time_t *lastreadptr, unsigned int *lastuidptr, 
		  time_t *lastchangeptr, char **seenuidsptr);

/* write an entry to 'seendb'; should have been already locked by
   seen_lockread() */
int seen_write(struct seen *seendb, time_t lastread, unsigned int lastuid, 
	       time_t lastchange, char *seenuids);

/* close this handle */
int seen_close(struct seen *seendb);

/* discard lock on handle */
int seen_unlock(struct seen *seendb);

/* called on mailbox operations */
int seen_create_mailbox(struct mailbox *mailbox);
int seen_delete_mailbox(struct mailbox *mailbox);
int seen_copy(struct mailbox *oldmailbox,struct mailbox *newmailbox);

/* called on user operations */
int seen_create_user(const char *user);
int seen_delete_user(const char *user);
int seen_rename_user(const char *olduser, const char *newuser);

int seen_reconstruct(struct mailbox *mailbox,
		     time_t report_time,
		     time_t prune_time,
		     int (*report_proc)(),
		     void *report_rock);

/* done with all seen operations for this process */
int seen_done(void);

/* Return a path to the seen database for the given user (or NULL if we are
 * using bigdb) */
char *seen_getpath(const char *userid);

/* Merge tmpfile into tgtfile */
int seen_merge(const char *tmpfile, const char *tgtfile);

#endif /* SEEN_LOCAL_H */
