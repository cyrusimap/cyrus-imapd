/* mboxlist.c -- Mailbox list manipulation routines
 * 
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
 * 
 * $Id: mboxlist.h,v 1.18 2002/01/24 16:39:28 rjs3 Exp $
 */

#ifndef INCLUDED_MBOXLIST_H
#define INCLUDED_MBOXLIST_H

#include "cyrusdb.h"
#include "mailbox.h"
#include "auth.h"
#include "acap.h"
#include "mboxname.h"

/* --- cut here --- */
#ifndef CONFIG_DB_SUBS
#define CONFIG_DB_SUBS (&cyrusdb_flat)
#endif

#ifndef CONFIG_DB_MBOX
#define CONFIG_DB_MBOX (&cyrusdb_db3)
#endif
/* -- cut here -- */
extern struct db *mbdb;

/*
 * Maximum length of partition name. [config.c has a limit of 70]
 */
#define MAX_PARTITION_LEN 64

/* flags for types of mailboxes */
#define MBTYPE_REMOTE 0x01
#define MBTYPE_RESERVE 0x02
#define MBTYPE_NETNEWS 0x04

/* master name of the mailboxes file */
#define FNAME_MBOXLIST "/mailboxes.db"

/* each mailbox has the following data */
struct mbox_entry {
    char name[MAX_MAILBOX_NAME];
    int mbtype;
    char partition[MAX_PARTITION_LEN];
				/* holds remote machine for REMOTE mailboxes */
    char acls[1];
};

/* Lookup 'name' in the mailbox list. */
int mboxlist_lookup(const char *name, char **pathp, char **aclp, void *tid);

/* Lookup 'name' and get more detail */
int mboxlist_detail(const char *name, int *typep, char **pathp, char **partp,
		    char **aclp, struct txn *tid);

/* insert a stub entry */
int mboxlist_insertremote(const char *name, int mbtype, const char *host,
			  const char *acl, void **rettid);

/* check user's ability to create mailbox */
int mboxlist_createmailboxcheck(char *name, int mbtype, char *partition, 
				int isadmin, char *userid, 
				struct auth_state *auth_state, 
				char **newacl, char **newpartition);

/* create mailbox */
int mboxlist_createmailbox(char *name, int mbtype, char *partition, 
			   int isadmin, char *userid, 
			   struct auth_state *auth_state);

/* Delete a mailbox. */
int mboxlist_deletemailbox(const char *name, int isadmin, char *userid, 
			   struct auth_state *auth_state, int checkacl);

/* Rename/move a mailbox (hierarchical) */
int mboxlist_renamemailbox(char *oldname, char *newname, char *partition, 
			   int isadmin, char *userid, 
			   struct auth_state *auth_state);

/* change ACL */
int mboxlist_setacl(char *name, char *identifier, char *rights, int isadmin, 
		    char *userid, struct auth_state *auth_state);

/* Find all mailboxes that match 'pattern'. */
int mboxlist_findall(struct namespace *namespace,
		     char *pattern, int isadmin, char *userid, 
		     struct auth_state *auth_state, int (*proc)(), void *rock);
int mboxlist_findall_std(struct namespace *namespace,
			 char *pattern, int isadmin, char *userid, 
			 struct auth_state *auth_state, int (*proc)(),
			 void *rock);
int mboxlist_findall_alt(struct namespace *namespace, char *pattern,
			 int isadmin, char *userid, 
			 struct auth_state *auth_state, int (*proc)(),
			 void *rock);

/* Find subscribed mailboxes that match 'pattern'. */
int mboxlist_findsub(struct namespace *namespace,
		     char *pattern, int isadmin, char *userid, 
		     struct auth_state *auth_state, int (*proc)(), void *rock,
		     int force);
int mboxlist_findsub_std(struct namespace *namespace,
			 char *pattern, int isadmin, char *userid, 
			 struct auth_state *auth_state, int (*proc)(),
			 void *rock, int force);
int mboxlist_findsub_alt(struct namespace *namespace, char *pattern,
			 int isadmin, char *userid, 
			 struct auth_state *auth_state, int (*proc)(),
			 void *rock, int force);

/* given a mailbox 'name', where should we stage messages for it? 
   'stagedir' should be MAX_MAILBOX_PATH. */
int mboxlist_findstage(const char *name, char *stagedir);

/* Change 'user's subscription status for mailbox 'name'. */
int mboxlist_changesub(const char *name, const char *userid, 
		       struct auth_state *auth_state, int add, int force);

/* get name a file containing subscriptions for 'userid' */
char *mboxlist_hash_usersubs(const char *userid);

/* set or create quota root */
int mboxlist_setquota(const char *root, int newquota);

/* returns a malloc() string that is the representation in the mailboxes 
   file.  for ctl_mboxlist */
char *mboxlist_makeentry(int mbtype, const char *part, const char *acl);

/* open the mailboxes db */
void mboxlist_open(char *name);

/* close the database */
void mboxlist_close(void);

/* initialize database structures */
#define MBOXLIST_RECOVER 0x01
#define MBOXLIST_SYNC 0x02
void mboxlist_init(int flags);

/* done with database stuff */
void mboxlist_done(void);

#endif
