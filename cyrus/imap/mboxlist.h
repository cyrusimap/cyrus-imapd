/* mboxlist.c -- Mailbox list manipulation routines
 * 
 * Copyright 1999 Carnegie Mellon University
 * 
 * $Id: mboxlist.h,v 1.2 2000/01/28 22:09:48 leg Exp $
 */

#ifndef INCLUDED_MBOXLIST_H
#define INCLUDED_MBOXLIST_H

#include <db.h>
#include "auth.h"
#include "acap.h"

/*
 * Maximum length of partition name. [config.c has a limit of 70]
 */
#define MAX_PARTITION_LEN 64

/* flags for types of mailboxes */
#define MBTYPE_REMOTE 0x01
#define MBTYPE_CONFLICT 0x02
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

typedef enum {
    MB_NEXT,
    MB_REMOVE,
    MB_UPDATE,
    MB_FATAL
} foreach_res;

typedef struct mbox_txn mbox_txn_t;

/* commit a previously started transaction */
int mboxlist_commit(struct mbox_txn *tid);

/* abort a previously started transaction */
int mboxlist_abort(struct mbox_txn *tid);

/* Lookup 'name' in the mailbox list. */
int mboxlist_lookup(const char *name, char **pathp, char **aclp, void *tid);

/* insert a stub entry */
int mboxlist_insertremote(char *name, int mbtype, char *host, char *acl,
			  void **rettid);

/* check user's ability to create mailbox */
int mboxlist_createmailboxcheck(char *name, int mbtype, char *partition, 
				int isadmin, char *userid, 
				struct auth_state *auth_state, 
				char **newacl, char **newpartition);

/* create mailbox; don't commit if tid != NULL */
int mboxlist_createmailbox(char *name, int mbtype, char *partition, 
			   int isadmin, char *userid, 
			   struct auth_state *auth_state);

/* Delete a mailbox. */
int mboxlist_deletemailbox(char *name, int isadmin, char *userid, 
			   struct auth_state *auth_state, int checkacl);

/* Rename/move a mailbox */
int mboxlist_renamemailbox(char *oldname, char *newname, char *partition, 
			   int isadmin, char *userid, 
			   struct auth_state *auth_state);

/* change ACL */
int mboxlist_setacl(char *name, char *identifier, char *rights, int isadmin, 
		    char *userid, struct auth_state *auth_state);

/* Find all mailboxes that match 'pattern'. */
int mboxlist_findall(char *pattern, int isadmin, char *userid, 
		     struct auth_state *auth_state, int (*proc)(), void *rock);

typedef foreach_res foreach_proc(void *rock, struct mbox_entry **mboxent);
  
int mboxlist_foreach(foreach_proc *p, void *rock, int rw);

/* Find subscribed mailboxes that match 'pattern'. */
int mboxlist_findsub(char *pattern, int isadmin, char *userid, 
		     struct auth_state *auth_state, int (*proc)(), void *rock);

/* Change 'user's subscription status for mailbox 'name'. */
int mboxlist_changesub(const char *name, const char *userid, 
		       struct auth_state *auth_state, int add);

/* set or create quota root */
int mboxlist_setquota(const char *root, int newquota);

/* Resynchronize the news mailboxes. */
int mboxlist_syncnews(int num, char **group, int *seen);

/* open the mailboxes db */
void mboxlist_open(char *name);

/* close the database */
void mboxlist_close(void);

/* initialize database structures */
void mboxlist_init(void);

/* done with database stuff */
void mboxlist_done(void);



/* open up acap connection if possible */
int mboxlist_acapinit(void);



#endif
