/* mboxlist.c -- Mailbox list manipulation routines
 * 
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
/*
 * $Id: mboxlist.c,v 1.132 2000/07/11 17:54:59 leg Exp $
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <syslog.h>
#include <com_err.h>

#include <sys/ipc.h>
#include <sys/msg.h>

#include <db.h>

extern int errno;

#include "acl.h"
#include "auth.h"
#include "glob.h"
#include "assert.h"
#include "imapconf.h"
#include "cyrusdb.h"
#include "util.h"
#include "mailbox.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "xmalloc.h"

#include "acap.h"
#include "acapmbox.h"
#include "mboxname.h"

#include "mboxlist.h"

/* --- cut here --- */
/*
 * what berkeley db algorithm should we use for deadlock detection?
 * 
 * DB_LOCK_DEFAULT
 *    Use the default policy as specified by db_deadlock. 
 * DB_LOCK_OLDEST
 *    Abort the oldest transaction. 
 * DB_LOCK_RANDOM
 *    Abort a random transaction involved in the deadlock. 
 * DB_LOCK_YOUNGEST
 *    Abort the youngest transaction. 
 */

#define CONFIG_DEADLOCK_DETECTION DB_LOCK_YOUNGEST
#define CONFIG_DB_SUBS (&cyrusdb_flat)
/* -- cut here -- */

#define SUBDB CONFIG_DB_SUBS

acl_canonproc_t mboxlist_ensureOwnerRights;

DB *mbdb;
DB_ENV *dbenv;

static int mboxlist_dbinit = 0,
    mboxlist_dbopen = 0;

static int mboxlist_opensubs();
static void mboxlist_closesubs();

static struct quota *mboxlist_newquota;
static int mboxlist_changequota();

static char *mboxlist_hash_usersubs(const char *userid);

#define FNAME_SUBSSUFFIX ".sub"

const char *acap_authname = NULL;
const char *acap_realm = NULL;
const char *acap_password = NULL;

/*
 * Convert a partition into a path
 */
static int mboxlist_getpath(char *partition, char *name, char **pathp)
{
    int partitionlen;
    char optionbuf[MAX_MAILBOX_NAME+1];
    static char pathresult[MAX_MAILBOX_PATH];
    const char *root;

    assert(partition && pathp);

    partitionlen = strlen(partition);

    if (partitionlen > sizeof(optionbuf)-11) {
	return IMAP_PARTITION_UNKNOWN;
    }
    strcpy(optionbuf, "partition-");
    strcat(optionbuf, partition);
    
    root = config_getstring(optionbuf, (char *)0);
    if (!root) {
	return IMAP_PARTITION_UNKNOWN;
    }
    mailbox_hash_mbox(pathresult, root, name);

    *pathp = pathresult;

    return 0;
}

/*
 * Lookup 'name' in the mailbox list.
 * The capitalization of 'name' is canonicalized to the way it appears
 * in the mailbox list.
 * If 'path' is non-nil, a pointer to the full pathname of the mailbox
 * is placed in the char * pointed to by it.  If 'acl' is non-nil, a pointer
 * to the mailbox ACL is placed in the char * pointed to by it.
 */
static int mboxlist_mylookup(const char* name, char** pathp, char** aclp, 
			     DB_TXN *tid, int flags)
{
    unsigned long partitionlen, acllen;
    static char *aclresult;
    static int aclresultalloced;
    int r;
    DBT key, data;
    struct mbox_entry *mboxent;

    memset(&data, 0, sizeof(key));
    memset(&key, 0, sizeof(key));
    key.data = (char *) name;
    key.size = strlen(name);

    if (key.size == 0) {
	return IMAP_MAILBOX_NONEXISTENT;
    }
    r = mbdb->get(mbdb, tid, &key, &data, flags);
    switch (r) {
    case 0:
	/* copy out interesting parts */
	mboxent = (struct mbox_entry *) data.data;
	partitionlen = strlen(mboxent->partition);
	acllen = strlen(mboxent->acls);
	break;

    case DB_LOCK_DEADLOCK:
      return IMAP_AGAIN;
      break;

    case DB_NOTFOUND:
	return IMAP_MAILBOX_NONEXISTENT;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error fetching %s: %s",
	       name, db_strerror(r));
	return IMAP_IOERROR;
	break;
    }

    /* construct pathname if requested */
    if (pathp) {
	if (mboxent->mbtype & MBTYPE_REMOTE) {
	    static char presult[MAX_PARTITION_LEN];
	    
	    strcpy(presult, mboxent->partition);
	    *pathp = presult;
	} else {
	    r = mboxlist_getpath(mboxent->partition, mboxent->name, pathp);
	    if (r) {
		return r;
	    }
	}
    }

    /* return ACL if requested */
    if (aclp) {
	if ((strlen(mboxent->acls) + 1) > aclresultalloced) {
	    aclresultalloced = strlen(mboxent->acls) + 100;
	    aclresult = xrealloc(aclresult, aclresultalloced);
	}
	strcpy(aclresult, mboxent->acls);

	*aclp = aclresult;
    }
    return 0;
}

/*
 * Lookup 'name' in the mailbox list.
 * The capitalization of 'name' is canonicalized to the way it appears
 * in the mailbox list.
 * If 'path' is non-nil, a pointer to the full pathname of the mailbox
 * is placed in the char * pointed to by it.  If 'acl' is non-nil, a pointer
 * to the mailbox ACL is placed in the char * pointed to by it.
 */
int mboxlist_lookup(const char *name, char **pathp, char **aclp, void *tid)
{
    return mboxlist_mylookup(name, pathp, aclp, (DB_TXN *) tid, 0);
}

/* same thing, but grab writelocks while doing the read */
int mboxlist_lookup_writelock(const char *name, char** pathp, char** aclp, 
			      DB_TXN *tid)
{
    return mboxlist_mylookup(name, pathp, aclp, tid, DB_RMW);
}

int mboxlist_findstage(const char *name, char *stagedir) 
{
    DBT key, data;
    struct mbox_entry *mboxent;
    char optionbuf[MAX_MAILBOX_NAME+1];
    const char *root;
    int r;

    assert(stagedir != NULL);

    memset(&key, 0, sizeof(key));
    key.data = (char *) name;
    key.size = strlen(name);

    memset(&data, 0, sizeof(key));

    /* Find mailbox */
    r = mbdb->get(mbdb, NULL, &key, &data, 0);
    switch (r) {
    case 0:
	mboxent = (struct mbox_entry *) data.data;
	break;
    case DB_NOTFOUND:
	return IMAP_MAILBOX_NONEXISTENT;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error fetching %s: %s",
	       name, db_strerror(r));
	return IMAP_IOERROR;
	break;
    }
	
    strcpy(optionbuf, "partition-");
    strcpy(optionbuf + 10, mboxent->partition);
    
    root = config_getstring(optionbuf, (char *)0);
    if (!root) {
	return IMAP_PARTITION_UNKNOWN;
    }
	
    sprintf(stagedir, "%s/stage./", root);
    
    return 0;
}

/*
 * Check/set up for mailbox creation
 */
int
mboxlist_mycreatemailboxcheck(char *name, int mbtype, char *partition, 
			      int isadmin, char *userid, 
			      struct auth_state *auth_state, 
			      char **newacl, char **newpartition,
			      int RMW, DB_TXN *tid)
{
    int r;
    char *p;
    char *acl;
    char *defaultacl, *identifier, *rights;
    char parent[MAX_MAILBOX_NAME+1];
    unsigned long parentlen;
    char *parentname = NULL;
    char *parentpartition = NULL;
    char *parentacl = NULL;
    unsigned long parentpartitionlen = 0;
    unsigned long parentacllen = 0;
    DBT key, data;
    struct mbox_entry *mboxent;

    /* Check for invalid name/partition */
    if (partition && strlen(partition) > MAX_PARTITION_LEN) {
	return IMAP_PARTITION_UNKNOWN;
    }
    r = mboxname_policycheck(name);
    if (r) return r;

    /* User has admin rights over their own mailbox namespace */
    if (mboxname_userownsmailbox(userid, name)) {
	isadmin = 1;
    }

    /* Check to see if new mailbox exists */
    memset(&data, 0, sizeof(key));
    memset(&key, 0, sizeof(key));

    key.data = (char *) name;
    key.size = strlen(name);

    r = mbdb->get(mbdb, tid, &key, &data, RMW);
    switch (r) {
    case 0:
      mboxent = (struct mbox_entry *) data.data;
      r = IMAP_MAILBOX_EXISTS;
      
      /* Lie about error if privacy demands */
      if (!isadmin) {
	  if (!(acl_myrights(auth_state, mboxent->acls) & ACL_LOOKUP)) {
	      r = IMAP_PERMISSION_DENIED;
	  }
      }
      return r;       
      break;
    case DB_NOTFOUND:
      break;
    case DB_LOCK_DEADLOCK:
      return IMAP_AGAIN;
      break;
    default:
	syslog(LOG_ERR, "DBERROR: error fetching %s: %s",
	       name, db_strerror(r));
	return IMAP_IOERROR;
	break;
    }

    /* Search for a parent */
    strcpy(parent, name);
    parentlen = 0;
    while ((parentlen==0) && (p = strrchr(parent, '.'))) {
	*p = '\0';

	key.data = parent;
	key.size = strlen(parent);

	r = mbdb->get(mbdb, tid, &key, &data, 0);
	switch (r) {
	case DB_NOTFOUND:	  
	    break;
	case 0:
	  parentlen = strlen(parent);
	  mboxent = data.data;

	  parentname = parent;
	  parentpartition = mboxent->partition;
	  parentpartitionlen = strlen(mboxent->partition);

	  parentacl = mboxent->acls;
	  parentacllen = strlen(mboxent->acls); 
               /* xxx this could be better */
	  break;
	case DB_LOCK_DEADLOCK:
	    return IMAP_AGAIN;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: error updating database: %s",
		   name, db_strerror(r));
	    r = IMAP_IOERROR;	  
	}

    }
    if (parentlen != 0) {
      	/* Copy partition, if not specified */
	if (partition == NULL) {
	    partition = xmalloc(parentpartitionlen + 1);
	    memcpy(partition, parentpartition, parentpartitionlen);
	    partition[parentpartitionlen] = '\0';
	} else {
	    partition = xstrdup(partition);
	}

	/* Copy ACL */
	acl = xmalloc(parentacllen + 1);
	memcpy(acl, parentacl, parentacllen);
	acl[parentacllen] = '\0';

	if (!isadmin && !(acl_myrights(auth_state, acl) & ACL_CREATE)) {
	    free(partition);
	    free(acl);
	    return IMAP_PERMISSION_DENIED;
	}

	/* Canonicalize case of parent prefix */
	strncpy(name, parent, strlen(parent));

    } else { /* parentlen == 0 */
	if (!isadmin) {
	    return IMAP_PERMISSION_DENIED;
	}
	
	acl = xstrdup("");
	if (!strncmp(name, "user.", 5)) {
	    if (strchr(name+5, '.')) {
		/* Disallow creating user.X.* when no user.X */
		free(acl);
		return IMAP_PERMISSION_DENIED;
	    }
	    /*
	     * Disallow wildcards in userids with inboxes.
	     * If we allowed them, then the delete-user code
	     * in mboxlist_deletemailbox() could potentially
	     * delete other user's personal mailboxes when applied
	     * to this mailbox
	     */	     
	    if (strchr(name, '*') || strchr(name, '%') || strchr(name, '?')) {
		return IMAP_MAILBOX_BADNAME;
	    }
	    /*
	     * Users by default have all access to their personal mailbox(es),
	     * Nobody else starts with any access to same.
	     */
	    acl_set(&acl, name+5, ACL_MODE_SET, ACL_ALL,
		    (acl_canonproc_t *)0, (void *)0);
	} else {
	    defaultacl = identifier = 
		xstrdup(config_getstring("defaultacl", "anyone lrs"));
	    for (;;) {
		while (*identifier && isspace((int) *identifier)) identifier++;
		rights = identifier;
		while (*rights && !isspace((int) *rights)) rights++;
		if (!*rights) break;
		*rights++ = '\0';
		while (*rights && isspace((int) *rights)) rights++;
		if (!*rights) break;
		p = rights;
		while (*p && !isspace((int) *p)) p++;
		if (*p) *p++ = '\0';
		acl_set(&acl, identifier, ACL_MODE_SET, acl_strtomask(rights),
			(acl_canonproc_t *)0, (void *)0);
		identifier = p;
	    }
	    free(defaultacl);
	}

	if (!partition) {  
	    partition = (char *)config_defpartition;
	    if (strlen(partition) > MAX_PARTITION_LEN) {
		/* Configuration error */
		fatal("name of default partition is too long", EC_CONFIG);
	    }
	}
	partition = xstrdup(partition);
    }

    if (newpartition) *newpartition = partition;
    else free(partition);
    if (newacl) *newacl = acl;
    else free(acl);

    return 0;
}

int
mboxlist_createmailboxcheck(char *name, int mbtype, char *partition, 
			      int isadmin, char *userid, 
			      struct auth_state *auth_state, 
			      char **newacl, char **newpartition)
{
    return mboxlist_mycreatemailboxcheck(name, mbtype, partition, isadmin,
					 userid, auth_state, newacl, 
					 newpartition, 0, NULL);
}

/*
 * Create a mailbox
 *
 *
 *
 * 1. start mailboxes transaction
 * 2. verify ACL's to best of ability (CRASH: abort)
 * 3. open ACAP connection if necessary
 * 4. verify parent ACL's if need to
 * 5. create ACAP entry and set as reserved (CRASH: ACAP inconsistant)
 * 6. create on disk (CRASH: ACAP inconsistant, disk inconsistant)
 * 7. ???
 * 8. commit local transaction (CRASH: ACAP inconsistant)
 * 9. set ACAP entry as commited (CRASH: commited)
 *
 */

int mboxlist_createmailbox(char *name, int mbtype, char *partition, 
				int isadmin, char *userid, 
				struct auth_state *auth_state)
{
    int r;
    char *acl = NULL;
    char buf2[MAX_PARTITION_LEN + 30];
    const char *root = NULL;
    char *newpartition = NULL;
    struct mailbox newmailbox;
    DB_TXN *tid;
    DBT key, data;
    struct mbox_entry *mboxent = NULL;
    acapmbox_data_t mboxdata;
    int madereserved = 0; /* made reserved entry on ACAP server */
    acapmbox_handle_t *acaphandle = NULL;

    /* retry the transaction from here */
    if (0) {
      retry:
	if ((r = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s",
		   db_strerror(r));
	    return IMAP_IOERROR;
	}
    }

    /* 1. start mailboxes transaction */
    if ((r = txn_begin(dbenv, NULL, &tid, 0)) != 0) {
	syslog(LOG_ERR, "DBERROR: error beginning txn: %s", db_strerror(r));
	r = IMAP_IOERROR;
	goto done;
    }

    /* 2. verify ACL's to best of ability (CRASH: abort) */
    r = mboxlist_mycreatemailboxcheck(name, mbtype, partition, isadmin, 
				      userid, auth_state, 
				      &acl, &newpartition, DB_RMW, tid);
    if (r == IMAP_AGAIN) {
	goto retry;
    }

    if (r != 0) {
	goto done;
    }

    if (!(mbtype & MBTYPE_REMOTE)) {
	/* Get partition's path */
	sprintf(buf2, "partition-%s", newpartition);
	root = config_getstring(buf2, (char *)0);
	if (!root) {
	    r = IMAP_PARTITION_UNKNOWN;
	    goto done;
	}
	if (strlen(root)+strlen(name)+20 > MAX_MAILBOX_PATH) {
	    r = IMAP_MAILBOX_BADNAME;
	    goto done;
	}
    }

    /* add the new entry */
    mboxent = (struct mbox_entry *) xmalloc(sizeof(struct mbox_entry) +
					    strlen(acl));
    memset(mboxent, 0, sizeof(struct mbox_entry)); 

    /* fill in its fields */
    strcpy(mboxent->name, name);
    mboxent->mbtype = mbtype;
    strcpy(mboxent->partition, newpartition);
    free(newpartition); newpartition = NULL;
    strcpy(mboxent->acls, acl);
    free(acl); acl = NULL;

    memset(&key, 0, sizeof(key));
    key.data = name;
    key.size = strlen(name);

    memset(&data, 0, sizeof(data));
    data.data = mboxent;
    data.size = sizeof(struct mbox_entry) + strlen(mboxent->acls);

    /* database put */
    r = mbdb->put(mbdb, tid, &key, &data, 0);
    switch (r) {
    case 0:
	break;
    case DB_LOCK_DEADLOCK:
	goto retry;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error updating database: %s",
	       name, db_strerror(r));
	r = IMAP_IOERROR;
	goto done;
    }

    /* 3. open ACAP connection if necessary */
    acaphandle = acapmbox_get_handle();
    
    /* 5. create ACAP entry and set as reserved (CRASH: ACAP inconsistant) */
    acapmbox_new(&mboxdata, NULL, name);
    r = acapmbox_create(acaphandle, &mboxdata);
    if (r) {
	syslog(LOG_ERR, "ACAP: unable to reserve %s: %s\n", name,
	       error_message(r));
	goto done;
    }
    madereserved = 1; /* so we can roll back on failure */
    
 done: /* ALL DATABASE OPERATIONS DONE; NEED TO DO FILESYSTEM OPERATIONS */
    if (!r && !(mboxent->mbtype & MBTYPE_REMOTE)) {
	/* Create new mailbox and move new mailbox list file into place */
	mailbox_hash_mbox(buf2, root, mboxent->name);
	r = mailbox_create(mboxent->name, buf2, mboxent->acls, 
			   ((mboxent->mbtype & MBTYPE_NETNEWS) ?
			    MAILBOX_FORMAT_NETNEWS :
			    MAILBOX_FORMAT_NORMAL), 
			   &newmailbox);
	mboxdata.uidvalidity = newmailbox.uidvalidity;
	mboxdata.acl = mboxent->acls;
	mboxdata.total = newmailbox.exists;
	if (!r) {
	    mailbox_close(&newmailbox);
	}
    }

    if (r) { /* CREATE failed */ 
	int r2;

	/* delete ACAP entry if we made it */
	if (madereserved == 1) {
	    r2 = acapmbox_delete(acaphandle, name);
	    if (r2) {
		syslog(LOG_ERR, "ACAP: unable to unreserve %s: %s\n", name, 
		       error_message(r2));
	    }
	}

	switch (r2 = txn_abort(tid)) {
	case 0:
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on abort: %s", db_strerror(r2));
	}
    } else { /* all is well */
	switch (r = txn_commit(tid, 0)) {
	case 0: 
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s", db_strerror(r));
	    r = IMAP_IOERROR;
	}
    }

    /* 9. set ACAP entry as commited (CRASH: commited) */
    if (!r) {
	r = acapmbox_markactive(acaphandle, &mboxdata);
	if (r) {
	    syslog(LOG_ERR, "ACAP: unable to commit %s: %s\n", name, 
		   error_message(r));
	}
    }
    acapmbox_release_handle(acaphandle);

    if (acl) free(acl);
    if (newpartition) free(newpartition);
    if (mboxent) free(mboxent);
   
    return r;
}

/* insert an entry for the proxy */
int mboxlist_insertremote(char *name, int mbtype, char *host, char *acl,
			  void **rettid)
{
    DB_TXN *tid;
    DBT key, data;
    struct mbox_entry *mboxent = (struct mbox_entry *)
	xmalloc(sizeof(struct mbox_entry) + strlen(acl));
    int r = 0;

    assert(name != NULL && host != NULL);
    
    memset(&key, 0, sizeof(key));
    key.data = name;
    key.size = strlen(name);

    memset(mboxent, 0, sizeof(struct mbox_entry));
    strcpy(mboxent->name, name);
    strcpy(mboxent->partition, host);
    strcpy(mboxent->acls, acl);
    mboxent->mbtype = mbtype | MBTYPE_REMOTE;

    memset(&data, 0, sizeof(data));
    data.data = mboxent;
    data.size = sizeof(struct mbox_entry) + strlen(acl);

    /* retry the transaction from here */
    if (0) {
      retry:
	if ((r = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s",
		   db_strerror(r));
	    if (rettid) *rettid = NULL;
	    return IMAP_IOERROR;
	}
    }

    /* begin transaction */
    if ((r = txn_begin(dbenv, NULL, &tid, 0)) != 0)
    {
	syslog(LOG_ERR, "DBERROR: error beginning txn: %s", db_strerror(r));
	r = IMAP_IOERROR;
    }

    if (!r) {
	/* database put */
	r = mbdb->put(mbdb, tid, &key, &data, 0);
	switch (r) {
	case 0:
	    break;
	case DB_LOCK_DEADLOCK:
	    goto retry;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: error updating database: %s",
		   name, db_strerror(r));
	    r = IMAP_IOERROR;
	    break;
	}
    }

    free(mboxent);
    
    if (r) {
	txn_abort(tid);
	if (rettid) *rettid = NULL;
    } else {
	/* commit now */
	switch (r = txn_commit(tid, 0)) {
	case 0: 
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   db_strerror(r));
	    r = IMAP_IOERROR;
	}
    }

    return r;
}
	
/*
 * Delete a mailbox.
 * Deleting the mailbox user.FOO deletes the user "FOO".  It may only be
 * performed by an admin.  The operation removes the user "FOO"'s 
 * subscriptions and all sub-mailboxes of user.FOO
 *
 * 1. Begin transaction
 * 2. Verify ACL's
 * 3. remove from database
 * 4. remove from disk
 * 5. commit transaction
 * 6. Open ACAP connection if necessary
 * 7. delete from ACAP
 *
 */
int mboxlist_deletemailbox(char *name, int isadmin, char *userid, 
				struct auth_state *auth_state, int checkacl)
{
    int r;
    char *acl;
    long access;
    int deleteuser = 0; /* if we are deleting user.<user> */
    struct mailbox mailbox;
    int deletequotaroot = 0;
    char *path;
    DB_TXN *tid;
    DBT key, data;
    struct mbox_entry *mboxent = NULL;
    acapmbox_handle_t *acaphandle = NULL;
    int isremote = 0;

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    /* restart transaction here */
    if (0) {
	int r2;
      retry:
	if ((r2 = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s", 
		   db_strerror(r2));
	    return IMAP_IOERROR;
	}
    }

    /* begin transaction */
    if ((r = txn_begin(dbenv, NULL, &tid, 0)) != 0) {
	syslog(LOG_ERR, "DBERROR: error beginning txn: %s", db_strerror(r));
	return IMAP_IOERROR;
    }

    /* Check for request to delete a user:
       user.<x> with no dots after it */
    if (!strncmp(name, "user.", 5) && !strchr(name+5, '.')) {
	/* Can't DELETE INBOX (your own inbox) */
	if (!strcmp(name+5, userid)) {
	    r = IMAP_MAILBOX_NOTSUPPORTED;
	    goto done;
	}

	/* Only admins may delete user */
	if (!isadmin) { r = IMAP_PERMISSION_DENIED; goto done; }

	r = mboxlist_lookup_writelock(name, NULL, &acl, tid);
	switch (r) {
	case 0:
	    break;
	case DB_LOCK_DEADLOCK:
	    goto retry;	  
	    break;
	default:
	    goto done;
	    break;
	}
	
	/* Check ACL before doing anything stupid
	 * We don't have to lie about the error code since we know
	 * the user is an admin.
	 */
	if (checkacl &&
	    (!(acl_myrights(auth_state, acl) & ACL_CREATE))) {
	    r = IMAP_PERMISSION_DENIED;
	    goto done;
	}
	
	deleteuser = 1;
    }

    key.data = name;
    key.size = strlen(name);
    r = mbdb->get(mbdb, tid, &key, &data, DB_RMW);
    if (!r) {
	int sz;

	mboxent = data.data;
	isremote = (mboxent->mbtype & MBTYPE_REMOTE);
	sz = sizeof(struct mbox_entry) + strlen(mboxent->acls);
	mboxent = (struct mbox_entry *) xmalloc(sz);
	memcpy(mboxent, data.data, sz);
    }
    switch (r) {
    case 0:
	break;
    case DB_LOCK_DEADLOCK:
	goto retry;
	break;
    case DB_NOTFOUND:
	r = IMAP_MAILBOX_NONEXISTENT;
	goto done;
    default:
	syslog(LOG_ERR, "DBERROR: error fetching entry: %s", db_strerror(r));
	r = IMAP_IOERROR;
	goto done;
    }

    /* check if user has Delete right */
    access = acl_myrights(auth_state, mboxent->acls);
    if (checkacl && !(access & ACL_CREATE)) {
	/* User has admin rights over their own mailbox namespace */
	if (mboxname_userownsmailbox(userid, name)) {
	    isadmin = 1;
	}

	/* Lie about error if privacy demands */
	r = (isadmin || (access & ACL_LOOKUP)) ?
	  IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	goto done;
    }

    /* delete entry */
    key.data = name;
    key.size = strlen(name);
    r = mbdb->del(mbdb, tid, &key, 0);
    switch(r) {
    case 0: /* success */
	break;
    case DB_LOCK_DEADLOCK:
	goto retry;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error deleting %s: %s",
	       name, db_strerror(r));
	r = IMAP_IOERROR;
	goto done;
	break;
    }

    if (isremote) goto done;

    r = mboxlist_getpath(mboxent->partition, mboxent->name, &path);
    if (!r) r = mailbox_open_header_path(mboxent->name, path, 
					 mboxent->acls, 0, &mailbox, 0);

    /*
     * See if we have to remove mailbox's quota root
     *
     * NB: this doesn't catch all cases.  We don't handle removing
     * orphaned quota roots on renaming or when inside the
     * ``if (deleteuser)'' code above.
     */
    if (!r && mailbox.quota.root != NULL) {
	/* if the mailbox has a quota root */
	DBC *cursor;      
	struct mbox_entry *mboxent2 = NULL;
	int mailboxqrlen = strlen(mailbox.quota.root);
	int r2;
	
	r = mbdb->cursor(mbdb, tid, &cursor, 0);
	if (r) { 
	    syslog(LOG_ERR, "DBERROR: unable to create cursor in delete");
	    goto done;
	}
	
	memset(&data, 0, sizeof(data));
	memset(&key, 0, sizeof(key));
	key.data = mailbox.quota.root; 
	key.size = mailboxqrlen;
	
	r = cursor->c_get(cursor, &key, &data, DB_SET_RANGE);
	
	switch (r) {
	case 0:
	    mboxent2 = (struct mbox_entry *) data.data;
	    
	    /* if this entry is not in the quota root then we can 
	       delete the quota root */
	    if (strncmp(mboxent2->name, mailbox.quota.root, mailboxqrlen)) {
		/* mailbox prefix not quotaroot */
		deletequotaroot = 1;
	    } else if (mboxent2->name[mailboxqrlen] != '.' 
		       && mboxent2->name[mailboxqrlen] != '\0') {
		/* mailbox prefix not a hierarchy level */
		deletequotaroot = 1;
	    } else if (deleteuser && 
		       !strncmp(mailbox.quota.root, "user.", 5) && 
		       !strchr(mailbox.quota.root + 5, '.')) {
		/* we're deleting user.foo and all submailboxes */
		deletequotaroot = 1;
	    }
	    break;
	case DB_NOTFOUND:
	    deletequotaroot = 1;
	    break;
	case DB_LOCK_DEADLOCK:
	    cursor->c_close(cursor);
	    goto retry;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: error advancing: %s", 
		   db_strerror(r));
	    r = IMAP_IOERROR;
	    break;
	}
	
	switch (r2 = cursor->c_close(cursor)) {
	case 0:
	    break;
	case DB_LOCK_DEADLOCK:
	    goto retry;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: couldn't close cursor: %s",
		   db_strerror(r2));
	    break;
	}
    }

  done: /* ALL DATABASE OPERATIONS DONE; NEED TO DO FILESYSTEM OPERATIONS */
    /*
     * See if we have to remove mailbox's quota root
     */
    if (!r && !isremote) {
	r = mboxlist_getpath(mboxent->partition, mboxent->name, &path);
	if (!r) r = mailbox_open_header_path(mboxent->name, path, 
					     mboxent->acls, 0, &mailbox, 0);

	/* remove the mailbox */
	if (!r) r = mailbox_delete(&mailbox, deletequotaroot);
    } /* end !remote */

    if (mboxent) free(mboxent);

    if (r != 0) {
	int r2;

	switch (r2 = txn_abort(tid)) {
	case 0:
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on abort: %s",
		   db_strerror(r2));
	}
	return r;
    } else {
	/* commit now */
	switch (r = txn_commit(tid, 0)) {
	case 0: 
	    if (!isremote) {
		/* open ACAP connection if necessary */
		acaphandle = acapmbox_get_handle();
	    
		/* delete from ACAP */
		r = acapmbox_delete(acaphandle, name);
		if (r) {
		    syslog(LOG_ERR, 
			   "ACAP: can't delete mailbox entry '%s': %s",
			   name, error_message(r));
		}
		acapmbox_release_handle(acaphandle);
	    }
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   db_strerror(r));
	    r = IMAP_IOERROR;
	}
    }

    if (!r && deleteuser) {
	/* Delete any subscription list file */
	char *fname = mboxlist_hash_usersubs(mboxent->name + 5);
	
	(void) unlink(fname);
	free(fname);
    }

    return r;
}

/*
 * Rename/move a mailbox
 *
 * 1. start transaction
 * 2. verify acls
 * 3. open acap connection if needed
 * 4. Delete entry from berkeley db
 * 5. ACAP make the new entry
 * 7. delete from disk
 * 8. commit transaction
 * 9. set new ACAP entry commited
 * 10. delete old ACAP entry
 *
 */
int mboxlist_renamemailbox(char *oldname, char *newname, char *partition, 
				int isadmin, char *userid, 
				struct auth_state *auth_state)
{
    int r;
    long access;
    int isusermbox = 0;
    int mbtype;
    char *oldpath = NULL;
    char newpath[MAX_MAILBOX_PATH];
    struct mailbox newmailbox;
    acapmbox_data_t mboxdata;
    char buf2[MAX_PARTITION_LEN + 30];
    char *oldacl;
    const char *root;
    DB_TXN *tid;
    DBT key, data;
    struct mbox_entry *mboxent = NULL, *newent = NULL;
    char *newpartition = NULL;
    int acap_madenew = 0;
    acapmbox_handle_t *acaphandle = NULL;

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    /* we just can't rename if there isn't enough info */
    if (partition && !strcmp(partition, "news")) {
	return IMAP_MAILBOX_NOTSUPPORTED;
    }

    /* place to retry transaction */
    if (0) {
      retry:
	if ((r = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s",
		   db_strerror(r));
	    return IMAP_IOERROR;
	}
    }

    /* begin transaction */
    if ((r = txn_begin(dbenv, NULL, &tid, 0)) != 0) {
	syslog(LOG_ERR, "DBERROR: error beginning txn: %s", db_strerror(r));
	return IMAP_IOERROR;
    }

    /* lookup the mailbox to make sure it exists and get its acl */
    key.data = oldname;
    key.size = strlen(oldname);
    r = mbdb->get(mbdb, tid, &key, &data, DB_RMW);
    switch (r) {
    case 0:
	mboxent = (struct mbox_entry *) data.data;
	oldacl = mboxent->acls;
	mbtype = mboxent->mbtype;
	r = mboxlist_getpath(mboxent->partition, mboxent->name, &oldpath);
	if (r) {
	    goto done;
	}
	break;
    case DB_LOCK_DEADLOCK:
	goto retry;
	break;
    case DB_NOTFOUND:
	r = IMAP_MAILBOX_NONEXISTENT;
	goto done;
	break;
    default:
	r = IMAP_IOERROR;
	goto done;
	break;
    }

    /* Check ability to delete old mailbox */
    if (!strcmp(oldname, newname) && !(mbtype & MBTYPE_REMOTE)) {
	/* Attempt to move mailbox across partition */
	if (!isadmin || !partition) {	  
	    r = IMAP_MAILBOX_EXISTS;
	    goto done;
	}

	root = config_partitiondir(partition);
	if (!root) {
	    r = IMAP_PARTITION_UNKNOWN;
	    goto done;
	}
	if (!strncmp(root, oldpath, strlen(root)) &&
	    oldpath[strlen(root)] == '/') {
	    /* partitions are the same or share common prefix */
	    r = IMAP_MAILBOX_EXISTS;
	    goto done;
	}
    } else if (!strncmp(oldname, "user.", 5) && !strchr(oldname+5, '.')) {
	if (!strcmp(oldname+5, userid)) {
	    /* Special case of renaming inbox */
	    access = acl_myrights(auth_state, oldacl);
	    if (!(access & ACL_CREATE)) {
	      r = IMAP_PERMISSION_DENIED;
	      goto done;
	    }
	    isusermbox = 1;
	} else {
	    /* Even admins can't rename users */
	    r = IMAP_MAILBOX_NOTSUPPORTED;
	    goto done;
	}
    } else if (mbtype & MBTYPE_NETNEWS) {
	r = IMAP_MAILBOX_NOTSUPPORTED;
	goto done;
    } else {
	access = acl_myrights(auth_state, oldacl);
	if (!(access & ACL_CREATE) && !isadmin) {
	    r = (isadmin || (access & ACL_LOOKUP)) ?
		IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	    goto done;
	}
    }

    /* Check ability to create new mailbox */
    if (strcmp(oldname, newname) != 0) {
	if (!strncmp(newname, "user.", 5) && !strchr(newname+5, '.')) {
	    /* Even admins can't rename to user's inboxes */
	    r = IMAP_MAILBOX_NOTSUPPORTED;
	    goto done;
	}
	r = mboxlist_mycreatemailboxcheck(newname, 0, partition, isadmin, 
					  userid, auth_state, NULL, 
					  &newpartition, DB_RMW, tid);
	switch (r) {
	case 0:
	    break;
	case IMAP_AGAIN:
	    goto retry;
	    break;
	default: /* not allowed to create the new mailbox */
	    goto done;
	    break;
	}
    } else {
	newpartition = xstrdup(partition);
    }

    if (!(mbtype & MBTYPE_REMOTE)) {
	/* Get partition's path */
	sprintf(buf2, "partition-%s", newpartition);
	root = config_getstring(buf2, (char *)0);
	if (!root) {
	    r = IMAP_PARTITION_UNKNOWN;
	    goto done;
	}
    }

    /* 3. open ACAP connection if necessary */
    acaphandle = acapmbox_get_handle();

    if (!isusermbox) {
	/* 4. Delete entry from berkeley db */
	key.data = oldname;
	key.size = strlen(oldname);
	
	r = mbdb->del(mbdb, tid, &key, 0);
	switch (r) {
	case 0: /* success */
	    break;
	case DB_LOCK_DEADLOCK:
	    goto retry;
	    break;
	case DB_NOTFOUND:
	    syslog(LOG_ERR, "DBERROR: error deleting %s from db (NOT FOUND)",
		   newent->name);
	    r = IMAP_IOERROR;
	    goto done;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: error deleting %s: %s",
		   oldname, db_strerror(r));
	    r = IMAP_IOERROR;
	    goto done;
	    break;
	}
    }

    /* create new entry */
    newent = xmalloc(sizeof(struct mbox_entry) + strlen(oldacl));
    strcpy(newent->name, newname);
    strcpy(newent->partition, newpartition);
    newent->mbtype = mbtype;
    strcpy(newent->acls, oldacl);

    /* make the keys */
    key.data = newname;
    key.size = strlen(newname);

    memset(&data, 0, sizeof(data));
    data.data = newent;
    data.size = sizeof(struct mbox_entry) + strlen(oldacl);

    /* put it into the db */
    r = mbdb->put(mbdb, tid, &key, &data, 0);
    switch (r) {
    case 0:
	break;
    case DB_LOCK_DEADLOCK:
	goto retry;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error renaming %s: %s",
	       newent->name, db_strerror(r));
	r = IMAP_IOERROR;
	goto done;
    }

    /* 5. ACAP make the new entry, set as reserved */
    acapmbox_new(&mboxdata, NULL, newname);
    r = acapmbox_create(acaphandle, &mboxdata);
    if (r != ACAP_OK) {
	goto done;
    }
    acap_madenew = 1;

  done: /* ALL DATABASE OPERATIONS DONE; NEED TO DO FILESYSTEM OPERATIONS */
    if (!r && !(newent->mbtype & MBTYPE_REMOTE)) {
	/* Get partition's path */
	sprintf(buf2, "partition-%s", newent->partition);
	root = config_getstring(buf2, (char *)0);

	/* Rename the actual mailbox */
	mailbox_hash_mbox(newpath, root, newname);
	
	r = mailbox_rename(oldname, oldpath, newent->acls, newent->name, 
			   newpath, isusermbox, NULL, NULL, &newmailbox);
	mboxdata.uidvalidity = newmailbox.uidvalidity;
	mboxdata.acl = newent->acls;
	mboxdata.total = newmailbox.exists;
	if (!r) {
	    mailbox_close(&newmailbox);
	}
    }

    if (r != 0) {
	int r2;
	
	/* unroll acap operations if necessary */
	if (acap_madenew == 1) {
	    r2 = acapmbox_delete(acaphandle, newname);
	    if (r2 != 0) {
		syslog(LOG_ERR, "ACAP: can't rollback %s: %s", newname, 
		       error_message(r));
	    }
	}

	txn_abort(tid);
    } else {
	/* commit now */
	switch (r = txn_commit(tid, 0)) {
	case 0: 
	    break;

	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   db_strerror(r));
	    r = IMAP_IOERROR;
	    break;
	}
    }

    if (!r) {
	/* 9. set new ACAP entry commited */
	r = acapmbox_markactive(acaphandle, &mboxdata);
	if (r) syslog(LOG_ERR, "ACAP: can't commit %s: %d", newname, r);
    }

    if (!r && !isusermbox) {
	/* 10. delete old ACAP entry */
	r = acapmbox_delete(acaphandle, oldname);
	if (r) syslog(LOG_ERR, "ACAP: can't delete %s: %d", oldname, r);
    }

    /* free memory */
    if (newpartition) free(newpartition);
    if (newent) free(newent);
    
    return r;
}

/*
 * Change the ACL for mailbox 'name' so that 'identifier' has the
 * rights enumerated in the string 'rights'.  If 'rights' is the null
 * pointer, removes the ACL entry for 'identifier'.   'isadmin' is
 * nonzero if user is a mailbox admin.  'userid' is the user's login id.
 *
 *
 * 1. Start transaction
 * 2. Check rights
 * 3. Open ACAP connection if necessary
 * 4. Set db entry
 * 5. Change on disk
 * 6. Commit transaction
 * 7. Change ACAP entry 
 *
 */
int mboxlist_setacl(char *name, char *identifier, char *rights, 
		    int isadmin, char *userid, 
		    struct auth_state *auth_state)
{
    int useridlen = strlen(userid);
    int r;
    int access;
    int mode = ACL_MODE_SET;
    int isusermbox = 0;
    struct mailbox mailbox;
    int mailbox_isopen;
    char *newacl=NULL;
    char *path;
    DB_TXN *tid;
    DBT key, data;
    struct mbox_entry *oldent = NULL, *newent=NULL;
    acapmbox_handle_t *acaphandle = NULL;

    if (!strncmp(name, "user.", 5) &&
	!strchr(userid, '.') &&
	!strncmp(name+5, userid, useridlen) &&
	(name[5+useridlen] == '\0' || name[5+useridlen] == '.')) {
	isusermbox = 1;
    }

    /* transaction retry point */
    if (0) {
      retry:
	if ((r = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s",
		   db_strerror(r));
	    return IMAP_IOERROR;
	}
    }

    mailbox_isopen = 0;

    /* begin transaction */
    if ((r = txn_begin(dbenv, NULL, &tid, 0)) != 0) {
	syslog(LOG_ERR, "DBERROR: error beginning txn: %s", db_strerror(r));
	return IMAP_IOERROR;
    }

    if (!r) {
	memset(&data, 0, sizeof(data));
	memset(&key, 0, sizeof(key));
	key.data = (char *) name;
	key.size = strlen(name);
    
        r = mbdb->get(mbdb, tid, &key, &data, DB_RMW);
	switch (r) {
	case 0:
	    oldent = (struct mbox_entry *) data.data;
	    break;
	case DB_NOTFOUND:
	    r = IMAP_MAILBOX_NONEXISTENT;
	    goto done;
	    break;
	case DB_LOCK_DEADLOCK:
	    goto retry;
	default:
	    syslog(LOG_ERR, "DBERROR: error fetching %s: %s",
		   name, db_strerror(r));
	    r = IMAP_IOERROR;
	    goto done;
	    break;
	}
    }

    if (!r && !isadmin && !isusermbox) {
	access = acl_myrights(auth_state, oldent->acls);
	if (!(access & ACL_ADMIN)) {
	    r = (access & ACL_LOOKUP) ?
	      IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	    goto done;
	}
    }

    /* 3. Open ACAP connection if necessary */
    acaphandle = acapmbox_get_handle();

    /* Make change to ACL */
    newacl = xstrdup(oldent->acls);
    if (rights) {
	if (*rights == '+') {
	    rights++;
	    mode = ACL_MODE_ADD;
	}
	else if (*rights == '-') {
	    rights++;
	    mode = ACL_MODE_REMOVE;
	}
	
	if (acl_set(&newacl, identifier, mode, acl_strtomask(rights),
		    isusermbox ? mboxlist_ensureOwnerRights : 0,
		    (void *)userid))
	{
	    r = IMAP_INVALID_IDENTIFIER;
	    goto done;
	}
    }
    else {
	if (acl_remove(&newacl, identifier,
		       isusermbox ? mboxlist_ensureOwnerRights : 0,
		       (void *)userid)) {
	  r = IMAP_INVALID_IDENTIFIER;
	  goto done;
	}
    }

    /* ok, make the change */
    newent = (struct mbox_entry *) xmalloc(sizeof(struct mbox_entry) +
					   strlen(newacl));
    memset(newent, 0, sizeof(struct mbox_entry) +
					   strlen(newacl));
    strcpy(newent->name, oldent->name);
    newent->mbtype = oldent->mbtype;
    strcpy(newent->partition, oldent->partition);
    strcpy(newent->acls, newacl);

    memset(&data, 0, sizeof(data));
    data.data = newent;
    data.size = sizeof(struct mbox_entry) + strlen(newacl);

    r = mbdb->put(mbdb, tid, &key, &data, 0);
    switch (r) {
    case 0:
	break;
    case DB_LOCK_DEADLOCK:
	goto retry;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error updating acl %s: %s",
	       newent->name, db_strerror(r));
	r = IMAP_IOERROR;
	goto done;
    }

    if (!(newent->mbtype & MBTYPE_REMOTE)) {
	/* calculate path */
	mboxlist_getpath(newent->partition, newent->name, &path);
	
	/* open & lock mailbox header */
        r = mailbox_open_header_path(newent->name, 
				     path, newent->acls, NULL, 
				     &mailbox, 0);

	if (!r) {
	    r = mailbox_lock_header(&mailbox);
	    if (!r) {
		/* set it in the /var/spool part */
		(void) mailbox_write_header(&mailbox);
	    }
	    mailbox_close(&mailbox);
	}
    }

  done:

    if (newent) free(newent);

    if (r) {
	if ((r = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s",
		   db_strerror(r));
	    r = IMAP_IOERROR;
	}
    } else {
	/* commit now */
	switch (r = txn_commit(tid, 0)) {
	case 0: 
	    /* ACAP: change ACL here */
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   db_strerror(r));
	    r = IMAP_IOERROR;
	}
    }

    /* 7. Change ACAP entry  */
    r = acapmbox_setproperty_acl(acaphandle,
				 name,
				 newacl);
    if (newacl) free(newacl);
    
    return r;
}

/*
 * Find all mailboxes that match 'pattern'.
 * 'isadmin' is nonzero if user is a mailbox admin.  'userid'
 * is the user's login id.  For each matching mailbox, calls
 * 'proc' with the name of the mailbox.  If 'proc' ever returns
 * a nonzero value, mboxlist_findall immediately stops searching
 * and returns that value.  'rock' is passed along as an argument to proc in
 * case it wants some persistant storage or extra data.
 */

/*
 * NOTE!!!
 *
 * Ok this is how we're doing it now. mboxlist_findall does not use
 * transactions, which can make the results a little funky.  We
 * remember where we are so if we hit a deadlock (unlikely?) we can just
 * restart where we left off. This can give results that aren't
 * consistent with the state of the world at any one time---but every
 * mailbox not touched will be listed once and only once.  IMAP has no
 * consistency guarantees on the LIST.
 *
 * Double deletion problem: 1 connection does a list. Another
 * connection deletes 2 mailboxes (mailbox.deleted.1 and
 * mailbox.deleted.2 in that order). The list could (depending on the
 * alphabetical order of the deleted mailboxes) say mailbox.deleted.1
 * exists but mailbox.deleted.2 doesn't. This is weird.
 *
 * Blame Larry if you don't like this solution.
 */

static int cursor_retryget(DBC *cursor, DBT *key, DBT *data, int operation)
{
    int r;

    r = cursor->c_get(cursor, key, data, operation);
    while (r == DB_LOCK_DEADLOCK) {
	switch (r = cursor->c_close(cursor)) {
	case 0:
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: couldn't close cursor: %s",
		   db_strerror(r));
	    goto done;
	}
	switch (r = mbdb->cursor(mbdb, NULL, &cursor, 0)) {
	case 0:
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: couldn't recreate cursor: %s",
		   db_strerror(r));
	    goto done;
	}
	if ((operation | DB_RMW) == (DB_NEXT | DB_RMW)) {
	    /* reset the cursor position */
	    r = cursor->c_get(cursor, key, data, DB_SET);
	    switch (r) {
	    case 0:
		break;
	    case DB_LOCK_DEADLOCK:
		continue;
	    case DB_NOTFOUND:
		r = cursor->c_get(cursor, key, data, DB_SET_RANGE);
		if (r == DB_LOCK_DEADLOCK) continue;
		break;
	    }
	}
	r = cursor->c_get(cursor, key, data, operation);
    }
 done:
    return r;
}

int mboxlist_findall(char *pattern, int isadmin, char *userid,
		     struct auth_state *auth_state,
		     int (*proc)(), void *rock)
{
    char inboxbuf[MAX_MAILBOX_NAME + 1], 
	usermboxname[MAX_MAILBOX_NAME + 1];
    int usermboxnamelen = 0;
    unsigned long prefixlen = 0;
    int r;
    struct glob *g = NULL;
    char *p;
    DBT key, data;
    DBC *cursor = NULL;
    struct mbox_entry *mboxent;

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    g = glob_init(pattern, GLOB_HIERARCHY | GLOB_INBOXCASE);
    
    if (userid && !strchr(userid, '.') && 
	strlen(userid) + 5 < MAX_MAILBOX_NAME) {
	strcpy(usermboxname, "user.");
	strcat(usermboxname, userid);
	usermboxnamelen = strlen(usermboxname);
    } else {
	userid = NULL;
    }

    /* Find fixed-string pattern prefix */
    for (p = pattern; *p; p++) {
	if (*p == '*' || *p == '%' || *p == '?') break;
    }
    prefixlen = p - pattern;
    *p = '\0';

    r = mbdb->cursor(mbdb, NULL, &cursor, 0);
    if (r != 0) { 
	syslog(LOG_ERR, "DBERROR: Unable to create cursor");
	goto done;
    }

    if (userid != NULL) {
	/* first find all personal mailboxes */
	if (!strncasecmp("inbox", pattern, prefixlen < 5 ? prefixlen : 5)) {
	    int i;

	    strcpy(inboxbuf, glob_inboxcase(g));
	    /* make inboxbuf match pattern's case */
	    for (i = 0; i < (prefixlen > 5 ? 5 : prefixlen); i++)
		inboxbuf[i] = pattern[i];
	} else if (!strncmp(pattern, usermboxname, usermboxnamelen)) {
	    /* we require "user.X" to appear in the glob to match
               personal mailboxes for user X */
	    strcpy(inboxbuf, usermboxname);
	} else {
	    /* this doesn't match personal mailboxes */
	    inboxbuf[0] = '\0';
	}
    }
    if (userid != NULL && inboxbuf[0]) {
	key.data = usermboxname;
	key.size = strlen(usermboxname);
	
	/* find out if INBOX exists */
	r = cursor_retryget(cursor, &key, &data, DB_SET);
	while (r != DB_NOTFOUND) {
	    long minmatch;

	    switch (r) {
	    case 0:
		break;
	    default:
		syslog(LOG_ERR, "DBERROR: error fetching %s: %s",
		       usermboxname, db_strerror(r));
		r = IMAP_IOERROR;
		goto done;
	    }
	    mboxent = (struct mbox_entry *) data.data;

	    /* make sure it's a personal mailbox */
	    if (strncmp(mboxent->name, usermboxname, usermboxnamelen)) break;
	    if (mboxent->name[usermboxnamelen] != '\0' &&
		mboxent->name[usermboxnamelen] != '.') break;

	    minmatch = 0;
	    while (minmatch >= 0) {
		char namebuf[MAX_MAILBOX_NAME+1];
		unsigned long namelen;
		long matchlen;
		
		strcpy(namebuf, inboxbuf);
		strcat(namebuf, mboxent->name + usermboxnamelen);
		namelen = strlen(namebuf);
		
		matchlen = glob_test(g, namebuf, namelen, &minmatch);
		if (matchlen == -1) { break; }

		r = proc(namebuf, matchlen, 1, rock);
		if (r) goto done;
	    }

	    r = cursor_retryget(cursor, &key, &data, DB_NEXT);
	}
    }


    /* search for all remaining mailboxes; start at the pattern prefix */
    if (prefixlen) {
	key.data = pattern;
	key.size = prefixlen;
	
	r = cursor_retryget(cursor, &key, &data, DB_SET_RANGE);
    } else {
	r = cursor_retryget(cursor, &key, &data, DB_FIRST);
    }

    /* iterate over all mailboxes matching prefix */
    while (r != DB_NOTFOUND) {
	char *name;
	unsigned long namelen;
	long minmatch;

	switch (r) {
	case 0:
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: error advancing: %s", db_strerror(r));
	    r = IMAP_IOERROR;
	    goto done;
	}
	
	mboxent = (struct mbox_entry *) data.data;
	name = mboxent->name;
	namelen = key.size;
	
	/* does this match our prefix? */
	if (strncmp(name, pattern, prefixlen)) break;

	/* does it match the glob? */
	minmatch = 0;
	while (minmatch >= 0) {
	    long matchlen = glob_test(g, name, namelen, &minmatch);
	    char namebuf[MAX_MAILBOX_NAME+1];

	    if (matchlen == -1 ||
		(userid && namelen >= usermboxnamelen &&
		 strncmp(name, usermboxname, usermboxnamelen) == 0 &&
		 (namelen == usermboxnamelen ||
		  name[usermboxnamelen] == '.'))) {
		/* we didn't match
		        OR
		   this is one of my personal mailboxes & 
		   we already listed it */
		break;
	    }

	    strcpy(namebuf, name);

	    if (isadmin) {
		r = proc(namebuf, matchlen, 1, rock);
		if (r) goto done;
	    } else {
		int rights = acl_myrights(auth_state, mboxent->acls);
		if (rights & ACL_LOOKUP) {
		    r = proc(namebuf, matchlen, (rights & ACL_CREATE), rock);
		    if (r) goto done;
		}
	    }
	}
	
	r = cursor_retryget(cursor, &key, &data, DB_NEXT);
    }
    /* normal case; DB_NOTFOUND or we stopped matching */
    r = 0;

 done:
    if (cursor) {
	int r2;

	switch (r2 = cursor->c_close(cursor)) {
	case 0:
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: couldn't close cursor: %s",
		   db_strerror(r2));
	    break;
	}
    }

    if (g) glob_free(&g);
   
    return r;
}

/*
 * Set the quota on or create a quota root
 */
int mboxlist_setquota(const char *root, int newquota)
{
    char quota_path[MAX_MAILBOX_PATH];
    char pattern[MAX_MAILBOX_PATH];
    struct quota quota;
    static struct quota zeroquota;
    int r;
    unsigned long len = 0;

    if (!root[0] || root[0] == '.' || strchr(root, '/')
	|| strchr(root, '*') || strchr(root, '%') || strchr(root, '?')) {
	return IMAP_MAILBOX_BADNAME;
    }
    
    quota = zeroquota;

    quota.root = (char *) root;
    mailbox_hash_quota(quota_path, root);

    if ((quota.fd = open(quota_path, O_RDWR, 0)) != -1) {
	/* Just lock and change it */
	r = mailbox_lock_quota(&quota);

	quota.limit = newquota;

	if (!r) r = mailbox_write_quota(&quota);
	if (quota.fd != -1) {
	    close(quota.fd);
	}
	return r;
    }

    /*
     * Have to create a new quota root
     */

    {
	DBC *cursor = NULL;
	struct mbox_entry *mboxent = NULL;
	DBT key, data;
	int r2;
	
	r = mbdb->cursor(mbdb, NULL, &cursor, 0);
	if (r != 0) { 
	    syslog(LOG_ERR, "DBERROR: couldn't create cursor in createqr: %s",
		   db_strerror(r));
	    return r;
	}
	
	memset(&data, 0, sizeof(data));
	memset(&key, 0, sizeof(key));
	key.data = quota.root; 
	key.size = strlen(quota.root);

	/* look for a mailbox in the proposed quotaroot */
	r = cursor->c_get(cursor, &key, &data, DB_SET_RANGE);
	switch (r) {
	case 0:
	    mboxent = (struct mbox_entry *) data.data;
	    
	    if ( strlen(mboxent->name) < strlen(quota.root)) {
		/* found mailbox shorter than qr name */
		r = IMAP_MAILBOX_NONEXISTENT;
	    } else if (strncmp(mboxent->name, quota.root, 
			       strlen(quota.root)) != 0) {
		/* the prefix of the mailbox doesn't match the qr */
		r = IMAP_MAILBOX_NONEXISTENT;
	    } else if (strlen(mboxent->name) > strlen(quota.root) &&
		       (mboxent->name[ strlen(quota.root) ] != '.')) {
		/* the prefix matches, but it's not a seperator */
		r = IMAP_MAILBOX_NONEXISTENT;
	    }
	    break;
	    
	case DB_NOTFOUND:
	    /* no mailbox */
	    r = IMAP_MAILBOX_NONEXISTENT;
	    break;
	    
	default:
	    syslog(LOG_ERR, "DBERROR: error search for mbox: %s", 
		   db_strerror(r));
	    r = IMAP_IOERROR;
	    break;
	}
	
	switch (r2 = cursor->c_close(cursor)) {
	case 0:
	    if (r != 0) {
		/* cursor close is ok, but don't create the qr */
		return r;
	    }
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: couldn't close cursor: %s",
		   db_strerror(r2));
	    return IMAP_IOERROR;
	    break;
	}
    }

    /* perhaps create .NEW, lock, check if it got recreated, move in place */
    quota.lock_count = 1;
    quota.used = 0;
    quota.limit = newquota;
    r = mailbox_write_quota(&quota);

    if (r) {
	return r;
    }

    strcpy(pattern, quota.root);
    strcat(pattern, ".*");
    mboxlist_newquota = &quota;
    
    if (len) {
	mboxlist_changequota(quota.root, 0, 0);
    }
    mboxlist_findall(pattern, 1, 0, 0, mboxlist_changequota, NULL);
    
    r = mailbox_write_quota(&quota);
    if (quota.fd != -1) {
	close(quota.fd);
    }

    return r;
}

/*
 * Retrieve internal information, for reconstructing mailboxes file
 */
void mboxlist_getinternalstuff(const char **listfnamep,
			       const char **newlistfnamep, 
			       const char **basep,
			       unsigned long * sizep)
{
    printf("yikes! don't reconstruct me!\n");
    abort();
}

/* Case-dependent comparison converter.
 * Treats \r and \t as end-of-string and treats '.' lower than
 * everything else.
 */
#define TOCOMPARE(c) (convert_to_compare[(unsigned char)(c)])
static unsigned char convert_to_compare[256] = {
    0x00, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x01, 0x01, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x02, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

__inline__ static int MIN(int a, int b)
{
    if (a < b) {
	return a;
    } else {
	return b;
    }
}

static int mbdb_order(const DBT *a, const DBT *b)
{
    char *s1 = a->data;
    char *s2 = b->data;
    int cmp;
    int i, m;

    m = MIN(a->size, b->size);
    i = 0;
    for (i = 0; i < m; i++) {
        cmp = TOCOMPARE(s1[i]) - TOCOMPARE(s2[i]);
        if (cmp) return cmp;
    }
    if (i == a->size) {
	if (i == b->size) {
	    return 0;
	}
        /* s1 is shorter than s2 */
        return -1;
    }
    /* s2 is shorter than s1 */
    return 1;
}



/*
 * ACL access canonicalization routine which ensures that 'owner'
 * retains lookup, administer, and create rights over a mailbox.
 */
int mboxlist_ensureOwnerRights(rock, identifier, access)
void *rock;
const char *identifier;
int access;
{
    char *owner = (char *)rock;
    if (strcmp(identifier, owner) != 0) return access;
    return access|ACL_LOOKUP|ACL_ADMIN|ACL_CREATE;
}

/*
 * Helper function to change the quota root for 'name' to that pointed
 * to by the static global struct pointer 'mboxlist_newquota'.
 */
static int
mboxlist_changequota(name, matchlen, maycreate)
char *name;
int matchlen;
int maycreate;
{
    int r;
    struct mailbox mailbox;

    r = mailbox_open_header(name, 0, &mailbox);
    if (r) goto error_noclose;

    r = mailbox_lock_header(&mailbox);
    if (r) goto error;

    r = mailbox_open_index(&mailbox);
    if (r) goto error;

    r = mailbox_lock_index(&mailbox);
    if (r) goto error;

    if (mailbox.quota.root) {
	if (strlen(mailbox.quota.root) >= strlen(mboxlist_newquota->root)) {
	    /* Part of a child quota root */
	    mailbox_close(&mailbox);
	    return 0;
	}

	r = mailbox_lock_quota(&mailbox.quota);
	if (r) goto error;
	if (mailbox.quota.used >= mailbox.quota_mailbox_used) {
	    mailbox.quota.used -= mailbox.quota_mailbox_used;
	}
	else {
	    mailbox.quota.used = 0;
	}
	r = mailbox_write_quota(&mailbox.quota);
	if (r) {
	    syslog(LOG_ERR,
		   "LOSTQUOTA: unable to record free of %u bytes in quota %s",
		   mailbox.quota_mailbox_used, mailbox.quota.root);
	}
	mailbox_unlock_quota(&mailbox.quota);
	free(mailbox.quota.root);
    }

    mailbox.quota.root = xstrdup(mboxlist_newquota->root);
    r = mailbox_write_header(&mailbox);
    if (r) goto error;

    mboxlist_newquota->used += mailbox.quota_mailbox_used;
    mailbox_close(&mailbox);
    return 0;

 error:
    mailbox_close(&mailbox);
 error_noclose:
    syslog(LOG_ERR, "LOSTQUOTA: unable to change quota root for %s to %s: %s",
	   name, mboxlist_newquota->root, error_message(r));
    
    return 0;
}

void db_panic(DB_ENV *dbenv, int errno)
{
    syslog(LOG_CRIT, "DBERROR: critical database situation");
    /* but don't bounce mail */
    exit(EC_TEMPFAIL);
}

static void db_err(const char *db_prfx, char *buffer)
{
    syslog(LOG_ERR, "DBERROR %s: %s", db_prfx, buffer);
}

void mboxlist_init(int myflags)
{
    int r;
    int flags = 0;
    char dbdir[1024];

    assert (!mboxlist_dbinit);

    if (myflags & MBOXLIST_RECOVER) flags |= DB_RECOVER;

    if ((r = db_env_create(&dbenv, 0)) != 0) {
	char err[1024];
	    
	sprintf(err, "DBERROR: db_appinit failed: %s", db_strerror(r));
	    
	syslog(LOG_ERR, err);
	fatal(err, EC_TEMPFAIL);
    }

    dbenv->set_paniccall(dbenv, (void (*)(DB_ENV *, int)) &db_panic);

    dbenv->set_verbose(dbenv, DB_VERB_DEADLOCK, 1);
    dbenv->set_verbose(dbenv, DB_VERB_WAITSFOR, 1);
    dbenv->set_verbose(dbenv, DB_VERB_CHKPOINT, 1);
    dbenv->set_errpfx(dbenv, "mbdb");
    dbenv->set_lk_detect(dbenv, CONFIG_DEADLOCK_DETECTION);
    dbenv->set_lk_max(dbenv, 10000);
    dbenv->set_errcall(dbenv, db_err);

    /*
     * We want to specify the shared memory buffer pool cachesize,
     * but everything else is the default.
     */
    if ((r = dbenv->set_cachesize(dbenv, 0, 64 * 1024, 0)) != 0) {
	dbenv->err(dbenv, r, "set_cachesize");
	dbenv->close(dbenv, 0);
	fatal("DBERROR: set_cachesize()", EC_TEMPFAIL);
    }

    /* create the name of the db file */
    strcpy(dbdir, config_dir);
    strcat(dbdir, FNAME_DBDIR);
    flags |= DB_CREATE | DB_INIT_LOCK | DB_INIT_MPOOL | 
	     DB_INIT_LOG | DB_INIT_TXN;
#if DB_VERSION_MINOR > 0
    r = dbenv->open(dbenv, dbdir, flags, 0644); 
#else
    r = dbenv->open(dbenv, dbdir, NULL, flags, 0644); 
#endif
    if (r) {
	char err[1024];
	    
	sprintf(err, "DBERROR: dbenv->open '%s' failed: %s", dbdir,
		db_strerror(r));
	syslog(LOG_ERR, err);
	fatal(err, EC_TEMPFAIL);
    }

    if (myflags & MBOXLIST_SYNC) {
	do {
#if DB_VERSION_MINOR > 0
	    r = txn_checkpoint(dbenv, 0, 0, 0);
#else
	    r = txn_checkpoint(dbenv, 0, 0);
#endif
	} while (r == DB_INCOMPLETE);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: couldn't checkpoint: %s",
		   db_strerror(r));
	}
    }

    mboxlist_dbinit = 1;

    r = acap_init();
    if (r != ACAP_OK) {
	syslog(LOG_ERR,"acap_init failed()");
    }
}

void mboxlist_open(char *fname)
{
    int ret;
    char *tofree = NULL;

    assert (mboxlist_dbinit);

    /* create db file name */
    if (!fname) {
	fname = xmalloc(strlen(config_dir)+sizeof(FNAME_MBOXLIST));
	tofree = fname;
	strcpy(fname, config_dir);
	strcat(fname, FNAME_MBOXLIST);
    }

    ret = db_create(&mbdb, dbenv, 0);
    if (ret != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
	       db_strerror(ret));
	    /* Exiting TEMPFAIL because Sendmail thinks this
	       EC_OSFILE == permanent failure. */
	fatal("db_create() failed", EC_TEMPFAIL);
    }    
    mbdb->set_bt_compare(mbdb, &mbdb_order);
    /* mbdb->set_bt_prefix(mbdb, &mbdb_prefix);*/

    ret = mbdb->open(mbdb, fname, NULL, DB_BTREE, DB_CREATE, 0664);
    if (ret != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
	       db_strerror(ret));
	    /* Exiting TEMPFAIL because Sendmail thinks this
	       EC_OSFILE == permanent failure. */
	fatal("can't read mailboxes file", EC_TEMPFAIL);
    }    

    if (tofree) free(tofree);

    mboxlist_dbopen = 1;
}

void
mboxlist_close(void)
{
    int r;

    if (mboxlist_dbopen) {
	r = mbdb->close(mbdb, 0);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing mailboxes: %s",
		   db_strerror(r));
	}
    }
}

void mboxlist_done(void)
{
    int r;

    assert (mboxlist_dbinit);

    r = dbenv->close(dbenv, 0);
    if (r) {
	syslog(LOG_ERR, "DBERROR: error exiting application: %s",
	       db_strerror(r));
    }
    
    mboxlist_dbinit = 0;

    /* finish ACAP API here */
}

/* hash the userid to a file containing the subscriptions for that user */
static char *mboxlist_hash_usersubs(const char *userid)
{
    char *fname = xmalloc(strlen(config_dir) + sizeof(FNAME_USERDIR) +
			  strlen(userid) + sizeof(FNAME_SUBSSUFFIX) + 10);
    char c;

    c = (char) tolower((int) *userid);
    if (!islower((int) c)) {
	c = 'q';
    }
    sprintf(fname, "%s%s%c/%s%s", config_dir, FNAME_USERDIR, c, userid,
	    FNAME_SUBSSUFFIX);

    return fname;
}

/*
 * Open the subscription list for 'userid'.
 * 
 * On success, returns zero.
 * On failure, returns an error code.
 */
static int
mboxlist_opensubs(const char *userid,
		  struct db **ret)
{
    int r = 0;
    char *subsfname;
    char inboxname[MAX_MAILBOX_NAME+1];

    /* Users without INBOXes may not keep subscriptions */
    if (strchr(userid, '.') || strlen(userid) + 6 > MAX_MAILBOX_NAME) {
	return IMAP_PERMISSION_DENIED;
    }
    strcpy(inboxname, "user.");
    strcat(inboxname, userid);
    if (mboxlist_lookup(inboxname, NULL, NULL, NULL) != 0) {
	return IMAP_PERMISSION_DENIED;
    }

    /* Build subscription list filename */
    subsfname = mboxlist_hash_usersubs(userid);
    r = SUBDB->open(subsfname, ret);
    if (r != CYRUSDB_OK) {
	r = IMAP_IOERROR;
    }
    free(subsfname);

    return r;
}

/*
 * Close a subscription file
 */
static void mboxlist_closesubs(struct db *sub)
{
    SUBDB->close(sub);
}

struct findsub_rock {
    struct glob *g;
    int inboxsubs;
    int inboxoffset;
    const char *inboxcase;
    const char *usermboxname;
    int usermboxnamelen;
    int force;
    int (*proc)(char *, int, int, void *rock);
    void *procrock;
};

static int findsub_cb(void *rockp, 
		      const char *key, int keylen,
		      const char *data, int datalen)
{
    char namebuf[MAX_MAILBOX_NAME+1];
    char namematchbuf[MAX_MAILBOX_NAME+1];
    struct findsub_rock *rock = (struct findsub_rock *) rockp;
    int r = 0;
    long minmatch;
    struct glob *g = rock->g;

    /* foreach match, do this test */
    minmatch = 0;
    while (minmatch >= 0) {
	long matchlen;

	memcpy(namebuf, key, keylen);
	namebuf[keylen] = '\0';
	strcpy(namematchbuf, namebuf);
	
	if (!rock->inboxsubs && rock->usermboxname &&
	    !strncmp(namebuf, rock->usermboxname, rock->usermboxnamelen)) {
	    /* this would've been output with the inbox stuff, so skip it */
	    return 0;
	}

	if (rock->inboxoffset) {
	    namematchbuf[rock->inboxoffset] = rock->inboxcase[0];
	    namematchbuf[rock->inboxoffset+1] = rock->inboxcase[1];
	    namematchbuf[rock->inboxoffset+2] = rock->inboxcase[2];
	    namematchbuf[rock->inboxoffset+3] = rock->inboxcase[3];
	    namematchbuf[rock->inboxoffset+4] = rock->inboxcase[4];
	}
	
	matchlen = glob_test(g, namematchbuf+rock->inboxoffset,
			     keylen-rock->inboxoffset, &minmatch);
	if (matchlen == -1) break;
	
      	/* make sure it's in the mailboxes db */
	if (!rock->force) {
	    r = mboxlist_lookup(namebuf, NULL, NULL, NULL);
	} else {
	    r = 0;		/* don't bother checking */
	}
	switch (r) {
	case 0:
	    /* found the entry; output it */
	    r = (*rock->proc)(namematchbuf+rock->inboxoffset, matchlen, 
			      1, rock->procrock);
	    break;
	    
	case DB_NOTFOUND:
	    /* didn't find the entry */
	    break;

	default:
	    syslog(LOG_ERR, "DBERROR: error fetching %s: %s",
		   namebuf, db_strerror(r));
	    r = IMAP_IOERROR;
	}

	if (r) break;
    }

    return r;
}

/*
 * Find subscribed mailboxes that match 'pattern'.
 * 'isadmin' is nonzero if user is a mailbox admin.  'userid'
 * is the user's login id.  For each matching mailbox, calls
 * 'proc' with the name of the mailbox.
 */
int mboxlist_findsub(char *pattern, int isadmin, char *userid, 
		     struct auth_state *auth_state, 
		     int (*proc)(), void *rock, int force)
{
    struct db *subs = NULL;
    struct findsub_rock cbrock;
    char usermboxname[MAX_MAILBOX_NAME+1];
    int usermboxnamelen = 0;
    const char *data;
    int datalen;
    int r = 0;
    char *p;
    int prefixlen;

    /* open the subscription file that contains the mailboxes the 
       user is subscribed to */
    if ((r = mboxlist_opensubs(userid, &subs)) != 0) {
	goto done;
    }

    cbrock.g = glob_init(pattern, GLOB_HIERARCHY|GLOB_INBOXCASE);
    cbrock.inboxcase = glob_inboxcase(cbrock.g);
    cbrock.usermboxname = usermboxname;
    cbrock.force = force;
    cbrock.proc = proc;
    cbrock.procrock = rock;

    /* Build usermboxname */
    if (userid && !strchr(userid, '.') &&
	strlen(userid)+5 < MAX_MAILBOX_NAME) {
	strcpy(usermboxname, "user.");
	strcat(usermboxname, userid);
	cbrock.usermboxnamelen = usermboxnamelen = strlen(usermboxname);
    }
    else {
	userid = 0;
    }

    /* Check for INBOX first of all */
    if (userid) {
	if (GLOB_TEST(cbrock.g, "INBOX") != -1) {
	    r = SUBDB->fetch(subs, usermboxname, usermboxnamelen,
			     &data, &datalen, NULL);
	    if (!r && data) {
		r = (*proc)(cbrock.inboxcase, 5, 1, rock);
	    }
	}
	else if (!strncmp(pattern, usermboxname, usermboxnamelen) &&
		 GLOB_TEST(cbrock.g, usermboxname) != -1) {
	    r = SUBDB->fetch(subs, usermboxname, usermboxnamelen,
			     &data, &datalen, NULL);
	    if (!r && data) {
		r = (*proc)(cbrock.inboxcase, 5, 1, rock);
	    }
	}
	strcpy(usermboxname+usermboxnamelen, ".");
	usermboxnamelen++;
    }

    if (r) goto done;

    /* Find fixed-string pattern prefix */
    for (p = pattern; *p; p++) {
	if (*p == '*' || *p == '%' || *p == '?') break;
    }
    prefixlen = p - pattern;
    *p = '\0';

    /*
     * If user.X.* or INBOX.* can match pattern,
     * search for those mailboxes next
     */
    if (userid &&
	(!strncmp(usermboxname, pattern, usermboxnamelen-1) ||
	 !strncasecmp("inbox.", pattern, prefixlen < 6 ? prefixlen : 6))) {

	if (!strncmp(usermboxname, pattern, usermboxnamelen-1)) {
	    cbrock.inboxoffset = 0;
	}
	else {
	    cbrock.inboxoffset = strlen(userid);
	}

	cbrock.inboxsubs = 1;
	/* iterate through prefixes matching usermboxname */
	SUBDB->foreach(subs,
		       usermboxname, usermboxnamelen,
		       &findsub_cb, &cbrock,
		       NULL);
    }

    cbrock.inboxsubs = 0;
    cbrock.inboxoffset = 0;
    /* search for all remaining mailboxes.
       just bother looking at the ones that have the same pattern prefix. */
    SUBDB->foreach(subs,
		   pattern, prefixlen,
		   &findsub_cb, &cbrock,
		   NULL);

  done:
    if (subs) mboxlist_closesubs(subs);
    glob_free(&cbrock.g);

    return r;
}

/*
 * Change 'user's subscription status for mailbox 'name'.
 * Subscribes if 'add' is nonzero, unsubscribes otherwise.
 * if 'force' is set, force the subscription through even if
 * we don't know about 'name'.
 */
int mboxlist_changesub(const char *name, const char *userid, 
		       struct auth_state *auth_state, int add, int force)
{
    int r;
    char *acl;
    struct db *subs;
    
    if ((r = mboxlist_opensubs(userid, &subs)) != 0) {
	return r;
    }

    if (add && !force) {
	/* Ensure mailbox exists and can be either seen or read by user */
	if ((r = mboxlist_lookup(name, NULL, &acl, NULL))!=0) {
	    mboxlist_closesubs(subs);
	    return r;
	}
	if ((acl_myrights(auth_state, acl) & (ACL_READ|ACL_LOOKUP)) == 0) {
	    mboxlist_closesubs(subs);
	    return IMAP_MAILBOX_NONEXISTENT;
	}
    }

    if (add) {
	r = SUBDB->store(subs, name, strlen(name), "", 0, NULL);
    } else {
	r = SUBDB->delete(subs, name, strlen(name), NULL);
	/* if it didn't exist, that's ok */
	if (r == CYRUSDB_EXISTS) r = CYRUSDB_OK;
    }

    switch (r) {
    case CYRUSDB_OK:
	r = 0;
    default:
	r = IMAP_IOERROR;
    }

    mboxlist_closesubs(subs);
    return r;
}
