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
 * $Id: mboxlist.c,v 1.139 2000/10/12 19:10:43 leg Exp $
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

#define DB CONFIG_DB_MBOX
#define SUBDB CONFIG_DB_SUBS

acl_canonproc_t mboxlist_ensureOwnerRights;

struct db *mbdb;

static int mboxlist_dbopen = 0;

static int mboxlist_opensubs();
static void mboxlist_closesubs();

static struct quota *mboxlist_newquota;
static int mboxlist_changequota();

static char *mboxlist_hash_usersubs(const char *userid);

#define FNAME_SUBSSUFFIX ".sub"

static int delete_user(const char *user)
{
    /* delete seen state */

    /* delete subscriptions */
    char *fname = mboxlist_hash_usersubs(user);
	
    (void) unlink(fname);
    free(fname);

    return 0;
}

/*
 * Convert a partition into a path
 */
static int mboxlist_getpath(const char *partition, const char *name, 
			    char **pathp)
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

char *mboxlist_makeentry(int mbtype, char *part, char *acl)
{
    char *mboxent = (char *) xmalloc(sizeof(char) * 
				     (30 + strlen(acl) + strlen(part)));
    sprintf(mboxent, "%d %s %s", mbtype, part, acl);
    return mboxent;
}

/*
 * Lookup 'name' in the mailbox list.
 * The capitalization of 'name' is canonicalized to the way it appears
 * in the mailbox list.
 * If 'path' is non-nil, a pointer to the full pathname of the mailbox
 * is placed in the char * pointed to by it.  If 'acl' is non-nil, a pointer
 * to the mailbox ACL is placed in the char * pointed to by it.
 */
static int mboxlist_mylookup(const char *name, int *typep,
			     char **pathp, char **partp,
			     char **aclp, 
			     struct txn **tid, int wrlock)
{
    int acllen;
    static char partition[MAX_PARTITION_LEN];
    static char *aclresult;
    static int aclresultalloced;
    int r;
    const char *data;
    char *p, *q;
    int datalen;
    int namelen;
    int mbtype;

    namelen = strlen(name);

    if (namelen == 0) {
	return IMAP_MAILBOX_NONEXISTENT;
    }
    if (wrlock) {
	r = DB->fetchlock(mbdb, name, namelen, &data, &datalen, tid);
    } else {
	r = DB->fetch(mbdb, name, namelen, &data, &datalen, tid);
    }
    switch (r) {
    case CYRUSDB_OK:
	if (data == NULL) {
	    return IMAP_MAILBOX_NONEXISTENT;
	    break;
	}

	/* copy out interesting parts */
	mbtype = strtol(data, &p, 10);
	if (typep) *typep = mbtype;

	if (*p == ' ') p++;
	q = partition;
	while (*p != ' ') {	/* copy out partition name */
	    *q++ = *p++;
	}
	*q = '\0';
	p++;

	if (partp) {
	    *partp = partition;
	}

	/* construct pathname if requested */
	if (pathp) {
	    if (mbtype & MBTYPE_REMOTE) {
		*pathp = partition;
	    } else {
		r = mboxlist_getpath(partition, name, pathp);
		if (r) {
		    return r;
		}
	    }
	}

	/* the rest is ACL; return it if requested */
	if (aclp) {
	    acllen = datalen - (p - data);
	    if (acllen >= aclresultalloced) {
		aclresultalloced = acllen + 100;
		aclresult = xrealloc(aclresult, aclresultalloced);
	    }
	    memcpy(aclresult, p, acllen);
	    aclresult[acllen] = '\0';

	    *aclp = aclresult;
	}
	break;

    case CYRUSDB_AGAIN:
	return IMAP_AGAIN;
	break;

    default:
	syslog(LOG_ERR, "DBERROR: error fetching %s: %s",
	       name, cyrusdb_strerror(r));
	return IMAP_IOERROR;
	break;
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
int mboxlist_lookup(const char *name, char **pathp, char **aclp, 
		    void *tid __attribute__((unused)))
{
    return mboxlist_mylookup(name, NULL, pathp, NULL, aclp, NULL, 0);
}

int mboxlist_findstage(const char *name, char *stagedir) 
{
    char optionbuf[MAX_MAILBOX_NAME+1];
    const char *root;
    char *partition;
    int r;

    assert(stagedir != NULL);

    /* Find mailbox */
    r = mboxlist_mylookup(name, NULL, NULL, &partition, NULL, NULL, 0);
    switch (r) {
    case 0:
	break;
    default:
	return r;
	break;
    }
	
    strcpy(optionbuf, "partition-");
    strcpy(optionbuf + 10, partition);
    
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
			      int RMW, struct txn **tid)
{
    int r;
    char *p;
    char *acl, *path;
    char *defaultacl, *identifier, *rights;
    char parent[MAX_MAILBOX_NAME+1];
    unsigned long parentlen;
    char *parentname = NULL;
    char *parentpartition = NULL;
    char *parentacl = NULL;
    unsigned long parentpartitionlen = 0;
    unsigned long parentacllen = 0;

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
    r = mboxlist_mylookup(name, NULL, &path, NULL, &acl, tid, RMW);
    switch (r) {
    case 0:
	r = IMAP_MAILBOX_EXISTS;
	
	/* Lie about error if privacy demands */
	if (!isadmin && 
	    !(acl_myrights(auth_state, acl) & ACL_LOOKUP)) {
	    r = IMAP_PERMISSION_DENIED;
	}
	return r;       
	break;
    case IMAP_MAILBOX_NONEXISTENT:
	break;

    default:
	return r;
	break;
    }

    /* Search for a parent */
    strcpy(parent, name);
    parentlen = 0;
    while ((parentlen==0) && (p = strrchr(parent, '.'))) {
	*p = '\0';

	r = mboxlist_mylookup(parent, NULL, NULL, &parentpartition, 
			      &parentacl, tid, 0);
	switch (r) {
	case 0:
	  parentlen = strlen(parent);
	  parentname = parent;

	  parentpartitionlen = strlen(parentpartition);

	  parentacllen = strlen(parentacl);
	  break;

	case IMAP_MAILBOX_NONEXISTENT:
	    break;

	default:
	    return r;
	    break;
	}
    }
    if (parentlen != 0) {
	/* check acl */
	if (!isadmin && !(acl_myrights(auth_state, parentacl) & ACL_CREATE)) {
	    return IMAP_PERMISSION_DENIED;
	}

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

	/* Canonicalize case of parent prefix */
	strlcpy(name, parent, strlen(parent));
    } else { /* parentlen == 0, no parent mailbox */
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
	    /* disallow wildcards in userids with inboxes. */	     
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
 * 1. start mailboxes transaction
 * 2. verify ACL's to best of ability (CRASH: abort)
 * 3. open ACAP connection if necessary
 * 4. verify parent ACL's if need to
 * 5. create ACAP entry and set as reserved (CRASH: ACAP inconsistant)
 * 6. create on disk (CRASH: ACAP inconsistant, disk inconsistant)
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
    char buf[MAX_PARTITION_LEN + 30];
    const char *root = NULL;
    char *newpartition = NULL;
    struct mailbox newmailbox;
    struct txn *tid = NULL;
    char *mboxent = NULL;

    acapmbox_data_t mboxdata;
    int madereserved = 0; /* made reserved entry on ACAP server */
    acapmbox_handle_t *acaphandle = NULL;

 retry:
    tid = NULL;

    /* 2. verify ACL's to best of ability (CRASH: abort) */
    r = mboxlist_mycreatemailboxcheck(name, mbtype, partition, isadmin, 
				      userid, auth_state, 
				      &acl, &newpartition, 1, &tid);
    switch (r) {
    case 0:
	break;
    case IMAP_AGAIN:
	goto retry;
    default:
	goto done;
    }

    if (!(mbtype & MBTYPE_REMOTE)) {
	/* Get partition's path */
	sprintf(buf, "partition-%s", newpartition);
	root = config_getstring(buf, (char *)0);
	if (!root) {
	    r = IMAP_PARTITION_UNKNOWN;
	    goto done;
	}
	if (strlen(root)+strlen(name)+20 > MAX_MAILBOX_PATH) {
	    r = IMAP_MAILBOX_BADNAME;
	    goto done;
	}
    }

    /* 3. open ACAP connection if necessary */
    acaphandle = acapmbox_get_handle();
    
    /* 4. create ACAP entry and set as reserved (CRASH: ACAP inconsistant) */
    acapmbox_new(&mboxdata, NULL, name);
    r = acapmbox_create(acaphandle, &mboxdata);
    if (r) {
	syslog(LOG_ERR, "ACAP: unable to reserve %s: %s\n", name,
	       error_message(r));
	goto done;
    }
    madereserved = 1; /* so we can roll back on failure */
    
    /* 5. add the new entry */
    mboxent = mboxlist_makeentry(mbtype, newpartition, acl);

    r = DB->store(mbdb, name, strlen(name), mboxent, strlen(mboxent),
		  &tid);
    switch (r) {
    case CYRUSDB_OK:
	break;
    case CYRUSDB_AGAIN:
	goto retry;
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error updating database: %s",
	       name, cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	goto done;
    }

 done: /* ALL DATABASE OPERATIONS DONE; NEED TO DO FILESYSTEM OPERATIONS */
    if (!r && !(mbtype & MBTYPE_REMOTE)) {
	/* Create new mailbox and move new mailbox list file into place */
	mailbox_hash_mbox(buf, root, name);
	r = mailbox_create(name, buf, acl, 
			   ((mbtype & MBTYPE_NETNEWS) ?
			    MAILBOX_FORMAT_NETNEWS :
			    MAILBOX_FORMAT_NORMAL), 
			   &newmailbox);
	mboxdata.uidvalidity = newmailbox.uidvalidity;
	mboxdata.acl = acl;
	mboxdata.total = newmailbox.exists;
	if (!r) {
	    mailbox_close(&newmailbox);
	}
    }

    if (r) { /* CREATE failed */ 
	int r2;

	r2 = 0;
	if (tid) r2 = DB->abort(mbdb, tid);
	switch (r2) {
	case 0:
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on abort: %s", 
		   cyrusdb_strerror(r2));
	}

	/* delete ACAP entry if we made it */
	if (madereserved == 1) {
	    r2 = acapmbox_delete(acaphandle, name);
	    if (r2) {
		syslog(LOG_ERR, "ACAP: unable to unreserve %s: %s\n", name, 
		       error_message(r2));
	    }
	}
    } else { /* all is well */
	switch (r = DB->commit(mbdb, tid)) {
	case 0: 
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s", 
		   cyrusdb_strerror(r));
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
    char *mboxent;
    int r = 0;

    assert(name != NULL && host != NULL);

    mboxent = mboxlist_makeentry(mbtype | MBTYPE_REMOTE, host, acl);

    /* database put */
    r = DB->store(mbdb, name, strlen(name), mboxent, strlen(mboxent), NULL);
    switch (r) {
    case CYRUSDB_OK:
	break;
    case CYRUSDB_AGAIN:
	abort(); /* shouldn't happen ! */
	break;
    default:
	syslog(LOG_ERR, "DBERROR: error updating database: %s",
	       name, cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	break;
    }

    free(mboxent);
    
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
    struct txn *tid = NULL;
    int isremote = 0;
    int mbtype;

 retry:
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

	r = mboxlist_mylookup(name, NULL, NULL, NULL, &acl, &tid, 1);
	switch (r) {
	case 0:
	    break;
	case IMAP_AGAIN:
	    goto retry;	  
	    break;
	default:
	    DB->abort(mbdb, tid);
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
	    DB->abort(mbdb, tid);
	    goto done;
	}
	
	deleteuser = 1;
    }

    r = mboxlist_mylookup(name, &mbtype, &path, NULL, &acl, &tid, 1);
    switch (r) {
    case 0:
	break;

    case IMAP_AGAIN:
	goto retry;
	break;

    default:
	DB->abort(mbdb, tid);
	goto done;
    }

    isremote = mbtype & MBTYPE_REMOTE;

    /* check if user has Delete right */
    access = acl_myrights(auth_state, acl);
    if (checkacl && !(access & ACL_CREATE)) {
	/* User has admin rights over their own mailbox namespace */
	if (mboxname_userownsmailbox(userid, name)) {
	    isadmin = 1;
	}

	/* Lie about error if privacy demands */
	r = (isadmin || (access & ACL_LOOKUP)) ?
	  IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	DB->abort(mbdb, tid);
	goto done;
    }

    /* delete entry */
    r = DB->delete(mbdb, name, strlen(name), &tid);
    switch (r) {
    case CYRUSDB_OK: /* success */
	break;
    case CYRUSDB_AGAIN:
	goto retry;
    default:
	syslog(LOG_ERR, "DBERROR: error deleting %s: %s",
	       name, cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	goto done;
    }

    /* commit db operations */
    if (!r) {
	r = DB->commit(mbdb, tid);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
    }

    if (r || isremote) goto done;

    if (!r) r = mailbox_open_header_path(name, path, acl, 0, &mailbox, 0);
    if (!r) r = mailbox_delete(&mailbox, deletequotaroot);
    if (!r) {
	/* open ACAP connection if necessary */
	acapmbox_handle_t *acaphandle = acapmbox_get_handle();
	
	/* delete from ACAP */
	r = acapmbox_delete(acaphandle, name);
	if (r) {
	    syslog(LOG_ERR, 
		   "ACAP: can't delete mailbox entry '%s': %s",
		   name, error_message(r));
	}
	acapmbox_release_handle(acaphandle);
    }

    /*
     * See if we have to remove mailbox's quota root
     */
    if (!r && mailbox.quota.root != NULL) {
	/* look for any other mailboxes in this quotaroot */
    }

    if (!r && deleteuser) {
	/* call the delete user function */
	
	delete_user(name + 5);
    }

 done:
    return r;
}

/*
 * Rename/move a single mailbox (recursive renames are handled at a
 * higher level)
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
 * */

/* note: partition moving should really be moved to another function */
int mboxlist_renamemailbox(char *oldname, char *newname, char *partition, 
			   int isadmin, char *userid, 
			   struct auth_state *auth_state)
{
    int r;
    long access;
    int isusermbox = 0;
    int partitionmove = 0;
    int mbtype;
    char *oldpath = NULL;
    char newpath[MAX_MAILBOX_PATH];
    struct mailbox newmailbox;
    acapmbox_data_t mboxdata;
    char *oldacl;
    const char *root = NULL;
    struct txn *tid = NULL;
    char *newpartition = NULL;
    char *mboxent = NULL;

    int acap_madenew = 0;

 retry:
    /* lookup the mailbox to make sure it exists and get its acl */
    r = mboxlist_mylookup(oldname, &mbtype, &oldpath, NULL, &oldacl, &tid, 1);
    switch (r) {
    case 0:
	break;
    case IMAP_AGAIN:
	goto retry;
    default:
	goto done;
    }

    /* Check ability to delete old mailbox */
    if (!strcmp(oldname, newname) && !(mbtype & MBTYPE_REMOTE)) {
	/* Attempt to move mailbox across partition */
	if (!isadmin || !partition) {	  
	    r = IMAP_MAILBOX_EXISTS;
	    goto done;
	}

	partitionmove = 1;
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
    } else {
	access = acl_myrights(auth_state, oldacl);
	if (!(access & ACL_CREATE) && !isadmin) {
	    r = (isadmin || (access & ACL_LOOKUP)) ?
		IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	    goto done;
	}
    }

    /* Check ability to create new mailbox */
    if (!partitionmove) {
	if (!strncmp(newname, "user.", 5) && !strchr(newname+5, '.')) {
	    /* Even admins can't rename to user's inboxes */
	    r = IMAP_MAILBOX_NOTSUPPORTED;
	    goto done;
	}
	r = mboxlist_mycreatemailboxcheck(newname, 0, partition, isadmin, 
					  userid, auth_state, NULL, 
					  &newpartition, 1, &tid);
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
	root = config_partitiondir(newpartition);
	if (!root) {
	    r = IMAP_PARTITION_UNKNOWN;
	    goto done;
	}
    }

    if (!r && !partitionmove) {
	/* 3. open ACAP connection if necessary */
	acapmbox_handle_t *acaphandle = acapmbox_get_handle();

	/* 5. ACAP make the new entry, set as reserved */
	acapmbox_new(&mboxdata, NULL, newname);
	r = acapmbox_create(acaphandle, &mboxdata);
	if (r != ACAP_OK) {
	    goto done;
	}
	acap_madenew = 1;

	acapmbox_release_handle(acaphandle);
    }

    if (!isusermbox) {
	/* 4. Delete entry from berkeley db */
	r = DB->delete(mbdb, oldname, strlen(oldname), &tid);
	switch (r) {
	case 0: /* success */
	    break;
	case CYRUSDB_AGAIN:
	    goto retry;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: error deleting %s: %s",
		   oldname, cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	    goto done;
	    break;
	}
    }

    /* create new entry */
    mboxent = mboxlist_makeentry(mbtype, newpartition, oldacl);

    /* put it into the db */
    r = DB->store(mbdb, newname, strlen(newname), 
		  mboxent, strlen(mboxent), &tid);
    switch (r) {
    case 0:
	break;
    case CYRUSDB_AGAIN:
	goto retry;
    default:
	syslog(LOG_ERR, "DBERROR: error renaming %s: %s",
	       newname, cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	goto done;
    }

  done: /* ALL DATABASE OPERATIONS DONE; NEED TO DO FILESYSTEM OPERATIONS */
    if (!r && !(mbtype & MBTYPE_REMOTE)) {
	/* Rename the actual mailbox */
	assert(root != NULL); /* from above */
	mailbox_hash_mbox(newpath, root, newname);
	
	r = mailbox_rename(oldname, oldpath, oldacl, newname, 
			   newpath, isusermbox, NULL, NULL, &newmailbox);
	mboxdata.uidvalidity = newmailbox.uidvalidity;
	mboxdata.acl = oldacl;
	mboxdata.total = newmailbox.exists;
	if (!r) {
	    mailbox_close(&newmailbox);
	}
    }

    if (r != 0) {
	int r2 = 0;
	
	if (tid) r2 = DB->abort(mbdb, tid);
	if (r2) {
	    syslog(LOG_ERR, "DBERROR: can't abort: %s", cyrusdb_strerror(r2));
	}
	
	/* unroll acap operations if necessary */
	if (acap_madenew) {
	    acapmbox_handle_t *acaphandle = acapmbox_get_handle();

	    r2 = acapmbox_delete(acaphandle, newname);
	    if (r2) syslog(LOG_ERR, "ACAP: can't rollback %s: %s", newname, 
			   error_message(r));

	    acapmbox_release_handle(acaphandle);
	}

    } else {
	/* commit now */
	switch (r = DB->commit(mbdb, tid)) {
	case 0: 
	    break;

	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	    break;
	}
    }

    if (!r && !partitionmove) {
	acapmbox_handle_t *acaphandle = acapmbox_get_handle();

	r = acapmbox_markactive(acaphandle, &mboxdata);
	if (r) syslog(LOG_ERR, "ACAP: can't commit %s: %s", newname, 
		      error_message(r));

	acapmbox_release_handle(acaphandle);
    }

    if (!r && !partitionmove) {
	acapmbox_handle_t *acaphandle = acapmbox_get_handle();
	
	/* delete old ACAP entry */
	r = acapmbox_delete(acaphandle, oldname);
	if (r) syslog(LOG_ERR, "ACAP: can't delete %s: %s", oldname, 
		      error_message(r));

	acapmbox_release_handle(acaphandle);
    }

    /* free memory */
    if (newpartition) free(newpartition);
    if (mboxent) free(mboxent);
    
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
    char *acl, *newacl = NULL;
    char *partition, *path;
    char *mboxent = NULL;
    int mbtype;
    struct txn *tid = NULL;

    if (!strncmp(name, "user.", 5) &&
	!strchr(userid, '.') &&
	!strncmp(name+5, userid, useridlen) &&
	(name[5+useridlen] == '\0' || name[5+useridlen] == '.')) {
	isusermbox = 1;
    }

 retry:
    /* lookup the mailbox to make sure it exists and get its acl */
    r = mboxlist_mylookup(name, &mbtype, &path, &partition, &acl, &tid, 1);
    switch (r) {
    case 0:
	break;
    case IMAP_AGAIN:
	goto retry;
    default:
	goto done;
    }

    if (!r && !isadmin && !isusermbox) {
	access = acl_myrights(auth_state, acl);
	if (!(access & ACL_ADMIN)) {
	    r = (access & ACL_LOOKUP) ?
	      IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	    goto done;
	}
    }

    /* Make change to ACL */
    newacl = xstrdup(acl);
    if (rights) {
	mode = ACL_MODE_SET;
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
    mboxent = mboxlist_makeentry(mbtype, partition, newacl);

    r = DB->store(mbdb, name, strlen(name), mboxent, strlen(mboxent), &tid);
    switch (r) {
    case 0:
	break;
    case CYRUSDB_AGAIN:
	goto retry;
    default:
	syslog(LOG_ERR, "DBERROR: error updating acl %s: %s",
	       name, cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	goto done;
    }

    if (!(mbtype & MBTYPE_REMOTE)) {
	/* open & lock mailbox header */
        r = mailbox_open_header_path(name, path, acl, NULL, &mailbox, 0);

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
    if (mboxent) free(mboxent);

    if (r) {
	int r2;

	if ((r2 = DB->abort(mbdb, tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s",
		   cyrusdb_strerror(r2));
	    r2 = IMAP_IOERROR;
	}
    } else {
	/* commit now */
	switch (r = DB->commit(mbdb, tid)) {
	case 0: 
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
    }

    /* 7. Change ACAP entry  */
    if (!r) { 
	acapmbox_handle_t *acaphandle = acapmbox_get_handle();
	r = acapmbox_setproperty_acl(acaphandle, name, newacl);
    }
    if (newacl) free(newacl);
    
    return r;
}

struct find_rock {
    struct glob *g;
    int inbox;
    int inboxoffset;
    const char *inboxcase;
    const char *usermboxname;
    int usermboxnamelen;
    int checkmboxlist;
    int isadmin;
    struct auth_state *auth_state;
    int (*proc)(char *, int, int, void *rock);
    void *procrock;
};

/* return non-zero if we like this one */
static int find_p(void *rockp, 
		   const char *key, int keylen)
{
    char namebuf[MAX_MAILBOX_NAME+1];
    char namematchbuf[MAX_MAILBOX_NAME+1];
    struct find_rock *rock = (struct find_rock *) rockp;
    long minmatch;
    struct glob *g = rock->g;

    /* foreach match, do this test */
    minmatch = 0;
    while (minmatch >= 0) {
	long matchlen;

	memcpy(namebuf, key, keylen);
	namebuf[keylen] = '\0';
	strcpy(namematchbuf, namebuf);
	
	if (!rock->inbox && rock->usermboxname &&
	    !strncmp(namebuf, rock->usermboxname, rock->usermboxnamelen)
	    && (keylen == rock->usermboxnamelen || 
		namebuf[rock->usermboxnamelen] == '.')) {
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

	/* if we get here, close enough for us to spend the time
           acting interested */
	return 1;
    }

    return 0;
}

static int find_cb(void *rockp, 
		   const char *key, int keylen,
		   const char *data, int datalen)
{
    char namebuf[MAX_MAILBOX_NAME+1];
    char namematchbuf[MAX_MAILBOX_NAME+1];
    struct find_rock *rock = (struct find_rock *) rockp;
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
	
	if (!rock->inbox && rock->usermboxname &&
	    !strncmp(namebuf, rock->usermboxname, rock->usermboxnamelen)
	    && (keylen == rock->usermboxnamelen || 
		namebuf[rock->usermboxnamelen] == '.')) {
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
	if (rock->checkmboxlist) {
	    r = mboxlist_lookup(namebuf, NULL, NULL, NULL);
	} else {
	    r = 0;		/* don't bother checking */
	}
	if (!r && !rock->isadmin) {
	    /* check the acls */
	    const char *p, *acl;
	    char aclbuf[1024];
	    int rights;
	    int acllen;

	    p = strchr(data, ' ');
	    if (!p) {
		syslog(LOG_ERR, "%s: can't find partition", namebuf);
		return IMAP_IOERROR;
	    }
	    p++;
	    acl = strchr(p, ' ');
	    if (!acl) {
		syslog(LOG_ERR, "%s: can't find acl", namebuf);
		return IMAP_IOERROR;
	    }
	    acl++;
	    acllen = datalen - (acl - data);
	    if (acllen < sizeof(aclbuf) - 1) {
		memcpy(aclbuf, acl, acllen);
		aclbuf[acllen] = '\0';
		rights = acl_myrights(rock->auth_state, aclbuf);
	    } else {
		char *a = xstrndup(acl, datalen - (acl - data));
		rights = acl_myrights(rock->auth_state, a);
		free(a);
	    }
	    if (!(rights & ACL_LOOKUP)) {
		r = IMAP_MAILBOX_NONEXISTENT;
	    }
	}

	switch (r) {
	case 0:
	    /* found the entry; output it */
	    r = (*rock->proc)(namematchbuf+rock->inboxoffset, matchlen, 
			      1, rock->procrock);
	    break;
	    
	case IMAP_MAILBOX_NONEXISTENT:
	    /* didn't find the entry */
	    r = 0;
	    break;

	default:
	    break;
	}

	if (r) break;
    }

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
/* Find all mailboxes that match 'pattern'. */
int mboxlist_findall(char *pattern, int isadmin, char *userid, 
		     struct auth_state *auth_state, int (*proc)(), void *rock)
{
    struct find_rock cbrock;
    char usermboxname[MAX_MAILBOX_NAME+1];
    int usermboxnamelen = 0;
    const char *data;
    int datalen;
    int r = 0;
    char *p;
    int prefixlen;

    cbrock.g = glob_init(pattern, GLOB_HIERARCHY|GLOB_INBOXCASE);
    cbrock.inboxcase = glob_inboxcase(cbrock.g);
    cbrock.isadmin = isadmin;
    cbrock.auth_state = auth_state;
    cbrock.checkmboxlist = 0;	/* don't duplicate work */
    cbrock.proc = proc;
    cbrock.procrock = rock;

    /* Build usermboxname */
    if (userid && !strchr(userid, '.') &&
	strlen(userid)+5 < MAX_MAILBOX_NAME) {
	strcpy(usermboxname, "user.");
	strcat(usermboxname, userid);
	usermboxnamelen = strlen(usermboxname);
    }
    else {
	userid = 0;
    }

    /* Check for INBOX first of all */
    if (userid) {
	if (GLOB_TEST(cbrock.g, "INBOX") != -1) {
	    r = DB->fetch(mbdb, usermboxname, usermboxnamelen,
			  &data, &datalen, NULL);
	    if (!r && data) {
		r = (*proc)(cbrock.inboxcase, 5, 1, rock);
	    }
	}
	else if (!strncmp(pattern, usermboxname, usermboxnamelen) &&
		 GLOB_TEST(cbrock.g, usermboxname) != -1) {
	    r = DB->fetch(mbdb, usermboxname, usermboxnamelen,
			  &data, &datalen, NULL);
	    if (!r && data) {
		r = (*proc)(usermboxname, usermboxnamelen, 1, rock);
	    }
	}
	strcpy(usermboxname+usermboxnamelen, ".");
	usermboxnamelen++;

	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    } else {
	cbrock.usermboxname = NULL;
	cbrock.usermboxnamelen = 0;
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

	cbrock.inbox = 1;
	/* iterate through prefixes matching usermboxname */
	DB->foreach(mbdb,
		    usermboxname, usermboxnamelen,
		    &find_p, &find_cb, &cbrock,
		    NULL);
    }

    cbrock.inbox = 0;
    cbrock.inboxoffset = 0;
    if (usermboxnamelen) {
	usermboxname[--usermboxnamelen] = '\0';
	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    }
    /* search for all remaining mailboxes.
       just bother looking at the ones that have the same pattern prefix. */
    DB->foreach(mbdb,
		pattern, prefixlen,
		&find_p, &find_cb, &cbrock,
		NULL);

  done:
    glob_free(&cbrock.g);

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
    int r;

    if (!root[0] || root[0] == '.' || strchr(root, '/')
	|| strchr(root, '*') || strchr(root, '%') || strchr(root, '?')) {
	return IMAP_MAILBOX_BADNAME;
    }
    
    memset(&quota, 0, sizeof(struct quota));

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
    /* look for a top-level mailbox in the proposed quotaroot */
    r = mboxlist_lookup(quota.root, NULL, NULL, NULL);
    if (r) {
	return r;
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
    
    /* top level mailbox */
    mboxlist_changequota(quota.root, 0, 0);
    /* submailboxes */
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

void mboxlist_init(int myflags)
{
    int r;
    char dbdir[1024];
    int flags = 0;

    /* create the name of the db file */
    strcpy(dbdir, config_dir);
    strcat(dbdir, FNAME_DBDIR);
    if (myflags & MBOXLIST_RECOVER) flags |= CYRUSDB_RECOVER;
    r = DB->init(dbdir, flags);
    if (r != CYRUSDB_OK) {
	fatal("can't initialize mboxlist environment", EC_TEMPFAIL);
    }

    if (myflags & MBOXLIST_SYNC) {
	r = DB->sync();
    }

    r = acap_init();
    if (r != ACAP_OK) {
	syslog(LOG_ERR,"acap_init failed()");
    }
}

void mboxlist_open(char *fname)
{
    int ret;
    char *tofree = NULL;

    /* create db file name */
    if (!fname) {
	fname = xmalloc(strlen(config_dir)+sizeof(FNAME_MBOXLIST));
	tofree = fname;
	strcpy(fname, config_dir);
	strcat(fname, FNAME_MBOXLIST);
    }

    ret = DB->open(fname, &mbdb);
    if (ret != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
	       cyrusdb_strerror(ret));
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
	r = DB->close(mbdb);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: error closing mailboxes: %s",
		   cyrusdb_strerror(r));
	}
	mboxlist_dbopen = 0;
    }
}

void mboxlist_done(void)
{
    int r;

    r = DB->done();
    if (r) {
	syslog(LOG_ERR, "DBERROR: error exiting application: %s",
	       cyrusdb_strerror(r));
    }
    
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
    struct find_rock cbrock;
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
    cbrock.isadmin = 1;		/* user can always see their subs */
    cbrock.auth_state = auth_state;
    cbrock.checkmboxlist = !force;
    cbrock.proc = proc;
    cbrock.procrock = rock;

    /* Build usermboxname */
    if (userid && !strchr(userid, '.') &&
	strlen(userid)+5 < MAX_MAILBOX_NAME) {
	strcpy(usermboxname, "user.");
	strcat(usermboxname, userid);
	usermboxnamelen = strlen(usermboxname);
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
		r = (*proc)(usermboxname, usermboxnamelen, 1, rock);
	    }
	}
	strcpy(usermboxname+usermboxnamelen, ".");
	usermboxnamelen++;

	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
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

	cbrock.inbox = 1;
	/* iterate through prefixes matching usermboxname */
	SUBDB->foreach(subs,
		       usermboxname, usermboxnamelen,
		       &find_p, &find_cb, &cbrock,
		       NULL);

	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    } else {
	cbrock.usermboxname = NULL;
	cbrock.usermboxnamelen = 0;
    }

    cbrock.inbox = 0;
    cbrock.inboxoffset = 0;
    if (usermboxnamelen) {
	usermboxname[--usermboxnamelen] = '\0';
	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    }
    /* search for all remaining mailboxes.
       just bother looking at the ones that have the same pattern prefix. */
    SUBDB->foreach(subs, pattern, prefixlen, 
		   &find_p, &find_cb, &cbrock, NULL);

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
	break;

    default:
	r = IMAP_IOERROR;
	break;
    }

    mboxlist_closesubs(subs);
    return r;
}
