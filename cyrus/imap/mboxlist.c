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
 * $Id: mboxlist.c,v 1.198.2.26 2002/11/15 21:46:57 rjs3 Exp $
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

#include "mboxname.h"
#include "mupdate-client.h"

#include "mboxlist.h"

#define DB CONFIG_DB_MBOX
#define SUBDB CONFIG_DB_SUBS

cyrus_acl_canonproc_t mboxlist_ensureOwnerRights;

struct db *mbdb;

static int mboxlist_dbopen = 0;

static int mboxlist_opensubs();
static void mboxlist_closesubs();

static int mboxlist_rmquota(const char *name, int matchlen, int maycreate,
			    void *rock);
static int mboxlist_changequota(const char *name, int matchlen, int maycreate,
				void *rock);

#define FNAME_SUBSSUFFIX ".sub"

/*
 * Convert a partition into a path
 */
static int mboxlist_getpath(const char *partition, const char *name, 
			    char **pathp)
{
    static char pathresult[MAX_MAILBOX_PATH];
    const char *root;

    assert(partition && pathp);

    root = config_partitiondir(partition);
    if (!root) return IMAP_PARTITION_UNKNOWN;

    mailbox_hash_mbox(pathresult, root, name);

    *pathp = pathresult;

    return 0;
}

char *mboxlist_makeentry(int mbtype, const char *part, const char *acl)
{
    char *mboxent = (char *) xmalloc(sizeof(char) * 
				     (30 + strlen(acl) + strlen(part)));
    sprintf(mboxent, "%d %s %s", mbtype, part, acl);
    return mboxent;
}

static const int get_deleteright(void)
{
    const char *r = config_getstring(IMAPOPT_DELETERIGHT);

    return cyrus_acl_strtomask(r);
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
	    } else if (mbtype & MBTYPE_MOVING) {
		char *part = strchr(partition, '!');
		
		if(!part) return IMAP_SYS_ERROR;
		else part++; /* skip the !, go to the beginning
				of the partition name */
		r = mboxlist_getpath(part, name, pathp);
		if(r) return r;
	    } else {
		r = mboxlist_getpath(partition, name, pathp);
		if(r) return r;
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

int mboxlist_detail(const char *name, int *typep, char **pathp, char **partp,
		    char **aclp, struct txn *tid __attribute__((unused))) 
{
    return mboxlist_mylookup(name, typep, pathp, partp, aclp, NULL, 0);
}

int mboxlist_findstage(const char *name, char *stagedir) 
{
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
	    
    root = config_partitiondir(partition);
    if (!root) return IMAP_PARTITION_UNKNOWN;
	
    sprintf(stagedir, "%s/stage./", root);
    
    return 0;
}

int mboxlist_update(char *name, int flags, const char *part, const char *acl)
{
    int r = 0;
    char *mboxent = NULL;
    
    mboxent = mboxlist_makeentry(flags, part, acl);
    r = DB->store(mbdb, name, strlen(name), mboxent, strlen(mboxent), NULL);
    free(mboxent);

    return r;
}


/*
 * Check/set up for mailbox creation
 */
/* xxx shouldn't we be using mbtype or getting rid of it entirely? */
static int
mboxlist_mycreatemailboxcheck(char *name,
			      int new_mbtype __attribute__((unused)),
			      char *partition, 
			      int isadmin, char *userid, 
			      struct auth_state *auth_state, 
			      char **newacl, char **newpartition,
			      int RMW, int localonly, int force_user_create,
			      struct txn **tid)
{
    int r;
    char *mbox = name;
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
    int mbtype;
    
    /* Check for invalid name/partition */
    if (partition && strlen(partition) > MAX_PARTITION_LEN) {
	return IMAP_PARTITION_UNKNOWN;
    }
    if (config_virtdomains && (p = strchr(name, '!'))) {
	/* pointer to mailbox w/o domain prefix */
	mbox = p + 1;
    }
    r = mboxname_policycheck(mbox);
    if (r) return r;

    /* you must be a real admin to create a local-only mailbox */
    if(!isadmin && localonly) return IMAP_PERMISSION_DENIED;
    if(!isadmin && force_user_create) return IMAP_PERMISSION_DENIED;

    /* User has admin rights over their own mailbox namespace */
    if (mboxname_userownsmailbox(userid, name)) {
	isadmin = 1;
    }

    /* Check to see if new mailbox exists */
    r = mboxlist_mylookup(name, &mbtype, &path, NULL, &acl, tid, RMW);
    switch (r) {
    case 0:
	if(mbtype & MBTYPE_RESERVE)
	    r = IMAP_MAILBOX_RESERVED;
	else
	    r = IMAP_MAILBOX_EXISTS;
	
	/* Lie about error if privacy demands */
	if (!isadmin && 
	    !(cyrus_acl_myrights(auth_state, acl) & ACL_LOOKUP)) {
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

    /* Search for a parent - stop if we hit the domain separator */
    strcpy(parent, name);
    parentlen = 0;
    while ((parentlen==0) && (p = strrchr(parent, '.')) && !strchr(p, '!')) {
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
	if (!isadmin &&
	    !(cyrus_acl_myrights(auth_state, parentacl) & ACL_CREATE)) {
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
	strncpy(name, parent, strlen(parent));
    } else { /* parentlen == 0, no parent mailbox */
	if (!isadmin) {
	    return IMAP_PERMISSION_DENIED;
	}
	
	acl = xstrdup("");
	if (!strncmp(mbox, "user.", 5)) {
	    char *firstdot = strchr(mbox+5, '.');
	    if (!force_user_create && firstdot) {
		/* Disallow creating user.X.* when no user.X */
		free(acl);
		return IMAP_PERMISSION_DENIED;
	    }
	    /* disallow wildcards in userids with inboxes. */	     
	    if (strchr(mbox, '*') || strchr(mbox, '%') || strchr(mbox, '?')) {
		return IMAP_MAILBOX_BADNAME;
	    }

	    /*
	     * Users by default have all access to their personal mailbox(es),
	     * Nobody else starts with any access to same.
	     *
	     * If this is a forced user create, we might have to avoid creating
	     * an acl for the wrong user.
	     */
	    if(firstdot) *firstdot = '\0';
	    identifier = xmalloc(mbox - name + strlen(mbox+5) + 1);
	    strcpy(identifier, mbox+5);
	    if(firstdot) *firstdot = '.';

	    if (config_getswitch(IMAPOPT_UNIXHIERARCHYSEP)) {
		/*
		 * The mailboxname is now in the internal format,
		 * so we we need to change DOTCHARs back to '.'
		 * in the identifier in order to have the correct ACL.
		 */
		for (p = identifier; *p; p++) {
		    if (*p == DOTCHAR) *p = '.';
		}
	    }
	    if (mbox != name) {
		/* add domain to identifier */
		sprintf(identifier+strlen(identifier),
			"@%.*s", mbox - name - 1, name);
	    }
	    cyrus_acl_set(&acl, identifier, ACL_MODE_SET, ACL_ALL,
		    (cyrus_acl_canonproc_t *)0, (void *)0);
	    free(identifier);
	} else {
	    defaultacl = identifier = 
		xstrdup(config_getstring(IMAPOPT_DEFAULTACL));
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
		cyrus_acl_set(&acl, identifier, ACL_MODE_SET, cyrus_acl_strtomask(rights),
			(cyrus_acl_canonproc_t *)0, (void *)0);
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
					 newpartition, 0, 0, 0, NULL);
}

/*
 * Create a mailbox
 *
 * 1. start mailboxes transaction
 * 2. verify ACL's to best of ability (CRASH: abort)
 * 3. open mupdate connection if necessary
 * 4. verify parent ACL's if need to
 * 5. create mupdate entry and set as reserved (CRASH: mupdate inconsistant)
 * 6. create on disk (CRASH: mupdate inconsistant, disk inconsistant)
 * 8. commit local transaction (CRASH: mupdate inconsistant)
 * 9. set mupdate entry as commited (CRASH: commited)
 *
 */

int mboxlist_createmailbox(char *name, int mbtype, char *partition, 
			   int isadmin, char *userid, 
			   struct auth_state *auth_state,
			   int localonly, int forceuser)
{
    int r;
    char *acl = NULL;
    const char *root = NULL;
    char *newpartition = NULL;
    struct txn *tid = NULL;
    mupdate_handle *mupdate_h = NULL;
    char *mboxent = NULL;
    int newreserved = 0; /* made reserved entry in local mailbox list */
    int madereserved = 0; /* made reserved entry on mupdate server */

    /* Must be atleast MAX_PARTITION_LEN + 30 for partition, need
     * MAX_PARTITION_LEN + HOSTNAME_SIZE + 2 for mupdate location */
    char buf[MAX_PARTITION_LEN + HOSTNAME_SIZE + 2];

 retry:
    tid = NULL;

    /* 2. verify ACL's to best of ability (CRASH: abort) */
    r = mboxlist_mycreatemailboxcheck(name, mbtype, partition, isadmin, 
				      userid, auth_state, 
				      &acl, &newpartition, 1, localonly,
				      forceuser, &tid);
    switch (r) {
    case 0:
	break;
    case IMAP_AGAIN:
	goto retry;
    default:
	goto done;
    }

    /* You can't explicitly create a MOVING or RESERVED mailbox */
    if(mbtype & (MBTYPE_MOVING | MBTYPE_RESERVE)) {
	r = IMAP_MAILBOX_NOTSUPPORTED;
	goto done;
    }

    if (!(mbtype & MBTYPE_REMOTE)) {
	/* Get partition's path */
	root = config_partitiondir(newpartition);
	if (!root) {
	    r = IMAP_PARTITION_UNKNOWN;
	    goto done;
	}
	if (strlen(root)+strlen(name)+20 > MAX_MAILBOX_PATH) {
	    r = IMAP_MAILBOX_BADNAME;
	    goto done;
	}
    }

    /* 3a. Reserve mailbox in local database */
    mboxent = mboxlist_makeentry(mbtype | MBTYPE_RESERVE,
				 newpartition, acl);
    r = DB->store(mbdb, name, strlen(name), 
		  mboxent, strlen(mboxent), &tid);
    free(mboxent);
    mboxent = NULL;

    /* 3b. Unlock mailbox list (before calling out to mupdate) */
    if(r) {
	syslog(LOG_ERR, "Could not reserve mailbox %s during create", name);
	goto done;
    } else {
	DB->commit(mbdb, tid);
	tid = NULL;
	newreserved = 1;
    }

    /* 4. Create mupdate reservation */
    if (config_mupdate_server && !localonly) {
	r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	if(r) {
	    syslog(LOG_ERR,
		   "can not connect to mupdate server for reservation on '%s'",
		   name);
	    goto done;
	}

	sprintf(buf, "%s!%s", config_servername, newpartition);

	/* reserve the mailbox in MUPDATE */
	r = mupdate_reserve(mupdate_h, name, buf);
	if(r) {
	    syslog(LOG_ERR,
		   "MUPDATE: can't reserve mailbox entry for '%s'", name);
	    goto done;
	}
    }
    madereserved = 1; /* so we can roll back on failure */

 done: /* All checks compete.  Time to fish or cut bait. */
    if (!r && !(mbtype & MBTYPE_REMOTE)) {
	char mbbuf[MAX_MAILBOX_PATH];

	/* Create new mailbox in the filesystem */
	mailbox_hash_mbox(mbbuf, root, name);
	r = mailbox_create(name, mbbuf, acl, NULL,
			   ((mbtype & MBTYPE_NETNEWS) ?
			    MAILBOX_FORMAT_NETNEWS :
			    MAILBOX_FORMAT_NORMAL), 
			   NULL);
    }

    if (r) { /* CREATE failed */ 
	int r2 = 0;

	if (tid) {
	    r2 = DB->abort(mbdb, tid);
	    tid = NULL;
	}
	if (r2) {
	    syslog(LOG_ERR, "DBERROR: can't abort: %s", cyrusdb_strerror(r2));
	}

	if(newreserved) {
	    /* remove the RESERVED mailbox entry if we failed */
	    r2 = DB->delete(mbdb, name, strlen(name), NULL, 0);
	    if(r2) {
		syslog(LOG_ERR,
		       "DBERROR: can't remove RESERVE entry for %s (%s)",
		       name, cyrusdb_strerror(r2));
	    }
	}

	/* delete mupdate entry if we made it */
	if (madereserved && config_mupdate_server) {
	    r2 = mupdate_delete(mupdate_h, name);
	    if(r2 > 0) {
		/* Disconnect, reconnect, and retry */
		syslog(LOG_WARNING,
		       "MUPDATE: lost connection, retrying");
		mupdate_disconnect(&mupdate_h);
		r2 = mupdate_connect(config_mupdate_server, NULL,
				     &mupdate_h, NULL);
		if(!r2) {
		    r2 = mupdate_delete(mupdate_h, name);
		}
	    }
	    if(r2) {
		syslog(LOG_ERR,
		       "MUPDATE: can't unreserve mailbox entry '%s'",
		       name);
	    }		
	}
    } else { /* all is well - activate the mailbox */
	mboxent = mboxlist_makeentry(mbtype, newpartition, acl);

	switch(r = DB->store(mbdb, name, strlen(name),
			     mboxent, strlen(mboxent), NULL)) {
	case 0: 
	    break;
	default:
	    /* xxx This leaves a reserved entry around, it is unclear
	     * that a DB->delete would work though */
	    syslog(LOG_ERR, "DBERROR: failed on activation: %s", 
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
    }

    /* 9. set MUPDATE entry as commited (CRASH: commited) */
    /* xxx maybe we should roll back if this fails? */
    if (!r && config_mupdate_server && !localonly) {
	/* commit the mailbox in MUPDATE */
	sprintf(buf, "%s!%s", config_servername, newpartition);
	    
	r = mupdate_activate(mupdate_h, name, buf, acl);
	if(r > 0) {
	    /* Disconnect, reconnect, and retry */
	    syslog(LOG_WARNING,
		   "MUPDATE: lost connection, retrying");
	    mupdate_disconnect(&mupdate_h);
	    r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	    if(!r) {
		r = mupdate_activate(mupdate_h, name, buf, acl);
	    }
	}
	if(r) {
	    syslog(LOG_ERR,
		   "MUPDATE: can't commit mailbox entry for '%s'", name);
	}
    }

    if(config_mupdate_server && mupdate_h) mupdate_disconnect(&mupdate_h);

    if (acl) free(acl);
    if (newpartition) free(newpartition);
    if (mboxent) free(mboxent);
   
    return r;
}

/* insert an entry for the proxy */
/* xxx rettid needs usage? */
int mboxlist_insertremote(const char *name, int mbtype,
			  const char *host, const char *acl,
			  void **rettid __attribute__((unused)))
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
	syslog(LOG_ERR, "DBERROR: error updating database %s: %s",
	       name, cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	break;
    }

    free(mboxent);
    
    return r;
}
	
/*
 * Delete a mailbox.
 * Deleting the mailbox user.FOO may only be performed by an admin.
 *
 * 1. Begin transaction
 * 2. Verify ACL's
 * 3. remove from database
 * 4. remove from disk
 * 5. commit transaction
 * 6. Open mupdate connection if necessary
 * 7. delete from mupdate
 *
 */
int mboxlist_deletemailbox(const char *name, int isadmin, char *userid, 
			   struct auth_state *auth_state, int checkacl,
			   int local_only, int force)
{
    int r;
    char *acl;
    long access;
    struct mailbox mailbox;
    int deletequotaroot = 0;
    char *path;
    struct txn *tid = NULL;
    int isremote = 0;
    int mbtype;
    int deleteright = get_deleteright();
    const char *p;
    mupdate_handle *mupdate_h = NULL;

    if(!isadmin && force) return IMAP_PERMISSION_DENIED;

 retry:
    /* Check for request to delete a user:
       user.<x> with no dots after it */
    if ((p = mboxname_isusermailbox(name, 1))) {
	/* Can't DELETE INBOX (your own inbox) */
	if (userid && !strncmp(p, userid,
			       config_virtdomains ? strcspn(userid, "@") :
			       strlen(userid))) {
	    r = IMAP_MAILBOX_NOTSUPPORTED;
	    goto done;
	}

	/* Only admins may delete user */
	if (!isadmin) { r = IMAP_PERMISSION_DENIED; goto done; }
    }

    r = mboxlist_mylookup(name, &mbtype, &path, NULL, &acl, NULL, 1);
    switch (r) {
    case 0:
	break;

    case IMAP_AGAIN:
	goto retry;
	break;

    default:
	goto done;
    }

    isremote = mbtype & MBTYPE_REMOTE;

    /* are we reserved? (but for remote mailboxes this is okay, since
     * we don't touch their data files at all) */
    if(!isremote && (mbtype & MBTYPE_RESERVE) && !force) {
	r = IMAP_MAILBOX_RESERVED;
	goto done;
    }

    /* check if user has Delete right (we've already excluded non-admins
     * from deleting a user mailbox) */
    if(checkacl) {
	access = cyrus_acl_myrights(auth_state, acl);
	if(!(access & deleteright)) {
	    /* User has admin rights over their own mailbox namespace */
	    if (mboxname_userownsmailbox(userid, name)) {
		isadmin = 1;
	    }
	    
	    /* Lie about error if privacy demands */
	    r = (isadmin || (access & ACL_LOOKUP)) ?
		IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	    goto done;
	}
    }

    /* Lock the mailbox if it isn't a remote mailbox */
    if(!r && !isremote) {
	r = mailbox_open_locked(name, path, acl, 0, &mailbox, 0);
	if(r && !force) goto done;
    }
    
    /* delete entry */
    r = DB->delete(mbdb, name, strlen(name), &tid, 0);
    switch (r) {
    case CYRUSDB_OK: /* success */
	break;
    case CYRUSDB_AGAIN:
	goto retry;
    default:
	syslog(LOG_ERR, "DBERROR: error deleting %s: %s",
	       name, cyrusdb_strerror(r));
	r = IMAP_IOERROR;
	if(!force) goto done;
    }

    /* remove from mupdate - this can be weird if the commit below fails */
    /* xxx this is network I/O being done while holding a mboxlist lock */
    if ((!r || force)
	&& !isremote && !local_only && config_mupdate_server) {
	/* delete the mailbox in MUPDATE */
	r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	if(r) {
	    syslog(LOG_ERR,
		   "can not connect to mupdate server for delete of '%s'",
		   name);
	    goto done;
	}
	r = mupdate_delete(mupdate_h, name);
	if(r) {
	    syslog(LOG_ERR,
		   "MUPDATE: can't delete mailbox entry '%s'", name);
	}
	mupdate_disconnect(&mupdate_h);
    }

    /* commit db operations */
    if (!r || force) {
	r = DB->commit(mbdb, tid);
	if (r) {
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
	tid = NULL;
    }

    if ((r && !force) || isremote) goto done;

    if (!r || force) r = mailbox_delete(&mailbox, deletequotaroot);

    /*
     * See if we have to remove mailbox's quota root
     */
    if (!r && mailbox.quota.root != NULL) {
	/* xxx look for any other mailboxes in this quotaroot */
    }

 done:
    if(r && tid && !force) {
	/* Abort the transaction if it is still in progress */
	DB->abort(mbdb, tid);
    } else if(tid && force) {
	DB->commit(mbdb, tid);
    }

    return r;
}

/*
 * Rename/move a single mailbox (recursive renames are handled at a
 * higher level)
 */
int mboxlist_renamemailbox(char *oldname, char *newname, char *partition, 
			   int isadmin, char *userid, 
			   struct auth_state *auth_state)
{
    int r;
    long access;
    int isusermbox = 0; /* Are we renaming someone's inbox */
    int partitionmove = 0;
    int mbtype;
    char *oldpath = NULL;
    char newpath[MAX_MAILBOX_PATH];
    int oldopen = 0, newopen = 0, newreserved = 0;
    struct mailbox oldmailbox;
    struct mailbox newmailbox;
    char *oldacl = NULL, *newacl = NULL;
    const char *root = NULL;
    struct txn *tid = NULL;
    char *newpartition = NULL;
    char *mboxent = NULL;
    int deleteright = get_deleteright();
    char *p;

    mupdate_handle *mupdate_h = NULL;
    int madenew = 0;

 retry:
    /* 1. get path & acl from mboxlist */
    r = mboxlist_mylookup(oldname, &mbtype, &oldpath, NULL, &oldacl, &tid, 1);
    switch (r) {
    case 0:
	break;
    case IMAP_AGAIN:
	goto retry;
    default:
	goto done;
    }

    if(mbtype & MBTYPE_RESERVE) {
	r = IMAP_MAILBOX_RESERVED;
	goto done;
    }

    /* make a copy of the old ACL so it doesn't get overwritten
       by another call to mboxlist_mylookup() */
    newacl = xstrdup(oldacl);

    /* 2. verify acls */
    if (!strcmp(oldname, newname) && !(mbtype & MBTYPE_REMOTE)) {
	/* Attempt to move mailbox across partition */
	if (!isadmin) {
	    r = IMAP_PERMISSION_DENIED;
	    goto done;
	} else if (!partition) {	  
	    r = IMAP_PARTITION_UNKNOWN;
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
    } else if ((p = mboxname_isusermailbox(oldname, 1))) {
	if (!strncmp(p, userid, config_virtdomains ? strcspn(userid, "@") :
		     strlen(userid))) {
	    /* Special case of renaming inbox */
	    access = cyrus_acl_myrights(auth_state, oldacl);
	    if (!(access & deleteright)) {
	      r = IMAP_PERMISSION_DENIED;
	      goto done;
	    }
	    isusermbox = 1;
	} else if (config_getswitch(IMAPOPT_ALLOWUSERMOVES) &&
		   mboxname_isusermailbox(newname, 1)) {
	    /* Special case of renaming a user */
	    access = cyrus_acl_myrights(auth_state, oldacl);
	    if (!(access & deleteright) && !isadmin) {
		r = (isadmin || (access & ACL_LOOKUP)) ?
		    IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
		goto done;
	    }
	} else {
	    /* Only admins can rename users (INBOX to INBOX) */
	    r = IMAP_MAILBOX_NOTSUPPORTED;
	    goto done;
	}
    } else {
	access = cyrus_acl_myrights(auth_state, oldacl);
	if (!(access & deleteright) && !isadmin) {
	    r = (isadmin || (access & ACL_LOOKUP)) ?
		IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	    goto done;
	}
    }

    /* We don't support renaming mailboxes in transit */
    if(!r && (mbtype & MBTYPE_MOVING)) {
	r = IMAP_MAILBOX_NOTSUPPORTED;
	goto done;
    }

    /* Check ability to create new mailbox */
    if (!partitionmove) {
	if (mboxname_isusermailbox(newname, 1)) {
	    if (config_getswitch(IMAPOPT_ALLOWUSERMOVES) &&
		mboxname_isusermailbox(oldname, 1)) {
		if (!isadmin) {
		    /* Only admins can rename users (INBOX to INBOX) */
		    r = IMAP_MAILBOX_NOTSUPPORTED;
		    goto done;
		}
	    } else {
		/* Even admins can't rename to user's inboxes */
		r = IMAP_MAILBOX_NOTSUPPORTED;
		goto done;
	    }
	}
	r = mboxlist_mycreatemailboxcheck(newname, 0, partition, isadmin, 
					  userid, auth_state, NULL, 
					  &newpartition, 1, 0, 0, &tid);
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

    /* 3a. mark as reserved in the local DB */
    if(!r && !partitionmove) {
	mboxent = mboxlist_makeentry(mbtype | MBTYPE_RESERVE,
				     newpartition, newacl);

	r = DB->store(mbdb, newname, strlen(newname), 
		      mboxent, strlen(mboxent), &tid);

	free(mboxent);
    }
        
    /* 3b. unlock mboxlist (before calling out to mupdate) */
    if(r) {
	syslog(LOG_ERR, "Could not reserve mailbox %s during rename", oldname);
	goto done;
    } else {
	DB->commit(mbdb, tid);
	tid = NULL;
	newreserved = 1;
    }

    /* 4. Open mupdate connection and reserve new name (if needed) */ 
    if(!r && config_mupdate_server) {	
	r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	if(r) {
	    syslog(LOG_ERR,
		   "can not connect to mupdate server for rename of '%s'",
		   newname);
	    goto done;
	}
	if (!partitionmove) {
	    /* Reserve new name in MUPDATE */
	    char buf[MAX_PARTITION_LEN + HOSTNAME_SIZE + 2];
	    sprintf(buf, "%s!%s", config_servername, newpartition);

	    r = mupdate_reserve(mupdate_h, newname, buf);
	    if(r) {
		syslog(LOG_ERR,
		       "MUPDATE: can't reserve mailbox entry for '%s'",
		       newname);
		goto done;
	    }
	    
	    madenew = 1;
	}
    }

    /* 5. Lock oldname/oldpath */

    if(!r) {
	r = mailbox_open_locked(oldname, oldpath, oldacl, auth_state,
				&oldmailbox, 0);
	oldopen = 1;
    }

    /* 6. Copy mailbox */
    if (!r && !(mbtype & MBTYPE_REMOTE)) {
	/* Rename the actual mailbox */
	assert(root != NULL); /* from above */
	mailbox_hash_mbox(newpath, root, newname);
	
	r = mailbox_rename_copy(&oldmailbox, newname, newpath,
				NULL, NULL, &newmailbox);
	if (r) {
	    goto done;
	} else {
	    newopen = 1;
	}
    }

    if (!isusermbox) {
	/* 4. Delete entry from berkeley db */
	r = DB->delete(mbdb, oldname, strlen(oldname), &tid, 0);
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
	    mailbox_close(&newmailbox);
	    goto done;
	    break;
	}
    }

    /* 7a. create new entry */
    mboxent = mboxlist_makeentry(mbtype, newpartition, newacl);

    /* 7b. put it into the db */
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

 done: /* Commit or cleanup */
    if (r != 0) {
	int r2 = 0;
	
	if (tid) {
	    r2 = DB->abort(mbdb, tid);
	    tid = NULL;
	}
	if (r2) {
	    syslog(LOG_ERR, "DBERROR: can't abort: %s", cyrusdb_strerror(r2));
	}
	
	if(newreserved) {
	    /* remove the RESERVED mailbox entry if we failed */
	    r2 = DB->delete(mbdb, newname, strlen(newname), NULL, 0);
	    if(r2) {
		syslog(LOG_ERR,
		       "DBERROR: can't remove RESERVE entry for %s (%s)",
		       newname, cyrusdb_strerror(r2));
	    }
	}
	
	/* unroll mupdate operations if necessary */
	if (madenew && config_mupdate_server) {
	    r2 = mupdate_delete(mupdate_h, newname);
	    if(r2 > 0) {
		/* Disconnect, reconnect, and retry */
		syslog(LOG_WARNING,
		       "MUPDATE: lost connection, retrying");
		mupdate_disconnect(&mupdate_h);
		r2 = mupdate_connect(config_mupdate_server, NULL,
				     &mupdate_h, NULL);
		if(!r2) {
		    r2 = mupdate_delete(mupdate_h, newname);
		}
	    }
	    if(r2) {
		syslog(LOG_ERR,
		       "MUPDATE: can't unreserve mailbox entry '%s'",
		       newname);
	    }		
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

    if (!r && config_mupdate_server) {
	/* commit the mailbox in MUPDATE */
	/* This is okay even if we are moving partitions */
	char buf[MAX_PARTITION_LEN + HOSTNAME_SIZE + 2];
	sprintf(buf, "%s!%s", config_servername, newpartition);
	
	r = mupdate_activate(mupdate_h, newname, buf, newacl);
	if(r > 0) {
	    /* Disconnect, reconnect, and retry */
	    syslog(LOG_WARNING,
		   "MUPDATE: lost connection, retrying");
	    mupdate_disconnect(&mupdate_h);
	    r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	    if(!r) {
		r = mupdate_activate(mupdate_h, newname, buf, newacl);
	    }
	}
	if(r) {
	    syslog(LOG_ERR,
		   "MUPDATE: can't commit mailbox entry for '%s'",
		   newname);
	}
    }

    if (!r && !partitionmove && !isusermbox && config_mupdate_server) {
	/* delete the old mailbox in MUPDATE..but only if not renaming
	 * your inbox */
	r = mupdate_delete(mupdate_h, oldname);
	if(r > 0) {
	    /* Disconnect, reconnect, and retry */
	    syslog(LOG_WARNING,
		   "MUPDATE: lost connection, retrying");
	    mupdate_disconnect(&mupdate_h);
	    r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	    if(!r) {
		r = mupdate_delete(mupdate_h, oldname);
	    }
	}
	if(r) {
	    syslog(LOG_ERR,
		   "MUPDATE: can't delete mailbox entry '%s'", oldname);
	}
    }

    if(newopen) mailbox_close(&newmailbox);
    if(config_mupdate_server) mupdate_disconnect(&mupdate_h);

    if(oldopen) {
	if(!r)
	    mailbox_rename_cleanup(&oldmailbox,isusermbox);

	mailbox_close(&oldmailbox);
    }
    
    /* free memory */
    if (newacl) free(newacl);	/* we're done with the new ACL */
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
 * 1. Start transaction
 * 2. Check rights
 * 3. Set db entry
 * 4. Change backup copy (cyrus.header)
 * 5. Commit transaction
 * 6. Change mupdate entry 
 *
 */
int mboxlist_setacl(const char *name, const char *identifier,
		    const char *rights, 
		    int isadmin, const char *userid, 
		    struct auth_state *auth_state)
{
    int useridlen = strlen(userid), domainlen = 0;
    char *cp, ident[256];
    const char *domain = NULL;
    int r;
    int access;
    int mode = ACL_MODE_SET;
    int isusermbox = 0;
    struct mailbox mailbox;
    int mailbox_open = 0;
    char *acl, *newacl = NULL;
    char *partition, *path;
    char *mboxent = NULL;
    int mbtype;
    struct txn *tid = NULL;

    if (config_virtdomains) {
	if ((cp = strchr(userid, '@'))) {
	    useridlen = cp - userid;
	}
	if ((cp = strchr(name, '!'))) {
	    domain = name;
	    domainlen = cp - name + 1;
	}

	/* canonify identifier so it is fully qualified,
	   except for "anonymous", "anyone", the global admin
	   and users in the default domain */
	if ((cp = strchr(identifier, '@'))) {
	    if (rights &&
		(!domain || strncasecmp(cp+1, domain, strlen(cp+1)))) {
		/* can't set cross-domain ACLs */
		return IMAP_INVALID_IDENTIFIER;
	    }
	    if ((config_defdomain && !strcasecmp(config_defdomain, cp+1)) ||
		!strcmp(identifier, "anonymous") ||
		!strcmp(identifier, "anyone")) {
		sprintf(ident, "%.*s", cp - identifier, identifier);
	    } else {
		strcpy(ident, identifier);
	    }
	} else {
	    strcpy(ident, identifier);
	    if (domain && !isadmin &&
		strcmp(ident, "anonymous") && strcmp(ident, "anyone")) {
		sprintf(ident+strlen(ident), "@%.*s",
			domainlen ? domainlen-1 : (int) strlen(domain), domain);
	    }
	}

	identifier = ident;
    }

    if (!strncmp(name+domainlen, "user.", 5) &&
	(!(cp = strchr(userid, '.')) || (cp - userid) > useridlen) &&
	!strncmp(name+domainlen+5, userid, useridlen) &&
	(name[domainlen+5+useridlen] == '\0' ||
	 name[domainlen+5+useridlen] == '.')) {
	isusermbox = 1;
    }

    /* 1. Start Transaction */
    /* lookup the mailbox to make sure it exists and get its acl */
    do {
	r = mboxlist_mylookup(name, &mbtype, &path, &partition, &acl, &tid, 1);
    } while(r == IMAP_AGAIN);    

    /* Can't do this to an in-transit or reserved mailbox */
    if(!r && mbtype & (MBTYPE_MOVING | MBTYPE_RESERVE)) {
	r = IMAP_MAILBOX_NOTSUPPORTED;
    }

    /* if it is not a remote mailbox, we need to unlock the mailbox list,
     * lock the mailbox, and re-lock the mailboxes list */
    /* we must do this to obey our locking rules */
    if (!r && !(mbtype & MBTYPE_REMOTE)) {
	DB->abort(mbdb, tid);
	tid = NULL;

	/* open & lock mailbox header */
        r = mailbox_open_header_path(name, path, acl, NULL, &mailbox, 0);
	if (!r) {
	    mailbox_open = 1;
	    r = mailbox_lock_header(&mailbox);
	} 

	if(!r) {
	    do {
		/* lookup the mailbox to make sure it exists and get its acl */
		r = mboxlist_mylookup(name, &mbtype, &path,
				      &partition, &acl, &tid, 1);
	    } while( r == IMAP_AGAIN );
	}

	if(r) goto done;
    }

    /* 2. Check Rights */
    if (!r && !isadmin && !isusermbox) {
	access = cyrus_acl_myrights(auth_state, acl);
	if (!(access & ACL_ADMIN)) {
	    r = (access & ACL_LOOKUP) ?
		IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	    goto done;
	}
    }

    /* 3. Set DB Entry */
    if(!r) {
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
	    
	    if (cyrus_acl_set(&newacl, identifier, mode,
			      cyrus_acl_strtomask(rights),
			      isusermbox ? mboxlist_ensureOwnerRights : 0,
			      (void *)userid)) {
		r = IMAP_INVALID_IDENTIFIER;
	    }
	} else {
	    if (cyrus_acl_remove(&newacl, identifier,
				 isusermbox ? mboxlist_ensureOwnerRights : 0,
				 (void *)userid)) {
		r = IMAP_INVALID_IDENTIFIER;
	    }
	}
    }

    if(!r) {
	/* ok, change the database */
	mboxent = mboxlist_makeentry(mbtype, partition, newacl);

	do {
	    r = DB->store(mbdb, name, strlen(name),
			  mboxent, strlen(mboxent), &tid);
	} while(r == CYRUSDB_AGAIN);
    
	if(r) {
	    syslog(LOG_ERR, "DBERROR: error updating acl %s: %s",
		   name, cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
    }

    /* 4. Change backup copy (cyrus.header) */
    /* we already have it locked from above */
    if (!r && !(mbtype & MBTYPE_REMOTE)) {
	if(mailbox.acl) free(mailbox.acl);
	mailbox.acl = xstrdup(newacl);
	r = mailbox_write_header(&mailbox);
    }

    /* 5. Commit transaction */
    if (!r) {
	if((r = DB->commit(mbdb, tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   cyrusdb_strerror(r));
	    r = IMAP_IOERROR;
	}
	tid = NULL;
    }

    /* 6. Change mupdate entry  */
    if (!r && config_mupdate_server) {
        mupdate_handle *mupdate_h = NULL;
	/* commit the update to MUPDATE */
	char buf[MAX_PARTITION_LEN + HOSTNAME_SIZE + 2];
	sprintf(buf, "%s!%s", config_servername, partition);

	r = mupdate_connect(config_mupdate_server, NULL, &mupdate_h, NULL);
	if(r) {
	    syslog(LOG_ERR,
		   "can not connect to mupdate server for reservation on '%s'",
		   name);
	} else {
	    r = mupdate_activate(mupdate_h, name, buf, newacl);
	    if(r) {
		syslog(LOG_ERR,
		       "MUPDATE: can't update mailbox entry for '%s'",
		       name);
	    }
	}
	mupdate_disconnect(&mupdate_h);
    }

  done:
    if (r && tid) {
	/* if we are mid-transaction, abort it! */
	int r2 = DB->abort(mbdb, tid);
	if(r2) {
	    syslog(LOG_ERR,
		   "DBERROR: error aborting txn in mboxlist_setacl: %s",
		   cyrusdb_strerror(r2));
	}
    }
    if (mailbox_open) mailbox_close(&mailbox);
    if (mboxent) free(mboxent);
    if (newacl) free(newacl);
    
    return r;
}

struct find_rock {
    struct glob *g;
    struct namespace *namespace;
    int find_namespace;
    int domainlen;
    int inboxoffset;
    const char *inboxcase;
    const char *usermboxname;
    int usermboxnamelen;
    int checkmboxlist;
    int checkshared;
    int isadmin;
    struct auth_state *auth_state;
    int (*proc)(char *, int, int, void *rock);
    void *procrock;
};

/* return non-zero if we like this one */
static int find_p(void *rockp, 
		  const char *key, int keylen,
		  const char *data, int datalen)
{
    struct find_rock *rock = (struct find_rock *) rockp;
    long minmatch;
    struct glob *g = rock->g;
    long matchlen;

    /* don't list mailboxes outside of the default domain */
    if (!rock->domainlen && !rock->isadmin && strchr(key, '!')) return 0; 

    minmatch = 0;
    if (rock->inboxoffset) {
	char namebuf[MAX_MAILBOX_NAME+1];

	memcpy(namebuf, key, keylen);
	namebuf[keylen] = '\0';
	
	if (rock->inboxoffset) {
	    namebuf[rock->inboxoffset] = rock->inboxcase[0];
	    namebuf[rock->inboxoffset+1] = rock->inboxcase[1];
	    namebuf[rock->inboxoffset+2] = rock->inboxcase[2];
	    namebuf[rock->inboxoffset+3] = rock->inboxcase[3];
	    namebuf[rock->inboxoffset+4] = rock->inboxcase[4];
	}
	
	matchlen = glob_test(g, namebuf+rock->inboxoffset,
			     keylen-rock->inboxoffset, &minmatch);
    } else {
	matchlen = glob_test(g, key, keylen, &minmatch);
    }
    if (matchlen == -1) return 0;

    if (rock->find_namespace != NAMESPACE_INBOX &&
	rock->usermboxname &&
	keylen >= rock->usermboxnamelen &&
	(keylen == rock->usermboxnamelen || 
	 key[rock->usermboxnamelen] == '.') &&
	!strncmp(key, rock->usermboxname, rock->usermboxnamelen)) {
	/* this would've been output with the inbox stuff, so skip it */
	return 0;
    }

    if (rock->find_namespace == NAMESPACE_SHARED &&
	rock->namespace && rock->namespace->isalt &&
	!strncmp(key+rock->domainlen, "user", 4) &&
	(key[rock->domainlen+4] == '\0' || key[rock->domainlen+4] == '.')) {
	/* this would've been output with the user stuff, so skip it */
	return 0;
    }

    /* check acl */
    if (!rock->isadmin) {
	/* check the acls */
	const char *p, *acl;
	int rights;
	int acllen;
	static char *aclbuf = NULL;
	static int aclbufsz = 0;

	p = strchr(data, ' ');
	if (!p) {
	    syslog(LOG_ERR, "%s: can't find partition", key);
	    return 0;
	}
	p++;
	acl = strchr(p, ' ');
	if (!acl) {
	    syslog(LOG_ERR, "%s: can't find acl", key);
	    return 0;
	}
	acl++;
	acllen = datalen - (acl - data);
	if (acllen >= aclbufsz) {
	    aclbufsz = acllen + 500;
	    aclbuf = xrealloc(aclbuf, aclbufsz);
	}
	memcpy(aclbuf, acl, acllen);
	aclbuf[acllen] = '\0';

	rights = cyrus_acl_myrights(rock->auth_state, aclbuf);
	if (!(rights & ACL_LOOKUP)) {
	    return 0;
	}
    }
    
    /* if we get here, close enough for us to spend the time
       acting interested */
    return 1;
}

static int find_cb(void *rockp, 
		   const char *key, int keylen,
		   const char *data, int datalen)
{
    char namebuf[MAX_MAILBOX_NAME+1];
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
	
	if (rock->find_namespace != NAMESPACE_INBOX &&
	    rock->usermboxname &&
	    !strncmp(namebuf, rock->usermboxname, rock->usermboxnamelen)
	    && (keylen == rock->usermboxnamelen || 
		namebuf[rock->usermboxnamelen] == '.')) {
	    /* this would've been output with the inbox stuff, so skip it */
	    return 0;
	}

      	/* make sure it's in the mailboxes db */
	if (rock->checkmboxlist) {
	    r = mboxlist_lookup(namebuf, NULL, NULL, NULL);
	} else {
	    r = 0;		/* don't bother checking */
	}

	if (!r && rock->inboxoffset) {
	    namebuf[rock->inboxoffset] = rock->inboxcase[0];
	    namebuf[rock->inboxoffset+1] = rock->inboxcase[1];
	    namebuf[rock->inboxoffset+2] = rock->inboxcase[2];
	    namebuf[rock->inboxoffset+3] = rock->inboxcase[3];
	    namebuf[rock->inboxoffset+4] = rock->inboxcase[4];
	}
	
	matchlen = glob_test(g, namebuf+rock->inboxoffset,
			     keylen-rock->inboxoffset, &minmatch);

	if (matchlen == -1) {
	    r = 0;
	    break;
	}

	switch (r) {
	case 0:
	    /* found the entry; output it */
	    if (rock->find_namespace == NAMESPACE_SHARED &&
		rock->checkshared && rock->namespace) {
		/* special case:  LIST "" % -- output prefix only */
		r = (*rock->proc)(rock->namespace->prefix[NAMESPACE_SHARED],
				  strlen(rock->namespace->prefix[NAMESPACE_SHARED])-1,
				  1, rock->procrock);
		/* short-circuit the foreach - one mailbox is sufficient */
		r = CYRUSDB_DONE;
	    }
	    else {
		r = (*rock->proc)(namebuf+rock->inboxoffset, matchlen, 
				  1, rock->procrock);
	    }
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
int mboxlist_findall(struct namespace *namespace __attribute__((unused)),
		     char *pattern, int isadmin, char *userid, 
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
    int userlen = userid ? strlen(userid) : 0, domainlen = 0;
    char domainpat[MAX_MAILBOX_NAME+1] = ""; /* do intra-domain fetches only */

    if (config_virtdomains) {
	if (userid && (p = strrchr(userid, '@'))) {
	    userlen = p - userid;
	    domainlen = strlen(p); /* includes separator */
	    sprintf(domainpat, "%s!%s", p+1, pattern);
	}
	if ((p = strrchr(pattern, '@'))) {
	    /* global admin specified mbox@domain */
	    if (domainlen) {
		/* can't do both user@domain and mbox@domain */
		return IMAP_MAILBOX_BADNAME;
	    }

	    /* don't prepend default domain */
	    if (!(config_defdomain && !strcasecmp(config_defdomain, p+1))) {
		sprintf(domainpat, "%s!", p+1);
		domainlen = strlen(p);
	    }
	    sprintf(domainpat+domainlen, "%.*s", p - pattern, pattern);
	}
    }

    if (domainpat[0] == '\0')
	strcpy(domainpat, pattern);

    cbrock.g = glob_init(pattern, GLOB_HIERARCHY|GLOB_INBOXCASE);
    cbrock.namespace = NULL;
    cbrock.domainlen = domainlen;
    cbrock.inboxcase = glob_inboxcase(cbrock.g);
    cbrock.isadmin = isadmin;
    cbrock.auth_state = auth_state;
    cbrock.checkmboxlist = 0;	/* don't duplicate work */
    cbrock.checkshared = 0;
    cbrock.proc = proc;
    cbrock.procrock = rock;

    /* Build usermboxname */
    if (userid && (!(p = strchr(userid, '.')) || ((p - userid) > userlen)) &&
	strlen(userid)+5 < MAX_MAILBOX_NAME) {
	if (domainlen)
	    sprintf(usermboxname, "%s!", userid+userlen+1);
	sprintf(usermboxname+domainlen, "user.%.*s", userlen, userid);
	usermboxnamelen = strlen(usermboxname);
    }
    else {
	userid = NULL;
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
	else if (!strncmp(pattern,
			  usermboxname+domainlen, usermboxnamelen-domainlen) &&
		 GLOB_TEST(cbrock.g, usermboxname+domainlen) != -1) {
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
	(!strncmp(usermboxname+domainlen, pattern, usermboxnamelen-domainlen-1) ||
	 !strncasecmp("inbox.", pattern, prefixlen < 6 ? prefixlen : 6))) {

	if (!strncmp(usermboxname+domainlen, pattern, usermboxnamelen-domainlen-1)) {
	    /* switch to pattern with domain prepended */
	    glob_free(&cbrock.g);
	    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	    cbrock.inboxoffset = 0;
	}
	else {
	    cbrock.inboxoffset = domainlen + userlen;
	}

	cbrock.find_namespace = NAMESPACE_INBOX;
	/* iterate through prefixes matching usermboxname */
	r = DB->foreach(mbdb,
			usermboxname, usermboxnamelen,
			&find_p, &find_cb, &cbrock,
			NULL);
    }

    if(!r) {
	cbrock.find_namespace = NAMESPACE_USER;
	/* switch to pattern with domain prepended */
	glob_free(&cbrock.g);
	cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	cbrock.inboxoffset = 0;
	if (usermboxnamelen) {
	    usermboxname[--usermboxnamelen] = '\0';
	    cbrock.usermboxname = usermboxname;
	    cbrock.usermboxnamelen = usermboxnamelen;
	}
	/* search for all remaining mailboxes.
	   just bother looking at the ones that have the same pattern
	   prefix. */
	r = DB->foreach(mbdb,
			domainpat, domainlen + prefixlen,
			&find_p, &find_cb, &cbrock,
			NULL);
    }
    

  done:
    glob_free(&cbrock.g);

    return r;
}

int mboxlist_findall_alt(struct namespace *namespace,
			 char *pattern, int isadmin, char *userid,
			 struct auth_state *auth_state, int (*proc)(),
			 void *rock)
{
    struct find_rock cbrock;
    char usermboxname[MAX_MAILBOX_NAME+1], patbuf[MAX_MAILBOX_NAME+1];
    int usermboxnamelen = 0;
    const char *data;
    int datalen;
    int r = 0;
    char *p;
    int prefixlen, len;
    int userlen = userid ? strlen(userid) : 0, domainlen = 0;
    char domainpat[MAX_MAILBOX_NAME+1]; /* do intra-domain fetches only */

    if (config_virtdomains && userid && (p = strchr(userid, '@'))) {
	userlen = p - userid;
	domainlen = strlen(p); /* includes separator */
	sprintf(domainpat, "%s!", p+1);
    }
    else
	strcpy(domainpat, "");

    cbrock.g = glob_init(pattern, GLOB_HIERARCHY|GLOB_INBOXCASE);
    cbrock.namespace = namespace;
    cbrock.domainlen = domainlen;
    cbrock.inboxcase = glob_inboxcase(cbrock.g);
    cbrock.isadmin = isadmin;
    cbrock.auth_state = auth_state;
    cbrock.checkmboxlist = 0;	/* don't duplicate work */
    cbrock.checkshared = 0;
    cbrock.proc = proc;
    cbrock.procrock = rock;

    /* Build usermboxname */
    if (userid && (!(p = strchr(userid, '.')) || ((p - userid) > userlen)) &&
	strlen(userid)+5 < MAX_MAILBOX_NAME) {
	if (domainlen)
	    sprintf(usermboxname, "%s!", userid+userlen+1);
	sprintf(usermboxname+domainlen, "user.%.*s", userlen, userid);
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
		r = (*proc)(cbrock.inboxcase, 5, 0, rock);
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

    glob_free(&cbrock.g);

    /* Find fixed-string pattern prefix */
    for (p = pattern; *p; p++) {
	if (*p == '*' || *p == '%' || *p == '?') break;
    }
    prefixlen = p - pattern;

    /*
     * Personal (INBOX) namespace
     *
     * Append pattern to "INBOX.", search for those mailboxes next
     */
    if (userid) {
	strcpy(patbuf, "INBOX.");
	strcat(patbuf, pattern);
	cbrock.g = glob_init(patbuf, GLOB_HIERARCHY|GLOB_INBOXCASE);
	cbrock.inboxcase = glob_inboxcase(cbrock.g);
	cbrock.inboxoffset = domainlen+userlen;
	cbrock.find_namespace = NAMESPACE_INBOX;

	/* iterate through prefixes matching usermboxname */
	DB->foreach(mbdb,
		    usermboxname, usermboxnamelen,
		    &find_p, &find_cb, &cbrock,
		    NULL);

	glob_free(&cbrock.g);
    }

    if (usermboxnamelen) {
	usermboxname[--usermboxnamelen] = '\0';
	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    }

    /*
     * Other Users namespace
     *
     * If "Other Users*" can match pattern, search for those mailboxes next
     */
    len = strlen(namespace->prefix[NAMESPACE_USER])-1;
    if (!strncmp(namespace->prefix[NAMESPACE_USER], pattern,
		 prefixlen < len ? prefixlen : len)) {

	if (prefixlen < len) {
	    strcpy(domainpat+domainlen, pattern+prefixlen);
	    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	}
	else {
	    strcpy(domainpat+domainlen, "user");
	    strcat(domainpat, pattern+len);
	    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	}
	cbrock.find_namespace = NAMESPACE_USER;
	cbrock.inboxoffset = 0;
	
	/* iterate through prefixes matching usermboxname */
	strcpy(domainpat+domainlen, "user");
	DB->foreach(mbdb,
		    domainpat, strlen(domainpat),
		    &find_p, &find_cb, &cbrock,
		    NULL);

	glob_free(&cbrock.g);
    }

    /*
     * Shared namespace
     *
     * search for all remaining mailboxes.
     * just bother looking at the ones that have the same pattern prefix.
     */
    len = strlen(namespace->prefix[NAMESPACE_SHARED]);
    if (!strncmp(namespace->prefix[NAMESPACE_SHARED], pattern,
		 prefixlen < len - 1 ? prefixlen : len - 1)) {

	cbrock.find_namespace = NAMESPACE_SHARED;
	cbrock.inboxoffset = 0;

	if (prefixlen < len) {
	    /* Find pattern which matches shared namespace prefix */
	    for (p = pattern+prefixlen; *p; p++) {
		if (*p == '%') continue;
		else if (*p == '.') p++;
		break;
	    }

	    if (!*p) {
		/* special case:  LIST "" % -- see if we have a shared mbox */
		strcpy(domainpat+domainlen, "*");
		cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
		cbrock.checkshared = 1;
	    }
	    else {
		strcpy(domainpat+domainlen, p);
		cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	    }
		
	    domainpat[domainlen] = '\0';
	    DB->foreach(mbdb,
			domainpat, domainlen,
			&find_p, &find_cb, &cbrock,
			NULL);
	}
	else if (pattern[len-1] == '.') {
	    strcpy(domainpat+domainlen, pattern+len);
	    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);

	    DB->foreach(mbdb,
			domainpat, strlen(domainpat),
			&find_p, &find_cb, &cbrock,
			NULL);
	}
    }

  done:
    glob_free(&cbrock.g);

    return r;
}

/*
 * Set the quota on or create a quota root
 */
int mboxlist_setquota(const char *root, int newquota, int force)
{
    char quota_path[MAX_MAILBOX_PATH];
    char pattern[MAX_MAILBOX_PATH];
    struct quota quota;
    int have_mailbox = 1;
    int r, t;

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
    r = mboxlist_detail(quota.root, &t, NULL, NULL, NULL, NULL);
    if (r) {
	/* are we going to force the create anyway? */
	if(!force) return r;
	else {
	    have_mailbox = 0;
	    t = 0;
	}
    }

    if(t & (MBTYPE_REMOTE | MBTYPE_MOVING)) {
	/* Can't set quota on a remote mailbox */
	return IMAP_MAILBOX_NOTSUPPORTED;
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
    
    /* top level mailbox */
    if(have_mailbox)
	mboxlist_changequota(quota.root, 0, 0, &quota);
    /* submailboxes - we're using internal names here */
    mboxlist_findall(NULL, pattern, 1, 0, 0, mboxlist_changequota, &quota);
    
    r = mailbox_write_quota(&quota);
    if (quota.fd != -1) {
	close(quota.fd);
    }

    return r;
}

/*
 *  Remove a quota root
 */
int mboxlist_unsetquota(const char *root)
{
    char quota_path[MAX_MAILBOX_PATH];
    char pattern[MAX_MAILBOX_PATH];
    int fd;
    int r=0;

    if (!root[0] || root[0] == '.' || strchr(root, '/')
	|| strchr(root, '*') || strchr(root, '%') || strchr(root, '?')) {
	return IMAP_MAILBOX_BADNAME;
    }
    
    mailbox_hash_quota(quota_path, root);

    if ((fd = open(quota_path, O_RDWR, 0)) == -1) {
	/* already unset */
	return 0;
    }
    
    close(fd);

    /*
     * Have to remove it from all affected mailboxes
     */
    strcpy(pattern, root);
    strcat(pattern, ".*");
    
    /* top level mailbox */
    mboxlist_rmquota(root, 0, 0, (void *)root);
    /* submailboxes - we're using internal names here */
    mboxlist_findall(NULL, pattern, 1, 0, 0, mboxlist_rmquota, (void *)root);

    if(unlink(quota_path) == -1) {
	syslog(LOG_ERR, "could not unlink %s (%m)", quota_path);
	r = IMAP_SYS_ERROR;
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
 * Helper function to remove the quota root for 'name'
 */
static int mboxlist_rmquota(const char *name, int matchlen, int maycreate,
			    void *rock)
{
    int r;
    struct mailbox mailbox;
    const char *oldroot = (const char *) rock;

    assert(rock != NULL);

    r = mailbox_open_header(name, 0, &mailbox);
    if (r) goto error_noclose;

    r = mailbox_lock_header(&mailbox);
    if (r) goto error;

    r = mailbox_open_index(&mailbox);
    if (r) goto error;

    r = mailbox_lock_index(&mailbox);
    if (r) goto error;

    if (mailbox.quota.root) {
	if (strlen(mailbox.quota.root) != strlen(oldroot)
	    || strcmp(mailbox.quota.root, oldroot)) {
	    /* Part of a different quota root */
	    mailbox_close(&mailbox);
	    return 0;
	}

	/* Need to clear the quota root */
	free(mailbox.quota.root);
	mailbox.quota.root = NULL;

	r = mailbox_write_header(&mailbox);	
	if(r) goto error;
    }

    mailbox_close(&mailbox);
    return 0;

 error:
    mailbox_close(&mailbox);
 error_noclose:
    syslog(LOG_ERR, "LOSTQUOTA: unable to remove quota root %s for %s: %s",
	   oldroot, name, error_message(r));
    
    return 0;
}

/*
 * Helper function to change the quota root for 'name' to that pointed
 * to by the static global struct pointer 'mboxlist_newquota'.
 */
static int mboxlist_changequota(const char *name, int matchlen, int maycreate,
				void *rock)
{
    int r;
    struct mailbox mailbox;
    struct quota *mboxlist_newquota = (struct quota *) rock;

    assert(rock != NULL);

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
		   "LOSTQUOTA: unable to record free of %lu bytes in quota %s",
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

    /* Note, we're a callback, and it's not a huge tragedy if we
     * fail, so we don't ever return a failure */
    return 0;
}

/* must be called after config_init */
void mboxlist_init(int myflags)
{
    int r;
    char dbdir[1024];
    int flags = 0;

    if (myflags & MBOXLIST_SYNC) {
	r = DB->sync();
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

void mboxlist_close(void)
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
}

/* hash the userid to a file containing the subscriptions for that user */
char *mboxlist_hash_usersubs(const char *userid)
{
    char *fname = xmalloc(strlen(config_dir) + sizeof(FNAME_DOMAINDIR) +
			  sizeof(FNAME_USERDIR) + strlen(userid) +
			  sizeof(FNAME_SUBSSUFFIX) + 10);
    char c, *domain;

    if (config_virtdomains && (domain = strchr(userid, '@'))) {
	char d = (char) dir_hash_c(domain+1);
	*domain = '\0';  /* split user@domain */
	c = (char) dir_hash_c(userid);
	sprintf(fname, "%s%s%c/%s%s%c/%s%s", config_dir, FNAME_DOMAINDIR, d,
		domain+1, FNAME_USERDIR, c, userid, FNAME_SUBSSUFFIX);
	*domain = '@';  /* replace '@' */
    }
    else {
	c = (char) dir_hash_c(userid);
	sprintf(fname, "%s%s%c/%s%s", config_dir, FNAME_USERDIR, c, userid,
		FNAME_SUBSSUFFIX);
    }

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
int mboxlist_findsub(struct namespace *namespace __attribute__((unused)),
		     char *pattern, int isadmin, char *userid, 
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
    int userlen = userid ? strlen(userid) : 0, domainlen = 0;
    char domainpat[MAX_MAILBOX_NAME+1]; /* do intra-domain fetches only */

    if (config_virtdomains && userid && (p = strchr(userid, '@'))) {
	userlen = p - userid;
	domainlen = strlen(p); /* includes separator */
	sprintf(domainpat, "%s!%s", p+1, pattern);
    }
    else
	strcpy(domainpat, pattern);

    cbrock.g = glob_init(pattern, GLOB_HIERARCHY|GLOB_INBOXCASE);
    cbrock.namespace = NULL;
    cbrock.domainlen = domainlen;
    cbrock.inboxcase = glob_inboxcase(cbrock.g);
    cbrock.isadmin = 1;		/* user can always see their subs */
    cbrock.auth_state = auth_state;
    cbrock.checkmboxlist = !force;
    cbrock.checkshared = 0;
    cbrock.proc = proc;
    cbrock.procrock = rock;

    /* open the subscription file that contains the mailboxes the 
       user is subscribed to */
    if ((r = mboxlist_opensubs(userid, &subs)) != 0) {
	goto done;
    }

    /* Build usermboxname */
    if (userid && (!(p = strchr(userid, '.')) || ((p - userid) > userlen)) &&
	strlen(userid)+5 < MAX_MAILBOX_NAME) {
	if (domainlen)
	    sprintf(usermboxname, "%s!", userid+userlen+1);
	sprintf(usermboxname+domainlen, "user.%.*s", userlen, userid);
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
	else if (!strncmp(pattern,
			  usermboxname+domainlen, usermboxnamelen-domainlen) &&
		 GLOB_TEST(cbrock.g, usermboxname+domainlen) != -1) {
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
	(!strncmp(usermboxname+domainlen, pattern, usermboxnamelen-domainlen-1) ||
	 !strncasecmp("inbox.", pattern, prefixlen < 6 ? prefixlen : 6))) {

	if (!strncmp(usermboxname+domainlen, pattern, usermboxnamelen-domainlen-1)) {
	    /* switch to pattern with domain prepended */
	    glob_free(&cbrock.g);
	    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	    cbrock.inboxoffset = 0;
	}
	else {
	    cbrock.inboxoffset = strlen(userid);
	}

	cbrock.find_namespace = NAMESPACE_INBOX;
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

    cbrock.find_namespace = NAMESPACE_USER;
    /* switch to pattern with domain prepended */
    glob_free(&cbrock.g);
    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
    cbrock.inboxoffset = 0;
    if (usermboxnamelen) {
	usermboxname[--usermboxnamelen] = '\0';
	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    }
    /* search for all remaining mailboxes.
       just bother looking at the ones that have the same pattern prefix. */
    SUBDB->foreach(subs, domainpat, domainlen + prefixlen, 
		   &find_p, &find_cb, &cbrock, NULL);

  done:
    if (subs) mboxlist_closesubs(subs);
    glob_free(&cbrock.g);

    return r;
}

int mboxlist_findsub_alt(struct namespace *namespace,
			 char *pattern, int isadmin, char *userid, 
			 struct auth_state *auth_state, 
			 int (*proc)(), void *rock, int force)
{
    struct db *subs = NULL;
    struct find_rock cbrock;
    char usermboxname[MAX_MAILBOX_NAME+1], patbuf[MAX_MAILBOX_NAME+1];
    int usermboxnamelen = 0;
    const char *data;
    int datalen;
    int r = 0;
    char *p;
    int prefixlen, len;
    int userlen = userid ? strlen(userid) : 0, domainlen = 0;
    char domainpat[MAX_MAILBOX_NAME+1]; /* do intra-domain fetches only */

    if (config_virtdomains && userid && (p = strchr(userid, '@'))) {
	userlen = p - userid;
	domainlen = strlen(p); /* includes separator */
	sprintf(domainpat, "%s!", p+1);
    }
    else
	strcpy(domainpat, "");

    cbrock.g = glob_init(pattern, GLOB_HIERARCHY|GLOB_INBOXCASE);
    cbrock.namespace = namespace;
    cbrock.domainlen = domainlen;
    cbrock.inboxcase = glob_inboxcase(cbrock.g);
    cbrock.isadmin = 1;		/* user can always see their subs */
    cbrock.auth_state = auth_state;
    cbrock.checkmboxlist = !force;
    cbrock.checkshared = 0;
    cbrock.proc = proc;
    cbrock.procrock = rock;

    /* open the subscription file that contains the mailboxes the 
       user is subscribed to */
    if ((r = mboxlist_opensubs(userid, &subs)) != 0) {
	goto done;
    }

    /* Build usermboxname */
    if (userid && (!(p = strchr(userid, '.')) || ((p - userid) > userlen)) &&
	strlen(userid)+5 < MAX_MAILBOX_NAME) {
	if (domainlen)
	    sprintf(usermboxname, "%s!", userid+userlen+1);
	sprintf(usermboxname+domainlen, "user.%.*s", userlen, userid);
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
		r = (*proc)(cbrock.inboxcase, 5, 0, rock);
	    }
	}
	strcpy(usermboxname+usermboxnamelen, ".");
	usermboxnamelen++;

	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    }

    if (r) goto done;

    glob_free(&cbrock.g);

    /* Find fixed-string pattern prefix */
    for (p = pattern; *p; p++) {
	if (*p == '*' || *p == '%' || *p == '?') break;
    }
    prefixlen = p - pattern;

    /*
     * Personal (INBOX) namespace
     *
     * Append pattern to "INBOX.", search for those subscriptions next
     */
    if (userid) {
	strcpy(patbuf, "INBOX.");
	strcat(patbuf, pattern);
	cbrock.g = glob_init(patbuf, GLOB_HIERARCHY|GLOB_INBOXCASE);
	cbrock.inboxcase = glob_inboxcase(cbrock.g);
	cbrock.inboxoffset = domainlen+userlen;
	cbrock.find_namespace = NAMESPACE_INBOX;

	/* iterate through prefixes matching usermboxname */
	SUBDB->foreach(subs,
		       usermboxname, usermboxnamelen,
		       &find_p, &find_cb, &cbrock,
		       NULL);

	glob_free(&cbrock.g);

	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    } else {
	cbrock.usermboxname = NULL;
	cbrock.usermboxnamelen = 0;
    }

    if (usermboxnamelen) {
	usermboxname[--usermboxnamelen] = '\0';
	cbrock.usermboxname = usermboxname;
	cbrock.usermboxnamelen = usermboxnamelen;
    }

    /*
     * Other Users namespace
     *
     * If "Other Users*" can match pattern, search for those subscriptions next
     */
    len = strlen(namespace->prefix[NAMESPACE_USER])-1;
    if (!strncmp(namespace->prefix[NAMESPACE_USER], pattern,
		 prefixlen < len ? prefixlen : len)) {

	if (prefixlen < len) {
	    strcpy(domainpat+domainlen, pattern+prefixlen);
	    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	}
	else {
	    strcpy(domainpat+domainlen, "user");
	    strcat(domainpat, pattern+len);
	    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	}
	cbrock.find_namespace = NAMESPACE_USER;
	cbrock.inboxoffset = 0;
	
	/* iterate through prefixes matching usermboxname */
	strcpy(domainpat+domainlen, "user");
	SUBDB->foreach(subs,
		       domainpat, strlen(domainpat),
		       &find_p, &find_cb, &cbrock,
		       NULL);

	glob_free(&cbrock.g);
    }

    /*
     * Shared namespace
     *
     * search for all remaining subscriptions.
     * just bother looking at the ones that have the same pattern prefix.
     */
    len = strlen(namespace->prefix[NAMESPACE_SHARED]);
    if (!strncmp(namespace->prefix[NAMESPACE_SHARED], pattern,
		 prefixlen < len - 1 ? prefixlen : len - 1)) {

	cbrock.find_namespace = NAMESPACE_SHARED;
	cbrock.inboxoffset = 0;

	if (prefixlen < len) {
	    /* Find pattern which matches shared namespace prefix */
	    for (p = pattern+prefixlen; *p; p++) {
		if (*p == '%') continue;
		else if (*p == '.') p++;
		break;
	    }

	    if (!*p) {
		/* special case:  LSUB "" % -- see if we have a shared mbox */
		strcpy(domainpat+domainlen, "*");
		cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
		cbrock.checkshared = 1;
	    }
	    else {
		strcpy(domainpat+domainlen, p);
		cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);
	    }

	    domainpat[domainlen] = '\0';
	    SUBDB->foreach(subs,
			   domainpat, domainlen,
			   &find_p, &find_cb, &cbrock,
			   NULL);
	}
	else if (pattern[len-1] == '.') {
	    strcpy(domainpat+domainlen, pattern+len);
	    cbrock.g = glob_init(domainpat, GLOB_HIERARCHY);

	    SUBDB->foreach(subs,
			   domainpat, strlen(domainpat),
			   &find_p, &find_cb, &cbrock,
			   NULL);
	}
    }

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
	if ((cyrus_acl_myrights(auth_state, acl) & (ACL_READ|ACL_LOOKUP)) == 0) {
	    mboxlist_closesubs(subs);
	    return IMAP_MAILBOX_NONEXISTENT;
	}
    }

    if (add) {
	r = SUBDB->store(subs, name, strlen(name), "", 0, NULL);
    } else {
	r = SUBDB->delete(subs, name, strlen(name), NULL, 0);
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
