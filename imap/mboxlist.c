/* mboxlist.c -- Mailbox list manipulation routines
 * 
 * Copyright 1998 Carnegie Mellon University
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
 *
 */
/*
 * $Id: mboxlist.c,v 1.101 2000/01/28 22:09:47 leg Exp $
 */

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
#include "config.h"
#include "map.h"
#include "bsearch.h"
#include "lock.h"
#include "util.h"
#include "retry.h"
#include "mailbox.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "xmalloc.h"

#include "acap.h"
#include "acapmbox.h"

#include "gun.h"

#include "mboxlist.h"


struct mbox_txn {
    DB_TXN *tid;
    enum {
	TXN_CREATE,
	TXN_DELETE,
	TXN_RENAME,
	TXN_SETACL
    } txn_type;
};

struct mbox_txn_create {
    struct mbox_txn a;
    struct mbox_entry *mboxent;
};

struct mbox_txn_delete {
    struct mbox_txn a;
    struct mbox_entry *mboxent;
    int deleteuser;
    int deletequotaroot;
};

struct mbox_txn_rename {
    struct mbox_txn a;
    char *oldname;
    char *oldpath;
    struct mbox_entry *newent;
};

struct mbox_txn_setacl {
    struct mbox_txn a;
    struct mbox_entry *newent;
};

acl_canonproc_t mboxlist_ensureOwnerRights;

static DB *mbdb;
static DB_ENV *dbenv;

static int mboxlist_dbinit = 0,
    mboxlist_dbopen = 0;

static int mboxlist_opensubs();
static void mboxlist_closesubs();

static struct quota *mboxlist_newquota;
static int mboxlist_changequota();

static char *mboxlist_hash_usersubs(const char *userid);

#define FNAME_DBDIR "/db"
#define FNAME_USERDIR "/user/"
#define FNAME_SUBSSUFFIX ".sub"

acap_conn_t *acap_conn = NULL;

int using_acap = 0; /* wheather acap support is turned on */

const char *acap_authname = NULL;
const char *acap_realm = NULL;
const char *acap_password = NULL;

/* callback to get userid or authid */
static int getsimple(void *context __attribute__((unused)),
		     int id,
		     const char **result,
		     unsigned *len)
{
  char *username;
  char *authid;

  if (! result)
    return SASL_BADPARAM;

  switch (id) {
  case SASL_CB_GETREALM:
      if (acap_realm == NULL) return SASL_FAIL;

      *result = acap_realm;
      if (len)
	  *len = acap_realm ? strlen(acap_realm) : 0;
      return SASL_FAIL;
      break;

  case SASL_CB_USER:
    *result = acap_authname;
    if (len)
      *len = acap_authname ? strlen(acap_authname) : 0;
    break;
  case SASL_CB_AUTHNAME:
    *result = acap_authname;
    if (len)
      *len = acap_authname ? strlen(acap_authname) : 0;
      break;
  case SASL_CB_LANGUAGE:
    *result = NULL;
    if (len)
      *len = 0;
    break;
  default:
    return SASL_BADPARAM;
  }
  return SASL_OK;
}

/* callback to get password */
static int
getsecret(sasl_conn_t *conn,
	  void *context __attribute__((unused)),
	  int id,
	  sasl_secret_t **psecret)
{
  if (! conn || ! psecret || id != SASL_CB_PASS)
    return SASL_BADPARAM;

  if (acap_password==NULL)
  {
      syslog(LOG_ERR,"Unable to find acap_password\n");      
      return SASL_FAIL;
  }

  *psecret = (sasl_secret_t *) malloc(sizeof(sasl_secret_t)+strlen(acap_password)+1);
  if (! *psecret)
    return SASL_FAIL;

  strcpy((*psecret)->data, acap_password);
  (*psecret)->len=strlen(acap_password);

  return SASL_OK;
}

/* callbacks we support */
static sasl_callback_t callbacks[] = {
  {
#ifdef SASL_CB_GETREALM
    SASL_CB_GETREALM, &getsimple, NULL
  }, {
#endif
    SASL_CB_AUTHNAME, &getsimple, NULL
  }, {
    SASL_CB_PASS, &getsecret, NULL    
  }, {
    SASL_CB_LIST_END, NULL, NULL
  }
};

/* initialize acap connection if necessary */
int mboxlist_acapinit(void)
{
    int r;
    char *str;
    const char *acapserver;

    /* if it's already initialized just return */
    if (acap_conn != NULL) return 0;

    
    /* See if it's turned on */
    if (config_getswitch("useacap", 0)==0) {
	using_acap = 0;
	return 0;
    }
    using_acap = 1;
    
    r = acap_init();
    if (r != ACAP_OK) {
	syslog(LOG_ERR,"acap_init failed()");
	return -1;
    }

    r = sasl_client_init(callbacks);
    if (r != SASL_OK) {
	syslog(LOG_ERR,"sasl_client_init() failed");
	return -2;
    }

    acap_authname = config_getstring("acap_authname", NULL);
    if (acap_authname == NULL)
    {
	syslog(LOG_ERR,"unable to find option acap_authname");
	return -3;
    }

    /* these aren't required */
    acap_password = config_getstring("acap_password", NULL);
    acap_realm = config_getstring("acap_realm", NULL);
    

    acapserver = config_getstring("acap_server", NULL);
    if (acapserver == NULL)
    {
	syslog(LOG_ERR,"unable to find option acap_server");
	return -4;
    }

    str = (char *) xmalloc (strlen("acap://")+strlen(acap_authname)+1+strlen(acapserver)+2);
    
    sprintf(str,"acap://%s@%s/",acap_authname,acapserver);
    
    r = acap_conn_connect(str, &acap_conn);
    free(str);
    if (r != SASL_OK) {
	acap_conn = NULL; /* xxx leaked? */
	syslog(LOG_ERR,"acap_conn_connect() failed");
	return -5;
    }

    return 0;
}

int convert_acap_errorcode(int r)
{
    /* xxx */
    return IMAP_IOERROR;
}

/*
 * Check our configuration for consistency, die if there's a problem
 */
void mboxlist_checkconfig()
{
}

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
    unsigned long offset, len, partitionlen, acllen;
    char *partition, *acl;
    static char *aclresult;
    static int aclresultalloced;
    int r;
    DBT key, data;
    struct mbox_entry *mboxent;

    memset(&data, 0, sizeof(key));

    memset(&key, 0, sizeof(key));
    key.data = (char *) name;
    key.size = strlen(name);

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
    unsigned long offset, len, partitionlen;
    DBT key, data;
    struct mbox_entry *mboxent;
    char optionbuf[MAX_MAILBOX_NAME+1];
    char *partition;
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
    unsigned long offset;
    char *acl;
    char *defaultacl, *identifier, *rights;
    char parent[MAX_MAILBOX_NAME+1];
    unsigned long parentlen;
    char *parentname, *parentpartition, *parentacl;
    unsigned long parentpartitionlen, parentacllen;
    DBT key, data;
    struct mbox_entry *mboxent;

    /* Check for invalid name/partition */
    if (partition && strlen(partition) > MAX_PARTITION_LEN) {
	return IMAP_PARTITION_UNKNOWN;
    }
    r = mboxname_policycheck(name);
    if (r) return r;

    if (mbtype & MBTYPE_NETNEWS) r = mboxname_netnewscheck(name);
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
		while (*identifier && isspace(*identifier)) identifier++;
		rights = identifier;
		while (*rights && !isspace(*rights)) rights++;
		if (!*rights) break;
		*rights++ = '\0';
		while (*rights && isspace(*rights)) rights++;
		if (!*rights) break;
		p = rights;
		while (*p && !isspace(*p)) p++;
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

int real_mboxlist_createmailbox(char *name, int mbtype, char *partition, 
				int isadmin, char *userid, 
				struct auth_state *auth_state,
				struct mbox_txn **rettid)
{
    int r;
    unsigned long offset, len;
    char *acl = NULL;
    char buf2[MAX_MAILBOX_PATH];
    const char *root;
    char *newpartition = NULL;
    int newlistfd;
    struct iovec iov[10];
    int n;
    struct mailbox newmailbox;
    DB_TXN *tid;
    DBT key, keydel, data;
    struct mbox_entry *mboxent = NULL;
    struct mbox_txn_create *mtxn = NULL;
    acapmbox_data_t mboxdata;
    int madereserved = 0; /* if we made the acap entry (so we can know to roll back) */

    if (rettid && *rettid) {
	/* two phase commit */
	mtxn = (struct mbox_txn_create *) *rettid;
	assert(mtxn->a.txn_type == TXN_CREATE && mtxn->mboxent);

	tid = mtxn->a.tid;
	mboxent = mtxn->mboxent;
	r = 0;

	goto done;
    }

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

    /* 3. open ACAP connection if necessary */
    r = mboxlist_acapinit();
    if (r != 0) goto done;


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

    /* 5. create ACAP entry and set as reserved (CRASH: ACAP inconsistant) */
    if (acap_conn != NULL)
    {
	char *postaddr = NULL;
	char *url = NULL;

	postaddr = xmalloc(strlen(name)+50);
	sprintf(postaddr,"post+%s@andrew.cmu.edu",name); /* xxx */

	url = xmalloc(strlen(name)+50);
	sprintf(url,"imap://%s/%s","polarbear.andrew.cmu.edu",name); /* xxx */

	memset(&mboxdata, '\0', sizeof(acapmbox_data_t));

	mboxdata.name = name;	
	mboxdata.post = postaddr;
	mboxdata.haschildren = 0; /* xxx */
	mboxdata.url = url;
	/* all other are initialized to zero */
	
	r = acapmbox_create(acap_conn, 
			    name,
			    &mboxdata);

	free(postaddr);
	free(url);

	if (r != ACAP_OK)
	{
	    r = convert_acap_errorcode(r);
	    goto done;
	}
	madereserved = 1; /* so we can roll back on failure */
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

    if (!r) {
	/* ACAP: reserve mailbox name */
    }

    if (!r && rettid) {
	/* we just prepare the transaction; we'll finish it later */
        switch (r = txn_prepare(tid)) {
        case 0:
	    mtxn = (struct mbox_txn_create *) 
		xmalloc(sizeof(struct mbox_txn_create));
	    mtxn->a.tid = tid;
	    mtxn->a.txn_type = TXN_CREATE;
	    mtxn->mboxent = mboxent;
	    *rettid = (struct mbox_txn *) mtxn;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on prepare: %s", db_strerror(r));
	    *rettid = NULL;
	    r = IMAP_IOERROR;
	    break;
	}
	return r;
    }

 done: /* ALL DATABASE OPERATIONS DONE; NEED TO DO FILESYSTEM OPERATIONS */
    if (!r && !(mboxent->mbtype & MBTYPE_REMOTE)) {
	/* recalculate root */
	sprintf(buf2, "partition-%s", mboxent->partition);
	root = config_getstring(buf2, (char *)0);
	
	/* Create new mailbox and move new mailbox list file into place */
	mailbox_hash_mbox(buf2, root, mboxent->name);
	r = mailbox_create(mboxent->name, buf2, mboxent->acls, 
			   ((mboxent->mbtype & MBTYPE_NETNEWS) ?
			    MAILBOX_FORMAT_NETNEWS :
			    MAILBOX_FORMAT_NORMAL), 
			   &newmailbox);
	if (!r) {
	    mailbox_close(&newmailbox);
	}
    }

    if (acl) free(acl);
    if (newpartition) free(newpartition);
    if (mboxent) free(mboxent);
    if (mtxn) free(mtxn);

    if (rettid) *rettid = NULL;
    
    if (r != 0) {
	int r2;

	/* delete ACAP entry if we made it */
	if ((madereserved == 1) && (acap_conn != NULL))
	{
	    r = acapmbox_delete(acap_conn,
				name);
	    /* xxx Can we deal with this failure? */
	}

	r2 = txn_abort(tid);

	switch (r2) {
	case 0:
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on abort: %s", db_strerror(r2));
	}
    } else {
	switch (r = txn_commit(tid, 0)) {
	case 0: 
	    /* ACAP: set mailbox here */
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s", db_strerror(r));
	    r = IMAP_IOERROR;
	}
    }

    /* 9. set ACAP entry as commited (CRASH: commited) */
    if (r == 0)
    {
	if (acap_conn != NULL)
	{
	    r = acapmbox_markactive(acap_conn,
				    name);
	    if (r!=0)
	    {
		syslog(LOG_ERR,"ACAP probably in inconsistant state for %s\n",name);
		r = convert_acap_errorcode(r);
	    }
	}

    }
   
    return r;
}

/* insert an entry for the proxy */
int mboxlist_insertremote(char *name, int mbtype, char *host, char *acl,
			  void **rettid)
{
    DB_TXN *tid;
    DBT key, keydel, data;
    struct mbox_entry *mboxent = (struct mbox_entry *)
	xmalloc(sizeof(struct mbox_entry) + strlen(acl));
    int r = 0;
    
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
    } else if (rettid) {
	/* just get ready to commit */
	switch (r = txn_prepare(tid)) {
	case 0:
	    *rettid = tid;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   db_strerror(r));
	    r = IMAP_IOERROR;
	    break;
	}
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
 *
 * 1. Begin transaction
 * 2. Verify ACL's
 * 3. Open ACAP connection if necessary
 * 4. ACAP mark entry reserved
 * 5. remove from database
 * 6. remove from disk
 * 7. commit transaction
 * 8. delete from ACAP
 *
 */
int real_mboxlist_deletemailbox(char *name, int isadmin, char *userid, 
				struct auth_state *auth_state, int checkacl,
				struct mbox_txn **rettid)
{
    int r;
    char *acl;
    long access;
    int deleteuser = 0; /* if we are deleting user.<user> */
    unsigned long offset, len;
    char submailboxname[MAX_MAILBOX_NAME+1];
    int newlistfd;
    int n;
    struct mailbox mailbox;
    int deletequotaroot = 0;
    char *path;
    DB_TXN *tid;
    DBT key, data;
    DBC *cursor = NULL;
    struct mbox_entry *mboxent = NULL;
    struct mbox_txn_delete *mtxn = NULL;

    if (rettid && *rettid) {
	/* two phase commit */
	mtxn = (struct mbox_txn_delete *) *rettid;
	assert(mtxn->a.txn_type == TXN_DELETE && mtxn->mboxent);

	tid = mtxn->a.tid;
	mboxent = mtxn->mboxent;
	deleteuser = mtxn->deleteuser;
	deletequotaroot = mtxn->deletequotaroot;
	r = 0;

	goto done;
    }

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    /* restart transaction here */
    if (0) {
	int r2;

      retry:
	if ((r2 = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s", db_strerror(r2));
	    if (rettid) *rettid = NULL;
	    return IMAP_IOERROR;
	}
    }

    /* begin transaction */
    if ((r = txn_begin(dbenv, NULL, &tid, 0)) != 0) {
	syslog(LOG_ERR, "DBERROR: error beginning txn: %s", db_strerror(r));
	if (rettid) *rettid = NULL;
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
	if (!(acl_myrights(auth_state, acl) & ACL_DELETE)) {
	    r = IMAP_PERMISSION_DENIED;
	    goto done;
	}
	
	deleteuser = 1;
    }

    /* 3. open ACAP connection if necessary */
    r = mboxlist_acapinit();
    if (r != 0) goto done;

    /* 4. ACAP mark entry reserved */
    if (acap_conn != NULL)
    {
	r = acapmbox_markreserved(acap_conn,
				  name);
	if ( r != ACAP_OK)
	{
	    r = convert_acap_errorcode(r);
	    goto done;
	}
    }



    key.data = name;
    key.size = strlen(name);
    r = mbdb->get(mbdb, tid, &key, &data, DB_RMW);
    if (!r) {
	int sz;

	mboxent = data.data;
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
    default:
	goto done;
    }

    /* check if user has Delete right */
    access = acl_myrights(auth_state, mboxent->acls);
    if (checkacl && !(access & ACL_DELETE)) {
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
	goto done;
	break;
    }

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
	    syslog(LOG_ERR, "unable to create cursor in delete");
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

    if (!r && rettid) {
	/* get ready to commit; we do the filesystem operations on commit */
	switch (r = txn_prepare(tid)) {
	case 0:
	    mtxn = (struct mbox_txn_delete *) 
		xmalloc(sizeof(struct mbox_txn_delete));
	    mtxn->a.tid = tid;
	    mtxn->a.txn_type = TXN_DELETE;
	    mtxn->mboxent = mboxent;
	    mtxn->deleteuser = deleteuser;
	    mtxn->deletequotaroot = deletequotaroot;
	    *rettid = (struct mbox_txn *) mtxn;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on prepare: %s", db_strerror(r));
	    *rettid = NULL;
	    r = IMAP_IOERROR;
	    break;
	}

	/* we'll finish on the second phase */
	return r;
    }

  done: /* ALL DATABASE OPERATIONS DONE; NEED TO DO FILESYSTEM OPERATIONS */
    /*
     * See if we have to remove mailbox's quota root
     *
     * NB: this doesn't catch all cases.  We don't handle removing
     * orphaned quota roots on renaming or when inside the
     * ``if (deleteuser)'' code above.
     */
    if (!r) {
	/* ACAP: delete mailbox now */

    }

    if (!r && !(mboxent->mbtype & MBTYPE_REMOTE)) {
	if (deleteuser) {
	    /* Delete any subscription list file */
	    char *fname = mboxlist_hash_usersubs(mboxent->name + 5);
	    
	    (void) unlink(fname);
	    free(fname);
	}

	r = mboxlist_getpath(mboxent->partition, mboxent->name, &path);
	if (!r) r = mailbox_open_header_path(mboxent->name, path, 
					     mboxent->acls, 0, &mailbox, 0);

	/* remove the mailbox */
	if (!r) r = mailbox_delete(&mailbox, deletequotaroot);
    } /* end !remote */

    if (mboxent) free(mboxent);
    if (mtxn) free(mtxn);

    if (r != 0) {

	if (acap_conn != NULL)
	{
	    r = acapmbox_markactive(acap_conn,
				    name);
	    if ( r != ACAP_OK)
	    {
		r = convert_acap_errorcode(r);
	    }
	}

	switch (r = txn_abort(tid)) {
	case 0:
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on abort: %s",
		   db_strerror(r));
	}
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

    /* 8. delete from ACAP */
    if (acap_conn != NULL)
    {
	r = acapmbox_delete(acap_conn,
			    name);
	if (r!=0)
	{
	    syslog(LOG_ERR,"Error deleting mailbox entry on ACAP server for %s\n",name);
	    r = convert_acap_errorcode(r);
	}
    }

    return r;
}

/*
 * Rename/move a mailbox
 *
 *
 *
 * 1. start transaction
 * 2. verify acl's
 * 3. open acap connection if needed
 * 4. Delete entry from berkeley db
 * 5. ACAP make the new entry
 * 6. set old ACAP entry as reserved
 * 7. delete from disk
 * 8. commit transaction
 * 9. set new ACAP entry commited
 * 10. delete old ACAP entry
 *
 */
int real_mboxlist_renamemailbox(char *oldname, char *newname, char *partition, 
				int isadmin, char *userid, 
				struct auth_state *auth_state, 
				struct mbox_txn **rettid)
{
    int r;
    long access;
    int isusermbox = 0;
    int mbtype;
    char *oldpath = NULL;
    char *oldpath_alloc = NULL;
    char newpath[MAX_MAILBOX_PATH];
    char buf2[MAX_MAILBOX_PATH];
    char *oldacl;
    const char *root;
    DB_TXN *tid;
    DBT key, data;
    struct mbox_entry *mboxent = NULL, *newent = NULL;
    char *newpartition = NULL;
    struct mbox_txn_rename *mtxn = NULL;
    int acap_madenew = 0;
    int acap_markedold = 0;
    char *oldname_tofree = NULL;

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    if (rettid && *rettid) {
	/* two phase commit */
	mtxn = (struct mbox_txn_rename *) *rettid;
	assert(mtxn->a.txn_type == TXN_RENAME && mtxn->oldname);
	
	tid = mtxn->a.tid;
	oldname = mtxn->oldname;
	oldpath = mtxn->oldpath;
	newent = mtxn->newent;
	r = 0;

	goto done;
    }

    /* we just can't rename if there isn't enough info */
    if (partition && !strcmp(partition, "news")) {
	if (rettid) *rettid = NULL;
	return IMAP_MAILBOX_NOTSUPPORTED;
    }

    oldname = xstrdup(oldname);	/* we need a persistant copy of this */
    oldname_tofree = oldname;

    /* place to retry transaction */
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
    if ((r = txn_begin(dbenv, NULL, &tid, 0)) != 0) {
	syslog(LOG_ERR, "DBERROR: error beginning txn: %s", db_strerror(r));
	if (rettid) *rettid = NULL;
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
	oldpath = (char *) xmalloc(MAX_MAILBOX_PATH);
	oldpath_alloc = oldpath; /* save for freeing later */
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
	    if (!(access & ACL_DELETE)) {
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
	if (!(access & ACL_DELETE)) {
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
    r = mboxlist_acapinit();
    if (r != 0) goto done;


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

    if (!r) {
	/* ACAP: reserve new mailbox name */
    }

    if (!r && rettid) {
	/* we just prepare the transaction; we'll finish it later */
	switch (r = txn_prepare(tid)) {
	case 0:
	    mtxn = (struct mbox_txn_rename *)
		xmalloc(sizeof(struct mbox_txn_rename));
	    mtxn->a.tid = tid;
	    mtxn->a.txn_type = TXN_RENAME;
	    mtxn->oldname = oldname;
	    mtxn->oldpath = oldpath;
	    mtxn->newent = newent;
	    *rettid = (struct mbox_txn *) mtxn;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on prepare: %s", db_strerror(r));
	    *rettid = NULL;
	    r = IMAP_IOERROR;
	    break;
	}
	return r;
    }

    /* 5. ACAP make the new entry */
    if (acap_conn != NULL)
    {
	r = acapmbox_copy(acap_conn,
			  oldname,
			  newname);
	if (r != ACAP_OK)
	{
	    r = convert_acap_errorcode(r);
	    goto done;
	}
	acap_madenew = 1;
    }

    /* 6. set old ACAP entry as reserved */
    if (acap_conn != NULL)
    {
	r =  acapmbox_markreserved(acap_conn,
				   oldname);
	if (r != ACAP_OK)
	{
	    r = convert_acap_errorcode(r);
	    goto done;
	}
	acap_markedold = 1;
    }

 done: /* ALL DATABASE OPERATIONS DONE; NEED TO DO FILESYSTEM OPERATIONS */
    if (!r) {
	/* ACAP: delete mailbox now */

    }

    if (!r && !(newent->mbtype & MBTYPE_REMOTE)) {
	/* Get partition's path */
	sprintf(buf2, "partition-%s", newent->partition);
	root = config_getstring(buf2, (char *)0);

	/* Rename the actual mailbox */
	mailbox_hash_mbox(newpath, root, newname);
	
	r = mailbox_rename(oldname, oldpath, newent->acls, newent->name, 
			   newpath, isusermbox, NULL, NULL);
    }

    if (r != 0) {
	int r2;
	
	/* unroll acap operations if necessary */
	if ((acap_madenew == 1) && (acap_conn != NULL))
	{
	    r2 = acapmbox_delete(acap_conn,
				 newname);
	    if (r2 != 0) syslog(LOG_ERR,"Error cleaning up %s\n",newname);
	}

	if ((acap_markedold == 1) && (acap_conn != NULL))
	{
	    r2 = acapmbox_markactive(acap_conn,
				     oldname);
	    if (r2 != 0) syslog(LOG_ERR,"Error setting %s as active in rollback\n",oldname);
	}
	
	txn_abort(tid);
	if (rettid) *rettid = NULL;
    } else {
	/* commit now */
	switch (r = txn_commit(tid, 0)) {
	case 0: 
	    /* 9. set new ACAP entry commited */
	    if (acap_conn != NULL)
	    {
		r = acapmbox_markactive(acap_conn,
					newname);
	    }
	    

	    /* 10. delete old ACAP entry */
	    if (acap_conn != NULL)
	    {
		if (r == ACAP_OK)
		{
		    r = acapmbox_delete(acap_conn,
					oldname);
		}

		if (r != ACAP_OK)
		{
		    r = convert_acap_errorcode(r);
		    goto done;
		}
	    }

	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   db_strerror(r));
	    r = IMAP_IOERROR;
	}
    }

    /* free memory */
    if (newpartition) free(newpartition);
    if (oldpath_alloc) free(oldpath_alloc);
    if (oldname_tofree) free(oldname_tofree);
    if (newent) free(newent);
    if (mtxn) free(mtxn);
    
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
int real_mboxlist_setacl(char *name, char *identifier, char *rights, 
			 int isadmin, char *userid, 
			 struct auth_state *auth_state, 
			 struct mbox_txn **rettid)
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
    int n;
    DB_TXN *tid;
    DBT key, data;
    struct mbox_entry *oldent, *newent=NULL;
    struct mbox_txn_setacl *mtxn = NULL;

    if (rettid && *rettid) {
	/* two phase commit */
	mtxn = (struct mbox_txn_setacl *) *rettid;
	assert(mtxn->a.txn_type == TXN_SETACL && mtxn->newent);

	tid = mtxn->a.tid;
	newent = mtxn->newent;
	r = 0;

	goto done;
    }

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
	    if (rettid) *rettid = NULL;
	    return IMAP_IOERROR;
	}
    }

    mailbox_isopen = 0;

    /* begin transaction */
    if ((r = txn_begin(dbenv, NULL, &tid, 0)) != 0) {
	syslog(LOG_ERR, "DBERROR: error beginning txn: %s", db_strerror(r));
	if (rettid) *rettid = NULL;
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
	    break;
	case DB_LOCK_DEADLOCK:
	    goto retry;
	default:
	    syslog(LOG_ERR, "DBERROR: error fetching %s: %s",
		   name, db_strerror(r));
	    r = IMAP_IOERROR;
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
    r = mboxlist_acapinit();
    if (r != 0) goto done;
    

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

    if (rettid) {
	/* just get ready to commit */
	switch (r = txn_prepare(tid)) {
	case 0:
	    mtxn = (struct mbox_txn_setacl *)
		xmalloc(sizeof(struct mbox_txn_setacl));
	    mtxn->a.tid = tid;
	    mtxn->a.txn_type = TXN_SETACL;
	    mtxn->newent = newent;

	    *rettid = (struct mbox_txn *) mtxn;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on prepare: %s", db_strerror(r));
	    r = IMAP_IOERROR;
	    *rettid = NULL;
	    break;
	}
	return r;
    }

  done:
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

    if (newent) free(newent);
    if (mtxn) free(mtxn);

    if (r) {
	if ((r = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s",
		   db_strerror(r));
	    r = IMAP_IOERROR;
	}
	if (rettid) *rettid = NULL;
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
    if (acap_conn != NULL)
    {
	r = acapmbox_setproperty_acl(acap_conn,
				     name,
				     newacl);
	if (r != 0) r = convert_acap_errorcode(r);
    }



    if (newacl) free(newacl);
    
    return r;
}

int mboxlist_abort(struct mbox_txn *mtid)
{
    int r;

    assert(mtid);

    switch (r = txn_abort(mtid->tid)) {
    case 0: 
	break;
    default:
	syslog(LOG_ERR, "DBERROR: failed on abort: %s", db_strerror(r));
	r = IMAP_IOERROR;
    }

    /* MEMORY LEAK! */
    free(mtid);
    
    return r;
}

int mboxlist_commit(struct mbox_txn *mtxn)
{
    int r;

    assert(mtxn);

    switch (mtxn->txn_type) {
    case TXN_CREATE:
	r = real_mboxlist_createmailbox(NULL, 0, NULL, 0, NULL, NULL, &mtxn);
	break;
    case TXN_DELETE:
	r = real_mboxlist_deletemailbox(NULL, 0, NULL, NULL, 0, &mtxn);
	break;
    case TXN_RENAME:
	r = real_mboxlist_renamemailbox(NULL, NULL, NULL, 0, NULL, NULL,
					&mtxn);
	break;
    case TXN_SETACL:
	r = real_mboxlist_setacl(NULL, NULL, NULL, 0, NULL, NULL, &mtxn);
	break;
    default:
	syslog(LOG_ERR, "mbdb: invalid transaction type %d", mtxn->txn_type);
	assert(0);
	break;
    }
    
    return r;
}

/* we just call the real routines */
int mboxlist_createmailbox(char *name, int mbtype, char *partition, 
			   int isadmin, char *userid, 
			   struct auth_state *auth_state)
{
    return real_mboxlist_createmailbox(name, mbtype, partition,
				       isadmin, userid, auth_state,
				       NULL);
}

int mboxlist_deletemailbox(char *name, int isadmin, char *userid, 
			   struct auth_state *auth_state, int checkacl)
{
    return real_mboxlist_deletemailbox(name, isadmin, userid, auth_state,
				       checkacl, NULL);
}


int mboxlist_renamemailbox(char *oldname, char *newname, char *partition, 
			   int isadmin, char *userid, 
			   struct auth_state *auth_state)
{
    return real_mboxlist_renamemailbox(oldname, newname, partition,
				       isadmin, userid, auth_state, NULL);
}

int mboxlist_setacl(char *name, char *identifier, char *rights, int isadmin, 
		    char *userid, struct auth_state *auth_state)
{
    return real_mboxlist_setacl(name, identifier, rights, isadmin,
				userid, auth_state, NULL);
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
 * Ok this is how we're doing it now. The whole thing is in a
 * transaction. we remember where we are so if the transaction abort
 * we can just restart where we left off. This can give results that
 * aren't consistent with the state of the world at any one time---but
 * every mailbox not touched will be listed once and only once.  IMAP
 * has no consistency guarantees on the LIST.
 *
 * Double deletion problem: 1 connection does a list. Another
 * connection deletes 2 mailboxes (mailbox.deleted.1 and
 * mailbox.deleted.2 in that order). The list could (depending on the
 * alphabetical order of the deleted mailboxes) say mailbox.deleted.1
 * exists but mailbox.deleted.2 doesn't. This is weird.
 *
 * Blame larry if you don't like this solution */

typedef enum {
  FINDALL_START,
  FINDALL_INBOX,
  FINDALL_PREFIX,
  FINDALL_DOING_INBOXSTAR,
  FINDALL_INBOXSTAR,
  FINDALL_DOING_REST,
  FINDALL_REST
} findall_t;

int mboxlist_findall(char *pattern, int isadmin, char *userid, 
		     struct auth_state *auth_state, 
		     int (*proc)(), void *rock)
{
    struct glob *g;
    char usermboxname[MAX_MAILBOX_NAME+1];
    int usermboxnamelen;
    unsigned long offset, len, namelen, prefixlen, acllen;
    int inboxoffset;
    long matchlen, minmatch;
    char *name, *p, *acl, *aclcopy;
    char aclbuf[1024];
    char namebuf[MAX_MAILBOX_NAME+1];
    int rights;
    int r, r2;
    char *inboxcase;
    DBC *cursor=NULL;
    DB_TXN *tid;
    DBT key, data;
    struct mbox_entry *mboxent;
    findall_t state = FINDALL_START;
    DBT DID_inboxstar_data;
    DBT DID_rest_data;    

    memset(&DID_rest_data, 0, sizeof(DID_rest_data));

    g = glob_init(pattern, GLOB_HIERARCHY|GLOB_INBOXCASE);
    inboxcase = glob_inboxcase(g);

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

    /* transaction restart place */
    if (0) {
      retry:
	if ((r = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s",
		   db_strerror(r));
	    return IMAP_IOERROR;
	}
    }

    /* begin the transaction */
    if ((r = txn_begin(dbenv, NULL, &tid, 0)) != 0) {
	syslog(LOG_ERR, "DBERROR: error beginning txn: %s", db_strerror(r));
	return IMAP_IOERROR;
    }

    /* Check for INBOX first of all */
    if (userid!=NULL)
    {
      if (state < FINDALL_INBOX)
      {
	if (GLOB_TEST(g, "INBOX") != -1)
	{
	    DBT key, data;

	    memset(&data, 0, sizeof(data));
	    memset(&key, 0, sizeof(key));
	    key.data = usermboxname;
	    key.size = usermboxnamelen;

	    r = mbdb->get(mbdb, tid, &key, &data, 0);
	    switch (r) {
	    case 0:
		r = proc(inboxcase, 5, 1, rock);
		if (r) {
		    glob_free(&g);
		    goto done;
		}
		break;
	    case DB_NOTFOUND:
		break;
	    case DB_LOCK_DEADLOCK:
		goto retry;
	    default: /* DB error */
		syslog(LOG_ERR, "DBERROR: error fetching %s: %s",
		       usermboxname, db_strerror(r));
		r = IMAP_IOERROR;
		goto done;
	    }
	}

	/* "user.X" matches patterns "user.X", "user.X*", "user.X%", etc */
	else if (!strncmp(pattern, usermboxname, usermboxnamelen) &&
		 GLOB_TEST(g, usermboxname) != -1) {
	    key.data = usermboxname;
	    key.size = usermboxnamelen;
	    r = mbdb->get(mbdb, tid, &key, &data, 0);
	    switch (r) {
	    case 0:
		r = proc(usermboxname, usermboxnamelen, 1, rock);
		if (r) {
		    glob_free(&g);
		    goto done;
		}
		break;
	    case DB_NOTFOUND:
		break;
	    case DB_LOCK_DEADLOCK:
		goto retry;
		break;
	    default: /* DB error */
		syslog(LOG_ERR, "DBERROR: error fetching %s: %s",
		       usermboxname, db_strerror(r));
		r = IMAP_IOERROR;
		goto done;
	    }
	}

	state=FINDALL_INBOX;
	strcpy(usermboxname+usermboxnamelen, ".");
	usermboxnamelen++;
      }

    }

    /* Find fixed-string pattern prefix */
    if (state < FINDALL_PREFIX)
    {
      for (p = pattern; *p; p++) {
	if (*p == '*' || *p == '%' || *p == '?') break;
      }
      prefixlen = p - pattern;
      *p = '\0';

      state = FINDALL_PREFIX;
    }

    /*
     * If user.X.* or INBOX.* can match pattern,
     * search for those mailboxes next
     */

    r = mbdb->cursor(mbdb, tid, &cursor, 0);
    if (r != 0) { 
	syslog(LOG_ERR, "DBERROR: Unable to create cursor");
	goto done;
    }

    if ((userid!=NULL) && (state < FINDALL_INBOXSTAR) &&
	(!strncmp(usermboxname, pattern, usermboxnamelen-1) ||
	 !strncasecmp("inbox.", pattern, prefixlen < 6 ? prefixlen : 6))) {
	int result;
	
	if (!strncmp(usermboxname, pattern, usermboxnamelen-1)) {
	    inboxoffset = 0;
	}
	else {
	    inboxoffset = strlen(userid);
	}

	
	memset(&data, 0, sizeof(data));
	memset(&key, 0, sizeof(key));

	if (state == FINDALL_DOING_INBOXSTAR)
	{  
	  /* we've been here before. let's start where we left off */
	  key.data = DID_inboxstar_data.data;
	  key.size = DID_inboxstar_data.size;
	} else {
	  /* first time we got here */
	  key.data = usermboxname;
	  key.size = usermboxnamelen;
	}

	r = cursor->c_get(cursor, &key, &data, DB_SET_RANGE);

	while (r != DB_NOTFOUND) {
	    switch (r) {
	    case 0:
	      break;
		
	    case DB_LOCK_DEADLOCK:
		goto retry;
		break;
		
	    default:
		syslog(LOG_ERR, "DBERROR: error advancing: %s", db_strerror(r));
		r = IMAP_IOERROR;
		goto done;
	    }

	    mboxent = (struct mbox_entry *) data.data;

	    /* make sure has the prefix */
	    if (strncmp(mboxent->name, usermboxname, usermboxnamelen) != 0) {
		break;
	    }

	    minmatch = 0;
	    while (minmatch >= 0) {
	      strcpy(namebuf, "INBOX.");
	      strcat(namebuf, mboxent->name+usermboxnamelen);
	      namelen=strlen(namebuf);

	      matchlen = glob_test(g, namebuf,
				   namelen, &minmatch);
	      if (matchlen == -1) { break; }
		
	      r = proc(namebuf, matchlen, 1, rock);
	      if (r) {
		glob_free(&g);
		goto done;
	      }

	    }

	    /* this is the last one we output in case we have to restart */
	    memset(&DID_inboxstar_data, 0, sizeof(DID_inboxstar_data));
	    DID_inboxstar_data.data = xmalloc(key.size);
	    memcpy(DID_inboxstar_data.data, key.data, key.size);
	    DID_inboxstar_data.size = key.size;	    
	    state = FINDALL_DOING_INBOXSTAR; /* we're in the middle now :) */


	    memset(&data, 0, sizeof(data));
	    r = cursor->c_get(cursor, &key, &data, DB_NEXT);
	}

	state = FINDALL_INBOXSTAR;
	if (userid) usermboxname[--usermboxnamelen] = '\0';
    }

    /* Search for all remaining mailboxes.  Start at the pattern prefix */
    memset(&data, 0, sizeof(data));
    memset(&key, 0, sizeof(key));    

    if (state == FINDALL_DOING_REST) {
	/* we've been here before. let's start where we left off */
	key.data = DID_rest_data.data;
	key.size = DID_rest_data.size;

	r = cursor->c_get(cursor, &key, &data, DB_SET_RANGE);
	if (!r) {
	    /* now skip to the next one */
	    r = cursor->c_get(cursor, &key, &data, DB_NEXT);
	}
	free(DID_rest_data.data); DID_rest_data.data = NULL;

    } else {
	if (prefixlen) {
	    key.data = pattern;
	    key.size = prefixlen;
	    
	    r = cursor->c_get(cursor, &key, &data, DB_SET_RANGE);
	} else {
	    r = cursor->c_get(cursor, &key, &data, DB_FIRST);
	}
    }

    while (r != DB_NOTFOUND) {
	switch (r) {
	case 0:
	    break;

	case DB_LOCK_DEADLOCK:
	    goto retry;
	    break;
	    
	default:
	    syslog(LOG_ERR, "DBERROR: error advancing: %s", db_strerror(r));
	    r = IMAP_IOERROR;
	    goto done;
	}
	
	name = key.data;
	namelen = key.size;
	mboxent = (struct mbox_entry *) data.data;

	/* does this even match our prefix? */
	if (strncmp(namebuf, pattern, prefixlen)) break;

	/* does it match the glob? */
	minmatch = 0;
	while (minmatch >= 0) {
	    matchlen = glob_test(g, name, namelen, &minmatch);

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

	    memcpy(namebuf, name, namelen);
	    namebuf[namelen] = '\0';

	    if (isadmin) {
		r = proc(namebuf, matchlen, 1, rock);
		if (r) {
		    glob_free(&g);
		    goto done;
		}
	    } else {
		rights = acl_myrights(auth_state, mboxent->acls);
		if (rights & ACL_LOOKUP) {
		    r = proc(namebuf, matchlen, (rights & ACL_CREATE),
			     rock);
		    if (r) {
			glob_free(&g);
			goto done;
		    }
		}
	    }
	}

	/* this is the last one we output (used when we have to restart) */
	if (DID_rest_data.data) free(DID_rest_data.data);
	memset(&DID_rest_data, 0, sizeof(DID_rest_data));
	DID_rest_data.data = xmalloc(key.size);
	memcpy(DID_rest_data.data, key.data, key.size);
	DID_rest_data.size = key.size;	    
	state = FINDALL_DOING_REST; /* we're in the middle now :) */

	memset(&data, 0, sizeof(data));

	r = cursor->c_get(cursor, &key, &data, DB_NEXT);
    }
    r = 0;

  done:
    if (cursor!=NULL) {
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

    switch (txn_commit(tid, 0)) {
    case 0:
	break;
    case EINVAL:
	syslog(LOG_WARNING, "tried to commit an already aborted transaction");
	break;
    default:
	syslog(LOG_WARNING, "failed on commit to read-only transaction");
	r = IMAP_IOERROR;
	break;
    }

    if (DID_rest_data.data) free(DID_rest_data.data);
	
    glob_free(&g);
    return r;
}

/*
 * Find subscribed mailboxes that match 'pattern'.
 * 'isadmin' is nonzero if user is a mailbox admin.  'userid'
 * is the user's login id.  For each matching mailbox, calls
 * 'proc' with the name of the mailbox.
 */
int mboxlist_findsub(char *pattern, int isadmin, char *userid, 
		     struct auth_state *auth_state, int (*proc)(), void *rock)
{
    int subsfd;
    const char *subs_base;
    unsigned long subs_size;
    char *subsfname;
    struct glob *g;
    char usermboxname[MAX_MAILBOX_NAME+1];
    int usermboxnamelen;
    char namebuf[MAX_MAILBOX_NAME+1];
    char namematchbuf[MAX_MAILBOX_NAME+1];
    int r;
    unsigned long offset, len, prefixlen, listlinelen;
    int inboxoffset;
    const char *name, *endname;
    char *p;
    unsigned long namelen;
    long matchlen, minmatch;
    char *acl;
    char *inboxcase;
    DBT key, data;
    DB_TXN *tid;

    /* open the subscription file that contains the mailboxes the 
       user is subscribed to */
    if (r = mboxlist_opensubs(userid, 0, &subsfd, &subs_base, &subs_size,
			      &subsfname, (char **) 0)) {
	goto done;
    }

    g = glob_init(pattern, GLOB_HIERARCHY|GLOB_INBOXCASE);
    inboxcase = glob_inboxcase(g);

    /* transaction restart place */
    if (0) {
      retry:
	if ((r = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s",
		   db_strerror(r));
	    return IMAP_IOERROR;
	}
    }

    /* begin the transaction */
    if ((r = txn_begin(dbenv, NULL, &tid, 0)) != 0) {
	syslog(LOG_ERR, "DBERROR: error beginning txn: %s", db_strerror(r));
	return IMAP_IOERROR;
    }



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
	if (GLOB_TEST(g, "INBOX") != -1) {

	    (void) bsearch_mem(usermboxname, 1, subs_base, subs_size, 0, &len);
	    if (len) {
		r = (*proc)(inboxcase, 5, 1, rock);
		if (r) {
		  goto done;
		}
	    }
	}
	else if (!strncmp(pattern, usermboxname, usermboxnamelen) &&
		 GLOB_TEST(g, usermboxname) != -1) {
	    (void) bsearch_mem(usermboxname, 1, subs_base, subs_size, 0, &len);
	    if (len) {
		r = (*proc)(inboxcase, 5, 1, rock);
		if (r) {
		  goto done;
		}
	    }
	}

	strcpy(usermboxname+usermboxnamelen, ".");
	usermboxnamelen++;
    }

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
	    inboxoffset = 0;
	}
	else {
	    inboxoffset = strlen(userid);
	}

	offset = bsearch_mem(usermboxname, 1, subs_base, subs_size, 0,
			     (unsigned long *)0);

	while (offset < subs_size) {

	name = subs_base + offset;
	    p = memchr(name, '\n', subs_size - offset);
	    endname = memchr(name, '\t', subs_size - offset);
	    if (!p || !endname || endname - name > MAX_MAILBOX_NAME) {
		syslog(LOG_ERR, "IOERROR: corrupted subscription file %s",
		       subsfname);
		/* xxx fatal inside a transaction */
		fatal("corrupted subscription file", EC_OSFILE);
	    }

	    len = p - name + 1;
	    namelen = endname - name;

	    if (strncmp(name, usermboxname, usermboxnamelen)) break;
	    minmatch = 0;
	    while (minmatch >= 0) {
		memcpy(namebuf, name, namelen);
		namebuf[namelen] = '\0';
		strcpy(namematchbuf, namebuf);

		if (inboxoffset) {
		    namematchbuf[inboxoffset] = inboxcase[0];
		    namematchbuf[inboxoffset+1] = inboxcase[1];
		    namematchbuf[inboxoffset+2] = inboxcase[2];
		    namematchbuf[inboxoffset+3] = inboxcase[3];
		    namematchbuf[inboxoffset+4] = inboxcase[4];
		}

		matchlen = glob_test(g, namematchbuf+inboxoffset,
				     namelen-inboxoffset, &minmatch);
		if (matchlen == -1) break;



		/* make sure it's in the mailboxes db */
		r = mboxlist_lookup(namebuf, (char **)0, NULL, tid);

		switch (r) {
		case 0:
		  /* found the entry; output it */
		  r = (*proc)(namematchbuf+inboxoffset, matchlen, 1, rock);
		  if (r) {
		    goto done;
		  }
		  break;
		  
		case DB_NOTFOUND:
		  /* didn't find the entry; take away the subscription */
		  mboxlist_changesub(namebuf, userid, auth_state, 0);
		  break;
		case DB_LOCK_DEADLOCK:
		  goto retry;
		  break;
		default:
		  syslog(LOG_ERR, "DBERROR: error fetching %s: %s",
			 name, db_strerror(r));
		  r = IMAP_IOERROR;
		  goto done;
		  break;
		}

	    }
	    offset += len;
	}
    }

    /* Search for all remaining mailboxes.  Start at the patten prefix */
    offset = bsearch_mem(pattern, 1, subs_base, subs_size, 0,
			 (unsigned long *)0);

    if (userid) usermboxname[--usermboxnamelen] = '\0';
    while (offset < subs_size) {
	name = subs_base + offset;
	p = memchr(name, '\n', subs_size - offset);
	endname = memchr(name, '\t', subs_size - offset);
	if (!p || !endname || endname - name > MAX_MAILBOX_NAME) {
	    syslog(LOG_ERR, "IOERROR: corrupted subscription file %s",
		   subsfname);
	    /* xxx fatal inside transaction */
	    fatal("corrupted subscription file", EC_OSFILE);
	}

	len = p - name + 1;
	namelen = endname - name;

	if (strncmp(name, pattern, prefixlen)) break;
	minmatch = 0;
	while (minmatch >= 0) {
	    matchlen = glob_test(g, name, namelen, &minmatch);
	    if (matchlen == -1 ||
		(userid && namelen >= usermboxnamelen &&
		 strncmp(name, usermboxname, usermboxnamelen) == 0 &&
		 (namelen == usermboxnamelen ||
		  name[usermboxnamelen] == '.'))) {
		break;
	    }

	    memcpy(namebuf, name, namelen);
	    namebuf[namelen] = '\0';

	    r = mboxlist_lookup(namebuf, (char **)0, &acl, tid);

	    switch (r) {
	    case 0:
	      /* found the entry; output it */
	      r = (*proc)(namebuf, matchlen,
			  (acl_myrights(auth_state, acl) & ACL_CREATE),
			  rock);
	      if (r) {
		goto done;
	      }
	      break;
		  
	    case IMAP_MAILBOX_NONEXISTENT:
	      /* didn't find the entry; take away the subscription */
	      mboxlist_changesub(namebuf, userid, auth_state, 0);
	      break;
	    case IMAP_AGAIN:
	      goto retry;
	      break;
	    default:
	      syslog(LOG_ERR, "DBERROR: error fetching %s: %i",
		     namebuf, r );
	      r = IMAP_IOERROR;
	      goto done;
	      break;
	    }

	}
	offset += len;
    }
	

  done:

    mboxlist_closesubs(subsfd, subs_base, subs_size);
    glob_free(&g);

    if (!r) {
	r = txn_commit(tid, 0);

	switch (r) {
	case 0:
	    break;
	case EINVAL:
	    syslog(LOG_WARNING, 
		   "tried to commit an already aborted transaction");
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   db_strerror(r));
	    r = IMAP_IOERROR;
	    break;
	}
    } else {
	int r2;

	if ((r2 = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn %s", db_strerror(r2));
	    r = IMAP_IOERROR;
	}
    }

    return r;
}

/* it's the responsibility of the caller to deal with this correctly if
   we end up aborting and restarting */
int mboxlist_foreach(foreach_proc *p, void *rock, int rw)
{
    /* iterate through all mailboxes, calling p on each one;
       continue as above if we deadlock */
    DB_TXN *tid;
    DBT key, data;
    DBC *cursor;
    int r, r2;
    int lasttime = 0;
    struct mbox_entry *mboxent;
    int flags;

    assert(mboxlist_dbinit && mboxlist_dbopen);
    assert(rw == 0 || rw == 1);

    if (rw) {
	flags = DB_RMW;
    } else {
	flags = 0;
    }
    
    memset(&data, 0, sizeof(data));
    memset(&key, 0, sizeof(key));

    if (0) {
      retry:
	cursor->c_close(cursor);

	if ((r = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s",
		   db_strerror(r));
	    return IMAP_IOERROR;
	}
    }

    /* begin the transaction */
    if ((r = txn_begin(dbenv, NULL, &tid, 0)) != 0) {
	syslog(LOG_ERR, "DBERROR: error beginning txn: %s", db_strerror(r));
	return IMAP_IOERROR;
    }

    r = mbdb->cursor(mbdb, tid, &cursor, 0);
    if (r != 0) { 
	syslog(LOG_ERR, "DBERROR: Unable to create cursor");
	goto done;
    }

    r = cursor->c_get(cursor, &key, &data, DB_FIRST | flags);
    while (r != DB_NOTFOUND) {
	switch (r) {
	case 0:
	    mboxent = (struct mbox_entry *) data.data;
	    break;
	case DB_LOCK_DEADLOCK:
	    goto retry;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: error advancing: %s", db_strerror(r));
	    r = IMAP_IOERROR;
	    break;
	}

	if (r) { /* error! */
	    break;
	}

	switch (p(rock, &mboxent)) {
	case MB_NEXT:
	    /* we liked this one; we keep going */
	    break;
	case MB_REMOVE:
	    if (rw) {
		r = mbdb->del(mbdb, tid, &key, 0);
	    } else {
		r = IMAP_IOERROR;
		goto done;
	    }
	    break;
	case MB_UPDATE:
	    if (rw) {
		data.data = (char *) mboxent;
		r = cursor->c_put(cursor, &key, &data, DB_CURRENT);
	    } else {
		r = IMAP_IOERROR;
		goto done;
	    }
	    break;
	case MB_FATAL:
	    r = IMAP_IOERROR;
	    goto done;
	    break;
	}

	if (mboxent) {
	    free(mboxent);
	}

	switch (r) {
	case 0:
	    break;
	case DB_LOCK_DEADLOCK:
	    goto retry;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: error advancing: %s", db_strerror(r));
	    r = IMAP_IOERROR;
	    break;
	}

	if (r) {
	    break;
	}

	r = cursor->c_get(cursor, &key, &data, DB_NEXT | flags);
    }
    if (r == DB_NOTFOUND) {
	r = 0;
    }

  done:
    r2 = cursor->c_close(cursor);
    switch (r2) {
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

    if (r) {
	if ((r = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s",
		   db_strerror(r));
	    r = IMAP_IOERROR;
	}
    } else {
	r = txn_commit(tid, 0);
	
	switch (r) {
	case 0:
	    break;
	case EINVAL:
	    syslog(LOG_WARNING,
		   "tried to commit an already aborted transaction");
	    r = IMAP_IOERROR;
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   db_strerror(r));
	    r = IMAP_IOERROR;
	    break;
	}
    }	    

    return r;
}



/*
 * Change 'user's subscription status for mailbox 'name'.
 * Subscribes if 'add' is nonzero, unsubscribes otherwise.
 */
int mboxlist_changesub(const char *name, const char *userid, 
		       struct auth_state *auth_state, int add)
{
    int r;
    char *acl;
    int subsfd, newsubsfd;
    const char *subs_base;
    unsigned long subs_size;
    char *subsfname, *newsubsfname;
    unsigned long offset, len;
    struct iovec iov[10];
    int num_iov;
    int n;
    
    if (r = mboxlist_opensubs(userid, 1, &subsfd, &subs_base, &subs_size,
			      &subsfname, &newsubsfname)) {
	return r;
    }

    if (add) {
	/* Ensure mailbox exists and can be either seen or read by user */
	if (r = mboxlist_lookup(name, (char **)0, &acl, NULL)) {
	    mboxlist_closesubs(subsfd, subs_base, subs_size);
	    return r;
	}
	if ((acl_myrights(auth_state, acl) & (ACL_READ|ACL_LOOKUP)) == 0) {
	    mboxlist_closesubs(subsfd, subs_base, subs_size);
	    return IMAP_MAILBOX_NONEXISTENT;
	}
    }

    /* Find where mailbox is/would go in subscription list */
    offset = bsearch_mem(name, 1, subs_base, subs_size, 0, &len);
    if (add) {
	if (len) {
	    mboxlist_closesubs(subsfd, subs_base, subs_size);
	    return 0;		/* Already unsubscribed */
	}
    }
    else {
	if (!len) {
	    mboxlist_closesubs(subsfd, subs_base, subs_size);
	    return 0;		/* Alredy subscribed */
	}
    }

    newsubsfd = open(newsubsfname, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (newsubsfd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", newsubsfname);
	mboxlist_closesubs(subsfd, subs_base, subs_size);
	return IMAP_IOERROR;
    }

    /* Copy over subscription list, making change */
    num_iov = 0;
    iov[num_iov].iov_base = (char *)subs_base;
    iov[num_iov++].iov_len = offset;
    if (add) {
	iov[num_iov].iov_base = (char *)name;
	iov[num_iov++].iov_len = strlen(name);
	iov[num_iov].iov_base = "\t\n";
	iov[num_iov++].iov_len = 2;
    }
    iov[num_iov].iov_base = (char *)subs_base + offset + len;
    iov[num_iov++].iov_len = subs_size - (offset + len);

    n = retry_writev(newsubsfd, iov, num_iov);

    if (n == -1 || fsync(newsubsfd)) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newsubsfname);
	mboxlist_closesubs(subsfd, subs_base, subs_size);
	close(newsubsfd);
	return IMAP_IOERROR;
    }	
    if (rename(newsubsfname, subsfname) == -1) {
	syslog(LOG_ERR, "IOERROR: renaming %s: %m", subsfname);
	mboxlist_closesubs(subsfd, subs_base, subs_size);
	close(newsubsfd);
	return IMAP_IOERROR;
    }
    mboxlist_closesubs(subsfd, subs_base, subs_size);
    close(newsubsfd);
    return 0;
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
    unsigned long offset, len;

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
	    syslog(LOG_ERR, "DBERROR: error search for mbox: %s", db_strerror(r));
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
 * Resynchronize the news mailboxes with the 'num' groups in the
 * sorted array 'group'.  Mark the ones we have seen in the array
 * 'seen'
 */
int mboxlist_syncnews(int num, char **group, int *seen)
{
    DB_TXN *tid;
    DBC *cursor;
    DBT key, keydel, data;
    struct mbox_entry *mboxent;
    int r;

    int deletethis;
    int deletedsomething = 0;
    int low, high, mid;
    struct mailbox mailbox;

    /* restart transaction place */
    if (0) {
      retry:
	if ((r = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn: %s",
		   db_strerror(r));
	    return IMAP_IOERROR;
	}
    }

    /* begin the transaction */
    if ((r = txn_begin(dbenv, NULL, &tid, 0)) != 0) {
	syslog(LOG_ERR, "DBERROR: error beginning txn: %s", db_strerror(r));
	return IMAP_IOERROR;
    }

    mbdb->cursor(mbdb, tid, &cursor, 0);

    r = cursor->c_get(cursor, &key, &data, DB_FIRST);
    while (r != DB_NOTFOUND) {
	switch (r) {
	case 0:
	    break;

	case DB_LOCK_DEADLOCK:
	    goto retry;
	    break;

	default:
	    syslog(LOG_ERR, "DBERROR: error advancing: %s", db_strerror(r));
	    r = IMAP_IOERROR;
	    goto done;
	}
	
	mboxent = (struct mbox_entry *) data.data;
	deletethis = 0;
	if (!strcasecmp(mboxent->partition, "news")) {
	    deletethis = 1;

	    /* Search for name in 'group' array */
	    low = 0;
	    high = num;
	    while (low <= high) {
		mid = (high - low)/2 + low;
		r = strcmp(key.data, group[mid]);
		if (r == 0) {
		    deletethis = 0;
		    seen[mid] = 1;
		    break;
		}
		else if (r < 0) {
		    high = mid - 1;
		}
		else {
		    low = mid + 1;
		}
	    }
	    if (deletethis) {
		/* Remove the mailbox.  Don't care about errors */

		/* if the transactions abort we can leave it in a
		   inconsistant state the worst that can happen is that
		   people get I/O Error's instead of Mailbox doesn't
		   exist on selects */
		r = mailbox_open_header(key.data, 0, &mailbox);
		if (!r) {
		    r = mailbox_delete(&mailbox, 0);
		}
	    }
	}

	keydel = key;
	r = cursor->c_get(cursor, &key, &data, DB_NEXT);

	if (deletethis) {
	    switch (mbdb->del(mbdb, tid, &keydel, 0)) {
	    case 0:
		break;

	    case DB_LOCK_DEADLOCK:
		goto retry;
		break;

	    default:
		syslog(LOG_ERR, "DBERROR: error deleting newsgroup");
		r = IMAP_IOERROR;
		goto done;
	    }
	}
    }
    r = 0;

    switch (cursor->c_close(cursor)) {
    case 0:
	break;
    case DB_LOCK_DEADLOCK:
	goto retry;
	break;
    }

  done:

    if (!r) {
	r = txn_commit(tid, 0);

	switch (r) {
	case 0:
	    break;
	case EINVAL:
	    syslog(LOG_WARNING, 
		   "tried to commit an already aborted transaction");
	    break;
	default:
	    syslog(LOG_ERR, "DBERROR: failed on commit: %s",
		   db_strerror(r));
	    r = IMAP_IOERROR;
	    break;
	}
    } else {
	int r2;

	if ((r2 = txn_abort(tid)) != 0) {
	    syslog(LOG_ERR, "DBERROR: error aborting txn %s", db_strerror(r2));
	    r = IMAP_IOERROR;
	}
    }

    return r;
}

/*
 * Retrieve internal information, for reconstructing mailboxes file
 */
void mboxlist_getinternalstuff(listfnamep, newlistfnamep, basep, sizep)
const char **listfnamep;
const char **newlistfnamep;
const char **basep;
unsigned long *sizep;
{
    printf("yikes! don't reconstruct me!\n");
    exit(1);
}

/*
 * Open the subscription list for 'userid'.  If 'lock' is nonzero,
 * lock it.
 * 
 * On success, returns zero.  The int pointed to by 'subsfile' is set
 * to the open, locked file.  The file is mapped into memory and the
 * base and size of the mapping are placed in variables pointed to by
 * 'basep' and 'sizep', respectively .  If they are non-null, the
 * character pointers pointed to by 'fname' and 'newfname' are set to
 * the filenames of the old and new subscription files, respectively.
 *
 * On failure, returns an error code.
 */
static int
mboxlist_opensubs(userid, lock, subsfdp, basep, sizep, fname, newfname)
const char *userid;
int lock;
int *subsfdp;
const char **basep;
unsigned long *sizep;
const char **fname;
const char **newfname;
{
    int r;
    static char *subsfname, *newsubsfname;
    int subsfd;
    struct stat sbuf;
    const char *lockfailaction;
    char inboxname[MAX_MAILBOX_NAME+1];

    /* Users without INBOXes may not keep subscriptions */
    if (strchr(userid, '.') || strlen(userid) + 6 > MAX_MAILBOX_NAME) {
	return IMAP_PERMISSION_DENIED;
    }
    strcpy(inboxname, "user.");
    strcat(inboxname, userid);
    if (mboxlist_lookup(inboxname, (char **)0, (char **)0, NULL) != 0) {
	return IMAP_PERMISSION_DENIED;
    }

    if (subsfname) {
	free(subsfname);
	free(newsubsfname);
    }

    /* Build subscription list filename */
    subsfname = mboxlist_hash_usersubs(userid);

    newsubsfname = xmalloc(strlen(subsfname)+5);
    strcpy(newsubsfname, subsfname);
    strcat(newsubsfname, ".NEW");

    subsfd = open(subsfname, O_RDWR|O_CREAT, 0666);
    if (subsfd == -1) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", subsfname);
	return IMAP_IOERROR;
    }

    if (lock) {
	r = lock_reopen(subsfd, subsfname, &sbuf, &lockfailaction);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, subsfname);
	    close(subsfd);
	    return IMAP_IOERROR;
	}
    }
    else {
	if (fstat(subsfd, &sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: fstat on %s: %m", subsfname);
	    fatal("can't fstat subscription list", EC_OSFILE);
	}
    }

    *basep = 0;
    *sizep = 0;
    map_refresh(subsfd, 1, basep, sizep, sbuf.st_size, subsfname, 0);

    *subsfdp = subsfd;
    if (fname) *fname = subsfname;
    if (newfname) *newfname = newsubsfname;
    return 0;
}

/*
 * Close a subscription file
 */
static void
mboxlist_closesubs(subsfd, base, size)
int subsfd;
const char *base;
unsigned long size;
{
    map_free(&base, &size);
    close(subsfd);
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
    char c2;
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

void db_err(char *db_prfx, char *buffer)
{
    syslog(LOG_INFO, "DBINFO: %s", buffer);
}

void mboxlist_init(void)
{
    int r;
    char dbdir[1024];

    assert (!mboxlist_dbinit);

    if ((r = db_env_create(&dbenv, 0)) != 0) {
	char err[1024];
	    
	sprintf(err, "DBERROR: db_appinit failed: %s", db_strerror(r));
	    
	syslog(LOG_ERR, err);
	fatal(err, EC_TEMPFAIL);
    }

    /* dbenv->set_paniccall(dbenv, (void (*)(DB_ENV *, int)) &db_panic);*/
    /* dbenv.db_errcall = &db_err; */
    dbenv->set_verbose(dbenv, DB_VERB_DEADLOCK, 1);
    dbenv->set_verbose(dbenv, DB_VERB_WAITSFOR, 1);
    dbenv->set_errfile(dbenv, stderr);
    dbenv->set_errpfx(dbenv, "mbdb");

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
    r = dbenv->open(dbenv, "/var/imap/db", NULL, 
		    DB_CREATE | DB_INIT_LOCK | DB_INIT_MPOOL
		    | DB_INIT_LOG | DB_INIT_TXN, 0644);
    if (r) {
	char err[1024];
	    
	sprintf(err, "DBERROR: dbenv->open '%s' failed: %s", dbdir,
		db_strerror(r));
	syslog(LOG_ERR, err);
	fatal(err, EC_TEMPFAIL);
    }

    mboxlist_dbinit = 1;

}

void mboxlist_open(char *fname)
{
    int ret;
    int flags = DB_CREATE;
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
}

/* hash the userid to a file containing the subscriptions for that user */
static char *mboxlist_hash_usersubs(const char *userid)
{
    char *fname = xmalloc(strlen(config_dir) + sizeof(FNAME_USERDIR) +
			  strlen(userid) + sizeof(FNAME_SUBSSUFFIX) + 10);
    char c;

    c = (char) tolower((int) *userid);
    if (!islower(c)) {
	c = 'q';
    }
    sprintf(fname, "%s%s%c/%s%s", config_dir, FNAME_USERDIR, c, userid,
	    FNAME_SUBSSUFFIX);

    return fname;
}
