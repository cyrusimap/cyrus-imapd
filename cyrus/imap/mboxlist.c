/* mboxlist.c -- Mailbox list manipulation routines
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <syslog.h>
#include <com_err.h>

extern int errno;

#include "acl.h"
#include "auth.h"
#include "glob.h"
#include "assert.h"
#include "config.h"
#include "util.h"
#include "mailbox.h"
#include "sysexits.h"
#include "imap_err.h"
#include "xmalloc.h"

long mboxlist_ensureOwnerRights();

static char *listfname, *newlistfname;
static int listfd = -1;
static long list_ino;
static char *list_base;
static unsigned long list_size = 0;
static int list_locked = 0;

static int mboxlist_opensubs();
static void mboxlist_closesubs();
static void mboxlist_reopen();
static void mboxlist_badline();
static void mboxlist_parseline();

static struct quota *mboxlist_newquota;
static int mboxlist_changequota();

#define FNAME_MBOXLIST "/mailboxes"
#define FNAME_USERDIR "/user/"
#define FNAME_SUBSSUFFIX ".sub"

/*
 * Maximum length of partition name.  [xxx probably no longer needed]
 * [config.c has a limit of 70]
 */
#define MAX_PARTITION_LEN 10

/*
 * Check our configuration for consistency, die if there's a problem
 */
mboxlist_checkconfig()
{
    mboxlist_reopen();
}

/*
 * Lookup 'name' in the mailbox list.
 * The capitalization of 'name' is canonicalized to the way it appears
 * in the mailbox list.
 * If 'path' is non-nil, a pointer to the full pathname of the mailbox
 * is placed in the char * pointed to by it.  If 'acl' is non-nil, a pointer
 * to the mailbox ACL is placed in the char * pointed to by it.
 */
mboxlist_lookup(name, pathp, aclp)
char *name;
char **pathp;
char **aclp;
{
    unsigned long offset, len, partitionlen, acllen;
    char optionbuf[MAX_MAILBOX_NAME+1];
    char *p, *partition, *acl, *root;
    static char pathresult[MAX_MAILBOX_PATH];
    static char *aclresult;
    static int aclresultalloced;

    mboxlist_reopen();

    /* Find mailbox */
    offset = bsearch_mem(name, 1, list_base, list_size, 0, &len);
    if (!len) {
	return IMAP_MAILBOX_NONEXISTENT;
    }
	
    /* Parse partition name, construct pathname if requested */
    mboxlist_parseline(offset, len, (char **)0, (unsigned long *)0,
		       &partition, &partitionlen, &acl, &acllen);

    if (pathp) {
	if (partitionlen > sizeof(optionbuf)-11) {
	    return IMAP_PARTITION_UNKNOWN;
	}
	strcpy(optionbuf, "partition-");
	memcpy(optionbuf + 10, partition, partitionlen);
	optionbuf[10+partitionlen] = '\0';
	
	root = config_getstring(optionbuf, (char *)0);
	if (!root) {
	    return IMAP_PARTITION_UNKNOWN;
	}
	
	sprintf(pathresult, "%s/%s", root, name);
	for (p = pathresult + strlen(root); *p; p++) {
	    if (*p == '.') *p = '/';
	}

	*pathp = pathresult;
    }

    /* Parse ACL if requested */
    if (aclp) {
	if (acllen+1 > aclresultalloced) {
	    aclresultalloced = acllen+100;
	    aclresult = xrealloc(aclresult, aclresultalloced);
	}

	memcpy(aclresult, acl, acllen);
	aclresult[acllen] = '\0';

	*aclp = aclresult;
    }

    return 0;
}

/*
 * Check/set up for mailbox creation
 */
mboxlist_createmailboxcheck(name, partition, isadmin, userid, newacl,
			    newpartition)
char *name;
char *partition;
int isadmin;
char *userid;
char **newacl;
char **newpartition;
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
    r = mboxlist_lookup(name, (char **)0, &acl);
    if (r != IMAP_MAILBOX_NONEXISTENT) {
	assert(r == 0);
	r = IMAP_MAILBOX_EXISTS;
	
	/* Lie about error if privacy demands */
	if (!isadmin) {
	    if (!(acl_myrights(acl) & ACL_LOOKUP)) {
		r = IMAP_PERMISSION_DENIED;
	    }
	}

	return r;
    }

    /* Search for a parent */
    strcpy(parent, name);
    parentlen = 0;
    while (!parentlen && (p = strrchr(parent, '.'))) {
	*p = '\0';
	offset = bsearch_mem(parent, 1, list_base, list_size, 0, &parentlen);
    }
    if (parentlen) {
	mboxlist_parseline(offset, parentlen, &parentname, (unsigned long *)0,
			   &parentpartition, &parentpartitionlen,
			   &parentacl, &parentacllen);

	/* Copy partition, if not specified */
	if (!partition) {
	    partition = xmalloc(parentpartitionlen + 1);
	    memcpy(partition, parentpartition, parentpartitionlen);
	    partition[parentpartitionlen] = '\0';
	}
	else {
	    partition = strsave(partition);
	}

	/* Copy ACL */
	acl = xmalloc(parentacllen + 1);
	memcpy(acl, parentacl, parentacllen);
	acl[parentacllen] = '\0';

	if (!isadmin && !(acl_myrights(acl) & ACL_CREATE)) {
	    free(partition);
	    free(acl);
	    return IMAP_PERMISSION_DENIED;
	}

	/* Canonicalize case of parent prefix */
	strncpy(name, parent, strlen(parent));
    }
    else {
	if (!isadmin) {
	    return IMAP_PERMISSION_DENIED;
	}
	
	acl = strsave("");
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
	    acl_set(&acl, name+5, ACL_ALL, (long (*)())0, (char *)0);
	}
	else {
	    defaultacl = identifier = 
	      strsave(config_getstring("defaultacl", "anyone lrs"));
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
		acl_set(&acl, identifier, acl_strtomask(rights),
			(long (*)())0, (char *)0);
		identifier = p;
	    }
	    free(defaultacl);
	}

	if (!partition) {  
	    partition = config_defpartition;
	    if (strlen(partition) > MAX_PARTITION_LEN) {
		/* Configuration error */
		fatal("name of default partition is too long", EX_CONFIG);
	    }
	}
	partition = strsave(partition);
    }	      

    if (newpartition) *newpartition = partition;
    else free(partition);
    if (newacl) *newacl = acl;
    else free(acl);

    return 0;
}

/*
 * Create a mailbox
 */
mboxlist_createmailbox(name, format, partition, isadmin, userid)
char *name;
int format;
char *partition;
int isadmin;
char *userid;
{
    int r;
    char *p;
    unsigned long offset, len;
    char *acl;
    char buf2[MAX_MAILBOX_PATH];
    char *root;
    int newlistfd;
    struct iovec iov[10];
    int n;
    struct mailbox newmailbox;

    /* Open and lock mailbox list file */
    r = mboxlist_openlock();
    if (r) return r;

    /* Check ability to create mailbox */
    r = mboxlist_createmailboxcheck(name, partition, isadmin, userid,
				    &acl, &partition);
    if (r) {
	mboxlist_unlock();
	return r;
    }

    /* Search for where the new entry goes */
    offset = bsearch_mem(name, 1, list_base, list_size, 0, &len);
    assert(len == 0);

    /* Get partition's path */
    sprintf(buf2, "partition-%s", partition);
    root = config_getstring(buf2, (char *)0);
    if (!root) {
	mboxlist_unlock();
	free(partition);
	free(acl);
	return IMAP_PARTITION_UNKNOWN;
    }
    if (strlen(root)+strlen(name)+20 > MAX_MAILBOX_PATH) {
	mboxlist_unlock();
	free(partition);
	free(acl);
	return IMAP_MAILBOX_BADNAME;
    }
    
    /* Create new mailbox list */
    newlistfd = open(newlistfname, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (newlistfd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", newlistfname);
	mboxlist_unlock();
	free(partition);
	free(acl);
	return IMAP_IOERROR;
    }

    /* Copy mailbox list, adding new entry */
    iov[0].iov_base = list_base;
    iov[0].iov_len = offset;
    iov[1].iov_base = name;
    iov[1].iov_len = strlen(name);
    iov[2].iov_base = "\t";
    iov[2].iov_len = 1;
    iov[3].iov_base = partition;
    iov[3].iov_len = strlen(partition);
    iov[4].iov_base = "\t";
    iov[4].iov_len = 1;
    iov[5].iov_base = acl;
    iov[5].iov_len = strlen(acl);
    iov[6].iov_base = "\n";
    iov[6].iov_len = 1;
    iov[7].iov_base = list_base + offset;
    iov[7].iov_len = list_size - offset;

    n = retry_writev(newlistfd, iov, 8);
    
    free(partition);

    if (n == -1 || fsync(newlistfd)) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newlistfname);
	mboxlist_unlock();
	close(newlistfd);
	free(acl);
	return IMAP_IOERROR;
    }
    close(newlistfd);

    /* Create new mailbox and move new mailbox list file into place */
    sprintf(buf2, "%s/%s", root, name);
    for (p = buf2 + strlen(root); *p; p++) {
	if (*p == '.') *p = '/';
    }
    r = mailbox_create(name, buf2, acl, format, &newmailbox);
    free(acl);
    if (r) return r;
    if (rename(newlistfname, listfname) == -1) {
	syslog(LOG_ERR, "IOERROR: renaming %s: %m", listfname);
	mboxlist_unlock();
	return IMAP_IOERROR;
    }

    mboxlist_unlock();

    toimsp(name, newmailbox.uidvalidity,
	   "ACLsn", newmailbox.acl, newmailbox.uidvalidity, 0);
    mailbox_close(&newmailbox);

    return 0;
}
	
/*
 * Delete a mailbox.
 * Deleting the mailbox user.FOO deletes the user "FOO".  It may only be
 * performed by an admin.  The operation removes the user "FOO"'s 
 * subscriptions and all sub-mailboxes of user.FOO
 */
mboxlist_deletemailbox(name, isadmin, userid, checkacl)
char *name;
int isadmin;
char *userid;
int checkacl;
{
    int r;
    char *acl;
    long access;
    int deleteuser = 0;
    unsigned long offset, len;
    char submailboxname[MAX_MAILBOX_NAME+1];
    int newlistfd;
    struct iovec iov[10];
    int n;
    struct mailbox mailbox;
    bit32 uidvalidity, timestamp;

    /* Check for request to delete a user */
    if (!strncmp(name, "user.", 5) && !strchr(name+5, '.')) {
	/* Can't DELETE INBOX */
	if (!strcmp(name+5, userid)) {
	    return IMAP_MAILBOX_NOTSUPPORTED;
	}

	/* Only admins may delete user */
	if (!isadmin) return IMAP_PERMISSION_DENIED;

	r = mboxlist_lookup(name, (char **)0, &acl);
	if (r) return r;
	
	/* Check ACL before doing anything stupid
	 * We don't have to lie about the error code since we know
	 * the user is an admin.
	 */
	if (!(acl_myrights(acl) & ACL_DELETE)) return IMAP_PERMISSION_DENIED;
	
	deleteuser = 1;

	/* Delete any subscription list file */
	{
	    char *fname;

	    fname = xmalloc(strlen(config_dir)+sizeof(FNAME_USERDIR)+
				strlen(name)+sizeof(FNAME_SUBSSUFFIX));
	    strcpy(fname, config_dir);
	    strcat(fname, FNAME_USERDIR);
	    strcat(fname, name+5);
	    strcat(fname, FNAME_SUBSSUFFIX);
	    (void) unlink(fname);
	    free(fname);
	}
    }

    /* Open and lock mailbox list file */
    r = mboxlist_openlock();
    if (r) return r;

    r = mboxlist_lookup(name, (char **)0, &acl);
    if (r) {
	mboxlist_unlock();
	return r;
    }
    access = acl_myrights(acl);
    if (checkacl && !(access & ACL_DELETE)) {
	mboxlist_unlock();

	/* User has admin rights over their own mailbox namespace */
	if (mboxname_userownsmailbox(userid, name)) {
	    isadmin = 1;
	}

	/* Lie about error if privacy demands */
	return (isadmin || (access & ACL_LOOKUP)) ?
	  IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
    }

    offset = bsearch_mem(name, 1, list_base, list_size, 0, &len);
    assert(len > 0);

    /* Create new mailbox list */
    newlistfd = open(newlistfname, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (newlistfd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", newlistfname);
	mboxlist_unlock();
	return IMAP_IOERROR;
    }

    if (deleteuser) {
	int namelen = strlen(name)+1;
	char *endname, *endline;

	strcpy(submailboxname, name);
	strcat(submailboxname, ".");

	/* Delete sub-mailboxes */
	while (offset + len + namelen < list_size &&
	       !strncmp(list_base + offset + len, submailboxname, namelen)) {
	    endname = memchr(list_base + offset + len, '\t',
			     list_size-offset-len);
	    if (!endname) {
		mboxlist_badline(list_base + offset + len, "no tab separator");
	    }
	    endline = memchr(list_base + offset + len, '\n',
			     list_size-offset-len);
	    if (!endline) {
		mboxlist_badline(list_base + offset + len,
				 "no newline terminator");
	    }
	    strncpy(submailboxname, list_base + offset + len,
		    endname - (list_base + offset + len));
	    submailboxname[endname - (list_base + offset + len)] = '\0';
	    len = endline - (list_base + offset) + 1;
	    
	    /* Remove the sub-mailbox  */
	    r = mailbox_open_header(submailboxname, &mailbox);
	    if (!r) r = mailbox_delete(&mailbox);
	}
    }

    /* Copy mailbox list, removing entry/entries */
    iov[0].iov_base = list_base;
    iov[0].iov_len = offset;
    iov[1].iov_base = list_base + offset + len;
    iov[1].iov_len = list_size - offset - len;

    n = retry_writev(newlistfd, iov, 2);

    if (n == -1 || fsync(newlistfd)) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newlistfname);
	mboxlist_unlock();
	close(newlistfd);
	return IMAP_IOERROR;
    }
    close(newlistfd);
    
    /* Remove the mailbox and move new mailbox list file into place */
    r = mailbox_open_header(name, &mailbox);
    uidvalidity = mailbox.uidvalidity;
    if (!r) r = mailbox_delete(&mailbox);
    if (r) {
	mboxlist_unlock();
	return r;
    }
    if (rename(newlistfname, listfname) == -1) {
	syslog(LOG_ERR, "IOERROR: renaming %s: %m", listfname);
	mboxlist_unlock();
	/* XXX We're left in an inconsistent state here */
	return IMAP_IOERROR;
    }

    mboxlist_unlock();

    toimsp(name, uidvalidity, "RENsn", "", 0, 0);

    return 0;
}

/*
 * Rename/move a mailbox
 */
int mboxlist_renamemailbox(oldname, newname, partition, isadmin, userid)
char *oldname;
char *newname;
char *partition;
int isadmin;
char *userid;
{
    int r;
    long access;
    int isusermbox = 0;
    char *oldpath;
    char *p;
    unsigned long oldoffset, oldlen;
    unsigned long newoffset, newlen;
    bit32 olduidvalidity, newuidvalidity;
    char *acl;
    char buf2[MAX_MAILBOX_PATH];
    char *root;
    int newlistfd;
    struct iovec iov[10];
    int num_iov;
    int n;

    /* Open and lock mailbox list file */
    r = mboxlist_openlock();
    if (r) return r;

    /* Check ability to delete old mailbox */
    if (!strncmp(oldname, "user.", 5) && !strchr(oldname+5, '.')) {
	if (!strcmp(oldname+5, userid)) {
	    /* Special case of renaming inbox */
	    r = mboxlist_lookup(oldname, &oldpath, &acl);
	    if (r) {
		mboxlist_unlock();
		return r;
	    }
	    access = acl_myrights(acl);
	    if (!(access & ACL_DELETE)) {
		mboxlist_unlock();
		return IMAP_PERMISSION_DENIED;
	    }
	    isusermbox = 1;
	}
	else {
	    /* Even admins can't rename users */
	    mboxlist_unlock();
	    return IMAP_PERMISSION_DENIED;
	}
    }
    else {
	r = mboxlist_lookup(oldname, &oldpath, &acl);
	if (r) {
	    mboxlist_unlock();
	    return r;
	}
	access = acl_myrights(acl);
	if (!(access & ACL_DELETE)) {
	    mboxlist_unlock();
	    return (isadmin || (access & ACL_LOOKUP)) ?
	      IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	}
    }
    acl = strsave(acl);

    /* Check ability to create new mailbox */
    if (!strncmp(newname, "user.", 5) && !strchr(newname+5, '.')) {
	/* Even admins can't rename to user's inboxes */
	mboxlist_unlock();
	free(acl);
	return IMAP_PERMISSION_DENIED;
    }
    r = mboxlist_createmailboxcheck(newname, partition, isadmin, userid,
				    (char **)0, &partition);
    if (r) {
	mboxlist_unlock();
	free(acl);
	return r;
    }
    
    /* Search for the old entry's location */
    if (isusermbox) {
	oldoffset = oldlen = 0;
    }
    else {
	oldoffset = bsearch_mem(oldname, 1, list_base, list_size, 0, &oldlen);
	assert(oldlen > 0);
    }

    /* Search for where the new entry goes */
    newoffset = bsearch_mem(newname, 1, list_base, list_size, 0, &newlen);

    /* Get partition's path */
    sprintf(buf2, "partition-%s", partition);
    root = config_getstring(buf2, (char *)0);
    if (!root) {
	mboxlist_unlock();
	free(acl);
	free(partition);
	return IMAP_PARTITION_UNKNOWN;
    }
    if (strlen(root)+strlen(newname)+20 > MAX_MAILBOX_PATH) {
	mboxlist_unlock();
	free(acl);
	free(partition);
	return IMAP_MAILBOX_BADNAME;
    }
    
    /* Create new mailbox list */
    newlistfd = open(newlistfname, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (newlistfd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", newlistfname);
	mboxlist_unlock();
	free(acl);
	free(partition);
	return IMAP_IOERROR;
    }

    /* Copy mailbox list, changing entry */
    num_iov  = 0;
    iov[num_iov].iov_base = list_base;
    if (oldoffset < newoffset) {
	iov[num_iov++].iov_len = oldoffset;
	iov[num_iov].iov_base = list_base + oldoffset + oldlen;
	iov[num_iov++].iov_len = newoffset - (oldoffset + oldlen);
    }
    else {
	iov[num_iov++].iov_len = newoffset;
    }
    iov[num_iov].iov_base = newname;
    iov[num_iov++].iov_len = strlen(newname);
    iov[num_iov].iov_base = "\t";
    iov[num_iov++].iov_len = 1;
    iov[num_iov].iov_base = partition;
    iov[num_iov++].iov_len = strlen(partition);
    iov[num_iov].iov_base = "\t";
    iov[num_iov++].iov_len = 1;
    iov[num_iov].iov_base = acl;
    iov[num_iov++].iov_len = strlen(acl);
    iov[num_iov].iov_base = "\n";
    iov[num_iov++].iov_len = 1;
    iov[num_iov].iov_base = list_base + newoffset;
    if (oldoffset < newoffset) {
	iov[num_iov++].iov_len = list_size - newoffset;
    }
    else {
	iov[num_iov++].iov_len = oldoffset - newoffset;
	iov[num_iov].iov_base = list_base + oldoffset + oldlen;
	iov[num_iov++].iov_len = list_size - (oldoffset + oldlen);
    }
	
    n = retry_writev(newlistfd, iov, num_iov);

    if (n == -1 || fsync(newlistfd)) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newlistfname);
	mboxlist_unlock();
	close(newlistfd);
	return IMAP_IOERROR;
    }
    close(newlistfd);

    /* Rename the mailbox and move new mailbox list file into place */
    sprintf(buf2, "%s/%s", root, newname);
    for (p = buf2 + strlen(root); *p; p++) {
	if (*p == '.') *p = '/';
    }
    r = mailbox_rename(oldname, newname, buf2, isusermbox);
    if (r) {
	mboxlist_unlock();
	return r;
    }
    if (rename(newlistfname, listfname) == -1) {
	syslog(LOG_ERR, "IOERROR: renaming %s: %m", listfname);
	mboxlist_unlock();
	/* XXX We're left in an inconsistent state here */
	return IMAP_IOERROR;
    }

    mboxlist_unlock();

    toimsp(oldname, olduidvalidity, "RENsn", newname, newuidvalidity, 0);

    return 0;
}

/*
 * Change the ACL for mailbox 'name' so that 'identifier' has the
 * rights enumerated in the string 'rights'.  If 'rights' is the null
 * pointer, removes the ACL entry for 'identifier'.   'isadmin' is
 * nonzero if user is a mailbox admin.  'userid' is the user's login id.
 */
int
mboxlist_setacl(name, identifier, rights, isadmin, userid)
char *name;
char *identifier;
char *rights;
int isadmin;
char *userid;
{
    int useridlen = strlen(userid);
    int r;
    long access;
    int isusermbox = 0;
    struct mailbox mailbox;
    unsigned long offset, len;
    char *oldacl, *acl, *newacl;
    unsigned long oldacllen;
    int newlistfd;
    struct iovec iov[10];
    int n;
    bit32 uidvalidity, timestamp;

    /* Open and lock mailbox list file */
    r = mboxlist_openlock();
    if (r) return r;

    if (!strncmp(name, "user.", 5) &&
	!strchr(userid, '.') &&
	!strncmp(name+5, userid, useridlen) &&
	(name[5+useridlen] == '\0' || name[5+useridlen] == '.')) {
	isusermbox = 1;
    }

    /* Get old ACL */
    r = mboxlist_lookup(name, (char **)0, &acl);
    if (!r && !isadmin && !isusermbox) {
	access = acl_myrights(acl);
	if (!(access & ACL_ADMIN)) {
	    r = (access & ACL_LOOKUP) ?
	      IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	}
    }

    /* Open & lock  mailbox header */
    if (!r) {
	r = mailbox_open_header(name, &mailbox);
    }
    if (r) {
	mboxlist_unlock();
	return r;
    }
    if (!r) {
	r = mailbox_lock_header(&mailbox);
    }

    if (!r) {
	newlistfd = open(newlistfname, O_RDWR|O_TRUNC|O_CREAT, 0666);
	if (newlistfd == -1) {
	    syslog(LOG_ERR, "IOERROR: creating %s: %m", newlistfname);
	    r = IMAP_IOERROR;
	}
    }

    if (r) {
	mailbox_close(&mailbox);
	mboxlist_unlock();
	return r;
    }

    /* Make change to ACL */
    newacl = strsave(acl);
    if (rights) {
	if (acl_set(&newacl, identifier, acl_strtomask(rights),
		    isusermbox ? mboxlist_ensureOwnerRights : 0, userid)) {
	    mailbox_close(&mailbox);
	    mboxlist_unlock();
	    free(newacl);
	    return IMAP_INVALID_IDENTIFIER;
	}
    }
    else {
	if (acl_delete(&newacl, identifier,
		       isusermbox ? mboxlist_ensureOwnerRights : 0, userid)) {
	    mailbox_close(&mailbox);
	    mboxlist_unlock();
	    free(newacl);
	    return IMAP_INVALID_IDENTIFIER;
	}
    }

    /* Copy over mailbox list, making change */
    offset = bsearch_mem(name, 1, list_base, list_size, 0, &len);
    if (!len) {
	mailbox_close(&mailbox);
	mboxlist_unlock();
	close(newlistfd);
	return IMAP_MAILBOX_NONEXISTENT;
    }

    mboxlist_parseline(offset, len, (char **)0, (unsigned long *)0,
		      (char **)0, (unsigned long *)0, &oldacl, &oldacllen);

    iov[0].iov_base = list_base;
    iov[0].iov_len = oldacl - list_base;
    iov[1].iov_base = newacl;
    iov[1].iov_len = strlen(newacl);
    iov[2].iov_base = list_base + offset + len - 1;
    iov[2].iov_len = list_size - (offset + len - 1);
    
    n = retry_writev(newlistfd, iov, 3);

    if (n == -1 || fsync(newlistfd)) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newlistfname);
	mboxlist_unlock();
	close(newlistfd);
	free(newacl);
	return IMAP_IOERROR;
    }
    if (rename(newlistfname, listfname) == -1) {
	syslog(LOG_ERR, "IOERROR: renaming %s: %m", listfname);
	mboxlist_unlock();
	close(newlistfd);
	free(newacl);
	return IMAP_IOERROR;
    }

    /* Change the redundant copy in mailbox header */
    free(mailbox.acl);
    mailbox.acl = strsave(newacl);
    (void) mailbox_write_header(&mailbox);
    timestamp = time(0);
    uidvalidity = mailbox.uidvalidity;
    mailbox_close(&mailbox);

    mboxlist_unlock();

    toimsp(name, uidvalidity, "ACLsn", newacl, timestamp, 0);

    close(newlistfd);
    free(newacl);
    return 0;
}

/*
 * Find all mailboxes that match 'pattern'.
 * 'isadmin' is nonzero if user is a mailbox admin.  'userid'
 * is the user's login id.  For each matching mailbox, calls
 * 'proc' with the name of the mailbox.  If 'proc' ever returns
 * a nonzero value, mboxlist_findall immediately stops searching
 * and returns that value.
 */
int mboxlist_findall(pattern, isadmin, userid, proc)
char *pattern;
int isadmin;
char *userid;
int (*proc)();
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
    int r;
    char *inboxcase;

    mboxlist_reopen();

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

    /* Check for INBOX first of all */
    if (userid) {
	if (GLOB_TEST(g, "INBOX") != -1) {
	    (void) bsearch_mem(usermboxname, 1, list_base, list_size, 0, &len);
	    if (len) {
		r = (*proc)(inboxcase, 5, 1);
		if (r) {
		    glob_free(&g);
		    return r;
		}
	    }
	}
	/* "user.X" matches patterns "user.X", "user.X*", "user.X%", etc */
	else if (!strncmp(pattern, usermboxname, usermboxnamelen) &&
		 GLOB_TEST(g, usermboxname) != -1) {
	    (void) bsearch_mem(usermboxname, 1, list_base, list_size, 0, &len);
	    if (len) {
		r = (*proc)(usermboxname, strlen(usermboxname), 1);
		if (r) {
		    glob_free(&g);
		    return r;
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

	offset = bsearch_mem(usermboxname, 1, list_base, list_size, 0,
			     (unsigned long *)0);

	while (offset < list_size) {
	    p = memchr(list_base + offset, '\n', list_size-offset);
	    if (!p) {
		mboxlist_badline(list_base + offset, "no newline terminator");
	    }

	    len = p - (list_base + offset) + 1;
	    mboxlist_parseline(offset, len, &name, &namelen,
			       (char **)0, (unsigned long *)0,
			       (char **)0, (unsigned long *)0);
		
	    if (strncmp(list_base + offset,
			    usermboxname, usermboxnamelen) != 0) break;
	    minmatch = 0;
	    while (minmatch >= 0) {
		memcpy(namebuf, name, namelen);
		namebuf[namelen] = '\0';

		if (inboxoffset) {
		    namebuf[inboxoffset] = inboxcase[0];
		    namebuf[inboxoffset+1] = inboxcase[1];
		    namebuf[inboxoffset+2] = inboxcase[2];
		    namebuf[inboxoffset+3] = inboxcase[3];
		    namebuf[inboxoffset+4] = inboxcase[4];
		}

		matchlen = glob_test(g, namebuf+inboxoffset,
				     namelen-inboxoffset, &minmatch);
		if (matchlen == -1) break;

		r = (*proc)(namebuf+inboxoffset, matchlen, 1);
		if (r) {
		    glob_free(&g);
		    return r;
		}
	    }
	    offset += len;
	}
    }

    /* Search for all remaining mailboxes.  Start at the pattern prefix */
    offset = bsearch_mem(pattern, 1, list_base, list_size, 0,
			 (unsigned long *)0);

    if (userid) usermboxname[--usermboxnamelen] = '\0';
    while (offset < list_size) {
	p = memchr(list_base + offset, '\n', list_size-offset);
	if (!p) {
	    mboxlist_badline(list_base + offset, "no newline terminator");
	}

	len = p - (list_base + offset) + 1;
	mboxlist_parseline(offset, len, &name, &namelen,
			   (char **)0, (unsigned long *)0, &acl, &acllen);
		
	if (strncmp(list_base + offset, pattern, prefixlen)) break;
	minmatch = 0;
	while (minmatch >= 0) {
	    matchlen = glob_test(g, name, namelen, &minmatch);
	    if (matchlen == -1 ||
		(userid && namelen >= usermboxnamelen &&
		 strncmp(name, usermboxname, usermboxnamelen) == 0 &&
		 (namelen == usermboxnamelen || name[usermboxnamelen] == '.'))) {
		break;
	    }

	    memcpy(namebuf, name, namelen);
	    namebuf[namelen] = '\0';

	    if (isadmin) {
		r = (*proc)(namebuf, matchlen, 1);
		if (r) {
		    glob_free(&g);
		    return r;
		}
	    }
	    else {
		if (acllen < sizeof(aclbuf)) {
		    memcpy(aclbuf, acl, acllen);
		    aclbuf[acllen] = '\0';
		    rights = acl_myrights(aclbuf);
		}
		else {
		    aclcopy = xmalloc(acllen + 1);
		    memcpy(aclcopy, acl, acllen);
		    aclcopy[acllen] = '\0';
		    rights = acl_myrights(aclcopy);
		    free(aclcopy);
		}
		if (rights & ACL_LOOKUP) {
		    r = (*proc)(namebuf, matchlen, (rights & ACL_CREATE));
		    if (r) {
			glob_free(&g);
			return r;
		    }
		}
	    }
	}
	offset += len;
    }
	
    glob_free(&g);
    return 0;
}

/*
 * Find subscribed mailboxes that match 'pattern'.
 * 'isadmin' is nonzero if user is a mailbox admin.  'userid'
 * is the user's login id.  For each matching mailbox, calls
 * 'proc' with the name of the mailbox.
 */
int mboxlist_findsub(pattern, isadmin, userid, proc)
char *pattern;
int isadmin;
char *userid;
int (*proc)();
{
    int subsfd;
    char *subs_base;
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
    char *name, *endname, *p;
    unsigned long namelen;
    long matchlen, minmatch;
    char *acl;
    char *inboxcase;

    if (r = mboxlist_opensubs(userid, 0, &subsfd, &subs_base, &subs_size,
			      &subsfname, (char **) 0)) {
	return r;
    }

    mboxlist_reopen();

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

    /* Check for INBOX first of all */
    if (userid) {
	if (GLOB_TEST(g, "INBOX") != -1) {
	    (void) bsearch_mem(usermboxname, 1, subs_base, subs_size, 0, &len);
	    if (len) {
		r = (*proc)(inboxcase, 5, 1);
		if (r) {
		    mboxlist_closesubs(subsfd, subs_base, subs_size);
		    glob_free(&g);
		    return r;
		}
	    }
	}
	else if (!strncmp(pattern, usermboxname, usermboxnamelen) &&
		 GLOB_TEST(g, usermboxname) != -1) {
	    (void) bsearch_mem(usermboxname, 1, subs_base, subs_size, 0, &len);
	    if (len) {
		r = (*proc)(inboxcase, 5, 1);
		if (r) {
		    mboxlist_closesubs(subsfd, subs_base, subs_size);
		    glob_free(&g);
		    return r;
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
		fatal("corrupted subscription file", EX_OSFILE);
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

		(void) bsearch_mem(namebuf, 1, list_base, list_size, 0,
				   &listlinelen);

		if (listlinelen) {
		    r = (*proc)(namematchbuf+inboxoffset, matchlen, 1);
		    if (r) {
			mboxlist_closesubs(subsfd, subs_base, subs_size);
			glob_free(&g);
			return r;
		    }
		}
		else {
		    mboxlist_changesub(namebuf, userid, 0);
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
	    fatal("corrupted subscription file", EX_OSFILE);
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
		 (namelen == usermboxnamelen || name[usermboxnamelen] == '.'))) {
		break;
	    }

	    memcpy(namebuf, name, namelen);
	    namebuf[namelen] = '\0';

	    r = mboxlist_lookup(namebuf, (char **)0, &acl);
	    if (r == 0) {
		r = (*proc)(namebuf, matchlen,
			    (acl_myrights(acl) & ACL_CREATE));
		if (r) {
		    mboxlist_closesubs(subsfd, subs_base, subs_size);
		    glob_free(&g);
		    return r;
		}
	    }
	    else {
		mboxlist_changesub(namebuf, userid, 0);
		break;
	    }
	}
	offset += len;
    }
	
    mboxlist_closesubs(subsfd, subs_base, subs_size);
    glob_free(&g);
    return 0;
}

/*
 * Change 'user's subscription status for mailbox 'name'.
 * Subscribes if 'add' is nonzero, unsubscribes otherwise.
 */
int 
mboxlist_changesub(name, userid, add)
char *name;
char *userid;
int add;
{
    int r;
    char *acl;
    int subsfd, newsubsfd;
    char *subs_base;
    unsigned long subs_size;
    char *subsfname, *newsubsfname;
    unsigned offset, len;
    struct iovec iov[10];
    int num_iov;
    int n;
    
    if (r = mboxlist_opensubs(userid, 1, &subsfd, &subs_base, &subs_size,
			      &subsfname, &newsubsfname)) {
	return r;
    }

    if (add) {
	/* Ensure mailbox exists and can be either seen or read by user */
	if (r = mboxlist_lookup(name, (char **)0, &acl)) {
	    mboxlist_closesubs(subsfd, subs_base, subs_size);
	    return r;
	}
	if ((acl_myrights(acl) & (ACL_READ|ACL_LOOKUP)) == 0) {
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
    iov[num_iov].iov_base = subs_base;
    iov[num_iov++].iov_len = offset;
    if (add) {
	iov[num_iov].iov_base = name;
	iov[num_iov++].iov_len = strlen(name);
	iov[num_iov].iov_base = "\t\n";
	iov[num_iov++].iov_len = 2;
    }
    iov[num_iov].iov_base = subs_base + offset + len;
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
int
mboxlist_setquota(root, newquota)
char *root;
int newquota;
{
    char quota_path[MAX_MAILBOX_PATH];
    char pattern[MAX_MAILBOX_PATH];
    struct quota quota;
    static struct quota zeroquota;
    int r;
    unsigned offset, len;

    if (!root[0] || root[0] == '.' || strchr(root, '/')
	|| strchr(root, '*') || strchr(root, '%') || strchr(root, '?')) {
	return IMAP_MAILBOX_BADNAME;
    }
    
    quota = zeroquota;

    strcpy(quota_path, config_dir);
    strcat(quota_path, FNAME_QUOTADIR);
    quota.root = quota_path + strlen(quota_path);
    strcpy(quota.root, root);

    if (quota.file = fopen(quota_path, "r+")) {
	/* Just lock and change it */
	r = mailbox_lock_quota(&quota);

	quota.limit = newquota;

	if (!r) r = mailbox_write_quota(&quota);
	if (quota.file) fclose(quota.file);
	return r;
    }

    /*
     * Have to create a new quota root
     * Open and lock mailbox list file
     */
    r = mboxlist_openlock();
    if (r) return r;

    /* Ensure there is at least one mailbox under the quota root */
    offset = bsearch_mem(quota.root, 1, list_base, list_size, 0, &len);
    if (!len) {
	if (strlen(quota.root) >= list_size - offset ||
	    strncmp(quota.root, list_base + offset,
		    strlen(quota.root)) != 0 ||
	    list_base[offset + strlen(quota.root)] != '.') {
	    mboxlist_unlock();
	    return IMAP_MAILBOX_NONEXISTENT;
	}
    }
    
    /* perhaps create .NEW, lock, check if it got recreated, move in place */
    quota.lock_count = 1;
    quota.used = 0;
    quota.limit = newquota;
    r = mailbox_write_quota(&quota);

    if (r) {
	mboxlist_unlock();
	return r;
    }

    strcpy(pattern, quota.root);
    strcat(pattern, ".*");
    mboxlist_newquota = &quota;
    
    if (len) {
	mboxlist_changequota(quota.root, 0, 0);
    }
    mboxlist_findall(pattern, 1, 0, mboxlist_changequota);
    
    r = mailbox_write_quota(&quota);
    if (quota.file) fclose(quota.file);
    mboxlist_unlock();
    return r;
}

/*
 * Resynchronize the news mailboxes with the 'num' groups in the
 * sorted array 'group'.  Mark the ones we have seen in the array
 * 'seen'
 */
int
mboxlist_syncnews(num, group, seen)
int num;
char **group;
int *seen;
{
    int r;
    int deletethis;
    int deletedsomething = 0;
    int low, high, mid;
    int newlistfd;
    struct mailbox mailbox;
    unsigned long offset, copyoffset;
    char *name;
    unsigned long namelen;
    char *partition;
    unsigned long partitionlen;
    char namebuf[MAX_MAILBOX_NAME+1];
    char *p;
    unsigned long len;
    int n;

    /* Open and lock mailbox list file */
    r = mboxlist_openlock();
    if (r) return r;

    newlistfd = open(newlistfname, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (newlistfd == -1) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", newlistfname);
	mboxlist_unlock();
	return IMAP_IOERROR;
    }

    offset = copyoffset = 0;

    /* Copy over mailbox list, making change */
    while (offset < list_size) {
	p = memchr(list_base + offset, '\n', list_size-offset);
	if (!p) {
	    mboxlist_badline(list_base + offset, "no newline terminator");
	}

	len = p - (list_base + offset) + 1;
	mboxlist_parseline(offset, len, &name, &namelen,
			   &partition, &partitionlen,
			   (char **)0, (unsigned long *)0);
		
	deletethis = 0;

	if (partitionlen == 4 && strncasecmp(partition, "news", 4) == 0) {
	    deletethis = 1;

	    memcpy(namebuf, name, namelen);
	    namebuf[namelen] = '\0';

	    /* Search for name in 'group' array */
	    low = 0;
	    high = num;
	    while (low <= high) {
		mid = (high - low)/2 + low;
		r = strcmp(namebuf, group[mid]);
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
		r = mailbox_open_header(namebuf, &mailbox);
		if (!r) {
		    toimsp(namebuf, mailbox.uidvalidity, "RENsn", "", 0, 0);
		    r = mailbox_delete(&mailbox);
		}
		printf("deleted %s\n", namebuf);
	    }
	}

	if (deletethis) {
	    n = retry_write(newlistfd, list_base + copyoffset,
			    offset - copyoffset);
	    if (n == -1) {
		syslog(LOG_ERR, "IOERROR: writing %s: %m", newlistfname);
		mboxlist_unlock();
		close(newlistfd);
		return IMAP_IOERROR;
	    }
	    copyoffset = offset + len;

	    deletedsomething++;
	}

	offset += len;
    }

    if (!deletedsomething) {
	mboxlist_unlock();
	close(newlistfd);
	return 0;
    }

    if (fsync(newlistfd)) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newlistfname);
	mboxlist_unlock();
	close(newlistfd);
	return IMAP_IOERROR;
    }
    if (rename(newlistfname, listfname) == -1) {
	syslog(LOG_ERR, "IOERROR: renaming %s: %m", listfname);
	mboxlist_unlock();
	close(newlistfd);
	return IMAP_IOERROR;
    }
    mboxlist_unlock();
    close(newlistfd);
    return 0;
}

/*
 * Open and lock the mailbox list file
 */
int
mboxlist_openlock()
{
    struct stat sbuf;
    char *lockfailaction;
    int r;

    assert(list_locked == 0);

    if (listfd == -1) mboxlist_reopen();

    r = lock_reopen(listfd, listfname, &sbuf, &lockfailaction);
    if (r == -1) {
	syslog(LOG_ERR, "IOERROR: %s %s: %m", lockfailaction, listfname);
	return IMAP_IOERROR;
    }

    list_locked = 1;

    if (sbuf.st_ino != list_ino) {
	list_ino = sbuf.st_ino;

	map_free(&list_base, &list_size);
	map_refresh(listfd, 1, &list_base, &list_size, sbuf.st_size,
		    listfname, 0);
    }

    return 0;
}

/*
 * Unlock the mailbox list file
 */
int
mboxlist_unlock()
{
    lock_unlock(listfd);
    list_locked = 0;
    return 0;
}

/*
 * Retrieve internal information, for reconstructing mailboxes file
 */
mboxlist_getinternalstuff(listfnamep, newlistfnamep, basep, sizep)
char **listfnamep;
char **newlistfnamep;
char **basep;
unsigned long *sizep;
{
    *listfnamep = listfname;
    *newlistfnamep = newlistfname;
    *basep = list_base;
    *sizep = list_size;
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
char *userid;
int lock;
int *subsfdp;
char **basep;
unsigned long *sizep;
char **fname;
char **newfname;
{
    int r;
    static char *subsfname, *newsubsfname;
    int subsfd;
    struct stat sbuf;
    char *lockfailaction;
    char inboxname[MAX_MAILBOX_NAME+1];

    /* Users without INBOXes may not keep subscriptions */
    if (strchr(userid, '.') || strlen(userid) + 6 > MAX_MAILBOX_NAME) {
	return IMAP_PERMISSION_DENIED;
    }
    strcpy(inboxname, "user.");
    strcat(inboxname, userid);
    if (mboxlist_lookup(inboxname, (char **)0, (char **)0) != 0) {
	return IMAP_PERMISSION_DENIED;
    }

    if (subsfname) {
	free(subsfname);
	free(newsubsfname);
    }

    /* Build subscription list filename */
    subsfname = xmalloc(strlen(config_dir)+sizeof(FNAME_USERDIR)+
			strlen(userid)+sizeof(FNAME_SUBSSUFFIX));
    strcpy(subsfname, config_dir);
    strcat(subsfname, FNAME_USERDIR);
    strcat(subsfname, userid);
    strcat(subsfname, FNAME_SUBSSUFFIX);
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
	    fatal("can't fstat subscription list", EX_OSFILE);
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
char *base;
unsigned long size;
{
    map_free(&base, &size);
    close(subsfd);
}


/*
 * Get the filenames of the mailbox list and the temporary file to
 * use when updating the mailbox list.
 */
static void
mboxlist_reopen()
{
    struct stat sbuf;

    if (!listfname) {
	listfname = xmalloc(strlen(config_dir)+sizeof(FNAME_MBOXLIST));
	strcpy(listfname, config_dir);
	strcat(listfname, FNAME_MBOXLIST);
	newlistfname = xmalloc(strlen(config_dir)+sizeof(FNAME_MBOXLIST)+4);
	strcpy(newlistfname, config_dir);
	strcat(newlistfname, FNAME_MBOXLIST);
	strcat(newlistfname, ".NEW");
    }

    if (list_locked) return;

    if (listfd != -1) {
	if (stat(listfname, &sbuf) == -1) {
	    syslog(LOG_ERR, "IOERROR: stat on %s: %m", listfname);
	    fatal("can't stat mailbox list", EX_OSFILE);
	}
	if (sbuf.st_ino == list_ino) return;
	close(listfd);
	map_free(&list_base, &list_size);
    }

    listfd = open(listfname, O_RDWR, 0666);
    if (listfd == -1) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", listfname);
	fatal("can't read mailbox list", EX_OSFILE);
    }
	
    if (fstat(listfd, &sbuf) == -1) {
	syslog(LOG_ERR, "IOERROR: fstat on %s: %m", listfname);
	fatal("can't fstat mailbox list", EX_OSFILE);
    }
    list_ino = sbuf.st_ino;

    map_refresh(listfd, 1, &list_base, &list_size, sbuf.st_size,
		listfname, 0);
}

static void
mboxlist_badline(line, error)
char *line;
char *error;
{
    char *p;
    char buf[1024];
    int lineno = 1;

    for (p = list_base; p < line; p++) {
	if (*p == '\n') lineno++;
    }

    syslog(LOG_ERR, "IOERROR: corrupted mailboxes file, line %d: %s",
	   lineno, error);
    sprintf(buf, "corrupted mailboxes file, line %d: %s", lineno, error);
    fatal(buf, EX_OSFILE);
}
    

/*
 * Parse a mailboxes line
 */
static void
mboxlist_parseline(offset, len, namep, namelenp, partitionp, partitionlenp,
		   aclp, acllenp)
unsigned long offset;
unsigned long len;
char **namep;
unsigned long *namelenp;
char **partitionp;
unsigned long *partitionlenp;
char **aclp;
unsigned long *acllenp;
{
    char *line = list_base + offset;
    char *p;
    unsigned fieldlen;

    if (namep) *namep = line;
    p = memchr(line, '\t', len);
    if (!p) {
	mboxlist_badline(line, "no tab separator");
    }
    fieldlen = p - line;
    if (fieldlen > MAX_MAILBOX_NAME) {
	mboxlist_badline(line, "mailbox name too long");
    }

    if (namelenp) *namelenp = fieldlen;
    p++;
    len -= fieldlen + 1;
    line += fieldlen + 1;

    if (partitionp) *partitionp = line;
    p = memchr(line, '\t', len);
    if (!p) {
	mboxlist_badline(line, "only one tab separator");
    }
    fieldlen = p - line;
    if (partitionlenp) *partitionlenp = fieldlen;
    p++;
    len -= fieldlen + 1;
    line += fieldlen + 1;

    if (!len || line[len-1] != '\n') {
	mboxlist_badline(line, "no newline terminator");
    }
    len--;
    if (aclp) *aclp = line;
    if (acllenp) *acllenp = len;
}

/*
 * ACL access canonicalization routine which ensures that 'owner'
 * retains lookup, administer, and create rights over a mailbox.
 */
long mboxlist_ensureOwnerRights(owner, identifier, access)
char *owner;
char *identifier;
long access;
{
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

    r = mailbox_open_header(name, &mailbox);
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

    mailbox.quota.root = strsave(mboxlist_newquota->root);
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

