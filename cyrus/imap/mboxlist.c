/* mboxlist.c -- Mailbox list manipulation routines
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

/*
 * This module could stand an almost complete rewrite.
 * Perhaps something that mmap()s in the 'mailboxes' file.
 */

#include <stdio.h>
#include <sysexits.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <syslog.h>
#include <com_err.h>

#include "acl.h"
#include "glob.h"
#include "assert.h"
#include "config.h"
#include "util.h"
#include "mailbox.h"
#include "imap_err.h"
#include "xmalloc.h"

/* Many systems don't define EX_CONFIG */
#ifndef EX_CONFIG
#define EX_CONFIG 78
#endif

static char *listfname, *newlistfname;

static int mboxlist_opensubs();
static int mboxlist_getfname();
static int mboxlist_policycheck();
static int mboxlist_userownsmailbox();
static long ensureOwnerRights();
static int mboxlist_deletesubmailbox();

static struct quota *mboxlist_newquota;
static int mboxlist_changequota();

#define FNAME_MBOXLIST "/mailboxes"
#define FNAME_USERDIR "/user/"
#define FNAME_SUBSSUFFIX ".sub"

/*
 * Maximum length of mailbox and partition names.  These together
 * must be at least 3 less than the size of the binary-search buffer
 * [512]
 */
#define MAX_NAME_LEN 490
#define MAX_PARTITION_LEN 10

/* Mailbox patterns which the design of the server prohibits */
static char *badmboxpatterns[] = {
    "",
    "*\t*",
    "*\n*",
    "*/*",
    ".*",
    "*.",
    "*..*",
    "inbox",
    "inbox.*",
    "user",
};
#define NUM_BADMBOXPATTERNS (sizeof(badmboxpatterns)/sizeof(*badmboxpatterns))

/*
 * Lookup 'name' in the mailbox list.
 * The capitalization of 'name' is canonicalized to the way it appears
 * in the mailbox list.
 * If 'path' is non-nil, a pointer to the full pathname of the mailbox
 * is placed in the char * pointed to by it.  If 'acl' is non-nil, a pointer
 * to the mailbox ACL is placed in the char * pointed to by it.
 */
mboxlist_lookup(name, path, acl)
char *name;
char **path;
char **acl;
{
    int namelen = strlen(name);
    FILE *listfile;
    unsigned offset, buflen, acllen;
    char *buf = 0;
    char buf2[MAX_NAME_LEN];
    char *p, *partition, *root;
    static char pathresult[MAX_MAILBOX_PATH];
    static char *aclresult;
    static int aclresultalloced;

    if (!listfname) mboxlist_getfname();

    /* Open mailbox list file */
    listfile = fopen(listfname, "r");
    if (!listfile) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", listfname);
	fatal("can't read mailbox list", EX_OSFILE);
    }

    /* Find mailbox */
    offset = n_binarySearchFD(fileno(listfile), name, 0, &buf, &buflen, 0, 0);
    if (!buflen) {
	fclose(listfile);
	return IMAP_MAILBOX_NONEXISTENT;
    }
	
    /* Canonify the case of the mailbox name */
    strncpy(name, buf, namelen);

    /* Parse partition name, construct pathname if requested */
    partition = buf + namelen + 1;
    p = strchr(partition, '\t');
    /* XXX assuming \t before running past buflen */
    *p = '\0';
    if (path) {
	sprintf(buf2, "partition-%s", partition);
	root = config_getstring(buf2, (char *)0);
	if (!root) {
	    fclose(listfile);
	    return IMAP_PARTITION_UNKNOWN;
	}
	
	sprintf(pathresult, "%s/%s", root, name);
	for (p = pathresult + strlen(root); *p; p++) {
	    if (isupper(*p)) *p = tolower(*p);
	    else if (*p == '.') *p = '/';
	}

	*path = pathresult;
    }

    /* Parse ACL if requested */
    if (acl) {
	p = buf + strlen(buf) + 1;
	buflen -= p - buf;
	for (acllen = 0; acllen < buflen; acllen++) {
	    if (p[acllen] == '\n') break;
	}
	if (acllen+2 > aclresultalloced) {
	    aclresultalloced = acllen+2;
	    aclresult = xrealloc(aclresult, aclresultalloced);
	}
	strncpy(aclresult, p, acllen+1);
	p = aclresult + acllen;
	if (*p != '\n') {
	    /*
	     * ACL is too long for buf.  we're going to have to read
	     * the rest of it.
	     */
	    fseek(listfile, offset+strlen(buf)+1+buflen, 0);
	}
	while (*p != '\n' && fgets(buf2, sizeof(buf2), listfile)) {
	    acllen += strlen(buf2);
	    if (acllen+2 > aclresultalloced) {
		aclresultalloced = acllen+2;
		offset = p - aclresult;
		aclresult = xrealloc(aclresult, aclresultalloced);
		p = aclresult + offset;
	    }
	    strcpy(p, buf2);
	    p += strlen(p)-1;
	}
	if (*p != '\n') p++;
	*p = '\0';

	*acl = aclresult;
    }

    fclose(listfile);
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
    FILE *listfile = 0;
    int i;
    struct glob *g;
    int r;
    char *buf, *p;
    char *acl;
    char parent[MAX_NAME_LEN+1];
    unsigned parentlen;

    if (!listfname) mboxlist_getfname();

    /* Check for invalid name/partition */
    if (strlen(name) > MAX_NAME_LEN) return IMAP_MAILBOX_BADNAME;
    if (partition && strlen(partition) > MAX_PARTITION_LEN) {
	return IMAP_PARTITION_UNKNOWN;
    }
    for (i = 0; i < NUM_BADMBOXPATTERNS; i++) {
	g = glob_init(badmboxpatterns[i], GLOB_ICASE);
	if (GLOB_TEST(g, name) != -1) {
	    glob_free(&g);
	    return IMAP_MAILBOX_BADNAME;
	}
	glob_free(&g);
    }
    r = mboxlist_policycheck(name);
    if (r) return r;

    /* User has admin rights over their own mailbox namespace */
    if (mboxlist_userownsmailbox(userid, name)) {
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

	fclose(listfile);
	return r;
    }

    /* Open mailbox list file */
    listfile = fopen(listfname, "r+");
    if (!listfile) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", listfname);
	fatal("can't read mailbox list", EX_OSFILE);
    }

    /* Search for a parent */
    strcpy(parent, name);
    parentlen = 0;
    while (!parentlen && (p = strrchr(parent, '.'))) {
	*p = '\0';
	buf = 0;
	(void) n_binarySearchFD(fileno(listfile), parent, 0, &buf,
				&parentlen, 0, 0);
    }
    if (parentlen) {
	if (!partition) {
	    partition = buf + strlen(parent) + 1;
	    p = strchr(partition, '\t');
	    /* XXX assuming \t before running past buflen */
	    *p = '\0';
	}
	partition = strsave(partition);

	r = mboxlist_lookup(parent, (char **)0, &acl);
	assert(r == 0);
	if (!isadmin && !(acl_myrights(acl) & ACL_CREATE)) {
	    fclose(listfile);
	    free(partition);
	    return IMAP_PERMISSION_DENIED;
	}
	/* Copy acl, canonify case of parent prefix */
	acl = strsave(acl);
	strncpy(name, parent, strlen(parent));
    }
    else {
	if (!isadmin) {
	    fclose(listfile);
	    return IMAP_PERMISSION_DENIED;
	}
	
	acl = strsave("");
	if (!strncasecmp(name, "user.", 5)) {
	    /* XXX canonify case */
	    if (strchr(name+5, '.')) {
		/* Disallow creating user.X.* when no user.X */
		fclose(listfile);
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
	    /* XXX config_getstring("defaultacl", ... */
	    acl_set(&acl, "anybody", ACL_LOOKUP|ACL_READ|ACL_SEEN,
		    (long (*)())0, (char *)0);
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

    fclose(listfile);

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
char *partition;
int isadmin;
char *userid;
{
    FILE *listfile = 0;
    struct stat sbuffd, sbuffile;
    int r;
    char *buf, *p;
    unsigned offset, len, size;
    char *acl;
    char buf2[MAX_MAILBOX_PATH];
    char *root;
    FILE *newlistfile;
    int n, left;

    if (!listfname) mboxlist_getfname();

    /* Open and lock mailbox list file */
    listfile = fopen(listfname, "r+");
    for (;;) {
	if (!listfile) {
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", listfname);
	    fatal("can't read mailbox list", EX_OSFILE);
	}

	r = flock(fileno(listfile), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    syslog(LOG_ERR, "IOERROR: locking %s: %m", listfname);
	    return IMAP_IOERROR;
	}
	
	fstat(fileno(listfile), &sbuffd);
	r = stat(listfname, &sbuffile);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: stating %s: %m", listfname);
	    return IMAP_IOERROR;
	}

	size = sbuffd.st_size;
	if (sbuffd.st_ino == sbuffile.st_ino) break;

	fclose(listfile);
	listfile = fopen(listfname, "r+");
    }

    /* Check ability to create mailbox */
    r = mboxlist_createmailboxcheck(name, partition, isadmin, userid,
				    &acl, &partition);
    if (r) {
	fclose(listfile);
	return r;
    }

    /* Search for where the new entry goes */
    buf = 0;
    offset = n_binarySearchFD(fileno(listfile), name, 0, &buf, &len, 0, size);
    assert(len == 0);

    /* Get partition's path */
    sprintf(buf2, "partition-%s", partition);
    root = config_getstring(buf2, (char *)0);
    if (!root) {
	fclose(listfile);
	free(partition);
	free(acl);
	return IMAP_PARTITION_UNKNOWN;
    }
    if (strlen(root)+strlen(name)+20 > MAX_MAILBOX_PATH) {
	fclose(listfile);
	free(partition);
	free(acl);
	return IMAP_MAILBOX_BADNAME;
    }
    
    /* Create new mailbox list */
    newlistfile = fopen(newlistfname, "w+");
    if (!newlistfile) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", newlistfname);
	fclose(listfile);
	free(partition);
	free(acl);
	return IMAP_IOERROR;
    }

    /* Copy mailbox list, adding new entry */
    left = offset;
    rewind(listfile);
    while (left) {
	n = fread(buf2, 1, left<sizeof(buf2) ? left : sizeof(buf2), listfile);
	if (!n) {
	    syslog(LOG_ERR, "IOERROR: reading %s: %m", listfname);
	    fclose(listfile);
	    fclose(newlistfile);
	    free(partition);
	    free(acl);
	    return IMAP_IOERROR;
	}
	fwrite(buf2, 1, n, newlistfile);
	left -= n;
    }
    fprintf(newlistfile, "%s\t%s\t%s\n", name, partition, acl);
    free(partition);
    free(acl);
    while (n = fread(buf2, 1, sizeof(buf2), listfile)) {
	fwrite(buf2, 1, n, newlistfile);
    }
    fflush(newlistfile);
    if (ferror(newlistfile) || fsync(fileno(newlistfile))) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newlistfname);
	fclose(listfile);
	fclose(newlistfile);
	return IMAP_IOERROR;
    }
    fclose(newlistfile);

    /* Create new mailbox and move new mailbox list file into place */
    sprintf(buf2, "%s/%s", root, name);
    for (p = buf2 + strlen(root); *p; p++) {
	if (isupper(*p)) *p = tolower(*p);
	else if (*p == '.') *p = '/';
    }
    r = mailbox_create(name, buf2, format, (struct mailbox *)0);
    if (r) return r;
    if (rename(newlistfname, listfname) == -1) {
	syslog(LOG_ERR, "IOERROR: renaming %s: %m", listfname);
	fclose(listfile);
	return IMAP_IOERROR;
    }

    fclose(listfile);
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
{
    FILE *listfile = 0;
    struct stat sbuffd, sbuffile;
    int r;
    char *acl;
    long access;
    unsigned offset, len, size;
    char buf2[MAX_MAILBOX_PATH];
    FILE *newlistfile;
    char *buf;
    int n, left;
    char *p;
    struct mailbox mailbox;

    /* Can't DELETE INBOX */
    if (!strcasecmp(name, "inbox")) {
	return IMAP_MAILBOX_NOTSUPPORTED;
    }

    /* Check for request to delete a user */
    if (!strncasecmp(name, "user.", 5) && !strchr(name+5, '.')) {
	/* Only admins may delete user */
	if (!isadmin) return IMAP_PERMISSION_DENIED;

	r = mboxlist_lookup(name, (char **)0, &acl);
	if (r) return r;
	
	/* Check ACL before doing anything stupid */
	if (!(acl_myrights(acl) & ACL_DELETE)) return IMAP_PERMISSION_DENIED;
	/* XXX might have to lie about error code ? */
	
	/* Delete sub-mailboxes */
	strcpy(buf2, name);
	strcat(buf2, ".*");
	r = mboxlist_findall(buf2, 1, 0, mboxlist_deletesubmailbox);
	if (r) return r;

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

    if (!listfname) mboxlist_getfname();

    /* Open and lock mailbox list file */
    listfile = fopen(listfname, "r+");
    for (;;) {
	if (!listfile) {
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", listfname);
	    fatal("can't read mailbox list", EX_OSFILE);
	}

	r = flock(fileno(listfile), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    syslog(LOG_ERR, "IOERROR: locking %s: %m", listfname);
	    fclose(listfile);
	    return IMAP_IOERROR;
	}
	
	fstat(fileno(listfile), &sbuffd);
	r = stat(listfname, &sbuffile);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: stating %s: %m", listfname);
	    fclose(listfile);
	    return IMAP_IOERROR;
	}

	size = sbuffd.st_size;
	if (sbuffd.st_ino == sbuffile.st_ino) break;

	fclose(listfile);
	listfile = fopen(listfname, "r+");
    }

    r = mboxlist_lookup(name, (char **)0, &acl);
    if (r) {
	fclose(listfile);
	return r;
    }
    access = acl_myrights(acl);
    if (checkacl && !(access & ACL_DELETE)) {
	fclose(listfile);

	/* User has admin rights over their own mailbox namespace */
	if (mboxlist_userownsmailbox(userid, name)) {
	    isadmin = 1;
	}

	/* Lie about error if privacy demands */
	return (isadmin || (access & ACL_LOOKUP)) ?
	  IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
    }

    buf = 0;
    offset = n_binarySearchFD(fileno(listfile), name, 0, &buf, &len, 0, size);
    assert(len > 0);

    /* Calculate real length of entry */
    p = strchr(buf, '\t')+1;
    p = strchr(p, '\t')+1;
    len = p - buf + strlen(acl) + 1;

    /* Create new mailbox list */
    newlistfile = fopen(newlistfname, "w+");
    if (!newlistfile) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", newlistfname);
	fclose(listfile);
	return IMAP_IOERROR;
    }

    /* Copy mailbox list, removing entry */
    left = offset;
    rewind(listfile);
    while (left) {
	n = fread(buf2, 1, left<sizeof(buf2) ? left : sizeof(buf2), listfile);
	if (!n) {
	    syslog(LOG_ERR, "IOERROR: reading %s: %m", listfname);
	    fclose(listfile);
	    fclose(newlistfile);
	    return IMAP_IOERROR;
	}
	fwrite(buf2, 1, n, newlistfile);
	left -= n;
    }
    fseek(listfile, len, 1);
    while (n = fread(buf2, 1, sizeof(buf2), listfile)) {
	fwrite(buf2, 1, n, newlistfile);
    }
    fflush(newlistfile);
    if (ferror(newlistfile) || fsync(fileno(newlistfile))) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newlistfname);
	fclose(listfile);
	fclose(newlistfile);
	return IMAP_IOERROR;
    }
    fclose(newlistfile);
    
    /* Remove the mailbox and move new mailbox list file into place */
    r = mailbox_open_header(name, &mailbox);
    if (!r) r = mailbox_delete(&mailbox);
    if (r) {
	fclose(listfile);
	return r;
    }
    if (rename(newlistfname, listfname) == -1) {
	syslog(LOG_ERR, "IOERROR: renaming %s: %m", listfname);
	fclose(listfile);
	/* XXX We're left in an inconsistent state here */
	return IMAP_IOERROR;
    }

    fclose(listfile);

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
    FILE *listfile = 0;
    struct stat sbuffd, sbuffile;
    int r;
    long access;
    int isusermbox = 0;
    char inboxname[MAX_NAME_LEN];
    char *oldpath;
    char *buf, *p;
    unsigned size;
    unsigned oldoffset, oldlen;
    unsigned newoffset, newlen;
    char *acl;
    char buf2[MAX_MAILBOX_PATH];
    char *root;
    FILE *newlistfile;
    int n, left;

    if (!listfname) mboxlist_getfname();

    /* Open and lock mailbox list file */
    listfile = fopen(listfname, "r+");
    for (;;) {
	if (!listfile) {
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", listfname);
	    fatal("can't read mailbox list", EX_OSFILE);
	}

	r = flock(fileno(listfile), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    syslog(LOG_ERR, "IOERROR: locking %s: %m", listfname);
	    return IMAP_IOERROR;
	}
	
	fstat(fileno(listfile), &sbuffd);
	r = stat(listfname, &sbuffile);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: stating %s: %m", listfname);
	    return IMAP_IOERROR;
	}

	size = sbuffd.st_size;
	if (sbuffd.st_ino == sbuffile.st_ino) break;

	fclose(listfile);
	listfile = fopen(listfname, "r+");
    }

    /* Check ability to delete old mailbox */
    if (strcasecmp(oldname, "inbox") == 0) {
	/* Special case of renaming inbox */
	if (strlen(userid)+6 > MAX_MAILBOX_PATH) {
	    fclose(listfile);
	    return IMAP_MAILBOX_NONEXISTENT;
	}
	strcpy(inboxname, "user.");
	strcat(inboxname, userid);
	r = mboxlist_lookup(inboxname, &oldpath, &acl);
	if (r) {
	    fclose(listfile);
	    return r;
	}
	access = acl_myrights(acl);
	if (!(access & ACL_DELETE)) {
	    fclose(listfile);
	    return IMAP_PERMISSION_DENIED;
	}
	isusermbox = 1;
    }
    else if (!strncasecmp(oldname, "user.", 5) && !strchr(oldname+5, '.')) {
	/* Even admins can't rename users */
	fclose(listfile);
	return IMAP_PERMISSION_DENIED;
    }
    else {
	r = mboxlist_lookup(oldname, &oldpath, &acl);
	if (r) {
	    fclose(listfile);
	    return r;
	}
	access = acl_myrights(acl);
	if (!(access & ACL_DELETE)) {
	    fclose(listfile);
	    return (isadmin || (access & ACL_LOOKUP)) ?
	      IMAP_PERMISSION_DENIED : IMAP_MAILBOX_NONEXISTENT;
	}
    }
    acl = strsave(acl);

    /* Check ability to create new mailbox */
    if (!strncasecmp(newname, "user.", 5) && !strchr(newname+5, '.')) {
	/* Even admins can't rename to user's inboxes */
	fclose(listfile);
	free(acl);
	return IMAP_PERMISSION_DENIED;
    }
    r = mboxlist_createmailboxcheck(newname, partition, isadmin, userid,
				    (char **)0, &partition);
    if (r) {
	fclose(listfile);
	free(acl);
	return r;
    }
    
    /* Search for the old entry's location */
    if (isusermbox) {
	oldoffset = oldlen = 0;
    }
    else {
	buf = 0;
	oldoffset = n_binarySearchFD(fileno(listfile), oldname, 0, &buf,
				     &oldlen, 0, size);
	assert(oldlen > 0);

	/* Calculate real length of entry */
	p = strchr(buf, '\t')+1;
	p = strchr(p, '\t')+1;
	oldlen = p - buf + strlen(acl) + 1;
    }

    /* Search for where the new entry goes */
    buf = 0;
    newoffset = n_binarySearchFD(fileno(listfile), newname, 0, &buf, &newlen,
				 0, size);

    /* Get partition's path */
    sprintf(buf2, "partition-%s", partition);
    root = config_getstring(buf2, (char *)0);
    if (!root) {
	fclose(listfile);
	free(acl);
	free(partition);
	return IMAP_PARTITION_UNKNOWN;
    }
    if (strlen(root)+strlen(newname)+20 > MAX_MAILBOX_PATH) {
	fclose(listfile);
	free(acl);
	free(partition);
	return IMAP_MAILBOX_BADNAME;
    }
    
    /* Create new mailbox list */
    newlistfile = fopen(newlistfname, "w+");
    if (!newlistfile) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", newlistfname);
	fclose(listfile);
	free(acl);
	free(partition);
	return IMAP_IOERROR;
    }

    /* Copy mailbox list, changing entry */
    left = oldoffset <= newoffset ? oldoffset : newoffset;
    rewind(listfile);
    while (left) {
	n = fread(buf2, 1, left<sizeof(buf2) ? left : sizeof(buf2), listfile);
	if (!n) {
	    syslog(LOG_ERR, "IOERROR: reading %s: %m", listfname);
	    fclose(listfile);
	    fclose(newlistfile);
	    free(partition);
	    free(acl);
	    return IMAP_IOERROR;
	}
	fwrite(buf2, 1, n, newlistfile);
	left -= n;
    }
    if (oldoffset < newoffset) {
	left = newoffset - oldoffset;
	if (!isusermbox) {
	    fseek(listfile, oldlen, 1);
	    left -= oldlen;
	}
    }
    else {
	fprintf(newlistfile, "%s\t%s\t%s\n", newname, partition, acl);
	left = oldoffset - newoffset;
    }
    while (left) {
	n = fread(buf2, 1, left<sizeof(buf2) ? left : sizeof(buf2), listfile);
	if (!n) {
	    syslog(LOG_ERR, "IOERROR: reading %s: %m", listfname);
	    fclose(listfile);
	    fclose(newlistfile);
	    free(partition);
	    free(acl);
	    return IMAP_IOERROR;
	}
	fwrite(buf2, 1, n, newlistfile);
	left -= n;
    }
    if (oldoffset < newoffset) {
	fprintf(newlistfile, "%s\t%s\t%s\n", newname, partition, acl);
    }
    else {
	if (!isusermbox) {
	    fseek(listfile, oldlen, 1);
	}
    }
    free(partition);
    free(acl);
    while (n = fread(buf2, 1, sizeof(buf2), listfile)) {
	fwrite(buf2, 1, n, newlistfile);
    }
    fflush(newlistfile);
    if (ferror(newlistfile) || fsync(fileno(newlistfile))) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newlistfname);
	fclose(listfile);
	fclose(newlistfile);
	return IMAP_IOERROR;
    }
    fclose(newlistfile);

    /* Rename the mailbox and move new mailbox list file into place */
    sprintf(buf2, "%s/%s", root, newname);
    for (p = buf2 + strlen(root); *p; p++) {
	if (isupper(*p)) *p = tolower(*p);
	else if (*p == '.') *p = '/';
    }
    r = mailbox_rename(isusermbox ? inboxname : oldname,
		       newname, buf2, isusermbox);
    if (r) {
	fclose(listfile);
	return r;
    }
    if (rename(newlistfname, listfname) == -1) {
	syslog(LOG_ERR, "IOERROR: renaming %s: %m", listfname);
	fclose(listfile);
	/* XXX We're left in an inconsistent state here */
	return IMAP_IOERROR;
    }

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
    FILE *listfile;
    struct glob *g;
    char usermboxname[MAX_NAME_LEN];
    int usermboxnamelen;
    char buf[512], *bufp = buf;
    unsigned offset, buflen, prefixlen;
    long matchlen, minmatch;
    char *endname, *p, *acl;
    int rights;
    int r;

    if (!listfname) mboxlist_getfname();

    listfile = fopen(listfname, "r");
    if (!listfile) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", listfname);
	fatal("can't read mailbox list", EX_OSFILE);
    }

    g = glob_init(pattern, GLOB_ICASE|GLOB_HIERARCHY);

    /* Check for INBOX first of all */
    if (userid && !strchr(userid, '.') && strlen(userid)+5 < MAX_NAME_LEN) {
	strcpy(usermboxname, "user.");
	strcat(usermboxname, userid);

	if (GLOB_TEST(g, "inbox") != -1) {
	    buflen = sizeof(buf);
	    (void) n_binarySearchFD(fileno(listfile), usermboxname, 0, &bufp,
				    &buflen, 0, 0);
	    if (buflen) {
		r = (*proc)("INBOX", 5, 0);
		if (r) {
		    fclose(listfile);
		    glob_free(&g);
		    return r;
		}
	    }
	}

	strcat(usermboxname, ".");
	usermboxnamelen = strlen(usermboxname);
    }
    else {
	userid = 0;
    }

    /* Find fixed-string pattern prefix */
    for (p = pattern; *p; p++) {
	if (*p == '*' || *p == '%' || *p == '?') break;
    }
    prefixlen = p - pattern;
    *p = '\0';

    /* If user.X can match pattern, search for those mailboxes next */
    if (userid && !strncasecmp(usermboxname, pattern,
	    prefixlen < usermboxnamelen ? prefixlen : usermboxnamelen)) {

	buflen = sizeof(buf);
	offset = n_binarySearchFD(fileno(listfile), usermboxname, 0, &bufp,
				  &buflen, 0, 0);
	fseek(listfile, offset, 0);
	for (;;) {
	    if (!fgets(buf, sizeof(buf), listfile)) break;
	    /* XXX assuming \t before running past sizeof(buf) */
	    p = strchr(buf, '\t');
	    *p = '\0';
	    if (strncasecmp(buf, usermboxname, usermboxnamelen) != 0) break;
	    minmatch = 0;
	    while (minmatch >= 0) {
		matchlen = glob_test(g, buf, 0L, &minmatch);
		if (matchlen == -1) break;
		r = (*proc)(buf, matchlen, 1);
		if (r) {
		    fclose(listfile);
		    glob_free(&g);
		    return r;
		}
	    }
	    *p = '\t';
	    while (buf[strlen(buf)-1] != '\n') {
		if (!fgets(buf, sizeof(buf), listfile)) break;
	    }
	}
    }

    /* Search for all remaining mailboxes */
    buflen = sizeof(buf);
    offset = n_binarySearchFD(fileno(listfile), pattern, 0, &bufp,
			      &buflen, 0, 0);
    fseek(listfile, offset, 0);
    if (userid) usermboxname[--usermboxnamelen] = '\0';
    for (;;) {
	if (!fgets(buf, sizeof(buf), listfile)) break;
	/* XXX assuming \t before running past sizeof(buf) */
	endname = strchr(buf, '\t');
	*endname = '\0';
	if (strncasecmp(buf, pattern, prefixlen)) break;
	minmatch = 0;
	while (minmatch >= 0) {
	    matchlen = glob_test(g, buf, 0, &minmatch);
	    if (matchlen == -1 ||
		(userid &&
		 strncasecmp(buf, usermboxname, usermboxnamelen) == 0 &&
		 (buf[usermboxnamelen] == '\0' || buf[usermboxnamelen] == '.'))) {
		break;
	    }
	    if (isadmin) {
		r = (*proc)(buf, matchlen, 1);
		if (r) {
		    fclose(listfile);
		    glob_free(&g);
		    return r;
		}
	    }
	    else {
		/* XXX assuming \t before running past sizeof(buf) */
		acl = strchr(buf+strlen(buf)+1, '\t') + 1;
		p = strchr(acl, '\n');
		if (p) {
		    *p = '\0';
		}
		else {
		    r = mboxlist_lookup(buf, (char **)0, &acl);
		    assert(r == 0);
		}
		rights = acl_myrights(acl);
		if (rights & ACL_LOOKUP) {
		    r = (*proc)(buf, matchlen, (rights & ACL_CREATE));
		    if (r) {
			fclose(listfile);
			glob_free(&g);
			return r;
		    }
		}
		if (p) {
		    *p = '\n';
		}
	    }
	}
	*endname = '\t';
	while (buf[strlen(buf)-1] != '\n') {
	    if (!fgets(buf, sizeof(buf), listfile)) break;
	}
    }
	
    fclose(listfile);
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
    FILE *subsfile;
    char *subsfname, *newsubsfname;
    FILE *listfile;
    struct glob *g;
    char usermboxname[MAX_NAME_LEN];
    int usermboxnamelen;
    char buf[512], *bufp = buf;
    int r;
    unsigned offset, buflen, prefixlen;
    char *endname, *p;
    long matchlen, minmatch;
    char *acl;

    if (r = mboxlist_opensubs(userid, &subsfile, &subsfname, &newsubsfname)) {
	return r;
    }
    flock(fileno(subsfile), LOCK_UN);

    if (!listfname) mboxlist_getfname();

    listfile = fopen(listfname, "r");
    if (!listfile) {
	syslog(LOG_ERR, "IOERROR: opening %s: %m", listfname);
	fatal("can't read mailbox list", EX_OSFILE);
    }

    g = glob_init(pattern, GLOB_ICASE|GLOB_HIERARCHY);

    /* Check for INBOX first of all */
    if (userid && !strchr(userid, '.') && strlen(userid)+5 < MAX_NAME_LEN) {
	strcpy(usermboxname, "user.");
	strcat(usermboxname, userid);

	if (GLOB_TEST(g, "inbox") != -1) {
	    buflen = sizeof(buf);
	    (void) n_binarySearchFD(fileno(subsfile), usermboxname, 0, &bufp,
				    &buflen, 0, 0);
	    if (buflen) {
		r = (*proc)("INBOX", 5, 0);
		if (r) {
		    fclose(subsfile);
		    fclose(listfile);
		    glob_free(&g);
		    return r;
		}
	    }
	}

	strcat(usermboxname, ".");
	usermboxnamelen = strlen(usermboxname);
    }
    else {
	userid = 0;
    }

    /* Find fixed-string pattern prefix */
    for (p = pattern; *p; p++) {
	if (*p == '*' || *p == '%' || *p == '?') break;
    }
    prefixlen = p - pattern;
    *p = '\0';

    /* If user.X can match pattern, search for those mailboxes next */
    if (userid && !strncasecmp(usermboxname, pattern,
	    prefixlen < usermboxnamelen ? prefixlen : usermboxnamelen)) {

	buflen = sizeof(buf);
	offset = n_binarySearchFD(fileno(subsfile), usermboxname, 0, &bufp,
				  &buflen, 0, 0);
	fseek(subsfile, offset, 0);
	for (;;) {
	    if (!fgets(buf, sizeof(buf), subsfile)) break;
	    /* XXX assuming \t before running past sizeof(buf) */
	    p = strchr(buf, '\t');
	    *p = '\0';
	    if (strncasecmp(buf, usermboxname, usermboxnamelen)) break;
	    minmatch = 0;
	    while (minmatch >= 0) {
		matchlen = glob_test(g, buf, 0L, &minmatch);
		if (matchlen == -1) break;
		bufp = 0;
		buflen = 0;
		offset = n_binarySearchFD(fileno(listfile), buf,
					  0, &bufp, &buflen, 0, 0);
		if (buflen) {
		    r = (*proc)(buf, matchlen, 1);
		    if (r) {
			fclose(subsfile);
			fclose(listfile);
			glob_free(&g);
			return r;
		    }
		}
		else {
		    mboxlist_changesub(buf, userid, 0);
		    break;
		}
	    }
	}
    }

    /* Search for all remaining mailboxes */
    buflen = sizeof(buf);
    offset = n_binarySearchFD(fileno(subsfile), pattern, 0, &bufp,
			      &buflen, 0, 0);
    fseek(subsfile, offset, 0);
    if (userid) usermboxname[--usermboxnamelen] = '\0';
    for (;;) {
	if (!fgets(buf, sizeof(buf), subsfile)) break;
	/* XXX assuming \t before running past sizeof(buf) */
	endname = strchr(buf, '\t');
	*endname = '\0';
	if (strncasecmp(buf, pattern, prefixlen)) break;
	minmatch = 0;
	while (minmatch >= 0) {
	    matchlen = glob_test(g, buf, 0L, &minmatch);
	    if (matchlen == -1 ||
		(userid &&
		 strncasecmp(buf, usermboxname, usermboxnamelen) == 0 &&
		 (buf[usermboxnamelen] == '\0' || buf[usermboxnamelen] == '.'))) {
		break;
	    }
	    r = mboxlist_lookup(buf, (char **)0, &acl);
	    if (r == 0) {
		r = (*proc)(buf, matchlen, (acl_myrights(acl) & ACL_CREATE));
		if (r) {
		    fclose(subsfile);
		    fclose(listfile);
		    glob_free(&g);
		    return r;
		}
	    }
	    else {
		mboxlist_changesub(buf, userid, 0);
		break;
	    }
	}
    }
	
    fclose(subsfile);
    fclose(listfile);
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
    char inbox[MAX_MAILBOX_PATH];
    int r;
    char *acl;
    FILE *subsfile, *newsubsfile;
    char *subsfname, *newsubsfname;
    unsigned offset, len;
    char *buf = 0;
    int n;
    char copybuf[4096];
    
    if (r = mboxlist_opensubs(userid, &subsfile, &subsfname, &newsubsfname)) {
	return r;
    }

    /* Convert "inbox" to user.USERID */
    if (!strcasecmp(name, "inbox")) {
	strcpy(inbox, "user.");
	strcat(inbox, userid);
	name = inbox;
    }

    if (add) {
	/* Ensure mailbox exists and can be either seen or read by user */
	if (r = mboxlist_lookup(name, (char **)0, &acl)) {
	    fclose(subsfile);
	    return r;
	}
	if ((acl_myrights(acl) & (ACL_READ|ACL_LOOKUP)) == 0) {
	    fclose(subsfile);
	    return IMAP_MAILBOX_NONEXISTENT;
	}
    }

    /* Find where mailbox is/would go in subscription list */
    offset = n_binarySearchFD(fileno(subsfile), name, 0, &buf, &len, 0, 0);
    if (add) {
	if (len) {
	    fclose(subsfile);
	    return 0;		/* Already unsubscribed */
	}
    }
    else {
	if (!len) {
	    fclose(subsfile);
	    return 0;		/* Alredy subscribed */
	}
    }

    rewind(subsfile);
    newsubsfile = fopen(newsubsfname, "w");
    if (!newsubsfile) {
	syslog(LOG_ERR, "IOERROR: creating %s: %m", newsubsfname);
	fclose(subsfile);
	return IMAP_IOERROR;
    }

    /* Copy over subscription list, making change */
    while (offset) {
	n = fread(copybuf, 1,
		  offset < sizeof(copybuf) ? offset : sizeof(copybuf),
		  subsfile);
	if (!n) {
	    syslog(LOG_ERR, "IOERROR: reading %s: %m", subsfname);
	    fclose(subsfile);
	    fclose(newsubsfile);
	    return IMAP_IOERROR;
	}
	fwrite(copybuf, 1, n, newsubsfile);
	offset -= n;
    }

    if (add) {
	fprintf(newsubsfile, "%s\t\n", name);
    }
    else {
	fseek(subsfile, len, 1);
    }

    while (n = fread(copybuf, 1, sizeof(copybuf), subsfile)) {
	fwrite(copybuf, 1, n, newsubsfile);
    }
    fflush(newsubsfile);
    if (ferror(newsubsfile) || fsync(fileno(newsubsfile))) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newsubsfname);
	fclose(subsfile);
	fclose(newsubsfile);
	return IMAP_IOERROR;
    }	
    if (rename(newsubsfname, subsfname) == -1) {
	syslog(LOG_ERR, "IOERROR: renaming %s: %m", subsfname);
	fclose(subsfile);
	fclose(newsubsfile);
	return IMAP_IOERROR;
    }
    fclose(subsfile);
    fclose(newsubsfile);
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
    FILE *listfile = 0;
    struct stat sbuffd, sbuffile;
    int r;
    long access;
    int isusermbox = 0;
    char inboxname[MAX_NAME_LEN];
    char *buf, *p;
    char buf2[MAX_NAME_LEN];
    unsigned offset, len, size, namepartlen;
    char *acl, *newacl;
    FILE *newlistfile;
    int n, left;

    if (!listfname) mboxlist_getfname();

    /* Open and lock mailbox list file */
    listfile = fopen(listfname, "r+");
    for (;;) {
	if (!listfile) {
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", listfname);
	    fatal("can't read mailbox list", EX_OSFILE);
	}

	r = flock(fileno(listfile), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    syslog(LOG_ERR, "IOERROR: locking %s: %m", listfname);
	    return IMAP_IOERROR;
	}
	
	fstat(fileno(listfile), &sbuffd);
	r = stat(listfname, &sbuffile);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: stating %s: %m", listfname);
	    return IMAP_IOERROR;
	}

	size = sbuffd.st_size;
	if (sbuffd.st_ino == sbuffile.st_ino) break;

	fclose(listfile);
	listfile = fopen(listfname, "r+");
    }

    if (!strchr(userid, '.') &&
	strlen(userid) + 6 <= MAX_MAILBOX_PATH) {
	strcpy(inboxname, "user.");
	strcat(inboxname, userid);
	if (!strcasecmp(name, "inbox") ||
	    !strcasecmp(name, inboxname)) {
	    name = inboxname;
	    isusermbox = 1;
	}
	else if (!strncasecmp(name, inboxname, strlen(inboxname)) &&
		 name[strlen(inboxname)] == '.') {
	    isusermbox = 1;
	}
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

    if (!r) {
	newlistfile = fopen(newlistfname, "w+");
	if (!newlistfile) {
	    syslog(LOG_ERR, "IOERROR: creating %s: %m", newlistfname);
	    r = IMAP_IOERROR;
	}
    }

    if (r) {
	fclose(listfile);
	return r;
    }

    /* Make change to ACL */
    newacl = strsave(acl);
    if (rights) {
	if (acl_set(&newacl, identifier, acl_strtomask(rights),
		    isusermbox ? ensureOwnerRights : 0, userid)) {
	    fclose(listfile);
	    free(newacl);
	    return IMAP_INVALID_IDENTIFIER;
	}
    }
    else {
	if (acl_delete(&newacl, identifier,
		       isusermbox ? ensureOwnerRights : 0, userid)) {
	    fclose(listfile);
	    free(newacl);
	    return IMAP_INVALID_IDENTIFIER;
	}
    }

    /* Copy over mailbox list, making change */
    buf = 0;
    offset = n_binarySearchFD(fileno(listfile), name, 0, &buf, &len, 0, size);
    if (!len) {
	fclose(listfile);
	fclose(newlistfile);
	return IMAP_MAILBOX_NONEXISTENT;
    }
    p = strchr(buf, '\t')+1;
    p = strchr(p, '\t')+1;
    namepartlen = p - buf;

    left = offset + namepartlen;
    rewind(listfile);
    while (left) {
	n = fread(buf2, 1, left<sizeof(buf2) ? left : sizeof(buf2), listfile);
	if (!n) {
	    syslog(LOG_ERR, "IOERROR: reading %s: %m", listfname);
	    fclose(listfile);
	    fclose(newlistfile);
	    free(newacl);
	    return IMAP_IOERROR;
	}
	fwrite(buf2, 1, n, newlistfile);
	left -= n;
    }
    fprintf(newlistfile, "%s", newacl);
    fseek(listfile, strlen(acl), 1);
    while (n = fread(buf2, 1, sizeof(buf2), listfile)) {
	fwrite(buf2, 1, n, newlistfile);
    }
    fflush(newlistfile);
    if (ferror(newlistfile) || fsync(fileno(newlistfile))) {
	syslog(LOG_ERR, "IOERROR: writing %s: %m", newlistfname);
	fclose(listfile);
	fclose(newlistfile);
	free(newacl);
	return IMAP_IOERROR;
    }
    if (rename(newlistfname, listfname) == -1) {
	syslog(LOG_ERR, "IOERROR: renaming %s: %m", listfname);
	fclose(listfile);
	fclose(newlistfile);
	free(newacl);
	return IMAP_IOERROR;
    }
    fclose(listfile);
    fclose(newlistfile);
    free(newacl);
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
    FILE *listfile = 0;
    struct stat sbuffd, sbuffile;
    char *p;
    unsigned offset, len, size;
    char buf[MAX_MAILBOX_PATH];

    if (!root[0] || root[0] == '.' || strchr(root, '/')
	|| strchr(root, '*') || strchr(root, '%') || strchr(root, '?')) {
	return IMAP_MAILBOX_BADNAME;
    }
    
    quota = zeroquota;

    strcpy(quota_path, config_dir);
    strcat(quota_path, FNAME_QUOTADIR);
    quota.root = quota_path + strlen(quota_path);
    strcpy(quota.root, root);
    lcase(quota.root);

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
    if (!listfname) mboxlist_getfname();
    listfile = fopen(listfname, "r+");
    for (;;) {
	if (!listfile) {
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", listfname);
	    fatal("can't read mailbox list", EX_OSFILE);
	}

	r = flock(fileno(listfile), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    syslog(LOG_ERR, "IOERROR: locking %s: %m", listfname);
	    return IMAP_IOERROR;
	}
	
	fstat(fileno(listfile), &sbuffd);
	r = stat(listfname, &sbuffile);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: stating %s: %m", listfname);
	    return IMAP_IOERROR;
	}

	size = sbuffd.st_size;
	if (sbuffd.st_ino == sbuffile.st_ino) break;

	fclose(listfile);
	listfile = fopen(listfname, "r+");
    }

    /* Ensure there is at least one mailbox under the quota root */
    p = 0;
    offset = n_binarySearchFD(fileno(listfile), quota.root, 0, &p, &len, 0, size);
    if (!len) {
	fseek(listfile, offset, 0);
	if (!fgets(buf, sizeof(buf), listfile) ||
	    strncasecmp(quota.root, buf, strlen(quota.root)) != 0 ||
	    buf[strlen(quota.root)] != '.') {
	    fclose(listfile);
	    return IMAP_MAILBOX_NONEXISTENT;
	}
    }
    
    /* perhaps create .NEW, lock, check if it got recreated, move in place */
    quota.lock_count = 1;
    quota.used = 0;
    quota.limit = newquota;
    r = mailbox_write_quota(&quota);

    if (r) {
	fclose(listfile);
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
    fclose(listfile);
    return r;
}


/*
 * Open and lock the subscription list for 'userid'.
 * The FILE pointer pointed to by 'subsfile' is set to the open,
 * locked file.  The character pointers pointed to by 'fname' and
 * 'newfname' are set to the filenames of the old and new subscription
 * files, respectively.
 */
static int
mboxlist_opensubs(userid, subsfile, fname, newfname)
char *userid;
FILE **subsfile;
char **fname;
char **newfname;
{
    int r;
    static char *subsfname, *newsubsfname;
    int subsfd;
    struct stat sbuffile, sbuffd;
    char buf[MAX_MAILBOX_PATH];

    /* Users without INBOXes may not keep subscriptions */
    if (strchr(userid, '.') || strlen(userid) + 6 > MAX_MAILBOX_PATH) {
	return IMAP_PERMISSION_DENIED;
    }
    strcpy(buf, "user.");
    strcat(buf, userid);
    if (mboxlist_lookup(buf, (char **)0, (char **)0) != 0) {
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
    *subsfile = fdopen(subsfd, "r+");
    for (;;) {
	r = flock(fileno(*subsfile), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    syslog(LOG_ERR, "IOERROR: locking %s: %m", subsfname);
	    fclose(*subsfile);
	    return IMAP_IOERROR;
	}
	
	fstat(fileno(*subsfile), &sbuffd);
	r = stat(subsfname, &sbuffile);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: stating %s: %m", subsfname);
	    fclose(*subsfile);
	    return IMAP_IOERROR;
	}

	if (sbuffd.st_ino == sbuffile.st_ino) break;

	fclose(*subsfile);
	*subsfile = fopen(subsfname, "r+");
	if (!*subsfile) {
	    syslog(LOG_ERR, "IOERROR: opening %s: %m", subsfname);
	    return IMAP_IOERROR;
	}
    }

    *fname = subsfname;
    *newfname = newsubsfname;
    return 0;
}

/*
 * Get the filenames of the mailbox list and the temporary file to
 * use when updating the mailbox list.
 */
static mboxlist_getfname()
{
    listfname = xmalloc(strlen(config_dir)+sizeof(FNAME_MBOXLIST));
    strcpy(listfname, config_dir);
    strcat(listfname, FNAME_MBOXLIST);
    newlistfname = xmalloc(strlen(config_dir)+sizeof(FNAME_MBOXLIST)+4);
    strcpy(newlistfname, config_dir);
    strcat(newlistfname, FNAME_MBOXLIST);
    strcat(newlistfname, ".NEW");
}

/*
 * Apply site policy restrictions on mailbox names.
 * Restrictions are hardwired for now.
 */
#define GOODCHARS "+,-.0123456789:=@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
static int mboxlist_policycheck(name)
char *name;
{
    if (*name == '~') return IMAP_MAILBOX_BADNAME;
    while (*name) {
	if (!strchr(GOODCHARS, *name++)) return IMAP_MAILBOX_BADNAME;
    }
    return 0;
}

/*
 * Check whether user owns mailbox
 */
static int mboxlist_userownsmailbox(userid, name)
char *userid;
char *name;
{
    if (!strchr(userid, '.') && !strncasecmp(name, "user.", 5) &&
	!strncasecmp(name+5, userid, strlen(userid)) &&
	name[5+strlen(userid)] == '.') {
	return 1;
    }
    return 0;
}

/*
 * ACL access canonification routine which ensures that 'owner'
 * retains lookup, administer, and create rights over a mailbox.
 */
static long ensureOwnerRights(owner, identifier, access)
char *owner;
char *identifier;
long access;
{
    if (strcasecmp(identifier, owner) != 0) return access;
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

    if (mailbox.quota.root) {
	if (strlen(mailbox.quota.root) >= strlen(mboxlist_newquota->root)) {
	    /* Part of a child quota root */
	    mailbox_close(&mailbox);
	    return 0;
	}

	r = mailbox_lock_quota(&mailbox.quota);
	if (r) goto error;
	mailbox.quota.used -= mailbox.quota_mailbox_used;
	r = mailbox_write_quota(&mailbox.quota);
	if (r) {
	    syslog(LOG_ERR,
		   "LOSTQUOTA: unable to record free of %d bytes in quota %s",
		   mailbox.quota_mailbox_used, mailbox.quota.root);
	}
	mailbox_unlock_quota(&mailbox.quota);
	free(mailbox.quota.root);
    }

    mailbox.quota.root = strsave(mboxlist_newquota->root);
    r = mailbox_write_header(&mailbox);
    if (r) goto error;

    mboxlist_newquota->used += mailbox.quota_mailbox_used;
    return 0;

 error:
    mailbox_close(&mailbox);
 error_noclose:
    syslog(LOG_ERR, "LOSTQUOTA: unable to change quota root for %s to %s: %s",
	   name, mboxlist_newquota->root, error_message(r));
    
    return 0;
}

/*
 * Helper function to delete a user's sub-mailbox when deleting that user
 */
static int mboxlist_deletesubmailbox(name, matchlen, maycreate)
char *name;
int matchlen;
int maycreate;
{
    return mboxlist_deletemailbox(name, 1, "", 0);
}
