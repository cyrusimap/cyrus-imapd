/*
 * Mailbox list manipulation routines
 */

#include <stdio.h>
#include <sysexits.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>

#include <acl.h>
#include <glob.h>
#include "assert.h"
#include "config.h"
#include "mailbox.h"
#include "imap_err.h"
#include "xmalloc.h"

static char *listfname, *newlistfname;

#define FNAME_MBOXLIST "/mailboxes"

/*
 * Maximum length of a mailbox name.  This, plus the partition name
 * must be at least 3 less than the size of the binary-search buffer
 * [512]
 */
#define MAX_NAME_LEN 500
#define MAX_NAME_PARTITION_LEN 509

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

    listfile = fopen(listfname, "r");
    if (!listfile) {
	fatal("can't read mailbox list", EX_OSFILE);
    }

    offset = n_binarySearchFD(fileno(listfile), name, 0, &buf, &buflen, 0, 0);
    if (!buflen) {
	fclose(listfile);
	return IMAP_MAILBOX_NONEXISTENT;
    }
	
    strncpy(name, buf, namelen);

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
	    fseek(listfile, offset+buflen, 0);
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

mboxlist_createmailbox(name, format, partition, isadmin, username)
char *name;
char *partition;
int isadmin;
char *username;
{
    FILE *listfile = 0;
    int i;
    struct glob *g;
    struct stat sbuffd, sbuffile;
    int r;
    char *buf, *p;
    unsigned offset, len, size;
    char *acl;
    char parent[MAX_NAME_LEN+1];
    unsigned parentlen;
    char buf2[MAX_MAILBOX_PATH];
    char *root;
    FILE *newlistfile;
    int n, left;

    if (!listfname) mboxlist_getfname();

    /* Check for invalid name */
    if (strlen(name) > MAX_NAME_LEN) return IMAP_MAILBOX_BADNAME;
    if (partition && strlen(partition)+strlen(name) > MAX_NAME_PARTITION_LEN) {
	return IMAP_MAILBOX_BADNAME;
    }
    for (i = 0; i < NUM_BADMBOXPATTERNS; i++) {
	g = glob_init(badmboxpatterns[i], 1);
	if (glob_test(g, name, -1)) {
	    free((char *)g);
	    return IMAP_MAILBOX_BADNAME;
	}
	glob_free(g);
    }
    r = mboxlist_policycheck(name);
    if (r) return r;

    /* User has admin rights over their own mailbox namespace */
    if (!strchr(username, '.') && !strncasecmp(name, "user.", 5) &&
	!strncasecmp(name+5, username, strlen(username)) &&
	name[5+strlen(username)] == '.') {
	isadmin = 1;
    }

    /* Open and lock mailbox list file */
    listfile = fopen(listfname, "r+");
    for (;;) {
	if (!listfile) {
	    fatal("can't read mailbox list", EX_OSFILE);
	}

	r = flock(fileno(listfile), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    return IMAP_IOERROR;
	}
	
	fstat(fileno(listfile), &sbuffd);
	r = stat(listfname, &sbuffile);
	if (r == -1) {
	    return IMAP_IOERROR;
	}

	size = sbuffd.st_size;
	if (sbuffd.st_ino == sbuffile.st_ino) break;

	fclose(listfile);
	listfile = fopen(listfname, "r+");
    }

    /* Search for where the new entry goes */
    buf = 0;
    offset = n_binarySearchFD(fileno(listfile), name, 0, &buf, &len, 0, size);
    if (len) {
	r = IMAP_MAILBOX_EXISTS;
	
	if (!isadmin) {
	    r = mboxlist_lookup(name, (char **)0, &acl);
	    assert(r == 0);
	    if (!(acl_myrights(acl) & ACL_LOOKUP)) {
		r = IMAP_PERMISSION_DENIED;
	    }
	    if (acl) free(acl);
	}
	fclose(listfile);
	return r;
    }

    /* Search for a parent */
    strcpy(parent, name);
    parentlen = 0;
    while (!parentlen && (p = strrchr(parent, '.'))) {
	*p = '\0';
	buf = 0;
	(void) n_binarySearchFD(fileno(listfile), parent, 0, &buf,
				&parentlen, 0, size);
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
	    free(acl);
	    return IMAP_PERMISSION_DENIED;
	}
	strncpy(name, parent, strlen(parent)); /* Canonify case */
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
	    acl_set(&acl, name+5, ACL_ALL);
	}
	else {
	    /* XXX config_getstring("defaultacl", ... */
	    acl_set(&acl, "anybody", ACL_LOOKUP|ACL_READ|ACL_SEEN);
	}

	partition = strsave(config_defpartition);
    }	      

    if (strlen(partition)+strlen(name) > MAX_NAME_PARTITION_LEN) {
	fclose(listfile);
	free(partition);
	free(acl);
	return IMAP_MAILBOX_BADNAME;
    }
    
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
    
    newlistfile = fopen(newlistfname, "w+");
    if (!newlistfile) {
	fclose(listfile);
	free(partition);
	free(acl);
	return IMAP_IOERROR;
    }

    left = offset;
    rewind(listfile);
    while (left) {
	n = fread(buf2, 1, left<sizeof(buf2) ? left : sizeof(buf2), listfile);
	if (!n) {
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
    while (n = fread(buf2, 1, sizeof(buf2), listfile)) {
	fwrite(buf2, 1, n, newlistfile);
    }
    fflush(newlistfile);
    if (ferror(newlistfile) || fsync(fileno(newlistfile))) {
	fclose(listfile);
	fclose(newlistfile);
	free(acl);
	return IMAP_IOERROR;
    }
    fclose(newlistfile);

    sprintf(buf2, "%s/%s", root, name);
    for (p = buf2 + strlen(root); *p; p++) {
	if (isupper(*p)) *p = tolower(*p);
	else if (*p == '.') *p = '/';
    }

    r = mailbox_create(name, buf2, format);
    if (r || rename(newlistfname, listfname) == -1) {
	fclose(listfile);
	free(acl);
	return IMAP_IOERROR;
    }

    fclose(listfile);
    free(acl);
    return 0;
}
	


static mboxlist_getfname()
{
    char *val = config_getstring("configdirectory", "");
    listfname = xmalloc(strlen(val)+sizeof(FNAME_MBOXLIST));
    strcpy(listfname, val);
    strcat(listfname, FNAME_MBOXLIST);
    newlistfname = xmalloc(strlen(val)+sizeof(FNAME_MBOXLIST)+4);
    strcpy(newlistfname, val);
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
