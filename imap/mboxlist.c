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
#define FNAME_USERDIR "/user/"
#define FNAME_SUBSSUFFIX ".sub"

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

mboxlist_createmailbox(name, format, partition, isadmin, userid)
char *name;
char *partition;
int isadmin;
char *userid;
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
	g = glob_init(badmboxpatterns[i], GLOB_ICASE);
	if (glob_test(g, name, -1)) {
	    glob_free(g);
	    return IMAP_MAILBOX_BADNAME;
	}
	glob_free(g);
    }
    r = mboxlist_policycheck(name);
    if (r) return r;

    /* User has admin rights over their own mailbox namespace */
    if (!strchr(userid, '.') && !strncasecmp(name, "user.", 5) &&
	!strncasecmp(name+5, userid, strlen(userid)) &&
	name[5+strlen(userid)] == '.') {
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
	
mboxlist_findall(pattern, isadmin, userid)
char *pattern;
int isadmin;
char *userid;
{
    FILE *listfile;
    struct glob *g;
    char usermboxname[MAX_NAME_LEN];
    int usermboxnamelen;
    char buf[512], *bufp = buf;
    unsigned offset, buflen, prefixlen;
    char *endname, *p, *acl;
    int r;

    if (!listfname) mboxlist_getfname();

    listfile = fopen(listfname, "r");
    if (!listfile) {
	fatal("can't read mailbox list", EX_OSFILE);
    }

    g = glob_init(pattern, GLOB_ICASE);

    if (!strchr(userid, '.') && strlen(userid)+5 < MAX_NAME_LEN) {
	strcpy(usermboxname, "user.");
	strcat(usermboxname, userid);

	if (glob_test(g, "inbox", -1)) {
	    buflen = sizeof(buf);
	    (void) n_binarySearchFD(fileno(listfile), usermboxname, 0, &bufp,
				    &buflen, 0, 0);
	    if (buflen) printf("* MAILBOX INBOX\r\n");
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

    /* If user.X can match pattern, search for those mailboxes first */
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
	    if (strncasecmp(buf, usermboxname, usermboxnamelen)) break;
	    if (glob_test(g, buf, -1)) printf("* MAILBOX %s\r\n", buf);
	    *p = '\t';
	    while (buf[strlen(buf)-1] != '\n') {
		if (!fgets(buf, sizeof(buf), listfile)) break;
	    }
	}
    }

    buflen = sizeof(buf);
    offset = n_binarySearchFD(fileno(listfile), pattern, 0, &bufp,
			      &buflen, 0, 0);
    fseek(listfile, offset, 0);
    usermboxname[--usermboxnamelen] = '\0';
    for (;;) {
	if (!fgets(buf, sizeof(buf), listfile)) break;
	/* XXX assuming \t before running past sizeof(buf) */
	endname = strchr(buf, '\t');
	*endname = '\0';
	if (strncasecmp(buf, pattern, prefixlen)) break;
	if (glob_test(g, buf, -1) &&
	    (strncasecmp(buf, usermboxname, usermboxnamelen) ||
	     (buf[usermboxnamelen] != '\0' && buf[usermboxnamelen] != '.'))) {
	    if (isadmin) {
		printf("* MAILBOX %s\r\n", buf);
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
		if (acl_myrights(acl) & ACL_LOOKUP) {
		    printf("* MAILBOX %s\r\n", buf);
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
    glob_free(g);
    return;
}

mboxlist_find(pattern, isadmin, userid)
char *pattern;
int isadmin;
char *userid;
{
    FILE *subsfile;
    char *subsfname, *newsubsfname;
    FILE *listfile;
    struct glob *g;
    char usermboxname[MAX_NAME_LEN];
    int usermboxnamelen;
    char buf[512], *bufp = buf;
    unsigned offset, buflen, prefixlen;
    char *endname, *p;

    if (mboxlist_opensubs(userid, &subsfile, &subsfname, &newsubsfname)) {
	return;
    }
    flock(fileno(subsfile), LOCK_UN);

    if (!listfname) mboxlist_getfname();

    listfile = fopen(listfname, "r");
    if (!listfile) {
	fatal("can't read mailbox list", EX_OSFILE);
    }

    g = glob_init(pattern, GLOB_ICASE);

    if (!strchr(userid, '.') && strlen(userid)+5 < MAX_NAME_LEN) {
	strcpy(usermboxname, "user.");
	strcat(usermboxname, userid);

	if (glob_test(g, "inbox", -1)) {
	    buflen = sizeof(buf);
	    (void) n_binarySearchFD(fileno(subsfile), usermboxname, 0, &bufp,
				    &buflen, 0, 0);
	    if (buflen) printf("* MAILBOX INBOX\r\n");
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

    /* If user.X can match pattern, search for those mailboxes first */
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
	    if (glob_test(g, buf, -1)) {
		bufp = 0;
		buflen = 0;
		offset = n_binarySearchFD(fileno(listfile), buf,
					  0, &bufp, &buflen, 0, 0);
		if (buflen) {
		    printf("* MAILBOX %s\r\n", buf);
		}
		else {
		    mboxlist_changesub(buf, userid, 0);
		}
	    }
	}
    }

    buflen = sizeof(buf);
    offset = n_binarySearchFD(fileno(subsfile), pattern, 0, &bufp,
			      &buflen, 0, 0);
    fseek(subsfile, offset, 0);
    usermboxname[--usermboxnamelen] = '\0';
    for (;;) {
	if (!fgets(buf, sizeof(buf), subsfile)) break;
	/* XXX assuming \t before running past sizeof(buf) */
	endname = strchr(buf, '\t');
	*endname = '\0';
	if (strncasecmp(buf, pattern, prefixlen)) break;
	if (glob_test(g, buf, -1) &&
	    (strncasecmp(buf, usermboxname, usermboxnamelen) ||
	     (buf[usermboxnamelen] != '\0' && buf[usermboxnamelen] != '.'))) {
	    bufp = 0;
	    buflen = 0;
	    offset = n_binarySearchFD(fileno(listfile), buf,
				      0, &bufp, &buflen, 0, 0);
	    if (buflen) {
		printf("* MAILBOX %s\r\n", buf);
	    }
	    else {
		mboxlist_changesub(buf, userid, 0);
	    }
	}
    }
	
    fclose(subsfile);
    fclose(listfile);
    glob_free(g);
    return;
}

int mboxlist_changesub(name, userid, add)
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

    if (!strcasecmp(name, "inbox")) {
	strcpy(inbox, "user.");
	strcat(inbox, userid);
	name = inbox;
    }

    if (add) {
	/* Ensure mailbox exists and can be either seen or read */
	if (r = mboxlist_lookup(name, (char **)0, &acl)) {
	    fclose(subsfile);
	    return r;
	}
	if ((acl_myrights(acl) & (ACL_READ|ACL_LOOKUP)) == 0) {
	    fclose(subsfile);
	    return IMAP_MAILBOX_NONEXISTENT;
	}
    }

    offset = n_binarySearchFD(fileno(subsfile), name, 0, &buf, &len, 0, 0);
    if (add) {
	if (len) {
	    fclose(subsfile);
	    return IMAP_MAILBOX_SUBSCRIBED;
	}
    }
    else {
	if (!len) {
	    fclose(subsfile);
	    return IMAP_MAILBOX_UNSUBSCRIBED;
	}
    }

    rewind(subsfile);
    newsubsfile = fopen(newsubsfname, "w");
    if (!newsubsfile) {
	fclose(subsfile);
	return IMAP_IOERROR;
    }

    while (offset) {
	n = fread(copybuf, 1,
		  offset < sizeof(copybuf) ? offset : sizeof(copybuf),
		  subsfile);
	if (!n) {
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
    if (ferror(newsubsfile) || fsync(fileno(newsubsfile)) ||
	rename(newsubsfname, subsfname) == -1) {
	fclose(subsfile);
	fclose(newsubsfile);
	return IMAP_IOERROR;
    }
    fclose(subsfile);
    fclose(newsubsfile);
    return 0;
}

    
static int
mboxlist_opensubs(userid, subsfile, fname, newfname)
char *userid;
FILE **subsfile;
char **fname;
char **newfname;
{
    int r;
    char *val;
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
    val = config_getstring("configdirectory", "");
    subsfname = xmalloc(strlen(val)+sizeof(FNAME_USERDIR)+
			strlen(userid)+sizeof(FNAME_SUBSSUFFIX));
    strcpy(subsfname, val);
    strcat(subsfname, FNAME_USERDIR);
    strcat(subsfname, userid);
    strcat(subsfname, FNAME_SUBSSUFFIX);
    newsubsfname = xmalloc(strlen(subsfname)+5);
    strcpy(newsubsfname, subsfname);
    strcat(newsubsfname, ".NEW");

    subsfd = open(subsfname, O_RDWR|O_CREAT, 0666);
    if (subsfd == -1) {
	return IMAP_IOERROR;
    }
    *subsfile = fdopen(subsfd, "r+");
    for (;;) {
	r = flock(fileno(*subsfile), LOCK_EX);
	if (r == -1) {
	    if (errno == EINTR) continue;
	    fclose(*subsfile);
	    return IMAP_IOERROR;
	}
	
	fstat(fileno(*subsfile), &sbuffd);
	r = stat(subsfname, &sbuffile);
	if (r == -1) {
	    fclose(*subsfile);
	    return IMAP_IOERROR;
	}

	if (sbuffd.st_ino == sbuffile.st_ino) break;

	fclose(*subsfile);
	*subsfile = fopen(subsfname, "r+");
	if (!*subsfile) {
	    return IMAP_IOERROR;
	}
    }

    *fname = subsfname;
    *newfname = newsubsfname;
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
