/*
 * Mailbox list manipulation routines
 */

#include <stdio.h>
#include <sysexits.h>
#include <string.h>

#include "config.h"
#include "imap_err.h"
#include "xmalloc.h"

static char *listfname;

mboxlist_nametopath(name, path)
char *name;
char **path;
{
    int len = strlen(name);
    FILE *listfile;
    char buf[4096];
    char buf2[1024];
    char *p, *partition, *root;
    static char *result;
    static int resultalloced;

    if (!listfname) mboxlist_getfname();

    listfile = fopen(listfile, "r");
    if (!listfile) {
	fatal("can't read mailbox list", EX_OSFILE);
    }

    while (fgets(buf, sizeof(buf), listfile)) {
	p = strchr(buf, ' ');
	if (!p) continue;
	
	if (p - buf != len) continue;
	if (strncasecmp(name, buf, len) != 0) continue;

	partition = ++p;
	p = strchr(buf, ' ');
	if (!p) {
	    fclose(listfile);
	    return IMAP_PARTITION_UNKNOWN;
	}
	*p = '\0';
	sprintf(buf2, "partition-%s", partition);
	root = config_getstring(buf2, (char *)0);
	if (!root) {
	    fclose(listfile);
	    return IMAP_PARTITION_UNKNOWN;
	}
	
	len += 2 + strlen(root);
	if (len > resultalloced) {
	    resultalloced = len;
	    result = xrealloc(result, len);
	}

	strcpy(result, root);
	strcat(result, "/");
	strcat(result, buf);
	
	for (p = result + strlen(root); *p; p++) {
	    if (isupper(*p)) *p = tolower(*p);
	    else if (*p == '.') *p = '/';
	}

	*path = result;
	return 0;
    }
    return IMAP_MAILBOX_NONEXISTENT;
}

#define FNAME_MBOXLIST "/mailboxes"

static mboxlist_getfname()
{
    char *val = config_getstring("configdirectory");
    listfname = xmalloc(strlen(val)+sizeof(FNAME_MBOXLIST));
    strcpy(listfname, val);
    strcat(listfname, FNAME_MBOXLIST);
}
