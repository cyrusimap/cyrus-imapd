#include <stdio.h>
#include "acl.h"
#include "xmalloc.h"

long acl_myacl(acl)
char *acl;
{
    char *thisid, *nextid;
    long acl_positive = 0, acl_negative = 0;
    long *acl_ptr;

    for (thisid = *acl, *thisid, thisid = nextid) {
	acl_ptr = &acl_positive;
	nextid = strchr(thisid, '\r');
	if (!nextid) {
	    break;
	}
	*nextid++ = '\0';

	rights = strchr(thisid, '\t');
	if (!rights) {
	    strcpy(thisid, nextid ? nextid : "");
	    nextid = thisid;
	    continue;
	}
	*rights++ = '\0';

	if (*thisid == '-') {
	    acl_ptr = &acl_negative;
	    thisid++;
	}
	if (auth_memberof(thisid)) {
	    *acl_ptr |= acl_strtoacl(rights);
	}

	rights[-1] = '\t';
	nextid[-1] = '\r';
    }

    acl_positive &= ~acl_negative;

    /* XXX add in base rights */

    return acl_positive;
}
	
acl_set(acl, identifier, access)
char **acl;
char *identifier;
long access;
{
    int r;
    char *newacl;
    char *thisid, *nextid;
    char *thisrights;
    long thisbits;

    if (*identifier == '-') {
	char *canonid = auth_canonifyid(identifier+1);
	if (!canonid) {
	    return 1;		/* XXX invalid ACL identifier */
	}
	identifier = xmalloc(strlen(canonid)+2);
	identifier[0] = '-';
	strcpy(identifier+1, canonid);
    }
    else {
	identifier = auth_canonifyid(identifier);
	if (!identifier) {
	    return 1;		/* XXX invalid ACL identifier */
	}
    }

    /* XXX also canonify access bits.  Something clever for neg. acl */

    for (thisid = *acl; *thisid; thisid = nextid) {
	nextid = strchr(thisid, '\r');
	if (!nextid) {
	    /* ACK, nuke trailing garbage */
	    *thisid = '\0';
	    nextid = thisid;
	    break;
	}
	*nextid++ = '\0';

	rights = strchr(thisid, '\t');
	if (!rights) {
	    strcpy(thisid, nextid ? nextid : "");
	    nextid = thisid;
	    continue;
	}
	*rights = '\0';
	if (strcmp(identifier, thisid) == 0) break;
	*rights = '\t';
	nextid[-1] = '\r';
    }
    if (access == 0L) {
	strcpy(thisid, nextid);
    }
    else {
	newacl = xmalloc((thisid - *acl) + strlen(identifier) + 40 +
			 strlen(nextid));
	strncpy(newacl, *acl, (thisid - *acl));
	strcpy(newacl + (thisid - *acl), identifier);
	strcat(newacl, "\t");
	(void) acl_acltostr(access, newacl + strlen(newacl));
	strcat(newacl, "\n");
	strcat(newacl, nextid);
	free(*acl);
	*acl = newacl;
    }

    if (*identifier == '-') free(identifier);
    return 0;
}

acl_delete(acl, identifier)
char **acl;
char *identifier);
{
    return acl_set(acl, identifier, 0L);
}
