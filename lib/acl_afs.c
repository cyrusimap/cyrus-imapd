/*
 * AFS-style ACL interpretation
 *
 * The user gets the cumulative set of rights granted to identifiers
 * of which they are a member.  Then, the cumulative set of negative
 * rights (rights granted to identifiers with '-' prepended to an
 * identifier of which they are a member) are removed.
 *
 */

#include <stdio.h>
#include <string.h>

#include <acl.h>
#include "auth.h"
#include "xmalloc.h"

/*
 * Calculate the set of rights the user has in the ACL 'acl'.
 * 'acl' must be writable, but is restored to its original condition.
 */
long acl_myacl(acl)
char *acl;
{
    char *thisid, *rights, *nextid;
    long acl_positive = 0, acl_negative = 0;
    long *acl_ptr;

    for (thisid = acl; *thisid; thisid = nextid) {
	acl_ptr = &acl_positive;
	rights = strchr(thisid, '\t');
	if (!rights) {
	    break;
	}
	*rights++ = '\0';

	nextid = strchr(rights, '\t');
	if (!nextid) {
	    break;
	}
	*nextid++ = '\0';

	if (*thisid == '-') {
	    acl_ptr = &acl_negative;
	    thisid++;
	}
	if (auth_memberof(thisid)) {
	    *acl_ptr |= acl_strtomask(rights);
	}

	/* Put the delimiters back */
	rights[-1] = '\t';
	nextid[-1] = '\t';
    }

    acl_positive &= ~acl_negative;

    /* XXX add in base rights */

    return acl_positive;
}
	
/*
 * Modify the ACL pointed to by 'acl' to make the rights granted to
 * 'identifier' the set specified in the mask 'access'.  The pointer
 * pointed to by 'acl' must have been obtained from malloc().
 */
acl_set(acl, identifier, access)
char **acl;
char *identifier;
long access;
{
    char *newacl;
    char *thisid, *nextid;
    char *rights;

    /* Convert 'identifier' into canonical form */
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

    /* Find any existing entry for 'identifier' in 'acl' */
    for (thisid = *acl; *thisid; thisid = nextid) {
	rights = strchr(thisid, '\t');
	if (!rights) {
	    /* ACK, nuke trailing garbage */
	    *thisid = '\0';
	    nextid = thisid;
	    break;
	}
	*rights++ = '\0';

	nextid = strchr(rights, '\t');
	if (!nextid) {
	    /* ACK, nuke trailing garbage */
	    *thisid = '\0';
	    nextid = thisid;
	    break;
	}
	*nextid++ = '\0';

	if (strcmp(identifier, thisid) == 0) break;
	rights[-1] = '\t';
	nextid[-1] = '\t';
    }
    if (access == 0L) {
	/* Remove any existing entry for 'identifier' */
	strcpy(thisid, nextid);
    }
    else {
	/* Replace any existing entry for 'identifier' */
	newacl = xmalloc((thisid - *acl) + strlen(identifier) + 40 +
			 strlen(nextid));
	strncpy(newacl, *acl, (thisid - *acl));
	strcpy(newacl + (thisid - *acl), identifier);
	strcat(newacl, "\t");
	(void) acl_masktostr(access, newacl + strlen(newacl));
	strcat(newacl, "\t");
	strcat(newacl, nextid);
	free(*acl);
	*acl = newacl;
    }

    if (*identifier == '-') free(identifier);
    return 0;
}

/*
 * Remove any entry for 'identifier' in the ACL pointed to by 'acl'.
 * The pointer pointed to by 'acl' must have been obtained from malloc().
 */
acl_delete(acl, identifier)
char **acl;
char *identifier;
{
    return acl_set(acl, identifier, 0L);
}
