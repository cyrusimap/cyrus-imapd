/*
 * AFS-style ACL interpretation
 *
 * The user gets the cumulative set of rights granted to identifiers
 * of which they are a member.  Then, the cumulative set of negative
 * rights (rights granted to identifiers with '-' prepended to an
 * identifier of which they are a member) are removed.
 *
 */
/* 
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */

#include <stdio.h>
#include <string.h>

#include "acl.h"
#include "auth.h"
#include "xmalloc.h"

/*
 * Calculate the set of rights the user in 'auth_state' has in the ACL 'acl'.
 * 'acl' must be writable, but is restored to its original condition.
 */
int acl_myrights(auth_state, acl)
struct auth_state *auth_state;
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
	    rights[-1] = '\t';
	    break;
	}
	*nextid++ = '\0';

	if (*thisid == '-') {
	    acl_ptr = &acl_negative;
	    thisid++;
	}
	if (auth_memberof(auth_state, thisid)) {
	    *acl_ptr |= acl_strtomask(rights);
	}

	/* Put the delimiters back */
	rights[-1] = '\t';
	nextid[-1] = '\t';
    }

    return acl_positive & ~acl_negative;
}
	
/*
 * Modify the ACL pointed to by 'acl' to make the rights granted to
 * 'identifier' the set specified in the mask 'access'.  The pointer
 * pointed to by 'acl' must have been obtained from malloc().
 */
int acl_set(acl, identifier, mode, access, canonproc, canonrock)
char **acl;
const char *identifier;
int mode;
int access;
acl_canonproc_t *canonproc;
void *canonrock;
{
    char *newidentifier = 0;
    char *newacl;
    char *thisid, *nextid;
    int oldaccess = 0;
    char *rights;

    /* Convert 'identifier' into canonical form */
    if (*identifier == '-') {
	char *canonid = auth_canonifyid(identifier+1);
	if (!canonid) {
	    return -1;
	}
	newidentifier = xmalloc(strlen(canonid)+2);
	newidentifier[0] = '-';
	strcpy(newidentifier+1, canonid);
	identifier = newidentifier;
	if (canonproc) {
	    access = ~(canonproc(canonrock, canonid, ~access));
	}
    }
    else {
	identifier = auth_canonifyid(identifier);
	if (!identifier) {
	    return -1;
	}
	if (canonproc) {
	    access = canonproc(canonrock, identifier, access);
	}
    }

    /* Find any existing entry for 'identifier' in 'acl' */
    for (thisid = nextid = *acl; *thisid; thisid = nextid) {
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

	if (strcmp(identifier, thisid) == 0) {
	    oldaccess = acl_strtomask(rights);
	    break;
	}
	rights[-1] = '\t';
	nextid[-1] = '\t';
    }

    switch (mode) {
    case ACL_MODE_SET:
	break;

    case ACL_MODE_ADD:
	access |= oldaccess;
	break;

    case ACL_MODE_REMOVE:
	access = oldaccess & ~access;
	break;
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

    if (newidentifier) free(newidentifier);
    return 0;
}

/*
 * Remove any entry for 'identifier' in the ACL pointed to by 'acl'.
 * The pointer pointed to by 'acl' must have been obtained from malloc().
 */
acl_remove(acl, identifier, canonproc, canonrock)
char **acl;
const char *identifier;
acl_canonproc_t canonproc;
void *canonrock;
{
    return acl_set(acl, identifier, ACL_MODE_SET, 0, canonproc, canonrock);
}
