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
 $Id: acl_afs.c,v 1.22 2003/02/13 20:15:38 rjs3 Exp $
 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "acl.h"
#include "auth.h"
#include "xmalloc.h"

/*
 * Calculate the set of rights the user in 'auth_state' has in the ACL 'acl'.
 * 'acl' must be writable, but is restored to its original condition.
 */
int cyrus_acl_myrights(auth_state, acl)
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
	    *acl_ptr |= cyrus_acl_strtomask(rights);
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
int cyrus_acl_set(acl, identifier, mode, access, canonproc, canonrock)
char **acl;
const char *identifier;
int mode;
int access;
cyrus_acl_canonproc_t *canonproc;
void *canonrock;
{
    char *newidentifier = 0;
    char *newacl;
    char *thisid, *nextid;
    int oldaccess = 0;
    char *rights;

    /* Convert 'identifier' into canonical form */
    if (*identifier == '-') {
	char *canonid = auth_canonifyid(identifier+1, 0);
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
	identifier = auth_canonifyid(identifier, 0);
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
	    oldaccess = cyrus_acl_strtomask(rights);
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
	(void) cyrus_acl_masktostr(access, newacl + strlen(newacl));
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
int cyrus_acl_remove(char **acl, const char *identifier, 
	       cyrus_acl_canonproc_t canonproc, void *canonrock)
{
    return cyrus_acl_set(acl, identifier, ACL_MODE_SET, 0, canonproc, canonrock);
}
