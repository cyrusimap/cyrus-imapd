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
