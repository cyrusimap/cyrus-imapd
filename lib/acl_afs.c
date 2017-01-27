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
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "acl.h"
#include "auth.h"
#include "xmalloc.h"
#include "strarray.h"
#include "libconfig.h"

/*
 * Calculate the set of rights the user in 'auth_state' has in the ACL 'acl'.
 */
EXPORTED int cyrus_acl_myrights(const struct auth_state *auth_state, const char *origacl)
{
    char *acl = xstrdupsafe(origacl);
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
            int mask;
            cyrus_acl_strtomask(rights, &mask);
            /* XXX and if strtomask fails? */
            *acl_ptr |= mask;
        }
    }

    free(acl);

    return acl_positive & ~acl_negative;
}

/*
 * Modify the ACL pointed to by 'acl' to make the rights granted to
 * 'identifier' the set specified in the mask 'access'.  The pointer
 * pointed to by 'acl' must have been obtained from malloc().
 */
EXPORTED int cyrus_acl_set(char **acl, const char *identifier,
                  int mode, int access,
                  cyrus_acl_canonproc_t *canonproc,
                  void *canonrock)
{
    const char *canonid;
    char *newidentifier = 0;
    char *newacl;
    char *thisid, *nextid;
    int oldaccess = 0;
    char *rights;

    if (!identifier)
        return -1;

    /* Convert 'identifier' into canonical form */
    canonid = auth_canonifyid(*identifier == '-' ? identifier+1 : identifier, 0);
    if (canonid) {
        if (*identifier == '-') {
            newidentifier = xmalloc(strlen(canonid)+2);
            newidentifier[0] = '-';
            strcpy(newidentifier+1, canonid);
            identifier = newidentifier;
        } else {
            identifier = canonid;
        }
    } else if (access != 0L) {
        return -1;
    } else {
        /* trying to delete invalid/non-existent identifier */
    }

    /* Prevent ACLs for empty identifiers */
    if (strlen(identifier) == 0) {
        if (newidentifier) free(newidentifier);
        return -1;
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
            cyrus_acl_strtomask(rights, &oldaccess);
            /* XXX and if strtomask fails? */
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

    if (canonproc) {
        if (*identifier == '-')
            access = ~(canonproc(canonrock, identifier+1, ~access));
        else
            access = canonproc(canonrock, identifier, access);
    }

    if (access == 0L) {
        /* Remove any existing entry for 'identifier'.
           Special case: When we try to delete an invalid/non-existent identifier,
           both 'thisid' and 'nextid' point to the end of *acl. */
        newacl = xmalloc(strlen(*acl) + strlen(nextid) - strlen(thisid) + 1);
        /* Copy existing ACLs without the current identifier.
           Note: The buffer will not be zero terminated. */
        strncpy(newacl, *acl, (thisid - *acl));
        /* Append the remaining ACL string. Zero-terminates the string. */
        strcpy(newacl + (thisid - *acl), nextid);

        free(*acl);
        *acl = newacl;
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
EXPORTED int cyrus_acl_remove(char **acl, const char *identifier,
               cyrus_acl_canonproc_t canonproc, void *canonrock)
{
    return cyrus_acl_set(acl, identifier, ACL_MODE_SET, 0, canonproc, canonrock);
}

EXPORTED int is_system_user(const char *userid)
{
    static strarray_t *admins = NULL;

    if (!admins) admins = strarray_split(config_getstring(IMAPOPT_ADMINS), NULL, STRARRAY_TRIM);

    if (!strcmp(userid, "anyone")) return 1;
    if (!strcmp(userid, "anonymous")) return 1;
    if (strarray_find(admins, userid, 0) >= 0)
        return 1;

    return 0;
}
