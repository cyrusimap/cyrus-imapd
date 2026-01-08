/* acl_afs.c -- AFS-style ACL interpretation */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */
/*
 * The user gets the cumulative set of rights granted to identifiers
 * of which they are a member.  Then, the cumulative set of negative
 * rights (rights granted to identifiers with '-' prepended to an
 * identifier of which they are a member) are removed.
 *
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
#include "lib/libcyr_cfg.h"

/*
 * Calculate the set of rights the user in 'auth_state' has in the ACL 'acl'.
 */
EXPORTED int cyrus_acl_myrights(const struct auth_state *auth_state, const char *origacl)
{
    int admin_implies_write = libcyrus_config_getswitch(CYRUSOPT_ACL_ADMIN_IMPLIES_WRITE);
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

    if (admin_implies_write && (acl_positive & ACL_ADMIN)) {
        acl_positive |= ACL_SETSEEN | ACL_WRITE | ACL_INSERT
                     | ACL_DELETEMSG | ACL_EXPUNGE | ACL_ANNOTATEMSG;
    }

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
    if (*userid == '-') userid++;

    if (!strcmp(userid, "anyone")) return 1;
    if (!strcmp(userid, "anonymous")) return 1;
    if (strarray_contains(config_admins, userid)) return 1;

    return 0;
}
