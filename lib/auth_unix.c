/* auth_unix.c -- Unix passwd file authorization
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <pwd.h>
#include <grp.h>

#include "xmalloc.h"

static char auth_userid[30] = "anonymous";
static char **auth_group;
static int auth_ngroups;

/*
 * Determine if the user is a member of 'identifier'
 * Returns one of:
 * 	0	User does not match identifier
 * 	1	identifier matches everybody
 *	2	User is in the group that is identifier
 *	3	User is identifer
 */
auth_memberof(identifier)
char *identifier;
{
    int i;

    if (strcmp(identifier, "anybody") == 0) return 1;

    if (strcmp(identifier, auth_userid) == 0) return 3;

    if (strncmp(identifier, "group:", 6) != 0) return 0;

    for (i=0; i<auth_ngroups; i++) {
	if (strcmp(identifier+6, auth_group[i]) == 0) return 2;
    }
    return 0;
}

/*
 * Convert 'identifier' into canonical form.
 * Returns a pointer to a static buffer containing the canonical form
 * or NULL if 'identifier' is invalid.
 */
char *auth_canonifyid(identifier)
char *identifier;
{
    static char retbuf[30];
    struct passwd *pwd;
    struct group *grp;

    if (strcasecmp(identifier, "anonymous") == 0) {
	return "anonymous";
    }
    if (strcasecmp(identifier, "anybody") == 0) {
	return "anybody";
    }
    
    if (strlen(identifier) >= sizeof(retbuf)) return 0;
    strcpy(retbuf, identifier);
    lcase(retbuf);

    if (!strncmp(retbuf, "group:", 6)) {
	grp = getgrnam(retbuf+6);
	if (!grp) return 0;
	strcpy(retbuf+6, grp->gr_name);
	return retbuf;
    }

    pwd = getpwnam(retbuf);
    if (!pwd) return 0;
    strcpy(retbuf, pwd->pw_name);
    return retbuf;
}

/*
 * Set the current user to 'identifier'
 */
auth_setid(identifier)
char *identifier;
{
    struct passwd *pwd;
    struct group *grp;
    char **mem;

    identifier = auth_canonifyid(identifier);
    if (!identifier) return -1;
    if (!strncmp(identifier, "group:", 6)) return -1;
    
    pwd = getpwnam(identifier);
    if (!pwd) return -1;

    strcpy(auth_userid, identifier);
    auth_ngroups = 0;

    setgrent();
    while (grp = getgrent()) {
	for (mem = grp->gr_mem; *mem; mem++) {
	    if (!strcmp(*mem, identifier)) break;
	}

	if (*mem || pwd->pw_gid == grp->gr_gid) {
	    auth_ngroups++;
	    auth_group = (char **)xrealloc((char *)auth_group,
					   auth_ngroups * sizeof(char *));
	    auth_group[auth_ngroups-1] = strsave(grp->gr_name);
	}
    }
    endgrent();
    return 0;
}

