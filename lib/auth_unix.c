/* auth_unix.c -- Unix passwd file authorization
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

#include <pwd.h>
#include <grp.h>
#include <ctype.h>

#include "auth.h"
#include "xmalloc.h"

struct auth_state {
    char userid[81];
    char **group;
    int ngroups;
};

static struct auth_state auth_anonymous = {
    "anonymous", 0, 0
};

/*
 * Determine if the user is a member of 'identifier'
 * Returns one of:
 * 	0	User does not match identifier
 * 	1	identifier matches everybody
 *	2	User is in the group that is identifier
 *	3	User is identifer
 */
auth_memberof(auth_state, identifier)
struct auth_state *auth_state;
const char *identifier;
{
    int i;

    if (!auth_state) auth_state = &auth_anonymous;
 
    if (strcmp(identifier, "anyone") == 0) return 1;

    if (strcmp(identifier, auth_state->userid) == 0) return 3;

    if (strncmp(identifier, "group:", 6) != 0) return 0;

    for (i=0; i<auth_state->ngroups; i++) {
	if (strcmp(identifier+6, auth_state->group[i]) == 0) return 2;
    }
    return 0;
}

/*
 * Convert 'identifier' into canonical form.
 * Returns a pointer to a static buffer containing the canonical form
 * or NULL if 'identifier' is invalid.
 */
char *auth_canonifyid(identifier)
const char *identifier;
{
    static char retbuf[81];
    struct group *grp;
    char *p;

    if (strcasecmp(identifier, "anonymous") == 0) {
	return "anonymous";
    }
    if (strcasecmp(identifier, "anybody") == 0 ||
	strcasecmp(identifier, "anyone") == 0) {
	return "anyone";
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

    if (strlen(identifier) >= sizeof(retbuf)) return 0;

    p = retbuf;
    if (!isalpha(*identifier)) return 0;
    while (*identifier) {
	*p = *identifier++;
	if (!isalpha(*p) && !isdigit(*p) && *p != '-') return 0;
	p++;
    }
    *p = 0;

    return retbuf;
}

/*
 * Set the current user to 'identifier'.  'cacheid', if non-null,
 * points to a 16-byte binary key to cache identifier's information
 * with.
 */
struct auth_state *
auth_newstate(identifier, cacheid)
const char *identifier;
const char *cacheid;
{
    struct auth_state *newstate;
    struct passwd *pwd;
    struct group *grp;
    char **mem;

    identifier = auth_canonifyid(identifier);
    if (!identifier) return 0;
    if (!strncmp(identifier, "group:", 6)) return 0;
    
    pwd = getpwnam(identifier);

    newstate = (struct auth_state *)xmalloc(sizeof(struct auth_state));

    strcpy(newstate->userid, identifier);
    newstate->ngroups = 0;

    setgrent();
    while (grp = getgrent()) {
	for (mem = grp->gr_mem; *mem; mem++) {
	    if (!strcmp(*mem, identifier)) break;
	}

	if (*mem || (pwd && pwd->pw_gid == grp->gr_gid)) {
	    newstate->ngroups++;
	    newstate->group = (char **)xrealloc((char *)newstate->group,
						newstate->ngroups * sizeof(char *));
	    newstate->group[newstate->ngroups-1] = xstrdup(grp->gr_name);
	}
    }
    endgrent();
    return newstate;
}

void
auth_freestate(auth_state)
struct auth_state *auth_state;
{
    if (auth_state->group) free((char *)auth_state->group);
    free((char *)auth_state);
}


