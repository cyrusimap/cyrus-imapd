/* auth_unix.c -- Unix passwd file authorization
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 */

/*
 * $Id: auth_unix.c,v 1.33.2.3 2002/12/11 20:40:29 rjs3 Exp $
 */

#include <config.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <string.h>

#include "auth.h"
#include "libcyr_cfg.h"
#include "xmalloc.h"

const char *auth_method_desc = "unix";

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
int auth_memberof(auth_state, identifier)
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

/* Map of which characters are allowed by auth_canonifyid.
 * Key: 0 -> not allowed (special, ctrl, or would confuse Unix or imapd)
 *      1 -> allowed, but requires an alpha somewhere else in the string
 *      2 -> allowed, and is an alpha
 *
 * At least one character must be an alpha.
 *
 * This may not be restrictive enough.
 * Here are the reasons for the restrictions:
 *
 * &	forbidden because of MUTF-7.  (This could be fixed.)
 * :    forbidden because it's special in /etc/passwd
 * /    forbidden because it can't be used in a mailbox name
 * * %  forbidden because they're IMAP magic in the LIST/LSUB commands
 * ?    it just scares me
 * ctrl chars, DEL
 *      can't send them as IMAP characters in plain folder names, I think
 * 80-FF forbidden because you can't send them in IMAP anyway
 *       (and they're forbidden as folder names). (This could be fixed.)
 *
 * + and - are *allowed* although '+' is probably used for userid+detail
 * subaddressing and qmail users use '-' for subaddressing.
 *
 * Identifiers don't require a digit, really, so that should probably be
 * relaxed, too.
 */
static char allowedchars[256] = {
 /* 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 00-0F */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 10-1F */
    1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, /* 20-2F */
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, /* 30-3F */

    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 40-4F */
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, /* 50-5F */
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 60-6F */
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 0, /* 70-7F */

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * Convert 'identifier' into canonical form.
 * Returns a pointer to a static buffer containing the canonical form
 * or NULL if 'identifier' is invalid.
 *
 * XXX If any of the characters marked with 0 are valid and are cropping up,
 * the right thing to do is probably to canonicalize the identifier to two
 * representations: one for getpwent calls and one for folder names.  The
 * latter canonicalizes to a MUTF7 representation.
 */
char *auth_canonifyid(identifier, len)
const char *identifier;
size_t len;
{
    static char retbuf[81];
    struct group *grp;
    char sawalpha;
    char *p;

    if(!len) len = strlen(identifier);
    if(len >= sizeof(retbuf)) return NULL;

    memcpy(retbuf, identifier, len);
    retbuf[len] = '\0';

    /* This used to be far more restrictive, but many sites seem to ignore the 
     * ye olde Unix conventions of username.  Specifically, we used to
     * - drop case on the buffer
     * - disallow lots of non-alpha characters ('-', '_', others)
     * Now we do neither of these, but impose a very different policy based on 
     * the character map above.
     */
    
    if (!strncmp(retbuf, "group:", 6)) {
	grp = getgrnam(retbuf+6);
	if (!grp) return 0;
	strcpy(retbuf+6, grp->gr_name);
	return retbuf;
    }

    /* Copy the string and look up values in the allowedchars array above.
     * If we see any we don't like, reject the string.
     */
    sawalpha = 0;
    for(p = retbuf; *p; p++) {
	switch (allowedchars[*(unsigned char*) p]) {
	case 0:
	    return NULL;
	    
	case 2:
	    sawalpha = 1;
	    /* FALL THROUGH */
	    
	default:
	    ;
	}
    }

    if (!sawalpha) return NULL;  /* has to be one alpha char */

    return retbuf;
}

/*
 * Set the current user to 'identifier'.  'cacheid', if non-null,
 * points to a 16-byte binary key to cache identifier's information
 * with.
 */
struct auth_state *auth_newstate(const char *identifier)
{
    struct auth_state *newstate;
    struct passwd *pwd;
    struct group *grp;
    char **mem;

    identifier = auth_canonifyid(identifier, 0);
    if (!identifier) return 0;
    if (!strncmp(identifier, "group:", 6)) return 0;
    
    pwd = getpwnam(identifier);

    newstate = (struct auth_state *)xmalloc(sizeof(struct auth_state));

    strcpy(newstate->userid, identifier);
    newstate->ngroups = 0;
    newstate->group = NULL;
    
    if(!libcyrus_config_getswitch(CYRUSOPT_AUTH_UNIX_GROUP_ENABLE))
	return newstate;

    setgrent();
    while ((grp = getgrent())) {
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


