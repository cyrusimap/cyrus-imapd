/* auth_krb.c -- Kerberos authorization
 * $Id: auth_krb.c,v 1.36.6.4 2003/02/27 18:12:08 rjs3 Exp $
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
 */

#include <config.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>

#include <krb.h>
#ifdef HAVE_LIBDB
#ifdef HAVE_DB_185_H
#include <db_185.h>
#else
#include <db.h>
#endif
#else
#include <ndbm.h>
#endif
#include <krb.h>

#include "xmalloc.h"
#include "auth.h"

const char *auth_method_desc = "krb";

#ifndef KRB_MAPNAME
#define KRB_MAPNAME "/etc/krb.equiv"
#endif

struct auth_state {
    char userid[MAX_K_NAME_SZ+1];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
};

static struct auth_state auth_anonymous = {
    "anonymous", "anonymous", "", ""
};



static int parse_krbequiv_line (const char *src,
				  char *principal, char *localuser);
char *auth_map_krbid (const char *real_aname, const char *real_inst,
		      const char *real_realm);

/*
 * Determine if the user is a member of 'identifier'
 * Returns one of:
 * 	0	User does not match identifier
 * 	1	identifier matches everybody
 *	2	User is in the group that is identifier
 *	3	User is identifer
 */
int
auth_memberof(auth_state, identifier)
struct auth_state *auth_state;
const char *identifier;
{
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];

    if (!auth_state) auth_state = &auth_anonymous;

    if (strcmp(identifier, "anyone") == 0) return 1;

    if (strcmp(identifier, auth_state->userid) == 0) return 3;

    /* "anonymous" is not a member of any group */
    if (strcmp(auth_state->userid, "anonymous") == 0) return 0;

    aname[0] = inst[0] = realm[0] = '\0';
    if (kname_parse(aname, inst, realm, (char *) identifier) != 0) {
	return 0;
    }

    if (strcmp(aname, auth_state->aname) != 0 && strcmp(aname, "*") != 0) {
	return 0;
    }
    if (strcmp(inst, auth_state->inst) != 0 && strcmp(inst, "*") != 0) {
	return 0;
    }
    if (strcmp(realm, auth_state->realm) != 0 && strcmp(realm, "*") != 0) {
	return 0;
    }
    return 2;
}

/*
 * Parse a line 'src' from an /etc/krb.equiv file.
 * Sets the buffer pointed to by 'principal' to be the kerberos
 * identity and sets the buffer pointed to by 'localuser' to
 * be the local user.  Both buffers must be of size one larger than
 * MAX_K_NAME_SZ.  Returns 1 on success, 0 on failure.
 */
static int
parse_krbequiv_line(src, principal, localuser)
const char *src;
char *principal;
char *localuser;
{
    int i;

    while (isspace(*src)) src++;
    if (!*src) return 0;

    for (i = 0; *src && !isspace(*src); i++) {
	if (i >= MAX_K_NAME_SZ) return 0;
	*principal++ = *src++;
    }
    *principal = 0;

    if (!isspace(*src)) return 0; /* Need at least one separator */
    while (isspace(*src)) src++;
    if (!*src) return 0;
  
    for (i = 0; *src && !isspace(*src); i++) {
	if (i >= MAX_K_NAME_SZ) return 0;
	*localuser++ = *src++;
    }
    *localuser = 0;
    return 1;
}

/*
 * Map a remote kerberos principal to a local username.  If a mapping
 * is found, a pointer to the local username is returned.  Otherwise,
 * a NULL pointer is returned.
 * Eventually, this may be more sophisticated than a simple file scan.
 */
char *auth_map_krbid(real_aname, real_inst, real_realm)
const char *real_aname;
const char *real_inst;
const char *real_realm;
{
    static char localuser[MAX_K_NAME_SZ + 1];
    char principal[MAX_K_NAME_SZ + 1];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char lrealm[REALM_SZ];
    char krbhst[256];
    char *p;
    char buf[1024];
    FILE *mapfile;

    if (!(mapfile = fopen(KRB_MAPNAME, "r"))) {
	/* If the file can't be opened, don't do mappings */
	return 0;
    }

    for (;;) {
	if (!fgets(buf, sizeof(buf), mapfile)) break;
	if (parse_krbequiv_line(buf, principal, localuser) == 0 ||
	    kname_parse(aname, inst, realm, principal) != 0) {
	    /* Ignore badly formed lines */
	    continue;
	}
	if (!strcmp(aname, real_aname) && !strcmp(inst, real_inst) &&
	    !strcmp(realm, real_realm)) {
	    fclose(mapfile);

	    aname[0] = inst[0] = realm[0] = '\0';
	    if (kname_parse(aname, inst, realm, localuser) != 0) {
		return 0;
	    }

	    /* Upcase realm name */
	    for (p = realm; *p; p++) {
		if (islower(*p)) *p = toupper(*p);
	    }

	    if (*realm) {
		if (krb_get_lrealm(lrealm,1) == 0 &&
		    strcmp(lrealm, realm) == 0) {
		    *realm = 0;
		}
		else if (krb_get_krbhst(krbhst, realm, 1)) {
		    return 0;		/* Unknown realm */
		}
	    }

	    strcpy(localuser, aname);
	    if (*inst) {
		strcat(localuser, ".");
		strcat(localuser, inst);
	    }
	    if (*realm) {
		strcat(localuser, "@");
		strcat(localuser, realm);
	    }
	    
	    return localuser;
	}
    }

    fclose(mapfile);
    return 0;
}

/*
 * Convert 'identifier' into canonical form.
 * Returns a pointer to a static buffer containing the canonical form
 * or NULL if 'identifier' is invalid.
 */
char *auth_canonifyid(identifier, len)
const char *identifier;
size_t len;
{
    static char retbuf[MAX_K_NAME_SZ+1];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char lrealm[REALM_SZ];
    char krbhst[256];
    char *canon_buf;
    char *p;

    if(!len) len = strlen(identifier);

    canon_buf = malloc(len + 1);
    if(!canon_buf) return 0;
    memcpy(canon_buf, identifier, len);
    canon_buf[len] = '\0';
   
    aname[0] = inst[0] = realm[0] = '\0';
    if (kname_parse(aname, inst, realm, canon_buf) != 0) {
	free(canon_buf);
	return 0;
    }

    free(canon_buf);

    /* Upcase realm name */
    for (p = realm; *p; p++) {
	if (islower(*p)) *p = toupper(*p);
    }

    if (*realm) {
	if (krb_get_lrealm(lrealm,1) == 0 &&
	    strcmp(lrealm, realm) == 0) {
	    *realm = 0;
	}
	else if (krb_get_krbhst(krbhst, realm, 1)) {
	    return 0;		/* Unknown realm */
	}
    }

    /* Check for krb.equiv remappings. */
    if ((p = auth_map_krbid(aname, inst, realm)) ) {
        strcpy(retbuf, p);
        return retbuf;
    }

    strcpy(retbuf, aname);
    if (*inst) {
	strcat(retbuf, ".");
	strcat(retbuf, inst);
    }
    if (*realm) {
	strcat(retbuf, "@");
	strcat(retbuf, realm);
    }

    return retbuf;
}

/*
 * Set the current user to 'identifier'.  'cacheid', if non-null,
 * points to a 16-byte binary key to cache identifier's information
 * with.
 */
struct auth_state *
auth_newstate(const char *identifier)
{
    struct auth_state *newstate;

    identifier = auth_canonifyid(identifier, 0);
    if (!identifier) return 0;

    newstate = (struct auth_state *)xmalloc(sizeof(struct auth_state));

    strcpy(newstate->userid, identifier);
    newstate->aname[0] = newstate->inst[0] = newstate->realm[0] = '\0';
    kname_parse(newstate->aname, newstate->inst, newstate->realm, (char *) identifier);

    return newstate;
}

void
auth_freestate(auth_state)
struct auth_state *auth_state;
{
    free((char *)auth_state);
}

