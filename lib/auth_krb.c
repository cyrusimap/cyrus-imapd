/* auth_krb.c -- Kerberos authorization
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

#include <limits.h>
#include <stdio.h>
#include <ctype.h>
#include <krb.h>

#include "auth.h"

#ifndef KRB_MAPNAME
#define KRB_MAPNAME "/etc/krb.equiv"
#endif

static char auth_userid[MAX_K_NAME_SZ+1] = "anonymous";
static char auth_aname[ANAME_SZ] = "anonymous";
static char auth_inst[INST_SZ];
static char auth_realm[REALM_SZ];

static int parse_krbequiv_line P((const char *src,
				  char *principal, char *localuser));
char *auth_map_krbid P((const char *real_aname, const char *real_inst,
			const char *real_realm));

/*
 * Determine if the user is a member of 'identifier'
 * Returns one of:
 * 	0	User does not match identifier
 * 	1	identifier matches everybody
 *	2	User is in the group that is identifier
 *	3	User is identifer
 */
auth_memberof(identifier)
const char *identifier;
{
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];

    if (strcmp(identifier, "anyone") == 0) return 1;

    if (strcmp(identifier, auth_userid) == 0) return 3;

    /* "anonymous" is not a member of any group */
    if (strcmp(auth_userid, "anonymous") == 0) return 0;

    aname[0] = inst[0] = realm[0] = '\0';
    if (kname_parse(aname, inst, realm, identifier) != 0) {
	return 0;
    }

    if (strcmp(aname, auth_aname) != 0 && strcmp(aname, "*") != 0) {
	return 0;
    }
    if (strcmp(inst, auth_inst) != 0 && strcmp(inst, "*") != 0) {
	return 0;
    }
    if (strcmp(realm, auth_realm) != 0 && strcmp(realm, "*") != 0) {
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
		else if (krb_get_krbhst(krbhst, realm, 0)) {
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
char *auth_canonifyid(identifier)
const char *identifier;
{
    static char retbuf[MAX_K_NAME_SZ+1];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char lrealm[REALM_SZ];
    char krbhst[256];
    char *p;
    
    if (strcasecmp(identifier, "anonymous") == 0) {
	return "anonymous";
    }
    if (strcasecmp(identifier, "anybody") == 0 ||
	strcasecmp(identifier, "anyone") == 0) {
	return "anyone";
    }
    
    aname[0] = inst[0] = realm[0] = '\0';
    if (kname_parse(aname, inst, realm, identifier) != 0) {
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
	else if (krb_get_krbhst(krbhst, realm, 0)) {
	    return 0;		/* Unknown realm */
	}
    }

    /* Check for krb.equiv remappings. */
    if (p = auth_map_krbid(aname, inst, realm)) {
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
auth_setid(identifier, cacheid)
const char *identifier;
const char *cacheid;
{
    identifier = auth_canonifyid(identifier);
    if (!identifier) return -1;

    strcpy(auth_userid, identifier);
    auth_aname[0] = auth_inst[0] = auth_realm[0] = '\0';
    kname_parse(auth_aname, auth_inst, auth_realm, identifier);
    return 0;
}

