/*
 * Kerberos authorization
 */

#include <ctype.h>
#include <krb.h>

char auth_userid[MAX_K_NAME_SZ+1] = "anonymous";
char auth_aname[ANAME_SZ] = "anonymous";
char auth_inst[INST_SZ];
char auth_realm[REALM_SZ];

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
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];

    if (strcmp(identifier, "anybody") == 0) return 1;

    if (strcmp(identifier, auth_userid) == 0) return 3;

    /* "anonymous" is not a member of any group */
    if (strcmp(auth_userid, "anonymous")) return 0;

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
 * Convert 'identifier' into canonical form.
 * Returns a pointer to a static buffer containing the canonical form
 * or NULL if 'identifier' is invalid.
 */
char *auth_canonifyid(identifier)
char *identifier;
{
    static char retbuf[MAX_K_NAME_SZ+1];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char lrealm[REALM_SZ];
    char krbhst[MAX_HSTNM];
    char *p;
    
    if (strcasecmp(identifier, "anonymous") == 0) {
	return "anonymous";
    }
    if (strcasecmp(identifier, "anybody") == 0) {
	return "anybody";
    }
    
    if (kname_parse(aname, inst, realm, identifier) != 0) {
	return 0;
    }

    /* Upcase realm name */
    for (p = realm; *p; p++) {
	if (islower(*p)) *p = toupper(*p);
    }

    if (*realm) {
	if (krb_get_lrealm(lrealm,1)) {
	    abort();		/* XXX krb configuration error */
	}
	if (strcmp(lrealm, realm) == 0) {
	    *realm = 0;
	}
	else if (krb_get_krbhst(krbhst, realm, 0)) {
	    return 0;		/* Unknown realm */
	}
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
 * Set the current user to 'identifier'
 */
auth_setid(identifier)
char *identifier;
{
    identifier = auth_canonifyid(identifier);
    if (!identifier) return 1;	/* XXX bad identifier */

    strcpy(auth_userid, identifier);
    kname_parse(auth_aname, auth_inst, auth_realm, identifier);
    return 0;
}

