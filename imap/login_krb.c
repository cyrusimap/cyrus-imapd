/* login_krb.c -- Kerberos login authentication
 *
 * Copyright 1996, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */

/*
 * This module supports three types of proxy-logins, in which kerberos
 * principal FOO can log in as user BAR.  The two cases are as follows:
 *   1. ACL proxy (enabled by loginUseAcl) - permitted if BAR has a
 *      mailbox, and FOO has administer (a) access to BAR's mailbox.
 *   2. krb.equiv proxy - permitted if the /etc/krb.equiv file contains
 *      a mapping from principal FOO
 *      to user FOO.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <krb.h>
#include <pwd.h>
#include <sys/param.h>

#include "sasl.h"
#include "config.h"
#include "sysexits.h"
#include "mailbox.h"
#include "acl.h"

static sasl_authproc_t login_authproc;

extern struct sasl_server krb_sasl_server;

extern char *auth_map_krbid P((const char *real_aname, const char *real_inst,
			       const char *real_realm));

static char lrealm[REALM_SZ];
static int use_acl = 0;

/*
 * Kerberos-authenticated login
 */

int
login_plaintext(user, pass, reply)
const char *user;
const char *pass;
const char **reply;
{
    const char *val;

    if (!lrealm[0]) {
	if (krb_get_lrealm(lrealm,1)) {
	    fatal("can't find local Kerberos realm", EX_OSFILE);
	}
	if (val = config_getstring("srvtab", 0)) {
	    kerberos_set_srvtab(val);
	}
	use_acl = config_getswitch("loginUseAcl", 0);
    }

    if (kerberos_verify_password(user, pass, "imap", reply) == 0) {
	return 1;
    }

    return 0;
}

int
login_authenticate(authtype, mech, authproc, reply)
const char *authtype;
struct sasl_server **mech;
sasl_authproc_t **authproc;
const char **reply;
{
    const char *val;

    if (strcmp(authtype, "kerberos_v4") != 0) return 1;

    if (!lrealm[0]) {
	if (krb_get_lrealm(lrealm,1)) {
	    fatal("can't find local Kerberos realm", EX_OSFILE);
	}
	if (val = config_getstring("srvtab", 0)) {
	    kerberos_set_srvtab(val);
	}
	use_acl = config_getswitch("loginUseAcl", 0);
    }

    *mech = &krb_sasl_server;
    *authproc = login_authproc;
    return 0;
}

const char *
login_capabilities()
{
    return " AUTH=KERBEROS_V4";
}

/*
 * kequiv_ok() checks to see if 'user' is mapped to from the principal
 * 'auth_aname', 'auth_inst', 'auth_realm'.  Returns 1 if so, 0 if
 * not.
 */
static int kequiv_ok(user, auth_aname, auth_inst, auth_realm)
const char *user;
const char *auth_aname;
const char *auth_inst;
const char *auth_realm;
{
    char *mapped_user = auth_map_krbid(auth_aname, auth_inst, auth_realm);

    return mapped_user && !strcmp(user, mapped_user);
}


/*
 * acl_ok() checks to see if the the inbox for 'user' grants the 'a'
 * right to the principal 'auth_identity'. Returns 1 if so, 0 if not.
 */
static int acl_ok(user, auth_identity)
const char *user;
const char *auth_identity;
{
    char *acl;
    char inboxname[1024];
    int r;
    struct auth_state *authstate;

    if (strchr(user, '.') || strlen(user)+6 >= sizeof(inboxname)) return 0;

    strcpy(inboxname, "user.");
    strcat(inboxname, user);

    if (!(authstate = auth_newstate(auth_identity, (char *)0)) ||
	mboxlist_lookup(inboxname, (char **)0, &acl)) {
	r = 0;  /* Failed so assume no proxy access */
    }
    else {
	r = (acl_myrights(authstate, acl) & ACL_ADMIN) != 0;
    }
    if (authstate) auth_freestate(authstate);
    return r;
}


static int
login_authproc(user, auth_identity, reply)
const char *user;
const char *auth_identity;
const char **reply;
{
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char auth_aname[ANAME_SZ];
    char auth_inst[INST_SZ];
    char auth_realm[REALM_SZ];
    const char *val;
    static char replybuf[100];

    aname[0] = inst[0] = realm[0] = '\0';
    auth_aname[0] = auth_inst[0] = auth_realm[0] = '\0';
    if (kname_parse(aname, inst, realm, user) != 0) {
	*reply = "unparsable user name";
	return 1;
    }
    if (kname_parse(auth_aname, auth_inst, auth_realm, auth_identity) != 0) {
	*reply = "unparsable Kerberos identity";
	return 1;
    }

    /* If remote realm, check configuration to ensure they're allowed in */
    if (realm[0]) {
	val = config_getstring("loginrealms", "");
	while (*val) {
	    if (!strncasecmp(val, realm, strlen(realm)) &&
		(!val[strlen(realm)] || isspace(val[strlen(realm)]))) {
		break;
		}
	    while (*val && !isspace(*val)) val++;
	    while (*val && isspace(*val)) val++;
	}
	if (!*val) {
	    sprintf(replybuf, "cross-realm login from %s%s%s@%s denied",
		    auth_aname, auth_inst[0] ? "." : "",
		    auth_inst, auth_realm);
	    *reply = replybuf;
	    return 1;
	}
    }

    /* Logging in as the user in the authenticator? */
    if (strcmp(auth_aname, aname) == 0 &&
	strcmp(auth_inst, inst) == 0 &&
	strcmp(auth_realm, realm[0] ? realm : lrealm) == 0) {
	return 0;
    }

    /* Check for imsp-server proxy login */
    if (!strcmp(auth_aname, "imap") && !strcmp(auth_realm, lrealm)) {
	val = config_getstring("imspservers", "");
	while (*val) {
	    if (!strncasecmp(val, auth_inst, strlen(auth_inst)) &&
		(!val[strlen(auth_inst)] || val[strlen(auth_inst)] == '.' ||
		 val[strlen(auth_inst)] == ' ')) {
		break;
	    }
	    while (*val && !isspace(*val)) val++;
	    while (*val && isspace(*val)) val++;
	}

	if (*val) {
	    sprintf(replybuf, "proxy from imap.%s@%s",
		    auth_inst, auth_realm);
	    *reply = replybuf;
	    return 0;
	}
    }

    /* Check for permitted proxy logins by other users */
    if (kequiv_ok(user, auth_aname, auth_inst, auth_realm) ||
	(use_acl && acl_ok(user, auth_identity))) {
        sprintf(replybuf, "proxy from %s%s%s@%s",
		auth_aname, auth_inst[0] ? "." : "",
		auth_inst, auth_realm);
        *reply = replybuf;
        return 0;
    }

    sprintf(replybuf, "proxy login from %s%s%s@%s denied",
	    auth_aname, auth_inst[0] ? "." : "",
	    auth_inst, auth_realm);
    *reply = replybuf;
    return 1;
}
