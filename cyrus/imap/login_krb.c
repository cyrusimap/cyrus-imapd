#include <stdio.h>
#include <ctype.h>
#include <sysexits.h>
#include <krb.h>
#include <syslog.h>

#include <kerberos.h>
#include "config.h"
#include "mailbox.h"
#include "imapd.h"

/*
 * Kerberos-authenticated login
 */

int
login_authenticate(user, pass, reply)
char *user;
char *pass;
char **reply;
{
    static char lrealm[REALM_SZ];
    AUTH_DAT kdata;
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char *val;


    if (!lrealm[0]) {
	if (krb_get_lrealm(lrealm,1)) {
	    fatal("can't find local Kerberos realm", EX_OSFILE);
	}
	if (val = config_getstring("srvtab", 0)) {
	    kerberos_set_srvtab(val);
	}
    }

    aname[0] = inst[0] = realm[0] = '\0';
    if (kname_parse(aname, inst, realm, user) != 0) {
	return 1;
    }

    if (strncmp(pass, KERBEROS_IDENT, strlen(KERBEROS_IDENT)) == 0) {
	if (kerberos_read_authenticator(pass+strlen(KERBEROS_IDENT),
					&kdata, reply) == 0) {
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
		syslog(LOG_NOTICE,
		     "badlogin: cross-realm login as %s from %s%s%s@%s denied",
		       kdata.pname, kdata.pinst[0] ? "." : "",
		       kdata.pinst, kdata.prealm);
		*reply = "Cross-realm login denied";
		return 1;
	    }
	}

	/* Logging in as the user in the authenticator? */
	if (strcmp(kdata.pname, aname) == 0 &&
	    strcmp(kdata.pinst, inst) == 0 &&
	    strcmp(kdata.prealm, realm[0] ? realm : lrealm) == 0) {

	    syslog(LOG_NOTICE, "login: using kerberos as %s", user);
	    login_setadmin(user);
	    return 0;
	}

	/* Check for imsp-server proxy login */
	if (!strcmp(kdata.pname, "imap") && !strcmp(kdata.prealm, lrealm)) {
	    val = config_getstring("imspservers", "");
	    while (*val) {
		if (!strncasecmp(val, inst, strlen(inst)) &&
		    (!val[strlen(inst)] || val[strlen(inst)] != '.')) {
		    break;
		}
		while (*val && !isspace(*val)) val++;
		while (*val && isspace(*val)) val++;
	    }
	    if (*val) {
		syslog(LOG_NOTICE, "login: proxy from imap.%s@%s as %s",
		       inst, lrealm, user);
		login_setadmin(user);
		return 0;
	    }
	}

	*reply = "Proxy login denied";
	return 1;
    }

    if (kerberos_verify_password(user, pass) == 0) {
	syslog(LOG_NOTICE, "badlogin: wrong password for %s", user);
	return 1;
    }

    syslog(LOG_NOTICE, "login: plaintext as %s", user);
    login_setadmin(user);
    return 0;
}
  
static login_setadmin(user)
char *user;
{
    char *val;

    val = config_getstring("admins", "");
    
    while (*val) {
	if (!strncmp(val, user, strlen(user)) &&
	    (!val[strlen(user)] || isspace(val[strlen(user)]))) {
	    break;
	}
	while (*val && !isspace(*val)) val++;
	while (*val && isspace(*val)) val++;
    }

    imapd_userisadmin = (*val != '\0');
}
