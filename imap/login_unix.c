#include <stdio.h>
#include <sysexits.h>
#include <pwd.h>
#include <syslog.h>

#include "config.h"
#include "mailbox.h"
#include "imapd.h"

/*
 * Unix passwd-authenticated login
 */

int
login_authenticate(user, pass, reply)
char *user;
char *pass;
char **reply;
{
    struct passwd *pwd;

    pwd = getpwnam(user);
    if (!pwd) return 1;

    if (strcmp(pwd->pw_passwd, crypt(pass, pwd->pw_passwd)) != 0) {
	syslog(LOG_NOTICE, "badlogin: %s wrong password for %s",
	       imapd_clienthost, user);
	return 1;
    }

    syslog(LOG_NOTICE, "login: %s as %s", imapd_clienthost, user);
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
