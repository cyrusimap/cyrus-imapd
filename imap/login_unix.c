/* login_unix.c -- Unix password file login authentication
 *
 *	(C) Copyright 1993 by Carnegie Mellon University
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
