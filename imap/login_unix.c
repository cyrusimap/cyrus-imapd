/* login_unix.c -- Unix password file login authentication
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
#include <stdio.h>
#include <pwd.h>

#include "sasl.h"
#include "config.h"
#include "sysexits.h"
#include "mailbox.h"
#include "imapd.h"

extern char *crypt();

/*
 * Unix passwd-authenticated login
 */

int
login_plaintext(user, pass, reply)
char *user;
char *pass;
char **reply;
{
    struct passwd *pwd;

    pwd = getpwnam(user);
    if (!pwd) return 1;

    if (strcmp(pwd->pw_passwd, crypt(pass, pwd->pw_passwd)) != 0) {
	*reply = "wrong password";
	return 1;
    }

    return 0;
}
  
int
login_authenticate(authtype, mech, authproc, reply)
char *authtype;
struct sasl_server **mech;
sasl_authproc_t **authproc;
char **reply;
{
    return 1;
}
  
const char *
login_capabilities()
{
    return "";
}
