/* login_unix.c -- Unix password file login authentication
 $Id: login_unix.c,v 1.16 1998/05/15 21:48:58 neplokh Exp $
 
 # Copyright 1998 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
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
