/* pwcheck_getpwnam.c -- check passwords using getpwname()
 *
 * Copyright 1998 Carnegie Mellon University
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
 *
 */

#include <pwd.h>

extern char *crypt();

char *pwcheck(userid, password)
char *userid;
char *password;
{
    char* r;
    struct passwd *pwd;

    pwd = getpwnam(userid);
    if (!pwd) {
	r = "Userid not found";
    }
    else if (pwd->pw_passwd[0] == '*') {
	r = "Account disabled";
    }
    else if (strcmp(pwd->pw_passwd, crypt(password, pwd->pw_passwd)) != 0) {
	r = "Incorrect password";
    }
    else {
	r = "OK";
    }

    endpwent();
    
    return r;
}
