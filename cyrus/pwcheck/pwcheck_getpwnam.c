/* pwcheck_getpwnam.c -- check passwords using getpwname()
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

#include <pwd.h>

extern char *crypt();

char *pwcheck(userid, password)
char *userid;
char *password;
{
    struct passwd *pwd;

    pwd = getpwnam(userid);
    if (!pwd) {
	return "Userid not found";
    }
    
    if (pwd->pw_passwd[0] == '*') {
	return "Account disabled";
    }

    if (strcmp(pwd->pw_passwd, crypt(password, pwd->pw_passwd)) != 0) {
	return "Incorrect password";
    }
    else {
	return "OK";
    }
}
