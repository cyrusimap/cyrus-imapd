/* pwcheck_getspnam.c -- check passwords using getspnam()
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

#include <shadow.h>

extern char *crypt();

char *pwcheck(userid, password)
char *userid;
char *password;
{
    struct spwd *pwd;

    pwd = getspnam(userid);
    if (!pwd) {
	return "Userid not found";
    }
    
    if (strcmp(pwd->sp_pwdp, crypt(password, pwd->sp_pwdp)) != 0) {
	return "Incorrect password";
    }
    else {
	return "OK";
    }
}
