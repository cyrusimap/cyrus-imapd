/* acl.c -- routines for access control lists
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
 * Author: Chris Newman
 * Start Date: 6/28/93
 */

#include <stdio.h>
#include "acl.h"

/* convert a string to an acl bit vector
 */
int acl_strtomask(str)
const char *str;
{
    long result = 0;

    while (*str) {
	switch (*str++) {
	    case 'l': result |= ACL_LOOKUP; break;
	    case 'r': result |= ACL_READ; break;
	    case 's': result |= ACL_SEEN; break;
	    case 'w': result |= ACL_WRITE; break;
	    case 'i': result |= ACL_INSERT; break;
	    case 'p': result |= ACL_POST; break;
	    case 'c': result |= ACL_CREATE; break;
	    case 'd': result |= ACL_DELETE; break;
	    case 'a': result |= ACL_ADMIN; break;
	    case '0': result |= ACL_USER0; break;
	    case '1': result |= ACL_USER1; break;
	    case '2': result |= ACL_USER2; break;
	    case '3': result |= ACL_USER3; break;
	    case '4': result |= ACL_USER4; break;
	    case '5': result |= ACL_USER5; break;
	    case '6': result |= ACL_USER6; break;
	    case '7': result |= ACL_USER7; break;
	    case '8': result |= ACL_USER8; break;
	    case '9': result |= ACL_USER9; break;
	}
    }

    return (result);
}

/* convert an acl bit vector to a string
 */
char *acl_masktostr(acl, str)
int acl;
char *str;
{
    char *pos = str;

    if (acl & ACL_LOOKUP) *pos++ = 'l';
    if (acl & ACL_READ) *pos++ = 'r';
    if (acl & ACL_SEEN) *pos++ = 's';
    if (acl & ACL_WRITE) *pos++ = 'w';
    if (acl & ACL_INSERT) *pos++ = 'i';
    if (acl & ACL_POST) *pos++ = 'p';
    if (acl & ACL_CREATE) *pos++ = 'c';
    if (acl & ACL_DELETE) *pos++ = 'd';
    if (acl & ACL_ADMIN) *pos++ = 'a';
    if (acl & ACL_USER0) *pos++ = '0';
    if (acl & ACL_USER1) *pos++ = '1';
    if (acl & ACL_USER2) *pos++ = '2';
    if (acl & ACL_USER3) *pos++ = '3';
    if (acl & ACL_USER4) *pos++ = '4';
    if (acl & ACL_USER5) *pos++ = '5';
    if (acl & ACL_USER6) *pos++ = '6';
    if (acl & ACL_USER7) *pos++ = '7';
    if (acl & ACL_USER8) *pos++ = '8';
    if (acl & ACL_USER9) *pos++ = '9';
    *pos = '\0';

    return (str);
}
