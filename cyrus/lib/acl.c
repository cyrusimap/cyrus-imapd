/* acl.c -- routines for access control lists
 $Id: acl.c,v 1.11 2006/11/30 17:11:22 murch Exp $
 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Author: Chris Newman
 * Start Date: 6/28/93
 *
 * RFC 4314 support added by Ken Murchison
 */

#include <config.h>
#include <stdio.h>
#include "acl.h"
#include "libcyr_cfg.h"

/* convert a string to an acl bit vector
 */
int cyrus_acl_strtomask(const char *str)
{
    const char *deleteright = libcyrus_config_getstring(CYRUSOPT_DELETERIGHT);
    long legacy_create = 0;
    long legacy_delete = 0;
    long result = 0;

    while (*str) {
	switch (*str++) {
	    case 'l': result |= ACL_LOOKUP; break;
	    case 'r': result |= ACL_READ; break;
	    case 's': result |= ACL_SEEN; break;
	    case 'w': result |= ACL_WRITE; break;
	    case 'i': result |= ACL_INSERT; break;
	    case 'p': result |= ACL_POST; break;
	    case 'c': /* legacy CREATE macro - build member rights */
		legacy_create = ACL_CREATE;
		if (*deleteright == 'c') legacy_create |= ACL_DELETEMBOX;
		break;
	    case 'k': result |= ACL_CREATE; break;
	    case 'x': result |= ACL_DELETEMBOX; break;
	    case 't': result |= ACL_DELETEMSG; break;
	    case 'e': result |= ACL_EXPUNGE; break;
	    case 'd': /* legacy DELETE macro - build member rights */
		legacy_delete = (ACL_DELETEMSG | ACL_EXPUNGE);
		if (*deleteright == 'd') legacy_delete |= ACL_DELETEMBOX;
		break;
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

    /* If the rights string contained a legacy macro, but none of its
       member rights, then we add all of the member rights for the macro.
       Otherwise, we ignore the legacy macro.
    */
    if (!(result & legacy_create)) result |= legacy_create;
    if (!(result & legacy_delete)) result |= legacy_delete;

    return (result);
}

/* convert an acl bit vector to a string
 */
char *cyrus_acl_masktostr(int acl, char *str)
{
    char *pos = str;
    const char *deleteright = libcyrus_config_getstring(CYRUSOPT_DELETERIGHT);
    int legacy_create = ACL_CREATE;
    int legacy_delete = (ACL_DELETEMSG | ACL_EXPUNGE);

    switch (*deleteright) {
    case 'c': legacy_create |= ACL_DELETEMBOX; break;
    case 'd': legacy_delete |= ACL_DELETEMBOX; break;
    default: /* XXX  we have backwards compatibility problems */ break;
    }

    if (acl & ACL_LOOKUP) *pos++ = 'l';
    if (acl & ACL_READ) *pos++ = 'r';
    if (acl & ACL_SEEN) *pos++ = 's';
    if (acl & ACL_WRITE) *pos++ = 'w';
    if (acl & ACL_INSERT) *pos++ = 'i';
    if (acl & ACL_POST) *pos++ = 'p';
    if (acl & ACL_CREATE) *pos++ = 'k';
    if (acl & ACL_DELETEMBOX) *pos++ = 'x';
    if (acl & ACL_DELETEMSG) *pos++ = 't';
    if (acl & ACL_EXPUNGE) *pos++ = 'e';
    if (acl & legacy_create) *pos++ = 'c';
    if (acl & legacy_delete) *pos++ = 'd';
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
