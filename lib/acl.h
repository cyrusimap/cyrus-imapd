/* acl.h -- definitions for access control lists
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
 * 
 * Author: Chris Newman
 * Start Date: 6/28/93
 */

/* $Id: acl.h,v 1.14 2003/02/13 20:15:38 rjs3 Exp $ */

#ifndef INCLUDED_ACL_H
#define INCLUDED_ACL_H

#include "auth.h"

/* max length of an acl string */
#define ACL_MAXSTR 32

/* ACL bits */
#define ACL_LOOKUP 0x00001L
#define ACL_READ   0x00002L
#define ACL_SEEN   0x00004L
#define ACL_WRITE  0x00008L
#define ACL_INSERT 0x00010L
#define ACL_POST   0x00020L
#define ACL_CREATE 0x00040L
#define ACL_DELETE 0x00080L
#define ACL_ADMIN  0x00100L
#define ACL_ALL    0x001FFL
#define ACL_USER0  0x00200L
#define ACL_USER1  0x00400L
#define ACL_USER2  0x00800L
#define ACL_USER3  0x01000L
#define ACL_USER4  0x02000L
#define ACL_USER5  0x04000L
#define ACL_USER6  0x08000L
#define ACL_USER7  0x10000L
#define ACL_USER8  0x20000L
#define ACL_USER9  0x40000L
#define ACL_FULL   0xFFFFFL

#define ACL_MODE_SET 0
#define ACL_MODE_ADD 1
#define ACL_MODE_REMOVE 2

typedef int cyrus_acl_canonproc_t(void *rock, const char *identifier, int rights);

/* convert a string to an acl bit vector */
extern int cyrus_acl_strtomask(const char *str);

/*  cyrus_acl_masktostr(acl, dst)
 * convert an acl bit vector to a string
 *  dst must have room for 32 characters (only 20 used currently)
 *  returns dst
 */
extern char *cyrus_acl_masktostr(int acl, char *str);

/*  cyrus_acl_myrights(acl)
 * Calculate the set of rights the user in 'auth_state' has in the ACL 'acl'.
 * 'acl' must be writable, but is restored to its original condition.
 */
extern int cyrus_acl_myrights(struct auth_state *auth_state, char *acl);

/*  cyrus_acl_set(acl, identifier, mode, access, canonproc, canonrock) Modify the
 * ACL pointed to by 'acl' to modify the rights granted to
 * 'identifier' as specified by 'mode' and the set specified in the
 * mask 'access'.  'mode' is one of ACL_MODE_SET, ACL_MODE_ADD, or
 * ACL_MODE_REMOVE.  The pointer pointed to by 'acl' must have been
 * obtained from malloc().  returns -1 on error, 0 on success */

extern int cyrus_acl_set(char **acl, const char *identifier,
		   int mode, int access,
		   cyrus_acl_canonproc_t *canonproc, void *canonrock);

/*  cyrus_acl_remove(acl, identifier, canonproc, canonrock)
 * Remove any entry for 'identifier' in the ACL pointed to by 'acl'.
 * The pointer pointed to by 'acl' must have been obtained from malloc().
 *  returns -1 on error, 0 on success
 */
extern int cyrus_acl_remove(char **acl, const char *identifier,
		      cyrus_acl_canonproc_t *canonproc, void *canonrock);

#endif /* INCLUDED_ACL_H */
