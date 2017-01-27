/* acl.h -- definitions for access control lists
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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
 */

#ifndef INCLUDED_ACL_H
#define INCLUDED_ACL_H

#include "auth.h"

/* max length of an acl string */
#define ACL_MAXSTR 32

/* ACL bits */
#define ACL_LOOKUP      0x000001L
#define ACL_READ        0x000002L
#define ACL_SETSEEN     0x000004L
#define ACL_WRITE       0x000008L
#define ACL_INSERT      0x000010L
#define ACL_POST        0x000020L
#define ACL_CREATE      0x000040L
#define ACL_DELETEMBOX  0x000080L
#define ACL_DELETEMSG   0x000100L
#define ACL_EXPUNGE     0x000200L
#define ACL_ADMIN       0x000400L
#define ACL_ANNOTATEMSG 0x000800L
#define ACL_USER1       0x001000L
#define ACL_USER2       0x002000L
#define ACL_USER3       0x004000L
#define ACL_USER4       0x008000L
#define ACL_USER5       0x010000L
#define ACL_USER6       0x020000L
#define ACL_USER7       0x040000L
#define ACL_USER8       0x080000L
#define ACL_USER9       0x100000L
#define ACL_USER0       0x200000L

/* ALL: all non-user ACLs */
#define ACL_ALL         (ACL_LOOKUP|ACL_READ|ACL_SETSEEN|ACL_WRITE\
                        |ACL_INSERT|ACL_POST|ACL_CREATE|ACL_DELETEMBOX\
                        |ACL_DELETEMSG|ACL_EXPUNGE|ACL_ADMIN\
                        |ACL_ANNOTATEMSG)
/* FULL: ALL ACLs including user ACLs */
#define ACL_FULL        (ACL_USER1|ACL_USER2|ACL_USER3|ACL_USER4|ACL_USER5\
                        |ACL_USER6|ACL_USER7|ACL_USER8|ACL_USER9|ACL_USER0\
                        |ACL_ALL)

/* READ-WRITE: removed from regular ACL if you EXAMINE a mailbox,
   so that nothing accidentally tries to write */
#define ACL_READ_WRITE (ACL_SETSEEN|ACL_WRITE|ACL_INSERT\
                       |ACL_DELETEMSG|ACL_EXPUNGE|ACL_ANNOTATEMSG)

#define ACL_MODE_SET 0
#define ACL_MODE_ADD 1
#define ACL_MODE_REMOVE 2

typedef int cyrus_acl_canonproc_t(void *rock, const char *identifier, int rights);

/* check a string, with meaningful description of error */
extern int cyrus_acl_checkstr(const char *str, char **errstr);

/* convert a string to an acl bit vector */
extern int cyrus_acl_strtomask(const char *str, int *mask);

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
extern int cyrus_acl_myrights(const struct auth_state *auth_state, const char *acl);

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

/* look up a user to see if they are a system user */
extern int is_system_user(const char *userid);

#endif /* INCLUDED_ACL_H */
