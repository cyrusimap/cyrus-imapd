/* acl.h -- definitions for access control lists
         Copyright 1998 by Carnegie Mellon University
 
                       All Rights Reserved
 
  Permission to use, copy, modify, and distribute this software and its
  documentation for any purpose and without fee is hereby granted,
  provided that the above copyright notice appear in all copies and that
  both that copyright notice and this permission notice appear in
  supporting documentation, and that the name of CMU not be
  used in advertising or publicity pertaining to distribution of the
  software without specific, written prior permission.
 
  CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
  ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
  CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
  ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
  WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
  ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
  SOFTWARE.
 
 * 
 * Author: Chris Newman
 * Start Date: 6/28/93
 */

#ifndef INCLUDED_ACL_H
#define INCLUDED_ACL_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

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

typedef int acl_canonproc_t P((void *rock, const char *identifier, int rights));

/* convert a string to an acl bit vector */
extern int acl_strtomask P((const char *str));

/*  acl_masktostr(acl, dst)
 * convert an acl bit vector to a string
 *  dst must have room for 32 characters (only 20 used currently)
 *  returns dst
 */
extern char *acl_masktostr P((int acl, char *str));

/*  acl_myrights(acl)
 * Calculate the set of rights the user in 'auth_state' has in the ACL 'acl'.
 * 'acl' must be writable, but is restored to its original condition.
 */
extern int acl_myrights P((struct auth_state *auth_state, char *acl));

/*  acl_set(acl, identifier, mode, access, canonproc, canonrock) Modify the
 * ACL pointed to by 'acl' to modify the rights granted to
 * 'identifier' as specified by 'mode' and the set specified in the
 * mask 'access'.  'mode' is one of ACL_MODE_SET, ACL_MODE_ADD, or
 * ACL_MODE_REMOVE.  The pointer pointed to by 'acl' must have been
 * obtained from malloc().  returns -1 on error, 0 on success */

extern int acl_set P((char **acl, const char *identifier,
		      int mode, int access,
		      acl_canonproc_t *canonproc, void *canonrock));

/*  acl_remove(acl, identifier, canonproc, canonrock)
 * Remove any entry for 'identifier' in the ACL pointed to by 'acl'.
 * The pointer pointed to by 'acl' must have been obtained from malloc().
 *  returns -1 on error, 0 on success
 */
extern int acl_remove P((char **acl, const char *identifier,
			 acl_canonproc_t *canonproc, void *canonrock));

#endif /* INCLUDED_ACL_H */
