/* acl.h -- definitions for access control lists
 *
 *	(C) Copyright 1993 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 * Author: Chris Newman
 * Start Date: 6/28/93
 */

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

/* convert a string to an acl bit vector
 */
long acl_strtomask( /* char *str */ );

/* convert an acl bit vector to a string
 *  returns dst
 */
char *acl_masktostr( /* long acl, char *dst */ );
