/* auth.h -- Site authorization module
	$Id: auth.h,v 1.9 2000/02/10 21:25:38 leg Exp $

#        Copyright 1998 by Carnegie Mellon University
#
#                      All Rights Reserved
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose and without fee is hereby granted,
# provided that the above copyright notice appear in all copies and that
# both that copyright notice and this permission notice appear in
# supporting documentation, and that the name of CMU not be
# used in advertising or publicity pertaining to distribution of the
# software without specific, written prior permission.
#
# CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
# ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
# CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
# ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
# ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
# SOFTWARE.

 *
 */

#ifndef INCLUDED_AUTH_H
#define INCLUDED_AUTH_H

struct auth_state;

extern int auth_memberof(struct auth_state *auth_state, 
			 const char *identifier);
extern char *auth_canonifyid(const char *identifier);
extern struct auth_state *auth_newstate(const char *identifier,
					const char *cacheid);
extern void auth_freestate(struct auth_state *auth_state);

#endif /* INCLUDED_AUTH_H */
