/* user.h -- User manipulation routines
 * 
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 */
/*
 * $Id: user.h,v 1.3.4.1 2002/08/23 19:53:26 ken3 Exp $
 */

#ifndef INCLUDED_USER_H
#define INCLUDED_USER_H

#include "auth.h"

/* Delete meta-data (seen state, subscriptions, ACLs, quotaroots,
 * sieve scripts) for 'user'.
 *
 * wipe-user says to delete seen state also (remove the user from the murder)
 */
int user_deletedata(char *user, char *userid, struct auth_state *authstate,
		    int wipe_user);

/* Rename/copy user meta-data (seen state, subscriptions, sieve scripts)
 * from 'olduser' to 'newuser'.
 */
int user_renamedata(char *olduser, char *newuser, char *userid,
		    struct auth_state *authstate);

/* Rename ACL for 'olduser' to 'newuser' on mailbox 'name'. */
int user_renameacl(char *name, char *olduser, char *newuser);

/* Copy a quotaroot from mailbox 'oldname' to 'newname' */
int user_copyquotaroot(char *oldname, char *newname);

/* Delete all quotaroots for 'user' */
int user_deletequotaroots(const char *user);

#endif
