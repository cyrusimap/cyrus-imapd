/* auth.h -- Site authorization module
 * $Id: auth.h,v 1.17 2006/11/30 17:11:22 murch Exp $
 *
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
 */

#ifndef INCLUDED_AUTH_H
#define INCLUDED_AUTH_H

struct auth_state;

struct auth_mech {
    const char *name;

    char *(*canonifyid)(const char *identifier, size_t len);
    int (*memberof)(struct auth_state *auth_state, 
             const char *identifier);
    struct auth_state *(*newstate)(const char *identifier);
    void (*freestate)(struct auth_state *auth_state);
};

extern struct auth_mech *auth_mechs[];

/* Note that some of these may be undefined symbols
 * if libcyrus was not built with support for them */
extern struct auth_mech auth_unix;
extern struct auth_mech auth_pts;
extern struct auth_mech auth_krb;
extern struct auth_mech auth_krb5;

/* auth_canonifyid: canonify the given identifier and return a pointer
 *                  to a static buffer with the canonified ID, or NULL on
 *                  failure */
/* identifier: id to canonify */
/* len: length of id, or 0 to do strlen(identifier) */
char *auth_canonifyid(const char *identifier, size_t len);

int auth_memberof(struct auth_state *auth_state, 
 	 const char *identifier);
struct auth_state *auth_newstate(const char *identifier);
void auth_freestate(struct auth_state *auth_state);

#endif /* INCLUDED_AUTH_H */
