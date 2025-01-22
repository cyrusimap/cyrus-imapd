/* auth.h -- Site authorization module
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
 */

#ifndef INCLUDED_AUTH_H
#define INCLUDED_AUTH_H

#include "strarray.h"

struct auth_state;

struct auth_mech {
    const char *name;

    const char *(*canonifyid)(const char *identifier, size_t len);
    int (*memberof)(const struct auth_state *auth_state,
             const char *identifier);
    struct auth_state *(*newstate)(const char *identifier);
    void (*freestate)(struct auth_state *auth_state);
    strarray_t *(*groups)(const struct auth_state *auth_state);
    void (*refresh)(struct auth_state *auth_state);
};

extern struct auth_mech *auth_mechs[];

/* Note that some of these may be undefined symbols
 * if libcyrus was not built with support for them */
extern struct auth_mech auth_unix;
extern struct auth_mech auth_pts;
extern struct auth_mech auth_krb5;
extern struct auth_mech auth_mboxgroups;

extern void register_mboxgroups_cb(int (*l)(const char *, strarray_t *));

/* auth_canonifyid: canonify the given identifier and return a pointer
 *                  to a static buffer with the canonified ID, or NULL on
 *                  failure */
/* identifier: id to canonify */
/* len: length of id, or 0 to do strlen(identifier) */
const char *auth_canonifyid(const char *identifier, size_t len);

int auth_memberof(const struct auth_state *auth_state,
         const char *identifier);
struct auth_state *auth_newstate(const char *identifier);
void auth_freestate(struct auth_state *auth_state);
strarray_t *auth_groups(const struct auth_state *auth_state);
void auth_refresh(struct auth_state *auth_state);

#endif /* INCLUDED_AUTH_H */
