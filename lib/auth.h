/* auth.h - Site authorization module */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
