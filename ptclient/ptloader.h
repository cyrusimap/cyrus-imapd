/* ptloader.h - Site authorization module */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_PTLOADER_H
#define INCLUDED_PTLOADER_H

struct auth_state;

struct pts_module {
    const char *name;

    void (*init)(void);
    struct auth_state *(*make_authstate)(const char *identifier,
                size_t size,
                const char **reply, int *dsize);
};

extern struct pts_module *pts_modules[];

/* Note that some of these may be undefined symbols
 * if libcyrus was not built with support for them */
extern struct pts_module pts_http;
extern struct pts_module pts_ldap;
extern struct pts_module pts_afskrb;

struct auth_state *ptsmodule_make_authstate(const char *identifier,
                                            size_t size,
                                            const char **reply, int *dsize);
char *ptsmodule_unix_canonifyid(const char *identifier, size_t len);
void ptsmodule_init(void);

#endif /* INCLUDED_PTLOADER_H */
