/* userdeny.h - User deny definitions */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_USERDENY_H
#define INCLUDED_USERDENY_H

#include <config.h>

extern int userdeny(const char *user, const char *service,
                    char *msgbuf, size_t bufsiz);
extern int denydb_set(const char *user, const char *service,
                    const char *msg);
extern int denydb_delete(const char *user);

/* iterate the user deny db */
typedef int (*denydb_proc_t)(const char *user, const char *services,
                             const char *message, void *rock);
extern int denydb_foreach(denydb_proc_t, void *rock);

/* open the user deny db */
int denydb_open(int create);

/* close the database */
void denydb_close(void);

/* initialize database structures */
void denydb_init(void);

/* done with database stuff */
void denydb_done(void);

#endif /* INCLUDED_USERDENY_H */
