/* config.h -- Configuration routines */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_MASTERCONF_H
#define INCLUDED_MASTERCONF_H

extern int masterconf_init(const char *ident, const char *alt_config);

struct entry;

extern const char *masterconf_getstring(struct entry *e,
                                        const char *key, const char *def);
extern int masterconf_getint(struct entry *e,
                             const char *key, int def);
extern int masterconf_getswitch(struct entry *e,
                                const char *key, int def);

/* entry values are good until the next call */
typedef void masterconf_process(const char *name, struct entry *e, void *rock);

extern void masterconf_getsection(const char *section,
                                  masterconf_process *f, void *rock);

/* fatalf() is like fatal() but takes a printf-like
 * format string which goes to syslog().  */
extern void fatalf(int code, const char *fmt, ...)
    __attribute__ ((format (printf, 2, 3)))
    __attribute__((noreturn));

#endif /* INCLUDED_MASTERCONF_H */
