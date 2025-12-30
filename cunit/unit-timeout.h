/* unit-timeout.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef CUNIT_UNIT_TIMEOUT_H
#define CUNIT_UNIT_TIMEOUT_H

extern int timeout_init(void (*cb)(void));
extern int timeout_begin(int millisec);
extern int timeout_end(void);
extern void timeout_fini(void);

#endif /* CUNIT_UNIT_TIMEOUT_H */
