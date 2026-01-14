/* notify_zephyr.h - zephyr notification method */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _NOTIFY_ZEPHYR_H_
#define _NOTIFY_ZEPHYR_H_

#include <config.h>

/* the options should be a list of users to notify in addition to 'user' */
char* notify_zephyr(const char *class, const char *priority,
                    const char *user, const char *mailbox,
                    int nopt, char **options,
                    const char *message, const char *fname);

#endif /* _NOTIFY_ZEPHYR_H_ */
