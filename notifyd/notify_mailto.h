/* notify_mailto.h -- email notification method */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _NOTIFY_MAILTO_H_
#define _NOTIFY_MAILTO_H_

#include <config.h>

/* the only option should be a mailto URI */
char* notify_mailto(const char *class, const char *priority,
                    const char *user, const char *mailbox,
                    int nopt, char **options,
                    const char *message, const char *fname);

#endif /* _NOTIFY_MAILTO_H_ */
