/* notify_null.h - NULL notification method */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _NOTIFY_NULL_H_
#define _NOTIFY_NULL_H_

#include <config.h>

char* notify_null(const char *class, const char *priority,
                  const char *user, const char *mailbox,
                  int nopt, char **options,
                  const char *message, const char *fname);

#endif /* _NOTIFY_NULL_H_ */
