/* notify_external.h - external notification method */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _NOTIFY_EXTERNAL_H
#define _NOTIFY_EXTERNAL_H

#include <config.h>

char* notify_external(const char *class, const char *priority,
                      const char *user, const char *mailbox,
                      int nopt, char **options,
                      const char *message, const char *fname);

#endif /* _NOTIFY_EXTERNAL_H */

