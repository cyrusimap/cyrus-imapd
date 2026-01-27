/* notify_log.h - syslog notification method */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _NOTIFY_LOG_H_
#define _NOTIFY_LOG_H_

#include <config.h>

char* notify_log(const char *class, const char *priority,
                 const char *user, const char *mailbox,
                 int nopt, char **options,
                 const char *message, const char *fname);

#endif /* _NOTIFY_LOG_H_ */
