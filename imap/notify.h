/* notify.h -- abstract interface for notifications */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef NOTIFY_H
#define NOTIFY_H

#define NOTIFY_MAXSIZE 65536  /* 64k */

void notify(const char *method,
            const char *class, const char *priority,
            const char *user, const char *mailbox,
            int nopt, const char **options,
            const char *message, const char *fname);

#endif /* NOTIFY_H */
