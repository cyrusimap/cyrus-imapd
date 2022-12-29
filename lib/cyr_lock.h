/* cyr_lock.h -- file locking primitives
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef INCLUDED_LOCK_H
#define INCLUDED_LOCK_H

#include <sys/stat.h>

extern const char lock_method_desc[];

extern double debug_locks_longer_than;

extern int lock_reopen_ex(int fd, const char *filename,
                          struct stat *sbuf, const char **failaction,
                          int *changed);
#define lock_reopen(fd, filename, sbuf, failaction) \
        lock_reopen_ex(fd, filename, sbuf, failaction, NULL)

extern int lock_setlock(int fd, int ex, int nb, const char *filename);
extern int lock_unlock(int fd, const char *filename);

extern void clearlocks(void);

/* compatibility defines for the older API */
#define lock_blocking(fd, fn) \
    lock_setlock((fd), /*exclusive*/1, /*blocking*/0, (fn))
#define lock_nonblocking(fd, fn) \
    lock_setlock((fd), /*exclusive*/1, /*nonblocking*/1, (fn))
#define lock_shared(fd, fn) \
    lock_setlock((fd), /*exclusive*/0, /*nonblocking*/0, (fn))

#endif /* INCLUDED_LOCK_H */
