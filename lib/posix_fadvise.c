/* posix_fadvise -- Replacement posix_fadvise() function */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <errno.h>

int posix_fadvise(int fd, off_t offset, off_t len, int advice)
{
    (void)fd; (void)offset; (void)len; (void)advice;
    errno = EINVAL;
    return -1;
}

