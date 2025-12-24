/* ftruncate -- Replacement ftruncate() function */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <errno.h>

int ftruncate(int fd, int length)
{
    (void)fd; (void)length;
    errno = EINVAL;
    return -1;
}

