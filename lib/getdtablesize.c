/* getdtablesize.c - Returns the maximum number of file descriptors allowed. */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include <unistd.h>

int
getdtablesize ()
{
        return(sysconf(_SC_OPEN_MAX));
}
