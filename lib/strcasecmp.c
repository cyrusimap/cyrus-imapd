/* strcasecmp.c -- replacement strcasecmp() & strncasecmp() routines */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/* for size_t */
#include <sys/types.h>
#include "util.h"

/* case insensitive string compare
 */
int strcasecmp(const char *str1, const char *str2)
{
    while (*str1 && TOLOWER(*str1) == TOLOWER(*str2)) ++str1, ++str2;

    return ((int) TOLOWER(*str1) - (int) TOLOWER(*str2));
}

/* case insensitive string compare with count
 */
int strncasecmp(const char *str1, const char *str2, size_t n)
{
    while (n && *str1 && TOLOWER(*str1) == TOLOWER(*str2)) ++str1, ++str2, --n;

    return (n ? (int) TOLOWER(*str1) - (int) TOLOWER(*str2) : 0);
}

