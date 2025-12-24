/* memmove.c -- replacement memmove() routine that only handles overlapping
 * strings when moving data upwards */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/* for size_t */
#include <sys/types.h>

void *memmove(void *s, const void *ct, size_t n)
{
    char *c_s = s;
    const char *c_ct = ct;

    if (c_s <= c_ct) {
        while (n--) {
            *c_s++ = *c_ct++;
        }
    }
    else {
        while (n--) {
            c_s[n] = c_ct[n];
        }
    }

    return s;
}

