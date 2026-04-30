/* strhash.c - string hashing */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include "config.h"

#include "lib/strhash.h"

/* The well-known djb2 algorithm (e.g. http://www.cse.yorku.ca/~oz/hash.html),
 * with the addition of an optional seed to limit predictability.
 */
EXPORTED uint32_t strhash_seeded_djb2(uint32_t seed, const char *string)
{
    const unsigned char *ustr = (const unsigned char *) string;
    uint32_t hash = 5381;
    int c;

    if (seed) {
        /* treat the bytes of the seed as a prefix to the string */
        uint32_t i;
        for (i = 0; i < sizeof seed; i++) {
            c = seed & 0xff;
            hash = ((hash << 5) + hash) ^ c;
            seed >>= 8;
        }
    }

    while ((c = *ustr++))
        hash = ((hash << 5) + hash) ^ c;

    return hash;
}

EXPORTED uint32_t strhash_legacy(const char *string)
{
    uint32_t ret_val = 0;
    int i;

    while (*string)
    {
        i = (int) *string;
        ret_val ^= i;
        ret_val <<= 1;
        string ++;
    }
    return ret_val;
}
