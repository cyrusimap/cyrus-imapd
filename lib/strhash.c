/* strhash.c -- string hashing */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include "config.h"

#include "lib/strhash.h"

/* The well-known djb2 algorithm (e.g. http://www.cse.yorku.ca/~oz/hash.html),
 * with the addition of an optional seed to limit predictability.
 *
 * XXX return type 'unsigned' for back-compat to previous version, but
 * XXX ought to be 'uint32_t'
 */
EXPORTED unsigned strhash_seeded_djb2(uint32_t seed, const char *string)
{
    const unsigned char *ustr = (const unsigned char *) string;
    unsigned hash = 5381;
    int c;

    if (seed) {
        /* treat the bytes of the seed as a prefix to the string */
        unsigned i;
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

EXPORTED unsigned strhash_legacy(const char *string)
{
    unsigned ret_val = 0;
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
