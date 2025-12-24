/* strhash.h -- string hashing */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _STRHASH_H_
#include <stdint.h>

unsigned strhash_seeded_djb2(uint32_t seed, const char *string);
unsigned strhash_legacy(const char *string);

#define strhash(in)             strhash_seeded_djb2((0),  (in))
#define strhash_seeded(sd, in)  strhash_seeded_djb2((sd), (in))

#endif /* _STRHASH_H_ */
