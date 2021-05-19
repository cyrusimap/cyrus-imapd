/* strhash.c string hashing
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
