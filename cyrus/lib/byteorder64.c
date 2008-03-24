/* byteorder64.c -- convert 64-bit values between host and network byte order
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
 *
 * $Id: byteorder64.c,v 1.4 2008/03/24 17:43:08 murch Exp $
 */

#include <config.h>
#include "byteorder64.h"

#if defined(HAVE_LONG_LONG_INT)

#if !defined(WORDS_BIGENDIAN)

#include <netinet/in.h>

/* Structure used to swap the bytes in a 64-bit unsigned long long. */
union byteswap_64_u {
    unsigned long long a;
    uint32_t b[2];
};

/* Function to byteswap 64bit unsigned integers on
 * little endian machines to big endian network order. 
 * On big endian machines this will be a null macro.
 * The macro htonll() is defined in byteorder64.h,
 * and if needed refers to _htonll() here.
 */
unsigned long long _htonll(unsigned long long x)
{
    union byteswap_64_u u1;
    union byteswap_64_u u2;

    u1.a = x;

    u2.b[0] = htonl(u1.b[1]);
    u2.b[1] = htonl(u1.b[0]);

    return u2.a;
}


/* Function to byteswap big endian 64bit unsigned integers
 * back to little endian host order on little endian machines. 
 * As above, on big endian machines this will be a null macro.
 * The macro ntohll() is defined in byteorder64.h, and if needed,
 * refers to _ntohll() here.
 */
unsigned long long _ntohll(unsigned long long x)
{
    union byteswap_64_u u1;
    union byteswap_64_u u2;

    u1.a = x;

    u2.b[1] = ntohl(u1.b[0]);
    u2.b[0] = ntohl(u1.b[1]);

    return u2.a;
}

#endif /* !defined(WORDS_BIGENDIAN) */

#include <string.h>

void *align_htonll(void *dst, unsigned long long src)
{
    unsigned long long tmp = htonll(src);
    return memcpy(dst, (void *) &tmp, sizeof(unsigned long long));
}

unsigned long long align_ntohll(const void *src)
{
    unsigned long long dst;

    memcpy((void *) &dst, src, sizeof(unsigned long long));
    return ntohll(dst);
}

#endif /* defined(HAVE_LONG_LONG_INT) */
