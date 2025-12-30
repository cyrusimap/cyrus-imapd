/* byteorder.c -- convert 32 and 64-bit values between host and network byte order */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>
#include "byteorder.h"

#ifdef CYRUS_BYTESWAP

#include <netinet/in.h>

/* Structure used to swap the bytes in a 64-bit uint64_t. */
union byteswap_64_u {
    uint64_t a;
    uint32_t b[2];
};

/* Function to byteswap 64bit unsigned integers on
 * little endian machines to big endian network order.
 * On big endian machines this will be a null macro.
 * The macro htonll() is defined in byteorder.h,
 * and if needed refers to _htonll() here.
 */
EXPORTED uint64_t _htonll(uint64_t x)
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
 * The macro ntohll() is defined in byteorder.h, and if needed,
 * refers to _ntohll() here.
 */
EXPORTED uint64_t _ntohll(uint64_t x)
{
    union byteswap_64_u u1;
    union byteswap_64_u u2;

    u1.a = x;

    u2.b[1] = ntohl(u1.b[0]);
    u2.b[0] = ntohl(u1.b[1]);

    return u2.a;
}

#endif /* CYRUS_BYTESWAP */

#include <string.h>

EXPORTED void *align_htonll(void *dst, uint64_t src)
{
    uint64_t tmp = htonll(src);
    return memcpy(dst, (void *) &tmp, sizeof(uint64_t));
}

EXPORTED uint64_t align_ntohll(const void *src)
{
    uint64_t dst;

    memcpy((void *) &dst, src, sizeof(uint64_t));
    return ntohll(dst);
}
