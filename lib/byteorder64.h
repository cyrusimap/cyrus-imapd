/* byteorder64.h -- convert 64-bit values between host and network byte order
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

#ifndef _BYTEORDER64_H
#define _BYTEORDER64_H

#include <config.h>

/* http://stackoverflow.com/a/4410728/94253 */

#if defined(__linux__)
#  include <endian.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#  include <sys/endian.h>
#elif defined(__OpenBSD__)
#  include <sys/types.h>
#  define be16toh(x) betoh16(x)
#  define be32toh(x) betoh32(x)
#  define be64toh(x) betoh64(x)
#endif

/* 64-bit host/network byte-order swap macros */

#if defined (WORDS_BIGENDIAN)
#  define htonll(x) (x)
#  define ntohll(x) (x)
#else
#  if defined (be64toh) && defined(htobe64)
#    define htonll(x) htobe64(x)
#    define ntohll(x) be64toh(x)
#  else
/* little-endian 64-bit host/network byte-order swap functions */
#    define CYRUS_BYTESWAP
extern unsigned long long _htonll(unsigned long long);
extern unsigned long long _ntohll(unsigned long long);
#    define htonll(x) _htonll(x)
#    define ntohll(x) _ntohll(x)
#  endif
#endif



/* 64-bit host/network byte-order swap functions to/from non-aligned buffers */
extern void *align_htonll(void *dst, unsigned long long src);
extern unsigned long long align_ntohll(const void *src);

#endif /* _BYTEORDER64_H */
