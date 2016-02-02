/* xsha1.c - wrapper for including suitable sha1 implementation
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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

#ifndef LIB_XSHA1_H
#define LIB_XSHA1_H

#include <config.h>

#ifdef HAVE_SSL

#include <openssl/sha.h>

#ifndef SHA1_DIGEST_LENGTH
#define SHA1_DIGEST_LENGTH (SHA_DIGEST_LENGTH)
#endif

#define xsha1 SHA1

#else /* HAVE_SSL */

#include <stdint.h>

typedef uint32_t sha1_quadbyte; /* 4 byte type */
typedef uint8_t sha1_byte;    /* single byte type */

#define SHA1_BLOCK_LENGTH   64
#define SHA1_DIGEST_LENGTH  20
#define SHA_DIGEST_LENGTH (SHA1_DIGEST_LENGTH)

/* opaque type for the SHA1 structure: */
typedef struct _SHA_CTX SHA_CTX;

int SHA1_Init(SHA_CTX* context);
int SHA1_Update(SHA_CTX *context, const sha1_byte *data, unsigned int len);
int SHA1_Final(sha1_byte digest[SHA1_DIGEST_LENGTH], SHA_CTX *context);

unsigned char *xsha1(const unsigned char *buf, unsigned long len,
              sha1_byte dest[SHA1_DIGEST_LENGTH]);

#endif /* HAVE_SSL */

#endif /* LIB_XSHA1_H */
