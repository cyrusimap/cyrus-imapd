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

#if HAVE_CONFIG_H
#include <config.h>
#endif

/* since an SSL library is available, just use its implementation */

#include <openssl/sha.h>
#include <openssl/evp.h>

#include "assert.h"

#ifndef SHA1_DIGEST_LENGTH
#define SHA1_DIGEST_LENGTH (SHA_DIGEST_LENGTH)
#endif

#define xsha256(d,l,h)     assert(EVP_Digest(d, l, h, NULL, EVP_sha256(), NULL))

#define xsha1(d,l,h)       assert(EVP_Digest(d, l, h, NULL, EVP_sha1(), NULL))

#define SHA1_CTX           EVP_MD_CTX*

#define SHA1Init(c)        assert((*c = EVP_MD_CTX_new())            \
                                  && EVP_DigestInit(*c, EVP_sha1()))
#define SHA1Update(c,d,l)  EVP_DigestUpdate(*c, d, l)
#define SHA1Final(h,c)                 \
    do {                               \
        EVP_DigestFinal(*c, h, NULL);  \
        EVP_MD_CTX_free(*c);           \
    } while(0);

#endif /* LIB_XSHA1_H */
