/* xsha1.c - wrapper for including suitable sha1 implementation */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
