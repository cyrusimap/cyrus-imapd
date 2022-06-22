/* MD5.H - wrapper for MD5 message digest routines
 */
#ifndef _CYRUS_MD5_H_
#define _CYRUS_MD5_H_ 1

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "lib/assert.h"

/*
 * This is gnarly, sorry :(  We might have been configured to build
 * with OpenSSL, or we might not.  Some older versions of OpenSSL
 * will drag in their own md5.h when we include <openssl/ssl.h>, but
 * newer ones don't.  The OpenSSL header might be included before or
 * after this header file is included.
 *
 * So, we *might* have a definition of the MD5_CTX structure from
 * OpenSSL, now or later, or not.
 *
 * LibSASL also has MD5 routines, declared in <sasl/md5.h>, and that
 * header also defines a MD5_CTX structure.  So we can't include
 * both md5.h's, but we need one.
 *
 * So we explicitly include the OpenSSL md5.h if OpenSSL is configured
 * in, otherwise we fallback to the libSASL routines.  Note that we
 * cannot build without libSASL anyway, so we don't need to fallback
 * any further.
 *
 * The MD5 API varies slightly from library to library.  Here's a
 * description of the API that Cyrus is expecting and that we try
 * to provide on top of whatever the library has.
 *
 * typedef struct ... { ... } MD5_CTX;
 * void MD5Init(MD5_CTX *);
 * void MD5Update(MD5_CTX *, const void *data, size_t len);
 * void MD5Final(unsigned char[MD5_DIGEST_LENGTH], MD5_CTX *);
 */

#ifdef HAVE_SSL
#include <openssl/md5.h>
#include <openssl/evp.h>

#define MD5_CTX           EVP_MD_CTX*

#define MD5Init(c)        assert((*c = EVP_MD_CTX_new())           \
                                 && EVP_DigestInit(*c, EVP_md5()))
#define MD5Update(c,d,l)  EVP_DigestUpdate(*c, d, l)
#define MD5Final(h,c)                  \
    do {                               \
        EVP_DigestFinal(*c, h, NULL);  \
        EVP_MD_CTX_free(*c);           \
    } while(0);

#else

#include <sasl/md5global.h>
#include <sasl/md5.h>

#define MD5Init                     _sasl_MD5Init
#define MD5Update(c,d,l)            _sasl_MD5Update(c, (unsigned char*)d, l)
#define MD5Final                    _sasl_MD5Final

#endif /* !HAVE_SSL */

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

#endif /* _CYRUS_MD5_H_ */
