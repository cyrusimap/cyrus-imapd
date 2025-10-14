/* MD5.H - wrapper for MD5 message digest routines
 */
#ifndef _CYRUS_MD5_H_
# define _CYRUS_MD5_H_ 1

# ifdef HAVE_CONFIG_H
#  include <config.h>
# endif

# include "assert.h"

/* Here's a description of the API that Cyrus is expecting and that we try
 * to provide on top of whatever the underlying library has.
 *
 * typedef struct ... { ... } MD5_CTX;
 * void MD5Init(MD5_CTX *);
 * void MD5Update(MD5_CTX *, const void *data, size_t len);
 * void MD5Final(unsigned char[MD5_DIGEST_LENGTH], MD5_CTX *);
 * void md5(const void *data, size_t len, unsigned char[MD5_DIGEST_LENGTH]);
 */

# include <openssl/md5.h>
# include <openssl/evp.h>

# define md5(d, l, h) assert(EVP_Digest(d, l, h, NULL, EVP_md5(), NULL))

# define MD5_CTX EVP_MD_CTX *

# define MD5Init(c)                                                            \
     assert((*c = EVP_MD_CTX_new()) && EVP_DigestInit(*c, EVP_md5()))
# define MD5Update(c, d, l) EVP_DigestUpdate(*c, d, l)
# define MD5Final(h, c)                                                        \
     do {                                                                      \
         EVP_DigestFinal(*c, h, NULL);                                         \
         EVP_MD_CTX_free(*c);                                                  \
     } while (0);

# ifndef MD5_DIGEST_LENGTH
#  define MD5_DIGEST_LENGTH 16
# endif

#endif /* _CYRUS_MD5_H_ */
