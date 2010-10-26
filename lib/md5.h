/* MD5.H - wrapper for MD5 message digest routines
 */
#ifndef _CYRUS_MD5_H_
#define _CYRUS_MD5_H_ 1

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* Use the libsasl MD5 routines, as we cannot build without SASL anyway */
#include <sasl/md5global.h>
#include <sasl/md5.h>

#define MD5Init		    _sasl_MD5Init
#define MD5Update	    _sasl_MD5Update
#define MD5Final	    _sasl_MD5Final
#define MD5_DIGEST_LENGTH   16

#endif /* _CYRUS_MD5_H_ */
