/* byteorder64.h -- convert 64-bit values between host and network byte order
 *
 * Copyright (c) 2004 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 * $Id: byteorder64.h,v 1.1.2.2 2004/08/16 11:44:34 ken3 Exp $
 */

#ifndef _BYTEORDER64_H
#define _BYTEORDER64_H

#include <config.h>

#ifdef HAVE_LONG_LONG_INT

/* 64-bit host/network byte-order swap macros */
#ifdef WORDS_BIGENDIAN
#define htonll(x) (x)
#define ntohll(x) (x)
#else
#define htonll(x) _htonll(x)
#define ntohll(x) _ntohll(x)

/* little-endian 64-bit host/network byte-order swap functions */
extern unsigned long long _htonll(unsigned long long);
extern unsigned long long _ntohll(unsigned long long);

#endif /* WORDS_BIGENDIAN */
#endif /* HAVE_LONG_LONG_INT */
#endif /* _BYTEORDER64_H */
