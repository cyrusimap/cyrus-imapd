/* retry.h -- Keep retrying write system calls
 $Id: retry.h,v 1.8.4.1 2002/11/04 20:48:05 ken3 Exp $
 
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 */

#ifndef INCLUDED_RETRY_H
#define INCLUDED_RETRY_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

#include <sys/uio.h>

extern int retry_read P((int fd, char *buf, size_t nbyte));
extern int retry_write P((int fd, const char *buf, size_t nbyte));
extern int retry_writev P((int fd, struct iovec *iov, int iovcnt));

/* add a buffer 's' of length 'len' to iovec 'iov' */
#define WRITEV_ADD_TO_IOVEC(iov, num_iov, s, len) \
    do { (iov)[(num_iov)].iov_base = (s); \
         (iov)[(num_iov)++].iov_len = (len); } while (0)

/* add a string 's' to iovec 'iov' */
#define WRITEV_ADDSTR_TO_IOVEC(iov, num_iov, s) WRITEV_ADD_TO_IOVEC(iov, num_iov, s, strlen(s))
                

#endif /* INCLUDED_RETRY_H */
