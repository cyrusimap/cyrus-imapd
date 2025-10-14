/* xunlink.h -- error-logging unlink wrapper
 *
 * Copyright (c) 1994-2023 Carnegie Mellon University.  All rights reserved.
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

#ifndef INCLUDED_XUNLINK_H
#define INCLUDED_XUNLINK_H

/**
 * Error-logging wrappers for unlink(2) and unlinkat(2).
 *
 * N.B. These are NOT "error-handling" wrappers; you still must check the
 * return value, errno, etc, and handle errors accordingly!
 *
 * These wrappers present almost the same interface as the original functions,
 * except that:
 *  1) errors are logged for you; and
 *  2) ENOENT is treated as not an error: nothing is logged, errno is not set,
 *     and 1 is returned
 *
 *  Almost all callers of xunlink ignore the return value, but if you're going
 *  to check it, remember:
 *  *  0 means a successful unlink
 *  *  1 means there was no file to unlink
 *  * <0 means another error, which will be syslogged
 **/

#define xunlink(pathname) xunlink_fn(__FILE__, __LINE__, __func__, (pathname))
#define xunlinkat(dirfd, pathname, flags)                                      \
    xunlinkat_fn(__FILE__, __LINE__, __func__, (dirfd), (pathname), (flags))

extern int xunlink_fn(const char *sfile,
                      int sline,
                      const char *sfunc,
                      const char *pathname);
extern int xunlinkat_fn(const char *sfile,
                        int sline,
                        const char *sfunc,
                        int dirfd,
                        const char *pathname,
                        int flags);

#endif
