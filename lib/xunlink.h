/* xunlink.h -- error-logging unlink wrapper */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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

#define xunlink(pathname)                                                     \
    xunlink_fn(__FILE__, __LINE__, __func__, (pathname))
#define xunlinkat(dirfd, pathname, flags)                                     \
    xunlinkat_fn(__FILE__, __LINE__, __func__, (dirfd), (pathname), (flags))

extern int xunlink_fn(const char *sfile, int sline, const char *sfunc,
                      const char *pathname);
extern int xunlinkat_fn(const char *sfile, int sline, const char *sfunc,
                        int dirfd, const char *pathname, int flags);

#endif
