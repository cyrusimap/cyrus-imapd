/* util.c -- general utility functions
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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

#include <config.h>

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#if defined(__linux__) && defined(HAVE_LIBCAP)
#include <sys/capability.h>
#include <sys/prctl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <time.h>
#include <ftw.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "assert.h"
#include "byteorder.h"
#include "libconfig.h"
#include "logfmt.h"
#include "map.h"
#include "retry.h"
#include "sessionid.h"
#include "util.h"
#include "xmalloc.h"
#include "xunlink.h"
#ifdef HAVE_ZLIB
#include "zlib.h"
#endif


#define BEAUTYBUFSIZE 4096

static const unsigned char unxdigit[128] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

EXPORTED const unsigned char convert_to_lowercase[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
    'x', 'y', 'z', 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

const unsigned char convert_to_uppercase[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

#ifdef EXTRA_IDENT
#define CYRUS_VERSION_STR PACKAGE_VERSION "-" EXTRA_IDENT
#else
#define CYRUS_VERSION_STR PACKAGE_VERSION
#endif
EXPORTED const char CYRUS_VERSION[sizeof(CYRUS_VERSION_STR)] = CYRUS_VERSION_STR;

/* convert string to all lower case
 */
EXPORTED char *lcase(char* str)
{
    char *scan = str;

    while (*scan) {
        *scan = TOLOWER(*scan);
        scan++;
    }

    return (str);
}

/* convert string to all upper case
 */
EXPORTED char *ucase(char* str)
{
    char *scan = str;

    while (*scan) {
        *scan = convert_to_uppercase[(unsigned char)(*scan)];
        scan++;
    }

    return (str);
}

/* clean up control characters in a string while copying it
 *  returns pointer to end of dst string.
 *  dst must have twice the length of source
 */
static char *beautify_copy(char* dst, const char* src)
{
    unsigned char c;

    while (*src) {
        c = *src++ & 0x7F;
        if (!isprint(c)) {
            *dst++ = '^';
            if (c > ' ') {
                c = '?';
            } else {
                c += '@';
            }
        }
        *dst++ = c;
    }
    *dst = '\0';

    return (dst);
}


/* clean up control characters in a string while copying it
 *  returns pointer to a static buffer containing the cleaned-up version
 */
EXPORTED char *beautify_string(const char* src)
{
    static char *beautybuf = NULL;
    static int beautysize = 0;
    int len;

    len = strlen(src) * 2 + 1;
    if (beautysize < len) {
        if (!beautysize) {
            beautysize = len > BEAUTYBUFSIZE ? len : BEAUTYBUFSIZE;
            beautybuf = xmalloc(beautysize);
        } else {
            beautysize *= 2;
            if (len > beautysize) beautysize = len;
            beautybuf = xrealloc(beautybuf, beautysize);
        }
    }
    (void) beautify_copy(beautybuf, src);

    return beautybuf;
}

EXPORTED int strcmpsafe(const char *a, const char *b)
{
    return strcmp((a == NULL ? "" : a),
                  (b == NULL ? "" : b));
}

EXPORTED int strncmpsafe(const char *a, const char *b, size_t n)
{
    return strncmp((a == NULL ? "" : a),
                   (b == NULL ? "" : b),
                   n);
}

EXPORTED int strcasecmpsafe(const char *a, const char *b)
{
    return strcasecmp((a == NULL ? "" : a),
                      (b == NULL ? "" : b));
}

EXPORTED int strncasecmpsafe(const char *a, const char *b, size_t n)
{
    return strncasecmp((a == NULL ? "" : a),
                       (b == NULL ? "" : b),
                       n);
}

/* in which NULL is NOT equal to "" */
EXPORTED int strcmpnull(const char *a, const char *b)
{
    if (a) {
        if (b) return strcmp(a, b);
        return 1;
    }
    if (b) return -1;
    return 0;
}


/* do a binary search in a keyvalue array
 *  nelem is the number of keyvalue elements in the kv array
 *  cmpf is the comparison function (strcmp, strcasecmp, etc).
 *  returns NULL if not found, or key/value pair if found.
 */
keyvalue *kv_bsearch(const char* key, keyvalue* kv, int nelem,
                     int (*cmpf) (const char *s1, const char *s2))
{
    int top, mid = 0, bot, cmp = 0;

    cmp = 1;
    bot = 0;
    top = nelem - 1;
    while (top >= bot && (cmp = (*cmpf)(key, kv[mid = (bot + top) >> 1].key)))
        if (cmp < 0) {
            top = mid - 1;
        } else {
            bot = mid + 1;
        }

    return (cmp ? NULL : kv + mid);
}

EXPORTED int cyrus_close_sock(int fd)
{
    shutdown(fd, SHUT_RD);
    return close(fd);
}

EXPORTED void cyrus_reset_stdio(void)
{
    int devnull = open("/dev/null", O_RDWR, 0);

    if (devnull == -1) {
        fatal("open() on /dev/null failed", EX_TEMPFAIL);
    }

    /* stdin */
    shutdown(0, SHUT_RD);
    dup2(devnull, STDIN_FILENO);

    /* stdout */
    shutdown(1, SHUT_RD);
    dup2(devnull, STDOUT_FILENO);

    /* stderr */
    shutdown(2, SHUT_RD);
    dup2(devnull, STDERR_FILENO);

    if (devnull > 2) close(devnull);
}

/* Given a directory, create a unique temporary file open for
 * reading and writing and return the file descriptor.
 *
 * This routine also unlinks the file so it won't appear in the
 * directory listing (but you won't have to worry about cleaning up
 * after it)
 */
EXPORTED int create_tempfile(const char *path)
{
    int fd;
    char *pattern;

    pattern = strconcat(path, "/cyrus_tmpfile_XXXXXX", (char *)NULL);

    fd = mkstemp(pattern);
    if (fd >= 0 && xunlink(pattern) == -1) {
        close(fd);
        fd = -1;
    }

    free(pattern);
    return fd;
}

EXPORTED char *create_tempdir(const char *path, const char *subname)
{
    struct buf buf = BUF_INITIALIZER;
    char *dbpath = NULL;

    buf_setcstr(&buf, path);
    if (!buf.len || buf.s[buf.len-1] != '/') {
        buf_putc(&buf, '/');
    }
    buf_appendcstr(&buf, "cyrus-");
    buf_appendcstr(&buf, subname && *subname ? subname : "tmpdir");
    buf_appendcstr(&buf, "-XXXXXX");
    buf_cstring(&buf);
    dbpath = xstrdupnull(mkdtemp(buf.s));

    buf_free(&buf);
    return dbpath;
}

static int removedir_cb(const char *fpath,
                        const struct stat *sb __attribute__((unused)),
                        int typeflag __attribute__((unused)),
                        struct FTW *ftwbuf __attribute__((unused)))
{
    return remove(fpath);
}

EXPORTED int removedir(const char *path)
{
    return nftw(path, removedir_cb, 128, FTW_DEPTH|FTW_PHYS);
}

EXPORTED int xrenameat(int dirfd, const char *src, const char *dest)
{
    char *copy = xstrdup(dest);
    const char *file = basename(copy);
    int r = renameat(AT_FDCWD, src, dirfd, file);
    free(copy);
    return r;
}

#define XOPENDIR_CREATE 1
#define XOPENDIR_NOSYNC 2
static int xopendirpath(const char *path, int flags)
{
#if defined(O_DIRECTORY)
    int dirfd = open(path, O_RDONLY|O_DIRECTORY, 0600);
#else
    int dirfd = open(path, O_RDONLY, 0600);
#endif
    if (dirfd >= 0) return dirfd; // exists, we're good
    if (!(flags & XOPENDIR_CREATE)) return dirfd; // not creating? Bail

    int parentfd = xopendir(path, flags);
    if (parentfd < 0) return parentfd; // failed, can't get further

    char *copy = xstrdup(path);
    const char *leaf = basename(copy);
    // ignore exist, if someone else won that's OK
    if (mkdirat(parentfd, leaf, 0755) == -1) {
        if (errno != EEXIST) {
            xsyslog(LOG_ERR, "IOERROR: failed to create intermediate directory",
                             "filename=<%s>", path);
            int saved_errno = errno;
            free(copy);
            close(parentfd);
            errno = saved_errno;
            return -1;
        }
        /* otherwise OK, directory already created */
    }
    else if (!(flags & XOPENDIR_NOSYNC)) {
        if (fsync(parentfd) < 0) {
            xsyslog(LOG_ERR, "IOERROR: fsync directory failed",
                             "filename=<%s>", path);
            int saved_errno = errno;
            free(copy);
            close(parentfd);
            errno = saved_errno;
            return -1;
        }
    }

    free(copy);
    close(parentfd);

#if defined(O_DIRECTORY)
    dirfd = open(path, O_RDONLY|O_DIRECTORY, 0600);
#else
    dirfd = open(path, O_RDONLY, 0600);
#endif

    return dirfd;
}

EXPORTED int xopendir(const char *dest, int flags)
{
    char *copy = xstrdup(dest);
    const char *dir = dirname(copy);
    int dirfd = xopendirpath(dir, flags);
    free(copy);
    return dirfd;
}

EXPORTED void xclosedir(int dirfd)
{
    // make sure close doesn't clear errno
    int saved_errno = errno;
    close(dirfd);
    errno = saved_errno;
}

EXPORTED int cyrus_settime_fdptr(const char *path, struct timespec *when, int *dirfdp)
{
    int local_dirfd = -1;
    if (!dirfdp) dirfdp = &local_dirfd;

    if (*dirfdp < 0) *dirfdp = xopendir(path, /*flags*/0);
    if (*dirfdp < 0) return *dirfdp;

    struct timespec ts[2];
    ts[0] = *when;
    ts[1] = *when;

    char *copy = xstrdup(path);
    const char *leaf = basename(copy);
    int r = utimensat(*dirfdp, leaf, ts, 0);
    free(copy);

    if (local_dirfd >= 0) xclosedir(local_dirfd);

    return r;
}

EXPORTED int cyrus_unlink_fdptr(const char *path, int *dirfdp)
{
    int local_dirfd = -1;
    if (!dirfdp) dirfdp = &local_dirfd;

    if (*dirfdp < 0) *dirfdp = xopendir(path, /*flags*/0);
    if (*dirfdp < 0) return *dirfdp;

    char *copy = xstrdup(path);
    const char *leaf = basename(copy);
    int r = xunlinkat(*dirfdp, leaf, /*flags*/0);
    free(copy);

    if (local_dirfd >= 0) xclosedir(local_dirfd);

    return r;
}

// rename a file (probably in the same directory) and fsync the
// destination directory before returning
EXPORTED int cyrus_rename(const char *src, const char *dest)
{
    int dirfd = xopendir(dest, XOPENDIR_CREATE);
    if (dirfd < 0) {
        return dirfd;
    }

    int r = xrenameat(dirfd, src, dest);
    if (!r) r = fsync(dirfd);
    xclosedir(dirfd);

    return r;
}

/* Create all parent directories for the given path,
 * up to but not including the basename.
 * NOTE: this used to just call:
 *  mkdir ("/foo");
 *  mkdir ("/foo/bar");
 *   etc; all the way up to basename
 *  Since it's used a lot for paths we don't care about, this API just uses _NOSYNC.
 *  If you want sync, then call xopendir directly.
 */
EXPORTED int cyrus_mkdir(const char *pathname, mode_t mode __attribute__((unused)))
{
    int fd = xopendir(pathname, XOPENDIR_CREATE|XOPENDIR_NOSYNC);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

EXPORTED int cyrus_copyfile_fdptr(const char *from, const char *to,
                                  int flags, int *dirfdp)
{
    /* copy over self is an error */
    if (!strcmp(from, to))
        return -1;

    int srcfd = -1;
    int destfd = -1;
    int local_dirfd = -1;
    const char *src_base = 0;
    size_t src_size = 0;
    struct stat sbuf;
    int n;
    int r = 0;
    int nolink = flags & COPYFILE_NOLINK;
    int keeptime = flags & COPYFILE_KEEPTIME;
    int nodirsync = flags & COPYFILE_NODIRSYNC;
    char *copy = xstrdup(to);
    const char *leaf = basename(copy);

    if (!dirfdp) dirfdp = &local_dirfd;
    if (*dirfdp < 0) *dirfdp = xopendir(to, flags & COPYFILE_MKDIR ? XOPENDIR_CREATE : 0);
    if (*dirfdp < 0) {
        r = -1;
        goto done;
    }

    /* try to hard link, but don't fail - fall back to regular copy */
    if (!nolink) {
        r = linkat(AT_FDCWD, from, *dirfdp, leaf, 0);
        if (r && errno == EEXIST) {
            /* n.b. unlink rather than xunlink.  at this point we believe
             * a file definitely exists that we want to remove, so if
             * unlink tells us ENOENT then that's super weird and we're
             * probably racing against something
             */
            if (unlinkat(*dirfdp, leaf, 0) == -1) {
                xsyslog(LOG_ERR, "IOERROR: unlinking to recreate failed",
                                 "filename=<%s>", to);
                errno = 0;
                r = -1;
                goto done;
            }

            r = linkat(AT_FDCWD, from, *dirfdp, leaf, 0);
        }
        if (!r) goto sync;
    }

    srcfd = open(from, O_RDONLY, 0666);
    if (srcfd == -1) {
        xsyslog(LOG_ERR, "IOERROR: open failed",
                         "filename=<%s>", from);
        r = -1;
        goto done;
    }

    if (fstat(srcfd, &sbuf) == -1) {
        xsyslog(LOG_ERR, "IOERROR: fstat failed",
                         "filename=<%s>", from);
        r = -1;
        goto done;
    }

    if (!sbuf.st_size) {
        xsyslog(LOG_ERR, "IOERROR: zero byte file",
                         "filename=<%s>", from);
        r = -1;
        goto done;
    }

    destfd = openat(*dirfdp, leaf, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (destfd == -1) {
        xsyslog(LOG_ERR, "IOERROR: create failed",
                         "filename=<%s>", to);
        r = -1;
        goto done;
    }

    map_refresh(srcfd, 1, &src_base, &src_size, sbuf.st_size, from, 0);

    n = retry_write(destfd, src_base, src_size);

    if (n == -1 || fsync(destfd)) {
        xsyslog(LOG_ERR, "IOERROR: retry_write failed",
                         "filename=<%s>", to);
        r = -1;
        xunlinkat(*dirfdp, leaf, /*flags*/0);  /* remove any rubbish we created */
        goto done;
    }

    if (keeptime) {
        int ret;
#if defined(HAVE_FUTIMENS)
        struct timespec ts[2];

        ts[0] = sbuf.st_atim;
        ts[1] = sbuf.st_mtim;
        ret = futimens(destfd, ts);
#elif defined(HAVE_FUTIMES)
        struct timeval tv[2];

        TIMESPEC_TO_TIMEVAL(&tv[0], &sbuf.st_atim);
        TIMESPEC_TO_TIMEVAL(&tv[1], &sbuf.st_mtim);
        ret = futimes(destfd, tv);
#else
        struct timeval tv[2];

        close(destfd);
        destfd = -1;
        ret = utimes(to, tv);
#endif
        if (ret) {
            xsyslog(LOG_ERR, "IOERROR: setting times failed",
                             "filename=<%s>", to);
            r = -1;
            xunlink(to);  /* remove any rubbish we created */
            goto done;
        }
    }

sync:
    if (!nodirsync && local_dirfd >= 0) {
        if (fsync(local_dirfd) < 0) {
            xsyslog(LOG_ERR, "IOERROR: fsync directory failed",
                             "filename=<%s>", to);
            r = -1;
            xunlink(to);  /* remove any rubbish we created */
            goto done;
        }
    }

done:
    map_free(&src_base, &src_size);
    free(copy);

    if (srcfd != -1) close(srcfd);
    if (destfd != -1) close(destfd);
    if (local_dirfd != -1) close(local_dirfd);

    return r;
}

#if defined(__linux__) && defined(HAVE_LIBCAP)
EXPORTED int set_caps(int stage, int is_master)
{
    cap_t cap = NULL;
    int r = 0;
    int e = errno;
    static const char * const capsets[2][5] = {
        { /* !master */
            "cap_setuid=ep",    /* BEFORE_SETUID */
            "=",                /* AFTER_SETUID */
            "=",                /* doesn't happen */
            "=",                /* doesn't happen */
            "="                 /* doesn't happen */
        }, { /* master */
            "cap_net_bind_service=p cap_setuid=ep",     /* BEFORE_SETUID */
            "cap_net_bind_service=p",                   /* AFTER_SETUID */
            "cap_net_bind_service=ep",                  /* BEFORE_BIND */
            "cap_net_bind_service=p",                   /* AFTER_BIND */
            "="                                         /* AFTER_FORK */
        }
    };

    cap = cap_from_text(capsets[!!is_master][stage]);
    assert(cap != NULL);

    r = cap_set_proc(cap);
    if (r < 0) {
        syslog(LOG_ERR, "cannot set caps: %m");
        goto out;
    }

    if ((stage == BEFORE_SETUID) || (stage == AFTER_SETUID)) {
        r = prctl(PR_SET_KEEPCAPS, (stage == BEFORE_SETUID));
        if (r < 0) {
            syslog(LOG_ERR, "cannot set keepcaps flag: %m");
            goto out;
        }
    }

  out:
    if (cap) cap_free(cap);
    errno = e;   /* preserve errno so the caller's error reporting is easy */

    return r;
}
#else
EXPORTED int set_caps(int stage __attribute__((unused)),
                      int is_master __attribute__((unused)))
{
    return 0;
}
#endif

static int cyrus_cap_setuid(int uid, int is_master)
{
    int r;

    set_caps(BEFORE_SETUID, is_master);
    r = setuid(uid);
    set_caps(AFTER_SETUID, is_master);

    return r;
}

EXPORTED int become_cyrus(int is_master)
{
    struct passwd *p;
    struct group *g;
    uid_t newuid;
    gid_t newgid;
    int result;
    static uid_t uid = 0;

    if (uid) return cyrus_cap_setuid(uid, is_master);

    const char *cyrus = cyrus_user();
    const char *mail = cyrus_group();

    p = getpwnam(cyrus);
    if (p == NULL) {
        syslog(LOG_ERR, "no entry in /etc/passwd for user %s", cyrus);
        return -1;
    }

    /* Save these in case initgroups does a getpw*() */
    newuid = p->pw_uid;
    newgid = p->pw_gid;

    if (mail != NULL) {
        g = getgrnam(mail);
        if (g == NULL) {
            syslog(LOG_ERR, "no entry in /etc/group for group %s", mail);
            return -1;
        }
        newgid = g->gr_gid;
    }

    if (newuid == geteuid() &&
        newuid == getuid() &&
        newgid == getegid() &&
        newgid == getgid()) {
        /* already the Cyrus user, stop trying */
        uid = newuid;
        set_caps(AFTER_SETUID, is_master);
        return 0;
    }

    if (initgroups(cyrus, newgid)) {
        syslog(LOG_ERR, "unable to initialize groups for user %s: %s",
               cyrus, strerror(errno));
        return -1;
    }

    if (setgid(newgid)) {
        syslog(LOG_ERR, "unable to set group id to %d for user %s: %s",
              newgid, cyrus, strerror(errno));
        return -1;
    }

    result = cyrus_cap_setuid(newuid, is_master);

    /* Only set static uid if successful, else future calls won't reset gid */
    if (result == 0)
        uid = newuid;
    return result;
}

EXPORTED const char *cyrus_user(void)
{
    const char *cyrus = getenv("CYRUS_USER");
    if (!cyrus) cyrus = config_getstring(IMAPOPT_CYRUS_USER);
    if (!cyrus) cyrus = CYRUS_USER;
    assert(cyrus != NULL);
    return cyrus;
}

EXPORTED const char *cyrus_group(void)
{
    const char *mail = getenv("CYRUS_GROUP");
    if (!mail) mail = config_getstring(IMAPOPT_CYRUS_GROUP);
    return mail;
}

static int cmdtime_enabled = 0;
static struct timeval cmdtime_start, cmdtime_end, nettime_start, nettime_end;
static double totaltime, cmdtime, nettime, search_maxtime;

EXPORTED double timeval_get_double(const struct timeval *tv)
{
    return (double)tv->tv_sec + (double)tv->tv_usec/1000000.0;
}

EXPORTED void timeval_set_double(struct timeval *tv, double d)
{
    tv->tv_sec = (long) d;
    tv->tv_usec = (long) (1000000 * (d - tv->tv_sec));
}

EXPORTED void timeval_add_double(struct timeval *tv, double delta)
{
    timeval_set_double(tv, timeval_get_double(tv) + delta);
}

EXPORTED double timesub(const struct timeval *start, const struct timeval *end)
{
    return (double)(end->tv_sec - start->tv_sec) +
           (double)(end->tv_usec - start->tv_usec)/1000000.0;
}

EXPORTED int64_t now_ms(void)
{
    struct timespec ts;

    if (cyrus_gettime(CLOCK_REALTIME, &ts) == 0) {
        return (ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
    }
    else {
        syslog(LOG_WARNING, "cyrus_gettime(): %m");
        return time(NULL) * 1000;
    }
}

EXPORTED void cmdtime_settimer(int enable)
{
    cmdtime_enabled = enable;

    /* always enable cmdtimer if MAXTIME set */
    const char *maxtime = config_getstring(IMAPOPT_SEARCH_MAXTIME);
    if (maxtime) {
        cmdtime_enabled = 1;
        search_maxtime = atof(maxtime);
    }
}

EXPORTED void cmdtime_starttimer(void)
{
    if (!cmdtime_enabled)
        return;
    gettimeofday(&cmdtime_start, 0);
    totaltime = cmdtime = nettime = 0.0;
}

EXPORTED void cmdtime_endtimer(double *pcmdtime, double *pnettime)
{
    if (!cmdtime_enabled)
        return;
    gettimeofday(&cmdtime_end, 0);
    totaltime = timesub(&cmdtime_start, &cmdtime_end);
    cmdtime = totaltime - nettime;
    *pcmdtime = cmdtime;
    *pnettime = nettime;
}

EXPORTED int cmdtime_checksearch(void)
{
    struct timeval nowtime;
    if (!search_maxtime)
        return 0;
    gettimeofday(&nowtime, 0);
    totaltime = timesub(&cmdtime_start, &nowtime);
    cmdtime = totaltime - nettime;
    if (cmdtime > search_maxtime)
        return -1;
    return 0;
}

EXPORTED void cmdtime_netstart(void)
{
    if (!cmdtime_enabled)
        return;
    gettimeofday(&nettime_start, 0);
}

EXPORTED void cmdtime_netend(void)
{
    if (!cmdtime_enabled)
        return;
    gettimeofday(&nettime_end, 0);
    nettime += timesub(&nettime_start, &nettime_end);
}

/*
 * Like the system clock() but works in system time
 * rather than process virtual time.  Would be more
 * useful and sensible if it worked in system monotonic
 * time using cyrus_gettime(CLOCK_MONOTONIC) but that
 * would require linking with -lrt.
 */
EXPORTED clock_t sclock(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec * CLOCKS_PER_SEC +
           (now.tv_usec * CLOCKS_PER_SEC) / 1000000;
}

EXPORTED int parseint32(const char *p, const char **ptr, int32_t *res)
{
    int32_t result = 0;
    int gotchar = 0;

    if (!p) return -1;

    /* INT_MAX == 2147483647 */
    while (cyrus_isdigit(*p)) {
        if (result > 214748364 || (result == 214748364 && (*p > '7'))) {
            return -1;
        }
        result = result * 10 + *p++ - '0';
        gotchar = 1;
    }

    if (!gotchar) return -1;

    if (ptr) *ptr = p;
    if (res) *res = result;

    return 0;
}

EXPORTED int parseuint32(const char *p, const char **ptr, uint32_t *res)
{
    uint32_t result = 0;
    int gotchar = 0;

    if (!p) return -1;

    /* UINT_MAX == 4294967295U */
    while (cyrus_isdigit(*p)) {
        if (result > 429496729 || (result == 429496729 && (*p > '5'))) {
            return -1;
        }
        result = result * 10 + *p++ - '0';
        gotchar = 1;
    }

    if (!gotchar) return -1;

    if (ptr) *ptr = p;
    if (res) *res = result;

    return 0;
}

EXPORTED int parsenum(const char *p, const char **ptr, int maxlen, bit64 *res)
{
    bit64 result = 0;
    int n;
    int cval;

    /* ULLONG_MAX == 18446744073709551615ULL
     */
    for (n = 0; !maxlen || n < maxlen; n++) {
        if (!cyrus_isdigit(p[n]))
            break;
        cval = p[n] - '0';
        if (result >= 1844674407370955161ULL) {
            if (result > 1844674407370955161ULL || cval > 5)
                return -1;
        }
        result = result * 10 + cval;
    }

    /* no characters found... */
    if (!n) return -1;

    if (ptr) *ptr = p + n;
    if (res) *res = result;

    return 0;
}

EXPORTED uint64_t str2uint64(const char *p)
{
    const char *rest = p;
    bit64 res = 0;
    if (parsenum(p, &rest, 0, &res))
        return 0;
    if (*rest) return 0;
    return res;
}

EXPORTED int parsehex(const char *p, const char **ptr, int maxlen, bit64 *res)
{
    bit64 result = 0;
    int n;
    int cval;

    /* ULLONG_MAX == 18446744073709551615ULL
     * so if we're greater or equal to (ULLONG_MAX+1)/16
     * then we will overflow
     */
    for (n = 0; !maxlen || n < maxlen; n++) {
        if (result >= 1152921504606846976ULL) {
            return -1;
        }
        cval = unxdigit[(int)p[n]];
        if (cval == 0xff) break;
        result = result * 16 + cval;
    }

    /* no characters found... */
    if (!n) return -1;

    if (ptr) *ptr = p + n;
    if (res) *res = result;

    return 0;
}

EXPORTED char *strconcat(const char *s1, ...)
{
    int sz = 1; /* 1 byte for the trailing NUL */
    const char *s;
    char *buf;
    char *p;
    va_list args;

    if (s1 == NULL)
        return NULL;

    /* first pass: calculate length */
    sz += strlen(s1);
    va_start(args, s1);
    while ((s = va_arg(args, const char *)) != NULL)
        sz += strlen(s);
    va_end(args);

    /* allocate exactly the right amount of space */
    p = buf = xmalloc(sz);

    /* second pass: copy strings in */
    strcpy(p, s1);
    p += strlen(p);
    va_start(args, s1);
    while ((s = va_arg(args, const char *)) != NULL) {
        strcpy(p, s);
        p += strlen(p);
    }
    va_end(args);

    return buf;
}

EXPORTED int bin_to_hex(const void *bin, size_t binlen, char *hex, int flags)
{
    const unsigned char *v = bin;
    char *p = hex;
    size_t i;
    const char *xd = (flags & BH_UPPER ? "0123456789ABCDEF" : "0123456789abcdef");
    char sep = _BH_GETSEP(flags);

    for (i = 0; i < binlen; i++, v++) {
        if (i && sep)
            *p++ = sep;
        *p++ = xd[(*v >> 4) & 0xf];
        *p++ = xd[*v & 0xf];
    }
    *p = '\0';

    return p-hex;
}

EXPORTED int buf_bin_to_hex(struct buf *hex, const void *bin, size_t binlen, int flags)
{
    size_t seplen = _BH_GETSEP(flags) && binlen ? binlen - 1 : 0;
    size_t newlen = hex->len + binlen * 2 + seplen;
    buf_ensure(hex, newlen - hex->len + 1);
    int r = bin_to_hex(bin, binlen, hex->s + hex->len, flags);
    buf_truncate(hex, newlen);
    buf_cstring(hex);
    return r;
}

EXPORTED int hex_to_bin(const char *hex, size_t hexlen, void *bin)
{
    unsigned char *v = bin, msn, lsn;
    const char *p = hex;
    size_t i;

    if (hex == NULL)
        return -1;
    if (hexlen == 0)
        hexlen = strlen(hex);
    if (hexlen % 2)
        return -1;
    hexlen /= 2;

    for (i = 0 ; i < hexlen ; i++) {
        msn = unxdigit[(*p++) & 0x7f];
        if (msn == 0xff)
            return -1;
        lsn = unxdigit[(*p++) & 0x7f];
        if (lsn == 0xff)
            return -1;
        *v++ = (msn << 4) | lsn;
    }

    return (unsigned char *)v - (unsigned char *)bin;
}

EXPORTED int buf_hex_to_bin(struct buf *bin, const char *hex, size_t hexlen)
{
    if (hex == NULL)
        return -1;
    if (hexlen == 0)
        hexlen = strlen(hex);
    if (hexlen % 2)
        return -1;

    size_t newlen = bin->len + hexlen / 2;
    buf_ensure(bin, newlen - bin->len + 1);
    int r = hex_to_bin(hex, hexlen, bin->s + bin->len);
    if (r >= 0) {
        buf_truncate(bin, newlen);
        buf_cstring(bin);
    }
    return r;
}

#ifdef HAVE_ZLIB

/* Wrappers for our memory management functions */
static voidpf zalloc(voidpf opaque __attribute__((unused)),
                     uInt items, uInt size)
{
    return (voidpf) xmalloc(items * size);
}

static void zfree(voidpf opaque __attribute__((unused)),
                  voidpf address)
{
    free(address);
}

EXPORTED int buf_inflate(struct buf *src, int scheme)
{
    struct buf localbuf = BUF_INITIALIZER;
    int zr = Z_OK;
    z_stream *zstrm = (z_stream *) xmalloc(sizeof(z_stream));
    int windowBits;

    switch (scheme) {
    case DEFLATE_RAW:
        windowBits = -MAX_WBITS;        /* raw deflate */
        break;

    case DEFLATE_GZIP:
        windowBits = 16+MAX_WBITS;      /* gzip header */
        break;

    case DEFLATE_ZLIB:
    default:
        windowBits = MAX_WBITS;         /* zlib header */
        break;
    }

    zstrm->zalloc = zalloc;
    zstrm->zfree = zfree;
    zstrm->opaque = Z_NULL;

    zstrm->next_in = Z_NULL;
    zstrm->avail_in = 0;
    zr = inflateInit2(zstrm, windowBits);
    if (zr != Z_OK) goto err;

    /* set up the source */
    zstrm->next_in = (unsigned char *)src->s;
    zstrm->avail_in = src->len;

    /* prepare the destination */
    do {
        buf_ensure(&localbuf, 4096);
        /* find the buffer */
        zstrm->next_out = (unsigned char *)localbuf.s + localbuf.len;
        zstrm->avail_out = localbuf.alloc - localbuf.len;
        zr = inflate(zstrm, Z_SYNC_FLUSH);
        if (!(zr == Z_OK || zr == Z_STREAM_END || zr == Z_BUF_ERROR))
           goto err;
        localbuf.len = localbuf.alloc - zstrm->avail_out;
    } while (zstrm->avail_out == 0);

    inflateEnd(zstrm);
    free(zstrm);

    buf_free(src); /* dispose of current buffer */
    *src = localbuf; /* in place replace */
    return 0;

 err:
    free(zstrm);
    buf_free(&localbuf);
    return -1;
}

EXPORTED int buf_deflate(struct buf *src, int compLevel, int scheme)
{
    struct buf localbuf = BUF_INITIALIZER;
    int zr = Z_OK;
    z_stream *zstrm = (z_stream *) xmalloc(sizeof(z_stream));
    int windowBits;

    switch (scheme) {
    case DEFLATE_RAW:
        windowBits = -MAX_WBITS;        /* raw deflate */
        break;

    case DEFLATE_GZIP:
        windowBits = 16+MAX_WBITS;      /* gzip header */
        break;

    case DEFLATE_ZLIB:
    default:
        windowBits = MAX_WBITS;         /* zlib header */
        break;
    }

    zstrm->zalloc = zalloc;
    zstrm->zfree = zfree;
    zstrm->opaque = Z_NULL;

    zr = deflateInit2(zstrm, compLevel, Z_DEFLATED, windowBits,
                      MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
    if (zr != Z_OK) goto err;

    /* set up the source */
    zstrm->next_in = (unsigned char *)src->s;
    zstrm->avail_in = src->len;

    /* prepare the destination */
    do {
        buf_ensure(&localbuf, 4096);
        /* find the buffer */
        zstrm->next_out = (unsigned char *)localbuf.s + localbuf.len;
        zstrm->avail_out = localbuf.alloc - localbuf.len;
        zr = deflate(zstrm, Z_SYNC_FLUSH);
        if (!(zr == Z_OK || zr == Z_STREAM_END || zr == Z_BUF_ERROR))
           goto err;
        localbuf.len = localbuf.alloc - zstrm->avail_out;
    } while (zstrm->avail_out == 0);

    deflateEnd(zstrm);
    free(zstrm);

    buf_free(src); /* dispose of current buffer */
    *src = localbuf; /* in place replace */
    return 0;

 err:
    free(zstrm);
    buf_free(&localbuf);
    return -1;
}

#endif

/*
 * Warm up a file, by beginning background readahead.  @offset and
 * @length define a subset of the file to be warmed; @length = 0 means
 * to the end of the file.  Returns a UNIX errno or 0 on success.  No
 * error is reported if the file is missing or the kernel doesn't have
 * the magic system call.
 *
 * Returns zero on success or an error code (system error code).
 */
EXPORTED int warmup_file(const char *filename,
                         off_t offset, off_t length)
{
    int fd;
    int r;

    if (!filename) return 0;

    fd = open(filename, O_RDONLY, 0);
    if (fd < 0) return 0;

    /* Note, posix_fadvise() returns its error code rather than
     * setting errno.  Unlike every other system call including
     * others defined in the same standard by the same committee. */
    r = posix_fadvise(fd, offset, length, POSIX_FADV_WILLNEED);

    /* posix_fadvise(WILLNEED) on Linux will return an EINVAL error
     * if the file is on tmpfs, even though this effectively means
     * the file's bytes are all already available in RAM.  Duh. */
    if (r == EINVAL) r = 0;

    close(fd);

    return r;
}

EXPORTED const char *makeuuid()
{
    /* 36 bytes of uuid plus \0 */
    static char res[UUID_STR_LEN];
    memset(res, 0, UUID_STR_LEN);
#ifdef HAVE_LIBUUID
    uuid_t uu;
    uuid_clear(uu); /* Just In Case */
    uuid_generate(uu);
    /* Solaris has an older libuuid which has uuid_unparse() but not
     * uuid_unparse_lower(), so we post-process the result ourself. */
    uuid_unparse(uu, res);
    lcase(res);
#else
    /* some random nonsense for 24 chars - probably less secure */
    int i;
    for (i = 0; i < 24; i++) {
        int item = rand() % 36;
        res[i] = (item < 10 ? '0' + item : 'a' + item - 10);
    }
#endif
    return res;
}

static int is_tcp_socket(int fd)
{
    int so_type;
    socklen_t so_type_len = sizeof(so_type);
    struct sockaddr sock_addr;
    socklen_t sock_addr_len = sizeof(sock_addr);

    if (fd < 0) return 0;

    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &so_type, &so_type_len) == -1) {
        if (errno != ENOTSOCK)
            syslog(LOG_ERR, "%s: getsockopt(%d): %m", __func__, fd);
        return 0;
    }

    if (so_type != SOCK_STREAM) return 0;

    if (getsockname(fd, &sock_addr, &sock_addr_len) == -1) {
        if (errno != ENOTSOCK)
            syslog(LOG_ERR, "%s: getsockname(%d): %m", __func__, fd);
        return 0;
    }

    /* XXX be a bit more pedantic? */
    if (sock_addr.sa_family == AF_UNIX) return 0;

    return 1;
}

EXPORTED void tcp_enable_keepalive(int fd)
{
    if (!is_tcp_socket(fd)) return;

    /* turn on TCP keepalive if set */
    if (config_getswitch(IMAPOPT_TCP_KEEPALIVE)) {
        int r;
        int optval = 1;
        socklen_t optlen = sizeof(optval);
        struct protoent *proto = getprotobyname("TCP");

        r = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);
        if (r < 0) {
            syslog(LOG_ERR, "unable to setsocketopt(SO_KEEPALIVE): %m");
        }
#ifdef TCP_KEEPCNT
        optval = config_getint(IMAPOPT_TCP_KEEPALIVE_CNT);
        if (optval) {
            r = setsockopt(fd, proto->p_proto, TCP_KEEPCNT, &optval, optlen);
            if (r < 0) {
                syslog(LOG_ERR, "unable to setsocketopt(TCP_KEEPCNT): %m");
            }
        }
#endif
#ifdef TCP_KEEPIDLE
        optval = config_getduration(IMAPOPT_TCP_KEEPALIVE_IDLE, 's');
        if (optval) {
            r = setsockopt(fd, proto->p_proto, TCP_KEEPIDLE, &optval, optlen);
            if (r < 0) {
                syslog(LOG_ERR, "unable to setsocketopt(TCP_KEEPIDLE): %m");
            }
        }
#endif
#ifdef TCP_KEEPINTVL
        optval = config_getduration(IMAPOPT_TCP_KEEPALIVE_INTVL, 's');
        if (optval) {
            r = setsockopt(fd, proto->p_proto, TCP_KEEPINTVL, &optval, optlen);
            if (r < 0) {
                syslog(LOG_ERR, "unable to setsocketopt(TCP_KEEPINTVL): %m");
            }
        }
#endif
    }
}

/* Disable Nagle's Algorithm => increase throughput
 *
 * http://en.wikipedia.org/wiki/Nagle's_algorithm
 */
EXPORTED void tcp_disable_nagle(int fd)
{
    if (!is_tcp_socket(fd)) return;

    struct protoent *proto = getprotobyname("tcp");
    if (!proto) {
        syslog(LOG_ERR, "unable to getprotobyname(\"tcp\"): %m");
        return;
    }

    int on = 1;
    if (setsockopt(fd, proto->p_proto, TCP_NODELAY, &on, sizeof(on)) != 0) {
        syslog(LOG_ERR, "unable to setsocketopt(TCP_NODELAY): %m");
    }
}

EXPORTED void xsyslog_fn(int priority, const char *description,
                         const char *func, const char *extra_fmt, ...)
{
    struct buf buf = BUF_INITIALIZER;
    const char *traceid = trace_id();
    int saved_errno = errno;
    int want_diag = (LOG_PRI(priority) != LOG_NOTICE
                     && LOG_PRI(priority) != LOG_INFO);

    buf_appendcstr(&buf, description);
    buf_appendmap(&buf, ": ", 2);
    if (session_have_id()) {
        buf_appendmap(&buf, "sessionid=<", 11);
        buf_appendcstr(&buf, session_id());
        buf_appendmap(&buf, "> ", 2);
    }
    if (traceid) {
        buf_appendmap(&buf, "r.tid=<", 7);
        buf_appendcstr(&buf, traceid);
        buf_appendmap(&buf, "> ", 2);
    }
    if (extra_fmt && *extra_fmt) {
        va_list args;

        va_start(args, extra_fmt);
        buf_vprintf(&buf, extra_fmt, args);
        va_end(args);

        buf_putc(&buf, ' ');
    }
    if (want_diag) {
        if (saved_errno) {
            buf_appendmap(&buf, "syserror=<", 10);
            buf_appendcstr(&buf, strerror(saved_errno));
            buf_appendmap(&buf, "> ", 2);
        }
        buf_appendmap(&buf, "func=<", 6);
        if (func) buf_appendcstr(&buf, func);
        buf_putc(&buf, '>');
    }

    syslog(priority, "%s", buf_cstring(&buf));
    buf_free(&buf);
    errno = saved_errno;
}

EXPORTED char *modseqtoa(modseq_t modseq)
{
    struct buf buf = BUF_INITIALIZER;
    buf_printf(&buf, MODSEQ_FMT, modseq);
    return buf_release(&buf);
}

EXPORTED void _xsyslog_ev(int saved_errno, int priority, const char *event,
                          xsyslog_ev_arg_list *arg)
{
    struct logfmt lf = LOGFMT_INITIALIZER;
    struct buf errbuf = BUF_INITIALIZER;

    logfmt_init(&lf, event);
    logfmt_push_session(&lf);

    for (size_t i = 0; i < arg->nmemb; i++) {
        const char *name = arg->data[i].name;

        switch(arg->data[i].type) {
        case LF_C:   logfmt_pushf(&lf, name, "%c", arg->data[i].c);     break;
        case LF_D:   logfmt_pushf(&lf, name, "%d", arg->data[i].d);     break;
        case LF_LD:  logfmt_pushf(&lf, name, "%ld", arg->data[i].ld);   break;
        case LF_LLD: logfmt_pushf(&lf, name, "%lld", arg->data[i].lld); break;
        case LF_U:   logfmt_pushf(&lf, name, "%u", arg->data[i].u);     break;
        case LF_LU:  logfmt_pushf(&lf, name, "%lu", arg->data[i].lu);   break;
        case LF_LLU: logfmt_pushf(&lf, name, "%llu", arg->data[i].llu); break;
        case LF_ZD:  logfmt_pushf(&lf, name, "%zd", arg->data[i].zd);   break;
        case LF_ZU:  logfmt_pushf(&lf, name, "%zu", arg->data[i].zu);   break;
        case LF_LLX: logfmt_pushf(&lf, name, "%llx", arg->data[i].llu); break;
        case LF_F:   logfmt_pushf(&lf, name, "%f", arg->data[i].f);     break;

        case LF_M:
            logfmt_push(&lf, name, strerror(saved_errno));
            break;
        case LF_S:
            logfmt_push(&lf, name, arg->data[i].s);
            break;
        case LF_UTF8:
            logfmt_push_utf8(&lf, name, arg->data[i].s);
            break;
        case LF_RAW:
            logfmt_push(&lf, name, arg->data[i].s);
            free((char *)arg->data[i].s);
            break;

        default:
            buf_printf(&errbuf, "Unknown lf type: %d", arg->data[i].type);
            fatal(buf_cstring(&errbuf), EX_SOFTWARE);
            break;
        }
    }

    syslog(priority, "%s", logfmt_cstring(&lf));
    logfmt_fini(&lf);

    errno = saved_errno;
}
