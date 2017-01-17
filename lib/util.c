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
#include <limits.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "byteorder64.h"
#include "exitcodes.h"
#include "libconfig.h"
#include "map.h"
#include "retry.h"
#include "util.h"
#include "assert.h"
#include "xmalloc.h"
#ifdef HAVE_ZLIB
#include "zlib.h"
#endif
#ifdef HAVE_LIBUUID
#include <uuid/uuid.h>
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

/* Examine the name of a file, and return a single character
 *  (as an int) that can be used as the name of a hash
 *  directory.  Stop before the first dot.  Caller is responsible
 *  for skipping any prefix of the name.
 */
EXPORTED int dir_hash_c(const char *name, int full)
{
    int c;

    if (full) {
        unsigned char *pt;
        uint32_t n;
        enum {
            DIR_X = 3,
            DIR_Y = 5,
            DIR_P = 23,
            DIR_A = 'A'
        };

        n = 0;
        pt = (unsigned char *)name;
        while (*pt && *pt != '.') {
            n = ((n << DIR_X) ^ (n >> DIR_Y)) ^ *pt;
            n &= UINT32_MAX;
            ++pt;
        }
        c = DIR_A + (n % DIR_P);
    }
    else {
        c = tolower(*name);
        if (!Uisascii(c) || !Uislower(c)) c = 'q';
    }

    return c;
}

EXPORTED char *dir_hash_b(const char *name, int full, char buf[2])
{
    buf[0] = (char)dir_hash_c(name, full);
    buf[1] = '\0';
    return buf;
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
        fatal("open() on /dev/null failed", EC_TEMPFAIL);
    }

    /* stdin */
    shutdown(0, SHUT_RD);
    dup2(devnull, 0);

    /* stdout */
    shutdown(1, SHUT_RD);
    dup2(devnull, 1);

    /* stderr */
    shutdown(2, SHUT_RD);
    dup2(devnull, 2);

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
    if (fd >= 0 && unlink(pattern) == -1) {
        close(fd);
        fd = -1;
    }

    free(pattern);
    return fd;
}

/* Create all parent directories for the given path,
 * up to but not including the basename.
 */
EXPORTED int cyrus_mkdir(const char *pathname, mode_t mode __attribute__((unused)))
{
    char *path = xstrdup(pathname);    /* make a copy to write into */
    char *p = path;
    int save_errno;
    struct stat sbuf;

    while ((p = strchr(p+1, '/'))) {
        *p = '\0';
        if (mkdir(path, 0755) == -1 && errno != EEXIST) {
            save_errno = errno;
            if (stat(path, &sbuf) == -1) {
                errno = save_errno;
                syslog(LOG_ERR, "IOERROR: creating directory %s: %m", path);
                free(path);
                return -1;
            }
        }
        *p = '/';
    }

    free(path);
    return 0;
}

static int _copyfile_helper(const char *from, const char *to, int flags)
{
    int srcfd = -1;
    int destfd = -1;
    const char *src_base = 0;
    size_t src_size = 0;
    struct stat sbuf;
    int n;
    int r = 0;
    int nolink = flags & COPYFILE_NOLINK;

    /* try to hard link, but don't fail - fall back to regular copy */
    if (!nolink) {
        if (link(from, to) == 0) return 0;
        if (errno == EEXIST) {
            if (unlink(to) == -1) {
                syslog(LOG_ERR, "IOERROR: unlinking to recreate %s: %m", to);
                return -1;
            }
            if (link(from, to) == 0) return 0;
        }
    }

    srcfd = open(from, O_RDONLY, 0666);
    if (srcfd == -1) {
        syslog(LOG_ERR, "IOERROR: opening %s: %m", from);
        r = -1;
        goto done;
    }

    if (fstat(srcfd, &sbuf) == -1) {
        syslog(LOG_ERR, "IOERROR: fstat on %s: %m", from);
        r = -1;
        goto done;
    }

    if (!sbuf.st_size) {
        syslog(LOG_ERR, "IOERROR: zero byte file %s: %m", from);
        r = -1;
        goto done;
    }

    destfd = open(to, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (destfd == -1) {
        if (!(flags & COPYFILE_MKDIR))
            syslog(LOG_ERR, "IOERROR: creating %s: %m", to);
        r = -1;
        goto done;
    }

    map_refresh(srcfd, 1, &src_base, &src_size, sbuf.st_size, from, 0);

    n = retry_write(destfd, src_base, src_size);

    if (n == -1 || fsync(destfd)) {
        syslog(LOG_ERR, "IOERROR: writing %s: %m", to);
        r = -1;
        unlink(to);  /* remove any rubbish we created */
        goto done;
    }

done:
    map_free(&src_base, &src_size);

    if (srcfd != -1) close(srcfd);
    if (destfd != -1) close(destfd);

    return r;
}

EXPORTED int cyrus_copyfile(const char *from, const char *to, int flags)
{
    int r;

    /* copy over self is an error */
    if (!strcmp(from, to))
        return -1;

    r = _copyfile_helper(from, to, flags);

    /* try creating the target directory if requested */
    if (r && (flags & COPYFILE_MKDIR)) {
        r = cyrus_mkdir(to, 0755);
        if (!r) r = _copyfile_helper(from, to, flags & ~COPYFILE_MKDIR);
    }

    if (!r && (flags & COPYFILE_RENAME)) {
        /* remove the original file if the copy succeeded */
        unlink(from);
    }

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

static int cap_setuid(int uid, int is_master)
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
    uid_t newuid;
    gid_t newgid;
    int result;
    static uid_t uid = 0;

    if (uid) return cap_setuid(uid, is_master);

    const char *cyrus = cyrus_user();

    p = getpwnam(cyrus);
    if (p == NULL) {
        syslog(LOG_ERR, "no entry in /etc/passwd for user %s", cyrus);
        return -1;
    }

    /* Save these in case initgroups does a getpw*() */
    newuid = p->pw_uid;
    newgid = p->pw_gid;

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

    result = cap_setuid(newuid, is_master);

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

static int cmdtime_enabled = 0;
static struct timeval cmdtime_start, cmdtime_end, nettime_start, nettime_end;
static double totaltime, cmdtime, nettime, search_maxtime;

double timeval_get_double(const struct timeval *tv)
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
 * time using clock_gettime(CLOCK_MONOTONIC) but that
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
        if (result > 214748364 || (result == 214748364 && (*p > '7')))
            fatal("num too big", EC_IOERR);
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
        if (result > 429496729 || (result == 429496729 && (*p > '5')))
            fatal("num too big", EC_IOERR);
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
     * - and I don't care about those last 5
     */
    for (n = 0; !maxlen || n < maxlen; n++) {
        if (!cyrus_isdigit(p[n]))
            break;
        if (result > 1844674407370955161ULL)
            fatal("num too big", EC_IOERR);
        cval = p[n] - '0';
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
     * - and I don't care about those last 5
     */
    for (n = 0; !maxlen || n < maxlen; n++) {
        if (result > 1844674407370955161ULL)
            fatal("num too big", EC_IOERR);
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

/* buffer handling functions */

static inline size_t roundup(size_t size)
    __attribute__((pure, always_inline, optimize("-O3")));
static inline size_t roundup(size_t size)
{
    if (size < 32)
        return 32;
    if (size < 64)
        return 64;
    if (size < 128)
        return 128;
    if (size < 256)
        return 256;
    if (size < 512)
        return 512;
    return ((size + 1024) & ~1023);
}

/* this function has a side-effect of always leaving the buffer writable */
EXPORTED void _buf_ensure(struct buf *buf, size_t n)
{
    size_t newlen = buf->len + n;
    char *s;

    assert(newlen); /* we never alloc zero bytes */

    if (buf->alloc >= newlen)
        return;

    if (buf->alloc) {
        buf->alloc = roundup(newlen);
        buf->s = xrealloc(buf->s, buf->alloc);
    }
    else {
        buf->alloc = roundup(newlen);
        s = xmalloc(buf->alloc);

        /* if no allocation, but data exists, it means copy on write.
         * grab a copy of what's there now */
        if (buf->len) {
            assert(buf->s);
            memcpy(s, buf->s, buf->len);
        }

        /* can release MMAP now, we've copied the data out */
        if (buf->flags & BUF_MMAP) {
            size_t len = buf->len; /* don't wipe the length, we still need it */
            map_free((const char **)&buf->s, &len);
            buf->flags &= ~BUF_MMAP;
        }

        buf->s = s;
    }
}

EXPORTED const char *buf_cstring(const struct buf *buf)
{
    struct buf *backdoor = (struct buf*)buf;
    buf_ensure(backdoor, 1);
    backdoor->s[backdoor->len] = '\0';
    return buf->s;
}

EXPORTED char *buf_newcstring(struct buf *buf)
{
    char *ret = xstrdup(buf_cstring(buf));
    buf_reset(buf);
    return ret;
}

EXPORTED char *buf_release(struct buf *buf)
{
    char *ret = (char *)buf_cstring(buf);
    buf_init(buf);
    return ret;
}

EXPORTED const char *buf_cstringnull(const struct buf *buf)
{
    if (!buf->s) return NULL;
    return buf_cstring(buf);
}

EXPORTED char *buf_releasenull(struct buf *buf)
{
    char *ret = (char *)buf_cstringnull(buf);
    buf_init(buf);
    return ret;
}

EXPORTED void buf_getmap(struct buf *buf, const char **base, size_t *len)
{
    *base = buf->s;
    *len = buf->len;
}

/* fetch a single line a file - terminated with \n ONLY.
 * buf does not contain the \n.
 * NOTE: if the final line does not contain a \n we still
 * return true so that the caller will process the line,
 * so a file A\nB will return two true responses with bufs
 * containing "A" and "B" respectively before returning a
 * false to the third call */
EXPORTED int buf_getline(struct buf *buf, FILE *fp)
{
    int c;

    buf_reset(buf);
    while ((c = fgetc(fp)) != EOF) {
        if (c == '\n')
            break;
        buf_putc(buf, c);
    }
    /* ensure trailing NULL */
    buf_cstring(buf);

    /* EOF and no content, we're done */
    return (!(buf->len == 0 && c == EOF));
}

EXPORTED inline size_t buf_len(const struct buf *buf)
    __attribute__((always_inline, optimize("-O3")));
EXPORTED inline size_t buf_len(const struct buf *buf)
{
    return buf->len;
}

EXPORTED inline const char *buf_base(const struct buf *buf)
    __attribute__((always_inline, optimize("-O3")));
EXPORTED inline const char *buf_base(const struct buf *buf)
{
    return buf->s;
}

EXPORTED void buf_reset(struct buf *buf)
{
    if (buf->flags & BUF_MMAP)
        map_free((const char **)&buf->s, &buf->len);
    buf->len = 0;
    buf->flags = 0;
}

EXPORTED void buf_truncate(struct buf *buf, ssize_t len)
{
    if (len < 0) {
        len = buf->len + len;
        if (len < 0) len = 0;
    }
    if ((size_t)len > buf->alloc) {
        /* grow the buffer and zero-fill the new bytes */
        size_t more = len - buf->len;
        buf_ensure(buf, more);
        memset(buf->s + buf->len, 0, more);
    }
    buf->len = len;
}

EXPORTED void buf_setcstr(struct buf *buf, const char *str)
{
    buf_setmap(buf, str, strlen(str));
}

EXPORTED void buf_setmap(struct buf *buf, const char *base, size_t len)
{
    buf_reset(buf);
    if (len) {
        buf_ensure(buf, len);
        memcpy(buf->s, base, len);
        buf->len = len;
    }
}

EXPORTED void buf_copy(struct buf *dst, const struct buf *src)
{
    buf_setmap(dst, src->s, src->len);
}

EXPORTED void buf_append(struct buf *dst, const struct buf *src)
{
    buf_appendmap(dst, src->s, src->len);
}

EXPORTED void buf_appendcstr(struct buf *buf, const char *str)
{
    buf_appendmap(buf, str, strlen(str));
}

EXPORTED void buf_appendbit32(struct buf *buf, bit32 num)
{
    bit32 item = htonl(num);
    buf_appendmap(buf, (char *)&item, 4);
}

EXPORTED void buf_appendbit64(struct buf *buf, bit64 num)
{
    bit64 item = htonll(num);
    buf_appendmap(buf, (char *)&item, 8);
}

EXPORTED void buf_appendmap(struct buf *buf, const char *base, size_t len)
{
    if (len) {
        buf_ensure(buf, len);
        memcpy(buf->s + buf->len, base, len);
        buf->len += len;
    }
}

/* This is like buf_appendmap() but attempts an optimisation where the
 * first append to an empty buf results in a read-only pointer to the
 * data at 'base' instead of a writable copy. */
EXPORTED void buf_cowappendmap(struct buf *buf, const char *base, unsigned int len)
{
    if (!buf->s)
        buf_init_ro(buf, base, len);
    else
        buf_appendmap(buf, base, len);
}

/* This is like buf_cowappendmap() but takes over the given map 'base',
 * which is a malloc()ed C string buffer of at least 'len' bytes. */
EXPORTED void buf_cowappendfree(struct buf *buf, char *base, unsigned int len)
{
    if (!buf->s)
        buf_initm(buf, base, len);
    else {
        buf_appendmap(buf, base, len);
        free(base);
    }
}

EXPORTED void buf_vprintf(struct buf *buf, const char *fmt, va_list args)
{
    va_list ap;
    int room;
    int n;

    /* Add some more room to the buffer.  We just guess a
     * size and rely on vsnprintf() to tell us if it
     * needs to overrun the size. */
    buf_ensure(buf, 1024);

    /* Copy args in case we guess wrong on the size */
    va_copy(ap, args);

    room = buf->alloc - buf->len;
    n = vsnprintf(buf->s + buf->len, room, fmt, args);

    if (n >= room) {
        /* woops, we guessed wrong...retry with enough space */
        buf_ensure(buf, n+1);
        n = vsnprintf(buf->s + buf->len, n+1, fmt, ap);
    }
    va_end(ap);

    buf->len += n;
}

EXPORTED void buf_printf(struct buf *buf, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    buf_vprintf(buf, fmt, args);
    va_end(args);
}

static void buf_replace_buf(struct buf *buf,
                            size_t offset,
                            size_t length,
                            const struct buf *replace)
{
    if (offset > buf->len) return;
    if (offset + length > buf->len)
        length = buf->len - offset;

    /* we need buf to be a writable C string now please */
    buf_cstring(buf);

    if (replace->len > length) {
        /* string will need to expand */
        buf_ensure(buf, replace->len - length + 1);
    }
    if (length != replace->len) {
        /* +1 to copy the NULL to keep cstring semantics */
        memmove(buf->s + offset + replace->len,
                buf->s + offset + length,
                buf->len - offset - length + 1);
        buf->len += (replace->len - length);
    }
    if (replace->len)
        memcpy(buf->s + offset, replace->s, replace->len);
}

/**
 * Replace all instances of the string literal @match in @buf
 * with the string @replace, which may be NULL to just remove
 * instances of @match.
 * Returns: the number of substitutions made.
 */
EXPORTED int buf_replace_all(struct buf *buf, const char *match,
                             const char *replace)
{
    int n = 0;
    int matchlen = strlen(match);
    struct buf replace_buf = BUF_INITIALIZER;
    size_t off;
    char *p;

    buf_init_ro_cstr(&replace_buf, replace);

    /* we need buf to be a nul terminated string now please */
    buf_cstring(buf);

    off = 0;
    while ((p = strstr(buf->s + off, match))) {
        off = (p - buf->s);
        buf_replace_buf(buf, off, matchlen, &replace_buf);
        n++;
        off += replace_buf.len;
    }

    return n;
}

EXPORTED int buf_replace_char(struct buf *buf, char match, char replace)
{
    int n = 0;
    size_t i;

    /* we need writable, so may as well cstring it */
    buf_cstring(buf);

    for (i = 0; i < buf->len; i++) {
        if (buf->s[i] == match) {
            buf->s[i] = replace;
            n++;
        }
    }

    return n;
}

#ifdef ENABLE_REGEX
/**
 * Replace the first instance of the compiled regexp @preg
 * in @buf with the string @replace, which may be NULL to just
 * remove an instance of @preg.  Does not support capture references
 * in the replace text.
 * Returns: the number of substitutions made (0 or 1)
 */
EXPORTED int buf_replace_one_re(struct buf *buf, const regex_t *preg,
                                const char *replace)
{
    struct buf replace_buf = BUF_INITIALIZER;
    regmatch_t rm;

    buf_init_ro_cstr(&replace_buf, replace);

    /* we need buf to be a nul terminated string now please */
    buf_cstring(buf);

    if (!regexec(preg, buf->s, 1, &rm, 0)) {
        buf_replace_buf(buf, rm.rm_so, rm.rm_eo - rm.rm_so, &replace_buf);
        return 1;
    }

    return 0;
}

/**
 * Replace all instances of the compiled regexp @preg in @buf
 * with the string @replace, which may be NULL to just remove
 * instances of @preg.  Does not support capture references
 * in the replace text.
 * Returns: the number of substitutions made.
 */
EXPORTED int buf_replace_all_re(struct buf *buf, const regex_t *preg,
                                const char *replace)
{
    int n = 0;
    struct buf replace_buf = BUF_INITIALIZER;
    regmatch_t rm;
    size_t off;

    buf_init_ro_cstr(&replace_buf, replace);

    /* we need buf to be a nul terminated string now please */
    buf_cstring(buf);

    off = 0;
    while (!regexec(preg, buf->s + off, 1, &rm, (off ? REG_NOTBOL : 0))) {
        buf_replace_buf(buf, off + rm.rm_so, rm.rm_eo - rm.rm_so, &replace_buf);
        off += rm.rm_so + replace_buf.len;
        n++;
    }

    return n;
}
#endif

EXPORTED void buf_insert(struct buf *dst, unsigned int off, const struct buf *src)
{
    buf_replace_buf(dst, off, 0, src);
}

EXPORTED void buf_insertcstr(struct buf *dst, unsigned int off, const char *str)
{
    struct buf str_buf = BUF_INITIALIZER;
    buf_init_ro_cstr(&str_buf, str);
    buf_replace_buf(dst, off, 0, &str_buf);
}

EXPORTED void buf_insertmap(struct buf *dst, unsigned int off,
                            const char *base, int len)
{
    struct buf map_buf = BUF_INITIALIZER;
    buf_init_ro(&map_buf, base, len);
    buf_replace_buf(dst, off, 0, &map_buf);
}

EXPORTED void buf_remove(struct buf *dst, unsigned int off, unsigned int len)
{
    struct buf empty_buf = BUF_INITIALIZER;
    buf_replace_buf(dst, off, len, &empty_buf);
}

/*
 * Compare two struct bufs bytewise.  Returns a number
 * like strcmp(), suitable for sorting e.g. with qsort(),
 */
EXPORTED int buf_cmp(const struct buf *a, const struct buf *b)
{
    size_t len = MIN(a->len, b->len);
    int r = 0;

    if (len)
        r = memcmp(a->s, b->s, len);

    if (!r) {
        if (a->len < b->len)
            r = -1;
        else if (a->len > b->len)
            r = 1;
    }

    return r;
}

EXPORTED void buf_init(struct buf *buf)
{
    buf->alloc = 0;
    buf->len = 0;
    buf->flags = 0;
    buf->s = NULL;
}

/*
 * Initialise a struct buf to point to read-only data.  The key here is
 * setting buf->alloc=0 which indicates CoW is in effect, i.e. the data
 * pointed to needs to be copied should it ever be modified.
 */
EXPORTED void buf_init_ro(struct buf *buf, const char *base, size_t len)
{
    buf->alloc = 0;
    buf->len = len;
    buf->flags = 0;
    buf->s = (char *)base;
}

/*
 * Initialise a struct buf to point to writable data at 'base', which
 * must be a malloc()ed allocation at least 'len' bytes long and is
 * taken over by the struct buf.
 */
EXPORTED void buf_initm(struct buf *buf, char *base, int len)
{
    buf->alloc = buf->len = len;
    buf->flags = 0;
    buf->s = base;
}

/*
 * Initialise a struct buf to point to a read-only C string.
 */
EXPORTED void buf_init_ro_cstr(struct buf *buf, const char *str)
{
    buf->alloc = 0;
    buf->len = (str ? strlen(str) : 0);
    buf->flags = 0;
    buf->s = (char *)str;
}

/*
 * Initialise a struct buf to point to a read-only mmap()ing.
 * This buf is CoW, and if written to the data will be freed
 * using map_free().
 */
EXPORTED void buf_init_mmap(struct buf *buf, int onceonly, int fd,
                            const char *fname, size_t size, const char *mboxname)
{
    buf->flags = BUF_MMAP;
    map_refresh(fd, onceonly, (const char **)&buf->s, &buf->len,
                size, fname, mboxname);
}

static void _buf_free_data(struct buf *buf)
{
    if (buf->alloc)
        free(buf->s);
    else if (buf->flags & BUF_MMAP)
        map_free((const char **)&buf->s, &buf->len);
}

EXPORTED void buf_free(struct buf *buf)
{
    _buf_free_data(buf);
    buf->alloc = 0;
    buf->s = NULL;
    buf->len = 0;
    buf->flags = 0;
}

EXPORTED void buf_move(struct buf *dst, struct buf *src)
{
    _buf_free_data(dst);
    *dst = *src;
    buf_init(src);
}

EXPORTED int buf_findchar(const struct buf *buf, unsigned int off, int c)
{
    const char *p;

    if (off < buf->len && (p = memchr(buf->s + off, c, buf->len - off)))
        return (p - buf->s);
    return -1;
}

/*
 * Find (the first line in) 'line' in the buffer 'buf'.  The found text
 * will be a complete line, i.e. bounded by either \n newlines or by the
 * edges of 'buf'.  Returns the byte index into 'buf' of the found text,
 * or -1 if not found.
 */
EXPORTED int buf_findline(const struct buf *buf, const char *line)
{
    int linelen;
    const char *p;
    const char *end = buf->s + buf->len;

    if (!line) return -1;

    /* find the length of the first line in the text at 'line' */
    p = strchr(line, '\n');
    linelen = (p ? (size_t)(p - line) : strlen(line));
    if (linelen == 0) return -1;

    for (p = buf->s ;
         (p = (const char *)memmem(p, end-p, line, linelen)) != NULL ;
         p++) {

        /* check the found string is at line boundaries */
        if (p > buf->s && p[-1] != '\n')
            continue;
        if ((p+linelen) < end && p[linelen] != '\n')
            continue;

        return (p - buf->s);
    }

    return -1;
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

EXPORTED const char *buf_lcase(struct buf *buf)
{
    buf_cstring(buf);
    lcase(buf->s);
    return buf->s;
}

EXPORTED void buf_trim(struct buf *buf)
{
    size_t i;
    for (i = 0; i < buf->len; i++) {
        if (buf->s[i] == ' ') continue;
        if (buf->s[i] == '\t') continue;
        if (buf->s[i] == '\r') continue;
        if (buf->s[i] == '\n') continue;
        break;
    }
    if (i) buf_remove(buf, 0, i);

    for (i = buf->len; i > 1; i--) {
        if (buf->s[i-1] == ' ') continue;
        if (buf->s[i-1] == '\t') continue;
        if (buf->s[i-1] == '\r') continue;
        if (buf->s[i-1] == '\n') continue;
        break;
    }
    if (i != buf->len) {
        buf_truncate(buf, i);
    }
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

    fd = open(filename, O_RDONLY, 0);
    if (fd < 0) return errno;

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
    static char res[37];
    memset(res, 0, 37);
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
        optval = config_getint(IMAPOPT_TCP_KEEPALIVE_IDLE);
        if (optval) {
            r = setsockopt(fd, proto->p_proto, TCP_KEEPIDLE, &optval, optlen);
            if (r < 0) {
                syslog(LOG_ERR, "unable to setsocketopt(TCP_KEEPIDLE): %m");
            }
        }
#endif
#ifdef TCP_KEEPINTVL
        optval = config_getint(IMAPOPT_TCP_KEEPALIVE_INTVL);
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
