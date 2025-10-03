/* util.h -- general utility functions
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
 *
 * Author: Chris Newman
 * Start Date: 4/6/93
 */

#ifndef INCLUDED_UTIL_H
#define INCLUDED_UTIL_H

#include <config.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef STDIN_FILENO
/* Standard file descriptors.  */
#define STDIN_FILENO    0       /* Standard input.  */
#define STDOUT_FILENO   1       /* Standard output.  */
#define STDERR_FILENO   2       /* Standard error output.  */
#endif

#include "buf.h"
#include "xmalloc.h"

/* version string printable in gdb tracking */
extern const char CYRUS_VERSION[];

#ifdef ENABLE_REGEX
# if defined HAVE_PCREPOSIX_H
#  include <pcre.h>
#  include <pcreposix.h>
# elif defined HAVE_PCRE2POSIX_H
#  ifndef PCRE2POSIX_H_INCLUDED
#   include <pcre2posix.h>
#   define PCRE2POSIX_H_INCLUDED
#  endif
# elif defined HAVE_RXPOSIX_H
#  include <rxposix.h>
# else
#  include <regex.h>
# endif
#endif

#ifdef HAVE_LIBUUID
#include <uuid/uuid.h>
#endif
#ifndef UUID_STR_LEN
#define UUID_STR_LEN  37
#endif

#define BIT32_MAX 4294967295U
#define BIT64_MAX 18446744073709551615UL

#define BIT64_FMT          "%016" PRIx64
#define UINT64_FMT         "%" PRIu64
#define UINT64_LALIGN_FMT  "%-*" PRIu64
#define UINT64_NANOSEC_FMT ".%.9" PRIu64

typedef uint32_t bit32;
typedef uint64_t bit64;
typedef uint64_t modseq_t;

#define MODSEQ_FMT UINT64_FMT
#define atomodseq_t(s) strtoull(s, NULL, 10)
char *modseqtoa(modseq_t modseq);

#define Uisalnum(c) isalnum((int)((unsigned char)(c)))
#define Uisalpha(c) isalpha((int)((unsigned char)(c)))
#define Uisascii(c) isascii((int)((unsigned char)(c)))
#define Uiscntrl(c) iscntrl((int)((unsigned char)(c)))
#define Uisdigit(c) isdigit((int)((unsigned char)(c)))
#define Uislower(c) islower((int)((unsigned char)(c)))
#define Uisspace(c) isspace((int)((unsigned char)(c)))
#define Uisupper(c) isupper((int)((unsigned char)(c)))
#define Uisxdigit(c) isxdigit((int)((unsigned char)(c)))

extern const unsigned char convert_to_lowercase[256];
extern const unsigned char convert_to_uppercase[256];

#ifndef TOUPPER
#define TOUPPER(c) (convert_to_uppercase[(unsigned char)(c)])
#endif
#ifndef TOLOWER
#define TOLOWER(c) (convert_to_lowercase[(unsigned char)(c)])
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

/* Some BSDs don't print "NULL" for a NULL pointer string. */
#ifndef IS_NULL
#define IS_NULL(s)      ((s) == NULL ? "(NULL)" : (s))
#endif

/* Calculate the number of entries in a vector */
#define VECTOR_SIZE(vector) (sizeof(vector)/sizeof(vector[0]))

#ifndef TIMESPEC_TO_TIMEVAL
#define TIMESPEC_TO_TIMEVAL(tv, ts) {         \
        (tv)->tv_sec  = (ts)->tv_sec;         \
        (tv)->tv_usec = (ts)->tv_nsec / 1000; \
}
#endif

/* We have an issue that we can't store UTIME_OMIT into the nanosecond
 * space, so we reserve '0' to mean OMIT, meaning that we can only store
 * postitive nanosecond values.  We also store 0 as 0, so callers are
 * required to make sure they have a SAFE_NSEC value when writing */
#define UTIME_SAFE_NSEC(n) (n > 0 && n < 1000000000)
#define _NSVAL(n)                                                           \
        (UTIME_SAFE_NSEC(n) ? n : 0)
#define TIMESPEC_TO_NANOSEC(ts)                                             \
        ((uint64_t) (ts)->tv_sec * 1000000000 + _NSVAL((ts)->tv_nsec))

/* On the way back, we convert 0 to UTIME_OMIT and all other values stay the
 * same, meaning that round-tripping a time with zero nanoseconds through this
 * function pair will add one nanosecond */
#define TIMESPEC_FROM_NANOSEC(ts, nanosec) {    \
        (ts)->tv_sec  = (nanosec) / 1000000000; \
        (ts)->tv_nsec = (nanosec) % 1000000000; \
}

#define NANOSEC_TO_JMAPID(buf, nanosec) {                                   \
        assert(nanosec);                                                    \
        uint64_t u64 = htonll(UINT64_MAX - (nanosec));                      \
        charset_encode(buf, (const char *) &u64, 8, ENCODING_BASE64JMAPID); \
}

#define MODSEQ_TO_JMAPID(buf, modseq) {                                 \
        uint64_t u64 = htonll(modseq);                                  \
        const char *p = (const char *) &u64;                            \
        size_t len = sizeof(u64);                                       \
        for (; *p == 0 && len > 1; p++, len--);                         \
        charset_encode(buf, p, len, ENCODING_BASE64JMAPID);             \
}

typedef struct keyvalue {
    char *key, *value;
} keyvalue;

/* convert string to all lower case
 */
extern char *lcase (char *str);

/* convert string to all upper case
 */
extern char *ucase (char *str);

/* clean up control characters in a string while copying it
 *  returns pointer to a static buffer containing the cleaned-up version
 */
extern char *beautify_string (const char *src);

/* Same semantics as strcmp() but gracefully handles
 * either or both it's arguments being NULL */
int strcmpsafe(const char *a, const char *b);
/* Same semantics as strcasecmp() but gracefully handles
 * either or both it's arguments being NULL */
int strcasecmpsafe(const char *a, const char *b);
/* ditto strncmp */
int strncmpsafe(const char *a, const char *b, size_t n);
int strncasecmpsafe(const char *a, const char *b, size_t n);

/* NULL isn't "" */
int strcmpnull(const char *a, const char *b);

/* do a binary search in a keyvalue array
 *  nelem is the number of keyvalue elements in the kv array
 *  cmpf is the comparison function (strcmp, stricmp, etc).
 *  returns NULL if not found, or key/value pair if found.
 */
extern keyvalue *kv_bsearch (const char *key, keyvalue *kv, int nelem,
                               int (*cmpf)(const char *s1, const char *s2));

/* Examine the name of a file, and return a single character
 *  (as an int) that can be used as the name of a hash
 *  directory.  Caller is responsible for skipping any prefix
 *  of the name.
 */
extern int dir_hash_c(const char *name, int full);
/*
 * Like dir_hash_c() but builds the result as a single-byte
 * C string in the provided buffer, and returns the buffer,
 * which is sometimes more convenient.
 */
extern char *dir_hash_b(const char *name, int full, char buf[2]);

/*
 * create an [unlinked] temporary file and return the file descriptor.
 */
extern int create_tempfile(const char *path);

/* create a temporary directory at path and return the directory
 * name "cyrus-subname-XXXXXX", where subname defaults to "tmpdir"
 * and XXXXXX is a string that makes the directory name unique.
 * */
extern char *create_tempdir(const char *path, const char *subname);

/* recursively call remove(3) on path and its descendants, except
 * symlinks. Returns zero on success, or the first non-zero return
 * value of remove on error. */
extern int removedir(const char *path);

/* Call rename but fsync the directory before returning success */
extern int xopendir(const char *dest, int create);
extern int xrenameat(int dirfd, const char *src, const char *dest);
extern int cyrus_settime_fdptr(const char *path, struct timespec *when, int *dirfdp);
extern int cyrus_unlink_fdptr(const char *fname, int *dirfdp);
extern void xclosedir(int dirfd);
extern int cyrus_rename(const char *src, const char *dest);

/* Close a network filedescriptor the "safe" way */
extern int cyrus_close_sock(int fd);

/* Reset stdin/stdout/stderr */
extern void cyrus_reset_stdio(void);

/* Create all parent directories for the given path,
 * up to but not including the basename.
 */
extern int cyrus_mkdir(const char *path, mode_t mode);

enum {
    COPYFILE_NOLINK = (1<<0),
    COPYFILE_MKDIR  = (1<<1),
    COPYFILE_KEEPTIME = (1<<2),
    COPYFILE_NODIRSYNC = (1<<3)
};

extern int cyrus_copyfile_fdptr(const char *from, const char *to, int flags, int *dirfdp);
#define cyrus_copyfile(from, to, flags) cyrus_copyfile_fdptr(from, to, flags, NULL)

enum {
    BEFORE_SETUID,
    AFTER_SETUID,
    BEFORE_BIND,
    AFTER_BIND,
    AFTER_FORK
};

extern int set_caps(int stage, int is_master);
extern int become_cyrus(int is_master);
extern const char *cyrus_user(void);
extern const char *cyrus_group(void);

/* Some systems have very inefficient implementations of isdigit,
 * and we use it in a lot of inner loops
 */

#define cyrus_isdigit(x) ((x) >= '0' && (x) <= '9')
int parseint32(const char *p, const char **ptr, int32_t *res);
int parseuint32(const char *p, const char **ptr, uint32_t *res);
int parsenum(const char *p, const char **ptr, int maxlen, bit64 *res);
int parsehex(const char *p, const char **ptr, int maxlen, bit64 *res);
uint64_t str2uint64(const char *p);

/* Timing related funcs/vars */
extern void cmdtime_settimer(int enable);
extern void cmdtime_starttimer(void);
extern void cmdtime_endtimer(double * cmdtime, double * nettime);
extern void cmdtime_netstart(void);
extern void cmdtime_netend(void);
extern int cmdtime_checksearch(void);
extern double timeval_get_double(const struct timeval *tv);
extern void timeval_set_double(struct timeval *tv, double d);
extern void timeval_add_double(struct timeval *tv, double delta);
extern double timesub(const struct timeval *start, const struct timeval *end);
extern int64_t now_ms(void);

extern clock_t sclock(void);

#ifdef ENABLE_REGEX
/* XXX These two ought to be declared in buf.h with their friends, but their
 * XXX declarations depend on regex_t, which is only available with config.h,
 * XXX and therefore not available within headers that are to be installed.
 */
int buf_replace_all_re(struct buf *buf, const regex_t *,
                       const char *replace);
int buf_replace_one_re(struct buf *buf, const regex_t *,
                       const char *replace);
#endif

/*
 * Given a list of strings, terminated by (char *)NULL,
 * return a newly allocated string containing the
 * concatenation of all the argument strings.  The
 * caller must free the returned string using free().
 *
 * This API idea based on glib's g_strconcat() which
 * is really quite amazingly convenient.
 */
char *strconcat(const char *s1, ...);

#define BH_LOWER            (0)
#define BH_UPPER            (1<<8)
#define _BH_SEP             (1<<9)
#define BH_SEPARATOR(c)     (_BH_SEP|((c)&0x7f))
#define _BH_GETSEP(flags)   (flags & _BH_SEP ? (char)(flags & 0x7f) : '\0')
int bin_to_hex(const void *bin, size_t binlen, char *hex, int flags);
int hex_to_bin(const char *hex, size_t hexlen, void *bin);

int buf_bin_to_hex(struct buf *hex, const void *bin, size_t binlen, int flags);
int buf_hex_to_bin(struct buf *bin, const char *hex, size_t hexlen);

/* use getpassphrase on machines which support it */
#ifdef HAVE_GETPASSPHRASE
#define cyrus_getpass getpassphrase
#else
#define cyrus_getpass getpass
#endif

#ifdef HAVE_ZLIB
enum {
    DEFLATE_RAW,
    DEFLATE_GZIP,
    DEFLATE_ZLIB
};

int buf_inflate(struct buf *buf, int scheme);
int buf_deflate(struct buf *buf, int compLevel, int scheme);
#endif

/* A wrapper for close() which handles the fd=-1 case cleanly.
 * The argument may have side effects and must be an lvalue */
#define xclose(fd) \
    do { \
        int *_fdp = &(fd); \
        if (*_fdp >= 0) { \
            close(*_fdp); \
            *_fdp = -1; \
        } \
    } while(0)

/* A wrapper for strncpy() which ensures that the destination
 * string is always NUL-terminated.  Yes, I know we have an
 * implementation of the BSD strlcpy() which has this semantic,
 * but that isn't a highly optimised libc or compiler provided
 * function like strncpy(), and we can trivially and efficiently
 * add the NUL termination semantic on top of strncpy(). */
#define xstrncpy(d, s, n) \
    do { \
        char *_d = (d); \
        size_t _n = (n); \
        strncpy(_d, (s), _n-1); \
        _d[_n-1] = '\0'; \
    } while(0)

/* simple function to request a file gets pre-loaded by the OS */
int warmup_file(const char *filename, off_t offset, off_t length);

const char *makeuuid();

void tcp_enable_keepalive(int fd);
void tcp_disable_nagle(int fd);

void xsyslog_fn(int priority, const char *description,
                const char *func, const char *extra_fmt, ...)
               __attribute__((format(printf, 4, 5)));
#define xsyslog(pri, desc, ...)  \
    xsyslog_fn(pri, desc, __func__, __VA_ARGS__)

/*
 * GCC_VERSION macro usage:
 * #if GCC_VERSION > 60909    //GCC version 7 and above
 *   do_something();
 * #endif
 */
#define GCC_VERSION (__GNUC__ * 10000           \
                     + __GNUC_MINOR__ * 100     \
                     + __GNUC_PATCHLEVEL__)

typedef struct logfmt_arg {
    const char *name;
    int type;
    union {
        char c;
        int d;
        long int ld;
        long long int lld;
        unsigned int u;
        long unsigned int lu;
        long long unsigned int llu;
        ssize_t zd;
        size_t zu;
        double f;
        const char *s;
    };
} logfmt_arg;

typedef struct logfmt_arg_list {
    size_t nmemb;
    logfmt_arg *data;
} logfmt_arg_list;

#define logfmt_arg_LIST(...) (logfmt_arg_list *)                   \
    &(logfmt_arg_list) {                                           \
        sizeof((logfmt_arg []){__VA_ARGS__}) / sizeof(logfmt_arg), \
        (logfmt_arg []){__VA_ARGS__}                               \
    }

void _xsyslog_ev(int saved_errno, int priority, const char *event,
                 logfmt_arg_list *arg);

#define xsyslog_ev(priority, event, ...)                                \
    do {                                                                \
        int se = errno;                                                 \
        _xsyslog_ev(se, priority, event, logfmt_arg_LIST(__VA_ARGS__)); \
    } while (0)

enum logfmt_type {
    LF_C,
    LF_D,
    LF_LD,
    LF_LLD,
    LF_U,
    LF_LU,
    LF_LLU,
    LF_ZD,
    LF_ZU,
    LF_LLX,
    LF_F,
    LF_M,
    LF_S,
    LF_RAW
};

#define lf_c(key, value)   (logfmt_arg){ key, LF_C,   { .c   = value } }
#define lf_d(key, value)   (logfmt_arg){ key, LF_D,   { .d   = value } }
#define lf_ld(key, value)  (logfmt_arg){ key, LF_LD,  { .ld  = value } }
#define lf_lld(key, value) (logfmt_arg){ key, LF_LLD, { .lld = value } }
#define lf_u(key, value)   (logfmt_arg){ key, LF_U,   { .u   = value } }
#define lf_lu(key, value)  (logfmt_arg){ key, LF_LU,  { .lu  = value } }
#define lf_llu(key, value) (logfmt_arg){ key, LF_LLU, { .llu = value } }
#define lf_zd(key, value)  (logfmt_arg){ key, LF_ZD,  { .zd  = value } }
#define lf_zu(key, value)  (logfmt_arg){ key, LF_ZU,  { .zu  = value } }
#define lf_llx(key, value) (logfmt_arg){ key, LF_LLX, { .llu = value } }
#define lf_f(key, value)   (logfmt_arg){ key, LF_F,   { .f   = value } }
#define lf_m(key)          (logfmt_arg){ key, LF_M,   {              } }
#define lf_s(key, value)   (logfmt_arg){ key, LF_S,   { .s   = value } }

#define lf_raw(key, fmt, ...) ({                               \
    struct buf value = BUF_INITIALIZER;                        \
    buf_printf(&value, fmt, __VA_ARGS__);                      \
    (logfmt_arg){ key, LF_RAW, { .s = buf_release(&value) } }; \
})

/* Set up cyrus_gettime as a weak alias for a wrapper around clock_gettime.
 * We then use cyrus_gettime everywhere instead of clock_gettime, and unit
 * tests can mock cyrus_gettime if they need to fake the passing of time.
 *
 * We need this shim because, unlike gettimeofday, clock_gettime itself is
 * not a weak alias, so it can't be overridden directly.
 */
static int wrap_clock_gettime(clockid_t id, struct timespec *ts)
{
    return clock_gettime(id, ts);
}
__attribute__((weak, alias("wrap_clock_gettime"), visibility("default")))
extern int cyrus_gettime(clockid_t, struct timespec *);

#endif /* INCLUDED_UTIL_H */
