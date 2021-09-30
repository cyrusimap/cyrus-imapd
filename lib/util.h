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
#include <sys/types.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef STDIN_FILENO
/* Standard file descriptors.  */
#define	STDIN_FILENO	0	/* Standard input.  */
#define	STDOUT_FILENO	1	/* Standard output.  */
#define	STDERR_FILENO	2	/* Standard error output.  */
#endif

#include "xmalloc.h"

/* version string printable in gdb tracking */
extern const char CYRUS_VERSION[];

#ifdef ENABLE_REGEX
# ifdef HAVE_PCREPOSIX_H
#  include <pcre.h>
#  include <pcreposix.h>
# else /* !HAVE_PCREPOSIX_H */
#  ifdef HAVE_RXPOSIX_H
#   include <rxposix.h>
#  else /* !HAVE_RXPOSIX_H */
#   include <regex.h>
#  endif /* HAVE_RXPOSIX_H */
# endif /* HAVE_PCREPOSIX_H */
#endif /* ENABLE_REGEX */

#ifdef HAVE_LIBUUID
#include <uuid/uuid.h>
#endif
#ifndef UUID_STR_LEN
#define UUID_STR_LEN  37
#endif

#define BIT32_MAX 4294967295U

#if UINT_MAX == BIT32_MAX
typedef unsigned int bit32;
#elif ULONG_MAX == BIT32_MAX
typedef unsigned long bit32;
#elif USHRT_MAX == BIT32_MAX
typedef unsigned short bit32;
#else
#error dont know what to use for bit32
#endif

typedef unsigned long long int bit64;
typedef unsigned long long int modseq_t;
#define MODSEQ_FMT "%llu"
#define atomodseq_t(s) strtoull(s, NULL, 10)

#if SIZEOF_LONG >= 8
#define INT64_FMT "%ld"
#else
#define INT64_FMT "%lld"
#endif

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
#define TIMESPEC_TO_TIMEVAL(tv, ts) { \
        (tv)->tv_sec = (ts)->tv_sec; \
        (tv)->tv_usec = (ts)->tv_nsec / 1000; \
}
#endif

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
 * symlinks. Returns zero on sucess, or the first non-zero return
 * value of remove on error. */
extern int removedir(const char *path);

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
    COPYFILE_RENAME = (1<<2),
    COPYFILE_KEEPTIME = (1<<3)
};

extern int cyrus_copyfile(const char *from, const char *to, int flags);

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

#define BUF_MMAP    (1<<1)

struct buf {
    char *s;
    size_t len;
    size_t alloc;
    unsigned flags;
};
#define BUF_INITIALIZER { NULL, 0, 0, 0 }

#define buf_new() ((struct buf *) xzmalloc(sizeof(struct buf)))
#define buf_destroy(b) do { buf_free((b)); free((b)); } while (0)
#define buf_ensure(b, n) do { if ((b)->alloc < (b)->len + (n)) _buf_ensure((b), (n)); } while (0)
#define buf_putc(b, c) do { buf_ensure((b), 1); (b)->s[(b)->len++] = (c); } while (0)

void _buf_ensure(struct buf *buf, size_t len);
const char *buf_cstring(const struct buf *buf);
const char *buf_cstringnull(const struct buf *buf);
const char *buf_cstringnull_ifempty(const struct buf *buf);
char *buf_release(struct buf *buf);
char *buf_newcstring(struct buf *buf);
char *buf_releasenull(struct buf *buf);
void buf_getmap(struct buf *buf, const char **base, size_t *len);
int buf_getline(struct buf *buf, FILE *fp);
size_t buf_len(const struct buf *buf);
const char *buf_base(const struct buf *buf);
void buf_reset(struct buf *buf);
void buf_truncate(struct buf *buf, ssize_t len);
void buf_setcstr(struct buf *buf, const char *str);
void buf_setmap(struct buf *buf, const char *base, size_t len);
void buf_copy(struct buf *dst, const struct buf *src);
void buf_append(struct buf *dst, const struct buf *src);
void buf_appendcstr(struct buf *buf, const char *str);
void buf_appendoverlap(struct buf *buf, const char *str);
void buf_appendbit32(struct buf *buf, bit32 num);
void buf_appendbit64(struct buf *buf, bit64 num);
void buf_appendmap(struct buf *buf, const char *base, size_t len);
void buf_cowappendmap(struct buf *buf, const char *base, unsigned int len);
void buf_cowappendfree(struct buf *buf, char *base, unsigned int len);
void buf_insert(struct buf *dst, unsigned int off, const struct buf *src);
void buf_insertcstr(struct buf *buf, unsigned int off, const char *str);
void buf_insertmap(struct buf *buf, unsigned int off, const char *base, int len);
void buf_vprintf(struct buf *buf, const char *fmt, va_list args)
                __attribute__((format(printf, 2, 0)));
void buf_printf(struct buf *buf, const char *fmt, ...)
                __attribute__((format(printf, 2, 3)));
int buf_replace_all(struct buf *buf, const char *match,
                    const char *replace);
int buf_replace_char(struct buf *buf, char match, char replace);
#ifdef ENABLE_REGEX
int buf_replace_all_re(struct buf *buf, const regex_t *,
                       const char *replace);
int buf_replace_one_re(struct buf *buf, const regex_t *,
                       const char *replace);
#endif
void buf_remove(struct buf *buf, unsigned int off, unsigned int len);
int buf_cmp(const struct buf *, const struct buf *);
int buf_findchar(const struct buf *, unsigned int off, int c);
int buf_findline(const struct buf *buf, const char *line);
void buf_init_ro(struct buf *buf, const char *base, size_t len);
void buf_initm(struct buf *buf, char *base, int len);
void buf_initmcstr(struct buf *buf, char *str);
void buf_init_ro_cstr(struct buf *buf, const char *str);
void buf_refresh_mmap(struct buf *buf, int onceonly, int fd,
                   const char *fname, size_t size, const char *mboxname);
void buf_free(struct buf *buf);
void buf_move(struct buf *dst, struct buf *src);
const char *buf_lcase(struct buf *buf);
const char *buf_ucase(struct buf *buf);
const char *buf_tocrlf(struct buf *buf);
void buf_trim(struct buf *buf);

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
int bin_to_lchex(const void *bin, size_t binlen, char *hex);
int hex_to_bin(const char *hex, size_t hexlen, void *bin);

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

const char *makeuuid(void);

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

#endif /* INCLUDED_UTIL_H */
