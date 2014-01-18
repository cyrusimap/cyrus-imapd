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
 * $Id: util.h,v 1.28 2010/06/28 12:06:44 brong Exp $
 *
 * Author: Chris Newman
 * Start Date: 4/6/93
 */

#ifndef INCLUDED_UTIL_H
#define INCLUDED_UTIL_H

#include <config.h>
#include <sys/types.h>
#include <limits.h>
#include <stdarg.h>

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

#ifdef HAVE_LONG_LONG_INT
typedef unsigned long long int bit64;
typedef unsigned long long int modseq_t;
#define MODSEQ_FMT "%llu"
#define atomodseq_t(s) strtoull(s, NULL, 10)
#else
typedef unsigned long int modseq_t;
#define MODSEQ_FMT "%lu"
#define atomodseq_t(s) strtoul(s, NULL, 10)
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

#define TOUPPER(c) (convert_to_uppercase[(unsigned char)(c)])
#define TOLOWER(c) (convert_to_lowercase[(unsigned char)(c)])

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
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
 *  returns pointer to end of dst string.
 *  dst must have twice the length of source
 */
extern char *beautify_copy (char *dst, const char *src);

/* clean up control characters in a string while copying it
 *  returns pointer to a static buffer containing the cleaned-up version
 *  returns NULL on malloc() error
 */
extern char *beautify_string (const char *src);

/* Same semantics as strcmp() but gracefully handles
 * either or both it's arguments being NULL */
int strcmpsafe(const char *a, const char *b);
/* Same semantics as strcasecmp() but gracefully handles
 * either or both it's arguments being NULL */
int strcasecmpsafe(const char *a, const char *b);

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
 * create an [unlinked] temporary file and return the file descriptor.
 */
extern int create_tempfile(const char *path);

/* Close a network filedescriptor the "safe" way */
extern int cyrus_close_sock(int fd);

/* Reset stdin/stdout/stderr */
extern void cyrus_reset_stdio();

/* Create all parent directories for the given path,
 * up to but not including the basename.
 */
extern int cyrus_mkdir(const char *path, mode_t mode);

extern int become_cyrus(void);

/* Some systems have very inefficient implementations of isdigit,
 * and we use it in a lot of inner loops
 */

#define cyrus_isdigit(x) ((x) >= '0' && (x) <= '9')
extern int parseint32(const char *p, const char **ptr, int32_t *res);
extern int parseuint32(const char *p, const char **ptr, uint32_t *res);

/* Timing related funcs/vars */
extern void cmdtime_settimer(int enable);
extern void cmdtime_starttimer();
extern void cmdtime_endtimer(double * cmdtime, double * nettime);
extern void cmdtime_netstart();
extern void cmdtime_netend();


#define BUF_CSTRING 1

struct buf {
    char *s;
    unsigned len;
    unsigned alloc;
    int flags;
};
#define BUF_INITIALIZER	{ NULL, 0, 0, 0 }

const char *buf_cstring(struct buf *buf);
void buf_ensure(struct buf *buf, unsigned morebytes);
char *buf_release(struct buf *buf);
void buf_getmap(struct buf *buf, const char **base, unsigned *len);
unsigned buf_len(const struct buf *buf);
void buf_reset(struct buf *buf);
void buf_truncate(struct buf *buf, unsigned int len);
void buf_setcstr(struct buf *buf, const char *str);
void buf_setmap(struct buf *buf, const char *base, unsigned len);
void buf_copy(struct buf *dst, const struct buf *src);
void buf_append(struct buf *dst, const struct buf *src);
void buf_appendcstr(struct buf *buf, const char *str);
void buf_appendbit32(struct buf *buf, bit32 num);
void buf_appendmap(struct buf *buf, const char *base, unsigned len);
void buf_putc(struct buf *buf, char c);
void buf_vprintf(struct buf *buf, const char *fmt, va_list args);
void buf_printf(struct buf *buf, const char *fmt, ...)
    __attribute__((format(printf,2,3)));
unsigned int buf_replace_all(struct buf *buf, const char *match,
			     const char *replace);
int buf_cmp(const struct buf *, const struct buf *);
void buf_init(struct buf *buf);
void buf_init_ro(struct buf *buf, const char *base, unsigned len);
void buf_free(struct buf *buf);
void buf_move(struct buf *dst, struct buf *src);

/* use getpassphrase on machines which support it */
#ifdef HAVE_GETPASSPHRASE
#define cyrus_getpass getpassphrase
#else
#define cyrus_getpass getpass
#endif

/*
 * Given a list of strings, terminated by (char *)NULL,
 * return a newly allocated string containing the
 * concatention of all the argument strings.  The
 * caller must free the returned string using free().
 *
 * This API idea based on glib's g_strconcat() which
 * is really quite amazingly convenient.
 */
char *strconcat(const char *s1, ...);

#ifdef HAVE_ZLIB
enum {
    DEFLATE_RAW,
    DEFLATE_GZIP,
    DEFLATE_ZLIB
};

int buf_inflate(struct buf *buf, int scheme);
int buf_deflate(struct buf *buf, int compLevel, int scheme);
#endif

#endif /* INCLUDED_UTIL_H */
