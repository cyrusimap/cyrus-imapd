/* buf.c -- dynamic string buffers
 *
 * Copyright (c) 1994-2025 Carnegie Mellon University.  All rights reserved.
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

#include "lib/buf.h"

#include "lib/assert.h"
#include "lib/byteorder.h"
#include "lib/map.h"
#include "lib/util.h"
#include "lib/xmalloc.h"

#include <string.h>

/* predeclarations to avoid including util.h */
extern char *lcase(char* str);
extern char *ucase (char *str);

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifdef HAVE_DECLARE_OPTIMIZE
static inline size_t roundup(size_t size)
    __attribute__((pure, always_inline, optimize("-O3")));
#endif
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
    return ((size * 2) & ~1023);
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

EXPORTED const char *buf_cstringnull(const struct buf *buf)
{
    if (!buf->s) return NULL;
    return buf_cstring(buf);
}

EXPORTED const char *buf_cstringnull_ifempty(const struct buf *buf)
{
    if (!buf->len) return NULL;
    return buf_cstring(buf);
}

EXPORTED const char *buf_cstring_or_empty(const struct buf *buf)
{
    if (!buf->s) return "";
    return buf_cstring(buf);
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
    buf->alloc = 0;
    buf->s = NULL;
    buf_free(buf);
    return ret;
}

EXPORTED char *buf_releasenull(struct buf *buf)
{
    char *ret = (char *)buf_cstringnull(buf);
    buf->alloc = 0;
    buf->s = NULL;
    buf_free(buf);
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

#ifdef HAVE_DECLARE_OPTIMIZE
EXPORTED inline size_t buf_len(const struct buf *buf)
    __attribute__((always_inline, optimize("-O3")));
#endif
EXPORTED inline size_t buf_len(const struct buf *buf)
{
    return buf->len;
}

#ifdef HAVE_DECLARE_OPTIMIZE
EXPORTED inline const char *buf_base(const struct buf *buf)
    __attribute__((always_inline, optimize("-O3")));
#endif
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

/* Append str to buf, omitting any byte sequence at the start
 * of str that matches the exact same byte sequence at the
 * end of buf. E.g. if buf="fooxyz" and str="xyzbar" then the
 * result is "fooxyzbar". */
EXPORTED void buf_appendoverlap(struct buf *buf, const char *str)
{
    const char *t = buf_cstring(buf);
    size_t matchlen = strlen(str);
    if (matchlen < buf_len(buf)) {
        t += buf_len(buf) - matchlen;
    } else {
        matchlen = buf_len(buf);
    }

    while (*t && matchlen && strncasecmp(t, str, matchlen)) {
        t++; matchlen--;
    }

    if (*t && matchlen) {
        buf_truncate(buf, buf_len(buf) - matchlen);
    }
    buf_appendcstr(buf, str);
}

EXPORTED void buf_appendbit32(struct buf *buf, uint32_t num)
{
    uint32_t item = htonl(num);
    buf_appendmap(buf, (char *)&item, 4);
}

EXPORTED void buf_appendbit64(struct buf *buf, uint64_t num)
{
    uint64_t item = htonll(num);
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

EXPORTED void buf_replace_buf(struct buf *buf,
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
    buf_free(&str_buf);
}

EXPORTED void buf_insertmap(struct buf *dst, unsigned int off,
                            const char *base, int len)
{
    struct buf map_buf = BUF_INITIALIZER;
    buf_init_ro(&map_buf, base, len);
    buf_replace_buf(dst, off, 0, &map_buf);
    buf_free(&map_buf);
}

EXPORTED void buf_remove(struct buf *dst, unsigned int off, unsigned int len)
{
    struct buf empty_buf = BUF_INITIALIZER;
    buf_replace_buf(dst, off, len, &empty_buf);
    buf_free(&empty_buf);
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

/*
 * Initialise a struct buf to point to read-only data.  The key here is
 * setting buf->alloc=0 which indicates CoW is in effect, i.e. the data
 * pointed to needs to be copied should it ever be modified.
 */
EXPORTED void buf_init_ro(struct buf *buf, const char *base, size_t len)
{
    buf_free(buf);
    buf->s = (char *)base;
    buf->len = len;
}

/*
 * Initialise a struct buf to point to writable data at 'base', which
 * must be a malloc()ed allocation at least 'len' bytes long and is
 * taken over by the struct buf.
 */
EXPORTED void buf_initm(struct buf *buf, char *base, int len)
{
    buf_free(buf);
    buf->s = base;
    buf->alloc = buf->len = len;
}

/*
 * Initialise a struct buf to point to writable c string str.
 */
EXPORTED void buf_initmcstr(struct buf *buf, char *str)
{
    buf_initm(buf, str, strlen(str));
}

/*
 * Initialise a struct buf to point to a read-only C string.
 */
EXPORTED void buf_init_ro_cstr(struct buf *buf, const char *str)
{
    buf_free(buf);
    buf->s = (char *)str;
    buf->len = (str ? strlen(str) : 0);
}

/*
 * Initialise a struct buf to point to a read-only mmap()ing.
 * This buf is CoW, and if written to the data will be freed
 * using map_free().
 */
EXPORTED void buf_refresh_mmap(struct buf *buf, int onceonly, int fd,
                            const char *fname, size_t size, const char *mboxname)
{
    assert(!buf->alloc);
    buf->flags = BUF_MMAP;
    map_refresh(fd, onceonly, (const char **)&buf->s, &buf->len,
                size, fname, mboxname);
}

EXPORTED void buf_free(struct buf *buf)
{
    if (!buf) return;

    if (buf->alloc)
        free(buf->s);
    else if (buf->flags & BUF_MMAP)
        map_free((const char **)&buf->s, &buf->len);
    buf->alloc = 0;
    buf->s = NULL;
    buf->len = 0;
    buf->flags = 0;
}

EXPORTED void buf_move(struct buf *dst, struct buf *src)
{
    buf_free(dst);
    *dst = *src;
    memset(src, 0, sizeof(struct buf));
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


EXPORTED const char *buf_lcase(struct buf *buf)
{
    buf_cstring(buf);
    lcase(buf->s);
    return buf->s;
}

EXPORTED const char *buf_ucase(struct buf *buf)
{
    buf_cstring(buf);
    ucase(buf->s);
    return buf->s;
}

EXPORTED const char *buf_tocrlf(struct buf *buf)
{
    size_t i;

    buf_cstring(buf);

    for (i = 0; i < buf->len; i++) {
        if (buf->s[i] == '\r' && buf->s[i+1] != '\n') {
            /* bare \r: add a \n after it */
            buf_insertcstr(buf, i+1, "\n");
        }
        else if (buf->s[i] == '\n') {
            if (i == 0 || buf->s[i-1] != '\r') {
                buf_insertcstr(buf, i, "\r");
            }
        }
    }

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
