/* buf.h - dynamic string buffers */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_BUF_H
#define INCLUDED_BUF_H

#include <stdint.h>
#include <stdio.h>

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
const char *buf_cstring_or_empty(const struct buf *buf);
char *buf_newcstring(struct buf *buf);
char *buf_release(struct buf *buf);
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
void buf_appendbit32(struct buf *buf, uint32_t num);
void buf_appendbit64(struct buf *buf, uint64_t num);
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
void buf_replace_buf(struct buf *buf, size_t offset, size_t length,
                     const struct buf *replace);
int buf_replace_all(struct buf *buf, const char *match,
                    const char *replace);
int buf_replace_char(struct buf *buf, char match, char replace);
/* XXX see also util.h for declarations of buf_replace_all_re() and
 * XXX buf_replace_one_re()
 */
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

#endif
