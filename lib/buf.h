/* buf.h -- dynamic string buffers
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
