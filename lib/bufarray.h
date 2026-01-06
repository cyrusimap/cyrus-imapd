/* buf.h -- buffers and buffer arrays */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef __CYRUS_BUF_H__
#define __CYRUS_BUF_H__

#include <string.h>
#include <sys/types.h>
#include "util.h"

typedef struct {
    size_t alloc;
    size_t count;
    struct buf **items;
} bufarray_t;

#define BUFARRAY_INITIALIZER { 0, 0, NULL }
#define bufarray_init(ba)   (memset((ba), 0, sizeof(bufarray_t)))
void bufarray_fini(bufarray_t *);

bufarray_t *bufarray_new(void);
void bufarray_free(bufarray_t **);

size_t bufarray_append(bufarray_t *, const struct buf *buf);
size_t bufarray_appendm(bufarray_t *, struct buf *buf);
const struct buf *bufarray_nth(const bufarray_t *sa, size_t idx);
void bufarray_truncate(bufarray_t *sa, size_t newlen);
bufarray_t *bufarray_dup(const bufarray_t *);

size_t bufarray_size(const bufarray_t *sa);

#endif /* __CYRUS_BUF_H__ */
