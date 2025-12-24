/* logfmt - formatted logging API */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_LOGFMT_H
#define INCLUDED_LOGFMT_H

#include "buf.h"

struct logfmt
{
    struct buf msg;
    struct buf scratch;
};
#define LOGFMT_INITIALIZER (struct logfmt){     \
    .msg = BUF_INITIALIZER,                     \
    .scratch = BUF_INITIALIZER,                 \
}

extern void logfmt_escape_bytestring(struct buf *buf, const char *val);
extern void logfmt_escape_utf8(struct buf *buf, const char *utf8val);

extern void logfmt_init(struct logfmt *lf, const char *event);
extern void logfmt_fini(struct logfmt *lf);
const char *logfmt_cstring(const struct logfmt *lf);

extern void logfmt_push(struct logfmt *lf, const char *key, const char *value);

extern void logfmt_push_utf8(struct logfmt *lf,
                             const char *key,
                             const char *value);

__attribute__((format(printf, 3, 4)))
extern void logfmt_pushf(struct logfmt *lf, const char *key,
                         const char *valuefmt, ...);

extern void logfmt_push_session(struct logfmt *lf);

extern void logfmt_push_caller(struct logfmt *lf,
                               const char *file,
                               int line,
                               const char *func);

#endif
