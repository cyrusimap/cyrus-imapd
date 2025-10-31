/* logfmt - formatted logging API
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
