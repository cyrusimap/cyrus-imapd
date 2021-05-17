/* smallarrayu64.h - an expanding array of 64 bit unsigned integers
 *
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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
 * Author: Greg Banks
 * Start Date: 2011/01/11
 */

#ifndef __CYRUS_SMALLARRAYU64_H__
#define __CYRUS_SMALLARRAYU64_H__

#include <sys/types.h>

#include <stdint.h>

#include "arrayu64.h"

#define SMALLARRAYU64_ALLOC 8

typedef struct {
    size_t count;
    uint8_t data[SMALLARRAYU64_ALLOC];
    arrayu64_t spillover;
    int use_spillover;
} smallarrayu64_t;

#define SMALLARRAYU64_INITIALIZER { 0, { 0 }, ARRAYU64_INITIALIZER, 0 }

#define smallarrayu64_init(sa)   (memset((sa), 0, sizeof(smallarrayu64_t)))
extern void smallarrayu64_fini(smallarrayu64_t *sa);

extern smallarrayu64_t *smallarrayu64_new(void);
extern void smallarrayu64_free(smallarrayu64_t *);

extern int smallarrayu64_append(smallarrayu64_t *sa, uint64_t num);

extern size_t smallarrayu64_size(smallarrayu64_t *sa);

extern uint64_t smallarrayu64_nth(smallarrayu64_t *sa, int idx);

#endif /* __CYRUS_SMALLARRAYU64_H__ */
