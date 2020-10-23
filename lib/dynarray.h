/* dynarray.h -- an expanding array of same-size members
 *
 * Copyright (c) 1994-2020 Carnegie Mellon University.  All rights reserved.
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
 */

#ifndef __CYRUS_DYNARRAY_H__
#define __CYRUS_DYNARRAY_H__

typedef struct dynarray {
    size_t membsize;
    int count;
    int alloc;
    void *data;
} dynarray_t;

extern void dynarray_init(struct dynarray *da, size_t membsize);
extern void dynarray_fini(struct dynarray *da);

extern struct dynarray *dynarray_new(size_t membsize);
extern void dynarray_free(struct dynarray **dap);

extern void dynarray_append(struct dynarray *da, void *memb);
extern void dynarray_set(struct dynarray *, int idx, void *memb);
extern void *dynarray_nth(const struct dynarray *da, int idx);
extern int dynarray_size(struct dynarray *da);
extern void dynarray_truncate(struct dynarray *da, int newlen);


#endif /* __CYRUS_DYNARRAY_H__ */
