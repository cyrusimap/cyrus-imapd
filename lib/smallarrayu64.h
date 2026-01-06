/* smallarrayu64.h - an expanding array of 64 bit unsigned integers */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
