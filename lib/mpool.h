/* mpool.h -- memory pool management */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef _MPOOL_H_

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

/* Opaque mpool handle */
struct mpool;

#define DEFAULT_MPOOL_SIZE 32768

/* Create a new pool -- pass zero for default */
/* 'size' is the size of the first blob of memory that will be allocated */
struct mpool *new_mpool(size_t size);

/* Free a pool */
void free_mpool(struct mpool *pool);

/* Allocate from a pool */
void *mpool_malloc(struct mpool *pool, size_t size);
char *mpool_strdup(struct mpool *pool, const char *str);
char *mpool_strndup(struct mpool *pool, const char *str, size_t n);

#endif /* _MPOOL_H_ */
