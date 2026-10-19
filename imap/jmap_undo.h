/* jmap_undo.h - Undo log for atomic JMAP Foo/set */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef JMAP_UNDO_H
#define JMAP_UNDO_H

#include "ptrarray.h"

/**
 * @file
 * An undo log for atomic Foo/set.  Apply code pushes the inverse of each
 * durable write, then either discards the log (success) or runs it in
 * reverse (failure).
 */

/** Inverse operation.  Returns 0 or an IMAP_* error code. */
typedef int jmap_undo_cb(void *rock);

/** An undo log.  Initialise with JMAP_UNDO_INITIALIZER. */
struct jmap_undo
{
    ptrarray_t entries;
    unsigned calls; /* failpoint calls so far */
};

#define JMAP_UNDO_INITIALIZER { PTRARRAY_INITIALIZER, 0 }

/**
 * Append an inverse operation.  @p free_rock, if not NULL, releases @p rock
 * once the entry has run or the log is finalised.
 */
void jmap_undo_push(struct jmap_undo *u,
                    jmap_undo_cb *cb,
                    void *rock,
                    void (*free_rock)(void *));

/**
 * Failure injection point; call before each durable write.  Returns
 * IMAP_IOERROR on the Nth call on @p u, where N is the imapd.conf option
 * debug_jmap_atomic_failstep, and 0 otherwise (always 0 if N is 0).
 */
int jmap_undo_failpoint(struct jmap_undo *u);

/**
 * Run the callbacks in reverse push order, freeing each entry afterwards.
 * A failing callback is logged and the rest still run.  Returns the number
 * of failures; the log is empty on return.
 */
int jmap_undo_run(struct jmap_undo *u);

/** Free any entries that were never run.  Does not run them. */
void jmap_undo_fini(struct jmap_undo *u);

#endif /* JMAP_UNDO_H */
