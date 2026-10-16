/* jmap_undo.c - Undo log for atomic JMAP Foo/set */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include "imap/imap_err.h"
#include "imap/jmap_undo.h"
#include "libconfig.h"
#include "xmalloc.h"
#include "logfmt.h"
#include "util.h"

struct undo_entry
{
    jmap_undo_cb *cb;
    void *rock;
    void (*free_rock)(void *);
};

static void entry_free(struct undo_entry *e)
{
    if (e->free_rock) {
        e->free_rock(e->rock);
    }
    free(e);
}

EXPORTED void jmap_undo_push(struct jmap_undo *u,
                             jmap_undo_cb *cb,
                             void *rock,
                             void (*free_rock)(void *))
{
    struct undo_entry *e = xzmalloc(sizeof(*e));
    e->cb = cb;
    e->rock = rock;
    e->free_rock = free_rock;
    ptrarray_append(&u->entries, e);
}

EXPORTED int jmap_undo_failpoint(struct jmap_undo *u)
{
    int step = imapopts[IMAPOPT_DEBUG_JMAP_ATOMIC_FAILSTEP].val.i32;
    u->calls++;
    if (step > 0 && u->calls == (unsigned) step) {
        return IMAP_IOERROR;
    }
    return 0;
}

EXPORTED int jmap_undo_run(struct jmap_undo *u)
{
    int nfail = 0;
    struct undo_entry *e;

    while ((e = ptrarray_pop(&u->entries))) {
        int r = e->cb(e->rock);
        if (r) {
            nfail++;
            xsyslog_ev(LOG_ERR, "jmap.atomic.undo.failed",
                       lf_err("error", r));
        }
        entry_free(e);
    }
    ptrarray_fini(&u->entries);

    return nfail;
}

EXPORTED void jmap_undo_fini(struct jmap_undo *u)
{
    struct undo_entry *e;

    while ((e = ptrarray_pop(&u->entries))) {
        entry_free(e);
    }
    ptrarray_fini(&u->entries);
}
