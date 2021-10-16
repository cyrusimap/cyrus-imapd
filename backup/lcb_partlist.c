/* lcb_partlist.c -- replication-based backup api - partlist functions
 *
 * Copyright (c) 1994-2016 Carnegie Mellon University.  All rights reserved.
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
#include <config.h>

#include "lib/libconfig.h"
#include "lib/xmalloc.h"

#include "imap/partlist.h"

static partlist_t *partlist_backup = NULL;


static void partlist_backup_init(void)
{
    if (partlist_backup) {
        /* already done */
        return;
    }

    partlist_backup = xzmalloc(sizeof(partlist_t));
    partlist_initialize(
        partlist_backup,
        NULL,
        "backuppartition-",
        NULL,
        config_getstring(IMAPOPT_PARTITION_SELECT_EXCLUDE),
        partlist_getmode(config_getstring(IMAPOPT_PARTITION_SELECT_MODE)),
        config_getint(IMAPOPT_PARTITION_SELECT_SOFT_USAGE_LIMIT),
        config_getint(IMAPOPT_PARTITION_SELECT_USAGE_REINIT)
    );
}


/* XXX the following should be in a shared header!!! (currently in lcb_internal.h) */
const char *partlist_backup_select(void);
int partlist_backup_foreach(partlist_foreach_cb proc, void *rock);
void partlist_backup_done(void);

HIDDEN const char *partlist_backup_select(void)
{
    /* lazy loading */
    if (!partlist_backup) {
        partlist_backup_init();
    }

    return (char *)partlist_select_value(partlist_backup);
}


HIDDEN int partlist_backup_foreach(partlist_foreach_cb proc, void *rock)
{
    /* lazy loading */
    if (!partlist_backup) {
        partlist_backup_init();
    }

    return partlist_foreach(partlist_backup, proc, rock);
}


HIDDEN void partlist_backup_done(void)
{
    if (partlist_backup) {
        partlist_free(partlist_backup);
        free(partlist_backup);
        partlist_backup = NULL;
    }
}
