/* api.c -- replication-based backup api
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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

#include <assert.h>
#include <errno.h>

#include "lib/cyr_lock.h"
#include "lib/sqldb.h"
#include "lib/xmalloc.h"

#include "imap/dlist.h"

#include "backup/api.h"
#include "backup/sqlconsts.h"

enum backup_lock_type {
    BACKUP_LOCK_SHARED = 0,
    BACKUP_LOCK_EXCLUSIVE,
#define backup_is_valid_lock_type(t) ((t) <= BACKUP_LOCK_EXCLUSIVE)
};

enum backup_data_mode {
    BACKUP_DATA_NORMAL = 0,
    BACKUP_DATA_APPEND,
    BACKUP_DATA_CREATE,
#define backup_is_valid_data_mode(m) ((m) <= BACKUP_DATA_CREATE)
};

enum backup_index_mode {
    BACKUP_INDEX_READ = 0,
    BACKUP_INDEX_WRITE,
    BACKUP_INDEX_CREATE,
#define backup_is_valid_index_mode(m) ((m) <= BACKUP_INDEX_CREATE)
};

struct backup {
    int fd;
    char *name;
    char *gzname;
    char *idxname;
    char *oldidxname;
    struct gzuncat *gzuc;
    sqldb_t *db;
    enum backup_lock_type lock_type;
    enum backup_data_mode data_mode;
    enum backup_index_mode index_mode;
};

/*
 * use cases:
 *  - backupd needs to be able to append to gz and update index (exclusive)
 *  - backupd maybe needs to create a new backup from scratch (exclusive)
 *  - reindex needs to gzuc gz and rewrite index (exclusive)
 *  - compress needs to rewrite gz and index (exclusive)
 *  - restore needs to read gz and index (shared)
 */

static int backup_open(struct backup **backupp, const char *name,
                       enum backup_lock_type lock_type,
                       enum backup_data_mode data_mode,
                       enum backup_index_mode index_mode)
{
    assert(backup_is_valid_lock_type(lock_type));
    assert(backup_is_valid_data_mode(data_mode));
    assert(backup_is_valid_index_mode(index_mode));

    struct backup *backup = xzmalloc(sizeof *backup);
    if (!backup) return -1;
    backup->fd = -1;

    backup->name = strdup(name);
    backup->gzname = strconcat(name, ".gz", NULL);
    backup->idxname = strconcat(name, ".index", NULL);

    int openflags;
    int r = 0;

    switch (data_mode) {
    case BACKUP_DATA_NORMAL:
        openflags = O_RDWR;
        break;
    case BACKUP_DATA_APPEND:
        openflags = O_RDWR | O_APPEND;
        lock_type = BACKUP_LOCK_EXCLUSIVE;
        break;
    case BACKUP_DATA_CREATE:
        openflags = O_RDWR | O_CREAT | O_EXCL;
        lock_type = BACKUP_LOCK_EXCLUSIVE;
        break;
    default:
        r = -1;
        goto error;
    }

    backup->fd = open(backup->gzname, openflags, S_IRUSR | S_IWUSR);
    if (backup->fd < 0) {
        r = errno;
        goto error;
    }
    backup->data_mode = data_mode;

    r = lock_setlock(backup->fd, lock_type == BACKUP_LOCK_EXCLUSIVE, /*nb*/ 0, backup->gzname);
    if (r) goto error;
    backup->lock_type = lock_type;

    // open the index
    const char *initsql = NULL;
    const struct sqldb_upgrade *upgradesql = NULL;

    if (index_mode == BACKUP_INDEX_WRITE) {
        initsql = backup_index_initsql;
        upgradesql = backup_index_upgrade;
    }
    else if (index_mode == BACKUP_INDEX_CREATE) {
        initsql = backup_index_initsql;
        upgradesql = backup_index_upgrade;

        char *oldidxname = strconcat(backup->idxname, ".old", NULL);

        r = rename(backup->idxname, oldidxname);
        if (r && errno != ENOENT) {
            r = errno;
            free(oldidxname);
            goto error;
        }

        backup->oldidxname = oldidxname;
    }

    backup->db = sqldb_open(backup->idxname, initsql, backup_index_version, upgradesql);
    if (!backup->db) {
        r = -1;
        goto error;
    }

    backup->index_mode = index_mode;

    *backupp = backup;
    return 0;

error:
    if (backup->lock_type) lock_unlock(backup->fd, backup->gzname);
    if (backup->fd >= 0) close(backup->fd);
    if (backup->name) free(backup->name);
    if (backup->gzname) free(backup->gzname);
    if (backup->idxname) free(backup->idxname);
    if (backup->oldidxname) free(backup->oldidxname);
    if (backup->db) sqldb_close(&backup->db);
    free(backup);
    return r;
}

//int backup_open_shared(struct backup **backupp, const char *name) {
//    return backup_open(backupp, name, BACKUP_LOCK_SHARED);
//}

//int backup_open_exclusive(struct backup **backupp, const char *name) {
//    return backup_open(backupp, name, BACKUP_LOCK_EXCLUSIVE);
//}

EXPORTED int backup_reindex(const char *name)
{
    return -1;
}

EXPORTED int backup_create(struct backup **backupp, const char *name)
{
    return -1;
}

EXPORTED int backup_close(struct backup **backupp)
{
    return -1;
}

EXPORTED int backup_write_dlist(struct backup *backup, time_t ts, struct dlist *dl)
{
    return -1;
}

EXPORTED int backup_index_dlist(struct backup *backup, time_t ts, struct dlist *dl)
{
    return -1;
}
