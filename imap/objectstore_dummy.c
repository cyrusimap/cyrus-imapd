/* objectstore_dummy.c
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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

#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>

#include "mailbox.h"
#include "mboxname.h"
#include "libconfig.h"
#include "xmalloc.h"
#include "util.h"
#include "objectstore.h"
#include "objectstore_db.h"

struct object_def
{
    /* primary */
    const char *
        namespace; //  in this implementation this is the flat directory emulating the  object storage
    const char *user;     //  this is the container name.
    const char *filename; //  Name of blob
};

static const char *objectstore_get_object_filename(
    struct mailbox *mailbox __attribute__((unused)),
    const struct index_record *record)
{
    return message_guid_encode(&record->guid);
}

static struct object_def *objectstore_get_object_def(
    struct mailbox *mailbox,
    const struct index_record *record)
{
    static struct object_def obj_def;
    const char *namespace =
        config_getstring(IMAPOPT_OBJECT_STORAGE_DUMMY_SPOOL);

    obj_def.namespace = namespace;
    obj_def.filename = objectstore_get_object_filename(mailbox, record);
    obj_def.user = mboxname_to_userid(mailbox->name);

    return &obj_def;
}

static const char *objectstore_container_path(struct mailbox *mailbox,
                                              const struct index_record *record)
{
    static char path[MAX_MAILBOX_PATH + 1];
    struct object_def *obj_def = NULL;

    obj_def = objectstore_get_object_def(mailbox, record);

    snprintf(path,
             sizeof(path),
             "%s/%s/%c%c",
             obj_def->namespace,
             obj_def->user,
             obj_def->filename[0],
             obj_def->filename[1]);

    return path;
}

static const char *objectstore_filename_in_container_path(
    struct mailbox *mailbox,
    const struct index_record *record)
{
    static char path[MAX_MAILBOX_PATH + 1];
    struct object_def *obj_def = NULL;

    obj_def = objectstore_get_object_def(mailbox, record);

    const char *container_path = objectstore_container_path(mailbox, record);

    snprintf(path, sizeof(path), "%s/%s", container_path, obj_def->filename);

    return path;
}

static int is_directory_empty(char *dir_path)
{
    int n = 0;
    struct dirent *d;
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        return 0;
    }
    while ((d = readdir(dir)) != NULL) {
        if (++n > 2) {
            break;
        }
    }
    closedir(dir);
    if (n <= 2) // The directory is empty
    {
        return 1;
    }
    else {
        return 0;
    }
}

int objectstore_put(struct mailbox *mailbox,
                    const struct index_record *record,
                    const char *fname)
{
    struct object_def *obj_def = NULL;
    int already = 0;
    int rc = 0;

    obj_def = objectstore_get_object_def(mailbox, record);

    struct stat fileStat;
    char path[MAX_MAILBOX_PATH + 1];

    // create user container if not there
    snprintf(path, sizeof(path), "%s/%s", obj_def->namespace, obj_def->user);
    if (stat(path, &fileStat) < 0) {
        if (cyrus_mkdir(path, 755) == -1) {
            syslog(LOG_ERR, "Dummy ObjectStore: Cannot create user %s", path);
            rc = 1;
        }
    }

    // create sub-container if not there
    const char *container_path = objectstore_container_path(mailbox, record);
    snprintf(path, sizeof(path), "%s/", container_path);
    if (stat(path, &fileStat) < 0) {
        if (cyrus_mkdir(path, 755) == -1) {
            syslog(LOG_ERR,
                   "Dummy ObjectStore: Cannot create user sub container %s",
                   path);
            rc = 1;
        }
    }

    add_message_guid(mailbox, record);

    // check is file already exist
    rc = objectstore_is_filename_in_container(mailbox, record, &already);
    if (!already) {
        // copy file
        const char *destfilename =
            objectstore_filename_in_container_path(mailbox, record);
        rc = cyrus_copyfile(fname, destfilename, COPYFILE_NOLINK);
    }
    return rc;
}

int objectstore_get(struct mailbox *mailbox,
                    const struct index_record *record,
                    const char *fname)
{
    int already, rc = 0;

    // check is file already exist
    rc = objectstore_is_filename_in_container(mailbox, record, &already);
    if (already) {
        // copy file
        const char *srcfilename =
            objectstore_filename_in_container_path(mailbox, record);
        rc = cyrus_copyfile(srcfilename, fname, COPYFILE_NOLINK);
    }
    return rc;
}

int objectstore_delete(struct mailbox *mailbox,
                       const struct index_record *record)
{
    static char path[MAX_MAILBOX_PATH + 1];
    int already, rc = 0;

    // check is file already exist
    rc = objectstore_is_filename_in_container(mailbox, record, &already);

    if (already) {
        int count = 0;
        delete_message_guid(mailbox, record, &count);
        if (!count) {
            // delete file
            const char *filename =
                objectstore_filename_in_container_path(mailbox, record);
            rc = remove(filename);

            // remove empty sub-container
            const char *container_path =
                objectstore_container_path(mailbox, record);
            snprintf(path, sizeof(path), "%s/", container_path);

            if (is_directory_empty(path)) {
                remove(path);
            }
        }
    }
    return rc;
}

int objectstore_is_filename_in_container(struct mailbox *mailbox,
                                         const struct index_record *record,
                                         int *isthere)
{
    const char *filename =
        objectstore_filename_in_container_path(mailbox, record);
    int rc = 0;

    struct stat fileStat;
    if (stat(filename, &fileStat) == -1) {
        rc = -1;
    }
    else {
        *isthere = 1;
    }
    return rc;
}
