/* objectstore_caringo.c */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#include "castor_sdk_c_interface.h"
#include "mailbox.h"
#include "mboxname.h"
#include "libconfig.h"
#include "xmalloc.h"
#include "util.h"
#include "objectstore.h"
#include "objectstore_db.h"


#define HTTP_OK 200
#define HTTP_CREATED 201

struct object_def
{
/* primary */
const char *user;       //  this is the container name.
const char *filename;   //  Name of blob
};


static const char *objectstore_get_object_filename(struct mailbox *mailbox, const struct index_record *record)
{
    return message_guid_encode(&record->guid);
}


static struct object_def *objectstore_get_object_def (struct mailbox *mailbox, const struct index_record *record)
{
    static struct object_def obj_def ;


    obj_def.filename = objectstore_get_object_filename(mailbox, record) ;
    obj_def.user = mboxname_to_userid(mailbox->name) ;

    return &obj_def;
}

static int binit = 0 ;

static int init (void)
{
    if (!binit){
        binit = 1;

        const char   *host_name   = config_getstring(IMAPOPT_CARINGO_HOSTNAME) ;
        unsigned int  port        = config_getint (IMAPOPT_CARINGO_PORT) ;
        unsigned int  retries     = 5 ;
        unsigned int  timeout     = 300 ;
        unsigned int  maxclient   = 1 ;     // only one client per process.
        open_client (host_name, port, retries, timeout, timeout, timeout, maxclient, maxclient);
    }
    return 0;
}

int objectstore_put (struct mailbox *mailbox, const struct index_record *record, const char *fname)
{
    struct object_def *obj_def = NULL;
    int already = 0 ;
    int rc = 0;

    rc = init () ;
    if (rc) return rc;

    obj_def = objectstore_get_object_def (mailbox, record);

    // create user container if not there
    if (info_bucket  (obj_def->user) != HTTP_OK ){
       create_bucket (obj_def->user) ;
    }

    add_message_guid (mailbox, record) ;

  // check is file already exist
    rc = objectstore_is_filename_in_container (mailbox, record, &already);

    if (!already) {
        struct buf buffer = BUF_INITIALIZER ;
        struct stat sbuf;
        int msgfd;

        msgfd = open(fname, O_RDONLY, 0666);
        if (msgfd == -1) {
            syslog(LOG_ERR, "IOERROR: Cannot open %s", fname);
            return msgfd;
        }

        if (fstat(msgfd, &sbuf) == -1) {
            syslog(LOG_ERR, "IOERROR: fstat on %s", fname);
        }

        buf_refresh_mmap(&buffer, /*onceonly*/1, msgfd, fname, sbuf.st_size, mailbox->name);
        close(msgfd);
        rc = write_named_object  (buffer.s, sbuf.st_size, obj_def->user, obj_def->filename) ;
        if (rc == HTTP_CREATED ) {
            syslog(LOG_INFO, "Caringo: file name %s write in bucket %s", fname, obj_def->user  );
            rc = 0;
        } else {
            syslog(LOG_ERR, "Caringo: file name  %s write error: [record:%u] (%d) in bucket %s",
                    fname, record->uid, rc, obj_def->user );
            rc = -1;
        }
        buf_free (&buffer) ;
    }
    return rc;
}

int objectstore_get (struct mailbox *mailbox, const struct index_record *record, const char *fname)
{
    struct object_def *obj_def = NULL;
    int rc = 0;

    rc = init () ;
    if (rc) return rc;

    obj_def = objectstore_get_object_def (mailbox, record);

    int len = info_named_object (obj_def->user, obj_def->filename) ;
    if (len != -1) {
        struct buf buffer = BUF_INITIALIZER ;
        buf_ensure(&buffer, len+1);
        rc = read_named_object (buffer.s, len, obj_def->user, obj_def->filename) ;

        if (rc == HTTP_OK ) {
            syslog(LOG_INFO, "Caringo: file name %s read from bucket %s", fname, obj_def->user  );
            rc = 0;
        } else {
            syslog(LOG_ERR, "Caringo: file name  %s read error: [record:%u] (%d) from bucket %s",
                    fname, record->uid, rc, obj_def->user );
            rc = -1 ;
        }

        if (rc != -1) {
            //write filename
            int fd;
            fd = open(fname, O_CREAT | O_TRUNC | O_RDWR, 0666);
            if (fd == -1) {
                syslog(LOG_ERR, "IOERROR: opening %s: %m", fname);
                rc = -1 ;
            }
            else {
            /* Write the file */
               rc = write(fd, buffer.s, len );
               if ( rc == len ) rc = 0 ;
               else rc = -1;
            }
            buf_free (&buffer) ;
            close (fd) ;
        }
    }
    return rc;
}

int objectstore_delete (struct mailbox *mailbox, const struct index_record *record)
{
    struct object_def *obj_def = NULL;
    int rc = 0;

    rc = init () ;
    if (rc) return rc;

    obj_def = objectstore_get_object_def (mailbox, record);

    int count = 0;
    delete_message_guid (mailbox, record, &count) ;
    if (!count){
        rc = delete_named_object (obj_def->user, obj_def->filename) ;

        if (rc == HTTP_OK ) {
            syslog(LOG_INFO, "Caringo: file name %s deleted from bucket %s", obj_def->filename, obj_def->user  );
            rc = 0;
        } else {
            syslog(LOG_ERR, "Caringo: file name  %s delete error : [record:%u] (%d) from bucket %s",
                    obj_def->filename, record->uid, rc, obj_def->user );
            rc = -1 ;
        }
    }
    return rc;
}

int objectstore_is_filename_in_container (struct mailbox *mailbox, const struct index_record *record, int *isthere)
{
    struct object_def *obj_def = NULL;
    int rc = 0;

    obj_def = objectstore_get_object_def (mailbox, record);

    rc = info_named_object (obj_def->user, obj_def->filename) ;

    if (rc > 0)
    {
        *isthere = 1 ;
        return 0 ;
    }
    return rc ;
}


