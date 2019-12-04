/* jmap_backup.c -- Routines for handling JMAP Backup/restoreXxx requests
 *
 * Copyright (c) 1994-2019 Carnegie Mellon University.  All rights reserved.
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <errno.h>

#include "caldav_db.h"
#include "carddav_db.h"
#include "hash.h"
#include "http_jmap.h"
#include "json_support.h"
#include "vcard_support.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int jmap_backup_restore_contacts(jmap_req_t *req);
static int jmap_backup_restore_calendars(jmap_req_t *req);
static int jmap_backup_restore_notes(jmap_req_t *req);
static int jmap_backup_restore_mail(jmap_req_t *req);

jmap_method_t jmap_backup_methods_standard[] = {
    { NULL, NULL, NULL, 0}
};

jmap_method_t jmap_backup_methods_nonstandard[] = {
    {
        "Backup/restoreContacts",
        JMAP_BACKUP_EXTENSION,
        &jmap_backup_restore_contacts,
        /*flags*/0
    },
    {
        "Backup/restoreCalendars",
        JMAP_BACKUP_EXTENSION,
        &jmap_backup_restore_calendars,
        /*flags*/0
    },
    {
        "Backup/restoreNotes",
        JMAP_BACKUP_EXTENSION,
        &jmap_backup_restore_notes,
        /*flags*/0
    },
    {
        "Backup/restoreMail",
        JMAP_BACKUP_EXTENSION,
        &jmap_backup_restore_mail,
        /*flags*/0
    },
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_backup_init(jmap_settings_t *settings)
{
    jmap_method_t *mp;
    for (mp = jmap_backup_methods_standard; mp->name; mp++) {
        hash_insert(mp->name, mp, &settings->methods);
    }

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(settings->server_capabilities,
                            JMAP_BACKUP_EXTENSION, json_object());

        for (mp = jmap_backup_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }

}

HIDDEN void jmap_backup_capabilities(json_t *account_capabilities)
{
    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        json_object_set_new(account_capabilities,
                            JMAP_BACKUP_EXTENSION, json_object());
    }
}

/* Backup/restoreXxx */

#define DESTROYS        0
#define UPDATES         1
#define CREATES         2
#define DRAFT_DESTROYS  1

#define UNDO_DESTROY  (1<<0)
#define UNDO_UPDATE   (1<<1)
#define UNDO_CREATE   (1<<2)

struct jmap_restore {
    /* Request arguments */
    time_t cutoff;
    unsigned is_email : 1;
    unsigned undo     : 3;

    /* Response fields */
    unsigned num_undone[3];
};

static void jmap_restore_parse(jmap_req_t *req,
                               struct jmap_parser *parser,
                               int is_email,
                               struct jmap_restore *restore,
                               json_t **err)
{
    json_t *jargs = req->args;
    const char *key;
    json_t *arg;

    memset(restore, 0, sizeof(struct jmap_restore));

    restore->is_email = is_email;

    json_object_foreach(jargs, key, arg) {
        if (!strcmp(key, "accountId")) {
            /* already handled in jmap_api() */
        }

        else if (!strcmp(key, "undoPeriod") && json_is_string(arg)) {
            struct icaldurationtype dur =
                icaldurationtype_from_string(json_string_value(arg));

            if (!icaldurationtype_is_bad_duration(dur)) {
                restore->cutoff = time(0) - icaldurationtype_as_int(dur);
            }
        }

        else if (!is_email && json_is_boolean(arg)) {
            if (!strcmp(key, "undoCreate")) {
                if (json_is_true(arg)) restore->undo |= UNDO_CREATE;
            }

            else if (!strcmp(key, "undoUpdate")) {
                if (json_is_true(arg)) restore->undo |= UNDO_UPDATE;
            }

            else if (!strcmp(key, "undoDestroy")) {
                if (json_is_true(arg)) restore->undo |= UNDO_DESTROY;
            }

            else {
                jmap_parser_invalid(parser, key);
            }
        }

        else {
            jmap_parser_invalid(parser, key);
        }
    }

    if (!restore->cutoff) {
        jmap_parser_invalid(parser, "undoPeriod");
    }

    if (json_array_size(parser->invalid)) {
        *err = json_pack("{s:s s:O}", "type", "invalidArguments",
                "arguments", parser->invalid);
    }
}

static void jmap_restore_fini(struct jmap_restore *restore __attribute__((unused)))
{
    return;
}

static json_t *jmap_restore_reply(struct jmap_restore *restore)
{
    json_t *res = json_object();

    if (restore->is_email) {
        json_object_set_new(res, "numDraftsRestored",
                            json_integer(restore->num_undone[DRAFT_DESTROYS]));
        json_object_set_new(res, "numNonDraftsRestored",
                            json_integer(restore->num_undone[DESTROYS]));
    }
    else {
        json_object_set_new(res, "numCreatesUndone",
                            json_integer(restore->num_undone[CREATES]));
        json_object_set_new(res, "numUpdatesUndone",
                            json_integer(restore->num_undone[UPDATES]));
        json_object_set_new(res, "numDestroysUndone",
                            json_integer(restore->num_undone[DESTROYS]));
    }

    return res;
}

struct restore_rock {
    jmap_req_t *req;
    struct jmap_restore *jrestore;
    int mbtype;
    char *(*resource_name_cb)(struct mailbox *, message_t *);
    int (*recreate_cb)(struct mailbox *, const struct index_record *,
                       const char *, jmap_req_t *, int);
    int (*destroy_cb)(struct mailbox *, const struct index_record *,
                      jmap_req_t *, int);
    struct mailbox *mailbox;
};

struct restore_info {
    unsigned char type;
    unsigned int msgno_todestroy;
    unsigned int msgno_torecreate;
};

static void restore_resource_cb(const char *resource, void *data, void *rock)
{
    struct restore_info *restore = (struct restore_info *) data;
    struct restore_rock *rrock = (struct restore_rock *) rock;
    struct mailbox *mailbox = rrock->mailbox;
    jmap_req_t *req = rrock->req;
    int r = 0, is_replace = 0;

    switch (restore->type) {
    case UPDATES:
        if (!(rrock->jrestore->undo & UNDO_UPDATE)) goto done;
        is_replace = 1;
        break;

    case DESTROYS:
        if (!(rrock->jrestore->undo & UNDO_DESTROY)) goto done;
        break;

    case CREATES:
        if (!(rrock->jrestore->undo & UNDO_CREATE)) goto done;
        break;

    default:
        goto done;
    }

    if (restore->msgno_torecreate) {
        message_t *msg = message_new_from_mailbox(mailbox,
                                                  restore->msgno_torecreate);

        r = rrock->recreate_cb(mailbox, msg_record(msg),
                               resource, req, is_replace);
        message_unref(&msg);
    }

    if (!r && restore->msgno_todestroy) {
        message_t *msg = message_new_from_mailbox(mailbox,
                                                  restore->msgno_todestroy);

        r = rrock->destroy_cb(mailbox, msg_record(msg), req, is_replace);
        message_unref(&msg);
    }

    if (!r) rrock->jrestore->num_undone[restore->type]++;

  done:
    free(restore);
}

static int restore_collection_cb(const mbentry_t *mbentry, void *rock)
{
    struct restore_rock *rrock = (struct restore_rock *) rock;
    hash_table resources = HASH_TABLE_INITIALIZER;
    struct mailbox *mailbox = NULL;
    message_t *msg = message_new();
    char *resource = NULL;
    int recno, r;

    if ((mbentry->mbtype & rrock->mbtype) != rrock->mbtype) return 0;

    r = jmap_openmbox(rrock->req, mbentry->name, &mailbox, /*rw*/1);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open mailbox %s", mbentry->name);
        return 0;
    }

    construct_hash_table(&resources, 64, 0);

    for (recno = mailbox->i.num_records; recno > 0; recno--) {
        message_set_from_mailbox(mailbox, recno, msg);

        resource = rrock->resource_name_cb(mailbox, msg);
        if (!resource) continue;

        const struct index_record *record = msg_record(msg);
        struct restore_info *restore = NULL;
        if (record->internal_flags & FLAG_INTERNAL_EXPUNGED) {
            /* Tombstone - resource has been destroyed or updated */
            restore = hash_lookup(resource, &resources);

            if ((!restore || !restore->msgno_torecreate) &&
                record->internaldate <= rrock->jrestore->cutoff) {
                /* Most recent version of the resource before cutoff */

                if (!restore &&
                    record->last_updated > rrock->jrestore->cutoff) {
                    /* Resource has been destroyed after cutoff */
                    restore = xzmalloc(sizeof(struct restore_info));
                    hash_insert(resource, restore, &resources);
                    restore->type = DESTROYS;
                }

                if (restore) {
                    /* Recreate this version of the resource */
                    restore->msgno_torecreate = recno;

                    if (restore->type == CREATES) {
                        /* Tombstone is before cutoff so this is an update */
                        restore->type = UPDATES;
                    }
                }
                else {
                    /* Resource was destroyed before cutoff - not interested */
                }
            }
        }
        else if (record->internaldate > rrock->jrestore->cutoff) {
            /* Resource has been created or updated after cutoff - 
               assume its a create unless we find a tombstone before cutoff.
               Either way, we need to destroy this version of the resource */
            restore = xzmalloc(sizeof(struct restore_info));
            hash_insert(resource, restore, &resources);
            restore->type = CREATES;
            restore->msgno_todestroy = recno;
        }
        else {
            /* Resource was not modified after cutoff - not interested */
        }

        free(resource);
    }
    message_unref(&msg);

    rrock->mailbox = mailbox;
    hash_enumerate(&resources, restore_resource_cb, rrock);
    free_hash_table(&resources, NULL);

    jmap_closembox(rrock->req, &mailbox);

    return 0;
}

static char *dav_resource_name(struct mailbox *mailbox, message_t *msg)
{
    const struct index_record *record = msg_record(msg);
    char *resource = NULL;
    struct body *body = NULL;
    struct param *param;
    int r;

    /* XXX  Should we fetch the resource name from the DAV DB instead? */

    /* Get resource from filename param in Content-Disposition header */
    r = mailbox_cacherecord(mailbox, record);
    if (r) return NULL;

    message_read_bodystructure(record, &body);
    for (param = body->disposition_params; param; param = param->next) {
        if (!strcmp(param->attribute, "FILENAME")) {
            resource = xstrdupsafe(param->value);
            break;
        }
    }

    message_free_body(body);
    free(body);

    return resource;
}

static int recreate_vcard(struct mailbox *mailbox,
                          const struct index_record *record,
                          const char *resource, jmap_req_t *req, int is_replace)
{
    struct vparse_card *vcard = record_to_vcard(mailbox, record);
    int r;

    if (!vcard || !vcard->objects) {
        r = IMAP_INTERNAL;
        goto done;
    }

    strarray_t *flags = mailbox_extract_flags(mailbox, record, req->accountid);
    struct entryattlist *annots = mailbox_extract_annots(mailbox, record);

    r = carddav_store(mailbox, vcard->objects, resource,
                      is_replace ? record->createdmodseq : 0, flags, annots,
                      req->accountid, req->authstate, /*ignorequota*/ 0);
    freeentryatts(annots);
    strarray_free(flags);

  done:
    vparse_free_card(vcard);

    return r;
}

static int destroy_vcard(struct mailbox *mailbox,
                         const struct index_record *record,
                         jmap_req_t *req, int is_replace)
{
    return carddav_remove(mailbox, record->uid, is_replace, req->accountid);
}

static int jmap_backup_restore_contacts(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_restore restore;
    json_t *err = NULL;

    /* Parse request */
    jmap_restore_parse(req, &parser, /*is_mail*/ 0, &restore, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    if (restore.undo) {
        char *addrhomeset = carddav_mboxname(req->accountid, NULL);
        struct restore_rock rrock = { req, &restore, MBTYPE_ADDRESSBOOK,
                                      &dav_resource_name, &recreate_vcard,
                                      &destroy_vcard, NULL };

        mboxlist_mboxtree(addrhomeset,
                          restore_collection_cb, &rrock, MBOXTREE_SKIP_ROOT);
        free(addrhomeset);
    }

    /* Build response */
    jmap_ok(req, jmap_restore_reply(&restore));

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}

static int jmap_backup_restore_calendars(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_restore restore;
    json_t *err = NULL;

    /* Parse request */
    jmap_restore_parse(req, &parser, /*is_mail*/ 0, &restore, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    jmap_ok(req, jmap_restore_reply(&restore));

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}

static int jmap_backup_restore_notes(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_restore restore;
    json_t *err = NULL;

    /* Parse request */
    jmap_restore_parse(req, &parser, /*is_mail*/ 0, &restore, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    jmap_ok(req, jmap_restore_reply(&restore));

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}

static int jmap_backup_restore_mail(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_restore restore;
    json_t *err = NULL;

    /* Parse request */
    jmap_restore_parse(req, &parser, /*is_mail*/ 1, &restore, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    /* Build response */
    jmap_ok(req, jmap_restore_reply(&restore));

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}
