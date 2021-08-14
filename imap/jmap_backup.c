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

#include "acl.h"
#include "append.h"
#include "arrayu64.h"
#include "caldav_db.h"
#include "carddav_db.h"
#include "hash.h"
#include "http_caldav_sched.h"
#include "http_jmap.h"
#include "json_support.h"
#include "times.h"
#include "user.h"
#include "vcard_support.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int jmap_backup_restore_contacts(jmap_req_t *req);
static int jmap_backup_restore_calendars(jmap_req_t *req);
static int jmap_backup_restore_notes(jmap_req_t *req);
static int jmap_backup_restore_mail(jmap_req_t *req);

static char *_prodid = NULL;

jmap_method_t jmap_backup_methods_standard[] = {
    { NULL, NULL, NULL, 0}
};

jmap_method_t jmap_backup_methods_nonstandard[] = {
    {
        "Backup/restoreContacts",
        JMAP_BACKUP_EXTENSION,
        &jmap_backup_restore_contacts,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "Backup/restoreCalendars",
        JMAP_BACKUP_EXTENSION,
        &jmap_backup_restore_calendars,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
    },
    {
        "Backup/restoreNotes",
        JMAP_BACKUP_EXTENSION,
        &jmap_backup_restore_notes,
        JMAP_READ_WRITE
    },
    {
        "Backup/restoreMail",
        JMAP_BACKUP_EXTENSION,
        &jmap_backup_restore_mail,
        JMAP_NEED_CSTATE | JMAP_READ_WRITE
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

    /* Initialize PRODID value
     *
     * XXX - OS X 10.11.6 Contacts is not unfolding PRODID lines, so make
     * sure that PRODID never exceeds the 75 octet limit without CRLF */
    struct buf prodidbuf = BUF_INITIALIZER;
    size_t max_len = 68; /* 75 - strlen("PRODID:") */
    buf_printf(&prodidbuf, "-//CyrusIMAP.org//Cyrus %s//EN", CYRUS_VERSION);
    if (buf_len(&prodidbuf) > max_len) {
        buf_truncate(&prodidbuf, max_len - 6);
        buf_appendcstr(&prodidbuf, "..//EN");
    }
    _prodid = buf_release(&prodidbuf);
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


#define DRY_RUN         (1<<0)
#define UNDO_EMAIL      (1<<1)
#define UNDO_DRAFTS     (1<<2)
#define UNDO_NONDRAFTS  (1<<3)
#define UNDO_ALL        (1<<4)

struct jmap_restore {
    /* Request arguments */
    time_t cutoff;
    unsigned mode : 5;

    int log_level;

    /* Response fields */
    unsigned num_undone[3];
};

#define JMAP_RESTORE_INITIALIZER(mode) { 0, mode, LOG_DEBUG, { 0, 0, 0 } }

static void jmap_restore_parse(jmap_req_t *req,
                               struct jmap_parser *parser,
                               struct jmap_restore *restore,
                               json_t **err)
{
    json_t *jargs = req->args;
    const char *key;
    json_t *arg;

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

        else if (!strcmp(key, "performDryRun") && json_is_boolean(arg)) {
            if (json_is_true(arg)) restore->mode |= DRY_RUN;
        }

        else if (!strcmp(key, "verboseLogging") && json_is_boolean(arg)) {
            if (json_is_true(arg)) restore->log_level = LOG_INFO;
        }

        else if (restore->mode & UNDO_EMAIL) {
            if (!strcmp(key, "restoreDrafts") && json_is_boolean(arg)) {
                if (json_is_false(arg)) restore->mode &= ~UNDO_DRAFTS;
            }
            else if (!strcmp(key, "restoreNonDrafts") && json_is_boolean(arg)) {
                if (json_is_false(arg)) restore->mode &= ~UNDO_NONDRAFTS;
            }
            else {
                jmap_parser_invalid(parser, key);
            }
        }

        else if (!strcmp(key, "undoAll") && json_is_boolean(arg)) {
            if (json_is_true(arg)) restore->mode |= UNDO_ALL;
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

    if (restore->mode & DRY_RUN) {
        json_object_set_new(res, "performDryRun", json_true());
    }

    if (restore->mode & UNDO_EMAIL) {
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
    uint32_t mbtype;
    modseq_t deletedmodseq;
    char *(*resource_name_cb)(message_t *, void *);
    int (*restore_cb)(message_t *, message_t *, jmap_req_t *, void *, int);
    void *rock;
    struct mailbox *mailbox;
};

struct restore_info {
    unsigned char type;
    unsigned int msgno_todestroy;
    unsigned int msgno_torecreate;
};

static void restore_resource_cb(const char *resource __attribute__((unused)),
                                void *data, void *rock)
{
    struct restore_info *restore = (struct restore_info *) data;
    struct restore_rock *rrock = (struct restore_rock *) rock;
    int log_level = rrock->jrestore->log_level;
    struct mailbox *mailbox = rrock->mailbox;
    jmap_req_t *req = rrock->req;
    message_t *recreatemsg = NULL;
    message_t *destroymsg = NULL;
    int r = 0;

    switch (restore->type) {
    case DESTROYS:
        syslog(log_level, "undo destroy %s", resource);
        break;

    case UPDATES:
        if (!(rrock->jrestore->mode & UNDO_ALL)) goto done;

        syslog(log_level, "undo update %s", resource);
        break;

    case CREATES:
        if (!(rrock->jrestore->mode & UNDO_ALL)) goto done;

        syslog(log_level, "undo create %s", resource);
        break;

    default:
        goto done;
    }

    if (restore->msgno_torecreate) {
        recreatemsg = message_new_from_mailbox(mailbox, restore->msgno_torecreate);
    }

    if (restore->msgno_todestroy) {
        destroymsg = message_new_from_mailbox(mailbox, restore->msgno_todestroy);
    }

    if (!(rrock->jrestore->mode & DRY_RUN))
        r = rrock->restore_cb(recreatemsg, destroymsg, req, rrock->rock, log_level);

    message_unref(&recreatemsg);
    message_unref(&destroymsg);

    if (!r) rrock->jrestore->num_undone[restore->type]++;

  done:
    free(restore);
}

static int restore_collection_cb(const mbentry_t *mbentry, void *rock)
{
    struct restore_rock *rrock = (struct restore_rock *) rock;
    int log_level = rrock->jrestore->log_level;
    hash_table resources = HASH_TABLE_INITIALIZER;
    struct mailbox *mailbox = NULL;
    char *resource = NULL;
    int recno, r;

    syslog(log_level, "restore_collection_cb: processing '%s'  (type = 0x%03x)",
           mbentry->name, mbentry->mbtype);

    if (mbtype_isa(mbentry->mbtype) != rrock->mbtype) {
        syslog(log_level, "skipping '%s': not type 0x%03x",
               mbentry->name, rrock->mbtype);

        return 0;
    }

    r = jmap_openmbox(rrock->req, mbentry->name, &mailbox, /*rw*/1);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open mailbox %s", mbentry->name);
        return r;
    }

    if ((rrock->jrestore->mode & UNDO_ALL) &&
        rrock->jrestore->cutoff < mailbox->i.changes_epoch) {
        syslog(log_level,
               "skipping '%s': cutoff (%ld) prior to mailbox history (%ld)",
               mailbox_name(mailbox), rrock->jrestore->cutoff, mailbox->i.changes_epoch);

        jmap_closembox(rrock->req, &mailbox);
        return HTTP_UNPROCESSABLE;
    }

    construct_hash_table(&resources, 64, 0);

    message_t *msg = message_new();
    for (recno = mailbox->i.num_records; recno > 0; recno--) {
        message_set_from_mailbox(mailbox, recno, msg);

        const struct index_record *record = msg_record(msg);

        resource = rrock->resource_name_cb(msg, rrock->rock);
        syslog(log_level,
               "UID %u: expunged: %x, savedate: %ld, updated: %ld, name: %s",
               record->uid, (record->internal_flags & FLAG_INTERNAL_EXPUNGED),
               record->savedate, record->last_updated,
               resource ? resource : "NULL");

        if (!resource) {
            syslog(log_level, "skipping UID %u: no resource name",
                   record->uid);
            continue;
        }

        struct restore_info *restore = NULL;
        if (record->internal_flags & FLAG_INTERNAL_EXPUNGED) {
            /* Tombstone - resource has been destroyed or updated */
            restore = hash_lookup(resource, &resources);

            if (restore && restore->msgno_torecreate) {
                syslog(log_level, "skipping UID %u: found a newer version",
                       record->uid);

                free(resource);
                continue;
            }

            if (record->savedate > rrock->jrestore->cutoff &&
                (rrock->jrestore->mode & UNDO_ALL)) {
                syslog(log_level, "skipping UID %u: created AND deleted",
                       record->uid);

                free(resource);
                continue;
            }

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

                    syslog(log_level, "UID %u: updated after cutoff",
                           record->uid);
                }
                else {
                    syslog(log_level, "UID %u: destroyed after cutoff",
                           record->uid);
                }
            }
            else {
                /* Resource was destroyed before cutoff - not interested */
                syslog(log_level, "skipping UID %u: destroyed before cutoff",
                       record->uid);
            }
        }
        else if (record->savedate > rrock->jrestore->cutoff) {
            /* Resource has been created or updated after cutoff - 
               assume its a create unless we find a tombstone before cutoff.
               Either way, we need to destroy this version of the resource */
            restore = xzmalloc(sizeof(struct restore_info));
            hash_insert(resource, restore, &resources);
            restore->type = CREATES;
            restore->msgno_todestroy = recno;

            syslog(log_level, "UID %u: created/updated after cutoff",
                   record->uid);
        }
        else {
            /* Resource was not modified after cutoff - not interested */
            syslog(log_level, "skipping UID %u: not modified after cutoff",
                   record->uid);
        }

        free(resource);
    }
    message_unref(&msg);

    rrock->mailbox = mailbox;
    hash_enumerate(&resources, restore_resource_cb, rrock);
    free_hash_table(&resources, NULL);

    /* Update deletedmodseq for this collection type */
    if (mailbox->i.deletedmodseq > rrock->deletedmodseq)
        rrock->deletedmodseq = mailbox->i.deletedmodseq;

    jmap_closembox(rrock->req, &mailbox);

    return 0;
}

static int recreate_resource(message_t *msg, struct mailbox *tomailbox,
                             jmap_req_t *req, int is_update, int log_level)
{
    struct mailbox *mailbox = msg_mailbox(msg);
    const struct index_record *record = msg_record(msg);
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    struct stagemsg *stage = NULL;
    struct appendstate as;
    const char *fname;
    FILE *f = NULL;
    int r;

    if (!tomailbox) tomailbox = mailbox;

    syslog(log_level, "recreating UID: %u (%s); is_update: %d",
           record->uid, mailbox_name(tomailbox), is_update);

    /* use latest version of the resource as the source for our append stage */
    r = message_get_fname(msg, &fname);
    if (r) return r;

    f = append_newstage_full(mailbox_name(tomailbox), time(0), 0, &stage, fname);
    if (!f) return IMAP_INTERNAL;
    fclose(f);

    /* setup for appending the message to the mailbox. */
    qdiffs[QUOTA_MESSAGE] = 1;
    qdiffs[QUOTA_STORAGE] = msg_size(msg);
    r = append_setup_mbox(&as, tomailbox, req->accountid, req->authstate,
                          JACL_ADDITEMS, qdiffs, NULL, 0, EVENT_MESSAGE_NEW);
    if (!r) {
        /* get existing flags and annotations */
        strarray_t *flags = mailbox_extract_flags(mailbox, record, req->accountid);
        struct entryattlist *annots = mailbox_extract_annots(mailbox, record);
        struct body *body = NULL;

        /* mark as undeleted */
        strarray_remove_all_case(flags, "\\Deleted");
        strarray_remove_all_case(flags, DFLAG_UNBIND);

        /* mark as $restored */ 
        strarray_add(flags, "$restored");

        /* append the message to the mailbox. */
        r = append_fromstage(&as, &body, stage, record->internaldate,
                             is_update ? record->createdmodseq : 0,
                             flags, /*nolink*/0, &annots);

        freeentryatts(annots);
        strarray_free(flags);
        message_free_body(body);
        free(body);

        if (r) append_abort(&as);
        else {
            /* If this resource was previously destroyed
               (not replaced by an update) we need to bump the deletedmodseq
               since we will no longer be able to differentiate between
               whether this resource has just been created or updated */
            if (!is_update && record->modseq > tomailbox->i.deletedmodseq) {
                tomailbox->i.deletedmodseq = record->modseq;
                mailbox_index_dirty(tomailbox);
            }
            r = append_commit(&as);
        }
    }
    append_removestage(stage);

    return r;
}

static int destroy_resource(message_t *msg, jmap_req_t *req,
                            int is_replaced, int log_level)
{
    struct mailbox *mailbox = msg_mailbox(msg);
    const struct index_record *record = msg_record(msg);
    struct index_record newrecord;
    int r = 0;

    syslog(log_level,
           "destroying UID: %u; is_replaced: %d", record->uid, is_replaced);

    /* copy the existing index_record */
    memcpy(&newrecord, record, sizeof(struct index_record));

    if (is_replaced) {
        int userflag;
        r = mailbox_user_flag(mailbox, DFLAG_UNBIND, &userflag, 1);
        newrecord.user_flags[userflag/32] |= 1<<(userflag&31);
    }

    if (!r) {
        /* mark expunged */
        newrecord.internal_flags |= FLAG_INTERNAL_EXPUNGED;

        /* store back to the mailbox */
        r = mailbox_rewrite_index_record(mailbox, &newrecord);
    }

    if (!r) {
        /* report mailbox event */
        struct mboxevent *mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);
        mboxevent_extract_record(mboxevent, mailbox, &newrecord);
        mboxevent_extract_mailbox(mboxevent, mailbox);
        mboxevent_set_numunseen(mboxevent, mailbox, -1);
        mboxevent_set_access(mboxevent, NULL, NULL,
                             req->accountid, mailbox_name(mailbox), 0);
        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);
    }

    return r;
}

static char *dav_resource_name(message_t *msg)
{
    const struct index_record *record = msg_record(msg);
    char *resource = NULL;
    struct body *body = NULL;
    struct param *param;
    int r;

    /* Get resource from filename param in Content-Disposition header */
    r = mailbox_cacherecord(msg_mailbox(msg), record);
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

struct contact_rock {
    /* global */
    struct carddav_db *carddavdb;
    struct buf buf;

    /* per-addressbook */
    struct vparse_card *group_vcard;
};

static char *contact_resource_name(message_t *msg, void *rock)
{
    struct mailbox *mailbox = msg_mailbox(msg);
    const struct index_record *record = msg_record(msg);
    const mbentry_t mbentry = { .name = (char *)mailbox_name(mailbox),
                                .uniqueid = (char *)mailbox_uniqueid(mailbox) };
    struct contact_rock *crock = (struct contact_rock *) rock;
    struct carddav_data *cdata = NULL;
    char *resource = NULL;

    /* Get resource from CardDAV DB, if possible */
    int r = carddav_lookup_imapuid(crock->carddavdb, &mbentry,
                                   record->uid, &cdata, /*tombstones*/ 1);
    if (!r) {
        resource = xstrdup(cdata->dav.resource);
    }
    else {
        /* IMAP UID is for a resource that has been updated,
           so we need to get the resource name from the resource itself */
        resource = dav_resource_name(msg);
    }

    return resource;
}

struct group_rock {
    const char *name;
    unsigned num;
};

static int _group_name_cb(void *rock, struct carddav_data *cdata)
{
    struct group_rock *grock = (struct group_rock *) rock;
    size_t len = strlen(grock->name);

    if (!cdata->dav.alive || !cdata->dav.rowid || !cdata->dav.imap_uid) {
        return 0;
    }

    /* Ignore non-groups */
    if (cdata->kind != CARDDAV_KIND_GROUP) {
        return 0;
    }

    if (!strncmp(cdata->fullname, grock->name, len)) {
        sscanf(cdata->fullname+len, " (%u)", &grock->num);
        return CYRUSDB_DONE;
    }

    return 0;
}

static int restore_contact(message_t *recreatemsg, message_t *destroymsg,
                           jmap_req_t *req, void *rock, int log_level)
{
    int is_update = recreatemsg && destroymsg;
    int r = 0;

    if (recreatemsg) {
        r = recreate_resource(recreatemsg, NULL, req, is_update, log_level);

        if (!r && !is_update) {
            /* Add this card to the group vCard of recreated contacts */
            struct mailbox *mailbox = msg_mailbox(recreatemsg);
            const struct index_record *record = msg_record(recreatemsg);
            const mbentry_t mbentry = { .name = (char *)mailbox_name(mailbox),
                                        .uniqueid = (char *)mailbox_uniqueid(mailbox) };
            struct contact_rock *crock = (struct contact_rock *) rock;
            struct vparse_card *vcard = record_to_vcard(mailbox, record);

            if (!vcard || !vcard->objects) {
                r = IMAP_INTERNAL;
            }
            else {
                if (!crock->group_vcard) {
                    /* Create the group vCard */
                    char datestr[RFC3339_DATETIME_MAX];
                    struct vparse_card *gcard = vparse_new_card("VCARD");

                    time_to_rfc3339(time(0), datestr, RFC3339_DATETIME_MAX);
                    buf_reset(&crock->buf);
                    buf_printf(&crock->buf, "Restored %.10s", datestr);

                    /* Look for existing group vCard with same date prefix */
                    struct group_rock grock = { buf_cstring(&crock->buf), 0 };
                    enum carddav_sort sort = CARD_SORT_FULLNAME | CARD_SORT_DESC;
                    if (carddav_foreach_sort(crock->carddavdb, &mbentry,
                                             &sort, 1, _group_name_cb, &grock)) {
                        buf_printf(&crock->buf, " (%u)", grock.num+1);
                    }

                    vparse_add_entry(gcard, NULL, "PRODID", _prodid);
                    vparse_add_entry(gcard, NULL, "VERSION", "3.0");
                    vparse_add_entry(gcard, NULL, "UID", makeuuid());
                    vparse_add_entry(gcard, NULL,
                                     "FN", buf_cstring(&crock->buf));
                    vparse_add_entry(gcard, NULL,
                                     "X-ADDRESSBOOKSERVER-KIND", "group");
                    crock->group_vcard = gcard;
                }

                /* Add the recreated contact as a member of the group */
                buf_reset(&crock->buf);
                buf_printf(&crock->buf, "urn:uuid:%s",
                           vparse_stringval(vcard->objects, "uid"));
                vparse_add_entry(crock->group_vcard, NULL,
                                 "X-ADDRESSBOOKSERVER-MEMBER",
                                 buf_cstring(&crock->buf));
            }

            vparse_free_card(vcard);
        }
    }

    if (!r && destroymsg) {
        r = destroy_resource(destroymsg, req, is_update, log_level);
    }

    return r;
}

static int restore_addressbook_cb(const mbentry_t *mbentry, void *rock)
{
    struct restore_rock *rrock = (struct restore_rock *) rock;
    struct contact_rock *crock = (struct contact_rock *) rrock->rock;
    struct mailbox *mailbox = NULL;
    int r;

    if (mbtype_isa(mbentry->mbtype) != rrock->mbtype) return 0;

    /* Open mailbox here since we need it later and it gets referenced counted */
    r = jmap_openmbox(rrock->req, mbentry->name, &mailbox, /*rw*/1);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open mailbox %s", mbentry->name);
        return r;
    }

    /* Do usual processing of the collection */
    r = restore_collection_cb(mbentry, rock);

    if (!r && crock->group_vcard) {
        /* Store the group vCard of recreated contacts */
        r = carddav_store(mailbox, crock->group_vcard, NULL, 0, NULL, NULL, 
                          rrock->req->accountid, rrock->req->authstate,
                          /*ignorequota*/ 0);
    }
    vparse_free_card(crock->group_vcard);
    crock->group_vcard = NULL;

    jmap_closembox(rrock->req, &mailbox);

    return r;
}

static int jmap_backup_restore_contacts(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_restore restore = JMAP_RESTORE_INITIALIZER(0);
    json_t *err = NULL;
    int r;

    /* Parse request */
    jmap_restore_parse(req, &parser, &restore, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    char *addrhomeset = carddav_mboxname(req->accountid, NULL);

    syslog(restore.log_level, "jmap_backup_restore_contacts(%s, %ld)",
           addrhomeset, restore.cutoff);

    struct contact_rock crock =
        { carddav_open_userid(req->accountid), BUF_INITIALIZER, NULL };
    struct restore_rock rrock = { req, &restore, MBTYPE_ADDRESSBOOK, 0,
                                  &contact_resource_name, &restore_contact,
                                  &crock, NULL };

    if (restore.mode & DRY_RUN) {
        /* Treat as regular collection since we won't create group vCard */
        r = mboxlist_mboxtree(addrhomeset, restore_collection_cb,
                              &rrock, MBOXTREE_SKIP_ROOT);
    }
    else {
        r = mboxlist_mboxtree(addrhomeset, restore_addressbook_cb,
                              &rrock, MBOXTREE_SKIP_ROOT);
        if (!r) mboxname_setmodseq(addrhomeset, rrock.deletedmodseq,
                                   MBTYPE_ADDRESSBOOK, MBOXMODSEQ_ISDELETE);
    }
    free(addrhomeset);
    carddav_close(crock.carddavdb);
    buf_free(&crock.buf);

    /* Build response */
    if (r) {
        jmap_error(req, (r == HTTP_UNPROCESSABLE) ? 
                   json_pack("{s:s}", "type", "cannotCalculateChanges") : 
                   jmap_server_error(r));
    }
    else {
        jmap_ok(req, jmap_restore_reply(&restore));
    }

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}

struct calendar_rock {
    struct caldav_db *caldavdb;
    char *inboxname;
    char *outboxname;
};

static char *ical_resource_name(message_t *msg, void *rock)
{
    struct mailbox *mailbox = msg_mailbox(msg);
    const struct index_record *record = msg_record(msg);
    const mbentry_t mbentry = { .name = (char *)mailbox_name(mailbox),
                                .uniqueid = (char *)mailbox_uniqueid(mailbox) };
    struct calendar_rock *crock = (struct calendar_rock *) rock;
    struct caldav_data *cdata = NULL;
    char *resource = NULL;

    /* Get resource from CalDAV DB, if possible */
    int r = caldav_lookup_imapuid(crock->caldavdb, &mbentry,
                                  record->uid, &cdata, /*tombstones*/ 1);
    if (!r) {
        resource = xstrdup(cdata->dav.resource);
    }
    else {
        /* IMAP UID is for a resource that has been updated,
           so we need to get the resource name from the resource itself */
        resource = dav_resource_name(msg);
    }

    return resource;
}

static int do_scheduling(jmap_req_t *req,
                         const char *mboxname, const char *organizer,
                         strarray_t *schedule_addresses,
                         icalcomponent *oldical, icalcomponent *ical,
                         int is_destroy)
{
    icalcomponent *src = is_destroy ? oldical : ical;
    icalcomponent *comp = icalcomponent_get_first_real_component(src);

    /* XXX Hack for Outlook */
    if (!icalcomponent_get_first_invitee(comp)) return 0;

    get_schedule_addresses(req->txn->req_hdrs, mboxname,
                           req->userid, schedule_addresses);

    if (strarray_find_case(schedule_addresses, organizer, 0) >= 0) {
        /* Organizer scheduling object resource */
        sched_request(req->userid, schedule_addresses, organizer, oldical, ical);
    } else {
        /* Attendee scheduling object resource */
        int omit_reply = 0;

        if (oldical && is_destroy) {
            icalproperty *prop;

            for (prop = icalcomponent_get_first_property(comp,
                                                         ICAL_ATTENDEE_PROPERTY);
                 prop;
                 prop = icalcomponent_get_next_property(comp,
                                                        ICAL_ATTENDEE_PROPERTY)) {
                const char *addr = icalproperty_get_attendee(prop);

                if (!addr || strncasecmp(addr, "mailto:", 7) ||
                    strcasecmp(strarray_nth(schedule_addresses, 0), addr+7)) {
                    continue;
                }

                icalparameter *param =
                    icalproperty_get_first_parameter(prop,
                                                     ICAL_PARTSTAT_PARAMETER);
                omit_reply = !param ||
                    icalparameter_get_partstat(param) == ICAL_PARTSTAT_NEEDSACTION;
                break;
            }
        }

        if (!omit_reply && strarray_size(schedule_addresses))
            sched_reply(req->userid, schedule_addresses, oldical, ical);
    }

    return 0;
}

static int recreate_ical(message_t *recreatemsg, message_t *destroymsg,
                         jmap_req_t *req, struct caldav_db *caldavdb, int log_level)
{
    struct mailbox *mailbox = msg_mailbox(recreatemsg);
    const struct index_record *record = msg_record(recreatemsg);
    const struct index_record *oldrecord =
        destroymsg ? msg_record(destroymsg) : NULL;
    const mbentry_t mbentry = { .name = (char *)mailbox_name(mailbox),
                                .uniqueid = (char *)mailbox_uniqueid(mailbox) };
    struct caldav_data *cdata = NULL;
    int r;

    r = caldav_lookup_imapuid(caldavdb, &mbentry,
                              oldrecord ? oldrecord->uid : record->uid,
                              &cdata, /*tombstones*/ 1);
    if (r) return r;

    if (cdata->organizer) {
        /* Send scheduling message */
        strarray_t schedule_addresses = STRARRAY_INITIALIZER;
        icalcomponent *ical =
            record_to_ical(mailbox, record, &schedule_addresses);
        icalcomponent *oldical = NULL;

        if (oldrecord) {
            oldical = record_to_ical(mailbox, oldrecord, NULL);

            /* Need to bump SEQUENCE number for an update */
            int sequence = icalcomponent_get_sequence(oldical);
            icalcomponent *comp = icalcomponent_get_first_real_component(ical);
            icalcomponent_set_sequence(comp, ++sequence);
        }

        r = do_scheduling(req, mailbox_name(mailbox), cdata->organizer,
                          &schedule_addresses, oldical, ical, /*is_destroy*/0);

        if (!r) {
            /* Rewrite updated resource */
            const mbentry_t mbentry = { .name = (char *)mailbox_name(mailbox),
                                        .uniqueid = (char *)mailbox_uniqueid(mailbox) };
            struct transaction_t txn;

            memset(&txn, 0, sizeof(struct transaction_t));
            txn.req_hdrs = spool_new_hdrcache();
            txn.req_tgt.mbentry = (mbentry_t *) &mbentry;

            r = caldav_store_resource(&txn, ical, mailbox,
                                      cdata->dav.resource, record->createdmodseq,
                                      caldavdb, NEW_STAG,
                                      req->userid, &schedule_addresses);
            if (r == HTTP_CREATED || r == HTTP_NO_CONTENT) r = 0;

            spool_free_hdrcache(txn.req_hdrs);
            buf_free(&txn.buf);
        }

        if (oldical) icalcomponent_free(oldical);
        icalcomponent_free(ical);
        strarray_fini(&schedule_addresses);
    }
    else {
        /* No scheduling - simple recreation will do */
        r = recreate_resource(recreatemsg, NULL, req, destroymsg != NULL, log_level);
    }

    return r;
}

static int destroy_ical(message_t *destroymsg, jmap_req_t *req,
                        int is_replaced, struct caldav_db *caldavdb, int log_level)
{
    int r = 0;

    if (!is_replaced) {
        struct mailbox *mailbox = msg_mailbox(destroymsg);
        const struct index_record *record = msg_record(destroymsg);
        const mbentry_t mbentry = { .name = (char *)mailbox_name(mailbox),
                                    .uniqueid = (char *)mailbox_uniqueid(mailbox) };
        struct caldav_data *cdata = NULL;

        r = caldav_lookup_imapuid(caldavdb, &mbentry,
                                  record->uid, &cdata, /*tombstones*/ 0);

        if (!r && cdata->organizer) {
            /* Send scheduling message */
            strarray_t schedule_addresses = STRARRAY_INITIALIZER;
            icalcomponent *ical =
                record_to_ical(mailbox, record, &schedule_addresses);

            r = do_scheduling(req, mailbox_name(mailbox), cdata->organizer,
                              &schedule_addresses, ical, NULL, /*is_destroy*/1);

            icalcomponent_free(ical);
            strarray_fini(&schedule_addresses);
        }
    }

    if (!r) r = destroy_resource(destroymsg, req, is_replaced, log_level);

    return r;
}

static int restore_ical(message_t *recreatemsg, message_t *destroymsg,
                        jmap_req_t *req, void *rock, int log_level)
{
    struct calendar_rock *crock = (struct calendar_rock *) rock;
    int is_update = recreatemsg && destroymsg;
    int r = 0;

    if (recreatemsg) {
        r = recreate_ical(recreatemsg, destroymsg, req, crock->caldavdb, log_level);
    }

    if (!r && destroymsg) {
        r = destroy_ical(destroymsg, req, is_update, crock->caldavdb, log_level);
    }

    return r;
}

struct cal_dispname_rock {
    const char *dispname;
    char *mboxname;
};

static int lookup_cal_by_dispname(const char *mailbox,
                                  uint32_t uid __attribute__((unused)),
                                  const char *entry __attribute__((unused)),
                                  const char *userid __attribute__((unused)),
                                  const struct buf *attrib,
                                  const struct annotate_metadata *mdata __attribute__((unused)),
                                  void *rock)
{
    struct cal_dispname_rock *crock = (struct cal_dispname_rock *) rock;

    if (!strcmp(buf_cstring(attrib), crock->dispname)) {
        crock->mboxname = xstrdup(mailbox);
        return CYRUSDB_DONE;
    }

    return 0;
}

static int recreate_calendar(const mbentry_t *mbentry,
                             struct restore_rock *rrock,
                             struct mailbox **newmailbox)
{
    jmap_req_t *req = rrock->req;
    const char *disp_annot = DAV_ANNOT_NS "<" XML_NS_DAV ">displayname";
    struct buf annot = BUF_INITIALIZER;
    int r = 0;

    /* Lookup DAV:displayname */
    annotatemore_lookupmask(mbentry->name, disp_annot, req->accountid, &annot);

    if (buf_len(&annot)) {
        /* Look for existing calendar with same displayname */
        struct cal_dispname_rock crock = { buf_cstring(&annot), NULL };
        mbname_t *mbname = mbname_from_intname(mbentry->name);

        mbname_set_isdeleted(mbname, 0);
        free(mbname_pop_boxes(mbname));
        mbname_push_boxes(mbname, "%");
        annotatemore_findall_pattern(mbname_intname(mbname), 0/*uid*/,
                                     disp_annot, 0/*since_modseq*/,
                                     &lookup_cal_by_dispname, &crock, 0/*flags*/);
        mbname_free(&mbname);

        if (crock.mboxname) {
            /* Open existing calendar */
            r = mailbox_open_iwl(crock.mboxname, newmailbox);

            if (r) {
                syslog(LOG_ERR,
                       "IOERROR: failed to open mailbox %s", crock.mboxname);
            }
            free(crock.mboxname);
        }
    }

    if (!r && !*newmailbox) {
        /* Create the calendar */
        char *newmboxname = caldav_mboxname(req->accountid, makeuuid());
        struct mboxlock *namespacelock = user_namespacelock(req->accountid);
        mbentry_t newmbentry = MBENTRY_INITIALIZER;
        newmbentry.name = newmboxname;
        newmbentry.mbtype = MBTYPE_CALENDAR;

        r = mboxlist_createmailbox(&newmbentry, 0/*options*/, 0/*highestmodseq*/,
                                   0/*isadmin*/, req->accountid, req->authstate,
                                   0/*flags*/, newmailbox);
        mboxname_release(&namespacelock);

        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to create mailbox %s: %s",
                   newmboxname, error_message(r));
        }
        else {
            /* Set the displayname */
            annotate_state_t *astate = NULL;

            astate = annotate_state_new();
            r = annotate_state_set_mailbox(astate, *newmailbox);
            if (!r) {
                r = annotate_state_writemask(astate, disp_annot,
                                             req->accountid, &annot);
                if (!r) {
                    /* Lookup APPLE:color */
                    const char *color_annot =
                        DAV_ANNOT_NS "<" XML_NS_APPLE ">calendar-color";

                    buf_reset(&annot);
                    annotatemore_lookupmask(mbentry->name, color_annot,
                                            req->accountid, &annot);
                    if (buf_len(&annot)) {
                        r = annotate_state_writemask(astate, color_annot,
                                                     req->accountid, &annot);
                    }
                }

                if (!r)
                    r = annotate_state_commit(&astate);
                else {
                    syslog(LOG_ERR,
                           "IOERROR: failed to create displayname/color"
                           " for mailbox %s: %s",
                           newmboxname, error_message(r));
                    annotate_state_abort(&astate);
                }
            }
        }
        free(newmboxname);
    }

    buf_free(&annot);

    return r;
}

static int recreate_ical_resources(const mbentry_t *mbentry,
                                   struct restore_rock *rrock,
                                   struct mailbox *newmailbox,
                                   int log_level)
{
    struct mailbox *mailbox = NULL;
    jmap_req_t *req = rrock->req;
    int r;

    r = jmap_openmbox(req, mbentry->name, &mailbox, /*rw*/1);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open mailbox %s", mbentry->name);
        return r;
    }

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, 0);
    const message_t *msg;

    while ((msg = mailbox_iter_step(iter))) {
        /* XXX  Look for existing resource with same UID */

        if (!(rrock->jrestore->mode & DRY_RUN)) {
            r = recreate_resource((message_t *) msg, newmailbox,
                                  req, 0/*is_update*/, log_level);
        }
        if (!r) rrock->jrestore->num_undone[DESTROYS]++;
    }
    mailbox_iter_done(&iter);

    jmap_closembox(req, &mailbox);

    return 0;
}

static int restore_calendar_cb(const mbentry_t *mbentry, void *rock)
{
    struct restore_rock *rrock = (struct restore_rock *) rock;
    struct calendar_rock *crock = (struct calendar_rock *) rrock->rock;
    int log_level = rrock->jrestore->log_level;
    jmap_req_t *req = rrock->req;
    time_t timestamp = 0;
    int r = 0;

    if (mbtype_isa(mbentry->mbtype) != rrock->mbtype) return 0;
    if (!jmap_hasrights_mbentry(rrock->req, mbentry, JACL_ADDITEMS)) return 0;

    if (!strcmp(mbentry->name, crock->inboxname) ||
        !strcmp(mbentry->name, crock->outboxname)) {
        /* Ignore scheduling Inbox and Outbox */
        return 0;
    }

    if (mboxname_isdeletedmailbox(mbentry->name, &timestamp)) {
        if (timestamp > rrock->jrestore->cutoff) {
            /* Calendar was destroyed after cutoff -
               restore calendar and resources */
            struct mailbox *newmailbox = NULL;

            if (!(rrock->jrestore->mode & DRY_RUN)) {
                r = recreate_calendar(mbentry, rrock, &newmailbox);
            }

            if (!r) {
                r = recreate_ical_resources(mbentry, rrock, newmailbox, log_level);
                mailbox_close(&newmailbox);
            }

            if (!r && !(rrock->jrestore->mode & DRY_RUN)) {
                /* XXX  Do we want to do this? */
                r = mboxlist_deletemailboxlock(mbentry->name, /*isadmin*/0,
                                               req->accountid, req->authstate,
                                               /*mboxevent*/NULL, /*flags*/0);
            }
        }
        else {
            /* Calendar was destroyed before cutoff - not interested */
        }
    }
    else {
        /* Do usual processing of the collection */
        r = restore_collection_cb(mbentry, rock);
    }

    return r;
}

static int jmap_backup_restore_calendars(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_restore restore = JMAP_RESTORE_INITIALIZER(0);
    json_t *err = NULL;
    int r;

    /* Parse request */
    jmap_restore_parse(req, &parser, &restore, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    char *calhomeset = caldav_mboxname(req->accountid, NULL);

    syslog(restore.log_level, "jmap_backup_restore_calendars(%s, %ld)",
           calhomeset, restore.cutoff);

    struct calendar_rock crock =
        { caldav_open_userid(req->accountid),
          caldav_mboxname(req->accountid, SCHED_INBOX),
          caldav_mboxname(req->accountid, SCHED_OUTBOX) };
    struct restore_rock rrock = { req, &restore, MBTYPE_CALENDAR, 0,
                                  &ical_resource_name, &restore_ical,
                                  &crock, NULL };

    r = mboxlist_mboxtree(calhomeset, restore_calendar_cb, &rrock,
                          MBOXTREE_SKIP_ROOT | MBOXTREE_DELETED);
    if (!(r || (restore.mode & DRY_RUN))) {
        mboxname_setmodseq(calhomeset, rrock.deletedmodseq,
                           MBTYPE_CALENDAR, MBOXMODSEQ_ISDELETE);
    }
    free(calhomeset);
    free(crock.inboxname);
    free(crock.outboxname);
    caldav_close(crock.caldavdb);

    /* Build response */
    if (r) {
        jmap_error(req, (r == HTTP_UNPROCESSABLE) ? 
                   json_pack("{s:s}", "type", "cannotCalculateChanges") : 
                   jmap_server_error(r));
    }
    else {
        jmap_ok(req, jmap_restore_reply(&restore));
    }

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}

static char *note_resource_name(message_t *msg,
                                void *rock __attribute__((unused)))
{
    struct buf buf = BUF_INITIALIZER;
    int r;

    r = message_get_field(msg, "X-Uniform-Type-Identifier",
                          MESSAGE_DECODED|MESSAGE_TRIM, &buf);
    if  (!r && !strcmp(buf_cstring(&buf), "com.apple.mail-note")) {
        r = message_get_field(msg, "X-Universally-Unique-Identifier",
                              MESSAGE_DECODED|MESSAGE_TRIM, &buf);
        return buf_release(&buf);
    }
    buf_free(&buf);

    return NULL;
}

static int restore_note(message_t *recreatemsg, message_t *destroymsg,
                        jmap_req_t *req, void *rock __attribute__((unused)),
                        int log_level)
{
    int is_update = recreatemsg && destroymsg;
    int r = 0;

    if (recreatemsg) {
        r = recreate_resource(recreatemsg, NULL, req, is_update, log_level);
    }

    if (!r && destroymsg) {
        r = destroy_resource(destroymsg, req, is_update, log_level);
    }

    return r;
}

static int jmap_backup_restore_notes(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_restore restore = JMAP_RESTORE_INITIALIZER(0);
    json_t *err = NULL;
    int r = 0;

    /* Parse request */
    jmap_restore_parse(req, &parser, &restore, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    const char *subfolder = config_getstring(IMAPOPT_NOTESMAILBOX);

    syslog(restore.log_level, "jmap_backup_restore_notes(%s, %ld)",
           subfolder ? subfolder : "NULL", restore.cutoff);

    if (subfolder) {
        char *notes = mboxname_user_mbox(req->accountid, subfolder);
        struct restore_rock rrock = { req, &restore, MBTYPE_EMAIL, 0,
                                      &note_resource_name, &restore_note,
                                      NULL, NULL };

        r = mboxlist_mboxtree(notes, restore_collection_cb,
                              &rrock, MBOXTREE_SKIP_CHILDREN);
        if (!(r || (restore.mode & DRY_RUN))) {
            mboxname_setmodseq(notes, rrock.deletedmodseq,
                               MBTYPE_EMAIL, MBOXMODSEQ_ISDELETE);
        }
        free(notes);
    }

    /* Build response */
    if (r) {
        jmap_error(req, (r == HTTP_UNPROCESSABLE) ? 
                   json_pack("{s:s}", "type", "cannotCalculateChanges") : 
                   jmap_server_error(r));
    }
    else {
        jmap_ok(req, jmap_restore_reply(&restore));
    }

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}

struct mail_rock {
    hash_table *emailids;
    hash_table *msgids;
    hash_table *mailboxes;
    struct buf buf;
};

struct removed_mail {
    char *mboxname;
    char *guid;
    time_t removed;
    uint32_t msgno;
    uint32_t size;
};

struct message_t {
    ptrarray_t deleted;
    unsigned ignore : 1;
};

static void message_t_free(void *data)
{
    struct message_t *message = (struct message_t *) data;
    ptrarray_t *deleted = &message->deleted;
    int n = ptrarray_size(deleted);

    while (n) {
        struct removed_mail *rmail = ptrarray_nth(deleted, --n);

        free(rmail->mboxname);
        free(rmail->guid);
        free(rmail);
    }

    ptrarray_fini(deleted);
    free(message);
}

static int restore_message_list_cb(const mbentry_t *mbentry, void *rock)
{
    struct restore_rock *rrock = (struct restore_rock *) rock;
    int log_level = rrock->jrestore->log_level;
    struct mail_rock *mrock = rrock->rock;
    struct mailbox *mailbox = NULL;
    const message_t *msg;
    time_t timestamp = 0;
    int userflag = -1, isdestroyed_mbox = 0;
    int r;

    syslog(log_level, "restore_message_list_cb: processing '%s'  (type = 0x%03x)",
           mbentry->name, mbentry->mbtype);

    if (mbtype_isa(mbentry->mbtype) != MBTYPE_EMAIL) {
        syslog(log_level, "skipping '%s': not type EMAIL", mbentry->name);

        return 0;
    }

    if (mboxname_isnotesmailbox(mbentry->name, MBTYPE_EMAIL)) {
        syslog(log_level, "skipping '%s': Notes mailbox", mbentry->name);

        return 0;
    }

    if (mboxname_isdeletedmailbox(mbentry->name, &timestamp)) {
        if (timestamp <= rrock->jrestore->cutoff) {
            /* Mailbox was destroyed before cutoff - not interested */
            syslog(log_level, "skipping '%s': destroyed (%ld) before cutoff",
                   mbentry->name, timestamp);

            return 0;
        }

        isdestroyed_mbox = 1;
    }

    r = jmap_openmbox(rrock->req, mbentry->name, &mailbox, /*rw*/1);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open mailbox %s", mbentry->name);
        return r;
    }

    if (!(rrock->jrestore->mode & DRY_RUN)) {
        if (!mailbox_user_flag(mailbox, "$restored", &userflag, 0)) {
            /* Remove $restored flag from mailbox */
            mailbox_remove_user_flag(mailbox, userflag);
        }
    }

    struct mailbox_iter *iter = mailbox_iter_init(mailbox, 0, 0);
    while ((msg = mailbox_iter_step(iter))) {
        const struct index_record *record = msg_record(msg);
        const char *guid = message_guid_encode(&record->guid);
        const char *msgid = NULL;
        int isdestroyed_msg = isdestroyed_mbox;
        int ignore_draft = 0;

        syslog(log_level,
               "UID %u: expunged: %x, draft: %x, intdate: %ld, updated: %ld",
               record->uid, (record->internal_flags & FLAG_INTERNAL_EXPUNGED),
               (record->system_flags & FLAG_DRAFT),
               record->internaldate, record->last_updated);

        /* Suppress fetching of Message-ID if not restoring drafts */
        if (rrock->jrestore->mode & UNDO_DRAFTS) {
            /* XXX  conversation ID is faster to lookup than Message-ID
                    so use it to make sure the message has a Message-ID */
            if (conversations_guid_cid_lookup(rrock->req->cstate, guid) &&
                !message_get_messageid((message_t *) msg, &mrock->buf)) {
                msgid = buf_cstring(&mrock->buf);
            }

            syslog(log_level, "UID: %u, msgid = '%s'",
                   record->uid, msgid ? msgid : "");
        }

        /* Remove $restored flag from message */
        if (userflag >= 0 &&
            (record->user_flags[userflag/32] & (1<<userflag%31))) {
            struct index_record *newrecord = (struct index_record *) record;

            newrecord->user_flags[userflag/32] &= ~(1<<userflag%31);
            r = mailbox_rewrite_index_record(mailbox, newrecord);
            if (r) {
                syslog(LOG_ERR,
                       "IOERROR: failed to rewrite index record for %s:%u",
                       mbentry->name, record->uid);
                return 0;
            }
        }

        /* See if we already have this message GUID */
        struct message_t *message = hash_lookup(guid, mrock->emailids);

        if (message && message->ignore) {
            /* An undeleted copy of this message exists */
            syslog(log_level, "skipping UID %u: undeleted copy exists",
                   record->uid);

            continue;
        }

        if ((record->system_flags & FLAG_DELETED) ||
            (record->internal_flags & FLAG_INTERNAL_EXPUNGED)) {
            /* Destroyed message */

            if (record->last_updated <= rrock->jrestore->cutoff) {
                /* Message has been destroyed before cutoff - ignore */
                syslog(log_level, "skipping UID %u: destroyed before cutoff",
                       record->uid);

                continue;
            }

            isdestroyed_msg = 1;
        }

        if (isdestroyed_msg) {
            if (record->system_flags & FLAG_DRAFT) {
                /* Destroyed draft */
                if (!msgid) {
                    /* No way to track this message */
                    syslog(log_level, "skipping UID %u: no msgid", record->uid);

                    continue;
                }

                /* See if we already have the Message-ID */
                message = hash_lookup(msgid, mrock->msgids);
                if (!message) {
                    /* Create message for this Message-ID */
                    message = xzmalloc(sizeof(struct message_t));
                    hash_insert(msgid, message, mrock->msgids);
                }
                else if (message->ignore) {
                    /* An undeleted copy of this draft exists OR
                       this Message-Id exists as a non-draft */
                    syslog(log_level,
                           "skipping UID %u: non-draft / undeleted draft exists",
                           record->uid);

                    continue;
                }
            }
            else {
                /* Destroyed non-draft */
                ignore_draft = 1;

                if (!message && (rrock->jrestore->mode & UNDO_NONDRAFTS)) {
                    /* Create message for this GUID */
                    message = xzmalloc(sizeof(struct message_t));
                    hash_insert(guid, message, mrock->emailids);
                }
            }

            if (message) {
                /* Add this destroyed message to its list */
                struct removed_mail *rmail =
                    xmalloc(sizeof(struct removed_mail));
                rmail->mboxname = xstrdup(mbentry->name);
                rmail->guid = 
                    (record->system_flags & FLAG_DRAFT) ? xstrdup(guid) : NULL;
                rmail->removed =
                    isdestroyed_mbox ? timestamp : record->last_updated;
                rmail->msgno = record->recno;
                rmail->size = record->size;
                ptrarray_append(&message->deleted, rmail);
            }
        }
        else {
            /* Active message - ignore both Message-ID and GUID */
            ignore_draft = 1;

            if (!message) {
                /* Create message for this GUID */
                message = xzmalloc(sizeof(struct message_t));
                hash_insert(guid, message, mrock->emailids);
            }
            message->ignore = 1;
        }

        if (ignore_draft && msgid) {
            /* Mark this Message-ID as undeleted */
            message = hash_lookup(msgid, mrock->msgids);
            if (!message) {
                /* Create message for this Message-ID */
                message = xzmalloc(sizeof(struct message_t));
                hash_insert(msgid, message, mrock->msgids);
            }

            message->ignore = 1;
        }
    }

    mailbox_iter_done(&iter);
    jmap_closembox(rrock->req, &mailbox);

    return 0;
}

static int rmail_cmp(const void **a, const void **b)
{
    const struct removed_mail *rmail_a = (const struct removed_mail *) *a;
    const struct removed_mail *rmail_b = (const struct removed_mail *) *b;

    /* Sort latest first */
    return (rmail_b->removed - rmail_a->removed);
}

static void restore_mailbox_plan_cb(const char *guid __attribute__((unused)),
                                    void *data, void *rock)
{
    struct message_t *message = (struct message_t *) data;
    ptrarray_t *deleted = &message->deleted;
    hash_table *mailboxes = (hash_table *) rock;
    time_t last_removed;
    int i;

    if (!message->ignore) ptrarray_sort(deleted, &rmail_cmp);

    for (i = 0; i < ptrarray_size(deleted); i++) {
        struct removed_mail *rmail = ptrarray_nth(deleted, i);

        if (!message->ignore) {
            /* Add the last removed copies of the message to the plan */
            if (i == 0) last_removed = rmail->removed;

            if (rmail->removed == last_removed) {
                arrayu64_t *msgnos = hash_lookup(rmail->mboxname, mailboxes);
                if (!msgnos) {
                    /* Create msgno list for this mailbox */
                    msgnos = arrayu64_new();
                    hash_insert(rmail->mboxname, msgnos, mailboxes);
                }

                /* Add this msgno to the mailbox */
                arrayu64_append(msgnos, rmail->msgno);
            }
        }
    }
}

static void restore_choose_draft_cb(const char *msgid __attribute__((unused)),
                                    void *data, void *rock)
{
    struct mail_rock *mrock = (struct mail_rock *) rock;
    struct message_t *message = (struct message_t *) data;
    ptrarray_t *drafts = &message->deleted;
    struct removed_mail *maxdraft = NULL;
    int i = 0, num_last = 0;

    /* Add the largest of the last 5 drafts to the plan */
    if (!message->ignore) {
        ptrarray_sort(drafts, &rmail_cmp);
        num_last = 5;
    }

    for (i = 0; i < ptrarray_size(drafts); i++) {
        struct removed_mail *rmail = ptrarray_nth(drafts, i);

        if (num_last) {
            struct message_t *emailid =
                hash_lookup(rmail->guid, mrock->emailids);

            if (!(emailid && emailid->ignore)) {
                if (!maxdraft || rmail->size > maxdraft->size) {
                    maxdraft = rmail;
                }

                num_last--;
            }
        }
    }

    if (maxdraft) {
        hash_table *mailboxes = mrock->mailboxes;
        arrayu64_t *msgnos = hash_lookup(maxdraft->mboxname, mailboxes);
        if (!msgnos) {
            /* Create msgno list for this mailbox */
            msgnos = arrayu64_new();
            hash_insert(maxdraft->mboxname, msgnos, mailboxes);
        }

        /* Add this msgno to the mailbox */
        arrayu64_append(msgnos, maxdraft->msgno);
    }
}

static void restore_mailbox_cb(const char *mboxname, void *data, void *rock)
{
    arrayu64_t *msgnos = (arrayu64_t *) data;
    struct restore_rock *rrock = (struct restore_rock *) rock;
    int log_level = rrock->jrestore->log_level;
    jmap_req_t *req = rrock->req;
    mbname_t *mbname = mbname_from_intname(mboxname);
    struct mailbox *newmailbox = NULL, *mailbox = NULL;
    int r = 0;
    size_t i = 0;

    if (!(rrock->jrestore->mode & DRY_RUN) && mbname_isdeleted(mbname)) {
        /* Look for existing mailbox with same (undeleted) name */
        const char *newmboxname = NULL;
        mbentry_t *mbentry = NULL;

        mbname_set_isdeleted(mbname, 0);
        newmboxname = mbname_intname(mbname);

        r = mboxlist_lookup(newmboxname, &mbentry, NULL);
        mboxlist_entry_free(&mbentry);

        if (!r) {
            /* Open existing mailbox */
            r = mailbox_open_iwl(newmboxname, &newmailbox);

            if (r) {
                syslog(LOG_ERR, "IOERROR: failed to open mailbox %s: %s",
                       newmboxname, error_message(r));
            }
        }
        else {
            struct mboxlock *namespacelock = user_namespacelock(req->accountid);
            mbentry_t newmbentry = MBENTRY_INITIALIZER;
            mbentry_t *parent = NULL;

            /* Find the nearest ancestor of the deleted mailbox
               to see if we have to fill out the branch */
            r = mboxlist_findparent(mbname_intname(mbname), &parent);
            if (r == IMAP_MAILBOX_NONEXISTENT) r = 0;

            if (!r && (parent || !mbname_userid(mbname))) {
                const strarray_t *boxes = mbname_boxes(mbname);
                mbname_t *ancestor =
                    mbname_from_intname(parent ? parent->name : NULL);
                int oldest = strarray_size(mbname_boxes(ancestor));
                int youngest = strarray_size(boxes) - 1;

                /* Are there any missing ancestors? */
                if (oldest > youngest) {
                    /* Verify that we can re-create the deleted mailbox
                       before creating its ancestors */
                    r = mboxlist_createmailboxcheck(mbname_intname(mbname),
                                                    MBTYPE_EMAIL,
                                                    /*partition*/NULL,
                                                    /*isadmin*/0,
                                                    req->accountid,
                                                    req->authstate,
                                                    /*dbonly*/0,
                                                    /*notify*/0,
                                                    /*forceuser*/0);

                    int i;
                    for (i = oldest; !r && i < youngest; i++) {
                        /* Create the ancestors */
                        mbname_push_boxes(ancestor, strarray_nth(boxes, i));
                        newmbentry.name = (char *) mbname_intname(ancestor);
                        newmbentry.mbtype = MBTYPE_EMAIL;
                        r = mboxlist_createmailbox(&newmbentry,
                                                   0/*options*/,
                                                   0/*highestmodseq*/,
                                                   0/*isadmin*/,
                                                   req->accountid,
                                                   req->authstate,
                                                   0/*flags*/,
                                                   NULL/*mailboxptr*/);
                        if (r) {
                            syslog(LOG_ERR,
                                   "IOERROR: failed to create mailbox %s: %s",
                                   mbname_intname(ancestor), error_message(r));
                            break;
                        }
                    }
                }
                
                mbname_free(&ancestor);
            }
            mboxlist_entry_free(&parent);

            if (!r) {
                /* Create the mailbox */
                newmbentry.name = (char *) newmboxname;
                newmbentry.mbtype = MBTYPE_EMAIL;
                r = mboxlist_createmailbox(&newmbentry,
                                           0/*options*/,
                                           0/*highestmodseq*/,
                                           0/*isadmin*/,
                                           req->accountid,
                                           req->authstate,
                                           0/*flags*/,
                                           &newmailbox);
            }
            mboxname_release(&namespacelock);

            if (r) {
                syslog(LOG_ERR, "IOERROR: failed to create mailbox %s: %s",
                       newmboxname, error_message(r));
            }
            else {
                /* Copy over any role (/specialuse) */
                struct buf attrib = BUF_INITIALIZER;
                const char *annot = "/specialuse";

                annotatemore_lookup(mboxname, annot,
                                    req->accountid, &attrib);

                if (attrib.len) {
                    r = annotatemore_write(newmboxname, annot,
                                           req->accountid, &attrib);
                    if (r) {
                        syslog(LOG_ERR,
                               "IOERROR: failed to write annotation %s: %s",
                               annot, error_message(r));
                    }
                }
                buf_reset(&attrib);
            }
        }
    }
    mbname_free(&mbname);

    if (!r) {
        r = jmap_openmbox(req, mboxname, &mailbox, /*rw*/newmailbox == NULL);
        if (r) {
            syslog(LOG_ERR, "IOERROR: failed to open mailbox %s: %s",
                   mboxname, error_message(r));
        }
    }
    if (r) goto done;

    /* Restore messages in msgno/UID order */
    arrayu64_sort(msgnos, NULL/*ascending*/);

    message_t *msg = message_new();
    for (i = 0; i < arrayu64_size(msgnos); i++) {
        uint32_t msgno = arrayu64_nth(msgnos, i);

        message_set_from_mailbox(mailbox, msgno, msg);
        if (!(rrock->jrestore->mode & DRY_RUN)) {
            r = recreate_resource(msg, newmailbox, req, 0/*is_update*/, log_level);
        }
        if (!r) {
            const struct index_record *record = msg_record(msg);
            int restore_type =
                (record->system_flags & FLAG_DRAFT) ? DRAFT_DESTROYS : DESTROYS;

            rrock->jrestore->num_undone[restore_type]++;
        }
    }
    message_unref(&msg);

    /* Update deletedmodseq for this collection type */
    if (mailbox->i.deletedmodseq > rrock->deletedmodseq)
        rrock->deletedmodseq = mailbox->i.deletedmodseq;

    jmap_closembox(req, &mailbox);

  done:
    mailbox_close(&newmailbox);
}

static int jmap_backup_restore_mail(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    struct jmap_restore restore =
        JMAP_RESTORE_INITIALIZER(UNDO_EMAIL|UNDO_DRAFTS|UNDO_NONDRAFTS);
    json_t *err = NULL;
    int r;

    /* Parse request */
    jmap_restore_parse(req, &parser, &restore, &err);
    if (err) {
        jmap_error(req, err);
        goto done;
    }

    hash_table mailboxes = HASH_TABLE_INITIALIZER;
    hash_table emailids = HASH_TABLE_INITIALIZER;
    hash_table msgids = HASH_TABLE_INITIALIZER;
    char *inbox = mboxname_user_mbox(req->accountid, NULL);

    syslog(restore.log_level, "jmap_backup_restore_mail(%s, %ld)",
           inbox, restore.cutoff);

    struct mail_rock mrock = {
        construct_hash_table(&emailids, 1024, 0),  // every message GUID
        construct_hash_table(&msgids, 1024, 0),    // every Message-ID of non-drafts
        construct_hash_table(&mailboxes, 32, 0),
        BUF_INITIALIZER };
    struct restore_rock rrock = { req, &restore, MBTYPE_EMAIL, 0,
                                  NULL, NULL, &mrock, NULL };

    /* Find all destroyed messages within our window -
       remove $restored flag from all messages as a side-effect */
    r = mboxlist_mboxtree(inbox, restore_message_list_cb, &rrock,
                          MBOXTREE_DELETED);
    buf_free(&mrock.buf);

    if (!r) {
        /* Find the largest of the 5 most recently destroyed copies of each draft
           and add them to the proper mailbox plan */
        hash_enumerate(&msgids, &restore_choose_draft_cb, &mrock);

        /* Find the most recently destroyed copies of non-draft messages
           and add them to the proper mailbox plan */
        hash_enumerate(&emailids, &restore_mailbox_plan_cb, &mailboxes);

        /* Restore destroyed messages by mailbox */
        hash_enumerate(&mailboxes, &restore_mailbox_cb, &rrock);

        if (!(restore.mode & DRY_RUN)) {
            mboxname_setmodseq(inbox, rrock.deletedmodseq,
                               MBTYPE_EMAIL, MBOXMODSEQ_ISDELETE);
        }
    }

    free_hash_table(&mailboxes, (void (*)(void *)) &arrayu64_free);
    free_hash_table(&emailids, &message_t_free);
    free_hash_table(&msgids, &message_t_free);
    free(inbox);

    /* Build response */
    if (r) {
        jmap_error(req, (r == HTTP_UNPROCESSABLE) ? 
                   json_pack("{s:s}", "type", "cannotCalculateChanges") : 
                   jmap_server_error(r));
    }
    else {
        jmap_ok(req, jmap_restore_reply(&restore));
    }

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}
