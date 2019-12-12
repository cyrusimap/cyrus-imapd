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
#include "caldav_db.h"
#include "carddav_db.h"
#include "hash.h"
#include "http_caldav_sched.h"
#include "http_jmap.h"
#include "json_support.h"
#include "times.h"
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
    char *(*resource_name_cb)(message_t *, void *);
    int (*restore_cb)(message_t *, message_t *, jmap_req_t *, void *);
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
    struct mailbox *mailbox = rrock->mailbox;
    jmap_req_t *req = rrock->req;
    message_t *recreatemsg = NULL;
    message_t *destroymsg = NULL;
    int r = 0;

    switch (restore->type) {
    case UPDATES:
        if (!(rrock->jrestore->undo & UNDO_UPDATE)) goto done;
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
        recreatemsg = message_new_from_mailbox(mailbox, restore->msgno_torecreate);
    }

    if (restore->msgno_todestroy) {
        destroymsg = message_new_from_mailbox(mailbox, restore->msgno_todestroy);
    }

    r = rrock->restore_cb(recreatemsg, destroymsg, req, rrock->rock);

    message_unref(&recreatemsg);
    message_unref(&destroymsg);

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

        resource = rrock->resource_name_cb(msg, rrock->rock);
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

static int recreate_resource(message_t *msg, jmap_req_t *req, int is_replace)
{
    struct mailbox *mailbox = msg_mailbox(msg);
    const struct index_record *record = msg_record(msg);
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_INITIALIZER;
    struct stagemsg *stage = NULL;
    struct appendstate as;
    const char *fname;
    FILE *f = NULL;
    int r;

    /* use latest version of the resource as the source for our append stage */
    r = message_get_fname(msg, &fname);
    if (r) return r;

    f = append_newstage_full(mailbox->name, time(0), 0, &stage, fname);
    if (!f) return IMAP_INTERNAL;

    /* setup for appending the message to the mailbox. */
    qdiffs[QUOTA_MESSAGE] = 1;
    qdiffs[QUOTA_STORAGE] = msg_size(msg);
    r = append_setup_mbox(&as, mailbox, req->accountid, req->authstate,
                          ACL_INSERT, qdiffs, NULL, 0, EVENT_MESSAGE_NEW);
    if (!r) {
        /* get existing flags and annotations */
        strarray_t *flags = mailbox_extract_flags(mailbox, record, req->accountid);
        struct entryattlist *annots = mailbox_extract_annots(mailbox, record);
        struct body *body = NULL;

        /* mark as undeleted */
        strarray_remove_all_case(flags, "\\Deleted");

        /* append the message to the mailbox. */
        r = append_fromstage(&as, &body, stage, /*internaldate*/0,
                             is_replace ? record->createdmodseq : 0,
                             flags, /*nolink*/0, annots);

        freeentryatts(annots);
        strarray_free(flags);
        message_free_body(body);
        free(body);

        if (r) append_abort(&as);
        else r = append_commit(&as);
    }
    append_removestage(stage);

    return r;
}

static int destroy_resource(message_t *msg, jmap_req_t *req, int is_replace)
{
    struct mailbox *mailbox = msg_mailbox(msg);
    const struct index_record *record = msg_record(msg);
    struct index_record newrecord;
    int r = 0;

    /* copy the existing index_record */
    memcpy(&newrecord, record, sizeof(struct index_record));

    if (is_replace) {
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
                             req->accountid, mailbox->name, 0);
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
    struct carddav_db *carddavdb;
    struct vparse_card *group_vcard;
    struct buf buf;
};

static char *contact_resource_name(message_t *msg, void *rock)
{
    struct mailbox *mailbox = msg_mailbox(msg);
    const struct index_record *record = msg_record(msg);
    struct contact_rock *crock = (struct contact_rock *) rock;
    struct carddav_data *cdata = NULL;
    char *resource = NULL;

    /* Get resource from CardDAV DB, if possible */
    int r = carddav_lookup_imapuid(crock->carddavdb, mailbox->name,
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

static int restore_contact(message_t *recreatemsg, message_t *destroymsg,
                           jmap_req_t *req, void *rock)
{
    int is_replace = recreatemsg && destroymsg;
    int r = 0;

    if (recreatemsg) {
        r = recreate_resource(recreatemsg, req, is_replace);

        if (!r && !is_replace) {
            /* Add this card to the group vCard of recreated contacts */
            struct mailbox *mailbox = msg_mailbox(recreatemsg);
            const struct index_record *record = msg_record(recreatemsg);
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

                    vparse_add_entry(gcard, NULL, "PRODID", _prodid);
                    vparse_add_entry(gcard, NULL, "VERSION", "3.0");
                    vparse_add_entry(gcard, NULL, "UID", makeuuid());
                    vparse_add_entry(gcard, NULL,
                                     "FN", buf_cstring(&crock->buf));
                    vparse_add_entry(gcard, NULL,
                                     "X-ADDRESSBOOKSERVER-KIND", "group");
                    crock->group_vcard = gcard;
                }

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
        r = destroy_resource(destroymsg, req, is_replace);
    }

    return r;
}

static int restore_addressbook_cb(const mbentry_t *mbentry, void *rock)
{
    struct restore_rock *rrock = (struct restore_rock *) rock;
    struct contact_rock *crock = (struct contact_rock *) rrock->rock;
    struct mailbox *mailbox = NULL;
    int r;

    if ((mbentry->mbtype & rrock->mbtype) != rrock->mbtype) return 0;

    /* Open mailbox here since we need it later and it gets referenced counted */
    r = jmap_openmbox(rrock->req, mbentry->name, &mailbox, /*rw*/1);
    if (r) {
        syslog(LOG_ERR, "IOERROR: failed to open mailbox %s", mbentry->name);
        return r;
    }

    /* Do usual processing of the collection */
    r = restore_collection_cb(mbentry, rock);

    if (!r && crock->group_vcard) {
        /* Store the group vCard os recreated contacts */
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
        struct contact_rock crock =
            { carddav_open_userid(req->accountid), NULL, BUF_INITIALIZER };
        struct restore_rock rrock = { req, &restore, MBTYPE_ADDRESSBOOK,
                                      &contact_resource_name, &restore_contact,
                                      &crock, NULL };

        mboxlist_mboxtree(addrhomeset,
                          restore_addressbook_cb, &rrock, MBOXTREE_SKIP_ROOT);
        free(addrhomeset);
        carddav_close(crock.carddavdb);
        buf_free(&crock.buf);
    }

    /* Build response */
    jmap_ok(req, jmap_restore_reply(&restore));

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}

static char *ical_resource_name(message_t *msg, void *rock)
{
    struct mailbox *mailbox = msg_mailbox(msg);
    const struct index_record *record = msg_record(msg);
    struct caldav_db *caldavdb = (struct caldav_db *) rock;
    struct caldav_data *cdata = NULL;
    char *resource = NULL;

    /* Get resource from CalDAV DB, if possible */
    int r = caldav_lookup_imapuid(caldavdb, mailbox->name,
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
                         jmap_req_t *req, struct caldav_db *caldavdb)
{
    struct mailbox *mailbox = msg_mailbox(recreatemsg);
    const struct index_record *record = msg_record(recreatemsg);
    const struct index_record *oldrecord =
        destroymsg ? msg_record(destroymsg) : NULL;
    struct caldav_data *cdata = NULL;
    int r;

    r = caldav_lookup_imapuid(caldavdb, mailbox->name,
                              oldrecord ? oldrecord->uid : record->uid,
                              &cdata, /*tombstones*/ 1);
    if (r) return r;

    if (cdata->organizer) {
        /* Send scheduling message */
        strarray_t schedule_addresses = STRARRAY_INITIALIZER;
        icalcomponent *ical =
            record_to_ical(mailbox, record, &schedule_addresses);
        icalcomponent *comp = icalcomponent_get_first_real_component(ical);
        icalcomponent *oldical = NULL;
        int sequence;

        /* Need to bump SEQUENCE and rewrite resource */
        if (oldrecord) {
            oldical = record_to_ical(mailbox, oldrecord, NULL);
            sequence = icalcomponent_get_sequence(oldical);
        }
        else {
            sequence = icalcomponent_get_sequence(ical);
        }

        icalcomponent_set_sequence(comp, ++sequence);

        r = do_scheduling(req, mailbox->name, cdata->organizer,
                          &schedule_addresses, oldical, ical, /*is_destroy*/0);

        if (!r) {
            struct transaction_t txn;

            memset(&txn, 0, sizeof(struct transaction_t));
            txn.req_hdrs = spool_new_hdrcache();

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
        r = recreate_resource(recreatemsg, req, destroymsg != NULL);
    }

    return r;
}

static int destroy_ical(message_t *destroymsg, jmap_req_t *req,
                        int is_replace, struct caldav_db *caldavdb)
{
    int r = 0;

    if (!is_replace) {
        struct mailbox *mailbox = msg_mailbox(destroymsg);
        const struct index_record *record = msg_record(destroymsg);
        struct caldav_data *cdata = NULL;

        r = caldav_lookup_imapuid(caldavdb, mailbox->name,
                                  record->uid, &cdata, /*tombstones*/ 0);

        if (!r && cdata->organizer) {
            /* Send scheduling message */
            strarray_t schedule_addresses = STRARRAY_INITIALIZER;
            icalcomponent *ical =
                record_to_ical(mailbox, record, &schedule_addresses);

            r = do_scheduling(req, mailbox->name, cdata->organizer,
                              &schedule_addresses, ical, NULL, /*is_destroy*/1);

            icalcomponent_free(ical);
            strarray_fini(&schedule_addresses);
        }
    }

    if (!r) r = destroy_resource(destroymsg, req, is_replace);

    return r;
}

static int restore_ical(message_t *recreatemsg, message_t *destroymsg,
                        jmap_req_t *req, void *rock)
{
    struct caldav_db *caldavdb = (struct caldav_db *) rock;
    int is_replace = recreatemsg && destroymsg;
    int r = 0;

    if (recreatemsg) {
        r = recreate_ical(recreatemsg, destroymsg, req, caldavdb);
    }

    if (!r && destroymsg) {
        r = destroy_ical(destroymsg, req, is_replace, caldavdb);
    }

    return r;
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

    if (restore.undo) {
        char *calhomeset = caldav_mboxname(req->accountid, NULL);
        struct caldav_db *caldavdb = caldav_open_userid(req->accountid);
        struct restore_rock rrock = { req, &restore, MBTYPE_CALENDAR,
                                      &ical_resource_name, &restore_ical,
                                      caldavdb, NULL };

        mboxlist_mboxtree(calhomeset,
                          restore_collection_cb, &rrock, MBOXTREE_SKIP_ROOT);
        free(calhomeset);
        caldav_close(caldavdb);
    }

    /* Build response */
    jmap_ok(req, jmap_restore_reply(&restore));

done:
    jmap_parser_fini(&parser);
    jmap_restore_fini(&restore);

    return 0;
}

static char *note_resource_name(message_t *msg,
                                void *rock __attribute__((unused)))
{
    struct buf buf = BUF_INITIALIZER;
    char *resource = NULL;
    int r;

    r = message_get_field(msg, "X-Uniform-Type-Identifier",
                          MESSAGE_DECODED|MESSAGE_TRIM, &buf);
    if  (!r && !strcmp(buf_cstring(&buf), "com.apple.mail-note")) {
        r = message_get_field(msg, "X-Universally-Unique-Identifier",
                              MESSAGE_DECODED|MESSAGE_TRIM, &buf);
        resource = buf_release(&buf);
    }
    buf_free(&buf);

    return resource;
}

static int restore_note(message_t *recreatemsg, message_t *destroymsg,
                        jmap_req_t *req, void *rock __attribute__((unused)))
{
    int is_replace = recreatemsg && destroymsg;
    int r = 0;

    if (recreatemsg) {
        r = recreate_resource(recreatemsg, req, is_replace);
    }

    if (!r && destroymsg) {
        r = destroy_resource(destroymsg, req, is_replace);
    }

    return r;
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

    const char *subfolder = config_getstring(IMAPOPT_NOTESMAILBOX);
    if (subfolder && restore.undo) {
        char *notes = mboxname_user_mbox(req->accountid, subfolder);
        struct restore_rock rrock = { req, &restore, MBTYPE_EMAIL,
                                      &note_resource_name, &restore_note,
                                      NULL, NULL };

        mboxlist_mboxtree(notes, restore_collection_cb,
                          &rrock, MBOXTREE_SKIP_CHILDREN);
        free(notes);
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
