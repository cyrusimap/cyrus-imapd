/* jmap_admin.c -- Routines for handling JMAP admin tasks
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

#include "bsearch.h"
#include "caldav_util.h"
#include "defaultalarms.h"
#include "hash.h"
#include "http_caldav_sched.h"
#include "http_jmap.h"
#include "user.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"

static int jmap_admin_rewrite_calevent_privacy(jmap_req_t *req);
static int jmap_admin_migrate_defaultalarms(jmap_req_t *req);

static jmap_method_t jmap_admin_methods_nonstandard[] = {
    {
        "Admin/rewriteCalendarEventPrivacy",
        JMAP_ADMIN_EXTENSION,
        &jmap_admin_rewrite_calevent_privacy,
        /*flags*/0
    },
    {
        "Admin/migrateCalendarDefaultAlarms",
        JMAP_ADMIN_EXTENSION,
        &jmap_admin_migrate_defaultalarms,
        /*flags*/0
    },
    { NULL, NULL, NULL, 0}
};

HIDDEN void jmap_admin_init(jmap_settings_t *settings)
{
    json_object_set_new(settings->server_capabilities,
            JMAP_ADMIN_EXTENSION, json_object());

    if (config_getswitch(IMAPOPT_JMAP_NONSTANDARD_EXTENSIONS)) {
        jmap_method_t *mp;
        for (mp = jmap_admin_methods_nonstandard; mp->name; mp++) {
            hash_insert(mp->name, mp, &settings->methods);
        }
    }
}

HIDDEN void jmap_admin_capabilities(json_t *account_capabilities)
{
    if (!httpd_userisadmin) return;

    json_object_set_new(account_capabilities, JMAP_ADMIN_EXTENSION, json_object());
}

struct rewrite_calevent_privacy_rock {
    /* Request state */
    json_t *rewritten;
    json_t *not_rewritten;
    /* Per-user state */
    hash_table uids_bymbkey;
    int mailbox_byname;
    struct transaction_t txn;
    struct buf buf;
};

static int rewrite_calevent_privacy_find_uids(void *vrock, struct caldav_data *cdata)
{
    if (!cdata->comp_flags.privacy)
        return 0;

    struct rewrite_calevent_privacy_rock *rock = vrock;

    bitvector_t *uids = hash_lookup(cdata->dav.mailbox, &rock->uids_bymbkey);
    if (!uids) {
        uids = xzmalloc(sizeof(struct bitvector));
        bv_init(uids);
        hash_insert(cdata->dav.mailbox, uids, &rock->uids_bymbkey);
    }
    bv_set(uids, cdata->dav.imap_uid);

    return 0;
}

static int rewrite_calevent_privacy_update_uid(struct mailbox *mbox, int uid,
                                               struct caldav_db *caldavdb,
                                               struct transaction_t *txn,
                                               struct buf *buf,
                                               strarray_t *sched_addrs)
{
    icalcomponent *ical = NULL;

    struct index_record record;
    int r = mailbox_find_index_record(mbox, uid, &record);
    if (r) goto done;

    struct caldav_data *cdata;
    r = caldav_lookup_imapuid(caldavdb, mbox->mbentry, uid, &cdata, 1);
    if (r) goto done;

    ical = record_to_ical(mbox, &record, NULL);
    if (!ical) goto done;

    buf_setcstr(buf, cdata->dav.resource);
    cdata->comp_flags.privacy = 0;
    int ret = caldav_store_resource(txn, ical, mbox, buf_cstring(buf),
            cdata->dav.createdmodseq, caldavdb, 0, txn->userid,
            NULL, NULL, sched_addrs);
    if (ret != HTTP_NO_CONTENT)
        r = IMAP_INTERNAL;

done:
    if (ical) icalcomponent_free(ical);
    return r;
}


static int rewrite_calevent_privacy(const char *userid, void *vrock)
{
    struct rewrite_calevent_privacy_rock *rock = vrock;
    char *calhomename = caldav_mboxname(userid, NULL);
    struct caldav_db *caldavdb = NULL;
    struct conversations_state *cstate = NULL;
    struct mboxlock *namespacelock = NULL;
    strarray_t sched_addrs = STRARRAY_INITIALIZER;

    int r = conversations_open_user(userid, 0, &cstate);
    if (r) {
        json_t *err = jmap_server_error(IMAP_INTERNAL);
        buf_reset(&rock->buf);
        buf_printf(&rock->buf, "can not open cstate: %s",
                error_message(r));
        json_object_set_new(err, "description",
                json_string(buf_cstring(&rock->buf)));
        json_object_set_new(rock->not_rewritten, userid, err);
        goto done;
    }

    namespacelock = user_namespacelock(userid);
    if (!namespacelock) {
        json_t *err = jmap_server_error(IMAP_INTERNAL);
        json_object_set_new(err, "description",
                json_string("can not lock namespace"));
        json_object_set_new(rock->not_rewritten, userid, err);
        goto done;
    }

    get_schedule_addresses(calhomename, userid, &sched_addrs);

    rock->txn.userid = userid;
    rock->txn.req_hdrs = spool_new_hdrcache();
    spool_append_header(xstrdup("Schedule-Reply"), xstrdup("F"),
            rock->txn.req_hdrs);

    caldavdb = caldav_open_userid(userid);
    if (!caldavdb) {
        json_t *err = jmap_server_error(IMAP_INTERNAL);
        json_object_set_new(err, "description",
                json_string("can not open caldavdb"));
        json_object_set_new(rock->not_rewritten, userid, err);
        goto done;
    }

    construct_hash_table(&rock->uids_bymbkey, 1024, 0);

    r = caldav_foreach(caldavdb, NULL,
            rewrite_calevent_privacy_find_uids, rock);
    if (r) {
        buf_reset(&rock->buf);
        buf_printf(&rock->buf, "caldav_foreach: %s",
                cyrusdb_strerror(r));
        json_t *err = jmap_server_error(IMAP_INTERNAL);
        json_object_set_new(err, "description",
                json_string(buf_cstring(&rock->buf)));
        json_object_set_new(rock->not_rewritten, userid, err);
        goto done;
    }

    strarray_t *mbkeys = hash_keys(&rock->uids_bymbkey);
    strarray_sort(mbkeys, cmpstringp_mbox);
    struct buf idbuf = BUF_INITIALIZER;
    json_t *rewritten_uids = json_object();
    json_t *not_rewritten_uids = json_object();

    for (int i = 0; i < strarray_size(mbkeys); i++) {
        const char *mbkey = strarray_nth(mbkeys, i);
        mbentry_t *mbentry = NULL;
        struct mailbox *mbox = NULL;
        bitvector_t *uids = hash_lookup(mbkey, &rock->uids_bymbkey);

        buf_reset(&idbuf);
        buf_putc(&idbuf, rock->mailbox_byname ? '<' : '{');
        buf_appendcstr(&idbuf, mbkey);
        buf_putc(&idbuf, rock->mailbox_byname ? '>' : '}');

        if (rock->mailbox_byname) {
            r = mboxlist_lookup(mbkey, &mbentry, NULL);
        }
        else {
            r = mboxlist_lookup_by_uniqueid(mbkey, &mbentry, NULL);
        }
        if (!r) {
            r = mailbox_open_iwl(mbentry->name, &mbox);
        }

        if (!r) {
            for (int uid = bv_first_set(uids); uid > 0;
                    uid = bv_next_set(uids, uid + 1)) {
                r = rewrite_calevent_privacy_update_uid(mbox, uid,
                        caldavdb, &rock->txn, &rock->buf, &sched_addrs);

                size_t l = buf_len(&idbuf);
                buf_printf(&idbuf, ":%d", uid);
                if (!r) {
                    json_object_set_new(rewritten_uids,
                            buf_cstring(&idbuf), json_true());
                }
                else {
                    json_object_set_new(not_rewritten_uids,
                            buf_cstring(&idbuf),
                            json_string(error_message(r)));
                }
                buf_truncate(&idbuf, l);
            }
        }
        else {
            for (int uid = bv_first_set(uids); uid > 0;
                    uid = bv_next_set(uids, uid + 1)) {

                size_t l = buf_len(&idbuf);
                buf_printf(&idbuf, ":%d", uid);
                json_object_set_new(not_rewritten_uids,
                        buf_cstring(&idbuf),
                        json_string(error_message(r)));
                buf_truncate(&idbuf, l);
            }
        }

        mailbox_close(&mbox);
        mboxlist_entry_free(&mbentry);
    }
    buf_free(&idbuf);

    if (json_object_size(rewritten_uids)) {
        json_object_set_new(rock->rewritten, userid, rewritten_uids);
    }
    else json_decref(rewritten_uids);

    if (json_object_size(not_rewritten_uids)) {
        json_t *err = json_pack("{s:s s:o}",
                "type", "rewritePrivacyError",
                "uids", not_rewritten_uids);
        json_object_set_new(rock->not_rewritten, userid, err);
    }
    else json_decref(not_rewritten_uids);

    strarray_free(mbkeys);

done:
    if (rock->uids_bymbkey.count) {
        hash_iter *iter = hash_table_iter(&rock->uids_bymbkey);
        while (hash_iter_next(iter)) {
            bitvector_t *uids = hash_iter_val(iter);
            bv_fini(uids);
            free(uids);
        }
        hash_iter_free(&iter);
        free_hash_table(&rock->uids_bymbkey, NULL);
    }

    spool_free_hdrcache(rock->txn.req_hdrs);
    buf_free(&rock->txn.buf);
    memset(&rock->txn, 0, sizeof(struct transaction_t));
    buf_free(&rock->buf);

    if (caldavdb) caldav_close(caldavdb);
    mboxname_release(&namespacelock);
    conversations_commit(&cstate);
    strarray_fini(&sched_addrs);
    free(calhomename);
    return 0;
}

static int jmap_admin_rewrite_calevent_privacy(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;

    if (!httpd_userisadmin) {
        jmap_error(req, json_pack("{s:s}", "type", "forbidden"));
        goto done;
    }

    // Validate arguments

    const char *arg;
    json_t *jarg;
    json_object_foreach(req->args, arg, jarg) {
        if (!strcmp(arg, "userIds")) {
            if (json_is_array(jarg)) {
                size_t i;
                json_t *jval;
                json_array_foreach(jarg, i, jval) {
                    if (!json_is_string(jval)) {
                        jmap_parser_push_index(&parser, "userIds", i, NULL);
                        jmap_parser_invalid(&parser, NULL);
                        jmap_parser_pop(&parser);
                    }
                }
            }
            else {
                jmap_parser_invalid(&parser, "userIds");
            }
        }
        else {
            jmap_parser_invalid(&parser, arg);
        }
    }

    if (json_array_size(parser.invalid)) {
        json_t *err = json_pack("{s:s s:O}",
                "type", "invalidArguments",
                "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    // Process users

    struct rewrite_calevent_privacy_rock rock = {
        .rewritten = json_object(), .not_rewritten = json_object()
    };

    json_t *userids = json_object_get(req->args, "userIds");
    if (json_is_array(userids)) {
        size_t i;
        json_t *jval;
        json_array_foreach(userids, i, jval) {
            rewrite_calevent_privacy(json_string_value(jval), &rock);
        }
    }
    else {
        mboxlist_alluser(rewrite_calevent_privacy, &rock);
    }

    // Create response

    json_t *res = json_object();
    json_object_set(res, "rewritten", rock.rewritten);
    if (json_object_size(rock.not_rewritten)) {
        json_object_set(res, "notRewritten", rock.not_rewritten);
    }
    jmap_ok(req, res);

    json_decref(rock.rewritten);
    json_decref(rock.not_rewritten);

done:
    jmap_parser_fini(&parser);
    return 0;
}

static int collect_userids(const char *userid, void *rock)
{
    strarray_append((strarray_t*)rock, userid);
    return 0;
}

struct migrate_defaultalarms_rock {
    const char *userid;
    json_t *migrated;
    json_t *not_migrated;
};

static int migrate_defaultalarms(const mbentry_t *mbentry, void *vrock)
{
    mbname_t *mbname = mbname_from_intname(mbentry->name);
    struct mailbox *mbox  = NULL;
    struct migrate_defaultalarms_rock *rock = vrock;
    int r = 0;

    if (mbentry->mbtype != MBTYPE_CALENDAR)
        goto done;

    if (!mboxname_iscalendarmailbox(mbname_intname(mbname), 0))
        goto done;

    const strarray_t *boxes = mbname_boxes(mbname);
    if (strarray_size(boxes) < 2)
        goto done;

    const char *collname = strarray_nth(boxes, strarray_size(boxes) - 1);
    if (!strncmpsafe(collname, SCHED_INBOX, strlen(SCHED_INBOX)-1) ||
        !strncmpsafe(collname, SCHED_OUTBOX, strlen(SCHED_OUTBOX)-1) ||
        !strncmpsafe(collname, MANAGED_ATTACH, strlen(MANAGED_ATTACH)-1)) {
        goto done;
    }

    r = mailbox_open_iwl(mbentry->name, &mbox);
    if (r) goto done;

    int did_migrate = 0;
    r = defaultalarms_migrate(mbox, rock->userid, &did_migrate);
    if (r) {
        xsyslog(LOG_ERR, "could not migrate",
                "mboxname=<%s> mboxid=<%s> error=<%s>",
                mbentry->name, mbentry->uniqueid, cyrusdb_strerror(r));
        goto done;
    }

    if (did_migrate) {
        json_array_append_new(rock->migrated, json_string(mbentry->name));
    }

done:
    if (r) {
        json_object_set_new(rock->not_migrated, mbentry->name,
                jmap_server_error(r));
    }
    mbname_free(&mbname);
    mailbox_close(&mbox);
    return 0;
}

static int jmap_admin_migrate_defaultalarms(jmap_req_t *req)
{
    struct jmap_parser parser = JMAP_PARSER_INITIALIZER;
    json_t *migrated_userids = json_object();
    json_t *not_migrated_userids = json_object();
    strarray_t userids = STRARRAY_INITIALIZER;

    if (!httpd_userisadmin) {
        jmap_error(req, json_pack("{s:s}", "type", "forbidden"));
        goto done;
    }

    // Validate arguments

    const char *arg;
    json_t *jarg;
    json_object_foreach(req->args, arg, jarg) {
        if (!strcmp(arg, "userIds")) {
            if (json_is_array(jarg)) {
                size_t i;
                json_t *jval;
                json_array_foreach(jarg, i, jval) {
                    if (!json_is_string(jval)) {
                        jmap_parser_push_index(&parser, "userIds", i, NULL);
                        jmap_parser_invalid(&parser, NULL);
                        jmap_parser_pop(&parser);
                    }
                }
            }
            else {
                jmap_parser_invalid(&parser, "userIds");
            }
        }
        else {
            jmap_parser_invalid(&parser, arg);
        }
    }

    if (json_array_size(parser.invalid)) {
        json_t *err = json_pack("{s:s s:O}",
                "type", "invalidArguments",
                "arguments", parser.invalid);
        jmap_error(req, err);
        goto done;
    }

    // Collect user ids
    json_t *juserids = json_object_get(req->args, "userIds");
    if (json_is_array(juserids)) {
        size_t i;
        json_t *jval;
        json_array_foreach(juserids, i, jval) {
            strarray_append(&userids, json_string_value(jval));
        }
    }
    else {
        mboxlist_alluser(collect_userids, &userids);
    }
    strarray_sort(&userids, cmpstringp_raw);

    // Process users
    for (int i = 0; i < strarray_size(&userids); i++) {
        const char *userid = strarray_nth(&userids, i);

        struct mboxlock *namespacelock = user_namespacelock(userid);
        if (!namespacelock) {
            json_t *err = jmap_server_error(IMAP_INTERNAL);
            json_object_set_new(err, "description",
                    json_string("can not lock namespace"));
            json_object_set_new(not_migrated_userids, userid, err);
            continue;
        }

        struct migrate_defaultalarms_rock rock = {
            .userid = userid,
            .migrated = json_array(),
            .not_migrated = json_object()
        };

        int r = mboxlist_usermboxtree(userid, NULL,
                migrate_defaultalarms, &rock, MBOXTREE_PLUS_RACL);

        if (json_object_size(rock.not_migrated)) {
            json_object_set(not_migrated_userids,
                    userid, rock.not_migrated);
        }
        else if (r) {
            json_object_set_new(not_migrated_userids, userid,
                    jmap_server_error(r));
        }

        json_object_set(migrated_userids, userid,
                json_array_size(rock.migrated) ?
                rock.migrated : json_null());

        json_decref(rock.migrated);
        json_decref(rock.not_migrated);

        mboxname_release(&namespacelock);
    }

    // Create response
    json_t *res = json_object();
    json_object_set(res, "migrated", migrated_userids);
    if (json_object_size(not_migrated_userids)) {
        json_object_set(res, "notMigrated", not_migrated_userids);
    }
    jmap_ok(req, res);

    json_decref(migrated_userids);
    json_decref(not_migrated_userids);

done:
    strarray_fini(&userids);
    jmap_parser_fini(&parser);
    return 0;
}
