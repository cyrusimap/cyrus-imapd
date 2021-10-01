/* caldav_db.c -- implementation of per-user CalDAV database
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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

#include <sysexits.h>
#include <syslog.h>
#include <string.h>

#include <libical/ical.h>

#include "caldav_alarm.h"
#include "caldav_db.h"
#include "cyrusdb.h"
#include "dynarray.h"
#include "httpd.h"
#include "http_dav.h"
#include "ical_support.h"
#include "libconfig.h"
#include "mboxname.h"
#include "util.h"
#include "xstrlcat.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

struct caldav_db {
    sqldb_t *db;                        /* DB handle */
    char *sched_inbox;                  /* DB owner's scheduling Inbox */
    struct buf mailbox;                 /* buffers for copies of column text */
    struct buf resource;
    struct buf lock_token;
    struct buf lock_owner;
    struct buf lock_ownerid;
    struct buf ical_uid;
    struct buf organizer;
    struct buf dtstart;
    struct buf dtend;
    struct buf sched_tag;
};


static struct namespace caldav_namespace;
EXPORTED time_t caldav_epoch = -1;
EXPORTED time_t caldav_eternity = -1;

static int caldav_initialized = 0;

static void done_cb(void *rock __attribute__((unused))) {
    caldav_done();
}

static void init_internal() {
    if (!caldav_initialized) {
        caldav_init();
        cyrus_modules_add(done_cb, NULL);
    }
}

EXPORTED int caldav_init(void)
{
    int r;
    struct icaltimetype date;

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&caldav_namespace, 1))) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EX_CONFIG);
    }

    /* Get min date-time */
    date = icaltime_from_string(config_getstring(IMAPOPT_CALDAV_MINDATETIME));
    if (!icaltime_is_null_time(date)) {
        caldav_epoch = icaltime_as_timet_with_zone(date, NULL);
    }
    if (caldav_epoch == -1) caldav_epoch = INT_MIN;

    /* Get max date-time */
    date = icaltime_from_string(config_getstring(IMAPOPT_CALDAV_MAXDATETIME));
    if (!icaltime_is_null_time(date)) {
        caldav_eternity = icaltime_as_timet_with_zone(date, NULL);
    }
    if (caldav_eternity == -1) caldav_eternity = INT_MAX;

    r = sqldb_init();
    caldav_alarm_init();

    if (!r) caldav_initialized = 1;
    return r;
}


EXPORTED int caldav_done(void)
{
    int r;
    caldav_alarm_done();
    r = sqldb_done();
    if (!r) caldav_initialized = 0;
    return r;
}

EXPORTED struct caldav_db *caldav_open_userid(const char *userid)
{
    struct caldav_db *caldavdb = NULL;

    init_internal();

    sqldb_t *db = dav_open_userid(userid);
    if (!db) return NULL;

    caldavdb = xzmalloc(sizeof(struct caldav_db));
    caldavdb->db = db;

    /* Construct mbox name corresponding to userid's scheduling Inbox */
    caldavdb->sched_inbox = caldav_mboxname(userid, SCHED_INBOX);

    if (db->version >= DB_MBOXID_VERSION) {
        /* Lookup mailbox ID of scheduling Inbox */
        mbentry_t *mbentry = NULL;
        if (!mboxlist_lookup(caldavdb->sched_inbox, &mbentry, NULL)) {
            free(caldavdb->sched_inbox);
            caldavdb->sched_inbox = xstrdup(mbentry->uniqueid);
        }
        mboxlist_entry_free(&mbentry);
    }

    return caldavdb;
}

/* Open DAV DB corresponding to userid */
EXPORTED struct caldav_db *caldav_open_mailbox(struct mailbox *mailbox)
{
    struct caldav_db *caldavdb = NULL;
    char *userid = mboxname_to_userid(mailbox_name(mailbox));

    init_internal();

    if (userid) {
        caldavdb = caldav_open_userid(userid);
        free(userid);
        return caldavdb;
    }

    sqldb_t *db = dav_open_mailbox(mailbox);
    if (!db) return NULL;

    caldavdb = xzmalloc(sizeof(struct caldav_db));
    caldavdb->db = db;

    return caldavdb;
}

/* Close DAV DB */
EXPORTED int caldav_close(struct caldav_db *caldavdb)
{
    int r = 0;

    if (!caldavdb) return 0;

    free(caldavdb->sched_inbox);
    buf_free(&caldavdb->mailbox);
    buf_free(&caldavdb->resource);
    buf_free(&caldavdb->lock_token);
    buf_free(&caldavdb->lock_owner);
    buf_free(&caldavdb->lock_ownerid);
    buf_free(&caldavdb->ical_uid);
    buf_free(&caldavdb->organizer);
    buf_free(&caldavdb->dtstart);
    buf_free(&caldavdb->dtend);
    buf_free(&caldavdb->sched_tag);

    r = dav_close(&caldavdb->db);

    free(caldavdb);

    return r;
}

EXPORTED int caldav_begin(struct caldav_db *caldavdb)
{
    return sqldb_begin(caldavdb->db, "caldav");
}

EXPORTED int caldav_commit(struct caldav_db *caldavdb)
{
    return sqldb_commit(caldavdb->db, "caldav");
}

EXPORTED int caldav_abort(struct caldav_db *caldavdb)
{
    return sqldb_rollback(caldavdb->db, "caldav");
}

#define RROCK_FLAG_TOMBSTONES (1<<0)
struct read_rock {
    struct caldav_db *db;
    struct caldav_data *cdata;
    int flags;
    caldav_cb_t *cb;
    void *rock;
};

static const char *text_to_buf(const char *text, struct buf *buf)
{
    if (text) {
        buf_setcstr(buf, text);
        text = buf_cstring(buf);
    }

    return text;
}

static void _num_to_comp_flags(struct comp_flags *flags, unsigned num)
{
    flags->recurring =  num & 1;
    flags->transp    = (num >> 1) & 1;
    flags->status    = (num >> 2) & 3;
    flags->tzbyref   = (num >> 4) & 1;
    flags->mattach   = (num >> 5) & 1;
    flags->shared    = (num >> 6) & 1;
    flags->defaultalerts = (num >> 7) & 1;
}

static unsigned _comp_flags_to_num(struct comp_flags *flags)
{
   return (flags->recurring & 1)
       + ((flags->transp    & 1) << 1)
       + ((flags->status    & 3) << 2)
       + ((flags->tzbyref   & 1) << 4)
       + ((flags->mattach   & 1) << 5)
       + ((flags->shared    & 1) << 6)
       + ((flags->defaultalerts & 1) << 7);
}

#define ICALOBJS_FIELDS         \
    " ical_objs.rowid,"         \
    " ical_objs.creationdate,"  \
    " ical_objs.mailbox,"       \
    " ical_objs.resource,"      \
    " ical_objs.imap_uid,"      \
    " ical_objs.lock_token,"    \
    " ical_objs.lock_owner,"    \
    " ical_objs.lock_ownerid,"  \
    " ical_objs.lock_expire,"   \
    " ical_objs.comp_type,"     \
    " ical_objs.ical_uid,"      \
    " ical_objs.organizer,"     \
    " ical_objs.dtstart,"       \
    " ical_objs.dtend,"         \
    " ical_objs.comp_flags,"    \
    " ical_objs.sched_tag,"     \
    " ical_objs.alive,"         \
    " ical_objs.modseq,"        \
    " ical_objs.createdmodseq," \

#define CMD_READFIELDS \
    "SELECT " ICALOBJS_FIELDS " NULL FROM ical_objs"

static void read_cdata(sqlite3_stmt *stmt,
                       struct caldav_db *db,
                       int skip_tombstones,
                       struct caldav_data *cdata)
{
    memset(cdata, 0, sizeof(struct caldav_data));

    cdata->dav.mailbox_byname = (db->db->version < DB_MBOXID_VERSION);
    cdata->dav.alive = sqlite3_column_int(stmt, 16);
    cdata->dav.modseq = sqlite3_column_int64(stmt, 17);
    cdata->dav.createdmodseq = sqlite3_column_int64(stmt, 18);

    if (skip_tombstones && !cdata->dav.alive) return;

    cdata->dav.rowid = sqlite3_column_int(stmt, 0);
    cdata->dav.creationdate = sqlite3_column_int(stmt, 1);
    cdata->dav.imap_uid = sqlite3_column_int(stmt, 4);
    cdata->dav.lock_expire = sqlite3_column_int(stmt, 8);
    cdata->comp_type = sqlite3_column_int(stmt, 9);
    _num_to_comp_flags(&cdata->comp_flags, sqlite3_column_int(stmt, 14));

    cdata->dav.mailbox = (const char *) sqlite3_column_text(stmt, 2);
    cdata->dav.resource = (const char *) sqlite3_column_text(stmt, 3);
    cdata->dav.lock_token = (const char *) sqlite3_column_text(stmt, 5);
    cdata->dav.lock_owner = (const char *) sqlite3_column_text(stmt, 6);
    cdata->dav.lock_ownerid = (const char *) sqlite3_column_text(stmt, 7);
    cdata->ical_uid = (const char *) sqlite3_column_text(stmt, 10);
    cdata->organizer = (const char *) sqlite3_column_text(stmt, 11);
    cdata->dtstart = (const char *) sqlite3_column_text(stmt, 12);
    cdata->dtend = (const char *) sqlite3_column_text(stmt, 13);
    cdata->sched_tag = (const char *) sqlite3_column_text(stmt, 15);
}

static int read_cb(sqlite3_stmt *stmt, void *rock)
{
    struct read_rock *rrock = (struct read_rock *) rock;
    struct caldav_db *db = rrock->db;
    struct caldav_data *cdata = rrock->cdata;
    int r = 0;

    int skip_tombstones = !(rrock->flags & RROCK_FLAG_TOMBSTONES);
    read_cdata(stmt, db, skip_tombstones, cdata);
    if (skip_tombstones && !cdata->dav.alive) return 0;

    if (rrock->cb) {
        /* We can use the column data directly for the callback */
        r = rrock->cb(rrock->rock, cdata);
    }
    else {
        /* For single row SELECTs like caldav_read(),
         * we need to make a copy of the column data before
         * it gets flushed by sqlite3_step() or sqlite3_reset() */
        cdata->dav.mailbox =
            text_to_buf(cdata->dav.mailbox, &db->mailbox);
        cdata->dav.resource =
            text_to_buf(cdata->dav.resource, &db->resource);
        cdata->dav.lock_token =
            text_to_buf(cdata->dav.lock_token, &db->lock_token);
        cdata->dav.lock_owner =
            text_to_buf(cdata->dav.lock_owner, &db->lock_owner);
        cdata->dav.lock_ownerid =
            text_to_buf(cdata->dav.lock_ownerid, &db->lock_ownerid);
        cdata->ical_uid =
            text_to_buf(cdata->ical_uid, &db->ical_uid);
        cdata->organizer =
            text_to_buf(cdata->organizer, &db->organizer);
        cdata->dtstart =
            text_to_buf(cdata->dtstart, &db->dtstart);
        cdata->dtend =
            text_to_buf(cdata->dtend, &db->dtend);
        cdata->sched_tag =
            text_to_buf(cdata->sched_tag, &db->sched_tag);
    }

    return r;
}


#define CMD_SELRSRC CMD_READFIELDS \
    " WHERE mailbox = :mailbox AND resource = :resource;"

EXPORTED int caldav_lookup_resource(struct caldav_db *caldavdb,
                           const mbentry_t *mbentry, const char *resource,
                           struct caldav_data **result,
                           int tombstones)
{
    const char *mailbox = (caldavdb->db->version >= DB_MBOXID_VERSION) ?
        mbentry->uniqueid : mbentry->name;
    struct sqldb_bindval bval[] = {
        { ":mailbox",  SQLITE_TEXT, { .s = mailbox       } },
        { ":resource", SQLITE_TEXT, { .s = resource      } },
        { NULL,        SQLITE_NULL, { .s = NULL          } } };
    static struct caldav_data cdata;
    struct read_rock rrock = { caldavdb, &cdata, tombstones, NULL, NULL };
    int r;

    *result = memset(&cdata, 0, sizeof(struct caldav_data));

    r = sqldb_exec(caldavdb->db, CMD_SELRSRC, bval, &read_cb, &rrock);
    if (!r && !cdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    /* always add the mailbox and resource, so error responses don't
     * crash out */
    cdata.dav.mailbox_byname = (caldavdb->db->version < DB_MBOXID_VERSION);
    cdata.dav.mailbox = mailbox;
    cdata.dav.resource = resource;

    return r;
}

#define CMD_SELIMAPUID CMD_READFIELDS \
    " WHERE mailbox = :mailbox AND imap_uid = :imap_uid;"

EXPORTED int caldav_lookup_imapuid(struct caldav_db *caldavdb,
                           const mbentry_t *mbentry, int imap_uid,
                           struct caldav_data **result,
                           int tombstones)
{
    const char *mailbox = (caldavdb->db->version >= DB_MBOXID_VERSION) ?
        mbentry->uniqueid : mbentry->name;
    struct sqldb_bindval bval[] = {
        { ":mailbox",  SQLITE_TEXT,    { .s = mailbox       } },
        { ":imap_uid", SQLITE_INTEGER, { .i = imap_uid      } },
        { NULL,        SQLITE_NULL,    { .s = NULL          } } };
    static struct caldav_data cdata;
    struct read_rock rrock = { caldavdb, &cdata, tombstones, NULL, NULL };
    int r;

    *result = memset(&cdata, 0, sizeof(struct caldav_data));

    r = sqldb_exec(caldavdb->db, CMD_SELIMAPUID, bval, &read_cb, &rrock);
    if (!r && !cdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    cdata.dav.mailbox = mailbox;
    cdata.dav.imap_uid = imap_uid;

    return r;
}


#define CMD_SELUID CMD_READFIELDS \
    " WHERE ical_uid = :ical_uid AND mailbox != :inbox AND alive = 1;"

EXPORTED int caldav_lookup_uid(struct caldav_db *caldavdb, const char *ical_uid,
                               struct caldav_data **result)
{
    struct sqldb_bindval bval[] = {
        { ":ical_uid", SQLITE_TEXT, { .s = ical_uid              } },
        { ":inbox",    SQLITE_TEXT, { .s = caldavdb->sched_inbox } },
        { NULL,        SQLITE_NULL, { .s = NULL                  } } };
    static struct caldav_data cdata;
    struct read_rock rrock = { caldavdb, &cdata, 0, NULL, NULL };
    int r;

    /* XXX - ability to pass through the tombstones flag */

    *result = memset(&cdata, 0, sizeof(struct caldav_data));

    r = sqldb_exec(caldavdb->db, CMD_SELUID, bval, &read_cb, &rrock);
    if (!r && !cdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_SELMBOX CMD_READFIELDS \
    " WHERE mailbox = :mailbox AND alive = 1;"

#define CMD_SELALIVE CMD_READFIELDS \
    " WHERE alive = 1;"

EXPORTED int caldav_foreach(struct caldav_db *caldavdb, const mbentry_t *mbentry,
                            caldav_cb_t *cb, void *rock)
{
    const char *mailbox = !mbentry ? NULL :
        ((caldavdb->db->version >= DB_MBOXID_VERSION) ?
         mbentry->uniqueid : mbentry->name);
    struct sqldb_bindval bval[] = {
        { ":mailbox", SQLITE_TEXT, { .s = mailbox } },
        { NULL,       SQLITE_NULL, { .s = NULL    } } };
    struct caldav_data cdata;
    struct read_rock rrock = { caldavdb, &cdata, 0, cb, rock };

    /* XXX - tombstones */

    if (mailbox) {
        return sqldb_exec(caldavdb->db, CMD_SELMBOX, bval, &read_cb, &rrock);
    } else {
        return sqldb_exec(caldavdb->db, CMD_SELALIVE, bval, &read_cb, &rrock);
    }
}

#define CMD_INSERT                                                      \
    "INSERT INTO ical_objs ("                                           \
    "  alive, mailbox, resource, creationdate, imap_uid, modseq,"       \
    "  createdmodseq,"                                                  \
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"              \
    "  comp_type, ical_uid, organizer, dtstart, dtend,"                 \
    "  comp_flags, sched_tag )"                                         \
    " VALUES ("                                                         \
    "  :alive, :mailbox, :resource, :creationdate, :imap_uid, :modseq," \
    "  :createdmodseq,"                                                 \
    "  :lock_token, :lock_owner, :lock_ownerid, :lock_expire,"          \
    "  :comp_type, :ical_uid, :organizer, :dtstart, :dtend,"            \
    "  :comp_flags, :sched_tag );"

#define CMD_UPDATE                      \
    "UPDATE ical_objs SET"              \
    "  alive        = :alive,"          \
    "  creationdate = :creationdate,"   \
    "  imap_uid     = :imap_uid,"       \
    "  modseq       = :modseq,"         \
    "  createdmodseq = :createdmodseq," \
    "  lock_token   = :lock_token,"     \
    "  lock_owner   = :lock_owner,"     \
    "  lock_ownerid = :lock_ownerid,"   \
    "  lock_expire  = :lock_expire,"    \
    "  comp_type    = :comp_type,"      \
    "  ical_uid     = :ical_uid,"       \
    "  organizer    = :organizer,"      \
    "  dtstart      = :dtstart,"        \
    "  dtend        = :dtend,"          \
    "  comp_flags   = :comp_flags,"     \
    "  sched_tag    = :sched_tag"       \
    " WHERE rowid = :rowid;"

#define CMD_DELETE_JSCALCACHE "DELETE FROM jscal_cache WHERE rowid = :rowid"

#define CMD_UPDATE_JSCAL_TOMBSTONES    \
    "UPDATE jscal_objs SET"            \
    "  alive = 0,"                     \
    "  modseq = :modseq"               \
    " WHERE jscal_objs.rowid = :rowid" \
    "   AND alive > 0"                 \
    "   AND jscal_objs.modseq <= :modseq"

EXPORTED int caldav_write(struct caldav_db *caldavdb, struct caldav_data *cdata)
{
    unsigned comp_flags = _comp_flags_to_num(&cdata->comp_flags);
    struct sqldb_bindval bval[] = {
        { ":rowid",        SQLITE_INTEGER, { .i = cdata->dav.rowid        } },
        { ":alive",        SQLITE_INTEGER, { .i = cdata->dav.alive        } },
        { ":mailbox",      SQLITE_TEXT,    { .s = cdata->dav.mailbox      } },
        { ":resource",     SQLITE_TEXT,    { .s = cdata->dav.resource     } },
        { ":creationdate", SQLITE_INTEGER, { .i = cdata->dav.creationdate } },
        { ":imap_uid",     SQLITE_INTEGER, { .i = cdata->dav.imap_uid     } },
        { ":modseq",       SQLITE_INTEGER, { .i = cdata->dav.modseq       } },
        { ":createdmodseq", SQLITE_INTEGER, { .i = cdata->dav.createdmodseq } },
        { ":lock_token",   SQLITE_TEXT,    { .s = cdata->dav.lock_token   } },
        { ":lock_owner",   SQLITE_TEXT,    { .s = cdata->dav.lock_owner   } },
        { ":lock_ownerid", SQLITE_TEXT,    { .s = cdata->dav.lock_ownerid } },
        { ":lock_expire",  SQLITE_INTEGER, { .i = cdata->dav.lock_expire  } },
        { ":comp_type",    SQLITE_INTEGER, { .i = cdata->comp_type        } },
        { ":ical_uid",     SQLITE_TEXT,    { .s = cdata->ical_uid         } },
        { ":organizer",    SQLITE_TEXT,    { .s = cdata->organizer        } },
        { ":dtstart",      SQLITE_TEXT,    { .s = cdata->dtstart          } },
        { ":dtend",        SQLITE_TEXT,    { .s = cdata->dtend            } },
        { ":sched_tag",    SQLITE_TEXT,    { .s = cdata->sched_tag        } },
        { ":comp_flags",   SQLITE_INTEGER, { .i = comp_flags              } },
        { NULL,            SQLITE_NULL,    { .s = NULL                    } } };

    if (cdata->dav.rowid) {
        int r = sqldb_exec(caldavdb->db, CMD_DELETE_JSCALCACHE, bval, NULL, NULL);
        if (r) return r;
        r = sqldb_exec(caldavdb->db, CMD_UPDATE, bval, NULL, NULL);
        if (r) return r;

        if (!cdata->dav.alive) {
            struct sqldb_bindval bvaljs[] = {
                { ":rowid",  SQLITE_INTEGER, { .i = cdata->dav.rowid  } },
                { ":modseq", SQLITE_INTEGER, { .i = cdata->dav.modseq } },
                { NULL,      SQLITE_NULL,    { .s = NULL              } } };
            r = sqldb_exec(caldavdb->db, CMD_UPDATE_JSCAL_TOMBSTONES,
                    bvaljs, NULL, NULL);
            if (r) return r;
        }
    }
    else {
        int r = sqldb_exec(caldavdb->db, CMD_INSERT, bval, NULL, NULL);
        if (r) return r;
        cdata->dav.rowid = sqldb_lastid(caldavdb->db);
    }

    return 0;
}


#define CMD_DELETE "DELETE FROM ical_objs WHERE rowid = :rowid;"

EXPORTED int caldav_delete(struct caldav_db *caldavdb, unsigned rowid)
{
    struct sqldb_bindval bval[] = {
        { ":rowid", SQLITE_INTEGER, { .i = rowid } },
        { NULL,     SQLITE_NULL,    { .s = NULL  } } };
    int r;

    r = sqldb_exec(caldavdb->db, CMD_DELETE, bval, NULL, NULL);

    return r;
}


#define CMD_DELMBOX "DELETE FROM ical_objs WHERE mailbox = :mailbox;"

EXPORTED int caldav_delmbox(struct caldav_db *caldavdb, const mbentry_t *mbentry)
{
    const char *mailbox = (caldavdb->db->version >= DB_MBOXID_VERSION) ?
        mbentry->uniqueid : mbentry->name;
    struct sqldb_bindval bval[] = {
        { ":mailbox", SQLITE_TEXT, { .s = mailbox } },
        { NULL,       SQLITE_NULL, { .s = NULL    } } };
    int r;

    r = sqldb_exec(caldavdb->db, CMD_DELMBOX, bval, NULL, NULL);

    return r;
}

EXPORTED int caldav_get_updates(struct caldav_db *caldavdb,
                                modseq_t oldmodseq, const mbentry_t *mbentry,
                                int kind, int limit,
                                int (*cb)(void *rock, struct caldav_data *cdata),
                                void *rock)
{
    const char *mailbox = !mbentry ? NULL :
        ((caldavdb->db->version >= DB_MBOXID_VERSION) ?
         mbentry->uniqueid : mbentry->name);
    struct sqldb_bindval bval[] = {
        { ":mailbox",      SQLITE_TEXT,    { .s = mailbox   } },
        { ":modseq",       SQLITE_INTEGER, { .i = oldmodseq } },
        { ":comp_type",    SQLITE_INTEGER, { .i = kind      } },
        /* SQLite interprets a negative limit as unbounded. */
        { ":limit",        SQLITE_INTEGER, { .i = limit > 0 ? limit : -1 } },
        { NULL,            SQLITE_NULL,    { .s = NULL      } }
    };
    static struct caldav_data cdata;
    struct read_rock rrock =
        { caldavdb, &cdata, RROCK_FLAG_TOMBSTONES, cb, rock };
    struct buf sqlbuf = BUF_INITIALIZER;
    int r;

    buf_setcstr(&sqlbuf, CMD_READFIELDS " WHERE");
    if (mailbox) buf_appendcstr(&sqlbuf, " mailbox = :mailbox AND");
    if (kind >= 0) {
        /* Use a negative value to signal that we accept ALL components types */
        buf_appendcstr(&sqlbuf, " comp_type = :comp_type AND");
    }
    if (!oldmodseq) buf_appendcstr(&sqlbuf, " alive = 1 AND");
    buf_appendcstr(&sqlbuf, " modseq > :modseq ORDER BY modseq LIMIT :limit;");

    r = sqldb_exec(caldavdb->db, buf_cstring(&sqlbuf), bval, &read_cb, &rrock);
    buf_free(&sqlbuf);

    if (r) {
        syslog(LOG_ERR, "caldav error %s", error_message(r));
    }
    return r;
}


static void check_mattach_cb(icalcomponent *comp, void *rock)
{
    int *mattach = (int *) rock;

    /* Check for managed attachment */
    if (!*mattach) {
        icalproperty *prop;

        for (prop = icalcomponent_get_first_property(comp, ICAL_ATTACH_PROPERTY);
             prop;
             prop = icalcomponent_get_next_property(comp, ICAL_ATTACH_PROPERTY)) {
            
            if (icalproperty_get_managedid_parameter(prop)) *mattach = 1;
        }
    }
}


#define CMD_INSERT_JSCALOBJS                                            \
    "INSERT INTO jscal_objs ("                                          \
    "  rowid, ical_recurid, alive, modseq, createdmodseq,"              \
    "  dtstart, dtend, ical_guid )"                                     \
    " VALUES ("                                                         \
    "  :rowid, :ical_recurid, :alive, :modseq, :createdmodseq,"         \
    "  :dtstart, :dtend, :ical_guid );"

static int caldav_insert_jscal(struct caldav_db *caldavdb,
                                 struct caldav_jscal *jscal)
{
    struct sqldb_bindval bvalinst[] = {
        { ":rowid",         SQLITE_INTEGER,  { .i = jscal->cdata.dav.rowid } },
        { ":ical_recurid",  SQLITE_TEXT,     { .s = jscal->ical_recurid } },
        { ":alive",         SQLITE_INTEGER,  { .i = jscal->alive } },
        { ":modseq",        SQLITE_INTEGER,  { .i = jscal->modseq  } },
        { ":createdmodseq", SQLITE_INTEGER,  { .i = jscal->createdmodseq } },
        { ":dtstart",       SQLITE_TEXT,     { .s = jscal->dtstart } },
        { ":dtend",         SQLITE_TEXT,     { .s = jscal->dtend } },
        { ":ical_guid",     SQLITE_TEXT,     { .s = jscal->ical_guid } },
        { NULL,             SQLITE_NULL,     { .s = NULL } } };

    return sqldb_exec(caldavdb->db, CMD_INSERT_JSCALOBJS, bvalinst, NULL, NULL);
}

#define CMD_UPDATE_JSCALOBJS            \
    "UPDATE jscal_objs SET"             \
    "  alive        = :alive,"          \
    "  modseq       = :modseq,"         \
    "  createdmodseq = :createdmodseq," \
    "  dtstart      = :dtstart,"        \
    "  dtend        = :dtend,"          \
    "  ical_guid    = :ical_guid"       \
    " WHERE rowid = :rowid AND ical_recurid = :ical_recurid;"

static int caldav_update_jscal(struct caldav_db *caldavdb,
                                 struct caldav_jscal *jscal)
{
    struct sqldb_bindval bvalinst[] = {
        { ":rowid",         SQLITE_INTEGER,  { .i = jscal->cdata.dav.rowid } },
        { ":ical_recurid",  SQLITE_TEXT,     { .s = jscal->ical_recurid } },
        { ":alive",         SQLITE_INTEGER,  { .i = jscal->alive } },
        { ":modseq",        SQLITE_INTEGER,  { .i = jscal->modseq  } },
        { ":createdmodseq", SQLITE_INTEGER,  { .i = jscal->createdmodseq } },
        { ":dtstart",       SQLITE_TEXT,     { .s = jscal->dtstart } },
        { ":dtend",         SQLITE_TEXT,     { .s = jscal->dtend } },
        { ":ical_guid",     SQLITE_TEXT,     { .s = jscal->ical_guid } },
        { NULL,             SQLITE_NULL,     { .s = NULL } } };

    return sqldb_exec(caldavdb->db, CMD_UPDATE_JSCALOBJS, bvalinst, NULL, NULL);
}

#define CMD_SELJSCALOBJS                                          \
    "SELECT rowid, ical_recurid, alive, modseq, createdmodseq,"   \
    "  dtstart, dtend, ical_guid "                                \
    "FROM jscal_objs "                                            \
    "WHERE rowid = :rowid ORDER BY ical_recurid ASC;"

struct read_jscals_rock {
    dynarray_t *jscalobjs;
    strarray_t *strpool;
};

static int read_jscals_cb(sqlite3_stmt *stmt, void *vrock)
{
    struct read_jscals_rock *rock = (struct read_jscals_rock *) vrock;
    struct caldav_jscal jscal = { 0 };

    jscal.cdata.dav.rowid = sqlite3_column_int(stmt, 0);
    strarray_append(rock->strpool, (const char *) sqlite3_column_text(stmt, 1));
    jscal.ical_recurid = strarray_nth(rock->strpool, -1);
    jscal.alive = sqlite3_column_int(stmt, 2);
    jscal.modseq = sqlite3_column_int64(stmt, 3);
    jscal.createdmodseq = sqlite3_column_int64(stmt, 4);
    strarray_append(rock->strpool, (const char *) sqlite3_column_text(stmt, 5));
    jscal.dtstart = strarray_nth(rock->strpool, -1);
    strarray_append(rock->strpool, (const char *) sqlite3_column_text(stmt, 6));
    jscal.dtend = strarray_nth(rock->strpool, -1);
    strarray_append(rock->strpool, (const char *) sqlite3_column_text(stmt, 7));
    jscal.ical_guid = strarray_nth(rock->strpool, -1);

    dynarray_append(rock->jscalobjs, &jscal);
    return 0;
}

#define JSCALOBJS_FIELDS          \
    " jscal_objs.ical_recurid,"   \
    " jscal_objs.alive,"          \
    " jscal_objs.modseq,"         \
    " jscal_objs.createdmodseq,"  \
    " jscal_objs.dtstart,"        \
    " jscal_objs.dtend,"          \
    " jscal_objs.ical_guid,"

#define JSCALCACHE_FIELDS         \
    " jscal_cache.version,"       \
    " jscal_cache.data,"

#define CMD_READFIELDS_JSCALOBJS                                   \
    "SELECT "                                                      \
      ICALOBJS_FIELDS JSCALOBJS_FIELDS JSCALCACHE_FIELDS           \
      "NULL"                                                       \
    " FROM ical_objs "                                             \
    "   LEFT JOIN jscal_objs"                                      \
    "   ON (ical_objs.rowid = jscal_objs.rowid)"                   \
    "   LEFT JOIN jscal_cache"                                     \
    "   ON (jscal_objs.rowid = jscal_cache.rowid "                 \
    "     AND jscal_objs.ical_recurid = jscal_cache.ical_recurid = :ical_recurid" \
    "     AND jscal_cache.userid = :cache_userid)"

#define CMD_READFIELDS_JSCALOBJS_NOCACHE                           \
    "SELECT "                                                      \
      ICALOBJS_FIELDS JSCALOBJS_FIELDS "NULL, NULL,"               \
      "NULL"                                                       \
    " FROM ical_objs "                                             \
    "   LEFT JOIN jscal_objs"                                      \
    "   ON (ical_objs.rowid = jscal_objs.rowid)"

struct read_jscal_rock {
    struct caldav_db *db;
    struct caldav_jscal jscal;
    caldav_jscal_cb_t *cb;
    void *rock;
};

static int read_jscal_cb(sqlite3_stmt *stmt, void *rock)
{
    struct read_jscal_rock *rrock = (struct read_jscal_rock *) rock;
    struct caldav_db *db = rrock->db;
    struct caldav_jscal *jscal = &rrock->jscal;

    memset(jscal, 0, sizeof(struct caldav_jscal));

    read_cdata(stmt, db, 0, &jscal->cdata);

    jscal->ical_recurid = (const char *) sqlite3_column_text(stmt, 19);
    jscal->alive = sqlite3_column_int(stmt, 20);
    jscal->modseq = sqlite3_column_int64(stmt, 21);
    jscal->createdmodseq = sqlite3_column_int64(stmt, 22);
    jscal->dtstart = (const char *) sqlite3_column_text(stmt, 23);
    jscal->dtend = (const char *) sqlite3_column_text(stmt, 24);
    jscal->ical_guid = (const char *) sqlite3_column_text(stmt, 25);
    jscal->cacheversion = sqlite3_column_int(stmt, 26);
    jscal->cachedata = (const char *) sqlite3_column_text(stmt, 27);

    return rrock->cb(rrock->rock, jscal);
}

EXPORTED int caldav_foreach_jscal(struct caldav_db *caldavdb,
                                  const char *cache_userid,
                                  struct caldav_jscal_filter *filter,
                                  enum caldav_sort* sort, size_t nsort,
                                  caldav_jscal_cb_t *cb, void *rock)
{
    struct sqldb_bindval bval[] = {
        { ":mailbox",      SQLITE_TEXT,    { .s = NULL } },
        { ":ical_uid",     SQLITE_TEXT,    { .s = NULL } },
        { ":ical_recurid", SQLITE_TEXT,    { .s = NULL } },
        { ":imap_uid",     SQLITE_INTEGER, { .i = 0    } },
        { ":after",        SQLITE_TEXT,    { .s = NULL } },
        { ":before",       SQLITE_TEXT,    { .s = NULL } },
        { ":cache_userid", SQLITE_TEXT,    { .s = cache_userid } },
        { ":aftermodseq",  SQLITE_INTEGER, { .i = 0 } },
        { ":maxcount",     SQLITE_INTEGER, { .i = 0 } },
        { NULL,            SQLITE_NULL,    { .s = NULL } } };

    struct buf stmt = BUF_INITIALIZER;
    buf_setcstr(&stmt, cache_userid ?
            CMD_READFIELDS_JSCALOBJS : CMD_READFIELDS_JSCALOBJS_NOCACHE);

    if (filter) {
        buf_appendcstr(&stmt, " WHERE 1 = 1");
        if (filter->mbentry) {
            buf_appendcstr(&stmt, " AND mailbox = :mailbox");
            bval[0].val.s = caldavdb->db->version >= DB_MBOXID_VERSION ?
                filter->mbentry->uniqueid : filter->mbentry->name;
        }
        if (filter->ical_uid) {
            buf_appendcstr(&stmt, " AND ical_uid = :ical_uid");
            bval[1].val.s = filter->ical_uid;
        }
        if (filter->ical_recurid) {
            buf_appendcstr(&stmt, " AND ical_recurid = :ical_recurid");
            bval[2].val.s = filter->ical_recurid;
        }
        if (filter->imap_uid) {
            buf_appendcstr(&stmt, " AND imap_uid = :imap_uid");
            bval[3].val.i = filter->imap_uid;
        }
        if (filter->after || filter->before) {
            icaltimezone *utc = icaltimezone_get_utc_timezone();
            icaltimetype dt;
            if (filter->after) {
                buf_appendcstr(&stmt, " AND jscal_objs.dtend > :after");
                dt = icaltime_from_timet_with_zone(*filter->after, 0, utc);
                bval[4].val.s = icaltime_as_ical_string(dt);
            }
            if (filter->before) {
                buf_appendcstr(&stmt, " AND jscal_objs.dtstart < :before");
                dt = icaltime_from_timet_with_zone(*filter->before, 0, utc);
                bval[5].val.s = icaltime_as_ical_string(dt);
            }
        }
        if (filter->aftermodseq) {
            buf_appendcstr(&stmt, " AND jscal_objs.modseq > :aftermodseq");
            bval[7].val.i = filter->aftermodseq;
        }
        if (!filter->tombstones) {
            buf_appendcstr(&stmt, " AND jscal_objs.alive = 1");
        }
    }
    if (nsort) {
        buf_appendcstr(&stmt, " ORDER BY ");
        size_t i;
        for (i = 0; i < nsort; i++) {
            if (i) buf_appendcstr(&stmt, ", ");
            switch (sort[i] & ~CAL_SORT_DESC) {
                case CAL_SORT_ICAL_UID:
                    buf_appendcstr(&stmt, "ical_uid");
                    break;
                case CAL_SORT_START:
                    buf_appendcstr(&stmt, "jscal_objs.dtstart");
                    break;
                case CAL_SORT_MAILBOX:
                    buf_appendcstr(&stmt, "mailbox");
                    break;
                case CAL_SORT_IMAP_UID:
                    buf_appendcstr(&stmt, "imap_uid");
                    break;
                case CAL_SORT_MODSEQ:
                    buf_appendcstr(&stmt, "jscal_objs.modseq");
                    break;
                default:
                    continue;
            }
            buf_appendcstr(&stmt, sort[i] & CAL_SORT_DESC ? " DESC" : " ASC");
        }
    }
    if (filter && filter->maxcount) {
        buf_appendcstr(&stmt, " LIMIT :maxcount");
        bval[8].val.i = filter->maxcount;
    }

    buf_putc(&stmt, ';');

    struct read_jscal_rock rrock = {
        .db = caldavdb,
        .cb = cb,
        .rock = rock
    };
    int r = sqldb_exec(caldavdb->db, buf_cstring(&stmt), bval,
            &read_jscal_cb, &rrock);
    buf_free(&stmt);
    return r;
}

static int jscal_cmp_ical_recurid(const void *va, const void *vb)
{
    return strcmpsafe(((struct caldav_jscal*)va)->ical_recurid,
                      ((struct caldav_jscal*)vb)->ical_recurid);
}

EXPORTED int caldav_writeical_jmap(struct caldav_db *caldavdb,
                                   struct caldav_data *cdata,
                                   icalcomponent *ical)
{
    if (cdata->comp_type != CAL_COMP_VEVENT) return 0;
    assert(cdata->dav.rowid);

    dynarray_t old_jscals;
    dynarray_t new_jscals;
    dynarray_init(&old_jscals, sizeof(struct caldav_jscal));
    dynarray_init(&new_jscals, sizeof(struct caldav_jscal));

    strarray_t strpool = STRARRAY_INITIALIZER;
    icalcomponent *comp;
    icaltimezone *utc = NULL;
    int r = 0;

    /* Determine current JMAP objects, ordered ascending by recurid */
    struct sqldb_bindval bval[] = {
        { ":rowid",   SQLITE_INTEGER, { .i = cdata->dav.rowid } },
        { NULL,       SQLITE_NULL,    { .s = NULL  } }
    };
    struct read_jscals_rock rock = { &old_jscals, &strpool };
    r = sqldb_exec(caldavdb->db, CMD_SELJSCALOBJS, bval,
            read_jscals_cb, &rock);
    if (r) goto done;

    /* Determine new JMAP objects, ordered ascending by recurid */
    icalcomponent_kind kind;
    for (comp = icalcomponent_get_first_real_component(ical);
         comp;
         comp = icalcomponent_get_next_component(ical, kind)) {

        kind = icalcomponent_isa(comp);

        const char *icalstr = icalcomponent_as_ical_string(comp);
        struct message_guid guid = MESSAGE_GUID_INITIALIZER;
        message_guid_generate(&guid, icalstr, strlen(icalstr));
        strarray_append(&strpool, message_guid_encode(&guid));
        const char *ical_guid = strarray_nth(&strpool, -1);

        icalproperty *prop =
            icalcomponent_get_first_property(comp, ICAL_RECURRENCEID_PROPERTY);
        if (!prop) {
            /* Found main component */
            dynarray_truncate(&new_jscals, 0);
            struct caldav_jscal jscal = {
                .cdata.dav.rowid = cdata->dav.rowid,
                .ical_recurid = "",
                .dtstart = cdata->dtstart,
                .dtend = cdata->dtend,
                .alive = cdata->dav.alive,
                .modseq = cdata->dav.modseq,
                .createdmodseq = cdata->dav.createdmodseq,
                .ical_guid = ical_guid,
            };
            dynarray_append(&new_jscals, &jscal);
            break;
        }

        /* Found recurrence instance */
        if (!utc) utc = icaltimezone_get_utc_timezone();
        icaltimetype recurid = icalproperty_get_recurrenceid(prop);
        icaltimetype dtstart = icalcomponent_get_dtstart(comp);
        dtstart = icaltime_convert_to_zone(dtstart, utc);
        icaltimetype dtend = icalcomponent_get_dtend(comp);
        dtend = icaltime_convert_to_zone(dtend, utc);

        struct caldav_jscal jscal = {
            .cdata.dav.rowid = cdata->dav.rowid,
            .ical_recurid = icaltime_as_ical_string(recurid),
            .dtstart = icaltime_as_ical_string(dtstart),
            .dtend = icaltime_as_ical_string(dtend),
            .alive = cdata->dav.alive,
            .modseq = cdata->dav.modseq,
            .createdmodseq = cdata->dav.createdmodseq,
            .ical_guid = ical_guid,
        };
        dynarray_append(&new_jscals, &jscal);
    }
    qsort(new_jscals.data, new_jscals.count,
            sizeof(struct caldav_jscal), jscal_cmp_ical_recurid);

    /* Determine which rows to insert and update. We never delete here. */
    ptrarray_t update = PTRARRAY_INITIALIZER;
    ptrarray_t insert = PTRARRAY_INITIALIZER;
    int old_i = 0;
    int new_i = 0;
    while (old_i < dynarray_size(&old_jscals) &&
           new_i < dynarray_size(&new_jscals)) {
        struct caldav_jscal *old_jscal = dynarray_nth(&old_jscals, old_i);
        struct caldav_jscal *new_jscal = dynarray_nth(&new_jscals, new_i);
        int cmp = strcmp(old_jscal->ical_recurid, new_jscal->ical_recurid);

        if (!cmp) {
            if (strcmp(old_jscal->ical_guid, new_jscal->ical_guid)) {
                // instance or main event got updated
                ptrarray_append(&update, new_jscal);
            }
            old_i++;
            new_i++;
            continue;
        }

        if (!new_jscal->ical_recurid[0]) {
            // old standalone instances got replaced with main event
            ptrarray_append(&insert, new_jscal);
            new_i++;
        }
        else if (cmp < 0) {
            // old instance or main event got removed
            if (old_jscal->alive) {
                old_jscal->alive = 0;
                old_jscal->modseq = cdata->dav.modseq;
                ptrarray_append(&update, old_jscal);
            }
            old_i++;
        }
        else {
            // new standalone instance got added
            new_jscal->createdmodseq = cdata->dav.modseq;
            ptrarray_append(&insert, new_jscal);
            new_i++;
        }
    }
    for ( ; old_i < dynarray_size(&old_jscals); old_i++) {
        struct caldav_jscal *old_jscal = dynarray_nth(&old_jscals, old_i);
        if (old_jscal->alive) {
            old_jscal->alive = 0;
            old_jscal->modseq = cdata->dav.modseq;
            ptrarray_append(&update, old_jscal);
        }
    }
    for ( ; new_i < dynarray_size(&new_jscals); new_i++) {
        struct caldav_jscal *new_jscal = dynarray_nth(&new_jscals, new_i);
        new_jscal->createdmodseq = cdata->dav.modseq;
        ptrarray_append(&insert, new_jscal);
    }

    /* Write changes */
    int i;
    for (i = 0; i < ptrarray_size(&insert); i++) {
        r = caldav_insert_jscal(caldavdb, ptrarray_nth(&insert, i));
        if (r) goto done;
    }
    for (i = 0; i < ptrarray_size(&update); i++) {
        r = caldav_update_jscal(caldavdb, ptrarray_nth(&update, i));
        if (r) goto done;
    }

done:
    dynarray_fini(&old_jscals);
    dynarray_fini(&new_jscals);
    ptrarray_fini(&insert);
    ptrarray_fini(&update);
    strarray_fini(&strpool);
    return r;
}

EXPORTED int caldav_writeical(struct caldav_db *caldavdb, struct caldav_data *cdata,
                              icalcomponent *ical)
{
    icalcomponent *comp = icalcomponent_get_first_real_component(ical);
    icalcomponent_kind kind;
    icalproperty *prop;
    unsigned mykind = 0, recurring = 0, transp = 0, status = 0, mattach = 0;
    struct icalperiodtype span;

    /* Get iCalendar UID */
    cdata->ical_uid = icalcomponent_get_uid(comp);

    /* Get component type and optional status */
    kind = icalcomponent_isa(comp);
    switch (kind) {
    case ICAL_VEVENT_COMPONENT:
        mykind = CAL_COMP_VEVENT;
        switch (icalcomponent_get_status(comp)) {
        case ICAL_STATUS_CANCELLED: status = CAL_STATUS_CANCELED; break;
        case ICAL_STATUS_TENTATIVE: status = CAL_STATUS_TENTATIVE; break;
        default: status = CAL_STATUS_BUSY; break;
        }
        break;
    case ICAL_VTODO_COMPONENT: mykind = CAL_COMP_VTODO; break;
    case ICAL_VJOURNAL_COMPONENT: mykind = CAL_COMP_VJOURNAL; break;
    case ICAL_VFREEBUSY_COMPONENT: mykind = CAL_COMP_VFREEBUSY; break;
    case ICAL_VAVAILABILITY_COMPONENT: mykind = CAL_COMP_VAVAILABILITY; break;
    case ICAL_VPOLL_COMPONENT: mykind = CAL_COMP_VPOLL; break;
    default: break;
    }
    cdata->comp_type = mykind;
    cdata->comp_flags.status = status;

    cdata->organizer = NULL;

    /* Get organizer */
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (prop) {
        cdata->organizer = icalproperty_get_organizer(prop);
        if (cdata->organizer && !strncasecmp(cdata->organizer, "mailto:", 7))
            cdata->organizer += 7;
    }
    /* maybe it's only on a sub event */
    icalcomponent *nextcomp;
    while (!cdata->organizer &&
           (nextcomp = icalcomponent_get_next_component(ical, kind))) {
        prop = icalcomponent_get_first_property(nextcomp, ICAL_ORGANIZER_PROPERTY);
        if (prop) {
            cdata->organizer = icalproperty_get_organizer(prop);
            if (cdata->organizer && !strncasecmp(cdata->organizer, "mailto:", 7))
                cdata->organizer += 7;
        }
    }

    /* Get transparency */
    prop = icalcomponent_get_first_property(comp, ICAL_TRANSP_PROPERTY);
    if (prop) {
        icalvalue *transp_val = icalproperty_get_value(prop);

        switch (icalvalue_get_transp(transp_val)) {
        case ICAL_TRANSP_TRANSPARENT:
        case ICAL_TRANSP_TRANSPARENTNOCONFLICT:
            transp = 1;
            break;

        default:
            transp = 0;
            break;
        }
    }
    cdata->comp_flags.transp = transp;

    /* Get span of component set and check for managed attachments */
    span = icalrecurrenceset_get_utc_timespan(ical, kind, NULL, &recurring,
                                              &check_mattach_cb, &mattach);

    cdata->dtstart = icaltime_as_ical_string(span.start);
    cdata->dtend = icaltime_as_ical_string(span.end);
    cdata->comp_flags.recurring = recurring;
    cdata->comp_flags.mattach = mattach;

    /* Get default alerts property in main component or override */
    cdata->comp_flags.defaultalerts = 0;
    for (comp = icalcomponent_get_first_real_component(ical);
         comp && !cdata->comp_flags.defaultalerts;
         comp = icalcomponent_get_next_component(ical, kind)) {

        cdata->comp_flags.defaultalerts =
            icalcomponent_read_usedefaultalerts(comp) > 0;
    }

    int r = caldav_write(caldavdb, cdata);
    if (!r) r = caldav_writeical_jmap(caldavdb, cdata, ical);
    return r;
}


EXPORTED char *caldav_mboxname(const char *userid, const char *name)
{
    struct buf boxbuf = BUF_INITIALIZER;
    char *res = NULL;

    buf_setcstr(&boxbuf, config_getstring(IMAPOPT_CALENDARPREFIX));

    if (name) {
        size_t len = strcspn(name, "/");
        buf_putc(&boxbuf, '.');
        buf_appendmap(&boxbuf, name, len);
    }

    res = mboxname_user_mbox(userid, buf_cstring(&boxbuf));

    buf_free(&boxbuf);

    return res;
}

#define CMD_DELETE_JSCALCACHE_USER \
    "DELETE FROM jscal_cache" \
    " WHERE rowid = :rowid AND userid = :userid"

#define CMD_INSERT_JSCALCACHE_USER                         \
    "INSERT INTO jscal_cache ("                            \
    " rowid, ical_recurid, userid, version, data)"         \
    "VALUES ("                                             \
    " :rowid, :ical_recurid, :userid, :version, :data);"

EXPORTED int caldav_write_jscalcache(struct caldav_db *caldavdb,
                                     int rowid,
                                     const char *ical_recurid,
                                     const char *userid,
                                     int version,
                                     const char *data)
{
    struct sqldb_bindval bval[] = {
        { ":rowid",        SQLITE_INTEGER, { .i = rowid  } },
        { ":ical_recurid", SQLITE_TEXT,    { .s = ical_recurid } },
        { ":userid",       SQLITE_TEXT,    { .s = userid } },
        { ":version",      SQLITE_INTEGER, { .i = version } },
        { ":data",         SQLITE_TEXT,    { .s = data   } },
        { NULL,            SQLITE_NULL,    { .s = NULL   } } };
    int r;

    /* clean up existing records if any */
    r = sqldb_exec(caldavdb->db, CMD_DELETE_JSCALCACHE_USER, bval, NULL, NULL);
    if (r) return r;

    /* insert the cache record */
    return sqldb_exec(caldavdb->db, CMD_INSERT_JSCALCACHE_USER, bval, NULL, NULL);
}

struct shareacls_rock {
    const char *userid;
    char *principalname;
    char *principalacl;
    char *newprincipalacl;
    char *outboxname;
    char *outboxacl;
    char *newoutboxacl;
    hash_table user_access;
};

#define CALSHARE_WANTSCHED 1
#define CALSHARE_HAVESCHED 2
#define CALSHARE_WANTPRIN 4
#define CALSHARE_HAVEPRIN 8

static int _add_shareacls(const mbentry_t *mbentry, void *rock)
{
    struct shareacls_rock *share = rock;

    char *acl = xstrdup(mbentry->acl);

    int isprincipal = !strcmp(mbentry->name, share->principalname);
    int isoutbox = !strcmp(mbentry->name, share->outboxname);

    if (isprincipal) {
        share->principalacl = xstrdup(acl);
        share->newprincipalacl = xstrdup(acl);
    }

    if (isoutbox) {
        share->outboxacl = xstrdup(acl);
        share->newoutboxacl = xstrdup(acl);
    }

    char *userid;
    char *nextid = NULL;
    for (userid = acl; userid; userid = nextid) {
        char *rightstr;
        int access;

        rightstr = strchr(userid, '\t');
        if (!rightstr) break;
        *rightstr++ = '\0';

        nextid = strchr(rightstr, '\t');
        if (!nextid) break;
        *nextid++ = '\0';

        /* skip system users and owner */
        if (is_system_user(userid)) continue;
        if (!strcmp(userid, share->userid)) continue;

        cyrus_acl_strtomask(rightstr, &access);

        uintptr_t have = (uintptr_t)hash_lookup(userid, &share->user_access);
        uintptr_t set = have;

        // if it's the principal, we have each user with principal read access
        if (isprincipal) {
            if ((access & DACL_READ) == DACL_READ)
                set |= CALSHARE_HAVEPRIN;
        }
        // if it's the Outbox, we have each user with reply ability
        else if (isoutbox) {
            if ((access & (DACL_INVITE|DACL_REPLY)) == (DACL_INVITE|DACL_REPLY))
                set |= CALSHARE_HAVESCHED;
        }
        // and if they can see anything else, then we NEED the above!
        else {
            if (access & ACL_READ)
                set |= CALSHARE_WANTPRIN;
            if (access & ACL_INSERT)
                set |= CALSHARE_WANTSCHED;
        }

        if (set != have) hash_insert(userid, (void *)set, &share->user_access);
    }

    free(acl);
    return 0;
}

static void _update_acls(const char *userid, void *data, void *rock)
{
    struct shareacls_rock *share = rock;
    uintptr_t aclstatus = (uintptr_t)data;

    if ((aclstatus & CALSHARE_WANTSCHED) && !(aclstatus & CALSHARE_HAVESCHED)) {
        cyrus_acl_set(&share->newoutboxacl, userid, ACL_MODE_ADD, (DACL_INVITE|DACL_REPLY), NULL, NULL);
    }

    if (!(aclstatus & CALSHARE_WANTSCHED) && (aclstatus & CALSHARE_HAVESCHED)) {
        cyrus_acl_set(&share->newoutboxacl, userid, ACL_MODE_REMOVE, (DACL_INVITE|DACL_REPLY), NULL, NULL);
    }

    if ((aclstatus & CALSHARE_WANTPRIN) && !(aclstatus & CALSHARE_HAVEPRIN)) {
        cyrus_acl_set(&share->newprincipalacl, userid, ACL_MODE_ADD, DACL_READ, NULL, NULL);
    }

    if (!(aclstatus & CALSHARE_WANTPRIN) && (aclstatus & CALSHARE_HAVEPRIN)) {
        cyrus_acl_set(&share->newprincipalacl, userid, ACL_MODE_REMOVE, DACL_READ, NULL, NULL);
    }
}

/* update the share acls.  We do this by:
 * 1) iterating all the calendars for this user, looking at all the ACLs and
 *    tracking for each user mentioned, whether they have or need principal
 *    access or scheduling access.
 * 2) when we see the inbox and outbox, clone the ACLs.
 * 3) iterate all seen users, and decide whether we need to change the ACLs
 *    for either of those mailboxes.
 */
EXPORTED int caldav_update_shareacls(const char *userid)
{
    struct shareacls_rock rock = {
        userid,
        NULL, NULL, NULL,
        NULL, NULL, NULL,
        HASH_TABLE_INITIALIZER
    };
    construct_hash_table(&rock.user_access, 10, 0);
    rock.principalname = caldav_mboxname(userid, NULL);
    rock.outboxname = caldav_mboxname(userid, SCHED_OUTBOX);

    // find out what the values should be
    int r = mboxlist_mboxtree(rock.principalname, _add_shareacls, &rock, 0);

    // did we find the ACLs?  If not, bail now!
    if (!rock.principalacl || !rock.outboxacl) {
        r = IMAP_MAILBOX_NONEXISTENT;
        goto done;
    }

    // change the ACLs as required
    hash_enumerate(&rock.user_access, _update_acls, &rock);

    if (strcmp(rock.principalacl, rock.newprincipalacl)) {
        r = mboxlist_updateacl_raw(rock.principalname, rock.newprincipalacl);
        if (r) goto done;
    }

    if (strcmp(rock.outboxacl, rock.newoutboxacl)) {
        r = mboxlist_updateacl_raw(rock.outboxname, rock.newoutboxacl);
        if (r) goto done;
    }

done:
    free(rock.principalname);
    free(rock.principalacl);
    free(rock.newprincipalacl);
    free(rock.outboxname);
    free(rock.outboxacl);
    free(rock.newoutboxacl);
    free_hash_table(&rock.user_access, NULL);

    return r;
}


EXPORTED const char *caldav_comp_type_as_string(unsigned comp_type)
{
    switch (comp_type) {
        /* "Real" components */
        case CAL_COMP_VEVENT:
            return "VEVENT";
        case CAL_COMP_VTODO:
            return "VTODO";
        case CAL_COMP_VJOURNAL:
            return "VJOURNAL";
        case CAL_COMP_VFREEBUSY:
            return "VFREEBUSY";
        case CAL_COMP_VAVAILABILITY:
            return "VAVAILABILITY";
        case CAL_COMP_VPOLL:
            return "VPOLL";
        /* Other components */
        case CAL_COMP_VALARM:
            return "VALARM";
        case CAL_COMP_VTIMEZONE:
            return "VTIMEZONE";
        case CAL_COMP_VCALENDAR:
            return "VCALENDAR";
        default:
            return NULL;
    }
}

