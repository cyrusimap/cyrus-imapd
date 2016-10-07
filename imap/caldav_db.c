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

#include <syslog.h>
#include <string.h>

#include <libical/ical.h>

#include "caldav_alarm.h"
#include "caldav_db.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "httpd.h"
#include "http_dav.h"
#include "ical_support.h"
#include "libconfig.h"
#include "mboxname.h"
#include "util.h"
#include "xstrlcat.h"
#include "xmalloc.h"


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
time_t caldav_epoch = -1;
time_t caldav_eternity = -1;

EXPORTED int caldav_init(void)
{
    int r;
    struct icaltimetype date;

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&caldav_namespace, 1))) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EC_CONFIG);
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
    return r;
}


EXPORTED int caldav_done(void)
{
    caldav_alarm_done();
    return sqldb_done();
}

EXPORTED struct caldav_db *caldav_open_userid(const char *userid)
{
    struct caldav_db *caldavdb = NULL;

    sqldb_t *db = dav_open_userid(userid);
    if (!db) return NULL;

    caldavdb = xzmalloc(sizeof(struct caldav_db));
    caldavdb->db = db;

    /* Construct mbox name corresponding to userid's scheduling Inbox */
    caldavdb->sched_inbox = caldav_mboxname(userid, SCHED_INBOX);

    return caldavdb;
}

/* Open DAV DB corresponding to userid */
EXPORTED struct caldav_db *caldav_open_mailbox(struct mailbox *mailbox)
{
    struct caldav_db *caldavdb = NULL;
    char *userid = mboxname_to_userid(mailbox->name);

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

    r = sqldb_close(&caldavdb->db);

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

static const char *column_text_to_buf(const char *text, struct buf *buf)
{
    if (text) {
        buf_setcstr(buf, text);
        text = buf_cstring(buf);
    }

    return text;
}

static void _num_to_comp_flags(struct comp_flags *flags, unsigned num)
{
    flags->recurring = num & 1;
    flags->transp = (num >> 1) & 1;
    flags->status = (num >> 2) & 3;
    flags->tzbyref = (num >> 4) & 1;
    flags->mattach = (num >> 5) & 1;
}

static unsigned _comp_flags_to_num(struct comp_flags *flags)
{
   return (flags->recurring & 1)
       + ((flags->transp & 1) << 1)
       + ((flags->status & 3) << 2)
       + ((flags->tzbyref & 1) << 4)
       + ((flags->mattach & 1) << 5);
}

#define CMD_READFIELDS                                                  \
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"          \
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"              \
    "  comp_type, ical_uid, organizer, dtstart, dtend,"                 \
    "  comp_flags, sched_tag, alive, modseq"                            \
    " FROM ical_objs"                                                   \

static int read_cb(sqlite3_stmt *stmt, void *rock)
{
    struct read_rock *rrock = (struct read_rock *) rock;
    struct caldav_db *db = rrock->db;
    struct caldav_data *cdata = rrock->cdata;
    int r = 0;

    memset(cdata, 0, sizeof(struct caldav_data));

    cdata->dav.alive = sqlite3_column_int(stmt, 16);
    cdata->dav.modseq = sqlite3_column_int(stmt, 17);
    if (!(rrock->flags && RROCK_FLAG_TOMBSTONES) && !cdata->dav.alive)
        return 0;

    cdata->dav.rowid = sqlite3_column_int(stmt, 0);
    cdata->dav.creationdate = sqlite3_column_int(stmt, 1);
    cdata->dav.imap_uid = sqlite3_column_int(stmt, 4);
    cdata->dav.lock_expire = sqlite3_column_int(stmt, 8);
    cdata->comp_type = sqlite3_column_int(stmt, 9);
    _num_to_comp_flags(&cdata->comp_flags, sqlite3_column_int(stmt, 14));

    if (rrock->cb) {
        /* We can use the column data directly for the callback */
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
        r = rrock->cb(rrock->rock, cdata);
    }
    else {
        /* For single row SELECTs like caldav_read(),
         * we need to make a copy of the column data before
         * it gets flushed by sqlite3_step() or sqlite3_reset() */
        cdata->dav.mailbox =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 2),
                               &db->mailbox);
        cdata->dav.resource =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 3),
                               &db->resource);
        cdata->dav.lock_token =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 5),
                               &db->lock_token);
        cdata->dav.lock_owner =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 6),
                               &db->lock_owner);
        cdata->dav.lock_ownerid =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 7),
                               &db->lock_ownerid);
        cdata->ical_uid =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 10),
                               &db->ical_uid);
        cdata->organizer =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 11),
                               &db->organizer);
        cdata->dtstart =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 12),
                               &db->dtstart);
        cdata->dtend =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 13),
                               &db->dtend);
        cdata->sched_tag =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 15),
                               &db->sched_tag);
    }

    return r;
}


#define CMD_SELRSRC CMD_READFIELDS \
    " WHERE mailbox = :mailbox AND resource = :resource;"

EXPORTED int caldav_lookup_resource(struct caldav_db *caldavdb,
                           const char *mailbox, const char *resource,
                           struct caldav_data **result,
                           int tombstones)
{
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
    cdata.dav.mailbox = mailbox;
    cdata.dav.resource = resource;

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

EXPORTED int caldav_foreach(struct caldav_db *caldavdb, const char *mailbox,
                            caldav_cb_t *cb, void *rock)
{
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

#define CMD_SELRANGE_MBOX CMD_READFIELDS \
    " WHERE dtend > :after AND dtstart < :before " \
    " AND mailbox = :mailbox AND alive = 1;"

#define CMD_SELRANGE CMD_READFIELDS \
    " WHERE dtend > :after AND dtstart < :before " \
    " AND alive = 1;"

EXPORTED int caldav_foreach_timerange(struct caldav_db *caldavdb,
                                      const char *mailbox,
                                      time_t after, time_t before,
                                      caldav_cb_t *cb, void *rock)
{
    struct sqldb_bindval bval[] = {
        { ":after",     SQLITE_TEXT, { .s = NULL    } },
        { ":before",   SQLITE_TEXT, { .s = NULL    } },
        { ":mailbox", SQLITE_TEXT, { .s = mailbox } },
        { NULL,       SQLITE_NULL, { .s = NULL    } } };
    struct caldav_data cdata;
    struct read_rock rrock = { caldavdb, &cdata, 0, cb, rock };
    icaltimetype dtafter, dtbefore;
    icaltimezone *utc = icaltimezone_get_utc_timezone();

    dtafter = icaltime_from_timet_with_zone(after, 0, utc);
    dtbefore= icaltime_from_timet_with_zone(before, 0, utc);

    bval[0].val.s = icaltime_as_ical_string(dtafter);
    bval[1].val.s = icaltime_as_ical_string(dtbefore);

    /* XXX - if 'before' defines the zero second of a day, a full-day
     * event starting on that day matches. That's not entirely correct,
     * since 'before' is defined to be exclusive. */

    /* XXX - tombstones */

    if (mailbox) {
        return sqldb_exec(caldavdb->db, CMD_SELRANGE_MBOX, bval, &read_cb, &rrock);
    } else {
        return sqldb_exec(caldavdb->db, CMD_SELRANGE, bval, &read_cb, &rrock);
    }
}


#define CMD_INSERT                                                      \
    "INSERT INTO ical_objs ("                                           \
    "  alive, mailbox, resource, creationdate, imap_uid, modseq,"       \
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"              \
    "  comp_type, ical_uid, organizer, dtstart, dtend,"                 \
    "  comp_flags, sched_tag )"                                         \
    " VALUES ("                                                         \
    "  :alive, :mailbox, :resource, :creationdate, :imap_uid, :modseq," \
    "  :lock_token, :lock_owner, :lock_ownerid, :lock_expire,"          \
    "  :comp_type, :ical_uid, :organizer, :dtstart, :dtend,"            \
    "  :comp_flags, :sched_tag );"

#define CMD_UPDATE                      \
    "UPDATE ical_objs SET"              \
    "  alive        = :alive,"          \
    "  creationdate = :creationdate,"   \
    "  imap_uid     = :imap_uid,"       \
    "  modseq       = :modseq,"         \
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

EXPORTED int caldav_write(struct caldav_db *caldavdb, struct caldav_data *cdata)
{
    int comp_flags = _comp_flags_to_num(&cdata->comp_flags);
    struct sqldb_bindval bval[] = {
        { ":rowid",        SQLITE_INTEGER, { .i = cdata->dav.rowid        } },
        { ":alive",        SQLITE_INTEGER, { .i = cdata->dav.alive        } },
        { ":mailbox",      SQLITE_TEXT,    { .s = cdata->dav.mailbox      } },
        { ":resource",     SQLITE_TEXT,    { .s = cdata->dav.resource     } },
        { ":creationdate", SQLITE_INTEGER, { .i = cdata->dav.creationdate } },
        { ":imap_uid",     SQLITE_INTEGER, { .i = cdata->dav.imap_uid     } },
        { ":modseq",       SQLITE_INTEGER, { .i = cdata->dav.modseq       } },
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
        int r = sqldb_exec(caldavdb->db, CMD_UPDATE, bval, NULL, NULL);
        if (r) return r;
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

EXPORTED int caldav_delmbox(struct caldav_db *caldavdb, const char *mailbox)
{
    struct sqldb_bindval bval[] = {
        { ":mailbox", SQLITE_TEXT, { .s = mailbox } },
        { NULL,       SQLITE_NULL, { .s = NULL    } } };
    int r;

    r = sqldb_exec(caldavdb->db, CMD_DELMBOX, bval, NULL, NULL);

    return r;
}


/* Get time period (start/end) of a component based in RFC 4791 Sec 9.9 */
EXPORTED void caldav_get_period(icalcomponent *comp, icalcomponent_kind kind,
                       struct icalperiodtype *period)
{
    icaltimezone *utc = icaltimezone_get_utc_timezone();

    period->start =
        icaltime_convert_to_zone(icalcomponent_get_dtstart(comp), utc);
    period->end =
        icaltime_convert_to_zone(icalcomponent_get_dtend(comp), utc);
    period->duration = icaldurationtype_null_duration();

    switch (kind) {
    case ICAL_VEVENT_COMPONENT:
        if (icaltime_is_null_time(period->end)) {
            /* No DTEND or DURATION */
            if (icaltime_is_date(period->start)) {
                /* DTSTART is not DATE-TIME */
                struct icaldurationtype dur = icaldurationtype_null_duration();

                dur.days = 1;
                period->end = icaltime_add(period->start, dur);
            }
            else
                memcpy(&period->end, &period->start, sizeof(struct icaltimetype));
        }
        break;

#ifdef HAVE_VPOLL
    case ICAL_VPOLL_COMPONENT:
#endif
    case ICAL_VTODO_COMPONENT: {
        struct icaltimetype due = (kind == ICAL_VPOLL_COMPONENT) ?
            icalcomponent_get_dtend(comp) : icalcomponent_get_due(comp);

        if (!icaltime_is_null_time(period->start)) {
            /* Has DTSTART */
            if (icaltime_is_null_time(period->end)) {
                /* No DURATION */
                memcpy(&period->end, &period->start,
                       sizeof(struct icaltimetype));

                if (!icaltime_is_null_time(due)) {
                    /* Has DUE (DTEND for VPOLL) */
                    if (icaltime_compare(due, period->start) < 0)
                        memcpy(&period->start, &due, sizeof(struct icaltimetype));
                    if (icaltime_compare(due, period->end) > 0)
                        memcpy(&period->end, &due, sizeof(struct icaltimetype));
                }
            }
        }
        else {
            icalproperty *prop;

            /* No DTSTART */
            if (!icaltime_is_null_time(due)) {
                /* Has DUE (DTEND for VPOLL) */
                memcpy(&period->start, &due, sizeof(struct icaltimetype));
                memcpy(&period->end, &due, sizeof(struct icaltimetype));
            }
            else if ((prop =
                      icalcomponent_get_first_property(comp,
                                                       ICAL_COMPLETED_PROPERTY))) {
                /* Has COMPLETED */
                period->start =
                    icaltime_convert_to_zone(icalproperty_get_completed(prop),
                                             utc);
                memcpy(&period->end, &period->start, sizeof(struct icaltimetype));

                if ((prop =
                     icalcomponent_get_first_property(comp,
                                                      ICAL_CREATED_PROPERTY))) {
                    /* Has CREATED */
                    struct icaltimetype created =
                        icaltime_convert_to_zone(icalproperty_get_created(prop),
                                                 utc);
                    if (icaltime_compare(created, period->start) < 0)
                        memcpy(&period->start, &created, sizeof(struct icaltimetype));
                    if (icaltime_compare(created, period->end) > 0)
                        memcpy(&period->end, &created, sizeof(struct icaltimetype));
                }
            }
            else if ((prop =
                      icalcomponent_get_first_property(comp,
                                                       ICAL_CREATED_PROPERTY))) {
                /* Has CREATED */
                period->start =
                    icaltime_convert_to_zone(icalproperty_get_created(prop),
                                             utc);
                period->end =
                    icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
            }
            else {
                /* Always */
                period->start =
                    icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
                period->end =
                    icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
            }
        }
        break;
    }

    case ICAL_VJOURNAL_COMPONENT:
        if (!icaltime_is_null_time(period->start)) {
            /* Has DTSTART */
            memcpy(&period->end, &period->start,
                   sizeof(struct icaltimetype));

            if (icaltime_is_date(period->start)) {
                /* DTSTART is not DATE-TIME */
                struct icaldurationtype dur;

                dur = icaldurationtype_from_int(60*60*24 - 1);  /* P1D */
                icaltime_add(period->end, dur);
            }
        }
        else {
            /* Never */
            period->start =
                icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
            period->end =
                icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
        }
        break;

    case ICAL_VFREEBUSY_COMPONENT:
        if (icaltime_is_null_time(period->start) ||
            icaltime_is_null_time(period->end)) {
            /* No DTSTART or DTEND */
            icalproperty *fb =
                icalcomponent_get_first_property(comp,
                                                 ICAL_FREEBUSY_PROPERTY);


            if (fb) {
                /* Has FREEBUSY */
                /* XXX  Convert FB period into our period */
            }
            else {
                /* Never */
                period->start =
                    icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
                period->end =
                    icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
            }
        }
        break;

    case ICAL_VAVAILABILITY_COMPONENT:
        if (icaltime_is_null_time(period->start)) {
            /* No DTSTART */
            period->start =
                icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
        }
        if (icaltime_is_null_time(period->end)) {
            /* No DTEND */
            period->end =
                icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
        }
        break;

    default:
        break;
    }
}


/* icalcomponent_foreach_recurrence() callback to find earliest/latest time */
static void recur_cb(icalcomponent *comp, struct icaltime_span *span,
                     void *rock)
{
    struct icalperiodtype *period = (struct icalperiodtype *) rock;
    int is_date = icaltime_is_date(icalcomponent_get_dtstart(comp));
    icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct icaltimetype start =
        icaltime_from_timet_with_zone(span->start, is_date, utc);
    struct icaltimetype end =
        icaltime_from_timet_with_zone(span->end, is_date, utc);

    if (icaltime_compare(start, period->start) < 0)
        memcpy(&period->start, &start, sizeof(struct icaltimetype));

    if (icaltime_compare(end, period->end) > 0)
        memcpy(&period->end, &end, sizeof(struct icaltimetype));
}

#define CMD_GETUPDATES CMD_READFIELDS \
      " WHERE comp_type = :comp_type AND modseq > :modseq" \
      " ORDER BY modseq LIMIT :limit;"

#define CMD_GETUPDATES_MBOX CMD_READFIELDS \
      " WHERE mailbox = :mailbox AND comp_type = :comp_type AND modseq > :modseq" \
      " ORDER BY modseq LIMIT :limit;"

EXPORTED int caldav_get_updates(struct caldav_db *caldavdb,
                                modseq_t oldmodseq, const char *mboxname, int kind, int limit,
                                int (*cb)(void *rock, struct caldav_data *cdata),
                                void *rock)
{
    struct sqldb_bindval bval[] = {
        { ":mailbox",      SQLITE_TEXT,    { .s = mboxname  } },
        { ":modseq",       SQLITE_INTEGER, { .i = oldmodseq } },
        { ":comp_type",    SQLITE_INTEGER, { .i = kind      } },
        { ":limit",        SQLITE_INTEGER, { .i = limit > 0 ? limit : -1 } },
        { NULL,            SQLITE_NULL,    { .s = NULL      } }
    };
    static struct caldav_data cdata;
    struct read_rock rrock = { caldavdb, &cdata, RROCK_FLAG_TOMBSTONES, cb, rock };
    int r;

    /* SQLite interprets a negative limit as unbounded. */
    if (mboxname) {
        r = sqldb_exec(caldavdb->db, CMD_GETUPDATES_MBOX, bval, &read_cb, &rrock);
    } else {
        r = sqldb_exec(caldavdb->db, CMD_GETUPDATES, bval, &read_cb, &rrock);
    }
    if (r) {
        syslog(LOG_ERR, "caldav error %s", error_message(r));
    }
    return r;
}


EXPORTED int caldav_writeentry(struct caldav_db *caldavdb, struct caldav_data *cdata,
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
#ifdef HAVE_VPOLL
    case ICAL_VPOLL_COMPONENT: mykind = CAL_COMP_VPOLL; break;
#endif
    default: break;
    }
    cdata->comp_type = mykind;
    cdata->comp_flags.status = status;

    /* Get organizer */
    prop = icalcomponent_get_first_property(comp, ICAL_ORGANIZER_PROPERTY);
    if (prop) cdata->organizer = icalproperty_get_organizer(prop)+7;
    else cdata->organizer = NULL;

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

    /* Initialize span to be nothing */
    span.start = icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);
    span.end = icaltime_from_timet_with_zone(caldav_epoch, 0, NULL);
    span.duration = icaldurationtype_null_duration();

    do {
        struct icalperiodtype period;
        icalproperty *rrule;

        /* Get base dtstart and dtend */
        caldav_get_period(comp, kind, &period);

        /* See if its a recurring event */
        rrule = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
        if (rrule ||
            icalcomponent_get_first_property(comp, ICAL_RDATE_PROPERTY) ||
            icalcomponent_get_first_property(comp, ICAL_EXDATE_PROPERTY)) {
            /* Recurring - find widest time range that includes events */
            int expand = recurring = 1;

            if (rrule) {
                struct icalrecurrencetype recur = icalproperty_get_rrule(rrule);

                if (!icaltime_is_null_time(recur.until)) {
                    /* Recurrence ends - calculate dtend of last recurrence */
                    struct icaldurationtype duration;
                    icaltimezone *utc = icaltimezone_get_utc_timezone();

                    duration = icaltime_subtract(period.end, period.start);
                    period.end =
                        icaltime_add(icaltime_convert_to_zone(recur.until, utc),
                                     duration);

                    /* Do RDATE expansion only */
                    /* XXX  This is destructive but currently doesn't matter */
                    icalcomponent_remove_property(comp, rrule);
                    icalproperty_free(rrule);
                }
                else if (!recur.count) {
                    /* Recurrence never ends - set end of span to eternity */
                    span.end =
                        icaltime_from_timet_with_zone(caldav_eternity, 0, NULL);

                    /* Skip RRULE & RDATE expansion */
                    expand = 0;
                }
            }

            /* Expand (remaining) recurrences */
            if (expand) {
                icalcomponent_foreach_recurrence(
                    comp,
                    icaltime_from_timet_with_zone(caldav_epoch, 0, NULL),
                    icaltime_from_timet_with_zone(caldav_eternity, 0, NULL),
                    recur_cb, &span);
            }
        }

        /* Check our dtstart and dtend against span */
        if (icaltime_compare(period.start, span.start) < 0)
            memcpy(&span.start, &period.start, sizeof(struct icaltimetype));

        if (icaltime_compare(period.end, span.end) > 0)
            memcpy(&span.end, &period.end, sizeof(struct icaltimetype));

        /* Check for managed attachment */
        if (!mattach) {
            for (prop = icalcomponent_get_first_property(comp,
                                                         ICAL_ATTACH_PROPERTY);
                 prop;
                 prop = icalcomponent_get_next_property(comp,
                                                        ICAL_ATTACH_PROPERTY)) {

                if (icalproperty_get_managedid_parameter(prop)) mattach = 1;
            }
        }

    } while ((comp = icalcomponent_get_next_component(ical, kind)));

    cdata->dtstart = icaltime_as_ical_string(span.start);
    cdata->dtend = icaltime_as_ical_string(span.end);
    cdata->comp_flags.recurring = recurring;
    cdata->comp_flags.mattach = mattach;
    
    return caldav_write(caldavdb, cdata);
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

#define CMD_SELMBOX CMD_READFIELDS \
    " WHERE mailbox = :mailbox AND alive = 1;"

EXPORTED int caldav_get_events(struct caldav_db *caldavdb,
                               const char *mailbox, const char *ical_uid,
                               caldav_cb_t *cb, void *rock)
{
    struct sqldb_bindval bval[] = {
        { ":mailbox",  SQLITE_TEXT, { .s = mailbox } },
        { ":ical_uid", SQLITE_TEXT, { .s = ical_uid } },
        { NULL,        SQLITE_NULL, { .s = NULL    } } };
    struct caldav_data cdata;
    struct read_rock rrock = { caldavdb, &cdata, 0, cb, rock };
    struct buf sqlbuf = BUF_INITIALIZER;

    buf_setcstr(&sqlbuf, CMD_READFIELDS);
    buf_appendcstr(&sqlbuf, " WHERE alive = 1");
    if (mailbox)
        buf_appendcstr(&sqlbuf, " AND mailbox = :mailbox");
    if (ical_uid)
        buf_appendcstr(&sqlbuf, " AND ical_uid = :ical_uid");
    buf_appendcstr(&sqlbuf, " ORDER BY mailbox, imap_uid;");

    /* XXX - tombstones */

    int r = sqldb_exec(caldavdb->db, buf_cstring(&sqlbuf), bval, &read_cb, &rrock);
    buf_free(&sqlbuf);

    if (r) {
        syslog(LOG_ERR, "carddav error %s", error_message(r));
        /* XXX - free memory */
    }


    return r;
}
