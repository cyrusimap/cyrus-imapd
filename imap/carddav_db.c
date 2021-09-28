/* carddav_db.c -- implementation of per-user CardDAV database
 *
 * Copyright (c) 1994-2013 Carnegie Mellon University.  All rights reserved.
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

#include "append.h"
#include "carddav_db.h"
#include "cyrusdb.h"
#include "httpd.h"
#include "http_dav.h"
#include "libconfig.h"
#include "mboxevent.h"
#include "times.h"
#include "util.h"
#include "xstrlcat.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/imap_err.h"


#define NUM_BUFS 10

struct carddav_db {
    sqldb_t *db;                        /* DB handle */
    struct buf bufs[NUM_BUFS];          /* buffers for copies of column text */
    char *userid;
};

static int carddav_initialized = 0;

static void done_cb(void *rock __attribute__((unused))) {
    carddav_done();
}

static void init_internal() {
    if (!carddav_initialized) {
        carddav_init();
        cyrus_modules_add(done_cb, NULL);
    }
}

EXPORTED int carddav_init(void)
{
    int r = sqldb_init();
    if (!r) carddav_initialized = 1;
    return r;
}


EXPORTED int carddav_done(void)
{
    int r = sqldb_done();
    if (!r) carddav_initialized = 0;
    return r;
}

EXPORTED struct carddav_db *carddav_open_userid(const char *userid)
{
    struct carddav_db *carddavdb = NULL;

    init_internal();

    sqldb_t *db = dav_open_userid(userid);
    if (!db) return NULL;

    carddavdb = xzmalloc(sizeof(struct carddav_db));
    carddavdb->userid = xstrdup(userid);
    carddavdb->db = db;

    return carddavdb;
}

EXPORTED struct carddav_db *carddav_open_mailbox(struct mailbox *mailbox)
{
    struct carddav_db *carddavdb = NULL;
    char *userid = mboxname_to_userid(mailbox_name(mailbox));

    init_internal();

    if (userid) {
        carddavdb = carddav_open_userid(userid);
        free(userid);
        return carddavdb;
    }

    sqldb_t *db = dav_open_mailbox(mailbox);
    if (!db) return NULL;

    carddavdb = xzmalloc(sizeof(struct carddav_db));
    carddavdb->db = db;

    return carddavdb;
}

EXPORTED int carddav_set_otheruser(struct carddav_db *carddavdb, const char *userid)
{
    sqldb_detach(carddavdb->db); // remove any current
    return dav_attach_userid(carddavdb->db, userid);
}


/* Close DAV DB */
EXPORTED int carddav_close(struct carddav_db *carddavdb)
{
    int i, r = 0;

    if (!carddavdb) return 0;

    for (i = 0; i < NUM_BUFS; i++) {
        buf_free(&carddavdb->bufs[i]);
    }

    r = dav_close(&carddavdb->db);

    free(carddavdb->userid);
    free(carddavdb);

    return r;
}

EXPORTED int carddav_begin(struct carddav_db *carddavdb)
{
    return sqldb_begin(carddavdb->db, "carddav");
}

EXPORTED int carddav_commit(struct carddav_db *carddavdb)
{
    return sqldb_commit(carddavdb->db, "carddav");
}

EXPORTED int carddav_abort(struct carddav_db *carddavdb)
{
    return sqldb_rollback(carddavdb->db, "carddav");
}

struct read_rock {
    struct carddav_db *db;
    struct carddav_data *cdata;
    int tombstones;
    carddav_cb_t *cb;
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

#define CMD_GETFIELDS                                                   \
    "SELECT rowid, creationdate, mailbox, resource, imap_uid,"          \
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"              \
    "  version, vcard_uid, kind, fullname, name, nickname, alive,"      \
    "  modseq, createdmodseq, NULL, NULL" \
    " FROM vcard_objs"

#define CMD_GETFIELDS_JMAP                                              \
    "SELECT vcard_objs.rowid, creationdate, mailbox, resource, imap_uid," \
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"              \
    "  version, vcard_uid, kind, fullname, name, nickname, alive,"      \
    "  modseq, createdmodseq, jmapversion, jmapdata" \
    " FROM vcard_objs LEFT JOIN vcard_jmapcache USING (rowid)"

static int read_cb(sqlite3_stmt *stmt, void *rock)
{
    struct read_rock *rrock = (struct read_rock *) rock;
    struct carddav_db *db = rrock->db;
    struct carddav_data *cdata = rrock->cdata;
    int r = 0;

    memset(cdata, 0, sizeof(struct carddav_data));

    cdata->dav.mailbox_byname = (db->db->version < DB_MBOXID_VERSION);
    cdata->dav.alive = sqlite3_column_int(stmt, 15);
    cdata->dav.modseq = sqlite3_column_int64(stmt, 16);
    cdata->dav.createdmodseq = sqlite3_column_int64(stmt, 17);
    if (!rrock->tombstones && !cdata->dav.alive)
        return 0;

    cdata->dav.rowid = sqlite3_column_int(stmt, 0);
    cdata->dav.creationdate = sqlite3_column_int(stmt, 1);
    cdata->dav.imap_uid = sqlite3_column_int(stmt, 4);
    cdata->dav.lock_expire = sqlite3_column_int(stmt, 8);
    cdata->version = sqlite3_column_int(stmt, 9);
    cdata->kind = sqlite3_column_int(stmt, 11);
    cdata->jmapversion = sqlite3_column_int(stmt, 18);

    if (rrock->cb) {
        /* We can use the column data directly for the callback */
        cdata->dav.mailbox = (const char *) sqlite3_column_text(stmt, 2);
        cdata->dav.resource = (const char *) sqlite3_column_text(stmt, 3);
        cdata->dav.lock_token = (const char *) sqlite3_column_text(stmt, 5);
        cdata->dav.lock_owner = (const char *) sqlite3_column_text(stmt, 6);
        cdata->dav.lock_ownerid = (const char *) sqlite3_column_text(stmt, 7);
        cdata->vcard_uid = (const char *) sqlite3_column_text(stmt, 10);
        cdata->fullname = (const char *) sqlite3_column_text(stmt, 12);
        cdata->name = (const char *) sqlite3_column_text(stmt, 13);
        cdata->nickname = (const char *) sqlite3_column_text(stmt, 14);
        cdata->jmapdata = (const char *) sqlite3_column_text(stmt, 19);
        r = rrock->cb(rrock->rock, cdata);
    }
    else {
        /* For single row SELECTs like carddav_read(),
         * we need to make a copy of the column data before
         * it gets flushed by sqlite3_step() or sqlite3_reset() */
        cdata->dav.mailbox =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 2),
                               &db->bufs[0]);
        cdata->dav.resource =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 3),
                               &db->bufs[1]);
        cdata->dav.lock_token =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 5),
                               &db->bufs[2]);
        cdata->dav.lock_owner =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 6),
                               &db->bufs[3]);
        cdata->dav.lock_ownerid =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 7),
                               &db->bufs[4]);
        cdata->vcard_uid =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 10),
                               &db->bufs[5]);
        cdata->fullname =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 12),
                               &db->bufs[6]);
        cdata->name =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 13),
                               &db->bufs[7]);
        cdata->nickname =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 14),
                               &db->bufs[8]);
        cdata->jmapdata =
            column_text_to_buf((const char *) sqlite3_column_text(stmt, 15),
                                &db->bufs[9]);
    }

    return r;
}

#define CMD_SELRSRC CMD_GETFIELDS \
    " WHERE mailbox = :mailbox AND resource = :resource;"

EXPORTED int carddav_lookup_resource(struct carddav_db *carddavdb,
                           const mbentry_t *mbentry, const char *resource,
                           struct carddav_data **result,
                           int tombstones)
{
    const char *mailbox = (carddavdb->db->version >= DB_MBOXID_VERSION) ?
        mbentry->uniqueid : mbentry->name;
    struct sqldb_bindval bval[] = {
        { ":mailbox",  SQLITE_TEXT, { .s = mailbox       } },
        { ":resource", SQLITE_TEXT, { .s = resource      } },
        { NULL,        SQLITE_NULL, { .s = NULL          } } };
    static struct carddav_data cdata;
    struct read_rock rrock = { carddavdb, &cdata, tombstones, NULL, NULL };
    int r;

    *result = memset(&cdata, 0, sizeof(struct carddav_data));

    r = sqldb_exec(carddavdb->db, CMD_SELRSRC, bval, &read_cb, &rrock);
    if (!r && !cdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    /* always mailbox and resource so error paths don't fail */
    cdata.dav.mailbox_byname = (carddavdb->db->version < DB_MBOXID_VERSION);
    cdata.dav.mailbox = mailbox;
    cdata.dav.resource = resource;

    return r;
}


#define CMD_SELIMAPUID CMD_GETFIELDS \
    " WHERE mailbox = :mailbox AND imap_uid = :imap_uid;"

EXPORTED int carddav_lookup_imapuid(struct carddav_db *carddavdb,
                                    const mbentry_t *mbentry, int imap_uid,
                                    struct carddav_data **result,
                                    int tombstones)
{
    const char *mailbox = (carddavdb->db->version >= DB_MBOXID_VERSION) ?
        mbentry->uniqueid : mbentry->name;
    struct sqldb_bindval bval[] = {
        { ":mailbox",  SQLITE_TEXT,    { .s = mailbox       } },
        { ":imap_uid", SQLITE_INTEGER, { .i = imap_uid      } },
        { NULL,        SQLITE_NULL,    { .s = NULL          } } };
    static struct carddav_data cdata;
    struct read_rock rrock = { carddavdb, &cdata, tombstones, NULL, NULL };
    int r;

    *result = memset(&cdata, 0, sizeof(struct carddav_data));

    r = sqldb_exec(carddavdb->db, CMD_SELIMAPUID, bval, &read_cb, &rrock);
    if (!r && !cdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    cdata.dav.mailbox = mailbox;
    cdata.dav.imap_uid = imap_uid;

    return r;
}


#define CMD_SELUID CMD_GETFIELDS \
    " WHERE vcard_uid = :vcard_uid AND alive = 1;"

EXPORTED int carddav_lookup_uid(struct carddav_db *carddavdb, const char *vcard_uid,
                                struct carddav_data **result)
{
    struct sqldb_bindval bval[] = {
        { ":vcard_uid", SQLITE_TEXT, { .s = vcard_uid            } },
        { NULL,         SQLITE_NULL, { .s = NULL                 } } };
    static struct carddav_data cdata;
    struct read_rock rrock = { carddavdb, &cdata, 0, NULL, NULL };
    int r;

    *result = memset(&cdata, 0, sizeof(struct carddav_data));

    r = sqldb_exec(carddavdb->db, CMD_SELUID, bval, &read_cb, &rrock);
    if (!r && !cdata.dav.rowid) r = CYRUSDB_NOTFOUND;

    return r;
}


#define CMD_SELMBOX CMD_GETFIELDS \
    " WHERE mailbox = :mailbox AND alive = 1"

#define CMD_SELALIVE CMD_GETFIELDS \
    " WHERE alive = 1"

#define CMD_DEFAULT_ORDER " ORDER BY modseq DESC;"

EXPORTED int carddav_foreach(struct carddav_db *carddavdb,
                             const mbentry_t *mbentry,
                             int (*cb)(void *rock, struct carddav_data *data),
                             void *rock)
{
    return carddav_foreach_sort(carddavdb, mbentry, NULL, 0, cb, rock);
}

EXPORTED int carddav_foreach_sort(struct carddav_db *carddavdb,
                                  const mbentry_t *mbentry,
                                  enum carddav_sort* sort, size_t nsort,
                                  int (*cb)(void *rock, struct carddav_data *data),
                                  void *rock)
{
    const char *mailbox = !mbentry ? NULL :
        ((carddavdb->db->version >= DB_MBOXID_VERSION) ?
         mbentry->uniqueid : mbentry->name);
    struct sqldb_bindval bval[] = {
        { ":mailbox", SQLITE_TEXT, { .s = mailbox } },
        { NULL,       SQLITE_NULL, { .s = NULL    } } };
    struct carddav_data cdata;
    struct read_rock rrock = { carddavdb, &cdata, 0, cb, rock };

    if (!nsort) {
        if (mailbox) {
            return sqldb_exec(carddavdb->db, CMD_SELMBOX CMD_DEFAULT_ORDER,
                              bval, &read_cb, &rrock);
        } else {
            return sqldb_exec(carddavdb->db, CMD_SELALIVE CMD_DEFAULT_ORDER,
                              bval, &read_cb, &rrock);
        }
    }

    struct buf stmt = BUF_INITIALIZER;
    buf_setcstr(&stmt, mailbox ? CMD_SELMBOX : CMD_SELALIVE);
    buf_appendcstr(&stmt, " ORDER BY");
    size_t i;
    for (i = 0; i < nsort; i++) {
        const char *column = NULL;
        switch (sort[i] & ~CARD_SORT_DESC) {
            case CARD_SORT_MODSEQ:
                column = "modseq";
                break;
            case CARD_SORT_UID:
                column = "vcard_uid";
                break;
            case CARD_SORT_FULLNAME:
                column = "fullname";
                break;
            default:
                continue;
        }
        if (i) buf_putc(&stmt, ',');
        buf_putc(&stmt, ' ');
        buf_appendcstr(&stmt, column);
        buf_appendcstr(&stmt, sort[i] & CARD_SORT_DESC ? " DESC" : " ASC");
    }
    buf_putc(&stmt, ';');

    int r = sqldb_exec(carddavdb->db, buf_cstring(&stmt), bval, &read_cb, &rrock);
    buf_free(&stmt);
    return r;
}

#define CMD_GETUID_GROUPS \
    "SELECT GO.vcard_uid FROM vcard_objs GO" \
    " JOIN vcard_groups G" \
    " WHERE G.objid = GO.rowid" \
    " AND G.member_uid = :uid AND GO.alive = 1;"

static int addarray_cb(sqlite3_stmt *stmt, void *rock)
{
    strarray_t *array = (strarray_t *)rock;
    const char *value = (const char *)sqlite3_column_text(stmt, 0);
    if (value) strarray_add(array, value);
    return 0;
}

static int addarray_kv_cb(sqlite3_stmt *stmt, void *rock)
{
    strarray_t *array = (strarray_t *)rock;
    const char *key = (const char *)sqlite3_column_text(stmt, 0);
    if (key) strarray_add(array, key);
    const char *value = (const char *)sqlite3_column_text(stmt, 1);
    if (value) strarray_add(array, value);
    return 0;
}

EXPORTED strarray_t *carddav_getuid_groups(struct carddav_db *carddavdb, const char *uid)
{
    struct sqldb_bindval bval[] = {
        { ":uid", SQLITE_TEXT, { .s = uid } },
        { NULL,   SQLITE_NULL, { .s = NULL  } }
    };

    strarray_t *groups;
    int r;

    groups = strarray_new();

    r = sqldb_exec(carddavdb->db, CMD_GETUID_GROUPS, bval, &addarray_cb, groups);
    if (r) {
        /* XXX syslog */
    }

    return groups;
}

#define CMD_GETEMAIL_EXISTS \
    "SELECT E.rowid " \
    " FROM vcard_emails E JOIN vcard_objs CO" \
    " WHERE E.objid = CO.rowid AND E.email = :email AND CO.alive = 1" \
    " LIMIT 1"

#define CMD_GETEMAIL_GROUPS \
    "SELECT GO.vcard_uid FROM vcard_objs GO" \
    " JOIN vcard_groups G JOIN vcard_objs CO JOIN vcard_emails E" \
    " WHERE E.objid = CO.rowid AND CO.vcard_uid = G.member_uid" \
    " AND G.objid = GO.rowid AND E.email = :email" \
    " AND GO.alive = 1 AND CO.alive = 1;"

#define CMD_GETEMAIL2DETAILS \
    "SELECT DISTINCT vcard_uid, ispinned " \
    " FROM vcard_objs CO JOIN vcard_emails E" \
    " WHERE E.objid = CO.rowid AND CO.alive = 1" \
    " AND E.email = :email AND CO.mailbox = :mailbox;"

#define CMD_GETUID2GROUPS \
    "SELECT DISTINCT GO.vcard_uid, GO.fullname" \
    " FROM vcard_objs GO JOIN vcard_groups G" \
    " WHERE G.objid = GO.rowid AND GO.alive = 1" \
    " AND G.member_uid = :member_uid AND G.otheruser = :otheruser" \
    " AND GO.mailbox = :mailbox;"

static int emailexists_cb(sqlite3_stmt *stmt, void *rock)
{
    int *exists = (int *)rock;
    if (sqlite3_column_int(stmt, 0))
        *exists = 1;
    return 0;
}

EXPORTED strarray_t *carddav_getemail(struct carddav_db *carddavdb, const char *email)
{
    struct sqldb_bindval bval[] = {
        { ":email", SQLITE_TEXT, { .s = email } },
        { NULL,     SQLITE_NULL, { .s = NULL  } }
    };

    int exists = 0;
    strarray_t *groups;
    int r;

    r = sqldb_exec(carddavdb->db, CMD_GETEMAIL_EXISTS, bval, &emailexists_cb, &exists);
    if (r) {
        /* XXX syslog */
        return NULL;
    }

    if (!exists)
        return NULL;

    groups = strarray_new();

    r = sqldb_exec(carddavdb->db, CMD_GETEMAIL_GROUPS, bval, &addarray_cb, groups);
    if (r) {
        /* XXX syslog */
    }

    return groups;
}

struct detailsdata {
    strarray_t *uids;
    int ispinned;
};

static int details_cb(sqlite3_stmt *stmt, void *rock)
{
    struct detailsdata *data = (struct detailsdata *)rock;
    const char *value = (const char *)sqlite3_column_text(stmt, 0);
    if (value) strarray_add(data->uids, value);
    if (sqlite3_column_int(stmt, 1))
        data->ispinned = 1;
    return 0;
}

EXPORTED strarray_t *carddav_getemail2details(struct carddav_db *carddavdb,
                                              const char *email,
                                              const mbentry_t *mbentry,
                                              int *ispinned)
{
    const char *mailbox = (carddavdb->db->version >= DB_MBOXID_VERSION) ?
        mbentry->uniqueid : mbentry->name;
    struct sqldb_bindval bval[] = {
        { ":email",   SQLITE_TEXT, { .s = email   } },
        { ":mailbox", SQLITE_TEXT, { .s = mailbox } },
        { NULL,       SQLITE_NULL, { .s = NULL    } }
    };
    struct detailsdata data = { strarray_new(), 0 };

    sqldb_exec(carddavdb->db, CMD_GETEMAIL2DETAILS, bval, &details_cb, &data);

    if (ispinned) {
        *ispinned = data.ispinned;
    }

    return data.uids;
}

EXPORTED strarray_t *carddav_getuid2groups(struct carddav_db *carddavdb,
                                           const char *member_uid,
                                           const mbentry_t *mbentry,
                                           const char *otheruser)
{
    const char *mailbox = (carddavdb->db->version >= DB_MBOXID_VERSION) ?
        mbentry->uniqueid : mbentry->name;
    struct sqldb_bindval bval[] = {
        { ":member_uid", SQLITE_TEXT, { .s = member_uid } },
        { ":mailbox",    SQLITE_TEXT, { .s = mailbox    } },
        { ":otheruser",  SQLITE_TEXT, { .s = otheruser  } },
        { NULL,          SQLITE_NULL, { .s = NULL       } }
    };
    strarray_t *groups = strarray_new();

    sqldb_exec(carddavdb->db, CMD_GETUID2GROUPS, bval, &addarray_kv_cb, groups);

    return groups;
}

/* FUNCTIONS FOR LOOKING UP headerAllContacts */

#define GETALL_LOCAL \
    "SELECT DISTINCT E.email FROM vcard_emails E" \
    " JOIN vcard_objs CO" \
    " WHERE E.objid = CO.rowid AND CO.alive = 1" \
    " AND (:mailbox IS NULL OR CO.mailbox = :mailbox)"

#define GETALL_MEMBERS GETALL_LOCAL ";"

#define GETALL_OTHERMEMBERS \
    GETALL_LOCAL " UNION " \
    "SELECT DISTINCT E.email FROM other.vcard_emails E" \
    " JOIN other.vcard_objs CO" \
    " WHERE E.objid = CO.rowid AND CO.alive = 1" \
    " AND CO.mailbox = :othermailbox;"

/* FUNCTIONS FOR LOOKING UP headerContactGroupId on own groups */

#define GETGROUP_EXISTS \
    "SELECT rowid " \
    " FROM vcard_objs" \
    " WHERE kind = :kind AND vcard_uid = :group AND alive = 1" \
    " AND (:mailbox IS NULL OR mailbox = :mailbox);"

#define GETGROUP_LOCAL \
    "SELECT DISTINCT E.email FROM vcard_emails E" \
    " JOIN vcard_objs CO JOIN vcard_groups G JOIN vcard_objs GO" \
    " WHERE E.objid = CO.rowid AND CO.vcard_uid = G.member_uid AND G.objid = GO.rowid" \
    " AND G.otheruser = '' AND GO.vcard_uid = :group AND GO.alive = 1 AND CO.alive = 1" \
    " AND (:mailbox IS NULL OR GO.mailbox = :mailbox)"

#define GETGROUP_MEMBERS GETGROUP_LOCAL ";"

#define GETGROUP_OTHERMEMBERS \
    GETGROUP_LOCAL " UNION " \
    "SELECT DISTINCT E.email FROM other.vcard_emails E" \
    " JOIN other.vcard_objs CO JOIN vcard_groups G JOIN vcard_objs GO" \
    " WHERE E.objid = CO.rowid AND CO.vcard_uid = G.member_uid AND G.objid = GO.rowid" \
    " AND G.otheruser = :otheruser AND GO.vcard_uid = :group AND GO.alive = 1 AND CO.alive = 1" \
    " AND (:mailbox IS NULL OR GO.mailbox = :mailbox) AND CO.mailbox = :othermailbox;"

/* FUNCTIONS FOR LOOKING UPO headerContactGroupId on shared groups:
 * this is different than GROUP_OTHERMEMBERS in the following way,
 * GROUP_OTHERMEMBERS: the group is in the user, but contains a member in the masteruser
 * OTHERGROUP_MEMBERS: the group is in the masteruser, containing members in the masteruser
 */

#define GETOTHERGROUP_EXISTS \
    "SELECT rowid " \
    " FROM other.vcard_objs" \
    " WHERE kind = :kind AND vcard_uid = :group AND alive = 1" \
    " AND mailbox = :othermailbox;"

// need to make sure all the contacts are only in 'Shared' as well!
#define GETOTHERGROUP_MEMBERS \
    "SELECT DISTINCT E.email FROM other.vcard_emails E" \
    " JOIN other.vcard_objs CO JOIN other.vcard_groups G JOIN other.vcard_objs GO" \
    " WHERE E.objid = CO.rowid AND CO.vcard_uid = G.member_uid AND G.objid = GO.rowid" \
    " AND G.otheruser = '' AND GO.vcard_uid = :group AND GO.alive = 1 AND CO.alive = 1" \
    " AND GO.mailbox = :othermailbox AND CO.mailbox = :othermailbox;"

static int groupexists_cb(sqlite3_stmt *stmt, void *rock)
{
    int *exists = (int *)rock;
    if (sqlite3_column_int(stmt, 0))
        *exists = 1;
    return 0;
}

static int groupmembers_cb(sqlite3_stmt *stmt, void *rock)
{
    strarray_t *array = (strarray_t *)rock;
    strarray_append(array, (const char *)sqlite3_column_text(stmt, 0));
    return 0;
}

EXPORTED strarray_t *carddav_getgroup(struct carddav_db *carddavdb,
                                      const mbentry_t *mbentry, const char *group,
                                      const mbentry_t *othermb)
{
    int r = 0;
    int isshared = 0;
    if (!strncmpsafe(group, "shared/", 7)) {
        assert(!mbentry); // no mailbox filter on shared groups
        if (!carddavdb->db->attached) return NULL;
        if (!*group) return NULL; // can't just be "shared/"
        isshared = 1;
        group += 7;
    }

    const char *mailbox = !mbentry ? NULL :
        (carddavdb->db->version >= DB_MBOXID_VERSION) ?
        mbentry->uniqueid : mbentry->name;

    const char *othermailbox = !othermb ? NULL :
        (carddavdb->db->version >= DB_MBOXID_VERSION) ?
        othermb->uniqueid : othermb->name;

    const char *otheruser = NULL;
    mbname_t *othermbname = NULL;
    if (othermb) {
        othermbname = mbname_from_intname(othermb->name);
        otheruser = mbname_userid(othermbname);
    }

    struct sqldb_bindval bval[] = {
        { ":mailbox",      SQLITE_TEXT,    { .s = mailbox } },
        { ":group",        SQLITE_TEXT,    { .s = group   } },
        { ":kind",         SQLITE_INTEGER, { .i = CARDDAV_KIND_GROUP } },
        { ":otheruser",    SQLITE_TEXT,    { .s = otheruser } },
        { ":othermailbox", SQLITE_TEXT,    { .s = othermailbox } },
        { NULL,            SQLITE_NULL,    { .s = NULL    } }
    };

    strarray_t *members = NULL;

    if (*group) {
        // first check that the group exists

        const char *existsql = isshared ? GETOTHERGROUP_EXISTS : GETGROUP_EXISTS;
        int exists = 0;
        r = sqldb_exec(carddavdb->db, existsql, bval, &groupexists_cb, &exists);
        if (r) {
            /* XXX syslog */
            goto done;
        }

        if (!exists) goto done;
    }

    // pick which filter to use!
    const char *membersql = GETGROUP_MEMBERS;
    if (carddavdb->db->attached) {
        if (isshared) membersql = GETOTHERGROUP_MEMBERS;
        else if (!*group) membersql = GETALL_OTHERMEMBERS;
        else membersql = GETGROUP_OTHERMEMBERS;
    }
    else if (!*group) membersql = GETALL_MEMBERS;

    members = strarray_new();
    r = sqldb_exec(carddavdb->db, membersql, bval, &groupmembers_cb, members);
    if (r) {
        /* XXX syslog */
    }

done:
    mbname_free(&othermbname);
    return members;
}


#define CMD_DELETE_EMAIL "DELETE FROM vcard_emails WHERE objid = :objid"
#define CMD_INSERT_EMAIL                                                \
    "INSERT INTO vcard_emails ( objid, pos, email, ispref, ispinned )"            \
    " VALUES ( :objid, :pos, :email, :ispref, :ispinned );"

static int carddav_write_emails(struct carddav_db *carddavdb, int rowid, const strarray_t *emails, int ispinned)
{
    struct sqldb_bindval bval[] = {
        { ":objid",        SQLITE_INTEGER, { .i = rowid  } },
        { ":pos",          SQLITE_INTEGER, { .i = 0      } },
        { ":email",        SQLITE_TEXT,    { .s = NULL   } },
        { ":ispref",       SQLITE_INTEGER, { .i = 0      } },
        { ":ispinned",     SQLITE_INTEGER, { .i = 0      } },
        { NULL,            SQLITE_NULL,    { .s = NULL   } } };
    int r;
    int i;

    /* clean up existing records if any */
    r = sqldb_exec(carddavdb->db, CMD_DELETE_EMAIL, bval, NULL, NULL);
    if (r) return r;
    for (i = 0; i < strarray_size(emails)/2; i++) {
        const char *pref = strarray_safenth(emails, i*2+1);
        bval[1].val.i = i;
        bval[2].val.s = strarray_safenth(emails, i*2);
        bval[3].val.i = *pref ? 1 : 0;
        bval[4].val.i = ispinned ? 1 : 0;
        r = sqldb_exec(carddavdb->db, CMD_INSERT_EMAIL, bval, NULL, NULL);
        if (r) return r;
    }

    return 0;
}

static int carddav_delete_emails(struct carddav_db *carddavdb, int rowid)
{
    struct sqldb_bindval bval[] = {
        { ":rowid", SQLITE_INTEGER, { .i = rowid } },
        { NULL,     SQLITE_NULL,    { .s = NULL  } } };
    int r;

    r = sqldb_exec(carddavdb->db, CMD_DELETE_EMAIL, bval, NULL, NULL);
    if (r) return r;

    return 0;
}

#define CMD_DELETE_GROUP "DELETE FROM vcard_groups WHERE objid = :objid"
#define CMD_INSERT_GROUP                                                \
    "INSERT INTO vcard_groups ( objid, pos, member_uid, otheruser )"    \
    " VALUES ( :objid, :pos, :member_uid, :otheruser );"

static int carddav_delete_groups(struct carddav_db *carddavdb, int rowid)
{
    struct sqldb_bindval bval[] = {
        { ":objid",        SQLITE_INTEGER, { .i = rowid        } },
        { ":pos",          SQLITE_INTEGER, { .i = 0            } },
        { ":member_uid",   SQLITE_TEXT,    { .s = NULL         } },
        { ":otheruser",    SQLITE_TEXT,    { .s = NULL         } },
        { NULL,            SQLITE_NULL,    { .s = NULL         } } };
    int r;

    r = sqldb_exec(carddavdb->db, CMD_DELETE_GROUP, bval, NULL, NULL);
    if (r) return r;

    return 0;
}

static int carddav_write_groups(struct carddav_db *carddavdb, int rowid, const strarray_t *member_uids)
{
    struct sqldb_bindval bval[] = {
        { ":objid",        SQLITE_INTEGER, { .i = rowid        } },
        { ":pos",          SQLITE_INTEGER, { .i = 0            } },
        { ":member_uid",   SQLITE_TEXT,    { .s = NULL         } },
        { ":otheruser",    SQLITE_TEXT,    { .s = NULL         } },
        { NULL,            SQLITE_NULL,    { .s = NULL         } } };
    int r;
    int i;

    /* remove any existing first */
    r = sqldb_exec(carddavdb->db, CMD_DELETE_GROUP, bval, NULL, NULL);
    if (r) return r;
    for (i = 0; i < strarray_size(member_uids)/2; i++) {
        bval[1].val.i = i;
        bval[2].val.s = strarray_safenth(member_uids, 2*i);
        bval[3].val.s = strarray_safenth(member_uids, 2*i+1);
        r = sqldb_exec(carddavdb->db, CMD_INSERT_GROUP, bval, NULL, NULL);
        if (r) return r;
    }

    return 0;
}

#define CMD_INSERT                                                      \
    "INSERT INTO vcard_objs ("                                          \
    "  alive, creationdate, mailbox, resource, imap_uid, modseq,"       \
    "  createdmodseq,"                                                  \
    "  lock_token, lock_owner, lock_ownerid, lock_expire,"              \
    "  version, vcard_uid, kind, fullname, name, nickname)"             \
    " VALUES ("                                                         \
    "  :alive, :creationdate, :mailbox, :resource, :imap_uid, :modseq," \
    "  :createdmodseq,"                                                 \
    "  :lock_token, :lock_owner, :lock_ownerid, :lock_expire,"          \
    "  :version, :vcard_uid, :kind, :fullname, :name, :nickname );"

#define CMD_UPDATE                      \
    "UPDATE vcard_objs SET"             \
    "  alive = :alive,"                 \
    "  creationdate = :creationdate,"   \
    "  imap_uid     = :imap_uid,"       \
    "  modseq       = :modseq,"         \
    "  createdmodseq = :createdmodseq," \
    "  lock_token   = :lock_token,"     \
    "  lock_owner   = :lock_owner,"     \
    "  lock_ownerid = :lock_ownerid,"   \
    "  lock_expire  = :lock_expire,"    \
    "  version      = :version,"        \
    "  vcard_uid    = :vcard_uid,"      \
    "  kind         = :kind,"           \
    "  fullname     = :fullname,"       \
    "  name         = :name,"           \
    "  nickname     = :nickname"        \
    " WHERE rowid = :rowid;"

#define CMD_DELETE_JMAPCACHE "DELETE FROM vcard_jmapcache WHERE rowid = :rowid"

EXPORTED int carddav_write(struct carddav_db *carddavdb, struct carddav_data *cdata)
{
    struct sqldb_bindval bval[] = {
        { ":rowid",        SQLITE_INTEGER, { .i = cdata->dav.rowid        } },
        { ":alive",        SQLITE_INTEGER, { .i = cdata->dav.alive        } },
        { ":creationdate", SQLITE_INTEGER, { .i = cdata->dav.creationdate } },
        { ":mailbox",      SQLITE_TEXT,    { .s = cdata->dav.mailbox      } },
        { ":resource",     SQLITE_TEXT,    { .s = cdata->dav.resource     } },
        { ":imap_uid",     SQLITE_INTEGER, { .i = cdata->dav.imap_uid     } },
        { ":modseq",       SQLITE_INTEGER, { .i = cdata->dav.modseq       } },
        { ":createdmodseq", SQLITE_INTEGER, { .i = cdata->dav.createdmodseq } },
        { ":lock_token",   SQLITE_TEXT,    { .s = cdata->dav.lock_token   } },
        { ":lock_owner",   SQLITE_TEXT,    { .s = cdata->dav.lock_owner   } },
        { ":lock_ownerid", SQLITE_TEXT,    { .s = cdata->dav.lock_ownerid } },
        { ":lock_expire",  SQLITE_INTEGER, { .i = cdata->dav.lock_expire  } },
        { ":version",      SQLITE_INTEGER, { .i = cdata->version          } },
        { ":vcard_uid",    SQLITE_TEXT,    { .s = cdata->vcard_uid        } },
        { ":kind",         SQLITE_INTEGER, { .i = cdata->kind             } },
        { ":fullname",     SQLITE_TEXT,    { .s = cdata->fullname         } },
        { ":name",         SQLITE_TEXT,    { .s = cdata->name             } },
        { ":nickname",     SQLITE_TEXT,    { .s = cdata->nickname         } },
        { NULL,            SQLITE_NULL,    { .s = NULL                    } } };

    if (cdata->dav.rowid) {
        int r = sqldb_exec(carddavdb->db, CMD_DELETE_JMAPCACHE, bval, NULL, NULL);
        if (r) return r;
        r = sqldb_exec(carddavdb->db, CMD_UPDATE, bval, NULL, NULL);
        if (r) return r;
    }
    else {
        int r = sqldb_exec(carddavdb->db, CMD_INSERT, bval, NULL, NULL);
        if (r) return r;
        cdata->dav.rowid = sqldb_lastid(carddavdb->db);
    }

    return 0;
}


#define CMD_DELETE "DELETE FROM vcard_objs WHERE rowid = :rowid;"

EXPORTED int carddav_delete(struct carddav_db *carddavdb, unsigned rowid)
{
    struct sqldb_bindval bval[] = {
        { ":rowid", SQLITE_INTEGER, { .i = rowid } },
        { NULL,     SQLITE_NULL,    { .s = NULL  } } };
    int r;

    r = sqldb_exec(carddavdb->db, CMD_DELETE, bval, NULL, NULL);
    if (!r) r = carddav_delete_emails(carddavdb, rowid);
    if (!r) r = carddav_delete_groups(carddavdb, rowid);
    if (r) return r;

    return 0;
}


#define CMD_DELMBOX "DELETE FROM vcard_objs WHERE mailbox = :mailbox;"

HIDDEN int carddav_delmbox(struct carddav_db *carddavdb,
                           const mbentry_t *mbentry)
{
    const char *mailbox = (carddavdb->db->version >= DB_MBOXID_VERSION) ?
        mbentry->uniqueid : mbentry->name;
    struct sqldb_bindval bval[] = {
        { ":mailbox", SQLITE_TEXT, { .s = mailbox } },
        { NULL,       SQLITE_NULL, { .s = NULL    } } };
    int r;

    r = sqldb_exec(carddavdb->db, CMD_DELMBOX, bval, NULL, NULL);
    if (r) return r;

    return 0;
}

#define CMD_INSERT_JMAPCACHE                                                \
    "INSERT INTO vcard_jmapcache ( rowid, jmapversion, jmapdata )"          \
    " VALUES ( :rowid, :jmapversion, :jmapdata );"

EXPORTED int carddav_write_jmapcache(struct carddav_db *carddavdb, int rowid, int version, const char *data)
{
    struct sqldb_bindval bval[] = {
        { ":rowid",        SQLITE_INTEGER, { .i = rowid  } },
        { ":jmapversion",  SQLITE_INTEGER, { .i = version } },
        { ":jmapdata",     SQLITE_TEXT,    { .s = data   } },
        { NULL,            SQLITE_NULL,    { .s = NULL   } } };
    int r;

    /* clean up existing records if any */
    r = sqldb_exec(carddavdb->db, CMD_DELETE_JMAPCACHE, bval, NULL, NULL);
    if (r) return r;

    /* insert the cache record */
    return sqldb_exec(carddavdb->db, CMD_INSERT_JMAPCACHE, bval, NULL, NULL);
}

EXPORTED int carddav_get_cards(struct carddav_db *carddavdb,
                               const mbentry_t *mbentry,
                               const char *vcard_uid, int kind,
                               int (*cb)(void *rock,
                                         struct carddav_data *cdata),
                               void *rock)
{
    const char *mailbox = !mbentry ? NULL :
        ((carddavdb->db->version >= DB_MBOXID_VERSION) ?
         mbentry->uniqueid : mbentry->name);
    struct sqldb_bindval bval[] = {
        { ":kind",      SQLITE_INTEGER, { .i = kind      } },
        { ":mailbox",   SQLITE_TEXT,    { .s = mailbox   } },
        { ":vcard_uid", SQLITE_TEXT,    { .s = vcard_uid } },
        { NULL,         SQLITE_NULL,    { .s = NULL      } }
    };
    static struct carddav_data cdata;
    struct read_rock rrock = { carddavdb, &cdata, 0, cb, rock };
    struct buf sqlbuf = BUF_INITIALIZER;

    buf_setcstr(&sqlbuf, CMD_GETFIELDS_JMAP);
    buf_appendcstr(&sqlbuf, " WHERE alive = 1 AND kind = :kind");
    if (mailbox)
        buf_appendcstr(&sqlbuf, " AND mailbox = :mailbox");
    if (vcard_uid)
        buf_appendcstr(&sqlbuf, " AND vcard_uid = :vcard_uid");
    buf_appendcstr(&sqlbuf, " ORDER BY mailbox, imap_uid;");

    int r = sqldb_exec(carddavdb->db, buf_cstring(&sqlbuf), bval, &read_cb, &rrock);
    buf_free(&sqlbuf);
    if (r) {
        syslog(LOG_ERR, "carddav error %s", error_message(r));
        /* XXX - free memory */
    }

    return r;
}


#define BYMAILBOX " mailbox = :mailbox AND"

#define BYKIND    " kind = :kind AND"

#define BYMODSEQ  " modseq > :modseq;"

EXPORTED int carddav_get_updates(struct carddav_db *carddavdb,
                                 modseq_t oldmodseq, const mbentry_t *mbentry,
                                 int kind, int limit,
                                 int (*cb)(void *rock,
                                           struct carddav_data *cdata),
                                 void *rock)
{
    const char *mailbox = !mbentry ? NULL :
        ((carddavdb->db->version >= DB_MBOXID_VERSION) ?
         mbentry->uniqueid : mbentry->name);
    struct sqldb_bindval bval[] = {
        { ":mailbox", SQLITE_TEXT,    { .s = mailbox   } },
        { ":modseq",  SQLITE_INTEGER, { .i = oldmodseq } },
        { ":kind",    SQLITE_INTEGER, { .i = kind      } },
        /* SQLite interprets a negative limit as unbounded. */
        { ":limit",   SQLITE_INTEGER, { .i = limit > 0 ? limit : -1 } },
        { NULL,       SQLITE_NULL,    { .s = NULL      } }
    };
    static struct carddav_data cdata;
    struct read_rock rrock = { carddavdb, &cdata, 1 /* tombstones */, cb, rock };
    struct buf sqlbuf = BUF_INITIALIZER;
    int r;

    buf_setcstr(&sqlbuf, CMD_GETFIELDS " WHERE");
    if (mailbox) buf_appendcstr(&sqlbuf, " mailbox = :mailbox AND");
    if (kind >= 0) {
        /* Use a negative value to signal that we accept ALL card types */
        buf_appendcstr(&sqlbuf, " kind = :kind AND");
    }
    if (!oldmodseq) buf_appendcstr(&sqlbuf, " alive = 1 AND");
    buf_appendcstr(&sqlbuf, " modseq > :modseq ORDER BY modseq LIMIT :limit;");

    r = sqldb_exec(carddavdb->db, buf_cstring(&sqlbuf), bval, &read_cb, &rrock);
    buf_free(&sqlbuf);

    if (r) {
        syslog(LOG_ERR, "carddav error %s", error_message(r));
        /* XXX - free memory */
    }

    return r;
}

EXPORTED int carddav_writecard(struct carddav_db *carddavdb,
                               struct carddav_data *cdata,
                               struct vparse_card *vcard,
                               int ispinned)
{
    struct vparse_entry *ventry;

    strarray_t emails = STRARRAY_INITIALIZER;
    strarray_t member_uids = STRARRAY_INITIALIZER;

    for (ventry = vcard->properties; ventry; ventry = ventry->next) {
        const char *name = ventry->name;
        const char *propval = ventry->v.value;

        if (!name) continue;
        if (!propval) continue;

        if (!strcasecmp(name, "uid")) {
            cdata->vcard_uid = propval;
        }
        else if (!strcasecmp(name, "n")) {
            cdata->name = propval;
        }
        else if (!strcasecmp(name, "fn")) {
            cdata->fullname = propval;
        }
        else if (!strcasecmp(name, "nickname")) {
            cdata->nickname = propval;
        }
        else if (!strcasecmp(name, "email")) {
            /* XXX - insert if primary */
            int ispref = 0;
            struct vparse_param *param;
            for (param = ventry->params; param; param = param->next) {
                if (!strcasecmp(param->name, "type") &&
                    !strcasecmp(param->value, "pref"))
                    ispref = 1;
            }
            strarray_append(&emails, propval);
            strarray_append(&emails, ispref ? "1" : "");
        }
        else if (!strcasecmp(name, "member") ||
                 !strcasecmp(name, "x-addressbookserver-member")) {
            if (strncmp(propval, "urn:uuid:", 9)) continue;
            strarray_append(&member_uids, propval+9);
            strarray_append(&member_uids, "");
        }
        else if (!strcasecmp(name, "x-fm-otheraccount-member")) {
            if (strncmp(propval, "urn:uuid:", 9)) continue;
            struct vparse_param *param = vparse_get_param(ventry, "userid");
            if (!param) continue;
            strarray_append(&member_uids, propval+9);
            strarray_append(&member_uids, param->value);
        }
        else if (!strcasecmp(name, "kind") ||
                 !strcasecmp(name, "x-addressbookserver-kind")) {
            if (!strcasecmp(propval, "group"))
                cdata->kind = CARDDAV_KIND_GROUP;
            /* default case is CARDDAV_KIND_CONTACT */
        }
    }

    int r = carddav_write(carddavdb, cdata);
    if (!r) r = carddav_write_emails(carddavdb, cdata->dav.rowid, &emails, ispinned);
    if (!r) r = carddav_write_groups(carddavdb, cdata->dav.rowid, &member_uids);

    strarray_fini(&emails);
    strarray_fini(&member_uids);

    return r;
}

EXPORTED int carddav_store(struct mailbox *mailbox, struct vparse_card *vcard,
                           const char *resource, modseq_t createdmodseq,
                           strarray_t *flags, struct entryattlist **annots,
                           const char *userid, struct auth_state *authstate,
                           int ignorequota)
{
    int r = 0;
    FILE *f = NULL;
    struct stagemsg *stage = NULL;
    char *header;
    quota_t qdiffs[QUOTA_NUMRESOURCES] = QUOTA_DIFFS_DONTCARE_INITIALIZER;
    struct appendstate as;
    time_t now = time(0);
    char *freeme = NULL;
    char datestr[80];
    static int vcard_max_size = -1;
    char *mbuserid = NULL;

    if (vcard_max_size < 0) {
        vcard_max_size = config_getint(IMAPOPT_VCARD_MAX_SIZE);
        if (vcard_max_size <= 0) vcard_max_size = INT_MAX;
    }

    init_internal();

    /* Prepare to stage the message */
    if (!(f = append_newstage(mailbox_name(mailbox), now, 0, &stage))) {
        syslog(LOG_ERR, "append_newstage(%s) failed", mailbox_name(mailbox));
        return -1;
    }

    /* set the REVision time */
    time_to_iso8601(now, datestr, sizeof(datestr), 0);
    vparse_replace_entry(vcard, NULL, "REV", datestr);

    /* Check size of vCard */
    struct buf buf = BUF_INITIALIZER;
    vparse_tobuf(vcard, &buf);
    if (buf_len(&buf) > (size_t) vcard_max_size) {
        buf_free(&buf);
        r = IMAP_MESSAGE_TOO_LARGE;
        goto done;
    }

    /* Create header for resource */
    const char *uid = vparse_stringval(vcard, "uid");
    const char *fullname = vparse_stringval(vcard, "fn");
    if (!resource) resource = freeme = strconcat(uid, ".vcf", (char *)NULL);
    mbuserid = mboxname_to_userid(mailbox_name(mailbox));

    time_to_rfc5322(now, datestr, sizeof(datestr));

    /* XXX  This needs to be done via an LDAP/DB lookup */
    header = charset_encode_mimeheader(mbuserid, 0, 0);
    fprintf(f, "From: %s <>\r\n", header);
    free(header);

    header = charset_encode_mimeheader(fullname, 0, 0);
    fprintf(f, "Subject: %s\r\n", header);
    free(header);

    fprintf(f, "Date: %s\r\n", datestr);

    /* Use SHA1(uid)@servername as Message-ID */
    struct message_guid uuid;
    message_guid_generate(&uuid, uid, strlen(uid));
    fprintf(f, "Message-ID: <%s@%s>\r\n",
            message_guid_encode(&uuid), config_servername);

    fprintf(f, "Content-Type: text/vcard; charset=utf-8\r\n");

    fprintf(f, "Content-Length: %u\r\n", (unsigned)buf_len(&buf));
    fprintf(f, "Content-Disposition: inline; filename=\"%s\"\r\n", resource);

    /* XXX  Check domain of data and use appropriate CTE */

    fprintf(f, "MIME-Version: 1.0\r\n");
    fprintf(f, "\r\n");

    /* Write the vCard data to the file */
    fprintf(f, "%s", buf_cstring(&buf));
    buf_free(&buf);

    qdiffs[QUOTA_STORAGE] = ftell(f);
    qdiffs[QUOTA_MESSAGE] = 1;

    fclose(f);

    if ((r = append_setup_mbox(&as, mailbox, userid, authstate, 0,
                               ignorequota ? NULL : qdiffs, 0, 0,
                               EVENT_MESSAGE_NEW|EVENT_CALENDAR))) {
        syslog(LOG_ERR, "append_setup(%s) failed: %s",
               mailbox_name(mailbox), error_message(r));
        goto done;
    }

    struct body *body = NULL;

    r = append_fromstage(&as, &body, stage, now, createdmodseq, flags, 0, annots);
    if (body) {
        message_free_body(body);
        free(body);
    }

    if (r) {
        syslog(LOG_ERR, "append_fromstage() failed");
        append_abort(&as);
        goto done;
    }

    /* Commit the append to the calendar mailbox */
    r = append_commit(&as);
    if (r) {
        syslog(LOG_ERR, "append_commit() failed");
        goto done;
    }

done:
    append_removestage(stage);
    free(freeme);
    free(mbuserid);
    return r;
}

EXPORTED int carddav_remove(struct mailbox *mailbox,
                            uint32_t olduid, int isreplace, const char *userid)
{

    int userflag;
    int r = mailbox_user_flag(mailbox, DFLAG_UNBIND, &userflag, 1);
    struct index_record oldrecord;

    init_internal();

    if (!r) r = mailbox_find_index_record(mailbox, olduid, &oldrecord);
    if (!r && !(oldrecord.internal_flags & FLAG_INTERNAL_EXPUNGED)) {
        if (isreplace) oldrecord.user_flags[userflag/32] |= 1<<(userflag&31);
        oldrecord.internal_flags |= FLAG_INTERNAL_EXPUNGED;

        r = mailbox_rewrite_index_record(mailbox, &oldrecord);

        /* Report mailbox event. */
        struct mboxevent *mboxevent = mboxevent_new(EVENT_MESSAGE_EXPUNGE);
        mboxevent_extract_record(mboxevent, mailbox, &oldrecord);
        mboxevent_extract_mailbox(mboxevent, mailbox);
        mboxevent_set_numunseen(mboxevent, mailbox, -1);
        mboxevent_set_access(mboxevent, NULL, NULL, userid, mailbox_name(mailbox), 0);
        mboxevent_notify(&mboxevent);
        mboxevent_free(&mboxevent);
    }
    if (r) {
        syslog(LOG_ERR, "expunging record (%s) failed: %s",
               mailbox_name(mailbox), error_message(r));
    }
    return r;
}

EXPORTED char *carddav_mboxname(const char *userid, const char *name)
{
    struct buf boxbuf = BUF_INITIALIZER;
    char *res = NULL;

    init_internal();

    buf_setcstr(&boxbuf, config_getstring(IMAPOPT_ADDRESSBOOKPREFIX));

    if (name) {
        size_t len = strcspn(name, "/");
        buf_putc(&boxbuf, '.');
        buf_appendmap(&boxbuf, name, len);
    }

    res = mboxname_user_mbox(userid, buf_cstring(&boxbuf));

    buf_free(&boxbuf);

    return res;
}

