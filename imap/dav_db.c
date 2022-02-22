/* dav_db.c -- implementation of per-user DAV database
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

#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "assert.h"
#include "caldav_alarm.h"
#include "cyrusdb.h"
#include "dav_db.h"
#include "global.h"
#include "sieve_db.h"
#include "user.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

#define CMD_CREATE_CAL                                                  \
    "CREATE TABLE IF NOT EXISTS ical_objs ("                            \
    " rowid INTEGER PRIMARY KEY,"                                       \
    " creationdate INTEGER,"                                            \
    " mailbox TEXT NOT NULL,"                                           \
    " resource TEXT NOT NULL,"                                          \
    " imap_uid INTEGER,"                                                \
    " modseq INTEGER,"                                                  \
    " createdmodseq INTEGER,"                                           \
    " lock_token TEXT,"                                                 \
    " lock_owner TEXT,"                                                 \
    " lock_ownerid TEXT,"                                               \
    " lock_expire INTEGER,"                                             \
    " comp_type INTEGER,"                                               \
    " ical_uid TEXT,"                                                   \
    " organizer TEXT,"                                                  \
    " dtstart TEXT,"                                                    \
    " dtend TEXT,"                                                      \
    " comp_flags INTEGER,"                                              \
    " sched_tag TEXT,"                                                  \
    " alive INTEGER,"                                                   \
    " UNIQUE( mailbox, imap_uid ),"                                     \
    " UNIQUE( mailbox, resource ) );"                                   \
    "CREATE INDEX IF NOT EXISTS idx_ical_uid ON ical_objs ( ical_uid );"

#define CMD_CREATE_JSCALOBJS                                            \
    "CREATE TABLE IF NOT EXISTS jscal_objs ("                           \
    " rowid INTEGER NOT NULL,"                                          \
    " ical_recurid TEXT NOT NULL DEFAULT '',"                           \
    " modseq INTEGER NOT NULL,"                                         \
    " createdmodseq INTEGER NOT NULL,"                                  \
    " dtstart TEXT NOT NULL,"                                           \
    " dtend TEXT NOT NULL,"                                             \
    " alive INTEGER NOT NULL,"                                          \
    " ical_guid TEXT NOT NULL,"                                         \
    " PRIMARY KEY (rowid, ical_recurid)"                                \
    " FOREIGN KEY (rowid) REFERENCES ical_objs (rowid) ON DELETE CASCADE );"

#define CMD_CREATE_CARD                                                 \
    "CREATE TABLE IF NOT EXISTS vcard_objs ("                           \
    " rowid INTEGER PRIMARY KEY,"                                       \
    " creationdate INTEGER,"                                            \
    " mailbox TEXT NOT NULL,"                                           \
    " resource TEXT NOT NULL,"                                          \
    " imap_uid INTEGER,"                                                \
    " modseq INTEGER,"                                                  \
    " createdmodseq INTEGER,"                                           \
    " lock_token TEXT,"                                                 \
    " lock_owner TEXT,"                                                 \
    " lock_ownerid TEXT,"                                               \
    " lock_expire INTEGER,"                                             \
    " version INTEGER,"                                                 \
    " vcard_uid TEXT,"                                                  \
    " kind INTEGER,"                                                    \
    " fullname TEXT,"                                                   \
    " name TEXT,"                                                       \
    " nickname TEXT,"                                                   \
    " alive INTEGER,"                                                   \
    " UNIQUE( mailbox, imap_uid ),"                                     \
    " UNIQUE( mailbox, resource ) );"                                   \
    "CREATE INDEX IF NOT EXISTS idx_vcard_fn ON vcard_objs ( fullname );" \
    "CREATE INDEX IF NOT EXISTS idx_vcard_uid ON vcard_objs ( vcard_uid );"

#define CMD_CREATE_EM                                                   \
    "CREATE TABLE IF NOT EXISTS vcard_emails ("                         \
    " rowid INTEGER PRIMARY KEY,"                                       \
    " objid INTEGER,"                                                   \
    " pos INTEGER NOT NULL," /* for sorting */                          \
    " email TEXT NOT NULL COLLATE NOCASE,"                              \
    " ispref INTEGER NOT NULL DEFAULT 0,"                               \
    " ispinned INTEGER NOT NULL DEFAULT 0,"                             \
    " FOREIGN KEY (objid) REFERENCES vcard_objs (rowid) ON DELETE CASCADE );" \
    "CREATE INDEX IF NOT EXISTS idx_vcard_email ON vcard_emails ( email COLLATE NOCASE );"

#define CMD_CREATE_GR                                                   \
    "CREATE TABLE IF NOT EXISTS vcard_groups ("                         \
    " rowid INTEGER PRIMARY KEY,"                                       \
    " objid INTEGER,"                                                   \
    " pos INTEGER NOT NULL," /* for sorting */                          \
    " member_uid TEXT NOT NULL,"                                        \
    " otheruser TEXT NOT NULL DEFAULT \"\","                            \
    " FOREIGN KEY (objid) REFERENCES vcard_objs (rowid) ON DELETE CASCADE );"

#define CMD_CREATE_OBJS                                                 \
    "CREATE TABLE IF NOT EXISTS dav_objs ("                             \
    " rowid INTEGER PRIMARY KEY,"                                       \
    " creationdate INTEGER,"                                            \
    " mailbox TEXT NOT NULL,"                                           \
    " resource TEXT NOT NULL,"                                          \
    " imap_uid INTEGER,"                                                \
    " modseq INTEGER,"                                                  \
    " createdmodseq INTEGER,"                                           \
    " lock_token TEXT,"                                                 \
    " lock_owner TEXT,"                                                 \
    " lock_ownerid TEXT,"                                               \
    " lock_expire INTEGER,"                                             \
    " filename TEXT,"                                                   \
    " type TEXT,"                                                       \
    " subtype TEXT,"                                                    \
    " res_uid TEXT,"                                                    \
    " ref_count INTEGER,"                                               \
    " alive INTEGER,"                                                   \
    " UNIQUE( mailbox, imap_uid ),"                                     \
    " UNIQUE( mailbox, resource ) );"                                   \

// dropped in version 12
#define CMD_CREATE_CALCACHE                                             \
    "CREATE TABLE IF NOT EXISTS ical_jmapcache ("                       \
    " rowid INTEGER NOT NULL,"                                          \
    " userid TEXT NOT NULL,"                                            \
    " jmapversion INTEGER NOT NULL,"                                    \
    " jmapdata TEXT NOT NULL,"                                          \
    " PRIMARY KEY (rowid, userid)"                                      \
    " FOREIGN KEY (rowid) REFERENCES ical_objs (rowid) ON DELETE CASCADE );"

#define CMD_CREATE_JSCALCACHE                                           \
    "CREATE TABLE IF NOT EXISTS jscal_cache ("                          \
    " rowid INTEGER NOT NULL,"                                          \
    " ical_recurid TEXT NOT NULL,"                                      \
    " userid TEXT NOT NULL,"                                            \
    " version INTEGER NOT NULL,"                                        \
    " data TEXT NOT NULL,"                                              \
    " PRIMARY KEY (rowid, ical_recurid, userid)"                             \
    " FOREIGN KEY (rowid, ical_recurid) REFERENCES jscal_objs (rowid, ical_recurid) ON DELETE CASCADE );"

#define CMD_CREATE_CARDCACHE                                            \
    "CREATE TABLE IF NOT EXISTS vcard_jmapcache ("                      \
    " rowid INTEGER NOT NULL PRIMARY KEY,"                              \
    " jmapversion INTEGER NOT NULL,"                                    \
    " jmapdata TEXT NOT NULL,"                                          \
    " FOREIGN KEY (rowid) REFERENCES vcard_objs (rowid) ON DELETE CASCADE );"

#define CMD_CREATE_SIEVE                                                \
    "CREATE TABLE IF NOT EXISTS sieve_scripts ("                        \
    " rowid INTEGER PRIMARY KEY,"                                       \
    " creationdate INTEGER,"                                            \
    " lastupdated INTEGER,"                                             \
    " mailbox TEXT NOT NULL,"                                           \
    " imap_uid INTEGER,"                                                \
    " modseq INTEGER,"                                                  \
    " createdmodseq INTEGER,"                                           \
    " id TEXT NOT NULL,"                                                \
    " name TEXT NOT NULL,"                                              \
    " contentid TEXT NOT NULL,"                                         \
    " isactive INTEGER,"                                                \
    " alive INTEGER,"                                                   \
    " UNIQUE( mailbox, imap_uid ),"                                     \
    " UNIQUE( id ) );"                                                  \
    "CREATE INDEX IF NOT EXISTS idx_sieve_name ON sieve_scripts ( name );"


#define CMD_CREATE CMD_CREATE_CAL CMD_CREATE_CARD CMD_CREATE_EM CMD_CREATE_GR \
                   CMD_CREATE_OBJS CMD_CREATE_CALCACHE CMD_CREATE_CARDCACHE   \
                   CMD_CREATE_SIEVE CMD_CREATE_JSCALOBJS CMD_CREATE_JSCALCACHE

/* leaves these unused columns around, but that's life.  A dav_reconstruct
 * will fix them */
#define CMD_DBUPGRADEv2                                         \
    "ALTER TABLE ical_objs ADD COLUMN comp_flags INTEGER;"      \
    "UPDATE ical_objs SET comp_flags = recurring + 2 * transp;"

#define CMD_DBUPGRADEv3                                         \
    "ALTER TABLE ical_objs ADD COLUMN modseq INTEGER;"          \
    "UPDATE ical_objs SET modseq = 1;"                          \
    "ALTER TABLE vcard_objs ADD COLUMN modseq INTEGER;"         \
    "UPDATE vcard_objs SET modseq = 1;"

#define CMD_DBUPGRADEv4                                         \
    "ALTER TABLE ical_objs ADD COLUMN alive INTEGER;"           \
    "UPDATE ical_objs SET alive = 1;"                           \
    "ALTER TABLE vcard_objs ADD COLUMN alive INTEGER;"          \
    "UPDATE vcard_objs SET alive = 1;"

#define CMD_DBUPGRADEv5                                         \
    "ALTER TABLE vcard_emails ADD COLUMN ispref INTEGER NOT NULL DEFAULT 0;"    \
    "ALTER TABLE vcard_groups ADD COLUMN otheruser TEXT NOT NULL DEFAULT \"\";"

#define CMD_DBUPGRADEv6 CMD_CREATE_OBJS

#define CMD_DBUPGRADEv7                                         \
    "ALTER TABLE ical_objs ADD COLUMN createdmodseq INTEGER;"   \
    "UPDATE ical_objs SET createdmodseq = 0;"                   \
    "ALTER TABLE vcard_objs ADD COLUMN createdmodseq INTEGER;"  \
    "UPDATE vcard_objs SET createdmodseq = 0;"                  \
    "ALTER TABLE dav_objs ADD COLUMN createdmodseq INTEGER;"    \
    "UPDATE dav_objs SET createdmodseq = 0;"

#define CMD_DBUPGRADEv8                                         \
    "ALTER TABLE vcard_emails ADD COLUMN ispinned INTEGER NOT NULL DEFAULT 0;"

#define CMD_DBUPGRADEv9 CMD_CREATE_CALCACHE CMD_CREATE_CARDCACHE

#define CMD_DBUPGRADEv10                                        \
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_ical_imapuid ON ical_objs ( mailbox, imap_uid );" \
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_vcard_imapuid ON vcard_objs ( mailbox, imap_uid );" \
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_object_imapuid ON dav_objs ( mailbox, imap_uid );" \
    "DROP INDEX IF EXISTS idx_res_uid;"

#define CMD_DBUPGRADEv14 CMD_CREATE_SIEVE

#define CMD_DBUPGRADEv15 \
    "DROP TABLE ical_jmapcache;" \
    CMD_CREATE_JSCALOBJS CMD_CREATE_JSCALCACHE \
    "INSERT INTO jscal_objs" \
    " SELECT rowid, '', modseq, createdmodseq, dtstart, dtend, alive, '' FROM ical_objs;"

static int sievedb_upgrade(sqldb_t *db);

struct sqldb_upgrade davdb_upgrade[] = {
  { 2, CMD_DBUPGRADEv2, NULL },
  { 3, CMD_DBUPGRADEv3, NULL },
  { 4, CMD_DBUPGRADEv4, NULL },
  { 5, CMD_DBUPGRADEv5, NULL },
  { 6, CMD_DBUPGRADEv6, NULL },
  { 7, CMD_DBUPGRADEv7, NULL },
  { 8, CMD_DBUPGRADEv8, NULL },
  { 9, CMD_DBUPGRADEv9, NULL },
  { 10, CMD_DBUPGRADEv10, NULL },
  /* Don't upgrade to version 11.  We only jump to 11 on CREATE */
  /* Don't upgrade to version 12.  This was an intermediate Sieve DB version */
  /* Don't upgrade to version 13.  This was an intermediate Sieve DB version */
  { 14, CMD_DBUPGRADEv14, &sievedb_upgrade },
  { 15, CMD_DBUPGRADEv15, NULL },
  { 0, NULL, NULL }
};

#define DB_VERSION 15

static sqldb_t *reconstruct_db;

/* Create filename corresponding to DAV DB for mailbox */
EXPORTED void dav_getpath(struct buf *fname, struct mailbox *mailbox)
{
    char *userid = mboxname_to_userid(mailbox_name(mailbox));

    if (userid) dav_getpath_byuserid(fname, userid);
    else buf_setcstr(fname, mailbox_meta_fname(mailbox, META_DAV));

    free(userid);
}

/* Create filename corresponding to DAV DB for userid */
EXPORTED void dav_getpath_byuserid(struct buf *fname, const char *userid)
{
    char *path = user_hash_meta(userid, FNAME_DAVSUFFIX);
    buf_setcstr(fname, path);
    free(path);
}

EXPORTED sqldb_t *dav_open_userid(const char *userid)
{
    if (reconstruct_db) return reconstruct_db;

    sqldb_t *db = NULL;
    struct buf fname = BUF_INITIALIZER;
    dav_getpath_byuserid(&fname, userid);
    db = sqldb_open(buf_cstring(&fname), CMD_CREATE, DB_VERSION, davdb_upgrade,
                    config_getduration(IMAPOPT_DAV_LOCK_TIMEOUT, 's') * 1000);
    buf_free(&fname);
    return db;
}

EXPORTED sqldb_t *dav_open_mailbox(struct mailbox *mailbox)
{
    if (reconstruct_db) return reconstruct_db;

    sqldb_t *db = NULL;
    struct buf fname = BUF_INITIALIZER;
    dav_getpath(&fname, mailbox);
    db = sqldb_open(buf_cstring(&fname), CMD_CREATE, DB_VERSION, davdb_upgrade,
                    config_getduration(IMAPOPT_DAV_LOCK_TIMEOUT, 's') * 1000);
    buf_free(&fname);
    return db;
}

EXPORTED int dav_attach_userid(sqldb_t *db, const char *userid)
{
    assert (!reconstruct_db);

    struct buf fname = BUF_INITIALIZER;
    dav_getpath_byuserid(&fname, userid);
    int r = sqldb_attach(db, buf_cstring(&fname));
    buf_free(&fname);
    return r;
}

EXPORTED int dav_attach_mailbox(sqldb_t *db, struct mailbox *mailbox)
{
    assert (!reconstruct_db);

    struct buf fname = BUF_INITIALIZER;
    dav_getpath(&fname, mailbox);
    int r = sqldb_attach(db, buf_cstring(&fname));
    buf_free(&fname);
    return r;
}

EXPORTED int dav_close(sqldb_t **dbp)
{
    if (reconstruct_db) return 0;

    return sqldb_close(dbp);
}


/*
 * mboxlist_usermboxtree() callback function to create DAV DB entries for a mailbox
 */
static int _dav_reconstruct_mb(const mbentry_t *mbentry,
                               void *rock
#ifndef WITH_JMAP
                                          __attribute__((unused))
#endif
                              )
{
#ifdef WITH_JMAP
    const char *userid = (const char *) rock;
    struct buf attrib = BUF_INITIALIZER;
#endif
    int (*addproc)(struct mailbox *) = NULL;
    int r = 0;

    signals_poll();

    switch (mbtype_isa(mbentry->mbtype)) {
#ifdef WITH_DAV
    case MBTYPE_CALENDAR:
    case MBTYPE_COLLECTION:
    case MBTYPE_ADDRESSBOOK:
        addproc = &mailbox_add_dav;
        break;
#endif
#ifdef USE_SIEVE
    case MBTYPE_SIEVE:
        addproc = &mailbox_add_sieve;
        break;
#endif
#ifdef WITH_JMAP
    case MBTYPE_JMAPSUBMIT:
        addproc = &mailbox_add_email_alarms;
        break;

    case MBTYPE_EMAIL:
        r = annotatemore_lookup(mbentry->name, "/specialuse", userid, &attrib);
        if (!r && buf_len(&attrib)) {
            strarray_t *specialuse =
                strarray_split(buf_cstring(&attrib), NULL, 0);

            if (strarray_find(specialuse, "\\Snoozed", 0) >= 0) {
                addproc = &mailbox_add_email_alarms;
            }
            strarray_free(specialuse);
        }
        buf_free(&attrib);
        break;
#endif
    }

    if (addproc) {
        struct mailbox *mailbox = NULL;
        /* Open/lock header */
        r = mailbox_open_irl(mbentry->name, &mailbox);
        if (!r) r = addproc(mailbox);
        mailbox_close(&mailbox);
    }

    return r;
}

static void run_audit_tool(const char *tool, const char *userid, const char *srcdb, const char *dstdb)
{
    pid_t pid = fork();
    if (pid < 0)
        return;

    if (pid == 0) {
        /* child */
        execl(tool, tool, "-C", config_filename, "-u", userid, srcdb, dstdb, (void *)NULL);
        exit(-1);
    }

    int status;
    while (waitpid(pid, &status, 0) < 0);
}

EXPORTED int dav_reconstruct_user(const char *userid, const char *audit_tool)
{
    syslog(LOG_NOTICE, "dav_reconstruct_user: %s", userid);

    struct buf fname = BUF_INITIALIZER;
    dav_getpath_byuserid(&fname, userid);

    struct buf newfname = BUF_INITIALIZER;
    dav_getpath_byuserid(&newfname, userid);
    buf_printf(&newfname, ".NEW");

    struct mboxlock *namespacelock = user_namespacelock(userid);

    int r = IMAP_IOERROR;
    reconstruct_db = sqldb_open(buf_cstring(&newfname), CMD_CREATE, DB_VERSION, davdb_upgrade,
                                config_getduration(IMAPOPT_DAV_LOCK_TIMEOUT, 's') * 1000);
    if (reconstruct_db) {
        r = sqldb_begin(reconstruct_db, "reconstruct");
#ifdef WITH_DAV
        // make all the alarm updates to go this database too
        if (!r) r = caldav_alarm_set_reconstruct(reconstruct_db);
#endif
        // reconstruct everything
        if (!r) r = mboxlist_usermboxtree(userid, NULL,
                                          _dav_reconstruct_mb, (void *) userid, 0);
#ifdef WITH_DAV
        // make sure all the alarms are resolved
        if (!r) r = caldav_alarm_process(0, NULL, /*dryrun*/1);
        // commit events over to ther alarm database if we're keeping them
        if (!r && !audit_tool) r = caldav_alarm_commit_reconstruct(userid);
        else caldav_alarm_rollback_reconstruct();
#endif
        // and commit to this DB
        if (r) sqldb_rollback(reconstruct_db, "reconstruct");
        else sqldb_commit(reconstruct_db, "reconstruct");
        sqldb_close(&reconstruct_db);
    }

    /* this actually works before close according to the internets */
    if (r) {
        syslog(LOG_ERR, "dav_reconstruct_user: %s FAILED %s", userid, error_message(r));
        if (audit_tool) {
            printf("Not auditing %s, reconstruct failed %s\n", userid, error_message(r));
        }
        unlink(buf_cstring(&newfname));
    }
    else {
        syslog(LOG_NOTICE, "dav_reconstruct_user: %s SUCCEEDED", userid);
        if (audit_tool) {
            run_audit_tool(audit_tool, userid, buf_cstring(&fname), buf_cstring(&newfname));
            unlink(buf_cstring(&newfname));
        }
        else {
            rename(buf_cstring(&newfname), buf_cstring(&fname));
        }
    }

    mboxname_release(&namespacelock);

    buf_free(&newfname);
    buf_free(&fname);

    return 0;
}


struct sievedb_upgrade_rock {
    char *mboxname;
    strarray_t *sha1;
};

static int sievedb_upgrade_cb(sqlite3_stmt *stmt, void *rock)
{
    struct sievedb_upgrade_rock *srock = (struct sievedb_upgrade_rock *) rock;

    if (!srock->mboxname) {
        srock->mboxname = xstrdup((const char *) sqlite3_column_text(stmt, 0));
    }

    if (srock->sha1) {
        const char *content = (const char *) sqlite3_column_text(stmt, 1);
        unsigned rowid = sqlite3_column_int(stmt, 2);
        struct message_guid uuid;

        /* Generate SHA1 from content */
        message_guid_generate(&uuid, content, strlen(content));

        /* Add SHA1 to our array using rowid as the index */
        strarray_set(srock->sha1, rowid, message_guid_encode(&uuid));
    }

    return 0;
}

#define CMD_GET_v12_ROWS                 \
    "SELECT mailbox, content, rowid FROM sieve_scripts;"

#define CMD_ALTER_v12_TABLE              \
    "ALTER TABLE sieve_scripts RENAME COLUMN content TO contentid;"

#define CMD_UPDATE_v13_ROW               \
    "UPDATE sieve_scripts SET contentid = :contentid WHERE rowid = :rowid;"

#define CMD_GET_v13_ROW1                 \
    "SELECT mailbox FROM sieve_scripts LIMIT 1;"

#define CMD_UPDATE_v13_TABLE             \
    "UPDATE sieve_scripts SET mailbox = :mailbox;"


/* Upgrade v12/v13 sieve_script table to v14 */
static int sievedb_upgrade(sqldb_t *db)
{
    struct sievedb_upgrade_rock srock = { NULL, NULL };
    struct sqldb_bindval bval[] = {
        { ":rowid",     SQLITE_INTEGER, { .i = 0    } },
        { ":contentid", SQLITE_TEXT,    { .s = NULL } },
        { ":mailbox",   SQLITE_TEXT,    { .s = NULL } },
        { NULL,         SQLITE_NULL,    { .s = NULL } } };
    strarray_t sha1 = STRARRAY_INITIALIZER;
    mbentry_t *mbentry = NULL;
    int rowid;
    int r = 0;

    if (db->version == 12) {
        /* Create an array of SHA1 for the content in each record */
        srock.sha1 = &sha1;
        r = sqldb_exec(db, CMD_GET_v12_ROWS, NULL, &sievedb_upgrade_cb, &srock);
        if (r) goto done;

        /* Rename 'content' -> 'contentid' */
        r = sqldb_exec(db, CMD_ALTER_v12_TABLE, NULL, NULL, NULL);
        if (r) goto done;

        /* Rewrite 'contentid' columns with actual ids (SHA1) */
        for (rowid = 1; rowid < strarray_size(&sha1); rowid++) {
            bval[0].val.i = rowid;
            bval[1].val.s = strarray_nth(&sha1, rowid);

            r = sqldb_exec(db, CMD_UPDATE_v13_ROW, bval, NULL, NULL);
            if (r) goto done;
        }
    }
    else if (db->version == 13) {
        /* Fetch mailbox name from first record */
        r = sqldb_exec(db, CMD_GET_v13_ROW1, NULL, &sievedb_upgrade_cb, &srock);
        if (r) goto done;
    }

    /* This will only be set if we are upgrading from v12 or v13
       AND there are records in the table */
    if (!srock.mboxname) goto done;

    r = mboxlist_lookup_allow_all(srock.mboxname, &mbentry, NULL);
    if (r) goto done;

    /* Rewrite 'mailbox' columns with mboxid rather than mboxname */
    bval[2].val.s = mbentry->uniqueid;
    r = sqldb_exec(db, CMD_UPDATE_v13_TABLE, bval, NULL, NULL);

  done:
    mboxlist_entry_free(&mbentry);
    strarray_fini(&sha1);
    free(srock.mboxname);

    return r;
}
