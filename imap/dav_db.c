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

#define CMD_CREATE_CALCACHE                                             \
    "CREATE TABLE IF NOT EXISTS ical_jmapcache ("                       \
    " rowid INTEGER NOT NULL,"                                          \
    " userid TEXT NOT NULL,"                                            \
    " jmapversion INTEGER NOT NULL,"                                    \
    " jmapdata TEXT NOT NULL,"                                          \
    " PRIMARY KEY (rowid, userid)"                                      \
    " FOREIGN KEY (rowid) REFERENCES ical_objs (rowid) ON DELETE CASCADE );"

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
                   CMD_CREATE_SIEVE

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

#define CMD_DBROLLBACKv15 \
    "DROP TABLE IF EXISTS jscal_objs;" \
    "DROP TABLE IF EXISTS jscal_cache;" \
    CMD_CREATE_CALCACHE

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
  /* Version 15 is reserved for the jmap-calendars-01 branch */
  { 16, CMD_DBROLLBACKv15, NULL },

  { 0, NULL, NULL }
};

#define DB_VERSION 16

static sqldb_t *reconstruct_db;

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
        // make all the alarm updates to go this database too
        if (!r) r = caldav_alarm_set_reconstruct(reconstruct_db);
        // reconstruct everything
        if (!r) r = mboxlist_usermboxtree(userid, NULL,
                                          _dav_reconstruct_mb, (void *) userid, 0);
        // make sure all the alarms are resolved
        if (!r) r = caldav_alarm_process(0, NULL, /*dryrun*/1);
        // commit events over to ther alarm database if we're keeping them
        if (!r && !audit_tool) r = caldav_alarm_commit_reconstruct(userid);
        else caldav_alarm_rollback_reconstruct();
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
