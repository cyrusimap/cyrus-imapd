/* sqlconsts.c -- backup index sql constants
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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

#include "backup/sqlconsts.h"

#define QUOTE(...) #__VA_ARGS__

const int backup_index_version = 1;

const char backup_index_initsql[] = QUOTE(
    CREATE TABLE backup(
        id INTEGER PRIMARY KEY ASC,
        timestamp INTEGER,
        offset INTEGER unique,
        length INTEGER
    );

    CREATE TABLE message(
        id INTEGER PRIMARY KEY ASC,
        guid CHAR UNIQUE NOT NULL,
        partition CHAR,
        backup_id INTEGER REFERENCES backup(id),
        offset INTEGER,
        length INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_msg_guid ON message(guid);

    CREATE TABLE mailbox(
        id INTEGER PRIMARY KEY ASC,
        last_backup_id INTEGER NOT NULL REFERENCES backup(id),
        uniqueid CHAR UNIQUE NOT NULL,
        mboxname CHAR NOT NULL,
        mboxtype CHAR,
        last_uid INTEGER,
        highestmodseq INTEGER,
        recentuid INTEGER,
        recenttime INTEGER,
        last_appenddate INTEGER,
        pop3_last_login INTEGER,
        pop3_show_after INTEGER,
        uidvalidity INTEGER,
        partition CHAR,
        acl CHAR,
        options CHAR,
        sync_crc INTEGER,
        sync_crc_annot INTEGER,
        quotaroot CHAR,
        xconvmodseq INTEGER,
        annotations CHAR,
        deleted INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_bmb_uid ON mailbox(uniqueid);

    CREATE TABLE mailbox_message(
        id INTEGER PRIMARY KEY ASC,
        mailbox_id INTEGER NOT NULL REFERENCES mailbox(id),
        message_id INTEGER NOT NULL REFERENCES message(id),
        last_backup_id INTEGER NOT NULL REFERENCES backup(id), /* maybe? */
        uid INTEGER NOT NULL,
        modseq INTEGER,
        last_updated INTEGER,
        flags CHAR,
        internaldate INTEGER,
        annotations CHAR,
        expunged INTEGER,
        UNIQUE (mailbox_id, message_id)
    );
    CREATE INDEX IF NOT EXISTS idx_mbr_uid ON mailbox_message(uid);
);

const struct sqldb_upgrade backup_index_upgrade[] = {
    { 0, NULL, NULL } /* leave me last */
};

const char backup_index_start_sql[] = QUOTE(
    INSERT INTO backup ( timestamp, offset )
        VALUES ( :timestamp, :offset );
);

const char backup_index_end_sql[] = QUOTE(
    UPDATE backup SET
        length = :length
    WHERE id = :id;
);

const char backup_index_mailbox_update_sql[] = QUOTE(
    UPDATE mailbox SET
        last_backup_id = :last_backup_id,
        mboxname = :mboxname,
        mboxtype = :mboxtype,
        last_uid = :last_uid,
        highestmodseq = :highestmodseq,
        recentuid = :recentuid,
        recenttime = :recenttime,
        last_appenddate = :last_appenddate,
        pop3_last_login = :pop3_last_login,
        pop3_show_after = :pop3_show_after,
        uidvalidity = :uidvalidity,
        partition = :partition,
        acl = :acl,
        options = :options,
        sync_crc = :sync_crc,
        sync_crc_annot = :sync_crc_annot,
        quotaroot = :quotaroot,
        xconvmodseq = :xconvmodseq,
        annotations = :annotations,
        deleted = :deleted
    WHERE uniqueid = :uniqueid;
);

const char backup_index_mailbox_insert_sql[] = QUOTE(
    INSERT INTO mailbox (
        last_backup_id, uniqueid, mboxname, mboxtype, last_uid,
        highestmodseq, recentuid, recenttime, last_appenddate,
        pop3_last_login, pop3_show_after, uidvalidity, partition,
        acl, options, sync_crc, sync_crc_annot, quotaroot,
        xconvmodseq, annotations, deleted
    )
    VALUES (
        :last_backup_id, :uniqueid, :mboxname, :mboxtype, :last_uid,
        :highestmodseq, :recentuid, :recenttime, :last_appenddate,
        :pop3_last_login, :pop3_show_after, :uidvalidity, :partition,
        :acl, :options, :sync_crc, :sync_crc_annot, :quotaroot,
        :xconvmodseq, :annotations, :deleted
    );
);

const char backup_index_mailbox_select_all_sql[] = QUOTE(
    SELECT
        id, last_backup_id, uniqueid, mboxname, mboxtype, last_uid, highestmodseq,
        recentuid, recenttime, last_appenddate, pop3_last_login, pop3_show_after,
        uidvalidity, partition, acl, options, sync_crc, sync_crc_annot, quotaroot,
        xconvmodseq, annotations, deleted
    FROM mailbox;
);

const char backup_index_mailbox_select_mboxname_sql[] = QUOTE(
    SELECT
        id, last_backup_id, uniqueid, mboxname, mboxtype, last_uid, highestmodseq,
        recentuid, recenttime, last_appenddate, pop3_last_login, pop3_show_after,
        uidvalidity, partition, acl, options, sync_crc, sync_crc_annot, quotaroot,
        xconvmodseq, annotations, deleted
    FROM mailbox
    WHERE mboxname = :mboxname;
);

const char backup_index_mailbox_select_uniqueid_sql[] = QUOTE(
    SELECT
        id, last_backup_id, uniqueid, mboxname, mboxtype, last_uid, highestmodseq,
        recentuid, recenttime, last_appenddate, pop3_last_login, pop3_show_after,
        uidvalidity, partition, acl, options, sync_crc, sync_crc_annot, quotaroot,
        xconvmodseq, annotations, deleted
    FROM mailbox
    WHERE uniqueid = :uniqueid;
);

const char backup_index_mailbox_message_update_sql[] = QUOTE(
    UPDATE mailbox_message SET
        last_backup_id = :last_backup_id,
        uid = :uid,
        modseq = :modseq,
        last_updated = :last_updated,
        flags = :flags,
        internaldate = :internaldate,
        annotations = :annotations,
        expunged = :expunged
    WHERE mailbox_id = :mailbox_id and message_id = :message_id;
);

const char backup_index_mailbox_message_insert_sql[] = QUOTE(
    INSERT INTO mailbox_message (
        mailbox_id, message_id, last_backup_id, uid,
        modseq, last_updated, flags, internaldate,
        annotations, expunged
    )
    VALUES (
        :mailbox_id, :message_id, :last_backup_id, :uid,
        :modseq, :last_updated, :flags, :internaldate,
        :annotations, :expunged
    );
);

const char backup_index_mailbox_message_select_mailbox_sql[] = QUOTE(
    SELECT
        r.id as id, mailbox_id, message_id, last_backup_id, uid,
        modseq, last_updated, flags, internaldate,
        m.guid as guid, m.length as length, annotations,
        expunged
    FROM mailbox_message as r
    JOIN message as m
    ON r.message_id = m.id
    WHERE mailbox_id = :mailbox_id;
);

const char backup_index_message_insert_sql[] = QUOTE(
    INSERT INTO message (
        guid, partition, backup_id, offset, length
    )
    VALUES (
        :guid, :partition, :backup_id, :offset, :length
    );
);

const char backup_index_message_select_guid_sql[] = QUOTE(
    SELECT id, guid, partition, backup_id, offset, length
    FROM message
    WHERE guid = :guid;
);
