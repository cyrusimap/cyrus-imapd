/* lcb_sqlconsts.c -- backup index sql constants
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

#include "backup/lcb_sqlconsts.h"

/* n.b. this will collapse internal whitespace, and swallow leading/trailing
 * whitespace.  be careful when concatenating QUOTE()d literals.
 */
#define QUOTE(...) #__VA_ARGS__

const int backup_index_version = 3;

const char backup_index_initsql[] = QUOTE(
    CREATE TABLE chunk(
        id INTEGER PRIMARY KEY ASC,
        ts_start INTEGER,
        ts_end INTEGER,
        offset INTEGER unique,
        length INTEGER,
        file_sha1 TEXT,
        data_sha1 TEXT
    );

    CREATE TABLE message(
        id INTEGER PRIMARY KEY ASC,
        guid CHAR UNIQUE NOT NULL,
        partition CHAR,
        chunk_id INTEGER REFERENCES chunk(id),
        offset INTEGER,
        size INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_msg_guid ON message(guid);

    CREATE TABLE mailbox(
        id INTEGER PRIMARY KEY ASC,
        last_chunk_id INTEGER NOT NULL REFERENCES chunk(id),
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
        last_chunk_id INTEGER NOT NULL REFERENCES chunk(id),
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

    CREATE TABLE subscription(
        id INTEGER PRIMARY KEY ASC,
        last_chunk_id INTEGER NOT NULL REFERENCES chunk(id),
        mboxname CHAR UNIQUE NOT NULL,
        unsubscribed INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_sub_mbx ON subscription(mboxname);

    CREATE TABLE seen(
        id INTEGER PRIMARY KEY ASC,
        last_chunk_id INTEGER NOT NULL REFERENCES chunk(id),
        uniqueid CHAR UNIQUE NOT NULL,
        lastread INTEGER,
        lastuid INTEGER,
        lastchange INTEGER,
        seenuids CHAR
    );
    CREATE INDEX IF NOT EXISTS idx_seen_unq ON seen(uniqueid);

    CREATE TABLE sieve(
        id INTEGER PRIMARY KEY ASC,
        chunk_id INTEGER NOT NULL REFERENCES chunk(id),
        last_update INTEGER,
        filename CHAR NOT NULL,
        guid CHAR NOT NULL,
        offset INTEGER,
        deleted INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_siv_fn ON sieve(filename);
);

static const char backup_index_upgrade_v2[] = QUOTE(
    CREATE TABLE subscription(
        id INTEGER PRIMARY KEY ASC,
        last_chunk_id INTEGER NOT NULL REFERENCES chunk(id),
        mboxname CHAR UNIQUE NOT NULL,
        unsubscribed INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_sub_mbx ON subscription(mboxname);
);

static const char backup_index_upgrade_v3[] = QUOTE(
    CREATE TABLE seen(
        id INTEGER PRIMARY KEY ASC,
        last_chunk_id INTEGER NOT NULL REFERENCES chunk(id),
        uniqueid CHAR UNIQUE NOT NULL,
        lastread INTEGER,
        lastuid INTEGER,
        lastchange INTEGER,
        seenuids CHAR
    );
    CREATE INDEX IF NOT EXISTS idx_seen_unq ON seen(uniqueid);
);

static const char backup_index_upgrade_v4[] = QUOTE(
    CREATE TABLE sieve(
        id INTEGER PRIMARY KEY ASC,
        chunk_id INTEGER NOT NULL REFERENCES chunk(id),
        last_update INTEGER,
        filename CHAR NOT NULL,
        guid CHAR NOT NULL,
        offset INTEGER,
        deleted INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_siv_fn ON sieve(filename);
);

const struct sqldb_upgrade backup_index_upgrade[] = {
    { 2, backup_index_upgrade_v2, NULL },
    { 3, backup_index_upgrade_v3, NULL },
    { 4, backup_index_upgrade_v4, NULL },
    { 0, NULL, NULL } /* leave me last */
};

const char backup_index_start_sql[] = QUOTE(
    INSERT INTO chunk ( ts_start, offset, file_sha1 )
        VALUES ( :ts_start, :offset, :file_sha1 );
);

const char backup_index_end_sql[] = QUOTE(
    UPDATE chunk SET
        ts_end = :ts_end,
        length = :length,
        data_sha1 = :data_sha1
    WHERE id = :id;
);

#define CHUNK_SELECT_FIELDS QUOTE(                              \
    id, ts_start, ts_end, offset, length, file_sha1, data_sha1  \
)

const char backup_index_chunk_select_all_sql[] =
    "SELECT " CHUNK_SELECT_FIELDS
    " FROM chunk"
    ";"
;

const char backup_index_chunk_select_live_sql[] =
    "SELECT " CHUNK_SELECT_FIELDS
    " FROM chunk"
    " WHERE id IN ("
    "  SELECT last_chunk_id"
    "   FROM mailbox"
    "   WHERE deleted IS NULL OR deleted > :since"
    "  UNION"
    "  SELECT last_chunk_id"
    "   FROM mailbox_message"
    "   WHERE expunged IS NULL OR expunged > :since"
    "  UNION"
    "  SELECT chunk_id"
    "   FROM message AS m"
    "   JOIN mailbox_message AS mm"
    "   ON m.id = mm.message_id"
    "    AND (mm.expunged IS NULL OR mm.expunged > :since)"
    "  UNION"
    "  SELECT last_chunk_id"
    "   FROM subscription"
    "   WHERE unsubscribed IS NULL OR unsubscribed > :since"
    "  UNION"
    "  SELECT last_chunk_id"
    "   FROM seen"
    "  UNION"
    "  SELECT chunk_id"
    "   FROM sieve"
    "   WHERE deleted IS NULL or deleted > :since"
    " )"
    ";"
;

const char backup_index_chunk_select_latest_sql[] =
    "SELECT " CHUNK_SELECT_FIELDS
    " FROM chunk"
    " WHERE id = (SELECT MAX(id) FROM chunk)"
    ";"
;

const char backup_index_chunk_select_id_sql[] =
    "SELECT " CHUNK_SELECT_FIELDS
    " FROM chunk"
    " WHERE id = :id"
    ";"
;

const char backup_index_mailbox_update_sql[] = QUOTE(
    UPDATE mailbox SET
        last_chunk_id = :last_chunk_id,
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

/* FIXME use uniqueid when sync proto contains it */
const char backup_index_mailbox_rename_sql[] = QUOTE(
    UPDATE mailbox SET
        mboxname = :newmboxname,
        partition = :partition,
        uidvalidity = :uidvalidity
    WHERE mboxname = :oldmboxname;
);

const char backup_index_mailbox_delete_sql[] = QUOTE(
    UPDATE mailbox SET
        deleted = :deleted
    WHERE mboxname = :mboxname;
);

const char backup_index_mailbox_insert_sql[] = QUOTE(
    INSERT INTO mailbox (
        last_chunk_id, uniqueid, mboxname, mboxtype, last_uid,
        highestmodseq, recentuid, recenttime, last_appenddate,
        pop3_last_login, pop3_show_after, uidvalidity, partition,
        acl, options, sync_crc, sync_crc_annot, quotaroot,
        xconvmodseq, annotations, deleted
    )
    VALUES (
        :last_chunk_id, :uniqueid, :mboxname, :mboxtype, :last_uid,
        :highestmodseq, :recentuid, :recenttime, :last_appenddate,
        :pop3_last_login, :pop3_show_after, :uidvalidity, :partition,
        :acl, :options, :sync_crc, :sync_crc_annot, :quotaroot,
        :xconvmodseq, :annotations, :deleted
    );
);

#define MAILBOX_SELECT_FIELDS QUOTE(                                \
    m.id, m.last_chunk_id, uniqueid, mboxname, mboxtype, last_uid,  \
    highestmodseq, recentuid, recenttime, last_appenddate,          \
    pop3_last_login, pop3_show_after, uidvalidity, m.partition, acl,\
    options, sync_crc, sync_crc_annot, quotaroot, xconvmodseq,      \
    m.annotations, deleted                                          \
)

const char backup_index_mailbox_select_all_sql[] =
    "SELECT " MAILBOX_SELECT_FIELDS
    " FROM mailbox AS m"
    ";"
;

const char backup_index_mailbox_select_mboxname_sql[] =
    "SELECT " MAILBOX_SELECT_FIELDS
    " FROM mailbox AS m"
    " WHERE mboxname = :mboxname"
    ";"
;

const char backup_index_mailbox_select_uniqueid_sql[] =
    "SELECT " MAILBOX_SELECT_FIELDS
    " FROM mailbox AS m"
    " WHERE uniqueid = :uniqueid"
    ";"
;

const char backup_index_mailbox_select_chunkid_sql[] =
    "SELECT " MAILBOX_SELECT_FIELDS
    " FROM mailbox AS m"
    " WHERE last_chunk_id = :last_chunk_id"
    ";"
;

const char backup_index_mailbox_select_message_guid_sql[] =
    "SELECT " MAILBOX_SELECT_FIELDS
    " FROM mailbox AS m"
    " JOIN mailbox_message AS mm"
    " ON mm.mailbox_id = m.id"
    " JOIN message AS msg"
    " ON mm.message_id = msg.id"
    " WHERE msg.guid = :guid"
    ";"
;

const char backup_index_mailbox_message_update_sql[] = QUOTE(
    UPDATE mailbox_message SET
        last_chunk_id = :last_chunk_id,
        uid = :uid,
        modseq = :modseq,
        last_updated = :last_updated,
        flags = :flags,
        internaldate = :internaldate,
        annotations = :annotations,
        expunged = COALESCE(
            (SELECT expunged FROM mailbox_message
                WHERE mailbox_id = :mailbox_id
                AND message_id = :message_id),
            :expunged
        )
    WHERE mailbox_id = :mailbox_id AND message_id = :message_id;
);

const char backup_index_mailbox_message_insert_sql[] = QUOTE(
    INSERT INTO mailbox_message (
        mailbox_id, message_id, last_chunk_id, uid,
        modseq, last_updated, flags, internaldate,
        annotations, expunged
    )
    VALUES (
        :mailbox_id, :message_id, :last_chunk_id, :uid,
        :modseq, :last_updated, :flags, :internaldate,
        :annotations, :expunged
    );
);

#define MAILBOX_MESSAGE_SELECT_FIELDS QUOTE(                                \
    r.id as id, mailbox_id, mb.uniqueid as mailbox_uniqueid, message_id,    \
    r.last_chunk_id, uid, modseq, last_updated, flags, internaldate,        \
    m.guid as guid, m.size as size, r.annotations,                          \
    expunged                                                                \
)

#define MAILBOX_MESSAGE_SELECT_JOIN QUOTE(                  \
    mailbox_message as r                                    \
    JOIN message as m                                       \
    ON r.message_id = m.id                                  \
    JOIN mailbox as mb                                      \
    on r.mailbox_id = mb.id                                 \
)

const char backup_index_mailbox_message_select_mailbox_sql[] =
    "SELECT " MAILBOX_MESSAGE_SELECT_FIELDS
    " FROM " MAILBOX_MESSAGE_SELECT_JOIN
    " WHERE mailbox_id = :mailbox_id"
    ";"
;

const char backup_index_mailbox_message_select_chunkid_sql[] =
    "SELECT " MAILBOX_MESSAGE_SELECT_FIELDS
    " FROM " MAILBOX_MESSAGE_SELECT_JOIN
    " WHERE r.last_chunk_id = :last_chunk_id"
    ";"
;

const char backup_index_mailbox_message_select_all_sql[] =
    "SELECT " MAILBOX_MESSAGE_SELECT_FIELDS
    " FROM " MAILBOX_MESSAGE_SELECT_JOIN
    ";"
;

const char backup_index_mailbox_message_select_one_sql[] =
    "SELECT " MAILBOX_MESSAGE_SELECT_FIELDS
    " FROM " MAILBOX_MESSAGE_SELECT_JOIN
    " WHERE mb.uniqueid = :uniqueid"
    "  AND m.guid = :guid"
    ";"
;

const char backup_index_mailbox_message_expunge_sql[] = QUOTE(
    UPDATE mailbox_message
    SET expunged = :expunged
    WHERE mailbox_id = :mailbox_id AND uid = :uid;
);

const char backup_index_message_update_sql[] = QUOTE(
    UPDATE message SET
        guid = :guid,
        partition = :partition,
        chunk_id = :chunk_id,
        offset = :offset,
        size = :size
    WHERE guid = :guid;
);

const char backup_index_message_insert_sql[] = QUOTE(
    INSERT INTO message (
        guid, partition, chunk_id, offset, size
    )
    VALUES (
        :guid, :partition, :chunk_id, :offset, :size
    );
);

#define MESSAGE_SELECT_FIELDS QUOTE(                    \
    m.id, guid, partition, chunk_id, offset, size       \
)

const char backup_index_message_select_all_sql[] =
    "SELECT " MESSAGE_SELECT_FIELDS
    " FROM message AS m"
    " ORDER BY id"
    ";"
;

const char backup_index_message_select_guid_sql[] =
    "SELECT " MESSAGE_SELECT_FIELDS
    " FROM message AS m"
    " WHERE guid = :guid"
    ";"
;

const char backup_index_message_select_chunkid_sql[] =
    "SELECT " MESSAGE_SELECT_FIELDS
    " FROM message AS m"
    " WHERE chunk_id = :chunk_id"
    ";"
;

const char backup_index_message_select_live_chunkid_sql[] =
    "SELECT DISTINCT " MESSAGE_SELECT_FIELDS
    " FROM message AS m"
    " JOIN mailbox_message AS mm"
    " ON m.id = mm.message_id"
    "  AND (mm.expunged IS NULL OR mm.expunged > :since)"
    " WHERE chunk_id = :chunk_id"
    ";"
;

const char backup_index_seen_update_sql[] = QUOTE(
    UPDATE seen SET
        last_chunk_id = :last_chunk_id,
        lastread = :lastread,
        lastuid = :lastuid,
        lastchange = :lastchange,
        seenuids = :seenuids
    WHERE uniqueid = :uniqueid;
);

const char backup_index_seen_insert_sql[] = QUOTE(
    INSERT INTO seen (
        last_chunk_id, uniqueid, lastread, lastuid, lastchange, seenuids
    )
    VALUES (
        :last_chunk_id, :uniqueid, :lastread, :lastuid, :lastchange, :seenuids
    );
);

#define SEEN_SELECT_FIELDS QUOTE(                       \
    seen.id, seen.last_chunk_id, uniqueid, lastread,    \
    lastuid, lastchange, seenuids                       \
)

const char backup_index_seen_select_all_sql[] =
    "SELECT " SEEN_SELECT_FIELDS
    " FROM seen AS seen"
    " ORDER BY seen.id"
    ";"
;

const char backup_index_seen_select_chunkid_sql[] =
    "SELECT " SEEN_SELECT_FIELDS
    " FROM seen AS seen"
    " WHERE last_chunk_id = :last_chunk_id"
    " ORDER BY seen.id"
    ";"
;

const char backup_index_subscription_update_sql[] = QUOTE(
    UPDATE subscription SET
        last_chunk_id = :last_chunk_id,
        unsubscribed = :unsubscribed
    WHERE mboxname = :mboxname;
);

const char backup_index_subscription_insert_sql[] = QUOTE(
    INSERT INTO subscription (
        last_chunk_id, mboxname, unsubscribed
    )
    VALUES (
        :last_chunk_id, :mboxname, :unsubscribed
    );
);

#define SUBSCRIPTION_SELECT_FIELDS QUOTE(               \
    sub.id, sub.last_chunk_id, mboxname, unsubscribed   \
)

const char backup_index_subscription_select_all_sql[] =
    "SELECT " SUBSCRIPTION_SELECT_FIELDS
    " FROM subscription AS sub"
    " ORDER BY sub.id"
    ";"
;

const char backup_index_subscription_select_chunkid_sql[] =
    "SELECT " SUBSCRIPTION_SELECT_FIELDS
    " FROM subscription AS sub"
    " WHERE last_chunk_id = :last_chunk_id"
    " ORDER BY sub.id"
    ";"
;

const char backup_index_sieve_insert_sql[] = QUOTE(
    INSERT INTO sieve (
        chunk_id, last_update, filename, guid, offset
    )
    VALUES (
        :chunk_id, :last_update, :filename, :guid, :offset
    );
);

const char backup_index_sieve_delete_sql[] = QUOTE(
    UPDATE sieve SET
        deleted = :deleted
    WHERE filename = :filename
        AND deleted IS NULL;
);

#define SIEVE_SELECT_FIELDS QUOTE(                      \
    sieve.id, sieve.chunk_id, last_update, filename,    \
    guid, offset, deleted                               \
)

const char backup_index_sieve_select_all_sql[] =
    "SELECT " SIEVE_SELECT_FIELDS
    " FROM sieve AS sieve"
    " ORDER BY sieve.id"
    ";"
;

const char backup_index_sieve_select_chunkid_sql[] =
    "SELECT " SIEVE_SELECT_FIELDS
    " FROM sieve AS sieve"
    " WHERE chunk_id = :chunk_id"
    " ORDER BY sieve.id"
    ";"
;
