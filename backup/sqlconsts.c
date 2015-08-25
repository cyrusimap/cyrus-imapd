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
    CREATE TABLE gzchunk(
        id INTEGER PRIMARY KEY ASC,
        offset INTEGER UNIQUE,
        length INTEGER
    );

    CREATE TABLE backup(
        id INTEGER PRIMARY KEY ASC,
        timestamp INTEGER,
        gzchunk_id INTEGER REFERENCES gzchunk(id)
    );

    CREATE TABLE message(
        id INTEGER PRIMARY KEY ASC,
        guid CHAR UNIQUE,
        gzchunk_id INTEGER REFERENCES gzchunk(id),
        offset INTEGER,
        length INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_msg_guid ON message(guid);

    CREATE TABLE backup_mailbox(
        id INTEGER PRIMARY KEY ASC,
        backup_id INTEGER NOT NULL REFERENCES backup(id),
        uniqueid CHAR NOT NULL,
        mboxname CHAR NOT NULL,
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
        /* [annotations] */
        UNIQUE ( backup_id, uniqueid ) /* ??? */
    );
    CREATE INDEX IF NOT EXISTS idx_bmb_uid ON backup_mailbox(uniqueid);

    CREATE TABLE mailbox_record(
        id INTEGER PRIMARY KEY ASC,
        backup_mailbox_id INTEGER NOT NULL REFERENCES backup_mailbox(id),
        message_id INTEGER NOT NULL REFERENCES message(id),
        uid INTEGER,
        modseq INTEGER,
        last_updated INTEGER,
        /* [flags] ??? */
        internaldate INTEGER
        /* [annotations] */
        /* expunged INTEGER, -- duplicated from [flags]? */
    );
    CREATE INDEX IF NOT EXISTS idx_mbr_uid ON mailbox_record(uid);
);

const struct sqldb_upgrade backup_index_upgrade[] = {
    { 0, NULL, NULL } /* leave me last */
};
