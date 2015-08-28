/* sqlconsts.h -- backup index sql constants
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

#ifndef BACKUP_SQLCONSTS_H
#define BACKUP_SQLCONSTS_H

#include "lib/sqldb.h"

extern const char backup_index_initsql[];

extern const struct sqldb_upgrade backup_index_upgrade[];

extern const int backup_index_version;

extern const char backup_index_start_sql[];
extern const char backup_index_end_sql[];

extern const char backup_index_mailbox_update_sql[];
extern const char backup_index_mailbox_insert_sql[];
extern const char backup_index_mailbox_select_all_sql[];
extern const char backup_index_mailbox_select_mboxname_sql[];
extern const char backup_index_mailbox_select_uniqueid_sql[];

extern const char backup_index_mailbox_message_update_sql[];
extern const char backup_index_mailbox_message_insert_sql[];
extern const char backup_index_mailbox_message_select_mailbox_sql[];

extern const char backup_index_message_insert_sql[];
extern const char backup_index_message_select_guid_sql[];
#endif
