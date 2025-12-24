/* objectstore_db.h */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include "message_guid.h"

#ifndef OBJECT_STORE_DB
#define OBJECT_STORE_DB

struct message_info
{
    int mailboxes;
    char **mailbox ;
};

struct message
{
    struct message_guid  message_guid;
    uint32_t message_uid ;
};

struct message_list
{
    int    count ;
    struct message *message ;
};

EXPORTED int add_message_guid (struct mailbox *mailbox, const struct index_record *record);
EXPORTED int delete_message_guid (struct mailbox *mailbox, const struct index_record *record, int *count);
EXPORTED int keep_user_message_db_open (int bopen) ;
EXPORTED struct message *get_list_of_message (struct mailbox *mailbox, uint32_t *count) ;
EXPORTED int discard_list () ;


#endif /*OBJECT_STORE_DB*/
