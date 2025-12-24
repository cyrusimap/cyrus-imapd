/* message_priv.h -- private details of the message_t object */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef __CYRUS_MESSAGE_PRIV_H__
#define __CYRUS_MESSAGE_PRIV_H__

#include <stdio.h>

#include "message.h"
#include "mailbox.h"
#include "charset.h"
#include "util.h"

/*
 * Flags for the 'have' and 'given' bitmask fields.  'Given' is the
 * resources we were initialised with by the caller, which are presumed
 * to belong to the caller and will not be freed.  'Have' is the
 * resources we have, including both those given us and those we created
 * or opened ourselves.  Resources are created or opened on demand, and
 * can be shut down again to minimise resource usage, so we need to
 * track the status of all these resources.
 */
#define M_MAILBOX       (1<<0)      /* an open mailbox* */
#define M_FILENAME      (1<<1)      /* filename of a message on disk */
#define M_RECORD        (1<<2)      /* a valid index_record */
#define M_UID           (1<<3)      /* valid UID in index_record */
#define M_MAP           (1<<4)      /* mmap()ed raw message data */
#define M_CACHE         (1<<5)      /* mmap()ed cyrus.cache */
#define M_CACHEBODY     (1<<6)      /* MIME header details from fields, or
                                     * BODYSTRUCTURE from cyrus.cache */
#define M_FULLBODY      (1<<7)      /* BODY parsed from the raw message */
#define M_CHEADER       (1<<8)      /* header from cyrus.cache */
#define M_CENVELOPE     (1<<9)      /* envelope from cyrus.cache */
#define M_INDEX         (1<<10)     /* per-index bits: msgno & indexflags */
#define M_ALL           (~0U)       /* everything */

#define M_BODY (M_CACHEBODY|M_FULLBODY) /* for yield masking */

struct message
{
    int refcount;
    unsigned short have;
    unsigned short given;
    char *filename;
    struct mailbox *mailbox;
    unsigned int msgno;
    uint32_t indexflags;
    struct buf map;
    struct body *body;
    char **envelope;
    struct index_record record;

    /* fallback fields for messages without record */
    struct message_guid guid;
};


#endif /* __CYRUS_MESSAGE_PRIV_H__ */
