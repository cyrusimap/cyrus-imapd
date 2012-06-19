/* message_priv.h -- private details of the message_t object
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
 * $Id: message.h,v 1.13 2010/01/06 17:01:37 murch Exp $
 */

#ifndef __CYRUS_MESSAGE_PRIV_H__
#define __CYRUS_MESSAGE_PRIV_H__

#include <stdio.h>

#include "message.h"
#include "mailbox.h"
#include "charset.h"
#include "util.h"

typedef struct field_desc field_desc_t;

enum segment_type {
    T_PART =			    0,
    T_SPECIAL =			    0x20000000,
    T_FIELD =			    0x40000000,
    T_UNFINISHED =		    0x60000000,
};
#define TYPE_MASK		    (0x60000000)
#define ID_MASK			    (0x1fffffff)

/* special part ids */
enum segment_id {
    ID_INVALID =  		0,

#define ID_MIME_FIRST		ID_MIME_VERSION
    ID_MIME_VERSION=		T_FIELD|1,
    ID_CONTENT_TYPE,
    ID_CONTENT_TRANSFER_ENCODING,
#define ID_MIME_LAST		ID_CONTENT_TRANSFER_ENCODING
    ID_MESSAGE_ID,
    ID_IN_REPLY_TO,
    ID_REFERENCES,
    ID_SUBJECT,
    ID_DATE,
#define ID_PREALLOCATED_LAST	ID_DATE

    ID_UNFINISHED =		T_SPECIAL|1,
    ID_HEADER,
    ID_BODY
};

typedef struct segment segment_t;
struct segment
{
    enum segment_id id;
    /* offset and length in raw octets, absolute in file */
    unsigned int offset, length;
    struct segment *next;
    struct segment *children;
    struct segment *parent;
};

struct part
{
    struct segment super;

    /* We keep a back pointer to the message_t in each part_t.
     * Not in each segment_t - that would mean keeping a back
     * pointer for each header field, which is silly.  */
    message_t *message;

    /* Extracted from Content-Type: */
    char *type;
    char *subtype;
    int charset;
    char *boundary;
    /* from Content-Transfer-Encoding: */
    int encoding;
};

struct field_desc
{
    const char *name;
    unsigned int min_cache_version;
    int id;
    int cache_idx;
    int env_idx;
};

/*
 * Flags for the 'have' and 'given' bitmask fields.  'Given' is the
 * resources we were initialised with by the caller, which are presumed
 * to belong to the caller and will not be freed.  'Have' is the
 * resources we have, including both those given us and those we created
 * or opened ourselves.  Resources are created or opened on demand, and
 * can be shut down again to minimise resource usage, so we need to
 * track the status of all these resources.
 */
#define M_MAILBOX	(1<<0)	    /* an open mailbox* */
#define M_FILENAME  	(1<<1)	    /* filename of a message on disk */
#define M_RECORD	(1<<2)	    /* a valid index_record */
#define M_UID		(1<<3)	    /* valid UID in index_record */
#define M_MAP		(1<<4)	    /* mmap()ed raw message data */
#define M_CACHE		(1<<5)	    /* mmap()ed cyrus.cache */
#define M_SEGS		(1<<6)	    /* top 2 levels of file segment tree from
				     * fields or SECTION in cyrus.cache */
#define M_BODY		(1<<7)	    /* MIME header details from fields, or
				     * BODYSTRUCTURE from cyrus.cache */
#define M_CHEADER	(1<<8)	    /* header from cyrus.cache */
#define M_CENVELOPE	(1<<9)	    /* envelope from cyrus.cache */
#define M_INDEX	    	(1<<10)	    /* per-index bits: msgno & indexflags */
#define M_ALL		(~0U)	    /* everything */

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
    segment_t *segs;
    struct buf cheader_map;
    segment_t *cheader_segs;
    char **envelope;
    struct index_record record;
};


#endif /* __CYRUS_MESSAGE_PRIV_H__ */
