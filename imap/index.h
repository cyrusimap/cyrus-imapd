/* index.h -- Routines for dealing with the index file in the imapd
 *
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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
 *
 */
/*
 * $Id: index.h,v 1.1 2001/02/25 05:09:42 ken3 Exp $
 */
#ifndef INCLUDED_INDEX_H
#define INCLUDED_INDEX_H

#include "imapd.h"

/* Access macros for the memory-mapped index file data */
#define INDEC_OFFSET(m, msgno) ((m)->index_base+(m)->start_offset+(((msgno)-1)*(m)->record_size))
#define UID(m, msgno) ntohl(*((bit32 *)(INDEC_OFFSET(m, msgno)+OFFSET_UID)))
#define INTERNALDATE(m, msgno) ntohl(*((bit32 *)(INDEC_OFFSET(m, msgno)+OFFSET_INTERNALDATE)))
#define SENTDATE(m, msgno) ntohl(*((bit32 *)(INDEC_OFFSET(m, msgno)+OFFSET_SENTDATE)))
#define SIZE(m, msgno) ntohl(*((bit32 *)(INDEC_OFFSET(m, msgno)+OFFSET_SIZE)))
#define HEADER_SIZE(m, msgno) ntohl(*((bit32 *)(INDEC_OFFSET(m, msgno)+OFFSET_HEADER_SIZE)))
#define CONTENT_OFFSET(m, msgno) ntohl(*((bit32 *)(INDEC_OFFSET(m, msgno)+OFFSET_CONTENT_OFFSET)))
#define CACHE_OFFSET(m, msgno) ntohl(*((bit32 *)(INDEC_OFFSET(m, msgno)+OFFSET_CACHE_OFFSET)))
#define LAST_UPDATED(m, msgno) ((time_t)ntohl(*((bit32 *)(INDEC_OFFSET(m, msgno)+OFFSET_LAST_UPDATED))))
#define SYSTEM_FLAGS(m, msgno) ntohl(*((bit32 *)(INDEC_OFFSET(m, msgno)+OFFSET_SYSTEM_FLAGS)))
#define USER_FLAGS(m, msgno,i) ntohl(*((bit32 *)(INDEC_OFFSET(m, msgno)+OFFSET_USER_FLAGS+((i)*4))))

/* Access assistance macros for memory-mapped cache file data */
#define CACHE_ITEM_BIT32(ptr) (ntohl(*((bit32 *)(ptr))))
#define CACHE_ITEM_LEN(ptr) CACHE_ITEM_BIT32(ptr)
#define CACHE_ITEM_NEXT(ptr) ((ptr)+4+((3+CACHE_ITEM_LEN(ptr))&~3))

/* Cached envelope token positions */
enum {
    ENV_DATE = 0,
    ENV_SUBJECT,
    ENV_FROM,
    ENV_SENDER,
    ENV_REPLYTO,
    ENV_TO,
    ENV_CC,
    ENV_BCC,
    ENV_INREPLYTO,
    ENV_MSGID
};
#define NUMENVTOKENS (10)

int _index_search(unsigned **msgno_list, struct mailbox *mailbox,
		  struct searchargs *searchargs);

void parse_cached_envelope(char *env, char *tokens[]);

#endif /* INCLUDED_INDEX_H */
