/* index.c -- Routines for dealing with the index file in the imapd
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 * $Id: index.h,v 1.7 2003/05/09 19:30:26 rjs3 Exp $
 */

/* Header for internal usage of index.c + programs that make raw access
 * to index files */

#ifndef INDEX_H
#define INDEX_H

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <syslog.h>
#include <com_err.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>

#include "mailbox.h" /* for bit32 */

/* Access macros for the memory-mapped index file data */
#define INDEC_OFFSET(msgno) (index_base+start_offset+(((msgno)-1)*record_size))
#define UID(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_UID)))
#define INTERNALDATE(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_INTERNALDATE)))
#define SENTDATE(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_SENTDATE)))
#define SIZE(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_SIZE)))
#define HEADER_SIZE(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_HEADER_SIZE)))
#define CONTENT_OFFSET(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_CONTENT_OFFSET)))
#define CACHE_OFFSET(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_CACHE_OFFSET)))
#define LAST_UPDATED(msgno) ((time_t)ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_LAST_UPDATED))))
#define SYSTEM_FLAGS(msgno) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_SYSTEM_FLAGS)))
#define USER_FLAGS(msgno,i) ntohl(*((bit32 *)(INDEC_OFFSET(msgno)+OFFSET_USER_FLAGS+((i)*4))))

/* Access assistance macros for memory-mapped cache file data */
/* CACHE_ITEM_BIT32: Convert to host byte order */
/* CACHE_ITEM_LEN: Get the length out */
/* CACHE_ITEM_NEXT: Return a pointer to the next entry.  Sizes are
 * 4-byte aligned, so round up to the next 4 byte boundry */
#define CACHE_ITEM_BIT32(ptr) (ntohl(*((bit32 *)(ptr))))
#define CACHE_ITEM_LEN(ptr) CACHE_ITEM_BIT32(ptr)
#define CACHE_ITEM_NEXT(ptr) ((ptr)+4+((3+CACHE_ITEM_LEN(ptr))&~3))

/* Size of a bit32 to skip when jumping over cache item sizes */
#define CACHE_ITEM_SIZE_SKIP sizeof(bit32)

/* Calculate the number of entries in a vector */
#define VECTOR_SIZE(vector) (sizeof(vector)/sizeof(vector[0]))

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

/* Special "sort criteria" to load message-id and references/in-reply-to
 * into msgdata array for threaders that need them.
 */
#define LOAD_IDS	256

struct copyargs {
    struct copymsg *copymsg;
    int nummsg;
    int msgalloc;
};

struct mapfile {
    const char *base;
    unsigned long size;
};

typedef struct msgdata {
    unsigned msgno;		/* message number */
    char *msgid;		/* message ID */
    char **ref;			/* array of references */
    int nref;			/* number of references */
    time_t date;		/* sent date & time of message
				   from Date: header (adjusted by time zone) */
    char *cc;			/* local-part of first "cc" address */
    char *from;			/* local-part of first "from" address */
    char *to;			/* local-part of first "to" address */
    char *xsubj;		/* extracted subject text */
    unsigned xsubj_hash;	/* hash of extracted subject text */
    int is_refwd;		/* is message a reply or forward? */
    char **annot;		/* array of annotation attribute values
				   (stored in order of sortcrit) */
    int nannot;			/* number of annotation values */
    struct msgdata *next;
} MsgData;

typedef struct thread {
    MsgData *msgdata;		/* message data */
    struct thread *parent;	/* parent message */
    struct thread *child;	/* first child message */
    struct thread *next;	/* next sibling message */
} Thread;

struct rootset {
    Thread *root;
    unsigned nroot;
};

struct thread_algorithm {
    char *alg_name;
    void (*threader)(unsigned *msgno_list, int nmsg, int usinguid);
};

#endif /* INDEX_H */
