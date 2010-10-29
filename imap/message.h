/* message.h -- Message parsing
 *
 * Copyright (c) 1994-2010 Carnegie Mellon University.  All rights reserved.
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

#ifndef INCLUDED_MESSAGE_H
#define INCLUDED_MESSAGE_H

#ifndef P
#ifdef __STDC__
#define P(x) x
#else
#define P(x) ()
#endif
#endif

#include <stdio.h>

#include "prot.h"
#include "mailbox.h"
#include "util.h"

/*
 * Parsed form of a body-part
 */
struct body {
    /* Content-* header information */
    char *type;
    char *subtype;
    struct param *params;
    char *id;
    char *description;
    char *encoding;
    char *md5;
    char *disposition;
    struct param *disposition_params;
    struct param *language;
    char *location;

    /* Location/size information */
    long header_offset;
    long header_size;
    long header_lines;
    long content_offset;
    long content_size;
    long content_lines;
    long boundary_size;		/* Size of terminating boundary */
    long boundary_lines;

    int numparts;		/* For multipart types */
    struct body *subpart;	/* For message/rfc822 and multipart types */

    /*
     * Other header information.
     * Only meaningful for body-parts at top level or
     * enclosed in message/rfc-822
     */
    char *date;
    char *subject;
    struct address *from;
    struct address *sender;
    struct address *reply_to;
    struct address *to;
    struct address *cc;
    struct address *bcc;
    char *in_reply_to;
    char *message_id;
    char *references;
    char *received_date;

    /*
     * Cached headers.  Only filled in at top-level
     */
    struct buf cacheheaders;

    /*
     * decoded body.  Filled in as needed.
     */
    char *decoded_body;

    /* Message GUID. Only filled in at top level */
    struct message_guid guid;
};

/* List of Content-type parameters */
struct param {
    struct param *next;
    char *attribute;
    char *value;
};
extern int message_copy_strict P((struct protstream *from, FILE *to,
				  unsigned size, int allow_null));

extern int message_parse(const char *fname, struct index_record *record);

/* declare this here so it can be used externally, but remain opaque */
struct body;

struct message_content {
    const char *base;  /* memory mapped file */
    unsigned long len;
    struct body *body; /* parsed body structure */
};

/* MUST keep this struct sync'd with sieve_bodypart in sieve_interface.h */
struct bodypart {
    char section[128];
    const char *decoded_body;
};

/* Calculate the number of entries in a vector */
#define VECTOR_SIZE(vector) (sizeof(vector)/sizeof(vector[0]))

extern void parse_cached_envelope P((char *env, char *tokens[], int tokens_size));

extern int message_parse_mapped P((const char *msg_base, unsigned long msg_len,
				   struct body *body));
extern int message_parse_binary_file P((FILE *infile, struct body **body));
extern int message_parse_file P((FILE *infile,
				 const char **msg_base, unsigned long *msg_len,
				 struct body **body));
extern void message_fetch_part P((struct message_content *msg,
				  const char **content_types,
				  struct bodypart ***parts));
extern void message_write_nstring(struct buf *buf, const char *s);
extern void message_write_nstring_map(struct buf *buf, const char *s, unsigned int len);
extern void message_write_xdrstring(struct buf *buf, const struct buf *s);
extern int message_write_cache P((struct index_record *record, const struct body *body));

extern int message_create_record P((struct index_record *message_index,
				    const struct body *body));
extern void message_free_body P((struct body *body));

#endif /* INCLUDED_MESSAGE_H */
