/* message.h -- Message parsing
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 * $Id: message.h,v 1.11 2009/11/17 03:31:45 brong Exp $
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

extern int message_copy_strict P((struct protstream *from, FILE *to,
				  unsigned size, int allow_null));

/* Flags for parsing message date/time - to be bitwise OR'd */
#define PARSE_DATE	(1<<0)  /* Default (always parsed) */
#define PARSE_TIME	(1<<1)
#define PARSE_ZONE	(1<<2)
#define PARSE_NOCREATE	(1<<15) /* Don't create one if its missing/invalid */

extern time_t message_parse_date P((char *hdr, unsigned flags));

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

extern int message_parse_binary_file P((FILE *infile, struct body **body));
extern int message_parse_file P((FILE *infile,
				 const char **msg_base, unsigned long *msg_len,
				 struct body **body));
extern void message_fetch_part P((struct message_content *msg,
				  const char **content_types,
				  struct bodypart ***parts));
extern int message_create_record P((const char *cache_name,
				    int cache_fd,
				    struct index_record *message_index,
				    struct body *body));
extern void message_free_body P((struct body *body));

#endif /* INCLUDED_MESSAGE_H */
