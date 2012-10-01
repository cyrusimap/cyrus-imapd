/*
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
 */

#ifndef INCLUDED_CHARSET_H
#define INCLUDED_CHARSET_H

#define ENCODING_NONE 0
#define ENCODING_QP 1
#define ENCODING_BASE64 2
#define ENCODING_UNKNOWN 255

#define CHARSET_SKIPDIACRIT (1<<0)
#define CHARSET_SKIPSPACE (1<<1)
#define CHARSET_MERGESPACE (1<<2)
#define CHARSET_SKIPHTML (1<<3)

#define CHARSET_UNKNOWN_CHARSET (-1)

typedef int comp_pat;
typedef int charset_index;

extern int encoding_lookupname(const char *name);
extern const char *encoding_name(int);

/* ensure up to MAXTRANSLATION times expansion into buf */
extern char *charset_convert(const char *s, charset_index charset, int flags);
extern char *charset_decode_mimeheader(const char *s, int flags);
extern char *charset_parse_mimeheader(const char *s);
extern char *charset_utf8_to_searchform(const char *s, int flags);

extern const char *charset_name(charset_index);
extern charset_index charset_lookupname(const char *name);
extern comp_pat *charset_compilepat(const char *s);
extern void charset_freepat(comp_pat *pat);
extern int charset_searchstring(const char *substr, comp_pat *pat,
			        const char *s, size_t len, int flags);
extern int charset_searchfile(const char *substr, comp_pat *pat,
                              const char *msg_base, size_t len, 
                              charset_index charset, int encoding, int flags);
extern const char *charset_decode_mimebody(const char *msg_base, size_t len,
					   int encoding, char **retval,
					   size_t *outlen);
extern char *charset_encode_mimebody(const char *msg_base, size_t len,
				     char *retval, size_t *outlen, 
				     int *outlines);
extern char *charset_to_utf8(const char *msg_base, size_t len, charset_index charset, int encoding);
extern int charset_search_mimeheader(const char *substr, comp_pat *pat, const char *s, int flags);

extern char *charset_encode_mimeheader(const char *header, size_t len);

/* These constants are passed into the search_text_receiver_t.begin_part callback to
   tell it which part of the message is being sent down */
#define SEARCH_PART_ANY	    0
#define SEARCH_PART_FROM    1
#define SEARCH_PART_TO      2
#define SEARCH_PART_CC      3
#define SEARCH_PART_BCC     4
#define SEARCH_PART_SUBJECT 5
#define SEARCH_PART_HEADERS 6 /* headers OTHER than the above headers */
#define SEARCH_PART_BODY    7
#define SEARCH_NUM_PARTS    8


/* The functions in search_text_receiver_t get called at least once for each part of every message.
   The invocations form a sequence:
       begin_message(<uid>)
       receiver->begin_part(<part1>)
       receiver->append_text(<text>)     (1 or more times)
       receiver->end_part(<part1>)
       ...
       receiver->begin_part(<partN>)
       receiver->append_text(<text>)     (1 or more times)
       receiver->end_part(<partN>)
       receiver->end_message(<uid>)

   The parts need not arrive in any particular order, but each part
   can only participate in one begin_part ... append_text ... end_part
   sequence, and the sequences for different parts cannot be interleaved.
*/
struct buf;
struct mailbox;
typedef struct search_text_receiver search_text_receiver_t;
struct search_text_receiver {
    int (*begin_mailbox)(search_text_receiver_t *,
			 struct mailbox *, int incremental);
    uint32_t (*first_unindexed_uid)(search_text_receiver_t *);
    int (*is_indexed)(search_text_receiver_t *, uint32_t uid);
    void (*begin_message)(search_text_receiver_t *, uint32_t uid);
    void (*begin_part)(search_text_receiver_t *, int part);
    void (*append_text)(search_text_receiver_t *, const struct buf *);
    void (*end_part)(search_text_receiver_t *, int part);
    int (*end_message)(search_text_receiver_t *);
    int (*end_mailbox)(search_text_receiver_t *,
		       struct mailbox *);
};

/* Extract the body text for the message denoted by 'uid', convert its
   text to the canonical form for searching, and pass the converted text
   down in a series of invocations of receiver->append_text().  This is
   called by index_getsearchtext to extract the MIME body parts. */
extern int charset_extract(search_text_receiver_t *receiver,
			   const struct buf *data,
			   charset_index charset, int encoding,
			   const char *subtype, int flags);

#endif /* INCLUDED_CHARSET_H */
