/* search_part.h --  Prefiltering routines for SEARCH
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
 */

#ifndef INCLUDED_SEARCH_PART_H
#define INCLUDED_SEARCH_PART_H

/* These constants are passed into the search_text_receiver_t.begin_part callback to
   tell it which part of the message is being sent down */
enum search_part {
    SEARCH_PART_NONE = -1,
    SEARCH_PART_ANY,
    SEARCH_PART_FROM,
    SEARCH_PART_TO,
    SEARCH_PART_CC,
    SEARCH_PART_BCC,
    SEARCH_PART_SUBJECT,
    SEARCH_PART_LISTID,  /* List-Id or Mailing-List fields */
    SEARCH_PART_TYPE,    /* MIME Content-Type except multipart */
    SEARCH_PART_HEADERS, /* headers OTHER than the above headers */
    SEARCH_PART_BODY,
    SEARCH_PART_LOCATION,
    SEARCH_PART_ATTACHMENTNAME,
    SEARCH_PART_ATTACHMENTBODY,
    SEARCH_PART_DELIVEREDTO,
    SEARCH_PART_LANGUAGE, /* ISO 639 two or three letter code */
    SEARCH_PART_PRIORITY, /* String-encoded decimal integer > 0 */
    SEARCH_PART_MESSAGEID,
    SEARCH_PART_REFERENCES,
    SEARCH_PART_INREPLYTO,
    SEARCH_NUM_PARTS,
};

/* Implemented in search_engines.c */
extern const char *search_part_as_string(int part);

extern int search_part_is_header(enum search_part part);
extern int search_part_is_body(enum search_part part);

#endif
