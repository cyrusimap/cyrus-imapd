/* search_part.h -- Prefiltering routines for SEARCH */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
