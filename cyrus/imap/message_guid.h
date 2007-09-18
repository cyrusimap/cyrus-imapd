/* message_guid.h -- GUID manipulation
 *
 * Copyright (c) 1998-2007 Carnegie Mellon University.  All rights reserved.
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
 * $Id: message_guid.h,v 1.1 2007/09/18 11:33:14 murch Exp $
 */

#ifndef MESSAGE_GUID_H
#define MESSAGE_GUID_H

/* Public interface */

#define MESSAGE_GUID_SIZE         (20)    /* Size of GUID byte sequence */
#define MESSAGE_GUID_PACKED_SIZE  (20)    /* Size on disk */
#define MESSAGE_GUID_TEXT_SIZE    (40)    /* GUID as hex */

struct message_guid {
   unsigned char value[MESSAGE_GUID_SIZE]; /* Matches packed encoding */
};

int
message_guid_compare(struct message_guid *guid1, struct message_guid *guid2);
  /* Compare a pair of GUIDs: Returns 1 => match. NULL GUIDs do not match. */

int
message_guid_compare_allow_null(struct message_guid *guid1,
                                struct message_guid *guid2);
  /* Compare a pair of GUIDs: Returns 1 => match. NULL GUIDs match anything */

int
message_guid_copy(struct message_guid *dst, struct message_guid *src);
  /* Copy a GUID */

unsigned long
message_guid_hash(struct message_guid *guid, int hash_size);
  /* Convert GUID into hash value for hash table lookup */
  /* Returns: positive int in range [0, hash_size-1] */

void
message_guid_set_null(struct message_guid *dst);
  /* Create a NULL GUID */

int
message_guid_isnull(struct message_guid *guid);
  /* Returns 1 if GUID is NULL value */

/* Routines for manipulating packed values */

int
message_guid_pack(struct message_guid *guid, char *packed);
  /* Store Message UID as packed sequence (MESSAGE_GUID_PACKED_SIZE)
   * (Wrapper for memcpy() with current implementation) */

int
message_guid_unpack(struct message_guid *guid, const unsigned char *packed);
  /* Fetch Message UID from packed sequence (MESSAGE_GUID_PACKED_SIZE)
   * (Wrapper for memcpy() with current implementation) */

/* Routines for manipulating text value */

void
message_guid_sha1(struct message_guid *guid, unsigned char *sha1);
  /* Generate GUID from message SHA1 */

char *
message_guid_text(struct message_guid *guid);
  /* Returns ptr to '\0' terminated static char * which can be strdup()ed */
  /* NULL => error. Should be impossible as entire range covered */

int
message_guid_from_text(struct message_guid *guid, const char *text);
  /* Sets Message GUID from text form. Returns 1 if valid */
  /* Returns: Cyrus error code, 0 on sucess */

int
message_guid_text_valid(const char *text);
  /* Returns 1 if test valid format for Message GUID */

int
message_guid_text_isnull(const char *text);
  /* Returns 1 if Textual GUID is NULL value */

#endif
