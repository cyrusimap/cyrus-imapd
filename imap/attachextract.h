/* attachextract.h -- Routines for extracting text from attachments
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

#ifndef INCLUDED_ATTACHEXTRACT_H
#define INCLUDED_ATTACHEXTRACT_H

#include "prot.h"

/**
 * Initialize the attachextract backend.
 *
 * clientin is an optional protocol stream to wait for timeouts.
 */
extern void attachextract_init(struct protstream *clientin);

/**
 * Destroy the attachextract backend.
 */
extern void attachextract_destroy(void);

/**
 * Identifies the content type of attachment data.
 */
struct attachextract_record {
    const char *type;          // MIME content type
    const char *subtype;       // MIME subtype
    struct message_guid guid;  // content guid of undecoded data
};

/**
 * Extracts text from attachment data.
 *
 * Data may be optionally encoded and its charset identifier specified.
 *
 * Returns 0 on success or an IMAP error.
 */
extern int attachextract_extract(const struct attachextract_record *record,
                                 const struct buf *data,
                                 int encoding, const char *charset,
                                 struct buf *text);

/**
 * Sets or gets where to read and cache extract in.
 */
extern void attachextract_set_cachedir(const char *cachedir);
extern const char *attachextract_get_cachedir(void);

/**
 * Sets or gets if extracted text may only read from the cache.
 */
extern void attachextract_set_cacheonly(int cacheonly);
extern int attachextract_get_cacheonly(void);

#endif
