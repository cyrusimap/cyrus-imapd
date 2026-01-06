/* attachextract.h -- Routines for extracting text from attachments */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
 * Data may be encoded with one of the charset ENCODING enums.
 *
 * Returns 0 on success or an IMAP error.
 */
extern int attachextract_extract(const struct attachextract_record *record,
                                 const struct buf *data, int encoding,
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
