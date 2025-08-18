/* index_file.h -- Index file format definitions and manipulation routines
 *
 * Copyright (c) 1994-2025 Carnegie Mellon University.  All rights reserved.
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

#ifndef INCLUDED_INDEX_FILE_H
#define INCLUDED_INDEX_FILE_H

#include <stdbool.h>

#include "mailbox.h"

/* "opaque" struct -- if you saw this, no you didn't (unit tests need it) */
struct opaque_index_field {
    uint8_t disk_size; // size of data on disk
                       // 0 = read w/o advancing, write nothing
    char data_type;    // data storage type:
                       // '4' = 4 bytes (bit32)
                       // '8' = 8 bytes (bit64)
                       // 'B' = byte array
                       // 'T' = struct timespec
                       // 'E' = empty field (no storage)
    off_t data_offset; // offset to data type in storage struct
};
typedef struct opaque_index_field index_field_t;

typedef struct index_file_template {
    uint8_t header_size;
    uint8_t record_size;
    unsigned long options_mask;
    const index_field_t *header_fields;
    const index_field_t *record_fields;
    const index_field_t *crc_field;
} index_file_template_t;

extern const index_file_template_t *const index_files_by_version[];
extern const size_t n_index_files;

extern const char *index_file_read_fields(const char *bufp, void *base,
                                          const index_field_t *fields)
#ifdef HAVE_DECLARE_OPTIMIZE
    __attribute__((optimize("-O3")))
#endif
    ;

extern unsigned char *index_file_write_fields(void *base, unsigned char *bufp,
                                              const index_field_t *fields);

#endif /* INCLUDED_INDEX_FILE_H */
