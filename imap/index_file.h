/* index_file.h - Index file format definitions and manipulation routines */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef INCLUDED_INDEX_FILE_H
#define INCLUDED_INDEX_FILE_H

#include <stdbool.h>

#include "mailbox.h"

/* "opaque" struct -- if you saw this, no you didn't (unit tests need it) */
struct opaque_index_field {
    uint8_t disk_size; // size of data on disk
                       // 0 = read w/o advancing, write nothing
    char data_type;    // data storage type:
                       // '4' = 4 bytes (uint32_t)
                       // '<' = 4 bytes on disk, 8 bytes in memory
                       // '8' = 8 bytes (uint64_t) - unaligned
                       // 'Q' = 8 bytes (uint64_t) - aligned
                       // 'B' = raw bytes
                       // 'G' = message_guid types (20 bytes on disk)
                       // 'T' = struct timespec (8 bytes on disk)
                       // 't' = 4 bytes unix timestamp (tv_sec)
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

extern const unsigned char *index_file_read_fields(const unsigned char *bufp, void *base,
                                                   const index_field_t *fields)
#ifdef HAVE_DECLARE_OPTIMIZE
    __attribute__((optimize("-O3")))
#endif
    ;

extern unsigned char *index_file_write_fields(void *base, unsigned char *bufp,
                                              const index_field_t *fields);

#endif /* INCLUDED_INDEX_FILE_H */
