/* index_file.c -- Index file format definitions and manipulation routines
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

#include <stddef.h>

#include "index_file.h"

struct index_field {
    size_t disk_size; // size of data on disk
                      // 0 = read w/o advancing, write nothing
    char data_type;   // data storage type:
                      // '4' = 4 bytes (bit32)
                      // '8' = 8 bytes (bit64)
                      // 'B' = byte array
                      // 'T' = struct timespec
                      // 'E' = empty field (no storage)
    off_t offset;     // offset to data type in storage struct
};

#define NULL_FIELD { 0, 0, -1 }


/*
 * Index file header fields by version
 *
 * Comment at the end of each field is the offset of the field in header buffer
 */

/*
 * "Base" header fields (by order and size) present in all versions
 *
 * exists is initialized to num_records until v12
 * (both values read from offset 20)
 */
static const index_field_t v00_header_fields[] = {
    {  4, '4', offsetof(struct index_header, generation_no)        }, /*   0 */
    {  4, '4', offsetof(struct index_header, format)               }, /*   4 */
    {  4, '4', offsetof(struct index_header, minor_version)        }, /*   8 */
    {  4, '4', offsetof(struct index_header, start_offset)         }, /*  12 */
    {  4, '4', offsetof(struct index_header, record_size)          }, /*  16 */
    {  0, '4', offsetof(struct index_header, exists)               }, /*  20 */
    {  4, '4', offsetof(struct index_header, num_records)          }, /*  20 */
    NULL_FIELD
};

/* Common fields (by order and size) present in versions 6 through 19 */
#define COMMON_HEADER_FIELDS                                                    \
    {  4, 'T', offsetof(struct index_header, last_appenddate)      }, /*  24 */ \
    {  4, '4', offsetof(struct index_header, last_uid)             }, /*  28 */ \
    {  8, '8', offsetof(struct index_header, quota_mailbox_used)   }, /*  32 */ \
    {  4, 'T', offsetof(struct index_header, pop3_last_login)      }, /*  40 */ \
    {  4, '4', offsetof(struct index_header, uidvalidity)          }, /*  44 */ \
    {  4, '4', offsetof(struct index_header, deleted)              }, /*  48 */ \
    {  4, '4', offsetof(struct index_header, answered)             }, /*  52 */ \
    {  4, '4', offsetof(struct index_header, flagged)              }  /*  56 */


#define V06_HEADER_FIELDS                                                       \
    COMMON_HEADER_FIELDS,                                             /*  24 */ \
    {  4, '4', offsetof(struct index_header, options)              }, /*  60 */ \
    {  4, '4', offsetof(struct index_header, leaked_cache_records) }  /*  64 */

static const index_field_t v06_header_fields[] =
    { V06_HEADER_FIELDS, NULL_FIELD };


/*
 * deletedmodseq is initialized to highestmodseq until v12
 * (both values read from offset 68)
 */
#define V08_HEADER_FIELDS                                                       \
    V06_HEADER_FIELDS,                                                /*  24 */ \
    {  0, '8', offsetof(struct index_header, deletedmodseq)        }, /*  68 */ \
    {  8, '8', offsetof(struct index_header, highestmodseq)        }  /*  68 */

static const index_field_t v08_header_fields[] = {
    V08_HEADER_FIELDS,
    NULL_FIELD
};


/*
 * changes_epoch is initialized to last_repack_time until v17
 * (both values read from offset 92)
 */
#define V12_HEADER_FIELDS                                                       \
    V08_HEADER_FIELDS,                                                /*  24 */ \
    {  8, '8', offsetof(struct index_header, deletedmodseq)        }, /*  76 */ \
    {  4, '4', offsetof(struct index_header, exists)               }, /*  84 */ \
    {  4, 'T', offsetof(struct index_header, first_expunged)       }, /*  88 */ \
    {  0, 'T', offsetof(struct index_header, changes_epoch)        }, /*  92 */ \
    {  4, 'T', offsetof(struct index_header, last_repack_time)     }, /*  92 */ \
    {  4, '4', offsetof(struct index_header, header_file_crc)      }, /*  96 */ \
    {  4, '4', offsetof(struct index_header, synccrcs.basic)       }, /* 100 */ \
    {  4, '4', offsetof(struct index_header, recentuid)            }, /* 104 */ \
    {  4, 'T', offsetof(struct index_header, recenttime)           }  /* 108 */

static const index_field_t v12_header_fields[] =
    { V12_HEADER_FIELDS, NULL_FIELD };


#define V13_HEADER_FIELDS                                                       \
    V12_HEADER_FIELDS,                                                /*  24 */ \
    {  4, 'T', offsetof(struct index_header, pop3_show_after)      }, /* 112 */ \
    {  4, '8', offsetof(struct index_header, quota_annot_used)     }, /* 116 */ \
    {  4, '4', offsetof(struct index_header, synccrcs.annot)       }  /* 120 */

static const index_field_t v13_header_fields[] =
    { V13_HEADER_FIELDS, NULL_FIELD };


#define V14_HEADER_FIELDS                                                       \
    V13_HEADER_FIELDS,                                                /*  24 */ \
    {  4, '4', offsetof(struct index_header, unseen)               }  /* 124 */

static const index_field_t v14_header_fields[] =
    { V14_HEADER_FIELDS, NULL_FIELD };


#define V16_HEADER_FIELDS                                                       \
    V14_HEADER_FIELDS,                                                /*  24 */ \
    {  8, '8', offsetof(struct index_header, createdmodseq)        }  /* 128 */

static const index_field_t v16_header_fields[] =
    { V16_HEADER_FIELDS, NULL_FIELD };


#define V17_HEADER_FIELDS                                                       \
    V16_HEADER_FIELDS,                                                /*  24 */ \
    {  4, 'T', offsetof(struct index_header, changes_epoch)        }  /* 136 */

static const index_field_t v17_header_fields[] =
    { V17_HEADER_FIELDS, NULL_FIELD };


static const index_field_t v18_header_fields[] = {
    V17_HEADER_FIELDS,                                                /*  24 */
    {  8, '8', offsetof(struct index_header, quota_deleted_used)   }, /* 140 */
    {  8, '8', offsetof(struct index_header, quota_expunged_used)  }, /* 148 */
    NULL_FIELD
};


/* v19 rearranged fields so modseq_t & quota_t fall on 8-byte boundaries */
static const index_field_t v19_header_fields[] = {
    COMMON_HEADER_FIELDS,                                             /*  24 */
    {  4, '4', offsetof(struct index_header, exists)               }, /*  60 */
    {  4, '4', offsetof(struct index_header, options)              }, /*  64 */
    {  4, '4', offsetof(struct index_header, leaked_cache_records) }, /*  68 */
    {  8, '8', offsetof(struct index_header, highestmodseq)        }, /*  72 */
    {  8, '8', offsetof(struct index_header, deletedmodseq)        }, /*  80 */
    {  4, 'T', offsetof(struct index_header, first_expunged)       }, /*  88 */
    {  4, 'T', offsetof(struct index_header, last_repack_time)     }, /*  92 */
    {  4, '4', offsetof(struct index_header, header_file_crc)      }, /*  96 */
    {  4, '4', offsetof(struct index_header, synccrcs.basic)       }, /* 100 */
    {  4, '4', offsetof(struct index_header, recentuid)            }, /* 104 */
    {  4, 'T', offsetof(struct index_header, recenttime)           }, /* 108 */
    {  4, 'T', offsetof(struct index_header, pop3_show_after)      }, /* 112 */
    {  4, '8', offsetof(struct index_header, quota_annot_used)     }, /* 116 */
    {  4, '4', offsetof(struct index_header, synccrcs.annot)       }, /* 120 */
    {  4, '4', offsetof(struct index_header, unseen)               }, /* 124 */
    {  8, '8', offsetof(struct index_header, createdmodseq)        }, /* 128 */
    {  8, '8', offsetof(struct index_header, quota_deleted_used)   }, /* 136 */
    {  8, '8', offsetof(struct index_header, quota_expunged_used)  }, /* 144 */
    {  4, 'T', offsetof(struct index_header, changes_epoch)        }, /* 152 */
    NULL_FIELD
};


/* v20 grew size of time fields and quota_annot_used to 64-bits
   and rearranged fields so that these would fall on 8-byte boundaries */
static const index_field_t v20_header_fields[] = {
    {  8, 'T', offsetof(struct index_header, last_appenddate)      }, /*  24 */
    {  8, '8', offsetof(struct index_header, quota_mailbox_used)   }, /*  32 */
    {  8, 'T', offsetof(struct index_header, pop3_last_login)      }, /*  40 */
    {  4, '4', offsetof(struct index_header, deleted)              }, /*  48 */
    {  4, '4', offsetof(struct index_header, answered)             }, /*  52 */
    {  4, '4', offsetof(struct index_header, flagged)              }, /*  56 */
    {  4, '4', offsetof(struct index_header, exists)               }, /*  60 */
    {  4, '4', offsetof(struct index_header, options)              }, /*  64 */
    {  4, '4', offsetof(struct index_header, leaked_cache_records) }, /*  68 */
    {  8, '8', offsetof(struct index_header, highestmodseq)        }, /*  72 */
    {  8, '8', offsetof(struct index_header, deletedmodseq)        }, /*  80 */
    {  4, '4', offsetof(struct index_header, last_uid)             }, /*  88 */
    {  4, '4', offsetof(struct index_header, uidvalidity)          }, /*  92 */
    {  4, '4', offsetof(struct index_header, header_file_crc)      }, /*  96 */
    {  4, '4', offsetof(struct index_header, synccrcs.basic)       }, /* 100 */
    {  8, 'T', offsetof(struct index_header, recenttime)           }, /* 104 */
    {  8, 'T', offsetof(struct index_header, pop3_show_after)      }, /* 112 */
    {  4, '4', offsetof(struct index_header, synccrcs.annot)       }, /* 120 */
    {  4, '4', offsetof(struct index_header, unseen)               }, /* 124 */
    {  8, '8', offsetof(struct index_header, createdmodseq)        }, /* 128 */
    {  8, '4', offsetof(struct index_header, quota_deleted_used)   }, /* 136 */
    {  8, '8', offsetof(struct index_header, quota_expunged_used)  }, /* 144 */
    {  8, '8', offsetof(struct index_header, quota_annot_used)     }, /* 152 */
    {  8, 'T', offsetof(struct index_header, changes_epoch)        }, /* 160 */
    {  8, 'T', offsetof(struct index_header, first_expunged)       }, /* 168 */
    {  8, 'T', offsetof(struct index_header, last_repack_time)     }, /* 176 */
    {  4, '4', offsetof(struct index_header, recentuid)            }, /* 184 */
    NULL_FIELD
};


/*
 * Index file record fields by version
 *
 * Comment at the end of each field is the offset of the field in record buffer
 */

/* Array of (MAX_USER_FLAGS/32) bit32 fields */
#define USER_FLAGS_FIELDS                                                       \
    {  4, '4', offsetof(struct index_record, user_flags[0])        },           \
    {  4, '4', offsetof(struct index_record, user_flags[1])        },           \
    {  4, '4', offsetof(struct index_record, user_flags[2])        },           \
    {  4, '4', offsetof(struct index_record, user_flags[3])        }


/* Common fields (by order and size) present in versions 6 through 19 */
#define COMMON_RECORD_FIELDS                                                    \
    {  4, '4', offsetof(struct index_record, uid)                  }, /*   0 */ \
    {  4, 'T', offsetof(struct index_record, internaldate)         }, /*   4 */ \
    {  4, 'T', offsetof(struct index_record, sentdate)             }, /*   8 */ \
    {  4, '8', offsetof(struct index_record, size)                 }, /*  12 */ \
    {  4, '4', offsetof(struct index_record, header_size)          }, /*  16 */ \
    {  4, 'T', offsetof(struct index_record, gmtime)               }, /*  20 */ \
    {  4, '4', offsetof(struct index_record, cache_offset)         }, /*  24 */ \
    {  4, 'T', offsetof(struct index_record, last_updated)         }, /*  28 */ \
    {  4, '4', offsetof(struct index_record, system_flags)         }, /*  32 */ \
    USER_FLAGS_FIELDS                                                 /*  36 */


#define V06_RECORD_FIELDS                                                       \
    COMMON_RECORD_FIELDS,                                             /*   0 */ \
    {  4, 'E', 0         /* legacy content_lines field */          }, /*  52 */ \
    {  4, '4', offsetof(struct index_record, cache_version)        }  /*  56 */

static const index_field_t v06_record_fields[] =
    { V06_RECORD_FIELDS, NULL_FIELD };


#define V07_RECORD_FIELDS                                                       \
    V06_RECORD_FIELDS,                                                /*   0 */ \
    { 12, 'E', 0                                                   }  /*  60 */

static const index_field_t v07_record_fields[] =
    { V07_RECORD_FIELDS, NULL_FIELD };


static const index_field_t v08_record_fields[] = {
    V07_RECORD_FIELDS,                                                /*   0 */
    {  8, '8', offsetof(struct index_record, modseq)               }, /*  72 */
    NULL_FIELD
};


#define V10_RECORD_FIELDS                                                       \
    V06_RECORD_FIELDS,                                                /*   0 */ \
    { 20, 'B', offsetof(struct index_record, guid.value)           }, /*  60 */ \
    {  8, '8', offsetof(struct index_record, modseq)               }  /*  80 */

static const index_field_t v10_record_fields[] =
    { V10_RECORD_FIELDS, NULL_FIELD };


#define CACHE_CRC_FIELD                                                         \
    {  4, '4', offsetof(struct index_record, cache_crc)            }


static const index_field_t v12_record_fields[] = {
    V10_RECORD_FIELDS,                                                /*   0 */
    CACHE_CRC_FIELD,                                                  /*  88 */
    NULL_FIELD
};


static const index_field_t v13_record_fields[] = {
    V10_RECORD_FIELDS,                                                /*   0 */
    {  8, '8', offsetof(struct index_record, cid)                  }, /*  88 */
    CACHE_CRC_FIELD,                                                  /*  96 */
    NULL_FIELD
};


#define V15_RECORD_FIELDS                                                       \
    COMMON_RECORD_FIELDS,                                             /*   0 */ \
    {  4, 'T', offsetof(struct index_record, savedate)             }, /*  52 */ \
    {  4, '4', offsetof(struct index_record, cache_version)        }, /*  56 */ \
    { 20, 'B', offsetof(struct index_record, guid.value)           }, /*  60 */ \
    {  8, '8', offsetof(struct index_record, modseq)               }, /*  80 */ \
    {  8, '8', offsetof(struct index_record, cid)                  }  /*  88 */

static const index_field_t v15_record_fields[] = {
    V15_RECORD_FIELDS,                                                /*   0 */
    CACHE_CRC_FIELD,                                                  /*  96 */
    NULL_FIELD
};


static const index_field_t v16_record_fields[] = {
    V15_RECORD_FIELDS,                                                /*   0 */
    {  8, '8', offsetof(struct index_record, createdmodseq)        }, /*  96 */
    CACHE_CRC_FIELD,                                                  /* 104 */
    NULL_FIELD
};


/* v20 grew the size and time fields to 64-bits
   and rearranged fields so that these would fall on 8-byte boundaries */
static const index_field_t v20_record_fields[] = {
    {  4, '4', offsetof(struct index_record, uid)                  }, /*   0 */
    {  4, '4', offsetof(struct index_record, cache_offset)         }, /*   4 */
    {  8, 'T', offsetof(struct index_record, internaldate)         }, /*   8 */
    {  8, 'T', offsetof(struct index_record, sentdate)             }, /*  16 */
    {  8, '8', offsetof(struct index_record, size)                 }, /*  24 */
    {  4, '4', offsetof(struct index_record, header_size)          }, /*  32 */
    {  4, '4', offsetof(struct index_record, system_flags)         }, /*  36 */
    USER_FLAGS_FIELDS,                                                /*  40 */
    {  4, '4', offsetof(struct index_record, cache_version)        }, /*  56 */
    { 20, 'B', offsetof(struct index_record, guid.value)           }, /*  60 */
    {  8, '8', offsetof(struct index_record, modseq)               }, /*  80 */
    {  8, '8', offsetof(struct index_record, cid)                  }, /*  88 */
    {  8, '8', offsetof(struct index_record, createdmodseq)        }, /*  96 */
    {  8, 'T', offsetof(struct index_record, gmtime)               }, /* 104 */
    {  8, 'T', offsetof(struct index_record, last_updated)         }, /* 112 */
    {  8, 'T', offsetof(struct index_record, savedate)             }, /* 120 */
    {  8, '8', offsetof(struct index_record, basecid)              }, /* 128 */
    CACHE_CRC_FIELD,                                                  /* 136 */
    NULL_FIELD
};


/*
 * Index file templates by version.
 * We don't support versions prior to 6 and version 11 was Fastmail internal
 */

static const index_file_template_t v00_template =
    {  24,   0, 0, 0,                 v00_header_fields, NULL              };

static const index_file_template_t v06_template =
    {  76,  60, 0, OPT_POP3_NEW_UIDL, v06_header_fields, v06_record_fields };

static const index_file_template_t v07_template =
    {  76,  72, 0, OPT_POP3_NEW_UIDL, v06_header_fields, v07_record_fields };

static const index_file_template_t v08_template =
    {  92,  80, 0, MAILBOX_OPT_VALID, v08_header_fields, v08_record_fields };

static const index_file_template_t v09_template =
    {  96,  80, 0, MAILBOX_OPT_VALID, v08_header_fields, v08_record_fields };

static const index_file_template_t v10_template =
    {  96,  88, 0, MAILBOX_OPT_VALID, v08_header_fields, v10_record_fields };

static const index_file_template_t v12_template =
    { 128,  96, 1, MAILBOX_OPT_VALID, v12_header_fields, v12_record_fields };

static const index_file_template_t v13_template =
    { 128, 104, 1, MAILBOX_OPT_VALID, v13_header_fields, v13_record_fields };

static const index_file_template_t v14_template =
    { 160, 104, 1, MAILBOX_OPT_VALID, v14_header_fields, v13_record_fields };

static const index_file_template_t v15_template =
    { 160, 104, 1, MAILBOX_OPT_VALID, v14_header_fields, v15_record_fields };

static const index_file_template_t v16_template =
    { 160, 112, 1, MAILBOX_OPT_VALID, v16_header_fields, v16_record_fields };

static const index_file_template_t v17_template =
    { 160, 112, 1, MAILBOX_OPT_VALID, v17_header_fields, v16_record_fields };

static const index_file_template_t v18_template =
    { 160, 112, 1, MAILBOX_OPT_VALID, v18_header_fields, v16_record_fields };

static const index_file_template_t v19_template =
    { 160, 112, 1, MAILBOX_OPT_VALID, v19_header_fields, v16_record_fields };

static const index_file_template_t v20_template =
    { 192, 144, 1, MAILBOX_OPT_VALID, v20_header_fields, v20_record_fields };


const index_file_template_t *index_files_by_version[MAILBOX_MINOR_VERSION+1] = {
    &v00_template, // "base" header fields
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    &v06_template,
    &v07_template,
    &v08_template,
    &v09_template,
    &v10_template,
    NULL,
    &v12_template,
    &v13_template,
    &v14_template,
    &v15_template,
    &v16_template,
    &v17_template,
    &v18_template,
    &v19_template,
    &v20_template
};

EXPORTED const char *index_file_read_fields(const char *bufp, void *base,
                                            const index_field_t *fields)
{
    for (; fields->data_type; fields++) {
        void *datap = (void *) ((off_t) base + fields->offset);

        switch (fields->data_type) {
        case '4':
            *((bit32 *) datap) = ntohl(*((bit32 *)(bufp)));
            break;

        case '8':
            if (fields->disk_size == 8)
                *((bit64 *) datap) = align_ntohll(bufp);
            else {
                /* this field is stored as a 32b on disk but 64b in memory */
                *((bit64 *) datap) = ntohl(*((bit32 *)(bufp)));
            }
            break;

        case 'B':
            memcpy(datap, bufp, fields->disk_size);
            break;

        case 'T': {
            struct timespec *ts = (struct timespec *) datap;

            if (fields->disk_size == 8) {
                TIMESPEC_FROM_NANOSEC(ts, align_ntohll(bufp));
            }
            else
                ts->tv_sec = ntohl(*((bit32 *)(bufp)));
            break;
        }

        case 'E':
            break;

        default:
            // should never get here
            assert(0);
        }

        bufp += fields->disk_size;
    }

    return bufp;
}

EXPORTED unsigned char *index_file_write_fields(void *base, unsigned char *bufp,
                                                const index_field_t *fields)
{
    for (; fields->data_type; fields++) {
        if (!fields->disk_size) continue;

        void *datap = (void *) ((off_t) base + fields->offset);

        switch (fields->data_type) {
        case '4':
            *((bit32 *) bufp) = htonl(*((bit32 *) datap));
            break;

        case '8':
            if (fields->disk_size == 8)
                align_htonll(bufp, *((bit64 *) datap));
            else {
                /* this field is 64b in memory but stored as 32b on disk */
                bit32 b32 = *((bit64 *) datap);
                *((bit32 *) bufp) = htonl(b32);
            }
            break;

        case 'B':
            memcpy(bufp, datap, fields->disk_size);
            break;

        case 'T': {
            struct timespec *ts = (struct timespec *) datap;

            if (fields->disk_size == 8)
                *((bit64 *)(bufp)) = htonll(TIMESPEC_TO_NANOSEC(ts));
            else
                *((bit32 *)(bufp)) = htonl(ts->tv_sec);
            break;
        }

        case 'E':
            break;

        default:
            // should never get here
            assert(0);
        }

        bufp += fields->disk_size;
    }

    return bufp;
}
