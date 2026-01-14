/* index_file.c - Index file format definitions and manipulation routines */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <stddef.h>
#include <sysexits.h>

#include "index_file.h"

#define EMPTY_FIELD(N) (struct opaque_index_field){ N, 'E', 0 }
#define END_FIELD      (struct opaque_index_field){ 0,  0,  0 }

/*
 * Index file header fields by version
 */

/*
 * "Base" header fields (by order and size) present in all versions
 *
 * exists is initialized to num_records until v12
 * (both values read from same buffer offset)
 */
static const index_field_t v00_hdr_fields[] = {
    {  4, '4', offsetof(struct index_header, generation_no)        },
    {  4, '4', offsetof(struct index_header, format)               },
    {  4, '4', offsetof(struct index_header, minor_version)        },
    {  4, '4', offsetof(struct index_header, start_offset)         },
    {  4, '4', offsetof(struct index_header, record_size)          },
    {  0, '4', offsetof(struct index_header, exists)               },
    {  4, '4', offsetof(struct index_header, num_records)          },
    END_FIELD
};

/* Common fields (by order and size) present in versions 6 through 19 */
#define COMMON_HEADER_FIELDS                                            \
    {  4, 't', offsetof(struct index_header, last_appenddate)      },   \
    {  4, '4', offsetof(struct index_header, last_uid)             },   \
    {  8, '8', offsetof(struct index_header, quota_mailbox_used)   },   \
    {  4, 't', offsetof(struct index_header, pop3_last_login)      },   \
    {  4, '4', offsetof(struct index_header, uidvalidity)          },   \
    {  4, '4', offsetof(struct index_header, deleted)              },   \
    {  4, '4', offsetof(struct index_header, answered)             },   \
    {  4, '4', offsetof(struct index_header, flagged)              }


#define V06_HEADER_FIELDS                                               \
    COMMON_HEADER_FIELDS,                                               \
    {  4, '4', offsetof(struct index_header, options)              },   \
    {  4, '4', offsetof(struct index_header, leaked_cache_records) }

static const index_field_t v06_hdr_fields[] = {
    V06_HEADER_FIELDS,
    EMPTY_FIELD(8),   /* spare fields */
    END_FIELD
};


/*
 * deletedmodseq is initialized to highestmodseq until v12
 * (both values read from same buffer offset)
 */
#define V08_HEADER_FIELDS                                               \
    V06_HEADER_FIELDS,                                                  \
    {  0, '8', offsetof(struct index_header, deletedmodseq)        },   \
    {  8, '8', offsetof(struct index_header, highestmodseq)        }

static const index_field_t v08_hdr_fields[] = {
    V08_HEADER_FIELDS,
    EMPTY_FIELD(16),  /* spare fields */
    END_FIELD
};


static const index_field_t v09_hdr_fields[] = {
    V08_HEADER_FIELDS,
    EMPTY_FIELD(20),  /* spare fields */
    END_FIELD
};


/*
 * changes_epoch is initialized to last_repack_time until v17
 * (both values read from same buffer offset)
 */
#define V12_HEADER_FIELDS                                               \
    V08_HEADER_FIELDS,                                                  \
    {  8, '8', offsetof(struct index_header, deletedmodseq)        },   \
    {  4, '4', offsetof(struct index_header, exists)               },   \
    {  4, 't', offsetof(struct index_header, first_expunged)       },   \
    {  0, 't', offsetof(struct index_header, changes_epoch)        },   \
    {  4, 't', offsetof(struct index_header, last_repack_time)     },   \
    {  4, '4', offsetof(struct index_header, header_file_crc)      },   \
    {  4, '4', offsetof(struct index_header, synccrcs.basic)       },   \
    {  4, '4', offsetof(struct index_header, recentuid)            },   \
    {  4, 't', offsetof(struct index_header, recenttime)           }

static const index_field_t v12_hdr_fields[] = {
    V12_HEADER_FIELDS,
    EMPTY_FIELD(12),  /* spare fields */
    END_FIELD
};


#define V13_HEADER_FIELDS                                               \
    V12_HEADER_FIELDS,                                                  \
    {  4, 't', offsetof(struct index_header, pop3_show_after)      },   \
    {  4, '<', offsetof(struct index_header, quota_annot_used)     },   \
    {  4, '4', offsetof(struct index_header, synccrcs.annot)       }

static const index_field_t v13_hdr_fields[] = {
    V13_HEADER_FIELDS,
    END_FIELD
};


#define V14_HEADER_FIELDS                                               \
    V13_HEADER_FIELDS,                                                  \
    {  4, '4', offsetof(struct index_header, unseen)               }

static const index_field_t v14_hdr_fields[] = {
    V14_HEADER_FIELDS,
    EMPTY_FIELD(28),  /* spare fields */
    END_FIELD
};


#define V16_HEADER_FIELDS                                               \
    V14_HEADER_FIELDS,                                                  \
    {  8, '8', offsetof(struct index_header, createdmodseq)        }

static const index_field_t v16_hdr_fields[] = {
    V16_HEADER_FIELDS,
    EMPTY_FIELD(20),  /* spare fields */
    END_FIELD
};


#define V17_HEADER_FIELDS                                               \
    V16_HEADER_FIELDS,                                                  \
    {  4, 't', offsetof(struct index_header, changes_epoch)        }

static const index_field_t v17_hdr_fields[] = {
    V17_HEADER_FIELDS,
    EMPTY_FIELD(16),  /* spare fields */
    END_FIELD
};


static const index_field_t v18_hdr_fields[] = {
    V17_HEADER_FIELDS,
    {  8, '8', offsetof(struct index_header, quota_deleted_used)   },
    {  8, '8', offsetof(struct index_header, quota_expunged_used)  },
    END_FIELD
};


/* v19 rearranged fields so modseq_t & quota_t fall on 8-byte boundaries */
static const index_field_t v19_hdr_fields[] = {
    COMMON_HEADER_FIELDS,
    {  4, '4', offsetof(struct index_header, exists)               },
    {  4, '4', offsetof(struct index_header, options)              },
    {  4, '4', offsetof(struct index_header, leaked_cache_records) },
    {  8, '8', offsetof(struct index_header, highestmodseq)        },
    {  8, '8', offsetof(struct index_header, deletedmodseq)        },
    {  4, 't', offsetof(struct index_header, first_expunged)       },
    {  4, 't', offsetof(struct index_header, last_repack_time)     },
    {  4, '4', offsetof(struct index_header, header_file_crc)      },
    {  4, '4', offsetof(struct index_header, synccrcs.basic)       },
    {  4, '4', offsetof(struct index_header, recentuid)            },
    {  4, 't', offsetof(struct index_header, recenttime)           },
    {  4, 't', offsetof(struct index_header, pop3_show_after)      },
    {  4, '<', offsetof(struct index_header, quota_annot_used)     },
    {  4, '4', offsetof(struct index_header, synccrcs.annot)       },
    {  4, '4', offsetof(struct index_header, unseen)               },
    {  8, '8', offsetof(struct index_header, createdmodseq)        },
    {  8, '8', offsetof(struct index_header, quota_deleted_used)   },
    {  8, '8', offsetof(struct index_header, quota_expunged_used)  },
    {  4, 't', offsetof(struct index_header, changes_epoch)        },
    END_FIELD
};


/* v20 grew size of time fields and quota_annot_used to 64-bits
   and rearranged fields so that these would fall on 8-byte boundaries */
static const index_field_t v20_hdr_fields[] = {
    {  8, 'T', offsetof(struct index_header, last_appenddate)      },
    {  8, 'Q', offsetof(struct index_header, quota_mailbox_used)   },
    {  8, 'T', offsetof(struct index_header, pop3_last_login)      },
    {  4, '4', offsetof(struct index_header, deleted)              },
    {  4, '4', offsetof(struct index_header, answered)             },
    {  4, '4', offsetof(struct index_header, flagged)              },
    {  4, '4', offsetof(struct index_header, exists)               },
    {  4, '4', offsetof(struct index_header, options)              },
    {  4, '4', offsetof(struct index_header, leaked_cache_records) },
    {  8, 'Q', offsetof(struct index_header, highestmodseq)        },
    {  8, 'Q', offsetof(struct index_header, deletedmodseq)        },
    {  4, '4', offsetof(struct index_header, last_uid)             },
    {  4, '4', offsetof(struct index_header, uidvalidity)          },
    {  4, '4', offsetof(struct index_header, header_file_crc)      },
    {  4, '4', offsetof(struct index_header, synccrcs.basic)       },
    {  8, 'T', offsetof(struct index_header, recenttime)           },
    {  8, 'T', offsetof(struct index_header, pop3_show_after)      },
    {  4, '4', offsetof(struct index_header, synccrcs.annot)       },
    {  4, '4', offsetof(struct index_header, unseen)               },
    {  8, 'Q', offsetof(struct index_header, createdmodseq)        },
    {  8, 'Q', offsetof(struct index_header, quota_deleted_used)   },
    {  8, 'Q', offsetof(struct index_header, quota_expunged_used)  },
    {  8, 'Q', offsetof(struct index_header, quota_annot_used)     },
    {  8, 'T', offsetof(struct index_header, changes_epoch)        },
    {  8, 'T', offsetof(struct index_header, first_expunged)       },
    {  8, 'T', offsetof(struct index_header, last_repack_time)     },
    {  4, '4', offsetof(struct index_header, recentuid)            },
    END_FIELD
};


/*
 * Index file record fields by version
 */

/* Array of (MAX_USER_FLAGS/32) uint32_t fields */
#define USER_FLAGS_FIELDS                                               \
    {  4, '4', offsetof(struct index_record, user_flags[0])        },   \
    {  4, '4', offsetof(struct index_record, user_flags[1])        },   \
    {  4, '4', offsetof(struct index_record, user_flags[2])        },   \
    {  4, '4', offsetof(struct index_record, user_flags[3])        }


/* Common fields (by order and size) present in versions 6 through 19 */
#define COMMON_RECORD_FIELDS                                            \
    {  4, '4', offsetof(struct index_record, uid)                  },   \
    {  4, 't', offsetof(struct index_record, internaldate)         },   \
    {  4, 't', offsetof(struct index_record, sentdate)             },   \
    {  4, '<', offsetof(struct index_record, size)                 },   \
    {  4, '4', offsetof(struct index_record, header_size)          },   \
    {  4, 't', offsetof(struct index_record, gmtime)               },   \
    {  4, '<', offsetof(struct index_record, cache_offset)         },   \
    {  4, 't', offsetof(struct index_record, last_updated)         },   \
    {  4, '4', offsetof(struct index_record, system_flags)         },   \
    USER_FLAGS_FIELDS


#define V06_RECORD_FIELDS                                               \
    COMMON_RECORD_FIELDS,                                               \
    EMPTY_FIELD(4),  /* legacy content_lines field */                   \
    {  4, '4', offsetof(struct index_record, cache_version)        }

static const index_field_t v06_rec_fields[] = {
    V06_RECORD_FIELDS,
    END_FIELD
};


#define V07_RECORD_FIELDS                                               \
    V06_RECORD_FIELDS,                                                  \
    { 12, 'E', 0                                                   }

static const index_field_t v07_rec_fields[] = {
    V07_RECORD_FIELDS,
    END_FIELD
};


static const index_field_t v08_rec_fields[] = {
    V07_RECORD_FIELDS,
    {  8, '8', offsetof(struct index_record, modseq)               },
    END_FIELD
};


#define V10_RECORD_FIELDS                                               \
    V06_RECORD_FIELDS,                                                  \
    { 20, 'G', offsetof(struct index_record, guid)                 },   \
    {  8, '8', offsetof(struct index_record, modseq)               }

static const index_field_t v10_rec_fields[] = {
    V10_RECORD_FIELDS,
    END_FIELD
};


#define CACHE_CRC_FIELD                                                 \
    {  4, '4', offsetof(struct index_record, cache_crc)            }


static const index_field_t v12_rec_fields[] = {
    V10_RECORD_FIELDS,
    CACHE_CRC_FIELD,
    END_FIELD
};


static const index_field_t v13_rec_fields[] = {
    V10_RECORD_FIELDS,
    {  8, '8', offsetof(struct index_record, cid)                  },
    CACHE_CRC_FIELD,
    END_FIELD
};


#define V15_RECORD_FIELDS                                               \
    COMMON_RECORD_FIELDS,                                               \
    {  4, 't', offsetof(struct index_record, savedate)             },   \
    {  4, '4', offsetof(struct index_record, cache_version)        },   \
    { 20, 'G', offsetof(struct index_record, guid)                 },   \
    {  8, '8', offsetof(struct index_record, modseq)               },   \
    {  8, '8', offsetof(struct index_record, cid)                  }

static const index_field_t v15_rec_fields[] = {
    V15_RECORD_FIELDS,
    CACHE_CRC_FIELD,
    END_FIELD
};


static const index_field_t v16_rec_fields[] = {
    V15_RECORD_FIELDS,
    {  8, '8', offsetof(struct index_record, createdmodseq)        },
    CACHE_CRC_FIELD,
    END_FIELD
};


/* v20 grew the size and time fields to 64-bits
   and rearranged fields so that these would fall on 8-byte boundaries */
static const index_field_t v20_rec_fields[] = {
    {  4, '4', offsetof(struct index_record, uid)                  },
    {  4, '<', offsetof(struct index_record, cache_offset)         },
    {  8, 'T', offsetof(struct index_record, internaldate)         },
    {  8, 'T', offsetof(struct index_record, sentdate)             },
    {  8, 'Q', offsetof(struct index_record, size)                 },
    {  4, '4', offsetof(struct index_record, header_size)          },
    {  4, '4', offsetof(struct index_record, system_flags)         },
    USER_FLAGS_FIELDS,
    {  4, '4', offsetof(struct index_record, cache_version)        },
    { 20, 'G', offsetof(struct index_record, guid)                 },
    {  8, 'Q', offsetof(struct index_record, modseq)               },
    {  8, 'Q', offsetof(struct index_record, cid)                  },
    {  8, 'Q', offsetof(struct index_record, createdmodseq)        },
    {  8, 'T', offsetof(struct index_record, gmtime)               },
    {  8, 'T', offsetof(struct index_record, last_updated)         },
    {  8, 'T', offsetof(struct index_record, savedate)             },
    {  8, 'Q', offsetof(struct index_record, basecid)              },
    CACHE_CRC_FIELD,
    END_FIELD
};


/*
 * Index header/record CRC field
 */
static const index_field_t crc_field[] = {
    {  4, '4', 0                                                   },
    END_FIELD
};


/*
 * Index file templates by version.
 * We don't support versions prior to 6, and version 11 was Fastmail internal
 */

static const index_file_template_t v00_template =
    {  24,   0, 0,                v00_hdr_fields, NULL,            NULL      };

static const index_file_template_t v06_template =
    {  76,  60, OPT_POP3_NEW_UIDL, v06_hdr_fields, v06_rec_fields, NULL      };

static const index_file_template_t v07_template =
    {  76,  72, OPT_POP3_NEW_UIDL, v06_hdr_fields, v07_rec_fields, NULL      };

static const index_file_template_t v08_template =
    {  92,  80, MAILBOX_OPT_VALID, v08_hdr_fields, v08_rec_fields, NULL      };

static const index_file_template_t v09_template =
    {  96,  80, MAILBOX_OPT_VALID, v09_hdr_fields, v08_rec_fields, NULL      };

static const index_file_template_t v10_template =
    {  96,  88, MAILBOX_OPT_VALID, v09_hdr_fields, v10_rec_fields, NULL      };

static const index_file_template_t v12_template =
    { 128,  96, MAILBOX_OPT_VALID, v12_hdr_fields, v12_rec_fields, crc_field };

static const index_file_template_t v13_template =
    { 128, 104, MAILBOX_OPT_VALID, v13_hdr_fields, v13_rec_fields, crc_field };

static const index_file_template_t v14_template =
    { 160, 104, MAILBOX_OPT_VALID, v14_hdr_fields, v13_rec_fields, crc_field };

static const index_file_template_t v15_template =
    { 160, 104, MAILBOX_OPT_VALID, v14_hdr_fields, v15_rec_fields, crc_field };

static const index_file_template_t v16_template =
    { 160, 112, MAILBOX_OPT_VALID, v16_hdr_fields, v16_rec_fields, crc_field };

static const index_file_template_t v17_template =
    { 160, 112, MAILBOX_OPT_VALID, v17_hdr_fields, v16_rec_fields, crc_field };

static const index_file_template_t v18_template =
    { 160, 112, MAILBOX_OPT_VALID, v18_hdr_fields, v16_rec_fields, crc_field };

static const index_file_template_t v19_template =
    { 160, 112, MAILBOX_OPT_VALID, v19_hdr_fields, v16_rec_fields, crc_field };

static const index_file_template_t v20_template =
    { 192, 144, MAILBOX_OPT_VALID, v20_hdr_fields, v20_rec_fields, crc_field };


EXPORTED const index_file_template_t *const index_files_by_version[] = {
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
EXPORTED const size_t n_index_files = sizeof(index_files_by_version)
                                      / sizeof(index_files_by_version[0]);

EXPORTED const unsigned char *index_file_read_fields(const unsigned char *bufp, void *base,
                                                     const index_field_t *fields)
{
    for (; fields->data_type; fields++) {
        void *datap = (void *) ((off_t) base + fields->data_offset);

        switch (fields->data_type) {
        case '4':
            *((uint32_t *) datap) = ntohl(*((uint32_t *)(bufp)));
            break;

        case '<':
            /* this field is stored as a 32b on disk but 64b in memory */
            *((uint64_t *) datap) = ntohl(*((uint32_t *)(bufp)));
            break;

        case '8':
            *((uint64_t *) datap) = align_ntohll(bufp);
            break;

        case 'Q':
            *((uint64_t *) datap) = ntohll(*((uint64_t *)(bufp)));
            break;

        case 'B':
            memcpy(datap, bufp, fields->disk_size);
            break;

        case 'G':
            message_guid_import((struct message_guid *)datap, (const char *)bufp);
            break;

        case 'T':
            TIMESPEC_FROM_NANOSEC((struct timespec *) datap, ntohll(*((uint64_t *)(bufp))));
            break;

        case 't':
            ((struct timespec *) datap)->tv_sec = ntohl(*((uint32_t *)(bufp)));
            ((struct timespec *) datap)->tv_nsec = 0;
            break;

        case 'E':
            /* nothing to read */
            break;

        default:
            // should never get here
            fatal("unknown header field data type", EX_SOFTWARE);
        }

        bufp += fields->disk_size;
    }

    return bufp;
}

EXPORTED unsigned char *index_file_write_fields(void *base, unsigned char *bufp,
                                                const index_field_t *fields)
{
    for (; fields->data_type; fields++) {
        void *datap = (void *) ((off_t) base + fields->data_offset);

        switch (fields->data_type) {
        case '4':
            *((uint32_t *) bufp) = htonl(*((uint32_t *) datap));
            break;

        case '<':
            /* this field is 64b in memory but stored as 32b on disk */
            assert(*((uint64_t *) datap) <= UINT32_MAX);
            *((uint32_t *) bufp) = htonl(*((uint64_t *) datap));
            break;

        case '8':
            align_htonll(bufp, *((uint64_t *) datap));
            break;

        case 'Q':
            *((uint64_t *) bufp) = htonll(*((uint64_t *)datap));
            break;

        case 'B':
            memcpy(bufp, datap, fields->disk_size);
            break;

        case 'G':
            message_guid_export((struct message_guid *)datap, (char *)bufp);
            break;

        case 'T':
            *((uint64_t *)(bufp)) = htonll(TIMESPEC_TO_NANOSEC((struct timespec *) datap));
            break;

        case 't':
            *((uint32_t *)(bufp)) = htonl(((struct timespec *) datap)->tv_sec);
            break;

        case 'E':
            /* nothing to write */
            break;

        default:
            // should never get here
            fatal("unknown header field data type", EX_SOFTWARE);
        }

        bufp += fields->disk_size;
    }

    return bufp;
}
