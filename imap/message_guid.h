/* message_guid.h - GUID manipulation */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef MESSAGE_GUID_H
#define MESSAGE_GUID_H

#include <stddef.h>
#include <stdint.h>

/* Public interface */

#define MESSAGE_GUID_SIZE         (20)    /* Size of GUID byte sequence */

enum guid_status {
    GUID_UNKNOWN = -1, /* Unknown if GUID is [non-]NULL (not yet tested) */
    GUID_NULL =     0, /* GUID is NULL */
    GUID_NONNULL =  1, /* GUID is non-NULL */
};

struct message_guid {
    enum guid_status status;
    unsigned char value[MESSAGE_GUID_SIZE];
};

#define MESSAGE_GUID_INITIALIZER { GUID_UNKNOWN, { 0 } }

/* Generate GUID from message */
void message_guid_generate(struct message_guid *guid,
                           const char *msg_base, unsigned long msg_len);

/* Copy a GUID */
void message_guid_copy(struct message_guid *dst, const struct message_guid *src);
struct message_guid message_guid_clone(const struct message_guid *src);

/* Compare a pair of GUIDs: Returns 1 => match. */
int message_guid_equal(const struct message_guid *guid1,
                       const struct message_guid *guid2);
int message_guid_cmp(const struct message_guid *guid1,
                     const struct message_guid *guid2);

/* Convert GUID into hash value for hash table lookup
 * Returns: positive int in range [0, hash_size-1]
 */
unsigned long message_guid_hash(const struct message_guid *guid, int hash_size);

  /* Create a NULL GUID */
void message_guid_set_null(struct message_guid *guid);

/* Returns 1 if GUID is NULL value */
int message_guid_isnull(const struct message_guid *guid);

/* Export Message GUID as byte sequence (MESSAGE_GUID_SIZE)
 * (Wrapper for memcpy() with current implementation)
 */
void message_guid_export(const struct message_guid *guid, char *buf);

/* Import Message GUID from packed sequence (MESSAGE_GUID_SIZE)
 * (Wrapper for memcpy() with current implementation)
 */
const char *message_guid_import(struct message_guid *guid,
                                const char *buf);


/* Routines for manipulating text value */

/* Returns ptr to '\0' terminated static char * which can be strdup()ed
 * NULL => error. Should be impossible as entire range covered
 */
const char *message_guid_encode(const struct message_guid *guid);

const char *message_guid_encode_short(const struct message_guid *guid, size_t len);

/* Sets Message GUID from text form. Returns 1 if valid
 */
int message_guid_decode(struct message_guid *guid, const char *text);

#endif /* MESSAGE_GUID_H */
