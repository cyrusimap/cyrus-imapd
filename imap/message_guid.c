/* message_guid.c -- GUID manipulation
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

#include <config.h>
#include <string.h>

#include "assert.h"
#include "global.h"
#include "message_guid.h"
#include "util.h"
#include "xsha1.h"

/* Four possible forms of Message GUID:
 *
 * Private:
 *   Used for internal manipulation.  Not visible to clients.
 *
 * Public:
 *   Opaque handle to GUID that Cyrus can pass around.
 *
 *   OR
 *
 *   Byte sequence of known length (MESSAGE_GUID_SIZE) which can
 *   be stored on disk.
 *
 * Textual:
 *   Textual representation for Message GUID for passing over the wire
 *   Currently BASE64 string + '\0'.
 *
 */

/* ====================================================================== */


/* Public interface */

/* message_guid_generate() ***********************************************
 *
 * Generate GUID from message
 *
 ************************************************************************/

EXPORTED void message_guid_generate(struct message_guid *guid,
                           const char *msg_base, unsigned long msg_len)
{
    guid->status = GUID_NULL;
    memset(guid->value, 0, MESSAGE_GUID_SIZE);

    guid->status = GUID_NONNULL;
    xsha1((const unsigned char *) msg_base, msg_len, guid->value);
}

/* message_guid_copy() ***************************************************
 *
 * Copy GUID
 *
 ************************************************************************/

EXPORTED void message_guid_copy(struct message_guid *dst, const struct message_guid *src)
{
    memcpy(dst, src, sizeof(struct message_guid));
}

/* message_guid_equal() **************************************************
 *
 * Compare a pair of GUIDs: Returns 1 => match.
 *
 ************************************************************************/

EXPORTED int message_guid_equal(const struct message_guid *g1,
                                const struct message_guid *g2)
{
    return (memcmp(g1->value, g2->value, MESSAGE_GUID_SIZE) == 0);
}

EXPORTED int message_guid_cmp(const struct message_guid *g1,
                              const struct message_guid *g2)
{
    return memcmp(g1->value, g2->value, MESSAGE_GUID_SIZE);
}

/* message_guid_hash() ***************************************************
 *
 * Convert GUID into hash value for hash table lookup
 * Returns: positive int in range [0, hash_size-1]
 *
 ************************************************************************/

EXPORTED unsigned long message_guid_hash(const struct message_guid *guid, int hash_size)
{
    int i;
    unsigned long result = 0;
    const unsigned char *s = &guid->value[0];

    assert(hash_size > 1);

    if (hash_size > 1024) {
        /* Pair up chars to get 16 bit values */
        for (i = 0; i < MESSAGE_GUID_SIZE; i += 2)
            result += (s[i] << 8) + s[i+1];
    }
    else
        for (i = 0; i < MESSAGE_GUID_SIZE; i++)
            result += s[i];

    return (result % hash_size);
}

/* message_guid_set_null() ***********************************************
 *
 * Create NULL GUID
 *
 ************************************************************************/

EXPORTED void message_guid_set_null(struct message_guid *guid)
{
    guid->status = GUID_NULL;
    memset(guid->value, 0, MESSAGE_GUID_SIZE);
}

/* message_guid_isnull() ************************************************
 *
 * Returns: 1 if GUID is NULL value
 *
 ************************************************************************/

EXPORTED int message_guid_isnull(const struct message_guid *guid)
{
    if (guid->status == GUID_UNKNOWN) {
        /* allow internal recalculation while still being const */
        struct message_guid *backdoor = (struct message_guid *)guid;
        const unsigned char *p = guid->value;
        int i;

        for (i = 0; (i < MESSAGE_GUID_SIZE) && !*p++; i++);
        backdoor->status = (i == MESSAGE_GUID_SIZE) ? GUID_NULL : GUID_NONNULL;
    }

    return (guid->status == GUID_NULL);
}

/* message_guid_export() *************************************************
 *
 * Export Message GUID as byte sequence (MESSAGE_GUID_SIZE)
 * (Wrapper for memcpy() with current implementation)
 *
 ************************************************************************/

EXPORTED void message_guid_export(const struct message_guid *guid, char *buf)
{
    memcpy(buf, guid->value, MESSAGE_GUID_SIZE);
}

/* message_guid_import() *************************************************
 *
 * Import Message GUID from byte sequence (MESSAGE_GUID_SIZE)
 * (Wrapper for memcpy() with current implementation)
 *
 ************************************************************************/

EXPORTED const char *message_guid_import(struct message_guid *guid,
                                         const char *buf)
{
    assert(guid);
    guid->status = GUID_UNKNOWN;
    memcpy(guid->value, buf, MESSAGE_GUID_SIZE);
    return buf + MESSAGE_GUID_SIZE;
}


/* Routines for manipulating text value (ASCII hex encoding) */

/* message_guid_encode() *************************************************
 *
 * Returns ptr to '\0' terminated static char * which can be strdup()ed
 * NULL => error. Should be impossible as entire range covered
 *
 ************************************************************************/

EXPORTED const char *message_guid_encode(const struct message_guid *guid)
{
    static char text[2*MESSAGE_GUID_SIZE+1];
    int r = bin_to_lchex(&guid->value, MESSAGE_GUID_SIZE, text);
    assert(r == 2*MESSAGE_GUID_SIZE);
    return text;
}

EXPORTED const char *message_guid_encode_short(const struct message_guid *guid, size_t len)
{
    char *backdoor = (char *)message_guid_encode(guid);

    assert(len > 0 && len < MESSAGE_GUID_SIZE*2);
    backdoor[len] = '\0';
    return backdoor;
}

/* message_guid_decode() *************************************************
 *
 * Sets Message GUID from text form. Returns 1 if valid
 * Returns: boolean success
 *
 ************************************************************************/

EXPORTED int message_guid_decode(struct message_guid *guid, const char *text)
{
    int r = hex_to_bin(text, 0, &guid->value);
    guid->status = (r > 0 ? GUID_NONNULL : GUID_NULL);
    return (r == MESSAGE_GUID_SIZE);
}
