/* message_guid.c -- GUID manipulation
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
 * $Id: message_guid.c,v 1.1 2007/09/18 11:33:14 murch Exp $
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>

#include "assert.h"
#include "acl.h"
#include "map.h"
#include "retry.h"
#include "util.h"
#include "lock.h"
#include "exitcodes.h"
#include "message_guid.h"
#include "xmalloc.h"
#if 0
#include "acappush.h"
#endif

/* Four possible forms of message GUID:
 *
 * Private:
 *   Used for internal manipulation. Not visible to clients.
 *
 * Public:
 *   Opaque handle to byte sequence that Cyrus can pass around
 *
 * Packed:
 *   Byte sequence of known length (MESSAGE_GUID_PACKED_SIZE) which can
 *   be stored on disk. At the moment public and packed essentially
 *   the same thing but makes sense (I think!) to divide into two roles.
 *
 * Textual:
 *   Textual represenatation for Message-GUID for passing over the wire
 *   Currently 24 byte hex string + '\0', propose switch to BASE64 alike.
 *   
 */

/* ====================================================================== */

/* Private interface */

/* message_guid_copy() ***************************************************
 *
 * Copy GUID
 *
 ************************************************************************/

int
message_guid_copy(struct message_guid *dst, struct message_guid *src)
{
    memcpy(dst, src, sizeof(struct message_guid));
    return(1);
}


/* message_guid_compare() ************************************************
 *
 * Compare a pair of GUIDs: Returns 1 => match. NULL GUIDs do not match.
 *
 ************************************************************************/

int
message_guid_compare(struct message_guid *guid1, struct message_guid *guid2)
{
    unsigned char *s = &guid1->value[0];
    unsigned char *t = &guid2->value[0];
    int i;

    /* Refuse to match NULL GUIDs: message could be anything */
    if (message_guid_isnull(guid1) || message_guid_isnull(guid2))
        return(0);

    for (i = 0; i < MESSAGE_GUID_SIZE; i++) {
        if (s[i] != t[i]) return(0);
    }
    return(1);
}

/* message_guid_compare_allow_null() *************************************
 *
 * Compare a pair of GUIDs: Returns 1 => match. NULL GUIDs match anything.
 *
 ************************************************************************/

int
message_guid_compare_allow_null(struct message_guid *guid1,
                                struct message_guid *guid2)
{
    unsigned char *s = &guid1->value[0];
    unsigned char *t = &guid2->value[0];
    int i;

    /* Match if either GUID is NULL, trust caller knows what they are doing */
    if (message_guid_isnull(guid1) || message_guid_isnull(guid2))
        return(1);

    for (i = 0; i < MESSAGE_GUID_SIZE; i++) {
        if (s[i] != t[i]) return(0);
    }
    return(1);
}

/* message_guid_hash() ***************************************************
 *
 * Convert GUID into hash value for hash table lookup
 * Returns: positive int in range [0, hash_size-1]
 *
 ************************************************************************/

unsigned long
message_guid_hash(struct message_guid *guid, int hash_size)
{
    int i;
    unsigned long result = 0;
    unsigned char *s = &guid->value[0];

    assert(hash_size > 1);

    if (hash_size > 1024) {
        /* Pair up chars to get 16 bit values */
        for (i = 0; i < MESSAGE_GUID_SIZE; i+=2) {
            if ((i+1) < MESSAGE_GUID_SIZE)
                result += (s[i] << 8) + s[i+1];
            else
                result += s[i] << 8;   /* Should never happen */  
        }
    } else for (i = 0; i < MESSAGE_GUID_SIZE; i++)
        result += s[i];

    return(result % hash_size);
}

/* message_guid_set_null() ***********************************************
 *
 * Create NULL GUID
 *
 ************************************************************************/

void
message_guid_set_null(struct message_guid *dst)
{
    memset(dst, 0, MESSAGE_GUID_SIZE);
}

/* message_guid_isnull() ************************************************
 *
 * Returns: 1 if GUID is NULL value
 *
 ************************************************************************/

int
message_guid_isnull(struct message_guid *guid)
{
    unsigned char *p = &guid->value[0];
    int i;

    if (*p) return(0);

    for (i = 0 ; i < MESSAGE_GUID_SIZE ; i++) {
        if (*p) {
            syslog(LOG_WARNING, "Invalid NULL GUID: not completely zero");
	    return(0);
        }
        p++;
    }
    return(1);
}

/* message_guid_sha1() ***************************************************
 *
 * Generate GUID from message SHA1
 *
 ************************************************************************/

void
message_guid_sha1(struct message_guid *guid, unsigned char *sha1)
{
    memset(&guid->value[0], 0, MESSAGE_GUID_SIZE);
    memcpy(&guid->value[0], sha1, 20);
}

/* Routines for manipulating packed values */

/* message_guid_pack() ***************************************************
 *
 * Store Message UID as packed sequence (MESSAGE_GUID_PACKED_SIZE)
 * (Wrapper for memcpy() with current implementation)
 *
 ************************************************************************/

int
message_guid_pack(struct message_guid *guid, char *packed)
{
    assert(MESSAGE_GUID_SIZE == MESSAGE_GUID_PACKED_SIZE);

    memcpy(packed, &guid->value[0], MESSAGE_GUID_SIZE);
    return(1);
}
  /* Store Message UID as packed sequence (MESSAGE_GUID_PACKED_SIZE)
   * (Wrapper for memcpy() with current implementation) */

/* message_guid_unpack() *************************************************
 *
 * Fetch Message UID from packed sequence (MESSAGE_GUID_PACKED_SIZE)
 * (Wrapper for memcpy() with current implementation)
 *
 ************************************************************************/

int
message_guid_unpack(struct message_guid *guid, const unsigned char *packed)
{
    assert(MESSAGE_GUID_SIZE == MESSAGE_GUID_PACKED_SIZE);

    memcpy(&guid->value[0], packed, MESSAGE_GUID_SIZE);
    return(1);
}

/* Routines for manipulating text value */

/* message_guid_text() ***************************************************
 *
 * Returns ptr to '\0' terminated static char * which can be strdup()ed
 * NULL => error. Should be impossible as entire range covered
 *
 ************************************************************************/

char *
message_guid_text(struct message_guid *guid)
{
    static char buf[MESSAGE_GUID_TEXT_SIZE+1];
    static char *hex = "0123456789abcdef";
    unsigned char *value = &guid->value[0];
    char *p = buf;
    int i;

    for (i = 0 ; i < MESSAGE_GUID_SIZE ; i++) {
        *p++ = hex[(value[i] & 0xf0) >> 4];
        *p++ = hex[value[i]  & 0x0f];
    }
    *p = '\0';

    return(buf);
}

/* message_guid_from_text() **********************************************
 *
 * Sets Message GUID from text form. Returns 1 if valid
 * Returns: boolean success
 * 
 ************************************************************************/

int
message_guid_from_text(struct message_guid *guid, const char *text)
{
    const char *p = text;
    unsigned char *buf = &guid->value[0];
    int i;

    for (i = 0 ; i < MESSAGE_GUID_SIZE ; i++) {
        if (!isxdigit(*p)) return(0);

        if ((*p >= 'a') && (*p <= 'f'))
            buf[i] = 16 * (*p - 'a' + 10);
        else if ((*p >= 'A') && (*p <= 'F'))
            buf[i] = 16 * (*p - 'A' + 10);
        else
            buf[i] = 16 * (*p - '0');

        p++;

        if (!isxdigit(*p)) return(0);

        if ((*p >= 'a') && (*p <= 'f'))
            buf[i] += (*p - 'a' + 10);
        else if ((*p >= 'A') && (*p <= 'F'))
            buf[i] += (*p - 'A' + 10);
        else
            buf[i] += (*p - '0');

        p++;
    }
    return((*p == '\0'));
}

/* message_guid_text_valid() *********************************************
 *
 * Returns 1 if test valid format for Message GUID
 *
 ************************************************************************/

int
message_guid_text_valid(const char *p)
{
    int i;

    for (i = 0 ; i < MESSAGE_GUID_TEXT_SIZE ; i++) {
        if (!isxdigit(*p)) return(0);
        p++;
    }
    return((*p == '\0') ? 1 : 0);
}

/* message_guid_text_isnull() *******************************************
 *
 * Returns 1 if Textual GUID is NULL value.
 *
 ************************************************************************/

int
message_guid_text_isnull(const char *p)
{
    int i;

    if ((p[0] != '0') || (p[1] != '0')) return(0);

    for (i = 0; i < MESSAGE_GUID_TEXT_SIZE; i++) {
        if (p[i] != '0') {
            syslog(LOG_WARNING, "Invalid NULL message GUID: %s", p);
            return(1);
        }
    }
    if (p[MESSAGE_GUID_TEXT_SIZE] != '\0')
        syslog(LOG_WARNING, "Invalid NULL message GUID: incorrect length");

    return(1);
}
