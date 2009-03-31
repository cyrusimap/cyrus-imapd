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
 *
 * $Id: message_guid.c,v 1.8 2009/03/31 04:11:19 brong Exp $
 */

#include <config.h>
#include <string.h>
#include <ctype.h>

#include "assert.h"
#include "global.h"
#include "message_guid.h"
#include "util.h"

#ifdef HAVE_SSL
#include <openssl/sha.h>
#endif

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
 *   Textual represenatation for Message GUID for passing over the wire
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

void message_guid_generate(struct message_guid *guid,
			   const char *msg_base, unsigned long msg_len)
{
    enum enum_value config_guidmode = config_getenum(IMAPOPT_GUID_MODE);

    guid->status = GUID_NULL;
    memset(guid->value, 0, MESSAGE_GUID_SIZE);

    switch (config_guidmode) {
    case IMAP_ENUM_GUID_MODE_SHA1:
#ifdef HAVE_SSL
	guid->status = GUID_NONNULL;
	SHA1((const unsigned char *) msg_base, msg_len, guid->value);
#endif /* HAVE_SSL */
	break;
    default:
	break;
    }
}

/* message_guid_copy() ***************************************************
 *
 * Copy GUID
 *
 ************************************************************************/

void message_guid_copy(struct message_guid *dst, struct message_guid *src)
{
    memcpy(dst, src, sizeof(struct message_guid));
}

/* _message_guid_compare() ***********************************************
 *
 * Compare a pair of GUIDs: Returns 1 => match.
 *
 * If allownull is 1, match if either GUID is NULL (trust caller knows
 * what they are doing).
 * Otherwise, refuse to match NULL GUIDs (message could be anything).
 *
 ************************************************************************/

static int _message_guid_compare(struct message_guid *g1,
				 struct message_guid *g2,
				 int allownull)
{
    if (message_guid_isnull(g1) || message_guid_isnull(g2)) return(allownull);

    return (memcmp(g1->value, g2->value, MESSAGE_GUID_SIZE) == 0);
}

/* message_guid_compare() ************************************************
 *
 * Compare a pair of GUIDs: Returns 1 => match.  NULL GUIDs do not match.
 *
 ************************************************************************/

int message_guid_compare(struct message_guid *guid1,
			 struct message_guid *guid2)
{
    return _message_guid_compare(guid1, guid2, 0);
}

/* message_guid_compare_allow_null() *************************************
 *
 * Compare a pair of GUIDs: Returns 1 => match.  NULL GUIDs match anything.
 *
 ************************************************************************/

int message_guid_compare_allow_null(struct message_guid *guid1,
				    struct message_guid *guid2)
{
    return _message_guid_compare(guid1, guid2, 1);
}

/* message_guid_hash() ***************************************************
 *
 * Convert GUID into hash value for hash table lookup
 * Returns: positive int in range [0, hash_size-1]
 *
 ************************************************************************/

unsigned long message_guid_hash(struct message_guid *guid, int hash_size)
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

void message_guid_set_null(struct message_guid *guid)
{
    guid->status = GUID_NULL;
    memset(guid->value, 0, MESSAGE_GUID_SIZE);
}

/* message_guid_isnull() ************************************************
 *
 * Returns: 1 if GUID is NULL value
 *
 ************************************************************************/

int message_guid_isnull(struct message_guid *guid)
{
    if (guid->status == GUID_UNKNOWN) {
	unsigned char *p = guid->value;
	int i;

	for (i = 0; (i < MESSAGE_GUID_SIZE) && !*p++; i++);
	guid->status = (i == MESSAGE_GUID_SIZE) ? GUID_NULL : GUID_NONNULL;
    }

    return(guid->status == GUID_NULL);
}

/* message_guid_export() *************************************************
 *
 * Export Message GUID as byte sequence (MESSAGE_GUID_SIZE)
 * (Wrapper for memcpy() with current implementation)
 *
 ************************************************************************/

void message_guid_export(struct message_guid *guid, unsigned char *buf)
{
    memcpy(buf, guid->value, MESSAGE_GUID_SIZE);
}

/* message_guid_import() *************************************************
 *
 * Import Message GUID from byte sequence (MESSAGE_GUID_SIZE)
 * (Wrapper for memcpy() with current implementation)
 *
 ************************************************************************/

struct message_guid *message_guid_import(struct message_guid *guid,
					 const unsigned char *buf)
{
    static struct message_guid tmp;

    if (!guid) guid = &tmp;

    guid->status = GUID_UNKNOWN;
    memcpy(guid->value, buf, MESSAGE_GUID_SIZE);

    return(guid);
}


/* Routines for manipulating text value (ASCII hex encoding) */

/* message_guid_encode() *************************************************
 *
 * Returns ptr to '\0' terminated static char * which can be strdup()ed
 * NULL => error. Should be impossible as entire range covered
 *
 ************************************************************************/

static char XDIGIT[] = "0123456789abcdef";

char *message_guid_encode(struct message_guid *guid)
{
    static char text[2*MESSAGE_GUID_SIZE+1];
    unsigned char *v = guid->value;
    char *p = text;
    int i;

    for (i = 0; i < MESSAGE_GUID_SIZE; i++, v++) {
        *p++ = XDIGIT[(*v >> 4) & 0xf];
        *p++ = XDIGIT[*v & 0xf];
    }
    *p = '\0';

    return(text);
}

/* message_guid_decode() *************************************************
 *
 * Sets Message GUID from text form. Returns 1 if valid
 * Returns: boolean success
 * 
 ************************************************************************/

int message_guid_decode(struct message_guid *guid, const char *text)
{
    unsigned char *v = guid->value, msn, lsn;
    const char *p = text;
    int i;

    guid->status = GUID_NULL;

    for (i = 0; i < MESSAGE_GUID_SIZE; i++, v++) {
	if (!Uisxdigit(*p)) return(0);
	msn = (*p > '9') ? tolower((int) *p) - 'a' + 10 : *p - '0';
	p++;

	if (!Uisxdigit(*p)) return(0);
	lsn = (*p > '9') ? tolower((int) *p) - 'a' + 10 : *p - '0';
	p++;
	
	*v = (unsigned char) (msn << 4) | lsn;
	if (*v) guid->status = GUID_NONNULL;
    }

    return(*p == '\0');
}
