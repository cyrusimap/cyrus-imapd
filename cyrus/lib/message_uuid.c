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
#include "message_uuid.h"
#include "xmalloc.h"
#if 0
#include "acappush.h"
#endif

/* Four possible forms of messageID:
 *
 * Private:
 *   Used for internal manipulation. Not visible to clients.
 *
 * Public:
 *   Opaque handle to byte sequence that Cyrus can pass around
 *
 * Packed:
 *   Byte sequence of known length (MESSAGE_UUID_PACKED_SIZE) which can
 *   be stored on disk. At the moment public and packed essentially
 *   the same thing but makes sense (I think!) to divide into two roles.
 *
 * Textual:
 *   Textual represenatation for Message-UUID for passing over the wire
 *   Currently 24 byte hex string + '\0', propose switch to BASE64 alike.
 *   
 */

/* ====================================================================== */

/* Private interface */

/* 96-bit UUID allocation space divided into 256 possible schemas based
 * on first byte. Currently two UUID schemas defined:
 *
 * Schema 0  => NULL values.
 * Schema 1  => UUIDs allocated by master process in 2^24 bit chunks.
 */

static int schema = 0;

/* Schema 1 Byte encoding is:
 *
 * Byte Offset       Use
 *
 * 0          Current UUID schema (following is schema 1)
 * 1  ->  8   64 bit prefix private to UUID schema.
 * 9  -> 11   24 bit counter for UUID with child process
 *            (means max 16777216 messages per child process)
 *
 * Numbers stored big-endian.
 */

static struct {
    unsigned char prefix[8];  /* 8 bytes used */
    unsigned long count;      /* 3 bytes used */
} schema_1;

/* message_uuid_record() *************************************************
 *
 * Decode public UUID into components for manipulation
 * Returns: Cyrus error code, 0 on sucess
 *
 ************************************************************************/

static int
message_uuid_record(struct message_uuid *uuid)
{
    unsigned char *s = &uuid->value[0];
    int rc = 1;

    switch (s[0]) {
    case 0:
        schema = 0;
        break;
    case 1:
        schema = 1;
        memcpy(&schema_1.prefix[0], &s[1], 8);
        schema_1.count = 0;
        break;
    default:
        rc = 0;
        break;
    }

    return(rc);
}

/* message_uuid_extract() ************************************************
 *
 * Convert message_uuid_structure into public UID
 * Returns: boolean success
 *
 ************************************************************************/

static int
message_uuid_extract(struct message_uuid *uuid)
{
   unsigned char *s = &uuid->value[0];
   int rc = 1;

   switch (schema) {
   case 0:
       message_uuid_set_null(uuid);
       break;
   case 1:
       s[0] = 1;

       memcpy(&s[1], &schema_1.prefix[0], 8);
       s[9]  = ((schema_1.count & 0xff0000) >> 16);
       s[10] = ((schema_1.count & 0x00ff00) >> 8);
       s[11] = ((schema_1.count & 0x0000ff));
       break;
   default:
       syslog(LOG_ERR, "UUID: Unknown schema");
       message_uuid_set_null(uuid);
       rc = 0;
       break;
   }

   return(rc);
}     

/* ====================================================================== */

/* message_uuid_client_init() ********************************************
 *
 * Initialise private UUID system
 * Returns: boolean success
 ************************************************************************/

int
message_uuid_client_init(char *uuid_prefix)
{
    struct message_uuid tmp;
    unsigned char *s = &tmp.value[0];
    unsigned long count, checksum;

    /* Record a NULL value in case of failure */
    message_uuid_set_null(&tmp);
    message_uuid_record(&tmp);
        
    if (uuid_prefix == NULL)
        return(1);

    if (!message_uuid_from_text(&tmp, uuid_prefix))
        return(0);

    /* Test and record UUID prefix in different schemas */
    switch (s[0]) {
    case 0:
        /* NOOP, used record NULL value */
        break;
    case 1:
        /* Compute 24 bit checksum from first 9 bytes */
        count  = (s[0] << 16) + (s[1] << 8)  + s[2];
        count += (s[3] << 16) + (s[4] << 8)  + s[5];
        count += (s[6] << 16) + (s[7] << 8)  + s[8];
        count &= 0x00ffffff;

        /* And retrieve checksum from last three bytes */
        checksum  = (s[9] << 16) + (s[10] << 8) + s[11];
        
        if (checksum != count) {
            syslog(LOG_ERR, "UUID checksum mismatch for %s", uuid_prefix);
            return(0);
        }

        /* Clear checksum bytes */
        s[9] = 0;
        s[10] = 0;
        s[11] = 0;

        if (!message_uuid_record(&tmp))
            return(0);
        break;
    default:
        syslog(LOG_ERR,
               "Attempt to initialise invalid UUID prefix: %s", uuid_prefix);
        return(0);
        break;
    }

    return(1);
}

/* message_uuid_assign() *************************************************
 *
 * Assign next UUID to preallocated structure
 * Returns: Cyrus error code, 0 on sucess
 *
 ************************************************************************/

int
message_uuid_assign(struct message_uuid *uuid)
{
    int rc = 1;

    switch (schema) {
    case 0:
        message_uuid_set_null(uuid);
        break;
    case 1:
        if (schema_1.count >= (256*256*256)) {
            /* Allocation space (2^24 nodes) exhausted */
            message_uuid_set_null(uuid);
            break;
        }

        if (!message_uuid_extract(uuid)) {
            message_uuid_set_null(uuid);
            rc = 0;
            break;
        }

        schema_1.count++;

        break;
    default:
        message_uuid_set_null(uuid);
        rc = 0;
        break;
    }

    return(rc);
}

/* message_uuid_alloc() **************************************************
 *
 * Allocate and assign next UUID using xmalloc.
 * Returns: NULL Message-UUID if allocation exhaused.
 *          NULL => Internal error
 *
 ************************************************************************/

struct message_uuid *
message_uuid_alloc()
{
    struct message_uuid *current = xmalloc(sizeof(struct message_uuid));

    if (!message_uuid_assign(current))
        return(NULL);

    return(current);
}

/* message_uuid_free() ***************************************************
 *
 * Wrapper for free function.
 *
 ************************************************************************/

void
message_uuid_free(struct message_uuid **uuidp)
{
    free(*uuidp);
    *uuidp = NULL;
}

/* message_uuid_copy() ***************************************************
 *
 * Copy UUID
 *
 ************************************************************************/

int
message_uuid_copy(struct message_uuid *dst, struct message_uuid *src)
{
    memcpy(dst, src, sizeof(struct message_uuid));
    return(1);
}


/* message_uuid_compare() ************************************************
 *
 * Compare a pair of UUIDs: Returns 1 => match
 *
 ************************************************************************/

int
message_uuid_compare(struct message_uuid *uuid1, struct message_uuid *uuid2)
{
    unsigned char *s = &uuid1->value[0];
    unsigned char *t = &uuid2->value[0];
    int i;

    for (i = 0; i < MESSAGE_UUID_SIZE; i++) {
        if (s[i] != t[i]) return(0);
    }
    return(1);
}

/* message_uuid_hash() ***************************************************
 *
 * Convert UUID into hash value for hash table lookup
 * Returns: positive int in range [0, hash_size-1]
 *
 ************************************************************************/

unsigned long
message_uuid_hash(struct message_uuid *uuid, int hash_size)
{
    int i;
    unsigned long result = 0;
    unsigned char *s = &uuid->value[0];

    assert(hash_size > 1);

    if (hash_size > 1024) {
        /* Pair up chars to get 16 bit values */
        for (i = 0; i < MESSAGE_UUID_SIZE; i+=2) {
            if ((i+1) < MESSAGE_UUID_SIZE)
                result += (s[i] << 8) + s[i+1];
            else
                result += s[i] << 8;   /* Should never happen */  
        }
    } else for (i = 0; i < MESSAGE_UUID_SIZE; i++)
        result += s[i];

    return(result % hash_size);
}

/* message_uuid_set_null() ***********************************************
 *
 * Create NULL UUID
 *
 ************************************************************************/

int
message_uuid_set_null(struct message_uuid *dst)
{
    memset(dst, 0, MESSAGE_UUID_SIZE);
    return(1);
}

/* message_uuid_isnull() ************************************************
 *
 * Returns: 1 if UUID is NULL value
 *
 ************************************************************************/

int
message_uuid_isnull(struct message_uuid *uuid)
{
    unsigned char *p = &uuid->value[0];
    int i;

    if (*p) return(0);

    for (i = 0 ; i < MESSAGE_UUID_SIZE ; i++) {
        if (*p) {
            syslog(LOG_WARNING, "Invalid NULL UUID: not completely zero");
            break;
        }
        p++;
    }
    return(1);
}

/* Routines for manipulating packed values */

/* message_uuid_pack() ***************************************************
 *
 * Store Message UID as packed sequence (MESSAGE_UUID_PACKED_SIZE)
 * (Wrapper for memcpy() with current implementation)
 *
 ************************************************************************/

int
message_uuid_pack(struct message_uuid *uuid, char *packed)
{
    assert(MESSAGE_UUID_SIZE == MESSAGE_UUID_PACKED_SIZE);

    memcpy(packed, &uuid->value[0], MESSAGE_UUID_SIZE);
    return(1);
}
  /* Store Message UID as packed sequence (MESSAGE_UUID_PACKED_SIZE)
   * (Wrapper for memcpy() with current implementation) */

/* message_uuid_unpack() *************************************************
 *
 * Fetch Message UID from packed sequence (MESSAGE_UUID_PACKED_SIZE)
 * (Wrapper for memcpy() with current implementation)
 *
 ************************************************************************/

int
message_uuid_unpack(struct message_uuid *uuid, const char *packed)
{
    assert(MESSAGE_UUID_SIZE == MESSAGE_UUID_PACKED_SIZE);

    memcpy(&uuid->value[0], packed, MESSAGE_UUID_SIZE);
    return(1);
}

/* Routines for manipulating text value */

/* message_uuid_text() ***************************************************
 *
 * Returns ptr to '\0' terminated static char * which can be strdup()ed
 * NULL => error. Should be impossible as entire range covered
 *
 ************************************************************************/

char *
message_uuid_text(struct message_uuid *uuid)
{
    static char buf[MESSAGE_UUID_TEXT_SIZE+1];
    static char *hex = "0123456789abcdef";
    unsigned char *value = &uuid->value[0];
    char *p = buf;
    int i;

    for (i = 0 ; i < MESSAGE_UUID_SIZE ; i++) {
        *p++ = hex[(value[i] & 0xf0) >> 4];
        *p++ = hex[value[i]  & 0x0f];
    }
    *p = '\0';

    return(buf);
}

/* message_uuid_from_text() **********************************************
 *
 * Sets Message UUID from text form. Returns 1 if valid
 * Returns: boolean success
 * 
 ************************************************************************/

int
message_uuid_from_text(struct message_uuid *uuid, const char *text)
{
    const char *p = text;
    char *buf = &uuid->value[0];
    int i;

    for (i = 0 ; i < MESSAGE_UUID_SIZE ; i++) {
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

/* message_uuid_text_valid() *********************************************
 *
 * Returns 1 if test valid format for Message UUID
 *
 ************************************************************************/

int
message_uuid_text_valid(const char *p)
{
    int i;

    for (i = 0 ; i < MESSAGE_UUID_TEXT_SIZE ; i++) {
        if (!isxdigit(*p)) return(0);
        p++;
    }
    return((*p == '\0') ? 1 : 0);
}

/* message_uuid_text_isnull() *******************************************
 *
 * Returns 1 if Textual UUID is NULL value.
 *
 ************************************************************************/

int
message_uuid_text_isnull(const char *p)
{
    int i;

    if ((p[0] != '0') || (p[1] != '0')) return(0);

    for (i = 0; i < MESSAGE_UUID_TEXT_SIZE; i++) {
        if (p[i] != '0') {
            syslog(LOG_WARNING, "Invalid NULL message UUID: %s", p);
            return(1);
        }
    }
    if (p[MESSAGE_UUID_TEXT_SIZE] != '\0')
        syslog(LOG_WARNING, "Invalid NULL message UUID: incorrect length");

    return(1);
}
