/* bytecode.h -- bytecode definition
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

#ifndef SIEVE_BYTECODE_H
#define SIEVE_BYTECODE_H

#include <stddef.h>

/* for debugging*/
#define DUMPCODE 0
#define VERBOSE 0

/*for finding correctly aligned bytes on strings*/
/* bump to the next multiple of 4 bytes */
#define ROUNDUP(num) (((num) + 3) & 0xFFFFFFFC)


/* yes, lots of these are superfluous, it's for clarity */
typedef union
{
    int op; /* OPTYPE */
    int value;

    int jump;

    int listlen;

    /* store strings (need 2 consecutive bytecodes) */
    int len;
    char *str;
} bytecode_t;

struct bytecode_info
{
    bytecode_t *data;/* pointer to almost-flat bytecode */
    size_t scriptend; /* used by emit code to know final length of bytecode */
    size_t reallen; /* allocated length of 'data' */
};

/* For sanity during input on 64-bit platforms.
 * str should only be accessed as (char *)&str, but given the use of
 * unwrap_string, this should be OK */
typedef union
{
    int op; /* OPTYPE */
    int value;

    int jump;

    int listlen;

    /* store strings (need 2 consecutive bytecodes) */
    int len;
    int str;
} bytecode_input_t;


/* version 0x01 scripts were written in host byte order.
 * we don't want to use this version number again and cause a mess
 * this isn't a huge concern, since this is version ntohl(1), or 16777216
 *
 * version 0x02 scripts started using network byte order (recompile)
 * version 0x03 scripts implemented short-circuiting of testlists (recompile)
 * version 0x04 scripts implemented BODY, INCLUDE and COPY extensions
 * version 0x05 scripts implemented updated VACATION (:from and :handle)
 * version 0x06 scripts implemented updated VACATION (:seconds)
 * version 0x07 scripts implemented updated INCLUDE (:once and :optional)
 * version 0x08 scripts implemented DATE and INDEX extensions
 * version 0x09 scripts implemented IMAP4FLAGS extension
 * version 0x10 scripts implemented Mailbox and Metadata (RFC5490)
 * version 0x11 scripts implemented Variables (RFC5229), eReject (RFC5429),
 *                                  and External Lists (RFC 6134)
 */
#define BYTECODE_VERSION 0x11
#define BYTECODE_MIN_VERSION 0x03 /* minimum supported version */
#define BYTECODE_MAGIC "CyrSBytecode"
#define BYTECODE_MAGIC_LEN 12 /* Should be multiple of 4 */

/* IMPORTANT: To maintain forward compatibility of bytecode, please only add
 * new instructions to the end of these enums.  (The reason these values
 * are all duplicated here is to avoid silliness if this caveat is forgotten
 * about in the other tables.) */
enum bytecode {
    B_STOP,

    B_KEEP_ORIG,        /* legacy keep w/o support for :copy and :flags */
    B_DISCARD,
    B_REJECT,           /* require reject */
    B_FILEINTO_ORIG,    /* legacy fileinto w/o support for :copy */
    B_REDIRECT_ORIG,    /* legacy redirect w/o support for :copy */

    B_IF,

    B_MARK,             /* require imapflags */
    B_UNMARK,           /* require imapflags */

    B_ADDFLAG_ORIG,	/* legacy addflag w/o support for variables */
    B_SETFLAG_ORIG,	/* legacy setflag w/o support for variables */
    B_REMOVEFLAG_ORIG,	/* legacy removeflag w/o support for variables */

    B_NOTIFY,           /* require notify */
    B_DENOTIFY,         /* require notify */

    B_VACATION_ORIG,    /* legacy vacation w/o support for :seconds */
    B_NULL,
    B_JUMP,

    B_INCLUDE,          /* require include */
    B_RETURN,           /* require include */

    B_FILEINTO_COPY,    /* legacy fileinto w/o support for :flags */
    B_REDIRECT_COPY,    /* legacy redirect w/o support for :list */

    B_VACATION,         /* require vacation */

    B_KEEP,
    B_FILEINTO_FLAGS,   /* legacy fileinto w/o support for :create */
    B_FILEINTO,         /* require mailbox, imap4flags, copy */

    B_SET,              /* require variables */

    B_ADDFLAG,          /* require imap4flags */
    B_SETFLAG,          /* require imap4flags */
    B_REMOVEFLAG,       /* require imap4flags */

    B_ADDHEADER,        /* require editheader */
    B_DELETEHEADER,     /* require editheader */

    B_EREJECT,          /* require ereject */

    B_REDIRECT
};

enum bytecode_comps {
    BC_FALSE,
    BC_TRUE,
    BC_NOT,
    BC_EXISTS,
    BC_SIZE,
    BC_ANYOF,
    BC_ALLOF,
    BC_ADDRESS_PRE_INDEX,
    BC_ENVELOPE,        /* require envelope */
    BC_HEADER_PRE_INDEX,
    BC_BODY,            /* require body */
    BC_DATE,            /* require date */
    BC_CURRENTDATE,     /* require date */
    BC_ADDRESS,
    BC_HEADER,
    BC_HASFLAG,         /* require imap4flags */
    BC_MAILBOXEXISTS,   /* require mailbox */
    BC_METADATA,        /* require mboxmetadata */
    BC_METADATAEXISTS,
    BC_SERVERMETADATA,  /* require servermetadata */
    BC_SERVERMETADATAEXISTS,
    BC_STRING,          /* require variables */
    BC_VALIDEXTLIST     /* require extlists */
};

/* currently one enum so as to help determine where values are being misused.
 * we have left placeholders incase we need to add more later to the middle */
enum bytecode_tags {
    /* Size Tests (0-3) */
    B_OVER,
    B_UNDER,

    B_SIZE_PLACEHOLDER_1,
    B_SIZE_PLACEHOLDER_2,

    /* Relational Match Types (4-11) */
    B_GT,               /* require relational */
    B_GE,               /* require relational */
    B_LT,               /* require relational */
    B_LE,               /* require relational */
    B_EQ,               /* require relational */
    B_NE,               /* require relational */

    B_RELATIONAL_PLACEHOLDER_1,
    B_RELATIONAL_PLACEHOLDER_2,

    /* Priorities (12-19) */
    B_LOW,              /* require notify */
    B_NORMAL,           /* require notify */
    B_HIGH,             /* require notify */
    B_ANY,              /* require notify */

    B_PRIORITY_PLACEHOLDER_1,
    B_PRIORITY_PLACEHOLDER_2,
    B_PRIORITY_PLACEHOLDER_3,
    B_PRIORITY_PLACEHOLDER_4,

    /* Address Parts (20-28) */
    B_ALL,
    B_LOCALPART,
    B_DOMAIN,
    B_USER,             /* require subaddress */
    B_DETAIL,           /* require subaddress */

    B_ADDRESS_PLACEHOLDER_1,
    B_ADDRESS_PLACEHOLDER_2,
    B_ADDRESS_PLACEHOLDER_3,
    B_ADDRESS_PLACEHOLDER_4,

    /* Comparators (29-35) */
    B_ASCIICASEMAP,
    B_OCTET,
    B_ASCIINUMERIC,     /* require comparator-i;ascii-numeric */

    B_COMPARATOR_PLACEHOLDER_1,
    B_COMPARATOR_PLACEHOLDER_2,
    B_COMPARATOR_PLACEHOLDER_3,
    B_COMPARATOR_PLACEHOLDER_4,

    /* Match Types (36-45) */
    B_IS,
    B_CONTAINS,
    B_MATCHES,
    B_REGEX,            /* require regex */
    B_COUNT,            /* require relational */
    B_VALUE,            /* require relational */
    B_LIST,             /* require extlists */

    B_MATCH_PLACEHOLDER_1,
    B_MATCH_PLACEHOLDER_2,
    B_MATCH_PLACEHOLDER_3,

    /* Body Transforms (46-53) */
    B_RAW,              /* require body */
    B_TEXT,             /* require body */
    B_CONTENT,          /* require body */

    B_TRANSFORM_PLACEHOLDER_1,
    B_TRANSFORM_PLACEHOLDER_2,
    B_TRANSFORM_PLACEHOLDER_3,
    B_TRANSFORM_PLACEHOLDER_4,
    B_TRANSFORM_PLACEHOLDER_5,

    /* Script locations (54-59) */
    B_PERSONAL,         /* require include */
    B_GLOBAL,           /* require include */

    B_LOCATION_PLACEHOLDER_1,
    B_LOCATION_PLACEHOLDER_2,
    B_LOCATION_PLACEHOLDER_3,
    B_LOCATION_PLACEHOLDER_4,

    /* Zones (60-63) */
    B_TIMEZONE,
    B_ORIGINALZONE,

    B_ZONE_PLACEHOLDER_1,
    B_ZONE_PLACEHOLDER_2,

    /* Date Parts (64-80) */
    B_YEAR,
    B_MONTH,
    B_DAY,
    B_DATE,
    B_JULIAN,
    B_HOUR,
    B_MINUTE,
    B_SECOND,
    B_TIME,
    B_ISO8601,
    B_STD11,
    B_ZONE,
    B_WEEKDAY,

    B_DATEPART_PLACEHOLDER_1,
    B_DATEPART_PLACEHOLDER_2,
    B_DATEPART_PLACEHOLDER_3,
    B_DATEPART_PLACEHOLDER_4
};

enum bytecode_variables_bitflags {
    BFV_LOWER	        = 1<<0,
    BFV_UPPER	        = 1<<1,
    BFV_LOWERFIRST      = 1<<2,
    BFV_UPPERFIRST      = 1<<3,
    BFV_QUOTEWILDCARD   = 1<<4,
    BFV_ENCODEURL	= 1<<5,
    BFV_LENGTH		= 1<<6
};

enum bytecode_required_extensions {
    BFE_VARIABLES       = 1<<0
};

#endif
