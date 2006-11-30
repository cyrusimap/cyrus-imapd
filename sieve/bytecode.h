/* bytecode.h -- bytecode definition
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*****************************************************************/

#ifndef SIEVE_BYTECODE_H
#define SIEVE_BYTECODE_H


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
 */
#define BYTECODE_VERSION 0x05
#define BYTECODE_MIN_VERSION 0x03 /* minimum supported version */
#define BYTECODE_MAGIC "CyrSBytecode"
#define BYTECODE_MAGIC_LEN 12 /* Should be multiple of 4 */

/* IMPORTANT: To maintain forward compatibility of bytecode, please only add
 * new instructions to the end of these enums.  (The reason these values
 * are all duplicated here is to avoid silliness if this caveat is forgotten
 * about in the other tables.) */
enum bytecode {
    B_STOP,

    B_KEEP,
    B_DISCARD,
    B_REJECT,		/* require reject */
    B_FILEINTO_ORIG,	/* legacy fileinto w/o support for :copy */
    B_REDIRECT_ORIG,	/* legacy redirect w/o support for :copy */

    B_IF,
  
    B_MARK,		/* require imapflags */
    B_UNMARK,		/* require imapflags */

    B_ADDFLAG,		/* require imapflags */
    B_SETFLAG,		/* require imapflags */
    B_REMOVEFLAG,	/* require imapflags */

    B_NOTIFY,		/* require notify */
    B_DENOTIFY,		/* require notify */

    B_VACATION,		/* require vacation */
    B_NULL,
    B_JUMP,

    B_INCLUDE,		/* require include */
    B_RETURN,		/* require include */

    B_FILEINTO,		/* require fileinto */
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
    BC_ADDRESS,
    BC_ENVELOPE,	/* require envelope */
    BC_HEADER,
    BC_BODY		/* require body */
};

/* currently one enum so as to help determine where values are being misused.
 * we have left placeholders incase we need to add more later to the middle */
enum bytecode_tags {
    /* Size Tests */
    B_OVER,
    B_UNDER,

    B_SIZE_PLACEHOLDER_1,
    B_SIZE_PLACEHOLDER_2,
     
    /* Relational Match Types */
    B_GT,		/* require relational */
    B_GE,		/* require relational */
    B_LT,		/* require relational */
    B_LE,		/* require relational */
    B_EQ,		/* require relational */
    B_NE,		/* require relational */
 
    B_RELATIONAL_PLACEHOLDER_1,
    B_RELATIONAL_PLACEHOLDER_2,
   
    /* Priorities */
    B_LOW,		/* require notify */
    B_NORMAL,		/* require notify */
    B_HIGH,		/* require notify */
    B_ANY,		/* require notify */

    B_PRIORITY_PLACEHOLDER_1,
    B_PRIORITY_PLACEHOLDER_2,
    B_PRIORITY_PLACEHOLDER_3,
    B_PRIORITY_PLACEHOLDER_4,
    
    /* Address Parts */
    B_ALL,
    B_LOCALPART,
    B_DOMAIN,
    B_USER,		/* require subaddress */
    B_DETAIL,		/* require subaddress */
    
    B_ADDRESS_PLACEHOLDER_1,
    B_ADDRESS_PLACEHOLDER_2,
    B_ADDRESS_PLACEHOLDER_3,
    B_ADDRESS_PLACEHOLDER_4,

    /* Comparators */
    B_ASCIICASEMAP,
    B_OCTET,
    B_ASCIINUMERIC,	/* require comparator-i;ascii-numeric */
    
    B_COMPARATOR_PLACEHOLDER_1,
    B_COMPARATOR_PLACEHOLDER_2,
    B_COMPARATOR_PLACEHOLDER_3,
    B_COMPARATOR_PLACEHOLDER_4,
 
    /* Match Types */
    B_IS,
    B_CONTAINS,
    B_MATCHES,
    B_REGEX,		/* require regex */
    B_COUNT,		/* require relational */
    B_VALUE,		/* require relational */

    B_MATCH_PLACEHOLDER_1,
    B_MATCH_PLACEHOLDER_2,
    B_MATCH_PLACEHOLDER_3,
    B_MATCH_PLACEHOLDER_4,

    /* Body Transforms */
    B_RAW,		/* require body */
    B_TEXT,		/* require body */
    B_CONTENT,		/* require body */

    B_TRANSFORM_PLACEHOLDER_1,
    B_TRANSFORM_PLACEHOLDER_2,
    B_TRANSFORM_PLACEHOLDER_3,
    B_TRANSFORM_PLACEHOLDER_4,
    B_TRANSFORM_PLACEHOLDER_5,

    /* Script locations */
    B_PERSONAL,		/* require include */
    B_GLOBAL,		/* require include */

    B_LOCATION_PLACEHOLDER_1,
    B_LOCATION_PLACEHOLDER_2,
    B_LOCATION_PLACEHOLDER_3,
    B_LOCATION_PLACEHOLDER_4
  
};

#endif
