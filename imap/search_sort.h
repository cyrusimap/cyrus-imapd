/* search_sort.h --  Sort criteria definition for search
 *
 * Copyright (c) 1994-2020 Carnegie Mellon University.  All rights reserved.
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

#ifndef __CYRUS_SEARCH_SORT_H__
#define __CYRUS_SEARCH_SORT_H__

/* Sort criterion */
struct sortcrit
{
    unsigned key; /* sort key */
    int flags;    /* key modifiers as defined below */
    union {       /* argument(s) to the sort key */
        struct
        {
            char *entry;
            char *userid;
        } annot;
        struct
        {
            char *name;
        } flag;
        struct
        {
            char *id;
        } mailbox;
    } args;
};

/* Values for sort keys */
enum {
    SORT_SEQUENCE = 0,
    SORT_ARRIVAL,       /* RFC 5256 */
    SORT_CC,            /* RFC 5256 */
    SORT_DATE,          /* RFC 5256 */
    SORT_DISPLAYFROM,   /* RFC 5957 */
    SORT_DISPLAYTO,     /* RFC 5957 */
    SORT_FROM,          /* RFC 5256 */
    SORT_SIZE,          /* RFC 5256 */
    SORT_SUBJECT,       /* RFC 5256 */
    SORT_TO,            /* RFC 5256 */
    SORT_ANNOTATION,    /* RFC 5257 */
    SORT_MODSEQ,        /* nonstandard */
    SORT_UID,           /* nonstandard */
    SORT_HASFLAG,       /* nonstandard */
    SORT_CONVMODSEQ,    /* nonstandard */
    SORT_CONVEXISTS,    /* nonstandard */
    SORT_CONVSIZE,      /* nonstandard */
    SORT_HASCONVFLAG,   /* nonstandard */
    SORT_FOLDER,        /* nonstandard */
    SORT_RELEVANCY,     /* RFC 6203 */
    SORT_SPAMSCORE,     /* nonstandard */
    SORT_GUID,          /* nonstandard */
    SORT_EMAILID,       /* nonstandard */
    SORT_THREADID,      /* nonstandard */
    SORT_SAVEDATE,      /* nonstandard */
    SORT_SNOOZEDUNTIL,  /* nonstandard */
    SORT_CREATEDMODSEQ, /* nonstandard */
    /* values > 255 are reserved for internal use */
};

/* Sort key modifier flag bits */
#define SORT_REVERSE (1 << 0) /* RFC 5256 */

#endif /* __CYRUS_SEARCH_SORT_H__ */
