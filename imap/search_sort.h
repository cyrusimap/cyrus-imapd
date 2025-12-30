/* search_sort.h -- Sort criteria definition for search */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef __CYRUS_SEARCH_SORT_H__
#define __CYRUS_SEARCH_SORT_H__

/* Sort criterion */
struct sortcrit {
    unsigned key;               /* sort key */
    int flags;                  /* key modifiers as defined below */
    union {                     /* argument(s) to the sort key */
        struct {
            char *entry;
            char *userid;
        } annot;
        struct {
            char *name;
        } flag;
        struct {
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
#define SORT_REVERSE            (1<<0)      /* RFC 5256 */


#endif /* __CYRUS_SEARCH_SORT_H__ */
