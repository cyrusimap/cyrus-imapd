/* imapd.h -- Common state for IMAP daemon
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

#ifndef INCLUDED_IMAPD_H
#define INCLUDED_IMAPD_H

#include "annotate.h"
#include "bufarray.h"
#include "hash.h"
#include "imparse.h"
#include "mailbox.h"
#include "message.h"
#include "prot.h"
#include "strarray.h"
#include "search_expr.h"
#include "search_sort.h"
#include "conversations.h"

/* Userid client has logged in as */
extern char *imapd_userid;

/* Authorization state for logged in userid */
extern struct auth_state *imapd_authstate;

struct octetinfo
{
    int start_octet;
    int octet_count;
};

struct section {
    char *name;
    struct octetinfo octetinfo;
    struct section *next;
};

/* List of HEADER.FIELDS[.NOT] fetch specifications */
struct fieldlist {
    char *section;              /* First part of BODY[x] value */
    strarray_t *fields;         /* Array of field-names */
    char *trail;                /* Last part of BODY[x] value */
    void *rock;
    struct fieldlist *next;
};

/* Items that may be fetched */
struct fetchargs {
    int fetchitems;               /* Bitmask */
    struct section *binsections;  /* BINARY[x]<x> values */
    struct section *sizesections; /* BINARY.SIZE[x] values */
    struct section *bodysections; /* BODY[x]<x> values */
    struct fieldlist *fsections;  /* BODY[xHEADER.FIELDSx]<x> values */
    strarray_t headers;           /* RFC822.HEADER.LINES */
    strarray_t headers_not;       /* RFC822.HEADER.LINES.NOT */
    int start_octet;              /* start_octet for partial fetch */
    int octet_count;              /* octet_count for partial fetch, or 0 */
    modseq_t changedsince;        /* changed since modseq, or 0 */
    int vanished;                 /* report expunges since changedsince */
    const char *match_seq;
    const char *match_uid;        /* sequence match data for VANISHED */

    bit32 cache_atleast;          /* to do headers we need atleast this
                                   * cache version */
    struct namespace *namespace;
    const char *userid;
    strarray_t entries;           /* for FETCH_ANNOTATION */
    strarray_t attribs;
    int isadmin;
    struct auth_state *authstate;
    struct conversations_state *convstate; /* for FETCH_MAILBOXIDS */

    range_t partial;              /* For PARTIAL */
};

/* Bitmasks for fetchitems */
enum {
    FETCH_UID =                 (1<<0),
    FETCH_INTERNALDATE =        (1<<1),
    FETCH_SIZE =                (1<<2),
    FETCH_FLAGS =               (1<<3),
    FETCH_ENVELOPE =            (1<<4),
    FETCH_BODYSTRUCTURE =       (1<<5),
    FETCH_BODY =                (1<<6),
    FETCH_HEADER =              (1<<7),
    FETCH_TEXT =                (1<<8),
    FETCH_RFC822 =              (1<<9),
    FETCH_SETSEEN =             (1<<10),
/*     FETCH_UNCACHEDHEADER =      (1<<11) -- obsolete */
    FETCH_IS_PARTIAL =          (1<<12), /* this is the PARTIAL command */
    FETCH_MODSEQ =              (1<<13),
    FETCH_ANNOTATION =          (1<<14),
    FETCH_GUID   =              (1<<15),
    FETCH_SHA1   =              (1<<16),
    FETCH_FILESIZE =            (1<<17),
    FETCH_CID =                 (1<<18),
    FETCH_FOLDER =              (1<<19),
    FETCH_UIDVALIDITY =         (1<<20),
    FETCH_BASECID =             (1<<21),
    FETCH_EMAILID =             (1<<22),
    FETCH_THREADID =            (1<<23),
    FETCH_SAVEDATE =            (1<<24),
    FETCH_CREATEDMODSEQ =       (1<<25),
    FETCH_MAILBOXIDS =          (1<<26),
    FETCH_MAILBOXES =           (1<<27),
    FETCH_PREVIEW =             (1<<28),
    FETCH_LASTUPDATED =         (1<<29),

    /* XXX fetchitems is an int, we're running low on bits */
};

enum {
    FETCH_FAST = (FETCH_FLAGS|FETCH_INTERNALDATE|FETCH_SIZE),
    FETCH_ALL = (FETCH_FLAGS|FETCH_INTERNALDATE|FETCH_SIZE|FETCH_ENVELOPE),
    FETCH_FULL = (FETCH_ALL|FETCH_BODY)
};

/* Arguments to Store functions */
struct storeargs {
    int operation;
    int usinguid;
    modseq_t unchangedsince; /* unchanged since modseq, or ULLONG_MAX */
    int silent;
    int seen;
    /* for STORE_*_FLAGS */
    uint32_t system_flags;
    /* Note that we must pass the user flags as names because the
     * lookup of user flag names must proceed under the index lock */
    strarray_t flags;
    /* for STORE_ANNOTATION */
    struct entryattlist *entryatts;
    struct namespace *namespace;
    int isadmin;
    const char *userid;
    struct auth_state *authstate;
    /* private to index.c */
    bit32 user_flags[MAX_USER_FLAGS/32];
    time_t update_time;
    /* private to index_storeflag() */
    unsigned last_msgno;
    unsigned last_found;
    /* returned to caller */
    seqset_t *modified;
};

/* values for operation */
enum {
    STORE_ADD_FLAGS = 1,
    STORE_REMOVE_FLAGS,
    STORE_REPLACE_FLAGS,
    STORE_ANNOTATION
};

struct searchannot {
    struct searchannot *next;       /* gnb:TODO remove */
    char *entry;
    char *attrib;
    struct namespace *namespace;    /* gnb:TODO get this from searchargs */
    int isadmin;                    /* gnb:TODO get this from searchargs */
    const char *userid;             /* gnb:TODO get this from searchargs */
    struct auth_state *auth_state;  /* gnb:TODO get this from searchargs */
    struct buf value;
};

/* Flags for searchargs.state */
enum {
    GETSEARCH_CHARSET_KEYWORD = 0x01,
    GETSEARCH_RETURN = 0x02,
    GETSEARCH_CHARSET_FIRST = 0x04,
    GETSEARCH_SOURCE = 0x08,
    GETSEARCH_MODSEQ = 0x10,
};

/* Bitmasks for search source options (RFC 7377) */
enum {
    SEARCH_SOURCE_SELECTED    = (1<<0),
    SEARCH_SOURCE_PERSONAL    = (1<<1),
    SEARCH_SOURCE_INBOXES     = (1<<2),
    SEARCH_SOURCE_SUBSCRIBED  = (1<<3),
    SEARCH_SOURCE_SUBTREE     = (1<<4),
    SEARCH_SOURCE_SUBTREE_ONE = (1<<5),
    SEARCH_SOURCE_MAILBOXES   = (1<<6)
};

/* Bitmasks for search return options (RFC 4731) */
enum {
    SEARCH_RETURN_MIN =         (1<<0),
    SEARCH_RETURN_MAX =         (1<<1),
    SEARCH_RETURN_ALL =         (1<<2),
    SEARCH_RETURN_COUNT =       (1<<3),
    SEARCH_RETURN_SAVE =        (1<<4),  /* RFC 5182 */
    SEARCH_RETURN_RELEVANCY =   (1<<5),  /* RFC 6203 */
    SEARCH_RETURN_PARTIAL =     (1<<6),  /* RFC 9394 */
};

/* Things that may be searched for */
struct searchargs {
    struct search_expr *root;
    charset_t charset;
    int state;
    /* used only during parsing */
    int fuzzy_depth;
    uint64_t maxargssize_mark;
    unsigned did_objectid : 1;

    /* For ESEARCH */
    const char *tag;
    int returnopts;
    struct namespace *namespace;
    const char *userid;
    struct auth_state *authstate;
    int isadmin;

    /* For MULTISEARCH */
    struct {
        unsigned filter;
        strarray_t subtree;
        strarray_t subtree_one;
        strarray_t mailboxes;
    } multi;

    /* For SEARCHRES */
    ptrarray_t result_vars;

    /* For PARTIAL */
    struct {
        range_t range;
        uint32_t start_msgno; /* based on last PARTIAL of same search */
        uint32_t start_count; /* based on last PARTIAL of same search */
    } partial;
};

/* Bitmask for status queries (RFC 3501) */
enum {
    STATUS_MESSAGES =           (1<<0),
    STATUS_RECENT =             (1<<1),
    STATUS_UIDNEXT =            (1<<2),
    STATUS_UIDVALIDITY =        (1<<3),
    STATUS_UNSEEN =             (1<<4),
    STATUS_HIGHESTMODSEQ =      (1<<5),  /* RFC 7162 */
    STATUS_APPENDLIMIT =        (1<<6),  /* RFC 7889 */
    STATUS_SIZE =               (1<<7),  /* RFC 8438 */
    STATUS_MAILBOXID =          (1<<8),  /* RFC 8474 */
    STATUS_DELETED =            (1<<9),  /* RFC 9051 */
    STATUS_DELETED_STORAGE =    (1<<10), /* RFC 9208 */

    /* Non-standard */
    STATUS_CREATEDMODSEQ =      (1<<14),
    STATUS_MBOPTIONS =          (1<<15)
    /* New items MUST be handled in imapd.c:list_data_remote() */
};

#define STATUS_MBENTRYITEMS (STATUS_MAILBOXID|STATUS_UIDVALIDITY)
#define STATUS_INDEXITEMS (STATUS_MESSAGES|STATUS_UIDNEXT|STATUS_SIZE|STATUS_HIGHESTMODSEQ|STATUS_CREATEDMODSEQ|STATUS_MBOPTIONS|STATUS_DELETED|STATUS_DELETED_STORAGE)
#define STATUS_SEENITEMS (STATUS_RECENT|STATUS_UNSEEN)

struct getmetadata_options {
    size_t biggest;
    size_t maxsize;
    int depth;
    char *lastname;
    bufarray_t items;
};

#define OPTS_INITIALIZER { 0, 0, 0, NULL, BUFARRAY_INITIALIZER }

/* Arguments to List functions */
struct listargs {
    unsigned cmd;               /* Command variant */
    unsigned sel;               /* Selection options */
    unsigned ret;               /* Return options */
    const char *ref;            /* Reference name */
    strarray_t pat;             /* Mailbox pattern(s) */
    unsigned statusitems;       /* for RETURN STATUS */
    struct getmetadata_options metaopts; /* for RETURN METADATA */
    strarray_t metaitems;       /* for RETURN METADATA */
    const char *denormalized;   /* for IMAP4rev2 OLDNAME -
                                   Denormalized UTF-8 mailbox name from
                                   SELECT/EXAMINE/CREATE/DELETE/RENAME/APPEND */
};

/* Value for List command variant */
enum {
    LIST_CMD_LIST = 0,
    LIST_CMD_LSUB,
    LIST_CMD_EXTENDED,
    LIST_CMD_XLIST,
};

/* Bitmask for List selection options (RFC 5258) */
enum {
    LIST_SEL_SUBSCRIBED =       (1<<0),
    LIST_SEL_REMOTE =           (1<<1),
    LIST_SEL_RECURSIVEMATCH =   (1<<2),
    LIST_SEL_SPECIALUSE =       (1<<3),  /* RFC 6154 */

    /* Non-standard */
    LIST_SEL_DAV =              (1<<12),
    LIST_SEL_METADATA =         (1<<13),
    LIST_SEL_INTERMEDIATES =    (1<<14),
    LIST_SEL_DELETED =          (1<<15)
    /* New options MUST be handled in imapd.c:list_data_remote() */
};

/* Bitmask for List return options (RFC 5258) */
enum {
    LIST_RET_SUBSCRIBED =       (1<<0),
    LIST_RET_CHILDREN =         (1<<1),
    LIST_RET_SPECIALUSE =       (1<<2),  /* RFC 6154 */
    LIST_RET_STATUS =           (1<<3),  /* RFC 5819 */
    LIST_RET_MYRIGHTS =         (1<<4),  /* RFC 8440 */
    LIST_RET_METADATA =         (1<<5)   /* RFC 9590 */
    /* New options MUST be handled in imapd.c:list_data_remote() */
};

/* Bitmask for List name attributes */
enum {
    /* from RFC 3501 */
    MBOX_ATTRIBUTE_NOINFERIORS =        (1<<0),
    MBOX_ATTRIBUTE_NOSELECT =           (1<<1),
    MBOX_ATTRIBUTE_MARKED =             (1<<2),
    MBOX_ATTRIBUTE_UNMARKED =           (1<<3),

    /* from RFC 5258 */
    MBOX_ATTRIBUTE_NONEXISTENT =        (1<<4),
    MBOX_ATTRIBUTE_SUBSCRIBED =         (1<<5),
    MBOX_ATTRIBUTE_REMOTE =             (1<<6),
    MBOX_ATTRIBUTE_HASCHILDREN =        (1<<7),
    MBOX_ATTRIBUTE_HASNOCHILDREN =      (1<<8),
    MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED=(1<<9),

    /* from RFC 5465 */
    MBOX_ATTRIBUTE_NOACCESS =           (1<<10),
};

#define MBOX_ATTRIBUTE_CHILDINFO_MASK   (MBOX_ATTRIBUTE_CHILDINFO_SUBSCRIBED)

struct mbox_name_attribute {
    uint32_t flag;   /* MBOX_ATTRIBUTE_* */
    const char *id;  /* string value */
};

extern const struct mbox_name_attribute mbox_name_attributes[];
extern const struct mbox_name_attribute mbox_name_childinfo[];

/* Bitmask for client capabilities */
enum {
    CAPA_CONDSTORE =    (1<<0),  /* RFC 7162 */
    CAPA_QRESYNC =      (1<<1),  /* RFC 7162 */
    CAPA_IMAP4REV2 =    (1<<2),  /* RFC 9051 */
    CAPA_UIDONLY =      (1<<3),  /* RFC 9586 */
    CAPA_UTF8_ACCEPT =  (1<<4),  /* RFC 6855 */
};

/* Bitmask for urlfetch params (RFC 5524) */
enum {
    URLFETCH_BODY =                     (1<<0),
    URLFETCH_BINARY =                   (1<<1),
    URLFETCH_BODYPARTSTRUCTURE =        (1<<2)
};

extern struct protstream *imapd_out, *imapd_in;

/* Bitmask for exhibited client behaviors */
enum {
    CB_BINARY      =  (1<<0),   /* FETCH BINARY or APPEND literal8       */
    CB_CATENATE    =  (1<<1),   /* CATENATE on APPEND                    */
    CB_COMPRESS    =  (1<<2),   /* COMPRESS                              */
    CB_CONDSTORE   =  (1<<3),   /* ENABLE CONSTORE/QRESYNC,
                                   CONDSTORE on SELECT, or
                                   UNCHANGEDSINCE on STORE               */
    CB_IDLE        =  (1<<4),   /* IDLE                                  */
    CB_IMAP4REV2   =  (1<<5),   /* ENABLE IMAP4rev2                      */
    CB_METADATA    =  (1<<6),   /* GET/SETMETADATA                       */
    CB_MOVE        =  (1<<7),   /* MOVE                                  */
    CB_MULTISEARCH =  (1<<8),   /* ESEARCH                               */
    CB_NOTIFY      =  (1<<9),   /* NOTIFY                                */
    CB_OBJECTID    =  (1<<10),  /* STATUS MAILBOXID or
                                   SEARCH/FETCH EMAILID/THREADID         */
    CB_PARTIAL     =  (1<<11),  /* SEARCH/FETCH PARTIAL                  */
    CB_PREVIEW     =  (1<<12),  /* FETCH PREVIEW                         */
    CB_QRESYNC     =  (1<<13),  /* ENABLE QRESYNC or QRESYNC on SELECT   */
    CB_REPLACE     =  (1<<14),  /* REPLACE                               */
    CB_SAVEDATE    =  (1<<15),  /* FETCH SAVEDATE                        */
    CB_SEARCHRES   =  (1<<16),  /* SAVE on SEARCH                        */
    CB_UIDBATCHES  =  (1<<20),  /* UIDBATCHES                            */
    CB_UIDONLY     =  (1<<17),  /* ENABLE UIDONLY                        */
    CB_UNSELECT    =  (1<<18),  /* UNSELECT                              */
    CB_UTF8ACCEPT  =  (1<<19),  /* ENABLE UTF8=ACCEPT                    */

    /* non-standard - track for possible deprecation                     */
    CB_ANNOTATE    =  (1<<30),  /* GET/SETANNOTATION or FETCH ANNOTATION */
    CB_XLIST       =  (1U<<31), /* XLIST                                 */
};

#endif /* INCLUDED_IMAPD_H */
