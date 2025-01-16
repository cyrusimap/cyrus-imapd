/* index.h -- Routines for dealing with the index file in the imapd
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

/* Header for internal usage of index.c + programs that make raw access
 * to index files */

#ifndef INDEX_H
#define INDEX_H

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>

#include "annotate.h" /* for strlist functionality */
#include "search_engines.h"
#include "message_guid.h"
#include "seqset.h"
#include "strarray.h"

/* Special "sort criteria" to load message-id and references/in-reply-to
 * into msgdata array for threaders that need them.
 */
#define LOAD_IDS        256

/* client capabilities by ENABLE command */
extern unsigned client_capa;

struct message;

struct vanished_params {
    uint32_t uidvalidity;
    modseq_t modseq;
    const char *match_seq;
    const char *match_uid;
    const char *sequence;
    int uidvalidity_is_max;
};

struct index_init {
    const char *userid;
    struct auth_state *authstate;
    struct protstream *out;
    int examine_mode;
    int select;
    int want_dav;
    uint32_t want_mbtype;
    int want_expunged;
    struct vanished_params vanished;
    seqset_t *vanishedlist;
};

struct index_map {
    modseq_t modseq;
    modseq_t told_modseq;
    uint64_t cache_offset;
    uint32_t user_flags[MAX_USER_FLAGS/32];
    uint32_t uid;
    uint32_t recno;
    uint32_t system_flags;
    uint32_t internal_flags;
    unsigned int isseen:1;
    unsigned int isrecent:1;
};

struct index_state {
    struct mailbox *mailbox;
    unsigned num_records;
    unsigned oldexists;
    unsigned exists;
    unsigned long last_uid;
    uint32_t generation; /* to notice repacks */
    uint32_t uidvalidity; /* to notice delete/recreate */
    modseq_t oldhighestmodseq;
    modseq_t highestmodseq;
    modseq_t delayed_modseq;
    struct index_map *map;
    unsigned mapsize;
    int internalseen;
    int skipped_expunge;
    int seen_dirty;
    int examining;
    int myrights;
    unsigned numrecent;
    unsigned numunseen;
    unsigned firstnotseen;
    char *flagname[MAX_USER_FLAGS];
    char *userid;
    char *mboxname;
    char *mboxid;
    struct protstream *out;
    struct auth_state *authstate;
    int want_dav;
    uint32_t want_mbtype;
    int want_expunged;
    unsigned num_expunged;
    message_t *m;
    seqset_t *searchres; /* RFC 5182 SEARCH results */
    struct {             /* RFC 9394 last SEARCH PARTIAL (to inform next one) */
        char *expr;
        range_t range;
        uint32_t last_match;
        uint64_t highestmodseq; /* of the folder */
    } last_partial;
};

struct copyargs {
    struct index_record *records;
    int nummsg;
    int msgalloc;
};

typedef struct msgdata {
    struct search_folder *folder; /* search folder (can be NULL) */

    /* items from the index_record */
    bit32 uid;                  /* UID for output purposes */
    uint32_t msgno;             /* message number */
    conversation_id_t cid;      /* conversation id */
    strarray_t ref;             /* array of references */
    time_t sentdate;            /* sent date & time of message
                                   from Date: header (adjusted by time zone) */
    struct timespec internaldate;/* internaldate */
    time_t savedate;            /* savedate */
    size_t size;                /* message size */
    modseq_t modseq;            /* modseq of record*/
    modseq_t createdmodseq;     /* createdmodseq of record*/
    bit32 hasflag;              /* hasflag values (up to 32 of them) */
    struct message_guid guid;   /* message guid */
    uint32_t system_flags;      /* system flags */
    uint32_t internal_flags;    /* internal flags */

    /* items from the conversations database */
    modseq_t convmodseq;        /* modseq of conversation */
    uint32_t convexists;        /* exists count of conversation */
    uint32_t convsize;          /* total size of messages in conversation */

    uint32_t spamscore;         /* x-spam-score header */

    /* items from the cache record */
    char *msgid;                /* message ID */
    char *listid;               /* List-Id and Mailing-List fields */
    char *contenttype;          /* all MIME Content-Types except multipart */
    char *cc;                   /* local-part of first "cc" address */
    char *from;                 /* local-part of first "from" address */
    char *to;                   /* local-part of first "to" address */
    char *displayfrom;          /* display-name of first "from" address */
    char *displayto;            /* display-name of first "to" address */
    char *xsubj;                /* extracted subject text */
    unsigned xsubj_hash;        /* hash of extracted subject text */
    int is_refwd;               /* is message a reply or forward? */

    /* items from the annotations database */
    strarray_t annot;           /* array of annotation attribute values
                                   (stored in order of sortcrit) */
} MsgData;

typedef struct thread {
    MsgData *msgdata;           /* message data */
    struct thread *parent;      /* parent message */
    struct thread *child;       /* first child message */
    struct thread *next;        /* next sibling message */
} Thread;

struct rootset {
    Thread *root;
    unsigned nroot;
};

struct thread_algorithm {
    const char *alg_name;
    void (*threader)(struct index_state *state, unsigned *msgno_list,
                     unsigned int nmsg, int usinguid);
};

struct nntp_overview {
    unsigned long uid;
    char *subj;
    char *from;
    char *date;
    char *msgid;
    char *ref;
    unsigned long bytes;
    unsigned long lines;
};

enum index_warmup_flags
{
    WARMUP_INDEX            = (1<<0),
    WARMUP_CONVERSATIONS    = (1<<1),
    WARMUP_ANNOTATIONS      = (1<<2),
    WARMUP_SEARCH           = (1<<3),
    WARMUP_ALL              = (~WARMUP_SEARCH)
};

enum index_changes_flags
{
    TELL_UID                = (1<<0),
    TELL_MODSEQ             = (1<<1),
    TELL_EXPUNGED           = (1<<2),
    TELL_SILENT             = (1<<3),
};

struct progress_rock {
    void (*cb)(unsigned count, unsigned total, void *rock);
    const char *tag;
    time_t last_resp;
    unsigned no_count : 1;
};

/* non-locking, non-updating - just do a fetch on the state
 * we already have */
int index_fetchresponses(struct index_state *state,
                         seqset_t *seq,
                         int usinguid,
                         const struct fetchargs *fetchargs,
                         int *fetchedsomething);
extern int index_fetch(struct index_state *state,
                       const char* sequence,
                       int usinguid,
                       const struct fetchargs* fetchargs,
                       int* fetchedsomething);
extern int index_store(struct index_state *state,
                       const char *sequence,
                       struct storeargs *storeargs);
extern int index_run_annotator(struct index_state *state,
                               const char *sequence, int usinguid,
                               struct namespace *namespace, int isadmin);
extern int index_warmup(struct mboxlist_entry *, unsigned int warmup_flags,
                        seqset_t *uids);
extern int index_sort(struct index_state *state, const struct sortcrit *sortcrit,
                      struct searchargs *searchargs, int usinguid,
                      struct progress_rock *prock);
extern int index_thread(struct index_state *state, int algorithm,
                        struct searchargs *searchargs, int usinguid,
                        struct progress_rock *prock);
extern int index_search(struct index_state *state,
                        struct searchargs *searchargs, int usinguid,
                        struct progress_rock *prock);
extern int index_copy(struct index_state *state,
                      const char *sequence,
                      int usinguid,
                      char *name,
                      char **copyuidp,
                      int nolink,
                      struct namespace *namespace,
                      int isadmin,
                      int ismove,
                      int ignorequota,
                      struct progress_rock *prock);
extern int find_thread_algorithm(char *arg);

extern int index_open(const char *name, struct index_init *init,
                      struct index_state **stateptr);
extern int index_open_mailbox(struct mailbox *mailbox, struct index_init *init,
                              struct index_state **stateptr);
extern int index_refresh(struct index_state *state);
extern void index_checkflags(struct index_state *state, int print, int dirty);
extern void index_select(struct index_state *state, struct index_init *init);
extern int index_status(struct index_state *state, struct statusdata *sdata);
extern void index_release(struct index_state *state);
extern void index_close(struct index_state **stateptr);

enum {
    FIND_EQ = 0,
    FIND_GE,
    FIND_LE
};

extern uint32_t index_finduid(struct index_state *state, uint32_t uid, int mode);
extern uint32_t index_getuid(struct index_state *state, uint32_t msgno);
extern void index_tellchanges(struct index_state *state, unsigned tell_flags);
extern modseq_t index_highestmodseq(struct index_state *state);
extern int index_check(struct index_state *state, unsigned tell_flags);
extern seqset_t *index_vanished(struct index_state *state,
                                    struct vanished_params *params);
extern int index_urlfetch(struct index_state *state, uint32_t msgno,
                          unsigned params, const char *section,
                          unsigned long start_octet, unsigned long octet_count,
                          struct protstream *pout, size_t maxsize, unsigned long *size);
extern char *index_get_msgid(struct index_state *state, uint32_t msgno);
extern struct nntp_overview *index_overview(struct index_state *state,
                                            uint32_t msgno);
extern char *index_getheader(struct index_state *state, uint32_t msgno,
                             const char *hdr);
extern unsigned long index_getsize(struct index_state *state, uint32_t msgno);
extern unsigned long index_getlines(struct index_state *state, uint32_t msgno);
extern int index_copy_remote(struct index_state *state, const char *sequence,
                             int usinguid, struct protstream *pout);

struct searchargs *new_searchargs(const char *tag, int state,
                                  struct namespace *namespace,
                                  const char *userid,
                                  struct auth_state *authstate,
                                  int isadmin);

void freesearchargs(struct searchargs *s);
char *sortcrit_as_string(const struct sortcrit *sortcrit);
void freesortcrit(struct sortcrit *s);
void index_msgdata_sort(MsgData **msgdata, int n, const struct sortcrit *sortcrit);
void index_msgdata_free(MsgData **, unsigned int);
MsgData **index_msgdata_load(struct index_state *state, unsigned *msgno_list, int n,
                             const struct sortcrit *sortcrit,
                             unsigned int anchor, int *found_anchor);
extern int index_search_evaluate(struct index_state *state, const search_expr_t *e, uint32_t msgno);

extern int index_expunge(struct index_state *state, const char *uidsequence,
                         int need_deleted);

/* Extract text for snippets: first look in message bodies, then attachments */
#define INDEX_GETSEARCHTEXT_SNIPPET  (1<<0)
/* Allow messages being indexed partially, if the attachment extractor
 * returned an error. If this flag is not set, then the first attachment
 * extractor error causes getsearchtext to return with an error. */
#define INDEX_GETSEARCHTEXT_ALLOW_PARTIALS (1<<1)
/* Do not log a warning if messages could only be indexed partially
 * (implies allowing partial message indexes) */
#define INDEX_GETSEARCHTEXT_NOLOG_PARTIALS \
    (INDEX_GETSEARCHTEXT_ALLOW_PARTIALS | (1<<2))
/* Disable calling the attachment extractor. The message is marked as
 * partially indexed, regardless of the ALLOW_PARTIALs flag. */
#define INDEX_GETSEARCHTEXT_NOCALL_ATTACHEXTRACT (1<<3)
extern int index_getsearchtext(struct message *msg, const strarray_t *partids,
                               struct search_text_receiver *receiver,
                               int flag);

extern int index_getuidsequence(struct index_state *state,
                                struct searchargs *searchargs,
                                unsigned **uid_list);

extern const char *index_mboxname(const struct index_state *state);
extern const char *index_mboxid(const struct index_state *state);
extern int index_hasrights(const struct index_state *state, int rights);

extern int index_reload_record(struct index_state *state,
                               uint32_t msgno,
                               struct index_record *record);

extern int insert_into_mailbox_allowed(struct mailbox *mailbox);

extern int index_want_attachextract(const char *type, const char *subtype);

#endif /* INDEX_H */
