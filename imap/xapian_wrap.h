/* xapian_wrap.h --  C++ hiding wrapper API for Xapian
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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

#ifndef __CYRUS_IMAP_XAPIAN_WRAP__
#define __CYRUS_IMAP_XAPIAN_WRAP__

#include "message_guid.h"
#include "util.h"
#include "strarray.h"
#include "ptrarray.h"

typedef struct xapian_dbw xapian_dbw_t;
typedef struct xapian_db xapian_db_t;
typedef struct xapian_query xapian_query_t;
typedef struct xapian_snipgen xapian_snipgen_t;
typedef struct xapian_doc xapian_doc_t;

/* Document types */
#define XAPIAN_WRAP_DOCTYPE_MSG  'G'
#define XAPIAN_WRAP_DOCTYPE_PART 'P'

/* compaction interface */
extern int xapian_compact_dbs(const char *dest, const char **sources);
extern void xapian_check_if_needs_reindex(const strarray_t *sources, strarray_t *toreindex, int always_upgrade);

/* write-side interface */
#define XAPIAN_DBW_CONVINDEXED 0
#define XAPIAN_DBW_XAPINDEXED 1
extern int xapian_dbw_open(const char **paths, xapian_dbw_t **dbwp, int mode, int nosync);
extern void xapian_dbw_close(xapian_dbw_t *dbw);
extern int xapian_dbw_begin_txn(xapian_dbw_t *dbw);
extern int xapian_dbw_commit_txn(xapian_dbw_t *dbw);
extern int xapian_dbw_begin_doc(xapian_dbw_t *dbw, const struct message_guid *guid, char doctype);
extern int xapian_dbw_doc_part(xapian_dbw_t *dbw, const struct buf *part, int num_part);
extern int xapian_dbw_end_doc(xapian_dbw_t *dbw, uint8_t indexlevel);
extern unsigned long xapian_dbw_total_length(xapian_dbw_t *dbw);
extern uint8_t xapian_dbw_is_indexed(xapian_dbw_t *dbw, const struct message_guid *guid, char doctype);

/* query-side interface */
extern int xapian_db_open(const char **paths, xapian_db_t **dbp);
extern int xapian_db_opendbw(struct xapian_dbw *dbw, xapian_db_t **dbp);
extern void xapian_db_close(xapian_db_t *);
extern void xapian_query_add_stemmer(xapian_db_t *, const char *iso_lang);
extern xapian_query_t *xapian_query_new_match(const xapian_db_t *, int num_part, const char *term);
extern xapian_query_t *xapian_query_new_compound(const xapian_db_t *, int is_or, xapian_query_t **children, int n);
extern xapian_query_t *xapian_query_new_matchall(const xapian_db_t *);
extern xapian_query_t *xapian_query_new_not(const xapian_db_t *, xapian_query_t *);
extern xapian_query_t *xapian_query_new_has_doctype(const xapian_db_t *, char doctype, xapian_query_t *);
extern void xapian_query_free(xapian_query_t *);
extern int xapian_query_run(const xapian_db_t *, const xapian_query_t *query,
                            int (*cb)(void *base, size_t n, void *rock), void *rock);
/* snippets interface */
extern xapian_snipgen_t *xapian_snipgen_new(xapian_db_t *db, const char *hi_start, const char *hi_end, const char *omit);
extern void xapian_snipgen_free(xapian_snipgen_t *);
extern int xapian_snipgen_add_match(xapian_snipgen_t *snipgen, const char *match);
extern int xapian_snipgen_begin_doc(xapian_snipgen_t *snipgen, const struct message_guid *guid, char doctype);
extern int xapian_snipgen_doc_part(xapian_snipgen_t *snipgen, const struct buf *part, int partnum);
extern int xapian_snipgen_end_doc(xapian_snipgen_t *snipgen, struct buf *);

/* filter interface */
extern int xapian_filter(const char *dest, const char **sources,
                         int (*cb)(const char *cyrusid, void *rock),
                         void *rock);

/* Language indexing support */
extern int xapian_db_langstats(xapian_db_t*, ptrarray_t*, size_t*);

/* Document interface */
extern xapian_doc_t *xapian_doc_new(void);
extern void xapian_doc_index_text(xapian_doc_t *doc, const char *text, size_t len);
extern size_t xapian_doc_termcount(xapian_doc_t *doc);
extern int xapian_doc_foreach_term(xapian_doc_t *doc, int(*cb)(const char*, void*), void *rock);
extern void xapian_doc_close(xapian_doc_t *doc);

extern const char *xapian_version_string();

#endif
