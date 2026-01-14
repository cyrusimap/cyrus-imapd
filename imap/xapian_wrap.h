/* xapian_wrap.h - C++ hiding wrapper API for Xapian */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef __CYRUS_IMAP_XAPIAN_WRAP__
#define __CYRUS_IMAP_XAPIAN_WRAP__

#include "message_guid.h"
#include "util.h"
#include "search_part.h"
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
#define XAPIAN_DBW_CONVINDEXED 0x0
#define XAPIAN_DBW_XAPINDEXED  0x1
#define XAPIAN_DBW_NOSYNC      0x2
extern int xapian_dbw_open(const char **paths, xapian_dbw_t **dbwp, int mode);
extern int xapian_dbw_openmem(xapian_dbw_t **dbwp); // use only for data <1mb
extern void xapian_dbw_close(xapian_dbw_t *dbw);
extern int xapian_dbw_begin_txn(xapian_dbw_t *dbw);
extern int xapian_dbw_commit_txn(xapian_dbw_t *dbw);
extern int xapian_dbw_cancel_txn(xapian_dbw_t *dbw);
extern int xapian_dbw_begin_doc(xapian_dbw_t *dbw, const struct message_guid *guid, char doctype);
extern int xapian_dbw_doc_part(xapian_dbw_t *dbw, const struct buf *part, enum search_part);
extern int xapian_dbw_end_doc(xapian_dbw_t *dbw, uint8_t indexlevel);
extern unsigned long xapian_dbw_total_length(xapian_dbw_t *dbw);
extern uint8_t xapian_dbw_is_indexed(xapian_dbw_t *dbw, const struct message_guid *guid, char doctype);

/* query-side interface */
extern int xapian_db_open(const char **paths, xapian_db_t **dbp);
extern int xapian_db_opendbw(struct xapian_dbw *dbw, xapian_db_t **dbp);
extern unsigned xapian_db_min_index_version(xapian_db_t*);
extern void xapian_db_close(xapian_db_t *);
extern void xapian_query_add_stemmer(xapian_db_t *, const char *iso_lang);
extern xapian_query_t *xapian_query_new_match(const xapian_db_t *, enum search_part, const char *term);
extern xapian_query_t *xapian_query_new_compound(const xapian_db_t *, int is_or, xapian_query_t **children, int n);
extern xapian_query_t *xapian_query_new_matchall(const xapian_db_t *);
extern xapian_query_t *xapian_query_new_not(const xapian_db_t *, xapian_query_t *);
extern xapian_query_t *xapian_query_new_has_doctype(const xapian_db_t *, char doctype, xapian_query_t *);
extern void xapian_query_serialize(xapian_query_t *, struct buf*);
extern void xapian_query_free(xapian_query_t *);
extern int xapian_query_run(const xapian_db_t *, const xapian_query_t *query,
                            int (*cb)(void *base, size_t n, void *rock), void *rock);
/* snippets interface */
extern xapian_snipgen_t *xapian_snipgen_new(xapian_db_t *db, const struct search_snippet_markup *markup);
extern void xapian_snipgen_free(xapian_snipgen_t *);
extern int xapian_snipgen_add_match(xapian_snipgen_t *snipgen, const char *match);
extern int xapian_snipgen_begin_doc(xapian_snipgen_t *snipgen, const struct message_guid *guid, char doctype);
extern int xapian_snipgen_doc_part(xapian_snipgen_t *snipgen, const struct buf *part);
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
extern void xapian_doc_reset(xapian_doc_t *doc);
extern void xapian_doc_close(xapian_doc_t *doc);

extern const char *xapian_version_string();

extern int xapian_charset_flags(int flags);

#endif
