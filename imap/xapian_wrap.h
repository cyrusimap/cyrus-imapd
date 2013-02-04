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

#include "util.h"

typedef struct xapian_dbw xapian_dbw_t;
typedef struct xapian_db xapian_db_t;
typedef struct xapian_query xapian_query_t;
typedef struct xapian_snipgen xapian_snipgen_t;

extern void xapian_init(void);

/* write-side interface */
extern xapian_dbw_t *xapian_dbw_open(const char *path, int incremental);
extern void xapian_dbw_close(xapian_dbw_t *dbw);
extern int xapian_dbw_begin_txn(xapian_dbw_t *dbw);
extern int xapian_dbw_commit_txn(xapian_dbw_t *dbw);
extern int xapian_dbw_cancel_txn(xapian_dbw_t *dbw);
extern int xapian_dbw_begin_doc(xapian_dbw_t *dbw, const char *cyrusid);
extern int xapian_dbw_doc_part(xapian_dbw_t *dbw, const struct buf *part, const char *prefix);
extern int xapian_dbw_end_doc(xapian_dbw_t *dbw);

/* query-side interface */
extern xapian_db_t *xapian_db_open(const char *path);
extern void xapian_db_close(xapian_db_t *);
extern xapian_query_t *xapian_query_new_match(const xapian_db_t *, const char *prefix, const char *term);
extern xapian_query_t *xapian_query_new_compound(const xapian_db_t *, int is_or, xapian_query_t **children, int n);
extern xapian_query_t *xapian_query_new_not(const xapian_db_t *, xapian_query_t *);
extern void xapian_query_free(xapian_query_t *);
extern int xapian_query_run(const xapian_db_t *, const xapian_query_t *,
			    int (*cb)(const char *cyrusid, void *rock), void *rock);

/* snippets interface */
extern xapian_snipgen_t *xapian_snipgen_new(void);
extern void xapian_snipgen_free(xapian_snipgen_t *);
extern int xapian_snipgen_add_match(xapian_snipgen_t *snipgen, const char *match);
extern int xapian_snipgen_begin_doc(xapian_snipgen_t *snipgen, unsigned context_length);
extern int xapian_snipgen_doc_part(xapian_snipgen_t *snipgen, const struct buf *part);
extern int xapian_snipgen_end_doc(xapian_snipgen_t *snipgen, struct buf *);

#endif
