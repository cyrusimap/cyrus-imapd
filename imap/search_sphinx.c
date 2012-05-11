/* search_sphinx.c -- glue code for searching with Sphinx
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

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "index.h"
#include "imap_err.h"
#include "global.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "bitvector.h"
#include "search_engines.h"

#include <mysql/mysql.h>

#define SEARCHD_SOCKET_PATH	    "/var/tmp/cass/casscmd/sphinx/searchd.sock"
static int connected = 0;
static MYSQL conn;

static int parse_cyrusid(const char *cyrusid,
			 const char **mboxnamep,
			 unsigned int *uidvalidityp,
			 unsigned int *uidp)
{
    // user.cassandane.1320711192.196715
    static struct buf buf = BUF_INITIALIZER;
    char *p;

    buf_reset(&buf);
    buf_appendcstr(&buf, cyrusid);

    p = strrchr(buf_cstring(&buf), '.');
    if (!p)
	return 0;
    *p++ = '\0';
    *uidp = strtoul(p, NULL, 10);

    p = strrchr(buf.s, '.');
    if (!p)
	return 0;
    *p++ = '\0';
    *uidvalidityp = strtoul(p, NULL, 10);

    *mboxnamep = buf.s;

    return 1;
}

static void escape(struct buf *to, const struct buf *from)
{
    buf_ensure(to, 2*from->len+1);
    to->len = mysql_real_escape_string(&conn, to->s, from->s, from->len);
    to->flags |= BUF_CSTRING;
}

static void add_match(struct buf *query, int *np,
		      const struct strlist *strs, const char *field)
{
    static struct buf f = BUF_INITIALIZER;
    static struct buf e1 = BUF_INITIALIZER;
    static struct buf e2 = BUF_INITIALIZER;

    for ( ; strs ; strs = strs->next) {
	buf_init_ro_cstr(&f, strs->s);
	escape(&e1, &f);
	escape(&e2, &e1);

	if (*np)
	    buf_appendcstr(query, " ");
	buf_printf(query, "@%s: %s", field, e2.s);
	(*np)++;
    }
}

static int search_sphinx(unsigned* msg_list, struct index_state *state,
			 const struct searchargs *args)
{
    MYSQL_RES *res;
    MYSQL_ROW row;
    struct buf query = BUF_INITIALIZER;
    int n = 0;
    int r = 0;

    if (!connected) {
	MYSQL *c;

	mysql_init(&conn);
	c = mysql_real_connect(&conn,
			       /*host*/NULL,
			       /*user*/"", /*password*/"",
			       /*database*/NULL,
			       /*port*/0, SEARCHD_SOCKET_PATH,
			       /*client_flag*/0);
	if (!c) {
	    syslog(LOG_ERR, "IOERROR: failed to connect to Sphinx on %s: %s",
		   SEARCHD_SOCKET_PATH, mysql_error(&conn));
	    return IMAP_IOERROR;
	}
	connected = 1;
    }

    buf_appendcstr(&query, "SELECT cyrusid FROM rt WHERE MATCH('");
    add_match(&query, &n, args->to, "header_to");
    add_match(&query, &n, args->from, "header_from");
    add_match(&query, &n, args->cc, "header_cc");
    add_match(&query, &n, args->subject, "header_subject");
    add_match(&query, &n, args->header_name, "header_to");
    add_match(&query, &n, args->body, "body");
    buf_appendcstr(&query, "')");
    // get sphinx to sort by most recent date first
    buf_appendcstr(&query, " ORDER BY header_date DESC");
    // TODO: Sphinx has an implicit default limit of 20 results
    //       we need to defeat that with a LIMIT clause here

    if (!n) {
	/* None of the fields which are indexed were in the search, so
	 * give up and let the next search engine try. */
	r = IMAP_NOTFOUND;
	goto out;
    }

    r = mysql_real_query(&conn, query.s, query.len);
    if (r) {
	syslog(LOG_ERR, "IOERROR: Sphinx query %s failed: %s",
	       query.s, mysql_error(&conn));
	r = IMAP_IOERROR;
	goto out;
    }

    n = 0;
    res = mysql_use_result(&conn);
    while ((row = mysql_fetch_row(res))) {
	const char *mboxname;
	unsigned int uidvalidity;
	unsigned int uid;
	if (!parse_cyrusid(row[0], &mboxname, &uidvalidity, &uid))
	    // TODO: whine
	    continue;
	if (strcmp(mboxname, state->mailbox->name))
	    continue;
	if (uidvalidity != state->mailbox->i.uidvalidity)
	    continue;
	msg_list[n++] = uid;
    }
    mysql_free_result(res);
    r = n;


    /* TODO: currently we neither track nor care about unindexed
     * messages, that should be handled by a layer above here. */

out:
    buf_free(&query);
    return r;
}

const struct search_engine sphinx_search_engine = {
    "Sphinx",
    0,
    search_sphinx
};

