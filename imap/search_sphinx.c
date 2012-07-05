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
#include "retry.h"
#include "command.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "bitvector.h"
#include "mboxlist.h"
#include "search_engines.h"

#include <mysql/mysql.h>

/* Various locations, relative to the Cyrus config directory */
#define SPHINX_CONFIG	    "/sphinx.conf"

#define SEARCHD		    "/usr/bin/searchd"

/* Name of columns */
#define COL_CYRUSID	"cyrusid"
#define COL_FROM	"header_from"
#define COL_TO		"header_to"
#define COL_CC	    	"header_cc"
#define COL_BCC	    	"header_bcc"
#define COL_SUBJECT	"header_subject"
#define COL_HEADERS	"headers"
#define COL_BODY	"body"
#define COL_ORDER	COL_CYRUSID

/* Returns in *basedir and *sockname, two new strings which must be free()d */
static int sphinx_paths_from_mboxname(const char *mboxname,
				      char **basedirp,
				      char **socknamep)
{
    char *confkey = NULL;
    const char *root;
    struct mboxlist_entry *mbentry = NULL;
    char *basedir = NULL;
    struct mboxname_parts parts;
    char *sockname = NULL;
    char c[2], d[2];
    int r;

    mboxname_init_parts(&parts);

    r = mboxlist_lookup(mboxname, &mbentry, /*tid*/NULL);
    if (r) goto out;
    if (mbentry->mbtype & MBTYPE_REMOTE) {
	r = IMAP_PARTITION_UNKNOWN;
	goto out;
    }

    confkey = strconcat("sphinxpartition-", mbentry->partition, NULL);
    root = config_getoverflowstring(confkey, NULL);
    if (!root) {
	r = IMAP_PARTITION_UNKNOWN;
	goto out;
    }

    r = mboxname_to_parts(mboxname, &parts);
    if (r) goto out;
    if (!parts.userid) {
	r = IMAP_PARTITION_UNKNOWN;
	goto out;
    }

    if (parts.domain)
	basedir = strconcat(root,
			    FNAME_DOMAINDIR,
			    dir_hash_b(parts.domain, config_fulldirhash, d),
			    "/", parts.domain,
			    FNAME_USERDIR,
			    dir_hash_b(parts.userid, config_fulldirhash, c),
			    "/", parts.userid,
			    (char *)NULL);
    else
	basedir = strconcat(root,
			    FNAME_USERDIR,
			    dir_hash_b(parts.userid, config_fulldirhash, c),
			    "/", parts.userid,
			    (char *)NULL);

    if (parts.domain)
	sockname = strconcat(config_dir,
			     "/socket/sphinx.",
			     parts.userid,
			     "@",
			     parts.domain,
			     (char *)NULL);
    else
	sockname = strconcat(config_dir,
			     "/socket/sphinx.",
			     parts.userid,
			     (char *)NULL);
    r = 0;

out:
    if (r) {
	free(basedir);
	free(sockname);
    }
    else {
	*basedirp = basedir;
	*socknamep = sockname;
    }
    free(confkey);
    mboxname_free_parts(&parts);
    mboxlist_entry_free(&mbentry);
    return r;
}

static MYSQL *get_connection(const char *mboxname)
{
    MYSQL *c;
    char *basedir = NULL;
    char *socket_path = NULL;
    int r;

    r = sphinx_paths_from_mboxname(mboxname, &basedir, &socket_path);
    if (r) return NULL;

    c = mysql_init(NULL);

    if (!mysql_real_connect(c,
			   /*host*/NULL,
			   /*user*/"", /*password*/"",
			   /*database*/NULL,
			   /*port*/0, socket_path,
			   /*client_flag*/0)) {
	syslog(LOG_ERR, "IOERROR: failed to connect to Sphinx: %s",
	       mysql_error(c));
	mysql_close(c);
	mysql_library_end();
	c = NULL;
    }

    free(basedir);
    free(socket_path);
    return c;
}

static void close_connection(MYSQL *c)
{
    mysql_close(c);
    mysql_library_end();
}

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

static const struct buf *make_cyrusid(struct mailbox *mailbox, uint32_t uid)
{
    static struct buf buf = BUF_INITIALIZER;
    // user.cassandane.1320711192.196715
    buf_reset(&buf);
    buf_printf(&buf, "%s.%u.%u",
		     mailbox->name,
		     mailbox->i.uidvalidity,
		     uid);
    return &buf;
}

static void append_escaped_map(MYSQL *conn, struct buf *buf,
			       const char *base, unsigned int len)
{
    buf_ensure(buf, 2*len+1);
    buf->len += mysql_real_escape_string(conn, buf->s + buf->len, base, len);
    buf->flags |= BUF_CSTRING;
}

static void append_escaped(MYSQL *conn, struct buf *to, const struct buf *from)
{
    append_escaped_map(conn, to, from->s, from->len);
}

static void append_escaped_cstr(MYSQL *conn, struct buf *to, const char *str)
{
    if (str)
	append_escaped_map(conn, to, str, strlen(str));
}

static void add_match(MYSQL *conn, struct buf *query, int *np,
		      const struct strlist *strs, const char *field)
{
    static struct buf f = BUF_INITIALIZER;
    static struct buf e1 = BUF_INITIALIZER;
    static struct buf e2 = BUF_INITIALIZER;

    for ( ; strs ; strs = strs->next) {
	buf_init_ro_cstr(&f, strs->s);
	buf_reset(&e1);
	append_escaped(conn, &e1, &f);
	buf_reset(&e2);
	append_escaped(conn, &e2, &e1);

	if (*np)
	    buf_appendcstr(query, " ");
	if (field)
	    buf_printf(query, "@%s:", field);
	buf_append(query, &e2);
	(*np)++;
    }
}

static int search_sphinx(unsigned* msg_list, struct index_state *state,
			 const struct searchargs *args)
{
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;
    struct buf query = BUF_INITIALIZER;
    int n = 0;
    int r = 0;

    conn = get_connection(state->mailbox->name);
    if (!conn) return IMAP_IOERROR;

    buf_appendcstr(&query, "SELECT "COL_CYRUSID" FROM rt WHERE MATCH('");
    add_match(conn, &query, &n, args->to, COL_TO);
    add_match(conn, &query, &n, args->from, COL_FROM);
    add_match(conn, &query, &n, args->cc, COL_CC);
    add_match(conn, &query, &n, args->subject, COL_SUBJECT);
    add_match(conn, &query, &n, args->header_name, COL_HEADERS);
    add_match(conn, &query, &n, args->header, COL_HEADERS);
    add_match(conn, &query, &n, args->body, COL_BODY);
    add_match(conn, &query, &n, args->text, NULL);
    buf_appendcstr(&query, "')");
    // get sphinx to sort by most recent date first
    buf_appendcstr(&query, " ORDER BY "COL_ORDER" DESC");
    // TODO: Sphinx has an implicit default limit of 20 results
    //       we need to defeat that with a LIMIT clause here

    if (!n) {
	/* None of the fields which are indexed were in the search, so
	 * give up and let the next search engine try. */
	r = IMAP_NOTFOUND;
	goto out;
    }

    r = mysql_real_query(conn, query.s, query.len);
    if (r) {
	syslog(LOG_ERR, "IOERROR: Sphinx query %s failed: %s",
	       query.s, mysql_error(conn));
	r = IMAP_IOERROR;
	goto out;
    }

    n = 0;
    res = mysql_use_result(conn);
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
    close_connection(conn);
    return r;
}

typedef struct sphinx_receiver sphinx_receiver_t;
struct sphinx_receiver
{
    search_text_receiver_t super;
    int verbose;
    MYSQL *conn;
    struct mailbox *mailbox;
    uint32_t uid;
    int part;
    unsigned int parts_total;
    int truncate_warning;
    struct buf parts[SEARCH_NUM_PARTS];
    struct buf query;
    unsigned int uncommitted;
    uint32_t latest;
    uint32_t latest_id;	    /* The 'id' attribute of the row in the
			     * 'latest' table which describes the
			     * current mailbox, or 0 */
    uint32_t latest_lastid; /* The largest document ID in the 'latest'
			     * table, used when INSERTing */
    uint32_t lastid;	    /* largest document ID in the 'tr' table,
			     * used to assign new document IDs when
			     * INSERTing into the table */
};

#define MAX_UNCOMMITTED	    10

/* Maximum size of a query, determined empirically, is a little bit
 * under 8MB.  That seems like more than enough, so let's limit the
 * total amount of parts text to 4 MB. */
#define MAX_PARTS_SIZE	    (4*1024*1024)

static const char *describe_query(MYSQL *conn, struct buf *desc,
				  const struct buf *query,
				  unsigned maxlen)
{
    buf_reset(desc);
    buf_appendcstr(desc, "Sphinx query \"");
    if (maxlen && query->len > maxlen) {
	buf_appendmap(desc, query->s, maxlen);
	buf_appendcstr(desc, "...");
    }
    else {
	append_escaped(conn, desc, query);
    }
    buf_appendcstr(desc, "\"");
    return buf_cstring(desc);
}

static int doquery(sphinx_receiver_t *tr, const struct buf *query)
{
    int r;
    struct buf desc = BUF_INITIALIZER;
    unsigned int maxlen = tr->verbose > 2 ? /*unlimited*/0 : 128;

    if (tr->verbose > 1)
	syslog(LOG_NOTICE, "%s", describe_query(tr->conn, &desc, query, maxlen));

    r = mysql_real_query(tr->conn, query->s, query->len);
    if (r) {
	syslog(LOG_ERR, "IOERROR: %s failed: %s",
			describe_query(tr->conn, &desc, query, maxlen),
			mysql_error(tr->conn));
	r = IMAP_IOERROR;
    }

    buf_free(&desc);
    return r;
}

#if 0
/* Dump a result which has had mysql_store_result() called on it */
static void dump_result(MYSQL_RES *res)
{
    uint64_t nrows = mysql_num_rows(res);
    unsigned int nfields = mysql_num_fields(res);
    unsigned int i;
    unsigned int j;
    MYSQL_FIELD *fields = mysql_fetch_fields(res);
    MYSQL_ROW *row;
    struct buf buf = BUF_INITIALIZER;

    syslog(LOG_NOTICE, "Sphinx result: %u rows", (unsigned int)nrows);
    i = 0;
    while ((row = mysql_fetch_row(res))) {
	buf_reset(&buf);
	for (j = 0 ; j < nfields ; j++)
	    buf_printf(&buf, " %s=\"%s\"", fields[j].name, row[j]);
	syslog(LOG_NOTICE, "    [%u]%s", ++i, buf_cstring(&buf));
    }

    buf_free(&buf);
    mysql_data_seek(res, 0);	/* rewind */
}
#endif


/*
 * Read the most recently indexed UID for the current mailboxfrom the
 * 'latest' table in the Sphinx searchd.  This is a bit of a shemozzle
 * because Sphinx does not let us write a WHERE clause in a SELECT or
 * UPDATE statement which matches against a string attribute, so we
 * can't just do the obvious SQL statements.  Instead we have to SELECT
 * on the uidvalidity only and then filter the results manually for
 * mboxname.  The same limitation makes write_latest() a real challange
 * too.
 * Updates tr->latest, tr->latest_id, tr->latest_lastid
 * Returns 0 on success or an IMAP error code.
 */
static int read_latest(sphinx_receiver_t *tr)
{
    struct buf query = BUF_INITIALIZER;
    MYSQL_RES *res = NULL;
    MYSQL_ROW row;
    int r = 0;

    tr->latest = 0;
    tr->latest_id = 0;
    tr->latest_lastid = 0;

    buf_printf(&query, "SELECT id,mboxname,uid "
		       "FROM latest "
		       "WHERE uidvalidity=%u "
		       "LIMIT 10000",
		       tr->mailbox->i.uidvalidity);

    r = doquery(tr, &query);
    if (r) goto out;

    res = mysql_store_result(tr->conn);
    while ((row = mysql_fetch_row(res))) {
	if (!strcmp(tr->mailbox->name, row[1])) {
	    tr->latest_id = strtoul(row[0], NULL, 10);
	    tr->latest = strtoul(row[2], NULL, 10);
	    break;
	}
    }

    mysql_free_result(res);
    res = NULL;

    buf_reset(&query);
    /* Guess what.. the query 'SELECT MAX(id) FROM latest' returns N
     * rows with all N valid ids..., rather than one row with the max */
    buf_appendcstr(&query, "SELECT max(id) FROM latest ORDER BY id DESC LIMIT 1;");

    r = doquery(tr, &query);
    if (r) goto out;

    res = mysql_store_result(tr->conn);
    if (!res) goto out;
    row = mysql_fetch_row(res);
    if (row)
	tr->latest_lastid = strtoul(row[0], NULL, 10);

out:
    if (res) mysql_free_result(res);
    buf_free(&query);
    return r;
}

static int write_latest(sphinx_receiver_t *tr)
{
    struct buf query = BUF_INITIALIZER;
    int r;
    uint32_t id = tr->latest_id;

    if (id) {
	buf_printf(&query, "UPDATE latest "
			   "SET uid=%u "
			   "WHERE id=%u",
			   tr->latest, id);
    }
    else {
	id = tr->latest_lastid+1;
	buf_appendcstr(&query, "INSERT INTO latest "
			       "(id,mboxname,uidvalidity,uid) "
			       "VALUES (");
	buf_printf(&query, "%u,'", id);
	append_escaped_cstr(tr->conn, &query, tr->mailbox->name);
	buf_printf(&query, "',%u,%u)",
		   tr->mailbox->i.uidvalidity, tr->latest);
    }

    r = doquery(tr, &query);
    if (r) goto out;

    tr->latest_id = id;

out:
    buf_free(&query);
    return 0;
}

/*
 * Read the last document ID from Sphinx.  Currently this is very dumb
 * and just SELECTs MAX(id), in the hope that this is efficient on the
 * server side (the documentation does not make that clear).  This has
 * the behaviour that document IDs might get re-used if the last
 * document is DELETEd; we don't really care because the only thing we
 * use the document IDs for is INSERTing a new row.
 *
 * Updates tr->lastid
 * Returns: 0 on success or an IMAP error code.
 */
static int read_lastid(sphinx_receiver_t *tr)
{
    struct buf query = BUF_INITIALIZER;
    MYSQL_RES *res = NULL;
    MYSQL_ROW row;
    int r = 0;

    tr->lastid = 0;

    buf_appendcstr(&query, "SELECT max(id) FROM rt ORDER BY id DESC LIMIT 1;");

    r = doquery(tr, &query);
    if (r) goto out;

    res = mysql_store_result(tr->conn);
    if (!res) goto out;
#if 0
    if (tr->verbose > 1) dump_result(res);
#endif
    row = mysql_fetch_row(res);

    if (row)
	tr->lastid = strtoul(row[0], NULL, 10);

    if (tr->verbose > 1)
	syslog(LOG_NOTICE, "Sphinx read_lastid: %u", tr->lastid);

out:
    if (res) mysql_free_result(res);
    buf_free(&query);
    return r;
}


static int flush(sphinx_receiver_t *tr, int force)
{
    int r = 0;

    if (!force && tr->uncommitted < MAX_UNCOMMITTED) return 0;

    if (tr->uncommitted) {
	r = write_latest(tr);
	if (r) return r;
    }

    if (tr->verbose > 1)
	syslog(LOG_NOTICE, "Sphinx committing");

    r = mysql_commit(tr->conn);
    if (r) {
	syslog(LOG_ERR, "IOERROR: Sphinx COMMIT failed for "
			"mailbox %s, %u messages ending at uid %u: %s",
			tr->mailbox->name, tr->uncommitted, tr->uid,
			mysql_error(tr->conn));
	return IMAP_IOERROR;
    }
    tr->uncommitted = 0;

    return r;
}

static void begin_message(search_text_receiver_t *rx, uint32_t uid)
{
    sphinx_receiver_t *tr = (sphinx_receiver_t *)rx;
    int i;

    tr->uid = uid;
    for (i = 0 ; i < SEARCH_NUM_PARTS ; i++)
	buf_reset(&tr->parts[i]);
    tr->parts_total = 0;
    tr->truncate_warning = 0;
}

static void begin_part(search_text_receiver_t *rx, int part)
{
    sphinx_receiver_t *tr = (sphinx_receiver_t *)rx;

    tr->part = part;
}

static void append_text(search_text_receiver_t *rx,
			const struct buf *text)
{
    sphinx_receiver_t *tr = (sphinx_receiver_t *)rx;

    if (tr->part) {
	unsigned len = text->len;
	if (tr->parts_total + len > MAX_PARTS_SIZE) {
	    if (!tr->truncate_warning++)
		syslog(LOG_ERR, "Sphinx: truncating text from "
				"message mailbox %s uid %u",
				tr->mailbox->name, tr->uid);
	    len = MAX_PARTS_SIZE - tr->parts_total;
	}
	if (len) {
	    tr->parts_total += len;
	    buf_appendmap(&tr->parts[tr->part], text->s, len);
	}
    }
}

static void end_part(search_text_receiver_t *rx,
		     int part __attribute__((unused)))
{
    sphinx_receiver_t *tr = (sphinx_receiver_t *)rx;

    if (tr->verbose > 1)
	syslog(LOG_NOTICE, "Sphinx: %u bytes in part %d",
	       tr->parts[tr->part].len, tr->part);

    tr->part = 0;
}

static void add_column(sphinx_receiver_t *tr, int part, const char *col)
{
    if (tr->parts[part].len) {
	buf_appendcstr(&tr->query, ",");
	buf_appendcstr(&tr->query, col);
    }
}

static void add_value(sphinx_receiver_t *tr, int part)
{
    if (tr->parts[part].len) {
	buf_appendcstr(&tr->query, ",'");
	append_escaped(tr->conn, &tr->query, &tr->parts[part]);
	buf_appendcstr(&tr->query, "'");
    }
    /* apparently Sphinx doesn't let you explicitly INSERT a NULL */
}

static void end_message(search_text_receiver_t *rx,
			uint32_t uid __attribute__((unused)))
{
    sphinx_receiver_t *tr = (sphinx_receiver_t *)rx;
    int r;

    buf_reset(&tr->query);
    buf_appendcstr(&tr->query, "INSERT INTO rt (id,"COL_CYRUSID);
    add_column(tr, SEARCH_PART_FROM, COL_FROM);
    add_column(tr, SEARCH_PART_TO, COL_TO);
    add_column(tr, SEARCH_PART_CC, COL_CC);
    add_column(tr, SEARCH_PART_BCC, COL_BCC);
    add_column(tr, SEARCH_PART_SUBJECT, COL_SUBJECT);
    add_column(tr, SEARCH_PART_HEADERS, COL_HEADERS);
    add_column(tr, SEARCH_PART_BODY, COL_BODY);
    buf_appendcstr(&tr->query, ") VALUES (");
    buf_printf(&tr->query, "%u,'", ++tr->lastid);
    append_escaped(tr->conn, &tr->query, make_cyrusid(tr->mailbox, tr->uid));
    buf_appendcstr(&tr->query, "'");
    add_value(tr, SEARCH_PART_FROM);
    add_value(tr, SEARCH_PART_TO);
    add_value(tr, SEARCH_PART_CC);
    add_value(tr, SEARCH_PART_BCC);
    add_value(tr, SEARCH_PART_SUBJECT);
    add_value(tr, SEARCH_PART_HEADERS);
    add_value(tr, SEARCH_PART_BODY);
    buf_appendcstr(&tr->query, ")");

    r = doquery(tr, &tr->query);
    if (r) goto out; /* TODO: propagate error to the user */

    ++tr->uncommitted;
    tr->latest = tr->uid;

    r = flush(tr, /*force*/0);
    /* TODO: propagate error to the user */

out:
    tr->uid = 0;
}

static int begin_mailbox(search_text_receiver_t *rx,
			 struct mailbox *mailbox,
			 int incremental __attribute__((unused)))
{
    sphinx_receiver_t *tr = (sphinx_receiver_t *)rx;
    MYSQL *c;
    int r;

    c = get_connection(mailbox->name);
    if (!c) return IMAP_IOERROR;
    tr->conn = c;

    tr->mailbox = mailbox;

    r = read_lastid(tr);
    if (r) return r;

    r = read_latest(tr);
    if (r) return r;

    return 0;
}

static int is_indexed(search_text_receiver_t *rx, uint32_t uid)
{
    sphinx_receiver_t *tr = (sphinx_receiver_t *)rx;

    return (uid <= tr->latest);
}

static int end_mailbox(search_text_receiver_t *rx,
		       struct mailbox *mailbox
			    __attribute__((unused)))
{
    sphinx_receiver_t *tr = (sphinx_receiver_t *)rx;
    int r = 0;

    if (tr->conn) {
	r = flush(tr, /*force*/1);
	close_connection(tr->conn);
	tr->conn = NULL;
    }

    tr->mailbox = NULL;

    return r;
}

static search_text_receiver_t *begin_update(int verbose)
{
    sphinx_receiver_t *tr;

    tr = xzmalloc(sizeof(sphinx_receiver_t));
    tr->super.begin_mailbox = begin_mailbox;
    tr->super.is_indexed = is_indexed;
    tr->super.begin_message = begin_message;
    tr->super.begin_part = begin_part;
    tr->super.append_text = append_text;
    tr->super.end_part = end_part;
    tr->super.end_message = end_message;
    tr->super.end_mailbox = end_mailbox;

    tr->verbose = verbose;

    return &tr->super;
}

static int end_update(search_text_receiver_t *rx)
{
    sphinx_receiver_t *tr = (sphinx_receiver_t *)rx;
    int i;
    int r = 0;

    for (i = 0 ; i < SEARCH_NUM_PARTS ; i++)
	buf_free(&tr->parts[i]);
    buf_free(&tr->query);
    free(tr);

    return r;
}

static int setup_sphinx_tree(const char *basedir)
{
    static const char * const tobuild[] = {
	"",
	"/binlog",
	NULL
    };
    const char * const *dp;
    char *path = NULL;
    int r;

    for (dp = tobuild ; *dp ; dp++) {
	free(path);
	path = strconcat(basedir, *dp, "/filename",  (char *)NULL);
	r = cyrus_mkdir(path, 0700);
	if (r < 0 && errno != EEXIST) {
	    syslog(LOG_ERR, "IOERROR: unable to mkdir %s: %m", path);
	    r = IMAP_IOERROR;
	    goto out;
	}
    }
    r = 0;

out:
    free(path);
    return r;
}

static int setup_sphinx_config(int verbose, const char *basedir,
			       const char *sockname)
{
    static const char config[] =
	"index rt\n"
	"{\n"
	"    type = rt\n"
	"    path = $sphinxdir/rt\n"
	"    morphology = stem_en\n"
	"    charset_type = utf-8\n"
	"\n"
	"    rt_attr_string = cyrusid\n"
	"    rt_field = header_from\n"
	"    rt_field = header_to\n"
	"    rt_field = header_cc\n"
	"    rt_field = header_bcc\n"
	"    rt_field = header_subject\n"
	"    rt_field = headers\n"
	"    rt_field = body\n"
	"}\n"
	"\n"
	"index latest\n"
	"{\n"
	"    type = rt\n"
	"    path = $sphinxdir/latest\n"
	"    rt_attr_string = mboxname\n"
	"    rt_attr_uint = uidvalidity\n"
	"    rt_attr_uint = uid\n"
	"    rt_field = dummy\n"
	"}\n"
	"\n"
	"searchd\n"
	"{\n"
	"    listen = $sphinxsock:mysql41\n"
	"    log = syslog\n"
	"    pid_file = $sphinxdir/searchd.pid\n"
	"    binlog_path = $sphinxdir/binlog\n"
	"    compat_sphinxql_magics = 0\n"
	"    workers = threads\n"
	"}\n";
    char *sphinx_config = NULL;
    int fd = -1;
    struct buf buf = BUF_INITIALIZER;
    int r;

    sphinx_config = strconcat(basedir, SPHINX_CONFIG, (char *)NULL);

/* the searchd.log entry changed, so force a rewrite of the config file */
#if 0
    struct stat sb;
    if (stat(sphinx_config, &sb) == 0 &&
	S_ISREG(sb.st_mode) &&
	sb.st_size > 0) {
	r = 0;
	goto out;	/* a non-zero file already exists */
    }
#endif

    if (verbose)
	syslog(LOG_NOTICE, "Sphinx writing config file %s", sphinx_config);

    fd = open(sphinx_config, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) {
	syslog(LOG_ERR, "IOERROR: unable to open %s for writing: %m",
	       sphinx_config);
	r = IMAP_IOERROR;
	goto out;
    }

    buf_init_ro_cstr(&buf, config);
    buf_replace_all(&buf, "$sphinxsock", sockname);
    buf_replace_all(&buf, "$sphinxdir", basedir);

    r = retry_write(fd, buf.s, buf.len);
    if (r < 0) {
	syslog(LOG_ERR, "IOERROR: error writing %s: %m", sphinx_config);
	r = IMAP_IOERROR;
	goto out;
    }
    r = 0;

out:
    if (fd >= 0) close(fd);
    free(sphinx_config);
    buf_free(&buf);
    return r;
}


static int start_daemon(int verbose, const char *mboxname)
{
    char *config_file = NULL;
    char *basedir = NULL;
    char *sockname = NULL;
    const char *syslog_prefix;
    int r;

    r = sphinx_paths_from_mboxname(mboxname, &basedir, &sockname);
    if (r) goto out;

    r = setup_sphinx_tree(basedir);
    if (r) goto out;

    r = setup_sphinx_config(verbose, basedir, sockname);
    if (r) goto out;

    syslog_prefix = config_getstring(IMAPOPT_SYSLOG_PREFIX);
    if (!syslog_prefix)
	syslog_prefix = "cyrus";

    if (verbose)
	syslog(LOG_NOTICE, "Sphinx starting searchd, "
			   "base directory %s socket %s",
			   basedir, sockname);

    config_file = strconcat(basedir, SPHINX_CONFIG, (char *)NULL);
    r = run_command(SEARCHD, "--config", config_file,
		    "--syslog-prefix", syslog_prefix, (char *)NULL);
    if (r) goto out;

    r = 0;

out:
    free(basedir);
    free(sockname);
    free(config_file);
    return r;
}

static int stop_daemon(int verbose, const char *mboxname)
{
    char *config_file = NULL;
    char *basedir = NULL;
    char *sockname = NULL;
    const char *syslog_prefix;
    int r;

    r = sphinx_paths_from_mboxname(mboxname, &basedir, &sockname);
    if (r) goto out;

    syslog_prefix = config_getstring(IMAPOPT_SYSLOG_PREFIX);
    if (!syslog_prefix)
	syslog_prefix = "cyrus";

    if (verbose)
	syslog(LOG_NOTICE, "Sphinx stopping searchd, "
			   "base directory %s socket %s",
			   basedir, sockname);

    config_file = strconcat(basedir, SPHINX_CONFIG, (char *)NULL);
    r = run_command(SEARCHD, "--config", config_file,
		    "--syslog-prefix", syslog_prefix,
		    "--stop", (char *)NULL);
    if (r) goto out;

    unlink(sockname);

    r = 0;

out:
    free(basedir);
    free(sockname);
    free(config_file);
    return r;
}

const struct search_engine sphinx_search_engine = {
    "Sphinx",
    0,
    search_sphinx,
    begin_update,
    end_update,
    start_daemon,
    stop_daemon
};

