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
#include "ptrarray.h"
#include "bitvector.h"
#include "mboxlist.h"
#include "xstats.h"
#include "search_engines.h"
#include "sphinxmgr_client.h"
#include "cyr_lock.h"

#include <mysql/mysql.h>

struct connection
{
    MYSQL *mysql;
    char *socket_path;
};
#define CONNECTION_INITIALIZER	{ 0, 0 }

struct latestdb
{
    struct db *db;
    char *path;
    char *config;
};
#define LATESTDB_INITIALIZER { 0, 0 }
#define LATESTDB_VERSION	1
#define LATESTDB_FNAME		"/latest.db"
#define LATESTDB_LASTID_KEY	"LASTID"


#define FMINDEX			"/usr/bin/fmindex"
/* This has to match the filename in the sphinx.conf
 * written in cyr_sphinxmgr.c */
#define FMINDEX_XML_FNAME	"/fmindex.xml"

#define INDEXING_LOCK_SUFFIX	".indexing.lock"

static int open_latest(struct mailbox *, struct latestdb *);
static void close_latest(struct latestdb *);
static int read_latest(struct latestdb *, struct mailbox *, uint32_t *, int);
static int write_latest(struct latestdb *, struct mailbox *, uint32_t, int);
static int doquery(struct connection *, int, const struct buf *);

/* Name of columns */
#define COL_CYRUSID	"cyrusid"
static const char * const column_by_part[SEARCH_NUM_PARTS] = {
    NULL,
    "header_from",
    "header_to",
    "header_cc",
    "header_bcc",
    "header_subject",
    "headers",
    "body"
};

static void close_connection(struct connection *conn)
{
    free(conn->socket_path);
    conn->socket_path = NULL;

    if (conn->mysql) {
	xstats_inc(SPHINX_CLOSE);
	mysql_close(conn->mysql);
	conn->mysql = NULL;
	mysql_library_end();
    }
}

static int get_connection(struct mailbox *mailbox, struct connection *conn)
{
    MYSQL *c = NULL;
    char *socket_path = NULL;
    int r;

    /* note, we always go through sphinxmgr even if
     * it's the same mboxname as last time - this lets
     * sphinxmgr know that the index daemon is being
     * used and so not to expire it */
    r = sphinxmgr_getsock(mailbox->name, &socket_path);
    if (r) return r;

    if (conn->socket_path && !strcmp(socket_path, conn->socket_path)) {
	free(socket_path);
	return IMAP_MAILBOX_EXISTS; /* evil error code repurposing */
    }

    close_connection(conn);

    xstats_inc(SPHINX_CONNECT);
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
	free(socket_path);
	return IMAP_IOERROR;
    }

    conn->socket_path = socket_path;
    conn->mysql = c;
    return 0;
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

/*
 * Escape a string for MySQL.  Note that mysql_real_escape_string
 * requires a live connection, and we now want to be able to build a
 * query string before we have a connection.  From the MySQL
 * documentation:
 *
 *	Strictly speaking, MySQL requires only that backslash and
 *	the quote character used to quote the string in the query
 *	be escaped. mysql_real_escape_string() quotes the other
 *	characters to make them easier to read in log files.
 *
 * Note that we need to escape a number of SphinxQL extended query
 * syntax metacharacters like ^ and $.
 */
static void append_escaped_map(struct buf *buf,
			       const char *base, unsigned int len,
			       int quote)
{
    static const char metacharacters[] = "!\"$'-/<=@[\\]^|~";
    buf_ensure(buf, len+1);

    buf_putc(buf, quote);
    for ( ; len ; len--, base++) {
	int c = *(unsigned char *)base;
	if (strchr(metacharacters, c))
	    buf_putc(buf, '\\');
	buf_putc(buf, c);
    }
    buf_putc(buf, quote);
    buf_cstring(buf);
}

static void append_escaped(struct buf *to, const struct buf *from, int quote)
{
    append_escaped_map(to, from->s, from->len, quote);
}

static void append_escaped_cstr(struct buf *to, const char *str, int quote)
{
    if (str)
	append_escaped_map(to, str, strlen(str), quote);
}

#define invalid_xml_char(c) \
    ((c) < 0x20 && !((c) == '\t' || (c) == '\n' || (c) == '\r'))

static void xml_escape_map(struct buf *buf,
			   const char *base, unsigned int len)
{
    buf_ensure(buf, len+1);

    for ( ; len ; len--, base++) {
	int c = *(unsigned char *)base;
	if (c == '<')
	    buf_appendcstr(buf, "&lt;");
	else if (c == '>')
	    buf_appendcstr(buf, "&gt;");
	else if (c == '&')
	    buf_appendcstr(buf, "&amp;");
	else if (!invalid_xml_char(c))
	    buf_putc(buf, c);
    }
    buf_cstring(buf);
}

static void xml_escape(struct buf *out, const struct buf *in)
{
    xml_escape_map(out, in->s, in->len);
}

struct opnode {
    int op;	/* SEARCH_OP_* or SEARCH_PART_* constant */
    char *arg;
    struct opnode *next;
    struct opnode *children;
};

typedef struct sphinx_builder sphinx_builder_t;
struct sphinx_builder {
    search_builder_t super;
    struct mailbox *mailbox;
    int opts;
    struct opnode *root;
    ptrarray_t stack;	    /* points to opnode* */
};

static struct opnode *opnode_new(int op, const char *arg)
{
    struct opnode *on = xzmalloc(sizeof(struct opnode));
    on->op = op;
    on->arg = xstrdupnull(arg);
    return on;
}

static void opnode_delete(struct opnode *on)
{
    struct opnode *child;
    struct opnode *next;

    for (child = on->children ; child ; child = next) {
	next = child->next;
	opnode_delete(child);
    }
    free(on->arg);
    free(on);
}

static void opnode_detach_child(struct opnode *parent, struct opnode *child)
{
    struct opnode **prevp;

    for (prevp = &parent->children ; *prevp ; prevp = &((*prevp)->next)) {
	if (*prevp == child) {
	    *prevp = child->next;
	    child->next = NULL;
	    return;
	}
    }
}

static void opnode_append_child(struct opnode *parent, struct opnode *child)
{
    struct opnode **tailp;

    for (tailp = &parent->children ; *tailp ; tailp = &((*tailp)->next))
	;
    *tailp = child;
    child->next = NULL;
}

static void opnode_insert_child(struct opnode *parent __attribute__((unused)),
				struct opnode *after,
				struct opnode *child)
{
    child->next = after->next;
    after->next = child;
}

static void begin_boolean(search_builder_t *bx, int op)
{
    sphinx_builder_t *bb = (sphinx_builder_t *)bx;
    struct opnode *top = ptrarray_tail(&bb->stack);
    struct opnode *on = opnode_new(op, NULL);
    if (top)
	opnode_append_child(top, on);
    else
	bb->root = on;
    ptrarray_push(&bb->stack, on);
    if (SEARCH_VERBOSE(bb->opts))
	syslog(LOG_INFO, "begin_boolean(op=%s)", search_op_as_string(op));
}

static void end_boolean(search_builder_t *bx, int op __attribute__((unused)))
{
    sphinx_builder_t *bb = (sphinx_builder_t *)bx;
    if (SEARCH_VERBOSE(bb->opts))
	syslog(LOG_INFO, "end_boolean");
    ptrarray_pop(&bb->stack);
}

static void match(search_builder_t *bx, int part, const char *str)
{
    sphinx_builder_t *bb = (sphinx_builder_t *)bx;
    struct opnode *top = ptrarray_tail(&bb->stack);
    struct opnode *on;

    if (!str) return;
    if (SEARCH_VERBOSE(bb->opts))
	syslog(LOG_INFO, "match(part=%s, str=\"%s\")",
	       search_part_as_string(part), str);

    xstats_inc(SPHINX_MATCH);

    on = opnode_new(part, str);
    if (top)
	opnode_append_child(top, on);
    else
	bb->root = on;
}

static void optimise_nodes(struct opnode *parent, struct opnode *on)
{
    struct opnode *child;
    struct opnode *next;

    switch (on->op) {
    case SEARCH_OP_NOT:
    case SEARCH_OP_OR:
    case SEARCH_OP_AND:
	for (child = on->children ; child ; child = next) {
	    next = child->next;
	    optimise_nodes(on, child);
	}
	if (parent) {
	    if (!on->children) {
		/* empty node - remove it */
		opnode_detach_child(parent, on);
		opnode_delete(on);
	    }
	    else if (on->op != SEARCH_OP_NOT && !on->children->next) {
		/* logical AND or OR with only one child - replace
		 * the node with its child */
		struct opnode *child = on->children;
		opnode_detach_child(on, child);
		opnode_insert_child(parent, on, child);
		opnode_detach_child(parent, on);
		opnode_delete(on);
	    }
	}
	break;
    }
}

/* Sphinx extended query syntax, not SphinxQL */
static void generate_query(struct buf *query,
			   struct opnode *on,
			   struct opnode *parent)
{
    struct opnode *child;
    struct buf arg = BUF_INITIALIZER;
    int need_paren;
    int sep;

    buf_init_ro_cstr(&arg, on->arg);

    switch (on->op) {

    case SEARCH_OP_NOT:
	if (on->children) buf_appendcstr(query, "!");
	/* fall through - note we treat multiple children to a NOT
	 * node as if they were ANDed together because that's the
	 * closest match to IMAP semantics. */
    case SEARCH_OP_OR:
    case SEARCH_OP_AND:

	need_paren = 0;
	if (parent && parent->op > on->op)
	    need_paren = 1;
	if (on->op == SEARCH_OP_NOT)
	    need_paren = 1;
	/* Note that we might have 0, 1, or >1 children, the caller will
	 * not have optimised the silly cases out. */
	if (!on->children || !on->children->next)
	    need_paren = 0;

	sep = (on->op == SEARCH_OP_OR ? '|' : ' ');

	if (need_paren) buf_putc(query, '(');
	for (child = on->children ; child ; child = child->next) {
	    generate_query(query, child, on);
	    if (child->next) buf_putc(query, sep);
	}
	if (need_paren) buf_putc(query, ')');
	break;

    case SEARCH_PART_ANY:
	assert(on->children == NULL);
	if (config_getswitch(IMAPOPT_SPHINX_TEXT_EXCLUDES_ODD_HEADERS)) {
	    /* This horrible hack makes TEXT searches match FROM, TO, CC, BCC
	     * and SUBJECT but not any other random headers, which is more
	     * like what users expect. */
	    int i;
	    const char *sep = "(";
	    buf_appendcstr(query, "@");
	    for (i = 0 ; i < SEARCH_NUM_PARTS ; i++) {
		if (column_by_part[i] && i != SEARCH_PART_HEADERS) {
		    buf_appendcstr(query, sep);
		    buf_appendcstr(query, column_by_part[i]);
		    sep = ",";
		}
	    }
	    buf_appendcstr(query, ") ");
	}
	append_escaped(query, &arg, '"');
	break;

    default:
	/* other SEARCH_PART_* constants */
	assert(on->op >= 0 && on->op < SEARCH_NUM_PARTS);
	assert(on->children == NULL);
	buf_appendcstr(query, "@");
	buf_appendcstr(query, column_by_part[on->op]);
	buf_appendcstr(query, " ");
	append_escaped(query, &arg, '"');
	break;
    }

    buf_free(&arg);
}

static void *get_internalised(search_builder_t *bx)
{
    sphinx_builder_t *bb = (sphinx_builder_t *)bx;
    struct opnode *on = bb->root;
    bb->root = NULL;
    optimise_nodes(NULL, on);
    return on;
}

char *describe_internalised(void *internalised)
{
    struct opnode *on = (struct opnode *)internalised;
    struct buf buf = BUF_INITIALIZER;

    generate_query(&buf, on, NULL);
    return buf_release(&buf);
}

static void free_internalised(void *internalised)
{
    struct opnode *on = (struct opnode *)internalised;
    if (on) opnode_delete(on);
}

static int run(search_builder_t *bx, search_hit_cb_t proc, void *rock);

static search_builder_t *begin_search(struct mailbox *mailbox, int opts)
{
    sphinx_builder_t *bb;

    bb = xzmalloc(sizeof(sphinx_builder_t));
    bb->super.begin_boolean = begin_boolean;
    bb->super.end_boolean = end_boolean;
    bb->super.match = match;
    bb->super.get_internalised = get_internalised;
    bb->super.run = run;

    bb->mailbox = mailbox;
    bb->opts = opts;

    if ((opts & SEARCH_MULTIPLE))
	xstats_inc(SPHINX_MULTIPLE);
    else
	xstats_inc(SPHINX_SINGLE);

    return &bb->super;
}

static int run(search_builder_t *bx, search_hit_cb_t proc, void *rock)
{
    sphinx_builder_t *bb = (sphinx_builder_t *)bx;
    struct connection conn = CONNECTION_INITIALIZER;
    struct buf query = BUF_INITIALIZER;	/* SphinxQL query */
    struct buf inner_query = BUF_INITIALIZER;	/* Sphinx extended match syntax  */
    MYSQL_RES *res = NULL;
    MYSQL_ROW row;
    uint32_t uid;
    uint32_t latest = 0;
    int r = 0;

    r = get_connection(bb->mailbox, &conn);
    if (r == IMAP_MAILBOX_EXISTS) r = 0; /* we're reusing one */
    if (r) goto out;

    if ((bb->opts & SEARCH_UNINDEXED)) {
	/* To avoid races, we want the 'latest' uid we use to be
	 * an underestimate, because the caller can handle false
	 * positives but not false negatives.  So we fetch it
	 * first before the main query. */
	struct latestdb ldb = LATESTDB_INITIALIZER;
	r = open_latest(bb->mailbox, &ldb);
	if (!r) goto out;
	r = read_latest(&ldb, bb->mailbox, &latest,
			SEARCH_VERBOSE(bb->opts));
	close_latest(&ldb);
	if (r) goto out;
    }

    optimise_nodes(NULL, bb->root);
    generate_query(&inner_query, bb->root, NULL);

    buf_init_ro_cstr(&query, "SELECT "COL_CYRUSID" FROM rt WHERE MATCH(");
    append_escaped(&query, &inner_query, '\'');
    buf_appendcstr(&query, ")");
    // get sphinx to sort by most recent date first
    buf_appendcstr(&query, " ORDER BY "COL_CYRUSID" DESC "
			       " LIMIT " SPHINX_MAX_MATCHES
			       " OPTION max_matches=" SPHINX_MAX_MATCHES);
    buf_cstring(&query);

    if (SEARCH_VERBOSE(bb->opts))
	syslog(LOG_NOTICE, "Sphinx query %s", query.s);
    xstats_inc(SPHINX_QUERY);

    r = mysql_real_query(conn.mysql, query.s, query.len);
    if (r) {
	syslog(LOG_ERR, "IOERROR: Sphinx query %s failed: %s",
	       query.s, mysql_error(conn.mysql));
	r = IMAP_IOERROR;
	goto out;
    }

    res = mysql_use_result(conn.mysql);
    while ((row = mysql_fetch_row(res))) {
	const char *mboxname;
	unsigned int uidvalidity;
	unsigned int uid;
	if (SEARCH_VERBOSE(bb->opts) > 1)
	    syslog(LOG_NOTICE, "Sphinx row cyrusid=%s", row[0]);
	xstats_inc(SPHINX_ROW);
	if (!parse_cyrusid(row[0], &mboxname, &uidvalidity, &uid))
	    // TODO: whine
	    continue;
	if (!(bb->opts & SEARCH_MULTIPLE)) {
	    if (strcmp(mboxname, bb->mailbox->name))
		continue;
	    if (uidvalidity != bb->mailbox->i.uidvalidity)
		continue;
	}
	xstats_inc(SPHINX_RESULT);
	r = proc(mboxname, uidvalidity, uid, rock);
	if (r) goto out;
    }
    r = 0;

    if ((bb->opts & SEARCH_UNINDEXED)) {
	/* add in the unindexed uids as false positives */
	for (uid = latest+1 ; uid <= bb->mailbox->i.last_uid ; uid++) {
	    xstats_inc(SPHINX_UNINDEXED);
	    r = proc(bb->mailbox->name, bb->mailbox->i.uidvalidity, uid, rock);
	    if (r) goto out;
	}
    }

out:
    if (res) mysql_free_result(res);
    close_connection(&conn);
    buf_free(&query);
    buf_free(&inner_query);
    return r;
}

static void end_search(search_builder_t *bx)
{
    sphinx_builder_t *bb = (sphinx_builder_t *)bx;

    ptrarray_fini(&bb->stack);
    if (bb->root) opnode_delete(bb->root);
    free(bx);
}

/* base class for both update and snippet receivers */
typedef struct sphinx_receiver sphinx_receiver_t;
struct sphinx_receiver
{
    search_text_receiver_t super;
    int verbose;
    struct mailbox *mailbox;
    uint32_t uid;
    int part;
    unsigned int parts_total;
    int truncate_warning;
    struct buf parts[SEARCH_NUM_PARTS];
    struct buf tmp;		/* SphinxQL query */
};

/* receiver used for updating the index */
typedef struct sphinx_update_receiver sphinx_update_receiver_t;
struct sphinx_update_receiver
{
    sphinx_receiver_t super;
    int indexing_lock_fd;
    unsigned int uncommitted;
    uint32_t latest;
    struct latestdb latestdb;
    uint32_t lastid;	    /* largest document ID in the 'tr' table,
			     * used to assign new document IDs when
			     * INSERTing into the table */
};

/* receiver used for extracting snippets after a search */
typedef struct sphinx_snippet_receiver sphinx_snippet_receiver_t;
struct sphinx_snippet_receiver
{
    sphinx_receiver_t super;
    struct connection conn;
    struct opnode *root;
    search_snippet_cb_t proc;
    void *rock;
};

/* This is carefully aligned with the default search_batchsize so that
 * we get the minimum number of commits with default parameters */
#define MAX_UNCOMMITTED	    20

/* Maximum size of a query, determined empirically, is a little bit
 * under 8MB.  That seems like more than enough, so let's limit the
 * total amount of parts text to 4 MB. */
#define MAX_PARTS_SIZE	    (4*1024*1024)

static const char *describe_query(struct buf *desc,
				  const struct buf *query,
				  unsigned maxlen)
{
    buf_reset(desc);
    buf_appendcstr(desc, "Sphinx query ");
    if (maxlen && query->len > maxlen) {
	buf_appendmap(desc, query->s, maxlen);
	buf_appendcstr(desc, "...");
    }
    else {
	buf_append(desc, query);
    }
    return buf_cstring(desc);
}

static int doquery(struct connection *conn, int verbose, const struct buf *query)
{
    int r;
    struct buf desc = BUF_INITIALIZER;
    unsigned int maxlen = verbose > 2 ? /*unlimited*/0 : 128;

    if (verbose > 1)
	syslog(LOG_NOTICE, "%s", describe_query(&desc, query, maxlen));

    r = mysql_real_query(conn->mysql, query->s, query->len);
    if (r) {
	syslog(LOG_ERR, "IOERROR: %s failed: %s",
			describe_query(&desc, query, maxlen),
			mysql_error(conn->mysql));
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

static int open_latest(struct mailbox *mailbox, struct latestdb *ldb)
{
    char *config = NULL;
    char *p;
    char *path = NULL;
    int r;

    /* note, we always go through sphinxmgr so that it can
     * prepare the directory if necessary */
    r = sphinxmgr_getconf(mailbox->name, &config);
    if (r) return r;

    /* temporarily chop off the filename component of the config path */
    p = strrchr(config, '/');
    assert(p != NULL);	/* should always be an absolute path */
    *p = '\0';
    path = strconcat(config, LATESTDB_FNAME, NULL);
    *p = '/';

    if (!strcmpsafe(path, ldb->path)) {
	free(path);
	free(config);
	return 0;
    }

    /* need to open a new DB */

    close_latest(ldb);

    r = cyrusdb_open(config_getstring(IMAPOPT_SEARCH_LATEST_DB),
		     path, CYRUSDB_CREATE, &ldb->db);
    if (r) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s",
	       path, cyrusdb_strerror(r));
	r = IMAP_IOERROR;
    }

out:
    if (r) {
	free(path);
	free(config);
    }
    else {
	ldb->path = path;
	ldb->config = config;
    }
    return r;
}

static void close_latest(struct latestdb *ldb)
{
    free(ldb->path);
    ldb->path = NULL;

    free(ldb->config);
    ldb->config = NULL;

    if (ldb->db) {
	cyrusdb_close(ldb->db);
	ldb->db = NULL;
    }
}

/*
 * Read the most recently indexed UID for the current mailboxfrom the
 * 'latest' DB in the Sphinx directory.
 * Returns 0 on success or an IMAP error code.
 */
static int read_latest(struct latestdb *ldb,
		       struct mailbox *mailbox,
		       uint32_t *latestp,
		       int verbose)
{
    struct buf key = BUF_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    const char *data = NULL;
    size_t datalen = 0;
    int r = 0;
    unsigned int version = 0;
    unsigned int uid = 0;

    *latestp = 0;
    if (verbose > 1)
	syslog(LOG_INFO, "read_latest db=%s mailbox=%s uidvalidity=%u",
	       ldb->path, mailbox->name, mailbox->i.uidvalidity);

    buf_printf(&key, "%s.%u", mailbox->name, mailbox->i.uidvalidity);

    r = cyrusdb_fetch(ldb->db,
		      key.s, key.len,
		      &data, &datalen,
		      (struct txn **)NULL);
    if (r == CYRUSDB_NOTFOUND) {
	if (verbose > 1) syslog(LOG_INFO, "read_latest defaults to 0");
	r = 0;
	goto out;
    }
    if (r) goto out;
    buf_init_ro(&buf, data, datalen);
    buf_cstring(&buf);

    r = sscanf(buf.s, "%u %u", &version, &uid);
    if (r != 2 || version != LATESTDB_VERSION) {
	r = IMAP_MAILBOX_BADFORMAT;
	goto out;
    }

    if (verbose > 1) syslog(LOG_INFO, "read_latest uid=%u", uid);
    *latestp = uid;
    r = 0;

out:
    buf_free(&key);
    buf_free(&buf);
    return r;
}

static int write_latest(struct latestdb *ldb,
			struct mailbox *mailbox,
			uint32_t uid,
			int verbose)
{
    struct buf key = BUF_INITIALIZER;
    struct buf data = BUF_INITIALIZER;
    struct txn *txn = NULL;
    int r = 0;

    if (verbose)
	syslog(LOG_INFO, "write_latest db=%s mailbox=%s uidvalidity=%u uid=%u",
	       ldb->path, mailbox->name, mailbox->i.uidvalidity, uid);

    buf_printf(&key, "%s.%u", mailbox->name, mailbox->i.uidvalidity);
    buf_printf(&data, "%u %u", LATESTDB_VERSION, uid);

    do {
	r = cyrusdb_store(ldb->db,
			  key.s, key.len,
			  data.s, data.len,
			  &txn);
    } while (r == CYRUSDB_AGAIN);
    if (!r)
	r = cyrusdb_commit(ldb->db, txn);
    else
	cyrusdb_abort(ldb->db, txn);

    buf_free(&data);
    buf_free(&key);
    return r;
}

/*
 * Read the last document ID from the "latest" DB.  This is a
 * temporary measure until we can get autoincrement behaviour
 * working for Sphinx.
 *
 * Returns: 0 on success or an IMAP error code.
 */
static int read_lastid(struct latestdb *ldb,
		       uint32_t *lastidp,
		       int verbose)
{
    struct buf key = BUF_INITIALIZER;
    struct buf buf = BUF_INITIALIZER;
    const char *data = NULL;
    size_t datalen = 0;
    int r = 0;
    unsigned int version = 0;
    unsigned int id = 0;

    *lastidp = 0;
    if (verbose > 1) syslog(LOG_INFO, "read_lastid db=%s", ldb->path);

    buf_init_ro_cstr(&key, LATESTDB_LASTID_KEY);

    r = cyrusdb_fetch(ldb->db,
		      key.s, key.len,
		      &data, &datalen,
		      (struct txn **)NULL);
    if (r == CYRUSDB_NOTFOUND) {
	if (verbose > 1) syslog(LOG_INFO, "read_lastid defaults to 0");
	r = 0;
	goto out;
    }
    if (r) goto out;
    buf_init_ro(&buf, data, datalen);
    buf_cstring(&buf);

    r = sscanf(buf.s, "%u %u", &version, &id);
    if (r != 2 || version != LATESTDB_VERSION) {
	r = IMAP_MAILBOX_BADFORMAT;
	goto out;
    }

    if (verbose > 1) syslog(LOG_INFO, "read_lastid id=%u", id);
    *lastidp = id;
    r = 0;

out:
    buf_free(&key);
    buf_free(&buf);
    return r;
}

static int write_lastid(struct latestdb *ldb,
			uint32_t lastid,
			int verbose)
{
    struct buf key = BUF_INITIALIZER;
    struct buf data = BUF_INITIALIZER;
    struct txn *txn = NULL;
    int r = 0;

    if (verbose > 1)
	syslog(LOG_INFO, "write_lastid db=%s lastid=%u", ldb->path, lastid);

    buf_init_ro_cstr(&key, LATESTDB_LASTID_KEY);
    buf_printf(&data, "%u %u", LATESTDB_VERSION, lastid);

    do {
	r = cyrusdb_store(ldb->db,
			  key.s, key.len,
			  data.s, data.len,
			  &txn);
    } while (r == CYRUSDB_AGAIN);
    if (!r)
	r = cyrusdb_commit(ldb->db, txn);
    else
	cyrusdb_abort(ldb->db, txn);


    buf_free(&data);
    buf_free(&key);
    return r;
}

static int flush(sphinx_update_receiver_t *tr, int force)
{
    int r = 0;
    char *xmlfile = NULL;
    char *sphinxdir;
    char *p;
    int fd;
    static const char prologue[] =
	"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
	"<sphinx:docset>\n";
    static const char epilogue[] =
	"</sphinx:docset>\n";

    if (!force && tr->uncommitted < MAX_UNCOMMITTED) return 0;
    if (!tr->uncommitted) return 0;

    /* We write the lastid out first, to avoid a future instance
     * allocating a duplicate Sphinx document id should we crash */
    r = write_lastid(&tr->latestdb, tr->lastid, tr->super.verbose);
    if (r) return r;

    if (tr->super.verbose > 1)
	syslog(LOG_NOTICE, "Sphinx sending to fmindex");
    if (tr->super.verbose > 3) {
	fwrite(prologue, 1, sizeof(prologue)-1, stderr);
	fwrite(tr->super.tmp.s, 1, tr->super.tmp.len, stderr);
	fwrite(epilogue, 1, sizeof(epilogue)-1, stderr);
    }

    sphinxdir = xstrdup(tr->latestdb.config);
    p = strrchr(sphinxdir, '/');
    assert(p != NULL);
    *p = '\0';
    xmlfile = strconcat(sphinxdir, FMINDEX_XML_FNAME, (char *) NULL);
    free(sphinxdir);

    fd = open(xmlfile, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) {
	syslog(LOG_ERR, "Failed to open %s: %m", xmlfile);
	goto out;
    }
    r = retry_write(fd, prologue, sizeof(prologue)-1);
    if (r > 0) retry_write(fd, tr->super.tmp.s, tr->super.tmp.len);
    if (r > 0) retry_write(fd, epilogue, sizeof(epilogue)-1);
    if (r < 0) {
	syslog(LOG_ERR, "Failed to write %s: %m", xmlfile);
	close(fd);
	goto out;
    }
    close(fd);

    r = run_command(FMINDEX, "--config", tr->latestdb.config, "rt", NULL);
    if (r) {
	syslog(LOG_ERR, "IOERROR: Sphinx "FMINDEX" failed for "
			"mailbox %s, %u messages ending at uid %u: %s",
			tr->super.mailbox->name,
			tr->uncommitted,
			tr->super.uid,
			error_message(r));
	r = IMAP_IOERROR;
	goto out;
    }

    /* We write out the latestid for the mailbox only after successfully
     * updating the index, to avoid a future instance not realising that
     * there are unindexed messages should we fail to index */
    r = write_latest(&tr->latestdb, tr->super.mailbox, tr->latest,
		     tr->super.verbose);
    if (r) goto out;

    tr->uncommitted = 0;
    buf_reset(&tr->super.tmp);

out:
    if (xmlfile) {
	if (r) {
	    /* failed, leave the xmlfile around for debugging */
	    char *x2;
	    struct timeval now;
	    char stamp[64];
	    gettimeofday(&now, NULL);
	    snprintf(stamp, sizeof(stamp), "%u.%06u",
		    (unsigned)now.tv_sec, (unsigned)now.tv_usec);
	    x2 = strconcat(xmlfile, stamp, NULL);
	    rename(xmlfile, x2);
	    syslog(LOG_INFO, "Saved XML as %s", x2);
	    free(x2);
	}
	else
	    unlink(xmlfile);
    }
    free(xmlfile);
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

static int end_message_update(search_text_receiver_t *rx)
{
    sphinx_update_receiver_t *tr = (sphinx_update_receiver_t *)rx;
    struct buf *xml = &tr->super.tmp;
    int i;
    int r;

    buf_printf(xml, "<sphinx:document id=\"%u\">\n", ++tr->lastid);

    buf_printf(xml, "<cyrusid>");
    xml_escape(xml, make_cyrusid(tr->super.mailbox, tr->super.uid));
    buf_printf(xml, "</cyrusid>\n");

    for (i = 0 ; i < SEARCH_NUM_PARTS ; i++) {
	if (tr->super.parts[i].len) {
	    buf_printf(xml, "<%s>", column_by_part[i]);
	    xml_escape(xml, &tr->super.parts[i]);
	    buf_printf(xml, "</%s>\n", column_by_part[i]);
	}
    }

    buf_printf(xml, "</sphinx:document>\n");

    ++tr->uncommitted;
    tr->latest = tr->super.uid;

    r = flush(tr, /*force*/0);

out:
    tr->super.uid = 0;
    return r;
}

static const char *indexing_lockpath(struct mailbox *mailbox)
{
    char *usermbox = mboxname_user_mbox(mboxname_to_userid(mailbox->name), NULL);
    const char *lockpath = mboxname_lockpath_suffix(usermbox, INDEXING_LOCK_SUFFIX);
    free(usermbox);
    return lockpath;
}

static void indexing_unlock(int *fdp)
{
    if (*fdp >= 0) {
	close(*fdp);
	*fdp = -1;
    }
}

static int indexing_lock(struct mailbox *mailbox, int *fdp)
{
    const char *lockpath = indexing_lockpath(mailbox);
    int fd;
    int r;

    indexing_unlock(fdp);

    fd = open(lockpath, O_WRONLY|O_CREAT, 0600);
    if (fd < 0) {
	if (cyrus_mkdir(lockpath, 0755) < 0) {
	    syslog(LOG_ERR, "IOERROR: unable to cyrus_mkdir %s: %m", lockpath);
	    return IMAP_IOERROR;
	}
	fd = open(lockpath, O_WRONLY|O_CREAT, 0600);
    }
    if (fd < 0) {
	syslog(LOG_ERR, "IOERROR: unable to create %s: %m", lockpath);
	return IMAP_IOERROR;
    }

    r = lock_blocking(fd, lockpath);
    if (r < 0) {
	syslog(LOG_ERR, "IOERROR: unable to lock %s: %m",
		lockpath);
	close(fd);
	return IMAP_IOERROR;
    }

    *fdp = fd;
    return 0;
}

static int begin_mailbox_update(search_text_receiver_t *rx,
				struct mailbox *mailbox,
				int incremental __attribute__((unused)))
{
    sphinx_update_receiver_t *tr = (sphinx_update_receiver_t *)rx;
    int r;

    tr->super.mailbox = mailbox;

    r = indexing_lock(mailbox, &tr->indexing_lock_fd);
    if (r) return r;

    r = open_latest(mailbox, &tr->latestdb);
    if (r) return r;

    r = read_lastid(&tr->latestdb, &tr->lastid, tr->super.verbose);
    if (r) return r;

    r = read_latest(&tr->latestdb, mailbox, &tr->latest, tr->super.verbose);
    if (r) return r;

    return 0;
}

static uint32_t first_unindexed_uid(search_text_receiver_t *rx)
{
    sphinx_update_receiver_t *tr = (sphinx_update_receiver_t *)rx;

    return tr->latest+1;
}

static int is_indexed(search_text_receiver_t *rx, uint32_t uid)
{
    sphinx_update_receiver_t *tr = (sphinx_update_receiver_t *)rx;

    return (uid <= tr->latest);
}

static int end_mailbox_update(search_text_receiver_t *rx,
			      struct mailbox *mailbox
			    __attribute__((unused)))
{
    sphinx_update_receiver_t *tr = (sphinx_update_receiver_t *)rx;
    int r = 0;

    r = flush(tr, /*force*/1);

    tr->super.mailbox = NULL;

    return r;
}

static search_text_receiver_t *begin_update(int verbose)
{
    sphinx_update_receiver_t *tr;

    tr = xzmalloc(sizeof(sphinx_update_receiver_t));
    tr->super.super.begin_mailbox = begin_mailbox_update;
    tr->super.super.first_unindexed_uid = first_unindexed_uid;
    tr->super.super.is_indexed = is_indexed;
    tr->super.super.begin_message = begin_message;
    tr->super.super.begin_part = begin_part;
    tr->super.super.append_text = append_text;
    tr->super.super.end_part = end_part;
    tr->super.super.end_message = end_message_update;
    tr->super.super.end_mailbox = end_mailbox_update;

    tr->indexing_lock_fd = -1;
    tr->super.verbose = verbose;

    return &tr->super.super;
}

static int free_receiver(sphinx_receiver_t *tr)
{
    int i;
    int r = 0;

    for (i = 0 ; i < SEARCH_NUM_PARTS ; i++)
	buf_free(&tr->parts[i]);
    buf_free(&tr->tmp);

    free(tr);

    return r;
}

static int end_update(search_text_receiver_t *rx)
{
    sphinx_update_receiver_t *tr = (sphinx_update_receiver_t *)rx;

    close_latest(&tr->latestdb);
    indexing_unlock(&tr->indexing_lock_fd);
    return free_receiver(&tr->super);
}

static int begin_mailbox_snippets(search_text_receiver_t *rx,
				  struct mailbox *mailbox,
				  int incremental __attribute__((unused)))
{
    sphinx_snippet_receiver_t *tr = (sphinx_snippet_receiver_t *)rx;
    int r;

    r = get_connection(mailbox, &tr->conn);
    if (r == IMAP_MAILBOX_EXISTS) r = 0; /* we're reusing one */
    if (r) return r;

    tr->super.mailbox = mailbox;

    return 0;
}

/* Generate Sphinx extended query syntax, not SphinxQL, customised for
 * using CALL SNIPPETS.  This differs from the regular query because
 * CALL SNIPPETS will silently ignore @field modifiers instead of
 * enforcing them.  So we have to emit one CALL SNIPPETS for every
 * field that may be mentioned in the original query, with a munged
 * query that contains a disjunction of all the search terms that
 * might apply to that part.  Thanks heaps Sphinx. [IRIS-2038] */
static void generate_snippet_query(struct buf *query,
				   int part,
				   struct opnode *on)
{
    struct opnode *child;
    struct buf arg = BUF_INITIALIZER;

    buf_init_ro_cstr(&arg, on->arg);

    switch (on->op) {

    case SEARCH_OP_NOT:
    case SEARCH_OP_OR:
    case SEARCH_OP_AND:
	for (child = on->children ; child ; child = child->next)
	    generate_snippet_query(query, part, child);
	break;

    case SEARCH_PART_ANY:
	assert(on->children == NULL);
	if (part != SEARCH_PART_HEADERS ||
	    !config_getswitch(IMAPOPT_SPHINX_TEXT_EXCLUDES_ODD_HEADERS)) {
	    if (query->len) buf_putc(query, '|');
	    append_escaped(query, &arg, '"');
	}
	break;

    default:
	/* other SEARCH_PART_* constants */
	assert(on->op >= 0 && on->op < SEARCH_NUM_PARTS);
	assert(on->children == NULL);
	if (part == on->op) {
	    if (query->len) buf_putc(query, '|');
	    append_escaped(query, &arg, '"');
	}
	break;
    }

    buf_free(&arg);
}

static int end_message_snippets(search_text_receiver_t *rx)
{
    sphinx_snippet_receiver_t *tr = (sphinx_snippet_receiver_t *)rx;
    struct buf query = BUF_INITIALIZER;
    struct buf inner_query = BUF_INITIALIZER;
    MYSQL_RES *res = NULL;
    MYSQL_ROW row;
    int i;
    int r;

    if (!tr->conn.mysql) {
	r = IMAP_INTERNAL;	    /* need to call begin_mailbox() */
	goto out;
    }
    if (!tr->root) {
	r = 0;
	goto out;
    }

    for (i = 0 ; i < SEARCH_NUM_PARTS ; i++) {
	if (res) {
	    mysql_free_result(res);
	    res = NULL;
	}
	if (i == SEARCH_PART_ANY) continue;

	if (!tr->super.parts[i].len) continue;

	buf_reset(&inner_query);
	generate_snippet_query(&inner_query, i, tr->root);
	if (!inner_query.len) continue;

	buf_reset(&query);
	buf_appendcstr(&query, "CALL SNIPPETS(");
	append_escaped(&query, &tr->super.parts[i], '\'');
	buf_appendcstr(&query, ", 'rt', ");
	append_escaped(&query, &inner_query, '\'');
	buf_appendcstr(&query, ", 1 AS query_mode, 1 AS allow_empty)");

	r = doquery(&tr->conn, tr->super.verbose, &query);
	if (r) goto out;

	res = mysql_store_result(tr->conn.mysql);
	if (!res) continue;

	row = mysql_fetch_row(res);
	if (!row) continue;

	if (tr->super.verbose > 1)
	    syslog(LOG_ERR, "snippet [%d] \"%s\"", i, row[0]);

	if (!row[0][0]) continue;
	r = tr->proc(tr->super.mailbox, tr->super.uid, i, row[0], tr->rock);
	if (r) break;
    }

out:
    if (res) mysql_free_result(res);
    buf_free(&query);
    buf_free(&inner_query);
    return r;
}

static int end_mailbox_snippets(search_text_receiver_t *rx,
				struct mailbox *mailbox
				    __attribute__((unused)))
{
    sphinx_snippet_receiver_t *tr = (sphinx_snippet_receiver_t *)rx;

    tr->super.mailbox = NULL;

    return 0;
}

static search_text_receiver_t *begin_snippets(void *internalised,
					      int verbose,
					      search_snippet_cb_t proc,
					      void *rock)
{
    sphinx_snippet_receiver_t *tr;

    tr = xzmalloc(sizeof(sphinx_snippet_receiver_t));
    tr->super.super.begin_mailbox = begin_mailbox_snippets;
    tr->super.super.begin_message = begin_message;
    tr->super.super.begin_part = begin_part;
    tr->super.super.append_text = append_text;
    tr->super.super.end_part = end_part;
    tr->super.super.end_message = end_message_snippets;
    tr->super.super.end_mailbox = end_mailbox_snippets;

    tr->super.verbose = verbose;
    tr->root = (struct opnode *)internalised;
    tr->proc = proc;
    tr->rock = rock;

    return &tr->super.super;
}

static int end_snippets(search_text_receiver_t *rx)
{
    sphinx_snippet_receiver_t *tr = (sphinx_snippet_receiver_t *)rx;

    close_connection(&tr->conn);
    return free_receiver(&tr->super);
}

static int start_daemon(int verbose __attribute__((unused)),
			const char *mboxname)
{
    char *socket_path = NULL;
    int r;

    r = sphinxmgr_getsock(mboxname, &socket_path);
    if (r) return r;

    free(socket_path);
    return 0;
}

static int stop_daemon(int verbose __attribute__((unused)),
		       const char *mboxname)
{
    return sphinxmgr_stop(mboxname);
}

const struct search_engine sphinx_search_engine = {
    "Sphinx",
    SEARCH_FLAG_CAN_BATCH,
    begin_search,
    end_search,
    begin_update,
    end_update,
    begin_snippets,
    end_snippets,
    describe_internalised,
    free_internalised,
    start_daemon,
    stop_daemon
};

