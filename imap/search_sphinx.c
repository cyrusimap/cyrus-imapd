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

#include <errno.h>
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
#include "cyr_lock.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"
#include "imap/imap_err.h"

#include <mysql/mysql.h>

struct connection
{
    MYSQL *mysql;
};
#define CONNECTION_INITIALIZER  { 0 }

struct latestdb
{
    struct db *db;
    char *path;
};
#define LATESTDB_INITIALIZER { 0, 0 }
#define LATESTDB_VERSION        1
#define LATESTDB_FNAME          "/latest.db"
#define LATESTDB_LASTID_KEY     "LASTID"

#define SPHINX_CONFIG       "/sphinx.conf"
#define SEARCHD             "/usr/bin/searchd"

#define INDEXING_LOCK_SUFFIX    ".indexing.lock"

static int open_latest(struct mailbox *, struct latestdb *);
static void close_latest(struct latestdb *);
static int read_latest(struct latestdb *, struct mailbox *, uint32_t *, int);
static int write_latest(struct latestdb *, struct mailbox *, uint32_t, int);
static int doquery(struct connection *, int, const struct buf *);
static int sphinx_basedir(const struct mailbox *mailbox, char **basedirp, char **indexnamep);
static int sphinx_setup(const struct mailbox *mailbox, int verbose, int create);

/* Name of columns */
#define COL_CYRUSID     "cyrusid"
static const char * const column_by_part[SEARCH_NUM_PARTS] = {
    NULL,
    "header_from",
    "header_to",
    "header_cc",
    "header_bcc",
    "header_subject",
    "header_listid",
    "header_type",
    "headers",
    "body",
    "location"
};

static void close_connection(struct connection *conn)
{
    if (conn->mysql) {
        xstats_inc(SPHINX_CLOSE);
        mysql_close(conn->mysql);
        conn->mysql = NULL;
        mysql_library_end();
    }
}

static int get_connection(struct connection *conn)
{
    MYSQL *c = NULL;
    const char *socket_path = config_getstring(IMAPOPT_SPHINX_SOCKET);

    if (conn->mysql) return 0;      /* already open */

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
        return IMAP_IOERROR;
    }

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
 *      Strictly speaking, MySQL requires only that backslash and
 *      the quote character used to quote the string in the query
 *      be escaped. mysql_real_escape_string() quotes the other
 *      characters to make them easier to read in log files.
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

struct opnode {
    int op;     /* SEARCH_OP_* or SEARCH_PART_* constant */
    char *arg;
    struct opnode *next;
    struct opnode *children;
};

typedef struct sphinx_builder sphinx_builder_t;
struct sphinx_builder {
    search_builder_t super;
    struct mailbox *mailbox;
    char *indexname;
    int opts;
    struct opnode *root;
    ptrarray_t stack;       /* points to opnode* */
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

static char *describe_internalised(void *internalised)
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
    int r;

    bb = xzmalloc(sizeof(sphinx_builder_t));
    bb->super.begin_boolean = begin_boolean;
    bb->super.end_boolean = end_boolean;
    bb->super.match = match;
    bb->super.get_internalised = get_internalised;
    bb->super.run = run;

    bb->mailbox = mailbox;
    bb->opts = opts;

    r = sphinx_basedir(mailbox, NULL, &bb->indexname);
    if (r) {
        free(bb);
        return NULL;
    }

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
    struct buf query = BUF_INITIALIZER; /* SphinxQL query */
    struct buf inner_query = BUF_INITIALIZER;   /* Sphinx extended match syntax  */
    MYSQL_RES *res = NULL;
    MYSQL_ROW row;
    uint32_t uid;
    uint32_t latest = 0;
    int r = 0;

    r = sphinx_setup(bb->mailbox, SEARCH_VERBOSE(bb->opts), /*create*/0);
    if (r == IMAP_NOTFOUND) {
        /* there's no index for this user */
        r = 0;
        goto out;
    }
    if (r) goto out;

    r = get_connection(&conn);
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

    buf_printf(&query, "SELECT "COL_CYRUSID" FROM %s WHERE MATCH(", bb->indexname);
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
    free(bb->indexname);
    free(bx);
}

/* base class for both update and snippet receivers */
typedef struct sphinx_receiver sphinx_receiver_t;
struct sphinx_receiver
{
    search_text_receiver_t super;
    int verbose;
    struct mailbox *mailbox;
    char *indexname;
    uint32_t uid;
    int part;
    unsigned int parts_total;
    int truncate_warning;
    struct buf parts[SEARCH_NUM_PARTS];
    struct buf tmp;             /* SphinxQL query */
};

/* receiver used for updating the index */
typedef struct sphinx_update_receiver sphinx_update_receiver_t;
struct sphinx_update_receiver
{
    sphinx_receiver_t super;
    struct connection conn;
    int indexing_lock_fd;
    unsigned int uncommitted;
    uint32_t latest;
    struct latestdb latestdb;
    uint32_t lastid;        /* largest document ID in the 'tr' table,
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

/* Maximum size of a query, determined empirically, is a little bit
 * under 8MB.  That seems like more than enough, so let's limit the
 * total amount of parts text to 4 MB. */
#define MAX_PARTS_SIZE      (4*1024*1024)

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
    mysql_data_seek(res, 0);    /* rewind */
}
#endif

static const char *sphinx_config_file(void)
{
    static const char *config_file = NULL;

    if (!config_file)
        config_file = strconcat(config_dir, SPHINX_CONFIG, (char *)NULL);
    return config_file;
}

static const char *sphinx_rootdir(const char *partition)
{
    char *confkey;
    const char *root;
    if (!partition)
        partition = config_getstring(IMAPOPT_DEFAULTPARTITION);
    confkey = strconcat("searchpartition-", partition, NULL);
    root = config_getoverflowstring(confkey, NULL);
    free(confkey);
    return root;
}

/* When building an index name we need to escape any @ or . characters
 * in the username.  We're slightly more general than that.  */
static void z_escape(struct buf *buf, const char *s)
{
    for ( ; *s ; s++) {
        if (*s == 'Z' || !Uisalnum(*s))
            buf_printf(buf, "Z%02X", *(const unsigned char *)s);
        else
            buf_putc(buf, *s);
    }
}

/* Returns in *basedir and *indexname new strings which must be free()d */
static int sphinx_basedir(const struct mailbox *mailbox,
                          char **basedirp,
                          char **indexnamep)
{
    const char *root;
    char *basedir = NULL;
    struct buf indexname = BUF_INITIALIZER;
    struct mboxname_parts parts;
    char c[2], d[2];
    int r;

    mboxname_init_parts(&parts);

    root = sphinx_rootdir(mailbox->part);
    if (!root) {
        r = IMAP_PARTITION_UNKNOWN;
        goto out;
    }

    r = mboxname_to_parts(mailbox->name, &parts);
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

    buf_appendcstr(&indexname, "X");
    z_escape(&indexname, parts.userid);
    if (parts.domain) {
        z_escape(&indexname, "@");
        z_escape(&indexname, parts.domain);
    }

    r = 0;

out:
    if (!r && indexnamep)
        *indexnamep = buf_release(&indexname);
    buf_free(&indexname);
    if (!r && basedirp)
        *basedirp = basedir;
    else
        free(basedir);
    mboxname_free_parts(&parts);
    return r;
}

static const char *sphinx_syslog_prefix(void)
{
    static const char *prefix = NULL;

    if (!prefix) {
        prefix = config_getstring(IMAPOPT_SYSLOG_PREFIX);
        if (!prefix)
            prefix = "cyrus";
    }
    return prefix;
}

static int check_directory(const char *dir, int verbose, int create)
{
    int r;
    char *dummyfile = NULL;
    struct stat sb;

    r = stat(dir, &sb);
    if (r < 0) {
        if (r != ENOENT) {
            /* something went wrong - permissions problem most likely */
            syslog(LOG_ERR, "IOERROR: unable to stat %s: %m", dir);
            r = IMAP_IOERROR;
            goto out;
        }
        /* the directory is just missing */
        if (!create) {
            /* caller doesn't care that much */
            r = IMAP_NOTFOUND;
            goto out;
        }
        if (verbose)
            syslog(LOG_INFO, "Building directory %s", dir);
        dummyfile = strconcat(dir, "/dummy", (char *)NULL);
        cyrus_mkdir(dummyfile, 0700);
        r = stat(dir, &sb);
        if (r < 0) {
            /* something went wrong - permissions problem most likely */
            syslog(LOG_ERR, "IOERROR: unable to stat %s: %m", dir);
            r = IMAP_IOERROR;
            goto out;
        }
    }

out:
    free(dummyfile);
    return r;
}

static int sphinx_signal(int sig, int verbose)
{
    const char *pidfile = config_getstring(IMAPOPT_SPHINX_PIDFILE);
    int fd = -1;
    pid_t pid;
    int r;
    char buf[33];

    fd = open(pidfile, O_RDONLY, 0);
    if (fd < 0) {
        if (fd == ENOENT) {
            r = IMAP_NOTFOUND;
        }
        else {
            syslog(LOG_ERR, "IOERROR: unable to open %s for reading: %m", pidfile);
            r = IMAP_IOERROR;
        }
        goto out;
    }

    memset(buf, 0, sizeof(buf));
    r = read(fd, buf, sizeof(buf)-1);
    if (r < 0) {
        syslog(LOG_ERR, "IOERROR: unable to read %s: %m", pidfile);
        r = IMAP_IOERROR;
        goto out;
    }
    if (r == 0) {
        syslog(LOG_ERR, "IOERROR: short file %s", pidfile);
        r = IMAP_IOERROR;
        goto out;
    }

    pid = strtoul(buf, NULL, 10);
    if (pid <= 0) {
        syslog(LOG_ERR, "IOERROR: invalid contents of %s", pidfile);
        r = IMAP_IOERROR;
        goto out;
    }

    if (verbose)
        syslog(LOG_INFO, "Sending signal %d to pid %d from %s",
                sig, (int)pid, pidfile);

    r = kill(pid, sig);
    if (r < 0) {
        if (r == ESRCH) {
            r = IMAP_NOTFOUND;
        }
        else {
            syslog(LOG_ERR, "IOERROR: failed to send signal %d "
                            "to searchd pid %d: %m",
                            sig, (int)pid);
            r = IMAP_SYS_ERROR;
        }
        goto out;
    }

    r = 0;

out:
    if (fd >= 0) close(fd);
    return r;
}


static int sphinx_setup(const struct mailbox *mailbox, int verbose, int create)
{
    static const char user_config[] =
        "index $indexname\n"
        "{\n"
        "    type = rt\n"
        "    path = $basedir/rt\n"
        "    morphology = stem_en\n"
        "    charset_type = utf-8\n"
        "    charset_table = 0..9, A..Z->a..z, _, a..z, \\\n"
        /* Support for Cyrillic from
         * http://sphinxsearch.com/wiki/doku.php?id=charset_tables#cyrillic */
        "       U+0400->U+0435, U+0401->U+0435, U+0402->U+0452, U+0452, \\\n"
        "       U+0403->U+0433, U+0404->U+0454, U+0454, U+0405->U+0455, \\\n"
        "       U+0455, U+0406->U+0456, U+0407->U+0456, U+0457->U+0456, \\\n"
        "       U+0456, U+0408..U+040B->U+0458..U+045B, U+0458..U+045B, \\\n"
        "       U+040C->U+043A, U+040D->U+0438, U+040E->U+0443, U+040F->U+045F, \\\n"
        "       U+045F, U+0450->U+0435, U+0451->U+0435, U+0453->U+0433, \\\n"
        "       U+045C->U+043A, U+045D->U+0438, U+045E->U+0443, U+0460->U+0461, \\\n"
        "       U+0461, U+0462->U+0463, U+0463, U+0464->U+0465, U+0465, \\\n"
        "       U+0466->U+0467, U+0467, U+0468->U+0469, U+0469, U+046A->U+046B, \\\n"
        "       U+046B, U+046C->U+046D, U+046D, U+046E->U+046F, U+046F, \\\n"
        "       U+0470->U+0471, U+0471, U+0472->U+0473, U+0473, U+0474->U+0475, \\\n"
        "       U+0476->U+0475, U+0477->U+0475, U+0475, U+0478->U+0479, U+0479, \\\n"
        "       U+047A->U+047B, U+047B, U+047C->U+047D, U+047D, U+047E->U+047F, \\\n"
        "       U+047F, U+0480->U+0481, U+0481, U+048A->U+0438, U+048B->U+0438, \\\n"
        "       U+048C->U+044C, U+048D->U+044C, U+048E->U+0440, U+048F->U+0440, \\\n"
        "       U+0490->U+0433, U+0491->U+0433, U+0490->U+0433, U+0491->U+0433, \\\n"
        "       U+0492->U+0433, U+0493->U+0433, U+0494->U+0433, U+0495->U+0433, \\\n"
        "       U+0496->U+0436, U+0497->U+0436, U+0498->U+0437, U+0499->U+0437, \\\n"
        "       U+049A->U+043A, U+049B->U+043A, U+049C->U+043A, U+049D->U+043A, \\\n"
        "       U+049E->U+043A, U+049F->U+043A, U+04A0->U+043A, U+04A1->U+043A, \\\n"
        "       U+04A2->U+043D, U+04A3->U+043D, U+04A4->U+043D, U+04A5->U+043D, \\\n"
        "       U+04A6->U+043F, U+04A7->U+043F, U+04A8->U+04A9, U+04A9, \\\n"
        "       U+04AA->U+0441, U+04AB->U+0441, U+04AC->U+0442, U+04AD->U+0442, \\\n"
        "       U+04AE->U+0443, U+04AF->U+0443, U+04B0->U+0443, U+04B1->U+0443, \\\n"
        "       U+04B2->U+0445, U+04B3->U+0445, U+04B4->U+04B5, U+04B5, \\\n"
        "       U+04B6->U+0447, U+04B7->U+0447, U+04B8->U+0447, U+04B9->U+0447, \\\n"
        "       U+04BA->U+04BB, U+04BB, U+04BC->U+04BD, U+04BE->U+04BD, \\\n"
        "       U+04BF->U+04BD, U+04BD, U+04C0->U+04CF, U+04CF, U+04C1->U+0436, \\\n"
        "       U+04C2->U+0436, U+04C3->U+043A, U+04C4->U+043A, U+04C5->U+043B, \\\n"
        "       U+04C6->U+043B, U+04C7->U+043D, U+04C8->U+043D, U+04C9->U+043D, \\\n"
        "       U+04CA->U+043D, U+04CB->U+0447, U+04CC->U+0447, U+04CD->U+043C, \\\n"
        "       U+04CE->U+043C, U+04D0->U+0430, U+04D1->U+0430, U+04D2->U+0430, \\\n"
        "       U+04D3->U+0430, U+04D4->U+00E6, U+04D5->U+00E6, U+04D6->U+0435, \\\n"
        "       U+04D7->U+0435, U+04D8->U+04D9, U+04DA->U+04D9, U+04DB->U+04D9, \\\n"
        "       U+04D9, U+04DC->U+0436, U+04DD->U+0436, U+04DE->U+0437, \\\n"
        "       U+04DF->U+0437, U+04E0->U+04E1, U+04E1, U+04E2->U+0438, \\\n"
        "       U+04E3->U+0438, U+04E4->U+0438, U+04E5->U+0438, U+04E6->U+043E, \\\n"
        "       U+04E7->U+043E, U+04E8->U+043E, U+04E9->U+043E, U+04EA->U+043E, \\\n"
        "       U+04EB->U+043E, U+04EC->U+044D, U+04ED->U+044D, U+04EE->U+0443, \\\n"
        "       U+04EF->U+0443, U+04F0->U+0443, U+04F1->U+0443, U+04F2->U+0443, \\\n"
        "       U+04F3->U+0443, U+04F4->U+0447, U+04F5->U+0447, U+04F6->U+0433, \\\n"
        "       U+04F7->U+0433, U+04F8->U+044B, U+04F9->U+044B, U+04FA->U+0433, \\\n"
        "       U+04FB->U+0433, U+04FC->U+0445, U+04FD->U+0445, U+04FE->U+0445, \\\n"
        "       U+04FF->U+0445, U+0410..U+0418->U+0430..U+0438, U+0419->U+0438, \\\n"
        "       U+0430..U+0438, U+041A..U+042F->U+043A..U+044F, U+043A..U+044F,\\\n"
        /* and this one was missing dammit */
        "       U+0418->U+0438, U+0439->U+0438, \\\n"
        /* Sumerian cuneiform which is fun for testing but seems
         * to be broken in Sphinx. */
        /*
        "       U+12000..U+1237F, \\\n"
        */
        /* Support for Chinese/Japanese/Korean, from
         * http://sphinxsearch.com/wiki/doku.php?id=charset_tables#cjk */
        "       U+F900->U+8C48, U+F901->U+66F4, U+F902->U+8ECA, U+F903->U+8CC8, \\\n"
        "       U+F904->U+6ED1, U+F905->U+4E32, U+F906->U+53E5, U+F907->U+9F9C, \\\n"
        "       U+F908->U+9F9C, U+F909->U+5951, U+F90A->U+91D1, U+F90B->U+5587, \\\n"
        "       U+F90C->U+5948, U+F90D->U+61F6, U+F90E->U+7669, U+F90F->U+7F85, \\\n"
        "       U+F910->U+863F, U+F911->U+87BA, U+F912->U+88F8, U+F913->U+908F, \\\n"
        "       U+F914->U+6A02, U+F915->U+6D1B, U+F916->U+70D9, U+F917->U+73DE, \\\n"
        "       U+F918->U+843D, U+F919->U+916A, U+F91A->U+99F1, U+F91B->U+4E82, \\\n"
        "       U+F91C->U+5375, U+F91D->U+6B04, U+F91E->U+721B, U+F91F->U+862D, \\\n"
        "       U+F920->U+9E1E, U+F921->U+5D50, U+F922->U+6FEB, U+F923->U+85CD, \\\n"
        "       U+F924->U+8964, U+F925->U+62C9, U+F926->U+81D8, U+F927->U+881F, \\\n"
        "       U+F928->U+5ECA, U+F929->U+6717, U+F92A->U+6D6A, U+F92B->U+72FC, \\\n"
        "       U+F92C->U+90CE, U+F92D->U+4F86, U+F92E->U+51B7, U+F92F->U+52DE, \\\n"
        "       U+F930->U+64C4, U+F931->U+6AD3, U+F932->U+7210, U+F933->U+76E7, \\\n"
        "       U+F934->U+8001, U+F935->U+8606, U+F936->U+865C, U+F937->U+8DEF, \\\n"
        "       U+F938->U+9732, U+F939->U+9B6F, U+F93A->U+9DFA, U+F93B->U+788C, \\\n"
        "       U+F93C->U+797F, U+F93D->U+7DA0, U+F93E->U+83C9, U+F93F->U+9304, \\\n"
        "       U+F940->U+9E7F, U+F941->U+8AD6, U+F942->U+58DF, U+F943->U+5F04, \\\n"
        "       U+F944->U+7C60, U+F945->U+807E, U+F946->U+7262, U+F947->U+78CA, \\\n"
        "       U+F948->U+8CC2, U+F949->U+96F7, U+F94A->U+58D8, U+F94B->U+5C62, \\\n"
        "       U+F94C->U+6A13, U+F94D->U+6DDA, U+F94E->U+6F0F, U+F94F->U+7D2F, \\\n"
        "       U+F950->U+7E37, U+F951->U+964B, U+F952->U+52D2, U+F953->U+808B, \\\n"
        "       U+F954->U+51DC, U+F955->U+51CC, U+F956->U+7A1C, U+F957->U+7DBE, \\\n"
        "       U+F958->U+83F1, U+F959->U+9675, U+F95A->U+8B80, U+F95B->U+62CF, \\\n"
        "       U+F95C->U+6A02, U+F95D->U+8AFE, U+F95E->U+4E39, U+F95F->U+5BE7, \\\n"
        "       U+F960->U+6012, U+F961->U+7387, U+F962->U+7570, U+F963->U+5317, \\\n"
        "       U+F964->U+78FB, U+F965->U+4FBF, U+F966->U+5FA9, U+F967->U+4E0D, \\\n"
        "       U+F968->U+6CCC, U+F969->U+6578, U+F96A->U+7D22, U+F96B->U+53C3, \\\n"
        "       U+F96C->U+585E, U+F96D->U+7701, U+F96E->U+8449, U+F96F->U+8AAA, \\\n"
        "       U+F970->U+6BBA, U+F971->U+8FB0, U+F972->U+6C88, U+F973->U+62FE, \\\n"
        "       U+F974->U+82E5, U+F975->U+63A0, U+F976->U+7565, U+F977->U+4EAE, \\\n"
        "       U+F978->U+5169, U+F979->U+51C9, U+F97A->U+6881, U+F97B->U+7CE7, \\\n"
        "       U+F97C->U+826F, U+F97D->U+8AD2, U+F97E->U+91CF, U+F97F->U+52F5, \\\n"
        "       U+F980->U+5442, U+F981->U+5973, U+F982->U+5EEC, U+F983->U+65C5, \\\n"
        "       U+F984->U+6FFE, U+F985->U+792A, U+F986->U+95AD, U+F987->U+9A6A, \\\n"
        "       U+F988->U+9E97, U+F989->U+9ECE, U+F98A->U+529B, U+F98B->U+66C6, \\\n"
        "       U+F98C->U+6B77, U+F98D->U+8F62, U+F98E->U+5E74, U+F98F->U+6190, \\\n"
        "       U+F990->U+6200, U+F991->U+649A, U+F992->U+6F23, U+F993->U+7149, \\\n"
        "       U+F994->U+7489, U+F995->U+79CA, U+F996->U+7DF4, U+F997->U+806F, \\\n"
        "       U+F998->U+8F26, U+F999->U+84EE, U+F99A->U+9023, U+F99B->U+934A, \\\n"
        "       U+F99C->U+5217, U+F99D->U+52A3, U+F99E->U+54BD, U+F99F->U+70C8, \\\n"
        "       U+F9A0->U+88C2, U+F9A1->U+8AAA, U+F9A2->U+5EC9, U+F9A3->U+5FF5, \\\n"
        "       U+F9A4->U+637B, U+F9A5->U+6BAE, U+F9A6->U+7C3E, U+F9A7->U+7375, \\\n"
        "       U+F9A8->U+4EE4, U+F9A9->U+56F9, U+F9AA->U+5BE7, U+F9AB->U+5DBA, \\\n"
        "       U+F9AC->U+601C, U+F9AD->U+73B2, U+F9AE->U+7469, U+F9AF->U+7F9A, \\\n"
        "       U+F9B0->U+8046, U+F9B1->U+9234, U+F9B2->U+96F6, U+F9B3->U+9748, \\\n"
        "       U+F9B4->U+9818, U+F9B5->U+4F8B, U+F9B6->U+79AE, U+F9B7->U+91B4, \\\n"
        "       U+F9B8->U+96B8, U+F9B9->U+60E1, U+F9BA->U+4E86, U+F9BB->U+50DA, \\\n"
        "       U+F9BC->U+5BEE, U+F9BD->U+5C3F, U+F9BE->U+6599, U+F9BF->U+6A02, \\\n"
        "       U+F9C0->U+71CE, U+F9C1->U+7642, U+F9C2->U+84FC, U+F9C3->U+907C, \\\n"
        "       U+F9C4->U+9F8D, U+F9C5->U+6688, U+F9C6->U+962E, U+F9C7->U+5289, \\\n"
        "       U+F9C8->U+677B, U+F9C9->U+67F3, U+F9CA->U+6D41, U+F9CB->U+6E9C, \\\n"
        "       U+F9CC->U+7409, U+F9CD->U+7559, U+F9CE->U+786B, U+F9CF->U+7D10, \\\n"
        "       U+F9D0->U+985E, U+F9D1->U+516D, U+F9D2->U+622E, U+F9D3->U+9678, \\\n"
        "       U+F9D4->U+502B, U+F9D5->U+5D19, U+F9D6->U+6DEA, U+F9D7->U+8F2A, \\\n"
        "       U+F9D8->U+5F8B, U+F9D9->U+6144, U+F9DA->U+6817, U+F9DB->U+7387, \\\n"
        "       U+F9DC->U+9686, U+F9DD->U+5229, U+F9DE->U+540F, U+F9DF->U+5C65, \\\n"
        "       U+F9E0->U+6613, U+F9E1->U+674E, U+F9E2->U+68A8, U+F9E3->U+6CE5, \\\n"
        "       U+F9E4->U+7406, U+F9E5->U+75E2, U+F9E6->U+7F79, U+F9E7->U+88CF, \\\n"
        "       U+F9E8->U+88E1, U+F9E9->U+91CC, U+F9EA->U+96E2, U+F9EB->U+533F, \\\n"
        "       U+F9EC->U+6EBA, U+F9ED->U+541D, U+F9EE->U+71D0, U+F9EF->U+7498, \\\n"
        "       U+F9F0->U+85FA, U+F9F1->U+96A3, U+F9F2->U+9C57, U+F9F3->U+9E9F, \\\n"
        "       U+F9F4->U+6797, U+F9F5->U+6DCB, U+F9F6->U+81E8, U+F9F7->U+7ACB, \\\n"
        "       U+F9F8->U+7B20, U+F9F9->U+7C92, U+F9FA->U+72C0, U+F9FB->U+7099, \\\n"
        "       U+F9FC->U+8B58, U+F9FD->U+4EC0, U+F9FE->U+8336, U+F9FF->U+523A, \\\n"
        "       U+FA00->U+5207, U+FA01->U+5EA6, U+FA02->U+62D3, U+FA03->U+7CD6, \\\n"
        "       U+FA04->U+5B85, U+FA05->U+6D1E, U+FA06->U+66B4, U+FA07->U+8F3B, \\\n"
        "       U+FA08->U+884C, U+FA09->U+964D, U+FA0A->U+898B, U+FA0B->U+5ED3, \\\n"
        "       U+FA0C->U+5140, U+FA0D->U+55C0, U+FA10->U+585A, U+FA12->U+6674, \\\n"
        "       U+FA15->U+51DE, U+FA16->U+732A, U+FA17->U+76CA, U+FA18->U+793C, \\\n"
        "       U+FA19->U+795E, U+FA1A->U+7965, U+FA1B->U+798F, U+FA1C->U+9756, \\\n"
        "       U+FA1D->U+7CBE, U+FA1E->U+7FBD, U+FA20->U+8612, U+FA22->U+8AF8, \\\n"
        "       U+FA25->U+9038, U+FA26->U+90FD, U+FA2A->U+98EF, U+FA2B->U+98FC, \\\n"
        "       U+FA2C->U+9928, U+FA2D->U+9DB4, U+FA30->U+4FAE, U+FA31->U+50E7, \\\n"
        "       U+FA32->U+514D, U+FA33->U+52C9, U+FA34->U+52E4, U+FA35->U+5351, \\\n"
        "       U+FA36->U+559D, U+FA37->U+5606, U+FA38->U+5668, U+FA39->U+5840, \\\n"
        "       U+FA3A->U+58A8, U+FA3B->U+5C64, U+FA3C->U+5C6E, U+FA3D->U+6094, \\\n"
        "       U+FA3E->U+6168, U+FA3F->U+618E, U+FA40->U+61F2, U+FA41->U+654F, \\\n"
        "       U+FA42->U+65E2, U+FA43->U+6691, U+FA44->U+6885, U+FA45->U+6D77, \\\n"
        "       U+FA46->U+6E1A, U+FA47->U+6F22, U+FA48->U+716E, U+FA49->U+722B, \\\n"
        "       U+FA4A->U+7422, U+FA4B->U+7891, U+FA4C->U+793E, U+FA4D->U+7949, \\\n"
        "       U+FA4E->U+7948, U+FA4F->U+7950, U+FA50->U+7956, U+FA51->U+795D, \\\n"
        "       U+FA52->U+798D, U+FA53->U+798E, U+FA54->U+7A40, U+FA55->U+7A81, \\\n"
        "       U+FA56->U+7BC0, U+FA57->U+7DF4, U+FA58->U+7E09, U+FA59->U+7E41, \\\n"
        "       U+FA5A->U+7F72, U+FA5B->U+8005, U+FA5C->U+81ED, U+FA5D->U+8279, \\\n"
        "       U+FA5E->U+8279, U+FA5F->U+8457, U+FA60->U+8910, U+FA61->U+8996, \\\n"
        "       U+FA62->U+8B01, U+FA63->U+8B39, U+FA64->U+8CD3, U+FA65->U+8D08, \\\n"
        "       U+FA66->U+8FB6, U+FA67->U+9038, U+FA68->U+96E3, U+FA69->U+97FF, \\\n"
        "       U+FA6A->U+983B, U+FA70->U+4E26, U+FA71->U+51B5, U+FA72->U+5168, \\\n"
        "       U+FA73->U+4F80, U+FA74->U+5145, U+FA75->U+5180, U+FA76->U+52C7, \\\n"
        "       U+FA77->U+52FA, U+FA78->U+559D, U+FA79->U+5555, U+FA7A->U+5599, \\\n"
        "       U+FA7B->U+55E2, U+FA7C->U+585A, U+FA7D->U+58B3, U+FA7E->U+5944, \\\n"
        "       U+FA7F->U+5954, U+FA80->U+5A62, U+FA81->U+5B28, U+FA82->U+5ED2, \\\n"
        "       U+FA83->U+5ED9, U+FA84->U+5F69, U+FA85->U+5FAD, U+FA86->U+60D8, \\\n"
        "       U+FA87->U+614E, U+FA88->U+6108, U+FA89->U+618E, U+FA8A->U+6160, \\\n"
        "       U+FA8B->U+61F2, U+FA8C->U+6234, U+FA8D->U+63C4, U+FA8E->U+641C, \\\n"
        "       U+FA8F->U+6452, U+FA90->U+6556, U+FA91->U+6674, U+FA92->U+6717, \\\n"
        "       U+FA93->U+671B, U+FA94->U+6756, U+FA95->U+6B79, U+FA96->U+6BBA, \\\n"
        "       U+FA97->U+6D41, U+FA98->U+6EDB, U+FA99->U+6ECB, U+FA9A->U+6F22, \\\n"
        "       U+FA9B->U+701E, U+FA9C->U+716E, U+FA9D->U+77A7, U+FA9E->U+7235, \\\n"
        "       U+FA9F->U+72AF, U+FAA0->U+732A, U+FAA1->U+7471, U+FAA2->U+7506, \\\n"
        "       U+FAA3->U+753B, U+FAA4->U+761D, U+FAA5->U+761F, U+FAA6->U+76CA, \\\n"
        "       U+FAA7->U+76DB, U+FAA8->U+76F4, U+FAA9->U+774A, U+FAAA->U+7740, \\\n"
        "       U+FAAB->U+78CC, U+FAAC->U+7AB1, U+FAAD->U+7BC0, U+FAAE->U+7C7B, \\\n"
        "       U+FAAF->U+7D5B, U+FAB0->U+7DF4, U+FAB1->U+7F3E, U+FAB2->U+8005, \\\n"
        "       U+FAB3->U+8352, U+FAB4->U+83EF, U+FAB5->U+8779, U+FAB6->U+8941, \\\n"
        "       U+FAB7->U+8986, U+FAB8->U+8996, U+FAB9->U+8ABF, U+FABA->U+8AF8, \\\n"
        "       U+FABB->U+8ACB, U+FABC->U+8B01, U+FABD->U+8AFE, U+FABE->U+8AED, \\\n"
        "       U+FABF->U+8B39, U+FAC0->U+8B8A, U+FAC1->U+8D08, U+FAC2->U+8F38, \\\n"
        "       U+FAC3->U+9072, U+FAC4->U+9199, U+FAC5->U+9276, U+FAC6->U+967C, \\\n"
        "       U+FAC7->U+96E3, U+FAC8->U+9756, U+FAC9->U+97DB, U+FACA->U+97FF, \\\n"
        "       U+FACB->U+980B, U+FACC->U+983B, U+FACD->U+9B12, U+FACE->U+9F9C, \\\n"
        "       U+FACF->U+2284A, U+FAD0->U+22844, U+FAD1->U+233D5, U+FAD2->U+3B9D, \\\n"
        "       U+FAD3->U+4018, U+FAD4->U+4039, U+FAD5->U+25249, U+FAD6->U+25CD0, \\\n"
        "       U+FAD7->U+27ED3, U+FAD8->U+9F43, U+FAD9->U+9F8E, U+2F800->U+4E3D, \\\n"
        "       U+2F801->U+4E38, U+2F802->U+4E41, U+2F803->U+20122, U+2F804->U+4F60, \\\n"
        "       U+2F805->U+4FAE, U+2F806->U+4FBB, U+2F807->U+5002, U+2F808->U+507A, \\\n"
        "       U+2F809->U+5099, U+2F80A->U+50E7, U+2F80B->U+50CF, U+2F80C->U+349E, \\\n"
        "       U+2F80D->U+2063A, U+2F80E->U+514D, U+2F80F->U+5154, U+2F810->U+5164, \\\n"
        "       U+2F811->U+5177, U+2F812->U+2051C, U+2F813->U+34B9, U+2F814->U+5167, \\\n"
        "       U+2F815->U+518D, U+2F816->U+2054B, U+2F817->U+5197, U+2F818->U+51A4, \\\n"
        "       U+2F819->U+4ECC, U+2F81A->U+51AC, U+2F81B->U+51B5, U+2F81C->U+291DF, \\\n"
        "       U+2F81D->U+51F5, U+2F81E->U+5203, U+2F81F->U+34DF, U+2F820->U+523B, \\\n"
        "       U+2F821->U+5246, U+2F822->U+5272, U+2F823->U+5277, U+2F824->U+3515, \\\n"
        "       U+2F825->U+52C7, U+2F826->U+52C9, U+2F827->U+52E4, U+2F828->U+52FA, \\\n"
        "       U+2F829->U+5305, U+2F82A->U+5306, U+2F82B->U+5317, U+2F82C->U+5349, \\\n"
        "       U+2F82D->U+5351, U+2F82E->U+535A, U+2F82F->U+5373, U+2F830->U+537D, \\\n"
        "       U+2F831->U+537F, U+2F832->U+537F, U+2F833->U+537F, U+2F834->U+20A2C, \\\n"
        "       U+2F835->U+7070, U+2F836->U+53CA, U+2F837->U+53DF, U+2F838->U+20B63, \\\n"
        "       U+2F839->U+53EB, U+2F83A->U+53F1, U+2F83B->U+5406, U+2F83C->U+549E, \\\n"
        "       U+2F83D->U+5438, U+2F83E->U+5448, U+2F83F->U+5468, U+2F840->U+54A2, \\\n"
        "       U+2F841->U+54F6, U+2F842->U+5510, U+2F843->U+5553, U+2F844->U+5563, \\\n"
        "       U+2F845->U+5584, U+2F846->U+5584, U+2F847->U+5599, U+2F848->U+55AB, \\\n"
        "       U+2F849->U+55B3, U+2F84A->U+55C2, U+2F84B->U+5716, U+2F84C->U+5606, \\\n"
        "       U+2F84D->U+5717, U+2F84E->U+5651, U+2F84F->U+5674, U+2F850->U+5207, \\\n"
        "       U+2F851->U+58EE, U+2F852->U+57CE, U+2F853->U+57F4, U+2F854->U+580D, \\\n"
        "       U+2F855->U+578B, U+2F856->U+5832, U+2F857->U+5831, U+2F858->U+58AC, \\\n"
        "       U+2F859->U+214E4, U+2F85A->U+58F2, U+2F85B->U+58F7, U+2F85C->U+5906, \\\n"
        "       U+2F85D->U+591A, U+2F85E->U+5922, U+2F85F->U+5962, U+2F860->U+216A8, \\\n"
        "       U+2F861->U+216EA, U+2F862->U+59EC, U+2F863->U+5A1B, U+2F864->U+5A27, \\\n"
        "       U+2F865->U+59D8, U+2F866->U+5A66, U+2F867->U+36EE, U+2F868->U+36FC, \\\n"
        "       U+2F869->U+5B08, U+2F86A->U+5B3E, U+2F86B->U+5B3E, U+2F86C->U+219C8, \\\n"
        "       U+2F86D->U+5BC3, U+2F86E->U+5BD8, U+2F86F->U+5BE7, U+2F870->U+5BF3, \\\n"
        "       U+2F871->U+21B18, U+2F872->U+5BFF, U+2F873->U+5C06, U+2F874->U+5F53, \\\n"
        "       U+2F875->U+5C22, U+2F876->U+3781, U+2F877->U+5C60, U+2F878->U+5C6E, \\\n"
        "       U+2F879->U+5CC0, U+2F87A->U+5C8D, U+2F87B->U+21DE4, U+2F87C->U+5D43, \\\n"
        "       U+2F87D->U+21DE6, U+2F87E->U+5D6E, U+2F87F->U+5D6B, U+2F880->U+5D7C, \\\n"
        "       U+2F881->U+5DE1, U+2F882->U+5DE2, U+2F883->U+382F, U+2F884->U+5DFD, \\\n"
        "       U+2F885->U+5E28, U+2F886->U+5E3D, U+2F887->U+5E69, U+2F888->U+3862, \\\n"
        "       U+2F889->U+22183, U+2F88A->U+387C, U+2F88B->U+5EB0, U+2F88C->U+5EB3, \\\n"
        "       U+2F88D->U+5EB6, U+2F88E->U+5ECA, U+2F88F->U+2A392, U+2F890->U+5EFE, \\\n"
        "       U+2F891->U+22331, U+2F892->U+22331, U+2F893->U+8201, U+2F894->U+5F22, \\\n"
        "       U+2F895->U+5F22, U+2F896->U+38C7, U+2F897->U+232B8, U+2F898->U+261DA, \\\n"
        "       U+2F899->U+5F62, U+2F89A->U+5F6B, U+2F89B->U+38E3, U+2F89C->U+5F9A, \\\n"
        "       U+2F89D->U+5FCD, U+2F89E->U+5FD7, U+2F89F->U+5FF9, U+2F8A0->U+6081, \\\n"
        "       U+2F8A1->U+393A, U+2F8A2->U+391C, U+2F8A3->U+6094, U+2F8A4->U+226D4, \\\n"
        "       U+2F8A5->U+60C7, U+2F8A6->U+6148, U+2F8A7->U+614C, U+2F8A8->U+614E, \\\n"
        "       U+2F8A9->U+614C, U+2F8AA->U+617A, U+2F8AB->U+618E, U+2F8AC->U+61B2, \\\n"
        "       U+2F8AD->U+61A4, U+2F8AE->U+61AF, U+2F8AF->U+61DE, U+2F8B0->U+61F2, \\\n"
        "       U+2F8B1->U+61F6, U+2F8B2->U+6210, U+2F8B3->U+621B, U+2F8B4->U+625D, \\\n"
        "       U+2F8B5->U+62B1, U+2F8B6->U+62D4, U+2F8B7->U+6350, U+2F8B8->U+22B0C, \\\n"
        "       U+2F8B9->U+633D, U+2F8BA->U+62FC, U+2F8BB->U+6368, U+2F8BC->U+6383, \\\n"
        "       U+2F8BD->U+63E4, U+2F8BE->U+22BF1, U+2F8BF->U+6422, U+2F8C0->U+63C5, \\\n"
        "       U+2F8C1->U+63A9, U+2F8C2->U+3A2E, U+2F8C3->U+6469, U+2F8C4->U+647E, \\\n"
        "       U+2F8C5->U+649D, U+2F8C6->U+6477, U+2F8C7->U+3A6C, U+2F8C8->U+654F, \\\n"
        "       U+2F8C9->U+656C, U+2F8CA->U+2300A, U+2F8CB->U+65E3, U+2F8CC->U+66F8, \\\n"
        "       U+2F8CD->U+6649, U+2F8CE->U+3B19, U+2F8CF->U+6691, U+2F8D0->U+3B08, \\\n"
        "       U+2F8D1->U+3AE4, U+2F8D2->U+5192, U+2F8D3->U+5195, U+2F8D4->U+6700, \\\n"
        "       U+2F8D5->U+669C, U+2F8D6->U+80AD, U+2F8D7->U+43D9, U+2F8D8->U+6717, \\\n"
        "       U+2F8D9->U+671B, U+2F8DA->U+6721, U+2F8DB->U+675E, U+2F8DC->U+6753, \\\n"
        "       U+2F8DD->U+233C3, U+2F8DE->U+3B49, U+2F8DF->U+67FA, U+2F8E0->U+6785, \\\n"
        "       U+2F8E1->U+6852, U+2F8E2->U+6885, U+2F8E3->U+2346D, U+2F8E4->U+688E, \\\n"
        "       U+2F8E5->U+681F, U+2F8E6->U+6914, U+2F8E7->U+3B9D, U+2F8E8->U+6942, \\\n"
        "       U+2F8E9->U+69A3, U+2F8EA->U+69EA, U+2F8EB->U+6AA8, U+2F8EC->U+236A3, \\\n"
        "       U+2F8ED->U+6ADB, U+2F8EE->U+3C18, U+2F8EF->U+6B21, U+2F8F0->U+238A7, \\\n"
        "       U+2F8F1->U+6B54, U+2F8F2->U+3C4E, U+2F8F3->U+6B72, U+2F8F4->U+6B9F, \\\n"
        "       U+2F8F5->U+6BBA, U+2F8F6->U+6BBB, U+2F8F7->U+23A8D, U+2F8F8->U+21D0B, \\\n"
        "       U+2F8F9->U+23AFA, U+2F8FA->U+6C4E, U+2F8FB->U+23CBC, U+2F8FC->U+6CBF, \\\n"
        "       U+2F8FD->U+6CCD, U+2F8FE->U+6C67, U+2F8FF->U+6D16, U+2F900->U+6D3E, \\\n"
        "       U+2F901->U+6D77, U+2F902->U+6D41, U+2F903->U+6D69, U+2F904->U+6D78, \\\n"
        "       U+2F905->U+6D85, U+2F906->U+23D1E, U+2F907->U+6D34, U+2F908->U+6E2F, \\\n"
        "       U+2F909->U+6E6E, U+2F90A->U+3D33, U+2F90B->U+6ECB, U+2F90C->U+6EC7, \\\n"
        "       U+2F90D->U+23ED1, U+2F90E->U+6DF9, U+2F90F->U+6F6E, U+2F910->U+23F5E, \\\n"
        "       U+2F911->U+23F8E, U+2F912->U+6FC6, U+2F913->U+7039, U+2F914->U+701E, \\\n"
        "       U+2F915->U+701B, U+2F916->U+3D96, U+2F917->U+704A, U+2F918->U+707D, \\\n"
        "       U+2F919->U+7077, U+2F91A->U+70AD, U+2F91B->U+20525, U+2F91C->U+7145, \\\n"
        "       U+2F91D->U+24263, U+2F91E->U+719C, U+2F91F->U+243AB, U+2F920->U+7228, \\\n"
        "       U+2F921->U+7235, U+2F922->U+7250, U+2F923->U+24608, U+2F924->U+7280, \\\n"
        "       U+2F925->U+7295, U+2F926->U+24735, U+2F927->U+24814, U+2F928->U+737A, \\\n"
        "       U+2F929->U+738B, U+2F92A->U+3EAC, U+2F92B->U+73A5, U+2F92C->U+3EB8, \\\n"
        "       U+2F92D->U+3EB8, U+2F92E->U+7447, U+2F92F->U+745C, U+2F930->U+7471, \\\n"
        "       U+2F931->U+7485, U+2F932->U+74CA, U+2F933->U+3F1B, U+2F934->U+7524, \\\n"
        "       U+2F935->U+24C36, U+2F936->U+753E, U+2F937->U+24C92, U+2F938->U+7570, \\\n"
        "       U+2F939->U+2219F, U+2F93A->U+7610, U+2F93B->U+24FA1, U+2F93C->U+24FB8, \\\n"
        "       U+2F93D->U+25044, U+2F93E->U+3FFC, U+2F93F->U+4008, U+2F940->U+76F4, \\\n"
        "       U+2F941->U+250F3, U+2F942->U+250F2, U+2F943->U+25119, U+2F944->U+25133, \\\n"
        "       U+2F945->U+771E, U+2F946->U+771F, U+2F947->U+771F, U+2F948->U+774A, \\\n"
        "       U+2F949->U+4039, U+2F94A->U+778B, U+2F94B->U+4046, U+2F94C->U+4096, \\\n"
        "       U+2F94D->U+2541D, U+2F94E->U+784E, U+2F94F->U+788C, U+2F950->U+78CC, \\\n"
        "       U+2F951->U+40E3, U+2F952->U+25626, U+2F953->U+7956, U+2F954->U+2569A, \\\n"
        "       U+2F955->U+256C5, U+2F956->U+798F, U+2F957->U+79EB, U+2F958->U+412F, \\\n"
        "       U+2F959->U+7A40, U+2F95A->U+7A4A, U+2F95B->U+7A4F, U+2F95C->U+2597C, \\\n"
        "       U+2F95D->U+25AA7, U+2F95E->U+25AA7, U+2F95F->U+7AEE, U+2F960->U+4202, \\\n"
        "       U+2F961->U+25BAB, U+2F962->U+7BC6, U+2F963->U+7BC9, U+2F964->U+4227, \\\n"
        "       U+2F965->U+25C80, U+2F966->U+7CD2, U+2F967->U+42A0, U+2F968->U+7CE8, \\\n"
        "       U+2F969->U+7CE3, U+2F96A->U+7D00, U+2F96B->U+25F86, U+2F96C->U+7D63, \\\n"
        "       U+2F96D->U+4301, U+2F96E->U+7DC7, U+2F96F->U+7E02, U+2F970->U+7E45, \\\n"
        "       U+2F971->U+4334, U+2F972->U+26228, U+2F973->U+26247, U+2F974->U+4359, \\\n"
        "       U+2F975->U+262D9, U+2F976->U+7F7A, U+2F977->U+2633E, U+2F978->U+7F95, \\\n"
        "       U+2F979->U+7FFA, U+2F97A->U+8005, U+2F97B->U+264DA, U+2F97C->U+26523, \\\n"
        "       U+2F97D->U+8060, U+2F97E->U+265A8, U+2F97F->U+8070, U+2F980->U+2335F, \\\n"
        "       U+2F981->U+43D5, U+2F982->U+80B2, U+2F983->U+8103, U+2F984->U+440B, \\\n"
        "       U+2F985->U+813E, U+2F986->U+5AB5, U+2F987->U+267A7, U+2F988->U+267B5, \\\n"
        "       U+2F989->U+23393, U+2F98A->U+2339C, U+2F98B->U+8201, U+2F98C->U+8204, \\\n"
        "       U+2F98D->U+8F9E, U+2F98E->U+446B, U+2F98F->U+8291, U+2F990->U+828B, \\\n"
        "       U+2F991->U+829D, U+2F992->U+52B3, U+2F993->U+82B1, U+2F994->U+82B3, \\\n"
        "       U+2F995->U+82BD, U+2F996->U+82E6, U+2F997->U+26B3C, U+2F998->U+82E5, \\\n"
        "       U+2F999->U+831D, U+2F99A->U+8363, U+2F99B->U+83AD, U+2F99C->U+8323, \\\n"
        "       U+2F99D->U+83BD, U+2F99E->U+83E7, U+2F99F->U+8457, U+2F9A0->U+8353, \\\n"
        "       U+2F9A1->U+83CA, U+2F9A2->U+83CC, U+2F9A3->U+83DC, U+2F9A4->U+26C36, \\\n"
        "       U+2F9A5->U+26D6B, U+2F9A6->U+26CD5, U+2F9A7->U+452B, U+2F9A8->U+84F1, \\\n"
        "       U+2F9A9->U+84F3, U+2F9AA->U+8516, U+2F9AB->U+273CA, U+2F9AC->U+8564, \\\n"
        "       U+2F9AD->U+26F2C, U+2F9AE->U+455D, U+2F9AF->U+4561, U+2F9B0->U+26FB1, \\\n"
        "       U+2F9B1->U+270D2, U+2F9B2->U+456B, U+2F9B3->U+8650, U+2F9B4->U+865C, \\\n"
        "       U+2F9B5->U+8667, U+2F9B6->U+8669, U+2F9B7->U+86A9, U+2F9B8->U+8688, \\\n"
        "       U+2F9B9->U+870E, U+2F9BA->U+86E2, U+2F9BB->U+8779, U+2F9BC->U+8728, \\\n"
        "       U+2F9BD->U+876B, U+2F9BE->U+8786, U+2F9BF->U+45D7, U+2F9C0->U+87E1, \\\n"
        "       U+2F9C1->U+8801, U+2F9C2->U+45F9, U+2F9C3->U+8860, U+2F9C4->U+8863, \\\n"
        "       U+2F9C5->U+27667, U+2F9C6->U+88D7, U+2F9C7->U+88DE, U+2F9C8->U+4635, \\\n"
        "       U+2F9C9->U+88FA, U+2F9CA->U+34BB, U+2F9CB->U+278AE, U+2F9CC->U+27966, \\\n"
        "       U+2F9CD->U+46BE, U+2F9CE->U+46C7, U+2F9CF->U+8AA0, U+2F9D0->U+8AED, \\\n"
        "       U+2F9D1->U+8B8A, U+2F9D2->U+8C55, U+2F9D3->U+27CA8, U+2F9D4->U+8CAB, \\\n"
        "       U+2F9D5->U+8CC1, U+2F9D6->U+8D1B, U+2F9D7->U+8D77, U+2F9D8->U+27F2F, \\\n"
        "       U+2F9D9->U+20804, U+2F9DA->U+8DCB, U+2F9DB->U+8DBC, U+2F9DC->U+8DF0, \\\n"
        "       U+2F9DD->U+208DE, U+2F9DE->U+8ED4, U+2F9DF->U+8F38, U+2F9E0->U+285D2, \\\n"
        "       U+2F9E1->U+285ED, U+2F9E2->U+9094, U+2F9E3->U+90F1, U+2F9E4->U+9111, \\\n"
        "       U+2F9E5->U+2872E, U+2F9E6->U+911B, U+2F9E7->U+9238, U+2F9E8->U+92D7, \\\n"
        "       U+2F9E9->U+92D8, U+2F9EA->U+927C, U+2F9EB->U+93F9, U+2F9EC->U+9415, \\\n"
        "       U+2F9ED->U+28BFA, U+2F9EE->U+958B, U+2F9EF->U+4995, U+2F9F0->U+95B7, \\\n"
        "       U+2F9F1->U+28D77, U+2F9F2->U+49E6, U+2F9F3->U+96C3, U+2F9F4->U+5DB2, \\\n"
        "       U+2F9F5->U+9723, U+2F9F6->U+29145, U+2F9F7->U+2921A, U+2F9F8->U+4A6E, \\\n"
        "       U+2F9F9->U+4A76, U+2F9FA->U+97E0, U+2F9FB->U+2940A, U+2F9FC->U+4AB2, \\\n"
        "       U+2F9FD->U+29496, U+2F9FE->U+980B, U+2F9FF->U+980B, U+2FA00->U+9829, \\\n"
        "       U+2FA01->U+295B6, U+2FA02->U+98E2, U+2FA03->U+4B33, U+2FA04->U+9929, \\\n"
        "       U+2FA05->U+99A7, U+2FA06->U+99C2, U+2FA07->U+99FE, U+2FA08->U+4BCE, \\\n"
        "       U+2FA09->U+29B30, U+2FA0A->U+9B12, U+2FA0B->U+9C40, U+2FA0C->U+9CFD, \\\n"
        "       U+2FA0D->U+4CCE, U+2FA0E->U+4CED, U+2FA0F->U+9D67, U+2FA10->U+2A0CE, \\\n"
        "       U+2FA11->U+4CF8, U+2FA12->U+2A105, U+2FA13->U+2A20E, U+2FA14->U+2A291, \\\n"
        "       U+2FA15->U+9EBB, U+2FA16->U+4D56, U+2FA17->U+9EF9, U+2FA18->U+9EFE, \\\n"
        "       U+2FA19->U+9F05, U+2FA1A->U+9F0F, U+2FA1B->U+9F16, U+2FA1C->U+9F3B, \\\n"
        "       U+2FA1D->U+2A600, U+2F00->U+4E00, U+2F01->U+4E28, U+2F02->U+4E36, \\\n"
        "       U+2F03->U+4E3F, U+2F04->U+4E59, U+2F05->U+4E85, U+2F06->U+4E8C, \\\n"
        "       U+2F07->U+4EA0, U+2F08->U+4EBA, U+2F09->U+513F, U+2F0A->U+5165, \\\n"
        "       U+2F0B->U+516B, U+2F0C->U+5182, U+2F0D->U+5196, U+2F0E->U+51AB, \\\n"
        "       U+2F0F->U+51E0, U+2F10->U+51F5, U+2F11->U+5200, U+2F12->U+529B, \\\n"
        "       U+2F13->U+52F9, U+2F14->U+5315, U+2F15->U+531A, U+2F16->U+5338, \\\n"
        "       U+2F17->U+5341, U+2F18->U+535C, U+2F19->U+5369, U+2F1A->U+5382, \\\n"
        "       U+2F1B->U+53B6, U+2F1C->U+53C8, U+2F1D->U+53E3, U+2F1E->U+56D7, \\\n"
        "       U+2F1F->U+571F, U+2F20->U+58EB, U+2F21->U+5902, U+2F22->U+590A, \\\n"
        "       U+2F23->U+5915, U+2F24->U+5927, U+2F25->U+5973, U+2F26->U+5B50, \\\n"
        "       U+2F27->U+5B80, U+2F28->U+5BF8, U+2F29->U+5C0F, U+2F2A->U+5C22, \\\n"
        "       U+2F2B->U+5C38, U+2F2C->U+5C6E, U+2F2D->U+5C71, U+2F2E->U+5DDB, \\\n"
        "       U+2F2F->U+5DE5, U+2F30->U+5DF1, U+2F31->U+5DFE, U+2F32->U+5E72, \\\n"
        "       U+2F33->U+5E7A, U+2F34->U+5E7F, U+2F35->U+5EF4, U+2F36->U+5EFE, \\\n"
        "       U+2F37->U+5F0B, U+2F38->U+5F13, U+2F39->U+5F50, U+2F3A->U+5F61, \\\n"
        "       U+2F3B->U+5F73, U+2F3C->U+5FC3, U+2F3D->U+6208, U+2F3E->U+6236, \\\n"
        "       U+2F3F->U+624B, U+2F40->U+652F, U+2F41->U+6534, U+2F42->U+6587, \\\n"
        "       U+2F43->U+6597, U+2F44->U+65A4, U+2F45->U+65B9, U+2F46->U+65E0, \\\n"
        "       U+2F47->U+65E5, U+2F48->U+66F0, U+2F49->U+6708, U+2F4A->U+6728, \\\n"
        "       U+2F4B->U+6B20, U+2F4C->U+6B62, U+2F4D->U+6B79, U+2F4E->U+6BB3, \\\n"
        "       U+2F4F->U+6BCB, U+2F50->U+6BD4, U+2F51->U+6BDB, U+2F52->U+6C0F, \\\n"
        "       U+2F53->U+6C14, U+2F54->U+6C34, U+2F55->U+706B, U+2F56->U+722A, \\\n"
        "       U+2F57->U+7236, U+2F58->U+723B, U+2F59->U+723F, U+2F5A->U+7247, \\\n"
        "       U+2F5B->U+7259, U+2F5C->U+725B, U+2F5D->U+72AC, U+2F5E->U+7384, \\\n"
        "       U+2F5F->U+7389, U+2F60->U+74DC, U+2F61->U+74E6, U+2F62->U+7518, \\\n"
        "       U+2F63->U+751F, U+2F64->U+7528, U+2F65->U+7530, U+2F66->U+758B, \\\n"
        "       U+2F67->U+7592, U+2F68->U+7676, U+2F69->U+767D, U+2F6A->U+76AE, \\\n"
        "       U+2F6B->U+76BF, U+2F6C->U+76EE, U+2F6D->U+77DB, U+2F6E->U+77E2, \\\n"
        "       U+2F6F->U+77F3, U+2F70->U+793A, U+2F71->U+79B8, U+2F72->U+79BE, \\\n"
        "       U+2F73->U+7A74, U+2F74->U+7ACB, U+2F75->U+7AF9, U+2F76->U+7C73, \\\n"
        "       U+2F77->U+7CF8, U+2F78->U+7F36, U+2F79->U+7F51, U+2F7A->U+7F8A, \\\n"
        "       U+2F7B->U+7FBD, U+2F7C->U+8001, U+2F7D->U+800C, U+2F7E->U+8012, \\\n"
        "       U+2F7F->U+8033, U+2F80->U+807F, U+2F81->U+8089, U+2F82->U+81E3, \\\n"
        "       U+2F83->U+81EA, U+2F84->U+81F3, U+2F85->U+81FC, U+2F86->U+820C, \\\n"
        "       U+2F87->U+821B, U+2F88->U+821F, U+2F89->U+826E, U+2F8A->U+8272, \\\n"
        "       U+2F8B->U+8278, U+2F8C->U+864D, U+2F8D->U+866B, U+2F8E->U+8840, \\\n"
        "       U+2F8F->U+884C, U+2F90->U+8863, U+2F91->U+897E, U+2F92->U+898B, \\\n"
        "       U+2F93->U+89D2, U+2F94->U+8A00, U+2F95->U+8C37, U+2F96->U+8C46, \\\n"
        "       U+2F97->U+8C55, U+2F98->U+8C78, U+2F99->U+8C9D, U+2F9A->U+8D64, \\\n"
        "       U+2F9B->U+8D70, U+2F9C->U+8DB3, U+2F9D->U+8EAB, U+2F9E->U+8ECA, \\\n"
        "       U+2F9F->U+8F9B, U+2FA0->U+8FB0, U+2FA1->U+8FB5, U+2FA2->U+9091, \\\n"
        "       U+2FA3->U+9149, U+2FA4->U+91C6, U+2FA5->U+91CC, U+2FA6->U+91D1, \\\n"
        "       U+2FA7->U+9577, U+2FA8->U+9580, U+2FA9->U+961C, U+2FAA->U+96B6, \\\n"
        "       U+2FAB->U+96B9, U+2FAC->U+96E8, U+2FAD->U+9751, U+2FAE->U+975E, \\\n"
        "       U+2FAF->U+9762, U+2FB0->U+9769, U+2FB1->U+97CB, U+2FB2->U+97ED, \\\n"
        "       U+2FB3->U+97F3, U+2FB4->U+9801, U+2FB5->U+98A8, U+2FB6->U+98DB, \\\n"
        "       U+2FB7->U+98DF, U+2FB8->U+9996, U+2FB9->U+9999, U+2FBA->U+99AC, \\\n"
        "       U+2FBB->U+9AA8, U+2FBC->U+9AD8, U+2FBD->U+9ADF, U+2FBE->U+9B25, \\\n"
        "       U+2FBF->U+9B2F, U+2FC0->U+9B32, U+2FC1->U+9B3C, U+2FC2->U+9B5A, \\\n"
        "       U+2FC3->U+9CE5, U+2FC4->U+9E75, U+2FC5->U+9E7F, U+2FC6->U+9EA5, \\\n"
        "       U+2FC7->U+9EBB, U+2FC8->U+9EC3, U+2FC9->U+9ECD, U+2FCA->U+9ED1, \\\n"
        "       U+2FCB->U+9EF9, U+2FCC->U+9EFD, U+2FCD->U+9F0E, U+2FCE->U+9F13, \\\n"
        "       U+2FCF->U+9F20, U+2FD0->U+9F3B, U+2FD1->U+9F4A, U+2FD2->U+9F52, \\\n"
        "       U+2FD3->U+9F8D, U+2FD4->U+9F9C, U+2FD5->U+9FA0, U+3042->U+3041, \\\n"
        "       U+3044->U+3043, U+3046->U+3045, U+3048->U+3047, U+304A->U+3049, \\\n"
        "       U+304C->U+304B, U+304E->U+304D, U+3050->U+304F, U+3052->U+3051, \\\n"
        "       U+3054->U+3053, U+3056->U+3055, U+3058->U+3057, U+305A->U+3059, \\\n"
        "       U+305C->U+305B, U+305E->U+305D, U+3060->U+305F, U+3062->U+3061, \\\n"
        "       U+3064->U+3063, U+3065->U+3063, U+3067->U+3066, U+3069->U+3068, \\\n"
        "       U+3070->U+306F, U+3071->U+306F, U+3073->U+3072, U+3074->U+3072, \\\n"
        "       U+3076->U+3075, U+3077->U+3075, U+3079->U+3078, U+307A->U+3078, \\\n"
        "       U+307C->U+307B, U+307D->U+307B, U+3084->U+3083, U+3086->U+3085, \\\n"
        "       U+3088->U+3087, U+308F->U+308E, U+3094->U+3046, U+3095->U+304B, \\\n"
        "       U+3096->U+3051, U+30A2->U+30A1, U+30A4->U+30A3, U+30A6->U+30A5, \\\n"
        "       U+30A8->U+30A7, U+30AA->U+30A9, U+30AC->U+30AB, U+30AE->U+30AD, \\\n"
        "       U+30B0->U+30AF, U+30B2->U+30B1, U+30B4->U+30B3, U+30B6->U+30B5, \\\n"
        "       U+30B8->U+30B7, U+30BA->U+30B9, U+30BC->U+30BB, U+30BE->U+30BD, \\\n"
        "       U+30C0->U+30BF, U+30C2->U+30C1, U+30C5->U+30C4, U+30C7->U+30C6, \\\n"
        "       U+30C9->U+30C8, U+30D0->U+30CF, U+30D1->U+30CF, U+30D3->U+30D2, \\\n"
        "       U+30D4->U+30D2, U+30D6->U+30D5, U+30D7->U+30D5, U+30D9->U+30D8, \\\n"
        "       U+30DA->U+30D8, U+30DC->U+30DB, U+30DD->U+30DB, U+30E4->U+30E3, \\\n"
        "       U+30E6->U+30E5, U+30E8->U+30E7, U+30EF->U+30EE, U+30F4->U+30A6, \\\n"
        "       U+30AB->U+30F5, U+30B1->U+30F6, U+30F7->U+30EF, U+30F8->U+30F0, \\\n"
        "       U+30F9->U+30F1, U+30FA->U+30F2, U+30AF->U+31F0, U+30B7->U+31F1, \\\n"
        "       U+30B9->U+31F2, U+30C8->U+31F3, U+30CC->U+31F4, U+30CF->U+31F5, \\\n"
        "       U+30D2->U+31F6, U+30D5->U+31F7, U+30D8->U+31F8, U+30DB->U+31F9, \\\n"
        "       U+30E0->U+31FA, U+30E9->U+31FB, U+30EA->U+31FC, U+30EB->U+31FD, \\\n"
        "       U+30EC->U+31FE, U+30ED->U+31FF, U+FF66->U+30F2, U+FF67->U+30A1, \\\n"
        "       U+FF68->U+30A3, U+FF69->U+30A5, U+FF6A->U+30A7, U+FF6B->U+30A9, \\\n"
        "       U+FF6C->U+30E3, U+FF6D->U+30E5, U+FF6E->U+30E7, U+FF6F->U+30C3, \\\n"
        "       U+FF71->U+30A1, U+FF72->U+30A3, U+FF73->U+30A5, U+FF74->U+30A7, \\\n"
        "       U+FF75->U+30A9, U+FF76->U+30AB, U+FF77->U+30AD, U+FF78->U+30AF, \\\n"
        "       U+FF79->U+30B1, U+FF7A->U+30B3, U+FF7B->U+30B5, U+FF7C->U+30B7, \\\n"
        "       U+FF7D->U+30B9, U+FF7E->U+30BB, U+FF7F->U+30BD, U+FF80->U+30BF, \\\n"
        "       U+FF81->U+30C1, U+FF82->U+30C3, U+FF83->U+30C6, U+FF84->U+30C8, \\\n"
        "       U+FF85->U+30CA, U+FF86->U+30CB, U+FF87->U+30CC, U+FF88->U+30CD, \\\n"
        "       U+FF89->U+30CE, U+FF8A->U+30CF, U+FF8B->U+30D2, U+FF8C->U+30D5, \\\n"
        "       U+FF8D->U+30D8, U+FF8E->U+30DB, U+FF8F->U+30DE, U+FF90->U+30DF, \\\n"
        "       U+FF91->U+30E0, U+FF92->U+30E1, U+FF93->U+30E2, U+FF94->U+30E3, \\\n"
        "       U+FF95->U+30E5, U+FF96->U+30E7, U+FF97->U+30E9, U+FF98->U+30EA, \\\n"
        "       U+FF99->U+30EB, U+FF9A->U+30EC, U+FF9B->U+30ED, U+FF9C->U+30EF, \\\n"
        "       U+FF9D->U+30F3, U+FFA0->U+3164, U+FFA1->U+3131, U+FFA2->U+3132, \\\n"
        "       U+FFA3->U+3133, U+FFA4->U+3134, U+FFA5->U+3135, U+FFA6->U+3136, \\\n"
        "       U+FFA7->U+3137, U+FFA8->U+3138, U+FFA9->U+3139, U+FFAA->U+313A, \\\n"
        "       U+FFAB->U+313B, U+FFAC->U+313C, U+FFAD->U+313D, U+FFAE->U+313E, \\\n"
        "       U+FFAF->U+313F, U+FFB0->U+3140, U+FFB1->U+3141, U+FFB2->U+3142, \\\n"
        "       U+FFB3->U+3143, U+FFB4->U+3144, U+FFB5->U+3145, U+FFB6->U+3146, \\\n"
        "       U+FFB7->U+3147, U+FFB8->U+3148, U+FFB9->U+3149, U+FFBA->U+314A, \\\n"
        "       U+FFBB->U+314B, U+FFBC->U+314C, U+FFBD->U+314D, U+FFBE->U+314E, \\\n"
        "       U+FFC2->U+314F, U+FFC3->U+3150, U+FFC4->U+3151, U+FFC5->U+3152, \\\n"
        "       U+FFC6->U+3153, U+FFC7->U+3154, U+FFCA->U+3155, U+FFCB->U+3156, \\\n"
        "       U+FFCC->U+3157, U+FFCD->U+3158, U+FFCE->U+3159, U+FFCF->U+315A, \\\n"
        "       U+FFD2->U+315B, U+FFD3->U+315C, U+FFD4->U+315D, U+FFD5->U+315E, \\\n"
        "       U+FFD6->U+315F, U+FFD7->U+3160, U+FFDA->U+3161, U+FFDB->U+3162, \\\n"
        "       U+FFDC->U+3163, U+3131->U+1100, U+3132->U+1101, U+3133->U+11AA, \\\n"
        "       U+3134->U+1102, U+3135->U+11AC, U+3136->U+11AD, U+3137->U+1103, \\\n"
        "       U+3138->U+1104, U+3139->U+1105, U+313A->U+11B0, U+313B->U+11B1, \\\n"
        "       U+313C->U+11B2, U+313D->U+11B3, U+313E->U+11B4, U+313F->U+11B5, \\\n"
        "       U+3140->U+111A, U+3141->U+1106, U+3142->U+1107, U+3143->U+1108, \\\n"
        "       U+3144->U+1121, U+3145->U+1109, U+3146->U+110A, U+3147->U+110B, \\\n"
        "       U+3148->U+110C, U+3149->U+110D, U+314A->U+110E, U+314B->U+110F, \\\n"
        "       U+314C->U+1110, U+314D->U+1111, U+314E->U+1112, U+314F->U+1161, \\\n"
        "       U+3150->U+1162, U+3151->U+1163, U+3152->U+1164, U+3153->U+1165, \\\n"
        "       U+3154->U+1166, U+3155->U+1167, U+3156->U+1168, U+3157->U+1169, \\\n"
        "       U+3158->U+116A, U+3159->U+116B, U+315A->U+116C, U+315B->U+116D, \\\n"
        "       U+315C->U+116E, U+315D->U+116F, U+315E->U+1170, U+315F->U+1171, \\\n"
        "       U+3160->U+1172, U+3161->U+1173, U+3162->U+1174, U+3163->U+1175, \\\n"
        "       U+3165->U+1114, U+3166->U+1115, U+3167->U+11C7, U+3168->U+11C8, \\\n"
        "       U+3169->U+11CC, U+316A->U+11CE, U+316B->U+11D3, U+316C->U+11D7, \\\n"
        "       U+316D->U+11D9, U+316E->U+111C, U+316F->U+11DD, U+3170->U+11DF, \\\n"
        "       U+3171->U+111D, U+3172->U+111E, U+3173->U+1120, U+3174->U+1122, \\\n"
        "       U+3175->U+1123, U+3176->U+1127, U+3177->U+1129, U+3178->U+112B, \\\n"
        "       U+3179->U+112C, U+317A->U+112D, U+317B->U+112E, U+317C->U+112F, \\\n"
        "       U+317D->U+1132, U+317E->U+1136, U+317F->U+1140, U+3180->U+1147, \\\n"
        "       U+3181->U+114C, U+3182->U+11F1, U+3183->U+11F2, U+3184->U+1157, \\\n"
        "       U+3185->U+1158, U+3186->U+1159, U+3187->U+1184, U+3188->U+1185, \\\n"
        "       U+3189->U+1188, U+318A->U+1191, U+318B->U+1192, U+318C->U+1194, \\\n"
        "       U+318D->U+119E, U+318E->U+11A1, U+A490->U+A408, U+A491->U+A1B9, \\\n"
        "       U+4E00..U+9FBB, U+3400..U+4DB5, U+20000..U+2A6D6, U+FA0E, U+FA0F, \\\n"
        "       U+FA11, U+FA13, U+FA14, U+FA1F, U+FA21, U+FA23, U+FA24, U+FA27, U+FA28, \\\n"
        "       U+FA29, U+3105..U+312C, U+31A0..U+31B7, U+3041, U+3043, U+3045, U+3047, \\\n"
        "       U+3049, U+304B, U+304D, U+304F, U+3051, U+3053, U+3055, U+3057, U+3059, \\\n"
        "       U+305B, U+305D, U+305F, U+3061, U+3063, U+3066, U+3068, U+306A..U+306F, \\\n"
        "       U+3072, U+3075, U+3078, U+307B, U+307E..U+3083, U+3085, U+3087, \\\n"
        "       U+3089..U+308E, U+3090..U+3093, U+30A1, U+30A3, U+30A5, U+30A7, U+30A9, \\\n"
        "       U+30AD, U+30AF, U+30B3, U+30B5, U+30BB, U+30BD, U+30BF, U+30C1, U+30C3, \\\n"
        "       U+30C4, U+30C6, U+30CA, U+30CB, U+30CD, U+30CE, U+30DE, U+30DF, U+30E1, \\\n"
        "       U+30E2, U+30E3, U+30E5, U+30E7, U+30EE, U+30F0..U+30F3, U+30F5, U+30F6, \\\n"
        "       U+31F0, U+31F1, U+31F2, U+31F3, U+31F4, U+31F5, U+31F6, U+31F7, U+31F8, \\\n"
        "       U+31F9, U+31FA, U+31FB, U+31FC, U+31FD, U+31FE, U+31FF, U+AC00..U+D7A3, \\\n"
        "       U+1100..U+1159, U+1161..U+11A2, U+11A8..U+11F9, U+A000..U+A48C, \\\n"
        "       U+A492..U+A4C6\n"
        "       ngram_chars = \\\n"
        /* Support for Chinese/Japanese/Korean, from
         * http://sphinxsearch.com/wiki/doku.php?id=charset_tables#cjk */
        "       U+4E00..U+9FBB, U+3400..U+4DB5, U+20000..U+2A6D6, U+FA0E, U+FA0F, \\\n"
        "       U+FA11, U+FA13, U+FA14, U+FA1F, U+FA21, U+FA23, U+FA24, U+FA27, U+FA28, \\\n"
        "       U+FA29, U+3105..U+312C, U+31A0..U+31B7, U+3041, U+3043, U+3045, U+3047, \\\n"
        "       U+3049, U+304B, U+304D, U+304F, U+3051, U+3053, U+3055, U+3057, U+3059, \\\n"
        "       U+305B, U+305D, U+305F, U+3061, U+3063, U+3066, U+3068, U+306A..U+306F, \\\n"
        "       U+3072, U+3075, U+3078, U+307B, U+307E..U+3083, U+3085, U+3087, \\\n"
        "       U+3089..U+308E, U+3090..U+3093, U+30A1, U+30A3, U+30A5, U+30A7, U+30A9, \\\n"
        "       U+30AD, U+30AF, U+30B3, U+30B5, U+30BB, U+30BD, U+30BF, U+30C1, U+30C3, \\\n"
        "       U+30C4, U+30C6, U+30CA, U+30CB, U+30CD, U+30CE, U+30DE, U+30DF, U+30E1, \\\n"
        "       U+30E2, U+30E3, U+30E5, U+30E7, U+30EE, U+30F0..U+30F3, U+30F5, U+30F6, \\\n"
        "       U+31F0, U+31F1, U+31F2, U+31F3, U+31F4, U+31F5, U+31F6, U+31F7, U+31F8, \\\n"
        "       U+31F9, U+31FA, U+31FB, U+31FC, U+31FD, U+31FE, U+31FF, U+AC00..U+D7A3, \\\n"
        "       U+1100..U+1159, U+1161..U+11A2, U+11A8..U+11F9, U+A000..U+A48C, \\\n"
        "       U+A492..U+A4C6\n"
        "       ngram_len = 1\n"
        "\n"
        "    rt_attr_string = cyrusid\n"
        "    rt_field = header_from\n"
        "    rt_field = header_to\n"
        "    rt_field = header_cc\n"
        "    rt_field = header_bcc\n"
        "    rt_field = header_subject\n"
        "    rt_field = header_listid\n"
        "    rt_field = header_type\n"
        "    rt_field = headers\n"
        "    rt_field = body\n"
        "}\n"
        "\n";
    static const char global_config[] =
        "searchd\n"
        "{\n"
        "    listen = $socket:mysql41\n"
        "    log = syslog\n"
        "    pid_file = $pidfile\n"
        "    binlog_path = $rootdir/binlog\n"
        "    compat_sphinxql_magics = 0\n"
        "    workers = threads\n"
        "    max_matches = " SPHINX_MAX_MATCHES "\n"
        "}\n"
        /* This index exists only to allow the searchd to start before
         * any real user indexes have been added */
        "index dummy\n"
        "{\n"
        "    type = rt\n"
        "    path = $rootdir/dummy\n"
        "    rt_field = dummy\n"
        "}\n";
    const char *rootdir = NULL;
    char *basedir = NULL;
    char *binlogdir = NULL;
    char *indexname = NULL;
    const char *config_file = NULL;
    char *new_config_file = NULL;
    int fd = -1;
    struct buf bits = BUF_INITIALIZER;
    struct buf user = BUF_INITIALIZER;
    struct buf global = BUF_INITIALIZER;
    int changed = 0;
    int r;

    config_file = sphinx_config_file();
    if (verbose) {
        if (mailbox)
            syslog(LOG_INFO, "Sphinx setting up config file %s for mailbox %s",
                    config_file, mailbox->name);
        else
            syslog(LOG_INFO, "Sphinx setting up config file %s",
                    config_file);
    }

    /* Read the old file */
    fd = open(config_file, O_RDONLY, 0);
    if (fd >= 0) {
        struct stat sb;

        r = fstat(fd, &sb);
        if (r < 0) {
            syslog(LOG_ERR, "IOERROR: unable to fstat %s: %m",
                   config_file);
            r = IMAP_IOERROR;
            goto out;
        }
        buf_ensure(&bits, sb.st_size+1);
        bits.len = sb.st_size;
        r = retry_read(fd, bits.s, bits.len);
        buf_cstring(&bits);
        if (r < 0) {
            syslog(LOG_ERR, "IOERROR: unable to read %s: %m",
                   config_file);
            r = IMAP_IOERROR;
            goto out;
        }
        close(fd);
        fd = -1;

        if (verbose)
            syslog(LOG_INFO, "Sphinx read %ld bytes of config file %s",
                    bits.len, config_file);
    }
    else if (fd != ENOENT) {
        /* it's ok to be missing the file - we build it from scratch */
        syslog(LOG_ERR, "IOERROR: unable to open %s for reading: %m",
               config_file);
        r = IMAP_IOERROR;
        goto out;
    }

    /* adjust the file contents */
    if (buf_findline(&bits, global_config) < 0) {

        /* See if the root directory already exists */
        rootdir = sphinx_rootdir(NULL);
        binlogdir = strconcat(rootdir, "/binlog", (char *)NULL);
        r = check_directory(binlogdir, verbose, create);
        if (r) goto out;

        buf_init_ro_cstr(&global, global_config);
        buf_replace_all(&global, "$socket", config_getstring(IMAPOPT_SPHINX_SOCKET));
        buf_replace_all(&global, "$pidfile", config_getstring(IMAPOPT_SPHINX_PIDFILE));
        buf_replace_all(&global, "$rootdir", rootdir);
        buf_append(&bits, &global);
        changed++;
        if (verbose)
            syslog(LOG_INFO, "Sphinx adding section \"searchd\"");
    }

    if (mailbox) {

        r = sphinx_basedir(mailbox, &basedir, &indexname);
        if (r) {
            syslog(LOG_ERR, "IOERROR: unable to name sphinx basedir for %s: %s",
                   mailbox->name, error_message(r));
            r = IMAP_IOERROR;
            goto out;
        }

        /* see if the base directory already exists */
        r = check_directory(basedir, verbose, create);
        if (r) goto out;

        buf_init_ro_cstr(&user, user_config);
        buf_replace_all(&user, "$indexname", indexname);
        if (buf_findline(&bits, user.s) < 0) {
            buf_replace_all(&user, "$basedir", basedir);
            buf_append(&bits, &user);
            changed++;
            if (verbose)
                syslog(LOG_INFO, "Sphinx adding section \"index %s\"", indexname);
        }
    }

    if (changed) {

        /* Write the new config file back */
        /* TODO: locking so multiple imapds don't all try to do this
         * at the same time */

        new_config_file = strconcat(config_file, ".new", (char *)NULL);
        if (verbose)
            syslog(LOG_INFO, "Sphinx writing new config file %s", new_config_file);

        fd = open(new_config_file, O_WRONLY|O_CREAT|O_TRUNC, 0600);
        if (fd < 0) {
            /* build the directory and retry */
            cyrus_mkdir(new_config_file, 0700);
            fd = open(new_config_file, O_WRONLY|O_CREAT|O_TRUNC, 0600);
        }
        if (fd < 0) {
            syslog(LOG_ERR, "IOERROR: unable to open %s for writing: %m",
                   new_config_file);
            r = IMAP_IOERROR;
            goto out;
        }

        r = retry_write(fd, bits.s, bits.len);
        if (r < 0) {
            syslog(LOG_ERR, "IOERROR: unable to write %s: %m",
                   new_config_file);
            r = IMAP_IOERROR;
            goto out;
        }

        close(fd);
        fd = -1;

        if (verbose)
            syslog(LOG_INFO, "Sphinx renaming config file %s into place", config_file);

        r = rename(new_config_file, config_file);
        if (r < 0) {
            syslog(LOG_ERR, "IOERROR: unable to rename %s to %s: %m",
                   new_config_file, config_file);
            r = IMAP_IOERROR;
            goto out;
        }
    }

    r = sphinx_signal(changed ? SIGHUP : 0, verbose);
    if (r == IMAP_NOTFOUND) {
        /* searchd not running, start it */
        if (verbose)
            syslog(LOG_INFO, "Sphinx starting searchd");

        r = run_command(SEARCHD, "--config", config_file,
                        "--syslog-prefix", sphinx_syslog_prefix(), (char *)NULL);
        if (r)
            syslog(LOG_ERR, "Failed to start searchd: %s", error_message(r));
    }

out:
    if (fd >= 0) close(fd);
    if (new_config_file) unlink(new_config_file);
    free(new_config_file);
    free(basedir);
    free(indexname);
    free(binlogdir);
    buf_free(&bits);
    buf_free(&user);
    buf_free(&global);
    return r;
}


static int open_latest(struct mailbox *mailbox, struct latestdb *ldb)
{
    char *basedir = NULL;
    char *path = NULL;
    int r;

    r = sphinx_basedir(mailbox, &basedir, NULL);
    if (r) return r;
    path = strconcat(basedir, LATESTDB_FNAME, NULL);
    free(basedir);

    if (!strcmpsafe(path, ldb->path)) {
        free(path);
        return 0;
    }

    /* need to open a new DB */

    close_latest(ldb);

    r = cyrusdb_open(config_getstring(IMAPOPT_SEARCH_INDEXED_DB),
                     path, CYRUSDB_CREATE, &ldb->db);
    if (r) {
        syslog(LOG_ERR, "DBERROR: opening %s: %s",
               path, cyrusdb_strerror(r));
        r = IMAP_IOERROR;
    }

    if (r) {
        free(path);
    }
    else {
        ldb->path = path;
    }
    return r;
}

static void close_latest(struct latestdb *ldb)
{
    free(ldb->path);
    ldb->path = NULL;

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

static int flush(search_text_receiver_t *rx)
{
    sphinx_update_receiver_t *tr = (sphinx_update_receiver_t *)rx;
    int r = 0;

    if (!tr->uncommitted) return 0;

    /* We write the lastid out first, to avoid a future instance
     * allocating a duplicate Sphinx document id should we crash */
    r = write_lastid(&tr->latestdb, tr->lastid, tr->super.verbose);
    if (r) return r;

    if (tr->super.verbose > 1)
        syslog(LOG_NOTICE, "Sphinx committing %u updates",
                tr->uncommitted);

    r = mysql_commit(tr->conn.mysql);
    if (r) {
        syslog(LOG_ERR, "IOERROR: Sphinx COMMIT failed for "
                        "mailbox %s, %u messages ending at uid %u: %s",
                        tr->super.mailbox->name,
                        tr->uncommitted,
                        tr->super.uid,
                        mysql_error(tr->conn.mysql));
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
    return r;
}

static int begin_message(search_text_receiver_t *rx, message_t *msg)
{
    sphinx_receiver_t *tr = (sphinx_receiver_t *)rx;
    int i;

    message_get_uid(msg, &tr->uid);
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
        syslog(LOG_NOTICE, "Sphinx: %ld bytes in part %s",
               tr->parts[tr->part].len, search_part_as_string(tr->part));

    tr->part = 0;
}

static void log_keywords(sphinx_update_receiver_t *tr)
{
    int i;
    int r;
    struct buf query = BUF_INITIALIZER;
    MYSQL_RES *res = NULL;
    MYSQL_ROW row = NULL;

    for (i = 0 ; i < SEARCH_NUM_PARTS ; i++) {
        if (!tr->super.parts[i].len) continue;
        buf_reset(&query);
        buf_appendcstr(&query, "CALL KEYWORDS(");
        append_escaped(&query, &tr->super.parts[i], '\'');
        buf_appendcstr(&query, ", ");
        append_escaped_cstr(&query, tr->super.indexname, '\'');
        buf_appendcstr(&query, ",0)");
        r = doquery(&tr->conn, tr->super.verbose, &query);

        res = mysql_use_result(tr->conn.mysql);
        if (!res) continue;

        while ((row = mysql_fetch_row(res)))
            syslog(LOG_INFO, "keyword %s\n", row[0]);
        mysql_free_result(res);
    }
    buf_free(&query);
}

static int end_message_update(search_text_receiver_t *rx)
{
    sphinx_update_receiver_t *tr = (sphinx_update_receiver_t *)rx;
    struct buf *query = &tr->super.tmp;
    int i;
    int r;

    if (!tr->conn.mysql) return IMAP_INTERNAL;

    buf_reset(query);
    buf_printf(query, "INSERT INTO %s (id,"COL_CYRUSID, tr->super.indexname);
    for (i = 0 ; i < SEARCH_NUM_PARTS ; i++) {
        if (tr->super.parts[i].len) {
            buf_appendcstr(query, ",");
            buf_appendcstr(query, column_by_part[i]);
        }
    }
    buf_appendcstr(query, ") VALUES (");
    buf_printf(query, "%u,", ++tr->lastid);
    append_escaped(query, make_cyrusid(tr->super.mailbox, tr->super.uid), '\'');
    for (i = 0 ; i < SEARCH_NUM_PARTS ; i++) {
        if (tr->super.parts[i].len) {
            buf_appendcstr(query, ",");
            append_escaped(query, &tr->super.parts[i], '\'');
        }
    }
    /* apparently Sphinx doesn't let you explicitly INSERT a NULL */
    buf_appendcstr(query, ")");

    r = doquery(&tr->conn, tr->super.verbose, query);
    if (r) goto out; /* TODO: propagate error to the user */

    if (tr->super.verbose > 3) log_keywords(tr);

    ++tr->uncommitted;
    tr->latest = tr->super.uid;

out:
    tr->super.uid = 0;
    return r;
}

static const char *indexing_lockpath(struct mailbox *mailbox)
{
    char *userid = mboxname_to_userid(mailbox->name);
    char *usermbox = mboxname_user_mbox(userid, NULL);
    const char *lockpath = mboxname_lockpath_suffix(usermbox, INDEXING_LOCK_SUFFIX);
    free(usermbox);
    free(userid);
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

    r = sphinx_setup(mailbox, tr->super.verbose, /*create*/1);
    if (r) return r;

    r = sphinx_basedir(mailbox, NULL, &tr->super.indexname);
    if (r) return r;

    r = get_connection(&tr->conn);
    if (r) return r;

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

    if (tr->conn.mysql)
        r = flush(rx);

    tr->super.mailbox = NULL;
    free(tr->super.indexname);
    tr->super.indexname = NULL;

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
    tr->super.super.flush = flush;

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
    free(tr->indexname);

    free(tr);

    return r;
}

static int end_update(search_text_receiver_t *rx)
{
    sphinx_update_receiver_t *tr = (sphinx_update_receiver_t *)rx;

    close_latest(&tr->latestdb);
    close_connection(&tr->conn);
    indexing_unlock(&tr->indexing_lock_fd);
    return free_receiver(&tr->super);
}

static int begin_mailbox_snippets(search_text_receiver_t *rx,
                                  struct mailbox *mailbox,
                                  int incremental __attribute__((unused)))
{
    sphinx_snippet_receiver_t *tr = (sphinx_snippet_receiver_t *)rx;
    int r;

    r = get_connection(&tr->conn);
    if (r) return r;

    r = sphinx_basedir(mailbox, NULL, &tr->super.indexname);
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
        r = IMAP_INTERNAL;          /* need to call begin_mailbox() */
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
        buf_appendcstr(&query, ", ");
        append_escaped_cstr(&query, tr->super.indexname, '\'');
        buf_appendcstr(&query, ", ");
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
    free(tr->super.indexname);
    tr->super.indexname = NULL;

    return 0;
}

static search_text_receiver_t *begin_snippets(void *internalised,
                                              int verbose,
                                              search_snippet_markup_t *m __attribute__((unused)),
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

static int start_daemon(int verbose)
{
    return sphinx_setup(NULL, verbose, /*create*/1);
}

static int stop_daemon(int verbose)
{
    int r;

    if (verbose)
        syslog(LOG_INFO, "Sphinx stopping searchd");

    r = run_command(SEARCHD, "--config", sphinx_config_file(),
                    "--syslog-prefix", sphinx_syslog_prefix(),
                    "--stopwait", (char *)NULL);
    if (r)
        syslog(LOG_ERR, "Failed to stop searchd: %s", error_message(r));
    return r;
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
    stop_daemon,
    /* list_files */NULL,   /* XXX: fixme */
    /* compact */NULL,
    /* deluser */NULL   /* XXX: fixme */
};

