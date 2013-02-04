/* search_xapian.c -- glue code for searching with Xapian
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
#include <dirent.h>

#include "imap_err.h"
#include "global.h"
#include "ptrarray.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "mboxlist.h"
#include "xstats.h"
#include "search_engines.h"
#include "cyr_lock.h"
#include "xapian_wrap.h"
#include "command.h"

struct latestdb
{
    struct db *db;
    char *path;
};
#define LATESTDB_INITIALIZER { 0, 0 }
#define LATESTDB_VERSION	1
#define LATESTDB_FNAME		"/latest.x.db"

#define XAPIAN_DIRNAME		"/xapian"
#define INDEXING_LOCK_SUFFIX	".indexing.lock"

static int open_latest(struct mailbox *, const char *root, struct latestdb *);
static void close_latest(struct latestdb *);
static int read_latest(struct latestdb *, struct mailbox *, uint32_t *, int);
static int write_latest(struct latestdb *, struct mailbox *, uint32_t, int);
static int xapian_basedir(const char *mboxname, const char *part,
			  const char *root, char **basedirp);

/* Name of columns */
#define COL_CYRUSID	"cyrusid"
static const char * const prefix_by_part[SEARCH_NUM_PARTS] = {
    NULL,
    "F",		/* FROM */
    "T",		/* TO */
    "C",		/* CC */
    "B",		/* BCC */
    "S",		/* SUBJECT */
    "L",		/* LISTID */
    "Y",		/* TYPE */
    "H",		/* HEADERS */
    "D",		/* BODY */
};

struct segment
{
    int part;
    int sequence;	/* forces stable sort order JIC */
    int is_finished;
    struct buf text;
};

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

static const char *make_cyrusid(struct mailbox *mailbox, uint32_t uid)
{
    static struct buf buf = BUF_INITIALIZER;
    // user.cassandane.1320711192.196715
    buf_reset(&buf);
    buf_printf(&buf, "%s.%u.%u",
		     mailbox->name,
		     mailbox->i.uidvalidity,
		     uid);
    return buf_cstring(&buf);
}

static int rsync_tree(const char *fromdir, const char *todir,
		      int verbose, int atomic, int remove)
{
    char *fromdir2 = strconcat(fromdir, "/", (char *)NULL);
    char *todir_new = NULL;
    char *todir_old = NULL;
    int r = 0;

    if (atomic) {
	todir_new = strconcat(todir, ".NEW", (char *)NULL);
	todir_old = strconcat(todir, ".OLD", (char *)NULL);
    }
    else {
	todir_new = xstrdup(todir);
    }

    if (verbose > 1)
	syslog(LOG_INFO, "running: rsync %s -> %s", fromdir2, todir_new);
    r = run_command("/usr/bin/rsync", (verbose ? "-av" : "-a"),
		       fromdir2, todir_new, (char *)NULL);
    if (r) goto out;

    if (atomic) {
	/* this isn't really atomic because the atomic-rename trick
	 * doesn't work on directories, but it does reduce the window */

	if (verbose > 1)
	    syslog(LOG_INFO, "renaming %s -> %s", todir, todir_old);
	r = rename(todir, todir_old);
	if (r) {
	    syslog(LOG_ERR, "IOERROR: failed to rename %s to %s: %s",
		    todir, todir_old, error_message(errno));
	    r = IMAP_IOERROR;
	    goto out;
	}

	if (verbose > 1)
	    syslog(LOG_INFO, "renaming %s -> %s", todir_new, todir);
	r = rename(todir_new, todir);
	if (r) {
	    syslog(LOG_ERR, "IOERROR: failed to rename %s to %s: %s",
		    todir_new, todir, error_message(errno));
	    r = IMAP_IOERROR;
	    goto out;
	}

	run_command("/bin/rm", "-rf", todir_old, (char *)NULL);
    }

    if (remove) {
	if (verbose > 1)
	    syslog(LOG_INFO, "Removing tree %s", fromdir);
	run_command("/bin/rm", "-rf", fromdir, (char *)NULL);
    }

out:
    free(fromdir2);
    free(todir_new);
    free(todir_old);
    return r;
}

/* ====================================================================== */

struct opnode
{
    int op;	/* SEARCH_OP_* or SEARCH_PART_* constant */
    char *arg;
    struct opnode *next;
    struct opnode *children;
};

typedef struct xapian_builder xapian_builder_t;
struct xapian_builder {
    search_builder_t super;
    struct mailbox *mailbox;
    xapian_db_t *db;
    int opts;
    struct opnode *root;
    ptrarray_t stack;	    /* points to opnode* */
    int (*proc)(const char *, uint32_t, uint32_t, void *);
    void *rock;
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

static xapian_query_t *opnode_to_query(const xapian_db_t *db, struct opnode *on)
{
    struct opnode *child;
    xapian_query_t *qq = NULL;
    int i;
    ptrarray_t childqueries = PTRARRAY_INITIALIZER;

    switch (on->op) {
    case SEARCH_OP_NOT:
	if (on->children)
	    qq = xapian_query_new_not(db, opnode_to_query(db, on->children));
	break;
    case SEARCH_OP_OR:
    case SEARCH_OP_AND:
	for (child = on->children ; child ; child = child->next) {
	    qq = opnode_to_query(db, child);
	    if (qq) ptrarray_push(&childqueries, qq);
	}
	qq = NULL;
	if (childqueries.count)
	    qq = xapian_query_new_compound(db, (on->op == SEARCH_OP_OR),
					   (xapian_query_t **)childqueries.data,
					   childqueries.count);
	break;
    case SEARCH_PART_ANY:
	/* Xapian does not have a convenient way of search for "any
	 * field"; instead we fake it by explicitly searching for
	 * all of the available prefixes */
	for (i = 0 ; i < SEARCH_NUM_PARTS ; i++) {
	    if (prefix_by_part[i] != NULL)
		ptrarray_push(&childqueries,
			      xapian_query_new_match(db, prefix_by_part[i], on->arg));
	}
	qq = xapian_query_new_compound(db, /*is_or*/1,
				       (xapian_query_t **)childqueries.data,
				       childqueries.count);
	break;
    default:
	assert(on->arg != NULL);
	assert(on->children == NULL);
	qq = xapian_query_new_match(db, prefix_by_part[on->op], on->arg);
	break;
    }
    ptrarray_fini(&childqueries);
    return qq;
}

static int xapian_run_cb(const char *cyrusid, void *rock)
{
    xapian_builder_t *bb = (xapian_builder_t *)rock;
    int r;
    const char *mboxname;
    unsigned int uidvalidity;
    unsigned int uid;

    r = parse_cyrusid(cyrusid, &mboxname, &uidvalidity, &uid);
    if (!r) {
	syslog(LOG_ERR, "IOERROR: Cannot parse \"%s\" as cyrusid", cyrusid);
	return IMAP_IOERROR;
    }

    if (!(bb->opts & SEARCH_MULTIPLE)) {
	if (strcmp(mboxname, bb->mailbox->name))
	    return 0;
	if (uidvalidity != bb->mailbox->i.uidvalidity)
	    return 0;
    }

    xstats_inc(SPHINX_RESULT);
    return bb->proc(mboxname, uidvalidity, uid, bb->rock);
}

static int run(search_builder_t *bx, search_hit_cb_t proc, void *rock)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;
    xapian_query_t *qq = NULL;
    uint32_t uid;
    uint32_t latest = 0;
    int r = 0;

    if (bb->db == NULL)
	return IMAP_NOTFOUND;	    /* there's no index for this user */

    if ((bb->opts & SEARCH_UNINDEXED)) {
	/* To avoid races, we want the 'latest' uid we use to be
	 * an underestimate, because the caller can handle false
	 * positives but not false negatives.  So we fetch it
	 * first before the main query. */
	struct latestdb ldb = LATESTDB_INITIALIZER;
	r = open_latest(bb->mailbox, NULL, &ldb);
	if (!r) goto out;
	r = read_latest(&ldb, bb->mailbox, &latest,
			SEARCH_VERBOSE(bb->opts));
	close_latest(&ldb);
	if (r) goto out;
    }

    optimise_nodes(NULL, bb->root);
    qq = opnode_to_query(bb->db, bb->root);

    bb->proc = proc;
    bb->rock = rock;

    r = xapian_query_run(bb->db, qq, xapian_run_cb, bb);
    if (r) goto out;

    if ((bb->opts & SEARCH_UNINDEXED)) {
	/* add in the unindexed uids as false positives */
	for (uid = latest+1 ; uid <= bb->mailbox->i.last_uid ; uid++) {
	    xstats_inc(SPHINX_UNINDEXED);
	    r = proc(bb->mailbox->name, bb->mailbox->i.uidvalidity, uid, rock);
	    if (r) goto out;
	}
    }

out:
    if (qq) xapian_query_free(qq);
    return r;
}

static void begin_boolean(search_builder_t *bx, int op)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;
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
    xapian_builder_t *bb = (xapian_builder_t *)bx;
    if (SEARCH_VERBOSE(bb->opts))
	syslog(LOG_INFO, "end_boolean");
    ptrarray_pop(&bb->stack);
}

static void match(search_builder_t *bx, int part, const char *str)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;
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

static void *get_internalised(search_builder_t *bx)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;
    struct opnode *on = bb->root;
    bb->root = NULL;
    optimise_nodes(NULL, on);
    return on;
}

static char *describe_internalised(void *internalised __attribute__((unused)))
{
    return xstrdup("--xapian query--");
}

static void free_internalised(void *internalised)
{
    struct opnode *on = (struct opnode *)internalised;
    if (on) opnode_delete(on);
}

static search_builder_t *begin_search(struct mailbox *mailbox, int opts)
{
    xapian_builder_t *bb;
    char *basedir = NULL;
    char *dir;
    int r = 0;

    xapian_init();

    bb = xzmalloc(sizeof(xapian_builder_t));
    bb->super.begin_boolean = begin_boolean;
    bb->super.end_boolean = end_boolean;
    bb->super.match = match;
    bb->super.get_internalised = get_internalised;
    bb->super.run = run;

    bb->mailbox = mailbox;
    bb->opts = opts;

    r = xapian_basedir(mailbox->name, mailbox->part, NULL, &basedir);
    if (r) goto out;
    dir = strconcat(basedir, XAPIAN_DIRNAME, NULL);

    bb->db = xapian_db_open(dir);
    if (!bb->db) goto out;

    if ((opts & SEARCH_MULTIPLE))
	xstats_inc(SPHINX_MULTIPLE);
    else
	xstats_inc(SPHINX_SINGLE);

out:
    free(basedir);
    free(dir);
    return &bb->super;
}

static void end_search(search_builder_t *bx)
{
    xapian_builder_t *bb = (xapian_builder_t *)bx;

    ptrarray_fini(&bb->stack);
    if (bb->root) opnode_delete(bb->root);
    if (bb->db) xapian_db_close(bb->db);
    free(bx);
}

/* ====================================================================== */

/* base class for both update and snippet receivers */
typedef struct xapian_receiver xapian_receiver_t;
struct xapian_receiver
{
    search_text_receiver_t super;
    int verbose;
    struct mailbox *mailbox;
    uint32_t uid;
    int part;
    unsigned int parts_total;
    int truncate_warning;
    ptrarray_t segs;
};

/* receiver used for updating the index */
typedef struct xapian_update_receiver xapian_update_receiver_t;
struct xapian_update_receiver
{
    xapian_receiver_t super;
    xapian_dbw_t *dbw;
    int indexing_lock_fd;
    unsigned int uncommitted;
    unsigned int commits;
    uint32_t latest;
    struct latestdb latestdb;
    char *temp_root;
    char *last_basedir;
    char *last_real_basedir;
};

/* receiver used for extracting snippets after a search */
typedef struct xapian_snippet_receiver xapian_snippet_receiver_t;
struct xapian_snippet_receiver
{
    xapian_receiver_t super;
    xapian_snipgen_t *snipgen;
    struct opnode *root;
    search_snippet_cb_t proc;
    void *rock;
};

/* Maximum size of a query, determined empirically, is a little bit
 * under 8MB.  That seems like more than enough, so let's limit the
 * total amount of parts text to 4 MB. */
#define MAX_PARTS_SIZE	    (4*1024*1024)

static const char *xapian_rootdir(const char *partition)
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

/* Returns in *basedirp a new string which must be free()d */
static int xapian_basedir(const char *mboxname, const char *partition,
			  const char *root, char **basedirp)
{
    char *basedir = NULL;
    struct mboxname_parts parts;
    char c[2], d[2];
    int r;

    mboxname_init_parts(&parts);

    if (!root)
	root = xapian_rootdir(partition);
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
			    "/", dir_hash_b(parts.userid, config_fulldirhash, c),
			    FNAME_USERDIR,
			    parts.userid,
			    (char *)NULL);
    else
	basedir = strconcat(root,
			    "/", dir_hash_b(parts.userid, config_fulldirhash, c),
			    FNAME_USERDIR,
			    parts.userid,
			    (char *)NULL);

    r = 0;

out:
    if (!r && basedirp)
	*basedirp = basedir;
    else
	free(basedir);
    mboxname_free_parts(&parts);
    return r;
}

static int check_directory(const char *dir, int verbose, int create)
{
    int r;
    char *dummyfile = NULL;
    struct stat sb;

    r = stat(dir, &sb);
    if (r < 0) {
	if (errno != ENOENT) {
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

static int open_latest(struct mailbox *mailbox, const char *root,
		       struct latestdb *ldb)
{
    char *basedir = NULL;
    char *path = NULL;
    int r;

    r = xapian_basedir(mailbox->name, mailbox->part, root, &basedir);
    if (r) return r;
    path = strconcat(basedir, LATESTDB_FNAME, NULL);
    free(basedir);

    if (!strcmpsafe(path, ldb->path)) {
	free(path);
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

static int flush(search_text_receiver_t *rx)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    int r = 0;
    struct timeval start, end;

    if (!tr->uncommitted) return 0;

    gettimeofday(&start, NULL);
    r = xapian_dbw_commit_txn(tr->dbw);
    if (r) goto out;
    gettimeofday(&end, NULL);

    syslog(LOG_INFO, "Xapian committed %u updates in %.6f sec",
		tr->uncommitted, timesub(&start, &end));

    /* We write out the latestid for the mailbox only after successfully
     * updating the index, to avoid a future instance not realising that
     * there are unindexed messages should we fail to index */
    r = write_latest(&tr->latestdb, tr->super.mailbox, tr->latest,
		     tr->super.verbose);
    if (r) goto out;

    tr->uncommitted = 0;
    tr->commits++;

out:
    return r;
}

static void free_segments(xapian_receiver_t *tr)
{
    int i;
    struct segment *seg;

    for (i = 0 ; i < tr->segs.count ; i++) {
	seg = (struct segment *)ptrarray_nth(&tr->segs, i);
	buf_free(&seg->text);
	free(seg);
    }
    ptrarray_truncate(&tr->segs, 0);
}

static void begin_message(search_text_receiver_t *rx, uint32_t uid)
{
    xapian_receiver_t *tr = (xapian_receiver_t *)rx;

    tr->uid = uid;
    free_segments(tr);
    tr->parts_total = 0;
    tr->truncate_warning = 0;
}

static void begin_part(search_text_receiver_t *rx, int part)
{
    xapian_receiver_t *tr = (xapian_receiver_t *)rx;

    tr->part = part;
}

static void append_text(search_text_receiver_t *rx,
			const struct buf *text)
{
    xapian_receiver_t *tr = (xapian_receiver_t *)rx;
    struct segment *seg;

    if (tr->part) {
	unsigned len = text->len;
	if (tr->parts_total + len > MAX_PARTS_SIZE) {
	    if (!tr->truncate_warning++)
		syslog(LOG_ERR, "Xapian: truncating text from "
				"message mailbox %s uid %u",
				tr->mailbox->name, tr->uid);
	    len = MAX_PARTS_SIZE - tr->parts_total;
	}
	if (len) {
	    tr->parts_total += len;

	    seg = (struct segment *)ptrarray_tail(&tr->segs);
	    if (!seg || seg->is_finished || seg->part != tr->part) {
		seg = (struct segment *)xzmalloc(sizeof(*seg));
		seg->sequence = tr->segs.count;
		seg->part = tr->part;
		ptrarray_append(&tr->segs, seg);
	    }
	    buf_appendmap(&seg->text, text->s, len);
	}
    }
}

static void end_part(search_text_receiver_t *rx,
		     int part __attribute__((unused)))
{
    xapian_receiver_t *tr = (xapian_receiver_t *)rx;
    struct segment *seg;

    seg = (struct segment *)ptrarray_tail(&tr->segs);
    if (seg)
	seg->is_finished = 1;

    if (tr->verbose > 1)
	syslog(LOG_NOTICE, "Xapian: %u bytes in part %s",
	       (seg ? seg->text.len : 0), search_part_as_string(tr->part));

    tr->part = 0;
}

static int compare_segs(const void **v1, const void **v2)
{
    const struct segment *s1 = *(const struct segment **)v1;
    const struct segment *s2 = *(const struct segment **)v2;
    int r;

    r = s1->part - s2->part;
    if (!r)
	r = s1->sequence - s2->sequence;
    return r;
}

static int end_message_update(search_text_receiver_t *rx)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    int i;
    struct segment *seg;
    int r = 0;

    if (!tr->dbw) return IMAP_INTERNAL;

    r = xapian_dbw_begin_doc(tr->dbw, make_cyrusid(tr->super.mailbox, tr->super.uid));
    if (r) goto out;

    ptrarray_sort(&tr->super.segs, compare_segs);

    for (i = 0 ; i < tr->super.segs.count ; i++) {
	seg = (struct segment *)ptrarray_nth(&tr->super.segs, i);
	r = xapian_dbw_doc_part(tr->dbw, &seg->text, prefix_by_part[seg->part]);
	if (r) goto out;
    }

    if (!tr->uncommitted) {
	r = xapian_dbw_begin_txn(tr->dbw);
	if (r) goto out;
    }
    r = xapian_dbw_end_doc(tr->dbw);
    if (r) goto out;
    ++tr->uncommitted;
    tr->latest = tr->super.uid;

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
				int incremental)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    char *basedir = NULL;
    char *real_basedir = NULL;
    char *dir = NULL;
    int r;

    r = xapian_basedir(mailbox->name, mailbox->part, tr->temp_root, &basedir);
    if (r) return r;
    dir = strconcat(basedir, XAPIAN_DIRNAME, NULL);

    r = indexing_lock(mailbox, &tr->indexing_lock_fd);
    if (r) goto out;

    r = check_directory(dir, tr->super.verbose, /*create*/1);
    if (r) goto out;

    if (tr->temp_root) {
	r = xapian_basedir(mailbox->name, mailbox->part, NULL, &real_basedir);
	if (r) goto out;

	r = check_directory(real_basedir, tr->super.verbose, /*create*/1);
	if (r) goto out;
    }

    if (strcmpsafe(basedir, tr->last_basedir)) {
	/* changing from one Xapian DB to another, or starting
	 * the first Xapian DB */

	if (tr->temp_root) {
	    if (tr->last_basedir && tr->commits) {
		/* rsync back in the database we just finished */
		r = rsync_tree(tr->last_basedir, tr->last_real_basedir,
			       tr->super.verbose, /*atomic*/1, /*remove*/0);
		if (r) goto out;
	    }

	    if (incremental) {
		/* rsync out a temporary copy of the database we're starting on */
		r = rsync_tree(real_basedir, basedir,
			       tr->super.verbose, /*atomic*/0, /*remove*/0);
		if (r) goto out;
	    }

	    tr->commits = 0;
	}

	if (tr->dbw)
	    xapian_dbw_close(tr->dbw);
	tr->dbw = xapian_dbw_open(dir, incremental);
	if (!tr->dbw) {
	    r = IMAP_IOERROR;
	    goto out;
	}
    }

    tr->super.mailbox = mailbox;

    r = open_latest(mailbox, tr->temp_root, &tr->latestdb);
    if (r) goto out;

    if (incremental) {
	r = read_latest(&tr->latestdb, mailbox, &tr->latest, tr->super.verbose);
	if (r) goto out;
    }
    else {
	if (tr->super.verbose > 1)
	    syslog(LOG_INFO, "resetting latest UID to 0");
	tr->latest = 0;
    }

    free(tr->last_basedir);
    tr->last_basedir = xstrdup(basedir);
    free(tr->last_real_basedir);
    tr->last_real_basedir = xstrdupnull(real_basedir);

out:
    free(basedir);
    free(real_basedir);
    free(dir);
    return 0;
}

static uint32_t first_unindexed_uid(search_text_receiver_t *rx)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;

    return tr->latest+1;
}

static int is_indexed(search_text_receiver_t *rx, uint32_t uid)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;

    return (uid <= tr->latest);
}

static int end_mailbox_update(search_text_receiver_t *rx,
			      struct mailbox *mailbox
			    __attribute__((unused)))
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    int r = 0;

    if (tr->dbw)
	r = flush(rx);

    tr->super.mailbox = NULL;

    return r;
}

static void use_temp_root(search_text_receiver_t *rx, const char *dir)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;

    free(tr->temp_root);
    tr->temp_root = xstrdupnull(dir);
}

static search_text_receiver_t *begin_update(int verbose)
{
    xapian_update_receiver_t *tr;

    xapian_init();

    tr = xzmalloc(sizeof(xapian_update_receiver_t));
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
    tr->super.super.use_temp_root = use_temp_root;

    tr->indexing_lock_fd = -1;
    tr->super.verbose = verbose;

    return &tr->super.super;
}

static int free_receiver(xapian_receiver_t *tr)
{
    int r = 0;

    free_segments(tr);
    ptrarray_fini(&tr->segs);

    free(tr);

    return r;
}

static int end_update(search_text_receiver_t *rx)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    int r = 0;

    if (tr->dbw) {
	xapian_dbw_close(tr->dbw);
	tr->dbw = NULL;
    }
    close_latest(&tr->latestdb);

    if (tr->temp_root) {
	if (tr->last_basedir && tr->commits)
	    r = rsync_tree(tr->last_basedir, tr->last_real_basedir,
			   tr->super.verbose, /*atomic*/1, /*remove*/1);
    }

    indexing_unlock(&tr->indexing_lock_fd);
    free(tr->temp_root);
    free(tr->last_basedir);
    free(tr->last_real_basedir);
    return free_receiver(&tr->super);
}

static int begin_mailbox_snippets(search_text_receiver_t *rx,
				  struct mailbox *mailbox,
				  int incremental __attribute__((unused)))
{
    xapian_snippet_receiver_t *tr = (xapian_snippet_receiver_t *)rx;

    tr->super.mailbox = mailbox;

    return 0;
}

/* Find match terms for the given part and add them to the Xapian
 * snippet generator.  */
static void generate_snippet_terms(xapian_snipgen_t *snipgen,
				   int part,
				   struct opnode *on)
{
    struct opnode *child;

    switch (on->op) {

    case SEARCH_OP_NOT:
    case SEARCH_OP_OR:
    case SEARCH_OP_AND:
	for (child = on->children ; child ; child = child->next)
	    generate_snippet_terms(snipgen, part, child);
	break;

    case SEARCH_PART_ANY:
	assert(on->children == NULL);
	if (part != SEARCH_PART_HEADERS ||
	    !config_getswitch(IMAPOPT_SPHINX_TEXT_EXCLUDES_ODD_HEADERS)) {
	    xapian_snipgen_add_match(snipgen, on->arg);
	}
	break;

    default:
	/* other SEARCH_PART_* constants */
	assert(on->op >= 0 && on->op < SEARCH_NUM_PARTS);
	assert(on->children == NULL);
	if (part == on->op) {
	    xapian_snipgen_add_match(snipgen, on->arg);
	}
	break;
    }
}

static int end_message_snippets(search_text_receiver_t *rx)
{
    xapian_snippet_receiver_t *tr = (xapian_snippet_receiver_t *)rx;
    struct buf snippets = BUF_INITIALIZER;
    unsigned int context_length;
    int i;
    struct segment *seg;
    int last_part = -1;
    int r;

    if (!tr->snipgen) {
	r = IMAP_INTERNAL;	    /* need to call begin_mailbox() */
	goto out;
    }
    if (!tr->root) {
	r = 0;
	goto out;
    }

    ptrarray_sort(&tr->super.segs, compare_segs);

    for (i = 0 ; i < tr->super.segs.count ; i++) {
	seg = (struct segment *)ptrarray_nth(&tr->super.segs, i);

	if (seg->part != last_part) {

	    if (last_part != -1) {
		r = xapian_snipgen_end_doc(tr->snipgen, &snippets);
		if (!r && snippets.len)
		    r = tr->proc(tr->super.mailbox, tr->super.uid, last_part, snippets.s, tr->rock);
		if (r) break;
	    }

	    /* TODO: UINT_MAX doesn't behave as expected, which is probably
	     * a bug, but really any value larger than a reasonable Subject
	     * length will do */
	    context_length = (seg->part == SEARCH_PART_HEADERS || seg->part == SEARCH_PART_BODY ? 5 : 1000000);
	    r = xapian_snipgen_begin_doc(tr->snipgen, context_length);
	    if (r) break;

	    generate_snippet_terms(tr->snipgen, seg->part, tr->root);
	}

	r = xapian_snipgen_doc_part(tr->snipgen, &seg->text);
	if (r) break;

	last_part = seg->part;
    }

    if (last_part != -1) {
	r = xapian_snipgen_end_doc(tr->snipgen, &snippets);
	if (!r && snippets.len)
	    r = tr->proc(tr->super.mailbox, tr->super.uid, last_part, snippets.s, tr->rock);
    }

out:
    buf_free(&snippets);
    return r;
}

static int end_mailbox_snippets(search_text_receiver_t *rx,
				struct mailbox *mailbox
				    __attribute__((unused)))
{
    xapian_snippet_receiver_t *tr = (xapian_snippet_receiver_t *)rx;

    tr->super.mailbox = NULL;

    return 0;
}

static search_text_receiver_t *begin_snippets(void *internalised,
					      int verbose,
					      search_snippet_cb_t proc,
					      void *rock)
{
    xapian_snippet_receiver_t *tr;

    xapian_init();

    tr = xzmalloc(sizeof(xapian_snippet_receiver_t));
    tr->super.super.begin_mailbox = begin_mailbox_snippets;
    tr->super.super.begin_message = begin_message;
    tr->super.super.begin_part = begin_part;
    tr->super.super.append_text = append_text;
    tr->super.super.end_part = end_part;
    tr->super.super.end_message = end_message_snippets;
    tr->super.super.end_mailbox = end_mailbox_snippets;

    tr->super.verbose = verbose;
    tr->root = (struct opnode *)internalised;
    tr->snipgen = xapian_snipgen_new();
    tr->proc = proc;
    tr->rock = rock;

    return &tr->super.super;
}

static int end_snippets(search_text_receiver_t *rx)
{
    xapian_snippet_receiver_t *tr = (xapian_snippet_receiver_t *)rx;

    if (tr->snipgen) xapian_snipgen_free(tr->snipgen);
    return free_receiver(&tr->super);
}

static int list_files(const char *mboxname, const char *partition, strarray_t *files)
{
    char *basedir = NULL;
    char *xapiandir = NULL;
    char *fname = NULL;
    DIR *dirh = NULL;
    struct dirent *de;
    struct stat sb;
    int r;

    r = xapian_basedir(mboxname, partition, NULL, &basedir);
    if (r) return r;

    fname = strconcat(basedir, LATESTDB_FNAME, (char *)NULL);
    r = stat(fname, &sb);
    if (!r) {
	strarray_appendm(files, fname);
	fname = NULL;
    }
    r = 0;

    xapiandir = strconcat(basedir, XAPIAN_DIRNAME, (char *)NULL);
    dirh = opendir(xapiandir);
    if (!dirh) goto out;

    while ((de = readdir(dirh))) {
	if (de->d_name[0] == '.') continue;
	free(fname);
	fname = strconcat(xapiandir, "/", de->d_name, (char *)NULL);
	r = stat(fname, &sb);
	if (!r && S_ISREG(sb.st_mode)) {
	    strarray_appendm(files, fname);
	    fname = NULL;
	}
    }
    r = 0;

out:
    if (dirh) closedir(dirh);
    free(basedir);
    free(xapiandir);
    free(fname);
    return r;
}

const struct search_engine xapian_search_engine = {
    "Xapian",
    SEARCH_FLAG_CAN_BATCH,
    begin_search,
    end_search,
    begin_update,
    end_update,
    begin_snippets,
    end_snippets,
    describe_internalised,
    free_internalised,
    /*start_daemon*/NULL,
    /*stop_daemon*/NULL,
    list_files
};

