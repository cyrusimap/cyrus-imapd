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

#include "imap_err.h"
#include "global.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "mboxlist.h"
#include "xstats.h"
#include "search_engines.h"
#include "cyr_lock.h"
#include "xapian_wrap.h"

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

static int open_latest(struct mailbox *, struct latestdb *);
static void close_latest(struct latestdb *);
static int read_latest(struct latestdb *, struct mailbox *, uint32_t *, int);
static int write_latest(struct latestdb *, struct mailbox *, uint32_t, int);

/* Name of columns */
#define COL_CYRUSID	"cyrusid"
static const char * const prefix_by_part[SEARCH_NUM_PARTS] = {
    NULL,
    "Xfen",		/* FROM, English */
    "Xten",		/* TO, English */
    "Xcen",		/* CC, English */
    "Xben",		/* BCC, English */
    "Xsen",		/* SUBJECT, English */
    "Xhen",		/* HEADERS, English */
    "Xden",		/* BODY, English */
};

#if 0
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
#endif

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
    struct buf parts[SEARCH_NUM_PARTS];
};

/* receiver used for updating the index */
typedef struct xapian_update_receiver xapian_update_receiver_t;
struct xapian_update_receiver
{
    xapian_receiver_t super;
    xapian_dbw_t *dbw;
    int indexing_lock_fd;
    unsigned int uncommitted;
    uint32_t latest;
    struct latestdb latestdb;
};

#if 0
/* receiver used for extracting snippets after a search */
typedef struct xapian_snippet_receiver xapian_snippet_receiver_t;
struct xapian_snippet_receiver
{
    xapian_receiver_t super;
    struct connection conn;
    struct opnode *root;
    search_snippet_cb_t proc;
    void *rock;
};
#endif

/* This is carefully aligned with the default search_batchsize so that
 * we get the minimum number of commits with default parameters */
#define MAX_UNCOMMITTED	    20

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
    confkey = strconcat("sphinxpartition-", partition, NULL);
    root = config_getoverflowstring(confkey, NULL);
    free(confkey);
    return root;
}

/* Returns in *basedirp a new string which must be free()d */
static int xapian_basedir(const struct mailbox *mailbox, char **basedirp)
{
    const char *root;
    char *basedir = NULL;
    struct mboxname_parts parts;
    char c[2], d[2];
    int r;

    mboxname_init_parts(&parts);

    root = xapian_rootdir(mailbox->part);
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

static int open_latest(struct mailbox *mailbox, struct latestdb *ldb)
{
    char *basedir = NULL;
    char *path = NULL;
    int r;

    r = xapian_basedir(mailbox, &basedir);
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

static int flush(xapian_update_receiver_t *tr, int force)
{
    int r = 0;

    if (!force && tr->uncommitted < MAX_UNCOMMITTED) return 0;
    if (!tr->uncommitted) return 0;

    if (tr->super.verbose > 1)
	syslog(LOG_NOTICE, "Xapian committing");

    r = xapian_dbw_commit_txn(tr->dbw);
    if (r) goto out;

    /* We write out the latestid for the mailbox only after successfully
     * updating the index, to avoid a future instance not realising that
     * there are unindexed messages should we fail to index */
    r = write_latest(&tr->latestdb, tr->super.mailbox, tr->latest,
		     tr->super.verbose);
    if (r) goto out;

    tr->uncommitted = 0;

out:
    return r;
}

static void begin_message(search_text_receiver_t *rx, uint32_t uid)
{
    xapian_receiver_t *tr = (xapian_receiver_t *)rx;
    int i;

    tr->uid = uid;
    for (i = 0 ; i < SEARCH_NUM_PARTS ; i++)
	buf_reset(&tr->parts[i]);
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
	    buf_appendmap(&tr->parts[tr->part], text->s, len);
	}
    }
}

static void end_part(search_text_receiver_t *rx,
		     int part __attribute__((unused)))
{
    xapian_receiver_t *tr = (xapian_receiver_t *)rx;

    if (tr->verbose > 1)
	syslog(LOG_NOTICE, "Xapian: %u bytes in part %d",
	       tr->parts[tr->part].len, tr->part);

    tr->part = 0;
}

static int end_message_update(search_text_receiver_t *rx)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    int i;
    int r = 0;

    if (!tr->dbw) return IMAP_INTERNAL;

    r = xapian_dbw_begin_doc(tr->dbw, make_cyrusid(tr->super.mailbox, tr->super.uid));
    if (r) goto out;

    for (i = 0 ; i < SEARCH_NUM_PARTS ; i++) {
	const struct buf *part = &tr->super.parts[i];
	if (!part->len) continue;
	r = xapian_dbw_doc_part(tr->dbw, part, prefix_by_part[i]);
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
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;
    char *basedir = NULL;
    char *dir = NULL;
    int r;

    r = xapian_basedir(mailbox, &basedir);
    if (r) return r;
    dir = strconcat(basedir, XAPIAN_DIRNAME, NULL);

    r = check_directory(dir, tr->super.verbose, /*create*/1);
    if (r) goto out;

    tr->dbw = xapian_dbw_open(dir);
    if (!tr->dbw) {
	r = IMAP_IOERROR;
	goto out;
    }

    tr->super.mailbox = mailbox;

    r = indexing_lock(mailbox, &tr->indexing_lock_fd);
    if (r) goto out;

    r = open_latest(mailbox, &tr->latestdb);
    if (r) goto out;

    r = read_latest(&tr->latestdb, mailbox, &tr->latest, tr->super.verbose);
    if (r) goto out;

out:
    free(basedir);
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

    if (tr->dbw) {
	r = flush(tr, /*force*/1);
	xapian_dbw_close(tr->dbw);
	tr->dbw = NULL;
    }

    tr->super.mailbox = NULL;

    return r;
}

static search_text_receiver_t *begin_update(int verbose)
{
    xapian_update_receiver_t *tr;

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

    tr->indexing_lock_fd = -1;
    tr->super.verbose = verbose;

    return &tr->super.super;
}

static int free_receiver(xapian_receiver_t *tr)
{
    int i;
    int r = 0;

    for (i = 0 ; i < SEARCH_NUM_PARTS ; i++)
	buf_free(&tr->parts[i]);

    free(tr);

    return r;
}

static int end_update(search_text_receiver_t *rx)
{
    xapian_update_receiver_t *tr = (xapian_update_receiver_t *)rx;

    close_latest(&tr->latestdb);
    indexing_unlock(&tr->indexing_lock_fd);
    return free_receiver(&tr->super);
}

const struct search_engine xapian_search_engine = {
    "Xapian",
    SEARCH_FLAG_CAN_BATCH,
    /*begin_search*/NULL,
    /*end_search*/NULL,
    begin_update,
    end_update,
    /*begin_snippets*/NULL,
    /*end_snippets*/NULL,
    /*describe_internalised*/NULL,
    /*free_internalised*/NULL,
    /*start_daemon*/NULL,
    /*stop_daemon*/NULL
};

