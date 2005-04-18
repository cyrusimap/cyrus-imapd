/*  cyrusdb_quotalegacy: cyrusdb backend for accessing legacy quota files
 *
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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

/* $Id: cyrusdb_quotalegacy.c,v 1.1.2.8 2005/04/18 15:09:05 shadow Exp $ */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <glob.h>

#include "assert.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "hash.h"
#include "map.h"
#include "libcyr_cfg.h"
#include "lock.h"
#include "retry.h"
#include "util.h"
#include "xmalloc.h"

#define FNAME_QUOTADIR "/quota/"
#define MAX_QUOTA_PATH 4096

/* we have the file locked iff we have an outstanding transaction */

struct db {
    char *path;

    char *data;  /* allocated buffer for fetched data */

    hash_table table;  /* transaction (hash table of sub-transactions) */
};

struct subtxn {
    int fd;

    char *fnamenew;
    int fdnew;

    int delete;
};

int abort_txn(struct db *db __attribute__((unused)), struct txn *tid);

/* simple hash so it's easy to find these things in the filesystem;
   our human time is worth more than efficiency */
static void hash_quota(char *buf, size_t size, const char *qr, char *path)
{
    int config_virtdomains = libcyrus_config_getswitch(CYRUSOPT_VIRTDOMAINS);
    const char *idx;
    char c, *p;
    unsigned len;

    if ((len = snprintf(buf, size, "%s", path)) >= size) {
        fatal("insufficient buffer size in hash_quota", EC_TEMPFAIL);
    }
    buf += len;
    size -= len;

    if (config_virtdomains && (p = strchr(qr, '!'))) {
	*p = '\0';  /* split domain!qr */
	c = (char) dir_hash_c(qr);
	if ((len = snprintf(buf, size, "%s%c/%s",
			    FNAME_DOMAINDIR, c, qr)) >= size) {
	    fatal("insufficient buffer size in hash_quota", EC_TEMPFAIL);
	}
	*p++ = '!';  /* reassemble domain!qr */
	qr = p;
	buf += len;
	size -= len;

	if (!*qr) {
	    /* quota for entire domain */
	    if (snprintf(buf, size, "%sroot", FNAME_QUOTADIR) >= size) {
		fatal("insufficient buffer size in hash_quota",
		      EC_TEMPFAIL);
	    }
	    return;
	}
    }

    idx = strchr(qr, '.'); /* skip past user. */
    if (idx == NULL) {
	idx = qr;
    } else {
	idx++;
    }
    c = (char) dir_hash_c(idx);

    if (snprintf(buf, size, "%s%c/%s", FNAME_QUOTADIR, c, qr) >= size) {
	fatal("insufficient buffer size in hash_quota", EC_TEMPFAIL);
    }
}

/* other routines call this one when they fail */
static int abort_subtxn(char *fname, struct subtxn *tid)
{
    int r = CYRUSDB_OK;

    assert(fname && tid);

    /* cleanup done while lock is held */
    if (tid->fnamenew) {
	unlink(tid->fnamenew);
	free(tid->fnamenew);
    }

    if (tid->fdnew != -1) {
	r = close(tid->fdnew);
    }

    if (tid->fd != -1) {
	/* release lock */
	r = lock_unlock(tid->fd);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: unlocking %s: %m", fname);
	    r = CYRUSDB_IOERROR;
	}

	/* close */
	r = close(tid->fd);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: closing %s: %m", fname);
	    r = CYRUSDB_IOERROR;
	}
    }

    free(tid);

    return r;
}

static int commit_subtxn(char *fname, struct subtxn *tid)
{
    int writefd;
    int r = 0;
    struct stat sbuf;

    assert(fname && tid);

    if ((writefd = tid->fdnew) != -1) {
	/* we wrote something */

	if (fsync(writefd) ||
	    fstat(writefd, &sbuf) == -1 ||
	    rename(tid->fnamenew, fname) == -1 ||
	    lock_unlock(writefd) == -1) {
	    syslog(LOG_ERR, "IOERROR: writing %s: %m", tid->fnamenew);
	    r = CYRUSDB_IOERROR;
	}
	close(writefd);
	free(tid->fnamenew);
    } else if (tid->delete) {
	/* delete file */
	r = unlink(fname);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: unlinking %s: %m", fname);
	    r = CYRUSDB_IOERROR;
	}
    } else {
	/* read-only txn */
    }

    /* release lock */
    if (tid->fd != -1) {
	r = lock_unlock(tid->fd);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: unlocking %s: %m", fname);
	    r = CYRUSDB_IOERROR;
	}

	r = close(tid->fd);
	if (r == -1) {
	    syslog(LOG_ERR, "IOERROR: closing %s: %m", fname);
	    r = CYRUSDB_IOERROR;
	}
    }

    free(tid);

    return r;
}

static void free_db(struct db *db)
{
    if (db) {
	if (db->path) free(db->path);
	if (db->data) free(db->data);
	free_hash_table(&db->table, NULL);
	free(db);
    }
}

static struct subtxn *new_subtxn(const char *fname __attribute__((unused)),
				 int fd)
{
    struct subtxn *ret = (struct subtxn *) xmalloc(sizeof(struct subtxn));

    ret->fd = fd;
    ret->fnamenew = NULL;
    ret->fdnew = -1;
    ret->delete = 0;
    return ret;
}

static int init(const char *dbdir __attribute__((unused)),
		int myflags __attribute__((unused)))
{
    return 0;
}

static int done(void)
{
    return 0;
}

static int mysync(void)
{
    return 0;
}

static int myarchive(const char **fnames __attribute__((unused)),
		     const char *dirname __attribute__((unused)))
{
    return 0;
}

static int myopen(const char *fname, int flags, struct db **ret)
{
    struct db *db = (struct db *) xzmalloc(sizeof(struct db));
    struct stat sbuf;
    char *p;
    int r;

    assert(fname && ret);

    db->path = xstrdup(fname);
    construct_hash_table(&db->table, 200, 0);

    /* strip any filename from the path */
    if ((p = strrchr(db->path, '/'))) *p = '\0';

    r = stat(db->path, &sbuf);
    if (r == -1 && errno == ENOENT && (flags & CYRUSDB_CREATE)) {
	if (cyrus_mkdir(fname, 0755) != -1) {
	    r = stat(db->path, &sbuf);
	}
    }

    if (r == -1) {
	int level = (flags & CYRUSDB_CREATE) ? LOG_ERR : LOG_DEBUG;
	syslog(level, "IOERROR: stating %s: %m", db->path);
	free_db(db);
	return CYRUSDB_IOERROR;
    }

    *ret = db;
    return 0;
}

static int myclose(struct db *db)
{
    assert(db);

    free_db(db);

    return 0;
}

static int myfetch(struct db *db, char *quota_path,
		   const char **data, int *datalen,
		   struct txn **tid)
{
    struct subtxn *mytid = NULL;
    int quota_fd;
    const char *quota_base = 0;
    unsigned long quota_len = 0;

    assert(db);

    if (data) *data = NULL;
    if (datalen) *datalen = 0;

    if (!data) {
	/* just check if the key exists */
	struct stat sbuf;

	if (stat(quota_path, &sbuf) == -1)
	    return CYRUSDB_NOTFOUND;

	return 0;
    }

    if (tid) {
	if (!*tid)
	    *tid = (struct txn *) &db->table;
	else
	    mytid = (struct subtxn *) hash_lookup(quota_path, &db->table);
    }

    /* open and lock file, if needed */
    if (!mytid) {
	quota_fd = open(quota_path, O_RDWR, 0);
	if (quota_fd == -1) {
	    if (errno == ENOENT) {
		/* key doesn't exist */
		return CYRUSDB_NOTFOUND;
	    }

	    syslog(LOG_ERR, "IOERROR: opening quota file %s: %m", quota_path);
	    return CYRUSDB_IOERROR;
	}

	if (tid) {
	    int r;
	    struct stat sbuf;
	    const char *lockfailaction;

	    r = lock_reopen(quota_fd, quota_path, &sbuf, &lockfailaction);
	    if (r == -1) {
		syslog(LOG_ERR, "IOERROR: %s quota %s: %m", lockfailaction,
		       quota_path);
		return CYRUSDB_IOERROR;
	    }

	    mytid = new_subtxn(quota_path, quota_fd);
	    hash_insert(quota_path, mytid, &db->table);
	}
    }
    else
	quota_fd = mytid->fd;

    map_refresh(quota_fd, 1, &quota_base, &quota_len,
		MAP_UNKNOWN_LEN, quota_path, 0);

    if (quota_len) {
	char *p, *eol;

	db->data = xrealloc(db->data, quota_len);
	memcpy(db->data, quota_base, quota_len);

	p = db->data;
	eol = memchr(p, '\n', quota_len - (p - db->data));
	if (!eol) {
	    map_free(&quota_base, &quota_len);
	    return CYRUSDB_IOERROR;
	}
	/* convert the separating \n to SP */
	*eol = ' ';

	p = eol + 1;
	eol = memchr(p, '\n', quota_len - (p - db->data));
	if (!eol) {
	    map_free(&quota_base, &quota_len);
	    return CYRUSDB_IOERROR;
	}
	/* convert the terminating \n to \0 */
	*eol = '\0';

	*data = db->data;
	*datalen = strlen(db->data);
    }

    map_free(&quota_base, &quota_len);
    if (!tid) close(quota_fd);

    return 0;
}

static int fetch(struct db *db, 
		 const char *key, int keylen,
		 const char **data, int *datalen,
		 struct txn **tid)
{
    char quota_path[MAX_QUOTA_PATH+1], *tmpkey = NULL;

    /* if we need to truncate the key, do so */
    if (key[keylen] != '\0') {
	tmpkey = xmalloc(keylen + 1);
	memcpy(tmpkey, key, keylen);
	tmpkey[keylen] = '\0';
	key = tmpkey;
    }

    hash_quota(quota_path, sizeof(quota_path), key, db->path);
    if (tmpkey) free(tmpkey);

    return myfetch(db, quota_path, data, datalen, tid);
}

static const char *path_to_qr(const char *path, char *buf)
{
    const char *qr;
    char *p;

    qr = strrchr(path, '/') + 1;
    if ((p = strstr(path, FNAME_DOMAINDIR))) {
	/* use the quota_path as a buffer to construct virtdomain qr */
	p += strlen(FNAME_DOMAINDIR) + 2; /* +2 for hashdir */
	sprintf(buf, "%.*s!%s", (int) strcspn(p, "/"), p,
		strcmp(qr, "root") ? qr : "");
	qr = buf;
    }

    return qr;
}

static int compar_qr(const void *v1, const void *v2)
{
    const char *qr1, *qr2;
    char qrbuf1[MAX_QUOTA_PATH+1], qrbuf2[MAX_QUOTA_PATH+1];

    qr1 = path_to_qr(*((const char **) v1), qrbuf1);
    qr2 = path_to_qr(*((const char **) v2), qrbuf2);

    return strcmp(qr1, qr2);
}   

static int foreach(struct db *db,
		   char *prefix, int prefixlen,
		   foreach_p *goodp,
		   foreach_cb *cb, void *rock, 
		   struct txn **tid)
{
    int r = CYRUSDB_OK;
    int config_virtdomains = libcyrus_config_getswitch(CYRUSOPT_VIRTDOMAINS);
    char quota_path[MAX_QUOTA_PATH+1];
    glob_t globbuf;
    int i;
    char *tmpprefix = NULL, *p = NULL;

    /* if we need to truncate the prefix, do so */
    if (prefix[prefixlen] != '\0') {
	tmpprefix = xmalloc(prefixlen + 1);
	memcpy(tmpprefix, prefix, prefixlen);
	tmpprefix[prefixlen] = '\0';
	prefix = tmpprefix;
    }

    hash_quota(quota_path, sizeof(quota_path), prefix, db->path);
    if (config_virtdomains && (p = strchr(prefix, '!')))
	prefix = p + 1;

    /* search for the quotaroots */
    glob(quota_path, GLOB_NOSORT, NULL, &globbuf);

    if (config_virtdomains) {
	if (!prefixlen) {
	    /* search for all virtdomain quotaroots */
	    snprintf(quota_path, sizeof(quota_path), "%s%s?/*%s?/*",
		     db->path, FNAME_DOMAINDIR, FNAME_QUOTADIR);
	    glob(quota_path, GLOB_NOSORT | GLOB_APPEND, NULL, &globbuf);

	    /* search for all domain quotas */
	    snprintf(quota_path, sizeof(quota_path), "%s%s?/*%sroot",
		     db->path, FNAME_DOMAINDIR, FNAME_QUOTADIR);
	    glob(quota_path, GLOB_NOSORT | GLOB_APPEND, NULL, &globbuf);
	}
	else if (!strlen(prefix)) {
	    /* search for the domain quotas */
	    strcpy(strstr(quota_path, FNAME_QUOTADIR) + strlen(FNAME_QUOTADIR),
		   "root");
	    glob(quota_path, GLOB_NOSORT | GLOB_APPEND, NULL, &globbuf);
	}
    }
    if (tmpprefix) free(tmpprefix);

    if (tid && !*tid) *tid = (struct txn *) &db->table;

    /* sort the quotaroots (ignoring paths) */
    qsort(globbuf.gl_pathv, globbuf.gl_pathc, sizeof(char *), &compar_qr);

    for (i = 0; i < globbuf.gl_pathc; i++) {
	const char *data, *key;
	int keylen, datalen;

	r = myfetch(db, globbuf.gl_pathv[i], &data, &datalen, tid);
	if (r) break;

	key = path_to_qr(globbuf.gl_pathv[i], quota_path);
	keylen = strlen(key);

	if (!goodp || goodp(rock, key, keylen, data, datalen)) {
	    /* make callback */
	    r = cb(rock, key, keylen, data, datalen);
	    if (r) break;
	}
    }

    globfree(&globbuf);

    return r;
}

static int mystore(struct db *db, 
		   const char *key, int keylen,
		   const char *data, int datalen,
		   struct txn **tid, int overwrite)
{
    char quota_path[MAX_QUOTA_PATH+1], *tmpkey = NULL;
    struct subtxn *mytid = NULL;
    int r = 0;

    /* if we need to truncate the key, do so */
    if (key[keylen] != '\0') {
	tmpkey = xmalloc(keylen + 1);
	memcpy(tmpkey, key, keylen);
	tmpkey[keylen] = '\0';
	key = tmpkey;
    }

    hash_quota(quota_path, sizeof(quota_path), key, db->path);
    if (tmpkey) free(tmpkey);

    if (tid) {
	if (!*tid)
	    *tid = (struct txn *) &db->table;
	else
	    mytid = (struct subtxn *) hash_lookup(quota_path, &db->table);
    }

    /* open and lock file, if needed */
    if (!mytid) {
	int fd;
	struct stat sbuf;
	const char *lockfailaction;

	fd = open(quota_path, O_RDWR, 0644);
	if (fd == -1 && errno == ENOENT && data) {
	    if (cyrus_mkdir(quota_path, 0755) != -1) {
		fd = open(quota_path, O_RDWR | O_CREAT, 0644);
	    }
	}
	if (fd == -1 && (errno != ENOENT || data)) {
	    syslog(LOG_ERR, "IOERROR: opening quota file %s: %m", quota_path);
	    return CYRUSDB_IOERROR;
	}

	if (fd != -1) {
	    r = lock_reopen(fd, quota_path, &sbuf, &lockfailaction);
	    if (r == -1) {
		syslog(LOG_ERR, "IOERROR: %s quota %s: %m", lockfailaction,
		       quota_path);
		return CYRUSDB_IOERROR;
	    }
	}

	mytid = new_subtxn(quota_path, fd);

	if (tid)
	    hash_insert(quota_path, mytid, &db->table);
    }

    if (!data) {
	mytid->delete = 1;
    }
    else {
	char new_quota_path[MAX_QUOTA_PATH+1], *buf, *p;
	int newfd = -1, r1 = 0;
	ssize_t n;

	if (mytid->fd != -1 && !overwrite) {
	    if (tid)
		abort_txn(db, *tid);
	    else
		abort_subtxn(quota_path, mytid);
	    return CYRUSDB_EXISTS;
	}

	if (mytid->fdnew == -1) {
	    strlcpy(new_quota_path, quota_path, sizeof(new_quota_path));
	    strlcat(new_quota_path, ".NEW", sizeof(new_quota_path));

	    unlink(new_quota_path);
	    newfd = open(new_quota_path, O_CREAT | O_TRUNC | O_RDWR, 0666);
	    if (newfd == -1 && errno == ENOENT) {
		if (cyrus_mkdir(new_quota_path, 0755) != -1)
		    newfd = open(new_quota_path, O_CREAT | O_TRUNC | O_RDWR, 0666);
	    }
	    if (newfd == -1) {
		syslog(LOG_ERR, "IOERROR: creating quota file %s: %m",
		       new_quota_path);
		if (tid)
		    abort_txn(db, *tid);
		else
		    abort_subtxn(quota_path, mytid);
		return CYRUSDB_IOERROR;
	    }

	    mytid->fdnew = newfd;
	    r = lock_blocking(newfd);
	    if (r) {
		syslog(LOG_ERR, "IOERROR: locking quota file %s: %m",
		       new_quota_path);
		if (tid)
		    abort_txn(db, *tid);
		else
		    abort_subtxn(quota_path, mytid);
		return CYRUSDB_IOERROR;
	    }
	}

	buf = xmalloc(datalen+1);
	memcpy(buf, data, datalen);
	/* convert separating SP to \n */
	p = memchr(buf, ' ', datalen);
	*p = '\n';
	/* add a terminating \n */
	buf[datalen] = '\n';

	lseek(mytid->fdnew, 0, SEEK_SET);
	n = write(mytid->fdnew, buf, datalen+1);
	if (n == datalen+1) r1 = ftruncate(mytid->fdnew, datalen+1);
	free(buf);

	if (n != datalen+1 || r1 == -1) {
	    if (n == -1 || r1 == -1)
		syslog(LOG_ERR, "IOERROR: writing quota file %s: %m",
		       new_quota_path);
	    else
		syslog(LOG_ERR, "IOERROR: writing quota file %s: failed to write %d bytes",
		       new_quota_path, datalen+1);
	    if (tid)
		abort_txn(db, *tid);
	    else
		abort_subtxn(quota_path, mytid);
	    return CYRUSDB_IOERROR;
	}

	if (!mytid->fnamenew)
	    mytid->fnamenew = xstrdup(new_quota_path);
    }

    if (!tid) {
	/* commit immediately */
	r = commit_subtxn(quota_path, mytid);
    }

    return r;
}

static int create(struct db *db, 
		  const char *key, int keylen,
		  const char *data, int datalen,
		  struct txn **tid)
{
    return mystore(db, key, keylen, data, datalen, tid, 0);
}

static int store(struct db *db, 
		 const char *key, int keylen,
		 const char *data, int datalen,
		 struct txn **tid)
{
    return mystore(db, key, keylen, data, datalen, tid, 1);
}

static int delete(struct db *db, 
		  const char *key, int keylen,
		  struct txn **mytid, int force __attribute__((unused)))
{
    return mystore(db, key, keylen, NULL, 0, mytid, 1);
}

struct txn_rock {
    hash_table *table;
    int (*func)(char *, struct subtxn *);
    int ret;
};

static void enum_func(char *fname, void *data, void *rock)
{
    struct txn_rock *trock = (struct txn_rock *) rock;
    int r;

    r = trock->func(fname, (struct subtxn *) data);
    hash_del(fname, trock->table);

    if (r && !trock->ret) trock->ret = r;
}

int commit_txn(struct db *db __attribute__((unused)), struct txn *tid)
{
    struct txn_rock trock;

    trock.table = (hash_table *) tid;
    trock.func = commit_subtxn;
    trock.ret = 0;

    hash_enumerate((hash_table *) tid, enum_func, &trock);

    return trock.ret;
}

int abort_txn(struct db *db __attribute__((unused)), struct txn *tid)
{
    struct txn_rock trock;

    trock.table = (hash_table *) tid;
    trock.func = abort_subtxn;
    trock.ret = 0;

    hash_enumerate((hash_table *) tid, enum_func, &trock);

    return trock.ret;
}

struct cyrusdb_backend cyrusdb_quotalegacy = 
{
    "quotalegacy",			/* name */

    &init,
    &done,
    &mysync,
    &myarchive,

    &myopen,
    &myclose,

    &fetch,
    &fetch,
    &foreach,
    &create,
    &store,
    &delete,

    &commit_txn,
    &abort_txn,

    NULL,
    NULL
};
