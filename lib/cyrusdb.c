/*
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 *
 * $Id: cyrusdb.c,v 1.14 2010/01/06 17:01:44 murch Exp $
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "cyrusdb.h"
#include "util.h"
#include "exitcodes.h"
#include "libcyr_cfg.h"
#include "retry.h"
#include "xmalloc.h"

struct cyrusdb_backend *cyrusdb_backends[] = {
#ifdef HAVE_BDB
    &cyrusdb_berkeley,
    &cyrusdb_berkeley_nosync,
    &cyrusdb_berkeley_hash,
    &cyrusdb_berkeley_hash_nosync,
#endif
    &cyrusdb_flat,
    &cyrusdb_skiplist,
    &cyrusdb_quotalegacy,
#if defined HAVE_MYSQL || defined HAVE_PGSQL || defined HAVE_SQLITE
    &cyrusdb_sql,
#endif
    &cyrusdb_twoskip,
    NULL };

void cyrusdb_init(void)
{
    int i, r;
    char dbdir[1024];
    const char *confdir = libcyrus_config_getstring(CYRUSOPT_CONFIG_DIR);
    int initflags = libcyrus_config_getint(CYRUSOPT_DB_INIT_FLAGS);
    
    strcpy(dbdir, confdir);
    strcat(dbdir, FNAME_DBDIR);

    for(i=0; cyrusdb_backends[i]; i++) {
	r = (cyrusdb_backends[i])->init(dbdir, initflags);
	if(r) {
	    syslog(LOG_ERR, "DBERROR: init() on %s",
		   cyrusdb_backends[i]->name);
	}
    }
}

void cyrusdb_done(void)
{
    int i;
    
    for(i=0; cyrusdb_backends[i]; i++) {
	(cyrusdb_backends[i])->done();
    }
}

int cyrusdb_copyfile(const char *srcname, const char *dstname)
{
    return cyrus_copyfile(srcname, dstname, COPYFILE_NOLINK);
}

struct db_rock {
    struct cyrusdb_backend *backend;
    struct db *db;
    struct txn **tid;
};

static int delete_cb(void *rock,
		     const char *key, size_t keylen,
		     const char *data __attribute__((unused)), 
		     size_t datalen __attribute__((unused))) 
{
    struct db_rock *cr = (struct db_rock *)rock;
    return (cr->backend->delete)(cr->db, key, keylen, cr->tid, 1);
}

static int print_cb(void *rock,
		    const char *key, size_t keylen,
		    const char *data, size_t datalen) 
{
    FILE *f = (FILE *)rock;

    /* XXX: improve binary safety */
    fprintf(f, "%.*s\t%.*s\n", (int)keylen, key, (int)datalen, data);

    return 0;
}


int cyrusdb_dump(struct cyrusdb_backend *backend,
		 struct db *db,
		 const char *prefix, size_t prefixlen,
		 FILE *f,
		 struct txn **tid)
{
    return (backend->foreach)(db, prefix, prefixlen, NULL, print_cb, f, tid);
}

int cyrusdb_truncate(struct cyrusdb_backend *backend,
		     struct db *db,
		     struct txn **tid)
{
    struct db_rock tr;

    tr.backend = backend;
    tr.db = db;
    tr.tid = tid;

    return (backend->foreach)(db, "", 0, NULL, delete_cb, &tr, tid);
}

int cyrusdb_undump(struct cyrusdb_backend *backend,
		   struct db *db,
		   FILE *f,
		   struct txn **tid)
{
    struct buf line = BUF_INITIALIZER;
    const char *tab;
    const char *str;
    int r = 0;

    while (buf_getline(&line, f)) {
	/* skip blank lines */
	if (!line.len) continue;
	str = buf_cstring(&line);
	/* skip comments */
	if (str[0] == '#') continue;

	tab = strchr(str, '\t');

	/* deletion (no value) */
	if (!tab) {
	    r = (backend->delete)(db, str, line.len, tid, 1);
	    if (r) goto out;
	}

	/* store */
	else {
	    unsigned klen = (tab - str);
	    unsigned vlen = line.len - klen - 1; /* TAB */
	    r = (backend->store)(db, str, klen, tab + 1, vlen, tid);
	    if (r) goto out;
	}
    }

  out:
    buf_free(&line);
    return r;
}

static int converter_cb(void *rock,
			const char *key, size_t keylen,
			const char *data, size_t datalen) 
{
    struct db_rock *cr = (struct db_rock *)rock;
    return (cr->backend->store)(cr->db, key, keylen, data, datalen, cr->tid);
}

/* convert (just copy every record) from one database to another in possibly
   a different format.  It's up to the surrounding code to copy the
   new database over the original if it wants to */
int cyrusdb_convert(const char *fromfname, const char *tofname,
		    struct cyrusdb_backend *frombackend,
		    struct cyrusdb_backend *tobackend)
{
    char *newfname = NULL;
    struct db *fromdb = NULL;
    struct db *todb = NULL;
    struct db_rock cr;
    struct txn *fromtid = NULL;
    struct txn *totid = NULL;
    int r;

    /* open source database */
    r = (frombackend->open)(fromfname, 0, &fromdb);
    if (r) goto err;

    /* use a bogus fetch to lock source DB before touching the destination */
    r = (frombackend->fetch)(fromdb, "_", 1, NULL, NULL, &fromtid);
    if (r == CYRUSDB_NOTFOUND) r = 0;
    if (r) goto err;

    /* same file?  Create with a new name */
    if (!strcmp(tofname, fromfname))
	tofname = newfname = strconcat(fromfname, ".NEW", NULL);

    /* remove any rubbish lying around */
    unlink(tofname);

    r = (tobackend->open)(tofname, CYRUSDB_CREATE, &todb);
    if (r) goto err;

    /* set up the copy rock */
    cr.backend = tobackend;
    cr.db = todb;
    cr.tid = &totid;

    /* copy each record to the destination DB */
    (frombackend->foreach)(fromdb, "", 0, NULL, converter_cb, &cr, &fromtid);

    /* commit destination transaction */
    if (totid) (tobackend->commit)(todb, totid);
    r = (tobackend->close)(todb);
    totid = NULL;
    todb = NULL;
    if (r) goto err;

    /* created a new filename - so it's a replace-in-place */
    if (newfname) {
	r = rename(newfname, fromfname);
	if (r) goto err;
    }

    /* and close the source database - nothing should have
     * written here, so an abort is fine */
    if (fromtid) (frombackend->abort)(fromdb, fromtid);
    (frombackend->close)(fromdb);

    free(newfname);

    return 0;

err:
    if (totid) (tobackend->abort)(todb, totid);
    if (todb) (tobackend->close)(todb);
    if (fromtid) (frombackend->abort)(fromdb, fromtid);
    if (fromdb) (frombackend->close)(fromdb);

    unlink(tofname);
    free(newfname);

    return r;
}

const char *cyrusdb_detect(const char *fname)
{
    FILE *f;
    char buf[16];
    int n;
    uint32_t bdb_magic;

    f = fopen(fname, "r");
    if (!f) return NULL;

    /* empty file? */
    n = fread(buf, 16, 1, f);
    fclose(f);

    if (n != 1) return NULL;

    /* only compare first 16 bytes, that's OK */
    if (!strncmp(buf, "\241\002\213\015skiplist file\0\0\0", 16))
	return "skiplist";

    if (!strncmp(buf, "\241\002\213\015twoskip file\0\0\0\0", 16))
	return "twoskip";

    bdb_magic = *(uint32_t *)(buf+12);

    if (bdb_magic == 0x053162) /* BDB BTREE MAGIC */
	return "berkeley";

    if (bdb_magic == 0x061561) /* BDB HASH MAGIC */
	return "berkeley-hash";

    /* unable to detect SQLite databases or flat files explicitly here */
    return NULL;
}

struct cyrusdb_backend *cyrusdb_fromname(const char *name)
{
    int i;
    struct cyrusdb_backend *db = NULL;

    for (i = 0; cyrusdb_backends[i]; i++) {
	if (!strcmp(cyrusdb_backends[i]->name, name)) {
	    db = cyrusdb_backends[i]; break;
	}
    }
    if (!db) {
	char errbuf[1024];
	snprintf(errbuf, sizeof(errbuf),
		 "cyrusdb backend %s not supported", name);
	fatal(errbuf, EC_CONFIG);
    }

    return db;
}
