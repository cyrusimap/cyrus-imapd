/*  cyrusdb_sql: SQL db backends
 *
 * Copyright (c) 1998-2004 Carnegie Mellon University.  All rights reserved.
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

/* $Id: cyrusdb_sql.c,v 1.1 2008/07/30 16:03:38 murch Exp $ */

#include <config.h>

#include <syslog.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "cyrusdb.h"
#include "exitcodes.h"
#include "libcyr_cfg.h"
#include "xmalloc.h"

extern void fatal(const char *, int);

typedef int exec_cb(void *rock,
		    const char *key, int keylen,
		    const char *data, int datalen);

typedef struct sql_engine {
    const char *name;
    const char *binary_type;
    void *(*sql_open)(char *host, char *port, int usessl,
		      const char *user, const char *password,
		      const char *database);
    char *(*sql_escape)(void *conn, char **to,
			const char *from, size_t fromlen);
    int (*sql_begin_txn)(void *conn);
    int (*sql_commit_txn)(void *conn);
    int (*sql_rollback_txn)(void *conn);
    int (*sql_exec)(void *conn, const char *cmd, exec_cb *cb, void *rock);
    void (*sql_close)(void *conn);
} sql_engine_t;

struct db {
    void *conn;     /* connection to database */
    char *table;    /* table that we are operating on */
    char *esc_key;  /* allocated buffer for escaped key */
    char *esc_data; /* allocated buffer for escaped data */
    char *data;     /* allocated buffer for fetched data */
};

struct txn {
    char *lastkey;  /* allocated buffer for last SELECTed key */
    size_t keylen;
};

static int dbinit = 0;
static const sql_engine_t *dbengine = NULL;


#ifdef HAVE_MYSQL
#include <mysql.h>

static void *_mysql_open(char *host, char *port, int usessl,
			 const char *user, const char *password,
			 const char *database)
{
    MYSQL *mysql;
    
    if (!(mysql = mysql_init(NULL))) {
	syslog(LOG_ERR, "DBERROR: SQL backend could not execute mysql_init()");
	return NULL;
    }
    
    return mysql_real_connect(mysql, host, user, password, database,
			      port ? strtoul(port, NULL, 10) : 0, NULL,
			      usessl ? CLIENT_SSL : 0);
}

static char *_mysql_escape(void *conn, char **to,
			   const char *from, size_t fromlen)
{
    size_t tolen;

    *to = xrealloc(*to, 2 * fromlen + 1); /* +1 for NUL */

    tolen = mysql_real_escape_string(conn, *to, from, fromlen);

    return *to;
}

static int _mysql_exec(void *conn, const char *cmd, exec_cb *cb, void *rock)
{
    MYSQL_RES *result;
    MYSQL_ROW row;
    int len, r = 0;

    syslog(LOG_DEBUG, "executing SQL cmd: %s", cmd);

    len = strlen(cmd);
    /* mysql_real_query() doesn't want a terminating ';' */
    if (cmd[len-1] == ';') len--;

    /* run the query */
    if ((mysql_real_query(conn, cmd, len) < 0) ||
	*mysql_error(conn)) {
	syslog(LOG_ERR, "DBERROR: SQL query failed: %s", mysql_error(conn));
	return CYRUSDB_INTERNAL;
    }

    /* see if we should expect some results */
    if (!mysql_field_count(conn)) {
	/* no results (BEGIN, COMMIT, ROLLBACK, CREATE, INSERT, UPDATE, DELETE) */
	syslog(LOG_DEBUG, "no results from SQL cmd");
	return 0;
    }

    /* get the results */
    result = mysql_store_result(conn);
    
    /* process the results */
    while (!r && (row = mysql_fetch_row(result))) {
	unsigned long *length = mysql_fetch_lengths(result);
	r = cb(rock, row[0], length[0], row[1], length[1]);
    }

    /* free result */
    mysql_free_result(result);
    
    return r;
}

static int _mysql_begin_txn(void *conn)
{
    return _mysql_exec(conn,
#if MYSQL_VERSION_ID >= 40011
		       "START TRANSACTION",
#else
		       "BEGIN",
#endif
		       NULL, NULL);
}

static int _mysql_commit_txn(void *conn)
{
    return _mysql_exec(conn, "COMMIT", NULL, NULL);
}

static int _mysql_rollback_txn(void *conn)
{
    return _mysql_exec(conn, "ROLLBACK", NULL, NULL);
}

static void _mysql_close(void *conn)
{
    mysql_close(conn);
}
#endif /* HAVE_MYSQL */


#ifdef HAVE_PGSQL
#include <libpq-fe.h>

#define sql_max(a, b) ((a) > (b) ? (a) : (b))
#define sql_len(input) ((input) ? strlen(input) : 0)
#define sql_exists(input) ((input) && (*input))

static void *_pgsql_open(char *host, char *port, int usessl,
			 const char *user, const char *password,
			 const char *database)
{
    PGconn *conn = NULL;
    char *conninfo, *p;

    /* create the connection info string */
    /* The 64 represents the number of characters taken by
     * the keyword tokens, plus a small pad
     */
    p = conninfo = xzmalloc(64 + sql_len(host) + sql_len(port)
			   + sql_len(user) + sql_len(password)
			   + sql_len(database));

    /* add each term that exists */
    if (sql_exists(host)) p += sprintf(p, " host='%s'", host);
    if (sql_exists(port)) p += sprintf(p, " port='%s'", port);
    if (sql_exists(user)) p += sprintf(p, " user='%s'", user);
    if (sql_exists(password)) p += sprintf(p, " password='%s'", password);
    if (sql_exists(database)) p += sprintf(p, " dbname='%s'", database);
    p += sprintf(p, " requiressl='%d'", usessl);

    conn = PQconnectdb(conninfo);
    free(conninfo);

    if ((PQstatus(conn) != CONNECTION_OK)) {
	syslog(LOG_ERR, "DBERROR: SQL backend: %s", PQerrorMessage(conn));
	return NULL;
    }

    return conn;
}

static char *_pgsql_escape(void *conn __attribute__((unused)),
			   char **to, const char *from, size_t fromlen)
{
    size_t tolen;

    /* returned buffer MUST be freed by caller */
    return PQescapeBytea((char *) from, fromlen, &tolen);
}

static int _pgsql_exec(void *conn, const char *cmd, exec_cb *cb, void *rock)
{
    PGresult *result;
    int row_count, i, r = 0;
    ExecStatusType status;

    syslog(LOG_DEBUG, "executing SQL cmd: %s", cmd);

    /* run the query */
    result = PQexec(conn, cmd);

    /* check the status */
    status = PQresultStatus(result);
    if (status == PGRES_COMMAND_OK) {
	/* no results (BEGIN, COMMIT, ROLLBACK, CREATE, INSERT, UPDATE, DELETE) */
	PQclear(result);
	return 0;
    }
    else if (status != PGRES_TUPLES_OK) {
	/* error */
	syslog(LOG_DEBUG, "SQL backend: %s ", PQresStatus(status));
	PQclear(result);
	return CYRUSDB_INTERNAL;
    }

    row_count = PQntuples(result);
    for (i = 0; !r && i < row_count; i++) {
	char *key, *data;
	size_t keylen, datalen;

	key = PQunescapeBytea(PQgetvalue(result, i, 0), &keylen);
	data = PQunescapeBytea(PQgetvalue(result, i, 1), &datalen);
	r = cb(rock, key, keylen, data, datalen);
	free(key); free(data);
    }

    /* free result */
    PQclear(result);

    return r;
}

static int _pgsql_begin_txn(void *conn)
{
    return _pgsql_exec(conn, "BEGIN;", NULL, NULL);
}

static int _pgsql_commit_txn(void *conn)
{
    return _pgsql_exec(conn, "COMMIT;", NULL, NULL);
}

static int _pgsql_rollback_txn(void *conn)
{
    return _pgsql_exec(conn, "ROLLBACK;", NULL, NULL);
}

static void _pgsql_close(void *conn)
{
    PQfinish(conn);
}
#endif /* HAVE_PGSQL */


#ifdef HAVE_SQLITE
#include <sqlite3.h>

static void *_sqlite_open(char *host __attribute__((unused)),
			  char *port __attribute__((unused)),
			  int usessl __attribute__((unused)),
			  const char *user __attribute__((unused)),
			  const char *password __attribute__((unused)),
			  const char *database)
{
    int rc;
    sqlite3 *db;

    rc = sqlite3_open(database, &db);
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "DBERROR: SQL backend: %s", sqlite3_errmsg(db));
	sqlite3_close(db);
    }

    return db;
}

static char *_sqlite_escape(void *conn __attribute__((unused)),
			    char **to, const char *from, size_t fromlen)
{
    size_t tolen;
#if 0
    *to = xrealloc(*to, 2 + (257 * fromlen) / 254);

    tolen = sqlite3_encode_binary(from, fromlen, *to);
#else
    *to = xrealloc(*to, fromlen + 1);
    memcpy(*to, from, fromlen);
    tolen = fromlen;
    (*to)[tolen] = '\0';
#endif
    
    return *to;
}

static int _sqlite_exec(void *conn, const char *cmd, exec_cb *cb, void *rock)
{
    int rc, r = 0;
    sqlite3_stmt *stmt = NULL;
    const char *tail;

    syslog(LOG_DEBUG, "executing SQL cmd: %s", cmd);

    /* compile the SQL cmd */
    rc = sqlite3_prepare(conn, cmd, strlen(cmd), &stmt, &tail);
    if (rc != SQLITE_OK) {
	syslog(LOG_DEBUG, "SQL backend: %s ", sqlite3_errmsg(conn));
	return CYRUSDB_INTERNAL;
    }

    /* process the results */
    while (!r && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
	const unsigned char *key = sqlite3_column_text(stmt, 0);
	int keylen = sqlite3_column_bytes(stmt, 0);
	const unsigned char *data = sqlite3_column_text(stmt, 1);
	int datalen = sqlite3_column_bytes(stmt, 1);

	r = cb(rock, (char *) key, keylen, (char *) data, datalen);
    }

    /* cleanup */
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
	syslog(LOG_DEBUG, "SQL backend: %s ", sqlite3_errmsg(conn));
	return CYRUSDB_INTERNAL;
    }

    return r;
}

static int _sqlite_begin_txn(void *conn)
{
    return _sqlite_exec(conn, "BEGIN TRANSACTION", NULL, NULL);
}

static int _sqlite_commit_txn(void *conn)
{
    return _sqlite_exec(conn, "COMMIT TRANSACTION", NULL, NULL);
}

static int _sqlite_rollback_txn(void *conn)
{
    return _sqlite_exec(conn, "ROLLBACK TRANSACTION", NULL, NULL);
}

static void _sqlite_close(void *conn)
{
    sqlite3_close(conn);
}
#endif /* HAVE_SQLITE */


static const sql_engine_t sql_engines[] = {
#ifdef HAVE_MYSQL
    { "mysql", "BLOB", &_mysql_open, &_mysql_escape,
      &_mysql_begin_txn, &_mysql_commit_txn, &_mysql_rollback_txn,
      &_mysql_exec, &_mysql_close },
#endif /* HAVE_MYSQL */
#ifdef HAVE_PGSQL
    { "pgsql", "BYTEA", &_pgsql_open, &_pgsql_escape,
      &_pgsql_begin_txn, &_pgsql_commit_txn, &_pgsql_rollback_txn,
      &_pgsql_exec, &_pgsql_close },
#endif
#ifdef HAVE_SQLITE
    { "sqlite", "BLOB", &_sqlite_open, &_sqlite_escape,
      &_sqlite_begin_txn, &_sqlite_commit_txn, &_sqlite_rollback_txn,
      &_sqlite_exec, &_sqlite_close },
#endif
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


static int init(const char *dbdir __attribute__((unused)),
		int flags __attribute__((unused)))
{
    const char *engine_name;
    int r = 0;

    if (dbinit++) return 0;

    engine_name = libcyrus_config_getstring(CYRUSOPT_SQL_ENGINE);

    /* find the correct engine */
    dbengine = sql_engines;
    while (dbengine->name) {
	if (!engine_name || !strcasecmp(engine_name, dbengine->name)) break;
	dbengine++;
    }

    if (!dbengine->name) {
	char errbuf[1024];
	snprintf(errbuf, sizeof(errbuf),
		 "SQL engine %s not supported", engine_name);
	fatal(errbuf, EC_CONFIG);
    }

    if (!engine_name) {
	syslog(LOG_DEBUG, "SQL backend defaulting to engine '%s'",
	       dbengine->name);
    }

    dbinit = 1;

    return r;
}

static int done(void)
{
    --dbinit;
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
    const char *database, *hostnames, *user, *passwd;
    char *host_ptr, *host, *cur_host, *cur_port;
    int usessl;
    void *conn = NULL;
    char *p, *table, cmd[1024];

    /* make a connection to the database */
    database = libcyrus_config_getstring(CYRUSOPT_SQL_DATABASE);
    hostnames = libcyrus_config_getstring(CYRUSOPT_SQL_HOSTNAMES);
    user = libcyrus_config_getstring(CYRUSOPT_SQL_USER);
    passwd = libcyrus_config_getstring(CYRUSOPT_SQL_PASSWD);
    usessl = libcyrus_config_getswitch(CYRUSOPT_SQL_USESSL);

    /* loop around hostnames until we get a connection */
    syslog(LOG_DEBUG, "SQL backend trying to connect to a host");
    
    /* create a working version of the hostnames */
    host_ptr = hostnames ? xstrdup(hostnames) : NULL;

    cur_host = host = host_ptr;
    while (cur_host != NULL) {
	host = strchr(host,',');
	if (host != NULL) {  
	    host[0] = '\0';

	    /* loop till we find some text */
	    while (!isalnum(host[0])) host++;
	}
	
	syslog(LOG_DEBUG,
	       "SQL backend trying to open db '%s' on host '%s'%s",
	       database, cur_host, usessl ? " using SSL" : "");
	
	/* set the optional port */
	if ((cur_port = strchr(cur_host, ':'))) *cur_port++ = '\0';
	
	conn = dbengine->sql_open(cur_host, cur_port, usessl,
				  user, passwd, database);
	if (conn) break;
	
	syslog(LOG_WARNING,
	       "DBERROR: SQL backend could not connect to host %s", cur_host);
	
	cur_host = host;
    }

    if (host_ptr) free(host_ptr);

    if (!conn) {
	syslog(LOG_ERR, "DBERROR: could not open SQL database '%s'", database);
	return CYRUSDB_IOERROR;
    }

    /* get the name of the table and CREATE it if necessary */

    /* strip any path from the fname */
    p = strrchr(fname, '/');
    table = xstrdup(p ? ++p : fname);

    /* convert '.' to '_' */
    if ((p = strrchr(table, '.'))) *p = '_';

    /* check if the table exists */
    /* XXX is this the best way to do this? */
    snprintf(cmd, sizeof(cmd), "SELECT * FROM %s LIMIT 0;", table);
    if (dbengine->sql_exec(conn, cmd, NULL, NULL) &&
	(flags & CYRUSDB_CREATE)) {
	/* create the table */
	snprintf(cmd, sizeof(cmd),
		 "CREATE TABLE %s (dbkey %s NOT NULL, data %s);",
		 table, dbengine->binary_type, dbengine->binary_type);
	if (dbengine->sql_exec(conn, cmd, NULL, NULL)) {
	    syslog(LOG_ERR, "DBERROR: SQL failed: %s", cmd);
	    dbengine->sql_close(conn);
	    return CYRUSDB_INTERNAL;
	}
    }

    *ret = (struct db *) xzmalloc(sizeof(struct db));
    (*ret)->conn = conn;
    (*ret)->table = table;

    return 0;
}
static int myclose(struct db *db)
{
    assert(db);

    dbengine->sql_close(db->conn);
    free(db->table);
    if (db->esc_key) free(db->esc_key);
    if (db->esc_data) free(db->esc_data);
    if (db->data) free(db->data);
    free(db);

    return 0;
}

static struct txn *start_txn(struct db *db)
{
    /* start a transaction */
    if (dbengine->sql_begin_txn(db->conn)) {
	syslog(LOG_ERR, "DBERROR: failed to start txn on %s",
	       db->table);
	return NULL;
    }
    return xzmalloc(sizeof(struct txn));
}

struct select_rock {
    int found;
    struct txn *tid;
    foreach_cb *goodp;
    foreach_cb *cb;
    void *rock;
};

static int select_cb(void *rock,
		     const char *key, int keylen,
		     const char *data, int datalen)
{
    struct select_rock *srock = (struct select_rock *) rock;
    int r = CYRUSDB_OK;

    /* if we're in a transaction, save this key */
    if (srock->tid) {
	srock->tid->lastkey = xrealloc(srock->tid->lastkey, keylen);
	memcpy(srock->tid->lastkey, key, keylen);
	srock->tid->keylen = keylen;
    }

    /* see if we want this entry */
    if (!srock->goodp ||
	srock->goodp(srock->rock, key, keylen, data, datalen)) {

	srock->found = 1;

	/* make callback */
	if (srock->cb) r = srock->cb(srock->rock, key, keylen, data, datalen);
    }

    return r;
}

struct fetch_rock {
    char **data;
    int *datalen;
};

static int fetch_cb(void *rock,
		    const char *key __attribute__((unused)),
		    int keylen __attribute__((unused)),
		    const char *data, int datalen)
{
    struct fetch_rock *frock = (struct fetch_rock *) rock;

    if (frock->data) {
	*(frock->data) = xrealloc(*(frock->data), datalen);
	memcpy(*(frock->data), data, datalen);
    }
    if (frock->datalen) *(frock->datalen) = datalen;

    return 0;
}

static int fetch(struct db *db, 
		 const char *key, int keylen,
		 const char **data, int *datalen,
		 struct txn **tid)
{
    char cmd[1024], *esc_key;
    struct fetch_rock frock = { &db->data, datalen };
    struct select_rock srock = { 0, NULL, NULL, &fetch_cb, &frock };
    int r;

    if (data) *data = NULL;
    if (datalen) *datalen = 0;

    if (tid) {
	if (!*tid && !(*tid = start_txn(db))) return CYRUSDB_INTERNAL;
	srock.tid = *tid;
    }

    /* fetch the data */
    esc_key = dbengine->sql_escape(db->conn, &db->esc_key, key, keylen);
    snprintf(cmd, sizeof(cmd),
	     "SELECT * FROM %s WHERE dbkey = '%s';", db->table, esc_key);
    r = dbengine->sql_exec(db->conn, cmd, &select_cb, &srock);

    if (esc_key != db->esc_key) free(esc_key);

    if (r) {
	syslog(LOG_ERR, "DBERROR: SQL failed %s", cmd);
	if (tid) dbengine->sql_rollback_txn(db->conn);
	return CYRUSDB_INTERNAL;
    }

    if (!srock.found) return CYRUSDB_NOTFOUND;

    if (data) *data = db->data;

    return 0;
}

static int foreach(struct db *db,
		   char *prefix, int prefixlen,
		   foreach_p *goodp,
		   foreach_cb *cb, void *rock, 
		   struct txn **tid)
{
    char cmd[1024], *esc_key = NULL;
    struct select_rock srock = { 0, NULL, goodp, cb, rock };
    int r;

    if (tid) {
	if (!*tid && !(*tid = start_txn(db))) return CYRUSDB_INTERNAL;
	srock.tid = *tid;
    }

    /* fetch the data */
    if (prefixlen) /* XXX hack for SQLite */
	esc_key = dbengine->sql_escape(db->conn, &db->esc_key,
				       prefix, prefixlen);
    snprintf(cmd, sizeof(cmd),
	     "SELECT * FROM %s WHERE dbkey LIKE '%s%%' ORDER BY dbkey;",
	     db->table, esc_key ? esc_key : "");
    r = dbengine->sql_exec(db->conn, cmd, &select_cb, &srock);

    if (esc_key && esc_key != db->esc_key) free(esc_key);

    if (r) {
	syslog(LOG_ERR, "DBERROR: SQL failed %s", cmd);
	if (tid) dbengine->sql_rollback_txn(db->conn);
	return CYRUSDB_INTERNAL;
    }

    return 0;
}

static int mystore(struct db *db, 
		   const char *key, int keylen,
		   const char *data, int datalen,
		   struct txn **tid, int overwrite)
{
    char cmd[1024], *esc_key;
    int r = 0;

    if (tid && !*tid && !(*tid = start_txn(db))) return CYRUSDB_INTERNAL;

    esc_key = dbengine->sql_escape(db->conn, &db->esc_key, key, keylen);

    if (!data) {
	/* DELETE the entry */
	snprintf(cmd, sizeof(cmd), "DELETE FROM %s WHERE dbkey = '%s';",
		 db->table, esc_key);
	r = dbengine->sql_exec(db->conn, cmd, NULL, NULL);

	/* see if we just removed the previously SELECTed key */
	if (!r && tid && *tid &&
	    (*tid)->keylen == strlen(esc_key) &&
	    !memcmp((*tid)->lastkey, esc_key, (*tid)->keylen)) {
	    (*tid)->keylen = 0;
	}
    }
    else {
	/* INSERT/UPDATE the entry */
	struct select_rock srock = { 0, NULL, NULL, NULL, NULL };

	char *esc_data = dbengine->sql_escape(db->conn, &db->esc_data,
					      data, datalen);

	/* see if we just SELECTed this key in this transaction */
	if (tid && *tid) {
	    if ((*tid)->keylen == strlen(esc_key) &&
		!memcmp((*tid)->lastkey, esc_key, (*tid)->keylen)) {
		srock.found = 1;
	    }
	    srock.tid = *tid;
	}

	/* check if the entry exists */
	if (!srock.found) {
	    snprintf(cmd, sizeof(cmd),
		     "SELECT * FROM %s WHERE dbkey = '%s';",
		     db->table, esc_key);
	    r = dbengine->sql_exec(db->conn, cmd, &select_cb, &srock);
	}

	if (!r && srock.found) {
	    if (overwrite) {
		/* already have this entry, UPDATE it */
		snprintf(cmd, sizeof(cmd),
			 "UPDATE %s SET data = '%s' WHERE dbkey = '%s';",
			 db->table, esc_data, esc_key);
		r = dbengine->sql_exec(db->conn, cmd, NULL, NULL);
	    }
	    else {
		if (tid) dbengine->sql_rollback_txn(db->conn);
		return CYRUSDB_EXISTS;
	    }
	}
	else if (!r && !srock.found) {
	    /* INSERT the new entry */
	    snprintf(cmd, sizeof(cmd),
		     "INSERT INTO %s VALUES ('%s', '%s');",
		     db->table, esc_key, esc_data);
	    r = dbengine->sql_exec(db->conn, cmd, NULL, NULL);
	}

	if (esc_data != db->esc_data) free(esc_data);
    }

    if (esc_key != db->esc_key) free(esc_key);

    if (r) {
	syslog(LOG_ERR, "DBERROR: SQL failed: %s", cmd);
	if (tid) dbengine->sql_rollback_txn(db->conn);
	return CYRUSDB_INTERNAL;
    }

    return 0;
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
		  struct txn **tid,
		  int force __attribute__((unused)))
{
    return mystore(db, key, keylen, NULL, 0, tid, 1);
}

static int finish_txn(struct db *db, struct txn *tid, int commit)
{
    if (tid) {
	int rc = commit ? dbengine->sql_commit_txn(db->conn) :
	    dbengine->sql_rollback_txn(db->conn);

	if (tid->lastkey) free(tid->lastkey);
	free(tid);

	if (rc) {
	    syslog(LOG_ERR, "DBERROR: failed to %s txn on %s",
		   commit ? "commit" : "abort", db->table);
	    return CYRUSDB_INTERNAL;
	}
    }

    return 0;
}

static int commit_txn(struct db *db, struct txn *tid)
{
    return finish_txn(db, tid, 1);
}

static int abort_txn(struct db *db, struct txn *tid)
{
    return finish_txn(db, tid, 0);
}

struct cyrusdb_backend cyrusdb_sql = 
{
    "sql",			/* name */

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
