/* 
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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

#ifndef INCLUDED_CYRUSDB_H
#define INCLUDED_CYRUSDB_H

struct db;
struct txn;

enum cyrusdb_ret {
    CYRUSDB_OK = 0,
    CYRUSDB_IOERROR = -1,
    CYRUSDB_AGAIN = -2,
    CYRUSDB_EXISTS = -3
};

#define cyrusdb_strerror(c) ("cyrusdb error")

enum cyrusdb_initflags {
    CYRUSDB_RECOVER = 0x01
};

enum cyrusdb_dbflags {
    CYRUSDB_NOSYNC = 0x01	/* durability not a concern */
};

typedef int foreach_p(void *rock,
		      const char *key, int keylen,
		      const char *data, int datalen);

typedef int foreach_cb(void *rock,
		       const char *key, int keylen,
		       const char *data, int datalen);

struct cyrusdb_backend {
    const char *name;

    int (*init)(const char *dbdir, int myflags);
    int (*done)(void);
    int (*sync)(void);

    int (*open)(const char *fname, struct db **ret);
    int (*close)(struct db *db);
    
    int (*fetch)(struct db *mydb, 
		 const char *key, int keylen,
		 const char **data, int *datalen,
		 struct txn **mytid);
    int (*fetchlock)(struct db *mydb, 
		     const char *key, int keylen,
 		     const char **data, int *datalen,
		     struct txn **mytid);
    int (*foreach)(struct db *mydb,
		   char *prefix, int prefixlen,
		   foreach_p *p,
		   foreach_cb *cb, void *rock, 
		   struct txn **tid);
    int (*create)(struct db *db, 
		  const char *key, int keylen,
		  const char *data, int datalen,
		  struct txn **tid);
    int (*store)(struct db *db, 
		 const char *key, int keylen,
		 const char *data, int datalen,
		 struct txn **tid);
    int (*delete)(struct db *db, 
		  const char *key, int keylen,
		  struct txn **tid);
    
    int (*commit)(struct db *db, struct txn *tid);
    int (*abort)(struct db *db, struct txn *tid);
};

extern struct cyrusdb_backend cyrusdb_db3;
extern struct cyrusdb_backend cyrusdb_flat;

#endif /* INCLUDED_CYRUSDB_H */
