/* dbcvt.c -- Convert between two database formats
 * 
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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
 *
 */
/*
 * $Id: cvt_cyrusdb.c,v 1.6.6.5 2002/11/15 21:46:55 rjs3 Exp $
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <syslog.h>
#include <com_err.h>

#include <sys/ipc.h>
#include <sys/msg.h>

#include "acl.h"
#include "assert.h"
#include "auth.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "glob.h"
#include "imap_err.h"
#include "imapconf.h"
#include "mailbox.h"
#include "util.h"
#include "xmalloc.h"

/* config.c stuff */
const int config_need_data = 0;

struct cyrusdb_backend *DB_OLD = NULL, *DB_NEW = NULL;

struct db *odb = NULL, *ndb = NULL;
struct txn *tid = NULL;

int converter_p(void *rock __attribute__((unused)),
		const char *key __attribute__((unused)),
		int keylen __attribute__((unused)),
		const char *data __attribute__((unused)),
		int datalen __attribute__((unused)))
{
    /* Always true */
    return 1;
}

int converter_cb(void *rock __attribute__((unused)),
		 const char *key, int keylen,
		 const char *data, int datalen) 
{
    return DB_NEW->store(ndb, key, keylen, data, datalen, &tid);
}

int main(int argc, char *argv[])
{
    const char *old_db, *new_db;
    int i,r;
    int opt;
    char *alt_config = NULL;

    while ((opt = getopt(argc, argv, "C:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;
	}
    }
	
    if((argc - optind) != 4) {
	fprintf(stderr, "Usage: %s [-C altconfig] <old db> <old db backend> <new db> <new db backend>\n", argv[0]);
	fprintf(stderr, "Usable Backends:  ");

	if(!cyrusdb_backends || !cyrusdb_backends[0])
	    fatal("we don't seem to have any db backends available", EC_OSERR);
	
	fprintf(stderr, "%s", cyrusdb_backends[0]->name);
	for(i=1; cyrusdb_backends[i]; i++)
	    fprintf(stderr, ", %s", cyrusdb_backends[i]->name);
	
	fprintf(stderr, "\n");
	exit(-1);
    }

    old_db = argv[optind];
    new_db = argv[optind+2];

    if(old_db[0] != '/' || new_db[0] != '/') {
	printf("\nSorry, you cannot use this tool with relative path names.\n"
	       "This is because some database backends (mainly berkeley) do not\n"
	       "always do what you would expect with them.\n"
	       "\nPlease use absolute pathnames instead.\n\n");
	exit(EC_OSERR);
    }

    for(i=0; cyrusdb_backends[i]; i++) {
	if(!strcmp(cyrusdb_backends[i]->name, argv[optind+1])) {
	    DB_OLD = cyrusdb_backends[i]; break;
	}
    }
    if(!cyrusdb_backends[i]) {
	fatal("unknown old backend", EC_TEMPFAIL);
    }   

    for(i=0; cyrusdb_backends[i]; i++) {
	if(!strcmp(cyrusdb_backends[i]->name, argv[optind+3])) {
	    DB_NEW = cyrusdb_backends[i]; break;
	}
    }
    if(!cyrusdb_backends[i]) {
	fatal("unknown new backend", EC_TEMPFAIL);
    }

    if(DB_NEW == DB_OLD) {
	fatal("no conversion required", EC_TEMPFAIL);
    }

    config_init(alt_config, "cvt_cyrusdb");

    printf("Converting from %s (%s) to %s (%s)\n", old_db, DB_OLD->name,
	   new_db, DB_NEW->name);

    r = DB_OLD->open(old_db, &odb);
    if(r != CYRUSDB_OK)
	fatal("can't open old database", EC_TEMPFAIL);
    r = DB_NEW->open(new_db, &ndb);
    if(r != CYRUSDB_OK)
	fatal("can't open new database", EC_TEMPFAIL);

    DB_OLD->foreach(odb, "", 0, converter_p, converter_cb, NULL, NULL);

    /* we want to have done atleast one entry at this point */
    if(tid)
	DB_NEW->commit(ndb, tid);
    else
	fprintf(stderr, "Warning: apparently empty database converted.\n");
    

    DB_OLD->close(odb);
    DB_NEW->close(ndb);
    
    cyrus_done();

    return 0;
}
