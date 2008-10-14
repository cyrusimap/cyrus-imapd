/* cyr_dbtool.c -- manage Cyrus databases
 *
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
 * $Id: cyr_dbtool.c,v 1.7 2008/10/14 14:53:40 murch Exp $
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
#include <syslog.h>

#include <sys/ipc.h>
#include <sys/msg.h>

#include "acl.h"
#include "assert.h"
#include "auth.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "glob.h"
#include "imap_err.h"
#include "global.h"
#include "mailbox.h"
#include "util.h"
#include "xmalloc.h"

#define STACKSIZE 64000
char stack[STACKSIZE+1];

/* config.c stuff */
const int config_need_data = 0;

struct cyrusdb_backend *DB_OLD = NULL;

struct db *odb = NULL;

int read_key_value(char **keyptr, int *keylen, char **valptr, int *vallen) {
  int c,res,inkey;
  res = 0;
  inkey = 1;
  *keyptr = stack;
  *keylen = 0;
  *vallen = 0;
  while( (c = getchar()) != EOF ) {
    if (c == '\n') break;
    if ((c == '\t') && inkey) {
      inkey = 0;
      *valptr = stack + *keylen + 1;
    } else {
      if (inkey) {
        (*keyptr)[(*keylen)++] = c;
        res = 1;
      } else {
        (*valptr)[(*vallen)++] = c;
      }
    }
    if (*keylen + *vallen >= STACKSIZE - 1) {
      printf("Error, stack overflow\n");
      fatal("stack overflow", EC_DATAERR);
    }
  }
  (*keyptr)[*keylen] = '\0';
  if (inkey) {
    *valptr = *keyptr + *keylen;
  } else {
    (*valptr)[*vallen] = '\0';
  }
  return res;
}

int printer_cb(void *rock __attribute__((unused)),
    const char *key, int keylen,
    const char *data, int datalen)
{
    fwrite(key, sizeof(char), keylen, stdout);
    fputc('\t', stdout);
    fwrite(data, sizeof(char), datalen, stdout);
    fputc('\n', stdout);

    return 0;
}

int main(int argc, char *argv[])
{
    const char *old_db;
    const char *action;
    char *key;
    char *value;
    int i,r,keylen,vallen,reslen;
    int opt,loop;
    char *alt_config = NULL;
    const char *res = NULL;
    int is_get = 0;
    int is_set = 0;
    int is_delete = 0;
    int use_stdin = 0;
    int db_flags = 0;
    struct txn *tid = NULL;

    while ((opt = getopt(argc, argv, "C:n")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;
	case 'n': /* create new */
	    db_flags |= CYRUSDB_CREATE;
	    break;
	}
    }
	
    if((argc - optind) < 3) {
	char sep;

	fprintf(stderr, "Usage: %s [-C altconfig] <old db> <old db backend> <action> [<key>] [<value>]\n", argv[0]);
	fprintf(stderr, "Usable Backends");

	for(i=0, sep = ':'; cyrusdb_backends[i]; i++) {
	    fprintf(stderr, "%c %s", sep, cyrusdb_backends[i]->name);
	    sep = ',';
	}
	
	fprintf(stderr, "\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Actions:\n");
	fprintf(stderr, "* show [<prefix>]\n");
	fprintf(stderr, "* get <key>\n");
	fprintf(stderr, "* set <key> <value>\n");
	fprintf(stderr, "* delete <key>\n");
	fprintf(stderr, "You may omit key or key/value and specify one per line on stdin\n");
	fprintf(stderr, "keys are terminated by tab or newline, values are terminated by newline\n");
	exit(-1);
    }

    old_db = argv[optind];
    action = argv[optind+2];

    if(old_db[0] != '/') {
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
	fatal("unknown backend", EC_TEMPFAIL);
    }   

    cyrus_init(alt_config, "cyr_dbtool", 0);


    r = (DB_OLD->open)(old_db, db_flags, &odb);
    if(r != CYRUSDB_OK)
	fatal("can't open database", EC_TEMPFAIL);

    if (( is_get = !strcmp(action, "get"))  ||
      (is_delete = !strcmp(action, "delete")) ||
      (is_set = !strcmp(action, "set")) ) {
        use_stdin = ( (argc - optind) < 4 );
        if (use_stdin) {
          loop = read_key_value( &key, &keylen, &value, &vallen );
        } else {
          key = argv[optind+3];
          keylen = strlen(key);
          if (is_set) {
            value = argv[optind+4];
            vallen = strlen(value);
          }
          loop = 1;
        }
        while ( loop ) {
          if (is_get) {
            DB_OLD->fetch(odb, key, keylen, &res, &reslen, &tid);
            fwrite(res, sizeof(char), reslen, stdout);
            printf("\n");
          } else if (is_set) {
            DB_OLD->store(odb, key, keylen, value, vallen, &tid);
          } else if (is_delete) {
            DB_OLD->delete(odb, key, keylen, &tid, 1);
          }
          loop = 0;
          if ( use_stdin ) {
            loop = read_key_value( &key, &keylen, &value, &vallen );
          }
        }
    } else if (!strcmp(action, "show")) {
        if ((argc - optind) < 4) {
            DB_OLD->foreach(odb, "", 0, NULL, printer_cb, NULL, &tid);
        } else {
            key = argv[optind+3];
            keylen = strlen(key);
            DB_OLD->foreach(odb, key, keylen, NULL, printer_cb, NULL, &tid);
        }
    } else if (!strcmp(action, "consistency")) {
        if (DB_OLD->consistent(odb)) {
            printf("Consistency Error for %s\n", old_db);
        }
    } else {
        printf("Unknown action %s\n", action);
    }
    if (tid) {
      DB_OLD->commit(odb, tid);
      tid = NULL;
    }

    (DB_OLD->close)(odb);
    
    cyrus_done();

    return 0;
}
