/* dump_deliver.c -- Program to dump deliver db for debugging purposes
 $Id: dump_deliver.c,v 1.7 2000/01/28 22:09:43 leg Exp $
 
 # Copyright 1998 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
 *
 */

static char _rcsid[] = "$Id: dump_deliver.c,v 1.7 2000/01/28 22:09:43 leg Exp $";

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <com_err.h>
#include <errno.h>
#include <db.h>
#include "util.h"
#include "config.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "duplicate.h"

int
dump_deliver(fname)
     char *fname;
{
    DB *db;
    DB_TXN *tid;
    DBC *c;
    int ret;
    DBT key, data;
    int count = 0, r;
    time_t mark;
    char *to;

    memset(&key, 0, sizeof(key));
    memset(&data, 0, sizeof(data));

    ret = db_create(&db, duplicate_dbenv, 0);
    if (ret != 0) {
	fprintf(stderr, "Unable to open db file: %s\n", fname);
	return -1;
    }
    ret = db->open(db, fname, NULL, DB_UNKNOWN, DB_RDONLY, 0664);
    if (ret != 0) {
	fprintf(stderr, "Unable to open db file: %s\n", fname);
	return -1;
    }

    if ((r = db->cursor(db, tid, &c, 0)) != 0) {
	fprintf(stderr, "DBERROR: error creating cursor: %s", strerror(r));
	return -2;
    }

    r = c->c_get(c, &key, &data, DB_FIRST);
    while (r == 0) {
	count++;
	(void)memcpy(&mark, data.data, sizeof(time_t));
	to = ((char *)key.data + (strlen(key.data) + 1));
	printf("id: %-40s\tto: %-20s\tat: %d\n", key.data, to, mark);
	r = c->c_get(c, &key, &data, DB_NEXT);
    }
    if (r != DB_NOTFOUND) {
	fprintf(stderr, "error detected looking up entry: %s\n", strerror(r));
    }
    
    printf("got %d entries\n", count);
}


int
main(argc, argv)
     int argc;
     char *argv[];
{
  extern char *optarg;
  int opt;
  char *alt_file = NULL;

  while ((opt = getopt(argc, argv, "f:")) != EOF) {
    switch (opt) {
    case 'f':
      alt_file = optarg;
      break;
    case '?':
      fprintf(stderr,"usage: -f"
	      "\n\t-f <dbfile>\tAlternate location for deliver.db file."
	      "\n");
      exit(-1);
      break;
    default:
      break;
      /* just pass through */
    }
  }

  config_init("dump_deliverdb");
  
  printf("it is NOW: %d\n", time(NULL));
  
  duplicate_init();
  if (alt_file == NULL) {
    char fname[MAX_MAILBOX_PATH];
    
    (void)strcpy(fname, config_dir);
    (void)strcat(fname, "/delivered.db");
    
    dump_deliver(fname);
  } else {
    dump_deliver(alt_file) ;
  }

  duplicate_done();
}

fatal(s, code)
char *s;
int code;
{
    fprintf(stderr,"dump_deliver: %s\n", s);
    exit(code);
}

/* $Header: /mnt/data/cyrus/cvsroot/src/cyrus/imap/Attic/dump_deliver.c,v 1.7 2000/01/28 22:09:43 leg Exp $ */
