/* dump_deliver.c -- Program to dump deliver db for debugging purposes
 $Id: dump_deliver.c,v 1.4 1998/05/15 21:48:25 neplokh Exp $
 
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

static char _rcsid[] = "$Id: dump_deliver.c,v 1.4 1998/05/15 21:48:25 neplokh Exp $";

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <com_err.h>
#include <errno.h>
#ifdef HAVE_LIBDB
#ifdef HAVE_DB_185_H
#include <db_185.h>
#else
#include <db.h>
#endif
#else
#include <ndbm.h>
#endif
#include "util.h"
#include "config.h"
#include "mailbox.h"

#ifdef HAVE_LIBDB
static DB	*DeliveredDBptr;
#else
static DBM	*DeliveredDBptr;
#endif

int
dump_deliver(fname)
     char *fname;
{
  char buf[MAX_MAILBOX_PATH];
  int lockfd;
  int rcode = 0;
  char datebuf[40];
  int len;
  int count = 1;


#ifdef HAVE_LIBDB
  int rc, mode;
  DBT date, delivery;
  DBT *deletions = 0;
  HASHINFO info;
  int num_deletions = 0, alloc_deletions = 0;
  char *to;


  /* Note we don't lock the db -- this may cause some problems if things
   * change in the middle of the dump but we're going to assume that it won't
   */

  (void)memset(&info, 0, sizeof(info));
  DeliveredDBptr = dbopen(fname, O_RDONLY, 0666, DB_HASH, &info);
  if (!DeliveredDBptr) {
    fprintf(stderr, "Unable to open db file: %s\n", fname);
    return -1;
  }
    
  mode = R_FIRST;
  while ((rc = DeliveredDBptr->seq(DeliveredDBptr, &delivery, &date, mode)) == 0) {
    count++;
    mode = R_NEXT;
    (void)memcpy(datebuf, date.data, date.size);
    datebuf[date.size] = '\0';
    to = ((char *)delivery.data + (strlen(delivery.data) + 1));
    printf("id: %-40s\tto: %-20s\tat: %s\n", delivery.data, to, datebuf);
  }
  if (rc < 0) {
    fprintf(stderr, "error detected looking up entry: %d\n");
  }
    
#else /* HAVE_LIBDB */

  printf("sorry, not implemented for non DB systems\n");

#endif /* HAVE_LIBDB */
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

  if (alt_file == NULL) {
    char fname[MAX_MAILBOX_PATH];
    
    (void)strcpy(fname, config_dir);
    (void)strcat(fname, "/delivered.db");
    
    dump_deliver(fname);
  } else {
    dump_deliver(alt_file) ;
  }

}

fatal(s, code)
char *s;
int code;
{
    fprintf(stderr,"dump_deliver: %s\n", s);
    exit(code);
}

/* $Header: /mnt/data/cyrus/cvsroot/src/cyrus/imap/Attic/dump_deliver.c,v 1.4 1998/05/15 21:48:25 neplokh Exp $ */

