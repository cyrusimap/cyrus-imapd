/* dump_deliver.c -- Program to dump deliver db for debugging purposes
 *
 * Copyright 1998, Carnegie Mellon University.  All Rights Reserved.
 * 
 * This software is made available for academic and research
 * purposes only.  No commercial license is hereby granted.
 * Copying and other reproduction is authorized only for research,
 * education, and other non-commercial purposes.  No warranties,
 * either expressed or implied, are made regarding the operation,
 * use, or results of the software.  Such a release does not permit
 * use of the code for commercial purposes or benefits by anyone
 * without specific, additional permission by the owner of the code.
 *
 */

static char _rcsid[] = "$Id: dump_deliver.c,v 1.2 1998/05/12 01:10:28 tjs Exp $";

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
    fprintf(stderr, "Unable to open db file: %s", fname);
    return -1;
  }
    
  mode = R_FIRST;
  while ((rc = DeliveredDBptr->seq(DeliveredDBptr, &delivery, &date, mode)) == 0) {
    count++;
    mode = R_NEXT;
    (void)memcpy(datebuf, date.data, date.size);
    datebuf[date.size] = '\0';
    to += strlen(delivery.data) + 1;
    printf("from: %s\tto: %s\tat: %s\n", delivery.data, to, datebuf);
  }
  if (rc < 0) {
    fprintf(stderr, "error detected looking up entry %d: %m");
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

/* $Header: /mnt/data/cyrus/cvsroot/src/cyrus/imap/Attic/dump_deliver.c,v 1.2 1998/05/12 01:10:28 tjs Exp $ */

