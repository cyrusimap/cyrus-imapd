/* mbpath.c -- help the sysadmin to find the path matching the mailbox
 * Copyright 1999 Carnegie Mellon University
 * $Id: mbpath.c,v 1.2 2000/01/28 22:09:49 leg Exp $
 * 
 * No warranties, either expressed or implied, are made regarding the
 * operation, use, or results of the software.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted for non-commercial purposes only
 * provided that this copyright notice appears in all copies and in
 * supporting documentation.
 *
 * Permission is also granted to Internet Service Providers and others
 * entities to use the software for internal purposes.
 *
 * The distribution, modification or sale of a product which uses or is
 * based on the software, in whole or in part, for commercial purposes or
 * benefits requires specific, additional permission from:
 *
 *  Office of Technology Transfer
 *  Carnegie Mellon University
 *  5000 Forbes Avenue
 *  Pittsburgh, PA  15213-3890
 *  (412) 268-4387, fax: (412) 268-7395
 *  tech-transfer@andrew.cmu.edu
 *
 */

static char _rcsid[] = "$Id: mbpath.c,v 1.2 2000/01/28 22:09:49 leg Exp $";

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>

#include "acl.h"
#include "util.h"
#include "auth.h"
#include "prot.h"
#include "imparse.h"
#include "lock.h"
#include "config.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"

extern int optind;
extern char *optarg;

extern int errno;

void
fatal(const char *s, int code) 
{
  if (s) {
    fprintf(stderr,"%s\n",s);
  }
  mboxlist_done();
  exit(code);
}

static int 
usage(void) {
  fprintf(stderr,"usage: cdmb [-q] <mailbox name>...\n");
  fprintf(stderr,"\t-q\tquietly drop any error messages\n");
  fatal(NULL, -1);
}

int
main(int argc, char **argv)
{
  char *path;
  int rc, i, quiet = 0, stop_on_error=0;
  char opt;


  config_init("mbpath");

  while ((opt = getopt(argc, argv, "qs")) != EOF) {
    switch(opt) {
    case 'q':
      quiet = 1;
      break;
    case 's':
      stop_on_error = 1;
      break;

    default:
      usage();
    }
  }

  mboxlist_open();

  for (i = optind; i < argc; i++) {
    (void)memset(&path, 0, sizeof(path));
    if ((rc = mboxlist_lookup(argv[i], &path, NULL, NULL)) == 0) {
      printf("%s\n", path);
    } else {
      if (!quiet && (rc == IMAP_MAILBOX_NONEXISTENT)) {
	fprintf(stderr, "Invalid mailbox name: %s\n", argv[i]);
      }
      if (stop_on_error) {
	if (quiet) {
	  fatal("", -1);
	} else {
	  fatal("Error in processing mailbox. Stopping\n", -1);
	}
      }
    }
  }

  exit(0);
}

/* $Header: /mnt/data/cyrus/cvsroot/src/cyrus/imap/mbpath.c,v 1.2 2000/01/28 22:09:49 leg Exp $ */

