/*
 * ipurge
 *
 * delete mail from cyrus imap mailbox or partition
 * based on date (or size?)
 *
 * includes support for ISPN virtual host extensions
 *
 * $Id: ipurge.c,v 1.13 2001/09/06 15:05:39 leg Exp $
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
 *
 *
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <com_err.h>
#include <string.h>
#include <time.h>

/* cyrus includes */
#include "imapconf.h"
#include "sysexits.h"
#include "exitcodes.h"
#include "imap_err.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "mboxlist.h"

/* globals for getopt routines */
extern char *optarg;
extern int  optind;
extern int  opterr;
extern int  optopt;

/* globals for callback functions */
int days = -1;
int size = -1;
int exact = -1;
int pattern = -1;

/* for statistical purposes */
typedef struct mbox_stats_s {

    int total;         /* total including those deleted */
    int total_bytes;
    int deleted;       
    int deleted_bytes;

} mbox_stats_t;

/* current namespace */
static struct namespace purge_namespace;

int verbose = 1;
int forceall = 0;

int purge_me(char *, int, int);
int purge_check(struct mailbox *, void *, char *);
int usage(char *name);
void print_stats(mbox_stats_t *stats);

int
main (int argc, char *argv[]) {
  char option;
  char buf[MAX_MAILBOX_PATH];
  char *alt_config = NULL;
  int r;

  if (geteuid() == 0) { /* don't run as root, changes permissions */
    usage(argv[0]);
  }

  while ((option = getopt(argc, argv, "C:hxd:b:k:m:f")) != EOF) {
    switch (option) {
    case 'C': /* alt config file */
      alt_config = optarg;
      break;
    case 'd': {
      if (optarg == 0) {
	usage(argv[0]);
      }
      days = atoi(optarg) * 86400 /* nominal # of seconds in a 'day' */;
    } break;
    case 'b': {
      if (optarg == 0) {
	usage(argv[0]);
      }
      size = atoi(optarg);
    } break;
    case 'k': {
      if (optarg == 0) {
	usage(argv[0]);
      }
      size = atoi(optarg) * 1024; /* make it bytes */
    } break;
    case 'm': {
      if (optarg == 0) {
	usage(argv[0]);
      }
      size = atoi(optarg) * 1048576; /* 1024 * 1024 */
    } break;
    case 'x' : {
      exact = 1;
    } break;
    case 'f' : {
      forceall = 1;
    } break;
    case 'h':
    default: usage(argv[0]);
    }
  }
  if ((days == -1 ) && (size == -1)) {
    printf("One of these must be specified -d, -b -k, -m\n");
    usage(argv[0]);
  }

  config_init(alt_config, "ipurge");

  if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);

  /* Set namespace -- force standard (internal) */
  if ((r = mboxname_init_namespace(&purge_namespace, 1)) != 0) {
      syslog(LOG_ERR, error_message(r));
      fatal(error_message(r), EC_CONFIG);
  }

  mboxlist_init(0);
  mboxlist_open(NULL);

  if (optind == argc) { /* do the whole partition */
    strcpy(buf, "*");
    (*purge_namespace.mboxlist_findall)(&purge_namespace, buf, 1, 0, 0,
					purge_me, NULL);
  } else {
    for (; optind < argc; optind++) {
      strncpy(buf, argv[optind], MAX_MAILBOX_NAME);
      /* Translate any separators in mailboxname */
      mboxname_hiersep_tointernal(&purge_namespace, buf);
      (*purge_namespace.mboxlist_findall)(&purge_namespace, buf, 1, 0, 0,
					  purge_me, NULL);
    }
  }
  mboxlist_close();
  mboxlist_done();

  return 0;
}

int
usage(char *name) {
  printf("usage: %s [-f] [-C <alt_config>] [-x] {-d days &| -b bytes|-k Kbytes|-m Mbytes}\n\t[mboxpattern1 ... [mboxpatternN]]\n", name);
  printf("\tthere are no defaults and at least one of -d, -b, -k, -m\n\tmust be specified\n");
  printf("\tif no mboxpattern is given %s works on all mailboxes\n", name);
  printf("\t -x specifies an exact match for days or size\n");
  printf("\t -f force also to delete mail below user.* and INBOX.*\n");
  exit(0);
}

/* we don't check what comes in on matchlen and maycreate, should we? */
int
purge_me(char *name, int matchlen, int maycreate) {
  struct mailbox the_box;
  int            error;
  mbox_stats_t   stats;

  if( ! forceall ) {
    /* DON'T purge INBOX* and user.* */
    if ((strncasecmp(name,"INBOX",5)==0) || (strncasecmp(name,"user.",5)==0))
      return 0;
  }

  memset(&stats, '\0', sizeof(mbox_stats_t));

  if (verbose)
      printf("Working on %s...\n",name);

  error = mailbox_open_header(name, 0, &the_box);
  if (error != 0) { /* did we find it? */
    syslog(LOG_ERR, "Couldn't find %s, check spelling", name);
    return error;
  }
  if (the_box.header_fd != -1) {
    (void) mailbox_lock_header(&the_box);
  }
  the_box.header_lock_count = 1;

  error = chdir(the_box.path);
  if (error < 0) {
    syslog(LOG_ERR, "Couldn't change directory to %s : %m", the_box.path);
    return error;
  }
  error = mailbox_open_index(&the_box);
  if (error != 0) {
    mailbox_close(&the_box);
    syslog(LOG_ERR, "Couldn't open mailbox index for %s", name);
    return error;
  }
  (void) mailbox_lock_index(&the_box);
  the_box.index_lock_count = 1;

  mailbox_expunge(&the_box, 1, purge_check, &stats);
  mailbox_close(&the_box);

  print_stats(&stats);

  return 0;
}

void deleteit(bit32 msgsize, mbox_stats_t *stats)
{
    stats->deleted++;
    stats->deleted_bytes += msgsize;
}

/* thumbs up routine, checks date & size and returns yes or no for deletion */
/* 0 = no, 1 = yes */
int
purge_check(struct mailbox *mailbox, void *deciderock, char *buf) {
  struct index_record *the_record;
  unsigned long       my_time;
  mbox_stats_t *stats = (mbox_stats_t *) deciderock;
  bit32 senttime;
  bit32 msgsize;

  senttime = ntohl(*((bit32 *)(buf + OFFSET_SENTDATE)));
  msgsize = ntohl(*((bit32 *)(buf + OFFSET_SIZE)));

  stats->total++;
  stats->total_bytes += msgsize;



  if (exact == 1) {
    if (days >= 0) {
      my_time = time(0);
      /*    printf("comparing %ld :: %ld\n", my_time, the_record->sentdate); */
      if (((my_time - senttime)/86400) == (days/86400)) {
	  deleteit(msgsize, stats);
	  return 1;
      }
    }
    if (size >= 0) {
      /* check size */
      if (msgsize == size) {
	  deleteit(msgsize, stats);
	  return 1;
      }
    }
    return 0;
  } else {
    if (days >= 0) {
      my_time = time(0);
      /*    printf("comparing %ld :: %ld\n", my_time, the_record->sentdate); */
      if ((my_time - senttime) > days) {
	  deleteit(msgsize, stats);
	  return 1;
      }
    }
    if (size >= 0) {
      /* check size */
      if (msgsize > size) {
	  deleteit(msgsize, stats);
	  return 1;
      }
    }
    return 0;
  }
}

void print_stats(mbox_stats_t *stats)
{
    printf("total messages    \t\t %d\n",stats->total);
    printf("total bytes       \t\t %d\n",stats->total_bytes);
    printf("Deleted messages  \t\t %d\n",stats->deleted);
    printf("Deleted bytes     \t\t %d\n",stats->deleted_bytes);
    printf("Remaining messages\t\t %d\n",stats->total - stats->deleted);
    printf("Remaining bytes   \t\t %d\n",stats->total_bytes - stats->deleted_bytes);
}

/* fatal needed for imap library */
void
fatal(const char *s, int code) {
  fprintf(stderr, "ipurge: %s\n", s);
  exit(code);
}
