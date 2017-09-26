/* mbpath.c -- help the sysadmin to find the path matching the mailbox
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
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>

#include "util.h"
#include "global.h"
#include "exitcodes.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "mboxlist.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

extern int optind;
extern char *optarg;

/* current namespace */
static struct namespace mbpath_namespace;

static int
usage(void) {
  fprintf(stderr,"usage: mbpath [-C <alt_config>] [-q] [-s] [-m] <mailbox name>...\n");
  fprintf(stderr,"\t-q\tquietly drop any error messages\n");
  fprintf(stderr,"\t-s\tstop on error\n");
  fprintf(stderr,"\t-m\toutput the path to the metadata files (if different from the message files)\n");
  exit(-1);
}

int
main(int argc, char **argv)
{
  mbentry_t *mbentry = NULL;
  int rc, i, quiet = 0, stop_on_error=0, metadata=0;
  int opt;              /* getopt() returns an int */
  char *alt_config = NULL;

  while ((opt = getopt(argc, argv, "C:qsm")) != EOF) {
    switch(opt) {
    case 'C': /* alt config file */
      alt_config = optarg;
      break;
    case 'q':
      quiet = 1;
      break;
    case 's':
      stop_on_error = 1;
      break;
    case 'm':
        metadata = 1;
        break;

    default:
      usage();
    }
  }

  cyrus_init(alt_config, "mbpath", 0, 0);

  if ((rc = mboxname_init_namespace(&mbpath_namespace, 1)) != 0) {
    fatal(error_message(rc), -1);
  }

  for (i = optind; i < argc; i++) {
    /* Translate mailboxname */
    char *intname = mboxname_from_external(argv[i], &mbpath_namespace, NULL);
    if ((rc = mboxlist_lookup(intname, &mbentry, NULL)) == 0) {
      if (mbentry->mbtype & MBTYPE_REMOTE) {
        printf("%s!%s\n", mbentry->server, mbentry->partition);
      } else if (metadata) {
        const char *path = mbentry_metapath(mbentry, 0, 0);
        printf("%s\n", path);
      }
      else {
        const char *path = mbentry_datapath(mbentry, 0);
        printf("%s\n", path);
      }
      mboxlist_entry_free(&mbentry);
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
    free(intname);
  }

  cyrus_done();

  return 0;
}

/* $Header: /mnt/data/cyrus/cvsroot/src/cyrus/imap/mbpath.c,v 1.23 2010/01/06 17:01:37 murch Exp $ */

