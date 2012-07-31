/* cyr_deny.c - tool to manipulate the deny database
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <syslog.h>
#include <errno.h>

#include "global.h"
#include "exitcodes.h"
#include "libcyr_cfg.h"
#include "userdeny.h"
#include "imap/imap_err.h"
#include "util.h"
#include "xmalloc.h"

static void usage(void)
{
    fprintf(stderr, "Usage: cyr_deny [-C <altconfig>] [ -s services ] [ -m message ] user\n");
    fprintf(stderr, "       cyr_deny [-C <altconfig>] -a user\n");
    exit(EC_USAGE);
}

int main(int argc, char **argv)
{
    int opt;
    int allow_flag = 0;
    const char *alt_config = NULL;
    const char *user = NULL;
    const char *message = NULL;
    const char *services = NULL;
    int r;

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((opt = getopt(argc, argv, "C:am:s:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'a':
	    allow_flag = 1;
	    break;

	case 'm':
	    message = optarg;
	    break;

	case 's':
	    services = optarg;
	    break;

	default:
	    usage();
	    break;
	}
    }
    if (allow_flag && (message || services))
	usage();
    if (optind != argc-1)
	usage();
    user = argv[optind];

    cyrus_init(alt_config, "cyr_deny", 0, 0);

    denydb_init(0);

    r = denydb_openw(/*create*/!allow_flag);
    if (r) {
	if (allow_flag && r == IMAP_NOTFOUND)
	    r = 0;
	else
	    fprintf(stderr, "cyr_deny: failed to open deny db: %s\n",
		    error_message(r));
	goto out;
    }

    if (allow_flag) {
	r = denydb_delete(user);
	if (r)
	    fprintf(stderr, "cyr_deny: failed to allow access for %s: %s\n",
		    user, error_message(r));
    }
    else {
	r = denydb_set(user, services, message);
	if (r)
	    fprintf(stderr, "cyr_deny: failed to deny access for %s: %s\n",
		    user, error_message(r));
    }

    denydb_close();
out:
    denydb_done();
    return !!r;
}
