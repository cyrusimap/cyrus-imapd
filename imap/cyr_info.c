/* ctl_info.c - tool to get information about cyrus
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
 * $Id: ctl_cyrusdb.c,v 1.33 2010/01/06 17:01:30 murch Exp $
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
#include "proc.h"
#include "util.h"
#include "xmalloc.h"

/* config.c stuff */
const int config_need_data = 0;

static void usage(void)
{
    fprintf(stderr, "cyr_info [-C <altconfig>] command\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Where command is one of:\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  * proc       - listing of all open processes\n");
    fprintf(stderr, "  * allconf    - listing of all config values\n");
    fprintf(stderr, "  * conf       - listing of non-default config values\n");
    exit(-1);
}

static int print_procinfo(int pid, const char *host, 
			  const char *user, const char *mailbox,
			  void *rock __attribute__((unused)))
{
    printf("%d %s", pid, host);
    if (user) printf(" %s", user);
    if (mailbox) printf(" %s", mailbox);
    printf("\n");
    return 0;
}

static void do_proc(void)
{
    proc_foreach(print_procinfo, NULL);
}

static void print_overflow(const char *key, const char *val,
			  void *rock __attribute__((unused)))
{
    printf("%s: %s\n", key, val);
}

static void do_conf(int only_changed)
{
    int i;
    unsigned j;

    /* XXX: this is semi-sorted, but the overflow strings aren't sorted at all */

    for (i = 1; i < IMAPOPT_LAST; i++) {
	switch (imapopts[i].t) {
	case OPT_STRING:
	case OPT_STRINGLIST:
	    if (only_changed) {
		if (!imapopts[i].def.s && !imapopts[i].val.s) break;
		if (imapopts[i].def.s && imapopts[i].val.s &&
		    !strcmp(imapopts[i].def.s, imapopts[i].val.s)) break;
	    }
	    printf("%s: %s\n", imapopts[i].optname, imapopts[i].val.s ? imapopts[i].val.s : "");
	    break;
	case OPT_INT:
	    if (only_changed) {
		if (imapopts[i].def.i == imapopts[i].val.i) break;
	    }
	    printf("%s: %ld\n", imapopts[i].optname, imapopts[i].val.i);
	    break;
	case OPT_SWITCH:
	    if (only_changed) {
		if (imapopts[i].def.b == imapopts[i].val.b) break;
	    }
	    printf("%s: %s\n", imapopts[i].optname, imapopts[i].val.b ? "yes" : "no");
	    break;
	case OPT_ENUM:
	    if (only_changed) {
		if (imapopts[i].def.e == imapopts[i].val.e) break;
	    }
	    printf("%s:", imapopts[i].optname);
	    for (j = 0; imapopts[i].enum_options[j].val; j++) {
		if (imapopts[i].val.e == j) {
		    printf(" %s", imapopts[i].enum_options[j].name);
		    break;
		}
	    }
	    printf("\n");
	    break;
	case OPT_BITFIELD:
	    if (only_changed) {
		if (imapopts[i].def.x == imapopts[i].val.x) break;
	    }
	    printf("%s:", imapopts[i].optname);
	    for (j = 0; imapopts[i].enum_options[j].val; j++) {
		if (imapopts[i].val.x & (1<<j)) {
		    printf(" %s", imapopts[i].enum_options[j].name);
		}
	    }
	    printf("\n");
	    break;
	default:
	    abort();
	}
    }

    /* and the overflows */
    config_foreachoverflowstring(print_overflow, NULL);
}

int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt;
    char *alt_config = NULL;

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((opt = getopt(argc, argv, "C:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	default:
	    usage();
	    break;
	}
    }

    cyrus_init(alt_config, "cyr_info", 0);

    if (!strcmp(argv[optind], "proc"))
	do_proc();
    else if (!strcmp(argv[optind], "allconf"))
	do_conf(0);
    else if (!strcmp(argv[optind], "conf"))
	do_conf(1);
    else
	usage();

    return 0;
}
