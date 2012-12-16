/*
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
#include <syslog.h>
#include <string.h>
#include <sys/stat.h>

/* cyrus includes */
#include "assert.h"
#include "bsearch.h"
#include "exitcodes.h"
#include "global.h"
#include "imap_err.h"
#include "index.h"
#include "search_engines.h"
#include "search_expr.h"
#include "search_query.h"
#include "message.h"
#include "sysexits.h"
#include "util.h"
#include "xmalloc.h"

#if !HAVE___ATTRIBUTE__
#define __attribute__(x)
#endif

static int usage(const char *name);

int verbose = 0;

/* ====================================================================== */

static void dump_one_folder(const char *key __attribute__((unused)),
			    void *data,
			    void *rock __attribute__((unused)))
{
    search_folder_t *folder = data;
    int uid;

    printf("mailbox %s\n", folder->mboxname);
    printf("min %u\n", search_folder_get_min(folder));
    printf("max %u\n", search_folder_get_max(folder));
    printf("count %u\n", search_folder_get_count(folder));
    printf("highestmodseq %llu\n", search_folder_get_highest_modseq(folder));
    search_folder_foreach(folder, uid) {
	printf("uid %u\n", uid);
    }
}

static int do_search(const char *mboxname,
		     int multiple,
		     const char *userid,
		     char **words, int nwords)
{
    struct buf querytext = BUF_INITIALIZER;
    struct namespace ns;
    struct index_init init;
    struct index_state *state = NULL;
    struct protstream *pin = NULL;
    struct protstream *pout = NULL;
    struct searchargs *searchargs = NULL;
    search_query_t *query = NULL;
    int i;
    int r;

    for (i = 0 ; i < nwords ; i++) {
	if (i) buf_putc(&querytext, ' ');
	buf_appendcstr(&querytext, words[i]);
    }
    if (verbose)
	fprintf(stderr, "search_test: IMAP query is \"%s\"\n", buf_cstring(&querytext));
    buf_putc(&querytext, '\r');
    buf_cstring(&querytext);

    r = mboxname_init_namespace(&ns, /*isadmin*/0);
    if (r) {
	fprintf(stderr, "Failed to initialise namespace: %s\n", error_message(r));
	goto out;
    }

    pin = prot_readmap(querytext.s, querytext.len);
    pout = prot_new(/*fd*/0, /*write*/1);

    memset(&init, 0, sizeof(struct index_init));
    init.userid = userid;
    init.authstate = auth_newstate(userid);
    init.out = pout;

    r = index_open(mboxname, &init, &state);
    if (r) {
	fprintf(stderr, "%s: %s\n", mboxname, error_message(r));
	goto out;
    }

    index_checkflags(state, 0, 0);

    searchargs = new_searchargs(".", /*state*/0, &ns, userid, init.authstate, /*isadmin*/0);

    r = get_search_program(pin, pout, searchargs);
    if (r != '\r') {
	fprintf(stderr, "Couldn't parse IMAP search program\n");
	goto out;
    }

    query = search_query_new(state, searchargs);
    query->multiple = multiple;
    query->verbose = verbose;
    r = search_query_run(query);
    if (r) {
	fprintf(stderr, "Failed to run query: %s\n", error_message(r));
	goto out;
    }

    hash_enumerate(&query->folders_by_name, dump_one_folder, query);

out:
    if (pin) prot_free(pin);
    if (pout) prot_free(pout);
    if (searchargs) freesearchargs(searchargs);
    search_query_free(query);
    index_close(&state);
    return !!r;
}

/* ====================================================================== */

int main(int argc, char **argv)
{
    int c;
    const char *alt_config = NULL;
    const char *userid = NULL;
    const char *mboxname = NULL;
    int multiple = 0;
    int r = 0;

    if ((geteuid()) == 0 && (become_cyrus() != 0)) {
	fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((c = getopt(argc, argv, "C:MSm:u:v")) != EOF) {
	switch (c) {

	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;

	case 'M':
	    multiple = 1;
	    break;

	case 'S':
	    multiple = 0;
	    break;

	case 'm':
	    mboxname = optarg;
	    break;

	case 'u':
	    userid = optarg;
	    break;

	case 'v':
	    verbose++;
	    break;

	default:
	    usage(argv[0]);
	    break;
	}
    }

    if (optind == argc)
	usage(argv[0]);
    if (!mboxname)
	usage(argv[0]);

    cyrus_init(alt_config, "search_test",
	       CYRUSINIT_PERROR, CONFIG_NEED_PARTITION_DATA);

    mboxlist_init(0);
    mboxlist_open(NULL);
    search_attr_init();

    if (!userid) {
	userid = mboxname_to_userid(mboxname);
	if (!userid)
	    usage(argv[0]);
    }

    r = do_search(mboxname, multiple, userid, argv+optind, argc-optind);

    mboxlist_close();
    mboxlist_done();

    cyrus_done();

    return r;
}

static int usage(const char *name)
{
    fprintf(stderr, "usage: %s [format-options] -m mailbox -u userid searchprogram...\n", name);
    exit(EC_USAGE);
}

void fatal(const char* s, int code)
{
    fprintf(stderr, "search_test: %s\n", s);
    cyrus_done();
    exit(code);
}


