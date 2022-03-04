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
#include <sysexits.h>
#include <syslog.h>
#include <string.h>
#include <sys/stat.h>

/* cyrus includes */
#include "assert.h"
#include "bsearch.h"
#include "global.h"
#include "index.h"
#include "search_engines.h"
#include "search_expr.h"
#include "search_query.h"
#include "message.h"
#include "util.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

static int usage(const char *name);

static int verbose = 0;

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
    printf("highestmodseq %llu\n", (unsigned long long)search_folder_get_highest_modseq(folder));
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
    struct timeval start_time, end_time;

    memset(&init, 0, sizeof(struct index_init));

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

    init.userid = userid;
    init.authstate = auth_newstate(userid);
    init.out = pout;

    r = index_open(mboxname, &init, &state);
    if (r) {
        fprintf(stderr, "%s: %s\n", mboxname, error_message(r));
        goto out;
    }

    index_checkflags(state, 0, 0);

    searchargs = new_searchargs(".", GETSEARCH_CHARSET_KEYWORD, &ns, userid, init.authstate, /*isadmin*/0);

    gettimeofday(&start_time, NULL);

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
    gettimeofday(&end_time, NULL);

    hash_enumerate(&query->folders_by_name, dump_one_folder, query);

    if (verbose)
        fprintf(stderr, "search_test: ran query in %.6f sec\n",
                timesub(&start_time, &end_time));

out:
    if (pin) prot_free(pin);
    if (pout) prot_free(pout);
    if (searchargs) freesearchargs(searchargs);
    search_query_free(query);
    index_close(&state);
    buf_free(&querytext);
    if (init.authstate) auth_freestate(init.authstate);
    return !!r;
}

/* ====================================================================== */

static int do_serialise(char **words, int nwords)
{
    const char *userid = "cassandane";
    struct buf querytext = BUF_INITIALIZER;
    struct namespace ns;
    struct protstream *pin = NULL;
    struct protstream *pout = NULL;
    struct searchargs *searchargs = NULL;
    char *str = NULL;
    search_expr_t *e = NULL;
    int i;
    int r;
    struct timeval start_time, end_time;

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

    searchargs = new_searchargs(".", GETSEARCH_CHARSET_KEYWORD, &ns, userid, auth_newstate(userid), /*isadmin*/0);

    r = get_search_program(pin, pout, searchargs);
    if (r != '\r') {
        fprintf(stderr, "Couldn't parse IMAP search program\n");
        goto out;
    }

    gettimeofday(&start_time, NULL);
    str = search_expr_serialise(searchargs->root);
    gettimeofday(&end_time, NULL);
    if (verbose)
        fprintf(stderr, "search_test: serialised query in %.6f sec\n",
                timesub(&start_time, &end_time));

    gettimeofday(&start_time, NULL);
    e = search_expr_unserialise(str);
    gettimeofday(&end_time, NULL);
    if (verbose)
        fprintf(stderr, "search_test: unserialised query in %.6f sec\n",
                timesub(&start_time, &end_time));

out:
    if (pin) prot_free(pin);
    if (pout) prot_free(pout);
    if (searchargs) freesearchargs(searchargs);
    if (e) search_expr_free(e);
    free(str);
    return !!r;
}

/* ====================================================================== */

int main(int argc, char **argv)
{
    int c;
    const char *alt_config = NULL;
    const char *userid = NULL;
    const char *mboxname = NULL;
    enum { SEARCH, SERIALISE } mode = SEARCH;
    int multiple = 0;
    int r = 0;

    while ((c = getopt(argc, argv, "C:LMSm:u:v")) != EOF) {
        switch (c) {

        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'L':
            mode = SERIALISE;
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
    if (mode == SEARCH && !mboxname)
        usage(argv[0]);

    cyrus_init(alt_config, "search_test",
               CYRUSINIT_PERROR, CONFIG_NEED_PARTITION_DATA);

    char *freeme = NULL;

    switch (mode) {

    case SEARCH:
        if (!userid) {
            userid = freeme = mboxname_to_userid(mboxname);
            if (!userid)
                usage(argv[0]);
        }

        r = do_search(mboxname, multiple, userid, argv+optind, argc-optind);
        free(freeme);
        break;

    case SERIALISE:
        r = do_serialise(argv+optind, argc-optind);
        break;
    }

    cyrus_done();

    return r;
}

static int usage(const char *name)
{
    fprintf(stderr, "usage: %s [format-options] -m mailbox -u userid searchprogram...\n", name);
    exit(EX_USAGE);
}

EXPORTED void fatal(const char* s, int code)
{
    fprintf(stderr, "search_test: %s\n", s);
    cyrus_done();
    exit(code);
}


