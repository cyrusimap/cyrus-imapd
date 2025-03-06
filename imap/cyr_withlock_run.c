/* cyr_withlock_run.c -- run a command with the global lock or a user lock held
 *
 * Copyright (c) 1994-2023 Carnegie Mellon University.  All rights reserved.
 *
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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "global.h"
#include "mboxname.h"
#include "command.h"
#include "strarray.h"
#include "user.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* current namespace */
static struct namespace cyr_runlock_namespace;

static int usage(const char *error)
{
    fprintf(stderr, "usage: cyr_runlock [-C <alt_config>] cmd args\n");
    fprintf(stderr, "\n");
    if (error) {
        fprintf(stderr, "\n");
        fprintf(stderr, "ERROR: %s", error);
    }
    exit(-1);
}

int runcmd(void *rock)
{
    return run_command_strarray((const strarray_t *)rock);
}

int main(int argc, char **argv)
{
    int r;
    int opt;
    char *alt_config = NULL;
    char *userid = NULL;

    /* keep this in alphabetical order */
    static const char short_options[] = "C:u:";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { "user", required_argument, NULL, 'u' },
        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch(opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;
        
        case 'u':
            userid = optarg;
            break;

        default:
            usage(NULL);
        }
    }

    cyrus_init(alt_config, "cyr_runlock", 0, 0);

    r = mboxname_init_namespace(&cyr_runlock_namespace, NAMESPACE_OPTION_ADMIN);
    if (r) {
        fatal(error_message(r), -1);
    }

    strarray_t args = STRARRAY_INITIALIZER;
    int i;
    for (i = optind; i < argc; i++)
        strarray_append(&args, argv[i]);
    if (userid) {
        static char env_userlock[MAX_MAILBOX_NAME+30];
        snprintf(env_userlock, sizeof(env_userlock), "CYRUS_HAVELOCK_USER=%s", userid);
        putenv(env_userlock);
        r = user_run_with_lock(userid, runcmd, &args);
    }
    else {
        static char env_havelock[100];
        snprintf(env_havelock, sizeof(env_havelock), "CYRUS_HAVELOCK_GLOBAL=1");
        putenv(env_havelock);
        r = mboxname_run_with_lock(runcmd, &args);
    }
    strarray_fini(&args);

    cyrus_done();

    exit(r ? EXIT_FAILURE : EXIT_SUCCESS);
}
