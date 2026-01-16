/* cyr_withlock_run.c - run a command with the global lock or a user lock held */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

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
