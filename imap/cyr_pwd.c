/* cyr_pwd.c -- current working directory within a spool dir */
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

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* current namespace */
static struct namespace cyr_pwd_namespace;

static int usage(const char *error)
{
    fprintf(stderr, "usage: cyr_pwd [-C <alt_config>]\n");
    fprintf(stderr, "\n");
    if (error) {
        fprintf(stderr, "\n");
        fprintf(stderr, "ERROR: %s", error);
    }
    exit(-1);
}

int main(int argc, char **argv)
{
    int r;
    int opt;
    char *alt_config = NULL;

    /* keep this in alphabetical order */
    static const char short_options[] = "C:";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch(opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        default:
            usage(NULL);
        }
    }

    cyrus_init(alt_config, "cyr_pwd", 0, 0);

    r = mboxname_init_namespace(&cyr_pwd_namespace, NAMESPACE_OPTION_ADMIN);
    if (r) {
        fatal(error_message(r), -1);
    }

    /* Translate mailboxname */
    mbname_t *mbname = NULL;
    const char *extname = NULL;

    mbname = mbname_from_path(".");

    if (mbname) 
        extname = mbname_extname(mbname, &cyr_pwd_namespace, "cyrus");

    if (extname)
        printf("%s\n", extname);
    else
        fprintf(stderr, "ERROR: not in Cyrus UUID mailbox directory\n");

    mbname_free(&mbname);

    cyrus_done();

    exit(0);
}
