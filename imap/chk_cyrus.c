/* chk_cyrus.c - cyrus mailstore consistency checker */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <limits.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "index.h"
#include "global.h"
#include "mboxlist.h"
#include "mailbox.h"
#include "map.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

static void usage(void)
{
    fprintf(stderr, "chk_cyrus [-C <altconfig>] partition\n");
    exit(-1);
}

static const char *check_part = NULL; /* partition we are checking */

static int chkmbox(struct findall_data *data, void *rock __attribute__((unused)))
{
    if (!data) return 0;
    if (!data->is_exactmatch) return 0;
    int r;
    mbentry_t *mbentry = NULL;
    const char *name = mbname_intname(data->mbname);

    r = mboxlist_lookup(name, &mbentry, NULL);

    if (r == IMAP_MAILBOX_NONEXISTENT)
       return 0;

    /* XXX reserved mailboxes? */

    if (r) {
        fprintf(stderr, "bad mailbox %s in chkmbox: %s\n", name, error_message(r));
        fatal("fatal error",EX_TEMPFAIL);
    }

    /* are we on the partition we are checking? */
    if (check_part && strcmp(mbentry->partition, check_part)) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    fprintf(stderr, "checking: %s\n", name);

    mailbox_reconstruct(name, 0, NULL); /* no changes allowed */

    mboxlist_entry_free(&mbentry);

    return 0;
}

int main(int argc, char **argv)
{
    char *alt_config = NULL;
    char pattern[2] = { '*', '\0' };
    const char *mailbox = NULL;
    int opt;

    /* keep this in alphabetical order */
    static const char short_options[] = "C:M:P:";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { "mailbox", required_argument, NULL, 'M' },
        { "partition", required_argument, NULL, 'P' },

        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'P':
            if(mailbox) {
                usage();
                exit(EX_USAGE);
            }
            check_part = optarg;
            break;

        case 'M':
            if(check_part) {
                usage();
                exit(EX_USAGE);
            }
            mailbox = optarg;
            break;

        default:
            usage();
            /* NOTREACHED */
        }
    }

    cyrus_init(alt_config, "chk_cyrus", 0, CONFIG_NEED_PARTITION_DATA);

    if(mailbox) {
        fprintf(stderr, "Examining mailbox: %s\n", mailbox);
        mboxlist_findone(NULL, mailbox, 1, NULL,
                         NULL, chkmbox, NULL);
    } else {
        fprintf(stderr, "Examining partition: %s\n",
                (check_part ? check_part : "ALL PARTITIONS"));

        /* build a list of mailboxes - we're using internal names here */
        mboxlist_findall(NULL, pattern, 1, NULL,
                         NULL, chkmbox, NULL);
    }

    cyrus_done();

    return 0;
}
