/* squat_dump.c -- SQUAT-based index dumping tool */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

/*
  This tool dumps out a SQUAT index in various ways.  It's useful
  for debugging.

  Currently hardcoded for SQUAT, doesn't use struct search_engine.
*/

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sysexits.h>
#include <string.h>

#include "assert.h"
#include "global.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "mboxlist.h"
#include "mailbox.h"
#include "mboxname.h"
#include "squat.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

extern char *optarg;
extern int optind;

static int usage(const char *name)
{
    fprintf(stderr,
            "usage: %s [-C <alt_config>] mailbox [...]\n",
            name);

    exit(EX_USAGE);
}

static const char *squat_strerror(int err)
{
    static char buf[64];

    switch (err) {
    case SQUAT_ERR_SYSERR:
        return strerror(errno);
    default:
        /* There are other error codes, but they only apply for searching,
           not index construction */
        snprintf(buf, sizeof(buf), "unknown squat error %d", err);
        return buf;
    }
}

static int dump_doc(void *closure __attribute__((unused)),
                    const SquatListDoc *doc)
{
    printf("DOC %s %llu\n", doc->doc_name, doc->size);
    return SQUAT_CALLBACK_CONTINUE;
}

/* This is called once for each mailbox we're told to dump. */
static int dump_one(char *name)
{
    struct mboxlist_entry *mbentry = NULL;
    struct mailbox *mailbox = NULL;
    int r;
    int fd = -1;
    SquatSearchIndex *index = NULL;
    char *fname = NULL;

    /* Skip remote mailboxes */
    r = mboxlist_lookup(name, &mbentry, NULL);
    if (r) {
        fprintf(stderr, "error opening looking up %s: %s\n",
                name, error_message(r));
        return 1;
    }

    if (mbentry->mbtype & MBTYPE_REMOTE) {
        mboxlist_entry_free(&mbentry);
        return 0;
    }

    mboxlist_entry_free(&mbentry);

    r = mailbox_open_irl(name, &mailbox);
    if (r) {
        fprintf(stderr, "error opening mailbox %s: %s\n",
                name, error_message(r));
        return 1;
    }

    fname = xstrdup(mailbox_meta_fname(mailbox, META_SQUAT));

    mailbox_close(&mailbox);

    fd = open(fname, O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "error opening file %s: %s\n",
                fname, error_message(errno));
        goto out;
    }

    index = squat_search_open(fd);
    if (index == NULL) {
        fprintf(stderr, "error opening index %s: %s\n",
                fname, squat_strerror(squat_get_last_error()));
        goto out;
    }

    printf("MAILBOX %s\n", name);

    r = squat_search_list_docs(index, dump_doc, NULL);
    if (r != SQUAT_OK) {
        fprintf(stderr, "error listing index %s: %s\n",
                fname, squat_strerror(r));
        goto out;
    }

out:
    if (fd >= 0) close(fd);
    if (index != NULL) squat_search_close(index);
    free(fname);
    return 0;
}

int main(int argc, char **argv)
{
    int opt;
    char *alt_config = NULL;
    int i;

    while ((opt = getopt(argc, argv, "C:")) != EOF) {
        switch (opt) {
        case 'C':               /* alt config file */
            alt_config = optarg;
            break;

        default:
            usage(argv[0]);
        }
    }

    cyrus_init(alt_config, "squat_dump", 0, CONFIG_NEED_PARTITION_DATA);

    if (optind == argc)
        usage(argv[0]);

    for (i = optind; i < argc; i++)
        dump_one(argv[i]);

    cyrus_done();

    return 0;
}
