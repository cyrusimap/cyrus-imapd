/* dav_reconstruct.c - (re)build DAV DB for a user */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>

#include <libical/ical.h>

#include "annotate.h"
#include "caldav_repair.h"
#include "global.h"
#include "http_dav.h"
#include "mailbox.h"
#include "message.h"
#include "message_guid.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "zoneinfo_db.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* current namespace */
static struct namespace recon_namespace;

/* config.c stuff */
const int config_need_data = 0;

/* forward declarations */
void usage(void) __attribute__((noreturn));
void shut_down(int code) __attribute__((noreturn));

static int code = 0;
static unsigned repair_flags = 0;

struct do_user_rock {
    const char *audit_tool;
};

static int do_user(const char *userid, void *rock)
{
    struct do_user_rock *urock = rock;

    printf("Reconstructing DAV DB for %s...\n", userid);

    if (dav_reconstruct_user(userid, urock->audit_tool, repair_flags))
        code = EX_DATAERR;

    return 0;
}

enum {
    OPT_REPAIR = 1000,
    OPT_REPAIR_UID_CONFLICTS,
    OPT_REALLY
};

int main(int argc, char **argv)
{
    int opt, r;
    char *alt_config = NULL;
    int allusers = 0;
    const char *audit_tool = NULL;
    bool really = 0;

    /* keep this in alphabetical order */
    static const char short_options[] = "C:A:a";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { "all", no_argument, NULL, 'a' },
        { "audit-tool", required_argument, NULL, 'A' },
        { "really", no_argument, NULL, OPT_REALLY },
        { "repair", no_argument, NULL, OPT_REPAIR },
        { "repair-uid-conflicts", no_argument, NULL, OPT_REPAIR_UID_CONFLICTS },
        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'a':
            allusers = 1;
            break;

        case 'A':
            audit_tool = optarg;
            break;

        case OPT_REPAIR:
            repair_flags |= DAV_REPAIR_ALL;
            break;

        case OPT_REPAIR_UID_CONFLICTS:
            repair_flags |= DAV_REPAIR_UID_CONFLICTS;
            break;

        case OPT_REALLY:
            /* --really only gates the repairs selected by --repair.  The
             * record rewrites mailbox_add_dav() does on its own -- assigning
             * a fresh createdmodseq, expunging superseded records -- happen
             * either way.  Those arguably belong behind --really too. */
            really = true;
            break;

        default:
            usage();
        }
    }

    if (geteuid() == 0) fatal("must run as the Cyrus user", EX_USAGE);

    if (really && !repair_flags) usage();

    /* the audit tool discards the rebuilt database, so a repair would leave
     * the mailboxes changed and dav.db stale */
    if (repair_flags && audit_tool) usage();

    if (really) repair_flags |= DAV_REPAIR_REALLY;

    cyrus_init(alt_config, "dav_reconstruct", 0, 0);
    global_sasl_init(1,0,NULL);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&recon_namespace, NAMESPACE_OPTION_ADMIN))) {
        xsyslog_ev(LOG_ERR, "dav.namespace.init.failed", lf_err("error", r));
        fatal(error_message(r), EX_CONFIG);
    }

    signals_set_shutdown(&shut_down);
    signals_add_handlers(0);
    sqldb_init();

    struct do_user_rock urock = { audit_tool };

    if (allusers) {
        mboxlist_alluser(do_user, &urock);
    }
    else if (optind == argc) {
         usage();
    }
    else {
        int i;
        for (i = optind; i < argc; i++)
            do_user(argv[i], &urock);
    }

    libcyrus_run_delayed();
    sqldb_done();
    cyrus_done();

    exit(code);
}


void usage(void)
{
    fprintf(stderr,
            "usage: dav_reconstruct [-C <alt_config>] [-A <audit tool>]\n"
            "                       [--repair] [--repair-uid-conflicts]"
            " [--really]\n"
            "                       [-a | userid...]\n");
    exit(EX_USAGE);
}

/*
 * Cleanly shut down and exit
 */
void shut_down(int code) __attribute__((noreturn));
void shut_down(int code)
{
    in_shutdown = 1;

    libcyrus_run_delayed();

    mboxlist_close();
    mboxlist_done();
    sqldb_done();
    exit(code);
}
