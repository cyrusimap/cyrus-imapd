/* chk_cyrus.c - cyrus mailstore consistency checker */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <errno.h>
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

#include "audit.h"
#include "index.h"
#include "global.h"
#include "mboxlist.h"
#include "mailbox.h"
#include "map.h"
#include "xmalloc.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

/* long-only options; values above any short option character */
enum {
    OPT_USERLIST = 256,
    OPT_SKIPUSER,
    OPT_PRUNE,
};

static void usage(void)
{
    fprintf(stderr, "chk_cyrus [-C <altconfig>] partition\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Audit mode (nothing below changes behaviour unless"
                    " --level is given):\n");
    fprintf(stderr, "  -l, --level N       0-4; enables audit mode\n");
    fprintf(stderr, "                        0: mailboxes.db keyspace only,"
                    " no disk access\n");
    fprintf(stderr, "                        1: also db entries vs UUID dirs"
                    " on disk\n");
    fprintf(stderr, "                        2: also index record vs data"
                    " file exists\n");
    fprintf(stderr, "                        3: also size match\n");
    fprintf(stderr, "                        4: also GUID match\n");
    fprintf(stderr, "  -j, --json          JSON-lines output instead of"
                    " text\n");
    fprintf(stderr, "  -u, --user USERID   restrict the run to one user\n");
    fprintf(stderr, "      --userlist FILE usernames expected on this"
                    " server\n");
    fprintf(stderr, "      --skip-user U   exclude a user; repeatable\n");
    fprintf(stderr, "  -d, --delete        remove locally-decidable"
                    " orphans\n");
    fprintf(stderr, "  -f, --fix           repair locally-decidable"
                    " damage\n");
    fprintf(stderr, "  -y, --really        actually act; without it -d/-f"
                    " only report\n");
    fprintf(stderr, "      --prune-tombstones DAYS\n");
    fprintf(stderr, "                      prune tombstones and history older"
                    " than DAYS\n");
    fprintf(stderr, "                        (no default; pruning is off"
                    " unless given)\n");
    exit(-1);
}

/* Read a newline-separated list of usernames, skipping blank lines. */
static strarray_t *read_userlist(const char *fname)
{
    strarray_t *list = strarray_new();
    char line[MAX_MAILBOX_NAME + 2];
    FILE *f = fopen(fname, "r");

    if (!f) {
        fprintf(stderr, "can't open userlist %s: %s\n",
                fname, strerror(errno));
        exit(EX_NOINPUT);
    }

    while (fgets(line, sizeof(line), f)) {
        char *p = line + strlen(line);
        while (p > line && (p[-1] == '\n' || p[-1] == '\r')) *--p = '\0';
        if (*line) strarray_append(list, line);
    }

    fclose(f);

    return list;
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
    struct audit_config audit_config = AUDIT_CONFIG_INITIALIZER;
    int do_audit = 0;
    int opt;

    /* keep this in alphabetical order */
    static const char short_options[] = "C:M:P:dfjl:u:y";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { "mailbox", required_argument, NULL, 'M' },
        { "partition", required_argument, NULL, 'P' },
        { "delete", no_argument, NULL, 'd' },
        { "fix", no_argument, NULL, 'f' },
        { "json", no_argument, NULL, 'j' },
        { "level", required_argument, NULL, 'l' },
        { "user", required_argument, NULL, 'u' },
        { "really", no_argument, NULL, 'y' },
        { "userlist", required_argument, NULL, OPT_USERLIST },
        { "skip-user", required_argument, NULL, OPT_SKIPUSER },
        { "prune-tombstones", required_argument, NULL, OPT_PRUNE },

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

        case 'l':
            audit_config.level = atoi(optarg);
            do_audit = 1;
            break;

        case 'j':
            audit_config.json = 1;
            break;

        case 'd':
            audit_config.do_delete = 1;
            break;

        case 'f':
            audit_config.do_fix = 1;
            break;

        case 'y':
            audit_config.really = 1;
            break;

        case 'u':
            audit_config.userid = optarg;
            break;

        case OPT_USERLIST:
            audit_config.userlist = read_userlist(optarg);
            break;

        case OPT_SKIPUSER:
            if (!audit_config.skipusers)
                audit_config.skipusers = strarray_new();
            strarray_append(audit_config.skipusers, optarg);
            break;

        case OPT_PRUNE:
            audit_config.prune_days = atoi(optarg);
            break;

        default:
            usage();
            /* NOTREACHED */
        }
    }

    if (do_audit) {
        if (audit_config.level < 0 || audit_config.level > 4) {
            fprintf(stderr, "--level must be between 0 and 4\n");
            usage();
        }
        if (audit_config.do_delete && audit_config.do_fix) {
            fprintf(stderr, "--delete and --fix are mutually exclusive\n");
            usage();
        }
        if (audit_config.really &&
            !audit_config.do_delete && !audit_config.do_fix) {
            fprintf(stderr, "--really requires --delete or --fix\n");
            usage();
        }
        /* Levels 2-4 are message and meta damage.  There is no local
         * source to repair from, and where a local resolution does exist
         * reconstruct already owns it, so acting there is never right. */
        if (audit_config.level >= 2 &&
            (audit_config.do_delete || audit_config.do_fix)) {
            fprintf(stderr, "--delete and --fix are only meaningful at"
                            " --level 0 or 1\n");
            usage();
        }
        if (audit_config.prune_days < 0) {
            fprintf(stderr, "--prune-tombstones must not be negative\n");
            usage();
        }
    }
    else if (audit_config.json || audit_config.do_delete ||
             audit_config.do_fix || audit_config.really ||
             audit_config.userlist || audit_config.skipusers ||
             audit_config.userid || audit_config.prune_days) {
        fprintf(stderr, "audit options require --level\n");
        usage();
    }

    cyrus_init(alt_config, "chk_cyrus", 0, CONFIG_NEED_PARTITION_DATA);

    if (do_audit) {
        struct audit_state *state;
        int r;

        audit_config.partition = check_part;

        /* jmapids come from createdmodseq, and without conversations the
         * per-user counter is never consulted, so every mailbox is created
         * with modseq 1 and the same jmapid.  The J keyspace is degenerate
         * there and JMAP unusable, so there is nothing worth checking. */
        audit_config.check_jmapids = config_getswitch(IMAPOPT_CONVERSATIONS);

        state = audit_begin(&audit_config);
        r = audit_run(state);
        audit_done(&state);

        if (audit_config.userlist) strarray_free(audit_config.userlist);
        if (audit_config.skipusers) strarray_free(audit_config.skipusers);

        cyrus_done();

        return r ? EX_SOFTWARE : 0;
    }

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
