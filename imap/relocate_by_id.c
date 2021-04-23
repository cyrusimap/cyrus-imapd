/* relocate_by_id.c -- program to relocate a mailbox trees
 *
 * Copyright (c) 1994-2019 Carnegie Mellon University.  All rights reserved.
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
#include <errno.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "dav_db.h"
#include "dav_util.h"
#include "global.h"
#include "ical_support.h"
#include "ptrarray.h"
#include "mboxkey.h"
#include "mboxlist.h"
#include "mboxname.h"
#include "seen.h"
#ifdef WITH_DAV
#include "sqldb.h"
#endif
#include "util.h"
#include "user.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

extern int optind;
extern char *optarg;

/* current namespace */
static struct namespace reloc_namespace;

/* Program name */
static const char *progname = NULL;

/* forward declarations */
static int find_p(const mbentry_t *mbentry, void *rock);
static void get_searchparts(const char *key, const char *val, void *rock);
static int relocate(const char *old, const char *new);
static void usage(void);

static int quiet = 0;
static int nochanges = 0;

struct search_rock {
    const char *userid;
    const char *userpath;
    strarray_t *oldpaths;
    strarray_t *newpaths;
};

int main(int argc, char **argv)
{
    int opt, i, r;
    int dousers = 0;
    struct buf buf = BUF_INITIALIZER;
    char *alt_config = NULL;
    mbentry_t *mbentry;

    progname = basename(argv[0]);

    while ((opt = getopt(argc, argv, "C:qnu")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'u':
            dousers = 1;
            break;

        case 'n':
            nochanges = 1;
            break;

        case 'q':
            quiet = 1;
            break;

        default:
            usage();
        }
    }

    cyrus_init(alt_config, "relocate_by_id", 0, CONFIG_NEED_PARTITION_DATA);
    global_sasl_init(1, 0, NULL);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&reloc_namespace, 1)) != 0) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EX_CONFIG);
    }

#ifdef WITH_DAV
    sqldb_init();

#ifdef HAVE_ICAL
    /* Initialize libical */
    ical_support_init();
#endif
#endif

    /* Normal Operation */
    if (optind == argc) {
        fprintf(stderr, "please specify a mailbox to recurse from\n");
        cyrus_done();
        exit(EX_USAGE);
    }

    for (i = optind; i < argc; i++) {
        ptrarray_t *mboxlist = ptrarray_new();
        int flags =
            MBOXTREE_TOMBSTONES | MBOXTREE_DELETED | MBOXTREE_INTERMEDIATES;

        /* Make a list of all mailboxes in tree */
        if (dousers)
            r = mboxlist_usermboxtree(argv[i], NULL, find_p, mboxlist, flags);
        else
            r = mboxlist_mboxtree(argv[i], find_p, mboxlist, flags);

        /* Process each mailbox in reverse order (children first) */
        struct buf part_buf = BUF_INITIALIZER;
        while ((mbentry = ptrarray_pop(mboxlist))) {
            const char *partition = mbentry->partition;
            const char *uniqueid = mbentry->uniqueid;
            const char *name = mbentry->name;
            const char *path = NULL;
            char *userid = NULL;
            strarray_t *oldpaths = strarray_new();
            strarray_t *newpaths = strarray_new();
            strarray_t *subs = NULL;
            int j, metafile;
            char *(*datapath[])(const char *, const char *,
                                const char *, unsigned long) =
                { &mboxname_datapath, &mboxname_archivepath, NULL };

            if (r) {
                mboxlist_entry_free(&mbentry);
                continue;
            }

            /* If we're missing a partition, use the partition of child */
            if (!partition || !*partition) partition = buf_cstring(&part_buf);
            else buf_setcstr(&part_buf, partition);

            /* Add data & archive paths */
            for (j = 0; datapath[j]; j++) {
                path = datapath[j](partition, name, NULL, 0);
                if (!path || strarray_find(oldpaths, path, 0) >= 0) continue;

                strarray_append(oldpaths, path);
                strarray_append(newpaths,
                                datapath[j](partition, name, uniqueid, 0));
            }

            /* Add metadata paths */
            for (metafile = 0; metafile <= META_ARCHIVECACHE; metafile++) {
                path = mboxname_metapath(partition, name, NULL, metafile, 0);
                if (!path || strarray_find(oldpaths, path, 0) >= 0) continue;

                strarray_append(oldpaths, path);
                strarray_append(newpaths,
                                mboxname_metapath(partition, name,
                                                  uniqueid, metafile, 0));
            }

            if (mboxname_isusermailbox(mbentry->name, 1)) {
                /* User INBOX */
                char userpath[MAX_MAILBOX_PATH+1];
                const char *usermeta[] = { FNAME_SUBSSUFFIX,
                                           FNAME_SEENSUFFIX,
                                           FNAME_CONVERSATIONS_SUFFIX,
                                           FNAME_COUNTERSSUFFIX,
                                           FNAME_MBOXKEYSUFFIX,
                                           FNAME_DAVSUFFIX,
                                           FNAME_XAPIANSUFFIX,
                                           NULL };

                userid = mboxname_to_userid(mbentry->name);

                /* Get user subdir */
                mboxname_id_hash(userpath, MAX_MAILBOX_PATH,
                                 NULL, mbentry->uniqueid);

                /* Add user metadata paths */
                for (j = 0; usermeta[j]; j++) {
                    char *mpath = user_hash_meta(userid, usermeta[j]);

                    if (mpath) {
                        strarray_appendm(oldpaths, mpath);

                        buf_setcstr(&buf, config_dir);
                        buf_printf(&buf, "%s%s/%s.db",
                                   FNAME_USERDIR, userpath, usermeta[j]);
                        strarray_append(newpaths, buf_cstring(&buf));
                    }
                }

                /* Add sieve path */
                path = user_sieve_path(userid);
                if (*path) {
                    strarray_append(oldpaths, path);

                    buf_setcstr(&buf, config_getstring(IMAPOPT_SIEVEDIR));
                    buf_printf(&buf, "/%s", userpath);
                    strarray_append(newpaths, buf_cstring(&buf));
                }

                /* Add xapian tier paths */
                struct search_rock rock =
                    { argv[i], userpath, oldpaths, newpaths };
                config_foreachoverflowstring(get_searchparts, &rock);
            }

            char *extname =
                mboxname_to_external(mbentry->name, &reloc_namespace, NULL);

            if (!quiet) printf("\nRelocating: %s\n", extname);

            struct mboxlock *namelock = NULL;
            if (!nochanges) {
                r = mboxname_lock(mbentry->name, &namelock, LOCK_EXCLUSIVE);
                if (r) {
                    fprintf(stderr,
                            "Failed to create namelock for %s: %s\n",
                            extname, error_message(r));
                    mboxlist_entry_free(&mbentry);
                    goto cleanup;
                }
            }

            /* Relocate our list of paths */
            for (j = 0; j < strarray_size(oldpaths); j++) {
                r = relocate(strarray_nth(oldpaths, j),
                             strarray_nth(newpaths, j));
                if (r) break;
            }
            if (r) {
                /* Something failed - move everything back */
                for (--j; j >= 0; j--) {
                    r = relocate(strarray_nth(newpaths, j),
                                 strarray_nth(oldpaths, j));
                }
                if (namelock) mboxname_release(&namelock);
            }
            else if (!nochanges) {
                /* Rewrite mbentry */
                mbentry->mbtype &= ~MBTYPE_LEGACY_DIRS;
                r = mboxlist_update(mbentry, 1 /*localonly*/);
                if (namelock) mboxname_release(&namelock);

                if (r) {
                    fprintf(stderr,
                            "Failed to rewrite mailboxes.db entry for %s: %s\n",
                            extname, error_message(r));
                }
                else {
                    /* Rewrite mailbox header */
                    struct mailbox *mailbox = NULL;

                    r = mailbox_open_iwl(mbentry->name, &mailbox);
                    if (!r) {
                        mailbox->mbtype = mbentry->mbtype;
                        mailbox->header_dirty = 1;
                        mailbox_close(&mailbox);
                    }
                    if (r) {
                        fprintf(stderr,
                                "Failed to rewrite cyrus.header for %s: %s\n",
                                extname, error_message(r));
                    }
                    else if (userid) {
#ifdef WITH_DAV
                        /* Rewrite dav.db */
                        r = dav_reconstruct_user(userid, NULL);
                        if (r) {
                            fprintf(stderr,
                                    "Failed to rewrite dav.db for %s: %s\n",
                                    userid, error_message(r));
                        }
#endif
                    }
                }
            }

          cleanup:
            mboxlist_entry_free(&mbentry);
            strarray_free(oldpaths);
            strarray_free(newpaths);
            strarray_free(subs);
            free(extname);
            free(userid);
        }
        ptrarray_free(mboxlist);
        buf_free(&part_buf);
    }

    buf_free(&buf);

    sqldb_done();
    cyrus_done();

    return 0;
}

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n", progname);
    fprintf(stderr, "A tool to relocate mailbox trees by their ids.\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "-C <config-file>   use <config-file> instead of config from imapd.conf\n");
    fprintf(stderr, "-q                 run quietly\n");
    fprintf(stderr, "-n                 do not make changes\n");
    fprintf(stderr, "-u                 give usernames instead of mailbox prefixes\n");

    fprintf(stderr, "\n");

    exit(EX_USAGE);
}

/*
 * Append mailboxes needing relocation to our array */
static int find_p(const mbentry_t *mbentry, void *rock)
{
    ptrarray_t *mboxlist = (ptrarray_t *) rock;

    if (mbentry->mbtype & MBTYPE_DELETED) {
        /* skip tombstones */
        return 0;
    }

    if (mbentry->mbtype & MBTYPE_LEGACY_DIRS) {
        mbentry_t *mbentry_copy = NULL;

        if (mbentry->mbtype & MBTYPE_INTERMEDIATE) {
            char *extname =
                mboxname_to_external(mbentry->name, &reloc_namespace, NULL);
            int r = 0;

            if (!quiet) printf("\nPromoting intermediary: %s\n", extname);

            if (!nochanges) {
                r = mboxlist_promote_intermediary(mbentry->name);
                if (r) {
                    fprintf(stderr,
                            "\tFailed to promote intermediary %s: %s\n",
                            extname, error_message(r));
                }
                else {
                    r = mboxlist_lookup(mbentry->name, &mbentry_copy, NULL);
                }
            }
            free(extname);

            if (r) return r;
        }
        else {
            mbentry_copy = mboxlist_entry_copy(mbentry);
        }

        ptrarray_push(mboxlist, mbentry_copy);
    }

    return 0;
}

static int relocate(const char *old, const char *new)
{
    struct stat sbuf;
    int r = stat(old, &sbuf);

    if (r) {
        switch (errno) {
        case ENOENT:
        case ENOTDIR:
            return 0;

        default:
            fprintf(stderr, "\tFailed to access %s: %m\n", old);
            return r;
        }
    }

    if (!quiet) printf("\tRenaming: %s\t -> %s\n", old, new);

    if (!nochanges) {
        r = rename(old, new);
        if (r && errno == ENOENT) {
            cyrus_mkdir(new, 0755);
            r = rename(old, new);
        }

        if (r) fprintf(stderr, "\tFailed to rename %s\t -> %s: %m\n", old, new);
    }

    return r;
}

/*
 * config_foreachoverflowstring() callback function to find searchpartition-
 * options and add user directorys to be relocated
 */
static void get_searchparts(const char *key, const char *val, void *rock)
{
    struct search_rock *srock = (struct search_rock *) rock;
    char *basedir;

    if (!strstr(key, "searchpartition-")) return;

    basedir = user_hash_xapian(srock->userid, val);
    if (basedir) {
        struct buf buf = BUF_INITIALIZER;

        buf_initm(&buf, basedir, strlen(basedir));
        buf_appendcstr(&buf, XAPIAN_DIRNAME);
        strarray_appendm(srock->oldpaths, buf_release(&buf));

        buf_setcstr(&buf, val);
        buf_printf(&buf, FNAME_USERDIR "%s" XAPIAN_DIRNAME, srock->userpath);
        strarray_appendm(srock->newpaths, buf_release(&buf));
    }
}
