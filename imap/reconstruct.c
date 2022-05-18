/* reconstruct.c -- program to reconstruct a mailbox
 *
 * Copyright (c) 1994-2017 Carnegie Mellon University.  All rights reserved.
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
#include <fcntl.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <libgen.h>
#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "acl.h"
#include "assert.h"
#include "bsearch.h"
#include "crc32.h"
#include "hash.h"
#include "global.h"
#include "mailbox.h"
#include "map.h"
#include "message.h"
#include "message_guid.h"
#include "partlist.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "strarray.h"
#include "mboxname.h"
#include "mboxlist.h"
#include "quota.h"
#include "seen.h"
#include "util.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

extern int optind;
extern char *optarg;

hash_table unqid_table;

/* current namespace */
static struct namespace recon_namespace;

struct reconstruct_rock {
    strarray_t *discovered;
    hash_table visited;
};

/* Program name */
static const char *progname = NULL;

/* forward declarations */
static void do_mboxlist(void);
static int do_reconstruct_p(const mbentry_t *mbentry, void *rock);
static int do_reconstruct(struct findall_data *data, void *rock);
static void usage(void);

extern cyrus_acl_canonproc_t mboxlist_ensureOwnerRights;

static int reconstruct_flags = RECONSTRUCT_MAKE_CHANGES | RECONSTRUCT_DO_STAT;
static int setversion = 0;
static int updateuniqueids = 0;

int main(int argc, char **argv)
{
    int opt, i, r;
    int dousers = 0;
    int rflag = 0;
    int mflag = 0;
    int fflag = 0;
    int xflag = 0;
    struct buf buf = BUF_INITIALIZER;
    char *alt_config = NULL;
    char *start_part = NULL;
    struct reconstruct_rock rrock = { NULL, HASH_TABLE_INITIALIZER };

    progname = basename(argv[0]);

    construct_hash_table(&unqid_table, 2047, 1);

    while ((opt = getopt(argc, argv, "C:kp:rmfsxgGqRUMIoOnV:u")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'p':
            start_part = optarg;
            break;

        case 'r':
            rflag = 1;
            break;

        case 'u':
            dousers = 1;
            break;

        case 'm':
            mflag = 1;
            break;

        case 'n':
            reconstruct_flags &= ~RECONSTRUCT_MAKE_CHANGES;
            break;

        case 'g':
            fprintf(stderr, "reconstruct: deprecated option -g ignored\n");
            break;

        case 'G':
            reconstruct_flags |= RECONSTRUCT_ALWAYS_PARSE;
            break;

        case 'f':
            fflag = 1;
            break;

        case 'x':
            xflag = 1;
            break;

        case 'k':
            fprintf(stderr, "reconstruct: deprecated option -k ignored\n");
            break;

        case 's':
            reconstruct_flags &= ~RECONSTRUCT_DO_STAT;
            break;

        case 'q':
            reconstruct_flags |= RECONSTRUCT_QUIET;
            break;

        case 'R':
            reconstruct_flags |= RECONSTRUCT_GUID_REWRITE;
            break;

        case 'U':
            reconstruct_flags |= RECONSTRUCT_GUID_UNLINK;
            break;

        case 'o':
            reconstruct_flags |= RECONSTRUCT_IGNORE_ODDFILES;
            break;

        case 'O':
            reconstruct_flags |= RECONSTRUCT_REMOVE_ODDFILES;
            break;

        case 'M':
            reconstruct_flags |= RECONSTRUCT_PREFER_MBOXLIST;
            break;

        case 'I':
            updateuniqueids = 1;
            break;

        case 'V':
            if (!strcasecmp(optarg, "max"))
                setversion = MAILBOX_MINOR_VERSION;
            else
                setversion = atoi(optarg);
            break;

        default:
            usage();
        }
    }

    cyrus_init(alt_config, "reconstruct", 0, CONFIG_NEED_PARTITION_DATA);
    global_sasl_init(1,0,NULL);

    /* Set namespace -- force standard (internal) */
    if ((r = mboxname_init_namespace(&recon_namespace, 1)) != 0) {
        syslog(LOG_ERR, "%s", error_message(r));
        fatal(error_message(r), EX_CONFIG);
    }

    if (mflag) {
        if (rflag || fflag || optind != argc) {
            cyrus_done();
            usage();
        }
        do_mboxlist();
    }

    /* Deal with nonexistent mailboxes */
    if (start_part) {
        /* We were handed a mailbox that does not exist currently */
        if(optind == argc) {
            fprintf(stderr,
                    "When using -p, you must specify a mailbox to attempt to reconstruct.");
            exit(EX_USAGE);
        }

        /* do any of the mailboxes exist in mboxlist already? */
        /* Do they look like mailboxes? */
        for (i = optind; i < argc; i++) {
            if (strchr(argv[i],'%') || strchr(argv[i],'*')) {
                fprintf(stderr, "Using wildcards with -p is not supported.\n");
                exit(EX_USAGE);
            }

            /* Translate mailboxname */
            char *intname = mboxname_from_external(argv[i], &recon_namespace, NULL);

            /* Does it exist */
            do {
                r = mboxlist_lookup(intname, NULL, NULL);
            } while (r == IMAP_AGAIN);

            if (r != IMAP_MAILBOX_NONEXISTENT) {
                fprintf(stderr,
                        "Mailbox %s already exists.  Cannot specify -p.\n",
                        argv[i]);
                exit(EX_USAGE);
            }
            free(intname);
        }

        /* None of them exist.  Create them. */
        for (i = optind; i < argc; i++) {
            /* Translate mailboxname */
            char *intname = mboxname_from_external(argv[i], &recon_namespace, NULL);

            /* don't notify mailbox creation here */
            r = mboxlist_createmailboxlock(intname, 0, start_part, 1,
                                           NULL, NULL, 0, 0, !xflag, 0, NULL);
            if (r) {
                fprintf(stderr, "could not create %s\n", argv[i]);
            }

            free(intname);
        }
    }

    /* set up reconstruct rock */
    if (fflag) rrock.discovered = strarray_new();
    construct_hash_table(&rrock.visited, 2047, 1); /* XXX magic numbers */

    /* Normal Operation */
    if (optind == argc) {
        if (rflag || dousers) {
            fprintf(stderr, "please specify a mailbox to recurse from\n");
            cyrus_done();
            exit(EX_USAGE);
        }
        assert(!rflag);
        buf_setcstr(&buf, "*");
        mboxlist_findall(&recon_namespace, buf_cstring(&buf), 1, 0, 0,
                         do_reconstruct, &rrock);
    }

    for (i = optind; i < argc; i++) {
        if (dousers) {
            mboxlist_usermboxtree(argv[i], NULL, do_reconstruct_p, &rrock,
                                  MBOXTREE_TOMBSTONES|MBOXTREE_DELETED);
            continue;
        }
        char *domain = NULL;

        /* save domain */
        if (config_virtdomains) domain = strchr(argv[i], '@');

        buf_setcstr(&buf, argv[i]);

        /* reconstruct the first mailbox/pattern */
        mboxlist_findall(&recon_namespace, buf_cstring(&buf), 1, 0, 0, do_reconstruct, &rrock);

        if (rflag) {
            /* build a pattern for submailboxes */
            int atidx = buf_findchar(&buf, 0, '@');
            if (atidx >= 0)
                buf_truncate(&buf, atidx);
            buf_putc(&buf, recon_namespace.hier_sep);
            buf_putc(&buf, '*');

            /* append the domain */
            if (domain) buf_appendcstr(&buf, domain);

            /* reconstruct the submailboxes */
            mboxlist_findall(&recon_namespace, buf_cstring(&buf), 1, 0, 0, do_reconstruct, &rrock);
        }
    }

    /* examine our list to see if we discovered anything */
    while (rrock.discovered && rrock.discovered->count) {
        char *name = strarray_shift(rrock.discovered);
        int r = 0;

        /* create p (database only) and reconstruct it */
        /* partition is defined by the parent mailbox */
        /* don't notify mailbox creation here */
        r = mboxlist_createmailboxlock(name, 0, NULL, 1,
                                       NULL, NULL, 0, 0, !xflag, 0, NULL);
        if (r) {
            fprintf(stderr, "createmailbox %s: %s\n",
                    name, error_message(r));
        } else {
            mboxlist_findone(&recon_namespace, name, 1, 0, 0, do_reconstruct, &rrock);
        }
        /* may have added more things into our list */

        free(name);
    }

    if (rrock.discovered) strarray_free(rrock.discovered);
    free_hash_table(&rrock.visited, NULL);

    free_hash_table(&unqid_table, free);

    buf_free(&buf);

    partlist_local_done();

    cyrus_done();

    return 0;
}

static void usage(void)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n", progname);
    fprintf(stderr, "A tool to reconstruct mailboxes.\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "-C <config-file>   use <config-file> instead of config from imapd.conf");
    fprintf(stderr, "-p <partition>     use this indicated partition for search\n");
    fprintf(stderr, "-x                 do not import metadata, create new\n");
    fprintf(stderr, "-r                 recursively reconstruct\n");
    fprintf(stderr, "-f                 examine filesystem underneath the mailbox\n");
    fprintf(stderr, "-s                 don't stat underlying files\n");
    fprintf(stderr, "-q                 run quietly\n");
    fprintf(stderr, "-n                 do not make changes\n");
    fprintf(stderr, "-G                 force re-parsing (checks GUID correctness)\n");
    fprintf(stderr, "-R                 perform UID upgrade operation on GUID mismatched files\n");
    fprintf(stderr, "-U                 use this if there are corrupt message files in spool\n");
    fprintf(stderr, "                   WARNING: this option deletes corrupted message files permanently\n");
    fprintf(stderr, "-o                 ignore odd files in mailbox disk directories\n");
    fprintf(stderr, "-O                 delete odd files (unlike -o)\n");
    fprintf(stderr, "-M                 prefer mailboxes.db over cyrus.header\n");
    fprintf(stderr, "-V <version>       Change the cyrus.index minor version to the version specified\n");
    fprintf(stderr, "-u                 give usernames instead of mailbox prefixes\n");

    fprintf(stderr, "\n");

    exit(EX_USAGE);
}

/*
 *
 */
static int do_reconstruct_p(const mbentry_t *mbentry, void *rock)
{
    if ((mbentry->mbtype & (MBTYPE_DELETED|MBTYPE_INTERMEDIATE)))
        return 0;

    mboxlist_findone(&recon_namespace, mbentry->name, 1, 0, 0,
                     do_reconstruct, rock);

    return 0;
}

/*
 * mboxlist_findall() callback function to reconstruct a mailbox
 */
static int do_reconstruct(struct findall_data *data, void *rock)
{
    if (!data) return 0;
    struct reconstruct_rock *rrock = (struct reconstruct_rock *) rock;
    int r;
    char *other;
    struct mailbox *mailbox = NULL;
    char outpath[MAX_MAILBOX_PATH];
    const char *name = NULL;

    /* ignore intermediates */
    if ((data->mbentry->mbtype & MBTYPE_INTERMEDIATE))
        return 0;

    /* ignore partial matches */
    if (!data->is_exactmatch) return 0;

    signals_poll();

    name = mbname_intname(data->mbname);

    /* don't repeat */
    if (hash_lookup(name, &rrock->visited)) return 0;

    if (!setversion) {
        r = mailbox_reconstruct(name, reconstruct_flags);
        if (r) {
            com_err(name, r, "%s",
                    (r == IMAP_IOERROR) ? error_message(errno) : "Failed to reconstruct mailbox");
            return 0;
        }
    }

    r = mailbox_open_iwl(name, &mailbox);
    if (r) {
        com_err(name, r, "Failed to open after reconstruct");
        return 0;
    }

    /* Convert internal name to external */
    char *extname = mboxname_to_external(name, &recon_namespace, NULL);
    if (!(reconstruct_flags & RECONSTRUCT_QUIET))
        printf("%s\n", extname);

    if (mailbox->uniqueid) {
        other = hash_lookup(mailbox->uniqueid, &unqid_table);
        if (other) {
            mbentry_t *oldmbentry = NULL;
            /* check that the old one still exists! */
            r = mboxlist_lookup(other, &oldmbentry, NULL);
            if (!r && !strcmpsafe(oldmbentry->uniqueid, mailbox->uniqueid)) {
                /* uniqueid change required! */
                if (updateuniqueids) {
                    mailbox_make_uniqueid(mailbox);
                    syslog (LOG_ERR, "uniqueid clash with %s - changed %s (%s => %s)",
                            other, mailbox->name, oldmbentry->uniqueid, mailbox->uniqueid);
                }
                else {
                    syslog (LOG_ERR, "uniqueid clash with %s for %s (%s)",
                            other, mailbox->name, mailbox->uniqueid);
                }
            }
            mboxlist_entry_free(&oldmbentry);
        }

        hash_insert(mailbox->uniqueid, xstrdup(mailbox->name), &unqid_table);
    }
    else {
        /* We should only get here for -V (setversion) or -n (no changes)
         * modes.  Otherwise, mailbox_reconstruct() should have dealt with it
         * already.
         * It would be nice if -V would also ensure there's a uniqueid, but
         * that change would require a refactor that's already on 3.6 but too
         * intrusive to backport.
         */
        printf("%s has no uniqueid, needs real reconstruct\n", extname);
    }

    strncpy(outpath, mailbox_meta_fname(mailbox, META_HEADER), MAX_MAILBOX_NAME);

    if (setversion && setversion != mailbox->i.minor_version) {
        int oldversion = mailbox->i.minor_version;
        /* need to re-set the version! */
        int r = mailbox_setversion(mailbox, setversion);
        if (r) {
            printf("FAILED TO REPACK %s with new version %s\n", extname, error_message(r));
        }
        else {
            printf("Converted %s version %d to %d\n", extname, oldversion, setversion);
        }
    }
    mailbox_close(&mailbox);
    free(extname);

    if (rrock->discovered) {
        char fnamebuf[MAX_MAILBOX_PATH];
        char *ptr;
        DIR *dirp;
        struct dirent *dirent;
        struct stat sbuf;

        ptr = strstr(outpath, "cyrus.header");
        if (!ptr) return 0;
        *ptr = 0;

        r = chdir(outpath);
        if (r) return 0;

        /* we recurse down this directory to see if there's any mailboxes
           under this not in the mailboxes database */
        dirp = opendir(".");
        if (!dirp) return 0;

        while ((dirent = readdir(dirp)) != NULL) {
            /* mailbox directories never have a dot in them */
            if (strchr(dirent->d_name, '.')) continue;
            if (stat(dirent->d_name, &sbuf) < 0) continue;
            if (!S_ISDIR(sbuf.st_mode)) continue;

            /* ok, we found a directory that doesn't have a dot in it;
               is there a cyrus.header file? */
            snprintf(fnamebuf, MAX_MAILBOX_PATH, "%s%s",
                     dirent->d_name, FNAME_HEADER);
            if (stat(fnamebuf, &sbuf) < 0) continue;

            /* ok, we have a real mailbox directory */
            char buf[MAX_MAILBOX_NAME];
            snprintf(buf, MAX_MAILBOX_NAME, "%s.%s",
                     name, dirent->d_name);

            /* does fnamebuf exist as a mailbox in mboxlist? */
            do {
                r = mboxlist_lookup(buf, NULL, NULL);
            } while (r == IMAP_AGAIN);
            if (!r) continue; /* mailbox exists; it'll be reconstructed
                                 with a -r */

            if (r != IMAP_MAILBOX_NONEXISTENT) break; /* erg? */
            else r = 0; /* reset error condition */

            printf("discovered %s\n", buf);
            strarray_append(rrock->discovered, buf);
        }
        closedir(dirp);
    }

    /* mark it as visited
     * we don't care about the value, it just needs to be a non-NULL pointer
     */
    hash_insert(name, &rrock, &rrock->visited);

    return 0;
}

/*
 * Reconstruct the mailboxes list.
 */
static void do_mboxlist(void)
{
    fprintf(stderr, "reconstructing mailboxes.db currently not supported\n");
    exit(EX_USAGE);
}
