/* cyr_ls.c -- list the contents of a mailbox
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <pwd.h>
#include <grp.h>

#include "bsearch.h"
#include "util.h"
#include "global.h"
#include "mailbox.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "user.h"

/* generated headers are not necessarily in current directory */
#include "imap/imap_err.h"

extern int optind;
extern char *optarg;

/* current namespace */
static struct namespace cyr_ls_namespace;

static int usage(const char *error)
{
    fprintf(stderr,"usage: cyr_ls [-C <alt_config>] [-m] [-i] [-e] [-l] [-R] [-1] [mailbox name]\n");
    fprintf(stderr, "\n");
    fprintf(stderr,"\t-m\tlist the contents of the metadata directory (if different from the data directory)\n");
    fprintf(stderr,"\t-i\tprint ID of each item (requires opening mailbox)\n");
    fprintf(stderr,"\t-e\tcolorize expunged messages (requires opening mailbox)\n");
    fprintf(stderr,"\t-l\tlong listing format\n");
    fprintf(stderr,"\t-R\tlist submailboxes recursively\n");
    fprintf(stderr,"\t-1\tlist one file per line\n");
    if (error) {
        fprintf(stderr,"\n");
        fprintf(stderr,"ERROR: %s", error);
    }
    exit(-1);
}

#define SECONDS_PER_YEAR 31536000  /* 365 * 24 * 60 * 60 */

#define ANSI_COLOR_RESET   "\x1b[0m"
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"

#define ANSI_COLOR_GRAY    "\x1b[90m"
#define ANSI_COLOR_BR_BLUE "\x1b[94m"

static void long_list(const char *path, const char *name,
                      const char *id, const char *color)
{
    struct stat sbuf;
    struct group *grp;
    struct passwd *pwd;
    time_t now = time(0);
    const char *datefmt = "%b %d %k:%M";
    char datestr[13];

    memset(&sbuf, 0, sizeof(struct stat));
    if (stat(path, &sbuf) != 0) color = ANSI_COLOR_RED;

    pwd = getpwuid(sbuf.st_uid);
    grp = getgrgid(sbuf.st_gid);

    if (now - sbuf.st_ctime > SECONDS_PER_YEAR) datefmt = "%b %d  %Y";

    strftime(datestr, 13, datefmt, localtime(&(sbuf.st_ctime)));

    printf("\n");
    if (id) printf("%-40s ", id);
    printf("%c%c%c%c%c%c%c%c%c%c %lu %-8s %-8s % 10ld %s %s%s%s",
           S_ISDIR(sbuf.st_mode) ? 'd' : '-',
           (sbuf.st_mode & S_IRUSR) ? 'r' : '-',
           (sbuf.st_mode & S_IWUSR) ? 'w' : '-',
           (sbuf.st_mode & S_IXUSR) ? 'x' : '-',
           (sbuf.st_mode & S_IRGRP) ? 'r' : '-',
           (sbuf.st_mode & S_IWGRP) ? 'w' : '-',
           (sbuf.st_mode & S_IXGRP) ? 'x' : '-',
           (sbuf.st_mode & S_IROTH) ? 'r' : '-',
           (sbuf.st_mode & S_IWOTH) ? 'w' : '-',
           (sbuf.st_mode & S_IXOTH) ? 'x' : '-',
           sbuf.st_nlink, pwd->pw_name, grp->gr_name,
           sbuf.st_size, datestr,
           color, name ? name : path, *color ? ANSI_COLOR_RESET : "");
}

struct list_opts {
    int recurse;
    int ids;
    int expunged;
    int longlist;
    int meta;
    int columns;
};

struct list_rock {
    struct list_opts *opts;
    int count;
    strarray_t *children;
};

static int list_cb(struct findall_data *data, void *rock)
{
    struct list_rock *lrock = (struct list_rock *) rock;
    int r = 0;

    /* don't want partial matches */
    if (!data || !data->is_exactmatch) return 0;

    const char *child_name = strarray_nth(mbname_boxes(data->mbname), -1);
    const char *color = ANSI_COLOR_BR_BLUE;
    const char *path;

    if (lrock->opts->meta) {
        path = mboxname_metapath(data->mbentry->partition,
                                 data->mbentry->name,
                                 data->mbentry->uniqueid, 0, 0);
    }
    else {
        path = mboxname_datapath(data->mbentry->partition,
                                 data->mbentry->name,
                                 data->mbentry->uniqueid, 0);
    }

    if (mbtype_isa(data->mbentry->mbtype) != MBTYPE_EMAIL) {
        color = ANSI_COLOR_MAGENTA;
    }

    if (lrock->opts->longlist) {
        long_list(path, child_name,
                  lrock->opts->ids ? data->mbentry->uniqueid : NULL, color);
    }
    else {
        struct stat sbuf;

        if (stat(path, &sbuf) != 0) color = ANSI_COLOR_RED;

        printf("%c", !(lrock->count++ % lrock->opts->columns) ? '\n' : '\t');
        if (lrock->opts->ids) printf("%-40s ", data->mbentry->uniqueid);
        printf("%s%s%s", color, child_name, *color ? ANSI_COLOR_RESET : "");
    }

    if (lrock->children) strarray_append(lrock->children, data->extname);

    return r;
}

static void do_list(mbname_t *mbname, struct list_opts *opts)
{
    const char *path = NULL;
    mbentry_t *mbentry = NULL;
    struct list_rock lrock = { opts, 0, NULL };
    strarray_t names = STRARRAY_INITIALIZER;
    int r, i;

    r = mboxlist_lookup_allow_all(mbname_intname(mbname), &mbentry, NULL);
    if (!r) {
        printf("\n%s:\n", mbname_extname(mbname, &cyr_ls_namespace, "cyrus"));

        if (mbentry->mbtype & MBTYPE_RESERVE) r = IMAP_MAILBOX_NONEXISTENT;
        else if (mbentry->mbtype & MBTYPE_DELETED) r = IMAP_MAILBOX_NONEXISTENT;
        else if (mbentry->mbtype & MBTYPE_REMOTE) {
            printf("Non-local mailbox: %s!%s\n",
                   mbentry->server, mbentry->partition);
        }
        else if (opts->meta) {
            path = mboxname_metapath(mbentry->partition,
                                     mbentry->name, mbentry->uniqueid, 0, 0);
        }
        else {
            path = mboxname_datapath(mbentry->partition,
                                     mbentry->name, mbentry->uniqueid, 0);
        }
    }
    else {
        fprintf(stderr, "Invalid mailbox name\n");
    }

    /* Scan the directory */
    if (path) {
        struct mailbox *mailbox = NULL;
        DIR *dirp;

        if (!chdir(path) && (dirp = opendir("."))) {
            struct dirent *dirent;

            while ((dirent = readdir(dirp))) {
                if (dirent->d_name[0] == '.') continue;

                strarray_append(&names, dirent->d_name);
            }
            closedir(dirp);
        }

        strarray_sort(&names, cmpstringp_raw);

        if (opts->ids || opts->expunged) {
            mailbox_open_irl(mbentry->name, &mailbox);
        }

        for (i = 0; i < strarray_size(&names); i++) {
            const char *name = strarray_nth(&names, i);
            const char *id = opts->ids ? "" : NULL;
            const char *color = "";
            struct index_record record;
            uint32_t uid;

            if (mailbox &&
                !mailbox_parse_datafilename(name, &uid) &&
                !mailbox_find_index_record(mailbox, uid, &record)) {

                if (opts->ids) id = message_guid_encode(&record.guid);

                if (record.internal_flags & FLAG_INTERNAL_EXPUNGED)
                    color = ANSI_COLOR_GRAY;
            }

            if (opts->longlist) {
                long_list(name, NULL, id, color);
            }
            else {
                printf("%c",
                       !(lrock.count++ % lrock.opts->columns) ? '\n' : '\t');
                if (id) printf("%-40s ", id);
                printf("%s%s%s", color, name, *color ? ANSI_COLOR_RESET : "");
            }
        }
        mailbox_close(&mailbox);
        strarray_fini(&names);
    }
    mboxlist_entry_free(&mbentry);

    if (!r) {
        /* List children */
        if (opts->recurse) lrock.children = &names;

        mbname_push_boxes(mbname, "%");
        mboxlist_findall(&cyr_ls_namespace,
                         mbname_extname(mbname, &cyr_ls_namespace, "cyrus"),
                         1, 0, 0, &list_cb, &lrock);
        printf("\n");

        if (opts->recurse) {
            for (i = 0; i < strarray_size(lrock.children); i++) {
                mbname_t *mbname =
                    mbname_from_extname(strarray_nth(lrock.children, i),
                                        &cyr_ls_namespace, NULL);
                do_list(mbname, opts);
                mbname_free(&mbname);
            }
            strarray_fini(&names);
        }
    }
}

int main(int argc, char **argv)
{
    int r;
    int opt;              /* getopt() returns an int */
    char *alt_config = NULL;

    // capture options
    struct list_opts opts = { 0, 0, 0, 0, 0, 4 /* default to 4 columns */ };

    while ((opt = getopt(argc, argv, "C:mielR1")) != EOF) {
        switch(opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'R':
            opts.recurse = 1;
            break;

        case 'i':
            opts.ids = 1;
            if (opts.columns > 1) opts.columns = 2;
            break;

        case 'e':
            opts.expunged = 1;
            break;

        case 'l':
            opts.longlist = 1;
            break;

        case 'm':
            opts.meta = 1;
            break;

        case '1':
            opts.columns = 1;
            break;

        default:
            usage(NULL);
        }
    }

    cyrus_init(alt_config, "cyr_ls", 0, 0);


    r = mboxname_init_namespace(&cyr_ls_namespace, 1);
    if (r) {
        fatal(error_message(r), -1);
    }

    /* Translate mailboxname */
    const char *path = (optind == argc) ? "." : argv[optind];
    mbname_t *mbname = NULL;

    mbname = mbname_from_path(path, &cyr_ls_namespace);

    do_list(mbname, &opts);

    mbname_free(&mbname);

    cyrus_done();

    exit(0);
}
