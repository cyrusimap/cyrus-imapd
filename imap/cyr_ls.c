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
    fprintf(stderr,"usage: cyr_ls [-C <alt_config>] [-p] [-m] [-i] [-l] [-R] [-1] [mailbox name]\n");
    fprintf(stderr, "\n");
    fprintf(stderr,"\t-p\targument is a UNIX path, not mailbox\n");
    fprintf(stderr,"\t-7\tmailbox argument is in modified UTF7 rather than UTF8\n");
    fprintf(stderr,"\t-m\tlist the contents of the metadata directory (if different from the data directory)\n");
    fprintf(stderr,"\t-i\tprint ID of each mailbox\n");
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

#define SPECIALS           " !\"#$&'()*,;<>?[\\]^`{|}~"

static int print_name(const char *name, int utf8)
{
    char *utf8name = NULL;

    if (utf8) {
        charset_t imaputf7 = charset_lookupname("imap-mailbox-name");
        utf8name = charset_to_utf8(name, strlen(name), imaputf7, ENCODING_NONE);
        name = utf8name;
    }

    size_t n = strcspn(name, SPECIALS);

    if (n == strlen(name)) {
        /* No specials */
        n = printf(" %s", name);
    }
    else if (strchr(name + n, '\'')) {
        if (strchr(name + n, '"')) {
            /* Need to escape single quote */
            putchar('\'');

            for (n = 0; *name; name++, n++) {
                if (*name == '\'') printf("\\'");
                else putchar(*name);
            }

            putchar('\'');

            n += 2;
        }
        else {
            /* Use double quotes */
            n = printf("\"%s\"", name);
        }
    }
    else {
        /* Use single quotes */
        n = printf("'%s'", name);
    }

    free(utf8name);

    return n;
}

static void long_list(struct stat *statp)
{
    struct group *grp;
    struct passwd *pwd;
    time_t now = time(0);
    const char *datefmt = "%b %d %k:%M";
    char datestr[13];

    pwd = getpwuid(statp->st_uid);
    grp = getgrgid(statp->st_gid);

    if (now - statp->st_ctime > SECONDS_PER_YEAR) datefmt = "%b %d  %Y";

    strftime(datestr, 13, datefmt, localtime(&(statp->st_ctime)));

    printf("%c%c%c%c%c%c%c%c%c%c %lu %-8s %-8s % 10ld %s ",
           S_ISDIR(statp->st_mode) ? 'd' : '-',
           (statp->st_mode & S_IRUSR) ? 'r' : '-',
           (statp->st_mode & S_IWUSR) ? 'w' : '-',
           (statp->st_mode & S_IXUSR) ? 'x' : '-',
           (statp->st_mode & S_IRGRP) ? 'r' : '-',
           (statp->st_mode & S_IWGRP) ? 'w' : '-',
           (statp->st_mode & S_IXGRP) ? 'x' : '-',
           (statp->st_mode & S_IROTH) ? 'r' : '-',
           (statp->st_mode & S_IWOTH) ? 'w' : '-',
           (statp->st_mode & S_IXOTH) ? 'x' : '-',
           statp->st_nlink, pwd->pw_name, grp->gr_name,
           statp->st_size, datestr);
}

struct list_opts {
    unsigned utf8     : 1;
    unsigned recurse  : 1;
    unsigned ids      : 1;
    unsigned longlist : 1;
    unsigned meta     : 1;
    unsigned colorize : 1;
    unsigned columns;
    unsigned column_size;
};

struct list_rock {
    struct list_opts *opts;
    int count;
    int magic_inbox;
    struct buf buf;
    strarray_t *children;
};

static int list_cb(struct findall_data *data, void *rock)
{
    struct list_rock *lrock = (struct list_rock *) rock;
    int r = 0;

    /* don't want partial matches */
    if (!data || !data->is_exactmatch) return 0;

    const char *child_name = strarray_nth(mbname_boxes(data->mbname), -1);
    const char *color = "";
    const char *path;

    if (lrock->opts->meta) {
        path = mbentry_metapath(data->mbentry, 0, 0);
    }
    else {
        path = mbentry_datapath(data->mbentry, 0);
    }

    printf("%s", !(lrock->count++ % lrock->opts->columns) ? "\n" : "    ");

    if (lrock->opts->ids) printf("%-40s ", data->mbentry->uniqueid);

    if (lrock->opts->longlist || lrock->opts->colorize) {
        struct stat sbuf;

        memset(&sbuf, 0, sizeof(struct stat));
        r = stat(path, &sbuf);

        if (lrock->opts->longlist) long_list(&sbuf);

        if (lrock->opts->colorize) {
            if (r != 0)
                color = ANSI_COLOR_RED;
            else if (mbtype_isa(data->mbentry->mbtype) != MBTYPE_EMAIL)
                color = ANSI_COLOR_MAGENTA;
            else
                color = ANSI_COLOR_BR_BLUE;
        }
    }

    printf("%s", color);
    if (lrock->magic_inbox) {
        buf_setcstr(&lrock->buf, "INBOX/");
        buf_appendcstr(&lrock->buf, child_name);
        child_name = buf_cstring(&lrock->buf);
    }
    r = print_name(child_name, lrock->opts->utf8);
    if (*color) printf("%s", ANSI_COLOR_RESET);

    if (lrock->opts->column_size) {
        /* fill column */
        int fill = lrock->opts->column_size - r;

        printf("%-*s", fill > 0 ? fill : 0, "");
    }

    if (lrock->children) strarray_append(lrock->children, data->extname);

    return 0;
}

static void do_list(mbname_t *mbname, struct list_opts *opts)
{
    mbentry_t *mbentry = NULL;
    struct list_rock lrock = { opts, 0, 0, BUF_INITIALIZER, NULL };
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
            r = IMAP_MAILBOX_NOTSUPPORTED;
        }
    }
    else {
        fprintf(stderr, "Invalid mailbox name: '%s'\n",
                mbname_extname(mbname, &cyr_ls_namespace, "cyrus"));
    }

    mboxlist_entry_free(&mbentry);

    if (!r) {
        /* List children */
        int isinbox = mboxname_isusermailbox(mbname_intname(mbname), 1);

        if (opts->recurse) lrock.children = &names;

        mbname_push_boxes(mbname, "%");
        mboxlist_findall(&cyr_ls_namespace,
                         mbname_extname(mbname, &cyr_ls_namespace, "cyrus"),
                         1, 0, 0, &list_cb, &lrock);

        if (isinbox) {
            free(mbname_pop_boxes(mbname));
            mbname_push_boxes(mbname, "INBOX");
            mbname_push_boxes(mbname, "%");
            lrock.magic_inbox = 1;
            mboxlist_findall(&cyr_ls_namespace,
                             mbname_extname(mbname, &cyr_ls_namespace, "cyrus"),
                             1, 0, 0, &list_cb, &lrock);
        }
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

    buf_free(&lrock.buf);
}

int main(int argc, char **argv)
{
    int r;
    int opt;              /* getopt() returns an int */
    char *alt_config = NULL;
    int is_path = 0;

    // capture options
    struct list_opts opts =
        { 1 /* default to UTF8 */, 0, 0, 0, 0,
          isatty(STDOUT_FILENO), 4 /* default to 4 columns */, 0 };

    while ((opt = getopt(argc, argv, "C:7milR1p")) != EOF) {
        switch(opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case '7':
            opts.utf8 = 0;
            break;

        case 'R':
            opts.recurse = 1;
            break;

        case 'i':
            opts.ids = 1;
            opts.columns = 1;
            break;

        case 'l':
            opts.longlist = 1;
            opts.columns = 1;
            break;

        case 'm':
            opts.meta = 1;
            break;

        case '1':
            opts.columns = 1;
            break;

        case 'p':
            is_path = 1;
            break;

        default:
            usage(NULL);
        }
    }

    if (opts.columns > 1) opts.column_size = 76 / opts.columns;

    cyrus_init(alt_config, "cyr_ls", 0, 0);


    r = mboxname_init_namespace(&cyr_ls_namespace, 1);
    if (r) {
        fatal(error_message(r), -1);
    }

    /* Translate mailboxname */
    mbname_t *mbname = NULL;
    r = IMAP_MAILBOX_NONEXISTENT;
    if (!is_path && (optind != argc)) {
        /* Is this an actual mailbox name */
        if (opts.utf8) {
            mbname = mbname_from_extnameUTF8(argv[optind], &cyr_ls_namespace, "cyrus");
        }
        else {
            mbname = mbname_from_extname(argv[optind], &cyr_ls_namespace, "cyrus");
        }

        r = mboxlist_lookup_allow_all(mbname_intname(mbname), NULL, NULL);
    }
    if (r == IMAP_MAILBOX_NONEXISTENT) {
        /* Are we in a mailbox directory? */
        const char *path = (optind == argc) ? "." : argv[optind];

        mbname = mbname_from_path(path);
    }

    do_list(mbname, &opts);

    mbname_free(&mbname);

    cyrus_done();

    exit(0);
}
