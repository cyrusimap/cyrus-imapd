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
    fprintf(stderr,"usage: cyr_ls [-C <alt_config>] [-l] [-m] <mailbox name>\n");
    fprintf(stderr, "\n");
    fprintf(stderr,"\t-l\tlong listing format\n");
    fprintf(stderr,"\t-m\toutput the path to the metadata files (if different from the message files)\n");
    if (error) {
        fprintf(stderr,"\n");
        fprintf(stderr,"ERROR: %s", error);
    }
    exit(-1);
}

static int list_cb(struct findall_data *data, void *rock __attribute__((unused)))
{
    int r = 0;

    /* don't want partial matches */
    if (!data || !data->mbname) return 0;

    /* Convert internal name to external */
    const char *extname = mbname_extname(data->mbname, &cyr_ls_namespace, "cyrus");
    printf("%s\n", strrchr(extname, '/')+1);

    return r;
}

int main(int argc, char **argv)
{
    mbentry_t *mbentry = NULL;
    int r;
    int opt;              /* getopt() returns an int */
    char *alt_config = NULL;

    // capture options
    int longlist = 0;
    int meta = 0;

    while ((opt = getopt(argc, argv, "C:lm")) != EOF) {
        switch(opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'l':
            longlist = 1;
            break;

        case 'm':
            meta = 1;
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
    char *freeme = NULL;

    mbname = mbname_from_path(path, &cyr_ls_namespace);
    path = NULL;

    printf("%s:\n\n", mbname_extname(mbname, &cyr_ls_namespace, "cyrus"));

    r = mboxlist_lookup(mbname_intname(mbname), &mbentry, NULL);
    if (!r) {
        if (mbentry->mbtype & MBTYPE_REMOTE) {
            printf("Non-local mailbox: %s!%s\n",
                   mbentry->server, mbentry->partition);
        }
        else if (meta) {
            path = mboxname_metapath(mbentry->partition, mbentry->name, mbentry->uniqueid, 0, 0);
        }
        else {
            path = mboxname_datapath(mbentry->partition, mbentry->name, mbentry->uniqueid, 0);
        }
    }
    else {
        fprintf(stderr, "Invalid mailbox name: %s\n", argv[optind]);
    }

    /* Scan the directory */
    if (path) {
        DIR *dirp = opendir(path);
        if (dirp) {
            struct dirent *dirent;

            while ((dirent = readdir(dirp))) {
                if (dirent->d_name[0] == '.') continue;

                printf("%s\n", dirent->d_name);
            }
            closedir(dirp);
        }

        /* List children */
        mbname_push_boxes(mbname, "%");
        mboxlist_findall(&cyr_ls_namespace,
                         mbname_extname(mbname, &cyr_ls_namespace, "cyrus"),
                         1, 0, 0, &list_cb, &longlist);
    }

    mbname_free(&mbname);
    free(freeme);

    cyrus_done();

    exit(0);
}
