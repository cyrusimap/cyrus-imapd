/* mbpath.c -- help the sysadmin to find the path matching the mailbox
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
static struct namespace mbpath_namespace;

static int usage(const char *error)
{
    fprintf(stderr,"usage: mbpath [-C <alt_config>] [-l] [-m] [-q] [-s] [-u] [-a|A|D|M|S|U] <mailbox name>...\n");
    fprintf(stderr, "\n");
    fprintf(stderr,"\t-a\tprint all values with prefixes\n");
    fprintf(stderr,"\t-l\tlocal only (exit with error for remote/nonexistent)\n");
    fprintf(stderr,"\t-m\toutput the path to the metadata files (if different from the message files)\n");
    fprintf(stderr,"\t-q\tquietly drop any error messages\n");
    fprintf(stderr,"\t-s\tstop on error\n");
    fprintf(stderr,"\t-u\targuments are user, not mailbox\n");
    fprintf(stderr,"\t-A\tpartition archive directory\n");
    fprintf(stderr,"\t-D\tpartition data directory (*default*)\n");
    fprintf(stderr,"\t-M\tpartition metadata file directory (duplicate of -m)\n");
    fprintf(stderr,"\t-S\tsieve directory for the user\n");
    fprintf(stderr,"\t-U\tuser files directory (seen, sub, etc)\n");
    if (error) {
        fprintf(stderr,"\n");
        fprintf(stderr,"ERROR: %s", error);
    }
    exit(-1);
}

int main(int argc, char **argv)
{
    mbentry_t *mbentry = NULL;
    int r, i;
    int opt;              /* getopt() returns an int */
    char *alt_config = NULL;

    // capture options
    int quiet = 0;
    int stop_on_error = 0;
    int localonly = 0;
    int usermode = 0;
    int doall = 0;
    int doA = 0;
    int doD = 1; // default
    int doM = 0;
    int doS = 0;
    int doU = 0;
    int sel = 0;

    while ((opt = getopt(argc, argv, "C:almqsuADMSU")) != EOF) {
        switch(opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'a':
            if (sel)
                usage("Duplicate selectors given");
            doall = 1;
            doD = 0;
            sel = 1;
            break;

        case 'l':
            localonly = 1;
            break;

        case 'm':
            if (sel)
                usage("Duplicate selectors given");
            doM = 1;
            doD = 0;
            sel = 1;
            break;

        case 'q':
            quiet = 1;
            break;

        case 's':
            stop_on_error = 1;
            break;

        case 'u':
            usermode = 1;
            break;

        case 'A':
            if (sel)
                usage("Duplicate selectors given");
            doA = 1;
            doD = 0;
            sel = 1;
            break;

        case 'D':
            if (sel)
                usage("Duplicate selectors given");
            sel = 1;
            break;

        case 'M':
            if (sel)
                usage("Duplicate selectors given");
            doM = 1;
            doD = 0;
            sel = 1;
            break;

        case 'S':
            if (sel)
                usage("Duplicate selectors given");
            doS = 1;
            doD = 0;
            sel = 1;
            break;

        case 'U':
            if (sel)
                usage("Duplicate selectors given");
            doU = 1;
            doD = 0;
            sel = 1;
            break;

        default:
            usage(NULL);
        }
    }

    cyrus_init(alt_config, "mbpath", 0, 0);


    r = mboxname_init_namespace(&mbpath_namespace, 1);
    if (r) {
        fatal(error_message(r), -1);
    }

    for (i = optind; i < argc; i++) {
        /* Translate mailboxname */
        mbname_t *mbname = NULL;
        if (usermode) {
            mbname = mbname_from_userid(argv[i]);
        }
        else {
            mbname = mbname_from_extname(argv[i], &mbpath_namespace, NULL);
        }
        r = mboxlist_lookup(mbname_intname(mbname), &mbentry, NULL);
        if (!r) {
            if (mbentry->mbtype & MBTYPE_REMOTE) {
                if (localonly) {
                    if (stop_on_error) {
                        if (quiet) {
                            fatal("", -1);
                        }
                        else {
                            fatal("Non-local mailbox. Stopping\n", -1);
                        }
                    }
                }
                else {
                    // ignore all selectors and just print this
                    printf("%s!%s\n", mbentry->server, mbentry->partition);
                }
            }
            else {
                if (doall || doA) {
                    const char *path = mboxname_archivepath(mbentry->partition, mbentry->name, mbentry->uniqueid, 0);
                    if (doall) printf("Archive: ");
                    printf("%s\n", path);
                }
                if (doall || doD) {
                    const char *path = mboxname_datapath(mbentry->partition, mbentry->name, mbentry->uniqueid, 0);
                    if (doall) printf("Data: ");
                    printf("%s\n", path);
                }
                if (doall || doM) {
                    const char *path = mboxname_metapath(mbentry->partition, mbentry->name, mbentry->uniqueid, 0, 0);
                    if (doall) printf("Meta: ");
                    printf("%s\n", path);
                }
                if (doall || doS) {
                    const char *path = user_sieve_path(mbname_userid(mbname));
                    if (doall) printf("Sieve: ");
                    printf("%s\n", path);
                }
                if (doall || doU) {
                    // different interface - caller must free
                    char *path = mboxname_conf_getpath(mbname, NULL);
                    if (doall) printf("User: ");
                    printf("%s\n", path);
                    free(path);
                }
            }
        }
        else {
            if (!quiet && (r == IMAP_MAILBOX_NONEXISTENT)) {
                fprintf(stderr, "Invalid mailbox name: %s\n", argv[i]);
            }
            if (stop_on_error) {
                if (quiet) {
                    fatal("", -1);
                }
                else {
                    fatal("Error in processing mailbox. Stopping\n", -1);
                }
            }
        }
        mbname_free(&mbname);
    }

    cyrus_done();

    return 0;
}
