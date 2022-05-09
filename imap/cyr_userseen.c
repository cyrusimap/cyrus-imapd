/* ctl_userseen.c - tool to remove seen records for owners.
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
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "global.h"
#include "libcyr_cfg.h"
#include "mailbox.h"
#include "mboxlist.h"
#include "seen.h"
#include "util.h"
#include "xmalloc.h"

/* config.c stuff */
static int do_remove = 0;

static void usage(void)
{
    fprintf(stderr, "cyr_userseen [-C <altconfig>] -d\n");
    exit(-1);
}

/* Callback for use by delete_seen */
static int deluserseen(const mbentry_t *mbentry, void *rock __attribute__((unused)))
{
    struct mailbox *mailbox = NULL;
    int r = 0;

    r = mailbox_open_irl(mbentry->name, &mailbox);
    if (r) goto done;

    char *userid = mboxname_to_userid(mbentry->name);
    if (userid) {
        printf("removing seen for %s on %s\n", userid, mailbox_name(mailbox));
        if (do_remove) seen_delete_mailbox(userid, mailbox);
        free(userid);
    }

    mailbox_close(&mailbox);

done:
    return r;
}

int main(int argc, char *argv[])
{
    int opt;
    char *alt_config = NULL;

    /* keep this in alphabetical order */
    static const char *const short_options = "C:d";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { "delete", no_argument, NULL, 'd' },
        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'd':
            do_remove = 1;
            break;

        default:
            usage();
            break;
        }
    }

    cyrus_init(alt_config, "cyr_userseen", 0, 0);

    /* build a list of mailboxes - we're using internal names here */
    mboxlist_allmbox("", deluserseen, NULL, /*flags*/0);

    cyrus_done();

    return 0;
}
