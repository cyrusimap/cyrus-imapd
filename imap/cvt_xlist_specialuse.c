/* cvt_xlist_specialuse.c - migrate xlist-foo settings to specialuse annots
 *
 * Copyright (c) 1994-2016 Carnegie Mellon University.  All rights reserved.
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
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include "lib/hash.h"
#include "lib/libconfig.h"

#include "imap/global.h"
#include "imap/mboxlist.h"
#include "imap/mboxname.h"

static int verbose = 0;

static const char *argv0 = NULL;
static void usage(void)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s [options] mailbox...\n", argv0);

    fprintf(stderr, "\n%s\n",
            "Options:\n"
            "    -C alt_config       # alternate config file\n"
            "    -v                  # verbose\n"
    );

    exit(EX_USAGE);
}

static void save_argv0(const char *s)
{
    const char *slash = strrchr(s, '/');
    if (slash)
        argv0 = slash + 1;
    else
        argv0 = s;
}

EXPORTED void fatal(const char *s, int code)
{
    fprintf(stderr, "Fatal error: %s\n", s);
    syslog(LOG_ERR, "Fatal error: %s", s);
    exit(code);
}

static void xlist_lookup_cb(const char *key, const char *val, void *rock)
{
    hash_table *xlistp = (hash_table *) rock;
    struct buf *flag;

    if (strncmp(key, "xlist-", 6)) return;

    flag = buf_new();
    buf_putc(flag, '\\');
    buf_appendcstr(flag, key + 6);

    if (verbose)
        printf("will set %s for folders named %s\n", buf_cstring(flag), val);

    hash_insert(val, flag, xlistp);
}

static int set_specialuse(struct findall_data *data, void *rock)
{
    const strarray_t *boxes = NULL;
    hash_table *xlist = (hash_table *) rock; /* XXX nice if this could be const */
    const struct buf *flag = NULL;
    char *existing;
    int r;

    if (!data) return 0;
    if (!data->is_exactmatch) return 0;

    if (!mbname_userid(data->mbname)) return 0;

    boxes = mbname_boxes(data->mbname);
    if (boxes->count != 1) /* INBOX, or nested subfolder */
        return 0;

    flag = hash_lookup(strarray_nth(boxes, 0), xlist);
    if (!flag || !buf_len(flag)) return 0;

    existing = mboxlist_find_specialuse(buf_cstring(flag), mbname_userid(data->mbname));
    if (existing) {
        if (verbose)
            printf("not setting specialuse %s for %s, already exists as %s\n",
                   buf_cstring(flag), mbname_intname(data->mbname), existing);
        free(existing);
        return 0;
    }

    r = annotatemore_write(mbname_intname(data->mbname), "/specialuse",
                           mbname_userid(data->mbname), flag);

    if (r) {
        fprintf(stderr, "failed to set specialuse %s for %s: %s",
                        buf_cstring(flag), mbname_intname(data->mbname),
                        error_message(r));
        r = 0;
    }
    else if (verbose) {
        printf("set specialuse %s for %s\n",
               buf_cstring(flag), mbname_intname(data->mbname));
    }

    return 0;
}

int main (int argc, char **argv)
{

    int opt, i, r = 0;
    char *alt_config = NULL;
    hash_table xlist = HASH_TABLE_INITIALIZER;
    strarray_t patterns = STRARRAY_INITIALIZER;

    save_argv0(argv[0]);

    while ((opt = getopt(argc, argv, "C:v")) != -1) {
        switch (opt) {
        case 'C':
            alt_config = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            usage();
        }
    }

    if (optind == argc) usage();

    cyrus_init(alt_config, "cvt_xlist_specialuse",
               (verbose ? CYRUSINIT_PERROR : 0),
               CONFIG_NEED_PARTITION_DATA);

    construct_hash_table(&xlist, 10, 0);
    config_foreachoverflowstring(xlist_lookup_cb, &xlist);

    if (hash_numrecords(&xlist) < 1) {
        /* nothing to do */
        fprintf(stderr, "no xlist- settings in %s, nothing to do\n",
                        alt_config ? alt_config : CONFIG_FILENAME);
        goto done;
    }

    for (i = optind; i < argc; i++) {
        strarray_append(&patterns, argv[i]);
    }

    r = mboxlist_findallmulti(NULL, &patterns, 1, NULL, NULL, set_specialuse, &xlist);

done:
    free_hash_table(&xlist, (void (*)(void*)) buf_free);
    strarray_fini(&patterns);

    cyrus_done();
    return r ? EX_TEMPFAIL : EX_OK;
}
