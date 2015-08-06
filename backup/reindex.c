/* reindex.c -- replication-based backup reindexer
 *
 * Copyright (c) 1994-2015 Carnegie Mellon University.  All rights reserved.
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

/*
 * Prototype of building backup index from anticipated backup data format.
 * This tool will go away once its functionality is properly integrated into
 * the backup system and its utilities.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>

#include "lib/exitcodes.h"
#include "lib/util.h"

#include "imap/imapparse.h"

#include "backup/gzuncat.h"

EXPORTED void fatal(const char *error, int code) {
    fprintf(stderr, "fatal error: %s\n", error);
    exit(code);
}

static void usage(const char *name) {
    fprintf(stderr, "Usage: %s backup_filename\n", name);
    exit(EC_USAGE);
}

static ssize_t fill_cb(unsigned char *buf, size_t len, void *rock) {
    struct gzuncat *gzuc = (struct gzuncat *) rock;
    ssize_t r = gzuc_read(gzuc, buf, len);
    fprintf(stderr, "fill_cb read %ld bytes\n", r);
    return r;
}

static int backup_parse_command(struct protstream *in, time_t *ts, struct buf *cmd, struct dlist **kin) {
    struct dlist *dl = NULL;
    struct buf buf = BUF_INITIALIZER;
    int64_t t;
    int c;

    c = prot_getc(in);
    if (c == '#') {
        eatline(in, c);
        fprintf(stderr, "ate a comment\n");
    }
    else {
        prot_ungetc(c, in);
    }

    c = getint64(in, &t);
    if (c == EOF)
        goto fail;

    c = getword(in, &buf);
    if (c == EOF)
        goto fail;

    c = dlist_parse(&dl, DLIST_SFILE | DLIST_PARSEKEY, in);

    if (!dl) {
        fprintf(stderr, "\ndidn't parse dlist, error %i\n", c);
        goto fail;
    }

    if (c == '\r') c = prot_getc(in);
    if (c != '\n') {
        fprintf(stderr, "expected newline, got '%c'\n", c);
        eatline(in, c);
        goto fail;
    }

    if (kin) *kin = dl;
    if (cmd) buf_copy(cmd, &buf);
    if (ts) *ts = (time_t) t;
    buf_free(&buf);
    return c;

fail:
    if (dl) dlist_free(&dl);
    buf_free(&buf);
    return c;
}

static int backup_apply_mailbox(time_t ts, struct dlist *dl) {
    struct buf out = BUF_INITIALIZER;

    dlist_printbuf(dl, 1, &out);
    fprintf(stderr, "backup_apply_mailbox: %.24s %s\n", ctime(&ts), buf_release(&out));
    return 0;
}

static int backup_apply_message(time_t ts, struct dlist *dl) {
    struct buf out = BUF_INITIALIZER;

    dlist_printbuf(dl, 1, &out);
    fprintf(stderr, "backup_apply_message: %.24s %s\n", ctime(&ts), buf_release(&out));
    return 0;
}

int main (int argc, char **argv) {
    if (argc != 2) usage(argv[0]);

    const char *backup_filename = argv[1];

    fprintf(stderr, "reindexing %s...\n", backup_filename);

    struct gzuncat *gzuc = gzuc_open(backup_filename);

    while (gzuc && !gzuc_eof(gzuc)) {
        gzuc_member_start(gzuc);

        fprintf(stderr, "\nfound member at offset %jd\n\n", gzuc_member_offset(gzuc));

        struct protstream *member = prot_readcb(fill_cb, gzuc);
        prot_setisclient(member, 1); /* don't sync literals */

        // FIXME stricter timestamp sequence checks
        time_t member_ts = -1;

        while (1) {
            struct buf cmd = BUF_INITIALIZER;
            time_t ts;
            struct dlist *dl = NULL;

            int c = backup_parse_command(member, &ts, &cmd, &dl);
            if (c == EOF) break;

            if (member_ts == -1)
                member_ts = ts;
            else if (member_ts > ts)
                fatal("timestamp older than previous", -1);

            if (strcmp(buf_cstring(&cmd), "APPLY") != 0) {
                fprintf(stderr, "skipping unrecognised command: %s\n", buf_cstring(&cmd));
                continue;
            }

            ucase(dl->name);

            int r;

            if (0) { }

            else if (strcmp(dl->name, "MAILBOX") == 0)
                r = backup_apply_mailbox(member_ts, dl);
            else if (strcmp(dl->name, "MESSAGE") == 0)
                r = backup_apply_message(member_ts, dl);

            else {
                fprintf(stderr, "ignoring unrecognised dlist name: %s\n", dl->name);
                continue;
            }

            if (r) {
                // FIXME do something
            }
        }

        prot_free(member);
        gzuc_member_end(gzuc, NULL);
    }

    fprintf(stderr, "reached end of file\n");

    gzuc_close(&gzuc);

    return 0;
}
