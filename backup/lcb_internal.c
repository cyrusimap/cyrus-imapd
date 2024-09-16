/* lcb_internal.c -- replication-based backup api - internal utility functions
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

#include <assert.h>
#include <syslog.h>

#include "lib/map.h"

#include "imap/dlist.h"
#include "imap/imapparse.h"

#include "backup/backup.h"

#define LIBCYRUS_BACKUP_SOURCE /* this file is part of libcyrus_backup */
#include "backup/lcb_internal.h"

HIDDEN int parse_backup_line(struct protstream *in, time_t *ts,
                             struct buf *cmd, struct dlist **kin)
{
    struct dlist *dl = NULL;
    struct buf buf = BUF_INITIALIZER;
    int64_t t;
    int c;

    c = prot_getc(in);
    if (c == '#')
        eatline(in, c);
    else
        prot_ungetc(c, in);

    c = getint64(in, &t);
    if (c == EOF)
        goto fail;

    c = getword(in, &buf);
    if (c == EOF)
        goto fail;

    c = dlist_parse(&dl, /*parsekeys*/ 1, /*isarchive*/ 0, 1, in);

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

HIDDEN const char *sha1_file(int fd, const char *fname, size_t limit,
                             char buf[2 * SHA1_DIGEST_LENGTH + 1])
{
    const char *map = NULL;
    size_t len = 0, calc_len;
    unsigned char sha1_raw[SHA1_DIGEST_LENGTH];
    int r;

    map_refresh(fd, /*onceonly*/ 1, &map, &len, MAP_UNKNOWN_LEN, fname, NULL);
    calc_len = limit == SHA1_LIMIT_WHOLE_FILE ? len : MIN(limit, len);
    xsha1((const unsigned char *) map, calc_len, sha1_raw);
    map_free(&map, &len);
    r = bin_to_hex(sha1_raw, SHA1_DIGEST_LENGTH, buf, BH_LOWER);
    assert(r == 2 * SHA1_DIGEST_LENGTH);

    return buf;
}
