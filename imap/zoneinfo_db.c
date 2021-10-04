/* zoneinfo_db.c -- zoneinfo DB routines
 *
 * Copyright (c) 1994-2013 Carnegie Mellon University.  All rights reserved.
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>

#include "assert.h"
#include "cyrusdb.h"
#include "global.h"
#include "tok.h"
#include "util.h"
#include "xmalloc.h"

#include "zoneinfo_db.h"

#define DB config_zoneinfo_db

struct db *zoneinfodb;
static int zoneinfo_dbopen = 0;
static struct buf databuf = BUF_INITIALIZER;

EXPORTED int zoneinfo_open(const char *fname)
{
    int ret;
    char *tofree = NULL;

    if (!fname) fname = config_getstring(IMAPOPT_ZONEINFO_DB_PATH);

    /* create db file name */
    if (!fname) {
        tofree = strconcat(config_dir, FNAME_ZONEINFODB, (char *)NULL);
        fname = tofree;
    }

    ret = cyrusdb_open(DB, fname, CYRUSDB_CREATE, &zoneinfodb);
    if (ret != 0) {
        syslog(LOG_ERR, "DBERROR: opening %s: %s", fname,
               cyrusdb_strerror(ret));
    }
    else zoneinfo_dbopen = 1;

    free(tofree);

    return ret;
}

EXPORTED void zoneinfo_close(struct txn *tid)
{
    if (zoneinfo_dbopen) {
        int r;

        if (tid) {
            r = cyrusdb_commit(zoneinfodb, tid);
            if (r) {
                syslog(LOG_ERR, "DBERROR: error committing zoneinfo: %s",
                       cyrusdb_strerror(r));
            }
        }
        r = cyrusdb_close(zoneinfodb);
        if (r) {
            syslog(LOG_ERR, "DBERROR: error closing zoneinfo: %s",
                   cyrusdb_strerror(r));
        }
        zoneinfo_dbopen = 0;

        buf_free(&databuf);
    }
}

void zoneinfo_done(void)
{
    /* DB->done() handled by cyrus_done() */
}

static int parse_zoneinfo(const char *data, int datalen,
                          struct zoneinfo *zi, int all)
{
    const char *dend = data + datalen;
    unsigned version;
    char *p;

    memset(zi, 0, sizeof(struct zoneinfo));

    /* version SP type SP dtstamp SP (string *(TAB string)) */

    version = strtoul(data, &p, 10);
    if (version != ZONEINFO_VERSION) return CYRUSDB_IOERROR;

    if (p < dend) zi->type = strtoul(p, &p, 10);
    if (p < dend) zi->dtstamp = strtotimet(p, &p, 10);

    if (all && p < dend) {
        size_t len = dend - ++p;
        char *str = xstrndup(p, len);
        const char *p;
        tok_t tok;

        tok_initm(&tok, str, "\t", TOK_FREEBUFFER);
        while ((p = tok_next(&tok))) appendstrlist(&zi->data, p);
        tok_fini(&tok);
    }

    return 0;
}

EXPORTED int zoneinfo_lookup(const char *tzid, struct zoneinfo *zi)
{
    const char *data = NULL;
    size_t datalen;
    int r;

    /* Don't access DB if it hasn't been opened */
    if (!zoneinfo_dbopen) return CYRUSDB_INTERNAL;

    assert(tzid);

    /* Check if there is an entry in the database */
    do {
        r = cyrusdb_fetch(zoneinfodb, tzid, strlen(tzid), &data, &datalen, NULL);
    } while (r == CYRUSDB_AGAIN);

    if (r || !data || (datalen < 6)) return r ? r : CYRUSDB_IOERROR;

    if (!zi) return 0;

    return parse_zoneinfo(data, datalen, zi, 1);
}

EXPORTED int zoneinfo_store(const char *tzid, struct zoneinfo *zi, struct txn **tid)
{
    struct strlist *sl;
    const char *sep;
    int r;

    /* Don't access DB if it hasn't been opened */
    if (!zoneinfo_dbopen) return CYRUSDB_INTERNAL;

    assert(tzid && zi);

    /* version SP type SP dtstamp SP (string *(TAB string)) */
    buf_reset(&databuf);
    buf_printf(&databuf, "%u %u " TIME_T_FMT " ", ZONEINFO_VERSION, zi->type, zi->dtstamp);
    for (sl = zi->data, sep = ""; sl; sl = sl->next, sep = "\t")
        buf_printf(&databuf, "%s%s", sep, sl->s);

    r = cyrusdb_store(zoneinfodb, tzid, strlen(tzid),
                  buf_cstring(&databuf), buf_len(&databuf), tid);

    if (r != CYRUSDB_OK) {
        syslog(LOG_ERR, "DBERROR: error updating zoneinfo: %s (%s)",
               tzid, cyrusdb_strerror(r));
    }

    return r;
}


static int tzmatch(const char *str, size_t slen, const char *pat)
{
    for ( ; *pat; str++, slen--, pat++) {
        /* End of string and more pattern */
        if (!slen && *pat != '*') return 0;

        switch (*pat) {
        case '*':
            /* Collapse consecutive stars */
            while (*++pat == '*') continue;

            /* Trailing star matches anything */
            if (!*pat) return 1;

            while (slen) if (tzmatch(str++, slen--, pat)) return 1;
            return 0;

        case ' ':
        case '_':
            /* Treat ' ' == '_' */
            if (*str != ' ' && *str != '_') return 0;
            break;

        default:
            /* Case-insensitive comparison */
            if (tolower(*str) != tolower(*pat)) return 0;
            break;
        }
    }

    /* Did we reach end of string? */
    return (!slen);
}


struct findrock {
    const char *find;
    int tzid_only;
    time_t changedsince;
    int (*proc)();
    void *rock;
};

static int find_p(void *rock,
                  const char *tzid, size_t tzidlen,
                  const char *data, size_t datalen)
{
    struct findrock *frock = (struct findrock *) rock;
    struct zoneinfo zi;

    if (parse_zoneinfo(data, datalen, &zi, 0)) return 0;

    switch (zi.type) {
    case ZI_INFO: return 0;

    case ZI_LINK:
        if (frock->tzid_only) return 0;
        break;

    case ZI_ZONE:
        if (zi.dtstamp <= frock->changedsince) return 0;
        break;
    }

    if (!frock->find) return 1;
    if (frock->tzid_only) return (tzidlen == strlen(frock->find));
    return tzmatch(tzid, tzidlen, frock->find);
}

static int find_cb(void *rock,
                   const char *tzid, size_t tzidlen,
                   const char *data, size_t datalen)
{
    struct findrock *frock = (struct findrock *) rock;
    struct zoneinfo zi;
    int r;

    r = parse_zoneinfo(data, datalen, &zi, 1);
    if (!r) {
        struct strlist *linkto = NULL;

        if (zi.type == ZI_LINK) {
            linkto = zi.data;
            zi.data = NULL;

            tzid = linkto->s;
            tzidlen = strlen(tzid);
            r = zoneinfo_lookup(tzid, &zi);
        }
        if (!r) r = (*frock->proc)(tzid, tzidlen, &zi, frock->rock);
        freestrlist(zi.data);
        freestrlist(linkto);
    }

    return r;
}

EXPORTED int zoneinfo_find(const char *find, int tzid_only, time_t changedsince,
                  int (*proc)(), void *rock)
{
    struct findrock frock;

    /* Don't access DB if it hasn't been opened */
    if (!zoneinfo_dbopen) return CYRUSDB_INTERNAL;

    assert(proc);

    frock.find = find;
    frock.tzid_only = tzid_only;
    frock.changedsince = changedsince;
    frock.proc = proc;
    frock.rock = rock;

    if (!find || !tzid_only) find = "";

    /* process each matching entry in our database */
    return cyrusdb_foreach(zoneinfodb, (char *) find, strlen(find),
                           &find_p, &find_cb, &frock, NULL);
}
