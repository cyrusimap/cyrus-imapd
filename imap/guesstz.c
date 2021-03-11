/* guesstz.h -- routines to guess timezone ids from VTIMEZONEs
 *
 * Copyright (c) 1994-2021 Carnegie Mellon University.  All rights reserved.
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
#include <fts.h>
#include <syslog.h>

#include <jansson.h>

#include "caldav_db.h"
#include "dynarray.h"
#include "ical_support.h"
#include "libconfig.h"
#include "map.h"

#include "guesstz.h"

#define GUESSTZDB_BACKEND "twoskip"

/*
 * The guesstz database organizes records by a single-byte key prefix.
 * Each key may contain
 *
 * Each key prefix is a single-byte character, followed by additional
 * type-specific data. Each entry data contains fields, described below
 * in order of their position in the data buffer. All multi-byte values
 * are in network order. If not specified otherwise, a field has a
 * cardinality of one.
 *
 * "C":
 *   Config metadata.
 *
 *   dbVersion: <uint8_t>
 *     The database version.
 *
 *   createdAt: <int64_t>
 *     The datetime this database was created at, in UNIX epoch time.
 *
 *   timeRange:
 *     The time range in which timezone observances are expanded,
 *     in UNIX epoch time.
 *     start: <int64_t>
 *       The start of the time range.
 *     end: <int64_t>
 *       The start of the time range.
 *
 *   ianaVersion: <cstring, including zero>
 *     The IANA database version this database is based on.
 *
 * "T"<tznum:uint32_t>:
 *   Timezone internally identified by tznum.
 *   Cardinality: {0,n}
 *
 *   tzid: <cstring, including zero>
 *     The timezone identifier of the timezone.
 *
 *   observance:
 *     A timezone observance.
 *       onset: <int64_t>
 *         The onset time of the observance, in UNIX epoch time.
 *       offset: <int32_t>
 *         The UTC offset of the observance in seconds.
 *   Cardinality: {1,n}
 *   Observances are ordered ascending by onset.
 *
 * "O"<offset:int32_t>:
 *   List of timezone numeric identifiers that have at least one observance
 *   with this UTC offset.
 *   Cardinality: {0,n}
 *
 *   tznum: <uint32_t>
 *     A numeric timezone identifier.
 *     Cardinality: {1,n}
 *
 */

static uint8_t guesstzdb_version = 1;

struct obsrec {
    int64_t onset;
    int32_t offset;
};

struct offsetrec {
    int32_t offset;
    uint32_t tznum;
};

struct guesstzdb {
    struct db *db;
    struct txn *tid;
    icaltimetype dbstart;
    icaltimetype dbend;
    char *ianaversion;
    char *fname;
    char version;
    time_t created;
    struct buf buf1;
    struct buf buf2;
};

static int format_offset(int32_t offset, char *buffer)
{
    char sign = '+';
    if (offset < 0) {
        offset = -offset;
        sign = '-';
    }

    int hours = offset / 3600;
    int minutes = (offset % 3600) / 60;
    int seconds = offset % 60;

    if (hours > 23 || minutes > 59 || seconds > 59) {
        return 0;
    }

    snprintf(buffer, 8, "%c%02i%02i", sign, hours, minutes);
    if (seconds) {
        snprintf(buffer + 5, 3, "%02i", seconds);
    }

    return strlen(buffer);
}


static void expand_observances(icalcomponent *vtz,
                       icaltimetype start, icaltimetype end,
                       dynarray_t *obsrecs)
{
    const icaltimezone *utc = icaltimezone_get_utc_timezone();
    icalarray *obsarray;


    icalcomponent *myvtz = icalcomponent_clone(vtz);
    obsarray = icalarray_new(sizeof(struct observance), 20);
    icaltimezone_truncate_vtimezone_advanced(myvtz, &start, &end, obsarray,
            NULL, NULL, NULL, NULL, 0);
    icalcomponent_free(myvtz);

    if (!obsarray->num_elements) {
        icalarray_free(obsarray);
        return;
    }

    unsigned i;
    for (i = 0; i < obsarray->num_elements; i++) {
        struct observance *obs = icalarray_element_at(obsarray, i);
        struct obsrec obsrec = {
            (int64_t) icaltime_as_timet_with_zone(obs->onset, utc),
            (int32_t) obs->offset_to
        };
        dynarray_append(obsrecs, &obsrec);
    }

    icalarray_free(obsarray);
}

static int offsetrec_cmp(const void *va, const void *vb)
{
    const struct offsetrec *a = va;
    const struct offsetrec *b = vb;

    if (a->offset != b->offset) {
        return a->offset < b->offset ? -1 : 1;
    }
    if (a->tznum != b->tznum) {
        return a->tznum < b->tznum ? -1 : 1;
    }

    return 0;
}

static char *guesstz_fname(const char *zoneinfo_dir, const char *alt_fname)
{
    struct buf fname = BUF_INITIALIZER;

    if (!zoneinfo_dir) {
        zoneinfo_dir = config_getstring(IMAPOPT_ZONEINFO_DIR);
        if (!zoneinfo_dir) {
            xsyslog(LOG_ERR, "No zoneinfo_dir found in config", NULL);
            return NULL;
        }
    }
    if (!alt_fname) {
        buf_setcstr(&fname, zoneinfo_dir);
        if (fname.s[fname.len-1] != '/') buf_putc(&fname, '/');
        buf_appendcstr(&fname, "guesstz.db");
    }
    else {
        buf_setcstr(&fname, alt_fname);
    }
    buf_cstring(&fname);

    return buf_release(&fname);
}

static int store_timezone(struct guesstzdb *gtzdb,
                          uint32_t tznum, const char *tzid,
                          const struct obsrec *obs, size_t nobs)
{
    struct buf *key = &gtzdb->buf1;
    buf_reset(key);
    buf_putc(key, 'T');
    buf_appendbit32(key, tznum);

    struct buf *data = &gtzdb->buf2;
    buf_setcstr(data, tzid);
    buf_putc(data, '\0');

    size_t tzidlen = buf_len(data);
    buf_ensure(data, tzidlen + nobs * sizeof(struct obsrec));
    size_t i;
    for (i = 0; i < nobs; i++) {
        buf_appendbit64(data, obs[i].onset);
        buf_appendbit32(data, obs[i].offset);
    }

     return cyrusdb_store(gtzdb->db, buf_base(key), buf_len(key),
            buf_base(data), buf_len(data), &gtzdb->tid);
}

static int store_offsets(struct guesstzdb *gtzdb,
                         struct offsetrec *offsetrecs,
                         size_t noffsetrecs)
{
    int r = 0;

    qsort(offsetrecs, noffsetrecs, sizeof(struct offsetrec), offsetrec_cmp);

    struct buf *key = &gtzdb->buf1;
    buf_reset(key);
    struct buf *data = &gtzdb->buf2;
    buf_reset(data);

    struct offsetrec *offsetrec = offsetrecs;
    int32_t prevoffset = offsetrec->offset;
    size_t i;
    for (i = 0; i < noffsetrecs; i++) {
        struct offsetrec *offsetrec = offsetrecs + i;
        if (prevoffset != offsetrec->offset) {
            /* Write previous record */
            buf_putc(key, 'O');
            buf_appendbit32(key, prevoffset);
            r = cyrusdb_store(gtzdb->db, buf_base(key), buf_len(key),
                    buf_base(data), buf_len(data), &gtzdb->tid);
            if (r) goto done;
            /* Reset state */
            prevoffset = offsetrec->offset;
            buf_reset(key);
            buf_reset(data);
        }
        buf_appendbit32(data, offsetrec->tznum);
    }
    if (buf_len(data)) {
        /* Write previous record */
        buf_putc(key, 'O');
        buf_appendbit32(key, prevoffset);
        r = cyrusdb_store(gtzdb->db, buf_base(key), buf_len(key),
                buf_base(data), buf_len(data), &gtzdb->tid);
        if (r) goto done;
    }

done:
    buf_reset(key);
    buf_reset(data);
    return r;
}

static int store_config(struct guesstzdb *gtzdb)
{
    struct buf *key = &gtzdb->buf1;
    buf_reset(key);
    buf_putc(key, 'C');

    struct buf *data = &gtzdb->buf2;
    buf_reset(data);

    /* 1-byte version */
    buf_appendmap(data, &gtzdb->version, 1);

    /* 8-byte timestamp of creation time */
    int64_t t = gtzdb->created;
    buf_appendmap(data, (char *)&t, 8);

    /* 16-byte time range */
    const icaltimezone *utc = icaltimezone_get_utc_timezone();
    int64_t tstart = icaltime_as_timet_with_zone(gtzdb->dbstart, utc);
    int64_t tend = icaltime_as_timet_with_zone(gtzdb->dbend, utc);
    buf_appendmap(data, (char *)&tstart, 8);
    buf_appendmap(data, (char *)&tend, 8);

    /* Zero-terminated IANA version name */
    buf_appendcstr(data, gtzdb->ianaversion);
    buf_putc(data, '\0');

    int r = cyrusdb_store(gtzdb->db, buf_base(key), buf_len(key),
            buf_base(data), buf_len(data), &gtzdb->tid);

    buf_free(key);
    buf_free(data);
    return r;
}

static int create_from_zonedir(struct guesstzdb *gtzdb,
                               const char *zoneinfo_dir,
                               icaltimetype start, icaltimetype end)
{
    dynarray_t offsetrecs;
    dynarray_init(&offsetrecs, sizeof(struct offsetrec));
    arrayu64_t uniqoffsets = ARRAYU64_INITIALIZER;
    dynarray_t obsrecs;
    dynarray_init(&obsrecs, sizeof(struct obsrec));
    int r = 0;

    /* Traverse timezone definitions */
    uint32_t tznum = 1; // time zone numeric ids start at 1
    FTS *fts = NULL;

    char *paths[2] = { (char *) zoneinfo_dir, NULL };
    fts = fts_open(paths, 0, NULL);
    if (!fts) {
        xsyslog(LOG_ERR, "fts_open", "zoneinfo_dir=<%s> err=<%s>",
                zoneinfo_dir, strerror(errno));
        r = CYRUSDB_IOERROR;
        goto done;
    }

    FTSENT *fe;
    while ((fe = fts_read(fts))) {
        if (fe->fts_info != FTS_F) {
            continue;
        }

        int fd = open(fe->fts_path, O_RDONLY);
        if (fd == -1) {
            int myerrno = errno;
            xsyslog(LOG_ERR, "can not open timezone file",
                    "fname=<%s> err=<%s>", fe->fts_path, strerror(myerrno));
            continue;
        }
        struct buf buf = BUF_INITIALIZER;
        buf_refresh_mmap(&buf, 1, fd, fe->fts_path, MAP_UNKNOWN_LEN, NULL);
        icalcomponent *ical = icalparser_parse_string(buf_cstring(&buf));

        if (ical && icalcomponent_isa(ical) == ICAL_VCALENDAR_COMPONENT) {
            icalcomponent *vtz;
            for (vtz = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
                 vtz;
                 vtz = icalcomponent_get_next_component(ical, ICAL_VTIMEZONE_COMPONENT)) {

                icalproperty *prop = icalcomponent_get_first_property(vtz, ICAL_TZID_PROPERTY);
                if (!prop) continue;

                const char *tzid = icalproperty_get_tzid(prop);

                /* Expand timezone observances */
                expand_observances(vtz, start, end, &obsrecs);
                if (!dynarray_size(&obsrecs)) continue;

                /* Write timezone */
                r = store_timezone(gtzdb, tznum, tzid, obsrecs.data, obsrecs.count);
                if (r) goto done;

                /* Determine unique offsets */
                size_t j;
                for (j = 0; j < (size_t) dynarray_size(&obsrecs); j++) {
                    struct obsrec *obsrec = dynarray_nth(&obsrecs, j);
                    arrayu64_add(&uniqoffsets, obsrec->offset);
                }
                for (j = 0; j < arrayu64_size(&uniqoffsets); j++) {
                    struct offsetrec offsetrec = {
                        (int32_t) arrayu64_nth(&uniqoffsets, j), tznum
                    };
                    dynarray_append(&offsetrecs, &offsetrec);
                }
                arrayu64_truncate(&uniqoffsets, 0);
                dynarray_truncate(&obsrecs, 0);

                tznum++;
            }
        }

        if (ical) icalcomponent_free(ical);
        buf_free(&buf);
        close(fd);
    }

    /* Store offset to timezone index */
    r = store_offsets(gtzdb, offsetrecs.data, offsetrecs.count);
    if (r) goto done;

    /* Store database metadata */
    r = store_config(gtzdb);
    if (r) goto done;

done:
    arrayu64_fini(&uniqoffsets);
    dynarray_fini(&offsetrecs);
    if (fts) fts_close(fts);
    return r;
}

static void truncate_obsbefore(struct obsrec **obsp, size_t *nobsp, int64_t onset)
{
    if (*nobsp == 0) return;

    if (*nobsp >= SSIZE_MAX) {
        *nobsp = 0;
        return;
    }

    const struct obsrec *obs = *obsp;
    ssize_t n = *nobsp;
    ssize_t l = 0, r = n - 1;
    ssize_t pos = n;
    while (l <= r) {
        pos = (l + r) / 2;
        if (obs[pos].onset < onset) {
            if (pos == n - 1 || obs[pos+1].onset > onset) {
                break;
            }
            l = pos + 1;
        }
        else if (obs[pos].onset > onset) {
            r = pos - 1;
        }
        else {
            break;
        }
    }
    if (l > r) {
        *nobsp = 0;
        return;
    }

    *obsp += pos;
    *nobsp -= pos;
}

static void parse_timezone(const char *data, size_t datalen, const char **tzidp,
                           struct obsrec **obsp, size_t *nobsp, struct buf *obsbuf)
{
    *tzidp = data;
    while (*data) { data++; datalen--; }
    data++; datalen--;

    size_t nobs = datalen / 12; // 8-byte onset, 4-byte offset
    buf_truncate(obsbuf, nobs * sizeof(struct obsrec));
    struct obsrec *obs = (struct obsrec*) obsbuf->s;
    size_t i;
    for (i = 0; i < nobs; i++) {
        obs[i].onset = ntohll(*((int64_t*)data));
        data += 8;
        obs[i].offset = ntohl(*((int32_t*)data));
        data += 4;
    }

    *obsp = obs;
    *nobsp = nobs;
}

static int fetch_timezone(struct guesstzdb *gtzdb, uint32_t tznum,
                          const char **tzidp,
                          struct obsrec **obsp, size_t *nobsp)
{
    struct buf *key = &gtzdb->buf1;
    buf_reset(key);
    buf_putc(key, 'T');
    buf_appendbit32(key, tznum);

    const char *data = NULL;
    size_t datalen = 0;
    int r = cyrusdb_fetch(gtzdb->db, key->s, key->len, &data, &datalen, NULL);
    if (!r) {
        parse_timezone(data, datalen, tzidp, obsp, nobsp, &gtzdb->buf2);
    }

    return r;
}

static int fetch_offset(struct guesstzdb *gtzdb, uint32_t offset,
                        const uint32_t **tznumsp, size_t *ntznumsp)
{
    struct buf *key = &gtzdb->buf1;
    buf_reset(key);
    buf_putc(key, 'O');
    buf_appendbit32(key, offset);

    const char *data = NULL;
    size_t datalen = 0;
    int r = cyrusdb_fetch(gtzdb->db, key->s, key->len, &data, &datalen, NULL);
    if (!r) {
        uint32_t *dbtznums = (uint32_t *) data;
        size_t ntznums = datalen / 4;
        buf_truncate(&gtzdb->buf2, datalen);
        uint32_t *tznums = (uint32_t *) gtzdb->buf2.s;
        size_t i;
        for (i = 0; i < ntznums; i++) {
            tznums[i] = ntohl(dbtznums[i]);
        }
        *tznumsp = tznums;
        *ntznumsp = ntznums;
    }

    return r;
}



EXPORTED int guesstz_create(const char *zoneinfo_dir, const char *alt_fname,
                            icaltimetype start, icaltimetype end)
{
    char *myfname = NULL;
    struct db *db = NULL;
    struct txn *tid = NULL;
    int r = 0;

    if (!zoneinfo_dir) {
        zoneinfo_dir = config_getstring(IMAPOPT_ZONEINFO_DIR);
        if (!zoneinfo_dir) {
            xsyslog(LOG_ERR, "No zoneinfo_dir found in config", NULL);
            r = CYRUSDB_INTERNAL;
            goto done;
        }
    }
    const char *fname = alt_fname;
    if (!fname) {
        myfname = guesstz_fname(zoneinfo_dir, NULL);
        if (!myfname) {
            xsyslog(LOG_ERR, "Can not determine database filename",
                    "zoneinfo_dir=<%s>", zoneinfo_dir);
            r = CYRUSDB_INTERNAL;
            goto done;
        }
        fname = myfname;
    }

    /* Read zoneinfo IANA version */
    struct buf ianaversion = BUF_INITIALIZER;
    char *vfname = strconcat(zoneinfo_dir, "/version", NULL);
    FILE *fp = fopen(vfname, "r");
    if (fp) {
        char version[32];
        size_t n = fread(version, 1, 32, fp);
        if (n) {
            buf_setmap(&ianaversion, version, n);
            buf_trim(&ianaversion);
        }
    }
    fclose(fp);
    free(vfname);
    if (!buf_len(&ianaversion)) {
        buf_setcstr(&ianaversion, "unknown");
    }

    r = cyrusdb_unlink(GUESSTZDB_BACKEND, fname, 0);
    if (r && r != CYRUSDB_NOTFOUND) {
        xsyslog(LOG_ERR, "cyrusdb_unlink", "fname=<%s> err=<%s>",
                fname, cyrusdb_strerror(r));
        goto done;
    }

    r = cyrusdb_lockopen(GUESSTZDB_BACKEND, fname,
            CYRUSDB_CREATE, &db, &tid);
    if (r) {
        xsyslog(LOG_ERR, "cyrusdb_lockopen", "fname=<%s> err<%s>",
                fname, cyrusdb_strerror(r));
        goto done;
    }

    struct guesstzdb *gtzdb = xzmalloc(sizeof(struct guesstzdb));
    gtzdb->db = db;
    gtzdb->tid = tid;
    gtzdb->dbstart = start;
    gtzdb->dbend = end;
    gtzdb->fname = xstrdup(fname);
    gtzdb->ianaversion = buf_release(&ianaversion);
    gtzdb->version = guesstzdb_version;
    gtzdb->created = time(NULL);

    r = create_from_zonedir(gtzdb, zoneinfo_dir, start, end);
    if (!r) {
        r = cyrusdb_commit(db, tid);
    }
    else {
        cyrusdb_abort(db, tid);
    }
    guesstz_close(&gtzdb);

done:
    free(myfname);
    return r;
}

EXPORTED struct guesstzdb *guesstz_open(const char *alt_fname)
{
    const icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct db *db = NULL;
    struct buf key = BUF_INITIALIZER;
    const char *data = NULL;
    size_t datalen = 0;
    struct guesstzdb *gtzdb = NULL;
    const char *fname = alt_fname;

    char *myfname = NULL;
    if (!fname) {
        myfname = guesstz_fname(NULL, NULL);
        if (!myfname) return NULL;
        fname = myfname;
    }

    int r = cyrusdb_open(GUESSTZDB_BACKEND, fname, 0, &db);
    if (r) {
        xsyslog(LOG_ERR, "cyrusdb_open", "fname=<%s> err=<%s>",
                fname, cyrusdb_strerror(r));
        free(myfname);
        return NULL;
    }

    /* Fetch config */
    buf_putc(&key, 'C');
    r = cyrusdb_fetch(db, key.s, key.len, &data, &datalen, NULL);
    if (r || !datalen) {
        xsyslog(LOG_ERR, "bogus C record in database", "fname=<%s>", fname);
        goto done;
    }
    buf_reset(&key);

    /* Initialize db */
    gtzdb = xzmalloc(sizeof(struct guesstzdb));
    gtzdb->fname = xstrdup(fname);
    gtzdb->db = db;

    /* Version */
    gtzdb->version = *data;
    data++;
    datalen--;

    /* Timestamp of creation */
    gtzdb->created = *((int64_t*)(data));
    data += 8; datalen -= 8;

    /* Start and end of time range */
    int64_t tstart = *((int64_t*)(data));
    int64_t tend = *((int64_t*)(data + 8));
    data += 16; datalen -= 16;
    gtzdb->dbstart = icaltime_from_timet_with_zone(tstart, 0, utc);
    gtzdb->dbend = icaltime_from_timet_with_zone(tend, 0, utc);

    /* Zero-terminated IANA version */
    gtzdb->ianaversion = xstrdup(data);

done:
    if (r && db) {
        cyrusdb_close(db);
    }
    buf_free(&key);
    free(myfname);
    return gtzdb;
}

EXPORTED void guesstz_close(struct guesstzdb **gtzdbptr)
{
    if (!gtzdbptr || !*gtzdbptr) return;

    struct guesstzdb *gtzdb = *gtzdbptr;

    int r = cyrusdb_close(gtzdb->db);
    if (r) {
        xsyslog(LOG_ERR, "cyrusdb_close", "err=<%s>", cyrusdb_strerror(r));
    }
    free(gtzdb->ianaversion);
    free(gtzdb->fname);
    buf_free(&gtzdb->buf1);
    buf_free(&gtzdb->buf2);
    free(gtzdb);

    *gtzdbptr = NULL;
}

EXPORTED void guesstz_toiana(struct guesstzdb *gtzdb,
                             struct buf *idbuf, icalcomponent *vtz,
                             struct icalperiodtype span,
                             unsigned is_recurring)
{
    const icaltimezone *utc = icaltimezone_get_utc_timezone();
    dynarray_t obsrecs;
    dynarray_init(&obsrecs, sizeof(struct obsrec));
    struct buf key = BUF_INITIALIZER;

    static strarray_t preferred_tzids = STRARRAY_INITIALIZER;
    if (!preferred_tzids.count) {
        /* A hand-curated list of timezone names that follow
         * the typical pattern of shifting daylight savings
         * time one hour from standard time. One for (almost)
         * every offset hour */
        strarray_append(&preferred_tzids, "US/Aleutian");
        strarray_append(&preferred_tzids, "US/Alaska");
        strarray_append(&preferred_tzids, "US/Pacific");
        strarray_append(&preferred_tzids, "US/Mountain");
        strarray_append(&preferred_tzids, "US/Central");
        strarray_append(&preferred_tzids, "US/Eastern");
        strarray_append(&preferred_tzids, "America/Puerto_Rico");
        strarray_append(&preferred_tzids, "America/Nuuk");
        strarray_append(&preferred_tzids, "Atlantic/Azores");
        strarray_append(&preferred_tzids, "Europe/London");
        strarray_append(&preferred_tzids, "Europe/Berlin");
        strarray_append(&preferred_tzids, "Europe/Athens");
        strarray_append(&preferred_tzids, "Indian/Mauritius");
        strarray_append(&preferred_tzids, "Asia/Dhaka");
        strarray_append(&preferred_tzids, "Australia/Melbourne");
        strarray_append(&preferred_tzids, "Pacific/Norfolk");
    }

    buf_reset(idbuf);

    /* Calendar object must start in database time span */
    if ((icaltime_compare(span.start, gtzdb->dbstart) < 0) ||
        (icaltime_compare(span.start, gtzdb->dbend) >= 0)) {
        xsyslog(LOG_WARNING, "calendar object start outside db range",
                "start=<%s> dbrange=<%s,%s>",
                icaltime_as_ical_string(span.start),
                icaltime_as_ical_string(gtzdb->dbstart),
                icaltime_as_ical_string(gtzdb->dbend));
        goto done;
    }

    /* Limit expansion span to database time span */
    time_t span_endt = icaltime_as_timet_with_zone(span.end, utc);
    if ((is_recurring && span_endt == caldav_epoch) ||
         icaltime_compare(span.end, gtzdb->dbend) > 0) {
        span.end = gtzdb->dbend;
    }

    /* Expand timezone observances */
    expand_observances(vtz, span.start, span.end, &obsrecs);
    if (!dynarray_size(&obsrecs)) goto done;
    struct obsrec *obs = (struct obsrec *) obsrecs.data;
    size_t nobs = dynarray_size(&obsrecs);
    int64_t startonset = obs[0].onset;
    int32_t startoffset = obs[0].offset;

    /* Attempt to convert to Etc/GMT+X timezone */
    if (nobs == 1 && ((startoffset % (60*60)) == 0)) {
        if (icalcomponent_get_first_component(vtz, ICAL_XSTANDARD_COMPONENT) &&
            !icalcomponent_get_next_component(vtz, ICAL_XSTANDARD_COMPONENT) &&
            !icalcomponent_get_first_component(vtz, ICAL_XDAYLIGHT_COMPONENT)) {
            /* Timezone has a single STANDARD observance */
            buf_printf(idbuf, "Etc/GMT%+d", startoffset / (60*60));
            goto done;
        }
    }

    /* Find timezone numeric ids that match the start offset */
    const uint32_t *tznums;
    size_t ntznums;
    int r = fetch_offset(gtzdb, startoffset, &tznums, &ntznums);
    if (r) goto done;

    /* Keep copy, the next fetch operation will overwrite the db buffer */
    struct buf tznumsbuf = BUF_INITIALIZER;
    buf_setmap(&tznumsbuf, (char*) tznums, ntznums * 4);
    tznums = (const uint32_t *) tznumsbuf.s;

    /* Compare observances of custom timezone with database timezones */
    size_t i;
    for (i = 0; i < ntznums; i++) {
        uint32_t tznum = tznums[i];

        /* Fetch timezone */
        const char *tzid;
        struct obsrec *dbobs;
        size_t ndbobs;
        r = fetch_timezone(gtzdb, tznum, &tzid, &dbobs, &ndbobs);
        if (r) continue;

        /* Find minimum onset at or after startonset */
        truncate_obsbefore(&dbobs, &ndbobs, startonset);
        if (ndbobs < nobs || dbobs[0].offset != startoffset) continue;

        /* Start observance offsets match, compare remaining oberservances */
        if (nobs > 1 && ndbobs > 1) {
            size_t cmplen = nobs < ndbobs ? nobs - 1 : ndbobs - 1;
            if (memcmp(&obs[1], &dbobs[1], cmplen)) {
                continue;
            }
        }

        /* Found a match! */
        buf_setcstr(idbuf, tzid);
        if (strarray_find(&preferred_tzids, buf_cstring(idbuf), 0) >= 0) {
            break;
        }
    }
    buf_free(&tznumsbuf);

done:
    buf_free(&key);
    dynarray_fini(&obsrecs);
}

struct dump_rock {
    struct guesstzdb *gtzdb;
    hashu64_table tzbynum;
    json_t *jtzs;
    json_t *joffs;
};

static int dump_timezone(void *vrock,
                         const char *key, size_t keylen __attribute__((unused)),
                         const char *data, size_t datalen)
{
    const icaltimezone *utc = icaltimezone_get_utc_timezone();
    struct dump_rock *rock = vrock;
    struct guesstzdb *gtzdb = rock->gtzdb;

    /* Read record */
    uint32_t tznum = ntohl(*((uint32_t*)(key+1)));
    const char *tzid;
    struct obsrec *obs;
    size_t nobs;
    parse_timezone(data, datalen, &tzid, &obs, &nobs, &gtzdb->buf2);

    /* Dump observances */
    json_t *jobs = json_array();
    size_t i;
    for (i = 0; i < nobs; i++) {
        icaltimetype dt = icaltime_from_timet_with_zone(obs[i].onset, 0, utc);
        char offsetstr[8];
        format_offset(obs[i].offset, offsetstr);
        json_array_append_new(jobs, json_pack("[s s]",
                    icaltime_as_ical_string(dt), offsetstr));
    }
    json_object_set_new(rock->jtzs, tzid, jobs);

    /* Keep track of numeric identifier */
    hashu64_insert(tznum, xstrdup(tzid), &rock->tzbynum);

    return 0;
}

static int dump_offset(void *vrock,
                         const char *key, size_t keylen __attribute__((unused)),
                         const char *data, size_t datalen)
{
    struct dump_rock *rock = vrock;

    /* Format offset */
    int32_t offset = ntohl(*((int32_t*)(key+1)));
    char offsetstr[8];
    format_offset(offset, offsetstr);

    /* Dump timezone names for this offset */
    json_t *jofftzs = json_array();
    const uint32_t *tznums = (const uint32_t*)data;
    size_t ntznums = datalen / 4;
    size_t i;
    for (i = 0; i < ntznums; i++) {
        uint32_t tznum = ntohl(tznums[i]);
        const char *tzid = hashu64_lookup(tznum, &rock->tzbynum);
        if (!tzid) continue;
        json_array_append_new(jofftzs, json_string(tzid));
    }
    json_object_set_new(rock->joffs, offsetstr, jofftzs);

    return 0;
}

EXPORTED char *guesstz_dump(const char *alt_fname)
{
    struct guesstzdb *gtzdb = guesstz_open(alt_fname);
    if (!gtzdb) return NULL;
    char *val = NULL;

    struct dump_rock rock = {
        gtzdb, HASHU64_TABLE_INITIALIZER, json_object(), json_object()
    };
    construct_hashu64_table(&rock.tzbynum, 2048, 0);

    /* Dump timezone observances */
    int r = cyrusdb_foreach(gtzdb->db, "T", 1, NULL, dump_timezone, &rock, NULL);
    if (r) {
        xsyslog(LOG_ERR, "cyrusdb_foreach", "err=<%s>", cyrusdb_strerror(r));
        goto done;
    }

    /* Dump timezones by offset*/
    r = cyrusdb_foreach(gtzdb->db, "O", 1, NULL, dump_offset, &rock, NULL);
    if (r) {
        xsyslog(LOG_ERR, "cyrusdb_foreach", "err=<%s>", cyrusdb_strerror(r));
        goto done;
    }

    /* Dump version */
    const icaltimezone *utc = icaltimezone_get_utc_timezone();
    icaltimetype dt = icaltime_from_timet_with_zone(gtzdb->created, 0, utc);

    json_t *jconfig = json_object();
    json_object_set_new(jconfig, "dbVersion",
            json_integer(gtzdb->version));
    json_object_set_new(jconfig, "ianaVersion",
            json_string(gtzdb->ianaversion));
    json_object_set_new(jconfig, "rangeStart",
            json_string(icaltime_as_ical_string(gtzdb->dbstart)));
    json_object_set_new(jconfig, "rangeEnd",
            json_string(icaltime_as_ical_string(gtzdb->dbend)));
    json_object_set_new(jconfig, "createdAt",
            json_string(icaltime_as_ical_string(dt)));


    json_t *jdb = json_object();
    json_object_set_new(jdb, "config", jconfig);
    json_object_set(jdb, "timezones", rock.jtzs);
    json_object_set(jdb, "offsets", rock.joffs);
    val = json_dumps(jdb, JSON_INDENT(2)|JSON_SORT_KEYS);
    json_decref(jdb);

done:
    guesstz_close(&gtzdb);
    free_hashu64_table(&rock.tzbynum, free);
    json_decref(rock.jtzs);
    json_decref(rock.joffs);
    return val;
}

