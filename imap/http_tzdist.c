/* http_tzdist.c -- Routines for handling tzdist service requests in httpd
 *
 * Copyright (c) 1994-2014 Carnegie Mellon University.  All rights reserved.
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
 * TODO:
 * - Implement localized names / handle Accept-Language header field?
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <math.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <errno.h>

#include "global.h"
#include "hash.h"
#include "httpd.h"
#include "http_dav.h"
#include "http_proxy.h"
#include "ical_support.h"
#include "jcal.h"
#include "map.h"
#include "strhash.h"
#include "times.h"
#include "tok.h"
#include "util.h"
#include "version.h"
#include "xcal.h"
#include "xstrlcpy.h"
#include "zoneinfo_db.h"

/* generated headers are not necessarily in current directory */
#include "imap/http_err.h"
#include "imap/tz_err.h"

#define TZDIST_WELLKNOWN_URI "/.well-known/timezone"

static time_t compile_time;
static unsigned synctoken_prefix;
static ptrarray_t *leap_seconds = NULL;
static int geo_enabled = 0;
static const char *zoneinfo_dir = NULL;
static void tzdist_init(struct buf *serverinfo);
static void tzdist_shutdown(void);
static int meth_get(struct transaction_t *txn, void *params);
static int action_capa(struct transaction_t *txn);
static int action_leap(struct transaction_t *txn);
static int action_list(struct transaction_t *txn);
static int action_get(struct transaction_t *txn);
static int action_expand(struct transaction_t *txn);
static int json_response(int code, struct transaction_t *txn, json_t *root,
                         char **resp);
static int json_error_response(struct transaction_t *txn, long tz_code,
                               struct strlist *param, icaltimetype *time);
static struct buf *icaltimezone_as_tzif(icalcomponent* comp);
static struct buf *icaltimezone_as_tzif_leap(icalcomponent* comp);
static struct buf *_icaltimezone_as_tzif(icalcomponent* ical, bit32 leapcnt,
                                         icaltimetype *startp, icaltimetype *endp);

static struct mime_type_t tz_mime_types[] = {
    /* First item MUST be the default type and storage format */
    { "text/calendar; charset=utf-8", "2.0", "ics",
      (struct buf* (*)(void *)) &my_icalcomponent_as_ical_string,
      NULL, NULL, NULL, NULL
    },
    { "application/calendar+xml; charset=utf-8", NULL, "xcs",
      (struct buf* (*)(void *)) &icalcomponent_as_xcal_string,
      NULL, NULL, NULL, NULL
    },
    { "application/calendar+json; charset=utf-8", NULL, "jcs",
      (struct buf* (*)(void *)) &icalcomponent_as_jcal_string,
      NULL, NULL, NULL, NULL
    },
    { "application/tzif", NULL, NULL,
      (struct buf* (*)(void *)) &icaltimezone_as_tzif,
      NULL, NULL, NULL, NULL
    },
    { "application/tzif-leap", NULL, NULL,
      (struct buf* (*)(void *)) &icaltimezone_as_tzif_leap,
      NULL, NULL, NULL, NULL
    },
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


/* Namespace for tzdist service */
struct namespace_t namespace_tzdist = {
    URL_NS_TZDIST, 0, "tzdist", "/tzdist", TZDIST_WELLKNOWN_URI,
    http_allow_noauth, /*authschemes*/0,
    /*mbtype*/0,
    ALLOW_READ,
    tzdist_init, NULL, NULL, tzdist_shutdown, NULL,
    {
        { NULL,                 NULL },                 /* ACL          */
        { NULL,                 NULL },                 /* BIND         */
        { NULL,                 NULL },                 /* CONNECT      */
        { NULL,                 NULL },                 /* COPY         */
        { NULL,                 NULL },                 /* DELETE       */
        { &meth_get,            NULL },                 /* GET          */
        { &meth_get,            NULL },                 /* HEAD         */
        { NULL,                 NULL },                 /* LOCK         */
        { NULL,                 NULL },                 /* MKCALENDAR   */
        { NULL,                 NULL },                 /* MKCOL        */
        { NULL,                 NULL },                 /* MOVE         */
        { &meth_options,        NULL },                 /* OPTIONS      */
        { NULL,                 NULL },                 /* POST         */
        { NULL,                 NULL },                 /* PATCH        */
        { NULL,                 NULL },                 /* PROPFIND     */
        { NULL,                 NULL },                 /* PROPPATCH    */
        { NULL,                 NULL },                 /* PUT          */
        { NULL,                 NULL },                 /* REPORT       */
        { &meth_trace,          NULL },                 /* TRACE        */
        { NULL,                 NULL },                 /* UNBIND       */
        { NULL,                 NULL }                  /* UNLOCK       */
    }
};


#ifdef HAVE_SHAPELIB
#include <shapefil.h>

struct tz_shape_t {
    int valid;
    SHPHandle shp;
    DBFHandle dbf;
};

static struct tz_shape_t tz_world = { 0, NULL, NULL };
static struct tz_shape_t tz_aq    = { 0, NULL, NULL };

static void open_shape_file(struct buf *serverinfo)
{
    char buf[1024];
    int nrecords, shapetype;
    double minbound[4], maxbound[4];
    DBFFieldType fieldtype;

    buf_printf(serverinfo, " ShapeLib/%s", SHAPELIB_VERSION);

    /* Open the tz_world shape files */
    snprintf(buf, sizeof(buf), "%s%s", zoneinfo_dir, FNAME_WORLD_SHAPEFILE);
    if (!(tz_world.shp = SHPOpen(buf, "rb"))) {
        syslog(LOG_ERR, "Failed to open file %s", buf);
        return;
    }

    if (!(tz_world.dbf = DBFOpen(buf, "rb"))) {
        syslog(LOG_ERR, "Failed to open file %s", buf);
        return;
    }

    /* Sanity check the shape files */
    SHPGetInfo(tz_world.shp, &nrecords, &shapetype, minbound, maxbound);
    if (!nrecords || shapetype != SHPT_POLYGON ||       /* polygons */
        minbound[0] < -180.0 || maxbound[0] > 180.0 ||  /* longitude range */
        minbound[1] <  -90.0 || maxbound[1] >  90.0 ||  /* latitude range */
        nrecords != DBFGetRecordCount(tz_world.dbf)) {  /* record counts */
        syslog(LOG_ERR, "%s appears to contain invalid data", buf);
        return;
    }

    fieldtype = DBFGetFieldInfo(tz_world.dbf, 0 /* column 1 */, buf, NULL, NULL);
    if (fieldtype != FTString || strcasecmp(buf, "TZID")) {   /* TZIDs */
        syslog(LOG_ERR, "%s appears to contain invalid data", buf);
        return;
    }

    geo_enabled = tz_world.valid = 1;

    /* Open the tz_antarctica shape files (optional) */
    snprintf(buf, sizeof(buf), "%s%s", zoneinfo_dir, FNAME_AQ_SHAPEFILE);
    if (!(tz_aq.shp = SHPOpen(buf, "rb"))) {
        syslog(LOG_NOTICE, "Failed to open file %s", buf);
        return;
    }

    if (!(tz_aq.dbf = DBFOpen(buf, "rb"))) {
        syslog(LOG_NOTICE, "Failed to open file %s", buf);
        SHPClose(tz_aq.shp);
        return;
    }

    /* Sanity check the shape files */
    SHPGetInfo(tz_aq.shp, &nrecords, &shapetype, minbound, maxbound);
    if (!nrecords || shapetype != SHPT_POINT ||         /* points */
        minbound[0] < -180.0 || maxbound[0] > 180.0 ||  /* longitude range */
        minbound[1] <  -90.0 || maxbound[1] > -60.0 ||  /* latitude range */
        nrecords != DBFGetRecordCount(tz_aq.dbf)) {     /* record counts */
        syslog(LOG_ERR, "%s appears to contain invalid data", buf);
        return;
    }

    fieldtype = DBFGetFieldInfo(tz_aq.dbf, 1 /* column 2 */, buf, NULL, NULL);
    if (fieldtype != FTString || strcasecmp(buf, "TZID")) {  /* TZIDs */
        syslog(LOG_ERR, "%s appears to contain invalid data", buf);
        return;
    }

    tz_aq.valid = 1;
}

static void close_shape_file()
{
    if (tz_world.dbf) DBFClose(tz_world.dbf);
    if (tz_world.shp) SHPClose(tz_world.shp);
    if (tz_aq.dbf) DBFClose(tz_aq.dbf);
    if (tz_aq.shp) SHPClose(tz_aq.shp);
}

static int pt_in_poly(int nvert, double *vx, double *vy, double px, double py)
{
    int i, j, in = 0;

    for (i = 0, j = nvert - 1; i < nvert; j = i++) {
        if (((vy[i] > py) != (vy[j] > py)) &&
            (px < (vx[j] - vx[i]) * (py - vy[i]) / (vy[j] - vy[i]) + vx[i])) {
            in = !in;
        }
    }

    return in;
}


#define M_EARTH_RADIUS    6371008.7                    /* mean radius (meters) */

#define M_PI_180          0.01745329251994329547       /* pi / 180             */

#define deg2rad(deg)      (deg * M_PI_180)             /* degrees -> radians   */

#define vec_normal(v)     vec_mult(1 / vec_mag(v), v)  /* normalize vector     */

#define vec_diff(v1, v2)  acos(vec_dot_prod(v1, v2))   /* angular difference   */

struct vector {
    double x, y, z;
};

static struct vector *geo2vec(double lat, double lon, struct vector *p)
{
    /* Convert lat/lon to radians */
    lat = deg2rad(lat);
    lon = deg2rad(lon);

    /* Convert lat/lon to unit vector */
    p->x = cos(lat) * cos(lon);
    p->y = cos(lat) * sin(lon);
    p->z = sin(lat);

    return p;
}

static double vec_mag(const struct vector *v)
{
    return sqrt(v->x * v->x + v->y * v->y + v->z * v->z);
}

static struct vector *vec_mult(double m, struct vector *v)
{
    v->x *= m;
    v->y *= m;
    v->z *= m;

    return v;
}

static double vec_dot_prod(const struct vector *v1, const struct vector *v2)
{
    return (v1->x * v2->x + v1->y * v2->y + v1->z * v2->z);
}

static struct vector *vec_cross_prod(const struct vector *v1,
                                    const struct vector *v2,
                                    struct vector *r)
{
    r->x = v1->y * v2->z - v1->z * v2->y;
    r->y = v1->z * v2->x - v1->x * v2->z;
    r->z = v1->x * v2->y - v1->y * v2->x;

    return r;
}

static int pt_near_poly(int nvert, double *vx, double *vy,
                        struct vector *p, double range)
{
    int i, j;

    for (i = 0, j = nvert - 1; i < nvert; j = i++) {
        struct vector a, b, n;

        geo2vec(vy[j], vx[j], &a);
        geo2vec(vy[i], vx[i], &b);

        /* Check if either end point of the line is within range */
        if (vec_diff(p, &a) <= range || vec_diff(p, &b) <= range) return 1;

        /* Find unit normal vector (n) for plane passing through a & b */
        vec_normal(vec_cross_prod(&a, &b, &n));

        /* Shortest distance between p and geodesic passing through a & b (ab) */
        if (asin(fabs(vec_dot_prod(&n, p))) <= range) {
            struct vector c, d;
            double ab_len;

            /* Find perpendicular geodesic (d) through p to ab */
            vec_cross_prod(p, &n, &d);

            /* Find intersection point (c) of d and ab */
            vec_normal(vec_cross_prod(&n, &d, &c));

            /* Make sure intersection point (c) lies between a & b */
            ab_len = vec_diff(&a, &b);
            if (vec_diff(&a, &c) <= ab_len && vec_diff(&b, &c) <= ab_len) {
                return 1;
            }
        }
    }

    return 0;
}

static strarray_t *tzid_from_geo(struct transaction_t *txn,
                                 double latitude, double longitude,
                                 double uncertainty)
{
    strarray_t *tzids = strarray_new();
    const char *tzid;
    struct vector p, a;
    int i, npoly;
    double minbound[4], maxbound[4];

    /* using unit vectors */
    uncertainty /= M_EARTH_RADIUS;
    geo2vec(latitude, longitude, &p);  /* vector for point */
    geo2vec(-60, longitude, &a);       /* perpendicular vector to Antarctic */

    if (tz_aq.valid &&
        /* Check if point is within or near Antarctic region */
        (latitude <= -60 || (uncertainty && vec_diff(&p, &a) <= uncertainty))) {

        /* check if point is near an Antarctic base */
        double dist = uncertainty;

        if (!dist) {
            /* default to 10km radius */
            dist = 10000 / M_EARTH_RADIUS;
        }

        for (i = 0; i < tz_aq.shp->nRecords; i++) {
            SHPObject *base = SHPReadObject(tz_aq.shp, i);
            struct vector b;

            geo2vec(base->padfY[0], base->padfX[0], &b);  /* vector for base */

            if (vec_diff(&p, &b) <= dist) {
                /* Point is near a base, check if it has a known time zone */
                tzid = DBFReadStringAttribute(tz_aq.dbf, i, 1 /* column 2 */);
                if (strcmp(tzid, "unknown")) strarray_append(tzids, tzid);
            }

            SHPDestroyObject(base);

            keepalive_response(txn);
        }
    }

    /* Check if point is within or near bounding box of tz_world */
    SHPGetInfo(tz_world.shp, &npoly, NULL, minbound, maxbound);

    double WbbX[5] =
        { minbound[0], minbound[0], maxbound[0], maxbound[0], minbound[0] };
    double WbbY[5] =
        { minbound[1], maxbound[1], maxbound[1], minbound[1], minbound[1] };

    if (pt_in_poly(5, WbbX, WbbY, longitude, latitude) ||
        (uncertainty && pt_near_poly(5, WbbX, WbbY, &p, uncertainty))) {
        /* Check if point is within or near a time zone boundary */

        for (i = 0; i < npoly; i++) {
            SHPObject *poly = SHPReadObject(tz_world.shp, i);
            double bbX[5] = { poly->dfXMin, poly->dfXMin,
                              poly->dfXMax, poly->dfXMax, poly->dfXMin };
            double bbY[5] = { poly->dfYMin, poly->dfYMax,
                              poly->dfYMax, poly->dfYMin, poly->dfYMin };

            /* Check if point is within or near bounding box of boundary */
            int within = pt_in_poly(5, bbX, bbY, longitude, latitude);
            int near = uncertainty && pt_near_poly(5, bbX, bbY, &p, uncertainty);
            int r = 0;

            if (within || near) {
                if (within) {
                    /* Check if point is within boundary */
                    r = pt_in_poly(poly->nVertices, poly->padfX, poly->padfY,
                                   longitude, latitude);
                }

                if (!r && uncertainty) {
                    /* Check if point is near boundary */
                    r = pt_near_poly(poly->nVertices, poly->padfX, poly->padfY,
                                     &p, uncertainty);
                }
            }

            if (r) {
                tzid = DBFReadStringAttribute(tz_world.dbf, i, 0 /* column 1 */);
                strarray_append(tzids, tzid);
            }

            SHPDestroyObject(poly);

            keepalive_response(txn);
        }
    }

    if (!strarray_size(tzids)) {
        /* No tzids found in shapefile(s) */
        char tzid_buf[20];

        if (latitude <= -60) {
            /* Antarctic region - guess-timate offset from GMT based on:

               https://en.wikipedia.org/wiki/Time_in_Antarctica
               https://en.wikipedia.org/wiki/Territorial_claims_in_Antarctica
               https://en.wikipedia.org/wiki/Australian_Antarctic_Territory
               https://en.wikipedia.org/wiki/Queen_Maud_Land
               https://en.wikipedia.org/wiki/Princess_Martha_Coast
               https://en.wikipedia.org/wiki/Princess_Astrid_Coast
               https://en.wikipedia.org/wiki/Princess_Ragnhild_Coast
               https://en.wikipedia.org/wiki/Prince_Harald_Coast
               https://en.wikipedia.org/wiki/Prince_Olav_Coast
            */
            if (latitude <= -89 || (longitude >= 160 || longitude <= -150)) {
                /* South Pole and New Zealand Claim (Ross Dependency) */
                tzid = "Antarctica/South_Pole";
            }
            else if (longitude >= -20 && latitude <= -80) {
                /* Uninhabited */
                tzid = "Etc/GMT";
            }
            else if (longitude >= 142.033333) {     /* 142° 2' */
                /* Australian Claim (George V / Oates Lands) */
                tzid = "Etc/GMT+10";
            }
            else if (longitude >= 136.183333) {     /* 136° 11' */
                /* French Claim (Adelie Land) */
                tzid = "Etc/GMT+10";
            }
            else if (longitude >= 44.633333) {      /*  44° 38' */
                /* Australian Claim */
                if (longitude >= 100.5) {           /* 100° 30' */
                    /* Wilkes Land */
                    tzid = "Etc/GMT+8";
                }
                else if (longitude >= 72.583333) {  /*  72° 35' */
                    /* Princess Elizabeth / Kaiser Wilhelm II / Queen Mary Lands */
                    tzid = "Etc/GMT+7";
                }
                else {
                    /* Enderby / Kemp / Mac. Robertson Lands */
                    tzid = "Etc/GMT+6";
                }
            }
            else if (longitude >= -20) {
                /* Norwegian Claim (Queen Maud Land) */
                if (longitude >= 20) {
                    /* Princess Ragnhild / Prince Harald / Prince Olav Coasts */
                    tzid = "Etc/GMT+3";
                }
                else {
                    /* Princess Martha / Princess Astrid Coasts */
                    tzid = "Etc/GMT";
                }
            }
            else if (longitude >= -90) {
                /* British / Argentine / Chilean Claims */
                if (longitude >= -74) {
                    /* Argentine / British Claims */
                    tzid = "Etc/GMT-3";
                }
                /* XXX  Is there a GMT-4 + DST region? */
                else {
                    /* Chilean / British Claims */
                    tzid = "Etc/GMT-4";
                }
            }
            else {
                /* Unclaimed */
                if (latitude <= -80) {
                    /* Uninhabited */
                    tzid = "Etc/GMT";
                }
                else tzid = "Etc/GMT-6";
            }
        }
        else {
            /* Assume international waters - 
               calculate offset from GMT based on longitude

               XXX  Which offset does an exact multiple of +/- 7.5
               and +/- 180 degrees belong to?
            */
            snprintf(tzid_buf, sizeof(tzid_buf), "Etc/GMT%+d",
                    (short) (longitude + copysign(1.0, longitude) * 7.5) / 15);
            tzid = tzid_buf;
        }

        strarray_append(tzids, tzid);
    }

    return tzids;
}
#else

static void open_shape_file(struct buf *serverinfo __attribute__((unused)))
{
    return;
}

static void close_shape_file()
{
    return;
}

static strarray_t *tzid_from_geo(struct transaction_t *txn __attribute__((unused)),
                                 double latitude __attribute__((unused)),
                                 double longitude __attribute__((unused)),
                                 double uncertainty __attribute__((unused)))
{
    return NULL;
}

#endif /* HAVE_SHAPELIB */


struct leapsec {
    long long int t;      /* transition time */
    long int sec;         /* leap seconds */
};

static void read_leap_seconds()
{
    FILE *fp;
    char buf[1024];
    struct leapsec *leap;

    snprintf(buf, sizeof(buf), "%s%s", zoneinfo_dir, FNAME_LEAPSECFILE);
    if (!(fp = fopen(buf, "r"))) {
        syslog(LOG_ERR, "Failed to open file %s", buf);
        return;
    }

    /* expires record is always at idx=0, if exists */
    leap_seconds = ptrarray_new();
    leap = xzmalloc(sizeof(struct leapsec));
    ptrarray_append(leap_seconds, leap);

    while (fgets(buf, sizeof(buf), fp)) {
        if (buf[0] == '#') {
            /* comment line */

            if (buf[1] == '@') {
                /* expires */
                leap = ptrarray_nth(leap_seconds, 0);
                sscanf(buf+2, "\t%lld", &leap->t);
                leap->t -= NIST_EPOCH_OFFSET;
            }
        }
        else if (isdigit(buf[0])) {
            /* leap second */
            leap = xmalloc(sizeof(struct leapsec));
            ptrarray_append(leap_seconds, leap);
            sscanf(buf, "%lld\t%ld", &leap->t, &leap->sec);
            leap->t -= NIST_EPOCH_OFFSET;
        }
    }
    fclose(fp);
}


static void tzdist_init(struct buf *serverinfo __attribute__((unused)))
{
    struct buf buf = BUF_INITIALIZER;

    namespace_tzdist.enabled =
        config_httpmodules & IMAP_ENUM_HTTPMODULES_TZDIST;

    if (!namespace_tzdist.enabled) return;

    /* Open zoneinfo db */
    if (zoneinfo_open(NULL)) {
        namespace_tzdist.enabled = 0;
        return;
    }

    /* Find configured zoneinfo_zir */
    zoneinfo_dir = config_getstring(IMAPOPT_ZONEINFO_DIR);
    if (!zoneinfo_dir) {
        syslog(LOG_ERR, "zoneinfo_dir must be set for tzdist service");
        namespace_tzdist.enabled = 0;
        return;
    }

    compile_time = calc_compile_time(__TIME__, __DATE__);

    buf_printf(&buf, "Cyrus TZdist: %s", config_servername);
    synctoken_prefix = strhash(buf_cstring(&buf));
    buf_free(&buf);

    initialize_tz_error_table();

    open_shape_file(serverinfo);

    read_leap_seconds();
    if (!leap_seconds || leap_seconds->count < 2) {
        /* Disable application/tzif-leap */
        struct mime_type_t *mime;

        for (mime = tz_mime_types; mime->content_type; mime++) {
            if (!strcmp(mime->content_type, "application/tzif-leap")) {
                mime->content_type = NULL;
                break;
            }
        }
    }
}


static void tzdist_shutdown(void)
{
    struct leapsec *leap;

    zoneinfo_close(NULL);

    close_shape_file();

    if (!leap_seconds) return;

    while ((leap = ptrarray_pop(leap_seconds))) free(leap);
    ptrarray_free(leap_seconds);
}


/* Perform a GET/HEAD request */
static int meth_get(struct transaction_t *txn,
                    void *params __attribute__((unused)))
{
    struct request_target_t *tgt = &txn->req_tgt;
    int (*action)(struct transaction_t *txn) = NULL;
    unsigned levels = 0;
    char *p;

    /* Make a working copy of target path */
    strlcpy(tgt->path, txn->req_uri->path, sizeof(tgt->path));
    p = tgt->path;

    /* Skip namespace */
    p += strlen(namespace_tzdist.prefix);
    if (*p == '/') *p++ = '\0';

    /* Check for path after prefix */
    if (*p) {
        /* Get collection (action) */
        tgt->collection = p;
        p += strcspn(p, "/");
        if (*p == '/') *p++ = '\0';

        if (!strcmp(tgt->collection, "capabilities")) {
            if (!*p) action = &action_capa;
        }
        else if (!strcmp(tgt->collection, "leapseconds")) {
            if (!*p) action = &action_leap;
        }
        else if (!strcmp(tgt->collection, "zones")) {
            if (!*p) {
                action = &action_list;
            }
            else {
                /* Get resource (tzid) */
                tgt->resource = p;
                p += strlen(p);
                if (p[-1] == '/') *--p = '\0';

                /* Check for sub-action */
                p = strstr(tgt->resource, "observances");
                if (!p) {
                    action = &action_get;
                }
                else if (p[-1] == '/') {
                    *--p = '\0';
                    action = &action_expand;
                }

                /* XXX  Hack - probably need to check for %2F vs '/'
                   Count the number of "levels".  Current tzid have max of 3. */
                for (p = tgt->resource; p && ++levels; (p = strchr(p+1, '/')));
            }
        }
    }

    if (!action || levels > 3)
        return json_error_response(txn, TZ_INVALID_ACTION, NULL, NULL);

    if (tgt->resource && strchr(tgt->resource, '.'))  /* paranoia */
        return json_error_response(txn, TZ_NOT_FOUND, NULL, NULL);

    return action(txn);
}


/* Perform a capabilities action */
static int action_capa(struct transaction_t *txn)
{
    int precond;
    struct message_guid guid;
    const char *etag;
    static time_t lastmod = 0;
    static char *resp = NULL;
    json_t *root = NULL;

    /* Generate ETag based on compile date/time of this source file.
     * Extend this to include config file size/mtime if we add run-time options.
     */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, TIME_T_FMT, compile_time);
    message_guid_generate(&guid, buf_cstring(&txn->buf), buf_len(&txn->buf));
    etag = message_guid_encode(&guid);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, etag, compile_time);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
        /* Fill in Etag,  Last-Modified, Expires */
        txn->resp_body.etag = etag;
        txn->resp_body.lastmod = compile_time;
        txn->resp_body.maxage = 86400;  /* 24 hrs */
        txn->flags.cc |= CC_MAXAGE;
        if (!httpd_userisanonymous) txn->flags.cc |= CC_PUBLIC;

        if (precond != HTTP_NOT_MODIFIED) break;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        return precond;
    }

    if (txn->resp_body.lastmod > lastmod) {
        struct zoneinfo info;
        struct mime_type_t *mime;
        json_t *formats;

        /* Get info record from the database */
        if (zoneinfo_lookup_info(&info)) return HTTP_SERVER_ERROR;

        buf_reset(&txn->buf);
        buf_printf(&txn->buf, "%s:%s", info.data->s, info.data->next->s);

        /* Construct our response */
        root = json_pack("{ s:i"                        /* version */
                         "  s:{"                        /* info */
                         "      s:s"                    /*   primary-source */
                         "      s:[]"                   /*   formats */
                         "      s:{s:b s:b}"            /*   truncated */
//                       "      s:s"                    /*   provider-details */
//                       "      s:[]"                   /*   contacts */
                         "    }"
                         "  s:["                        /* actions */
                         "    {s:s s:s s:["             /*   capabilities */
                         "    ]}"
                         "    {s:s s:s s:["             /*   list */
                         "      {s:s}"                  /*     changedsince */
                         "    ]}"
                         "    {s:s s:s s:["             /*   get */
                         "      {s:s}"                  /*     start */
                         "      {s:s}"                  /*     end */
                         "    ]}"
                         "    {s:s s:s s:["             /*   expand */
                         "      {s:s s:b}"              /*     start */
                         "      {s:s s:b}"              /*     end */
                         "    ]}"
                         "    {s:s s:s s:["             /*   find */
                         "      {s:s s:b}"              /*     pattern */
                         "    ]}"
                         "    {s:s s:s s:["             /*   leapseconds */
                         "    ]}"
                         "  ]}",

                         "version", 1,

                         "info",
                         "primary-source", buf_cstring(&txn->buf), "formats",
                         "truncated", "any", 1, "untruncated", 1,
//                       "provider-details", "", "contacts",

                         "actions",
                         "name", "capabilities",
                         "uri-template", "/capabilities", "parameters",

                         "name", "list",
                         "uri-template", "/zones{?changedsince}", "parameters",
                         "name", "changedsince",

                         "name", "get", "uri-template",
                         "/zones{/tzid}{?start,end}", "parameters",
                         "name", "start",
                         "name", "end",

                         "name", "expand", "uri-template",
                         "/zones{/tzid}/observances{?start,end}",
                         "parameters",
                         "name", "start", "required", 1,
                         "name", "end", "required", 1,

                         "name", "find",
                         "uri-template", "/zones{?pattern}", "parameters",
                         "name", "pattern", "required", 1,

                         "name", "leapseconds",
                         "uri-template", "/leapseconds", "parameters");

        freestrlist(info.data);

        if (!root) {
            txn->error.desc = "Unable to create JSON response";
            return HTTP_SERVER_ERROR;
        }

        if (geo_enabled) {
            /* Add geolocate action */
            json_t *actions = json_object_get(root, "actions");

            json_array_append_new(actions,
                                  json_pack("{s:s s:s s:["
                                            "  {s:s s:b}"
                                            "]}",
                                            "name", "geolocate", "uri-template",
                                            "/zones{?location}",
                                            "parameters",
                                            "name", "location", "required", 1));
        }

        /* Add supported formats */
        formats = json_object_get(json_object_get(root, "info"), "formats");
        for (mime = tz_mime_types; mime->content_type; mime++) {
            buf_setcstr(&txn->buf, mime->content_type);
            buf_truncate(&txn->buf, strcspn(mime->content_type, ";"));
            json_array_append_new(formats, json_string(buf_cstring(&txn->buf)));
        }
        buf_reset(&txn->buf);

        /* Update lastmod */
        lastmod = txn->resp_body.lastmod;
    }

    /* Output the JSON object */
    return json_response(precond, txn, root, &resp);
}

/* Perform a leapseconds action */
static int action_leap(struct transaction_t *txn)
{
    int r, ret = 0, precond;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct zoneinfo info, leap;

    /* Get info record from the database */
    if (zoneinfo_lookup_info(&info)) return HTTP_SERVER_ERROR;

    /* Get leap record from the database */
    if ((r = zoneinfo_lookup_leap(&leap))) {
        ret = (r == CYRUSDB_NOTFOUND ? HTTP_NOT_FOUND : HTTP_SERVER_ERROR);
        goto done;
    }

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, leap.data->s, leap.dtstamp);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
        /* Fill in ETag, Last-Modified, and Expires */
        resp_body->etag = leap.data->s;
        resp_body->lastmod = leap.dtstamp;
        resp_body->maxage = 86400;  /* 24 hrs */
        txn->flags.cc |= CC_MAXAGE | CC_REVALIDATE;
        if (!httpd_userisanonymous) txn->flags.cc |= CC_PUBLIC;

        if (precond != HTTP_NOT_MODIFIED) break;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        resp_body->type = NULL;
        ret = precond;
        goto done;
    }


    if (txn->meth != METH_HEAD) {
        json_t *root, *expires, *leapseconds;
        struct leapsec *leapsec;
        char buf[1024];
        int n;

        if (!leap_seconds) {
            ret = HTTP_NOT_FOUND;
            goto done;
        }

        /* Construct our response */
        root = json_pack("{s:s s:s s:s s:[]}",
                         "expires", "", "publisher", info.data->s,
                         "version", info.data->next->s, "leapseconds");
        if (!root) {
            txn->error.desc = "Unable to create JSON response";
            ret = HTTP_SERVER_ERROR;
            goto done;
        }

        expires = json_object_get(root, "expires");
        leapseconds = json_object_get(root, "leapseconds");

        leapsec = ptrarray_nth(leap_seconds, 0);
        if (leapsec->t) {
            time_to_rfc3339(leapsec->t, buf, 11 /* clip time */);
            json_string_set(expires, buf);
        }

        for (n = 1; n < leap_seconds->count; n++) {
            json_t *leap;

            leapsec = ptrarray_nth(leap_seconds, n);
            time_to_rfc3339(leapsec->t, buf, 11 /* clip time */);
            leap = json_pack("{s:i s:s}",
                             "utc-offset", leapsec->sec, "onset", buf);
            json_array_append_new(leapseconds, leap);
        }

        /* Output the JSON object */
        ret = json_response(precond, txn, root, NULL);
    }

  done:
    freestrlist(leap.data);
    freestrlist(info.data);
    return ret;
}


struct list_rock {
    struct strlist *meta;
    json_t *tzarray;
    struct hash_table *tztable;
};

static int list_cb(const char *tzid, int tzidlen,
                   struct zoneinfo *zi, void *rock)
{
    struct list_rock *lrock = (struct list_rock *) rock;
    char tzidbuf[200], etag[32], lastmod[RFC3339_DATETIME_MAX];
    json_t *tz;

    snprintf(tzidbuf, sizeof(tzidbuf), "%.*s", tzidlen, tzid);

    if (lrock->tztable) {
        if (hash_lookup(tzidbuf, lrock->tztable)) return 0;
        hash_insert(tzidbuf, (void *) 0xDEADBEEF, lrock->tztable);
    }

    sprintf(etag, "%u-" TIME_T_FMT, strhash(tzidbuf), zi->dtstamp);
    time_to_rfc3339(zi->dtstamp, lastmod, RFC3339_DATETIME_MAX);

    tz = json_pack("{s:s s:s s:s s:s s:s}",
                   "tzid", tzidbuf, "etag", etag, "last-modified", lastmod,
                   "publisher", lrock->meta->s, "version", lrock->meta->next->s);
    json_array_append_new(lrock->tzarray, tz);

    if (zi->data) {
        struct strlist *sl;
        json_t *aliases = json_array();

        json_object_set_new(tz, "aliases", aliases);

        for (sl = zi->data; sl; sl = sl->next)
            json_array_append_new(aliases, json_string(sl->s));
    }

    return 0;
}

/* Perform a list action */
static int action_list(struct transaction_t *txn)
{
    int ret, precond;
    struct strlist *param;
    const char *pattern = NULL;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct zoneinfo info;
    time_t changedsince = 0, lastmod;
    double latitude = 99.9, longitude = 0.0;
    double altitude = 0.0, uncertainty = 0.0;
    strarray_t *geo_tzids = NULL;
    json_t *root = NULL;

    /* Get info record from the database */
    if (zoneinfo_lookup_info(&info)) return HTTP_SERVER_ERROR;

    /* Sanity check the parameters */
    if ((param = hash_lookup("pattern", &txn->req_qparams))) {
        if (param->next                   /* once only */
            || !param->s || !*param->s    /* not empty */
            || strspn(param->s, "*") == strlen(param->s)) {  /* not (*)+ */
            return json_error_response(txn, TZ_INVALID_PATTERN, param, NULL);
        }
        pattern = param->s;
    }
    else if (geo_enabled &&
             (param = hash_lookup("location", &txn->req_qparams))) {
        /* Parse 'geo' URI */
        char *endptr;

        if (param->next                         /* once only */
            || strncmp(param->s, "geo:", 4)) {  /* value value */
            return json_error_response(txn, TZ_INVALID_LOCATION, param, NULL);
        }

        latitude = strtod(param->s + 4, &endptr);
        if (errno || *endptr != ','
            || latitude < -90.0 || latitude > 90.0) {  /* valid value */ 
            return json_error_response(txn, TZ_INVALID_LOCATION, param, NULL);
        }

        longitude = strtod(++endptr, &endptr);
        if (errno || (*endptr && !strchr(",;", *endptr))
            || longitude < -180.0 || longitude > 180.0) {  /* valid value */ 
            return json_error_response(txn, TZ_INVALID_LOCATION, param, NULL);
        }

        if (*endptr == ',') {
            altitude = strtod(++endptr, &endptr);
            if (*endptr && *endptr != ';') {  /* valid value */
                return json_error_response(txn, TZ_INVALID_LOCATION, param, NULL);
            }
            (void) altitude;
        }

        if (!strncmp(endptr, ";crs=", 5)) {
            char *crs = endptr + 5;
            size_t len = strcspn(crs, ";");

            if (len != 5 || strncmp(crs, "wgs84", 5)) {  /* unsupported value */
                return json_error_response(txn, TZ_INVALID_LOCATION, param, NULL);
            }
            endptr = crs + len;
        }

        if (!strncmp(endptr, ";u=", 3)) {
            uncertainty = strtod(endptr + 3, &endptr);
            if (errno || uncertainty < 0) {  /* valid value */ 
                return json_error_response(txn, TZ_INVALID_LOCATION, param, NULL);
            }
        }

        if (*endptr && *endptr != ';') {  /* valid value */
            return json_error_response(txn, TZ_INVALID_LOCATION, param, NULL);
        }
    }
    else if ((param = hash_lookup("changedsince", &txn->req_qparams))) {
        unsigned prefix = 0;

        if (param->next) {  /* once only */
            return json_error_response(txn, TZ_INVALID_CHANGEDSINCE,
                                       param, NULL);
        }

        /* Parse and sanity check the changedsince token */
        sscanf(param->s, "%u-" TIME_T_FMT, &prefix, &changedsince);
        if (prefix != synctoken_prefix || changedsince > info.dtstamp) {
            changedsince = 0;
        }
    }
    else if (hash_numrecords(&txn->req_qparams)) {
        return json_error_response(txn, TZ_INVALID_ACTION, NULL, NULL);
    }

    /* Generate ETag & Last-Modified from info record */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%u-" TIME_T_FMT, synctoken_prefix, info.dtstamp);
    lastmod = info.dtstamp;

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, buf_cstring(&txn->buf), lastmod);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
        /* Fill in ETag, Last-Modified, and Expires */
        resp_body->etag = buf_cstring(&txn->buf);
        resp_body->lastmod = lastmod;
        resp_body->maxage = 86400;  /* 24 hrs */
        txn->flags.cc |= CC_MAXAGE | CC_REVALIDATE;
        if (!httpd_userisanonymous) txn->flags.cc |= CC_PUBLIC;

        if (precond != HTTP_NOT_MODIFIED) break;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        resp_body->type = NULL;
        ret = precond;
        goto done;
    }


    if (txn->meth != METH_HEAD) {
        struct list_rock lrock = { NULL, NULL, NULL };
        struct hash_table tzids = HASH_TABLE_INITIALIZER;
        int i = 0;

        /* Start constructing our response */
        root = json_pack("{s:s s:[]}",
                         "synctoken", resp_body->etag, "timezones");
        if (!root) {
            txn->error.desc = "Unable to create JSON response";
            ret = HTTP_SERVER_ERROR;
            goto done;
        }

        lrock.meta = info.data;
        lrock.tzarray = json_object_get(root, "timezones");

        if (latitude <= 90) {
            geo_tzids = tzid_from_geo(txn, latitude, longitude, uncertainty);
            pattern = strarray_nth(geo_tzids, 0);
            if (!pattern) pattern = "/";  /* force lookup failure */
        }

        if (pattern) {
            construct_hash_table(&tzids, 500, 1);
            lrock.tztable = &tzids;
        }

        /* Add timezones to array */
        do {
            zoneinfo_find(pattern, !pattern, changedsince, &list_cb, &lrock);

        } while (geo_tzids && (pattern = strarray_nth(geo_tzids, ++i)));

        free_hash_table(&tzids, NULL);
    }

    /* Output the JSON object */
    ret = json_response(precond, txn, root, NULL);

  done:
    strarray_free(geo_tzids);
    freestrlist(info.data);
    return ret;
}


/* Perform a get action */
static int action_get(struct transaction_t *txn)
{
    int r, precond;
    struct strlist *param;
    const char *tzid = txn->req_tgt.resource;
    struct zoneinfo zi;
    time_t lastmod;
    icaltimetype start = icaltime_null_time(), end = icaltime_null_time();
    char *data = NULL;
    unsigned long datalen = 0;
    struct resp_body_t *resp_body = &txn->resp_body;
    struct mime_type_t *mime = NULL;
    const char **hdr;

    /* Check/find requested MIME type:
       1st entry in gparams->mime_types array MUST be default MIME type */
    if ((param = hash_lookup("format", &txn->req_qparams))) {
        for (mime = tz_mime_types;
             mime->content_type && !is_mediatype(mime->content_type, param->s);
             mime++);
    }
    else if ((hdr = spool_getheader(txn->req_hdrs, "Accept")))
        mime = get_accept_type(hdr, tz_mime_types);
    else mime = tz_mime_types;

    if (!mime || !mime->content_type)
        return json_error_response(txn, TZ_INVALID_FORMAT, NULL, NULL);

    /* Sanity check the parameters */
    if ((param = hash_lookup("start", &txn->req_qparams))) {
        start = icaltime_from_string(param->s);
        if (param->next || !icaltime_is_utc(start)) {  /* once only, UTC */
            return json_error_response(txn, TZ_INVALID_START, param, &start);
        }
    }

    if ((param = hash_lookup("end", &txn->req_qparams))) {
        end = icaltime_from_string(param->s);
        if (param->next || !icaltime_is_utc(end)  /* once only, UTC */
            || icaltime_compare(end, start) <= 0) {  /* end MUST be > start */
            return json_error_response(txn, TZ_INVALID_END, param, &end);
        }
    }

    /* Get info record from the database */
    if ((r = zoneinfo_lookup(tzid, &zi))) {
        return (r == CYRUSDB_NOTFOUND ?
                json_error_response(txn, TZ_NOT_FOUND, NULL, NULL)
                : HTTP_SERVER_ERROR);
    }

    /* Generate ETag & Last-Modified from info record */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%u-" TIME_T_FMT, strhash(tzid), zi.dtstamp);
    lastmod = zi.dtstamp;
    freestrlist(zi.data);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, buf_cstring(&txn->buf), lastmod);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
        /* Fill in Content-Type, ETag, Last-Modified, and Expires */
        resp_body->type = mime->content_type;
        resp_body->etag = buf_cstring(&txn->buf);
        resp_body->lastmod = lastmod;
        resp_body->maxage = 86400;  /* 24 hrs */
        txn->flags.cc |= CC_MAXAGE | CC_REVALIDATE;
        if (!httpd_userisanonymous) txn->flags.cc |= CC_PUBLIC;

        if (precond != HTTP_NOT_MODIFIED) break;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        resp_body->type = NULL;
        return precond;
    }


    if (txn->meth != METH_HEAD) {
        static struct buf pathbuf = BUF_INITIALIZER;
        const char *p, *path, *proto, *host, *msg_base = NULL;
        size_t msg_size = 0;
        icalcomponent *ical, *vtz;
        icalproperty *prop;
        struct buf *buf = NULL;
        int fd;

        /* Open, mmap, and parse the file */
        buf_reset(&pathbuf);
        buf_printf(&pathbuf, "%s/%s.ics", zoneinfo_dir, tzid);
        path = buf_cstring(&pathbuf);
        if ((fd = open(path, O_RDONLY)) == -1) return HTTP_SERVER_ERROR;

        map_refresh(fd, 1, &msg_base, &msg_size, MAP_UNKNOWN_LEN, path, NULL);
        if (!msg_base) return HTTP_SERVER_ERROR;

        ical = icalparser_parse_string(msg_base);
        map_free(&msg_base, &msg_size);
        close(fd);

        vtz = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
        prop = icalcomponent_get_first_property(vtz, ICAL_TZID_PROPERTY);

        if ((zi.type == ZI_LINK) &&
            !icalcomponent_get_first_property(vtz, ICAL_TZIDALIASOF_PROPERTY)) {
            /* Add TZID-ALIAS-OF */
            const char *aliasof = icalproperty_get_tzid(prop);
            icalproperty *atzid = icalproperty_new_tzidaliasof(aliasof);

            icalcomponent_add_property(vtz, atzid);

            /* Substitute TZID alias */
            icalproperty_set_tzid(prop, tzid);
        }

        /* Start constructing TZURL */
        buf_reset(&pathbuf);
        http_proto_host(txn->req_hdrs, &proto, &host);
        buf_printf(&pathbuf, "%s://%s%s/zones/",
                   proto, host, namespace_tzdist.prefix);

        /* Escape '/' and ' ' in tzid */
        for (p = tzid; *p; p++) {
            switch (*p) {
            case '/':
            case ' ':
                buf_printf(&pathbuf, "%%%02X", *p);
                break;

            default:
                buf_putc(&pathbuf, *p);
                break;
            }
        }

        if (!icaltime_is_null_time(start) || !icaltime_is_null_time(end)) {

            if (!icaltime_is_null_time(end)) {
                /* Add TZUNTIL to VTIMEZONE */
                icalproperty *tzuntil = icalproperty_new_tzuntil(end);
                icalcomponent_add_property(vtz, tzuntil);
            }

            /* Add truncation parameter(s) to TZURL */
            buf_printf(&pathbuf, "?%s", URI_QUERY(txn->req_uri));

            if (!strncmp(mime->content_type, "application/tzif", 16)) {
                /* Truncate and convert the VTIMEZONE */
                bit32 leapcnt = 0;

                if (!strcmp(mime->content_type + 16, "-leap"))
                    leapcnt = leap_seconds->count - 2;

                buf =_icaltimezone_as_tzif(ical, leapcnt, &start, &end);
            }
            else {
                /* Truncate the VTIMEZONE */
                icaltimezone_truncate_vtimezone_advanced(vtz, &start, &end,
                        NULL, NULL, NULL, NULL, NULL, 0);
            }
        }

        /* Set TZURL property */
        prop = icalproperty_new_tzurl(buf_cstring(&pathbuf));
        icalcomponent_add_property(vtz, prop);

        /* Convert to requested MIME type */
        if (!buf) buf = mime->from_object(ical);
        datalen = buf_len(buf);
        data = buf_release(buf);
        buf_destroy(buf);

        /* Set Content-Disposition filename */
        buf_setcstr(&pathbuf, tzid);
        if (mime->file_ext) buf_printf(&pathbuf, ".%s", mime->file_ext);
        resp_body->dispo.fname = buf_cstring(&pathbuf);

        txn->flags.vary |= VARY_ACCEPT;

        icalcomponent_free(ical);
    }

    write_body(precond, txn, data, datalen);

    if (data) free(data);

    return 0;
}


#define CTIME_FMT "%s %s %2d %02d:%02d:%02d %4d"
#define CTIME_ARGS(tt) \
    wday[icaltime_day_of_week(tt)-1], monthname[tt.month-1], \
    tt.day, tt.hour, tt.minute, tt.second, tt.year


/* Perform an expand action */
static int action_expand(struct transaction_t *txn)
{
    int r, precond, zdump = 0;
    struct strlist *param;
    const char *tzid = txn->req_tgt.resource;
    struct zoneinfo zi;
    time_t lastmod;
    icaltimetype start, end;
    struct resp_body_t *resp_body = &txn->resp_body;
    json_t *root = NULL;

    /* Sanity check the parameters */
    param = hash_lookup("start", &txn->req_qparams);
    if (!param || param->next)  /* mandatory, once only */
        return json_error_response(txn, TZ_INVALID_START, param, NULL);

    start = icaltime_from_string(param->s);
    if (!icaltime_is_utc(start))  /* MUST be UTC */
        return json_error_response(txn, TZ_INVALID_START, param, &start);

    param = hash_lookup("end", &txn->req_qparams);
    if (!param || param->next)  /* mandatory, once only */
        return json_error_response(txn, TZ_INVALID_END, param, NULL);

    end = icaltime_from_string(param->s);
    if (!icaltime_is_utc(end)  /* MUST be UTC */
        || icaltime_compare(end, start) <= 0) {  /* end MUST be > start */
        return json_error_response(txn, TZ_INVALID_END, param, &end);
    }

    /* Check requested format (debugging only) */
    if ((param = hash_lookup("format", &txn->req_qparams)) &&
        !strcmp(param->s, "application/zdump")) {
        /* Mimic zdump(8) -V output for comparison:

           For each zonename, print the times both one  second  before  and
           exactly at each detected time discontinuity, the time at one day
           less than the highest possible time value, and the time  at  the
           highest  possible  time value.  Each line is followed by isdst=D
           where D is positive, zero, or negative depending on whether  the
           given time is daylight saving time, standard time, or an unknown
           time type, respectively.  Each line is also followed by gmtoff=N
           if  the given local time is known to be N seconds east of Green‐
           wich.
        */
        zdump = 1;
    }

    /* Get info record from the database */
    if ((r = zoneinfo_lookup(tzid, &zi))) {
        return (r == CYRUSDB_NOTFOUND ?
                json_error_response(txn, TZ_NOT_FOUND, NULL, NULL)
                : HTTP_SERVER_ERROR);
    }

    /* Generate ETag & Last-Modified from info record */
    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, "%u-" TIME_T_FMT, strhash(tzid), zi.dtstamp);
    lastmod = zi.dtstamp;
    freestrlist(zi.data);

    /* Check any preconditions, including range request */
    txn->flags.ranges = 1;
    precond = check_precond(txn, buf_cstring(&txn->buf), lastmod);

    switch (precond) {
    case HTTP_OK:
    case HTTP_PARTIAL:
    case HTTP_NOT_MODIFIED:
        /* Fill in ETag, Last-Modified, and Expires */
        resp_body->etag = buf_cstring(&txn->buf);
        resp_body->lastmod = lastmod;
        resp_body->maxage = 86400;  /* 24 hrs */
        txn->flags.cc |= CC_MAXAGE | CC_REVALIDATE;
        if (!httpd_userisanonymous) txn->flags.cc |= CC_PUBLIC;

        if (precond != HTTP_NOT_MODIFIED) break;

        GCC_FALLTHROUGH

    default:
        /* We failed a precondition - don't perform the request */
        resp_body->type = NULL;
        return precond;
    }


    if (txn->meth != METH_HEAD) {
        static struct buf pathbuf = BUF_INITIALIZER;
        const char *path, *msg_base = NULL;
        size_t msg_size = 0;
        icalcomponent *ical, *vtz;
        struct observance proleptic;
        icalarray *obsarray;
        json_t *jobsarray;
        unsigned n;
        int fd;

        /* Open, mmap, and parse the file */
        buf_reset(&pathbuf);
        buf_printf(&pathbuf, "%s/%s.ics", zoneinfo_dir, tzid);
        path = buf_cstring(&pathbuf);
        if ((fd = open(path, O_RDONLY)) == -1) return HTTP_SERVER_ERROR;

        map_refresh(fd, 1, &msg_base, &msg_size, MAP_UNKNOWN_LEN, path, NULL);
        if (!msg_base) return HTTP_SERVER_ERROR;

        ical = icalparser_parse_string(msg_base);
        map_free(&msg_base, &msg_size);
        close(fd);


        /* Create an array of observances */
        obsarray = icalarray_new(sizeof(struct observance), 20);
        vtz = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
        icaltimezone_truncate_vtimezone_advanced(vtz, &start, &end, obsarray,
                &proleptic, NULL, NULL, NULL, 0);


        if (zdump) {
            struct buf *body = &txn->resp_body.payload;
            struct icaldurationtype off = icaldurationtype_null_duration();
            const char *prev_name = proleptic.name;
            int prev_isdst = proleptic.is_daylight;

            for (n = 0; n < obsarray->num_elements; n++) {
                struct observance *obs = icalarray_element_at(obsarray, n);
                struct icaltimetype local, ut;

                /* Skip any no-ops as zdump doesn't output them */
                if (obs->offset_from == obs->offset_to
                    && prev_isdst == obs->is_daylight
                    && !strcmp(prev_name, obs->name)) continue;

                /* UT and local time 1 second before onset */
                off.seconds = -1;
                ut = icaltime_add(obs->onset, off);

                off.seconds = obs->offset_from;
                local = icaltime_add(ut, off);

                buf_printf(body,
                           "%s  " CTIME_FMT " UT = " CTIME_FMT " %s"
                           " isdst=%d gmtoff=%d\n",
                           tzid, CTIME_ARGS(ut), CTIME_ARGS(local),
                           prev_name, prev_isdst, obs->offset_from);

                /* UT and local time at onset */
                icaltime_adjust(&ut, 0, 0, 0, 1);

                off.seconds = obs->offset_to;
                local = icaltime_add(ut, off);

                buf_printf(body,
                           "%s  " CTIME_FMT " UT = " CTIME_FMT " %s"
                           " isdst=%d gmtoff=%d\n",
                           tzid, CTIME_ARGS(ut), CTIME_ARGS(local),
                           obs->name, obs->is_daylight, obs->offset_to);

                prev_name = obs->name;
                prev_isdst = obs->is_daylight;
            }
        }
        else {
            /* Start constructing our response */
            root = json_pack("{s:s}", "tzid", tzid);
            if (!root) {
                txn->error.desc = "Unable to create JSON response";
                return HTTP_SERVER_ERROR;
            }

            json_object_set_new(root, "start",
                                json_string(icaltime_as_iso_string(start)));
            json_object_set_new(root, "end",
                                json_string(icaltime_as_iso_string(end)));

            /* Add observances to JSON array */
            jobsarray = json_array();
            for (n = 0; n < obsarray->num_elements; n++) {
                struct observance *obs = icalarray_element_at(obsarray, n);

                json_array_append_new(jobsarray,
                                      json_pack(
                                          "{s:s s:s s:i s:i}",
                                          "name", obs->name,
                                          "onset",
                                          icaltime_as_iso_string(obs->onset),
                                          "utc-offset-from", obs->offset_from,
                                          "utc-offset-to", obs->offset_to));
            }
            json_object_set_new(root, "observances", jobsarray);
        }
        icalarray_free(obsarray);

        icalcomponent_free(ical);
    }

    if (zdump) {
        struct resp_body_t *body = &txn->resp_body;

        body->type = "text/plain; charset=us-ascii";

        write_body(precond, txn,
                   buf_cstring(&body->payload), buf_len(&body->payload));

        return 0;
    }
    else {
        /* Output the JSON object */
        return json_response(precond, txn, root, NULL);
    }
}


static int json_response(int code, struct transaction_t *txn, json_t *root,
                         char **resp)
{
    size_t flags = JSON_PRESERVE_ORDER;
    static char *buf = NULL;  /* keep generated data until next call */
    char *json = NULL;

    free(buf);

    if (root) {
        /* Dump JSON object into a text buffer */
        flags |= (config_httpprettytelemetry ? JSON_INDENT(2) : JSON_COMPACT);
        json = buf = json_dumps(root, flags);
        json_decref(root);

        if (!buf) {
            txn->error.desc = "Error dumping JSON object";
            return HTTP_SERVER_ERROR;
        }
        else if (resp) {
            if (*resp) free(*resp);
            *resp = buf;
            buf = NULL;
        }
    }
    else if (resp) json = *resp;

    /* Output the JSON object */
    if (code == HTTP_OK)
        txn->resp_body.type = "application/json; charset=utf-8";
    else
        txn->resp_body.type = "application/problem+json; charset=utf-8";
    write_body(code, txn, json, json ? strlen(json) : 0);

    return 0;
}


/* Array of parameter names - MUST be kept in sync with tz_err.et */
static const char *param_names[] = {
    "action",
    "pattern",
    "format",
    "start",
    "end",
    "changedsince",
    "latitude",
    "longitude",
    "tzid"
};

static int json_error_response(struct transaction_t *txn, long tz_code,
                               struct strlist *param, icaltimetype *time)
{
    long http_code = HTTP_BAD_REQUEST;
    const char *param_name, *fmt = NULL;
    json_t *root;

    param_name = param_names[tz_code - tz_err_base];

    if (!param) {
        switch (tz_code) {
        case TZ_INVALID_ACTION:
            fmt = "Request URI doesn't map to a known action";
            break;

        case TZ_INVALID_FORMAT:
            http_code = HTTP_NOT_ACCEPTABLE;
            fmt = "Unsupported media type";
            break;

        case TZ_NOT_FOUND:
            http_code = HTTP_NOT_FOUND;
            fmt = "Time zone identifier not found";
            break;

        default:
            fmt = "Missing %s parameter";
            break;
        }
    }
    else if (param->next) fmt = "Multiple %s parameters";
    else if (!param->s || !param->s[0]) fmt = "Missing %s value";
    else if (!time) fmt = "Invalid %s value";
    else if (!icaltime_is_utc(*time)) fmt = "Invalid %s UTC value";
    else fmt = "End date-time <= start date-time";

    assert(!buf_len(&txn->buf));
    buf_printf(&txn->buf, fmt, param_name);

    root = json_pack("{s:s s:s s:i}", "title", buf_cstring(&txn->buf),
                     "type", error_message(tz_code),
                     "status", atoi(error_message(http_code)));
    if (!root) {
        txn->error.desc = "Unable to create JSON response";
        return HTTP_SERVER_ERROR;
    }

    return json_response(http_code, txn, root, NULL);
}


#ifndef BIG_BANG
#define BIG_BANG (- (1LL << 59))  /* from zic.c */
#endif

#ifndef INT32_MAX
#define INT32_MAX 0x7fffffff
#endif
#ifndef INT32_MIN
#define INT32_MIN (-INT32_MAX - 1)
#endif

#define NUM_LEAP_DAYS(y) ((y-1) / 4 - (y-1) / 100 + (y-1) / 400)
#define NUM_YEAR_DAYS(y) (365 * y + NUM_LEAP_DAYS(y))

/* Day of year offsets for each month.  Second array is for leap years. */
static const int month_doy_offsets[2][12] = {
    /* jan  feb  mar  apr  may  jun  jul  aug  sep  oct  nov  dec */
    {    0,  31,  59,  90, 120, 151, 181, 212, 243, 273, 304, 334 },
    {    0,  31,  60,  91, 121, 152, 182, 213, 244, 274, 305, 335 }
};

/* Convert icaltimetype to 64-bit time_t.  0 = Jan 1 00:00:00 1970 UTC */
static long long int icaltime_to_gmtime64(const struct icaltimetype tt)
{
    long long int days;

    days = NUM_YEAR_DAYS(tt.year) - NUM_YEAR_DAYS(1970);
    days += month_doy_offsets[icaltime_is_leap_year(tt.year)][tt.month - 1];
    days += tt.day - 1;

    return (((days * 24 + tt.hour) * 60 + tt.minute) * 60 + tt.second);
}

struct ttinfo {
    long int offset;      /* offset from GMT */
    unsigned char isdst;  /* transition time is for DST */
    unsigned char idx;    /* index into 'abbrev' buffer */
    unsigned char isstd;  /* transition time is in standard time */
    unsigned char isgmt;  /* transition time is in GMT */
};

static void set_ttinfo(struct ttinfo *ttinfo,
                       const struct observance *obs, unsigned char idx)
{
    ttinfo->offset = obs->offset_to;
    ttinfo->isdst = obs->is_daylight;
    ttinfo->isstd = obs->is_std;
    ttinfo->isgmt = obs->is_gmt;
    ttinfo->idx = idx;
}

static void buf_append_utcoffset_as_iso_string(struct buf *buf, int off)
{
    int h, m, s;

    h = -off/3600;
    m = (abs(off) % 3600) / 60;
    s = abs(off) % 60;
    buf_printf(buf, "%d", h);
    if (m || s) buf_printf(buf, ":%02d", m);
    if (s) buf_printf(buf, ":%02d", s);
}

/* Generate a POSIX rule from iCal RRULE.
   We assume that the RRULE parts are sane for a VTIMEZONE
   and all rules refer to a day of week in a single month. */
static unsigned buf_append_rrule_as_posix_string(struct buf *buf,
                                                 icalcomponent *comp)
{
    icalproperty *prop;
    icaltimetype at;
    struct icalrecurrencetype rrule;
    unsigned ver = '2';
    int hour;

    prop = icalcomponent_get_first_property(comp, ICAL_RRULE_PROPERTY);
    rrule = icalproperty_get_rrule(prop);

#ifdef HAVE_RSCALE
    if (rrule.rscale && strcasecmp(rrule.rscale, "GREGORIAN")) {
        /* POSIX rules are based on Gregorian calendar only */
        return 0;
    }
#endif

    prop = icalcomponent_get_first_property(comp, ICAL_DTSTART_PROPERTY);
    at = icalproperty_get_dtstart(prop);
    hour = at.hour;

    if (rrule.by_day[0] == ICAL_RECURRENCE_ARRAY_MAX) {
        /* date - Julian yday */
        buf_printf(buf, ",J%u", month_doy_offsets[0][at.month - 1] + at.day);
    }
    else {
        /* BYDAY */
        unsigned month;
        int week = icalrecurrencetype_day_position(rrule.by_day[0]);
        int wday = icalrecurrencetype_day_day_of_week(rrule.by_day[0]);
        int yday = rrule.by_year_day[0];

        if (yday != ICAL_RECURRENCE_ARRAY_MAX) {
            /* BYYEARDAY */

            if (yday >= 0 || hour) {
                /* Bogus?  Either way, we can't handle this */
                return 0;
            }

            /* Rewrite as last (wday-1) @ 24:00 */
            week = -1;
            wday--;
            hour = 24;

            /* Find month that contains this yday */
            yday += 365;
            for (month = 0; month < 12; month++) {
                if (yday <= month_doy_offsets[0][month]) break;
            }
        }
        else {
            /* BYMONTH */
            int mday = rrule.by_month_day[0];

            month = rrule.by_month[0];

            if (mday != ICAL_RECURRENCE_ARRAY_MAX) {
                /* MONTHDAY:  wday >= mday */

                /* Need to use an extension to POSIX: -167 <= hour <= 167 */
                ver = '3';

                if (mday + 7 == icaltime_days_in_month(month, 0)) {
                    /* Rewrite as last (wday+1) @ hour < 0 */
                    week = -1;
                    wday++;
                    hour -= 24;
                }
                else {
                    /* Rewrite as nth (wday-offset) @ hour > 24 */
                    unsigned mday_offset;

                    week = (mday - 1) / 7 + 1;
                    mday_offset = mday - ((week - 1) * 7 + 1);
                    wday -= mday_offset;
                    hour += 24 * mday_offset;
                }
            }
        }

        /* date - month, week, wday */
        buf_printf(buf, ",M%u.%u.%u", month,
                   (week + 6) % 6,   /* normalize; POSIX uses 5 for last (-1) */
                   (wday + 6) % 7);  /* normalize; POSIX is 0-based */
    }

    /* time - default is 02:00:00 */
    if (hour != 2 || at.minute || at.second) {
        buf_printf(buf, "/%d", hour);
        if (at.minute || at.second) buf_printf(buf, ":%02u", at.minute);
        if (at.second) buf_printf(buf, ":%02u", at.second);
    }

    return ver;
}

/* Convert VTIMEZONE into tzif format (draft-murchison-tzdist-tzif) */
static struct buf *_icaltimezone_as_tzif(icalcomponent* ical, bit32 leapcnt,
                                         icaltimetype *startp, icaltimetype *endp)
{
    icalcomponent *vtz, *eternal_std = NULL, *eternal_dst = NULL;
    icalarray *obsarray;
    struct observance proleptic;
    icaltimetype start = icaltime_null_time();
    icaltimetype end = icaltime_from_day_of_year(1, 2100);
    icaltimetype last_dtstart = icaltime_null_time();
    char header[] =  {
        'T', 'Z', 'i', 'f',   /* magic */
        '2',                  /* version */
        0, 0, 0, 0, 0,        /* reserved */
        0, 0, 0, 0, 0,        /* reserved */
        0, 0, 0, 0, 0         /* reserved */
    };
    struct transition {
        long long int t;      /* transition time */
        unsigned char idx;    /* index into 'types' array */
    } *times = NULL;
    struct ttinfo types[256]; /* only indexed by unsigned char */
    struct buf *tzif, posix = BUF_INITIALIZER, abbrev = BUF_INITIALIZER;
    struct observance *obs;
    unsigned do_bit64;
    struct leapsec *leap = NULL;
    bit32 leap_init = 0, leap_sec = 0;

    tzif = buf_new();

    vtz = icalcomponent_get_first_component(ical, ICAL_VTIMEZONE_COMPONENT);
    if (!vtz) return tzif;

    if (leapcnt) {
        leap = ptrarray_nth(leap_seconds, 1);
        leap_init = leap->sec;
    }

    if (!startp) startp = &start;
    if (!endp || icaltime_is_null_time(*endp)) endp = &end;

    /* Create an array of observances */
    obsarray = icalarray_new(sizeof(struct observance), 100);
    icaltimezone_truncate_vtimezone_advanced(vtz, startp, endp, obsarray,
            &proleptic, &eternal_std, &eternal_dst, &last_dtstart, 0);

    /* Create an array of transitions */
    times = xmalloc((obsarray->num_elements+1) * sizeof(struct transition));

    /* Try to create POSIX tz rule */
    if (eternal_dst) {
        unsigned d_ver, s_ver;

        if ((d_ver = buf_append_rrule_as_posix_string(&posix, eternal_dst)) &&
            (s_ver = buf_append_rrule_as_posix_string(&posix, eternal_std))) {
            /* Set format version */
            header[4] = d_ver | s_ver;
        }
        else {
            /* Can't create rule */
            buf_reset(&posix);
        }
    }

    /* Add two tzif datasets:
       The first using 32-bit times and the second using 64-bit times. */
    for (do_bit64 = 0; do_bit64 <= 1; do_bit64++) {
        long long int epoch = do_bit64 ? BIG_BANG : INT32_MIN;
        struct observance *prev_obs = &proleptic;
        bit32 timecnt = 0, typecnt = 0;
        int leapidx = 2;
        size_t n;

        buf_reset(&abbrev);

        leap_sec = 0;
        if (leapcnt) leap = ptrarray_nth(leap_seconds, leapidx);

        /* Populate array of transitions & types */
        for (n = 0; n < obsarray->num_elements; n++) {
            long long int t;
            unsigned typeidx;
            icaltimetype tt_1601 = icaltime_from_string("1601-01-01T00:00:00Z");

            obs = icalarray_element_at(obsarray, n);
            t = icaltime_to_gmtime64(obs->onset);
            icaltime_adjust(&tt_1601, 0, 0, 0, -obs->offset_to);

            if (obs->onset.year > 2037 &&
                (!do_bit64 || obs->onset.year > last_dtstart.year)) {
                /* tzdata doesn't seem to go any further */
                break;
            }
            else if (!timecnt) {
                if (t > epoch && proleptic.onset.year < 0) {
                    /* Insert a tombstone prior to first real transition */
                    t = epoch;
                    obs = prev_obs;
                    
                    /* Need to reprocess current observance */
                    n--;
                }
                else {
                    /* Reset types and abbreviations */
                    typecnt = 0;
                    buf_reset(&abbrev);
                }
            }
            else if (!icaltime_compare(obs->onset, tt_1601)) {
                /* Skip vzic tombstone for YEAR_MINIMUM */
                continue;
            }
            else if (obs->offset_from == obs->offset_to
                && prev_obs->is_daylight == obs->is_daylight
                && prev_obs->is_std == obs->is_std
                && prev_obs->is_gmt == obs->is_gmt
                && !strcmp(prev_obs->name, obs->name)) {
                /* Skip any no-ops */
                continue;
            }
            prev_obs = obs;

            /* Check for existing type */
            for (typeidx = 0; typeidx < typecnt; typeidx++) {
                if ((obs->offset_to == types[typeidx].offset) &&
                    (obs->is_daylight == types[typeidx].isdst) &&
                    (obs->is_std == types[typeidx].isstd) &&
                    (obs->is_gmt == types[typeidx].isgmt) &&
                    !strcmp(obs->name, buf_cstring(&abbrev) + types[typeidx].idx))
                    break;
            }

            if (typeidx == typecnt) {
                /* Didn't find existing type */
                const char *p = buf_base(&abbrev);
                const char *endp = p + buf_len(&abbrev);

                /* Check for existing abbreviation */
                while (p < endp) {
                    if (!strcmp(p, obs->name)) break;
                    p += strlen(p) + 1;
                }

                /* Add new type */
                set_ttinfo(&types[typecnt++], obs, p - buf_base(&abbrev));

                if (p == endp) {
                    /* Add new abbreviation (including the NUL) */
                    buf_appendmap(&abbrev, obs->name, strlen(obs->name) + 1);
                }
            }

            if (t < epoch) {
                /* Skip transitions earlier than our epoch */
                continue;
            }

            /* Add transition */
            if (leapcnt) {
                while (t >= leap->t && leapidx < leap_seconds->count) {
                    leap_sec = leap->sec - leap_init;
                    if (++leapidx < leap_seconds->count)
                        leap = ptrarray_nth(leap_seconds, leapidx);
                }
                t += leap_sec;
            }
            times[timecnt].t = t;
            times[timecnt].idx = typeidx;
            timecnt++;
        }


        /* Output dataset */

        /* Header */
        buf_appendmap(tzif, header, sizeof(header));
        buf_appendbit32(tzif, typecnt);           /* isgmtcnt */
        buf_appendbit32(tzif, typecnt);           /* isstdcnt */
        buf_appendbit32(tzif, leapcnt);           /* leapcnt */
        buf_appendbit32(tzif, timecnt);           /* timecnt */
        buf_appendbit32(tzif, typecnt);           /* typecnt */
        buf_appendbit32(tzif, buf_len(&abbrev));  /* charcnt */

        /* Transition times */
        for (n = 0; n < timecnt; n++) {
            if (do_bit64) buf_appendbit64(tzif, times[n].t);
            else buf_appendbit32(tzif, times[n].t);
        }

        /* Transition time indices */
        for (n = 0; n < timecnt; n++) buf_putc(tzif, times[n].idx);

        /* Types structures */
        for (n = 0; n < typecnt; n++) {
            buf_appendbit32(tzif, types[n].offset);
            buf_putc(tzif, types[n].isdst);
            buf_putc(tzif, types[n].idx);
        }

        /* Abbreviation array */
        buf_append(tzif, &abbrev);

        /* Leap second records */
        if (leapcnt) {
            leap_sec = 0;

            for (leapidx = 2; leapidx < leap_seconds->count; leapidx++) {
                long long int t;

                leap = ptrarray_nth(leap_seconds, leapidx);
                t = leap->t + leap_sec;
                if (do_bit64) buf_appendbit64(tzif, t);
                else buf_appendbit32(tzif, t);

                leap_sec = leap->sec - leap_init;
                buf_appendbit32(tzif, leap_sec);
            }
        }

        /* Standard/wall indicators */
        for (n = 0; n < typecnt; n++) buf_putc(tzif, types[n].isstd);

        /* GMT/local indicators */
        for (n = 0; n < typecnt; n++) buf_putc(tzif, types[n].isgmt);
    }

    free(times);
    buf_free(&abbrev);


    /* POSIX timezone string */
    buf_putc(tzif, '\n');

    /* std offset [dst [offset] [,rule] ] */
    if (buf_len(&posix)) {
        /* Use POSIX rule */
        icalproperty *prop;
        int stdoff, dstoff;

        /* std name */
        prop = icalcomponent_get_first_property(eternal_std,
                                                ICAL_TZNAME_PROPERTY);
        buf_appendcstr(tzif, icalproperty_get_tzname(prop));

        /* std offset */
        prop = icalcomponent_get_first_property(eternal_std,
                                                ICAL_TZOFFSETTO_PROPERTY);
        stdoff = icalproperty_get_tzoffsetto(prop);
        buf_append_utcoffset_as_iso_string(tzif, stdoff);

        /* dst name */
        prop = icalcomponent_get_first_property(eternal_dst,
                                                ICAL_TZNAME_PROPERTY);
        buf_appendcstr(tzif, icalproperty_get_tzname(prop));

        /* dst offset */
        prop = icalcomponent_get_first_property(eternal_dst,
                                                ICAL_TZOFFSETTO_PROPERTY);
        dstoff = icalproperty_get_tzoffsetto(prop);
        if (dstoff - stdoff != 3600) {  /* default is 1hr from std */
            buf_append_utcoffset_as_iso_string(tzif, dstoff);
        }

        /* rule */
        buf_append(tzif, &posix);
    }
    else if (!eternal_dst &&
             !icalcomponent_get_tzuntil_property(vtz)) {
        /* Use last observance as fixed offset */
        obs = icalarray_element_at(obsarray, obsarray->num_elements - 1);

        /* std name */
        if (obs->name[0] == ':' ||
            strcspn(obs->name, ",+-0123456789") < strlen(obs->name)) {
            buf_printf(tzif, "<%s>", obs->name);
        }
        else buf_appendcstr(tzif, obs->name);

        /* std offset */
        buf_append_utcoffset_as_iso_string(tzif, obs->offset_to);
    }
    buf_putc(tzif, '\n');

    buf_free(&posix);
    icalarray_free(obsarray);

    return tzif;
}

static struct buf *icaltimezone_as_tzif(icalcomponent* ical)
{
    return _icaltimezone_as_tzif(ical, 0, NULL, NULL);
}

static struct buf *icaltimezone_as_tzif_leap(icalcomponent* ical)
{
    return _icaltimezone_as_tzif(ical, leap_seconds->count - 2, NULL, NULL);
}

