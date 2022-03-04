/* cyr_buildinfo.c - tool to inspect Cyrus build configuration
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
 */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <jansson.h>

#include "global.h"
#include "proc.h"
#include "util.h"
#include "../master/masterconf.h"
#include "xmalloc.h"

/* Make ld happy */
const char *MASTER_CONFIG_FILENAME = DEFAULT_MASTER_CONFIG_FILENAME;

/* Print usage info on stderr and exit */
static void usage(void)
{
    fprintf(stderr, "cyr_buildinfo [-C <file>] [format]\n");
    fprintf(stderr, "Where format is one of:\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  * pretty        - pretty-print JSON (default)\n");
    fprintf(stderr, "  * dense         - print dense JSON\n");
    fprintf(stderr, "  * flat          - print as flattened properties\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "The -C option is accepted but ignored.\n");
    exit(-1);
}

/* Gather the build configuration parameters as JSON object */
static json_t *buildinfo()
{
    json_t *component = json_object();
    json_t *dependency = json_object();
    json_t *database = json_object();
    json_t *search = json_object();
    json_t *hardware = json_object();
    json_t *buildconf = json_object();

    json_object_set_new(buildconf, "component", component);
    json_object_set_new(buildconf, "dependency", dependency);
    json_object_set_new(buildconf, "database", database);
    json_object_set_new(buildconf, "search", search);
    json_object_set_new(buildconf, "hardware", hardware);

    /* Yikes... */

    /* Enabled components */
    json_object_set_new(component, "event_notification", json_true());
#ifdef HAVE_GSSAPI_H
    json_object_set_new(component, "gssapi", json_true());
#else
    json_object_set_new(component, "gssapi", json_false());
#endif
#ifdef USE_AUTOCREATE
    json_object_set_new(component, "autocreate", json_true());
#else
    json_object_set_new(component, "autocreate", json_false());
#endif
#ifdef USE_IDLED
    json_object_set_new(component, "idled", json_true());
#else
    json_object_set_new(component, "idled", json_false());
#endif
#ifdef USE_HTTPD
    json_object_set_new(component, "httpd", json_true());
#else
    json_object_set_new(component, "httpd", json_false());
#endif
#ifdef HAVE_KRB
    json_object_set_new(component, "kerberos_v4", json_true());
#else
    json_object_set_new(component, "kerberos_v4", json_false());
#endif
#ifdef USE_MURDER
    json_object_set_new(component, "murder", json_true());
#else
    json_object_set_new(component, "murder", json_false());
#endif
#ifdef USE_NNTPD
    json_object_set_new(component, "nntpd", json_true());
#else
    json_object_set_new(component, "nntpd", json_false());
#endif
#ifdef USE_REPLICATION
    json_object_set_new(component, "replication", json_true());
#else
    json_object_set_new(component, "replication", json_false());
#endif
#ifdef USE_SIEVE
    json_object_set_new(component, "sieve", json_true());
#else
    json_object_set_new(component, "sieve", json_false());
#endif
#ifdef USE_CALALARMD
    json_object_set_new(component, "calalarmd", json_true());
#else
    json_object_set_new(component, "calalarmd", json_false());
#endif
#ifdef WITH_JMAP
    json_object_set_new(component, "jmap", json_true());
#else
    json_object_set_new(component, "jmap", json_false());
#endif
#ifdef ENABLE_OBJECTSTORE
    json_object_set_new(component, "objectstore", json_true());
#else
    json_object_set_new(component, "objectstore", json_false());
#endif
#ifdef ENABLE_BACKUP
    json_object_set_new(component, "backup", json_true());
#else
    json_object_set_new(component, "backup", json_false());
#endif

    /* Build dependencies */
#ifdef HAVE_LDAP
    json_object_set_new(dependency, "ldap", json_true());
#else
    json_object_set_new(dependency, "ldap", json_false());
#endif
#ifdef HAVE_SSL
    json_object_set_new(dependency, "openssl", json_true());
#else
    json_object_set_new(dependency, "openssl", json_false());
#endif
#ifdef HAVE_ZLIB
    json_object_set_new(dependency, "zlib", json_true());
#else
    json_object_set_new(dependency, "zlib", json_false());
#endif
#ifdef HAVE_JANSSON
    json_object_set_new(dependency, "jansson", json_true());
#else
    json_object_set_new(dependency, "jansson", json_false());
#endif
#if defined(ENABLE_REGEX) && defined(HAVE_PCREPOSIX_H)
    json_object_set_new(dependency, "pcre", json_true());
#else
    json_object_set_new(dependency, "pcre", json_false());
#endif
#ifdef HAVE_CLAMAV
    json_object_set_new(dependency, "clamav", json_true());
#else
    json_object_set_new(dependency, "clamav", json_false());
#endif
#ifdef WITH_OPENIO
    json_object_set_new(dependency, "openio", json_true());
#else
    json_object_set_new(dependency, "openio", json_false());
#endif
#ifdef HAVE_NGHTTP2
    json_object_set_new(dependency, "nghttp2", json_true());
#else
    json_object_set_new(dependency, "nghttp2", json_false());
#endif
#ifdef HAVE_WSLAY
    json_object_set_new(dependency, "wslay", json_true());
#else
    json_object_set_new(dependency, "wslay", json_false());
#endif
#ifdef HAVE_BROTLI
    json_object_set_new(dependency, "brotli", json_true());
#else
    json_object_set_new(dependency, "brotli", json_false());
#endif
#ifdef USE_HTTPD
    json_object_set_new(dependency, "xml2", json_true());
#else
    json_object_set_new(dependency, "xml2", json_false());
#endif
#ifdef HAVE_ICAL
    json_object_set_new(dependency, "ical", json_true());
#else
    json_object_set_new(dependency, "ical", json_false());
#endif
#ifdef HAVE_ICU
    json_object_set_new(dependency, "icu4c", json_true());
#else
    json_object_set_new(dependency, "icu4c", json_false());
#endif
#ifdef HAVE_SHAPELIB
    json_object_set_new(dependency, "shapelib", json_true());
#else
    json_object_set_new(dependency, "shapelib", json_false());
#endif
#ifdef HAVE_LIBCHARDET
    json_object_set_new(dependency, "chardet", json_true());
#else
    json_object_set_new(dependency, "chardet", json_false());
#endif
#ifdef HAVE_CLD2
    json_object_set_new(dependency, "cld2", json_true());
#else
    json_object_set_new(dependency, "cld2", json_false());
#endif
#ifdef HAVE_GUESSTZ
    json_object_set_new(dependency, "guesstz", json_true());
#else
    json_object_set_new(dependency, "guesstz", json_false());
#endif

    /* Enabled databases */
#ifdef HAVE_MYSQL
    json_object_set_new(database, "mysql", json_true());
#else
    json_object_set_new(database, "mysql", json_false());
#endif
#ifdef HAVE_PGSQL
    json_object_set_new(database, "pgsql", json_true());
#else
    json_object_set_new(database, "pgsql", json_false());
#endif
#ifdef HAVE_SQLITE
    json_object_set_new(database, "sqlite", json_true());
#else
    json_object_set_new(database, "sqlite", json_false());
#endif

    /* Enabled search engines */
#ifdef USE_SQUAT
    json_object_set_new(search, "squat", json_true());
#else
    json_object_set_new(search, "squat", json_false());
#endif
#ifdef USE_XAPIAN
    json_object_set_new(search, "xapian", json_true());
#else
    json_object_set_new(search, "xapian", json_false());
#endif
    json_object_set_new(search, "xapian_cjk_tokens", json_string(XAPIAN_CJK_TOKENS));

    return buildconf;
}

#define FORMAT_PRETTY 1
#define FORMAT_DENSE 2
#define FORMAT_FLAT 3

/* Print the build information as flattened properties, prefixed by
 * the contents of buf. */
static void format_flat(json_t *buildinfo, struct buf *buf)
{
    const char *key;
    json_t *val;

    json_object_foreach(buildinfo, key, val) {
        buf_appendcstr(buf, key);
        if (json_typeof(val) == JSON_OBJECT) {
            buf_appendcstr(buf, ".");
            format_flat(val, buf);
            buf_truncate(buf, -1);
        } else {
            char *jval = json_dumps(val, JSON_ENCODE_ANY);
            buf_appendcstr(buf, "=");
            buf_appendcstr(buf, jval);
            printf("%s\n", buf_cstring(buf));
            buf_truncate(buf, -strlen(jval)-1);
            free(jval);
        }
        buf_truncate(buf, -strlen(key));
    }
}

/* Print build the build information as JSON object, with fmt
 * indicating the specific JSON format (dense or pretty). */
static void format_json(json_t *buildinfo, int fmt)
{
    int flags = JSON_PRESERVE_ORDER;
    char *dump;

    if (fmt == FORMAT_PRETTY) flags |= JSON_INDENT(2);
    dump = json_dumps(buildinfo, flags);
    printf("%s\n", dump);
    free(dump);
}


int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt;
    int fmt = FORMAT_PRETTY;
    struct buf buf = BUF_INITIALIZER;
    json_t *bi;

    /* Parse arguments */
    while ((opt = getopt(argc, argv, "C:")) != EOF) {
        switch (opt) {
        case 'C': /* alt config file. We don't care but don't bark for -C. */
            break;
        default:
            usage();
            break;
        }
    }
    if (optind < argc) {
        if (!strcmp(argv[optind], "pretty"))
            fmt = FORMAT_PRETTY;
        else if (!strcmp(argv[optind], "dense"))
            fmt = FORMAT_DENSE;
        else if (!strcmp(argv[optind], "flat"))
            fmt = FORMAT_FLAT;
        else
            usage();
    }

    /* Create and print the build configuration */
    bi = buildinfo();
    if (!bi) exit(-2);
    switch (fmt) {
        case FORMAT_PRETTY:
        case FORMAT_DENSE:
            format_json(bi, fmt);
            break;
        case FORMAT_FLAT:
            format_flat(bi, &buf);
            break;
        default:
            /* should not happen */
            exit(-3);
    }

    /* All done */
    buf_free(&buf);
    json_decref(bi);
    return 0;
}
