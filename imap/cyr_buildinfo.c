/* cyr_buildinfo.c - tool to inspect Cyrus build configuration */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <jansson.h>

#include "lib/proc.h"
#include "lib/util.h"
#include "lib/xmalloc.h"

#include "imap/conversations.h"
#include "imap/global.h"
#include "imap/mailbox.h"
#include "imap/statuscache.h"
#include "imap/zoneinfo_db.h"

#include "master/masterconf.h"

#ifdef USE_SIEVE
#include "sieve/bytecode.h"
#include "sieve/sieve_interface.h"
#endif

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
    json_t *cyrusdb = json_object();
    json_t *search = json_object();
    json_t *hardware = json_object();
    json_t *buildconf = json_object();
    json_t *version = json_object();
    json_t *ical = json_object();

    json_object_set_new(buildconf, "component", component);
    json_object_set_new(buildconf, "dependency", dependency);
    json_object_set_new(buildconf, "cyrusdb", cyrusdb);
    json_object_set_new(buildconf, "search", search);
    json_object_set_new(buildconf, "ical", ical);
    json_object_set_new(buildconf, "hardware", hardware);
    json_object_set_new(buildconf, "version", version);

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
#ifdef ENABLE_DEBUG_SLOWIO
    json_object_set_new(component, "slowio", json_true());
#else
    json_object_set_new(component, "slowio", json_false());
#endif

    /* Build dependencies */
    json_object_set_new(dependency, "openssl", json_true());
    json_object_set_new(dependency, "openssl_alpn", json_true());
#ifdef HAVE_LDAP
    json_object_set_new(dependency, "ldap", json_true());
#else
    json_object_set_new(dependency, "ldap", json_false());
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
#if defined(ENABLE_REGEX) && defined(HAVE_PCRE2POSIX_H)
    json_object_set_new(dependency, "pcre2", json_true());
#else
    json_object_set_new(dependency, "pcre2", json_false());
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

    /* cyrusdb backends */
    json_object_set_new(cyrusdb, "flat", json_true());
    json_object_set_new(cyrusdb, "quotalegacy", json_true());
    json_object_set_new(cyrusdb, "skiplist", json_true());
    json_object_set_new(cyrusdb, "twom", json_true());
    json_object_set_new(cyrusdb, "twoskip", json_true());
#ifdef USE_CYRUSDB_SQL
    {
        json_t *sql_engines = json_array();
        json_object_set_new(cyrusdb, "sql", sql_engines);
# ifdef HAVE_MYSQL
        json_array_append_new(sql_engines, json_string("mysql"));
# endif
# ifdef HAVE_PGSQL
        json_array_append_new(sql_engines, json_string("pgsql"));
# endif
# ifdef HAVE_SQLITE
        json_array_append_new(sql_engines, json_string("sqlite"));
# endif
    }
#else
    json_object_set_new(cyrusdb, "sql", json_false());
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

    /* Internal version numbers */
#ifdef USE_SIEVE
    json_object_set_new(version, "BYTECODE_MIN_VERSION",
                                 json_integer(BYTECODE_MIN_VERSION));
    json_object_set_new(version, "BYTECODE_VERSION",
                                 json_integer(BYTECODE_VERSION));
#endif
    json_object_set_new(version, "CONVERSATIONS_KEY_VERSION",
                                 json_integer(CONVERSATIONS_KEY_VERSION));
    json_object_set_new(version, "CONVERSATIONS_RECORD_VERSION",
                                 json_integer(CONVERSATIONS_RECORD_VERSION));
    json_object_set_new(version, "CONVERSATIONS_STATUS_VERSION",
                                 json_integer(CONVERSATIONS_STATUS_VERSION));
    json_object_set_new(version, "CONV_GUIDREC_BYNAME_VERSION",
                                 json_integer(CONV_GUIDREC_BYNAME_VERSION));
    json_object_set_new(version, "CONV_GUIDREC_VERSION",
                                 json_integer(CONV_GUIDREC_VERSION));
    json_object_set_new(version, "CYRUS_VERSION",
                                 json_string(CYRUS_VERSION));
    json_object_set_new(version, "MAILBOX_CACHE_MINOR_VERSION",
                                 json_integer(MAILBOX_CACHE_MINOR_VERSION));
    json_object_set_new(version, "MAILBOX_MINOR_VERSION",
                                 json_integer(MAILBOX_MINOR_VERSION));
#ifdef USE_SIEVE
    json_object_set_new(version, "SIEVE_VERSION",
                                 json_string(SIEVE_VERSION));
#endif
    json_object_set_new(version, "STATUSCACHE_VERSION",
                                 json_integer(STATUSCACHE_VERSION));
    json_object_set_new(version, "ZONEINFO_VERSION",
                                 json_integer(ZONEINFO_VERSION));

#if defined __USE_FORTIFY_LEVEL && __USE_FORTIFY_LEVEL > 0
    json_object_set_new(version, "FORTIFY_LEVEL",
                                 json_integer(__USE_FORTIFY_LEVEL));
#else
    json_object_set_new(version, "FORTIFY_LEVEL",
                                 json_integer(0));
#endif

    /* Whew ... */
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

    /* keep this in alphabetical order */
    static const char short_options[] = "C:";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        { 0, 0, 0, 0 },
    };

    /* Parse arguments */
    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
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
