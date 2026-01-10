/* libconfig.c -- imapd.conf handling */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>

#include "assert.h"
#include "hash.h"
#include "libconfig.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"
#include "tok.h"
#include "util.h"

#define CONFIGHASHSIZE 30 /* relatively small,
                           * because it is for overflow only */
#define INCLUDEHASHSIZE 5 /* relatively small,
                            * but how many includes are reasonable? */

static struct hash_table confighash, includehash;

/* cached configuration variables accessible to the external world */
EXPORTED const char *config_filename= NULL;       /* filename of configuration file */
EXPORTED const char *config_dir = NULL;          /* ie /var/imap */
EXPORTED const char *config_defpartition = NULL;  /* /var/spool/imap */
EXPORTED const char *config_servername= NULL;    /* gethostname() */
EXPORTED enum enum_value config_serverinfo;      /* on */
EXPORTED const char *config_mupdate_server = NULL;/* NULL */
EXPORTED const char *config_defdomain = NULL;     /* NULL */
EXPORTED const char *config_ident = NULL;         /* the service name */
EXPORTED int config_hashimapspool;        /* f */
EXPORTED enum enum_value config_virtdomains;              /* f */
EXPORTED enum enum_value config_mupdate_config; /* IMAP_ENUM_MUPDATE_CONFIG_STANDARD */
EXPORTED strarray_t config_cua_domains = STRARRAY_INITIALIZER;
EXPORTED int config_auditlog;
EXPORTED int config_iolog;
EXPORTED unsigned config_maxword;
EXPORTED unsigned config_maxquoted;
EXPORTED unsigned config_maxliteral;
EXPORTED int config_qosmarking;
EXPORTED int config_debug;
EXPORTED toggle_debug_cb config_toggle_debug_cb = NULL;
EXPORTED int config_debug_slowio = 0;
EXPORTED int config_fatals_abort = 0;
EXPORTED const char *config_zoneinfo_dir = NULL;
EXPORTED strarray_t *config_admins = NULL;

static int config_loaded;

extern void fatal(const char *fatal_message, int fatal_code)
   __attribute__ ((noreturn));

/* prototype to allow for sane function ordering */
static void config_read_file(const char *filename);

static void assert_not_deprecated(enum imapopt opt)
{
    if (imapopts[opt].deprecated_since) {
        char errbuf[1024];
        enum imapopt popt = imapopts[opt].preferred_opt;
        if (popt != IMAPOPT_ZERO) {
            snprintf(errbuf, sizeof(errbuf),
                    "Option '%s' is deprecated in favor of '%s' since version %s.",
                    imapopts[opt].optname, imapopts[popt].optname,
                    imapopts[opt].deprecated_since);
        }
        else {
            snprintf(errbuf, sizeof(errbuf),
                    "Option '%s' is deprecated in version %s.",
                    imapopts[opt].optname, imapopts[opt].deprecated_since);
        }
        fatal(errbuf, EX_SOFTWARE);
    }
}

EXPORTED const char *config_getstring(enum imapopt opt)
{
    assert(config_loaded);
    assert(opt > IMAPOPT_ZERO && opt < IMAPOPT_LAST);
    assert_not_deprecated(opt);
    assert((imapopts[opt].t == OPT_STRING) ||
           (imapopts[opt].t == OPT_STRINGLIST));

    return imapopts[opt].val.s;
}

EXPORTED int config_getint(enum imapopt opt)
{
    assert(config_loaded);
    assert(opt > IMAPOPT_ZERO && opt < IMAPOPT_LAST);
    assert_not_deprecated(opt);
    assert(imapopts[opt].t == OPT_INT);
#if (SIZEOF_LONG != 4)
    if ((imapopts[opt].val.i > 0x7fffffff)||
        (imapopts[opt].val.i < -0x7fffffff)) {
        syslog(LOG_ERR, "config_getint: %s: %ld too large for type",
               imapopts[opt].optname, imapopts[opt].val.i);
    }
#endif
    return imapopts[opt].val.i;
}

EXPORTED int config_getswitch(enum imapopt opt)
{
    assert(config_loaded);
    assert(opt > IMAPOPT_ZERO && opt < IMAPOPT_LAST);
    assert_not_deprecated(opt);
    assert(imapopts[opt].t == OPT_SWITCH);
#if (SIZEOF_LONG != 4)
    if ((imapopts[opt].val.b > 0x7fffffff)||
        (imapopts[opt].val.b < -0x7fffffff)) {
        syslog(LOG_ERR, "config_getswitch: %s: %ld too large for type",
               imapopts[opt].optname, imapopts[opt].val.b);
    }
#endif
    return imapopts[opt].val.b;
}

EXPORTED enum enum_value config_getenum(enum imapopt opt)
{
    assert(config_loaded);
    assert(opt > IMAPOPT_ZERO && opt < IMAPOPT_LAST);
    assert_not_deprecated(opt);
    assert(imapopts[opt].t == OPT_ENUM);

    return imapopts[opt].val.e;
}

EXPORTED uint64_t config_getbitfield(enum imapopt opt)
{
    assert(config_loaded);
    assert(opt > IMAPOPT_ZERO && opt < IMAPOPT_LAST);
    assert_not_deprecated(opt);
    assert(imapopts[opt].t == OPT_BITFIELD);

    return imapopts[opt].val.x;
}

static inline int accumulate(int *val, int mult, int nextchar,
                             struct buf *parse_err)
{
    int newdigit = 0;

    assert(val != NULL);

    if (cyrus_isdigit(nextchar)) newdigit = nextchar - '0';

    if (*val > INT_MAX / mult
        || (*val == INT_MAX / mult
            && newdigit > INT_MAX % mult))
    {
        if (parse_err)
            buf_printf(parse_err, "would overflow at '%c'", nextchar);
        return -1;
    }

    *val = *val * mult + newdigit;
    return 0;
}

/* Parse a duration value, converted to seconds.
 *
 * defunit is one of 'd', 'h', 'm', 's' and determines how
 * unitless values are parsed.
 *
 * On success, 0 is returned and the duration in seconds is written to
 * out_duration (if provided).

 * On error, -1 is returned and out_duration is unchanged.
 */
EXPORTED int config_parseduration(const char *str, int defunit, int *out_duration)
{
    assert(strchr("dhms", defunit) != NULL); /* n.b. also permits \0 */

    const size_t len = strlen(str);
    const char *p;
    int accum = 0, duration = 0, neg = 0, sawdigit = 0, r = 0;
    char *copy = NULL;
    struct buf parse_err = BUF_INITIALIZER;

    /* the default default unit is seconds */
    if (!defunit) defunit = 's';

    /* make a copy and append the default unit if necessary */
    copy = xzmalloc(len + 2);
    strlcpy(copy, str, len + 2);
    if (len > 0 && cyrus_isdigit(copy[len-1]))
        copy[len] = defunit;

    p = copy;
    if (*p == '-') {
        if (!cyrus_isdigit(p[1])) {
            buf_setcstr(&parse_err, "no digit after '-'");
            r = -1;
            goto done;
        }
        neg = 1;
        p++;
    }
    for (; *p; p++) {
        if (cyrus_isdigit(*p)) {
            r = accumulate(&accum, 10, *p, &parse_err);
            if (r) goto done;
            sawdigit = 1;
        }
        else {
            if (!sawdigit) {
                buf_printf(&parse_err, "no digit before '%c'", *p);
                r = -1;
                goto done;
            }
            sawdigit = 0;
            switch (*p) {
            case 'd':
                r = accumulate(&accum, 24, *p, &parse_err);
                if (r) goto done;
                /* fall through */
            case 'h':
                r = accumulate(&accum, 60, *p, &parse_err);
                if (r) goto done;
                /* fall through */
            case 'm':
                r = accumulate(&accum, 60, *p, &parse_err);
                if (r) goto done;
                /* fall through */
            case 's':
                if (duration > INT_MAX - accum) {
                    buf_printf(&parse_err, "would overflow at '%c'", *p);
                    r = -1;
                    goto done;
                }
                duration += accum;
                accum = 0;
                break;
            default:
                buf_printf(&parse_err, "bad unit '%c'", *p);
                r = -1;
                goto done;
            }
        }
    }

    /* we shouldn't have anything left in the accumulator */
    assert(accum == 0);

    if (neg) duration = -duration;
    if (out_duration) *out_duration = duration;

done:
    if (r) {
        xsyslog(LOG_ERR, "unable to parse duration from string",
                         "value=<%s> parse_err=<%s>",
                         str, buf_cstring_or_empty(&parse_err));
    }

    buf_free(&parse_err);
    free(copy);
    return r;
}

/* Get a duration value, converted to seconds.
 *
 * defunit is one of 'd', 'h', 'm', 's' and determines how
 * unitless values are parsed.
 */
EXPORTED int config_getduration(enum imapopt opt, int defunit)
{
    int duration;

    assert(opt > IMAPOPT_ZERO && opt < IMAPOPT_LAST);
    assert(imapopts[opt].t == OPT_DURATION);
    assert_not_deprecated(opt);
    assert(strchr("dhms", defunit) != NULL); /* n.b. also permits \0 */

    if (imapopts[opt].val.s == NULL) return 0;

    if (config_parseduration(imapopts[opt].val.s, defunit, &duration)) {
        /* should have been rejected by config_read_file, but just in case */
        char errbuf[1024];
        snprintf(errbuf, sizeof(errbuf),
                 "%s: %s: couldn't parse duration '%s'",
                 __func__, imapopts[opt].optname, imapopts[opt].val.s);
        fatal(errbuf, EX_CONFIG);
    }

    return duration;
}

/* Parse a size value, converted to bytes.
 *
 * On success, 0 is returned and the size in bytes is written to
 * out_bytesize (if provided).
 *
 * On error, -1 is returned and out_bytesize is unchanged.
 */
EXPORTED int config_parsebytesize(const char *str,
                                  int defunit,
                                  int64_t *out_bytesize)
{
    const size_t len = strlen(str);
    int64_t bytesize;
    int i_allowed = 0, r = 0;
    char *copy = NULL, *p;
    struct buf parse_err = BUF_INITIALIZER;

    assert(strchr("BKMG", defunit) != NULL); /* n.b. also permits \0 */

    /* the default default unit is bytes */
    if (!defunit) defunit = 'B';

    /* make a copy and append the default unit if necessary */
    copy = xzmalloc(len + 2);
    strlcpy(copy, str, len + 2);
    if (len > 0 && cyrus_isdigit(copy[len-1]))
        copy[len] = defunit;

    /* start parsing */
    errno = 0;
    bytesize = strtoll(copy, &p, 10);
    if (errno) {
        buf_setcstr(&parse_err, strerror(errno));
        errno = 0;
        r = -1;
        goto done;
    }

    /* better be some digits */
    if (p == copy) {
        buf_setcstr(&parse_err, "no digit");
        if (*p) buf_printf(&parse_err, " before '%c'", *p);
        r = -1;
        goto done;
    }

    /* optional space for readability */
    while (isspace(*p)) p++;

    /* optional G, M, K multiplier */
    switch (*p) {
    case 'g':
    case 'G':
        if (bytesize > INT64_MAX / 1024 || bytesize < INT64_MIN / 1024) {
            buf_printf(&parse_err, "would overflow at '%c'", *p);
            r = -1;
            goto done;
        }
        bytesize *= 1024;
        /* fall through */
    case 'm':
    case 'M':
        if (bytesize > INT64_MAX / 1024 || bytesize < INT64_MIN / 1024) {
            buf_printf(&parse_err, "would overflow at '%c'", *p);
            r = -1;
            goto done;
        }
        bytesize *= 1024;
        /* fall through */
    case 'k':
    case 'K':
        if (bytesize > INT64_MAX / 1024 || bytesize < INT64_MIN / 1024) {
            buf_printf(&parse_err, "would overflow at '%c'", *p);
            r = -1;
            goto done;
        }
        bytesize *= 1024;
        i_allowed = 1;
        p++;
        break;
    }

    /* allow multiplier to be spelt as Gi, Mi, Ki */
    if (i_allowed && (*p == 'i' || *p == 'I')) p++;

    /* optional B suffix */
    if (*p == 'b' || *p == 'B') p++;

    /* we'd better be at end of string! */
    if (*p) {
        buf_printf(&parse_err, "bad unit '%c'", *p);
        r = -1;
        goto done;
    }

done:
    if (r) {
        xsyslog(LOG_ERR, "unable to parse bytesize from string",
                         "value=<%s> parse_err=<%s>",
                         str, buf_cstring_or_empty(&parse_err));
    }
    else if (out_bytesize) {
        *out_bytesize = bytesize;
    }

    buf_free(&parse_err);
    free(copy);
    return r;
}

/* Get a size value, converted to bytes. */
EXPORTED int64_t config_getbytesize(enum imapopt opt, int defunit)
{
    int64_t bytesize;

    assert(config_loaded);
    assert(opt > IMAPOPT_ZERO && opt < IMAPOPT_LAST);
    assert(imapopts[opt].t == OPT_BYTESIZE);
    assert_not_deprecated(opt);
    assert(strchr("BKMG", defunit) != NULL); /* n.b. also permits \0 */

    if (imapopts[opt].val.s == NULL) return 0;

    if (config_parsebytesize(imapopts[opt].val.s, defunit, &bytesize)) {
        /* should have been rejected by config_read_file, but just in case */
        char errbuf[1024];
        snprintf(errbuf, sizeof(errbuf),
                 "%s: %s: couldn't parse byte size '%s'",
                 __func__, imapopts[opt].optname, imapopts[opt].val.s);
        fatal(errbuf, EX_CONFIG);
    }

    return bytesize;
}

EXPORTED const char *config_getoverflowstring(const char *key, const char *def)
{
    char buf[256];
    char *ret = NULL;

    if (!config_filename) return 0;

    /* First lookup <ident>_key, to see if we have a service-specific
     * override */

    if (config_ident) {
        if (snprintf(buf,sizeof(buf),"%s_%s",config_ident,key) == -1)
            fatal("key too long in config_getoverflowstring", EX_TEMPFAIL);

        lcase(buf);
        ret = hash_lookup(buf, &confighash);
    }

    /* No service-specific override, check the actual key */
    if (!ret)
        ret = hash_lookup(key, &confighash);

    /* Return what we got or the default */
    return ret ? ret : def;
}

EXPORTED void config_foreachoverflowstring(void (*func)(const char *, const char *, void *),
                                  void *rock)
{
    if (!config_filename) return;

    hash_enumerate(&confighash, (void (*)(const char *, void *, void *)) func, rock);
}

EXPORTED const char *config_partitiondir(const char *partition)
{
    char buf[80];

    if (strlcpy(buf, "partition-", sizeof(buf)) >= sizeof(buf))
        return 0;
    if (strlcat(buf, partition, sizeof(buf)) >= sizeof(buf))
        return 0;

    const char *dir = config_getoverflowstring(buf, NULL);
    if (!dir)
        syslog(LOG_WARNING, "requested partition directory for unknown partition '%s'",
                            partition);

    return dir;
}

EXPORTED const char *config_metapartitiondir(const char *partition)
{
    char buf[80];

    if (strlcpy(buf, "metapartition-", sizeof(buf)) >= sizeof(buf))
        return 0;
    if (strlcat(buf, partition, sizeof(buf)) >= sizeof(buf))
        return 0;

    const char *dir = config_getoverflowstring(buf, NULL);
    if (!dir)
        syslog(LOG_DEBUG, "requested meta partition directory for unknown partition '%s'",
                          partition);

    return dir;
}

EXPORTED const char *config_archivepartitiondir(const char *partition)
{
    char buf[80];

    if (!config_getswitch(IMAPOPT_ARCHIVE_ENABLED))
        return NULL;

    if(strlcpy(buf, "archivepartition-", sizeof(buf)) >= sizeof(buf))
        return NULL;
    if(strlcat(buf, partition, sizeof(buf)) >= sizeof(buf))
        return NULL;

    const char *dir = config_getoverflowstring(buf, NULL);
    if (!dir)
        syslog(LOG_DEBUG, "requested archive partition directory for unknown partition '%s'",
                          partition);

    return dir;
}

static void config_ispartition(const char *key,
                               const char *val __attribute__((unused)),
                               void *rock)
{
    int *found = (int *) rock;

    if (!strncmp("partition-", key, 10)) *found = 1;
}

static void config_option_deprecate(const int dopt)
{
    const int opt = imapopts[dopt].preferred_opt;
    const char *since = imapopts[dopt].deprecated_since;

    if (opt == IMAPOPT_ZERO) {
        syslog(LOG_WARNING, "Option '%s' is deprecated in version %s.",
               imapopts[dopt].optname, since);
        return;
    }

    syslog(LOG_WARNING,
           "Option '%s' is deprecated in favor of '%s' since version %s.",
           imapopts[dopt].optname, imapopts[opt].optname, since);

    /* Don't override values if the preferred option has been seen */
    if (imapopts[opt].seen) return;

    imapopts[opt].seen = imapopts[dopt].seen;

    switch (imapopts[dopt].t) {
    case OPT_BITFIELD:
        imapopts[opt].val.x = imapopts[dopt].val.x;
        break;

    case OPT_ENUM:
        imapopts[opt].val.e = imapopts[dopt].val.e;
        break;

    case OPT_SWITCH:
        imapopts[opt].val.b = imapopts[dopt].val.b;
        break;

    case OPT_INT:
        imapopts[opt].val.i = imapopts[dopt].val.i;
        break;

    case OPT_STRINGLIST:
    case OPT_STRING:
    case OPT_DURATION:
    case OPT_BYTESIZE:
        imapopts[opt].val.s = imapopts[dopt].val.s;
        imapopts[dopt].val.s = NULL;
        break;

    default:
        break;
    }
}

/*
 * Reset the global configuration to a virginal state.  This is
 * only useful for unit tests.
 */
EXPORTED void config_reset(void)
{
    enum imapopt opt;

    /* XXX this gate should probably use config_loaded, not config_filename */
    if (!config_filename)
        return;

    free((char *)config_filename);
    config_filename = NULL;
    if (config_servername != config_getstring(IMAPOPT_SERVERNAME))
        free((char *)config_servername);
    config_servername = NULL;
    strarray_fini(&config_cua_domains);
    config_defpartition = NULL;
    config_mupdate_server = NULL;
    config_mupdate_config = 0;
    config_hashimapspool = 0;
    config_virtdomains = 0;
    config_defdomain = NULL;
    config_auditlog = 0;
    config_serverinfo = 0;
    config_maxliteral = 0;
    config_maxquoted = 0;
    config_maxword = 0;
    config_qosmarking = 0;
    config_debug = 0;
    config_toggle_debug_cb = NULL;
    config_debug_slowio = 0;
    config_fatals_abort = 0;
    config_zoneinfo_dir = NULL;
    strarray_free(config_admins);
    config_admins = NULL;

    /* reset all the options */
    for (opt = IMAPOPT_ZERO; opt < IMAPOPT_LAST; opt++) {
        if ((imapopts[opt].t == OPT_STRING ||
             imapopts[opt].t == OPT_DURATION ||
             imapopts[opt].t == OPT_BYTESIZE) &&
            (imapopts[opt].seen ||
             (imapopts[opt].def.s &&
              imapopts[opt].val.s != imapopts[opt].def.s &&
              !strncasecmp(imapopts[opt].def.s, "{configdirectory}", 17))))
            free((char *)imapopts[opt].val.s);
        memcpy(&imapopts[opt].val,
               &imapopts[opt].def,
               sizeof(imapopts[opt].val));
        imapopts[opt].seen = 0;
    }
    config_dir = NULL;

    /* free the overflow table */
    free_hash_table(&confighash, free);

    /* in normal use this was either freed already or we fatal'd out,
     * but under cunit we may continue after catching a fatal, so make
     * sure includehash gets reset with everything else
     */
    free_hash_table(&includehash, NULL);

    /* we no longer have loaded config */
    config_loaded = 0;
}

static const unsigned char qos[] = {
/* cs0..cs7 */          0x00, 0x20, 0x40, 0x60, 0x80, 0xa0, 0xc0, 0xe0,
/* af11..af13 */        0x28, 0x30, 0x38,
/* af21..af23 */        0x48, 0x50, 0x58,
/* af31..af33 */        0x68, 0x70, 0x78,
/* af41..af43 */        0x88, 0x90, 0x98,
/* ef */                0xb8
};


EXPORTED void config_read(const char *alt_config, const int config_need_data)
{
    enum imapopt opt = IMAPOPT_ZERO;
    char buf[4096];
    char *p;
    int ival;
    int64_t i64val;
    const char *cua_domains;
    char *domain;
    tok_t tok;

    config_loaded = 1;

    /* XXX this is leaked, this may be able to be better in 2.2 (cyrus_done) */
    if (alt_config) config_filename = xstrdup(alt_config);
    else config_filename = xstrdup(CONFIG_FILENAME);

    if (!construct_hash_table(&confighash, CONFIGHASHSIZE, 1)) {
        fatal("could not construct configuration hash table", EX_CONFIG);
    }

    if (!construct_hash_table(&includehash, INCLUDEHASHSIZE, 1)) {
        fatal("could not construct include file  hash table", EX_CONFIG);
    }

    config_read_file(config_filename);

    free_hash_table(&includehash, NULL);

    /* Check configdirectory config option */
    if (!config_dir) {
        fatal("configdirectory option not specified in configuration file",
              EX_CONFIG);
    }

    for (opt = IMAPOPT_ZERO; opt < IMAPOPT_LAST; opt++) {
        /* Scan options to see if we need to replace {configdirectory} */
        /* XXX need to scan overflow options as well! */

        /* Skip options that have a NULL value, aren't strings, or
         * are the configdirectory option */
        if (
                !imapopts[opt].val.s ||
                imapopts[opt].t != OPT_STRING ||
                opt == IMAPOPT_CONFIGDIRECTORY
            ) {

            continue;
        }

        /* We use some magic numbers here,
         * 17 is the length of "{configdirectory}",
         * 16 is one less than that length, so that the replacement string
         *    that is malloced has room for the '\0' */
        if (!strncasecmp(imapopts[opt].val.s,"{configdirectory}",17)) {
            const char *str = imapopts[opt].val.s;
            char *newstring =
                xmalloc(strlen(config_dir) + strlen(str) - 16);
            char *freeme = NULL;

            /* we need to replace this string, will we need to free
             * the current value?  -- only if we've actually seen it in
             * the config file. */
            if (imapopts[opt].seen)
                freeme = (char *)str;

            /* Build replacement string from configdirectory option */
            strcpy(newstring, config_dir);
            strcat(newstring, str + 17);

            imapopts[opt].val.s = newstring;

            if (freeme) free(freeme);
        }
    }

    for (opt = IMAPOPT_ZERO; opt < IMAPOPT_LAST; opt++) {
        /* See if the option configured is a part of the deprecated hash. */
        if (imapopts[opt].seen && imapopts[opt].deprecated_since) {
            config_option_deprecate(opt);
        }
    }

    /* Look up default partition */
    config_defpartition = config_getstring(IMAPOPT_DEFAULTPARTITION);
    for (p = (char *)config_defpartition; p && *p; p++) {
        if (!Uisalnum(*p)) {
            syslog(LOG_ERR, "INVALID defaultpartition: %s",
                   config_defpartition);
            fatal("defaultpartition option contains non-alnum character",
                  EX_CONFIG);
        }
        if (Uisupper(*p)) *p = tolower((unsigned char) *p);
    }

    config_mupdate_server = config_getstring(IMAPOPT_MUPDATE_SERVER);

    if (config_mupdate_server) {
        config_mupdate_config = config_getenum(IMAPOPT_MUPDATE_CONFIG);
    }

    if (config_need_data & CONFIG_NEED_PARTITION_DATA) {
        int found = 0;

        if (config_defpartition) {
            /* see if defaultpartition is specified properly */
            if (config_partitiondir(config_defpartition)) found = 1;
        }
        else if ((config_mupdate_config == IMAP_ENUM_MUPDATE_CONFIG_STANDARD)
                 && !config_getstring(IMAPOPT_PROXYSERVERS)) {
            found = 1; /* don't need partitions on the frontend */
        }
        else {
            /* see if we have ANY partition-<name> options */
            config_foreachoverflowstring(config_ispartition, &found);
        }

        if (!found) {
            snprintf(buf, sizeof(buf),
                     "partition-%s option not specified in configuration file",
                     config_defpartition ? config_defpartition : "<name>");
            fatal(buf, EX_CONFIG);
        }

        if (config_check_partitions(NULL)) {
            fatal("invalid partition value detected", EX_CONFIG);
        }
    }

    /* look up mailbox hashing */
    config_hashimapspool = config_getswitch(IMAPOPT_HASHIMAPSPOOL);

    /* are we supporting virtual domains?  */
    config_virtdomains = config_getenum(IMAPOPT_VIRTDOMAINS);
    config_defdomain = config_getstring(IMAPOPT_DEFAULTDOMAIN);

    /* are we auditlogging */
    config_auditlog = config_getswitch(IMAPOPT_AUDITLOG);

    /* are we doing I/O logging */
    config_iolog = config_getswitch(IMAPOPT_IOLOG);
    if (config_iolog) {
        if (access("/proc/self/io", R_OK)) {
            config_iolog = 0;
            syslog(LOG_WARNING,"iolog directive needs a kernel built with I/O accounting");
        }
    }

    /* look up the hostname and info we should present to the user */
    config_servername = config_getstring(IMAPOPT_SERVERNAME);
    if (!config_servername) {
        config_servername = xmalloc(sizeof(char) * 256);
        gethostname((char *) config_servername, 256);
    }
    config_serverinfo = config_getenum(IMAPOPT_SERVERINFO);

    
    /* create an array of calendar-user-address-set domains */
    cua_domains = config_getstring(IMAPOPT_CALENDAR_USER_ADDRESS_SET);
    if (!cua_domains) cua_domains = config_defdomain;

    tok_init(&tok, cua_domains, " \t", TOK_TRIMLEFT|TOK_TRIMRIGHT);
    while ((domain = tok_next(&tok)))
        strarray_append(&config_cua_domains, domain);
    tok_fini(&tok);

    /* set some limits */
    i64val = config_getbytesize(IMAPOPT_MAXLITERAL, 'B');
    if (i64val <= 0 || i64val > BYTESIZE_UNLIMITED) {
        i64val = BYTESIZE_UNLIMITED;
    }
    config_maxliteral = i64val;
    i64val = config_getbytesize(IMAPOPT_MAXQUOTED, 'B');
    if (i64val <= 0 || i64val > BYTESIZE_UNLIMITED) {
        i64val = BYTESIZE_UNLIMITED;
    }
    config_maxquoted = i64val;
    i64val = config_getbytesize(IMAPOPT_MAXWORD, 'B');
    if (i64val <= 0 || i64val > BYTESIZE_UNLIMITED) {
        i64val = BYTESIZE_UNLIMITED;
    }
    config_maxword = i64val;

    ival = config_getenum(IMAPOPT_QOSMARKING);
    config_qosmarking = qos[ival];

    /* allow debug logging */
    config_debug = config_getswitch(IMAPOPT_DEBUG);
    if (config_toggle_debug_cb) config_toggle_debug_cb();

    /* do we want artificially-slow I/O ops */
    config_debug_slowio = config_getswitch(IMAPOPT_DEBUG_SLOWIO);

    /* do we want to abort() on fatal errors */
    config_fatals_abort = config_getswitch(IMAPOPT_FATALS_ABORT);

    config_zoneinfo_dir = config_getstring(IMAPOPT_ZONEINFO_DIR);
#ifdef DEFAULT_ZONEINFO_DIR
    if (!config_zoneinfo_dir)
        config_zoneinfo_dir = DEFAULT_ZONEINFO_DIR;
#endif

    config_admins = strarray_split(config_getstring(IMAPOPT_ADMINS),
                                   NULL, STRARRAY_TRIM);
}

#define GROWSIZE 4096

static void config_add_overflowstring(const char *key, const char *value, int lineno)
{
    char *newval = xstrdup(value);
    if (newval != hash_insert(key, newval, &confighash)) {
        char errbuf[1024];
        snprintf(errbuf, sizeof(errbuf),
                "option '%s' was specified twice in config file "
                "(second occurrence on line %d)",
                key, lineno);
        fatal(errbuf, EX_CONFIG);
    }
}

EXPORTED int config_parse_switch(const char *p)
{
    if (*p == '0' || *p == 'n' ||
            (*p == 'o' && p[1] == 'f') || *p == 'f') {
        return 0;
    }
    else if (*p == '1' || *p == 'y' ||
            (*p == 'o' && p[1] == 'n') || *p == 't') {
        return 1;
    }
    return -1;
}

static void config_read_file(const char *filename)
{
    FILE *infile = NULL;
    enum imapopt opt = IMAPOPT_ZERO;
    int lineno = 0;
    char *buf, errbuf[1024];
    const char *cyrus_path;
    unsigned bufsize, len;
    char *p, *q, *key, *fullkey, *srvkey;
    int service_specific;
    int idlen = (config_ident ? strlen(config_ident) : 0);

    bufsize = GROWSIZE;
    buf = xmalloc(bufsize);

    /* read in config file
       Check if we have CYRUS_PREFIX defined, and then use that config */
    cyrus_path = getenv("CYRUS_PREFIX");
    if (cyrus_path) {
        strlcpy(buf, cyrus_path, bufsize);
        strlcat(buf, filename, bufsize);
        infile = fopen(buf, "r");
    }

    if (!infile)
        infile = fopen(filename, "r");

    if (!infile) {
        snprintf(errbuf, sizeof(errbuf),
                 "can't open configuration file %s: %s",
                 filename, strerror(errno));
        free(buf);
        fatal(errbuf, EX_CONFIG);
    }

    /* check to see if we've already read this file */
    if (hash_lookup(filename, &includehash)) {
        snprintf(errbuf, sizeof(errbuf),
                 "configuration file %s included twice",
                 filename);
        free(buf);
        fatal(errbuf, EX_CONFIG);
    }
    else {
        hash_insert(filename, (void*) 0xDEADBEEF, &includehash);
    }

    len = 0;
    while (fgets(buf+len, bufsize-len, infile)) {
        if (buf[len]) {
            len = strlen(buf);
            if (buf[len-1] == '\n') {
                /* end of line */
                buf[--len] = '\0';

                if (len && buf[len-1] == '\\') {
                    /* line continuation */
                    len--;
                    lineno++;
                    continue;
                }
            }
            else if (!feof(infile) && len == bufsize-1) {
                /* line is longer than the buffer */
                bufsize += GROWSIZE;
                buf = xrealloc(buf, bufsize);
                continue;
            }
        }
        len = 0;
        lineno++;

        service_specific = 0;

        /* remove leading whitespace */
        for (p = buf; *p && Uisspace(*p); p++);

        /* skip comments */
        if (!*p || *p == '#') continue;

        fullkey = key = p;
        if (*p == '@') p++;  /* allow @ as the first char (for directives) */
        while (*p && (Uisalnum(*p) || *p == '-' || *p == '_')) {
            if (Uisupper(*p)) *p = tolower((unsigned char) *p);
            p++;
        }
        if (*p != ':') {
            snprintf(errbuf, sizeof(errbuf),
                     "invalid option name on line %d of configuration file %s",
                     lineno, filename);
            free(buf);
            fatal(errbuf, EX_CONFIG);
        }
        *p++ = '\0';

        /* remove leading whitespace */
        while (*p && Uisspace(*p)) p++;

        /* remove trailing whitespace */
        for (q = p + strlen(p) - 1; q > p && Uisspace(*q); q--) {
            *q = '\0';
        }

        if (!*p) {
            snprintf(errbuf, sizeof(errbuf),
                     "empty option value on line %d of configuration file",
                     lineno);
            free(buf);
            fatal(errbuf, EX_CONFIG);
        }

        srvkey = NULL;

        /* Look for directives */
        if (key[0] == '@') {
            if (!strcasecmp(key, "@include")) {
                config_read_file(p);
                continue;
            }
            else {
                snprintf(errbuf, sizeof(errbuf),
                         "invalid directive on line %d of configuration file %s",
                         lineno, filename);
                free(buf);
                fatal(errbuf, EX_CONFIG);
            }
        }

        /* Find if there is a <service>_ prefix */
        if (config_ident && !strncasecmp(key, config_ident, idlen)
           && key[idlen] == '_') {
            /* skip service_ prefix */
            srvkey = key + idlen + 1;
        }

        /* look for a service_ prefix match in imapopts */
        if (srvkey) {
            for (opt = IMAPOPT_ZERO; opt < IMAPOPT_LAST; opt++) {
                if (!strcasecmp(imapopts[opt].optname, srvkey)) {
                    key = srvkey;
                    service_specific = 1;
                    break;
                }
            }
        }

        /* Did not find a service_ specific match, try looking for an
         * exact match */
        if (!service_specific) {
            for (opt = IMAPOPT_ZERO; opt < IMAPOPT_LAST; opt++) {
                if (!strcasecmp(imapopts[opt].optname, key)) {
                    break;
                }
            }
        }

        /* If both of those loops failed, it goes verbatim into the
         * overflow hash table. */

        if (opt < IMAPOPT_LAST) {
            /* Okay, we know about this configure option.
             * So first check that we have either
             *  1. not seen it
             *  2. seen its generic form, but this is a service specific form
             *
             *  If we have already seen a service-specific form, and this is
             *  a generic form, just skip it and don't moan.
             */
            if (
                    (imapopts[opt].seen == 1 && !service_specific) ||
                    (imapopts[opt].seen == 2 && service_specific)
                ) {

                snprintf(errbuf, sizeof(errbuf),
                         "option '%s' was specified twice in config file"
                         " (second occurrence on line %d)",
                         fullkey, lineno);
                free(buf);
                fatal(errbuf, EX_CONFIG);

            } else if (imapopts[opt].seen == 2 && !service_specific) {
                continue;
            }

            /* If we've seen it already, we're replacing it, so we need
             * to free the current string if there is one */
            if (imapopts[opt].seen
                && (imapopts[opt].t == OPT_STRING
                    || imapopts[opt].t == OPT_DURATION
                    || imapopts[opt].t == OPT_BYTESIZE))
                free((char *)imapopts[opt].val.s);

            if (service_specific)
                imapopts[opt].seen = 2;
            else
                imapopts[opt].seen = 1;

            /* If this is a deprecated option, save a copy of its value to the
             * overflow hash.  If we need to look up the deprecated name for
             * some reason, we can do so with config_getoverflowstring().
             */
            if (imapopts[opt].deprecated_since) {
                config_add_overflowstring(fullkey, p, lineno);
            }

            /* this is a known option */
            switch (imapopts[opt].t) {
            case OPT_STRING:
            {
                imapopts[opt].val.s = xstrdup(p);

                if (opt == IMAPOPT_CONFIGDIRECTORY)
                    config_dir = imapopts[opt].val.s;

                break;
            }
            case OPT_INT:
            {
                long val;
                char *ptr;

                val = strtol(p, &ptr, 0);
                if (!ptr || *ptr != '\0') {
                    /* error during conversion */
                    snprintf(errbuf, sizeof(errbuf),
                             "non-integer value for %s in line %d",
                             imapopts[opt].optname, lineno);
                    free(buf);
                    fatal(errbuf, EX_CONFIG);
                }

                imapopts[opt].val.i = val;
                break;
            }
            case OPT_SWITCH:
            {
                int b = config_parse_switch(p);
                if (b < 0) {
                    /* error during conversion */
                    snprintf(errbuf, sizeof(errbuf),
                             "non-switch value for %s in line %d",
                             imapopts[opt].optname, lineno);
                    free(buf);
                    fatal(errbuf, EX_CONFIG);
                }
                imapopts[opt].val.b = b;
                break;
            }
            case OPT_ENUM:
            case OPT_STRINGLIST:
            case OPT_BITFIELD:
            {
                const struct enum_option_s *e;

                /* zero the value */
                memset(&imapopts[opt].val, 0, sizeof(imapopts[opt].val));

                /* q is already at EOS so we'll process entire the string
                   as one value unless told otherwise */

                if (imapopts[opt].t == OPT_ENUM) {
                    /* normalize on/off values
                     * we don't write to p in this section of the parser, so
                     * this is safe, but if that ever changes it'll crash!
                     */
                    if (!strcmp(p, "1") || !strcmp(p, "yes") ||
                        !strcmp(p, "t") || !strcmp(p, "true"))
                    {
                        p = (char *) "on";
                    }
                    else if (!strcmp(p, "0") || !strcmp(p, "no") ||
                             !strcmp(p, "f") || !strcmp(p, "false"))
                    {
                        p = (char *) "off";
                    }
                } else if (imapopts[opt].t == OPT_BITFIELD) {
                    /* split the string into separate values */
                    q = p;
                }

                while (*p) {
                    /* find the end of the first value */
                    for (; *q && !Uisspace(*q); q++);
                    if (*q) *q++ = '\0';

                    /* see if its a legal value */
                    for (e = imapopts[opt].enum_options;
                         e->name && strcmp(e->name, p); e++);

                    if (!e->name) {
                        /* error during conversion */
                        snprintf(errbuf, sizeof(errbuf),
                                 "invalid value '%s' for %s in line %d",
                                 p, imapopts[opt].optname, lineno);
                        free(buf);
                        fatal(errbuf, EX_CONFIG);
                    }
                    else if (imapopts[opt].t == OPT_STRINGLIST)
                        imapopts[opt].val.s = e->name;
                    else if (imapopts[opt].t == OPT_ENUM)
                        imapopts[opt].val.e = e->val;
                    else {
                        const struct enum_option_s *pref = e;
                        for (; pref > imapopts[opt].enum_options &&
                                 pref[-1].val == e->val; pref--);
                        if (pref != e) {
                            syslog(LOG_WARNING,
                                   "Value '%s' for option '%s'"
                                   " is deprecated in favor of value '%s'",
                                   e->name, imapopts[opt].optname, pref->name);
                        }

                        imapopts[opt].val.x |= e->val;
                    }

                    /* find the start of the next value */
                    for (p = q; *p && Uisspace(*p); p++);
                    q = p;
                }

                break;
            }
            case OPT_DURATION:
            {
                /* make sure it's parseable, though we don't know the default units */
                if (config_parseduration(p, '\0', NULL)) {
                    imapopts[opt].seen = 0; /* not seen after all */
                    snprintf(errbuf, sizeof(errbuf),
                             "unparsable duration '%s' for %s in line %d",
                             p, imapopts[opt].optname, lineno);
                    free(buf);
                    fatal(errbuf, EX_CONFIG);
                }

                /* but then store it unparsed, it will be parsed again by
                 * config_getduration() where the caller knows the appropriate
                 * default units */
                imapopts[opt].val.s = xstrdup(p);
                break;
            }
            case OPT_BYTESIZE:
            {
                /* make sure it's parseable, though we don't know the default units */
                if (config_parsebytesize(p, '\0', NULL)) {
                    imapopts[opt].seen = 0; /* not seen after all */
                    snprintf(errbuf, sizeof(errbuf),
                             "unparsable byte size '%s' for %s in line %d",
                             p, imapopts[opt].optname, lineno);
                    free(buf);
                    fatal(errbuf, EX_CONFIG);
                }

                /* but then store it unparsed, it will be parsed again by
                 * config_getbytesize() where the caller knows the appropriate
                 * default units */
                imapopts[opt].val.s = xstrdup(p);
                break;
            }
            case OPT_NOTOPT:
            default:
                abort();
            }
        } else {
            /* check to make sure it's valid for overflow */
            /* that is, partition names and anything that might be
             * used by SASL */
/*
  XXX this would be nice if it wasn't for other services who might be
      sharing this config file and whose names we cannot predict

            if (strncasecmp(key,"sasl_",5)
                && strncasecmp(key,"partition-",10))
            {
                snprintf(errbuf, sizeof(errbuf),
                         "option '%s' is unknown on line %d of config file",
                         fullkey, lineno);
                free(buf);
                fatal(errbuf, EX_CONFIG);
            }
*/

            /* Put it in the overflow hash table */
            config_add_overflowstring(key, p, lineno);
        }
    }

    fclose(infile);
    free(buf);
}

EXPORTED void config_toggle_debug(void)
{
    config_debug = !config_debug;
    if (config_toggle_debug_cb) config_toggle_debug_cb();
}

static const unsigned char cmpstringp_path_lookup[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,  /* interesting */
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x20,  /* bit is here */
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};
_Static_assert(256 == sizeof(cmpstringp_path_lookup),
               "cmpstringp_path_lookup has wrong number of elems");

/* Treats '/' (0x2f) as lower than other printables so that
 * file paths sort pre-order, depth-first.
 * XXX This should probably be in lib/bsearch.c, but that's in
 * XXX libcyrus, which we don't have here.
 */
static int cmpstringp_path(const void *aa, const void *bb)
{
    const unsigned char *a = *(const unsigned char **) aa;
    const unsigned char *b = *(const unsigned char **) bb;
    int cmp = 0;

    #define L(x) (cmpstringp_path_lookup[x])
    #define CMP(y,z) ((y) > (z)) - ((y) < (z))

    while (*a && *b && 0 == (cmp = CMP(L(*a), L(*b)))) {
        a++;
        b++;
    }

    /* found a mismatch */
    if (cmp) return cmp;

    /* Walked off the end of one (or both) strings, in which case one
     * (or both) of these will be zero, and the string with bytes remaining
     * is the greater.
     */
    return CMP(*a, *b);

    #undef CMP
    #undef L
}

static void collect_partitions(const char *key, const char *value, void *rock)
{
    hash_table *by_value = rock;

    if (strstr(key, "partition-")) {
        strarray_t *keys;

        keys = hash_lookup(value, by_value);
        if (!keys) {
            keys = hash_insert(value, strarray_new(), by_value);
        }

        strarray_append(keys, key);
    }
}

struct check_no_dups_rock {
    FILE *user_output;
    int *found_bad;
};

static void check_no_dups(const char *value, void *vpkeys, void *vprock)
{
    const strarray_t *keys = vpkeys;
    struct check_no_dups_rock *rock = vprock;
    FILE *user_output = rock->user_output;
    int *found_bad = rock->found_bad;

    if (strarray_size(keys) > 1) {
        char *joined_keys = NULL;

        joined_keys = strarray_join(keys, ",");
        xsyslog(LOG_ERR, "disk path used by multiple partitions",
                         "path=<%s> partitions=<%s>",
                         value, joined_keys);
        free(joined_keys);

        if (user_output) {
            int i, n;

            for (i = 0, n = strarray_size(keys); i < n; i++) {
                fprintf(user_output, "%s: %s\n", strarray_nth(keys, i), value);
            }
        }

        (*found_bad) ++;
    }
}

static void dump_kv(FILE *user_output,
                    hash_table *by_value,
                    const char *value)
{
    const strarray_t *keys;

    keys = hash_lookup(value, by_value);
    if (keys && strarray_size(keys)) {
        fprintf(user_output, "%s: %s\n", strarray_nth(keys, 0), value);
    }
}

static int check_no_subdirs(hash_table *by_value, FILE *user_output)
{
    strarray_t *all_values;
    const char *prev, *value;
    int found_bad = 0, i, n;

    all_values = hash_keys(by_value);
    strarray_sort(all_values, cmpstringp_path);
    prev = strarray_nth(all_values, 0);
    for (i = 1, n = strarray_size(all_values); i < n; i++) {
        size_t prev_len = strlen(prev);

        value = strarray_nth(all_values, i);
        if (strlen(value) > prev_len
            && 0 == strncmp(prev, value, prev_len)
            && value[prev_len] == '/')
        {
            /* XXX only logs first example, and no keys... */
            xsyslog(LOG_ERR, "disk path is a prefix of others",
                             "path1=<%s> path2=<%s>",
                             prev, value);
            if (user_output) {
                dump_kv(user_output, by_value, prev);
                dump_kv(user_output, by_value, value);
            }
            found_bad++;
        }

        prev = value;
    }

    strarray_free(all_values);

    return found_bad;
}

/* free_hash_table() needs a function matching free()'s signature */
static void wrap_strarray_free(void *vp)
{
    strarray_free((strarray_t *) vp);
}

EXPORTED int config_check_partitions(FILE *user_output)
{
    hash_table by_value = HASH_TABLE_INITIALIZER;
    int found_bad = 0;

    assert(config_loaded);

    /* supposing 2 search tiers, that's possibly 5 disk paths per named
     * partition.  supposing 5 named partitions, that's possibly 25 paths.
     */
    construct_hash_table(&by_value, 25, /* mpool */ 1);

    config_foreachoverflowstring(&collect_partitions, &by_value);

    /* check that multiple partitions are not using the same disk path */
    hash_enumerate(&by_value, &check_no_dups, &(struct check_no_dups_rock){
                                                    user_output,
                                                    &found_bad,
                                                });

    /* check that partitions are not subdirectories of other partitions */
    found_bad += check_no_subdirs(&by_value, user_output);

    free_hash_table(&by_value, &wrap_strarray_free);
    return 0 - found_bad;
}

/* Examine the name of a file, and return a single character
 * (as an int) that can be used as the name of a hash
 * directory.  Stop before the first dot.  Caller is responsible
 * for skipping any prefix of the name.
 */
EXPORTED int dir_hash_c(const char *name, int full)
{
    int c;

    if (full) {
        unsigned char *pt;
        uint32_t n;
        enum {
            DIR_X = 3,
            DIR_Y = 5,
            DIR_P = 23,
            DIR_A = 'A'
        };

        n = 0;
        pt = (unsigned char *)name;
        while (*pt && *pt != '.') {
            n = ((n << DIR_X) ^ (n >> DIR_Y)) ^ *pt;
            n &= UINT32_MAX;
            ++pt;
        }
        c = DIR_A + (n % DIR_P);
    }
    else {
        c = tolower(*name);
        if (!Uisascii(c) || !Uislower(c)) c = 'q';
    }

    return c;
}

EXPORTED char *dir_hash_b(const char *name, int full, char buf[2])
{
    buf[0] = (char)dir_hash_c(name, full);
    buf[1] = '\0';
    return buf;
}
