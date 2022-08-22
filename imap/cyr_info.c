/* cyr_info.c - tool to get information about cyrus
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "global.h"
#include "proc.h"
#include "util.h"
#include "../master/masterconf.h"
#include "xmalloc.h"

/* config.c stuff */
const char *MASTER_CONFIG_FILENAME = DEFAULT_MASTER_CONFIG_FILENAME;

struct service_item {
    char *prefix;
    int prefixlen;
    struct service_item *next;
};

static void usage(void)
{
    fprintf(stderr, "cyr_info [-C <altconfig>] [-M <cyrus.conf>] [-n servicename] [-s oldversion] command\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "If you give a service name (-n), it will show config as if you\n");
    fprintf(stderr, "were running that service, i.e. imap\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "If you give an old version (-s), it will highlight config\n");
    fprintf(stderr, "options that are new or whose behaviour has changed since that\n");
    fprintf(stderr, "version.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Where command is one of:\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  * conf          - listing of non-default config values\n");
    fprintf(stderr, "  * conf-all      - listing of all config values\n");
    fprintf(stderr, "  * conf-default  - listing of all default config values\n");
    fprintf(stderr, "  * conf-lint     - unknown config keys\n");
    fprintf(stderr, "  * proc          - listing of all open processes\n");
    fprintf(stderr, "  * version       - Cyrus version\n");
    fprintf(stderr, "\n");
    cyrus_done();
    exit(-1);
}

static int print_procinfo(pid_t pid,
                          const char *servicename, const char *host,
                          const char *user, const char *mailbox,
                          const char *cmdname,
                          void *rock __attribute__((unused)))
{
    printf("%d %s %s", (int)pid, servicename, host);
    if (user) printf(" %s", user);
    if (mailbox) printf(" %s", mailbox);
    if (cmdname) printf(" %s", cmdname);
    printf("\n");
    return 0;
}

static void do_proc(void)
{
    proc_foreach(print_procinfo, NULL);
}

static void print_overflow(const char *key, const char *val,
                          void *rock __attribute__((unused)))
{
    printf("%s: %s\n", key, val);
}

static void highlight(uint32_t version)
{
    printf("(%u.%u.%u) ",
            (version >> 24) & 0xff,
            (version >> 16) & 0xff,
            (version >>  8) & 0xff);
}

static void do_conf(int only_changed, int want_since, uint32_t since)
{
    int i;
    unsigned j;

    /* XXX: this is semi-sorted, but the overflow strings aren't sorted at all */

    for (i = 1; i < IMAPOPT_LAST; i++) {
        switch (imapopts[i].t) {
            case OPT_BITFIELD:
                if (only_changed) {
                    if (imapopts[i].def.x == imapopts[i].val.x) break;
                }
                if (want_since && since < imapopts[i].last_modified)
                    highlight(imapopts[i].last_modified);
                printf("%s:", imapopts[i].optname);
                for (j = 0; imapopts[i].enum_options[j].name; j++) {
                    if (imapopts[i].val.x & (1<<j)) {
                        printf(" %s", imapopts[i].enum_options[j].name);
                    }
                }
                printf("\n");
                break;

            case OPT_DURATION:
                if (only_changed) {
                    if (0 == strcmpsafe(imapopts[i].def.s, imapopts[i].val.s))
                        break;
                }
                if (want_since && since < imapopts[i].last_modified)
                    highlight(imapopts[i].last_modified);
                printf("%s: %s\n", imapopts[i].optname, imapopts[i].val.s);
                break;

            case OPT_ENUM:
                if (only_changed) {
                    if (imapopts[i].def.e == imapopts[i].val.e) break;
                }
                if (want_since && since < imapopts[i].last_modified)
                    highlight(imapopts[i].last_modified);
                printf("%s:", imapopts[i].optname);
                for (j = 0; imapopts[i].enum_options[j].name; j++) {
                    if (imapopts[i].val.e == imapopts[i].enum_options[j].val) {
                        printf(" %s", imapopts[i].enum_options[j].name);
                        break;
                    }
                }
                printf("\n");
                break;

            case OPT_INT:
                if (only_changed) {
                    if (imapopts[i].def.i == imapopts[i].val.i) break;
                }
                if (want_since && since < imapopts[i].last_modified)
                    highlight(imapopts[i].last_modified);
                printf("%s: %ld\n", imapopts[i].optname, imapopts[i].val.i);
                break;

            case OPT_STRING:
            case OPT_STRINGLIST:
                if (only_changed) {
                    const char *defvalue = imapopts[i].def.s;
                    char *freeme = NULL;

                    if (defvalue &&
                        !strncasecmp(defvalue, "{configdirectory}", 17))
                    {
                        freeme = strconcat(imapopts[IMAPOPT_CONFIGDIRECTORY].val.s,
                                           defvalue+17, (char *)NULL);
                        defvalue = freeme;
                    }
                    if (!strcmpsafe(defvalue, imapopts[i].val.s)) {
                        free(freeme);
                        break;
                    }
                    free(freeme);
                }
                if (want_since && since < imapopts[i].last_modified)
                    highlight(imapopts[i].last_modified);
                printf("%s: %s\n", imapopts[i].optname, imapopts[i].val.s ? imapopts[i].val.s : "");
                break;

            case OPT_SWITCH:
                if (only_changed) {
                    if (imapopts[i].def.b == imapopts[i].val.b) break;
                }
                if (want_since && since < imapopts[i].last_modified)
                    highlight(imapopts[i].last_modified);
                printf("%s: %s\n", imapopts[i].optname, imapopts[i].val.b ? "yes" : "no");
                break;

            default:
                abort();
        }
    }

    /* and the overflows */
    config_foreachoverflowstring(print_overflow, NULL);
}

static void do_defconf(int want_since, uint32_t since)
{
    int i;
    unsigned j;

    /* XXX: this is semi-sorted, but the overflow strings aren't sorted at all */

    for (i = 1; i < IMAPOPT_LAST; i++) {
        if (want_since && since < imapopts[i].last_modified)
            highlight(imapopts[i].last_modified);
        switch (imapopts[i].t) {
            case OPT_BITFIELD:
                printf("%s:", imapopts[i].optname);
                for (j = 0; imapopts[i].enum_options[j].name; j++) {
                    if (imapopts[i].def.x & (1<<j)) {
                        printf(" %s", imapopts[i].enum_options[j].name);
                    }
                }
                printf("\n");
                break;

            case OPT_ENUM:
                printf("%s:", imapopts[i].optname);
                for (j = 0; imapopts[i].enum_options[j].name; j++) {
                    if (imapopts[i].val.e == imapopts[i].enum_options[j].val) {
                        printf(" %s", imapopts[i].enum_options[j].name);
                        break;
                    }
                }
                printf("\n");
                break;


            case OPT_INT:
                printf("%s: %ld\n", imapopts[i].optname, imapopts[i].def.i);
                break;

            case OPT_DURATION:
            case OPT_STRING:
            case OPT_STRINGLIST:
                printf("%s: %s\n", imapopts[i].optname, imapopts[i].def.s ? imapopts[i].def.s : "");
                break;

            case OPT_SWITCH:
                printf("%s: %s\n", imapopts[i].optname, imapopts[i].def.b ? "yes" : "no");
                break;

            default:
                abort();
        }
    }
}

static int known_overflowkey(const char *key)
{
    const char *match;
    /* any partition is OK (XXX: are there name restrictions to check?) */
    if (!strncmp(key, "partition-", 10)) return 1;

    /* only valid if there's a partition with the same name */
    if (!strncmp(key, "metapartition-", 14)) {
        if (config_getoverflowstring(key+4, NULL))
            return 1;
    }

    /* only valid if there's a partition with the same name */
    if (!strncmp(key, "archivepartition-", 17)) {
        if (config_getoverflowstring(key+7, NULL))
            return 1;
    }

    /* no relation to partition- */
    if (!strncmp(key, "backuppartition-", 16)) return 1;

    /* XXX prefixed with a tier, which we don't currently validate here */
    match = strstr(key, "searchpartition-");
    if (match) {
        if (config_getoverflowstring(match+6, NULL))
            return 1;
    }

    /* legacy xlist-flag settings are OK */
    if (!strncmp(key, "xlist-", 6)) return 1;

    return 0;
}

static int known_regularkey(const char *key)
{
    int i;

    for (i = 1; i < IMAPOPT_LAST; i++) {
        if (!strcmp(imapopts[i].optname, key))
            return 1;
    }

    return 0;
}

static int known_saslkey(const char *key __attribute__((unused)))
{
    /* XXX - we don't know all the sasl keys, assume it's OK! */
    return 1;
}

struct lint_callback_rock {
    struct service_item *known_services;
    strarray_t *known_channels;
};

static void lint_callback(const char *key, const char *val, void *rock)
{
    struct lint_callback_rock *cbrock = (struct lint_callback_rock *) rock;
    struct service_item *svc;
    int i;

    if (known_overflowkey(key)) return;

    if (!strncmp(key, "sasl_", 5)) {
        if (known_saslkey(key+5)) return;
    }

    for (svc = cbrock->known_services; svc; svc = svc->next) {
        if (!strncmp(key, svc->prefix, svc->prefixlen)) {
            /* check if it's a known key */
            if (known_regularkey(key+svc->prefixlen)) return;
            if (known_overflowkey(key+svc->prefixlen)) return;
        }
    }

    for (i = 0; i < strarray_size(cbrock->known_channels); i++) {
        const char *channel = strarray_nth(cbrock->known_channels, i);
        size_t channel_len = strlen(channel);
        if (!strcmp(channel, "\"\"")) {
            /* ignore default channel, it cannot be a prefix */
            continue;
        }
        else if (!strncmp(key, channel, channel_len)) {
            /* channel prefix must be separated by an underscore */
            if (strlen(key) <= channel_len + 1) break;
            if (key[channel_len] != '_') break;

            /* channel prefix only applies to sync_* options */
            if (strncmp(key + channel_len + 1, "sync_", strlen("sync_"))) break;

            /* check if it's a known key */
            if (known_regularkey(key + channel_len + 1)) return;
            if (known_overflowkey(key + channel_len + 1)) return;
        }
    }

    printf("%s: %s\n", key, val);
}

static void add_service(const char *name,
                        struct entry *e __attribute__((unused)),
                        void *rock)
{
    struct service_item **ksp = (struct service_item **)rock;
    struct service_item *knew = xmalloc(sizeof(struct service_item));
    knew->prefix = strconcat(name, "_", (char *)NULL);
    knew->prefixlen = strlen(knew->prefix);
    knew->next = *ksp;
    *ksp = knew;
}

static void do_lint(void)
{
    struct lint_callback_rock rock = {0};

    /* pull the config from cyrus.conf to get service names */
    masterconf_getsection("SERVICES", &add_service, &rock.known_services);

    /* read channels from sync_log_channels config */
    rock.known_channels = strarray_split(config_getstring(IMAPOPT_SYNC_LOG_CHANNELS),
                                         " ", 0);

    /* check all overflow strings */
    config_foreachoverflowstring(lint_callback, &rock);

    /* XXX - check directories and permissions? */

    /* clean up */
    struct service_item *ks = rock.known_services;
    while (ks) {
        struct service_item *next = ks->next;
        free(ks->prefix);
        free(ks);
        ks = next;
    }
    strarray_free(rock.known_channels);
}

static uint32_t parse_since_version(const char *str)
{
    unsigned parts[3] = {0}, i;
    const char *p;
    int saw_digit = 0;
    size_t pnlen = strlen(PACKAGE_NAME);

    /* politely strip 'cyrus-imapd[- ]' from start of version string */
    if (!strncmp(str, PACKAGE_NAME, pnlen)
            && (str[pnlen] == '-' || str[pnlen] == ' '))
        str += pnlen + 1;

    for (p = str, i = 0; *p; p++) {
        if (cyrus_isdigit(*p)) {
            saw_digit++;
            parts[i] *= 10;
            parts[i] += *p - '0';
            if (parts[i] > 255) usage();
        }
        else if (*p == '.') {
            if (!saw_digit) usage();
            saw_digit = 0;
            if (++i > 2) break;
        }
        else if (*p == '-') {
            break;
        }
        else {
            usage();
        }
    }

    return (parts[0] & 0xff) * 0x01000000
        +  (parts[1] & 0xff) * 0x00010000
        +  (parts[2] & 0xff) * 0x00000100
        +  0;
}

int main(int argc, char *argv[])
{
    int opt;
    const char *alt_config = NULL;
    const char *srvname = "cyr_info";
    uint32_t since = 0;
    int want_since = 0;

    /* keep this in alphabetical order */
    static const char *const short_options = "C:M:n:s:";

    static const struct option long_options[] = {
        /* n.b. no long option for -C */
        /* n.b. no long option for -M */
        { "service", required_argument, NULL, 'n' },
        { "since", required_argument, NULL, 's' },
        { 0, 0, 0, 0 },
    };

    while (-1 != (opt = getopt_long(argc, argv,
                                    short_options, long_options, NULL)))
    {
        switch (opt) {
        case 'C': /* alt config file */
            alt_config = optarg;
            break;

        case 'M': /* alt cyrus.conf file */
            MASTER_CONFIG_FILENAME = optarg;
            break;

        case 'n':
            srvname = optarg;
            break;

        case 's':
            want_since = 1;
            since = parse_since_version(optarg);
            break;

        default:
            usage();
            break;
        }
    }

    if (optind >= argc)
        usage();

    /* we don't need to read config to handle this one */
    if (!strcmp(argv[optind], "version")) {
        printf("%s %s\n", PACKAGE_NAME, CYRUS_VERSION);
        return 0;
    }

    cyrus_init(alt_config, srvname, 0, 0);

    if (!strcmp(argv[optind], "proc"))
        do_proc();
    else if (!strcmp(argv[optind], "conf-all"))
        do_conf(0, want_since, since);
    else if (!strcmp(argv[optind], "conf"))
        do_conf(1, want_since, since);
    else if (!strcmp(argv[optind], "conf-default"))
        do_defconf(want_since, since);
    else if (!strcmp(argv[optind], "conf-lint"))
        do_lint();
    else
        usage();

    cyrus_done();

    return 0;
}
