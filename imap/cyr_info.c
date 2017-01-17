/* ctl_info.c - tool to get information about cyrus
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "global.h"
#include "exitcodes.h"
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
    fprintf(stderr, "cyr_info [-C <altconfig>] [-M <cyrus.conf>] [-n servicename] command [mailbox]\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "If you give a service name, it will show config as if you were\n");
    fprintf(stderr, "running that service, i.e. imap\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Where command is one of:\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  * conf-all      - listing of all config values\n");
    fprintf(stderr, "  * conf          - listing of non-default config values\n");
    fprintf(stderr, "  * conf-default  - listing of all default config values\n");
    fprintf(stderr, "  * conf-lint     - unknown config keys\n");
    fprintf(stderr, "  * proc          - listing of all open processes\n");
    frpintf(stderr, "  * reid [mbox]   - create new unique ID for mailbox [mbox]\n");
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

static void do_conf(int only_changed)
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
                printf("%s:", imapopts[i].optname);
                for (j = 0; imapopts[i].enum_options[j].name; j++) {
                    if (imapopts[i].val.x & (1<<j)) {
                        printf(" %s", imapopts[i].enum_options[j].name);
                    }
                }
                printf("\n");
                break;

            case OPT_ENUM:
                if (only_changed) {
                    if (imapopts[i].def.e == imapopts[i].val.e) break;
                }
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
                printf("%s: %s\n", imapopts[i].optname, imapopts[i].val.s ? imapopts[i].val.s : "");
                break;

            case OPT_SWITCH:
                if (only_changed) {
                    if (imapopts[i].def.b == imapopts[i].val.b) break;
                }
                printf("%s: %s\n", imapopts[i].optname, imapopts[i].val.b ? "yes" : "no");
                break;

            default:
                abort();
        }
    }

    /* and the overflows */
    config_foreachoverflowstring(print_overflow, NULL);
}

static void do_defconf(void)
{
    int i;
    unsigned j;

    /* XXX: this is semi-sorted, but the overflow strings aren't sorted at all */

    for (i = 1; i < IMAPOPT_LAST; i++) {
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
        if (config_getoverflowstring(key+8, NULL))
            return 1;
    }

    /* no relation to partition- */
    if (!strncmp(key, "backuppartition-", 16)) return 1;

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

static void lint_callback(const char *key, const char *val, void *rock)
{
    struct service_item *known_services = (struct service_item *)rock;
    struct service_item *svc;

    if (known_overflowkey(key)) return;

    if (!strncmp(key, "sasl_", 5)) {
        if (known_saslkey(key+5)) return;
    }

    for (svc = known_services; svc; svc = svc->next) {
        if (!strncmp(key, svc->prefix, svc->prefixlen)) {
            /* check if it's a known key */
            if (known_regularkey(key+svc->prefixlen)) return;
            if (known_overflowkey(key+svc->prefixlen)) return;
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
    struct service_item *ks = NULL;

    /* pull the config from cyrus.conf to get service names */
    masterconf_getsection("SERVICES", &add_service, &ks);

    /* check all overflow strings */
    config_foreachoverflowstring(lint_callback, ks);

    /* XXX - check directories and permissions? */

    /* clean up */
    while (ks) {
        struct service_item *next = ks->next;
        free(ks->prefix);
        free(ks);
        ks = next;
    }
}

static void do_reid(const char *mboxname)
{
    struct mailbox *mailbox = NULL;
    mbentry_t *mbentry = NULL;
    int r;

    annotate_init(NULL, NULL);
    annotatemore_open();

    mboxlist_init(0);
    mboxlist_open(NULL);

    r = mailbox_open_iwl(mboxname, &mailbox);
    if (r) return;

    mailbox_make_uniqueid(mailbox);

    r = mboxlist_lookup(mboxname, &mbentry, NULL);
    if (r) return;

    free(mbentry->uniqueid);
    mbentry->uniqueid = xstrdup(mailbox->uniqueid);

    mboxlist_update(mbentry, 0);

    mailbox_close(&mailbox);

    mboxlist_close();
    mboxlist_done();

    annotatemore_close();
    annotate_done();

    printf("did reid %s\n", mboxname);
}

int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt;
    char *alt_config = NULL;
    char *srvname = "cyr_info";

    if ((geteuid()) == 0 && (become_cyrus(/*is_master*/0) != 0)) {
        fatal("must run as the Cyrus user", EC_USAGE);
    }

    while ((opt = getopt(argc, argv, "C:M:n:")) != EOF) {
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

        default:
            usage();
            break;
        }
    }

    cyrus_init(alt_config, srvname, 0, 0);

    if (optind >= argc)
        usage();

    if (!strcmp(argv[optind], "proc"))
        do_proc();
    else if (!strcmp(argv[optind], "conf-all"))
        do_conf(0);
    else if (!strcmp(argv[optind], "conf"))
        do_conf(1);
    else if (!strcmp(argv[optind], "conf-default"))
        do_defconf();
    else if (!strcmp(argv[optind], "conf-lint"))
        do_lint();
    else if (!strcmp(argv[optind], "reid")) {
        if (optind + 1 >= argc)
            usage();
        do_reid(argv[optind+1]);
    }
    else
        usage();

    cyrus_done();

    return 0;
}
