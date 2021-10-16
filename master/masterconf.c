/* masterconfig.c -- Configuration routines for master process
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sysexits.h>

#include "util.h"
#include "libconfig.h"
#include "xmalloc.h"
#include "xstrlcat.h"
#include "xstrlcpy.h"

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "masterconf.h"

extern const char *MASTER_CONFIG_FILENAME;

struct configlist {
    char *key;
    char *value;
};

extern void fatal(const char *buf, int code)
    __attribute__((noreturn));

void fatalf(int code, const char *fmt, ...)
{
    va_list args;
    char buf[2048];

    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    fatal(buf, code);
}


int masterconf_init(const char *ident, const char *alt_config)
{
    char *buf = NULL;
    const char *prefix;

    /* If our prefix is configured in the environment we can set it early */
    if ((prefix = getenv("CYRUS_SYSLOG_PREFIX"))) {
        buf = strconcat(prefix, "/", ident, NULL);
        openlog(buf, LOG_PID, SYSLOG_FACILITY);
    }
    else {
        openlog(ident, LOG_PID, SYSLOG_FACILITY);
    }

    config_ident = ident;
    config_read(alt_config, 0);

    /* If we didn't already get the syslog prefix from the environment,
     * check config. */
    if (!buf) {
        prefix = config_getstring(IMAPOPT_SYSLOG_PREFIX);
        /* XXX master ignores IMAPOPT_SYSLOG_FACILITY */

        if (prefix)
            buf = strconcat(prefix, "/", ident, NULL);
        else
            buf = xstrdup(ident);

        /* Reopen the log with the new prefix */
        closelog();
        openlog(buf, LOG_PID, SYSLOG_FACILITY);
    }

    /* don't free 'buf', syslog needs it for the lifetime of the process */

    /* drop debug messages locally */
    if (!config_debug)
        setlogmask(~LOG_MASK(LOG_DEBUG));

    return 0;
}

struct entry {
#define MAXARGS     64
    int nargs;
    struct {
        char *key;
        char *value;
    } args[MAXARGS];
    int lineno;
};

const char *masterconf_getstring(struct entry *e, const char *key,
                                 const char *def)
{
    int i;

    for (i = 0 ; i < e->nargs ; i++) {
        if (!strcmp(key, e->args[i].key))
            return e->args[i].value;
    }
    return def;
}

int masterconf_getint(struct entry *e,
                      const char *key, int def)
{
    const char *val = masterconf_getstring(e, key, NULL);

    if (!val) return def;
    if (!Uisdigit(*val) &&
        (*val != '-' || !Uisdigit(val[1]))) {
            syslog(LOG_DEBUG,
                   "value '%s' for '%s' does not look like a number.",
                   val, key);
            return def;
    }
    return atoi(val);
}

int masterconf_getswitch(struct entry *e, const char *key, int def)
{
    const char *val = masterconf_getstring(e, key, NULL);

    if (!val) return def;

    if (val[0] == '0' || val[0] == 'n' ||
        (val[0] == 'o' && val[1] == 'f') || val[0] == 'f') {
        return 0;
    }
    else if (val[0] == '1' || val[0] == 'y' ||
             (val[0] == 'o' && val[1] == 'n') || val[0] == 't') {
        return 1;
    }

    syslog(LOG_DEBUG, "cannot interpret value '%s' for key '%s'. use y/n.",
	       val, key);

    return def;
}

static void split_args(struct entry *e, char *buf)
{
    char *p = buf, *q;
    char *key, *value;

    for (;;) {
        /* skip whitespace before arg */
        while (Uisspace(*p))
            p++;
        if (!*p)
            return;
        key = p;

        /* parse the key */
        for (q = p ; Uisalnum(*q) ; q++)
            ;
        if (*q != '=')
            fatalf(EX_CONFIG, "configuration file %s: "
                              "bad character '%c' in argument on line %d",
                              MASTER_CONFIG_FILENAME, *q, e->lineno);
        *q++ = '\0';

        /* parse the value */
        if (*q == '"') {
            /* quoted string */
            value = ++q;
            q = strchr(q, '"');
            if (!q)
                fatalf(EX_CONFIG, "configuration file %s: missing \" on line %d",
                        MASTER_CONFIG_FILENAME, e->lineno);
            *q++ = '\0';
        }
        else {
            /* simple word */
            value = q;
            while (*q && !Uisspace(*q))
                q++;
            if (*q)
                *q++ = '\0';
        }

        if (e->nargs == MAXARGS)
                fatalf(EX_CONFIG, "configuration file %s: too many arguments on line %d",
                        MASTER_CONFIG_FILENAME, e->lineno);
        e->args[e->nargs].key = key;
        e->args[e->nargs].value = value;
        e->nargs++;
        p = q;
    }
}

static void process_section(FILE *f, int *lnptr,
                            masterconf_process *func, void *rock)
{
    struct entry e;
    char buf[4096];
    int lineno = *lnptr;

    while (fgets(buf, sizeof(buf), f)) {
        char *p, *q;

        lineno++;

        /* remove EOL character */
        if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
        /* remove starting whitespace */
        for (p = buf; *p && Uisspace(*p); p++);

        /* remove comments */
        q = strchr(p, '#');
        if (q) *q = '\0';

        /* skip empty lines or all comment lines */
        if (!*p) continue;
        if (*p == '}') break;

        for (q = p; Uisalnum(*q); q++) ;
        if (*q) {
            if (q > p && !Uisspace(*q))
                fatalf(EX_CONFIG, "configuration file %s: "
                                  "bad character '%c' in name on line %d",
                                  MASTER_CONFIG_FILENAME, *q, lineno);
            *q++ = '\0';
        }

        if (q - p > 0) {
            /* there's a value on this line */
            memset(&e, 0, sizeof(e));
            e.lineno = lineno;
            split_args(&e, q);
            func(p, &e, rock);
        }

        /* end of section? */
        if (strchr(q, '}')) break;
    }

    *lnptr = lineno;
}

void masterconf_getsection(const char *section, masterconf_process *f,
                           void *rock)
{
    FILE *infile = NULL;
    int seclen = strlen(section);
    int level = 0;
    int lineno = 0;
    char buf[4096];
    const char *cyrus_path;

    /* try loading the copy inside CYRUS_PREFIX first */
    cyrus_path = getenv("CYRUS_PREFIX");
    if (cyrus_path) {
        strlcpy(buf, cyrus_path, sizeof(buf));
        strlcat(buf, MASTER_CONFIG_FILENAME, sizeof(buf));
        infile = fopen(buf, "r");
    }

    if (!infile)
        infile = fopen(MASTER_CONFIG_FILENAME, "r");

    if (!infile)
        fatalf(EX_CONFIG, "can't open configuration file %s: %s",
                MASTER_CONFIG_FILENAME, strerror(errno));

    while (fgets(buf, sizeof(buf), infile)) {
        char *p, *q;

        lineno++;

        if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
        for (p = buf; *p && Uisspace(*p); p++);

        /* remove comments */
        q = strchr(p, '#');
        if (q) *q = '\0';

        /* skip empty lines or all comment lines */
        if (!*p) continue;

        if (level == 0 &&
            *p == *section && !strncasecmp(p, section, seclen) &&
            !Uisalnum(p[seclen])) {
            for (p += seclen; *p; p++) {
                if (*p == '{') level++;
                if (*p == '}') level--;
            }

            /* valid opening; process the section */
            if (level == 1) process_section(infile, &lineno, f, rock);

            continue;
        }

        for (; *p; p++) {
            if (*p == '{') level++;
            if (*p == '}') level--;
        }
    }

    fclose(infile);
}


