/* masterconfig.c -- Configuration routines for master process
 $Id: masterconf.c,v 1.6.6.4 2003/02/06 22:41:03 rjs3 Exp $
 
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sysexits.h>

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "masterconf.h"

struct configlist {
    char *key;
    char *value;
};

extern void fatal(const char *buf, int code);

int masterconf_init(const char *ident)
{
    openlog(ident, LOG_PID, SYSLOG_FACILITY);

    return 0;
}

struct entry {
    char *line;
    int lineno;
};

const char *masterconf_getstring(struct entry *e, const char *key, 
				 const char *def)
{
    char k[256];
    static char v[256];
    int i;
    char *p;

    strcpy(k, key);
    strcat(k, "=");

    p = strstr(e->line, k);
    if (p) {
	p += strlen(k);
	if (*p == '"') {
	    p++;
	    for (i = 0; i < 255; i++) {
		if (*p == '"') break;
		v[i] = *p++;
	    }
	    if (*p != '"') {
		sprintf(k, "configuration file %s: missing \" on line %d",
			MASTER_CONFIG_FILENAME, e->lineno);
		fatal(k, EX_CONFIG);
	    }
	} else {
	    /* one word */
	    for (i = 0; i < 255; i++) {
		if (isspace((int) *p)) break;
		v[i] = *p++;
	    }
	}
	v[i] = '\0';
	return v;
    } else {
	return def;
    }
}

int masterconf_getint(struct entry *e, 
		      const char *key, int def)
{
    const char *val = masterconf_getstring(e, key, NULL);

    if (!val) return def;
    if (!isdigit((int) *val) && 
	(*val != '-' || !isdigit((int) val[1]))) return def;
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
    return def;
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
	for (p = buf; *p && isspace((int) *p); p++);
	
	/* remove comments */
	q = strchr(p, '#');
	if (q) *q = '\0';

	/* skip empty lines or all comment lines */
	if (!*p) continue;
	if (*p == '}') break;

	for (q = p; isalnum((int) *q); q++) ;
	if (q) { *q = '\0'; q++; }
	
	if (q - p > 0) {
	    /* there's a value on this line */
	    e.line = q;
	    e.lineno = lineno;
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
    FILE *infile;
    int seclen = strlen(section);
    int level = 0;
    int lineno = 0;
    char buf[4096];

    infile = fopen(MASTER_CONFIG_FILENAME, "r");
    if (!infile) {
	snprintf(buf, sizeof(buf), "can't open configuration file %s: %s",
		MASTER_CONFIG_FILENAME, strerror(errno));
	fatal(buf, EX_CONFIG);
    }

    while (fgets(buf, sizeof(buf), infile)) {
	char *p, *q;

	lineno++;

	if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
	for (p = buf; *p && isspace((int) *p); p++);
	
	/* remove comments */
	q = strchr(p, '#');
	if (q) *q = '\0';

	/* skip empty lines or all comment lines */
	if (!*p) continue;
	
	if (level == 0 &&
	    *p == *section && !strncasecmp(p, section, seclen) &&
	    !isalnum((int) p[seclen])) {
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


