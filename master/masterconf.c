/* masterconfig.c -- Configuration routines for master process
 $Id: masterconf.c,v 1.2 2000/02/21 06:22:58 leg Exp $
 
 # Copyright 2000 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
 *
 */
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <com_err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sysexits.h>

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "masterconf.h"

extern int errno;

#define CONFIG_FILENAME "/etc/cyrus.conf"

struct configlist {
    char *key;
    char *value;
};

extern void fatal(const char *buf, int code);

int masterconf_init(const char *ident)
{
    openlog(ident, LOG_PID, LOG_LOCAL6);

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
			CONFIG_FILENAME, e->lineno);
		fatal(k, EX_CONFIG);
	    }
	} else {
	    /* one word */
	    for (i = 0; i < 255; i++) {
		if (isspace(*p)) break;
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

	for (q = p; isalnum(*q); q++) ;
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

    infile = fopen(CONFIG_FILENAME, "r");
    if (!infile) {
	sprintf(buf, "can't open configuration file %s: %s", CONFIG_FILENAME,
		strerror(errno));
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
	    !isalnum(p[seclen])) {
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

}


