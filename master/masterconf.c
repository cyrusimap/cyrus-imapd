/* masterconfig.c -- Configuration routines for master process
 $Id: masterconf.c,v 1.1 2000/02/18 06:42:05 leg Exp $
 
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

static struct configlist *configlist;
static int nconfiglist;

static void masterconf_read(void);
extern void fatal(const char *buf, int code);

int masterconf_init(const char *ident)
{
    openlog(ident, LOG_PID, LOG_LOCAL6);

    masterconf_read();

    return 0;
}

const char *masterconf_getstring(const char *key, const char *def)
{
    int opt;

    for (opt = 0; opt < nconfiglist; opt++) {
	if (*key == configlist[opt].key[0] &&
	    !strcmp(key, configlist[opt].key))
	  return configlist[opt].value;
    }
    return def;
}

int masterconf_getint(const char *key, int def)
{
    const char *val = masterconf_getstring(key, (char *)0);

    if (!val) return def;
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) return def;
    return atoi(val);
}

int masterconf_getswitch(const char *key, int def)
{
    const char *val = masterconf_getstring(key, (char *)0);

    if (!val) return def;

    if (*val == '0' || *val == 'n' ||
	(*val == 'o' && val[1] == 'f') || *val == 'f') {
	return 0;
    }
    else if (*val == '1' || *val == 'y' ||
	     (*val == 'o' && val[1] == 'n') || *val == 't') {
	return 1;
    }
    return def;
}

#define CONFIGLISTGROWSIZE 10 /* 100 */
static void
masterconf_read()
{
    FILE *infile;
    int lineno = 0;
    int alloced = 0;
    char buf[4096];
    char *p, *key;

    infile = fopen(CONFIG_FILENAME, "r");
    if (!infile) {
	sprintf(buf, "can't open configuration file %s: %s", CONFIG_FILENAME,
		strerror(errno));
	fatal(buf, EX_CONFIG);
    }
    
    while (fgets(buf, sizeof(buf), infile)) {
	lineno++;

	if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
	for (p = buf; *p && isspace((int) *p); p++);
	if (!*p || *p == '#') continue;

	key = p;
	while (*p && (isalnum((int) *p) || *p == '-' || *p == '_')) {
	    if (isupper((int) *p)) *p = tolower((int) *p);
	    p++;
	}
	if (*p != ':') {
	    sprintf(buf,
		    "invalid option name on line %d of configuration file",
		    lineno);
	    fatal(buf, EX_CONFIG);
	}
	*p++ = '\0';

	while (*p && isspace((int) *p)) p++;
	
	if (!*p) {
	    sprintf(buf, "empty option value on line %d of configuration file",
		    lineno);
	    fatal(buf, EX_CONFIG);
	}

	if (nconfiglist == alloced) {
	    alloced += CONFIGLISTGROWSIZE;
	    configlist = (struct configlist *)
		realloc((char *)configlist, alloced*sizeof(struct configlist));
	    if (configlist == NULL) goto abort;
	}

	configlist[nconfiglist].key = strdup(key);
	if (!configlist[nconfiglist].key) goto abort;
	configlist[nconfiglist].value = strdup(p);
	if (!configlist[nconfiglist].value) goto abort;
	nconfiglist++;
    }
 abort:
    fclose(infile);
}
