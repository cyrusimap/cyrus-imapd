/* config.c -- read configuration information from /etc/imapd.conf
 * Tim Martin
 * 9/21/99
 */
/***********************************************************
        Copyright 1999 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#include <stdio.h>
#include <ctype.h>
#include <syslog.h>
#include <com_err.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>


#include "config.h"
#include "exitcodes.h"
#include "xmalloc.h"

extern int errno;

#define CONFIG_FILENAME "/etc/imapd.conf"

struct configlist {
    char *key;
    char *value;
};

static struct configlist *configlist;
static int nconfiglist;

const char *config_dir;
const char *config_defpartition;
const char *config_newsspool;

int config_hashimapspool;

static void config_read P((void));

int config_init(const char *ident)
{
    char buf[100];
    char *p;
    const char *val;
    int umaskval = 0;

    /*     initialize_imap_error_table();*/

    openlog(ident, LOG_PID, LOG_LOCAL6);

    config_read();

    /* Look up configdirectory config option */
    config_dir = config_getstring("configdirectory", (char *)0);
    if (!config_dir) {
	fatal("configdirectory option not specified in configuration file",
	      EC_CONFIG);
    }

    /*    mboxlist_checkconfig();*/

    /* Look up default partition */
    config_defpartition = config_getstring("defaultpartition", "default");
    for (p = (char *)config_defpartition; *p; p++) {
	if (!isalnum((int) *p))
	  fatal("defaultpartition option contains non-alphanumeric character",
		EC_CONFIG);
	if (isupper((int) *p)) *p = tolower((int) *p);
    }
    if (!config_partitiondir(config_defpartition)) {
	sprintf(buf, "partition-%s option not specified in configuration file",
		config_defpartition);
	fatal(buf, EC_CONFIG);
    }

    /* Look up umask */
    val = config_getstring("umask", "077");
    while (*val) {
	if (*val >= '0' && *val <= '7') umaskval = umaskval*8 + *val - '0';
	val++;
    }
    umask(umaskval);

    /* Look up news spool */
    config_newsspool = config_getstring("newsspool", 0);

    /* look up mailbox hashing */
    config_hashimapspool = config_getswitch("hashimapspool", 0);

    return 0;
}

const char *config_getstring(key, def)
const char *key;
const char *def;
{
    int opt;

    for (opt = 0; opt < nconfiglist; opt++) {
	if (*key == configlist[opt].key[0] &&
	    !strcmp(key, configlist[opt].key))
	  return configlist[opt].value;
    }
    return def;
}

int config_getint(const char *key, int def)
{
    const char *val = config_getstring(key, (char *)0);

    if (!val) return def;
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) return def;
    return atoi(val);
}

int config_getswitch(const char *key, int def)
{
    const char *val = config_getstring(key, (char *)0);

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

const char *config_partitiondir(const char *partition)
{
    char buf[80];

    if (strlen(partition) > 70) return 0;
    strcpy(buf, "partition-");
    strcat(buf, partition);

    return config_getstring(buf, (char *)0);
}

#define CONFIGLISTGROWSIZE 10 /* 100 */
static void
config_read()
{
    FILE *infile;
    int lineno = 0;
    int alloced = 0;
    char buf[4096];
    char *p, *key;

    infile = fopen(CONFIG_FILENAME, "r");
    if (!infile) {
	sprintf(buf, "can't open configuration file %s: %s", CONFIG_FILENAME,
		"foo");
	fatal(buf, EC_CONFIG);
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
	    fatal(buf, EC_CONFIG);
	}
	*p++ = '\0';

	while (*p && isspace((int) *p)) p++;
	
	if (!*p) {
	    sprintf(buf, "empty option value on line %d of configuration file",
		    lineno);
	    fatal(buf, EC_CONFIG);
	}

	if (nconfiglist == alloced) {
	    alloced += CONFIGLISTGROWSIZE;
	    configlist = (struct configlist *)
	      xrealloc((char *)configlist, alloced*sizeof(struct configlist));
	}

	configlist[nconfiglist].key = xstrdup(key);
	configlist[nconfiglist].value = xstrdup(p);
	nconfiglist++;
    }
    fclose(infile);
}

/*
 * Call proc (expected to be todo_append in reconstruct.c) with
 * information on each configured partition
 */
void
config_scanpartition(proc)
void (*proc)();
{
    int opt;
    char *s;

    for (opt = 0; opt < nconfiglist; opt++) {
	if (!strncmp(configlist[opt].key, "partition-", 10)) {
	    s = xstrdup(configlist[opt].value);
	    (*proc)(xstrdup(""), s, configlist[opt].key+10);
	}
    }
}
