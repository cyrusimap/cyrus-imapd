/* config.c -- Configuration routines
 $Id: config.c,v 1.28 2000/02/18 22:51:34 leg Exp $
 
 # Copyright 1998 Carnegie Mellon University
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

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "config.h"
#include "exitcodes.h"
#include "xmalloc.h"
#include "mboxlist.h"
#include "util.h"
#include "imap_err.h"

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

const char *config_servername;

int config_hashimapspool;

static void config_read P((void));

int config_init(ident)
const char *ident;
{
    char buf[100];
    char *p;
    const char *val;
    int umaskval = 0;

    initialize_imap_error_table();

    openlog(ident, LOG_PID, LOG_LOCAL6);

    config_read();

    /* Look up configdirectory config option */
    config_dir = config_getstring("configdirectory", (char *)0);
    if (!config_dir) {
	fatal("configdirectory option not specified in configuration file",
	      EC_CONFIG);
    }

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

    /* look up the hostname we should present to the user */
    config_servername = config_getstring("servername", 0);
    if (!config_servername) {
	config_servername = xmalloc(sizeof(char) * 256);
	gethostname((char *) config_servername, 256);
    }

    return 0;
}

int config_changeident(const char *ident)
{
    closelog();
    openlog(ident, LOG_PID, LOG_LOCAL6);
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

int config_getint(key, def)
const char *key;
int def;
{
    const char *val = config_getstring(key, (char *)0);

    if (!val) return def;
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) return def;
    return atoi(val);
}

int config_getswitch(key, def)
const char *key;
int def;
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

const char *config_partitiondir(partition)
const char *partition;
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
		error_message(errno));
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
void config_scanpartition( void (*proc)() )
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

/* this is a wrapper to call the cyrus configuration from SASL */
int mysasl_config(void *context __attribute__((unused)), 
		  const char *plugin_name,
		  const char *option,
		  const char **result,
		  unsigned *len)
{
    char opt[1024];

    if (strcmp(option, "srvtab")) { /* we don't transform srvtab! */
	int sl = 5 + (plugin_name ? strlen(plugin_name) + 1 : 0);

	strncpy(opt, "sasl_", 1024);
	if (plugin_name) {
	    strncat(opt, plugin_name, 1019);
	    strncat(opt, "_", 1024 - sl);
	}
 	strncat(opt, option, 1024 - sl - 1);
	opt[1023] = '\0';
    } else {
	strncpy(opt, option, 1024);
    }

    *result = config_getstring(opt, NULL);
    if (*result != NULL) {
	if (len) { *len = strlen(*result); }
	return SASL_OK;
    }
   
    return SASL_FAIL;
}
