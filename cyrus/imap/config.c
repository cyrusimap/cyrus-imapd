/*
 * Configuration routines
 */
#include <stdio.h>
#include <ctype.h>
#include <sysexits.h>
#include <syslog.h>
#include <com_err.h>

#include "config.h"
#include "xmalloc.h"

/* Many systems don't define EX_CONFIG */
#ifndef EX_CONFIG
#define EX_CONFIG 78
#endif

extern int errno;

#define CONFIG_FILENAME "/etc/imapd.conf"

struct configlist {
    char *key;
    char *value;
};

static struct configlist *configlist;
static int nconfiglist;

char *config_dir;
char *config_defpartition;

config_init(ident)
char *ident;
{
    char buf[100];
    char *p;

    initialize_imap_error_table();

    openlog(ident, LOG_PID, LOG_LOCAL4);

    config_read();

    /* Look up configdirectory config option */
    config_dir = config_getstring("configdirectory", (char *)0);
    if (!config_dir) {
	fatal("configdirectory option not specified in configuration file",
	      EX_CONFIG);
    }

    /* Look up default partition */
    config_defpartition = config_getstring("defaultpartition", "default");
    for (p = config_defpartition; *p; p++) {
	if (!isalnum(*p))
	  fatal("defaultpartition option contains non-alphanumeric character",
		EX_CONFIG);
	if (isupper(*p)) *p = tolower(*p);
    }
    p = config_partitiondir(config_defpartition);
    if (!p) {
	sprintf(buf, "partition-%s option not specified in configuration file",
		config_defpartition);
	fatal(buf, EX_CONFIG);
    }

    return 0;
}

char *config_getstring(key, def)
char *key;
char *def;
{
    int opt;

    for (opt = 0; opt < nconfiglist; opt++) {
	if (*key == configlist[opt].key[0] &&
	    !strcmp(key, configlist[opt].key))
	  return configlist[opt].value;
    }
    return def;
}

config_getint(key, def)
char *key;
int def;
{
    char *val = config_getstring(key, (char *)0);

    if (!val) return def;
    if (!isdigit(*val) && (*val != '-' || !isdigit(val[1]))) return def;
    return atoi(val);
}

config_getswitch(key, def)
char *key;
int def;
{
    char *val = config_getstring(key, (char *)0);

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

char *config_partitiondir(partition)
char *partition;
{
    char buf[80];

    if (strlen(partition) > 70) return 0;
    strcpy(buf, "partition-");
    strcat(buf, partition);

    return config_getstring(buf, (char *)0);
}

#define CONFIGLISTGROWSIZE 10 /* 100 */
static config_read()
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
	fatal(buf, EX_CONFIG);
    }
    
    while (fgets(buf, sizeof(buf), infile)) {
	lineno++;

	buf[strlen(buf)-1] = '\0';
	for (p = buf; *p && isspace(*p); p++);
	if (!*p || *p == '#') continue;

	key = p;
	while (*p && (isalnum(*p) || *p == '-')) {
	    if (isupper(*p)) *p = tolower(*p);
	    p++;
	}
	if (*p != ':') {
	    sprintf(buf,
		    "invalid option name on line %d of configuration file",
		    lineno);
	    fatal(buf, EX_CONFIG);
	}
	*p++ = '\0';

	while (*p && isspace(*p)) p++;
	
	if (!*p) {
	    sprintf(buf, "empty option value on line %d of configuration file",
		    lineno);
	    fatal(buf, EX_CONFIG);
	}

	if (nconfiglist == alloced) {
	    alloced += CONFIGLISTGROWSIZE;
	    configlist = (struct configlist *)
	      xrealloc((char *)configlist, alloced*sizeof(struct configlist));
	}

	configlist[nconfiglist].key = strsave(key);
	configlist[nconfiglist].value = strsave(p);
	nconfiglist++;
    }
    fclose(infile);
}

