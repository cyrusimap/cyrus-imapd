/* config.c -- Configuration routines
 * Copyright (c) 1998-2000 Carnegie Mellon University.  All rights reserved.
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

#include "imapconf.h"
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


/* variables accessible to the external world */
const char *config_dir;		 /* ie /var/imap */
const char *config_defpartition; /* /var/spool/imap */
const char *config_newsspool;	 /* /var/spool/news */
const char *config_servername;	 /* gethostname() */
int config_hashimapspool;	 /* f */


static void config_read(void);

int config_init(const char *ident)
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

const char *config_getstring(const char *key, const char *def)
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
    if (!isdigit((int) *val) && (*val != '-' || !isdigit((int) val[1]))) 
	return def;
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
static void config_read(void)
{
    FILE *infile;
    int lineno = 0;
    int alloced = 0;
    char buf[4096];
    char *p, *key;

    infile = fopen(CONFIG_FILENAME, "r");
    if (!infile) {
	strcpy(buf, CYRUS_PATH);
	strcat(buf, CONFIG_FILENAME);
	infile = fopen(buf, "r");
    }
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
    int sl = sizeof(opt);

    if (!strcmp(option, "srvtab")) { 
	/* we don't transform srvtab! */
	*result = config_getstring(option, NULL);
    } else {
	*result = NULL;

	if (plugin_name) {
	    /* first try it with the plugin name */
	    strlcpy(opt, "sasl_", sl);
	    strlcat(opt, plugin_name, sl);
	    strlcat(opt, "_", sl);
	    strlcat(opt, option, sl);
	    *result = config_getstring(opt, NULL);
	}

	if (*result == NULL) {
	    /* try without the plugin name */
	    strlcpy(opt, "sasl_", sl);
	    strlcat(opt, option, sl);
	    *result = config_getstring(opt, NULL);
	}
    }

    if (*result != NULL) {
	if (len) { *len = strlen(*result); }
	return SASL_OK;
    }
   
    return SASL_FAIL;
}

/* This creates a structure that defines the allowable
 *   security properties 
 */
sasl_security_properties_t *mysasl_secprops(int flags)
{
    static sasl_security_properties_t ret;

    ret.maxbufsize = 4000;
    ret.min_ssf = config_getint("sasl_minimum_layer", 0);	
				/* minimum allowable security strength */
    ret.max_ssf = config_getint("sasl_maximum_layer", 256);
				/* maximum allowable security strength */

    ret.security_flags = flags;
    /* ret.security_flags |= SASL_SEC_NOPLAINTEXT; */
    if (!config_getswitch("allowanonymouslogin", 0)) {
	ret.security_flags |= SASL_SEC_NOANONYMOUS;
    }
    ret.property_names = NULL;
    ret.property_values = NULL;

    return &ret;
}

/* true if 'authstate' is in 'val' */
static int isa(struct auth_state *authstate, const char *opt)
{
    char buf[1024];
    const char *val = config_getstring(opt, "");

    while (*val) {
	char *p;
	
	for (p = (char *) val; *p && !isspace((int) *p); p++);
	strlcpy(buf, val, p-val);
	buf[p-val] = 0;

	if (auth_memberof(authstate, buf)) {
	    return 1;
	}
	val = p;
	while (*val && isspace((int) *val)) val++;
    }
    return 0;
}

/* 
 * check 'service_class' and 'class'
 */
int authisa(struct auth_state *authstate, 
	    const char *service, 
	    const char *class)
{
    char buf[512];

    if (!authstate) {
	/* not authenticated? */
	return 0;
    }

    /* 'class' */
    if (isa(authstate, class)) {
	return 1;
    }

    /* 'service_class' */
    snprintf(buf, sizeof(buf), "%s_%s", service, class);
    if (isa(authstate, buf)) {
	return 1;
    }
    
    return 0;
}
