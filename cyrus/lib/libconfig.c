/* libconfig.c -- imapd.conf handling
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
 */

/* $Id: libconfig.c,v 1.1.2.1 2003/02/06 22:41:00 rjs3 Exp $ */

#include <config.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <com_err.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>

#include "hash.h"
#include "libconfig.h"
#include "imapopts.h"
#include "xmalloc.h"

#define CONFIGHASHSIZE 30 /* relatively small,
			   * because it is for overflow only */
static struct hash_table confighash;

/* cached configuration variables accessible to the external world */
const char *config_filename;      /* filename of configuration file */
const char *config_dir;		  /* ie /var/imap */
const char *config_defpartition;  /* /var/spool/imap */
const char *config_servername;	  /* gethostname() */
const char *config_mupdate_server;/* NULL */
const char *config_defdomain;     /* NULL */
const char *config_ident;         /* the service name */
int config_hashimapspool;	  /* f */
int config_implicitrights;        /* "lca" */
int config_virtdomains;	          /* f */

/* declared in each binary that uses libconfig */
extern const int config_need_data;
extern void fatal(const char *fatal_message, int fatal_code)
   __attribute__ ((noreturn));

const char *config_getstring(enum imapopt opt)
{
    assert(opt > IMAPOPT_ZERO && opt < IMAPOPT_LAST);
    assert(imapopts[opt].t == OPT_STRING);
    
    return imapopts[opt].val.s;
}

int config_getint(enum imapopt opt)
{
    assert(opt > IMAPOPT_ZERO && opt < IMAPOPT_LAST);
    assert(imapopts[opt].t == OPT_INT);

    return imapopts[opt].val.i;
}

int config_getswitch(enum imapopt opt)
{
    assert(opt > IMAPOPT_ZERO && opt < IMAPOPT_LAST);
    assert(imapopts[opt].t == OPT_SWITCH);
    
    return imapopts[opt].val.b;
}

const char *config_getoverflowstring(const char *key, const char *def)
{
    char buf[256];
    char *ret;

    /* First lookup <ident>_key, to see if we have a service-specific
     * override */

    if(snprintf(buf,sizeof(buf),"%s_%s",config_ident,key) == -1)
	fatal("key too long in config_getoverflowstring", EC_TEMPFAIL);
    
    ret = hash_lookup(buf, &confighash);
    
    /* No service-specific override, check the actual key */
    if(!ret)
	ret = hash_lookup(key, &confighash);

    /* Return what we got or the default */
    return ret ? ret : def;
}

const char *config_partitiondir(const char *partition)
{
    char buf[80];

    if (strlen(partition) > 70) return 0;
    strcpy(buf, "partition-");
    strcat(buf, partition);

    return config_getoverflowstring(buf, NULL);
}

void config_read(const char *alt_config)
{
    FILE *infile;
    enum opttype opt = IMAPOPT_ZERO;
    int lineno = 0;
    char buf[4096], errbuf[1024];
    char *p, *q, *key, *fullkey, *srvkey, *val, *newval;
    int service_specific;
    int idlen = strlen(config_ident);

    if(!construct_hash_table(&confighash, CONFIGHASHSIZE, 1)) {
	fatal("could not construct configuration hash table", EC_CONFIG);
    }

    if(alt_config) config_filename = xstrdup(alt_config);
    else config_filename = xstrdup(CONFIG_FILENAME);

    /* read in config file */
    infile = fopen(config_filename, "r");
    if (!infile) {
	strcpy(buf, CYRUS_PATH);
	strcat(buf, config_filename);
	infile = fopen(buf, "r");
    }
    if (!infile) {
	snprintf(buf, sizeof(buf), "can't open configuration file %s: %s",
		 config_filename, error_message(errno));
	fatal(buf, EC_CONFIG);
    }
    
    while (fgets(buf, sizeof(buf), infile)) {
	lineno++;

	service_specific = 0;
	
	if (buf[strlen(buf)-1] == '\n') buf[strlen(buf)-1] = '\0';
	for (p = buf; *p && isspace((int) *p); p++);
	if (!*p || *p == '#') continue;

	fullkey = key = p;
	while (*p && (isalnum((int) *p) || *p == '-' || *p == '_')) {
	    if (isupper((unsigned char) *p)) *p = tolower((unsigned char) *p);
	    p++;
	}
	if (*p != ':') {
	    snprintf(errbuf, sizeof(errbuf),
		    "invalid option name on line %d of configuration file",
		    lineno);
	    fatal(buf, EC_CONFIG);
	}
	*p++ = '\0';
	
	while (*p && isspace((int) *p)) p++;
	
	/* remove trailing whitespace */
	for (q = p + strlen(p) - 1; q > p && isspace((int) *q); q--) {
	    *q = '\0';
	}
	
	if (!*p) {
	    snprintf(errbuf, sizeof(errbuf),
		    "empty option value on line %d of configuration file",
		    lineno);
	    fatal(buf, EC_CONFIG);
	}
	
	srvkey = NULL;

	/* Find if there is a service_ prefix */
	if(!strncasecmp(key, config_ident, idlen) 
	   && key[idlen] == '_') {
	    /* skip service_ prefix */
	    srvkey = key + idlen + 1;
	}
	
	/* look for a service_ prefix match in imapopts */
	if(srvkey) {
	    for (opt = IMAPOPT_ZERO; opt < IMAPOPT_LAST; opt++) {
		if (!strcasecmp(imapopts[opt].optname, srvkey)) {
		    key = srvkey;
		    service_specific = 1;
		    break;
		}
	    }
	}
	
	/* Did not find a service_ specific match, try looking for an
	 * exact match */
	if(!service_specific) {
	    for (opt = IMAPOPT_ZERO; opt < IMAPOPT_LAST; opt++) {
		if (!strcasecmp(imapopts[opt].optname, key)) {
		    break;
		}
	    }
	}

	/* If both of those loops failed, it goes verbatim into the
	 * overflow hash table. */
	
	if (opt < IMAPOPT_LAST) {
	    /* Okay, we know about this configure option.
	     * So first check that we have either
	     *  1. not seen it
	     *  2. seen its generic form, but this is a service specific form
	     *
	     *  If we have already seen a service-specific form, and this is
	     *  a generic form, just skip it and don't moan.
	     */
	    if((imapopts[opt].seen == 1 && !service_specific) 
	     ||(imapopts[opt].seen == 2 && service_specific)) {
		sprintf(errbuf,
			"option '%s' was specified twice in config file (second occurance on line %d)",
			fullkey, lineno);
		fatal(errbuf, EC_CONFIG);
	    } else if(imapopts[opt].seen == 2 && !service_specific) {
		continue;
	    }

	    /* If we've seen it already, we're replacing it, so we need
	     * to free the current string if there is one */
	    if(imapopts[opt].seen && imapopts[opt].t == OPT_STRING)
		free((char *)imapopts[opt].val.s);

            if(service_specific)
		imapopts[opt].seen = 2;
	    else
		imapopts[opt].seen = 1;
	    
	    /* this is a known option */
	    switch (imapopts[opt].t) {
	    case OPT_STRING: 
	    {		    
		imapopts[opt].val.s = xstrdup(p);

		if(opt == IMAPOPT_CONFIGDIRECTORY)
		    config_dir = imapopts[opt].val.s;

		break;
	    }
	    case OPT_INT:
	    {
		long val;
		char *ptr;
		
		val = strtol(p, &ptr, 0);
		if (!ptr || *ptr != '\0') {
		    /* error during conversion */
		    sprintf(errbuf, "non-integer value for %s in line %d",
			    imapopts[opt].optname, lineno);
		    fatal(buf, EC_CONFIG);
		}

		imapopts[opt].val.i = val;
		break;
	    }
	    case OPT_SWITCH:
	    {
		if (*p == '0' || *p == 'n' ||
		    (*p == 'o' && p[1] == 'f') || *p == 'f') {
		    imapopts[opt].val.b = 0;
		}
		else if (*p == '1' || *p == 'y' ||
			 (*p == 'o' && p[1] == 'n') || *p == 't') {
		    imapopts[opt].val.b = 1;
		}
		else {
		    /* error during conversion */
		    sprintf(errbuf, "non-switch value for %s in line %d",
			    imapopts[opt].optname, lineno);
		    fatal(buf, EC_CONFIG);
		}
		break;
	    }
	    case OPT_NOTOPT:
	    default:
		abort();
	    }
	} else {
	    /* check to make sure it's valid for overflow */
	    /* that is, partition names and anything that might be
	     * used by SASL */
/*
  xxx this would be nice if it wasn't for other services who might be
      sharing this config file and whose names we cannot predict

	    if(strncasecmp(key,"sasl_",5)
	    && strncasecmp(key,"partition-",10)) {
		sprintf(errbuf,
			"option '%s' is unknown on line %d of config file",
			fullkey, lineno);
		fatal(errbuf, EC_CONFIG);
	    }
*/

	    /* Put it in the overflow hash table */
	    newval = xstrdup(p);
	    val = hash_insert(key, newval, &confighash);
	    if(val != newval) {
		snprintf(errbuf, sizeof(errbuf), 
			"option '%s' was specified twice in config file (second occurance on line %d)",
			fullkey, lineno);
		fatal(errbuf, EC_CONFIG);
	    }
	}
    }
    fclose(infile);

    /* Check configdirectory config option */
    if (!config_dir) {
	fatal("configdirectory option not specified in configuration file",
	      EC_CONFIG);
    }

    /* Scan options to see if we need to replace {configdirectory} */
    /* xxx need to scan overflow options as well! */
    for(opt = IMAPOPT_ZERO; opt < IMAPOPT_LAST; opt++) {
	if(!imapopts[opt].val.s ||
	   imapopts[opt].t != OPT_STRING ||
	   opt == IMAPOPT_CONFIGDIRECTORY) {
	    /* Skip options that have a NULL value, aren't strings, or
	     * are the configdirectory option */
	    continue;
	}
	
	/* We use some magic numbers here,
	 * 17 is the length of "{configdirectory}",
	 * 16 is one less than that length, so that the replacement string
	 *    that is malloced has room for the '\0' */
	if(!strncasecmp(imapopts[opt].val.s,"{configdirectory}",17)) {
	    const char *str = imapopts[opt].val.s;
	    char *newstring =
		xmalloc(strlen(config_dir) + strlen(str) - 16);
	    char *freeme = NULL;
	    
	    /* we need to replace this string, will we need to free
	     * the current value?  -- only if we've actually seen it in
	     * the config file. */
	    if(imapopts[opt].seen)
		freeme = (char *)str;

	    /* Build replacement string from configdirectory option */
	    strcpy(newstring, config_dir);
	    strcat(newstring, str + 17);

	    imapopts[opt].val.s = newstring;

	    if(freeme) free(freeme);
	}
    }

    /* Look up default partition */
    config_defpartition = config_getstring(IMAPOPT_DEFAULTPARTITION);
    for (p = (char *)config_defpartition; *p; p++) {
	if (!isalnum((unsigned char) *p))
	  fatal("defaultpartition option contains non-alphanumeric character",
		EC_CONFIG);
	if (isupper((unsigned char) *p)) *p = tolower((unsigned char) *p);
    }
    if ((config_need_data & CONFIG_NEED_PARTITION_DATA) &&
	(!config_defpartition || !config_partitiondir(config_defpartition))) {
	snprintf(buf, sizeof(buf),
		"partition-%s option not specified in configuration file",
		config_defpartition);
	fatal(buf, EC_CONFIG);
    }

    /* look up mailbox hashing */
    config_hashimapspool = config_getswitch(IMAPOPT_HASHIMAPSPOOL);

    /* are we supporting virtual domains?  */
    config_virtdomains = config_getswitch(IMAPOPT_VIRTDOMAINS);
    config_defdomain = config_getstring(IMAPOPT_DEFAULTDOMAIN);

    /* look up the hostname we should present to the user */
    config_servername = config_getstring(IMAPOPT_SERVERNAME);
    if (!config_servername) {
	config_servername = xmalloc(sizeof(char) * 256);
	gethostname((char *) config_servername, 256);
    }

    /* look up and canonify the implicit rights of mailbox owners */
    config_implicitrights =
	cyrus_acl_strtomask(config_getstring(IMAPOPT_IMPLICIT_OWNER_RIGHTS));

    config_mupdate_server = config_getstring(IMAPOPT_MUPDATE_SERVER);
}
