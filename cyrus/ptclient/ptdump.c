/*
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
#include <config.h>
#include <stdio.h>
#include <stdlib.h>

#include "auth_krb_pts.h"
#include "cyrusdb.h"
#include "imapconf.h"

static char rcsid[] = "$Id: ptdump.c,v 1.5.16.2 2002/11/15 21:47:05 rjs3 Exp $";

int config_need_data = 0;

static int dump_p(void *rockp __attribute__((unused)),
		    const char *key __attribute__((unused)),
		    int keylen __attribute__((unused)),
		    const char *data __attribute__((unused)),
		    int datalen __attribute__((unused)))
{
    return 1;
}

static int dump_cb(void *rockp __attribute__((unused)),
		     const char *key, int keylen __attribute__((unused)),
		     const char *data,
		     int datalen __attribute__((unused))) 
{
    struct auth_state *authstate = (struct auth_state *)data;
    int i;
    
    printf("user: %s time: %d groups: %d\n",
	   key, (unsigned)authstate->mark, (unsigned)authstate->ngroups);

    for (i=0; i < authstate->ngroups; i++)
	printf("  %s\n",authstate->groups[i].id);
    
    return 0;
}

int main(int argc, char *argv[])
{
    struct db *ptdb;
    char fnamebuf[1024];
    extern char *optarg;
    int opt;
    int r;
    char *alt_config = NULL;

    while ((opt = getopt(argc, argv, "C:")) != EOF) {
	switch (opt) {
	case 'C': /* alt config file */
	    alt_config = optarg;
	    break;
	default:
	    fprintf(stderr,"usage: [-C filename]"
		    "\n\t-C <filename>\tAlternate Config File"
		    "\n");
	    exit(-1);
	    break;
	    /* just pass through */
	}
    }

    config_init(alt_config, "ptdump");

    /* open database */
    strcpy(fnamebuf, config_dir);
    strcat(fnamebuf, PTS_DBFIL);
    r = CONFIG_DB_PTS->open(fnamebuf, &ptdb);
    if(r != CYRUSDB_OK) {
	fprintf(stderr,"error opening %s (%s)", fnamebuf,
	       cyrusdb_strerror(r));
	exit(1);
    }

    /* iterate through db, wiping expired entries */
    CONFIG_DB_PTS->foreach(ptdb, "", 0, dump_p, dump_cb, ptdb, NULL);

    CONFIG_DB_PTS->close(ptdb);

    cyrus_done();

    return 0;
}

int fatal(const char *msg,int exitcode)
{
  fprintf(stderr,"%s", msg);
  exit(exitcode);
}
