/* ptloader.c -- AFS group loader daemon
 */
/*
 * Copyright (c) 1996-2000 Carnegie Mellon University.  All rights reserved.
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

static char rcsid[] __attribute__((unused)) = 
      "$Id: ptloader.c,v 1.25.4.3 2002/11/14 19:36:28 rjs3 Exp $";

#include <config.h>

#include <string.h>
#include "auth_krb_pts.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <krb.h>
#include <rx/rxkad.h>
#include <afs/auth.h>
#include <com_err.h>

//#include <db.h>

#include "cyrusdb.h"
#include "exitcodes.h"
#include "hash.h"
#include "imapconf.h"
#include "lock.h"
#include "retry.h"
#include "xmalloc.h"

/* config.c info (libimap) */
const int config_need_data = 0;

/* blame transarc i've been told */
#ifndef AFSCONF_CLIENTNAME
#include <afs/dirpath.h>
#define AFSCONF_CLIENTNAME AFSDIR_CLIENT_ETC_DIRPATH
#endif

static char ptclient_debug = 0;

#define DB (CONFIG_DB_PTS)
  
struct db *ptsdb = NULL;
  
int service_init(int argc, char *argv[], char **envp __attribute__((unused)))
{
    int r;
    int opt;
    char fnamebuf[1024];
    extern char *optarg;

    syslog(LOG_NOTICE, "starting: $Id: ptloader.c,v 1.25.4.3 2002/11/14 19:36:28 rjs3 Exp $");

    while ((opt = getopt(argc, argv, "d:")) != EOF) {
	switch (opt) {
	case 'd':
	    ptclient_debug = atoi(optarg);
	    if (ptclient_debug < 1) {
		ptclient_debug = 1;
	    }
	    break;
	default:
            syslog(LOG_ERR, "invalid command line option specified");
	    break;
	    /* just pass through */
	}
    }

    r = pr_Initialize (1L, AFSCONF_CLIENTNAME, 0);
    if (r) {
	syslog(LOG_DEBUG, "pr_Initialize failed: %d", r);
	fatal("pr_initialize failed", EC_TEMPFAIL);
    }

    strcpy(fnamebuf, config_dir);
    strcat(fnamebuf, FNAME_DBDIR);
    r = DB->init(fnamebuf, 0);
    if (r != CYRUSDB_OK) {
	fatal("can't initialize the database environment", EC_TEMPFAIL);
    }

    strcpy(fnamebuf, config_dir);
    strcat(fnamebuf, PTS_DBFIL);
    r = DB->open(fnamebuf, &ptsdb);
    if (r != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fnamebuf,
	       cyrusdb_strerror(ret));
	fatal("can't read pts database", EC_TEMPFAIL);
    }

    return 0;
}

/* called if 'service_init()' was called but not 'service_main()' */
void service_abort(int error)
{
    int r;

    r = DB->close(ptsdb);
    if (r) {
	syslog(LOG_ERR, "DBERROR: error closing ptsdb: %s",
	       cyrusdb_strerror(r));
    }

    r = DB->done();
    if (r) {
	syslog(LOG_ERR, "DBERROR: error exiting application: %s",
	       cyrusdb_strerror(r));
    }

    exit(error);
}

/* we're a 'threaded' service, but since we never fork or create any
   threads, we're just one-person-at-a-time based */
int service_main_fd(int c, int argc, char **argv, char **envp)
{
    char keyinhex[512];
    const char *reply = NULL;
    char indata[PTS_DB_KEYSIZE];
    char user[PR_MAXNAMELEN];
    namelist groups;
    int i, rc, dsize;
    size_t size;
    struct auth_state *newstate;

    (void)memset(&size, 0, sizeof(size));
    if (read(c, &size, sizeof(size_t)) < 0) {
        syslog(LOG_ERR, "socket (size): %m");
        reply = "Error reading request (size)";
        goto sendreply;
    }

    if (size > PTS_DB_KEYSIZE)  {
	syslog(LOG_ERR, "size sent %d is greater than buffer size %d", 
	       size, PTS_DB_KEYSIZE);
	reply = "Error: invalid request size";
	goto sendreply;
    }

    memset(&indata, 0, PTS_DB_KEYSIZE);
    if (read(c, &indata, size) < 0) {
        syslog(LOG_ERR,"socket (indata; size = %d): %m", size);
        reply = "Error reading request (key)";
        goto sendreply;
    }

    /* convert request to hex */
    for (i=0; i<size; i++) {
	sprintf(keyinhex+(2*i), "%.2x", indata[i]);
    }

    memset(&user, 0, sizeof(user));
    if (read(c, &user, PR_MAXNAMELEN) < 0) {
        syslog(LOG_ERR, "socket(user; size = %d; key = %s): %m", 
	       size, keyinhex);
        reply = "Error reading request (user)";
        goto sendreply;
    }

    if (ptclient_debug) {
	syslog(LOG_DEBUG, "user %s, cacheid %s", user, keyinhex);
    }

    memset(&groups, 0, sizeof(groups));
    groups.namelist_len = 0;
    groups.namelist_val = NULL;
    
    if ((rc = pr_ListMembers(user, &groups))) {
	/* Failure may indicate that we need new tokens */
	pr_End();
	rc = pr_Initialize (1L, AFSCONF_CLIENTNAME, 0);
        if (rc) {
	    syslog(LOG_DEBUG, "pr_Initialize failed: %d", rc);
	    fatal("pr_Initialize failed", EC_TEMPFAIL);
        }
	/* Okay, rerun it now */
	rc = pr_ListMembers(user, &groups);
    }

    if(rc) 
    {
        syslog(LOG_ERR, "pr_ListMembers %s: %s", user, error_message(rc));
        reply = error_message(rc);
        goto sendreply;
    }

    /* fill in our new state structure */
    dsize = sizeof(struct auth_state) + 
	(groups.namelist_len * sizeof(struct auth_ident));
    newstate = (struct auth_state *) xmalloc(dsize);

    strcpy(newstate->userid.id, user);
    newstate->userid.hash = hash(user);
    kname_parse(newstate->aname, newstate->inst, newstate->realm, user);
    newstate->mark = time(0);
    newstate->ngroups = groups.namelist_len;
    /* store group list in contiguous array for easy storage in the database */
    memset(newstate->groups, 0, newstate->ngroups * sizeof(struct auth_ident));
    for (i = 0; i < newstate->ngroups; i++) {
        strcpy(newstate->groups[i].id, groups.namelist_val[i]);
	newstate->groups[i].hash = hash(groups.namelist_val[i]);
	/* don't free groups.namelist_val[i]. Something else currently
	 * takes care of that data. 
	 */
    }
    if (groups.namelist_val != NULL) {
	free(groups.namelist_val);
    }

    rc = DB->store(ptsdb, indata, size, newstate, dsize, NULL);
    
    free(newstate);

    /* and we're done */
    reply = "OK";
    
 sendreply:
    if (retry_write(c, reply, strlen(reply)) <0) {
	syslog(LOG_WARNING, "retry_write: %m");
    }
    close(c);

    return 0;
}

/* we need to have this function here 'cause libcyrus.a 
 * makes calls to this function. 
 */
void fatal(const char *msg, int exitcode)
{
    syslog(LOG_ERR, "%s", msg);
    exit(-1);
}
/* $Header: /mnt/data/cyrus/cvsroot/src/cyrus/ptclient/ptloader.c,v 1.25.4.3 2002/11/14 19:36:28 rjs3 Exp $ */
