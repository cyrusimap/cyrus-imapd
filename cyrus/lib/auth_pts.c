/* auth_pts.c -- PTLOADER authorization
 * $Id: auth_pts.c,v 1.1.2.4 2002/12/20 18:38:46 rjs3 Exp $
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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

#include "auth.h"
#include "auth_pts.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "hash.h"
#include "libcyr_cfg.h"
#include "lock.h"
#include "retry.h"
#include "xmalloc.h"

const char *auth_method_desc = "pts";

char *canonuser_id = NULL;
struct auth_state *canonuser_cache = NULL;

/* Returns 0 on successful connection to ptloader/valid cache entry,
 * complete with allocated & filled in struct auth_state.
 *
 * state must be a NULL pointer when passed in */
int ptload(const char *identifier,struct auth_state **state);

/*
 * Determine if the user is a member of 'identifier'
 * Returns one of:
 *      0       User does not match identifier
 *      1       identifier matches everybody
 *      2       User is in the group that is identifier
 *      3       User is identifer
 */
int auth_memberof(struct auth_state *auth_state,
		  const char *identifier)
{
    int i;
    unsigned idhash = hash(identifier);
    static unsigned anyonehash = 0;

    anyonehash = !anyonehash ? hash("anyone") : anyonehash;
    
    if (!auth_state) {
	/* special case anonymous */
	if (!strcmp(identifier, "anyone")) return 1;
	else if (!strcmp(identifier, "anonymous")) return 3;

	/* "anonymous" is not a member of any group */
	else return 0;
    }

    /* is 'identifier' "anyone"? */
    if (idhash == anyonehash &&
	!strcmp(identifier, "anyone")) return 1;
    
    /* is 'identifier' me? */
    if (idhash == auth_state->userid.hash &&
	!strcmp(identifier, auth_state->userid.id)) return 3;
    
    /* is it a group i'm a member of ? */
    for (i=0; i < auth_state->ngroups; i++)
        if (idhash == auth_state->groups[i].hash &&
	    !strcmp(identifier, auth_state->groups[i].id))
            return 2;
  
    return 0;
}

/*
 * Convert 'identifier' into canonical form.
 * Returns a pointer to a static buffer containing the canonical form
 * or NULL if 'identifier' is invalid.
 */
char *auth_canonifyid(const char *identifier,
		      size_t len __attribute__((unused)))
{
    static char retbuf[PTS_DB_KEYSIZE];

    if(canonuser_id &&
       (!strcmp(identifier, canonuser_id) || !strcmp(identifier, retbuf))) {
	/* It's the currently cached user, return the previous result */
	return retbuf;
    } else if(canonuser_id) {
	/* We've got a new one, invalidate our cache */
	free(canonuser_id);
	auth_freestate(canonuser_cache);

	canonuser_id = NULL;
	canonuser_cache = NULL;
    }

    if(!strcmp(identifier, "anyone") ||
       !strcmp(identifier, "anonymous")) {
        /* we can fill this in ourselves - no cacheing */
	strlcpy(retbuf, identifier, sizeof(retbuf));
	return retbuf;
    } else if(ptload(identifier, &canonuser_cache)) {
	/* Couldn't contact ptloader/database.  Fail. */
	return NULL;
    } else {
	canonuser_id = xstrdup(identifier);
	strlcpy(retbuf, canonuser_cache->userid.id, sizeof(retbuf));
	return retbuf;
    }
}

/* 
 * Produce an auth_state structure for the given identifier
 */
struct auth_state *auth_newstate(const char *identifier) 
{
    struct auth_state *output;

    if(canonuser_id &&
       (!strcmp(canonuser_id, identifier) ||
	!strcmp(canonuser_id, canonuser_cache->userid.id))) {
	/* It's the currently cached user, return the previous result */
	free(canonuser_id);
	canonuser_id = NULL;

	output = canonuser_cache;
	canonuser_cache = NULL;
    } else {
	if(!strcmp(identifier, "anyone") ||
           !strcmp(identifier, "anonymous") ||
	   ptload(identifier, &output)) {
		/* Anyone/Anonymous/ptload failure; fake it */
		output =
		    (struct auth_state *)xzmalloc(sizeof(struct auth_state));
		strlcpy(output->userid.id, identifier,
			sizeof(output->userid.id));
		output->userid.hash = hash(identifier);
	}
    }
	
    return output;
}

/* Returns 0 on success */
int ptload(const char *identifier, struct auth_state **state) 
{
    struct auth_state *fetched;
    size_t id_len;
    const char *data;
    int dsize;
    char fnamebuf[1024];
    struct db *ptdb;
    int s;
    struct sockaddr_un srvaddr;
    int r;
    static char response[1024];
    struct iovec iov[10];
    int niov, n;
    unsigned int start;
    const char *config_dir =
	libcyrus_config_getstring(CYRUSOPT_CONFIG_DIR);

    if(!state || *state) {
	fatal("bad state pointer passed to ptload()", EC_TEMPFAIL);
    }
    
    strcpy(fnamebuf, config_dir);
    strcat(fnamebuf, PTS_DBFIL);
    r = CONFIG_DB_PTS->open(fnamebuf, &ptdb);
    if (r != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fnamebuf,
	       cyrusdb_strerror(ret));
	return -1;
    }

    id_len = strlen(identifier);
    if(id_len > PTS_DB_KEYSIZE) {
	syslog(LOG_ERR, "identifier too long in auth_newstate");
	return -1;
    }
      
    /* fetch the current record for the user */
    r = CONFIG_DB_PTS->fetch(ptdb, identifier, id_len,
                             &data, &dsize, NULL);
    if (r != 0) {
        syslog(LOG_ERR, "auth_newstate: error fetching record: %s",
               cyrusdb_strerror(r));

        goto done;
    }

    /* if it's expired (or nonexistant),
     * ask the ptloader to reload it and reread it */
    fetched = (struct auth_state *) data;

    if(fetched) {        
	time_t now = time(NULL);
	int timeout = libcyrus_config_getint(CYRUSOPT_PTS_CACHE_TIMEOUT);
	
	syslog(LOG_DEBUG,
	       "ptload(): fetched cache record " \
	       "(mark %d, current %d, limit %d)",
	       fetched->mark, now, now - timeout);

	if (fetched->mark > (now - timeout)) {
	    /* not expired; let's return it */
	    *state = (struct auth_state *)xmalloc(dsize);
	    memcpy(*state, fetched, dsize);
	    
	    goto done;
	}
    }
    
    syslog(LOG_DEBUG, "ptload(): pinging ptloader");

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
        syslog(LOG_ERR,
               "ptload(): unable to create socket for ptloader: %m");

        goto done;
    }
        
    strcpy(fnamebuf, config_dir);
    strcat(fnamebuf, PTS_DBSOCKET);

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, fnamebuf);
    r = connect(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
    if (r == -1) {
	syslog(LOG_ERR, "ptload(): can't connect to ptloader server: %m");
	close(s);

        goto done;
    }

    niov = 0;
    WRITEV_ADD_TO_IOVEC(iov, niov, (char *) &id_len, sizeof(id_len));
    WRITEV_ADD_TO_IOVEC(iov, niov, (char *) identifier, id_len);

    retry_writev(s, iov, niov);
        
    start = 0;
    while (start < sizeof(response) - 1) {
	n = read(s, response+start, sizeof(response) - 1 - start);
	if (n < 1) break;
	start += n;
    }
        
    close(s);
        
    if (start <= 1 || strncmp(response, "OK", 2)) {
       if(start > 1) {
	   syslog(LOG_ERR,
		  "ptload(): bad response from ptloader server: %s", response);
       } else {
	   syslog(LOG_ERR, "ptload(): empty response from ptloader server");
       }
       goto done;
    }

    /* fetch the current record for the user */
    r = CONFIG_DB_PTS->fetch(ptdb, identifier, id_len, 
			     &data, &dsize, NULL);
    if (r != 0 || !data) {
	syslog(LOG_ERR, "ptload(): error fetching record: %s"
	       "(did ptloader add the record?)",
	       cyrusdb_strerror(r));
	
        goto done;
    }

    /* ok, we got what we wanted */
    fetched = (struct auth_state *) data;

    /* copy it into our structure */
    *state = (struct auth_state *)xmalloc(dsize);
    memcpy(*state, fetched, dsize);

 done:
    /* close and unlock the database */
    CONFIG_DB_PTS->close(ptdb);

    return (*state) ? 0 : -1;
}

void auth_freestate(struct auth_state *auth_state)
{
    free(auth_state);
}
