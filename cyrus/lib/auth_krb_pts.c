/* auth_krb_pts.c -- Kerberos authorization with AFS PTServer groups
 * $Id: auth_krb_pts.c,v 1.44.4.7 2002/11/15 21:47:00 rjs3 Exp $
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

#include <krb.h>

#include "auth_krb_pts.h"
#include "auth.h"
#include "cyrusdb.h"
#include "hash.h"
#include "libcyr_cfg.h"
#include "lock.h"
#include "retry.h"
#include "xmalloc.h"

const char *auth_method_desc = "krb_pts";

#ifndef KRB_MAPNAME
#define KRB_MAPNAME "/etc/krb.equiv"
#endif

static int parse_krbequiv_line(const char *src,
			       char *principal, char *localuser);
char *auth_map_krbid(const char *real_aname, const char *real_inst,
		     const char *real_realm);

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
 * Parse a line 'src' from an /etc/krb.equiv file.
 * Sets the buffer pointed to by 'principal' to be the kerberos
 * identity and sets the buffer pointed to by 'localuser' to
 * be the local user.  Both buffers must be of size one larger than
 * MAX_K_NAME_SZ.  Returns 1 on success, 0 on failure.
 */
static int parse_krbequiv_line(const char *src, 
			       char *principal, 
			       char *localuser)
{
    int i;
    
    while (isspace(*src)) src++;
    if (!*src) return 0;

    for (i = 0; *src && !isspace(*src); i++) {
        if (i >= MAX_K_NAME_SZ) return 0;
        *principal++ = *src++;
    }
    *principal = 0;
    
    if (!isspace(*src)) return 0; /* Need at least one separator */
    while (isspace(*src)) src++;
    if (!*src) return 0;
  
    for (i = 0; *src && !isspace(*src); i++) {
        if (i >= MAX_K_NAME_SZ) return 0;
        *localuser++ = *src++;
    }
    *localuser = 0;
    return 1;
}

/*
 * Map a remote kerberos principal to a local username.  If a mapping
 * is found, a pointer to the local username is returned.  Otherwise,
 * a NULL pointer is returned.
 * Eventually, this may be more sophisticated than a simple file scan.
 */
char *auth_map_krbid(const char *real_aname,
		     const char *real_inst,
		     const char *real_realm)
{
    static char localuser[MAX_K_NAME_SZ + 1];
    char principal[MAX_K_NAME_SZ + 1];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char lrealm[REALM_SZ];
    char krbhst[MAX_HSTNM];
    char *p;
    char buf[1024];
    FILE *mapfile;

    if (!(mapfile = fopen(KRB_MAPNAME, "r"))) {
        /* If the file can't be opened, don't do mappings */
        return 0;
    }
    
    for (;;) {
        if (!fgets(buf, sizeof(buf), mapfile)) break;
        if (parse_krbequiv_line(buf, principal, localuser) == 0 ||
            kname_parse(aname, inst, realm, principal) != 0) {
            /* Ignore badly formed lines */
            continue;
        }
        if (!strcmp(aname, real_aname) && !strcmp(inst, real_inst) &&
            !strcmp(realm, real_realm)) {
            fclose(mapfile);
            
            aname[0] = inst[0] = realm[0] = '\0';
            if (kname_parse(aname, inst, realm, localuser) != 0) {
                return 0;
            }
            
            /* Upcase realm name */
            for (p = realm; *p; p++) {
                if (islower(*p)) *p = toupper(*p);
            }
            
            if (*realm) {
                if (krb_get_lrealm(lrealm,1) == 0 &&
		    strcmp(lrealm, realm) == 0) {
                    *realm = 0;
                }
                else if (krb_get_krbhst(krbhst, realm, 1)) {
                    return 0;           /* Unknown realm */
                }
            }
            
            strcpy(localuser, aname);
            if (*inst) {
                strcat(localuser, ".");
                strcat(localuser, inst);
            }
            if (*realm) {
                strcat(localuser, "@");
                strcat(localuser, realm);
            }
            
            return localuser;
        }
    }

    fclose(mapfile);
    return 0;
}

/*
 * Convert 'identifier' into canonical form.
 * Returns a pointer to a static buffer containing the canonical form
 * or NULL if 'identifier' is invalid.
 */
char *auth_canonifyid(const char *identifier, size_t len)
{
    static char retbuf[MAX_K_NAME_SZ+1];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char lrealm[REALM_SZ];
    char krbhst[MAX_HSTNM];
    char *canon_buf;
    char *p;

    if(!len) len = strlen(identifier);

    canon_buf = malloc(len + 1);
    if(!canon_buf) return 0;
    memcpy(canon_buf, identifier, len);
    canon_buf[len] = '\0';
   
    aname[0] = inst[0] = realm[0] = '\0';
    if (kname_parse(aname, inst, realm, canon_buf) != 0) {
	free(canon_buf);
        return 0;
    }

    free(canon_buf);
    
    /* Upcase realm name */
    for (p = realm; *p; p++) {
        if (islower(*p)) *p = toupper(*p);
    }
    
    if (*realm) {
        if (krb_get_lrealm(lrealm,1) == 0 &&
	    strcmp(lrealm, realm) == 0) {
            *realm = 0;
        }
        else if (krb_get_krbhst(krbhst, realm, 1)) {
            return 0;           /* Unknown realm */
        }
    }
    

    /* Check for krb.equiv remappings. */
    p = auth_map_krbid(aname, inst, realm);
    if (p) {
        strcpy(retbuf, p);
        return retbuf;
    }
    
    strcpy(retbuf, aname);
    if (*inst) {
        strcat(retbuf, ".");
        strcat(retbuf, inst);
    }
    if (*realm) {
        strcat(retbuf, "@");
        strcat(retbuf, realm);
    }
    
    return retbuf;
}


/* 
 * Set the current user to 'identifier'
 *
 * This function also fetches the list of groups the user is a member of and
 * stores them in a static array. The system uses a berkely DB database as a
 * means of communication between this library and the external program that
 * contacts the PTS server. The database also caches this information using an
 * optional fixed length cache key provided by the caller (assuming the calling
 * program uses the session's encryption key, this allows users to force the
 * cache to be updated by re-authenticating themselves.) For programs that do
 * not have access to a useful object to use as an identifier, the userid is
 * used  instead (with up to 3 nulls at the end to round the length up to a
 * multiple of 4).  
 * Two different kinds of objects are stored in the database. One is a "header"
 * containing the userid  (for verification), the time the record was last
 * updated, and the number of groups the user is a member of. The database key
 * for this entry is formed by appending an 'H' and 3 nulls to the base
 * key. The other object in the database is the actual list of groups. This is
 * stored in a contigous array of fixed (maximum) length strings. The key for
 * this object is formed by appending a 'D' and 3 nulls to the base key.
 */

struct auth_state *auth_newstate(const char *identifier, 
				 const char *cacheid)
{
    struct auth_state *newstate;
    struct auth_state *fetched;
    char keydata[PTS_DB_KEYSIZE];
    const char *data;
    int ksize, dsize;
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

    identifier = auth_canonifyid(identifier, 0);
    if (!identifier) return 0;

    newstate = (struct auth_state *)xmalloc(sizeof(struct auth_state));
    memset(newstate, 0, sizeof(struct auth_state));

    kname_parse(newstate->aname, newstate->inst, newstate->realm, 
		(char *) identifier);
    strcpy(newstate->userid.id, identifier);
    newstate->userid.hash = hash(identifier);

    if (!strcmp(identifier, "anyone")) return newstate;
    if (!strcmp(identifier, "anonymous")) return newstate;

    if (cacheid) {
	/* this should be the session key + the userid */
        memset(keydata, 0, PTS_DB_KEYSIZE);
        memcpy(keydata, cacheid, 16); /* why 16? see sasl_krb_server.c */
	/* toss on userid to further uniquify */
	if ((strlen(identifier) + 16)  < PTS_DB_KEYSIZE) {
	    memcpy(keydata+16, identifier, strlen(identifier)); 
	} else {
	    memcpy(keydata+16, identifier, PTS_DB_KEYSIZE-16);
	}
    } else {
	/* this is just the userid */
        memset(keydata, 0, PTS_DB_KEYSIZE);
        strncpy(keydata, identifier, PR_MAXNAMELEN);
    }

#ifdef RUNNING_QUANTIFY
/* xxx do we still need this with the cyrusdb routines? */
    return newstate;
#endif
    
    strcpy(fnamebuf, config_dir);
    strcat(fnamebuf, PTS_DBFIL);
    r = CONFIG_DB_PTS->open(fnamebuf, &ptdb);
    if (r != 0) {
	syslog(LOG_ERR, "DBERROR: opening %s: %s", fnamebuf,
	       cyrusdb_strerror(ret));
	return newstate;
    }
      
    /* fetch the current record for the user */
    r = CONFIG_DB_PTS->fetch(ptdb, keydata, PTS_DB_KEYSIZE,
                             &data, &dsize, NULL);
    if (r != 0) {
        syslog(LOG_ERR, "auth_newstate: error fetching record: %s",
               cyrusdb_strerror(r));

        goto done;
    }

    /* if it's expired, ask the ptloader to reload it and reread it */
    fetched = (struct auth_state *) data;

    if(fetched) {        
      syslog(LOG_DEBUG,
             "auth_newstate: fetched cache record (mark %d, current %d, limit %d)",
             fetched->mark, time(0),
             time(0) - libcyrus_config_getint(CYRUSOPT_PTS_CACHE_TIMEOUT));
    }

    if (fetched && fetched->mark > 
        (time(0) - libcyrus_config_getint(CYRUSOPT_PTS_CACHE_TIMEOUT))) {
        /* not expired; let's return it */
        newstate = (struct auth_state *) xrealloc(newstate, dsize);
        memcpy(newstate, fetched, dsize);
        
        goto done;
    }

    syslog(LOG_DEBUG, "auth_newstate: pinging ptloader");

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) {
        syslog(LOG_ERR,
               "auth_newstate: unable to create socket for ptloader: %m");

        goto done;
    }
        
    strcpy(fnamebuf, config_dir);
    strcat(fnamebuf, PTS_DBSOCKET);

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strcpy(srvaddr.sun_path, fnamebuf);
    r = connect(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
    if (r == -1) {
	syslog(LOG_ERR, "auth_newstate: can't connect to ptloader server: %m");
	close(s);

        goto done;
    }

    ksize = PTS_DB_KEYSIZE;

    niov = 0;
    WRITEV_ADD_TO_IOVEC(iov, niov, (char *) &ksize, sizeof(ksize));
    WRITEV_ADD_TO_IOVEC(iov, niov, keydata, ksize);
    WRITEV_ADD_TO_IOVEC(iov, niov, (char *) identifier, PR_MAXNAMELEN);

    retry_writev(s, iov, niov);
        
    start = 0;
    while (start < sizeof(response) - 1) {
	n = read(s, response+start, sizeof(response) - 1 - start);
	if (n < 1) break;
	start += n;
    }
        
    close(s);
        
    if (start <= 1 || strncmp(response, "OK", 2)) {
        syslog(LOG_ERR, "auth_newstate: bad response from ptloader server");
        goto done;
    }

    /* fetch the current record for the user */
    r = CONFIG_DB_PTS->fetch(ptdb, keydata, PTS_DB_KEYSIZE, 
			     &data, &dsize, NULL);
    if (r != 0) {
	syslog(LOG_ERR, "auth_newstate: error fetching record: %s", 
	       cyrusdb_strerror(r));

        goto done;
    }

    if (!data) {
	syslog(LOG_ERR, "auth_newstate: error fetching record: %s "
	       "(did ptloader add the record?)", 
	       cyrusdb_strerror(r));

        goto done;
    }

    /* ok, we got what we wanted */
    fetched = (struct auth_state *) data;

    /* copy it into our structure */
    newstate = (struct auth_state *) xrealloc(newstate, dsize);
    memcpy(newstate, fetched, dsize);

 done:
    /* close and unlock the database */
    CONFIG_DB_PTS->close(ptdb);

    return newstate;
}

void auth_freestate(struct auth_state *auth_state)
{
    free(auth_state);
}
