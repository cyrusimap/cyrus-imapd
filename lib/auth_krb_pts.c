/* auth_krb_pts.c -- Kerberos authorization with AFS PTServer groups
 $Id: auth_krb_pts.c,v 1.31 2000/01/28 22:09:53 leg Exp $
 
 #        Copyright 1998 by Carnegie Mellon University
 #
 #                      All Rights Reserved
 #
 # Permission to use, copy, modify, and distribute this software and its
 # documentation for any purpose and without fee is hereby granted,
 # provided that the above copyright notice appear in all copies and that
 # both that copyright notice and this permission notice appear in
 # supporting documentation, and that the name of CMU not be
 # used in advertising or publicity pertaining to distribution of the
 # software without specific, written prior permission.
 #
 # CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 # ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 # CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 # ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 # WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 # ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 # SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

#define DB_LIBRARY_COMPATIBILITY_API
#include <db_185.h>
#include <krb.h>

#include "auth_krb_pts.h"
#include "auth.h"
#include "lock.h"
#include "retry.h"
#include "xmalloc.h"

#ifndef KRB_MAPNAME
#define KRB_MAPNAME "/etc/krb.equiv"
#endif

struct auth_state {
    char userid[PR_MAXNAMELEN];
    char name[PR_MAXNAMELEN];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    int ngroups;
    char (*groups)[PR_MAXNAMELEN];
};

static struct auth_state auth_anonymous = {
    "anonymous", "anonymous", "anonymous", "", "", 0, 0
};


static int parse_krbequiv_line P((const char *src,
				  char *principal, char *localuser));
char *auth_map_krbid P((const char *real_aname, const char *real_inst,
			const char *real_realm));

/*
 * Determine if the user is a member of 'identifier'
 * Returns one of:
 *      0       User does not match identifier
 *      1       identifier matches everybody
 *      2       User is in the group that is identifier
 *      3       User is identifer
 */
int auth_memberof(auth_state, identifier)
struct auth_state *auth_state;
const char *identifier;
{
    int i;
    
    if (!auth_state) auth_state = &auth_anonymous;

    if (strcmp(identifier, "anyone") == 0) return 1;
    
    if (strcmp(identifier, auth_state->userid) == 0) return 3;
    
    /* "anonymous" is not a member of any group */
    if (strcmp(auth_state->userid, "anonymous") == 0) return 0;
    
    for (i=0; i < auth_state->ngroups; i++)
        if (!strcmp(identifier,auth_state->groups[i]))
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
static int parse_krbequiv_line(src, principal, localuser)
const char *src;
char *principal;
char *localuser;
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
char *auth_map_krbid(real_aname, real_inst, real_realm)
const char *real_aname;
const char *real_inst;
const char *real_realm;
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
char *auth_canonifyid(identifier)
const char *identifier;
{
    static char retbuf[MAX_K_NAME_SZ+1];
    char aname[ANAME_SZ];
    char inst[INST_SZ];
    char realm[REALM_SZ];
    char lrealm[REALM_SZ];
    char krbhst[MAX_HSTNM];
    char *p;
    
    if (strcasecmp(identifier, "anonymous") == 0) {
        return "anonymous";
    }
    if (strcasecmp(identifier, "anybody") == 0 ||
        strcasecmp(identifier, "anyone") == 0) {
        return "anyone";
    }
    
    aname[0] = inst[0] = realm[0] = '\0';
    if (kname_parse(aname, inst, realm, (char *) identifier) != 0) {
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
    

    /* Check for krb.equiv remappings. */
    if (p = auth_map_krbid(aname, inst, realm)) {
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

struct auth_state *
auth_newstate(identifier, cacheid)
const char *identifier;
const char *cacheid;
{
    struct auth_state *newstate;
    DBT key, dataheader,datalist;
    char keydata[PTS_DB_KEYSIZE];
    char fnamebuf[1024];
    DB *ptdb;
    HASHINFO info;
    ptluser us;
    int s;
    struct sockaddr_un srvaddr;
    int r;
    int fd, rc;
    struct iovec iov[10];
    static char response[1024];
    int start, n;

    identifier = auth_canonifyid(identifier);
    if (!identifier) return 0;

    newstate = (struct auth_state *)xmalloc(sizeof(struct auth_state));
    (void)memset(newstate, 0, sizeof(struct auth_state));

    kname_parse(newstate->aname, newstate->inst, newstate->realm, 
		(char *) identifier);
    (void)strcpy(newstate->userid, identifier);

    if (strcmp(identifier, "anyone") == 0) return newstate;

    (void)memset(&info, 0, sizeof(info));
    (void)memset(&key, 0, sizeof(key));
    key.data = keydata;
    key.size = PTS_DB_KEYSIZE;
    (void)strcpy(fnamebuf, STATEDIR);
    (void)strcat(fnamebuf, PTS_DBLOCK);
    fd = open(fnamebuf, O_CREAT|O_TRUNC|O_RDWR, 0664);
    if (fd == -1) {
        syslog(LOG_ERR, "IOERROR: creating lock file %s: %m", fnamebuf);
        return newstate;
    }
    if (lock_shared(fd) < 0) {
        syslog(LOG_ERR, "IOERROR: locking lock file %s: %m", fnamebuf);
        return newstate;
    }
    (void)strcpy(fnamebuf, STATEDIR);
    (void)strcat(fnamebuf, PTS_DBFIL);
    ptdb = dbopen(fnamebuf, O_RDONLY, 0, DB_HASH, &info);

    (void)memset(&dataheader, 0, sizeof(dataheader));
    (void)memset(&datalist, 0, sizeof(datalist));

    if (!ptdb) {
	if (errno == ENOENT) {
	    /*
	     * Hopefully, this should prevent two different processes from
	     * trying to create the database at the same time
	     */
	    ptdb = dbopen(fnamebuf, O_CREAT|O_RDWR|O_EXCL, 0664, DB_HASH, &info);
	    if (!ptdb && errno == EEXIST) {
		ptdb = dbopen(fnamebuf, O_RDONLY, 0, DB_HASH, &info);
		if (!ptdb) {
		    syslog(LOG_ERR, "IOERROR:(1) opening database %s: %m", fnamebuf);
		    close(fd);
		    return newstate;
		}
	    }
	    else if (!ptdb) {
		syslog(LOG_ERR, "IOERROR: creating database %s: %m", fnamebuf);
		CLOSE(ptdb);
		close(fd);
		return newstate;
	    }
	    else {
		/*
		 * Write a record to the database, so that the database
		 * header will be written out
		 */
	        (void)memset(key.data, 0, key.size);
		(void)strcpy(key.data, "DUMMYREC");
		dataheader.size = 5;
		dataheader.data = "NULL";
		if (PUT(ptdb, &key, &dataheader, 0) < 0) {
		    syslog(LOG_ERR, "IOERROR: initializing database %s: %m",
			   fnamebuf); 
		    CLOSE(ptdb);
		    close(fd);
		    return newstate;
		}
		/* close and reopen the database in read-only mode */
		if (CLOSE(ptdb) < 0) {
		    syslog(LOG_ERR, "IOERROR: initializing database %s: %m",
			   fnamebuf); 
		    close(fd);
		    return newstate;
		}
		ptdb = dbopen(fnamebuf, O_RDONLY, 0664, DB_HASH, &info);
		if (!ptdb) {
		    syslog(LOG_ERR, "IOERROR: reopening new database %s: %m",
			   fnamebuf); 
		    close(fd);
		    return newstate;
		}
	    }          
	}
	else {
	    syslog(LOG_ERR, "IOERROR:(2) opening database %s: %m", fnamebuf);
	    close(fd);
	    return newstate;
	}
    }
    if (cacheid) {
      /* this should be the session key + the userid */
        (void)memset(keydata, 0, key.size);
        (void)memcpy(keydata, cacheid, 16); /* why 16? see sasl_krb_server.c */
	/* toss on userid to further uniquify */
	if ((strlen(identifier) + 16)  < PTS_DB_KEYSIZE) {
	  (void)memcpy(keydata+16, identifier, strlen(identifier)); 
	} else {
	  (void)memcpy(keydata+16, identifier, PTS_DB_KEYSIZE-16);
	}
    } /* cacheid */
    else {
      /* this is just the userid */
        (void)memset(keydata, 0, key.size);
        (void)strncpy(keydata, identifier, PR_MAXNAMELEN);
    }
    /* Fetch and process the header record for the user, if any */
    keydata[PTS_DB_HOFFSET] = 'H';
    rc = GET(ptdb, &key, &dataheader, 0);
    keydata[PTS_DB_HOFFSET] = 0;
    if (rc < 0) {
        syslog(LOG_ERR, "IOERROR: reading database %s: %m", fnamebuf);
        CLOSE(ptdb);
        close(fd);
        return newstate;
    }
    if (!rc) {
        if (dataheader.size != sizeof(ptluser)) {
            syslog(LOG_ERR, "IOERROR: Database %s probably corrupt (%d != %d) ", 
		   fnamebuf, dataheader.size, sizeof(ptluser));
            CLOSE(ptdb);
            close(fd);
            return newstate;
        }
        /* make sure the record is aligned */
        (void)memcpy(&us, dataheader.data, sizeof(ptluser));
    }
    if (rc || (!cacheid && us.cached < time(0) - EXPIRE_TIME)) {
        CLOSE(ptdb);
        close(fd);
        
        s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s == -1) return newstate;
        
	(void)strcpy(fnamebuf, STATEDIR);
	(void)strcat(fnamebuf, PTS_DBSOCKET);

        (void)memset((char *)&srvaddr, 0, sizeof(srvaddr));
        srvaddr.sun_family = AF_UNIX;
        (void)strcpy(srvaddr.sun_path, fnamebuf);
        r = connect(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
        if (r == -1) {
	    /* *reply = "cannot connect to ptloader server";*/
            return newstate;
        }
        
        iov[0].iov_base = (char *)&key.size;
        iov[0].iov_len = sizeof(key.size);
        iov[1].iov_base = key.data;
        iov[1].iov_len = key.size;
        iov[2].iov_base = (char *)identifier;
        iov[2].iov_len = PR_MAXNAMELEN;
        retry_writev(s, iov, 3);
        
        start = 0;
        while (start < sizeof(response) - 1) {
            n = read(s, response+start, sizeof(response) - 1 - start);
            if (n < 1) break;
            start += n;
        }
        
        close(s);
        
        if (start <= 1 || strncmp(response, "OK", 2)) return newstate;
        /*  response[start] = '\0';
         *reply = response; */

        /* The database must be re-opened after external modifications, at
           least in db 1.1.85 */
	(void)strcpy(fnamebuf, STATEDIR);
	(void)strcat(fnamebuf, PTS_DBLOCK);
        fd = open(fnamebuf, O_CREAT|O_TRUNC|O_RDWR, 0664);
        if (fd == -1) {
            syslog(LOG_ERR, "IOERROR: creating lock file %s: %m", fnamebuf);
            return newstate;
        }
        if (lock_shared(fd) < 0) {
            syslog(LOG_ERR, "IOERROR: locking lock file %s: %m", fnamebuf);
            return newstate;
        }
	(void)strcpy(fnamebuf, STATEDIR);
	(void)strcat(fnamebuf, PTS_DBFIL);
        ptdb = dbopen(fnamebuf, O_RDONLY, 0, DB_HASH, &info);
        if (!ptdb) {
            syslog(LOG_ERR, "IOERROR: opening database %s: %m", fnamebuf);
            close(fd);
            return newstate;
        }

        /* fetch the new header record and process it */
        keydata[PTS_DB_HOFFSET] = 'H';
        rc = GET(ptdb, &key, &dataheader, 0);
        keydata[PTS_DB_HOFFSET] = 0;
        if (rc < 0) {
            syslog(LOG_ERR, "IOERROR: reading database: %m");             
	    goto done;
        }
        /* The record still isn't there, even though the child claimed sucess
         */ 
        if (rc) {
            syslog(LOG_ERR, "ptloader did not add database record for %s",
                   identifier);
	    goto done;

        }
        (void)memcpy(&us, dataheader.data, dataheader.size);
    }
    /*
     * We assume cache keys will be unique. This will catch duplicates if they
     * occur
     */
    if (strcasecmp(identifier, us.user)) {
        syslog(LOG_ERR,
               "Internal error: Fetched record for user %s was for user %s: key not unique",
               identifier, us.user);
	goto done;
    }
    /*
     * now get the actual data from the database. this will be a contiguous
     * char[][] of size PR_MAXNAMELEN * us.ngroups
     */
    keydata[PTS_DB_HOFFSET] = 'D';
    rc = GET(ptdb, &key, &datalist, 0);
    if (rc < 0) {
        syslog(LOG_ERR, "IOERROR: reading database %s: %m", fnamebuf);
	goto done;
    }
    if (rc) {
        syslog(LOG_ERR,
               "Database %s inconsistent: header record found, data record missing", fnamebuf);
	goto done;
    }

    newstate->ngroups = us.ngroups;

#if 0
    if (newstate->ngroups * PR_MAXNAMELEN < datalist.size) {
	syslog(LOG_ERR,
	       "Database %s inconsistent: ngroups(%d) * PR_MAXNAMELEN(%d) < datalist.size(%d)",
	       fnamebuf, newstate->ngroups, PR_MAXNAMELEN, datalist.size);
    }
#endif

    if (newstate->ngroups) {
      newstate->groups = (char (*)[PR_MAXNAMELEN])xmalloc(newstate->ngroups *
							  PR_MAXNAMELEN); 
      (void)memcpy(newstate->groups, datalist.data, newstate->ngroups*PR_MAXNAMELEN);
    }

 done:
    CLOSE(ptdb);    
    close(fd);
    return newstate;
}

void
auth_freestate(auth_state)
struct auth_state *auth_state;
{
    if (auth_state->groups) free((char *)auth_state->groups);
    free((char *)auth_state);
}
