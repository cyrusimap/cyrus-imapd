/* auth_krb_pts.c -- Kerberos authorization with AFS PTServer groups
 *
 *	(C) Copyright 1994 by Carnegie Mellon University
 *
 *                      All Rights Reserved
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without
 * fee, provided that the above copyright notice appear in all copies
 * and that both that copyright notice and this permission notice
 * appear in supporting documentation, and that the name of Carnegie
 * Mellon University not be used in advertising or publicity
 * pertaining to distribution of the software without specific,
 * written prior permission.  Carnegie Mellon University makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include <krb.h>
#include <sys/wait.h>
#include "auth_krb_pts.h"

#ifndef KRB_MAPNAME
#define KRB_MAPNAME "/etc/krb.equiv"
#endif

static char auth_userid[PR_MAXNAMELEN] = "anonymous";
static char auth_name[PR_MAXNAMELEN] = "anonymous";
static char auth_aname[ANAME_SZ] = "anonymous";
static char auth_inst[INST_SZ] = ""; 
static char auth_realm[REALM_SZ] = "";

static char ptclient_path[4096];

/*
  cdecl> declare x as pointer to array of array 64 of char
  char (*x)[][64]
  */
static char (*auth_groups)[][PR_MAXNAMELEN]=NULL;
static int auth_ngroups=0;

/*
 * Determine if the user is a member of 'identifier'
 * Returns one of:
 *      0       User does not match identifier
 *      1       identifier matches everybody
 *      2       User is in the group that is identifier
 *      3       User is identifer
 */
int auth_memberof(identifier)
char *identifier;
{
    int i;
    
    if (strcmp(identifier, "anyone") == 0) return 1;
    
    if (strcmp(identifier, auth_userid) == 0) return 3;
    
    /* "anonymous" is not a member of any group */
    if (strcmp(auth_userid, "anonymous") == 0) return 0;
    
    for (i=0;i<auth_ngroups;i++)
        if (!strcmp(identifier,(*auth_groups)[i]))
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
char *src;
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
char *real_aname;
char *real_inst;
char *real_realm;
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
                if (krb_get_lrealm(lrealm,1)) {
                    return 0;           /* configuration error */
                }
                if (strcmp(lrealm, realm) == 0) {
                    *realm = 0;
                }
                else if (krb_get_krbhst(krbhst, realm, 0)) {
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
char *identifier;
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
    if (kname_parse(aname, inst, realm, identifier) != 0) {
        return 0;
    }
    
    /* Upcase realm name */
    for (p = realm; *p; p++) {
        if (islower(*p)) *p = toupper(*p);
    }
    
    if (*realm) {
        if (krb_get_lrealm(lrealm,1)) {
            return 0;           /* configuration error */
        }
        if (strcmp(lrealm, realm) == 0) {
            *realm = 0;
        }
        else if (krb_get_krbhst(krbhst, realm, 0)) {
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


int auth_setid(char *identifier, char *cacheid) {
    DBT key, dataheader,datalist;
    char keydata[PR_MAXNAMELEN + 4]; /* or 20, whichever is greater */
    int fd,rc,xpid;
    DB *ptdb;
    HASHINFO info;
    ptluser us;
    int forktries = 0;

    if (auth_ngroups) {
      free(auth_groups);
      auth_groups=NULL;
      auth_ngroups=0;
    }
    identifier = auth_canonifyid(identifier);
    if (!identifier) return -1;
    auth_aname[0] = auth_inst[0] = auth_realm[0] = '\0';
    kname_parse(auth_aname, auth_inst, auth_realm, identifier);
    if (strcmp(auth_userid, "anyone") == 0) return 0;
    strcpy(auth_userid, identifier);
    
    info.hash=hashfn;
    info.lorder=0;
    info.bsize=2048;
    info.cachesize=20480;
    info.ffactor=8;
    key.data=keydata;
    key.size=20;
    fd=open(DBLOCK, O_CREAT|O_TRUNC|O_RDWR, 0644);
    if (fd == -1) {
        syslog(LOG_ERR, "IOERROR: creating lock file %s: %m", DBLOCK);
        return -1;
    }
    if (lock_shared(fd) < 0) {
        syslog(LOG_ERR, "IOERROR: locking lock file %s: %m", DBLOCK);
        return -1;
    }
    ptdb=dbopen(DBFIL,O_RDONLY,0,DB_HASH,&info);
    if (!ptdb)
      if (errno == ENOENT) {
          /* Hopefully, this should prevent two different processes from trying
             to crete the database at the same time */
          ptdb=dbopen(DBFIL,O_CREAT|O_RDWR|O_EXCL,0644,DB_HASH,&info);
          if (!ptdb && errno == EEXIST) {
              ptdb=dbopen(DBFIL,O_RDONLY,0,DB_HASH,&info);
              if (!ptdb) {
                  syslog(LOG_ERR, "IOERROR: opening database %s: %m", DBFIL);
                  close(fd);
                  return -1;
              }
          } else if (!ptdb) {
              syslog(LOG_ERR, "IOERROR: creating database %s: %m", DBFIL);
              return -1;
          } else {
              /* Write a record to the database, so that the database header
                 will be written out */
              memset(key.data,0,key.size);
              strcpy(key.data,"DUMMYREC");
              dataheader.size=5;
              dataheader.data="NULL";
              if (PUT(ptdb,&key,&dataheader,0) < 0) {
                  syslog(LOG_ERR, "IOERROR: initializing database %s: %m",
                         DBFIL); 
                  return -1;
              }
              /* close and reopen the database in read-only mode */
              if (CLOSE(ptdb) <0 ) {
                  syslog(LOG_ERR, "IOERROR: initializing database %s: %m",
                         DBFIL); 
                  return -1;
              }
              ptdb=dbopen(DBFIL,O_RDONLY,0644,DB_HASH,&info);
              if (!ptdb) {
                  syslog(LOG_ERR, "IOERROR: reopening new database %s: %m",
                         DBFIL); 
                  return -1;
              }
          }          
      } else {
          syslog(LOG_ERR, "IOERROR: opening database %s: %m", DBFIL);
          return -1;
      }
    if (cacheid) {
        memset(key.data,0,key.size);
        memcpy(key.data,cacheid,16);
        key.size=20;
    } else {
        key.size=PR_MAXNAMELEN + 4;
        if ((strlen(identifier) + 5 )  < PR_MAXNAMELEN)
            /* round length up to nearest multiple of 4
               so that the the hash function works properly */
            key.size=(((strlen(identifier) + 3) >> 2) << 2) + 4;
        memset(key.data,0,key.size);
        strncpy(key.data,identifier,key.size-4);
    }
    /* Fetch and process the header record for the user, if any */
    keydata[key.size-4]='H';
    rc=GET(ptdb,&key,&dataheader,0);
    keydata[key.size-4]=0;
    if (rc < 0) {
        syslog(LOG_ERR, "IOERROR: reading database %s: %m", DBFIL);
        CLOSE(ptdb);
        close(fd);
        return -1;
    }
    if (!rc) {
        if(dataheader.size != sizeof(ptluser)) {
            syslog(LOG_ERR, "IOERROR: Database %s probably corrupt", DBFIL);
            CLOSE(ptdb);
            close(fd);
            return -1;
        }
        /* make sure the record is alignes */
        memcpy(&us,dataheader.data,sizeof(ptluser));
    }
    if (rc || (!cacheid && us.cached < time(0) - EXPIRE_TIME)) {
        int pfd[2];
        int pid;
        /* There's no record for this user. close the database, and run the
           external lookup client */
        CLOSE(ptdb);
        close(fd);

	if (!ptclient_path[0]) {
	    strcpy(ptclient_path, CYRUS_PATH);
	    strcat(ptclient_path, "/bin/");
	    strcat(ptclient_path, PTCLIENT);
	}

        if (pipe(pfd) < 0) {
            syslog(LOG_ERR, "SYSERR: pipe: %m");
            return -1;
        }

	pid = -1;
	while (pid == -1) {
	    pid = vfork();
	    if (pid < 0) {
		if (errno == EAGAIN && ++forktries < 10) {
		    sleep(1);
		}
		else {
		    syslog(LOG_ERR, "SYSERR: vfork: %m");
		    close(pfd[0]);
		    close(pfd[1]);
		    return -1;
		}
	    }
	}

        if (!pid) {
            close(pfd[1]);
            dup2(pfd[0],0);
            execl(ptclient_path, PTCLIENT, 0);
            syslog(LOG_ERR, "SYSERR: exec %s: %m", ptclient_path);
            exit(-1);
        } else {
            /* The data passed along the pipe is as follows:
               Size of the cache tag, followed by the tag itself (variable
               length) then the username, in a fixed-length string */
            write(pfd[1],&key.size,sizeof(size_t));
            write(pfd[1],key.data,key.size);
            write(pfd[1],identifier,PR_MAXNAMELEN);
            close(pfd[1]);
            xpid=waitpid(pid,&rc,0);
            if (xpid==-1 || WEXITSTATUS(rc) != 0) {
                return -1;
            }
            /* The database must be re-opened after external modifications, at
               least in db 1.1.85 */
            fd=open(DBLOCK, O_CREAT|O_TRUNC|O_RDWR, 0644);
            if (fd == -1){
                syslog(LOG_ERR, "IOERROR: creating lock file %s: %m", DBLOCK);
                return -1;
            }
            if (lock_shared(fd) < 0) {
                syslog(LOG_ERR, "IOERROR: locking lock file %s: %m", DBLOCK);
                return -1;
            }
            ptdb=dbopen(DBFIL,O_RDONLY,0,DB_HASH,&info);
            if (!ptdb) {
                syslog(LOG_ERR, "IOERROR: opening database %s: %m", DBFIL);
                close(fd);
                return -1;
            }
        }
        /* fetch the new header record and proces it */
        keydata[key.size-4]='H';
        rc=GET(ptdb,&key,&dataheader,0);
        keydata[key.size-4]=0;
        if (rc < 0) {
            syslog(LOG_ERR, "IOERROR: reading database: %m");             
            CLOSE(ptdb);
            close(fd);
            return -1;
        }
        /* The record still isn't there, even though the child claimed sucess
         */ 
        if (rc) {
            syslog(LOG_ERR, "Sucessful %s run did not update database",
                   PTCLIENT);
            CLOSE(ptdb);
            close(fd);
            return -1;
        }
        memcpy(&us,dataheader.data,dataheader.size);
    }
    /* We assume cache keys will be unique. This will catch duplicates if they
       occur */
    if (strcasecmp(identifier,us.user)) {
        syslog(LOG_ERR,
               "Internal error: Fetched record for user %s was for user %s: key not unique",
               identifier, us.user);
        CLOSE(ptdb);
        close(fd);      
        return -1;
    }
    /* now get the actual data from the database. this will be a contiguous
       char[][] of size PR_MAXNAMELEN * us.ngroups */
    keydata[key.size-4]='D';
    rc=GET(ptdb,&key,&datalist,0);
    CLOSE(ptdb);    
    close(fd);
    if (rc < 0) {
        syslog(LOG_ERR, "IOERROR: reading database %s: %m", DBFIL);
        return -1;
    }
    if (rc) {
        syslog(LOG_ERR,
               "Database %s inconsistent: header record found, data record missing", DBFIL);
        return -1;
    }
    auth_ngroups=us.ngroups;
    if (auth_ngroups) {
        auth_groups=(char (*)[][PR_MAXNAMELEN])xmalloc(auth_ngroups *
                                                       PR_MAXNAMELEN); 
        memcpy(auth_groups,datalist.data, auth_ngroups*PR_MAXNAMELEN);
    }
    return 0;
}
