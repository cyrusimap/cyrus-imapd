#include "auth_krb_pts.h"

typedef struct {
    char keydata[PR_MAXNAMELEN + 4];
    int keysize;
    char user[PR_MAXNAMELEN];
} delrec,*dellist;

static int ndels,ndalloc;

/* This program purges old entries from the database. It holds an exclusive
   lock throughout the process. The reaseon for the split data
   gathering/expunge phases is because DB's SEQ operator breaks if the database
   is modified while the database is being sequenced through.
   */
int main()
{
    char fnamebuf[1024];
    HASHINFO info;
    DB * ptdb;
    char keydata[PR_MAXNAMELEN+4], *thekey;
    namelist groups;
    int i, j, found, fd, rc;
    DBT key, data;
    ptluser us;
    size_t size;    
    time_t timenow;
    dellist deletions;

    openlog("ptexpire", LOG_PID, LOG_LOCAL6);

    timenow = time(0);
    ndels = 0;
    ndalloc = 10;
    deletions = (dellist)xmalloc((ndalloc + 1)*sizeof(delrec));
    
    
    info.hash = hashfn;
    info.lorder = 0;
    info.bsize = 2048;
    info.cachesize = 20480;
    info.ffactor = 8;
    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, PTS_DBLOCK);
    fd=open(fnamebuf, O_CREAT|O_TRUNC|O_RDWR, 0664);
    if (fd == -1) {
        syslog(LOG_ERR, "IOERROR: creating lock file %s: %m", fnamebuf);
        return -1;
    }
    if (lock_blocking(fd) < 0) {
        syslog(LOG_ERR, "IOERROR: locking lock file %s: %m", fnamebuf);
        return -1;
    }
    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, PTS_DBFIL);
    ptdb = dbopen(fnamebuf, O_RDWR, 0, DB_HASH, &info);
    if (!ptdb) {
        syslog(LOG_ERR, "IOERROR: opening database %s: %m", fnamebuf);
        return -1;
    }
    rc = SEQ(ptdb, &key, &data, R_FIRST);
    if (rc < 0) {
        syslog(LOG_ERR, "IOERROR: reading database %s: %m", fnamebuf);
        return -1;
    }
    if (rc) {
	exit(0);
    }
    thekey = key.data;
#ifdef DEBUG
    printf("Processing entry with key:");
    for (i=0; i<key.size; i++) {
	if (isprint(thekey[i])) {
	    printf("%c",thekey[i]);
	}
	else {
	    printf("\\%.3o", thekey[i]);
	}
    }
    printf("\n");
#endif
    if (thekey[key.size-4] == 'H') {
        if (data.size != sizeof(ptluser)) {
            syslog(LOG_ERR, "IOERROR: Database probably corrupt");
            return -1;
        }
      
        memcpy(&us, data.data, data.size);
#ifdef DEBUG
        printf("Found header record for user %s\n", us.user);
#endif
        if (us.cached + EXPIRE_TIME < timenow) {
#ifdef DEBUG
            printf("record expired, marking for deletion\n");
#endif
            if (ndels > ndalloc) {
                ndalloc *=2;
                deletions=(dellist)xrealloc(deletions,(ndalloc + 1)
                                            * sizeof(delrec));
            }
            deletions[ndels].keysize = key.size;
            memcpy(deletions[ndels].keydata, key.data, key.size);
            strcpy(deletions[ndels].user, us.user);
            ndels++;
        }
    }  
    found = 1;
    while (found) {
        rc = SEQ(ptdb, &key, &data, R_NEXT);
        found = (rc == 0);
        if (rc < 0) {
            syslog(LOG_ERR, "IOERROR: reading database %s: %m", fnamebuf);
            return -1;
        }
        
        if (rc == 0) {
            thekey = key.data;
#ifdef DEBUG
            printf("Processing entry with key:");
            thekey = key.data;
            for (i=0; i<key.size; i++) {
		if (isprint(thekey[i])) {
		    printf("%c",thekey[i]);
		}
		else {
		    printf("\\%.3o", thekey[i]);
		}
	    }
            printf("\n");
#endif
            if (thekey[key.size-4] == 'H') {
                if (data.size != sizeof(ptluser)) {
                    syslog(LOG_ERR, "IOERROR: Database probably corrupt");
                    CLOSE(ptdb);
                    close(fd);
                    return -1;
                }
                memcpy(&us, data.data, data.size);
#ifdef DEBUG
                printf("Found header record for user %s\n", us.user);
#endif
                if (us.cached + EXPIRE_TIME < timenow) {
#ifdef DEBUG
                    printf("record expired, marking for deletion\n");
#endif
                    if (ndels > ndalloc) {
                        ndalloc *= 2;
                        deletions=(dellist)xrealloc(deletions,(ndalloc + 1) *
                                                    sizeof(delrec)); 
                    }
                    deletions[ndels].keysize = key.size;
                    memcpy(deletions[ndels].keydata, key.data, key.size);
                    strcpy(deletions[ndels].user, us.user);
                    ndels++;
                }
            }
        }
    }

    for (j=0; j<ndels; j++) {
        key.size = deletions[j].keysize;
        key.data = deletions[j].keydata;
        thekey = key.data;
#ifdef DEBUG
        printf("User %s: Key: ", deletions[j].user);
        for (i=0; i<key.size; i++) {
	    if (isprint(thekey[i])) {
		printf("%c",thekey[i]);
	    }
	    else {
		printf("\\%.3o", thekey[i]);
	    }
	}
        printf("\n");
        
        printf("Expunging header....");
#endif
        rc = DEL(ptdb, &key, 0);
        if (rc < 0) {
            syslog(LOG_ERR, "IOERROR: writing database %s: %m", fnamebuf);
            CLOSE(ptdb);
            close(fd);
            return -1;
        }
        if (rc) {
            syslog(LOG_ERR, "Aiee. header record disappeared!");
            CLOSE(ptdb);
            close(fd);
            return -1;
        }
#ifdef DEBUG
        printf("data....");
#endif
        thekey[key.size-4] = 'D';
        rc = DEL(ptdb, &key, 0);
        if (rc < 0) {
            syslog(LOG_ERR, "IOERROR: writing database %s: %m", fnamebuf);
            CLOSE(ptdb);
            return -1;
        }
        if (rc) {
            syslog(LOG_ERR, "Data record missing, continuing anyway");
        }
#ifdef DEBUG
        printf("done\n");
#endif
    }
    
    CLOSE(ptdb);
    close(fd);
    
    free(deletions);
    exit(0);
}      

int fatal(msg, exitcode)
char *msg;
int exitcode;
{
    syslog(LOG_ERR,"%s", msg);
    exit(-1);
}
