#include "auth_krb_pts.h"

/* This program does the actual work of contacting the PTS server and updating
   the database. it reads the base database key and username from stdin */
int main(int argc, char *argv) {
    HASHINFO info;
    DB * ptdb;
    char indata[PR_MAXNAMELEN+4];
    char user[PR_MAXNAMELEN];
    namelist groups;
    int i,fd,rc;
    DBT key,dataheader,datalist;
    ptluser us;
    char (*list)[][PR_MAXNAMELEN];
    size_t size;
    openlog(PTCLIENT,LOG_PID,LOG_LOCAL6);
    
    
    memset(indata,0,PR_MAXNAMELEN+4);
    
    if (read(0,&size,sizeof(size_t)) < 0) {
        syslog(LOG_ERR,"read from pipe: %m");
        exit(-1);
    }
    if (read(0,indata,size) < 0) {
        syslog(LOG_ERR,"read from pipe: %m");
        exit (-1);
        }
    key.data=indata;
    key.size=size;
    if (read(0,user,PR_MAXNAMELEN) < 0) {
        syslog(LOG_ERR,"read from pipe: %m");   
        exit (-1);
    }      
#ifdef DEBUG
    printf("Ptclient got user %s\ncache val: ", user);
    for (i=0;i<size;i++)
      if (isprint(indata[i]))
        printf("%c",indata[i]);
      else
        printf("\\%.3o", indata[i]);
    printf("\n");
#endif
    info.hash=hashfn;
    info.lorder=0;
    info.bsize=2048;
    info.cachesize=20480;
    info.ffactor=8;
    /* Get group list from PTS */
    if ((rc=pr_Initialize(1L,AFSCONF_CLIENTNAME,0))) {
        syslog(LOG_ERR, "pr_Initialize: %s", error_message(rc));
        exit(-1);
    }
    if ((rc=pr_ListMembers(user,&groups))) {
        syslog(LOG_ERR, "pr_ListMembers %s: %s", user,  error_message(rc));
        exit(-1);
    }
    us.ngroups=groups.namelist_len;
    us.cached=time(0);
    /* store group list in contiguous array for easy storage in the database */
    list=(char (*)[][PR_MAXNAMELEN])xmalloc(us.ngroups*PR_MAXNAMELEN);
    memset(list,0,us.ngroups*PR_MAXNAMELEN);
    for (i=0;i<us.ngroups;i++){
        strcpy((*list)[i],groups.namelist_val[i]);
    }
    pr_End();
    /* build and store a header record for this user */
    strcpy(us.user,user);
    dataheader.data=&us;
    dataheader.size=sizeof(ptluser);
    datalist.data=list;
    datalist.size=us.ngroups*PR_MAXNAMELEN;
    indata[key.size-4]='H';
  
    fd=open(DBLOCK, O_CREAT|O_TRUNC|O_RDWR, 0644);
    if (fd == -1) {
        syslog(LOG_ERR, "IOERROR: creating lock file %s: %m", DBLOCK);
        return -1;
    }
    if (lock_blocking(fd) < 0) {
        syslog(LOG_ERR, "IOERROR: locking lock file %s: %m", DBLOCK);
            return -1;
    }
    ptdb=dbopen(DBFIL,O_RDWR,0,DB_HASH,&info);
    if (!ptdb) {
        syslog(LOG_ERR, "IOERROR: opening database %s: %m", DBFIL);
        close(fd);
        return -1;
    }
    rc=PUT(ptdb,&key,&dataheader,0);
    if (rc < 0) {
        syslog(LOG_ERR, "IOERROR: writing database %s: %m", DBFIL);
        CLOSE(ptdb);
        close(fd);        
        return -1;
    }
    /* store the grouplist */
    indata[key.size-4]='D';
    rc=PUT(ptdb,&key,&datalist,0);
    if (rc < 0) {
        syslog(LOG_ERR, "IOERROR: writing database %s: %m", DBFIL);
        CLOSE(ptdb);
        close(fd);
        return -1;
    }
    CLOSE(ptdb);
    close(fd);
    /* and we're done */
    free(list);
#ifdef DEBUG
    printf("Ptclient suceeded\n");
#endif
    
    exit(0);
}

int fatal(char *msg, int exitcode) {
    syslog(LOG_ERR,"%s", msg);
    exit(-1);
}

    
