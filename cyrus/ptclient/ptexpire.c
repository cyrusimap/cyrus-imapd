/*
 */

/* This program purges old entries from the database. It holds an exclusive
 * lock throughout the process. The reaseon for the split data
 * gathering/expunge phases is because DB's SEQ operator breaks if the database
 * is modified while the database is being sequenced through.
 *
 * NOTE: by adding the alt_file flag, we let exit() handle the cleanup of 
 *       the lock file's fd. That's bad in principal but not in practice. We do
 *       to make the code easier to read.
 */

#include <sys/param.h>
#ifndef MAXPATHLEN
#define MAXPATHLEN MAXPATHNAMELEN
#endif

#include "auth_krb_pts.h"

static char rcsid[] = "$Id: ptexpire.c,v 1.6 1998/07/30 21:31:02 wcw Exp $";

typedef struct {
  char keydata[PR_MAXNAMELEN + 4];
  size_t keysize;
  char user[PR_MAXNAMELEN];
} delrec,*dellist;

static int ndels,ndalloc;
static int ptexpire_verbose = 0;
static char keyinhex[512];

int 
main(argc, argv)
     int argc;
     char *argv[];
{
  char fnamebuf[MAXPATHLEN];
  HASHINFO info;
  DB * ptdb;
  char *thekey;
  int i, j, found, fd, rc;
  DBT key, data;
  ptluser us;
  size_t size;    
  time_t timenow;
  dellist deletions;
  time_t expire_time = EXPIRE_TIME;
  extern char *optarg;
  int opt;
  char *alt_file = NULL;

  openlog("ptexpire", LOG_PID, LOG_LOCAL6);

  while ((opt = getopt(argc, argv, "v:f:E:")) != EOF) {
    switch (opt) {
    case 'v':
      ptexpire_verbose = atoi(optarg);
      break;
    case 'f':
      alt_file = optarg;
      break;
    case 'E':
      expire_time = atoi(optarg);
      break;
    case '?':
      fprintf(stderr,"usage: -vEf"
	      "\n\t-E <seconds>\tExpiration time"
	      "\n\t-v <n>\tVerbosity level"
	      "\n\t-f <dbfile>\tAlternate location for the db file."
	      "\n\t*WARNING* Using this option bypasses the locking mechanism."
	      "\n\t** DO NOT USE THIS OPTION ON A LIVE DATABASE FILE **"
	      "\n");
      syslog(LOG_ERR, "Invalid command line option");
      exit(-1);
      break;
    default:
      break;
      /* just pass through */
    }
  }

  timenow = time(0);
  syslog(LOG_DEBUG, "start (%d): %s", timenow, rcsid);
  syslog(LOG_DEBUG, "Expiring entries older than %d seconds", expire_time);

  ndels = 0;
  ndalloc = 10;
  deletions = (dellist)xmalloc((ndalloc + 1)*sizeof(delrec));
    
  (void)memset(&info, 0, sizeof(info));

  if (alt_file) {
    syslog(LOG_DEBUG, "Using alternate file: %s", alt_file);
    strcpy(fnamebuf, alt_file);
  } else {
    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, PTS_DBLOCK);
    if ((fd=open(fnamebuf, O_CREAT|O_TRUNC|O_RDWR, 0664)) < 0) {
      syslog(LOG_ERR, "IOERROR: creating lock file %s: %m", fnamebuf);
      exit(-1);
    }

    if (lock_blocking(fd) < 0) {
      syslog(LOG_ERR, "IOERROR: locking lock file %s: %m", fnamebuf);
      exit(-1);
    }

    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, PTS_DBFIL);
  }

  (void)memset(&key, 0, sizeof(key));
  (void)memset(&data, 0, sizeof(data));

  ptdb = dbopen(fnamebuf, O_RDWR, 0, DB_HASH, &info);
  if (!ptdb) {
    syslog(LOG_ERR, "IOERROR: opening database %s: %m", fnamebuf);
    exit(-1);
  }

  rc = SEQ(ptdb, &key, &data, R_FIRST);
  if (rc < 0) {
    syslog(LOG_ERR, "IOERROR: reading database %s: %m", fnamebuf);
    exit(-1);
  }
  if (rc) {
    syslog(LOG_DEBUG, "No entries found. Exiting");
    exit(0);
  }
  thekey = key.data;
  size = key.size;

  /* the following block takes care of the first
   * entry. Notice that much of this code is duplicated
   * in the while (found) loop. I found it this way and I'm going
   * to leave it this way.
   */
  if (ptexpire_verbose > 5) {
    for (i=0; i<size; i++) 
      sprintf(keyinhex+(2*i), "%.2x", thekey[i]);
    syslog(LOG_DEBUG, "Processing: %s", keyinhex);
  }

  if (thekey[PTS_DB_HOFFSET] == 'H') {
    if (data.size != sizeof(ptluser)) {
      syslog(LOG_ERR, "IOERROR: Database probably corrupt");
      exit(-1);
    }
      
    memcpy(&us, data.data, data.size);

    if (ptexpire_verbose > 10) {
      syslog(LOG_DEBUG, "Found user %s at %d", 
	     us.user, us.cached);
    }

    if ((us.cached + expire_time)< timenow) {
      if (ptexpire_verbose > 10) { 
	syslog(LOG_DEBUG, "Entry expired; marking for deletion");
      }
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

  /* as per the earlier comment... here we go again */
  found = 1;
  while (found) {
    rc = SEQ(ptdb, &key, &data, R_NEXT);
    found = (rc == 0);
    if (rc < 0) {
      syslog(LOG_ERR, "IOERROR: reading database %s: %m", fnamebuf);
      exit(-1);
    }
        
    if (rc == 0) {
      thekey = key.data;
      size = key.size;
      if (ptexpire_verbose > 10) {
	for (i=0; i<size; i++) 
	  sprintf(keyinhex+(2*i), "%.2x", thekey[i]);
	syslog(LOG_DEBUG, "Processing: %s", keyinhex);
      }
      if (thekey[PTS_DB_HOFFSET] == 'H') {
	if (data.size != sizeof(ptluser)) {
	  syslog(LOG_ERR, "IOERROR: Database probably corrupt");
	  CLOSE(ptdb);
	  exit(-1);
	}

	memcpy(&us, data.data, data.size);

	if (ptexpire_verbose > 10) {
	  syslog(LOG_DEBUG, "Found user %s at %d", 
		 us.user, us.cached);
	}

	if ((us.cached + expire_time) < timenow) {
	  if (ptexpire_verbose > 10) { 
	    syslog(LOG_DEBUG, "Entry expired; marking for deletion");
	  }
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
    size = key.size;

    if (ptexpire_verbose > 10) {
      for (i=0; i<size; i++) 
	sprintf(keyinhex+(2*i), "%.2x", thekey[i]);
      syslog(LOG_DEBUG, "deleting header key: %s", keyinhex);
    }
    rc = DEL(ptdb, &key, 0);
    if (rc < 0) {
      syslog(LOG_ERR, "IOERROR: writing database %s: %m", fnamebuf);
      exit(-1);
    }
    if (rc) {
      syslog(LOG_ERR, "Aiee. header record disappeared!");
      exit(-1);
    }

    thekey[PTS_DB_HOFFSET] = 'D';
    if (ptexpire_verbose > 10) {
      for (i=0; i<size; i++) 
	sprintf(keyinhex+(2*i), "%.2x", thekey[i]);
      syslog(LOG_DEBUG, "deleting data key: %s", keyinhex);
    }
    rc = DEL(ptdb, &key, 0);
    if (rc < 0) {
      syslog(LOG_ERR, "IOERROR: writing database %s: %m", fnamebuf);
      exit(-1);
    }
    if (rc) {
      syslog(LOG_ERR, "Data record missing, continuing anyway");
    }

    if (ptexpire_verbose > 5) {
      syslog(LOG_DEBUG, "deleted entry: %s", keyinhex);
    }
  }
    
  CLOSE(ptdb);

  if (alt_file == NULL) {
    close(fd);
  }
  free(deletions);
  syslog(LOG_DEBUG, "finished");
  exit(0);
}      

int fatal(msg, exitcode)
     char *msg;
     int exitcode;
{
  syslog(LOG_ERR,"%s", msg);
  exit(-1);
}
