#include "auth_krb_pts.h"

static char rcsid[] = "$Id: dump_ptc.c,v 1.1 1998/05/01 21:55:50 tjs Exp $";

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
  extern char *optarg;
  int opt;
  char *alt_file = NULL;

  while ((opt = getopt(argc, argv, "f:")) != EOF) {
    switch (opt) {
    case 'f':
      alt_file = optarg;
      break;
    case '?':
      fprintf(stderr,"usage: -f"
	      "\n\t-f <dbfile>\tAlternate location for the db file."
	      "\n");
      exit(-1);
      break;
    default:
      break;
      /* just pass through */
    }
  }

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

    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, PTS_DBFIL);
  }

  (void)memset(&key, 0, sizeof(key));
  (void)memset(&data, 0, sizeof(data));

  ptdb = dbopen(fnamebuf, O_RDONLY, 0, DB_HASH, &info);
  if (!ptdb) {
    syslog(LOG_ERR, "IOERROR: opening database %s: %m", fnamebuf);
    exit(-1);
  }

  rc = SEQ(ptdb, &key, &data, R_FIRST);
  if (rc < 0) {
    fprintf(stderr, "Error reading database %s", fnamebuf);
    perror("");
    exit(-1);
  }
  if (rc) {
    fprintf(stderr,"Database is empty\n");
    exit(0);
  }
  thekey = key.data;
  size = key.size;

  for (i=0; i<size; i++) 
    sprintf(keyinhex+(2*i), "%.2x", thekey[i]);

  if (thekey[key.size-4] == 'H') {
    printf( "key: %s\t", keyinhex);
    if (data.size != sizeof(ptluser)) {
      printf("\nERROR: data.size (%d) != sizeof(ptluser)\n", 
	      data.size, sizeof(ptluser));
    }
    (void)memcpy(&us, data.data, data.size);
    printf("user: %s\t time: %d\n", us.user, us.cached);
    thekey[key.size-4] = 'D';
    for (i=0; i<size; i++) 
      sprintf(keyinhex+(2*i), "%.2x", thekey[i]);
    printf( "data key: %s", keyinhex);
    rc = GET(ptdb, &key, &data, 0);
    if (rc < 0) {
      fprintf(stderr,"ERROR: Database read error");
      perror("");
    } else if (rc) {
      printf("ERROR: Unable to find matching data record");
    } else {
      printf("\tdata size: %d\n", data.size);
    }
  } else if (thekey[key.size-4] == 'D') {
    for (i=0; i<size; i++) 
      sprintf(keyinhex+(2*i), "%.2x", thekey[i]);
    printf( "key: %s\t", keyinhex);

    printf("Found data record key: %s\n");
  } else {
    printf("Found other key: %s\n");
  }

  found = 1;

  while (found) {
    rc = SEQ(ptdb, &key, &data, R_NEXT);
    
    if (rc < 0) {
      fprintf(stderr, "Error reading database %s", fnamebuf);
      perror("");
      exit(-1);
    }
    if (rc) {
      found = 0;
      continue;
    }
  th
    ekey = key.data;
    size = key.size;

    for (i=0; i<size; i++) 
      sprintf(keyinhex+(2*i), "%.2x", thekey[i]);

    if (thekey[key.size-4] == 'H') {
      printf( "key: %s\t", keyinhex);
      if (data.size != sizeof(ptluser)) {
	printf("\nERROR: data.size (%d) != sizeof(ptluser)\n", 
		data.size, sizeof(ptluser));
      }
      (void)memcpy(&us, data.data, data.size);
      printf("user: %s\t time: %d\n", us.user, us.cached);
      thekey[key.size-4] = 'D';
      for (i=0; i<size; i++) 
	sprintf(keyinhex+(2*i), "%.2x", thekey[i]);
      printf( "data key: %s", keyinhex);
      rc = GET(ptdb, &key, &data, 0);
      if (rc < 0) {
	fprintf(stderr,"ERROR: Database read error");
	perror("");
      } else if (rc) {
	printf("ERROR: Unable to find matching data record");
      } else {
	printf("\tdata size: %d\n", data.size);
      }
    } else if (thekey[key.size-4] == 'D') {
      for (i=0; i<size; i++) 
	sprintf(keyinhex+(2*i), "%.2x", thekey[i]);
      printf( "key: %s\t", keyinhex);

      printf("Found data record key: %s\n");
    } else {
      printf("Found other key: %s\n");
    }
  }

  if (alt_file == NULL) {
    close(fd);
  }
  free(deletions);
  printf("finished");
  exit(0);
}      

int fatal(msg, exitcode)
     char *msg;
     int exitcode;
{
  syslog(LOG_ERR,"%s", msg);
  exit(-1);
}
