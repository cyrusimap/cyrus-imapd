#include <config.h>

#include "auth_krb_pts.h"

static char rcsid[] = "$Id: ptdump.c,v 1.4 2000/02/10 21:25:42 leg Exp $";

int 
main(argc, argv)
     int argc;
     char *argv[];
{
  char fnamebuf[MAXPATHLEN];
  char keyinhex[512];
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
    printf("Using alternate file: %s\n", alt_file);
    strcpy(fnamebuf, alt_file);
  } else {
    strcpy(fnamebuf, STATEDIR);
    strcat(fnamebuf, PTS_DBFIL);
  }

  (void)memset(&key, 0, sizeof(key));
  (void)memset(&data, 0, sizeof(data));

  ptdb = dbopen(fnamebuf, O_RDONLY, 0, DB_HASH, &info);
  if (!ptdb) {
    fprintf(stderr, "ERROR: opening database %s: ", fnamebuf);
    perror("");
    exit(-1);
  }

  rc = SEQ(ptdb, &key, &data, R_FIRST);
  if (rc < 0) {
    fprintf(stderr, "Error reading database %s: ", fnamebuf);
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

  if (thekey[PTS_DB_HOFFSET] == 'H') {
    printf( "key: %s\t", keyinhex);
    if (data.size != sizeof(ptluser)) {
      printf("\nERROR: data.size (%d) != sizeof(ptluser)\n", 
	      data.size, sizeof(ptluser));
    }
    (void)memcpy(&us, data.data, data.size);
    printf("user: %s\ttime: %d\tngroups: %d\n",
	   us.user, us.cached, us.ngroups);
    thekey[PTS_DB_HOFFSET] = 'D';
    for (i=0; i<size; i++) 
      sprintf(keyinhex+(2*i), "%.2x", thekey[i]);
    printf( "matching data key: %s", keyinhex);
    rc = GET(ptdb, &key, &data, 0);
    if (rc < 0) {
      fprintf(stderr,"ERROR: Database read error: ");
      perror("");
    } else if (rc) {
      printf("ERROR: Unable to find matching data record\n");
    } else {
      printf("\tdata size: %d\n", data.size);
    }
  } else if (thekey[PTS_DB_HOFFSET] == 'D') {
    for (i=0; i<size; i++) 
      sprintf(keyinhex+(2*i), "%.2x", thekey[i]);
    printf( "key: %s\t", keyinhex);

    printf("DATA key: %s\n", keyinhex);
  } else {
    printf("OTHER key: %s\n", keyinhex);
  }

  found = 1;

  while (found) {
    rc = SEQ(ptdb, &key, &data, R_NEXT);
    
    if (rc < 0) {
      fprintf(stderr, "Error reading database %s:", fnamebuf);
      perror("");
      exit(-1);
    }
    if (rc) {
      found = 0;
      continue;
    }
    thekey = key.data;
    size = key.size;

    for (i=0; i<size; i++) 
      sprintf(keyinhex+(2*i), "%.2x", thekey[i]);

    if (thekey[PTS_DB_HOFFSET] == 'H') {
      printf( "key: %s\t", keyinhex);
      if (data.size != sizeof(ptluser)) {
	printf("\nERROR: data.size (%d) != sizeof(ptluser)\n", 
		data.size, sizeof(ptluser));
      }
      (void)memcpy(&us, data.data, data.size);
      printf("user: %s\ttime: %d\tngroups: %d\n",
	     us.user, us.cached, us.ngroups);
      thekey[PTS_DB_HOFFSET] = 'D';
      for (i=0; i<size; i++) 
	sprintf(keyinhex+(2*i), "%.2x", thekey[i]);
      printf( "matching data key: %s", keyinhex);
      rc = GET(ptdb, &key, &data, 0);
      if (rc < 0) {
	fprintf(stderr,"ERROR: Database read error: ");
	perror("");
      } else if (rc) {
	printf("ERROR: Unable to find matching data record\n");
      } else {
	printf("\tdata size: %d\n", data.size);
      }
    } else if (thekey[PTS_DB_HOFFSET] == 'D') {
      for (i=0; i<size; i++) 
	sprintf(keyinhex+(2*i), "%.2x", thekey[i]);
      printf("DATA key: %s\n  Group data is:\n", keyinhex);
      for(j=0; j < (data.size / PR_MAXNAMELEN); j++) {
	  printf("    %s\n", ((char (*)[PR_MAXNAMELEN])(data.data))[j]);
      }
    } else {
      printf("OTHER key: %s\n", keyinhex);
    }
  }

  CLOSE(ptdb);
  exit(0);
}      

int fatal(msg, exitcode)
     char *msg;
     int exitcode;
{
  fprintf(stderr,"%s", msg);
  exit(-1);
}
