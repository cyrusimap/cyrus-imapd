/*
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
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
#include <config.h>

#include "auth_krb_pts.h"

static char rcsid[] = "$Id: ptdump.c,v 1.6 2003/02/13 20:15:56 rjs3 Exp $";

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
