/* amssync.c -- read AMS bboards
 # Copyright 1998 Carnegie Mellon University
 # 
 # No warranties, either expressed or implied, are made regarding the
 # operation, use, or results of the software.
 #
 # Permission to use, copy, modify and distribute this software and its
 # documentation is hereby granted for non-commercial purposes only
 # provided that this copyright notice appears in all copies and in
 # supporting documentation.
 #
 # Permission is also granted to Internet Service Providers and others
 # entities to use the software for internal purposes.
 #
 # The distribution, modification or sale of a product which uses or is
 # based on the software, in whole or in part, for commercial purposes or
 # benefits requires specific, additional permission from:
 #
 #  Office of Technology Transfer
 #  Carnegie Mellon University
 #  5000 Forbes Avenue
 #  Pittsburgh, PA  15213-3890
 #  (412) 268-4387, fax: (412) 268-7395
 #  tech-transfer@andrew.cmu.edu
 *
 */

#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <string.h>
#include <sysexits.h>

#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "sasl.h"
#include "imclient.h"
#include "xmalloc.h"
#include "AMSstuff.h"
#include "amssync.h"

extern int debug,verbose;
extern FILE *logfile;

static unsigned char DigVals[96] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 11, 0, 0,
        0, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 0, 0, 0, 0, 10,
        0, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
        53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 0, 0, 0, 0, 0 
};

/*
 * decode the timestamp of an AMS message (filename)
 * stolen from atk-atk ..../overhead/mail/lib/genid.c
 */
unsigned long conv64tolong(xnum)
register char *xnum;
{
    register int digits;
    unsigned long Answer = 0;
 
    digits = strlen(xnum);
    if (digits > 6) digits = 6;
    switch(digits) {
        case 6: Answer |= DigVals[(*xnum)-040] << 30; ++xnum;
        case 5: Answer |= DigVals[(*xnum)-040] << 24; ++xnum;
        case 4: Answer |= DigVals[(*xnum)-040] << 18; ++xnum;
        case 3: Answer |= DigVals[(*xnum)-040] << 12; ++xnum;
        case 2: Answer |= DigVals[(*xnum)-040] << 6; ++xnum;
        case 1: Answer |= DigVals[(*xnum)-040];
    }
    return(Answer);
}

/*
 * allocate and build a bboard struct for the AMS mailbox contained in
 * the named directory. gets name and date information from the
 * filenames, and builds a sorted message list . amsbbd->name is not
 * filled in. the inuse and alloced members do not take the sentinel
 * into account. This assumes that the passed parameter string will
 * not be freed/out of scope until this structure is freed
 */
int getams(amsname, abbd)
    char *amsname;
    bboard *abbd;
{
    message *msg;
    FILE *msdir;
    struct stat stbuf;
    int i;
    char dname[MAXPATHLEN];
    char snap[AMS_SNAPSHOTSIZE];

    sprintf(dname, "%s/%s", amsname, MS_DIRNAME);
    if ((msdir = fopen(dname, "r")) == NULL) {
	fprintf(stderr, "Couldn't open AMS folder ");
	perror(amsname);
	return (1);
    }
    if (fstat(fileno(msdir), &stbuf) < 0) {
	fprintf(stderr, "Couldn't stat AMS folder");
	perror(amsname);
	fclose(msdir);
	return (1);
    }
    abbd->alloced = abbd->inuse = (stbuf.st_size - AMS_DIRHEADSIZE) / AMS_SNAPSHOTSIZE;
    msg = abbd->msgs =
	(message *) xmalloc((abbd->inuse + 1) * sizeof (message));
    if (abbd->inuse) {
	fseek(msdir, AMS_DIRHEADSIZE, 0);
	for (i = 0; i < abbd->inuse; ++i, ++msg) {
	    fread(snap, AMS_SNAPSHOTSIZE, 1, msdir);
	    msg->name[0] = '+';
	    strcpy(msg->name+1, AMS_ID(snap));
	    msg->stamp = conv64tolong(AMS_DATE(snap));
	}
    }
    fclose(msdir);
    msg->stamp = 0x7fffffff;
    abbd->inuse--;

    return (0);
}
