/* amssync.c -- read AMS bboards
 *
 *	(C) Copyright 1995 by Carnegie Mellon University
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

#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/time.h>
#include <string.h>
#include <sysexits.h>

#include "xmalloc.h"
#include "amssync.h"

extern int debug,verbose;


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
bboard *getams(char *dname)
{
    char buf[1024];
    DIR *dirp;
    struct dirent *dirent;
    bboard *amsbbd;
    int i;
  

    amsbbd=(bboard *)xmalloc(sizeof(bboard));
    amsbbd->alloced=50;
    amsbbd->inuse=-1;
 
    chdir(dname);
    dirp=opendir(dname);
    if (!dirp) {
	fprintf(stderr, "Bboard does not exist!\n");
	perror(dname);
	exit(EX_NOINPUT);
    }
    amsbbd->msgs=(message *)xmalloc((amsbbd->alloced + 1) * sizeof (message));
    amsbbd->internaldata=dname;
    amsbbd->internalfreeproc=NULL;
    memset(buf, 0, sizeof(buf));
  
    while ((dirent=readdir(dirp))) {
	if (dirent->d_name[0] == '+') {
	    if (++amsbbd->inuse == amsbbd->alloced) {
		amsbbd->alloced *= 2;
		amsbbd->msgs=(message *)xrealloc(amsbbd->msgs, amsbbd->alloced
						 * sizeof (message)); 
	    }
	    /* skip the + in the name */
	    amsbbd->msgs[amsbbd->inuse].stamp=conv64tolong(&dirent->d_name[1]); 
	    strcpy(amsbbd->msgs[amsbbd->inuse].name, dirent->d_name);
	}  
    }
    closedir(dirp);
    qsort(amsbbd->msgs, amsbbd->inuse+1, sizeof (message), cmpmsg);
    if (debug) {
	for (i=0;i<=amsbbd->inuse;i++){
	    printf("file %s was submitted at %ld\n" /* and is%s BE2 formatted\n"*/,
		   amsbbd->msgs[i].name, (long)amsbbd->msgs[i].stamp);
	}
    }
    else if (verbose) {
	printf("There are %d messages in %s\n", amsbbd->inuse+1, dname);
    }
    amsbbd->msgs[amsbbd->inuse+1].stamp=0x7fffffff;
    return amsbbd;
  
}

/*
 * Return the name of the file that contains the given message. User
 * should free value when done
 */
char *getfilename(bboard *bbd, message *msg)
{
    char *result;
    int slen;

    slen=strlen((char *)bbd->internaldata)+ strlen(msg->name) + 2;
    if (!slen) {
	return NULL;
    }
    result=xmalloc(slen);
    sprintf(result, "%s/%s", (char *)bbd->internaldata, msg->name);
    return result;
}

  
